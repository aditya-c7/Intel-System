import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import net from 'net';
import path from 'path';
import fs from 'fs';
import Database from 'better-sqlite3';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import type {
  BrowserDeviceInfo,
  LocationInfo,
  VisitStatistics,
  VisitHistoryRecord,
  IntelVisitorResponse,
} from './src/types/visitor.ts';

dotenv.config();

const PORT = 3000;
const SESSION_TIMEOUT_MINUTES = 30;
const SESSION_EXPIRATION_MS = SESSION_TIMEOUT_MINUTES * 60 * 1000;

const HMAC_SECRET =
  process.env.VISITOR_HMAC_SECRET ||
  process.env.GEMINI_API_KEY ||
  'intel-system-first-party-hmac-secret-2026';

const SPEED_TEST_MAX_TOTAL_DOWNLOAD_BYTES = 512 * 1024 * 1024; // 512 MB max budget so fast connections can sustain full 5s download
const SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES = 256 * 1024 * 1024; // 256 MB max budget so fast connections can sustain full 5s upload
const SPEED_TEST_MAX_STREAM_DOWNLOAD_BYTES = 16 * 1024 * 1024; // 16 MB max per individual stream request
const SPEED_TEST_MAX_STREAM_UPLOAD_BYTES = 10 * 1024 * 1024; // 10 MB max per individual upload stream request
const SPEED_TEST_CONCURRENT_STREAMS = 4;
const SPEED_TEST_TOKEN_TTL_MS = 60 * 1000; // 60s token validity
const SPEED_TEST_STREAM_TIMEOUT_MS = 15 * 1000; // 15s hard per-stream timeout
const HIGH_ENTROPY_64KB_CHUNK = crypto.randomBytes(65536); // Non-compressible 64 KB random buffer

const dataDir = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'intel_system.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS visitors (
    visitor_id TEXT PRIMARY KEY,
    hmac_token TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    active_session_id TEXT NOT NULL,
    last_activity_utc TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visit_id TEXT UNIQUE NOT NULL,
    visitor_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    page_load_id TEXT NOT NULL,
    visited_at_utc TEXT NOT NULL,
    public_ip TEXT NOT NULL,
    city TEXT NOT NULL,
    region TEXT NOT NULL,
    country TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    isp TEXT NOT NULL DEFAULT 'Unknown',
    org TEXT NOT NULL DEFAULT 'Unknown',
    asn TEXT NOT NULL DEFAULT 'Unknown',
    browser TEXT NOT NULL,
    os TEXT NOT NULL,
    device_type TEXT NOT NULL,
    screen_resolution TEXT NOT NULL,
    language TEXT NOT NULL,
    timezone TEXT NOT NULL,
    UNIQUE(visitor_id, page_load_id),
    FOREIGN KEY (visitor_id) REFERENCES visitors(visitor_id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_visits_visitor_utc ON visits(visitor_id, visited_at_utc DESC, id DESC);

  CREATE TABLE IF NOT EXISTS verified_geo_cache_v3 (
    ip_address TEXT PRIMARY KEY,
    city TEXT NOT NULL,
    region TEXT NOT NULL,
    country TEXT NOT NULL,
    country_code TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    isp TEXT NOT NULL,
    org TEXT NOT NULL,
    asn TEXT NOT NULL,
    is_vpn_or_hosting INTEGER NOT NULL DEFAULT 0,
    verified_at_ms INTEGER NOT NULL
  );
`);

// Add isp, org, asn, latitude, longitude columns to existing tables if migrating from earlier schema
for (const col of ['isp', 'org', 'asn']) {
  try {
    db.exec(`ALTER TABLE visits ADD COLUMN ${col} TEXT NOT NULL DEFAULT 'Unknown'`);
  } catch {
    // Column already exists
  }
}
for (const col of ['latitude', 'longitude']) {
  try {
    db.exec(`ALTER TABLE visits ADD COLUMN ${col} REAL`);
  } catch {
    // Column already exists
  }
  try {
    db.exec(`ALTER TABLE verified_geo_cache_v3 ADD COLUMN ${col} REAL`);
  } catch {
    // Column already exists
  }
}

function signVisitorId(visitorId: string): string {
  return crypto.createHmac('sha256', HMAC_SECRET).update(visitorId).digest('hex');
}

function verifyVisitorToken(visitorId: string | undefined | null, token: string | undefined | null): boolean {
  if (!visitorId || !token || typeof visitorId !== 'string' || typeof token !== 'string') {
    return false;
  }
  const expected = signVisitorId(visitorId);
  if (expected.length !== token.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(token, 'hex'));
  } catch {
    return false;
  }
}

function generateVisitorId(): string {
  return 'vid_' + crypto.randomBytes(10).toString('hex');
}

function generateSessionId(): string {
  return 'ses_' + crypto.randomBytes(6).toString('hex');
}

function generateVisitId(): string {
  return 'vst_' + crypto.randomBytes(8).toString('hex');
}

export function normalizeIpCandidate(raw: string | undefined | null): string | null {
  if (!raw || typeof raw !== 'string') return null;
  let candidate = raw.trim().replace(/^["']|["']$/g, '');
  if (!candidate) return null;

  if (candidate.toLowerCase().startsWith('for=')) {
    candidate = candidate.slice(4).trim().replace(/^["']|["']$/g, '');
  }

  if (candidate.startsWith('[')) {
    const closeBracket = candidate.indexOf(']');
    if (closeBracket !== -1) {
      candidate = candidate.slice(1, closeBracket);
    }
  } else {
    const colonCount = (candidate.match(/:/g) || []).length;
    if (colonCount === 1 && candidate.includes('.')) {
      candidate = candidate.split(':')[0];
    }
  }

  if (candidate.toLowerCase().startsWith('::ffff:')) {
    candidate = candidate.slice(7);
  }

  const zoneIdx = candidate.indexOf('%');
  if (zoneIdx !== -1) {
    candidate = candidate.slice(0, zoneIdx);
  }

  const ipVersion = net.isIP(candidate);
  if (ipVersion === 0) return null;
  return candidate;
}

export function isPublicRoutableIp(ip: string | null): boolean {
  if (!ip) return false;
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split('.').map((n) => parseInt(n, 10));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false;
    return true;
  }

  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::' || lower === '0:0:0:0:0:0:0:1' || lower === '0:0:0:0:0:0:0:0') {
      return false;
    }
    if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
      return false;
    }
    if (lower.startsWith('fc') || lower.startsWith('fd')) {
      return false;
    }
    if (lower.startsWith('ff')) {
      return false;
    }
    return true;
  }

  return false;
}

export function extractVisitorIp(req: express.Request): { ip: string; isPublic: boolean } {
  const singleHeaders = [
    'cf-connecting-ip',
    'true-client-ip',
    'x-real-ip',
    'x-client-ip',
    'x-appengine-user-ip',
  ];

  for (const headerName of singleHeaders) {
    const rawVal = req.headers[headerName];
    if (typeof rawVal === 'string' && rawVal.trim()) {
      const normalized = normalizeIpCandidate(rawVal);
      if (normalized && isPublicRoutableIp(normalized)) {
        return { ip: normalized, isPublic: true };
      }
    }
  }

  const xff = req.headers['x-forwarded-for'];
  const xffList = Array.isArray(xff) ? xff.join(',') : typeof xff === 'string' ? xff : '';
  if (xffList) {
    const hops = xffList.split(',');
    for (const hop of hops) {
      const normalized = normalizeIpCandidate(hop);
      if (normalized && isPublicRoutableIp(normalized)) {
        return { ip: normalized, isPublic: true };
      }
    }
  }

  const forwarded = req.headers['forwarded'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    const segments = forwarded.split(/[,;]/);
    for (const seg of segments) {
      if (seg.trim().toLowerCase().startsWith('for=')) {
        const normalized = normalizeIpCandidate(seg.trim());
        if (normalized && isPublicRoutableIp(normalized)) {
          return { ip: normalized, isPublic: true };
        }
      }
    }
  }

  const socketIp = normalizeIpCandidate(req.socket?.remoteAddress);
  if (socketIp && isPublicRoutableIp(socketIp)) {
    return { ip: socketIp, isPublic: true };
  }

  return { ip: 'Unavailable', isPublic: false };
}

/**
 * Formats recognizable ISP names (Jio, Airtel, BSNL, ACT, Vodafone Idea, etc.)
 * strictly when the geolocation provider's ISP or Organization string identifies them.
 * Never guesses based on country, city, or IP prefix.
 */
export function normalizeIspAndOrg(
  rawIspInput: unknown,
  rawOrgInput: unknown,
  rawAsnInput: unknown,
  explicitHostingOrVpnFlag = false
): {
  isp: string;
  org: string;
  asn: string;
  isVpnOrHosting: boolean;
} {
  let cleanIsp = typeof rawIspInput === 'string' ? rawIspInput.trim() : '';
  let cleanOrg = typeof rawOrgInput === 'string' ? rawOrgInput.trim() : '';
  let cleanAsn = '';

  if (typeof rawAsnInput === 'number' && Number.isFinite(rawAsnInput)) {
    cleanAsn = `AS${rawAsnInput}`;
  } else if (typeof rawAsnInput === 'string' && rawAsnInput.trim()) {
    const trimmedAsn = rawAsnInput.trim();
    cleanAsn = /^AS\d+/i.test(trimmedAsn) ? trimmedAsn.toUpperCase() : `AS${trimmedAsn}`;
  }

  // Strip leading AS number if embedded in org string (e.g. "AS55836 Reliance Jio Infocomm Limited")
  const stripEmbeddedAsn = (text: string): { asnFound: string; rest: string } => {
    const match = text.match(/^(AS\d+)\s+(.+)$/i);
    if (match) {
      return { asnFound: match[1].toUpperCase(), rest: match[2].trim() };
    }
    return { asnFound: '', rest: text };
  };

  if (cleanIsp) {
    const parsed = stripEmbeddedAsn(cleanIsp);
    if (!cleanAsn && parsed.asnFound) cleanAsn = parsed.asnFound;
    cleanIsp = parsed.rest;
  }
  if (cleanOrg) {
    const parsed = stripEmbeddedAsn(cleanOrg);
    if (!cleanAsn && parsed.asnFound) cleanAsn = parsed.asnFound;
    cleanOrg = parsed.rest;
  }

  const combinedSource = `${cleanIsp} ${cleanOrg}`.trim();
  if (!combinedSource || combinedSource.toLowerCase() === 'unknown') {
    return {
      isp: 'Unknown',
      org: 'Unknown',
      asn: cleanAsn || 'Unknown',
      isVpnOrHosting: explicitHostingOrVpnFlag,
    };
  }

  const lower = combinedSource.toLowerCase();
  let recognizableBrand: string | null = null;

  if (/\bjio\b|reliance jio/i.test(combinedSource)) {
    recognizableBrand = 'Jio';
  } else if (/\bairtel\b|bharti airtel|bharti hexacom/i.test(combinedSource)) {
    recognizableBrand = 'Airtel';
  } else if (/\bbsnl\b|bharat sanchar|national internet backbone/i.test(combinedSource)) {
    recognizableBrand = 'BSNL';
  } else if (/\bact\b|act fibernet|atria convergence|beam telecom/i.test(combinedSource)) {
    recognizableBrand = 'ACT';
  } else if (/vodafone idea|\bvodafone\b|\bidea cellular\b/i.test(combinedSource)) {
    recognizableBrand = 'Vodafone Idea';
  } else if (/tata play fiber|tata teleservices|tata communications/i.test(combinedSource)) {
    recognizableBrand = 'Tata';
  } else if (/\bhathway\b/i.test(combinedSource)) {
    recognizableBrand = 'Hathway';
  } else if (/\bexcitel\b/i.test(combinedSource)) {
    recognizableBrand = 'Excitel';
  } else if (/\bmtnl\b|mahanagar telephone/i.test(combinedSource)) {
    recognizableBrand = 'MTNL';
  } else if (/\brailwire\b|\brailtel\b/i.test(combinedSource)) {
    recognizableBrand = 'RailWire';
  } else if (/\byou broadband\b/i.test(combinedSource)) {
    recognizableBrand = 'YOU Broadband';
  } else if (/\basianet\b/i.test(combinedSource)) {
    recognizableBrand = 'Asianet';
  } else if (/\balliance broadband\b/i.test(combinedSource)) {
    recognizableBrand = 'Alliance Broadband';
  }

  const primaryProvider = cleanIsp || cleanOrg;
  let formattedIsp = primaryProvider;

  if (recognizableBrand) {
    if (primaryProvider.toLowerCase() === recognizableBrand.toLowerCase()) {
      formattedIsp = recognizableBrand;
    } else {
      formattedIsp = `${recognizableBrand} (${primaryProvider})`;
    }
  }

  const hostingOrVpnKeywords = [
    'mullvad',
    'nordvpn',
    'expressvpn',
    'protonvpn',
    'surfshark',
    'cyberghost',
    'm247',
    'datacamp',
    'tzulo',
    'digitalocean',
    'linode',
    'vultr',
    'choopa',
    'hetzner',
    'ovh',
    'leaseweb',
    'amazon',
    'aws',
    'google cloud',
    'google llc',
    'cloudflare',
    'microsoft corporation',
    'akamai',
    'fastly',
    'zscaler',
    'netskope',
    'palo alto networks',
  ];

  const isVpnOrHosting =
    explicitHostingOrVpnFlag || hostingOrVpnKeywords.some((kw) => lower.includes(kw));

  return {
    isp: formattedIsp || 'Unknown',
    org: cleanOrg || cleanIsp || 'Unknown',
    asn: cleanAsn || 'Unknown',
    isVpnOrHosting,
  };
}

async function lookupVerifiedGeolocation(visitorIp: string, isPublic: boolean): Promise<LocationInfo> {
  if (!isPublic || !visitorIp || visitorIp === 'Unavailable') {
    return {
      publicIp: 'Unavailable',
      city: 'Unavailable',
      region: 'Unavailable',
      country: 'Unavailable',
      countryCode: '',
      latitude: null,
      longitude: null,
      isp: 'Unknown',
      org: 'Unknown',
      asn: 'Unknown',
      isVpnOrHosting: false,
      isIpVerified: false,
      isLocationVerified: false,
    };
  }

  const nowMs = Date.now();
  const cached = db
    .prepare(
      'SELECT city, region, country, country_code, latitude, longitude, isp, org, asn, is_vpn_or_hosting, verified_at_ms FROM verified_geo_cache_v3 WHERE ip_address = ?'
    )
    .get(visitorIp) as
    | {
        city: string;
        region: string;
        country: string;
        country_code: string;
        latitude: number | null;
        longitude: number | null;
        isp: string;
        org: string;
        asn: string;
        is_vpn_or_hosting: number;
        verified_at_ms: number;
      }
    | undefined;

  if (
    cached &&
    nowMs - cached.verified_at_ms < 6 * 3600 * 1000 &&
    cached.isp !== 'Unknown' &&
    typeof cached.latitude === 'number' &&
    typeof cached.longitude === 'number'
  ) {
    return {
      publicIp: visitorIp,
      city: cached.city,
      region: cached.region,
      country: cached.country,
      countryCode: cached.country_code,
      latitude: cached.latitude,
      longitude: cached.longitude,
      isp: cached.isp,
      org: cached.org,
      asn: cached.asn,
      isVpnOrHosting: Boolean(cached.is_vpn_or_hosting),
      isIpVerified: true,
      isLocationVerified: cached.city !== 'Unavailable' || cached.country !== 'Unavailable',
    };
  }

  const cleanField = (val: unknown): string => {
    if (typeof val !== 'string') return 'Unknown';
    const trimmed = val.trim();
    return trimmed.length > 0 ? trimmed : 'Unknown';
  };

  // Provider 1: ipwho.is/{visitorIp}
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const resp = await fetch(`https://ipwho.is/${encodeURIComponent(visitorIp)}`, {
      signal: controller.signal,
      headers: { Accept: 'application/json', 'User-Agent': 'IntelSystem/1.0' },
    });
    clearTimeout(timer);

    if (resp.ok) {
      const data = (await resp.json()) as Record<string, unknown>;
      const providerIp = normalizeIpCandidate(typeof data.ip === 'string' ? data.ip : '');
      if (
        data.success !== false &&
        providerIp &&
        providerIp.toLowerCase() === visitorIp.toLowerCase()
      ) {
        const city = cleanField(data.city);
        const region = cleanField(data.region);
        const country = cleanField(data.country);
        const countryCode = typeof data.country_code === 'string' ? data.country_code.trim() : '';
        const latitude = typeof data.latitude === 'number' && Number.isFinite(data.latitude) ? data.latitude : null;
        const longitude = typeof data.longitude === 'number' && Number.isFinite(data.longitude) ? data.longitude : null;
        const conn = (data.connection as Record<string, unknown>) || {};
        const sec = (data.security as Record<string, unknown>) || {};
        const explicitVpn = Boolean(sec.vpn || sec.proxy || sec.tor || sec.hosting);

        const netDetails = normalizeIspAndOrg(conn.isp, conn.org, conn.asn, explicitVpn);

        if (city !== 'Unknown' || country !== 'Unknown' || netDetails.isp !== 'Unknown') {
          db.prepare(
            `INSERT OR REPLACE INTO verified_geo_cache_v3 (
              ip_address, city, region, country, country_code, latitude, longitude, isp, org, asn, is_vpn_or_hosting, verified_at_ms
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            visitorIp,
            city,
            region,
            country,
            countryCode,
            latitude,
            longitude,
            netDetails.isp,
            netDetails.org,
            netDetails.asn,
            netDetails.isVpnOrHosting ? 1 : 0,
            nowMs
          );

          return {
            publicIp: visitorIp,
            city,
            region,
            country,
            countryCode,
            latitude,
            longitude,
            isp: netDetails.isp,
            org: netDetails.org,
            asn: netDetails.asn,
            isVpnOrHosting: netDetails.isVpnOrHosting,
            isIpVerified: true,
            isLocationVerified: city !== 'Unknown' || country !== 'Unknown',
          };
        }
      }
    }
  } catch {
    // Proceed to fallback provider
  }

  // Provider 2: ipapi.co/{visitorIp}/json/
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const resp = await fetch(`https://ipapi.co/${encodeURIComponent(visitorIp)}/json/`, {
      signal: controller.signal,
      headers: { Accept: 'application/json', 'User-Agent': 'IntelSystem/1.0' },
    });
    clearTimeout(timer);

    if (resp.ok) {
      const data = (await resp.json()) as Record<string, unknown>;
      const providerIp = normalizeIpCandidate(typeof data.ip === 'string' ? data.ip : '');
      if (
        !data.error &&
        providerIp &&
        providerIp.toLowerCase() === visitorIp.toLowerCase()
      ) {
        const city = cleanField(data.city);
        const region = cleanField(data.region);
        const country = cleanField(data.country_name || data.country);
        const countryCode = typeof data.country_code === 'string' ? data.country_code.trim() : '';
        const latitude = typeof data.latitude === 'number' && Number.isFinite(data.latitude) ? data.latitude : null;
        const longitude = typeof data.longitude === 'number' && Number.isFinite(data.longitude) ? data.longitude : null;
        const netDetails = normalizeIspAndOrg(data.org, data.org, data.asn, false);

        if (city !== 'Unknown' || country !== 'Unknown' || netDetails.isp !== 'Unknown') {
          db.prepare(
            `INSERT OR REPLACE INTO verified_geo_cache_v3 (
              ip_address, city, region, country, country_code, latitude, longitude, isp, org, asn, is_vpn_or_hosting, verified_at_ms
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            visitorIp,
            city,
            region,
            country,
            countryCode,
            latitude,
            longitude,
            netDetails.isp,
            netDetails.org,
            netDetails.asn,
            netDetails.isVpnOrHosting ? 1 : 0,
            nowMs
          );

          return {
            publicIp: visitorIp,
            city,
            region,
            country,
            countryCode,
            latitude,
            longitude,
            isp: netDetails.isp,
            org: netDetails.org,
            asn: netDetails.asn,
            isVpnOrHosting: netDetails.isVpnOrHosting,
            isIpVerified: true,
            isLocationVerified: city !== 'Unknown' || country !== 'Unknown',
          };
        }
      }
    }
  } catch {
    // Proceed to tertiary fallback
  }

  // Provider 3: freeipapi.com/api/json/{visitorIp}
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const resp = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(visitorIp)}`, {
      signal: controller.signal,
      headers: { Accept: 'application/json', 'User-Agent': 'IntelSystem/1.0' },
    });
    clearTimeout(timer);

    if (resp.ok) {
      const data = (await resp.json()) as Record<string, unknown>;
      const providerIp = normalizeIpCandidate(typeof data.ipAddress === 'string' ? data.ipAddress : '');
      if (providerIp && providerIp.toLowerCase() === visitorIp.toLowerCase()) {
        const city = cleanField(data.cityName);
        const region = cleanField(data.regionName);
        const country = cleanField(data.countryName);
        const countryCode = typeof data.countryCode === 'string' ? data.countryCode.trim() : '';
        const latitude = typeof data.latitude === 'number' && Number.isFinite(data.latitude) ? data.latitude : null;
        const longitude = typeof data.longitude === 'number' && Number.isFinite(data.longitude) ? data.longitude : null;
        const netDetails = normalizeIspAndOrg(
          data.asnOrganization,
          data.asnOrganization,
          data.asn,
          Boolean(data.isProxy)
        );

        if (city !== 'Unknown' || country !== 'Unknown' || netDetails.isp !== 'Unknown') {
          db.prepare(
            `INSERT OR REPLACE INTO verified_geo_cache_v3 (
              ip_address, city, region, country, country_code, latitude, longitude, isp, org, asn, is_vpn_or_hosting, verified_at_ms
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            visitorIp,
            city,
            region,
            country,
            countryCode,
            latitude,
            longitude,
            netDetails.isp,
            netDetails.org,
            netDetails.asn,
            netDetails.isVpnOrHosting ? 1 : 0,
            nowMs
          );

          return {
            publicIp: visitorIp,
            city,
            region,
            country,
            countryCode,
            latitude,
            longitude,
            isp: netDetails.isp,
            org: netDetails.org,
            asn: netDetails.asn,
            isVpnOrHosting: netDetails.isVpnOrHosting,
            isIpVerified: true,
            isLocationVerified: city !== 'Unknown' || country !== 'Unknown',
          };
        }
      }
    }
  } catch {
    // Ignore
  }

  return {
    publicIp: visitorIp,
    city: 'Unavailable',
    region: 'Unavailable',
    country: 'Unavailable',
    countryCode: '',
    latitude: null,
    longitude: null,
    isp: 'Unknown',
    org: 'Unknown',
    asn: 'Unknown',
    isVpnOrHosting: false,
    isIpVerified: true,
    isLocationVerified: false,
  };
}

function sanitizeBrowserDevice(input: Partial<BrowserDeviceInfo> | undefined): BrowserDeviceInfo {
  const safeStr = (val: unknown, fallback: string): string => {
    if (typeof val !== 'string') return fallback;
    const t = val.trim();
    return t.length > 0 ? t.slice(0, 120) : fallback;
  };

  const validDeviceTypes = ['Desktop', 'Mobile', 'Tablet', 'Unknown'] as const;
  const rawType = input?.deviceType;
  const deviceType: BrowserDeviceInfo['deviceType'] =
    rawType && validDeviceTypes.includes(rawType) ? rawType : 'Unknown';

  return {
    browser: safeStr(input?.browser, 'Unknown'),
    os: safeStr(input?.os, 'Unknown'),
    deviceType,
    platform: safeStr(input?.platform, 'Unavailable'),
    screenResolution: safeStr(input?.screenResolution, 'Unavailable'),
    pixelRatio: safeStr(input?.pixelRatio, 'Unavailable'),
    language: safeStr(input?.language, 'Unavailable'),
    timezone: safeStr(input?.timezone, 'Unavailable'),
  };
}

interface SpeedTestLedger {
  testId: string;
  visitorKey: string;
  sessionKey: string;
  ipKey: string;
  createdAtMs: number;
  expiresAtMs: number;
  downloadedBytes: number;
  uploadedBytes: number;
  activeStreams: number;
  completed: boolean;
}

const activeSpeedTests = new Map<string, SpeedTestLedger>();
const visitorTestTimestamps = new Map<string, number[]>();
const sessionTestCounts = new Map<string, number>();
const ipTestTimestamps = new Map<string, number[]>();

const RATE_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const MAX_TESTS_PER_VISITOR_WINDOW = 120; // Supports automatic 10-second speed test intervals (60 per 10m + manual)
const MAX_TESTS_PER_SESSION = 1000;
const MAX_TESTS_PER_IP_WINDOW = 360; // CGNAT-safe secondary limit
const MAX_CONCURRENT_TESTS_PER_IP = 8;
const MAX_CONCURRENT_TESTS_PER_INSTANCE = 24;

function detectServerRegion(req?: express.Request): {
  regionCode: string;
  regionLabel: string;
} {
  const envRegion =
    process.env.CLOUD_RUN_REGION ||
    process.env.GOOGLE_CLOUD_REGION ||
    '';
  const appUrl = process.env.APP_URL || '';
  const hostHeader = req ? String(req.headers['x-forwarded-host'] || req.headers.host || '') : '';
  const combined = `${envRegion} ${appUrl} ${hostHeader}`.toLowerCase();

  const regionNames: Record<string, string> = {
    'asia-southeast1': 'asia-southeast1 (Singapore)',
    'asia-south1': 'asia-south1 (Mumbai, India)',
    'asia-south2': 'asia-south2 (Delhi, India)',
    'asia-east1': 'asia-east1 (Taiwan)',
    'asia-northeast1': 'asia-northeast1 (Tokyo, Japan)',
    'europe-west1': 'europe-west1 (Belgium)',
    'europe-west2': 'europe-west2 (London, UK)',
    'us-central1': 'us-central1 (Iowa, USA)',
    'us-east1': 'us-east1 (South Carolina, USA)',
    'us-west1': 'us-west1 (Oregon, USA)',
  };

  for (const [code, label] of Object.entries(regionNames)) {
    if (combined.includes(code)) {
      return { regionCode: code, regionLabel: label };
    }
  }

  return {
    regionCode: 'asia-southeast1',
    regionLabel: 'asia-southeast1 (Singapore)',
  };
}

function pruneSpeedTestState(nowMs: number): void {
  for (const [testId, ledger] of activeSpeedTests.entries()) {
    if (nowMs > ledger.expiresAtMs || (ledger.completed && nowMs - ledger.createdAtMs > 5000)) {
      activeSpeedTests.delete(testId);
    }
  }
  for (const [key, list] of visitorTestTimestamps.entries()) {
    const filtered = list.filter((ts) => nowMs - ts < RATE_WINDOW_MS);
    if (filtered.length === 0) visitorTestTimestamps.delete(key);
    else visitorTestTimestamps.set(key, filtered);
  }
  for (const [key, list] of ipTestTimestamps.entries()) {
    const filtered = list.filter((ts) => nowMs - ts < RATE_WINDOW_MS);
    if (filtered.length === 0) ipTestTimestamps.delete(key);
    else ipTestTimestamps.set(key, filtered);
  }
}

function createSignedSpeedTestToken(
  testId: string,
  expiresAtMs: number,
  visitorKey: string
): string {
  const vHash = crypto.createHash('sha256').update(visitorKey).digest('hex').slice(0, 12);
  const payload = `${testId}.${expiresAtMs}.${vHash}`;
  const sig = crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(`speedtest:${payload}`)
    .digest('hex')
    .slice(0, 24);
  return `${payload}.${sig}`;
}

function verifyAndGetSpeedTestLedger(
  rawToken: string | undefined | null,
  visitorKey: string,
  ipKey: string
): { valid: boolean; reason?: string; ledger?: SpeedTestLedger } {
  if (!rawToken || typeof rawToken !== 'string') {
    return { valid: false, reason: 'Missing speed test authorization token.' };
  }

  const parts = rawToken.trim().split('.');
  if (parts.length !== 4) {
    return { valid: false, reason: 'Malformed speed test token.' };
  }

  const [testId, expStr, vHash, providedSig] = parts;
  const expiresAtMs = parseInt(expStr, 10);
  const nowMs = Date.now();

  if (Number.isNaN(expiresAtMs) || nowMs > expiresAtMs) {
    return { valid: false, reason: 'Speed test token has expired.' };
  }

  const payload = `${testId}.${expiresAtMs}.${vHash}`;
  const expectedSig = crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(`speedtest:${payload}`)
    .digest('hex')
    .slice(0, 24);

  if (
    providedSig.length !== expectedSig.length ||
    !crypto.timingSafeEqual(Buffer.from(providedSig), Buffer.from(expectedSig))
  ) {
    return { valid: false, reason: 'Invalid speed test token signature.' };
  }

  let ledger = activeSpeedTests.get(testId);
  if (!ledger) {
    // Rehydrate ledger if request landed on a different Cloud Run instance
    ledger = {
      testId,
      visitorKey,
      sessionKey: vHash,
      ipKey,
      createdAtMs: nowMs,
      expiresAtMs,
      downloadedBytes: 0,
      uploadedBytes: 0,
      activeStreams: 0,
      completed: false,
    };
    activeSpeedTests.set(testId, ledger);
  }

  if (ledger.completed) {
    return { valid: false, reason: 'Speed test session is already completed.' };
  }

  return { valid: true, ledger };
}

async function startServer() {
  const app = express();
  app.set('trust proxy', true);
  app.use(cookieParser());

  // Ensure HTTP Permissions-Policy header allows compute-pressure in both top-level and embedded contexts
  app.use((_req, res, next) => {
    res.setHeader('Permissions-Policy', 'compute-pressure=*');
    next();
  });

  app.get('/api/network/ping', (_req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Timing-Allow-Origin', '*');
    res.status(200).json({ ok: true, serverTimestampMs: Date.now() });
  });

  // Streaming Download Endpoint: 4 concurrent streams, max 64 MB aggregate per test, non-compressible 64KB chunks
  app.get('/api/network/download', (req, res) => {
    const nowMs = Date.now();
    pruneSpeedTestState(nowMs);

    const token = typeof req.query.token === 'string' ? req.query.token : '';
    const { ip: extractedIp } = extractVisitorIp(req);
    const visitorKey =
      (req.cookies?.intel_http_vid as string | undefined) || extractedIp || 'anon';

    const verification = verifyAndGetSpeedTestLedger(token, visitorKey, extractedIp);
    if (!verification.valid || !verification.ledger) {
      res.status(403).json({ error: verification.reason || 'Unauthorized speed test request.' });
      return;
    }

    const ledger = verification.ledger;
    if (ledger.activeStreams >= SPEED_TEST_CONCURRENT_STREAMS + 2) {
      res.status(429).json({ error: 'Concurrent stream limit exceeded for this speed test.' });
      return;
    }

    const remainingBudget = SPEED_TEST_MAX_TOTAL_DOWNLOAD_BYTES - ledger.downloadedBytes;
    if (remainingBudget <= 0) {
      res.status(429).json({ error: 'Maximum 64 MB download transfer limit reached for this test.' });
      return;
    }

    const requestedBytes = parseInt(String(req.query.bytes || 2 * 1024 * 1024), 10);
    const clampedRequest = Number.isNaN(requestedBytes)
      ? 2 * 1024 * 1024
      : Math.max(65536, Math.min(SPEED_TEST_MAX_STREAM_DOWNLOAD_BYTES, requestedBytes));
    const targetBytes = Math.min(clampedRequest, remainingBudget);

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Encoding', 'identity');
    res.setHeader('Content-Length', String(targetBytes));
    res.setHeader(
      'Cache-Control',
      'no-store, no-cache, must-revalidate, proxy-revalidate, no-transform'
    );
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Timing-Allow-Origin', '*');
    res.setHeader('X-Accel-Buffering', 'no');

    ledger.activeStreams += 1;
    let bytesSentForStream = 0;
    let streamClosed = false;

    const cleanupStream = () => {
      if (streamClosed) return;
      streamClosed = true;
      ledger.activeStreams = Math.max(0, ledger.activeStreams - 1);
      clearTimeout(streamTimer);
    };

    const streamTimer = setTimeout(() => {
      cleanupStream();
      if (!res.writableEnded) {
        res.end();
      }
    }, SPEED_TEST_STREAM_TIMEOUT_MS);

    req.on('close', cleanupStream);
    res.on('close', cleanupStream);
    res.on('error', cleanupStream);

    const writeNextChunk = () => {
      while (!streamClosed && bytesSentForStream < targetBytes) {
        const remainingInTest = SPEED_TEST_MAX_TOTAL_DOWNLOAD_BYTES - ledger.downloadedBytes;
        if (remainingInTest <= 0) {
          cleanupStream();
          res.end();
          return;
        }

        const remainingInStream = targetBytes - bytesSentForStream;
        const toWrite = Math.min(
          HIGH_ENTROPY_64KB_CHUNK.length,
          remainingInStream,
          remainingInTest
        );

        const slice =
          toWrite === HIGH_ENTROPY_64KB_CHUNK.length
            ? HIGH_ENTROPY_64KB_CHUNK
            : HIGH_ENTROPY_64KB_CHUNK.subarray(0, toWrite);

        bytesSentForStream += toWrite;
        ledger.downloadedBytes += toWrite;

        const canContinue = res.write(slice);
        if (bytesSentForStream >= targetBytes) {
          cleanupStream();
          res.end();
          return;
        }
        if (!canContinue) {
          res.once('drain', writeNextChunk);
          return;
        }
      }
    };

    writeNextChunk();
  });

  // Streaming Upload Endpoint: mounted BEFORE express.json(), counts actual bytes received without disk/RAM buffering
  app.post('/api/network/upload', (req, res) => {
    const nowMs = Date.now();
    pruneSpeedTestState(nowMs);

    const token =
      (typeof req.query.token === 'string' ? req.query.token : '') ||
      (typeof req.headers['x-speedtest-token'] === 'string' ? req.headers['x-speedtest-token'] : '');
    const { ip: extractedIp } = extractVisitorIp(req);
    const visitorKey =
      (req.cookies?.intel_http_vid as string | undefined) || extractedIp || 'anon';

    const verification = verifyAndGetSpeedTestLedger(token, visitorKey, extractedIp);
    if (!verification.valid || !verification.ledger) {
      req.resume();
      res.status(403).json({ error: verification.reason || 'Unauthorized upload test request.' });
      return;
    }

    const ledger = verification.ledger;
    if (ledger.activeStreams >= SPEED_TEST_CONCURRENT_STREAMS + 2) {
      req.resume();
      res.status(429).json({ error: 'Concurrent upload stream limit exceeded.' });
      return;
    }

    if (ledger.uploadedBytes >= SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES) {
      req.resume();
      res.status(429).json({ error: 'Maximum 40 MB upload transfer limit reached for this test.' });
      return;
    }

    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Timing-Allow-Origin', '*');

    ledger.activeStreams += 1;
    const streamStartMs = Date.now();
    let streamReceivedBytes = 0;
    let finished = false;
    let exceededCap = false;

    const cleanupUpload = () => {
      if (finished) return;
      finished = true;
      ledger.activeStreams = Math.max(0, ledger.activeStreams - 1);
      clearTimeout(uploadTimer);
    };

    const uploadTimer = setTimeout(() => {
      cleanupUpload();
      if (!res.headersSent) {
        res.status(408).json({
          ok: false,
          error: 'Upload stream timed out.',
          receivedBytes: streamReceivedBytes,
        });
      }
    }, SPEED_TEST_STREAM_TIMEOUT_MS);

    req.on('data', (chunk: Buffer) => {
      if (finished || exceededCap) return;
      const chunkLen = chunk.length;
      if (
        streamReceivedBytes + chunkLen > SPEED_TEST_MAX_STREAM_UPLOAD_BYTES ||
        ledger.uploadedBytes + chunkLen > SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES
      ) {
        exceededCap = true;
        cleanupUpload();
        req.resume();
        if (!res.headersSent) {
          res.status(413).json({
            ok: false,
            error: 'Upload transfer limit exceeded.',
            receivedBytes: streamReceivedBytes,
          });
        }
        return;
      }
      streamReceivedBytes += chunkLen;
      ledger.uploadedBytes += chunkLen;
    });

    req.on('end', () => {
      if (finished || exceededCap) return;
      cleanupUpload();
      const elapsedServerMs = Math.max(1, Date.now() - streamStartMs);
      res.status(200).json({
        ok: true,
        receivedBytes: streamReceivedBytes,
        totalTestUploadedBytes: ledger.uploadedBytes,
        elapsedServerMs,
        serverTimestampMs: Date.now(),
      });
    });

    req.on('aborted', () => {
      cleanupUpload();
    });

    req.on('error', () => {
      cleanupUpload();
    });
  });

  app.use(express.json({ limit: '128kb' }));

  // Initialize a user-triggered Speed Test session with rate limiting & short-lived signed token
  app.post('/api/network/speed-test/init', (req, res) => {
    const nowMs = Date.now();
    pruneSpeedTestState(nowMs);

    const { ip: extractedIp } = extractVisitorIp(req);
    const body = (req.body || {}) as { visitorId?: string; sessionId?: string };
    const cookieVid = req.cookies?.intel_http_vid as string | undefined;

    const visitorKey = cookieVid || (typeof body.visitorId === 'string' && body.visitorId.trim()) || extractedIp || 'anon';
    const sessionKey = (typeof body.sessionId === 'string' && body.sessionId.trim()) || visitorKey;
    const ipKey = extractedIp && extractedIp !== 'Unavailable' ? extractedIp : visitorKey;

    // 1. Check global instance concurrency & replace any stale test for the same visitor
    let activeCount = 0;
    let activeIpCount = 0;
    for (const [existingId, ledger] of activeSpeedTests.entries()) {
      if (ledger.visitorKey === visitorKey) {
        ledger.completed = true;
        activeSpeedTests.delete(existingId);
        continue;
      }
      if (!ledger.completed && nowMs < ledger.expiresAtMs && nowMs - ledger.createdAtMs < 20000) {
        activeCount += 1;
        if (ledger.ipKey === ipKey) {
          activeIpCount += 1;
        }
      }
    }

    if (activeCount >= MAX_CONCURRENT_TESTS_PER_INSTANCE) {
      res.status(503).json({
        error: 'Server speed-test capacity is currently busy. Please try again in a few seconds.',
      });
      return;
    }

    if (activeIpCount >= MAX_CONCURRENT_TESTS_PER_IP) {
      res.status(429).json({
        error: 'Too many simultaneous speed tests from this network. Please wait a moment.',
      });
      return;
    }

    // 2. Per-visitor rolling 10-minute rate limit
    const visitorHistory = visitorTestTimestamps.get(visitorKey) || [];
    if (visitorHistory.length >= MAX_TESTS_PER_VISITOR_WINDOW) {
      const oldestMs = visitorHistory[0];
      const retrySec = Math.max(5, Math.ceil((RATE_WINDOW_MS - (nowMs - oldestMs)) / 1000));
      res.status(429).json({
        error: `Rate limit reached (${MAX_TESTS_PER_VISITOR_WINDOW} tests per 10 minutes). Try again in ${retrySec}s.`,
      });
      return;
    }

    // 3. Per-session limit
    const sessionCount = sessionTestCounts.get(sessionKey) || 0;
    if (sessionCount >= MAX_TESTS_PER_SESSION) {
      res.status(429).json({
        error: `Session speed-test limit (${MAX_TESTS_PER_SESSION} tests) reached.`,
      });
      return;
    }

    // 4. CGNAT-aware per-IP secondary rate limit
    const ipHistory = ipTestTimestamps.get(ipKey) || [];
    if (ipHistory.length >= MAX_TESTS_PER_IP_WINDOW) {
      res.status(429).json({
        error: 'Network rate limit reached. Please wait a few minutes before running another test.',
      });
      return;
    }

    // Record test start
    visitorHistory.push(nowMs);
    visitorTestTimestamps.set(visitorKey, visitorHistory);
    sessionTestCounts.set(sessionKey, sessionCount + 1);
    ipHistory.push(nowMs);
    ipTestTimestamps.set(ipKey, ipHistory);

    const testId = 'st_' + crypto.randomBytes(8).toString('hex');
    const expiresAtMs = nowMs + SPEED_TEST_TOKEN_TTL_MS;
    const token = createSignedSpeedTestToken(testId, expiresAtMs, visitorKey);

    activeSpeedTests.set(testId, {
      testId,
      visitorKey,
      sessionKey,
      ipKey,
      createdAtMs: nowMs,
      expiresAtMs,
      downloadedBytes: 0,
      uploadedBytes: 0,
      activeStreams: 0,
      completed: false,
    });

    const { regionCode, regionLabel } = detectServerRegion(req);

    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.status(200).json({
      ok: true,
      testId,
      token,
      expiresAtMs,
      serverRegion: regionLabel,
      serverRegionCode: regionCode,
      concurrentStreams: SPEED_TEST_CONCURRENT_STREAMS,
      maxDownloadBytes: SPEED_TEST_MAX_TOTAL_DOWNLOAD_BYTES,
      maxUploadBytes: SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES,
    });
  });

  // Release active lock when a test finishes or is cancelled by the visitor
  app.post('/api/network/speed-test/complete', (req, res) => {
    const body = (req.body || {}) as { token?: string };
    const rawToken = typeof body.token === 'string' ? body.token.trim() : '';
    const testId = rawToken.split('.')[0];
    if (testId && activeSpeedTests.has(testId)) {
      const ledger = activeSpeedTests.get(testId);
      if (ledger) {
        ledger.completed = true;
      }
      activeSpeedTests.delete(testId);
    }
    res.status(200).json({ ok: true });
  });

  app.get('/api/health', (_req, res) => {
    const visitorsCount = (
      db.prepare('SELECT COUNT(*) AS count FROM visitors').get() as { count: number }
    ).count;
    const visitsCount = (
      db.prepare('SELECT COUNT(*) AS count FROM visits').get() as { count: number }
    ).count;
    const { regionCode, regionLabel } = detectServerRegion();
    res.json({ status: 'ok', visitorsCount, visitsCount, regionCode, regionLabel });
  });

  app.post('/api/visitor/identify', async (req, res) => {
    try {
      const {
        pageLoadId,
        storedVisitorId,
        storedVisitorToken,
        clientSessionId,
        browserDevice: rawBrowserDevice,
        clientGeoHint,
      } = req.body as {
        pageLoadId?: string;
        storedVisitorId?: string | null;
        storedVisitorToken?: string | null;
        clientSessionId?: string | null;
        browserDevice?: Partial<BrowserDeviceInfo>;
        clientGeoHint?: {
          ip?: string;
          city?: string;
          region?: string;
          country?: string;
          countryCode?: string;
          latitude?: number | null;
          longitude?: number | null;
          isp?: string;
          org?: string;
          asn?: string;
          isVpnOrHosting?: boolean;
        } | null;
      };

      const safePageLoadId =
        typeof pageLoadId === 'string' && pageLoadId.trim().length > 0
          ? pageLoadId.trim().slice(0, 80)
          : 'pl_' + crypto.randomBytes(8).toString('hex');

      const browserDevice = sanitizeBrowserDevice(rawBrowserDevice);

      let { ip: extractedIp, isPublic } = extractVisitorIp(req);

      if (!isPublic && clientGeoHint && typeof clientGeoHint.ip === 'string') {
        const normalizedHintIp = normalizeIpCandidate(clientGeoHint.ip);
        if (normalizedHintIp && isPublicRoutableIp(normalizedHintIp)) {
          extractedIp = normalizedHintIp;
          isPublic = true;
        }
      }

      let location = await lookupVerifiedGeolocation(extractedIp, isPublic);

      if (
        isPublic &&
        (!location.isLocationVerified || location.isp === 'Unknown' || location.latitude === null) &&
        clientGeoHint &&
        normalizeIpCandidate(clientGeoHint.ip)?.toLowerCase() === extractedIp.toLowerCase()
      ) {
        const hintNet = normalizeIspAndOrg(
          clientGeoHint.isp,
          clientGeoHint.org,
          clientGeoHint.asn,
          Boolean(clientGeoHint.isVpnOrHosting)
        );
        const hintLat =
          typeof clientGeoHint.latitude === 'number' && Number.isFinite(clientGeoHint.latitude)
            ? clientGeoHint.latitude
            : null;
        const hintLon =
          typeof clientGeoHint.longitude === 'number' && Number.isFinite(clientGeoHint.longitude)
            ? clientGeoHint.longitude
            : null;
        location = {
          publicIp: extractedIp,
          city:
            location.city !== 'Unavailable' && location.city !== 'Unknown'
              ? location.city
              : typeof clientGeoHint.city === 'string' && clientGeoHint.city
              ? clientGeoHint.city
              : 'Unknown',
          region:
            location.region !== 'Unavailable' && location.region !== 'Unknown'
              ? location.region
              : typeof clientGeoHint.region === 'string' && clientGeoHint.region
              ? clientGeoHint.region
              : 'Unknown',
          country:
            location.country !== 'Unavailable' && location.country !== 'Unknown'
              ? location.country
              : typeof clientGeoHint.country === 'string' && clientGeoHint.country
              ? clientGeoHint.country
              : 'Unknown',
          countryCode:
            location.countryCode ||
            (typeof clientGeoHint.countryCode === 'string' ? clientGeoHint.countryCode : ''),
          latitude: location.latitude !== null ? location.latitude : hintLat,
          longitude: location.longitude !== null ? location.longitude : hintLon,
          isp: location.isp !== 'Unknown' ? location.isp : hintNet.isp,
          org: location.org !== 'Unknown' ? location.org : hintNet.org,
          asn: location.asn !== 'Unknown' ? location.asn : hintNet.asn,
          isVpnOrHosting: location.isVpnOrHosting || hintNet.isVpnOrHosting,
          isIpVerified: true,
          isLocationVerified: true,
        };
      }

      const cookieVid = req.cookies?.intel_http_vid as string | undefined;
      const cookieToken = req.cookies?.intel_http_token as string | undefined;

      let existingVisitor:
        | {
            visitor_id: string;
            hmac_token: string;
            created_at_utc: string;
            updated_at_utc: string;
            active_session_id: string;
            last_activity_utc: string;
          }
        | undefined;

      let recognitionSource: IntelVisitorResponse['recognitionSource'] = 'New First-Party ID';

      if (cookieVid && verifyVisitorToken(cookieVid, cookieToken)) {
        const row = db
          .prepare('SELECT * FROM visitors WHERE visitor_id = ?')
          .get(cookieVid) as typeof existingVisitor;
        if (row) {
          existingVisitor = row;
          recognitionSource = 'First-Party Cookie';
        }
      }

      if (!existingVisitor && storedVisitorId && verifyVisitorToken(storedVisitorId, storedVisitorToken)) {
        const row = db
          .prepare('SELECT * FROM visitors WHERE visitor_id = ?')
          .get(storedVisitorId) as typeof existingVisitor;
        if (row) {
          existingVisitor = row;
          recognitionSource = 'First-Party LocalStorage';
        }
      }

      const nowUtc = new Date().toISOString();
      const nowMs = Date.now();

      let visitorId: string;
      let visitorToken: string;
      let currentSessionId: string;
      let isReturning = false;

      if (existingVisitor) {
        visitorId = existingVisitor.visitor_id;
        visitorToken = existingVisitor.hmac_token;
        isReturning = true;

        const lastActivityMs = new Date(existingVisitor.last_activity_utc).getTime();
        const isExpiredByInactivity =
          Number.isNaN(lastActivityMs) || nowMs - lastActivityMs > SESSION_EXPIRATION_MS;
        const isSameClientSession =
          Boolean(clientSessionId) && clientSessionId === existingVisitor.active_session_id;

        const existingPageLoadVisit = db
          .prepare('SELECT session_id, visited_at_utc FROM visits WHERE visitor_id = ? AND page_load_id = ?')
          .get(visitorId, safePageLoadId) as { session_id: string; visited_at_utc: string } | undefined;

        if (existingPageLoadVisit) {
          currentSessionId = existingPageLoadVisit.session_id;
        } else {
          if (isExpiredByInactivity || !isSameClientSession) {
            currentSessionId = generateSessionId();
          } else {
            currentSessionId = existingVisitor.active_session_id;
          }

          const visitId = generateVisitId();
          db.prepare(
            `INSERT OR IGNORE INTO visits (
              visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
              public_ip, city, region, country, latitude, longitude, isp, org, asn,
              browser, os, device_type, screen_resolution, language, timezone
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            visitId,
            visitorId,
            currentSessionId,
            safePageLoadId,
            nowUtc,
            location.publicIp,
            location.city,
            location.region,
            location.country,
            location.latitude,
            location.longitude,
            location.isp,
            location.org,
            location.asn,
            browserDevice.browser,
            browserDevice.os,
            browserDevice.deviceType,
            browserDevice.screenResolution,
            browserDevice.language,
            browserDevice.timezone
          );

          db.prepare(
            `UPDATE visitors
             SET updated_at_utc = ?, active_session_id = ?, last_activity_utc = ?
             WHERE visitor_id = ?`
          ).run(nowUtc, currentSessionId, nowUtc, visitorId);
        }
      } else {
        visitorId = generateVisitorId();
        visitorToken = signVisitorId(visitorId);
        currentSessionId = generateSessionId();
        isReturning = false;

        db.prepare(
          `INSERT INTO visitors (
            visitor_id, hmac_token, created_at_utc, updated_at_utc, active_session_id, last_activity_utc
          ) VALUES (?, ?, ?, ?, ?, ?)`
        ).run(visitorId, visitorToken, nowUtc, nowUtc, currentSessionId, nowUtc);

        const visitId = generateVisitId();
        db.prepare(
          `INSERT INTO visits (
            visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
            public_ip, city, region, country, latitude, longitude, isp, org, asn,
            browser, os, device_type, screen_resolution, language, timezone
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          visitId,
          visitorId,
          currentSessionId,
          safePageLoadId,
          nowUtc,
          location.publicIp,
          location.city,
          location.region,
          location.country,
          location.latitude,
          location.longitude,
          location.isp,
          location.org,
          location.asn,
          browserDevice.browser,
          browserDevice.os,
          browserDevice.deviceType,
          browserDevice.screenResolution,
          browserDevice.language,
          browserDevice.timezone
        );
      }

      const cookieOptions = {
        maxAge: 365 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax' as const,
        path: '/',
      };
      res.cookie('intel_http_vid', visitorId, cookieOptions);
      res.cookie('intel_http_token', visitorToken, cookieOptions);

      const statsAgg = db
        .prepare(
          `SELECT
            COUNT(*) AS total_visits,
            MIN(visited_at_utc) AS first_visit_utc,
            MAX(visited_at_utc) AS last_visit_utc,
            COUNT(DISTINCT session_id) AS total_sessions
           FROM visits
           WHERE visitor_id = ?`
        )
        .get(visitorId) as {
        total_visits: number;
        first_visit_utc: string | null;
        last_visit_utc: string | null;
        total_sessions: number;
      };

      const prevVisitRow = db
        .prepare(
          `SELECT visited_at_utc
           FROM visits
           WHERE visitor_id = ?
           ORDER BY visited_at_utc DESC, id DESC
           LIMIT 1 OFFSET 1`
        )
        .get(visitorId) as { visited_at_utc: string } | undefined;

      const statistics: VisitStatistics = {
        firstVisitUtc: statsAgg.first_visit_utc || nowUtc,
        lastVisitUtc: statsAgg.last_visit_utc || nowUtc,
        previousVisitUtc: prevVisitRow ? prevVisitRow.visited_at_utc : null,
        totalVisits: Number(statsAgg.total_visits) || 1,
        totalSessions: Number(statsAgg.total_sessions) || 1,
        currentSessionId,
        sessionTimeoutMinutes: SESSION_TIMEOUT_MINUTES,
      };

      if (statistics.totalVisits > 1) {
        isReturning = true;
      }

      const rawVisits = db
        .prepare(
          `SELECT
            id, visit_id, visitor_id, session_id, visited_at_utc,
            public_ip, city, region, country, latitude, longitude, isp, org, asn,
            browser, os, device_type, screen_resolution, language, timezone
           FROM visits
           WHERE visitor_id = ?
           ORDER BY visited_at_utc DESC, id DESC
           LIMIT 50`
        )
        .all(visitorId) as Array<Record<string, unknown>>;

      const visitHistory: VisitHistoryRecord[] = rawVisits.map((r) => ({
        id: Number(r.id),
        visitId: String(r.visit_id),
        visitorId: String(r.visitor_id),
        sessionId: String(r.session_id),
        visitedAtUtc: String(r.visited_at_utc),
        publicIp: String(r.public_ip),
        city: String(r.city),
        region: String(r.region),
        country: String(r.country),
        latitude: typeof r.latitude === 'number' && Number.isFinite(r.latitude) ? r.latitude : null,
        longitude: typeof r.longitude === 'number' && Number.isFinite(r.longitude) ? r.longitude : null,
        isp: String(r.isp || 'Unknown'),
        org: String(r.org || 'Unknown'),
        asn: String(r.asn || 'Unknown'),
        browser: String(r.browser),
        os: String(r.os),
        deviceType: String(r.device_type),
        screenResolution: String(r.screen_resolution),
        language: String(r.language),
        timezone: String(r.timezone),
      }));

      const payload: IntelVisitorResponse = {
        visitorId,
        visitorToken,
        isReturning,
        recognitionSource,
        location,
        browserDevice,
        statistics,
        visitHistory,
      };

      res.json(payload);
    } catch (err) {
      console.error('Error in /api/visitor/identify:', err);
      res.status(500).json({ error: 'Unable to process visitor identification request.' });
    }
  });

  app.get('/api/visitor/history/:visitorId', (req, res) => {
    const requestedVisitorId = req.params.visitorId;
    const headerToken = req.headers['x-visitor-token'] as string | undefined;
    const cookieVid = req.cookies?.intel_http_vid as string | undefined;
    const cookieToken = req.cookies?.intel_http_token as string | undefined;

    const authorizedByHeader = verifyVisitorToken(requestedVisitorId, headerToken);
    const authorizedByCookie =
      cookieVid === requestedVisitorId && verifyVisitorToken(cookieVid, cookieToken);

    if (!authorizedByHeader && !authorizedByCookie) {
      res.status(403).json({
        error: 'Forbidden: You are not authorized to access another visitor’s records.',
      });
      return;
    }

    const visits = db
      .prepare(
        `SELECT
          id, visit_id, visitor_id, session_id, visited_at_utc,
          public_ip, city, region, country, isp, org, asn,
          browser, os, device_type, screen_resolution, language, timezone
         FROM visits
         WHERE visitor_id = ?
         ORDER BY visited_at_utc DESC, id DESC
         LIMIT 50`
      )
      .all(requestedVisitorId);

    res.json({ visitorId: requestedVisitorId, visits });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Intel System running on http://0.0.0.0:${PORT}`);
  });
}

startServer();

import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import net from 'net';
import os from 'os';
import path from 'path';
import fs from 'fs';
import { createRequire } from 'module';
import dotenv from 'dotenv';
import type {
  BrowserDeviceInfo,
  LocationInfo,
  VisitStatistics,
  VisitHistoryRecord,
  SignedHistoryBackup,
  IntelVisitorResponse,
} from './src/types/visitor';

dotenv.config();

const PORT = Number(process.env.PORT) || 3000;
const SESSION_TIMEOUT_MINUTES = 30;
const SESSION_EXPIRATION_MS = SESSION_TIMEOUT_MINUTES * 60 * 1000;

const IS_SERVERLESS_RUNTIME = Boolean(
  process.env.VERCEL ||
    process.env.VERCEL_ENV ||
    process.env.AWS_LAMBDA_FUNCTION_NAME ||
    process.env.NETLIFY
);

const HMAC_SECRET =
  process.env.VISITOR_HMAC_SECRET ||
  'intel-system-first-party-hmac-secret-2026';

const SPEED_TEST_MAX_TOTAL_DOWNLOAD_BYTES = 512 * 1024 * 1024; // 512 MB max budget so fast connections can sustain full 5s download
const SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES = 256 * 1024 * 1024; // 256 MB max budget so fast connections can sustain full 5s upload
const SPEED_TEST_MAX_STREAM_DOWNLOAD_BYTES = 2 * 1024 * 1024; // 2 MB max per individual stream request (safely under Vercel 4.5 MB limit)
const SPEED_TEST_MAX_STREAM_UPLOAD_BYTES = 2 * 1024 * 1024; // 2 MB max per individual upload request (safely under Vercel 4.5 MB limit)
const SPEED_TEST_CONCURRENT_STREAMS = 4;
const SPEED_TEST_TOKEN_TTL_MS = 60 * 1000; // 60s token validity
const SPEED_TEST_STREAM_TIMEOUT_MS = 15 * 1000; // 15s hard per-stream timeout
const HIGH_ENTROPY_64KB_CHUNK = crypto.randomBytes(65536); // Non-compressible 64 KB random buffer

interface VisitorRow {
  visitor_id: string;
  hmac_token: string;
  created_at_utc: string;
  updated_at_utc: string;
  active_session_id: string;
  last_activity_utc: string;
}

interface VisitRow {
  id: number;
  visit_id: string;
  visitor_id: string;
  session_id: string;
  page_load_id: string;
  visited_at_utc: string;
  public_ip: string;
  city: string;
  region: string;
  country: string;
  latitude: number | null;
  longitude: number | null;
  isp: string;
  org: string;
  asn: string;
  browser: string;
  os: string;
  device_type: string;
  screen_resolution: string;
  language: string;
  timezone: string;
}

interface GeoCacheRow {
  ip_address: string;
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

interface PreparedStatementShim {
  get: (...params: unknown[]) => unknown;
  all: (...params: unknown[]) => unknown[];
  run: (...params: unknown[]) => { changes: number };
}

interface DatabaseAdapter {
  prepare: (sql: string) => PreparedStatementShim;
  exec: (sql: string) => void;
}

function createInMemoryDbAdapter(): DatabaseAdapter {
  const visitorsMap = new Map<string, VisitorRow>();
  const visitsList: VisitRow[] = [];
  const geoCacheMap = new Map<string, GeoCacheRow>();
  let autoIncrementId = 1;

  return {
    exec: () => {},
    prepare: (sql: string): PreparedStatementShim => {
      const normalized = sql.replace(/\s+/g, ' ').trim();

      return {
        get: (...params: unknown[]) => {
          if (normalized.includes('FROM verified_geo_cache_v3 WHERE ip_address = ?')) {
            const ip = String(params[0] || '');
            return geoCacheMap.get(ip);
          }
          if (normalized.includes('SELECT COUNT(*) AS count FROM visitors')) {
            return { count: visitorsMap.size };
          }
          if (normalized.includes('SELECT COUNT(*) AS count FROM visits')) {
            return { count: visitsList.length };
          }
          if (normalized.includes('SELECT * FROM visitors WHERE visitor_id = ?')) {
            const vid = String(params[0] || '');
            return visitorsMap.get(vid);
          }
          if (
            normalized.includes(
              'SELECT session_id, visited_at_utc FROM visits WHERE visitor_id = ? AND page_load_id = ?'
            )
          ) {
            const vid = String(params[0] || '');
            const plId = String(params[1] || '');
            const found = visitsList.find(
              (v) => v.visitor_id === vid && v.page_load_id === plId
            );
            return found
              ? { session_id: found.session_id, visited_at_utc: found.visited_at_utc }
              : undefined;
          }
          if (normalized.includes('COUNT(*) AS total_visits') && normalized.includes('FROM visits WHERE visitor_id = ?')) {
            const vid = String(params[0] || '');
            const userVisits = visitsList.filter((v) => v.visitor_id === vid);
            if (userVisits.length === 0) {
              return {
                total_visits: 0,
                first_visit_utc: null,
                last_visit_utc: null,
                total_sessions: 0,
              };
            }
            const sortedAsc = [...userVisits].sort((a, b) =>
              a.visited_at_utc.localeCompare(b.visited_at_utc)
            );
            const sessions = new Set(userVisits.map((v) => v.session_id));
            return {
              total_visits: userVisits.length,
              first_visit_utc: sortedAsc[0].visited_at_utc,
              last_visit_utc: sortedAsc[sortedAsc.length - 1].visited_at_utc,
              total_sessions: sessions.size,
            };
          }
          if (normalized.includes('LIMIT 1 OFFSET 1')) {
            const vid = String(params[0] || '');
            const userVisits = visitsList
              .filter((v) => v.visitor_id === vid)
              .sort((a, b) => b.visited_at_utc.localeCompare(a.visited_at_utc) || b.id - a.id);
            return userVisits.length > 1
              ? { visited_at_utc: userVisits[1].visited_at_utc }
              : undefined;
          }
          return undefined;
        },

        all: (...params: unknown[]) => {
          if (normalized.includes('FROM visits WHERE visitor_id = ?')) {
            const vid = String(params[0] || '');
            return visitsList
              .filter((v) => v.visitor_id === vid)
              .sort((a, b) => b.visited_at_utc.localeCompare(a.visited_at_utc) || b.id - a.id)
              .slice(0, 50);
          }
          return [];
        },

        run: (...params: unknown[]) => {
          if (normalized.includes('INSERT OR REPLACE INTO verified_geo_cache_v3')) {
            const row: GeoCacheRow = {
              ip_address: String(params[0] || ''),
              city: String(params[1] || 'Unknown'),
              region: String(params[2] || 'Unknown'),
              country: String(params[3] || 'Unknown'),
              country_code: String(params[4] || ''),
              latitude: typeof params[5] === 'number' ? params[5] : null,
              longitude: typeof params[6] === 'number' ? params[6] : null,
              isp: String(params[7] || 'Unknown'),
              org: String(params[8] || 'Unknown'),
              asn: String(params[9] || 'Unknown'),
              is_vpn_or_hosting: Number(params[10] || 0),
              verified_at_ms: Number(params[11] || Date.now()),
            };
            geoCacheMap.set(row.ip_address, row);
            return { changes: 1 };
          }
          if (normalized.includes('INSERT INTO visitors') || normalized.includes('INSERT OR REPLACE INTO visitors')) {
            const row: VisitorRow = {
              visitor_id: String(params[0] || ''),
              hmac_token: String(params[1] || ''),
              created_at_utc: String(params[2] || ''),
              updated_at_utc: String(params[3] || ''),
              active_session_id: String(params[4] || ''),
              last_activity_utc: String(params[5] || ''),
            };
            visitorsMap.set(row.visitor_id, row);
            return { changes: 1 };
          }
          if (normalized.includes('UPDATE visitors')) {
            const vid = String(params[3] || '');
            const existing = visitorsMap.get(vid);
            if (existing) {
              existing.updated_at_utc = String(params[0] || existing.updated_at_utc);
              existing.active_session_id = String(params[1] || existing.active_session_id);
              existing.last_activity_utc = String(params[2] || existing.last_activity_utc);
              return { changes: 1 };
            }
            return { changes: 0 };
          }
          if (normalized.includes('INSERT OR IGNORE INTO visits')) {
            const visitId = String(params[0] || '');
            const visitorId = String(params[1] || '');
            const pageLoadId = String(params[3] || '');
            const duplicate = visitsList.some(
              (v) =>
                v.visit_id === visitId ||
                (v.visitor_id === visitorId && v.page_load_id === pageLoadId)
            );
            if (duplicate) {
              return { changes: 0 };
            }
            visitsList.push({
              id: autoIncrementId++,
              visit_id: visitId,
              visitor_id: visitorId,
              session_id: String(params[2] || ''),
              page_load_id: pageLoadId,
              visited_at_utc: String(params[4] || ''),
              public_ip: String(params[5] || 'Unavailable'),
              city: String(params[6] || 'Unknown'),
              region: String(params[7] || 'Unknown'),
              country: String(params[8] || 'Unknown'),
              latitude: typeof params[9] === 'number' ? params[9] : null,
              longitude: typeof params[10] === 'number' ? params[10] : null,
              isp: String(params[11] || 'Unknown'),
              org: String(params[12] || 'Unknown'),
              asn: String(params[13] || 'Unknown'),
              browser: String(params[14] || 'Unknown'),
              os: String(params[15] || 'Unknown'),
              device_type: String(params[16] || 'Unknown'),
              screen_resolution: String(params[17] || 'Unavailable'),
              language: String(params[18] || 'Unavailable'),
              timezone: String(params[19] || 'Unavailable'),
            });
            return { changes: 1 };
          }
          return { changes: 0 };
        },
      };
    },
  };
}

function initializeDatabase(): DatabaseAdapter {
  if (process.env.INTEL_FORCE_MEMORY_DB === '1') {
    return createInMemoryDbAdapter();
  }

  let targetDir = path.join(os.tmpdir(), 'intel-system-data');
  if (!IS_SERVERLESS_RUNTIME) {
    try {
      const localDataDir = path.resolve(process.cwd(), 'data');
      if (!fs.existsSync(localDataDir)) {
        fs.mkdirSync(localDataDir, { recursive: true });
      }
      fs.accessSync(localDataDir, fs.constants.W_OK);
      targetDir = localDataDir;
    } catch {
      targetDir = path.join(os.tmpdir(), 'intel-system-data');
    }
  }

  try {
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }
    const dbPath = path.join(targetDir, 'intel_system.db');
    const requireModule = createRequire(import.meta.url);
    const BetterSqlite3 = requireModule('better-sqlite3') as new (
      filename: string
    ) => DatabaseAdapter & { pragma: (str: string) => void };

    const sqliteDb = new BetterSqlite3(dbPath);
    sqliteDb.pragma('journal_mode = WAL');
    sqliteDb.pragma('foreign_keys = ON');

    sqliteDb.exec(`
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

    for (const col of ['isp', 'org', 'asn']) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} TEXT NOT NULL DEFAULT 'Unknown'`);
      } catch {
        // Column already exists
      }
    }
    for (const col of ['latitude', 'longitude']) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} REAL`);
      } catch {
        // Column already exists
      }
      try {
        sqliteDb.exec(`ALTER TABLE verified_geo_cache_v3 ADD COLUMN ${col} REAL`);
      } catch {
        // Column already exists
      }
    }

    return sqliteDb;
  } catch {
    return createInMemoryDbAdapter();
  }
}

const db = initializeDatabase();

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

function computeHistoryBackupSignature(
  visitorId: string,
  totalVisits: number,
  totalSessions: number,
  firstVisitUtc: string,
  visits: VisitHistoryRecord[]
): string {
  const visitDigest = visits
    .map((v) => `${v.visitId}:${v.sessionId}:${v.visitedAtUtc}:${v.publicIp}`)
    .join('|');
  const payload = `hist:${visitorId}:${totalVisits}:${totalSessions}:${firstVisitUtc}:${visitDigest}`;
  return crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
}

function createSignedHistoryBackup(
  visitorId: string,
  totalVisits: number,
  totalSessions: number,
  firstVisitUtc: string,
  visits: VisitHistoryRecord[]
): SignedHistoryBackup {
  const compactVisits = visits.slice(0, 35);
  const signature = computeHistoryBackupSignature(
    visitorId,
    totalVisits,
    totalSessions,
    firstVisitUtc,
    compactVisits
  );
  return {
    visitorId,
    totalVisits,
    totalSessions,
    firstVisitUtc,
    visits: compactVisits,
    signature,
  };
}

function verifySignedHistoryBackup(
  expectedVisitorId: string,
  backup: SignedHistoryBackup | null | undefined
): boolean {
  if (
    !backup ||
    typeof backup !== 'object' ||
    backup.visitorId !== expectedVisitorId ||
    typeof backup.signature !== 'string' ||
    typeof backup.totalVisits !== 'number' ||
    typeof backup.totalSessions !== 'number' ||
    typeof backup.firstVisitUtc !== 'string' ||
    !Array.isArray(backup.visits)
  ) {
    return false;
  }
  const expectedSig = computeHistoryBackupSignature(
    backup.visitorId,
    backup.totalVisits,
    backup.totalSessions,
    backup.firstVisitUtc,
    backup.visits
  );
  if (expectedSig.length !== backup.signature.length) return false;
  try {
    return crypto.timingSafeEqual(
      Buffer.from(expectedSig, 'hex'),
      Buffer.from(backup.signature, 'hex')
    );
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
    'x-vercel-forwarded-for',
    'x-vercel-proxied-for',
    'cf-connecting-ip',
    'true-client-ip',
    'x-real-ip',
    'x-client-ip',
    'x-appengine-user-ip',
  ];

  for (const headerName of singleHeaders) {
    const rawVal = req.headers[headerName];
    if (typeof rawVal === 'string' && rawVal.trim()) {
      const firstHop = rawVal.split(',')[0];
      const normalized = normalizeIpCandidate(firstHop);
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
    process.env.VERCEL_REGION ||
    process.env.CLOUD_RUN_REGION ||
    process.env.GOOGLE_CLOUD_REGION ||
    '';
  const appUrl = process.env.APP_URL || '';
  const vercelIdHeader = req ? String(req.headers['x-vercel-id'] || '') : '';
  const hostHeader = req ? String(req.headers['x-forwarded-host'] || req.headers.host || '') : '';
  const combined = `${envRegion} ${vercelIdHeader} ${appUrl} ${hostHeader}`.toLowerCase();

  const regionNames: Record<string, string> = {
    'bom1': 'bom1 (Mumbai, India)',
    'sin1': 'sin1 (Singapore)',
    'hnd1': 'hnd1 (Tokyo, Japan)',
    'icn1': 'icn1 (Seoul, South Korea)',
    'syd1': 'syd1 (Sydney, Australia)',
    'fra1': 'fra1 (Frankfurt, Germany)',
    'lhr1': 'lhr1 (London, UK)',
    'cdg1': 'cdg1 (Paris, France)',
    'iad1': 'iad1 (Washington, D.C., USA)',
    'sfo1': 'sfo1 (San Francisco, USA)',
    'pdx1': 'pdx1 (Portland, USA)',
    'cle1': 'cle1 (Cleveland, USA)',
    'gru1': 'gru1 (Sao Paulo, Brazil)',
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
    regionCode: 'global-edge',
    regionLabel: 'Global Edge Network',
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

export const app = express();
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

// Streaming Download Endpoint: 4 concurrent streams, non-compressible 64KB chunks
app.get('/api/network/download', (req, res) => {
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
    res.status(429).json({ error: 'Maximum download transfer limit reached for this test.' });
    return;
  }

  const headerBytes = Number(req.headers['x-speedtest-bytes']);
  const requestedBytes = Number.isFinite(headerBytes) && headerBytes > 0
    ? Math.floor(headerBytes)
    : parseInt(String(req.query.bytes || 1024 * 1024), 10);
  const clampedRequest = Number.isNaN(requestedBytes)
    ? 1024 * 1024
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

  // Vercel's Node.js runtime exposes `request.body` as a lazy getter and may
  // already have consumed the raw request stream for application/octet-stream
  // payloads. Reading it here lets us count the bytes instead of waiting for
  // `data`/`end` events that will never fire.
  let platformBufferedBody: Buffer | null = null;
  try {
    const candidate = (req as express.Request & { body?: unknown }).body;
    if (Buffer.isBuffer(candidate)) {
      platformBufferedBody = candidate;
    } else if (candidate instanceof Uint8Array) {
      platformBufferedBody = Buffer.from(candidate);
    }
  } catch {
    platformBufferedBody = null;
  }

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
    res.status(429).json({ error: 'Maximum upload transfer limit reached for this test.' });
    return;
  }

  if (platformBufferedBody) {
    const receivedBytes = platformBufferedBody.byteLength;
    if (
      receivedBytes > SPEED_TEST_MAX_STREAM_UPLOAD_BYTES ||
      ledger.uploadedBytes + receivedBytes > SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES
    ) {
      res.status(413).json({
        ok: false,
        error: 'Upload transfer limit exceeded.',
        receivedBytes: 0,
      });
      return;
    }

    ledger.uploadedBytes += receivedBytes;
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.status(200).json({
      ok: true,
      receivedBytes,
      totalTestUploadedBytes: ledger.uploadedBytes,
      elapsedServerMs: 1,
      serverTimestampMs: Date.now(),
    });
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

app.use(express.json({ limit: '512kb' }));

// Initialize a Speed Test session with rate limiting & short-lived signed token
app.post('/api/network/speed-test/init', (req, res) => {
  const nowMs = Date.now();
  pruneSpeedTestState(nowMs);

  const { ip: extractedIp } = extractVisitorIp(req);
  const body = (req.body || {}) as { visitorId?: string; sessionId?: string };
  const cookieVid = req.cookies?.intel_http_vid as string | undefined;

  const visitorKey =
    cookieVid ||
    (typeof body.visitorId === 'string' && body.visitorId.trim()) ||
    extractedIp ||
    'anon';
  const sessionKey = (typeof body.sessionId === 'string' && body.sessionId.trim()) || visitorKey;
  const ipKey = extractedIp && extractedIp !== 'Unavailable' ? extractedIp : visitorKey;

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

  const visitorHistory = visitorTestTimestamps.get(visitorKey) || [];
  if (visitorHistory.length >= MAX_TESTS_PER_VISITOR_WINDOW) {
    const oldestMs = visitorHistory[0];
    const retrySec = Math.max(5, Math.ceil((RATE_WINDOW_MS - (nowMs - oldestMs)) / 1000));
    res.status(429).json({
      error: `Rate limit reached (${MAX_TESTS_PER_VISITOR_WINDOW} tests per 10 minutes). Try again in ${retrySec}s.`,
    });
    return;
  }

  const sessionCount = sessionTestCounts.get(sessionKey) || 0;
  if (sessionCount >= MAX_TESTS_PER_SESSION) {
    res.status(429).json({
      error: `Session speed-test limit (${MAX_TESTS_PER_SESSION} tests) reached.`,
    });
    return;
  }

  const ipHistory = ipTestTimestamps.get(ipKey) || [];
  if (ipHistory.length >= MAX_TESTS_PER_IP_WINDOW) {
    res.status(429).json({
      error: 'Network rate limit reached. Please wait a few minutes before running another test.',
    });
    return;
  }

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

app.get('/api/health', (req, res) => {
  const visitorsCount = (
    db.prepare('SELECT COUNT(*) AS count FROM visitors').get() as { count: number }
  ).count;
  const visitsCount = (
    db.prepare('SELECT COUNT(*) AS count FROM visits').get() as { count: number }
  ).count;
  const { regionCode, regionLabel } = detectServerRegion(req);
  res.json({ status: 'ok', visitorsCount, visitsCount, regionCode, regionLabel });
});

function extractVercelEdgeGeo(req: express.Request): {
  city: string;
  region: string;
  country: string;
  latitude: number | null;
  longitude: number | null;
} {
  const decodeHeader = (val: unknown): string => {
    if (typeof val !== 'string' || !val.trim()) return '';
    try {
      return decodeURIComponent(val.trim());
    } catch {
      return val.trim();
    }
  };
  const city = decodeHeader(req.headers['x-vercel-ip-city']);
  const region = decodeHeader(req.headers['x-vercel-ip-country-region']);
  const country = decodeHeader(req.headers['x-vercel-ip-country']);
  const rawLat = parseFloat(String(req.headers['x-vercel-ip-latitude'] || ''));
  const rawLon = parseFloat(String(req.headers['x-vercel-ip-longitude'] || ''));

  return {
    city,
    region,
    country,
    latitude: Number.isFinite(rawLat) ? rawLat : null,
    longitude: Number.isFinite(rawLon) ? rawLon : null,
  };
}

app.post('/api/visitor/identify', async (req, res) => {
  try {
    const {
      pageLoadId,
      storedVisitorId,
      storedVisitorToken,
      clientSessionId,
      clientHistoryBackup,
      browserDevice: rawBrowserDevice,
      clientGeoHint,
    } = (req.body || {}) as {
      pageLoadId?: string;
      storedVisitorId?: string | null;
      storedVisitorToken?: string | null;
      clientSessionId?: string | null;
      clientHistoryBackup?: SignedHistoryBackup | null;
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
    const vercelGeo = extractVercelEdgeGeo(req);

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
          : vercelGeo.latitude;
      const hintLon =
        typeof clientGeoHint.longitude === 'number' && Number.isFinite(clientGeoHint.longitude)
          ? clientGeoHint.longitude
          : vercelGeo.longitude;
      location = {
        publicIp: extractedIp,
        city:
          location.city !== 'Unavailable' && location.city !== 'Unknown'
            ? location.city
            : (typeof clientGeoHint.city === 'string' && clientGeoHint.city) ||
              vercelGeo.city ||
              'Unknown',
        region:
          location.region !== 'Unavailable' && location.region !== 'Unknown'
            ? location.region
            : (typeof clientGeoHint.region === 'string' && clientGeoHint.region) ||
              vercelGeo.region ||
              'Unknown',
        country:
          location.country !== 'Unavailable' && location.country !== 'Unknown'
            ? location.country
            : (typeof clientGeoHint.country === 'string' && clientGeoHint.country) ||
              vercelGeo.country ||
              'Unknown',
        countryCode:
          location.countryCode ||
          (typeof clientGeoHint.countryCode === 'string' ? clientGeoHint.countryCode : '') ||
          vercelGeo.country,
        latitude: location.latitude !== null ? location.latitude : hintLat,
        longitude: location.longitude !== null ? location.longitude : hintLon,
        isp: location.isp !== 'Unknown' ? location.isp : hintNet.isp,
        org: location.org !== 'Unknown' ? location.org : hintNet.org,
        asn: location.asn !== 'Unknown' ? location.asn : hintNet.asn,
        isVpnOrHosting: location.isVpnOrHosting || hintNet.isVpnOrHosting,
        isIpVerified: true,
        isLocationVerified: true,
      };
    } else if (
      isPublic &&
      (!location.isLocationVerified || location.latitude === null) &&
      (vercelGeo.city || vercelGeo.country || vercelGeo.latitude !== null)
    ) {
      location = {
        ...location,
        city:
          location.city !== 'Unavailable' && location.city !== 'Unknown'
            ? location.city
            : vercelGeo.city || 'Unknown',
        region:
          location.region !== 'Unavailable' && location.region !== 'Unknown'
            ? location.region
            : vercelGeo.region || 'Unknown',
        country:
          location.country !== 'Unavailable' && location.country !== 'Unknown'
            ? location.country
            : vercelGeo.country || 'Unknown',
        countryCode: location.countryCode || vercelGeo.country,
        latitude: location.latitude !== null ? location.latitude : vercelGeo.latitude,
        longitude: location.longitude !== null ? location.longitude : vercelGeo.longitude,
        isLocationVerified: true,
      };
    }

    const cookieVid = req.cookies?.intel_http_vid as string | undefined;
    const cookieToken = req.cookies?.intel_http_token as string | undefined;

    let existingVisitor: VisitorRow | undefined;
    let recognitionSource: IntelVisitorResponse['recognitionSource'] = 'New First-Party ID';

    const cookieVerified = Boolean(cookieVid && verifyVisitorToken(cookieVid, cookieToken));
    const storageVerified = Boolean(
      storedVisitorId && verifyVisitorToken(storedVisitorId, storedVisitorToken)
    );

    const verifiedVid = cookieVerified
      ? cookieVid!
      : storageVerified
      ? storedVisitorId!
      : null;
    const verifiedToken = cookieVerified
      ? cookieToken!
      : storageVerified
      ? storedVisitorToken!
      : null;

    if (verifiedVid && verifiedToken) {
      recognitionSource = cookieVerified ? 'First-Party Cookie' : 'First-Party LocalStorage';
      existingVisitor = db
        .prepare('SELECT * FROM visitors WHERE visitor_id = ?')
        .get(verifiedVid) as VisitorRow | undefined;

      // Serverless cold-start rehydration: if HMAC token is valid, restore visitor & signed history backup into db
      const validHistoryBackup =
        clientHistoryBackup &&
        verifySignedHistoryBackup(verifiedVid, clientHistoryBackup)
          ? clientHistoryBackup
          : null;

      if (!existingVisitor) {
        const nowIso = new Date().toISOString();
        const restoredFirstUtc = validHistoryBackup?.firstVisitUtc || nowIso;
        const latestBackupVisit = validHistoryBackup?.visits?.[0];
        const restoredLastUtc = latestBackupVisit?.visitedAtUtc || nowIso;
        const restoredSessionId =
          clientSessionId || latestBackupVisit?.sessionId || generateSessionId();

        db.prepare(
          `INSERT INTO visitors (
            visitor_id, hmac_token, created_at_utc, updated_at_utc, active_session_id, last_activity_utc
          ) VALUES (?, ?, ?, ?, ?, ?)`
        ).run(
          verifiedVid,
          verifiedToken,
          restoredFirstUtc,
          restoredLastUtc,
          restoredSessionId,
          restoredLastUtc
        );

        existingVisitor = db
          .prepare('SELECT * FROM visitors WHERE visitor_id = ?')
          .get(verifiedVid) as VisitorRow | undefined;
      }

      if (validHistoryBackup && validHistoryBackup.visits.length > 0) {
        const orderedAsc = [...validHistoryBackup.visits].reverse();
        for (const histVisit of orderedAsc) {
          db.prepare(
            `INSERT OR IGNORE INTO visits (
              visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
              public_ip, city, region, country, latitude, longitude, isp, org, asn,
              browser, os, device_type, screen_resolution, language, timezone
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            histVisit.visitId,
            verifiedVid,
            histVisit.sessionId,
            `rehydrated_${histVisit.visitId}`,
            histVisit.visitedAtUtc,
            histVisit.publicIp,
            histVisit.city,
            histVisit.region,
            histVisit.country,
            histVisit.latitude,
            histVisit.longitude,
            histVisit.isp || 'Unknown',
            histVisit.org || 'Unknown',
            histVisit.asn || 'Unknown',
            histVisit.browser,
            histVisit.os,
            histVisit.deviceType,
            histVisit.screenResolution,
            histVisit.language,
            histVisit.timezone
          );
        }
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
    }

    const cookieOptions = {
      maxAge: 365 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: 'lax' as const,
      path: '/',
      secure: Boolean(process.env.VERCEL) || process.env.NODE_ENV === 'production',
    };
    res.cookie('intel_http_vid', visitorId, cookieOptions);
    res.cookie('intel_http_token', visitorToken, cookieOptions);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');

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

    const validBackupForStats =
      clientHistoryBackup && verifySignedHistoryBackup(visitorId, clientHistoryBackup)
        ? clientHistoryBackup
        : null;

    const dbTotalVisits = Number(statsAgg.total_visits) || 1;
    const mergedTotalVisits = validBackupForStats
      ? Math.max(dbTotalVisits, validBackupForStats.totalVisits)
      : dbTotalVisits;

    const dbTotalSessions = Number(statsAgg.total_sessions) || 1;
    const mergedTotalSessions = validBackupForStats
      ? Math.max(dbTotalSessions, validBackupForStats.totalSessions)
      : dbTotalSessions;

    const mergedFirstVisitUtc =
      validBackupForStats &&
      validBackupForStats.firstVisitUtc &&
      validBackupForStats.firstVisitUtc < (statsAgg.first_visit_utc || nowUtc)
        ? validBackupForStats.firstVisitUtc
        : statsAgg.first_visit_utc || nowUtc;

    const statistics: VisitStatistics = {
      firstVisitUtc: mergedFirstVisitUtc,
      lastVisitUtc: statsAgg.last_visit_utc || nowUtc,
      previousVisitUtc: prevVisitRow ? prevVisitRow.visited_at_utc : null,
      totalVisits: mergedTotalVisits,
      totalSessions: mergedTotalSessions,
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

    const historyBackup = createSignedHistoryBackup(
      visitorId,
      statistics.totalVisits,
      statistics.totalSessions,
      statistics.firstVisitUtc,
      visitHistory
    );

    const payload: IntelVisitorResponse = {
      visitorId,
      visitorToken,
      isReturning,
      recognitionSource,
      location,
      browserDevice,
      statistics,
      visitHistory,
      historyBackup,
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

// Explicit JSON 404 for unknown API routes (instead of the SPA fallback HTML).
app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'API endpoint not found.' });
});

// Central error handler so a thrown error never leaves the serverless function
// in an undefined state (recommended by Vercel for Express apps).
app.use(
  (
    err: unknown,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction
  ) => {
    console.error('Unhandled API error:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Internal server error.' });
    }
  }
);

async function startStandaloneServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
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

if (!IS_SERVERLESS_RUNTIME) {
  startStandaloneServer();
}

export default app;

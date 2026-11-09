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
  HardwareSignals,
  IspNetworkClassification,
  SecuritySignals,
  RiskLevel,
  PersistenceMode,
  LocationInfo,
  VisitStatistics,
  VisitHistoryRecord,
  SignedHistoryBackup,
  IntelVisitorResponse,
  SmartSignal,
  SmartSignals,
  SmartSignalLevel,
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

const SPEED_TEST_MAX_TOTAL_DOWNLOAD_BYTES = 1024 * 1024 * 1024; // 1 GB max budget so high-bandwidth connections sustain full 15s download
const SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES = 512 * 1024 * 1024; // 512 MB max budget so high-bandwidth connections sustain full 15s upload
const SPEED_TEST_MAX_STREAM_DOWNLOAD_BYTES = 2 * 1024 * 1024; // 2 MB max per individual stream request (well below Vercel 4.5 MB limit)
const SPEED_TEST_MAX_STREAM_UPLOAD_BYTES = 2 * 1024 * 1024; // 2 MB max per individual upload request (well below Vercel 4.5 MB limit)
const SPEED_TEST_CONCURRENT_STREAMS = 6;
const SPEED_TEST_TOKEN_TTL_MS = 120 * 1000; // 120s token validity for 15s DL + 15s UL cycle
const SPEED_TEST_TOKEN_MAX_AGE_MS = 2 * 60 * 60 * 1000; // Stateless HMAC token freshness window (2h)
const SPEED_TEST_TOKEN_CLOCK_SKEW_MS = 60 * 1000; // Tolerance for issuedAtMs timestamps slightly in the future
const SPEED_TEST_HMAC_SECRET =
  process.env.VISITOR_HMAC_SECRET || 'intel-system-default-hmac-secret-v1';
const SPEED_TEST_MIN_STREAM_BYTES = 65536; // 64 KB floor for a single download request
const SPEED_TEST_STREAM_CHUNK_BYTES = 1024 * 1024; // 1 MB default / reported per-request chunk size
const SPEED_TEST_REPORTED_CONCURRENT_STREAMS = 2; // Parallel stream count reported to the client
const SPEED_TEST_STREAM_TIMEOUT_MS = 25 * 1000; // 25s hard per-stream timeout
const HIGH_ENTROPY_64KB_CHUNK = crypto.randomBytes(65536); // Non-compressible 64 KB random buffer

interface VisitorRow {
  visitor_id: string;
  hmac_token: string;
  hardware_id: string;
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
          if (normalized.includes('SELECT * FROM visitors WHERE hardware_id = ?')) {
            const hwid = String(params[0] || '');
            if (!hwid || !hwid.startsWith('hwid_')) return undefined;
            const matches = Array.from(visitorsMap.values())
              .filter((v) => v.hardware_id === hwid)
              .sort((a, b) => b.updated_at_utc.localeCompare(a.updated_at_utc));
            return matches[0];
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
            const hasHwCol = normalized.includes('hardware_id');
            const row: VisitorRow = hasHwCol
              ? {
                  visitor_id: String(params[0] || ''),
                  hmac_token: String(params[1] || ''),
                  hardware_id: String(params[2] || ''),
                  created_at_utc: String(params[3] || ''),
                  updated_at_utc: String(params[4] || ''),
                  active_session_id: String(params[5] || ''),
                  last_activity_utc: String(params[6] || ''),
                }
              : {
                  visitor_id: String(params[0] || ''),
                  hmac_token: String(params[1] || ''),
                  hardware_id: '',
                  created_at_utc: String(params[2] || ''),
                  updated_at_utc: String(params[3] || ''),
                  active_session_id: String(params[4] || ''),
                  last_activity_utc: String(params[5] || ''),
                };
            visitorsMap.set(row.visitor_id, row);
            return { changes: 1 };
          }
          if (normalized.includes('UPDATE visitors')) {
            const hasHwUpdate = normalized.includes('hardware_id = ?');
            const vid = String(hasHwUpdate ? params[4] : params[3] || '');
            const existing = visitorsMap.get(vid);
            if (existing) {
              existing.updated_at_utc = String(params[0] || existing.updated_at_utc);
              existing.active_session_id = String(params[1] || existing.active_session_id);
              existing.last_activity_utc = String(params[2] || existing.last_activity_utc);
              if (hasHwUpdate && typeof params[3] === 'string' && params[3]) {
                existing.hardware_id = params[3];
              }
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
        hardware_id TEXT NOT NULL DEFAULT '',
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

    try {
      sqliteDb.exec(`ALTER TABLE visitors ADD COLUMN hardware_id TEXT NOT NULL DEFAULT ''`);
    } catch {
      // Column already exists
    }
    try {
      sqliteDb.exec(`CREATE INDEX IF NOT EXISTS idx_visitors_hwid ON visitors(hardware_id)`);
    } catch {
      // Ignore index error
    }

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
  visits: VisitHistoryRecord[],
  hardwareId?: string
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
    hardwareId,
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
    'google',
    'gcp',
    'as15169',
    'as396982',
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
    'cloudflare',
    'microsoft corporation',
    'azure',
    'oracle',
    'akamai',
    'fastly',
    'zscaler',
    'netskope',
    'palo alto networks',
  ];

  const asnAndSourceLower = `${lower} ${(cleanAsn || '').toLowerCase()}`;
  const isVpnOrHosting =
    explicitHostingOrVpnFlag || hostingOrVpnKeywords.some((kw) => asnAndSourceLower.includes(kw));

  return {
    isp: formattedIsp || 'Unknown',
    org: cleanOrg || cleanIsp || 'Unknown',
    asn: cleanAsn || 'Unknown',
    isVpnOrHosting,
  };
}

/** ASN numbers of the major cloud / hosting providers used by the network classification. */
const CLOUD_PROVIDER_ASN_NUMBERS = new Set<number>([
  396178, 15169, 16509, 14618, 13335, 14061, 9009, 60068, 24940, 63949, 16276, 8075, 20473,
]);

/**
 * Server-side mirror of the collector's ISP brand and network-type classifier (Task 1).
 *
 * Intentionally a self-contained copy so the Node API bundle never imports the browser
 * collector module; brand names, network types and consumer / hosting flags must match
 * the client helper exactly. Consumer broadband rules are evaluated BEFORE the
 * cloud / datacenter rule so that e.g. Google Fiber (AS16591) is never swallowed by the
 * generic 'google' cloud keywords.
 *
 * Input: normalized location fields (normalizeIspAndOrg output); embedded 'AS<number>'
 * tokens in isp / org text are leniently re-scanned so partially normalized inputs
 * (e.g. client hints) also classify.
 */
function classifyIspNetwork(isp: string, org: string, asn: string): IspNetworkClassification {
  const cleanIsp = typeof isp === 'string' ? isp.trim() : '';
  const cleanOrg = typeof org === 'string' ? org.trim() : '';
  const cleanAsn = typeof asn === 'string' ? asn.trim().toUpperCase() : '';
  const keywordHaystack = `${cleanIsp} ${cleanOrg}`;

  const asnNumbers = new Set<number>();
  const asnTokenRegex = /\bAS(\d{1,10})\b/gi;
  let asnTokenMatch: RegExpExecArray | null;
  while ((asnTokenMatch = asnTokenRegex.exec(`${cleanAsn} ${keywordHaystack}`)) !== null) {
    const parsedAsn = Number.parseInt(asnTokenMatch[1], 10);
    if (Number.isFinite(parsedAsn)) asnNumbers.add(parsedAsn);
  }

  const matchConsumerRule = (
    brand: string,
    networkType: IspNetworkClassification['networkType'],
    asns: number[],
    keywords: RegExp | null
  ): IspNetworkClassification | null => {
    const asnHit = asns.find((a) => asnNumbers.has(a));
    const keywordHit = keywords !== null && keywords.test(keywordHaystack);
    if (asnHit === undefined && !keywordHit) return null;
    return {
      brandName: brand,
      networkType,
      isConsumerBroadband: true,
      isDatacenterOrHosting: false,
      matchedReason:
        asnHit !== undefined ? `ASN AS${asnHit}` : `ISP metadata keyword ${String(keywords)}`,
    };
  };

  const consumerMatch =
    // US consumer broadband (Residential Broadband)
    matchConsumerRule('Xfinity (Comcast)', 'Residential Broadband', [7922, 7015, 7016], /comcast|xfinity/i) ||
    matchConsumerRule('Spectrum (Charter)', 'Residential Broadband', [20115, 11426, 10796], /charter|spectrum/i) ||
    matchConsumerRule('AT&T Fiber', 'Residential Broadband', [7018, 20057], /at&t|att services|sbcglobal/i) ||
    matchConsumerRule('Verizon Fios', 'Residential Broadband', [701, 19262], /fios|mci communications|verizon online/i) ||
    matchConsumerRule('Optimum', 'Residential Broadband', [6128, 19108], /optimum|cablevision|altice|suddenlink/i) ||
    matchConsumerRule('Cox', 'Residential Broadband', [22773], /\bcox\b/i) ||
    matchConsumerRule('Frontier / CenturyLink', 'Residential Broadband', [5650, 209], null) ||
    matchConsumerRule('Google Fiber', 'Residential Broadband', [16591], /google fiber|gfiber/i) ||
    // US 5G home internet (Cellular / 5G)
    matchConsumerRule('Verizon 5G Home', 'Cellular / 5G', [6167, 22394], /cellco|verizon wireless/i) ||
    matchConsumerRule('T-Mobile 5G Home', 'Cellular / 5G', [21928], /t-mobile|tmobile/i) ||
    // Satellite
    matchConsumerRule('Starlink (SpaceX)', 'Satellite', [14593], /starlink|spacex/i) ||
    // India consumer broadband (Residential Broadband)
    matchConsumerRule('Jio (Reliance Jio)', 'Residential Broadband', [55836], /reliance jio|\bjio\b/i) ||
    matchConsumerRule('Airtel Xstream', 'Residential Broadband', [24560, 45609, 9498], /bharti airtel|\bairtel\b/i) ||
    matchConsumerRule('ACT Fibernet', 'Residential Broadband', [24309], /act fibernet|atria convergence/i) ||
    matchConsumerRule('BSNL Broadband', 'Residential Broadband', [9829], /\bbsnl\b|bharat sanchar/i) ||
    matchConsumerRule('Tata Play / Hathway', 'Residential Broadband', [], /tata play|tata sky broadband|hathway|excitel/i);

  if (consumerMatch) {
    return consumerMatch;
  }

  // Cloud / datacenter — only reached when no consumer rule matched above.
  const cloudAsnHit = Array.from(asnNumbers).find((n) => CLOUD_PROVIDER_ASN_NUMBERS.has(n));
  const cloudKeywords =
    /google llc|google cloud|amazonaws|cloudflare|digitalocean|hetzner|m247|datacamp|linode|ovh|choopa|vultr|leaseweb|hostinger|contabo|akamai/i;
  if (cloudAsnHit !== undefined || cloudKeywords.test(keywordHaystack)) {
    return {
      brandName: 'Cloud Provider / Datacenter',
      networkType: 'Cloud / Datacenter',
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason:
        cloudAsnHit !== undefined
          ? `ASN AS${cloudAsnHit}`
          : `ISP metadata keyword ${String(cloudKeywords)}`,
    };
  }

  return {
    brandName:
      cleanIsp && !/^unknown$|^unknown isp$/i.test(cleanIsp)
        ? cleanIsp
        : cleanOrg && !/^unknown$|^unknown isp$/i.test(cleanOrg)
        ? cleanOrg
        : 'Unknown ISP',
    networkType: 'Residential Broadband',
    isConsumerBroadband: false,
    isDatacenterOrHosting: false,
    matchedReason: null,
  };
}

/**
 * Task 2b — per-visit suspect scores stored before the 0..10 normalization used a 0..100
 * scale. Any stored value above 10 is treated as legacy and rescaled to 0..10
 * (Math.round(value / 10), clamped); values already within 0..10 pass through untouched.
 */
function normalizeLegacySuspectScore(rawSuspectScore: number): number {
  if (!Number.isFinite(rawSuspectScore)) return 0;
  if (rawSuspectScore <= 10) return Math.max(0, rawSuspectScore);
  return Math.max(0, Math.min(10, Math.round(rawSuspectScore / 10)));
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

  // The collector mirrors its storage-physics verdict onto the device object; these
  // aliases are carried through untouched so the client tile can read them.
  const incognitoAlias =
    typeof input?.incognito === 'boolean' ||
    typeof input?.isIncognito === 'boolean' ||
    typeof input?.privateMode === 'boolean'
      ? Boolean(input?.incognito ?? input?.isIncognito ?? input?.privateMode)
      : undefined;
  const incognitoMethod =
    typeof input?.incognitoMethod === 'string' && input.incognitoMethod.trim()
      ? input.incognitoMethod.trim().slice(0, 120)
      : undefined;
  const idbDurabilityRatio =
    typeof input?.idbDurabilityRatio === 'number' && Number.isFinite(input.idbDurabilityRatio)
      ? Number(input.idbDurabilityRatio)
      : undefined;
  const opfsFlushMs =
    typeof input?.opfsFlushMs === 'number' && Number.isFinite(input.opfsFlushMs)
      ? Number(input.opfsFlushMs)
      : undefined;

  return {
    browser: safeStr(input?.browser, 'Unknown'),
    os: safeStr(input?.os, 'Unknown'),
    deviceType,
    platform: safeStr(input?.platform, 'Unavailable'),
    screenResolution: safeStr(input?.screenResolution, 'Unavailable'),
    pixelRatio: safeStr(input?.pixelRatio, 'Unavailable'),
    language: safeStr(input?.language, 'Unavailable'),
    timezone: safeStr(input?.timezone, 'Unavailable'),
    incognito: incognitoAlias,
    isIncognito: incognitoAlias,
    privateMode: incognitoAlias,
    incognitoMethod,
    idbDurabilityRatio,
    opfsFlushMs,
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

const SPEED_TEST_STATELESS_TOKEN_PATTERN = /^st_(\d{10,17})_([0-9a-fA-F]{64})$/;

/**
 * Create a 100% stateless speed-test token: `st_<issuedAtMs>_<hmacHex>`.
 *
 * The HMAC-SHA256 of the issuance timestamp makes the token verifiable on ANY
 * serverless instance (nothing needs to live in the shared in-memory Map), and
 * the freshness window caps its replay lifetime to 2 hours.
 */
function createSignedSpeedTestToken(): string {
  const issuedAtMs = Date.now();
  const hmacHex = crypto
    .createHmac('sha256', SPEED_TEST_HMAC_SECRET)
    .update(String(issuedAtMs))
    .digest('hex');
  return `st_${issuedAtMs}_${hmacHex}`;
}

/**
 * Verify a stateless speed-test token (`st_<issuedAtMs>_<hmacHex>`) without any
 * in-memory state: recompute the HMAC, compare timing-safely, and check that the
 * token is fresh (issued no earlier than 2 hours ago).
 */
export function verifySpeedTestToken(rawToken: string | null | undefined): {
  valid: boolean;
  issuedAtMs: number;
  fresh: boolean;
} {
  const token = typeof rawToken === 'string' ? rawToken.trim() : '';
  const match = SPEED_TEST_STATELESS_TOKEN_PATTERN.exec(token);
  if (!match) {
    return { valid: false, issuedAtMs: 0, fresh: false };
  }

  const issuedAtMs = Number.parseInt(match[1], 10);
  if (!Number.isFinite(issuedAtMs) || issuedAtMs <= 0) {
    return { valid: false, issuedAtMs: 0, fresh: false };
  }

  const nowMs = Date.now();
  const fresh =
    issuedAtMs <= nowMs + SPEED_TEST_TOKEN_CLOCK_SKEW_MS &&
    nowMs - issuedAtMs <= SPEED_TEST_TOKEN_MAX_AGE_MS;

  const expectedHex = crypto
    .createHmac('sha256', SPEED_TEST_HMAC_SECRET)
    .update(String(issuedAtMs))
    .digest('hex');
  const providedHex = match[2].toLowerCase();

  const valid =
    providedHex.length === expectedHex.length &&
    crypto.timingSafeEqual(Buffer.from(providedHex, 'utf8'), Buffer.from(expectedHex, 'utf8'));

  return { valid, issuedAtMs, fresh };
}

function createStatelessSpeedTestLedger(
  testId: string,
  tokenKey: string,
  visitorKey: string,
  ipKey: string,
  nowMs: number
): SpeedTestLedger {
  const statelessLedger: SpeedTestLedger = {
    testId,
    visitorKey,
    sessionKey: visitorKey,
    ipKey,
    createdAtMs: nowMs,
    expiresAtMs: nowMs + SPEED_TEST_TOKEN_TTL_MS,
    downloadedBytes: 0,
    uploadedBytes: 0,
    activeStreams: 0,
    completed: false,
  };
  activeSpeedTests.set(tokenKey, statelessLedger);
  return statelessLedger;
}

function verifyAndGetSpeedTestLedger(
  rawToken: string | undefined | null,
  visitorKey: string,
  ipKey: string
): { valid: boolean; reason?: string; ledger?: SpeedTestLedger } {
  const nowMs = Date.now();
  const cleanedToken = typeof rawToken === 'string' ? rawToken.trim() : '';

  // 1. Direct lookup in activeSpeedTests by full token or testId prefix (same instance)
  if (cleanedToken) {
    const directLedger =
      activeSpeedTests.get(cleanedToken) || activeSpeedTests.get(cleanedToken.split('.')[0]);
    if (directLedger && !directLedger.completed) {
      return { valid: true, ledger: directLedger };
    }
  }

  // 2. Stateless HMAC validation for `st_<issuedAtMs>_<hmacHex>` tokens: the request landed
  //    on a different Vercel serverless instance (or a cold start wiped the Map). Recreate
  //    the ledger instead of rejecting with 403/404.
  const statelessCheck = verifySpeedTestToken(cleanedToken);
  if (statelessCheck.valid && statelessCheck.fresh) {
    const ledger = createStatelessSpeedTestLedger(
      cleanedToken,
      cleanedToken,
      visitorKey,
      ipKey,
      nowMs
    );
    return { valid: true, ledger };
  }

  // 3. Legacy dotted-format HMAC validation (`st_<id>.<expiry>.<vHash>.<sig>`) for tokens
  //    issued before the stateless rollout, with a 5-minute clock-skew grace window.
  if (cleanedToken && cleanedToken.startsWith('st_')) {
    const parts = cleanedToken.split('.');
    const testId = parts[0];

    if (parts.length === 4) {
      const [, expStr, vHash, providedSig] = parts;
      const expiresAtMs = parseInt(expStr, 10);

      if (!Number.isNaN(expiresAtMs) && nowMs <= expiresAtMs + 5 * 60 * 1000) {
        const payload = `${testId}.${expiresAtMs}.${vHash}`;
        const expectedSig = crypto
          .createHmac('sha256', HMAC_SECRET)
          .update(`speedtest:${payload}`)
          .digest('hex')
          .slice(0, 24);

        if (
          providedSig.length === expectedSig.length &&
          crypto.timingSafeEqual(Buffer.from(providedSig), Buffer.from(expectedSig))
        ) {
          const statelessLedger = createStatelessSpeedTestLedger(
            testId,
            testId,
            visitorKey,
            ipKey,
            nowMs
          );
          statelessLedger.expiresAtMs = Math.max(expiresAtMs, nowMs + SPEED_TEST_TOKEN_TTL_MS);
          statelessLedger.sessionKey = vHash;
          activeSpeedTests.set(cleanedToken, statelessLedger);
          return { valid: true, ledger: statelessLedger };
        }
      }
    }
  }

  return { valid: false, reason: 'Invalid or missing speed test authorization token.' };
}

export const app = express();
app.set('trust proxy', true);
app.use(cookieParser());

// Ensure HTTP Permissions-Policy header allows compute-pressure in both top-level and embedded contexts
app.use((_req, res, next) => {
  res.setHeader('Permissions-Policy', 'compute-pressure=*');
  next();
});

const firstHeaderValue = (value: string | string[] | undefined): string => {
  const raw = Array.isArray(value) ? value[0] : value;
  return typeof raw === 'string' ? raw : '';
};

const handleNetworkHeadPing = (_req: express.Request, res: express.Response) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Timing-Allow-Origin', '*');
  res.status(200).end();
};

const handleNetworkPing = (_req: express.Request, res: express.Response) => {
  const serverTimestamp = Date.now();
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Timing-Allow-Origin', '*');
  res.status(200).json({ ok: true, serverTimestamp, serverTimestampMs: serverTimestamp });
};

app.head('/api/network/ping', handleNetworkHeadPing);
app.get('/api/network/ping', handleNetworkPing);

// Streaming Download Endpoint: stateless on Vercel — a valid HMAC token is always served even
// when the in-memory ledger was created on a different serverless instance. Keeps explicit
// Content-Type / Content-Length / no-store headers and avoids any buffering/compressing middle
// layer so the payload is streamed out deterministically in one fixed-size pass.
app.get('/api/network/download', (req, res) => {
  const nowMs = Date.now();
  pruneSpeedTestState(nowMs);

  const token =
    (typeof req.query.token === 'string' ? req.query.token : '') ||
    firstHeaderValue(req.headers['x-speed-test-token']) ||
    firstHeaderValue(req.headers['x-speedtest-token']);
  const { ip: extractedIp } = extractVisitorIp(req);
  const visitorKey =
    (req.cookies?.intel_http_vid as string | undefined) || extractedIp || 'anon';

  const verification = verifyAndGetSpeedTestLedger(token, visitorKey, extractedIp);
  if (!verification.valid || !verification.ledger) {
    // Only a missing/invalid/tampered token is rejected here. Losing the in-memory ledger
    // across instances is handled statelessly inside verifyAndGetSpeedTestLedger.
    res.status(403).json({ error: verification.reason || 'Unauthorized speed test request.' });
    return;
  }

  const ledger = verification.ledger;
  if (ledger.activeStreams >= SPEED_TEST_CONCURRENT_STREAMS + 6) {
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
    : parseInt(String(req.query.bytes || SPEED_TEST_STREAM_CHUNK_BYTES), 10);
  const clampedRequest = Number.isNaN(requestedBytes)
    ? SPEED_TEST_STREAM_CHUNK_BYTES
    : Math.max(
        SPEED_TEST_MIN_STREAM_BYTES,
        Math.min(SPEED_TEST_MAX_STREAM_DOWNLOAD_BYTES, requestedBytes)
      );
  const targetBytes = Math.min(clampedRequest, remainingBudget);

  // Deterministic, fast-filling payload: a small non-compressible repeating pattern copied over
  // the exact requested byte length into a pre-allocated buffer (no per-chunk streaming writes).
  const streamBuffer = Buffer.allocUnsafe(targetBytes);
  for (let offset = 0; offset < targetBytes; offset += HIGH_ENTROPY_64KB_CHUNK.length) {
    const toFill = Math.min(HIGH_ENTROPY_64KB_CHUNK.length, targetBytes - offset);
    HIGH_ENTROPY_64KB_CHUNK.copy(streamBuffer, offset, 0, toFill);
  }

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
  let streamClosed = false;

  const cleanupStream = () => {
    if (streamClosed) return;
    streamClosed = true;
    ledger.activeStreams = Math.max(0, ledger.activeStreams - 1);
  };

  req.on('close', cleanupStream);
  res.on('close', cleanupStream);
  res.on('error', cleanupStream);
  res.on('finish', cleanupStream);

  ledger.downloadedBytes += targetBytes;
  res.end(streamBuffer);
});

/**
 * Route-level raw-body capture for the upload endpoint, registered BEFORE the global
 * express.json() below. Binary octet-stream payloads must never be mangled or rejected
 * by the JSON parser, and raw-body must never sit waiting on a stream that the
 * serverless platform already consumed into `req.body`.
 */
const speedTestUploadRawParser = express.raw({ type: '*/*', limit: '4mb' });

const speedTestUploadBodyGuard = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  // Case (a): the platform already buffered the body (Vercel exposes `request.body` as a
  // lazy getter that consumes the raw stream on first access) — skip raw-body entirely.
  let platformBody: unknown;
  try {
    platformBody = (req as express.Request & { body?: unknown }).body;
  } catch {
    platformBody = undefined;
  }
  if (
    platformBody !== undefined &&
    platformBody !== null &&
    (Buffer.isBuffer(platformBody) ||
      typeof platformBody === 'string' ||
      platformBody instanceof Uint8Array)
  ) {
    next();
    return;
  }

  // Case (b): the stream was already drained by the runtime but no body was exposed —
  // counting falls back to Content-Length in the handler, no parsing needed.
  if (req.readableEnded || req.complete) {
    next();
    return;
  }

  // Case (c): a live stream — capture the raw payload (4 MB ceiling, below Vercel's
  // hard 4.5 MB serverless request cap) instead of letting global express.json() run.
  speedTestUploadRawParser(req, res, (parseError: unknown) => {
    if (parseError) {
      if (!res.headersSent) {
        res.status(413).json({
          ok: false,
          error: 'Upload payload exceeds the 4 MB route limit.',
          receivedBytes: 0,
        });
      }
      return;
    }
    next();
  });
};

// Streaming Upload Endpoint: mounted BEFORE express.json(), counts actual bytes received without disk/RAM buffering
app.post('/api/network/upload', speedTestUploadBodyGuard, (req, res) => {
  const nowMs = Date.now();
  pruneSpeedTestState(nowMs);

  // Vercel's Node.js runtime exposes `request.body` as a lazy getter and may
  // already have consumed the raw request stream for application/octet-stream
  // payloads. Accepting every already-parsed shape here lets us count the bytes
  // instead of waiting for `data`/`end` events that will never fire.
  let platformBufferedBody: Buffer | null = null;
  try {
    const candidate = (req as express.Request & { body?: unknown }).body;
    if (Buffer.isBuffer(candidate)) {
      platformBufferedBody = candidate;
    } else if (candidate instanceof Uint8Array) {
      platformBufferedBody = Buffer.from(candidate);
    } else if (typeof candidate === 'string' && candidate.length > 0) {
      platformBufferedBody = Buffer.from(candidate, 'utf8');
    }
  } catch {
    platformBufferedBody = null;
  }

  const token =
    (typeof req.query.token === 'string' ? req.query.token : '') ||
    firstHeaderValue(req.headers['x-speed-test-token']) ||
    firstHeaderValue(req.headers['x-speedtest-token']);
  const { ip: extractedIp } = extractVisitorIp(req);
  const visitorKey =
    (req.cookies?.intel_http_vid as string | undefined) || extractedIp || 'anon';

  // 100% stateless: a missing in-memory ledger (different serverless instance) must never
  // 401/403/404 the upload. If a token is present and HMAC-valid the ledger is (re)created by
  // verifyAndGetSpeedTestLedger; without any valid token we still count and accept the bytes.
  const verification = verifyAndGetSpeedTestLedger(token, visitorKey, extractedIp);
  const ledger = verification.valid ? verification.ledger : undefined;

  const bumpActiveStreams = (delta: number) => {
    if (!ledger) return;
    ledger.activeStreams = Math.max(0, ledger.activeStreams + delta);
  };

  // If the serverless platform already buffered or ended the incoming request stream,
  // count the buffered bytes (or Content-Length header) immediately without hanging on req.on('end')
  const contentLengthHeader = parseInt(String(req.headers['content-length'] || '0'), 10);
  if (platformBufferedBody || req.readableEnded || req.complete) {
    const receivedBytes = platformBufferedBody
      ? platformBufferedBody.byteLength
      : Number.isFinite(contentLengthHeader) && contentLengthHeader > 0
      ? Math.min(contentLengthHeader, SPEED_TEST_MAX_STREAM_UPLOAD_BYTES)
      : 0;

    if (
      receivedBytes > SPEED_TEST_MAX_STREAM_UPLOAD_BYTES ||
      (ledger && ledger.uploadedBytes + receivedBytes > SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES)
    ) {
      res.status(413).json({
        ok: false,
        error: 'Upload transfer limit exceeded.',
        receivedBytes: 0,
      });
      return;
    }

    if (ledger) {
      ledger.uploadedBytes += receivedBytes;
    }
    const reportedTimestamp = Date.now();
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.status(200).json({
      ok: true,
      receivedBytes,
      totalTestUploadedBytes: ledger ? ledger.uploadedBytes : receivedBytes,
      elapsedServerMs: 1,
      serverTimestamp: reportedTimestamp,
      serverTimestampMs: reportedTimestamp,
    });
    return;
  }

  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Timing-Allow-Origin', '*');

  bumpActiveStreams(1);
  const streamStartMs = Date.now();
  let streamReceivedBytes = 0;
  let finished = false;
  let exceededCap = false;

  const cleanupUpload = () => {
    if (finished) return;
    finished = true;
    bumpActiveStreams(-1);
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
      (ledger && ledger.uploadedBytes + chunkLen > SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES)
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
    if (ledger) {
      ledger.uploadedBytes += chunkLen;
    }
  });

  req.on('end', () => {
    if (finished || exceededCap) return;
    cleanupUpload();
    const elapsedServerMs = Math.max(1, Date.now() - streamStartMs);
    const reportedTimestamp = Date.now();
    res.status(200).json({
      ok: true,
      receivedBytes: streamReceivedBytes,
      totalTestUploadedBytes: ledger ? ledger.uploadedBytes : streamReceivedBytes,
      elapsedServerMs,
      serverTimestamp: reportedTimestamp,
      serverTimestampMs: reportedTimestamp,
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

  // Auto-evict any earlier entry for this visitor / IP BEFORE applying the concurrency caps:
  // re-runs and page refreshes must always succeed, even when the previous test has not been
  // garbage-collected yet (it would otherwise block a new test with 429).
  for (const [ledgerKey, ledger] of activeSpeedTests.entries()) {
    if (ledger.ipKey === ipKey || ledger.visitorKey === visitorKey) {
      activeSpeedTests.delete(ledgerKey);
    }
  }

  let activeCount = 0;
  let activeIpCount = 0;
  const seenTestIds = new Set<string>();
  for (const [, ledger] of activeSpeedTests.entries()) {
    if (seenTestIds.has(ledger.testId)) continue;
    seenTestIds.add(ledger.testId);
    if (!ledger.completed && nowMs < ledger.expiresAtMs && nowMs - ledger.createdAtMs < 45000) {
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
  const token = createSignedSpeedTestToken();

  const newLedger: SpeedTestLedger = {
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
  };
  activeSpeedTests.set(testId, newLedger);
  activeSpeedTests.set(token, newLedger);

  const { regionCode, regionLabel } = detectServerRegion(req);

  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.status(200).json({
    ok: true,
    testId,
    token,
    expiresAtMs,
    serverRegion: regionLabel,
    serverRegionCode: regionCode,
    // Stateless contract reported to clients: 2 parallel streams, 1 MB per-request chunks.
    concurrentStreams: SPEED_TEST_REPORTED_CONCURRENT_STREAMS,
    maxDownloadBytes: SPEED_TEST_STREAM_CHUNK_BYTES,
    maxUploadBytes: SPEED_TEST_STREAM_CHUNK_BYTES,
  });
});

// Release active lock when a test finishes or is cancelled by the visitor (100% stateless on Vercel)
app.post('/api/network/speed-test/complete', (req, res) => {
  const body = (req.body || {}) as { token?: string };
  const queryToken = typeof req.query.token === 'string' ? req.query.token : '';
  const headerToken =
    firstHeaderValue(req.headers['x-speed-test-token']) ||
    firstHeaderValue(req.headers['x-speedtest-token']);
  const rawToken = (typeof body.token === 'string' ? body.token : queryToken || headerToken).trim();
  // Legacy dotted tokens carry the testId as the first dot-separated segment; new stateless
  // tokens are self-contained so the token itself doubles as the ledger key.
  const dotIndex = rawToken.indexOf('.');
  const testId = dotIndex === -1 ? rawToken : rawToken.slice(0, dotIndex);
  if (rawToken) {
    const ledger = activeSpeedTests.get(rawToken);
    if (ledger) {
      ledger.completed = true;
      activeSpeedTests.delete(ledger.testId);
    }
    activeSpeedTests.delete(rawToken);
    if (testId && testId !== rawToken) {
      const legacyLedger = activeSpeedTests.get(testId);
      if (legacyLedger) legacyLedger.completed = true;
      activeSpeedTests.delete(testId);
    }
  }
  // Always acknowledge: the test may have been served (or already evicted) on another instance.
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
  timezone: string;
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
  const timezone = decodeHeader(req.headers['x-vercel-ip-timezone']);
  const rawLat = parseFloat(String(req.headers['x-vercel-ip-latitude'] || ''));
  const rawLon = parseFloat(String(req.headers['x-vercel-ip-longitude'] || ''));

  return {
    city,
    region,
    country,
    timezone,
    latitude: Number.isFinite(rawLat) ? rawLat : null,
    longitude: Number.isFinite(rawLon) ? rawLon : null,
  };
}

const SERVER_TIMEZONE_ALIAS_MAP: Record<string, string> = {
  'asia/calcutta': 'asia/kolkata',
  'asia/katmandu': 'asia/kathmandu',
  'asia/rangoon': 'asia/yangon',
  'asia/saigon': 'asia/ho_chi_minh',
  'europe/kiev': 'europe/kyiv',
  'us/eastern': 'america/new_york',
  'us/central': 'america/chicago',
  'us/mountain': 'america/denver',
  'us/pacific': 'america/los_angeles',
  'etc/utc': 'utc',
  'etc/gmt': 'utc',
};

/**
 * Canonical IANA timezone aliases. The client and the IP geolocation provider frequently
 * disagree only because one of them reports a legacy alias (e.g. Asia/Calcutta) — mapping both
 * sides through this table removes those false-positive VPN / timezone-relay mismatches.
 */
const TIMEZONE_ALIAS_MAP: Record<string, string> = {
  'Asia/Calcutta': 'Asia/Kolkata',
  'Asia/Katmandu': 'Asia/Kathmandu',
  'Asia/Saigon': 'Asia/Ho_Chi_Minh',
  'Asia/Rangoon': 'Asia/Yangon',
  'Europe/Kiev': 'Europe/Kyiv',
  'Europe/Uzhgorod': 'Europe/Kyiv',
  'Europe/Zaporozhye': 'Europe/Kyiv',
  'US/Eastern': 'America/New_York',
  'US/Central': 'America/Chicago',
  'US/Mountain': 'America/Denver',
  'US/Pacific': 'America/Los_Angeles',
};

/**
 * Trims a timezone identifier and canonicalizes legacy aliases, preserving the caller's
 * casing for known ids. Falsy / non-string input resolves to an empty string.
 */
function normalizeTimezone(tz?: string | null): string {
  if (!tz || typeof tz !== 'string') return '';
  const trimmed = tz.trim();
  if (!trimmed) return '';
  return TIMEZONE_ALIAS_MAP[trimmed] || trimmed;
}

function normalizeServerTimezoneId(tz: string | null | undefined): string {
  if (!tz || typeof tz !== 'string') return '';
  // Delegate alias resolution to normalizeTimezone so the two helpers never drift, then fold
  // to the lowercase comparison form this server-side matcher has always used.
  const canonical = normalizeTimezone(tz).toLowerCase();
  if (!canonical || canonical === 'unknown' || canonical === 'unavailable') return '';
  return SERVER_TIMEZONE_ALIAS_MAP[canonical] || canonical;
}

function sanitizeHardwareSignals(
  raw: Partial<HardwareSignals> | null | undefined,
  browserDevice: BrowserDeviceInfo
): HardwareSignals {
  const safeStr = (val: unknown, fallback: string, maxLen = 140): string =>
    typeof val === 'string' && val.trim().length > 0 ? val.trim().slice(0, maxLen) : fallback;

  const rawHwId = safeStr(raw?.hardwareId, '', 40);
  const validHwId = /^hwid_[0-9a-f]{16,32}$/i.test(rawHwId)
    ? rawHwId.toLowerCase()
    : 'hwid_' +
      crypto
        .createHash('sha256')
        .update(
          `${browserDevice.os}|${browserDevice.screenResolution}|${browserDevice.pixelRatio}|${safeStr(raw?.gpuRenderer, 'gpu')}|${safeStr(raw?.canvasHash, 'canvas')}`
        )
        .digest('hex')
        .slice(0, 20);

  const cpuCores =
    typeof raw?.cpuCores === 'number' && Number.isFinite(raw.cpuCores) && raw.cpuCores > 0
      ? Math.min(256, Math.round(raw.cpuCores))
      : null;

  const deviceMemoryGb =
    typeof raw?.deviceMemoryGb === 'number' &&
    Number.isFinite(raw.deviceMemoryGb) &&
    raw.deviceMemoryGb > 0
      ? Number(raw.deviceMemoryGb)
      : null;

  const maxTouchPoints =
    typeof raw?.maxTouchPoints === 'number' &&
    Number.isFinite(raw.maxTouchPoints) &&
    raw.maxTouchPoints >= 0
      ? Math.min(64, Math.round(raw.maxTouchPoints))
      : 0;

  const colorDepth =
    typeof raw?.colorDepth === 'number' && Number.isFinite(raw.colorDepth) && raw.colorDepth > 0
      ? Math.min(64, Math.round(raw.colorDepth))
      : 24;

  const maxTextureSize =
    typeof raw?.maxTextureSize === 'number' &&
    Number.isFinite(raw.maxTextureSize) &&
    raw.maxTextureSize >= 0
      ? Math.round(raw.maxTextureSize)
      : 0;

  return {
    hardwareId: validHwId,
    gpuVendor: safeStr(raw?.gpuVendor, 'Standard WebGL Vendor', 120),
    gpuRenderer: safeStr(raw?.gpuRenderer, 'Standard Hardware Renderer', 160),
    maxTextureSize,
    canvasHash: safeStr(raw?.canvasHash, 'unavailable', 40),
    audioHash: safeStr(raw?.audioHash, 'unavailable', 40),
    cpuCores,
    deviceMemoryGb,
    colorDepth,
    maxTouchPoints,
    hdrSupported: Boolean(raw?.hdrSupported),
    colorGamut:
      raw?.colorGamut === 'Rec2020' || raw?.colorGamut === 'P3' || raw?.colorGamut === 'sRGB'
        ? raw.colorGamut
        : 'sRGB',
    architecture: safeStr(raw?.architecture, browserDevice.os, 80),
  };
}

/**
 * Incognito cross-mode context, resolved by the identify handler before any row is written:
 * a hardware-fingerprint recovery with no surviving cookie / localStorage state is proof of an
 * ephemeral (private) browsing context even when the client probe stays silent.
 */
interface IncognitoCrossModeContext {
  hadPersistentClientState?: boolean;
  existingHwidVisitor?: boolean;
  clientReportedIncognito?: boolean;
  /** Case B — an earlier visit by this same physical device (last 7 days) used a different visitor id. */
  crossSessionEphemeral?: boolean;
}

function sanitizeAndReinforceSecuritySignals(
  raw: Partial<SecuritySignals> | null | undefined,
  browserDevice: BrowserDeviceInfo,
  hardwareSignals: HardwareSignals,
  location: LocationInfo,
  ipTimezoneHint: string,
  recognitionSource: IntelVisitorResponse['recognitionSource'],
  classification: IspNetworkClassification,
  velocity: { visitsLastHour: number; distinctIpsLastHour: number },
  incognitoContext: IncognitoCrossModeContext = {}
): SecuritySignals {
  const safeStrArray = (arr: unknown): string[] =>
    Array.isArray(arr)
      ? arr
          .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
          .map((s) => s.trim().slice(0, 180))
          .slice(0, 10)
      : [];

  // Bot / automation: client flags only. `isBot` is the union of the explicit bot verdict,
  // the WebDriver handshake and the CDP (Chrome DevTools Protocol) runtime probe.
  const webdriver = Boolean(raw?.webdriver);
  const cdpDetected = Boolean(raw?.cdpDetected);
  const isBot = Boolean(raw?.isBot || webdriver || cdpDetected);
  const isHeadless = Boolean(raw?.isHeadless);
  const botReason =
    typeof raw?.botReason === 'string' && raw.botReason.trim()
      ? raw.botReason.trim().slice(0, 200)
      : '';
  const botSignals = safeStrArray(raw?.botSignals);

  const browserTimezone =
    typeof raw?.browserTimezone === 'string' && raw.browserTimezone.trim()
      ? raw.browserTimezone.trim().slice(0, 80)
      : browserDevice.timezone || 'UTC';

  const ipTimezone =
    ipTimezoneHint ||
    (typeof raw?.ipTimezone === 'string' && raw.ipTimezone.trim() && raw.ipTimezone !== 'Unavailable'
      ? raw.ipTimezone.trim().slice(0, 80)
      : 'Unavailable');

  const normBrowserTz = normalizeServerTimezoneId(browserTimezone);
  const normIpTz = normalizeServerTimezoneId(ipTimezone);
  const serverTzMismatch = Boolean(normBrowserTz && normIpTz && normBrowserTz !== normIpTz);
  const timezoneMismatch = Boolean(raw?.timezoneMismatch) || serverTzMismatch;

  // Task 1/2 — the datacenter label now comes from the mirrored ISP classification instead
  // of the old bare-keyword regex (which mis-flagged e.g. Google Fiber AS16591 as cloud
  // because of the generic 'google' keyword).
  const isCloudOrDatacenterNetwork =
    classification.isDatacenterOrHosting || Boolean(location.isVpnOrHosting);

  const isGpuMaskedOrUnavailable =
    !hardwareSignals.gpuVendor ||
    hardwareSignals.gpuVendor === 'Unavailable' ||
    /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuVendor) ||
    !hardwareSignals.gpuRenderer ||
    hardwareSignals.gpuRenderer === 'Unavailable' ||
    /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuRenderer);

  // Consumer broadband is never a datacenter / hosting network, even when the geo provider
  // (or a legacy cached flag) tagged the IP as hosting.
  const datacenterAsn = classification.isConsumerBroadband
    ? false
    : isCloudOrDatacenterNetwork;
  const vpnReasons = safeStrArray(raw?.vpnReasons);
  if (
    timezoneMismatch &&
    !vpnReasons.some((r) => r.toLowerCase().includes('timezone'))
  ) {
    vpnReasons.push(
      `Browser timezone (${browserTimezone}) differs from IP geolocation timezone (${ipTimezone})`
    );
  }
  if (
    datacenterAsn &&
    !vpnReasons.some((r) => r.toLowerCase().includes('datacenter') || r.toLowerCase().includes('asn'))
  ) {
    vpnReasons.push(
      `Network ASN / ISP (${location.isp}${location.asn !== 'Unknown' ? ` • ${location.asn}` : ''}) matches cloud/hosting or VPN infrastructure`
    );
  }
  if (
    datacenterAsn &&
    isGpuMaskedOrUnavailable &&
    !vpnReasons.some((r) => /Cloud \/ Masked GPU/i.test(r))
  ) {
    vpnReasons.push('Cloud / Masked GPU environment');
  }
  const vpnSuspected = Boolean(raw?.vpnSuspected) || timezoneMismatch || datacenterAsn;

  // Smart-signal timezone comparison: both sides are canonicalized through normalizeTimezone so
  // a legacy alias (Asia/Calcutta vs Asia/Kolkata, US/Pacific vs America/Los_Angeles) is never
  // mis-reported as a timezone relay. Casing is folded for the comparison only.
  const clientTzCanonical = normalizeTimezone(browserTimezone);
  const ipTzCanonical = normalizeTimezone(ipTimezone === 'Unavailable' ? '' : ipTimezone);
  const hasTzMismatch = Boolean(
    clientTzCanonical &&
      ipTzCanonical &&
      clientTzCanonical.toLowerCase() !== ipTzCanonical.toLowerCase()
  );

  const tamperDetected = Boolean(raw?.tamperDetected);
  const tamperReasons = safeStrArray(raw?.tamperReasons);

  const incognitoLikely = Boolean(raw?.incognitoLikely);
  const storageQuotaMb =
    typeof raw?.storageQuotaMb === 'number' &&
    Number.isFinite(raw.storageQuotaMb) &&
    raw.storageQuotaMb > 0
      ? Math.round(raw.storageQuotaMb)
      : null;

  // Task 3 — deep technical detection signals read off the raw collector payload with the
  // same forward-compat wrapping the original cloudOrMaskedGpu pass-through used, so
  // absent / unknown fields normalize to safe defaults instead of undefined. The deprecated
  // DevTools / ad-blocker / WebRTC / visit-velocity points are no longer scored: their fields
  // survive as inert values purely for response-shape backward compatibility.
  const webrtcCandidateIp =
    typeof raw?.webrtcCandidateIp === 'string' && raw.webrtcCandidateIp.trim()
      ? raw.webrtcCandidateIp.trim().slice(0, 64)
      : null;
  const webrtcDetail =
    typeof raw?.webrtcDetail === 'string' && raw.webrtcDetail.trim()
      ? raw.webrtcDetail.trim().slice(0, 200)
      : '';
  const privacyProtected = Boolean(raw?.privacyProtected);
  const privacyDetail =
    typeof raw?.privacyDetail === 'string' && raw.privacyDetail.trim()
      ? raw.privacyDetail.trim().slice(0, 200)
      : '';
  const canvasFarblingDetected = Boolean(raw?.canvasFarblingDetected);
  const isVirtualMachine = Boolean(raw?.isVirtualMachine);
  const isOsTampered = Boolean(raw?.isOsTampered);
  const vmReason =
    typeof raw?.vmReason === 'string' && raw.vmReason.trim()
      ? raw.vmReason.trim().slice(0, 200)
      : '';
  const incognitoMethod =
    typeof raw?.incognitoMethod === 'string' && raw.incognitoMethod.trim()
      ? raw.incognitoMethod.trim().slice(0, 120)
      : '';
  const headroomGiB =
    typeof raw?.headroomGiB === 'number' && Number.isFinite(raw.headroomGiB)
      ? Number(raw.headroomGiB)
      : null;
  const idbDurabilityRatio =
    typeof raw?.idbDurabilityRatio === 'number' && Number.isFinite(raw.idbDurabilityRatio)
      ? Number(raw.idbDurabilityRatio)
      : null;
  const opfsFlushMs =
    typeof raw?.opfsFlushMs === 'number' && Number.isFinite(raw.opfsFlushMs)
      ? Number(raw.opfsFlushMs)
      : null;
  // Forward-compatibility pass-through for the masked GPU flag (kept as pure pass-through so
  // the per-visit history row mapping keeps reading securitySignals.cloudOrMaskedGpu).
  const cloudOrMaskedGpu = Boolean(
    (raw as (Partial<SecuritySignals> & { cloudOrMaskedGpu?: boolean }) | null | undefined)
      ?.cloudOrMaskedGpu
  );

  // Persistence mode resolution order is fixed: hardware-fingerprint recovery wins, then a
  // private / restricted storage context, else a first-party cookie.
  let persistenceMode: SecuritySignals['persistenceMode'] = 'First-Party Cookie';
  if (recognitionSource === 'Hardware Fingerprint (Cookie-less / Incognito)') {
    persistenceMode = 'Hardware ID Recovered';
  } else if (incognitoLikely) {
    persistenceMode = 'Private / Restricted Storage';
  }

  // Incognito cross-reference: a device recognized purely through its hardware fingerprint
  // means no first-party cookie / storage token survived — treat as incognito or cleared.
  // Exhaustive: raw client flag, the hardware-fingerprint recognition path, or a persistence
  // mode that resolves to 'Hardware ID Recovered' all count as incognito / cleared storage.
  const incognitoOrCleared =
    Boolean(raw?.incognitoOrCleared) ||
    recognitionSource === 'Hardware Fingerprint (Cookie-less / Incognito)' ||
    persistenceMode === 'Hardware ID Recovered';

  // Final incognito verdict: the client's own storage probe, or the server-side cross-session
  // proof — an ephemeral context with no surviving cookie / localStorage / signed backup.
  const clientReportedIncognito =
    Boolean(incognitoContext.clientReportedIncognito) || incognitoLikely;
  const serverCrossModeIncognito = Boolean(
    !incognitoContext.hadPersistentClientState &&
      (incognitoContext.existingHwidVisitor || incognitoContext.crossSessionEphemeral)
  );
  const isIncognito = Boolean(clientReportedIncognito || serverCrossModeIncognito);

  const tierFor = (score: number): RiskLevel =>
    score >= 7 ? 'High' : score >= 3 ? 'Medium' : 'Low';
  const levelFor = (score: number): SmartSignalLevel =>
    score >= 7 ? 'high' : score >= 3 ? 'medium' : 'low';

  /* ---- 4-signal Smart Signals grid, every tile rated strictly out of 10 ---- */

  // Tile 1 — Incognito / Private Browsing (4)
  const incognitoScore = isIncognito ? 4 : 0;
  const incognitoSignal: SmartSignal = {
    id: 'incognito',
    title: 'Incognito / Private Browsing',
    status: isIncognito ? 'Incognito / Private Mode' : 'Standard Window',
    scoreOutOf10: incognitoScore,
    riskLabel: `${tierFor(incognitoScore)} Risk • ${incognitoScore}/10`,
    level: levelFor(incognitoScore),
    detail: isIncognito
      ? `Ephemeral RAM storage detected (${
          incognitoMethod || 'In-memory LevelDB / Cookie-less known hwid'
        })`
      : `Persistent disk-backed storage verified (${incognitoMethod || 'Standard profile'})`,
  };

  // Tile 2 — Bot & Automation Detection (9 / 7 / 0)
  const botScore = isBot ? 9 : isHeadless ? 7 : 0;
  const botSignal: SmartSignal = {
    id: 'bot',
    title: 'Bot & Automation Detection',
    status: isBot ? 'Bot / Automated' : isHeadless ? 'Cloud / Headless' : 'Verified Human',
    scoreOutOf10: botScore,
    riskLabel: `${tierFor(botScore)} Risk • ${botScore}/10`,
    level: levelFor(botScore),
    detail:
      botReason ||
      (isBot
        ? 'WebDriver / CDP automation runtime detected'
        : isHeadless
        ? 'Headless rendering context without an attached physical display'
        : 'No automation, WebDriver, CDP hooks, or headless runtime detected'),
  };

  // Tile 3 — VPN / Proxy & Network Type (8 / 6 / 5 / 0)
  const isDatacenterAsn = datacenterAsn;
  const ispBrand = classification.brandName || location.isp || 'Unknown ISP';
  const asnSuffix = location.asn !== 'Unknown' ? ` • ${location.asn}` : '';
  const vpnScore =
    isDatacenterAsn && hasTzMismatch ? 8 : isDatacenterAsn ? 6 : hasTzMismatch ? 5 : 0;
  const vpnSignal: SmartSignal = {
    id: 'vpn',
    title: 'VPN / Proxy & Network Type',
    status: isDatacenterAsn
      ? 'VPN / Datacenter Proxy'
      : hasTzMismatch
      ? 'VPN / Timezone Relay'
      : ispBrand !== 'Unknown ISP'
      ? `Standard ISP (${ispBrand})`
      : 'Standard ISP',
    scoreOutOf10: vpnScore,
    riskLabel: `${tierFor(vpnScore)} Risk • ${vpnScore}/10`,
    level: levelFor(vpnScore),
    detail:
      isDatacenterAsn && hasTzMismatch
        ? `Datacenter ASN (${ispBrand}${asnSuffix}) combined with a browser/IP timezone mismatch (${clientTzCanonical} vs ${ipTzCanonical})`
        : isDatacenterAsn
        ? `Datacenter / hosting ASN detected on ${ispBrand}${asnSuffix}`
        : hasTzMismatch
        ? `Browser timezone (${browserTimezone}) differs from IP geolocation timezone (${ipTimezone})`
        : `${ispBrand} • ${classification.networkType} verified against browser timezone ${browserTimezone}`,
  };

  // Tile 4 — Virtual Machine & OS Integrity (8 / 7 / 6 / 0)
  const isVm = isVirtualMachine;
  const isTampered = isOsTampered;
  const vmScore = isVm && isTampered ? 8 : isVm ? 7 : isTampered ? 6 : 0;
  const vmSignal: SmartSignal = {
    id: 'vm',
    title: 'Virtual Machine & OS Integrity',
    status:
      isVm && isTampered
        ? 'Virtual Machine / Spoofed OS'
        : isVm
        ? 'Virtual Machine / Hypervisor'
        : isTampered
        ? 'Spoofed OS / Tampered UA'
        : 'Physical Hardware',
    scoreOutOf10: vmScore,
    riskLabel: `${tierFor(vmScore)} Risk • ${vmScore}/10`,
    level: levelFor(vmScore),
    detail:
      vmReason ||
      (isTampered
        ? tamperReasons[0] || 'Operating-system / User-Agent tampering detected'
        : 'Unmasked physical GPU & consistent OS platform verified'),
  };

  const smartSignals: SmartSignals = {
    incognito: incognitoSignal,
    bot: botSignal,
    vpn: vpnSignal,
    vm: vmSignal,
  };

  // Composite — bot/headless 5|4, network 3|2, VM/tampered-OS 3, incognito 2 (strictly ≤ 10).
  const rawCompositePoints =
    (isBot ? 5 : isHeadless ? 4 : 0) +
    (isDatacenterAsn ? 3 : hasTzMismatch ? 2 : 0) +
    (vmScore > 0 ? 3 : 0) +
    (isIncognito ? 2 : 0);
  const suspectScore = Math.min(10, rawCompositePoints);
  const riskLevel: SecuritySignals['riskLevel'] = tierFor(suspectScore);
  const riskBadgeText = `${riskLevel} Risk • ${suspectScore}/10`;

  // Risk factors mirror the composite weights that actually fired. The deprecated DevTools /
  // ad-blocker / WebRTC / visit-velocity points are intentionally absent.
  const riskFactors: string[] = [];
  if (isBot) {
    riskFactors.push(
      `Automated browser / bot runtime detected (+5): ${
        botReason || botSignals[0] || 'WebDriver / CDP automation signatures'
      }`
    );
  } else if (isHeadless) {
    riskFactors.push(
      `Headless browser environment (+4): ${botReason || 'no physical display attached'}`
    );
  }
  if (isDatacenterAsn) {
    riskFactors.push(
      `Datacenter / hosting network detected (+3): ${vpnReasons[0] || ispBrand}`
    );
  } else if (hasTzMismatch) {
    riskFactors.push(
      `Browser timezone differs from IP geolocation (+2): ${clientTzCanonical} vs ${ipTzCanonical}`
    );
  }
  if (vmScore > 0) {
    riskFactors.push(`Virtual machine / tampered OS (+3): ${vmSignal.detail}`);
  }
  if (isIncognito) {
    riskFactors.push(`Incognito / ephemeral storage (+2): ${incognitoSignal.detail}`);
  }

  const securitySignalsCore: SecuritySignals = {
    isBot,
    botSignals,
    vpnSuspected,
    timezoneMismatch,
    datacenterAsn,
    vpnReasons,
    browserTimezone,
    ipTimezone,
    tamperDetected,
    tamperReasons,
    incognitoLikely,
    storageQuotaMb,
    persistenceMode,
    suspectScore,
    riskLevel,
    riskFactors,
  };

  // Forward-compatibility pass-through: newly introduced collector fields are never stripped
  // during sanitization. Values are spread from a typed object so this stays strict-clean
  // even when the shared SecuritySignals interface lags behind the collector.
  return {
    ...securitySignalsCore,
    ...({
      cloudOrMaskedGpu,
      // Task 1 — ISP brand & network classification from the server-resolved location
      brandName: classification.brandName,
      networkType: classification.networkType,
      isConsumerBroadband: classification.isConsumerBroadband,
      isDatacenterOrHosting: classification.isDatacenterOrHosting,
      // Task 3 — deep technical detection signals
      webrtcLeak: false,
      webrtcCandidateIp,
      webrtcDetail,
      privacyProtected,
      privacyDetail,
      // Deprecated scoring inputs kept inert for response-shape backward compatibility.
      adBlockerDetected: false,
      devToolsOpen: false,
      canvasFarblingDetected,
      isVirtualMachine,
      vmReason,
      isOsTampered,
      incognitoOrCleared,
      // Client-side composite private-browsing probe (confidence 0..1 + evidence)
      incognitoConfidence: Math.max(
        0,
        Math.min(
          1,
          typeof raw?.incognitoConfidence === 'number' && Number.isFinite(raw.incognitoConfidence)
            ? raw.incognitoConfidence
            : 0
        )
      ),
      incognitoDetail:
        typeof raw?.incognitoDetail === 'string' ? raw.incognitoDetail.trim().slice(0, 240) : '',
      // Final 4-signal upgrade — private browsing, bot, network, VM integrity
      isIncognito,
      incognito: isIncognito,
      privateMode: isIncognito,
      incognitoMethod,
      headroomGiB,
      idbDurabilityRatio,
      opfsFlushMs,
      isHeadless,
      botReason,
      webdriver,
      cdpDetected,
      smartSignals,
      riskBadgeText,
      // Task 3 — visit velocity / IP rotation (display only, never scored)
      distinctIpsLastHour: velocity.distinctIpsLastHour,
      visitsLastHour: velocity.visitsLastHour,
    } as Partial<SecuritySignals> & { cloudOrMaskedGpu?: boolean }),
  };
}

app.post('/api/visitor/identify', async (req, res) => {
  try {
    const requestBody = (req.body || {}) as {
      pageLoadId?: string;
      storedVisitorId?: string | null;
      storedVisitorToken?: string | null;
      clientSessionId?: string | null;
      clientHistoryBackup?: SignedHistoryBackup | null;
      browserDevice?: Partial<BrowserDeviceInfo>;
      hardwareSignals?: Partial<HardwareSignals> | null;
      securitySignals?: Partial<SecuritySignals> | null;
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
        timezone?: string;
        isVpnOrHosting?: boolean;
      } | null;
      /** Alternate / legacy incognito spellings a client may post at the top level. */
      incognito?: boolean;
      isIncognito?: boolean;
      privateMode?: boolean;
      incognitoMethod?: string;
      idbDurabilityRatio?: number | null;
      opfsFlushMs?: number | null;
      browserInfo?: { incognito?: boolean; isIncognito?: boolean } | null;
      telemetry?: { incognito?: boolean; isIncognito?: boolean } | null;
    };

    const {
      pageLoadId,
      storedVisitorId,
      storedVisitorToken,
      clientSessionId,
      clientHistoryBackup,
      browserDevice: rawBrowserDevice,
      hardwareSignals: rawHardwareSignals,
      securitySignals: rawSecuritySignals,
      clientGeoHint,
    } = requestBody;

    const safePageLoadId =
      typeof pageLoadId === 'string' && pageLoadId.trim().length > 0
        ? pageLoadId.trim().slice(0, 80)
        : 'pl_' + crypto.randomBytes(8).toString('hex');

    const browserDevice = sanitizeBrowserDevice(rawBrowserDevice);
    const hardwareSignals = sanitizeHardwareSignals(rawHardwareSignals, browserDevice);
    const hardwareId = hardwareSignals.hardwareId;

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

    // Task 1 — the classification is derived from the SERVER-RESOLVED location only (the
    // clientGeoHint ISP / org / ASN was merged into this location above when trusted), so it
    // is the authoritative source; the client hint is never classified separately.
    const classification = classifyIspNetwork(location.isp, location.org, location.asn);

    const cookieVid = req.cookies?.intel_http_vid as string | undefined;
    const cookieToken = req.cookies?.intel_http_token as string | undefined;

    let existingVisitor: VisitorRow | undefined;
    let recognitionSource: IntelVisitorResponse['recognitionSource'] = 'New First-Party ID';
    // True only when this request recovered an ALREADY EXISTING row purely by hardware
    // fingerprint — i.e. no cookie / localStorage identity survived.
    let existingHwidVisitor = false;

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
            visitor_id, hmac_token, hardware_id, created_at_utc, updated_at_utc, active_session_id, last_activity_utc
          ) VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).run(
          verifiedVid,
          verifiedToken,
          hardwareId,
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
    } else if (hardwareId) {
      // Cookie-less / Incognito recovery: look up visitor by deterministic Hardware ID (hwid_...)
      const hwMatchedVisitor = db
        .prepare('SELECT * FROM visitors WHERE hardware_id = ?')
        .get(hardwareId) as VisitorRow | undefined;

      if (hwMatchedVisitor) {
        existingVisitor = hwMatchedVisitor;
        existingHwidVisitor = true;
        recognitionSource = 'Hardware Fingerprint (Cookie-less / Incognito)';
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
           SET updated_at_utc = ?, active_session_id = ?, last_activity_utc = ?, hardware_id = ?
           WHERE visitor_id = ?`
        ).run(nowUtc, currentSessionId, nowUtc, hardwareId, visitorId);
      }
    } else {
      visitorId = generateVisitorId();
      visitorToken = signVisitorId(visitorId);
      currentSessionId = generateSessionId();
      isReturning = false;

      db.prepare(
        `INSERT INTO visitors (
          visitor_id, hmac_token, hardware_id, created_at_utc, updated_at_utc, active_session_id, last_activity_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(visitorId, visitorToken, hardwareId, nowUtc, nowUtc, currentSessionId, nowUtc);

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
          id, visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
          public_ip, city, region, country, latitude, longitude, isp, org, asn,
          browser, os, device_type, screen_resolution, language, timezone
         FROM visits
         WHERE visitor_id = ?
         ORDER BY visited_at_utc DESC, id DESC
         LIMIT 50`
      )
      .all(visitorId) as Array<Record<string, unknown>>;

    const ipTimezoneHint =
      (typeof clientGeoHint?.timezone === 'string' && clientGeoHint.timezone.trim()) ||
      vercelGeo.timezone ||
      '';

    // Task 3 — visit velocity / IP rotation across the last hour. rawVisits is fetched AFTER
    // the current visit is inserted, so the visit being logged right now is already part of
    // the window; when the insert was deduplicated by page_load_id the current visit still
    // counts (minimum of one), and its public IP is included in the distinct set. The cutoff
    // `new Date(Date.now() - 3600 * 1000).toISOString()` is applied via Date.parse so rows
    // from mixed legacy formats still compare on the same UTC instant scale.
    const oneHourAgoMs = Date.now() - 3600 * 1000;
    const lastHourVisitRows = rawVisits.filter((r) => {
      const visitedAtMs = Date.parse(String(r.visited_at_utc || ''));
      return Number.isFinite(visitedAtMs) && visitedAtMs >= oneHourAgoMs;
    });
    const lastHourIpSet = new Set<string>();
    for (const lastHourRow of lastHourVisitRows) {
      const lastHourIp = String(lastHourRow.public_ip || '').trim();
      if (lastHourIp && lastHourIp !== 'Unavailable') lastHourIpSet.add(lastHourIp);
    }
    const currentVisitIp = String(location.publicIp || '').trim();
    if (currentVisitIp && currentVisitIp !== 'Unavailable') {
      lastHourIpSet.add(currentVisitIp);
    }
    const visitsLastHour = Math.max(1, lastHourVisitRows.length);
    const distinctIpsLastHour = lastHourIpSet.size;

    // Incognito cross-mode inputs. Persistent client state means a verified first-party cookie,
    // a verified body visitor id, or a valid signed history backup. When none of those survived
    // AND this request recovered an existing hardware-ID row, the browsing context is ephemeral.
    const bodyVisitorId = storageVerified ? storedVisitorId ?? null : null;
    const historyBackupValid = Boolean(validBackupForStats);
    const hadPersistentClientState = Boolean(cookieVid || bodyVisitorId || historyBackupValid);

    // Accept every incognito spelling this app (and its legacy payloads) can post:
    // top-level, browserInfo.*, telemetry.*, securitySignals.* and any alias.
    const clientReportedIncognito = Boolean(
      requestBody.incognito ?? requestBody.isIncognito ?? requestBody.privateMode ??
      requestBody.browserInfo?.incognito ?? requestBody.browserInfo?.isIncognito ??
      requestBody.telemetry?.incognito ?? requestBody.telemetry?.isIncognito ??
      rawSecuritySignals?.isIncognito ?? rawSecuritySignals?.incognito ??
      rawSecuritySignals?.privateMode ?? rawSecuritySignals?.incognitoLikely
    );

    // Fingerprint.com-style ephemeral-storage correlation. Only meaningful when NO persistent
    // client state survived (no verified cookie, no verified body visitor id, no signed backup).
    // Case A is the existing `hwid_...` lookup hit (`existingHwidVisitor`). Case B looks for an
    // earlier visit by this same physical device inside the last 7 days that belongs to a
    // DIFFERENT visitor id — `visitors.hardware_id` is the persisted GPU-derived identity
    // column (there is no GPU renderer column on `visits`), so it is matched together with the
    // per-visit columns the schema actually has: public_ip, screen_resolution, browser, os.
    let crossSessionEphemeral = false;
    if (!hadPersistentClientState && !existingHwidVisitor && hardwareId) {
      try {
        const sevenDaysAgoUtc = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
        const earlierDeviceVisit = db
          .prepare(
            `SELECT v.visitor_id
             FROM visits v
             JOIN visitors pv ON pv.visitor_id = v.visitor_id
             WHERE v.visitor_id != ?
               AND pv.hardware_id = ?
               AND v.public_ip = ?
               AND v.screen_resolution = ?
               AND v.browser = ?
               AND v.os = ?
               AND v.visited_at_utc >= ?
             ORDER BY v.visited_at_utc DESC
             LIMIT 1`
          )
          .get(
            visitorId,
            hardwareId,
            location.publicIp,
            browserDevice.screenResolution,
            browserDevice.browser,
            browserDevice.os,
            sevenDaysAgoUtc
          ) as { visitor_id: string } | undefined;
        crossSessionEphemeral = Boolean(earlierDeviceVisit);
      } catch {
        // A correlation query failure must never 500 the identify endpoint.
        crossSessionEphemeral = false;
      }
    }

    const securitySignalsInput: Partial<SecuritySignals> | null | undefined =
      rawSecuritySignals || requestBody.incognitoMethod
        ? {
            ...(rawSecuritySignals ?? {}),
            // Top-level method spelling is honoured when securitySignals omitted it.
            incognitoMethod: rawSecuritySignals?.incognitoMethod ?? requestBody.incognitoMethod,
          }
        : rawSecuritySignals;

    const securitySignals = sanitizeAndReinforceSecuritySignals(
      securitySignalsInput,
      browserDevice,
      hardwareSignals,
      location,
      ipTimezoneHint,
      recognitionSource,
      classification,
      { visitsLastHour, distinctIpsLastHour },
      {
        hadPersistentClientState,
        existingHwidVisitor,
        clientReportedIncognito,
        crossSessionEphemeral,
      }
    );

    // Every history row always carries suspectScore / riskLevel / recognitionSource so the UI
    // never renders `undefined`. Stored per-visit risk data is used when present; the current
    // visit falls back to the just-computed security signals; legacy rows use safe defaults.
    const visitHistory = rawVisits.map((r) => {
      // Task 2b — legacy rows stored per-visit scores on a 0..100 scale; values above 10 are
      // rescaled so stored scores always render on the same 0..10 scale as the current visit.
      const storedSuspectScore =
        typeof r.suspect_score === 'number' && Number.isFinite(r.suspect_score)
          ? normalizeLegacySuspectScore(r.suspect_score)
          : null;
      const isCurrentVisitRow = String(r.page_load_id || '') === safePageLoadId;
      const rowSuspectScore =
        storedSuspectScore !== null
          ? storedSuspectScore
          : isCurrentVisitRow
          ? securitySignals.suspectScore
          : 0;
      const rowRiskLevel: RiskLevel =
        rowSuspectScore >= 7 ? 'High' : rowSuspectScore >= 3 ? 'Medium' : 'Low';
      const rowRecognitionSource = isCurrentVisitRow ? recognitionSource : 'Cookie';
      const rowCloudOrMaskedGpu = isCurrentVisitRow
        ? Boolean(
            (securitySignals as SecuritySignals & { cloudOrMaskedGpu?: boolean }).cloudOrMaskedGpu
          )
        : false;

      return {
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
        suspectScore: rowSuspectScore,
        riskLevel: rowRiskLevel,
        recognitionSource: rowRecognitionSource,
        cloudOrMaskedGpu: rowCloudOrMaskedGpu,
      };
    });

    const historyBackup = createSignedHistoryBackup(
      visitorId,
      statistics.totalVisits,
      statistics.totalSessions,
      statistics.firstVisitUtc,
      visitHistory,
      hardwareId
    );

    const payload: IntelVisitorResponse = {
      visitorId,
      visitorToken,
      hardwareId,
      isReturning,
      recognitionSource,
      location,
      browserDevice,
      hardwareSignals,
      securitySignals,
      statistics,
      visitHistory,
      historyBackup,
      // Top-level mirrors so clients can read the 4-signal verdict without digging.
      isIncognito: securitySignals.isIncognito,
      incognito: securitySignals.isIncognito,
      suspectScore: securitySignals.suspectScore,
      riskLevel: securitySignals.riskLevel,
      riskBadgeText: securitySignals.riskBadgeText,
      smartSignals: securitySignals.smartSignals,
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

  const rawVisits = db
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
    .all(requestedVisitorId) as Array<Record<string, unknown>>;

  // Every row always carries suspectScore / riskLevel / recognitionSource (with safe defaults
  // for legacy rows that have no stored per-visit risk record). Task 2b — legacy 0..100
  // scores above 10 are rescaled so every response speaks the 0..10 scale.
  const visits = rawVisits.map((row) => {
    const storedSuspectScore =
      typeof row.suspect_score === 'number' && Number.isFinite(row.suspect_score)
        ? normalizeLegacySuspectScore(row.suspect_score)
        : 0;
    const storedRecognitionSource =
      typeof row.recognition_source === 'string' && row.recognition_source.trim()
        ? row.recognition_source
        : 'Cookie';
    const rowRiskLevel: RiskLevel =
      storedSuspectScore >= 7 ? 'High' : storedSuspectScore >= 3 ? 'Medium' : 'Low';

    return {
      ...row,
      suspectScore: storedSuspectScore,
      riskLevel: rowRiskLevel,
      recognitionSource: storedRecognitionSource,
    };
  });

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

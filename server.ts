import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import net from 'net';
import os from 'os';
import path from 'path';
import fs from 'fs';
import dns from 'node:dns/promises';
import { createRequire } from 'module';
import dotenv from 'dotenv';
import type {
  AiAgentAttribution,
  BrowserDeviceInfo,
  BotSubtype,
  HardwareSignals,
  IspNetworkClassification,
  SecurityEnvelope,
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
 * Public Tor relay operators. An address routed through one of these ASNs is anonymity
 * infrastructure even before any DNS answer arrives, so the network badge must never present
 * it as consumer broadband.
 */
const TOR_OPERATOR_ASN_SET = new Set<string>([
  'AS215125', // Church of Cyberology / Nothing to Hide
  'AS60729', // Zwiebelfreunde e.V. / Torservers.net
  'AS208323', // Foundation for Applied Privacy
  'AS396507', // Emerald Onion
  'AS200052', // Artikel10 e.V.
  'AS206848', // CCC Stuttgart / Chaos Computer Club
  'AS205100', // F3 Netze e.V.
  'AS199695', // Nos Oignons
]);

const TOR_OPERATOR_ORG_PATTERN =
  /\b(church of cyberology|cyberology|nothing to hide|nothingtohide|hart voor internetvrijheid|zwiebelfreunde|torservers|emerald onion|emeraldonion|applied privacy|applied-privacy|nos oignons|nos-oignons|artikel10|f3\s?netze|ccc stuttgart|r0cket|tor\s?exit|tor\s?relay)\b/i;

/** Prefixes dedicated to Tor relay operators. */
const TOR_OPERATOR_IPV4_CIDRS = ['192.42.116.0/24'];
const TOR_OPERATOR_IPV6_PREFIXES = ['2001:67c:e60::/48', '2a02:898:256::/48'];

/** Reverse-DNS hostnames that only Tor relay operators publish. */
const TOR_OPERATOR_REVERSE_DNS_PATTERN =
  /\b(tor-?exit|tor-?relay|exit-?node|nothingtohide\.nl|hartvoorinternetvrijheid\.nl|cyberology\.(nl|church)|torservers\.net|emeraldonion\.org|applied-privacy\.net|artikel10\.org|nos-oignons\.net|tor\.r0cket\.net)\b/i;

const VPN_PROXY_PATTERN =
  /\b(vpn|nordvpn|expressvpn|surfshark|cyberghost|private internet access|proton\s?vpn|mullvad|windscribe|ipvanish|hide\.?me|hola vpn|psiphon|packet hub|packethub|tor ?guard|proxy|socks5|smart dns)\b/i;

// Indian carriers (Jio / Airtel) are intentionally absent: their branded consumer rules label
// them as Residential Broadband, and the mobile step must not pre-empt those.
const MOBILE_CARRIER_PATTERN =
  /\b(mobile|cellular|wireless|5g|4g|lte|t-mobile|tmobile|verizon wireless|cellco|vodafone|orange s\.?a|telefonica|movistar|claro|tim s\.?p\.?a|mtn)\b/i;

function matchesTorOperatorAsn(asn: string): boolean {
  const clean = typeof asn === 'string' ? asn.trim().toUpperCase() : '';
  if (!clean) return false;
  return TOR_OPERATOR_ASN_SET.has(clean.startsWith('AS') ? clean : `AS${clean}`);
}

/**
 * Server-side mirror of the collector's ISP brand and network-type classifier (Task 1).
 *
 * Intentionally a self-contained copy so the Node API bundle never imports the browser
 * collector module; brand names, network types and consumer / hosting flags must match
 * the client helper exactly. Consumer broadband rules are evaluated BEFORE the
 * cloud / datacenter rule so that e.g. Google Fiber (AS16591) is never swallowed by the
 * generic 'google' cloud keywords.
 *
 * Classification priority is strict and descending: consumer broadband is only ever returned
 * when the ISP positively matches an explicit consumer ISP rule. Every unrecognised network
 * falls back to 'Unknown Network' — never to 'Residential Broadband'.
 */
export function classifyIspNetwork(isp: string, org: string, asn: string): IspNetworkClassification {
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

  // Branded consumer rules are closures so each family can be evaluated at its exact priority
  // slot (mobile home / satellite / residential) after Tor, cloud, VPN and mobile verdicts.
  const mobileHomeMatch = (): IspNetworkClassification | null =>
    matchConsumerRule('Verizon 5G Home', 'Cellular / 5G', [6167, 22394], /cellco|verizon wireless/i) ||
    matchConsumerRule('T-Mobile 5G Home', 'Cellular / 5G', [21928], /t-mobile|tmobile/i);

  const satelliteMatch = (): IspNetworkClassification | null =>
    matchConsumerRule('Starlink (SpaceX)', 'Satellite', [14593], /starlink|spacex/i);

  const residentialMatch = (): IspNetworkClassification | null =>
    // US consumer broadband (Residential Broadband)
    matchConsumerRule('Xfinity (Comcast)', 'Residential Broadband', [7922, 7015, 7016], /comcast|xfinity/i) ||
    matchConsumerRule('Spectrum (Charter)', 'Residential Broadband', [20115, 11426, 10796], /charter|spectrum/i) ||
    matchConsumerRule('AT&T Fiber', 'Residential Broadband', [7018, 20057], /at&t|att services|sbcglobal/i) ||
    matchConsumerRule('Verizon Fios', 'Residential Broadband', [701, 19262], /fios|mci communications|verizon online/i) ||
    matchConsumerRule('Optimum', 'Residential Broadband', [6128, 19108], /optimum|cablevision|altice|suddenlink/i) ||
    matchConsumerRule('Cox', 'Residential Broadband', [22773], /\bcox\b/i) ||
    matchConsumerRule('Frontier / CenturyLink', 'Residential Broadband', [5650, 209], null) ||
    matchConsumerRule('Google Fiber', 'Residential Broadband', [16591], /google fiber|gfiber/i) ||
    // India consumer broadband (Residential Broadband)
    matchConsumerRule('Jio (Reliance Jio)', 'Residential Broadband', [55836], /reliance jio|\bjio\b/i) ||
    matchConsumerRule('Airtel Xstream', 'Residential Broadband', [24560, 45609, 9498], /bharti airtel|\bairtel\b/i) ||
    matchConsumerRule('ACT Fibernet', 'Residential Broadband', [24309], /act fibernet|atria convergence/i) ||
    matchConsumerRule('BSNL Broadband', 'Residential Broadband', [9829], /\bbsnl\b|bharat sanchar/i) ||
    matchConsumerRule('Tata Play / Hathway', 'Residential Broadband', [], /tata play|tata sky broadband|hathway|excitel/i);

  // Tor relay operators, before any hosting rule: anonymity infrastructure must never be
  // reported as a consumer connection or a generic cloud host.
  const asnTokenHits = Array.from(asnNumbers).map((n) => `AS${n}`);
  const torAsnHit = asnTokenHits.find((token) => matchesTorOperatorAsn(token));
  const torOrgHit = TOR_OPERATOR_ORG_PATTERN.test(keywordHaystack);
  if (torAsnHit !== undefined || torOrgHit) {
    return {
      brandName:
        cleanIsp && !/^unknown( isp)?$/i.test(cleanIsp)
          ? cleanIsp
          : cleanOrg && !/^unknown( isp)?$/i.test(cleanOrg)
          ? cleanOrg
          : 'Tor Relay Operator',
      networkType: 'Tor Exit / Anonymity Network',
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: torAsnHit !== undefined ? `Tor operator ASN ${torAsnHit}` : 'Tor operator organisation',
    };
  }

  // Cloud / datacenter — only reached when no consumer rule matched above.
  const cloudAsnHit = Array.from(asnNumbers).find((n) => CLOUD_PROVIDER_ASN_NUMBERS.has(n));
  const cloudKeywords =
    /google llc|google cloud|amazonaws|cloudflare|digitalocean|hetzner|m247|datacamp|linode|ovh|choopa|vultr|leaseweb|hostinger|contabo|akamai|oracle cloud|alibaba|aliyun|tencent cloud/i;
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

  // Commercial VPN / privacy proxy.
  if (VPN_PROXY_PATTERN.test(keywordHaystack)) {
    return {
      brandName: cleanIsp || cleanOrg || 'VPN / Proxy Provider',
      networkType: 'VPN / Proxy Relay',
      isConsumerBroadband: false,
      isDatacenterOrHosting: false,
      matchedReason: 'VPN / proxy provider keyword',
    };
  }

  // Mobile carrier — branded 5G home products keep their Sharp 'Cellular / 5G' label.
  const mobileHome = mobileHomeMatch();
  if (mobileHome) return mobileHome;
  if (MOBILE_CARRIER_PATTERN.test(keywordHaystack)) {
    return {
      brandName: cleanIsp || cleanOrg || 'Mobile Carrier',
      networkType: 'Mobile Carrier',
      isConsumerBroadband: false,
      isDatacenterOrHosting: false,
      matchedReason: 'Cellular carrier keyword',
    };
  }

  // Satellite consumer links.
  const satellite = satelliteMatch();
  if (satellite) return satellite;

  // Residential broadband — ONLY on a positive branded / ASN match, never as a default.
  const residential = residentialMatch();
  if (residential) return residential;

  // Unknown / unrecognised network: never claim residential broadband without positive proof.
  return {
    brandName:
      cleanIsp && !/^(unknown|unknown isp|n\/a)$/i.test(cleanIsp)
        ? cleanIsp
        : cleanOrg && !/^(unknown|unknown isp|n\/a)$/i.test(cleanOrg)
        ? cleanOrg
        : 'Unknown ISP',
    networkType: 'Unknown Network',
    isConsumerBroadband: false,
    isDatacenterOrHosting: false,
    matchedReason: null,
  };
}

/**
 * Reconciles the operator-level classification with the verdicts produced by the Tor, AI-agent
 * and VM engines. Priority is strict: Tor anonymity > AI agent cloud > datacenter/VM > VPN >
 * mobile > residential > unknown.
 */
function applyNetworkOverrides(
  base: IspNetworkClassification,
  context: {
    torExit: boolean;
    torOperatorHint: boolean;
    isTorBrowserClient: boolean;
    aiAgentDetected: boolean;
    datacenterVm: boolean;
    vpnSuspected: boolean;
  }
): IspNetworkClassification {
  const torNetwork =
    context.torExit ||
    context.torOperatorHint ||
    context.isTorBrowserClient ||
    base.networkType === 'Tor Exit / Anonymity Network';
  if (torNetwork) {
    return {
      ...base,
      networkType: 'Tor Exit / Anonymity Network',
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || 'Tor anonymity network',
    };
  }
  if (context.aiAgentDetected && base.networkType === 'Cloud / Datacenter') {
    return {
      ...base,
      networkType: 'AI Agent Cloud Network',
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || 'AI agent cloud infrastructure',
    };
  }
  if (context.datacenterVm && base.networkType !== 'Cloud / Datacenter') {
    return {
      ...base,
      networkType: 'Cloud / Datacenter',
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || 'Cloud VM / masked GPU footprint',
    };
  }
  if (context.vpnSuspected && base.networkType === 'Residential Broadband') {
    return {
      ...base,
      networkType: 'VPN / Proxy Relay',
      isConsumerBroadband: false,
      matchedReason: base.matchedReason || 'VPN indicator on a residential line',
    };
  }
  if (base.networkType === 'Residential Broadband' && !base.isConsumerBroadband) {
    return { ...base, networkType: 'Unknown Network' };
  }
  return base;
}

/* -------------------------------------------------------------------------- */
/* Phase 1 — bot / AI-agent subtype classification                            */
/* -------------------------------------------------------------------------- */

type RawHeaderBag = Record<string, string | string[] | undefined>;

interface BotClassification {
  subtype: BotSubtype;
  label: string;
  provider: string;
  category: string;
  confidence: number;
  reasons: string[];
}

interface BotNetworkIdentity {
  org?: string;
  isp?: string;
  asn?: string;
}

interface BotClientSignals {
  isBot?: boolean;
  isHeadless?: boolean;
  webdriver?: boolean;
  cdpDetected?: boolean;
  botSignals?: string[];
}

/** Reads a header case-insensitively, collapsing repeated headers into a comma list. */
function readRequestHeader(headers: RawHeaderBag | null | undefined, name: string): string {
  if (!headers) return '';
  const direct = headers[name.toLowerCase()];
  const raw = Array.isArray(direct) ? direct.join(', ') : direct;
  return typeof raw === 'string' ? raw.trim() : '';
}

/** Coarse browser / tool family used to compare a signed UA with the HTTP header. */
function detectUaFamily(userAgent: string): string {
  const ua = userAgent.toLowerCase();
  if (!ua) return '';
  if (/edg\//.test(ua)) return 'edge';
  if (/opr\/|opera/.test(ua)) return 'opera';
  if (/firefox\/|fxios/.test(ua)) return 'firefox';
  if (/chrome\/|crios|chromium\//.test(ua)) return 'chrome';
  if (/safari\//.test(ua)) return 'safari';
  if (/^curl\//.test(ua)) return 'curl';
  if (/postmanruntime/.test(ua)) return 'postman';
  if (/python-requests|python-urllib|aiohttp/.test(ua)) return 'python';
  if (/^wget\//.test(ua)) return 'wget';
  if (/^node-fetch|undici|axios/.test(ua)) return 'node';
  return '';
}

/** Coarse operating-system family used to compare a signed UA with the HTTP header. */
function detectUaOs(userAgent: string): string {
  const ua = userAgent.toLowerCase();
  if (/windows nt|win32|win64/.test(ua)) return 'windows';
  if (/android/.test(ua)) return 'android';
  if (/iphone|ipad|ipod/.test(ua)) return 'ios';
  if (/macintosh|mac os x/.test(ua)) return 'macos';
  if (/cros/.test(ua)) return 'chromeos';
  if (/linux|x11/.test(ua)) return 'linux';
  return '';
}

/**
 * Compares the HTTP User-Agent header with the signed payload UA. Edge proxies may
 * truncate long header values (Vercel cuts them at ~67 chars), so an exact match is not
 * required: a clean prefix relationship is the same client, otherwise the browser family
 * and OS must agree. Unknown signatures never trigger a tamper verdict.
 */
function userAgentsCompatible(headerUserAgent: string, payloadUserAgent: string): boolean {
  const header = headerUserAgent.trim();
  const payload = payloadUserAgent.trim();
  if (!header || !payload || header === payload) return true;
  const shorter = header.length <= payload.length ? header : payload;
  const longer = header.length <= payload.length ? payload : header;
  if (shorter.length >= 24 && longer.startsWith(shorter)) return true;
  const headerFamily = detectUaFamily(header);
  const payloadFamily = detectUaFamily(payload);
  if (headerFamily && payloadFamily && headerFamily !== payloadFamily) return false;
  const headerOs = detectUaOs(header);
  const payloadOs = detectUaOs(payload);
  if (headerOs && payloadOs && headerOs !== payloadOs) return false;
  return true;
}

const GOOD_BOT_UA_RULES: Array<{
  pattern: RegExp;
  provider: string;
  label: string;
  category: string;
  network: RegExp;
}> = [
  {
    pattern: /googlebot/i,
    provider: 'Google',
    label: 'Googlebot',
    category: 'Search Crawler',
    network: /google/i,
  },
  {
    pattern: /bingbot|bingpreview/i,
    provider: 'Microsoft',
    label: 'Bingbot',
    category: 'Search Crawler',
    network: /microsoft|\bbing\b/i,
  },
  {
    pattern: /applebot/i,
    provider: 'Apple',
    label: 'Applebot',
    category: 'Search Crawler',
    network: /\bapple\b/i,
  },
  {
    pattern: /duckduckbot/i,
    provider: 'DuckDuckGo',
    label: 'DuckDuckBot',
    category: 'Search Crawler',
    network: /duckduckgo/i,
  },
  {
    pattern: /linkedinbot/i,
    provider: 'LinkedIn',
    label: 'LinkedInBot',
    category: 'Link Preview',
    network: /linkedin/i,
  },
  {
    pattern: /twitterbot/i,
    provider: 'X (Twitter)',
    label: 'Twitterbot',
    category: 'Link Preview',
    network: /twitter|\bx corp\b/i,
  },
  {
    pattern: /slackbot/i,
    provider: 'Slack',
    label: 'Slackbot',
    category: 'Link Preview',
    network: /slack/i,
  },
  {
    pattern: /vercelbot/i,
    provider: 'Vercel',
    label: 'Vercelbot',
    category: 'Link Preview',
    network: /vercel/i,
  },
];

const AI_AGENT_UA_RULES: Array<{ pattern: RegExp; provider: string; label: string }> = [
  { pattern: /gptbot/i, provider: 'OpenAI', label: 'GPTBot' },
  { pattern: /chatgpt-user/i, provider: 'OpenAI', label: 'ChatGPT-User' },
  { pattern: /oai-searchbot/i, provider: 'OpenAI', label: 'OAI-SearchBot' },
  { pattern: /claudebot/i, provider: 'Anthropic', label: 'ClaudeBot' },
  { pattern: /claude-web/i, provider: 'Anthropic', label: 'Claude-Web' },
  { pattern: /anthropic-ai/i, provider: 'Anthropic', label: 'Anthropic-AI' },
  { pattern: /perplexitybot/i, provider: 'Perplexity', label: 'PerplexityBot' },
  { pattern: /perplexity-user/i, provider: 'Perplexity', label: 'Perplexity-User' },
  { pattern: /google-extended/i, provider: 'Google', label: 'Google-Extended' },
  { pattern: /ccbot/i, provider: 'Common Crawl', label: 'CCBot' },
  { pattern: /bytespider/i, provider: 'ByteDance', label: 'Bytespider' },
  { pattern: /cohere-ai/i, provider: 'Cohere', label: 'Cohere-AI' },
  { pattern: /meta-externalagent/i, provider: 'Meta', label: 'Meta-ExternalAgent' },
  { pattern: /headlesschrome/i, provider: 'Cloud Browser Agent', label: 'Headless Chrome' },
];

const AUTOMATION_UA_PATTERN = /playwright|puppeteer|selenium|cypress|phantomjs/i;

/** `keyid` fragments in Web Bot Auth `Signature-Input` headers → operator display names. */
const BOT_SIGNATURE_KEYID_PROVIDERS: Array<[string, string]> = [
  ['openai', 'OpenAI'],
  ['anthropic', 'Anthropic'],
  ['perplexity', 'Perplexity'],
  ['google', 'Google'],
  ['microsoft', 'Microsoft'],
  ['apple', 'Apple'],
  ['amazon', 'Amazon'],
  ['cloudflare', 'Cloudflare'],
  ['web-bot-auth', 'Web Bot Auth Directory'],
];

const DATACENTER_NETWORK_PATTERN =
  /\b(amazon|amazonaws|aws|google cloud|azure|microsoft azure|digitalocean|hetzner|linode|akamai|ovh|vultr|oracle cloud|alibaba|aliyun|tencent|leaseweb|contabo|m247|choopa|datacamp)\b/i;

const KNOWN_AI_CRAWLER_REASON = 'LLM crawler user-agent signature';

/**
 * Phase 1 — resolves the request identity into one of `human`, `good_bot`, `ai_agent`
 * or `bad_bot`. A search-crawler UA is only trusted when the network identity matches the
 * crawler operator; every other claim of that UA is a spoof. Automation runtimes and
 * header-incomplete desktop browsers fall through to `bad_bot`. Never throws.
 */
function classifyBotTraffic(
  headers: RawHeaderBag | null | undefined,
  network: BotNetworkIdentity,
  client: BotClientSignals
): BotClassification {
  const ua = readRequestHeader(headers, 'user-agent');
  const acceptLanguage = readRequestHeader(headers, 'accept-language');
  const secFetchSite = readRequestHeader(headers, 'sec-fetch-site');
  const secFetchMode = readRequestHeader(headers, 'sec-fetch-mode');
  const secFetchDest = readRequestHeader(headers, 'sec-fetch-dest');
  const networkHaystack = [network.org, network.isp, network.asn]
    .filter((part): part is string => typeof part === 'string' && part.trim().length > 0)
    .join(' ');
  const clientSignals = Array.isArray(client.botSignals)
    ? client.botSignals.filter((s): s is string => typeof s === 'string' && s.trim().length > 0)
    : [];

  for (const rule of GOOD_BOT_UA_RULES) {
    if (!rule.pattern.test(ua)) continue;
    if (rule.network.test(networkHaystack)) {
      return {
        subtype: 'good_bot',
        label: rule.label,
        provider: rule.provider,
        category: rule.category,
        confidence: 0.97,
        reasons: [
          `${rule.label} user-agent matched`,
          `Network identity (${networkHaystack || 'unknown'}) matches ${rule.provider}`,
        ],
      };
    }
    return {
      subtype: 'bad_bot',
      label: 'Spoofed Crawler',
      provider: `Unverified ${rule.provider} claim`,
      category: 'Spoofed Identity',
      confidence: 0.99,
      reasons: [
        `${rule.label} user-agent presented`,
        `Network identity (${networkHaystack || 'unknown'}) does not belong to ${rule.provider}`,
      ],
    };
  }

  for (const rule of AI_AGENT_UA_RULES) {
    if (!rule.pattern.test(ua)) continue;
    return {
      subtype: 'ai_agent',
      label: rule.label,
      provider: rule.provider,
      category: rule.provider === 'Cloud Browser Agent' ? 'Autonomous Agent' : 'AI Crawler',
      confidence: rule.provider === 'Cloud Browser Agent' ? 0.85 : 0.92,
      reasons: [
        `${rule.label} user-agent matched`,
        networkHaystack ? `Network identity: ${networkHaystack}` : 'Network identity unavailable',
      ],
    };
  }

  // RFC 9421 HTTP Message Signatures ("Web Bot Auth"): an agent that signs its request with a
  // `Signature` + `Signature-Input` pair is self-identifying as automated even when its
  // User-Agent imitates a desktop browser. Browsers never emit these headers. `keyid` names the
  // operator, so the tile can attribute it instead of printing a generic automation verdict.
  const signatureInput = readRequestHeader(headers, 'signature-input');
  const signatureHeader = readRequestHeader(headers, 'signature');
  if (signatureInput && signatureHeader) {
    const keyIdMatch = /keyid\s*=\s*"([^"]+)"/i.exec(signatureInput);
    const keyId = keyIdMatch ? keyIdMatch[1].trim().slice(0, 80) : '';
    const keyIdLower = keyId.toLowerCase();
    const namedOperator = BOT_SIGNATURE_KEYID_PROVIDERS.find(([needle]) =>
      keyIdLower.includes(needle)
    );
    return {
      subtype: 'ai_agent',
      label: 'Web Bot Auth Agent',
      provider: namedOperator ? namedOperator[1] : keyId || 'RFC 9421 Signer',
      category: 'Autonomous Agent',
      confidence: 0.9,
      reasons: [
        'RFC 9421 Signature / Signature-Input headers present (Web Bot Auth)',
        keyId ? `Agent key identifier: ${keyId}` : 'Agent key identifier not published',
      ],
    };
  }

  const datacenterNetwork = DATACENTER_NETWORK_PATTERN.test(networkHaystack);  const automationRuntimeDetected = Boolean(client.webdriver || client.cdpDetected);
  if (automationRuntimeDetected && datacenterNetwork) {
    return {
      subtype: 'ai_agent',
      label: 'Cloud Browser Agent',
      provider: 'Cloud Browser Agent',
      category: 'Autonomous Agent',
      confidence: 0.78,
      reasons: [
        client.webdriver ? 'WebDriver runtime binding present' : 'CDP runtime binding present',
        `Datacenter ASN hosting the agent (${networkHaystack})`,
      ],
    };
  }

  const isDesktopChromeOrSafari =
    /chrome\/|crios\/|safari\//i.test(ua) && !/mobile|android|iphone|ipad/i.test(ua);
  const missingFetchMetadata = !secFetchSite && !secFetchMode && !secFetchDest;
  // Only a UA that claims a real desktop browser but supplies neither a language nor any
  // fetch metadata is treated as automation. Requiring both keep older Safari builds (which
  // predate Sec-Fetch support) and language-stripping privacy setups out of the bot verdict.
  const headerAnomaly = isDesktopChromeOrSafari && missingFetchMetadata && !acceptLanguage;

  if (
    client.isBot ||
    client.webdriver ||
    client.cdpDetected ||
    AUTOMATION_UA_PATTERN.test(ua) ||
    headerAnomaly
  ) {
    const reasons: string[] = [];
    if (client.isBot) reasons.push('Client reported an automated runtime');
    if (client.webdriver) reasons.push('WebDriver handshake detected');
    if (client.cdpDetected) reasons.push('Chrome DevTools Protocol binding detected');
    if (AUTOMATION_UA_PATTERN.test(ua)) reasons.push('Automation framework signature in user-agent');
    if (headerAnomaly) {
      reasons.push('Desktop browser user-agent without accept-language or sec-fetch metadata');
    }
    for (const signal of clientSignals.slice(0, 2)) reasons.push(signal);
    return {
      subtype: 'bad_bot',
      label: AUTOMATION_UA_PATTERN.test(ua) ? 'Automation Runtime' : 'Automation / Header Anomaly',
      provider: 'Unattributed Automation',
      category: 'Automation',
      confidence: client.isBot || automationRuntimeDetected ? 0.93 : 0.7,
      reasons: reasons.length > 0 ? reasons : ['Automated traffic signature detected'],
    };
  }

  return {
    subtype: 'human',
    label: 'Verified Human',
    provider: 'None',
    category: 'Human Interaction',
    confidence: 0.6,
    reasons: ['Interactive browser profile without automation signatures'],
  };
}

/* -------------------------------------------------------------------------- */
/* Phase 1b — AI agent attribution                                             */
/*   official CIDR sync (OpenAI / Google JSON) + RFC 9421 Web Bot Auth + FCrDNS */
/* -------------------------------------------------------------------------- */

type AiBotCidrSourceId =
  | 'chatgpt-user'
  | 'gptbot'
  | 'searchbot'
  | 'google-common'
  | 'google-user-triggered'
  | 'google-user-triggered-google';

interface AiBotCidrSource {
  id: AiBotCidrSourceId;
  url: string;
}

const AI_BOT_CIDR_SOURCES: AiBotCidrSource[] = [
  { id: 'chatgpt-user', url: 'https://openai.com/chatgpt-user.json' },
  { id: 'gptbot', url: 'https://openai.com/gptbot.json' },
  { id: 'searchbot', url: 'https://openai.com/searchbot.json' },
  {
    id: 'google-common',
    url: 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
  },
  {
    id: 'google-user-triggered',
    url: 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json',
  },
  {
    id: 'google-user-triggered-google',
    url: 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json',
  },
];

const AI_BOT_CIDR_SYNC_INTERVAL_MS = 6 * 60 * 60 * 1000;
const AI_BOT_CIDR_TIMEOUT_MS = 10000;
const AI_AUTH_DIRECTORY_TIMEOUT_MS = 1500;
const AI_AUTH_DIRECTORY_TTL_MS = 60 * 60 * 1000;
const AI_FORWARD_DNS_TIMEOUT_MS = 1200;
const AI_FORWARD_DNS_TTL_MS = 60 * 60 * 1000;
const AI_VERDICT_TABLE_MAX_ENTRIES = 10000;

let aiBotPrefixTable = new Map<string, string[]>();
let aiBotCidrLastSyncMs = 0;
let aiBotCidrSyncInFlight: Promise<void> | null = null;
let aiBotCidrTimer: ReturnType<typeof setInterval> | null = null;

const aiAuthDirectoryCache = new Map<
  string,
  { clientName: string; trigger: string | null; expiresAtMs: number }
>();
const aiForwardConfirmedDnsCache = new Map<string, { names: string[]; expiresAtMs: number }>();

/** Extracts every `ipv4Prefix` / `ipv6Prefix` / `prefix` from a Google/OpenAI JSON payload. */
function extractAiPrefixes(payload: unknown): string[] {
  const prefixes: string[] = [];
  const visit = (value: unknown, depth: number): void => {
    if (depth > 4 || value === null || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    const record = value as Record<string, unknown>;
    for (const key of ['ipv4Prefix', 'ipv6Prefix', 'prefix']) {
      const raw = record[key];
      if (typeof raw === 'string' && raw.includes('/')) prefixes.push(raw.trim());
    }
    for (const nested of Object.values(record)) {
      if (nested && typeof nested === 'object') visit(nested, depth + 1);
    }
  };
  visit(payload, 0);
  return Array.from(new Set(prefixes));
}

async function syncAiBotCidrs(): Promise<void> {
  const next = new Map<string, string[]>();
  await Promise.all(
    AI_BOT_CIDR_SOURCES.map(async (source) => {
      const body = await fetchTextWithTimeout(
        source.url,
        AI_BOT_CIDR_TIMEOUT_MS,
        'application/json'
      );
      if (!body) return;
      try {
        const prefixes = extractAiPrefixes(JSON.parse(body) as unknown);
        if (prefixes.length > 0) next.set(source.id, prefixes);
      } catch {
        // Malformed payload: this provider keeps its previous prefix list.
      }
    })
  );
  if (next.size === 0) return;
  // Merge so a provider that fails one refresh keeps its previously verified ranges.
  const merged = new Map(aiBotPrefixTable);
  for (const [id, prefixes] of next) merged.set(id, prefixes);
  aiBotPrefixTable = merged;
  aiBotCidrLastSyncMs = Date.now();
}

function runAiBotCidrSync(): Promise<void> {
  if (aiBotCidrSyncInFlight) return aiBotCidrSyncInFlight;
  aiBotCidrSyncInFlight = syncAiBotCidrs()
    .catch(() => undefined)
    .finally(() => {
      aiBotCidrSyncInFlight = null;
    });
  return aiBotCidrSyncInFlight;
}

function ensureAiBotCidrSync(): void {
  if (aiBotCidrTimer === null) {
    void runAiBotCidrSync();
    aiBotCidrTimer = setInterval(() => {
      void runAiBotCidrSync();
    }, AI_BOT_CIDR_SYNC_INTERVAL_MS);
    const handle = aiBotCidrTimer as unknown as { unref?: () => void };
    if (typeof handle.unref === 'function') handle.unref();
    return;
  }
  if (Date.now() - aiBotCidrLastSyncMs >= AI_BOT_CIDR_SYNC_INTERVAL_MS) {
    void runAiBotCidrSync();
  }
}

// Workers reject global-scope timers; requests lazily re-arm the daemon there.
try {
  ensureAiBotCidrSync();
} catch {
  // Started on the first request instead.
}

function matchesAiPrefixTable(ip: string, ids: AiBotCidrSourceId[]): boolean {
  return ids.some((id) => ipMatchesCidrList(ip, aiBotPrefixTable.get(id) ?? []));
}

type AiAgentOperatorId =
  | 'google'
  | 'openai'
  | 'perplexity'
  | 'anthropic'
  | 'xai'
  | 'meta'
  | 'browserbase'
  | 'anchorbrowser';

interface WebBotAuthInfo {
  /** Both `Signature` and `Signature-Input` are present → cryptographically signed agent. */
  present: boolean;
  label: string;
  keyId: string;
  tag: string;
  agentUrl: string | null;
  agentHost: string;
  operator: AiAgentOperatorId | null;
}

function firstHttpsUrl(text: string): string | null {
  const match = /https?:\/\/[^\s",;)]+/i.exec(text);
  return match ? match[0].replace(/[.;]+$/, '') : null;
}

function resolveSignatureAgentOperator(host: string, label: string): AiAgentOperatorId | null {
  const lowerHost = host.toLowerCase();
  const lowerLabel = label.toLowerCase();
  if (
    lowerHost === 'agent.bot.goog' ||
    lowerHost.endsWith('.bot.goog') ||
    lowerHost.endsWith('bot.goog') ||
    lowerLabel === 'g'
  ) {
    return 'google';
  }
  if (lowerHost.endsWith('openai.com') || lowerHost.endsWith('chatgpt.com')) return 'openai';
  if (lowerHost.endsWith('perplexity.ai')) return 'perplexity';
  if (lowerHost.endsWith('anthropic.com') || lowerHost.endsWith('claude.ai')) return 'anthropic';
  if (lowerHost.endsWith('browserbase.com')) return 'browserbase';
  if (lowerHost.endsWith('anchorbrowser.io')) return 'anchorbrowser';
  if (lowerHost.endsWith('x.ai') || lowerHost.endsWith('grok.com')) return 'xai';
  if (lowerHost.endsWith('meta.com') || lowerHost.endsWith('facebook.com')) return 'meta';
  return null;
}

/**
 * Parses the RFC 9421 Web Bot Auth headers. Labelled signatures (`g=("@authority" ...)`) and a
 * `Signature-Agent` URI both identify the operator; the `keyid` names the exact key.
 */
export function parseWebBotAuthHeaders(headers: RawHeaderBag | null | undefined): WebBotAuthInfo {
  const signatureInput = readRequestHeader(headers, 'signature-input');
  const signature = readRequestHeader(headers, 'signature');
  const signatureAgent = readRequestHeader(headers, 'signature-agent');
  const labelMatch = /^\s*([A-Za-z0-9_-]+)\s*=/.exec(signatureInput);
  const keyIdMatch = /keyid\s*=\s*"([^"]+)"/i.exec(signatureInput);
  const tagMatch = /tag\s*=\s*"([^"]+)"/i.exec(signatureInput);
  const agentUrl = signatureAgent ? firstHttpsUrl(signatureAgent) : null;
  let agentHost = '';
  if (agentUrl) {
    try {
      agentHost = new URL(agentUrl).hostname.toLowerCase();
    } catch {
      agentHost = '';
    }
  }
  const label = labelMatch ? labelMatch[1] : '';
  return {
    present: Boolean(signatureInput && signature),
    label,
    keyId: keyIdMatch ? keyIdMatch[1].trim().slice(0, 160) : '',
    tag: tagMatch ? tagMatch[1].trim().slice(0, 80) : '',
    agentUrl,
    agentHost,
    operator: resolveSignatureAgentOperator(agentHost, label),
  };
}

/** Best-effort client-name / trigger lookup from the agent's signature directory (1 h cache). */
async function fetchWebBotAuthDirectory(
  agentUrl: string
): Promise<{ clientName: string; trigger: string | null } | null> {
  let origin = '';
  try {
    origin = new URL(agentUrl).origin;
  } catch {
    return null;
  }
  const nowMs = Date.now();
  const cached = aiAuthDirectoryCache.get(origin);
  if (cached && cached.expiresAtMs > nowMs) {
    return { clientName: cached.clientName, trigger: cached.trigger };
  }

  const body = await fetchTextWithTimeout(
    `${origin}/.well-known/http-message-signatures-directory`,
    AI_AUTH_DIRECTORY_TIMEOUT_MS,
    'application/json'
  );
  if (!body) return null;

  let clientName = '';
  let trigger: string | null = null;
  const visit = (value: unknown, depth: number): void => {
    if (depth > 4 || value === null || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    const record = value as Record<string, unknown>;
    if (!clientName) {
      const name = record.client_name ?? record.clientName;
      if (typeof name === 'string' && name.trim()) clientName = name.trim().slice(0, 120);
    }
    if (trigger === null) {
      const rawTrigger = record.trigger;
      if (typeof rawTrigger === 'string' && /fetcher|crawler/i.test(rawTrigger)) {
        trigger = /fetcher/i.test(rawTrigger) ? 'fetcher' : 'crawler';
      }
    }
    for (const nested of Object.values(record)) {
      if (nested && typeof nested === 'object') visit(nested, depth + 1);
    }
  };
  try {
    visit(JSON.parse(body) as unknown, 0);
  } catch {
    return null;
  }
  if (!clientName && trigger === null) return null;

  if (aiAuthDirectoryCache.size > 500) aiAuthDirectoryCache.clear();
  aiAuthDirectoryCache.set(origin, {
    clientName,
    trigger,
    expiresAtMs: nowMs + AI_AUTH_DIRECTORY_TTL_MS,
  });
  return { clientName, trigger };
}

/** Forward-confirmed reverse DNS for the visitor IP. Cached for one hour. */
async function resolveForwardConfirmedReverseDns(ip: string): Promise<string[]> {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return [];
  const nowMs = Date.now();
  const cached = aiForwardConfirmedDnsCache.get(normalized);
  if (cached && cached.expiresAtMs > nowMs) return cached.names;

  const reverseNames = await resolveTorReverseDns(normalized);
  const isV4 = isIpv4Literal(normalized);
  const confirmed: string[] = [];

  const forwardLookup = async (name: string): Promise<string[]> => {
    if (!/^[a-z0-9.-]+$/i.test(name)) return [];
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    try {
      const lookup = (isV4 ? dns.resolve4(name) : dns.resolve6(name)).catch(
        () => [] as string[]
      );
      const timeout = new Promise<string[]>((resolve) => {
        timeoutHandle = setTimeout(() => resolve([]), AI_FORWARD_DNS_TIMEOUT_MS);
      });
      const addresses = await Promise.race([lookup, timeout]);
      return Array.isArray(addresses) ? addresses : [];
    } catch {
      return [];
    } finally {
      if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
    }
  };

  for (const name of reverseNames.slice(0, 3)) {
    const addresses = await forwardLookup(name);
    if (addresses.some((address) => normalizeIpAddress(address) === normalized)) {
      confirmed.push(name);
    }
  }

  if (aiForwardConfirmedDnsCache.size > AI_VERDICT_TABLE_MAX_ENTRIES) {
    aiForwardConfirmedDnsCache.clear();
  }
  aiForwardConfirmedDnsCache.set(normalized, {
    names: confirmed,
    expiresAtMs: nowMs + AI_FORWARD_DNS_TTL_MS,
  });
  return confirmed;
}

/** True when any FCrDNS hostname ends with one of the operator-owned suffixes. */
function hostMatchesSuffix(names: readonly string[], suffixes: readonly string[]): boolean {
  return names.some((name) => {
    const lower = name.toLowerCase().replace(/\.$/, '');
    return suffixes.some((suffix) => lower === suffix || lower.endsWith(`.${suffix}`));
  });
}

function asnDigits(asn: string | undefined): string {
  if (typeof asn !== 'string') return '';
  const match = /(\d{1,10})/.exec(asn);
  return match ? match[1] : '';
}

function asnIn(asn: string | undefined, digits: readonly string[]): boolean {
  const value = asnDigits(asn);
  return value.length > 0 && digits.includes(value);
}

const GOOGLE_VERIFICATION_SUFFIXES = ['googlebot.com', 'google.com'];
const OPENAI_VERIFICATION_SUFFIXES = ['openai.com', 'chatgpt.com'];
const PERPLEXITY_VERIFICATION_SUFFIXES = ['perplexity.ai'];
const ANTHROPIC_VERIFICATION_SUFFIXES = ['anthropic.com', 'claude.ai'];
const XAI_VERIFICATION_SUFFIXES = ['x.ai', 'grok.com'];
const META_VERIFICATION_SUFFIXES = ['facebook.com', 'meta.com', 'fb.com'];

const GCP_ASNS = ['15169', '396982'];
const XAI_ASNS = ['400562', '13414'];
const META_ASNS = ['32934', '63293'];
const AWS_ASNS = ['16509', '14618'];
const AZURE_ASNS = ['8075'];
const PERPLEXITY_ASNS = ['209242'];

interface AiAgentResolverClient {
  isBot?: boolean;
  isHeadless?: boolean;
  webdriver?: boolean;
  cdpDetected?: boolean;
  isVirtualMachine?: boolean;
  gpuVendor?: string;
  gpuRenderer?: string;
  idbDurabilityRatio?: number | null;
  screenResolution?: string;
  platform?: string;
  botSignals?: string[];
}

interface AiAgentResolverInput {
  headers: RawHeaderBag | null | undefined;
  userAgent: string;
  network: { isp?: string; org?: string; asn?: string };
  publicIp: string;
  client: AiAgentResolverClient;
}

const NO_AI_AGENT: AiAgentAttribution = {
  detected: false,
  agentId: null,
  agentName: '',
  operator: '',
  executionMode: null,
  verified: false,
  confidence: 'Medium',
  riskScore: 0,
  evidence: [],
};

function aiAgentResult(
  partial: Omit<AiAgentAttribution, 'detected' | 'riskScore'> &
    Partial<Pick<AiAgentAttribution, 'riskScore'>>
): AiAgentAttribution {
  return {
    detected: true,
    riskScore: partial.riskScore ?? (partial.agentId === 'impostor-spoof' ? 10 : 8),
    ...partial,
  };
}

/**
 * Attributable identity of an autonomous agent. Verification only ever comes from first-party
 * evidence: RFC 9421 Web Bot Auth, an official CIDR range synced from the vendor's own JSON, or
 * forward-confirmed reverse DNS. A User-Agent string on its own is a claim, never proof, so a
 * failed claim is reported as a spoofed impostor.
 */
export async function resolveAiAgentIdentity(input: AiAgentResolverInput): Promise<AiAgentAttribution> {
  const ua = input.userAgent || readRequestHeader(input.headers, 'user-agent');
  if (!ua) return NO_AI_AGENT;

  const webBotAuth = parseWebBotAuthHeaders(input.headers);
  const referer = `${readRequestHeader(input.headers, 'referer')} ${readRequestHeader(
    input.headers,
    'origin'
  )}`;
  const networkHaystack = [input.network.org, input.network.isp, input.network.asn]
    .filter((part): part is string => typeof part === 'string' && part.trim().length > 0)
    .join(' · ');

  let confirmedNamesPromise: Promise<string[]> | null = null;
  const confirmedNames = (): Promise<string[]> => {
    if (confirmedNamesPromise === null) {
      confirmedNamesPromise = resolveForwardConfirmedReverseDns(input.publicIp);
    }
    return confirmedNamesPromise;
  };

  const gpuRenderer = (input.client.gpuRenderer || '').toLowerCase();
  const maskedGpu =
    !gpuRenderer ||
    gpuRenderer === 'unavailable' ||
    /swiftshader|llvmpipe|mesa|software|generic|^standard/.test(gpuRenderer);
  const idbRatio =
    typeof input.client.idbDurabilityRatio === 'number' ? input.client.idbDurabilityRatio : null;
  const clientAutomation = Boolean(
    input.client.isBot ||
      input.client.webdriver ||
      input.client.cdpDetected ||
      input.client.isHeadless
  );
  const desktopChrome =
    /chrome\//i.test(ua) && !/mobile|android|iphone|ipad/i.test(ua);
  const screen = (input.client.screenResolution || '').toLowerCase();
  const claudeComputerUseViewport =
    screen.includes('1024x768') || screen.includes('1280x800') || screen.includes('1280×800');
  const silentCloudTelemetry = Boolean(
    input.client.isVirtualMachine ||
      (idbRatio !== null && idbRatio > 0.95 && maskedGpu) ||
      (desktopChrome && clientAutomation && maskedGpu)
  );

  const signatureEvidence = webBotAuth.present
    ? [
        'RFC 9421 Signature / Signature-Input headers present (Web Bot Auth)',
        webBotAuth.label ? `Signature label: ${webBotAuth.label}` : '',
        webBotAuth.agentUrl ? `Signature-Agent: ${webBotAuth.agentUrl}` : '',
        webBotAuth.keyId ? `keyid: ${webBotAuth.keyId}` : '',
      ].filter(Boolean)
    : [];

  const directoryHint = webBotAuth.agentUrl
    ? await fetchWebBotAuthDirectory(webBotAuth.agentUrl)
    : null;
  const directoryEvidence = directoryHint
    ? [
        directoryHint.clientName ? `Agent directory client_name: ${directoryHint.clientName}` : '',
        directoryHint.trigger ? `Agent trigger: ${directoryHint.trigger}` : '',
      ].filter(Boolean)
    : [];

  /* --------------- Rule A (prelude) — Googlebot verification ---------------- */
  // Googlebot is a search crawler, not an LLM agent, but a spoofed claim must still be caught.
  // Only flag a spoof when at least one authoritative source actually answered.
  if (/\bgooglebot\b/i.test(ua)) {
    const googleCidr = matchesAiPrefixTable(input.publicIp, [
      'google-common',
      'google-user-triggered',
      'google-user-triggered-google',
    ]);
    const googleDnsNames = await confirmedNames();
    const googleDns = hostMatchesSuffix(googleDnsNames, GOOGLE_VERIFICATION_SUFFIXES);
    const googleRangesLoaded = (aiBotPrefixTable.get('google-common')?.length ?? 0) > 0;
    if (googleCidr || googleDns) {
      return aiAgentResult({
        agentId: 'gemini',
        agentName: 'Googlebot (Verified Google Crawler)',
        operator: 'Google LLC',
        executionMode: 'Autonomous Crawler',
        verified: true,
        confidence: 'Verified',
        evidence: [
          `Googlebot user-agent: ${ua.slice(0, 120)}`,
          googleCidr ? 'Source IP matched a Google official crawler CIDR range' : '',
          googleDns ? 'FCrDNS matched *.googlebot.com / *.google.com' : '',
        ].filter(Boolean),
      });
    }
    if (googleRangesLoaded || googleDnsNames.length > 0) {
      return aiAgentResult({
        agentId: 'impostor-spoof',
        agentName: 'Spoofed Google Bot Impostor (Unverified IP)',
        operator: 'Unverified Google claim',
        executionMode: 'Spoofed Impostor',
        verified: false,
        confidence: 'Verified',
        evidence: [
          `Googlebot user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not inside Google's official crawler ranges`,
          'Forward-confirmed reverse DNS does not resolve to googlebot.com / google.com',
        ],
      });
    }
    return NO_AI_AGENT;
  }

  /* ---------------------------- Rule A — Gemini ---------------------------- */
  const geminiUa =
    /Gemini-Deep-Research|GoogleAgent-Mariner|Google-NotebookLM|Google-CloudVertexBot|Google-Extended|GoogleOther(-Image|-Video)?|Google-InspectionTool/i.test(
      ua
    );
  if (webBotAuth.operator === 'google' || geminiUa) {
    const googleCidr = matchesAiPrefixTable(input.publicIp, [
      'google-common',
      'google-user-triggered',
      'google-user-triggered-google',
    ]);
    const googleDnsNames = await confirmedNames();
    const googleDns = hostMatchesSuffix(googleDnsNames, GOOGLE_VERIFICATION_SUFFIXES);
    const googleRangesLoaded = (aiBotPrefixTable.get('google-common')?.length ?? 0) > 0;
    const verified = webBotAuth.operator === 'google' || googleCidr || googleDns;
    if (geminiUa && !verified && (googleRangesLoaded || googleDnsNames.length > 0)) {
      return aiAgentResult({
        agentId: 'impostor-spoof',
        agentName: 'Spoofed Google Gemini Agent (Unverified IP)',
        operator: 'Unverified Google claim',
        executionMode: 'Spoofed Impostor',
        verified: false,
        confidence: 'Verified',
        evidence: [
          `Gemini / Google agent user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not inside Google's official crawler ranges`,
          'Forward-confirmed reverse DNS does not resolve to googlebot.com / google.com',
        ],
      });
    }
    return aiAgentResult({
      agentId: 'gemini',
      agentName:
        directoryHint?.clientName ||
        (verified
          ? 'Google Gemini (Mariner / Deep Research)'
          : 'Google Gemini / Cloud Agent (GCP VM)'),
      operator: 'Google LLC',
      executionMode: webBotAuth.operator === 'google'
        ? 'RFC 9421 Signed Agent'
        : geminiUa && !clientAutomation
        ? 'User-Triggered Fetcher'
        : 'Autonomous Crawler',
      verified,
      confidence: verified
        ? 'Verified'
        : googleRangesLoaded || googleDnsNames.length > 0
        ? 'High'
        : 'Medium',
      evidence: [
        ...(webBotAuth.operator === 'google' ? signatureEvidence : []),
        ...(geminiUa ? [`Google AI agent user-agent: ${ua.slice(0, 120)}`] : []),
        ...(googleCidr ? ['Source IP matched a Google official crawler CIDR range'] : []),
        ...(googleDns ? ['FCrDNS matched *.googlebot.com / *.google.com'] : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from headers'] : []),
        ...directoryEvidence,
      ],
    });
  }
  if (
    (asnIn(input.network.asn, GCP_ASNS) ||
      hostMatchesSuffix(await confirmedNames(), ['googleusercontent.com'])) &&
    (webBotAuth.present || silentCloudTelemetry)
  ) {
    return aiAgentResult({
      agentId: 'gemini',
      agentName: 'Google Gemini / Cloud Agent (GCP VM)',
      operator: 'Google LLC',
      executionMode: webBotAuth.present ? 'RFC 9421 Signed Agent' : 'Silent Cloud VM Browser',
      verified: webBotAuth.present,
      confidence: webBotAuth.present ? 'Verified' : 'High',
      evidence: [
        ...signatureEvidence,
        ...(asnIn(input.network.asn, GCP_ASNS)
          ? [`Google Cloud ASN (${input.network.asn}) hosting the browser`]
          : ['Reverse DNS matched *.googleusercontent.com']),
        ...(silentCloudTelemetry
          ? ['Cloud-VM browser telemetry (masked WebGL / ephemeral storage)']
          : []),
      ],
    });
  }

  /* ------------------------------ Rule B — Grok ----------------------------- */
  const grokUa = /GrokBot|xAI-GrokBot|Grok-Search|xAI-Bot|\bGrok\b/i.test(ua);
  const grokReferer = /grok\.com|x\.ai/i.test(referer);
  if (webBotAuth.operator === 'xai' || grokUa || grokReferer) {
    const xaiDnsNames = await confirmedNames();
    const xaiDns = hostMatchesSuffix(xaiDnsNames, XAI_VERIFICATION_SUFFIXES);
    const xaiAsn = asnIn(input.network.asn, XAI_ASNS);
    const verified = webBotAuth.operator === 'xai' || xaiDns || xaiAsn;
    if (grokUa && !verified && !grokReferer && xaiDnsNames.length > 0) {
      return aiAgentResult({
        agentId: 'impostor-spoof',
        agentName: 'Spoofed xAI Grok Bot (Unverified IP)',
        operator: 'Unverified xAI claim',
        executionMode: 'Spoofed Impostor',
        verified: false,
        confidence: 'Verified',
        evidence: [
          `Grok user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not on xAI infrastructure`,
        ],
      });
    }
    return aiAgentResult({
      agentId: 'grok',
      agentName: directoryHint?.clientName || 'xAI Grok Bot',
      operator: 'xAI',
      executionMode: webBotAuth.operator === 'xai'
        ? 'RFC 9421 Signed Agent'
        : grokReferer && !grokUa
        ? 'Silent Cloud VM Browser'
        : 'Autonomous Crawler',
      verified,
      confidence: verified ? 'Verified' : xaiDnsNames.length > 0 ? 'High' : 'Medium',
      evidence: [
        ...(webBotAuth.operator === 'xai' ? signatureEvidence : []),
        ...(grokUa ? [`Grok user-agent: ${ua.slice(0, 120)}`] : []),
        ...(grokReferer ? [`Referer / Origin points at grok.com or x.ai`] : []),
        ...(xaiAsn ? [`xAI / X Corp ASN ${input.network.asn}`] : []),
        ...(xaiDns ? ['FCrDNS matched *.x.ai / *.grok.com'] : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from headers'] : []),
        ...directoryEvidence,
      ],
    });
  }

  /* ------------------------------ Rule C — Muse ----------------------------- */
  const museUa = /\bMuseBot\b|\bMuse\b|Meta-ExternalAgent|Meta-ExternalFetcher|FacebookBot/i.test(ua);
  if (webBotAuth.operator === 'meta' || museUa) {
    const metaDnsNames = await confirmedNames();
    const metaDns = hostMatchesSuffix(metaDnsNames, META_VERIFICATION_SUFFIXES);
    const metaAsn = asnIn(input.network.asn, META_ASNS);
    const verified = webBotAuth.operator === 'meta' || metaDns || metaAsn;
    if (museUa && !verified && metaDnsNames.length > 0) {
      return aiAgentResult({
        agentId: 'impostor-spoof',
        agentName: 'Spoofed Meta Muse Agent (Unverified IP)',
        operator: 'Unverified Meta claim',
        executionMode: 'Spoofed Impostor',
        verified: false,
        confidence: 'Verified',
        evidence: [
          `Meta agent user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not on Meta infrastructure`,
        ],
      });
    }
    return aiAgentResult({
      agentId: 'muse',
      agentName: directoryHint?.clientName || 'Meta Muse',
      operator: 'Meta Platforms',
      executionMode: webBotAuth.operator === 'meta' ? 'RFC 9421 Signed Agent' : 'Autonomous Crawler',
      verified,
      confidence: verified ? 'Verified' : metaDnsNames.length > 0 ? 'High' : 'Medium',
      evidence: [
        ...(webBotAuth.operator === 'meta' ? signatureEvidence : []),
        ...(museUa ? [`Meta / Muse user-agent: ${ua.slice(0, 120)}`] : []),
        ...(metaAsn ? [`Meta Platforms ASN ${input.network.asn}`] : []),
        ...(metaDns ? ['FCrDNS matched *.facebook.com / *.meta.com'] : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from headers'] : []),
        ...directoryEvidence,
      ],
    });
  }
  if (asnIn(input.network.asn, META_ASNS) && desktopChrome && silentCloudTelemetry) {
    return aiAgentResult({
      agentId: 'muse',
      agentName: 'Meta Muse (Cloud VM Browser Agent)',
      operator: 'Meta Platforms',
      executionMode: 'Silent Cloud VM Browser',
      verified: false,
      confidence: 'High',
      evidence: [
        `Meta Platforms ASN (${input.network.asn}) hosting a desktop Chrome session`,
        'Virtual machine / cloud browser telemetry (masked WebGL, Linux platform or ephemeral storage)',
      ],
    });
  }

  /* --------------------------- Rule D — Perplexity -------------------------- */
  const perplexityUa = /PerplexityBot|Perplexity-User/i.test(ua);
  if (webBotAuth.operator === 'perplexity' || perplexityUa) {
    const perplexityDnsNames = await confirmedNames();
    const perplexityDns = hostMatchesSuffix(
      perplexityDnsNames,
      PERPLEXITY_VERIFICATION_SUFFIXES
    );
    const perplexityAsn = asnIn(input.network.asn, PERPLEXITY_ASNS);
    const verified = webBotAuth.operator === 'perplexity' || perplexityDns || perplexityAsn;
    if (perplexityUa && !verified && perplexityDnsNames.length > 0) {
      return aiAgentResult({
        agentId: 'impostor-spoof',
        agentName: 'Spoofed Perplexity Agent (Unverified IP)',
        operator: 'Unverified Perplexity claim',
        executionMode: 'Spoofed Impostor',
        verified: false,
        confidence: 'Verified',
        evidence: [
          `Perplexity user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not on Perplexity infrastructure`,
        ],
      });
    }
    return aiAgentResult({
      agentId: 'perplexity',
      agentName: directoryHint?.clientName || 'Perplexity AI Agent',
      operator: 'Perplexity AI',
      executionMode: webBotAuth.operator === 'perplexity'
        ? 'RFC 9421 Signed Agent'
        : 'Autonomous Crawler',
      verified,
      confidence: verified ? 'Verified' : perplexityDnsNames.length > 0 ? 'High' : 'Medium',
      evidence: [
        ...(webBotAuth.operator === 'perplexity' ? signatureEvidence : []),
        ...(perplexityUa ? [`Perplexity user-agent: ${ua.slice(0, 120)}`] : []),
        ...(perplexityAsn ? [`Perplexity ASN ${input.network.asn}`] : []),
        ...(perplexityDns ? ['FCrDNS matched *.perplexity.ai'] : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from headers'] : []),
        ...directoryEvidence,
      ],
    });
  }
  if (
    asnIn(input.network.asn, AWS_ASNS) &&
    clientAutomation &&
    (webBotAuth.present ||
      hostMatchesSuffix(await confirmedNames(), PERPLEXITY_VERIFICATION_SUFFIXES))
  ) {
    return aiAgentResult({
      agentId: 'perplexity',
      agentName: 'Perplexity AI (PerplexityBot / Stealth Agent)',
      operator: 'Perplexity AI',
      executionMode: webBotAuth.present ? 'RFC 9421 Signed Agent' : 'Silent Cloud VM Browser',
      verified: webBotAuth.present,
      confidence: webBotAuth.present ? 'Verified' : 'Medium',
      evidence: [
        ...signatureEvidence,
        `AWS ASN (${input.network.asn}) hosting a headless Chromium session`,
        'RFC 9421 headers or Perplexity network attribution',
      ],
    });
  }

  /* ----------------------------- Rule E — OpenAI ---------------------------- */
  const openAiUa = /ChatGPT-User|OAI-SearchBot|GPTBot/i.test(ua);
  if (webBotAuth.operator === 'openai' || openAiUa) {
    const openAiDnsNames = await confirmedNames();
    const openAiDns = hostMatchesSuffix(openAiDnsNames, OPENAI_VERIFICATION_SUFFIXES);
    const openAiCidr = matchesAiPrefixTable(input.publicIp, ['chatgpt-user', 'gptbot', 'searchbot']);
    const openAiRangesLoaded =
      (aiBotPrefixTable.get('chatgpt-user')?.length ?? 0) > 0 ||
      (aiBotPrefixTable.get('gptbot')?.length ?? 0) > 0;
    const verified = webBotAuth.operator === 'openai' || openAiDns || openAiCidr;
    if (openAiUa && !verified && (openAiRangesLoaded || openAiDnsNames.length > 0)) {
      return aiAgentResult({
        agentId: 'impostor-spoof',
        agentName: 'Spoofed OpenAI Agent (Unverified IP)',
        operator: 'Unverified OpenAI claim',
        executionMode: 'Spoofed Impostor',
        verified: false,
        confidence: 'Verified',
        evidence: [
          `OpenAI user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not inside chatgpt-user.json / gptbot.json / searchbot.json`,
          'Forward-confirmed reverse DNS does not resolve to openai.com / chatgpt.com',
        ],
      });
    }
    return aiAgentResult({
      agentId: 'openai',
      agentName: directoryHint?.clientName || 'OpenAI ChatGPT Agent / Operator',
      operator: 'OpenAI',
      executionMode: webBotAuth.operator === 'openai'
        ? 'RFC 9421 Signed Agent'
        : /chatgpt-user/i.test(ua)
        ? 'User-Triggered Fetcher'
        : 'Autonomous Crawler',
      verified,
      confidence: verified
        ? 'Verified'
        : openAiRangesLoaded || openAiDnsNames.length > 0
        ? 'High'
        : 'Medium',
      evidence: [
        ...(webBotAuth.operator === 'openai' ? signatureEvidence : []),
        ...(openAiUa ? [`OpenAI user-agent: ${ua.slice(0, 120)}`] : []),
        ...(openAiCidr ? ['Source IP matched an official OpenAI JSON prefix list'] : []),
        ...(openAiDns ? ['FCrDNS matched *.openai.com / *.chatgpt.com'] : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from headers'] : []),
        ...directoryEvidence,
      ],
    });
  }
  if (asnIn(input.network.asn, AZURE_ASNS) && webBotAuth.present) {
    return aiAgentResult({
      agentId: 'openai',
      agentName: 'OpenAI ChatGPT Agent / Operator',
      operator: 'OpenAI',
      executionMode: 'RFC 9421 Signed Agent',
      verified: true,
      confidence: 'Verified',
      evidence: [
        ...signatureEvidence,
        `Microsoft Azure ASN (${input.network.asn}) hosting the signed agent`,
      ],
    });
  }

  /* ----------------------------- Rule F — Claude ---------------------------- */
  const claudeUa = /Claude-User|Claude-SearchBot|ClaudeBot|anthropic-ai/i.test(ua);
  if (webBotAuth.operator === 'anthropic' || claudeUa) {
    const anthropicDnsNames = await confirmedNames();
    const anthropicDns = hostMatchesSuffix(anthropicDnsNames, ANTHROPIC_VERIFICATION_SUFFIXES);
    const verified = webBotAuth.operator === 'anthropic' || anthropicDns;
    if (claudeUa && !verified && anthropicDnsNames.length > 0) {
      return aiAgentResult({
        agentId: 'impostor-spoof',
        agentName: 'Spoofed Anthropic Claude Agent (Unverified IP)',
        operator: 'Unverified Anthropic claim',
        executionMode: 'Spoofed Impostor',
        verified: false,
        confidence: 'Verified',
        evidence: [
          `Claude user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not on Anthropic infrastructure`,
        ],
      });
    }
    return aiAgentResult({
      agentId: 'claude',
      agentName: directoryHint?.clientName || 'Anthropic Claude (Claude-User / Computer Use)',
      operator: 'Anthropic',
      executionMode: webBotAuth.operator === 'anthropic'
        ? 'RFC 9421 Signed Agent'
        : /claude-user/i.test(ua)
        ? 'User-Triggered Fetcher'
        : 'Autonomous Crawler',
      verified,
      confidence: verified ? 'Verified' : anthropicDnsNames.length > 0 ? 'High' : 'Medium',
      evidence: [
        ...(webBotAuth.operator === 'anthropic' ? signatureEvidence : []),
        ...(claudeUa ? [`Claude user-agent: ${ua.slice(0, 120)}`] : []),
        ...(anthropicDns ? ['FCrDNS matched *.anthropic.com / *.claude.ai'] : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from headers'] : []),
        ...directoryEvidence,
      ],
    });
  }
  if (
    (asnIn(input.network.asn, AWS_ASNS) || asnIn(input.network.asn, GCP_ASNS)) &&
    claudeComputerUseViewport &&
    /llvmpipe|mesa|swiftshader|software/i.test(gpuRenderer) &&
    clientAutomation
  ) {
    return aiAgentResult({
      agentId: 'claude',
      agentName: 'Anthropic Claude (Claude-User / Computer Use)',
      operator: 'Anthropic',
      executionMode: 'Silent Cloud VM Browser',
      verified: false,
      confidence: 'Medium',
      evidence: [
        `Cloud ASN (${input.network.asn}) hosting a Linux X11 / Xvfb framebuffer`,
        `Viewport ${input.client.screenResolution} matches a Claude computer-use desktop`,
        'Software WebGL renderer (llvmpipe / Mesa) with an automated session',
      ],
    });
  }

  /* -------------------- Rule G — signed cloud browser ---------------------- */
  const cloudBrowserOperator =
    webBotAuth.operator === 'browserbase'
      ? { name: 'Browserbase Cloud Agent', operator: 'Browserbase' }
      : webBotAuth.operator === 'anchorbrowser'
      ? { name: 'Anchor Browser AI Agent', operator: 'Anchor Browser' }
      : null;
  if (webBotAuth.present || cloudBrowserOperator) {
    const handle = webBotAuth.agentHost || webBotAuth.keyId || 'unattributed signer';
    return aiAgentResult({
      agentId: 'cloud-browser',
      agentName:
        directoryHint?.clientName ||
        cloudBrowserOperator?.name ||
        'AI Agent · Cloud Browser (RFC 9421 Signed)',
      operator: cloudBrowserOperator?.operator || 'Unattributed Cloud Browser',
      executionMode: 'RFC 9421 Signed Agent',
      verified: webBotAuth.present,
      confidence: webBotAuth.present ? 'Verified' : 'High',
      evidence: [
        ...signatureEvidence,
        ...(cloudBrowserOperator ? [`Signature-Agent operator: ${handle}`] : []),
        ...(!cloudBrowserOperator ? [`Signed agent handle: ${handle}`] : []),
        ...(networkHaystack ? [`Network identity: ${networkHaystack}`] : []),
        ...directoryEvidence,
      ],
    });
  }

  /* ------------------ Rule H — spoofed impostor (fallback) ----------------- */
  const officialBotClaim =
    /googlebot|googleother|gemini-deep-research|gptbot|chatgpt-user|perplexitybot|perplexity-user|claudebot|claude-user|grokbot|meta-externalagent|muse/i.test(
      ua
    );
  if (officialBotClaim) {
    return aiAgentResult({
      agentId: 'impostor-spoof',
      agentName: 'Spoofed AI Bot Impostor (Unverified IP)',
      operator: 'Unverified AI crawler claim',
      executionMode: 'Spoofed Impostor',
      verified: false,
      confidence: 'Verified',
      evidence: [
        `Official AI crawler user-agent claim: ${ua.slice(0, 120)}`,
        `Source IP ${input.publicIp} could not be verified via CIDR or FCrDNS`,
      ],
    });
  }

  return NO_AI_AGENT;
}

/* -------------------------------------------------------------------------- */
/* Phase 3 — server-side emulator / simulator re-verification                  */
/* -------------------------------------------------------------------------- */

/**
 * The client probe in `src/lib/collector.ts` reports `emulatorDetected` inside the payload, but a
 * client is free to omit or forge that flag. These are the same predicates re-applied on the
 * server to the sanitized payload (the signed User-Agent, `navigator.platform`, touch capability
 * and the WebGL renderer string), so an emulated runtime cannot hide by lying about the verdict.
 */
const EMULATOR_GPU_SIGNATURE_PATTERN =
  /android emulator opengl es translator|goldfish|ranchu|bluestacks|nox|ldplayer|memu|genymotion|virgl|apple software renderer/i;
/** x86 / desktop platform strings a real Android handset can never report. */
const NON_ARM_ANDROID_PLATFORM_PATTERN = /linux x86|x86_64|i[3-6]86|win32|win64|macintel/i;
const IOS_DEVICE_UA_PATTERN = /(iphone|ipad|ipod)/i;
const IOS_FOREIGN_PLATFORM_PATTERN = /linux|win32|win64/i;
const IPHONE_OR_IPOD_UA_PATTERN = /(iphone|ipod)/i;

/** `1920x1080` / `1920 × 1080` → viewport width in CSS pixels (0 when unparsable). */
function parseScreenResolutionWidth(resolution: string): number {
  const match = /(\d+)\s*[x×]\s*(\d+)/i.exec(resolution || '');
  if (match) {
    const width = Number.parseInt(match[1], 10);
    return Number.isFinite(width) && width > 0 ? width : 0;
  }
  const single = Number.parseInt(resolution || '', 10);
  return Number.isFinite(single) && single > 0 ? single : 0;
}

/**
 * Server-side mirror of `detectEmulatorEvidence()`: Android UA on an x86/desktop platform or with
 * zero touch points, an emulator/simulator GPU renderer, an iOS UA on a foreign platform or with
 * no touch points (iPadOS 13+ reports `MacIntel` WITH touch points and stays clean), and an
 * iPhone/iPod UA on a desktop-width screen.
 */
function classifyEmulatorFromSignals(input: {
  userAgent: string;
  platform: string;
  maxTouchPoints: number;
  gpuVendor: string;
  gpuRenderer: string;
  screenResolution: string;
}): { detected: boolean; reason: string } {
  const ua = typeof input.userAgent === 'string' ? input.userAgent : '';
  const platform = (input.platform || '').trim();
  const maxTouchPoints =
    typeof input.maxTouchPoints === 'number' ? Math.max(0, input.maxTouchPoints) : 0;
  const vendor = (input.gpuVendor || '').trim();
  const renderer = (input.gpuRenderer || '').trim();
  const gpuSignature = `${vendor} ${renderer}`;

  const claimsAndroid = /android/i.test(ua);
  const claimsIos = IOS_DEVICE_UA_PATTERN.test(ua);

  if (claimsAndroid && NON_ARM_ANDROID_PLATFORM_PATTERN.test(platform)) {
    return {
      detected: true,
      reason: `Android user-agent on desktop ${platform} (emulator CPU profile)`,
    };
  }
  if (claimsAndroid && maxTouchPoints === 0) {
    return {
      detected: true,
      reason: 'Android user-agent reporting zero touch points (emulated input layer)',
    };
  }
  if (EMULATOR_GPU_SIGNATURE_PATTERN.test(gpuSignature)) {
    return {
      detected: true,
      reason: `Emulator GPU renderer (${renderer || vendor || 'masked renderer'})`,
    };
  }
  if (claimsIos) {
    if (IOS_FOREIGN_PLATFORM_PATTERN.test(platform)) {
      return { detected: true, reason: `iOS user-agent on ${platform} platform (simulator host)` };
    }
    if (maxTouchPoints === 0) {
      return {
        detected: true,
        reason: `iOS user-agent on ${platform || 'desktop'} with zero touch points (simulator)`,
      };
    }
  }
  const screenWidth = parseScreenResolutionWidth(input.screenResolution);
  if (IPHONE_OR_IPOD_UA_PATTERN.test(ua) && screenWidth >= 1000) {
    return { detected: true, reason: `iPhone user-agent on a ${screenWidth}px desktop-width screen` };
  }

  return { detected: false, reason: '' };
}

/* -------------------------------------------------------------------------- */
/* Phase 2 — Tor exit relay resolution and local abuse blocklist               */
/* -------------------------------------------------------------------------- */

const TOR_DNS_TIMEOUT_MS = 600;
const TOR_DOH_TIMEOUT_MS = 1200;
const TOR_DOH_ENDPOINTS = ['https://dns.google/resolve', 'https://cloudflare-dns.com/dns-query'];
const TOR_BULK_LIST_URL = 'https://check.torproject.org/torbulkexitlist';
const TOR_EXIT_ADDRESSES_URL = 'https://check.torproject.org/exit-addresses';
const TOR_ONIONOO_DETAILS_URL = 'https://onionoo.torproject.org/details';
const TOR_BULK_LIST_MAX_ENTRIES = 20000;
/** Full consensus refresh cadence (bulk list + exit-addresses + Onionoo details). */
const TOR_INTELLIGENCE_SYNC_INTERVAL_MS = 30 * 60 * 1000;
const TOR_INTELLIGENCE_SYNC_TIMEOUT_MS = 10000;
const TOR_BULK_TIMEOUT_MS = TOR_INTELLIGENCE_SYNC_TIMEOUT_MS;
const TOR_LIVE_LOOKUP_TIMEOUT_MS = 1800;
const TOR_REVERSE_DNS_TIMEOUT_MS = 1200;
const TOR_VERDICT_CACHE_TTL_MS = 30 * 60 * 1000;
const TOR_VERDICT_CACHE_MAX_ENTRIES = 5000;
const TOR_OPERATOR_PREFIX_CACHE_TTL_MS = 6 * 60 * 60 * 1000;

interface TorRelayMetadata {
  nickname: string;
  fingerprint: string;
  as?: string;
  asName?: string;
  country?: string;
  flags: string[];
}

/**
 * Hot in-memory consensus tables. Replaced by reference (never mutated in place) so an in-flight
 * request either sees the complete previous snapshot or the complete new one, never a half-filled
 * set.
 */
let torIpv4ExitSet = new Set<string>();
let torIpv6ExitSet = new Set<string>();
let torIpv6Prefix64Set = new Set<string>();
let torIpv6Prefix48Set = new Set<string>();
let torRelayMetadataMap = new Map<string, TorRelayMetadata>();

let torIntelligenceLastSyncMs = 0;
let torIntelligenceSyncInFlight: Promise<void> | null = null;
let torIntelligenceTimer: ReturnType<typeof setInterval> | null = null;

const torVerdictCache = new Map<
  string,
  { verdict: 'exit' | 'relay' | 'no'; expiresAtMs: number }
>();
const torReverseDnsCache = new Map<string, { names: string[]; expiresAtMs: number }>();

/* -------------------------------------------------------------------------- */
/* Dual-stack IP normalization (IPv4 + IPv6, mapped / bracketed / zoned forms) */
/* -------------------------------------------------------------------------- */

/** Canonicalizes an IP literal: trims, drops brackets, zone ids and maps `::ffff:` to IPv4. */
export function normalizeIpAddress(rawIp: string): string {
  if (typeof rawIp !== 'string') return '';
  let value = rawIp.trim();
  if (!value) return '';
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
  const zoneIndex = value.indexOf('%');
  if (zoneIndex >= 0) value = value.slice(0, zoneIndex);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (mapped) value = mapped[1];
  return value.toLowerCase();
}

function isIpv6Hextet(value: string): boolean {
  return /^[0-9a-f]{1,4}$/.test(value);
}

/**
 * Expands `::` compression into a canonical 8-hextet string so `/64` (first 4 hextets) and
 * `/48` (first 3 hextets) prefixes can be extracted deterministically.
 */
export function expandIpv6Address(ip: string): string | null {
  let value = normalizeIpAddress(ip);
  if (!value || !value.includes(':')) return null;

  // Rewrite a dotted-quad tail (`::ffff:192.0.2.1`) as two hextets before compression expands.
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    if (lastColon < 0) return null;
    const tail = value.slice(lastColon + 1);
    if (!isIpv4Literal(tail)) return null;
    const [a, b, c, d] = tail.split('.').map((octet) => Number.parseInt(octet, 10));
    value = `${value.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${(
      (c << 8) |
      d
    ).toString(16)}`;
  }

  const halves = value.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if (halves.length === 2) {
    if (head.length + tail.length > 7) return null;
    const zeros = new Array<string>(8 - head.length - tail.length).fill('0');
    const hextets = [...head, ...zeros, ...tail];
    if (!hextets.every(isIpv6Hextet)) return null;
    return hextets.map((hextet) => hextet.replace(/^0+(?=.)/, '')).join(':');
  }
  if (head.length !== 8 || !head.every(isIpv6Hextet)) return null;
  return head.map((hextet) => hextet.replace(/^0+(?=.)/, '')).join(':');
}

function ipv4ToInt(ip: string): number | null {
  if (!isIpv4Literal(ip)) return null;
  const octets = ip.split('.').map((octet) => Number.parseInt(octet, 10));
  return (
    ((octets[0] * 0x1000000 + octets[1] * 0x10000 + octets[2] * 0x100 + octets[3]) >>> 0) >>> 0
  );
}

function ipv4MatchesCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf('/');
  const base = (slash >= 0 ? cidr.slice(0, slash) : cidr).trim();
  const bits = slash >= 0 ? Number.parseInt(cidr.slice(slash + 1), 10) : 32;
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) >>> 0 === (baseInt & mask) >>> 0;
}

function ipv6MatchesCidr(ip: string, cidr: string): boolean {
  const slash = cidr.lastIndexOf('/');
  const base = (slash >= 0 ? cidr.slice(0, slash) : cidr).trim();
  const bits = slash >= 0 ? Number.parseInt(cidr.slice(slash + 1), 10) : 128;
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return false;
  const ipExpanded = expandIpv6Address(ip);
  const baseExpanded = expandIpv6Address(base);
  if (!ipExpanded || !baseExpanded) return false;
  const ipHextets = ipExpanded.split(':');
  const baseHextets = baseExpanded.split(':');
  const fullHextets = Math.floor(bits / 16);
  for (let index = 0; index < fullHextets; index += 1) {
    if (ipHextets[index] !== baseHextets[index]) return false;
  }
  const remainingBits = bits % 16;
  if (remainingBits === 0) return true;
  const mask = (0xffff << (16 - remainingBits)) & 0xffff;
  const ipValue = Number.parseInt(ipHextets[fullHextets], 16);
  const baseValue = Number.parseInt(baseHextets[fullHextets], 16);
  return (ipValue & mask) === (baseValue & mask);
}

/** Fast dual-stack CIDR matcher shared by the Tor operator ranges and the AI bot prefix lists. */
export function ipMatchesCidrList(ip: string, cidrList: readonly string[]): boolean {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return false;
  const isV4 = isIpv4Literal(normalized);
  for (const cidr of cidrList) {
    if (typeof cidr !== 'string') continue;
    const candidate = cidr.trim();
    if (!candidate) continue;
    if (isV4) {
      if (ipv4MatchesCidr(normalized, candidate)) return true;
    } else if (ipv6MatchesCidr(normalized, candidate)) {
      return true;
    }
  }
  return false;
}

/**
 * Tier 2 — dual-stack operators such as Church of Cyberology embed the relay's IPv4 address in
 * the last four hextets (`2001:67c:e60:c0c:192:42:116:110` → `192.42.116.110`).
 */
export function extractEmbeddedIpv4FromIpv6(ip: string): string | null {
  const expanded = expandIpv6Address(ip);
  if (!expanded) return null;
  const tail = expanded.split(':').slice(4);
  if (tail.length !== 4 || !tail.every((hextet) => /^\d{1,3}$/.test(hextet))) return null;
  const octets = tail.map((hextet) => Number.parseInt(hextet, 10));
  if (octets.some((octet) => octet > 255)) return null;
  return octets.join('.');
}

function isTorOperatorPrefix(ip: string): boolean {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return false;
  if (isIpv4Literal(normalized)) return ipMatchesCidrList(normalized, TOR_OPERATOR_IPV4_CIDRS);
  return ipMatchesCidrList(normalized, TOR_OPERATOR_IPV6_PREFIXES);
}

/** Splits an Onionoo `or_addresses` entry (`1.2.3.4:443`, `[2001:db8::1]:443`). */
function splitTorAddressPort(entry: string): string {
  const trimmed = entry.trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('[')) {
    const close = trimmed.indexOf(']');
    if (close > 0) return trimmed.slice(1, close);
  }
  const firstColon = trimmed.indexOf(':');
  const lastColon = trimmed.lastIndexOf(':');
  if (firstColon > 0 && firstColon === lastColon) return trimmed.slice(0, lastColon);
  return trimmed;
}

async function fetchTextWithTimeout(
  url: string,
  timeoutMs: number,
  accept: string
): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { accept },
    });
    if (!response.ok) return null;
    return await response.text();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/* -------------------------------------------------------------------------- */
/* Tier 1 — background Tor consensus synchronization (IPv4 + IPv6 exits)       */
/* -------------------------------------------------------------------------- */

interface OnionooRelay {
  nickname?: string;
  fingerprint?: string;
  as?: string;
  as_name?: string;
  country?: string;
  flags?: unknown;
  or_addresses?: unknown;
  exit_addresses?: unknown;
}

function torRelayMetadataFromOnionoo(relay: OnionooRelay): TorRelayMetadata {
  return {
    nickname: typeof relay.nickname === 'string' ? relay.nickname : '',
    fingerprint: typeof relay.fingerprint === 'string' ? relay.fingerprint : '',
    as: typeof relay.as === 'string' ? relay.as : undefined,
    asName: typeof relay.as_name === 'string' ? relay.as_name : undefined,
    country: typeof relay.country === 'string' ? relay.country : undefined,
    flags: Array.isArray(relay.flags)
      ? relay.flags.filter((flag): flag is string => typeof flag === 'string')
      : [],
  };
}

/** Downloads every source and swaps all tables in one atomic reference update. */
async function syncTorIntelligence(): Promise<void> {
  const nextIpv4 = new Set<string>();
  const nextIpv6 = new Set<string>();
  const nextPrefix64 = new Set<string>();
  const nextPrefix48 = new Set<string>();
  const nextMetadata = new Map<string, TorRelayMetadata>();

  const remember = (key: string, metadata: TorRelayMetadata): void => {
    if (!nextMetadata.has(key)) nextMetadata.set(key, metadata);
  };

  const addIpv4 = (rawIp: unknown, metadata: TorRelayMetadata | null): void => {
    if (typeof rawIp !== 'string') return;
    const ip = normalizeIpAddress(rawIp);
    if (!isIpv4Literal(ip)) return;
    nextIpv4.add(ip);
    if (metadata) remember(ip, metadata);
  };

  const addIpv6 = (rawIp: unknown, metadata: TorRelayMetadata | null): void => {
    if (typeof rawIp !== 'string') return;
    const ip = normalizeIpAddress(rawIp);
    const expanded = expandIpv6Address(ip);
    if (!expanded) return;
    nextIpv6.add(ip);
    nextIpv6.add(expanded);
    const hextets = expanded.split(':');
    nextPrefix64.add(hextets.slice(0, 4).join(':'));
    nextPrefix48.add(hextets.slice(0, 3).join(':'));
    if (metadata) {
      remember(ip, metadata);
      remember(expanded, metadata);
    }
  };

  const [bulkList, exitAddresses, onionoo] = await Promise.all([
    fetchTextWithTimeout(TOR_BULK_LIST_URL, TOR_INTELLIGENCE_SYNC_TIMEOUT_MS, 'text/plain'),
    fetchTextWithTimeout(TOR_EXIT_ADDRESSES_URL, TOR_INTELLIGENCE_SYNC_TIMEOUT_MS, 'text/plain'),
    fetchTextWithTimeout(
      `${TOR_ONIONOO_DETAILS_URL}?search=running:true&fields=nickname,fingerprint,or_addresses,exit_addresses,flags,as,as_name,country`,
      TOR_INTELLIGENCE_SYNC_TIMEOUT_MS,
      'application/json'
    ),
  ]);

  if (bulkList) {
    for (const line of bulkList.split(/\r?\n/)) {
      const candidate = line.trim();
      if (!candidate || candidate.startsWith('#')) continue;
      addIpv4(candidate, null);
      if (nextIpv4.size >= TOR_BULK_LIST_MAX_ENTRIES) break;
    }
  }

  if (exitAddresses) {
    let fingerprint = '';
    for (const line of exitAddresses.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith('ExitNode ')) {
        fingerprint = trimmed.slice('ExitNode '.length).trim();
        continue;
      }
      if (!trimmed.startsWith('ExitAddress ')) continue;
      const address = trimmed.split(/\s+/)[1] ?? '';
      addIpv4(address, {
        nickname: fingerprint ? `exit-${fingerprint.slice(0, 8)}` : '',
        fingerprint,
        flags: ['Exit'],
      });
    }
  }

  if (onionoo) {
    try {
      const parsed = JSON.parse(onionoo) as { relays?: unknown };
      const relays = Array.isArray(parsed.relays) ? (parsed.relays as OnionooRelay[]) : [];
      for (const relay of relays) {
        const flags = Array.isArray(relay.flags)
          ? relay.flags.filter((flag): flag is string => typeof flag === 'string')
          : [];
        // Only exit-capable relays can be an anonymity egress.
        if (!flags.includes('Exit')) continue;
        const metadata = torRelayMetadataFromOnionoo(relay);
        const exitAddressesForRelay = Array.isArray(relay.exit_addresses)
          ? relay.exit_addresses
          : [];
        for (const address of exitAddressesForRelay) addIpv4(address, metadata);
        const orAddresses = Array.isArray(relay.or_addresses) ? relay.or_addresses : [];
        for (const entry of orAddresses) {
          if (typeof entry !== 'string') continue;
          const host = splitTorAddressPort(entry);
          if (!host) continue;
          if (isIpv4Literal(host)) addIpv4(host, metadata);
          else addIpv6(host, metadata);
        }
      }
    } catch {
      // Malformed payload: keep the previous snapshot rather than publishing a partial one.
    }
  }

  if (nextIpv4.size === 0 && nextIpv6.size === 0) return;

  torIpv4ExitSet = nextIpv4;
  torIpv6ExitSet = nextIpv6;
  torIpv6Prefix64Set = nextPrefix64;
  torIpv6Prefix48Set = nextPrefix48;
  torRelayMetadataMap = nextMetadata;
  torIntelligenceLastSyncMs = Date.now();
}

function runTorIntelligenceSync(): Promise<void> {
  if (torIntelligenceSyncInFlight) return torIntelligenceSyncInFlight;
  torIntelligenceSyncInFlight = syncTorIntelligence()
    .catch(() => undefined)
    .finally(() => {
      torIntelligenceSyncInFlight = null;
    });
  return torIntelligenceSyncInFlight;
}

function ensureTorIntelligenceSync(): void {
  if (torIntelligenceTimer === null) {
    void runTorIntelligenceSync();
    torIntelligenceTimer = setInterval(() => {
      void runTorIntelligenceSync();
    }, TOR_INTELLIGENCE_SYNC_INTERVAL_MS);
    const handle = torIntelligenceTimer as unknown as { unref?: () => void };
    if (typeof handle.unref === 'function') handle.unref();
    return;
  }
  // The timer exists but a runtime can evict timers; re-arm a straggling refresh.
  if (Date.now() - torIntelligenceLastSyncMs >= TOR_INTELLIGENCE_SYNC_INTERVAL_MS) {
    void runTorIntelligenceSync();
  }
}

// Workers reject global-scope timers, so this is best-effort at boot and lazily re-armed on the
// first request in runtimes that refuse it.
try {
  ensureTorIntelligenceSync();
} catch {
  // Started on the first request instead.
}

function lookupTorRelayMetadata(ip: string): TorRelayMetadata | null {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return null;
  const direct = torRelayMetadataMap.get(normalized);
  if (direct) return direct;
  const expanded = expandIpv6Address(normalized);
  if (!expanded) return null;
  return torRelayMetadataMap.get(expanded) ?? null;
}

/** Human-readable operator label, e.g. `Church of Cyberology · AS215125`. */
function describeTorRelay(ip: string): string | null {
  const metadata = lookupTorRelayMetadata(ip);
  if (!metadata) return null;
  const organization = metadata.asName || metadata.nickname;
  const asn = metadata.as ? (metadata.as.startsWith('AS') ? metadata.as : `AS${metadata.as}`) : '';
  if (organization && asn) return `${organization} · ${asn}`;
  return organization || asn || null;
}

function pruneTorVerdictCache(nowMs: number): void {
  for (const [ip, entry] of torVerdictCache) {
    if (entry.expiresAtMs <= nowMs) torVerdictCache.delete(ip);
  }
  while (torVerdictCache.size >= TOR_VERDICT_CACHE_MAX_ENTRIES) {
    const oldestKey = torVerdictCache.keys().next().value;
    if (typeof oldestKey !== 'string') break;
    torVerdictCache.delete(oldestKey);
  }
}

const SUSPICIOUS_IP_TTL_MS = 24 * 60 * 60 * 1000;
const SUSPICIOUS_IP_MAX_ENTRIES = 10000;
// A single anomalous request is not enough to brand an IP: residential lines are shared and a
// single stale tab, clock glitch or one-off probe must never show a visitor as blocklisted.
// Only repeated, independent evidence promotes an entry into the visible blocklist.
const SUSPICIOUS_IP_BLOCK_THRESHOLD = 2;
const suspiciousIpLedger = new Map<string, number>();
const suspiciousIpReasons = new Map<string, string[]>();
const suspiciousIpStrikes = new Map<string, number>();

function isIpv4Literal(value: string): boolean {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed)) return false;
  return trimmed.split('.').every((octet) => {
    const parsed = Number.parseInt(octet, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 255;
  });
}

type TorExitVerdict = 'exit' | 'relay' | 'not_exit' | 'unknown';

/**
 * Authoritative per-IP Tor DNSEL query (`<reversed-octets>.dnsel.torproject.org`). Only
 * `127.0.0.2` means "exit relay". Native resolver first, DNS-over-HTTPS as fallback for hosts
 * whose own resolver refuses direct A queries. Returns null when no resolver produced an answer.
 */
async function resolveTorDnsel(ipv4: string): Promise<boolean | null> {
  const queryName = `${ipv4.split('.').reverse().join('.')}.dnsel.torproject.org`;
  let resolved = false;
  let isTorExit = false;

  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
  try {
    const lookup = dns.resolve4(queryName).catch((error: NodeJS.ErrnoException) => {
      // A missing record is a definitive "not an exit relay"; a refused or timed-out query
      // says nothing about the address and must fall through to DNS-over-HTTPS.
      const code = typeof error?.code === 'string' ? error.code : '';
      if (code === 'ENOTFOUND' || code === 'ENODATA' || code === 'ENOTIMP') {
        return [] as string[];
      }
      return null;
    });
    const timeout = new Promise<string[] | null>((resolve) => {
      timeoutHandle = setTimeout(() => resolve(null), TOR_DNS_TIMEOUT_MS);
    });
    const records = await Promise.race([lookup, timeout]);
    if (Array.isArray(records)) {
      resolved = true;
      isTorExit = records.includes('127.0.0.2');
    }
  } catch {
    resolved = false;
  } finally {
    if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
  }

  if (!resolved) {
    for (const endpoint of TOR_DOH_ENDPOINTS) {
      const answers = await resolveAOverDoh(endpoint, queryName);
      if (answers) {
        resolved = true;
        isTorExit = answers.includes('127.0.0.2');
        break;
      }
    }
  }

  return resolved ? isTorExit : null;
}

/** Reverse DNS (PTR) with a hard timeout. Never throws: some runtimes refuse PTR lookups. */
async function resolveTorReverseDns(ip: string): Promise<string[]> {
  const nowMs = Date.now();
  const cached = torReverseDnsCache.get(ip);
  if (cached && cached.expiresAtMs > nowMs) return cached.names;

  let names: string[] = [];
  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
  try {
    const lookup = dns.reverse(ip).catch(() => [] as string[]);
    const timeout = new Promise<string[]>((resolve) => {
      timeoutHandle = setTimeout(() => resolve([]), TOR_REVERSE_DNS_TIMEOUT_MS);
    });
    const records = await Promise.race([lookup, timeout]);
    if (Array.isArray(records)) {
      names = records.filter((name): name is string => typeof name === 'string');
    }
  } catch {
    names = [];
  } finally {
    if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
  }

  if (torReverseDnsCache.size > TOR_VERDICT_CACHE_MAX_ENTRIES) torReverseDnsCache.clear();
  torReverseDnsCache.set(ip, {
    names,
    expiresAtMs: nowMs + TOR_OPERATOR_PREFIX_CACHE_TTL_MS,
  });
  return names;
}

/**
 * Tier 4 live Onionoo lookup. `search=<ip>` matches both `or_addresses` and `exit_addresses` for
 * IPv4, but Onionoo's `exit_addresses` field is IPv4-only, so the /64 prefix comparison below is
 * what resolves IPv6 exits.
 */
async function lookupOnionooRelay(
  target: string
): Promise<{ matched: boolean; isExit: boolean } | null> {
  const url = `${TOR_ONIONOO_DETAILS_URL}?search=${encodeURIComponent(
    target
  )}&fields=nickname,fingerprint,or_addresses,exit_addresses,flags,as`;
  const body = await fetchTextWithTimeout(url, TOR_LIVE_LOOKUP_TIMEOUT_MS, 'application/json');
  if (!body) return null;
  let relays: OnionooRelay[] = [];
  try {
    const parsed = JSON.parse(body) as { relays?: unknown };
    relays = Array.isArray(parsed.relays) ? (parsed.relays as OnionooRelay[]) : [];
  } catch {
    return null;
  }

  const targetExpanded = expandIpv6Address(target);
  const targetPrefix64 = targetExpanded ? targetExpanded.split(':').slice(0, 4).join(':') : null;
  let matched = false;
  let isExit = false;

  for (const relay of relays) {
    const addresses: string[] = [];
    if (Array.isArray(relay.exit_addresses)) {
      for (const address of relay.exit_addresses) {
        if (typeof address === 'string') addresses.push(address);
      }
    }
    if (Array.isArray(relay.or_addresses)) {
      for (const entry of relay.or_addresses) {
        if (typeof entry !== 'string') continue;
        const host = splitTorAddressPort(entry);
        if (host) addresses.push(host);
      }
    }

    const hasMatch = addresses.some((address) => {
      const normalized = normalizeIpAddress(address);
      if (!normalized) return false;
      if (normalized === target) return true;
      const expanded = expandIpv6Address(normalized);
      if (!expanded) return false;
      if (targetExpanded && expanded === targetExpanded) return true;
      return targetPrefix64 !== null && expanded.split(':').slice(0, 4).join(':') === targetPrefix64;
    });
    if (!hasMatch) continue;
    matched = true;
    const flags = Array.isArray(relay.flags)
      ? relay.flags.filter((flag): flag is string => typeof flag === 'string')
      : [];
    if (flags.includes('Exit')) {
      isExit = true;
      break;
    }
  }

  return { matched, isExit };
}

/**
 * Resolves the Tor verdict for an IPv4 *or* IPv6 visitor, in strict order of authority:
 *
 * 1. Tier 1 — synced consensus sets (IPv4 exit list / Onionoo IPv4+IPv6 exits)
 * 2. Tier 2 — IPv4 address embedded in the last four hextets of an IPv6 address
 * 3. Tier 3 — dedicated relay-operator prefix, then reverse DNS
 * 4. Tier 4 — live DNSEL (IPv4) + Onionoo, cached for 30 minutes
 *
 * A relay that is part of the Tor network but is not an exit returns `'relay'`; only `'exit'`
 * means traffic could leave the network at that address.
 */
export async function resolveTorExitVerdict(ip: string): Promise<TorExitVerdict> {
  const cleanIp = normalizeIpAddress(ip);
  if (!cleanIp) return 'unknown';
  const isV4 = isIpv4Literal(cleanIp);
  const expanded = isV4 ? null : expandIpv6Address(cleanIp);
  if (!isV4 && expanded === null) return 'unknown';

  /* Tier 1 — consensus tables, O(1). */
  if (isV4 && torIpv4ExitSet.has(cleanIp)) return 'exit';
  if (expanded !== null && (torIpv6ExitSet.has(cleanIp) || torIpv6ExitSet.has(expanded))) {
    return 'exit';
  }

  /* Tier 2 — embedded IPv4-in-IPv6 (Church of Cyberology et al.). */
  if (!isV4) {
    const embeddedIpv4 = extractEmbeddedIpv4FromIpv6(cleanIp);
    if (embeddedIpv4 !== null) {
      if (torIpv4ExitSet.has(embeddedIpv4)) return 'exit';
      if (ipMatchesCidrList(embeddedIpv4, TOR_OPERATOR_IPV4_CIDRS)) return 'exit';
    }
  }

  /* Tier 3 — dedicated operator prefix, then reverse DNS. */
  if (isTorOperatorPrefix(cleanIp)) return 'relay';
  const reverseNames = await resolveTorReverseDns(cleanIp);
  if (reverseNames.some((name) => TOR_OPERATOR_REVERSE_DNS_PATTERN.test(name))) return 'relay';

  /* Tier 4 — cached live lookup. */
  const nowMs = Date.now();
  const cached = torVerdictCache.get(cleanIp);
  if (cached && cached.expiresAtMs > nowMs) {
    return cached.verdict === 'exit' ? 'exit' : cached.verdict === 'relay' ? 'relay' : 'not_exit';
  }

  let liveVerdict: 'exit' | 'relay' | 'no' | 'unknown' = 'unknown';

  if (isV4) {
    const [dnsel, onionoo] = await Promise.all([
      resolveTorDnsel(cleanIp),
      lookupOnionooRelay(cleanIp),
    ]);
    if (dnsel === true) {
      liveVerdict = 'exit';
    } else if (onionoo && onionoo.matched) {
      liveVerdict = onionoo.isExit ? 'exit' : 'relay';
    } else if (dnsel === false || (onionoo && !onionoo.matched)) {
      // At least one authoritative source answered: the address is not part of the network.
      liveVerdict = 'no';
    }
  } else {
    const onionoo = await lookupOnionooRelay(expanded ?? cleanIp);
    if (onionoo && onionoo.matched) liveVerdict = onionoo.isExit ? 'exit' : 'relay';
    else if (onionoo && !onionoo.matched) liveVerdict = 'no';
  }

  if (liveVerdict !== 'unknown') {
    pruneTorVerdictCache(nowMs);
    torVerdictCache.set(cleanIp, {
      verdict: liveVerdict,
      expiresAtMs: nowMs + TOR_VERDICT_CACHE_TTL_MS,
    });
  }

  return liveVerdict === 'exit' ? 'exit' : liveVerdict === 'relay' ? 'relay' : liveVerdict === 'no' ? 'not_exit' : 'unknown';
}

/** Boolean wrapper used by diagnostics; `unknown` degrades to `false`. */
async function isTorExitNode(ip: string): Promise<boolean> {
  return (await resolveTorExitVerdict(ip)) === 'exit';
}

/**
 * Operator fallback for the `unknown` DNSEL verdict: a relay operator ASN, organisation name or
 * the operator's dedicated prefix. Never used to overrule a definitive DNS answer.
 */
function matchesTorOperatorHint(location: {
  isp?: string;
  org?: string;
  asn?: string;
  publicIp?: string;
}): boolean {
  const haystack = [location.isp, location.org, location.asn]
    .filter((part): part is string => typeof part === 'string' && part.trim().length > 0)
    .join(' ');
  if (haystack.length > 0 && TOR_OPERATOR_ORG_PATTERN.test(haystack)) return true;
  if (matchesTorOperatorAsn(location.asn || '')) return true;
  const ip = typeof location.publicIp === 'string' ? normalizeIpAddress(location.publicIp) : '';
  return ip.length > 0 && isTorOperatorPrefix(ip);
}

/** IP / ASN / organisation operator label, independent of the Onionoo consensus. */
function relayOperatorLabel(location: {
  isp?: string;
  org?: string;
  asn?: string;
}): string | null {
  const rawAsn = typeof location.asn === 'string' ? location.asn.trim().toUpperCase() : '';
  const asn = rawAsn ? (rawAsn.startsWith('AS') ? rawAsn : `AS${rawAsn}`) : '';
  const name =
    [location.isp, location.org].find(
      (value): value is string =>
        typeof value === 'string' && value.trim().length > 0 && !/^unknown/i.test(value.trim())
    ) ?? '';
  if (name && asn) return `${name} · ${asn}`;
  return name || asn || null;
}

/**
 * Resolves the Tor verdict from every first-party layer, in strict order of authority:
 * synced consensus tables (IPv4 + IPv6) → DNSEL / Onionoo → operator ASN / prefix fallback.
 * The three outputs are distinct on purpose: a relay is part of the network but is not an
 * egress, so only `isExit` may drive the exit-node risk weights.
 */
interface TorExitStatus {
  isExit: boolean;
  isRelay: boolean;
  verdict: TorExitVerdict;
  viaOperatorHint: boolean;
  operator: string | null;
  relay: TorRelayMetadata | null;
}

async function resolveTorExitStatus(
  publicIp: string,
  location: { isp?: string; org?: string; asn?: string },
  prefetched?: Promise<TorExitVerdict>
): Promise<TorExitStatus> {
  const relay = lookupTorRelayMetadata(publicIp);
  const operator = describeTorRelay(publicIp) ?? relayOperatorLabel(location);

  if (isTorBulkListed(publicIp)) {
    return {
      isExit: true,
      isRelay: true,
      verdict: 'exit',
      viaOperatorHint: false,
      operator,
      relay,
    };
  }

  const verdict = await (prefetched ?? resolveTorExitVerdict(publicIp));
  if (verdict === 'exit') {
    return { isExit: true, isRelay: true, verdict, viaOperatorHint: false, operator, relay };
  }
  if (verdict === 'relay') {
    return { isExit: false, isRelay: true, verdict, viaOperatorHint: false, operator, relay };
  }
  if (verdict === 'unknown' && matchesTorOperatorHint({ ...location, publicIp })) {
    return {
      isExit: true,
      isRelay: true,
      verdict: 'relay',
      viaOperatorHint: true,
      operator: operator ?? relayOperatorLabel(location),
      relay,
    };
  }
  return { isExit: false, isRelay: false, verdict, viaOperatorHint: false, operator: null, relay: null };
}

/** Minimal DNS-over-HTTPS A-record lookup (JSON API). Returns null on any transport error. */
async function resolveAOverDoh(endpoint: string, name: string): Promise<string[] | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TOR_DOH_TIMEOUT_MS);
  try {
    const response = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=A`, {
      headers: { accept: 'application/dns-json' },
      signal: controller.signal,
    });
    if (!response.ok) return null;
    const payload = (await response.json()) as {
      Status?: number;
      Answer?: Array<{ type?: number; data?: string }>;
    };
    // Status 3 (NXDOMAIN) and an empty answer section are definitive negatives: the address is
    // not on the exit list. Servfail / refused are transport-quality problems and stay unknown.
    if (payload.Status === 3) return [];
    if (payload.Status !== 0) return null;
    const answers = Array.isArray(payload.Answer) ? payload.Answer : [];
    return answers
      .filter((entry) => entry.type === 1 && typeof entry.data === 'string')
      .map((entry) => String(entry.data).trim());
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Exact dual-stack membership in the synced consensus sets (no prefix heuristics here). */
function isTorBulkListed(ip: string): boolean {
  const cleanIp = normalizeIpAddress(ip);
  if (!cleanIp) return false;
  if (isIpv4Literal(cleanIp)) return torIpv4ExitSet.has(cleanIp);
  const expanded = expandIpv6Address(cleanIp);
  if (!expanded) return false;
  return torIpv6ExitSet.has(cleanIp) || torIpv6ExitSet.has(expanded);
}

/**
 * Kept as the request-path entry point: starts the background consensus daemon on first use and
 * forces a refresh when the last snapshot is older than the sync interval. A page load never
 * waits for this download — the per-IP lookup is authoritative and already tiered.
 */
async function refreshTorBulkList(): Promise<void> {
  ensureTorIntelligenceSync();
  if (torIntelligenceSyncInFlight) return;
  if (Date.now() - torIntelligenceLastSyncMs < TOR_INTELLIGENCE_SYNC_INTERVAL_MS) return;
  await runTorIntelligenceSync();
}

function flagSuspiciousIp(ip: string, reason: string): void {
  const cleanIp = typeof ip === 'string' ? ip.trim() : '';
  if (!cleanIp || cleanIp === 'Unavailable') return;

  const nowMs = Date.now();
  for (const [knownIp, expiresAtMs] of suspiciousIpLedger) {
    if (expiresAtMs <= nowMs) {
      suspiciousIpLedger.delete(knownIp);
      suspiciousIpReasons.delete(knownIp);
      suspiciousIpStrikes.delete(knownIp);
    }
  }
  while (suspiciousIpLedger.size >= SUSPICIOUS_IP_MAX_ENTRIES) {
    const oldestKey = suspiciousIpLedger.keys().next().value;
    if (typeof oldestKey !== 'string') break;
    suspiciousIpLedger.delete(oldestKey);
    suspiciousIpReasons.delete(oldestKey);
    suspiciousIpStrikes.delete(oldestKey);
  }

  const cleanReason = reason.trim().slice(0, 180);
  const existingReasons = suspiciousIpReasons.get(cleanIp) ?? [];
  if (cleanReason && !existingReasons.includes(cleanReason) && existingReasons.length < 5) {
    existingReasons.push(cleanReason);
  }
  suspiciousIpReasons.set(cleanIp, existingReasons);
  // Strikes count distinct reasons; the same reason repeated (for example a cached page that
  // keeps resending one stale envelope) never escalates on its own.
  const strikes = existingReasons.length;
  suspiciousIpStrikes.set(cleanIp, strikes);
  suspiciousIpLedger.set(cleanIp, nowMs + SUSPICIOUS_IP_TTL_MS);
}

function lookupSuspiciousIp(ip: string): { blocklisted: boolean; reasons: string[] } {
  const cleanIp = typeof ip === 'string' ? ip.trim() : '';
  if (!cleanIp) return { blocklisted: false, reasons: [] };
  const expiresAtMs = suspiciousIpLedger.get(cleanIp);
  if (expiresAtMs === undefined) return { blocklisted: false, reasons: [] };
  if (expiresAtMs <= Date.now()) {
    suspiciousIpLedger.delete(cleanIp);
    suspiciousIpReasons.delete(cleanIp);
    suspiciousIpStrikes.delete(cleanIp);
    return { blocklisted: false, reasons: [] };
  }
  const strikes = suspiciousIpStrikes.get(cleanIp) ?? 0;
  if (strikes < SUSPICIOUS_IP_BLOCK_THRESHOLD) {
    return { blocklisted: false, reasons: [] };
  }
  return {
    blocklisted: true,
    reasons: [...(suspiciousIpReasons.get(cleanIp) ?? [])],
  };
}

/* -------------------------------------------------------------------------- */
/* Phase 4 — sealed request envelope verification                             */
/* -------------------------------------------------------------------------- */

// A signed payload may only be replayed inside the nonce window; anything older is stale.
// The window is deliberately generous so a visitor whose system clock drifted (dead CMOS
// battery, wrong timezone offset, throttled VM clock) is never labelled as tampered.
const ENVELOPE_FRESHNESS_WINDOW_MS = 10 * 60 * 1000;
const NONCE_TTL_MS = 15 * 60 * 1000;
const NONCE_CACHE_MAX_ENTRIES = 5000;
const seenEnvelopeNonces = new Map<string, number>();

interface EnvelopeVerdict {
  tamperedRequest: boolean;
  replayDetected: boolean;
  requestIntegrityReason: string;
  requestNonce: string;
}

function sha256HexLower(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex').toLowerCase();
}

/** Folds navigator.platform / `sec-ch-ua-platform` spellings onto one comparison key. */
function normalizePlatformKey(value: string): string {
  const folded = value.replace(/"/g, '').trim().toLowerCase();
  if (!folded) return '';
  if (/windows|win32|win64|winnt/.test(folded)) return 'windows';
  if (/mac|macintosh|macintel/.test(folded)) return 'macos';
  if (/android/.test(folded)) return 'android';
  if (/ipad/.test(folded)) return 'ipados';
  if (/iphone|ios/.test(folded)) return 'ios';
  if (/chrome ?os|cros/.test(folded)) return 'chromeos';
  if (/linux|x11/.test(folded)) return 'linux';
  return '';
}

function rememberEnvelopeNonce(nonce: string, nowMs: number): boolean {
  for (const [knownNonce, expiresAtMs] of seenEnvelopeNonces) {
    if (expiresAtMs <= nowMs) seenEnvelopeNonces.delete(knownNonce);
  }
  const seenAtMs = seenEnvelopeNonces.get(nonce);
  if (seenAtMs !== undefined && seenAtMs > nowMs) return true;

  while (seenEnvelopeNonces.size >= NONCE_CACHE_MAX_ENTRIES) {
    const oldestKey = seenEnvelopeNonces.keys().next().value;
    if (typeof oldestKey !== 'string') break;
    seenEnvelopeNonces.delete(oldestKey);
  }
  seenEnvelopeNonces.set(nonce, nowMs + NONCE_TTL_MS);
  return false;
}

/**
 * Phase 4 — verifies the sealed request envelope. A missing signature is accepted (older
 * cached bundles), but a present-and-wrong signature, a stale timestamp or a header that
 * contradicts the JS payload marks the request tampered. A reused nonce is a replay.
 */
function verifySecurityEnvelope(args: {
  envelope: Partial<SecurityEnvelope> | null | undefined;
  headers: RawHeaderBag | null | undefined;
  hardwareId: string;
  nowMs: number;
}): EnvelopeVerdict {
  const { envelope, headers, hardwareId, nowMs } = args;
  const reasons: string[] = [];
  let tamperedRequest = false;

  const headerSignature = readRequestHeader(headers, 'x-intel-signature');
  const headerNonce = readRequestHeader(headers, 'x-intel-nonce');
  const headerTimestamp = readRequestHeader(headers, 'x-intel-timestamp');

  const envNonce = typeof envelope?.nonce === 'string' ? envelope.nonce.trim() : '';
  const requestNonce = (envNonce || headerNonce).slice(0, 128);

  const envSignature =
    typeof envelope?.signature === 'string' && envelope.signature.trim()
      ? envelope.signature.trim()
      : headerSignature;

  const envTimestamp =
    typeof envelope?.timestamp === 'number' && Number.isFinite(envelope.timestamp)
      ? envelope.timestamp
      : Number.parseFloat(headerTimestamp);
  const timestamp = Number.isFinite(envTimestamp) && envTimestamp > 0 ? envTimestamp : 0;

  const envelopeUserAgent =
    typeof envelope?.userAgent === 'string' ? envelope.userAgent.trim() : '';
  const envelopePlatform = typeof envelope?.platform === 'string' ? envelope.platform.trim() : '';
  const envelopeScreenResolution =
    typeof envelope?.screenResolution === 'string' ? envelope.screenResolution.trim() : '';
  const envelopeTimezone =
    typeof envelope?.timezone === 'string' ? envelope.timezone.trim() : '';

  // Payload integrity: only a present body signature is verified, and only when the fields the
  // canonical string needs (timestamp + nonce) are present. A signature carried only in headers
  // without an envelope object, or without a nonce, is unverifiable rather than tampered.
  if (envelope && envSignature && timestamp > 0 && requestNonce) {
    const canonical = [
      'INTEL_ENVELOPE_V1',
      String(timestamp),
      requestNonce,
      hardwareId,
      envelopeUserAgent,
      envelopePlatform,
      envelopeScreenResolution,
      envelopeTimezone,
    ].join('|');
    if (sha256HexLower(canonical) !== envSignature.toLowerCase()) {
      tamperedRequest = true;
      reasons.push('Payload integrity hash mismatch');
    }
  }

  // Freshness: a timestamp-less payload is unverifiable, not tampered. A signed payload is
  // only rejected when it is far outside the clock tolerance, so ordinary client clock drift
  // never produces a tamper verdict; the nonce cache below covers replays inside the window.
  if (timestamp > 0 && Math.abs(nowMs - timestamp) > ENVELOPE_FRESHNESS_WINDOW_MS) {
    tamperedRequest = true;
    reasons.push('Expired or replayed payload timestamp (>10m)');
  }

  // Replay: a nonce may be used exactly once inside the 15-minute window.
  let replayDetected = false;
  if (requestNonce) {
    replayDetected = rememberEnvelopeNonce(requestNonce, nowMs);
    if (replayDetected) reasons.push('Duplicate payload nonce (Replay Attack detected)');
  }

  // Header cross-check: the raw HTTP headers must agree with the signed JS payload.
  // Edge proxies (including Vercel) may truncate long User-Agent headers, so an exact
  // string comparison is unsafe. Compare the browser family and OS instead, and treat a
  // prefix relationship as compatible (truncated header).
  const headerUserAgent = readRequestHeader(headers, 'user-agent');
  if (headerUserAgent && envelopeUserAgent && !userAgentsCompatible(headerUserAgent, envelopeUserAgent)) {
    tamperedRequest = true;
    reasons.push('HTTP User-Agent header contradicts JS payload');
  }

  const clientHintPlatform = readRequestHeader(headers, 'sec-ch-ua-platform');
  const payloadPlatformKey = normalizePlatformKey(envelopePlatform);
  const clientHintPlatformKey = normalizePlatformKey(clientHintPlatform);
  // navigator.platform reports "Linux armv8l" on Android and "Linux x86_64" on Chrome OS while
  // the client hint reports "Android" / "Chrome OS" — those pairs are the same platform.
  const androidEquivalent =
    /android/i.test(headerUserAgent) &&
    ((payloadPlatformKey === 'linux' && clientHintPlatformKey === 'android') ||
      (payloadPlatformKey === 'android' && clientHintPlatformKey === 'linux'));
  const chromeOsEquivalent =
    /cros/i.test(headerUserAgent) &&
    ((payloadPlatformKey === 'linux' && clientHintPlatformKey === 'chromeos') ||
      (payloadPlatformKey === 'chromeos' && clientHintPlatformKey === 'linux'));
  const platformPairCompatible = androidEquivalent || chromeOsEquivalent;
  if (
    payloadPlatformKey &&
    clientHintPlatformKey &&
    payloadPlatformKey !== clientHintPlatformKey &&
    !platformPairCompatible
  ) {
    tamperedRequest = true;
    reasons.push('HTTP User-Agent header contradicts JS payload');
  }

  return {
    tamperedRequest,
    replayDetected,
    requestIntegrityReason: Array.from(new Set(reasons)).join('; '),
    requestNonce,
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

export const app = express();
app.set('trust proxy', true);
app.use(cookieParser());

// Ensure HTTP Permissions-Policy header allows compute-pressure in both top-level and embedded contexts
app.use((_req, res, next) => {
  res.setHeader('Permissions-Policy', 'compute-pressure=*');
  next();
});

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

app.use(express.json({ limit: '512kb' }));

app.get('/api/health', async (req, res) => {
  const visitorsCount = (
    db.prepare('SELECT COUNT(*) AS count FROM visitors').get() as { count: number }
  ).count;
  const visitsCount = (
    db.prepare('SELECT COUNT(*) AS count FROM visits').get() as { count: number }
  ).count;
  const { regionCode, regionLabel } = detectServerRegion(req);

  // Diagnostics: `?torCheck=<ipv4>` reports whether the Tor Project exit list resolves this
  // address from the server's network, so the relay reputation path can be verified directly.
  const torCheckIp =
    typeof req.query.torCheck === 'string' ? normalizeIpCandidate(req.query.torCheck) : null;
  if (torCheckIp && (isIpv4Literal(torCheckIp) || expandIpv6Address(torCheckIp) !== null)) {
    const startedAtMs = Date.now();
    ensureTorIntelligenceSync();
    const verdict = await resolveTorExitVerdict(torCheckIp);
    const relay = lookupTorRelayMetadata(torCheckIp);
    res.json({
      status: 'ok',
      visitorsCount,
      visitsCount,
      regionCode,
      regionLabel,
      torCheck: {
        ip: torCheckIp,
        exitNode: verdict === 'exit',
        verdict,
        bulkListed: isTorBulkListed(torCheckIp),
        operatorPrefix: isTorOperatorPrefix(torCheckIp),
        embeddedIpv4: extractEmbeddedIpv4FromIpv6(torCheckIp),
        operator: describeTorRelay(torCheckIp),
        relayOperatorAsn: relay?.as ?? null,
        relayOperatorName: relay?.asName ?? null,
        consensusIpv4Exits: torIpv4ExitSet.size,
        consensusIpv6Exits: torIpv6ExitSet.size,
        consensusSyncedAtMs: torIntelligenceLastSyncMs || null,
        latencyMs: Date.now() - startedAtMs,
      },
    });
    return;
  }

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

/**
 * Phase 1/2/4 request context, resolved by the identify handler before sanitization:
 * sealed-envelope verdicts, Tor / blocklist lookups and the resolved bot classification.
 * Everything is optional so older callers keep the previous behaviour.
 */
interface RequestIntegrityContext {
  headers?: RawHeaderBag;
  /** The signed / full User-Agent used for Phase 1 + Phase 3 identity checks. */
  requestUserAgent?: string;
  tamperedRequest?: boolean;
  replayDetected?: boolean;
  requestIntegrityReason?: string;
  requestNonce?: string;
  torExitNode?: boolean;
  /** True when the address belongs to the Tor network (exit *or* relay). */
  torRelay?: boolean;
  /** Resolved tri-state Tor verdict (drives the anonymity-network badge). */
  torVerdict?: TorExitVerdict;
  /** Relay operator label, e.g. `Church of Cyberology · AS215125`. */
  torOperator?: string | null;
  /** Client-side Tor Browser fingerprint (Gecko RFP + letterboxing). */
  clientTorBrowser?: boolean;
  /** Granular AI-agent attribution resolved by the AI attribution engine. */
  aiAgent?: AiAgentAttribution | null;
  /** True when the Tor verdict came from the operator-name fallback, not a DNS answer. */
  torOperatorHint?: boolean;
  ipBlocklisted?: boolean;
  ipBlocklistReasons?: string[];
  botClassification?: BotClassification;
}

function sanitizeAndReinforceSecuritySignals(
  raw: Partial<SecuritySignals> | null | undefined,
  browserDevice: BrowserDeviceInfo,
  hardwareSignals: HardwareSignals,
  location: LocationInfo,
  ipTimezoneHint: string,
  recognitionSource: IntelVisitorResponse['recognitionSource'],
  baseClassification: IspNetworkClassification,
  velocity: { visitsLastHour: number; distinctIpsLastHour: number },
  incognitoContext: IncognitoCrossModeContext = {},
  requestContext: RequestIntegrityContext = {}
): SecuritySignals {
  const safeStrArray = (arr: unknown): string[] =>
    Array.isArray(arr)
      ? arr
          .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
          .map((s) => s.trim().slice(0, 180))
          .slice(0, 10)
      : [];

  // Bot / automation: client flags plus the server-side identity classification. `isBot` is
  // the union of the explicit client verdict, the WebDriver handshake, the CDP (Chrome DevTools
  // Protocol) runtime probe and any non-human subtype the request signature proves.
  const webdriver = Boolean(raw?.webdriver);
  const cdpDetected = Boolean(raw?.cdpDetected);
  const isHeadless = Boolean(raw?.isHeadless);
  const botReason =
    typeof raw?.botReason === 'string' && raw.botReason.trim()
      ? raw.botReason.trim().slice(0, 200)
      : '';
  const botSignals = safeStrArray(raw?.botSignals);
  const clientAutomationDetected = Boolean(raw?.isBot || webdriver || cdpDetected);

  const botClassification: BotClassification =
    requestContext.botClassification ??
    classifyBotTraffic(
      requestContext.headers,
      { org: location.org, isp: location.isp, asn: location.asn },
      { isBot: clientAutomationDetected, isHeadless, webdriver, cdpDetected, botSignals }
    );
  const botSubtype: BotSubtype = botClassification.subtype;
  const spoofedCrawler =
    botClassification.subtype === 'bad_bot' && botClassification.label === 'Spoofed Crawler';
  const isBot = Boolean(
    clientAutomationDetected || botSubtype === 'bad_bot' || botSubtype === 'ai_agent'
  );

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
  const isGpuMaskedOrUnavailable =
    !hardwareSignals.gpuVendor ||
    hardwareSignals.gpuVendor === 'Unavailable' ||
    /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuVendor) ||
    !hardwareSignals.gpuRenderer ||
    hardwareSignals.gpuRenderer === 'Unavailable' ||
    /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuRenderer);

  const clientTorBrowser = Boolean(requestContext.clientTorBrowser ?? raw?.isTorBrowserClient);

  // Strict priority reconciliation: Tor anonymity > AI agent cloud > datacenter/VM > VPN >
  // mobile > residential > unknown. The base classifier is network-only; these verdicts are
  // first-party evidence that outranks ISP metadata.
  const classification = applyNetworkOverrides(baseClassification, {
    torExit: Boolean(requestContext.torExitNode || requestContext.torRelay),
    torOperatorHint: Boolean(requestContext.torOperatorHint),
    isTorBrowserClient: clientTorBrowser,
    aiAgentDetected: Boolean(requestContext.aiAgent?.detected),
    datacenterVm:
      Boolean(raw?.isVirtualMachine) &&
      (baseClassification.isDatacenterOrHosting || isGpuMaskedOrUnavailable),
    vpnSuspected: Boolean(raw?.vpnSuspected) || timezoneMismatch,
  });

  const isCloudOrDatacenterNetwork =
    classification.isDatacenterOrHosting || Boolean(location.isVpnOrHosting);

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
  // Phase 2 verdicts are consumed by the network boolean below, so they are resolved first.
  const torExitNode = Boolean(requestContext.torExitNode);
  const torOperatorHint = Boolean(requestContext.torOperatorHint);

  // A confirmed Tor exit relay is a network-reputation verdict in its own right; it must reach
  // `vpnSuspected` even when the relay sits on a residential ASN.
  const vpnSuspected =
    Boolean(raw?.vpnSuspected) ||
    timezoneMismatch ||
    torExitNode ||
    (datacenterAsn && botSubtype !== 'good_bot');

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

  const tamperDetected = Boolean(raw?.tamperDetected || requestContext.tamperedRequest);
  const tamperReasons = safeStrArray(raw?.tamperReasons);
  if (
    requestContext.tamperedRequest &&
    requestContext.requestIntegrityReason &&
    !tamperReasons.includes(requestContext.requestIntegrityReason)
  ) {
    tamperReasons.unshift(requestContext.requestIntegrityReason);
    tamperReasons.splice(10);
  }

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

  // Phase 3 — mobile emulator / simulator verdict. The client probe is authoritative when it
  // fires, but it is re-derived here from the signed payload so a client that omits or forges
  // `emulatorDetected` still gets the same verdict.
  const serverEmulator = classifyEmulatorFromSignals({
    userAgent:
      requestContext.requestUserAgent ||
      readRequestHeader(requestContext.headers, 'user-agent') ||
      '',
    platform: browserDevice.platform,
    maxTouchPoints: hardwareSignals.maxTouchPoints,
    gpuVendor: hardwareSignals.gpuVendor,
    gpuRenderer: hardwareSignals.gpuRenderer,
    screenResolution: browserDevice.screenResolution,
  });
  const clientEmulatorReported = Boolean(raw?.emulatorDetected);
  const emulatorDetected = clientEmulatorReported || serverEmulator.detected;
  const clientEmulatorReason =
    typeof raw?.emulatorReason === 'string' && raw.emulatorReason.trim()
      ? raw.emulatorReason.trim().slice(0, 200)
      : '';
  const emulatorReason = emulatorDetected
    ? serverEmulator.detected
      ? serverEmulator.reason
      : clientEmulatorReason
    : '';

  // Phase 2 / 4 — sealed-envelope and network reputation verdicts resolved by the handler.
  const tamperedRequest = Boolean(requestContext.tamperedRequest);
  const replayDetected = Boolean(requestContext.replayDetected);
  const requestIntegrityReason =
    typeof requestContext.requestIntegrityReason === 'string'
      ? requestContext.requestIntegrityReason.trim().slice(0, 240)
      : '';
  const requestNonce =
    typeof requestContext.requestNonce === 'string' ? requestContext.requestNonce.slice(0, 128) : '';
  const ipBlocklisted = Boolean(requestContext.ipBlocklisted);
  const ipBlocklistReasons = Array.isArray(requestContext.ipBlocklistReasons)
    ? requestContext.ipBlocklistReasons
        .filter((reason): reason is string => typeof reason === 'string' && reason.trim().length > 0)
        .map((reason) => reason.trim().slice(0, 180))
        .slice(0, 5)
    : [];

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
  // The Incognito tile is driven by the client's physical storage-commit probe. The
  // server-side "known hardware without cookies" correlation is deliberately not enough on
  // its own: a brand-new browser profile, cleared cookies or a cookie-blocking extension is
  // indistinguishable from a private window and must not be labelled Incognito.
  const clientReportedIncognito =
    Boolean(incognitoContext.clientReportedIncognito) || incognitoLikely;
  const isIncognito = clientReportedIncognito;

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
    // The physical proof must match the verdict: a private tile always quotes the client's
    // own storage-commit probe method, a normal tile quotes the verified disk-backed path.
    detail: isIncognito
      ? `Ephemeral RAM storage detected (${
          incognitoMethod || 'In-memory LevelDB / 10 GiB decoy quota'
        })`
      : `Persistent disk-backed storage verified (${incognitoMethod || 'Standard profile'})`,
  };

  // Tile 2 — Bot & Automation Detection (10 spoofed impostor / 9 bad bot / 8 AI agent /
  // 2 good bot / 0). The attribution engine names the exact agent and quotes its evidence.
  const aiAgent = requestContext.aiAgent ?? null;
  const spoofedImpostor =
    aiAgent?.agentId === 'impostor-spoof' ||
    (botSubtype === 'bad_bot' && spoofedCrawler);
  const botScore =
    spoofedImpostor ? 10 : botSubtype === 'bad_bot' ? 9 : botSubtype === 'ai_agent' ? 8 : botSubtype === 'good_bot' ? 2 : 0;
  const botStatus = spoofedImpostor
    ? 'Spoofed AI Impostor'
    : botSubtype === 'bad_bot'
    ? 'Bot / Automated'
    : aiAgent?.detected && aiAgent.agentName
    ? aiAgent.agentName
    : botSubtype === 'ai_agent'
    ? 'AI Agent · Cloud Browser'
    : botSubtype === 'good_bot'
    ? 'Good Bot · Search Crawler'
    : 'Verified Human';
  const aiAgentDetail =
    aiAgent?.detected && aiAgent.agentName
      ? `${aiAgent.agentName} — ${aiAgent.operator}${
          aiAgent.executionMode ? ` · ${aiAgent.executionMode}` : ''
        } · ${aiAgent.confidence}${aiAgent.verified ? ' (verified)' : ''}: ${
          aiAgent.evidence[0] || 'agent identity attributed from request headers'
        }`
      : '';
  const botDetail =
    botSubtype === 'human' && !aiAgent?.detected
      ? 'Verified human interactive session'
      : aiAgentDetail
      ? aiAgentDetail
      : botSubtype === 'ai_agent'
      ? `${botClassification.provider} ${botClassification.label} — ${
          botClassification.reasons[0] || KNOWN_AI_CRAWLER_REASON
        }`
      : botSubtype === 'good_bot'
      ? `${botClassification.provider} ${botClassification.label} verified against its official network — ${
          botClassification.reasons[1] || 'ASN / organisation match'
        }`
      : botReason ||
        botClassification.reasons[0] ||
        (spoofedCrawler
          ? 'Crawler user-agent claimed from a network that does not belong to the operator'
          : 'WebDriver / CDP automation runtime detected');

  const botSignal: SmartSignal = {
    id: 'bot',
    title: 'Bot & Automation Detection',
    status: botStatus,
    scoreOutOf10: botScore,
    riskLabel: `${tierFor(botScore)} Risk • ${botScore}/10`,
    level: levelFor(botScore),
    detail: botDetail,
  };

  // Tile 3 — VPN / Proxy & Network Type (10 Tor / 9 blocklisted / 8 datacenter + tz / 6 / 5 / 0)
  const isDatacenterAsn = datacenterAsn;
  // A verified search crawler legitimately runs on its operator's own datacenter ASN. Scoring
  // that as a consumer-facing "VPN / datacenter proxy" is a false positive produced by two
  // engines disagreeing about the same network, so the tile drops to a low-risk crawler state.
  const verifiedCrawlerNetwork = botSubtype === 'good_bot' && isDatacenterAsn;
  const ispBrand = classification.brandName || location.isp || 'Unknown ISP';
  const asnSuffix = location.asn !== 'Unknown' ? ` • ${location.asn}` : '';
  const asnLabel =
    location.asn && location.asn !== 'Unknown'
      ? /^AS/i.test(location.asn)
        ? location.asn.toUpperCase()
        : `AS${location.asn}`
      : 'AS unknown';
  const asnOrOrg = `${asnLabel} · ${location.org !== 'Unknown' ? location.org : ispBrand}`;
  const torBrowserClient = clientTorBrowser;
  const torRelayNetwork = requestContext.torVerdict === 'relay' || requestContext.torRelay === true;
  const torAnonymity = torExitNode || torBrowserClient;
  const torOperatorLabel =
    requestContext.torOperator ?? describeTorRelay(location.publicIp) ?? null;
  const vpnScore = torAnonymity
    ? torExitNode && torBrowserClient
      ? 10
      : 9
    : ipBlocklisted
    ? 9
    : verifiedCrawlerNetwork
    ? 2
    : torRelayNetwork
    ? 6
    : aiAgent?.detected
    ? 8
    : isDatacenterAsn && hasTzMismatch
    ? 8
    : isDatacenterAsn
    ? 6
    : hasTzMismatch
    ? 5
    : 0;
  const vpnStatus = torAnonymity
    ? torExitNode && torBrowserClient
      ? 'Tor Exit Node & Tor Browser'
      : torExitNode
      ? 'Tor Exit Node'
      : 'Tor Browser (Onion Routing / RFP)'
    : ipBlocklisted
    ? 'Blocklisted IP'
    : verifiedCrawlerNetwork
    ? 'Verified Crawler Network'
    : torRelayNetwork
    ? 'Tor Relay (Non-Exit)'
    : aiAgent?.detected
    ? 'AI Agent Cloud Network'
    : isDatacenterAsn
    ? 'VPN / Datacenter Proxy'
    : hasTzMismatch
    ? 'VPN / Timezone Relay'
    : 'Standard ISP';
  const vpnDetail = torAnonymity
    ? `${torExitNode ? 'Confirmed active Tor exit relay' : 'Tor Browser fingerprint (Gecko RFP + letterboxing)'} (${
        location.publicIp
      } · ${torOperatorLabel || asnOrOrg})${
        torOperatorHint ? ' — DNSEL unreachable, operator attribution used' : ''
      }${torExitNode && torBrowserClient ? ' · server exit IP and client RFP both matched (10/10)' : ''}`
    : ipBlocklisted
    ? 'IP flagged on abuse / tamper blocklist'
    : verifiedCrawlerNetwork
    ? `${botClassification.provider} crawler operating from its own ${ispBrand}${asnSuffix} — crawler infrastructure, not a consumer proxy`
    : torRelayNetwork
    ? `Tor relay network (${torOperatorLabel || asnOrOrg}) — part of the Tor network but not an exit egress`
    : aiAgent?.detected
    ? `${aiAgent.agentName} (${aiAgent.operator}) — ${aiAgent.executionMode || 'AI agent'} traffic from ${ispBrand}${asnSuffix}`
    : isDatacenterAsn && hasTzMismatch
    ? `Datacenter ASN (${ispBrand}${asnSuffix}) combined with a browser/IP timezone mismatch (${clientTzCanonical} vs ${ipTzCanonical})`
    : isDatacenterAsn
    ? `Datacenter / hosting ASN detected on ${ispBrand}${asnSuffix}`
    : hasTzMismatch
    ? `Browser timezone (${browserTimezone}) differs from IP geolocation timezone (${ipTimezone})`
    : `${ispBrand} • ${classification.networkType} (${asnLabel}) verified against browser timezone ${browserTimezone}`;

  const vpnSignal: SmartSignal = {
    id: 'vpn',
    title: 'VPN / Proxy & Network Type',
    status: vpnStatus,
    scoreOutOf10: vpnScore,
    riskLabel: `${tierFor(vpnScore)} Risk • ${vpnScore}/10`,
    level: levelFor(vpnScore),
    detail: vpnDetail,
  };

  // Tile 4 — Virtual Machine, Emulator & OS Integrity (10 tampered / 8 emulator or cloud VM
  // with masked GPU / 7 VM or cloud container / 6 spoofed environment / 0 physical hardware)
  const isVm = isVirtualMachine;
  const isTampered = isOsTampered;
  const cloudContainerVm = datacenterAsn && (isGpuMaskedOrUnavailable || cloudOrMaskedGpu);
  const vmLike = isVm || cloudContainerVm;
  // Table: turquoise 7 = cloud VM / masked WebGL on a datacenter ASN. An emulator stays 8 and
  // cryptographic tampering stays 10.
  const vmScore = tamperedRequest || replayDetected
    ? 10
    : emulatorDetected
    ? 8
    : vmLike
    ? 7
    : isTampered
    ? 6
    : 0;
  const vmStatus =
    tamperedRequest || replayDetected
      ? 'Tampered / Replayed'
      : emulatorDetected
      ? 'Mobile Emulator'
      : vmLike
      ? 'Virtual Machine / VM'
      : isTampered
      ? 'Spoofed Environment'
      : 'Physical Hardware';
  const vmDetail =
    tamperedRequest || replayDetected
      ? requestIntegrityReason || 'Sealed request envelope failed verification'
      : emulatorDetected
      ? emulatorReason || vmReason || 'Mobile emulator / simulator runtime detected'
      : vmLike
      ? vmReason ||
        (cloudContainerVm
          ? `Cloud container on ${ispBrand}${asnSuffix} exposed an unavailable / masked GPU`
          : 'Hypervisor CPUID / virtualised GPU footprint detected')
      : isTampered
      ? vmReason || tamperReasons[0] || 'Operating-system / User-Agent tampering detected'
      : 'Unmasked physical GPU & consistent OS platform verified';

  const vmSignal: SmartSignal = {
    id: 'vm',
    title: 'Virtual Machine & OS Integrity',
    status: vmStatus,
    scoreOutOf10: vmScore,
    riskLabel: `${tierFor(vmScore)} Risk • ${vmScore}/10`,
    level: levelFor(vmScore),
    detail: vmDetail,
  };

  const smartSignals: SmartSignals = {
    incognito: incognitoSignal,
    bot: botSignal,
    vpn: vpnSignal,
    vm: vmSignal,
  };

  // Composite — bot/headless 5|4, network 3|2, VM/tampered-OS 3, incognito 2,
  // sealed-envelope tamper or replay 2 (strictly ≤ 10).
  const integrityViolation = Boolean(tamperedRequest || replayDetected);
  // Network weight: a confirmed exit relay (5) outranks generic hosting (3); a verified
  // crawler's own network costs nothing; a plain timezone relay is worth 2.
  const networkPoints = torExitNode
    ? 5
    : verifiedCrawlerNetwork
    ? 0
    : isDatacenterAsn
    ? 3
    : hasTzMismatch
    ? 2
    : 0;
  const rawCompositePoints =
    (isBot ? 5 : isHeadless ? 4 : 0) +
    networkPoints +
    (vmScore > 0 ? 3 : 0) +
    (isIncognito ? 2 : 0) +
    (integrityViolation ? 2 : 0);
  const weightedCompositeScore = Math.min(10, rawCompositePoints);
  // Monotonic card-floor invariant: the headline score can never be lower than the highest
  // individual card. Two elevated cards add +1 synergy, three or more add +2. This is why a
  // 4/10 Incognito card next to a 5/10 VPN card can never be summarised as "4/10".
  const cardScores = [incognitoScore, botScore, vpnScore, vmScore];
  const maxCardScore = Math.max(0, ...cardScores);
  const elevatedCardCount = cardScores.filter((score) => score >= 4).length;
  const synergyBonus = elevatedCardCount >= 3 ? 2 : elevatedCardCount === 2 ? 1 : 0;
  const suspectScore = Math.min(
    10,
    Math.max(weightedCompositeScore, maxCardScore + synergyBonus)
  );
  const riskLevel: SecuritySignals['riskLevel'] = tierFor(suspectScore);
  const riskBadgeText = `${riskLevel} Risk • ${suspectScore}/10`;

  // Risk factors mirror the composite weights that actually fired. The deprecated DevTools /
  // ad-blocker / WebRTC / visit-velocity points are intentionally absent.
  const riskFactors: string[] = [];
  if (isBot) {
    riskFactors.push(
      `Automated browser / bot runtime detected (+5): ${
        botReason ||
        botClassification.reasons[0] ||
        botSignals[0] ||
        'WebDriver / CDP automation signatures'
      }`
    );
  } else if (isHeadless) {
    riskFactors.push(
      `Headless browser environment (+4): ${botReason || 'no physical display attached'}`
    );
  }
  if (torAnonymity) {
    riskFactors.push(
      `${torExitNode ? 'Confirmed Tor exit relay' : 'Tor Browser fingerprint'} (+${
        torExitNode && torBrowserClient ? 10 : 9
      } card): ${
        torExitNode
          ? torOperatorHint
            ? 'exit-operator attribution'
            : 'Tor Project DNSEL / consensus exit list'
          : 'Gecko RFP + letterboxing detected on the client'
      } ${location.publicIp}`
    );
  } else if (torRelayNetwork) {
    riskFactors.push(
      `Tor relay network (+6 card): ${torOperatorLabel || asnOrOrg} — relay, not an exit egress`
    );
  } else if (verifiedCrawlerNetwork) {
    // Verified crawler infrastructure is intentional and unweighted.
  } else if (isDatacenterAsn) {
    riskFactors.push(
      `Datacenter / hosting network detected (+3): ${vpnReasons[0] || ispBrand}`
    );
  } else if (hasTzMismatch) {
    riskFactors.push(
      `Browser timezone differs from IP geolocation (+2): ${clientTzCanonical} vs ${ipTzCanonical}`
    );
  }
  if (aiAgent?.detected) {
    riskFactors.push(
      `${aiAgent.agentId === 'impostor-spoof' ? 'Spoofed AI bot impostor (10/10)' : 'AI agent attributed (8/10)'}: ${
        aiAgent.agentName
      } · ${aiAgent.operator} · ${aiAgent.confidence}`
    );
  }
  if (vmScore > 0) {
    // When the VM tile was maxed by the sealed-envelope verdict, the integrity factor below
    // already reports the same evidence — never list one finding twice.
    const duplicatesIntegrityReason =
      integrityViolation && vmSignal.detail === (requestIntegrityReason || 'tampered or replayed payload');
    if (!duplicatesIntegrityReason) {
      riskFactors.push(`Virtual machine / tampered OS (+3): ${vmSignal.detail}`);
    }
  }
  if (isIncognito) {
    riskFactors.push(`Incognito / ephemeral storage (+2): ${incognitoSignal.detail}`);
  }
  if (integrityViolation) {
    riskFactors.push(
      `Sealed request envelope failed verification (+2): ${
        requestIntegrityReason || 'tampered or replayed payload'
      }`
    );
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
      // Phase 1 — bot / AI-agent subtype classification
      botSubtype,
      botProvider: botClassification.provider,
      botCategory: botClassification.category,
      botIdentityConfidence: botClassification.confidence,
      // Phase 2 — Tor exit relay + local abuse blocklist
      torExitNode,
      isTorBrowserClient: clientTorBrowser,
      torVerdict: requestContext.torVerdict ?? (torExitNode ? 'exit' : 'unknown'),
      torOperator:
        requestContext.torOperator ??
        describeTorRelay(location.publicIp) ??
        (torExitNode ? relayOperatorLabel(location) : null),
      aiAgent: requestContext.aiAgent ?? null,
      ipBlocklisted,
      ipBlocklistReasons,
      // Phase 3 — mobile emulator / simulator verdict
      emulatorDetected,
      emulatorReason,
      // Phase 4 — sealed request envelope verdicts
      tamperedRequest,
      replayDetected,
      requestIntegrityReason,
      requestNonce,
      // Task 3 — visit velocity / IP rotation (display only, never scored)
      distinctIpsLastHour: velocity.distinctIpsLastHour,
      visitsLastHour: velocity.visitsLastHour,
    } as Partial<SecuritySignals> & { cloudOrMaskedGpu?: boolean }),
  };
}

app.post('/api/visitor/identify', async (req, res) => {
  try {
    // Start the hourly bulk Tor exit-list refresh immediately so it overlaps the geolocation
    // work below. It is deliberately not awaited: the per-IP DNSEL query is authoritative and
    // fast, and a page load must never wait on a list download.
    void refreshTorBulkList();
    const requestBody = (req.body || {}) as {
      pageLoadId?: string;
      storedVisitorId?: string | null;
      storedVisitorToken?: string | null;
      clientSessionId?: string | null;
      clientHistoryBackup?: SignedHistoryBackup | null;
      browserDevice?: Partial<BrowserDeviceInfo>;
      hardwareSignals?: Partial<HardwareSignals> | null;
      securitySignals?: Partial<SecuritySignals> | null;
      /** Phase 4 — sealed request envelope (timestamp / nonce / signature + JS payload identity). */
      securityEnvelope?: Partial<SecurityEnvelope> | null;
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

    // Phase 2 — the authoritative Tor DNSEL query is started here so its network round trip
    // overlaps the geolocation lookups below instead of being serialized after them. A cold
    // cache costs a DNS query; a warm one resolves from the 10-minute per-IP cache.
    const torLookupPromise: Promise<TorExitVerdict> = resolveTorExitVerdict(extractedIp).catch(
      () => 'unknown' as TorExitVerdict
    );

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

    // Phase 4 — sealed request envelope verification runs BEFORE sanitization so every tile,
    // the composite score and the blocklist see the same verdict.
    const rawRequestHeaders = req.headers as RawHeaderBag;
    const envelopeVerdict = verifySecurityEnvelope({
      envelope: requestBody.securityEnvelope,
      headers: rawRequestHeaders,
      hardwareId,
      nowMs,
    });

    // Phase 1 — bot identity is resolved from the raw headers plus the server network identity.
    // Edge proxies truncate long User-Agent headers, so the signed envelope carries the full UA;
    // fall back to the raw header for older clients. A crawler/automation signature in the raw
    // header always wins so a spoofed envelope cannot mask a bot.
    const headerRequestUserAgent = readRequestHeader(rawRequestHeaders, 'user-agent');
    const envelopeRequestUserAgent =
      typeof requestBody.securityEnvelope?.userAgent === 'string'
        ? requestBody.securityEnvelope.userAgent.trim()
        : '';
    const headerCarriesBotSignature =
      Boolean(headerRequestUserAgent) &&
      (AUTOMATION_UA_PATTERN.test(headerRequestUserAgent) ||
        GOOD_BOT_UA_RULES.some((rule) => rule.pattern.test(headerRequestUserAgent)) ||
        AI_AGENT_UA_RULES.some((rule) => rule.pattern.test(headerRequestUserAgent)));
    const fullRequestUserAgent = headerCarriesBotSignature
      ? headerRequestUserAgent
      : envelopeRequestUserAgent || headerRequestUserAgent;
    const botClassification = classifyBotTraffic(
      { ...rawRequestHeaders, 'user-agent': fullRequestUserAgent },
      { org: location.org, isp: location.isp, asn: location.asn },
      {
        isBot: Boolean(
          rawSecuritySignals?.isBot ||
            rawSecuritySignals?.webdriver ||
            rawSecuritySignals?.cdpDetected
        ),
        isHeadless: Boolean(rawSecuritySignals?.isHeadless),
        webdriver: Boolean(rawSecuritySignals?.webdriver),
        cdpDetected: Boolean(rawSecuritySignals?.cdpDetected),
        botSignals: Array.isArray(rawSecuritySignals?.botSignals)
          ? rawSecuritySignals.botSignals
          : [],
      }
    );

    // Phase 2 — the per-IP DNSEL query started before geolocation is authoritative for the
    // extracted address; if the geo provider reported a different address, that one is checked.
    const torLookupTarget = location.publicIp.trim().toLowerCase();
    const torStatus = await resolveTorExitStatus(
      location.publicIp,
      location,
      torLookupTarget === extractedIp.trim().toLowerCase() ? torLookupPromise : undefined
    );
    const torExitNode = torStatus.isExit;

    // Phase 1b — granular AI-agent attribution. CIDR / FCrDNS / RFC 9421 verification is only
    // attempted when the request actually claims an agent identity, so a normal page load pays
    // no DNS cost.
    const aiAgent = await resolveAiAgentIdentity({
      headers: rawRequestHeaders,
      userAgent: fullRequestUserAgent,
      network: { isp: location.isp, org: location.org, asn: location.asn },
      publicIp: location.publicIp,
      client: {
        isBot: Boolean(rawSecuritySignals?.isBot),
        isHeadless: Boolean(rawSecuritySignals?.isHeadless),
        webdriver: Boolean(rawSecuritySignals?.webdriver),
        cdpDetected: Boolean(rawSecuritySignals?.cdpDetected),
        isVirtualMachine: Boolean(rawSecuritySignals?.isVirtualMachine),
        gpuVendor: hardwareSignals.gpuVendor,
        gpuRenderer: hardwareSignals.gpuRenderer,
        idbDurabilityRatio: rawSecuritySignals?.idbDurabilityRatio ?? null,
        screenResolution: browserDevice.screenResolution,
        platform: browserDevice.platform,
        botSignals: Array.isArray(rawSecuritySignals?.botSignals)
          ? rawSecuritySignals.botSignals
          : [],
      },
    });

    // The attribution engine is authoritative over the generic classifier for AI identities:
    // a named agent replaces the generic label, and a failed official-bot claim becomes a
    // spoofed impostor (10/10) instead of a neutral crawler verdict.
    const attributedBotClassification: BotClassification | null =
      aiAgent.detected && aiAgent.agentId === 'impostor-spoof'
        ? {
            subtype: 'bad_bot',
            label: 'Spoofed AI Bot',
            provider: aiAgent.operator,
            category: 'Spoofed Identity',
            confidence: 0.99,
            reasons: aiAgent.evidence.slice(0, 3),
          }
        : aiAgent.detected && aiAgent.agentId !== null
        ? {
            subtype: 'ai_agent',
            label: aiAgent.agentName,
            provider: aiAgent.operator,
            category: 'AI Agent',
            confidence: aiAgent.verified ? 0.99 : 0.85,
            reasons: aiAgent.evidence.slice(0, 3),
          }
        : null;
    const effectiveBotClassification = attributedBotClassification ?? botClassification;

    // Only cryptographic tampering (modified signed payload) and nonce replay poison the IP
    // ledger. A User-Agent header mismatch is deliberately excluded: edge proxies can rewrite
    // or truncate headers, so it must never blocklist an otherwise normal visitor.
    const signedPayloadTampered = /Payload integrity hash mismatch/i.test(
      envelopeVerdict.requestIntegrityReason
    );
    if (signedPayloadTampered) {
      flagSuspiciousIp(
        location.publicIp,
        envelopeVerdict.requestIntegrityReason || 'Tampered request payload'
      );
    }
    if (envelopeVerdict.replayDetected) {
      flagSuspiciousIp(location.publicIp, 'Replayed payload nonce');
    }
    if (
      effectiveBotClassification.subtype === 'bad_bot' &&
      effectiveBotClassification.label === 'Spoofed Crawler'
    ) {
      flagSuspiciousIp(location.publicIp, 'Spoofed crawler user-agent');
    } else if (aiAgent.agentId === 'impostor-spoof') {
      flagSuspiciousIp(location.publicIp, 'Spoofed AI bot user-agent');
    }
    const blocklist = lookupSuspiciousIp(location.publicIp);

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
      },
      {
        headers: rawRequestHeaders,
        requestUserAgent: fullRequestUserAgent,
        tamperedRequest: envelopeVerdict.tamperedRequest,
        replayDetected: envelopeVerdict.replayDetected,
        requestIntegrityReason: envelopeVerdict.requestIntegrityReason,
        requestNonce: envelopeVerdict.requestNonce,
        torExitNode,
        torRelay: torStatus.isRelay,
        torVerdict: torStatus.verdict,
        torOperator: torStatus.operator,
        torOperatorHint: torStatus.viaOperatorHint,
        clientTorBrowser: Boolean(rawSecuritySignals?.isTorBrowserClient),
        aiAgent,
        ipBlocklisted: blocklist.blocklisted,
        ipBlocklistReasons: blocklist.reasons,
        botClassification: effectiveBotClassification,
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

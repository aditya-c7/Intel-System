import { createRequire as __intelCreateRequire } from 'node:module';
const require = __intelCreateRequire(import.meta.url);

// server.ts
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import net from "net";
import os from "os";
import path from "path";
import fs from "fs";
import { createRequire } from "module";
import dotenv from "dotenv";
dotenv.config();
var PORT = Number(process.env.PORT) || 3e3;
var SESSION_TIMEOUT_MINUTES = 30;
var SESSION_EXPIRATION_MS = SESSION_TIMEOUT_MINUTES * 60 * 1e3;
var IS_SERVERLESS_RUNTIME = Boolean(
  process.env.VERCEL || process.env.VERCEL_ENV || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY
);
var HMAC_SECRET = process.env.VISITOR_HMAC_SECRET || "intel-system-first-party-hmac-secret-2026";
var SPEED_TEST_MAX_TOTAL_DOWNLOAD_BYTES = 1024 * 1024 * 1024;
var SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES = 512 * 1024 * 1024;
var SPEED_TEST_MAX_STREAM_DOWNLOAD_BYTES = 2 * 1024 * 1024;
var SPEED_TEST_MAX_STREAM_UPLOAD_BYTES = 2 * 1024 * 1024;
var SPEED_TEST_CONCURRENT_STREAMS = 6;
var SPEED_TEST_TOKEN_TTL_MS = 120 * 1e3;
var SPEED_TEST_TOKEN_MAX_AGE_MS = 2 * 60 * 60 * 1e3;
var SPEED_TEST_TOKEN_CLOCK_SKEW_MS = 60 * 1e3;
var SPEED_TEST_HMAC_SECRET = process.env.VISITOR_HMAC_SECRET || "intel-system-default-hmac-secret-v1";
var SPEED_TEST_MIN_STREAM_BYTES = 65536;
var SPEED_TEST_STREAM_CHUNK_BYTES = 1024 * 1024;
var SPEED_TEST_REPORTED_CONCURRENT_STREAMS = 2;
var SPEED_TEST_STREAM_TIMEOUT_MS = 25 * 1e3;
var HIGH_ENTROPY_64KB_CHUNK = crypto.randomBytes(65536);
function createInMemoryDbAdapter() {
  const visitorsMap = /* @__PURE__ */ new Map();
  const visitsList = [];
  const geoCacheMap = /* @__PURE__ */ new Map();
  let autoIncrementId = 1;
  return {
    exec: () => {
    },
    prepare: (sql) => {
      const normalized = sql.replace(/\s+/g, " ").trim();
      return {
        get: (...params) => {
          if (normalized.includes("FROM verified_geo_cache_v3 WHERE ip_address = ?")) {
            const ip = String(params[0] || "");
            return geoCacheMap.get(ip);
          }
          if (normalized.includes("SELECT COUNT(*) AS count FROM visitors")) {
            return { count: visitorsMap.size };
          }
          if (normalized.includes("SELECT COUNT(*) AS count FROM visits")) {
            return { count: visitsList.length };
          }
          if (normalized.includes("SELECT * FROM visitors WHERE visitor_id = ?")) {
            const vid = String(params[0] || "");
            return visitorsMap.get(vid);
          }
          if (normalized.includes("SELECT * FROM visitors WHERE hardware_id = ?")) {
            const hwid = String(params[0] || "");
            if (!hwid || !hwid.startsWith("hwid_")) return void 0;
            const matches = Array.from(visitorsMap.values()).filter((v) => v.hardware_id === hwid).sort((a, b) => b.updated_at_utc.localeCompare(a.updated_at_utc));
            return matches[0];
          }
          if (normalized.includes(
            "SELECT session_id, visited_at_utc FROM visits WHERE visitor_id = ? AND page_load_id = ?"
          )) {
            const vid = String(params[0] || "");
            const plId = String(params[1] || "");
            const found = visitsList.find(
              (v) => v.visitor_id === vid && v.page_load_id === plId
            );
            return found ? { session_id: found.session_id, visited_at_utc: found.visited_at_utc } : void 0;
          }
          if (normalized.includes("COUNT(*) AS total_visits") && normalized.includes("FROM visits WHERE visitor_id = ?")) {
            const vid = String(params[0] || "");
            const userVisits = visitsList.filter((v) => v.visitor_id === vid);
            if (userVisits.length === 0) {
              return {
                total_visits: 0,
                first_visit_utc: null,
                last_visit_utc: null,
                total_sessions: 0
              };
            }
            const sortedAsc = [...userVisits].sort(
              (a, b) => a.visited_at_utc.localeCompare(b.visited_at_utc)
            );
            const sessions = new Set(userVisits.map((v) => v.session_id));
            return {
              total_visits: userVisits.length,
              first_visit_utc: sortedAsc[0].visited_at_utc,
              last_visit_utc: sortedAsc[sortedAsc.length - 1].visited_at_utc,
              total_sessions: sessions.size
            };
          }
          if (normalized.includes("LIMIT 1 OFFSET 1")) {
            const vid = String(params[0] || "");
            const userVisits = visitsList.filter((v) => v.visitor_id === vid).sort((a, b) => b.visited_at_utc.localeCompare(a.visited_at_utc) || b.id - a.id);
            return userVisits.length > 1 ? { visited_at_utc: userVisits[1].visited_at_utc } : void 0;
          }
          return void 0;
        },
        all: (...params) => {
          if (normalized.includes("FROM visits WHERE visitor_id = ?")) {
            const vid = String(params[0] || "");
            return visitsList.filter((v) => v.visitor_id === vid).sort((a, b) => b.visited_at_utc.localeCompare(a.visited_at_utc) || b.id - a.id).slice(0, 50);
          }
          return [];
        },
        run: (...params) => {
          if (normalized.includes("INSERT OR REPLACE INTO verified_geo_cache_v3")) {
            const row = {
              ip_address: String(params[0] || ""),
              city: String(params[1] || "Unknown"),
              region: String(params[2] || "Unknown"),
              country: String(params[3] || "Unknown"),
              country_code: String(params[4] || ""),
              latitude: typeof params[5] === "number" ? params[5] : null,
              longitude: typeof params[6] === "number" ? params[6] : null,
              isp: String(params[7] || "Unknown"),
              org: String(params[8] || "Unknown"),
              asn: String(params[9] || "Unknown"),
              is_vpn_or_hosting: Number(params[10] || 0),
              verified_at_ms: Number(params[11] || Date.now())
            };
            geoCacheMap.set(row.ip_address, row);
            return { changes: 1 };
          }
          if (normalized.includes("INSERT INTO visitors") || normalized.includes("INSERT OR REPLACE INTO visitors")) {
            const hasHwCol = normalized.includes("hardware_id");
            const row = hasHwCol ? {
              visitor_id: String(params[0] || ""),
              hmac_token: String(params[1] || ""),
              hardware_id: String(params[2] || ""),
              created_at_utc: String(params[3] || ""),
              updated_at_utc: String(params[4] || ""),
              active_session_id: String(params[5] || ""),
              last_activity_utc: String(params[6] || "")
            } : {
              visitor_id: String(params[0] || ""),
              hmac_token: String(params[1] || ""),
              hardware_id: "",
              created_at_utc: String(params[2] || ""),
              updated_at_utc: String(params[3] || ""),
              active_session_id: String(params[4] || ""),
              last_activity_utc: String(params[5] || "")
            };
            visitorsMap.set(row.visitor_id, row);
            return { changes: 1 };
          }
          if (normalized.includes("UPDATE visitors")) {
            const hasHwUpdate = normalized.includes("hardware_id = ?");
            const vid = String(hasHwUpdate ? params[4] : params[3] || "");
            const existing = visitorsMap.get(vid);
            if (existing) {
              existing.updated_at_utc = String(params[0] || existing.updated_at_utc);
              existing.active_session_id = String(params[1] || existing.active_session_id);
              existing.last_activity_utc = String(params[2] || existing.last_activity_utc);
              if (hasHwUpdate && typeof params[3] === "string" && params[3]) {
                existing.hardware_id = params[3];
              }
              return { changes: 1 };
            }
            return { changes: 0 };
          }
          if (normalized.includes("INSERT OR IGNORE INTO visits")) {
            const visitId = String(params[0] || "");
            const visitorId = String(params[1] || "");
            const pageLoadId = String(params[3] || "");
            const duplicate = visitsList.some(
              (v) => v.visit_id === visitId || v.visitor_id === visitorId && v.page_load_id === pageLoadId
            );
            if (duplicate) {
              return { changes: 0 };
            }
            visitsList.push({
              id: autoIncrementId++,
              visit_id: visitId,
              visitor_id: visitorId,
              session_id: String(params[2] || ""),
              page_load_id: pageLoadId,
              visited_at_utc: String(params[4] || ""),
              public_ip: String(params[5] || "Unavailable"),
              city: String(params[6] || "Unknown"),
              region: String(params[7] || "Unknown"),
              country: String(params[8] || "Unknown"),
              latitude: typeof params[9] === "number" ? params[9] : null,
              longitude: typeof params[10] === "number" ? params[10] : null,
              isp: String(params[11] || "Unknown"),
              org: String(params[12] || "Unknown"),
              asn: String(params[13] || "Unknown"),
              browser: String(params[14] || "Unknown"),
              os: String(params[15] || "Unknown"),
              device_type: String(params[16] || "Unknown"),
              screen_resolution: String(params[17] || "Unavailable"),
              language: String(params[18] || "Unavailable"),
              timezone: String(params[19] || "Unavailable")
            });
            return { changes: 1 };
          }
          return { changes: 0 };
        }
      };
    }
  };
}
function initializeDatabase() {
  if (process.env.INTEL_FORCE_MEMORY_DB === "1") {
    return createInMemoryDbAdapter();
  }
  let targetDir = path.join(os.tmpdir(), "intel-system-data");
  if (!IS_SERVERLESS_RUNTIME) {
    try {
      const localDataDir = path.resolve(process.cwd(), "data");
      if (!fs.existsSync(localDataDir)) {
        fs.mkdirSync(localDataDir, { recursive: true });
      }
      fs.accessSync(localDataDir, fs.constants.W_OK);
      targetDir = localDataDir;
    } catch {
      targetDir = path.join(os.tmpdir(), "intel-system-data");
    }
  }
  try {
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }
    const dbPath = path.join(targetDir, "intel_system.db");
    const requireModule = createRequire(import.meta.url);
    const BetterSqlite3 = requireModule("better-sqlite3");
    const sqliteDb = new BetterSqlite3(dbPath);
    sqliteDb.pragma("journal_mode = WAL");
    sqliteDb.pragma("foreign_keys = ON");
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
    }
    try {
      sqliteDb.exec(`CREATE INDEX IF NOT EXISTS idx_visitors_hwid ON visitors(hardware_id)`);
    } catch {
    }
    for (const col of ["isp", "org", "asn"]) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} TEXT NOT NULL DEFAULT 'Unknown'`);
      } catch {
      }
    }
    for (const col of ["latitude", "longitude"]) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} REAL`);
      } catch {
      }
      try {
        sqliteDb.exec(`ALTER TABLE verified_geo_cache_v3 ADD COLUMN ${col} REAL`);
      } catch {
      }
    }
    return sqliteDb;
  } catch {
    return createInMemoryDbAdapter();
  }
}
var db = initializeDatabase();
function signVisitorId(visitorId) {
  return crypto.createHmac("sha256", HMAC_SECRET).update(visitorId).digest("hex");
}
function verifyVisitorToken(visitorId, token) {
  if (!visitorId || !token || typeof visitorId !== "string" || typeof token !== "string") {
    return false;
  }
  const expected = signVisitorId(visitorId);
  if (expected.length !== token.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(token, "hex"));
  } catch {
    return false;
  }
}
function computeHistoryBackupSignature(visitorId, totalVisits, totalSessions, firstVisitUtc, visits) {
  const visitDigest = visits.map((v) => `${v.visitId}:${v.sessionId}:${v.visitedAtUtc}:${v.publicIp}`).join("|");
  const payload = `hist:${visitorId}:${totalVisits}:${totalSessions}:${firstVisitUtc}:${visitDigest}`;
  return crypto.createHmac("sha256", HMAC_SECRET).update(payload).digest("hex");
}
function createSignedHistoryBackup(visitorId, totalVisits, totalSessions, firstVisitUtc, visits, hardwareId) {
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
    signature
  };
}
function verifySignedHistoryBackup(expectedVisitorId, backup) {
  if (!backup || typeof backup !== "object" || backup.visitorId !== expectedVisitorId || typeof backup.signature !== "string" || typeof backup.totalVisits !== "number" || typeof backup.totalSessions !== "number" || typeof backup.firstVisitUtc !== "string" || !Array.isArray(backup.visits)) {
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
      Buffer.from(expectedSig, "hex"),
      Buffer.from(backup.signature, "hex")
    );
  } catch {
    return false;
  }
}
function generateVisitorId() {
  return "vid_" + crypto.randomBytes(10).toString("hex");
}
function generateSessionId() {
  return "ses_" + crypto.randomBytes(6).toString("hex");
}
function generateVisitId() {
  return "vst_" + crypto.randomBytes(8).toString("hex");
}
function normalizeIpCandidate(raw) {
  if (!raw || typeof raw !== "string") return null;
  let candidate = raw.trim().replace(/^["']|["']$/g, "");
  if (!candidate) return null;
  if (candidate.toLowerCase().startsWith("for=")) {
    candidate = candidate.slice(4).trim().replace(/^["']|["']$/g, "");
  }
  if (candidate.startsWith("[")) {
    const closeBracket = candidate.indexOf("]");
    if (closeBracket !== -1) {
      candidate = candidate.slice(1, closeBracket);
    }
  } else {
    const colonCount = (candidate.match(/:/g) || []).length;
    if (colonCount === 1 && candidate.includes(".")) {
      candidate = candidate.split(":")[0];
    }
  }
  if (candidate.toLowerCase().startsWith("::ffff:")) {
    candidate = candidate.slice(7);
  }
  const zoneIdx = candidate.indexOf("%");
  if (zoneIdx !== -1) {
    candidate = candidate.slice(0, zoneIdx);
  }
  const ipVersion = net.isIP(candidate);
  if (ipVersion === 0) return null;
  return candidate;
}
function isPublicRoutableIp(ip) {
  if (!ip) return false;
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split(".").map((n) => parseInt(n, 10));
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
    if (lower === "::1" || lower === "::" || lower === "0:0:0:0:0:0:0:1" || lower === "0:0:0:0:0:0:0:0") {
      return false;
    }
    if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) {
      return false;
    }
    if (lower.startsWith("fc") || lower.startsWith("fd")) {
      return false;
    }
    if (lower.startsWith("ff")) {
      return false;
    }
    return true;
  }
  return false;
}
function extractVisitorIp(req) {
  const singleHeaders = [
    "x-vercel-forwarded-for",
    "x-vercel-proxied-for",
    "cf-connecting-ip",
    "true-client-ip",
    "x-real-ip",
    "x-client-ip",
    "x-appengine-user-ip"
  ];
  for (const headerName of singleHeaders) {
    const rawVal = req.headers[headerName];
    if (typeof rawVal === "string" && rawVal.trim()) {
      const firstHop = rawVal.split(",")[0];
      const normalized = normalizeIpCandidate(firstHop);
      if (normalized && isPublicRoutableIp(normalized)) {
        return { ip: normalized, isPublic: true };
      }
    }
  }
  const xff = req.headers["x-forwarded-for"];
  const xffList = Array.isArray(xff) ? xff.join(",") : typeof xff === "string" ? xff : "";
  if (xffList) {
    const hops = xffList.split(",");
    for (const hop of hops) {
      const normalized = normalizeIpCandidate(hop);
      if (normalized && isPublicRoutableIp(normalized)) {
        return { ip: normalized, isPublic: true };
      }
    }
  }
  const forwarded = req.headers["forwarded"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    const segments = forwarded.split(/[,;]/);
    for (const seg of segments) {
      if (seg.trim().toLowerCase().startsWith("for=")) {
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
  return { ip: "Unavailable", isPublic: false };
}
function normalizeIspAndOrg(rawIspInput, rawOrgInput, rawAsnInput, explicitHostingOrVpnFlag = false) {
  let cleanIsp = typeof rawIspInput === "string" ? rawIspInput.trim() : "";
  let cleanOrg = typeof rawOrgInput === "string" ? rawOrgInput.trim() : "";
  let cleanAsn = "";
  if (typeof rawAsnInput === "number" && Number.isFinite(rawAsnInput)) {
    cleanAsn = `AS${rawAsnInput}`;
  } else if (typeof rawAsnInput === "string" && rawAsnInput.trim()) {
    const trimmedAsn = rawAsnInput.trim();
    cleanAsn = /^AS\d+/i.test(trimmedAsn) ? trimmedAsn.toUpperCase() : `AS${trimmedAsn}`;
  }
  const stripEmbeddedAsn = (text) => {
    const match = text.match(/^(AS\d+)\s+(.+)$/i);
    if (match) {
      return { asnFound: match[1].toUpperCase(), rest: match[2].trim() };
    }
    return { asnFound: "", rest: text };
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
  if (!combinedSource || combinedSource.toLowerCase() === "unknown") {
    return {
      isp: "Unknown",
      org: "Unknown",
      asn: cleanAsn || "Unknown",
      isVpnOrHosting: explicitHostingOrVpnFlag
    };
  }
  const lower = combinedSource.toLowerCase();
  let recognizableBrand = null;
  if (/\bjio\b|reliance jio/i.test(combinedSource)) {
    recognizableBrand = "Jio";
  } else if (/\bairtel\b|bharti airtel|bharti hexacom/i.test(combinedSource)) {
    recognizableBrand = "Airtel";
  } else if (/\bbsnl\b|bharat sanchar|national internet backbone/i.test(combinedSource)) {
    recognizableBrand = "BSNL";
  } else if (/\bact\b|act fibernet|atria convergence|beam telecom/i.test(combinedSource)) {
    recognizableBrand = "ACT";
  } else if (/vodafone idea|\bvodafone\b|\bidea cellular\b/i.test(combinedSource)) {
    recognizableBrand = "Vodafone Idea";
  } else if (/tata play fiber|tata teleservices|tata communications/i.test(combinedSource)) {
    recognizableBrand = "Tata";
  } else if (/\bhathway\b/i.test(combinedSource)) {
    recognizableBrand = "Hathway";
  } else if (/\bexcitel\b/i.test(combinedSource)) {
    recognizableBrand = "Excitel";
  } else if (/\bmtnl\b|mahanagar telephone/i.test(combinedSource)) {
    recognizableBrand = "MTNL";
  } else if (/\brailwire\b|\brailtel\b/i.test(combinedSource)) {
    recognizableBrand = "RailWire";
  } else if (/\byou broadband\b/i.test(combinedSource)) {
    recognizableBrand = "YOU Broadband";
  } else if (/\basianet\b/i.test(combinedSource)) {
    recognizableBrand = "Asianet";
  } else if (/\balliance broadband\b/i.test(combinedSource)) {
    recognizableBrand = "Alliance Broadband";
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
    "google",
    "gcp",
    "as15169",
    "as396982",
    "mullvad",
    "nordvpn",
    "expressvpn",
    "protonvpn",
    "surfshark",
    "cyberghost",
    "m247",
    "datacamp",
    "tzulo",
    "digitalocean",
    "linode",
    "vultr",
    "choopa",
    "hetzner",
    "ovh",
    "leaseweb",
    "amazon",
    "aws",
    "cloudflare",
    "microsoft corporation",
    "azure",
    "oracle",
    "akamai",
    "fastly",
    "zscaler",
    "netskope",
    "palo alto networks"
  ];
  const asnAndSourceLower = `${lower} ${(cleanAsn || "").toLowerCase()}`;
  const isVpnOrHosting = explicitHostingOrVpnFlag || hostingOrVpnKeywords.some((kw) => asnAndSourceLower.includes(kw));
  return {
    isp: formattedIsp || "Unknown",
    org: cleanOrg || cleanIsp || "Unknown",
    asn: cleanAsn || "Unknown",
    isVpnOrHosting
  };
}
async function lookupVerifiedGeolocation(visitorIp, isPublic) {
  if (!isPublic || !visitorIp || visitorIp === "Unavailable") {
    return {
      publicIp: "Unavailable",
      city: "Unavailable",
      region: "Unavailable",
      country: "Unavailable",
      countryCode: "",
      latitude: null,
      longitude: null,
      isp: "Unknown",
      org: "Unknown",
      asn: "Unknown",
      isVpnOrHosting: false,
      isIpVerified: false,
      isLocationVerified: false
    };
  }
  const nowMs = Date.now();
  const cached = db.prepare(
    "SELECT city, region, country, country_code, latitude, longitude, isp, org, asn, is_vpn_or_hosting, verified_at_ms FROM verified_geo_cache_v3 WHERE ip_address = ?"
  ).get(visitorIp);
  if (cached && nowMs - cached.verified_at_ms < 6 * 3600 * 1e3 && cached.isp !== "Unknown" && typeof cached.latitude === "number" && typeof cached.longitude === "number") {
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
      isLocationVerified: cached.city !== "Unavailable" || cached.country !== "Unavailable"
    };
  }
  const cleanField = (val) => {
    if (typeof val !== "string") return "Unknown";
    const trimmed = val.trim();
    return trimmed.length > 0 ? trimmed : "Unknown";
  };
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3e3);
    const resp = await fetch(`https://ipwho.is/${encodeURIComponent(visitorIp)}`, {
      signal: controller.signal,
      headers: { Accept: "application/json", "User-Agent": "IntelSystem/1.0" }
    });
    clearTimeout(timer);
    if (resp.ok) {
      const data = await resp.json();
      const providerIp = normalizeIpCandidate(typeof data.ip === "string" ? data.ip : "");
      if (data.success !== false && providerIp && providerIp.toLowerCase() === visitorIp.toLowerCase()) {
        const city = cleanField(data.city);
        const region = cleanField(data.region);
        const country = cleanField(data.country);
        const countryCode = typeof data.country_code === "string" ? data.country_code.trim() : "";
        const latitude = typeof data.latitude === "number" && Number.isFinite(data.latitude) ? data.latitude : null;
        const longitude = typeof data.longitude === "number" && Number.isFinite(data.longitude) ? data.longitude : null;
        const conn = data.connection || {};
        const sec = data.security || {};
        const explicitVpn = Boolean(sec.vpn || sec.proxy || sec.tor || sec.hosting);
        const netDetails = normalizeIspAndOrg(conn.isp, conn.org, conn.asn, explicitVpn);
        if (city !== "Unknown" || country !== "Unknown" || netDetails.isp !== "Unknown") {
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
            isLocationVerified: city !== "Unknown" || country !== "Unknown"
          };
        }
      }
    }
  } catch {
  }
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3e3);
    const resp = await fetch(`https://ipapi.co/${encodeURIComponent(visitorIp)}/json/`, {
      signal: controller.signal,
      headers: { Accept: "application/json", "User-Agent": "IntelSystem/1.0" }
    });
    clearTimeout(timer);
    if (resp.ok) {
      const data = await resp.json();
      const providerIp = normalizeIpCandidate(typeof data.ip === "string" ? data.ip : "");
      if (!data.error && providerIp && providerIp.toLowerCase() === visitorIp.toLowerCase()) {
        const city = cleanField(data.city);
        const region = cleanField(data.region);
        const country = cleanField(data.country_name || data.country);
        const countryCode = typeof data.country_code === "string" ? data.country_code.trim() : "";
        const latitude = typeof data.latitude === "number" && Number.isFinite(data.latitude) ? data.latitude : null;
        const longitude = typeof data.longitude === "number" && Number.isFinite(data.longitude) ? data.longitude : null;
        const netDetails = normalizeIspAndOrg(data.org, data.org, data.asn, false);
        if (city !== "Unknown" || country !== "Unknown" || netDetails.isp !== "Unknown") {
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
            isLocationVerified: city !== "Unknown" || country !== "Unknown"
          };
        }
      }
    }
  } catch {
  }
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3e3);
    const resp = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(visitorIp)}`, {
      signal: controller.signal,
      headers: { Accept: "application/json", "User-Agent": "IntelSystem/1.0" }
    });
    clearTimeout(timer);
    if (resp.ok) {
      const data = await resp.json();
      const providerIp = normalizeIpCandidate(typeof data.ipAddress === "string" ? data.ipAddress : "");
      if (providerIp && providerIp.toLowerCase() === visitorIp.toLowerCase()) {
        const city = cleanField(data.cityName);
        const region = cleanField(data.regionName);
        const country = cleanField(data.countryName);
        const countryCode = typeof data.countryCode === "string" ? data.countryCode.trim() : "";
        const latitude = typeof data.latitude === "number" && Number.isFinite(data.latitude) ? data.latitude : null;
        const longitude = typeof data.longitude === "number" && Number.isFinite(data.longitude) ? data.longitude : null;
        const netDetails = normalizeIspAndOrg(
          data.asnOrganization,
          data.asnOrganization,
          data.asn,
          Boolean(data.isProxy)
        );
        if (city !== "Unknown" || country !== "Unknown" || netDetails.isp !== "Unknown") {
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
            isLocationVerified: city !== "Unknown" || country !== "Unknown"
          };
        }
      }
    }
  } catch {
  }
  return {
    publicIp: visitorIp,
    city: "Unavailable",
    region: "Unavailable",
    country: "Unavailable",
    countryCode: "",
    latitude: null,
    longitude: null,
    isp: "Unknown",
    org: "Unknown",
    asn: "Unknown",
    isVpnOrHosting: false,
    isIpVerified: true,
    isLocationVerified: false
  };
}
function sanitizeBrowserDevice(input) {
  const safeStr = (val, fallback) => {
    if (typeof val !== "string") return fallback;
    const t = val.trim();
    return t.length > 0 ? t.slice(0, 120) : fallback;
  };
  const validDeviceTypes = ["Desktop", "Mobile", "Tablet", "Unknown"];
  const rawType = input?.deviceType;
  const deviceType = rawType && validDeviceTypes.includes(rawType) ? rawType : "Unknown";
  return {
    browser: safeStr(input?.browser, "Unknown"),
    os: safeStr(input?.os, "Unknown"),
    deviceType,
    platform: safeStr(input?.platform, "Unavailable"),
    screenResolution: safeStr(input?.screenResolution, "Unavailable"),
    pixelRatio: safeStr(input?.pixelRatio, "Unavailable"),
    language: safeStr(input?.language, "Unavailable"),
    timezone: safeStr(input?.timezone, "Unavailable")
  };
}
var activeSpeedTests = /* @__PURE__ */ new Map();
var visitorTestTimestamps = /* @__PURE__ */ new Map();
var sessionTestCounts = /* @__PURE__ */ new Map();
var ipTestTimestamps = /* @__PURE__ */ new Map();
var RATE_WINDOW_MS = 10 * 60 * 1e3;
var MAX_TESTS_PER_VISITOR_WINDOW = 120;
var MAX_TESTS_PER_SESSION = 1e3;
var MAX_TESTS_PER_IP_WINDOW = 360;
var MAX_CONCURRENT_TESTS_PER_IP = 8;
var MAX_CONCURRENT_TESTS_PER_INSTANCE = 24;
function detectServerRegion(req) {
  const envRegion = process.env.VERCEL_REGION || process.env.CLOUD_RUN_REGION || "";
  const appUrl = process.env.APP_URL || "";
  const vercelIdHeader = req ? String(req.headers["x-vercel-id"] || "") : "";
  const hostHeader = req ? String(req.headers["x-forwarded-host"] || req.headers.host || "") : "";
  const combined = `${envRegion} ${vercelIdHeader} ${appUrl} ${hostHeader}`.toLowerCase();
  const regionNames = {
    "bom1": "bom1 (Mumbai, India)",
    "sin1": "sin1 (Singapore)",
    "hnd1": "hnd1 (Tokyo, Japan)",
    "icn1": "icn1 (Seoul, South Korea)",
    "syd1": "syd1 (Sydney, Australia)",
    "fra1": "fra1 (Frankfurt, Germany)",
    "lhr1": "lhr1 (London, UK)",
    "cdg1": "cdg1 (Paris, France)",
    "iad1": "iad1 (Washington, D.C., USA)",
    "sfo1": "sfo1 (San Francisco, USA)",
    "pdx1": "pdx1 (Portland, USA)",
    "cle1": "cle1 (Cleveland, USA)",
    "gru1": "gru1 (Sao Paulo, Brazil)",
    "asia-southeast1": "asia-southeast1 (Singapore)",
    "asia-south1": "asia-south1 (Mumbai, India)",
    "asia-south2": "asia-south2 (Delhi, India)",
    "asia-east1": "asia-east1 (Taiwan)",
    "asia-northeast1": "asia-northeast1 (Tokyo, Japan)",
    "europe-west1": "europe-west1 (Belgium)",
    "europe-west2": "europe-west2 (London, UK)",
    "us-central1": "us-central1 (Iowa, USA)",
    "us-east1": "us-east1 (South Carolina, USA)",
    "us-west1": "us-west1 (Oregon, USA)"
  };
  for (const [code, label] of Object.entries(regionNames)) {
    if (combined.includes(code)) {
      return { regionCode: code, regionLabel: label };
    }
  }
  return {
    regionCode: "global-edge",
    regionLabel: "Global Edge Network"
  };
}
function pruneSpeedTestState(nowMs) {
  for (const [testId, ledger] of activeSpeedTests.entries()) {
    if (nowMs > ledger.expiresAtMs || ledger.completed && nowMs - ledger.createdAtMs > 5e3) {
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
var SPEED_TEST_STATELESS_TOKEN_PATTERN = /^st_(\d{10,17})_([0-9a-fA-F]{64})$/;
function createSignedSpeedTestToken() {
  const issuedAtMs = Date.now();
  const hmacHex = crypto.createHmac("sha256", SPEED_TEST_HMAC_SECRET).update(String(issuedAtMs)).digest("hex");
  return `st_${issuedAtMs}_${hmacHex}`;
}
function verifySpeedTestToken(rawToken) {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  const match = SPEED_TEST_STATELESS_TOKEN_PATTERN.exec(token);
  if (!match) {
    return { valid: false, issuedAtMs: 0, fresh: false };
  }
  const issuedAtMs = Number.parseInt(match[1], 10);
  if (!Number.isFinite(issuedAtMs) || issuedAtMs <= 0) {
    return { valid: false, issuedAtMs: 0, fresh: false };
  }
  const nowMs = Date.now();
  const fresh = issuedAtMs <= nowMs + SPEED_TEST_TOKEN_CLOCK_SKEW_MS && nowMs - issuedAtMs <= SPEED_TEST_TOKEN_MAX_AGE_MS;
  const expectedHex = crypto.createHmac("sha256", SPEED_TEST_HMAC_SECRET).update(String(issuedAtMs)).digest("hex");
  const providedHex = match[2].toLowerCase();
  const valid = providedHex.length === expectedHex.length && crypto.timingSafeEqual(Buffer.from(providedHex, "utf8"), Buffer.from(expectedHex, "utf8"));
  return { valid, issuedAtMs, fresh };
}
function createStatelessSpeedTestLedger(testId, tokenKey, visitorKey, ipKey, nowMs) {
  const statelessLedger = {
    testId,
    visitorKey,
    sessionKey: visitorKey,
    ipKey,
    createdAtMs: nowMs,
    expiresAtMs: nowMs + SPEED_TEST_TOKEN_TTL_MS,
    downloadedBytes: 0,
    uploadedBytes: 0,
    activeStreams: 0,
    completed: false
  };
  activeSpeedTests.set(tokenKey, statelessLedger);
  return statelessLedger;
}
function verifyAndGetSpeedTestLedger(rawToken, visitorKey, ipKey) {
  const nowMs = Date.now();
  const cleanedToken = typeof rawToken === "string" ? rawToken.trim() : "";
  if (cleanedToken) {
    const directLedger = activeSpeedTests.get(cleanedToken) || activeSpeedTests.get(cleanedToken.split(".")[0]);
    if (directLedger && !directLedger.completed) {
      return { valid: true, ledger: directLedger };
    }
  }
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
  if (cleanedToken && cleanedToken.startsWith("st_")) {
    const parts = cleanedToken.split(".");
    const testId = parts[0];
    if (parts.length === 4) {
      const [, expStr, vHash, providedSig] = parts;
      const expiresAtMs = parseInt(expStr, 10);
      if (!Number.isNaN(expiresAtMs) && nowMs <= expiresAtMs + 5 * 60 * 1e3) {
        const payload = `${testId}.${expiresAtMs}.${vHash}`;
        const expectedSig = crypto.createHmac("sha256", HMAC_SECRET).update(`speedtest:${payload}`).digest("hex").slice(0, 24);
        if (providedSig.length === expectedSig.length && crypto.timingSafeEqual(Buffer.from(providedSig), Buffer.from(expectedSig))) {
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
  return { valid: false, reason: "Invalid or missing speed test authorization token." };
}
var app = express();
app.set("trust proxy", true);
app.use(cookieParser());
app.use((_req, res, next) => {
  res.setHeader("Permissions-Policy", "compute-pressure=*");
  next();
});
var firstHeaderValue = (value) => {
  const raw = Array.isArray(value) ? value[0] : value;
  return typeof raw === "string" ? raw : "";
};
var handleNetworkHeadPing = (_req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Timing-Allow-Origin", "*");
  res.status(200).end();
};
var handleNetworkPing = (_req, res) => {
  const serverTimestamp = Date.now();
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Timing-Allow-Origin", "*");
  res.status(200).json({ ok: true, serverTimestamp, serverTimestampMs: serverTimestamp });
};
app.head("/api/network/ping", handleNetworkHeadPing);
app.get("/api/network/ping", handleNetworkPing);
app.get("/api/network/download", (req, res) => {
  const nowMs = Date.now();
  pruneSpeedTestState(nowMs);
  const token = (typeof req.query.token === "string" ? req.query.token : "") || firstHeaderValue(req.headers["x-speed-test-token"]) || firstHeaderValue(req.headers["x-speedtest-token"]);
  const { ip: extractedIp } = extractVisitorIp(req);
  const visitorKey = req.cookies?.intel_http_vid || extractedIp || "anon";
  const verification = verifyAndGetSpeedTestLedger(token, visitorKey, extractedIp);
  if (!verification.valid || !verification.ledger) {
    res.status(403).json({ error: verification.reason || "Unauthorized speed test request." });
    return;
  }
  const ledger = verification.ledger;
  if (ledger.activeStreams >= SPEED_TEST_CONCURRENT_STREAMS + 6) {
    res.status(429).json({ error: "Concurrent stream limit exceeded for this speed test." });
    return;
  }
  const remainingBudget = SPEED_TEST_MAX_TOTAL_DOWNLOAD_BYTES - ledger.downloadedBytes;
  if (remainingBudget <= 0) {
    res.status(429).json({ error: "Maximum download transfer limit reached for this test." });
    return;
  }
  const headerBytes = Number(req.headers["x-speedtest-bytes"]);
  const requestedBytes = Number.isFinite(headerBytes) && headerBytes > 0 ? Math.floor(headerBytes) : parseInt(String(req.query.bytes || SPEED_TEST_STREAM_CHUNK_BYTES), 10);
  const clampedRequest = Number.isNaN(requestedBytes) ? SPEED_TEST_STREAM_CHUNK_BYTES : Math.max(
    SPEED_TEST_MIN_STREAM_BYTES,
    Math.min(SPEED_TEST_MAX_STREAM_DOWNLOAD_BYTES, requestedBytes)
  );
  const targetBytes = Math.min(clampedRequest, remainingBudget);
  const streamBuffer = Buffer.allocUnsafe(targetBytes);
  for (let offset = 0; offset < targetBytes; offset += HIGH_ENTROPY_64KB_CHUNK.length) {
    const toFill = Math.min(HIGH_ENTROPY_64KB_CHUNK.length, targetBytes - offset);
    HIGH_ENTROPY_64KB_CHUNK.copy(streamBuffer, offset, 0, toFill);
  }
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Encoding", "identity");
  res.setHeader("Content-Length", String(targetBytes));
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate, no-transform"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Timing-Allow-Origin", "*");
  res.setHeader("X-Accel-Buffering", "no");
  ledger.activeStreams += 1;
  let streamClosed = false;
  const cleanupStream = () => {
    if (streamClosed) return;
    streamClosed = true;
    ledger.activeStreams = Math.max(0, ledger.activeStreams - 1);
  };
  req.on("close", cleanupStream);
  res.on("close", cleanupStream);
  res.on("error", cleanupStream);
  res.on("finish", cleanupStream);
  ledger.downloadedBytes += targetBytes;
  res.end(streamBuffer);
});
var speedTestUploadRawParser = express.raw({ type: "*/*", limit: "4mb" });
var speedTestUploadBodyGuard = (req, res, next) => {
  let platformBody;
  try {
    platformBody = req.body;
  } catch {
    platformBody = void 0;
  }
  if (platformBody !== void 0 && platformBody !== null && (Buffer.isBuffer(platformBody) || typeof platformBody === "string" || platformBody instanceof Uint8Array)) {
    next();
    return;
  }
  if (req.readableEnded || req.complete) {
    next();
    return;
  }
  speedTestUploadRawParser(req, res, (parseError) => {
    if (parseError) {
      if (!res.headersSent) {
        res.status(413).json({
          ok: false,
          error: "Upload payload exceeds the 4 MB route limit.",
          receivedBytes: 0
        });
      }
      return;
    }
    next();
  });
};
app.post("/api/network/upload", speedTestUploadBodyGuard, (req, res) => {
  const nowMs = Date.now();
  pruneSpeedTestState(nowMs);
  let platformBufferedBody = null;
  try {
    const candidate = req.body;
    if (Buffer.isBuffer(candidate)) {
      platformBufferedBody = candidate;
    } else if (candidate instanceof Uint8Array) {
      platformBufferedBody = Buffer.from(candidate);
    } else if (typeof candidate === "string" && candidate.length > 0) {
      platformBufferedBody = Buffer.from(candidate, "utf8");
    }
  } catch {
    platformBufferedBody = null;
  }
  const token = (typeof req.query.token === "string" ? req.query.token : "") || firstHeaderValue(req.headers["x-speed-test-token"]) || firstHeaderValue(req.headers["x-speedtest-token"]);
  const { ip: extractedIp } = extractVisitorIp(req);
  const visitorKey = req.cookies?.intel_http_vid || extractedIp || "anon";
  const verification = verifyAndGetSpeedTestLedger(token, visitorKey, extractedIp);
  const ledger = verification.valid ? verification.ledger : void 0;
  const bumpActiveStreams = (delta) => {
    if (!ledger) return;
    ledger.activeStreams = Math.max(0, ledger.activeStreams + delta);
  };
  const contentLengthHeader = parseInt(String(req.headers["content-length"] || "0"), 10);
  if (platformBufferedBody || req.readableEnded || req.complete) {
    const receivedBytes = platformBufferedBody ? platformBufferedBody.byteLength : Number.isFinite(contentLengthHeader) && contentLengthHeader > 0 ? Math.min(contentLengthHeader, SPEED_TEST_MAX_STREAM_UPLOAD_BYTES) : 0;
    if (receivedBytes > SPEED_TEST_MAX_STREAM_UPLOAD_BYTES || ledger && ledger.uploadedBytes + receivedBytes > SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES) {
      res.status(413).json({
        ok: false,
        error: "Upload transfer limit exceeded.",
        receivedBytes: 0
      });
      return;
    }
    if (ledger) {
      ledger.uploadedBytes += receivedBytes;
    }
    const reportedTimestamp = Date.now();
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.status(200).json({
      ok: true,
      receivedBytes,
      totalTestUploadedBytes: ledger ? ledger.uploadedBytes : receivedBytes,
      elapsedServerMs: 1,
      serverTimestamp: reportedTimestamp,
      serverTimestampMs: reportedTimestamp
    });
    return;
  }
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Timing-Allow-Origin", "*");
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
        error: "Upload stream timed out.",
        receivedBytes: streamReceivedBytes
      });
    }
  }, SPEED_TEST_STREAM_TIMEOUT_MS);
  req.on("data", (chunk) => {
    if (finished || exceededCap) return;
    const chunkLen = chunk.length;
    if (streamReceivedBytes + chunkLen > SPEED_TEST_MAX_STREAM_UPLOAD_BYTES || ledger && ledger.uploadedBytes + chunkLen > SPEED_TEST_MAX_TOTAL_UPLOAD_BYTES) {
      exceededCap = true;
      cleanupUpload();
      req.resume();
      if (!res.headersSent) {
        res.status(413).json({
          ok: false,
          error: "Upload transfer limit exceeded.",
          receivedBytes: streamReceivedBytes
        });
      }
      return;
    }
    streamReceivedBytes += chunkLen;
    if (ledger) {
      ledger.uploadedBytes += chunkLen;
    }
  });
  req.on("end", () => {
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
      serverTimestampMs: reportedTimestamp
    });
  });
  req.on("aborted", () => {
    cleanupUpload();
  });
  req.on("error", () => {
    cleanupUpload();
  });
});
app.use(express.json({ limit: "512kb" }));
app.post("/api/network/speed-test/init", (req, res) => {
  const nowMs = Date.now();
  pruneSpeedTestState(nowMs);
  const { ip: extractedIp } = extractVisitorIp(req);
  const body = req.body || {};
  const cookieVid = req.cookies?.intel_http_vid;
  const visitorKey = cookieVid || typeof body.visitorId === "string" && body.visitorId.trim() || extractedIp || "anon";
  const sessionKey = typeof body.sessionId === "string" && body.sessionId.trim() || visitorKey;
  const ipKey = extractedIp && extractedIp !== "Unavailable" ? extractedIp : visitorKey;
  for (const [ledgerKey, ledger] of activeSpeedTests.entries()) {
    if (ledger.ipKey === ipKey || ledger.visitorKey === visitorKey) {
      activeSpeedTests.delete(ledgerKey);
    }
  }
  let activeCount = 0;
  let activeIpCount = 0;
  const seenTestIds = /* @__PURE__ */ new Set();
  for (const [, ledger] of activeSpeedTests.entries()) {
    if (seenTestIds.has(ledger.testId)) continue;
    seenTestIds.add(ledger.testId);
    if (!ledger.completed && nowMs < ledger.expiresAtMs && nowMs - ledger.createdAtMs < 45e3) {
      activeCount += 1;
      if (ledger.ipKey === ipKey) {
        activeIpCount += 1;
      }
    }
  }
  if (activeCount >= MAX_CONCURRENT_TESTS_PER_INSTANCE) {
    res.status(503).json({
      error: "Server speed-test capacity is currently busy. Please try again in a few seconds."
    });
    return;
  }
  if (activeIpCount >= MAX_CONCURRENT_TESTS_PER_IP) {
    res.status(429).json({
      error: "Too many simultaneous speed tests from this network. Please wait a moment."
    });
    return;
  }
  const visitorHistory = visitorTestTimestamps.get(visitorKey) || [];
  if (visitorHistory.length >= MAX_TESTS_PER_VISITOR_WINDOW) {
    const oldestMs = visitorHistory[0];
    const retrySec = Math.max(5, Math.ceil((RATE_WINDOW_MS - (nowMs - oldestMs)) / 1e3));
    res.status(429).json({
      error: `Rate limit reached (${MAX_TESTS_PER_VISITOR_WINDOW} tests per 10 minutes). Try again in ${retrySec}s.`
    });
    return;
  }
  const sessionCount = sessionTestCounts.get(sessionKey) || 0;
  if (sessionCount >= MAX_TESTS_PER_SESSION) {
    res.status(429).json({
      error: `Session speed-test limit (${MAX_TESTS_PER_SESSION} tests) reached.`
    });
    return;
  }
  const ipHistory = ipTestTimestamps.get(ipKey) || [];
  if (ipHistory.length >= MAX_TESTS_PER_IP_WINDOW) {
    res.status(429).json({
      error: "Network rate limit reached. Please wait a few minutes before running another test."
    });
    return;
  }
  visitorHistory.push(nowMs);
  visitorTestTimestamps.set(visitorKey, visitorHistory);
  sessionTestCounts.set(sessionKey, sessionCount + 1);
  ipHistory.push(nowMs);
  ipTestTimestamps.set(ipKey, ipHistory);
  const testId = "st_" + crypto.randomBytes(8).toString("hex");
  const expiresAtMs = nowMs + SPEED_TEST_TOKEN_TTL_MS;
  const token = createSignedSpeedTestToken();
  const newLedger = {
    testId,
    visitorKey,
    sessionKey,
    ipKey,
    createdAtMs: nowMs,
    expiresAtMs,
    downloadedBytes: 0,
    uploadedBytes: 0,
    activeStreams: 0,
    completed: false
  };
  activeSpeedTests.set(testId, newLedger);
  activeSpeedTests.set(token, newLedger);
  const { regionCode, regionLabel } = detectServerRegion(req);
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
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
    maxUploadBytes: SPEED_TEST_STREAM_CHUNK_BYTES
  });
});
app.post("/api/network/speed-test/complete", (req, res) => {
  const body = req.body || {};
  const queryToken = typeof req.query.token === "string" ? req.query.token : "";
  const headerToken = firstHeaderValue(req.headers["x-speed-test-token"]) || firstHeaderValue(req.headers["x-speedtest-token"]);
  const rawToken = (typeof body.token === "string" ? body.token : queryToken || headerToken).trim();
  const dotIndex = rawToken.indexOf(".");
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
  res.status(200).json({ ok: true });
});
app.get("/api/health", (req, res) => {
  const visitorsCount = db.prepare("SELECT COUNT(*) AS count FROM visitors").get().count;
  const visitsCount = db.prepare("SELECT COUNT(*) AS count FROM visits").get().count;
  const { regionCode, regionLabel } = detectServerRegion(req);
  res.json({ status: "ok", visitorsCount, visitsCount, regionCode, regionLabel });
});
function extractVercelEdgeGeo(req) {
  const decodeHeader = (val) => {
    if (typeof val !== "string" || !val.trim()) return "";
    try {
      return decodeURIComponent(val.trim());
    } catch {
      return val.trim();
    }
  };
  const city = decodeHeader(req.headers["x-vercel-ip-city"]);
  const region = decodeHeader(req.headers["x-vercel-ip-country-region"]);
  const country = decodeHeader(req.headers["x-vercel-ip-country"]);
  const timezone = decodeHeader(req.headers["x-vercel-ip-timezone"]);
  const rawLat = parseFloat(String(req.headers["x-vercel-ip-latitude"] || ""));
  const rawLon = parseFloat(String(req.headers["x-vercel-ip-longitude"] || ""));
  return {
    city,
    region,
    country,
    timezone,
    latitude: Number.isFinite(rawLat) ? rawLat : null,
    longitude: Number.isFinite(rawLon) ? rawLon : null
  };
}
var SERVER_TIMEZONE_ALIAS_MAP = {
  "asia/calcutta": "asia/kolkata",
  "asia/katmandu": "asia/kathmandu",
  "asia/rangoon": "asia/yangon",
  "asia/saigon": "asia/ho_chi_minh",
  "europe/kiev": "europe/kyiv",
  "us/eastern": "america/new_york",
  "us/central": "america/chicago",
  "us/mountain": "america/denver",
  "us/pacific": "america/los_angeles",
  "etc/utc": "utc",
  "etc/gmt": "utc"
};
function normalizeServerTimezoneId(tz) {
  if (!tz || typeof tz !== "string") return "";
  const cleaned = tz.trim().toLowerCase();
  if (!cleaned || cleaned === "unknown") return "";
  return SERVER_TIMEZONE_ALIAS_MAP[cleaned] || cleaned;
}
function sanitizeHardwareSignals(raw, browserDevice) {
  const safeStr = (val, fallback, maxLen = 140) => typeof val === "string" && val.trim().length > 0 ? val.trim().slice(0, maxLen) : fallback;
  const rawHwId = safeStr(raw?.hardwareId, "", 40);
  const validHwId = /^hwid_[0-9a-f]{16,32}$/i.test(rawHwId) ? rawHwId.toLowerCase() : "hwid_" + crypto.createHash("sha256").update(
    `${browserDevice.os}|${browserDevice.screenResolution}|${browserDevice.pixelRatio}|${safeStr(raw?.gpuRenderer, "gpu")}|${safeStr(raw?.canvasHash, "canvas")}`
  ).digest("hex").slice(0, 20);
  const cpuCores = typeof raw?.cpuCores === "number" && Number.isFinite(raw.cpuCores) && raw.cpuCores > 0 ? Math.min(256, Math.round(raw.cpuCores)) : null;
  const deviceMemoryGb = typeof raw?.deviceMemoryGb === "number" && Number.isFinite(raw.deviceMemoryGb) && raw.deviceMemoryGb > 0 ? Number(raw.deviceMemoryGb) : null;
  const maxTouchPoints = typeof raw?.maxTouchPoints === "number" && Number.isFinite(raw.maxTouchPoints) && raw.maxTouchPoints >= 0 ? Math.min(64, Math.round(raw.maxTouchPoints)) : 0;
  const colorDepth = typeof raw?.colorDepth === "number" && Number.isFinite(raw.colorDepth) && raw.colorDepth > 0 ? Math.min(64, Math.round(raw.colorDepth)) : 24;
  const maxTextureSize = typeof raw?.maxTextureSize === "number" && Number.isFinite(raw.maxTextureSize) && raw.maxTextureSize >= 0 ? Math.round(raw.maxTextureSize) : 0;
  return {
    hardwareId: validHwId,
    gpuVendor: safeStr(raw?.gpuVendor, "Standard WebGL Vendor", 120),
    gpuRenderer: safeStr(raw?.gpuRenderer, "Standard Hardware Renderer", 160),
    maxTextureSize,
    canvasHash: safeStr(raw?.canvasHash, "unavailable", 40),
    audioHash: safeStr(raw?.audioHash, "unavailable", 40),
    cpuCores,
    deviceMemoryGb,
    colorDepth,
    maxTouchPoints,
    hdrSupported: Boolean(raw?.hdrSupported),
    colorGamut: raw?.colorGamut === "Rec2020" || raw?.colorGamut === "P3" || raw?.colorGamut === "sRGB" ? raw.colorGamut : "sRGB",
    architecture: safeStr(raw?.architecture, browserDevice.os, 80)
  };
}
function sanitizeAndReinforceSecuritySignals(raw, browserDevice, hardwareSignals, location, ipTimezoneHint, recognitionSource) {
  const safeStrArray = (arr) => Array.isArray(arr) ? arr.filter((item) => typeof item === "string" && item.trim().length > 0).map((s) => s.trim().slice(0, 180)).slice(0, 10) : [];
  const isBot = Boolean(raw?.isBot);
  const botSignals = safeStrArray(raw?.botSignals);
  const browserTimezone = typeof raw?.browserTimezone === "string" && raw.browserTimezone.trim() ? raw.browserTimezone.trim().slice(0, 80) : browserDevice.timezone || "UTC";
  const ipTimezone = ipTimezoneHint || (typeof raw?.ipTimezone === "string" && raw.ipTimezone.trim() && raw.ipTimezone !== "Unavailable" ? raw.ipTimezone.trim().slice(0, 80) : "Unavailable");
  const normBrowserTz = normalizeServerTimezoneId(browserTimezone);
  const normIpTz = normalizeServerTimezoneId(ipTimezone);
  const serverTzMismatch = Boolean(normBrowserTz && normIpTz && normBrowserTz !== normIpTz);
  const timezoneMismatch = Boolean(raw?.timezoneMismatch) || serverTzMismatch;
  const combinedNet = `${location.isp || ""} ${location.org || ""} ${location.asn || ""}`;
  const isCloudOrDatacenterNetwork = Boolean(location.isVpnOrHosting) || /google|gcp|as15169|as396982|aws|amazon|digitalocean|cloudflare|m247|hetzner|azure|microsoft|linode|vultr|ovh|oracle|datacenter|hosting|cloud/i.test(
    combinedNet
  );
  const isGpuMaskedOrUnavailable = !hardwareSignals.gpuVendor || hardwareSignals.gpuVendor === "Unavailable" || /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuVendor) || !hardwareSignals.gpuRenderer || hardwareSignals.gpuRenderer === "Unavailable" || /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuRenderer);
  const datacenterAsn = Boolean(raw?.datacenterAsn) || isCloudOrDatacenterNetwork;
  const vpnReasons = safeStrArray(raw?.vpnReasons);
  if (timezoneMismatch && !vpnReasons.some((r) => r.toLowerCase().includes("timezone"))) {
    vpnReasons.push(
      `Browser timezone (${browserTimezone}) differs from IP geolocation timezone (${ipTimezone})`
    );
  }
  if (datacenterAsn && !vpnReasons.some((r) => r.toLowerCase().includes("datacenter") || r.toLowerCase().includes("asn"))) {
    vpnReasons.push(
      `Network ASN / ISP (${location.isp}${location.asn !== "Unknown" ? ` \u2022 ${location.asn}` : ""}) matches cloud/hosting or VPN infrastructure`
    );
  }
  if (datacenterAsn && isGpuMaskedOrUnavailable && !vpnReasons.some((r) => /Cloud \/ Masked GPU/i.test(r))) {
    vpnReasons.push("Cloud / Masked GPU environment");
  }
  const vpnSuspected = Boolean(raw?.vpnSuspected) || timezoneMismatch || datacenterAsn;
  const tamperDetected = Boolean(raw?.tamperDetected);
  const tamperReasons = safeStrArray(raw?.tamperReasons);
  const incognitoLikely = Boolean(raw?.incognitoLikely);
  const storageQuotaMb = typeof raw?.storageQuotaMb === "number" && Number.isFinite(raw.storageQuotaMb) && raw.storageQuotaMb > 0 ? Math.round(raw.storageQuotaMb) : null;
  let persistenceMode = "First-Party Cookie";
  if (recognitionSource === "Hardware Fingerprint (Cookie-less / Incognito)") {
    persistenceMode = "Hardware ID Recovered";
  } else if (incognitoLikely) {
    persistenceMode = "Private / Restricted Storage";
  }
  let suspectScore = 0;
  const riskFactors = [];
  if (isBot) {
    suspectScore += 45;
    riskFactors.push(botSignals[0] || "Headless / automated browser runtime detected");
  }
  if (timezoneMismatch) {
    suspectScore += 25;
    riskFactors.push(`Timezone mismatch (${browserTimezone} vs ${ipTimezone})`);
  }
  if (datacenterAsn) {
    suspectScore += 15;
    riskFactors.push(
      isGpuMaskedOrUnavailable ? `Cloud / Masked GPU environment (${location.isp})` : `Datacenter or VPN network ASN (${location.isp})`
    );
  }
  if (tamperDetected) {
    suspectScore += 15;
    riskFactors.push(tamperReasons[0] || "User-Agent / platform mismatch detected");
  }
  if (incognitoLikely) {
    suspectScore += 10;
    riskFactors.push(
      storageQuotaMb !== null ? `Restricted storage quota (${storageQuotaMb} MB) indicates private browsing` : "Private or restricted browser storage environment"
    );
  }
  suspectScore = Math.min(100, suspectScore);
  const riskLevel = suspectScore >= 50 ? "High" : suspectScore >= 20 ? "Medium" : "Low";
  const cloudOrMaskedGpu = Boolean(
    raw?.cloudOrMaskedGpu
  );
  const securitySignalsCore = {
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
    riskFactors
  };
  return {
    ...securitySignalsCore,
    ...{ cloudOrMaskedGpu }
  };
}
app.post("/api/visitor/identify", async (req, res) => {
  try {
    const {
      pageLoadId,
      storedVisitorId,
      storedVisitorToken,
      clientSessionId,
      clientHistoryBackup,
      browserDevice: rawBrowserDevice,
      hardwareSignals: rawHardwareSignals,
      securitySignals: rawSecuritySignals,
      clientGeoHint
    } = req.body || {};
    const safePageLoadId = typeof pageLoadId === "string" && pageLoadId.trim().length > 0 ? pageLoadId.trim().slice(0, 80) : "pl_" + crypto.randomBytes(8).toString("hex");
    const browserDevice = sanitizeBrowserDevice(rawBrowserDevice);
    const hardwareSignals = sanitizeHardwareSignals(rawHardwareSignals, browserDevice);
    const hardwareId = hardwareSignals.hardwareId;
    let { ip: extractedIp, isPublic } = extractVisitorIp(req);
    if (!isPublic && clientGeoHint && typeof clientGeoHint.ip === "string") {
      const normalizedHintIp = normalizeIpCandidate(clientGeoHint.ip);
      if (normalizedHintIp && isPublicRoutableIp(normalizedHintIp)) {
        extractedIp = normalizedHintIp;
        isPublic = true;
      }
    }
    let location = await lookupVerifiedGeolocation(extractedIp, isPublic);
    const vercelGeo = extractVercelEdgeGeo(req);
    if (isPublic && (!location.isLocationVerified || location.isp === "Unknown" || location.latitude === null) && clientGeoHint && normalizeIpCandidate(clientGeoHint.ip)?.toLowerCase() === extractedIp.toLowerCase()) {
      const hintNet = normalizeIspAndOrg(
        clientGeoHint.isp,
        clientGeoHint.org,
        clientGeoHint.asn,
        Boolean(clientGeoHint.isVpnOrHosting)
      );
      const hintLat = typeof clientGeoHint.latitude === "number" && Number.isFinite(clientGeoHint.latitude) ? clientGeoHint.latitude : vercelGeo.latitude;
      const hintLon = typeof clientGeoHint.longitude === "number" && Number.isFinite(clientGeoHint.longitude) ? clientGeoHint.longitude : vercelGeo.longitude;
      location = {
        publicIp: extractedIp,
        city: location.city !== "Unavailable" && location.city !== "Unknown" ? location.city : typeof clientGeoHint.city === "string" && clientGeoHint.city || vercelGeo.city || "Unknown",
        region: location.region !== "Unavailable" && location.region !== "Unknown" ? location.region : typeof clientGeoHint.region === "string" && clientGeoHint.region || vercelGeo.region || "Unknown",
        country: location.country !== "Unavailable" && location.country !== "Unknown" ? location.country : typeof clientGeoHint.country === "string" && clientGeoHint.country || vercelGeo.country || "Unknown",
        countryCode: location.countryCode || (typeof clientGeoHint.countryCode === "string" ? clientGeoHint.countryCode : "") || vercelGeo.country,
        latitude: location.latitude !== null ? location.latitude : hintLat,
        longitude: location.longitude !== null ? location.longitude : hintLon,
        isp: location.isp !== "Unknown" ? location.isp : hintNet.isp,
        org: location.org !== "Unknown" ? location.org : hintNet.org,
        asn: location.asn !== "Unknown" ? location.asn : hintNet.asn,
        isVpnOrHosting: location.isVpnOrHosting || hintNet.isVpnOrHosting,
        isIpVerified: true,
        isLocationVerified: true
      };
    } else if (isPublic && (!location.isLocationVerified || location.latitude === null) && (vercelGeo.city || vercelGeo.country || vercelGeo.latitude !== null)) {
      location = {
        ...location,
        city: location.city !== "Unavailable" && location.city !== "Unknown" ? location.city : vercelGeo.city || "Unknown",
        region: location.region !== "Unavailable" && location.region !== "Unknown" ? location.region : vercelGeo.region || "Unknown",
        country: location.country !== "Unavailable" && location.country !== "Unknown" ? location.country : vercelGeo.country || "Unknown",
        countryCode: location.countryCode || vercelGeo.country,
        latitude: location.latitude !== null ? location.latitude : vercelGeo.latitude,
        longitude: location.longitude !== null ? location.longitude : vercelGeo.longitude,
        isLocationVerified: true
      };
    }
    const cookieVid = req.cookies?.intel_http_vid;
    const cookieToken = req.cookies?.intel_http_token;
    let existingVisitor;
    let recognitionSource = "New First-Party ID";
    const cookieVerified = Boolean(cookieVid && verifyVisitorToken(cookieVid, cookieToken));
    const storageVerified = Boolean(
      storedVisitorId && verifyVisitorToken(storedVisitorId, storedVisitorToken)
    );
    const verifiedVid = cookieVerified ? cookieVid : storageVerified ? storedVisitorId : null;
    const verifiedToken = cookieVerified ? cookieToken : storageVerified ? storedVisitorToken : null;
    if (verifiedVid && verifiedToken) {
      recognitionSource = cookieVerified ? "First-Party Cookie" : "First-Party LocalStorage";
      existingVisitor = db.prepare("SELECT * FROM visitors WHERE visitor_id = ?").get(verifiedVid);
      const validHistoryBackup = clientHistoryBackup && verifySignedHistoryBackup(verifiedVid, clientHistoryBackup) ? clientHistoryBackup : null;
      if (!existingVisitor) {
        const nowIso = (/* @__PURE__ */ new Date()).toISOString();
        const restoredFirstUtc = validHistoryBackup?.firstVisitUtc || nowIso;
        const latestBackupVisit = validHistoryBackup?.visits?.[0];
        const restoredLastUtc = latestBackupVisit?.visitedAtUtc || nowIso;
        const restoredSessionId = clientSessionId || latestBackupVisit?.sessionId || generateSessionId();
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
        existingVisitor = db.prepare("SELECT * FROM visitors WHERE visitor_id = ?").get(verifiedVid);
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
            histVisit.isp || "Unknown",
            histVisit.org || "Unknown",
            histVisit.asn || "Unknown",
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
      const hwMatchedVisitor = db.prepare("SELECT * FROM visitors WHERE hardware_id = ?").get(hardwareId);
      if (hwMatchedVisitor) {
        existingVisitor = hwMatchedVisitor;
        recognitionSource = "Hardware Fingerprint (Cookie-less / Incognito)";
      }
    }
    const nowUtc = (/* @__PURE__ */ new Date()).toISOString();
    const nowMs = Date.now();
    let visitorId;
    let visitorToken;
    let currentSessionId;
    let isReturning = false;
    if (existingVisitor) {
      visitorId = existingVisitor.visitor_id;
      visitorToken = existingVisitor.hmac_token;
      isReturning = true;
      const lastActivityMs = new Date(existingVisitor.last_activity_utc).getTime();
      const isExpiredByInactivity = Number.isNaN(lastActivityMs) || nowMs - lastActivityMs > SESSION_EXPIRATION_MS;
      const isSameClientSession = Boolean(clientSessionId) && clientSessionId === existingVisitor.active_session_id;
      const existingPageLoadVisit = db.prepare("SELECT session_id, visited_at_utc FROM visits WHERE visitor_id = ? AND page_load_id = ?").get(visitorId, safePageLoadId);
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
      maxAge: 365 * 24 * 60 * 60 * 1e3,
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      secure: Boolean(process.env.VERCEL) || process.env.NODE_ENV === "production"
    };
    res.cookie("intel_http_vid", visitorId, cookieOptions);
    res.cookie("intel_http_token", visitorToken, cookieOptions);
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    const statsAgg = db.prepare(
      `SELECT
          COUNT(*) AS total_visits,
          MIN(visited_at_utc) AS first_visit_utc,
          MAX(visited_at_utc) AS last_visit_utc,
          COUNT(DISTINCT session_id) AS total_sessions
         FROM visits
         WHERE visitor_id = ?`
    ).get(visitorId);
    const prevVisitRow = db.prepare(
      `SELECT visited_at_utc
         FROM visits
         WHERE visitor_id = ?
         ORDER BY visited_at_utc DESC, id DESC
         LIMIT 1 OFFSET 1`
    ).get(visitorId);
    const validBackupForStats = clientHistoryBackup && verifySignedHistoryBackup(visitorId, clientHistoryBackup) ? clientHistoryBackup : null;
    const dbTotalVisits = Number(statsAgg.total_visits) || 1;
    const mergedTotalVisits = validBackupForStats ? Math.max(dbTotalVisits, validBackupForStats.totalVisits) : dbTotalVisits;
    const dbTotalSessions = Number(statsAgg.total_sessions) || 1;
    const mergedTotalSessions = validBackupForStats ? Math.max(dbTotalSessions, validBackupForStats.totalSessions) : dbTotalSessions;
    const mergedFirstVisitUtc = validBackupForStats && validBackupForStats.firstVisitUtc && validBackupForStats.firstVisitUtc < (statsAgg.first_visit_utc || nowUtc) ? validBackupForStats.firstVisitUtc : statsAgg.first_visit_utc || nowUtc;
    const statistics = {
      firstVisitUtc: mergedFirstVisitUtc,
      lastVisitUtc: statsAgg.last_visit_utc || nowUtc,
      previousVisitUtc: prevVisitRow ? prevVisitRow.visited_at_utc : null,
      totalVisits: mergedTotalVisits,
      totalSessions: mergedTotalSessions,
      currentSessionId,
      sessionTimeoutMinutes: SESSION_TIMEOUT_MINUTES
    };
    if (statistics.totalVisits > 1) {
      isReturning = true;
    }
    const rawVisits = db.prepare(
      `SELECT
          id, visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
          public_ip, city, region, country, latitude, longitude, isp, org, asn,
          browser, os, device_type, screen_resolution, language, timezone
         FROM visits
         WHERE visitor_id = ?
         ORDER BY visited_at_utc DESC, id DESC
         LIMIT 50`
    ).all(visitorId);
    const ipTimezoneHint = typeof clientGeoHint?.timezone === "string" && clientGeoHint.timezone.trim() || vercelGeo.timezone || "";
    const securitySignals = sanitizeAndReinforceSecuritySignals(
      rawSecuritySignals,
      browserDevice,
      hardwareSignals,
      location,
      ipTimezoneHint,
      recognitionSource
    );
    const visitHistory = rawVisits.map((r) => {
      const storedSuspectScore = typeof r.suspect_score === "number" && Number.isFinite(r.suspect_score) ? Math.max(0, Math.min(100, Math.round(r.suspect_score))) : null;
      const isCurrentVisitRow = String(r.page_load_id || "") === safePageLoadId;
      const rowSuspectScore = storedSuspectScore !== null ? storedSuspectScore : isCurrentVisitRow ? securitySignals.suspectScore : 0;
      const rowRiskLevel = rowSuspectScore >= 50 ? "High" : rowSuspectScore >= 20 ? "Medium" : "Low";
      const rowRecognitionSource = isCurrentVisitRow ? recognitionSource : "Cookie";
      const rowCloudOrMaskedGpu = isCurrentVisitRow ? Boolean(
        securitySignals.cloudOrMaskedGpu
      ) : false;
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
        latitude: typeof r.latitude === "number" && Number.isFinite(r.latitude) ? r.latitude : null,
        longitude: typeof r.longitude === "number" && Number.isFinite(r.longitude) ? r.longitude : null,
        isp: String(r.isp || "Unknown"),
        org: String(r.org || "Unknown"),
        asn: String(r.asn || "Unknown"),
        browser: String(r.browser),
        os: String(r.os),
        deviceType: String(r.device_type),
        screenResolution: String(r.screen_resolution),
        language: String(r.language),
        timezone: String(r.timezone),
        suspectScore: rowSuspectScore,
        riskLevel: rowRiskLevel,
        recognitionSource: rowRecognitionSource,
        cloudOrMaskedGpu: rowCloudOrMaskedGpu
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
    const payload = {
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
      historyBackup
    };
    res.json(payload);
  } catch (err) {
    console.error("Error in /api/visitor/identify:", err);
    res.status(500).json({ error: "Unable to process visitor identification request." });
  }
});
app.get("/api/visitor/history/:visitorId", (req, res) => {
  const requestedVisitorId = req.params.visitorId;
  const headerToken = req.headers["x-visitor-token"];
  const cookieVid = req.cookies?.intel_http_vid;
  const cookieToken = req.cookies?.intel_http_token;
  const authorizedByHeader = verifyVisitorToken(requestedVisitorId, headerToken);
  const authorizedByCookie = cookieVid === requestedVisitorId && verifyVisitorToken(cookieVid, cookieToken);
  if (!authorizedByHeader && !authorizedByCookie) {
    res.status(403).json({
      error: "Forbidden: You are not authorized to access another visitor\u2019s records."
    });
    return;
  }
  const rawVisits = db.prepare(
    `SELECT
        id, visit_id, visitor_id, session_id, visited_at_utc,
        public_ip, city, region, country, isp, org, asn,
        browser, os, device_type, screen_resolution, language, timezone
       FROM visits
       WHERE visitor_id = ?
       ORDER BY visited_at_utc DESC, id DESC
       LIMIT 50`
  ).all(requestedVisitorId);
  const visits = rawVisits.map((row) => {
    const storedSuspectScore = typeof row.suspect_score === "number" && Number.isFinite(row.suspect_score) ? Math.max(0, Math.min(100, Math.round(row.suspect_score))) : 0;
    const storedRecognitionSource = typeof row.recognition_source === "string" && row.recognition_source.trim() ? row.recognition_source : "Cookie";
    const rowRiskLevel = storedSuspectScore >= 50 ? "High" : storedSuspectScore >= 20 ? "Medium" : "Low";
    return {
      ...row,
      suspectScore: storedSuspectScore,
      riskLevel: rowRiskLevel,
      recognitionSource: storedRecognitionSource
    };
  });
  res.json({ visitorId: requestedVisitorId, visits });
});
app.use("/api", (_req, res) => {
  res.status(404).json({ error: "API endpoint not found." });
});
app.use(
  (err, _req, res, _next) => {
    console.error("Unhandled API error:", err);
    if (!res.headersSent) {
      res.status(500).json({ error: "Internal server error." });
    }
  }
);
async function startStandaloneServer() {
  if (process.env.NODE_ENV !== "production") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Intel System running on http://0.0.0.0:${PORT}`);
  });
}
if (!IS_SERVERLESS_RUNTIME) {
  startStandaloneServer();
}
var server_default = app;

// api/_entry.ts
var API_PREFIX = "/api";
function applyRestoredUrlAndQuery(req, restoredPath, params) {
  params.delete("__ipath");
  const remainingQuery = params.toString();
  const finalUrl = remainingQuery ? `${restoredPath}?${remainingQuery}` : restoredPath;
  req.url = finalUrl;
  req.originalUrl = finalUrl;
  const internalReq = req;
  if ("_parsedUrl" in internalReq) {
    delete internalReq._parsedUrl;
  }
  if ("_parsedOriginalUrl" in internalReq) {
    delete internalReq._parsedOriginalUrl;
  }
  const cleanQuery = {};
  for (const [key, value] of params.entries()) {
    if (key === "__ipath") continue;
    const existing = cleanQuery[key];
    if (existing === void 0) {
      cleanQuery[key] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      cleanQuery[key] = [existing, value];
    }
  }
  try {
    Object.defineProperty(req, "query", {
      value: cleanQuery,
      writable: true,
      enumerable: true,
      configurable: true
    });
  } catch {
    try {
      req.query = cleanQuery;
    } catch {
    }
  }
}
function restoreOriginalApiUrl(req) {
  const rawUrl = typeof req.url === "string" && req.url.length > 0 ? req.url : "/";
  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl, "http://localhost");
  } catch {
    try {
      parsedUrl = new URL(rawUrl.replace(/%(?![0-9a-fA-F]{2})/g, "%25"), "http://localhost");
    } catch {
      return;
    }
  }
  const searchParams = parsedUrl.searchParams;
  try {
    if (req.query && typeof req.query === "object") {
      for (const [k, v] of Object.entries(req.query)) {
        if (!searchParams.has(k)) {
          if (typeof v === "string") {
            searchParams.set(k, v);
          } else if (Array.isArray(v) && typeof v[0] === "string") {
            searchParams.set(k, v[0]);
          }
        }
      }
    }
  } catch {
  }
  const pathPart = parsedUrl.pathname;
  const rawIpath = searchParams.get("__ipath");
  if (rawIpath !== null) {
    searchParams.delete("__ipath");
    let decodedInjected = rawIpath;
    try {
      if (decodedInjected.includes("%")) {
        decodedInjected = decodeURIComponent(decodedInjected);
      }
    } catch {
      decodedInjected = rawIpath;
    }
    const [cleanInjectedPath, embeddedQuery] = decodedInjected.split("?");
    if (embeddedQuery) {
      const embeddedParams = new URLSearchParams(embeddedQuery);
      for (const [ek, ev] of embeddedParams.entries()) {
        if (ek !== "__ipath" && !searchParams.has(ek)) {
          searchParams.set(ek, ev);
        }
      }
    }
    const cleanSubpath = cleanInjectedPath.replace(/^\/+/, "").replace(/^api\/+/i, "");
    const restoredPath = cleanSubpath ? `${API_PREFIX}/${cleanSubpath}` : API_PREFIX;
    applyRestoredUrlAndQuery(req, restoredPath, searchParams);
    return;
  }
  if (pathPart === "/api/index" || pathPart === "/api/index.js") {
    const headerValue = req.headers["x-vercel-original-path"] || req.headers["x-original-url"] || req.headers["x-rewrite-url"] || req.headers["x-matched-path"];
    if (headerValue) {
      const original = headerValue.startsWith("http") ? new URL(headerValue).pathname + new URL(headerValue).search : headerValue;
      const normalized = original.startsWith("/") ? original : `/${original}`;
      const normQIdx = normalized.indexOf("?");
      const normPath = normQIdx === -1 ? normalized : normalized.slice(0, normQIdx);
      const normQuery = normQIdx === -1 ? "" : normalized.slice(normQIdx + 1);
      const mergedParams = new URLSearchParams(normQuery);
      for (const [k, v] of searchParams.entries()) {
        if (k !== "__ipath" && !mergedParams.has(k)) {
          mergedParams.set(k, v);
        }
      }
      applyRestoredUrlAndQuery(req, normPath, mergedParams);
      return;
    }
  }
  applyRestoredUrlAndQuery(req, pathPart, searchParams);
}
function handler(req, res) {
  try {
    restoreOriginalApiUrl(req);
  } catch {
  }
  server_default(req, res);
}
export {
  handler as default
};

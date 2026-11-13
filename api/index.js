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
import dns from "node:dns/promises";
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
var CLOUD_PROVIDER_ASN_NUMBERS = /* @__PURE__ */ new Set([
  396178,
  15169,
  16509,
  14618,
  13335,
  14061,
  9009,
  60068,
  24940,
  63949,
  16276,
  8075,
  20473
]);
function classifyIspNetwork(isp, org, asn) {
  const cleanIsp = typeof isp === "string" ? isp.trim() : "";
  const cleanOrg = typeof org === "string" ? org.trim() : "";
  const cleanAsn = typeof asn === "string" ? asn.trim().toUpperCase() : "";
  const keywordHaystack = `${cleanIsp} ${cleanOrg}`;
  const asnNumbers = /* @__PURE__ */ new Set();
  const asnTokenRegex = /\bAS(\d{1,10})\b/gi;
  let asnTokenMatch;
  while ((asnTokenMatch = asnTokenRegex.exec(`${cleanAsn} ${keywordHaystack}`)) !== null) {
    const parsedAsn = Number.parseInt(asnTokenMatch[1], 10);
    if (Number.isFinite(parsedAsn)) asnNumbers.add(parsedAsn);
  }
  const matchConsumerRule = (brand, networkType, asns, keywords) => {
    const asnHit = asns.find((a) => asnNumbers.has(a));
    const keywordHit = keywords !== null && keywords.test(keywordHaystack);
    if (asnHit === void 0 && !keywordHit) return null;
    return {
      brandName: brand,
      networkType,
      isConsumerBroadband: true,
      isDatacenterOrHosting: false,
      matchedReason: asnHit !== void 0 ? `ASN AS${asnHit}` : `ISP metadata keyword ${String(keywords)}`
    };
  };
  const consumerMatch = (
    // US consumer broadband (Residential Broadband)
    matchConsumerRule("Xfinity (Comcast)", "Residential Broadband", [7922, 7015, 7016], /comcast|xfinity/i) || matchConsumerRule("Spectrum (Charter)", "Residential Broadband", [20115, 11426, 10796], /charter|spectrum/i) || matchConsumerRule("AT&T Fiber", "Residential Broadband", [7018, 20057], /at&t|att services|sbcglobal/i) || matchConsumerRule("Verizon Fios", "Residential Broadband", [701, 19262], /fios|mci communications|verizon online/i) || matchConsumerRule("Optimum", "Residential Broadband", [6128, 19108], /optimum|cablevision|altice|suddenlink/i) || matchConsumerRule("Cox", "Residential Broadband", [22773], /\bcox\b/i) || matchConsumerRule("Frontier / CenturyLink", "Residential Broadband", [5650, 209], null) || matchConsumerRule("Google Fiber", "Residential Broadband", [16591], /google fiber|gfiber/i) || // US 5G home internet (Cellular / 5G)
    matchConsumerRule("Verizon 5G Home", "Cellular / 5G", [6167, 22394], /cellco|verizon wireless/i) || matchConsumerRule("T-Mobile 5G Home", "Cellular / 5G", [21928], /t-mobile|tmobile/i) || // Satellite
    matchConsumerRule("Starlink (SpaceX)", "Satellite", [14593], /starlink|spacex/i) || // India consumer broadband (Residential Broadband)
    matchConsumerRule("Jio (Reliance Jio)", "Residential Broadband", [55836], /reliance jio|\bjio\b/i) || matchConsumerRule("Airtel Xstream", "Residential Broadband", [24560, 45609, 9498], /bharti airtel|\bairtel\b/i) || matchConsumerRule("ACT Fibernet", "Residential Broadband", [24309], /act fibernet|atria convergence/i) || matchConsumerRule("BSNL Broadband", "Residential Broadband", [9829], /\bbsnl\b|bharat sanchar/i) || matchConsumerRule("Tata Play / Hathway", "Residential Broadband", [], /tata play|tata sky broadband|hathway|excitel/i)
  );
  if (consumerMatch) {
    return consumerMatch;
  }
  const cloudAsnHit = Array.from(asnNumbers).find((n) => CLOUD_PROVIDER_ASN_NUMBERS.has(n));
  const cloudKeywords = /google llc|google cloud|amazonaws|cloudflare|digitalocean|hetzner|m247|datacamp|linode|ovh|choopa|vultr|leaseweb|hostinger|contabo|akamai/i;
  if (cloudAsnHit !== void 0 || cloudKeywords.test(keywordHaystack)) {
    return {
      brandName: "Cloud Provider / Datacenter",
      networkType: "Cloud / Datacenter",
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: cloudAsnHit !== void 0 ? `ASN AS${cloudAsnHit}` : `ISP metadata keyword ${String(cloudKeywords)}`
    };
  }
  return {
    brandName: cleanIsp && !/^unknown$|^unknown isp$/i.test(cleanIsp) ? cleanIsp : cleanOrg && !/^unknown$|^unknown isp$/i.test(cleanOrg) ? cleanOrg : "Unknown ISP",
    networkType: "Residential Broadband",
    isConsumerBroadband: false,
    isDatacenterOrHosting: false,
    matchedReason: null
  };
}
function readRequestHeader(headers, name) {
  if (!headers) return "";
  const direct = headers[name.toLowerCase()];
  const raw = Array.isArray(direct) ? direct.join(", ") : direct;
  return typeof raw === "string" ? raw.trim() : "";
}
var GOOD_BOT_UA_RULES = [
  {
    pattern: /googlebot/i,
    provider: "Google",
    label: "Googlebot",
    category: "Search Crawler",
    network: /google/i
  },
  {
    pattern: /bingbot|bingpreview/i,
    provider: "Microsoft",
    label: "Bingbot",
    category: "Search Crawler",
    network: /microsoft|\bbing\b/i
  },
  {
    pattern: /applebot/i,
    provider: "Apple",
    label: "Applebot",
    category: "Search Crawler",
    network: /\bapple\b/i
  },
  {
    pattern: /duckduckbot/i,
    provider: "DuckDuckGo",
    label: "DuckDuckBot",
    category: "Search Crawler",
    network: /duckduckgo/i
  },
  {
    pattern: /linkedinbot/i,
    provider: "LinkedIn",
    label: "LinkedInBot",
    category: "Link Preview",
    network: /linkedin/i
  },
  {
    pattern: /twitterbot/i,
    provider: "X (Twitter)",
    label: "Twitterbot",
    category: "Link Preview",
    network: /twitter|\bx corp\b/i
  },
  {
    pattern: /slackbot/i,
    provider: "Slack",
    label: "Slackbot",
    category: "Link Preview",
    network: /slack/i
  },
  {
    pattern: /vercelbot/i,
    provider: "Vercel",
    label: "Vercelbot",
    category: "Link Preview",
    network: /vercel/i
  }
];
var AI_AGENT_UA_RULES = [
  { pattern: /gptbot/i, provider: "OpenAI", label: "GPTBot" },
  { pattern: /chatgpt-user/i, provider: "OpenAI", label: "ChatGPT-User" },
  { pattern: /oai-searchbot/i, provider: "OpenAI", label: "OAI-SearchBot" },
  { pattern: /claudebot/i, provider: "Anthropic", label: "ClaudeBot" },
  { pattern: /claude-web/i, provider: "Anthropic", label: "Claude-Web" },
  { pattern: /anthropic-ai/i, provider: "Anthropic", label: "Anthropic-AI" },
  { pattern: /perplexitybot/i, provider: "Perplexity", label: "PerplexityBot" },
  { pattern: /perplexity-user/i, provider: "Perplexity", label: "Perplexity-User" },
  { pattern: /google-extended/i, provider: "Google", label: "Google-Extended" },
  { pattern: /ccbot/i, provider: "Common Crawl", label: "CCBot" },
  { pattern: /bytespider/i, provider: "ByteDance", label: "Bytespider" },
  { pattern: /cohere-ai/i, provider: "Cohere", label: "Cohere-AI" },
  { pattern: /meta-externalagent/i, provider: "Meta", label: "Meta-ExternalAgent" },
  { pattern: /headlesschrome/i, provider: "Cloud Browser Agent", label: "Headless Chrome" }
];
var AUTOMATION_UA_PATTERN = /playwright|puppeteer|selenium|cypress|phantomjs/i;
var DATACENTER_NETWORK_PATTERN = /\b(amazon|amazonaws|aws|google cloud|azure|microsoft azure|digitalocean|hetzner|linode|akamai|ovh|vultr|oracle cloud|alibaba|aliyun|tencent|leaseweb|contabo|m247|choopa|datacamp)\b/i;
var KNOWN_AI_CRAWLER_REASON = "LLM crawler user-agent signature";
function classifyBotTraffic(headers, network, client) {
  const ua = readRequestHeader(headers, "user-agent");
  const acceptLanguage = readRequestHeader(headers, "accept-language");
  const secFetchSite = readRequestHeader(headers, "sec-fetch-site");
  const secFetchMode = readRequestHeader(headers, "sec-fetch-mode");
  const secFetchDest = readRequestHeader(headers, "sec-fetch-dest");
  const networkHaystack = [network.org, network.isp, network.asn].filter((part) => typeof part === "string" && part.trim().length > 0).join(" ");
  const clientSignals = Array.isArray(client.botSignals) ? client.botSignals.filter((s) => typeof s === "string" && s.trim().length > 0) : [];
  for (const rule of GOOD_BOT_UA_RULES) {
    if (!rule.pattern.test(ua)) continue;
    if (rule.network.test(networkHaystack)) {
      return {
        subtype: "good_bot",
        label: rule.label,
        provider: rule.provider,
        category: rule.category,
        confidence: 0.97,
        reasons: [
          `${rule.label} user-agent matched`,
          `Network identity (${networkHaystack || "unknown"}) matches ${rule.provider}`
        ]
      };
    }
    return {
      subtype: "bad_bot",
      label: "Spoofed Crawler",
      provider: `Unverified ${rule.provider} claim`,
      category: "Spoofed Identity",
      confidence: 0.99,
      reasons: [
        `${rule.label} user-agent presented`,
        `Network identity (${networkHaystack || "unknown"}) does not belong to ${rule.provider}`
      ]
    };
  }
  for (const rule of AI_AGENT_UA_RULES) {
    if (!rule.pattern.test(ua)) continue;
    return {
      subtype: "ai_agent",
      label: rule.label,
      provider: rule.provider,
      category: rule.provider === "Cloud Browser Agent" ? "Autonomous Agent" : "AI Crawler",
      confidence: rule.provider === "Cloud Browser Agent" ? 0.85 : 0.92,
      reasons: [
        `${rule.label} user-agent matched`,
        networkHaystack ? `Network identity: ${networkHaystack}` : "Network identity unavailable"
      ]
    };
  }
  const datacenterNetwork = DATACENTER_NETWORK_PATTERN.test(networkHaystack);
  const automationRuntimeDetected = Boolean(client.webdriver || client.cdpDetected);
  if (automationRuntimeDetected && datacenterNetwork) {
    return {
      subtype: "ai_agent",
      label: "Cloud Browser Agent",
      provider: "Cloud Browser Agent",
      category: "Autonomous Agent",
      confidence: 0.78,
      reasons: [
        client.webdriver ? "WebDriver runtime binding present" : "CDP runtime binding present",
        `Datacenter ASN hosting the agent (${networkHaystack})`
      ]
    };
  }
  const isDesktopChromeOrSafari = /chrome\/|crios\/|safari\//i.test(ua) && !/mobile|android|iphone|ipad/i.test(ua);
  const missingFetchMetadata = !secFetchSite && !secFetchMode && !secFetchDest;
  if (client.isBot || client.webdriver || client.cdpDetected || AUTOMATION_UA_PATTERN.test(ua) || isDesktopChromeOrSafari && (!acceptLanguage || missingFetchMetadata)) {
    const reasons = [];
    if (client.isBot) reasons.push("Client reported an automated runtime");
    if (client.webdriver) reasons.push("WebDriver handshake detected");
    if (client.cdpDetected) reasons.push("Chrome DevTools Protocol binding detected");
    if (AUTOMATION_UA_PATTERN.test(ua)) reasons.push("Automation framework signature in user-agent");
    if (isDesktopChromeOrSafari && !acceptLanguage) {
      reasons.push("Desktop browser user-agent without accept-language");
    }
    if (isDesktopChromeOrSafari && missingFetchMetadata) {
      reasons.push("Desktop browser user-agent without sec-fetch metadata");
    }
    for (const signal of clientSignals.slice(0, 2)) reasons.push(signal);
    return {
      subtype: "bad_bot",
      label: AUTOMATION_UA_PATTERN.test(ua) ? "Automation Runtime" : "Automation / Header Anomaly",
      provider: "Unattributed Automation",
      category: "Automation",
      confidence: client.isBot || automationRuntimeDetected ? 0.93 : 0.7,
      reasons: reasons.length > 0 ? reasons : ["Automated traffic signature detected"]
    };
  }
  return {
    subtype: "human",
    label: "Verified Human",
    provider: "None",
    category: "Human Interaction",
    confidence: 0.6,
    reasons: ["Interactive browser profile without automation signatures"]
  };
}
var TOR_DNS_TIMEOUT_MS = 600;
var TOR_DNS_CACHE_TTL_MS = 10 * 60 * 1e3;
var TOR_DNS_CACHE_MAX_ENTRIES = 5e3;
var TOR_BULK_LIST_URL = "https://check.torproject.org/torbulkexitlist";
var TOR_BULK_REFRESH_INTERVAL_MS = 60 * 60 * 1e3;
var TOR_BULK_TIMEOUT_MS = 1500;
var TOR_BULK_LIST_MAX_ENTRIES = 2e4;
var torDnsCache = /* @__PURE__ */ new Map();
var torBulkExitList = /* @__PURE__ */ new Set();
var torBulkRefreshedAtMs = 0;
var torBulkRefreshInFlight = false;
var SUSPICIOUS_IP_TTL_MS = 24 * 60 * 60 * 1e3;
var SUSPICIOUS_IP_MAX_ENTRIES = 1e4;
var suspiciousIpLedger = /* @__PURE__ */ new Map();
var suspiciousIpReasons = /* @__PURE__ */ new Map();
function isIpv4Literal(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed)) return false;
  return trimmed.split(".").every((octet) => {
    const parsed = Number.parseInt(octet, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 255;
  });
}
function pruneTorDnsCache(nowMs) {
  for (const [ip, entry] of torDnsCache) {
    if (entry.expiresAtMs <= nowMs) torDnsCache.delete(ip);
  }
  while (torDnsCache.size >= TOR_DNS_CACHE_MAX_ENTRIES) {
    const oldestKey = torDnsCache.keys().next().value;
    if (typeof oldestKey !== "string") break;
    torDnsCache.delete(oldestKey);
  }
}
async function isTorExitNode(ip) {
  const cleanIp = typeof ip === "string" ? ip.trim() : "";
  if (!isIpv4Literal(cleanIp)) return false;
  const nowMs = Date.now();
  const cached = torDnsCache.get(cleanIp);
  if (cached && cached.expiresAtMs > nowMs) return cached.isTorExit;
  let timeoutHandle;
  try {
    const reversedIp = cleanIp.split(".").reverse().join(".");
    const lookup = dns.resolve4(`${reversedIp}.dnsel.torproject.org`).catch(() => []);
    const timeout = new Promise((resolve) => {
      timeoutHandle = setTimeout(() => resolve([]), TOR_DNS_TIMEOUT_MS);
    });
    const records = await Promise.race([lookup, timeout]);
    const isTorExit = Array.isArray(records) && records.includes("127.0.0.2");
    pruneTorDnsCache(nowMs);
    torDnsCache.set(cleanIp, {
      isTorExit,
      expiresAtMs: nowMs + TOR_DNS_CACHE_TTL_MS
    });
    return isTorExit;
  } catch {
    return false;
  } finally {
    if (timeoutHandle !== void 0) clearTimeout(timeoutHandle);
  }
}
function isTorBulkListed(ip) {
  const cleanIp = typeof ip === "string" ? ip.trim() : "";
  return cleanIp.length > 0 && torBulkExitList.has(cleanIp);
}
async function refreshTorBulkList() {
  const nowMs = Date.now();
  if (torBulkRefreshInFlight) return;
  if (nowMs - torBulkRefreshedAtMs < TOR_BULK_REFRESH_INTERVAL_MS) return;
  torBulkRefreshInFlight = true;
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), TOR_BULK_TIMEOUT_MS);
  try {
    const response = await fetch(TOR_BULK_LIST_URL, {
      signal: controller.signal,
      headers: { accept: "text/plain" }
    });
    if (!response.ok) return;
    const body = await response.text();
    let added = 0;
    for (const line of body.split(/\r?\n/)) {
      const candidate = line.trim();
      if (!isIpv4Literal(candidate)) continue;
      torBulkExitList.add(candidate);
      added += 1;
      if (added >= TOR_BULK_LIST_MAX_ENTRIES) break;
    }
  } catch {
  } finally {
    clearTimeout(timeoutHandle);
    torBulkRefreshInFlight = false;
    torBulkRefreshedAtMs = Date.now();
  }
}
function flagSuspiciousIp(ip, reason) {
  const cleanIp = typeof ip === "string" ? ip.trim() : "";
  if (!cleanIp || cleanIp === "Unavailable") return;
  const nowMs = Date.now();
  for (const [knownIp, expiresAtMs] of suspiciousIpLedger) {
    if (expiresAtMs <= nowMs) {
      suspiciousIpLedger.delete(knownIp);
      suspiciousIpReasons.delete(knownIp);
    }
  }
  while (suspiciousIpLedger.size >= SUSPICIOUS_IP_MAX_ENTRIES) {
    const oldestKey = suspiciousIpLedger.keys().next().value;
    if (typeof oldestKey !== "string") break;
    suspiciousIpLedger.delete(oldestKey);
    suspiciousIpReasons.delete(oldestKey);
  }
  const cleanReason = reason.trim().slice(0, 180);
  const existingReasons = suspiciousIpReasons.get(cleanIp) ?? [];
  if (cleanReason && !existingReasons.includes(cleanReason) && existingReasons.length < 5) {
    existingReasons.push(cleanReason);
  }
  suspiciousIpReasons.set(cleanIp, existingReasons);
  suspiciousIpLedger.set(cleanIp, nowMs + SUSPICIOUS_IP_TTL_MS);
}
function lookupSuspiciousIp(ip) {
  const cleanIp = typeof ip === "string" ? ip.trim() : "";
  if (!cleanIp) return { blocklisted: false, reasons: [] };
  const expiresAtMs = suspiciousIpLedger.get(cleanIp);
  if (expiresAtMs === void 0) return { blocklisted: false, reasons: [] };
  if (expiresAtMs <= Date.now()) {
    suspiciousIpLedger.delete(cleanIp);
    suspiciousIpReasons.delete(cleanIp);
    return { blocklisted: false, reasons: [] };
  }
  return {
    blocklisted: true,
    reasons: [...suspiciousIpReasons.get(cleanIp) ?? []]
  };
}
var ENVELOPE_FRESHNESS_WINDOW_MS = 60 * 1e3;
var NONCE_TTL_MS = 15 * 60 * 1e3;
var NONCE_CACHE_MAX_ENTRIES = 5e3;
var seenEnvelopeNonces = /* @__PURE__ */ new Map();
function sha256HexLower(input) {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex").toLowerCase();
}
function normalizePlatformKey(value) {
  const folded = value.replace(/"/g, "").trim().toLowerCase();
  if (!folded) return "";
  if (/windows|win32|win64|winnt/.test(folded)) return "windows";
  if (/mac|macintosh|macintel/.test(folded)) return "macos";
  if (/android/.test(folded)) return "android";
  if (/ipad/.test(folded)) return "ipados";
  if (/iphone|ios/.test(folded)) return "ios";
  if (/chrome ?os|cros/.test(folded)) return "chromeos";
  if (/linux|x11/.test(folded)) return "linux";
  return "";
}
function rememberEnvelopeNonce(nonce, nowMs) {
  for (const [knownNonce, expiresAtMs] of seenEnvelopeNonces) {
    if (expiresAtMs <= nowMs) seenEnvelopeNonces.delete(knownNonce);
  }
  const seenAtMs = seenEnvelopeNonces.get(nonce);
  if (seenAtMs !== void 0 && seenAtMs > nowMs) return true;
  while (seenEnvelopeNonces.size >= NONCE_CACHE_MAX_ENTRIES) {
    const oldestKey = seenEnvelopeNonces.keys().next().value;
    if (typeof oldestKey !== "string") break;
    seenEnvelopeNonces.delete(oldestKey);
  }
  seenEnvelopeNonces.set(nonce, nowMs + NONCE_TTL_MS);
  return false;
}
function verifySecurityEnvelope(args) {
  const { envelope, headers, hardwareId, nowMs } = args;
  const reasons = [];
  let tamperedRequest = false;
  const headerSignature = readRequestHeader(headers, "x-intel-signature");
  const headerNonce = readRequestHeader(headers, "x-intel-nonce");
  const headerTimestamp = readRequestHeader(headers, "x-intel-timestamp");
  const envNonce = typeof envelope?.nonce === "string" ? envelope.nonce.trim() : "";
  const requestNonce = (envNonce || headerNonce).slice(0, 128);
  const envSignature = typeof envelope?.signature === "string" && envelope.signature.trim() ? envelope.signature.trim() : headerSignature;
  const envTimestamp = typeof envelope?.timestamp === "number" && Number.isFinite(envelope.timestamp) ? envelope.timestamp : Number.parseFloat(headerTimestamp);
  const timestamp = Number.isFinite(envTimestamp) && envTimestamp > 0 ? envTimestamp : 0;
  const envelopeUserAgent = typeof envelope?.userAgent === "string" ? envelope.userAgent.trim() : "";
  const envelopePlatform = typeof envelope?.platform === "string" ? envelope.platform.trim() : "";
  const envelopeScreenResolution = typeof envelope?.screenResolution === "string" ? envelope.screenResolution.trim() : "";
  const envelopeTimezone = typeof envelope?.timezone === "string" ? envelope.timezone.trim() : "";
  if (envelope && envSignature && timestamp > 0 && requestNonce) {
    const canonical = [
      "INTEL_ENVELOPE_V1",
      String(timestamp),
      requestNonce,
      hardwareId,
      envelopeUserAgent,
      envelopePlatform,
      envelopeScreenResolution,
      envelopeTimezone
    ].join("|");
    if (sha256HexLower(canonical) !== envSignature.toLowerCase()) {
      tamperedRequest = true;
      reasons.push("Payload integrity hash mismatch");
    }
  }
  if (timestamp > 0 && Math.abs(nowMs - timestamp) > ENVELOPE_FRESHNESS_WINDOW_MS) {
    tamperedRequest = true;
    reasons.push("Expired or replayed payload timestamp (>60s)");
  }
  let replayDetected = false;
  if (requestNonce) {
    replayDetected = rememberEnvelopeNonce(requestNonce, nowMs);
    if (replayDetected) reasons.push("Duplicate payload nonce (Replay Attack detected)");
  }
  const headerUserAgent = readRequestHeader(headers, "user-agent");
  if (headerUserAgent && envelopeUserAgent && headerUserAgent !== envelopeUserAgent) {
    tamperedRequest = true;
    reasons.push("HTTP User-Agent header contradicts JS payload");
  }
  const clientHintPlatform = readRequestHeader(headers, "sec-ch-ua-platform");
  const payloadPlatformKey = normalizePlatformKey(envelopePlatform);
  const clientHintPlatformKey = normalizePlatformKey(clientHintPlatform);
  const androidEquivalent = /android/i.test(headerUserAgent) && (payloadPlatformKey === "linux" && clientHintPlatformKey === "android" || payloadPlatformKey === "android" && clientHintPlatformKey === "linux");
  const chromeOsEquivalent = /cros/i.test(headerUserAgent) && (payloadPlatformKey === "linux" && clientHintPlatformKey === "chromeos" || payloadPlatformKey === "chromeos" && clientHintPlatformKey === "linux");
  const platformPairCompatible = androidEquivalent || chromeOsEquivalent;
  if (payloadPlatformKey && clientHintPlatformKey && payloadPlatformKey !== clientHintPlatformKey && !platformPairCompatible) {
    tamperedRequest = true;
    reasons.push("HTTP User-Agent header contradicts JS payload");
  }
  return {
    tamperedRequest,
    replayDetected,
    requestIntegrityReason: Array.from(new Set(reasons)).join("; "),
    requestNonce
  };
}
function normalizeLegacySuspectScore(rawSuspectScore) {
  if (!Number.isFinite(rawSuspectScore)) return 0;
  if (rawSuspectScore <= 10) return Math.max(0, rawSuspectScore);
  return Math.max(0, Math.min(10, Math.round(rawSuspectScore / 10)));
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
  const incognitoAlias = typeof input?.incognito === "boolean" || typeof input?.isIncognito === "boolean" || typeof input?.privateMode === "boolean" ? Boolean(input?.incognito ?? input?.isIncognito ?? input?.privateMode) : void 0;
  const incognitoMethod = typeof input?.incognitoMethod === "string" && input.incognitoMethod.trim() ? input.incognitoMethod.trim().slice(0, 120) : void 0;
  const idbDurabilityRatio = typeof input?.idbDurabilityRatio === "number" && Number.isFinite(input.idbDurabilityRatio) ? Number(input.idbDurabilityRatio) : void 0;
  const opfsFlushMs = typeof input?.opfsFlushMs === "number" && Number.isFinite(input.opfsFlushMs) ? Number(input.opfsFlushMs) : void 0;
  return {
    browser: safeStr(input?.browser, "Unknown"),
    os: safeStr(input?.os, "Unknown"),
    deviceType,
    platform: safeStr(input?.platform, "Unavailable"),
    screenResolution: safeStr(input?.screenResolution, "Unavailable"),
    pixelRatio: safeStr(input?.pixelRatio, "Unavailable"),
    language: safeStr(input?.language, "Unavailable"),
    timezone: safeStr(input?.timezone, "Unavailable"),
    incognito: incognitoAlias,
    isIncognito: incognitoAlias,
    privateMode: incognitoAlias,
    incognitoMethod,
    idbDurabilityRatio,
    opfsFlushMs
  };
}
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
var app = express();
app.set("trust proxy", true);
app.use(cookieParser());
app.use((_req, res, next) => {
  res.setHeader("Permissions-Policy", "compute-pressure=*");
  next();
});
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
app.use(express.json({ limit: "512kb" }));
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
var TIMEZONE_ALIAS_MAP = {
  "Asia/Calcutta": "Asia/Kolkata",
  "Asia/Katmandu": "Asia/Kathmandu",
  "Asia/Saigon": "Asia/Ho_Chi_Minh",
  "Asia/Rangoon": "Asia/Yangon",
  "Europe/Kiev": "Europe/Kyiv",
  "Europe/Uzhgorod": "Europe/Kyiv",
  "Europe/Zaporozhye": "Europe/Kyiv",
  "US/Eastern": "America/New_York",
  "US/Central": "America/Chicago",
  "US/Mountain": "America/Denver",
  "US/Pacific": "America/Los_Angeles"
};
function normalizeTimezone(tz) {
  if (!tz || typeof tz !== "string") return "";
  const trimmed = tz.trim();
  if (!trimmed) return "";
  return TIMEZONE_ALIAS_MAP[trimmed] || trimmed;
}
function normalizeServerTimezoneId(tz) {
  if (!tz || typeof tz !== "string") return "";
  const canonical = normalizeTimezone(tz).toLowerCase();
  if (!canonical || canonical === "unknown" || canonical === "unavailable") return "";
  return SERVER_TIMEZONE_ALIAS_MAP[canonical] || canonical;
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
function sanitizeAndReinforceSecuritySignals(raw, browserDevice, hardwareSignals, location, ipTimezoneHint, recognitionSource, classification, velocity, incognitoContext = {}, requestContext = {}) {
  const safeStrArray = (arr) => Array.isArray(arr) ? arr.filter((item) => typeof item === "string" && item.trim().length > 0).map((s) => s.trim().slice(0, 180)).slice(0, 10) : [];
  const webdriver = Boolean(raw?.webdriver);
  const cdpDetected = Boolean(raw?.cdpDetected);
  const isHeadless = Boolean(raw?.isHeadless);
  const botReason = typeof raw?.botReason === "string" && raw.botReason.trim() ? raw.botReason.trim().slice(0, 200) : "";
  const botSignals = safeStrArray(raw?.botSignals);
  const clientAutomationDetected = Boolean(raw?.isBot || webdriver || cdpDetected);
  const botClassification = requestContext.botClassification ?? classifyBotTraffic(
    requestContext.headers,
    { org: location.org, isp: location.isp, asn: location.asn },
    { isBot: clientAutomationDetected, isHeadless, webdriver, cdpDetected, botSignals }
  );
  const botSubtype = botClassification.subtype;
  const spoofedCrawler = botClassification.subtype === "bad_bot" && botClassification.label === "Spoofed Crawler";
  const isBot = Boolean(
    clientAutomationDetected || botSubtype === "bad_bot" || botSubtype === "ai_agent"
  );
  const browserTimezone = typeof raw?.browserTimezone === "string" && raw.browserTimezone.trim() ? raw.browserTimezone.trim().slice(0, 80) : browserDevice.timezone || "UTC";
  const ipTimezone = ipTimezoneHint || (typeof raw?.ipTimezone === "string" && raw.ipTimezone.trim() && raw.ipTimezone !== "Unavailable" ? raw.ipTimezone.trim().slice(0, 80) : "Unavailable");
  const normBrowserTz = normalizeServerTimezoneId(browserTimezone);
  const normIpTz = normalizeServerTimezoneId(ipTimezone);
  const serverTzMismatch = Boolean(normBrowserTz && normIpTz && normBrowserTz !== normIpTz);
  const timezoneMismatch = Boolean(raw?.timezoneMismatch) || serverTzMismatch;
  const isCloudOrDatacenterNetwork = classification.isDatacenterOrHosting || Boolean(location.isVpnOrHosting);
  const isGpuMaskedOrUnavailable = !hardwareSignals.gpuVendor || hardwareSignals.gpuVendor === "Unavailable" || /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuVendor) || !hardwareSignals.gpuRenderer || hardwareSignals.gpuRenderer === "Unavailable" || /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuRenderer);
  const datacenterAsn = classification.isConsumerBroadband ? false : isCloudOrDatacenterNetwork;
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
  const clientTzCanonical = normalizeTimezone(browserTimezone);
  const ipTzCanonical = normalizeTimezone(ipTimezone === "Unavailable" ? "" : ipTimezone);
  const hasTzMismatch = Boolean(
    clientTzCanonical && ipTzCanonical && clientTzCanonical.toLowerCase() !== ipTzCanonical.toLowerCase()
  );
  const tamperDetected = Boolean(raw?.tamperDetected || requestContext.tamperedRequest);
  const tamperReasons = safeStrArray(raw?.tamperReasons);
  if (requestContext.tamperedRequest && requestContext.requestIntegrityReason && !tamperReasons.includes(requestContext.requestIntegrityReason)) {
    tamperReasons.unshift(requestContext.requestIntegrityReason);
    tamperReasons.splice(10);
  }
  const incognitoLikely = Boolean(raw?.incognitoLikely);
  const storageQuotaMb = typeof raw?.storageQuotaMb === "number" && Number.isFinite(raw.storageQuotaMb) && raw.storageQuotaMb > 0 ? Math.round(raw.storageQuotaMb) : null;
  const webrtcCandidateIp = typeof raw?.webrtcCandidateIp === "string" && raw.webrtcCandidateIp.trim() ? raw.webrtcCandidateIp.trim().slice(0, 64) : null;
  const webrtcDetail = typeof raw?.webrtcDetail === "string" && raw.webrtcDetail.trim() ? raw.webrtcDetail.trim().slice(0, 200) : "";
  const privacyProtected = Boolean(raw?.privacyProtected);
  const privacyDetail = typeof raw?.privacyDetail === "string" && raw.privacyDetail.trim() ? raw.privacyDetail.trim().slice(0, 200) : "";
  const canvasFarblingDetected = Boolean(raw?.canvasFarblingDetected);
  const isVirtualMachine = Boolean(raw?.isVirtualMachine);
  const isOsTampered = Boolean(raw?.isOsTampered);
  const vmReason = typeof raw?.vmReason === "string" && raw.vmReason.trim() ? raw.vmReason.trim().slice(0, 200) : "";
  const incognitoMethod = typeof raw?.incognitoMethod === "string" && raw.incognitoMethod.trim() ? raw.incognitoMethod.trim().slice(0, 120) : "";
  const headroomGiB = typeof raw?.headroomGiB === "number" && Number.isFinite(raw.headroomGiB) ? Number(raw.headroomGiB) : null;
  const idbDurabilityRatio = typeof raw?.idbDurabilityRatio === "number" && Number.isFinite(raw.idbDurabilityRatio) ? Number(raw.idbDurabilityRatio) : null;
  const opfsFlushMs = typeof raw?.opfsFlushMs === "number" && Number.isFinite(raw.opfsFlushMs) ? Number(raw.opfsFlushMs) : null;
  const cloudOrMaskedGpu = Boolean(
    raw?.cloudOrMaskedGpu
  );
  const emulatorDetected = Boolean(raw?.emulatorDetected);
  const emulatorReason = typeof raw?.emulatorReason === "string" && raw.emulatorReason.trim() ? raw.emulatorReason.trim().slice(0, 200) : "";
  const tamperedRequest = Boolean(requestContext.tamperedRequest);
  const replayDetected = Boolean(requestContext.replayDetected);
  const requestIntegrityReason = typeof requestContext.requestIntegrityReason === "string" ? requestContext.requestIntegrityReason.trim().slice(0, 240) : "";
  const requestNonce = typeof requestContext.requestNonce === "string" ? requestContext.requestNonce.slice(0, 128) : "";
  const torExitNode = Boolean(requestContext.torExitNode);
  const ipBlocklisted = Boolean(requestContext.ipBlocklisted);
  const ipBlocklistReasons = Array.isArray(requestContext.ipBlocklistReasons) ? requestContext.ipBlocklistReasons.filter((reason) => typeof reason === "string" && reason.trim().length > 0).map((reason) => reason.trim().slice(0, 180)).slice(0, 5) : [];
  let persistenceMode = "First-Party Cookie";
  if (recognitionSource === "Hardware Fingerprint (Cookie-less / Incognito)") {
    persistenceMode = "Hardware ID Recovered";
  } else if (incognitoLikely) {
    persistenceMode = "Private / Restricted Storage";
  }
  const incognitoOrCleared = Boolean(raw?.incognitoOrCleared) || recognitionSource === "Hardware Fingerprint (Cookie-less / Incognito)" || persistenceMode === "Hardware ID Recovered";
  const clientReportedIncognito = Boolean(incognitoContext.clientReportedIncognito) || incognitoLikely;
  const serverCrossModeIncognito = Boolean(
    !incognitoContext.hadPersistentClientState && (incognitoContext.existingHwidVisitor || incognitoContext.crossSessionEphemeral)
  );
  const isIncognito = Boolean(clientReportedIncognito || serverCrossModeIncognito);
  const tierFor = (score) => score >= 7 ? "High" : score >= 3 ? "Medium" : "Low";
  const levelFor = (score) => score >= 7 ? "high" : score >= 3 ? "medium" : "low";
  const incognitoScore = isIncognito ? 4 : 0;
  const incognitoSignal = {
    id: "incognito",
    title: "Incognito / Private Browsing",
    status: isIncognito ? "Incognito / Private Mode" : "Standard Window",
    scoreOutOf10: incognitoScore,
    riskLabel: `${tierFor(incognitoScore)} Risk \u2022 ${incognitoScore}/10`,
    level: levelFor(incognitoScore),
    // The physical proof has to match the verdict: when the client probe itself reported a
    // private context we can quote its method, but when the verdict comes only from the
    // server's cross-session correlation the client advertised (or had) disk-backed storage,
    // so quoting that method would contradict the tile.
    detail: isIncognito ? clientReportedIncognito ? `Ephemeral RAM storage detected (${incognitoMethod || "In-memory LevelDB / 10 GiB decoy quota"})` : "Returning hardware ID (hwid) detected with wiped cookies & localStorage \u2014 ephemeral cookie jar" : `Persistent disk-backed storage verified (${incognitoMethod || "Standard profile"})`
  };
  const botScore = botSubtype === "bad_bot" ? spoofedCrawler ? 10 : 9 : botSubtype === "ai_agent" ? 8 : botSubtype === "good_bot" ? 2 : 0;
  const botStatus = botSubtype === "bad_bot" ? spoofedCrawler ? "Spoofed Crawler" : "Bot / Automated" : botSubtype === "ai_agent" ? "AI Agent \xB7 Cloud Browser" : botSubtype === "good_bot" ? "Good Bot \xB7 Search Crawler" : "Verified Human";
  const botDetail = botSubtype === "human" ? "Verified human interactive session" : botSubtype === "ai_agent" ? `${botClassification.provider} ${botClassification.label} \u2014 ${botClassification.reasons[0] || KNOWN_AI_CRAWLER_REASON}` : botSubtype === "good_bot" ? `${botClassification.provider} ${botClassification.label} verified against its official network \u2014 ${botClassification.reasons[1] || "ASN / organisation match"}` : botReason || botClassification.reasons[0] || (spoofedCrawler ? "Crawler user-agent claimed from a network that does not belong to the operator" : "WebDriver / CDP automation runtime detected");
  const botSignal = {
    id: "bot",
    title: "Bot & Automation Detection",
    status: botStatus,
    scoreOutOf10: botScore,
    riskLabel: `${tierFor(botScore)} Risk \u2022 ${botScore}/10`,
    level: levelFor(botScore),
    detail: botDetail
  };
  const isDatacenterAsn = datacenterAsn;
  const ispBrand = classification.brandName || location.isp || "Unknown ISP";
  const asnSuffix = location.asn !== "Unknown" ? ` \u2022 ${location.asn}` : "";
  const asnLabel = location.asn && location.asn !== "Unknown" ? /^AS/i.test(location.asn) ? location.asn.toUpperCase() : `AS${location.asn}` : "AS unknown";
  const asnOrOrg = `${asnLabel} \xB7 ${location.org !== "Unknown" ? location.org : ispBrand}`;
  const vpnScore = torExitNode ? 10 : ipBlocklisted ? 9 : isDatacenterAsn && hasTzMismatch ? 8 : isDatacenterAsn ? 6 : hasTzMismatch ? 5 : 0;
  const vpnStatus = torExitNode ? "Tor Exit Node" : ipBlocklisted ? "Blocklisted IP" : isDatacenterAsn ? "VPN / Datacenter Proxy" : hasTzMismatch ? "VPN / Timezone Relay" : "Standard ISP";
  const vpnDetail = torExitNode ? `Confirmed active Tor exit relay (${location.publicIp} \xB7 ${asnOrOrg})` : ipBlocklisted ? "IP flagged on abuse / tamper blocklist" : isDatacenterAsn && hasTzMismatch ? `Datacenter ASN (${ispBrand}${asnSuffix}) combined with a browser/IP timezone mismatch (${clientTzCanonical} vs ${ipTzCanonical})` : isDatacenterAsn ? `Datacenter / hosting ASN detected on ${ispBrand}${asnSuffix}` : hasTzMismatch ? `Browser timezone (${browserTimezone}) differs from IP geolocation timezone (${ipTimezone})` : `${ispBrand} \u2022 ${classification.networkType} (${asnLabel}) verified against browser timezone ${browserTimezone}`;
  const vpnSignal = {
    id: "vpn",
    title: "VPN / Proxy & Network Type",
    status: vpnStatus,
    scoreOutOf10: vpnScore,
    riskLabel: `${tierFor(vpnScore)} Risk \u2022 ${vpnScore}/10`,
    level: levelFor(vpnScore),
    detail: vpnDetail
  };
  const isVm = isVirtualMachine;
  const isTampered = isOsTampered;
  const cloudContainerVm = datacenterAsn && (isGpuMaskedOrUnavailable || cloudOrMaskedGpu);
  const vmLike = isVm || cloudContainerVm;
  const vmScore = tamperedRequest || replayDetected ? 10 : emulatorDetected ? 8 : vmLike ? datacenterAsn && isGpuMaskedOrUnavailable ? 8 : 7 : isTampered ? 6 : 0;
  const vmStatus = tamperedRequest || replayDetected ? "Tampered / Replayed" : emulatorDetected ? "Mobile Emulator" : vmLike ? "Virtual Machine / VM" : isTampered ? "Spoofed Environment" : "Physical Hardware";
  const vmDetail = tamperedRequest || replayDetected ? requestIntegrityReason || "Sealed request envelope failed verification" : emulatorDetected ? emulatorReason || vmReason || "Mobile emulator / simulator runtime detected" : vmLike ? vmReason || (cloudContainerVm ? `Cloud container on ${ispBrand}${asnSuffix} exposed an unavailable / masked GPU` : "Hypervisor CPUID / virtualised GPU footprint detected") : isTampered ? vmReason || tamperReasons[0] || "Operating-system / User-Agent tampering detected" : "Unmasked physical GPU & consistent OS platform verified";
  const vmSignal = {
    id: "vm",
    title: "Virtual Machine & OS Integrity",
    status: vmStatus,
    scoreOutOf10: vmScore,
    riskLabel: `${tierFor(vmScore)} Risk \u2022 ${vmScore}/10`,
    level: levelFor(vmScore),
    detail: vmDetail
  };
  const smartSignals = {
    incognito: incognitoSignal,
    bot: botSignal,
    vpn: vpnSignal,
    vm: vmSignal
  };
  const integrityViolation = Boolean(tamperedRequest || replayDetected);
  const rawCompositePoints = (isBot ? 5 : isHeadless ? 4 : 0) + (isDatacenterAsn ? 3 : hasTzMismatch ? 2 : 0) + (vmScore > 0 ? 3 : 0) + (isIncognito ? 2 : 0) + (integrityViolation ? 2 : 0);
  const suspectScore = Math.min(10, rawCompositePoints);
  const riskLevel = tierFor(suspectScore);
  const riskBadgeText = `${riskLevel} Risk \u2022 ${suspectScore}/10`;
  const riskFactors = [];
  if (isBot) {
    riskFactors.push(
      `Automated browser / bot runtime detected (+5): ${botReason || botClassification.reasons[0] || botSignals[0] || "WebDriver / CDP automation signatures"}`
    );
  } else if (isHeadless) {
    riskFactors.push(
      `Headless browser environment (+4): ${botReason || "no physical display attached"}`
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
  if (integrityViolation) {
    riskFactors.push(
      `Sealed request envelope failed verification (+2): ${requestIntegrityReason || "tampered or replayed payload"}`
    );
  }
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
    ...{
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
          typeof raw?.incognitoConfidence === "number" && Number.isFinite(raw.incognitoConfidence) ? raw.incognitoConfidence : 0
        )
      ),
      incognitoDetail: typeof raw?.incognitoDetail === "string" ? raw.incognitoDetail.trim().slice(0, 240) : "",
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
      visitsLastHour: velocity.visitsLastHour
    }
  };
}
app.post("/api/visitor/identify", async (req, res) => {
  try {
    const requestBody = req.body || {};
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
    } = requestBody;
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
    const classification = classifyIspNetwork(location.isp, location.org, location.asn);
    const cookieVid = req.cookies?.intel_http_vid;
    const cookieToken = req.cookies?.intel_http_token;
    let existingVisitor;
    let recognitionSource = "New First-Party ID";
    let existingHwidVisitor = false;
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
        existingHwidVisitor = true;
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
    const oneHourAgoMs = Date.now() - 3600 * 1e3;
    const lastHourVisitRows = rawVisits.filter((r) => {
      const visitedAtMs = Date.parse(String(r.visited_at_utc || ""));
      return Number.isFinite(visitedAtMs) && visitedAtMs >= oneHourAgoMs;
    });
    const lastHourIpSet = /* @__PURE__ */ new Set();
    for (const lastHourRow of lastHourVisitRows) {
      const lastHourIp = String(lastHourRow.public_ip || "").trim();
      if (lastHourIp && lastHourIp !== "Unavailable") lastHourIpSet.add(lastHourIp);
    }
    const currentVisitIp = String(location.publicIp || "").trim();
    if (currentVisitIp && currentVisitIp !== "Unavailable") {
      lastHourIpSet.add(currentVisitIp);
    }
    const visitsLastHour = Math.max(1, lastHourVisitRows.length);
    const distinctIpsLastHour = lastHourIpSet.size;
    const bodyVisitorId = storageVerified ? storedVisitorId ?? null : null;
    const historyBackupValid = Boolean(validBackupForStats);
    const hadPersistentClientState = Boolean(cookieVid || bodyVisitorId || historyBackupValid);
    const clientReportedIncognito = Boolean(
      requestBody.incognito ?? requestBody.isIncognito ?? requestBody.privateMode ?? requestBody.browserInfo?.incognito ?? requestBody.browserInfo?.isIncognito ?? requestBody.telemetry?.incognito ?? requestBody.telemetry?.isIncognito ?? rawSecuritySignals?.isIncognito ?? rawSecuritySignals?.incognito ?? rawSecuritySignals?.privateMode ?? rawSecuritySignals?.incognitoLikely
    );
    let crossSessionEphemeral = false;
    if (!hadPersistentClientState && !existingHwidVisitor && hardwareId) {
      try {
        const sevenDaysAgoUtc = new Date(Date.now() - 7 * 24 * 3600 * 1e3).toISOString();
        const earlierDeviceVisit = db.prepare(
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
        ).get(
          visitorId,
          hardwareId,
          location.publicIp,
          browserDevice.screenResolution,
          browserDevice.browser,
          browserDevice.os,
          sevenDaysAgoUtc
        );
        crossSessionEphemeral = Boolean(earlierDeviceVisit);
      } catch {
        crossSessionEphemeral = false;
      }
    }
    const securitySignalsInput = rawSecuritySignals || requestBody.incognitoMethod ? {
      ...rawSecuritySignals ?? {},
      // Top-level method spelling is honoured when securitySignals omitted it.
      incognitoMethod: rawSecuritySignals?.incognitoMethod ?? requestBody.incognitoMethod
    } : rawSecuritySignals;
    const rawRequestHeaders = req.headers;
    const envelopeVerdict = verifySecurityEnvelope({
      envelope: requestBody.securityEnvelope,
      headers: rawRequestHeaders,
      hardwareId,
      nowMs
    });
    const botClassification = classifyBotTraffic(
      rawRequestHeaders,
      { org: location.org, isp: location.isp, asn: location.asn },
      {
        isBot: Boolean(
          rawSecuritySignals?.isBot || rawSecuritySignals?.webdriver || rawSecuritySignals?.cdpDetected
        ),
        isHeadless: Boolean(rawSecuritySignals?.isHeadless),
        webdriver: Boolean(rawSecuritySignals?.webdriver),
        cdpDetected: Boolean(rawSecuritySignals?.cdpDetected),
        botSignals: Array.isArray(rawSecuritySignals?.botSignals) ? rawSecuritySignals.botSignals : []
      }
    );
    void refreshTorBulkList();
    const torExitNode = isTorBulkListed(location.publicIp) || await isTorExitNode(location.publicIp);
    if (envelopeVerdict.tamperedRequest) {
      flagSuspiciousIp(
        location.publicIp,
        envelopeVerdict.requestIntegrityReason || "Tampered request payload"
      );
    }
    if (envelopeVerdict.replayDetected) {
      flagSuspiciousIp(location.publicIp, "Replayed payload nonce");
    }
    if (botClassification.subtype === "bad_bot" && botClassification.label === "Spoofed Crawler") {
      flagSuspiciousIp(location.publicIp, "Spoofed crawler user-agent");
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
        crossSessionEphemeral
      },
      {
        headers: rawRequestHeaders,
        tamperedRequest: envelopeVerdict.tamperedRequest,
        replayDetected: envelopeVerdict.replayDetected,
        requestIntegrityReason: envelopeVerdict.requestIntegrityReason,
        requestNonce: envelopeVerdict.requestNonce,
        torExitNode,
        ipBlocklisted: blocklist.blocklisted,
        ipBlocklistReasons: blocklist.reasons,
        botClassification
      }
    );
    const visitHistory = rawVisits.map((r) => {
      const storedSuspectScore = typeof r.suspect_score === "number" && Number.isFinite(r.suspect_score) ? normalizeLegacySuspectScore(r.suspect_score) : null;
      const isCurrentVisitRow = String(r.page_load_id || "") === safePageLoadId;
      const rowSuspectScore = storedSuspectScore !== null ? storedSuspectScore : isCurrentVisitRow ? securitySignals.suspectScore : 0;
      const rowRiskLevel = rowSuspectScore >= 7 ? "High" : rowSuspectScore >= 3 ? "Medium" : "Low";
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
      historyBackup,
      // Top-level mirrors so clients can read the 4-signal verdict without digging.
      isIncognito: securitySignals.isIncognito,
      incognito: securitySignals.isIncognito,
      suspectScore: securitySignals.suspectScore,
      riskLevel: securitySignals.riskLevel,
      riskBadgeText: securitySignals.riskBadgeText,
      smartSignals: securitySignals.smartSignals
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
    const storedSuspectScore = typeof row.suspect_score === "number" && Number.isFinite(row.suspect_score) ? normalizeLegacySuspectScore(row.suspect_score) : 0;
    const storedRecognitionSource = typeof row.recognition_source === "string" && row.recognition_source.trim() ? row.recognition_source : "Cookie";
    const rowRiskLevel = storedSuspectScore >= 7 ? "High" : storedSuspectScore >= 3 ? "Medium" : "Low";
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

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
var TOR_OPERATOR_ASN_SET = /* @__PURE__ */ new Set([
  "AS215125",
  // Church of Cyberology / Nothing to Hide
  "AS60729",
  // Zwiebelfreunde e.V. / Torservers.net
  "AS208323",
  // Foundation for Applied Privacy
  "AS396507",
  // Emerald Onion
  "AS200052",
  // Artikel10 e.V.
  "AS206848",
  // CCC Stuttgart / Chaos Computer Club
  "AS205100",
  // F3 Netze e.V.
  "AS199695"
  // Nos Oignons
]);
var TOR_OPERATOR_ORG_PATTERN = /\b(church of cyberology|cyberology|nothing to hide|nothingtohide|hart voor internetvrijheid|zwiebelfreunde|torservers|emerald onion|emeraldonion|applied privacy|applied-privacy|nos oignons|nos-oignons|artikel10|f3\s?netze|ccc stuttgart|r0cket|tor\s?exit|tor\s?relay)\b/i;
var TOR_OPERATOR_IPV4_CIDRS = ["192.42.116.0/24"];
var TOR_OPERATOR_IPV6_PREFIXES = ["2001:67c:e60::/48", "2a02:898:256::/48"];
var TOR_OPERATOR_REVERSE_DNS_PATTERN = /\b(tor-?exit|tor-?relay|exit-?node|nothingtohide\.nl|hartvoorinternetvrijheid\.nl|cyberology\.(nl|church)|torservers\.net|emeraldonion\.org|applied-privacy\.net|artikel10\.org|nos-oignons\.net|tor\.r0cket\.net)\b/i;
var VPN_PROXY_PATTERN = /\b(vpn|nordvpn|expressvpn|surfshark|cyberghost|private internet access|proton\s?vpn|mullvad|windscribe|ipvanish|hide\.?me|hola vpn|psiphon|packet hub|packethub|tor ?guard|proxy|socks5|smart dns)\b/i;
var MOBILE_CARRIER_PATTERN = /\b(mobile|cellular|wireless|5g|4g|lte|t-mobile|tmobile|verizon wireless|cellco|vodafone|orange s\.?a|telefonica|movistar|claro|tim s\.?p\.?a|mtn)\b/i;
function matchesTorOperatorAsn(asn) {
  const clean = typeof asn === "string" ? asn.trim().toUpperCase() : "";
  if (!clean) return false;
  return TOR_OPERATOR_ASN_SET.has(clean.startsWith("AS") ? clean : `AS${clean}`);
}
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
  const mobileHomeMatch = () => matchConsumerRule("Verizon 5G Home", "Cellular / 5G", [6167, 22394], /cellco|verizon wireless/i) || matchConsumerRule("T-Mobile 5G Home", "Cellular / 5G", [21928], /t-mobile|tmobile/i);
  const satelliteMatch = () => matchConsumerRule("Starlink (SpaceX)", "Satellite", [14593], /starlink|spacex/i);
  const residentialMatch = () => (
    // US consumer broadband (Residential Broadband)
    matchConsumerRule("Xfinity (Comcast)", "Residential Broadband", [7922, 7015, 7016], /comcast|xfinity/i) || matchConsumerRule("Spectrum (Charter)", "Residential Broadband", [20115, 11426, 10796], /charter|spectrum/i) || matchConsumerRule("AT&T Fiber", "Residential Broadband", [7018, 20057], /at&t|att services|sbcglobal/i) || matchConsumerRule("Verizon Fios", "Residential Broadband", [701, 19262], /fios|mci communications|verizon online/i) || matchConsumerRule("Optimum", "Residential Broadband", [6128, 19108], /optimum|cablevision|altice|suddenlink/i) || matchConsumerRule("Cox", "Residential Broadband", [22773], /\bcox\b/i) || matchConsumerRule("Frontier / CenturyLink", "Residential Broadband", [5650, 209], null) || matchConsumerRule("Google Fiber", "Residential Broadband", [16591], /google fiber|gfiber/i) || // India consumer broadband (Residential Broadband)
    matchConsumerRule("Jio (Reliance Jio)", "Residential Broadband", [55836], /reliance jio|\bjio\b/i) || matchConsumerRule("Airtel Xstream", "Residential Broadband", [24560, 45609, 9498], /bharti airtel|\bairtel\b/i) || matchConsumerRule("ACT Fibernet", "Residential Broadband", [24309], /act fibernet|atria convergence/i) || matchConsumerRule("BSNL Broadband", "Residential Broadband", [9829], /\bbsnl\b|bharat sanchar/i) || matchConsumerRule("Tata Play / Hathway", "Residential Broadband", [], /tata play|tata sky broadband|hathway|excitel/i)
  );
  const asnTokenHits = Array.from(asnNumbers).map((n) => `AS${n}`);
  const torAsnHit = asnTokenHits.find((token) => matchesTorOperatorAsn(token));
  const torOrgHit = TOR_OPERATOR_ORG_PATTERN.test(keywordHaystack);
  if (torAsnHit !== void 0 || torOrgHit) {
    return {
      brandName: cleanIsp && !/^unknown( isp)?$/i.test(cleanIsp) ? cleanIsp : cleanOrg && !/^unknown( isp)?$/i.test(cleanOrg) ? cleanOrg : "Tor Relay Operator",
      networkType: "Tor Exit / Anonymity Network",
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: torAsnHit !== void 0 ? `Tor operator ASN ${torAsnHit}` : "Tor operator organisation"
    };
  }
  const cloudAsnHit = Array.from(asnNumbers).find((n) => CLOUD_PROVIDER_ASN_NUMBERS.has(n));
  const cloudKeywords = /google llc|google cloud|amazonaws|cloudflare|digitalocean|hetzner|m247|datacamp|linode|ovh|choopa|vultr|leaseweb|hostinger|contabo|akamai|oracle cloud|alibaba|aliyun|tencent cloud/i;
  if (cloudAsnHit !== void 0 || cloudKeywords.test(keywordHaystack)) {
    return {
      brandName: "Cloud Provider / Datacenter",
      networkType: "Cloud / Datacenter",
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: cloudAsnHit !== void 0 ? `ASN AS${cloudAsnHit}` : `ISP metadata keyword ${String(cloudKeywords)}`
    };
  }
  if (VPN_PROXY_PATTERN.test(keywordHaystack)) {
    return {
      brandName: cleanIsp || cleanOrg || "VPN / Proxy Provider",
      networkType: "VPN / Proxy Relay",
      isConsumerBroadband: false,
      isDatacenterOrHosting: false,
      matchedReason: "VPN / proxy provider keyword"
    };
  }
  const mobileHome = mobileHomeMatch();
  if (mobileHome) return mobileHome;
  if (MOBILE_CARRIER_PATTERN.test(keywordHaystack)) {
    return {
      brandName: cleanIsp || cleanOrg || "Mobile Carrier",
      networkType: "Mobile Carrier",
      isConsumerBroadband: false,
      isDatacenterOrHosting: false,
      matchedReason: "Cellular carrier keyword"
    };
  }
  const satellite = satelliteMatch();
  if (satellite) return satellite;
  const residential = residentialMatch();
  if (residential) return residential;
  return {
    brandName: cleanIsp && !/^(unknown|unknown isp|n\/a)$/i.test(cleanIsp) ? cleanIsp : cleanOrg && !/^(unknown|unknown isp|n\/a)$/i.test(cleanOrg) ? cleanOrg : "Unknown ISP",
    networkType: "Unknown Network",
    isConsumerBroadband: false,
    isDatacenterOrHosting: false,
    matchedReason: null
  };
}
function applyNetworkOverrides(base, context) {
  const torNetwork = context.torExit || context.torOperatorHint || context.isTorBrowserClient || base.networkType === "Tor Exit / Anonymity Network";
  if (torNetwork) {
    return {
      ...base,
      networkType: "Tor Exit / Anonymity Network",
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || "Tor anonymity network"
    };
  }
  if (context.aiAgentDetected && base.networkType === "Cloud / Datacenter") {
    return {
      ...base,
      networkType: "AI Agent Cloud Network",
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || "AI agent cloud infrastructure"
    };
  }
  if (context.datacenterVm && base.networkType !== "Cloud / Datacenter") {
    return {
      ...base,
      networkType: "Cloud / Datacenter",
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || "Cloud VM / masked GPU footprint"
    };
  }
  if (context.vpnSuspected && base.networkType === "Residential Broadband") {
    return {
      ...base,
      networkType: "VPN / Proxy Relay",
      isConsumerBroadband: false,
      matchedReason: base.matchedReason || "VPN indicator on a residential line"
    };
  }
  if (base.networkType === "Residential Broadband" && !base.isConsumerBroadband) {
    return { ...base, networkType: "Unknown Network" };
  }
  return base;
}
function readRequestHeader(headers, name) {
  if (!headers) return "";
  const direct = headers[name.toLowerCase()];
  const raw = Array.isArray(direct) ? direct.join(", ") : direct;
  return typeof raw === "string" ? raw.trim() : "";
}
function detectProxyHeaders(headers, resolvedIp) {
  const reasons = [];
  if (!headers) return { detected: false, reasons };
  if (readRequestHeader(headers, "proxy-authorization")) {
    reasons.push("Proxy-Authorization header");
  }
  if (readRequestHeader(headers, "proxy-connection")) {
    reasons.push("Proxy-Connection header");
  }
  const via = readRequestHeader(headers, "via").toLowerCase();
  if (via && !/varnish|vegur|cloudflare|akamai|fastly|vercel|netlify/.test(via)) {
    reasons.push(`Via header (${via.slice(0, 80)})`);
  }
  const forwarded = readRequestHeader(headers, "forwarded");
  if (forwarded) {
    for (const segment of forwarded.split(/[,;]/)) {
      const match = /for="?\[?([0-9a-f:.]+)\]?"?/i.exec(segment.trim());
      const hop = match?.[1]?.replace(/^::ffff:/, "");
      if (hop && hop !== resolvedIp && isPublicRoutableIp(hop)) {
        reasons.push(`Forwarded header names upstream relay ${hop}`);
        break;
      }
    }
  }
  const xff = readRequestHeader(headers, "x-forwarded-for");
  if (xff) {
    const hops = new Set(
      xff.split(",").map((hop) => normalizeIpCandidate(hop)).filter((hop) => Boolean(hop) && isPublicRoutableIp(hop))
    );
    if (hops.size >= 3) {
      reasons.push(`X-Forwarded-For chain with ${hops.size} public hops`);
    }
  }
  return { detected: reasons.length > 0, reasons };
}
function detectUaFamily(userAgent) {
  const ua = userAgent.toLowerCase();
  if (!ua) return "";
  if (/edg\//.test(ua)) return "edge";
  if (/opr\/|opera/.test(ua)) return "opera";
  if (/firefox\/|fxios/.test(ua)) return "firefox";
  if (/chrome\/|crios|chromium\//.test(ua)) return "chrome";
  if (/safari\//.test(ua)) return "safari";
  if (/^curl\//.test(ua)) return "curl";
  if (/postmanruntime/.test(ua)) return "postman";
  if (/python-requests|python-urllib|aiohttp/.test(ua)) return "python";
  if (/^wget\//.test(ua)) return "wget";
  if (/^node-fetch|undici|axios/.test(ua)) return "node";
  return "";
}
function detectUaOs(userAgent) {
  const ua = userAgent.toLowerCase();
  if (/windows nt|win32|win64/.test(ua)) return "windows";
  if (/android/.test(ua)) return "android";
  if (/iphone|ipad|ipod/.test(ua)) return "ios";
  if (/macintosh|mac os x/.test(ua)) return "macos";
  if (/cros/.test(ua)) return "chromeos";
  if (/linux|x11/.test(ua)) return "linux";
  return "";
}
function userAgentsCompatible(headerUserAgent, payloadUserAgent) {
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
var BOT_SIGNATURE_KEYID_PROVIDERS = [
  ["openai", "OpenAI"],
  ["anthropic", "Anthropic"],
  ["perplexity", "Perplexity"],
  ["google", "Google"],
  ["microsoft", "Microsoft"],
  ["apple", "Apple"],
  ["amazon", "Amazon"],
  ["cloudflare", "Cloudflare"],
  ["web-bot-auth", "Web Bot Auth Directory"]
];
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
  const signatureInput = readRequestHeader(headers, "signature-input");
  const signatureHeader = readRequestHeader(headers, "signature");
  if (signatureInput && signatureHeader) {
    const keyIdMatch = /keyid\s*=\s*"([^"]+)"/i.exec(signatureInput);
    const keyId = keyIdMatch ? keyIdMatch[1].trim().slice(0, 80) : "";
    const keyIdLower = keyId.toLowerCase();
    const namedOperator = BOT_SIGNATURE_KEYID_PROVIDERS.find(
      ([needle]) => keyIdLower.includes(needle)
    );
    return {
      subtype: "ai_agent",
      label: "Web Bot Auth Agent",
      provider: namedOperator ? namedOperator[1] : keyId || "RFC 9421 Signer",
      category: "Autonomous Agent",
      confidence: 0.9,
      reasons: [
        "RFC 9421 Signature / Signature-Input headers present (Web Bot Auth)",
        keyId ? `Agent key identifier: ${keyId}` : "Agent key identifier not published"
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
  const headerAnomaly = isDesktopChromeOrSafari && missingFetchMetadata && !acceptLanguage;
  if (client.isBot || client.webdriver || client.cdpDetected || AUTOMATION_UA_PATTERN.test(ua) || headerAnomaly) {
    const reasons = [];
    if (client.isBot) reasons.push("Client reported an automated runtime");
    if (client.webdriver) reasons.push("WebDriver handshake detected");
    if (client.cdpDetected) reasons.push("Chrome DevTools Protocol binding detected");
    if (AUTOMATION_UA_PATTERN.test(ua)) reasons.push("Automation framework signature in user-agent");
    if (headerAnomaly) {
      reasons.push("Desktop browser user-agent without accept-language or sec-fetch metadata");
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
var AI_BOT_CIDR_SOURCES = [
  { id: "chatgpt-user", url: "https://openai.com/chatgpt-user.json" },
  { id: "gptbot", url: "https://openai.com/gptbot.json" },
  { id: "searchbot", url: "https://openai.com/searchbot.json" },
  {
    id: "google-common",
    url: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"
  },
  {
    id: "google-user-triggered",
    url: "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json"
  },
  {
    id: "google-user-triggered-google",
    url: "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json"
  }
];
var AI_BOT_CIDR_SYNC_INTERVAL_MS = 6 * 60 * 60 * 1e3;
var AI_BOT_CIDR_TIMEOUT_MS = 1e4;
var AI_AUTH_DIRECTORY_TIMEOUT_MS = 1500;
var AI_AUTH_DIRECTORY_TTL_MS = 60 * 60 * 1e3;
var AI_FORWARD_DNS_TIMEOUT_MS = 1200;
var AI_FORWARD_DNS_TTL_MS = 60 * 60 * 1e3;
var AI_VERDICT_TABLE_MAX_ENTRIES = 1e4;
var aiBotPrefixTable = /* @__PURE__ */ new Map();
var aiBotCidrLastSyncMs = 0;
var aiBotCidrSyncInFlight = null;
var aiBotCidrTimer = null;
var aiAuthDirectoryCache = /* @__PURE__ */ new Map();
var aiForwardConfirmedDnsCache = /* @__PURE__ */ new Map();
function extractAiPrefixes(payload) {
  const prefixes = [];
  const visit = (value, depth) => {
    if (depth > 4 || value === null || typeof value !== "object") return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    const record = value;
    for (const key of ["ipv4Prefix", "ipv6Prefix", "prefix"]) {
      const raw = record[key];
      if (typeof raw === "string" && raw.includes("/")) prefixes.push(raw.trim());
    }
    for (const nested of Object.values(record)) {
      if (nested && typeof nested === "object") visit(nested, depth + 1);
    }
  };
  visit(payload, 0);
  return Array.from(new Set(prefixes));
}
async function syncAiBotCidrs() {
  const next = /* @__PURE__ */ new Map();
  await Promise.all(
    AI_BOT_CIDR_SOURCES.map(async (source) => {
      const body = await fetchTextWithTimeout(
        source.url,
        AI_BOT_CIDR_TIMEOUT_MS,
        "application/json"
      );
      if (!body) return;
      try {
        const prefixes = extractAiPrefixes(JSON.parse(body));
        if (prefixes.length > 0) next.set(source.id, prefixes);
      } catch {
      }
    })
  );
  if (next.size === 0) return;
  const merged = new Map(aiBotPrefixTable);
  for (const [id, prefixes] of next) merged.set(id, prefixes);
  aiBotPrefixTable = merged;
  aiBotCidrLastSyncMs = Date.now();
}
function runAiBotCidrSync() {
  if (aiBotCidrSyncInFlight) return aiBotCidrSyncInFlight;
  aiBotCidrSyncInFlight = syncAiBotCidrs().catch(() => void 0).finally(() => {
    aiBotCidrSyncInFlight = null;
  });
  return aiBotCidrSyncInFlight;
}
function ensureAiBotCidrSync() {
  if (aiBotCidrTimer === null) {
    void runAiBotCidrSync();
    aiBotCidrTimer = setInterval(() => {
      void runAiBotCidrSync();
    }, AI_BOT_CIDR_SYNC_INTERVAL_MS);
    const handle = aiBotCidrTimer;
    if (typeof handle.unref === "function") handle.unref();
    return;
  }
  if (Date.now() - aiBotCidrLastSyncMs >= AI_BOT_CIDR_SYNC_INTERVAL_MS) {
    void runAiBotCidrSync();
  }
}
try {
  ensureAiBotCidrSync();
} catch {
}
function matchesAiPrefixTable(ip, ids) {
  return ids.some((id) => ipMatchesCidrList(ip, aiBotPrefixTable.get(id) ?? []));
}
function firstHttpsUrl(text) {
  const match = /https?:\/\/[^\s",;)]+/i.exec(text);
  return match ? match[0].replace(/[.;]+$/, "") : null;
}
function resolveSignatureAgentOperator(host, label) {
  const lowerHost = host.toLowerCase();
  const lowerLabel = label.toLowerCase();
  if (lowerHost === "agent.bot.goog" || lowerHost.endsWith(".bot.goog") || lowerHost.endsWith("bot.goog") || lowerLabel === "g") {
    return "google";
  }
  if (lowerHost.endsWith("openai.com") || lowerHost.endsWith("chatgpt.com")) return "openai";
  if (lowerHost.endsWith("perplexity.ai")) return "perplexity";
  if (lowerHost.endsWith("anthropic.com") || lowerHost.endsWith("claude.ai")) return "anthropic";
  if (lowerHost.endsWith("browserbase.com")) return "browserbase";
  if (lowerHost.endsWith("anchorbrowser.io")) return "anchorbrowser";
  if (lowerHost.endsWith("x.ai") || lowerHost.endsWith("grok.com")) return "xai";
  if (lowerHost.endsWith("meta.com") || lowerHost.endsWith("facebook.com")) return "meta";
  return null;
}
function parseWebBotAuthHeaders(headers) {
  const signatureInput = readRequestHeader(headers, "signature-input");
  const signature = readRequestHeader(headers, "signature");
  const signatureAgent = readRequestHeader(headers, "signature-agent");
  const labelMatch = /^\s*([A-Za-z0-9_-]+)\s*=/.exec(signatureInput);
  const keyIdMatch = /keyid\s*=\s*"([^"]+)"/i.exec(signatureInput);
  const tagMatch = /tag\s*=\s*"([^"]+)"/i.exec(signatureInput);
  const agentUrl = signatureAgent ? firstHttpsUrl(signatureAgent) : null;
  let agentHost = "";
  if (agentUrl) {
    try {
      agentHost = new URL(agentUrl).hostname.toLowerCase();
    } catch {
      agentHost = "";
    }
  }
  const label = labelMatch ? labelMatch[1] : "";
  return {
    present: Boolean(signatureInput && signature),
    label,
    keyId: keyIdMatch ? keyIdMatch[1].trim().slice(0, 160) : "",
    tag: tagMatch ? tagMatch[1].trim().slice(0, 80) : "",
    agentUrl,
    agentHost,
    operator: resolveSignatureAgentOperator(agentHost, label)
  };
}
async function fetchWebBotAuthDirectory(agentUrl) {
  let origin = "";
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
    "application/json"
  );
  if (!body) return null;
  let clientName = "";
  let trigger = null;
  const visit = (value, depth) => {
    if (depth > 4 || value === null || typeof value !== "object") return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    const record = value;
    if (!clientName) {
      const name = record.client_name ?? record.clientName;
      if (typeof name === "string" && name.trim()) clientName = name.trim().slice(0, 120);
    }
    if (trigger === null) {
      const rawTrigger = record.trigger;
      if (typeof rawTrigger === "string" && /fetcher|crawler/i.test(rawTrigger)) {
        trigger = /fetcher/i.test(rawTrigger) ? "fetcher" : "crawler";
      }
    }
    for (const nested of Object.values(record)) {
      if (nested && typeof nested === "object") visit(nested, depth + 1);
    }
  };
  try {
    visit(JSON.parse(body), 0);
  } catch {
    return null;
  }
  if (!clientName && trigger === null) return null;
  if (aiAuthDirectoryCache.size > 500) aiAuthDirectoryCache.clear();
  aiAuthDirectoryCache.set(origin, {
    clientName,
    trigger,
    expiresAtMs: nowMs + AI_AUTH_DIRECTORY_TTL_MS
  });
  return { clientName, trigger };
}
async function resolveForwardConfirmedReverseDns(ip) {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return [];
  const nowMs = Date.now();
  const cached = aiForwardConfirmedDnsCache.get(normalized);
  if (cached && cached.expiresAtMs > nowMs) return cached.names;
  const reverseNames = await resolveTorReverseDns(normalized);
  const isV4 = isIpv4Literal(normalized);
  const confirmed = [];
  const forwardLookup = async (name) => {
    if (!/^[a-z0-9.-]+$/i.test(name)) return [];
    let timeoutHandle;
    try {
      const lookup = (isV4 ? dns.resolve4(name) : dns.resolve6(name)).catch(
        () => []
      );
      const timeout = new Promise((resolve) => {
        timeoutHandle = setTimeout(() => resolve([]), AI_FORWARD_DNS_TIMEOUT_MS);
      });
      const addresses = await Promise.race([lookup, timeout]);
      return Array.isArray(addresses) ? addresses : [];
    } catch {
      return [];
    } finally {
      if (timeoutHandle !== void 0) clearTimeout(timeoutHandle);
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
    expiresAtMs: nowMs + AI_FORWARD_DNS_TTL_MS
  });
  return confirmed;
}
function hostMatchesSuffix(names, suffixes) {
  return names.some((name) => {
    const lower = name.toLowerCase().replace(/\.$/, "");
    return suffixes.some((suffix) => lower === suffix || lower.endsWith(`.${suffix}`));
  });
}
function asnDigits(asn) {
  if (typeof asn !== "string") return "";
  const match = /(\d{1,10})/.exec(asn);
  return match ? match[1] : "";
}
function asnIn(asn, digits) {
  const value = asnDigits(asn);
  return value.length > 0 && digits.includes(value);
}
var GOOGLE_VERIFICATION_SUFFIXES = ["googlebot.com", "google.com"];
var OPENAI_VERIFICATION_SUFFIXES = ["openai.com", "chatgpt.com"];
var PERPLEXITY_VERIFICATION_SUFFIXES = ["perplexity.ai"];
var ANTHROPIC_VERIFICATION_SUFFIXES = ["anthropic.com", "claude.ai"];
var XAI_VERIFICATION_SUFFIXES = ["x.ai", "grok.com"];
var META_VERIFICATION_SUFFIXES = ["facebook.com", "meta.com", "fb.com"];
var GCP_ASNS = ["15169", "396982"];
var XAI_ASNS = ["400562", "13414"];
var META_ASNS = ["32934", "63293"];
var AWS_ASNS = ["16509", "14618"];
var AZURE_ASNS = ["8075"];
var PERPLEXITY_ASNS = ["209242"];
var NO_AI_AGENT = {
  detected: false,
  agentId: null,
  agentName: "",
  operator: "",
  executionMode: null,
  verified: false,
  confidence: "Medium",
  riskScore: 0,
  evidence: []
};
function aiAgentResult(partial) {
  return {
    detected: true,
    riskScore: partial.riskScore ?? (partial.agentId === "impostor-spoof" ? 10 : 8),
    ...partial
  };
}
async function resolveAiAgentIdentity(input) {
  const ua = input.userAgent || readRequestHeader(input.headers, "user-agent");
  if (!ua) return NO_AI_AGENT;
  const webBotAuth = parseWebBotAuthHeaders(input.headers);
  const referer = `${readRequestHeader(input.headers, "referer")} ${readRequestHeader(
    input.headers,
    "origin"
  )}`;
  const networkHaystack = [input.network.org, input.network.isp, input.network.asn].filter((part) => typeof part === "string" && part.trim().length > 0).join(" \xB7 ");
  let confirmedNamesPromise = null;
  const confirmedNames = () => {
    if (confirmedNamesPromise === null) {
      confirmedNamesPromise = resolveForwardConfirmedReverseDns(input.publicIp);
    }
    return confirmedNamesPromise;
  };
  const gpuRenderer = (input.client.gpuRenderer || "").toLowerCase();
  const maskedGpu = !gpuRenderer || gpuRenderer === "unavailable" || /swiftshader|llvmpipe|mesa|software|generic|^standard/.test(gpuRenderer);
  const idbRatio = typeof input.client.idbDurabilityRatio === "number" ? input.client.idbDurabilityRatio : null;
  const clientAutomation = Boolean(
    input.client.isBot || input.client.webdriver || input.client.cdpDetected || input.client.isHeadless
  );
  const desktopChrome = /chrome\//i.test(ua) && !/mobile|android|iphone|ipad/i.test(ua);
  const screen = (input.client.screenResolution || "").toLowerCase();
  const claudeComputerUseViewport = screen.includes("1024x768") || screen.includes("1280x800") || screen.includes("1280\xD7800");
  const silentCloudTelemetry = Boolean(
    input.client.isVirtualMachine || idbRatio !== null && idbRatio > 0.95 && maskedGpu || desktopChrome && clientAutomation && maskedGpu
  );
  const signatureEvidence = webBotAuth.present ? [
    "RFC 9421 Signature / Signature-Input headers present (Web Bot Auth)",
    webBotAuth.label ? `Signature label: ${webBotAuth.label}` : "",
    webBotAuth.agentUrl ? `Signature-Agent: ${webBotAuth.agentUrl}` : "",
    webBotAuth.keyId ? `keyid: ${webBotAuth.keyId}` : ""
  ].filter(Boolean) : [];
  const directoryHint = webBotAuth.agentUrl ? await fetchWebBotAuthDirectory(webBotAuth.agentUrl) : null;
  const directoryEvidence = directoryHint ? [
    directoryHint.clientName ? `Agent directory client_name: ${directoryHint.clientName}` : "",
    directoryHint.trigger ? `Agent trigger: ${directoryHint.trigger}` : ""
  ].filter(Boolean) : [];
  const remoteBrowserUa = /firecrawl|browserbase|browser[-_ ]?use|skyvern|multion|hyperbrowser|steel[-_ ]?browser|airtop|\bnotte\b|lightpanda|browserless|scrapingbee|scrapfly|zenrows|brightdata|oxylabs|\bzyte\b/i;
  if (remoteBrowserUa.test(ua)) {
    const remoteOperator = /firecrawl/i.test(ua) ? "Firecrawl" : /browserbase/i.test(ua) ? "Browserbase" : /browser[-_ ]?use/i.test(ua) ? "Browser Use" : /skyvern/i.test(ua) ? "Skyvern" : /multion/i.test(ua) ? "MultiOn" : /hyperbrowser/i.test(ua) ? "Hyperbrowser" : /steel[-_ ]?browser/i.test(ua) ? "Steel" : /airtop/i.test(ua) ? "Airtop" : /notte/i.test(ua) ? "Notte" : /lightpanda/i.test(ua) ? "Lightpanda" : /browserless/i.test(ua) ? "Browserless" : /scrapingbee/i.test(ua) ? "ScrapingBee" : /scrapfly/i.test(ua) ? "Scrapfly" : /zenrows/i.test(ua) ? "ZenRows" : /brightdata/i.test(ua) ? "Bright Data" : /oxylabs/i.test(ua) ? "Oxylabs" : "Zyte";
    return aiAgentResult({
      agentId: "remote-browser",
      agentName: `${remoteOperator} Remote Browser Agent`,
      operator: remoteOperator,
      executionMode: "Remote Browser Agent",
      verified: false,
      confidence: clientAutomation ? "High" : "Medium",
      evidence: [
        `Remote browser agent user-agent: ${ua.slice(0, 120)}`,
        clientAutomation ? "Automation runtime flags confirmed the harness (WebDriver / CDP / headless)" : "User-agent claim without an automation flag",
        networkHaystack ? `Network identity: ${networkHaystack}` : ""
      ].filter(Boolean)
    });
  }
  if (/\bgooglebot\b/i.test(ua)) {
    const googleCidr = matchesAiPrefixTable(input.publicIp, [
      "google-common",
      "google-user-triggered",
      "google-user-triggered-google"
    ]);
    const googleDnsNames = await confirmedNames();
    const googleDns = hostMatchesSuffix(googleDnsNames, GOOGLE_VERIFICATION_SUFFIXES);
    const googleRangesLoaded = (aiBotPrefixTable.get("google-common")?.length ?? 0) > 0;
    if (googleCidr || googleDns) {
      return aiAgentResult({
        agentId: "gemini",
        agentName: "Googlebot (Verified Google Crawler)",
        operator: "Google LLC",
        executionMode: "Autonomous Crawler",
        verified: true,
        confidence: "Verified",
        evidence: [
          `Googlebot user-agent: ${ua.slice(0, 120)}`,
          googleCidr ? "Source IP matched a Google official crawler CIDR range" : "",
          googleDns ? "FCrDNS matched *.googlebot.com / *.google.com" : ""
        ].filter(Boolean)
      });
    }
    const googleOwnedNetwork = asnIn(input.network.asn, GCP_ASNS) || /google/i.test(input.network.org || "");
    if (googleRangesLoaded && !googleOwnedNetwork) {
      return aiAgentResult({
        agentId: "impostor-spoof",
        agentName: "Spoofed Google Bot Impostor (Unverified IP)",
        operator: "Unverified Google claim",
        executionMode: "Spoofed Impostor",
        verified: false,
        confidence: "Verified",
        evidence: [
          `Googlebot user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not inside Google's official crawler ranges`,
          "Forward-confirmed reverse DNS does not resolve to googlebot.com / google.com"
        ]
      });
    }
    return NO_AI_AGENT;
  }
  const geminiUa = /Gemini-Deep-Research|GoogleAgent-Mariner|Google-NotebookLM|Google-CloudVertexBot|Google-Extended|GoogleOther(-Image|-Video)?|Google-InspectionTool/i.test(
    ua
  );
  if (webBotAuth.operator === "google" || geminiUa) {
    const googleCidr = matchesAiPrefixTable(input.publicIp, [
      "google-common",
      "google-user-triggered",
      "google-user-triggered-google"
    ]);
    const googleDnsNames = await confirmedNames();
    const googleDns = hostMatchesSuffix(googleDnsNames, GOOGLE_VERIFICATION_SUFFIXES);
    const googleRangesLoaded = (aiBotPrefixTable.get("google-common")?.length ?? 0) > 0;
    const verified = webBotAuth.operator === "google" || googleCidr || googleDns;
    if (geminiUa && !verified && googleRangesLoaded) {
      return aiAgentResult({
        agentId: "impostor-spoof",
        agentName: "Spoofed Google Gemini Agent (Unverified IP)",
        operator: "Unverified Google claim",
        executionMode: "Spoofed Impostor",
        verified: false,
        confidence: "Verified",
        evidence: [
          `Gemini / Google agent user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not inside Google's official crawler ranges`,
          "Forward-confirmed reverse DNS does not resolve to googlebot.com / google.com"
        ]
      });
    }
    return aiAgentResult({
      agentId: "gemini",
      agentName: directoryHint?.clientName || (verified ? "Google Gemini (Mariner / Deep Research)" : "Google Gemini / Cloud Agent (GCP VM)"),
      operator: "Google LLC",
      executionMode: webBotAuth.operator === "google" ? "RFC 9421 Signed Agent" : geminiUa && !clientAutomation ? "User-Triggered Fetcher" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : googleRangesLoaded || googleDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "google" ? signatureEvidence : [],
        ...geminiUa ? [`Google AI agent user-agent: ${ua.slice(0, 120)}`] : [],
        ...googleCidr ? ["Source IP matched a Google official crawler CIDR range"] : [],
        ...googleDns ? ["FCrDNS matched *.googlebot.com / *.google.com"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  if ((asnIn(input.network.asn, GCP_ASNS) || hostMatchesSuffix(await confirmedNames(), ["googleusercontent.com"])) && (webBotAuth.present || silentCloudTelemetry)) {
    return aiAgentResult({
      agentId: "gemini",
      agentName: "Google Gemini / Cloud Agent (GCP VM)",
      operator: "Google LLC",
      executionMode: webBotAuth.present ? "RFC 9421 Signed Agent" : "Silent Cloud VM Browser",
      verified: webBotAuth.present,
      confidence: webBotAuth.present ? "Verified" : "High",
      evidence: [
        ...signatureEvidence,
        ...asnIn(input.network.asn, GCP_ASNS) ? [`Google Cloud ASN (${input.network.asn}) hosting the browser`] : ["Reverse DNS matched *.googleusercontent.com"],
        ...silentCloudTelemetry ? ["Cloud-VM browser telemetry (masked WebGL / ephemeral storage)"] : []
      ]
    });
  }
  const grokUa = /GrokBot|xAI-GrokBot|Grok-Search|xAI-Bot|\bGrok\b/i.test(ua);
  const grokReferer = /grok\.com|x\.ai/i.test(referer);
  if (webBotAuth.operator === "xai" || grokUa || grokReferer) {
    const xaiDnsNames = await confirmedNames();
    const xaiDns = hostMatchesSuffix(xaiDnsNames, XAI_VERIFICATION_SUFFIXES);
    const xaiAsn = asnIn(input.network.asn, XAI_ASNS);
    const verified = webBotAuth.operator === "xai" || xaiDns || xaiAsn;
    return aiAgentResult({
      agentId: "grok",
      agentName: directoryHint?.clientName || "xAI Grok Bot",
      operator: "xAI",
      executionMode: webBotAuth.operator === "xai" ? "RFC 9421 Signed Agent" : grokReferer && !grokUa ? "Silent Cloud VM Browser" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : xaiDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "xai" ? signatureEvidence : [],
        ...grokUa ? [`Grok user-agent: ${ua.slice(0, 120)}`] : [],
        ...grokReferer ? [`Referer / Origin points at grok.com or x.ai`] : [],
        ...xaiAsn ? [`xAI / X Corp ASN ${input.network.asn}`] : [],
        ...xaiDns ? ["FCrDNS matched *.x.ai / *.grok.com"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  const museUa = /\bMuseBot\b|\bMuse\b|Meta-ExternalAgent|Meta-ExternalFetcher|FacebookBot/i.test(ua);
  if (webBotAuth.operator === "meta" || museUa) {
    const metaDnsNames = await confirmedNames();
    const metaDns = hostMatchesSuffix(metaDnsNames, META_VERIFICATION_SUFFIXES);
    const metaAsn = asnIn(input.network.asn, META_ASNS);
    const verified = webBotAuth.operator === "meta" || metaDns || metaAsn;
    return aiAgentResult({
      agentId: "muse",
      agentName: directoryHint?.clientName || "Meta Muse",
      operator: "Meta Platforms",
      executionMode: webBotAuth.operator === "meta" ? "RFC 9421 Signed Agent" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : metaDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "meta" ? signatureEvidence : [],
        ...museUa ? [`Meta / Muse user-agent: ${ua.slice(0, 120)}`] : [],
        ...metaAsn ? [`Meta Platforms ASN ${input.network.asn}`] : [],
        ...metaDns ? ["FCrDNS matched *.facebook.com / *.meta.com"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  if (asnIn(input.network.asn, META_ASNS) && desktopChrome && silentCloudTelemetry) {
    return aiAgentResult({
      agentId: "muse",
      agentName: "Meta Muse (Cloud VM Browser Agent)",
      operator: "Meta Platforms",
      executionMode: "Silent Cloud VM Browser",
      verified: false,
      confidence: "High",
      evidence: [
        `Meta Platforms ASN (${input.network.asn}) hosting a desktop Chrome session`,
        "Virtual machine / cloud browser telemetry (masked WebGL, Linux platform or ephemeral storage)"
      ]
    });
  }
  const perplexityUa = /PerplexityBot|Perplexity-User/i.test(ua);
  if (webBotAuth.operator === "perplexity" || perplexityUa) {
    const perplexityDnsNames = await confirmedNames();
    const perplexityDns = hostMatchesSuffix(
      perplexityDnsNames,
      PERPLEXITY_VERIFICATION_SUFFIXES
    );
    const perplexityAsn = asnIn(input.network.asn, PERPLEXITY_ASNS);
    const verified = webBotAuth.operator === "perplexity" || perplexityDns || perplexityAsn;
    return aiAgentResult({
      agentId: "perplexity",
      agentName: directoryHint?.clientName || "Perplexity AI Agent",
      operator: "Perplexity AI",
      executionMode: webBotAuth.operator === "perplexity" ? "RFC 9421 Signed Agent" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : perplexityDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "perplexity" ? signatureEvidence : [],
        ...perplexityUa ? [`Perplexity user-agent: ${ua.slice(0, 120)}`] : [],
        ...perplexityAsn ? [`Perplexity ASN ${input.network.asn}`] : [],
        ...perplexityDns ? ["FCrDNS matched *.perplexity.ai"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  if (asnIn(input.network.asn, AWS_ASNS) && clientAutomation && (webBotAuth.present || hostMatchesSuffix(await confirmedNames(), PERPLEXITY_VERIFICATION_SUFFIXES))) {
    return aiAgentResult({
      agentId: "perplexity",
      agentName: "Perplexity AI (PerplexityBot / Stealth Agent)",
      operator: "Perplexity AI",
      executionMode: webBotAuth.present ? "RFC 9421 Signed Agent" : "Silent Cloud VM Browser",
      verified: webBotAuth.present,
      confidence: webBotAuth.present ? "Verified" : "Medium",
      evidence: [
        ...signatureEvidence,
        `AWS ASN (${input.network.asn}) hosting a headless Chromium session`,
        "RFC 9421 headers or Perplexity network attribution"
      ]
    });
  }
  const openAiUa = /ChatGPT-User|OAI-SearchBot|GPTBot/i.test(ua);
  if (webBotAuth.operator === "openai" || openAiUa) {
    const openAiDnsNames = await confirmedNames();
    const openAiDns = hostMatchesSuffix(openAiDnsNames, OPENAI_VERIFICATION_SUFFIXES);
    const openAiCidr = matchesAiPrefixTable(input.publicIp, ["chatgpt-user", "gptbot", "searchbot"]);
    const openAiRangesLoaded = (aiBotPrefixTable.get("chatgpt-user")?.length ?? 0) > 0 || (aiBotPrefixTable.get("gptbot")?.length ?? 0) > 0;
    const verified = webBotAuth.operator === "openai" || openAiDns || openAiCidr;
    return aiAgentResult({
      agentId: "openai",
      agentName: directoryHint?.clientName || "OpenAI ChatGPT Agent / Operator",
      operator: "OpenAI",
      executionMode: webBotAuth.operator === "openai" ? "RFC 9421 Signed Agent" : /chatgpt-user/i.test(ua) ? "User-Triggered Fetcher" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : openAiRangesLoaded || openAiDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "openai" ? signatureEvidence : [],
        ...openAiUa ? [`OpenAI user-agent: ${ua.slice(0, 120)}`] : [],
        ...openAiCidr ? ["Source IP matched an official OpenAI JSON prefix list"] : [],
        ...openAiDns ? ["FCrDNS matched *.openai.com / *.chatgpt.com"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  if (asnIn(input.network.asn, AZURE_ASNS) && webBotAuth.present) {
    return aiAgentResult({
      agentId: "openai",
      agentName: "OpenAI ChatGPT Agent / Operator",
      operator: "OpenAI",
      executionMode: "RFC 9421 Signed Agent",
      verified: true,
      confidence: "Verified",
      evidence: [
        ...signatureEvidence,
        `Microsoft Azure ASN (${input.network.asn}) hosting the signed agent`
      ]
    });
  }
  const claudeUa = /Claude-User|Claude-SearchBot|ClaudeBot|anthropic-ai/i.test(ua);
  if (webBotAuth.operator === "anthropic" || claudeUa) {
    const anthropicDnsNames = await confirmedNames();
    const anthropicDns = hostMatchesSuffix(anthropicDnsNames, ANTHROPIC_VERIFICATION_SUFFIXES);
    const verified = webBotAuth.operator === "anthropic" || anthropicDns;
    if (claudeUa && !verified && anthropicDns) {
      return aiAgentResult({
        agentId: "impostor-spoof",
        agentName: "Spoofed Anthropic Claude Agent (Unverified IP)",
        operator: "Unverified Anthropic claim",
        executionMode: "Spoofed Impostor",
        verified: false,
        confidence: "Verified",
        evidence: [
          `Claude user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not on Anthropic infrastructure`
        ]
      });
    }
    return aiAgentResult({
      agentId: "claude",
      agentName: directoryHint?.clientName || "Anthropic Claude (Claude-User / Computer Use)",
      operator: "Anthropic",
      executionMode: webBotAuth.operator === "anthropic" ? "RFC 9421 Signed Agent" : /claude-user/i.test(ua) ? "User-Triggered Fetcher" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : anthropicDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "anthropic" ? signatureEvidence : [],
        ...claudeUa ? [`Claude user-agent: ${ua.slice(0, 120)}`] : [],
        ...anthropicDns ? ["FCrDNS matched *.anthropic.com / *.claude.ai"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  if ((asnIn(input.network.asn, AWS_ASNS) || asnIn(input.network.asn, GCP_ASNS)) && claudeComputerUseViewport && /llvmpipe|mesa|swiftshader|software/i.test(gpuRenderer) && clientAutomation) {
    return aiAgentResult({
      agentId: "claude",
      agentName: "Anthropic Claude (Claude-User / Computer Use)",
      operator: "Anthropic",
      executionMode: "Silent Cloud VM Browser",
      verified: false,
      confidence: "Medium",
      evidence: [
        `Cloud ASN (${input.network.asn}) hosting a Linux X11 / Xvfb framebuffer`,
        `Viewport ${input.client.screenResolution} matches a Claude computer-use desktop`,
        "Software WebGL renderer (llvmpipe / Mesa) with an automated session"
      ]
    });
  }
  const cloudBrowserOperator = webBotAuth.operator === "browserbase" ? { name: "Browserbase Cloud Agent", operator: "Browserbase" } : webBotAuth.operator === "anchorbrowser" ? { name: "Anchor Browser AI Agent", operator: "Anchor Browser" } : null;
  if (webBotAuth.present || cloudBrowserOperator) {
    const handle = webBotAuth.agentHost || webBotAuth.keyId || "unattributed signer";
    return aiAgentResult({
      agentId: "cloud-browser",
      agentName: directoryHint?.clientName || cloudBrowserOperator?.name || "AI Agent \xB7 Cloud Browser (RFC 9421 Signed)",
      operator: cloudBrowserOperator?.operator || "Unattributed Cloud Browser",
      executionMode: "RFC 9421 Signed Agent",
      verified: webBotAuth.present,
      confidence: webBotAuth.present ? "Verified" : "High",
      evidence: [
        ...signatureEvidence,
        ...cloudBrowserOperator ? [`Signature-Agent operator: ${handle}`] : [],
        ...!cloudBrowserOperator ? [`Signed agent handle: ${handle}`] : [],
        ...networkHaystack ? [`Network identity: ${networkHaystack}`] : [],
        ...directoryEvidence
      ]
    });
  }
  const officialBotClaim = /googlebot|googleother|gemini-deep-research|gptbot|chatgpt-user|perplexitybot|perplexity-user|claudebot|claude-user|grokbot|meta-externalagent|muse/i.test(
    ua
  );
  if (officialBotClaim) {
    return aiAgentResult({
      agentId: "impostor-spoof",
      agentName: "Spoofed AI Bot Impostor (Unverified IP)",
      operator: "Unverified AI crawler claim",
      executionMode: "Spoofed Impostor",
      verified: false,
      confidence: "Verified",
      evidence: [
        `Official AI crawler user-agent claim: ${ua.slice(0, 120)}`,
        `Source IP ${input.publicIp} could not be verified via CIDR or FCrDNS`
      ]
    });
  }
  return NO_AI_AGENT;
}
var EMULATOR_GPU_SIGNATURE_PATTERN = /android emulator opengl es translator|goldfish|ranchu|bluestacks|nox|ldplayer|memu|genymotion|virgl|apple software renderer/i;
var NON_ARM_ANDROID_PLATFORM_PATTERN = /linux x86|x86_64|i[3-6]86|win32|win64|macintel/i;
var IOS_DEVICE_UA_PATTERN = /(iphone|ipad|ipod)/i;
var IOS_FOREIGN_PLATFORM_PATTERN = /linux|win32|win64/i;
var IPHONE_OR_IPOD_UA_PATTERN = /(iphone|ipod)/i;
function parseScreenResolutionWidth(resolution) {
  const match = /(\d+)\s*[x×]\s*(\d+)/i.exec(resolution || "");
  if (match) {
    const width = Number.parseInt(match[1], 10);
    return Number.isFinite(width) && width > 0 ? width : 0;
  }
  const single = Number.parseInt(resolution || "", 10);
  return Number.isFinite(single) && single > 0 ? single : 0;
}
function classifyEmulatorFromSignals(input) {
  const ua = typeof input.userAgent === "string" ? input.userAgent : "";
  const claimedOs = typeof input.os === "string" ? input.os : "";
  const platform = (input.platform || "").trim();
  const maxTouchPoints = typeof input.maxTouchPoints === "number" ? Math.max(0, input.maxTouchPoints) : 0;
  const vendor = (input.gpuVendor || "").trim();
  const renderer = (input.gpuRenderer || "").trim();
  const gpuSignature = `${vendor} ${renderer}`;
  const claimsAndroid = /android/i.test(ua) || /android/i.test(claimedOs);
  const claimsIos = IOS_DEVICE_UA_PATTERN.test(ua) || /ipad|ios/i.test(claimedOs);
  if (claimsAndroid && NON_ARM_ANDROID_PLATFORM_PATTERN.test(platform)) {
    return {
      detected: true,
      reason: `Android user-agent on desktop ${platform} (emulator CPU profile)`
    };
  }
  if (claimsAndroid && maxTouchPoints === 0) {
    return {
      detected: true,
      reason: "Android user-agent reporting zero touch points (emulated input layer)"
    };
  }
  if (EMULATOR_GPU_SIGNATURE_PATTERN.test(gpuSignature)) {
    return {
      detected: true,
      reason: `Emulator GPU renderer (${renderer || vendor || "masked renderer"})`
    };
  }
  if (claimsIos) {
    if (IOS_FOREIGN_PLATFORM_PATTERN.test(platform)) {
      return { detected: true, reason: `iOS user-agent on ${platform} platform (simulator host)` };
    }
    if (maxTouchPoints === 0) {
      return {
        detected: true,
        reason: `iOS user-agent on ${platform || "desktop"} with zero touch points (simulator)`
      };
    }
  }
  const screenWidth = parseScreenResolutionWidth(input.screenResolution);
  if (IPHONE_OR_IPOD_UA_PATTERN.test(ua) && screenWidth >= 1e3) {
    return { detected: true, reason: `iPhone user-agent on a ${screenWidth}px desktop-width screen` };
  }
  return { detected: false, reason: "" };
}
var TOR_DNS_TIMEOUT_MS = 600;
var TOR_DOH_TIMEOUT_MS = 1200;
var TOR_DOH_ENDPOINTS = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"];
var TOR_BULK_LIST_URL = "https://check.torproject.org/torbulkexitlist";
var TOR_EXIT_ADDRESSES_URL = "https://check.torproject.org/exit-addresses";
var TOR_ONIONOO_DETAILS_URL = "https://onionoo.torproject.org/details";
var TOR_BULK_LIST_MAX_ENTRIES = 2e4;
var TOR_INTELLIGENCE_SYNC_INTERVAL_MS = 30 * 60 * 1e3;
var TOR_INTELLIGENCE_SYNC_TIMEOUT_MS = 1e4;
var TOR_LIVE_LOOKUP_TIMEOUT_MS = 1800;
var TOR_REVERSE_DNS_TIMEOUT_MS = 1200;
var TOR_VERDICT_CACHE_TTL_MS = 30 * 60 * 1e3;
var TOR_VERDICT_CACHE_MAX_ENTRIES = 5e3;
var TOR_OPERATOR_PREFIX_CACHE_TTL_MS = 6 * 60 * 60 * 1e3;
var torIpv4ExitSet = /* @__PURE__ */ new Set();
var torIpv6ExitSet = /* @__PURE__ */ new Set();
var torIpv6Prefix64Set = /* @__PURE__ */ new Set();
var torIpv6Prefix48Set = /* @__PURE__ */ new Set();
var torRelayMetadataMap = /* @__PURE__ */ new Map();
var torIntelligenceLastSyncMs = 0;
var torIntelligenceSyncInFlight = null;
var torIntelligenceTimer = null;
var torVerdictCache = /* @__PURE__ */ new Map();
var torReverseDnsCache = /* @__PURE__ */ new Map();
function normalizeIpAddress(rawIp) {
  if (typeof rawIp !== "string") return "";
  let value = rawIp.trim();
  if (!value) return "";
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);
  const zoneIndex = value.indexOf("%");
  if (zoneIndex >= 0) value = value.slice(0, zoneIndex);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (mapped) value = mapped[1];
  return value.toLowerCase();
}
function isIpv6Hextet(value) {
  return /^[0-9a-f]{1,4}$/.test(value);
}
function expandIpv6Address(ip) {
  let value = normalizeIpAddress(ip);
  if (!value || !value.includes(":")) return null;
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    if (lastColon < 0) return null;
    const tail2 = value.slice(lastColon + 1);
    if (!isIpv4Literal(tail2)) return null;
    const [a, b, c, d] = tail2.split(".").map((octet) => Number.parseInt(octet, 10));
    value = `${value.slice(0, lastColon + 1)}${(a << 8 | b).toString(16)}:${(c << 8 | d).toString(16)}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (halves.length === 2) {
    if (head.length + tail.length > 7) return null;
    const zeros = new Array(8 - head.length - tail.length).fill("0");
    const hextets = [...head, ...zeros, ...tail];
    if (!hextets.every(isIpv6Hextet)) return null;
    return hextets.map((hextet) => hextet.replace(/^0+(?=.)/, "")).join(":");
  }
  if (head.length !== 8 || !head.every(isIpv6Hextet)) return null;
  return head.map((hextet) => hextet.replace(/^0+(?=.)/, "")).join(":");
}
function ipv4ToInt(ip) {
  if (!isIpv4Literal(ip)) return null;
  const octets = ip.split(".").map((octet) => Number.parseInt(octet, 10));
  return octets[0] * 16777216 + octets[1] * 65536 + octets[2] * 256 + octets[3] >>> 0 >>> 0;
}
function ipv4MatchesCidr(ip, cidr) {
  const slash = cidr.indexOf("/");
  const base = (slash >= 0 ? cidr.slice(0, slash) : cidr).trim();
  const bits = slash >= 0 ? Number.parseInt(cidr.slice(slash + 1), 10) : 32;
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  if (bits === 0) return true;
  const mask = 4294967295 << 32 - bits >>> 0;
  return (ipInt & mask) >>> 0 === (baseInt & mask) >>> 0;
}
function ipv6MatchesCidr(ip, cidr) {
  const slash = cidr.lastIndexOf("/");
  const base = (slash >= 0 ? cidr.slice(0, slash) : cidr).trim();
  const bits = slash >= 0 ? Number.parseInt(cidr.slice(slash + 1), 10) : 128;
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return false;
  const ipExpanded = expandIpv6Address(ip);
  const baseExpanded = expandIpv6Address(base);
  if (!ipExpanded || !baseExpanded) return false;
  const ipHextets = ipExpanded.split(":");
  const baseHextets = baseExpanded.split(":");
  const fullHextets = Math.floor(bits / 16);
  for (let index = 0; index < fullHextets; index += 1) {
    if (ipHextets[index] !== baseHextets[index]) return false;
  }
  const remainingBits = bits % 16;
  if (remainingBits === 0) return true;
  const mask = 65535 << 16 - remainingBits & 65535;
  const ipValue = Number.parseInt(ipHextets[fullHextets], 16);
  const baseValue = Number.parseInt(baseHextets[fullHextets], 16);
  return (ipValue & mask) === (baseValue & mask);
}
function ipMatchesCidrList(ip, cidrList) {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return false;
  const isV4 = isIpv4Literal(normalized);
  for (const cidr of cidrList) {
    if (typeof cidr !== "string") continue;
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
function extractEmbeddedIpv4FromIpv6(ip) {
  const expanded = expandIpv6Address(ip);
  if (!expanded) return null;
  const tail = expanded.split(":").slice(4);
  if (tail.length !== 4 || !tail.every((hextet) => /^\d{1,3}$/.test(hextet))) return null;
  const octets = tail.map((hextet) => Number.parseInt(hextet, 10));
  if (octets.some((octet) => octet > 255)) return null;
  return octets.join(".");
}
function isTorOperatorPrefix(ip) {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return false;
  if (isIpv4Literal(normalized)) return ipMatchesCidrList(normalized, TOR_OPERATOR_IPV4_CIDRS);
  return ipMatchesCidrList(normalized, TOR_OPERATOR_IPV6_PREFIXES);
}
function splitTorAddressPort(entry) {
  const trimmed = entry.trim();
  if (!trimmed) return "";
  if (trimmed.startsWith("[")) {
    const close = trimmed.indexOf("]");
    if (close > 0) return trimmed.slice(1, close);
  }
  const firstColon = trimmed.indexOf(":");
  const lastColon = trimmed.lastIndexOf(":");
  if (firstColon > 0 && firstColon === lastColon) return trimmed.slice(0, lastColon);
  return trimmed;
}
async function fetchTextWithTimeout(url, timeoutMs, accept) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { accept }
    });
    if (!response.ok) return null;
    return await response.text();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
function torRelayMetadataFromOnionoo(relay) {
  return {
    nickname: typeof relay.nickname === "string" ? relay.nickname : "",
    fingerprint: typeof relay.fingerprint === "string" ? relay.fingerprint : "",
    as: typeof relay.as === "string" ? relay.as : void 0,
    asName: typeof relay.as_name === "string" ? relay.as_name : void 0,
    country: typeof relay.country === "string" ? relay.country : void 0,
    flags: Array.isArray(relay.flags) ? relay.flags.filter((flag) => typeof flag === "string") : []
  };
}
async function syncTorIntelligence() {
  const nextIpv4 = /* @__PURE__ */ new Set();
  const nextIpv6 = /* @__PURE__ */ new Set();
  const nextPrefix64 = /* @__PURE__ */ new Set();
  const nextPrefix48 = /* @__PURE__ */ new Set();
  const nextMetadata = /* @__PURE__ */ new Map();
  const remember = (key, metadata) => {
    if (!nextMetadata.has(key)) nextMetadata.set(key, metadata);
  };
  const addIpv4 = (rawIp, metadata) => {
    if (typeof rawIp !== "string") return;
    const ip = normalizeIpAddress(rawIp);
    if (!isIpv4Literal(ip)) return;
    nextIpv4.add(ip);
    if (metadata) remember(ip, metadata);
  };
  const addIpv6 = (rawIp, metadata) => {
    if (typeof rawIp !== "string") return;
    const ip = normalizeIpAddress(rawIp);
    const expanded = expandIpv6Address(ip);
    if (!expanded) return;
    nextIpv6.add(ip);
    nextIpv6.add(expanded);
    const hextets = expanded.split(":");
    nextPrefix64.add(hextets.slice(0, 4).join(":"));
    nextPrefix48.add(hextets.slice(0, 3).join(":"));
    if (metadata) {
      remember(ip, metadata);
      remember(expanded, metadata);
    }
  };
  const [bulkList, exitAddresses, onionoo] = await Promise.all([
    fetchTextWithTimeout(TOR_BULK_LIST_URL, TOR_INTELLIGENCE_SYNC_TIMEOUT_MS, "text/plain"),
    fetchTextWithTimeout(TOR_EXIT_ADDRESSES_URL, TOR_INTELLIGENCE_SYNC_TIMEOUT_MS, "text/plain"),
    fetchTextWithTimeout(
      `${TOR_ONIONOO_DETAILS_URL}?search=running:true&fields=nickname,fingerprint,or_addresses,exit_addresses,flags,as,as_name,country`,
      TOR_INTELLIGENCE_SYNC_TIMEOUT_MS,
      "application/json"
    )
  ]);
  if (bulkList) {
    for (const line of bulkList.split(/\r?\n/)) {
      const candidate = line.trim();
      if (!candidate || candidate.startsWith("#")) continue;
      addIpv4(candidate, null);
      if (nextIpv4.size >= TOR_BULK_LIST_MAX_ENTRIES) break;
    }
  }
  if (exitAddresses) {
    let fingerprint = "";
    for (const line of exitAddresses.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith("ExitNode ")) {
        fingerprint = trimmed.slice("ExitNode ".length).trim();
        continue;
      }
      if (!trimmed.startsWith("ExitAddress ")) continue;
      const address = trimmed.split(/\s+/)[1] ?? "";
      addIpv4(address, {
        nickname: fingerprint ? `exit-${fingerprint.slice(0, 8)}` : "",
        fingerprint,
        flags: ["Exit"]
      });
    }
  }
  if (onionoo) {
    try {
      const parsed = JSON.parse(onionoo);
      const relays = Array.isArray(parsed.relays) ? parsed.relays : [];
      for (const relay of relays) {
        const flags = Array.isArray(relay.flags) ? relay.flags.filter((flag) => typeof flag === "string") : [];
        if (!flags.includes("Exit")) continue;
        const metadata = torRelayMetadataFromOnionoo(relay);
        const exitAddressesForRelay = Array.isArray(relay.exit_addresses) ? relay.exit_addresses : [];
        for (const address of exitAddressesForRelay) addIpv4(address, metadata);
        const orAddresses = Array.isArray(relay.or_addresses) ? relay.or_addresses : [];
        for (const entry of orAddresses) {
          if (typeof entry !== "string") continue;
          const host = splitTorAddressPort(entry);
          if (!host) continue;
          if (isIpv4Literal(host)) addIpv4(host, metadata);
          else addIpv6(host, metadata);
        }
      }
    } catch {
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
function runTorIntelligenceSync() {
  if (torIntelligenceSyncInFlight) return torIntelligenceSyncInFlight;
  torIntelligenceSyncInFlight = syncTorIntelligence().catch(() => void 0).finally(() => {
    torIntelligenceSyncInFlight = null;
  });
  return torIntelligenceSyncInFlight;
}
function ensureTorIntelligenceSync() {
  if (torIntelligenceTimer === null) {
    void runTorIntelligenceSync();
    torIntelligenceTimer = setInterval(() => {
      void runTorIntelligenceSync();
    }, TOR_INTELLIGENCE_SYNC_INTERVAL_MS);
    const handle = torIntelligenceTimer;
    if (typeof handle.unref === "function") handle.unref();
    return;
  }
  if (Date.now() - torIntelligenceLastSyncMs >= TOR_INTELLIGENCE_SYNC_INTERVAL_MS) {
    void runTorIntelligenceSync();
  }
}
try {
  ensureTorIntelligenceSync();
} catch {
}
function lookupTorRelayMetadata(ip) {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return null;
  const direct = torRelayMetadataMap.get(normalized);
  if (direct) return direct;
  const expanded = expandIpv6Address(normalized);
  if (!expanded) return null;
  return torRelayMetadataMap.get(expanded) ?? null;
}
function describeTorRelay(ip) {
  const metadata = lookupTorRelayMetadata(ip);
  if (!metadata) return null;
  const organization = metadata.asName || metadata.nickname;
  const asn = metadata.as ? metadata.as.startsWith("AS") ? metadata.as : `AS${metadata.as}` : "";
  if (organization && asn) return `${organization} \xB7 ${asn}`;
  return organization || asn || null;
}
function pruneTorVerdictCache(nowMs) {
  for (const [ip, entry] of torVerdictCache) {
    if (entry.expiresAtMs <= nowMs) torVerdictCache.delete(ip);
  }
  while (torVerdictCache.size >= TOR_VERDICT_CACHE_MAX_ENTRIES) {
    const oldestKey = torVerdictCache.keys().next().value;
    if (typeof oldestKey !== "string") break;
    torVerdictCache.delete(oldestKey);
  }
}
var SUSPICIOUS_IP_TTL_MS = 24 * 60 * 60 * 1e3;
var SUSPICIOUS_IP_MAX_ENTRIES = 1e4;
var SUSPICIOUS_IP_BLOCK_THRESHOLD = 2;
var suspiciousIpLedger = /* @__PURE__ */ new Map();
var suspiciousIpReasons = /* @__PURE__ */ new Map();
var suspiciousIpStrikes = /* @__PURE__ */ new Map();
function isIpv4Literal(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed)) return false;
  return trimmed.split(".").every((octet) => {
    const parsed = Number.parseInt(octet, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 255;
  });
}
async function resolveTorDnsel(ipv4) {
  const queryName = `${ipv4.split(".").reverse().join(".")}.dnsel.torproject.org`;
  let resolved = false;
  let isTorExit = false;
  let timeoutHandle;
  try {
    const lookup = dns.resolve4(queryName).catch((error) => {
      const code = typeof error?.code === "string" ? error.code : "";
      if (code === "ENOTFOUND" || code === "ENODATA" || code === "ENOTIMP") {
        return [];
      }
      return null;
    });
    const timeout = new Promise((resolve) => {
      timeoutHandle = setTimeout(() => resolve(null), TOR_DNS_TIMEOUT_MS);
    });
    const records = await Promise.race([lookup, timeout]);
    if (Array.isArray(records)) {
      resolved = true;
      isTorExit = records.includes("127.0.0.2");
    }
  } catch {
    resolved = false;
  } finally {
    if (timeoutHandle !== void 0) clearTimeout(timeoutHandle);
  }
  if (!resolved) {
    for (const endpoint of TOR_DOH_ENDPOINTS) {
      const answers = await resolveAOverDoh(endpoint, queryName);
      if (answers) {
        resolved = true;
        isTorExit = answers.includes("127.0.0.2");
        break;
      }
    }
  }
  return resolved ? isTorExit : null;
}
async function resolveTorReverseDns(ip) {
  const nowMs = Date.now();
  const cached = torReverseDnsCache.get(ip);
  if (cached && cached.expiresAtMs > nowMs) return cached.names;
  let names = [];
  let timeoutHandle;
  try {
    const lookup = dns.reverse(ip).catch(() => []);
    const timeout = new Promise((resolve) => {
      timeoutHandle = setTimeout(() => resolve([]), TOR_REVERSE_DNS_TIMEOUT_MS);
    });
    const records = await Promise.race([lookup, timeout]);
    if (Array.isArray(records)) {
      names = records.filter((name) => typeof name === "string");
    }
  } catch {
    names = [];
  } finally {
    if (timeoutHandle !== void 0) clearTimeout(timeoutHandle);
  }
  if (torReverseDnsCache.size > TOR_VERDICT_CACHE_MAX_ENTRIES) torReverseDnsCache.clear();
  torReverseDnsCache.set(ip, {
    names,
    expiresAtMs: nowMs + TOR_OPERATOR_PREFIX_CACHE_TTL_MS
  });
  return names;
}
async function lookupOnionooRelay(target) {
  const url = `${TOR_ONIONOO_DETAILS_URL}?search=${encodeURIComponent(
    target
  )}&fields=nickname,fingerprint,or_addresses,exit_addresses,flags,as`;
  const body = await fetchTextWithTimeout(url, TOR_LIVE_LOOKUP_TIMEOUT_MS, "application/json");
  if (!body) return null;
  let relays = [];
  try {
    const parsed = JSON.parse(body);
    relays = Array.isArray(parsed.relays) ? parsed.relays : [];
  } catch {
    return null;
  }
  const targetExpanded = expandIpv6Address(target);
  const targetPrefix64 = targetExpanded ? targetExpanded.split(":").slice(0, 4).join(":") : null;
  let matched = false;
  let isExit = false;
  for (const relay of relays) {
    const addresses = [];
    if (Array.isArray(relay.exit_addresses)) {
      for (const address of relay.exit_addresses) {
        if (typeof address === "string") addresses.push(address);
      }
    }
    if (Array.isArray(relay.or_addresses)) {
      for (const entry of relay.or_addresses) {
        if (typeof entry !== "string") continue;
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
      return targetPrefix64 !== null && expanded.split(":").slice(0, 4).join(":") === targetPrefix64;
    });
    if (!hasMatch) continue;
    matched = true;
    const flags = Array.isArray(relay.flags) ? relay.flags.filter((flag) => typeof flag === "string") : [];
    if (flags.includes("Exit")) {
      isExit = true;
      break;
    }
  }
  return { matched, isExit };
}
async function resolveTorExitVerdict(ip) {
  const cleanIp = normalizeIpAddress(ip);
  if (!cleanIp) return "unknown";
  const isV4 = isIpv4Literal(cleanIp);
  const expanded = isV4 ? null : expandIpv6Address(cleanIp);
  if (!isV4 && expanded === null) return "unknown";
  if (isV4 && torIpv4ExitSet.has(cleanIp)) return "exit";
  if (expanded !== null && (torIpv6ExitSet.has(cleanIp) || torIpv6ExitSet.has(expanded))) {
    return "exit";
  }
  if (!isV4) {
    const embeddedIpv4 = extractEmbeddedIpv4FromIpv6(cleanIp);
    if (embeddedIpv4 !== null) {
      if (torIpv4ExitSet.has(embeddedIpv4)) return "exit";
      if (ipMatchesCidrList(embeddedIpv4, TOR_OPERATOR_IPV4_CIDRS)) return "exit";
    }
  }
  if (isTorOperatorPrefix(cleanIp)) return "relay";
  const reverseNames = await resolveTorReverseDns(cleanIp);
  if (reverseNames.some((name) => TOR_OPERATOR_REVERSE_DNS_PATTERN.test(name))) return "relay";
  const nowMs = Date.now();
  const cached = torVerdictCache.get(cleanIp);
  if (cached && cached.expiresAtMs > nowMs) {
    return cached.verdict === "exit" ? "exit" : cached.verdict === "relay" ? "relay" : "not_exit";
  }
  let liveVerdict = "unknown";
  if (isV4) {
    const [dnsel, onionoo] = await Promise.all([
      resolveTorDnsel(cleanIp),
      lookupOnionooRelay(cleanIp)
    ]);
    if (dnsel === true) {
      liveVerdict = "exit";
    } else if (onionoo && onionoo.matched) {
      liveVerdict = onionoo.isExit ? "exit" : "relay";
    } else if (dnsel === false || onionoo && !onionoo.matched) {
      liveVerdict = "no";
    }
  } else {
    const onionoo = await lookupOnionooRelay(expanded ?? cleanIp);
    if (onionoo && onionoo.matched) liveVerdict = onionoo.isExit ? "exit" : "relay";
    else if (onionoo && !onionoo.matched) liveVerdict = "no";
  }
  if (liveVerdict !== "unknown") {
    pruneTorVerdictCache(nowMs);
    torVerdictCache.set(cleanIp, {
      verdict: liveVerdict,
      expiresAtMs: nowMs + TOR_VERDICT_CACHE_TTL_MS
    });
  }
  return liveVerdict === "exit" ? "exit" : liveVerdict === "relay" ? "relay" : liveVerdict === "no" ? "not_exit" : "unknown";
}
function matchesTorOperatorHint(location) {
  const haystack = [location.isp, location.org, location.asn].filter((part) => typeof part === "string" && part.trim().length > 0).join(" ");
  if (haystack.length > 0 && TOR_OPERATOR_ORG_PATTERN.test(haystack)) return true;
  if (matchesTorOperatorAsn(location.asn || "")) return true;
  const ip = typeof location.publicIp === "string" ? normalizeIpAddress(location.publicIp) : "";
  return ip.length > 0 && isTorOperatorPrefix(ip);
}
function relayOperatorLabel(location) {
  const rawAsn = typeof location.asn === "string" ? location.asn.trim().toUpperCase() : "";
  const asn = rawAsn ? rawAsn.startsWith("AS") ? rawAsn : `AS${rawAsn}` : "";
  const name = [location.isp, location.org].find(
    (value) => typeof value === "string" && value.trim().length > 0 && !/^unknown/i.test(value.trim())
  ) ?? "";
  if (name && asn) return `${name} \xB7 ${asn}`;
  return name || asn || null;
}
async function resolveTorExitStatus(publicIp, location, prefetched) {
  const relay = lookupTorRelayMetadata(publicIp);
  const operator = describeTorRelay(publicIp) ?? relayOperatorLabel(location);
  if (isTorBulkListed(publicIp)) {
    return {
      isExit: true,
      isRelay: true,
      verdict: "exit",
      viaOperatorHint: false,
      operator,
      relay
    };
  }
  const verdict = await (prefetched ?? resolveTorExitVerdict(publicIp));
  if (verdict === "exit") {
    return { isExit: true, isRelay: true, verdict, viaOperatorHint: false, operator, relay };
  }
  if (verdict === "relay") {
    return { isExit: false, isRelay: true, verdict, viaOperatorHint: false, operator, relay };
  }
  if (verdict === "unknown" && matchesTorOperatorHint({ ...location, publicIp })) {
    return {
      isExit: true,
      isRelay: true,
      verdict: "relay",
      viaOperatorHint: true,
      operator: operator ?? relayOperatorLabel(location),
      relay
    };
  }
  return { isExit: false, isRelay: false, verdict, viaOperatorHint: false, operator: null, relay: null };
}
async function resolveAOverDoh(endpoint, name) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TOR_DOH_TIMEOUT_MS);
  try {
    const response = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=A`, {
      headers: { accept: "application/dns-json" },
      signal: controller.signal
    });
    if (!response.ok) return null;
    const payload = await response.json();
    if (payload.Status === 3) return [];
    if (payload.Status !== 0) return null;
    const answers = Array.isArray(payload.Answer) ? payload.Answer : [];
    return answers.filter((entry) => entry.type === 1 && typeof entry.data === "string").map((entry) => String(entry.data).trim());
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
function isTorBulkListed(ip) {
  const cleanIp = normalizeIpAddress(ip);
  if (!cleanIp) return false;
  if (isIpv4Literal(cleanIp)) return torIpv4ExitSet.has(cleanIp);
  const expanded = expandIpv6Address(cleanIp);
  if (!expanded) return false;
  return torIpv6ExitSet.has(cleanIp) || torIpv6ExitSet.has(expanded);
}
async function refreshTorBulkList() {
  ensureTorIntelligenceSync();
  if (torIntelligenceSyncInFlight) return;
  if (Date.now() - torIntelligenceLastSyncMs < TOR_INTELLIGENCE_SYNC_INTERVAL_MS) return;
  await runTorIntelligenceSync();
}
function flagSuspiciousIp(ip, reason) {
  const cleanIp = typeof ip === "string" ? ip.trim() : "";
  if (!cleanIp || cleanIp === "Unavailable") return;
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
    if (typeof oldestKey !== "string") break;
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
  const strikes = existingReasons.length;
  suspiciousIpStrikes.set(cleanIp, strikes);
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
    suspiciousIpStrikes.delete(cleanIp);
    return { blocklisted: false, reasons: [] };
  }
  const strikes = suspiciousIpStrikes.get(cleanIp) ?? 0;
  if (strikes < SUSPICIOUS_IP_BLOCK_THRESHOLD) {
    return { blocklisted: false, reasons: [] };
  }
  return {
    blocklisted: true,
    reasons: [...suspiciousIpReasons.get(cleanIp) ?? []]
  };
}
var ENVELOPE_FRESHNESS_WINDOW_MS = 10 * 60 * 1e3;
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
    reasons.push("Expired or replayed payload timestamp (>10m)");
  }
  let replayDetected = false;
  if (requestNonce) {
    replayDetected = rememberEnvelopeNonce(requestNonce, nowMs);
    if (replayDetected) reasons.push("Duplicate payload nonce (Replay Attack detected)");
  }
  const headerUserAgent = readRequestHeader(headers, "user-agent");
  if (headerUserAgent && envelopeUserAgent && !userAgentsCompatible(headerUserAgent, envelopeUserAgent)) {
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
var VELOCITY_WINDOW_MS = {
  "5_minutes": 5 * 60 * 1e3,
  "1_hour": 60 * 60 * 1e3,
  "24_hours": 24 * 60 * 60 * 1e3
};
var EMPTY_WINDOW = { "5_minutes": 0, "1_hour": 0, "24_hours": 0 };
var EMPTY_VELOCITY = {
  distinct_ip: { ...EMPTY_WINDOW },
  distinct_linked_id: { ...EMPTY_WINDOW },
  distinct_country: { ...EMPTY_WINDOW },
  events: { ...EMPTY_WINDOW },
  ip_events: { ...EMPTY_WINDOW },
  distinct_ip_by_linked_id: { ...EMPTY_WINDOW },
  distinct_visitor_id_by_linked_id: { ...EMPTY_WINDOW }
};
function computeVelocitySignals(db2, visitorId, publicIp, sessionId) {
  const now = Date.now();
  const iso = (ms) => new Date(now - ms).toISOString();
  const fiveMinuteCutoff = iso(VELOCITY_WINDOW_MS["5_minutes"]);
  const oneHourCutoff = iso(VELOCITY_WINDOW_MS["1_hour"]);
  const dayCutoff = iso(VELOCITY_WINDOW_MS["24_hours"]);
  try {
    const row = db2.prepare(
      `SELECT
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS ip_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS ip_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS ip_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN session_id END) AS linked_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN session_id END) AS linked_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN session_id END) AS linked_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN country END) AS country_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN country END) AS country_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN country END) AS country_24h,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS events_5m,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS events_1h,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS events_24h
         FROM visits
         WHERE visitor_id = ?`
    ).get(
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      visitorId
    );
    const num = (value) => {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : 0;
    };
    const ipEventsRow = db2.prepare(
      `SELECT
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS ip_events_5m,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS ip_events_1h,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS ip_events_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS ip_visitors_24h
         FROM visits
         WHERE public_ip = ?`
    ).get(fiveMinuteCutoff, oneHourCutoff, dayCutoff, dayCutoff, publicIp);
    const linkedIpRow = db2.prepare(
      `SELECT
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS linked_ips_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS linked_ips_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS linked_ips_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS linked_visitors_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS linked_visitors_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS linked_visitors_24h
         FROM visits
         WHERE session_id = ?`
    ).get(
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      sessionId
    );
    const velocity = row ? {
      distinct_ip: {
        "5_minutes": num(row.ip_5m),
        "1_hour": num(row.ip_1h),
        "24_hours": num(row.ip_24h)
      },
      distinct_linked_id: {
        "5_minutes": num(row.linked_5m),
        "1_hour": num(row.linked_1h),
        "24_hours": num(row.linked_24h)
      },
      distinct_country: {
        "5_minutes": num(row.country_5m),
        "1_hour": num(row.country_1h),
        "24_hours": num(row.country_24h)
      },
      events: {
        "5_minutes": num(row.events_5m),
        "1_hour": num(row.events_1h),
        "24_hours": num(row.events_24h)
      },
      ip_events: {
        "5_minutes": num(ipEventsRow?.ip_events_5m),
        "1_hour": num(ipEventsRow?.ip_events_1h),
        "24_hours": num(ipEventsRow?.ip_events_24h)
      },
      distinct_ip_by_linked_id: {
        "5_minutes": num(linkedIpRow?.linked_ips_5m),
        "1_hour": num(linkedIpRow?.linked_ips_1h),
        "24_hours": num(linkedIpRow?.linked_ips_24h)
      },
      distinct_visitor_id_by_linked_id: {
        "5_minutes": num(linkedIpRow?.linked_visitors_5m),
        "1_hour": num(linkedIpRow?.linked_visitors_1h),
        "24_hours": num(linkedIpRow?.linked_visitors_24h)
      }
    } : { ...EMPTY_VELOCITY };
    return {
      velocity,
      events24h: velocity.events["24_hours"],
      distinctIps24h: velocity.distinct_ip["24_hours"]
    };
  } catch {
    return { velocity: { ...EMPTY_VELOCITY }, events24h: 0, distinctIps24h: 0 };
  }
}
function computeDeviceRarity(db2, browserDevice) {
  try {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1e3).toISOString();
    const row = db2.prepare(
      `SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN screen_resolution = ? AND browser = ? AND os = ? THEN 1 ELSE 0 END) AS matching
         FROM visits
         WHERE visited_at_utc >= ?`
    ).get(
      browserDevice.screenResolution,
      browserDevice.browser,
      browserDevice.os,
      cutoff
    );
    const total = Number(row?.total) || 0;
    const matching = Number(row?.matching) || 0;
    if (total < 20) {
      return { rareDevice: false, bucket: "<p95", share: 1, sampleSize: total };
    }
    const share = matching / total;
    const bucket = share <= 0.01 ? ">p99" : share <= 0.05 ? "p95-p99" : "<p95";
    return { rareDevice: bucket !== "<p95", bucket, share, sampleSize: total };
  } catch {
    return { rareDevice: false, bucket: "<p95", share: 1, sampleSize: 0 };
  }
}
function computeSuspectScore100(input) {
  let score = 0;
  if (input.bot) score += 45;
  if (input.replayed) score += 35;
  if (input.tampering) score += 25;
  if (input.vpn) score += 10 + (input.vpnMethodCount > 1 ? 4 : 0);
  if (input.blocklisted) score += 12;
  if (input.virtualMachine) score += 12;
  if (input.proxy) score += 10;
  if (input.simulator) score += 10;
  if (input.activeCall) score += 10;
  if (input.privacySettings) score += 8;
  if (input.incognito) score += 6;
  if (input.highActivityDevice) score += 6;
  if (input.developerTools) score += 5;
  if (input.rareDevice) score += 4;
  return Math.max(0, Math.min(100, Math.round(score)));
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
app.get("/api/health", async (req, res) => {
  const visitorsCount = db.prepare("SELECT COUNT(*) AS count FROM visitors").get().count;
  const visitsCount = db.prepare("SELECT COUNT(*) AS count FROM visits").get().count;
  const { regionCode, regionLabel } = detectServerRegion(req);
  const torCheckIp = typeof req.query.torCheck === "string" ? normalizeIpCandidate(req.query.torCheck) : null;
  if (torCheckIp && (isIpv4Literal(torCheckIp) || expandIpv6Address(torCheckIp) !== null)) {
    const startedAtMs = Date.now();
    ensureTorIntelligenceSync();
    const verdict = await resolveTorExitVerdict(torCheckIp);
    const relay = lookupTorRelayMetadata(torCheckIp);
    res.json({
      status: "ok",
      visitorsCount,
      visitsCount,
      regionCode,
      regionLabel,
      torCheck: {
        ip: torCheckIp,
        exitNode: verdict === "exit",
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
        latencyMs: Date.now() - startedAtMs
      }
    });
    return;
  }
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
function sanitizeAndReinforceSecuritySignals(raw, browserDevice, hardwareSignals, location, ipTimezoneHint, recognitionSource, baseClassification, velocity, incognitoContext = {}, requestContext = {}) {
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
  const isGpuMaskedOrUnavailable = !hardwareSignals.gpuVendor || hardwareSignals.gpuVendor === "Unavailable" || /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuVendor) || !hardwareSignals.gpuRenderer || hardwareSignals.gpuRenderer === "Unavailable" || /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuRenderer);
  const clientTorBrowser = Boolean(requestContext.clientTorBrowser ?? raw?.isTorBrowserClient);
  const classification = applyNetworkOverrides(baseClassification, {
    torExit: Boolean(requestContext.torExitNode || requestContext.torRelay),
    torOperatorHint: Boolean(requestContext.torOperatorHint),
    isTorBrowserClient: clientTorBrowser,
    aiAgentDetected: Boolean(requestContext.aiAgent?.detected),
    datacenterVm: Boolean(raw?.isVirtualMachine) && (baseClassification.isDatacenterOrHosting || isGpuMaskedOrUnavailable),
    vpnSuspected: Boolean(raw?.vpnSuspected) || timezoneMismatch
  });
  const isCloudOrDatacenterNetwork = classification.isDatacenterOrHosting || Boolean(location.isVpnOrHosting);
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
  const torExitNode = Boolean(requestContext.torExitNode);
  const torOperatorHint = Boolean(requestContext.torOperatorHint);
  const vpnSuspected = Boolean(raw?.vpnSuspected) || timezoneMismatch || torExitNode || datacenterAsn && botSubtype !== "good_bot";
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
  const serverEmulator = classifyEmulatorFromSignals({
    userAgent: requestContext.requestUserAgent || readRequestHeader(requestContext.headers, "user-agent") || "",
    os: browserDevice.os,
    platform: browserDevice.platform,
    maxTouchPoints: hardwareSignals.maxTouchPoints,
    gpuVendor: hardwareSignals.gpuVendor,
    gpuRenderer: hardwareSignals.gpuRenderer,
    screenResolution: browserDevice.screenResolution
  });
  const clientEmulatorReported = Boolean(raw?.emulatorDetected);
  const emulatorDetected = clientEmulatorReported || serverEmulator.detected;
  const clientEmulatorReason = typeof raw?.emulatorReason === "string" && raw.emulatorReason.trim() ? raw.emulatorReason.trim().slice(0, 200) : "";
  const emulatorReason = emulatorDetected ? serverEmulator.detected ? serverEmulator.reason : clientEmulatorReason : "";
  const tamperedRequest = Boolean(requestContext.tamperedRequest);
  const replayDetected = Boolean(requestContext.replayDetected);
  const requestIntegrityReason = typeof requestContext.requestIntegrityReason === "string" ? requestContext.requestIntegrityReason.trim().slice(0, 240) : "";
  const requestNonce = typeof requestContext.requestNonce === "string" ? requestContext.requestNonce.slice(0, 128) : "";
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
  const isIncognito = clientReportedIncognito;
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
    // The physical proof must match the verdict: a private tile always quotes the client's
    // own storage-commit probe method, a normal tile quotes the verified disk-backed path.
    detail: isIncognito ? `Ephemeral RAM storage detected (${incognitoMethod || "In-memory LevelDB / 10 GiB decoy quota"})` : `Persistent disk-backed storage verified (${incognitoMethod || "Standard profile"})`
  };
  const aiAgent = requestContext.aiAgent ?? null;
  const spoofedImpostor = aiAgent?.agentId === "impostor-spoof" || botSubtype === "bad_bot" && spoofedCrawler;
  const botScore = spoofedImpostor ? 10 : botSubtype === "bad_bot" ? 9 : botSubtype === "ai_agent" ? 8 : botSubtype === "good_bot" ? 2 : 0;
  const botStatus = spoofedImpostor ? "Spoofed AI Impostor" : botSubtype === "bad_bot" ? "Bot / Automated" : aiAgent?.detected && aiAgent.agentName ? aiAgent.agentName : botSubtype === "ai_agent" ? "AI Agent \xB7 Cloud Browser" : botSubtype === "good_bot" ? "Good Bot \xB7 Search Crawler" : "Verified Human";
  const aiAgentDetail = aiAgent?.detected && aiAgent.agentName ? `${aiAgent.agentName} \u2014 ${aiAgent.operator}${aiAgent.executionMode ? ` \xB7 ${aiAgent.executionMode}` : ""} \xB7 ${aiAgent.confidence}${aiAgent.verified ? " (verified)" : ""}: ${aiAgent.evidence[0] || "agent identity attributed from request headers"}` : "";
  const botDetail = botSubtype === "human" && !aiAgent?.detected ? "Verified human interactive session" : aiAgentDetail ? aiAgentDetail : botSubtype === "ai_agent" ? `${botClassification.provider} ${botClassification.label} \u2014 ${botClassification.reasons[0] || KNOWN_AI_CRAWLER_REASON}` : botSubtype === "good_bot" ? `${botClassification.provider} ${botClassification.label} verified against its official network \u2014 ${botClassification.reasons[1] || "ASN / organisation match"}` : botReason || botClassification.reasons[0] || (spoofedCrawler ? "Crawler user-agent claimed from a network that does not belong to the operator" : "WebDriver / CDP automation runtime detected");
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
  const verifiedCrawlerNetwork = botSubtype === "good_bot" && isDatacenterAsn;
  const ispBrand = classification.brandName || location.isp || "Unknown ISP";
  const asnSuffix = location.asn !== "Unknown" ? ` \u2022 ${location.asn}` : "";
  const asnLabel = location.asn && location.asn !== "Unknown" ? /^AS/i.test(location.asn) ? location.asn.toUpperCase() : `AS${location.asn}` : "AS unknown";
  const asnOrOrg = `${asnLabel} \xB7 ${location.org !== "Unknown" ? location.org : ispBrand}`;
  const torBrowserClient = clientTorBrowser;
  const torRelayNetwork = requestContext.torVerdict === "relay" || requestContext.torRelay === true;
  const torAnonymity = torExitNode || torBrowserClient;
  const torOperatorLabel = requestContext.torOperator ?? describeTorRelay(location.publicIp) ?? null;
  const vpnScore = torAnonymity ? torExitNode && torBrowserClient ? 10 : 9 : ipBlocklisted ? 9 : verifiedCrawlerNetwork ? 2 : torRelayNetwork ? 6 : aiAgent?.detected ? 8 : isDatacenterAsn && hasTzMismatch ? 8 : isDatacenterAsn ? 6 : hasTzMismatch ? 5 : 0;
  const vpnStatus = torAnonymity ? torExitNode && torBrowserClient ? "Tor Exit Node & Tor Browser" : torExitNode ? "Tor Exit Node" : "Tor Browser (Onion Routing / RFP)" : ipBlocklisted ? "Blocklisted IP" : verifiedCrawlerNetwork ? "Verified Crawler Network" : torRelayNetwork ? "Tor Relay (Non-Exit)" : aiAgent?.detected ? "AI Agent Cloud Network" : isDatacenterAsn ? "VPN / Datacenter Proxy" : hasTzMismatch ? "VPN / Timezone Relay" : "Standard ISP";
  const vpnDetail = torAnonymity ? `${torExitNode ? "Confirmed active Tor exit relay" : "Tor Browser fingerprint (Gecko RFP + letterboxing)"} (${location.publicIp} \xB7 ${torOperatorLabel || asnOrOrg})${torOperatorHint ? " \u2014 DNSEL unreachable, operator attribution used" : ""}${torExitNode && torBrowserClient ? " \xB7 server exit IP and client RFP both matched (10/10)" : ""}` : ipBlocklisted ? "IP flagged on abuse / tamper blocklist" : verifiedCrawlerNetwork ? `${botClassification.provider} crawler operating from its own ${ispBrand}${asnSuffix} \u2014 crawler infrastructure, not a consumer proxy` : torRelayNetwork ? `Tor relay network (${torOperatorLabel || asnOrOrg}) \u2014 part of the Tor network but not an exit egress` : aiAgent?.detected ? `${aiAgent.agentName} (${aiAgent.operator}) \u2014 ${aiAgent.executionMode || "AI agent"} traffic from ${ispBrand}${asnSuffix}` : isDatacenterAsn && hasTzMismatch ? `Datacenter ASN (${ispBrand}${asnSuffix}) combined with a browser/IP timezone mismatch (${clientTzCanonical} vs ${ipTzCanonical})` : isDatacenterAsn ? `Datacenter / hosting ASN detected on ${ispBrand}${asnSuffix}` : hasTzMismatch ? `Browser timezone (${browserTimezone}) differs from IP geolocation timezone (${ipTimezone})` : `${ispBrand} \u2022 ${classification.networkType} (${asnLabel}) verified against browser timezone ${browserTimezone}`;
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
  const vmScore = tamperedRequest || replayDetected ? 10 : emulatorDetected ? 8 : vmLike ? 7 : isTampered ? 6 : 0;
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
  const networkPoints = torExitNode ? 5 : verifiedCrawlerNetwork ? 0 : isDatacenterAsn ? 3 : hasTzMismatch ? 2 : 0;
  const rawCompositePoints = (isBot ? 5 : isHeadless ? 4 : 0) + networkPoints + (vmScore > 0 ? 3 : 0) + (isIncognito ? 2 : 0) + (integrityViolation ? 2 : 0);
  const weightedCompositeScore = Math.min(10, rawCompositePoints);
  const cardScores = [incognitoScore, botScore, vpnScore, vmScore];
  const maxCardScore = Math.max(0, ...cardScores);
  const elevatedCardCount = cardScores.filter((score) => score >= 4).length;
  const synergyBonus = elevatedCardCount >= 3 ? 2 : elevatedCardCount === 2 ? 1 : 0;
  const suspectScore = Math.min(
    10,
    Math.max(weightedCompositeScore, maxCardScore + synergyBonus)
  );
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
  if (torAnonymity) {
    riskFactors.push(
      `${torExitNode ? "Confirmed Tor exit relay" : "Tor Browser fingerprint"} (+${torExitNode && torBrowserClient ? 10 : 9} card): ${torExitNode ? torOperatorHint ? "exit-operator attribution" : "Tor Project DNSEL / consensus exit list" : "Gecko RFP + letterboxing detected on the client"} ${location.publicIp}`
    );
  } else if (torRelayNetwork) {
    riskFactors.push(
      `Tor relay network (+6 card): ${torOperatorLabel || asnOrOrg} \u2014 relay, not an exit egress`
    );
  } else if (verifiedCrawlerNetwork) {
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
      `${aiAgent.agentId === "impostor-spoof" ? "Spoofed AI bot impostor (10/10)" : "AI agent attributed (8/10)"}: ${aiAgent.agentName} \xB7 ${aiAgent.operator} \xB7 ${aiAgent.confidence}`
    );
  }
  if (vmScore > 0) {
    const duplicatesIntegrityReason = integrityViolation && vmSignal.detail === (requestIntegrityReason || "tampered or replayed payload");
    if (!duplicatesIntegrityReason) {
      riskFactors.push(`Virtual machine / tampered OS (+3): ${vmSignal.detail}`);
    }
  }
  if (isIncognito) {
    riskFactors.push(`Incognito / ephemeral storage (+2): ${incognitoSignal.detail}`);
  }
  if (integrityViolation) {
    riskFactors.push(
      `Sealed request envelope failed verification (+2): ${requestIntegrityReason || "tampered or replayed payload"}`
    );
  }
  const proxyAssessment = detectProxyHeaders(requestContext.headers, location.publicIp);
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
      isTorBrowserClient: clientTorBrowser,
      torVerdict: requestContext.torVerdict ?? (torExitNode ? "exit" : "unknown"),
      torOperator: requestContext.torOperator ?? describeTorRelay(location.publicIp) ?? (torExitNode ? relayOperatorLabel(location) : null),
      aiAgent: requestContext.aiAgent ?? null,
      ipBlocklisted,
      ipBlocklistReasons,
      // Phase 5 — explicit proxy relay markers (Via / Forwarded / Proxy-Authorization chains)
      proxyDetected: proxyAssessment.detected,
      proxyReasons: proxyAssessment.reasons,
      // Phase 3 — mobile emulator / simulator verdict
      emulatorDetected,
      emulatorReason,
      // Phase 5 — browser tampering / docked DevTools (client-probed, echoed for the grid)
      tampering: Boolean(raw?.tampering),
      tamperingConfidence: raw?.tamperingConfidence || "high",
      tamperingMlScore: typeof raw?.tamperingMlScore === "number" ? raw.tamperingMlScore : 24e-4,
      tamperingDetails: raw?.tamperingDetails,
      developerTools: Boolean(raw?.developerTools),
      privacySettings: Boolean(raw?.privacySettings || clientTorBrowser),
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
    void refreshTorBulkList();
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
    const torLookupPromise = resolveTorExitVerdict(extractedIp).catch(
      () => "unknown"
    );
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
    const headerRequestUserAgent = readRequestHeader(rawRequestHeaders, "user-agent");
    const envelopeRequestUserAgent = typeof requestBody.securityEnvelope?.userAgent === "string" ? requestBody.securityEnvelope.userAgent.trim() : "";
    const headerCarriesBotSignature = Boolean(headerRequestUserAgent) && (AUTOMATION_UA_PATTERN.test(headerRequestUserAgent) || GOOD_BOT_UA_RULES.some((rule) => rule.pattern.test(headerRequestUserAgent)) || AI_AGENT_UA_RULES.some((rule) => rule.pattern.test(headerRequestUserAgent)));
    const fullRequestUserAgent = headerCarriesBotSignature ? headerRequestUserAgent : envelopeRequestUserAgent || headerRequestUserAgent;
    const botClassification = classifyBotTraffic(
      { ...rawRequestHeaders, "user-agent": fullRequestUserAgent },
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
    const torLookupTarget = location.publicIp.trim().toLowerCase();
    const torStatus = await resolveTorExitStatus(
      location.publicIp,
      location,
      torLookupTarget === extractedIp.trim().toLowerCase() ? torLookupPromise : void 0
    );
    const torExitNode = torStatus.isExit;
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
        botSignals: Array.isArray(rawSecuritySignals?.botSignals) ? rawSecuritySignals.botSignals : []
      }
    });
    const attributedBotClassification = aiAgent.detected && aiAgent.agentId === "impostor-spoof" ? {
      subtype: "bad_bot",
      label: "Spoofed AI Bot",
      provider: aiAgent.operator,
      category: "Spoofed Identity",
      confidence: 0.99,
      reasons: aiAgent.evidence.slice(0, 3)
    } : aiAgent.detected && aiAgent.agentId !== null ? {
      subtype: "ai_agent",
      label: aiAgent.agentName,
      provider: aiAgent.operator,
      category: "AI Agent",
      confidence: aiAgent.verified ? 0.99 : 0.85,
      reasons: aiAgent.evidence.slice(0, 3)
    } : null;
    const effectiveBotClassification = attributedBotClassification ?? botClassification;
    const signedPayloadTampered = /Payload integrity hash mismatch/i.test(
      envelopeVerdict.requestIntegrityReason
    );
    if (signedPayloadTampered) {
      flagSuspiciousIp(
        location.publicIp,
        envelopeVerdict.requestIntegrityReason || "Tampered request payload"
      );
    }
    if (envelopeVerdict.replayDetected) {
      flagSuspiciousIp(location.publicIp, "Replayed payload nonce");
    }
    if (effectiveBotClassification.subtype === "bad_bot" && effectiveBotClassification.label === "Spoofed Crawler") {
      flagSuspiciousIp(location.publicIp, "Spoofed crawler user-agent");
    } else if (aiAgent.agentId === "impostor-spoof") {
      flagSuspiciousIp(location.publicIp, "Spoofed AI bot user-agent");
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
        botClassification: effectiveBotClassification
      }
    );
    const velocityReport = computeVelocitySignals(
      db,
      visitorId,
      location.publicIp,
      currentSessionId
    );
    const rarityReport = computeDeviceRarity(db, browserDevice);
    const highActivityDevice = velocityReport.events24h >= 20;
    const clientTampering = rawSecuritySignals?.tampering ?? null;
    const tamperingAssessment = clientTampering === null ? null : {
      tampering: Boolean(clientTampering),
      confidence: rawSecuritySignals?.tamperingConfidence || "high",
      mlScore: typeof rawSecuritySignals?.tamperingMlScore === "number" ? rawSecuritySignals.tamperingMlScore : 24e-4,
      details: rawSecuritySignals?.tamperingDetails ?? {
        anomaly_score: 0,
        anti_detect_browser: false,
        devtools_device_emulation: false,
        reasons: []
      }
    };
    const activeCallSupported = Boolean(rawSecuritySignals?.activeCallSupported);
    const activeCall = activeCallSupported && Boolean(rawSecuritySignals?.activeCall);
    const privacySettings = Boolean(
      rawSecuritySignals?.privacySettings || rawSecuritySignals?.isTorBrowserClient || securitySignals.privacyProtected
    );
    const developerTools = Boolean(rawSecuritySignals?.developerTools);
    const suspectScore100 = computeSuspectScore100({
      bot: Boolean(securitySignals.isBot),
      replayed: Boolean(securitySignals.replayDetected),
      tampering: Boolean(tamperingAssessment?.tampering),
      vpn: Boolean(securitySignals.vpnSuspected),
      vpnMethodCount: Array.isArray(securitySignals.vpnReasons) ? securitySignals.vpnReasons.length : 0,
      blocklisted: Boolean(securitySignals.torExitNode || securitySignals.ipBlocklisted),
      virtualMachine: Boolean(
        securitySignals.isVirtualMachine || securitySignals.cloudOrMaskedGpu || securitySignals.emulatorDetected
      ),
      proxy: Boolean(
        securitySignals.proxyDetected
      ),
      simulator: Boolean(securitySignals.emulatorDetected),
      activeCall,
      privacySettings,
      incognito: Boolean(securitySignals.isIncognito),
      highActivityDevice,
      developerTools,
      rareDevice: rarityReport.rareDevice
    });
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
      smartSignals: securitySignals.smartSignals,
      // API v4 mirrors: 0-100 calibrated composite, velocity windows and device rarity.
      suspectScore100,
      velocity: velocityReport.velocity,
      highActivityDevice,
      rareDevice: rarityReport.rareDevice,
      rareDevicePercentileBucket: rarityReport.bucket,
      tampering: tamperingAssessment?.tampering ?? false,
      tamperingConfidence: tamperingAssessment?.confidence ?? "high",
      tamperingDetails: tamperingAssessment?.details,
      activeCall,
      activeCallSupported,
      rawDeviceAttributes: rawSecuritySignals?.rawDeviceAttributes ?? null
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

/**
 * Blocking index for multi-key visitor identity — Cloudflare Workers compatible.
 *
 * Three tables (created idempotently through the injected `{ prepare, exec }` adapter):
 *   • `visitor_profiles`  — one row per visitor id, holding the canonical profile JSON.
 *   • `identity_blocks`   — inverted index: bucket_key → visitor ids that ever matched it.
 *   • `visitor_links`     — cross-browser / cross-hardware stitch evidence per visitor id.
 *
 * Bucket keys (deterministic, exported via `blockKeysFor`):
 *   • `hw_hash:<fnv hex>`          — exact hardware-fingerprint bucket.
 *   • `block_gpu:<gpu>:<os>`       — rendering family narrowed by the stable OS family.
 *   • `block_net:<subnet|asn>`     — coarse network bucket only.
 *   • `band_0..3:<hex4>`           — 4 simhash bands over canonical feature tokens
 *                                    (Hamming-near-duplicate detection; tokens and the
 *                                    64-bit FNV-1a simhash are fully deterministic, so
 *                                    the same profile always lands in the same buckets).
 *
 * Screen size, device-pixel-ratio, touch capability and timezone are deliberately NOT used
 * to build stable identity keys: they change with display scaling, monitor swaps, input
 * devices and travel. They remain volatile context for scoring, never an anchor or block key.
 *
 * Adapter notes (see `src/server/db/types.ts`):
 *   • Schema is ensured via `exec` and is safe to call on every request.
 *   • All statements use positional parameters; LIMIT values are inlined integers.
 *   • `findCandidates` deliberately avoids `IN (...)` and uses per-key point queries plus
 *     JS-side dedupe, because the local MemoryDatabase adapter only understands the subset
 *     of SQL used by `schema.ts`.
 */

import type { AIBotDatabase } from '../db/types';

/* -------------------------------------------------------------------------- */
/* Schema                                                                      */
/* -------------------------------------------------------------------------- */

export const IDENTITY_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS visitor_profiles (
  visitor_id TEXT PRIMARY KEY,
  profile_json TEXT,
  hardware_fingerprint TEXT,
  created_at_utc TEXT NOT NULL,
  updated_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_visitor_profiles_hw ON visitor_profiles(hardware_fingerprint);
CREATE INDEX IF NOT EXISTS idx_visitor_profiles_updated ON visitor_profiles(updated_at_utc);

CREATE TABLE IF NOT EXISTS identity_blocks (
  bucket_key TEXT NOT NULL,
  visitor_id TEXT NOT NULL,
  created_at_utc TEXT NOT NULL,
  updated_at_utc TEXT NOT NULL,
  PRIMARY KEY (bucket_key, visitor_id)
);
CREATE INDEX IF NOT EXISTS idx_identity_blocks_key ON identity_blocks(bucket_key);
CREATE INDEX IF NOT EXISTS idx_identity_blocks_visitor ON identity_blocks(visitor_id);

CREATE TABLE IF NOT EXISTS visitor_links (
  visitor_id TEXT NOT NULL,
  hardware_fingerprint TEXT NOT NULL,
  link_mode TEXT,
  link_score REAL,
  created_at_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  PRIMARY KEY (visitor_id, hardware_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_visitor_links_hw ON visitor_links(hardware_fingerprint);
`;

/**
 * Idempotently creates the three identity tables and their indexes.
 * Mirrors the identity section of the Worker DB bootstrap.
 */
export function ensureIdentitySchema(db: AIBotDatabase): void {
  db.exec(IDENTITY_SCHEMA_SQL);
}

/* -------------------------------------------------------------------------- */
/* Types                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Loose, all-optional profile shape accepted by the blocking index. The richer
 * `ResolverProfile` in `./resolver` extends this interface, so profiles can be
 * passed here directly without copying.
 */
export interface BlockKeyProfile {
  hardwareFingerprint?: string | null;
  browser?: { family?: string | null; major?: string | null } | null;
  os?: { family?: string | null } | null;
  net?: { ip?: string | null; asn?: string | null } | null;
  screen?: { width?: number | null; height?: number | null } | null;
  timezone?: string | null;
  fonts?: { count?: number | null; list?: string[] | null } | null;
  gpu?: { vendor?: string | null; renderer?: string | null } | null;
  canvas?: { hash?: string | null } | null;
  webgl?: { hash?: string | null } | null;
  audio?: { hash?: string | null } | null;
  cpu?: { cores?: number | null; architecture?: string | null } | null;
  languages?: string[] | null;
}

/** Row shape returned by `loadVisitorProfile`. */
export interface StoredVisitorProfile {
  visitor_id: string;
  hardware_fingerprint: string | null;
  profile: BlockKeyProfile | null;
  profile_json: string | null;
  created_at_utc: string;
  updated_at_utc: string;
}

/* -------------------------------------------------------------------------- */
/* Normalisation helpers                                                       */
/* -------------------------------------------------------------------------- */

function normalizeText(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase();
}

function normalizeInt(value: unknown): number | null {
  const num = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(num) ? Math.floor(num) : null;
}

/** FNV-1a over the raw hardware fingerprint, rendered as fixed-width hex. */
function hexHash(text: string): string {
  return fnv1a64(text).toString(16).padStart(16, '0');
}

/** IPv4 → `a.b.c` (/24); anything else falls back to the ASN label or 'unknown'. */
function networkBucket(net: BlockKeyProfile['net']): string {
  const ip = normalizeText(net?.ip);
  const asn = normalizeText(net?.asn);
  if (ip) {
    const octets = ip.split('.');
    if (octets.length === 4 && octets.every((o) => /^\d{1,3}$/.test(o))) {
      return octets.slice(0, 3).join('.');
    }
  }
  return asn || 'unknown';
}

/* -------------------------------------------------------------------------- */
/* Deterministic hashing (no node:crypto — Workers safe)                        */
/* -------------------------------------------------------------------------- */

const FNV_OFFSET_64 = 0xcbf29ce484222325n;
const FNV_PRIME_64 = 0x00000100000001b3n;
const MASK_64 = 0xffffffffffffffffn;

/** 64-bit FNV-1a over UTF-16 code units — deterministic across runtimes. */
export function fnv1a64(input: string): bigint {
  let hash = FNV_OFFSET_64;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= BigInt(input.charCodeAt(i) & 0xff);
    hash = (hash * FNV_PRIME_64) & MASK_64;
  }
  return hash;
}

/**
 * Classic 64-bit simhash: each token casts a signed vote on every bit of its
 * FNV-1a-64 hash; bits with a positive vote total are set. Similar token sets
 * produce Hamming-close hashes, which the 4-band keys exploit.
 */
export function simhash64(tokens: string[]): bigint {
  const votes = new Array<number>(64).fill(0);
  for (const token of tokens) {
    const hash = fnv1a64(normalizeText(token));
    for (let bit = 0; bit < 64; bit += 1) {
      votes[bit] += (hash >> BigInt(bit)) & 1n ? 1 : -1;
    }
  }
  let out = 0n;
  for (let bit = 0; bit < 64; bit += 1) {
    if (votes[bit] > 0) out |= 1n << BigInt(bit);
  }
  return out;
}

/** 16-bit slice of the simhash as 4 hex chars — band `k` covers bits [16k, 16k+16). */
function bandHex(simhash: bigint, band: number): string {
  const slice = (simhash >> BigInt(band * 16)) & 0xffffn;
  return slice.toString(16).padStart(4, '0');
}

/**
 * Canonical, order-stable feature tokens fed to `simhash64`. Browser majors are
 * deliberately excluded (they churn monthly and would orphan the band buckets);
 * everything else that survives across browser reinstalls is included.
 *
 * Screen dimensions, DPR, touch and timezone are volatile context only. Screen/DPR/touch
 * are excluded outright; the timezone token is a single low-weight context vote — it is
 * never a hard block key (see `blockKeysFor`) so travel cannot split a visitor.
 */
export function canonicalIdentityFeatures(profile: BlockKeyProfile): string[] {
  const tokens: string[] = [];
  const push = (prefix: string, value: unknown) => {
    const text = normalizeText(value);
    if (text) tokens.push(`${prefix}:${text}`);
  };

  push('hw', profile.hardwareFingerprint);
  const gpu = [normalizeText(profile.gpu?.vendor), normalizeText(profile.gpu?.renderer)]
    .filter(Boolean)
    .join('|');
  if (gpu) tokens.push(`gpu:${gpu}`);
  push('os', profile.os?.family);
  // Low-weight context only (one token); never a hard block key.
  push('tz', profile.timezone);
  // screen width/height, DPR and touch are volatile: excluded from stable hashing.
  const fontsCount = normalizeInt(profile.fonts?.count);
  if (fontsCount !== null && fontsCount > 0) tokens.push(`fonts:${fontsCount}`);
  const cores = normalizeInt(profile.cpu?.cores);
  if (cores !== null && cores > 0) tokens.push(`cpu:${cores}`);
  push('cpuarch', profile.cpu?.architecture);
  push('canvas', profile.canvas?.hash);
  push('webgl', profile.webgl?.hash);
  push('audio', profile.audio?.hash);
  push('browser', profile.browser?.family);
  const langs = (profile.languages ?? [])
    .map((lang) => normalizeText(lang))
    .filter(Boolean)
    .slice(0, 6)
    .join(',');
  if (langs) tokens.push(`langs:${langs}`);
  return tokens;
}

/* -------------------------------------------------------------------------- */
/* Bucket keys                                                                 */
/* -------------------------------------------------------------------------- */

const MIN_TOKENS_FOR_BANDS = 3;

/**
 * All blocking keys for a profile. Pure and deterministic: the same profile
 * always produces the same key list, so `identity_blocks` stays coherent.
 */
export function blockKeysFor(profile: BlockKeyProfile): string[] {
  const keys = new Set<string>();

  const hardware = normalizeText(profile.hardwareFingerprint);
  if (hardware) keys.add(`hw_hash:${hexHash(hardware)}`);

  const gpuText = [normalizeText(profile.gpu?.vendor), normalizeText(profile.gpu?.renderer)]
    .filter(Boolean)
    .join('|');
  const osFamily = normalizeText(profile.os?.family);
  // OS family is the stable anchor. Timezone is deliberately excluded from this hard key:
  // travel/TZ changes must not split a visitor.
  if (gpuText && osFamily) {
    keys.add(`block_gpu:${hexHash(gpuText)}:${osFamily}`);
  }

  // Network bucket only — no volatile screen envelope. A larger display, 2x scaling or
  // enabling touch no longer changes the block key and can no longer mint a new identity.
  const net = networkBucket(profile.net);
  if (net !== 'unknown') {
    keys.add(`block_net:${net}`);
  }

  const tokens = canonicalIdentityFeatures(profile);
  if (tokens.length >= MIN_TOKENS_FOR_BANDS) {
    const simhash = simhash64(tokens);
    for (let band = 0; band < 4; band += 1) keys.add(`band_${band}:${bandHex(simhash, band)}`);
  }

  return [...keys];
}

/* -------------------------------------------------------------------------- */
/* Writes                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Registers a visitor under every bucket key.
 *
 * `INSERT OR IGNORE` is deliberate: an existing (bucket_key, visitor_id) row already links
 * the visitor, so refreshing its `updated_at_utc` bought nothing but one Durable Object
 * `rows_written` per key on every page load — the exact resource the free tier caps. New
 * keys (a changed GPU, a new simhash band) are still inserted, so matching keeps improving.
 * Each key is wrapped in its own try/catch so one malformed key cannot abort the batch.
 */
export function upsertBlocks(db: AIBotDatabase, visitorId: string, keys: string[], nowUtc: string): void {
  const statement = db.prepare(
    `INSERT OR IGNORE INTO identity_blocks (bucket_key, visitor_id, created_at_utc, updated_at_utc)
     VALUES (?, ?, ?, ?)`
  );
  for (const key of keys) {
    if (typeof key !== 'string' || key.length === 0) continue;
    try {
      statement.run(key, visitorId, nowUtc, nowUtc);
    } catch {
      // Index writes are best-effort; matching still works from the remaining keys.
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Reads                                                                       */
/* -------------------------------------------------------------------------- */

function sanitizeLimit(limit: number): number {
  const num = Math.floor(limit);
  return Number.isFinite(num) && num > 0 ? Math.min(num, 500) : 200;
}

/**
 * Candidate visitor ids for a set of bucket keys. Issues one point query per key
 * (`WHERE bucket_key = ? ORDER BY updated_at_utc DESC LIMIT <n>`), dedupes in JS
 * keeping the most recent sighting, and returns the freshest `limit` ids.
 */
export function findCandidates(db: AIBotDatabase, keys: string[], limit = 200): string[] {
  const capped = sanitizeLimit(limit);
  const perKey = Math.max(10, Math.ceil(capped / 2));
  const seen = new Map<string, string>();
  const statement = db.prepare(
    `SELECT visitor_id FROM identity_blocks WHERE bucket_key = ? ORDER BY updated_at_utc DESC LIMIT ${perKey}`
  );
  for (const key of keys) {
    if (typeof key !== 'string' || key.length === 0) continue;
    let rows: Array<{ visitor_id?: unknown }> = [];
    try {
      rows = statement.all(key) as Array<{ visitor_id?: unknown }>;
    } catch {
      continue;
    }
    for (const row of rows) {
      const candidateId = typeof row?.visitor_id === 'string' ? row.visitor_id : '';
      if (!candidateId) continue;
      // Rows come newest-first per key; the first sighting wins the timestamp race.
      if (!seen.has(candidateId)) seen.set(candidateId, candidateId);
    }
  }
  return [...seen.keys()].slice(0, capped);
}

/** Loads one visitor profile row (or null). JSON parsing is fault-tolerant. */
export function loadVisitorProfile(db: AIBotDatabase, visitorId: string): StoredVisitorProfile | null {
  if (typeof visitorId !== 'string' || visitorId.length === 0) return null;
  try {
    const row = db
      .prepare('SELECT * FROM visitor_profiles WHERE visitor_id = ?')
      .get(visitorId) as
      | {
          visitor_id?: unknown;
          profile_json?: unknown;
          hardware_fingerprint?: unknown;
          created_at_utc?: unknown;
          updated_at_utc?: unknown;
        }
      | undefined;
    if (!row || typeof row.visitor_id !== 'string') return null;
    let profile: BlockKeyProfile | null = null;
    if (typeof row.profile_json === 'string' && row.profile_json.length > 0) {
      try {
        profile = JSON.parse(row.profile_json) as BlockKeyProfile;
      } catch {
        profile = null;
      }
    }
    return {
      visitor_id: row.visitor_id,
      hardware_fingerprint: typeof row.hardware_fingerprint === 'string' ? row.hardware_fingerprint : null,
      profile,
      profile_json: typeof row.profile_json === 'string' ? row.profile_json : null,
      created_at_utc: typeof row.created_at_utc === 'string' ? row.created_at_utc : '',
      updated_at_utc: typeof row.updated_at_utc === 'string' ? row.updated_at_utc : '',
    };
  } catch {
    return null;
  }
}

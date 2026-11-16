/**
 * Multi-key visitor identity resolver — Cloudflare Workers compatible.
 *
 * Resolution ladder (first hit wins):
 *   1. Storage — a verified visitor id whose stored hardware fingerprint matches
 *      (or predates) the incoming one → exact re-identification.
 *   2. Blocking index — `blockKeysFor` generates deterministic bucket keys, the
 *      index yields ≤ 200 candidate visitor ids, and every candidate is compared
 *      with the concurrent fingerprint engine (`../../shared/matching/compareFingerprints`).
 *      Ladder tiers: lenient ≥ 82 → cross_browser ≥ 85 → hardware ≥ 88; the
 *      strongest tier (then the highest score) wins. Candidates flagged with
 *      `version_downgrade_anomaly` are skipped.
 *   3. Stitch + heal — the link evidence is recorded in `visitor_links` and the
 *      stored profile is healed forward only (a strictly newer browser major may
 *      replace the stored one; rendering hashes may drift only on the same or a
 *      newer major — never backwards).
 *   4. Fresh identity — nobody matched: mint a new visitor id (WebCrypto, with a
 *      deterministic LCG fallback for runtimes without it), persist the profile
 *      and its blocking keys.
 *
 * Every failure path degrades silently: the resolver NEVER throws. A broken
 * adapter, a malformed profile or an engine error yields a fresh visitor id with
 * `degraded: true` so the request pipeline can continue.
 */

import { bestMode, compareFingerprints, type ComparisonInput } from '../../shared/matching/compareFingerprints';
import type { AIBotDatabase } from '../ai-protection/schema';
import { scoreConfidence } from './confidenceScorer';
import {
  blockKeysFor,
  ensureIdentitySchema,
  findCandidates,
  loadVisitorProfile,
  upsertBlocks,
  type BlockKeyProfile,
  type StoredVisitorProfile,
} from './identityIndex';

/* Re-exported so callers can precompute the engine's best comparison mode. */
export { bestMode };

/* -------------------------------------------------------------------------- */
/* Types                                                                       */
/* -------------------------------------------------------------------------- */

/** Ladder modes, mirroring `ConfidenceMatchMode` from the calibrated scorer. */
export type ResolverMatchMode = 'exact' | 'lenient' | 'cross_browser' | 'hardware' | 'none';

/**
 * The canonical identity profile. Extends the loose `BlockKeyProfile` so it can
 * be handed to the blocking index directly; every family is optional and
 * tolerant of partial telemetry (degraded clients, VPNs, hardened browsers).
 */
export interface ResolverProfile extends BlockKeyProfile {
  /** Stable browser-scope fingerprint echoed from storage (cookie / localStorage). */
  browserFingerprint?: string | null;
  fonts?: { count?: number | null; list?: string[] | null } | null;
  mediaDevices?: { count?: number | null; kinds?: string[] | null } | null;
  webgl?: { hash?: string | null; vendor?: string | null; renderer?: string | null } | null;
  fontPrefs?: { hash?: string | null; families?: string[] | null } | null;
  /** Free-form signals that never block, but travel with the profile for scoring. */
  misc?: Record<string, unknown> | null;
  /** Known component versions (browser, engine, UA-CH, …) — used for heal logic. */
  versions?: Record<string, string | number> | null;
}

export interface ResolveVisitorInput {
  /** Incoming (client-supplied) identity profile for this request. */
  profile?: ResolverProfile | null;
  /** Visitor id echoed from first-party storage (HMAC verified by the caller). */
  storageVisitorId?: string | null;
  /** Mobile iOS flag — lowers the first-visit confidence tier in the scorer. */
  isMobileIos?: boolean;
}

/** Auxiliary identity link for cross-browser stitches. */
export interface SupplementaryMatch {
  visitor_id: string;
  confidence_hint: number;
}

export interface ResolveVisitorResult {
  visitor_id: string;
  match_mode: ResolverMatchMode | string;
  match_score: number;
  is_new: boolean;
  /** camelCase alias of `is_new` for callers that prefer JS-style naming. */
  isNew: boolean;
  /** Calibrated hint from `scoreConfidence`; the facade may recompute with full inputs. */
  confidence_hint: number;
  /** True when the stored profile was healed forward (never downgraded). */
  healed: boolean;
  /** Comparison violations of the winning candidate (scorer consistency flags). */
  reasons: string[];
  /** Present only for cross-browser stitches. */
  supplementary?: SupplementaryMatch;
  /** Set only on the degraded path. */
  degraded?: boolean;
  degraded_reason?: string;
}

/* -------------------------------------------------------------------------- */
/* Small helpers                                                               */
/* -------------------------------------------------------------------------- */

function normalizeText(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase();
}

/** Leading integer of a version string ('126.0.6478.126' → 126). */
function parseMajor(value: unknown): number | null {
  const text = normalizeText(value);
  const match = /^(\d{1,5})/.exec(text);
  return match ? Number.parseInt(match[1], 10) : null;
}

function clampScore(score: unknown): number {
  const num = typeof score === 'number' ? score : Number(score);
  if (!Number.isFinite(num)) return 0;
  return Math.min(100, Math.max(0, Math.round(num * 100) / 100));
}

function confidenceHint(mode: string, score: number, isMobileIos: boolean): number {
  return scoreConfidence({ match_mode: mode, match_score: score, isMobileIos }).score;
}

const LADDER_TIERS: Array<{ mode: ResolverMatchMode; min: number; priority: number }> = [
  { mode: 'hardware', min: 88, priority: 3 },
  { mode: 'cross_browser', min: 85, priority: 2 },
  { mode: 'lenient', min: 82, priority: 1 },
];

const EXACT_PRIORITY = 4;

function tierForScore(score: number): { mode: ResolverMatchMode; priority: number } | null {
  for (const tier of LADDER_TIERS) {
    if (score >= tier.min) return { mode: tier.mode, priority: tier.priority };
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* Defensive engine bridge                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Normalizes the concurrent engine's output defensively: the score is read from
 * any of the known key spellings and violations from theirs, so the resolver
 * compiles and behaves regardless of the engine's exact result shape.
 */
function normalizeComparison(raw: unknown): { score: number; violations: string[] } {
  const obj = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const score = clampScore(obj['match_score'] ?? obj['matchScore'] ?? obj['score'] ?? obj['similarity']);
  const violationsRaw = obj['constraintViolations'] ?? obj['constraint_violations'] ?? obj['violations'];
  const violations = Array.isArray(violationsRaw)
    ? violationsRaw.filter((item): item is string => typeof item === 'string')
    : [];
  return { score, violations };
}

/**
 * Calls the engine with a couple of plausible argument shapes (positional pair
 * first, then a single descriptor object) and awaits a possible promise. All
 * failures collapse to a neutral zero-score comparison.
 */
async function runEngine(incoming: ResolverProfile, stored: BlockKeyProfile | null) {
  const engine = compareFingerprints as unknown as
    | ((input: ComparisonInput | unknown, ...rest: unknown[]) => unknown)
    | null;
  if (typeof engine !== 'function') return { score: 0, violations: [] };

  const attempts: Array<() => unknown> = [
    () => engine(incoming, stored),
    () => engine({ incoming, stored } as unknown as ComparisonInput),
    () => engine({ a: incoming, b: stored } as unknown as ComparisonInput),
  ];
  for (const attempt of attempts) {
    try {
      const raw = await Promise.resolve(attempt());
      if (raw && typeof raw === 'object') {
        return normalizeComparison(raw);
      }
    } catch {
      // Try the next argument shape; the engine may expect a single object.
    }
  }
  return { score: 0, violations: [] };
}

/* -------------------------------------------------------------------------- */
/* Visitor id generation (Workers-safe; no node:crypto)                        */
/* -------------------------------------------------------------------------- */

const ID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const ID_LENGTH = 20;

/** WebCrypto path: rejection sampling below 248 keeps `byte % 62` uniform. */
function randomIdByte(): number | null {
  const cryptoRef = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  if (typeof cryptoRef?.getRandomValues !== 'function') return null;
  const buffer = new Uint8Array(1);
  for (let attempt = 0; attempt < 32; attempt += 1) {
    cryptoRef.getRandomValues(buffer);
    const byte = buffer[0];
    if (byte < 248) return byte;
  }
  return null;
}

/** Deterministic LCG fallback for runtimes without WebCrypto. */
function createLcgBytes(): () => number {
  let seed = (Date.now() ^ Math.floor(Math.random() * 0xffffffff)) >>> 0;
  return () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return (seed >>> 16) & 0xff;
  };
}

function idFromByte(byte: number): string {
  return ID_ALPHABET[byte % ID_ALPHABET.length];
}

function mintVisitorId(): string {
  const lcg = createLcgBytes();
  let id = '';
  while (id.length < ID_LENGTH) {
    const byte = randomIdByte() ?? lcg();
    id += idFromByte(byte);
  }
  return id;
}

/**
 * Generates a 20-char [A-Za-z0-9] visitor id and, when a database is provided,
 * retries against `visitor_profiles` (3 uniqueness retries). Falls back to a
 * time-seeded LCG suffix if every attempt collides (astronomically unlikely).
 */
export function generateVisitorId(db?: AIBotDatabase): string {
  const attempts = 4;
  for (let i = 0; i < attempts; i += 1) {
    const candidate = mintVisitorId();
    if (!db) return candidate;
    try {
      const row = db
        .prepare('SELECT visitor_id FROM visitor_profiles WHERE visitor_id = ?')
        .get(candidate) as { visitor_id?: unknown } | undefined;
      if (!row || row.visitor_id !== candidate) return candidate;
    } catch {
      return candidate;
    }
  }
  return (mintVisitorId() + Date.now().toString(36).slice(-4)).slice(0, ID_LENGTH);
}

/* -------------------------------------------------------------------------- */
/* Persistence helpers (exported for the facade)                               */
/* -------------------------------------------------------------------------- */

/**
 * Inserts or merges a visitor profile. On conflict, non-null incoming values
 * replace stored ones (COALESCE) and `created_at_utc` is preserved. Production
 * adapters (better-sqlite3, Durable Object SQLite) support this upsert natively;
 * the local MemoryDatabase adapter in `../ai-protection/schema` does not parse
 * COALESCE expressions and would overwrite the column instead of merging.
 */
export function upsertVisitorProfile(
  db: AIBotDatabase,
  visitorId: string,
  profile: ResolverProfile | BlockKeyProfile | null,
  hardwareFingerprint: string | null,
  nowUtc: string
): void {
  db.prepare(
    `INSERT INTO visitor_profiles (visitor_id, profile_json, hardware_fingerprint, created_at_utc, updated_at_utc)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(visitor_id) DO UPDATE SET
       profile_json = COALESCE(excluded.profile_json, visitor_profiles.profile_json),
       hardware_fingerprint = COALESCE(excluded.hardware_fingerprint, visitor_profiles.hardware_fingerprint),
       updated_at_utc = excluded.updated_at_utc`
  ).run(visitorId, profile ? JSON.stringify(profile) : null, hardwareFingerprint, nowUtc, nowUtc);
}

/** Records (or refreshes) the cross-hardware link evidence for a visitor. */
export function upsertVisitorLink(
  db: AIBotDatabase,
  visitorId: string,
  hardwareFingerprint: string,
  linkMode: string,
  linkScore: number,
  nowUtc: string
): void {
  const hardware = normalizeText(hardwareFingerprint);
  if (!hardware) return;
  try {
    db.prepare(
      `INSERT INTO visitor_links (visitor_id, hardware_fingerprint, link_mode, link_score, created_at_utc, last_seen_utc)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(visitor_id, hardware_fingerprint) DO UPDATE SET
         link_mode = excluded.link_mode,
         link_score = excluded.link_score,
         last_seen_utc = excluded.last_seen_utc`
    ).run(visitorId, hardware, linkMode, linkScore, nowUtc, nowUtc);
  } catch {
    // Link evidence is best-effort; identity resolution continues without it.
  }
}

/* -------------------------------------------------------------------------- */
/* Profile healing                                                             */
/* -------------------------------------------------------------------------- */

const RENDERING_HASH_KEYS = ['canvas', 'webgl', 'audio'] as const;

/**
 * Heals the stored profile strictly forward: a strictly newer incoming browser
 * major replaces the stored one (never a downgrade), and rendering hashes may
 * drift only when the incoming major is the same or newer. Returns the next
 * profile JSON, or null when there is nothing to heal.
 */
function healStoredProfile(
  stored: StoredVisitorProfile,
  incoming: ResolverProfile
): { healed: boolean; nextProfile: BlockKeyProfile | null } {
  const storedProfile = stored.profile;
  if (!storedProfile || typeof storedProfile !== 'object') return { healed: false, nextProfile: null };

  let healed = false;
  const next: Record<string, unknown> = { ...storedProfile } as Record<string, unknown>;

  const incomingMajor = parseMajor(incoming.browser?.major);
  const storedMajor = parseMajor((storedProfile as BlockKeyProfile).browser?.major);
  const driftAllowed = incomingMajor === null || storedMajor === null || incomingMajor >= storedMajor;

  if (incomingMajor !== null && storedMajor !== null && incomingMajor > storedMajor) {
    const storedBrowser = (storedProfile as BlockKeyProfile).browser ?? {};
    next['browser'] = {
      ...storedBrowser,
      family: incoming.browser?.family ?? storedBrowser.family ?? null,
      major: incoming.browser?.major ?? null,
    };
    healed = true;
  }

  if (driftAllowed) {
    for (const key of RENDERING_HASH_KEYS) {
      const incomingHash = normalizeText((incoming as BlockKeyProfile)[key]?.hash);
      const storedHash = normalizeText((storedProfile as BlockKeyProfile)[key]?.hash);
      if (incomingHash && incomingHash !== storedHash) {
        next[key] = { ...(storedProfile as BlockKeyProfile)[key], hash: incomingHash };
        healed = true;
      }
    }
  }

  const incomingHw = normalizeText(incoming.hardwareFingerprint);
  const storedHw = normalizeText(stored.hardware_fingerprint) || normalizeText((storedProfile as BlockKeyProfile).hardwareFingerprint);
  if (incomingHw && !storedHw) {
    next['hardwareFingerprint'] = incoming.hardwareFingerprint ?? null;
    healed = true;
  }

  return { healed, nextProfile: healed ? (next as unknown as BlockKeyProfile) : null };
}

/** Persists a healed profile (if any) and returns whether a heal happened. */
function persistHeal(
  db: AIBotDatabase,
  stored: StoredVisitorProfile,
  incoming: ResolverProfile,
  nowUtc: string
): boolean {
  const { healed, nextProfile } = healStoredProfile(stored, incoming);
  if (!healed || !nextProfile) return false;
  const incomingHw = normalizeText(incoming.hardwareFingerprint);
  const hardware = normalizeText(stored.hardware_fingerprint) || incomingHw || null;
  try {
    db.prepare(
      'UPDATE visitor_profiles SET profile_json = ?, hardware_fingerprint = ?, updated_at_utc = ? WHERE visitor_id = ?'
    ).run(JSON.stringify(nextProfile), hardware, nowUtc, stored.visitor_id);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Main resolver                                                               */
/* -------------------------------------------------------------------------- */

function degradedResult(
  db: AIBotDatabase | null,
  input: ResolveVisitorInput,
  reason: string,
  nowUtc: string
): ResolveVisitorResult {
  let visitorId = generateVisitorId(db ?? undefined);
  try {
    if (db) {
      upsertVisitorProfile(db, visitorId, input.profile ?? null, normalizeText(input.profile?.hardwareFingerprint) || null, nowUtc);
      upsertBlocks(db, visitorId, blockKeysFor(input.profile ?? {}), nowUtc);
    }
  } catch {
    // Persistence failed too — still return a usable id for the request.
    visitorId = generateVisitorId();
  }
  return {
    visitor_id: visitorId,
    match_mode: 'none',
    match_score: 0,
    is_new: true,
    isNew: true,
    confidence_hint: confidenceHint('none', 0, Boolean(input.isMobileIos)),
    healed: false,
    reasons: [],
    degraded: true,
    degraded_reason: reason,
  };
}

/**
 * Resolves the incoming profile against storage, the blocking index and the
 * fingerprint engine. Never throws; never fabricates matches.
 */
export async function resolveVisitor(db: AIBotDatabase, input: ResolveVisitorInput): Promise<ResolveVisitorResult> {
  const nowUtc = new Date().toISOString();
  try {
    ensureIdentitySchema(db);

    const profile: ResolverProfile = input.profile && typeof input.profile === 'object' ? input.profile : {};
    const incomingHw = normalizeText(profile.hardwareFingerprint);
    const storageVisitorId = normalizeText(input.storageVisitorId) || '';
    const keys = blockKeysFor(profile);

    /* ---- 1. Storage path — verified id with a compatible hardware fingerprint. */
    if (storageVisitorId) {
      const stored = loadVisitorProfile(db, storageVisitorId);
      if (stored) {
        const storedHw =
          normalizeText(stored.hardware_fingerprint) ||
          normalizeText((stored.profile as BlockKeyProfile | null)?.hardwareFingerprint);
        if (!incomingHw || !storedHw || incomingHw === storedHw) {
          try {
            db.prepare(
              'UPDATE visitor_profiles SET updated_at_utc = ?, hardware_fingerprint = ? WHERE visitor_id = ?'
            ).run(nowUtc, storedHw || incomingHw || null, storageVisitorId);
          } catch {
            // Touch failure must not downgrade an exact match.
          }
          upsertBlocks(db, storageVisitorId, keys, nowUtc);
          return {
            visitor_id: storageVisitorId,
            match_mode: 'exact',
            match_score: 100,
            is_new: false,
            isNew: false,
            confidence_hint: confidenceHint('exact', 100, Boolean(input.isMobileIos)),
            healed: false,
            reasons: [],
          };
        }
        // Verified id but the hardware changed: fall through — the ladder may
        // still recover this id through other keys, or prove it is a new device.
      }
    }

    /* ---- 2. Blocking index + engine ladder. */
    const candidateIds = findCandidates(db, keys, 200);
    let best: {
      id: string;
      stored: StoredVisitorProfile;
      mode: ResolverMatchMode;
      score: number;
      violations: string[];
      priority: number;
    } | null = null;

    for (const candidateId of candidateIds) {
      const stored = loadVisitorProfile(db, candidateId);
      if (!stored) continue;
      if (stored.profile_json && stored.profile_json.includes('version_downgrade_anomaly')) continue;

      const storedHw =
        normalizeText(stored.hardware_fingerprint) ||
        normalizeText((stored.profile as BlockKeyProfile | null)?.hardwareFingerprint);

      // Hardware-equality shortcut — the strongest non-storage signal.
      if (incomingHw && storedHw && incomingHw === storedHw) {
        best = {
          id: candidateId,
          stored,
          mode: 'exact',
          score: 100,
          violations: [],
          priority: EXACT_PRIORITY,
        };
        break;
      }

      const { score, violations } = await runEngine(profile, stored.profile);
      if (violations.includes('version_downgrade_anomaly')) continue;
      const tier = tierForScore(score);
      if (!tier) continue;
      if (!best || tier.priority > best.priority || (tier.priority === best.priority && score > best.score)) {
        best = { id: candidateId, stored, mode: tier.mode, score, violations, priority: tier.priority };
      }
    }

    /* ---- 3. Matched: record the stitch, heal forward, return. */
    if (best) {
      const healed = persistHeal(db, best.stored, profile, nowUtc);
      if (incomingHw) {
        upsertVisitorLink(db, best.id, incomingHw, best.mode, best.score, nowUtc);
      }
      upsertBlocks(db, best.id, keys, nowUtc);
      return {
        visitor_id: best.id,
        match_mode: best.mode,
        match_score: best.score,
        is_new: false,
        isNew: false,
        confidence_hint: confidenceHint(best.mode, best.score, Boolean(input.isMobileIos)),
        healed,
        reasons: best.violations,
        supplementary:
          best.mode === 'cross_browser'
            ? { visitor_id: best.id, confidence_hint: 0.95 }
            : undefined,
      };
    }

    /* ---- 4. Fresh identity. */
    const visitorId = generateVisitorId(db);
    upsertVisitorProfile(db, visitorId, profile, incomingHw || null, nowUtc);
    upsertBlocks(db, visitorId, keys, nowUtc);
    return {
      visitor_id: visitorId,
      match_mode: 'none',
      match_score: 0,
      is_new: true,
      isNew: true,
      confidence_hint: confidenceHint('none', 0, Boolean(input.isMobileIos)),
      healed: false,
      reasons: [],
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message.slice(0, 200) : 'identity resolver failure';
    return degradedResult(db, input, reason, nowUtc);
  }
}

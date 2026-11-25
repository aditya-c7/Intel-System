/**
 * Three-tier identity backlog — pure, dependency-free, non-throwing helpers.
 *
 * This module deliberately performs NO writes, talks to NO Durable Object, and raises NO
 * alarms. Every export is a total function over untrusted input: a malformed, hostile or
 * partially observed signal object degrades to a conservative answer rather than throwing
 * or fabricating an identifier.
 *
 * The three tiers are intentionally kept separate so a caller can escalate one without
 * minting an identity at a lower tier:
 *
 *   1. `resolveVisitorIdentityTier`  — decides ONLY a visitor-id STRATEGY
 *      ('precision' | 'high_recall'). It never returns a visitor id, not even one that was
 *      supplied in the signals, so a caller can never mistake this helper for an id issuer.
 *   2. `resolveSupplementaryHighRecall` — returns descriptive, stable GROUP KEYS derived
 *      from stable feature groups. They are cohort labels, not opaque ids: no random or
 *      per-session value is ever minted.
 *   3. `resolveHardwareSimHashProfile` — a normalized hardware-invariant feature vector
 *      plus a 512-bit-shaped hash string built from pure FNV-1a (no external SDK). Only
 *      browser-invariant signals enter the vector (WebGPU static limits/features, GPU
 *      renderer family, CPU arch/cores consensus, screen geometry/color profile, system
 *      fonts, timezone NAME, audio hardware traits). Volatile signals (canvas noise,
 *      storage quota, timezone OFFSET, audio fingerprint sum) are structurally excluded.
 *
 * The R4 supplementary high-recall ID lives in `identityEngine.ts` as an ADDITIVE sibling:
 * a deterministic, versioned HMAC-SHA-256 hint derived only from resolved stable signals.
 * It is emitted beside the primary id, carries no confidence score and is never a sole
 * blocking key. This module's Tier-2 group keys below remain descriptive cohort labels.
 *
 * HONESTY / RESEARCH BOUNDARY:
 *   - The 512-bit hash is a HEURISTIC cohort label, NOT a verified device identity.
 *   - WebGPU static limits + features carry only ~5.19 bits (~122 anonymity sets), and
 *     `adapter.info` is frequently empty; this is a weak fingerprint surface.
 *   - Atomic-contention WebGPU identity (DrawnApart / LockedApart / atomic histograms) is
 *     RESEARCH_ONLY: 57/80 cross-visit stability, timer-sensitive (a 32 ms clamp collapses
 *     AUROC), GPU/driver/thermal dependent, and needs a labeled training corpus. It is
 *     NEVER hashed here; when such a signal is supplied, an explicit `research_only`
 *     disclosure is returned in the profile.
 */

/* -------------------------------------------------------------------------- */
/* Public types                                                                */
/* -------------------------------------------------------------------------- */

export type VisitorIdStrategy = 'precision' | 'high_recall';
export type TierConfidence = 'high' | 'medium' | 'low';

/** Shape of the signal bundle the three helpers consume. Every field is optional and
 *  defensive code must treat the whole thing as untrusted; an index signature allows
 *  extra fields (including volatile ones) without a compile error. */
export interface IdentityTierSignals {
  /* tier 1 — precision evidence */
  storageVisitorId?: string | null;
  storageValid?: boolean;
  exactHardwareId?: string | null;
  distinctStorageSeedsCount?: number;
  matchStage?: string | null;
  matchSimilarity?: number | null;
  collisionDensity?: number | null;
  structuralAnchorRatio?: number | null;

  /* stable structural / hardware features (CPU + GPU consensus) */
  architecture?: string | null;
  gpuVendor?: string | null;
  gpuRenderer?: string | null;
  gpuArchFamily?: string | null;
  hostOs?: string | null;
  engine?: string | null;
  browserFamily?: string | null;
  osFamily?: string | null;
  deviceClass?: string | null;
  platform?: string | null;
  hardwareConcurrency?: number | null;
  deviceMemory?: number | null;

  /* ALREADY RESOLVED stable signals consumed by the additive high-recall sibling id in
   * `identityEngine.ts` (buildHighRecallInput / resolveSupplementaryHighRecall). These are
   * descriptive inputs only: this module never mints an id from them. Raw IP / raw UA are
   * deliberately absent — only a /24 or /48 prefix and a normalized UA may be used as seed. */
  normalizedUserAgent?: string | null;
  firstLanguage?: string | null;
  language?: string | null;
  clientIp?: string | null;
  publicIp?: string | null;
  ip?: string | null;
  tenantId?: string | null;
  instanceId?: string | null;

  /* browser-invariant screen / font / timezone / audio-hardware traits */
  screenWidth?: number | null;
  screenHeight?: number | null;
  colorDepth?: number | null;
  pixelDepth?: number | null;
  systemFonts?: readonly string[] | ReadonlySet<string> | null;
  fontCount?: number | null;
  /** IANA timezone NAME (stable-ish) — NOT the volatile `timezoneOffset`. */
  timezone?: string | null;
  audioSampleRate?: number | null;
  audioOutputChannels?: number | null;

  /* WebGPU STATIC surface (adapter.info is often empty; features + limits are the signal) */
  webgpuAdapterInfo?: {
    vendor?: string | null;
    architecture?: string | null;
    device?: string | null;
    description?: string | null;
  } | null;
  webgpuVendor?: string | null;
  webgpuArchitecture?: string | null;
  webgpuDevice?: string | null;
  webgpuDescription?: string | null;
  webgpuFeatures?: readonly string[] | ReadonlySet<string> | null;
  webgpuLimits?: {
    maxComputeWorkgroupSizeX?: number | null;
    maxComputeWorkgroupSizeY?: number | null;
    maxComputeWorkgroupSizeZ?: number | null;
    maxComputeWorkgroupsPerDimension?: number | null;
  } | null;
  webgpuMaxComputeWorkgroupSizeX?: number | null;
  webgpuMaxComputeWorkgroupSizeY?: number | null;
  webgpuMaxComputeWorkgroupSizeZ?: number | null;
  webgpuMaxComputeWorkgroupsPerDimension?: number | null;

  /* RESEARCH-ONLY atomic-contention signals — never hashed, disclosed when present */
  webgpuAtomicContention?: unknown;
  drawnApart?: unknown;
  lockedApart?: unknown;
  atomicHistogram?: unknown;
  atomicContention?: unknown;

  /* hardening / tampering — downgrade precision */
  privacyHardened?: boolean;
  antiDetectBrowser?: boolean;
  tamperingDetected?: boolean;

  /* volatile — accepted for auditing but NEVER used by the hardware profile */
  canvasNoise?: unknown;
  canvasHash?: unknown;
  storageQuota?: unknown;
  timezoneOffset?: unknown;
  audioSum?: unknown;
  audioFingerprint?: unknown;
  audioNoise?: unknown;

  [key: string]: unknown;
}

export interface VisitorIdentityTier {
  /** Strategy only. There is intentionally no id field on this result. */
  visitor_id_strategy: VisitorIdStrategy;
  /** Ordered, stable tokens explaining the decision (never signal VALUES / ids). */
  reason: string[];
  confidence: TierConfidence;
}

/** Documented upper-bound research estimate for the WebGPU static surface. */
export interface WebgpuStaticEntropy {
  readonly bits: number;
  readonly anonymitySets: number;
  readonly surface: string;
  readonly note: string;
}

export interface ResearchOnlyDisclosure {
  atomicContentionWebGpu: 'research_only';
  note: string;
  /** Sorted keys of any research-only atomic-contention signals that were supplied. */
  referencedSignals: string[];
}

export interface HardwareSimHashProfile {
  /** Normalized, hardware-invariant feature vector. Keys sorted, values normalized strings. */
  features: Record<string, string>;
  /** 512-bit-shaped hash: 128 lowercase hex chars (8 x 64-bit pure FNV-1a words). */
  hash512: string;
  /** Sorted whitelisted feature keys that were actually present. */
  usedKeys: string[];
  /** Sorted volatile keys that were detected and deliberately ignored. */
  ignoredVolatileKeys: string[];
  /** Honest framing: heuristic cohort hash, never a verified device identity. */
  heuristic: true;
  verifiedDeviceIdentity: false;
  /** WebGPU static entropy ceiling (research figure, not a guaranteed entropy budget). */
  webgpuStaticEntropy: WebgpuStaticEntropy;
  /** Explicit disclosure for research-only atomic-contention WebGPU signals. */
  researchOnly: ResearchOnlyDisclosure;
}

/** Volatile signals the hardware profile must never fold into its vector or hash. */
export const VOLATILE_SIGNAL_KEYS: ReadonlySet<string> = new Set([
  'audioFingerprint',
  'audioNoise',
  'audioSum',
  'canvas',
  'canvasHash',
  'canvasNoise',
  'localStorageQuota',
  'quota',
  'storageQuota',
  'timezoneOffset',
]);

/** Research-only atomic-contention WebGPU signals: disclosed, never hashed. */
export const WEBGPU_RESEARCH_ONLY_KEYS: ReadonlySet<string> = new Set([
  'atomicContention',
  'atomicHistogram',
  'drawnApart',
  'lockedApart',
  'webgpuAtomicContention',
]);

/** Explicit research-only note for atomic-contention WebGPU identity. */
export const WEBGPU_RESEARCH_ONLY_NOTE =
  'Atomic-contention WebGPU identity (DrawnApart/LockedApart/atomic histograms) is RESEARCH_ONLY: ' +
  'cross-visit stability 57/80, timer-sensitive (a 32ms clamp collapses AUROC), ' +
  'GPU/driver/thermal dependent, and requires a labeled training corpus. ' +
  'It is NOT a cryptographic or stable hardware id and is never hashed into this profile.';

/** WebGPU static surface: features Set + static compute limits. ~5.19 bits / 122 sets. */
export const WEBGPU_STATIC_ENTROPY: WebgpuStaticEntropy = {
  bits: 5.19,
  anonymitySets: 122,
  surface:
    'device.features Set + static limits (maxComputeWorkgroupSizeX/Y/Z, maxComputeWorkgroupsPerDimension)',
  note:
    'adapter.info {vendor,architecture,device,description} is frequently empty; this is a weak, ' +
    'heuristic fingerprint surface, not a verified device identity.',
};

/* -------------------------------------------------------------------------- */
/* Defensive primitives — all total (never throw)                             */
/* -------------------------------------------------------------------------- */

/** Property read that survives null/undefined, primitives and throwing getters/proxies. */
function safeGet(source: unknown, key: string): unknown {
  if (source === null || source === undefined) return undefined;
  const kind = typeof source;
  if (kind !== 'object' && kind !== 'function') return undefined;
  try {
    return (source as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/** Bounded, trimmed string. Long/pathological inputs are truncated deterministically. */
function asString(value: unknown): string {
  if (typeof value !== 'string') return '';
  const text = value.trim();
  if (!text) return '';
  return text.length > 256 ? text.slice(0, 256) : text;
}

function asBool(value: unknown): boolean {
  return value === true;
}

function asFiniteNumber(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return value;
}

/** Lowercase, whitespace-collapsed, bounded token. */
function token(value: unknown): string {
  return asString(value)
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

/** Non-negative integer token (for WebGPU limits, screen geometry, audio traits). */
function intToken(value: unknown): string {
  const n = asFiniteNumber(value);
  if (n === null || n < 0) return '';
  return String(Math.trunc(n));
}

/** Quantize device memory to a power-of-two bucket so tiny probe jitter cannot change it. */
function memoryBucket(value: unknown): string {
  const gb = asFiniteNumber(value);
  if (gb === null || gb <= 0) return '';
  const bucket = Math.pow(2, Math.floor(Math.log2(gb)));
  return Number.isFinite(bucket) ? String(bucket) : '';
}

/** Quantize core counts into stable buckets; half-integer boundaries absorb probe jitter
 *  (8 and 8.5 cores both land in '5-8'). */
function coresBucket(value: unknown): string {
  const n = asFiniteNumber(value);
  if (n === null || n <= 0) return '';
  if (n <= 2.5) return '1-2';
  if (n <= 4.5) return '3-4';
  if (n <= 8.5) return '5-8';
  if (n <= 16.5) return '9-16';
  return '17+';
}

/** Coarse font-count bucket. */
function countBucket(value: unknown): string {
  const n = asFiniteNumber(value);
  if (n === null || n < 0) return '';
  if (n < 10) return '0-9';
  if (n < 50) return '10-49';
  if (n < 100) return '50-99';
  if (n < 200) return '100-199';
  return '200+';
}

/** Coarse, normalized GPU renderer family (stable across driver string noise). */
function gpuRendererFamily(value: unknown): string {
  const t = token(value);
  if (!t) return '';
  if (/swiftshader|llvmpipe|softpipe|software|basic render|virgl|ranchu/.test(t)) return 'software';
  if (/nvidia|geforce|quadro|\brtx\b|\bgtx\b/.test(t)) return 'nvidia';
  if (/radeon|\bamd\b/.test(t)) return 'amd';
  if (/intel|iris|uhd|hd graphics|arc/.test(t)) return 'intel';
  if (/apple m[1-9]|apple gpu/.test(t)) return 'apple';
  if (/adreno|mali|powervr|arm gpu/.test(t)) return 'arm';
  return 'unknown';
}

/** Normalize an array / Set / iterable of tokens into a bounded, sorted, deduped list. */
function asTokenList(value: unknown): string[] {
  if (value === null || value === undefined) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (item: unknown): void => {
    const valueToken = token(item);
    if (valueToken && !seen.has(valueToken) && out.length < 64) {
      seen.add(valueToken);
      out.push(valueToken);
    }
  };
  try {
    if (Array.isArray(value)) {
      for (const item of value) push(item);
    } else if (value instanceof Set) {
      for (const item of value) push(item);
    } else if (typeof (value as { [Symbol.iterator]?: unknown })?.[Symbol.iterator] === 'function') {
      for (const item of value as Iterable<unknown>) push(item);
    } else {
      push(value);
    }
  } catch {
    // A throwing iterable contributes nothing.
  }
  return out.sort();
}

/** WebGPU adapter.info field — flat override first, nested adapter.info second. */
function webgpuInfoField(signals: unknown, name: 'Vendor' | 'Architecture' | 'Device' | 'Description'): string {
  const flat = safeGet(signals, `webgpu${name}`);
  if (flat !== undefined) return token(flat);
  const info = safeGet(signals, 'webgpuAdapterInfo');
  return token(safeGet(info, name.charAt(0).toLowerCase() + name.slice(1)));
}

/** WebGPU static limit — flat override first, nested `webgpuLimits` second. */
function webgpuLimit(signals: unknown, name: string): string {
  const flat = safeGet(signals, `webgpu${name}`);
  if (flat !== undefined) return intToken(flat);
  return intToken(safeGet(safeGet(signals, 'webgpuLimits'), name));
}

/** WebGPU device.features Set (or array) — flat first, nested device object second. */
function webgpuFeatureTokens(signals: unknown): string[] {
  const flat = safeGet(signals, 'webgpuFeatures');
  if (flat !== undefined) return asTokenList(flat);
  return asTokenList(safeGet(safeGet(signals, 'webgpuDeviceFeatures'), 'features'));
}

/* -------------------------------------------------------------------------- */
/* Tier 1 — visitor id STRATEGY (never an id)                                  */
/* -------------------------------------------------------------------------- */

/**
 * Choose how a caller SHOULD resolve a visitor id. The result contains a strategy and
 * reasons only: no supplied id is echoed and no new id is generated. Untrusted
 * environments (tampering / anti-detect) are forced to high recall so a precision merge
 * can never be pinned on a compromised signal bundle.
 */
export function resolveVisitorIdentityTier(signals: unknown): VisitorIdentityTier {
  const reason: string[] = [];

  const storageId = asString(safeGet(signals, 'storageVisitorId'));
  const storageValid = asBool(safeGet(signals, 'storageValid'));
  const hardwareId = asString(safeGet(signals, 'exactHardwareId'));
  const seedsRaw = asFiniteNumber(safeGet(signals, 'distinctStorageSeedsCount'));
  const seeds = seedsRaw === null ? 0 : Math.max(0, Math.floor(seedsRaw));
  const privacy = asBool(safeGet(signals, 'privacyHardened'));
  const antiDetect = asBool(safeGet(signals, 'antiDetectBrowser'));
  const tampering = asBool(safeGet(signals, 'tamperingDetected'));
  const stage = token(safeGet(signals, 'matchStage'));
  const similarity = asFiniteNumber(safeGet(signals, 'matchSimilarity'));
  const collision = asFiniteNumber(safeGet(signals, 'collisionDensity'));
  const anchorRatio = asFiniteNumber(safeGet(signals, 'structuralAnchorRatio'));

  // 1. Untrusted environment — never bind a precision identity.
  if (tampering || antiDetect) {
    if (tampering) reason.push('tampering_detected');
    if (antiDetect) reason.push('anti_detect_browser');
    reason.push('untrusted_environment_requires_high_recall');
    return { visitor_id_strategy: 'high_recall', reason, confidence: 'low' };
  }

  // 2. First-party continuity — strongest precision anchor; storage is authoritative.
  if (storageValid && storageId) {
    reason.push('first_party_storage_valid');
    if (privacy) reason.push('privacy_hardened_but_storage_authoritative');
    return { visitor_id_strategy: 'precision', reason, confidence: 'high' };
  }
  reason.push('no_valid_first_party_storage');

  // 3. Exact hardware anchor, gated by the distinct-storage-seed collision guard.
  if (hardwareId) {
    reason.push('exact_hardware_anchor');
    if (seeds >= 2 && !privacy) {
      reason.push('distinct_storage_seeds_consensus');
      return { visitor_id_strategy: 'precision', reason, confidence: 'high' };
    }
    if (privacy) reason.push('privacy_hardened_blocks_hardware_precision');
    else reason.push('single_storage_seed_insufficient_for_precision');
    return { visitor_id_strategy: 'high_recall', reason, confidence: privacy ? 'low' : 'medium' };
  }
  reason.push('no_exact_hardware_anchor');

  // 4. Fuzzy (LSH) evidence — precision only with high similarity, low collision and a
  //    strong structural anchor, and never under privacy hardening.
  if (stage.includes('lsh') || similarity !== null) {
    const sim = similarity ?? 0;
    const col = collision ?? 0;
    const anchor = anchorRatio ?? 0;
    reason.push('fuzzy_match_evidence');
    if (sim >= 0.9 && col < 2 && anchor >= 0.8 && !privacy) {
      reason.push('high_similarity_low_collision_strong_anchor');
      return { visitor_id_strategy: 'precision', reason, confidence: 'medium' };
    }
    if (privacy) reason.push('privacy_hardened_entropy_reduced');
    if (sim < 0.9) reason.push('similarity_below_precision_gate');
    if (col >= 2) reason.push('collision_density_blocks_precision');
    if (anchor < 0.8) reason.push('weak_structural_anchor');
    return { visitor_id_strategy: 'high_recall', reason, confidence: 'medium' };
  }

  // 5. Privacy-hardened / reduced entropy — recall grouping is the only safe option.
  if (privacy) {
    reason.push('privacy_hardened_entropy_reduced', 'high_recall_grouping_only');
    return { visitor_id_strategy: 'high_recall', reason, confidence: 'low' };
  }

  // 6. Insufficient evidence — new / unobserved enrollment.
  reason.push('insufficient_evidence_new_enrollment');
  return { visitor_id_strategy: 'high_recall', reason, confidence: 'low' };
}

/* -------------------------------------------------------------------------- */
/* Tier 2 — supplementary high-recall group keys (no ids minted)               */
/* -------------------------------------------------------------------------- */

/**
 * Stable, descriptive group keys built from stable feature groups. These are cohort
 * labels (e.g. `grp:arch:x86_64`), NOT opaque identifiers: every segment is derived from a
 * normalized feature value so the same signals always produce the same keys and no random
 * or per-session value is introduced. Volatile signals are ignored.
 */
export function resolveSupplementaryHighRecall(signals: unknown): string[] {
  const groups: ReadonlyArray<{ prefix: string; signal: string; normalize: (v: unknown) => string }> = [
    { prefix: 'arch', signal: 'architecture', normalize: token },
    { prefix: 'browser', signal: 'browserFamily', normalize: token },
    { prefix: 'cores', signal: 'hardwareConcurrency', normalize: coresBucket },
    { prefix: 'device-class', signal: 'deviceClass', normalize: token },
    { prefix: 'engine', signal: 'engine', normalize: token },
    { prefix: 'gpu-family', signal: 'gpuArchFamily', normalize: token },
    { prefix: 'gpu-renderer', signal: 'gpuRenderer', normalize: token },
    { prefix: 'gpu-vendor', signal: 'gpuVendor', normalize: token },
    { prefix: 'os', signal: 'hostOs', normalize: token },
    { prefix: 'os-family', signal: 'osFamily', normalize: token },
  ];

  const keys = new Set<string>();
  for (const group of groups) {
    const value = group.normalize(safeGet(signals, group.signal));
    if (value) keys.add(`grp:${group.prefix}:${value}`);
  }
  // Always return a deterministic, non-empty cohort key set.
  if (keys.size === 0) keys.add('grp:unclassified');
  return Array.from(keys).sort();
}

/* -------------------------------------------------------------------------- */
/* Tier 3 — hardware-invariant normalized vector + pure-FNV 512-bit hash       */
/* -------------------------------------------------------------------------- */

const MASK64 = (1n << 64n) - 1n;
const FNV_PRIME64 = 0x100000001b3n;
/** Eight distinct offset bases yield 8 x 64 = 512 bits of pure FNV-1a. */
const FNV_OFFSETS: readonly bigint[] = [
  0xcbf29ce484222325n,
  0x84222325cbf29ce4n,
  0x9e3779b97f4a7c15n,
  0xbf58476d1ce4e5b9n,
  0x94d049bb133111ebn,
  0x7f4a7c15bf58476dn,
  0x2545f4914f6cdd1dn,
  0xd6e8feb86659fd93n,
];

/** Pure FNV-1a, 64-bit, using BigInt only. No external SDK, no Math.random, no Date. */
function fnv1a64(input: string, offset: bigint): bigint {
  let hash = offset & MASK64;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= BigInt(input.charCodeAt(i));
    hash = (hash * FNV_PRIME64) & MASK64;
  }
  return hash & MASK64;
}

/** 128 lowercase hex chars (512 bits), stable across key insertion order. */
function hash512(features: Record<string, string>): string {
  const serialized = Object.keys(features)
    .sort()
    .map((key) => `${key}=${features[key]}`)
    .join('|');
  let out = '';
  for (const offset of FNV_OFFSETS) {
    out += fnv1a64(serialized, offset).toString(16).padStart(16, '0');
  }
  return out;
}

/** Build the normalized, browser-invariant feature vector. Every entry is a whitelisted
 *  stable signal; research-only atomic-contention signals are deliberately absent. */
function buildHardwareFeatures(signals: unknown): Record<string, string> {
  const features: Record<string, string> = {};
  const add = (key: string, value: string): void => {
    if (value) features[key] = value;
  };

  // CPU / GPU consensus.
  add('architecture', token(safeGet(signals, 'architecture')));
  add('browser_family', token(safeGet(signals, 'browserFamily')));
  add('cpu_cores_bucket', coresBucket(safeGet(signals, 'hardwareConcurrency')));
  add('device_class', token(safeGet(signals, 'deviceClass')));
  add('engine', token(safeGet(signals, 'engine')));
  add('gpu_arch_family', token(safeGet(signals, 'gpuArchFamily')));
  add('gpu_renderer', token(safeGet(signals, 'gpuRenderer')));
  add('gpu_renderer_family', gpuRendererFamily(safeGet(signals, 'gpuRenderer')));
  add('gpu_vendor', token(safeGet(signals, 'gpuVendor')));
  add('host_os', token(safeGet(signals, 'hostOs')));
  add('memory_gb_bucket', memoryBucket(safeGet(signals, 'deviceMemory')));
  add('os_family', token(safeGet(signals, 'osFamily')));
  add('platform', token(safeGet(signals, 'platform')));

  // Screen geometry / color profile / system fonts / timezone NAME / audio hardware traits.
  add('audio_channels', intToken(safeGet(signals, 'audioOutputChannels')));
  add('audio_sample_rate', intToken(safeGet(signals, 'audioSampleRate')));
  add('color_depth', intToken(safeGet(signals, 'colorDepth')));
  add('font_count', countBucket(safeGet(signals, 'fontCount')));
  add('font_list', asTokenList(safeGet(signals, 'systemFonts')).join(','));
  add('pixel_depth', intToken(safeGet(signals, 'pixelDepth')));
  add('screen_height', intToken(safeGet(signals, 'screenHeight')));
  add('screen_width', intToken(safeGet(signals, 'screenWidth')));
  add('timezone_name', token(safeGet(signals, 'timezone')));

  // WebGPU STATIC surface. adapter.info is frequently empty; only non-empty values enter.
  add('webgpu_adapter_arch', webgpuInfoField(signals, 'Architecture'));
  add('webgpu_adapter_desc', webgpuInfoField(signals, 'Description'));
  add('webgpu_adapter_device', webgpuInfoField(signals, 'Device'));
  add('webgpu_adapter_vendor', webgpuInfoField(signals, 'Vendor'));
  add('webgpu_features', webgpuFeatureTokens(signals).join(','));
  add('webgpu_limits_compute_wg_x', webgpuLimit(signals, 'maxComputeWorkgroupSizeX'));
  add('webgpu_limits_compute_wg_y', webgpuLimit(signals, 'maxComputeWorkgroupSizeY'));
  add('webgpu_limits_compute_wg_z', webgpuLimit(signals, 'maxComputeWorkgroupSizeZ'));
  add('webgpu_limits_dispatch_dim', webgpuLimit(signals, 'maxComputeWorkgroupsPerDimension'));

  return features;
}

/**
 * Build a normalized hardware-invariant feature vector and its pure-FNV 512-bit-shaped
 * hash. Only whitelisted stable hardware features enter the vector; every volatile key in
 * `VOLATILE_SIGNAL_KEYS` is structurally excluded and reported in `ignoredVolatileKeys`
 * for auditability. Two signals differing only in volatile noise produce the SAME hash.
 *
 * The result is explicitly labeled HEURISTIC, not a verified device identity, and any
 * research-only atomic-contention WebGPU signal is disclosed but never hashed.
 */
export function resolveHardwareSimHashProfile(signals: unknown): HardwareSimHashProfile {
  const features = buildHardwareFeatures(signals);

  const ignoredVolatileKeys: string[] = [];
  for (const key of VOLATILE_SIGNAL_KEYS) {
    if (safeGet(signals, key) !== undefined) ignoredVolatileKeys.push(key);
  }
  ignoredVolatileKeys.sort();

  const referencedSignals: string[] = [];
  for (const key of WEBGPU_RESEARCH_ONLY_KEYS) {
    if (safeGet(signals, key) !== undefined) referencedSignals.push(key);
  }
  referencedSignals.sort();

  return {
    features,
    hash512: hash512(features),
    usedKeys: Object.keys(features).sort(),
    ignoredVolatileKeys,
    heuristic: true,
    verifiedDeviceIdentity: false,
    webgpuStaticEntropy: WEBGPU_STATIC_ENTROPY,
    researchOnly: {
      atomicContentionWebGpu: 'research_only',
      note: WEBGPU_RESEARCH_ONLY_NOTE,
      referencedSignals,
    },
  };
}

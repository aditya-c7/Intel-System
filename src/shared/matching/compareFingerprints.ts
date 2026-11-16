/**
 * Intel System — 6-mode fuzzy fingerprint matching engine.
 *
 * Pure TypeScript, dual-target (browser + Cloudflare Workers). No Node APIs,
 * no project imports. `compareFingerprints` is deterministic (no
 * Math.random / Date.now), synchronous, and total — it never throws and
 * returns a well-formed result even for empty or malformed inputs.
 *
 * Scoring model: per-family similarity kernels in [0, 1] combined through a
 * per-mode weight matrix whose weights sum to 100. Families with no
 * comparable signal on BOTH sides are excluded from the denominator (they
 * neither help nor hurt); a family present on only one side scores 0 and
 * counts against the match.
 */

/* -------------------------------------------------------------------------- */
/* Types                                                                       */
/* -------------------------------------------------------------------------- */

export type MatchMode =
  | 'exact'
  | 'strict'
  | 'lenient'
  | 'cross-browser'
  | 'hardware-only'
  | 'engine-only';

export type Family =
  | 'gpu'
  | 'cpu'
  | 'screen'
  | 'timezone'
  | 'fonts'
  | 'mediaDevices'
  | 'canvas'
  | 'webgl'
  | 'audio'
  | 'fontPrefs'
  | 'misc';

export const FAMILY_ORDER: Family[] = [
  'gpu',
  'cpu',
  'screen',
  'timezone',
  'fonts',
  'mediaDevices',
  'canvas',
  'webgl',
  'audio',
  'fontPrefs',
  'misc',
];

export interface GpuSignals {
  normalizedGpu: string;
  invariantLimitsHash: string;
}

export interface CpuSignals {
  arch: string;
  cores: number | null;
  memoryGb: number | null;
  osFamily: string;
}

export interface ScreenSignals {
  width: number;
  height: number;
  dpr: number;
  colorDepth: number;
  touch: number;
}

export interface TimezoneSignals {
  name: string;
  offsetMinutes: number;
}

export interface FontsSignals {
  list: string[];
  hash: string;
  platformClass: string;
}

export interface MediaDevicesSignals {
  audioIn: number | boolean | null;
  audioOut: number | boolean | null;
  video: number | boolean | null;
}

export interface CanvasSignals {
  geometry: string;
  text: string;
  stabilized?: string;
}

export interface WebglSignals {
  extensionsHash: string;
  paramsHash: string;
  shaderPrecisionHash: string;
  extensionsList?: string[];
}

export interface AudioSignals {
  sum: number | null;
  baseLatency: number | null;
  braveFlag?: boolean;
}

export interface FontPrefsSignals {
  widths: Record<string, number | null>;
  emojiRectHash: string;
}

export interface MiscSignals {
  mathHash: string;
  errorStackHash: string;
}

export interface VersionsSignals {
  browserFamily: string;
  browserMajor: number;
  osVersionMajor: number;
}

/**
 * Every family slot is optional (collectors may fail or be unavailable), but
 * each slot is fully typed when present.
 */
export interface ComparisonInput {
  gpu?: GpuSignals;
  cpu?: CpuSignals;
  screen?: ScreenSignals;
  timezone?: TimezoneSignals;
  fonts?: FontsSignals;
  mediaDevices?: MediaDevicesSignals;
  canvas?: CanvasSignals;
  webgl?: WebglSignals;
  audio?: AudioSignals;
  fontPrefs?: FontPrefsSignals;
  misc?: MiscSignals;
  versions?: VersionsSignals;
}

export interface FamilyScore {
  /** [0, 1], or -1 when the family was excluded from the denominator. */
  similarity: number;
  /** Raw mode weight (0 in engine-only-zero modes). */
  weight: number;
  /** weight × similarity, or 0 when excluded. */
  contribution: number;
}

export interface ComparisonResult {
  matchScore: number;
  match: boolean;
  hardwareMatch: boolean;
  mode: MatchMode;
  constraintViolations: string[];
  /** Per-family similarity in FAMILY_ORDER; -1 marks an excluded family. */
  diffVector: number[];
  perFamily: Record<Family, FamilyScore>;
}

/* -------------------------------------------------------------------------- */
/* Weight matrix + thresholds (each row sums to 100)                           */
/* -------------------------------------------------------------------------- */

export const WEIGHT_MATRIX: Record<MatchMode, Record<Family, number>> = {
  exact: {
    gpu: 15, cpu: 10, screen: 8, timezone: 5, fonts: 10, mediaDevices: 2,
    canvas: 15, webgl: 10, audio: 10, fontPrefs: 7, misc: 8,
  },
  strict: {
    gpu: 18, cpu: 12, screen: 10, timezone: 6, fonts: 12, mediaDevices: 2,
    canvas: 14, webgl: 8, audio: 8, fontPrefs: 5, misc: 5,
  },
  lenient: {
    gpu: 22, cpu: 15, screen: 12, timezone: 8, fonts: 13, mediaDevices: 4,
    canvas: 8, webgl: 6, audio: 5, fontPrefs: 4, misc: 3,
  },
  'cross-browser': {
    gpu: 30, cpu: 20, screen: 16, timezone: 12, fonts: 16, mediaDevices: 6,
    canvas: 0, webgl: 0, audio: 0, fontPrefs: 0, misc: 0,
  },
  'hardware-only': {
    gpu: 32, cpu: 22, screen: 18, timezone: 12, fonts: 10, mediaDevices: 6,
    canvas: 0, webgl: 0, audio: 0, fontPrefs: 0, misc: 0,
  },
  'engine-only': {
    gpu: 0, cpu: 0, screen: 0, timezone: 0, fonts: 10, mediaDevices: 0,
    canvas: 25, webgl: 20, audio: 18, fontPrefs: 12, misc: 15,
  },
};

/** Minimum matchScore (out of 100) for `match: true`. */
export const MODE_THRESHOLDS: Record<MatchMode, number> = {
  exact: 100,
  strict: 92,
  lenient: 82,
  'cross-browser': 85,
  'hardware-only': 88,
  'engine-only': 85,
};

/* -------------------------------------------------------------------------- */
/* Kernels                                                                     */
/* -------------------------------------------------------------------------- */

/** Jaccard similarity over normalized (trim + lowercase) string sets. */
export function jaccardSet(a: readonly string[], b: readonly string[]): number {
  const norm = (list: readonly string[]): string[] =>
    (list ?? [])
      .filter((x) => typeof x === 'string' && x.trim().length > 0)
      .map((x) => x.trim().toLowerCase());
  const setA = new Set(norm(a));
  const setB = new Set(norm(b));
  if (setA.size === 0 && setB.size === 0) return 1;
  if (setA.size === 0 || setB.size === 0) return 0;
  let intersection = 0;
  for (const item of setA) if (setB.has(item)) intersection += 1;
  const union = setA.size + setB.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

/* --- 64-bit SimHash over two 32-bit FNV-1a lanes --------------------------- */

const FNV_OFFSET_A = 0x811c9dc5;
const FNV_OFFSET_B = 0x811c9dc5 ^ 0xdeadbeef; /* distinct second lane */
const FNV_PRIME = 16777619;

function fnv1a32(input: string, seed: number): number {
  let h = seed >>> 0;
  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    /* Fold each UTF-16 code unit as two bytes (deterministic, no TextEncoder). */
    h = h ^ (code & 0xff);
    h = Math.imul(h, FNV_PRIME) >>> 0;
    h = h ^ ((code >>> 8) & 0xff);
    h = Math.imul(h, FNV_PRIME) >>> 0;
  }
  return h >>> 0;
}

function hex8(value: number): string {
  return (value >>> 0).toString(16).padStart(8, '0');
}

/**
 * 64-bit Charikar SimHash over per-feature deterministic hashes.
 *
 * Precision trade-off (documented): a true 64-bit integer cannot be composed
 * with plain JS numbers (`hi * 2**32 + lo` loses precision above 2^53), so the
 * 64-bit value is kept as two separate 32-bit halves. Each half is a 32-bit
 * FNV-1a hash with a distinct seed; bit i of the 64-bit space is bit i of the
 * low half for i < 32 and bit (i − 32) of the high half otherwise. Every
 * feature votes ±1 on each of the 64 bits; the output bit is 1 when the vote
 * sum is positive. Feature order is irrelevant (votes are summed).
 *
 * Returns a 16-char hex string (high 8 chars + low 8 chars).
 */
export function simhash64(features: Record<string, string>): string {
  const keys = Object.keys(features ?? {}).sort();
  const accHi = new Array<number>(32).fill(0);
  const accLo = new Array<number>(32).fill(0);
  let anyFeature = false;

  for (const key of keys) {
    const value = features[key];
    if (typeof value !== 'string') continue;
    anyFeature = true;
    const feature = `${key}\u0000${value}`;
    const lo = fnv1a32(feature, FNV_OFFSET_A);
    const hi = fnv1a32(feature, FNV_OFFSET_B);
    for (let bit = 0; bit < 32; bit += 1) {
      accLo[bit] += (lo >>> bit) & 1 ? 1 : -1;
      accHi[bit] += (hi >>> bit) & 1 ? 1 : -1;
    }
  }

  if (!anyFeature) return '0000000000000000';

  let outLo = 0;
  let outHi = 0;
  for (let bit = 0; bit < 32; bit += 1) {
    if (accLo[bit] > 0) outLo |= 1 << bit;
    if (accHi[bit] > 0) outHi |= 1 << bit;
  }
  return `${hex8(outHi)}${hex8(outLo)}`;
}

function parseHex64(hex: string): { hi: number; lo: number } | null {
  const clean = (hex ?? '').trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{1,16}$/.test(clean)) return null;
  const padded = clean.padStart(16, '0');
  const hi = parseInt(padded.slice(0, 8), 16) >>> 0;
  const lo = parseInt(padded.slice(8), 16) >>> 0;
  return { hi, lo };
}

function popcount32(value: number): number {
  let v = value >>> 0;
  v = v - ((v >>> 1) & 0x55555555);
  v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
  v = (v + (v >>> 4)) & 0x0f0f0f0f;
  v = (v * 0x01010101) >>> 24;
  return v >>> 0;
}

/**
 * Hamming similarity of two 64-bit hex values: max(0, 1 − d/16) where d is the
 * bit-level Hamming distance (0..64). Per spec, any distance ≥ 16 bits maps to
 * 0, so only near-identical hashes score above zero.
 */
export function hammingSimilarity64(hex1: string, hex2: string): number {
  const a = parseHex64(hex1);
  const b = parseHex64(hex2);
  if (a === null || b === null) return 0;
  const d = popcount32((a.hi ^ b.hi) >>> 0) + popcount32((a.lo ^ b.lo) >>> 0);
  return Math.max(0, 1 - d / 16);
}

/* -------------------------------------------------------------------------- */
/* OS-shipped font table (cross-browser font subset)                           */
/* -------------------------------------------------------------------------- */

/**
 * Approximation (documented deviation): a static allowlist of well-known
 * OS-shipped font families used to restrict the cross-browser font comparison
 * to "OS-level" fonts (fonts that ship with the platform rather than with a
 * specific browser).
 */
const OS_FONT_TABLE: Record<string, string[]> = {
  windows: [
    'arial', 'calibri', 'cambria', 'candara', 'comic sans ms', 'consolas', 'constantia',
    'corbel', 'courier new', 'georgia', 'impact', 'lucida console', 'lucida sans unicode',
    'microsoft sans serif', 'palatino linotype', 'segoe ui', 'tahoma', 'times new roman',
    'trebuchet ms', 'verdana',
  ],
  mac: [
    'american typewriter', 'andale mono', 'arial', 'arial black', 'arial narrow',
    'avenir next', 'baskerville', 'big caslon', 'chalkboard', 'chalkduster', 'cochin',
    'comic sans ms', 'courier', 'courier new', 'didot', 'futura', 'geneva', 'georgia',
    'gill sans', 'helvetica', 'helvetica neue', 'impact', 'lucida grande', 'menlo',
    'monaco', 'optima', 'palatino', 'tahoma', 'times', 'times new roman',
    'trebuchet ms', 'verdana',
  ],
  linux: [
    'dejavu sans', 'dejavu sans mono', 'dejavu serif', 'liberation mono',
    'liberation sans', 'liberation serif', 'noto sans', 'noto serif', 'ubuntu',
  ],
  android: ['roboto', 'noto sans', 'noto serif', 'droid sans', 'droid serif'],
  ios: [
    'american typewriter', 'andale mono', 'arial', 'arial black', 'arial narrow',
    'baskerville', 'cochin', 'comic sans ms', 'courier', 'courier new', 'georgia',
    'helvetica', 'helvetica neue', 'impact', 'menlo', 'palatino', 'tahoma',
    'times new roman', 'trebuchet ms', 'verdana', 'snell roundhand',
  ],
};

function isOsShippedOn(font: string, platformClass: string): boolean {
  const list = OS_FONT_TABLE[platformClass.toLowerCase()];
  /* Unknown platform class: no reliable filter, treat the font as OS-level. */
  if (!list) return true;
  return list.indexOf(font) !== -1;
}

/* -------------------------------------------------------------------------- */
/* Family similarity kernels                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Family similarity kernels return `number | null`:
 *   - number in [0, 1] — comparable, counts in the weight denominator;
 *   - null — excluded from the denominator (no comparable signal on both
 *     sides, or an explicit exclusion rule such as the Brave audio flag).
 */
type FamilyKernel = (stored: ComparisonInput, incoming: ComparisonInput, mode: MatchMode) => number | null;

function str(v: unknown): string {
  return typeof v === 'string' ? v.trim() : '';
}

function gpuSim(s: ComparisonInput, i: ComparisonInput): number | null {
  const a = s.gpu;
  const b = i.gpu;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const ga = str(a.normalizedGpu).toLowerCase();
  const gb = str(b.normalizedGpu).toLowerCase();
  if (ga && gb) return ga === gb ? 1 : 0;
  /* Renderer string missing on one side: fall back to the invariant limits. */
  const ha = str(a.invariantLimitsHash).toLowerCase();
  const hb = str(b.invariantLimitsHash).toLowerCase();
  if (ha && hb) return ha === hb ? 0.6 : 0;
  return null;
}

function cpuSim(s: ComparisonInput, i: ComparisonInput): number | null {
  const a = s.cpu;
  const b = i.cpu;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  let comparable = 0;
  let matched = 0;
  const archA = str(a.arch).toLowerCase();
  const archB = str(b.arch).toLowerCase();
  if (archA && archB) {
    comparable += 1;
    if (archA !== archB) return 0; /* arch mismatch is also a hard veto */
    matched += 1;
  }
  if (a.cores !== null && a.cores !== undefined && b.cores !== null && b.cores !== undefined) {
    comparable += 1;
    if (a.cores === b.cores) matched += 1;
  }
  if (a.memoryGb !== null && a.memoryGb !== undefined && b.memoryGb !== null && b.memoryGb !== undefined) {
    comparable += 1;
    if (a.memoryGb === b.memoryGb) matched += 1;
  }
  return comparable === 0 ? null : matched / comparable;
}

function screenSim(s: ComparisonInput, i: ComparisonInput): number | null {
  const a = s.screen;
  const b = i.screen;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const w1 = typeof a.width === 'number' ? a.width : 0;
  const h1 = typeof a.height === 'number' ? a.height : 0;
  const w2 = typeof b.width === 'number' ? b.width : 0;
  const h2 = typeof b.height === 'number' ? b.height : 0;
  if (!w1 || !h1 || !w2 || !h2) return 0;
  if (w1 === w2 && h1 === h2) return 1;

  const dpr1 = typeof a.dpr === 'number' && a.dpr > 0 ? a.dpr : 1;
  const dpr2 = typeof b.dpr === 'number' && b.dpr > 0 ? b.dpr : 1;

  const r1 = w1 / h1;
  const r2 = w2 / h2;
  if (Math.abs(r1 - r2) > 0.02) return 0;

  const nearMultiplier = (x: number): boolean =>
    ZOOM_MULTIPLIERS.some((m) => Math.abs(x - m) <= 0.02 * m);

  const raw = w2 / w1;
  const dprScaled = (w2 * dpr2) / (w1 * dpr1);
  if (nearMultiplier(raw) || nearMultiplier(1 / raw) || nearMultiplier(dprScaled) || nearMultiplier(1 / dprScaled)) {
    return 0.85;
  }
  return 0;
}

/** Standard browser-zoom multipliers that change reported CSS dimensions. */
const ZOOM_MULTIPLIERS = [0.75, 0.8, 0.9, 1.1, 1.25, 1.5];

function timezoneSim(s: ComparisonInput, i: ComparisonInput): number | null {
  const a = s.timezone;
  const b = i.timezone;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const nameA = str(a.name).toLowerCase();
  const nameB = str(b.name).toLowerCase();
  if (nameA && nameB) return nameA === nameB ? 1 : 0;
  const oA = typeof a.offsetMinutes === 'number' ? a.offsetMinutes : null;
  const oB = typeof b.offsetMinutes === 'number' ? b.offsetMinutes : null;
  if (oA !== null && oB !== null) return Math.abs(oA - oB) <= 1 ? 0.7 : 0;
  return null;
}

function fontsSim(s: ComparisonInput, i: ComparisonInput, mode: MatchMode): number | null {
  const a = s.fonts;
  const b = i.fonts;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const listA = Array.isArray(a.list) ? a.list : [];
  const listB = Array.isArray(b.list) ? b.list : [];

  if (mode === 'cross-browser') {
    /* Compare only the platformClass-shared subset (OS-level fonts). */
    const pcA = str(a.platformClass).toLowerCase();
    const pcB = str(b.platformClass).toLowerCase();
    const filteredA = listA.filter(
      (f) => isOsShippedOn(f.toLowerCase(), pcA) && isOsShippedOn(f.toLowerCase(), pcB),
    );
    const filteredB = listB.filter(
      (f) => isOsShippedOn(f.toLowerCase(), pcA) && isOsShippedOn(f.toLowerCase(), pcB),
    );
    const useA = filteredA.length > 0 ? filteredA : listA;
    const useB = filteredB.length > 0 ? filteredB : listB;
    const j = jaccardSet(useA, useB);
    /* J ≥ 0.85 is treated as a positive hardware match (score 1). Otherwise
     * halve: browser-bundled fonts inflate the raw difference. */
    return j >= 0.85 ? 1 : j * 0.5;
  }

  return jaccardSet(listA, listB);
}

function mediaDeviceBit(v: number | boolean | null | undefined): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v === 'boolean') return v ? '1' : '0';
  if (typeof v === 'number' && isFinite(v)) return v > 0 ? '1' : '0';
  return null;
}

function mediaDevicesSim(s: ComparisonInput, i: ComparisonInput): number | null {
  const a = s.mediaDevices;
  const b = i.mediaDevices;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const pairs: Array<[number | boolean | null | undefined, number | boolean | null | undefined]> = [
    [a.audioIn, b.audioIn],
    [a.audioOut, b.audioOut],
    [a.video, b.video],
  ];
  let comparable = 0;
  let matched = 0;
  for (const [x, y] of pairs) {
    const vx = mediaDeviceBit(x);
    const vy = mediaDeviceBit(y);
    if (vx === null || vy === null) continue;
    comparable += 1;
    if (vx === vy) matched += 1;
  }
  return comparable === 0 ? null : matched / comparable;
}

function canvasSim(s: ComparisonInput, i: ComparisonInput, mode: MatchMode): number | null {
  const a = s.canvas;
  const b = i.canvas;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  /* Lenient mode weights geometry 2× text. */
  const geoWeight = mode === 'lenient' ? 2 : 1;
  let total = 0;
  let matched = 0;
  const geoA = str(a.geometry);
  const geoB = str(b.geometry);
  if (geoA && geoB) {
    total += geoWeight;
    if (geoA === geoB) matched += geoWeight;
  }
  const textA = str(a.text);
  const textB = str(b.text);
  if (textA && textB) {
    total += 1;
    if (textA === textB) matched += 1;
  }
  const stA = str(a.stabilized);
  const stB = str(b.stabilized);
  if (stA && stB) {
    total += 1;
    if (stA === stB) matched += 1;
  }
  return total === 0 ? null : matched / total;
}

function webglSim(s: ComparisonInput, i: ComparisonInput): number | null {
  const a = s.webgl;
  const b = i.webgl;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const pairs: Array<[unknown, unknown]> = [
    [a.extensionsHash, b.extensionsHash],
    [a.paramsHash, b.paramsHash],
    [a.shaderPrecisionHash, b.shaderPrecisionHash],
  ];
  let comparable = 0;
  let matched = 0;
  for (const [x, y] of pairs) {
    const vx = str(x);
    const vy = str(y);
    if (!vx || !vy) continue;
    comparable += 1;
    if (vx.toLowerCase() === vy.toLowerCase()) matched += 1;
  }
  return comparable === 0 ? null : matched / comparable;
}

function audioSim(s: ComparisonInput, i: ComparisonInput): number | null {
  const a = s.audio;
  const b = i.audio;
  /* Brave randomizes audio sums — exclude the family from the denominator. */
  if ((a !== null && a !== undefined && a.braveFlag === true) || (b !== null && b !== undefined && b.braveFlag === true)) {
    return null;
  }
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const sumA = a.sum;
  const sumB = b.sum;
  const hasA = typeof sumA === 'number' && isFinite(sumA);
  const hasB = typeof sumB === 'number' && isFinite(sumB);
  if (!hasA && !hasB) return null;
  if (!hasA || !hasB) return 0;
  const delta = Math.abs((sumA as number) - (sumB as number));
  const scale = Math.max(Math.abs(sumA as number), Math.abs(sumB as number), 1e-12);
  const relative = delta / scale;
  let score: number;
  if (relative < 1e-9) score = 1;
  else if (relative < 1e-4) score = 0.9;
  else score = 0;
  /* Latency mismatch (when both known) caps a matching sum. */
  const blA = a.baseLatency;
  const blB = b.baseLatency;
  if (
    typeof blA === 'number' && isFinite(blA) && blA > 0 &&
    typeof blB === 'number' && isFinite(blB) && blB > 0
  ) {
    const rel = Math.abs(blA - blB) / Math.max(blA, blB);
    if (rel >= 1e-4) score = Math.min(score, 0.5);
  }
  return score;
}

function fontPrefsSim(s: ComparisonInput, i: ComparisonInput): number | null {
  const a = s.fontPrefs;
  const b = i.fontPrefs;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const widthsA = a.widths && typeof a.widths === 'object' ? a.widths : {};
  const widthsB = b.widths && typeof b.widths === 'object' ? b.widths : {};
  const keys = Object.keys(widthsA).filter((k) => Object.prototype.hasOwnProperty.call(widthsB, k));
  let widthComparable = 0;
  let widthMatched = 0;
  for (const k of keys) {
    const x = widthsA[k];
    const y = widthsB[k];
    if (x === null || x === undefined || y === null || y === undefined) continue;
    if (typeof x !== 'number' || typeof y !== 'number') continue;
    widthComparable += 1;
    if (Math.abs(x - y) < 1e-9) widthMatched += 1;
  }
  const widthRatio = widthComparable === 0 ? null : widthMatched / widthComparable;
  const emojiA = str(a.emojiRectHash);
  const emojiB = str(b.emojiRectHash);
  const emojiEq = emojiA && emojiB ? (emojiA.toLowerCase() === emojiB.toLowerCase() ? 1 : 0) : null;
  if (widthRatio === null && emojiEq === null) return null;
  if (widthRatio === null) return emojiEq as number;
  if (emojiEq === null) return widthRatio;
  return 0.5 * widthRatio + 0.5 * (emojiEq as number);
}

function miscSim(s: ComparisonInput, i: ComparisonInput): number | null {
  const a = s.misc;
  const b = i.misc;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  let comparable = 0;
  let matched = 0;
  const mA = str(a.mathHash);
  const mB = str(b.mathHash);
  if (mA && mB) {
    comparable += 1;
    if (mA.toLowerCase() === mB.toLowerCase()) matched += 1;
  }
  const eA = str(a.errorStackHash);
  const eB = str(b.errorStackHash);
  if (eA && eB) {
    comparable += 1;
    if (eA.toLowerCase() === eB.toLowerCase()) matched += 1;
  }
  return comparable === 0 ? null : matched / comparable;
}

const FAMILY_KERNELS: Record<Family, FamilyKernel> = {
  gpu: (s, i) => gpuSim(s, i),
  cpu: (s, i) => cpuSim(s, i),
  screen: (s, i) => screenSim(s, i),
  timezone: (s, i) => timezoneSim(s, i),
  fonts: (s, i, mode) => fontsSim(s, i, mode),
  mediaDevices: (s, i) => mediaDevicesSim(s, i),
  canvas: (s, i, mode) => canvasSim(s, i, mode),
  webgl: (s, i) => webglSim(s, i),
  audio: (s, i) => audioSim(s, i),
  fontPrefs: (s, i) => fontPrefsSim(s, i),
  misc: (s, i) => miscSim(s, i),
};

/**
 * Public per-family similarity (dashboard helper). Uses the 'exact' mode
 * context (full-list fonts, equal-weight canvas). Returns 0 for families that
 * would be excluded from a comparison's denominator.
 */
export function similarityFamily(stored: ComparisonInput, incoming: ComparisonInput, family: Family): number {
  try {
    const kernel = FAMILY_KERNELS[family];
    if (!kernel) return 0;
    const sim = kernel(stored, incoming, 'exact');
    return sim === null ? 0 : sim;
  } catch {
    return 0;
  }
}

/* -------------------------------------------------------------------------- */
/* Version monotonicity + hard constraints                                     */
/* -------------------------------------------------------------------------- */

const HARD_VIOLATION_OS = 'os_family_mismatch';
const HARD_VIOLATION_ARCH = 'cpu_arch_mismatch';
const VIOLATION_DOWNGRADE = 'version_downgrade_anomaly';
const NOTE_DRIFT = 'version_upgrade_drift_allowed';

function normalizeArch(arch: string): string {
  const a = (arch ?? '').trim().toLowerCase();
  if (a === 'amd64' || a === 'x64' || a === 'x86-64' || a === 'x86_64' || a === 'wow64') return 'x86_64';
  if (a === 'arm64' || a === 'aarch64') return 'arm64';
  if (a === 'i386' || a === 'i486' || a === 'i586' || a === 'i686' || a === 'x86') return 'x86';
  if (a.indexOf('arm') !== -1) return 'arm';
  return a;
}

/**
 * Rendering-hash drift allowance: same browser family, incoming version is
 * 0–3 majors ahead of stored, and the hardware signals (gpu / screen / cpu
 * arch, when comparable) match. Allows exactly ONE rendering hash (canvas.text
 * or audio sum) to drift with zero penalty.
 */
function hardwareSignalsMatch(raws: Record<Family, number>): boolean {
  const checks: boolean[] = [];
  const gpu = raws.gpu;
  if (gpu !== null) checks.push(gpu >= 0.6);
  const screen = raws.screen;
  if (screen !== null) checks.push(screen >= 0.85);
  const cpu = raws.cpu;
  if (cpu !== null) checks.push(cpu > 0);
  if (checks.length === 0) return false;
  return checks.every(Boolean);
}

function audioDrifted(s: ComparisonInput, i: ComparisonInput): boolean {
  const a = s.audio;
  const b = i.audio;
  if (!a || !b) return false;
  const sumA = a.sum;
  const sumB = b.sum;
  if (typeof sumA !== 'number' || !isFinite(sumA) || typeof sumB !== 'number' || !isFinite(sumB)) return false;
  const scale = Math.max(Math.abs(sumA), Math.abs(sumB), 1e-12);
  return Math.abs(sumA - sumB) / scale >= 1e-4;
}

/* -------------------------------------------------------------------------- */
/* Core comparison                                                             */
/* -------------------------------------------------------------------------- */

function round3(x: number): number {
  return Math.round(x * 1000) / 1000;
}

function blankPerFamily(weights: Record<Family, number>): Record<Family, FamilyScore> {
  const out = {} as Record<Family, FamilyScore>;
  for (const family of FAMILY_ORDER) {
    out[family] = { similarity: -1, weight: weights[family], contribution: 0 };
  }
  return out;
}

/**
 * Compares a stored fingerprint against an incoming one in the given mode.
 * Deterministic, synchronous, total (never throws).
 *
 * Semantics:
 * - `matchScore` is the renormalized weighted similarity out of 100 over the
 *   families included in the denominator.
 * - Hard constraints (osFamily mismatch, CPU arch mismatch) veto the match in
 *   every mode except engine-only; a version downgrade on the same browser
 *   family vetoes the same way.
 * - 'exact' additionally requires a full weight denominator (no exclusions)
 *   to count as a match — it is the perfect-match gate at threshold 100.
 */
export function compareFingerprints(
  stored: ComparisonInput,
  incoming: ComparisonInput,
  mode: MatchMode,
): ComparisonResult {
  const safeMode: MatchMode = WEIGHT_MATRIX[mode] ? mode : 'exact';
  const weights = WEIGHT_MATRIX[safeMode];

  const s = stored && typeof stored === 'object' ? stored : {};
  const i = incoming && typeof incoming === 'object' ? incoming : {};

  /* 1. Raw per-family similarities. */
  const raws = {} as Record<Family, number | null>;
  for (const family of FAMILY_ORDER) {
    let sim: number | null = null;
    try {
      sim = FAMILY_KERNELS[family](s, i, safeMode);
    } catch {
      sim = null;
    }
    raws[family] = sim === null || !isFinite(sim) ? null : Math.max(0, Math.min(1, sim));
  }

  /* 2. Version monotonicity + drift allowance. */
  const violations: string[] = [];
  const vs = s.versions;
  const vi = i.versions;
  const famA = str(vs?.browserFamily).toLowerCase();
  const famB = str(vi?.browserFamily).toLowerCase();
  const sameFamily = Boolean(famA && famB && famA === famB);
  const majorA = vs && typeof vs.browserMajor === 'number' && isFinite(vs.browserMajor) ? vs.browserMajor : null;
  const majorB = vi && typeof vi.browserMajor === 'number' && isFinite(vi.browserMajor) ? vi.browserMajor : null;

  let driftAllowed = false;
  if (sameFamily && majorA !== null && majorB !== null) {
    const delta = majorB - majorA;
    if (delta < 0) {
      violations.push(VIOLATION_DOWNGRADE);
    } else if (delta <= 3 && hardwareSignalsMatch(raws as Record<Family, number>)) {
      driftAllowed = true;
    }
  }

  if (driftAllowed) {
    /* Allow exactly ONE rendering hash to drift: prefer canvas.text, else audio. */
    const canvasBoth = Boolean(s.canvas && i.canvas);
    const canvasDrift =
      canvasBoth && str(s.canvas!.geometry) && str(s.canvas!.geometry) === str(i.canvas!.geometry) &&
      str(s.canvas!.text) && str(i.canvas!.text) && str(s.canvas!.text) !== str(i.canvas!.text);
    const audioDrift = audioDrifted(s, i);
    if (canvasDrift) {
      raws.canvas = 1;
      violations.push(NOTE_DRIFT);
    } else if (audioDrift) {
      raws.audio = 1;
      violations.push(NOTE_DRIFT);
    }
  }

  /* 3. Hard constraints. */
  const osA = str(s.cpu?.osFamily).toLowerCase();
  const osB = str(i.cpu?.osFamily).toLowerCase();
  const archA = normalizeArch(str(s.cpu?.arch));
  const archB = normalizeArch(str(i.cpu?.arch));
  const osMismatch = Boolean(osA && osB && osA !== osB);
  const archMismatch = Boolean(archA && archB && archA !== archB);
  if (osMismatch) violations.push(HARD_VIOLATION_OS);
  if (archMismatch) violations.push(HARD_VIOLATION_ARCH);

  /* 4. Weighted score with denominator renormalization. */
  const perFamily = blankPerFamily(weights);
  let weighted = 0;
  let weightSum = 0;
  const diffVector: number[] = [];
  for (const family of FAMILY_ORDER) {
    const sim = raws[family];
    const weight = weights[family];
    if (sim === null) {
      diffVector.push(-1);
      continue;
    }
    diffVector.push(round3(sim));
    perFamily[family].similarity = round3(sim);
    perFamily[family].contribution = weight * sim;
    weighted += weight * sim;
    weightSum += weight;
  }
  const matchScore = weightSum > 0 ? round3((weighted / weightSum) * 100) : 0;

  /* 5. Match decision. */
  let veto = false;
  if (safeMode !== 'engine-only' && (osMismatch || archMismatch)) veto = true;
  if (safeMode !== 'engine-only' && violations.indexOf(VIOLATION_DOWNGRADE) !== -1) veto = true;
  const threshold = MODE_THRESHOLDS[safeMode];
  let match = !veto && matchScore >= threshold;
  if (safeMode === 'exact' && weightSum < 100) match = false;

  /* 6. Hardware match: weighted average over comparable hardware families,
   * plus the cross-browser positive-font signal. */
  const hwFamilies: Family[] = ['gpu', 'cpu', 'screen'];
  let hwWeighted = 0;
  let hwWeightSum = 0;
  for (const family of hwFamilies) {
    const sim = raws[family];
    if (sim === null) continue;
    hwWeighted += weights[family] * sim;
    hwWeightSum += weights[family];
  }
  let hardwareMatch = hwWeightSum > 0 ? hwWeighted / hwWeightSum >= 0.85 : false;
  if (safeMode === 'cross-browser' && (raws.fonts ?? 0) >= 0.85) hardwareMatch = true;

  return {
    matchScore,
    match,
    hardwareMatch,
    mode: safeMode,
    constraintViolations: violations,
    diffVector,
    perFamily,
  };
}

/**
 * Mode chooser: tries lenient → cross-browser → hardware-only and returns the
 * first mode whose match is true. When none matches, returns the best-scoring
 * mode (ties resolve to the earlier mode in the try order).
 */
export function bestMode(stored: ComparisonInput, incoming: ComparisonInput): MatchMode {
  const order: MatchMode[] = ['lenient', 'cross-browser', 'hardware-only'];
  let best: { mode: MatchMode; score: number } | null = null;
  for (const mode of order) {
    try {
      const result = compareFingerprints(stored, incoming, mode);
      if (result.match) return mode;
      if (best === null || result.matchScore > best.score) {
        best = { mode, score: result.matchScore };
      }
    } catch {
      /* never throws — defensive only */
    }
  }
  return best === null ? 'lenient' : best.mode;
}

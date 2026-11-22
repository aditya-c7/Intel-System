/**
 * Shadow-only, additive entropy-matrix normalizers (pure, dependency-free, Workers safe).
 *
 * This module is a *data normalization* model of a FingerprintJS-v5-style entropy surface
 * matrix. It deliberately performs NO browser probing: it never touches `document`, `window`,
 * canvas/WebGL/AudioContext, `navigator`, `Intl`, or any third-party SDK. Callers are expected
 * to have already collected the raw observations and to pass them in as plain data.
 *
 * Design guarantees (mirroring `zeroTrust.ts` / `stealthSignals.ts` / `privacySignatures.ts`):
 *  - pure and side-effect free at import time; no I/O, no network, no globals;
 *  - NEVER throws — hostile getters, proxies, cyclic/wrong-typed values degrade to safe records;
 *  - every normalizer returns an *additive typed record* carrying a canonical `surface` id,
 *    a three-way `status` ('ok' | 'unavailable' | 'blocked'), and sorted/deduped `reasons`;
 *  - NO hashing of volatile data (canvas text/geometry are stored as bounded normalized strings,
 *    never as hashes/digests), no risk scoring, no verdicts;
 *  - deterministic: output is a pure function of input values and does not depend on locale,
 *    iteration order of input arrays, wall clock, or ambient environment.
 *
 * Status semantics (consistent across every surface):
 *  - `ok`          — usable observations were normalized into the record.
 *  - `unavailable` — no usable observations (missing / empty / malformed input), no block evidence.
 *  - `blocked`     — positive evidence the surface was actively denied (blocked/denied/error
 *                    flag, or DOM-blocker hits). Blocked records still carry whatever was seen.
 *
 * Research-brief alignment (factual inventory/notes only — never probe logic or scoring):
 *  - The FingerprintJS v5 high-value source inventory is exported as `FJS_V5_HIGH_VALUE_SOURCES`
 *    so coverage can be reasoned about without importing an SDK. The 9 original normalizers
 *    cover fonts/fontPreferences, domBlockers, audio + audioBaseLatency, canvas, math,
 *    webGlBasics + webGlExtensions. The remaining inventory names are documentation only.
 *  - `ENTROPY_NOTES.webglAfterCanvas`: WebGL must be collected AFTER canvas (WebGL context
 *    creation can affect canvas rendering). This module normalizes already-collected data, so
 *    the ordering note is carried explicitly rather than enforced by here-doing a probe.
 *  - `ENTROPY_NOTES.noWebgpuInFjsV5`: FingerprintJS v5 has NO WebGPU source. The WebGPU
 *    normalizer below is a separate, additive deployable slice, not an FJS v5 source.
 *  - `ENTROPY_NOTES.researchOnly`: atomic-contention histograms and ML device classification
 *    are research-only (unstable across visits, timer-sensitive, heavy GPU cost). They are
 *    deliberately NOT implemented; the explicit `research_only` note is exposed if referenced.
 *  - Static WebGPU (adapter.info + features + limits + timestamp-query) is ~5.19 bits per the
 *    brief. That figure is exported as descriptive research metadata, never as a risk score.
 *
 * Nothing in production imports this module yet; it is a shadow evaluation surface only.
 */

/* -------------------------------------------------------------------------- */
/* Public record types                                                        */
/* -------------------------------------------------------------------------- */

export type EntropyStatus = 'ok' | 'unavailable' | 'blocked';

export type EntropySurface =
  | 'fonts'
  | 'emoji'
  | 'webgl'
  | 'audio'
  | 'canvas'
  | 'keyboard'
  | 'css'
  | 'math'
  | 'dom-blockers'
  | 'webgpu';

/**
 * FingerprintJS v5 high-value source inventory (research reference, not a probe or a score).
 * Names are informational: only surfaces with a normalizer in this module produce records.
 */
export const FJS_V5_HIGH_VALUE_SOURCES = Object.freeze([
  'fonts', 'fontPreferences', 'domBlockers', 'audio', 'audioBaseLatency', 'canvas', 'math',
  'webGlBasics', 'webGlExtensions', 'screenFrame', 'colorGamut', 'hdr', 'monochrome',
  'invertedColors', 'forcedColors', 'contrast', 'reducedMotion', 'reducedTransparency',
  'architecture', 'osCpu', 'cpuClass', 'deviceMemory', 'hardwareConcurrency', 'platform',
  'vendor', 'vendorFlavors', 'userAgentData', 'userAgent', 'languages', 'timezone',
  'dateTimeLocale', 'screenResolution', 'touchSupport', 'plugins',
] as const);

export type FjsV5Source = (typeof FJS_V5_HIGH_VALUE_SOURCES)[number];

/**
 * Explicit research notes. `researchOnly.id` is literally `research_only` as required; the
 * underlying techniques are NOT implemented here and must never be used as deployable entropy.
 */
export const ENTROPY_NOTES = Object.freeze({
  webglAfterCanvas: Object.freeze({
    id: 'webgl-after-canvas',
    text: 'WebGL must run AFTER canvas: WebGL context creation can affect canvas rendering.',
  }),
  noWebgpuInFjsV5: Object.freeze({
    id: 'fjs-v5-no-webgpu',
    text: 'FingerprintJS v5 has NO WebGPU source; WebGPU here is a separate additive deployable slice.',
  }),
  staticWebGpuEstimate: Object.freeze({
    id: 'static-webgpu-estimate',
    text: 'Static WebGPU (adapter.info + features + limits + timestamp-query) is ~5.19 bits in research estimates.',
    estimatedBits: 5.19,
    /** Descriptive research metadata only — never a risk score or decision input. */
    riskScore: false,
  }),
  researchOnly: Object.freeze({
    id: 'research_only',
    text: 'Atomic-contention histograms and ML device classification are research-only: unstable across visits, timer-sensitive, heavy GPU cost. NOT implemented.',
    implemented: false,
  }),
});

/** Convenience alias for the explicit research-only marker. */
export const RESEARCH_ONLY_NOTE = ENTROPY_NOTES.researchOnly;

/** Fields shared by every additive entropy record. */
export interface EntropyRecordBase {
  /** Stable canonical identifier of the normalized surface. */
  surface: EntropySurface;
  /** Outcome status of the normalization. */
  status: EntropyStatus;
  /** Canonical, de-duplicated reason tokens (no volatile data, no scores). */
  reasons: string[];
}

export interface FontPreferencesRecord extends EntropyRecordBase {
  surface: 'fonts';
  /** Canonical, case-insensitively de-duplicated, sorted font family names. */
  fonts: string[];
  /** Number of normalized fonts (mirrors `fonts.length`; convenience field). */
  count: number;
}

export interface ShaderPrecisionRecord {
  precision: string | null;
  rangeMin: number | null;
  rangeMax: number | null;
}

export interface EmojiMetricsRecord extends EntropyRecordBase {
  surface: 'emoji';
  /** Canonical, de-duplicated, sorted emoji glyphs. */
  glyphs: string[];
  /** Normalized rendered width in px (finite number, else null). */
  width: number | null;
  /** Normalized rendered height in px (finite number, else null). */
  height: number | null;
}

export interface WebglSurfacesInput {
  basics?: {
    vendor?: unknown;
    renderer?: unknown;
    version?: unknown;
    shadingLanguageVersion?: unknown;
    unmaskedVendor?: unknown;
    unmaskedRenderer?: unknown;
    blocked?: unknown;
  } | null;
  extensions?: unknown;
  shaderPrecision?: {
    fragment?: unknown;
    vertex?: unknown;
    blocked?: unknown;
  } | null;
  blocked?: unknown;
}

export interface WebglSurfacesRecord extends EntropyRecordBase {
  surface: 'webgl';
  vendor: string | null;
  renderer: string | null;
  version: string | null;
  shadingLanguageVersion: string | null;
  unmaskedVendor: string | null;
  unmaskedRenderer: string | null;
  /** Enabled extension names (canonical, sorted, de-duplicated). */
  extensions: string[];
  precision: {
    fragment: ShaderPrecisionRecord | null;
    vertex: ShaderPrecisionRecord | null;
  };
}

export interface AudioDriverInput {
  sampleRate?: unknown;
  baseLatency?: unknown;
  outputLatency?: unknown;
  maxChannelCount?: unknown;
  blocked?: unknown;
}

export interface AudioDriverRecord extends EntropyRecordBase {
  surface: 'audio';
  sampleRate: number | null;
  baseLatency: number | null;
  outputLatency: number | null;
  maxChannelCount: number | null;
}

export interface CanvasSurfacesInput {
  winding?: unknown;
  geometry?: unknown;
  text?: unknown;
  blocked?: unknown;
  /** A thrown probe error marker (truthy object/message) is an explicit block signal. */
  error?: unknown;
}

export interface CanvasSurfacesRecord extends EntropyRecordBase {
  surface: 'canvas';
  /** Normalized winding token: 'cw' | 'ccw' | null. */
  winding: string | null;
  /** Bounded `key=value;...` descriptor of numeric geometry probes (NOT a hash). */
  geometry: string | null;
  /** Bounded, whitespace-normalized text probe descriptor (NOT a hash). */
  text: string | null;
}

export interface KeyboardLayoutRecord extends EntropyRecordBase {
  surface: 'keyboard';
  /** Optional canonical layout name, when provided. */
  layout: string | null;
  /** Canonical, de-duplicated, sorted key/glyph tokens. */
  keys: string[];
}

export interface CssVectorRecord extends EntropyRecordBase {
  surface: 'css';
  /** Canonical, de-duplicated, sorted names of enabled/supported CSS features. */
  features: string[];
}

export interface MathConstantsRecord extends EntropyRecordBase {
  surface: 'math';
  /** Canonical, bounded subset of numeric math constants (rounded for stability). */
  constants: Record<string, number>;
}

export interface DomBlockersRecord extends EntropyRecordBase {
  surface: 'dom-blockers';
  /** Canonical, de-duplicated, sorted names of DOM probes reported as blocked. */
  blocked: string[];
  /** Number of blocked probes (mirrors `blocked.length`; convenience field). */
  count: number;
}

/** Pre-collected static WebGPU data (adapter.info may legitimately be empty). */
export interface WebGpuSurfacesInput {
  adapterInfo?: {
    vendor?: unknown;
    architecture?: unknown;
    device?: unknown;
    description?: unknown;
  } | null;
  /** device.features as a Set/array of names, or a name->enabled map. */
  features?: unknown;
  limits?: {
    maxComputeWorkgroupSizeX?: unknown;
    maxComputeWorkgroupSizeY?: unknown;
    maxComputeWorkgroupSizeZ?: unknown;
    maxComputeWorkgroupsPerDimension?: unknown;
  } | null;
  timestampQuery?: unknown;
  blocked?: unknown;
  error?: unknown;
}

export interface WebGpuSurfacesRecord extends EntropyRecordBase {
  surface: 'webgpu';
  adapter: {
    vendor: string | null;
    architecture: string | null;
    device: string | null;
    description: string | null;
  };
  /** Canonical, sorted device feature names (Set/array/map normalized). */
  features: string[];
  limits: {
    maxComputeWorkgroupSizeX: number | null;
    maxComputeWorkgroupSizeY: number | null;
    maxComputeWorkgroupSizeZ: number | null;
    maxComputeWorkgroupsPerDimension: number | null;
  };
  /** `timestamp-query` availability: 'available' | 'unavailable' | null (unknown). */
  timestampQuery: 'available' | 'unavailable' | null;
  /** Explicit note ids carried with the record (e.g. `fjs-v5-no-webgpu`). */
  notes: string[];
}

/* -------------------------------------------------------------------------- */
/* Defensive primitives — every read is guarded so hostile input cannot throw */
/* -------------------------------------------------------------------------- */

function asObject(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function safeGet(src: Record<string, unknown>, key: string): unknown {
  try {
    return src[key];
  } catch {
    return undefined;
  }
}

function finiteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function safeText(value: unknown, maxLen = 128): string {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) : trimmed;
}

/** Stable, locale-independent comparator (never `localeCompare`). */
function compareStrings(a: string, b: string): number {
  const al = a.toLowerCase();
  const bl = b.toLowerCase();
  if (al < bl) return -1;
  if (al > bl) return 1;
  return 0;
}

/** De-duplicate (case-insensitive), drop junk, cap and sort raw strings. */
function canonicalizeStrings(raw: string[], maxItems: number, maxLen: number): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== 'string') continue;
    const token = entry.trim();
    if (!token || token.length > maxLen) continue;
    const key = token.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(token);
    if (out.length >= maxItems) break;
  }
  out.sort(compareStrings);
  return out;
}

/** Accept an array of strings or a delimited string; return canonical tokens. Non-string junk is ignored. */
function stringList(value: unknown, maxItems = 256, maxLen = 96): string[] {
  const raw: string[] = [];
  if (Array.isArray(value)) {
    for (const item of value) {
      if (typeof item === 'string') raw.push(item);
    }
  } else if (typeof value === 'string') {
    raw.push(...value.split(/[,|;\n]/));
  }
  return canonicalizeStrings(raw, maxItems, maxLen);
}

function firstDefined(src: Record<string, unknown>, keys: string[]): unknown {
  for (const key of keys) {
    const value = safeGet(src, key);
    if (value !== undefined && value !== null) return value;
  }
  return undefined;
}

/** Positive evidence of an actively blocked/denied/errored probe. */
function hasBlockSignal(src: Record<string, unknown>): boolean {
  for (const key of ['blocked', 'denied', 'forbidden']) {
    const value = safeGet(src, key);
    if (value === true) return true;
    if (typeof value === 'string' && /^(blocked|denied|forbidden)$/i.test(value.trim())) return true;
  }
  // A thrown probe leaves a truthy error/exception marker (an Error object, a message, or true).
  for (const key of ['error', 'threw', 'exception']) {
    const value = safeGet(src, key);
    if (value !== undefined && value !== null && value !== false && value !== 0 && value !== '') return true;
  }
  return false;
}

function reasonTokens(...tokens: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const token of tokens) {
    if (token && !seen.has(token)) {
      seen.add(token);
      out.push(token);
    }
  }
  return out;
}

function roundTo(value: number, digits: number): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function numericInRange(value: unknown, min: number, max: number, digits: number | null): number | null {
  const n = finiteNumber(value);
  if (n === null || n < min || n > max) return null;
  return digits === null ? n : roundTo(n, digits);
}

function isEmptyInput(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'object') return Object.keys(asObject(value)).length === 0;
  if (typeof value === 'string') return value.trim().length === 0;
  return false;
}

/** Bounded, whitespace-normalized descriptor. No hashing or digest of any kind. */
function normalizeDescriptor(value: unknown, maxLen: number): string | null {
  if (typeof value !== 'string') return null;
  const text = value.replace(/\s+/g, ' ').trim();
  if (!text) return null;
  return text.length > maxLen ? text.slice(0, maxLen) : text;
}

/** Normalize a native Set / array / delimited string / name->enabled map of token names. */
function featureTokens(value: unknown, maxItems = 256, maxLen = 96): string[] {
  if (value instanceof Set) {
    const raw: string[] = [];
    for (const item of value) {
      if (typeof item === 'string') raw.push(item);
    }
    return canonicalizeStrings(raw, maxItems, maxLen);
  }
  if (Array.isArray(value) || typeof value === 'string') return stringList(value, maxItems, maxLen);
  const source = asObject(value);
  if (isEmptyInput(value)) return [];
  const enabled: string[] = [];
  for (const key of Object.keys(source)) {
    const flag = safeGet(source, key);
    if (flag === true || flag === 1) enabled.push(key);
  }
  return canonicalizeStrings(enabled, maxItems, maxLen);
}

/** Tri-state availability for `timestamp-query` (unknown stays null). */
function availability(value: unknown): 'available' | 'unavailable' | null {
  if (value === true) return 'available';
  if (value === false) return 'unavailable';
  if (typeof value === 'string') {
    const token = value.trim().toLowerCase();
    if (token === 'available' || token === 'supported' || token === 'true') return 'available';
    if (token === 'unavailable' || token === 'unsupported' || token === 'false') return 'unavailable';
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* Normalizers                                                                */
/* -------------------------------------------------------------------------- */

export function normalizeFontPreferences(input: unknown): FontPreferencesRecord {
  try {
    if (hasBlockSignal(asObject(input))) {
      return { surface: 'fonts', status: 'blocked', fonts: [], count: 0, reasons: reasonTokens('explicit-block') };
    }
    const source = Array.isArray(input) || typeof input === 'string'
      ? input
      : firstDefined(asObject(input), ['fonts', 'families', 'preferred', 'detected']);
    const fonts = stringList(source, 256, 96);
    if (!fonts.length) {
      return { surface: 'fonts', status: 'unavailable', fonts: [], count: 0, reasons: reasonTokens('no-usable-fonts') };
    }
    return { surface: 'fonts', status: 'ok', fonts, count: fonts.length, reasons: reasonTokens('normalized') };
  } catch {
    return {
      surface: 'fonts',
      status: 'unavailable',
      fonts: [],
      count: 0,
      reasons: reasonTokens('exception-during-normalization'),
    };
  }
}

export function normalizeEmojiMetrics(input: unknown): EmojiMetricsRecord {
  try {
    const source = asObject(input);
    if (hasBlockSignal(source)) {
      return {
        surface: 'emoji',
        status: 'blocked',
        glyphs: [],
        width: null,
        height: null,
        reasons: reasonTokens('explicit-block'),
      };
    }
    const glyphSource = firstDefined(source, ['glyphs', 'supported', 'emoji', 'codepoints']);
    // Emoji glyphs are compared exactly (multi-codepoint sequences must survive intact).
    const glyphs = canonicalizeStrings(
      Array.isArray(glyphSource) ? (glyphSource as string[]) : glyphSource ? [String(glyphSource)] : [],
      256,
      32
    );
    const width = finiteNumber(firstDefined(source, ['width', 'renderedWidth']));
    const height = finiteNumber(firstDefined(source, ['height', 'renderedHeight']));
    if (!glyphs.length && width === null && height === null) {
      return {
        surface: 'emoji',
        status: 'unavailable',
        glyphs: [],
        width: null,
        height: null,
        reasons: reasonTokens('no-usable-metrics'),
      };
    }
    return {
      surface: 'emoji',
      status: 'ok',
      glyphs,
      width,
      height,
      reasons: reasonTokens('normalized', !glyphs.length || width === null || height === null ? 'partial' : 'complete'),
    };
  } catch {
    return {
      surface: 'emoji',
      status: 'unavailable',
      glyphs: [],
      width: null,
      height: null,
      reasons: reasonTokens('exception-during-normalization'),
    };
  }
}

function normalizeShaderPrecision(value: unknown): ShaderPrecisionRecord | null {
  const source = asObject(value);
  if (isEmptyInput(value)) return null;
  const precision = safeText(safeGet(source, 'precision'), 16).toLowerCase();
  const rangeMin = finiteNumber(safeGet(source, 'rangeMin'));
  const rangeMax = finiteNumber(safeGet(source, 'rangeMax'));
  if (!precision && rangeMin === null && rangeMax === null) return null;
  return { precision: precision || null, rangeMin, rangeMax };
}

function webglExtensionNames(value: unknown): string[] {
  if (Array.isArray(value)) return stringList(value, 256, 96);
  const source = asObject(value);
  if (isEmptyInput(value)) return [];
  const enabled: string[] = [];
  for (const key of Object.keys(source)) {
    const flag = safeGet(source, key);
    if (flag === true || flag === 1) enabled.push(key);
  }
  return canonicalizeStrings(enabled, 256, 96);
}

export function normalizeWebglSurfaces(input: WebglSurfacesInput | null | undefined): WebglSurfacesRecord {
  const empty: WebglSurfacesRecord = {
    surface: 'webgl',
    status: 'unavailable',
    vendor: null,
    renderer: null,
    version: null,
    shadingLanguageVersion: null,
    unmaskedVendor: null,
    unmaskedRenderer: null,
    extensions: [],
    precision: { fragment: null, vertex: null },
    reasons: reasonTokens('no-usable-data'),
  };
  try {
    const root = asObject(input);
    const basics = asObject(safeGet(root, 'basics'));
    const shaderPrecision = asObject(safeGet(root, 'shaderPrecision'));
    const blocked =
      hasBlockSignal(root) || hasBlockSignal(basics) || hasBlockSignal(shaderPrecision);

    const vendor = safeText(safeGet(basics, 'vendor'), 128) || null;
    const renderer = safeText(safeGet(basics, 'renderer'), 128) || null;
    const version = safeText(safeGet(basics, 'version'), 64) || null;
    const shadingLanguageVersion = safeText(safeGet(basics, 'shadingLanguageVersion'), 64) || null;
    const unmaskedVendor = safeText(safeGet(basics, 'unmaskedVendor'), 128) || null;
    const unmaskedRenderer = safeText(safeGet(basics, 'unmaskedRenderer'), 128) || null;
    const extensions = webglExtensionNames(safeGet(root, 'extensions'));
    const precision = {
      fragment: normalizeShaderPrecision(safeGet(shaderPrecision, 'fragment')),
      vertex: normalizeShaderPrecision(safeGet(shaderPrecision, 'vertex')),
    };

    const hasBasics = Boolean(vendor || renderer || version || shadingLanguageVersion || unmaskedVendor || unmaskedRenderer);
    const hasPrecision = Boolean(precision.fragment || precision.vertex);
    const hasData = hasBasics || extensions.length > 0 || hasPrecision;

    if (blocked) {
      return {
        ...empty,
        status: 'blocked',
        vendor, renderer, version, shadingLanguageVersion, unmaskedVendor, unmaskedRenderer,
        extensions,
        precision,
        reasons: reasonTokens('explicit-block', hasData ? 'partial-data-retained' : 'no-usable-data'),
      };
    }
    if (!hasData) return empty;
    return {
      ...empty,
      status: 'ok',
      vendor, renderer, version, shadingLanguageVersion, unmaskedVendor, unmaskedRenderer,
      extensions,
      precision,
      reasons: reasonTokens('normalized', !hasBasics || !extensions.length || !hasPrecision ? 'partial' : 'complete'),
    };
  } catch {
    return { ...empty, reasons: reasonTokens('exception-during-normalization') };
  }
}

export function normalizeAudioDriver(input: AudioDriverInput | null | undefined): AudioDriverRecord {
  const empty: AudioDriverRecord = {
    surface: 'audio',
    status: 'unavailable',
    sampleRate: null,
    baseLatency: null,
    outputLatency: null,
    maxChannelCount: null,
    reasons: reasonTokens('no-usable-data'),
  };
  try {
    const source = asObject(input);
    if (hasBlockSignal(source)) {
      return { ...empty, status: 'blocked', reasons: reasonTokens('explicit-block') };
    }
    const sampleRate = numericInRange(safeGet(source, 'sampleRate'), 8_000, 384_000, 0);
    const baseLatency = numericInRange(safeGet(source, 'baseLatency'), 0, 10, 9);
    const outputLatency = numericInRange(safeGet(source, 'outputLatency'), 0, 10, 9);
    const maxChannelCount = numericInRange(safeGet(source, 'maxChannelCount'), 1, 256, 0);

    const provided = ['sampleRate', 'baseLatency', 'outputLatency', 'maxChannelCount'].filter(
      (key) => safeGet(source, key) !== undefined
    );
    if (!provided.length) return empty;

    const outOfRange = (sampleRate === null && safeGet(source, 'sampleRate') !== undefined) ||
      (baseLatency === null && safeGet(source, 'baseLatency') !== undefined) ||
      (outputLatency === null && safeGet(source, 'outputLatency') !== undefined) ||
      (maxChannelCount === null && safeGet(source, 'maxChannelCount') !== undefined);

    const values = [sampleRate, baseLatency, outputLatency, maxChannelCount];
    if (values.every((value) => value === null)) {
      return {
        ...empty,
        reasons: reasonTokens('no-usable-data', outOfRange ? 'out-of-range' : 'malformed-fields'),
      };
    }
    return {
      ...empty,
      status: 'ok',
      sampleRate,
      baseLatency,
      outputLatency,
      maxChannelCount,
      reasons: reasonTokens('normalized', values.some((value) => value === null) ? 'partial' : 'complete', outOfRange ? 'out-of-range' : ''),
    };
  } catch {
    return { ...empty, reasons: reasonTokens('exception-during-normalization') };
  }
}

function normalizeWinding(value: unknown): string | null {
  if (value === true) return 'cw';
  if (value === false) return 'ccw';
  if (typeof value === 'string') {
    const token = value.trim().toLowerCase();
    if (token === 'cw' || token === 'clockwise') return 'cw';
    if (token === 'ccw' || token === 'counterclockwise' || token === 'counter-clockwise') return 'ccw';
  }
  return null;
}

function geometryDescriptor(value: unknown): string | null {
  if (typeof value === 'string') return normalizeDescriptor(value, 128);
  const source = asObject(value);
  if (isEmptyInput(value)) return null;
  const keys = Object.keys(source).sort(compareStrings).slice(0, 16);
  const parts: string[] = [];
  for (const key of keys) {
    const n = finiteNumber(safeGet(source, key));
    if (n !== null) parts.push(`${key}=${roundTo(n, 6)}`);
  }
  return parts.length ? parts.join(';') : null;
}

export function normalizeCanvasSurfaces(input: CanvasSurfacesInput | null | undefined): CanvasSurfacesRecord {
  const empty: CanvasSurfacesRecord = {
    surface: 'canvas',
    status: 'unavailable',
    winding: null,
    geometry: null,
    text: null,
    reasons: reasonTokens('no-usable-data'),
  };
  try {
    const source = asObject(input);
    if (hasBlockSignal(source)) {
      return { ...empty, status: 'blocked', reasons: reasonTokens('explicit-block') };
    }
    const winding = normalizeWinding(safeGet(source, 'winding'));
    const geometry = geometryDescriptor(safeGet(source, 'geometry'));
    const text = normalizeDescriptor(safeGet(source, 'text'), 128);
    if (!winding && !geometry && !text) return empty;
    return {
      ...empty,
      status: 'ok',
      winding,
      geometry,
      text,
      reasons: reasonTokens('normalized', !winding || !geometry || !text ? 'partial' : 'complete', 'no-hashing'),
    };
  } catch {
    return { ...empty, reasons: reasonTokens('exception-during-normalization') };
  }
}

function keyboardTokens(value: unknown): string[] {
  if (Array.isArray(value)) {
    return canonicalizeStrings(value.filter((item) => typeof item === 'string'), 256, 24);
  }
  if (typeof value === 'string') {
    const parts = /[\s,|]/.test(value) ? value.split(/[\s,|]+/) : Array.from(value);
    return canonicalizeStrings(parts, 256, 24);
  }
  return [];
}

export function normalizeKeyboardLayout(input: unknown): KeyboardLayoutRecord {
  try {
    if (hasBlockSignal(asObject(input))) {
      return { surface: 'keyboard', status: 'blocked', layout: null, keys: [], reasons: reasonTokens('explicit-block') };
    }
    const asRecord = asObject(input);
    const layout = Array.isArray(input) || typeof input === 'string'
      ? null
      : safeText(safeGet(asRecord, 'layout'), 64) || null;
    const keysValue = Array.isArray(input) || typeof input === 'string'
      ? input
      : firstDefined(asRecord, ['keys', 'characters', 'chars', 'sequence', 'value']);
    const keys = keyboardTokens(keysValue);
    if (!keys.length && !layout) {
      return { surface: 'keyboard', status: 'unavailable', layout: null, keys: [], reasons: reasonTokens('no-usable-keys') };
    }
    return {
      surface: 'keyboard',
      status: 'ok',
      layout,
      keys,
      reasons: reasonTokens('normalized', !keys.length ? 'layout-only' : ''),
    };
  } catch {
    return {
      surface: 'keyboard',
      status: 'unavailable',
      layout: null,
      keys: [],
      reasons: reasonTokens('exception-during-normalization'),
    };
  }
}

function cssFeatureNames(value: unknown): string[] {
  if (Array.isArray(value)) return stringList(value, 256, 96);
  const source = asObject(value);
  if (isEmptyInput(value)) return [];
  const enabled: string[] = [];
  for (const key of Object.keys(source)) {
    const flag = safeGet(source, key);
    if (flag === true || flag === 1 || (typeof flag === 'string' && flag.trim() !== '')) enabled.push(key);
  }
  return canonicalizeStrings(enabled, 256, 96);
}

export function normalizeCssVector(input: unknown): CssVectorRecord {
  try {
    if (hasBlockSignal(asObject(input))) {
      return { surface: 'css', status: 'blocked', features: [], reasons: reasonTokens('explicit-block') };
    }
    const inputObject = asObject(input);
    const wrapped = firstDefined(inputObject, ['features', 'supported', 'properties', 'enabled']);
    // A flat { featureName: flag } map is itself the feature vector; a wrapper key is optional.
    const source = Array.isArray(input) || typeof input === 'string' ? input : wrapped ?? inputObject;
    const features = cssFeatureNames(source);
    if (!features.length) {
      return { surface: 'css', status: 'unavailable', features: [], reasons: reasonTokens('no-usable-features') };
    }
    return { surface: 'css', status: 'ok', features, reasons: reasonTokens('normalized') };
  } catch {
    return { surface: 'css', status: 'unavailable', features: [], reasons: reasonTokens('exception-during-normalization') };
  }
}

/** Whitelisted math keys keep the record bounded and free of volatile/extra data. */
const MATH_KEYS = [
  'sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'atan2',
  'sinh', 'cosh', 'tanh', 'exp', 'log', 'log2', 'log10',
  'sqrt', 'cbrt', 'pow', 'E', 'PI', 'LN2', 'LN10', 'LOG2E', 'LOG10E', 'SQRT2', 'SQRT1_2',
] as const;

export function normalizeMathConstants(input: unknown): MathConstantsRecord {
  try {
    if (hasBlockSignal(asObject(input))) {
      return { surface: 'math', status: 'blocked', constants: {}, reasons: reasonTokens('explicit-block') };
    }
    const source = asObject(input);
    if (isEmptyInput(input)) {
      return { surface: 'math', status: 'unavailable', constants: {}, reasons: reasonTokens('no-usable-constants') };
    }
    const constants: Record<string, number> = {};
    for (const key of MATH_KEYS) {
      const value = finiteNumber(safeGet(source, key));
      if (value === null) continue;
      constants[key] = roundTo(value, 12);
    }
    const keys = Object.keys(constants).sort(compareStrings);
    if (!keys.length) {
      return {
        surface: 'math',
        status: 'unavailable',
        constants: {},
        reasons: reasonTokens('no-usable-constants', 'no-whitelisted-keys'),
      };
    }
    const sorted: Record<string, number> = {};
    for (const key of keys) sorted[key] = constants[key];
    return { surface: 'math', status: 'ok', constants: sorted, reasons: reasonTokens('normalized', 'rounded-12dp') };
  } catch {
    return { surface: 'math', status: 'unavailable', constants: {}, reasons: reasonTokens('exception-during-normalization') };
  }
}

export function normalizeDomBlockers(input: unknown): DomBlockersRecord {
  try {
    if (hasBlockSignal(asObject(input))) {
      return { surface: 'dom-blockers', status: 'blocked', blocked: [], count: 0, reasons: reasonTokens('explicit-block') };
    }
    const hadInput = !isEmptyInput(input);
    const source = Array.isArray(input) || typeof input === 'string'
      ? input
      : firstDefined(asObject(input), ['blocked', 'detected', 'probes', 'blockers']);
    const blocked = stringList(source, 256, 96);
    if (!blocked.length) {
      return {
        surface: 'dom-blockers',
        status: hadInput ? 'ok' : 'unavailable',
        blocked: [],
        count: 0,
        reasons: reasonTokens(hadInput ? 'no-blockers-detected' : 'no-usable-data'),
      };
    }
    return {
      surface: 'dom-blockers',
      status: 'blocked',
      blocked,
      count: blocked.length,
      reasons: reasonTokens('blockers-detected', 'normalized'),
    };
  } catch {
    return {
      surface: 'dom-blockers',
      status: 'unavailable',
      blocked: [],
      count: 0,
      reasons: reasonTokens('exception-during-normalization'),
    };
  }
}

/* -------------------------------------------------------------------------- */
/* WebGPU — additive deployable slice (NOT a FingerprintJS v5 source)          */
/* -------------------------------------------------------------------------- */

/**
 * Normalize the static WebGPU slice described in the research brief: `adapter.info`
 * (vendor / architecture / device / description, which may legitimately be empty),
 * `device.features`, `device.limits` (the four compute-workgroup fields), and
 * `timestamp-query` availability.
 *
 * This is pure data normalization of already-collected values. It performs NO adapter
 * enumeration, NO GPU work, NO atomic-contention histogram, NO ML device classification,
 * NO hashing, and NO risk scoring. Research-only techniques are excluded via
 * `ENTROPY_NOTES.researchOnly` (id literally `research_only`); the ~5.19-bit estimate is
 * descriptive metadata in `ENTROPY_NOTES.staticWebGpuEstimate`, never a decision input.
 */
export function normalizeWebGpuSurfaces(input: WebGpuSurfacesInput | null | undefined): WebGpuSurfacesRecord {
  const emptyAdapter = { vendor: null, architecture: null, device: null, description: null };
  const emptyLimits = {
    maxComputeWorkgroupSizeX: null,
    maxComputeWorkgroupSizeY: null,
    maxComputeWorkgroupSizeZ: null,
    maxComputeWorkgroupsPerDimension: null,
  };
  const baseNotes = [ENTROPY_NOTES.noWebgpuInFjsV5.id];
  const blank = (status: EntropyStatus, reasons: string[], notes: string[] = baseNotes): WebGpuSurfacesRecord => ({
    surface: 'webgpu',
    status,
    adapter: { ...emptyAdapter },
    features: [],
    limits: { ...emptyLimits },
    timestampQuery: null,
    notes,
    reasons,
  });
  try {
    const root = asObject(input);
    if (hasBlockSignal(root)) {
      return blank('blocked', reasonTokens('explicit-block'), baseNotes);
    }

    const adapterInfo = asObject(safeGet(root, 'adapterInfo'));
    const limits = asObject(safeGet(root, 'limits'));
    const features = featureTokens(firstDefined(root, ['features', 'featureNames']));

    const adapter = {
      vendor: safeText(safeGet(adapterInfo, 'vendor'), 96) || null,
      architecture: safeText(safeGet(adapterInfo, 'architecture'), 96) || null,
      device: safeText(safeGet(adapterInfo, 'device'), 96) || null,
      description: safeText(safeGet(adapterInfo, 'description'), 192) || null,
    };
    const normalizedLimits = {
      maxComputeWorkgroupSizeX: numericInRange(safeGet(limits, 'maxComputeWorkgroupSizeX'), 1, 65_536, 0),
      maxComputeWorkgroupSizeY: numericInRange(safeGet(limits, 'maxComputeWorkgroupSizeY'), 1, 65_536, 0),
      maxComputeWorkgroupSizeZ: numericInRange(safeGet(limits, 'maxComputeWorkgroupSizeZ'), 1, 65_536, 0),
      maxComputeWorkgroupsPerDimension: numericInRange(safeGet(limits, 'maxComputeWorkgroupsPerDimension'), 1, 2_147_483_647, 0),
    };

    const explicitTimestamp = availability(firstDefined(root, ['timestampQuery', 'timestampQueryAvailable']));
    const claimsTimestamp = features.some((name) => name.toLowerCase() === 'timestamp-query');
    const timestampQuery = explicitTimestamp ?? (claimsTimestamp ? 'available' : features.length ? 'unavailable' : null);

    const hasAdapter = Object.values(adapter).some((value) => value !== null);
    const hasLimits = Object.values(normalizedLimits).some((value) => value !== null);
    const hasData = hasAdapter || features.length > 0 || hasLimits || timestampQuery !== null;

    if (!hasData) return blank('unavailable', reasonTokens('no-usable-data'), baseNotes);

    return {
      ...blank('ok', [], baseNotes),
      adapter,
      features,
      limits: normalizedLimits,
      timestampQuery,
      reasons: reasonTokens(
        'normalized',
        !hasAdapter || !features.length || !hasLimits || timestampQuery === null ? 'partial' : 'complete',
        hasAdapter ? '' : 'empty-adapter-info'
      ),
    };
  } catch {
    return blank('unavailable', reasonTokens('exception-during-normalization'), baseNotes);
  }
}

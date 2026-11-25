/**
 * Shadow-only, additive FingerprintJS-v5 parity snapshot (pure, deterministic, zero I/O).
 *
 * This module is a *descriptive coverage report* over data that some caller has ALREADY
 * collected. It performs NO browser probing: it never touches `document`, `window`, canvas,
 * WebGL, AudioContext, `navigator`, `Intl`, `BatteryManager`, or any third-party SDK. It makes
 * no network requests, reads no clock, and has no ambient state. Nothing in production imports
 * it — it is a shadow evaluation surface used only by its own test.
 *
 * Design guarantees:
 *  - NEVER throws. Hostile getters, proxies, cyclic/wrong-typed values degrade to empty /
 *    absent descriptors (fail closed) via guarded reads, never to fabricated observations.
 *  - NEVER fabricates a font detection. `status: 'present'` is emitted ONLY when a family
 *    literally appears in a pre-collected detection array supplied by the caller. A family
 *    inferred from a coarse platform-class marker is labelled `derived` (never `present`),
 *    and `detected: true` is set ONLY for literal detections.
 *  - NO hashing, no digests, no risk/verdict/confidence inputs. No value here is folded into a
 *    score, an identity hash, the 8-field sealed-envelope canonical string, or a bot verdict.
 *  - Additive and namespaced: every report lives inside the returned `FjsV5ParitySnapshot`
 *    object under its own `surface` id. The function only reads its input; it never mutates a
 *    payload, envelope, or collector record and never adds fields to them.
 *  - Deterministic: output is a pure function of input values. Arrays are canonical, deduped
 *    and sorted; no `localeCompare`, no iteration-order dependence, no wall clock.
 *
 * Research-context note (from the entropy-matrix brief): the "9 vs 16" gap is NOT a live
 * probe gap. `9` is the length of the Linux OS-shipped font allowlist used by cross-browser
 * matching (`src/shared/matching/compareFingerprints.ts`); `16` is the cross-browser `fonts`
 * weight in that same matching table. This module reports coverage of a canonical 16-family
 * high-value set descriptively; it does not add probes to reconcile those two numbers.
 *
 * `battery` has no client producer at all, so it is always reported `absent`. Keyboard layout
 * reasons are transported by the collector but are NOT consumed by any server verdict, so
 * keyboard is always reported `descriptive` (never as a weight, tier or verdict input).
 */

/* -------------------------------------------------------------------------- */
/* Canonical, frozen reference inventories (documentation, not probes)         */
/* -------------------------------------------------------------------------- */

/**
 * Sixteen canonical high-value font families used for descriptive coverage reporting.
 * Every entry is a family already named by an existing probe list
 * (`src/client/signals/fonts.ts`, `src/lib/collector.ts:PROBE_FONT_FAMILIES`); no new font is
 * introduced and no detection is inferred from this list alone.
 */
export const FJS_V5_HIGH_VALUE_FONT_FAMILIES = Object.freeze([
  'Arial', 'Arial Narrow', 'Calibri', 'Cambria', 'Courier New', 'Georgia',
  'Helvetica', 'Helvetica Neue', 'Menlo', 'Roboto', 'Segoe UI', 'Tahoma',
  'Times New Roman', 'Trebuchet MS', 'Ubuntu', 'Verdana',
] as const);

/** The fifteen ordered FPJS-style transcendental values hashed by `collector.ts`. */
export const FPJS15_VECTOR_KEYS = Object.freeze([
  'acos', 'acosh', 'asin', 'asinh', 'atan', 'atanh', 'cbrt', 'cos',
  'cosh', 'expm1', 'log1p', 'sin', 'sinh', 'tanh', 'pow',
] as const);

/** The seven font-preference presets measured by `src/client/signals/fontPreferences.ts`. */
export const FONT_PREFERENCE_PRESETS = Object.freeze([
  'default', 'apple', 'serif', 'sans', 'mono', 'min', 'system',
] as const);

/** The eight DOMRect numeric metrics captured by the emoji probe shapes. */
export const EMOJI_DOMRECT_METRICS = Object.freeze([
  'width', 'height', 'top', 'bottom', 'left', 'right', 'x', 'y',
] as const);

/** Core `LocationInfo` fields (src/types/visitor.ts) used for field-level parity. */
export const LOCATION_INFO_FIELDS = Object.freeze([
  'publicIp', 'city', 'region', 'country', 'countryCode', 'latitude', 'longitude',
  'isp', 'org', 'asn', 'timezone', 'isVpnOrHosting', 'isIpVerified', 'isLocationVerified',
] as const);

/**
 * Coarse platform-class → canonical-family markers. Only used to label a family `derived`;
 * a derived family is an inference from a platform marker and is NEVER a font detection.
 */
const PLATFORM_MARKERS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  windows: ['Segoe UI', 'Calibri', 'Tahoma', 'Trebuchet MS', 'Arial'],
  mac: ['Menlo', 'Helvetica Neue', 'Helvetica'],
  linux: ['Ubuntu'],
});

/* -------------------------------------------------------------------------- */
/* Public types                                                               */
/* -------------------------------------------------------------------------- */

export type FamilyCoverageStatus = 'present' | 'derived' | 'absent';

/** Input contract (all members optional). The function itself accepts `unknown` and fails closed. */
export interface FjsV5ParityInput {
  fonts?: {
    installed?: unknown;
    fonts?: unknown;
    detected?: unknown;
    fontHash?: unknown;
    platformClassGuess?: unknown;
    error?: unknown;
  } | null;
  rawFonts?: unknown;
  installedFonts?: unknown;
  fontPreferences?: {
    widths?: unknown;
    widthsExactIntegers?: unknown;
    error?: unknown;
  } | null;
  emoji?: {
    font?: unknown;
    width?: unknown;
    height?: unknown;
    top?: unknown;
    bottom?: unknown;
    left?: unknown;
    right?: unknown;
    x?: unknown;
    y?: unknown;
    error?: unknown;
  } | null;
  math?: {
    values?: unknown;
    vector?: unknown;
    errorStackFunctions?: unknown;
    error?: unknown;
  } | null;
  location?: Record<string, unknown> | null;
  battery?: unknown;
  keyboard?: unknown;
}

export interface FontFamilyCoverage {
  family: string;
  status: FamilyCoverageStatus;
  /** True ONLY for a literal detection in a supplied array. Never true for `derived`. */
  detected: boolean;
  /** Descriptive provenance token — never a verdict, weight or score. */
  reason: 'direct-detection' | 'derived-from-platform-class-marker' | 'no-detection-evidence';
}

export interface FontCoverageSnapshot {
  surface: 'fontCoverage';
  canonicalFamilies: string[];
  families: FontFamilyCoverage[];
  counts: { present: number; derived: number; absent: number };
  note: string;
}

export interface EmojiParitySnapshot {
  surface: 'emoji';
  domRectMetrics: string[];
  present: string[];
  missing: string[];
  status: 'present' | 'absent';
  /** The declared font stack is a CSS string, not a DOMRect metric; tracked separately. */
  declaredFontStack: boolean;
  note: string;
}

export interface MathParitySnapshot {
  surface: 'math';
  canonicalKeys: string[];
  present: string[];
  missing: string[];
  count: number;
  status: 'present' | 'absent';
  note: string;
}

export interface FontPreferencesParitySnapshot {
  surface: 'fontPreferences';
  presets: string[];
  measured: string[];
  missing: string[];
  widthsExactIntegers: boolean | null;
  status: 'present' | 'absent';
}

export interface GeoFieldsParitySnapshot {
  surface: 'geoFields';
  fields: string[];
  present: string[];
  missing: string[];
  status: 'parity' | 'partial' | 'absent';
}

export interface DescriptiveAbsence {
  surface: 'battery' | 'keyboard';
  status: 'absent' | 'descriptive';
  dataProvided: boolean;
  consumer: 'none';
  detail: string;
}

export interface FjsV5ParitySnapshot {
  surface: 'fjs-v5-parity';
  status: 'ok' | 'unavailable';
  fontCoverage: FontCoverageSnapshot;
  emoji: EmojiParitySnapshot;
  math: MathParitySnapshot;
  fontPreferences: FontPreferencesParitySnapshot;
  geoFields: GeoFieldsParitySnapshot;
  battery: DescriptiveAbsence;
  keyboard: DescriptiveAbsence;
  reasons: string[];
}

/* -------------------------------------------------------------------------- */
/* Defensive primitives — every read is guarded so hostile input cannot throw */
/* -------------------------------------------------------------------------- */

function asObject(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
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

function safeText(value: unknown, maxLen = 96): string {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) : trimmed;
}

/** A vector slot is "present" when it carries a finite number or a parseable numeric string. */
function numericSlot(value: unknown): boolean {
  return finiteNumber(value) !== null ||
    (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value)));
}

/** Iterate an array defensively: hostile proxies may throw on reads/iteration. */
function safeArrayItems(value: unknown): unknown[] {
  if (!Array.isArray(value)) return [];
  try {
    const out: unknown[] = [];
    for (const item of value) out.push(item);
    return out;
  } catch {
    return [];
  }
}

function firstDefined(src: Record<string, unknown>, keys: string[]): unknown {
  for (const key of keys) {
    const value = safeGet(src, key);
    if (value !== undefined && value !== null) return value;
  }
  return undefined;
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function sortedUnique(values: string[]): string[] {
  return Array.from(new Set(values)).sort(compareStrings);
}

/* -------------------------------------------------------------------------- */
/* Surface builders                                                           */
/* -------------------------------------------------------------------------- */

function collectDetectedFontKeys(input: unknown): Set<string> {
  const root = asObject(input);
  const fonts = asObject(safeGet(root, 'fonts'));
  const sources: unknown[] = [
    safeGet(fonts, 'installed'),
    safeGet(fonts, 'fonts'),
    safeGet(fonts, 'detected'),
    safeGet(root, 'rawFonts'),
    safeGet(root, 'installedFonts'),
    Array.isArray(input) ? input : undefined,
  ];
  const keys = new Set<string>();
  for (const source of sources) {
    for (const item of safeArrayItems(source)) {
      const token = safeText(item, 96).toLowerCase();
      if (token) keys.add(token);
    }
  }
  return keys;
}

function resolvePlatformClass(input: unknown): string {
  const root = asObject(input);
  const fonts = asObject(safeGet(root, 'fonts'));
  return safeText(firstDefined(fonts, ['platformClassGuess', 'platformClass']), 32).toLowerCase();
}

function buildFontCoverage(input: unknown): FontCoverageSnapshot {
  const detectedKeys = collectDetectedFontKeys(input);
  const platformClass = resolvePlatformClass(input);
  const markers = PLATFORM_MARKERS[platformClass] ?? [];

  const families: FontFamilyCoverage[] = [];
  const counts = { present: 0, derived: 0, absent: 0 };
  for (const family of FJS_V5_HIGH_VALUE_FONT_FAMILIES) {
    let coverage: FontFamilyCoverage;
    if (detectedKeys.has(family.toLowerCase())) {
      coverage = { family, status: 'present', detected: true, reason: 'direct-detection' };
    } else if (markers.indexOf(family) !== -1) {
      coverage = { family, status: 'derived', detected: false, reason: 'derived-from-platform-class-marker' };
    } else {
      coverage = { family, status: 'absent', detected: false, reason: 'no-detection-evidence' };
    }
    counts[coverage.status] += 1;
    families.push(coverage);
  }

  return {
    surface: 'fontCoverage',
    canonicalFamilies: [...FJS_V5_HIGH_VALUE_FONT_FAMILIES],
    families,
    counts,
    note: 'Coverage is descriptive only. "present" requires a literal detection in caller-supplied data; "derived" is a platform-class inference and is never a detection; "absent" means no evidence was supplied. No font is probed or invented here.',
  };
}

function buildEmoji(input: unknown): EmojiParitySnapshot {
  const root = asObject(input);
  const emoji = asObject(safeGet(root, 'emoji'));
  const present: string[] = [];
  const missing: string[] = [];
  for (const key of EMOJI_DOMRECT_METRICS) {
    if (finiteNumber(safeGet(emoji, key)) !== null) present.push(key);
    else missing.push(key);
  }
  return {
    surface: 'emoji',
    domRectMetrics: [...EMOJI_DOMRECT_METRICS],
    present: [...present],
    missing: [...missing],
    status: present.length ? 'present' : 'absent',
    declaredFontStack: safeText(safeGet(emoji, 'font'), 192) !== '',
    note: 'DOMRect metric presence from an already-collected emoji shape only; no DOMRect is created here and the declared font stack is not a metric.',
  };
}

function buildMath(input: unknown): MathParitySnapshot {
  const root = asObject(input);
  const math = asObject(safeGet(root, 'math'));
  const values = asObject(safeGet(math, 'values'));
  const vector = safeArrayItems(safeGet(math, 'vector'));
  const present: string[] = [];
  const missing: string[] = [];

  for (let i = 0; i < FPJS15_VECTOR_KEYS.length; i += 1) {
    const key = FPJS15_VECTOR_KEYS[i];
    const fromValues = numericSlot(safeGet(values, key));
    const fromVector = numericSlot(vector[i]);
    if (fromValues || fromVector) present.push(key);
    else missing.push(key);
  }

  return {
    surface: 'math',
    canonicalKeys: [...FPJS15_VECTOR_KEYS],
    present: [...present],
    missing: [...missing],
    count: present.length,
    status: present.length ? 'present' : 'absent',
    note: 'Presence of the 15-value FPJS-style math vector only. Values are neither emitted nor hashed; no math is executed here.',
  };
}

function buildFontPreferences(input: unknown): FontPreferencesParitySnapshot {
  const root = asObject(input);
  const prefs = asObject(safeGet(root, 'fontPreferences'));
  const widths = asObject(safeGet(prefs, 'widths'));
  const measured: string[] = [];
  const missing: string[] = [];
  for (const preset of FONT_PREFERENCE_PRESETS) {
    if (finiteNumber(safeGet(widths, preset)) !== null) measured.push(preset);
    else missing.push(preset);
  }
  const flag = safeGet(prefs, 'widthsExactIntegers');
  return {
    surface: 'fontPreferences',
    presets: [...FONT_PREFERENCE_PRESETS],
    measured,
    missing,
    widthsExactIntegers: typeof flag === 'boolean' ? flag : null,
    status: measured.length ? 'present' : 'absent',
  };
}

function buildGeoFields(input: unknown): GeoFieldsParitySnapshot {
  const root = asObject(input);
  const location = asObject(safeGet(root, 'location'));
  const present: string[] = [];
  const missing: string[] = [];
  for (const field of LOCATION_INFO_FIELDS) {
    if (safeGet(location, field) !== undefined) present.push(field);
    else missing.push(field);
  }
  const total = LOCATION_INFO_FIELDS.length;
  return {
    surface: 'geoFields',
    fields: [...LOCATION_INFO_FIELDS],
    present,
    missing,
    status: !present.length ? 'absent' : present.length === total ? 'parity' : 'partial',
  };
}

function buildDescriptiveAbsence(
  surface: 'battery' | 'keyboard',
  status: 'absent' | 'descriptive',
  input: unknown,
  detail: string
): DescriptiveAbsence {
  const root = asObject(input);
  const value = safeGet(root, surface);
  return {
    surface,
    status,
    dataProvided: value !== undefined && value !== null,
    consumer: 'none',
    detail,
  };
}

/* -------------------------------------------------------------------------- */
/* Public entry point                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Build a complete, deterministic parity snapshot. Never throws: any hostile read degrades
 * to empty/absent descriptors. The returned object is the ONLY output; no payload, envelope,
 * hash, verdict or score is produced or mutated.
 */
export function buildFjsV5ParitySnapshot(input: unknown): FjsV5ParitySnapshot {
  try {
    const fontCoverage = buildFontCoverage(input);
    const emoji = buildEmoji(input);
    const math = buildMath(input);
    const fontPreferences = buildFontPreferences(input);
    const geoFields = buildGeoFields(input);
    const battery = buildDescriptiveAbsence(
      'battery',
      'absent',
      input,
      'No client producer exists for battery data; it is never collected, emitted or scored.'
    );
    const keyboard = buildDescriptiveAbsence(
      'keyboard',
      'descriptive',
      input,
      'Keyboard-layout reasons are transported by the collector but no server verdict consumes them; no weight, tier or score.'
    );

    const hasAnyData =
      fontCoverage.counts.present > 0 || fontCoverage.counts.derived > 0 ||
      emoji.status === 'present' || math.status === 'present' ||
      fontPreferences.status === 'present' || geoFields.status !== 'absent';

    return {
      surface: 'fjs-v5-parity',
      status: hasAnyData ? 'ok' : 'unavailable',
      fontCoverage,
      emoji,
      math,
      fontPreferences,
      geoFields,
      battery,
      keyboard,
      reasons: sortedUnique([
        'descriptive-only',
        'no-probes-run',
        'no-verdict-or-score-input',
        hasAnyData ? 'some-shape-evidence' : 'no-shape-evidence',
      ]),
    };
  } catch {
    // Fail closed: a well-formed, entirely empty snapshot. No field may leak a partial read.
    const families = FJS_V5_HIGH_VALUE_FONT_FAMILIES.map((family) => ({
      family,
      status: 'absent' as const,
      detected: false,
      reason: 'no-detection-evidence' as const,
    }));
    return {
      surface: 'fjs-v5-parity',
      status: 'unavailable',
      fontCoverage: {
        surface: 'fontCoverage',
        canonicalFamilies: [...FJS_V5_HIGH_VALUE_FONT_FAMILIES],
        families,
        counts: { present: 0, derived: 0, absent: families.length },
        note: 'Coverage is descriptive only; no evidence was supplied.',
      },
      emoji: {
        surface: 'emoji',
        domRectMetrics: [...EMOJI_DOMRECT_METRICS],
        present: [],
        missing: [...EMOJI_DOMRECT_METRICS],
        status: 'absent',
        declaredFontStack: false,
        note: 'No DOMRect metric was observed.',
      },
      math: {
        surface: 'math',
        canonicalKeys: [...FPJS15_VECTOR_KEYS],
        present: [],
        missing: [...FPJS15_VECTOR_KEYS],
        count: 0,
        status: 'absent',
        note: 'No math-vector slot was observed.',
      },
      fontPreferences: {
        surface: 'fontPreferences',
        presets: [...FONT_PREFERENCE_PRESETS],
        measured: [],
        missing: [...FONT_PREFERENCE_PRESETS],
        widthsExactIntegers: null,
        status: 'absent',
      },
      geoFields: {
        surface: 'geoFields',
        fields: [...LOCATION_INFO_FIELDS],
        present: [],
        missing: [...LOCATION_INFO_FIELDS],
        status: 'absent',
      },
      battery: {
        surface: 'battery',
        status: 'absent',
        dataProvided: false,
        consumer: 'none',
        detail: 'No client producer exists for battery data; it is never collected, emitted or scored.',
      },
      keyboard: {
        surface: 'keyboard',
        status: 'descriptive',
        dataProvided: false,
        consumer: 'none',
        detail: 'Keyboard-layout reasons are transported but no server verdict consumes them; no weight, tier or score.',
      },
      reasons: ['descriptive-only', 'exception-during-snapshot', 'no-shape-evidence', 'no-probes-run', 'no-verdict-or-score-input'],
    };
  }
}

/**
 * Additive, informational media-preference resolver.
 *
 * Canonical home for the coarse `matchMedia` observations carried on the telemetry envelope's
 * `media_preferences` field (color scheme, reduced motion, forced colors, contrast, locale,
 * timezone). It deliberately produces ONLY descriptive transport data:
 *
 *  - it is NEVER an input to `anti_detect_browser`, a bot/human verdict, a risk score, or an
 *    identity/hash seed. Accessibility and theme choices are ordinary user preferences; treating
 *    them as automation evidence would punish users who enable them for legitimate reasons.
 *  - it is pure, deterministic and side-effect free at import time (no I/O, no SDK, no globals);
 *  - it NEVER throws: hostile getters, proxies, primitives and malformed values degrade to null
 *    per field with a diagnostic note, and the remaining fields are still read.
 *
 * The timezone field is folded through the one canonical IANA resolver (`./timezone`) so a
 * legacy alias is never mistaken for a different zone.
 */

import { canonicalTimezone } from './timezone';

/* -------------------------------------------------------------------------- */
/* Input / output contracts                                                    */
/* -------------------------------------------------------------------------- */

/** Raw, optional media signals. Only literal booleans and strings are evidence. */
export interface MediaPreferencesInput {
  /** `matchMedia('(forced-colors: active)').matches`. */
  forcedColors?: boolean | null | undefined;
  /** `matchMedia('(prefers-reduced-motion: reduce)').matches`. */
  reducedMotion?: boolean | null | undefined;
  /** `matchMedia('(prefers-reduced-transparency: reduce)').matches`. */
  reducedTransparency?: boolean | null | undefined;
  /** `prefers-color-scheme` value: `light`, `dark` or `no-preference`. */
  colorScheme?: string | null | undefined;
  /** `prefers-contrast` value: `no-preference`, `more`, `less` or `forced`. */
  contrast?: string | null | undefined;
  /** Browser locale / language tag (BCP-47 shaped). */
  locale?: string | null | undefined;
  /** Browser-reported IANA timezone identifier. */
  timezone?: string | null | undefined;
}

/**
 * Additive record mirroring the envelope's `media_preferences` vocabulary. Every value is
 * nullable so a partially observed probe still yields a valid, informational-only record.
 */
export interface MediaPreferencesResult {
  forced_colors: boolean | null;
  reduced_motion: boolean | null;
  reduced_transparency: boolean | null;
  color_scheme: string | null;
  contrast: string | null;
  locale: string | null;
  timezone: string | null;
  /** Human-readable normalization / rejection audit trail. */
  notes: string[];
}

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                            */
/* -------------------------------------------------------------------------- */

const EMPTY_INPUT: MediaPreferencesInput = Object.freeze({});

/** Always-present runtime reminder of the field's strictly informational status. */
export const MEDIA_PREFERENCES_INFORMATIONAL_NOTE =
  'Informational only: never used for anti_detect_browser, bot verdict or identity hashing.';

const COLOR_SCHEMES: ReadonlySet<string> = new Set(['light', 'dark', 'no-preference']);
const CONTRASTS: ReadonlySet<string> = new Set(['no-preference', 'more', 'less', 'forced']);

const COLOR_SCHEME_ALIASES: Readonly<Record<string, string>> = Object.freeze({
  normal: 'no-preference',
});

const CONTRAST_ALIASES: Readonly<Record<string, string>> = Object.freeze({
  normal: 'no-preference',
  high: 'more',
  low: 'less',
});

type InputKey = keyof MediaPreferencesInput;

function asObject(input: MediaPreferencesInput | null | undefined): MediaPreferencesInput {
  return input !== null && typeof input === 'object' ? input : EMPTY_INPUT;
}

/** Reads one field in isolation; a throwing getter is reported, not propagated. */
function readRaw(
  src: MediaPreferencesInput,
  key: InputKey,
  notes: string[],
): { present: boolean; value: unknown } {
  try {
    const value: unknown = src[key];
    return { present: value !== undefined && value !== null, value };
  } catch {
    notes.push(`${key}: unreadable field ignored`);
    return { present: false, value: undefined };
  }
}

/** Only a literal boolean is evidence; `1`, `'true'`, boxed values and objects are rejected. */
function readBoolean(
  src: MediaPreferencesInput,
  key: InputKey,
  notes: string[],
): boolean | null {
  const { present, value } = readRaw(src, key, notes);
  if (!present) return null;
  if (typeof value === 'boolean') return value;
  notes.push(`${key}: expected a boolean, got ${typeof value} value`);
  return null;
}

/** Reads a primitive string, trimmed. Boxed strings and other values are rejected. */
function readString(
  src: MediaPreferencesInput,
  key: InputKey,
  notes: string[],
): string | null {
  const { present, value } = readRaw(src, key, notes);
  if (!present) return null;
  if (typeof value !== 'string') {
    notes.push(`${key}: expected a string, got ${typeof value} value`);
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    notes.push(`${key}: empty string ignored`);
    return null;
  }
  return trimmed;
}

/** Maps a CSS media-feature value onto its canonical vocabulary. */
function readEnum(
  src: MediaPreferencesInput,
  key: InputKey,
  allowed: ReadonlySet<string>,
  aliases: Readonly<Record<string, string>>,
  notes: string[],
): string | null {
  const raw = readString(src, key, notes);
  if (raw === null) return null;
  const lowered = raw.toLowerCase();
  const candidate = Object.prototype.hasOwnProperty.call(aliases, lowered) ? aliases[lowered] : lowered;
  if (!allowed.has(candidate)) {
    notes.push(`${key}: unrecognised value ignored`);
    return null;
  }
  if (candidate !== raw) notes.push(`${key}: normalized to ${candidate}`);
  return candidate;
}

/**
 * Light BCP-47-shaped normalization: underscores become hyphens, the language subtag is
 * lowercased, a two-letter region is uppercased, a four-letter script is title-cased and
 * later subtags are lowercased. Junk, control characters and over-long tags are rejected.
 */
function normalizeLocale(raw: string): string | null {
  const value = raw.replace(/_/g, '-');
  if (value.length > 64 || /[\u0000-\u001F\u007F]/.test(value)) return null;
  const parts = value.split('-');
  if (parts.length > 5 || !/^[A-Za-z]{2,3}$/.test(parts[0])) return null;
  for (let i = 1; i < parts.length; i += 1) {
    if (!/^[A-Za-z0-9]{1,8}$/.test(parts[i])) return null;
  }
  parts[0] = parts[0].toLowerCase();
  let inExtension = false;
  for (let i = 1; i < parts.length; i += 1) {
    const part = parts[i];
    // A one-letter singleton starts a BCP-47 extension; everything after it is lowercase.
    if (part.length === 1) {
      inExtension = true;
      parts[i] = part.toLowerCase();
    } else if (inExtension || part.length < 2 || part.length > 4) {
      parts[i] = part.toLowerCase();
    } else if (part.length === 4) {
      // Script subtags are title-cased (e.g. Hant).
      parts[i] = part[0].toUpperCase() + part.slice(1).toLowerCase();
    } else {
      // Two-letter region subtags are uppercased wherever they appear (e.g. zh-Hant-TW).
      parts[i] = part.toUpperCase();
    }
  }
  return parts.join('-');
}

function readLocale(src: MediaPreferencesInput, notes: string[]): string | null {
  const raw = readString(src, 'locale', notes);
  if (raw === null) return null;
  const normalized = normalizeLocale(raw);
  if (normalized === null) {
    notes.push('locale: unrecognised value ignored');
    return null;
  }
  if (normalized !== raw) notes.push(`locale: normalized to ${normalized}`);
  return normalized;
}

function readTimezone(src: MediaPreferencesInput, notes: string[]): string | null {
  const raw = readString(src, 'timezone', notes);
  if (raw === null) return null;
  try {
    const canonical = canonicalTimezone(raw);
    if (canonical === null) {
      notes.push('timezone: unrecognised value ignored');
      return null;
    }
    if (canonical !== raw) notes.push(`timezone: normalized to ${canonical}`);
    return canonical;
  } catch {
    notes.push('timezone: normalization failed, value ignored');
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Canonical resolver                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Resolve raw media observations into the additive, informational record.
 *
 * Absent (`undefined` / `null`) fields stay null without a note: absence of evidence is normal.
 * Invalid or unreadable fields stay null WITH a note, and never stop the other fields from
 * being resolved. The function never throws, mutates its input, or reads platform state.
 */
export function resolveMediaPreferences(
  input: MediaPreferencesInput | null | undefined,
): MediaPreferencesResult {
  const notes: string[] = [];
  const result: MediaPreferencesResult = {
    forced_colors: null,
    reduced_motion: null,
    reduced_transparency: null,
    color_scheme: null,
    contrast: null,
    locale: null,
    timezone: null,
    notes,
  };

  try {
    const src = asObject(input);
    result.forced_colors = readBoolean(src, 'forcedColors', notes);
    result.reduced_motion = readBoolean(src, 'reducedMotion', notes);
    result.reduced_transparency = readBoolean(src, 'reducedTransparency', notes);
    result.color_scheme = readEnum(src, 'colorScheme', COLOR_SCHEMES, COLOR_SCHEME_ALIASES, notes);
    result.contrast = readEnum(src, 'contrast', CONTRASTS, CONTRAST_ALIASES, notes);
    result.locale = readLocale(src, notes);
    result.timezone = readTimezone(src, notes);
  } catch {
    /* Absolute last-resort guard: no hostile input may turn this helper into a crash. */
    notes.push('unexpected read failure, unresolved fields degraded to null');
  }

  notes.push(MEDIA_PREFERENCES_INFORMATIONAL_NOTE);
  return result;
}

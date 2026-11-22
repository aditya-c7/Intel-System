/**
 * One canonical IANA timezone resolver for the browser, the server and the ledger.
 *
 * A browser and an IP-geolocation provider frequently disagree only because one side reports a
 * legacy `backward` alias (`Asia/Calcutta`) while the other reports its canonical replacement
 * (`Asia/Kolkata`). Comparing raw strings turns that into a false timezone-relay signal. This
 * module resolves both sides through the same frozen table so a mismatch means a real difference
 * between two canonical zone identities — never a spelling or casing difference, and never an
 * UTC-offset coincidence (Asia/Singapore and Asia/Hong_Kong are both UTC+8 but are NOT equal).
 *
 * Dependency-free, side-effect free at import time (all lookups are lazy/memoised) and never
 * throws, so it is safe to import from a React client, an Express server or a Worker bundle.
 */

/**
 * Frozen map of the most common IANA `backward` aliases (plus a few spellings emitted by
 * geolocation providers). Keys are lowercased; values are canonical IANA zone identifiers.
 * The table is authoritative: some runtimes' `Intl.supportedValuesOf('timeZone')` still lists the
 * legacy alias instead of the canonical name, so Intl data may never override these mappings.
 */
export const IANA_TIMEZONE_ALIASES: Readonly<Record<string, string>> = Object.freeze({
  // Asia
  'asia/calcutta': 'Asia/Kolkata',
  'asia/katmandu': 'Asia/Kathmandu',
  'asia/rangoon': 'Asia/Yangon',
  'asia/saigon': 'Asia/Ho_Chi_Minh',
  'asia/chongqing': 'Asia/Shanghai',
  'asia/harbin': 'Asia/Shanghai',
  'asia/beijing': 'Asia/Shanghai',
  'asia/kashgar': 'Asia/Urumqi',
  'asia/ulan_baba': 'Asia/Ulaanbaatar',
  'asia/phnom_penh': 'Asia/Bangkok',
  'asia/vientiane': 'Asia/Bangkok',
  'asia/tel_aviv': 'Asia/Jerusalem',
  // Europe
  'europe/kiev': 'Europe/Kyiv',
  'europe/uzhgorod': 'Europe/Kyiv',
  'europe/zaporozhye': 'Europe/Kyiv',
  'europe/belfast': 'Europe/London',
  'europe/ljubljana': 'Europe/Belgrade',
  'europe/podgorica': 'Europe/Belgrade',
  'europe/sarajevo': 'Europe/Belgrade',
  'europe/skopje': 'Europe/Belgrade',
  'europe/zagreb': 'Europe/Belgrade',
  'europe/bratislava': 'Europe/Prague',
  'europe/tiraspol': 'Europe/Chisinau',
  // Americas
  'america/buenos_aires': 'America/Argentina/Buenos_Aires',
  'america/catamarca': 'America/Argentina/Catamarca',
  'america/cordoba': 'America/Argentina/Cordoba',
  'america/jujuy': 'America/Argentina/Jujuy',
  'america/mendoza': 'America/Argentina/Mendoza',
  'america/rosario': 'America/Argentina/Cordoba',
  'america/indianapolis': 'America/Indiana/Indianapolis',
  'america/fort_wayne': 'America/Indiana/Indianapolis',
  'america/louisville': 'America/Kentucky/Louisville',
  'america/monticello': 'America/Kentucky/Monticello',
  'america/godthab': 'America/Nuuk',
  'us/eastern': 'America/New_York',
  'us/central': 'America/Chicago',
  'us/mountain': 'America/Denver',
  'us/pacific': 'America/Los_Angeles',
  'us/alaska': 'America/Anchorage',
  'us/aleutian': 'America/Adak',
  'us/arizona': 'America/Phoenix',
  'us/hawaii': 'Pacific/Honolulu',
  'us/michigan': 'America/Detroit',
  'us/samoa': 'Pacific/Pago_Pago',
  'us/east-indiana': 'America/Indiana/Indianapolis',
  'us/indiana-starke': 'America/Indiana/Knox',
  // Pacific / Australia / Africa
  'pacific/johnston': 'Pacific/Honolulu',
  'pacific/samoa': 'Pacific/Pago_Pago',
  'pacific/truk': 'Pacific/Chuuk',
  'pacific/yap': 'Pacific/Chuuk',
  'pacific/ponape': 'Pacific/Pohnpei',
  'australia/act': 'Australia/Sydney',
  'australia/nsw': 'Australia/Sydney',
  'australia/canberra': 'Australia/Sydney',
  'australia/victoria': 'Australia/Melbourne',
  'australia/queensland': 'Australia/Brisbane',
  'australia/south': 'Australia/Adelaide',
  'australia/west': 'Australia/Perth',
  'australia/tasmania': 'Australia/Hobart',
  'africa/asmera': 'Africa/Asmara',
  'atlantic/faeroe': 'Atlantic/Faroe',
  // UTC spellings (Etc/GMT±N offsets are intentionally NOT aliases for UTC)
  'etc/utc': 'UTC',
  'etc/gmt': 'UTC',
  'etc/universal': 'UTC',
  'etc/zulu': 'UTC',
  'etc/greenwich': 'UTC',
  'etc/gmt0': 'UTC',
  'etc/uct': 'UTC',
  utc: 'UTC',
  gmt: 'UTC',
  universal: 'UTC',
  zulu: 'UTC',
  greenwich: 'UTC',
  gmt0: 'UTC',
  uct: 'UTC',
});

/** Values that mean "no timezone" and must never be compared as if they were a zone. */
const SENTINEL_KEYS: ReadonlySet<string> = new Set([
  'unknown',
  'unavailable',
  'n/a',
  'na',
  'none',
  'null',
  'undefined',
  'etc/unknown',
  'local',
]);

/**
 * Every name we know about (alias keys and canonical targets) mapped to its canonical form.
 * Lets a canonical id be resolved even when an older ICU list only knows the legacy alias, e.g.
 * `Asia/Kolkata` is accepted because `asia/calcutta` is in the table above.
 */
const CANONICAL_BY_KNOWN_NAME: ReadonlyMap<string, string> = (() => {
  const map = new Map<string, string>();
  for (const [alias, canonical] of Object.entries(IANA_TIMEZONE_ALIASES)) {
    if (typeof canonical !== 'string' || canonical.length === 0) continue;
    for (const knownName of [alias, canonical]) {
      const key = knownName.toLowerCase();
      if (!map.has(key)) map.set(key, canonical);
    }
  }
  return map;
})();

/** `Etc/GMT+5` / `Etc/GMT-14` are real zones that some ICU lists omit entirely. */
const ETC_GMT_OFFSET = /^etc\/gmt([+-](?:0?\d|1[0-4]))$/;

type SupportedValuesOf = (key: 'timeZone') => readonly string[];

let supportedZoneIndexCache: ReadonlyMap<string, string> | null | undefined;

/**
 * Lazily builds a lowercased -> runtime spelling index from `Intl.supportedValuesOf('timeZone')`.
 * Returns `null` when the API is unavailable or throws. Cached because the list is immutable for
 * the lifetime of a realm, and memoising keeps repeated comparisons cheap.
 */
function supportedZoneIndex(): ReadonlyMap<string, string> | null {
  if (supportedZoneIndexCache !== undefined) return supportedZoneIndexCache;
  let index: Map<string, string> | null = null;
  try {
    const intl = typeof Intl === 'undefined' ? undefined : Intl;
    const supportedValuesOf = intl
      ? (intl as typeof Intl & { supportedValuesOf?: SupportedValuesOf }).supportedValuesOf
      : undefined;
    if (typeof supportedValuesOf === 'function') {
      const values = supportedValuesOf.call(intl, 'timeZone');
      if (Array.isArray(values)) {
        index = new Map<string, string>();
        for (const value of values) {
          if (typeof value !== 'string' || value.length === 0) continue;
          const key = value.toLowerCase();
          if (!index.has(key)) index.set(key, value);
        }
      }
    }
  } catch {
    index = null;
  }
  supportedZoneIndexCache = index;
  return index;
}

/**
 * Trims, lowercases and resolves a timezone identifier to its canonical IANA name.
 *
 * Resolution order: sentinel rejection -> frozen alias table -> `Intl.supportedValuesOf` (used
 * for canonical casing and validation when available) -> curated known-name map -> null. Returns
 * `null` for empty, sentinel, unrecognised or malformed input and never throws.
 */
export function canonicalTimezone(input: string | null | undefined): string | null {
  try {
    if (typeof input !== 'string') return null;
    const trimmed = input.trim();
    if (trimmed.length === 0) return null;
    const key = trimmed.toLowerCase();
    if (SENTINEL_KEYS.has(key)) return null;

    const alias = IANA_TIMEZONE_ALIASES[key];
    const candidate = typeof alias === 'string' && alias.length > 0 ? alias : trimmed;
    const candidateKey = candidate.toLowerCase();

    const index = supportedZoneIndex();
    const fromIntl = index?.get(candidateKey);
    if (fromIntl) {
      // An older ICU may itself return a legacy alias here; fold it through the table as well.
      return CANONICAL_BY_KNOWN_NAME.get(fromIntl.toLowerCase()) ?? fromIntl;
    }

    const known = CANONICAL_BY_KNOWN_NAME.get(candidateKey);
    if (known) return known;

    const gmtOffset = ETC_GMT_OFFSET.exec(candidateKey);
    if (gmtOffset) return `Etc/GMT${gmtOffset[1]}`;

    // Without Intl data we cannot validate, but a stable lowercased key is still better than
    // dropping a legitimate zone. With Intl data, an unknown name is genuinely unresolvable.
    return index === null ? candidateKey : null;
  } catch {
    return null;
  }
}

/**
 * True only when both inputs resolve to the same canonical zone identity. This is a name
 * comparison, never an offset comparison: Singapore and Hong Kong are both UTC+8 but their
 * canonical names differ, so this returns false. Unresolvable inputs are never treated as
 * equivalent (two unknowns must not manufacture a match).
 */
export function timezonesEquivalent(
  a: string | null | undefined,
  b: string | null | undefined,
): boolean {
  const canonicalA = canonicalTimezone(a);
  const canonicalB = canonicalTimezone(b);
  if (canonicalA === null || canonicalB === null) return false;
  return canonicalA.toLowerCase() === canonicalB.toLowerCase();
}

/** Uniform result shape for UI notes, server verdicts and the risk ledger. */
export interface TimezoneMismatchContext {
  mismatch: boolean;
  canonicalBrowser: string | null;
  canonicalIp: string | null;
}

/**
 * Compares a browser-reported timezone with an IP-geolocation timezone through the canonical
 * resolver. `mismatch` is true only when BOTH sides resolved and their canonical names differ;
 * an unresolved side is absence of evidence, not a mismatch. The canonical names are returned so
 * every consumer can display or log the exact same normalised values.
 */
export function timezoneMismatchContext(
  browserTz: string | null | undefined,
  ipTz: string | null | undefined,
): TimezoneMismatchContext {
  const canonicalBrowser = canonicalTimezone(browserTz);
  const canonicalIp = canonicalTimezone(ipTz);
  const mismatch =
    canonicalBrowser !== null &&
    canonicalIp !== null &&
    canonicalBrowser.toLowerCase() !== canonicalIp.toLowerCase();
  return { mismatch, canonicalBrowser, canonicalIp };
}

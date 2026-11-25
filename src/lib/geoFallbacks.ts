/**
 * Fail-safe geolocation & ISP/ASN resolution helpers (Fix 1).
 *
 * Edge platforms (Vercel, Cloudflare) attach geolocation headers to every incoming
 * request. Unlike third-party GeoIP APIs they cannot be rate-limited, so they are the
 * primary source on serverless; external providers are only merged in field by field.
 *
 * This module is intentionally dependency-free so both the Node API bundle
 * (`scripts/build-api.mjs`) and the Cloudflare worker bundle (`scripts/build-worker.mjs`)
 * can import it without pulling in browser or Node-only code.
 */

import type { LocationInfo } from '../types/visitor';
import { countryAnchor, isCoordinateConsistentWithCountry } from './countryGeo';

export type EdgeHeaderBag = Record<string, string | string[] | undefined>;

export type EdgeGeoSource = 'vercel' | 'cloudflare' | 'none' | 'unverified';

export interface EdgeGeoHeaders {
  city: string;
  region: string;
  /** Full country name, e.g. `The Netherlands`. */
  country: string;
  /** ISO-3166 alpha-2 code, e.g. `NL`. */
  countryCode: string;
  timezone: string;
  latitude: number | null;
  longitude: number | null;
  /** Normalised ASN (`AS15169`) or an empty string. */
  asn: string;
  /** ASN owner reported by the edge (`request.cf.asOrganization`). */
  organization: string;
  postalCode: string;
  /**
   * ISO-3166-2 subdivision code from the edge (`request.cf.regionCode`, e.g. `CA`), not the
   * human-readable `region` name. Empty when the edge did not report one.
   */
  regionCode: string;
  /**
   * Raw continent value from the edge: a two-letter code (`NA`) on Vercel or a full name
   * (`North America`) on Cloudflare. Empty when unavailable — never inferred.
   */
  continent: string;
  /**
   * Accuracy radius in kilometres reported alongside the coordinates. Only a real value
   * from the edge/provider is returned; an unavailable value is never replaced with a
   * fabricated constant.
   */
  accuracyRadius: number | null;
  /** Routed BGP prefix (Team Cymru / registry), when supplied by the edge or enrichment. */
  asnNetwork: string;
  /** Cloudflare reports `T1` for requests that arrive over the Tor network. */
  isTorNetwork: boolean;
  /**
   * True ONLY when `x-intel-edge-geo` carried a signature that the caller-supplied verifier
   * accepted. A raw platform header (Vercel / Cloudflare) or an unverified signed header is
   * always false: `trusted` is the single flag downstream code must gate any verification
   * claim (`isIpVerified` / `isLocationVerified`) on.
   */
  trusted: boolean;
  /** `unverified` means a signed header was present but could not be authenticated. */
  source: EdgeGeoSource;
}

const MISSING_TOKENS = new Set([
  '',
  'unknown',
  'unavailable',
  'n/a',
  'na',
  'null',
  'undefined',
  '-',
  'xx',
]);

/** True when a geolocation field carries no usable value. */
export function isMissingGeoValue(value: string | null | undefined): boolean {
  if (typeof value !== 'string') return true;
  return MISSING_TOKENS.has(value.trim().toLowerCase());
}

/**
 * Minimal fallback table for the country codes seen most often. `Intl.DisplayNames`
 * covers every ISO-3166 region when the runtime ships full ICU (Vercel / Node 20 and
 * Cloudflare Workers both do); this table keeps full names available even on a
 * small-icu runtime.
 */
const COUNTRY_NAME_FALLBACK: Record<string, string> = {
  AE: 'United Arab Emirates',
  AR: 'Argentina',
  AT: 'Austria',
  AU: 'Australia',
  BD: 'Bangladesh',
  BE: 'Belgium',
  BG: 'Bulgaria',
  BR: 'Brazil',
  CA: 'Canada',
  CH: 'Switzerland',
  CL: 'Chile',
  CN: 'China',
  CO: 'Colombia',
  CZ: 'Czechia',
  DE: 'Germany',
  DK: 'Denmark',
  EG: 'Egypt',
  ES: 'Spain',
  FI: 'Finland',
  FR: 'France',
  GB: 'United Kingdom',
  GR: 'Greece',
  HK: 'Hong Kong',
  HU: 'Hungary',
  ID: 'Indonesia',
  IE: 'Ireland',
  IL: 'Israel',
  IN: 'India',
  IT: 'Italy',
  JP: 'Japan',
  KE: 'Kenya',
  KR: 'South Korea',
  LK: 'Sri Lanka',
  LT: 'Lithuania',
  LU: 'Luxembourg',
  MY: 'Malaysia',
  MX: 'Mexico',
  NG: 'Nigeria',
  NL: 'The Netherlands',
  NO: 'Norway',
  NP: 'Nepal',
  NZ: 'New Zealand',
  PE: 'Peru',
  PH: 'Philippines',
  PK: 'Pakistan',
  PL: 'Poland',
  PT: 'Portugal',
  RO: 'Romania',
  RU: 'Russia',
  SA: 'Saudi Arabia',
  SE: 'Sweden',
  SG: 'Singapore',
  SK: 'Slovakia',
  TH: 'Thailand',
  TR: 'Turkey',
  TW: 'Taiwan',
  UA: 'Ukraine',
  US: 'United States',
  VN: 'Vietnam',
  ZA: 'South Africa',
};

type RegionDisplayNames = { of: (code: string) => string | undefined };

let cachedRegionDisplayNames: RegionDisplayNames | null | undefined;

function getRegionDisplayNames(): RegionDisplayNames | null {
  if (cachedRegionDisplayNames !== undefined) return cachedRegionDisplayNames;
  try {
    const ctor = (
      Intl as unknown as {
        DisplayNames?: new (
          locales: string[],
          options: { type: 'region' }
        ) => RegionDisplayNames;
      }
    ).DisplayNames;
    cachedRegionDisplayNames = ctor ? new ctor(['en'], { type: 'region' }) : null;
  } catch {
    cachedRegionDisplayNames = null;
  }
  return cachedRegionDisplayNames;
}

/**
 * Turns an ISO-3166 alpha-2 code (or an already-resolved country name) into a full
 * English country name. Returns an empty string for known-missing sentinel codes.
 */
export function countryNameFromCode(raw: string | null | undefined): string {
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  if (!trimmed) return '';
  const upper = trimmed.toUpperCase();
  // `XX` = unknown, `T1` = Tor network (Cloudflare sentinel values).
  if (upper === 'XX' || upper === 'T1') return '';
  if (upper.length !== 2) {
    if (isMissingGeoValue(trimmed)) return '';
    return trimmed;
  }
  const fallback = COUNTRY_NAME_FALLBACK[upper];
  try {
    const display = getRegionDisplayNames();
    const resolved = display?.of(upper);
    if (resolved && resolved !== upper) return resolved;
  } catch {
    // fall through to the static table
  }
  return fallback || upper;
}

function headerValue(headers: EdgeHeaderBag, names: string[]): string {
  for (const name of names) {
    const raw = headers[name] ?? headers[name.toLowerCase()];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function decodeCity(raw: string): string {
  if (!raw) return '';
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** Normalises `15169`, `as15169` and `AS15169` to `AS15169`; invalid input yields ''. */
export function normalizeAsnLabel(raw: string | null | undefined): string {
  if (typeof raw !== 'string') return '';
  const match = raw.trim().match(/^(?:as)?\s*(\d{1,10})$/i);
  return match ? `AS${match[1]}` : '';
}

function parseLat(raw: string): number | null {
  if (!raw) return null;
  const value = Number.parseFloat(raw);
  return Number.isFinite(value) && Math.abs(value) <= 90 ? value : null;
}

function parseLng(raw: string): number | null {
  if (!raw) return null;
  const value = Number.parseFloat(raw);
  return Number.isFinite(value) && Math.abs(value) <= 180 ? value : null;
}

/** Country codes that are sentinels rather than real ISO countries. */
function normalizeCountryCode(raw: string | null | undefined): string {
  if (typeof raw !== 'string') return '';
  const upper = raw.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(upper)) return '';
  if (upper === 'XX' || upper === 'T1') return '';
  return upper;
}

/** ISO continent codes with the English names we can surface without guessing. */
const CONTINENT_NAMES: Record<string, string> = {
  AF: 'Africa',
  AN: 'Antarctica',
  AS: 'Asia',
  EU: 'Europe',
  NA: 'North America',
  OC: 'Oceania',
  SA: 'South America',
};

const CONTINENT_CODES_BY_NAME: Record<string, string> = Object.fromEntries(
  Object.entries(CONTINENT_NAMES).map(([code, name]) => [name.toLowerCase(), code])
);

/**
 * Splits a free-form continent value into an ISO code and a full name. Vercel sends a code
 * (`NA`) while Cloudflare sends a full name (`North America`), so both are accepted. An
 * unrecognised value keeps its reported name but never gains an invented code.
 */
export function parseContinentValue(raw: string | null | undefined): { code: string; name: string } {
  const value = typeof raw === 'string' ? raw.trim() : '';
  if (!value) return { code: '', name: '' };
  const upper = value.toUpperCase();
  if (/^[A-Z]{2}$/.test(upper)) {
    const name = CONTINENT_NAMES[upper] || '';
    return { code: name ? upper : '', name };
  }
  const code = CONTINENT_CODES_BY_NAME[value.toLowerCase()] || '';
  return { code, name: code ? CONTINENT_NAMES[code] : value };
}

/**
 * Parses a real accuracy radius in kilometres. Only finite, non-negative numbers (or their
 * numeric-string equivalents) are accepted; a missing/invalid value stays null instead of
 * becoming a fabricated constant such as `100`.
 */
export function parseAccuracyRadius(raw: unknown): number | null {
  const value =
    typeof raw === 'number'
      ? raw
      : typeof raw === 'string' && raw.trim()
      ? Number(raw)
      : Number.NaN;
  return Number.isFinite(value) && value >= 0 && value < 1_000_000 ? value : null;
}

/** Keeps only a syntactically valid IPv4/IPv6 CIDR label, so no prefix is ever invented. */
export function parseAsnNetwork(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  const value = raw.trim();
  if (!value) return '';
  return /^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^[0-9a-fA-F:.]+\/\d{1,3}$/.test(value) ? value : '';
}

interface EdgeGeoPayload {
  country?: string;
  region?: string;
  regionCode?: string;
  region_code?: string;
  city?: string;
  latitude?: string;
  longitude?: string;
  timezone?: string;
  asn?: string;
  organization?: string;
  postalCode?: string;
  postal_code?: string;
  continent?: string;
  continentCode?: string;
  continent_code?: string;
  /** Real accuracy radius in km, when the edge/enricher actually supplies one. */
  accuracyRadius?: string | number;
  accuracy_radius?: string | number;
  /** Routed BGP prefix (Team Cymru / registry), when supplied. */
  asnNetwork?: string;
  asn_network?: string;
  colo?: string;
}

/**
 * Injection point for the edge header's MAC check. The server owns the secret and the HMAC
 * implementation; this dependency-free module only calls the supplied function.
 *
 * `payload` is the exact JSON text that was signed (the envelope with the signature field
 * removed) and `signature` is the value read from that field. Return a strict boolean.
 * The Worker must sign `JSON.stringify(payload)` BEFORE inserting the signature field, with
 * the same key order, so the reconstruction below reproduces the signed bytes.
 */
export type EdgeGeoVerifier = (payload: string, signature: string) => boolean;

/**
 * Reserved envelope field(s) holding the Worker's HMAC. `sig` is canonical; the aliases are
 * accepted so a deployment that named the field differently still verifies. Whichever field
 * is found is the one removed before the payload text handed to the verifier is rebuilt.
 */
const EDGE_GEO_SIGNATURE_FIELDS = ['sig', 'signature', 'hmac', 'mac'] as const;

export interface VerifiedEdgeGeoPayload {
  /** True only when `verify` accepted the MAC over the reconstructed payload bytes. */
  verified: boolean;
  /**
   * The decoded envelope with the signature field removed. Callers MUST gate all use of this
   * on `verified === true`; on a verification failure it is attacker-controlled data.
   */
  payload: EdgeGeoPayload | null;
}

/**
 * Verifies the `x-intel-edge-geo` envelope without any network I/O or crypto dependency.
 * Parses the URI-encoded JSON, extracts the HMAC field, rebuilds the exact signed payload
 * text, and calls `verify(payload, signature)`. This is pure and NEVER throws on hostile
 * input: malformed encoding, non-object JSON and missing/invalid signatures yield
 * `{ verified: false, payload: null }`; a rejected or throwing verifier yields
 * `{ verified: false, payload: <decoded envelope> }`, which callers MUST ignore.
 */
export function verifyEdgeGeoPayload(
  rawHeader: string,
  verify: EdgeGeoVerifier
): VerifiedEdgeGeoPayload {
  const invalid: VerifiedEdgeGeoPayload = { verified: false, payload: null };
  if (typeof rawHeader !== 'string' || !rawHeader || typeof verify !== 'function') return invalid;

  let envelope: Record<string, unknown>;
  try {
    const decoded = decodeURIComponent(rawHeader);
    const parsed = JSON.parse(decoded) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return invalid;
    envelope = parsed as Record<string, unknown>;
  } catch {
    return invalid;
  }

  let signatureField = '';
  let signature = '';
  for (const name of EDGE_GEO_SIGNATURE_FIELDS) {
    const value = envelope[name];
    if (typeof value === 'string' && value.trim()) {
      signatureField = name;
      signature = value.trim();
      break;
    }
  }
  // No signature field means this header is an unsigned lookalike, not a signed payload.
  if (!signatureField || !signature) return invalid;

  let unsigned: Record<string, unknown>;
  let signedPayloadText: string;
  try {
    unsigned = { ...envelope };
    delete unsigned[signatureField];
    signedPayloadText = JSON.stringify(unsigned);
  } catch {
    return invalid;
  }

  let verified = false;
  try {
    verified = verify(signedPayloadText, signature) === true;
  } catch {
    verified = false;
  }
  return { verified, payload: unsigned as EdgeGeoPayload };
}

/**
 * Decodes the `x-intel-edge-geo` header.
 *
 * SECURITY / BACKWARD COMPATIBILITY WARNING: when `verify` is OMITTED this function only
 * JSON-decodes the header — it performs NO authentication whatsoever. On Node/Vercel ingress
 * any client can set this header, so the unauthenticated form is unsafe for production. It is
 * retained ONLY so legacy callers keep working; new code must pass the verifier (or call
 * `verifyEdgeGeoPayload` directly) and must gate every downstream trust claim on `verified`.
 */
function parseEdgeGeoPayload(raw: string, verify?: EdgeGeoVerifier): EdgeGeoPayload | null {
  if (!raw) return null;
  if (typeof verify === 'function') {
    const result = verifyEdgeGeoPayload(raw, verify);
    return result.verified ? result.payload : null;
  }
  try {
    const decoded = JSON.parse(decodeURIComponent(raw)) as unknown;
    if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) return null;
    return decoded as EdgeGeoPayload;
  } catch {
    return null;
  }
}

function payloadText(payload: EdgeGeoPayload, key: keyof EdgeGeoPayload): string {
  const value = payload[key];
  return typeof value === 'string' ? value.trim() : '';
}

/** First non-empty text among several accepted key spellings (camelCase / snake_case). */
function payloadAnyText(payload: EdgeGeoPayload, keys: (keyof EdgeGeoPayload)[]): string {
  for (const key of keys) {
    const text = payloadText(payload, key);
    if (text) return text;
  }
  return '';
}

function payloadAccuracyRadius(payload: EdgeGeoPayload): number | null {
  return (
    parseAccuracyRadius(payload.accuracyRadius) ?? parseAccuracyRadius(payload.accuracy_radius)
  );
}

/**
 * Result for a `x-intel-edge-geo` header that could not be authenticated. Every value is
 * blanked so neither this module's merge nor a caller's direct reads of `edgeGeo.*` can be
 * influenced by a client-forged country, coordinate, ASN or Tor flag.
 */
function unverifiedEdgeGeo(): EdgeGeoHeaders {
  return {
    city: '',
    region: '',
    country: '',
    countryCode: '',
    timezone: '',
    latitude: null,
    longitude: null,
    asn: '',
    organization: '',
    postalCode: '',
    regionCode: '',
    continent: '',
    accuracyRadius: null,
    asnNetwork: '',
    isTorNetwork: false,
    trusted: false,
    source: 'unverified',
  };
}

/** True when an envelope carries a reserved MAC field. An unsigned Worker payload has none. */
function hasEdgeGeoSignature(payload: EdgeGeoPayload): boolean {
  const record = payload as unknown as Record<string, unknown>;
  return EDGE_GEO_SIGNATURE_FIELDS.some(
    (name) => typeof record[name] === 'string' && String(record[name]).trim().length > 0
  );
}

/**
 * Reads edge geolocation.
 *
 * SECURITY: `x-intel-edge-geo` is normally an UNSIGNED envelope that the Worker builds from
 * `request.cf` (the trust boundary is the Worker stamping the header, not a MAC). A signed
 * envelope is also supported: when a reserved MAC field is present, it is accepted ONLY if the
 * caller-supplied `verify` accepts it; a present-but-failing or unverifiable signature is
 * discarded wholesale (all fields blank, source `unverified`) so no forged value escapes.
 * Unsigned payloads keep the original decode path and all edge fields (country, coordinates,
 * ASN, Tor) with the original `trusted: true, source: 'cloudflare'` result.
 */
export function readEdgeGeoHeaders(
  headers: EdgeHeaderBag,
  verify?: EdgeGeoVerifier
): EdgeGeoHeaders {
  const rawSigned = headerValue(headers, ['x-intel-edge-geo']);
  if (rawSigned) {
    const plainPayload = parseEdgeGeoPayload(rawSigned);
    const signedEnvelope = plainPayload ? hasEdgeGeoSignature(plainPayload) : false;
    // A signature field that cannot be verified fails closed. A normal unsigned Worker
    // payload is parsed the legacy way regardless of whether a verifier was supplied.
    const signedPayload = signedEnvelope
      ? verify
        ? parseEdgeGeoPayload(rawSigned, verify)
        : null
      : plainPayload;
    if (signedEnvelope && !signedPayload) return unverifiedEdgeGeo();
    if (signedPayload) {
      const rawCountry = payloadText(signedPayload, 'country');
      const isTorNetwork = /^t1$/i.test(rawCountry);
      const countryCode = normalizeCountryCode(rawCountry);
      const city = decodeCity(payloadText(signedPayload, 'city'));
      const region = payloadText(signedPayload, 'region');
      const regionCode = payloadAnyText(signedPayload, ['regionCode', 'region_code']);
      const continent = payloadAnyText(signedPayload, [
        'continent',
        'continentCode',
        'continent_code',
      ]);
      const timezone = payloadText(signedPayload, 'timezone');
      const postalCode = payloadAnyText(signedPayload, ['postalCode', 'postal_code']);
      const accuracyRadius = payloadAccuracyRadius(signedPayload);
      const asnNetwork = parseAsnNetwork(
        payloadAnyText(signedPayload, ['asnNetwork', 'asn_network'])
      );
      return {
        city: isMissingGeoValue(city) ? '' : city,
        region: isMissingGeoValue(region) ? '' : region,
        country: countryNameFromCode(countryCode),
        countryCode,
        timezone: isMissingGeoValue(timezone) ? '' : timezone,
        latitude: parseLat(payloadText(signedPayload, 'latitude')),
        longitude: parseLng(payloadText(signedPayload, 'longitude')),
        asn: normalizeAsnLabel(payloadText(signedPayload, 'asn')),
        organization: payloadText(signedPayload, 'organization'),
        postalCode: isMissingGeoValue(postalCode) ? '' : postalCode,
        regionCode: isMissingGeoValue(regionCode) ? '' : regionCode,
        continent: isMissingGeoValue(continent) ? '' : continent,
        accuracyRadius,
        asnNetwork,
        isTorNetwork,
        trusted: true,
        source: 'cloudflare',
      };
    }
    // Malformed / non-object header with no signature: ignore it and fall through to the
    // raw Vercel / Cloudflare headers, exactly as before the signature support existed.
  }

  const vercelCountryCode = headerValue(headers, [
    'x-vercel-ip-country',
    'x-vercel-ip-country-code',
  ]);
  const cloudflareCountryCode = headerValue(headers, ['cf-ipcountry']);
  const rawCountryCode = vercelCountryCode || cloudflareCountryCode;
  const isTorNetwork = /^t1$/i.test(rawCountryCode);
  const countryCode = normalizeCountryCode(rawCountryCode);

  const city = decodeCity(
    headerValue(headers, ['x-vercel-ip-city']) ||
      decodeCity(headerValue(headers, ['cf-ipcity']))
  );
  const region = headerValue(headers, [
    'x-vercel-ip-country-region',
    'cf-region',
    'cf-region-code',
  ]);
  const timezone = headerValue(headers, ['x-vercel-ip-timezone', 'cf-timezone']);
  const latitude = parseLat(headerValue(headers, ['x-vercel-ip-latitude', 'cf-iplatitude']));
  const longitude = parseLng(headerValue(headers, ['x-vercel-ip-longitude', 'cf-iplongitude']));
  const asn = normalizeAsnLabel(
    headerValue(headers, ['x-vercel-ip-as-number', 'x-vercel-ip-asn', 'cf-asn'])
  );
  const organization = headerValue(headers, ['x-vercel-ip-as-organization']);
  const postalCode = headerValue(headers, ['x-vercel-ip-postal-code', 'cf-postal-code']);
  const regionCode = headerValue(headers, [
    'x-vercel-ip-country-region',
    'cf-region-code',
    'cf-regioncode',
    'x-intel-ip-region-code',
  ]);
  const continent = headerValue(headers, [
    'x-vercel-ip-continent',
    'cf-ipcontinent',
    'cf-continent',
    'x-intel-ip-continent',
  ]);
  const accuracyRadius = parseAccuracyRadius(
    headerValue(headers, [
      'x-vercel-ip-accuracy-radius',
      'cf-ipaccuracy-radius',
      'x-intel-ip-accuracy-radius',
    ])
  );
  const asnNetwork = parseAsnNetwork(
    headerValue(headers, [
      'x-vercel-ip-as-network',
      'cf-as-network',
      'cf-asn-network',
      'x-intel-ip-as-network',
    ])
  );

  const source: EdgeGeoSource = headerValue(headers, ['x-vercel-id', 'x-vercel-ip-country'])
    ? 'vercel'
    : headerValue(headers, ['cf-ipcountry', 'cf-ray'])
    ? 'cloudflare'
    : 'none';

  return {
    city: isMissingGeoValue(city) ? '' : city,
    region: isMissingGeoValue(region) ? '' : region,
    country: countryNameFromCode(countryCode),
    countryCode,
    timezone: isMissingGeoValue(timezone) ? '' : timezone,
    latitude,
    longitude,
    asn,
    organization: isMissingGeoValue(organization) ? '' : organization,
    postalCode: isMissingGeoValue(postalCode) ? '' : postalCode,
    regionCode: isMissingGeoValue(regionCode) ? '' : regionCode,
    continent: isMissingGeoValue(continent) ? '' : continent,
    accuracyRadius,
    asnNetwork,
    isTorNetwork,
    trusted: false,
    source,
  };
}

/**
 * Known cloud / AI-provider ASN → owning organisation. Used so an unresolved provider
 * lookup still produces the real operator name (Google LLC, Amazon.com, Inc., …)
 * instead of an anonymous `Unknown ISP` or a false Tor label.
 */
const CLOUD_ASN_ORG: Record<string, string> = {
  AS15169: 'Google LLC',
  AS396982: 'Google Cloud',
  AS19527: 'Google LLC',
  AS16591: 'Google Fiber',
  AS16509: 'Amazon.com, Inc.',
  AS14618: 'Amazon.com, Inc.',
  AS8987: 'Amazon.com, Inc.',
  AS8075: 'Microsoft Corporation',
  AS8068: 'Microsoft Corporation',
  AS20940: 'Akamai Technologies',
  AS63949: 'Akamai / Linode',
  AS13335: 'Cloudflare, Inc.',
  AS132892: 'Cloudflare, Inc.',
  AS14061: 'DigitalOcean, LLC',
  AS24940: 'Hetzner Online GmbH',
  AS16276: 'OVH SAS',
  AS20473: 'Vultr Holdings',
  AS31898: 'Oracle Cloud',
  AS45102: 'Alibaba Cloud',
  AS132203: 'Tencent Cloud',
  AS32934: 'Meta Platforms, Inc.',
  AS714: 'Apple Inc.',
  AS2906: 'Netflix, Inc.',
};

/** Returns the owning cloud organisation for a known ASN, else ''. */
export function cloudProviderOrgForAsn(rawAsn: string | null | undefined): string {
  const asn = normalizeAsnLabel(rawAsn);
  return asn ? CLOUD_ASN_ORG[asn] || '' : '';
}

function meaningful(value: string | null | undefined): value is string {
  return typeof value === 'string' && !isMissingGeoValue(value);
}

/** First non-missing string among the candidates, in trust order. */
function firstMeaningful(...values: (string | null | undefined)[]): string {
  for (const value of values) {
    if (meaningful(value)) return value.trim();
  }
  return '';
}

/**
 * Free geo fields that a provider response or the ASN enrichment layer may carry on a
 * `LocationInfo` even though they are not part of its core contract yet. All optional: a
 * provider that does not report a value simply leaves it null in the merged result.
 */
export interface ProviderGeoExtras {
  continent?: string | null;
  continentCode?: string | null;
  continent_code?: string | null;
  continentName?: string | null;
  continent_name?: string | null;
  postalCode?: string | null;
  postal_code?: string | null;
  postal?: string | null;
  regionCode?: string | null;
  region_code?: string | null;
  subdivisionIso?: string | null;
  subdivision_iso?: string | null;
  accuracyRadius?: number | string | null;
  accuracy_radius?: number | string | null;
  asnNetwork?: string | null;
  asn_network?: string | null;
}

/**
 * `LocationInfo` with the surfaced free edge/provider geo fields. `continent_name` is added
 * here because the canonical `LocationInfo` contract does not declare it yet; the other five
 * follow that contract, where an unavailable string is simply absent.
 */
export type MergedLocationInfo = LocationInfo & {
  continent_name?: string | null;
};

/**
 * Field-level merge of an edge-header geo result onto a provider-resolved location.
 *
 * Trust order follows the evidence: the edge country comes from `request.cf`, which the
 * client cannot forge, so it always wins. Provider city/region/coordinates are only kept
 * when they agree with that country; a coordinate that falls outside the reported country
 * is discarded rather than plotted.
 *
 * A `x-intel-edge-geo` header whose MAC was not verified is reported with source
 * `unverified` and blank fields. Every edge-derived value is ignored in that case — there is
 * no partial merge. Verified Worker payloads and the raw platform-header fallback keep their
 * exact prior merge behavior.
 */
export function mergeLocationWithEdge(
  location: LocationInfo,
  edge: EdgeGeoHeaders
): MergedLocationInfo {
  const extras = location as LocationInfo & ProviderGeoExtras;
  // Verified Worker payloads are `trusted: true`; raw Vercel / Cloudflare fallback headers
  // keep their historical merge role. Only the explicit `unverified` source — a forged or
  // unauthenticated signed header — is discarded in full.
  const edgeUsable = edge.trusted === true || edge.source !== 'unverified';
  const edgeCountryCode = edgeUsable ? normalizeCountryCode(edge.countryCode) : '';
  const edgeCountry = edgeUsable ? edge.country : '';
  const edgeAsn = edgeUsable ? edge.asn : '';
  const edgeOrganization = edgeUsable ? edge.organization : '';
  const edgeLatitude = edgeUsable ? edge.latitude : null;
  const edgeLongitude = edgeUsable ? edge.longitude : null;
  const edgeCity = edgeUsable ? edge.city : '';
  const edgeRegion = edgeUsable ? edge.region : '';
  const edgeTimezone = edgeUsable ? edge.timezone : '';
  const edgeContinent = edgeUsable ? edge.continent : '';
  const edgeRegionCode = edgeUsable ? edge.regionCode : '';
  const edgePostalCode = edgeUsable ? edge.postalCode : '';
  const edgeAccuracyRadius = edgeUsable ? edge.accuracyRadius : null;
  const edgeAsnNetwork = edgeUsable ? edge.asnNetwork : '';
  const edgeIsTorNetwork = edgeUsable && edge.isTorNetwork;

  const providerCountryCode = normalizeCountryCode(location.countryCode);
  const countryCode = edgeCountryCode || providerCountryCode;

  const providerCountryAgrees =
    !edgeCountryCode || !providerCountryCode || edgeCountryCode === providerCountryCode;

  const country =
    countryNameFromCode(countryCode) ||
    (providerCountryAgrees && meaningful(location.country) ? location.country : '') ||
    edgeCountry ||
    countryNameFromCode(location.country) ||
    'Unknown';

  const asn = edgeAsn || normalizeAsnLabel(location.asn);
  const edgeOrg = meaningful(edgeOrganization)
    ? edgeOrganization
    : cloudProviderOrgForAsn(edgeAsn);
  const providerIspUsable = providerCountryAgrees && meaningful(location.isp);
  const isp = providerIspUsable
    ? location.isp
    : edgeOrg ||
      (meaningful(location.org)
        ? location.org
        : meaningful(location.isp)
        ? location.isp
        : asn
        ? `Autonomous System ${asn}`
        : 'Unknown');
  const org = meaningful(location.org) && providerCountryAgrees
    ? location.org
    : edgeOrg || isp;

  const providerHasCoords =
    providerCountryAgrees &&
    typeof location.latitude === 'number' &&
    typeof location.longitude === 'number';
  let latitude = providerHasCoords ? location.latitude : null;
  let longitude = providerHasCoords ? location.longitude : null;

  const providerCoordsUsable =
    latitude !== null &&
    longitude !== null &&
    (!countryCode || isCoordinateConsistentWithCountry(latitude, longitude, countryCode));
  if (!providerCoordsUsable) {
    latitude = null;
    longitude = null;
  }

  // Edge coordinates are applied only when the edge evidence is usable: a verified Worker
  // payload or the historical raw-platform fallback. Forged signed headers are blanked by
  // readEdgeGeoHeaders() and excluded by `edgeUsable` above, so nothing partially merges.
  if (
    latitude === null &&
    edgeLatitude !== null &&
    edgeLongitude !== null &&
    (!countryCode || isCoordinateConsistentWithCountry(edgeLatitude, edgeLongitude, countryCode))
  ) {
    latitude = edgeLatitude;
    longitude = edgeLongitude;
  }

  // A city is only as trustworthy as the country and coordinates it arrived with. When the
  // provider's own coordinate falls outside its own country (the classic stale-record bug),
  // the city goes with it instead of being plotted or labelled in the wrong country.
  const providerLocationTrusted =
    providerCountryAgrees &&
    (!providerHasCoords || providerCoordsUsable) &&
    (!edgeCountryCode || Boolean(providerCountryCode) || providerCoordsUsable);

  const city = providerLocationTrusted && meaningful(location.city)
    ? location.city
    : edgeCity || 'Unknown';
  const region = providerLocationTrusted && meaningful(location.region)
    ? location.region
    : edgeRegion || 'Unknown';
  const timezone = meaningful(location.timezone)
    ? location.timezone
    : edgeTimezone || undefined;

  /*
   * Additional free fields are merged individually, with the same evidence rule as above:
   * the edge answer (from `request.cf`) is authoritative because a client cannot forge it,
   * while any provider value is only accepted when its country agrees with that edge country.
   * Unavailable values stay null — no code, continent, prefix or radius is ever invented.
   */
  const edgeContinentParsed = parseContinentValue(edgeContinent);
  const providerContinent = providerCountryAgrees
    ? parseContinentValue(
        firstMeaningful(
          extras.continentCode,
          extras.continent_code,
          extras.continentName,
          extras.continent_name,
          extras.continent
        )
      )
    : { code: '', name: '' };
  const continentCode = edgeContinentParsed.code || providerContinent.code;
  const continentName = edgeContinentParsed.name || providerContinent.name;

  // The edge subdivision is a real ISO-3166-2 code; a provider code is only a fallback.
  const providerSubdivision = providerCountryAgrees
    ? firstMeaningful(
        extras.subdivisionIso,
        extras.subdivision_iso,
        extras.regionCode,
        extras.region_code
      )
    : '';
  const subdivisionIso = firstMeaningful(edgeRegionCode, providerSubdivision) || null;

  const providerPostal = providerCountryAgrees
    ? firstMeaningful(extras.postalCode, extras.postal_code, extras.postal)
    : '';
  const postalCode = firstMeaningful(edgePostalCode, providerPostal) || null;

  // A radius is only surfaced when an actual value was reported (never a constant fallback).
  // A provider value is trusted only alongside an agreeing country; edge values are already
  // validated by readEdgeGeoHeaders()/parseAccuracyRadius().
  const accuracyRadius =
    (providerCountryAgrees
      ? parseAccuracyRadius(extras.accuracyRadius ?? extras.accuracy_radius)
      : null) ?? edgeAccuracyRadius ?? null;

  // The routed prefix is a BGP fact (registry / Team Cymru), independent of the country
  // claim. Prefer a validated enrichment prefix, then one on the signed edge payload.
  const asnNetwork =
    parseAsnNetwork(firstMeaningful(extras.asnNetwork, extras.asn_network)) ||
    parseAsnNetwork(edgeAsnNetwork) ||
    null;

  const locationPrecision =
    meaningful(city) && !isMissingGeoValue(city)
      ? 'city'
      : meaningful(region) && !isMissingGeoValue(region)
      ? 'region'
      : countryCode
      ? 'country'
      : 'unknown';

  const hasCountry = Boolean(countryCode) || (meaningful(country) && country !== 'Unknown');

  return {
    ...location,
    city,
    region,
    country,
    countryCode: countryCode.toUpperCase(),
    latitude,
    longitude,
    timezone,
    isp,
    org,
    asn,
    isTor: Boolean(location.isTor) || edgeIsTorNetwork,
    isTorExit: Boolean(location.isTorExit) || edgeIsTorNetwork,
    locationSource: edgeCountryCode ? 'edge' : location.locationSource ?? 'provider',
    locationPrecision,
    isLocationVerified: hasCountry,
    continent_code: continentCode || undefined,
    continent_name: continentName || undefined,
    postal_code: postalCode || undefined,
    subdivision_iso: subdivisionIso || undefined,
    accuracy_radius: accuracyRadius,
    asn_network: asnNetwork || undefined,
  };
}

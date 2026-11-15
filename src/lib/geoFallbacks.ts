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

export type EdgeHeaderBag = Record<string, string | string[] | undefined>;

export type EdgeGeoSource = 'vercel' | 'cloudflare' | 'none';

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
  postalCode: string;
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

function parseCoord(raw: string): number | null {
  if (!raw) return null;
  const value = Number.parseFloat(raw);
  return Number.isFinite(value) && Math.abs(value) <= 180 ? value : null;
}

/** Normalises `15169`, `as15169` and `AS15169` to `AS15169`; invalid input yields ''. */
export function normalizeAsnLabel(raw: string | null | undefined): string {
  if (typeof raw !== 'string') return '';
  const match = raw.trim().match(/^(?:as)?\s*(\d{1,10})$/i);
  return match ? `AS${match[1]}` : '';
}

/**
 * Reads Vercel (`x-vercel-ip-*`) and Cloudflare (`cf-*`) edge geolocation headers.
 * Vercel wins when both are present because it also exposes the ASN.
 */
export function readEdgeGeoHeaders(headers: EdgeHeaderBag): EdgeGeoHeaders {
  const vercelCountryCode = headerValue(headers, [
    'x-vercel-ip-country',
    'x-vercel-ip-country-code',
  ]);
  const cloudflareCountryCode = headerValue(headers, ['cf-ipcountry']);
  const rawCountryCode = vercelCountryCode || cloudflareCountryCode;
  const countryCode =
    rawCountryCode && !/^(xx|t1)$/i.test(rawCountryCode)
      ? rawCountryCode.toUpperCase()
      : '';

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
  const latitude = parseCoord(headerValue(headers, ['x-vercel-ip-latitude', 'cf-iplatitude']));
  const longitude = parseCoord(
    headerValue(headers, ['x-vercel-ip-longitude', 'cf-iplongitude'])
  );
  const asn = normalizeAsnLabel(
    headerValue(headers, ['x-vercel-ip-as-number', 'x-vercel-ip-asn', 'cf-asn'])
  );
  const postalCode = headerValue(headers, ['x-vercel-ip-postal-code', 'cf-postal-code']);

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
    postalCode: isMissingGeoValue(postalCode) ? '' : postalCode,
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

/**
 * Field-level merge of an edge-header geo result onto a provider-resolved location.
 * Edge fields only fill gaps, so a provider that answers with a city or ASN always
 * wins, while a provider timeout still leaves the edge values intact.
 */
export function mergeLocationWithEdge(
  location: LocationInfo,
  edge: EdgeGeoHeaders
): LocationInfo {
  const countryCodeRaw = meaningful(location.countryCode)
    ? location.countryCode
    : edge.countryCode;
  const providerCountry =
    meaningful(location.country) && !/^[a-z]{2}$/i.test(location.country)
      ? location.country
      : '';
  const country =
    providerCountry ||
    countryNameFromCode(countryCodeRaw) ||
    countryNameFromCode(location.country) ||
    edge.country ||
    'Unknown';

  const asn = normalizeAsnLabel(location.asn) || edge.asn;
  const edgeOrg = cloudProviderOrgForAsn(edge.asn);
  const isp = meaningful(location.isp)
    ? location.isp
    : meaningful(location.org)
    ? location.org
    : edgeOrg || (asn ? `Autonomous System ${asn}` : 'Unknown');
  const org = meaningful(location.org) ? location.org : edgeOrg || isp;

  const latitude = location.latitude !== null ? location.latitude : edge.latitude;
  const longitude = location.longitude !== null ? location.longitude : edge.longitude;
  const city = meaningful(location.city) ? location.city : edge.city || 'Unknown';
  const region = meaningful(location.region) ? location.region : edge.region || 'Unknown';
  const timezone = meaningful(location.timezone)
    ? location.timezone
    : edge.timezone || undefined;

  return {
    ...location,
    city,
    region,
    country,
    countryCode: countryCodeRaw.toUpperCase(),
    latitude,
    longitude,
    timezone,
    isp,
    org,
    asn,
    isLocationVerified:
      location.isLocationVerified ||
      Boolean(edge.city || edge.countryCode || latitude !== null),
  };
}

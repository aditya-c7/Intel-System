/**
 * Zero-cost 4-tier network / ASN enrichment.
 *
 * Resolution order (first tier that answers wins):
 *   1. Edge headers — Cloudflare/Vercel already know the ASN + organization for free.
 *   2. Bundled Tier-2 registry (`asnRegistry.json`) — matched by ASN number and by
 *      longest-prefix IPv4 containment against curated sample prefixes, backed by an
 *      in-memory LRU (7-day TTL for ASN metadata).
 *   3. Team Cymru over DNS TXT (`origin.asn.cymru.com`, `AS<asn>.asn.cymru.com`) via
 *      `node:dns/promises` `resolveTxt` with a 1.5 s budget. When the runtime has no
 *      DNS (Workers, restricted sandboxes) the same queries fall back to
 *      DNS-over-HTTPS with the same budget.
 *   4. `cleanCymruAsName` normalisation of whatever Cymru returned.
 *
 * The resolver NEVER throws and NEVER fabricates a placeholder name such as
 * 'Standard Network' — when nothing is known it returns empty strings with
 * `source: 'none'` so callers can degrade to `AS<number>`.
 *
 * Caches (module-level LRU, max 500 entries): 7 days for ASN metadata, 24 hours for
 * prefix/IP lookups, 30 seconds for negative results. All expiry is lazy (checked on
 * read) so no timers are required in ephemeral runtimes.
 */

import registryJson from './asnRegistry.json';

/* -------------------------------------------------------------------------- */
/* Types                                                                       */
/* -------------------------------------------------------------------------- */

export type AsnType = 'isp' | 'mobile' | 'datacenter' | 'cloud' | 'cdn' | 'ai_operator';

export interface AsnRegistryEntry {
  asn: number;
  asn_name: string;
  handle: string;
  asn_type: AsnType;
  datacenter_result: boolean;
  sample_prefixes: string[];
}

export interface EnrichedNetwork {
  /** Digits only ('15169') or '' when unknown. */
  asn: string;
  asn_name: string;
  /** BGP prefix / network label when one is known ('8.8.8.0/24'), else ''. */
  asn_network: string;
  asn_type: AsnType;
  datacenter_result: boolean;
  source: 'edge' | 'registry' | 'cymru' | 'none';
}

export interface EdgeNetworkHints {
  asn?: number | null;
  asOrganization?: string;
  country?: string;
}

export type NetworkCategory =
  | 'Residential Broadband'
  | 'Mobile Carrier'
  | 'Cloud / Datacenter'
  | 'AI Agent Cloud Network'
  | 'Standard Network';

/* -------------------------------------------------------------------------- */
/* Bundled registry                                                            */
/* -------------------------------------------------------------------------- */

const REGISTRY = registryJson as unknown as AsnRegistryEntry[];

const REGISTRY_BY_ASN = new Map<number, AsnRegistryEntry>();
for (const entry of REGISTRY) REGISTRY_BY_ASN.set(entry.asn, entry);

interface PrefixRange {
  first: number;
  last: number;
  prefix: string;
  prefixLength: number;
  entry: AsnRegistryEntry;
}

/** IPv4 sample prefixes, sorted longest-prefix first so containment checks win correctly. */
const REGISTRY_PREFIXES: PrefixRange[] = (() => {
  const ranges: PrefixRange[] = [];
  for (const entry of REGISTRY) {
    for (const prefix of entry.sample_prefixes ?? []) {
      const parsed = parseIpv4Prefix(prefix);
      if (parsed) ranges.push({ ...parsed, prefix, entry });
    }
  }
  ranges.sort((a, b) => b.prefixLength - a.prefixLength);
  return ranges;
})();

function parseIpv4(text: string): number | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text.trim());
  if (!match) return null;
  const octets = [match[1], match[2], match[3], match[4]].map((part) => Number.parseInt(part, 10));
  if (octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return null;
  return (((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0);
}

function parseIpv4Prefix(prefix: string): { first: number; last: number; prefixLength: number } | null {
  const [addressPart, lengthPart] = prefix.split('/');
  const base = parseIpv4(addressPart ?? '');
  const prefixLength = Number.parseInt(lengthPart ?? '', 10);
  if (base === null || !Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 32) return null;
  const mask = prefixLength === 0 ? 0 : (0xFFFFFFFF << (32 - prefixLength)) >>> 0;
  const first = (base & mask) >>> 0;
  const last = (first | (mask ^ 0xFFFFFFFF)) >>> 0;
  return { first, last, prefixLength };
}

function ipv4InRanges(ip: string): PrefixRange | null {
  const value = parseIpv4(ip);
  if (value === null) return null;
  for (const range of REGISTRY_PREFIXES) {
    if (value >= range.first && value <= range.last) return range;
  }
  return null;
}

/** Curated registry entry for an ASN number, or null. */
export function registryEntryForAsn(asn: number | string | null | undefined): AsnRegistryEntry | null {
  const value = typeof asn === 'number' ? asn : Number.parseInt(String(asn ?? '').replace(/^\s*as/i, ''), 10);
  if (!Number.isInteger(value) || value <= 0) return null;
  return REGISTRY_BY_ASN.get(value) ?? null;
}

/** Longest-prefix registry match for an IPv4 address (IPv6 sample prefixes are not bundled). */
export function registryEntryForIp(ip: string): { entry: AsnRegistryEntry; prefix: string } | null {
  const match = ipv4InRanges(ip);
  return match ? { entry: match.entry, prefix: match.prefix } : null;
}

/* -------------------------------------------------------------------------- */
/* LRU cache (max 500, lazy TTL)                                               */
/* -------------------------------------------------------------------------- */

type CachedValue = EnrichedNetwork | AsnOrganization | string | null;

interface CacheSlot {
  value: CachedValue;
  expiresAt: number;
}

const CACHE_LIMIT = 500;
const ASN_META_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days for ASN metadata
const IP_LOOKUP_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours for prefix/IP lookups
const NEGATIVE_TTL_MS = 30 * 1000; // 30-second negative cache

const CACHE = new Map<string, CacheSlot>();

function cacheGet(key: string): CachedValue | undefined {
  const slot = CACHE.get(key);
  if (!slot) return undefined;
  if (slot.expiresAt <= Date.now()) {
    CACHE.delete(key);
    return undefined;
  }
  // Refresh LRU ordering on hit.
  CACHE.delete(key);
  CACHE.set(key, slot);
  return slot.value;
}

function cacheSet(key: string, value: CachedValue, ttlMs: number): void {
  CACHE.delete(key);
  CACHE.set(key, { value, expiresAt: Date.now() + ttlMs });
  while (CACHE.size > CACHE_LIMIT) {
    const oldest = CACHE.keys().next();
    if (oldest.done) break;
    CACHE.delete(oldest.value);
  }
}

/** Test/wiring helper: drops every cached lookup. */
export function clearNetworkCache(): void {
  CACHE.clear();
}

/* -------------------------------------------------------------------------- */
/* Tier 4 — AS-name normalisation                                              */
/* -------------------------------------------------------------------------- */

/**
 * Cleans a raw Team Cymru AS-name: strips a trailing ', XX' two-letter country,
 * strips a leading 'HANDLE - ' prefix when the handle is ALL-CAPS/dashed, and
 * collapses whitespace. Example: `GOOGLE - Google, Inc., US` → `Google, Inc.`
 */
export function cleanCymruAsName(raw: string | null | undefined): string {
  let name = String(raw ?? '');
  name = name.replace(/^"+|"+$/g, '').trim();
  // Trailing ', XX' country suffix (also tolerate the registry date coming through).
  name = name.replace(/,\s*[A-Za-z]{2}\s*$/, '');
  // Leading registry handle when it is ALL-CAPS / dashed: 'GOOGLE - Google, Inc.'
  name = name.replace(/^[A-Z0-9][A-Z0-9-]{0,40}\s+-\s+/, (match, offset: number, text: string) => {
    const remainder = text.slice(offset + match.length);
    return remainder.trim() ? '' : match;
  });
  if (!name.trim()) name = String(raw ?? '').replace(/^"+|"+$/g, '').trim();
  return name.replace(/\s+/g, ' ').trim();
}

/** Strips the leading `AS13335 ` token from Cloudflare-style `asOrganization` strings. */
function cleanEdgeAsOrg(raw: string | null | undefined): string {
  return String(raw ?? '')
    .replace(/^[Aa][Ss]\d+\s+/, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/* -------------------------------------------------------------------------- */
/* Best-effort heuristics                                                      */
/* -------------------------------------------------------------------------- */

const HOSTING_NAME_HINTS = [
  'amazon web services',
  'aws',
  'azure',
  'google cloud',
  'oracle cloud',
  'alibaba cloud',
  'tencent cloud',
  'digitalocean',
  'linode',
  'vultr',
  'hetzner',
  'ovh',
  'contabo',
  'm247',
  'leaseweb',
  'scaleway',
  'cloudflare',
  'akamai',
  'fastly',
  'datacenter',
  'data center',
  'hosting',
  'colocation',
  'vps',
  'anthropic',
  'openai',
  'mistral',
  'bytedance',
];

const MOBILE_NAME_HINTS = [
  'airtel',
  'jio',
  'vodafone',
  'idea cellular',
  'verizon',
  't-mobile',
  'tmobile',
  'at&t',
  'sprint',
  'boost mobile',
  'metro',
  'mint mobile',
  'google fi',
  'o2 uk',
  'orange',
  'movistar',
  'telcel',
  'safaricom',
  'docomo',
  'softbank',
  'kddi',
  'sk telecom',
  'cellular',
  'mobile',
];

function heuristicAsnType(name: string): { type: AsnType; datacenter: boolean } {
  const text = String(name ?? '').toLowerCase();
  if (!text) return { type: 'isp', datacenter: false };
  if (HOSTING_NAME_HINTS.some((hint) => text.includes(hint))) return { type: 'datacenter', datacenter: true };
  if (MOBILE_NAME_HINTS.some((hint) => text.includes(hint))) return { type: 'mobile', datacenter: false };
  return { type: 'isp', datacenter: false };
}

/**
 * Best-effort human category for a network. Only returns 'Standard Network' when
 * nothing at all is known about the AS type (the neutral bucket of `NetworkType`).
 */
export function classifyNetwork(
  asnType: string | null | undefined,
  datacenterResult: boolean | null | undefined,
  orgName: string | null | undefined
): NetworkCategory {
  const type = String(asnType ?? '').toLowerCase();
  const org = String(orgName ?? '');
  if (type === 'ai_operator') return 'AI Agent Cloud Network';
  if (type === 'datacenter' || type === 'cloud' || type === 'cdn') return 'Cloud / Datacenter';
  if (type === 'mobile') return 'Mobile Carrier';
  if (type === 'isp') {
    if (datacenterResult === true) return 'Cloud / Datacenter';
    if (MOBILE_NAME_HINTS.some((hint) => org.toLowerCase().includes(hint))) return 'Mobile Carrier';
    return 'Residential Broadband';
  }
  if (!type) {
    // Unknown AS type — fall back on the org-name heuristics, else the neutral label.
    const heuristic = heuristicAsnType(org);
    if (heuristic.datacenter) return 'Cloud / Datacenter';
    if (heuristic.type === 'mobile') return 'Mobile Carrier';
  }
  return 'Standard Network';
}

/** a.b.c/24 bucket for IPv4 ('2600:1700:…' IPv6 → first 4 hextets + '::/64'). */
export function subnetOf(ip: string): string {
  const text = String(ip ?? '').trim();
  const ipv4 = parseIpv4(text);
  if (ipv4 !== null) {
    const octets = [
      (ipv4 >>> 24) & 0xff,
      (ipv4 >>> 16) & 0xff,
      (ipv4 >>> 8) & 0xff,
      ipv4 & 0xff,
    ];
    return `${octets[0]}.${octets[1]}.${octets[2]}/24`;
  }
  const groups = expandIpv6Groups(text);
  if (!groups) return '';
  const firstFour = groups.slice(0, 4).map((value) => value.toString(16)).join(':');
  return `${firstFour}::/64`;
}

/* -------------------------------------------------------------------------- */
/* IPv4 / IPv6 helpers (pure string maths, no node:dns)                         */
/* -------------------------------------------------------------------------- */

function ipv4ReverseOctets(ip: string): string[] {
  const value = parseIpv4(ip);
  if (value === null) return [];
  return [
    String((value >>> 24) & 0xff),
    String((value >>> 16) & 0xff),
    String((value >>> 8) & 0xff),
    String(value & 0xff),
  ].reverse();
}

/** Expands an IPv6 literal to 8 16-bit groups, handling '::' and IPv4-mapped tails. */
function expandIpv6Groups(ip: string): number[] | null {
  const text = String(ip ?? '').trim().toLowerCase();
  if (!text || !text.includes(':') || !/^[0-9a-f:.]+$/.test(text)) return null;
  if (text.includes('%')) return null; // zone indices are not supported

  const halves = text.split('::');
  if (halves.length > 2) return null;
  let head = halves[0] ? halves[0].split(':') : [];
  let tail = halves[1] ? halves[1].split(':') : [];

  const unfoldIpv4Tail = (tokens: string[]): string[] => {
    const last = tokens[tokens.length - 1] ?? '';
    if (!last.includes('.')) return tokens;
    const parts = last.split('.');
    if (parts.length !== 4) return [];
    const values = parts.map((part) => Number.parseInt(part, 10));
    if (values.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return [];
    return tokens.slice(0, -1).concat([(values[0] << 8) | values[1], (values[2] << 8) | values[3]].map((v) => v.toString(16)));
  };
  head = unfoldIpv4Tail(head);
  tail = unfoldIpv4Tail(tail);
  if (head.length === 0 && halves[0]) return null;
  if (tail.length === 0 && halves[1]) return null;

  const fill = 8 - head.length - tail.length;
  if (fill < 0) return null;
  if (halves.length === 1 && fill !== 0) return null;

  const groups = halves.length === 2
    ? [...head, ...new Array<string>(fill).fill('0'), ...tail]
    : [...head, ...tail];
  if (groups.length !== 8) return null;

  const values: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    values.push(Number.parseInt(group, 16));
  }
  return values;
}

/** Reversed nibble string list for `<nibbles>.origin6.asn.cymru.com`. */
function ipv6ReverseNibbles(ip: string): string[] {
  const groups = expandIpv6Groups(ip);
  if (!groups) return [];
  const nibbles: string[] = [];
  for (const value of groups) {
    for (const shift of [12, 8, 4, 0]) nibbles.push(((value >> shift) & 0xf).toString(16));
  }
  return nibbles.reverse();
}

/* -------------------------------------------------------------------------- */
/* Tier 3 — Team Cymru over DNS TXT (node:dns, DoH fallback)                   */
/* -------------------------------------------------------------------------- */

const CYMRU_TIMEOUT_MS = 1500;
const DOH_ENDPOINTS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];

/** Races a promise against a fixed budget; the timeout resolves to the fallback. */
function withBudget<T>(task: Promise<T>, fallback: T, ms: number): Promise<T> {
  return new Promise<T>((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve(fallback);
    }, ms);
    task.then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(fallback);
      }
    );
  });
}

/**
 * Team Cymru TXT lookup through the system resolver. `node:dns/promises` is imported
 * lazily so the module stays importable in runtimes without it; a failure (no DNS,
 * blocked UDP, NXDOMAIN) resolves to an empty list and the DoH tier takes over.
 */
async function dnsTxtRecords(name: string): Promise<string[]> {
  try {
    const dns = await import('node:dns/promises');
    if (!dns || typeof dns.resolveTxt !== 'function') return [];
    const lookup = dns.resolveTxt(name).then((records) =>
      records.map((chunks) => chunks.join('')),
    );
    const records = await withBudget<string[]>(lookup, [], CYMRU_TIMEOUT_MS);
    return records.filter((record) => typeof record === 'string' && record.length > 0);
  } catch {
    return [];
  }
}

/** Tier 3 transport: DNS first, DNS-over-HTTPS as the portable fallback. */
async function cymruTextRecords(name: string): Promise<string[]> {
  const fromDns = await dnsTxtRecords(name);
  if (fromDns.length > 0) return fromDns;
  return dohTextRecords(name);
}

interface DohAnswer {
  type?: number;
  data?: string;
}

async function dohTextRecords(name: string): Promise<string[]> {
  if (typeof fetch !== 'function') return [];
  const signal =
    typeof AbortSignal !== 'undefined' && typeof (AbortSignal as { timeout?: unknown }).timeout === 'function'
      ? (AbortSignal as { timeout(ms: number): AbortSignal }).timeout(CYMRU_TIMEOUT_MS)
      : undefined;
  for (const endpoint of DOH_ENDPOINTS) {
    try {
      const response = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=TXT`, {
        headers: { accept: 'application/dns-json' },
        signal,
      });
      if (!response.ok) continue;
      const payload = (await response.json()) as { Answer?: DohAnswer[] };
      const answers = Array.isArray(payload?.Answer) ? payload.Answer : [];
      const records = answers
        .filter((answer) => typeof answer?.data === 'string' && answer.data.length > 0)
        .map((answer) => answer.data as string);
      if (records.length) return records;
    } catch {
      // Try the next public resolver; total failure degrades silently.
    }
  }
  return [];
}

function firstCymruRecord(raw: string): string {
  // DNS-JSON wraps TXT payloads in quotes; multi-string records are quote-separated.
  return String(raw ?? '')
    .replace(/^"+|"+$/g, '')
    .split(/"\s*"/)[0] ?? '';
}

const CYMRU_DATE_FIELD = /^\d{4}-\d{2}-\d{2}$/;
const CYMRU_REGISTRY_FIELD = /^(?:apnic|arin|ripe|ripe-ncc|afrinic|lacnic|iana|arin-.*)$/i;

/**
 * Picks the AS-name field from a Cymru pipe-delimited record. The documented 5th
 * field is preferred; real records often append the allocated date and the name after
 * it, so a trailing field that contains letters and is not a date/registry token is
 * accepted as well.
 */
function pickCymruAsName(fields: string[]): string {
  const candidates = [fields[4], fields[5], fields[fields.length - 1]]
    .map((value) => String(value ?? '').trim())
    .filter((value) => value.length > 0);
  for (const candidate of candidates) {
    if (/[A-Za-z]/.test(candidate) && !CYMRU_DATE_FIELD.test(candidate) && !CYMRU_REGISTRY_FIELD.test(candidate)) {
      return candidate;
    }
  }
  return '';
}

function parseCymruOriginLine(raw: string): { asn: number; network: string; cc: string } | null {
  const fields = firstCymruRecord(raw)
    .split('|')
    .map((field) => field.trim());
  const asn = Number.parseInt(fields[0] ?? '', 10);
  if (!Number.isInteger(asn) || asn <= 0 || asn > 4294967295) return null;
  return { asn, network: fields[1] ?? '', cc: (fields[2] ?? '').toUpperCase().slice(0, 2) };
}

async function lookupCymruByIp(ip: string): Promise<{ asn: number; network: string; cc: string } | null> {
  const text = String(ip ?? '').trim();
  if (!text) return null;
  const name = text.includes(':')
    ? `${ipv6ReverseNibbles(text).join('.')}.origin6.asn.cymru.com`
    : `${ipv4ReverseOctets(text).join('.')}.origin.asn.cymru.com`;
  if (name.startsWith('.origin') || name.endsWith('.origin') || name.startsWith('.') || name.endsWith('.')) return null;
  for (const record of await cymruTextRecords(name)) {
    const parsed = parseCymruOriginLine(record);
    if (parsed) return parsed;
  }
  return null;
}

async function lookupCymruAsName(asn: number): Promise<string | null> {
  const key = `asname:${asn}`;
  const cached = cacheGet(key);
  if (cached !== undefined) return typeof cached === 'string' ? cached : null;
  for (const record of await cymruTextRecords(`AS${asn}.asn.cymru.com`)) {
    const fields = firstCymruRecord(record)
      .split('|')
      .map((field) => field.trim());
    // '<AS> | <prefixes> | <cc> | <registry> | <date> | <AS name>' — the name is the
    // documented 5th field, with a trailing name accepted for real-world records.
    const rawName = pickCymruAsName(fields);
    if (rawName) {
      cacheSet(key, rawName, ASN_META_TTL_MS);
      return rawName;
    }
  }
  cacheSet(key, null, NEGATIVE_TTL_MS);
  return null;
}

/* -------------------------------------------------------------------------- */
/* The 4-tier resolver                                                         */
/* -------------------------------------------------------------------------- */

const EMPTY_NETWORK = (): EnrichedNetwork => ({
  asn: '',
  asn_name: '',
  asn_network: '',
  asn_type: 'isp',
  datacenter_result: false,
  source: 'none',
});

function cloneResult(result: EnrichedNetwork): EnrichedNetwork {
  return { ...result };
}

function toAsnNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isInteger(value) && value > 0 && value <= 4294967295) return value;
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value.replace(/^\s*[Aa][Ss]/, '').trim(), 10);
    if (Number.isInteger(parsed) && parsed > 0 && parsed <= 4294967295) return parsed;
  }
  return null;
}

export interface AsnOrganization {
  /** Digits only ('55836') or '' when the input was not a number. */
  asn: string;
  asn_name: string;
  asn_type: AsnType;
  datacenter_result: boolean;
  source: 'registry' | 'cymru' | 'none';
}

/**
 * Resolves only the organisation behind an AS number. Used when the network path
 * already knows the numeric ASN (edge header, provider cascade, client hint) but not
 * the operator name. Registry first, Team Cymru second, empty result last — the
 * caller decides how to label an unresolved network (`AS<number>`, never
 * 'Standard Network').
 */
export async function resolveAsnOrganization(
  asn: number | string | null | undefined
): Promise<AsnOrganization> {
  const number = toAsnNumber(asn);
  const empty: AsnOrganization = {
    asn: number === null ? '' : String(number),
    asn_name: '',
    asn_type: 'isp',
    datacenter_result: false,
    source: 'none',
  };
  if (number === null) return empty;

  const cacheKey = `asnorg:${number}`;
  const cached = cacheGet(cacheKey);
  if (cached !== undefined && typeof cached === 'object' && cached !== null) {
    return { ...(cached as AsnOrganization) };
  }

  const entry = registryEntryForAsn(number);
  if (entry) {
    const result: AsnOrganization = {
      asn: String(number),
      asn_name: entry.asn_name,
      asn_type: entry.asn_type,
      datacenter_result: entry.datacenter_result,
      source: 'registry',
    };
    cacheSet(cacheKey, result, ASN_META_TTL_MS);
    return result;
  }

  try {
    const rawName = await lookupCymruAsName(number);
    if (rawName) {
      const name = cleanCymruAsName(rawName);
      if (name) {
        const heuristic = heuristicAsnType(name);
        const result: AsnOrganization = {
          asn: String(number),
          asn_name: name,
          asn_type: heuristic.type,
          datacenter_result: heuristic.datacenter,
          source: 'cymru',
        };
        cacheSet(cacheKey, result, ASN_META_TTL_MS);
        return result;
      }
    }
  } catch {
    // Degrade to the numeric label below.
  }

  cacheSet(cacheKey, empty, NEGATIVE_TTL_MS);
  return empty;
}

/**
 * Zero-cost network enrichment. Never throws; the empty result (`source: 'none'`)
 * is the terminal fallback — a placeholder name is never fabricated.
 */
export async function enrichNetwork(
  ip: string,
  edge: EdgeNetworkHints = {}
): Promise<EnrichedNetwork> {
  try {
    const ipClean = String(ip ?? '').trim();
    const cacheKey = `ip:${ipClean}`;
    const cached = cacheGet(cacheKey);
    if (cached !== undefined && typeof cached === 'object' && cached !== null) {
      return cloneResult(cached as EnrichedNetwork);
    }

    const edgeAsn = toAsnNumber(edge?.asn);
    const edgeOrg = String(edge?.asOrganization ?? '').trim();

    // Tier 1 — edge headers: ASN + organization are already known for free.
    if (edgeAsn && edgeOrg) {
      const entry = registryEntryForAsn(edgeAsn);
      const heuristic = entry ? null : heuristicAsnType(cleanEdgeAsOrg(edgeOrg));
      const result: EnrichedNetwork = {
        asn: String(edgeAsn),
        asn_name: cleanEdgeAsOrg(edgeOrg),
        asn_network: registryEntryForIp(ipClean)?.prefix ?? '',
        asn_type: entry?.asn_type ?? heuristic?.type ?? 'isp',
        datacenter_result: entry ? entry.datacenter_result : heuristic?.datacenter ?? false,
        source: 'edge',
      };
      cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
      return result;
    }

    // Tier 2 — bundled registry: longest-prefix IPv4 match, then curated ASN match.
    const prefixMatch = registryEntryForIp(ipClean);
    if (prefixMatch) {
      const result: EnrichedNetwork = {
        asn: String(prefixMatch.entry.asn),
        asn_name: prefixMatch.entry.asn_name,
        asn_network: prefixMatch.prefix,
        asn_type: prefixMatch.entry.asn_type,
        datacenter_result: prefixMatch.entry.datacenter_result,
        source: 'registry',
      };
      cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
      return result;
    }

    if (edgeAsn) {
      const entry = registryEntryForAsn(edgeAsn);
      if (entry) {
        const result: EnrichedNetwork = {
          asn: String(edgeAsn),
          asn_name: entry.asn_name,
          asn_network: '',
          asn_type: entry.asn_type,
          datacenter_result: entry.datacenter_result,
          source: 'registry',
        };
        cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
        return result;
      }

      // ASN known, organisation unknown: ask Team Cymru for the AS name alone.
      const byAsn = await resolveAsnOrganization(edgeAsn);
      if (byAsn.source !== 'none') {
        const result: EnrichedNetwork = {
          asn: String(edgeAsn),
          asn_name: byAsn.asn_name,
          asn_network: registryEntryForIp(ipClean)?.prefix ?? '',
          asn_type: byAsn.asn_type,
          datacenter_result: byAsn.datacenter_result,
          source: byAsn.source,
        };
        cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
        return result;
      }
    }

    if (edgeOrg) {
      // Organization known without an ASN number — keep the operator name, no fabricated ASN.
      const heuristic = heuristicAsnType(edgeOrg);
      const result: EnrichedNetwork = {
        asn: '',
        asn_name: cleanEdgeAsOrg(edgeOrg),
        asn_network: '',
        asn_type: heuristic.type,
        datacenter_result: heuristic.datacenter,
        source: 'edge',
      };
      cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
      return result;
    }

    // Tier 3 — Team Cymru via DNS-over-HTTPS.
    const cymru = await lookupCymruByIp(ipClean);
    if (cymru) {
      const entry = registryEntryForAsn(cymru.asn);
      let asnName = entry?.asn_name ?? '';
      let asnType = entry?.asn_type;
      let datacenter = entry?.datacenter_result;
      if (!asnName) {
        const rawName = await lookupCymruAsName(cymru.asn);
        if (rawName) {
          asnName = cleanCymruAsName(rawName);
          const heuristic = heuristicAsnType(asnName);
          asnType = heuristic.type;
          datacenter = heuristic.datacenter;
        }
      }
      const result: EnrichedNetwork = {
        asn: String(cymru.asn),
        asn_name: asnName,
        asn_network: cymru.network || '',
        asn_type: asnType ?? 'isp',
        datacenter_result: datacenter ?? false,
        source: 'cymru',
      };
      cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
      return result;
    }

    // Nothing is known — degrade silently (30-second negative cache).
    const empty = EMPTY_NETWORK();
    cacheSet(cacheKey, empty, NEGATIVE_TTL_MS);
    return empty;
  } catch {
    return EMPTY_NETWORK();
  }
}

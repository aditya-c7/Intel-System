/**
 * Official crawler IP-feed verification helpers (RS5).
 *
 * Design contract
 * ---------------
 *  - The ONLY authoritative signal here is the operator's published CIDR list.
 *    Matching is numeric subnet containment: `(addr & mask) === (network & mask)`,
 *    evaluated independently for IPv4 and IPv6. There is no string matching and
 *    no prefix widening: a prefix with host bits set is rejected outright rather
 *    than rounded down to a shorter network.
 *  - A User-Agent is a *prefilter* only. `uaPrefilter` narrows which feeds to
 *    check; it can never produce a match on its own.
 *  - Forward-confirmed reverse DNS (FCrDNS) is only meaningful where an operator
 *    publishes a suffix contract (Google, Bing, Apple). OpenAI, Anthropic and
 *    Perplexity publish IP lists + UA only and share cloud ranges, so they have
 *    no suffix contract and `fcrdnsSuffixAllowed` returns false for them.
 *  - Every exported helper is pure and NON-THROWING. Hostile input yields a safe
 *    empty/negative result, never an exception.
 *  - No third-party SDK: IPv4/IPv6 parsing and masking are implemented here in
 *    plain TypeScript with BigInt.
 *
 * Freshness policy
 * ----------------
 *  Google publishes daily (creationTime present), Perplexity weekly, and the
 *  other operators publish no cadence. A feed with a defined cadence is rejected
 *  beyond its configured maxAge; an undefined cadence means "no expiry".
 */

/* -------------------------------------------------------------------------- */
/* Public types                                                               */
/* -------------------------------------------------------------------------- */

export type IpVersion = 4 | 6;

export interface ParsedPrefix {
  readonly version: IpVersion;
  readonly cidr: string;
  readonly prefixLen: number;
  readonly network: bigint;
  readonly mask: bigint;
}

export interface ParsedFeed {
  /** Raw creationTime as published (string or number), or null when absent/invalid. */
  readonly creationTimeRaw: string | number | null;
  /** creationTime coerced to epoch milliseconds, or null when unparseable. */
  readonly creationTimeMs: number | null;
  /** Canonical, non-widened prefixes parsed from the feed. */
  readonly prefixes: readonly ParsedPrefix[];
  /** Number of prefix entries that were malformed / non-canonical and discarded. */
  readonly rejectedCount: number;
}

export interface LookupEntry {
  readonly feedId: string;
  readonly operator: string;
  readonly prefix: ParsedPrefix;
}

export interface IpLookup {
  readonly entries: readonly LookupEntry[];
  readonly feedCount: number;
  readonly prefixCount: number;
}

export interface IpMatch {
  readonly matched: boolean;
  /** Unique operator names whose published CIDR contains the address. */
  readonly operators: readonly string[];
  /** Feed ids that contributed a match (a shared cloud range may list several). */
  readonly feedIds: readonly string[];
  readonly reason: 'exact-cidr-match' | 'no-exact-cidr-match' | 'invalid-ip' | 'empty-lookup';
}

export interface FeedDefinition {
  readonly id: string;
  readonly operator: string;
  readonly url: string;
  readonly refresh: 'daily' | 'weekly' | null;
  /** Maximum acceptable age derived from creationTime, or null = no expiry. */
  readonly defaultMaxAgeMs: number | null;
  /** UA substrings used ONLY as a prefilter. Never sufficient for a verdict. */
  readonly uaHints: readonly string[];
  /** Published FCrDNS suffix contracts. Empty = operator publishes none. */
  readonly fcrdnsSuffixes: readonly string[];
}

export type CacheStatus = 'accepted' | 'rejected' | 'stale';

export interface CachedFeed {
  readonly feedId: string;
  readonly parsed: ParsedFeed;
  readonly fetchedAtMs: number;
  readonly expiresAtMs: number;
}

export interface FeedCache {
  readonly entries: Readonly<Record<string, CachedFeed>>;
}

/* -------------------------------------------------------------------------- */
/* Canonical catalog of official feeds (exact URLs from the research brief)   */
/* -------------------------------------------------------------------------- */

const DAY = 24 * 60 * 60 * 1000;
const GOOGLE_MAX_AGE = 2 * DAY; // daily publication + slack for propagation
const PERPLEXITY_MAX_AGE = 10 * DAY; // weekly publication + slack

const GOOGLE_FCRDNS = ['.googlebot.com', '.google.com'] as const;
const BING_FCRDNS = ['.search.msn.com', '.bing.com'] as const;
const APPLE_FCRDNS = ['.applebot.apple.com'] as const;

export const OFFICIAL_FEEDS: readonly FeedDefinition[] = Object.freeze([
  // Google — https://developers.google.com/search/apis/ipranges/
  { id: 'common-crawlers', operator: 'Google', url: 'https://developers.google.com/search/apis/ipranges/common-crawlers.json', refresh: 'daily', defaultMaxAgeMs: GOOGLE_MAX_AGE, uaHints: ['googlebot'], fcrdnsSuffixes: GOOGLE_FCRDNS },
  { id: 'special-crawlers', operator: 'Google', url: 'https://developers.google.com/search/apis/ipranges/special-crawlers.json', refresh: 'daily', defaultMaxAgeMs: GOOGLE_MAX_AGE, uaHints: ['googlebot-image', 'googlebot-news', 'googlebot-video'], fcrdnsSuffixes: GOOGLE_FCRDNS },
  { id: 'user-triggered-fetchers', operator: 'Google', url: 'https://developers.google.com/search/apis/ipranges/user-triggered-fetchers.json', refresh: 'daily', defaultMaxAgeMs: GOOGLE_MAX_AGE, uaHints: ['google-web-preview', 'google-read-aloud', 'google-translate'], fcrdnsSuffixes: GOOGLE_FCRDNS },
  { id: 'user-triggered-fetchers-google', operator: 'Google', url: 'https://developers.google.com/search/apis/ipranges/user-triggered-fetchers-google.json', refresh: 'daily', defaultMaxAgeMs: GOOGLE_MAX_AGE, uaHints: ['google'], fcrdnsSuffixes: GOOGLE_FCRDNS },
  { id: 'user-triggered-agents', operator: 'Google', url: 'https://developers.google.com/search/apis/ipranges/user-triggered-agents.json', refresh: 'daily', defaultMaxAgeMs: GOOGLE_MAX_AGE, uaHints: ['google-extended', 'google-web-preview'], fcrdnsSuffixes: GOOGLE_FCRDNS },
  // OpenAI — https://openai.com/<feed>.json (IP list + UA only; no FCrDNS contract)
  { id: 'gptbot', operator: 'OpenAI', url: 'https://openai.com/gptbot.json', refresh: null, defaultMaxAgeMs: null, uaHints: ['gptbot'], fcrdnsSuffixes: [] },
  { id: 'searchbot', operator: 'OpenAI', url: 'https://openai.com/searchbot.json', refresh: null, defaultMaxAgeMs: null, uaHints: ['oai-searchbot'], fcrdnsSuffixes: [] },
  { id: 'chatgpt-user', operator: 'OpenAI', url: 'https://openai.com/chatgpt-user.json', refresh: null, defaultMaxAgeMs: null, uaHints: ['chatgpt-user'], fcrdnsSuffixes: [] },
  { id: 'adsbot', operator: 'OpenAI', url: 'https://openai.com/adsbot.json', refresh: null, defaultMaxAgeMs: null, uaHints: ['adsbot'], fcrdnsSuffixes: [] },
  // Anthropic (IP list + UA only)
  { id: 'claude', operator: 'Anthropic', url: 'https://claude.com/crawling/bots.json', refresh: null, defaultMaxAgeMs: null, uaHints: ['claudebot', 'claude-web', 'anthropic'], fcrdnsSuffixes: [] },
  // Perplexity (weekly IP list + UA only; predominantly /32 — never broaden)
  { id: 'perplexitybot', operator: 'Perplexity', url: 'https://www.perplexity.com/perplexitybot.json', refresh: 'weekly', defaultMaxAgeMs: PERPLEXITY_MAX_AGE, uaHints: ['perplexitybot'], fcrdnsSuffixes: [] },
  { id: 'perplexity-user', operator: 'Perplexity', url: 'https://www.perplexity.com/perplexity-user.json', refresh: 'weekly', defaultMaxAgeMs: PERPLEXITY_MAX_AGE, uaHints: ['perplexity-user'], fcrdnsSuffixes: [] },
  // Bing / Microsoft (publishes FCrDNS suffix contract)
  { id: 'bingbot', operator: 'Microsoft', url: 'https://www.bing.com/toolbox/bingbot.json', refresh: null, defaultMaxAgeMs: null, uaHints: ['bingbot', 'bingpreview'], fcrdnsSuffixes: BING_FCRDNS },
  // Apple (publishes FCrDNS suffix contract)
  { id: 'applebot', operator: 'Apple', url: 'https://search.developer.apple.com/applebot.json', refresh: null, defaultMaxAgeMs: null, uaHints: ['applebot'], fcrdnsSuffixes: APPLE_FCRDNS },
]);

/** Local shorthand ids used by cached snapshots / fixtures, mapped to catalog ids. */
const FEED_ALIASES = new Map<string, string>([
  ['google-common', 'common-crawlers'],
  ['googlebot', 'common-crawlers'],
  ['google-special', 'special-crawlers'],
  ['google-utf', 'user-triggered-fetchers'],
  ['google-uta', 'user-triggered-agents'],
]);

const FEED_BY_ID = new Map<string, FeedDefinition>(OFFICIAL_FEEDS.map((d) => [d.id, d]));
const FEEDS_BY_OPERATOR = new Map<string, FeedDefinition[]>();
for (const def of OFFICIAL_FEEDS) {
  const key = def.operator.toLowerCase();
  const list = FEEDS_BY_OPERATOR.get(key);
  if (list) list.push(def);
  else FEEDS_BY_OPERATOR.set(key, [def]);
}

/** Look up a feed definition by id, operator name, or exact URL. Non-throwing. */
export function getFeedDefinition(idOrOperatorOrUrl: unknown): FeedDefinition | null {
  if (typeof idOrOperatorOrUrl !== 'string') return null;
  const key = idOrOperatorOrUrl.trim();
  const byId = FEED_BY_ID.get(FEED_ALIASES.get(key) ?? key);
  if (byId) return byId;
  const byOperator = FEEDS_BY_OPERATOR.get(key.toLowerCase());
  if (byOperator && byOperator.length > 0) return byOperator[0];
  for (const def of OFFICIAL_FEEDS) {
    if (def.url === key) return def;
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* Internal primitives — all total functions, no throws                       */
/* -------------------------------------------------------------------------- */

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** (bits-ary mask) with the top `prefixLen` bits set. */
function maskFor(bits: number, prefixLen: number): bigint {
  if (prefixLen <= 0) return 0n;
  return ((1n << BigInt(prefixLen)) - 1n) << BigInt(bits - prefixLen);
}

/** Parse one dotted-decimal IPv4 address into a 32-bit BigInt. Strict: no leading zeros. */
function parseIpv4Address(value: string): bigint | null {
  if (value.length < 7 || value.length > 15) return null;
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  let result = 0n;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    result = (result << 8n) | BigInt(octet);
  }
  return result;
}

/** Parse one 16-bit IPv6 hextet. */
function parseHextet(value: string): number | null {
  if (value.length < 1 || value.length > 4) return null;
  let result = 0;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    let digit: number;
    if (code >= 48 && code <= 57) digit = code - 48;
    else if (code >= 97 && code <= 102) digit = code - 87;
    else if (code >= 65 && code <= 70) digit = code - 55;
    else return null;
    result = result * 16 + digit;
  }
  return result;
}

/** Parse an IPv6 address (no prefix, no zone id) into a 128-bit BigInt. */
function parseIpv6Address(input: string): bigint | null {
  if (input.length < 2 || input.length > 45) return null;
  let body = input;

  // IPv4-mapped / embedded form: replace the dotted tail with two hextets.
  if (body.includes('.')) {
    const colon = body.lastIndexOf(':');
    if (colon < 0) return null;
    const tail = body.slice(colon + 1);
    const v4 = parseIpv4Address(tail);
    if (v4 === null) return null;
    const hi = Number((v4 >> 16n) & 0xffffn).toString(16);
    const lo = Number(v4 & 0xffffn).toString(16);
    body = body.slice(0, colon + 1) + hi + ':' + lo;
  }

  let groups: number[];
  const compression = body.indexOf('::');

  if (compression !== -1) {
    // A second "::" (including the ":::" case) is malformed.
    if (body.indexOf('::', compression + 2) !== -1) return null;
    const leftRaw = body.slice(0, compression);
    const rightRaw = body.slice(compression + 2);
    const left = leftRaw === '' ? [] : leftRaw.split(':');
    const right = rightRaw === '' ? [] : rightRaw.split(':');
    // Empty groups other than the single "::" are malformed.
    if (left.some((g) => g === '') || right.some((g) => g === '')) return null;
    // "::" must stand for at least one zero group.
    if (left.length + right.length >= 8) return null;
    const parsedLeft = left.map(parseHextet);
    const parsedRight = right.map(parseHextet);
    if (parsedLeft.some((g) => g === null) || parsedRight.some((g) => g === null)) return null;
    const zeros = new Array<number>(8 - left.length - right.length).fill(0);
    groups = [...(parsedLeft as number[]), ...zeros, ...(parsedRight as number[])];
  } else {
    const raw = body.split(':');
    if (raw.length !== 8 || raw.some((g) => g === '')) return null;
    const parsed = raw.map(parseHextet);
    if (parsed.some((g) => g === null)) return null;
    groups = parsed as number[];
  }

  if (groups.length !== 8) return null;
  let value = 0n;
  for (const group of groups) value = (value << 16n) | BigInt(group);
  return value;
}

/** Parse a single CIDR string into a canonical, non-widened prefix. */
function parseCidr(value: unknown, version: IpVersion): ParsedPrefix | null {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (text.length === 0) return null;
  const slash = text.indexOf('/');
  if (slash <= 0 || slash !== text.lastIndexOf('/')) return null;
  const addressText = text.slice(0, slash);
  const lenText = text.slice(slash + 1);
  const lenPattern = version === 4 ? /^\d{1,2}$/ : /^\d{1,3}$/;
  if (!lenPattern.test(lenText)) return null;
  const prefixLen = Number(lenText);
  if (prefixLen < 0 || prefixLen > (version === 4 ? 32 : 128)) return null;

  const address = version === 4 ? parseIpv4Address(addressText) : parseIpv6Address(addressText);
  if (address === null) return null;

  const bits = version === 4 ? 32 : 128;
  const mask = maskFor(bits, prefixLen);
  const network = address & mask;
  // CRITICAL: reject host bits set. Rounding down would widen the prefix and
  // brand unrelated addresses (e.g. an entire cloud ASN) as an operator.
  if (network !== address) return null;

  return { version, cidr: `${addressText}/${prefixLen}`, prefixLen, network, mask };
}

/** Parse a bare IP address (never a CIDR, never a zone id) for matching. */
function parseIpAddress(value: unknown): { version: IpVersion; value: bigint } | null {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (text.length === 0 || text.length > 45) return null;
  if (text.includes('/') || text.includes('%') || text.includes(' ')) return null;
  if (text.includes(':')) {
    const parsed = parseIpv6Address(text);
    return parsed === null ? null : { version: 6, value: parsed };
  }
  const parsed = parseIpv4Address(text);
  return parsed === null ? null : { version: 4, value: parsed };
}

/** Parse creationTime in the forms used by official feeds (no-TZ, Z, offsets). */
function parseCreationTime(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  let iso = trimmed;
  // Google/OpenAI publish "2026-11-20T15:45:50.000000" with no zone: it is UTC.
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(iso)) iso += 'Z';
  // Truncate excess fractional digits to milliseconds for stable cross-engine parsing.
  iso = iso.replace(/\.(\d{3})\d+(?=Z|[+-]\d{2}:?\d{2}$)/, '.$1');
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
}

const EMPTY_FEED: ParsedFeed = Object.freeze({
  creationTimeRaw: null,
  creationTimeMs: null,
  prefixes: Object.freeze([] as ParsedPrefix[]),
  rejectedCount: 0,
});

/* -------------------------------------------------------------------------- */
/* Public helpers                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Parse one official feed payload. Accepts an already-parsed object or a JSON
 * string. Non-throwing; malformed prefix entries are counted and discarded.
 * A prefix with host bits set is DISCARDED, never widened.
 */
function parseFeedImpl(json: unknown): ParsedFeed {
  let obj: Record<string, unknown> | null = null;
  if (isRecord(json)) {
    obj = json;
  } else if (typeof json === 'string') {
    try {
      const decoded: unknown = JSON.parse(json);
      if (isRecord(decoded)) obj = decoded;
    } catch {
      return EMPTY_FEED;
    }
  }
  if (!obj) return EMPTY_FEED;

  const rawCreationTime = obj['creationTime'];
  const creationTimeRaw =
    typeof rawCreationTime === 'string' || typeof rawCreationTime === 'number'
      ? rawCreationTime
      : null;
  const creationTimeMs = parseCreationTime(rawCreationTime);

  const rawPrefixes = obj['prefixes'];
  const prefixes: ParsedPrefix[] = [];
  let rejectedCount = 0;
  if (Array.isArray(rawPrefixes)) {
    for (const item of rawPrefixes) {
      if (!isRecord(item)) {
        rejectedCount += 1;
        continue;
      }
      const v4 = item['ipv4Prefix'];
      const v6 = item['ipv6Prefix'];
      const parsed =
        (typeof v4 === 'string' ? parseCidr(v4, 4) : null) ??
        (typeof v6 === 'string' ? parseCidr(v6, 6) : null);
      if (parsed === null) rejectedCount += 1;
      else prefixes.push(parsed);
    }
  }

  return Object.freeze({
    creationTimeRaw,
    creationTimeMs,
    prefixes: Object.freeze(prefixes),
    rejectedCount,
  });
}

/** Non-throwing wrapper: even a throwing Proxy input yields an empty feed. */
export function parseFeed(json: unknown): ParsedFeed {
  try {
    return parseFeedImpl(json);
  } catch {
    return EMPTY_FEED;
  }
}

/**
 * Build an immutable lookup index from a map of {feedId: rawFeedJson}.
 * Feed ids are resolved against OFFICIAL_FEEDS; unknown ids still work and are
 * treated as their own operator. Feeds with no valid prefixes are skipped.
 */
function buildLookupImpl(feeds: unknown): IpLookup {
  const empty: IpLookup = Object.freeze({
    entries: Object.freeze([] as LookupEntry[]),
    feedCount: 0,
    prefixCount: 0,
  });
  if (!isRecord(feeds)) return empty;

  let keys: string[];
  try {
    keys = Object.keys(feeds);
  } catch {
    return empty;
  }

  const entries: LookupEntry[] = [];
  let feedCount = 0;
  for (const key of keys) {
    let parsed: ParsedFeed;
    try {
      parsed = parseFeed(feeds[key]);
    } catch {
      continue;
    }
    if (parsed.prefixes.length === 0) continue;
    const def = getFeedDefinition(key);
    const feedId = def?.id ?? key;
    const operator = def?.operator ?? key;
    feedCount += 1;
    for (const prefix of parsed.prefixes) entries.push({ feedId, operator, prefix });
  }

  return Object.freeze({
    entries: Object.freeze(entries),
    feedCount,
    prefixCount: entries.length,
  });
}

/** Non-throwing wrapper around the index builder. */
export function buildLookup(feeds: unknown): IpLookup {
  try {
    return buildLookupImpl(feeds);
  } catch {
    return Object.freeze({
      entries: Object.freeze([] as LookupEntry[]),
      feedCount: 0,
      prefixCount: 0,
    });
  }
}

/**
 * Numeric subnet containment. IPv4 and IPv6 are evaluated independently.
 * An IP that merely *looks* like a bot's UA is never considered here.
 */
function prefixContains(addr: bigint, network: bigint, mask: bigint): boolean {
  return (addr & mask) === (network & mask);
}
function matchIpImpl(lookup: IpLookup, ip: unknown): IpMatch {
  if (!isRecord(lookup) || !Array.isArray(lookup.entries)) {
    return { matched: false, operators: [], feedIds: [], reason: 'empty-lookup' };
  }
  const address = parseIpAddress(ip);
  if (address === null) {
    return { matched: false, operators: [], feedIds: [], reason: 'invalid-ip' };
  }
  if (lookup.entries.length === 0) {
    return { matched: false, operators: [], feedIds: [], reason: 'empty-lookup' };
  }

  const operators: string[] = [];
  const feedIds: string[] = [];
  for (const entry of lookup.entries) {
    if (!entry || !entry.prefix || entry.prefix.version !== address.version) continue;
    const { network, mask } = entry.prefix;
    if (!prefixContains(address.value, network, mask)) continue;
    if (typeof entry.operator === 'string' && !operators.includes(entry.operator)) {
      operators.push(entry.operator);
    }
    if (typeof entry.feedId === 'string' && !feedIds.includes(entry.feedId)) {
      feedIds.push(entry.feedId);
    }
  }

  return {
    matched: operators.length > 0,
    operators: Object.freeze(operators),
    feedIds: Object.freeze(feedIds),
    reason: operators.length > 0 ? 'exact-cidr-match' : 'no-exact-cidr-match',
  };
}

/** Non-throwing wrapper around the matcher. */
export function matchIp(lookup: IpLookup, ip: unknown): IpMatch {
  try {
    return matchIpImpl(lookup, ip);
  } catch {
    return { matched: false, operators: [], feedIds: [], reason: 'invalid-ip' };
  }
}

/**
 * Freshness gate for a feed's own creationTime.
 *  - An unparseable creationTime is NOT fresh (cannot verify → reject).
 *  - A missing/non-positive/infinite maxAge means "no expiry" → true.
 *  - Equality at the boundary is accepted (age <= maxAge).
 */
export function isFresh(creationTime: unknown, nowMs: unknown, maxAgeMs: unknown): boolean {
  if (maxAgeMs === Infinity) return true;
  if (typeof maxAgeMs !== 'number' || !Number.isFinite(maxAgeMs) || maxAgeMs <= 0) return true;
  const created = parseCreationTime(creationTime);
  if (created === null) return false;
  const now = typeof nowMs === 'number' && Number.isFinite(nowMs) ? nowMs : Date.now();
  const age = now - created;
  if (!Number.isFinite(age)) return false;
  return age <= maxAgeMs;
}

/**
 * User-Agent PREFILTER ONLY. Returns candidate feed ids worth checking with
 * matchIp + FCrDNS. An empty result (or a non-empty one) is never a verdict.
 */
export function uaPrefilter(userAgent: unknown, feedId?: string): string[] {
  if (typeof userAgent !== 'string' || userAgent.length === 0) return [];
  const ua = userAgent.toLowerCase();
  const candidates: string[] = [];
  for (const def of OFFICIAL_FEEDS) {
    if (feedId !== undefined && def.id !== feedId) continue;
    for (const hint of def.uaHints) {
      if (ua.includes(hint.toLowerCase())) {
        candidates.push(def.id);
        break;
      }
    }
  }
  return candidates;
}

/**
 * Forward-confirmed reverse DNS suffix check. Only operators that PUBLISH a
 * suffix contract (Google, Bing, Apple) can pass. For IP-list-only operators
 * (OpenAI, Anthropic, Perplexity) this always returns false — a missing
 * contract is never treated as an automatic pass.
 */
export function fcrdnsSuffixAllowed(hostname: unknown, operator: unknown): boolean {
  if (typeof hostname !== 'string' || typeof operator !== 'string') return false;
  let host = hostname.trim().toLowerCase();
  if (host.length === 0 || host.length > 253) return false;
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (host.length === 0 || host.includes('..')) return false;
  if (!/^[a-z0-9.-]+$/.test(host)) return false;
  if (host.split('.').some((label) => label.length === 0 || label.startsWith('-') || label.endsWith('-'))) return false;

  const defs = getFeedDefinition(operator)
    ? [getFeedDefinition(operator) as FeedDefinition]
    : FEEDS_BY_OPERATOR.get(operator.trim().toLowerCase()) ?? [];
  const suffixes = new Set<string>();
  for (const def of defs) {
    for (const suffix of def.fcrdnsSuffixes) {
      const normalized = suffix.trim().toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '');
      if (normalized.length > 0) suffixes.add(normalized);
    }
  }
  if (suffixes.size === 0) return false;

  for (const suffix of suffixes) {
    // Require a label boundary: "x.googlebot.com" passes, "notgooglebot.com"
    // and "evil-googlebot.com.attacker.net" do not.
    if (host === suffix || host.endsWith('.' + suffix)) return true;
  }
  return false;
}

/* -------------------------------------------------------------------------- */
/* Caching with TTL and last-known-good retention                             */
/* -------------------------------------------------------------------------- */

export const EMPTY_FEED_CACHE: FeedCache = Object.freeze({ entries: Object.freeze({}) });

/** Resolve the effective maxAge: explicit override, else the catalog cadence. */
export function maxAgeForFeed(feedId: unknown, overrideMs?: unknown): number {
  if (typeof overrideMs === 'number' && Number.isFinite(overrideMs) && overrideMs > 0) {
    return overrideMs;
  }
  const def = getFeedDefinition(feedId);
  return def?.defaultMaxAgeMs ?? Infinity;
}

/**
 * Pure cache update. A fresh, valid feed replaces the cached entry; a malformed
 * or stale feed is rejected and the previous last-known-good entry is retained.
 */
export function updateFeedCache(
  cache: FeedCache | null | undefined,
  feedId: unknown,
  json: unknown,
  nowMs: unknown,
  maxAgeMs?: unknown,
): { cache: FeedCache; status: CacheStatus } {
  const previous = isRecord(cache?.entries) ? (cache as FeedCache).entries : {};
  const now = typeof nowMs === 'number' && Number.isFinite(nowMs) ? nowMs : Date.now();
  const id = typeof feedId === 'string' ? feedId : '';
  const keep = (status: CacheStatus) => ({
    cache: Object.freeze({ entries: Object.freeze({ ...previous }) }) as FeedCache,
    status,
  });

  const parsed = parseFeed(json);
  if (parsed.prefixes.length === 0) return keep('rejected');

  const ttl = maxAgeForFeed(id, maxAgeMs);
  if (!isFresh(parsed.creationTimeMs, now, ttl)) return keep('stale');

  const entries: Record<string, CachedFeed> = { ...previous };
  entries[id] = Object.freeze({
    feedId: id,
    parsed,
    fetchedAtMs: now,
    expiresAtMs: ttl === Infinity ? Infinity : now + ttl,
  });
  return {
    cache: Object.freeze({ entries: Object.freeze(entries) }) as FeedCache,
    status: 'accepted',
  };
}

/** Whether a cached entry is still inside its TTL at `nowMs`. Non-throwing. */
export function isCacheEntryUsable(entry: CachedFeed | null | undefined, nowMs: unknown): boolean {
  if (!isRecord(entry) || typeof (entry as CachedFeed).expiresAtMs !== 'number') return false;
  const now = typeof nowMs === 'number' && Number.isFinite(nowMs) ? nowMs : Date.now();
  return now < (entry as CachedFeed).expiresAtMs;
}

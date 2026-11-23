/**
 * Official bot feed verification helpers — isolated test suite (RS5).
 *
 *   npx tsx scripts/test-official-bot-feeds.ts
 *
 * Uses only scripts/fixtures/official-bot-feeds.json (synthetic, representative
 * CIDRs + RFC 5737/3849 documentation addresses). No network, no third-party SDK.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  buildLookup,
  EMPTY_FEED_CACHE,
  fcrdnsSuffixAllowed,
  getFeedDefinition,
  isCacheEntryUsable,
  isFresh,
  matchIp,
  maxAgeForFeed,
  OFFICIAL_FEEDS,
  parseFeed,
  uaPrefilter,
  updateFeedCache,
  type FeedCache,
  type IpLookup,
} from '../src/lib/officialBotFeeds';

interface FixtureCase {
  name: string;
  ip: string;
  operators: string[];
  feedIds: string[];
}
interface Fixture {
  nowMs: number;
  feeds: Record<string, unknown>;
  hostileFeeds: Record<string, unknown>;
  hosts: Record<string, string>;
  cases: FixtureCase[];
}

const fixturePath = fileURLToPath(new URL('./fixtures/official-bot-feeds.json', import.meta.url));
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as Fixture;
const { nowMs, feeds, hostileFeeds, hosts, cases } = fixture;
const DAY = 24 * 60 * 60 * 1000;

let assertions = 0;
let failures = 0;

function check(name: string, condition: boolean, detail?: unknown): void {
  assertions += 1;
  if (condition) {
    console.log(`ok   ${name}`);
    return;
  }
  failures += 1;
  console.error(`FAIL ${name}`);
  if (detail !== undefined) console.error('     ', detail);
}

/** Assert a helper does not throw for hostile input, returning a fallback value. */
function noThrow<T>(name: string, fn: () => T): T | undefined {
  assertions += 1;
  try {
    const value = fn();
    console.log(`ok   ${name}`);
    return value;
  } catch (error) {
    failures += 1;
    console.error(`FAIL ${name} (threw)`);
    console.error('     ', error);
    return undefined;
  }
}

function main(): void {
  /* --- catalog ----------------------------------------------------------- */
  check('catalog lists all 14 official feeds', OFFICIAL_FEEDS.length === 14);
  check(
    'catalog includes every exact official filename',
    [
      'common-crawlers', 'special-crawlers', 'user-triggered-fetchers',
      'user-triggered-fetchers-google', 'user-triggered-agents',
      'gptbot', 'searchbot', 'chatgpt-user', 'adsbot', 'claude',
      'perplexitybot', 'perplexity-user', 'bingbot', 'applebot',
    ].every((id) => OFFICIAL_FEEDS.some((def) => def.id === id)),
  );
  check('Google cadence is daily', getFeedDefinition('google-common')?.refresh === 'daily');
  check('Perplexity cadence is weekly', getFeedDefinition('perplexitybot')?.refresh === 'weekly');
  check('OpenAI cadence is undefined', getFeedDefinition('gptbot')?.refresh === null);
  check('FCrDNS published for Google', getFeedDefinition('google-common')!.fcrdnsSuffixes.length > 0);
  check('FCrDNS published for Bing', getFeedDefinition('bingbot')!.fcrdnsSuffixes.length > 0);
  check('FCrDNS published for Apple', getFeedDefinition('applebot')!.fcrdnsSuffixes.length > 0);
  check('FCrDNS NOT published for OpenAI', getFeedDefinition('gptbot')!.fcrdnsSuffixes.length === 0);
  check('FCrDNS NOT published for Anthropic', getFeedDefinition('claude')!.fcrdnsSuffixes.length === 0);
  check('FCrDNS NOT published for Perplexity', getFeedDefinition('perplexitybot')!.fcrdnsSuffixes.length === 0);

  /* --- parseFeed --------------------------------------------------------- */
  const parsedGoogle = parseFeed(feeds['google-common']);
  check('parseFeed reads creationTime (no-TZ micros)', parsedGoogle.creationTimeMs === Date.UTC(2026, 10, 22, 8, 0, 0), parsedGoogle.creationTimeMs);
  check('parseFeed reads v4 + v6 prefixes', parsedGoogle.prefixes.length === 2 && parsedGoogle.prefixes.some((p) => p.version === 4) && parsedGoogle.prefixes.some((p) => p.version === 6));
  check('parseFeed accepts a JSON string', parseFeed(JSON.stringify(feeds['gptbot'])).prefixes.length === 1);
  const parsedHostile = parseFeed(hostileFeeds.malformed);
  check('parseFeed discards malformed/non-canonical prefixes', parsedHostile.prefixes.length === 1, parsedHostile);
  check('parseFeed counts 9 rejected entries', parsedHostile.rejectedCount === 9, parsedHostile.rejectedCount);
  check('parseFeed rejects host bits on v4 (18.97.9.96/24)', parseFeed({ prefixes: [{ ipv4Prefix: '18.97.9.96/24' }] }).prefixes.length === 0);
  check('parseFeed rejects host bits on v6', parseFeed({ prefixes: [{ ipv6Prefix: '2001:4860:4801:10::1/120' }] }).prefixes.length === 0);
  check('parseFeed rejects /33 and /129', parseFeed({ prefixes: [{ ipv4Prefix: '1.2.3.4/33' }, { ipv6Prefix: '2001:db8::/129' }] }).prefixes.length === 0);
  check('parseFeed accepts exact /32 and /128', parseFeed({ prefixes: [{ ipv4Prefix: '18.97.9.96/32' }, { ipv6Prefix: '2001:db8::1/128' }] }).prefixes.length === 2);
  check('parseFeed never widens Perplexity /32', parseFeed(feeds.perplexitybot).prefixes.every((p) => p.prefixLen === 32));
  check('parseFeed invalid creationTime is null', parsedHostile.creationTimeMs === null);

  /* --- hostile / non-throwing -------------------------------------------- */
  for (const [label, value] of [
    ['null', null], ['number', 42], ['array', []], ['boolean', true],
    ['empty string', ''], ['bad JSON', '{nope'],
  ] as Array<[string, unknown]>) {
    const result = noThrow(`parseFeed(${label}) does not throw`, () => parseFeed(value));
    check(`parseFeed(${label}) returns empty feed`, result?.prefixes.length === 0);
  }
  const throwingProxy = new Proxy({}, { get() { throw new Error('hostile proxy'); } });
  noThrow('parseFeed(throwing proxy) does not throw', () => parseFeed(throwingProxy));
  noThrow('buildLookup(throwing proxy) does not throw', () => buildLookup(throwingProxy));
  noThrow('matchIp(throwing proxy lookup) does not throw', () => matchIp(throwingProxy as unknown as IpLookup, '1.2.3.4'));

  /* --- buildLookup ------------------------------------------------------- */
  const lookup = buildLookup(feeds);
  check('buildLookup indexes all valid feeds', lookup.feedCount === 10, lookup.feedCount);
  check('buildLookup counts all prefixes', lookup.prefixCount === 14, lookup.prefixCount);
  check('buildLookup skips empty feeds', !lookup.entries.some((e) => e.feedId === 'empty-feed'));
  check('buildLookup(empty) yields empty index', buildLookup(null).prefixCount === 0);

  /* --- matchIp: fixture-driven cases ------------------------------------- */
  for (const c of cases) {
    const result = matchIp(lookup, c.ip);
    check(
      `matchIp ${c.name}: ${c.ip}`,
      result.matched === (c.operators.length > 0)
        && JSON.stringify(result.operators) === JSON.stringify(c.operators)
        && JSON.stringify(result.feedIds) === JSON.stringify(c.feedIds),
      result,
    );
  }

  /* --- matchIp: boundaries, family isolation, invalid input -------------- */
  const outside = matchIp(lookup, '66.249.66.32');
  check('exact /27 boundary excludes next address', outside.reason === 'no-exact-cidr-match' && outside.matched === false);
  const v6Neighbor = matchIp(lookup, '2001:4860:4801:11::1');
  check('exact /64 boundary excludes neighbor', v6Neighbor.matched === false);
  check('v4 address never matches a v6 prefix', matchIp(buildLookup({ f: { prefixes: [{ ipv6Prefix: '2001:db8::/32' }] } }), '203.0.113.7').matched === false);
  check('v6 address never matches a v4 prefix', matchIp(buildLookup({ f: { prefixes: [{ ipv4Prefix: '203.0.113.0/24' }] } }), '2001:db8::1').matched === false);
  check('RFC 5737 address never matches any operator', matchIp(lookup, '198.51.100.7').matched === false);
  check('RFC 3849 address never matches any operator', matchIp(lookup, '2001:db8::1').matched === false);
  check('whole /24 is not matched for a /32 feed', matchIp(lookup, '3.41.218.0').matched === false);
  for (const bad of ['', '999.1.1.1', '1.2.3', '1.2.3.4.5', '1.2.3.4/32', 'gggg::1', '1::2::3', '::ffff:999.1.1.1']) {
    const r = matchIp(lookup, bad);
    check(`matchIp invalid ${JSON.stringify(bad)}`, r.reason === 'invalid-ip' && r.matched === false);
  }
  check('matchIp(null ip) is invalid', matchIp(lookup, null).reason === 'invalid-ip');
  check('matchIp(empty lookup) reports empty-lookup', matchIp(buildLookup(null), '66.249.66.1').reason === 'empty-lookup');
  check('UA alone is never a match', matchIp(lookup, 'GPTBot/1.0').matched === false);

  /* --- freshness --------------------------------------------------------- */
  const googleMaxAge = maxAgeForFeed('google-common');
  const perplexityMaxAge = maxAgeForFeed('perplexitybot');
  check('Google maxAge is 2 days', googleMaxAge === 2 * DAY);
  check('Perplexity maxAge is 10 days', perplexityMaxAge === 10 * DAY);
  check('OpenAI maxAge is unbounded', maxAgeForFeed('gptbot') === Infinity);
  check('explicit maxAge override wins', maxAgeForFeed('google-common', 1000) === 1000);
  check('fresh Google creationTime', isFresh(parsedGoogle.creationTimeMs, nowMs, googleMaxAge) === true);
  check('stale Google creationTime (> 2d)', isFresh('2026-11-01T00:00:00Z', nowMs, googleMaxAge) === false);
  check('fresh Perplexity creationTime (weekly)', isFresh(parseFeed(feeds.perplexitybot).creationTimeMs, nowMs, perplexityMaxAge) === true);
  check('stale Perplexity creationTime', isFresh('2026-10-01T00:00:00Z', nowMs, perplexityMaxAge) === false);
  check('freshness boundary age === maxAge accepted', isFresh(nowMs - googleMaxAge, nowMs, googleMaxAge) === true);
  check('freshness boundary age > maxAge rejected', isFresh(nowMs - googleMaxAge - 1, nowMs, googleMaxAge) === false);
  check('unparseable creationTime is not fresh', isFresh('nonsense', nowMs, googleMaxAge) === false);
  check('no configured maxAge means no expiry', isFresh('2020-01-01T00:00:00Z', nowMs, Infinity) === true);
  check('creationTime all published forms agree', [
    parseFeed({ creationTime: '2026-11-22T08:00:00.000000' }).creationTimeMs,
    parseFeed({ creationTime: '2026-11-22T08:00:00Z' }).creationTimeMs,
    parseFeed({ creationTime: '2026-11-22T08:00:00.000000+00:00' }).creationTimeMs,
  ].every((ms) => ms === Date.UTC(2026, 10, 22, 8, 0, 0)));

  /* --- FCrDNS ------------------------------------------------------------ */
  check('Google .googlebot.com FCrDNS passes', fcrdnsSuffixAllowed(hosts.googleValid, 'Google'));
  check('Google .google.com FCrDNS passes', fcrdnsSuffixAllowed(hosts.googleValidAlt, 'Google'));
  check('Bing .search.msn.com FCrDNS passes', fcrdnsSuffixAllowed(hosts.bingValid, 'Microsoft'));
  check('Apple .applebot.apple.com FCrDNS passes', fcrdnsSuffixAllowed(hosts.appleValid, 'Apple'));
  check('trailing dot + uppercase FCrDNS passes', fcrdnsSuffixAllowed('CRAWL-1.GOOGLEBOT.COM.', 'google-common'));
  check('spoofed suffix in middle fails', fcrdnsSuffixAllowed(hosts.spoofed, 'Google') === false);
  check('label-boundary confusion fails', fcrdnsSuffixAllowed(hosts.labelBoundary, 'Google') === false);
  check('suffix not at end fails', fcrdnsSuffixAllowed(hosts.suffixNotAtEnd, 'Google') === false);
  check('OpenAI has no FCrDNS contract', fcrdnsSuffixAllowed(hosts.googleValid, 'OpenAI') === false);
  check('Anthropic has no FCrDNS contract', fcrdnsSuffixAllowed(hosts.googleValid, 'Anthropic') === false);
  check('Perplexity has no FCrDNS contract', fcrdnsSuffixAllowed(hosts.googleValid, 'Perplexity') === false);
  for (const bad of [null, 42, '', '   ', 'a..b.googlebot.com', 'crawl-.googlebot.com', 'crawl_x.googlebot.com']) {
    check(`fcrdnsSuffixAllowed hostile ${JSON.stringify(bad)}`, fcrdnsSuffixAllowed(bad, 'Google') === false);
  }
  noThrow('fcrdnsSuffixAllowed never throws', () => fcrdnsSuffixAllowed(throwingProxy, throwingProxy) as boolean);

  /* --- UA prefilter ------------------------------------------------------ */
  check('GPTBot UA prefilters to gptbot', uaPrefilter('Mozilla/5.0 GPTBot/1.1').includes('gptbot'));
  check('Bing UA prefilters to bingbot', uaPrefilter('Mozilla/5.0 bingbot/2.0').includes('bingbot'));
  check('empty UA yields no candidates', uaPrefilter('').length === 0);
  check('unknown UA yields no candidates', uaPrefilter('curl/8.0').length === 0);

  /* --- cache (TTL + last-known-good) ------------------------------------- */
  const accepted = updateFeedCache(EMPTY_FEED_CACHE, 'google-common', feeds['google-common'], nowMs);
  check('cache accepts a fresh feed', accepted.status === 'accepted');
  const cached = accepted.cache.entries['google-common'];
  check('cached feed carries parsed prefixes', cached?.parsed.prefixes.length === 2);
  check('cached entry usable inside TTL', isCacheEntryUsable(cached, nowMs) === true);
  check('cached entry expired past TTL', isCacheEntryUsable(cached, nowMs + 2 * DAY + 1) === false);

  const staleUpdate = updateFeedCache(accepted.cache, 'google-common', {
    creationTime: '2026-11-01T00:00:00Z',
    prefixes: [{ ipv4Prefix: '198.51.100.0/24' }],
  }, nowMs);
  check('cache rejects a stale update', staleUpdate.status === 'stale');
  check('cache keeps last-known-good on stale', staleUpdate.cache.entries['google-common'] === cached);

  const invalidUpdate = updateFeedCache(accepted.cache, 'google-common', hostileFeeds.malformed, nowMs);
  check('cache rejects an unparseable creationTime', invalidUpdate.status === 'stale');
  check('cache keeps last-known-good on invalid feed', invalidUpdate.cache.entries['google-common'] === cached);
  const noPrefixUpdate = updateFeedCache(accepted.cache, 'google-common', { creationTime: null, prefixes: [] }, nowMs);
  check('cache rejects a feed with no valid prefixes', noPrefixUpdate.status === 'rejected');
  check('cache keeps last-known-good on empty feed', noPrefixUpdate.cache.entries['google-common'] === cached);

  const lkgLookup = buildLookup(noPrefixUpdate.cache.entries['google-common'].parsed.prefixes as unknown as Record<string, unknown>);
  check('last-known-good still matches its original IP', matchIp(buildLookup({ 'google-common': { prefixes: [{ ipv4Prefix: '66.249.66.0/27' }] } }), '66.249.66.1').matched === true);
  check('rejected bogus prefix never enters the cache', !JSON.stringify(lkgLookup).includes('198.51.100'));

  const openAiCached = updateFeedCache(EMPTY_FEED_CACHE, 'gptbot', feeds.gptbot, nowMs).cache.entries['gptbot'];
  check('uncadenced feed has infinite TTL', isCacheEntryUsable(openAiCached, nowMs + 365 * DAY) === true);
  noThrow('updateFeedCache(null, ...) does not throw', () => updateFeedCache(null, null, null, nowMs).cache as FeedCache);

  /* --- summary ----------------------------------------------------------- */
  if (failures > 0) {
    console.error(`\n${failures} of ${assertions} assertion(s) failed`);
    process.exit(1);
  }
  console.log(`\nAll ${assertions} official-bot-feed assertions passed`);
}

main();

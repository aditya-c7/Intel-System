/**
 * Official bot feed verification helpers — isolated test suite (RS5).
 *
 *   npx tsx scripts/test-official-bot-feeds.ts
 *
 * Uses only scripts/fixtures/official-bot-feeds.json (synthetic, representative
 * CIDRs + RFC 5737/3849 documentation addresses) plus the frozen pinned-snapshot
 * store in src/lib/agentFeedSnapshots.ts. No network, no third-party SDK.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  AGENT_BY_ID,
  AGENT_REGISTRY,
  AI_AGENT_UA_RULES,
  AI_BOT_CIDR_SOURCES,
  BOT_DIRECTORY,
  findAgentByUa,
  GOOD_BOT_UA_RULES,
  normalizeFeed,
  PILLS,
  PREFIX_FEEDS,
} from '../src/lib/agentRegistry';
import { FEED_METADATA, PINNED_PREFIXES } from '../src/lib/agentFeedSnapshots';
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

  /* --- registry prefix feeds + frozen pinned snapshots ------------------- */
  // The extended operator catalog (fetched 2026-11-27, see FEED_METADATA notes): every
  // PREFIX_FEEDS entry must expose a pinned snapshot whose shape and prefix count match
  // the live feed, and the derived registry views must still resolve the new agents.
  const NEW_FEED_PREFIX_COUNTS: Record<string, number> = {
    'google-user-triggered-agents': 4,
    'google-special-crawlers': 272,
    'google-user-triggered-fetchers': 1096,
    'google-user-triggered-fetchers-google': 504,
    'openai-adsbot': 2,
    'duckduckbot': 486,
    'ahrefs': 81,
    'hark': 1,
  };
  const CIDR_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}\/(?:\d|[12]\d|3[0-2])$|^[0-9A-Fa-f:]+\/(?:\d{1,3})$/;
  for (const id of Object.keys(NEW_FEED_PREFIX_COUNTS)) {
    const feed = PREFIX_FEEDS.find((entry) => entry.sourceId === id);
    check(`prefix feed ${id} is registered`, Boolean(feed));
    check(
      `prefix feed ${id} declares json format, daily refresh and a bounded maxBytes`,
      feed?.format === 'json' && feed?.refreshMs === DAY && feed?.pinnedKey === id
        && typeof feed?.maxBytes === 'number' && feed.maxBytes >= 1_000_000 && feed.maxBytes <= 8_000_000,
      feed,
    );
    check(
      `prefix feed ${id} is exposed to CIDR consumers`,
      AI_BOT_CIDR_SOURCES.some((s) => s.id === id && s.url === feed?.url),
    );
    const pinned = PINNED_PREFIXES[id];
    check(`pinned snapshot exists for ${id}`, Array.isArray(pinned) && pinned.length > 0);
    check(`pinned snapshot ${id} prefix count matches the live feed`, pinned?.length === NEW_FEED_PREFIX_COUNTS[id], pinned?.length);
    check(`pinned snapshot ${id} holds canonical CIDR prefixes`, (pinned ?? []).every((p) => CIDR_PATTERN.test(p)));
    check(`pinned snapshot ${id} has no duplicate prefixes`, new Set(pinned ?? []).size === pinned?.length);
    const meta = FEED_METADATA[id];
    check(`FEED_METADATA documents ${id}`, Boolean(meta), meta);
    // Round-trip the first pinned prefixes through the pure normalizer (synthetic body only).
    const sample = (pinned ?? []).slice(0, 3).map((p) => (p.includes(':') ? { ipv6Prefix: p } : { ipv4Prefix: p }));
    const normalized = normalizeFeed(id, JSON.stringify({ creationTime: meta?.creationTime ?? undefined, prefixes: sample }));
    check(`normalizeFeed round-trips ${id} prefixes`, JSON.stringify(normalized.prefixes) === JSON.stringify((pinned ?? []).slice(0, 3)), normalized.prefixes);
    check(`normalizeFeed round-trips ${id} creationTime`, normalized.creationTime === (meta?.creationTime ?? null), normalized.creationTime);
  }
  // Every pinnedKey across the whole catalog resolves to a frozen snapshot (old + new).
  check(
    'every PREFIX_FEEDS pinnedKey resolves into PINNED_PREFIXES',
    PREFIX_FEEDS.every((feed) => feed.pinnedKey === undefined || Array.isArray(PINNED_PREFIXES[feed.pinnedKey])),
  );

  /* --- registry entries for the new agents -------------------------------- */
  const googleAgent = AGENT_BY_ID['google_agent'];
  const harkBot = AGENT_BY_ID['hark_bot'];
  check(
    'google_agent verifies via the user-triggered-agents CIDR feed',
    googleAgent?.feedIds?.includes('google-user-triggered-agents') === true
      && googleAgent?.minProofForVerified === 'cidr'
      && googleAgent?.signature?.agentHosts?.includes('agent.bot.goog') === true,
  );
  check(
    'hark_bot is an RFC 9421 signed agent on the hark feed',
    harkBot?.feedIds?.includes('hark') === true
      && harkBot?.signature?.wbaRequired === true
      && harkBot?.signature?.agentHosts?.includes('hark.com') === true
      && harkBot?.minProofForVerified === 'signed_agent',
  );
  check('google_agent UA resolves ahead of gemini_deep_research', findAgentByUa('Mozilla/5.0 (compatible; Google-Agent/1.0)')?.id === 'google_agent');
  check('hark_bot UA resolves to the exact version-anchored token', findAgentByUa('Mozilla/5.0 (compatible; HarkBot/1.0)')?.id === 'hark_bot');
  check('registry rank ordering stays ascending', AGENT_REGISTRY.every((agent, i, arr) => i === 0 || arr[i - 1].rank <= agent.rank));
  check(
    'derived directory holds google_agent unverified (UA-impersonable) and hark_bot signed',
    BOT_DIRECTORY.find((e) => e.name === 'Google-Agent')?.identity === 'unknown'
      && BOT_DIRECTORY.find((e) => e.name === 'HarkBot')?.identity === 'signed'
      && BOT_DIRECTORY.find((e) => e.name === 'HarkBot')?.requiresWebBotAuth === true,
  );
  check(
    'PILLS cover the new agents',
    PILLS['google_agent']?.label === 'Google-Agent' && PILLS['hark_bot']?.label === 'HarkBot',
  );

  /* --- extended crawler catalog: per-crawler registry coverage ----------------------------
     Every crawler in the owner's target list must resolve by UA to the right id + category.
     Tokens already covered by earlier entries (googlebot, bingbot, applebot, gptbot family,
     claude family, perplexity family, amazonbot, ccbot, meta-externalagent, DuckAssistBot,
     Meta Muse, Anchor Browser) resolve to their EXISTING ids — no duplicate entries exist. */
  interface CoverageCase { ua: string; id: string; category: string }
  const COVERAGE_CASES: CoverageCase[] = [
    // Search engine crawlers (new)
    { ua: 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)', id: 'baiduspider', category: 'search_crawler' },
    { ua: 'Mozilla/5.0 (compatible; Baiduspider-image/2.0; +http://www.baidu.com/search/spider.html)', id: 'baiduspider', category: 'search_crawler' },
    { ua: 'Mozilla/5.0 (compatible;Baiduspider+(+http://www.baidu.com/search/spider.htm))', id: 'baiduspider', category: 'search_crawler' },
    { ua: 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)', id: 'yandex_bot', category: 'search_crawler' },
    { ua: 'Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)', id: 'yandex_bot', category: 'search_crawler' },
    { ua: 'Mozilla/5.0 (compatible; YandexMetrika/2.0; +http://yandex.com/bots)', id: 'yandex_bot', category: 'search_crawler' },
    { ua: 'Mozilla/5.0 (compatible; YaDirectFetcher/1.0; +http://yandex.com/bots)', id: 'yandex_bot', category: 'search_crawler' },
    { ua: 'Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot.html)', id: 'duckduckbot', category: 'search_crawler' },
    { ua: 'Mozilla/5.0 (compatible; TerraCotta https://github.com/CeramicTeam/CeramicTerracotta)', id: 'terracotta_bot', category: 'search_crawler' },
    { ua: 'Mozilla/5.0 (compatible; Terracotta-News/1.0)', id: 'terracotta_bot', category: 'search_crawler' },
    // Archivers (new category)
    { ua: 'Mozilla/5.0 (compatible; archive.org_bot; Wayback Machine Living Web Archive; +http://archive.org/details/archive.org_bot)', id: 'archive_bot', category: 'archiver' },
    { ua: 'ia_archiver', id: 'archive_bot', category: 'archiver' },
    { ua: 'Mozilla/5.0 (compatible; Arquivo-web-crawler; +https://arquivo.pt/faq/crawling)', id: 'arquivo_bot', category: 'archiver' },
    // AI crawlers / assistants (new)
    { ua: 'Mozilla/5.0 (compatible; Bytespider; https://asemangel.github.io/about)', id: 'bytespider', category: 'ai_crawler' },
    { ua: 'Mozilla/5.0 (compatible; TikTokSpider/1.0; +https://www.tiktok.com)', id: 'tiktok_spider', category: 'ai_crawler' },
    { ua: 'Google-CloudVertexBot/1.0', id: 'cloudvertex_bot', category: 'ai_crawler' },
    { ua: 'Mozilla/5.0 (compatible; FacebookBot/1.0; +https://developers.facebook.com/docs/sharing/webmasters/crawler)', id: 'facebookbot', category: 'ai_crawler' },
    { ua: 'meta-externalfetcher/1.0 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)', id: 'meta_external_fetcher', category: 'ai_assistant' },
    { ua: 'Mozilla/5.0 (compatible;PetalBot;+https://aspiegel.com/petalbot)', id: 'petalbot', category: 'ai_crawler' },
    { ua: 'Mozilla/5.0 (compatible; ProRataInc/1.0; +https://www.prorata.com)', id: 'prorata_inc', category: 'ai_crawler' },
    { ua: 'Mozilla/5.0 (compatible; Timpibot/0.2; +https://timpi.io)', id: 'timpibot', category: 'ai_crawler' },
    { ua: 'Mozilla/5.0 (compatible; Novellum/1.0; +https://novellum.ai)', id: 'novellum_ai_crawl', category: 'ai_crawler' },
    { ua: 'Mozilla/5.0 (compatible; NovellumAICrawl/1.0)', id: 'novellum_ai_crawl', category: 'ai_crawler' },
    // Target-list tokens that ALREADY had registry entries keep resolving there.
    { ua: 'meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)', id: 'meta_external_agent', category: 'ai_search' },
    { ua: 'Mozilla/5.0 (compatible; DuckAssistBot/1.0; +http://duckduckgo.com/duckassistbot.html)', id: 'duck_assist_bot', category: 'ai_assistant' },
    { ua: 'Mozilla/5.0 AppleWebKit/537.36 Muse/1.0', id: 'meta_muse', category: 'ai_agent' },
    { ua: 'Mozilla/5.0 AnchorBrowser/1.0', id: 'anchor_browser', category: 'ai_browser' },
    // The new entries must not swallow the pre-existing neighbor tokens.
    { ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', id: 'googlebot', category: 'search_crawler' },
    { ua: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/120.0.0.0 Safari/537.36', id: 'bingbot', category: 'search_crawler' },
    { ua: 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claude.com/cli)', id: 'claude_bot', category: 'ai_crawler' },
    { ua: 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)', id: 'gptbot', category: 'ai_crawler' },
  ];
  for (const c of COVERAGE_CASES) {
    const found = findAgentByUa(c.ua);
    check(
      `coverage ${c.id} resolves the operator token`,
      found?.id === c.id && found?.category === c.category,
      { ua: c.ua, found: found?.id, category: found?.category },
    );
  }

  /* --- extended catalog: verification wiring ---------------------------------------------- */
  // Baidu publishes no IP ranges; its documented contract is FCrDNS (*.baidu.com / *.baidu.jp).
  const baidu = AGENT_BY_ID['baiduspider'];
  check(
    'baiduspider verifies via operator-documented FCrDNS (*.baidu.com / *.baidu.jp), no CIDR feed',
    baidu?.category === 'search_crawler'
      && baidu?.fcrdnsSuffixes?.join(',') === 'baidu.com,baidu.jp'
      && baidu?.minProofForVerified === 'fcrdns'
      && !baidu?.feedIds
      && Boolean(baidu?.ua?.requireNetworkMatch),
    baidu,
  );
  // Yandex's webmaster docs publish the same FCrDNS shape for every Yandex robot.
  const yandex = AGENT_BY_ID['yandex_bot'];
  check(
    'yandex_bot verifies via operator-documented FCrDNS (*.yandex.ru / .net / .com)',
    yandex?.category === 'search_crawler'
      && yandex?.fcrdnsSuffixes?.join(',') === 'yandex.ru,yandex.net,yandex.com'
      && yandex?.minProofForVerified === 'fcrdns'
      && !yandex?.feedIds,
    yandex,
  );
  // DuckDuckBot rides the already-pinned official DuckDuckGo CIDR feed.
  const duckDuck = AGENT_BY_ID['duckduckbot'];
  check(
    'duckduckbot verifies via the pinned official DuckDuckGo CIDR feed',
    duckDuck?.category === 'search_crawler'
      && duckDuck?.feedIds?.includes('duckduckbot') === true
      && duckDuck?.minProofForVerified === 'cidr'
      && Array.isArray(PINNED_PREFIXES['duckduckbot'])
      && PINNED_PREFIXES['duckduckbot'].length === 486,
    duckDuck,
  );
  // CloudVertexBot: no dedicated ipranges file (developers.google.com …/vertexbot.json is
  // HTTP 404) — Google extends the Googlebot reverse-DNS contract to it instead.
  const cloudvertex = AGENT_BY_ID['cloudvertex_bot'];
  check(
    'cloudvertex_bot verifies via the Googlebot FCrDNS contract, never a fabricated feed',
    cloudvertex?.category === 'ai_crawler'
      && cloudvertex?.fcrdnsSuffixes?.join(',') === 'googlebot.com,google.com'
      && cloudvertex?.minProofForVerified === 'fcrdns'
      && !cloudvertex?.feedIds,
    cloudvertex,
  );
  // Every ua_claim-only catalog entry: token is a claim, identity stays unknown.
  const CLAIM_ONLY_IDS = [
    'terracotta_bot', 'bytespider', 'tiktok_spider', 'facebookbot', 'meta_external_fetcher',
    'petalbot', 'prorata_inc', 'timpibot', 'novellum_ai_crawl', 'archive_bot', 'arquivo_bot',
  ] as const;
  check(
    'ua_claim-only catalog entries carry no feeds/suffixes and stay unverified from a UA',
    CLAIM_ONLY_IDS.every((id) => {
      const agent = AGENT_BY_ID[id];
      return agent?.minProofForVerified === 'ua_claim'
        && !agent?.feedIds
        && !agent?.fcrdnsSuffixes
        && BOT_DIRECTORY.find((e) => e.name === agent.displayName)?.identity === 'unknown';
    }),
  );
  check(
    'archivers are a derived archiver category, never a good-bot verdict path',
    AGENT_BY_ID['archive_bot']?.category === 'archiver'
      && AGENT_BY_ID['arquivo_bot']?.category === 'archiver'
      && BOT_DIRECTORY.find((e) => e.name === 'Archive.org Bot')?.category === 'archiver'
      // AI_AGENT_UA_RULES only covers ai_*/automation categories — archivers stay out.
      && !AI_AGENT_UA_RULES.some((r) => r.label === 'Archive.org Bot')
      && !AI_AGENT_UA_RULES.some((r) => r.label === 'Arquivo Web Crawler'),
  );
  check(
    'network-gated GOOD_BOT_UA_RULES gained the operator-documented crawlers',
    GOOD_BOT_UA_RULES.some((r) => r.label === 'Baiduspider' && Boolean(r.network?.test('baidu')))
      && GOOD_BOT_UA_RULES.some((r) => r.label === 'YandexBot' && Boolean(r.network?.test('yandex')))
      && GOOD_BOT_UA_RULES.some((r) => r.label === 'DuckDuckBot')
      && GOOD_BOT_UA_RULES.some((r) => r.label === 'Google-CloudVertexBot'),
  );
  check(
    'PILLS cover every extended-crawler entry',
    [
      'baiduspider', 'yandex_bot', 'duckduckbot', 'archive_bot', 'arquivo_bot', 'cloudvertex_bot',
      'terracotta_bot', 'bytespider', 'tiktok_spider', 'facebookbot', 'meta_external_fetcher',
      'petalbot', 'prorata_inc', 'timpibot', 'novellum_ai_crawl', 'anchor_browser',
    ].every((id) => Boolean(PILLS[id])),
  );
  check(
    'anchor_browser keeps its existing entry and only gains the pill',
    AGENT_BY_ID['anchor_browser']?.pill?.kind === 'anchor'
      && AGENT_BY_ID['anchor_browser']?.which.includes('pill')
      && AGENT_BY_ID['anchor_browser']?.minProofForVerified === 'ua_claim',
  );
  // Ascending rank by specificity: exact CloudVertexBot token must outrank the broader
  // googlebot alternation set, and the registry array itself stays monotonic (next check).
  check(
    'cloudvertex UA resolves ahead of googlebot family entries',
    findAgentByUa('Google-CloudVertexBot/1.0')?.id === 'cloudvertex_bot'
      && findAgentByUa('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')?.id === 'googlebot',
  );

  /* --- summary ----------------------------------------------------------- */
  if (failures > 0) {
    console.error(`\n${failures} of ${assertions} assertion(s) failed`);
    process.exit(1);
  }
  console.log(`\nAll ${assertions} official-bot-feed assertions passed`);
}

main();

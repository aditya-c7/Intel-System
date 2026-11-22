/**
 * Zero-trust shadow suite (dependency-free).
 *
 *   npx tsx scripts/test-zero-trust.ts
 *
 * Covers the strict origin/referer cross-check, the 65-second sealed-envelope freshness
 * boundary and one-shot replay detection, and the replay-rate attack threshold with its
 * small-sample guard. Hostile/non-shape inputs are asserted to be non-throwing.
 */
import {
  checkStrictOrigin,
  ipReplayRate,
  replayWindowStatus,
} from '../src/lib/zeroTrust.ts';

let passed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail = ''): void {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}${detail ? ` (${detail})` : ''}`);
    return;
  }
  failures.push(name);
  console.log(`  FAIL  ${name}${detail ? ` (${detail})` : ''}`);
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

function noThrow<T>(fn: () => T): T | null {
  try {
    return fn();
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* checkStrictOrigin                                                           */
/* -------------------------------------------------------------------------- */
section('checkStrictOrigin');

const agreeingOrigin = checkStrictOrigin({
  origin: 'https://intel.example',
  clientUrl: 'https://intel.example/path?q=1',
});
check(
  'matching Origin and client url are accepted',
  agreeingOrigin.ok && /corroborate/i.test(agreeingOrigin.reason),
  agreeingOrigin.reason
);

const agreeingReferer = checkStrictOrigin({
  referer: 'https://search.example/results?q=intel',
  clientReferrer: 'https://search.example/results?q=intel#fragment',
});
check(
  'matching Referer and client referrer ignore the stripped fragment',
  agreeingReferer.ok && /corroborate/i.test(agreeingReferer.reason),
  agreeingReferer.reason
);

const contradiction = checkStrictOrigin({
  origin: 'https://evil.example',
  clientUrl: 'https://intel.example/dashboard',
});
check(
  'contradictory Origin is rejected even when the client claims a good url',
  !contradiction.ok && /contradicts/.test(contradiction.reason),
  contradiction.reason
);

const partialAgreement = checkStrictOrigin({
  origin: 'https://intel.example',
  clientUrl: 'https://intel.example/',
  referer: 'https://evil.example/landing',
  clientReferrer: 'https://intel.example/landing',
});
check(
  'one agreeing header never approves a contradiction in the other',
  !partialAgreement.ok && /Referer/.test(partialAgreement.reason),
  partialAgreement.reason
);

const legacy = checkStrictOrigin({ clientUrl: 'https://intel.example/' });
check(
  'absent headers are accepted as legacy with an explicit reason',
  legacy.ok && /legacy/i.test(legacy.reason) && /without corroboration/i.test(legacy.reason),
  legacy.reason
);

const empty = checkStrictOrigin({});
check('fully empty input is accepted without throwing', empty.ok && /legacy/i.test(empty.reason), empty.reason);

const opaqueOrigin = checkStrictOrigin({
  origin: 'null',
  clientUrl: 'https://intel.example/',
  referer: 'https://intel.example/home',
  clientReferrer: 'https://intel.example/home',
});
check(
  'opaque "null" Origin is reported unusable, not treated as agreement',
  opaqueOrigin.ok && /unusable Origin/i.test(opaqueOrigin.reason),
  opaqueOrigin.reason
);

const hostileOrigin = noThrow(() =>
  checkStrictOrigin({
    origin: 42 as unknown as string,
    referer: {} as unknown as string,
    clientUrl: [] as unknown as string,
    clientReferrer: 'not a url',
    nowMs: Number.NaN,
  })
);
check(
  'hostile field types do not throw and are reported as unusable',
  hostileOrigin !== null &&
    hostileOrigin.ok &&
    /unusable/i.test(hostileOrigin.reason) &&
    /invalid nowMs/i.test(hostileOrigin.reason),
  hostileOrigin?.reason ?? 'threw'
);

const nullInput = noThrow(() => checkStrictOrigin(null as unknown as Parameters<typeof checkStrictOrigin>[0]));
check('null input object does not throw', nullInput !== null && nullInput.ok, nullInput?.reason ?? 'threw');

const truncatedReferer = checkStrictOrigin({
  referer: 'https://intel.example/',
  clientReferrer: 'https://intel.example/page?x=1',
});
check(
  'strict-origin-when-cross-origin style truncation is compatible',
  truncatedReferer.ok,
  truncatedReferer.reason
);

const prefixBoundary = checkStrictOrigin({
  referer: 'https://intel.example/account',
  clientReferrer: 'https://intel.example/accounting',
});
check(
  'a referer path prefix is not a loose substring match',
  !prefixBoundary.ok && /contradicts/.test(prefixBoundary.reason),
  prefixBoundary.reason
);

const schemeMismatch = checkStrictOrigin({
  origin: 'http://intel.example',
  clientUrl: 'https://intel.example/',
});
check('http vs https origins contradict', !schemeMismatch.ok, schemeMismatch.reason);

const portMismatch = checkStrictOrigin({
  origin: 'https://intel.example:8443',
  clientUrl: 'https://intel.example/',
});
check('port mismatches contradict', !portMismatch.ok, portMismatch.reason);

/* -------------------------------------------------------------------------- */
/* replayWindowStatus — 65s envelope semantics                                 */
/* -------------------------------------------------------------------------- */
section('replayWindowStatus');

const BASE = 1_000_000;
const boundary = replayWindowStatus(BASE, BASE + 65_000);
check('age exactly 65000ms is still fresh (inclusive boundary)', boundary.fresh && !boundary.duplicate, boundary.reason);

const pastBoundary = replayWindowStatus(BASE, BASE + 65_001);
check('age 65001ms is stale', !pastBoundary.fresh && /stale/i.test(pastBoundary.reason), pastBoundary.reason);

const customWindow = replayWindowStatus(BASE, BASE + 1_000, undefined, 1_000);
check('custom maxAgeMs boundary is honored', customWindow.fresh, customWindow.reason);

const customStale = replayWindowStatus(BASE, BASE + 1_001, undefined, 1_000);
check('custom maxAgeMs overflow is stale', !customStale.fresh, customStale.reason);

const replay = replayWindowStatus(BASE, BASE + 1_000, 'nonce-abc');
check('a seen nonce is a duplicate while the envelope is still fresh', replay.fresh && replay.duplicate, replay.reason);
check('duplicate reason names the replay', /replay/i.test(replay.reason), replay.reason);

const staleReplay = replayWindowStatus(BASE, BASE + 70_000, 'nonce-abc');
check('staleness and replay are reported independently', !staleReplay.fresh && staleReplay.duplicate && /stale/i.test(staleReplay.reason) && /replay/i.test(staleReplay.reason), staleReplay.reason);

const emptyNonce = replayWindowStatus(BASE, BASE + 1_000, '   ');
check('blank nonce is not a duplicate', !emptyNonce.duplicate && emptyNonce.fresh, emptyNonce.reason);

const toleratedFuture = replayWindowStatus(BASE + 60_000, BASE);
check('60s of future clock skew stays fresh', toleratedFuture.fresh, toleratedFuture.reason);

const extremeFuture = replayWindowStatus(BASE + 300_001, BASE);
check('future timestamps beyond 5 minutes are not fresh', !extremeFuture.fresh && /future/i.test(extremeFuture.reason), extremeFuture.reason);

const zeroTimestamp = replayWindowStatus(0, BASE);
check('a zero timestamp is unverifiable, not fresh', !zeroTimestamp.fresh && /invalid/i.test(zeroTimestamp.reason), zeroTimestamp.reason);

const hostileReplay = noThrow(() =>
  replayWindowStatus(Number.NaN as unknown as number, '1000000' as unknown as number, 123 as unknown as string)
);
check(
  'hostile replay inputs do not throw',
  hostileReplay !== null && !hostileReplay.fresh && /invalid/i.test(hostileReplay.reason),
  hostileReplay?.reason ?? 'threw'
);

const badMaxAge = noThrow(() => replayWindowStatus(BASE, BASE + 65_001, undefined, Number.POSITIVE_INFINITY));
check(
  'an invalid maxAgeMs falls back to the 65s envelope window',
  badMaxAge !== null && !badMaxAge.fresh,
  badMaxAge?.reason ?? 'threw'
);

/* -------------------------------------------------------------------------- */
/* ipReplayRate — 75% with a 20-sample guard                                   */
/* -------------------------------------------------------------------------- */
section('ipReplayRate');

const exactThreshold = ipReplayRate(15, 20);
check('15/20 (75%) with 20 samples is an attack source', exactThreshold.attack_source && exactThreshold.ratio === 0.75, JSON.stringify(exactThreshold));

const smallSample = ipReplayRate(15, 19);
check('15/19 (79%) is not an attack source: 20-sample guard', !smallSample.attack_source && smallSample.ratio > 0.75, JSON.stringify(smallSample));

const tinySample = ipReplayRate(3, 4);
check('3/4 (75%) is not an attack source', !tinySample.attack_source, JSON.stringify(tinySample));

const belowThreshold = ipReplayRate(14, 20);
check('14/20 (70%) is not an attack source', !belowThreshold.attack_source, JSON.stringify(belowThreshold));

const largeBelowThreshold = ipReplayRate(749, 1000);
check('749/1000 (74.9%) stays below the threshold', !largeBelowThreshold.attack_source, JSON.stringify(largeBelowThreshold));

const largeAboveThreshold = ipReplayRate(751, 1000);
check('751/1000 (75.1%) is an attack source', largeAboveThreshold.attack_source, JSON.stringify(largeAboveThreshold));

const noSamples = ipReplayRate(5, 0);
check('zero total yields ratio 0 and no attack source', noSamples.ratio === 0 && !noSamples.attack_source, JSON.stringify(noSamples));

const windowAgnostic = ipReplayRate(15, 20, 30);
check('windowDays is descriptive and does not change the decision', windowAgnostic.attack_source && windowAgnostic.ratio === exactThreshold.ratio, JSON.stringify(windowAgnostic));

const hostileRate = noThrow(() => ipReplayRate(Number.POSITIVE_INFINITY, Number.NaN, -5));
check(
  'hostile rate inputs do not throw and clamp to ratio 0',
  hostileRate !== null && hostileRate.ratio === 0 && !hostileRate.attack_source,
  hostileRate ? JSON.stringify(hostileRate) : 'threw'
);

const overCount = ipReplayRate(50, 20);
check('replayed > total clamps the ratio to 1', overCount.ratio === 1 && overCount.attack_source, JSON.stringify(overCount));

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log(`FAILED: ${failures.join(' | ')}`);
  process.exit(1);
}

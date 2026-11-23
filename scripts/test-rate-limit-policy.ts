/**
 * RS9 rate-limit policy regression suite for `src/lib/rateLimitPolicy.ts`.
 *
 * Covers: 429 void/evaluable classification, Retry-After parsing (delay-seconds and
 * HTTP-date), budget overflow, capped exponential backoff + full jitter bounds, token-bucket
 * pacing, the 429 ledger, hostile input, purity and determinism. Nothing here sleeps,
 * schedules work, touches the network or writes state.
 *
 *   npx tsx scripts/test-rate-limit-policy.ts
 *
 * Exits non-zero when any assertion fails.
 */
import assert from 'node:assert/strict';

import {
  backoffDelayMs,
  backoffDelayRange,
  classifyRateLimit,
  DEFAULT_MAX_CONCURRENCY,
  DEFAULT_PACING_FRACTION,
  MAX_PACING_FRACTION,
  MAX_RATE_LIMIT_RETRIES,
  MIN_FALLBACK_WAIT_MS,
  MIN_PACING_FRACTION,
  NOT_EVALUABLE_FAIL_THRESHOLD,
  NO_REFILL_NEXT_MS,
  parseRetryAfter,
  rateLimitLedger,
  retryExhausted,
  tokenBucket,
} from '../src/lib/rateLimitPolicy';

let passed = 0;
const failures: string[] = [];

function check(name: string, verify: () => void): void {
  try {
    verify();
    passed += 1;
    console.log(`  PASS  ${name}`);
  } catch (error) {
    failures.push(name);
    console.error(`  FAIL  ${name}`);
    console.error(`        ${error instanceof Error ? error.message : String(error)}`);
  }
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

/* -------------------------------------------------------------------------- */
/* 1. parseRetryAfter                                                         */
/* -------------------------------------------------------------------------- */

section('1. Retry-After parsing (delay-seconds | HTTP-date)');

check('P1 numeric delay-seconds is honored exactly', () => {
  assert.equal(parseRetryAfter(12), 12);
  assert.equal(parseRetryAfter(0), 0);
});

check('P2 numeric string delay-seconds is parsed', () => {
  assert.equal(parseRetryAfter('120'), 120);
  assert.equal(parseRetryAfter('  7.5  '), 7.5);
  assert.equal(parseRetryAfter('+3'), 3);
});

check('P3 HTTP-date is relative to the supplied nowMs reference', () => {
  const now = Date.parse('2026-01-01T00:00:00Z');
  const later = 'Wed, 07 Jan 2026 00:00:00 GMT'; // 6 days ahead
  assert.equal(parseRetryAfter(later, now), 6 * 24 * 60 * 60);
});

check('P4 HTTP-date in the past clamps to zero seconds', () => {
  const now = Date.parse('2026-01-01T00:00:00Z');
  assert.equal(parseRetryAfter('Tue, 30 Dec 2025 00:00:00 GMT', now), 0);
});

check('P5 invalid / negative / wrong-type Retry-After returns null', () => {
  for (const raw of ['not-a-date', '', -1, Number.NaN, Infinity, null, undefined, {}, [], true]) {
    assert.equal(parseRetryAfter(raw), null, `raw=${String(raw)}`);
  }
});

check('P6 hostile objects and hostile nowMs do not throw', () => {
  const hostile = {
    get value(): unknown {
      throw new Error('getter exploded');
    },
  };
  assert.doesNotThrow(() => parseRetryAfter(hostile));
  assert.equal(parseRetryAfter(hostile), null);
  assert.equal(parseRetryAfter('5', 'not-a-number'), 5);
});

/* -------------------------------------------------------------------------- */
/* 2. classifyRateLimit                                                       */
/* -------------------------------------------------------------------------- */

section('2. 429 classification: void / evaluable / retry / abort');

check('C1 non-429 (and string non-429) carries no rate-limit signal', () => {
  const ok = classifyRateLimit({ status: 200, retryAfterSeconds: 5 });
  assert.equal(ok.classification, 'ok');
  assert.equal(ok.waitMs, null);
  assert.equal(classifyRateLimit({ status: '503' }).classification, 'ok');
});

check('C2 Retry-After is honored exactly, in milliseconds', () => {
  const decision = classifyRateLimit({ status: 429, retryAfterSeconds: 2.5, runBudgetMs: 300_000 });
  assert.equal(decision.classification, 'retry');
  assert.equal(decision.waitMs, 2500);
  assert.match(decision.reason, /^retry_after_honored_exactly$/);
});

check('C3 Retry-After equal to the run budget is still allowed', () => {
  const decision = classifyRateLimit({ status: 429, retryAfterSeconds: 10, runBudgetMs: 10_000 });
  assert.equal(decision.classification, 'retry');
  assert.equal(decision.waitMs, 10_000);
});

check('C4 Retry-After beyond the run budget aborts as NOT EVALUABLE', () => {
  const decision = classifyRateLimit({ status: 429, retryAfterSeconds: 61, runBudgetMs: 60_000 });
  assert.equal(decision.classification, 'not_evaluable');
  assert.equal(decision.waitMs, null, 'an aborted case must never inflate latency with a sleep');
  assert.match(decision.reason, /retry_after_exceeds_run_budget/);
});

check('C5 missing Retry-After waits at least 60s then uses exponential backoff', () => {
  const decision = classifyRateLimit({ status: 429, runBudgetMs: 120_000 });
  assert.equal(decision.classification, 'retry');
  assert.ok((decision.waitMs as number) >= MIN_FALLBACK_WAIT_MS);
  assert.match(decision.reason, /no_retry_after:wait>=60s_then_capped_exponential_backoff/);
});

check('C6 a too-small budget also aborts the >=60s fallback', () => {
  const decision = classifyRateLimit({ status: 429, runBudgetMs: 30_000 });
  assert.equal(decision.classification, 'not_evaluable');
  assert.equal(decision.waitMs, null);
  assert.match(decision.reason, /fallback_wait_exceeds_run_budget/);
});

check('C7 harness/shared-egress 429 is voided before any retry logic', () => {
  const decision = classifyRateLimit({
    status: 429,
    retryAfterSeconds: 1,
    runBudgetMs: 60_000,
    harnessAttributable: true,
  });
  assert.equal(decision.classification, 'not_evaluable');
  assert.equal(decision.waitMs, null);
  assert.match(decision.reason, /void_sample:429_attributable_to_harness_or_shared_egress/);
});

check('C8 a 429 is EVALUABLE only when rate-limit enforcement is under test', () => {
  const decision = classifyRateLimit({
    status: 429,
    retryAfterSeconds: 999,
    runBudgetMs: 0,
    testingRateLimit: true,
  });
  assert.equal(decision.classification, 'evaluable');
  assert.equal(decision.waitMs, null);
  assert.match(decision.reason, /rate_limit_enforcement_under_test/);
});

check('C9 harness attribution dominates even when testing rate limits', () => {
  const decision = classifyRateLimit({
    status: 429,
    harnessAttributable: true,
    testingRateLimit: true,
  });
  assert.equal(decision.classification, 'not_evaluable');
});

check('C10 retry exhaustion (>=5 attempts) voids the case', () => {
  assert.equal(retryExhausted(MAX_RATE_LIMIT_RETRIES - 1), false);
  assert.equal(retryExhausted(MAX_RATE_LIMIT_RETRIES), true);
  const decision = classifyRateLimit({ status: 429, attempt: 5, runBudgetMs: 999_999 });
  assert.equal(decision.classification, 'not_evaluable');
  assert.match(decision.reason, /retry_exhausted/);
});

check('C11 hostile input never throws and fails closed', () => {
  const hostiles: unknown[] = [null, undefined, 42, '429', [], () => 0, { status: Number.NaN }];
  for (const hostile of hostiles) {
    let decision: ReturnType<typeof classifyRateLimit> | undefined;
    assert.doesNotThrow(() => {
      decision = classifyRateLimit(hostile);
    }, `hostile=${String(hostile)}`);
    assert.ok(decision && ['ok', 'retry', 'not_evaluable', 'evaluable'].includes(decision.classification));
    assert.ok(decision && (decision.waitMs === null || decision.waitMs >= 0));
  }
});

check('C12 throwing getters are contained and void the sample', () => {
  const hostile = {
    get status(): unknown {
      throw new Error('status getter exploded');
    },
  };
  let decision: ReturnType<typeof classifyRateLimit> | undefined;
  assert.doesNotThrow(() => {
    decision = classifyRateLimit(hostile);
  });
  assert.equal(decision?.classification, 'not_evaluable');
});

check('C13 negative / string / NaN Retry-After falls back to the >=60s path', () => {
  for (const retryAfterSeconds of [-5, '5', Number.NaN, Infinity, null]) {
    const decision = classifyRateLimit({ status: 429, retryAfterSeconds, runBudgetMs: 120_000 });
    assert.equal(decision.classification, 'retry', `retryAfterSeconds=${String(retryAfterSeconds)}`);
    assert.ok((decision.waitMs as number) >= MIN_FALLBACK_WAIT_MS);
  }
});

check('C14 reasons are stable lowercase tokens', () => {
  const decisions = [
    classifyRateLimit({ status: 200 }),
    classifyRateLimit({ status: 429, retryAfterSeconds: 1, runBudgetMs: 1_000 }),
    classifyRateLimit({ status: 429, runBudgetMs: 0 }),
    classifyRateLimit({ status: 429, testingRateLimit: true }),
    classifyRateLimit(null),
  ];
  for (const decision of decisions) {
    assert.match(decision.reason, /^[a-z0-9_>=;:.-]+$/);
    assert.ok(decision.reason.length > 0);
  }
});

check('C15 classifyRateLimit is pure and deterministic', () => {
  const input = { status: 429, retryAfterSeconds: 1, runBudgetMs: 10_000 };
  const snapshot = JSON.stringify(input);
  assert.deepEqual(classifyRateLimit(input), classifyRateLimit(input));
  assert.equal(JSON.stringify(input), snapshot);
});

/* -------------------------------------------------------------------------- */
/* 3. backoffDelayMs / backoffDelayRange                                      */
/* -------------------------------------------------------------------------- */

section('3. Capped exponential backoff + full jitter');

const backoff = (attempt: number): number =>
  backoffDelayMs({ attempt, baseMs: 1000, capMs: 10_000, jitter: 0 });

check('B1 jitter=0 is deterministic capped exponential', () => {
  assert.equal(backoff(0), 1000);
  assert.equal(backoff(1), 2000);
  assert.equal(backoff(2), 4000);
  assert.equal(backoff(3), 8000);
});

check('B2 the cap is enforced (attempt 4 would be 16000)', () => {
  assert.equal(backoff(4), 10_000);
  assert.equal(backoff(20), 10_000);
});

check('B3 full-jitter range is [0, min(cap, base*2^n)]', () => {
  assert.deepEqual(backoffDelayRange({ attempt: 2, baseMs: 1000, capMs: 10_000 }), {
    minMs: 0,
    maxMs: 4000,
  });
  assert.equal(backoffDelayMs({ attempt: 2, baseMs: 1000, capMs: 10_000, jitter: true }), 4000);
});

check('B4 caller-supplied jitter samples stay inside the range', () => {
  const input = { attempt: 3, baseMs: 1000, capMs: 10_000, jitter: true } as const;
  const { minMs, maxMs } = backoffDelayRange(input);
  for (const jitterSample of [0, 0.1, 0.5, 0.9, 1]) {
    const delay = backoffDelayMs({ ...input, jitterSample });
    assert.ok(delay >= minMs && delay <= maxMs, `sample=${jitterSample} -> ${delay}`);
  }
  assert.equal(backoffDelayMs({ ...input, jitterSample: 0.5 }), 4000);
});

check('B5 out-of-range jitter samples are clamped into [0,1]', () => {
  const input = { attempt: 1, baseMs: 1000, capMs: 10_000, jitter: true } as const;
  assert.equal(backoffDelayMs({ ...input, jitterSample: -3 }), 0);
  assert.equal(backoffDelayMs({ ...input, jitterSample: 99 }), 2000);
  assert.equal(backoffDelayMs({ ...input, jitterSample: Number.NaN }), 2000);
});

check('B6 jitter mode draws no RNG: repeated calls are identical', () => {
  const input = { attempt: 2, baseMs: 1000, capMs: 10_000, jitter: true };
  assert.equal(backoffDelayMs(input), backoffDelayMs(input));
  assert.equal(backoffDelayMs(input), backoffDelayMs({ ...input }));
});

check('B7 the delay is monotonically non-decreasing until the cap', () => {
  const delays = [0, 1, 2, 3, 4, 5, 6].map(backoff);
  for (let i = 1; i < delays.length; i += 1) {
    assert.ok(delays[i] >= delays[i - 1]);
  }
});

check('B8 hostile / missing attempt, base and cap never throw', () => {
  const hostiles: unknown[] = [null, undefined, 'bad', [], Number.NaN, { get x(): never { throw new Error('x'); } }];
  for (const hostile of hostiles) {
    assert.doesNotThrow(() => backoffDelayMs(hostile));
    const range = backoffDelayRange(hostile);
    assert.ok(range.minMs === 0 && Number.isFinite(range.maxMs) && range.maxMs >= 0);
  }
  assert.ok(backoffDelayMs({ attempt: 1000, baseMs: 1000, capMs: 5000 }) <= 5000);
});

check('B9 both jitter flag forms (true / 1) enable jitter mode', () => {
  const base = { attempt: 0, baseMs: 1000, capMs: 10_000 };
  assert.equal(backoffDelayMs({ ...base, jitter: true }), 1000);
  assert.equal(backoffDelayMs({ ...base, jitter: 1 }), 1000);
});

/* -------------------------------------------------------------------------- */
/* 4. tokenBucket                                                             */
/* -------------------------------------------------------------------------- */

section('4. Proactive token-bucket pacing (70-80% of documented limit)');

check('T1 a full bucket allows one token and reports the remainder', () => {
  const result = tokenBucket({ tokens: 10, capacity: 10, refillPerSec: 0, nowMs: 1000, lastMs: 1000 });
  assert.equal(result.allowed, true);
  assert.equal(result.remaining, 6.5); // 10 * 0.75 - 1
  assert.equal(result.nextMs, 1000);
});

check('T2 refill is applied over the elapsed window, then one token is consumed', () => {
  const result = tokenBucket({ tokens: 0, capacity: 2, refillPerSec: 1, nowMs: 2000, lastMs: 1000 });
  assert.equal(result.allowed, false);
  assert.equal(result.remaining, 0.75); // 1s * 1/s * 0.75
  assert.equal(result.nextMs, 2334);
});

check('T3 a denied bucket reports a future nextMs', () => {
  const result = tokenBucket({ tokens: 0, capacity: 2, refillPerSec: 1, nowMs: 1000, lastMs: 1000 });
  assert.equal(result.allowed, false);
  assert.equal(result.remaining, 0);
  assert.equal(result.nextMs, 2334);
  assert.ok(result.nextMs > 1000);
});

check('T4 no refill available -> NO_REFILL_NEXT_MS sentinel', () => {
  const result = tokenBucket({ tokens: 0, capacity: 2, refillPerSec: 0, nowMs: 1000, lastMs: 0 });
  assert.equal(result.allowed, false);
  assert.equal(result.nextMs, NO_REFILL_NEXT_MS);
});

check('T5 a sub-one-token effective capacity can never allow a request', () => {
  const result = tokenBucket({ tokens: 1, capacity: 1, refillPerSec: 10, nowMs: 1000, lastMs: 900 });
  assert.equal(result.allowed, false);
  assert.equal(result.nextMs, NO_REFILL_NEXT_MS);
});

check('T6 pacing is clamped into the 70-80% band', () => {
  const base = { tokens: 10, capacity: 10, refillPerSec: 0, nowMs: 0, lastMs: 0 };
  assert.equal(tokenBucket({ ...base, pacingFraction: 1 }).remaining, 7); // 10 * 0.8 - 1
  assert.equal(tokenBucket({ ...base, pacingFraction: 0 }).remaining, 6); // 10 * 0.7 - 1
  assert.equal(tokenBucket({ ...base, pacingFraction: 0.75 }).remaining, 6.5);
});

check('T7 tokens are clamped to the effective (paced) capacity', () => {
  const result = tokenBucket({ tokens: 1000, capacity: 10, refillPerSec: 0, nowMs: 0, lastMs: 0 });
  assert.equal(result.remaining, 6.5);
  assert.ok(result.remaining < 7.5);
});

check('T8 time travel (now < last) grants no refill', () => {
  const result = tokenBucket({ tokens: 0, capacity: 10, refillPerSec: 100, nowMs: 500, lastMs: 1000 });
  assert.equal(result.allowed, false);
  assert.equal(result.remaining, 0);
});

check('T9 hostile input never throws and fails closed', () => {
  for (const hostile of [null, undefined, 42, 'bucket', [], { get x(): never { throw new Error('x'); } }]) {
    let result: ReturnType<typeof tokenBucket> | undefined;
    assert.doesNotThrow(() => {
      result = tokenBucket(hostile);
    });
    assert.equal(result?.allowed, false);
    assert.equal(result?.nextMs, NO_REFILL_NEXT_MS);
  }
});

check('T10 tokenBucket is deterministic and does not mutate its input', () => {
  const input = { tokens: 3, capacity: 5, refillPerSec: 2, nowMs: 5000, lastMs: 3000 };
  const snapshot = JSON.stringify(input);
  assert.deepEqual(tokenBucket(input), tokenBucket(input));
  assert.equal(JSON.stringify(input), snapshot);
});

check('T11 policy constants are pinned', () => {
  assert.equal(MIN_PACING_FRACTION, 0.7);
  assert.equal(DEFAULT_PACING_FRACTION, 0.75);
  assert.equal(MAX_PACING_FRACTION, 0.8);
  assert.equal(DEFAULT_MAX_CONCURRENCY, 4);
});

/* -------------------------------------------------------------------------- */
/* 5. rateLimitLedger                                                         */
/* -------------------------------------------------------------------------- */

section('5. 429 ledger and run gate');

const ledgerEvents = [
  { status: 429, endpoint: '/a', egress: 'eg-1', retryAfterSeconds: 5, window: '60s' },
  { status: 429, endpoint: '/a', egress: 'eg-1', harnessAttributable: true },
  { status: 200, endpoint: '/b' },
  { status: 429, endpoint: '/b', egress: 'eg-2', notEvaluable: true, retryAfterSeconds: 2 },
  {
    status: '429',
    endpoint: '/b',
    egress: 'eg-2',
    testingRateLimit: true,
    harnessAttributable: true,
  },
];

check('L1 only 429 events are counted', () => {
  assert.equal(rateLimitLedger(ledgerEvents).count, 4);
});

check('L2 byEndpoint aggregates counts, egresses, windows and Retry-After', () => {
  const { byEndpoint } = rateLimitLedger(ledgerEvents);
  assert.deepEqual(Object.keys(byEndpoint), ['/a', '/b']);
  assert.equal(byEndpoint['/a'].count, 2);
  assert.deepEqual(byEndpoint['/a'].egresses, ['eg-1']);
  assert.deepEqual(byEndpoint['/a'].windows, ['60s', 'unspecified']);
  assert.equal(byEndpoint['/a'].maxRetryAfterSeconds, 5);
  assert.equal(byEndpoint['/b'].maxRetryAfterSeconds, 2);
});

check('L3 not_evaluable_rate counts harness voids and explicit flags only', () => {
  const ledger = rateLimitLedger(ledgerEvents);
  assert.equal(ledger.byEndpoint['/a'].notEvaluable, 1);
  assert.equal(ledger.byEndpoint['/b'].notEvaluable, 1);
  assert.equal(ledger.notEvaluableRate, 0.5);
  assert.equal(NOT_EVALUABLE_FAIL_THRESHOLD, 0.1);
});

check('L4 an all-evaluable ledger has zero not_evaluable_rate', () => {
  const ledger = rateLimitLedger([{ status: 429, endpoint: '/x', testingRateLimit: true }]);
  assert.equal(ledger.notEvaluableRate, 0);
  assert.match(ledger.disclosure.join('|'), /PASS_RUN/);
});

check('L5 disclosure covers egress, retry, cache, pacing and run gate', () => {
  const text = rateLimitLedger(ledgerEvents).disclosure.join('\n');
  assert.match(text, /multi_egress_rotation_detected/);
  assert.match(text, /authenticated\/sanctioned capacity/);
  assert.match(text, /429_never_cached/);
  assert.match(text, /successful_metadata_only/);
  assert.match(text, /honor_exactly\(delay_seconds\|http_date\)/);
  assert.match(text, /token_bucket_at_70-80%_of_documented_limit/);
  assert.match(text, /FAIL_RUN/);
  assert.match(text, /run_failure_not_product_failure/);
});

check('L6 a single egress is disclosed as pinned, not rotated', () => {
  const text = rateLimitLedger([
    { status: 429, endpoint: '/a', egress: 'eg-1' },
    { status: 429, endpoint: '/a', egress: 'eg-1' },
  ]).disclosure.join('\n');
  assert.match(text, /egress_pinning: single_egress_per_sample; disclosed/);
  assert.doesNotMatch(text, /multi_egress_rotation_detected/);
});

check('L7 empty and non-array input is safe', () => {
  for (const input of [[], null, undefined, 42, 'events', {}]) {
    const ledger = rateLimitLedger(input);
    assert.equal(ledger.count, 0);
    assert.deepEqual(ledger.byEndpoint, {});
    assert.equal(ledger.notEvaluableRate, 0);
    assert.ok(ledger.disclosure.length > 0);
  }
});

check('L8 hostile events and throwing getters never throw', () => {
  const hostile = {
    get status(): unknown {
      throw new Error('status getter exploded');
    },
  };
  assert.doesNotThrow(() => rateLimitLedger([hostile, null, 5, 'event', []]));
  assert.equal(rateLimitLedger([hostile]).count, 0);
});

check('L9 hostile endpoint labels cannot poison the object prototype', () => {
  const ledger = rateLimitLedger([{ status: 429, endpoint: '__proto__' }]);
  assert.deepEqual(Object.keys(ledger.byEndpoint), ['[redacted]']);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
});

check('L10 ledger is deterministic and does not mutate its input', () => {
  const snapshot = JSON.stringify(ledgerEvents);
  assert.deepEqual(rateLimitLedger(ledgerEvents), rateLimitLedger(ledgerEvents));
  assert.equal(JSON.stringify(ledgerEvents), snapshot);
});

check('L11 Retry-After values are reported per endpoint, never cached', () => {
  const ledger = rateLimitLedger([
    { status: 429, endpoint: '/a', retryAfterSeconds: 10 },
    { status: 429, endpoint: '/a', retryAfterSeconds: 3 },
    { status: 429, endpoint: '/a', retryAfterSeconds: -5 },
  ]);
  assert.equal(ledger.byEndpoint['/a'].maxRetryAfterSeconds, 10);
  assert.equal(ledger.count, 3);
  assert.match(ledger.disclosure.join('\n'), /429_never_cached/);
});

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}

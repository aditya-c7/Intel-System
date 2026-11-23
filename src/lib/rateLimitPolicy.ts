/**
 * RS9 rate-limit policy helpers (shadow-only, additive).
 *
 * This module is NOT imported by the production server. It encodes the web-research
 * brief's guardrails as isolated, side-effect-free reference helpers so that a harness
 * can evaluate a product without turning an upstream 429 into a false product verdict:
 *
 *  - 429 is never a product answer. A 429 attributable to the harness / shared egress is
 *    voided as NOT EVALUABLE; it is evaluable only when rate-limit enforcement itself is
 *    the thing under test.
 *  - Retry-After is honored exactly (delay-seconds or HTTP-date). Without it, wait >=60s
 *    and then fall back to capped exponential backoff. A Retry-After beyond the run budget
 *    aborts the case as NOT EVALUABLE instead of inflating latency with sleeps.
 *  - Backoff is capped exponential + full jitter: sleep = U[0, min(cap, base*2^n)], with
 *    retries bounded at 5. This module never draws randomness: it exposes the range and
 *    accepts an optional caller-supplied uniform sample.
 *  - Proactive pacing uses a token bucket at 70-80% of the documented limit; concurrency
 *    is capped by the caller (see DEFAULT_MAX_CONCURRENCY).
 *  - Only successful metadata is cacheable. A 429 is never cached.
 *  - Multi-egress rotation is an evasion / last resort; prefer authenticated, sanctioned
 *    capacity. If authorized, pin one egress per sample and disclose it.
 *  - A 429 ledger reports count / endpoint / egress / Retry-After / window /
 *    not_evaluable_rate and fails the RUN (never the product) above the threshold.
 *
 * PURE / NON-THROWING / ZERO SIDE EFFECTS:
 *  - no timers, sleeps, network calls, storage, clock or RNG reads;
 *  - hostile input is coerced or fail-closed instead of throwing;
 *  - caller-owned arrays/objects are never mutated; equal inputs give equal outputs.
 */

/* -------------------------------------------------------------------------- */
/* Policy constants                                                            */
/* -------------------------------------------------------------------------- */

/** The only status treated as a rate-limit signal. */
export const RATE_LIMIT_STATUS = 429;
/** Minimum wait when a 429 carries no Retry-After header. */
export const MIN_FALLBACK_WAIT_MS = 60_000;
/** Hard bound on rate-limit retries; exhausting them voids the case. */
export const MAX_RATE_LIMIT_RETRIES = 5;
/** Default exponential backoff base (matches the >=60s fallback). */
export const DEFAULT_BACKOFF_BASE_MS = 60_000;
/** Default exponential backoff cap. */
export const DEFAULT_BACKOFF_CAP_MS = 300_000;
/** Policy band for proactive token-bucket pacing (70-80% of documented limit). */
export const MIN_PACING_FRACTION = 0.7;
export const MAX_PACING_FRACTION = 0.8;
export const DEFAULT_PACING_FRACTION = 0.75;
/** Advisory concurrency cap for harness egress. */
export const DEFAULT_MAX_CONCURRENCY = 4;
/** not_evaluable_rate gates: warn above 5%, fail the RUN above 10%. */
export const NOT_EVALUABLE_WARN_THRESHOLD = 0.05;
export const NOT_EVALUABLE_FAIL_THRESHOLD = 0.1;
/** Sentinel next-available time when a bucket cannot ever refill to one token. */
export const NO_REFILL_NEXT_MS = Number.POSITIVE_INFINITY;

/* -------------------------------------------------------------------------- */
/* Shared defensive coercions                                                  */
/* -------------------------------------------------------------------------- */

/** Sentinel returned when a hostile property getter throws. */
const HOSTILE_READ = Symbol('hostile_read');

/** Read a property without letting a hostile getter throw. */
function safeGet(source: unknown, key: string): unknown {
  try {
    if (!source || typeof source !== 'object') return undefined;
    return (source as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/** Stricter read for classification: an unreadable field voids the sample. */
function readField(source: unknown, key: string): unknown {
  try {
    if (!source || typeof source !== 'object') return undefined;
    return (source as Record<string, unknown>)[key];
  } catch {
    return HOSTILE_READ;
  }
}

/** Finite numbers pass through; everything else becomes 0. */
function finiteNonNegative(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : 0;
}

/** Finite number with an explicit fallback for hostile input. */
function finiteOr(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function nonNegativeOr(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback;
}

/** Coerce truthy flags without throwing on hostiles; only explicit signals count. */
function truthyFlag(value: unknown): boolean {
  try {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return Number.isFinite(value) && value !== 0;
    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();
      return normalized === 'true' || normalized === '1' || normalized === 'yes';
    }
    return false;
  } catch {
    return false;
  }
}

/** Short, printable label for endpoint / egress / window fields. */
function label(value: unknown, fallback: string): string {
  try {
    let out: string;
    if (typeof value === 'string') out = value.trim();
    else if (typeof value === 'number' && Number.isFinite(value)) out = String(value);
    else out = '';
    if (!out) return fallback;
    out = out.slice(0, 120);
    // Never let a hostile label poison the byEndpoint object prototype.
    if (out === '__proto__' || out === 'constructor' || out === 'prototype') return '[redacted]';
    return out;
  } catch {
    return fallback;
  }
}

function isRateLimitStatus(value: unknown): boolean {
  try {
    if (typeof value === 'number') return value === RATE_LIMIT_STATUS;
    if (typeof value === 'string') return value.trim() === String(RATE_LIMIT_STATUS);
    return false;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* 0. Retry-After parsing (delay-seconds or HTTP-date)                         */
/* -------------------------------------------------------------------------- */

/**
 * Parse a Retry-After header value into seconds.
 *
 *  - delay-seconds: a non-negative finite number or numeric string, returned exactly;
 *  - HTTP-date: parsed against the caller-supplied `nowMs` reference (no clock read here)
 *    and returned as max(0, (date - now)/1000);
 *  - anything else -> null (no Retry-After), so the caller applies the >=60s fallback.
 */
export function parseRetryAfter(raw: unknown, nowMs: unknown = 0): number | null {
  try {
    if (typeof raw === 'number') {
      return Number.isFinite(raw) && raw >= 0 ? raw : null;
    }
    if (typeof raw !== 'string') return null;
    const text = raw.trim();
    if (!text) return null;
    if (/^\+?\d+(?:\.\d+)?$/.test(text)) {
      const seconds = Number(text);
      return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
    }
    const dateMs = Date.parse(text);
    if (!Number.isFinite(dateMs)) return null;
    const reference = finiteOr(nowMs, 0);
    return Math.max(0, (dateMs - reference) / 1000);
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* 1. classifyRateLimit                                                        */
/* -------------------------------------------------------------------------- */

export type RateLimitClassification = 'ok' | 'retry' | 'not_evaluable' | 'evaluable';

/**
 * Input to `classifyRateLimit`. Every field is `unknown` so hostile values can be exercised
 * directly. `attempt` is optional and, when supplied, enforces the <=5 retry bound.
 */
export interface ClassifyRateLimitInput {
  status: unknown;
  retryAfterSeconds?: unknown;
  runBudgetMs?: unknown;
  harnessAttributable?: unknown;
  testingRateLimit?: unknown;
  attempt?: unknown;
}

export interface RateLimitDecision {
  classification: RateLimitClassification;
  /** Exact wait to observe, or null when there is no wait (ok/evaluable/void/abort). */
  waitMs: number | null;
  reason: string;
}

/**
 * Decide how a harness sample that produced `status` must be treated.
 *
 * Decision order for a 429:
 *   1. harness-attributable  -> NOT EVALUABLE (void; never inflate latency with a sleep);
 *   2. testing rate limiting -> EVALUABLE (the 429 is the expected signal);
 *   3. retry budget exhausted -> NOT EVALUABLE;
 *   4. Retry-After present    -> RETRY with the exact delay, or NOT EVALUABLE if that delay
 *                               exceeds the remaining run budget (abort the case);
 *   5. Retry-After absent     -> RETRY with >=60s, then capped exponential backoff, or
 *                               NOT EVALUABLE if even the minimum wait exceeds the budget.
 *
 * Non-429 statuses carry no rate-limit signal and are 'ok'. This function never sleeps,
 * never reads a clock and never mutates its input.
 */
export function classifyRateLimit(input: unknown): RateLimitDecision {
  try {
    const status = readField(input, 'status');
    const harnessAttributable = readField(input, 'harnessAttributable');
    const testingRateLimit = readField(input, 'testingRateLimit');
    const attemptRaw = readField(input, 'attempt');
    const budgetRaw = readField(input, 'runBudgetMs');
    const retryAfterRaw = readField(input, 'retryAfterSeconds');

    // If any decision input cannot be read, the sample cannot be trusted: void it.
    if (
      [status, harnessAttributable, testingRateLimit, attemptRaw, budgetRaw, retryAfterRaw].some(
        (value) => value === HOSTILE_READ
      )
    ) {
      return {
        classification: 'not_evaluable',
        waitMs: null,
        reason: 'hostile_input:unreadable_field;void_sample',
      };
    }

    if (!isRateLimitStatus(status)) {
      return {
        classification: 'ok',
        waitMs: null,
        reason: 'no_rate_limit_signal:status_not_429',
      };
    }

    if (truthyFlag(harnessAttributable)) {
      return {
        classification: 'not_evaluable',
        waitMs: null,
        reason: 'void_sample:429_attributable_to_harness_or_shared_egress',
      };
    }

    if (truthyFlag(testingRateLimit)) {
      return {
        classification: 'evaluable',
        waitMs: null,
        reason: 'rate_limit_enforcement_under_test:429_is_expected_signal',
      };
    }

    const attempt = Math.min(finiteNonNegative(attemptRaw), MAX_RATE_LIMIT_RETRIES);
    if (attempt >= MAX_RATE_LIMIT_RETRIES) {
      return {
        classification: 'not_evaluable',
        waitMs: null,
        reason: 'retry_exhausted:attempt>=5;void_sample',
      };
    }

    const budgetMs = nonNegativeOr(budgetRaw, 0);
    const retryAfterSeconds =
      typeof retryAfterRaw === 'number' && Number.isFinite(retryAfterRaw) && retryAfterRaw >= 0
        ? retryAfterRaw
        : null;

    if (retryAfterSeconds !== null) {
      const waitMs = retryAfterSeconds * 1000;
      if (waitMs > budgetMs) {
        return {
          classification: 'not_evaluable',
          waitMs: null,
          reason: `retry_after_exceeds_run_budget:required_ms=${Math.round(waitMs)};budget_ms=${Math.round(budgetMs)};abort_case`,
        };
      }
      return {
        classification: 'retry',
        waitMs,
        reason: 'retry_after_honored_exactly',
      };
    }

    // No Retry-After: wait at least 60s and then continue with capped exponential backoff.
    const fallbackMs = Math.max(
      MIN_FALLBACK_WAIT_MS,
      backoffDelayMs({
        attempt,
        baseMs: DEFAULT_BACKOFF_BASE_MS,
        capMs: DEFAULT_BACKOFF_CAP_MS,
        jitter: false,
      })
    );
    if (fallbackMs > budgetMs) {
      return {
        classification: 'not_evaluable',
        waitMs: null,
        reason: `fallback_wait_exceeds_run_budget:required_ms=${fallbackMs};budget_ms=${Math.round(budgetMs)};abort_case`,
      };
    }
    return {
      classification: 'retry',
      waitMs: fallbackMs,
      reason: 'no_retry_after:wait>=60s_then_capped_exponential_backoff',
    };
  } catch {
    return {
      classification: 'not_evaluable',
      waitMs: null,
      reason: 'hostile_input:fail_closed_void_sample',
    };
  }
}

/** True once the retry bound (>=5 attempts) is reached. */
export function retryExhausted(attempt: unknown): boolean {
  return finiteNonNegative(attempt) >= MAX_RATE_LIMIT_RETRIES;
}

/* -------------------------------------------------------------------------- */
/* 2. Capped exponential backoff + full jitter                                 */
/* -------------------------------------------------------------------------- */

export interface BackoffInput {
  attempt: unknown;
  baseMs: unknown;
  capMs: unknown;
  /** Falsy -> exact deterministic sleep; truthy -> full-jitter mode (see below). */
  jitter?: unknown;
  /**
   * Optional caller-supplied uniform sample in [0,1]. The pure helper never draws RNG:
   * when jitter is on and no sample is supplied, the returned number is the range maximum
   * (`min(cap, base*2^n)`) and the actual sleep is U[0, max] chosen by the caller.
   */
  jitterSample?: unknown;
}

export interface BackoffRange {
  minMs: number;
  maxMs: number;
}

/** Full-jitter interval for an attempt: [0, min(cap, base*2^attempt)]. */
export function backoffDelayRange(input: unknown): BackoffRange {
  try {
    // Clamp the exponent so a hostile attempt cannot overflow to Infinity.
    const attempt = Math.min(finiteNonNegative(safeGet(input, 'attempt')), 63);
    const base = nonNegativeOr(safeGet(input, 'baseMs'), DEFAULT_BACKOFF_BASE_MS);
    const cap = nonNegativeOr(safeGet(input, 'capMs'), DEFAULT_BACKOFF_CAP_MS);
    const ceiling = Math.min(cap, base * Math.pow(2, attempt));
    const maxMs = Number.isFinite(ceiling) ? Math.max(0, ceiling) : cap;
    return { minMs: 0, maxMs };
  } catch {
    return { minMs: 0, maxMs: 0 };
  }
}

/**
 * Deterministic capped-exponential ceiling when `jitter` is off. With jitter on, returns the
 * upper bound of the full-jitter range (or a caller-sampled point when `jitterSample` is given).
 * No randomness is ever generated inside this function.
 */
export function backoffDelayMs(input: unknown): number {
  try {
    const { minMs, maxMs } = backoffDelayRange(input);
    if (!truthyFlag(safeGet(input, 'jitter'))) return maxMs;
    const sample = safeGet(input, 'jitterSample');
    if (typeof sample !== 'number' || !Number.isFinite(sample)) return maxMs;
    const unit = Math.min(1, Math.max(0, sample));
    return minMs + unit * (maxMs - minMs);
  } catch {
    return 0;
  }
}

/* -------------------------------------------------------------------------- */
/* 3. Proactive token-bucket pacing                                            */
/* -------------------------------------------------------------------------- */

export interface TokenBucketInput {
  tokens: unknown;
  capacity: unknown;
  refillPerSec: unknown;
  nowMs: unknown;
  lastMs: unknown;
  /** Optional; clamped into the documented 70-80% pacing band. */
  pacingFraction?: unknown;
}

export interface TokenBucketResult {
  allowed: boolean;
  remaining: number;
  /** Earliest absolute time (ms) the next token is available, or NO_REFILL_NEXT_MS. */
  nextMs: number;
}

/**
 * Refill a token bucket from `lastMs` to `nowMs`, optionally consume one token, and report
 * when the next token will be ready. Effective capacity and refill rate are both scaled to
 * 70-80% of the documented limit (pacing), so the harness stays below the published ceiling.
 * No clock is read: `nowMs` / `lastMs` are supplied by the caller.
 */
export function tokenBucket(input: unknown): TokenBucketResult {
  try {
    const tokens = nonNegativeOr(safeGet(input, 'tokens'), 0);
    const capacity = nonNegativeOr(safeGet(input, 'capacity'), 0);
    const refillPerSec = nonNegativeOr(safeGet(input, 'refillPerSec'), 0);
    const nowMs = finiteOr(safeGet(input, 'nowMs'), 0);
    const lastMs = finiteOr(safeGet(input, 'lastMs'), nowMs);

    const pacing = Math.min(
      MAX_PACING_FRACTION,
      Math.max(MIN_PACING_FRACTION, finiteOr(safeGet(input, 'pacingFraction'), DEFAULT_PACING_FRACTION))
    );
    const effectiveCapacity = capacity * pacing;
    const effectiveRefill = refillPerSec * pacing;
    const elapsedSec = Math.max(0, nowMs - lastMs) / 1000;
    const refilled = Math.min(effectiveCapacity, tokens + elapsedSec * effectiveRefill);

    if (effectiveCapacity < 1) {
      return { allowed: false, remaining: refilled, nextMs: NO_REFILL_NEXT_MS };
    }

    const allowed = refilled >= 1;
    const remaining = allowed ? refilled - 1 : refilled;
    let nextMs: number;
    if (remaining >= 1) nextMs = nowMs;
    else if (effectiveRefill > 0) {
      nextMs = nowMs + Math.ceil(((1 - remaining) / effectiveRefill) * 1000);
    } else nextMs = NO_REFILL_NEXT_MS;

    return { allowed, remaining, nextMs };
  } catch {
    return { allowed: false, remaining: 0, nextMs: NO_REFILL_NEXT_MS };
  }
}

/* -------------------------------------------------------------------------- */
/* 4. 429 ledger                                                              */
/* -------------------------------------------------------------------------- */

export interface RateLimitEvent {
  status?: unknown;
  endpoint?: unknown;
  egress?: unknown;
  retryAfterSeconds?: unknown;
  window?: unknown;
  notEvaluable?: unknown;
  harnessAttributable?: unknown;
  testingRateLimit?: unknown;
}

export interface EndpointLedger {
  count: number;
  notEvaluable: number;
  egresses: string[];
  windows: string[];
  maxRetryAfterSeconds: number | null;
}

export interface RateLimitLedgerResult {
  count: number;
  byEndpoint: Record<string, EndpointLedger>;
  notEvaluableRate: number;
  disclosure: string[];
}

/**
 * Build the 429 ledger. Only 429 events are counted. An event is NOT EVALUABLE when it is
 * explicitly flagged so, or when it is harness-attributable and rate-limit enforcement is
 * not itself under test. The disclosure lines carry the egress / retry / cache / pacing /
 * run-gate policy so a reviewer can see that a high not-evaluable rate fails the RUN and
 * never the product.
 */
export function rateLimitLedger(events: unknown): RateLimitLedgerResult {
  try {
    const list: unknown[] = Array.isArray(events) ? (events as unknown[]) : [];
    const byEndpoint: Record<string, EndpointLedger> = {};
    const allEgresses = new Set<string>();
    let notEvaluableCount = 0;

    for (const raw of list) {
      if (!isRateLimitStatus(safeGet(raw, 'status'))) continue;

      const endpoint = label(safeGet(raw, 'endpoint'), 'unknown');
      const egress = label(safeGet(raw, 'egress'), 'unknown');
      const window = label(safeGet(raw, 'window'), 'unspecified');
      const notEvaluable =
        truthyFlag(safeGet(raw, 'notEvaluable')) ||
        (truthyFlag(safeGet(raw, 'harnessAttributable')) &&
          !truthyFlag(safeGet(raw, 'testingRateLimit')));
      const rawRetryAfter = safeGet(raw, 'retryAfterSeconds');
      const retryAfterSeconds =
        typeof rawRetryAfter === 'number' && Number.isFinite(rawRetryAfter) && rawRetryAfter >= 0
          ? rawRetryAfter
          : null;

      if (!Object.prototype.hasOwnProperty.call(byEndpoint, endpoint)) {
        byEndpoint[endpoint] = {
          count: 0,
          notEvaluable: 0,
          egresses: [],
          windows: [],
          maxRetryAfterSeconds: null,
        };
      }
      const bucket = byEndpoint[endpoint];
      bucket.count += 1;
      if (notEvaluable) {
        bucket.notEvaluable += 1;
        notEvaluableCount += 1;
      }
      if (!bucket.egresses.includes(egress)) bucket.egresses.push(egress);
      if (!bucket.windows.includes(window)) bucket.windows.push(window);
      if (
        retryAfterSeconds !== null &&
        (bucket.maxRetryAfterSeconds === null || retryAfterSeconds > bucket.maxRetryAfterSeconds)
      ) {
        bucket.maxRetryAfterSeconds = retryAfterSeconds;
      }
      allEgresses.add(egress);
    }

    const endpoints = Object.keys(byEndpoint).sort();
    let count = 0;
    for (const endpoint of endpoints) {
      const bucket = byEndpoint[endpoint];
      count += bucket.count;
      bucket.egresses.sort();
      bucket.windows.sort();
    }
    const notEvaluableRate =
      count === 0 ? 0 : Math.round((notEvaluableCount / count) * 10_000) / 10_000;
    const egresses = [...allEgresses].sort();
    const runGate =
      notEvaluableRate > NOT_EVALUABLE_FAIL_THRESHOLD ? 'FAIL_RUN' : 'PASS_RUN';

    const disclosure: string[] = [
      `429_ledger: count=${count}; endpoints=${endpoints.length}; not_evaluable_rate=${notEvaluableRate}`,
      `egress_disclosure: ${egresses.length === 0 ? 'none_observed' : egresses.join(',')}`,
      egresses.length > 1
        ? 'multi_egress_rotation_detected: evasion/last-resort only; prefer authenticated/sanctioned capacity; if authorized pin one egress per sample and disclose'
        : 'egress_pinning: single_egress_per_sample; disclosed',
      'retry_after_policy: honor_exactly(delay_seconds|http_date); absent=>wait>=60s_then_exponential; budget_overflow=>not_evaluable_abort',
      `backoff_policy: capped_exponential_full_jitter; sleep=U[0,min(cap,base*2^n)]; retries<=${MAX_RATE_LIMIT_RETRIES}; exhausted=>not_evaluable`,
      `pacing_policy: token_bucket_at_${Math.round(MIN_PACING_FRACTION * 100)}-${Math.round(MAX_PACING_FRACTION * 100)}%_of_documented_limit; concurrency<=${DEFAULT_MAX_CONCURRENCY}`,
      'cache_policy: successful_metadata_only; 429_never_cached',
      `run_gate: ${runGate}_if_not_evaluable_rate>${NOT_EVALUABLE_FAIL_THRESHOLD} (warn>${NOT_EVALUABLE_WARN_THRESHOLD}); run_failure_not_product_failure`,
    ];

    return { count, byEndpoint, notEvaluableRate, disclosure };
  } catch {
    return {
      count: 0,
      byEndpoint: {},
      notEvaluableRate: 0,
      disclosure: ['429_ledger: unavailable_due_to_hostile_input; fail_closed'],
    };
  }
}

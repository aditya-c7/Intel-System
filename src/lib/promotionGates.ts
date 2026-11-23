/**
 * Shadow-only promotion gates for additive candidate changes.
 *
 * ADDITIVE: this module is not imported by the production server. It is an isolated,
 * side-effect-free reference implementation of the RS2 promotion discipline:
 *
 *  - Shadow: tee candidate output, log & discard, correlate by id, bound latency/resource cost,
 *    sample reviews + outliers, soak representative traffic.
 *  - Canary: 1% -> 5% -> 25% -> 50% -> 100%, always compared against a concurrent control, one
 *    canary at a time, deterministic (sticky) hashing, previous version kept hot for rollback.
 *  - Wiring: optional additive fields with defaults; expand -> migrate -> contract; feature flags
 *    and tolerant readers; consumer-driven semantic contract tests.
 *  - Observability: per-canary/control metrics (presence, coverage, null rate, freshness, drift)
 *    and a signed audit record per stage.
 *  - Rollback: pre-registered thresholds vs the concurrent baseline; rollback is a routing change,
 *    not a redeploy; governed by a written policy.
 *
 * PURE / NON-THROWING / ZERO SIDE EFFECTS:
 *  - no timers, scheduling, DB/network access, clock or random reads;
 *  - hostile input (null, strings, NaN, hostile getters) is coerced or fail-closed, never thrown;
 *  - caller-owned objects are never mutated; repeated calls with the same inputs return the same
 *    result;
 *  - no metric here is re-derived from another module — every value is supplied by the caller.
 */

/* -------------------------------------------------------------------------- */
/* Pre-registered contract constants                                           */
/* -------------------------------------------------------------------------- */

/** Ordered promotion ladder. `shadow` tees and discards; `canary_*` are traffic percentages. */
export const PROMOTION_STAGES = [
  'shadow',
  'canary_1',
  'canary_5',
  'canary_25',
  'canary_50',
  'canary_100',
] as const;

export type PromotionStage = (typeof PROMOTION_STAGES)[number];

/**
 * Frozen decision thresholds. These are pre-registered: changing them invalidates every
 * audit record produced under the old values, so they are constants, not configuration.
 *
 *  - `maxErrorDeltaPct`: candidate error rate may rise by at most +1 percentage point.
 *    (The input field keeps the requested `errorDeltaPct` name; its unit is percentage points.)
 *  - `maxP99DeltaPct`: candidate p99 latency may rise by at most +20 percent.
 *  - `minQualityDelta`: candidate quality may fall by at most 5 points.
 *  - `coverageFloor`: additive-field presence/coverage must be at least 0.80 (80%).
 *  - `requireSignedAudit`: no stage may advance without its signed audit record.
 */
export const PROMOTION_THRESHOLDS = {
  maxErrorDeltaPct: 1,
  maxP99DeltaPct: 20,
  minQualityDelta: -5,
  coverageFloor: 0.8,
  requireSignedAudit: true,
} as const;

export const MAX_ERROR_DELTA_PCT = PROMOTION_THRESHOLDS.maxErrorDeltaPct;
export const MAX_P99_DELTA_PCT = PROMOTION_THRESHOLDS.maxP99DeltaPct;
export const MIN_QUALITY_DELTA = PROMOTION_THRESHOLDS.minQualityDelta;
export const COVERAGE_FLOOR = PROMOTION_THRESHOLDS.coverageFloor;

/** Float slack so control-coverage parity does not trip on representation noise. */
const COVERAGE_EPSILON = 1e-9;

/* -------------------------------------------------------------------------- */
/* Shared defensive readers                                                    */
/* -------------------------------------------------------------------------- */

/** Finite numbers pass through; everything else (NaN, Infinity, strings, null) is rejected. */
function finiteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** Coverage values are fractions in [0,1]; out-of-range values are invalid, never normalized. */
function unitInterval(value: unknown, name: string, reasons: string[]): number | null {
  const parsed = finiteNumber(value);
  if (parsed === null || parsed < 0 || parsed > 1) {
    reasons.push(`${name} must be a finite number in [0,1] (hostile input is not normalized)`);
    return null;
  }
  return parsed;
}

function requireFinite(name: string, value: unknown, reasons: string[]): number | null {
  const parsed = finiteNumber(value);
  if (parsed === null) reasons.push(`${name} must be a finite number`);
  return parsed;
}

/* -------------------------------------------------------------------------- */
/* 1. Promotion stage decision                                                 */
/* -------------------------------------------------------------------------- */

/** All measurements are supplied by the caller; nothing here is computed or re-derived. */
export interface PromotionStageInput {
  /** Current rung on `PROMOTION_STAGES`. */
  stage: PromotionStage;
  /** Canary additive-field presence / coverage, fraction in [0,1]. */
  coverage: number;
  /** Canary error-rate change vs the concurrent control, in percentage points (+ = worse). */
  errorDeltaPct: number;
  /** Canary p99 latency change vs the concurrent control, in percent (+ = slower). */
  p99DeltaPct: number;
  /** Canary quality change vs the concurrent control, in points (- = worse). */
  qualityDelta: number;
  /** Same coverage measurement from the concurrent control, fraction in [0,1]. */
  baselineCoverage: number;
  /** Signed, per-stage audit record exists (shadow/canary observability requirement). */
  auditPresent: boolean;
}

export interface PromotionStageResult {
  /** True only when every pre-registered gate passed and the stage is fully audited. */
  advance: boolean;
  /** True when a metric breached a pre-registered threshold (a routing change, not a redeploy). */
  rollback: boolean;
  /** Human-readable explanation of the decision, including the offending threshold. */
  reasons: string[];
}

function invalidStageInput(reason: string): PromotionStageResult {
  return { advance: false, rollback: false, reasons: [reason] };
}

/**
 * Evaluate one promotion rung against the pre-registered thresholds.
 *
 * Decision order:
 *  1. Missing/unreadable or invalid input fails closed (no advance); it is an operator error,
 *     not a quality regression, so it does not by itself order a rollback.
 *  2. Any breached metric sets `rollback = true` (error +1pp, p99 +20%, quality -5, coverage
 *     floor 0.80, or coverage below the concurrent control). Rollback is a routing change back
 *     to the hot previous version, never a redeploy.
 *  3. `advance` requires a valid rung, no breached metric, coverage parity with the control and
 *     a signed audit record. At `canary_100` a pass means the promotion is complete.
 *
 * Thresholds are inclusive: exactly +1pp / +20% / -5 points / 0.80 coverage passes.
 * Never throws, never mutates `input`.
 */
export function evaluatePromotionStage(input: PromotionStageInput): PromotionStageResult {
  try {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      return invalidStageInput('stage evaluation requires a non-array object input');
    }

    const reasons: string[] = [];
    let inputValid = true;

    const rawStage: unknown = input.stage;
    const stage =
      typeof rawStage === 'string' && (PROMOTION_STAGES as readonly string[]).includes(rawStage)
        ? (rawStage as PromotionStage)
        : null;
    if (stage === null) {
      inputValid = false;
      reasons.push(
        `invalid stage=${String(rawStage)}; expected one of ${PROMOTION_STAGES.join(', ')}`
      );
    }

    const errorDelta = requireFinite('errorDeltaPct', input.errorDeltaPct, reasons);
    if (errorDelta === null) inputValid = false;
    const p99Delta = requireFinite('p99DeltaPct', input.p99DeltaPct, reasons);
    if (p99Delta === null) inputValid = false;
    const qualityDelta = requireFinite('qualityDelta', input.qualityDelta, reasons);
    if (qualityDelta === null) inputValid = false;

    const coverage = unitInterval(input.coverage, 'coverage', reasons);
    if (coverage === null) inputValid = false;
    const baselineCoverage = unitInterval(input.baselineCoverage, 'baselineCoverage', reasons);
    if (baselineCoverage === null) inputValid = false;

    const auditPresent = input.auditPresent === true;
    if (!auditPresent) {
      reasons.push(
        `signed audit record missing for stage ${stage ?? '<invalid>'}; no advance without a per-stage audit`
      );
    }

    let rollback = false;
    if (errorDelta !== null && errorDelta > PROMOTION_THRESHOLDS.maxErrorDeltaPct) {
      rollback = true;
      reasons.push(
        `error regression ${errorDelta}pp exceeds +${PROMOTION_THRESHOLDS.maxErrorDeltaPct}pp ceiling`
      );
    }
    if (p99Delta !== null && p99Delta > PROMOTION_THRESHOLDS.maxP99DeltaPct) {
      rollback = true;
      reasons.push(
        `p99 regression ${p99Delta}% exceeds +${PROMOTION_THRESHOLDS.maxP99DeltaPct}% ceiling`
      );
    }
    if (qualityDelta !== null && qualityDelta < PROMOTION_THRESHOLDS.minQualityDelta) {
      rollback = true;
      reasons.push(
        `quality regression ${qualityDelta} falls below ${PROMOTION_THRESHOLDS.minQualityDelta} floor`
      );
    }
    if (coverage !== null && coverage < PROMOTION_THRESHOLDS.coverageFloor) {
      rollback = true;
      reasons.push(
        `coverage ${coverage} below ${PROMOTION_THRESHOLDS.coverageFloor} coverage floor`
      );
    }
    if (
      coverage !== null &&
      baselineCoverage !== null &&
      coverage + COVERAGE_EPSILON < baselineCoverage
    ) {
      rollback = true;
      reasons.push(
        `coverage ${coverage} below concurrent control coverage ${baselineCoverage}`
      );
    }

    const advance = inputValid && !rollback && auditPresent;
    if (advance && stage !== null) {
      const index = PROMOTION_STAGES.indexOf(stage);
      const next = PROMOTION_STAGES[index + 1];
      reasons.push(
        next === undefined
          ? `all pre-registered gates passed at terminal stage ${stage}; promotion complete`
          : `all pre-registered gates passed at ${stage}; eligible to advance to ${next}`
      );
    }

    return { advance, rollback, reasons };
  } catch {
    /* Hostile getters / proxies must never turn a gate check into a crash. */
    return invalidStageInput('stage evaluation could not read its input (hostile getter/proxy)');
  }
}

/* -------------------------------------------------------------------------- */
/* 2. Additive-field contract                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Evidence bundle required before an optional additive field may move past expand/migrate.
 * Each member must be the literal boolean `true` — truthy strings/numbers never satisfy a
 * contract check.
 */
export interface AdditiveFieldContractInput {
  /** The candidate additive field is present in the payload under test. */
  fieldPresent: boolean;
  /** Old (field-less) producer is still available to prove the legacy absence path. */
  oldProducer: boolean;
  /** Old consumer (ignores unknown fields) is still available to prove forward compatibility. */
  oldConsumer: boolean;
  /** Replay with/without the field produced identical behavior (no-behavior-change proof). */
  noBehaviorChangeProof: boolean;
  /** New reader tolerates missing / default / null field (expand -> migrate -> contract). */
  tolerantReader: boolean;
  /** Feature flag off reproduces the baseline exactly. */
  flagOffParity: boolean;
}

export interface AdditiveFieldContractResult {
  safe: boolean;
  issues: string[];
}

const ADDITIVE_FIELD_CHECKS: ReadonlyArray<readonly [keyof AdditiveFieldContractInput, string]> = [
  [
    'fieldPresent',
    'candidate additive field was not observed in the payload under test',
  ],
  [
    'oldProducer',
    'old field-less producer unavailable; legacy absence / default path is unproven',
  ],
  ['oldConsumer', 'old consumer unavailable; forward compatibility is unproven'],
  [
    'noBehaviorChangeProof',
    'no-behavior-change proof missing; replay with/without the field was not run',
  ],
  [
    'tolerantReader',
    'tolerant reader missing; missing/null/default path (expand -> migrate -> contract) unproven',
  ],
  [
    'flagOffParity',
    'flag-off parity missing; output with the feature flag off was not compared to baseline',
  ],
];

/**
 * Pure contract gate for an optional additive field. Every pre-condition must hold; any missing
 * or hostile evidence is reported as an issue and `safe` is false. An empty `issues` array means
 * the field is safe under the consumer-driven semantic contract. Never throws, never mutates input.
 */
export function additiveFieldContract(
  input: AdditiveFieldContractInput
): AdditiveFieldContractResult {
  try {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      return { safe: false, issues: ['additive-field contract requires a non-array object input'] };
    }

    const issues: string[] = [];
    for (const [key, message] of ADDITIVE_FIELD_CHECKS) {
      if ((input as unknown as Record<string, unknown>)[key] !== true) issues.push(`${key}: ${message}`);
    }
    return { safe: issues.length === 0, issues };
  } catch {
    return {
      safe: false,
      issues: ['additive-field contract could not read its input (hostile getter/proxy)'],
    };
  }
}

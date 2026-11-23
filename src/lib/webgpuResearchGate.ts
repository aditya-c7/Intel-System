/**
 * WebGPU research gate (RS3) — shadow-only, additive, pure, non-throwing, zero imports.
 *
 * Nothing in production imports this module. It gives a canonical, side-effect-free home to
 * the RS3 literature conclusion: atomic-contention WebGPU identity is a NO-GO for production
 * identity. It is a *gate over supplied evidence*, not a probe: this file never touches a GPU
 * API, never reads a clock, never hashes a signature and never mints an identifier.
 *
 * Evidence behind the pre-registered thresholds (all external research, reproduced here only
 * as provenance — none of it is measured or re-derived in code):
 *  - LockedApart poster: 6 PCs + 4 phones, no time-lapse test, ~52ms/trace.
 *  - AtomicIncrement: 7 devices / 21 days; per-device exact-stability means 0.63-1.00 with
 *    minima of 0.00; ~1.2s capture.
 *  - WGPULens: 1095/1095 unique, but repeat stability 57/80 active and 45/80 combined;
 *    timer/clamp sensitive; high-resolution AUROC 0.718 collapses to 0.512 when coarsened,
 *    and a 32ms clamp collapses 0.637 to 0.500.
 *  - Tranco top-10k: zero observed page-load GPU activity.
 *
 * GO criteria (ALL must pass to lift the research-only default):
 *  1. per-device exact stability >= 95%, observed over >= 30 days and >= 2 browser updates;
 *  2. open-world candidate pool >= 10,000 devices;
 *  3. capture <= 200ms;
 *  4. timer-free capture (literal `true` — no timer-based contention measurement);
 *  5. documented consent (literal `true`).
 *
 * Design invariants (enforced in code, not only documented):
 *  - `deployable` is true ONLY when every criterion passes. Any invalid, missing, hostile or
 *    out-of-range observation fails closed and is reported in `reasons`.
 *  - `researchOnly` defaults to true: it is true for every failure and is lifted only by a
 *    complete, evidence-backed pass. There is no input that can silence the research-only flag.
 *  - Every field is read defensively: hostile getters/proxies, null, primitives, arrays, NaN and
 *    Infinity degrade to a failed criterion instead of throwing.
 *  - Total and deterministic: no I/O, no globals, no mutation of caller-owned objects; repeated
 *    calls with the same inputs return deeply identical results.
 *  - The disclosure literal is the standard `WEBGPU_RESEARCH_ONLY_NOTE` text from identityTiers;
 *    it is duplicated here as a frozen literal (the test pins equality) to keep this module
 *    dependency-free.
 */

/* -------------------------------------------------------------------------- */
/* Pre-registered thresholds                                                   */
/* -------------------------------------------------------------------------- */

/** 30 days expressed in milliseconds — the minimum per-device observation window. */
export const THIRTY_DAYS_MS: number = 30 * 24 * 60 * 60 * 1000;

/** Frozen GO thresholds. Changing these invalidates every verdict produced under them. */
export const WEBGPU_RESEARCH_THRESHOLDS = Object.freeze({
  /** Per-device exact-match fraction over the observation window (>= 95%). */
  minExactStability: 0.95,
  /** Minimum per-device observation span in ms (>= 30 days). */
  minObservationMs: THIRTY_DAYS_MS,
  /** Distinct browser updates that must be covered (>= 2). */
  minBrowserUpdates: 2,
  /** Open-world device pool size (>= 10,000). */
  minCandidatePool: 10_000,
  /** Maximum capture latency in ms (<= 200). */
  maxCaptureMs: 200,
});

/** Stable reason tokens; detail is appended in parentheses when an observed value exists. */
export const WEBGPU_RESEARCH_REASON = Object.freeze({
  exactStability: 'per-device-exact-stability-below-95-percent',
  observationWindow: 'per-device-observation-window-below-30-days',
  browserUpdates: 'fewer-than-2-browser-updates-covered',
  candidatePool: 'open-world-candidate-pool-below-10000',
  capture: 'capture-exceeds-200ms-budget',
  timerFree: 'timer-based-capture-is-not-timer-free',
  consent: 'consent-not-documented',
  unreadable: 'webgpu-research-input-unreadable',
  allPassed: 'all-webgpu-research-go-criteria-met',
});

/**
 * The standard research-only disclosure literal (the `WEBGPU_RESEARCH_ONLY_NOTE` text used by
 * identityTiers). Kept here as a literal so this gate has zero imports; the regression suite
 * asserts strict equality with the canonical constant.
 */
export const WEBGPU_RESEARCH_DISCLOSURE: string =
  'Atomic-contention WebGPU identity (DrawnApart/LockedApart/atomic histograms) is RESEARCH_ONLY: ' +
  'cross-visit stability 57/80, timer-sensitive (a 32ms clamp collapses AUROC), ' +
  'GPU/driver/thermal dependent, and requires a labeled training corpus. ' +
  'It is NOT a cryptographic or stable hardware id and is never hashed into this profile.';

/* -------------------------------------------------------------------------- */
/* Public contracts                                                           */
/* -------------------------------------------------------------------------- */

/** All evidence the gate consumes. Every field is optional and nullable. */
export interface WebgpuResearchInput {
  /** Worst per-device exact-match fraction over the observation window, in [0,1]. */
  exactStability30d?: number | null;
  /** Shortest per-device observation span, in milliseconds (>= 30 days required). */
  minPerDeviceStabilityMs?: number | null;
  /** Open-world candidate device pool size. */
  candidatePool?: number | null;
  /** Capture latency in milliseconds. */
  captureMs?: number | null;
  /** Capture is timer-free. Only the literal boolean `true` counts. */
  timerFree?: boolean | null;
  /** Consent for the measurement is documented. Only literal `true` counts. */
  consentDocumented?: boolean | null;
  /** Number of distinct browser updates covered by the observation. */
  browserUpdatesCovered?: number | null;
}

export interface WebgpuResearchResult {
  /** True only when every GO criterion passed. */
  deployable: boolean;
  /** Deterministic audit trail: one token per failed criterion, or a single success token. */
  reasons: string[];
  /** Research-only by default; lifted only by a complete pass (`!deployable`). */
  researchOnly: boolean;
}

/* -------------------------------------------------------------------------- */
/* Defensive readers — every helper is total and never throws                 */
/* -------------------------------------------------------------------------- */

function readField(source: object, key: string): unknown {
  try {
    return (source as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/** Only finite primitive numbers pass through; NaN, Infinity, strings, wrappers are rejected. */
function finiteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function detail(token: string, observed: number | null): string {
  return observed === null ? `${token} (observed=invalid)` : `${token} (observed=${observed})`;
}

function verdict(reasons: string[]): WebgpuResearchResult {
  const deployable = reasons.length === 0;
  if (deployable) {
    return { deployable: true, reasons: [WEBGPU_RESEARCH_REASON.allPassed], researchOnly: false };
  }
  return { deployable: false, reasons, researchOnly: true };
}

function failed(note: string): WebgpuResearchResult {
  return { deployable: false, reasons: [note], researchOnly: true };
}

/* -------------------------------------------------------------------------- */
/* Gate                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Evaluate the RS3 GO criteria against caller-supplied evidence. Pure, total and deterministic:
 * it never throws, never mutates `input`, and returns identical output for identical input.
 *
 * A numeric criterion fails when its value is missing, non-finite, or outside its
 * pre-registered range; the two boolean criteria require the literal `true` (truthy junk such
 * as `'true'` or `1` never satisfies a gate). Exactly one reason is emitted per failed
 * criterion, so the reason count equals the number of unmet GO criteria.
 */
export function evaluateWebgpuResearch(
  input?: WebgpuResearchInput | null,
): WebgpuResearchResult {
  try {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      return failed(WEBGPU_RESEARCH_REASON.unreadable);
    }

    const reasons: string[] = [];

    const stability = finiteNumber(readField(input, 'exactStability30d'));
    if (
      stability === null ||
      stability < WEBGPU_RESEARCH_THRESHOLDS.minExactStability ||
      stability > 1
    ) {
      reasons.push(detail(WEBGPU_RESEARCH_REASON.exactStability, stability));
    }

    const observationMs = finiteNumber(readField(input, 'minPerDeviceStabilityMs'));
    if (observationMs === null || observationMs < WEBGPU_RESEARCH_THRESHOLDS.minObservationMs) {
      reasons.push(detail(WEBGPU_RESEARCH_REASON.observationWindow, observationMs));
    }

    const rawUpdates = finiteNumber(readField(input, 'browserUpdatesCovered'));
    if (
      rawUpdates === null ||
      !Number.isInteger(rawUpdates) ||
      rawUpdates < WEBGPU_RESEARCH_THRESHOLDS.minBrowserUpdates
    ) {
      reasons.push(detail(WEBGPU_RESEARCH_REASON.browserUpdates, rawUpdates));
    }

    const rawPool = finiteNumber(readField(input, 'candidatePool'));
    if (
      rawPool === null ||
      !Number.isInteger(rawPool) ||
      rawPool < WEBGPU_RESEARCH_THRESHOLDS.minCandidatePool
    ) {
      reasons.push(detail(WEBGPU_RESEARCH_REASON.candidatePool, rawPool));
    }

    const captureMs = finiteNumber(readField(input, 'captureMs'));
    if (
      captureMs === null ||
      captureMs < 0 ||
      captureMs > WEBGPU_RESEARCH_THRESHOLDS.maxCaptureMs
    ) {
      reasons.push(detail(WEBGPU_RESEARCH_REASON.capture, captureMs));
    }

    if (readField(input, 'timerFree') !== true) {
      reasons.push(WEBGPU_RESEARCH_REASON.timerFree);
    }

    if (readField(input, 'consentDocumented') !== true) {
      reasons.push(WEBGPU_RESEARCH_REASON.consent);
    }

    return verdict(reasons);
  } catch (error) {
    // Absolute containment: even an exotic proxy failure must not escape this module.
    const message = error instanceof Error ? error.message : String(error);
    return failed(`${WEBGPU_RESEARCH_REASON.unreadable}: ${message}`);
  }
}

/** Return the standard research-only disclosure literal. Pure and non-throwing. */
export function researchDisclosure(): string {
  return WEBGPU_RESEARCH_DISCLOSURE;
}

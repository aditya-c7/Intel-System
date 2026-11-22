/**
 * Calibration evidence engine — pure, additive, and honest by construction.
 *
 * This module deliberately owns NO calibration gate of its own. The locked policy lives in
 * `rarityHonesty.ts` (constants `CALIBRATION_MIN_LABELED_PAIRS` / `CALIBRATION_MAX_ECE` and
 * the `calibrationStatusFor` helper). `calibration_status` here is *only* whatever that gate
 * returns for the supplied labeled-pair count and held-out ECE, so a record can never be
 * marked 'calibrated' without >= 200 labeled pairs AND ECE <= 0.05.
 *
 * The four observable calibration signals are normalized to [0,1] and combined additively
 * with fixed, documented weights into an auditable `evidence_score`. That score is purely
 * descriptive: it never feeds the gate and therefore cannot promote an uncalibrated record.
 *
 * No I/O, no risk scoring, no verdict changes, no third-party SDK. Every exported function is
 * defensive and fails closed on hostile input (it returns a zero/uncalibrated record rather
 * than throwing).
 */

import {
  calibrationStatusFor,
  confidenceLabel,
  type CalibrationStatus,
} from './rarityHonesty';

/* Re-export the locked thresholds so callers have a single source of truth (no duplication). */
export { CALIBRATION_MIN_LABELED_PAIRS, CALIBRATION_MAX_ECE } from './rarityHonesty';

/* -------------------------------------------------------------------------- */
/* Public shapes                                                               */
/* -------------------------------------------------------------------------- */

/** Observable signals plus the two gate inputs. All fields optional; absence scores zero. */
export interface CalibrationEvidenceInput {
  /** Completeness of the calibration data sources, on a 0..1 scale. */
  sourceCompleteness?: number | null;
  /** Separation margin between nearest neighbors, on a 0..1 scale. */
  neighborMargin?: number | null;
  /** Agreement across independent evidence layers, on a 0..1 scale. */
  crossLayerAgreement?: number | null;
  /** Stability of returning-identity observations, on a 0..1 scale. */
  returnStability?: number | null;
  /** Number of human-labeled held-out comparison pairs (gate input). */
  labeledPairs?: number | null;
  /** Held-out expected calibration error, lower is better (gate input). */
  ece?: number | null;
}

/** One additive, auditable component of the evidence record. */
export interface CalibrationEvidenceComponent {
  name: 'source_completeness' | 'neighbor_margin' | 'cross_layer_agreement' | 'return_stability';
  /** Normalized signal in [0,1]. */
  score: number;
  /** Fixed weight applied to `score`. */
  weight: number;
  /** Signed additive contribution = `score * weight`, in [0,1]. */
  contribution: number;
}

export interface CalibrationEvidenceRecord {
  /** The four normalized, weighted evidence components, in fixed order. */
  components: CalibrationEvidenceComponent[];
  /** Additive sum of the component contributions, clamped to [0,1]. Descriptive only. */
  evidence_score: number;
  /** Finite gate inputs actually used (null when absent/malformed), for audit. */
  labeled_pairs: number | null;
  /** Finite gate inputs actually used (null when absent/malformed), for audit. */
  ece: number | null;
  /** Derived solely from the imported rarityHonesty gate — never inferred from evidence. */
  calibration_status: CalibrationStatus;
}

/* -------------------------------------------------------------------------- */
/* Locked, additive weighting rubric (weights sum to exactly 1)                */
/* -------------------------------------------------------------------------- */

export const CALIBRATION_EVIDENCE_WEIGHTS = {
  source_completeness: 0.3,
  neighbor_margin: 0.25,
  cross_layer_agreement: 0.25,
  return_stability: 0.2,
} as const;

const EVIDENCE_SIGNALS: ReadonlyArray<{
  field: keyof Omit<CalibrationEvidenceInput, 'labeledPairs' | 'ece'>;
  name: CalibrationEvidenceComponent['name'];
}> = [
  { field: 'sourceCompleteness', name: 'source_completeness' },
  { field: 'neighborMargin', name: 'neighbor_margin' },
  { field: 'crossLayerAgreement', name: 'cross_layer_agreement' },
  { field: 'returnStability', name: 'return_stability' },
];

/* -------------------------------------------------------------------------- */
/* Defensive numeric helpers                                                   */
/* -------------------------------------------------------------------------- */

function round4(value: number): number {
  return Math.round(value * 10000) / 10000;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

/** Any non-finite / wrong-type signal is absent evidence: zero, never a guess. */
function unitScore(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0;
  return round4(clamp01(value));
}

/** Gate inputs are passed through unchanged (no rounding) so boundary values are exact. */
function finiteOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function emptyEvidence(): CalibrationEvidenceRecord {
  return {
    components: EVIDENCE_SIGNALS.map(({ name }) => ({
      name,
      score: 0,
      weight: CALIBRATION_EVIDENCE_WEIGHTS[name],
      contribution: 0,
    })),
    evidence_score: 0,
    labeled_pairs: null,
    ece: null,
    calibration_status: 'uncalibrated',
  };
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Build an additive evidence record from observable calibration signals.
 *
 * `calibration_status` is obtained exclusively from the imported `calibrationStatusFor`
 * gate using `labeledPairs` + `ece`. The descriptive `evidence_score` and the four signals
 * have zero influence on that status. Pure and non-throwing: hostile input yields a
 * zero-score, 'uncalibrated' record.
 */
export function buildCalibrationEvidence(input?: CalibrationEvidenceInput | null): CalibrationEvidenceRecord {
  try {
    const source: CalibrationEvidenceInput =
      input && typeof input === 'object' ? (input as CalibrationEvidenceInput) : {};

    const components: CalibrationEvidenceComponent[] = EVIDENCE_SIGNALS.map(({ field, name }) => {
      const score = unitScore(source[field]);
      const weight = CALIBRATION_EVIDENCE_WEIGHTS[name];
      return { name, score, weight, contribution: round4(score * weight) };
    });

    const evidenceScore = round4(
      clamp01(components.reduce((total, component) => total + component.contribution, 0))
    );

    const labeledPairs = finiteOrNull(source.labeledPairs);
    const ece = finiteOrNull(source.ece);
    // The locked gate is the sole authority for status. No local threshold logic exists here.
    const calibration_status = calibrationStatusFor({ labeledPairs, heldOutEce: ece });

    return {
      components,
      evidence_score: evidenceScore,
      labeled_pairs: labeledPairs,
      ece,
      calibration_status,
    };
  } catch {
    // Defensive fallback: a hostile/proxy input must never break a response. Stay uncalibrated.
    return emptyEvidence();
  }
}

/**
 * Human-facing label for a calibration record's score. Delegates wording entirely to the
 * existing `confidenceLabel` helper so the "Confidence X%" / "Match evidence X%" strings
 * cannot drift. A calibrated status unlocks the confidence wording; anything else stays as
 * explicitly uncalibrated match evidence.
 */
export function confidenceLabelFor(
  status: CalibrationStatus,
  score: number | null | undefined
): string {
  return confidenceLabel(score, status === 'calibrated');
}

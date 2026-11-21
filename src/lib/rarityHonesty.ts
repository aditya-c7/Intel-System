/**
 * Phase 6 — rarity honesty, proximity honesty and identity-calibration honesty.
 *
 * All numerical facts come from `telemetryContract.ts` (exact Clopper–Pearson and the
 * decideRarity gates). This module only applies the presentation / scoring policy:
 *  - suppressed rarity contributes ZERO score;
 *  - proximity is never derived from IP coordinates without granted geolocation permission;
 *  - a genuine identity match publishes a deterministic, auditable numeric confidence
 *    (weighted observable evidence, clamped to [0,1]) while `calibration_status` honestly
 *    stays 'uncalibrated' until a real held-out calibration gate has passed;
 *  - a genuinely unseen / non-identifying profile keeps null (never a fabricated number).
 */

import {
  decideRarity,
  type RarityDecision,
} from './telemetryContract';
import type { IdentityAxes } from './telemetryContract';
import {
  scoreConfidence,
  type EvidenceMatchTier,
} from '../server/identity/confidenceScorer';

export interface HonestRarity extends RarityDecision {
  /** Zero when status !== 'published'; rarity never silently adds points. */
  score_contribution: number;
  corpus_n: number;
  prevalence_ci95_upper: number;
}

export function computeHonestRarity(corpusN: number, observedCount = 1): HonestRarity {
  const decision = decideRarity(corpusN, observedCount);
  return {
    ...decision,
    corpus_n: decision.corpus_n,
    prevalence_ci95_upper: decision.prevalence_ci95_upper,
    score_contribution: decision.status === 'published' ? 1 : 0,
  };
}

/* -------------------------------------------------------------------------- */
/* Proximity honesty                                                           */
/* -------------------------------------------------------------------------- */

export interface ProximityInput {
  /** Explicit navigator.geolocation permission state. */
  permission?: 'granted' | 'prompt' | 'denied' | string;
  accuracyM?: number;
  /** Coordinates the browser actually granted — never IP-derived coordinates. */
  grantedCoordinates?: { latitude: number; longitude: number } | null;
}

export interface HonestProximity {
  status: 'granted' | 'permission_required' | 'unavailable';
  accuracy_m?: number;
  /** Present only with granted, browser-supplied coordinates. */
  coordinates?: { latitude: number; longitude: number };
}

/**
 * IP coordinates are never proximity evidence. Only an explicit granted geolocation
 * permission unlocks the 'granted' status; otherwise the honest status is permission_required.
 */
export function computeHonestProximity(input: ProximityInput = {}): HonestProximity {
  const permission = String(input.permission || '').toLowerCase();
  if (permission !== 'granted' || !input.grantedCoordinates) {
    return { status: permission === 'denied' ? 'unavailable' : 'permission_required' };
  }
  const result: HonestProximity = { status: 'granted' };
  if (typeof input.accuracyM === 'number' && Number.isFinite(input.accuracyM)) {
    result.accuracy_m = input.accuracyM;
  }
  result.coordinates = input.grantedCoordinates;
  return result;
}

/* -------------------------------------------------------------------------- */
/* Identity confidence calibration honesty                                     */
/* -------------------------------------------------------------------------- */

export const CALIBRATION_MIN_LABELED_PAIRS = 200;
export const CALIBRATION_MAX_ECE = 0.05;

export interface CalibrationInput {
  labeledPairs: number;
  heldOutEce: number;
  /** The resolved match stage; maps to a categorical confidence tier. */
  matchStage: IdentityAxes['match_stage'];
  calibratedScore?: number;

  /* Observable evidence for the weighted numeric score. Every field is optional and
   * contributes zero weight when absent, so legacy callers remain source-compatible. */
  matchTier?: EvidenceMatchTier | string;
  matchScore?: number;
  structuralAnchorRatio?: number;
  matchedAnchors?: number;
  totalAnchors?: number;
  distinctStorageSeedsCount?: number;
  browserFamilyConsensus?: boolean;
  osFamilyConsensus?: boolean;
}

/** Display band derived from the numeric confidence score. */
export type NumericConfidenceTier = 'High' | 'Medium-High' | 'Medium' | 'Low' | 'New/Unobserved';

export interface HonestIdentityConfidence {
  confidence_score: number | null;
  /** Numeric band for scored profiles; the legacy stage tier for unseen profiles. */
  confidence_tier: IdentityAxes['confidence_tier'] | NumericConfidenceTier;
  calibration_status: 'uncalibrated' | 'calibrated';
}

const TIER_BY_STAGE: Record<IdentityAxes['match_stage'], IdentityAxes['confidence_tier']> = {
  storage_continuity: 'First-Party Continuity Match',
  exact_hardware: 'High-Agreement Hardware Match',
  lsh_fuzzy: 'Probabilistic Fuzzy Match',
  privacy_hardened: 'Privacy-Hardened Profile (Reduced Entropy)',
  new_enrollment: 'New Unobserved Profile',
};

/** Only these stages represent an actual identity match with observable evidence. */
const MATCH_STAGES_WITH_EVIDENCE: ReadonlySet<string> = new Set([
  'storage_continuity',
  'exact_hardware',
  'lsh_fuzzy',
]);

/** Locked numeric-score → display-band mapping. */
export function confidenceBandForScore(score: number): NumericConfidenceTier {
  if (typeof score !== 'number' || !Number.isFinite(score) || score <= 0) return 'New/Unobserved';
  if (score >= 0.85) return 'High';
  if (score >= 0.65) return 'Medium-High';
  if (score >= 0.40) return 'Medium';
  return 'Low';
}

/**
 * Publishes a real, deterministic confidence number for profiles that actually matched,
 * and keeps `confidence_score: null` only for a genuinely unseen / non-identifying profile
 * (no storage continuity, no hardware match, no fuzzy match).
 *
 * `calibration_status` stays 'uncalibrated' on purpose: the numeric value comes from
 * weighted observable evidence (`scoreConfidence`), NOT from a claimed calibration gate.
 * The legacy calibration inputs are still accepted (and `calibratedScore` is used as a
 * fallback match-score signal) so existing callers keep working unchanged.
 */
export function computeHonestIdentityConfidence(input: CalibrationInput): HonestIdentityConfidence {
  const source: CalibrationInput = input && typeof input === 'object' ? input : ({} as CalibrationInput);
  const stage =
    typeof source.matchStage === 'string' ? source.matchStage.trim().toLowerCase() : 'new_enrollment';
  const explicitTier =
    typeof source.matchTier === 'string' ? source.matchTier.trim().toLowerCase() : '';
  // An explicit match tier is the authoritative evidence discriminator; the resolved stage
  // is the fallback for legacy callers that do not supply one.
  const effectiveTier = explicitTier || stage;
  const displayStage = MATCH_STAGES_WITH_EVIDENCE.has(effectiveTier) ? stage : effectiveTier;
  const stageTier = TIER_BY_STAGE[displayStage as IdentityAxes['match_stage']] || 'New Unobserved Profile';

  // Genuinely unseen / non-identifying: preserve the historical null score and stage tier.
  // Both the resolved stage AND the effective tier must carry real evidence — an explicit
  // `new_enrollment` never publishes a number, even if the stage claims a match (and vice
  // versa). No fabricated probability is ever emitted for these profiles.
  if (!MATCH_STAGES_WITH_EVIDENCE.has(stage) || !MATCH_STAGES_WITH_EVIDENCE.has(effectiveTier)) {
    return { confidence_score: null, confidence_tier: stageTier, calibration_status: 'uncalibrated' };
  }

  // Backward compatibility: the legacy calibrated score is a [0,1] probability-like value;
  // map it onto the engine's 0..100 match-score scale only when no explicit evidence exists.
  const fallbackMatchScore =
    typeof source.calibratedScore === 'number' && Number.isFinite(source.calibratedScore)
      ? Math.max(0, Math.min(1, source.calibratedScore)) * 100
      : 0;

  // Exactly one match-score signal is used — never both (no double counting). A present
  // but non-finite/negative explicit score is zeroed rather than replaced by a guess.
  const explicitMatchScore = source.matchScore;
  const matchScore =
    explicitMatchScore === undefined || explicitMatchScore === null
      ? fallbackMatchScore
      : typeof explicitMatchScore === 'number' &&
        Number.isFinite(explicitMatchScore) &&
        explicitMatchScore >= 0
      ? explicitMatchScore
      : 0;

  const score = scoreConfidence({
    match_tier: effectiveTier as EvidenceMatchTier,
    match_score: matchScore,
    structural_anchor_ratio: source.structuralAnchorRatio,
    matched_anchors: source.matchedAnchors,
    total_anchors: source.totalAnchors,
    distinct_storage_seeds_count: source.distinctStorageSeedsCount,
    browser_family_consensus: source.browserFamilyConsensus,
    os_family_consensus: source.osFamilyConsensus,
  });

  return {
    confidence_score: score,
    confidence_tier: confidenceBandForScore(score),
    calibration_status: 'uncalibrated',
  };
}

/**
 * Phase 6 — rarity honesty, proximity honesty and identity-calibration honesty.
 *
 * All numerical facts come from `telemetryContract.ts` (exact Clopper–Pearson and the
 * decideRarity gates). This module only applies the presentation / scoring policy:
 *  - suppressed rarity contributes ZERO score;
 *  - proximity is never derived from IP coordinates without granted geolocation permission;
 *  - confidence_score stays null (with a categorical tier + 'uncalibrated' status) until the
 *    held-out calibration gate (>=200 labeled pairs AND ECE < 0.05) has passed.
 */

import {
  decideRarity,
  type RarityDecision,
} from './telemetryContract';
import type { IdentityAxes } from './telemetryContract';

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
}

export interface HonestIdentityConfidence {
  confidence_score: number | null;
  confidence_tier: IdentityAxes['confidence_tier'];
  calibration_status: 'uncalibrated' | 'calibrated';
}

const TIER_BY_STAGE: Record<IdentityAxes['match_stage'], IdentityAxes['confidence_tier']> = {
  storage_continuity: 'First-Party Continuity Match',
  exact_hardware: 'High-Agreement Hardware Match',
  lsh_fuzzy: 'Probabilistic Fuzzy Match',
  privacy_hardened: 'Privacy-Hardened Profile (Reduced Entropy)',
  new_enrollment: 'New Unobserved Profile',
};

/**
 * Confidence is never a fabricated probability. Unseen / uncalibrated profiles receive a
 * categorical tier, a null confidence_score and 'uncalibrated' status until BOTH the
 * >=200 labeled-pair sample gate and the held-out ECE < 0.05 gate have passed.
 */
export function computeHonestIdentityConfidence(input: CalibrationInput): HonestIdentityConfidence {
  const confidence_tier = TIER_BY_STAGE[input.matchStage] || 'New Unobserved Profile';
  const calibrated =
    input.labeledPairs >= CALIBRATION_MIN_LABELED_PAIRS &&
    Number.isFinite(input.heldOutEce) &&
    input.heldOutEce < CALIBRATION_MAX_ECE;
  if (!calibrated) {
    return { confidence_score: null, confidence_tier, calibration_status: 'uncalibrated' };
  }
  const raw = typeof input.calibratedScore === 'number' && Number.isFinite(input.calibratedScore)
    ? input.calibratedScore
    : null;
  return {
    confidence_score: raw === null ? null : Math.max(0, Math.min(1, raw)),
    confidence_tier,
    calibration_status: 'calibrated',
  };
}

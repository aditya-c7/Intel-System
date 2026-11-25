/**
 * Confidence-% and risk-math regression suite.
 *
 * These tests pin the two deterministic calculations that used to drift:
 *   - the weighted, auditable identity-match confidence (0..1, four decimals) and its
 *     honest publication gate (null only for genuinely unseen profiles);
 *   - the canonical 0..100 risk composite -> 0..10 headline + tier mapping, checked
 *     against the frozen graded-ledger fixtures.
 *
 *   npx tsx scripts/test-confidence-risk.ts
 */
import assert from 'node:assert/strict';

import {
  EVIDENCE_CONFIDENCE_WEIGHTS,
  scoreConfidence,
  scoreConfidenceBreakdown,
  type ConfidenceComponent,
  type ConfidenceResult,
  type EvidenceConfidenceInput,
  type EvidenceMatchTier,
} from '../src/server/identity/confidenceScorer';
import {
  CALIBRATION_MAX_ECE,
  CALIBRATION_MIN_LABELED_PAIRS,
  confidenceBandForScore,
  computeHonestIdentityConfidence,
  type CalibrationInput,
} from '../src/lib/rarityHonesty';
import {
  GRADED_RISK_FIXTURES,
  buildGradedRiskLedger,
  riskTierFromScore100,
  score10FromScore100,
  verifyGradedRiskFixtures,
  type GradedRiskInput,
} from '../src/lib/riskLedger';
import { assertCanonicalConsistency, riskTier } from '../src/lib/telemetryContract';

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

type ScoredEvidence = EvidenceConfidenceInput & { match_tier: EvidenceMatchTier };

/** Evidence-shape inputs return a number; assert that dispatch explicitly. */
function evidenceScore(input: ScoredEvidence): number {
  const result = scoreConfidence(input);
  assert.equal(typeof result, 'number', 'evidence input must score to a number');
  return result as number;
}

function componentOf(components: readonly ConfidenceComponent[], name: string): ConfidenceComponent {
  const found = components.find((item) => item.name === name);
  assert.ok(found, `missing breakdown component: ${name}`);
  return found as ConfidenceComponent;
}

/** Count fractional digits without being fooled by scientific notation. */
function decimalPlaces(value: number): number {
  assert.ok(Number.isFinite(value), `not finite: ${value}`);
  const text = String(value);
  const exponent = text.indexOf('e-');
  if (exponent !== -1) {
    const mantissa = text.slice(0, exponent);
    const dot = mantissa.indexOf('.');
    const mantissaDigits = dot === -1 ? 0 : mantissa.length - dot - 1;
    return Number(text.slice(exponent + 2)) + mantissaDigits;
  }
  const dot = text.indexOf('.');
  return dot === -1 ? 0 : text.length - dot - 1;
}

function assertRoundedAtMost4(value: number, label: string): void {
  assert.ok(
    decimalPlaces(value) <= 4,
    `${label}=${value} has ${decimalPlaces(value)} decimals (expected <= 4)`,
  );
}

const FULL_EVIDENCE = {
  match_score: 100,
  structural_anchor_ratio: 1,
  distinct_storage_seeds_count: 1,
  browser_family_consensus: true,
  os_family_consensus: true,
} as const;

const CALIBRATED_GATE = {
  labeledPairs: CALIBRATION_MIN_LABELED_PAIRS + 300,
  heldOutEce: CALIBRATION_MAX_ECE / 5,
} as const;

/* -------------------------------------------------------------------------- */
/* 1. Evidence-based confidence score + breakdown                             */
/* -------------------------------------------------------------------------- */

section('1. Evidence-based confidence % math');

check('weights table is the locked six-component rubric', () => {
  assert.deepEqual(EVIDENCE_CONFIDENCE_WEIGHTS, {
    match_score: 0.25,
    structural_anchor: 0.15,
    storage_seed_single: 0.10,
    storage_seed_collision: -0.20,
    browser_family: 0.025,
    os_family: 0.025,
  });
});

check('breakdown has six ordered, named components', () => {
  const components = scoreConfidenceBreakdown({ match_tier: 'storage_continuity', ...FULL_EVIDENCE });
  assert.deepEqual(
    components.map((item) => item.name),
    [
      'match_tier_base',
      'match_score',
      'structural_anchor_ratio',
      'distinct_storage_seeds',
      'browser_family_consensus',
      'os_family_consensus',
    ],
  );
});

check('breakdown components sum exactly to the score', () => {
  const input: ScoredEvidence = { match_tier: 'lsh_fuzzy', ...FULL_EVIDENCE };
  const components = scoreConfidenceBreakdown(input);
  const summed = components.reduce((total, item) => total + item.contribution, 0);
  assert.equal(Math.round(summed * 10000) / 10000, evidenceScore(input));
});

check('exact per-component contributions and sum (mixed evidence, single seed)', () => {
  const input: ScoredEvidence = {
    match_tier: 'lsh_fuzzy',
    match_score: 80,
    structural_anchor_ratio: 0.5,
    distinct_storage_seeds_count: 1,
    browser_family_consensus: true,
    os_family_consensus: false,
  };
  const components = scoreConfidenceBreakdown(input);
  const expected: Record<string, { evidence: number; weight: number; contribution: number }> = {
    match_tier_base: { evidence: 0.2, weight: 1, contribution: 0.2 },
    match_score: { evidence: 0.8, weight: 0.25, contribution: 0.2 },
    structural_anchor_ratio: { evidence: 0.5, weight: 0.15, contribution: 0.075 },
    distinct_storage_seeds: { evidence: 1, weight: 0.1, contribution: 0.1 },
    browser_family_consensus: { evidence: 1, weight: 0.025, contribution: 0.025 },
    os_family_consensus: { evidence: 0, weight: 0.025, contribution: 0 },
  };
  assert.equal(components.length, Object.keys(expected).length);
  for (const component of components) {
    const want = expected[component.name];
    assert.ok(want, `unexpected component ${component.name}`);
    assert.equal(component.evidence, want.evidence, `${component.name}.evidence`);
    assert.equal(component.weight, want.weight, `${component.name}.weight`);
    assert.equal(component.contribution, want.contribution, `${component.name}.contribution`);
  }
  const summed = components.reduce((total, item) => total + item.contribution, 0);
  assert.equal(Math.round(summed * 10000) / 10000, 0.6);
  assert.equal(evidenceScore(input), 0.6);
});

check('exact per-component contributions and sum (collision evidence)', () => {
  const input: ScoredEvidence = {
    match_tier: 'exact_hardware',
    match_score: 90,
    structural_anchor_ratio: 1,
    distinct_storage_seeds_count: 2,
    browser_family_consensus: true,
    os_family_consensus: true,
  };
  const components = scoreConfidenceBreakdown(input);
  const expected: Record<string, { evidence: number; weight: number; contribution: number }> = {
    match_tier_base: { evidence: 0.35, weight: 1, contribution: 0.35 },
    match_score: { evidence: 0.9, weight: 0.25, contribution: 0.225 },
    structural_anchor_ratio: { evidence: 1, weight: 0.15, contribution: 0.15 },
    distinct_storage_seeds: { evidence: 2, weight: -0.2, contribution: -0.2 },
    browser_family_consensus: { evidence: 1, weight: 0.025, contribution: 0.025 },
    os_family_consensus: { evidence: 1, weight: 0.025, contribution: 0.025 },
  };
  assert.equal(components.length, Object.keys(expected).length);
  for (const component of components) {
    const want = expected[component.name];
    assert.ok(want, `unexpected component ${component.name}`);
    assert.equal(component.evidence, want.evidence, `${component.name}.evidence`);
    assert.equal(component.weight, want.weight, `${component.name}.weight`);
    assert.equal(component.contribution, want.contribution, `${component.name}.contribution`);
  }
  const summed = components.reduce((total, item) => total + item.contribution, 0);
  assert.equal(Math.round(summed * 10000) / 10000, 0.575);
  assert.equal(evidenceScore(input), 0.575);
});

check('storage_continuity exact -> high score (>0.85) and tier base 0.45', () => {
  const input: ScoredEvidence = { match_tier: 'storage_continuity', ...FULL_EVIDENCE };
  const score = evidenceScore(input);
  assert.notEqual(score, null);
  assert.ok(score > 0.85, `score ${score} must exceed 0.85`);
  assert.equal(score, 1); // 0.45 + 0.25 + 0.15 + 0.10 + 0.025 + 0.025
  assert.equal(componentOf(scoreConfidenceBreakdown(input), 'match_tier_base').contribution, 0.45);
});

check('exact_hardware anchor with one seed -> >0.65, non-null', () => {
  const score = evidenceScore({ match_tier: 'exact_hardware', ...FULL_EVIDENCE });
  assert.notEqual(score, null);
  assert.ok(score > 0.65, `score ${score} must exceed 0.65`);
  assert.equal(score, 0.9); // 0.35 base replaces the 0.45 storage-continuity base
});

check('exact_hardware anchor with zero seeds -> still >0.65', () => {
  const score = evidenceScore({
    match_tier: 'exact_hardware',
    match_score: 100,
    structural_anchor_ratio: 1,
    distinct_storage_seeds_count: 0,
    browser_family_consensus: true,
    os_family_consensus: true,
  });
  assert.ok(score > 0.65, `score ${score} must exceed 0.65`);
  assert.equal(score, 0.8);
});

check('lsh_fuzzy with density>=2 -> collision penalty applied, score is lower', () => {
  const base = {
    match_tier: 'lsh_fuzzy' as const,
    match_score: 100,
    structural_anchor_ratio: 1,
    browser_family_consensus: true,
    os_family_consensus: true,
  };
  const noCollision = evidenceScore({ ...base, distinct_storage_seeds_count: 0 });
  const collision = evidenceScore({ ...base, distinct_storage_seeds_count: 2 });
  assert.equal(noCollision, 0.65);
  assert.equal(collision, 0.45);
  assert.ok(collision < noCollision, 'collision must lower the score');
  assert.equal(
    Math.round((noCollision - collision) * 10000) / 10000,
    -EVIDENCE_CONFIDENCE_WEIGHTS.storage_seed_collision,
  );
  const seeds = componentOf(
    scoreConfidenceBreakdown({ ...base, distinct_storage_seeds_count: 2 }),
    'distinct_storage_seeds',
  );
  assert.equal(seeds.evidence, 2);
  assert.equal(seeds.weight, -0.2);
  assert.equal(seeds.contribution, -0.2);
});

check('single seed adds exactly +0.10 and every collision subtracts exactly -0.20', () => {
  const base = {
    match_tier: 'lsh_fuzzy' as const,
    match_score: 100,
    structural_anchor_ratio: 1,
    browser_family_consensus: false,
    os_family_consensus: false,
  };
  const zero = evidenceScore({ ...base, distinct_storage_seeds_count: 0 });
  const one = evidenceScore({ ...base, distinct_storage_seeds_count: 1 });
  assert.equal(Math.round((one - zero) * 10000) / 10000, 0.1);
  const single = componentOf(
    scoreConfidenceBreakdown({ ...base, distinct_storage_seeds_count: 1 }),
    'distinct_storage_seeds'
  );
  assert.equal(single.weight, 0.1);
  assert.equal(single.contribution, 0.1);
  assert.equal(single.evidence, 1);

  for (const seeds of [2, 3, 5, 100]) {
    const collision = evidenceScore({ ...base, distinct_storage_seeds_count: seeds });
    assert.equal(
      Math.round((zero - collision) * 10000) / 10000,
      0.2,
      `seeds=${seeds}: collision must cost exactly 0.20`,
    );
    const component = componentOf(
      scoreConfidenceBreakdown({ ...base, distinct_storage_seeds_count: seeds }),
      'distinct_storage_seeds'
    );
    assert.equal(component.weight, -0.2, `seeds=${seeds} weight`);
    assert.equal(component.contribution, -0.2, `seeds=${seeds} contribution`);
  }
});

check('anchor ratio can be derived from matched/total counts', () => {
  const score = evidenceScore({
    match_tier: 'exact_hardware',
    match_score: 100,
    matched_anchors: 7,
    total_anchors: 10,
    distinct_storage_seeds_count: 0,
  });
  assert.equal(score, 0.35 + 0.25 + 0.105); // 0.7 * 0.15 = 0.105
});

check('score is clamped to [0,1] at both extremes', () => {
  const tooHigh = evidenceScore({
    match_tier: 'storage_continuity',
    match_score: 500,
    structural_anchor_ratio: 5,
    distinct_storage_seeds_count: 1,
    browser_family_consensus: true,
    os_family_consensus: true,
  });
  assert.equal(tooHigh, 1);
  const tooLow = evidenceScore({
    match_tier: 'new_enrollment',
    match_score: -50,
    structural_anchor_ratio: -1,
    distinct_storage_seeds_count: 2,
  });
  assert.equal(tooLow, 0);
});

check('missing / malformed fields never throw and simply contribute zero', () => {
  for (const input of [undefined, null, {}, { match_tier: null }, { match_score: 'nope', structural_anchor_ratio: NaN }]) {
    assert.doesNotThrow(() => scoreConfidenceBreakdown(input as EvidenceConfidenceInput));
    const components = scoreConfidenceBreakdown(input as EvidenceConfidenceInput);
    assert.equal(components.length, 6);
    assert.equal(components.reduce((sum, item) => sum + item.contribution, 0), 0);
  }
  assert.doesNotThrow(() => scoreConfidence(null as any));
  assert.equal(evidenceScore({ match_tier: 'privacy_hardened' }), 0);
});

check('NaN / Infinity / wrong-type evidence never throws and never fabricates a collision', () => {
  const input: ScoredEvidence = {
    match_tier: 'lsh_fuzzy',
    match_score: Number.NaN,
    structural_anchor_ratio: Number.POSITIVE_INFINITY,
    matched_anchors: Number.NaN,
    total_anchors: Number.POSITIVE_INFINITY,
    distinct_storage_seeds_count: Number.NaN,
    browser_family_consensus: 'yes' as unknown as boolean,
    os_family_consensus: 'off' as unknown as boolean,
  };
  assert.doesNotThrow(() => scoreConfidenceBreakdown(input));
  const components = scoreConfidenceBreakdown(input);
  assert.equal(components.length, 6);
  // Malformed match/anchor evidence contributes zero.
  assert.equal(componentOf(components, 'match_score').evidence, 0);
  assert.equal(componentOf(components, 'match_score').contribution, 0);
  assert.equal(componentOf(components, 'structural_anchor_ratio').evidence, 0);
  assert.equal(componentOf(components, 'structural_anchor_ratio').contribution, 0);
  assert.equal(componentOf(components, 'browser_family_consensus').contribution, 0);
  assert.equal(componentOf(components, 'os_family_consensus').contribution, 0);
  // A PRESENT but invalid seed count is unavailable evidence, never a fabricated corroborating seed.
  const seeds = componentOf(components, 'distinct_storage_seeds');
  assert.equal(seeds.evidence, 0);
  assert.equal(seeds.weight, 0);
  assert.equal(seeds.contribution, 0);
  assert.match(seeds.detail, /invalid\/unavailable; zero weight/);
  // lsh_fuzzy base 0.20 only; no fabricated single-seed bonus.
  assert.equal(evidenceScore(input), 0.2);
  assert.doesNotThrow(() => scoreConfidence(input));
});

check('malformed seed variants stay at zero while missing seeds stay at zero', () => {
  const base = {
    match_tier: 'lsh_fuzzy' as const,
    match_score: 100,
    structural_anchor_ratio: 1,
    browser_family_consensus: false,
    os_family_consensus: false,
  };
  assert.equal(evidenceScore({ ...base }), 0.6); // 0.20 + 0.25 + 0.15, no seed evidence
  assert.equal(evidenceScore({ ...base, distinct_storage_seeds_count: null }), 0.6);
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5, 'abc']) {
    const input = { ...base, distinct_storage_seeds_count: bad as unknown as number };
    const component = componentOf(scoreConfidenceBreakdown(input), 'distinct_storage_seeds');
    assert.equal(component.weight, 0, `bad seed ${String(bad)} must carry no weight`);
    assert.equal(component.contribution, 0, `bad seed ${String(bad)} contribution`);
    assert.equal(evidenceScore(input), 0.6, `bad seed ${String(bad)} score`);
  }
});

check('consensus flags accept only the locked truthy tokens', () => {
  for (const value of [true, 1, '1', 'true']) {
    const component = componentOf(
      scoreConfidenceBreakdown({ os_family_consensus: value as unknown as boolean }),
      'os_family_consensus'
    );
    assert.equal(component.contribution, 0.025, `truthy ${String(value)}`);
  }
  for (const value of [false, 0, '0', 'yes', '', null, undefined]) {
    const component = componentOf(
      scoreConfidenceBreakdown({ os_family_consensus: value as unknown as boolean }),
      'os_family_consensus'
    );
    assert.equal(component.contribution, 0, `falsy ${String(value)}`);
  }
});

check('all evidence outputs are rounded to <= 4 decimals', () => {
  const input: ScoredEvidence = {
    match_tier: 'lsh_fuzzy',
    match_score: 87,
    structural_anchor_ratio: 0.91337,
    distinct_storage_seeds_count: 2,
    browser_family_consensus: true,
    os_family_consensus: false,
  };
  for (const item of scoreConfidenceBreakdown(input)) {
    assertRoundedAtMost4(item.evidence, `${item.name}.evidence`);
    assertRoundedAtMost4(item.weight, `${item.name}.weight`);
    assertRoundedAtMost4(item.contribution, `${item.name}.contribution`);
  }
  assertRoundedAtMost4(evidenceScore(input), 'score');
});

/* -------------------------------------------------------------------------- */
/* 1b. Continuity corroboration (P0-6)                                          */
/* -------------------------------------------------------------------------- */

section('1b. Continuity corroboration: 131 visits raises 0.60 -> 0.69');

/** A 0.60-scoring profile: lsh_fuzzy 0.20 + match 0.20 + anchors 0.075
 *  + single seed 0.10 + browser consensus 0.025 (no OS consensus). */
const CONTINUITY_BASE = {
  match_tier: 'lsh_fuzzy' as const,
  match_score: 80,
  structural_anchor_ratio: 0.5,
  distinct_storage_seeds_count: 1,
  browser_family_consensus: true,
  os_family_consensus: false,
};

check('0-visit baseline scores 0.60 regardless of an explicit zero count', () => {
  assert.equal(evidenceScore({ ...CONTINUITY_BASE }), 0.6);
  assert.equal(evidenceScore({ ...CONTINUITY_BASE, visitContinuity: 0 }), 0.6);
});

check('131-visit corroborated input scores 0.69 (+0.09 capped) vs 0.60 baseline', () => {
  const zero = evidenceScore({ ...CONTINUITY_BASE });
  const oneThirtyOne = evidenceScore({
    ...CONTINUITY_BASE,
    storageHealed: true,
    visitContinuity: 131,
    profileAgeDays: 180,
  });
  assert.equal(zero, 0.6);
  assert.equal(oneThirtyOne, 0.69);
  assert.equal(Math.round((oneThirtyOne - zero) * 10000) / 10000, 0.09);
});

check('six components still sum exactly to the published corroborated score', () => {
  const input: ScoredEvidence = {
    ...CONTINUITY_BASE,
    storageHealed: true,
    visitContinuity: 131,
    profileAgeDays: 180,
  };
  const components = scoreConfidenceBreakdown(input);
  assert.equal(components.length, 6);
  const summed = Math.round(components.reduce((total, item) => total + item.contribution, 0) * 10000) / 10000;
  assert.equal(summed, 0.69);
  assert.equal(summed, evidenceScore(input));
  // The single seed (+0.10) and the full corroboration (+0.09) share one signed bucket.
  const seeds = componentOf(components, 'distinct_storage_seeds');
  assert.equal(seeds.weight, 0.1);
  assert.equal(seeds.contribution, 0.19);
  assert.match(seeds.detail, /continuity corroboration \+0\.09/);
  assert.match(seeds.detail, /visitContinuity=131/);
});

check('corroboration is suppressed for an unmatched tier', () => {
  const unmatched: ScoredEvidence = {
    match_tier: 'new_enrollment',
    match_score: 80,
    structural_anchor_ratio: 0.5,
    distinct_storage_seeds_count: 1,
    storageHealed: true,
    visitContinuity: 131,
    profileAgeDays: 180,
  };
  const without = evidenceScore({ ...unmatched, storageHealed: undefined, visitContinuity: undefined, profileAgeDays: undefined });
  assert.equal(evidenceScore(unmatched), without);
  assert.equal(componentOf(scoreConfidenceBreakdown(unmatched), 'distinct_storage_seeds').detail.match(/continuity corroboration/) ?? null, null);
});

/* -------------------------------------------------------------------------- */
/* 2. Honest publication of the number                                         */
/* -------------------------------------------------------------------------- */

section('2. Honest identity confidence publication');

check('storage_continuity exact -> non-null >0.85 with a High band', () => {
  const result = computeHonestIdentityConfidence({
    ...CALIBRATED_GATE,
    matchStage: 'storage_continuity',
    matchScore: 100,
    structuralAnchorRatio: 1,
    distinctStorageSeedsCount: 1,
    browserFamilyConsensus: true,
    osFamilyConsensus: true,
  });
  assert.notEqual(result.confidence_score, null);
  assert.ok((result.confidence_score ?? 0) > 0.85, String(result.confidence_score));
  assert.equal(result.confidence_score, 1);
  assert.equal(result.confidence_tier, 'High');
  // CALIBRATED_GATE (200 pairs, ECE<=0.05) now passes the real calibration gate, so a
  // genuinely scored match is honestly 'calibrated' rather than forced 'uncalibrated'.
  assert.equal(result.calibration_status, 'calibrated');
});

check('exact hardware anchor with <=1 seed -> non-null >0.65', () => {
  for (const seeds of [0, 1]) {
    const result = computeHonestIdentityConfidence({
      ...CALIBRATED_GATE,
      matchStage: 'exact_hardware',
      matchScore: 100,
      structuralAnchorRatio: 1,
      distinctStorageSeedsCount: seeds,
      browserFamilyConsensus: true,
      osFamilyConsensus: true,
    });
    assert.notEqual(result.confidence_score, null);
    assert.ok((result.confidence_score ?? 0) > 0.65, `seeds=${seeds}: ${result.confidence_score}`);
  }
});

check('lsh_fuzzy with density>=2 is lower and carries the collision penalty', () => {
  const base: Omit<CalibrationInput, 'matchStage' | 'distinctStorageSeedsCount'> = {
    ...CALIBRATED_GATE,
    matchScore: 100,
    structuralAnchorRatio: 1,
    browserFamilyConsensus: true,
    osFamilyConsensus: true,
  };
  const clean = computeHonestIdentityConfidence({
    ...base,
    matchStage: 'lsh_fuzzy',
    distinctStorageSeedsCount: 0,
  });
  const collision = computeHonestIdentityConfidence({
    ...base,
    matchStage: 'lsh_fuzzy',
    distinctStorageSeedsCount: 2,
  });
  assert.equal(clean.confidence_score, 0.65);
  assert.equal(collision.confidence_score, 0.45);
  assert.ok((collision.confidence_score ?? 1) < (clean.confidence_score ?? 0));
  assert.equal(
    Math.round(((clean.confidence_score ?? 0) - (collision.confidence_score ?? 0)) * 10000) / 10000,
    -EVIDENCE_CONFIDENCE_WEIGHTS.storage_seed_collision,
  );
});

check('new_enrollment with no storage stays null / uncalibrated', () => {
  const result = computeHonestIdentityConfidence({ ...CALIBRATED_GATE, matchStage: 'new_enrollment' });
  assert.equal(result.confidence_score, null);
  assert.equal(result.confidence_tier, 'New Unobserved Profile');
  assert.equal(result.calibration_status, 'uncalibrated');
});

check('honest confidence is clamped to [0,1] and rounded to <=4 decimals', () => {
  const upper = computeHonestIdentityConfidence({
    ...CALIBRATED_GATE,
    matchStage: 'storage_continuity',
    matchScore: 1000,
    structuralAnchorRatio: 9,
    distinctStorageSeedsCount: 1,
    browserFamilyConsensus: true,
    osFamilyConsensus: true,
  });
  const lower = computeHonestIdentityConfidence({
    ...CALIBRATED_GATE,
    matchStage: 'lsh_fuzzy',
    matchScore: -100,
    distinctStorageSeedsCount: 3,
  });
  assert.equal(upper.confidence_score, 1);
  assert.equal(lower.confidence_score, 0);
  assertRoundedAtMost4(upper.confidence_score ?? 0, 'upper confidence_score');
  assertRoundedAtMost4(lower.confidence_score ?? 0, 'lower confidence_score');
});

check('honest confidence accepts missing / null input without throwing', () => {
  assert.doesNotThrow(() => computeHonestIdentityConfidence(null as unknown as CalibrationInput));
  const missing = computeHonestIdentityConfidence(null as unknown as CalibrationInput);
  assert.equal(missing.confidence_score, null);
  assert.equal(missing.confidence_tier, 'New Unobserved Profile');
});

check('numeric display bands use the locked boundaries', () => {
  assert.equal(confidenceBandForScore(0), 'New/Unobserved');
  assert.equal(confidenceBandForScore(0.3999), 'Low');
  assert.equal(confidenceBandForScore(0.4), 'Medium');
  assert.equal(confidenceBandForScore(0.65), 'Medium-High');
  assert.equal(confidenceBandForScore(0.85), 'High');
  assert.equal(confidenceBandForScore(1), 'High');
});

check('boundary bands are exact on both sides of 0 / 0.4 / 0.65 / 0.85', () => {
  assert.equal(confidenceBandForScore(-1), 'New/Unobserved');
  assert.equal(confidenceBandForScore(Number.NaN), 'New/Unobserved');
  assert.equal(confidenceBandForScore(0.3999), 'Low');
  assert.equal(confidenceBandForScore(0.4), 'Medium');
  assert.equal(confidenceBandForScore(0.6499), 'Medium');
  assert.equal(confidenceBandForScore(0.65), 'Medium-High');
  assert.equal(confidenceBandForScore(0.8499), 'Medium-High');
  assert.equal(confidenceBandForScore(0.85), 'High');
});

check('non-matching stages stay null even with strong-looking evidence', () => {
  const strongEvidence = {
    matchScore: 100,
    structuralAnchorRatio: 1,
    distinctStorageSeedsCount: 1,
    browserFamilyConsensus: true,
    osFamilyConsensus: true,
  };
  for (const matchStage of ['new_enrollment', 'privacy_hardened'] as const) {
    const result = computeHonestIdentityConfidence({ ...CALIBRATED_GATE, ...strongEvidence, matchStage });
    assert.equal(result.confidence_score, null, `${matchStage} must stay null`);
    assert.equal(result.calibration_status, 'uncalibrated', matchStage);
  }
  // A matching stage with no evidence still publishes an honest, non-null number.
  const fuzzyNoEvidence = computeHonestIdentityConfidence({ ...CALIBRATED_GATE, matchStage: 'lsh_fuzzy' });
  assert.equal(fuzzyNoEvidence.confidence_score, 0.2);
  assert.equal(fuzzyNoEvidence.confidence_tier, 'Low');
});

check('confidence_score mirrors agree across the scorer, honest publisher and band', () => {
  const cases: ReadonlyArray<{
    stage: EvidenceMatchTier;
    seeds: number;
    score: number;
    band: 'High' | 'Medium-High' | 'Medium';
  }> = [
    { stage: 'storage_continuity', seeds: 1, score: 1, band: 'High' },
    { stage: 'exact_hardware', seeds: 0, score: 0.8, band: 'Medium-High' },
    { stage: 'exact_hardware', seeds: 1, score: 0.9, band: 'High' },
    { stage: 'lsh_fuzzy', seeds: 0, score: 0.65, band: 'Medium-High' },
    { stage: 'lsh_fuzzy', seeds: 2, score: 0.45, band: 'Medium' },
  ];
  for (const c of cases) {
    const raw = evidenceScore({
      match_tier: c.stage,
      match_score: 100,
      structural_anchor_ratio: 1,
      distinct_storage_seeds_count: c.seeds,
      browser_family_consensus: true,
      os_family_consensus: true,
    });
    const honest = computeHonestIdentityConfidence({
      ...CALIBRATED_GATE,
      matchStage: c.stage,
      matchScore: 100,
      structuralAnchorRatio: 1,
      distinctStorageSeedsCount: c.seeds,
      browserFamilyConsensus: true,
      osFamilyConsensus: true,
    });
    assert.equal(honest.confidence_score, raw, `${c.stage}/${c.seeds}: raw vs honest mirror`);
    assert.equal(honest.confidence_score, c.score, `${c.stage}/${c.seeds}: exact score`);
    assert.equal(confidenceBandForScore(honest.confidence_score ?? 0), c.band, `${c.stage}/${c.seeds}: band`);
    assert.equal(honest.confidence_tier, c.band, `${c.stage}/${c.seeds}: honest tier mirror`);
  }
});

check('continuity signals are forwarded and never force calibration', () => {
  const base: Omit<CalibrationInput, 'matchStage'> = {
    ...CALIBRATED_GATE,
    matchScore: 80,
    structuralAnchorRatio: 0.5,
    distinctStorageSeedsCount: 1,
    browserFamilyConsensus: true,
    osFamilyConsensus: false,
  };
  const zero = computeHonestIdentityConfidence({ ...base, matchStage: 'lsh_fuzzy' });
  const corroborated = computeHonestIdentityConfidence({
    ...base,
    matchStage: 'lsh_fuzzy',
    storageHealed: true,
    visitContinuity: 131,
    profileAgeDays: 180,
  });
  assert.equal(zero.confidence_score, 0.6);
  assert.equal(corroborated.confidence_score, 0.69);
  // A dormant gate stays uncalibrated even though the evidence score rose by +0.09.
  const dormantGate = computeHonestIdentityConfidence({
    labeledPairs: 0,
    heldOutEce: 1,
    matchStage: 'lsh_fuzzy',
    matchScore: 80,
    structuralAnchorRatio: 0.5,
    distinctStorageSeedsCount: 1,
    browserFamilyConsensus: true,
    storageHealed: true,
    visitContinuity: 131,
    profileAgeDays: 180,
  });
  assert.equal(dormantGate.confidence_score, 0.69);
  assert.equal(dormantGate.calibration_status, 'uncalibrated');
});

/* -------------------------------------------------------------------------- */
/* 3. Risk math                                                                */
/* -------------------------------------------------------------------------- */

section('3. Risk 0-100 -> 0-10 mapping and tiers');

check('score10FromScore100 exact frozen values', () => {
  assert.equal(score10FromScore100(67), 7);
  assert.equal(score10FromScore100(100), 10);
  assert.equal(score10FromScore100(35), 4);
  assert.equal(score10FromScore100(0), 0);
});

check('score10FromScore100 clamps and treats non-finite as zero', () => {
  assert.equal(score10FromScore100(-5), 0);
  assert.equal(score10FromScore100(200), 10);
  assert.equal(score10FromScore100(Number.NaN), 0);
});

check('tier thresholds are Low<25, Elevated<50, High<75, Critical>=75', () => {
  assert.equal(riskTierFromScore100(24), 'Low');
  assert.equal(riskTierFromScore100(25), 'Elevated');
  assert.equal(riskTierFromScore100(49), 'Elevated');
  assert.equal(riskTierFromScore100(50), 'High');
  assert.equal(riskTierFromScore100(74), 'High');
  assert.equal(riskTierFromScore100(75), 'Critical');
  assert.equal(riskTierFromScore100(100), 'Critical');
  assert.equal(riskTierFromScore100(Number.NaN), 'Low');
});

check('graded tier helper agrees with the canonical riskTier at every boundary', () => {
  for (const score of [0, 24, 25, 49, 50, 67, 74, 75, 99, 100]) {
    assert.equal(riskTierFromScore100(score), riskTier(score), `score ${score}`);
  }
});

check('frozen graded fixtures still produce 67/35/100/0 with matching score10/tier', () => {
  const expected: ReadonlyArray<{
    name: string;
    score100: number;
    score10: number;
    tier: string;
  }> = [
    { name: 'MCP Playwright', score100: 67, score10: 7, tier: 'High' },
    { name: 'spec fuzz', score100: 35, score10: 4, tier: 'Elevated' },
    { name: 'drift + proxy + velocity', score100: 100, score10: 10, tier: 'Critical' },
    { name: 'clean human', score100: 0, score10: 0, tier: 'Low' },
  ];
  assert.equal(GRADED_RISK_FIXTURES.length, expected.length);
  expected.forEach((want, index) => {
    const fixture = GRADED_RISK_FIXTURES[index];
    assert.equal(fixture.name, want.name);
    const ledger = buildGradedRiskLedger(fixture.input as GradedRiskInput);
    assert.equal(ledger.score_0_100, want.score100, `${want.name} composite`);
    assert.equal(ledger.score10, want.score10, `${want.name} headline`);
    assert.equal(ledger.risk_tier, want.tier, `${want.name} graded tier`);
    assert.equal(ledger.tier, want.tier, `${want.name} contract tier`);
    assert.equal(ledger.score10, score10FromScore100(ledger.score_0_100));
    assert.equal(ledger.risk_tier, riskTierFromScore100(ledger.score_0_100));
  });
});

check('verifyGradedRiskFixtures validates every frozen tuple', () => {
  const results = verifyGradedRiskFixtures();
  assert.equal(results.length, 4);
  for (const result of results) {
    assert.equal(result.ok, true, `${result.name} fixture drifted`);
  }
});

/* -------------------------------------------------------------------------- */
/* 4. Legacy scorer contract — ConfidenceResult must keep its full shape       */
/* -------------------------------------------------------------------------- */

section('4. Legacy scoreConfidence callers still receive ConfidenceResult');

check('evidence-shape scoreConfidence still returns a number (dispatch lock)', () => {
  const value = scoreConfidence({ match_tier: 'storage_continuity', ...FULL_EVIDENCE });
  assert.equal(typeof value, 'number');
  assert.equal(value as number, 1);
});

check('legacy scoreConfidence returns a complete ConfidenceResult', () => {
  const result: ConfidenceResult = scoreConfidence({
    match_mode: 'exact',
    match_score: 100,
    storage_healed: true,
    entropy: {
      deterministicCanvas: true,
      unmaskedWebgl: true,
      fontsCount: 12,
      deterministicAudio: true,
    },
  });
  assert.equal(typeof result, 'object');
  assert.ok(!Array.isArray(result));
  assert.equal(result.version, '2.0');
  assert.equal(typeof result.score, 'number');
  assert.ok(Number.isFinite(result.score));
  assert.equal(typeof result.tampering, 'boolean');
  assert.equal(typeof result.tampering_ml_score, 'number');
  assert.ok(
    result.spoof_likelihood === 'low' ||
      result.spoof_likelihood === 'medium' ||
      result.spoof_likelihood === 'high',
    `bad spoof_likelihood ${result.spoof_likelihood}`,
  );
  assert.equal(typeof result.breakdown.base_tier, 'number');
  assert.equal(typeof result.breakdown.entropy_bonus, 'number');
  assert.equal(typeof result.breakdown.penalty, 'number');
  assert.ok(Array.isArray(result.breakdown.reasons));
  // Exact, auditable legacy math: 0.985 base + 0.014 entropy - 0 penalty, clamped to 0.999.
  assert.equal(result.breakdown.base_tier, 0.985);
  assert.equal(result.breakdown.entropy_bonus, 0.014);
  assert.equal(result.breakdown.penalty, 0);
  assert.equal(result.score, 0.999);
  assert.equal(result.tampering, false);
  assert.equal(result.spoof_likelihood, 'low');
});

check('legacy genuine-spoof input reports tampering + high spoof fields', () => {
  const result: ConfidenceResult = scoreConfidence({
    match_mode: 'none',
    match_score: 0,
    genuineSpoof: true,
    consistencyFlags: ['gpu_vendor_mismatch', 'canvas_noise_uniform'],
  });
  assert.equal(result.tampering, true);
  assert.equal(result.spoof_likelihood, 'high');
  assert.equal(result.tampering_ml_score, 0.9);
  assert.equal(result.breakdown.penalty, 0.35);
  assert.ok(result.breakdown.reasons.includes('consistency_genuine_spoof'));
  // Clean first-visit base 0.900 + 0 entropy - 0.35 penalty -> 0.55 (above the 0.10 floor).
  assert.equal(result.breakdown.base_tier, 0.9);
  assert.equal(result.score, 0.55);
});

/* -------------------------------------------------------------------------- */
/* 5. Tranche 0-1 — canonical risk headline consistency                        */
/* -------------------------------------------------------------------------- */

section('5. Tranche 0-1 risk headline consistency');

const canonicalHeadlineCases: ReadonlyArray<{
  score100: number;
  score10: number;
  tier: string;
}> = [
  { score100: 67, score10: 7, tier: 'High' },
  { score100: 100, score10: 10, tier: 'Critical' },
  { score100: 0, score10: 0, tier: 'Low' },
];

for (const c of canonicalHeadlineCases) {
  check(`score10/tier mapping ${c.score100} -> ${c.score10}/${c.tier}`, () => {
    assert.equal(score10FromScore100(c.score100), c.score10);
    assert.equal(riskTierFromScore100(c.score100), c.tier);
    assert.equal(riskTier(c.score100), c.tier);
  });
}

const gradedHeadlineFixtures = [
  {
    input: {
      automation: { tierA: true },
      network: { vpnOrRelay: true },
      environment: { swiftshader: true, ephemeralOrPrivateStorage: true },
    } as GradedRiskInput,
    score100: 67,
    score10: 7,
    tier: 'High',
  },
  {
    input: {
      automation: { tierB: true },
      tampering: { tierA: true },
      network: { rotatingProxy: true },
      environment: { ephemeralOrPrivateStorage: true },
      velocity: { high: true },
    } as GradedRiskInput,
    score100: 100,
    score10: 10,
    tier: 'Critical',
  },
  { input: {} as GradedRiskInput, score100: 0, score10: 0, tier: 'Low' },
];

for (const fixture of gradedHeadlineFixtures) {
  check(`graded ledger ${fixture.score100} carries score10=${fixture.score10} / ${fixture.tier}`, () => {
    const ledger = buildGradedRiskLedger(fixture.input);
    assert.equal(ledger.score_0_100, fixture.score100);
    assert.equal(ledger.score10, fixture.score10);
    assert.equal(ledger.risk_tier, fixture.tier);
    assert.equal(ledger.tier, fixture.tier);
  });
}

check('all frozen graded ledgers agree with the canonical consistency checker', () => {
  for (const fixture of GRADED_RISK_FIXTURES) {
    const ledger = buildGradedRiskLedger(fixture.input);
    const issues = assertCanonicalConsistency({
      risk: {
        score_0_100: ledger.score_0_100,
        tier: ledger.tier,
        score10: ledger.score10,
        risk_tier: ledger.risk_tier,
      },
    });
    assert.deepEqual(issues, [], fixture.name);
  }
});

/*
 * The badge string is still assembled inline in App.tsx / server.ts; there is no shared
 * `riskBadgeText` export to import. Keep the expectation local and emit an explicit SKIP
 * so the missing parity helper is never silent.
 */
console.log('  SKIP  riskBadgeText parity helper (not exported from src/lib) — asserting local expected badge text');
const expectedRiskBadgeText = (score10: number, tier: string): string => `${tier} Risk • ${score10}/10`;

check('local riskBadgeText expectation matches the canonical headline math', () => {
  assert.equal(expectedRiskBadgeText(7, 'High'), 'High Risk • 7/10');
  assert.equal(expectedRiskBadgeText(10, 'Critical'), 'Critical Risk • 10/10');
  assert.equal(expectedRiskBadgeText(0, 'Low'), 'Low Risk • 0/10');
  for (const fixture of gradedHeadlineFixtures) {
    const ledger = buildGradedRiskLedger(fixture.input);
    assert.equal(
      expectedRiskBadgeText(ledger.score10, ledger.risk_tier),
      `${fixture.tier} Risk • ${fixture.score10}/10`,
    );
  }
});

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}

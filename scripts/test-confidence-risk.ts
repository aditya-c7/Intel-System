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
import { riskTier } from '../src/lib/telemetryContract';

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
  assert.equal(result.calibration_status, 'uncalibrated');
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

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}

/**
 * Calibration engine regression suite.
 *
 * Pins the additive evidence scoring and — above all — the locked honesty gate: a record is
 * 'calibrated' ONLY via the imported rarityHonesty gate (>= 200 labeled pairs, ECE <= 0.05).
 * The evidence score can never promote a record on its own.
 *
 *   npx tsx scripts/test-calibration-engine.ts
 */
import assert from 'node:assert/strict';

import {
  CALIBRATION_EVIDENCE_WEIGHTS,
  buildCalibrationEvidence,
  confidenceLabelFor,
  type CalibrationEvidenceRecord,
} from '../src/lib/calibrationEngine';
import {
  CALIBRATION_MAX_ECE,
  CALIBRATION_MIN_LABELED_PAIRS,
  confidenceLabel,
} from '../src/lib/rarityHonesty';

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

const STRONG_EVIDENCE = {
  sourceCompleteness: 1,
  neighborMargin: 1,
  crossLayerAgreement: 1,
  returnStability: 1,
} as const;

const PASSING_GATE = {
  labeledPairs: CALIBRATION_MIN_LABELED_PAIRS,
  ece: CALIBRATION_MAX_ECE,
} as const;

/* -------------------------------------------------------------------------- */
/* 1. Additive scoring                                                         */
/* -------------------------------------------------------------------------- */

section('1. Additive calibration evidence scoring (0..1)');

check('weights are the locked rubric and sum to exactly 1', () => {
  assert.deepEqual(CALIBRATION_EVIDENCE_WEIGHTS, {
    source_completeness: 0.3,
    neighbor_margin: 0.25,
    cross_layer_agreement: 0.25,
    return_stability: 0.2,
  });
  const sum = Object.values(CALIBRATION_EVIDENCE_WEIGHTS).reduce((a, b) => a + b, 0);
  assert.equal(Math.round(sum * 10000) / 10000, 1);
});

check('record has four named components in fixed order', () => {
  const record = buildCalibrationEvidence(STRONG_EVIDENCE);
  assert.deepEqual(
    record.components.map((c) => c.name),
    ['source_completeness', 'neighbor_margin', 'cross_layer_agreement', 'return_stability']
  );
  assert.equal(record.components.length, 4);
});

check('every component score and contribution is within [0,1]', () => {
  const record = buildCalibrationEvidence({
    sourceCompleteness: 0.75,
    neighborMargin: 0.4,
    crossLayerAgreement: 0.9,
    returnStability: 0.1,
    ...PASSING_GATE,
  });
  for (const component of record.components) {
    assert.ok(component.score >= 0 && component.score <= 1, `${component.name}.score`);
    assert.ok(
      component.contribution >= 0 && component.contribution <= 1,
      `${component.name}.contribution`
    );
    assert.equal(
      component.contribution,
      Math.round(component.score * component.weight * 10000) / 10000,
      `${component.name} additive (4-decimal rounded)`
    );
  }
  assert.ok(record.evidence_score >= 0 && record.evidence_score <= 1);
});

check('evidence_score is exactly the additive sum of contributions', () => {
  const record = buildCalibrationEvidence({
    sourceCompleteness: 0.75,
    neighborMargin: 0.4,
    crossLayerAgreement: 0.9,
    returnStability: 0.1,
  });
  const sum = record.components.reduce((a, c) => a + c.contribution, 0);
  assert.equal(record.evidence_score, Math.round(sum * 10000) / 10000);
});

check('perfect evidence yields evidence_score = 1', () => {
  const record = buildCalibrationEvidence(STRONG_EVIDENCE);
  assert.equal(record.evidence_score, 1);
  assert.ok(record.components.every((c) => c.score === 1));
});

check('absent / zero evidence yields evidence_score = 0', () => {
  const record = buildCalibrationEvidence({});
  assert.equal(record.evidence_score, 0);
  assert.ok(record.components.every((c) => c.score === 0 && c.contribution === 0));
});

check('out-of-range signals are clamped to [0,1]', () => {
  const high = buildCalibrationEvidence({
    sourceCompleteness: 5,
    neighborMargin: 2,
    crossLayerAgreement: 99,
    returnStability: 1.0001,
  });
  assert.ok(high.components.every((c) => c.score === 1));
  assert.equal(high.evidence_score, 1);
  const low = buildCalibrationEvidence({
    sourceCompleteness: -5,
    neighborMargin: -0.2,
    crossLayerAgreement: -99,
    returnStability: -1.0001,
  });
  assert.ok(low.components.every((c) => c.score === 0));
  assert.equal(low.evidence_score, 0);
});

check('partial evidence produces the exact weighted sum', () => {
  const record = buildCalibrationEvidence({
    sourceCompleteness: 1,
    neighborMargin: 0,
    crossLayerAgreement: 0,
    returnStability: 0,
  });
  // Only source_completeness contributes: 1 * 0.30 = 0.30.
  assert.equal(record.evidence_score, 0.3);
  assert.equal(record.components[0].contribution, 0.3);
});

/* -------------------------------------------------------------------------- */
/* 2. The locked calibration gate (reused, never duplicated)                   */
/* -------------------------------------------------------------------------- */

section('2. Locked gate: >= 200 labeled pairs AND ECE <= 0.05');

check('re-exported constants equal the rarityHonesty source of truth', () => {
  assert.equal(CALIBRATION_MIN_LABELED_PAIRS, 200);
  assert.equal(CALIBRATION_MAX_ECE, 0.05);
});

check('record is deterministic (pure): identical input -> identical output', () => {
  const a = buildCalibrationEvidence({ ...STRONG_EVIDENCE, ...PASSING_GATE });
  const b = buildCalibrationEvidence({ ...STRONG_EVIDENCE, ...PASSING_GATE });
  assert.deepEqual(a, b);
});

check('building does not mutate the caller input', () => {
  const input = { ...STRONG_EVIDENCE, ...PASSING_GATE };
  const snapshot = { ...input };
  buildCalibrationEvidence(input);
  assert.deepEqual(input, snapshot);
});

check('gate boundary: 199 labeled pairs is uncalibrated', () => {
  const record = buildCalibrationEvidence({ ...STRONG_EVIDENCE, labeledPairs: 199, ece: 0 });
  assert.equal(record.calibration_status, 'uncalibrated');
  assert.equal(record.labeled_pairs, 199);
});

check('gate boundary: exactly 200 labeled pairs is calibrated', () => {
  const record = buildCalibrationEvidence({ ...STRONG_EVIDENCE, labeledPairs: 200, ece: 0 });
  assert.equal(record.calibration_status, 'calibrated');
});

check('ECE boundary: 0.05 is calibrated', () => {
  const record = buildCalibrationEvidence({ ...STRONG_EVIDENCE, labeledPairs: 200, ece: 0.05 });
  assert.equal(record.calibration_status, 'calibrated');
  assert.equal(record.ece, 0.05);
});

check('ECE boundary: 0.051 is uncalibrated', () => {
  const record = buildCalibrationEvidence({ ...STRONG_EVIDENCE, labeledPairs: 200, ece: 0.051 });
  assert.equal(record.calibration_status, 'uncalibrated');
});

check('both gate conditions are required (200 pairs but bad ECE fails)', () => {
  const record = buildCalibrationEvidence({ ...STRONG_EVIDENCE, labeledPairs: 250, ece: 0.051 });
  assert.equal(record.calibration_status, 'uncalibrated');
});

check('both gate conditions are required (good ECE but 199 pairs fails)', () => {
  const record = buildCalibrationEvidence({ ...STRONG_EVIDENCE, labeledPairs: 199, ece: 0.01 });
  assert.equal(record.calibration_status, 'uncalibrated');
});

check('perfect evidence cannot promote a failing gate', () => {
  const record = buildCalibrationEvidence({ ...STRONG_EVIDENCE, labeledPairs: 199, ece: 0.9 });
  assert.equal(record.evidence_score, 1);
  assert.equal(record.calibration_status, 'uncalibrated');
});

check('zero evidence still yields calibrated when the gate passes', () => {
  const record = buildCalibrationEvidence({ labeledPairs: 200, ece: 0.04 });
  assert.equal(record.evidence_score, 0);
  assert.equal(record.calibration_status, 'calibrated');
});

check('negative / non-finite ECE fails closed', () => {
  for (const ece of [-0.01, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    const record = buildCalibrationEvidence({ ...STRONG_EVIDENCE, labeledPairs: 500, ece });
    assert.equal(record.calibration_status, 'uncalibrated', `ece=${String(ece)}`);
  }
});

check('negative / non-finite labeled-pair count fails closed', () => {
  for (const labeledPairs of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
    const record = buildCalibrationEvidence({ ...STRONG_EVIDENCE, labeledPairs, ece: 0 });
    assert.equal(record.calibration_status, 'uncalibrated', `pairs=${String(labeledPairs)}`);
  }
});

check('no gate inputs defaults to uncalibrated', () => {
  const record = buildCalibrationEvidence(STRONG_EVIDENCE);
  assert.equal(record.calibration_status, 'uncalibrated');
  assert.equal(record.labeled_pairs, null);
  assert.equal(record.ece, null);
});

check('status is always one of the two honest values', () => {
  for (const record of [
    buildCalibrationEvidence(),
    buildCalibrationEvidence({ ...STRONG_EVIDENCE, ...PASSING_GATE }),
    buildCalibrationEvidence({ labeledPairs: 199, ece: 0.05 }),
  ]) {
    assert.ok(
      record.calibration_status === 'calibrated' || record.calibration_status === 'uncalibrated',
      String(record.calibration_status)
    );
  }
});

/* -------------------------------------------------------------------------- */
/* 3. Hostile input — never throws, fails closed                               */
/* -------------------------------------------------------------------------- */

section('3. Hostile input fails closed without throwing');

check('null / undefined / primitive inputs never throw and stay uncalibrated', () => {
  const hostile: unknown[] = [null, undefined, 42, 'calibrate', true, [], () => undefined];
  for (const value of hostile) {
    let record: CalibrationEvidenceRecord | undefined;
    assert.doesNotThrow(() => {
      record = buildCalibrationEvidence(value as never);
    }, `threw for ${String(value)}`);
    assert.equal(record?.calibration_status, 'uncalibrated');
    assert.equal(record?.evidence_score, 0);
    assert.equal(record?.components.length, 4);
  }
});

check('hostile signal types are zeroed, not thrown or guessed', () => {
  const record = buildCalibrationEvidence({
    sourceCompleteness: 'high' as unknown as number,
    neighborMargin: Number.NaN,
    crossLayerAgreement: {} as unknown as number,
    returnStability: [] as unknown as number,
    ...PASSING_GATE,
  });
  assert.equal(record.evidence_score, 0);
  assert.ok(record.components.every((c) => c.score === 0));
  // Gate still legitimately passes: hostile signals do not affect status.
  assert.equal(record.calibration_status, 'calibrated');
});

check('hostile gate input types cannot be forged into calibrated', () => {
  const record = buildCalibrationEvidence({
    ...STRONG_EVIDENCE,
    labeledPairs: '200' as unknown as number,
    ece: '0.01' as unknown as number,
  });
  assert.equal(record.calibration_status, 'uncalibrated');
  assert.equal(record.labeled_pairs, null);
  assert.equal(record.ece, null);
});

/* -------------------------------------------------------------------------- */
/* 4. Confidence label reuses existing wording                                 */
/* -------------------------------------------------------------------------- */

section('4. confidenceLabelFor delegates wording to confidenceLabel');

check('calibrated status uses the "Confidence X%" wording', () => {
  assert.equal(confidenceLabelFor('calibrated', 0.87), 'Confidence 87%');
  assert.equal(confidenceLabelFor('calibrated', 1), 'Confidence 100%');
  assert.equal(confidenceLabelFor('calibrated', 0), 'Confidence 0%');
});

check('uncalibrated status uses the "Match evidence X%" wording', () => {
  assert.equal(confidenceLabelFor('uncalibrated', 0.87), 'Match evidence 87%');
  assert.equal(confidenceLabelFor('uncalibrated', 0.5), 'Match evidence 50%');
});

check('label matches the existing helper exactly (no new wording)', () => {
  for (const status of ['calibrated', 'uncalibrated'] as const) {
    for (const score of [0, 0.1234, 0.5, 0.856, 1, null, undefined, Number.NaN]) {
      assert.equal(
        confidenceLabelFor(status, score),
        confidenceLabel(score, status === 'calibrated'),
        `${status}/${String(score)}`
      );
    }
  }
});

check('label clamps / rounds the score and never throws on hostile input', () => {
  assert.equal(confidenceLabelFor('calibrated', 2), 'Confidence 100%');
  assert.equal(confidenceLabelFor('calibrated', -1), 'Confidence 0%');
  assert.doesNotThrow(() => confidenceLabelFor('calibrated', null));
  assert.equal(confidenceLabelFor('uncalibrated', null), 'Match evidence 0%');
});

check('label tracks the record produced by the engine end-to-end', () => {
  const calibrated = buildCalibrationEvidence({ ...STRONG_EVIDENCE, ...PASSING_GATE });
  const uncalibrated = buildCalibrationEvidence({ ...STRONG_EVIDENCE, labeledPairs: 199, ece: 0 });
  assert.equal(confidenceLabelFor(calibrated.calibration_status, calibrated.evidence_score), 'Confidence 100%');
  assert.equal(
    confidenceLabelFor(uncalibrated.calibration_status, uncalibrated.evidence_score),
    'Match evidence 100%'
  );
});

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}

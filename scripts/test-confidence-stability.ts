/**
 * Confidence-stability regression suite.
 *
 * Pins the single source of truth for "a returning pair freezes its confidence":
 *   - the (visitorId, hardwareId) pair alone determines the stability key;
 *   - the published score/tier are a pure function of that pair + rawScore;
 *   - volatile channels (bot/audio/privacy/network) never enter the result, so
 *     drift in them cannot move score, tier, key, changed or reason;
 *   - no stable pair -> null score;
 *   - the helper owns NO calibration gate and never claims 'calibrated'.
 *
 *   npx tsx scripts/test-confidence-stability.ts
 */
import assert from 'node:assert/strict';

import {
  CALIBRATION_GATE_OWNER,
  NO_PAIR_STABILITY_KEY,
  STABILITY_QUANTUM,
  stabilizeConfidence,
  type StabilizedConfidence,
} from '../src/lib/confidenceStability';
import {
  CALIBRATION_MAX_ECE,
  CALIBRATION_MIN_LABELED_PAIRS,
  calibrationStatusFor,
  confidenceBandForScore,
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

const PAIR = { visitorId: 'visitor-abc', hardwareId: 'hw-123', rawScore: 0.87 } as const;
const NULL_SCORE_TIERS = new Set(['New/Unobserved']);

/* -------------------------------------------------------------------------- */
/* 1. Result shape + determinism                                               */
/* -------------------------------------------------------------------------- */

section('1. Result shape and determinism');

check('result has exactly the five documented fields (no calibration_status)', () => {
  const result = stabilizeConfidence(PAIR);
  assert.deepEqual(Object.keys(result).sort(), ['changed', 'reason', 'score', 'stabilityKey', 'tier']);
  for (const key of Object.keys(result)) {
    assert.ok(!key.toLowerCase().includes('calibration'), `unexpected calibration field: ${key}`);
  }
});

check('identical input yields deeply identical output (pure)', () => {
  assert.deepEqual(stabilizeConfidence(PAIR), stabilizeConfidence(PAIR));
});

check('calling repeatedly does not accumulate state', () => {
  stabilizeConfidence(PAIR);
  stabilizeConfidence({ ...PAIR, rawScore: 0.12 });
  assert.deepEqual(stabilizeConfidence(PAIR), stabilizeConfidence(PAIR));
});

check('does not mutate the caller input', () => {
  const input = { ...PAIR, volatileInputs: { bot: true } };
  const snapshot = JSON.parse(JSON.stringify(input));
  stabilizeConfidence(input);
  assert.deepEqual(input, snapshot);
});

/* -------------------------------------------------------------------------- */
/* 2. Stable pair -> stable key, score and tier                                */
/* -------------------------------------------------------------------------- */

section('2. Stable pair drives key, score and tier');

check('stabilityKey has the locked stab:<16 hex> shape', () => {
  const { stabilityKey } = stabilizeConfidence(PAIR);
  assert.match(stabilityKey, /^stab:[0-9a-f]{16}$/);
});

check('stabilityKey depends ONLY on the pair (rawScore changes do not move it)', () => {
  const a = stabilizeConfidence({ ...PAIR, rawScore: 0.12 });
  const b = stabilizeConfidence({ ...PAIR, rawScore: 0.99 });
  assert.equal(a.stabilityKey, b.stabilityKey);
});

check('different pairs produce different stabilityKeys', () => {
  const a = stabilizeConfidence(PAIR);
  const b = stabilizeConfidence({ ...PAIR, hardwareId: 'hw-999' });
  const c = stabilizeConfidence({ ...PAIR, visitorId: 'visitor-xyz' });
  assert.notEqual(a.stabilityKey, b.stabilityKey);
  assert.notEqual(a.stabilityKey, c.stabilityKey);
});

check('id normalization is stable (case / whitespace / surrounding space)', () => {
  const base = stabilizeConfidence({ visitorId: 'Visitor ABC', hardwareId: 'HW-123', rawScore: 0.87 });
  const noisy = stabilizeConfidence({ visitorId: '  visitor   abc ', hardwareId: ' hw-123 ', rawScore: 0.87 });
  assert.equal(base.stabilityKey, noisy.stabilityKey);
  assert.equal(base.score, noisy.score);
  assert.equal(base.tier, noisy.tier);
});

check('score is quantized to the stability quantum', () => {
  const result = stabilizeConfidence({ ...PAIR, rawScore: 0.87 });
  assert.equal(STABILITY_QUANTUM, 0.05);
  const rawQuantized = Math.round(0.87 / STABILITY_QUANTUM) * STABILITY_QUANTUM;
  assert.equal(result.score, Math.round(rawQuantized * 10000) / 10000);
  assert.ok((result.score as number) >= 0 && (result.score as number) <= 1);
});

check('score never carries more than 4 decimals', () => {
  for (const rawScore of [0.123456789, 0.91337, 0.7777777, 0.5]) {
    const { score } = stabilizeConfidence({ ...PAIR, rawScore });
    assert.ok(score !== null);
    assert.ok(Number.isFinite(score));
    assert.equal(score as number, Math.round((score as number) * 10000) / 10000);
  }
});

check('rawScore is clamped to [0,1] before publishing', () => {
  assert.equal(stabilizeConfidence({ ...PAIR, rawScore: 5 }).score, 1);
  assert.equal(stabilizeConfidence({ ...PAIR, rawScore: -3 }).score, 0);
});

check('changed reflects whether quantization adjusted the raw score', () => {
  const quantized = stabilizeConfidence({ ...PAIR, rawScore: 0.87 });
  const exact = stabilizeConfidence({ ...PAIR, rawScore: 0.85 });
  assert.equal(quantized.changed, true, '0.87 should quantize to 0.85');
  assert.equal(quantized.score, 0.85);
  assert.equal(exact.changed, false, '0.85 is already on the quantum');
  assert.equal(exact.score, 0.85);
});

check('tier is the locked display band for the stable score', () => {
  for (const rawScore of [0.95, 0.7, 0.5, 0.2, 0]) {
    const result = stabilizeConfidence({ ...PAIR, rawScore });
    assert.equal(result.tier, confidenceBandForScore(result.score as number), `rawScore=${rawScore}`);
  }
});

check('tier boundaries match the canonical band mapping exactly', () => {
  assert.equal(stabilizeConfidence({ ...PAIR, rawScore: 0.85 }).score, 0.85);
  assert.equal(stabilizeConfidence({ ...PAIR, rawScore: 0.85 }).tier, 'High');
  assert.equal(stabilizeConfidence({ ...PAIR, rawScore: 0.65 }).tier, 'Medium-High');
  assert.equal(stabilizeConfidence({ ...PAIR, rawScore: 0.4 }).tier, 'Medium');
  assert.equal(stabilizeConfidence({ ...PAIR, rawScore: 0.2 }).tier, 'Low');
});

/* -------------------------------------------------------------------------- */
/* 3. Volatile-input drift cannot move the result                              */
/* -------------------------------------------------------------------------- */

section('3. Volatile channels (bot/audio/privacy/network) are inert');

check('drifting volatile values leave score/tier/key/changed/reason untouched', () => {
  const baseline = stabilizeConfidence({ ...PAIR, volatileInputs: {} });
  const drifted = stabilizeConfidence({
    ...PAIR,
    volatileInputs: {
      bot: true,
      audio: { sum: 12345.678, noise: 'farbling' },
      privacy: { hardened: true, vpn: true },
      network: { asn: 'AS999', rtt: 999 },
    },
  });
  assert.deepEqual(drifted, baseline);
});

check('hostile volatile inputs are never read and never throw', () => {
  const hostileVolatile = {
    get bot(): unknown {
      throw new Error('bot getter exploded');
    },
    get audio(): unknown {
      throw new Error('audio getter exploded');
    },
    get privacy(): unknown {
      throw new Error('privacy getter exploded');
    },
    get network(): unknown {
      throw new Error('network getter exploded');
    },
  };
  const baseline = stabilizeConfidence(PAIR);
  let result: StabilizedConfidence | undefined;
  assert.doesNotThrow(() => {
    result = stabilizeConfidence({ ...PAIR, volatileInputs: hostileVolatile });
  });
  assert.deepEqual(result, baseline);
});

check('hostile volatile container types (null/primitives) are ignored', () => {
  const baseline = stabilizeConfidence(PAIR);
  for (const volatileInputs of [null, 42, 'noise', [], () => undefined, true] as never[]) {
    assert.deepEqual(stabilizeConfidence({ ...PAIR, volatileInputs }), baseline);
  }
});

check('small rawScore drift inside one quantum does not move the score', () => {
  const a = stabilizeConfidence({ ...PAIR, rawScore: 0.871 });
  const b = stabilizeConfidence({ ...PAIR, rawScore: 0.874 });
  assert.equal(a.score, b.score);
  assert.equal(a.tier, b.tier);
  assert.equal(a.stabilityKey, b.stabilityKey);
});

check('rawScore drift across a quantum is quantized deterministically', () => {
  const a = stabilizeConfidence({ ...PAIR, rawScore: 0.871 });
  const b = stabilizeConfidence({ ...PAIR, rawScore: 0.89 });
  assert.equal(a.score, 0.85);
  assert.equal(b.score, 0.9);
  assert.equal(a.stabilityKey, b.stabilityKey, 'the pair key must never drift');
});

/* -------------------------------------------------------------------------- */
/* 4. Null when no stable pair                                                 */
/* -------------------------------------------------------------------------- */

section('4. No stable pair -> null score');

check('missing visitorId yields a null score and the no-pair key', () => {
  const result = stabilizeConfidence({ hardwareId: 'hw-123', rawScore: 0.9 });
  assert.equal(result.score, null);
  assert.equal(result.stabilityKey, NO_PAIR_STABILITY_KEY);
  assert.equal(result.reason, 'no_visitor_id');
  assert.ok(NULL_SCORE_TIERS.has(result.tier));
  assert.equal(result.changed, false);
});

check('missing hardwareId yields a null score and the no-pair key', () => {
  const result = stabilizeConfidence({ visitorId: 'visitor-abc', rawScore: 0.9 });
  assert.equal(result.score, null);
  assert.equal(result.stabilityKey, NO_PAIR_STABILITY_KEY);
  assert.equal(result.reason, 'no_hardware_id');
});

check('both ids missing (or empty/whitespace) yields no_stable_pair', () => {
  for (const input of [
    { rawScore: 0.9 },
    { visitorId: '', hardwareId: '', rawScore: 0.9 },
    { visitorId: '   ', hardwareId: '\t', rawScore: 0.9 },
  ]) {
    const result = stabilizeConfidence(input);
    assert.equal(result.score, null, JSON.stringify(input));
    assert.equal(result.stabilityKey, NO_PAIR_STABILITY_KEY);
    assert.equal(result.reason, 'no_stable_pair');
  }
});

check('stable pair with a non-finite rawScore stays null but keeps its key', () => {
  for (const rawScore of [Number.NaN, Infinity, -Infinity, '0.9', {}, []] as never[]) {
    const result = stabilizeConfidence({ ...PAIR, rawScore });
    assert.equal(result.score, null, String(rawScore));
    assert.equal(result.reason, 'no_finite_raw_score');
    assert.notEqual(result.stabilityKey, NO_PAIR_STABILITY_KEY);
    assert.ok(NULL_SCORE_TIERS.has(result.tier));
  }
});

/* -------------------------------------------------------------------------- */
/* 5. Hostile top-level input — never throws, always fails closed              */
/* -------------------------------------------------------------------------- */

section('5. Hostile input fails closed without throwing');

check('null/undefined/primitive/array/function inputs never throw', () => {
  for (const hostile of [null, undefined, 42, 'pair', true, [], () => undefined] as never[]) {
    let result: StabilizedConfidence | undefined;
    assert.doesNotThrow(() => {
      result = stabilizeConfidence(hostile);
    }, `threw for ${String(hostile)}`);
    assert.equal(result?.score, null);
    assert.equal(result?.stabilityKey, NO_PAIR_STABILITY_KEY);
  }
});

check('throwing getters on the input object are contained', () => {
  const hostile = {
    get visitorId(): unknown {
      throw new Error('visitor getter exploded');
    },
    get hardwareId(): unknown {
      throw new Error('hardware getter exploded');
    },
    get rawScore(): unknown {
      throw new Error('score getter exploded');
    },
  };
  let result: StabilizedConfidence | undefined;
  assert.doesNotThrow(() => {
    result = stabilizeConfidence(hostile as never);
  });
  assert.equal(result?.score, null);
  assert.equal(result?.stabilityKey, NO_PAIR_STABILITY_KEY);
  assert.equal(result?.reason, 'no_stable_pair');
});

check('wrong-type stable ids are rejected, not coerced', () => {
  for (const visitorId of [123, {}, [], true] as never[]) {
    const result = stabilizeConfidence({ visitorId, hardwareId: 'hw-123', rawScore: 0.9 });
    assert.equal(result.score, null, String(visitorId));
    assert.equal(result.stabilityKey, NO_PAIR_STABILITY_KEY);
  }
});

check('reason tokens are stable, lowercase and carry no ids or volatile values', () => {
  const result = stabilizeConfidence(PAIR);
  assert.match(result.reason, /^[a-z0-9_]+$/);
  assert.ok(!result.reason.includes('visitor'));
  assert.ok(!result.reason.includes('bot'));
  assert.ok(!result.reason.includes('network'));
});

/* -------------------------------------------------------------------------- */
/* 6. Calibration gate is untouched                                            */
/* -------------------------------------------------------------------------- */

section('6. Calibration status is never claimed here');

check('result never contains the string "calibrated"', () => {
  const samples = [
    stabilizeConfidence(PAIR),
    stabilizeConfidence({ ...PAIR, rawScore: 1 }),
    stabilizeConfidence({}),
    stabilizeConfidence(null),
  ];
  for (const sample of samples) {
    assert.ok(!JSON.stringify(sample).includes('calibrated'), JSON.stringify(sample));
  }
});

check('CALIBRATION_GATE_OWNER names the existing rarityHonesty gate', () => {
  assert.equal(CALIBRATION_GATE_OWNER, 'rarityHonesty.calibrationStatusFor');
});

check('the real gate is still the sole calibration authority and still dormant by default', () => {
  assert.equal(CALIBRATION_MIN_LABELED_PAIRS, 200);
  assert.equal(CALIBRATION_MAX_ECE, 0.05);
  assert.equal(
    calibrationStatusFor({ labeledPairs: CALIBRATION_MIN_LABELED_PAIRS, heldOutEce: CALIBRATION_MAX_ECE }),
    'calibrated'
  );
  // A high, stable confidence from this helper can never pass the gate on its own.
  assert.equal(calibrationStatusFor({ labeledPairs: 0, heldOutEce: 0 }), 'uncalibrated');
  assert.equal(stabilizeConfidence({ ...PAIR, rawScore: 1 }).score, 1);
  assert.ok(!JSON.stringify(stabilizeConfidence({ ...PAIR, rawScore: 1 })).includes('calibration'));
});

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}

/**
 * Calibration corpus regression suite — SHADOW-OFFLINE.
 *
 *   npx tsx scripts/test-calibration-corpus.ts
 *
 * Drives the four frozen RS1 scenarios in scripts/fixtures/calibration-corpus.json against
 * the pure `buildCalibrationCorpus` helper. No live requests, no browser, no deploy, no writes,
 * no timers, no randomness: the only I/O is reading the frozen fixture. Each case reports
 * PASS / FAIL; the final RESULT line summarizes checks/assertions and any FAIL makes the
 * process exit non-zero. Expectations are golden — never edit them to make a failing suite
 * green; fix the implementation instead.
 */

import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

import {
  CALIBRATION_BIN_COUNT,
  INDEPENDENT_LABEL_SOURCES,
  buildCalibrationCorpus,
  type CalibrationBin,
  type CalibrationCorpusResult,
  type CalibrationRecord,
} from '../src/lib/calibrationCorpus';
import {
  CALIBRATION_MAX_ECE,
  CALIBRATION_MIN_LABELED_PAIRS,
  isCalibrationEligible,
} from '../src/lib/rarityHonesty';

/* -------------------------------------------------------------------------- */
/* Fixture types                                                               */
/* -------------------------------------------------------------------------- */

interface Expected {
  eligible: boolean;
  labeledPairs: number;
  ece?: number;
  eceLte?: number;
  brier?: number;
  binsCount: number;
  /** null = do not pin individual bin counts. */
  binCounts: number[] | null;
  reasonIncludes: string[];
  warningsInclude: string[];
  warningsExclude?: string[];
}

interface CaseDefinition {
  id: string;
  name: string;
  scenario: string;
  records: CalibrationRecord[];
  expected: Expected;
}

interface Fixture {
  schema_version: number;
  title: string;
  generated_on: string;
  frozen: boolean;
  offline: boolean;
  gate: { min_labeled_pairs: number; max_ece: number };
  cases: CaseDefinition[];
}

/* -------------------------------------------------------------------------- */
/* Reporting                                                                   */
/* -------------------------------------------------------------------------- */

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

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

async function loadFixture(): Promise<Fixture> {
  const url = new URL('./fixtures/calibration-corpus.json', import.meta.url);
  const parsed = JSON.parse(await readFile(url, 'utf8')) as Fixture;
  if (!parsed || !Array.isArray(parsed.cases)) {
    throw new Error('fixture is malformed: cases must be an array');
  }
  return deepFreeze(parsed);
}

/* Independent recomputation of the binary ECE/Brier for cross-checking the implementation. */
function recompute(records: CalibrationRecord[]): { ece: number; brier: number } {
  const n = records.length;
  if (n === 0) return { ece: 0, brier: 0 };
  const sums = Array.from({ length: CALIBRATION_BIN_COUNT }, () => ({ count: 0, score: 0, label: 0 }));
  let brier = 0;
  for (const record of records) {
    const score = Number(record.frozenScore);
    const label = record.label === true || record.label === 1 ? 1 : 0;
    const idx = Math.max(0, Math.min(CALIBRATION_BIN_COUNT - 1, Math.floor(score * CALIBRATION_BIN_COUNT)));
    sums[idx].count += 1;
    sums[idx].score += score;
    sums[idx].label += label;
    brier += (score - label) ** 2;
  }
  let ece = 0;
  for (const bin of sums) {
    if (bin.count === 0) continue;
    ece += (bin.count / n) * Math.abs(bin.label / bin.count - bin.score / bin.count);
  }
  return { ece: Math.round(ece * 10000) / 10000, brier: Math.round((brier / n) * 10000) / 10000 };
}

/* -------------------------------------------------------------------------- */

async function run(): Promise<void> {
  const fixture = await loadFixture();

  section('0. Fixture + locked gate constants');

  check('fixture is frozen and offline', () => {
    assert.equal(fixture.frozen, true);
    assert.equal(fixture.offline, true);
  });
  check('fixture schema_version is 1', () => assert.equal(fixture.schema_version, 1));
  check('fixture has exactly four frozen cases', () => assert.equal(fixture.cases.length, 4));
  check('case ids match the four RS1 scenarios', () => {
    assert.deepEqual(
      [...fixture.cases.map((c) => c.id)].sort(),
      ['ece-fail', 'eligible', 'insufficient', 'leakage-rejected']
    );
    assert.deepEqual(
      [...fixture.cases.map((c) => c.scenario)].sort(),
      ['ece_fail', 'eligible', 'insufficient_pairs', 'leakage_attempt_rejected']
    );
  });
  check('fixture gate metadata matches the imported locked constants', () => {
    assert.equal(fixture.gate.min_labeled_pairs, CALIBRATION_MIN_LABELED_PAIRS);
    assert.equal(fixture.gate.max_ece, CALIBRATION_MAX_ECE);
    assert.equal(CALIBRATION_MIN_LABELED_PAIRS, 200);
    assert.equal(CALIBRATION_MAX_ECE, 0.05);
  });
  check('bin count is the locked value 10', () => assert.equal(CALIBRATION_BIN_COUNT, 10));
  check('label-source allowlist contains only independent first-party/authenticated sources', () => {
    assert.equal(INDEPENDENT_LABEL_SOURCES['model_confidence'], undefined);
    assert.equal(INDEPENDENT_LABEL_SOURCES['our_score'], undefined);
    assert.equal(INDEPENDENT_LABEL_SOURCES['first_party_cookie'], 'observed');
    assert.equal(INDEPENDENT_LABEL_SOURCES['oauth_subject'], 'strong');
    assert.equal(INDEPENDENT_LABEL_SOURCES['crm_id'], 'strong');
  });
  check('gate helper itself still guards both conditions', () => {
    assert.equal(isCalibrationEligible({ labeledPairs: 200, heldOutEce: 0.05 }), true);
    assert.equal(isCalibrationEligible({ labeledPairs: 199, heldOutEce: 0 }), false);
    assert.equal(isCalibrationEligible({ labeledPairs: 200, heldOutEce: 0.051 }), false);
  });

  const results = new Map<string, CalibrationCorpusResult>();
  for (const testCase of fixture.cases) {
    results.set(testCase.id, buildCalibrationCorpus(testCase.records));
  }

  section('1. Per-case golden outcomes');

  for (const testCase of fixture.cases) {
    const exp = testCase.expected;
    const result = results.get(testCase.id)!;
    section(`CASE ${testCase.id} | ${testCase.name} (${testCase.scenario})`);

    check(`[${testCase.id}] eligible is ${exp.eligible}`, () => {
      assert.equal(result.eligible, exp.eligible);
    });
    check(`[${testCase.id}] labeledPairs is ${exp.labeledPairs}`, () => {
      assert.equal(result.labeledPairs, exp.labeledPairs);
    });
    check(`[${testCase.id}] ECE matches golden value`, () => {
      if (exp.ece !== undefined) assert.equal(result.ece, exp.ece);
      if (exp.eceLte !== undefined) assert.ok(result.ece <= exp.eceLte, `ece=${result.ece}`);
      assert.ok(result.ece >= 0 && result.ece <= 1, `ece=${result.ece}`);
    });
    if (exp.brier !== undefined) {
      check(`[${testCase.id}] Brier matches golden value ${exp.brier}`, () => {
        assert.equal(result.brier, exp.brier);
      });
    }
    check(`[${testCase.id}] publishes exactly ${exp.binsCount} bins`, () => {
      assert.equal(result.bins.length, exp.binsCount);
    });
    if (exp.binCounts !== null) {
      check(`[${testCase.id}] per-bin counts match golden distribution`, () => {
        assert.deepEqual(result.bins.map((b) => b.count), exp.binCounts);
      });
    }
    check(`[${testCase.id}] bin counts sum to labeledPairs`, () => {
      assert.equal(result.bins.reduce((sum, b) => sum + b.count, 0), result.labeledPairs);
    });
    check(`[${testCase.id}] bin ranges are 10 well-formed equal-width intervals`, () => {
      assert.deepEqual(
        result.bins.map((b) => b.range),
        [
          '[0.0,0.1)', '[0.1,0.2)', '[0.2,0.3)', '[0.3,0.4)', '[0.4,0.5)',
          '[0.5,0.6)', '[0.6,0.7)', '[0.7,0.8)', '[0.8,0.9)', '[0.9,1.0]',
        ]
      );
    });
    check(`[${testCase.id}] empty bins are zeroed; non-empty bins have conf/acc in [0,1]`, () => {
      for (const bin of result.bins) {
        if (bin.count === 0) {
          assert.equal(bin.confidence, 0);
          assert.equal(bin.accuracy, 0);
        } else {
          assert.ok(bin.confidence >= 0 && bin.confidence <= 1, bin.range);
          assert.ok(bin.accuracy >= 0 && bin.accuracy <= 1, bin.range);
          assert.ok(bin.confidence <= 1 && bin.accuracy <= 1, bin.range);
        }
        assert.ok(Number.isInteger(bin.count) && bin.count >= 0, bin.range);
      }
    });
    check(`[${testCase.id}] confidence/accuracy are rounded to at most 4 decimals`, () => {
      for (const bin of result.bins) {
        assert.equal(bin.confidence, Math.round(bin.confidence * 10000) / 10000, bin.range);
        assert.equal(bin.accuracy, Math.round(bin.accuracy * 10000) / 10000, bin.range);
      }
    });
    check(`[${testCase.id}] reason contains every expected substring`, () => {
      for (const needle of exp.reasonIncludes) {
        assert.ok(result.reason.includes(needle), `reason=${result.reason} missing ${needle}`);
      }
    });
    check(`[${testCase.id}] warnings contain every expected substring`, () => {
      for (const needle of exp.warningsInclude) {
        assert.ok(
          result.warnings.some((w) => w.includes(needle)),
          `warnings missing ${needle}: ${JSON.stringify(result.warnings)}`
        );
      }
    });
    check(`[${testCase.id}] warnings exclude forbidden substrings`, () => {
      for (const needle of exp.warningsExclude ?? []) {
        assert.ok(
          !result.warnings.some((w) => w.includes(needle)),
          `warnings unexpectedly include ${needle}: ${JSON.stringify(result.warnings)}`
        );
      }
    });
    check(`[${testCase.id}] result has NO calibration_status field`, () => {
      assert.equal(Object.prototype.hasOwnProperty.call(result, 'calibration_status'), false);
    });
    check(`[${testCase.id}] builder is pure/deterministic (identical input -> identical result)`, () => {
      assert.deepEqual(buildCalibrationCorpus(testCase.records), result);
    });
    check(`[${testCase.id}] builder does not mutate the frozen input`, () => {
      const before = JSON.stringify(testCase.records);
      buildCalibrationCorpus(testCase.records);
      assert.equal(JSON.stringify(testCase.records), before);
    });
  }

  section('2. ECE / Brier formula cross-check (independent recomputation)');

  for (const testCase of fixture.cases.filter((c) => c.scenario !== 'leakage_attempt_rejected')) {
    check(`[${testCase.id}] ECE/Brier recomputed from records match the result`, () => {
      const expectedValues = recompute(testCase.records as CalibrationRecord[]);
      const actual = results.get(testCase.id)!;
      assert.equal(actual.ece, expectedValues.ece, `ece ${actual.ece} != ${expectedValues.ece}`);
      assert.equal(actual.brier, expectedValues.brier, `brier ${actual.brier} != ${expectedValues.brier}`);
    });
  }

  check('ECE is the weighted sum of per-bin |accuracy - confidence|', () => {
    const bins = results.get('ece-fail')!.bins;
    const n = bins.reduce((sum, b) => sum + b.count, 0);
    const manual = bins.reduce((sum, b) => sum + (b.count / n) * Math.abs(b.accuracy - b.confidence), 0);
    assert.equal(results.get('ece-fail')!.ece, Math.round(manual * 10000) / 10000);
  });
  check('empty bins always contribute zero (leakage case has all-empty bins and ECE=0)', () => {
    const leaked = results.get('leakage-rejected')!;
    assert.ok(leaked.bins.every((b: CalibrationBin) => b.count === 0));
    assert.equal(leaked.ece, 0);
    assert.equal(leaked.brier, 0);
  });

  section('3. Leakage, contradiction and sample-size policy invariants');

  check('leakage case rejects every vector and reports each in the reason', () => {
    const leaked = results.get('leakage-rejected')!;
    assert.equal(leaked.eligible, false);
    assert.equal(leaked.labeledPairs, 0);
    for (const fragment of ['bot', 'quarantined', 'non-independent label source', 'temporal leak', 'id contradiction', 'cross-partition browser']) {
      assert.ok(leaked.reason.includes(fragment), `reason missing ${fragment}: ${leaked.reason}`);
    }
  });
  check('self-confidence label source is explicitly rejected as non-independent', () => {
    const leaked = results.get('leakage-rejected')!;
    assert.ok(leaked.warnings.some((w) => w.includes("label source 'model_confidence' is not an independent evidence source")));
  });
  check('a contradiction excludes the whole browser group (both conflicting records)', () => {
    const leaked = results.get('leakage-rejected')!;
    assert.ok(leaked.warnings.some((w) => w.includes('CONTRADICTION [v-leak-contrad]')));
    assert.ok(!leaked.warnings.some((w) => w.includes('[leak-contradict-a]')));
  });
  check('sample-size warnings are descriptive only — the locked gate is never relaxed', () => {
    const eligible = results.get('eligible')!;
    const insufficient = results.get('insufficient')!;
    assert.equal(eligible.eligible, true);
    assert.equal(insufficient.eligible, false);
    assert.ok(eligible.warnings.some((w) => w.includes('5,000-10,000')));
    assert.ok(eligible.warnings.some((w) => w.includes('is unchanged')));
    assert.ok(eligible.labeledPairs >= CALIBRATION_MIN_LABELED_PAIRS);
    assert.ok(eligible.ece <= CALIBRATION_MAX_ECE);
    assert.ok(insufficient.labeledPairs < CALIBRATION_MIN_LABELED_PAIRS);
  });
  check('low ECE does not imply accuracy: eligible case has ECE 0 but Brier 0.1675', () => {
    const eligible = results.get('eligible')!;
    assert.equal(eligible.ece, 0);
    assert.equal(eligible.brier, 0.1675);
    assert.ok(eligible.warnings.some((w) => w.includes('does not imply accuracy')));
  });
  check('ECE-fail case has enough pairs but ECE above the ceiling', () => {
    const failed = results.get('ece-fail')!;
    assert.equal(failed.labeledPairs, CALIBRATION_MIN_LABELED_PAIRS);
    assert.ok(failed.ece > CALIBRATION_MAX_ECE);
    assert.equal(failed.eligible, false);
  });
  check('eligible corpus uses both observed and strong label bands', () => {
    assert.ok(results.get('eligible')!.warnings.some((w) => w.includes('observed-band=100, strong-band=100')));
  });

  section('4. Hostile input fails closed without throwing');

  const hostile: unknown[] = [null, undefined, 42, 'corpus', true, {}, () => undefined, [null, 7, 'x']];
  check('hostile inputs never throw and always return a closed, well-formed result', () => {
    for (const value of hostile) {
      let result: CalibrationCorpusResult | undefined;
      assert.doesNotThrow(() => { result = buildCalibrationCorpus(value); });
      assert.equal(result?.eligible, false);
      assert.equal(result?.labeledPairs, 0);
      assert.equal(result?.bins.length, CALIBRATION_BIN_COUNT);
      assert.ok((result?.warnings.length ?? 0) > 0);
    }
  });
  check('hostile inputs still report sample-size and interpretation warnings', () => {
    const result = buildCalibrationCorpus(null);
    assert.ok(result.warnings.some((w) => w.includes('SAMPLE SIZE <500')));
    assert.ok(result.warnings.some((w) => w.includes('INTERPRETATION')));
  });
}

/* -------------------------------------------------------------------------- */

run()
  .then(() => {
    console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
    if (failures.length > 0) {
      console.error(`FAILED: ${failures.join(' | ')}`);
      process.exitCode = 1;
    } else {
      console.log('RESULT: PASS — all four calibration-corpus scenarios green');
    }
  })
  .catch((error: unknown) => {
    console.error(`FAIL  [fatal] ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  });

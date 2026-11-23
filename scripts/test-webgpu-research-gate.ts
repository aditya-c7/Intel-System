/**
 * Regression suite for src/lib/webgpuResearchGate.ts (RS3 research gate).
 *
 * Pins:
 *  - ALL GO criteria must pass before `deployable` is true; `researchOnly` defaults to true and
 *    is lifted only by a complete pass;
 *  - pre-registered inclusive thresholds (95%, 30 days, 2 updates, 10k pool, 200ms) and the
 *    literal-true boolean gates;
 *  - hostile input (null, primitives, arrays, functions, proxies, throwing getters, NaN,
 *    Infinity, wrong types) fails closed without throwing and never mutates the caller input;
 *  - `researchDisclosure()` returns the standard WEBGPU_RESEARCH_ONLY_NOTE literal;
 *  - the gate contains NO WebGPU fingerprint probe;
 *  - the frozen fixture's hypothetical pass and three real-world NO-GO cases pin the contract.
 *
 *   npx tsx scripts/test-webgpu-research-gate.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure. The run is
 * wrapped so no assertion/import error escapes uncaught.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  evaluateWebgpuResearch,
  researchDisclosure,
  THIRTY_DAYS_MS,
  WEBGPU_RESEARCH_DISCLOSURE,
  WEBGPU_RESEARCH_REASON,
  WEBGPU_RESEARCH_THRESHOLDS,
  type WebgpuResearchInput,
  type WebgpuResearchResult,
} from '../src/lib/webgpuResearchGate';
import { WEBGPU_RESEARCH_ONLY_NOTE } from '../src/lib/identityTiers';

/* -------------------------------------------------------------------------- */
/* Reporting                                                                   */
/* -------------------------------------------------------------------------- */

let passed = 0;
let failed = 0;

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function check(id: string, label: string, body: () => void): void {
  try {
    body();
    passed += 1;
    console.log(`PASS  [${id}] ${label}`);
  } catch (error) {
    failed += 1;
    console.error(`FAIL  [${id}] ${label}\n      ${describeError(error)}`);
  }
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

function baseInput(): WebgpuResearchInput {
  return {
    exactStability30d: 0.98,
    minPerDeviceStabilityMs: THIRTY_DAYS_MS,
    candidatePool: 10_000,
    captureMs: 200,
    timerFree: true,
    consentDocumented: true,
    browserUpdatesCovered: 2,
  };
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

function hasReason(result: WebgpuResearchResult, token: string): boolean {
  return result.reasons.some((reason) => reason === token || reason.startsWith(`${token} (`));
}

/* -------------------------------------------------------------------------- */
/* Fixture contracts                                                          */
/* -------------------------------------------------------------------------- */

interface FixtureCase {
  id: string;
  name: string;
  input: WebgpuResearchInput;
  expected: {
    deployable: boolean;
    researchOnly: boolean;
    failingCriteria: string[];
  };
}

interface Fixture {
  schema_version: number;
  frozen: boolean;
  offline: boolean;
  generated_on: string;
  note: string;
  description: string;
  researchFindings: Array<{ source: string; observed: string; gateImpact: string }>;
  cases: FixtureCase[];
}

function loadFixture(): Fixture {
  const url = new URL('./fixtures/webgpu-research.json', import.meta.url);
  const parsed = JSON.parse(readFileSync(url, 'utf8')) as Fixture;
  if (!parsed || !Array.isArray(parsed.cases)) {
    throw new Error('fixture is malformed: cases must be an array');
  }
  return deepFreeze(parsed);
}

/* -------------------------------------------------------------------------- */

function run(): void {
  check('setup', 'evaluateWebgpuResearch and researchDisclosure are exported functions', () => {
    assert.equal(typeof evaluateWebgpuResearch, 'function');
    assert.equal(typeof researchDisclosure, 'function');
  });

  section('A. Result shape, happy path and transparency');

  check('A1', 'result has exactly three documented fields', () => {
    const result = evaluateWebgpuResearch(baseInput());
    assert.deepEqual(Object.keys(result).sort(), ['deployable', 'reasons', 'researchOnly']);
  });

  check('A2', 'a complete evidence pass is deployable and leaves research-only mode', () => {
    const result = evaluateWebgpuResearch(baseInput());
    assert.equal(result.deployable, true);
    assert.equal(result.researchOnly, false);
    assert.deepEqual(result.reasons, [WEBGPU_RESEARCH_REASON.allPassed]);
  });

  check('A3', 'deterministic and non-mutating, including on frozen input', () => {
    const input = deepFreeze(baseInput());
    const before = JSON.stringify(input);
    const first = evaluateWebgpuResearch(input);
    const second = evaluateWebgpuResearch(input);
    assert.deepEqual(first, second);
    assert.equal(JSON.stringify(input), before);
  });

  check('A4', 'thresholds are inclusive: 95%, 30 days, 2 updates, 10k devices, 200ms', () => {
    const result = evaluateWebgpuResearch(baseInput());
    assert.equal(result.deployable, true);
    assert.equal(WEBGPU_RESEARCH_THRESHOLDS.minExactStability, 0.95);
    assert.equal(WEBGPU_RESEARCH_THRESHOLDS.minObservationMs, 2_592_000_000);
    assert.equal(WEBGPU_RESEARCH_THRESHOLDS.minBrowserUpdates, 2);
    assert.equal(WEBGPU_RESEARCH_THRESHOLDS.minCandidatePool, 10_000);
    assert.equal(WEBGPU_RESEARCH_THRESHOLDS.maxCaptureMs, 200);
  });

  check('A5', 'researchDisclosure returns the standard WEBGPU_RESEARCH_ONLY_NOTE literal', () => {
    assert.equal(researchDisclosure(), WEBGPU_RESEARCH_ONLY_NOTE);
    assert.equal(researchDisclosure(), WEBGPU_RESEARCH_DISCLOSURE);
    assert.equal(typeof researchDisclosure(), 'string');
    assert.ok(researchDisclosure().length > 0);
    assert.ok(researchDisclosure().includes('RESEARCH_ONLY'));
    assert.equal(researchDisclosure(), researchDisclosure());
  });

  section('B. Each GO criterion independently blocks deployment');

  check('B1', 'exact stability below 95% fails closed', () => {
    const result = evaluateWebgpuResearch({ ...baseInput(), exactStability30d: 0.94 });
    assert.equal(result.deployable, false);
    assert.equal(result.researchOnly, true);
    assert.equal(result.reasons.length, 1);
    assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.exactStability));
  });

  check('B2', 'AtomicIncrement mean 0.63 and minima 0.00 both fail', () => {
    for (const exactStability30d of [0.63, 0]) {
      const result = evaluateWebgpuResearch({ ...baseInput(), exactStability30d });
      assert.equal(result.deployable, false);
      assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.exactStability));
    }
  });

  check('B3', 'WGPULens combined repeat stability 45/80 fails', () => {
    const result = evaluateWebgpuResearch({ ...baseInput(), exactStability30d: 45 / 80 });
    assert.equal(result.deployable, false);
    assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.exactStability));
  });

  check('B4', 'an exact-stability fraction above 1 is invalid, not a pass', () => {
    for (const exactStability30d of [1.01, 100]) {
      const result = evaluateWebgpuResearch({ ...baseInput(), exactStability30d });
      assert.equal(result.deployable, false);
      assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.exactStability));
    }
  });

  check('B5', 'observation window shorter than 30 days fails (21 days, 1ms short)', () => {
    for (const minPerDeviceStabilityMs of [21 * 24 * 60 * 60 * 1000, THIRTY_DAYS_MS - 1]) {
      const result = evaluateWebgpuResearch({ ...baseInput(), minPerDeviceStabilityMs });
      assert.equal(result.deployable, false);
      assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.observationWindow));
    }
  });

  check('B6', 'exactly 30 days passes the observation-window criterion', () => {
    const result = evaluateWebgpuResearch({
      ...baseInput(),
      minPerDeviceStabilityMs: THIRTY_DAYS_MS,
    });
    assert.equal(result.deployable, true);
  });

  check('B7', 'fewer than 2 browser updates fails', () => {
    for (const browserUpdatesCovered of [1, 0]) {
      const result = evaluateWebgpuResearch({ ...baseInput(), browserUpdatesCovered });
      assert.equal(result.deployable, false);
      assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.browserUpdates));
    }
  });

  check('B8', 'a fractional update count is not a valid coverage claim', () => {
    const result = evaluateWebgpuResearch({ ...baseInput(), browserUpdatesCovered: 2.5 });
    assert.equal(result.deployable, false);
    assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.browserUpdates));
  });

  check('B9', 'open-world pool below 10,000 fails (including 9,999)', () => {
    for (const candidatePool of [7, 10, 1095, 9999]) {
      const result = evaluateWebgpuResearch({ ...baseInput(), candidatePool });
      assert.equal(result.deployable, false);
      assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.candidatePool));
    }
  });

  check('B10', 'capture above 200ms fails (including 200.001ms)', () => {
    for (const captureMs of [201, 200.001, 1200]) {
      const result = evaluateWebgpuResearch({ ...baseInput(), captureMs });
      assert.equal(result.deployable, false);
      assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.capture));
    }
  });

  check('B11', 'a negative capture time is invalid, not a pass', () => {
    const result = evaluateWebgpuResearch({ ...baseInput(), captureMs: -1 });
    assert.equal(result.deployable, false);
    assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.capture));
  });

  check('B12', 'timer-based capture fails even when everything else passes', () => {
    const result = evaluateWebgpuResearch({ ...baseInput(), timerFree: false });
    assert.equal(result.deployable, false);
    assert.equal(result.reasons.length, 1);
    assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.timerFree));
  });

  check('B13', 'only literal true satisfies timerFree (truthy junk is rejected)', () => {
    for (const timerFree of ['true', 1, {}, [], null, undefined] as never[]) {
      const result = evaluateWebgpuResearch({ ...baseInput(), timerFree });
      assert.equal(result.deployable, false, String(timerFree));
      assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.timerFree));
    }
  });

  check('B14', 'only literal true satisfies consentDocumented', () => {
    for (const consentDocumented of ['true', 1, {}, [], false, null] as never[]) {
      const result = evaluateWebgpuResearch({ ...baseInput(), consentDocumented });
      assert.equal(result.deployable, false, String(consentDocumented));
      assert.ok(hasReason(result, WEBGPU_RESEARCH_REASON.consent));
    }
  });

  check('B15', 'a single failure keeps researchOnly true', () => {
    const result = evaluateWebgpuResearch({ ...baseInput(), consentDocumented: false });
    assert.equal(result.deployable, false);
    assert.equal(result.researchOnly, true);
  });

  section('C. Invalid and missing evidence fails closed');

  check('C1', 'NaN and infinities never satisfy numeric gates', () => {
    for (const poison of [Number.NaN, Infinity, -Infinity]) {
      const result = evaluateWebgpuResearch({
        exactStability30d: poison,
        minPerDeviceStabilityMs: poison,
        candidatePool: poison,
        captureMs: poison,
        browserUpdatesCovered: poison,
        timerFree: true,
        consentDocumented: true,
      });
      assert.equal(result.deployable, false, String(poison));
      assert.equal(result.reasons.length, 5, String(poison));
    }
  });

  check('C2', 'wrong-type numeric values are rejected, not coerced', () => {
    const result = evaluateWebgpuResearch({
      exactStability30d: '0.98',
      minPerDeviceStabilityMs: new Number(THIRTY_DAYS_MS),
      candidatePool: [],
      captureMs: {},
      browserUpdatesCovered: true,
      timerFree: true,
      consentDocumented: true,
    } as never);
    assert.equal(result.deployable, false);
    assert.equal(result.reasons.length, 5);
  });

  check('C3', 'missing fields fail their own criterion, one reason each', () => {
    const result = evaluateWebgpuResearch({});
    assert.equal(result.deployable, false);
    assert.equal(result.researchOnly, true);
    assert.equal(result.reasons.length, 7);
    assert.equal(new Set(result.reasons).size, 7);
  });

  check('C4', 'null-valued fields fail the same way as missing fields', () => {
    const input: WebgpuResearchInput = {
      exactStability30d: null,
      minPerDeviceStabilityMs: null,
      candidatePool: null,
      captureMs: null,
      timerFree: null,
      consentDocumented: null,
      browserUpdatesCovered: null,
    };
    const result = evaluateWebgpuResearch(input);
    assert.deepEqual(result, evaluateWebgpuResearch({}));
    assert.equal(result.deployable, false);
  });

  section('D. Hostile input — nothing throws and nothing is trusted');

  check('D1', 'null, undefined, primitives, arrays and functions never throw', () => {
    for (const hostile of [null, undefined, 42, 'gate', true, [], () => undefined] as never[]) {
      let result: WebgpuResearchResult | undefined;
      assert.doesNotThrow(() => {
        result = evaluateWebgpuResearch(hostile);
      }, `threw for ${String(hostile)}`);
      assert.equal(result?.deployable, false);
      assert.equal(result?.researchOnly, true);
      assert.deepEqual(result?.reasons, [WEBGPU_RESEARCH_REASON.unreadable]);
    }
  });

  check('D2', 'throwing getters on every field are contained', () => {
    const hostile = {
      get exactStability30d(): unknown { throw new Error('stability getter exploded'); },
      get minPerDeviceStabilityMs(): unknown { throw new Error('window getter exploded'); },
      get candidatePool(): unknown { throw new Error('pool getter exploded'); },
      get captureMs(): unknown { throw new Error('capture getter exploded'); },
      get timerFree(): unknown { throw new Error('timer getter exploded'); },
      get consentDocumented(): unknown { throw new Error('consent getter exploded'); },
      get browserUpdatesCovered(): unknown { throw new Error('updates getter exploded'); },
    } as WebgpuResearchInput;
    let result: WebgpuResearchResult | undefined;
    assert.doesNotThrow(() => {
      result = evaluateWebgpuResearch(hostile);
    });
    assert.equal(result?.deployable, false);
    assert.equal(result?.researchOnly, true);
    assert.equal(result?.reasons.length, 7);
  });

  check('D3', 'a proxy whose get trap throws is contained', () => {
    const hostile = new Proxy({}, {
      get(): unknown { throw new Error('proxy trap exploded'); },
    }) as WebgpuResearchInput;
    let result: WebgpuResearchResult | undefined;
    assert.doesNotThrow(() => {
      result = evaluateWebgpuResearch(hostile);
    });
    assert.equal(result?.deployable, false);
    assert.equal(result?.researchOnly, true);
    assert.equal(result?.reasons.length, 7);
  });

  check('D4', 'hostile extra fields are ignored and cannot influence a pass', () => {
    const extra = {
      ...baseInput(),
      get attack(): unknown { throw new Error('should never be read'); },
      score: 1,
      verdict: 'deployable',
    } as WebgpuResearchInput & Record<string, unknown>;
    assert.equal(evaluateWebgpuResearch(extra).deployable, true);
    assert.deepEqual(Object.keys(evaluateWebgpuResearch(extra)).sort(), [
      'deployable',
      'reasons',
      'researchOnly',
    ]);
  });

  section('E. Cross-cutting contracts');

  check('E1', 'reason count equals the number of failed criteria', () => {
    const allFail = evaluateWebgpuResearch({});
    const partial = evaluateWebgpuResearch({
      ...baseInput(),
      candidatePool: 10,
      captureMs: 1200,
    });
    assert.equal(allFail.reasons.length, 7);
    assert.equal(partial.reasons.length, 2);
    assert.ok(hasReason(partial, WEBGPU_RESEARCH_REASON.candidatePool));
    assert.ok(hasReason(partial, WEBGPU_RESEARCH_REASON.capture));
    assert.equal(new Set([...allFail.reasons, ...partial.reasons]).size >= 7, true);
  });

  check('E2', 'researchOnly is the exact complement of deployable across samples', () => {
    const samples = [
      evaluateWebgpuResearch(baseInput()),
      evaluateWebgpuResearch({}),
      evaluateWebgpuResearch(null),
      evaluateWebgpuResearch({ ...baseInput(), timerFree: false }),
      evaluateWebgpuResearch({ ...baseInput(), exactStability30d: 0.98, candidatePool: 10_001 }),
    ];
    for (const result of samples) {
      assert.equal(result.researchOnly, !result.deployable);
      assert.equal(result.reasons.length > 0, true);
    }
  });

  check('E3', 'reasons are stable, duplicate-free and never empty', () => {
    const input = { ...baseInput(), consentDocumented: false, timerFree: false };
    const first = evaluateWebgpuResearch(input);
    const second = evaluateWebgpuResearch(input);
    assert.deepEqual(first.reasons, second.reasons);
    assert.equal(new Set(first.reasons).size, first.reasons.length);
    assert.ok(first.reasons.every((reason) => reason.length > 0));
  });

  check('E4', 'the gate contains no WebGPU fingerprint probe', () => {
    const source = readFileSync(
      new URL('../src/lib/webgpuResearchGate.ts', import.meta.url),
      'utf8',
    );
    for (const forbidden of [
      'navigator.gpu',
      'requestAdapter',
      'requestDevice',
      'createComputePipeline',
      'createBuffer',
      'GPUBufferUsage',
      'mapAsync',
      'writeBuffer',
      'createCommandEncoder',
    ]) {
      assert.equal(source.includes(forbidden), false, `must not contain ${forbidden}`);
    }
  });

  section('F. Frozen fixture');

  const fixture = loadFixture();

  check('F1', 'fixture metadata is frozen, offline and schema v1', () => {
    assert.equal(fixture.schema_version, 1);
    assert.equal(fixture.frozen, true);
    assert.equal(fixture.offline, true);
    assert.ok(Object.isFrozen(fixture));
    assert.ok(fixture.note.toLowerCase().includes('research'));
    assert.equal(fixture.cases.length, 4);
    assert.equal(fixture.researchFindings.length, 4);
  });

  check('F2', 'fixture has one passing hypothetical and three real-world NO-GO cases', () => {
    const ids = fixture.cases.map((testCase) => testCase.id);
    assert.equal(new Set(ids).size, ids.length);
    assert.deepEqual(ids, [
      'hypothetical-pass',
      'lockedapart-no-timelapse',
      'atomic-increment-realworld',
      'wgpulens-realworld',
    ]);
    assert.equal(fixture.cases.filter((testCase) => testCase.expected.deployable).length, 1);
    assert.equal(fixture.cases.filter((testCase) => !testCase.expected.deployable).length, 3);
  });

  for (const testCase of fixture.cases) {
    check(`F3-${testCase.id}`, `fixture case matches the gate: ${testCase.name}`, () => {
      const result = evaluateWebgpuResearch(testCase.input);
      assert.equal(result.deployable, testCase.expected.deployable);
      assert.equal(result.researchOnly, testCase.expected.researchOnly);
      if (testCase.expected.deployable) {
        assert.deepEqual(result.reasons, [WEBGPU_RESEARCH_REASON.allPassed]);
      } else {
        assert.equal(result.reasons.length, testCase.expected.failingCriteria.length);
        for (const token of testCase.expected.failingCriteria) {
          assert.ok(hasReason(result, token), `missing failing criterion ${token}`);
        }
        for (const reason of result.reasons) {
          assert.ok(
            testCase.expected.failingCriteria.some((token) => hasReason({ ...result, reasons: [reason] }, token)),
            `unexpected reason ${reason}`,
          );
        }
      }
    });
  }

  check('F4', 'all published real-world studies are NO-GO for production identity', () => {
    for (const testCase of fixture.cases.filter((item) => item.id !== 'hypothetical-pass')) {
      const result = evaluateWebgpuResearch(testCase.input);
      assert.equal(result.deployable, false, testCase.id);
      assert.equal(result.researchOnly, true, testCase.id);
      assert.ok(result.reasons.length >= 5, testCase.id);
    }
  });

  check('F5', 'the hypothetical pass still reports the research-only disclosure text', () => {
    const disclosure = researchDisclosure();
    assert.ok(disclosure.includes('RESEARCH_ONLY'));
    assert.ok(disclosure.includes('DrawnApart/LockedApart'));
    assert.ok(disclosure.includes('32ms clamp'));
    const pass = evaluateWebgpuResearch(fixture.cases[0].input);
    assert.equal(pass.deployable, true);
    assert.deepEqual(Object.keys(pass).sort(), ['deployable', 'reasons', 'researchOnly']);
  });
}

/* -------------------------------------------------------------------------- */

let runFailed = false;
try {
  run();
} catch (error) {
  runFailed = true;
  console.error(`FAIL  [fatal] unexpected error: ${describeError(error)}`);
} finally {
  const failedTotal = failed + (runFailed ? 1 : 0);
  if (failedTotal === 0) {
    console.log(`\nRESULT: PASS — ${passed} passed, 0 failed`);
  } else {
    console.log(`\nRESULT: FAIL — ${passed} passed, ${failedTotal} failed`);
    process.exitCode = 1;
  }
}

/**
 * Shadow-only stealth-signal regression suite.
 *
 *   npx tsx scripts/test-stealth-signals.ts
 *
 * Pins the four-tier semantics shared with botVerifier/verdict:
 * hard escalates alone, the conditional trio needs corroboration or a companion,
 * weak is telemetry-only, a bare CDP bridge is developer_tools, and signed-good
 * suppresses the verdict without erasing the evidence inventory.
 */
import assert from 'node:assert/strict';

import {
  evaluateStealthSignals,
  type StealthEvaluation,
  type StealthObservation,
  type StealthSignalId,
} from '../src/lib/stealthSignals';
import { stealthReasonId, stealthReasonWeight } from '../src/lib/verdict';

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

function obs(
  id: StealthSignalId,
  observed = true,
  corroborated?: boolean | null,
): StealthObservation {
  return corroborated === undefined ? { id, observed } : { id, observed, corroborated };
}

const HARD: readonly StealthSignalId[] = [
  'ipcFloodingProtection',
  'pwInitScripts',
  'exposeFunctionLeak',
  'bypassCsp',
  'marionette',
  'chromeHeadlessShell',
];
const MEDIUM: readonly StealthSignalId[] = [
  'runtimeEnableLeak',
  'documentInterception',
  'storagePartitioning',
];
const WEAK: readonly StealthSignalId[] = ['sourceUrlLeak', 'popupBlocking'];

const INERT: StealthEvaluation = {
  detected: false,
  ids: [],
  hard: [],
  reasons: ['not_detected'],
};

/* -------------------------------------------------------------------------- */
/* A. Empty and inactive input                                                */
/* -------------------------------------------------------------------------- */

section('A. Empty / inactive input');

check('empty observations yield the inert shape', () => {
  assert.deepEqual(evaluateStealthSignals([]), INERT);
});

check('observed:false entries are not evidence', () => {
  assert.deepEqual(evaluateStealthSignals(MEDIUM.map((id) => obs(id, false))), INERT);
  assert.deepEqual(evaluateStealthSignals([obs('marionette', false)]), INERT);
});

/* -------------------------------------------------------------------------- */
/* B. Weak tier — telemetry only                                              */
/* -------------------------------------------------------------------------- */

section('B. Bare weak signals never escalate');

for (const id of WEAK) {
  check(`single weak ${id} stays undetected`, () => {
    const result = evaluateStealthSignals([obs(id)]);
    assert.equal(result.detected, false);
    assert.deepEqual(result.ids, [id]);
    assert.deepEqual(result.hard, []);
    assert.equal(result.reasons[result.reasons.length - 1], 'not_detected');
  });
}

check('two weak signals together still stay undetected', () => {
  const result = evaluateStealthSignals([obs('sourceUrlLeak'), obs('popupBlocking')]);
  assert.equal(result.detected, false);
  assert.deepEqual(result.hard, []);
  assert.deepEqual(result.ids, ['sourceUrlLeak', 'popupBlocking']);
});

/* -------------------------------------------------------------------------- */
/* C. Conditional trio — corroboration or a companion is mandatory            */
/* -------------------------------------------------------------------------- */

section('C. Conditional medium signals');

for (const id of MEDIUM) {
  check(`bare ${id} does not escalate`, () => {
    const result = evaluateStealthSignals([obs(id)]);
    assert.equal(result.detected, false);
    assert.deepEqual(result.hard, []);
    assert.equal(result.reasons[result.reasons.length - 1], 'not_detected');
  });
}

for (const id of MEDIUM) {
  check(`corroborated ${id} escalates`, () => {
    const result = evaluateStealthSignals([obs(id, true, true)]);
    assert.equal(result.detected, true);
    assert.deepEqual(result.ids, [id]);
    assert.equal(result.reasons[result.reasons.length - 1], 'automated-runtime');
  });
}

check('a conditional probe paired with a weak signal escalates', () => {
  const result = evaluateStealthSignals([obs('runtimeEnableLeak'), obs('popupBlocking')]);
  assert.equal(result.detected, true);
  assert.deepEqual(result.hard, []);
  assert.deepEqual(result.ids, ['runtimeEnableLeak', 'popupBlocking']);
});

check('two conditional probes paired together escalate', () => {
  const result = evaluateStealthSignals([obs('documentInterception'), obs('storagePartitioning')]);
  assert.equal(result.detected, true);
});

check('a bare CDP bridge does NOT corroborate a conditional probe', () => {
  const result = evaluateStealthSignals([obs('runtimeEnableLeak'), obs('cdpBindingGlobals')]);
  assert.equal(result.detected, false);
  assert.deepEqual(result.hard, []);
});

check('explicitly uncorroborated conditional probe stays bare', () => {
  const result = evaluateStealthSignals([obs('storagePartitioning', true, false)]);
  assert.equal(result.detected, false);
});

/* -------------------------------------------------------------------------- */
/* D. Hard tier — sufficient alone                                            */
/* -------------------------------------------------------------------------- */

section('D. Hard automation artifacts');

for (const id of HARD) {
  check(`hard ${id} escalates on its own`, () => {
    const result = evaluateStealthSignals([obs(id)]);
    assert.equal(result.detected, true);
    assert.deepEqual(result.hard, [id]);
    assert.equal(result.reasons[result.reasons.length - 1], 'automated-runtime');
  });
}

check('hard evidence does not admit medium/weak ids into the hard array', () => {
  const result = evaluateStealthSignals([
    obs('pwInitScripts'),
    obs('runtimeEnableLeak', true, true),
    obs('popupBlocking'),
  ]);
  assert.equal(result.detected, true);
  assert.deepEqual(result.hard, ['pwInitScripts']);
  assert.deepEqual(result.ids, ['pwInitScripts', 'runtimeEnableLeak', 'popupBlocking']);
});

check('hard reason ids reuse the botVerifier vocabulary', () => {
  const result = evaluateStealthSignals([obs('ipcFloodingProtection'), obs('marionette')]);
  assert.ok(result.reasons.includes('launch.ipc-flooding-switch'));
  assert.ok(result.reasons.includes('navigator.webdriver'));
});

/* -------------------------------------------------------------------------- */
/* E. Developer-tools tier                                                    */
/* -------------------------------------------------------------------------- */

section('E. CDP binding globals are developer_tools, not a bot');

check('cdpBindingGlobals alone stays undetected with a developer_tools reason', () => {
  const result = evaluateStealthSignals([obs('cdpBindingGlobals')]);
  assert.equal(result.detected, false);
  assert.deepEqual(result.ids, ['cdpBindingGlobals']);
  assert.deepEqual(result.hard, []);
  assert.equal(result.reasons[result.reasons.length - 1], 'developer_tools');
});

check('corroborated cdpBindingGlobals promotes to hard', () => {
  const result = evaluateStealthSignals([obs('cdpBindingGlobals', true, true)]);
  assert.equal(result.detected, true);
  assert.deepEqual(result.hard, ['cdpBindingGlobals']);
  assert.equal(result.reasons[result.reasons.length - 1], 'automated-runtime');
});

check('observed:false cdpBindingGlobals is ignored', () => {
  assert.deepEqual(evaluateStealthSignals([obs('cdpBindingGlobals', false)]), INERT);
});

/* -------------------------------------------------------------------------- */
/* F. Signed-good precedence                                                  */
/* -------------------------------------------------------------------------- */

section('F. verifiedGoodBot suppresses the verdict, not the evidence');

check('signed-good suppresses even hard evidence', () => {
  const result = evaluateStealthSignals([obs('marionette'), obs('pwInitScripts')], true);
  assert.equal(result.detected, false);
  assert.deepEqual(result.ids, ['marionette', 'pwInitScripts']);
  assert.deepEqual(result.hard, ['marionette', 'pwInitScripts']);
  assert.equal(result.reasons[result.reasons.length - 1], 'signed-agent');
});

check('signed-good suppresses corroborated medium evidence', () => {
  const result = evaluateStealthSignals([obs('runtimeEnableLeak', true, true)], true);
  assert.equal(result.detected, false);
  assert.deepEqual(result.hard, []);
  assert.equal(result.reasons[result.reasons.length - 1], 'signed-agent');
});

check('only a literal boolean true suppresses', () => {
  for (const truthy of ['true', 1, {}, ['x']]) {
    const result = evaluateStealthSignals(
      [obs('marionette')],
      truthy as unknown as boolean,
    );
    assert.equal(result.detected, true, `verifiedGoodBot=${String(truthy)} must not suppress`);
  }
  assert.equal(evaluateStealthSignals([obs('marionette')], false).detected, true);
});

check('signed-good with no observations reports not_detected', () => {
  const result = evaluateStealthSignals([], true);
  assert.equal(result.detected, false);
  assert.deepEqual(result.reasons, ['not_detected']);
});

/* -------------------------------------------------------------------------- */
/* G. Hostile input is contained                                              */
/* -------------------------------------------------------------------------- */

section('G. Hostile inputs never throw');

const hostileContainers: readonly unknown[] = [
  null,
  undefined,
  42,
  'runtimeEnableLeak',
  {},
  Symbol('nope'),
];

for (const [index, hostile] of hostileContainers.entries()) {
  check(`hostile container #${index} yields the inert shape`, () => {
    let result: StealthEvaluation | undefined;
    assert.doesNotThrow(() => {
      result = evaluateStealthSignals(hostile as unknown as readonly StealthObservation[]);
    });
    assert.deepEqual(result, INERT);
  });
}

check('malformed entries are skipped without throwing', () => {
  const hostile = [
    null,
    undefined,
    42,
    'runtimeEnableLeak',
    {},
    { id: 'not-a-signal', observed: true },
    { id: 'popupBlocking', observed: 1 },
    { id: 'runtimeEnableLeak', observed: true, corroborated: 'true' },
  ] as unknown as readonly StealthObservation[];
  let result: StealthEvaluation | undefined;
  assert.doesNotThrow(() => {
    result = evaluateStealthSignals(hostile);
  });
  // The last entry is a valid observation; its string `corroborated` is ignored,
  // so it is recorded for telemetry but cannot escalate on its own.
  assert.deepEqual(result, {
    detected: false,
    ids: ['runtimeEnableLeak'],
    hard: [],
    reasons: ['stealth.runtime-enable-leak', 'not_detected'],
  });
});

check('throwing getters and hostile proxies are contained', () => {
  const hostileGetter = {} as StealthObservation;
  Object.defineProperty(hostileGetter, 'id', {
    get(): StealthSignalId {
      throw new Error('boom');
    },
  });
  const hostileProxy = new Proxy([obs('marionette')], {
    get(): never {
      throw new Error('proxy boom');
    },
  }) as unknown as readonly StealthObservation[];
  let result: StealthEvaluation | undefined;
  assert.doesNotThrow(() => {
    result = evaluateStealthSignals([hostileGetter]);
  });
  assert.deepEqual(result, INERT);
  assert.doesNotThrow(() => {
    evaluateStealthSignals(hostileProxy);
  });
});

/* -------------------------------------------------------------------------- */
/* H. Duplicates, exhaustiveness, determinism                                 */
/* -------------------------------------------------------------------------- */

section('H. Normalization and purity');

check('duplicate ids are deduplicated but may supply corroboration', () => {
  const result = evaluateStealthSignals([
    obs('runtimeEnableLeak'),
    obs('runtimeEnableLeak', true, true),
  ]);
  assert.equal(result.detected, true);
  assert.deepEqual(result.ids, ['runtimeEnableLeak']);
  assert.equal(result.reasons.filter((r) => r === 'stealth.runtime-enable-leak').length, 1);
});

check('all twelve signal ids are recognized', () => {
  const all: readonly StealthSignalId[] = [...HARD, ...MEDIUM, ...WEAK, 'cdpBindingGlobals'];
  assert.equal(all.length, 12);
  const result = evaluateStealthSignals(all.map((id) => obs(id)));
  assert.equal(result.ids.length, 12);
  assert.deepEqual([...result.ids].sort(), [...all].sort());
});

check('evaluation is deterministic and does not mutate a frozen input', () => {
  const input = Object.freeze([
    Object.freeze(obs('popupBlocking')),
    Object.freeze(obs('storagePartitioning', true, true)),
  ]) as readonly StealthObservation[];
  const first = evaluateStealthSignals(input);
  const second = evaluateStealthSignals(input);
  assert.deepEqual(first, second);
  assert.equal(input.length, 2);
  assert.equal(input[0].id, 'popupBlocking');
  assert.equal(input[1].corroborated, true);
});

check('reason outcome tokens come from the botVerifier vocabulary', () => {
  const outcomes = [
    evaluateStealthSignals([]).reasons,
    evaluateStealthSignals([obs('cdpBindingGlobals')]).reasons,
    evaluateStealthSignals([obs('marionette')]).reasons,
    evaluateStealthSignals([obs('marionette')], true).reasons,
  ].map((reasons) => reasons[reasons.length - 1]);
  assert.deepEqual(outcomes, ['not_detected', 'developer_tools', 'automated-runtime', 'signed-agent']);
});

/* -------------------------------------------------------------------------- */
/* I. Confirmed (RED) variants resolve to the hard protocol ids               */
/* -------------------------------------------------------------------------- */

section('I. Confirmed (RED) variants resolve to the hard protocol ids');

// The collector's buildStealthObservations emits documentInterception with
// corroborated:true when the navigation-timing guard is the RED condition
// (transferSize>0 && nextHopProtocol==='' && deliveryType==='' && workerStart===0) —
// a protocol-level impossibility no page script, extension or user setting reproduces.
check('confirmed documentInterception maps to the hard RED id', () => {
  assert.equal(
    stealthReasonId('documentInterception', false, { confirmed: true }),
    'stealth.document-interception-protocol'
  );
  assert.equal(stealthReasonWeight('documentInterception', false, { confirmed: true }), 'hard');
});

check('the bare documentInterception id stays medium', () => {
  assert.equal(stealthReasonId('documentInterception'), 'stealth.document-interception');
  assert.equal(stealthReasonWeight('documentInterception'), 'medium');
});

check('a corroborated documentInterception observation escalates (RED semantics)', () => {
  const result = evaluateStealthSignals([obs('documentInterception', true, true)]);
  assert.equal(result.detected, true);
  // The RED id itself is selected by stealthReasonId at the botVerifier boundary; the
  // evaluator records the escalation with the medium base id plus the outcome token.
  assert.ok(result.reasons.includes('stealth.document-interception'));
  assert.equal(result.reasons[result.reasons.length - 1], 'automated-runtime');
});

check('the plain (uncorroborated) observation stays bare', () => {
  const result = evaluateStealthSignals([obs('documentInterception', true, false)]);
  assert.equal(result.detected, false);
  assert.equal(result.reasons[result.reasons.length - 1], 'not_detected');
});

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}

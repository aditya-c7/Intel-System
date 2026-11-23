/**
 * Regression suite for the identity-scope resolver (dependency-free).
 *
 *   npx tsx scripts/test-identity-scope.ts
 *
 * Covers the explicit-context-salt rule (the ONLY isolated scope), the incognito +
 * stable-hardware-anchor rule (hardware scope from explicit metadata — incognito never implies
 * isolation), the full 16-combination truth table, and hostile/non-throwing input. The suite also
 * asserts the "never mints an id" contract (exact three-field shape, no echoes, deterministic).
 */
import assert from 'node:assert/strict';

import {
  resolveIdentityScope,
  type IdentityScopeInput,
  type IdentityScopeResult,
} from '../src/lib/identityScope.ts';

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

/* -------------------------------------------------------------------------- */
/* 1. Explicit context salt — the only isolated scope                          */
/* -------------------------------------------------------------------------- */

section('1. context_salt_present -> context / isolated');

check('a context salt alone produces a context-scoped, isolated identity', () => {
  const result: IdentityScopeResult = resolveIdentityScope({ contextSaltPresent: true });
  assert.equal(result.id_scope, 'context');
  assert.equal(result.context_isolated, true);
  assert.match(result.reason, /context_salt_present/);
  assert.match(result.reason, /isolates the identity scope/);
});

check('context salt overrides incognito + stable hardware anchor', () => {
  const result = resolveIdentityScope({
    incognito: true,
    hardwareAnchorStable: true,
    firstPartyStorageSurvived: true,
    contextSaltPresent: true,
  });
  assert.equal(result.id_scope, 'context');
  assert.equal(result.context_isolated, true);
  assert.match(result.reason, /context_salt_present/);
  assert.doesNotMatch(result.reason, /hardware scope from explicit metadata/);
});

check('context salt still wins when the other three fields are hostile', () => {
  const hostile = new Proxy(
    { contextSaltPresent: true },
    {
      get(target, prop, receiver) {
        if (prop === 'contextSaltPresent') return Reflect.get(target, prop, receiver);
        throw new Error('hostile getter');
      },
    },
  );
  let result: IdentityScopeResult | undefined;
  assert.doesNotThrow(() => {
    result = resolveIdentityScope(hostile);
  });
  assert.equal(result?.id_scope, 'context');
  assert.equal(result?.context_isolated, true);
  assert.match(result?.reason ?? '', /unreadable fields ignored \(incognito, firstPartyStorageSurvived, hardwareAnchorStable\)/);
});

check('salt result records all four inputs in its metadata clause', () => {
  const result = resolveIdentityScope({
    incognito: true,
    firstPartyStorageSurvived: false,
    hardwareAnchorStable: true,
    contextSaltPresent: true,
  });
  assert.match(
    result.reason,
    /metadata: incognito=true, first_party_storage_survived=false, hardware_anchor_stable=true, context_salt_present=true/,
  );
  assert.ok(result.reason.endsWith('.'));
});

/* -------------------------------------------------------------------------- */
/* 2. Incognito + stable anchor — explicit metadata, never assume isolation    */
/* -------------------------------------------------------------------------- */

section('2. incognito + stable_hardware_anchor + no salt -> hardware');

check('incognito with a stable hardware anchor stays hardware and NOT isolated', () => {
  const result = resolveIdentityScope({
    incognito: true,
    hardwareAnchorStable: true,
  });
  assert.equal(result.id_scope, 'hardware');
  assert.equal(result.context_isolated, false);
  assert.match(result.reason, /stable_hardware_anchor/);
});

check('the reason explicitly says incognito never implies isolation', () => {
  const result = resolveIdentityScope({ incognito: true, hardwareAnchorStable: true });
  assert.match(result.reason, /explicit metadata/);
  assert.match(result.reason, /never implies privacy isolation/i);
  assert.match(result.reason, /context isolation is NOT assumed/);
});

check('first-party storage survival cannot create an isolated scope', () => {
  const survived = resolveIdentityScope({
    incognito: true,
    hardwareAnchorStable: true,
    firstPartyStorageSurvived: true,
  });
  const gone = resolveIdentityScope({
    incognito: true,
    hardwareAnchorStable: true,
    firstPartyStorageSurvived: false,
  });
  assert.equal(survived.id_scope, 'hardware');
  assert.equal(survived.context_isolated, false);
  assert.equal(gone.id_scope, survived.id_scope);
  assert.equal(gone.context_isolated, survived.context_isolated);
  assert.match(survived.reason, /first-party storage survival is not isolation metadata/);
});

/* -------------------------------------------------------------------------- */
/* 3. Every other no-salt combination is hardware / non-isolated              */
/* -------------------------------------------------------------------------- */

section('3. No context salt -> hardware / non-isolated');

check('incognito without a confirmed stable anchor is still hardware', () => {
  const result = resolveIdentityScope({ incognito: true });
  assert.equal(result.id_scope, 'hardware');
  assert.equal(result.context_isolated, false);
  assert.match(result.reason, /hardware anchor not confirmed stable/);
  assert.match(result.reason, /context isolation is NOT assumed/);
});

check('a stable hardware anchor without incognito is hardware', () => {
  const result = resolveIdentityScope({ hardwareAnchorStable: true });
  assert.equal(result.id_scope, 'hardware');
  assert.equal(result.context_isolated, false);
  assert.match(result.reason, /stable hardware anchor/);
});

check('empty input and explicit all-false input use the hardware fallback', () => {
  const empty = resolveIdentityScope({});
  const allFalse = resolveIdentityScope({
    incognito: false,
    firstPartyStorageSurvived: false,
    hardwareAnchorStable: false,
    contextSaltPresent: false,
  });
  assert.equal(empty.id_scope, 'hardware');
  assert.equal(empty.context_isolated, false);
  assert.deepEqual(allFalse, empty, 'explicit false must equal absence of evidence');
  assert.match(empty.reason, /hardware scope fallback/);
  assert.match(empty.reason, /no explicit isolation metadata/);
});

/* -------------------------------------------------------------------------- */
/* 4. Exhaustive truth table                                                    */
/* -------------------------------------------------------------------------- */

section('4. Exhaustive 16-combination truth table');

const TRUTH_TABLE: IdentityScopeInput[] = [];
for (const incognito of [false, true]) {
  for (const firstPartyStorageSurvived of [false, true]) {
    for (const hardwareAnchorStable of [false, true]) {
      for (const contextSaltPresent of [false, true]) {
        TRUTH_TABLE.push({ incognito, firstPartyStorageSurvived, hardwareAnchorStable, contextSaltPresent });
      }
    }
  }
}

check('all 16 combinations: scope is context iff an explicit salt is present', () => {
  assert.equal(TRUTH_TABLE.length, 16);
  for (const input of TRUTH_TABLE) {
    const salt = input.contextSaltPresent === true;
    const result = resolveIdentityScope(input);
    assert.equal(result.id_scope, salt ? 'context' : 'hardware', JSON.stringify(input));
    assert.equal(result.context_isolated, salt, JSON.stringify(input));
    assert.equal(result.context_isolated, result.id_scope === 'context', JSON.stringify(input));
    assert.equal(typeof result.reason, 'string');
    assert.ok(result.reason.length > 0);
    assert.ok(result.reason.endsWith('.'));
  }
});

check('all 16 combinations are deterministic across repeated calls', () => {
  for (const input of TRUTH_TABLE) {
    assert.deepEqual(resolveIdentityScope(input), resolveIdentityScope(input), JSON.stringify(input));
  }
});

/* -------------------------------------------------------------------------- */
/* 5. Hostile input is non-throwing and fails safe                             */
/* -------------------------------------------------------------------------- */

section('5. Hostile input never throws and never assumes isolation');

check('hostile primitive inputs degrade to the safe hardware result', () => {
  const hostileInputs: unknown[] = [null, undefined, 42, 'x', true, false, Symbol('s'), () => 1, [], new Number(1)];
  for (const input of hostileInputs) {
    let result: IdentityScopeResult | undefined;
    assert.doesNotThrow(() => {
      result = resolveIdentityScope(input as IdentityScopeInput);
    }, `input ${String(input)} must not throw`);
    assert.equal(result?.id_scope, 'hardware');
    assert.equal(result?.context_isolated, false);
    assert.ok((result?.reason ?? '').length > 0);
  }
});

check('a proxy whose every getter throws degrades without throwing', () => {
  const hostile = new Proxy({}, { get() { throw new Error('hostile getter'); } });
  let result: IdentityScopeResult | undefined;
  assert.doesNotThrow(() => {
    result = resolveIdentityScope(hostile);
  });
  assert.equal(result?.id_scope, 'hardware');
  assert.equal(result?.context_isolated, false);
  assert.match(result?.reason ?? '', /context isolation is NOT assumed/);
  assert.match(
    result?.reason ?? '',
    /unreadable fields ignored \(incognito, firstPartyStorageSurvived, hardwareAnchorStable, contextSaltPresent\)/,
  );
});

check('a throwing contextSaltPresent getter is treated as absence of salt', () => {
  const partial = new Proxy(
    { incognito: true, firstPartyStorageSurvived: true, hardwareAnchorStable: true },
    {
      get(target, prop, receiver) {
        if (prop === 'contextSaltPresent') throw new Error('no salt for you');
        return Reflect.get(target, prop, receiver);
      },
    },
  );
  let result: IdentityScopeResult | undefined;
  assert.doesNotThrow(() => {
    result = resolveIdentityScope(partial);
  });
  assert.equal(result?.id_scope, 'hardware');
  assert.equal(result?.context_isolated, false);
  assert.match(result?.reason ?? '', /hardware scope from explicit metadata/);
  assert.match(result?.reason ?? '', /unreadable fields ignored \(contextSaltPresent\)/);
});

check('truthy junk is NOT affirmative for any field', () => {
  const result = resolveIdentityScope({
    incognito: 1,
    firstPartyStorageSurvived: 'true',
    hardwareAnchorStable: {},
    contextSaltPresent: new Boolean(true),
  });
  assert.equal(result.id_scope, 'hardware');
  assert.equal(result.context_isolated, false);
  assert.match(result.reason, /metadata: incognito=false, first_party_storage_survived=false, hardware_anchor_stable=false, context_salt_present=false/);
});

check('null and undefined inputs are accepted and return a valid shape', () => {
  for (const input of [null, undefined]) {
    const result = resolveIdentityScope(input);
    assert.equal(result.id_scope, 'hardware');
    assert.equal(result.context_isolated, false);
    assert.deepEqual(Object.keys(result).sort(), ['context_isolated', 'id_scope', 'reason']);
  }
});

/* -------------------------------------------------------------------------- */
/* 6. No id is ever minted or echoed                                            */
/* -------------------------------------------------------------------------- */

section('6. Never mints or echoes an identifier');

check('the result has exactly three declarative fields and no id field', () => {
  const result = resolveIdentityScope({
    incognito: true,
    hardwareAnchorStable: true,
    contextSaltPresent: true,
  });
  assert.deepEqual(Object.keys(result).sort(), ['context_isolated', 'id_scope', 'reason']);
  assert.ok(!Object.prototype.hasOwnProperty.call(result, 'visitorId'));
  assert.ok(!Object.prototype.hasOwnProperty.call(result, 'visitor_id'));
  assert.ok(!Object.prototype.hasOwnProperty.call(result, 'identifier'));
  assert.ok(!Object.prototype.hasOwnProperty.call(result, 'salt'));
  for (const key of Object.keys(result)) {
    assert.ok(key === 'id_scope' || !/id/i.test(key), `unexpected id-like key ${key}`);
  }
});

check('supplied id-like strings are never echoed into the reason', () => {
  const secretId = 'SECRET_VISITOR_ID_DO_NOT_ECHO_9f3c';
  const result = resolveIdentityScope({
    incognito: secretId,
    firstPartyStorageSurvived: secretId,
    hardwareAnchorStable: secretId,
    contextSaltPresent: secretId,
  });
  assert.equal(result.id_scope, 'hardware');
  assert.equal(result.context_isolated, false);
  assert.ok(!JSON.stringify(result).includes(secretId), 'input values must never leak into the result');
});

check('every result explicitly states that no identifier was minted', () => {
  for (const input of TRUTH_TABLE) {
    assert.match(resolveIdentityScope(input).reason, /no identifier was minted/);
  }
  assert.match(resolveIdentityScope(null).reason, /no identifier was minted/);
});

check('the helper does not mutate a frozen input object', () => {
  const frozen = Object.freeze({
    incognito: true,
    firstPartyStorageSurvived: true,
    hardwareAnchorStable: true,
    contextSaltPresent: false,
  });
  const snapshot = JSON.stringify(frozen);
  assert.doesNotThrow(() => {
    resolveIdentityScope(frozen);
    resolveIdentityScope(frozen);
  });
  assert.equal(JSON.stringify(frozen), snapshot, 'input evidence must not be mutated');
});

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}

/**
 * R4 regression suite — supplementary high-recall sibling id.
 *
 * Coverage-first, deterministic, versioned HMAC-SHA-256 cohort hint derived from ALREADY
 * RESOLVED stable signals only. Emitted beside the primary id; never a confidence claim and
 * never a sole blocking key. No network, no Durable Object writes, no random minting.
 *
 *   npx tsx scripts/test-supplementary-id.ts
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  HIGH_RECALL_DEFAULT_PEPPER,
  HIGH_RECALL_ID_ALPHABET,
  HIGH_RECALL_ID_LENGTH,
  HIGH_RECALL_MAX_ID_LENGTH,
  HIGH_RECALL_PRIOR_PURPOSE_KEY,
  HIGH_RECALL_PURPOSE_KEY,
  HIGH_RECALL_STABLE_FIELDS,
  asSupplementaryIdentity,
  buildHighRecallInput,
  resolveSupplementaryFriction,
  resolveSupplementaryHighRecall,
  withSupplementaryHighRecall,
  type HighRecallInput,
  type SupplementaryHighRecallResult,
} from '../src/lib/identityEngine';

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

interface FixtureCase {
  id: string;
  name: string;
  input: unknown;
  expected: { visitor_id: string | null; visitor_found: boolean; reason: string; key_version: string };
  expected_input?: { values: Record<string, string>; pepper: string; key_version: string };
}
interface Fixture {
  schema_version: number;
  contract: Record<string, unknown>;
  cases: FixtureCase[];
}

const fixture = JSON.parse(
  readFileSync(new URL('./fixtures/supplementary-id.json', import.meta.url), 'utf8'),
) as Fixture;
const byId = (id: string): FixtureCase => {
  const found = fixture.cases.find((entry) => entry.id === id);
  assert.ok(found, `fixture case ${id} must exist`);
  return found;
};
const derive = (input: unknown): SupplementaryHighRecallResult =>
  resolveSupplementaryHighRecall(buildHighRecallInput(input));

/* -------------------------------------------------------------------------- */
/* 1. Frozen fixture contract                                                  */
/* -------------------------------------------------------------------------- */

section('1. Frozen fixture contract');

check('fixture is a versioned, frozen, offline contract with 10 cases', () => {
  assert.equal(fixture.schema_version, 1);
  assert.equal(fixture.contract.purpose_key, HIGH_RECALL_PURPOSE_KEY);
  assert.equal(fixture.contract.prior_key_accepted_one_rotation, HIGH_RECALL_PRIOR_PURPOSE_KEY);
  assert.equal(fixture.contract.id_length, HIGH_RECALL_ID_LENGTH);
  assert.equal(fixture.contract.max_id_length, HIGH_RECALL_MAX_ID_LENGTH);
  assert.equal(fixture.contract.confidence_claim, 'none');
  assert.equal(fixture.cases.length, 10);
});

check('every fixture case resolves to its pinned result', () => {
  for (const entry of fixture.cases) {
    const actual = derive(entry.input);
    assert.deepEqual(actual, entry.expected, `case ${entry.id}`);
  }
});

check('fixture canonical inputs pin truncation, pepper and key version', () => {
  for (const entry of fixture.cases) {
    if (!entry.expected_input) continue;
    const built = buildHighRecallInput(entry.input);
    assert.deepEqual(built.values, entry.expected_input.values, `values for ${entry.id}`);
    assert.equal(built.pepper, entry.expected_input.pepper, `pepper for ${entry.id}`);
    assert.equal(built.key_version, entry.expected_input.key_version, `key version for ${entry.id}`);
  }
});

check('derived ids are 20-char alphanumeric and within the <=25 shape', () => {
  for (const entry of fixture.cases) {
    const result = derive(entry.input);
    if (!result.visitor_id) continue;
    assert.equal(result.visitor_id.length, HIGH_RECALL_ID_LENGTH, `length for ${entry.id}`);
    assert.ok(result.visitor_id.length <= HIGH_RECALL_MAX_ID_LENGTH);
    assert.match(result.visitor_id, /^[A-Za-z0-9]+$/, `alphabet for ${entry.id}`);
    for (const char of result.visitor_id) assert.ok(HIGH_RECALL_ID_ALPHABET.includes(char));
    assert.doesNotMatch(result.visitor_id, /^[0-9a-f]{8}-[0-9a-f]{4}-/, 'must never be a UUID');
  }
});

check('result has exactly four fields — no confidence or score claim', () => {
  const result = derive(byId('full-stable-bundle').input);
  assert.deepEqual(Object.keys(result).sort(), ['key_version', 'reason', 'visitor_found', 'visitor_id']);
  assert.ok(!Object.prototype.hasOwnProperty.call(result, 'confidence'));
  assert.ok(!Object.prototype.hasOwnProperty.call(result, 'score'));
  assert.ok(!JSON.stringify(result).includes('confidence'));
});

/* -------------------------------------------------------------------------- */
/* 2. Determinism — no random minting                                          */
/* -------------------------------------------------------------------------- */

section('2. Determinism and no-minting');

const STABLE = byId('full-stable-bundle').input;

check('identical signals produce an identical id across repeated calls', () => {
  const a = derive(STABLE);
  for (let i = 0; i < 25; i += 1) assert.deepEqual(derive(STABLE), a);
});

check('object key insertion order cannot change the id', () => {
  const forward = derive(STABLE);
  const reversed = derive({
    tenantId: 'tenant-acme',
    browserDetails: { browser_name: 'Chrome' },
    architecture: 'x86_64',
    platform: 'Win32',
    timezone: 'America/New_York',
    clientIp: '203.0.113.42',
    firstLanguage: 'en-US',
    normalizedUserAgent: 'Chrome/124.0.0.0 Windows NT 10.0',
  });
  assert.equal(reversed.visitor_id, forward.visitor_id);
});

check('the helper never mints an id from nothing', () => {
  assert.equal(derive({}).visitor_id, null);
  assert.equal(derive({}).visitor_found, false);
  assert.equal(derive({}).reason, 'insufficient_resolved_signals');
  assert.deepEqual(buildHighRecallInput({}).values, {});
});

check('primary id fields are never folded into the HR seed', () => {
  const withoutPrimary = derive(STABLE);
  const withPrimary = derive({
    ...(STABLE as Record<string, unknown>),
    storageVisitorId: 'PRIMARY-VISITOR-123',
    exactHardwareId: 'HW-SECRET-456',
    visitorId: 'PRIMARY-VISITOR-123',
  });
  assert.equal(withPrimary.visitor_id, withoutPrimary.visitor_id);
  const input = buildHighRecallInput({ storageVisitorId: 'PRIMARY-VISITOR-123', exactHardwareId: 'HW-SECRET-456' });
  assert.deepEqual(input.values, {});
  assert.ok(!JSON.stringify(input).includes('PRIMARY-VISITOR-123'));
  assert.ok(!JSON.stringify(input).includes('HW-SECRET-456'));
});

check('reason names only whitelisted field keys, never signal values', () => {
  const result = derive(STABLE);
  assert.equal(result.reason, `derived_from:${HIGH_RECALL_STABLE_FIELDS.slice().sort().join(',')}`);
  assert.ok(!result.reason.includes('chrome'));
  assert.ok(!result.reason.includes('203'));
  assert.ok(!result.reason.includes('tenant-acme'));
});

/* -------------------------------------------------------------------------- */
/* 3. Canonicalization and hostile input                                       */
/* -------------------------------------------------------------------------- */

section('3. Canonicalization and hostile input');

check('lowercase, trim, whitespace collapse and unicode spaces canonicalize', () => {
  const noisy = derive({
    normalizedUserAgent: '  CHROME/124.0.0.0\u00a0Windows   NT 10.0  ',
    firstLanguage: 'EN-us',
    timezone: '  America/New_York ',
    tenantId: ' TENANT-ACME ',
  });
  const clean = derive({
    normalizedUserAgent: 'chrome/124.0.0.0 windows nt 10.0',
    firstLanguage: 'en-us',
    timezone: 'america/new_york',
    tenantId: 'tenant-acme',
  });
  assert.equal(noisy.visitor_id, clean.visitor_id);
});

check('delimiter injection (| = ,) is stripped before HMAC serialization', () => {
  const a = derive({ timezone: 'utc|inject=true,other', tenantId: 't|1' });
  const b = derive({ timezone: 'utc inject true other', tenantId: 't 1' });
  assert.equal(a.visitor_id, b.visitor_id);
  const built = buildHighRecallInput({ timezone: 'utc|inject=true' });
  assert.ok(!Object.values(built.values).some((value) => value.includes('|') || value.includes('=')));
});

check('pathologically long tokens are bounded without throwing', () => {
  const huge = 'x'.repeat(1_000_000);
  let result: SupplementaryHighRecallResult | undefined;
  assert.doesNotThrow(() => {
    result = derive({ timezone: huge, tenantId: 'tenant-acme' });
  });
  assert.equal(result?.visitor_found, true);
  assert.ok(result?.visitor_id && result.visitor_id.length <= HIGH_RECALL_MAX_ID_LENGTH);
  assert.ok(!JSON.stringify(result).includes(huge));
});

check('hostile primitives degrade conservatively without throwing', () => {
  for (const input of [null, undefined, 42, 'x', true, [], Symbol('s'), () => 1]) {
    let result: SupplementaryHighRecallResult | undefined;
    assert.doesNotThrow(() => {
      result = derive(input);
    }, `input ${String(input)} must not throw`);
    assert.equal(result?.visitor_id, null);
    assert.equal(result?.visitor_found, false);
    assert.equal(result?.key_version, HIGH_RECALL_PURPOSE_KEY);
  }
});

check('throwing getters / proxies never escape as exceptions', () => {
  const hostile = new Proxy({}, { get() { throw new Error('hostile getter'); } });
  let result: SupplementaryHighRecallResult | undefined;
  assert.doesNotThrow(() => {
    result = derive(hostile);
  });
  assert.equal(result?.visitor_found, false);

  const valuesProxy = new Proxy({ timezone: 'utc' }, {
    ownKeys() { throw new Error('hostile ownKeys'); },
  });
  assert.doesNotThrow(() => {
    resolveSupplementaryHighRecall({ values: valuesProxy, pepper: 'p', key_version: HIGH_RECALL_PURPOSE_KEY });
  });
});

check('frozen signal bundles are never mutated', () => {
  const frozen = Object.freeze({ ...(STABLE as Record<string, unknown>) });
  const snapshot = JSON.stringify(frozen);
  assert.doesNotThrow(() => {
    buildHighRecallInput(frozen);
    derive(frozen);
  });
  assert.equal(JSON.stringify(frozen), snapshot);
});

check('volatile-only bundles and the DST offset yield no id', () => {
  const volatile = derive(byId('volatile-only').input);
  assert.equal(volatile.visitor_found, false);
  const named = derive({ timezone: 'America/New_York', tenantId: 'tenant-acme' });
  const offsetOnly = derive({ timezoneOffset: -300, tenantId: 'tenant-acme' });
  assert.equal(offsetOnly.visitor_found, false);
  assert.equal(named.visitor_id, derive({ timezone: 'America/New_York', timezoneOffset: -240, tenantId: 'tenant-acme' }).visitor_id);
});

/* -------------------------------------------------------------------------- */
/* 4. IP truncation (v4 /24, v6 /48) and PII minimization                     */
/* -------------------------------------------------------------------------- */

section('4. IP truncation and PII minimization');

check('IPv4 /24 collapses every host in the same block', () => {
  const base = { timezone: 'UTC', tenantId: 'tenant-acme' };
  const a = derive({ ...base, clientIp: '198.51.100.1' });
  const b = derive({ ...base, clientIp: '198.51.100.254' });
  const c = derive({ ...base, clientIp: '198.51.101.1' });
  assert.equal(a.visitor_id, b.visitor_id);
  assert.notEqual(a.visitor_id, c.visitor_id);
  assert.equal(buildHighRecallInput({ clientIp: '198.51.100.254' }).values.ip_prefix, '198.51.100.0/24');
});

check('invalid IPv4 octets are rejected rather than hashed', () => {
  for (const bad of ['999.1.1.1', '1.2.3', '1.2.3.4.5', 'not-an-ip', '1.2.3.-4']) {
    assert.equal(buildHighRecallInput({ clientIp: bad }).values.ip_prefix, undefined, `reject ${bad}`);
  }
});

check('IPv6 /48 collapses full and compressed forms', () => {
  const full = buildHighRecallInput({ clientIp: '2001:db8:abcd:9999:1111:2222:3333:4444' }).values.ip_prefix;
  const compressed = buildHighRecallInput({ clientIp: '2001:db8:abcd::1' }).values.ip_prefix;
  assert.equal(full, '2001:0db8:abcd::/48');
  assert.equal(compressed, full);
  const base = { timezone: 'UTC', tenantId: 'tenant-acme' };
  assert.equal(
    derive({ ...base, clientIp: '2001:db8:abcd:1111::1' }).visitor_id,
    derive({ ...base, clientIp: '2001:0db8:abcd:ffff::beef' }).visitor_id,
  );
});

check('IPv6 /48 distinguishes a different third hextet', () => {
  const base = { timezone: 'UTC', tenantId: 'tenant-acme' };
  const a = derive({ ...base, clientIp: '2001:db8:abcd::1' });
  const b = derive({ ...base, clientIp: '2001:db8:abce::1' });
  assert.notEqual(a.visitor_id, b.visitor_id);
});

check('malformed IPv6 (including embedded IPv4) is rejected', () => {
  for (const bad of ['2001:db8::gg', '2001:::1', '::ffff:192.0.2.1', '12345::1']) {
    assert.equal(buildHighRecallInput({ clientIp: bad }).values.ip_prefix, undefined, `reject ${bad}`);
  }
});

check('raw IP never appears in the canonical input or the derived id', () => {
  const built = buildHighRecallInput({ clientIp: '203.0.113.77', tenantId: 'tenant-acme' });
  assert.ok(!JSON.stringify(built).includes('203.0.113.77'));
  assert.ok(!JSON.stringify(built).includes('.77'));
  const result = resolveSupplementaryHighRecall(built);
  assert.ok(!JSON.stringify(result).includes('203.0.113'));
  assert.equal(built.values.ip_prefix, '203.0.113.0/24');
});

check('first language uses the resolved primary language only', () => {
  const a = derive({ firstLanguage: 'en-US', tenantId: 'tenant-acme' });
  const b = derive({ languages: ['de-DE', 'en-US'], tenantId: 'tenant-acme' });
  const c = derive({ languages: ['en-US', 'de-DE'], tenantId: 'tenant-acme' });
  assert.equal(a.visitor_id, c.visitor_id, 'the first language, not the full list, is the seed');
  assert.notEqual(b.visitor_id, c.visitor_id, 'changing the first language changes the cohort');
  assert.equal(a.visitor_id, derive({ language: 'en-US', tenantId: 'tenant-acme' }).visitor_id);
  assert.equal(b.visitor_id, derive({ firstLanguage: 'de-DE', tenantId: 'tenant-acme' }).visitor_id);
});

/* -------------------------------------------------------------------------- */
/* 5. Versioned purpose key and tenant-scoped pepper                          */
/* -------------------------------------------------------------------------- */

section('5. Key rotation and tenant scope');

check('active and prior purpose keys produce different but valid ids', () => {
  const active = derive(byId('full-stable-bundle').input);
  const prior = derive(byId('prior-key-rotation').input);
  assert.equal(active.key_version, HIGH_RECALL_PURPOSE_KEY);
  assert.equal(prior.key_version, HIGH_RECALL_PRIOR_PURPOSE_KEY);
  assert.equal(prior.visitor_found, true);
  assert.notEqual(active.visitor_id, prior.visitor_id);
});

check('only one prior key is accepted; older versions are rejected', () => {
  const rejected = derive(byId('unsupported-key-rotation').input);
  assert.equal(rejected.visitor_id, null);
  assert.equal(rejected.visitor_found, false);
  assert.equal(rejected.reason, 'unsupported_key_version');
  const forged = resolveSupplementaryHighRecall({ values: { timezone: 'utc' }, key_version: 'high-recall:v-1' });
  assert.equal(forged.visitor_found, false);
});

check('tenant / instance pepper isolates otherwise identical cohorts', () => {
  const a = derive({ timezone: 'UTC', tenantId: 'tenant-a' });
  const b = derive({ timezone: 'UTC', tenantId: 'tenant-b' });
  assert.notEqual(a.visitor_id, b.visitor_id);
  const fallbackA = derive({ timezone: 'UTC' });
  const fallbackB = derive({ timezone: 'UTC', instanceId: HIGH_RECALL_DEFAULT_PEPPER });
  assert.equal(fallbackA.visitor_id, fallbackB.visitor_id);
});

check('unsupported input versions degrade without throwing', () => {
  for (const input of [null, 0, 'v1', [], { values: null }]) {
    let result: SupplementaryHighRecallResult | undefined;
    assert.doesNotThrow(() => {
      result = resolveSupplementaryHighRecall(input);
    });
    assert.equal(result?.visitor_found, false);
  }
});

/* -------------------------------------------------------------------------- */
/* 6. Friction matrix — hint only, never a sole blocking key                  */
/* -------------------------------------------------------------------------- */

section('6. Friction matrix');

check('both primary and HR match -> low friction', () => {
  const decision = resolveSupplementaryFriction({ primaryMatch: true, highRecallMatch: true });
  assert.equal(decision.friction, 'low');
  assert.equal(decision.blocks, false);
  assert.match(decision.reason, /primary_authoritative/);
});

check('HR hint only -> moderate friction, never a block', () => {
  const decision = resolveSupplementaryFriction({ primaryMatch: false, highRecallMatch: true });
  assert.equal(decision.friction, 'moderate');
  assert.equal(decision.blocks, false);
  assert.match(decision.reason, /hint_only/);
});

check('both differ -> new enrollment, never a block', () => {
  const decision = resolveSupplementaryFriction({ primaryMatch: false, highRecallMatch: false });
  assert.equal(decision.friction, 'new');
  assert.equal(decision.blocks, false);
  assert.match(decision.reason, /new_enrollment/);
});

check('primary match stays authoritative when the HR hint disagrees', () => {
  const decision = resolveSupplementaryFriction({ primaryMatch: true, highRecallMatch: false });
  assert.equal(decision.friction, 'low');
  assert.equal(decision.blocks, false);
});

check('hostile friction input degrades to new without throwing', () => {
  for (const input of [null, 3, 'x', [], new Proxy({}, { get() { throw new Error('no'); } })]) {
    let decision: ReturnType<typeof resolveSupplementaryFriction> | undefined;
    assert.doesNotThrow(() => {
      decision = resolveSupplementaryFriction(input);
    });
    assert.equal(decision?.friction, 'new');
    assert.equal(decision?.blocks, false);
  }
});

/* -------------------------------------------------------------------------- */
/* 7. Additive sibling object — no mutation of identification fields          */
/* -------------------------------------------------------------------------- */

section('7. Additive sibling object');

check('sibling carries no confidence field and optional timestamps only', () => {
  const result = derive(STABLE);
  const sibling = asSupplementaryIdentity(result);
  assert.deepEqual(Object.keys(sibling).sort(), ['visitor_found', 'visitor_id']);
  assert.equal(sibling.visitor_id, result.visitor_id);
  assert.equal(sibling.visitor_found, true);
  assert.ok(!Object.prototype.hasOwnProperty.call(sibling, 'confidence'));
  const stamped = asSupplementaryIdentity(result, { first_seen_at: '2026-11-24T00:00:00Z', last_seen_at: '2026-11-24T01:00:00Z' });
  assert.equal(stamped.first_seen_at, '2026-11-24T00:00:00Z');
  assert.equal(stamped.last_seen_at, '2026-11-24T01:00:00Z');
});

check('a hostile confidence field on the result is never copied into the sibling', () => {
  const hostile = { ...derive(STABLE), confidence: 0.99 } as SupplementaryHighRecallResult;
  const sibling = asSupplementaryIdentity(hostile);
  assert.ok(!Object.prototype.hasOwnProperty.call(sibling, 'confidence'));
  assert.deepEqual(Object.keys(sibling).sort(), ['visitor_found', 'visitor_id']);
});

check('attaching the sibling never mutates existing identification fields', () => {
  const identification = Object.freeze({
    visitor_id: 'PRIMARY-AUTHORITATIVE',
    identification: { confidence: { score: 0.9, version: 'v2' }, visitor_found: true },
    identity_layers: { visitor_id: 'PRIMARY-AUTHORITATIVE', match_mode: 'hardware' },
  });
  const before = JSON.stringify(identification);
  const sibling = asSupplementaryIdentity(derive(STABLE));
  const merged = withSupplementaryHighRecall(identification, sibling);
  assert.equal(JSON.stringify(identification), before, 'input must stay untouched');
  assert.equal(merged.visitor_id, 'PRIMARY-AUTHORITATIVE');
  assert.deepEqual(merged.identification, identification.identification);
  assert.deepEqual(merged.identity_layers, identification.identity_layers);
  assert.deepEqual(merged.supplementary_high_recall, sibling);
  assert.notEqual(merged, identification);
});

check('no sibling is attached when no HR candidate was derived', () => {
  const merged = withSupplementaryHighRecall({ visitor_id: 'PRIMARY' }, asSupplementaryIdentity(derive({})));
  assert.deepEqual(Object.keys(merged), ['visitor_id']);
  assert.ok(!Object.prototype.hasOwnProperty.call(merged, 'supplementary_high_recall'));
});

check('the sibling never replaces the primary id', () => {
  const merged = withSupplementaryHighRecall({ visitor_id: 'PRIMARY-20-CHARS' }, asSupplementaryIdentity(derive(STABLE)));
  assert.equal(merged.visitor_id, 'PRIMARY-20-CHARS');
  assert.notEqual(merged.supplementary_high_recall?.visitor_id, merged.visitor_id);
  assert.equal(merged.supplementary_high_recall?.visitor_found, true);
});

check('HighRecallInput is a canonical, whitelisted shape', () => {
  const input: HighRecallInput = buildHighRecallInput(STABLE);
  assert.deepEqual(Object.keys(input).sort(), ['key_version', 'pepper', 'values']);
  for (const key of Object.keys(input.values)) assert.ok(HIGH_RECALL_STABLE_FIELDS.includes(key));
  assert.deepEqual(Object.keys(input.values), Object.keys(input.values).sort());
});

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}

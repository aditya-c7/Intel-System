/**
 * Benchmark-15 automated regression harness — SHADOW-OFFLINE.
 *
 *   npx tsx scripts/test-benchmark15.ts
 *
 * Drives the 15 frozen scenarios in scripts/fixtures/benchmark15.json against the
 * pure, already-in-repo SHADOW helper modules only. No live requests, no browser,
 * no deploy, no writes, no timers, no randomness: the only I/O is reading the
 * frozen fixture files. Each case reports PASS / FAIL / SKIP, with an explicit
 * reason whenever a helper module or helper function is missing. The final
 * RESULT line summarizes cases, checks and field assertions; any FAIL **or SKIP**
 * makes the process exit non-zero (a skipped assertion is not a green build).
 * A second frozen fixture, scripts/fixtures/gemini-exit-gate.json, pins the locked
 * Gemini wave constraints (0-10 score, uncalibrated, "Match evidence" prefix,
 * zero new panels / third-party SDKs / alarms, no auto-deploy) using the same
 * field-assertion engine.
 *
 * The expectations in the fixture are golden. Never edit an expected value to
 * make a failing case green — fix the implementation instead.
 */

import { readFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';

/* -------------------------------------------------------------------------- */
/* Fixture types                                                                */
/* -------------------------------------------------------------------------- */

interface FieldExpectation {
  /** Dotted path into the helper result; '' means the whole result. */
  path?: string;
  op: string;
  value?: unknown;
}

interface CheckDefinition {
  id: string;
  helper: string;
  fn: string;
  /** Literal values or placeholders: { "$input": "key" } / { "$result": "check-id" }. */
  args: unknown[];
  fields: FieldExpectation[];
}

interface CaseDefinition {
  id: string;
  name: string;
  scenario: string;
  input: Record<string, unknown>;
  expected: CheckDefinition[];
}

interface Fixture {
  schema_version: number;
  frozen: boolean;
  helper_modules: Record<string, string>;
  cases: CaseDefinition[];
}

/** Frozen contract pinned by scripts/fixtures/gemini-exit-gate.json. */
interface GeminiExitGateFixture {
  schema_version: number;
  frozen: boolean;
  description?: string;
  gate: {
    score: number;
    calibration_status: string;
    confidence_label_prefix: string;
    new_panel_count: number;
    third_party_sdk_count: number;
    do_alarm_count: number;
    auto_deploy: boolean;
  };
}

/* -------------------------------------------------------------------------- */
/* Helper registry — lazy dynamic imports so a missing helper ⇒ SKIP, not crash */
/* -------------------------------------------------------------------------- */

interface HelperDefinition {
  /** Path relative to this script. */
  modulePath: string;
  functions: readonly string[];
}

const HELPERS: Readonly<Record<string, HelperDefinition>> = Object.freeze({
  proxyTruth: Object.freeze({
    modulePath: '../src/lib/proxyTruth.ts',
    functions: Object.freeze(['resolveProxyDetails', 'proxyDetailsParityIssue']),
  }),
  vpnMethods: Object.freeze({
    modulePath: '../src/lib/vpnMethods.ts',
    functions: Object.freeze(['resolveVpnMethods', 'vpnMethodsParityIssue']),
  }),
  privacySignatures: Object.freeze({
    modulePath: '../src/lib/privacySignatures.ts',
    functions: Object.freeze(['resolvePrivacySignatures']),
  }),
  stealthSignals: Object.freeze({
    modulePath: '../src/lib/stealthSignals.ts',
    functions: Object.freeze(['evaluateStealthSignals']),
  }),
  tamperingLies: Object.freeze({
    modulePath: '../src/lib/tamperingLies.ts',
    functions: Object.freeze(['resolveTamperingLies']),
  }),
  hexProximity: Object.freeze({
    modulePath: '../src/lib/hexProximity.ts',
    functions: Object.freeze(['hexCellId', 'resolvePrecisionTier', 'proximityFromGeolocation']),
  }),
  zeroTrust: Object.freeze({
    modulePath: '../src/lib/zeroTrust.ts',
    functions: Object.freeze(['checkStrictOrigin', 'replayWindowStatus', 'ipReplayRate']),
  }),
  velocityThresholds: Object.freeze({
    modulePath: '../src/lib/velocityThresholds.ts',
    functions: Object.freeze(['highActivityThreshold', 'velocityCap', 'rarityBucket']),
  }),
  idbDurabilityTruth: Object.freeze({
    modulePath: '../src/lib/idbDurabilityTruth.ts',
    functions: Object.freeze(['resolveIdbDurabilityTruth', 'shouldApplyMarkerVeto']),
  }),
  uaNormalizer: Object.freeze({
    modulePath: '../src/shared/normalization/uaNormalizer.ts',
    functions: Object.freeze([
      'normalizeUserAgent',
      'normalizeIdentity',
      'validateUserAgentNormalization',
    ]),
  }),
});

type HelperFn = (...args: unknown[]) => unknown | Promise<unknown>;

interface LoadedHelper {
  module: Record<string, unknown> | null;
  error?: string;
}

const helperCache = new Map<string, LoadedHelper>();

async function loadHelper(name: string): Promise<LoadedHelper> {
  const cached = helperCache.get(name);
  if (cached) return cached;

  const definition = HELPERS[name];
  if (!definition) {
    const loaded: LoadedHelper = {
      module: null,
      error: `helper '${name}' is not registered in the SHADOW helper registry`,
    };
    helperCache.set(name, loaded);
    return loaded;
  }

  try {
    const imported = (await import(new URL(definition.modulePath, import.meta.url).href)) as Record<
      string,
      unknown
    >;
    const loaded: LoadedHelper = { module: imported };
    helperCache.set(name, loaded);
    return loaded;
  } catch (error) {
    const loaded: LoadedHelper = {
      module: null,
      error: `helper module '${name}' (${definition.modulePath}) could not be imported: ${describe(error)}`,
    };
    helperCache.set(name, loaded);
    return loaded;
  }
}

/** Returns the function, or an explicit SKIP reason when the helper is missing. */
async function resolveHelperFunction(
  name: string,
  fnName: string,
): Promise<{ fn: HelperFn | null; reason?: string }> {
  const loaded = await loadHelper(name);
  if (!loaded.module) return { fn: null, reason: loaded.error };
  const candidate = loaded.module[fnName];
  if (typeof candidate !== 'function') {
    return { fn: null, reason: `helper '${name}.${fnName}' is missing (module exports no such function)` };
  }
  return { fn: candidate as HelperFn };
}

/* -------------------------------------------------------------------------- */
/* Reporting                                                                    */
/* -------------------------------------------------------------------------- */

const counters = {
  casesPass: 0,
  casesFail: 0,
  casesSkip: 0,
  checksPass: 0,
  checksFail: 0,
  checksSkip: 0,
  fieldsPass: 0,
  fieldsFail: 0,
};

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function fmt(value: unknown): string {
  try {
    const text = JSON.stringify(value);
    return text === undefined ? String(value) : text;
  } catch {
    return String(value);
  }
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

/* -------------------------------------------------------------------------- */
/* Frozen fixture loading                                                       */
/* -------------------------------------------------------------------------- */

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

async function loadFixture(): Promise<Fixture> {
  const url = new URL('./fixtures/benchmark15.json', import.meta.url);
  const raw = await readFile(url, 'utf8');
  const parsed = JSON.parse(raw) as Fixture;
  if (!parsed || !Array.isArray(parsed.cases)) {
    throw new Error('fixture is malformed: cases must be an array');
  }
  return deepFreeze(parsed);
}

async function loadGeminiExitGate(): Promise<GeminiExitGateFixture> {
  const url = new URL('./fixtures/gemini-exit-gate.json', import.meta.url);
  const parsed = JSON.parse(await readFile(url, 'utf8')) as GeminiExitGateFixture;
  if (!parsed || typeof parsed !== 'object' || !parsed.gate || typeof parsed.gate !== 'object') {
    throw new Error('gemini exit gate fixture is malformed: gate must be an object');
  }
  const actualKeys = Object.keys(parsed.gate).sort();
  const expectedKeys = [...GEMINI_GATE_KEYS].sort();
  if (!isDeepStrictEqual(actualKeys, expectedKeys)) {
    throw new Error(
      `gemini exit gate key drift: missing=${fmt(expectedKeys.filter((k) => !actualKeys.includes(k)))} ` +
        `extra=${fmt(actualKeys.filter((k) => !expectedKeys.includes(k)))}`,
    );
  }
  return deepFreeze(parsed);
}

const EXPECTED_SCENARIOS: readonly string[] = Object.freeze([
  'standard_browsers',
  'incognito',
  'cross_browser',
  'good_bot',
  'spoofed_bot',
  'stealth_frameworks',
  'devtools',
  'os_spoof',
  'noise_injection',
  'privacy_hardened',
  'vpn_mismatch',
  'vpn_matching_tz',
  'proxy_classification',
  'swiftshader_vs_vm',
  'replay_zero_trust',
]);

/** Exact frozen key set of the Gemini exit gate — extra keys are contract drift. */
const GEMINI_GATE_KEYS: readonly string[] = Object.freeze([
  'auto_deploy',
  'calibration_status',
  'confidence_label_prefix',
  'do_alarm_count',
  'new_panel_count',
  'score',
  'third_party_sdk_count',
]);

interface GateExpectation {
  path: string;
  label: string;
  op: string;
  value?: unknown;
}

const GEMINI_GATE_EXPECTATIONS: readonly GateExpectation[] = Object.freeze([
  { path: 'schema_version', label: 'schema_version is 1', op: 'eq', value: 1 },
  { path: 'frozen', label: 'fixture is frozen', op: 'true' },
  // gte/lte also reject non-numeric values: Number(NaN) fails both comparisons.
  { path: 'gate.score', label: 'score is a number >= 0', op: 'gte', value: 0 },
  { path: 'gate.score', label: 'score is a number <= 10', op: 'lte', value: 10 },
  { path: 'gate.calibration_status', label: 'calibration_status is uncalibrated', op: 'eq', value: 'uncalibrated' },
  { path: 'gate.confidence_label_prefix', label: 'confidence label uses the "Match evidence" prefix', op: 'matches', value: '^Match evidence' },
  { path: 'gate.new_panel_count', label: 'new_panel_count is 0', op: 'eq', value: 0 },
  { path: 'gate.third_party_sdk_count', label: 'third_party_sdk_count is 0', op: 'eq', value: 0 },
  { path: 'gate.do_alarm_count', label: 'do_alarm_count is 0', op: 'eq', value: 0 },
  { path: 'gate.auto_deploy', label: 'auto_deploy is false', op: 'false' },
]);

function validateFixture(fixture: Fixture): string[] {
  const problems: string[] = [];
  if (fixture.schema_version !== 1) problems.push(`unexpected schema_version ${fixture.schema_version}`);
  if (fixture.frozen !== true) problems.push('fixture is not marked frozen');

  const scenarios = fixture.cases.map((testCase) => testCase.scenario);
  const expected = [...EXPECTED_SCENARIOS].sort();
  if (!isDeepStrictEqual([...scenarios].sort(), expected)) {
    problems.push(
      `scenario set mismatch: missing=${fmt(expected.filter((s) => !scenarios.includes(s)))} extra=${fmt(scenarios.filter((s) => !EXPECTED_SCENARIOS.includes(s)))}`,
    );
  }
  if (fixture.cases.length !== 15) problems.push(`expected 15 cases, found ${fixture.cases.length}`);

  const ids = new Set<string>();
  for (const testCase of fixture.cases) {
    if (!testCase.id || !testCase.name || !testCase.scenario) {
      problems.push(`case ${fmt(testCase.id)} is missing id/name/scenario`);
    }
    if (ids.has(testCase.id)) problems.push(`duplicate case id ${testCase.id}`);
    ids.add(testCase.id);
    if (!testCase.input || typeof testCase.input !== 'object') {
      problems.push(`case ${testCase.id} has no input object`);
    }
    if (!Array.isArray(testCase.expected) || testCase.expected.length === 0) {
      problems.push(`case ${testCase.id} has no expected checks`);
    }
    const checkIds = new Set<string>();
    for (const check of testCase.expected ?? []) {
      if (checkIds.has(check.id)) problems.push(`duplicate check id ${check.id} in case ${testCase.id}`);
      checkIds.add(check.id);
      if (!check.helper || !check.fn || !Array.isArray(check.args) || !Array.isArray(check.fields)) {
        problems.push(`check ${check.id} in case ${testCase.id} is malformed`);
      }
    }
  }
  return problems;
}

/* -------------------------------------------------------------------------- */
/* Declarative argument + expectation evaluation                                 */
/* -------------------------------------------------------------------------- */

function readDotted(source: unknown, dotted: string): { found: boolean; value: unknown } {
  if (!dotted) return { found: true, value: source };
  let current: unknown = source;
  for (const key of dotted.split('.')) {
    if (current === null || current === undefined) return { found: false, value: undefined };
    try {
      if (!Object.prototype.hasOwnProperty.call(Object(current), key)) {
        return { found: false, value: undefined };
      }
      current = (current as Record<string, unknown>)[key];
    } catch {
      return { found: false, value: undefined };
    }
  }
  return { found: true, value: current };
}

function isPlaceholder(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) &&
    ('$input' in (value as Record<string, unknown>) || '$result' in (value as Record<string, unknown>));
}

interface ArgsResult {
  args?: unknown[];
  error?: string;
}

function resolveArgs(
  rawArgs: unknown[],
  input: Record<string, unknown>,
  results: Map<string, unknown>,
): ArgsResult {
  const args: unknown[] = [];
  for (const raw of rawArgs) {
    if (!isPlaceholder(raw)) {
      args.push(raw);
      continue;
    }
    if ('$input' in raw) {
      const key = String(raw.$input);
      const resolved = readDotted(input, key);
      if (!resolved.found) return { error: `fixture error: input key '${key}' is missing` };
      args.push(resolved.value);
      continue;
    }
    const checkId = String(raw.$result);
    if (!results.has(checkId)) {
      return { error: `fixture error: referenced check result '${checkId}' is unavailable` };
    }
    args.push(results.get(checkId));
  }
  return { args };
}

interface FieldResult {
  ok: boolean;
  detail: string;
}

/**
 * Membership for both scalars and arrays. String entries in an array also match a
 * substring, mirroring how the repo's suites assert on `reasons[].includes('...')`.
 */
function includesValue(actual: unknown, value: unknown): boolean {
  if (Array.isArray(actual)) {
    return actual.some(
      (item) =>
        isDeepStrictEqual(item, value) ||
        (typeof item === 'string' && typeof value === 'string' && item.includes(value)),
    );
  }
  return typeof actual === 'string' && typeof value === 'string' && actual.includes(value);
}

function evalField(
  actual: unknown,
  expectation: FieldExpectation,
  results: Map<string, unknown>,
): FieldResult {
  const path = expectation.path ?? '';
  const shown = path ? `field '${path}'` : 'result';
  const op = expectation.op;
  const value = expectation.value;
  const pass = (): FieldResult => ({ ok: true, detail: `${shown} ${op} OK` });
  const fail = (detail: string): FieldResult => ({ ok: false, detail: `${shown}: ${detail}` });

  switch (op) {
    case 'eq':
      return isDeepStrictEqual(actual, value)
        ? pass()
        : fail(`expected ${fmt(value)}, got ${fmt(actual)}`);
    case 'neq':
      return !isDeepStrictEqual(actual, value)
        ? pass()
        : fail(`expected value != ${fmt(value)}, got ${fmt(actual)}`);
    case 'true':
      return actual === true ? pass() : fail(`expected true, got ${fmt(actual)}`);
    case 'false':
      return actual === false ? pass() : fail(`expected false, got ${fmt(actual)}`);
    case 'null':
      return actual === null ? pass() : fail(`expected null, got ${fmt(actual)}`);
    case 'nonEmpty':
      return (typeof actual === 'string' || Array.isArray(actual)) && actual.length > 0
        ? pass()
        : fail(`expected a non-empty string/array, got ${fmt(actual)}`);
    case 'lengthEq':
      return typeof (actual as { length?: unknown })?.length === 'number' &&
        (actual as { length: number }).length === value
        ? pass()
        : fail(`expected length ${fmt(value)}, got ${fmt((actual as { length?: unknown })?.length)}`);
    case 'includes': {
      return includesValue(actual, value)
        ? pass()
        : fail(`expected ${fmt(actual)} to include ${fmt(value)}`);
    }
    case 'notIncludes': {
      return includesValue(actual, value)
        ? fail(`expected ${fmt(actual)} NOT to include ${fmt(value)}`)
        : pass();
    }
    case 'matches': {
      let regex: RegExp;
      try {
        regex = new RegExp(String(value));
      } catch (error) {
        return fail(`invalid expected regex ${fmt(value)}: ${describe(error)}`);
      }
      return typeof actual === 'string' && regex.test(actual)
        ? pass()
        : fail(`expected ${fmt(actual)} to match /${String(value)}/`);
    }
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      const numeric = typeof actual === 'number' ? actual : Number.NaN;
      const target = Number(value);
      const ok =
        op === 'gt' ? numeric > target :
        op === 'gte' ? numeric >= target :
        op === 'lt' ? numeric < target :
        numeric <= target;
      return ok ? pass() : fail(`expected ${op} ${fmt(value)}, got ${fmt(actual)}`);
    }
    case 'eqResult': {
      const ref = value as { result: string; path?: string } | null;
      if (!ref || typeof ref.result !== 'string' || !results.has(ref.result)) {
        return fail(`referenced check result ${fmt(value)} is unavailable`);
      }
      const prior = readDotted(results.get(ref.result), ref.path ?? '');
      if (!prior.found) {
        return fail(`referenced check '${ref.result}' has no field '${fmt(ref.path)}'`);
      }
      return isDeepStrictEqual(actual, prior.value)
        ? pass()
        : fail(`expected ${fmt(prior.value)} (from check '${ref.result}'), got ${fmt(actual)}`);
    }
    default:
      return fail(`unsupported expectation operator '${op}'`);
  }
}

/* -------------------------------------------------------------------------- */
/* Runner                                                                       */
/* -------------------------------------------------------------------------- */

async function runCase(testCase: CaseDefinition): Promise<void> {
  const results = new Map<string, unknown>();
  const problems: string[] = [];
  let checksPass = 0;
  let checksFail = 0;
  let checksSkip = 0;

  section(`CASE ${testCase.id} | ${testCase.name} (scenario: ${testCase.scenario})`);
  const inputDigest = fmt(testCase.input);
  console.log(`  input: ${inputDigest.length > 260 ? `${inputDigest.slice(0, 260)}...` : inputDigest}`);
  console.log(`  expected: ${testCase.expected.length} checks / ${testCase.expected.reduce((n, c) => n + c.fields.length, 0)} fields`);

  for (const check of testCase.expected) {
    const { fn, reason } = await resolveHelperFunction(check.helper, check.fn);
    if (!fn) {
      checksSkip += 1;
      const message = `SKIP  [${check.id}] helper '${check.helper}.${check.fn}' missing: ${reason}`;
      problems.push(message);
      console.log(`  ${message}`);
      continue;
    }

    const resolved = resolveArgs(check.args, testCase.input, results);
    if (!resolved.args) {
      checksFail += 1;
      const message = `FAIL  [${check.id}] ${resolved.error}`;
      problems.push(message);
      console.log(`  ${message}`);
      continue;
    }

    let result: unknown;
    try {
      result = await fn(...resolved.args);
    } catch (error) {
      checksFail += 1;
      const message = `FAIL  [${check.id}] helper threw: ${describe(error)}`;
      problems.push(message);
      console.log(`  ${message}`);
      continue;
    }
    results.set(check.id, result);

    const fieldProblems: string[] = [];
    for (const expectation of check.fields) {
      let actual: unknown;
      try {
        actual = readDotted(result, expectation.path ?? '').value;
      } catch (error) {
        fieldProblems.push(`FAIL  [${check.id}] field '${expectation.path}' unreadable: ${describe(error)}`);
        continue;
      }
      const evaluated = evalField(actual, expectation, results);
      if (evaluated.ok) {
        counters.fieldsPass += 1;
      } else {
        counters.fieldsFail += 1;
        fieldProblems.push(`FAIL  [${check.id}] ${evaluated.detail}`);
      }
    }

    if (fieldProblems.length > 0) {
      checksFail += 1;
      problems.push(...fieldProblems);
      for (const problem of fieldProblems) console.log(`  ${problem}`);
    } else {
      checksPass += 1;
      console.log(`  ok    [${check.id}] ${check.helper}.${check.fn} — ${check.fields.length} field(s) verified`);
    }
  }

  const status: 'PASS' | 'FAIL' | 'SKIP' =
    checksFail > 0 ? 'FAIL' : checksSkip > 0 ? 'SKIP' : 'PASS';

  if (status === 'PASS') counters.casesPass += 1;
  else if (status === 'FAIL') counters.casesFail += 1;
  else counters.casesSkip += 1;
  counters.checksPass += checksPass;
  counters.checksFail += checksFail;
  counters.checksSkip += checksSkip;

  console.log(`  ${status}  [${testCase.id}] ${testCase.name} — ${checksPass}/${testCase.expected.length} checks passed` +
    (checksSkip > 0 ? `, ${checksSkip} skipped` : '') +
    (checksFail > 0 ? `, ${checksFail} failed` : ''));
}

/** Verifies every frozen Gemini exit-gate constraint through the shared field engine. */
function runGeminiExitGate(gate: GeminiExitGateFixture): void {
  section('GEMINI EXIT GATE (frozen lock constraints)');
  const results = new Map<string, unknown>();
  let pass = 0;
  let fail = 0;
  for (const expectation of GEMINI_GATE_EXPECTATIONS) {
    const actual = readDotted(gate, expectation.path).value;
    const evaluated = evalField(
      actual,
      { path: expectation.path, op: expectation.op, value: expectation.value },
      results,
    );
    if (evaluated.ok) {
      pass += 1;
      counters.fieldsPass += 1;
      console.log(`  ok    [gemini-gate] ${expectation.label}`);
    } else {
      fail += 1;
      counters.fieldsFail += 1;
      console.log(`  FAIL  [gemini-gate] ${expectation.label}: ${evaluated.detail}`);
    }
  }
  if (fail === 0) counters.checksPass += 1;
  else counters.checksFail += 1;
  console.log(
    `  ${fail === 0 ? 'PASS' : 'FAIL'}  [gemini-gate] ${pass}/${GEMINI_GATE_EXPECTATIONS.length} lock constraints verified`,
  );
}

async function run(): Promise<void> {
  const fixture = await loadFixture();
  const problems = validateFixture(fixture);
  if (problems.length > 0) {
    for (const problem of problems) console.error(`FAIL  [fixture] ${problem}`);
    throw new Error(`fixture validation failed with ${problems.length} problem(s)`);
  }

  console.log('BENCHMARK-15 — SHADOW-OFFLINE regression harness');
  console.log(`fixture: scripts/fixtures/benchmark15.json (frozen=${fixture.frozen}, offline=true)`);
  console.log(`cases: ${fixture.cases.length}; helper modules: ${Object.keys(HELPERS).length}`);
  console.log('policy: pure helpers only — no live requests, browser, deploy, timers or writes.');

  const gate = await loadGeminiExitGate();
  console.log(`gemini exit gate: scripts/fixtures/gemini-exit-gate.json (frozen=${gate.frozen})`);

  for (const testCase of fixture.cases) {
    await runCase(testCase);
  }
  runGeminiExitGate(gate);
}

/* -------------------------------------------------------------------------- */

let fatal = false;
try {
  await run();
} catch (error) {
  fatal = true;
  console.error(`FAIL  [fatal] ${describe(error)}`);
} finally {
  const totalCases = counters.casesPass + counters.casesFail + counters.casesSkip;
  const totalChecks = counters.checksPass + counters.checksFail + counters.checksSkip;
  const totalFields = counters.fieldsPass + counters.fieldsFail;
  const executedChecks = counters.checksPass + counters.checksFail;
  // Pass-with-no-tests is banned: at least one check AND one field must actually execute.
  const noTestsExecuted = executedChecks === 0 || totalFields === 0 || totalCases === 0;
  // A SKIP is not a green build: any skipped case or check fails this gate.
  const failed =
    fatal ||
    noTestsExecuted ||
    counters.casesFail > 0 ||
    counters.checksFail > 0 ||
    counters.fieldsFail > 0 ||
    counters.casesSkip > 0 ||
    counters.checksSkip > 0;

  section('RESULT');
  console.log(`Cases:  ${totalCases} total — ${counters.casesPass} PASS, ${counters.casesFail} FAIL, ${counters.casesSkip} SKIP`);
  console.log(`Checks: ${totalChecks} total — ${counters.checksPass} PASS, ${counters.checksFail} FAIL, ${counters.checksSkip} SKIP`);
  console.log(`Fields: ${totalFields} total — ${counters.fieldsPass} PASS, ${counters.fieldsFail} FAIL`);
  if (failed) {
    const reasons: string[] = [];
    if (fatal) reasons.push('fatal error');
    if (counters.casesFail) reasons.push(`${counters.casesFail} failed case(s)`);
    if (counters.checksFail) reasons.push(`${counters.checksFail} failed check(s)`);
    if (counters.fieldsFail) reasons.push(`${counters.fieldsFail} failed field assertion(s)`);
    if (counters.casesSkip) reasons.push(`${counters.casesSkip} skipped case(s)`);
    if (counters.checksSkip) reasons.push(`${counters.checksSkip} skipped check(s)`);
    console.log(`RESULT: FAIL — ${reasons.join(', ')} (SKIP is treated as FAIL here)`);
    process.exitCode = 1;
  } else {
    console.log('RESULT: PASS — all 15 SHADOW-OFFLINE benchmark scenarios green');
  }
}

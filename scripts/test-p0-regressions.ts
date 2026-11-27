/**
 * P0 benchmark-defect regression harness — SHADOW-OFFLINE.
 *
 *   npx tsx scripts/test-p0-regressions.ts
 *
 * Drives the five frozen P0 defect scenarios in scripts/fixtures/p0-regressions.json
 * against the pure, already-in-repo helper modules only. No live requests, no browser,
 * no deploy, no writes, no timers, no randomness: the only I/O is reading the frozen
 * fixture file. Each case reports PASS / FAIL / SKIP, with an explicit reason whenever
 * a helper module or helper function is missing. The final RESULT line summarizes
 * cases, checks and field assertions; any FAIL makes the process exit non-zero.
 *
 * The expectations in the fixture are golden. Never edit an expected value to
 * make a failing case green — fix the implementation instead.
 */

import { readFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';

/* Static imports for the direct wiring-regression section (runWiringRegressions).
 * The fixture-driven cases keep their lazy helper registry below. */
import { composeBotVerdict } from '../src/server/agents/botVerifier';
import { buildGradedRiskLedger } from '../src/lib/riskLedger';
import { enrichNetwork } from '../src/server/network/asnEnricher';

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
  title: string;
  generated_on: string;
  frozen: boolean;
  offline: boolean;
  helper_modules: Record<string, string>;
  cases: CaseDefinition[];
}

/* -------------------------------------------------------------------------- */
/* Helper registry — lazy dynamic imports so a missing helper ⇒ SKIP, not crash  */
/* -------------------------------------------------------------------------- */

interface HelperDefinition {
  /** Path relative to this script. */
  modulePath: string;
  functions: readonly string[];
}

const HELPERS: Readonly<Record<string, HelperDefinition>> = Object.freeze({
  idbDurabilityTruth: Object.freeze({
    modulePath: '../src/lib/idbDurabilityTruth.ts',
    functions: Object.freeze(['resolveIdbDurabilityTruth', 'shouldApplyMarkerVeto']),
  }),
  botVerifier: Object.freeze({
    modulePath: '../src/server/agents/botVerifier.ts',
    functions: Object.freeze(['classifyReasonId', 'gateAgentReasons', 'composeBotVerdict']),
  }),
  verdict: Object.freeze({
    modulePath: '../src/lib/verdict.ts',
    functions: Object.freeze(['gateAutomationEvidence']),
  }),
  uaNormalizer: Object.freeze({
    modulePath: '../src/shared/normalization/uaNormalizer.ts',
    functions: Object.freeze(['normalizeUserAgent', 'validateUserAgentNormalization']),
  }),
  specInvariants: Object.freeze({
    modulePath: '../src/lib/specInvariants.ts',
    functions: Object.freeze([
      'canonicalInspectorFlags',
      'inspectorFlagsForState',
      'checkInspectorInvariants',
    ]),
  }),
  confidenceScorer: Object.freeze({
    modulePath: '../src/server/identity/confidenceScorer.ts',
    functions: Object.freeze(['scoreConfidence']),
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
      error: `helper '${name}' is not registered in the P0 helper registry`,
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
  if (!loaded.module || typeof candidate !== 'function') {
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
  const url = new URL('./fixtures/p0-regressions.json', import.meta.url);
  const raw = await readFile(url, 'utf8');
  const parsed = JSON.parse(raw) as Fixture;
  if (!parsed || !Array.isArray(parsed.cases)) {
    throw new Error('fixture is malformed: cases must be an array');
  }
  return deepFreeze(parsed);
}

const EXPECTED_SCENARIOS: readonly string[] = Object.freeze([
  'incognito_cookie_clear',
  'headful_cdp_webdriver',
  'forged_uach_major',
  'cdp_devtools_flag_asymmetry',
  'spoofed_crawler_identity',
]);

function validateFixture(fixture: Fixture): string[] {
  const problems: string[] = [];
  if (fixture.schema_version !== 1) problems.push(`unexpected schema_version ${fixture.schema_version}`);
  if (fixture.frozen !== true) problems.push('fixture is not marked frozen');
  if (fixture.offline !== true) problems.push('fixture is not marked offline');

  const scenarios = fixture.cases.map((testCase) => testCase.scenario);
  const expected = [...EXPECTED_SCENARIOS].sort();
  if (!isDeepStrictEqual([...scenarios].sort(), expected)) {
    problems.push(
      `scenario set mismatch: missing=${fmt(expected.filter((s) => !scenarios.includes(s)))} extra=${fmt(scenarios.filter((s) => !EXPECTED_SCENARIOS.includes(s)))}`,
    );
  }
  if (fixture.cases.length !== 5) problems.push(`expected 5 cases, found ${fixture.cases.length}`);

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

/**
 * Recursively resolve placeholders so a check can build a helper input object from
 * several frozen fixture fields (e.g. an IncognitoDiagnostics-shaped snapshot).
 */
function resolveValue(
  raw: unknown,
  input: Record<string, unknown>,
  results: Map<string, unknown>,
): { ok: true; value: unknown } | { ok: false; error: string } {
  if (isPlaceholder(raw)) {
    if ('$input' in raw) {
      const key = String(raw.$input);
      const resolved = readDotted(input, key);
      if (!resolved.found) return { ok: false, error: `fixture error: input key '${key}' is missing` };
      return { ok: true, value: resolved.value };
    }
    const checkId = String(raw.$result);
    if (!results.has(checkId)) {
      return { ok: false, error: `fixture error: referenced check result '${checkId}' is unavailable` };
    }
    const path = typeof raw.path === 'string' ? raw.path : '';
    const resolved = readDotted(results.get(checkId), path);
    if (!resolved.found) {
      return { ok: false, error: `fixture error: referenced check '${checkId}' has no field '${path}'` };
    }
    return { ok: true, value: resolved.value };
  }
  if (Array.isArray(raw)) {
    const out: unknown[] = [];
    for (const item of raw) {
      const resolved = resolveValue(item, input, results);
      if (!resolved.ok) return resolved;
      out.push(resolved.value);
    }
    return { ok: true, value: out };
  }
  if (raw && typeof raw === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(raw as Record<string, unknown>)) {
      const resolved = resolveValue(item, input, results);
      if (!resolved.ok) return resolved;
      out[key] = resolved.value;
    }
    return { ok: true, value: out };
  }
  return { ok: true, value: raw };
}

function resolveArgs(
  rawArgs: unknown[],
  input: Record<string, unknown>,
  results: Map<string, unknown>,
): ArgsResult {
  const args: unknown[] = [];
  for (const raw of rawArgs) {
    const resolved = resolveValue(raw, input, results);
    if (!resolved.ok) return { error: resolved.error };
    args.push(resolved.value);
  }
  return { args };
}

/** Membership for both scalars and arrays, mirroring the repo's suite conventions. */
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

interface FieldResult {
  ok: boolean;
  detail: string;
}

function evalField(actual: unknown, expectation: FieldExpectation): FieldResult {
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
    case 'includes':
      return includesValue(actual, value)
        ? pass()
        : fail(`expected ${fmt(actual)} to include ${fmt(value)}`);
    case 'notIncludes':
      return includesValue(actual, value)
        ? fail(`expected ${fmt(actual)} NOT to include ${fmt(value)}`)
        : pass();
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
      const evaluated = evalField(actual, expectation);
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

async function run(): Promise<void> {
  const fixture = await loadFixture();
  const problems = validateFixture(fixture);
  if (problems.length > 0) {
    for (const problem of problems) console.error(`FAIL  [fixture] ${problem}`);
    throw new Error(`fixture validation failed with ${problems.length} problem(s)`);
  }

  console.log('P0-REGRESSIONS — SHADOW-OFFLINE regression harness');
  console.log(`fixture: scripts/fixtures/p0-regressions.json (frozen=${fixture.frozen}, offline=${fixture.offline}, generated_on=${fixture.generated_on})`);
  console.log(`cases: ${fixture.cases.length}; helper modules: ${Object.keys(HELPERS).length}`);
  console.log('policy: pure helpers only — no live requests, browser, deploy, timers or writes.');

  for (const testCase of fixture.cases) {
    await runCase(testCase);
  }

  await runWiringRegressions();
}

/* -------------------------------------------------------------------------- */
/* Wiring regressions — direct pins for server-side wiring (not fixture-driven) */
/*                                                                              */
/* The identify handler is a monolithic server script and cannot be imported    */
/* here, so these checks pin the CONTRACTS the handler must satisfy: the        */
/* composeBotVerdict stealth/clientProbe inputs the handler now threads, the    */
/* graded-ledger signed-agent exemption the handler must supply, and the        */
/* enrichNetwork edge tier the handler must feed with the edge organization.    */
/* The enrichNetwork edge tier performs no I/O (ASN + org short-circuit), and    */
/* the registry-tier negative case resolves in-process without DNS.             */
/* -------------------------------------------------------------------------- */

let wiringChecks = 0;
let wiringFailures = 0;

function wiringCheck(name: string, condition: boolean, detail?: unknown): void {
  wiringChecks += 1;
  if (condition) {
    console.log(`  ok    [wiring] ${name}`);
    return;
  }
  wiringFailures += 1;
  console.error(`  FAIL  [wiring] ${name}`);
  if (detail !== undefined) console.error('     ', fmt(detail));
}

async function runWiringRegressions(): Promise<void> {
  section('WIRING REGRESSIONS — stealth escalation / signed-agent precedence / ASN org hint');

  /* 1 — stealth-input wiring: a non-empty hard stealth tier with NO WBA verification     */
  /*     escalates the composed verdict to bad/automated-runtime (the handler maps this   */
  /*     to bad / stealth_automation and automation tier A).                              */
  const hardStealth = {
    detected: true,
    ids: ['documentInterception', 'runtimeEnableLeak'],
    hard: ['documentInterception'],
    confirmed: ['documentInterception'],
  };
  const escalated = composeBotVerdict({ stealth: hardStealth });
  wiringCheck(
    'composed stealth hard tier (no WBA) escalates to bad/automated-runtime',
    escalated.verdict === 'bad' &&
      escalated.reason === 'automated-runtime' &&
      escalated.severity === 'high',
    escalated
  );
  wiringCheck(
    'stealth reasons ride the SAME probe channel (no second taxonomy)',
    escalated.reason_ids.slice(1).includes('stealth.document-interception-protocol') &&
      escalated.reason_ids.slice(1).includes('stealth.runtime-enable-leak'),
    escalated.reason_ids
  );

  /* 2 — verified-agent precedence: the identical stealth evidence CANNOT escalate a      */
  /*     signed-good agent; the composed verdict stays good/signed-agent and ZERO         */
  /*     stealth/automation reasons escape it.                                            */
  const signedGood = composeBotVerdict({
    stealth: hardStealth,
    clientProbe: { verdict: 'agent', reasons: ['bot.playwright-binding'] },
    webBotAuth: {
      verified: true,
      outcome: 'VALID',
      identity: 'signed',
      reason: 'signed-agent',
      category: 'ai_agent',
      bot_id: 'signed-agent-fixture',
    },
  });
  wiringCheck(
    'signed-good agent is never escalated by stealth/clientProbe evidence',
    signedGood.verdict === 'good' && signedGood.reason === 'signed-agent',
    signedGood
  );
  wiringCheck(
    'signed-good verdict publishes exactly [signed-agent] (no stealth reasons leak)',
    signedGood.reason_ids.length === 1 && signedGood.reason_ids[0] === 'signed-agent',
    signedGood.reason_ids
  );

  /* 3 — verified-agent ledger precedence: rfc9421SignedAgent exempts the automation      */
  /*     family even when tier-A hard automation evidence is present.                     */
  const exemptLedger = buildGradedRiskLedger({
    automation: { tierA: true, rfc9421SignedAgent: true },
    network: { vpnOrRelay: true },
    environment: { swiftshader: true, ephemeralOrPrivateStorage: true },
  });
  wiringCheck(
    'rfc9421SignedAgent zeroes the automation family despite tier-A evidence',
    exemptLedger.automation === 0,
    exemptLedger
  );
  wiringCheck(
    'no scored automation component is billed for a signed agent',
    !exemptLedger.evidence_ledger.some(
      (line) => line.family === 'automation' && line.points > 0
    ),
    exemptLedger.evidence_ledger
  );
  const unexemptLedger = buildGradedRiskLedger({ automation: { tierA: true } });
  wiringCheck(
    'without the exemption the automation family still bills tier A (45)',
    unexemptLedger.automation === 45,
    unexemptLedger
  );

  /* 4 — ASN org-hint acceptance: asnEnricher's zero-cost edge tier requires BOTH the     */
  /*     ASN and the organization; the identify/geolocation handlers must forward         */
  /*     `edgeGeo.organization` as asOrganization or the tier never fires.                */
  const edgeEnriched = await enrichNetwork('8.8.8.8', {
    asn: 15169,
    asOrganization: 'Google LLC',
  });
  wiringCheck(
    'enrichNetwork edge tier fires when asOrganization is supplied',
    edgeEnriched.source === 'edge' && edgeEnriched.asn_name === 'Google LLC',
    edgeEnriched
  );
  const asnOnly = await enrichNetwork('8.8.4.4', { asn: 15169 });
  wiringCheck(
    'an ASN without an organization never fabricates the edge tier',
    asnOnly.source !== 'edge',
    asnOnly
  );
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
  const failed =
    fatal ||
    counters.casesFail > 0 ||
    counters.checksFail > 0 ||
    counters.fieldsFail > 0 ||
    wiringFailures > 0;

  section('RESULT');
  console.log(`Cases:  ${totalCases} total — ${counters.casesPass} PASS, ${counters.casesFail} FAIL, ${counters.casesSkip} SKIP`);
  console.log(`Checks: ${totalChecks} total — ${counters.checksPass} PASS, ${counters.checksFail} FAIL, ${counters.checksSkip} SKIP`);
  console.log(`Fields: ${totalFields} total — ${counters.fieldsPass} PASS, ${counters.fieldsFail} FAIL`);
  console.log(`Wiring: ${wiringChecks} checks — ${wiringChecks - wiringFailures} PASS${wiringFailures > 0 ? `, ${wiringFailures} FAIL` : ''}`);
  if (failed) {
    console.log('RESULT: FAIL — P0 regression harness detected failures');
    process.exitCode = 1;
  } else {
    console.log('RESULT: PASS — all 5 P0 defect scenarios green');
  }
}

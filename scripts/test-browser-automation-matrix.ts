/**
 * RS10 browser-automation matrix suite (dependency-free, shadow-only, offline).
 *
 *   npx tsx scripts/test-browser-automation-matrix.ts
 *
 * Drives the frozen scenarios in scripts/fixtures/browser-automation-matrix.json
 * against the pure helper in src/lib/browserAutomationMatrix.ts. No browser, no
 * network, no writes, no timers, no randomness. Covers every stack plus a human
 * control, hostile/wrong-typed inputs (non-throwing), axis separation, CDP weight-0,
 * determinism, and the no-vendor-label guarantee.
 */

import { readFile } from 'node:fs/promises';
import {
  ALL_TELLS,
  AUTOMATION_STACKS,
  HUMAN_STACKS,
  KNOWN_STACKS,
  RS10_RESEARCH,
  TELL_AXIS,
  classifyAutomationConfig,
  validateHumanBaseline,
  type AutomationConfigInput,
  type AutomationConfigVerdict,
  type HumanBaselineInput,
  type HumanBaselineResult,
} from '../src/lib/browserAutomationMatrix.ts';

/* -------------------------------------------------------------------------- */
/* Fixture types                                                               */
/* -------------------------------------------------------------------------- */

interface ClassifyExpectation {
  expected: string;
  axis: string;
  confidence: string;
  tellsInclude: string[];
  reasonsInclude: string[];
}

interface ClassifyCase {
  id: string;
  name: string;
  input: unknown;
  expect: ClassifyExpectation;
}

interface BaselineExpectation {
  valid: boolean;
  falsePositiveRate: number;
  reasonIncludes: string;
  logBeforeEnforce: boolean;
}

interface BaselineCase {
  id: string;
  input: unknown;
  expect: BaselineExpectation;
}

interface Fixture {
  schema_version: number;
  frozen: boolean;
  offline: boolean;
  rules: Record<string, string>;
  research: {
    openWaf: Record<string, unknown>;
    botstopV12: Record<string, unknown>;
    causality: Record<string, string>;
    stealth: Record<string, string>;
  };
  stacks: string[];
  classifyCases: ClassifyCase[];
  baselineCases: BaselineCase[];
}

/* -------------------------------------------------------------------------- */
/* Test harness                                                               */
/* -------------------------------------------------------------------------- */

let passed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail = ''): void {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}${detail ? ` (${detail})` : ''}`);
    return;
  }
  failures.push(name);
  console.log(`  FAIL  ${name}${detail ? ` (${detail})` : ''}`);
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

function noThrow<T>(fn: () => T): T | null {
  try {
    return fn();
  } catch {
    return null;
  }
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function wellFormedVerdict(value: unknown): value is AutomationConfigVerdict {
  if (value === null || typeof value !== 'object') return false;
  const v = value as Partial<AutomationConfigVerdict>;
  const expectedOk = v.expected === 'automated' || v.expected === 'human' || v.expected === 'unknown';
  const axisOk = v.axis === 'automation' || v.axis === 'machine' || v.axis === 'both';
  const confidenceOk = v.confidence === 'high' || v.confidence === 'medium' || v.confidence === 'low';
  const tellsOk = Array.isArray(v.tells) && v.tells.every((t) => typeof t === 'string' && Object.prototype.hasOwnProperty.call(TELL_AXIS, t));
  const reasonsOk = Array.isArray(v.reasons) && v.reasons.every((r) => typeof r === 'string' && r.length > 0);
  return expectedOk && axisOk && confidenceOk && tellsOk && reasonsOk;
}

function wellFormedBaseline(value: unknown): value is HumanBaselineResult {
  if (value === null || typeof value !== 'object') return false;
  const v = value as Partial<HumanBaselineResult>;
  return typeof v.valid === 'boolean' &&
    typeof v.falsePositiveRate === 'number' && Number.isFinite(v.falsePositiveRate) &&
    typeof v.reason === 'string' && v.reason.length > 0;
}

function includesAll(actual: readonly string[], required: readonly string[]): boolean {
  return required.every((item) => actual.includes(item));
}

const fixture = JSON.parse(
  await readFile(new URL('./fixtures/browser-automation-matrix.json', import.meta.url), 'utf8'),
) as Fixture;

/* -------------------------------------------------------------------------- */
/* Fixture integrity + research grounding                                      */
/* -------------------------------------------------------------------------- */
section('fixture integrity and RS10 research grounding');

check('fixture schema_version is 1', fixture.schema_version === 1);
check('fixture is frozen and offline', fixture.frozen === true && fixture.offline === true, `${fixture.frozen}/${fixture.offline}`);
check('fixture declares all 11 stacks', fixture.stacks.length === 11, String(fixture.stacks.length));
check('library allowlist matches fixture stacks', same([...KNOWN_STACKS], fixture.stacks), `${KNOWN_STACKS.length} stacks`);
check('automation allowlist has 10 stacks and human allowlist has 1', AUTOMATION_STACKS.length === 10 && HUMAN_STACKS.length === 1);
check('fixture has >= 20 classify cases', fixture.classifyCases.length >= 20, String(fixture.classifyCases.length));
check('fixture has a human control case', fixture.classifyCases.some((c) => c.expect.expected === 'human' && c.id === 'HUM-CTRL'));
check('every allowlisted stack has a classify case', [...KNOWN_STACKS].every((s) => fixture.classifyCases.some((c) => (c.input as { stack?: unknown } | null)?.stack === s)));
check('OpenWAF lab numbers match the helper constants', same(fixture.research.openWaf, { ...RS10_RESEARCH.openWaf }), 'Chrome 156 / 110 runs');
check('botstop v12 range matches the helper constants', same(fixture.research.botstopV12, { ...RS10_RESEARCH.botstopV12 }), '83-100 automated');
check('causality table matches the helper constants', same(fixture.research.causality, { ...RS10_RESEARCH.causality }));
check('stealth findings match the helper constants', same(fixture.research.stealth, { ...RS10_RESEARCH.stealth }));
check('published human baseline is 0/31 (no flags)', RS10_RESEARCH.openWaf.humans === '0/31 flagged');
check('published botstop v12 verdict is automated', RS10_RESEARCH.botstopV12.verdict === 'automated');
check('teach axis table covers every emitted tell', ALL_TELLS.length === Object.keys(TELL_AXIS).length && ALL_TELLS.length > 20, `${ALL_TELLS.length} tells`);

/* -------------------------------------------------------------------------- */
/* Fixture-driven classification                                               */
/* -------------------------------------------------------------------------- */
section('controlled-config classification (all stacks + controls)');

const verdicts = new Map<string, AutomationConfigVerdict>();
for (const c of fixture.classifyCases) {
  const result = classifyAutomationConfig(c.input as AutomationConfigInput);
  verdicts.set(c.id, result);
  check(`${c.id}: well-formed verdict`, wellFormedVerdict(result));
  check(
    `${c.id}: expected/axis/confidence`,
    result.expected === c.expect.expected && result.axis === c.expect.axis && result.confidence === c.expect.confidence,
    `${result.expected}/${result.axis}/${result.confidence}`,
  );
  check(`${c.id}: required tells present`, includesAll(result.tells, c.expect.tellsInclude), `${result.tells.length} tells`);
  check(`${c.id}: required reasons present`, includesAll(result.reasons, c.expect.reasonsInclude), `${result.reasons.length} reasons`);
}

/* -------------------------------------------------------------------------- */
/* Axis separation: automation tells vs machine tells                          */
/* -------------------------------------------------------------------------- */
section('automation/machine axis separation');

check(
  'every tell carries exactly one axis prefix consistent with TELL_AXIS',
  ALL_TELLS.every((t) => TELL_AXIS[t] === (t.startsWith('machine:') ? 'machine' : 'automation')),
);
check(
  'no tell mixes automation and machine namespaces',
  ALL_TELLS.every((t) => !(t.includes('automation:') && t.includes('machine:'))),
);
check(
  'machine tells are only GPU/fonts/audio/screen/codecs',
  ALL_TELLS.filter((t) => t.startsWith('machine:')).every((t) => /gpu|font|audio|screen|codec/.test(t)),
);
const machineOnly = verdicts.get('MACHINE-ONLY');
check('machine-only case has axis machine', machineOnly?.axis === 'machine', machineOnly?.axis ?? 'missing');
check('machine-only case emits no automation tells', (machineOnly?.tells ?? []).every((t) => !t.startsWith('automation:')));
const humanControl = verdicts.get('HUM-CTRL');
check('human control emits no machine tells', (humanControl?.tells ?? []).every((t) => !t.startsWith('machine:')));
const bothAxes = verdicts.get('AUT-PW');
check('AUT-PW reports both axes', bothAxes?.axis === 'both');
check(
  'both-axes case actually contains both tell kinds',
  (bothAxes?.tells ?? []).some((t) => t.startsWith('automation:')) && (bothAxes?.tells ?? []).some((t) => t.startsWith('machine:')),
);
check(
  '--disable-component-extensions maps to the audio/machine tell, not an automation tell',
  (verdicts.get('AUT-PW')?.tells ?? []).includes('machine:audio-missing-google-speech-voices'),
);

/* -------------------------------------------------------------------------- */
/* No-vendor-label guarantee                                                   */
/* -------------------------------------------------------------------------- */
section('no-vendor-label guarantee');

const vendorHuman = verdicts.get('VENDOR-CLAIM-HUMAN');
check('vendor claim of human does not change a known-stack label', vendorHuman?.expected === 'automated');
check('vendor claim case records that the verdict was ignored', (vendorHuman?.reasons ?? []).includes('vendor-verdict-ignored'));
check('vendor claim string "human" never appears in the result', !JSON.stringify(vendorHuman).includes('"human"'));
const vendorUnknown = verdicts.get('VENDOR-UNKNOWN');
check('vendor claim of automated for unknown stack stays unknown', vendorUnknown?.expected === 'unknown');
check('vendor claim string "automated" never appears in the result', !JSON.stringify(vendorUnknown).includes('"automated"'));
check('vendor verdict cannot manufacture a human label', verdicts.get('HUM-VENDOR')?.expected === 'unknown');

const vendorBase: AutomationConfigInput = {
  stack: 'playwright',
  headlessMode: 'headful',
  flags: [],
  cdpClients: 0,
  humanOperated: false,
  source: 'vendor_verdict',
};
const vendorNone = classifyAutomationConfig(vendorBase);
const vendorSaysHuman = classifyAutomationConfig({ ...vendorBase, vendorVerdict: 'human' });
const vendorSaysAutomated = classifyAutomationConfig({ ...vendorBase, vendorVerdict: 'automated' });
check('vendorVerdict=human is byte-identical to no verdict', same(vendorNone, vendorSaysHuman));
check('vendorVerdict=automated is byte-identical to no verdict', same(vendorNone, vendorSaysAutomated));
const throwingVendor = new Proxy({}, { get() { throw new Error('hostile vendor verdict'); } });
check('a hostile vendor verdict getter is never read', noThrow(() => classifyAutomationConfig({ ...vendorBase, vendorVerdict: throwingVendor }))?.expected === 'automated');

/* -------------------------------------------------------------------------- */
/* CDP attached is weight 0                                                    */
/* -------------------------------------------------------------------------- */
section('CDP client attached is weight 0');

const cdpBase: AutomationConfigInput = {
  stack: 'mystery_bot',
  headlessMode: 'headful',
  flags: [],
  cdpClients: 0,
  humanOperated: false,
  source: 'controlled_launch_config',
};
const cdpZero = classifyAutomationConfig(cdpBase);
const cdpThree = classifyAutomationConfig({ ...cdpBase, cdpClients: 3 });
check('CDP count does not change the label', cdpZero.expected === cdpThree.expected && cdpThree.expected === 'unknown');
check('CDP count does not change confidence', cdpZero.confidence === cdpThree.confidence && cdpThree.confidence === 'low');
check('CDP three emits the weight-0 tell', cdpThree.tells.includes('automation:cdp-client-attached'));
check('CDP zero emits no attached-client tell', !cdpZero.tells.includes('automation:cdp-client-attached'));
check('CDP three records the weight-0 reason', cdpThree.reasons.includes('cdp-client-weight-0'));
check('invalid CDP counts are ignored (no attached tell)', classifyAutomationConfig({ ...cdpBase, cdpClients: Number.NaN }).tells.length === cdpZero.tells.length);
check('negative CDP count is ignored', classifyAutomationConfig({ ...cdpBase, cdpClients: -5 }).tells.length === cdpZero.tells.length);
check('Infinite CDP count is ignored', classifyAutomationConfig({ ...cdpBase, cdpClients: Number.POSITIVE_INFINITY }).tells.length === cdpZero.tells.length);
check('CDP alone never produces a hard automation tell', !cdpThree.tells.some((t) => t.includes('runtime-enable') || t.includes('network-enable')));

/* -------------------------------------------------------------------------- */
/* Determinism and immutability                                                */
/* -------------------------------------------------------------------------- */
section('determinism and immutability');

const complexCase = fixture.classifyCases.find((c) => c.id === 'AUT-PW');
const complexInput = complexCase?.input as AutomationConfigInput;
const inputSnapshot = JSON.stringify(complexInput);
const first = classifyAutomationConfig(complexInput);
const second = classifyAutomationConfig(complexInput);
check('repeated classification is byte-identical', same(first, second));
check('classification does not mutate its input', JSON.stringify(complexInput) === inputSnapshot);
check('returned tells/reasons arrays are fresh each call', first.tells !== second.tells && first.reasons !== second.reasons);
check('flag order does not change the emitted tell set', same(
  new Set(classifyAutomationConfig({ ...complexInput, flags: ['--disable-component-extensions', '--disable-ipc-flooding-protection'] }).tells),
  new Set(first.tells),
));

/* -------------------------------------------------------------------------- */
/* Hostile input — never throws, always well-formed                            */
/* -------------------------------------------------------------------------- */
section('hostile input (non-throwing)');

const hostileProxy = new Proxy({}, {
  get() { throw new Error('hostile get'); },
  ownKeys() { throw new Error('hostile keys'); },
  has() { throw new Error('hostile has'); },
});
const cycle: Record<string, unknown> = { stack: 'playwright', source: 'controlled_launch_config', flags: [] };
cycle.self = cycle;
const proxyFlags = new Proxy(['--disable-gpu'], {
  get(target, prop) {
    if (prop === Symbol.iterator) throw new Error('hostile iterator');
    return Reflect.get(target, prop);
  },
});
const trickyStack = new Proxy({}, {
  get(_target, prop) {
    if (prop === 'stack') return 'playwright';
    if (prop === 'source') return 'controlled_launch_config';
    throw new Error('hostile field');
  },
});

const hostileCases: Array<[string, () => unknown]> = [
  ['throwing proxy', () => classifyAutomationConfig(hostileProxy as unknown as AutomationConfigInput)],
  ['cyclic object', () => classifyAutomationConfig(cycle as unknown as AutomationConfigInput)],
  ['null', () => classifyAutomationConfig(null as unknown as AutomationConfigInput)],
  ['undefined', () => classifyAutomationConfig(undefined as unknown as AutomationConfigInput)],
  ['number', () => classifyAutomationConfig(99 as unknown as AutomationConfigInput)],
  ['boolean', () => classifyAutomationConfig(true as unknown as AutomationConfigInput)],
  ['string', () => classifyAutomationConfig('playwright' as unknown as AutomationConfigInput)],
  ['function', () => classifyAutomationConfig((() => undefined) as unknown as AutomationConfigInput)],
  ['proxy flags array', () => classifyAutomationConfig({ ...cdpBase, flags: proxyFlags })],
  ['proxy cdpDomains array', () => classifyAutomationConfig({ ...cdpBase, cdpDomains: proxyFlags })],
  ['hostile userAgentSpoofed getter', () => classifyAutomationConfig({ ...cdpBase, get userAgentSpoofed() { throw new Error('hostile ua'); } })],
  ['hostile source getter', () => classifyAutomationConfig({ ...cdpBase, get source() { throw new Error('hostile source'); } })],
  ['hostile stack getter', () => classifyAutomationConfig({ ...cdpBase, get stack() { throw new Error('hostile stack'); } })],
  ['5000 flags capped', () => classifyAutomationConfig({ ...cdpBase, flags: Array.from({ length: 5000 }, () => '--disable-gpu') })],
  ['wrong-typed flags entries', () => classifyAutomationConfig({ ...cdpBase, flags: [1, null, {}, true, '--disable-gpu'] })],
  ['wrong-typed cdpDomains', () => classifyAutomationConfig({ ...cdpBase, cdpDomains: { Runtime: 'enable' } })],
  ['hostile humanOperated object', () => classifyAutomationConfig({ ...cdpBase, humanOperated: { valueOf() { throw new Error('x'); } } })],
];

let hostileOk = 0;
for (const [name, fn] of hostileCases) {
  const result = noThrow(fn);
  const ok = wellFormedVerdict(result);
  if (ok) hostileOk += 1;
  else console.log(`  hostile case failed: ${name}`);
  check(`hostile ${name}: no throw and well-formed`, ok);
}
check('all hostile inputs contained', hostileOk === hostileCases.length, `${hostileOk}/${hostileCases.length}`);
check('throwing proxy still defaults to unknown', noThrow(() => classifyAutomationConfig(hostileProxy as unknown as AutomationConfigInput))?.expected === 'unknown');
check('partial getter exposure still classifies from readable stack', noThrow(() => classifyAutomationConfig(trickyStack as unknown as AutomationConfigInput))?.expected === 'automated');
check('hostile inputs never emit out-of-vocabulary tells', hostileCases.every(([, fn]) => {
  const v = noThrow(fn) as AutomationConfigVerdict | null;
  return v === null || v.tells.every((t: string) => ALL_TELLS.includes(t));
}));

/* -------------------------------------------------------------------------- */
/* Human baseline validation                                                   */
/* -------------------------------------------------------------------------- */
section('human baseline validation (log before enforce, fail on flags)');

for (const c of fixture.baselineCases) {
  const result = validateHumanBaseline(c.input as HumanBaselineInput);
  check(`${c.id}: well-formed baseline`, wellFormedBaseline(result));
  check(`${c.id}: valid flag`, result.valid === c.expect.valid, String(result.valid));
  check(`${c.id}: false-positive rate`, result.falsePositiveRate === c.expect.falsePositiveRate, String(result.falsePositiveRate));
  check(`${c.id}: reason content`, result.reason.includes(c.expect.reasonIncludes));
  check(`${c.id}: log-before-enforce discipline`, c.expect.logBeforeEnforce
    ? result.reason.includes('Log mode before enforce')
    : result.reason.includes('Fail run') || result.reason.includes('INVALID') || result.reason.includes('MISSING'));
}

const baselineHostile: Array<[string, () => unknown]> = [
  ['NaN human', () => validateHumanBaseline({ humanCases: Number.NaN, flaggedCases: 0 })],
  ['Infinity human', () => validateHumanBaseline({ humanCases: Number.POSITIVE_INFINITY, flaggedCases: 0 })],
  ['negative human', () => validateHumanBaseline({ humanCases: -1, flaggedCases: 0 })],
  ['string human', () => validateHumanBaseline({ humanCases: '31', flaggedCases: 0 })],
  ['null input', () => validateHumanBaseline(null as unknown as HumanBaselineInput)],
  ['proxy input', () => validateHumanBaseline(hostileProxy as unknown as HumanBaselineInput)],
  ['NaN flagged', () => validateHumanBaseline({ humanCases: 31, flaggedCases: Number.NaN })],
  ['fractional flagged', () => validateHumanBaseline({ humanCases: 31, flaggedCases: 0.5 })],
  ['negative flagged', () => validateHumanBaseline({ humanCases: 31, flaggedCases: -1 })],
];
let baselineHostileOk = 0;
for (const [name, fn] of baselineHostile) {
  const result = noThrow(fn);
  const ok = wellFormedBaseline(result) && result.valid === false;
  if (ok) baselineHostileOk += 1;
  check(`baseline hostile ${name}: contained and invalid`, ok);
}
check('all hostile baselines contained', baselineHostileOk === baselineHostile.length, `${baselineHostileOk}/${baselineHostile.length}`);
check('zero flagged human cases yields exact zero rate', validateHumanBaseline({ humanCases: 31, flaggedCases: 0 }).falsePositiveRate === 0);
check('one flagged human case fails the run', validateHumanBaseline({ humanCases: 31, flaggedCases: 1 }).valid === false);

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log(`FAILED: ${failures.join(' | ')}`);
  process.exit(1);
}

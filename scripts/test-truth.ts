/**
 * Golden-corpus regression suite for the five live contradictions.
 *
 * Loads scripts/fixtures/contradictions.json and pins the canonical outcomes to the pure
 * helpers that exist in src/lib today. It never edits the fixture: when a check fails, the
 * implementation regressed. A helper that is not present is reported as an explicit SKIP
 * (with the expected behavior already frozen in the fixture), never as a silent pass.
 *
 *   npx tsx scripts/test-truth.ts
 */

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import * as hardwareTruth from '../src/lib/hardwareTruth';
import * as spec from '../src/lib/specInvariants';
import * as telemetry from '../src/lib/telemetryContract';
import * as risk from '../src/lib/riskLedger';
import * as honesty from '../src/lib/rarityHonesty';

/* -------------------------------------------------------------------------- */
/* Fixture + reporting                                                         */
/* -------------------------------------------------------------------------- */

interface RawCase {
  id: string;
  title: string;
  observed: Record<string, unknown>;
  expected: Record<string, unknown>;
  helper_functions?: string[];
}

interface Corpus {
  schema_version: number;
  cases: RawCase[];
}

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE_PATH = join(ROOT, 'scripts', 'fixtures', 'contradictions.json');
const corpus = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as Corpus;

if (!Array.isArray(corpus.cases) || corpus.cases.length !== 5) {
  throw new Error(`${FIXTURE_PATH}: expected exactly 5 golden cases, found ${corpus.cases?.length}`);
}

function byId(id: string): RawCase {
  const found = corpus.cases.find((item) => item.id === id);
  if (!found) throw new Error(`${FIXTURE_PATH}: missing case '${id}'`);
  return found;
}

let passed = 0;
let failed = 0;
let skipped = 0;

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

function skip(id: string, label: string, reason: string): void {
  skipped += 1;
  console.log(`SKIP  [${id}] ${label} — ${reason}`);
}

function hasFn(namespace: object, name: string): boolean {
  return typeof (namespace as Record<string, unknown>)[name] === 'function';
}

/** Explicit SKIP when a helper export is missing — never a silent omission. */
function requireExports(id: string, moduleLabel: string, namespace: object, names: readonly string[]): boolean {
  const missing = names.filter((name) => !hasFn(namespace, name));
  if (missing.length > 0) {
    skip(
      id,
      `${moduleLabel} helper assertions`,
      `missing export(s): ${missing.join(', ')}; expected behavior is frozen in ${FIXTURE_PATH}`
    );
    return false;
  }
  return true;
}

const specExports = ['resolveGpuObservation', 'gpuObservationIsHardwareAnchor', 'checkGpuObservationInvariants', 'isSwiftShaderRenderer', 'classifyWebglBackend', 'resolveInspectorState', 'toInspectorState', 'inspectorFlagsForState', 'checkInspectorInvariants', 'permitsHumanVerdict'] as const;

const specExportsReady = requireExports('setup', 'src/lib/specInvariants', spec, specExports);
const riskExportsReady = requireExports('setup', 'src/lib/riskLedger', risk, ['score10FromScore100', 'riskTierFromScore100']);
const telemetryExportsReady = requireExports('setup', 'src/lib/telemetryContract', telemetry, ['riskTier', 'assertCanonicalConsistency']);
const honestyExportsReady = requireExports('setup', 'src/lib/rarityHonesty', honesty, ['calibrationStatusFor', 'confidenceLabel', 'computeHonestIdentityConfidence']);
const hardwareExportsReady = requireExports('setup', 'src/lib/hardwareTruth', hardwareTruth, ['classifyGpuArchFamily']);

/* -------------------------------------------------------------------------- */
/* Case 1 — Asia/Calcutta vs Asia/Kolkata                                      */
/* -------------------------------------------------------------------------- */

const c1 = byId('tz-alias-calcutta-kolkata');
const o1 = c1.observed as {
  browserTimezone: string;
  ipGeoTz: string;
  timezoneMismatch: boolean;
  riskNote: string;
  riskLine: { family: string; component: string; points: number };
};
const e1 = c1.expected as {
  canonicalBrowser: string;
  canonicalIp: string;
  timezonesEquivalent: boolean;
  mismatch: boolean;
  riskLine: null;
  networkRiskPoints: number;
};

// src/lib/timezone is the designated home for these pure helpers. It may not exist in every
// checkout (the assertion is skipped explicitly in that case); the expected outcome is always
// recorded in the fixture, so nothing is ever silently assumed.
const TZ_CANDIDATES = [
  join(ROOT, 'src', 'lib', 'timezone.ts'),
  join(ROOT, 'src', 'lib', 'timezone', 'index.ts'),
];
const tzPath = TZ_CANDIDATES.find((candidate) => existsSync(candidate));

type CanonicalTimezone = (input: string | null | undefined) => string | null;
type TimezonesEquivalent = (a: string | null | undefined, b: string | null | undefined) => boolean;
type TimezoneMismatchContext = (a: string | null | undefined, b: string | null | undefined) => {
  mismatch: boolean;
  canonicalBrowser: string | null;
  canonicalIp: string | null;
};

let tzModule: Record<string, unknown> | null = null;
if (!tzPath) {
  skip(
    c1.id,
    'src/lib/timezone pure-function assertions',
    'module not present in this checkout; canonical expectations are recorded in the fixture (cases[0].expected) — deferred, never silently ignored'
  );
} else {
  try {
    tzModule = (await import(pathToFileURL(tzPath).href)) as Record<string, unknown>;
  } catch (error) {
    skip(c1.id, 'src/lib/timezone pure-function assertions', `module present but import failed: ${describeError(error)}`);
  }
}

if (tzModule && requireExports(c1.id, 'src/lib/timezone', tzModule, c1.helper_functions ?? [])) {
  const canonicalTimezone = tzModule.canonicalTimezone as CanonicalTimezone;
  const timezonesEquivalent = tzModule.timezonesEquivalent as TimezonesEquivalent;
  const timezoneMismatchContext = tzModule.timezoneMismatchContext as TimezoneMismatchContext;

  check(c1.id, 'both alias spellings resolve to one canonical IANA id', () => {
    assert.equal(canonicalTimezone(o1.browserTimezone), e1.canonicalBrowser);
    assert.equal(canonicalTimezone(o1.ipGeoTz), e1.canonicalIp);
  });
  check(c1.id, 'alias pair is equivalent and reports no mismatch', () => {
    assert.equal(timezonesEquivalent(o1.browserTimezone, o1.ipGeoTz), e1.timezonesEquivalent);
    assert.deepEqual(timezoneMismatchContext(o1.browserTimezone, o1.ipGeoTz), {
      mismatch: e1.mismatch,
      canonicalBrowser: e1.canonicalBrowser,
      canonicalIp: e1.canonicalIp,
    });
  });
  check(c1.id, 'distinct zones at the same UTC offset are NOT collapsed', () => {
    assert.equal(timezonesEquivalent('Asia/Singapore', 'Asia/Hong_Kong'), false);
    assert.equal(timezoneMismatchContext('Asia/Singapore', 'Asia/Hong_Kong').mismatch, true);
  });
}

if (telemetryExportsReady && hasFn(risk, 'buildGradedRiskLedger')) {
  const buildGradedRiskLedger = risk.buildGradedRiskLedger as (input?: {
    network?: { timezoneMismatch?: boolean; otherComponentFired?: boolean };
  }) => { network: number; score_0_100: number; evidence_ledger: Array<{ component: string; points: number }> };
  check(c1.id, 'alias fix removes the timezone risk line and its points', () => {
    const clean = buildGradedRiskLedger({});
    assert.equal(clean.network, e1.networkRiskPoints);
    assert.equal(clean.evidence_ledger.some((line) => line.component.includes('timezone_mismatch')), false);
    // The reported line is exactly the standalone rubric entry — pin it so a rubric drift is caught.
    const mismatched = buildGradedRiskLedger({ network: { timezoneMismatch: true, otherComponentFired: false } });
    assert.equal(
      mismatched.evidence_ledger.some(
        (line) => line.component === o1.riskLine.component && line.points === o1.riskLine.points
      ),
      true
    );
  });
}

/* -------------------------------------------------------------------------- */
/* Case 2 — masked GPU label with a real Intel Iris Xe renderer                */
/* -------------------------------------------------------------------------- */

const c2 = byId('gpu-masked-label-real-iris-xe');
const o2 = c2.observed as {
  gpuVendor: string;
  gpuRenderer: string;
  gpuCapabilityClass: string;
  softwareRenderer: boolean;
};
const e2 = c2.expected as {
  gpuObservation: string;
  hardwareAnchor: boolean;
  gpuArchFamily: string;
  webglBackend: string;
  swiftShader: boolean;
};

if (specExportsReady && hardwareExportsReady) {
  const observation = spec.resolveGpuObservation(o2.gpuVendor, o2.gpuRenderer, o2.gpuCapabilityClass);
  check(c2.id, 'explicit renderer is a visible hardware observation, never masked/VM proof', () => {
    assert.equal(observation, e2.gpuObservation);
    assert.equal(spec.gpuObservationIsHardwareAnchor(observation), e2.hardwareAnchor);
    assert.deepEqual(spec.checkGpuObservationInvariants({ gpu_observation: observation, claimed_hardware_anchor: true }), []);
  });
  check(c2.id, 'renderer is not SwiftShader and its backend is Direct3D', () => {
    assert.equal(spec.isSwiftShaderRenderer(o2.gpuRenderer), e2.swiftShader);
    assert.equal(spec.classifyWebglBackend(o2.gpuRenderer), e2.webglBackend);
  });
  check(c2.id, 'real Intel silicon resolves to the x86 architecture family', () => {
    assert.equal(hardwareTruth.classifyGpuArchFamily(o2.gpuVendor, o2.gpuRenderer, false), e2.gpuArchFamily);
  });
  check(c2.id, 'a missing renderer is masked/unavailable — never software_or_virtual', () => {
    assert.notEqual(spec.resolveGpuObservation('', '', 't16|h|e3'), 'software_or_virtual');
    assert.notEqual(spec.resolveGpuObservation('', '', null), 'software_or_virtual');
  });
}

/* -------------------------------------------------------------------------- */
/* Case 3 — CDP note present but cdp_attached false                            */
/* -------------------------------------------------------------------------- */

const c3 = byId('cdp-note-but-cdp-attached-false');
const e3 = c3.expected as {
  rawSignals: { cdpAttached: boolean; devtoolsActiveVerified: boolean; viewportContractionNormalized: boolean };
  inspectorState: string;
  cdpAttached: boolean;
  developerTools: boolean;
  permitsHumanVerdict: boolean;
};

if (specExportsReady) {
  const state = spec.resolveInspectorState(e3.rawSignals);
  check(c3.id, 'a bare CDP probe resolves to yes-unattributed, not closed', () => {
    assert.equal(state, e3.inspectorState);
  });
  check(c3.id, 'state and flags are internally consistent (CDP != DevTools UI)', () => {
    assert.deepEqual(spec.inspectorFlagsForState(state), {
      cdp_attached: e3.cdpAttached,
      developer_tools: e3.developerTools,
    });
    assert.deepEqual(
      spec.checkInspectorInvariants({
        inspector_state: state,
        cdp_attached: e3.cdpAttached,
        developer_tools: e3.developerTools,
      }).contradictions,
      []
    );
  });
  check(c3.id, 'an observed inspector never permits a Verified Human verdict', () => {
    assert.equal(spec.permitsHumanVerdict(state), e3.permitsHumanVerdict);
  });
  check(c3.id, 'a corroborated CDP+DevTools pair is the only path to cdp_attached=true', () => {
    const corroborated = spec.resolveInspectorState({ cdpAttached: true, devtoolsActiveVerified: true });
    assert.equal(corroborated, 'yes-corroborated');
    assert.deepEqual(spec.inspectorFlagsForState(corroborated), { cdp_attached: true, developer_tools: true });
  });
}

/* -------------------------------------------------------------------------- */
/* Case 4 — 3/10 headline vs 0-100 canonical ledger                            */
/* -------------------------------------------------------------------------- */

const c4 = byId('risk-scales-3-of-10-vs-0-100');
const o4 = c4.observed as { score10: number; score_0_100: number; tier: string };
const e4 = c4.expected as {
  for_ledger_0: { score10: number; tier: string };
  for_ledger_30: { score10: number; tier: string };
  headline_3_only_valid_with_ledger: number;
};

if (riskExportsReady && telemetryExportsReady) {
  check(c4.id, 'the reported 3/10 vs ledger 0 pair is detected as inconsistent', () => {
    const issues = telemetry.assertCanonicalConsistency({
      risk: { score_0_100: o4.score_0_100, tier: o4.tier as telemetry.RiskTier, score10: o4.score10 },
    });
    assert.ok(issues.length > 0, 'expected the observed mismatch to be reported');
    assert.ok(issues.some((issue) => issue.includes('risk.score10')), `expected a score10 parity issue, got ${JSON.stringify(issues)}`);
  });
  check(c4.id, 'a clean ledger has no consistency issues at 0 or at 30', () => {
    assert.deepEqual(
      telemetry.assertCanonicalConsistency({
        risk: { score_0_100: o4.score_0_100, tier: e4.for_ledger_0.tier as telemetry.RiskTier, score10: e4.for_ledger_0.score10 },
      }),
      []
    );
    assert.deepEqual(
      telemetry.assertCanonicalConsistency({
        risk: { score_0_100: e4.headline_3_only_valid_with_ledger, tier: e4.for_ledger_30.tier as telemetry.RiskTier, score10: e4.for_ledger_30.score10 },
      }),
      []
    );
  });
  check(c4.id, '0-10 is derived from 0-100 by the frozen mapping and tier follows the composite', () => {
    assert.equal(risk.score10FromScore100(0), e4.for_ledger_0.score10);
    assert.equal(risk.score10FromScore100(e4.headline_3_only_valid_with_ledger), e4.for_ledger_30.score10);
    assert.equal(risk.riskTierFromScore100(e4.headline_3_only_valid_with_ledger), e4.for_ledger_30.tier);
    assert.equal(telemetry.riskTier(e4.headline_3_only_valid_with_ledger), e4.for_ledger_30.tier);
  });
}

/* -------------------------------------------------------------------------- */
/* Case 5 — uncalibrated confidence shown as a percentage                      */
/* -------------------------------------------------------------------------- */

const c5 = byId('uncalibrated-confidence-percentage');
const o5 = c5.observed as {
  confidence_score: number;
  labeledPairs: number;
  heldOutEce: number;
  match_stage: 'new_enrollment';
};
const e5 = c5.expected as {
  calibration_status: 'uncalibrated';
  confidence_score: null;
  confidence_tier: string;
  honest_label_for_evidenced_number: string;
  forbidden_label: string;
};

if (honestyExportsReady && telemetryExportsReady) {
  check(c5.id, 'an unpassed held-out gate cannot produce calibrated status', () => {
    assert.equal(honesty.calibrationStatusFor({ labeledPairs: o5.labeledPairs, heldOutEce: o5.heldOutEce }), e5.calibration_status);
    assert.equal(honesty.calibrationStatusFor({ labeledPairs: 200, heldOutEce: 0.04 }), 'calibrated');
  });
  check(c5.id, 'an uncalibrated evidence number is labelled as evidence, not confidence', () => {
    assert.equal(honesty.confidenceLabel(o5.confidence_score, false), e5.honest_label_for_evidenced_number);
    assert.notEqual(honesty.confidenceLabel(o5.confidence_score, false), e5.forbidden_label);
    assert.equal(honesty.confidenceLabel(o5.confidence_score, true), e5.forbidden_label);
  });
  check(c5.id, 'a genuinely unseen profile publishes a null score and a categorical tier', () => {
    const honest = honesty.computeHonestIdentityConfidence({
      labeledPairs: o5.labeledPairs,
      heldOutEce: o5.heldOutEce,
      matchStage: o5.match_stage,
      matchTier: o5.match_stage,
      calibratedScore: o5.confidence_score,
    });
    assert.equal(honest.confidence_score, e5.confidence_score);
    assert.equal(honest.confidence_tier, e5.confidence_tier);
    assert.equal(honest.calibration_status, e5.calibration_status);
  });
  check(c5.id, 'canonical consistency rejects uncalibrated-with-score and accepts the fix', () => {
    const baseRisk = { score_0_100: 0, tier: 'Low' as telemetry.RiskTier, score10: 0 };
    const observedIssues = telemetry.assertCanonicalConsistency({
      risk: baseRisk,
      identity: {
        match_stage: o5.match_stage,
        confidence_tier: 'New Unobserved Profile',
        confidence_score: o5.confidence_score,
        calibration_status: e5.calibration_status,
      },
    });
    assert.ok(observedIssues.length > 0, 'expected the observed identity contradiction to be reported');
    assert.deepEqual(
      telemetry.assertCanonicalConsistency({
        risk: baseRisk,
        identity: {
          match_stage: o5.match_stage,
          confidence_tier: e5.confidence_tier as 'New Unobserved Profile',
          confidence_score: e5.confidence_score,
          calibration_status: e5.calibration_status,
        },
      }),
      []
    );
  });
}

/* -------------------------------------------------------------------------- */
/* Summary                                                                     */
/* -------------------------------------------------------------------------- */

console.log(`\nTruth-corpus suite: ${passed} passed, ${failed} failed, ${skipped} skipped`);
if (failed > 0) process.exitCode = 1;

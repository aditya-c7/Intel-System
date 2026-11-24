/**
 * Additive incognito-diagnostics contract — SHADOW-ONLY regression suite.
 *
 * Pins four properties of the optional `diagnostics` readout:
 *   1. the shape is additive: only `enabled` is required, every other field is optional
 *      AND nullable, in both canonical type homes, and `enabled:false` is a valid record;
 *   2. low probe confidence implies a hard server veto (`lowConfidenceVeto` /
 *      `serverWouldVeto`), while high confidence does not — the veto is a MIRROR of the
 *      server gate, not a new decision path (server.ts gate logic, cited below);
 *   3. IANA alias pairs are NOT timezone mismatches (real exported resolver helpers);
 *   4. diagnostics never change the risk headline: 0-100 composite -> 0-10 score10 -> tier
 *      is a pure function of graded risk signals, with no diagnostics input anywhere.
 *
 *   npx tsx scripts/test-incognito-diagnostics.ts
 */
import assert from 'node:assert/strict';

import type {
  CanonicalConsistencyView,
  IncognitoDiagnostics as TelemetryIncognitoDiagnostics,
} from '../src/lib/telemetryContract';
import type { IncognitoDiagnostics as VisitorIncognitoDiagnostics } from '../src/types/visitor';
import { assertCanonicalConsistency, buildRiskLedger, riskTier } from '../src/lib/telemetryContract';
import {
  buildGradedRiskLedger,
  GRADED_RISK_FIXTURES,
  riskTierFromScore100,
  score10FromScore100,
  verifyGradedRiskFixtures,
  type GradedRiskInput,
} from '../src/lib/riskLedger';
import { timezonesEquivalent, timezoneMismatchContext } from '../src/lib/timezone';
import { isIncognitoDiagnosticsEnabled } from '../src/lib/collector';
import {
  buildTimingShadow,
  evaluateCollectorBudget,
  percentilesFromTimings,
  type CollectorTimingStats,
} from '../src/lib/collectorTimingShadow';

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
/* Shape manifest — type-level coverage + runtime validation                   */
/* -------------------------------------------------------------------------- */

/** Keys whose declaration is optional AND nullable in the canonical type. */
type OptionalNullableKeys<T> = {
  [K in keyof T]-?: undefined extends T[K] ? (null extends T[K] ? K : never) : never;
}[keyof T];

/**
 * Compile-time proof of the additive shape: the manifest names every field except `enabled`,
 * and every named non-enabled field is optional + nullable. Emits a `true` literal that is only
 * assignable when both halves hold (checked by tsc; tsx still runs the runtime checks below).
 */
type ManifestContract<T, M extends readonly (keyof T)[]> = [Exclude<keyof T, 'enabled'>] extends [
  M[number],
]
  ? [Exclude<M[number], 'enabled'>] extends [OptionalNullableKeys<T>]
    ? true
    : false
  : false;

const TELEMETRY_DIAG_FIELDS = [
  'enabled',
  'engine',
  'method',
  'confidence',
  'isPrivate',
  'quotaBytes',
  'headroomGiB',
  'idbDurabilityRatio',
  'idbHighVariance',
  'idbTruthRule',
  'opfsFlushMs',
  'persistedStorageGrant',
  'isolatedContextVeto',
  'sessionLockHit',
  'lowConfidenceVeto',
  'clientReportedIncognito',
  'serverWouldVeto',
] as const satisfies readonly (keyof TelemetryIncognitoDiagnostics)[];

const VISITOR_DIAG_FIELDS = [
  'enabled',
  'engine',
  'method',
  'confidence',
  'isPrivate',
  'quotaBytes',
  'headroomGiB',
  'idbDurabilityRatio',
  'idbHighVariance',
  'idbTruthRule',
  'opfsFlushMs',
  'persistedStorageGrant',
  'isolatedContextVeto',
  'sessionLockHit',
  'lowConfidenceVeto',
  'clientReportedIncognito',
  'serverWouldVeto',
] as const satisfies readonly (keyof VisitorIncognitoDiagnostics)[];

const TELEMETRY_MANIFEST_OK: ManifestContract<
  TelemetryIncognitoDiagnostics,
  typeof TELEMETRY_DIAG_FIELDS
> = true;
const VISITOR_MANIFEST_OK: ManifestContract<VisitorIncognitoDiagnostics, typeof VISITOR_DIAG_FIELDS> =
  true;
void TELEMETRY_MANIFEST_OK;
void VISITOR_MANIFEST_OK;

type FieldKind = 'boolean' | 'string' | 'number';
const OPTIONAL_FIELD_KINDS: Readonly<Record<string, FieldKind>> = Object.freeze({
  engine: 'string',
  method: 'string',
  confidence: 'string',
  isPrivate: 'boolean',
  quotaBytes: 'number',
  headroomGiB: 'number',
  idbDurabilityRatio: 'number',
  idbHighVariance: 'boolean',
  idbTruthRule: 'string',
  opfsFlushMs: 'number',
  persistedStorageGrant: 'boolean',
  isolatedContextVeto: 'boolean',
  sessionLockHit: 'boolean',
  lowConfidenceVeto: 'boolean',
  clientReportedIncognito: 'boolean',
  serverWouldVeto: 'boolean',
});

/** Runtime mirror of the type contract: required `enabled`, all else absent/null/typed. */
function diagnosticsIssues(value: unknown): string[] {
  const issues: string[] = [];
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return ['diagnostics must be a non-array object'];
  }
  const record = value as Record<string, unknown>;
  if (typeof record.enabled !== 'boolean') issues.push('enabled must be a boolean');
  for (const key of Object.keys(record)) {
    if (key === 'enabled') continue;
    const kind = OPTIONAL_FIELD_KINDS[key];
    if (kind === undefined) {
      issues.push(`unknown field ${key}`);
      continue;
    }
    const field = record[key];
    if (field === null || field === undefined) continue;
    if (typeof field !== kind) {
      issues.push(`${key} must be ${kind} | null (got ${typeof field})`);
    }
  }
  return issues;
}

function sampleValue(field: string): unknown {
  const kind = OPTIONAL_FIELD_KINDS[field];
  if (kind === 'string') return 'sample';
  if (kind === 'number') return 0.5;
  return true;
}

const allNull: Record<string, unknown> = { enabled: false };
const allPopulated: Record<string, unknown> = { enabled: true };
for (const field of TELEMETRY_DIAG_FIELDS) {
  if (field === 'enabled') continue;
  allNull[field] = null;
  allPopulated[field] = sampleValue(field);
}

/** Typed fixtures — the assignments themselves enforce the contract under tsc. */
const disabledRecord: TelemetryIncognitoDiagnostics = { enabled: false };
const nullRecord: TelemetryIncognitoDiagnostics =
  allNull as unknown as TelemetryIncognitoDiagnostics;
const populatedVisitorRecord: VisitorIncognitoDiagnostics =
  allPopulated as unknown as VisitorIncognitoDiagnostics;

const heavyDiagnostics: TelemetryIncognitoDiagnostics = {
  enabled: true,
  engine: 'V8',
  method: 'private-storage-detected',
  confidence: 'low',
  isPrivate: true,
  quotaBytes: 0,
  headroomGiB: 0,
  idbDurabilityRatio: 0.5,
  idbHighVariance: true,
  opfsFlushMs: 900,
  persistedStorageGrant: false,
  isolatedContextVeto: true,
  sessionLockHit: true,
  lowConfidenceVeto: true,
  clientReportedIncognito: true,
  serverWouldVeto: true,
};

/* -------------------------------------------------------------------------- */
/* Server veto gate — explicit local fixture (no exported helper exists)        */
/* -------------------------------------------------------------------------- */

/**
 * Local fixture of the SHADOW mirror of the server gate in server.ts:
 * `lowConfidenceVeto = confidence === 'low' || (typeof confidence === 'number' && confidence < 0.9)`;
 * `incognitoConfidenceHigh = !lowConfidenceVeto && (confidence === 'high' || numeric >= 0.9)`.
 * `serverWouldVeto` mirrors `lowConfidenceVeto` — it is a readout, never a new veto path.
 */
function shadowVetoFromConfidence(confidence: unknown): {
  lowConfidenceVeto: boolean;
  serverWouldVeto: boolean;
  incognitoConfidenceHigh: boolean;
} {
  const lowConfidenceVeto =
    confidence === 'low' || (typeof confidence === 'number' && confidence < 0.9);
  return {
    lowConfidenceVeto,
    serverWouldVeto: lowConfidenceVeto,
    incognitoConfidenceHigh:
      !lowConfidenceVeto &&
      (confidence === 'high' || (typeof confidence === 'number' && confidence >= 0.9)),
  };
}

function main(): void {
  /* ------------------------------------------------------------------------ */
  section('1. Additive shape: optional + nullable, enabled:false valid');
  /* ------------------------------------------------------------------------ */

  check('telemetryContract and visitor type manifests name the same 17 fields', () => {
    assert.deepEqual([...VISITOR_DIAG_FIELDS], [...TELEMETRY_DIAG_FIELDS]);
    assert.equal(TELEMETRY_DIAG_FIELDS.length, 17);
    assert.equal(TELEMETRY_DIAG_FIELDS[0], 'enabled');
    assert.equal(new Set(TELEMETRY_DIAG_FIELDS).size, TELEMETRY_DIAG_FIELDS.length);
  });

  check('a record with only enabled:false is valid (all other fields omitted)', () => {
    assert.deepEqual(diagnosticsIssues(disabledRecord), []);
    assert.equal(disabledRecord.enabled, false);
    assert.deepEqual(Object.keys(disabledRecord), ['enabled']);
  });

  check('every optional field accepts null simultaneously', () => {
    assert.deepEqual(diagnosticsIssues(nullRecord), []);
    assert.equal(nullRecord.enabled, false);
    for (const field of TELEMETRY_DIAG_FIELDS) {
      if (field === 'enabled') continue;
      const value = (nullRecord as unknown as Record<string, unknown>)[field];
      assert.equal(value, null, `${field} must be null`);
    }
  });

  check('every optional field accepts its populated primitive type', () => {
    assert.deepEqual(diagnosticsIssues(populatedVisitorRecord), []);
    assert.equal(populatedVisitorRecord.enabled, true);
    assert.equal(populatedVisitorRecord.engine, 'sample');
    assert.equal(populatedVisitorRecord.quotaBytes, 0.5);
    assert.equal(populatedVisitorRecord.serverWouldVeto, true);
  });

  check('the shadow record carries no risk/headline fields', () => {
    const dangerous = TELEMETRY_DIAG_FIELDS.filter((field) =>
      /(?:^|_)(?:risk|score|tier|headline)/i.test(field),
    );
    assert.deepEqual(dangerous, []);
    assert.deepEqual(diagnosticsIssues({ enabled: true, score10: 7 }), [
      'unknown field score10',
    ]);
    assert.deepEqual(diagnosticsIssues({ enabled: false, risk_tier: 'High' }), [
      'unknown field risk_tier',
    ]);
  });

  check('wrong primitive types are rejected by the shape (no silent coercion)', () => {
    assert.match(diagnosticsIssues({ enabled: 'false' })[0], /enabled must be a boolean/);
    assert.match(diagnosticsIssues({ enabled: true, quotaBytes: '8' })[0], /quotaBytes must be number/);
    assert.match(
      diagnosticsIssues({ enabled: true, lowConfidenceVeto: 1 })[0],
      /lowConfidenceVeto must be boolean/,
    );
  });

  check('diagnostics default OFF in a Node realm (flag gate is shadow-only)', () => {
    assert.equal(isIncognitoDiagnosticsEnabled(), false);
  });

  check('flag gate turns on only via the explicit session flag', () => {
    const globals = globalThis as unknown as Record<string, unknown>;
    const hadOwn = Object.prototype.hasOwnProperty.call(globals, 'sessionStorage');
    const previous = globals.sessionStorage;
    try {
      globals.sessionStorage = {
        getItem: (key: string) => (key === 'intel_diag_v1' ? '1' : null),
      };
      assert.equal(isIncognitoDiagnosticsEnabled(), true);
      globals.sessionStorage = { getItem: () => null };
      assert.equal(isIncognitoDiagnosticsEnabled(), false);
    } finally {
      if (hadOwn) globals.sessionStorage = previous;
      else delete globals.sessionStorage;
    }
  });

  /* ------------------------------------------------------------------------ */
  section('2. Low confidence => server veto (shadow mirror of the server gate)');
  /* ------------------------------------------------------------------------ */

  check("confidence 'low' implies lowConfidenceVeto and serverWouldVeto", () => {
    const veto = shadowVetoFromConfidence('low');
    assert.equal(veto.lowConfidenceVeto, true);
    assert.equal(veto.serverWouldVeto, true);
    assert.equal(veto.incognitoConfidenceHigh, false);
    const record: TelemetryIncognitoDiagnostics = {
      ...disabledRecord,
      enabled: true,
      confidence: 'low',
      lowConfidenceVeto: veto.lowConfidenceVeto,
      serverWouldVeto: veto.serverWouldVeto,
    };
    assert.deepEqual(diagnosticsIssues(record), []);
    assert.equal(record.serverWouldVeto, true);
  });

  check('numeric confidence < 0.9 implies a server veto', () => {
    for (const confidence of [0, 0.5, 0.89, 0.899999, -1]) {
      const veto = shadowVetoFromConfidence(confidence);
      assert.equal(veto.lowConfidenceVeto, true, `confidence ${confidence}`);
      assert.equal(veto.serverWouldVeto, true, `confidence ${confidence}`);
      assert.equal(veto.incognitoConfidenceHigh, false, `confidence ${confidence}`);
      assert.equal(veto.serverWouldVeto, veto.lowConfidenceVeto);
    }
  });

  check("'high' and numeric >= 0.9 do not veto (boundary at 0.9)", () => {
    for (const confidence of ['high', 0.9, 0.91, 1]) {
      const veto = shadowVetoFromConfidence(confidence);
      assert.equal(veto.lowConfidenceVeto, false, `confidence ${String(confidence)}`);
      assert.equal(veto.serverWouldVeto, false, `confidence ${String(confidence)}`);
      assert.equal(veto.incognitoConfidenceHigh, true, `confidence ${String(confidence)}`);
    }
  });

  check('the veto flags are mirrors only: both true and false records are valid', () => {
    const vetoed: TelemetryIncognitoDiagnostics = { enabled: true, lowConfidenceVeto: true, serverWouldVeto: true };
    const clean: TelemetryIncognitoDiagnostics = { enabled: true, lowConfidenceVeto: false, serverWouldVeto: false };
    assert.deepEqual(diagnosticsIssues(vetoed), []);
    assert.deepEqual(diagnosticsIssues(clean), []);
    assert.equal(vetoed.serverWouldVeto, shadowVetoFromConfidence('low').serverWouldVeto);
    assert.equal(clean.serverWouldVeto, shadowVetoFromConfidence('high').serverWouldVeto);
  });

  /* ------------------------------------------------------------------------ */
  section('3. IANA alias pairs are NOT timezone mismatches');
  /* ------------------------------------------------------------------------ */

  const ALIAS_PAIRS: ReadonlyArray<readonly [string, string]> = [
    ['Asia/Calcutta', 'Asia/Kolkata'],
    ['Europe/Kiev', 'Europe/Kyiv'],
    ['Asia/Katmandu', 'Asia/Kathmandu'],
    ['US/Pacific', 'America/Los_Angeles'],
    ['Etc/UTC', 'UTC'],
    ['GMT', 'UTC'],
  ];

  for (const [alias, canonical] of ALIAS_PAIRS) {
    check(`${alias} === ${canonical} (no mismatch)`, () => {
      assert.equal(timezonesEquivalent(alias, canonical), true);
      const context = timezoneMismatchContext(alias, canonical);
      assert.equal(context.mismatch, false);
      assert.ok(context.canonicalBrowser !== null && context.canonicalIp !== null);
      assert.equal(
        context.canonicalBrowser?.toLowerCase(),
        context.canonicalIp?.toLowerCase(),
      );
    });
  }

  check('the resolver still reports a real mismatch (not an always-false helper)', () => {
    assert.equal(timezonesEquivalent('Asia/Singapore', 'Asia/Hong_Kong'), false);
    assert.equal(timezoneMismatchContext('Asia/Singapore', 'Asia/Hong_Kong').mismatch, true);
  });

  check('an unresolved timezone is absence of evidence, never a mismatch', () => {
    assert.equal(timezonesEquivalent('Unknown', 'Unknown'), false);
    assert.equal(timezoneMismatchContext('Unknown', 'Asia/Kolkata').mismatch, false);
    assert.equal(timezoneMismatchContext(null, null).mismatch, false);
  });

  /* ------------------------------------------------------------------------ */
  section('4. Diagnostics never alter risk headline math');
  /* ------------------------------------------------------------------------ */

  check('graded risk fixtures still produce their frozen 0-100 / 0-10 / tier tuples', () => {
    assert.equal(GRADED_RISK_FIXTURES.length, 4);
    for (const result of verifyGradedRiskFixtures()) {
      assert.equal(result.ok, true, `${result.name} fixture drifted`);
      assert.equal(result.score10, score10FromScore100(result.score_0_100));
      assert.equal(result.risk_tier, riskTierFromScore100(result.score_0_100));
      assert.equal(result.ledger.tier, riskTier(result.score_0_100));
    }
  });

  check('score10 and tier boundaries are the canonical frozen mapping', () => {
    assert.equal(score10FromScore100(67), 7);
    assert.equal(score10FromScore100(35), 4);
    assert.equal(score10FromScore100(100), 10);
    assert.equal(score10FromScore100(0), 0);
    assert.equal(riskTierFromScore100(24), 'Low');
    assert.equal(riskTierFromScore100(25), 'Elevated');
    assert.equal(riskTierFromScore100(50), 'High');
    assert.equal(riskTierFromScore100(75), 'Critical');
    assert.equal(riskTierFromScore100(67), riskTier(67));
  });

  check('a diagnostics-laden input cannot change any graded ledger headline', () => {
    const headline = (input: GradedRiskInput): Record<string, unknown> => {
      const ledger = buildGradedRiskLedger(input);
      return {
        score_0_100: ledger.score_0_100,
        score10: ledger.score10,
        risk_tier: ledger.risk_tier,
        tier: ledger.tier,
      };
    };
    for (const fixture of GRADED_RISK_FIXTURES) {
      const withoutDiag = headline(fixture.input);
      // Excess runtime key: the graded ledger reads only graded risk signals.
      const withDiag = headline({ ...fixture.input, diagnostics: heavyDiagnostics } as GradedRiskInput);
      assert.deepEqual(withDiag, withoutDiag, `${fixture.name} headline changed`);
    }
  });

  check('evidence ledger contains no incognito/diagnostics scoring line', () => {
    const ledger = buildGradedRiskLedger({
      automation: { tierA: true },
      network: { vpnOrRelay: true },
      environment: { swiftshader: true, ephemeralOrPrivateStorage: true },
    });
    assert.equal(ledger.score_0_100, 67);
    assert.equal(ledger.score10, 7);
    assert.equal(ledger.risk_tier, 'High');
    const diagnosticLines = ledger.evidence_ledger.filter((line) =>
      /incognito|diagnostic|veto|private.brows/i.test(`${line.component} ${line.reason}`),
    );
    assert.deepEqual(diagnosticLines, []);
  });

  check('canonical consistency is identical with and without a diagnostics mirror', () => {
    const baseView: CanonicalConsistencyView = {
      risk: {
        score_0_100: 67,
        tier: 'High',
        score10: 7,
        risk_tier: 'High',
      },
    };
    const withDiag = {
      ...baseView,
      diagnostics: heavyDiagnostics,
    } as unknown as CanonicalConsistencyView;
    const withoutIssues = assertCanonicalConsistency(baseView);
    const withIssues = assertCanonicalConsistency(withDiag);
    assert.deepEqual(withoutIssues, []);
    assert.deepEqual(withIssues, withoutIssues);
  });

  check('real ledger APIs: diagnostics never move the risk headline', () => {
    const gradedInput: GradedRiskInput = {
      automation: { tierA: true },
      network: { vpnOrRelay: true },
      environment: { swiftshader: true, ephemeralOrPrivateStorage: true },
    };
    // buildGradedRiskLedger is the real orchestrator; `diagnostics` is an excess runtime key.
    const withDiag = buildGradedRiskLedger({
      ...gradedInput,
      diagnostics: heavyDiagnostics,
    } as GradedRiskInput);
    const withoutDiag = buildGradedRiskLedger(gradedInput);
    const headline = (ledger: ReturnType<typeof buildGradedRiskLedger>): Record<string, unknown> => ({
      automation: ledger.automation,
      tampering: ledger.tampering,
      network: ledger.network,
      environment: ledger.environment,
      velocity: ledger.velocity,
      raw_score: ledger.raw_score,
      score_0_100: ledger.score_0_100,
      score10: ledger.score10,
      tier: ledger.tier,
      risk_tier: ledger.risk_tier,
    });
    assert.deepEqual(headline(withDiag), headline(withoutDiag));
    assert.deepEqual(withDiag.evidence_ledger, withoutDiag.evidence_ledger);
    assert.equal(withoutDiag.score_0_100, 67);
    assert.equal(withoutDiag.score10, score10FromScore100(67));
    assert.equal(withoutDiag.risk_tier, riskTierFromScore100(67));

    // The contract primitive consumes the real evidence ledger and agrees on the headline.
    const primitive = buildRiskLedger(withoutDiag.evidence_ledger);
    assert.equal(primitive.score_0_100, withoutDiag.score_0_100);
    assert.equal(primitive.tier, withoutDiag.tier);
    assert.equal(primitive.tier, riskTier(primitive.score_0_100));
  });

  /* ------------------------------------------------------------------------ */
  section('5. Additive collector timing shadow: flag-gated, deterministic, total');
  /* ------------------------------------------------------------------------ */

  check('percentilesFromTimings uses nearest-rank p50/p95 over finite numeric timings', () => {
    const stats = percentilesFromTimings({ a: 100, b: 200, c: 300, d: 400 });
    assert.equal(stats.count, 4);
    // ceil(0.5*4)=2 -> 200 ; ceil(0.95*4)=4 -> 400
    assert.equal(stats.p50, 200);
    assert.equal(stats.p95, 400);
    const odd = percentilesFromTimings({ boot: 120, probe: 260, render: 700 });
    assert.equal(odd.count, 3);
    assert.equal(odd.p50, 260); // ceil(0.5*3)=2
    assert.equal(odd.p95, 700); // ceil(0.95*3)=3
  });

  check('percentilesFromTimings is deterministic and never mutates its input', () => {
    const timings: Record<string, number> = { z: 90, a: 10, m: 50 };
    const keys = Object.keys(timings);
    const snapshot = { ...timings };
    const first = percentilesFromTimings(timings);
    const second = percentilesFromTimings(timings);
    assert.deepEqual(first, second);
    assert.deepEqual(timings, snapshot);
    assert.deepEqual(Object.keys(timings), keys);
  });

  check('percentilesFromTimings is total on null/hostile input (neutral count=0)', () => {
    const neutral = { count: 0, p50: 0, p95: 0 };
    const hostile: unknown[] = [
      null,
      undefined,
      42,
      'x',
      [],
      { a: NaN },
      { a: Infinity },
      { a: '5' },
      { a: null },
    ];
    for (const value of hostile) {
      assert.deepEqual(
        percentilesFromTimings(value as unknown as Record<string, number>),
        neutral,
        `hostile input ${String(value)}`,
      );
    }
  });

  check('evaluateCollectorBudget reports the 250ms/800ms budgets descriptively', () => {
    assert.deepEqual(evaluateCollectorBudget({ count: 3, p50: 100, p95: 500 }), {
      p50Within250: true,
      p95Within800: true,
    });
    assert.deepEqual(evaluateCollectorBudget({ count: 3, p50: 300, p95: 900 }), {
      p50Within250: false,
      p95Within800: false,
    });
    // Boundary values are inclusive.
    assert.deepEqual(evaluateCollectorBudget({ count: 1, p50: 250, p95: 800 }), {
      p50Within250: true,
      p95Within800: true,
    });
  });

  check('evaluateCollectorBudget is total and neutral on hostile input', () => {
    const neutral = { p50Within250: false, p95Within800: false };
    const hostile: unknown[] = [null, undefined, 7, 'x', {}, { count: 0, p50: 0, p95: 0 }];
    for (const value of hostile) {
      assert.deepEqual(
        evaluateCollectorBudget(value as unknown as CollectorTimingStats),
        neutral,
      );
    }
  });

  check('buildTimingShadow composes stats + budget deterministically without side effects', () => {
    const timings = { boot: 120, probe: 260, render: 700 };
    const first = buildTimingShadow(timings);
    const second = buildTimingShadow(timings);
    assert.deepEqual(first, second);
    assert.deepEqual(first, {
      count: 3,
      p50: 260,
      p95: 700,
      budget: { p50Within250: false, p95Within800: true },
    });
    assert.deepEqual(buildTimingShadow(null), {
      count: 0,
      p50: 0,
      p95: 0,
      budget: { p50Within250: false, p95Within800: false },
    });
  });

  check('flag-off payload has no timing_shadow and load_get_timing is byte-identical', () => {
    // Mirror of the exact identify-body spread logic: the flag gate is the ONLY switch.
    const recordedTimings = { boot: 120, probe: 260 };
    const recordedTotalDuration = 900;
    const loadGetTiming = {
      source: 'signals.meta',
      timings_ms: recordedTimings,
      ...(typeof recordedTotalDuration === 'number' && Number.isFinite(recordedTotalDuration)
        ? { total_duration_ms: recordedTotalDuration }
        : {}),
    };
    const compose = (diagOn: boolean): Record<string, unknown> => ({
      ...(loadGetTiming ? { load_get_timing: loadGetTiming } : {}),
      ...(diagOn ? { timing_shadow: buildTimingShadow(recordedTimings) } : {}),
    });
    const off = compose(false);
    const on = compose(true);
    assert.deepEqual(Object.keys(off), ['load_get_timing']);
    assert.deepEqual(off, { load_get_timing: loadGetTiming });
    assert.equal(JSON.stringify(off.load_get_timing), JSON.stringify(on.load_get_timing));
    assert.deepEqual(Object.keys(on).sort(), ['load_get_timing', 'timing_shadow']);
    assert.deepEqual(on.timing_shadow, buildTimingShadow(recordedTimings));
  });
}

try {
  main();
} catch (error) {
  failures.push('<unexpected top-level error>');
  console.error('  FAIL  <unexpected top-level error>');
  console.error(`        ${error instanceof Error ? error.message : String(error)}`);
}

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}

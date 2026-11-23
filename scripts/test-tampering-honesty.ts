/**
 * P1-3 "tampering honesty" regression suite for src/lib/tamperingDetector.ts.
 *
 * Pins four honesty invariants:
 *  1. the canonical score producer is `tampering_rule_score` with provenance
 *     `baseline_constant`; the legacy `tampering_ml_score` key is a synchronized alias;
 *  2. collector `entropyTelemetry` is projected into `tampering_lies` as POINTS:0 reasons —
 *     no shadow score, canonical verdict, tier or anti_detect threshold may move;
 *  3. silent-buffer / cyclic `__proto__` / `iframe.contentWindow === window` are shadow-only
 *     STRONG indicators that abstain until observed and stay gated from promotion;
 *  4. cdc_* / webdriver / CDP artifacts stay decoupled and privacy hardening suppresses
 *     noise-only lies.
 *
 *   npx tsx scripts/test-tampering-honesty.ts
 */

import assert from 'node:assert/strict';
import { detectBrowserTampering, type TamperingAssessment } from '../src/lib/tamperingDetector';

/* -------------------------------------------------------------------------- */
/* Reporting                                                                   */
/* -------------------------------------------------------------------------- */

let passed = 0;
let failed = 0;

function check(id: string, label: string, body: () => void): void {
  try {
    body();
    passed += 1;
    console.log(`PASS  [${id}] ${label}`);
  } catch (error) {
    failed += 1;
    const message = error instanceof Error ? error.message : String(error);
    console.error(`FAIL  [${id}] ${label}\n      ${message}`);
  }
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

/* -------------------------------------------------------------------------- */
/* Browser globals — a clean Chrome desktop that trips no canonical rule       */
/* -------------------------------------------------------------------------- */

interface FakeWindow {
  outerWidth: number;
  outerHeight: number;
  innerWidth: number;
  innerHeight: number;
  screen: { width: number; height: number };
  matchMedia: (query: string) => { matches: boolean };
  chrome?: { runtime: unknown };
}

function installGlobals(): void {
  const navigatorStub = {
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36',
    platform: 'Win32',
    languages: ['en-US', 'en'],
    maxTouchPoints: 0,
    webdriver: false,
  };
  const windowStub: FakeWindow = {
    outerWidth: 1536,
    outerHeight: 960,
    innerWidth: 1520,
    innerHeight: 860,
    screen: { width: 1920, height: 1080 },
    matchMedia: () => ({ matches: true }),
  };
  const documentStub = {
    createElement: () => ({
      style: {},
      contentWindow: undefined,
      setAttribute: () => {},
      remove: () => {},
    }),
    body: { appendChild: () => {} },
  };
  Object.defineProperty(globalThis, 'window', { value: windowStub, configurable: true });
  Object.defineProperty(globalThis, 'document', { value: documentStub, configurable: true });
  Object.defineProperty(globalThis, 'navigator', { value: navigatorStub, configurable: true });
}

installGlobals();

/** The canonical baseline is recomputed after every global swap; shadow inputs never move it. */
function baseline(): TamperingAssessment {
  return detectBrowserTampering({});
}

/* -------------------------------------------------------------------------- */

function run(): void {
  section('A. Score producer honesty');

  check('A1', 'canonical rule score and provenance are published', () => {
    const result = baseline();
    assert.equal(typeof result.tampering_rule_score, 'number');
    assert.equal(result.tampering_score_source, 'baseline_constant');
    assert.equal(result.tampering_rule_score, result.tampering_ml_score);
    assert.equal(result.tampering_rule_score, 0.0024);
  });

  check('A2', 'deprecated alias stays synchronized through either name for one cycle', () => {
    const result = baseline();
    result.tampering_ml_score = 0.9;
    assert.equal(result.tampering_rule_score, 0.9);
    result.tampering_rule_score = 0.42;
    assert.equal(result.tampering_ml_score, 0.42);
    assert.equal(Object.prototype.hasOwnProperty.call(result, 'tampering_ml_score'), true);
    assert.equal(result.tampering_score_source, 'baseline_constant');
  });

  check('A3', 'a rule escalation still publishes the same value under both names', () => {
    const result = detectBrowserTampering({
      entropyTelemetry: {
        workerTriangulation: { available: true, strong: true, strong_fields: ['brands'] },
      },
    });
    assert.equal(result.tampering_rule_score, result.tampering_ml_score);
  });

  section('B. entropyTelemetry is projected as POINTS:0 reasons');

  check('B1', 'worker brands divergence is a zero-point shadow reason', () => {
    const clean = baseline();
    const result = detectBrowserTampering({
      entropyTelemetry: {
        workerTriangulation: { available: true, strong: true, strong_fields: ['brands'] },
      },
    });
    assert.ok(result.tampering_lies.reasons.some((r) => r.includes('brands divergence')), JSON.stringify(result.tampering_lies.reasons));
    assert.equal(result.tampering_lies.anomaly_score, 0);
    assert.equal(result.tampering_lies.anti_detect_browser, false);
    assert.equal(result.tampering_details.tampering_lies?.anomaly_score, 0);
    assert.equal(result.tampering_rule_score, clean.tampering_rule_score);
    assert.equal(result.tampering, clean.tampering);
    assert.equal(result.tampering_confidence, clean.tampering_confidence);
    assert.equal(result.tampering_details.anomaly_score, clean.tampering_details.anomaly_score);
    assert.equal(result.tampering_details.anti_detect_browser, clean.tampering_details.anti_detect_browser);
  });

  check('B2', 'ActiveText / repeat-read / soft worker drift are zero-point soft reasons', () => {
    const result = detectBrowserTampering({
      entropyTelemetry: {
        workerTriangulation: { available: true, soft: true, soft_fields: ['languages', 'languages'] },
        activeText: { color: 'rgb(255,0,0)', windows_blue: false, warning_soft: 0.5 },
        audioRepeatReadDiverged: true,
      },
    });
    const reasons = result.tampering_lies.reasons.join(' | ');
    assert.ok(reasons.includes('soft worker-triangulation drift'));
    assert.ok(reasons.includes('ActiveText color'));
    assert.ok(reasons.includes('repeated audio reads diverged'));
    assert.equal(result.tampering_lies.anomaly_score, 0);
    assert.equal(result.tampering_lies_rating.rating, 0.5);
    assert.equal(result.tampering_lies.anti_detect_browser, false);
  });

  check('B3', 'shader OS contradiction is a zero-point shadow reason', () => {
    const result = detectBrowserTampering({
      entropyTelemetry: {
        shaderPrecisionProfile: 'd3d11|highp',
        claimedGpuOs: 'Linux',
      },
    });
    assert.ok(result.tampering_lies.reasons.some((r) => r.includes('shader precision profile')), JSON.stringify(result.tampering_lies.reasons));
    assert.equal(result.tampering_lies.anomaly_score, 0);
    assert.equal(result.tampering_lies_rating.rating, 1);
    assert.equal(result.tampering_lies.anti_detect_browser, false);
    assert.equal(result.tampering_details.anti_detect_browser, false);
  });

  check('B4', 'privacy hardening suppresses noise-only entropy projections', () => {
    const result = detectBrowserTampering({
      privacyHardened: true,
      entropyTelemetry: {
        workerTriangulation: { available: true, soft: true, soft_fields: ['languages'] },
        activeText: { color: 'rgb(255,0,0)', warning_soft: 0.5 },
        audioRepeatReadDiverged: true,
        audioSilentBufferNonZero: true,
      },
    });
    const reasons = result.tampering_lies.reasons.join(' | ');
    assert.equal(reasons.includes('repeated audio reads diverged'), false);
    assert.equal(reasons.includes('silent audio buffer'), false);
    assert.equal(reasons.includes('ActiveText color'), false);
    assert.equal(reasons.includes('soft worker-triangulation drift'), false);
    assert.equal(result.tampering_lies.anomaly_score, 0);
  });

  check('B5', 'hard entropy contradictions survive privacy hardening but stay zero-point', () => {
    const result = detectBrowserTampering({
      privacyHardened: true,
      entropyTelemetry: {
        workerTriangulation: { available: true, strong: true, strong_fields: ['brands'] },
        shaderPrecisionProfile: 'd3d11|highp',
        claimedGpuOs: 'Linux',
      },
    });
    const reasons = result.tampering_lies.reasons.join(' | ');
    assert.ok(reasons.includes('brands divergence'));
    assert.ok(reasons.includes('shader precision profile'));
    assert.equal(result.tampering_lies.anomaly_score, 0);
    assert.equal(result.tampering_lies.anti_detect_browser, false);
  });

  section('C. Shadow-only STRONG indicators: abstain, zero points, gated');

  const strongCases: ReadonlyArray<readonly [string, string, Record<string, unknown>]> = [
    ['C1', 'silent buffer anomaly', { silentBufferAnomaly: true }],
    ['C2', 'cyclic __proto__ trap', { prototypeCyclicTrap: true }],
    ['C3', 'iframe.contentWindow === window', { iframeContentWindowEqualsWindow: true }],
  ];
  for (const [id, label, extras] of strongCases) {
    check(id, `${label} is a STRONG, zero-point, gated shadow reason`, () => {
      const clean = baseline();
      const result = detectBrowserTampering({ tamperingLies: extras });
      assert.equal(result.tampering_lies.anomaly_score, 0);
      assert.equal(result.tampering_lies_rating.rating, 1);
      assert.ok(result.tampering_lies_rating.strong_signals.length > 0);
      assert.equal(result.tampering_lies.anti_detect_browser, false);
      assert.equal(result.tampering_rule_score, clean.tampering_rule_score);
      assert.equal(result.tampering, clean.tampering);
      assert.equal(result.tampering_confidence, clean.tampering_confidence);
      assert.equal(result.tampering_details.anomaly_score, clean.tampering_details.anomaly_score);
      assert.equal(result.tampering_details.anti_detect_browser, clean.tampering_details.anti_detect_browser);
    });
  }

  check('C4', 'null / false observations abstain completely', () => {
    const result = detectBrowserTampering({
      tamperingLies: {
        silentBufferAnomaly: null,
        prototypeCyclicTrap: false,
        iframeContentWindowEqualsWindow: null,
      },
    });
    assert.deepEqual(result.tampering_lies, {
      anomaly_score: 0,
      anti_detect_browser: false,
      tampering_confidence: 'low',
      reasons: [],
    });
    assert.equal(result.tampering_lies_rating.rating, 0);
  });

  check('C5', 'scored resolver evidence opens the promotion gate without adding points', () => {
    const clean = baseline();
    const result = detectBrowserTampering({
      tamperingLies: {
        window: { ua: 'Mozilla/5.0 (Windows)' },
        dedicated: { ua: 'Mozilla/5.0 (X11; Linux)' },
        prototypeCyclicTrap: true,
      },
    });
    assert.equal(result.tampering_lies.anomaly_score, 0.25);
    assert.equal(result.tampering_lies.anti_detect_browser, true);
    assert.equal(result.tampering_rule_score, clean.tampering_rule_score);
    assert.equal(result.tampering, clean.tampering);
    assert.equal(result.tampering_details.anti_detect_browser, clean.tampering_details.anti_detect_browser);
  });

  check('C6', 'an explicit caller gate opens promotion for zero-point indicators only', () => {
    const result = detectBrowserTampering({
      tamperingLies: {
        iframeContentWindowEqualsWindow: true,
        shadowStrongGate: true,
      },
    });
    assert.equal(result.tampering_lies.anomaly_score, 0);
    assert.equal(result.tampering_lies.anti_detect_browser, true);
  });

  section('D. Automation artifact decoupling');

  check('D1', 'automationArtifactOnly still vetoes the shadow flag beside hard evidence', () => {
    const result = detectBrowserTampering({
      tamperingLies: {
        window: { ua: 'Mozilla/5.0 (Windows)' },
        dedicated: { ua: 'Mozilla/5.0 (X11; Linux)' },
        prototypeCyclicTrap: true,
        automationArtifactOnly: true,
      },
    });
    assert.equal(result.tampering_lies.anomaly_score, 0.25);
    assert.equal(result.tampering_lies.anti_detect_browser, false);
    assert.equal(result.tampering_details.anti_detect_browser, false);
  });

  check('D2', 'automation stack frames are artifact-only and cannot set the flag', () => {
    const result = detectBrowserTampering({
      tamperingLies: {
        automationStackFrames: true,
        silentBufferAnomaly: true,
      },
    });
    assert.equal(result.tampering_lies.anti_detect_browser, false);
    assert.ok(result.tampering_lies.reasons.some((r) => r.includes('automation stack frames')));
  });

  check('D3', 'noise-only lies never move the canonical score or tier', () => {
    const clean = baseline();
    const result = detectBrowserTampering({
      entropyTelemetry: {
        workerTriangulation: { strong: true, strong_fields: ['brands'] },
        activeText: { warning_soft: 0.5 },
        audioRepeatReadDiverged: true,
      },
      tamperingLies: {
        silentBufferAnomaly: true,
        iframeContentWindowEqualsWindow: true,
        shadowStrongGate: true,
      },
    });
    assert.equal(result.tampering, clean.tampering);
    assert.equal(result.tampering_confidence, clean.tampering_confidence);
    assert.equal(result.tampering_rule_score, clean.tampering_rule_score);
    assert.equal(result.tampering_details.anomaly_score, clean.tampering_details.anomaly_score);
    assert.equal(result.tampering_details.anti_detect_browser, clean.tampering_details.anti_detect_browser);
    assert.equal(result.tampering_details.devtools_device_emulation, clean.tampering_details.devtools_device_emulation);
  });
}

/* -------------------------------------------------------------------------- */

let runFailed = false;
try {
  run();
} catch (error) {
  runFailed = true;
  const message = error instanceof Error ? error.message : String(error);
  console.error(`FAIL  [fatal] unexpected error: ${message}`);
} finally {
  const failedTotal = failed + (runFailed ? 1 : 0);
  if (failedTotal === 0) {
    console.log(`\nRESULT: PASS — ${passed} passed, 0 failed`);
  } else {
    console.log(`\nRESULT: FAIL — ${passed} passed, ${failedTotal} failed`);
    process.exitCode = 1;
  }
}

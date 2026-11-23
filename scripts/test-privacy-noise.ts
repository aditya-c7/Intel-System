/**
 * Regression suite for src/lib/privacyNoise.ts (SHADOW-ONLY additive helper).
 *
 * Pins the documented invariants:
 *  - privacyHardened + canvas/audio/shader noise => privacy_settings=true,
 *    anti_detect_browser=false, anomaly_score=0;
 *  - only the four accepted vendor families (Brave, Firefox RFP, Tor, Safari AFP) fire
 *    privacy_settings;
 *  - automation artifacts and locales never create a privacy signature or anti-detect;
 *  - only a hard contradiction sets anti_detect_browser with anomaly_score>0, clamped 0..1;
 *  - hostile getters / proxies and malformed payloads degrade without throwing;
 *  - the classifier is pure, deterministic, and always returns a non-empty audit trail.
 *
 *   npx tsx scripts/test-privacy-noise.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 */

import assert from 'node:assert/strict';

import {
  classifyPrivacyNoise,
  type PrivacyNoiseInput,
  type PrivacyNoiseResult,
} from '../src/lib/privacyNoise';

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

/** Object whose every property read throws, used to prove totality on hostile input. */
function hostileInput(): PrivacyNoiseInput {
  return new Proxy(
    {},
    {
      get(): never {
        throw new Error('hostile getter');
      },
    },
  ) as PrivacyNoiseInput;
}

/** A getter that throws on one field, to prove per-field isolation of guarded reads. */
function partiallyHostileInput(): PrivacyNoiseInput {
  return {
    get privacyHardened(): boolean {
      throw new Error('hostile privacyHardened getter');
    },
    vendorSignature: 'Brave',
  } as PrivacyNoiseInput;
}

/* -------------------------------------------------------------------------- */

function run(): void {
  check('setup', 'classifyPrivacyNoise is exported as a function', () => {
    assert.equal(typeof classifyPrivacyNoise, 'function');
  });

  section('A. privacyHardened noise');

  check('A1', 'privacyHardened + canvasNoise is a privacy signature, not anti-detect', () => {
    const verdict = classifyPrivacyNoise({ privacyHardened: true, canvasNoise: true });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
    assert.ok(verdict.reasons.some((reason) => reason.includes('explains canvas noise')));
  });

  check('A2', 'privacyHardened + all three noise channels stays clean', () => {
    const verdict = classifyPrivacyNoise({
      privacyHardened: true,
      canvasNoise: true,
      audioNoise: true,
      shaderNoise: true,
    });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('canvas/audio/shader noise')),
      JSON.stringify(verdict.reasons),
    );
  });

  check('A3', 'privacyHardened alone is an explicit privacy signature', () => {
    const verdict = classifyPrivacyNoise({ privacyHardened: true });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
    assert.ok(verdict.reasons.some((reason) => reason.includes('Explicit privacy-hardened runtime')));
  });

  section('B. Accepted vendor signatures');

  const acceptedVendors: ReadonlyArray<readonly [string, string]> = [
    ['brave', 'Brave'],
    ['firefox-rfp', 'Firefox RFP'],
    ['tor', 'Tor'],
    ['safari-afp', 'Safari AFP'],
  ];

  for (const [index, [token, family]] of acceptedVendors.entries()) {
    check(`B${index + 1}`, `${token} is accepted as ${family}`, () => {
      const verdict = classifyPrivacyNoise({ vendorSignature: token });
      assert.equal(verdict.privacy_settings, true);
      assert.equal(verdict.anti_detect_browser, false);
      assert.equal(verdict.anomaly_score, 0);
      assert.ok(
        verdict.reasons.some((reason) => reason.includes(`Accepted vendor privacy signature: ${family}`)),
        JSON.stringify(verdict.reasons),
      );
    });
  }

  check('B5', 'vendor signature matching normalizes case and separators', () => {
    for (const token of ['Brave-Shields', 'FIREFOX RFP', 'TOR Browser', 'Safari/AFP']) {
      const verdict = classifyPrivacyNoise({ vendorSignature: token });
      assert.equal(verdict.privacy_settings, true, `token=${token}`);
      assert.equal(verdict.anti_detect_browser, false);
      assert.equal(verdict.anomaly_score, 0);
    }
  });

  section('C. Automation artifacts and locales are never signatures');

  check('C1', 'a locale tag creates neither privacy signature nor anti-detect', () => {
    for (const locale of ['en-US', 'de_DE', 'zh-Hans-CN']) {
      const verdict = classifyPrivacyNoise({ vendorSignature: locale });
      assert.equal(verdict.privacy_settings, false, `locale=${locale}`);
      assert.equal(verdict.anti_detect_browser, false);
      assert.equal(verdict.anomaly_score, 0);
      assert.ok(
        verdict.reasons.some((reason) => reason.includes('Unrecognized vendor signature ignored')),
        JSON.stringify(verdict.reasons),
      );
    }
  });

  check('C2', 'automation artifacts create neither privacy signature nor anti-detect', () => {
    for (const artifact of ['cdp', 'playwright', 'puppeteer', 'webdriver', 'marionette']) {
      const verdict = classifyPrivacyNoise({ vendorSignature: artifact });
      assert.equal(verdict.privacy_settings, false, `artifact=${artifact}`);
      assert.equal(verdict.anti_detect_browser, false);
      assert.equal(verdict.anomaly_score, 0);
    }
  });

  check('C3', 'noise alone is not a privacy signature and not anti-detect', () => {
    const verdict = classifyPrivacyNoise({ canvasNoise: true, audioNoise: true, shaderNoise: true });
    assert.equal(verdict.privacy_settings, false);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('abstaining (noise may be an automation artifact)')),
      JSON.stringify(verdict.reasons),
    );
  });

  check('C4', 'noise + automation artifact still abstains', () => {
    const verdict = classifyPrivacyNoise({ canvasNoise: true, vendorSignature: 'webdriver' });
    assert.equal(verdict.privacy_settings, false);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
  });

  section('D. Hard contradiction');

  check('D1', 'hard contradiction alone sets anti_detect with a positive clamped score', () => {
    const verdict = classifyPrivacyNoise({ hardContradiction: true });
    assert.equal(verdict.privacy_settings, false);
    assert.equal(verdict.anti_detect_browser, true);
    assert.ok(verdict.anomaly_score > 0 && verdict.anomaly_score <= 1, `score=${verdict.anomaly_score}`);
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('Hard contradiction present')),
      JSON.stringify(verdict.reasons),
    );
  });

  check('D2', 'hard contradiction is not suppressed by privacy hardening', () => {
    const verdict = classifyPrivacyNoise({
      privacyHardened: true,
      canvasNoise: true,
      hardContradiction: true,
    });
    assert.equal(verdict.privacy_settings, true, 'the explicit signature is not erased');
    assert.equal(verdict.anti_detect_browser, true);
    assert.ok(verdict.anomaly_score > 0 && verdict.anomaly_score <= 1);
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('cannot be explained away by privacy hardening')),
      JSON.stringify(verdict.reasons),
    );
  });

  check('D3', 'hard contradiction with an accepted vendor still reports anti-detect', () => {
    const verdict = classifyPrivacyNoise({ vendorSignature: 'tor', hardContradiction: true });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.anti_detect_browser, true);
    assert.ok(verdict.anomaly_score > 0 && verdict.anomaly_score <= 1);
  });

  check('D4', 'anomaly_score never leaves 0..1 across representative inputs', () => {
    const inputs: PrivacyNoiseInput[] = [
      {},
      { canvasNoise: true },
      { privacyHardened: true, audioNoise: true },
      { vendorSignature: 'brave' },
      { hardContradiction: true },
      { privacyHardened: true, hardContradiction: true, shaderNoise: true },
    ];
    for (const input of inputs) {
      const score = classifyPrivacyNoise(input).anomaly_score;
      assert.ok(Number.isFinite(score), `non-finite score for ${JSON.stringify(input)}`);
      assert.ok(score >= 0 && score <= 1, `score=${score} for ${JSON.stringify(input)}`);
    }
  });

  section('E. Totality on malformed and hostile input');

  check('E1', 'null / primitive / array inputs degrade to safe defaults', () => {
    for (const input of [null, undefined, 42, 'privacy', []]) {
      const verdict = classifyPrivacyNoise(input as unknown as PrivacyNoiseInput);
      assert.equal(verdict.privacy_settings, false);
      assert.equal(verdict.anti_detect_browser, false);
      assert.equal(verdict.anomaly_score, 0);
      assert.ok(verdict.reasons.length > 0, 'reasons must never be empty');
    }
  });

  check('E2', 'an all-throwing proxy never throws and yields safe defaults', () => {
    let verdict: PrivacyNoiseResult | undefined;
    assert.doesNotThrow(() => {
      verdict = classifyPrivacyNoise(hostileInput());
    });
    assert.equal(verdict?.privacy_settings, false);
    assert.equal(verdict?.anti_detect_browser, false);
    assert.equal(verdict?.anomaly_score, 0);
    assert.ok((verdict?.reasons.length ?? 0) > 0);
  });

  check('E3', 'one hostile getter does not hide the remaining good evidence', () => {
    let verdict: PrivacyNoiseResult | undefined;
    assert.doesNotThrow(() => {
      verdict = classifyPrivacyNoise(partiallyHostileInput());
    });
    assert.equal(verdict?.privacy_settings, true, 'braveSignature is still readable');
    assert.equal(verdict?.anti_detect_browser, false);
    assert.ok(
      verdict?.reasons.some((reason) => reason.includes('Accepted vendor privacy signature: Brave')),
      JSON.stringify(verdict?.reasons),
    );
  });

  check('E4', 'only literal true counts for boolean flags', () => {
    for (const junk of [1, 'true', {}, [], false, null, undefined]) {
      const verdict = classifyPrivacyNoise({
        privacyHardened: junk as unknown as boolean,
        canvasNoise: junk as unknown as boolean,
        hardContradiction: junk as unknown as boolean,
      });
      assert.equal(verdict.privacy_settings, false, `junk=${JSON.stringify(junk)}`);
      assert.equal(verdict.anti_detect_browser, false);
      assert.equal(verdict.anomaly_score, 0);
    }
  });

  check('E5', 'a non-string vendor signature is ignored', () => {
    for (const junk of [1, true, {}, ['tor']]) {
      const verdict = classifyPrivacyNoise({ vendorSignature: junk as unknown as string });
      assert.equal(verdict.privacy_settings, false, `junk=${JSON.stringify(junk)}`);
      assert.equal(verdict.anti_detect_browser, false);
      assert.equal(verdict.anomaly_score, 0);
    }
  });

  section('F. Purity / determinism');

  check('F1', 'classifier does not mutate its input', () => {
    const input: PrivacyNoiseInput = {
      privacyHardened: true,
      canvasNoise: true,
      hardContradiction: true,
      vendorSignature: 'brave',
    };
    const before = JSON.stringify(input);
    classifyPrivacyNoise(input);
    assert.equal(JSON.stringify(input), before, 'input object must be untouched');
  });

  check('F2', 'repeated calls on the same input return the same verdict', () => {
    const input: PrivacyNoiseInput = {
      privacyHardened: true,
      audioNoise: true,
      shaderNoise: true,
      hardContradiction: true,
    };
    assert.deepEqual(classifyPrivacyNoise(input), classifyPrivacyNoise(input));
  });

  check('F3', 'reasons are always a non-empty string array', () => {
    const cases: PrivacyNoiseInput[] = [
      {},
      { privacyHardened: true, canvasNoise: true },
      { vendorSignature: 'en-US' },
      { hardContradiction: true },
      { canvasNoise: true },
    ];
    for (const input of cases) {
      const reasons = classifyPrivacyNoise(input).reasons;
      assert.ok(Array.isArray(reasons) && reasons.length > 0, JSON.stringify(input));
      assert.ok(reasons.every((reason) => typeof reason === 'string'));
    }
  });

  check('F4', 'omitting input entirely resolves to a clean abstention', () => {
    const verdict = classifyPrivacyNoise();
    assert.equal(verdict.privacy_settings, false);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
  });
}

/* -------------------------------------------------------------------------- */

let runFailed = false;
try {
  run();
} catch (error) {
  // Absolute last-resort guard: even a catastrophic failure is reported, not thrown.
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

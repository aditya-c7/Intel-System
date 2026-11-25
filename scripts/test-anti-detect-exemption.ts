/**
 * Regression suite for src/lib/antiDetectExemption.ts (SHADOW-ONLY additive helper).
 *
 * Pins the documented invariants:
 *  - `privacyHardened` or an accepted `vendorSignature`, together with `noiseOnly`, is the
 *    ONLY path to `suppressPenalty=true` (with `anti_detect_browser=false`, `anomaly_score=0`);
 *  - `automationArtifact` alone (boolean or token string) NEVER sets `anti_detect_browser`;
 *  - only `hardContradiction` sets `anti_detect_browser=true` with a non-zero score, and it
 *    wins even when privacy hardening / a vendor signature / noise-only are all present;
 *  - hostile getters / proxies and malformed payloads degrade to safe defaults without throwing;
 *  - the resolver is pure: it does not mutate its input and is deterministic.
 *
 *   npx tsx scripts/test-anti-detect-exemption.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 */

import assert from 'node:assert/strict';

import {
  resolveAntiDetectExemption,
  type AntiDetectExemptionInput,
  type AntiDetectExemptionResult,
} from '../src/lib/antiDetectExemption';

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
function hostileInput(): AntiDetectExemptionInput {
  return new Proxy(
    {},
    {
      get(): never {
        throw new Error('hostile getter');
      },
    },
  ) as AntiDetectExemptionInput;
}

/** A getter that throws on a single field, to prove per-field isolation of guarded reads. */
function partiallyHostileInput(): AntiDetectExemptionInput {
  return {
    get privacyHardened(): boolean {
      throw new Error('hostile privacyHardened getter');
    },
    vendorSignature: 'Brave',
    noiseOnly: true,
  } as AntiDetectExemptionInput;
}

function isInUnitRange(value: number): boolean {
  return Number.isFinite(value) && value >= 0 && value <= 1;
}

/* -------------------------------------------------------------------------- */

function run(): void {
  check('setup', 'resolveAntiDetectExemption is exported as a function', () => {
    assert.equal(typeof resolveAntiDetectExemption, 'function');
  });

  section('A. The exemption rule: (posture OR vendor) + noiseOnly');

  check('A1', 'privacyHardened + noiseOnly suppresses the penalty', () => {
    const verdict = resolveAntiDetectExemption({ privacyHardened: true, noiseOnly: true });
    assert.equal(verdict.suppressPenalty, true);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
    assert.ok(verdict.reasons.some((reason) => reason.includes('Exemption granted')));
  });

  check('A2', 'an allowlisted vendor string + noiseOnly suppresses the penalty', () => {
    for (const vendor of ['Brave', 'Firefox-RFP', 'TOR Browser', 'Safari AFP', 'rfp']) {
      const verdict = resolveAntiDetectExemption({ vendorSignature: vendor, noiseOnly: true });
      assert.equal(verdict.suppressPenalty, true, `vendor=${vendor}`);
      assert.equal(verdict.anti_detect_browser, false, `vendor=${vendor}`);
      assert.equal(verdict.anomaly_score, 0, `vendor=${vendor}`);
      assert.ok(verdict.reasons.some((reason) => reason.includes('Accepted vendor privacy signature')));
    }
  });

  check('A3', 'a bare boolean vendorSignature=true is not vendor evidence and cannot suppress', () => {
    const verdict = resolveAntiDetectExemption({ vendorSignature: true, noiseOnly: true });
    assert.equal(verdict.suppressPenalty, false);
    assert.ok(verdict.reasons.some((reason) => /vendor/i.test(reason) && /ignor|unrecognized/i.test(reason)));
  });

  check('A4', 'privacyHardened and vendorSignature together still suppress (no double count)', () => {
    const verdict = resolveAntiDetectExemption({
      privacyHardened: true,
      vendorSignature: 'Brave',
      noiseOnly: true,
    });
    assert.equal(verdict.suppressPenalty, true);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
  });

  check('A5', 'posture without noiseOnly does NOT suppress and does NOT flag anti-detect', () => {
    const verdict = resolveAntiDetectExemption({ privacyHardened: true, noiseOnly: false });
    assert.equal(verdict.suppressPenalty, false);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
    assert.ok(verdict.reasons.some((reason) => reason.includes('noise-only condition missing')));
  });

  check('A6', 'posture with noiseOnly omitted does NOT suppress', () => {
    const verdict = resolveAntiDetectExemption({ vendorSignature: 'Tor' });
    assert.equal(verdict.suppressPenalty, false);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
  });

  check('A7', 'noiseOnly alone (no posture, no vendor) does NOT suppress', () => {
    const verdict = resolveAntiDetectExemption({ noiseOnly: true });
    assert.equal(verdict.suppressPenalty, false);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
    assert.ok(verdict.reasons.some((reason) => reason.includes('Noise alone does not earn the exemption')));
  });

  check('A8', 'an empty / default input abstains', () => {
    const verdict = resolveAntiDetectExemption();
    assert.equal(verdict.suppressPenalty, false);
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
    assert.ok(verdict.reasons.some((reason) => reason.includes('abstaining')));
  });

  section('B. Only hardContradiction sets anti_detect_browser');

  check('B1', 'hardContradiction alone flags anti-detect with a positive score', () => {
    const verdict = resolveAntiDetectExemption({ hardContradiction: true });
    assert.equal(verdict.anti_detect_browser, true);
    assert.ok(verdict.anomaly_score > 0);
    assert.ok(isInUnitRange(verdict.anomaly_score));
    assert.equal(verdict.suppressPenalty, false);
  });

  check('B2', 'hardContradiction overrides privacyHardened + noiseOnly', () => {
    const verdict = resolveAntiDetectExemption({
      privacyHardened: true,
      noiseOnly: true,
      hardContradiction: true,
    });
    assert.equal(verdict.anti_detect_browser, true, 'even if privacyHardened');
    assert.ok(verdict.anomaly_score > 0);
    assert.equal(verdict.suppressPenalty, false, 'exemption must be revoked');
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('cannot be explained away')),
      JSON.stringify(verdict.reasons),
    );
  });

  check('B3', 'hardContradiction overrides vendorSignature + noiseOnly', () => {
    const verdict = resolveAntiDetectExemption({
      vendorSignature: 'Firefox RFP',
      noiseOnly: true,
      hardContradiction: true,
    });
    assert.equal(verdict.anti_detect_browser, true);
    assert.ok(verdict.anomaly_score > 0);
    assert.equal(verdict.suppressPenalty, false);
  });

  check('B4', 'hardContradiction with an automation artifact still flags anti-detect', () => {
    const verdict = resolveAntiDetectExemption({
      hardContradiction: true,
      automationArtifact: true,
    });
    assert.equal(verdict.anti_detect_browser, true);
    assert.ok(verdict.anomaly_score > 0);
  });

  check('B5', 'hardContradiction=false never flags anti-detect', () => {
    const verdict = resolveAntiDetectExemption({
      hardContradiction: false,
      noiseOnly: true,
      privacyHardened: true,
    });
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
  });

  section('C. automationArtifact is diagnostic only');

  check('C1', 'automationArtifact alone (boolean) never sets anti-detect', () => {
    const verdict = resolveAntiDetectExemption({ automationArtifact: true });
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
    assert.equal(verdict.suppressPenalty, false);
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('never sets anti_detect_browser')),
      JSON.stringify(verdict.reasons),
    );
  });

  check('C2', 'automation token strings alone never set anti-detect', () => {
    for (const token of ['cdp', 'playwright', 'cdc', 'chrome-headless-shell']) {
      const verdict = resolveAntiDetectExemption({ automationArtifact: token });
      assert.equal(verdict.anti_detect_browser, false, `token=${token}`);
      assert.equal(verdict.anomaly_score, 0, `token=${token}`);
      assert.equal(verdict.suppressPenalty, false, `token=${token}`);
    }
  });

  check('C3', 'automationArtifact + noiseOnly (no posture) grants no exemption', () => {
    const verdict = resolveAntiDetectExemption({ automationArtifact: true, noiseOnly: true });
    assert.equal(verdict.anti_detect_browser, false);
    assert.equal(verdict.anomaly_score, 0);
    assert.equal(verdict.suppressPenalty, false);
  });

  check('C4', 'automation token supplied as vendorSignature is ignored', () => {
    const verdict = resolveAntiDetectExemption({ vendorSignature: 'cdp', noiseOnly: true });
    assert.equal(verdict.suppressPenalty, false);
    assert.equal(verdict.anti_detect_browser, false);
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('Unrecognized vendor signature ignored')),
      JSON.stringify(verdict.reasons),
    );
  });

  section('D. Malformed values and untrusted inputs');

  check('D1', 'false / null / truthy junk flags are all treated as absence of evidence', () => {
    for (const value of [false, null, undefined, 1, 'true', {}, []]) {
      const verdict = resolveAntiDetectExemption({
        privacyHardened: value as unknown as boolean,
        hardContradiction: value as unknown as boolean,
        noiseOnly: value as unknown as boolean,
        vendorSignature: value as unknown as string,
        automationArtifact: value as unknown as string,
      });
      assert.equal(verdict.anti_detect_browser, false, `value=${JSON.stringify(value)}`);
      assert.equal(verdict.suppressPenalty, false, `value=${JSON.stringify(value)}`);
      assert.equal(verdict.anomaly_score, 0, `value=${JSON.stringify(value)}`);
    }
  });

  check('D2', 'null / primitive / array inputs degrade to safe defaults', () => {
    for (const input of [null, undefined, 42, 'privacy', []]) {
      const verdict = resolveAntiDetectExemption(input as unknown as AntiDetectExemptionInput);
      assert.equal(verdict.anti_detect_browser, false);
      assert.equal(verdict.suppressPenalty, false);
      assert.equal(verdict.anomaly_score, 0);
      assert.ok(verdict.reasons.length > 0, 'reasons must never be empty');
    }
  });

  check('D3', 'an all-throwing proxy never throws and yields safe defaults', () => {
    let verdict: AntiDetectExemptionResult | undefined;
    assert.doesNotThrow(() => {
      verdict = resolveAntiDetectExemption(hostileInput());
    });
    assert.equal(verdict?.anti_detect_browser, false);
    assert.equal(verdict?.suppressPenalty, false);
    assert.equal(verdict?.anomaly_score, 0);
    assert.ok((verdict?.reasons.length ?? 0) > 0);
  });

  check('D4', 'one hostile getter does not hide the remaining good evidence', () => {
    let verdict: AntiDetectExemptionResult | undefined;
    assert.doesNotThrow(() => {
      verdict = resolveAntiDetectExemption(partiallyHostileInput());
    });
    assert.equal(verdict?.suppressPenalty, true, 'vendorSignature=Brave + noiseOnly are still readable');
    assert.equal(verdict?.anti_detect_browser, false);
    assert.equal(verdict?.anomaly_score, 0);
  });

  check('D5', 'locale / unrelated strings are not accepted as vendor signatures', () => {
    for (const vendor of ['en-US', 'windows', '', '   ', 'unknown-vendor']) {
      const verdict = resolveAntiDetectExemption({ vendorSignature: vendor, noiseOnly: true });
      assert.equal(verdict.suppressPenalty, false, `vendor=${JSON.stringify(vendor)}`);
      assert.equal(verdict.anti_detect_browser, false);
    }
  });

  section('E. Score invariants');

  check('E1', 'anomaly_score is always within [0, 1]', () => {
    const cases: AntiDetectExemptionInput[] = [
      {},
      { privacyHardened: true, noiseOnly: true },
      { hardContradiction: true },
      { hardContradiction: true, privacyHardened: true, noiseOnly: true },
      { automationArtifact: true, noiseOnly: true },
    ];
    for (const input of cases) {
      assert.ok(isInUnitRange(resolveAntiDetectExemption(input).anomaly_score), JSON.stringify(input));
    }
  });

  check('E2', 'anti_detect_browser=true implies a positive score, and vice versa', () => {
    const inputs: AntiDetectExemptionInput[] = [
      { hardContradiction: true },
      { privacyHardened: true, noiseOnly: true },
      { automationArtifact: true },
      { hardContradiction: true, vendorSignature: 'Tor', noiseOnly: true },
    ];
    for (const input of inputs) {
      const verdict = resolveAntiDetectExemption(input);
      assert.equal(
        verdict.anti_detect_browser,
        verdict.anomaly_score > 0,
        `score/flag must agree for ${JSON.stringify(input)}`,
      );
    }
  });

  check('E3', 'suppressPenalty=true never coexists with anti_detect_browser=true', () => {
    const inputs: AntiDetectExemptionInput[] = [
      { privacyHardened: true, noiseOnly: true },
      { vendorSignature: 'Safari AFP', noiseOnly: true },
      { privacyHardened: true, noiseOnly: true, hardContradiction: true },
      { hardContradiction: true },
    ];
    for (const input of inputs) {
      const verdict = resolveAntiDetectExemption(input);
      assert.equal(
        verdict.suppressPenalty && verdict.anti_detect_browser,
        false,
        `mutually exclusive for ${JSON.stringify(input)}`,
      );
    }
  });

  section('F. Purity / determinism');

  check('F1', 'resolver does not mutate its input', () => {
    const input: AntiDetectExemptionInput = {
      privacyHardened: true,
      vendorSignature: 'Brave',
      noiseOnly: true,
      automationArtifact: 'cdp',
      hardContradiction: false,
    };
    const before = JSON.stringify(input);
    resolveAntiDetectExemption(input);
    assert.equal(JSON.stringify(input), before, 'input object must be untouched');
  });

  check('F2', 'repeated calls on the same input return the same verdict', () => {
    const input: AntiDetectExemptionInput = {
      privacyHardened: true,
      noiseOnly: true,
      hardContradiction: false,
    };
    assert.deepEqual(resolveAntiDetectExemption(input), resolveAntiDetectExemption(input));
  });

  check('F3', 'every verdict carries a non-empty reasons array', () => {
    const inputs: AntiDetectExemptionInput[] = [
      {},
      { privacyHardened: true, noiseOnly: true },
      { hardContradiction: true },
      { automationArtifact: 'playwright' },
    ];
    for (const input of inputs) {
      const verdict = resolveAntiDetectExemption(input);
      assert.ok(Array.isArray(verdict.reasons));
      assert.ok(verdict.reasons.length > 0, `reasons empty for ${JSON.stringify(input)}`);
    }
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

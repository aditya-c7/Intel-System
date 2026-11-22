/**
 * Regression suite for src/lib/privacySignatures.ts (SHADOW-ONLY additive helper).
 *
 * Pins the documented invariants:
 *  - only explicit vendor signatures (Brave, Firefox RFP >=2 probes, Tor, Safari AFP) or
 *    reducedEntropy with >=2 corroborations can fire `privacy_settings`;
 *  - `automationArtifact` never creates a signature or a corroboration;
 *  - `suppressAntiDetectPenalty` requires a fired signature AND no contradiction evidence;
 *  - hostile getters / proxies and malformed payloads degrade to safe defaults without throwing;
 *  - the resolver is pure: it does not mutate its input and is deterministic.
 *
 *   npx tsx scripts/test-privacy-signatures.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 */

import assert from 'node:assert/strict';

import {
  resolvePrivacySignatures,
  type PrivacySignalsInput,
  type PrivacySignatureResult,
} from '../src/lib/privacySignatures';

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
function hostileInput(): PrivacySignalsInput {
  return new Proxy(
    {},
    {
      get(): never {
        throw new Error('hostile getter');
      },
    },
  ) as PrivacySignalsInput;
}

/** A getter that throws on a single field, to prove per-field isolation of guarded reads. */
function partiallyHostileInput(): PrivacySignalsInput {
  return {
    get braveNavigator(): boolean {
      throw new Error('hostile braveNavigator getter');
    },
    braveShields: true,
  } as PrivacySignalsInput;
}

/* -------------------------------------------------------------------------- */

function run(): void {
  check('setup', 'resolvePrivacySignatures is exported as a function', () => {
    assert.equal(typeof resolvePrivacySignatures, 'function');
  });

  section('A. Brave signatures');

  check('A1', 'braveNavigator is an explicit Brave signature', () => {
    const verdict = resolvePrivacySignatures({ braveNavigator: true });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.privacy_hardened, true);
    assert.equal(verdict.suppressAntiDetectPenalty, true);
    assert.equal(verdict.confidence, 'high');
    assert.ok(verdict.signatures.includes('brave-navigator'), JSON.stringify(verdict.signatures));
    assert.ok(verdict.reasons.some((reason) => reason.includes('Explicit Brave signature')));
  });

  check('A2', 'braveShields alone is an explicit Brave signature (medium confidence)', () => {
    const verdict = resolvePrivacySignatures({ braveShields: true });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.suppressAntiDetectPenalty, true);
    assert.equal(verdict.confidence, 'medium');
    assert.ok(verdict.signatures.includes('brave-shields'), JSON.stringify(verdict.signatures));
  });

  check('A3', 'false / null / truthy junk never fire a signature', () => {
    for (const value of [false, null, undefined, 1, 'true', {}, []]) {
      const verdict = resolvePrivacySignatures({
        braveNavigator: value as unknown as boolean,
        braveShields: value as unknown as boolean,
      });
      assert.equal(verdict.privacy_settings, false, `brave value=${JSON.stringify(value)}`);
      assert.deepEqual(verdict.signatures, []);
      assert.equal(verdict.suppressAntiDetectPenalty, false);
    }
  });

  section('B. Firefox Resist Fingerprinting');

  check('B1', 'two independent RFP probes establish Firefox RFP', () => {
    const verdict = resolvePrivacySignatures({
      firefoxRfpUtc: true,
      firefoxRfpRoundedViewport: true,
    });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.confidence, 'high');
    assert.ok(verdict.signatures.includes('firefox-rfp-utc'), JSON.stringify(verdict.signatures));
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('Explicit Firefox RFP signature')),
      JSON.stringify(verdict.reasons),
    );
  });

  check('B2', 'all three RFP probes fire with high confidence', () => {
    const verdict = resolvePrivacySignatures({
      firefoxRfpUtc: true,
      firefoxRfpRoundedViewport: true,
      firefoxRfpCoresCapped: true,
    });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.confidence, 'high');
    assert.equal(verdict.suppressAntiDetectPenalty, true);
    assert.equal(
      ['firefox-rfp-utc', 'firefox-rfp-rounded-viewport', 'firefox-rfp-cores-capped'].every((token) =>
        verdict.signatures.includes(token),
      ),
      true,
      JSON.stringify(verdict.signatures),
    );
  });

  check('B3', 'a single RFP probe is recorded but is not a vendor signature', () => {
    for (const field of ['firefoxRfpUtc', 'firefoxRfpRoundedViewport', 'firefoxRfpCoresCapped'] as const) {
      const verdict = resolvePrivacySignatures({ [field]: true });
      assert.equal(verdict.privacy_settings, false, `field=${field}`);
      assert.equal(verdict.suppressAntiDetectPenalty, false);
      assert.equal(verdict.signatures.length, 1);
      assert.ok(
        verdict.reasons.some((reason) => reason.includes('at least two are required')),
        JSON.stringify(verdict.reasons),
      );
    }
  });

  section('C. Tor signatures');

  check('C1', 'torLetterboxing is an explicit Tor Browser signature', () => {
    const verdict = resolvePrivacySignatures({ torLetterboxing: true });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.confidence, 'high');
    assert.ok(verdict.signatures.includes('tor-letterboxing'), JSON.stringify(verdict.signatures));
  });

  check('C2', 'torExit is a Tor signature (network-level, medium confidence)', () => {
    const verdict = resolvePrivacySignatures({ torExit: true });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.confidence, 'medium');
    assert.ok(verdict.signatures.includes('tor-exit'), JSON.stringify(verdict.signatures));
    assert.ok(verdict.reasons.some((reason) => reason.includes('Explicit Tor signature')));
  });

  check('C3', 'torExit + torLetterboxing corroborate each other', () => {
    const verdict = resolvePrivacySignatures({ torExit: true, torLetterboxing: true });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.confidence, 'high');
    assert.deepEqual(verdict.signatures, ['tor-exit', 'tor-letterboxing']);
  });

  section('D. Safari AFP');

  check('D1', 'safariAfp is an explicit Safari signature', () => {
    const verdict = resolvePrivacySignatures({ safariAfp: true });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.privacy_hardened, true);
    assert.equal(verdict.suppressAntiDetectPenalty, true);
    assert.equal(verdict.confidence, 'high');
    assert.ok(verdict.signatures.includes('safari-afp'), JSON.stringify(verdict.signatures));
    assert.ok(verdict.reasons.some((reason) => reason.includes('Explicit Safari AFP signature')));
  });

  section('E. reducedEntropy corroboration path');

  check('E1', 'reducedEntropy with two corroborations fires privacy_settings', () => {
    const verdict = resolvePrivacySignatures({
      reducedEntropy: true,
      hardwareMasked: true,
      braveShields: true,
    });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.confidence, 'medium');
    assert.ok(verdict.signatures.includes('reduced-entropy'), JSON.stringify(verdict.signatures));
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('reducedEntropy confirmed by 2')),
      JSON.stringify(verdict.reasons),
    );
  });

  check('E2', 'reducedEntropy alone or with a single corroboration abstains', () => {
    const cases: PrivacySignalsInput[] = [
      { reducedEntropy: true },
      { reducedEntropy: true, hardwareMasked: true },
    ];
    for (const input of cases) {
      const verdict = resolvePrivacySignatures(input);
      assert.equal(verdict.privacy_settings, false, JSON.stringify(input));
      assert.equal(verdict.suppressAntiDetectPenalty, false);
      assert.equal(verdict.confidence, 'low');
      assert.ok(
        verdict.reasons.some((reason) => reason.includes('at least two are required')),
        JSON.stringify(verdict.reasons),
      );
    }
  });

  check('E3', 'reducedEntropy with three corroborations is high confidence', () => {
    const verdict = resolvePrivacySignatures({
      reducedEntropy: true,
      hardwareMasked: true,
      firefoxRfpUtc: true,
      firefoxRfpCoresCapped: true,
    });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.confidence, 'high');
  });

  section('F. Contradiction veto on suppression');

  check('F1', 'contradiction keeps the signature but withholds suppression', () => {
    const verdict = resolvePrivacySignatures({
      braveNavigator: true,
      contradictionEvidence: true,
    });
    assert.equal(verdict.privacy_settings, true, 'the signature is not erased');
    assert.equal(verdict.privacy_hardened, false);
    assert.equal(verdict.suppressAntiDetectPenalty, false);
    assert.equal(verdict.confidence, 'low');
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('anti-detect suppression withheld')),
      JSON.stringify(verdict.reasons),
    );
  });

  check('F2', 'contradiction without any signature never suppresses', () => {
    const verdict = resolvePrivacySignatures({ contradictionEvidence: true });
    assert.equal(verdict.privacy_settings, false);
    assert.equal(verdict.suppressAntiDetectPenalty, false);
    assert.deepEqual(verdict.signatures, []);
  });

  section('G. Automation is never a privacy signature');

  check('G1', 'automationArtifact alone does not fire privacy_settings', () => {
    const verdict = resolvePrivacySignatures({ automationArtifact: true });
    assert.equal(verdict.privacy_settings, false);
    assert.equal(verdict.privacy_hardened, false);
    assert.equal(verdict.suppressAntiDetectPenalty, false);
    assert.equal(verdict.confidence, 'low');
    assert.deepEqual(verdict.signatures, []);
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('never counted as a privacy signature')),
      JSON.stringify(verdict.reasons),
    );
  });

  check('G2', 'automation cannot supply a reducedEntropy corroboration', () => {
    const verdict = resolvePrivacySignatures({
      reducedEntropy: true,
      automationArtifact: true,
      hardwareMasked: true,
    });
    assert.equal(verdict.privacy_settings, false, 'only one genuine corroboration is present');
    assert.equal(verdict.suppressAntiDetectPenalty, false);
    assert.equal(
      verdict.signatures.includes('automation-artifact'),
      false,
      JSON.stringify(verdict.signatures),
    );
  });

  check('G3', 'automation does not erase an explicit signature', () => {
    const verdict = resolvePrivacySignatures({ safariAfp: true, automationArtifact: true });
    assert.equal(verdict.privacy_settings, true);
    assert.equal(verdict.suppressAntiDetectPenalty, true);
    assert.equal(
      verdict.signatures.includes('automation-artifact'),
      false,
      JSON.stringify(verdict.signatures),
    );
  });

  section('H. Totality on malformed and hostile input');

  check('H1', 'null / primitive / array inputs degrade to safe defaults', () => {
    for (const input of [null, undefined, 42, 'privacy', []]) {
      const verdict = resolvePrivacySignatures(input as unknown as PrivacySignalsInput);
      assert.equal(verdict.privacy_settings, false);
      assert.equal(verdict.privacy_hardened, false);
      assert.equal(verdict.suppressAntiDetectPenalty, false);
      assert.equal(verdict.confidence, 'low');
      assert.deepEqual(verdict.signatures, []);
      assert.ok(verdict.reasons.length > 0, 'reasons must never be empty');
    }
  });

  check('H2', 'an all-throwing proxy never throws and yields safe defaults', () => {
    let verdict: PrivacySignatureResult | undefined;
    assert.doesNotThrow(() => {
      verdict = resolvePrivacySignatures(hostileInput());
    });
    assert.equal(verdict?.privacy_settings, false);
    assert.equal(verdict?.confidence, 'low');
    assert.deepEqual(verdict?.signatures, []);
    assert.ok((verdict?.reasons.length ?? 0) > 0);
  });

  check('H3', 'one hostile getter does not hide the remaining good evidence', () => {
    let verdict: PrivacySignatureResult | undefined;
    assert.doesNotThrow(() => {
      verdict = resolvePrivacySignatures(partiallyHostileInput());
    });
    assert.equal(verdict?.privacy_settings, true, 'braveShields is still readable');
    assert.ok(verdict?.signatures.includes('brave-shields'), JSON.stringify(verdict?.signatures));
    assert.ok(
      verdict?.reasons.some((reason) => reason.includes('Unreadable signal fields ignored')),
      JSON.stringify(verdict?.reasons),
    );
  });

  section('I. Purity / determinism');

  check('I1', 'resolver does not mutate its input', () => {
    const input: PrivacySignalsInput = {
      braveNavigator: true,
      reducedEntropy: true,
      hardwareMasked: true,
    };
    const before = JSON.stringify(input);
    resolvePrivacySignatures(input);
    assert.equal(JSON.stringify(input), before, 'input object must be untouched');
  });

  check('I2', 'repeated calls on the same input return the same verdict', () => {
    const input: PrivacySignalsInput = {
      firefoxRfpUtc: true,
      firefoxRfpRoundedViewport: true,
      reducedEntropy: true,
    };
    assert.deepEqual(resolvePrivacySignatures(input), resolvePrivacySignatures(input));
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

/**
 * Isolated regression suite for src/lib/tamperingLies.ts (ADDITIVE SHADOW-ONLY).
 *
 * Pins the invariants documented in the module header:
 *  - pure / total / deterministic on hostile input (null, primitives, arrays, throwing getters);
 *  - hard contradictions (cross-scope identity, ActiveText vs claimed OS, shader profile vs
 *    claimed GPU OS) survive privacy hardening;
 *  - noise lies (audio silent-buffer / repeat-read divergence, prototype proxy, iframe trap)
 *    are suppressed by privacy hardening;
 *  - `automationArtifactOnly` NEVER sets `anti_detect_browser`, even beside hard evidence;
 *  - `anomaly_score` is always clamped to [0, 1] and confidence uses the canonical 3-state
 *    vocabulary.
 *
 *   npx tsx scripts/test-tampering-lies.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 * The whole run is wrapped so no assertion/import error ever escapes uncaught.
 */

import assert from 'node:assert/strict';

import {
  resolveTamperingLies,
  type TamperingLiesResult,
  type WorkerScopeObservations,
} from '../src/lib/tamperingLies';

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

/** An object whose every property read throws — used to prove totality. */
function hostileInput(): WorkerScopeObservations {
  return new Proxy(
    {},
    {
      get(): never {
        throw new Error('hostile getter');
      },
    }
  ) as unknown as WorkerScopeObservations;
}

function expectShape(result: TamperingLiesResult): void {
  assert.deepEqual(Object.keys(result).sort(), [
    'anomaly_score',
    'anti_detect_browser',
    'reasons',
    'tampering_confidence',
  ]);
  assert.equal(typeof result.anomaly_score, 'number');
  assert.equal(Number.isFinite(result.anomaly_score), true);
  assert.equal(typeof result.anti_detect_browser, 'boolean');
  assert.ok(['high', 'medium', 'low'].includes(result.tampering_confidence));
  assert.equal(Array.isArray(result.reasons), true);
  for (const reason of result.reasons) assert.equal(typeof reason, 'string');
}

const emptyVerdict = (): TamperingLiesResult => ({
  anomaly_score: 0,
  anti_detect_browser: false,
  tampering_confidence: 'low',
  reasons: [],
});

/* -------------------------------------------------------------------------- */

function run(): void {
  check('setup', 'resolveTamperingLies is exported as a function', () => {
    assert.equal(typeof resolveTamperingLies, 'function');
  });

  section('A. Purity, shape and safe defaults');

  check('A1', 'empty input yields the zero verdict with a stable shape', () => {
    const result = resolveTamperingLies({});
    expectShape(result);
    assert.deepEqual(result, emptyVerdict());
  });

  check('A2', 'omitted input yields the same zero verdict', () => {
    assert.deepEqual(resolveTamperingLies(), emptyVerdict());
  });

  check('A3', 'null / primitive / array inputs degrade to safe defaults without throwing', () => {
    for (const bad of [null, undefined, 42, 'lies', [], NaN, true] as unknown[]) {
      let result: TamperingLiesResult | undefined;
      assert.doesNotThrow(() => {
        result = resolveTamperingLies(bad as WorkerScopeObservations);
      });
      expectShape(result as TamperingLiesResult);
      assert.deepEqual(result, emptyVerdict());
    }
  });

  check('A4', 'an all-keys-throwing proxy degrades to safe defaults without throwing', () => {
    let result: TamperingLiesResult | undefined;
    assert.doesNotThrow(() => {
      result = resolveTamperingLies(hostileInput());
    });
    expectShape(result as TamperingLiesResult);
    assert.deepEqual(result, emptyVerdict());
  });

  check('A5', 'a throwing scope getter does not escape and does not manufacture evidence', () => {
    const input = {
      get window(): unknown {
        throw new Error('hostile scope');
      },
      activeTextColor: 'rgb(0, 102, 204)',
      claimedOs: 'Windows',
    } as unknown as WorkerScopeObservations;
    let result: TamperingLiesResult | undefined;
    assert.doesNotThrow(() => {
      result = resolveTamperingLies(input);
    });
    expectShape(result as TamperingLiesResult);
    assert.deepEqual(result, emptyVerdict());
  });

  check('A6', 'repeated calls are deterministic and never mutate a frozen input', () => {
    const scope = Object.freeze({ ua: 'Mozilla/5.0', platform: 'Win32', cores: 8, memory: 16, languages: 'en-US' });
    const input = Object.freeze({
      window: scope,
      dedicated: scope,
      activeTextColor: 'rgb(0,102,204)',
      claimedOs: 'Windows',
      privacyHardened: false,
    }) as unknown as WorkerScopeObservations;
    const first = resolveTamperingLies(input);
    const second = resolveTamperingLies(input);
    assert.deepEqual(second, first);
    assert.deepEqual(first, emptyVerdict());
    assert.equal(Object.keys(scope).length, 5);
  });

  section('B. Hard contradiction — cross-scope identity');

  check('B1', 'UA divergence between window and dedicated worker is a hard contradiction', () => {
    const result = resolveTamperingLies({
      window: { ua: 'Mozilla/5.0 (Windows NT 10.0)' },
      dedicated: { ua: 'Mozilla/5.0 (X11; Linux)' },
    });
    assert.equal(result.anomaly_score, 0.25);
    assert.equal(result.anti_detect_browser, true);
    assert.equal(result.tampering_confidence, 'high');
    assert.ok(
      result.reasons.some((reason) => reason.includes('navigator.userAgent divergence (window vs dedicated)')),
      JSON.stringify(result.reasons)
    );
  });

  check('B2', 'hardwareConcurrency and deviceMemory divergence are both flagged', () => {
    const result = resolveTamperingLies({
      window: { cores: 8, memory: 16 },
      shared: { cores: 4, memory: 8 },
      service: { cores: 4, memory: 8 },
    });
    assert.equal(result.anomaly_score, 0.3); // 0.15 + 0.15
    assert.equal(result.anti_detect_browser, true);
    assert.ok(
      result.reasons.some((reason) => reason.includes('navigator.hardwareConcurrency divergence')),
      JSON.stringify(result.reasons)
    );
    assert.ok(
      result.reasons.some((reason) => reason.includes('navigator.deviceMemory divergence')),
      JSON.stringify(result.reasons)
    );
  });

  check('B3', 'platform and languages divergence are flagged against the window baseline', () => {
    const result = resolveTamperingLies({
      window: { platform: 'Win32', languages: 'en-US' },
      dedicated: { platform: 'Linux x86_64', languages: 'fr-FR' },
    });
    assert.equal(result.anomaly_score, 0.4); // platform 0.25 + languages 0.15
    assert.equal(result.anti_detect_browser, true);
    assert.equal(result.reasons.filter((reason) => reason.includes('divergence')).length, 2);
  });

  check('B4', 'four consistent scopes produce no divergence evidence', () => {
    const scope = { ua: 'UA', platform: 'Win32', cores: 8, memory: 16, languages: 'en-US' };
    const result = resolveTamperingLies({
      window: scope,
      dedicated: scope,
      shared: scope,
      service: scope,
    });
    assert.deepEqual(result, emptyVerdict());
  });

  check('B5', 'null / non-finite scope values abstain instead of diverging', () => {
    const result = resolveTamperingLies({
      window: { cores: 8, memory: 16, ua: 'UA' },
      dedicated: { cores: NaN, memory: null, ua: null },
    });
    assert.deepEqual(result, emptyVerdict());
  });

  section('C. Hard contradiction — ActiveText color vs claimed OS');

  check('C1', 'rgb(0,102,204) with a Windows claim is consistent', () => {
    const result = resolveTamperingLies({ activeTextColor: 'rgb(0, 102, 204)', claimedOs: 'Windows NT 10.0' });
    assert.deepEqual(result, emptyVerdict());
  });

  check('C2', 'rgb(0,102,204) with a Linux claim is a hard contradiction', () => {
    const result = resolveTamperingLies({ activeTextColor: 'rgb(0,102,204)', claimedOs: 'Linux x86_64' });
    assert.equal(result.anomaly_score, 0.3);
    assert.equal(result.anti_detect_browser, true);
    assert.equal(result.tampering_confidence, 'high');
    assert.ok(result.reasons.some((reason) => reason.includes('ActiveText color')), JSON.stringify(result.reasons));
  });

  check('C3', 'pure red with a macOS claim is consistent (Linux/macOS family)', () => {
    const result = resolveTamperingLies({ activeTextColor: 'rgb(255,0,0)', claimedOs: 'MacIntel' });
    assert.deepEqual(result, emptyVerdict());
  });

  check('C4', 'pure red with a Windows claim is a hard contradiction', () => {
    const result = resolveTamperingLies({ activeTextColor: '#ff0000', claimedOs: 'Win32' });
    assert.equal(result.anomaly_score, 0.3);
    assert.equal(result.anti_detect_browser, true);
    assert.ok(result.reasons.some((reason) => reason.includes('claimed OS is windows')), JSON.stringify(result.reasons));
  });

  check('C5', 'an unrecognised color or OS abstains (absence of evidence is not a lie)', () => {
    for (const input of [
      { activeTextColor: 'rgb(1,2,3)', claimedOs: 'Linux' },
      { activeTextColor: 'rgb(0,102,204)', claimedOs: 'Plan9' },
      { activeTextColor: null, claimedOs: 'Windows' },
    ]) {
      assert.deepEqual(resolveTamperingLies(input), emptyVerdict());
    }
  });

  section('D. Hard contradiction — shader precision profile vs GPU OS');

  check('D1', 'a D3D shader profile with a Windows GPU claim is consistent', () => {
    const result = resolveTamperingLies({
      shaderPrecisionProfile: 'angle_d3d11|highp',
      claimedGpuOs: 'Windows',
    });
    assert.deepEqual(result, emptyVerdict());
  });

  check('D2', 'a D3D shader profile with a Linux GPU claim is a hard contradiction', () => {
    const result = resolveTamperingLies({
      shaderPrecisionProfile: 'd3d11|highp',
      claimedGpuOs: 'Linux',
    });
    assert.equal(result.anomaly_score, 0.3);
    assert.equal(result.anti_detect_browser, true);
    assert.equal(result.tampering_confidence, 'high');
    assert.ok(result.reasons.some((reason) => reason.includes('shader precision profile')), JSON.stringify(result.reasons));
  });

  check('D3', 'a Metal shader profile with a Windows GPU claim is a hard contradiction', () => {
    const result = resolveTamperingLies({
      shaderPrecisionProfile: 'metal|highp',
      claimedGpuOs: 'Windows',
    });
    assert.equal(result.anomaly_score, 0.3);
    assert.equal(result.anti_detect_browser, true);
  });

  check('D4', 'a cross-platform software shader profile never contradicts the GPU OS', () => {
    for (const profile of ['swiftshader|mediump', 'llvmpipe|highp', 'software rasterizer']) {
      assert.deepEqual(
        resolveTamperingLies({ shaderPrecisionProfile: profile, claimedGpuOs: 'Windows' }),
        emptyVerdict(),
        profile
      );
    }
  });

  section('E. Noise lies and privacy suppression');

  check('E1', 'non-zero silent audio buffer counts when not privacy hardened', () => {
    const result = resolveTamperingLies({ audioSilentBufferNonZero: true });
    assert.equal(result.anomaly_score, 0.15);
    assert.equal(result.anti_detect_browser, true);
    assert.equal(result.tampering_confidence, 'low');
    assert.ok(result.reasons.some((reason) => reason.includes('silent audio buffer')), JSON.stringify(result.reasons));
  });

  check('E2', 'repeat-read divergence counts when not privacy hardened', () => {
    const result = resolveTamperingLies({ audioRepeatReadDiverged: true });
    assert.equal(result.anomaly_score, 0.15);
    assert.equal(result.anti_detect_browser, true);
    assert.ok(result.reasons.some((reason) => reason.includes('repeated audio reads diverged')), JSON.stringify(result.reasons));
  });

  check('E3', 'privacy hardening suppresses all noise-based lies', () => {
    const result = resolveTamperingLies({
      privacyHardened: true,
      audioSilentBufferNonZero: true,
      audioRepeatReadDiverged: true,
      prototypeProxy: true,
      iframeStealthTrap: true,
    });
    assert.deepEqual(result, emptyVerdict());
  });

  check('E4', 'privacy hardening does NOT suppress a hard cross-scope contradiction', () => {
    const result = resolveTamperingLies({
      privacyHardened: true,
      window: { ua: 'Mozilla/5.0 (Windows)' },
      dedicated: { ua: 'Mozilla/5.0 (X11; Linux)' },
    });
    assert.equal(result.anomaly_score, 0.25);
    assert.equal(result.anti_detect_browser, true);
    assert.equal(result.tampering_confidence, 'high');
  });

  check('E5', 'privacy hardening does NOT suppress the ActiveText or shader contradictions', () => {
    const result = resolveTamperingLies({
      privacyHardened: true,
      activeTextColor: 'rgb(0,102,204)',
      claimedOs: 'Linux',
      shaderPrecisionProfile: 'd3d11',
      claimedGpuOs: 'MacOS',
    });
    assert.equal(result.anomaly_score, 0.6); // 0.30 + 0.30, noise absent
    assert.equal(result.anti_detect_browser, true);
    assert.equal(result.tampering_confidence, 'high');
    assert.equal(result.reasons.length, 2);
  });

  check('E6', 'truthy junk is not a verified boolean signal', () => {
    const result = resolveTamperingLies({
      audioSilentBufferNonZero: 1,
      audioRepeatReadDiverged: 'true',
      prototypeProxy: {},
      privacyHardened: 1,
    } as unknown as WorkerScopeObservations);
    assert.deepEqual(result, emptyVerdict());
  });

  section('F. automationArtifactOnly decoupling');

  check('F1', 'automationArtifactOnly alone never sets anti_detect_browser', () => {
    const result = resolveTamperingLies({ automationArtifactOnly: true });
    assert.equal(result.anomaly_score, 0);
    assert.equal(result.anti_detect_browser, false);
    assert.equal(result.tampering_confidence, 'low');
    assert.ok(result.reasons.some((reason) => reason.includes('anti_detect_browser discounted')));
  });

  check('F2', 'automationArtifactOnly does not suppress the score or the raw reasons', () => {
    const evidence = {
      window: { ua: 'Mozilla/5.0 (Windows)' },
      dedicated: { ua: 'Mozilla/5.0 (X11; Linux)' },
      audioSilentBufferNonZero: true,
    } as WorkerScopeObservations;
    const plain = resolveTamperingLies(evidence);
    const discounted = resolveTamperingLies({ ...evidence, automationArtifactOnly: true });
    assert.equal(discounted.anomaly_score, plain.anomaly_score);
    assert.deepEqual(
      discounted.reasons.filter((reason) => !reason.includes('anti_detect_browser discounted')),
      plain.reasons
    );
    assert.equal(plain.anti_detect_browser, true);
    assert.equal(discounted.anti_detect_browser, false);
  });

  check('F3', 'automationArtifactOnly overrides even hard ActiveText evidence for the flag', () => {
    const evidence: WorkerScopeObservations = {
      activeTextColor: 'rgb(0,102,204)',
      claimedOs: 'Linux',
    };
    const plain = resolveTamperingLies(evidence);
    const discounted = resolveTamperingLies({ ...evidence, automationArtifactOnly: true });
    assert.equal(plain.anti_detect_browser, true);
    assert.equal(discounted.anti_detect_browser, false);
    assert.equal(discounted.anomaly_score, 0.3);
    assert.equal(discounted.tampering_confidence, 'high');
  });

  check('F4', 'a false automationArtifactOnly is not a discount switch', () => {
    const result = resolveTamperingLies({
      automationArtifactOnly: false,
      audioSilentBufferNonZero: true,
    });
    assert.equal(result.anti_detect_browser, true);
    assert.equal(result.reasons.some((reason) => reason.includes('discounted')), false);
  });

  section('G. Score bounds, confidence and vocabulary parity');

  check('G1', 'many simultaneous signals clamp the score to exactly 1', () => {
    const result = resolveTamperingLies({
      window: { ua: 'UA-1', platform: 'Win32', cores: 8, memory: 16, languages: 'en-US' },
      dedicated: { ua: 'UA-2', platform: 'Linux x86_64', cores: 4, memory: 8, languages: 'fr-FR' },
      activeTextColor: 'rgb(0,102,204)',
      claimedOs: 'Linux',
      shaderPrecisionProfile: 'd3d11',
      claimedGpuOs: 'Linux',
      audioSilentBufferNonZero: true,
      audioRepeatReadDiverged: true,
      prototypeProxy: true,
      iframeStealthTrap: true,
    });
    assert.equal(result.anomaly_score, 1);
    assert.equal(result.anti_detect_browser, true);
    assert.equal(result.tampering_confidence, 'high');
  });

  check('G2', 'medium confidence is reachable without hard evidence', () => {
    const result = resolveTamperingLies({
      audioSilentBufferNonZero: true,
      audioRepeatReadDiverged: true,
    });
    assert.equal(result.anomaly_score, 0.3);
    assert.equal(result.tampering_confidence, 'medium');
  });

  check('G3', 'the three confidence values use the canonical lowercase vocabulary', () => {
    const low = resolveTamperingLies({ prototypeProxy: true });
    const medium = resolveTamperingLies({ audioSilentBufferNonZero: true, audioRepeatReadDiverged: true });
    const high = resolveTamperingLies({ activeTextColor: 'rgb(255,0,0)', claimedOs: 'Windows' });
    assert.equal(low.tampering_confidence, 'low');
    assert.equal(medium.tampering_confidence, 'medium');
    assert.equal(high.tampering_confidence, 'high');
    for (const verdict of [low, medium, high]) {
      assert.ok(['high', 'medium', 'low'].includes(verdict.tampering_confidence));
    }
  });

  check('G4', 'privacy hardening alone produces no verdict and no reasons', () => {
    assert.deepEqual(resolveTamperingLies({ privacyHardened: true }), emptyVerdict());
  });

  check('G5', 'every returned verdict stays inside the documented bounds', () => {
    const inputs: WorkerScopeObservations[] = [
      {},
      { privacyHardened: true, audioSilentBufferNonZero: true },
      { window: { ua: 'A' }, service: { ua: 'B' }, automationArtifactOnly: true },
      {
        window: { ua: 'A' },
        dedicated: { ua: 'B' },
        shared: { ua: 'C' },
        service: { ua: 'D' },
        activeTextColor: 'red',
        claimedOs: 'Windows',
      },
    ];
    for (const input of inputs) {
      const result = resolveTamperingLies(input);
      expectShape(result);
      assert.ok(result.anomaly_score >= 0 && result.anomaly_score <= 1);
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

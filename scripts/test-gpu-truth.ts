/**
 * Regression suite for src/lib/gpuTruth.ts (shadow-only GPU truth resolver).
 *
 * Pins the documented invariants:
 *  - SwiftShader / llvmpipe / ANGLE software vendor => `software_renderer`, NEVER a VM
 *    verdict, with a reliable answer (`answerUnreliable: false`);
 *  - stealth-template denylist, constant WebGL strings and unsupported high-end claims
 *    => `spoofed_suspect`;
 *  - a masked debug extension or missing unmasked identity => `masked` + unreliable answer;
 *  - real unmasked manufacturer identity => `hardware`; otherwise abstain as `unknown`;
 *  - no identity/risk/score fields, no third-party SDK, no throwing on hostile input.
 *
 *   npx tsx scripts/test-gpu-truth.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 * The whole run is wrapped so no assertion/import error ever escapes uncaught.
 */

import assert from 'node:assert/strict';

import {
  resolveGpuTruthState,
  type GpuTruthInput,
  type GpuTruthState,
  type GpuTruthStateResult,
} from '../src/lib/gpuTruth';

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

function hasReason(verdict: GpuTruthStateResult, token: string): boolean {
  return verdict.reasons.some((reason) => reason.includes(token));
}

/** Representative inputs used by the cross-cutting state/flag assertions. */
function representatives(): Record<GpuTruthState, GpuTruthInput> {
  return {
    hardware: {
      unmaskedVendor: 'NVIDIA Corporation',
      unmaskedRenderer: 'NVIDIA GeForce RTX 3080',
      debugExtensionAvailable: true,
    },
    software_renderer: {
      renderer: 'Google SwiftShader',
      unmaskedRenderer: 'Google SwiftShader',
      unmaskedVendor: 'Google Inc. (Google)',
      debugExtensionAvailable: true,
    },
    masked: {
      renderer: 'Intel(R) HD Graphics 4600',
      vendor: 'Intel Inc.',
      debugExtensionAvailable: false,
    },
    spoofed_suspect: {
      renderer: 'NVIDIA GeForce RTX 4090',
      vendor: 'NVIDIA Corporation',
      debugExtensionAvailable: false,
    },
    unknown: {
      unmaskedVendor: 'Acme Microsystems',
      unmaskedRenderer: 'Acme Vision 9000',
      debugExtensionAvailable: true,
    },
  };
}

/* -------------------------------------------------------------------------- */

function run(): void {
  check('setup', 'resolveGpuTruthState is exported as a function', () => {
    assert.equal(typeof resolveGpuTruthState, 'function');
  });

  section('A. Software rasterisers (never a hard VM verdict)');

  check('A1', 'SwiftShader => software_renderer with a reliable, VM-free reason trail', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'Google Inc.',
      renderer: 'Google SwiftShader',
      unmaskedVendor: 'Google Inc. (Google)',
      unmaskedRenderer: 'Google SwiftShader',
      debugExtensionAvailable: true,
      shaderPrecisionProfile: '8|8',
    });
    assert.equal(verdict.state, 'software_renderer');
    assert.equal(verdict.answerUnreliable, false);
    assert.ok(hasReason(verdict, 'software-rasteriser-signature-detected'));
    assert.ok(hasReason(verdict, 'software-rendering-is-not-a-virtual-machine-verdict'));
  });

  check('A2', 'llvmpipe with LLVM suffix => software_renderer', () => {
    const verdict = resolveGpuTruthState({
      unmaskedVendor: 'Mesa',
      unmaskedRenderer: 'llvmpipe (LLVM 17.0.6, 256 bits)',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'software_renderer');
    assert.equal(verdict.answerUnreliable, false);
  });

  check('A3', 'ANGLE software vendor alias alone => software_renderer, masked noted', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'Google Inc. (Google)',
      renderer: 'WebKit WebGL',
      debugExtensionAvailable: false,
    });
    assert.equal(verdict.state, 'software_renderer');
    assert.equal(verdict.answerUnreliable, false);
    assert.ok(hasReason(verdict, 'software-identified-without-webgl-debug-info'));
  });

  check('A4', 'software signature in unmasked strings overrides a high-end public claim', () => {
    const verdict = resolveGpuTruthState({
      renderer: 'NVIDIA GeForce RTX 4090',
      unmaskedRenderer: 'Google SwiftShader',
      unmaskedVendor: 'Google Inc. (Google)',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'software_renderer');
    assert.equal(verdict.answerUnreliable, false);
  });

  check('A5', 'no VM / risk / score / identity field is ever emitted', () => {
    const verdict = resolveGpuTruthState({ renderer: 'llvmpipe', debugExtensionAvailable: true });
    assert.deepEqual(Object.keys(verdict).sort(), ['answerUnreliable', 'reasons', 'state']);
    const states: GpuTruthState[] = ['hardware', 'software_renderer', 'masked', 'spoofed_suspect', 'unknown'];
    assert.ok(states.includes(verdict.state));
    assert.equal(verdict.state.includes('vm'), false);
    // Reasons may state that software rendering is NOT a VM verdict; that is different
    // from emitting a VM classification, score or identity field.
    const serialized = JSON.stringify(verdict).toLowerCase();
    for (const forbidden of ['vm_', '"vm"', 'risk', 'score', 'identity', 'bot']) {
      assert.equal(serialized.includes(forbidden), false, `must not contain ${forbidden}`);
    }
  });

  section('B. Stealth templates and spoof suspicion');

  check('B1', 'Intel Iris OpenGL Engine denylist => spoofed_suspect', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'Intel Inc.',
      renderer: 'Intel Iris OpenGL Engine',
      unmaskedVendor: 'Intel Inc.',
      unmaskedRenderer: 'Intel Iris OpenGL Engine',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'spoofed_suspect');
    assert.equal(verdict.answerUnreliable, true);
    assert.ok(hasReason(verdict, 'stealth-template-denylist:intel-iris-opengl-engine'));
  });

  check('B2', 'Intel Inc. vendor with a generic model => spoofed_suspect', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'Intel Inc.',
      renderer: 'Generic OpenGL Engine',
      unmaskedVendor: 'Intel Inc.',
      unmaskedRenderer: 'Generic OpenGL Engine',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'spoofed_suspect');
    assert.ok(hasReason(verdict, 'stealth-template-denylist:intel-inc-with-generic-model'));
  });

  check('B3', 'constant WebGL strings (WebKit) with no unmasked identity => spoofed_suspect', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'WebKit',
      renderer: 'WebKit WebGL',
      debugExtensionAvailable: false,
    });
    assert.equal(verdict.state, 'spoofed_suspect');
    assert.equal(verdict.answerUnreliable, true);
    assert.ok(hasReason(verdict, 'constant-webgl-string-denylist'));
  });

  check('B4', 'all constant placeholder variants are denied', () => {
    const variants: GpuTruthInput[] = [
      { vendor: 'Mozilla', renderer: 'Mozilla', debugExtensionAvailable: false },
      { vendor: 'Standard WebGL Vendor', renderer: 'Standard WebGL Renderer', debugExtensionAvailable: false },
      { vendor: 'WebGL', renderer: 'WebGL', debugExtensionAvailable: false },
    ];
    for (const input of variants) {
      const verdict = resolveGpuTruthState(input);
      assert.equal(verdict.state, 'spoofed_suspect', JSON.stringify(input));
      assert.ok(hasReason(verdict, 'constant-webgl-string-denylist'));
    }
  });

  check('B5', 'high-end renderer claim while unmasked is missing => spoofed_suspect', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'NVIDIA Corporation',
      renderer: 'NVIDIA GeForce RTX 4090',
      debugExtensionAvailable: false,
    });
    assert.equal(verdict.state, 'spoofed_suspect');
    assert.ok(hasReason(verdict, 'high-end-renderer-claim-without-unmasked-renderer'));
  });

  check('B6', 'privacyHardened does not excuse an unsupported high-end claim', () => {
    const verdict = resolveGpuTruthState({
      renderer: 'NVIDIA GeForce RTX 4090',
      debugExtensionAvailable: false,
      privacyHardened: true,
    });
    assert.equal(verdict.state, 'spoofed_suspect');
  });

  check('B7', 'high-end claim contradicted by low shader precision => spoofed_suspect', () => {
    const verdict = resolveGpuTruthState({
      unmaskedVendor: 'NVIDIA Corporation',
      unmaskedRenderer: 'NVIDIA GeForce RTX 4090',
      shaderPrecisionProfile: 'low',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'spoofed_suspect');
    assert.ok(hasReason(verdict, 'high-end-renderer-claim-contradicted-by-low-shader-precision'));
  });

  check('B8', 'legitimate Intel UHD model is not a stealth-template false positive', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'Intel Inc.',
      renderer: 'Intel(R) UHD Graphics 620',
      unmaskedVendor: 'Intel Inc.',
      unmaskedRenderer: 'Intel(R) UHD Graphics 620',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'hardware');
    assert.equal(verdict.answerUnreliable, false);
  });

  section('C. Masked identity and privacy hardening');

  check('C1', 'masked debug extension => masked with an unreliable answer', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'Intel Inc.',
      renderer: 'Intel(R) HD Graphics 4600',
      debugExtensionAvailable: false,
    });
    assert.equal(verdict.state, 'masked');
    assert.equal(verdict.answerUnreliable, true);
    assert.ok(hasReason(verdict, 'webgl-debug-renderer-info-extension-unavailable'));
  });

  check('C2', 'unmasked placeholder strings with an available extension => masked', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'Intel Inc.',
      renderer: 'Intel(R) HD Graphics 4600',
      unmaskedVendor: 'unavailable',
      unmaskedRenderer: 'unavailable',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'masked');
    assert.ok(hasReason(verdict, 'unmasked-webgl-strings-unavailable'));
  });

  check('C3', 'privacyHardened annotates a masked verdict without making it trustworthy', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'Intel Inc.',
      renderer: 'Intel(R) HD Graphics 4600',
      debugExtensionAvailable: false,
      privacyHardened: true,
    });
    assert.equal(verdict.state, 'masked');
    assert.equal(verdict.answerUnreliable, true);
    assert.ok(hasReason(verdict, 'privacy-hardened-runtime-masks-gpu-identity'));
  });

  check('C4', 'constant public strings are tolerated when a real unmasked GPU is exposed', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'WebKit',
      renderer: 'WebKit WebGL',
      unmaskedVendor: 'NVIDIA Corporation',
      unmaskedRenderer: 'NVIDIA GeForce RTX 3080',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'hardware');
    assert.equal(verdict.answerUnreliable, false);
  });

  section('D. Genuine hardware');

  check('D1', 'unmasked NVIDIA GPU => hardware', () => {
    const verdict = resolveGpuTruthState({
      vendor: 'NVIDIA Corporation',
      renderer: 'NVIDIA GeForce RTX 3080',
      unmaskedVendor: 'NVIDIA Corporation',
      unmaskedRenderer: 'NVIDIA GeForce RTX 3080',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'hardware');
    assert.equal(verdict.answerUnreliable, false);
    assert.ok(hasReason(verdict, 'real-unmasked-gpu-identifier-present'));
  });

  check('D2', 'unmasked AMD GPU => hardware', () => {
    const verdict = resolveGpuTruthState({
      unmaskedVendor: 'Advanced Micro Devices, Inc.',
      unmaskedRenderer: 'Radeon RX 6600 XT',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'hardware');
  });

  check('D3', 'unmasked Apple Silicon GPU => hardware', () => {
    const verdict = resolveGpuTruthState({
      unmaskedVendor: 'Apple Inc.',
      unmaskedRenderer: 'Apple M2',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'hardware');
  });

  check('D4', 'strong shader-precision capability corroborates a hardware verdict', () => {
    const verdict = resolveGpuTruthState({
      unmaskedVendor: 'NVIDIA Corporation',
      unmaskedRenderer: 'NVIDIA GeForce RTX 3080',
      shaderPrecisionProfile: '23|23',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'hardware');
    assert.ok(hasReason(verdict, 'shader-precision-profile-consistent-with-hardware'));
  });

  section('E. Abstention');

  check('E1', 'unrecognized but non-masked signature => unknown', () => {
    const verdict = resolveGpuTruthState({
      unmaskedVendor: 'Acme Microsystems',
      unmaskedRenderer: 'Acme Vision 9000',
      debugExtensionAvailable: true,
    });
    assert.equal(verdict.state, 'unknown');
    assert.equal(verdict.answerUnreliable, true);
    assert.ok(hasReason(verdict, 'unrecognized-gpu-signature'));
  });

  check('E2', 'empty input abstains as masked (no debug extension evidence)', () => {
    const verdict = resolveGpuTruthState({});
    assert.equal(verdict.state, 'masked');
    assert.equal(verdict.answerUnreliable, true);
    assert.ok(verdict.reasons.length > 0);
  });

  section('F. Totality — no input can throw');

  check('F1', 'hostile throwing getters never escape the resolver', () => {
    const hostile = {
      get vendor(): string {
        throw new Error('hostile getter');
      },
      get unmaskedRenderer(): string {
        throw new Error('hostile getter');
      },
    } as GpuTruthInput;
    let verdict: GpuTruthStateResult | undefined;
    assert.doesNotThrow(() => {
      verdict = resolveGpuTruthState(hostile);
    });
    assert.ok(verdict);
    assert.equal(verdict?.state, 'masked');
    assert.equal(typeof verdict?.answerUnreliable, 'boolean');
  });

  check('F2', 'null, primitives and arrays are handled without throwing', () => {
    const inputs: unknown[] = [null, undefined, 42, 'gpu', true, [], { vendor: null, renderer: 7 }];
    const states: GpuTruthState[] = ['hardware', 'software_renderer', 'masked', 'spoofed_suspect', 'unknown'];
    for (const input of inputs) {
      let verdict: GpuTruthStateResult | undefined;
      assert.doesNotThrow(() => {
        verdict = resolveGpuTruthState(input as GpuTruthInput);
      }, `input=${JSON.stringify(input)}`);
      assert.ok(verdict && states.includes(verdict.state));
      assert.equal(typeof verdict?.answerUnreliable, 'boolean');
      assert.ok(Array.isArray(verdict?.reasons));
    }
  });

  section('G. Cross-cutting contracts');

  check('G1', 'the resolver is deterministic and does not mutate its input', () => {
    const input: GpuTruthInput = {
      vendor: 'NVIDIA Corporation',
      renderer: 'NVIDIA GeForce RTX 3080',
      unmaskedVendor: 'NVIDIA Corporation',
      unmaskedRenderer: 'NVIDIA GeForce RTX 3080',
      debugExtensionAvailable: true,
    };
    const before = JSON.stringify(input);
    const first = resolveGpuTruthState(input);
    const second = resolveGpuTruthState(input);
    assert.deepEqual(first, second);
    assert.equal(JSON.stringify(input), before);
  });

  check('G2', 'all five documented states are reachable', () => {
    const samples = representatives();
    const observed = Object.keys(samples).map((state) =>
      resolveGpuTruthState(samples[state as GpuTruthState]).state
    );
    assert.deepEqual(observed.sort(), [
      'hardware',
      'masked',
      'software_renderer',
      'spoofed_suspect',
      'unknown',
    ]);
  });

  check('G3', 'answerUnreliable follows the state contract', () => {
    const expected: Record<GpuTruthState, boolean> = {
      hardware: false,
      software_renderer: false,
      masked: true,
      spoofed_suspect: true,
      unknown: true,
    };
    const samples = representatives();
    for (const state of Object.keys(expected) as GpuTruthState[]) {
      const verdict = resolveGpuTruthState(samples[state]);
      assert.equal(
        verdict.answerUnreliable,
        expected[state],
        `${state} answerUnreliable mismatch`
      );
    }
  });

  check('G4', 'reason trails are non-empty, duplicate-free and stable', () => {
    const input: GpuTruthInput = {
      vendor: 'Intel Inc.',
      renderer: 'Intel Iris OpenGL Engine',
      unmaskedVendor: 'Intel Inc.',
      unmaskedRenderer: 'Intel Iris OpenGL Engine',
      debugExtensionAvailable: true,
    };
    const verdict = resolveGpuTruthState(input);
    assert.ok(verdict.reasons.length > 0);
    assert.equal(new Set(verdict.reasons).size, verdict.reasons.length);
    assert.deepEqual(verdict.reasons, resolveGpuTruthState(input).reasons);
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

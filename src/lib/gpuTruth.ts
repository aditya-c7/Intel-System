/**
 * GPU "truth" resolver — shadow-only, additive, pure, zero imports.
 *
 * Nothing in production consumes this module yet. It gives a canonical, side-effect-free
 * home to a narrow question: "given the WebGL vendor/renderer strings this runtime exposed,
 * what may we honestly say about its graphics backend?" The answer is one of five
 * categorical states — there is deliberately NO identity signal, NO risk/score, NO VM
 * escalation and NO third-party SDK anywhere in this file.
 *
 * Design invariants (all enforced in code, not only documented):
 *
 *  - SwiftShader / llvmpipe and friends are reported as `software_renderer`. Software
 *    rendering is a graphics capability, NEVER a hard virtual-machine verdict; the reason
 *    trail says so explicitly. No `vm`/`virtual` state or field exists.
 *  - A stealth-template denylist (known forged strings), constant WebGL placeholder
 *    strings, and a high-end renderer claim whose unmasked identity is missing (or is
 *    contradicted by a low shader-precision capability) produce `spoofed_suspect`.
 *  - A masked/absent `WEBGL_debug_renderer_info` extension, or missing unmasked strings,
 *    produce `masked` with `answerUnreliable: true`. A privacy-hardened runtime is labelled
 *    as such in the reasons but is still not a trustworthy hardware answer.
 *  - `hardware` is emitted only when a real unmasked manufacturer identifier is present
 *    AND no software/spoof/mask rule fired. Anything else degrades to `unknown`
 *    (`answerUnreliable: true`) — false hardware claims are worse than abstention.
 *  - Total function: no I/O, no globals, no mutation, no randomness. Any input shape
 *    (null, primitive, array, hostile getters that throw) returns a well-formed verdict
 *    and never throws.
 */

/* -------------------------------------------------------------------------- */
/* Public types                                                                */
/* -------------------------------------------------------------------------- */

export type GpuTruthState =
  | 'hardware'
  | 'software_renderer'
  | 'masked'
  | 'spoofed_suspect'
  | 'unknown';

export interface GpuTruthInput {
  /** Masked `gl.getParameter(gl.VENDOR)` string. */
  vendor?: string | null;
  /** Masked `gl.getParameter(gl.RENDERER)` string. */
  renderer?: string | null;
  /** `UNMASKED_VENDOR_WEBGL` via `WEBGL_debug_renderer_info`, if available. */
  unmaskedVendor?: string | null;
  /** `UNMASKED_RENDERER_WEBGL` via `WEBGL_debug_renderer_info`, if available. */
  unmaskedRenderer?: string | null;
  /** True only when `WEBGL_debug_renderer_info` could actually be obtained. */
  debugExtensionAvailable?: boolean | null;
  /**
   * Capability-derived shader precision profile (e.g. `'high'`, `'23|23'`, `'low'`).
   * Capabilities do not change when strings are spoofed, so a weak profile can
   * contradict a high-end renderer claim.
   */
  shaderPrecisionProfile?: string | null;
  /** Explicit browser privacy-hardening posture; annotates a masked verdict. */
  privacyHardened?: boolean | null;
}

export interface GpuTruthStateResult {
  state: GpuTruthState;
  /** True when the runtime cannot give a trustworthy answer about its GPU. */
  answerUnreliable: boolean;
  /** Deterministic, human-readable audit trail (no scores, no identity labels). */
  reasons: string[];
}

/* -------------------------------------------------------------------------- */
/* Signature tables                                                           */
/* -------------------------------------------------------------------------- */

/** Positive software-rasteriser signatures. Never a VM verdict. */
const SOFTWARE_RENDERER_PATTERN =
  /swiftshader|llvmpipe|softpipe|mesa offscreen|software rasterizer|software renderer|basic render driver|microsoft basic render|apple software renderer|virgl|goldfish|ranchu/i;

/** ANGLE's software vendor alias (`Google Inc. (NVIDIA)` is deliberately NOT included). */
const SOFTWARE_VENDOR_PATTERN = /^google\s+inc\.?\s*\(\s*google\s*\)$|^google$|^mesa$/i;

/** Renderer tokens that an anti-detect template likes to claim without proof. */
const HIGH_END_RENDERER_PATTERN =
  /\brtx\b|\bgtx\b|geforce|radeon\s*(rx|pro)|quadro|\btitan\b|apple\s*m[1-9]\b|arc\s*a[0-9]/i;

/** The specific forged renderer string used by stealth templates. */
const STEALTH_TEMPLATE_RENDERER_PATTERN = /intel\s+iris\s+opengl\s+engine|intel\s+opengl\s+engine/i;

/** A "manufacturer" vendor plus a generic model is a template, not a real identity. */
const GENERIC_MODEL_PATTERN =
  /iris\s+opengl\s+engine|opengl\s+engine|\bgeneric\b|\bbasic\b|\bunknown\b|\bstandard\b|\b(na|n\/a)\b/i;

/** Real manufacturer tokens. Only consulted after every negative rule has passed. */
const HARDWARE_GPU_PATTERN =
  /nvidia|geforce|quadro|radeon|\bamd\b|\bintel\b|iris|uhd graphics|hd graphics|arc graphics|apple m[1-9]|adreno|mali|powervr|videocore|apple gpu/i;

/** Constant strings returned when a runtime hides its real WebGL implementation. */
const CONSTANT_WEBGL_STRINGS: ReadonlySet<string> = new Set([
  'webkit webgl',
  'webkit',
  'mozilla',
  'webgl',
  'standard webgl vendor',
  'standard webgl renderer',
  'webgl vendor',
  'webgl renderer',
]);

/** Placeholder values that mean "no usable string was exposed". */
const MISSING_STRINGS: ReadonlySet<string> = new Set([
  'unavailable',
  'n/a',
  'na',
  'none',
  'null',
  'undefined',
  'unknown',
  'err',
  'error',
]);

/* -------------------------------------------------------------------------- */
/* Defensive normalization — every helper is total and never throws           */
/* -------------------------------------------------------------------------- */

function readField(source: Record<string, unknown>, key: string): unknown {
  try {
    return source[key];
  } catch {
    return undefined;
  }
}

function asString(value: unknown): string {
  try {
    return typeof value === 'string' ? value.trim().replace(/\s+/g, ' ') : '';
  } catch {
    return '';
  }
}

function normalize(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, ' ');
}

function isPresent(value: string): boolean {
  const token = normalize(value);
  return token !== '' && !MISSING_STRINGS.has(token);
}

function isConstantWebGLString(value: string): boolean {
  return CONSTANT_WEBGL_STRINGS.has(normalize(value));
}

function isIntelIncVendor(value: string): boolean {
  return /^intel\s+inc\.?$/i.test(value.trim());
}

type PrecisionStrength = 'weak' | 'strong' | 'unknown';

function shaderPrecisionStrength(profile: string): PrecisionStrength {
  const token = normalize(profile);
  if (!token) return 'unknown';
  if (/^(low|lowp|none|no|0|n\/a|na|err|error|unavailable|unknown)$/.test(token)) return 'weak';
  if (/\blowp?\b/.test(token)) return 'weak';
  if (/\bhighp?\b|\bhigh\b/.test(token)) return 'strong';
  if (/^\d+(?:\|\d+)?$/.test(token)) {
    const parts = token.split('|').map((part) => Number(part));
    if (parts.every((part) => part <= 10)) return 'weak';
    if (parts.every((part) => part >= 20)) return 'strong';
  }
  return 'unknown';
}

function unique(reasons: string[]): string[] {
  return Array.from(new Set(reasons));
}

/* -------------------------------------------------------------------------- */
/* Resolver                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Resolve the GPU truth state from the supplied WebGL signals. Pure and total: it never
 * throws, never mutates its input, and returns identical output for identical input.
 *
 * Resolution order (first matching branch wins):
 *  1. positive software-rasteriser signature → `software_renderer`;
 *  2. stealth-template / constant-string / unsupported high-end claim → `spoofed_suspect`;
 *  3. masked debug extension or missing unmasked strings → `masked`;
 *  4. real unmasked manufacturer identifier → `hardware`;
 *  5. otherwise → `unknown`.
 */
export function resolveGpuTruthState(input: GpuTruthInput = {}): GpuTruthStateResult {
  try {
    const source: Record<string, unknown> =
      input && typeof input === 'object' && !Array.isArray(input)
        ? (input as Record<string, unknown>)
        : {};

    const vendor = asString(readField(source, 'vendor'));
    const renderer = asString(readField(source, 'renderer'));
    const unmaskedVendor = asString(readField(source, 'unmaskedVendor'));
    const unmaskedRenderer = asString(readField(source, 'unmaskedRenderer'));
    const debugExtensionAvailable = readField(source, 'debugExtensionAvailable') === true;
    const shaderPrecisionProfile = asString(readField(source, 'shaderPrecisionProfile'));
    const privacyHardened = readField(source, 'privacyHardened') === true;

    const unmaskedRendererPresent = isPresent(unmaskedRenderer);
    const unmaskedVendorPresent = isPresent(unmaskedVendor);
    const effectiveRenderer = unmaskedRendererPresent ? unmaskedRenderer : renderer;
    const effectiveVendor = unmaskedVendorPresent ? unmaskedVendor : vendor;

    const signature = `${vendor} ${renderer} ${unmaskedVendor} ${unmaskedRenderer}`;
    const precision = shaderPrecisionStrength(shaderPrecisionProfile);

    // 1. Software rasterisers are a capability, not a VM verdict. Positive evidence here
    //    outranks a forged high-end public string: the unmasked truth wins.
    if (
      SOFTWARE_RENDERER_PATTERN.test(signature) ||
      SOFTWARE_VENDOR_PATTERN.test(vendor.trim()) ||
      SOFTWARE_VENDOR_PATTERN.test(unmaskedVendor.trim())
    ) {
      const reasons = [
        'software-rasteriser-signature-detected',
        'software-rendering-is-not-a-virtual-machine-verdict',
      ];
      if (!debugExtensionAvailable) {
        reasons.push('software-identified-without-webgl-debug-info');
      }
      return { state: 'software_renderer', answerUnreliable: false, reasons };
    }

    // 2. Active deception / unsupported identity claims.
    const spoofReasons: string[] = [];
    if (STEALTH_TEMPLATE_RENDERER_PATTERN.test(effectiveRenderer)) {
      spoofReasons.push('stealth-template-denylist:intel-iris-opengl-engine');
    }
    if (isIntelIncVendor(effectiveVendor) && GENERIC_MODEL_PATTERN.test(effectiveRenderer)) {
      spoofReasons.push('stealth-template-denylist:intel-inc-with-generic-model');
    }
    if (isConstantWebGLString(effectiveRenderer) || isConstantWebGLString(effectiveVendor)) {
      spoofReasons.push('constant-webgl-string-denylist');
    }
    const highEndClaim = HIGH_END_RENDERER_PATTERN.test(effectiveRenderer);
    if (highEndClaim && !unmaskedRendererPresent) {
      spoofReasons.push('high-end-renderer-claim-without-unmasked-renderer');
    }
    if (highEndClaim && precision === 'weak') {
      spoofReasons.push('high-end-renderer-claim-contradicted-by-low-shader-precision');
    }
    if (spoofReasons.length > 0) {
      return { state: 'spoofed_suspect', answerUnreliable: true, reasons: unique(spoofReasons) };
    }

    // 3. Masking: no debug extension, or no unmasked identity to inspect. A privacy-
    //    hardened posture is annotated but never turns a masked answer into a truthful one.
    if (!debugExtensionAvailable || !unmaskedRendererPresent || !unmaskedVendorPresent) {
      const reasons = [
        !debugExtensionAvailable
          ? 'webgl-debug-renderer-info-extension-unavailable'
          : 'unmasked-webgl-strings-unavailable',
      ];
      if (privacyHardened) reasons.push('privacy-hardened-runtime-masks-gpu-identity');
      return { state: 'masked', answerUnreliable: true, reasons };
    }

    // 4. A genuine unmasked manufacturer identifier is the only hardware anchor.
    if (HARDWARE_GPU_PATTERN.test(`${effectiveVendor} ${effectiveRenderer}`)) {
      const reasons = ['real-unmasked-gpu-identifier-present'];
      if (precision === 'strong') {
        reasons.push('shader-precision-profile-consistent-with-hardware');
      }
      return { state: 'hardware', answerUnreliable: false, reasons };
    }

    return {
      state: 'unknown',
      answerUnreliable: true,
      reasons: ['unrecognized-gpu-signature'],
    };
  } catch (error) {
    // Absolute containment: even an exotic proxy failure must not escape this module.
    const message = error instanceof Error ? error.message : String(error);
    return {
      state: 'unknown',
      answerUnreliable: true,
      reasons: [`gpu-truth-resolution-failed: ${message}`],
    };
  }
}

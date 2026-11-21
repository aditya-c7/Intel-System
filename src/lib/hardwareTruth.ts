/**
 * Silicon-grounded hardware truth probes.
 *
 * UA and UA-CH values are *claims*: they are ordinary JavaScript strings and can be
 * rewritten by a DevTools device preset or an anti-detect browser. This module derives
 * host facts from runtime physics instead, using three independent probes:
 *
 *   1. IEEE754 NaN sign-bit probe — RETAINED AS TELEMETRY ONLY. Live audits showed it
 *      reports `arm` on real x86_64 Xeon hardware, so it is NEVER an architecture anchor
 *      and can NEVER create an architecture mismatch. See `nanProbe` on the result.
 *   2. `(-1).toFixed(-1)` engine-length probe — the RangeError message length identifies
 *      the JS engine (51 = V8/Chromium, 25 = SpiderMonkey/Firefox, 43/44 = JavaScriptCore).
 *   3. `Math.tanh(0.8)` ULP probe — since Chromium 148 V8 calls the host libm directly, so
 *      a single transcendental result separates the host OS (Linux glibc, macOS libsystem_m,
 *      Windows UCRT).
 *
 * Architecture resolution is a strict consensus of three trustworthy sources: the
 * WebGL silicon family (only when a real manufacturer GPU is exposed), the UA-CH
 * architecture/bitness claim and `navigator.platform`. A software rasteriser such as
 * SwiftShader offers no silicon clue and is ignored. The result is reported as
 * `architectureSource: 'webgl-silicon' | 'platform-consensus' | 'ua-ch-consensus'` —
 * NEVER 'nan-sign-bit' — and a platform/UA-CH consensus never yields a mismatch.
 *
 * Pure, dependency-free and total: every probe is wrapped in try/catch and the
 * resolver never throws. A missing/unavailable probe degrades to `unknown`, which never
 * produces a mismatch — false positives are worse than abstention here.
 */

export type ArchFamily = 'x86' | 'arm' | 'unknown';
export type HostOsFamily = 'windows' | 'macos' | 'linux' | 'unknown';
export type EngineFamily = 'chromium' | 'firefox' | 'webkit' | 'unknown';
export type GpuArchFamily = 'x86' | 'arm' | 'software' | 'unknown';

export interface NanArchProbe {
  /** Most-significant byte of the produced IEEE754 double (0x7f / 0xff family). */
  highByte: number | null;
  negative: boolean | null;
  family: ArchFamily;
  reason: string;
}

export interface TanhUlpProbe {
  value: number | null;
  /** ULP distance to the nearest host-OS reference value. */
  ulpDelta: number | null;
  hostOs: HostOsFamily;
  reason: string;
}

export interface HardwareTruthInput {
  gpuVendor?: string;
  gpuRenderer?: string;
  /** UA-CH / `sec-ch-ua-arch` architecture claim (e.g. 'x86', 'arm', 'arm64'). */
  claimedArchitecture?: string;
  /** UA-CH `sec-ch-ua-bitness` claim ('64' / '32'); used only for the 32/64 label. */
  claimedBitness?: string;
  /** `navigator.platform` / UA-CH platform claim. */
  claimedPlatform?: string;
  /** Capability-derived software-rasteriser verdict (SwiftShader / masked / low-tier GPU). */
  softwareRenderer?: boolean;
  /** The UA-derived OS family label (e.g. 'Windows 11', 'Android 14', 'iOS 18'). */
  claimedOs?: string;
  userAgent?: string;
}

export interface HardwareTruth {
  /** Silicon architecture label used as the stable hardware anchor. */
  architecture: string;
  /** How `architecture` was determined (for telemetry/attribution). */
  architectureSource: string;
  /** The UA/UA-CH architecture claim, kept beside the truth for the mismatch flag. */
  claimedArchitecture: string;
  hostOs: HostOsFamily;
  engine: EngineFamily;
  engineErrorLength: number;
  gpuArchFamily: GpuArchFamily;
  archUaMismatch: boolean;
  osUaMismatch: boolean;
  reasons: string[];
  nanProbe: NanArchProbe;
  tanhProbe: TanhUlpProbe;
}

/** Canonical `Math.tanh(0.8)` values from the host libm (Chromium 148+ research). */
const TANH_OS_REFERENCE: ReadonlyArray<{ os: Exclude<HostOsFamily, 'unknown'>; value: number }> = [
  { os: 'linux', value: 0.6640367702678491 },
  { os: 'macos', value: 0.664036770267849 },
  { os: 'windows', value: 0.6640367702678489 },
];

/** Reinterpret a positive double's bits as an integer so ULP distance is exact. */
function doubleBits(value: number): bigint {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, value);
  return view.getBigUint64(0);
}

function ulpDistance(a: number, b: number): number {
  try {
    const ba = doubleBits(a);
    const bb = doubleBits(b);
    return Number(ba >= bb ? ba - bb : bb - ba);
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

/**
 * Independent host-OS hint from the WebGL graphics backend. This is deliberately a
 * DIFFERENT source from the `Math.tanh` ULP probe: the two must agree before an OS is
 * asserted as verified. Software renderers (SwiftShader/llvmpipe) give no reliable host
 * clue and therefore return 'unknown'.
 */
function hostOsFromGpuBackend(
  vendor: string,
  renderer: string,
  softwareRenderer = false
): HostOsFamily {
  // A software / masked rasteriser (including a spoofed hardware renderer on software
  // silicon) runs unchanged on every host OS and can never corroborate a math-ULP hint.
  if (softwareRenderer) return 'unknown';
  const text = `${vendor || ''} ${renderer || ''}`;
  if (/Direct3D|D3D11|D3D12|ANGLE\s*\([^)]*Direct3D|Microsoft Basic Render/i.test(text)) {
    return 'windows';
  }
  if (/\bMetal\b|Apple M[1-9]\b|Apple GPU\b/i.test(text)) {
    return 'macos';
  }
  // Mesa / EGL / X11 / Vulkan-on-Linux are strong Linux indicators, but exclude the
  // software renderers because those run unchanged on Windows and macOS too.
  if (!/SwiftShader|Software Rasterizer|Software Renderer|Microsoft Basic Render/i.test(text) &&
      /\bMesa\b|llvmpipe|softpipe|Gallium|Linux|X11|\bEGL\b|\bGLX\b/i.test(text)) {
    return 'linux';
  }
  return 'unknown';
}

/**
 * IEEE754 NaN sign-bit architecture probe. `Math.sqrt(-1)` yields a NaN whose top byte
 * is 0xff on x86-class FP implementations (sign bit set) and 0x7f on ARM/aarch64
 * (sign bit cleared). Some engines canonicalise the payload, so an unexpected byte is
 * reported as `unknown` rather than guessed — the GPU family is the tie-breaker.
 */
export function probeNanSignArch(): NanArchProbe {
  try {
    const buffer = new ArrayBuffer(8);
    const float = new Float64Array(buffer);
    const bytes = new Uint8Array(buffer);
    float[0] = Math.sqrt(-1);
    const highByte = bytes[7];
    const negative = (highByte & 0x80) !== 0;
    let family: ArchFamily = 'unknown';
    if (highByte === 0xff || highByte === 0xfd || highByte === 0xfe) family = 'x86';
    else if (highByte === 0x7f || highByte === 0x7d || highByte === 0x7e) family = 'arm';
    return {
      highByte,
      negative,
      family,
      reason: `NaN high byte 0x${highByte.toString(16).padStart(2, '0')} (${family})`,
    };
  } catch {
    return { highByte: null, negative: null, family: 'unknown', reason: 'NaN probe unavailable' };
  }
}

/**
 * `(-1).toFixed(-1)` engine-length probe. The call throws a RangeError whose message
 * length is stable per engine: 51 = V8, 25 = SpiderMonkey, 43/44 = JavaScriptCore.
 * The `(-1)` form is deliberate — coercing through `parseInt` can change the message
 * in engines that optimise the literal path differently.
 */
export function probeEngineLength(): number {
  try {
    return (-1).toFixed(-1).length;
  } catch (error) {
    return error instanceof Error ? error.message.length : 0;
  }
}

export function resolveEngineFamily(length: number): EngineFamily {
  if (length === 51) return 'chromium';
  if (length === 25) return 'firefox';
  if (length === 43 || length === 44) return 'webkit';
  return 'unknown';
}

/**
 * `Math.tanh(0.8)` host-OS ULP probe. The three libm implementations differ by one or
 * two ULPs at this input. Only a value within 3 ULPs of a canonical reference is
 * trusted; anything else (a different engine, a polyfill, a hardened math shim) yields
 * `unknown` so it can never manufacture an OS mismatch.
 */
export function probeTanhUlp(): TanhUlpProbe {
  try {
    const value = Math.tanh(0.8);
    let best: Exclude<HostOsFamily, 'unknown'> = 'linux';
    let bestDelta = Number.POSITIVE_INFINITY;
    for (const reference of TANH_OS_REFERENCE) {
      const delta = ulpDistance(value, reference.value);
      if (delta < bestDelta) {
        bestDelta = delta;
        best = reference.os;
      }
    }
    const hostOs: HostOsFamily = bestDelta <= 3 ? best : 'unknown';
    return {
      value,
      ulpDelta: bestDelta === Number.POSITIVE_INFINITY ? null : bestDelta,
      hostOs,
      reason: `tanh(0.8)=${value} (${bestDelta} ULP from ${best}${bestDelta <= 3 ? '' : ' — untrusted'})`,
    };
  } catch {
    return {
      value: null,
      ulpDelta: null,
      hostOs: 'unknown',
      reason: 'tanh probe unavailable',
    };
  }
}

/** Software / masked rasteriser signatures: these expose no CPU architecture clue. */
const SOFTWARE_GPU_PATTERN =
  /swiftshader|llvmpipe|softpipe|mesa offscreen|software rasterizer|software renderer|basic render driver|microsoft basic render|apple software renderer|virgl|goldfish|ranchu/i;

/** A discrete-GPU renderer token, used to detect a spoofed renderer on software silicon. */
const DISCRETE_GPU_RENDERER_PATTERN =
  /nvidia|geforce|quadro|\brtx\b|\bgtx\b|radeon|\bamd\b|intel|iris|uhd graphics|hd graphics|arc graphics|apple m[1-9]/i;

/** A known software vendor token — deliberately excludes ANGLE's `Google Inc. (NVIDIA)`. */
function isSoftwareGpuVendor(vendor: string): boolean {
  const value = (vendor || '').trim();
  if (/google inc\.?\s*\(\s*google\s*\)|swiftshader|^google$|^webkit$|^mozilla$|^mesa/i.test(value)) {
    return true;
  }
  return false;
}

/**
 * WebGL silicon family. Software rasterisers and inconsistent (spoofed) signatures are
 * classified as 'software'/'unknown' — NEVER as a manufacturer family. A spoofed renderer
 * that claims an RTX 4090 while the vendor is still the ANGLE/Google software vendor, or
 * while the capability-derived `softwareRenderer` hint is set, is reported as software.
 */
export function classifyGpuArchFamily(
  gpuVendor?: string,
  gpuRenderer?: string,
  softwareRenderer = false
): GpuArchFamily {
  const signature = `${gpuVendor || ''} ${gpuRenderer || ''}`.trim();
  if (softwareRenderer) return 'software';
  if (!signature) return 'unknown';
  if (SOFTWARE_GPU_PATTERN.test(signature)) return 'software';
  // A software vendor claiming a discrete desktop GPU is an inconsistent (spoofed)
  // signature: never mint an x86/arm manufacturer family from it.
  if (isSoftwareGpuVendor(gpuVendor || '') && DISCRETE_GPU_RENDERER_PATTERN.test(gpuRenderer || '')) {
    return 'software';
  }
  if (
    /adreno|mali|powervr|apple gpu|apple m[1-9]|videocore|broadcom|tegra|imagination|arm gpu/i.test(
      signature
    )
  ) {
    return 'arm';
  }
  if (
    /nvidia|geforce|quadro|radeon|amd|intel|iris|uhd graphics|hd graphics|arc graphics|direct3d|d3d1[01]|angle \(.*(nvidia|intel|amd|radeon)/i.test(
      signature
    )
  ) {
    return 'x86';
  }
  return 'unknown';
}

/** Derive an architecture family from a UA-CH string or a `navigator.platform` value. */
export function archFamilyFromClaim(claim: string): ArchFamily {
  const value = (claim || '').toLowerCase();
  if (!value) return 'unknown';
  if (/arm|aarch|arm64|armv[3-9]/i.test(value)) return 'arm';
  if (/x86|x64|amd64|ia64|i[3-6]86|win64|wow64/i.test(value)) return 'x86';
  return 'unknown';
}

/** Derive an OS family from a UA-derived label or a `navigator.platform` value. */
export function osFamilyFromClaim(claim: string, userAgent = ''): HostOsFamily {
  const corpus = `${claim || ''} ${userAgent || ''}`.toLowerCase();
  if (!corpus.trim()) return 'unknown';
  if (/windows|win32|win64|windows nt/i.test(corpus)) return 'windows';
  if (/iphone|ipad|ipod|ios|macintosh|mac os x|macintel|macos/i.test(corpus)) return 'macos';
  if (/android/i.test(corpus)) return 'linux';
  if (/cros|chrome os|linux|x11/i.test(corpus)) return 'linux';
  return 'unknown';
}

/** Turn a family into the stable label stored on `HardwareSignals.architecture`. */
function architectureLabel(family: ArchFamily, bitnessHint: string): string {
  if (family === 'unknown') return 'unknown';
  const bits64 = /64|x86_64|arm64|aarch64|amd64|wow64/i.test(bitnessHint);
  if (family === 'arm') return bits64 ? 'arm64' : 'arm';
  return bits64 ? 'x86_64' : 'x86';
}

/**
 * A Rosetta / WOW64-style translation is a legitimate reason for the claimed arch to
 * differ from the silicon arch (Apple Silicon running x86 Chrome, Windows-on-ARM
 * running x86 binaries). Such pairs must never be flagged as a UA mismatch.
 */
function isKnownArchTranslation(silicon: ArchFamily, claimed: ArchFamily, ua: string, gpu: string): boolean {
  if (silicon === 'unknown' || claimed === 'unknown') return false;
  const macVm = /macintosh|mac os x|macintel/i.test(ua) && /apple m[1-9]|apple gpu/i.test(gpu);
  const rosetta = macVm && silicon === 'arm' && claimed === 'x86';
  const wow64 = /wow64|win64/i.test(ua) && silicon === 'x86' && claimed === 'x86';
  return rosetta || wow64;
}

/**
 * Combine all probes into one hardware-truth verdict.
 *
 * `archUaMismatch` / `osUaMismatch` are intentionally conservative: architecture fires
 * only when WebGL silicon disagrees with a STRONG two-source (sec-ch-ua-arch +
 * navigator.platform) claim — a lone platform string is labelling-only, never proof — and
 * OS fires only when two independent host probes agree, with no legitimate translation
 * layer explaining the difference. This keeps a genuine Mali-G615 Android device (silicon
 * 'arm', GPU family 'arm'/'unknown', NaN telemetry 'arm') out of both mismatch flags. The
 * NaN sign-bit probe is telemetry only and can never manufacture an architecture mismatch
 * (live x86_64 audits showed it reporting `arm`).
 */
export function resolveHardwareTruth(input: HardwareTruthInput = {}): HardwareTruth {
  const nan = probeNanSignArch(); // TELEMETRY ONLY — never an architecture anchor.
  const engineLength = probeEngineLength();
  const engine = resolveEngineFamily(engineLength);
  const tanh = probeTanhUlp();
  const gpuArchFamily = classifyGpuArchFamily(
    input.gpuVendor,
    input.gpuRenderer,
    input.softwareRenderer
  );
  const claimedArchitecture = (input.claimedArchitecture || '').trim();
  const reasons: string[] = [tanh.reason];

  // UA-CH architecture + navigator.platform consensus. When both are known and agree they
  // are the authoritative claim; when they disagree the claim is treated as unknown.
  const uaArchFamily = archFamilyFromClaim(claimedArchitecture);
  const platformArchFamily = archFamilyFromClaim(input.claimedPlatform || '');
  const claimedArchFamily: ArchFamily =
    uaArchFamily !== 'unknown' && platformArchFamily !== 'unknown'
      ? uaArchFamily === platformArchFamily
        ? uaArchFamily
        : 'unknown'
      : uaArchFamily !== 'unknown'
      ? uaArchFamily
      : platformArchFamily;
  // A mismatch may only be asserted from a STRONG claim: sec-ch-ua-arch AND navigator.platform
  // both known and agreeing. A lone platform string (often odd on genuine Android builds) or a
  // lone UA-CH token is fine for labelling, but can never manufacture an arch mismatch against
  // real silicon such as a Mali-G615 GPU (which reports 'arm' even when one claim says 'x86').
  const hasStrongArchClaim =
    uaArchFamily !== 'unknown' && platformArchFamily !== 'unknown' && uaArchFamily === platformArchFamily;

  // Architecture resolution — three trustworthy sources, strictly ranked:
  //   (a) a real WebGL silicon family (manufacturer GPU exposed), else
  //   (b) the UA-CH architecture/bitness + navigator.platform consensus.
  // A software/unavailable rasteriser offers no silicon clue; the NaN sign-bit probe is
  // telemetry only and is deliberately NEVER a source.
  let silicon: ArchFamily = 'unknown';
  // Only these three labels are ever emitted; 'nan-sign-bit' and 'unavailable' are retired.
  let architectureSource: 'webgl-silicon' | 'platform-consensus' | 'ua-ch-consensus' =
    'ua-ch-consensus';
  let hardwareAnchored = false;
  if (gpuArchFamily === 'x86' || gpuArchFamily === 'arm') {
    silicon = gpuArchFamily;
    architectureSource = 'webgl-silicon';
    hardwareAnchored = true;
    reasons.push(`GPU silicon family ${gpuArchFamily} is the architecture anchor`);
    if (nan.family !== 'unknown' && nan.family !== silicon) {
      reasons.push(
        `NaN sign-bit ${nan.family} disagrees with GPU family ${silicon}; ignored (NaN is telemetry only)`
      );
    }
  } else if (claimedArchFamily !== 'unknown') {
    silicon = claimedArchFamily;
    // UA-CH architecture + navigator.platform agreement is a UA-CH consensus. A family
    // recovered from navigator.platform alone is reported as a platform consensus.
    architectureSource = uaArchFamily !== 'unknown' ? 'ua-ch-consensus' : 'platform-consensus';
    reasons.push(
      `No GPU silicon clue (${gpuArchFamily}); architecture resolved from UA-CH/platform consensus (${silicon})`
    );
    reasons.push('NaN sign-bit probe retained as telemetry only; never an architecture anchor');
  } else {
    reasons.push('No trustworthy architecture source (NaN sign-bit deliberately ignored)');
  }

  const archLabel = architectureLabel(
    silicon,
    `${input.claimedBitness || ''} ${claimedArchitecture} ${input.claimedPlatform || ''}`
  );
  const gpuSignature = `${input.gpuVendor || ''} ${input.gpuRenderer || ''}`;
  // A mismatch can only be asserted from corroborated hardware evidence AND a strong,
  // two-source UA-CH/platform consensus. Platform-consensus resolution (software GPU),
  // a lone platform string and the ignored NaN probe can NEVER create a mismatch.
  const archUaMismatch =
    hardwareAnchored &&
    hasStrongArchClaim &&
    claimedArchFamily !== 'unknown' &&
    silicon !== claimedArchFamily &&
    !isKnownArchTranslation(silicon, claimedArchFamily, input.userAgent || '', gpuSignature);
  if (archUaMismatch) {
    reasons.push(`GPU silicon ${silicon} contradicts claimed architecture ${claimedArchFamily}`);
  }

  const claimedOsFamily = osFamilyFromClaim(input.claimedOs || '', input.userAgent || '');
  const gpuHostOs = hostOsFromGpuBackend(
    input.gpuVendor || '',
    input.gpuRenderer || '',
    input.softwareRenderer
  );

  // The `Math.tanh` ULP probe is only one-ULP separated between Linux/macOS/Windows and
  // V8/libm changes can shift it. It is NEVER sufficient on its own. Require agreement
  // with the independent graphics-backend hint before asserting a host OS; a disagreement
  // means "unknown", not "pick one". Software renderers leave the OS unknown.
  let resolvedHostOs: HostOsFamily = 'unknown';
  // Only a two-probe agreement is strong enough to assert an OS mismatch. A single graphics
  // hint (e.g. an Android WebGL string containing a Mesa/EGL token, or a software rasteriser)
  // is left unverified so it can never manufacture an osUaMismatch against a real device.
  let hostOsConfirmed = false;
  if (tanh.hostOs !== 'unknown' && gpuHostOs !== 'unknown' && tanh.hostOs === gpuHostOs) {
    resolvedHostOs = tanh.hostOs;
    hostOsConfirmed = true;
    reasons.push(`Host OS ${resolvedHostOs} confirmed by independent math and graphics-backend probes`);
  } else if (tanh.hostOs !== 'unknown' && gpuHostOs !== 'unknown') {
    reasons.push(
      `Host OS probes disagree (math=${tanh.hostOs}, graphics=${gpuHostOs}); OS left unverified`
    );
  } else if (gpuHostOs !== 'unknown') {
    resolvedHostOs = gpuHostOs;
    reasons.push(`Host OS ${gpuHostOs} inferred from graphics backend (not independently confirmed)`);
  } else if (tanh.hostOs !== 'unknown') {
    reasons.push(
      `Math ULP probe suggested ${tanh.hostOs} but no corroborating graphics backend; OS left unverified`
    );
  }

  const osUaMismatch =
    hostOsConfirmed &&
    resolvedHostOs !== 'unknown' &&
    claimedOsFamily !== 'unknown' &&
    resolvedHostOs !== claimedOsFamily;
  if (osUaMismatch) {
    reasons.push(`Host OS ${resolvedHostOs} contradicts claimed OS ${claimedOsFamily}`);
  }

  return {
    architecture: archLabel,
    architectureSource,
    claimedArchitecture: claimedArchitecture || (claimedArchFamily !== 'unknown' ? claimedArchFamily : ''),
    hostOs: resolvedHostOs,
    engine,
    engineErrorLength: engineLength,
    gpuArchFamily,
    archUaMismatch,
    osUaMismatch,
    reasons,
    nanProbe: nan,
    tanhProbe: tanh,
  };
}

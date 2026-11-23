/**
 * Browser Tampering Detection — DevTools Device Mode & anti-detect browsers.
 *
 * Chrome DevTools "Dimensions" emulation only overrides surface-level JavaScript getters
 * (`navigator.userAgent`, `screen.width`, `devicePixelRatio`), leaving the underlying engine,
 * operating-system and GPU invariants untouched. Every rule below therefore compares two
 * independent sources of truth instead of trusting a single value:
 *
 *  1. mobile user-agent claim + a desktop `navigator.platform`
 *  2. iOS user-agent claim + a Chromium V8 engine (`eval.toString().length === 33`)
 *  3. iOS user-agent claim + `navigator.maxTouchPoints === 1` (DevTools hard-codes 1;
 *     every physical iPhone reports 5)
 *  4. mobile user-agent claim + `window.outerWidth > screen.width * 1.35`
 *     (DevTools shrinks innerWidth/screen.width but never outerWidth)
 *  5. mobile user-agent claim + a desktop WebGL renderer (NVIDIA / Radeon / Intel / Apple M*)
 *  6. anti-detect browsers: `matchMedia('(device-width: Wpx)')` disagreeing with `screen.width`,
 *     or a replaced `Navigator.prototype` getter, or a UA that differs from the HTTP header
 *
 * Hard evidence only: a genuine iPadOS 13+ device reports `MacIntel` **with** real touch
 * points and is never flagged, and desktop browsers never trigger a mobile rule.
 *
 * Privacy hardening (Tor RFP, Firefox FPP, Brave shields, Safari 26 ATFP) is never granted
 * from a UA token alone: a Gecko-only or JavaScriptCore-only claim executing on Chromium's
 * V8 engine is a UA spoof and is flagged as tampering instead of earning an exemption.
 * Likewise, an injected `window.chrome` on a non-Chromium UA/engine is flagged, while a
 * genuine Electron / Chromium runtime with its real chrome object is not.
 *
 * Automation evidence is split by strength. Injected driver globals (and a confirmed
 * cross-realm getter leak with non-native getters on multiple surfaces) are genuinely
 * strong proof and are promoted to hard bot evidence. A non-native `navigator.webdriver`
 * descriptor and V8's `Error.prototype.name` descriptor preview are WEAK, engine-dependent
 * artifacts that also occur on genuine mobile browsers and under privacy extensions — they
 * are NEVER promoted on their own, and only ever accompany strong proof as context. This
 * is what keeps a real Android/Chrome visitor out of the automation gate.
 *
 * Cross-scope "tampering lie" observations (`tamperingLies.ts`) are integrated as an
 * ADDITIVE shadow verdict only: `resolveTamperingLies` is called with caller-supplied
 * observations and the result is exposed as `tampering_lies`. It never feeds `tampering`,
 * `anti_detect_browser`, `tampering_rule_score`, or any risk score / verdict tier.
 *
 * P1-3 honesty notes:
 *  - `tampering_rule_score` is the canonical score producer. It is a deterministic RULE
 *    BASELINE CONSTANT (`tampering_score_source: 'baseline_constant'`), never a machine
 *    learning model output; the legacy `tampering_ml_score` key is a deprecated alias kept
 *    for one cycle and is synchronized with it.
 *  - The collector's `entropyTelemetry` (worker triangulation, ActiveText, shader profile,
 *    repeat-read) is projected into the shadow verdict as POINTS:0 reasons. Projection never
 *    grants resolver weights, so no score, tier, threshold or canonical flag can move.
 *  - silent-buffer, cyclic `__proto__` and `iframe.contentWindow === window` are shadow-only
 *    STRONG indicators: they abstain unless explicitly observed, carry zero points, and are
 *    gated from promotion until corroborated by actual scored evidence (or a caller gate).
 *
 * A rating layer enforces the false-positive rule on the SHADOW flag only: STRONG (rating 1)
 * contradictions — user-agent / platform / brand divergence between the page and a worker,
 * an iframe realm leak, automation stack frames, a cyclic __proto__ proxy trap, and a
 * 12-triple shader-backend mismatch — may set the additive `anti_detect_browser`. Zero-point STRONG indicators (including the P1-3 ones and the entropy projection) stay gated until scored resolver evidence corroborates them or a caller opens the gate. SOFT
 * (rating 0.5) warnings — languages / hardwareConcurrency / deviceMemory drift, ActiveText
 * color (Windows claim + pure red), simple native getters and privacy-class audio noise —
 * keep their score and reason but can NEVER set that flag. Privacy hardening still removes
 * noise-only lies; cdc_* / webdriver / CDP artifacts are marked artifact-only so they can
 * never set the flag either. Worker collection order (service → shared → dedicated) and
 * its timeouts (4s / 3s / 3s) are collection-side concerns; this function only consumes the
 * resulting observations.
 *
 * T9/T11 corrections (all additive):
 *  - canvas read noise is a real tampering signal (per-read pixels contradict a stable device)
 *    but it is NOT an anti-detect/browser-automation signal, and it invalidates any claim that
 *    a GPU string is an unmasked physical-hardware anchor;
 *  - under privacy hardening (Brave RFP / Tor / Safari AFP) only cross-scope UA/platform/brands,
 *    iframe realm, cyclic __proto__ and a full 12-triple shader OS contradiction may escalate.
 *    All other drift stays a 0.5 warning with no score and no `anti_detect_browser`;
 *  - a masked WEBGL_debug_renderer_info extension or a stealth/template renderer string
 *    ("Intel Iris OpenGL Engine", "WebKit WebGL", placeholders) is published as the additive
 *    `gpu_answer_unreliable` warning (rating 0.5), never as a hardware anchor;
 *  - cdc_* / webdriver / CDP artifacts remain decoupled from `anti_detect_browser`.
 */

import { resolveTamperingLies, type TamperingLiesResult, type WorkerScopeObservations } from './tamperingLies';

export type TamperingConfidence = 'low' | 'medium' | 'high';

export interface TamperingDetails {
  anomaly_score: number;
  anti_detect_browser: boolean;
  devtools_device_emulation: boolean;
  /** True when the runtime is a confirmed privacy-hardened browser (Tor/RFP, Firefox FPP,
   * Brave shields, Safari 26 ATFP). Such browsers are exempt from anti-detect/tamper. */
  privacy_hardened: boolean;
  reasons: string[];
  /** Deterministic automation artifacts corroborated by GENUINELY STRONG proof (injected
   * CDP/Playwright/CDC driver globals or a confirmed cross-realm getter leak on multiple
   * surfaces). Weak, engine-dependent artifacts (a non-native webdriver descriptor or an
   * Error.prototype.name preview) never appear here on their own. The verdict module
   * promotes this list to the single authoritative bot gate. */
  hardAutomationEvidence?: string[];
  /** Additive shadow mirror of the cross-scope lie verdict, colocated with the other tamper
   * telemetry. Identical to the top-level `tampering_lies`; never a verdict input. */
  tampering_lies?: TamperingLiesResult;
  /** ADDITIVE (T9/T11): true when the observed canvas read noise, a masked
   * `WEBGL_debug_renderer_info` extension or a stealth/template GPU string makes the GPU answer
   * unusable as a direct physical-hardware anchor. Informational only. */
  gpu_answer_unreliable?: boolean;
  /** ADDITIVE (T9/T11): the observed canvas read-noise signal, when supplied by the caller. */
  canvas_noise?: boolean;
}

/** Provenance of the published tampering score. It is always rule-derived, never ML. */
export type TamperingScoreSource = 'baseline_constant';

export interface TamperingAssessment {
  tampering: boolean;
  /** Docked DevTools window detected from the outer/inner viewport delta. */
  developerTools: boolean;
  tampering_confidence: TamperingConfidence;
  /** Canonical score producer. A deterministic rule baseline constant raised by the rules
   * below — NOT a machine-learning model output. */
  tampering_rule_score: number;
  /** Machine-readable provenance of `tampering_rule_score`. Always 'baseline_constant'. */
  tampering_score_source: TamperingScoreSource;
  /** @deprecated Misnamed legacy alias for `tampering_rule_score`. It has always been a rule
   * baseline constant, never an ML score. Kept for one deprecation cycle as a synchronized
   * accessor so existing consumers (including ones that mutate it) keep working. */
  tampering_ml_score: number;
  tampering_details: TamperingDetails;
  /** Additive, shadow-only cross-scope lie verdict. Carries the resolver's score and reasons
   * with the false-positive rating layer applied to its flag. NEVER consumed by the canonical
   * tampering verdict, risk score, or verdict tier. Zero/low/false when no observations
   * are supplied. */
  tampering_lies: TamperingLiesResult;
  /** Additive rating metadata for `tampering_lies`: which signals were STRONG (rating 1)
   * versus SOFT warnings (rating 0.5). Never a verdict input. */
  tampering_lies_rating: TamperingLieRating;
  /** ADDITIVE (T9/T11) mirror of `tampering_details.gpu_answer_unreliable`; never a
   * canonical verdict, risk-score or hardware-anchor input. */
  gpu_answer_unreliable?: boolean;
}

/** Rating metadata for the additive shadow lie verdict. */
export interface TamperingLieRating {
  /** 1 when at least one strong contradiction fired, 0.5 for warnings only, 0 when clean. */
  rating: 1 | 0.5 | 0;
  /** Reasons backed by STRONG (rating 1) evidence. */
  strong_signals: string[];
  /** Reasons backed only by SOFT (rating 0.5) evidence. */
  weak_signals: string[];
  /** True when nothing stronger than a 0.5 warning fired. */
  warning_only: boolean;
}

/**
 * Additive entropy telemetry mirrored by the collector (`entropyTelemetry`). It is already
 * collected for informational purposes; the detector only projects POINTS:0 reasons from it
 * into the shadow lie verdict. No field grants score weight or changes a threshold.
 */
export interface EntropyTelemetryLies {
  /** Blob-worker triangulation: only `brands` is a strong contradiction; the other drift
   * fields are soft warnings in the collector and are projected as such here. */
  workerTriangulation?: {
    available?: boolean | null;
    strong?: boolean | null;
    soft?: boolean | null;
    strong_fields?: string[] | null;
    soft_fields?: string[] | null;
  } | null;
  /** `ActiveText` system-color hint. Only the explicit `warning_soft` contradiction is
   * projected, and only outside privacy hardening (noise-only lies are suppressed there). */
  activeText?: {
    color?: string | null;
    windows_blue?: boolean | null;
    warning_soft?: number | null;
  } | null;
  shaderPrecisionProfile?: string | null;
  claimedGpuOs?: string | null;
  audioSilentBufferNonZero?: boolean | null;
  audioRepeatReadDiverged?: boolean | null;
}

/**
 * Extra shadow signals the standalone resolver cannot represent in `WorkerScopeObservations`.
 * All are precomputed by the collector's worker/prototype/shader/audio probes; none is read
 * from a platform API here and none can change the canonical verdict.
 */
export interface TamperingLieExtras {
  /** UA-CH `navigator.userData.brands` differs between window and worker (STRONG). */
  brandsDivergence?: boolean | null;
  /** Clean-iframe `srcdoc` reports the same Navigator identity as the top realm (STRONG). */
  iframeRealmLeak?: boolean | null;
  /** Automation frames are present in the captured error stack (STRONG). */
  automationStackFrames?: boolean | null;
  /** Cyclic `__proto__` trap succeeded: `Object.setPrototypeOf(fn, Object.create(fn))`
   * did not throw, which only a Proxy permits (STRONG). */
  prototypeCyclicTrap?: boolean | null;
  /** Intentional Brave / Firefox RFP / Safari AFP audio noise: classified as privacy, not
   * spoofing, so the audio reasons are dropped from the additive verdict. */
  audioPrivacyNoise?: boolean | null;
  /** Count of `getShaderPrecisionFormat` triples (2 stages x 3 precisions x 2 types).
   * 12 is the full OS-backend check; an explicit value below 12 downgrades the shader
   * contradiction to a 0.5 warning. Absent counts keep the resolver's strong default. */
  shaderPrecisionTripleCount?: number | null;
  /** SHADOW STRONG (points:0): a deliberately silent audio buffer rendered non-zero samples
   * outside privacy hardening. Abstains when null/false or privacy-hardened. */
  silentBufferAnomaly?: boolean | null;
  /** SHADOW STRONG (points:0): a "clean" iframe reported `contentWindow === window`, i.e. the
   * probe never entered a separate realm. Abstains when null/false. */
  iframeContentWindowEqualsWindow?: boolean | null;
  /** Optional caller gate. When true, zero-point STRONG indicators may promote the SHADOW
   * anti_detect flag even without scored resolver evidence. Never affects the canonical
   * verdict, risk score, tier or canonical anti_detect_browser. */
  shadowStrongGate?: boolean | null;
}

export interface TamperingInput {
  webglVendor?: string;
  webglRenderer?: string;
  /** The raw HTTP `User-Agent` header as seen by the server proxy, when available. */
  serverHeaderUA?: string;
  /** Confirmed privacy-hardened runtime. Suppresses anti-detect/tamper rules that are
   * intentional defences (RFP device-width drift, getter wrappers, UA reduction). */
  privacyHardened?: boolean;
  /** Optional cross-scope "tampering lie" observations forwarded to `resolveTamperingLies`.
   * Additive only: the rated verdict is emitted as `tampering_lies` and cannot change this
   * function's canonical verdict, score, or anti_detect_browser flag. */
  tamperingLies?: (WorkerScopeObservations & TamperingLieExtras) | null;
  /** ADDITIVE (P1-3): the collector's `entropyTelemetry` mirror. Every observation is
   * projected into the shadow verdict as a POINTS:0 reason; it cannot change score, tier,
   * threshold, canonical anti_detect_browser, or any risk field. */
  entropyTelemetry?: EntropyTelemetryLies | null;
  /** ADDITIVE (T9/T11): per-read canvas pixel noise (farbling) observed by the collector.
   * `canvasNoiseDetected` and `canvas.noise` are accepted aliases. */
  canvasNoise?: boolean | null;
  canvasNoiseDetected?: boolean | null;
  canvas?: { noise?: boolean | null; classification?: string | null } | null;
  /** ADDITIVE (T9/T11): the unmasked `WEBGL_debug_renderer_info` extension was unavailable
   * or masked. `maskedByPrivacyGpu` / `gpuAnswerUnreliable` are accepted aliases. */
  webglDebugRendererInfoMasked?: boolean | null;
  debugRendererInfoMasked?: boolean | null;
  maskedByPrivacyGpu?: boolean | null;
  gpuAnswerUnreliable?: boolean | null;
  /** Sibling `gpuTruth` aliases, accepted so callers can forward a resolved observation. */
  debugExtensionAvailable?: boolean | null;
  gpuTruthState?: 'hardware' | 'software_renderer' | 'masked' | 'spoofed_suspect' | 'unknown' | string | null;
  /** Coarse, spoof-resistant capability bucket. Telemetry only: it can never anchor hardware. */
  gpuCapabilityClass?: string | null;
}

/** Desktop-only platform strings. A real handheld never reports one. */
const DESKTOP_PLATFORM_PATTERN = /^(Win32|Win64|Windows|MacIntel|Macintosh|Linux x86_64|Linux i686|Linux armv7l?)$/i;

/** Desktop GPU families that can never drive a physical phone or tablet. */
const DESKTOP_GPU_PATTERN =
  /NVIDIA|GeForce|Radeon|RDNA|Intel\(R\)|Iris|UHD Graphics|HD Graphics|Direct3D|D3D11|Apple M[1-9]/i;

/**
 * Stealth/template GPU answers: these are renderer *placeholders*, not a directly observed
 * physical GPU. Safari/AFP and stealth shims return e.g. "Intel Iris OpenGL Engine" when the
 * unmasked-info extension is blocked. Word boundaries keep legitimate ANGLE strings
 * ("... Direct3D11 vs_5_0 ...", "Apple M4") out of this bucket.
 */
const UNRELIABLE_GPU_STRING_PATTERN =
  /\bOpenGL Engine\b|\bWebGL (?:Renderer|Vendor)\b|\bStandard WebGL\b|\bWebKit WebGL\b|\b(?:Unavailable|Unknown|Generic|Mozilla)\b|\bn\/?a\b/i;

/** Canonical, machine-readable reason id shared by all GPU-unreliable causes. */
const GPU_UNRELIABLE_REASON = 'gpu_answer_unreliable';

/** Strict boolean reader: truthy junk (1, 'true', {}) is never treated as evidence. */
function isTrueFlag(...values: unknown[]): boolean {
  return values.some((value) => value === true);
}

/** Canvas farbling may be reported through several collector aliases. */
function hasCanvasNoise(input: TamperingInput): boolean {
  if (isTrueFlag(input.canvasNoise, input.canvasNoiseDetected)) return true;
  try {
    const canvas = input.canvas;
    if (canvas && typeof canvas === 'object') {
      if (canvas.noise === true) return true;
      if (/canvas_noise/i.test(canvas.classification || '')) return true;
    }
  } catch {
    // Ignore hostile sub-objects.
  }
  return false;
}

/**
 * A masked unmasked-info extension, a placeholder/template renderer, or canvas farbling
 * (which perturbs every read of the same surface) makes any "unmasked physical GPU" claim
 * unreliable. Purely additive: no points, no anti-detect flag, no hardware anchor.
 */
function gpuAnswerIsUnreliable(input: TamperingInput, gpuSignature: string): boolean {
  if (
    isTrueFlag(
      input.webglDebugRendererInfoMasked,
      input.debugRendererInfoMasked,
      input.maskedByPrivacyGpu,
      input.gpuAnswerUnreliable
    )
  ) {
    return true;
  }
  // An explicit "extension unavailable" observation, or a sibling gpuTruth state that is not a
  // directly observed hardware/software identity, is likewise not a hardware anchor.
  if (input.debugExtensionAvailable === false) return true;
  if (
    input.gpuTruthState === 'masked' ||
    input.gpuTruthState === 'spoofed_suspect' ||
    input.gpuTruthState === 'unknown'
  ) {
    return true;
  }
  if (gpuSignature && UNRELIABLE_GPU_STRING_PATTERN.test(gpuSignature)) return true;
  return hasCanvasNoise(input);
}

function readNavigatorString(getter: () => unknown): string {
  try {
    const value = getter();
    return typeof value === 'string' ? value : '';
  } catch {
    return '';
  }
}

/** Bindings that only exist when a CDP/Playwright/CDC/Selenium driver owns the page. */
const AUTOMATION_GLOBAL_PATTERN =
  /^cdc_|^\$cdc_|^__\$webdriver|^__webdriverAsyncExecutor|^__selenium|^__fxdriver|^__playwright|^__pwInitScripts|^_phantom|^callPhantom|^domAutomation/i;

/**
 * Weak, engine-dependent automation artifacts. A non-native `navigator.webdriver`
 * descriptor and V8's `Error.prototype.name` descriptor preview both occur on genuine
 * mobile browsers and under privacy extensions, so they are recorded only as *context*.
 * They are NEVER hard evidence by themselves — `detectAutomationTamper` promotes them
 * only when genuinely strong proof already exists.
 */
function weakAutomationArtifacts(): string[] {
  const weak: string[] = [];
  try {
    const proto = typeof Navigator !== 'undefined' ? Navigator.prototype : undefined;
    const descriptor =
      (proto && Object.getOwnPropertyDescriptor(proto, 'webdriver')) ||
      (typeof navigator !== 'undefined' ? Object.getOwnPropertyDescriptor(navigator, 'webdriver') : undefined);
    if (descriptor && typeof descriptor.get === 'function') {
      const source = Function.prototype.toString.call(descriptor.get);
      if (!/\[native code\]/.test(source)) {
        weak.push('non-native navigator.webdriver descriptor (engine-dependent artifact)');
      }
    }
  } catch {
    // Ignore hostile proxies.
  }
  // V8 serialises the Error.prototype.name descriptor while a CDP inspector previews a
  // thrown Error. It is an engine artifact (observable server-side) and is intentionally
  // NOT promoted here; listed so downstream keeps it in the weak-evidence set.
  return weak;
}

/**
 * Strong proof from a cross-realm identity leak: the top window exposes non-native
 * getters on MULTIPLE automation surfaces while a fresh same-origin iframe still reports
 * native getters, together with a controlled (`true`) webdriver value. Genuine mobile
 * browsers and privacy extensions never produce that combination, so it is safe to treat
 * it as hard evidence. A blocked/unreadable iframe is inconclusive and abstains.
 */
function confirmedCrossRealmLeak(): boolean {
  if (typeof document === 'undefined' || typeof window === 'undefined' || !document.body) return false;
  let frame: HTMLIFrameElement | null = null;
  try {
    frame = document.createElement('iframe');
    frame.style.cssText =
      'position:absolute;left:-9999px;top:0;width:1px;height:1px;border:0;opacity:0;';
    frame.setAttribute('aria-hidden', 'true');
    frame.src = 'about:blank';
    document.body.appendChild(frame);
    const child = frame.contentWindow as (Window & typeof globalThis) | null;
    if (!child || !child.navigator) return false;
    const getterSource = (target: object | undefined, property: string): string => {
      try {
        if (!target) return '';
        const descriptor = Object.getOwnPropertyDescriptor(target, property);
        return typeof descriptor?.get === 'function'
          ? Function.prototype.toString.call(descriptor.get)
          : '';
      } catch {
        return '';
      }
    };
    const parentProto = typeof Navigator !== 'undefined' ? Navigator.prototype : undefined;
    let childProto: object | undefined;
    try {
      childProto = child.navigator ? Object.getPrototypeOf(child.navigator) : undefined;
    } catch {
      return false;
    }
    const parentUserAgent = getterSource(parentProto, 'userAgent');
    const parentWebdriver = getterSource(parentProto, 'webdriver');
    const childUserAgent = getterSource(childProto, 'userAgent');
    const childWebdriver = getterSource(childProto, 'webdriver');
    const nonNativeParentSurfaces = [parentUserAgent, parentWebdriver].filter(
      (source) => source && !/\[native code\]/.test(source)
    ).length;
    const webdriverControlled = Boolean(navigator.webdriver);
    return (
      webdriverControlled &&
      nonNativeParentSurfaces >= 2 &&
      /\[native code\]/.test(childUserAgent) &&
      /\[native code\]/.test(childWebdriver)
    );
  } catch {
    return false;
  } finally {
    try {
      frame?.remove();
    } catch {
      // Ignore.
    }
  }
}

/**
 * Deterministic automation artifacts that are hard evidence rather than environment
 * quirks. Strong proof (injected driver globals, or a confirmed cross-realm getter leak
 * on multiple surfaces) is REQUIRED; weak engine-dependent artifacts — a non-native
 * webdriver descriptor or an Error.prototype.name preview — are NEVER promoted on their
 * own. This keeps a genuine Android/Chrome session out of the bot gate. Never throws.
 */
function detectAutomationTamper(): string[] {
  const strong: string[] = [];
  for (const target of [
    typeof window !== 'undefined' ? (window as unknown as Record<string, unknown>) : null,
    typeof document !== 'undefined' ? (document as unknown as Record<string, unknown>) : null,
  ]) {
    if (!target) continue;
    try {
      for (const key of Object.keys(target)) {
        if (AUTOMATION_GLOBAL_PATTERN.test(key)) {
          strong.push(`automation driver binding '${key}' injected into the page`);
        }
      }
    } catch {
      // A hostile global proxy is not evidence.
    }
  }
  if (confirmedCrossRealmLeak()) {
    strong.push('confirmed cross-realm automation identity leak (non-native getters on multiple surfaces)');
  }
  if (strong.length === 0) {
    // Weak artifacts alone are engine-dependent and occur on real mobile browsers.
    return [];
  }
  // Only accompany genuinely strong proof with the weak artifacts as explanatory detail.
  return [...strong, ...weakAutomationArtifacts()];
}

/**
 * Additive-only automation probe. Wider and read-only: it marks the shadow lie verdict as
 * "automation artifact only" for every cdc_* / webdriver / CDP trace so those artifacts can
 * never turn on the additive `anti_detect_browser` flag. It deliberately does NOT feed the
 * canonical hard-evidence list, so no canonical verdict, score, or tier can change here.
 */
function observesAutomationArtifacts(hardEvidence: string[]): boolean {
  if (hardEvidence.length > 0) return true;
  try {
    if (typeof navigator !== 'undefined' && navigator.webdriver === true) return true;
  } catch {
    // Ignore hostile proxies.
  }
  for (const target of [
    typeof window !== 'undefined' ? (window as unknown as object) : null,
    typeof document !== 'undefined' ? (document as unknown as object) : null,
  ]) {
    if (!target) continue;
    try {
      for (const key of Object.getOwnPropertyNames(target)) {
        if (AUTOMATION_GLOBAL_PATTERN.test(key)) return true;
      }
    } catch {
      // An unreadable global is not evidence either way.
    }
  }
  return false;
}

/** STRONG (rating 1) lie evidence: a physical identity contradiction or an injected realm.
 * The three P1-3 shadow-only indicators are rated STRONG for telemetry but carry zero points
 * and are gated from promotion (see `promotionGateOpen` in `detectBrowserTampering`). */
const STRONG_LIE_REASON =
  /navigator\.(?:userAgent|platform) divergence|brands divergence|shader precision profile|iframe realm leak|automation stack frame|cyclic __proto__|silent buffer rendered non-zero|iframe\.contentWindow\s*===\s*window/i;

/** SOFT (rating 0.5) lie evidence: warnings legitimately produced by Chrome privacy tools. */
const WEAK_LIE_REASON =
  /navigator\.(?:languages|hardwareConcurrency|deviceMemory) divergence|ActiveText color|silent audio buffer|repeated audio reads diverged|soft worker-triangulation drift|proxy-wrapped|iframe stealth trap|gpu_answer_unreliable/i;

/**
 * Rate the additive lie reasons. Only STRONG (rating 1) contradictions may set the shadow
 * anti-detect flag; a lone 0.5 warning stays a warning (its score/reason are still reported).
 * A shader profile collected with fewer than 12 precision triples is the weaker 8-triple
 * CreepJS-style probe and is downgraded to a warning.
 */
function rateLieReasons(reasons: string[], shaderTriples?: number | null): TamperingLieRating {
  const strong_signals: string[] = [];
  const weak_signals: string[] = [];
  for (const reason of reasons) {
    const isShader = /shader precision profile/i.test(reason);
    const shaderTooShort =
      isShader && typeof shaderTriples === 'number' && Number.isFinite(shaderTriples) && shaderTriples < 12;
    if (shaderTooShort) {
      // CreepJS-style 8-triple probe: still a warning, never a hard OS-backend contradiction.
      weak_signals.push(reason);
    } else if (STRONG_LIE_REASON.test(reason)) {
      strong_signals.push(reason);
    } else if (WEAK_LIE_REASON.test(reason)) {
      weak_signals.push(reason);
    }
  }
  return {
    rating: strong_signals.length > 0 ? 1 : weak_signals.length > 0 ? 0.5 : 0,
    strong_signals,
    weak_signals,
    warning_only: strong_signals.length === 0 && weak_signals.length > 0,
  };
}

/**
 * Under privacy hardening only the STRONG contradictions may contribute score: cross-scope
 * UA / platform / brands, a clean-iframe realm leak, a cyclic __proto__ trap and a full
 * 12-triple shader OS mismatch. The resolver itself treats cores/memory/languages drift and an
 * ActiveText OS mismatch as hard, but the rating layer classifies them as 0.5 warnings, so this
 * sanitised copy removes them from the *score* path (the reasons remain visible for telemetry).
 * An automation stack frame is a CDP artifact and is likewise removed from the score path.
 */
function stripSoftLieFields(
  source: (WorkerScopeObservations & TamperingLieExtras) | null
): WorkerScopeObservations & TamperingLieExtras {
  const copy: Record<string, unknown> = { ...(source ?? {}) };
  for (const scopeName of ['window', 'dedicated', 'shared', 'service']) {
    const scope = copy[scopeName];
    if (scope && typeof scope === 'object' && !Array.isArray(scope)) {
      const clean: Record<string, unknown> = { ...(scope as Record<string, unknown>) };
      clean.cores = null;
      clean.memory = null;
      clean.languages = null;
      copy[scopeName] = clean;
    }
  }
  copy.activeTextColor = null;
  copy.claimedOs = null;
  copy.automationStackFrames = null;
  const triples = source?.shaderPrecisionTripleCount;
  if (typeof triples === 'number' && Number.isFinite(triples) && triples < 12) {
    copy.shaderPrecisionProfile = null;
    copy.claimedGpuOs = null;
  }
  return copy as WorkerScopeObservations & TamperingLieExtras;
}

/**
 * P1-3: project the collector's additive `entropyTelemetry` into the shadow lie verdict as
 * POINTS:0 reasons. The resolver's weights are deliberately NOT granted here, so projected
 * reasons can never move `anomaly_score`, a risk score, a tier, or any anti_detect threshold.
 * Noise-class observations (activeText warning, audio silent-buffer / repeat-read, worker
 * soft drift) abstain under privacy hardening; hard contradictions (worker `brands`, shader
 * OS mismatch) survive but remain ungated zero-point reasons. Totality is preserved: hostile
 * or malformed telemetry degrades to no reasons rather than throwing.
 */
function projectEntropyTelemetry(
  telemetry: EntropyTelemetryLies | null | undefined,
  privacyForLies: boolean
): string[] {
  const reasons: string[] = [];
  if (!telemetry || typeof telemetry !== 'object') return reasons;
  try {
    const worker = telemetry.workerTriangulation;
    if (worker && typeof worker === 'object') {
      const strongFields = Array.isArray(worker.strong_fields)
        ? worker.strong_fields.filter((field): field is string => typeof field === 'string')
        : [];
      if (worker.strong === true || strongFields.includes('brands')) {
        reasons.push(
          'brands divergence between window and worker (entropyTelemetry worker triangulation, points:0)'
        );
      }
      if (!privacyForLies) {
        const softFields = Array.isArray(worker.soft_fields)
          ? worker.soft_fields.filter((field): field is string => typeof field === 'string')
          : [];
        for (const field of softFields) {
          if (/languages|hardwareConcurrency|deviceMemory/i.test(field)) {
            reasons.push(
              `navigator.${field} divergence (soft worker-triangulation drift, entropyTelemetry, points:0)`
            );
          } else {
            reasons.push(
              `soft worker-triangulation drift in navigator.${field} (entropyTelemetry, points:0)`
            );
          }
        }
      }
    }

    const activeText = telemetry.activeText;
    if (
      !privacyForLies &&
      activeText &&
      typeof activeText === 'object' &&
      activeText.warning_soft === 0.5
    ) {
      reasons.push(
        'ActiveText color contradicts the claimed OS (entropyTelemetry, points:0)'
      );
    }

    if (telemetry.shaderPrecisionProfile && telemetry.claimedGpuOs) {
      // Reuse the resolver's own contradiction detection instead of duplicating its OS
      // classifier. Only the deterministic reason text is projected; its weight is discarded.
      const shaderProbe = resolveTamperingLies({
        shaderPrecisionProfile: telemetry.shaderPrecisionProfile,
        claimedGpuOs: telemetry.claimedGpuOs,
        privacyHardened: true,
      });
      for (const reason of shaderProbe.reasons) {
        reasons.push(`${reason} (entropyTelemetry, points:0)`);
      }
    }

    if (!privacyForLies && telemetry.audioRepeatReadDiverged === true) {
      reasons.push('repeated audio reads diverged (entropyTelemetry, points:0)');
    }
    if (!privacyForLies && telemetry.audioSilentBufferNonZero === true) {
      reasons.push('silent audio buffer returned non-zero samples (entropyTelemetry, points:0)');
    }
  } catch {
    // Hostile telemetry abstains; it never throws into the canonical pipeline.
  }
  return reasons;
}

function detectEngine(): { evalLen: number; isV8: boolean; hasChrome: boolean; isWebKit: boolean } {
  let evalLen = 0;
  try {
    // eslint-disable-next-line no-eval
    evalLen = eval.toString().length;
  } catch {
    evalLen = 0;
  }
  let isV8 = evalLen === 33;
  let hasChrome = false;
  let isWebKit = false;
  try {
    const scope = window as unknown as Record<string, unknown>;
    hasChrome = 'chrome' in scope;
    // A WebKit-only binding is decisive JavaScriptCore evidence and vetoes V8: Safari also
    // exposes the ambiguous `webkitPersistentStorage` prefix, so that token must never be
    // used to assert Chromium (it would misclassify genuine Safari ATFP as a UA spoof).
    if (typeof scope.webkitConvertPointFromNodeToPage === 'function') {
      isWebKit = true;
      isV8 = false;
    } else if (hasChrome) {
      // Legacy V8-positive assertion. `window.chrome` alone is NOT proof of a genuine
      // Chromium engine (it can be injected): the separate chrome-injection rule below
      // uses the eval signature (`evalLen`) so a forged chrome object on a non-V8 engine
      // is still flagged as tampering.
      isV8 = true;
    }
  } catch {
    // Engine probes unavailable (SSR / sandboxed frame): keep the eval-length verdict.
  }
  return { evalLen, isV8, hasChrome, isWebKit };
}

/** True when a `Navigator` getter on the prototype OR the instance was replaced by a spoof. */
function hookedNavigatorGetters(): string[] {
  const hooked: string[] = [];
  try {
    if (typeof navigator === 'undefined') return hooked;
    const touched: (object | null)[] = [
      typeof Navigator !== 'undefined' ? Navigator.prototype : null,
      navigator,
    ];
    for (const target of touched) {
      if (!target) continue;
      for (const property of ['userAgent', 'platform', 'webdriver']) {
        const descriptor = Object.getOwnPropertyDescriptor(target, property);
        if (!descriptor) continue;
        // An own data property on the navigator instance is an explicit spoof: real browsers
        // expose these as prototype getters, never as instance values.
        if (target === navigator && !descriptor.get && !descriptor.set) {
          hooked.push(property);
          continue;
        }
        const getter = descriptor.get;
        if (!getter) continue;
        try {
          if (!/\[native code\]/.test(Function.prototype.toString.call(getter)) && !hooked.includes(property)) {
            hooked.push(property);
          }
        } catch {
          if (!hooked.includes(property)) hooked.push(property);
        }
      }
    }
  } catch {
    // Ignore hostile proxies.
  }
  return hooked;
}

/**
 * `screen.width` vs its own `device-width` media query. Browser zoom, fractional display
 * scaling and sub-pixel rounding legitimately disagree by ±1–2 CSS px, so the check only
 * fails when no width in that tolerance band matches. A real anti-detect spoof moves
 * `screen.width` far outside the band.
 */
function deviceWidthQueryMatches(screenWidth: number): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return true;
  for (let delta = 0; delta <= 2; delta += 1) {
    const candidates = delta === 0 ? [screenWidth] : [screenWidth - delta, screenWidth + delta];
    for (const width of candidates) {
      try {
        if (window.matchMedia(`(device-width: ${width}px)`).matches) return true;
      } catch {
        // Keep trying the remaining widths.
      }
    }
  }
  return false;
}

/**
 * The JS `navigator.userAgent` and the HTTP `User-Agent` must agree, but edge proxies
 * truncate long headers and some privacy tools shorten the header side. A truncation is a
 * prefix relationship, not a spoof; only a substantial non-prefix difference is evidence.
 */
function userAgentContradictsHeader(headerUA: string, ua: string): boolean {
  if (!headerUA || !ua || headerUA === ua) return false;
  if (ua.startsWith(headerUA) || headerUA.startsWith(ua)) return false;
  return Math.abs(headerUA.length - ua.length) > 8;
}

export function detectBrowserTampering(input: TamperingInput = {}): TamperingAssessment {
  const ua =
    readNavigatorString(() => navigator.userAgent) ||
    readNavigatorString(() => (globalThis as { navigator?: Navigator }).navigator?.userAgent) ||
    '';
  const platform = readNavigatorString(() => navigator.platform);
  const maxTouchPoints = Number(
    typeof navigator !== 'undefined' ? navigator.maxTouchPoints ?? 0 : 0
  );
  const outerWidth =
    typeof window !== 'undefined' ? Number(window.outerWidth) || 0 : 0;
  const screenWidth =
    typeof window !== 'undefined' && window.screen ? Number(window.screen.width) || 0 : 0;
  const reasons: string[] = [];
  const hardAutomationEvidence = detectAutomationTamper();
  // T9/T11: canvas farbling is a genuine tampering signal, but never an anti-detect /
  // automation signal. A masked or template GPU answer cannot anchor physical hardware.
  const canvasNoise = hasCanvasNoise(input);
  const gpuSignature = `${input.webglVendor || ''} ${input.webglRenderer || ''}`.trim();
  const gpuUnreliable = gpuAnswerIsUnreliable(input, gpuSignature);
  let anomalyPoints = 0;
  let devtoolsEmulation = false;
  let antiDetect = false;

  // Engine cross-check runs BEFORE any privacy exemption is granted. A privacy-hardened
  // runtime is an intentional defence only when the claimed browser family matches the
  // engine actually executing the page. Firefox/Tor (Gecko) and Safari (JavaScriptCore)
  // UAs never run on Chromium's V8 — that combination is a one-line UA spoof, not FPP/RFP/
  // ATFP. Genuine Tor/FPP (Gecko), Brave shields (Chromium) and Safari 26 ATFP (JSC)
  // profiles stay exempt because their UA and engine agree.
  const engine = detectEngine();
  const claimsFirefox = /Firefox\/|FxiOS\//i.test(ua);
  const claimsSafari =
    /Safari\//i.test(ua) && !/Chrome|Chromium|Edg|OPR|CriOS|FxiOS|Firefox/i.test(ua);
  const firefoxOnV8 = claimsFirefox && engine.isV8;
  const safariOnV8 = claimsSafari && engine.isV8;
  let privacyHardened = input.privacyHardened === true;
  // A UA token alone can never earn the exemption when the engine contradicts it.
  if (privacyHardened && (firefoxOnV8 || safariOnV8)) privacyHardened = false;
  if (firefoxOnV8) {
    reasons.push('Firefox UA on Chromium V8 engine — not a genuine Gecko/FPP profile');
    antiDetect = true;
    anomalyPoints += 55;
  } else if (safariOnV8) {
    reasons.push('Safari UA on Chromium V8 engine — not a genuine JavaScriptCore/ATFP profile');
    antiDetect = true;
    anomalyPoints += 55;
  }

  // An injected `window.chrome` surface on a browser that neither claims a Chromium-family
  // UA nor runs V8 natively is a forged browser artifact. Genuine Electron (which carries
  // `Electron/<version>` alongside `Chrome/<version>`) and real Chromium browsers expose
  // `window.chrome` naturally, so a genuine Electron session is never flagged here.
  const claimsChromiumFamily =
    /Chrome\/|Chromium\/|CriOS\/|HeadlessChrome|Edg[AE]?\/|OPR\/|Electron\//i.test(ua);
  const nativeV8 = engine.evalLen === 33 && !engine.isWebKit;
  // Both halves must be non-Chromium: a genuine Electron/Chromium runtime has a Chromium UA
  // (so the first term is false) and its real chrome object is therefore never flagged.
  if (engine.hasChrome && !claimsChromiumFamily && !nativeV8) {
    privacyHardened = false;
    antiDetect = true;
    anomalyPoints += 55;
    reasons.push('window.chrome injected on a non-Chromium user-agent / engine');
  }

  // Confirmed privacy hardening (Tor/RFP, Firefox FPP, Brave shields, Safari 26 ATFP) is
  // an intentional defence, not active spoofing. Suppress ONLY the rules whose evidence is
  // a known anti-fingerprinting measure; hard device-emulation evidence still stands.
  if (privacyHardened) {
    reasons.push('Privacy-hardened browser (RFP/FPP/farbling/ATFP) — anti-detect rules exempt');
  }

  const claimsIOS = /iPhone|iPad|iPod/i.test(ua);
  const claimsAndroid = /Android/i.test(ua);
  const claimsMobile = claimsIOS || claimsAndroid || /Mobile/i.test(ua);
  const isDesktopPlatform = DESKTOP_PLATFORM_PATTERN.test(platform);
  // iPadOS 13+ identifies as desktop Safari: `MacIntel` plus real multi-touch. That is a
  // legitimate physical device, never a DevTools mobile preset.
  const isLegitIpadOs = platform === 'MacIntel' && maxTouchPoints > 1;

  // 1. Mobile user-agent claim on a desktop platform (DevTools Dimensions preset).
  if (claimsMobile && isDesktopPlatform && !isLegitIpadOs) {
    devtoolsEmulation = true;
    anomalyPoints += 55;
    reasons.push(`Mobile user-agent on desktop platform ${platform}`);
  }

  // 2. iOS user-agent claim executing inside Chromium's V8 engine.
  if (claimsIOS && engine.isV8 && !isLegitIpadOs) {
    devtoolsEmulation = true;
    anomalyPoints += 60;
    reasons.push('iOS user-agent running on the Chromium V8 engine, not JavaScriptCore');
  }

  // 3. DevTools hard-codes a single touch point when emulating an iPhone.
  if (claimsIOS && maxTouchPoints === 1 && !isLegitIpadOs) {
    devtoolsEmulation = true;
    anomalyPoints += 35;
    reasons.push('iOS user-agent with exactly one touch point (DevTools emulation signature)');
  }

  // 4. The outer window can never be wider than the emulated screen.
  if (
    claimsMobile &&
    outerWidth > 0 &&
    screenWidth > 0 &&
    outerWidth > screenWidth * 1.35
  ) {
    devtoolsEmulation = true;
    anomalyPoints += 40;
    reasons.push(
      `Outer window ${outerWidth}px exceeds emulated screen width ${screenWidth}px by >35%`
    );
  }

  // 5. A desktop GPU renderer under a mobile user-agent claim. `gpuSignature` is computed once
  //    at the top of this function and reused by the GPU-reliability check.
  if (claimsMobile && gpuSignature && DESKTOP_GPU_PATTERN.test(gpuSignature)) {
    devtoolsEmulation = true;
    anomalyPoints += 45;
    reasons.push(`Desktop GPU renderer under a mobile user-agent: ${gpuSignature.slice(0, 80)}`);
  }

  // 6a. Cross-path media-query check (anti-detect browsers spoofing `screen.width`).
  //     A ±1–2 px band absorbs browser zoom / fractional DPI rounding, so a normal window
  //     never trips this; only a real spoof moves `screen.width` outside the band.
  if (
    !privacyHardened &&
    typeof window !== 'undefined' &&
    screenWidth > 0 &&
    typeof window.matchMedia === 'function'
  ) {
    try {
      if (!deviceWidthQueryMatches(screenWidth)) {
        antiDetect = true;
        anomalyPoints += 30;
        reasons.push('screen.width disagrees with its own device-width media query');
      }
    } catch {
      // matchMedia rejected the query: no evidence either way.
    }
  }

  // 6b. Replaced Navigator.prototype getters. Privacy extensions commonly wrap a getter
  //     while returning the real value, so a non-native getter is weak evidence on its own:
  //     it must never set `anti_detect_browser` or cross the tampering threshold. Only a
  //     value that actually contradicts another source (rule 8 below) is proof.
  const hookedGetters = hookedNavigatorGetters();
  if (hookedGetters.length > 0 && !privacyHardened) {
    anomalyPoints += 10;
    reasons.push(
      `Navigator getter decorated by a non-native wrapper (${hookedGetters.join(', ')}) — value verified independently`
    );
  }

  // 7. A docked DevTools window reserves a large slice of the outer viewport. Chrome and
  //    Firefox chrome (tab strip, address bar, bookmarks) stays well under 160 px, so the
  //    threshold only trips on a docked panel.
  const outerHeight = typeof window !== 'undefined' ? Number(window.outerHeight) || 0 : 0;
  const innerWidth = typeof window !== 'undefined' ? Number(window.innerWidth) || 0 : 0;
  const innerHeight = typeof window !== 'undefined' ? Number(window.innerHeight) || 0 : 0;
  // Only the height delta is used. Embedded desktop shells and side panels also shrink the
  // inner width, which made a width-based rule fire on legitimate windows.
  const developerTools =
    outerHeight > 0 && innerHeight > 0 && outerHeight - innerHeight > 200;

  // 8. The JS user-agent must equal the HTTP User-Agent header the server observed. Edge
  //    proxies truncate long headers, so a prefix relationship is a truncation, not a spoof.
  const headerUA = (input.serverHeaderUA || '').trim();
  if (userAgentContradictsHeader(headerUA, ua) && !privacyHardened) {
    antiDetect = true;
    anomalyPoints += 40;
    reasons.push('JS navigator.userAgent differs from the HTTP User-Agent header');
  }

  // 9. Deterministic automation artifacts are hard evidence ONLY when backed by genuinely
  //    strong proof (CDP / Playwright / CDC bindings or a confirmed cross-realm getter leak).
  //    A forged webdriver descriptor / Error.name preview on its own is engine-dependent and
  //    is deliberately not promoted. Privacy-hardened runtimes (Tor/RFP, Firefox FPP, Brave
  //    shields, Safari ATFP) stay exempt: their entropy reductions are never an automation verdict.
  if (hardAutomationEvidence.length > 0 && !privacyHardened) {
    antiDetect = true;
    anomalyPoints += 45;
    reasons.push(...hardAutomationEvidence);
  }

  // 10. T9/T11 canvas farbling. It is a real tampering signal (the same surface produces
  //     different pixels on every read), but under privacy hardening it is an intentional
  //     defence: keep the tampering verdict and the reason, and add NO anomaly points and NO
  //     anti-detect flag. Outside privacy hardening it carries its own weight.
  if (canvasNoise) {
    if (!privacyHardened) anomalyPoints += 60;
    if (!reasons.some((reason) => /canvas/i.test(reason))) {
      reasons.push('Canvas toDataURL/getImageData pixel noise (farbling) detected');
    }
  }

  // 11. T9/T11 GPU answer reliability. A masked unmasked-info extension, a stealth/template
  //     renderer or canvas farbling means the GPU string is NOT a physical-hardware anchor.
  //     This is a soft 0.5 warning on the shadow rating: no points, no anti-detect flag.
  if (gpuUnreliable && !reasons.includes(GPU_UNRELIABLE_REASON)) {
    reasons.push(GPU_UNRELIABLE_REASON);
  }

  const clampedScore = Math.min(1, Number((anomalyPoints / 100).toFixed(4)));
  // A privacy-hardened runtime keeps only hard device-emulation evidence and canvas
  // farbling (an intentional defence with its own tamper signal); anti-detect points are
  // suppressed so an intentional defence never becomes an anti-detect / bot verdict.
  const isTampered = privacyHardened
    ? devtoolsEmulation || canvasNoise
    : devtoolsEmulation || antiDetect || canvasNoise || anomalyPoints >= 40;

  // ADDITIVE shadow path. Every canonical value above is already final; nothing below can
  // change `tampering`, `anti_detect_browser`, `tampering_rule_score`, or any risk/verdict tier.
  // The resolver suppresses noise-only lies under privacy hardening; the rating layer here
  // additionally guarantees that a lone 0.5 warning can NEVER set the shadow anti-detect
  // flag. cdc_* / webdriver / CDP traces are marked artifact-only, so they cannot set it
  // either. A hostile observation object degrades to the resolver's safe zero verdict.
  let tampering_lies: TamperingLiesResult = resolveTamperingLies();
  let tampering_lies_rating: TamperingLieRating = {
    rating: 0,
    strong_signals: [],
    weak_signals: [],
    warning_only: false,
  };
  try {
    const source =
      input.tamperingLies && typeof input.tamperingLies === 'object' ? input.tamperingLies : null;
    const privacyForLies = privacyHardened || source?.privacyHardened === true;
    // P1-3: the collector's entropy telemetry is projected as POINTS:0 reasons only. No
    // resolver weight is granted, so the shadow score and every threshold stay untouched.
    const entropyReasons = projectEntropyTelemetry(input.entropyTelemetry, privacyForLies);
    // cdc_* / webdriver / CDP artifacts (stack frames included) are ALWAYS artifact-only:
    // they report a score/reason but can never switch anti_detect_browser on.
    const automationArtifactOnly =
      source?.automationArtifactOnly === true ||
      source?.automationStackFrames === true ||
      observesAutomationArtifacts(hardAutomationEvidence);
    const resolved = resolveTamperingLies({
      ...(source ?? {}),
      privacyHardened: privacyForLies,
      automationArtifactOnly,
    });

    // Brave / Firefox RFP / Safari AFP audio noise is a privacy defence, not spoofing: drop
    // those reasons and their 0.15 weights even when the caller did not flag a hardened UA.
    const audioReason = /silent audio buffer|repeated audio reads diverged/i;
    const audioPrivacy = source?.audioPrivacyNoise === true;
    const droppedAudio = audioPrivacy
      ? resolved.reasons.filter((reason) => audioReason.test(reason)).length
      : 0;
    const reasons = audioPrivacy
      ? resolved.reasons.filter((reason) => !audioReason.test(reason))
      : [...resolved.reasons];

    // Strong signals the standalone resolver cannot encode in WorkerScopeObservations.
    if (source?.brandsDivergence === true) {
      reasons.push('navigator.userAgentData.brands divergence between window and worker');
    }
    if (source?.iframeRealmLeak === true) {
      reasons.push('clean-iframe srcdoc Navigator identity leak (stealth script)');
    }
    if (source?.automationStackFrames === true) {
      reasons.push('automation stack frames detected in the error stack');
    }
    if (source?.prototypeCyclicTrap === true) {
      reasons.push('cyclic __proto__ trap succeeded (Proxy-wrapped native)');
    }

    // P1-3 shadow-only STRONG indicators. They abstain unless explicitly true (the silent
    // buffer additionally abstains under privacy hardening, where noise is an expected
    // defence), carry ZERO points, and are gated from promotion below. They are telemetry,
    // never canonical automation/bot evidence and never an anti_detect threshold change.
    const silentBufferStrong = source?.silentBufferAnomaly === true && !privacyForLies;
    const cyclicTrapStrong = source?.prototypeCyclicTrap === true;
    const iframeSelfStrong = source?.iframeContentWindowEqualsWindow === true;
    const newStrongReasons: string[] = [];
    if (silentBufferStrong) {
      newStrongReasons.push('silent buffer rendered non-zero samples (shadow STRONG, points:0)');
    }
    if (iframeSelfStrong) {
      newStrongReasons.push('iframe.contentWindow === window (shadow STRONG, points:0)');
    }
    reasons.push(...newStrongReasons);

    // T9/T11: a masked renderer / stealth GPU template / farbled canvas is reported as an
    // informational 0.5 warning. It never contributes shadow score or anti_detect_browser.
    if (gpuUnreliable && !reasons.includes(GPU_UNRELIABLE_REASON)) {
      reasons.push(GPU_UNRELIABLE_REASON);
    }
    // Append the entropy-telemetry projection last. It is deliberately outside the score
    // path, so these reasons are visible for telemetry but add no points whatsoever.
    reasons.push(...entropyReasons);

    tampering_lies_rating = rateLieReasons(reasons, source?.shaderPrecisionTripleCount);
    // Privacy hardening removes the score contribution of every 0.5 warning; only the four
    // allowed hard contradictions may still raise the shadow score. Reasons stay visible.
    const scoreSource = privacyForLies
      ? resolveTamperingLies({
          ...stripSoftLieFields(source),
          privacyHardened: true,
          automationArtifactOnly,
        })
      : resolved;
    // P1-3 gate: zero-point STRONG indicators (the three new shadow indicators plus any
    // STRONG entropy-telemetry projection) are rated STRONG for telemetry but cannot promote
    // the shadow anti_detect flag until real scored resolver evidence corroborates them —
    // or the caller explicitly opens the gate. They never add score points in either case.
    const hasZeroPointStrong =
      silentBufferStrong ||
      cyclicTrapStrong ||
      iframeSelfStrong ||
      entropyReasons.some((reason) => STRONG_LIE_REASON.test(reason));
    const hasScoredEvidence = scoreSource.anomaly_score > 0;
    const promotionGateOpen =
      !hasZeroPointStrong || hasScoredEvidence || source?.shadowStrongGate === true;

    tampering_lies = {
      anomaly_score: Math.max(
        0,
        Number((scoreSource.anomaly_score - droppedAudio * 0.15).toFixed(4))
      ),
      // Only STRONG (rating 1) evidence can set the flag, automation artifacts never can,
      // and zero-point indicators stay gated until the gate above opens.
      anti_detect_browser:
        tampering_lies_rating.rating === 1 && !automationArtifactOnly && promotionGateOpen,
      tampering_confidence: tampering_lies_rating.rating === 1 ? 'high' : 'low',
      reasons,
    };
  } catch {
    // Keep the safe zero verdict and empty rating; never throw into the canonical pipeline.
  }

  const ruleScore = isTampered ? Math.max(0.842, clampedScore) : 0.0024;
  const assessment: TamperingAssessment = {
    tampering: isTampered,
    developerTools,
    tampering_confidence: isTampered ? (anomalyPoints >= 70 ? 'high' : 'medium') : 'high',
    tampering_rule_score: ruleScore,
    tampering_score_source: 'baseline_constant',
    tampering_ml_score: ruleScore,
    tampering_details: {
      anomaly_score: privacyHardened && !isTampered ? 0 : Number((Math.min(100, anomalyPoints) / 100).toFixed(2)),
      anti_detect_browser: privacyHardened ? false : antiDetect,
      devtools_device_emulation: devtoolsEmulation,
      privacy_hardened: privacyHardened,
      reasons,
      hardAutomationEvidence: privacyHardened ? [] : hardAutomationEvidence,
      tampering_lies,
      gpu_answer_unreliable: gpuUnreliable,
      canvas_noise: canvasNoise,
    },
    tampering_lies,
    tampering_lies_rating,
    gpu_answer_unreliable: gpuUnreliable,
  };
  // P1-3: the deprecated `tampering_ml_score` name is kept for one cycle as a SYNCHRONIZED
  // alias of the canonical rule score. A consumer that still writes the old key (the collector
  // does today) cannot desynchronize it from `tampering_rule_score`, while the honest name and
  // provenance are available to new consumers. The score remains a rule baseline constant.
  Object.defineProperty(assessment, 'tampering_ml_score', {
    enumerable: true,
    configurable: true,
    get: () => assessment.tampering_rule_score,
    set: (value: number) => {
      assessment.tampering_rule_score = value;
    },
  });
  return assessment;
}

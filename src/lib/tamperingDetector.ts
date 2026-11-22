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
 * `anti_detect_browser`, `tampering_ml_score`, or any risk score / verdict tier.
 *
 * A rating layer enforces the false-positive rule on the SHADOW flag only: STRONG (rating 1)
 * contradictions — user-agent / platform / brand divergence between the page and a worker,
 * an iframe realm leak, automation stack frames, a cyclic __proto__ proxy trap, and a
 * 12-triple shader-backend mismatch — may set the additive `anti_detect_browser`. SOFT
 * (rating 0.5) warnings — languages / hardwareConcurrency / deviceMemory drift, ActiveText
 * color (Windows claim + pure red), simple native getters and privacy-class audio noise —
 * keep their score and reason but can NEVER set that flag. Privacy hardening still removes
 * noise-only lies; cdc_* / webdriver / CDP artifacts are marked artifact-only so they can
 * never set the flag either. Worker collection order (service → shared → dedicated) and
 * its timeouts (4s / 3s / 3s) are collection-side concerns; this function only consumes the
 * resulting observations.
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
}

export interface TamperingAssessment {
  tampering: boolean;
  /** Docked DevTools window detected from the outer/inner viewport delta. */
  developerTools: boolean;
  tampering_confidence: TamperingConfidence;
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
}

/** Desktop-only platform strings. A real handheld never reports one. */
const DESKTOP_PLATFORM_PATTERN = /^(Win32|Win64|Windows|MacIntel|Macintosh|Linux x86_64|Linux i686|Linux armv7l?)$/i;

/** Desktop GPU families that can never drive a physical phone or tablet. */
const DESKTOP_GPU_PATTERN =
  /NVIDIA|GeForce|Radeon|RDNA|Intel\(R\)|Iris|UHD Graphics|HD Graphics|Direct3D|D3D11|Apple M[1-9]/i;

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

/** STRONG (rating 1) lie evidence: a physical identity contradiction or an injected realm. */
const STRONG_LIE_REASON =
  /navigator\.(?:userAgent|platform) divergence|brands divergence|shader precision profile|iframe realm leak|automation stack frame|cyclic __proto__/i;

/** SOFT (rating 0.5) lie evidence: warnings legitimately produced by Chrome privacy tools. */
const WEAK_LIE_REASON =
  /navigator\.(?:languages|hardwareConcurrency|deviceMemory) divergence|ActiveText color|silent audio buffer|repeated audio reads diverged|proxy-wrapped|iframe stealth trap/i;

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

  // 5. A desktop GPU renderer under a mobile user-agent claim.
  const gpuSignature = `${input.webglVendor || ''} ${input.webglRenderer || ''}`.trim();
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

  const clampedScore = Math.min(1, Number((anomalyPoints / 100).toFixed(4)));
  // A privacy-hardened runtime keeps only hard device-emulation evidence; anti-detect
  // points are suppressed so an intentional defence never becomes a tamper verdict.
  const isTampered = privacyHardened
    ? devtoolsEmulation
    : devtoolsEmulation || antiDetect || anomalyPoints >= 40;

  // ADDITIVE shadow path. Every canonical value above is already final; nothing below can
  // change `tampering`, `anti_detect_browser`, `tampering_ml_score`, or any risk/verdict tier.
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
    const automationArtifactOnly =
      source?.automationArtifactOnly === true || observesAutomationArtifacts(hardAutomationEvidence);
    const resolved = resolveTamperingLies({
      ...(source ?? {}),
      privacyHardened: privacyHardened || source?.privacyHardened === true,
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

    tampering_lies_rating = rateLieReasons(reasons, source?.shaderPrecisionTripleCount);
    tampering_lies = {
      anomaly_score: Math.max(
        0,
        Number((resolved.anomaly_score - droppedAudio * 0.15).toFixed(4))
      ),
      // Only STRONG (rating 1) evidence can set the flag, and automation artifacts never can.
      anti_detect_browser: tampering_lies_rating.rating === 1 && !automationArtifactOnly,
      tampering_confidence: tampering_lies_rating.rating === 1 ? 'high' : 'low',
      reasons,
    };
  } catch {
    // Keep the safe zero verdict and empty rating; never throw into the canonical pipeline.
  }

  return {
    tampering: isTampered,
    developerTools,
    tampering_confidence: isTampered ? (anomalyPoints >= 70 ? 'high' : 'medium') : 'high',
    tampering_ml_score: isTampered ? Math.max(0.842, clampedScore) : 0.0024,
    tampering_details: {
      anomaly_score: privacyHardened && !isTampered ? 0 : Number((Math.min(100, anomalyPoints) / 100).toFixed(2)),
      anti_detect_browser: privacyHardened ? false : antiDetect,
      devtools_device_emulation: devtoolsEmulation,
      privacy_hardened: privacyHardened,
      reasons,
      hardAutomationEvidence: privacyHardened ? [] : hardAutomationEvidence,
      tampering_lies,
    },
    tampering_lies,
    tampering_lies_rating,
  };
}

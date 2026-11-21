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
 */

export type TamperingConfidence = 'low' | 'medium' | 'high';

export interface TamperingDetails {
  anomaly_score: number;
  anti_detect_browser: boolean;
  devtools_device_emulation: boolean;
  /** True when the runtime is a confirmed privacy-hardened browser (Tor/RFP, Firefox FPP,
   * Brave shields, Safari 26 ATFP). Such browsers are exempt from anti-detect/tamper. */
  privacy_hardened: boolean;
  reasons: string[];
  /** Deterministic automation artifacts (CDP/Playwright/CDC/getter tamper). Each one is
   * hard evidence on its own and is promoted to the bot gate by the verdict module. */
  hardAutomationEvidence?: string[];
}

export interface TamperingAssessment {
  tampering: boolean;
  /** Docked DevTools window detected from the outer/inner viewport delta. */
  developerTools: boolean;
  tampering_confidence: TamperingConfidence;
  tampering_ml_score: number;
  tampering_details: TamperingDetails;
}

export interface TamperingInput {
  webglVendor?: string;
  webglRenderer?: string;
  /** The raw HTTP `User-Agent` header as seen by the server proxy, when available. */
  serverHeaderUA?: string;
  /** Confirmed privacy-hardened runtime. Suppresses anti-detect/tamper rules that are
   * intentional defences (RFP device-width drift, getter wrappers, UA reduction). */
  privacyHardened?: boolean;
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
 * Deterministic automation artifacts that are hard evidence rather than environment
 * quirks: injected driver globals and a `navigator.webdriver` getter that was rewritten
 * to report a controlled session. A privacy extension that merely wraps the getter but
 * still returns `false` is deliberately not flagged. Never throws.
 */
function detectAutomationTamper(): string[] {
  const evidence: string[] = [];
  for (const target of [
    typeof window !== 'undefined' ? (window as unknown as Record<string, unknown>) : null,
    typeof document !== 'undefined' ? (document as unknown as Record<string, unknown>) : null,
  ]) {
    if (!target) continue;
    try {
      for (const key of Object.keys(target)) {
        if (AUTOMATION_GLOBAL_PATTERN.test(key)) {
          evidence.push(`automation driver binding '${key}' injected into the page`);
        }
      }
    } catch {
      // A hostile global proxy is not evidence.
    }
  }
  try {
    const proto = typeof Navigator !== 'undefined' ? Navigator.prototype : undefined;
    const descriptor =
      (proto && Object.getOwnPropertyDescriptor(proto, 'webdriver')) ||
      (typeof navigator !== 'undefined' ? Object.getOwnPropertyDescriptor(navigator, 'webdriver') : undefined);
    if (descriptor && typeof descriptor.get === 'function') {
      const source = Function.prototype.toString.call(descriptor.get);
      if (!/\[native code\]/.test(source) && Boolean(navigator.webdriver)) {
        evidence.push('patched navigator.webdriver getter reports a controlled session');
      }
    }
  } catch {
    // Ignore hostile proxies.
  }
  return evidence;
}

function detectEngine(): { evalLen: number; isV8: boolean } {
  let evalLen = 0;
  try {
    // eslint-disable-next-line no-eval
    evalLen = eval.toString().length;
  } catch {
    evalLen = 0;
  }
  let isV8 = evalLen === 33;
  try {
    const scope = window as unknown as Record<string, unknown>;
    // A WebKit-only binding is decisive JavaScriptCore evidence and vetoes V8: Safari also
    // exposes the ambiguous `webkitPersistentStorage` prefix, so that token must never be
    // used to assert Chromium (it would misclassify genuine Safari ATFP as a UA spoof).
    if (typeof scope.webkitConvertPointFromNodeToPage === 'function') {
      isV8 = false;
    } else if ('chrome' in scope) {
      isV8 = true;
    }
  } catch {
    // Engine probes unavailable (SSR / sandboxed frame): keep the eval-length verdict.
  }
  return { evalLen, isV8 };
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

  // 9. Deterministic automation artifacts (CDP / Playwright / CDC bindings and a forged
  //    webdriver getter) are hard evidence, not environment quirks. Privacy-hardened
  //    runtimes (Tor/RFP, Firefox FPP, Brave shields, Safari ATFP) stay exempt: their
  //    entropy reductions must never become an automation verdict.
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
    },
  };
}

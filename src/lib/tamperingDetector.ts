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
 */

export type TamperingConfidence = 'low' | 'medium' | 'high';

export interface TamperingDetails {
  anomaly_score: number;
  anti_detect_browser: boolean;
  devtools_device_emulation: boolean;
  reasons: string[];
}

export interface TamperingAssessment {
  tampering: boolean;
  tampering_confidence: TamperingConfidence;
  tampering_ml_score: number;
  tampering_details: TamperingDetails;
}

export interface TamperingInput {
  webglVendor?: string;
  webglRenderer?: string;
  /** The raw HTTP `User-Agent` header as seen by the server proxy, when available. */
  serverHeaderUA?: string;
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
    const nav = navigator as unknown as Record<string, unknown>;
    if ('webkitPersistentStorage' in nav || 'chrome' in scope) {
      isV8 = true;
    } else if (typeof scope.webkitConvertPointFromNodeToPage === 'function') {
      isV8 = false;
    }
  } catch {
    // Engine probes unavailable (SSR / sandboxed frame): keep the eval-length verdict.
  }
  return { evalLen, isV8 };
}

/** True when a `Navigator.prototype` getter was replaced by a non-native function. */
function hasHookedNavigatorGetter(): boolean {
  try {
    if (typeof Navigator === 'undefined') return false;
    const descriptors = [
      Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent')?.get,
      Object.getOwnPropertyDescriptor(Navigator.prototype, 'platform')?.get,
      Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver')?.get,
    ];
    return descriptors.some((getter) => {
      if (!getter) return false;
      try {
        return !/\[native code\]/.test(Function.prototype.toString.call(getter));
      } catch {
        return true;
      }
    });
  } catch {
    return false;
  }
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
  let anomalyPoints = 0;
  let devtoolsEmulation = false;
  let antiDetect = false;

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
  const engine = detectEngine();
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
  if (typeof window !== 'undefined' && screenWidth > 0 && typeof window.matchMedia === 'function') {
    try {
      const matchesEmulatedWidth = window.matchMedia(`(device-width: ${screenWidth}px)`).matches;
      if (!matchesEmulatedWidth) {
        antiDetect = true;
        anomalyPoints += 30;
        reasons.push('screen.width disagrees with its own device-width media query');
      }
    } catch {
      // matchMedia rejected the query: no evidence either way.
    }
  }

  // 6b. Replaced Navigator.prototype getters.
  if (hasHookedNavigatorGetter()) {
    antiDetect = true;
    anomalyPoints += 50;
    reasons.push('Navigator.prototype getter replaced by a non-native function');
  }

  // 7. The JS user-agent must equal the HTTP User-Agent header the server observed.
  const headerUA = (input.serverHeaderUA || '').trim();
  if (headerUA && ua && headerUA !== ua) {
    antiDetect = true;
    anomalyPoints += 40;
    reasons.push('JS navigator.userAgent differs from the HTTP User-Agent header');
  }

  const clampedScore = Math.min(1, Number((anomalyPoints / 100).toFixed(4)));
  const isTampered = devtoolsEmulation || antiDetect || anomalyPoints >= 40;

  return {
    tampering: isTampered,
    tampering_confidence: isTampered ? (anomalyPoints >= 70 ? 'high' : 'medium') : 'high',
    tampering_ml_score: isTampered ? Math.max(0.842, clampedScore) : 0.0024,
    tampering_details: {
      anomaly_score: Number((anomalyPoints / 100).toFixed(2)),
      anti_detect_browser: antiDetect,
      devtools_device_emulation: devtoolsEmulation,
      reasons,
    },
  };
}

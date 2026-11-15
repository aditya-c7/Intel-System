/**
 * Genuine physical-device classification.
 *
 * Resizing a window, changing the aspect ratio, or enabling Chrome DevTools
 * device emulation must never turn a desktop into a phone. Viewport width is
 * never used as evidence on its own: a device only counts as mobile when the
 * underlying hardware (platform, CPU architecture, GPU silicon and finger
 * input) agrees with the User-Agent.
 *
 * Ported from aditya-c7/sitebuild (src/lib/deviceDetect.ts) and fused with the
 * WebGL / Client Hints telemetry already collected by Intel System.
 */

export type DeviceKind = 'pc' | 'mobile' | 'tablet';

/** Browser-reported hardware model (UA-CH) — only set for genuine mobile devices. */
export interface DeviceSnapshot {
  kind: DeviceKind;
  os: string;
  browserName: string;
  browserVersion: string;
  reportedModel?: string;
}

export interface PcLock {
  kind: 'pc';
  deviceLabel: string;
  browserName: string;
  firstSeen: string;
  visits: number;
}

// Bump the version whenever detection logic changes so stale snapshots are abandoned.
export const PC_LOCK_KEY = 'adityahq_device_lock_v2';
const LEGACY_LOCK_KEYS = ['adityahq_device_lock'];

const DESKTOP_PLATFORM_PATTERN =
  /^(Win32|Win64|Windows|MacIntel|Macintosh|Linux x86_64|Linux i686|Linux i386|Linux x86)$/i;

/** Desktop-only GPU families — a physical phone or tablet can never report one. */
const DESKTOP_GPU_PATTERN =
  /Direct3D|D3D11|D3D9|NVIDIA|GeForce|Radeon|RDNA|Intel\(R\)|Iris|UHD Graphics|HD Graphics|Apple M[1-9]|llvmpipe|SwiftShader|VMware|Parallels|VirtualBox|Microsoft Basic Render/i;

/** Genuine mobile silicon. */
const MOBILE_GPU_PATTERN = /Adreno|Mali|PowerVR|Immortalis|Xclipse|Apple GPU|Apple A\d/i;

const DESKTOP_ARCH_PATTERN = /x86|x64|amd64|i[3-6]86/i;
const ARM_ARCH_PATTERN = /arm|aarch64|arm64/i;

export interface DeviceGateInput {
  ua: string;
  /** Raw `navigator.platform`. */
  platform: string;
  /** UA-CH `architecture` (e.g. "arm", "x86"). */
  architecture?: string;
  /** UA-CH `mobile` hint. */
  mobileHint?: boolean;
  gpuVendor?: string;
  gpuRenderer?: string;
  maxTouchPoints: number;
  pointerCoarse: boolean;
  hoverNone: boolean;
  hasTouchEvent: boolean;
  viewportWidth: number;
  /** True when a previous visit persisted a desktop hardware lock. */
  pcLocked: boolean;
}

export interface DeviceGateResult {
  kind: DeviceKind;
  /** True only when every hardware invariant confirms physical mobile silicon. */
  genuineMobile: boolean;
  /** True when a mobile User-Agent is running on desktop hardware (DevTools preset). */
  devtoolsDeviceEmulation: boolean;
  reasons: string[];
}

function safeNumber(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

/**
 * Classify the underlying hardware. Pure: callers pass every signal so the
 * same function can be unit-tested without a DOM.
 */
export function classifyGenuineDevice(input: DeviceGateInput): DeviceGateResult {
  const ua = input.ua || '';
  const platform = (input.platform || '').trim();
  const architecture = (input.architecture || '').trim();
  const gpuSignature = `${input.gpuVendor || ''} ${input.gpuRenderer || ''}`.trim();
  const maxTouchPoints = safeNumber(input.maxTouchPoints);
  const viewportWidth = safeNumber(input.viewportWidth);

  const claimsIOS = /iPhone|iPad|iPod/i.test(ua);
  const claimsAndroid = /Android/i.test(ua);
  const claimsMobileUA =
    claimsIOS ||
    claimsAndroid ||
    /Mobile|IEMobile|Opera Mini|Silk|Kindle|BlackBerry|webOS/i.test(ua) ||
    input.mobileHint === true;

  const isDesktopPlatform = DESKTOP_PLATFORM_PATTERN.test(platform);
  const isDesktopArch = DESKTOP_ARCH_PATTERN.test(architecture);
  const isArmArch = ARM_ARCH_PATTERN.test(architecture);
  const hasDesktopGpu = gpuSignature !== '' && DESKTOP_GPU_PATTERN.test(gpuSignature);
  const hasMobileGpu = gpuSignature !== '' && MOBILE_GPU_PATTERN.test(gpuSignature);

  const hasTouch = maxTouchPoints >= 1 || input.hasTouchEvent;
  // Touch alone is not mobile: touchscreen laptops report touch points with a
  // fine (mouse) pointer, so coarse + hover:none are required together.
  const fingerDriven = hasTouch && input.pointerCoarse && input.hoverNone;
  // iPadOS 13+ identifies as desktop Safari: MacIntel with real multi-touch and
  // Apple silicon, never a DevTools preset (which hard-codes one touch point).
  const isLegitIpadOs =
    (platform === 'MacIntel' && maxTouchPoints >= 5 && !hasDesktopGpu) ||
    (/iPad/i.test(ua) && !hasDesktopGpu && !isDesktopArch);

  const reasons: string[] = [];

  // Layer 1 — persistent PC hardware lock. Opening DevTools cannot erase it.
  if (input.pcLocked) {
    reasons.push('Persistent desktop hardware lock');
    return {
      kind: 'pc',
      genuineMobile: false,
      devtoolsDeviceEmulation: claimsMobileUA,
      reasons,
    };
  }

  // Layer 2a — a desktop platform string under a mobile UA is DevTools emulation.
  if (claimsMobileUA && isDesktopPlatform && !isLegitIpadOs) {
    reasons.push(`Mobile user-agent on desktop platform ${platform || 'unknown'}`);
    return { kind: 'pc', genuineMobile: false, devtoolsDeviceEmulation: true, reasons };
  }

  // Layer 2b — x86 CPU under a mobile UA: real phones are ARM.
  if (claimsMobileUA && isDesktopArch && !isLegitIpadOs) {
    reasons.push(`Mobile user-agent on ${architecture} CPU (real phones are ARM)`);
    return { kind: 'pc', genuineMobile: false, devtoolsDeviceEmulation: true, reasons };
  }

  // Layer 2c — desktop GPU under a mobile UA, even with emulated touch points.
  if (claimsMobileUA && hasDesktopGpu && !isLegitIpadOs) {
    reasons.push(`Desktop GPU under a mobile user-agent: ${gpuSignature.slice(0, 80)}`);
    return { kind: 'pc', genuineMobile: false, devtoolsDeviceEmulation: true, reasons };
  }

  // A genuine iPad in desktop-class Safari.
  if (isLegitIpadOs && fingerDriven) {
    reasons.push('iPad-class touch hardware with Apple GPU');
    return { kind: 'tablet', genuineMobile: true, devtoolsDeviceEmulation: false, reasons };
  }

  // iOS: platform + touch silicon must both agree.
  if (claimsIOS) {
    const isIpad = /iPad/i.test(ua) || platform === 'iPad';
    if (fingerDriven && !hasDesktopGpu && !isDesktopArch) {
      reasons.push(isIpad ? 'iPad touch hardware' : 'iPhone touch hardware');
      return {
        kind: isIpad ? 'tablet' : 'mobile',
        genuineMobile: true,
        devtoolsDeviceEmulation: false,
        reasons,
      };
    }
    reasons.push('iOS user-agent without matching touch hardware');
    return { kind: 'pc', genuineMobile: false, devtoolsDeviceEmulation: true, reasons };
  }

  // Android / generic handheld: require finger input and non-desktop silicon.
  if (fingerDriven && !hasDesktopGpu && !isDesktopArch) {
    const androidLike = claimsAndroid || input.mobileHint === true || isArmArch || hasMobileGpu;
    if (androidLike) {
      const tablet =
        input.mobileHint === false ||
        /Tablet/i.test(ua) ||
        (viewportWidth > 767 && !/Mobile/i.test(ua));
      reasons.push(
        tablet ? 'Finger-driven tablet-class hardware' : 'Finger-driven ARM/Android hardware'
      );
      return {
        kind: tablet ? 'tablet' : 'mobile',
        genuineMobile: true,
        devtoolsDeviceEmulation: false,
        reasons,
      };
    }
  }

  // Android UA without finger input is not a genuine phone (emulator / spoof).
  if (claimsAndroid) {
    reasons.push('Android user-agent without coarse finger input');
    return { kind: 'pc', genuineMobile: false, devtoolsDeviceEmulation: true, reasons };
  }

  // Touchscreen laptops keep a fine pointer and land here.
  if (hasTouch && maxTouchPoints > 1 && !fingerDriven) {
    reasons.push('Touch points with a fine (mouse) pointer — desktop hardware');
    return { kind: 'pc', genuineMobile: false, devtoolsDeviceEmulation: false, reasons };
  }

  return { kind: 'pc', genuineMobile: false, devtoolsDeviceEmulation: false, reasons };
}

/** Extract the Android `Build.MODEL` token from a User-Agent (fallback when UA-CH is absent). */
export function extractAndroidModelFromUA(ua: string): string {
  const match = ua.match(
    /Android\s+[\d.]+;\s*(?:[a-z]{2}(?:-[a-zA-Z]{2})?;\s*)?([^;)]+?)(?:\s+Build\/|;?\s*\))/i
  );
  const raw = match?.[1]?.trim() ?? '';
  if (!raw) return '';
  // Chrome's reduced UA sends a generic "K"; wv/Mobile are WebView tokens, not models.
  if (/^(k|wv|mobile|tablet|android)$/i.test(raw)) return '';
  return raw;
}

/** In-app and niche mobile browsers that embed Chrome/Safari tokens. */
export function detectInAppBrowser(ua: string): string | null {
  if (/Instagram/i.test(ua)) return 'Instagram';
  if (/FBAN\/|FBAV\/|FB_IOS|FBIOS/i.test(ua)) return 'Facebook';
  if (/TikTok|musical_ly/i.test(ua)) return 'TikTok';
  if (/Snapchat/i.test(ua)) return 'Snapchat';
  if (/LinkedInApp/i.test(ua)) return 'LinkedIn';
  if (/MicroMessenger/i.test(ua)) return 'WeChat';
  if (/\bLine\//i.test(ua)) return 'Line';
  if (/Twitter for|TwitterAndroid/i.test(ua)) return 'X (Twitter)';
  if (/Reddit/i.test(ua)) return 'Reddit';
  if (/Pinterest/i.test(ua)) return 'Pinterest';
  if (/WhatsApp/i.test(ua)) return 'WhatsApp';
  return null;
}

/** True when a previous visit persisted a desktop hardware lock. */
export function getPcLock(): PcLock | null {
  try {
    if (typeof localStorage === 'undefined') return null;
    const raw = localStorage.getItem(PC_LOCK_KEY);
    if (!raw) return null;
    const data = JSON.parse(raw) as Partial<PcLock>;
    if (
      data &&
      data.kind === 'pc' &&
      typeof data.deviceLabel === 'string' &&
      typeof data.browserName === 'string'
    ) {
      return {
        kind: 'pc',
        deviceLabel: data.deviceLabel,
        browserName: data.browserName,
        firstSeen:
          typeof data.firstSeen === 'string' ? data.firstSeen : new Date(0).toISOString(),
        visits: typeof data.visits === 'number' ? data.visits : 0,
      };
    }
    return null;
  } catch {
    return null;
  }
}

export function savePcLock(
  input: { deviceLabel: string; browserName: string },
  bumpVisits: boolean
): PcLock | null {
  try {
    if (typeof localStorage === 'undefined') return null;
    const existing = getPcLock();
    const lock: PcLock = existing
      ? { ...existing, visits: bumpVisits ? existing.visits + 1 : existing.visits }
      : {
          kind: 'pc',
          deviceLabel: input.deviceLabel,
          browserName: input.browserName,
          firstSeen: new Date().toISOString(),
          visits: 1,
        };
    localStorage.setItem(PC_LOCK_KEY, JSON.stringify(lock));
    return lock;
  } catch {
    return null;
  }
}

/**
 * Mobile hygiene: drop corrupt/legacy device snapshots so a phone never keeps
 * stale desktop state. A valid PC lock is always preserved.
 */
export function releaseNonPcLock(): boolean {
  try {
    if (typeof localStorage === 'undefined') return false;
    let cleared = false;
    for (const key of LEGACY_LOCK_KEYS) {
      if (localStorage.getItem(key) !== null) {
        localStorage.removeItem(key);
        cleared = true;
      }
    }
    const raw = localStorage.getItem(PC_LOCK_KEY);
    if (!raw) return cleared;
    if (getPcLock() !== null) return cleared;
    localStorage.removeItem(PC_LOCK_KEY);
    return true;
  } catch {
    return false;
  }
}

export function detectDeviceLabel(info: DeviceSnapshot): string {
  if (info.kind === 'pc') return info.os;
  return `surfing on ${info.browserName}`;
}

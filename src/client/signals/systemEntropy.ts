/**
 * System entropy probe — environment facts that are cheap to read and hard
 * to fake consistently: timezone, hardware concurrency/memory, screen
 * geometry, media device counts (counts only, never labels — enumerateDevices
 * labels require an active capture permission), storage quota, Apple Pay,
 * speech voices and permission states.
 *
 * Additive context-only sources: battery, geolocation and keyboardStatic.
 * These are read defensively and are NEVER inputs to the hardware or engine
 * digests (see index.ts) — they describe the environment without identifying
 * it. FingerprintJS v5 has no equivalent sources.
 */

import { errorMessage } from './hash';
import type { SystemEntropySignals } from './types';

interface NavigatorWithDeviceMemory extends Navigator {
  deviceMemory?: number;
}

interface ApplePaySessionLike {
  canMakePayments?: () => boolean;
}

/* -------------------------------------------------------------------------- */
/* Additive context shapes — all digest-neutral                               */
/* -------------------------------------------------------------------------- */

/** Stable vocabulary for the coarseness of the Battery Status time readouts. */
export type BatteryTimePrecision = 'none' | 'coarse' | 'whole-seconds' | 'sub-second';

export interface BatterySignals {
  /** True when `navigator.getBattery` was present and callable. */
  supported: boolean;
  charging: boolean | null;
  /** Seconds to full; spec `Infinity` sentinel is normalized to null. */
  chargingTime: number | null;
  /** Seconds to empty; spec `Infinity` sentinel is normalized to null. */
  dischargingTime: number | null;
  /** Charge fraction in [0, 1] per spec; null when unreadable. */
  level: number | null;
  /** Browsers round/bucket times for privacy; see `BatteryTimePrecision`. */
  timePrecisionHint: BatteryTimePrecision | null;
  error?: string;
}

export interface GeolocationCoordinatesSummary {
  latitude: number | null;
  longitude: number | null;
  accuracy: number | null;
  altitude: number | null;
  altitudeAccuracy: number | null;
  heading: number | null;
  speed: number | null;
}

export interface GeolocationSignals {
  /** Permission state from the probe below; the only gate for a location read. */
  permission: PermissionState | null;
  /** True only when the API exists and permission was already granted. */
  available: boolean;
  /** Present only from a successful `getCurrentPosition` callback. */
  coords: GeolocationCoordinatesSummary | null;
  /** DOMTimeStamp of the position, when available. */
  timestamp: number | null;
  /** PositionError.code (1 denied, 2 unavailable, 3 timeout), when reported. */
  errorCode: number | null;
  errorMessage: string | null;
}

export interface KeyboardStaticSignals {
  /** True when `navigator.keyboard.getLayoutMap` was present and callable. */
  supported: boolean;
  /** Static code -> character mapping count (no key-press history). */
  mapSize: number | null;
  /** Whether the static map contains `KeyQ` (the H4 evidence in automation.ts). */
  hasKeyQ: boolean | null;
  /** True when the static layout map resolved empty. */
  layoutEmpty: boolean | null;
  error?: string;
}

/** Superset of the stable shape; every added field is strictly additive. */
export interface SystemEntropySignalsExtended extends SystemEntropySignals {
  battery: BatterySignals;
  geolocation: GeolocationSignals;
  keyboardStatic: KeyboardStaticSignals;
}

const PERMISSION_KEYS: Array<[keyof SystemEntropySignals['permissions'], PermissionName]> = [
  ['geolocation', 'geolocation'],
  ['notifications', 'notifications'],
  ['camera', 'camera' as PermissionName],
  ['microphone', 'microphone' as PermissionName],
];

const GEO_TIMEOUT_MS = 2000;
const GEO_GUARD_MS = GEO_TIMEOUT_MS + 250;

interface NavigatorWithBattery extends Navigator {
  getBattery?: () => Promise<{
    charging: unknown;
    chargingTime: unknown;
    dischargingTime: unknown;
    level: unknown;
  }>;
}

interface NavigatorWithKeyboard extends Navigator {
  keyboard?: {
    getLayoutMap?: () => Promise<{ readonly size: number; has(key: string): boolean }>;
  };
}

/** Finite numbers pass through; `Infinity`, `-Infinity`, `NaN` and non-numbers become null. */
function finiteOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** Coarseness of the finite Battery Status times (`none` when both are sentinels). */
function batteryPrecisionHint(
  chargingTime: number | null,
  dischargingTime: number | null
): BatteryTimePrecision {
  const times: number[] = [];
  if (chargingTime !== null) times.push(chargingTime);
  if (dischargingTime !== null) times.push(dischargingTime);
  if (times.length === 0) return 'none';
  if (times.every((t) => Number.isInteger(t) && t % 60 === 0)) return 'coarse';
  if (times.every((t) => Number.isInteger(t))) return 'whole-seconds';
  return 'sub-second';
}

/**
 * Battery Status API — Chromium-only (removed from Firefox, never shipped in
 * Safari), so absence is reported rather than treated as evidence.
 *
 * W3C spec invariants we rely on when normalizing:
 *  - `level` is a fraction in [0, 1]; 1 means full OR no battery attached.
 *  - `chargingTime` MUST be 0 when full/no battery, and +Infinity when
 *    discharging or the UA cannot estimate it.
 *  - `dischargingTime` MUST be +Infinity when charging, no battery is
 *    attached, or the UA cannot estimate it.
 *  - The spec says a UA SHOULD NOT expose high-precision readouts (a
 *    fingerprinting vector); Chromium rounds `level` and buckets both times.
 * We take one snapshot, map the Infinity sentinels to null, and describe the
 * remaining precision. No change events are subscribed to and nothing here
 * feeds a digest.
 */
async function collectBatterySignals(): Promise<BatterySignals> {
  const result: BatterySignals = {
    supported: false,
    charging: null,
    chargingTime: null,
    dischargingTime: null,
    level: null,
    timePrecisionHint: null,
  };
  if (typeof navigator === 'undefined') return result;
  try {
    const nav = navigator as NavigatorWithBattery;
    if (typeof nav.getBattery !== 'function') return result;
    result.supported = true;
    const battery = await nav.getBattery();
    if (!battery) return result;

    if (typeof battery.charging === 'boolean') result.charging = battery.charging;
    result.chargingTime = finiteOrNull(battery.chargingTime);
    result.dischargingTime = finiteOrNull(battery.dischargingTime);
    result.level = finiteOrNull(battery.level);
    result.timePrecisionHint = batteryPrecisionHint(result.chargingTime, result.dischargingTime);
  } catch (err) {
    result.error = errorMessage(err);
  }
  return result;
}

/**
 * Browser geolocation — read ONLY when the shared permission probe already
 * reports `granted`, so this never prompts and never derives coordinates from
 * an IP/network lookup. `maximumAge` prefers a cached fix and the bound keeps a
 * hostile/slow implementation from stalling the collector. Digest-neutral.
 */
async function collectGeolocationSignals(permission: PermissionState | null): Promise<GeolocationSignals> {
  const result: GeolocationSignals = {
    permission,
    available: false,
    coords: null,
    timestamp: null,
    errorCode: null,
    errorMessage: null,
  };
  if (permission !== 'granted' || typeof navigator === 'undefined') return result;

  try {
    const geo = (navigator as Navigator).geolocation;
    if (!geo || typeof geo.getCurrentPosition !== 'function') return result;
    result.available = true;

    await new Promise<void>((resolve) => {
      let settled = false;
      let guard: ReturnType<typeof setTimeout> | undefined;
      const finish = (): void => {
        if (settled) return;
        settled = true;
        if (guard !== undefined) clearTimeout(guard);
        resolve();
      };
      guard = setTimeout(finish, GEO_GUARD_MS);
      try {
        geo.getCurrentPosition(
          (position) => {
            if (settled) return;
            try {
              const c = position?.coords;
              if (c) {
                result.coords = {
                  latitude: finiteOrNull(c.latitude),
                  longitude: finiteOrNull(c.longitude),
                  accuracy: finiteOrNull(c.accuracy),
                  altitude: finiteOrNull(c.altitude),
                  altitudeAccuracy: finiteOrNull(c.altitudeAccuracy),
                  heading: finiteOrNull(c.heading),
                  speed: finiteOrNull(c.speed),
                };
              }
              result.timestamp = finiteOrNull(position?.timestamp);
            } catch (err) {
              result.errorMessage = errorMessage(err);
            }
            finish();
          },
          (err) => {
            if (settled) return;
            result.errorCode = finiteOrNull(err?.code);
            result.errorMessage = err?.message ? errorMessage(err.message) : null;
            finish();
          },
          { enableHighAccuracy: false, timeout: GEO_TIMEOUT_MS, maximumAge: 60_000 }
        );
      } catch (err) {
        result.errorMessage = errorMessage(err);
        finish();
      }
    });
  } catch (err) {
    result.errorMessage = errorMessage(err);
  }
  return result;
}

/**
 * Static keyboard-layout evidence only. The Keyboard Map spec states that
 * `getLayoutMap()` returns static data with no key-press history; this mirrors
 * the capability/empty-map check already used by automation.ts (H4). There are
 * deliberately NO keydown/keyup or timing listeners — no behavioral signal is
 * collected. Digest-neutral.
 */
async function collectKeyboardStaticSignals(): Promise<KeyboardStaticSignals> {
  const result: KeyboardStaticSignals = {
    supported: false,
    mapSize: null,
    hasKeyQ: null,
    layoutEmpty: null,
  };
  if (typeof navigator === 'undefined') return result;
  try {
    const keyboard = (navigator as NavigatorWithKeyboard).keyboard;
    if (!keyboard || typeof keyboard.getLayoutMap !== 'function') return result;
    result.supported = true;
    const map = await keyboard.getLayoutMap();
    if (!map) return result;
    result.mapSize = typeof map.size === 'number' ? map.size : null;
    result.hasKeyQ = typeof map.has === 'function' ? map.has('KeyQ') : null;
    result.layoutEmpty = result.mapSize === 0;
  } catch (err) {
    result.error = errorMessage(err);
  }
  return result;
}

/** Total (async): always returns a payload. */
export async function collectSystemEntropySignals(): Promise<SystemEntropySignalsExtended> {
  const result: SystemEntropySignalsExtended = {
    timezone: null,
    timezoneOffset: null,
    deviceMemory: null,
    hardwareConcurrency: null,
    screen: {
      width: null,
      height: null,
      colorDepth: null,
      pixelRatio: null,
      maxTouchPoints: null,
    },
    mediaDeviceCounts: {
      audioinput: null,
      audiooutput: null,
      videoinput: null,
    },
    storageQuota: null,
    applePayAvailable: null,
    speechVoicesCount: null,
    permissions: {
      geolocation: null,
      notifications: null,
      camera: null,
      microphone: null,
    },
    battery: {
      supported: false,
      charging: null,
      chargingTime: null,
      dischargingTime: null,
      level: null,
      timePrecisionHint: null,
    },
    geolocation: {
      permission: null,
      available: false,
      coords: null,
      timestamp: null,
      errorCode: null,
      errorMessage: null,
    },
    keyboardStatic: {
      supported: false,
      mapSize: null,
      hasKeyQ: null,
      layoutEmpty: null,
    },
  };

  try {
    try {
      const resolved = Intl.DateTimeFormat().resolvedOptions();
      result.timezone = resolved.timeZone ?? null;
    } catch {
      /* ignore */
    }
    try {
      result.timezoneOffset = new Date().getTimezoneOffset();
    } catch {
      /* ignore */
    }
    try {
      result.deviceMemory = (navigator as NavigatorWithDeviceMemory).deviceMemory ?? null;
    } catch {
      /* ignore */
    }
    try {
      result.hardwareConcurrency = typeof navigator.hardwareConcurrency === 'number'
        ? navigator.hardwareConcurrency
        : null;
    } catch {
      /* ignore */
    }

    try {
      result.screen.width = typeof screen.width === 'number' ? screen.width : null;
    } catch {
      /* ignore */
    }
    try {
      result.screen.height = typeof screen.height === 'number' ? screen.height : null;
    } catch {
      /* ignore */
    }
    try {
      result.screen.colorDepth = typeof screen.colorDepth === 'number' ? screen.colorDepth : null;
    } catch {
      /* ignore */
    }
    try {
      result.screen.pixelRatio = typeof window.devicePixelRatio === 'number' ? window.devicePixelRatio : null;
    } catch {
      /* ignore */
    }
    try {
      result.screen.maxTouchPoints = typeof navigator.maxTouchPoints === 'number' ? navigator.maxTouchPoints : null;
    } catch {
      /* ignore */
    }

    // Media device counts — enumerateDevices() length per kind, labels never
    // read (labels require an active capture permission anyway).
    try {
      const devices = await navigator.mediaDevices?.enumerateDevices();
      if (devices) {
        const counts = { audioinput: 0, audiooutput: 0, videoinput: 0 };
        for (const device of devices) {
          if (device.kind === 'audioinput') counts.audioinput++;
          else if (device.kind === 'audiooutput') counts.audiooutput++;
          else if (device.kind === 'videoinput') counts.videoinput++;
        }
        result.mediaDeviceCounts = counts;
      }
    } catch {
      /* ignore */
    }

    // Storage quota (usage/quota estimate).
    try {
      const estimate = await navigator.storage?.estimate?.();
      if (estimate) {
        result.storageQuota = {
          usage: typeof estimate.usage === 'number' ? estimate.usage : null,
          quota: typeof estimate.quota === 'number' ? estimate.quota : null,
        };
      }
    } catch {
      /* ignore */
    }

    // Apple Pay availability (Safari-only surface).
    try {
      const session = (window as unknown as { ApplePaySession?: ApplePaySessionLike }).ApplePaySession;
      if (!session) {
        result.applePayAvailable = false;
      } else if (typeof session.canMakePayments === 'function') {
        try {
          result.applePayAvailable = session.canMakePayments() === true;
        } catch {
          // Present but refused (e.g. cross-origin iframe without allow) —
          // availability of the surface itself is still meaningful.
          result.applePayAvailable = true;
        }
      } else {
        result.applePayAvailable = true;
      }
    } catch {
      result.applePayAvailable = null;
    }

    // Speech voices count. Note: engines may return [] until voiceschanged
    // fires; treat as a weak input downstream.
    try {
      result.speechVoicesCount = window.speechSynthesis ? window.speechSynthesis.getVoices().length : null;
    } catch {
      /* ignore */
    }

    // Permission states — each independent, never fatal.
    await Promise.all(
      PERMISSION_KEYS.map(async ([key, name]) => {
        try {
          const status = await navigator.permissions.query({ name });
          result.permissions[key] = status?.state ?? null;
        } catch {
          result.permissions[key] = null;
        }
      })
    );

    // Additive, context-only sources. Each helper is total and never feeds a
    // digest; geolocation reuses the permission state just resolved above so
    // it can never trigger a permission prompt.
    result.battery = await collectBatterySignals();
    result.geolocation = await collectGeolocationSignals(result.permissions.geolocation);
    result.keyboardStatic = await collectKeyboardStaticSignals();
  } catch (err) {
    result.error = errorMessage(err);
  }

  return result;
}

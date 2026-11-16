/**
 * System entropy probe — environment facts that are cheap to read and hard
 * to fake consistently: timezone, hardware concurrency/memory, screen
 * geometry, media device counts (counts only, never labels — enumerateDevices
 * labels require an active capture permission), storage quota, Apple Pay,
 * speech voices and permission states.
 */

import { errorMessage } from './hash';
import type { SystemEntropySignals } from './types';

interface NavigatorWithDeviceMemory extends Navigator {
  deviceMemory?: number;
}

interface ApplePaySessionLike {
  canMakePayments?: () => boolean;
}

const PERMISSION_KEYS: Array<[keyof SystemEntropySignals['permissions'], PermissionName]> = [
  ['geolocation', 'geolocation'],
  ['notifications', 'notifications'],
  ['camera', 'camera' as PermissionName],
  ['microphone', 'microphone' as PermissionName],
];

/** Total (async): always returns a payload. */
export async function collectSystemEntropySignals(): Promise<SystemEntropySignals> {
  const result: SystemEntropySignals = {
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
  } catch (err) {
    result.error = errorMessage(err);
  }

  return result;
}

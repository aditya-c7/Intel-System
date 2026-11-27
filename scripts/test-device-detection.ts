/**
 * Device-detection matrix.
 *
 * Runs the pure genuine-mobile gate plus exact phone-model resolution against a
 * broad cross-section of real User-Agent strings (Android OEMs, iOS, KaiOS,
 * feature phones, tablets, in-app browsers and desktop/DevTools cases).
 *
 *   npx tsx scripts/test-device-detection.ts
 *
 * Exits non-zero when any expectation fails so it can gate CI.
 */
import { classifyGenuineDevice, extractAndroidModelFromUA } from '../src/lib/deviceDetect';
import type { DeviceGateInput } from '../src/lib/deviceDetect';
import { resolvePhoneModel, formatPhoneDisplayLabel } from '../src/lib/phoneModel';
import { detectBotD19Signals } from '../src/lib/aiBotDirectory';
import type { BotD19Result } from '../src/lib/aiBotDirectory';

interface Case {
  name: string;
  input: DeviceGateInput;
  expectKind: 'pc' | 'mobile' | 'tablet';
  /** Expected extracted Android model code, or null when none is expected. */
  expectModel?: string | null;
  /** Expected resolved marketing name (substring), or null when it must not resolve. */
  expectLabel?: string | null;
  expectDevtools?: boolean;
}

// Shared genuine-phone hardware: finger-driven ARM silicon.
const phoneHw = (
  ua: string,
  extra: Partial<DeviceGateInput> = {}
): DeviceGateInput => ({
  ua,
  platform: 'Linux armv8l',
  architecture: 'arm',
  mobileHint: true,
  gpuVendor: 'Qualcomm',
  gpuRenderer: 'Adreno (TM) 740',
  maxTouchPoints: 5,
  pointerCoarse: true,
  hoverNone: true,
  hasTouchEvent: true,
  viewportWidth: 412,
  pcLocked: false,
  ...extra,
});

const chromeAndroid = (model: string, android = '14', version = '131.0.0.0') =>
  `Mozilla/5.0 (Linux; Android ${android}; ${model}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Mobile Safari/537.36`;

const cases: Case[] = [
  // --- Google Pixel -------------------------------------------------------------
  {
    name: 'Pixel 9 Pro (Chrome)',
    input: phoneHw(chromeAndroid('Pixel 9 Pro', '15')),
    expectKind: 'mobile',
    expectModel: 'Pixel 9 Pro',
    expectLabel: 'Google Pixel 9 Pro',
  },
  {
    name: 'Pixel 10 Pro XL (Chrome)',
    input: phoneHw(chromeAndroid('Pixel 10 Pro XL', '16')),
    expectKind: 'mobile',
    expectModel: 'Pixel 10 Pro XL',
    expectLabel: 'Pixel 10 Pro XL',
  },
  {
    name: 'Pixel 9 Pro Fold (Chrome)',
    input: phoneHw(chromeAndroid('Pixel 9 Pro Fold', '15')),
    expectKind: 'mobile',
    expectModel: 'Pixel 9 Pro Fold',
    expectLabel: 'Pixel 9 Pro Fold',
  },
  {
    name: 'Pixel tablet (Pixel Tablet)',
    input: phoneHw(chromeAndroid('Pixel Tablet', '14'), { mobileHint: false, viewportWidth: 1280 }),
    expectKind: 'tablet',
    expectModel: 'Pixel Tablet',
  },

  // --- Samsung ------------------------------------------------------------------
  {
    name: 'Galaxy S24 Ultra (Chrome)',
    input: phoneHw(chromeAndroid('SM-S928B', '15')),
    expectKind: 'mobile',
    expectModel: 'SM-S928B',
    expectLabel: 'Samsung Galaxy S24 Ultra',
  },
  {
    name: 'Galaxy S25 Ultra (Chrome)',
    input: phoneHw(chromeAndroid('SM-S938B', '16')),
    expectKind: 'mobile',
    expectLabel: 'Samsung Galaxy S25 Ultra',
  },
  {
    name: 'Galaxy Z Fold7 (Chrome)',
    input: phoneHw(chromeAndroid('SM-F966B', '16')),
    expectKind: 'mobile',
    expectLabel: 'Samsung Galaxy Z Fold7',
  },
  {
    name: 'Galaxy A54 + /DS suffix (Chrome)',
    input: phoneHw(chromeAndroid('SM-A546B/DS', '14')),
    expectKind: 'mobile',
    expectModel: 'SM-A546B',
    expectLabel: 'Galaxy A54 5G',
  },
  {
    name: 'Samsung Internet (SAMSUNG prefix)',
    input: phoneHw(
      'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36'
    ),
    expectKind: 'mobile',
    expectModel: 'SM-G991B',
    expectLabel: 'Galaxy S21 5G',
  },
  {
    name: 'Galaxy Tab S9 (tablet)',
    input: phoneHw(
      'Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      { mobileHint: false, viewportWidth: 1280, formFactors: ['Tablet'] }
    ),
    expectKind: 'tablet',
    expectModel: 'SM-X710',
  },

  // --- OnePlus / OPPO / realme ---------------------------------------------------
  {
    name: 'OnePlus 13 (CPH2649)',
    input: phoneHw(chromeAndroid('CPH2649', '15')),
    expectKind: 'mobile',
    expectLabel: 'OnePlus 13',
  },
  {
    name: 'OPPO Reno 12 (CPH2625)',
    input: phoneHw(chromeAndroid('CPH2625', '14')),
    expectKind: 'mobile',
    expectModel: 'CPH2625',
  },
  {
    name: 'realme GT5 (RMX3820)',
    input: phoneHw(chromeAndroid('RMX3820', '14')),
    expectKind: 'mobile',
    expectLabel: 'realme GT5',
  },

  // --- Xiaomi / Redmi / POCO -----------------------------------------------------
  {
    name: 'Redmi Note 13 Pro 5G (2312DRA50G)',
    input: phoneHw(chromeAndroid('2312DRA50G', '14')),
    expectKind: 'mobile',
    expectLabel: 'Redmi Note 13 Pro 5G',
  },
  {
    name: 'POCO F6 (24069PC21G)',
    input: phoneHw(chromeAndroid('24069PC21G', '14')),
    expectKind: 'mobile',
    expectLabel: 'POCO F6',
  },
  {
    name: 'Xiaomi 14 (23127PN0CG)',
    input: phoneHw(chromeAndroid('23127PN0CG', '14')),
    expectKind: 'mobile',
    expectModel: '23127PN0CG',
  },

  // --- vivo / iQOO ---------------------------------------------------------------
  {
    name: 'vivo X100 (V2309A)',
    input: phoneHw(chromeAndroid('V2309A', '14')),
    expectKind: 'mobile',
    expectLabel: 'Vivo X100',
  },
  {
    name: 'iQOO 12 (V2307A)',
    input: phoneHw(chromeAndroid('V2307A', '14')),
    expectKind: 'mobile',
    expectModel: 'V2307A',
  },

  // --- Motorola / Huawei / Honor -------------------------------------------------
  {
    name: 'moto g84 5G',
    input: phoneHw(chromeAndroid('moto g84 5G', '14')),
    expectKind: 'mobile',
    expectLabel: 'moto g84 5G',
  },
  {
    name: 'Huawei P30 Pro (VOG-L29)',
    input: phoneHw(chromeAndroid('VOG-L29', '10')),
    expectKind: 'mobile',
    expectModel: 'VOG-L29',
    expectLabel: 'P30 Pro',
  },
  {
    name: 'Honor Magic4 Pro (LGE-NX9)',
    input: phoneHw(chromeAndroid('LGE-NX9', '12')),
    expectKind: 'mobile',
    expectLabel: 'HONOR Magic4 Pro',
  },

  // --- Nothing / Asus / Sony ------------------------------------------------------
  {
    name: 'Nothing Phone (2) (A065)',
    input: phoneHw(chromeAndroid('A065', '14')),
    expectKind: 'mobile',
    expectLabel: 'Nothing Phone (2)',
  },
  {
    name: 'Asus ROG Phone 8 (ASUS_AI2401_A)',
    input: phoneHw(chromeAndroid('ASUS_AI2401_A', '14')),
    expectKind: 'mobile',
    expectLabel: 'ROG Phone 8',
  },
  {
    name: 'Sony Xperia 1 V (XQ-DQ72)',
    input: phoneHw(chromeAndroid('XQ-DQ72', '14')),
    expectKind: 'mobile',
    expectLabel: 'Xperia 1 V',
  },

  // --- Nokia / TCL / ZTE ----------------------------------------------------------
  {
    name: 'Nokia G42 5G (TA-1583)',
    input: phoneHw(chromeAndroid('TA-1583', '14')),
    expectKind: 'mobile',
    expectModel: 'TA-1583',
  },
  {
    name: 'TCL 40 SE (T610K)',
    input: phoneHw(chromeAndroid('T610K', '13')),
    expectKind: 'mobile',
    expectModel: 'T610K',
  },
  {
    name: 'ZTE Blade (ZTE 8050)',
    input: phoneHw(chromeAndroid('ZTE 8050', '12')),
    expectKind: 'mobile',
    expectModel: 'ZTE 8050',
  },

  // --- Transsion ------------------------------------------------------------------
  {
    name: 'Infinix HOT 40 Pro (X6837)',
    input: phoneHw(chromeAndroid('Infinix X6837', '14')),
    expectKind: 'mobile',
    expectLabel: 'Infinix HOT 40 Pro',
  },
  {
    name: 'TECNO SPARK 20 Pro+ (KJ7)',
    input: phoneHw(chromeAndroid('TECNO KJ7', '14')),
    expectKind: 'mobile',
    expectLabel: 'TECNO SPARK 20 Pro+',
  },
  {
    name: 'itel A70 (A665L)',
    input: phoneHw(chromeAndroid('itel A665L', '13')),
    expectKind: 'mobile',
    expectLabel: 'A70',
  },

  // --- LG / HTC -------------------------------------------------------------------
  {
    name: 'LG VELVET (LM-G910)',
    input: phoneHw(chromeAndroid('LM-G910', '11')),
    expectKind: 'mobile',
    expectLabel: 'VELVET',
  },
  {
    name: 'HTC U23 (HTC_2Q4R100)',
    input: phoneHw(chromeAndroid('HTC_2Q4R100', '13')),
    expectKind: 'mobile',
    expectModel: 'HTC_2Q4R100',
  },

  // --- Firefox Android / WebView / in-app browsers --------------------------------
  {
    name: 'Firefox Android (no UA-CH arch, ARM platform)',
    input: phoneHw(
      'Mozilla/5.0 (Android 14; Mobile; rv:132.0) Gecko/132.0 Firefox/132.0',
      { architecture: undefined, gpuVendor: 'ARM', gpuRenderer: 'Mali-G715' }
    ),
    expectKind: 'mobile',
    expectModel: null,
  },
  {
    name: 'Chrome WebView (Build token + wv)',
    input: phoneHw(
      'Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.0.0 Mobile Safari/537.36'
    ),
    expectKind: 'mobile',
    expectModel: 'SM-S918B',
    expectLabel: 'Galaxy S23 Ultra',
  },
  {
    name: 'Instagram in-app (Pixel 8)',
    input: phoneHw(
      'Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP1A.240505.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.0.0 Mobile Safari/537.36 Instagram 335.0.0.42.101'
    ),
    expectKind: 'mobile',
    expectModel: 'Pixel 8',
    expectLabel: 'Google Pixel 8',
  },
  {
    name: 'WhatsApp in-app (Galaxy A54)',
    input: phoneHw(
      'Mozilla/5.0 (Linux; Android 14; SM-A546B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.0.0 Mobile Safari/537.36 WhatsApp/2.24.12.78'
    ),
    expectKind: 'mobile',
    expectModel: 'SM-A546B',
  },

  {
    name: 'Legacy typo UA (Bulid/)',
    input: phoneHw(
      'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Moblie Safari/537.36'
    ),
    expectKind: 'mobile',
    expectModel: 'SM-G892A',
    expectLabel: 'Galaxy S8 Active',
  },

  // --- KaiOS / feature phones -----------------------------------------------------
  {
    name: 'KaiOS Nokia 8110 4G',
    input: phoneHw(
      'Mozilla/5.0 (Mobile; Nokia_8110_4G; rv:48.0) Gecko/48.0 Firefox/48.0 KaiOS/1.0',
      {
        platform: 'Linux armv7l',
        architecture: undefined,
        mobileHint: false,
        gpuVendor: '',
        gpuRenderer: '',
        maxTouchPoints: 0,
        pointerCoarse: false,
        hoverNone: true,
        hasTouchEvent: false,
        viewportWidth: 240,
      }
    ),
    expectKind: 'mobile',
  },
  {
    name: 'Raspberry Pi desktop (ARM Linux, X11)',
    input: {
      ua: 'Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      platform: 'Linux armv7l',
      architecture: 'arm',
      mobileHint: false,
      gpuVendor: 'Broadcom',
      gpuRenderer: 'VideoCore VI',
      maxTouchPoints: 0,
      pointerCoarse: false,
      hoverNone: false,
      hasTouchEvent: false,
      viewportWidth: 1920,
      pcLocked: false,
    },
    expectKind: 'pc',
  },
  {
    name: 'KaiOS Alcatel 4044O (touch)',
    input: phoneHw(
      'Mozilla/5.0 (Mobile; ALCATEL4044O; rv:48.0) Gecko/48.0 Firefox/48.0 KaiOS/1.0',
      {
        platform: 'Linux armv7l',
        architecture: undefined,
        gpuVendor: '',
        gpuRenderer: '',
      }
    ),
    expectKind: 'mobile',
  },

  // --- iOS ------------------------------------------------------------------------
  {
    name: 'iPhone 16 Pro (iOS 18.7)',
    input: phoneHw(
      'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1',
      {
        platform: 'iPhone',
        architecture: undefined,
        gpuVendor: 'Apple Inc.',
        gpuRenderer: 'Apple GPU',
      }
    ),
    expectKind: 'mobile',
    expectModel: null,
  },
  {
    name: 'iPhone (iOS 26 frozen UA token)',
    input: phoneHw(
      'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/604.1',
      {
        platform: 'iPhone',
        architecture: undefined,
        gpuVendor: 'Apple Inc.',
        gpuRenderer: 'Apple GPU',
      }
    ),
    expectKind: 'mobile',
  },
  {
    name: 'iPad Pro (iPadOS 18)',
    input: phoneHw(
      'Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1',
      {
        platform: 'iPad',
        architecture: undefined,
        gpuVendor: 'Apple Inc.',
        gpuRenderer: 'Apple GPU',
        viewportWidth: 1024,
      }
    ),
    expectKind: 'tablet',
  },
  {
    name: 'iPadOS desktop-mode Safari',
    input: phoneHw(
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
      {
        platform: 'MacIntel',
        architecture: undefined,
        mobileHint: false,
        gpuVendor: 'Apple Inc.',
        gpuRenderer: 'Apple GPU',
        viewportWidth: 1024,
      }
    ),
    expectKind: 'tablet',
  },

  // --- Desktops & emulation -------------------------------------------------------
  {
    name: 'Windows 11 desktop',
    input: {
      ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      platform: 'Win32',
      architecture: 'x86',
      mobileHint: false,
      gpuVendor: 'Google Inc.',
      gpuRenderer: 'ANGLE (NVIDIA GeForce RTX 4070 Direct3D11)',
      maxTouchPoints: 0,
      pointerCoarse: false,
      hoverNone: false,
      hasTouchEvent: false,
      viewportWidth: 1920,
      pcLocked: false,
    },
    expectKind: 'pc',
  },
  {
    name: 'Windows desktop resized to 390px',
    input: {
      ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      platform: 'Win32',
      architecture: 'x86',
      mobileHint: false,
      gpuVendor: 'Google Inc.',
      gpuRenderer: 'ANGLE (NVIDIA GeForce RTX 4070 Direct3D11)',
      maxTouchPoints: 0,
      pointerCoarse: false,
      hoverNone: false,
      hasTouchEvent: false,
      viewportWidth: 390,
      pcLocked: false,
    },
    expectKind: 'pc',
  },
  {
    name: 'MacBook Air (M3)',
    input: {
      ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      platform: 'MacIntel',
      architecture: 'arm',
      mobileHint: false,
      gpuVendor: 'Apple Inc.',
      gpuRenderer: 'ANGLE (Apple, Apple M3, OpenGL 4.1)',
      maxTouchPoints: 0,
      pointerCoarse: false,
      hoverNone: false,
      hasTouchEvent: false,
      viewportWidth: 1512,
      pcLocked: false,
    },
    expectKind: 'pc',
  },
  {
    name: 'Linux desktop',
    input: {
      ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      platform: 'Linux x86_64',
      architecture: 'x86',
      mobileHint: false,
      gpuVendor: 'Intel',
      gpuRenderer: 'Mesa Intel(R) UHD Graphics 630',
      maxTouchPoints: 0,
      pointerCoarse: false,
      hoverNone: false,
      hasTouchEvent: false,
      viewportWidth: 1920,
      pcLocked: false,
    },
    expectKind: 'pc',
  },
  {
    name: 'Touchscreen Windows laptop',
    input: {
      ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      platform: 'Win32',
      architecture: 'x86',
      mobileHint: false,
      gpuVendor: 'Intel',
      gpuRenderer: 'ANGLE (Intel Iris Xe Graphics Direct3D11)',
      maxTouchPoints: 10,
      pointerCoarse: false,
      hoverNone: false,
      hasTouchEvent: true,
      viewportWidth: 1440,
      pcLocked: false,
    },
    expectKind: 'pc',
  },
  {
    name: 'Chromebook (Android UA, desktop form factor)',
    input: {
      ua: chromeAndroid('Pixel 8', '14'),
      platform: 'Linux x86_64',
      architecture: 'x86',
      mobileHint: true,
      formFactors: ['Desktop'],
      gpuVendor: 'Intel',
      gpuRenderer: 'ANGLE (Intel UHD Graphics Direct3D11)',
      maxTouchPoints: 10,
      pointerCoarse: true,
      hoverNone: false,
      hasTouchEvent: true,
      viewportWidth: 1366,
      pcLocked: false,
    },
    expectKind: 'pc',
    expectDevtools: true,
  },
  {
    name: 'DevTools Pixel 8 preset',
    input: {
      ua: chromeAndroid('Pixel 8', '14'),
      platform: 'Linux armv8l',
      architecture: 'x86',
      mobileHint: true,
      gpuVendor: 'Google Inc.',
      gpuRenderer: 'ANGLE (Intel Iris Xe Graphics Direct3D11)',
      maxTouchPoints: 5,
      pointerCoarse: true,
      hoverNone: true,
      hasTouchEvent: true,
      viewportWidth: 412,
      pcLocked: false,
    },
    expectKind: 'pc',
    expectDevtools: true,
  },
  {
    name: 'DevTools iPhone 15 preset',
    input: {
      ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
      platform: 'MacIntel',
      architecture: 'x86',
      mobileHint: true,
      gpuVendor: 'Apple Inc.',
      gpuRenderer: 'Apple M2',
      maxTouchPoints: 1,
      pointerCoarse: true,
      hoverNone: true,
      hasTouchEvent: true,
      viewportWidth: 393,
      pcLocked: false,
    },
    expectKind: 'pc',
    expectDevtools: true,
  },
  {
    name: 'Persistent PC lock beats mobile UA',
    input: phoneHw(chromeAndroid('SM-S928B', '15'), { pcLocked: true }),
    expectKind: 'pc',
    expectDevtools: true,
  },
  // Tor Browser on Android ships a reduced Firefox UA and RFP spoofs
  // `navigator.platform` / UA-CH architecture to desktop x86. A finger-driven
  // handset with no desktop GPU must still be recognised as a phone.
  {
    name: 'Tor Browser on Android (RFP desktop platform)',
    input: phoneHw('Mozilla/5.0 (Android 14; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0', {
      platform: 'Linux x86_64',
      architecture: 'x86',
      gpuVendor: 'Mozilla',
      gpuRenderer: 'Mozilla',
    }),
    expectKind: 'mobile',
    expectDevtools: false,
  },
  {
    name: 'Tor Browser Android beats poisoned PC lock',
    input: phoneHw('Mozilla/5.0 (Android 14; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0', {
      platform: 'Linux x86_64',
      architecture: 'x86',
      gpuVendor: 'Mozilla',
      gpuRenderer: 'Mozilla',
      pcLocked: true,
    }),
    expectKind: 'mobile',
    expectDevtools: false,
  },
];

let failures = 0;
for (const testCase of cases) {
  const gate = classifyGenuineDevice(testCase.input);
  const model = /Android/i.test(testCase.input.ua)
    ? extractAndroidModelFromUA(testCase.input.ua)
    : '';
  const entry = model ? resolvePhoneModel(model) : null;
  const label = entry ? formatPhoneDisplayLabel(entry) : null;

  const errors: string[] = [];
  if (gate.kind !== testCase.expectKind) {
    errors.push(`kind ${gate.kind} != ${testCase.expectKind}`);
  }
  if (
    testCase.expectModel !== undefined &&
    (testCase.expectModel ?? '') !== model
  ) {
    errors.push(`model "${model}" != "${testCase.expectModel ?? ''}"`);
  }
  if (
    testCase.expectLabel !== undefined &&
    testCase.expectLabel !== null &&
    !(label ?? '').includes(testCase.expectLabel)
  ) {
    errors.push(`label "${label ?? ''}" !~ "${testCase.expectLabel}"`);
  }
  if (testCase.expectLabel === null && label !== null) {
    errors.push(`label "${label}" should not resolve`);
  }
  if (testCase.expectDevtools !== undefined && gate.devtoolsDeviceEmulation !== testCase.expectDevtools) {
    errors.push(`devtools ${gate.devtoolsDeviceEmulation} != ${testCase.expectDevtools}`);
  }

  if (errors.length) {
    failures += 1;
    console.log(`FAIL ${testCase.name}\n     ${errors.join('; ')}`);
  } else {
    console.log(
      `ok   ${testCase.name.padEnd(46)} ${gate.kind.padEnd(6)} ${label ?? model ?? '—'}`
    );
  }
}

console.log(`\n${cases.length - failures}/${cases.length} cases passed`);
if (failures > 0) process.exitCode = 1;

/* -------------------------------------------------------------------------- */
/* BotD19 client-signal matrix (src/lib/aiBotDirectory.ts)                     */
/* -------------------------------------------------------------------------- */

/**
 * Synthetic window/navigator/document stubs for the client-side BotD
 * detectors (window_size focus gate + Sequentum window.external scan).
 * Globals are swapped in and restored around every case so the device matrix
 * above is never affected.
 */
const BOTD_DESKTOP_CHROME_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

/** A getter whose Function.prototype.toString carries `[native code]` (bound functions do). */
const BOTD_NATIVE_GETTER = (function () {
  return undefined;
}).bind(null);

interface BotDStub {
  window: Record<string, unknown>;
  navigator: Record<string, unknown>;
  document: Record<string, unknown>;
  /** Installed as the global `Navigator` so descriptor checks see native getters. */
  navigatorClass: (abstract new () => Record<string, unknown>) | null;
}

function botdCleanStub(): BotDStub {
  class FakeNavigator {}
  Object.defineProperty(FakeNavigator.prototype, 'plugins', { get: BOTD_NATIVE_GETTER, configurable: true });
  Object.defineProperty(FakeNavigator.prototype, 'mimeTypes', { get: BOTD_NATIVE_GETTER, configurable: true });
  return {
    window: {
      outerWidth: 1920,
      outerHeight: 1080,
      // Branded like the native External object so the tampering brand check passes.
      external: { [Symbol.toStringTag]: 'External' },
    },
    navigator: {
      userAgent: BOTD_DESKTOP_CHROME_UA,
      appVersion:
        '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      language: 'en-US',
      languages: ['en-US', 'en'],
      productSub: '20030107',
      webdriver: false,
      plugins: { length: 0, item: () => null },
      mimeTypes: { length: 0, item: () => null },
    },
    document: { hasFocus: () => true },
    navigatorClass: FakeNavigator as unknown as (abstract new () => Record<string, unknown>),
  };
}

function withBotDGlobals(stub: BotDStub, fn: () => void): void {
  const keys = ['window', 'navigator', 'document', 'Navigator'] as const;
  const saved = new Map<string, PropertyDescriptor | undefined>();
  for (const key of keys) {
    saved.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
  }
  Object.defineProperty(globalThis, 'window', { value: stub.window, writable: true, configurable: true });
  Object.defineProperty(globalThis, 'navigator', { value: stub.navigator, writable: true, configurable: true });
  Object.defineProperty(globalThis, 'document', { value: stub.document, writable: true, configurable: true });
  if (stub.navigatorClass) {
    Object.defineProperty(globalThis, 'Navigator', { value: stub.navigatorClass, writable: true, configurable: true });
  }
  try {
    fn();
  } finally {
    for (const key of keys) {
      const descriptor = saved.get(key);
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete (globalThis as unknown as Record<string, unknown>)[key];
    }
  }
}

interface BotDCase {
  name: string;
  mutate: (stub: BotDStub) => void;
  expect: (result: BotD19Result, problems: string[]) => void;
}

const botdCases: BotDCase[] = [
  {
    name: 'window_size flags zero outer size while the document HAS focus',
    mutate: (stub) => {
      stub.window.outerWidth = 0;
      stub.window.outerHeight = 0;
    },
    expect: (result, problems) => {
      if (result.signals.window_size !== true) problems.push('window_size should be true');
      if (!result.reasons.includes('Window outerWidth and outerHeight are 0')) problems.push('reason missing');
      if (result.detected !== true) problems.push('detected should be true');
    },
  },
  {
    name: 'unfocused tab with zero outer size is never flagged (BotD focus gate)',
    mutate: (stub) => {
      stub.window.outerWidth = 0;
      stub.window.outerHeight = 0;
      stub.document = { hasFocus: () => false };
    },
    expect: (result, problems) => {
      if (result.signals.window_size !== false) problems.push('window_size should stay false when unfocused');
      if (result.detected !== false) problems.push('detected should be false');
    },
  },
  {
    name: 'missing document.hasFocus stays silent on zero outer size',
    mutate: (stub) => {
      stub.window.outerWidth = 0;
      stub.window.outerHeight = 0;
      stub.document = {};
    },
    expect: (result, problems) => {
      if (result.signals.window_size !== false) problems.push('window_size should stay false without focus evidence');
      if (result.detected !== false) problems.push('detected should be false');
    },
  },
  {
    name: 'focused normal window with a native-branded external is fully clean',
    mutate: () => {},
    expect: (result, problems) => {
      if (result.detected !== false) problems.push(`detected should be false, reasons: ${JSON.stringify(result.reasons)}`);
      if (result.signals.window_size !== false) problems.push('window_size should be false');
      if (result.signals.window_external !== false) problems.push('window_external should be false');
    },
  },
  {
    name: 'Sequentum leaks through a custom window.external toString',
    mutate: (stub) => {
      stub.window.external = { toString(): string { return 'Sequentum Content Extractor v1'; } };
    },
    expect: (result, problems) => {
      if (result.signals.window_external !== true) problems.push('window_external should be true');
      if (!result.reasons.some((reason) => /Sequentum/.test(reason))) problems.push('Sequentum reason missing');
      if (result.detected !== true) problems.push('detected should be true');
    },
  },
  {
    name: 'Sequentum leaks through external JSON/own keys without a custom toString',
    mutate: (stub) => {
      stub.window.external = { SequentumAgent: { build: 42 } };
    },
    expect: (result, problems) => {
      if (result.signals.window_external !== true) problems.push('window_external should be true');
      if (!result.reasons.some((reason) => /Sequentum/.test(reason))) problems.push('Sequentum reason missing');
    },
  },
  {
    name: 'Sequentum outside window.external does not flag the external signal',
    mutate: (stub) => {
      // The UA itself carries Sequentum (fires `user_agent`), external stays clean.
      stub.navigator.userAgent = BOTD_DESKTOP_CHROME_UA.replace('Chrome/131.0.0.0', 'Chrome/131.0.0.0 Sequentum/2');
    },
    expect: (result, problems) => {
      if (result.signals.user_agent !== true) problems.push('user_agent should fire for the Sequentum UA');
      if (result.signals.window_external !== false) problems.push('window_external must stay false for a clean external');
      if (result.reasons.some((reason) => /Sequentum/.test(reason) && /external/i.test(reason))) {
        problems.push('Sequentum external reason must not fire');
      }
    },
  },
];

let botdFailures = 0;
for (const botdCase of botdCases) {
  const stub = botdCleanStub();
  botdCase.mutate(stub);
  const problems: string[] = [];
  let result: BotD19Result | undefined;
  try {
    withBotDGlobals(stub, () => {
      result = detectBotD19Signals('ANGLE (Intel UHD Graphics Direct3D11)');
    });
  } catch (error) {
    problems.push(`threw: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (result) botdCase.expect(result, problems);
  if (problems.length) {
    botdFailures += 1;
    console.log(`FAIL ${botdCase.name}\n     ${problems.join('; ')}`);
  } else {
    console.log(`ok   ${botdCase.name}`);
  }
}

console.log(`\n${botdCases.length - botdFailures}/${botdCases.length} BotD19 client-signal cases passed`);
if (botdFailures > 0) process.exitCode = 1;

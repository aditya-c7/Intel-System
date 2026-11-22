/**
 * UA / Client-Hints normalization matrix.
 *
 * Verifies the camelCase `normalizeUserAgent({ userAgent, clientHints })` contract:
 *   - `os` is the family only (no digits), the version lives in `osVersion`
 *   - Windows 11 comes from `Sec-CH-UA-Platform-Version` major >= 13, with the
 *     UA `Windows NT 6.1/6.2/6.3/10.0` fallback for hint-less browsers
 *   - iPadOS is `Macintosh` + multi-touch
 *   - GREASE brands are dropped and Edge/Opera/Brave outrank Chrome
 *   - `browserMajorVersion` is never empty when a full version is known
 *   - the post-normalization assertion helper reports every invariant break
 *
 *   npx tsx scripts/test-ua-normalizer.ts
 *
 * Exits non-zero when any expectation fails.
 */
import {
  normalizeUserAgent,
  validateUserAgentNormalization,
  assertUserAgentNormalization,
  parseMobileFlag,
  type NormalizeUserAgentInput,
  type NormalizedUserAgent,
} from '../src/shared/normalization/uaNormalizer';

let failures = 0;

function check(name: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    console.log(`ok   ${name}`);
    return;
  }
  failures += 1;
  console.error(`FAIL ${name}`);
  if (detail !== undefined) console.error('     ', detail);
}

function expectIdentity(
  name: string,
  input: NormalizeUserAgentInput,
  expected: Partial<NormalizedUserAgent>,
): NormalizedUserAgent {
  const result = normalizeUserAgent(input);
  for (const [key, value] of Object.entries(expected)) {
    const actual = (result as unknown as Record<string, unknown>)[key];
    check(`${name} → ${key}`, actual === value, { expected: value, actual });
  }
  const issues = validateUserAgentNormalization(result);
  check(`${name} → invariants`, issues.length === 0, issues);
  return result;
}

const windows11ChromeUa =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36';

expectIdentity(
  'Windows 11 / Chrome (client hints)',
  {
    userAgent: windows11ChromeUa,
    clientHints: {
      fullVersionList: [
        { brand: 'Not.A/Brand', version: '99.0.0.0' },
        { brand: 'Chromium', version: '153.0.8010.52' },
        { brand: 'Google Chrome', version: '153.0.8010.52' },
      ],
      platform: 'Windows',
      platformVersion: '15.0.0',
      architecture: 'x86',
      bitness: '64',
    },
  },
  {
    os: 'Windows',
    osVersion: '11',
    browserName: 'Google Chrome',
    browserMajorVersion: '153',
    browserFullVersion: '153.0.8010.52',
    architecture: 'x86_64',
    bitness: '64',
    device: 'Desktop',
  },
);

expectIdentity(
  'Windows 11 thresholds',
  {
    userAgent: windows11ChromeUa,
    clientHints: { platform: 'Windows', platformVersion: '13.0.0' },
  },
  { os: 'Windows', osVersion: '11' },
);

expectIdentity(
  'Windows 10 (platformVersion 10.0.0)',
  {
    userAgent: windows11ChromeUa,
    clientHints: { platform: 'Windows', platformVersion: '10.0.0' },
  },
  { os: 'Windows', osVersion: '10' },
);

expectIdentity(
  'Firefox on Windows 11 (no hints, UA fallback)',
  {
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
  },
  { os: 'Windows', osVersion: '10', browserName: 'Firefox', browserMajorVersion: '130' },
);

expectIdentity(
  'Windows 7 UA fallback',
  {
    userAgent:
      'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
  },
  { os: 'Windows', osVersion: '7' },
);

expectIdentity(
  'Edge outranks Chrome in the full-version list',
  {
    userAgent: windows11ChromeUa,
    clientHints: {
      fullVersionList: [
        { brand: 'Google Chrome', version: '153.0.8010.52' },
        { brand: 'Microsoft Edge', version: '153.0.3405.86' },
      ],
      platform: 'Windows',
      platformVersion: '15.0.0',
    },
  },
  { browserName: 'Microsoft Edge', browserMajorVersion: '153', browserFullVersion: '153.0.3405.86' },
);

expectIdentity(
  'GREASE-only brand list falls back to the UA token',
  {
    userAgent: windows11ChromeUa,
    clientHints: {
      fullVersionList: [{ brand: 'Not)A;Brand', version: '24.0.0.0' }],
      platform: 'Windows',
      platformVersion: '15.0.0',
    },
  },
  { browserName: 'Google Chrome', browserMajorVersion: '153' },
);

expectIdentity(
  'Header-keyed hint bag is accepted',
  {
    userAgent: windows11ChromeUa,
    clientHints: {
      'sec-ch-ua-platform': '"Windows"',
      'sec-ch-ua-platform-version': '"15.0.0"',
      'sec-ch-ua-full-version-list':
        '"Chromium";v="153.0.8010.52", "Google Chrome";v="153.0.8010.52"',
    } as unknown as NormalizeUserAgentInput['clientHints'],
  },
  { os: 'Windows', osVersion: '11', browserName: 'Google Chrome', browserMajorVersion: '153' },
);

expectIdentity(
  'iPadOS 13+ (Macintosh UA + touch)',
  {
    userAgent:
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    platform: 'MacIntel',
    maxTouchPoints: 5,
  },
  { os: 'iOS', device: 'Tablet', browserName: 'Safari', browserMajorVersion: '17' },
);

expectIdentity(
  'macOS desktop (no touch)',
  {
    userAgent:
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    platform: 'MacIntel',
    maxTouchPoints: 0,
  },
  { os: 'Mac OS X', osVersion: '10.15.7', device: 'Desktop' },
);

expectIdentity(
  'Android + Pixel model from hints',
  {
    userAgent:
      'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
    clientHints: {
      platform: 'Android',
      platformVersion: '14.0.0',
      model: 'Pixel 8 Pro',
      mobile: true,
    },
  },
  { os: 'Android', osVersion: '14', device: 'Mobile', model: 'Pixel 8 Pro' },
);

expectIdentity(
  'Cursor agent token',
  {
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Cursor/0.42.3 Chrome/128.0.0.0 Safari/537.36',
  },
  { browserName: 'Cursor', browserMajorVersion: '0' },
);

/* Tranche 0-1 regression matrix --------------------------------------------- */

const ELECTRON_UA =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) OpenCode/2.3.0 Chrome/152.0.7977.167 Electron/44.9.1 Safari/537.36';

expectIdentity(
  'Electron 44.9.1 runtime outranks the embedded Chromium brand',
  {
    userAgent: ELECTRON_UA,
    platform: 'Linux',
    clientHints: {
      fullVersionList: [
        { brand: 'Chromium', version: '152.0.7977.167' },
        { brand: 'Google Chrome', version: '152.0.7977.167' },
      ],
      platform: 'Linux',
      platformVersion: '6.8.0',
      architecture: 'x86',
      bitness: '64',
    },
  },
  {
    browserName: 'Electron',
    browserFullVersion: '44.9.1',
    browserMajorVersion: '44',
  },
);

const electronResult = normalizeUserAgent({ userAgent: ELECTRON_UA, platform: 'Linux' });
check(
  'Electron UA is never reported as the embedded Chromium/Chrome identity',
  electronResult.browserName === 'Electron' && electronResult.browserFullVersion !== '152.0.7977.167',
  electronResult,
);

/** Sec-CH-UA-Mobile ?1 is a structured boolean, not a raw string. */
check('Sec-CH-UA-Mobile ?1 parses to boolean true', parseMobileFlag('?1') === true);
check('Sec-CH-UA-Mobile "?1" parses to boolean true', parseMobileFlag('"?1"') === true);
check('Sec-CH-UA-Mobile ?0 parses to boolean false', parseMobileFlag('?0') === false);
check('boolean true Sec-CH-UA-Mobile parses to true', parseMobileFlag(true) === true);

expectIdentity(
  'Sec-CH-UA-Mobile ?1 promotes an otherwise unknown device to Mobile',
  { userAgent: 'Mozilla/5.0', clientHints: { mobile: '?1' } },
  { device: 'Mobile' },
);
expectIdentity(
  'Sec-CH-UA-Mobile ?0 does not promote an unknown device',
  { userAgent: 'Mozilla/5.0', clientHints: { mobile: '?0' } },
  { device: 'Unknown' },
);

/* Chromium 156 Linux regression (additive) ---------------------------------- */

const CHROMIUM_156_LINUX_UA =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36';

const chromium156Result = expectIdentity(
  'Chromium 156.0.8078.79 (Linux) resolves to a concrete browser (never Unknown)',
  {
    userAgent: CHROMIUM_156_LINUX_UA,
    platform: 'Linux',
    clientHints: {
      fullVersionList: [
        { brand: 'Not)A;Brand', version: '24.0.0.0' },
        { brand: 'Chromium', version: '156.0.8078.79' },
      ],
      platform: 'Linux',
    },
  },
  {
    os: 'Linux',
    browserName: 'Chromium',
    browserMajorVersion: '156',
    browserFullVersion: '156.0.8078.79',
  },
);
check(
  'Chromium 156.0.8078.79 (Linux) is never reported as Unknown',
  chromium156Result.browserName !== 'Unknown',
  chromium156Result,
);

const chromium156BrandsOnly = normalizeUserAgent({
  userAgent: CHROMIUM_156_LINUX_UA,
  platform: 'Linux',
  clientHints: {
    brands: [
      { brand: 'Not)A;Brand', version: '24' },
      { brand: 'Chromium', version: '156' },
    ],
    platform: 'Linux',
  },
});
check(
  'UA_DATA brands-only Chromium 156 with GREASE tokens is never Unknown',
  chromium156BrandsOnly.browserName !== 'Unknown',
  chromium156BrandsOnly,
);

/* Assertion helper ---------------------------------------------------------- */

const badDigit = validateUserAgentNormalization({
  os: 'Windows 11',
  osVersion: '11',
  browserName: 'Chrome',
  browserMajorVersion: '153',
  browserFullVersion: '153.0.8010.52',
  device: 'Desktop',
  model: '',
  architecture: '',
  bitness: '',
});
check('assertion flags digits in os', badDigit.some((m) => m.includes('contains digits')), badDigit);

const badEqual = validateUserAgentNormalization({
  os: 'Windows',
  osVersion: 'Windows',
  browserName: 'Chrome',
  browserMajorVersion: '153',
  browserFullVersion: '153.0.8010.52',
  device: 'Desktop',
  model: '',
  architecture: '',
  bitness: '',
});
check('assertion flags os === osVersion', badEqual.some((m) => m.includes('must not equal')), badEqual);

const badMajor = validateUserAgentNormalization({
  os: 'Windows',
  osVersion: '11',
  browserName: 'Chrome',
  browserMajorVersion: '',
  browserFullVersion: '153.0.8010.52',
  device: 'Desktop',
  model: '',
  architecture: '',
  bitness: '',
});
check('assertion flags empty major', badMajor.some((m) => m.includes('empty')), badMajor);

let threw = false;
try {
  assertUserAgentNormalization({
    os_version: 'Windows 11',
    os: 'Windows 11',
    browser_name: 'Chrome',
    browser_major_version: '153',
    browser_full_version: '153.0.0.0',
    device: 'Desktop',
    device_model: '',
    architecture: '',
    bitness: '',
    platformFamily: 'windows',
  });
} catch {
  threw = true;
}
check('assertion helper throws on a violation', threw);

if (failures > 0) {
  console.error(`\n${failures} expectation(s) failed`);
  process.exit(1);
}
console.log('\nAll UA normalizer expectations passed');

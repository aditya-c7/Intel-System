/**
 * Human-vs-bot verdict regression tests.
 *
 * Covers the three-axis split introduced to stop real people being labelled
 * "Bot / Automated":
 *
 *   bot                   — WebDriver / automation UA / stealth plugin artifacts
 *   developerTools        — CDP Runtime bridge (DevTools, Electron, IDE webview)
 *   automationEnvironment — none | electron | ide_webview | headless_shell | vm
 *
 * Plus the tampering false-positive fixes (screen-width rounding tolerance and
 * privacy-extension getter wrappers).
 *
 *   npx tsx scripts/test-human-verdict.ts
 */

import assert from 'node:assert/strict';

/* -------------------------------------------------------------------------- */
/* Browser globals                                                            */
/* -------------------------------------------------------------------------- */

interface FakeNavigator {
  userAgent: string;
  platform: string;
  languages: string[];
  language: string;
  maxTouchPoints: number;
  webdriver: boolean;
  plugins: unknown[];
  mimeTypes: unknown[];
  productSub: string;
  hardwareConcurrency: number;
  deviceMemory?: number;
}

interface FakeWindow {
  outerWidth: number;
  outerHeight: number;
  innerWidth: number;
  innerHeight: number;
  screen: { width: number; height: number; availWidth: number; availHeight: number };
  devicePixelRatio: number;
  matchMedia: (query: string) => { matches: boolean };
  addEventListener: () => void;
  process?: { versions?: { electron?: string; node?: string } };
  chrome?: { runtime?: unknown };
  acquireVsCodeApi?: () => unknown;
}

const baseNavigator: FakeNavigator = {
  userAgent:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36',
  platform: 'Win32',
  languages: ['en-US', 'en'],
  language: 'en-US',
  maxTouchPoints: 0,
  webdriver: false,
  plugins: [],
  mimeTypes: [],
  productSub: '20030107',
  hardwareConcurrency: 8,
  deviceMemory: 8,
};

function makeWindow(overrides: Partial<FakeWindow> = {}): FakeWindow {
  return {
    outerWidth: 1536,
    outerHeight: 960,
    innerWidth: 1520,
    innerHeight: 860,
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040 },
    devicePixelRatio: 1,
    // Normal window: the device-width query matches every candidate width.
    matchMedia: () => ({ matches: true }),
    addEventListener: () => {},
    chrome: { runtime: {} },
    ...overrides,
  };
}

function installGlobals(
  options: {
    ua?: string;
    platform?: string;
    languages?: string[];
    win?: Partial<FakeWindow>;
    navigator?: Partial<FakeNavigator>;
  } = {}
): void {
  const nav = {
    ...baseNavigator,
    ...(options.ua ? { userAgent: options.ua } : {}),
    ...(options.platform ? { platform: options.platform } : {}),
    ...(options.languages ? { languages: options.languages, language: options.languages[0] } : {}),
    ...options.navigator,
  };
  const win = makeWindow(options.win);
  const documentStub = {
    visibilityState: 'visible',
    createElement: () => ({
      style: {} as Record<string, string>,
      contentWindow: undefined,
      remove: () => {},
    }),
    body: { appendChild: () => {} },
    documentElement: { attributes: [] },
  };
  Object.defineProperty(globalThis, 'window', { value: win, configurable: true });
  Object.defineProperty(globalThis, 'document', { value: documentStub, configurable: true });
  Object.defineProperty(globalThis, 'navigator', { value: nav, configurable: true });
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

let passed = 0;
let failed = 0;
function check(label: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed += 1;
    console.log(`PASS  ${label}`);
  } else {
    failed += 1;
    console.error(`FAIL  ${label}${detail === undefined ? '' : `\n      ${JSON.stringify(detail)}`}`);
  }
}

/* -------------------------------------------------------------------------- */
/* Module import (globals must exist first)                                   */
/* -------------------------------------------------------------------------- */

installGlobals();

const { detectAutomationEnvironment, measureHumanCorroboration, detectBotAndAutomation } =
  await import('../src/lib/collector');
import { detectBrowserTampering } from '../src/lib/tamperingDetector';
const { detectAiBotFromServerSignals } = await import('../src/lib/aiBotDirectory');

const ELECTRON_UA =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) OpenCode/2.3.0 Chrome/152.0.7977.167 Electron/44.9.1 Safari/537.36';
const GENERIC_ELECTRON_UA =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Slack/4.39.90 Chrome/128.0.6613.186 Electron/32.0.1 Safari/537.36';
const PLAIN_CHROME_UA = baseNavigator.userAgent;

/* -------------------------------------------------------------------------- */
/* A. Runtime environment detection                                           */
/* -------------------------------------------------------------------------- */

section('A. Automation environment');

installGlobals({ ua: GENERIC_ELECTRON_UA, win: { process: { versions: { electron: '32.0.1' } } } });
check(
  'Electron shell (Slack-style UA) → electron',
  detectAutomationEnvironment(GENERIC_ELECTRON_UA, 'NVIDIA GeForce RTX 3060').environment ===
    'electron'
);

installGlobals({ ua: ELECTRON_UA });
check(
  'IDE webview UA → ide_webview',
  detectAutomationEnvironment(ELECTRON_UA, 'NVIDIA GeForce RTX 3060').environment === 'ide_webview'
);

installGlobals({ ua: PLAIN_CHROME_UA });
check(
  'plain Chrome → none',
  detectAutomationEnvironment(PLAIN_CHROME_UA, 'NVIDIA GeForce RTX 3060').environment === 'none'
);

installGlobals({ ua: 'Mozilla/5.0 HeadlessChrome/152.0.0.0 Safari/537.36' });
check(
  'HeadlessChrome UA → headless_shell',
  detectAutomationEnvironment('Mozilla/5.0 HeadlessChrome/152.0.0.0 Safari/537.36', 'SwiftShader')
    .environment === 'headless_shell'
);

installGlobals({ ua: PLAIN_CHROME_UA });
check(
  'software GPU only → vm',
  detectAutomationEnvironment(PLAIN_CHROME_UA, 'Google SwiftShader').environment === 'vm'
);

/* -------------------------------------------------------------------------- */
/* B. Human corroboration                                                     */
/* -------------------------------------------------------------------------- */

section('B. Human corroboration score');

const strong = measureHumanCorroboration('NVIDIA GeForce RTX 3060');
check('real viewport + visible doc + hardware GPU → >= 0.8', strong.score >= 0.8, strong);

installGlobals({
  win: { outerWidth: 0, outerHeight: 0, innerWidth: 0, innerHeight: 0 },
  languages: [],
});
const weak = measureHumanCorroboration('Google SwiftShader');
check('zero geometry + no languages + software GPU → < 0.4', weak.score < 0.4, weak);

/* -------------------------------------------------------------------------- */
/* C. CDP bridge is developer tools, not a bot                                */
/* -------------------------------------------------------------------------- */

section('C. Electron + CDP Runtime leak → human with developer tools');

installGlobals({
  ua: ELECTRON_UA,
  win: { process: { versions: { electron: '44.9.1' } } },
});
// Simulate the CDP Runtime.enable serialization probe: when the collector's probe
// calls console.debug(Error), a CDP client serializes it and invokes prepareStackTrace.
const realDebug = console.debug;
console.debug = (...args: unknown[]) => {
  const errorCtor = Error as unknown as { prepareStackTrace?: unknown };
  const prep = errorCtor.prepareStackTrace;
  if (typeof prep === 'function') {
    (prep as (e: unknown, s: unknown) => string)(args[0], []);
  }
};
const electronVerdict = detectBotAndAutomation('NVIDIA GeForce RTX 3060');
console.debug = realDebug;

check('Electron + CDP is not a bot', electronVerdict.isBot === false, electronVerdict);
check('Electron + CDP reports developerTools', electronVerdict.developerTools === true);
check(
  'Electron + CDP reports the IDE webview environment',
  electronVerdict.automationEnvironment === 'ide_webview'
);
check(
  'CDP leak is still recorded for telemetry',
  electronVerdict.cdpRuntimeLeak === true
);
check(
  'human corroboration is high',
  (electronVerdict.humanCorroboration ?? 0) >= 0.8,
  electronVerdict.humanCorroboration
);

section('D. Playwright-style WebDriver is still a bot');

installGlobals({ ua: PLAIN_CHROME_UA, navigator: { webdriver: true } });
const webdriverVerdict = detectBotAndAutomation('NVIDIA GeForce RTX 3060');
check('navigator.webdriver=true → bot', webdriverVerdict.isBot === true, webdriverVerdict);

installGlobals({
  ua: 'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/152.0.0.0 Safari/537.36',
});
const headlessVerdict = detectBotAndAutomation('Google SwiftShader');
check('HeadlessChrome UA → bot', headlessVerdict.isBot === true, headlessVerdict);

/* -------------------------------------------------------------------------- */
/* E. Tampering false positives                                               */
/* -------------------------------------------------------------------------- */

section('E. Tampering false positives on real browsers');

installGlobals({ ua: PLAIN_CHROME_UA });
// Own data properties on navigator look "non-native" but return the real values.
const normalTamper = detectBrowserTampering({
  webglVendor: 'Google Inc. (NVIDIA)',
  webglRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
});
check('normal Chrome is not anti-detect', normalTamper.tampering_details.anti_detect_browser === false);
check('normal Chrome is not tampered', normalTamper.tampering === false);
check('getter wrapper alone does not raise the ML score past 0.5', normalTamper.tampering_ml_score < 0.5);

installGlobals({ ua: PLAIN_CHROME_UA });
// Browser zoom / fractional DPI: query matches at width-1, not at width.
Object.defineProperty(globalThis, 'window', {
  value: makeWindow({
    matchMedia: (query: string) => ({ matches: query.includes('1919px') }),
  }),
  configurable: true,
});
const roundingTamper = detectBrowserTampering({});
check(
  '±1 px screen-width rounding is tolerated',
  roundingTamper.tampering_details.anti_detect_browser === false,
  roundingTamper.tampering_details.reasons
);

installGlobals({ ua: PLAIN_CHROME_UA });
Object.defineProperty(globalThis, 'window', {
  value: makeWindow({ matchMedia: () => ({ matches: false }) }),
  configurable: true,
});
const spoofTamper = detectBrowserTampering({});
check(
  'a real screen-width spoof is still flagged',
  spoofTamper.tampering_details.anti_detect_browser === true,
  spoofTamper.tampering_details.reasons
);

/* -------------------------------------------------------------------------- */
/* F. ASN-only matches must not name an AI agent                              */
/* -------------------------------------------------------------------------- */

section('F. Cloud ASN hosts real people');

const awsHuman = detectAiBotFromServerSignals({
  userAgent: PLAIN_CHROME_UA,
  asnNumber: 16509,
  asnOrg: 'Amazon.com, Inc.',
  headers: {},
});
check(
  'AWS ASN + normal Chrome UA is not Bedrock AgentCore',
  awsHuman.detected === false,
  awsHuman.botInfo
);

const awsClaim = detectAiBotFromServerSignals({
  userAgent: 'Mozilla/5.0 (compatible; BedrockAgentCore/1.0)',
  asnNumber: 16509,
  asnOrg: 'Amazon.com, Inc.',
  headers: {},
});
check(
  'AWS ASN + explicit Bedrock UA is still detected',
  awsClaim.detected === true && awsClaim.botType === 'ai_agent',
  awsClaim.botInfo
);

const gcpHuman = detectAiBotFromServerSignals({
  userAgent: PLAIN_CHROME_UA,
  asnNumber: 396982,
  asnOrg: 'Google LLC',
  headers: {},
});
check('Google Cloud ASN + normal Chrome UA is not an AI agent', gcpHuman.detected === false);

/* -------------------------------------------------------------------------- */

console.log(`\nHuman-verdict suite: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;

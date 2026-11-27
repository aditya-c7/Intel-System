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
import { buildGradedRiskLedger, riskTierFromScore100, score10FromScore100 } from '../src/lib/riskLedger';
import {
  checkInspectorInvariants,
  inspectorFlagsForState,
  resolveInspectorState,
} from '../src/lib/specInvariants';
import {
  CALIBRATION_MAX_ECE,
  CALIBRATION_MIN_LABELED_PAIRS,
  computeHonestIdentityConfidence,
  confidenceBandForScore,
} from '../src/lib/rarityHonesty';

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
  removeEventListener: () => void;
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
    removeEventListener: () => {},
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

const {
  detectAutomationEnvironment,
  measureHumanCorroboration,
  detectBotAndAutomation,
  detectStealthArtifacts,
  inspectorProbes,
} = await import('../src/lib/collector');
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

section('G. Canonical risk headline math (shared with the graded ledger)');

const humanGraded = buildGradedRiskLedger({});
check('clean human graded ledger -> score10 0 / Low', humanGraded.score10 === 0 && humanGraded.risk_tier === 'Low');
check('score10/tier derive from 67 composite', score10FromScore100(67) === 7 && riskTierFromScore100(67) === 'High');

/* -------------------------------------------------------------------------- */
/* H. Confidence score mirrors are single-sourced                              */
/* -------------------------------------------------------------------------- */

section('H. Confidence score mirror consistency');

const humanMirrorGate = {
  labeledPairs: CALIBRATION_MIN_LABELED_PAIRS + 300,
  heldOutEce: CALIBRATION_MAX_ECE / 5,
};
const unseenMirror = computeHonestIdentityConfidence({
  ...humanMirrorGate,
  matchStage: 'new_enrollment',
});
check(
  'unseen human profile publishes no numeric confidence',
  unseenMirror.confidence_score === null && unseenMirror.confidence_tier === 'New Unobserved Profile',
  unseenMirror,
);
check('band mirror of a zero score stays New/Unobserved', confidenceBandForScore(0) === 'New/Unobserved');
const matchedMirror = computeHonestIdentityConfidence({
  ...humanMirrorGate,
  matchStage: 'lsh_fuzzy',
  matchScore: 100,
  structuralAnchorRatio: 1,
  distinctStorageSeedsCount: 0,
  browserFamilyConsensus: true,
  osFamilyConsensus: true,
});
check(
  'matched profile mirror is a real number with an agreeing band',
  matchedMirror.confidence_score === 0.65 &&
    confidenceBandForScore(matchedMirror.confidence_score ?? 0) === matchedMirror.confidence_tier,
  matchedMirror,
);

/* -------------------------------------------------------------------------- */
/* I. Tranche 0-1 — inspector tri-state                                        */
/* -------------------------------------------------------------------------- */

section('I. Inspector tri-state flags');

const unattributedInspector = resolveInspectorState({ cdpAttached: true });
check('unattributed CDP resolves to yes-unattributed', unattributedInspector === 'yes-unattributed');
check(
  'unattributed CDP -> cdp_attached true, developer_tools false',
  (() => {
    const flags = inspectorFlagsForState(unattributedInspector);
    return flags.cdp_attached === true && flags.developer_tools === false;
  })(),
);
check(
  'legacy automation_protocol_attached normalizes to the unattributed flags',
  (() => {
    const flags = inspectorFlagsForState('automation_protocol_attached');
    return flags.cdp_attached === true && flags.developer_tools === false;
  })(),
);

const corroboratedInspector = resolveInspectorState({
  cdpAttached: true,
  devtoolsActiveVerified: true,
});
check('corroborated CDP + DevTools resolves to yes-corroborated', corroboratedInspector === 'yes-corroborated');
check(
  'corroborated CDP + DevTools -> both flags true',
  (() => {
    const flags = inspectorFlagsForState(corroboratedInspector);
    return flags.cdp_attached === true && flags.developer_tools === true;
  })(),
);

check(
  'no inspector -> both flags false',
  (() => {
    const state = resolveInspectorState({});
    const flags = inspectorFlagsForState(state);
    return state === 'no' && flags.cdp_attached === false && flags.developer_tools === false;
  })(),
);

check(
  'inspector invariants accept bare CDP attach but reject a docked DevTools claim',
  (() => {
    const bareAttach = checkInspectorInvariants({
      inspector_state: unattributedInspector,
      cdp_attached: true,
      developer_tools: false,
    });
    const dockedClaim = checkInspectorInvariants({
      inspector_state: unattributedInspector,
      cdp_attached: false,
      developer_tools: true,
    });
    return (
      bareAttach.consistent === true &&
      dockedClaim.consistent === false &&
      dockedClaim.contradictions.length === 2
    );
  })(),
);
check(
  'inspector invariants accept the corroborated flags',
  checkInspectorInvariants({
    inspector_state: corroboratedInspector,
    cdp_attached: true,
    developer_tools: true,
  }).consistent,
);

/* -------------------------------------------------------------------------- */
/* J. Automation probes — notification contract + SwiftShader desktop tell    */
/* -------------------------------------------------------------------------- */

section('J. Automation probes: headless.notification-contract + .swiftshader.caveat.desktop');

const { collectAutomationSignals } = await import('../src/client/signals/automation');

interface AutomationGlobalsOptions {
  /** navigator.maxTouchPoints (default 0 — a plain desktop). */
  maxTouchPoints?: number;
  /** UA-CH platform string; omit to simulate a browser without userAgentData. */
  platformUaCh?: string;
  /** Notification.permission value; 'not-present' removes the Notification global. */
  notificationPermission?: 'denied' | 'granted' | 'default' | 'not-present';
  /** What navigator.permissions.query resolves (or does) for 'notifications'. */
  permissionsState?: 'prompt' | 'denied' | 'granted' | 'throw' | 'not-present';
  /** The object a canvas.getContext('webgl', …) returns; omit for no WebGL at all. */
  canvasContext?: Record<string, unknown> | null;
}

function installAutomationGlobals(options: AutomationGlobalsOptions = {}): void {
  const nav = {
    ...baseNavigator,
    maxTouchPoints: options.maxTouchPoints ?? 0,
    ...(options.platformUaCh
      ? {
          userAgentData: {
            brands: [{ brand: 'Chromium', version: '152' }],
            platform: options.platformUaCh,
            mobile: false,
          },
        }
      : {}),
    permissions:
      options.permissionsState === 'not-present'
        ? undefined
        : {
            query: async (): Promise<{ state: string }> => {
              if (options.permissionsState === 'throw') throw new TypeError('Bad permission name');
              return { state: options.permissionsState ?? 'prompt' };
            },
          },
  };
  const documentStub = {
    visibilityState: 'visible',
    createElement: (tag: string) => {
      if (tag === 'canvas' && options.canvasContext) {
        return {
          style: {} as Record<string, string>,
          getContext: () => options.canvasContext,
          remove: () => {},
        };
      }
      return { style: {} as Record<string, string>, contentWindow: undefined, remove: () => {} };
    },
    body: { appendChild: () => {} },
    documentElement: { attributes: [], children: [] },
  };
  Object.defineProperty(globalThis, 'window', { value: makeWindow(), configurable: true });
  Object.defineProperty(globalThis, 'document', { value: documentStub, configurable: true });
  Object.defineProperty(globalThis, 'navigator', { value: nav, configurable: true });
  if (options.notificationPermission && options.notificationPermission !== 'not-present') {
    Object.defineProperty(globalThis, 'Notification', {
      value: { permission: options.notificationPermission },
      configurable: true,
    });
  } else {
    delete (globalThis as Record<string, unknown>).Notification;
  }
}

// A WebGL context that reports SwiftShader despite the failIfMajorPerformanceCaveat
// request — the H3 precondition (a real browser refuses the context on software GL).
const SWIFTSHADER_CONTEXT: Record<string, unknown> = {
  getExtension: () => ({ UNMASKED_RENDERER_WEBGL: 0x9246 }),
  getParameter: (key: number) => (key === 0x9246 ? 'Google SwiftShader (Intel)' : 'WebKit WebGL'),
  RENDERER: 0x1f01,
};

// J1 — happy path: Notification.permission claims 'denied' while the real permission
// store still answers 'prompt'. A genuine denied store would answer 'denied'.
installAutomationGlobals({ notificationPermission: 'denied', permissionsState: 'prompt' });
const contractSignals = await collectAutomationSignals();
check(
  'Notification denied vs Permissions prompt → headless.notification-contract',
  contractSignals.reasonIds.includes('headless.notification-contract'),
  contractSignals.reasonIds
);

// J2 — a consistent store (denied vs denied) is NOT a contradiction.
installAutomationGlobals({ notificationPermission: 'denied', permissionsState: 'denied' });
const consistentSignals = await collectAutomationSignals();
check(
  'denied vs denied is consistent → no notification-contract reason',
  !consistentSignals.reasonIds.includes('headless.notification-contract'),
  consistentSignals.reasonIds
);

// J3 — inconclusive path: the Notification API is absent entirely (Firefox/Safari).
installAutomationGlobals({ notificationPermission: 'not-present', permissionsState: 'prompt' });
const noNotificationSignals = await collectAutomationSignals();
check(
  'absent Notification API → inconclusive, no reason emitted',
  !noNotificationSignals.reasonIds.includes('headless.notification-contract'),
  noNotificationSignals.reasonIds
);

// J4 — inconclusive path: some browsers throw on the 'notifications' query name.
installAutomationGlobals({ notificationPermission: 'denied', permissionsState: 'throw' });
const throwingQuerySignals = await collectAutomationSignals();
check(
  'throwing permissions.query → inconclusive, no reason emitted',
  !throwingQuerySignals.reasonIds.includes('headless.notification-contract'),
  throwingQuerySignals.reasonIds
);

// J5 — H3 desktop conjunction happy path: a context returned DESPITE the caveat, the
// renderer IS SwiftShader, and the runtime claims a desktop platform with no touch.
installAutomationGlobals({
  platformUaCh: 'Windows',
  maxTouchPoints: 0,
  canvasContext: SWIFTSHADER_CONTEXT,
});
const desktopSignals = await collectAutomationSignals();
check(
  'SwiftShader context + desktop UA-CH + zero touch → hard desktop conjunction',
  desktopSignals.reasonIds.includes('headless.swiftshader.caveat.desktop'),
  desktopSignals.reasonIds
);
check(
  'the weak plain caveat still fires alongside the hard conjunction',
  desktopSignals.reasonIds.includes('headless.swiftshader.caveat'),
  desktopSignals.reasonIds
);

// J6 — anti-flag: a touch-capable device is mobile-shaped, never the desktop tell.
installAutomationGlobals({
  platformUaCh: 'Windows',
  maxTouchPoints: 5,
  canvasContext: SWIFTSHADER_CONTEXT,
});
const touchSignals = await collectAutomationSignals();
check(
  'touch-capable device → no hard desktop conjunction (weak caveat only)',
  !touchSignals.reasonIds.includes('headless.swiftshader.caveat.desktop') &&
    touchSignals.reasonIds.includes('headless.swiftshader.caveat'),
  touchSignals.reasonIds
);

// J7 — anti-flag: without UA-CH the desktop claim cannot be corroborated, so the hard
// reason is deliberately unreachable (Firefox / Safari never fire it).
installAutomationGlobals({
  maxTouchPoints: 0,
  canvasContext: SWIFTSHADER_CONTEXT,
});
const noUachSignals = await collectAutomationSignals();
check(
  'UA-CH absent → no hard desktop conjunction',
  !noUachSignals.reasonIds.includes('headless.swiftshader.caveat.desktop'),
  noUachSignals.reasonIds
);

delete (globalThis as Record<string, unknown>).Notification;
installGlobals({ ua: PLAIN_CHROME_UA });

/* -------------------------------------------------------------------------- */
/* K. Cyclic-native tamper audit — TAMPERING axis, never bot-hard             */
/* -------------------------------------------------------------------------- */

section('K. Cyclic prototype tamper check (tamper.cyclic-native-absent)');

// Baseline: none of the audited constructors exists in this environment — every
// surface is skipped and the flag stays absent (inconclusive, never fabricated true).
detectStealthArtifacts('ANGLE (NVIDIA, NVIDIA GeForce RTX 3060)');
check(
  'no audited natives → tamper flag stays absent',
  inspectorProbes.tamperCyclicNativeAbsent === false
);

// Happy path: a Proxy-wrapped AudioBuffer.getChannelData swallows the cyclic-prototype
// write that every stock native rejects with the 'Cyclic __proto__' TypeError. The
// three stock methods before it must throw and NOT flag, then the wrapper flags.
const swallowingProxy = new Proxy(function getChannelData(): Float32Array {
  return new Float32Array(0);
}, {
  setPrototypeOf: () => true,
});
class FakeHTMLCanvasElement {}
class FakeCanvasRenderingContext2D {
  getImageData(): object {
    return {};
  }
}
class FakeWebGLRenderingContext {
  getParameter(): string {
    return '';
  }
}
class FakeAudioBuffer {
  getChannelData(): Float32Array {
    return new Float32Array(0);
  }
}
Object.defineProperty(globalThis, 'HTMLCanvasElement', {
  value: FakeHTMLCanvasElement,
  configurable: true,
});
Object.defineProperty(globalThis, 'CanvasRenderingContext2D', {
  value: FakeCanvasRenderingContext2D,
  configurable: true,
});
Object.defineProperty(globalThis, 'WebGLRenderingContext', {
  value: FakeWebGLRenderingContext,
  configurable: true,
});
Object.defineProperty(globalThis, 'AudioBuffer', { value: FakeAudioBuffer, configurable: true });
Object.defineProperty(FakeAudioBuffer.prototype, 'getChannelData', {
  value: swallowingProxy,
  configurable: true,
  writable: true,
});
detectStealthArtifacts('ANGLE (NVIDIA, NVIDIA GeForce RTX 3060)');
check(
  'one Proxy-wrapped native (swallowed cyclic write) → tamper flag set',
  inspectorProbes.tamperCyclicNativeAbsent === true
);
check(
  'the wrapped method kept its original prototype (side-effect-free audit)',
  Object.getPrototypeOf(swallowingProxy) === Function.prototype
);

// The collector forwards the flag through the existing tamperingLies.prototypeCyclicTrap
// channel (TAMPERING axis): a POINTS:0 shadow reason that can never flip the bot gate.
const cyclicTamperAssessment = detectBrowserTampering({
  privacyHardened: false,
  tamperingLies: { prototypeCyclicTrap: inspectorProbes.tamperCyclicNativeAbsent === true },
});
check(
  'the forwarded flag reaches the TAMPERING axis as the cyclic-trap reason',
  cyclicTamperAssessment.tampering_lies.reasons.includes(
    'cyclic __proto__ trap succeeded (Proxy-wrapped native)'
  ),
  cyclicTamperAssessment.tampering_lies.reasons
);
check(
  'cyclic evidence alone never sets the canonical tampering verdict',
  cyclicTamperAssessment.tampering === false
);
check(
  'cyclic evidence is gated from anti_detect promotion without scored evidence',
  cyclicTamperAssessment.tampering_lies.anti_detect_browser === false
);
check(
  'privacy-hardened runtimes never bot-flag from wrapper extensions',
  detectBrowserTampering({
    privacyHardened: true,
    tamperingLies: { prototypeCyclicTrap: true },
  }).tampering_lies.anti_detect_browser === false
);

for (const globalName of [
  'HTMLCanvasElement',
  'CanvasRenderingContext2D',
  'WebGLRenderingContext',
  'AudioBuffer',
]) {
  delete (globalThis as Record<string, unknown>)[globalName];
}
installGlobals({ ua: PLAIN_CHROME_UA });

/* -------------------------------------------------------------------------- */
/* L. Aggregate kinematics — zero-PII passive motion attestation              */
/* -------------------------------------------------------------------------- */

section('L. Kinematics aggregate (zero-PII motion attestation)');

const { computeKinematicsShapeFeatures } = await import('../src/client/signals/automation');
const { buildKinematicsPayload } = await import('../src/lib/collector');

interface KinematicsPoint {
  x: number;
  y: number;
  t: number;
}

/** Human reference bands from the Corroborated-Human contract. */
type KinematicsShapeKey =
  | 'brakingRatio'
  | 'microStructure'
  | 'meanTurnAngle'
  | 'turnsWhileFast'
  | 'straightness'
  | 'speedCv'
  | 'minFlightMs';

const KINEMATICS_BANDS: Array<[KinematicsShapeKey, string, (value: number | null) => boolean]> = [
  ['brakingRatio', 'brakingRatio <= 0.25', (v) => v !== null && v <= 0.25],
  ['microStructure', 'microStructure in 0.3-0.95', (v) => v !== null && v >= 0.3 && v <= 0.95],
  ['meanTurnAngle', 'meanTurnAngle in 0.08-0.7', (v) => v !== null && v >= 0.08 && v <= 0.7],
  ['turnsWhileFast', 'turnsWhileFast <= 0.3', (v) => v !== null && v <= 0.3],
  ['straightness', 'straightness <= 0.985', (v) => v !== null && v <= 0.985],
  ['speedCv', 'speedCv in 0.35-2.6', (v) => v !== null && v >= 0.35 && v <= 2.6],
  ['minFlightMs', 'minFlightMs >= 15', (v) => v !== null && v >= 15],
];

/**
 * Synthetic HUMAN-like trail (deterministic): cruise with a 3-4 Hz submovement
 * speed rhythm, a slow corrective phase whose turns happen only while slow, a
 * gentle arc, then a hard deceleration to rest. Inter-event intervals sit in
 * the 16-18 ms band of Chrome's coalesced pointermove delivery.
 */
function humanTrail(): KinematicsPoint[] {
  const points: KinematicsPoint[] = [];
  let x = 100;
  let y = 200;
  let heading = 0.4;
  let t = 0;
  const push = (stepPx: number, turn: number): void => {
    heading += turn;
    x += Math.cos(heading) * stepPx;
    y += Math.sin(heading) * stepPx;
    t += 16 + (points.length % 3);
    points.push({
      x: Math.round(x * 1000) / 1000,
      y: Math.round(y * 1000) / 1000,
      t: Math.round(t * 1000) / 1000,
    });
  };
  for (let i = 0; i < 30; i++) push(Math.max(0.6, 3.1 + 2.1 * Math.sin(i * 0.8)), 0.008);
  for (let i = 0; i < 26; i++) push(1.4, (i % 2 === 0 ? 1 : -1) * 0.85);
  for (let i = 0; i < 22; i++) push(Math.max(0.15, 4.5 * Math.exp(-i / 1.6)), 0);
  return points;
}

/** Perfectly linear, constant-speed bot trail (8 ms teleport-free dispatch). */
function botTrail(): KinematicsPoint[] {
  const points: KinematicsPoint[] = [];
  for (let i = 0; i < 120; i++) {
    points.push({ x: 50 + i * 4, y: 300, t: Math.round((i + 1) * 8 * 1000) / 1000 });
  }
  return points;
}

const humanFeatures = computeKinematicsShapeFeatures(humanTrail());
check('human trail → clockMonotonic true', humanFeatures.clockMonotonic === true, humanFeatures);
for (const [key, label, inBand] of KINEMATICS_BANDS) {
  check(`human trail → ${label}`, inBand(humanFeatures[key]), humanFeatures);
}

const botFeatures = computeKinematicsShapeFeatures(botTrail());
const botViolations = KINEMATICS_BANDS.filter(
  ([key, , inBand]) => !inBand(botFeatures[key])
).map(([, label]) => label);
check('linear constant-speed bot trail violates >= 3 bounds', botViolations.length >= 3, {
  botFeatures,
  botViolations,
});

const emptyFeatures = computeKinematicsShapeFeatures([]);
check(
  'empty trail → every shape feature null',
  (['brakingRatio', 'microStructure', 'meanTurnAngle', 'turnsWhileFast', 'straightness', 'speedCv', 'minFlightMs', 'maxSpeedPx'] as const).every(
    (key) => emptyFeatures[key] === null
  ),
  emptyFeatures
);
check('empty trail → clockMonotonic true', emptyFeatures.clockMonotonic === true);

const nonMonotonic = computeKinematicsShapeFeatures([
  { x: 0, y: 0, t: 0 },
  { x: 5, y: 0, t: 50 },
  { x: 10, y: 0, t: 40 },
  { x: 15, y: 0, t: 70 },
  { x: 20, y: 0, t: 90 },
  { x: 25, y: 0, t: 110 },
  { x: 30, y: 0, t: 130 },
  { x: 35, y: 0, t: 150 },
  { x: 40, y: 0, t: 170 },
]);
check('backwards capture clock → clockMonotonic false', nonMonotonic.clockMonotonic === false);

// Payload block: in this process no trusted input ever reached the counters, so the
// posted kinematics block must be the all-nulls/zero empty state.
const kinematicsBlock = buildKinematicsPayload();
check('payload kinematics → eventCount 0', kinematicsBlock.eventCount === 0, kinematicsBlock);
check(
  'payload kinematics → pointer/key/scroll counts 0',
  kinematicsBlock.pointerEvents === 0 && kinematicsBlock.keyEvents === 0 && kinematicsBlock.scrollEvents === 0,
  kinematicsBlock
);
check('payload kinematics → interactionMs 0', kinematicsBlock.interactionMs === 0, kinematicsBlock);
check('payload kinematics → clockMonotonic true', kinematicsBlock.clockMonotonic === true);
check(
  'payload kinematics → shape features null with too few events',
  (['brakingRatio', 'microStructure', 'meanTurnAngle', 'turnsWhileFast', 'straightness', 'speedCv', 'minFlightMs', 'maxSpeedPx'] as const).every(
    (key) => kinematicsBlock[key] === null
  ),
  kinematicsBlock
);

// Serialization invariant: round-trip a posted-body-shaped object and assert no raw
// trajectory data (arrays of points carrying numeric x/y, or any array inside the
// kinematics block) survives serialization.
const KINEMATICS_CONTRACT_KEYS = [
  'eventCount', 'pointerEvents', 'keyEvents', 'scrollEvents', 'interactionMs',
  'brakingRatio', 'microStructure', 'meanTurnAngle', 'turnsWhileFast', 'straightness',
  'speedCv', 'minFlightMs', 'clockMonotonic', 'maxSpeedPx',
];
const payloadShape: Record<string, unknown> = {
  pageLoadId: 'page-1',
  sessionId: 'session-1',
  kinematics: { ...kinematicsBlock, straightness: 0.912, speedCv: 0.7 },
  interactionEvidence: ['pointer-kinematics:3', 'keyboard:2'],
  privacy_signature_ids: ['a.b.c'],
  cdpReasonIds: ['cdp.runtime.enable'],
  stealth_signal_ids: ['stealth.x'],
  gpu_honesty_labels: ['gpu.webgl:reported'],
  inspectorProbes: { cdpAttached: false, nameGetterCount: 0 },
};
const roundTrip = JSON.parse(JSON.stringify(payloadShape)) as unknown;
const findRawPointArray = (value: unknown): boolean => {
  if (Array.isArray(value)) {
    if (
      value.some(
        (item) =>
          typeof item === 'object' &&
          item !== null &&
          !Array.isArray(item) &&
          typeof (item as Record<string, unknown>).x === 'number' &&
          typeof (item as Record<string, unknown>).y === 'number'
      )
    ) {
      return true;
    }
    return value.some((item) => findRawPointArray(item));
  }
  if (typeof value === 'object' && value !== null) {
    return Object.values(value as Record<string, unknown>).some(findRawPointArray);
  }
  return false;
};
check('round-tripped payload contains no arrays of raw points', !findRawPointArray(roundTrip));
const rtKinematics = (roundTrip as Record<string, unknown>).kinematics as Record<string, unknown>;
check(
  'kinematics block survives serialization as scalars only (no arrays, exactly the contract keys)',
  Object.keys(rtKinematics).length === KINEMATICS_CONTRACT_KEYS.length &&
    KINEMATICS_CONTRACT_KEYS.every((key) => Object.prototype.hasOwnProperty.call(rtKinematics, key)) &&
    Object.values(rtKinematics).every(
      (value) =>
        value === null || typeof value === 'number' || typeof value === 'boolean'
    ),
  rtKinematics
);

console.log(`\nHuman-verdict suite: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;

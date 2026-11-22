import type {
  BrowserDeviceInfo,
  HardwareSignals,
  IspNetworkClassification,
  NetworkType,
  SecuritySignals,
  RiskLevel,
  PersistenceMode,
  IntelVisitorResponse,
  SecurityEnvelope,
  SignedHistoryBackup,
} from '../types/visitor';
import { detectBrowserTampering } from './tamperingDetector';
import {
  CORROBORATED_CDP_REASON_ID,
  CORROBORATED_CHROMIUM_CDP_REASON_ID,
  deriveBotVerdict,
} from './verdict';
import type { GpuObservation } from './telemetryContract';
import { resolveGpuObservation } from './specInvariants';
import { timezoneMismatchContext } from './timezone';
import { probeEngineLength, resolveHardwareTruth } from './hardwareTruth';
import { detectBotD19Signals } from './aiBotDirectory';
import {
  collectAllSignals,
  computeBrowserFingerprint,
  computeHardwareFingerprint,
  hashStrings,
  type CollectedSignals,
} from '../client/signals';
import type { BrowserCanvasHints } from '../client/signals/types';
import { loadStoredIdentity, persistIdentity, getSessionId } from '../client/storage/identityStore';
import { normalizeIdentity } from '../shared/normalization/uaNormalizer';
import {
  createIsolatedFontMeasurer,
  FONT_MEASURE_TEST_STRING,
} from '../client/signals/fontPreferences';
import {
  classifyGenuineDevice,
  detectInAppBrowser,
  extractAndroidModelFromUA,
  getPcLock,
  releaseNonPcLock,
  savePcLock,
  type DeviceGateResult,
} from './deviceDetect';

const STORAGE_KEYS = {
  VISITOR_ID: 'intel_fp_vid',
  VISITOR_TOKEN: 'intel_fp_token',
  SESSION_ID: 'intel_fp_sid',
  HARDWARE_ID: 'intel_fp_hwid',
  HISTORY_BACKUP: 'intel_fp_history_backup',
};

const CURRENT_PAGE_LOAD_ID: string =
  typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : 'pl_' + Math.random().toString(36).slice(2) + '_' + Date.now().toString(36);

/**
 * Corroborated-CDP dwell. A bare CDP bridge is weight-0 developer-tools evidence: a real
 * person with DevTools open, an Electron shell or an IDE webview all expose one. We give a
 * genuine user a short, bounded window to produce trusted input before a bridge with NO
 * such input is escalated to a stealth-automation bot verdict. The wait is bounded and
 * only runs in the async identify path — it never blocks rendering or adds UI.
 */
const CDP_CORROBORATION_DWELL_MS = 2500;
const PAGE_SESSION_STARTED_AT: number = Date.now();

interface NavigatorUABrand {
  brand: string;
  version: string;
}

interface NavigatorUAData {
  brands?: NavigatorUABrand[];
  mobile?: boolean;
  platform?: string;
  getHighEntropyValues?: (hints: string[]) => Promise<{
    fullVersionList?: NavigatorUABrand[];
    platform?: string;
    platformVersion?: string;
    architecture?: string;
    bitness?: string;
    mobile?: boolean;
    model?: string;
    formFactors?: string[];
  }>;
}

export interface ClientGeoHint {
  ip: string;
  city: string;
  region: string;
  country: string;
  countryCode: string;
  latitude: number | null;
  longitude: number | null;
  isp: string;
  org: string;
  asn: string;
  timezone: string;
  isVpnOrHosting: boolean;
}

/* -------------------------------------------------------------------------- */
/* Client runtime / host-app detection                                         */
/* -------------------------------------------------------------------------- */

export type ClientRuntime = 'browser' | 'electron' | 'ide_webview' | 'headless_shell';
export type ClientType = 'web_browser' | 'desktop_app' | 'ide_webview' | 'headless_shell';

/** The three additive runtime fields emitted on the identify payload. */
export interface ClientRuntimeSignals {
  /** Coarse host runtime. Electron is its own value — never reported as "Chromium". */
  runtime: ClientRuntime;
  /** Human-readable host app (IDE name, Electron build, headless shell, or Browser). */
  host_app: string;
  /** Consumer-facing client category, derived from the runtime, not the engine. */
  client_type: ClientType;
}

interface RuntimeFacts extends ClientRuntimeSignals {
  electron: boolean;
  electronVersion: string;
  nodeVersion: string;
  ideWebview: boolean;
  headlessShell: boolean;
}

/** UA tokens for known host applications. IDE tokens are also used for the webview verdict. */
const HOST_APP_UA_TOKENS: Array<[RegExp, string]> = [
  [/\bCursor\/\d/i, 'Cursor'],
  [/\bOpenCode\/\d/i, 'OpenCode'],
  [/\bWindsurf\/\d/i, 'Windsurf'],
  [/VSCodium\/\d/i, 'VSCodium'],
  [/(?:^|[\s(])(?:Code|vscode-webview)\/\d/i, 'Visual Studio Code'],
  [/\bSlack\/\d/i, 'Slack'],
  [/\bDiscord\/\d/i, 'Discord'],
  [/\bTeams\/\d/i, 'Microsoft Teams'],
  [/\bWhatsApp\/\d/i, 'WhatsApp'],
  [/\bSpotify\/\d/i, 'Spotify'],
  [/\bNotion\/\d/i, 'Notion'],
  [/\bPostmanRuntime\/\d/i, 'Postman'],
];

const IDE_HOST_LABELS: ReadonlySet<string> = new Set([
  'Cursor',
  'OpenCode',
  'Windsurf',
  'VSCodium',
  'Visual Studio Code',
]);

/**
 * Reads the host runtime from independent immutable facts: the `Electron/<version>` UA token,
 * `window.process.versions.electron` / `.node`, `acquireVsCodeApi`, the page protocol and known
 * host-app tokens. No single getter is trusted, and every scope read is guarded. An Electron
 * token is NEVER treated as the embedded Chromium engine version.
 */
function detectRuntimeFacts(uaOverride?: string): RuntimeFacts {
  let ua = '';
  if (typeof uaOverride === 'string') {
    ua = uaOverride;
  } else {
    try {
      ua = typeof navigator !== 'undefined' ? navigator.userAgent || '' : '';
    } catch {
      ua = '';
    }
  }

  let electronVersion = '';
  let nodeVersion = '';
  let hasVsCodeApi = false;
  let protocol = '';
  try {
    const scope = window as unknown as {
      process?: { versions?: { electron?: string; node?: string } };
      acquireVsCodeApi?: unknown;
    };
    electronVersion = String(scope.process?.versions?.electron || '');
    nodeVersion = String(scope.process?.versions?.node || '');
    hasVsCodeApi = typeof scope.acquireVsCodeApi === 'function';
  } catch {
    // A hostile scope is not evidence.
  }
  try {
    protocol = typeof location !== 'undefined' ? location.protocol : '';
  } catch {
    protocol = '';
  }

  const uaElectronVersion = ua.match(/Electron\/([\d.]+)/i)?.[1] || '';
  electronVersion = uaElectronVersion || electronVersion;
  const electron = Boolean(uaElectronVersion || electronVersion);

  const matchedHost = HOST_APP_UA_TOKENS.find(([pattern]) => pattern.test(ua));
  const hostLabel = matchedHost ? matchedHost[1] : '';
  const ideWebview =
    hasVsCodeApi ||
    /^(vscode-webview|code-oss)/i.test(protocol) ||
    IDE_HOST_LABELS.has(hostLabel);
  const headlessShell = /HeadlessChrome|PhantomJS|SlimerJS/i.test(ua);

  let hostApp = hostLabel;
  if (!hostApp && electron) hostApp = electronVersion ? `Electron ${electronVersion}` : 'Electron';
  if (!hostApp && headlessShell) hostApp = 'Headless Chrome';
  if (!hostApp && nodeVersion) hostApp = `Node.js ${nodeVersion}`;
  if (!hostApp) hostApp = 'Browser';

  let runtime: ClientRuntime = 'browser';
  let clientType: ClientType = 'web_browser';
  if (ideWebview) {
    runtime = 'ide_webview';
    clientType = 'ide_webview';
  } else if (electron) {
    runtime = 'electron';
    clientType = 'desktop_app';
  } else if (headlessShell) {
    runtime = 'headless_shell';
    clientType = 'headless_shell';
  }

  return {
    runtime,
    host_app: hostApp,
    client_type: clientType,
    electron,
    electronVersion,
    nodeVersion,
    ideWebview,
    headlessShell,
  };
}

/** Public accessor used to attach `runtime` / `host_app` / `client_type` to the payload. */
export function detectClientRuntime(ua?: string): ClientRuntimeSignals {
  const facts = detectRuntimeFacts(ua);
  return { runtime: facts.runtime, host_app: facts.host_app, client_type: facts.client_type };
}

const IANA_TIMEZONE_ALIASES: Record<string, string> = {
  'asia/calcutta': 'asia/kolkata',
  'asia/saigon': 'asia/ho_chi_minh',
  'asia/katmandu': 'asia/kathmandu',
  'asia/rangoon': 'asia/yangon',
  'europe/kiev': 'europe/kyiv',
  'europe/uzhgorod': 'europe/kyiv',
  'europe/zaporozhye': 'europe/kyiv',
  'us/eastern': 'america/new_york',
  'us/central': 'america/chicago',
  'us/mountain': 'america/denver',
  'us/pacific': 'america/los_angeles',
  'etc/utc': 'utc',
  'etc/gmt': 'utc',
  'gmt': 'utc',
};

/**
 * @deprecated Local alias folding retained for backwards compatibility only. Mismatch decisions
 * MUST go through `isCanonicalTimezoneMismatch` / the shared `./timezone` resolver instead.
 */
export function normalizeTimezoneId(tz: string | null | undefined): string {
  if (!tz || typeof tz !== 'string') return '';
  const cleaned = tz.trim().toLowerCase();
  if (!cleaned || cleaned === 'unknown' || cleaned === 'unavailable') return '';
  return IANA_TIMEZONE_ALIASES[cleaned] || cleaned;
}

/**
 * @deprecated Local equivalence retained for backwards compatibility only. It accepts a shared
 * UTC offset as a match; use the canonical `./timezone` resolver for any mismatch decision.
 */
export function areTimezonesEquivalent(tzA: string | null | undefined, tzB: string | null | undefined): boolean {
  const normA = normalizeTimezoneId(tzA);
  const normB = normalizeTimezoneId(tzB);
  if (!normA || !normB) return true;
  if (normA === normB) return true;

  // Also check if both timezones currently share the exact same UTC offset and region continent
  try {
    const now = new Date();
    const fmtA = new Intl.DateTimeFormat('en-US', { timeZone: tzA!, timeZoneName: 'shortOffset' }).format(now);
    const fmtB = new Intl.DateTimeFormat('en-US', { timeZone: tzB!, timeZoneName: 'shortOffset' }).format(now);
    const regionA = normA.split('/')[0];
    const regionB = normB.split('/')[0];
    if (fmtA === fmtB && regionA === regionB) {
      return true;
    }
  } catch {
    // Ignore Intl errors on non-standard timezone strings
  }
  return false;
}

/**
 * Canonical timezone-mismatch decision — the ONLY place a mismatch is derived.
 *
 * Delegates to the shared `./timezone` resolver so the browser, the server and the risk ledger
 * compare the SAME canonical IANA identity. Legacy aliases are folded, a shared UTC offset is
 * NOT treated as equality (Singapore != Hong Kong), and an unresolved side is absence of
 * evidence rather than a mismatch. No raw `!==` comparison is used here, and the raw browser
 * timezone itself is still emitted verbatim as telemetry.
 */
export function isCanonicalTimezoneMismatch(
  browserTimezone: string | null | undefined,
  ipTimezone: string | null | undefined
): boolean {
  return timezoneMismatchContext(browserTimezone, ipTimezone).mismatch;
}

const DATACENTER_NETWORK_PATTERN =
  /google|gcp|as15169|as396982|cloudflare|amazon|aws|digitalocean|hetzner|m247|linode|akamai|ovh|microsoft corporation|azure|oracle|choopa|vultr|datacamp|leaseweb|packethub|tzulo|cogent|equinix|fastly|scaleway|upcloud|contabo|kamatera|nordvpn|expressvpn|mullvad|proton ag|surfshark|private internet access|cyberghost|ivpn|tor exit|hosting|datacenter|cloud|vps|dedibox/i;

export function isMaskedOrUnavailableGpu(
  gpuVendor: string | null | undefined,
  gpuRenderer: string | null | undefined
): boolean {
  const vendor = (gpuVendor || '').trim();
  const renderer = (gpuRenderer || '').trim();
  if (
    !vendor ||
    !renderer ||
    vendor === 'Unavailable' ||
    renderer === 'Unavailable' ||
    /^Standard (GPU|WebGL|Hardware)/i.test(vendor) ||
    /^Standard (GPU|WebGL|Hardware)/i.test(renderer) ||
    /SwiftShader|llvmpipe|Mesa OffScreen|Software Rasterizer/i.test(renderer)
  ) {
    return true;
  }
  if (/^(WebKit|Mozilla)$/i.test(vendor) && /^(WebKit WebGL|Mozilla)$/i.test(renderer)) {
    return true;
  }
  return false;
}

export function isDatacenterOrVpnNetwork(
  isp: string | null | undefined,
  org: string | null | undefined,
  asn: string | null | undefined,
  flaggedByProvider = false
): { isDatacenter: boolean; matchedReason: string | null } {
  const combined = `${isp || ''} ${org || ''} ${asn || ''}`.trim();
  const match = combined.match(DATACENTER_NETWORK_PATTERN);
  if (match) {
    return {
      isDatacenter: true,
      matchedReason: `ASN/ISP matches cloud or VPN network (${match[0]})`,
    };
  }
  if (flaggedByProvider) {
    return {
      isDatacenter: true,
      matchedReason: 'IP intelligence provider flagged hosting, proxy, or VPN routing',
    };
  }
  return { isDatacenter: false, matchedReason: null };
}

/**
 * Task 1 - Clean ISP brand & network type classifier.
 * Maps verbose WHOIS / legal network names into clean retail brands
 * (e.g. "Comcast Cable Communications, LLC" -> "Xfinity (Comcast)").
 * Rules are evaluated in the listed order: numeric ASN evidence first
 * (ASN rules win over keywords inside the same rule), then ISP / Org keywords.
 * Consumer rules are always checked BEFORE the cloud / datacenter rule, and
 * Google Fiber is checked BEFORE generic Google cloud, so residential FTTH
 * networks such as AS16591 are never mis-flagged as hosting.
 */
interface IspNetworkRule {
  brandName: string;
  networkType: NetworkType;
  isConsumer: boolean;
  label: string;
  asns: number[];
  pattern?: RegExp;
}

const RESIDENTIAL_BROADBAND: NetworkType = 'Residential Broadband';
const CELLULAR_5G: NetworkType = 'Cellular / 5G';
const SATELLITE_NETWORK: NetworkType = 'Satellite';
const CLOUD_DATACENTER: NetworkType = 'Cloud / Datacenter';

const ISP_NETWORK_RULES: IspNetworkRule[] = [
  // US consumer broadband
  {
    brandName: 'Xfinity (Comcast)',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'Comcast consumer broadband',
    asns: [7922, 7015, 7016],
    pattern: /comcast|xfinity/i,
  },
  {
    brandName: 'Spectrum (Charter)',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'Charter Spectrum consumer broadband',
    asns: [20115, 11426, 10796],
    pattern: /charter|spectrum/i,
  },
  {
    brandName: 'AT&T Fiber',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'AT&T consumer broadband',
    asns: [7018, 20057],
    pattern: /at&t|att services|sbcglobal/i,
  },
  {
    brandName: 'Verizon Fios',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'Verizon Fios consumer broadband',
    asns: [701, 19262],
    pattern: /fios|mci communications|verizon online/i,
  },
  {
    brandName: 'Optimum',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'Optimum consumer broadband',
    asns: [6128, 19108],
    pattern: /optimum|cablevision|altice|suddenlink/i,
  },
  {
    brandName: 'Cox',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'Cox consumer broadband',
    asns: [22773],
    pattern: /\bcox\b/i,
  },
  {
    brandName: 'Frontier / CenturyLink',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'Frontier / CenturyLink consumer broadband',
    asns: [5650, 209],
  },
  {
    brandName: 'Google Fiber',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'Google Fiber residential FTTH',
    asns: [16591],
    pattern: /google fiber|gfiber/i,
  },
  // US mobile / 5G home
  {
    brandName: 'Verizon 5G Home',
    networkType: CELLULAR_5G,
    isConsumer: true,
    label: 'Verizon Wireless 5G home',
    asns: [6167, 22394],
    pattern: /cellco|verizon wireless/i,
  },
  {
    brandName: 'T-Mobile 5G Home',
    networkType: CELLULAR_5G,
    isConsumer: true,
    label: 'T-Mobile 5G home',
    asns: [21928],
    pattern: /t-mobile|tmobile/i,
  },
  // Satellite
  {
    brandName: 'Starlink (SpaceX)',
    networkType: SATELLITE_NETWORK,
    isConsumer: true,
    label: 'Starlink satellite broadband',
    asns: [14593],
    pattern: /starlink|spacex/i,
  },
  // India consumer broadband
  {
    brandName: 'Jio (Reliance Jio)',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'Reliance Jio consumer broadband',
    asns: [55836],
    pattern: /reliance jio|\bjio\b/i,
  },
  {
    brandName: 'Airtel Xstream',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'Bharti Airtel consumer broadband',
    asns: [24560, 45609, 9498],
    pattern: /bharti airtel|\bairtel\b/i,
  },
  {
    brandName: 'ACT Fibernet',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'ACT Fibernet consumer broadband',
    asns: [24309],
    pattern: /act fibernet|atria convergence/i,
  },
  {
    brandName: 'BSNL Broadband',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'BSNL consumer broadband',
    asns: [9829],
    pattern: /\bbsnl\b|bharat sanchar/i,
  },
  {
    brandName: 'Tata Play / Hathway',
    networkType: RESIDENTIAL_BROADBAND,
    isConsumer: true,
    label: 'Tata Play / Hathway consumer broadband',
    asns: [],
    pattern: /tata play|tata sky broadband|hathway|excitel/i,
  },
  // Cloud / Datacenter rule: LAST on purpose, only reached when no consumer rule above matched.
  {
    brandName: 'Cloud Provider / Datacenter',
    networkType: CLOUD_DATACENTER,
    isConsumer: false,
    label: 'cloud/hosting network',
    asns: [
      396178, 15169, 16509, 14618, 13335, 14061, 9009, 60068, 24940, 63949, 16276, 8075, 20473,
    ],
    pattern:
      /google llc|google cloud|amazonaws|cloudflare|digitalocean|hetzner|m247|datacamp|linode|ovh|choopa|vultr|leaseweb|hostinger|contabo|akamai/i,
  },
];

const UNKNOWN_NETWORK_NAME_PATTERN = /^(unknown|unavailable|n\/a|na|none|-)$/i;

function extractAsnNumber(rawAsn: string | null | undefined): number | null {
  if (!rawAsn) return null;
  const trimmed = rawAsn.trim();
  if (!trimmed) return null;
  const lowered = trimmed.toLowerCase();
  if (lowered === 'unknown' || lowered === 'unavailable') return null;
  // Accept both "AS55836" and "55836" forms; treat anything without a numeric
  // head as unknown.
  const digitsMatch = trimmed.replace(/^AS/i, '').match(/^(\d{1,10})/);
  const digits = digitsMatch && digitsMatch[1] ? digitsMatch[1] : null;
  if (!digits) return null;
  const value = Number.parseInt(digits, 10);
  return Number.isFinite(value) && value > 0 ? value : null;
}

function cleanIspBrandText(ispText: string, orgText: string, asnText = ''): string {
  const candidates = [ispText, orgText];
  for (const candidate of candidates) {
    const cleaned = candidate.replace(/\s+/g, ' ').trim();
    if (!cleaned || UNKNOWN_NETWORK_NAME_PATTERN.test(cleaned)) continue;
    return cleaned;
  }
  // Numeric ASN known but no name: `AS<number>` is honest, "Standard Network" is not.
  const asnNumber = extractAsnNumber(asnText);
  return asnNumber !== null ? `AS${asnNumber}` : 'Standard Network';
}

export function classifyIspNetwork(
  isp: string,
  org: string,
  asn: string
): IspNetworkClassification {
  const ispText = (isp || '').trim();
  const orgText = (org || '').trim();
  const keywordCorpus = `${ispText} ${orgText}`.trim();
  const asnNumber = extractAsnNumber(asn);

  const applyRule = (rule: IspNetworkRule, matchedReason: string): IspNetworkClassification => ({
    brandName: rule.brandName,
    networkType: rule.networkType,
    isConsumerBroadband: rule.isConsumer,
    isDatacenterOrHosting: !rule.isConsumer,
    matchedReason,
  });

  // Pass 1: numeric ASN evidence takes priority over any ISP / Org keyword.
  if (asnNumber !== null) {
    for (const rule of ISP_NETWORK_RULES) {
      if (rule.asns.includes(asnNumber)) {
        return applyRule(rule, `Matched AS${asnNumber} (${rule.label})`);
      }
    }
  }

  // Pass 2: keyword evidence over the ISP / Org strings (rule order matters).
  for (const rule of ISP_NETWORK_RULES) {
    if (!rule.pattern) continue;
    const keywordMatch = keywordCorpus.match(rule.pattern);
    const keyword = keywordMatch && keywordMatch[0] ? keywordMatch[0] : null;
    if (keyword) {
      return applyRule(rule, `Matched keyword '${keyword}' (${rule.label})`);
    }
  }

  // Fallback: nothing matched; keep the cleaned ISP / Org name as the brand.
  return {
    brandName: cleanIspBrandText(ispText, orgText, asn),
    networkType: RESIDENTIAL_BROADBAND,
    isConsumerBroadband: false,
    isDatacenterOrHosting: false,
    matchedReason: null,
  };
}

/**
 * Computes SHA-256 hex digest using native Web Crypto API (with pure-JS FNV-1a fallback if subtle is unavailable).
 */
async function sha256Hex(input: string): Promise<string> {
  try {
    if (typeof crypto !== 'undefined' && crypto.subtle && typeof TextEncoder !== 'undefined') {
      const encoded = new TextEncoder().encode(input);
      const digest = await crypto.subtle.digest('SHA-256', encoded);
      const bytes = Array.from(new Uint8Array(digest));
      return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
    }
  } catch {
    // Fallback below
  }

  // Deterministic 64-char hex fallback if Web Crypto is restricted
  let h1 = 0xdeadbeef ^ input.length;
  let h2 = 0x41c6ce57 ^ input.length;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const part1 = (h1 >>> 0).toString(16).padStart(8, '0');
  const part2 = (h2 >>> 0).toString(16).padStart(8, '0');
  return `${part1}${part2}${part1}${part2}`;
}

/**
 * Envelope-only SHA-256 helper (Phase 4).
 *
 * Unlike `sha256Hex`, this never substitutes a non-cryptographic digest: the server
 * verifies the envelope with a real SHA-256, so a fake digest would be reported as a
 * tampered request. When Web Crypto is unavailable this resolves to `''`, which the
 * server treats as "unverifiable" rather than "tampered". Never throws.
 */
async function sha256EnvelopeSignature(input: string): Promise<string> {
  try {
    if (typeof crypto === 'undefined' || !crypto.subtle || typeof TextEncoder === 'undefined') {
      return '';
    }
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  } catch {
    return '';
  }
}

/**
 * 32 hex characters (16 cryptographically random bytes) for the envelope nonce.
 * Falls back to a Math.random-derived value when `crypto.getRandomValues` is missing.
 */
function generateEnvelopeNonce(): string {
  try {
    if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
      const bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    }
  } catch {
    // Fallback below
  }
  let fallback = '';
  while (fallback.length < 32) {
    fallback += Math.random().toString(16).slice(2);
  }
  return fallback.slice(0, 32);
}

/** Stable, capability-derived GPU probe used by both device classification and the hwid seed. */
interface WebGlGpuProbe {
  gpuVendor: string;
  gpuRenderer: string;
  maxTextureSize: number;
  /**
   * Coarse GPU class derived from WebGL *capabilities* (max texture size, shader precision,
   * extension count) — NOT from the raw, spoofable vendor/renderer strings. Stable across
   * renderer spoofing (e.g. SwiftShader masquerading as an RTX 4090).
   */
  gpuClass: string;
  /** True when strings or capabilities indicate a software / masked rasteriser. */
  softwareRenderer: boolean;
}

const SOFTWARE_GPU_RENDERER_PATTERN =
  /swiftshader|llvmpipe|softpipe|mesa offscreen|software rasterizer|software renderer|basic render driver|microsoft basic render|apple software renderer|virgl/i;
const HIGH_END_GPU_RENDERER_PATTERN =
  /\brtx\b|\bgtx\b|geforce|radeon rx|quadro|\bapple m[1-9]\b/i;

/**
 * 1. Native WebGL GPU Inspector:
 * Queries WEBGL_debug_renderer_info for UNMASKED_VENDOR_WEBGL and UNMASKED_RENDERER_WEBGL,
 * plus capability limits (MAX_TEXTURE_SIZE, shader precision, extension count). The raw
 * strings remain telemetry; `gpuClass` is the coarse, spoof-resistant seed anchor.
 */
function inspectWebGlGpu(): WebGlGpuProbe {
  const unavailable: WebGlGpuProbe = {
    gpuVendor: 'Unavailable',
    gpuRenderer: 'Unavailable',
    maxTextureSize: 0,
    gpuClass: 'na',
    softwareRenderer: false,
  };
  if (typeof document === 'undefined') {
    return unavailable;
  }

  try {
    const canvas = document.createElement('canvas');
    const gl =
      (canvas.getContext('webgl2') as WebGLRenderingContext | null) ||
      (canvas.getContext('webgl') as WebGLRenderingContext | null) ||
      (canvas.getContext('experimental-webgl') as WebGLRenderingContext | null);

    if (!gl) {
      return unavailable;
    }

    const debugExt = gl.getExtension('WEBGL_debug_renderer_info');
    const rawVendor = debugExt
      ? gl.getParameter(debugExt.UNMASKED_VENDOR_WEBGL)
      : gl.getParameter(gl.VENDOR);
    const rawRenderer = debugExt
      ? gl.getParameter(debugExt.UNMASKED_RENDERER_WEBGL)
      : gl.getParameter(gl.RENDERER);
    const rawMaxTex = gl.getParameter(gl.MAX_TEXTURE_SIZE);
    const gpuVendor =
      typeof rawVendor === 'string' && rawVendor.trim() ? rawVendor.trim() : 'Standard WebGL Vendor';
    const gpuRenderer =
      typeof rawRenderer === 'string' && rawRenderer.trim()
        ? rawRenderer.trim()
        : 'Standard WebGL Renderer';
    const maxTextureSize =
      typeof rawMaxTex === 'number' && Number.isFinite(rawMaxTex) ? rawMaxTex : 0;

    // Capability reads — these reflect the *actual* driver, not the spoofable strings.
    let fragmentPrecision = 0;
    let vertexPrecision = 0;
    let extensionCount = 0;
    try {
      fragmentPrecision =
        gl.getShaderPrecisionFormat?.(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT)?.precision ?? 0;
      vertexPrecision = gl.getShaderPrecisionFormat?.(gl.VERTEX_SHADER, gl.HIGH_FLOAT)?.precision ?? 0;
      extensionCount = gl.getSupportedExtensions?.()?.length ?? 0;
    } catch {
      // Capability probe unavailable: degrade to a conservative coarse class.
    }

    const loseExt = gl.getExtension('WEBGL_lose_context');
    if (loseExt && typeof loseExt.loseContext === 'function') {
      loseExt.loseContext();
    }

    // Software detection: explicit software strings, OR a hardware-string spoof on a
    // low-capability driver (e.g. SwiftShader reporting 8192px claiming an RTX 4090).
    const softwareByString =
      SOFTWARE_GPU_RENDERER_PATTERN.test(`${gpuVendor} ${gpuRenderer}`) ||
      /^google inc\.?\s*\(\s*google\s*\)$/i.test(gpuVendor);
    const spoofedHighEnd =
      HIGH_END_GPU_RENDERER_PATTERN.test(gpuRenderer) && maxTextureSize > 0 && maxTextureSize <= 8192;
    const softwareRenderer = softwareByString || spoofedHighEnd;

    const texBucket =
      maxTextureSize >= 16384
        ? 't16'
        : maxTextureSize >= 8192
        ? 't8'
        : maxTextureSize >= 4096
        ? 't4'
        : 't0';
    const precisionBucket = fragmentPrecision > 0 && vertexPrecision > 0 ? 'h' : 'l';
    const extBucket = extensionCount >= 40 ? 'e3' : extensionCount >= 20 ? 'e2' : extensionCount >= 8 ? 'e1' : 'e0';
    const gpuClass = `${texBucket}|${precisionBucket}|${extBucket}`;

    return { gpuVendor, gpuRenderer, maxTextureSize, gpuClass, softwareRenderer };
  } catch {
    return unavailable;
  }
}

/** Canvas probe result: the stable SHA-256 signature plus structural/noise metadata. */
interface CanvasSignatureResult {
  signature: string;
  /** 8x8 coarse-quantized luminance digest (structural anchor, farbling-resistant). */
  coarseHash: string | null;
  /** True when two reads of the same static bitmap differ. */
  noise: boolean;
}

/**
 * 2. Native Canvas 2D Signature:
 * Renders custom geometry, gradients, and multi-font text onto an offscreen <canvas>
 * and hashes the data URL via SHA-256 into a compact 16-char hex signature.
 *
 * The bitmap is deliberately read twice: a farbling browser (Brave / Safari / Tor RFP)
 * returns different pixels on each read, which is recorded as `noise` rather than being
 * allowed to mint a new hardware id. An 8x8 quantized luminance grid gives a coarse,
 * noise-tolerant structural digest used by the LSH structural-anchor fallback.
 */
async function computeCanvas2dSignature(): Promise<CanvasSignatureResult> {
  if (typeof document === 'undefined') {
    return { signature: 'unavailable', coarseHash: null, noise: false };
  }
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 260;
    canvas.height = 64;
    const ctx = canvas.getContext('2d');
    if (!ctx) return { signature: 'unavailable', coarseHash: null, noise: false };

    ctx.textBaseline = 'alphabetic';
    const grad = ctx.createLinearGradient(0, 0, 260, 64);
    grad.addColorStop(0, '#f05a28');
    grad.addColorStop(0.5, '#2563eb');
    grad.addColorStop(1, '#10b981');
    ctx.fillStyle = grad;
    ctx.fillRect(4, 4, 252, 56);

    ctx.globalCompositeOperation = 'multiply';
    ctx.fillStyle = 'rgba(255, 210, 45, 0.82)';
    ctx.beginPath();
    ctx.arc(68, 32, 22, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fill();

    ctx.globalCompositeOperation = 'source-over';
    ctx.fillStyle = '#0f172a';
    ctx.font = '600 15px "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, sans-serif';
    ctx.fillText('IntelSystem-HWID:2026 #[0x7F]', 12, 26);

    ctx.fillStyle = '#f8fafc';
    ctx.font = '13px "JetBrains Mono", monospace';
    ctx.fillText('Canvas2D::Subpixel_AA(3.14159)', 14, 48);

    ctx.strokeStyle = 'rgba(255, 255, 255, 0.65)';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(12, 54);
    ctx.bezierCurveTo(75, 12, 165, 58, 244, 18);
    ctx.stroke();

    // Dual read of the SAME static bitmap — no repaint between reads.
    const first = canvas.toDataURL('image/png');
    const second = canvas.toDataURL('image/png');
    const noise = first !== second;

    // 8x8 coarse quantized digest: average luminance per cell, bucketed to 4 bits.
    let coarseHash: string | null = null;
    try {
      const { data } = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const width = canvas.width;
      const height = canvas.height;
      const cells: string[] = [];
      for (let gy = 0; gy < 8; gy += 1) {
        const y0 = Math.floor((gy * height) / 8);
        const y1 = Math.floor(((gy + 1) * height) / 8);
        for (let gx = 0; gx < 8; gx += 1) {
          const x0 = Math.floor((gx * width) / 8);
          const x1 = Math.floor(((gx + 1) * width) / 8);
          let sum = 0;
          let count = 0;
          for (let y = y0; y < y1; y += 1) {
            for (let x = x0; x < x1; x += 1) {
              const i = (y * width + x) * 4;
              // Integer luminance (Rec. 601), alpha-weighted so transparent cells stay dark.
              const alpha = data[i + 3] / 255;
              sum += Math.round((data[i] * 77 + data[i + 1] * 150 + data[i + 2] * 29) / 256) * alpha;
              count += 1;
            }
          }
          const avg = count > 0 ? Math.round(sum / count) : 0;
          cells.push(Math.max(0, Math.min(15, avg >> 4)).toString(16));
        }
      }
      coarseHash = (await sha256Hex(cells.join(''))).slice(0, 16);
    } catch {
      coarseHash = null;
    }

    const fullHex = await sha256Hex(first);
    return { signature: fullHex.slice(0, 16), coarseHash, noise };
  } catch {
    return { signature: 'restricted', coarseHash: null, noise: false };
  }
}

/** Audio probe result: the stable SHA-256 signature plus a dual-render noise flag. */
interface AudioSignatureResult {
  signature: string;
  noise: boolean;
}

/**
 * Coarse, farbling-resistant audio stability class for the hardware-id seed. It is derived
 * ONLY from the dual-render comparison and the probe's availability state — never from the
 * raw rendered float or its hash, both of which drift under Brave/Safari/Tor farbling.
 */
function audioStabilityClass(audio: AudioSignatureResult): 'stable' | 'noisy' | 'unavailable' {
  if (audio.noise) return 'noisy';
  if (/timeout|unsupported|unavailable|restricted/i.test(audio.signature)) return 'unavailable';
  return 'stable';
}

/**
 * 3. Native Web Audio Signature:
 * Uses OfflineAudioContext with a triangle OscillatorNode and DynamicsCompressorNode
 * to render a short in-memory buffer, sums channel data samples, and hashes via SHA-256.
 *
 * The graph is rendered twice with identical parameters. A farbling browser injects
 * different noise into each render, recorded as `noise` instead of minting a new id.
 */
async function computeWebAudioSignature(): Promise<AudioSignatureResult> {
  if (typeof window === 'undefined') return { signature: 'unavailable', noise: false };
  try {
    const OfflineCtx =
      window.OfflineAudioContext ||
      (window as unknown as { webkitOfflineAudioContext?: typeof OfflineAudioContext })
        .webkitOfflineAudioContext;
    if (!OfflineCtx) return { signature: 'unsupported', noise: false };

    const renderOnce = async (): Promise<string | null> => {
      try {
        const context = new OfflineCtx(1, 4500, 44100);
        const oscillator = context.createOscillator();
        oscillator.type = 'triangle';
        oscillator.frequency.setValueAtTime(10000, context.currentTime);

        const compressor = context.createDynamicsCompressor();
        compressor.threshold.setValueAtTime(-50, context.currentTime);
        compressor.knee.setValueAtTime(40, context.currentTime);
        compressor.ratio.setValueAtTime(12, context.currentTime);
        compressor.attack.setValueAtTime(0, context.currentTime);
        compressor.release.setValueAtTime(0.25, context.currentTime);

        oscillator.connect(compressor);
        compressor.connect(context.destination);
        oscillator.start(0);

        const renderedBuffer = await Promise.race([
          context.startRendering(),
          new Promise<null>((resolve) => setTimeout(() => resolve(null), 500)),
        ]);
        if (!renderedBuffer) return null;

        const channelData = renderedBuffer.getChannelData(0);
        let sampleSum = 0;
        const quantizedSamples: string[] = [];
        for (let i = 450; i < channelData.length; i += 50) {
          const val = channelData[i];
          sampleSum += Math.abs(val);
          quantizedSamples.push(val.toFixed(6));
        }
        return `${sampleSum.toFixed(8)}|${quantizedSamples.join(',')}`;
      } catch {
        return null;
      }
    };

    const first = await renderOnce();
    if (first === null) return { signature: 'timeout', noise: false };
    const second = await renderOnce();
    const noise = second !== null && second !== first;
    const fullHex = await sha256Hex(first);
    return { signature: fullHex.slice(0, 16), noise };
  } catch {
    return { signature: 'restricted', noise: false };
  }
}

/**
 * Queries public IP, network ISP, and IP timezone directly from the visitor's browser
 * as a fallback/reinforcement hint.
 */
async function collectClientGeoHint(): Promise<ClientGeoHint | null> {
  // 1. Primary: ipwho.is
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2200);
    const res = await fetch('https://ipwho.is/', {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    clearTimeout(timer);
    if (res.ok) {
      const data = (await res.json()) as Record<string, unknown>;
      if (data && data.success !== false && typeof data.ip === 'string' && data.ip) {
        const conn = (data.connection as Record<string, unknown>) || {};
        const sec = (data.security as Record<string, unknown>) || {};
        const tzObj = (data.timezone as Record<string, unknown>) || {};
        const rawAsn = conn.asn ? `AS${String(conn.asn).replace(/^AS/i, '')}` : 'Unknown';
        const lat = typeof data.latitude === 'number' && Number.isFinite(data.latitude) ? data.latitude : null;
        const lon = typeof data.longitude === 'number' && Number.isFinite(data.longitude) ? data.longitude : null;
        const ipTz =
          typeof tzObj.id === 'string' && tzObj.id.trim() ? tzObj.id.trim() : 'Unknown';
        return {
          ip: data.ip.trim(),
          city: typeof data.city === 'string' && data.city.trim() ? data.city.trim() : 'Unknown',
          region: typeof data.region === 'string' && data.region.trim() ? data.region.trim() : 'Unknown',
          country: typeof data.country === 'string' && data.country.trim() ? data.country.trim() : 'Unknown',
          countryCode: typeof data.country_code === 'string' ? data.country_code.trim() : '',
          latitude: lat,
          longitude: lon,
          isp: typeof conn.isp === 'string' && conn.isp.trim() ? conn.isp.trim() : 'Unknown',
          org: typeof conn.org === 'string' && conn.org.trim() ? conn.org.trim() : 'Unknown',
          asn: rawAsn,
          timezone: ipTz,
          isVpnOrHosting: Boolean(sec.vpn || sec.proxy || sec.tor || sec.hosting),
        };
      }
    }
  } catch {
    // Fallback to secondary provider
  }

  // 2. Secondary: ipapi.co/json/
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2200);
    const res = await fetch('https://ipapi.co/json/', {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    clearTimeout(timer);
    if (res.ok) {
      const data = (await res.json()) as Record<string, unknown>;
      if (data && !data.error && typeof data.ip === 'string' && data.ip) {
        const orgStr = typeof data.org === 'string' && data.org.trim() ? data.org.trim() : 'Unknown';
        const asnStr = typeof data.asn === 'string' && data.asn.trim() ? data.asn.trim() : 'Unknown';
        const lat = typeof data.latitude === 'number' && Number.isFinite(data.latitude) ? data.latitude : null;
        const lon = typeof data.longitude === 'number' && Number.isFinite(data.longitude) ? data.longitude : null;
        const ipTz =
          typeof data.timezone === 'string' && data.timezone.trim() ? data.timezone.trim() : 'Unknown';
        return {
          ip: data.ip.trim(),
          city: typeof data.city === 'string' && data.city.trim() ? data.city.trim() : 'Unknown',
          region: typeof data.region === 'string' && data.region.trim() ? data.region.trim() : 'Unknown',
          country:
            typeof data.country_name === 'string' && data.country_name.trim()
              ? data.country_name.trim()
              : 'Unknown',
          countryCode: typeof data.country_code === 'string' ? data.country_code.trim() : '',
          latitude: lat,
          longitude: lon,
          isp: orgStr,
          org: orgStr,
          asn: asnStr,
          timezone: ipTz,
          isVpnOrHosting: false,
        };
      }
    }
  } catch {
    // Fallback to tertiary provider
  }

  // 3. Tertiary: freeipapi.com
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2200);
    const res = await fetch('https://freeipapi.com/api/json', {
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (res.ok) {
      const data = (await res.json()) as Record<string, unknown>;
      if (data && typeof data.ipAddress === 'string' && data.ipAddress) {
        const orgStr =
          typeof data.asnOrganization === 'string' && data.asnOrganization.trim()
            ? data.asnOrganization.trim()
            : 'Unknown';
        const rawAsn = data.asn ? `AS${String(data.asn).replace(/^AS/i, '')}` : 'Unknown';
        const lat = typeof data.latitude === 'number' && Number.isFinite(data.latitude) ? data.latitude : null;
        const lon = typeof data.longitude === 'number' && Number.isFinite(data.longitude) ? data.longitude : null;
        const tzList = Array.isArray(data.timeZones) ? data.timeZones : [];
        const ipTz =
          typeof tzList[0] === 'string' && tzList[0].trim() ? tzList[0].trim() : 'Unknown';
        return {
          ip: data.ipAddress.trim(),
          city: typeof data.cityName === 'string' && data.cityName.trim() ? data.cityName.trim() : 'Unknown',
          region: typeof data.regionName === 'string' && data.regionName.trim() ? data.regionName.trim() : 'Unknown',
          country: typeof data.countryName === 'string' && data.countryName.trim() ? data.countryName.trim() : 'Unknown',
          countryCode: typeof data.countryCode === 'string' ? data.countryCode.trim() : '',
          latitude: lat,
          longitude: lon,
          isp: orgStr,
          org: orgStr,
          asn: rawAsn,
          timezone: ipTz,
          isVpnOrHosting: Boolean(data.isProxy),
        };
      }
    }
  } catch {
    // Ignore
  }

  return null;
}

export async function collectBrowserDeviceInfo(): Promise<BrowserDeviceInfo & ClientRuntimeSignals> {
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent || '' : '';
  const runtimeFacts = detectRuntimeFacts(ua);
  const uaData =
    typeof navigator !== 'undefined'
      ? ((navigator as unknown as { userAgentData?: NavigatorUAData }).userAgentData ?? null)
      : null;

  let highEntropy: {
    fullVersionList?: NavigatorUABrand[];
    platform?: string;
    platformVersion?: string;
    architecture?: string;
    bitness?: string;
    mobile?: boolean;
    model?: string;
    formFactors?: string[];
  } | null = null;

  if (uaData && typeof uaData.getHighEntropyValues === 'function') {
    try {
      highEntropy = await Promise.race([
        uaData.getHighEntropyValues([
          'fullVersionList',
          'platform',
          'platformVersion',
          'architecture',
          'bitness',
          'mobile',
          'model',
          'formFactors',
        ]),
        new Promise<null>((resolve) => setTimeout(() => resolve(null), 2000)),
      ]);
    } catch {
      highEntropy = null;
    }
  }

  let browser = 'Unknown';
  const versionList = highEntropy?.fullVersionList || uaData?.brands || [];

  let isBrave = false;
  try {
    const navBrave = navigator as unknown as { brave?: { isBrave?: () => Promise<boolean> } };
    if (navBrave.brave && typeof navBrave.brave.isBrave === 'function') {
      isBrave = Boolean(await navBrave.brave.isBrave());
    }
  } catch {
    isBrave = false;
  }

  const findBrand = (pattern: RegExp) => versionList.find((b) => pattern.test(b.brand));

  const edgeBrand = findBrand(/Microsoft Edge|Edge/i);
  const operaBrand = findBrand(/Opera|OPR/i);
  const vivaldiBrand = findBrand(/Vivaldi/i);
  const braveBrand = findBrand(/Brave/i);
  const samsungBrand = findBrand(/Samsung/i);
  const chromeBrand = findBrand(/Chrome|Chromium/i);

  const edgUa = ua.match(/Edg(?:e|A|iOS)?\/([\d.]+)/);
  const oprUa = ua.match(/(?:OPR|Opera)\/([\d.]+)/);
  const vivaldiUa = ua.match(/Vivaldi\/([\d.]+)/);
  const samsungUa = ua.match(/SamsungBrowser\/([\d.]+)/);
  const firefoxUa = ua.match(/(?:Firefox|FxiOS)\/([\d.]+)/);
  const criosUa = ua.match(/CriOS\/([\d.]+)/);
  const chromeUa = ua.match(/Chrome\/([\d.]+)/);
  const safariUa = ua.match(/Version\/([\d.]+).*Safari/);

  if (runtimeFacts.electron) {
    // Electron's UA contains a `Chrome/<ver>` token for the embedded engine. The Electron
    // token (or process.versions.electron) is authoritative: label the runtime, not Chromium.
    const ver = ua.match(/Electron\/([\d.]+)/i)?.[1] || runtimeFacts.electronVersion;
    browser = ver ? `Electron ${ver}` : 'Electron';
  } else if (isBrave || braveBrand) {
    const ver = braveBrand?.version || (chromeUa ? chromeUa[1] : '');
    browser = ver ? `Brave ${ver}` : 'Brave';
  } else if (detectInAppBrowser(ua)) {
    browser = detectInAppBrowser(ua) as string;
  } else if (edgeBrand || edgUa) {
    const ver = edgUa ? edgUa[1] : edgeBrand?.version || '';
    browser = ver ? `Microsoft Edge ${ver}` : 'Microsoft Edge';
  } else if (operaBrand || oprUa) {
    const ver = oprUa ? oprUa[1] : operaBrand?.version || '';
    browser = ver ? `Opera ${ver}` : 'Opera';
  } else if (vivaldiBrand || vivaldiUa) {
    const ver = vivaldiUa ? vivaldiUa[1] : vivaldiBrand?.version || '';
    browser = ver ? `Vivaldi ${ver}` : 'Vivaldi';
  } else if (samsungBrand || samsungUa) {
    const ver = samsungUa ? samsungUa[1] : samsungBrand?.version || '';
    browser = ver ? `Samsung Internet ${ver}` : 'Samsung Internet';
  } else if (firefoxUa) {
    browser = `Firefox ${firefoxUa[1]}`;
  } else if (criosUa) {
    browser = `Chrome ${criosUa[1]}`;
  } else if (chromeBrand || chromeUa) {
    const ver = chromeUa ? chromeUa[1] : chromeBrand?.version || '';
    browser = ver ? `Chrome ${ver}` : 'Chrome';
  } else if (safariUa && !/Chrome|Chromium|Edg|OPR/i.test(ua)) {
    browser = `Safari ${safariUa[1]}`;
  }

  let os = 'Unknown';
  // iOS 26 froze the legacy `CPU iPhone OS 18_7 like Mac OS X` token while
  // `Version/26.x` carries the real OS, so compare majors and keep the most
  // precise candidate instead of trusting the frozen token.
  const resolveIosVersion = (): string => {
    const candidates: string[] = [];
    const fromUa = ua.match(/(?:CPU (?:iPhone |iPad )?OS|OS) ([\d_]+) like Mac OS X/)?.[1];
    if (fromUa) candidates.push(fromUa.replace(/_/g, '.'));
    const fromVersion = ua.match(/Version\/([\d.]+)/)?.[1];
    if (fromVersion) candidates.push(fromVersion);
    if (/^\d+/.test(hintPlatformVersion)) {
      const hinted = hintPlatformVersion.split('.').slice(0, 3).join('.');
      if (hinted) candidates.push(hinted);
    }
    if (!candidates.length) return '';
    return candidates
      .map((value) => {
        const parts = value.split('.').map((part) => parseInt(part, 10));
        return { value, parts, major: Number.isNaN(parts[0]) ? 0 : parts[0] };
      })
      .sort((a, b) => b.major - a.major || b.parts.length - a.parts.length)
      .map((entry) => entry.value.replace(/\.$/, ''))[0];
  };
  const maxTouchPoints = typeof navigator !== 'undefined' ? Number(navigator.maxTouchPoints ?? 0) : 0;
  const hintPlatform = highEntropy?.platform || uaData?.platform || '';
  const hintPlatformVersion = highEntropy?.platformVersion || '';

  if (/Windows/i.test(hintPlatform) || /Windows NT/i.test(ua)) {
    os = 'Windows';
    if (hintPlatformVersion) {
      const majorBuild = parseInt(hintPlatformVersion.split('.')[0], 10);
      if (!Number.isNaN(majorBuild) && majorBuild > 0) {
        os = majorBuild >= 13 ? 'Windows 11' : 'Windows 10';
      }
    }
  } else if (/CrOS/i.test(ua) || /Chrome OS|ChromeOS/i.test(hintPlatform)) {
    os = 'ChromeOS';
  } else if (/Android/i.test(hintPlatform) || /Android/i.test(ua)) {
    const androidVersion =
      hintPlatformVersion && /^\d+/.test(hintPlatformVersion)
        ? hintPlatformVersion.split('.')[0]
        : (ua.match(/Android ([\d.]+)/)?.[1] ?? '');
    os = androidVersion ? `Android ${androidVersion}` : 'Android';
  } else if (/iPad/i.test(ua) || (/Macintosh/i.test(ua) && maxTouchPoints > 2)) {
    const iosVersion = resolveIosVersion();
    os = iosVersion ? `iPadOS ${iosVersion}` : 'iPadOS';
  } else if (/iPhone|iPod/i.test(ua) || /iOS/i.test(hintPlatform)) {
    const iosVersion = resolveIosVersion();
    os = iosVersion ? `iOS ${iosVersion}` : 'iOS';
  } else if (/macOS|Mac OS/i.test(hintPlatform) || /Macintosh|Mac OS X/i.test(ua)) {
    if (hintPlatformVersion) {
      const parts = hintPlatformVersion.split('.');
      const major = parseInt(parts[0], 10);
      if (!Number.isNaN(major) && major >= 11) {
        os = `macOS ${parts.slice(0, 2).join('.')}`;
      } else {
        os = 'macOS';
      }
    } else {
      os = 'macOS';
    }
  } else if (/Linux/i.test(hintPlatform) || /Linux/i.test(ua)) {
    os = 'Linux';
  }

  const rawPlatform = hintPlatform || (typeof navigator !== 'undefined' ? navigator.platform : '');
  const platform = rawPlatform && rawPlatform.trim() ? rawPlatform.trim() : 'Unavailable';

  // --- Genuine physical-device gate -------------------------------------------------
  // Viewport width alone is never a signal. The gate requires the platform, CPU
  // architecture, GPU silicon and finger input to agree with the User-Agent, so a
  // resized window or a DevTools device preset can never turn a desktop into a phone.
  const navPlatform =
    typeof navigator !== 'undefined' && typeof navigator.platform === 'string'
      ? navigator.platform
      : '';
  const gateTouchPoints =
    typeof navigator !== 'undefined' ? Number(navigator.maxTouchPoints ?? 0) : 0;
  const pointerCoarse =
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(pointer: coarse)').matches
      : false;
  const hoverNone =
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(hover: none)').matches
      : false;
  const hasTouchEvent =
    typeof window !== 'undefined' && 'ontouchstart' in window;
  const viewportWidth =
    typeof window !== 'undefined' ? Number(window.innerWidth) || 0 : 0;
  const gpuProbe = inspectWebGlGpu();
  const pcLock = getPcLock();

  const deviceGate: DeviceGateResult = classifyGenuineDevice({
    ua,
    platform: navPlatform,
    architecture: highEntropy?.architecture,
    mobileHint: highEntropy?.mobile ?? uaData?.mobile,
    formFactors: highEntropy?.formFactors,
    gpuVendor: gpuProbe.gpuVendor,
    gpuRenderer: gpuProbe.gpuRenderer,
    maxTouchPoints: gateTouchPoints,
    pointerCoarse,
    hoverNone,
    hasTouchEvent,
    viewportWidth,
    pcLocked: pcLock !== null,
  });

  const deviceType: BrowserDeviceInfo['deviceType'] =
    typeof navigator === 'undefined'
      ? 'Unknown'
      : deviceGate.kind === 'mobile'
      ? 'Mobile'
      : deviceGate.kind === 'tablet'
      ? 'Tablet'
      : 'Desktop';

  // Persist the desktop lock on genuinely desktop hardware; flush stale snapshots
  // on a genuine handheld. A valid PC lock survives DevTools emulation.
  try {
    if (typeof window !== 'undefined') {
      if (deviceGate.kind === 'pc') {
        savePcLock({ deviceLabel: os, browserName: browser }, false);
      } else if (deviceGate.genuineMobile) {
        releaseNonPcLock();
      }
    }
  } catch {
    // Storage blocked: classification still stands for this visit.
  }

  // --- Exact phone-model resolution (mobile only) -----------------------------------
  // High-entropy `model` first; Android UA Build token as the fallback for browsers
  // that do not expose Client Hints (Firefox Android, in-app WebViews, Samsung Internet).
  let reportedModel = '';
  if (deviceGate.kind === 'mobile') {
    const hintModel =
      typeof highEntropy?.model === 'string' ? highEntropy.model.trim() : '';
    if (hintModel && !/^(k|unknown)$/i.test(hintModel)) {
      reportedModel = hintModel;
    } else if (/Android/i.test(ua)) {
      reportedModel = extractAndroidModelFromUA(ua);
    }
  }

  let phoneBrand = '';
  let phoneModel = '';
  let phoneModelCode = '';
  let phoneDeviceCode = '';
  let phoneDisplayLabel = '';

  if (deviceGate.kind === 'mobile') {
    if (/iPhone|iPod/i.test(ua)) {
      phoneBrand = 'Apple';
      phoneModel = 'Apple iPhone';
      phoneDisplayLabel = 'Apple iPhone';
    } else if (reportedModel) {
      try {
        // Lazy chunk: desktop visitors never download the 37k-entry catalog.
        const { resolvePhoneModel, formatPhoneLabel, formatPhoneDisplayLabel } =
          await import('./phoneModel');
        const entry = resolvePhoneModel(reportedModel);
        if (entry) {
          phoneBrand = entry.retailBrand;
          phoneModel = formatPhoneLabel(entry);
          phoneModelCode = entry.modelCode;
          phoneDeviceCode = entry.deviceCode;
          phoneDisplayLabel = formatPhoneDisplayLabel(entry);
        } else {
          phoneModel = reportedModel;
          phoneModelCode = reportedModel;
          phoneDisplayLabel = reportedModel;
        }
      } catch {
        phoneModel = reportedModel;
        phoneModelCode = reportedModel;
        phoneDisplayLabel = reportedModel;
      }
    } else {
      // No model is exposed at all (Tor Browser strips it from the reduced UA and
      // Firefox has no UA-CH). Show the honest OS-level label instead of inventing
      // a handset name: "Android 14 Smartphone" is still more useful than "Mobile".
      phoneModel = `${os} Smartphone`;
      phoneDisplayLabel = `${os} Smartphone`;
    }
  }

  const sw = typeof window !== 'undefined' && window.screen ? Number(window.screen.width) : 0;
  const sh = typeof window !== 'undefined' && window.screen ? Number(window.screen.height) : 0;
  const screenResolution = sw > 0 && sh > 0 ? `${sw} x ${sh}` : 'Unavailable';

  const dpr = typeof window !== 'undefined' ? Number(window.devicePixelRatio) : NaN;
  const pixelRatio = !Number.isNaN(dpr) && dpr > 0 ? `${Number(dpr.toFixed(2))}x` : 'Unavailable';

  const language =
    typeof navigator !== 'undefined' && navigator.language && navigator.language.trim()
      ? navigator.language.trim()
      : 'Unavailable';

  let timezone = 'Unavailable';
  try {
    const resolvedTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (resolvedTz && resolvedTz.trim()) {
      timezone = resolvedTz.trim();
    }
  } catch {
    timezone = 'Unavailable';
  }

  // Attach the storage-physics verdict to the device-info object as well, so any
  // consumer that only reads browserDevice still sees the incognito aliases.
  const incognitoVerdict = await detectIncognitoMode();

  return {
    browser,
    os,
    deviceType,
    platform,
    screenResolution,
    pixelRatio,
    language,
    timezone,
    /* Additive runtime provenance — Electron is never labelled Chromium. */
    runtime: runtimeFacts.runtime,
    host_app: runtimeFacts.host_app,
    client_type: runtimeFacts.client_type,
    deviceKind: deviceGate.kind,
    genuineMobile: deviceGate.genuineMobile,
    devtoolsDeviceEmulation: deviceGate.devtoolsDeviceEmulation,
    reportedModel: reportedModel || undefined,
    phoneBrand: phoneBrand || undefined,
    phoneModel: phoneModel || undefined,
    phoneModelCode: phoneModelCode || undefined,
    phoneDeviceCode: phoneDeviceCode || undefined,
    phoneDisplayLabel: phoneDisplayLabel || undefined,
    incognito: incognitoVerdict.isPrivate,
    isIncognito: incognitoVerdict.isPrivate,
    privateMode: incognitoVerdict.isPrivate,
    incognitoMethod: incognitoVerdict.method,
    idbDurabilityRatio: incognitoVerdict.idbDurabilityRatio,
    opfsFlushMs: incognitoVerdict.opfsFlushMs,
    ...(incognitoVerdict.diagnostics ? { diagnostics: incognitoVerdict.diagnostics } : {}),
  };
}

/**
 * UA-CH values posted alongside the identify payload.
 *
 * Low-entropy values (`brands`, `mobile`, `platform`) are always available from
 * `navigator.userAgentData`. High-entropy values are requested per identify and raced
 * against a 1.5 s budget: a browser that never answers must not hold up the request,
 * so the caller always receives whatever the low-entropy layer already knew.
 * Never throws.
 */
export interface ClientHintsPayload {
  brands?: Array<{ brand: string; version: string }>;
  fullVersionList?: Array<{ brand: string; version: string }>;
  platform?: string;
  platformVersion?: string;
  architecture?: string;
  bitness?: string;
  model?: string;
  mobile?: boolean;
}

let clientHintsInFlight: Promise<ClientHintsPayload | null> | null = null;

async function collectClientHintsUncached(): Promise<ClientHintsPayload | null> {
  if (typeof navigator === 'undefined') return null;
  const uaData = (navigator as unknown as { userAgentData?: NavigatorUAData }).userAgentData;
  if (!uaData) return null;

  const lowEntropy: ClientHintsPayload = {
    brands: Array.isArray(uaData.brands)
      ? uaData.brands.map((entry) => ({ brand: entry.brand, version: entry.version }))
      : undefined,
    mobile: typeof uaData.mobile === 'boolean' ? uaData.mobile : undefined,
    platform: typeof uaData.platform === 'string' ? uaData.platform : undefined,
  };

  if (typeof uaData.getHighEntropyValues !== 'function') return lowEntropy;

  try {
    const highEntropy = await Promise.race([
      uaData.getHighEntropyValues([
        'fullVersionList',
        'platform',
        'platformVersion',
        'architecture',
        'bitness',
        'model',
        'uaFullVersion',
      ]),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 1500)),
    ]);
    if (!highEntropy) return lowEntropy;
    return {
      ...lowEntropy,
      fullVersionList: Array.isArray(highEntropy.fullVersionList)
        ? highEntropy.fullVersionList.map((entry) => ({
            brand: entry.brand,
            version: entry.version,
          }))
        : undefined,
      platform: highEntropy.platform || lowEntropy.platform,
      platformVersion: highEntropy.platformVersion || undefined,
      architecture: highEntropy.architecture || undefined,
      bitness: highEntropy.bitness || undefined,
      model: highEntropy.model || undefined,
    };
  } catch {
    return lowEntropy;
  }
}

/**
 * Shared, cached UA-CH probe. The same promise backs the identify payload and any
 * later caller, so a single identify never asks the browser twice.
 */
export function collectClientHints(): Promise<ClientHintsPayload | null> {
  if (!clientHintsInFlight) {
    clientHintsInFlight = collectClientHintsUncached().catch(() => null);
  }
  return clientHintsInFlight;
}

/**
 * Low-volatility structural anchors for the hardware id seed. Font metrics are measured
 * in the same isolated 16px iframe contract used by the rest of the app, and the math
 * anchor is a fixed transcendentals vector. Neither drifts under canvas farbling, GPU
 * renderer spoofing, resize, touch toggles or UA swaps. Never throws.
 */
function stableStructuralAnchors(): { fontMetric: string; mathAnchor: string } {
  let fontMetric = 'na';
  try {
    const measurer = createIsolatedFontMeasurer();
    if (measurer) {
      const widths = [
        measurer.width(FONT_MEASURE_TEST_STRING, 'sans-serif'),
        measurer.width(FONT_MEASURE_TEST_STRING, 'serif'),
        measurer.width(FONT_MEASURE_TEST_STRING, 'monospace'),
      ];
      measurer.dispose();
      if (widths.every((value) => Number.isFinite(value))) {
        fontMetric = widths.map((value) => Math.round(value)).join('/');
      }
    }
  } catch {
    // Keep the neutral fallback; a blocked iframe must not split a visitor.
  }
  let mathAnchor = 'na';
  try {
    mathAnchor = [Math.tanh(0.8), Math.sin(1.2345), Math.log(123.456)]
      .map((value) => value.toFixed(12))
      .join('/');
  } catch {
    // Keep the neutral fallback.
  }
  return { fontMetric, mathAnchor };
}

/**
 * Collects native Hardware & Rendering Entropy and computes a deterministic Stateless
 * Hardware ID (`hwid_<20_hex_chars>`) using SHA-256.
 */
export async function collectHardwareSignals(
  browserDevice: BrowserDeviceInfo
): Promise<HardwareSignals & { gpuClass: string; gpuObservation: GpuObservation }> {
  const [{ gpuVendor, gpuRenderer, maxTextureSize, gpuClass, softwareRenderer }, canvas, audio] =
    await Promise.all([
      Promise.resolve(inspectWebGlGpu()),
      computeCanvas2dSignature(),
      computeWebAudioSignature(),
    ]);
  const canvasHash = canvas.signature;
  const audioHash = audio.signature;

  const nav = typeof navigator !== 'undefined' ? navigator : undefined;
  const rawCores = nav && typeof nav.hardwareConcurrency === 'number' ? nav.hardwareConcurrency : null;
  const cpuCores = rawCores && rawCores > 0 ? rawCores : null;

  const rawMem =
    nav && typeof (nav as unknown as { deviceMemory?: number }).deviceMemory === 'number'
      ? (nav as unknown as { deviceMemory: number }).deviceMemory
      : null;
  const deviceMemoryGb = rawMem && rawMem > 0 ? rawMem : null;

  const colorDepth =
    typeof window !== 'undefined' && window.screen && typeof window.screen.colorDepth === 'number'
      ? window.screen.colorDepth
      : 24;

  const maxTouchPoints =
    nav && typeof nav.maxTouchPoints === 'number' ? Math.max(0, nav.maxTouchPoints) : 0;

  let hdrSupported = false;
  let colorGamut: HardwareSignals['colorGamut'] = 'sRGB';
  if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
    try {
      hdrSupported = Boolean(window.matchMedia('(dynamic-range: high)').matches);
      if (window.matchMedia('(color-gamut: rec2020)').matches) {
        colorGamut = 'Rec2020';
      } else if (window.matchMedia('(color-gamut: p3)').matches) {
        colorGamut = 'P3';
      }
    } catch {
      // Ignore matchMedia error
    }
  }

  // UA-CH is a *claim* now. It is kept beside the silicon truth for the mismatch flag,
  // but it no longer anchors the hardware id (a device preset can rewrite it freely).
  let claimedArchitecture = '';
  let claimedBitness = '';
  const uaData =
    nav ? ((nav as unknown as { userAgentData?: NavigatorUAData }).userAgentData ?? null) : null;
  if (uaData && typeof uaData.getHighEntropyValues === 'function') {
    try {
      const entropy = await Promise.race([
        uaData.getHighEntropyValues(['architecture', 'bitness']),
        new Promise<null>((resolve) => setTimeout(() => resolve(null), 120)),
      ]);
      if (entropy?.architecture) {
        claimedBitness = entropy.bitness || '';
        claimedArchitecture = entropy.bitness
          ? `${entropy.architecture} (${entropy.bitness}-bit)`
          : entropy.architecture;
      }
    } catch {
      // Keep the empty claim; silicon truth still resolves.
    }
  }

  // Silicon-grounded truth: WebGL silicon family or UA-CH/platform consensus. The NaN
  // sign-bit probe is telemetry only and can never anchor architecture or create a mismatch.
  const truth = resolveHardwareTruth({
    gpuVendor,
    gpuRenderer,
    claimedArchitecture,
    claimedBitness,
    claimedPlatform: browserDevice.platform,
    softwareRenderer,
    claimedOs: browserDevice.os,
    userAgent: (() => {
      try {
        return typeof navigator !== 'undefined' ? navigator.userAgent || '' : '';
      } catch {
        return '';
      }
    })(),
  });
  const architecture = truth.architecture;

  // Hardware-id seed — anchored ONLY on non-volatile structural entropy:
  //  - coarse GPU capability class (texture size / shader precision / extension count),
  //    NOT the spoofable vendor/renderer strings
  //  - CPU cores, bucketed device memory, colour depth/gamut
  //  - 8x8 quantized canvas digest (farbling-tolerant), isolated font metrics and a fixed
  //    transcendental math anchor
  //  - an explicit audio stability class from the dual-render comparison
  // Deliberately EXCLUDED: raw canvas SHA-256, raw audio float/hash, raw GPU strings,
  // the resolved architecture (a UA-CH/platform claim), screen size, DPR, UA and touch.
  const { fontMetric, mathAnchor } = stableStructuralAnchors();
  // Coarse digest is ALWAYS preferred over the exact canvas SHA-256 for the seed/matching;
  // this is the farbling-tolerant anchor used when canvasNoise/audioNoise flags are set.
  const coarseCanvas = canvas.coarseHash ?? 'na';
  const audioClass = audioStabilityClass(audio);
  const memoryBucket =
    deviceMemoryGb === null
      ? 'na'
      : deviceMemoryGb >= 8
      ? '8+'
      : deviceMemoryGb >= 4
      ? '4'
      : deviceMemoryGb >= 2
      ? '2'
      : deviceMemoryGb >= 1
      ? '1'
      : 'lt1';
  const fingerprintSeed = [
    gpuClass,
    String(colorDepth),
    String(cpuCores ?? 'na'),
    memoryBucket,
    colorGamut,
    coarseCanvas,
    audioClass,
    fontMetric,
    mathAnchor,
  ].join('||');

  const fullDigest = await sha256Hex(fingerprintSeed);
  const hardwareId = `hwid_${fullDigest.slice(0, 20)}`;

  try {
    localStorage.setItem(STORAGE_KEYS.HARDWARE_ID, hardwareId);
  } catch {
    // Ignore storage block
  }

  // Four-state GPU observation from explicit identifiers only (canonical resolver in
  // specInvariants.ts). A masked/unavailable extension is NEVER promoted to VM/software proof,
  // and SwiftShader maps to `software_or_virtual` without setting any VM verdict.
  const gpuObservation = resolveGpuObservation(gpuVendor, gpuRenderer, gpuClass);

  return {
    hardwareId,
    gpuVendor,
    gpuRenderer,
    maxTextureSize,
    gpuClass,
    gpuObservation,
    canvasHash,
    audioHash,
    cpuCores,
    deviceMemoryGb,
    colorDepth,
    maxTouchPoints,
    hdrSupported,
    colorGamut,
    architecture,
    architectureSource: truth.architectureSource,
    claimedArchitecture: truth.claimedArchitecture,
    archUaMismatch: truth.archUaMismatch,
    osUaMismatch: truth.osUaMismatch,
    hostOs: truth.hostOs,
    engine: truth.engine,
    engineErrorLength: truth.engineErrorLength,
    gpuArchFamily: truth.gpuArchFamily,
    canvasNoise: canvas.noise,
    audioNoise: audio.noise,
    canvasCoarseHash: canvas.coarseHash,
  };
}

/**
 * Virtual machine & OS integrity verdict.
 */
export interface VmAndIntegritySignals {
  isVirtualMachine: boolean;
  isOsTampered: boolean;
  vmReason: string;
  /** Phase 3 — mobile emulator / simulator verdict. */
  emulatorDetected: boolean;
  /** Phase 3 — evidence for the emulator verdict ('' when none). */
  emulatorReason: string;
  gpuVendor: string;
  gpuRenderer: string;
}

/**
 * Extra context for the Phase 3 emulator / cloud-container rules.
 * Optional so the existing two-argument call sites keep working.
 */
export interface VmDetectionContext {
  /** `BrowserDeviceInfo.screenResolution`, e.g. `1920 x 1080`. */
  screenResolution?: string;
  /** Result of the ISP classification in `evaluateSecuritySignals`. */
  datacenterAsn?: boolean;
}

/**
 * Runtime host of the page. This is an environment label, never a bot verdict.
 * Fingerprint Pro makes the same split between `developer_tools` and `bot`.
 */
export type AutomationEnvironment = 'none' | 'electron' | 'ide_webview' | 'headless_shell' | 'vm';

/**
 * Bot & automation verdict.
 *
 * Three independent axes, exactly like Fingerprint Pro's server response:
 *   bot                   → is the traffic automated? (`isBot`)
 *   developerTools        → is a CDP / DevTools bridge attached? (informational)
 *   automationEnvironment → which host is the page running inside?
 *
 * A CDP bridge alone is NOT proof of a bot: Electron apps, IDE webviews (VS Code,
 * Cursor, OpenCode) and anyone with DevTools open expose it while a real person is
 * driving the session. Only an automation UA, the WebDriver handshake, a spinning
 * runtime binding, or stealth-plugin artifacts prove automation on their own.
 */
export interface BotAutomationSignals {
  isBot: boolean;
  isHeadless: boolean;
  botReason: string;
  webdriver: boolean;
  cdpDetected: boolean;
  botSignals?: string[];
  /** True when only ambiguous environment quirks were found. Never a bot verdict. */
  botSuspicion?: boolean;
  /** CDP Runtime domain serialization leak: developer-tools evidence, not a verdict. */
  cdpRuntimeLeak?: boolean;
  /** Stealth plugin (puppeteer-extra / playwright-stealth) artifacts detected. */
  stealthPluginDetected?: boolean;
  /** A CDP / DevTools bridge is attached to this page (informational, not a threat). */
  developerTools?: boolean;
  /** Host runtime: `none`, `electron`, `ide_webview`, `headless_shell` or `vm`. */
  automationEnvironment?: AutomationEnvironment;
  /**
   * 0–1 confidence that a real person is driving this runtime. Recomputed on EVERY call
   * after the dwell window — static geometry alone can never reach the human tier; only
   * genuine, trusted pointer/keyboard/scroll/touch evidence can.
   */
  humanCorroboration?: number;
  /** Passive isTrusted physical-interaction evidence (pointer/touch/scroll/keyboard). */
  interactionEvidence?: string[];
  /** True when a CDP bridge was escalated to a bot because no trusted human input arrived. */
  corroboratedCdpEscalation?: boolean;
  /** The bridge artifacts that fed the corroborated escalation (telemetry/attribution). */
  cdpBridgeEvidence?: string[];
  /** Passive inspector probe results — informational input for `inspector_state`. */
  inspectorProbes?: InspectorProbes;
}

/**
 * Stable confidence label for the incognito verdict.
 *
 * 'high'   — the verdict came from a deterministic probe or from two corroborating
 *            physics probes, so it may be reported as incognito.
 * 'low'    — inconclusive / deadband / fail-open / probe-error. Such a result is
 *            ALWAYS mapped to `incognito === false` by every consumer.
 */
export type IncognitoConfidence = 'high' | 'low';

/**
 * Incognito / private-browsing verdict produced by the multi-engine physics probe.
 *
 * This is the one authoritative, per-tab-session verdict. It is cached in
 * sessionStorage (versioned key) and returned verbatim on later loads of the same
 * tab, so no ephemeral context — touch, geometry, language, a first identify write —
 * can ever re-derive or flip it.
 */
/** Jargon-free method labels — storage APIs, probe internals and ratios never leak. */
const METHOD_PRIVATE_STORAGE = 'private-storage-detected';
const METHOD_STANDARD_STORAGE = 'standard-storage';
const METHOD_INCONCLUSIVE = 'storage-check-inconclusive';

/**
 * Additive, flag-gated incognito probe diagnostics. Every field beyond `enabled` is
 * nullable so a partially observed probe still yields a valid record. This is a
 * READ-ONLY mirror of values the probe already computes — it never feeds the verdict,
 * the risk score or any downstream decision.
 */
export interface IncognitoDiagnostics {
  enabled: boolean;
  engine: string | null;
  method: string | null;
  confidence: IncognitoConfidence | null;
  isPrivate: boolean | null;
  quotaBytes: number | null;
  headroomGiB: number | null;
  idbDurabilityRatio: number | null;
  idbHighVariance: boolean | null;
  opfsFlushMs: number | null;
  persistedStorageGrant: boolean | null;
  isolatedContextVeto: boolean | null;
  sessionLockHit: boolean | null;
  lowConfidenceVeto: boolean | null;
  clientReportedIncognito: boolean | null;
  serverWouldVeto: boolean | null;
}

/**
 * Module-level flag gate for additive incognito diagnostics. True only when the page
 * URL carries `intelDiag=1` or this tab's sessionStorage holds `intel_diag_v1 = '1'`.
 * Never throws: a blocked or hostile scope simply means "off", the default everywhere.
 */
export function isIncognitoDiagnosticsEnabled(): boolean {
  try {
    if (typeof window !== 'undefined' && window.location) {
      const search = window.location.search;
      if (typeof search === 'string' && search.includes('intelDiag=1')) return true;
    }
  } catch {
    // Scope access denied — diagnostics stay off.
  }
  try {
    if (typeof sessionStorage !== 'undefined' && sessionStorage.getItem('intel_diag_v1') === '1') {
      return true;
    }
  } catch {
    // Storage blocked — diagnostics stay off.
  }
  return false;
}

export interface IncognitoDetectionResult {
  isPrivate: boolean;
  browserName: string;
  method: string;
  /** Stable high/low label. Low confidence can never produce `incognito: true`. */
  confidence: IncognitoConfidence;
  /** True when the Chromium IndexedDB ratio spread was too wide to trust. */
  idbHighVariance?: boolean;
  quotaBytes: number | null;
  headroomGiB: number | null;
  idbDurabilityRatio: number | null;
  opfsFlushMs: number | null;
  /** Weak Chromium-only off-the-record context hints; telemetry, never a verdict input. */
  storagePrivateHints?: boolean;
  /** Optional, flag-gated diagnostic mirror. No decision path ever reads this. */
  diagnostics?: IncognitoDiagnostics;
}

/**
 * Module-level cache for the storage-physics probe. The probe is started eagerly at
 * module load (bottom of this file) so it runs on an idle main thread; every later call
 * — App mount, evaluateSecuritySignals, identifyCurrentVisitor — reuses the same promise.
 */
let cachedIncognitoPromise: Promise<IncognitoDetectionResult> | null = null;

const GIB_BYTES = 1024 * 1024 * 1024;

/**
 * Engine fingerprint probe.
 *
 * `Number.prototype.toFixed` rejects a negative digit count with an engine-specific
 * RangeError message whose length identifies the JavaScript engine:
 * 51 = V8, 25 = SpiderMonkey, 44/43 = JavaScriptCore.
 */
function getEngineErrorLength(): number {
  // Delegated to the shared `(-1).toFixed(-1)` probe (51 V8 / 25 SpiderMonkey /
  // 43-44 JavaScriptCore). Kept as a thin wrapper so every caller shares one path.
  return probeEngineLength();
}

/**
 * Returns true when `property` on `proto` is still a native accessor.
 * An overridden getter (anti-detect proxy) fails the `[native code]` check.
 */
function isNativeAccessor(proto: object | undefined, property: string): boolean {
  try {
    if (!proto) return true;
    const descriptor = Object.getOwnPropertyDescriptor(proto, property);
    if (!descriptor) return true;
    if (typeof descriptor.get !== 'function') return false;
    return /\[native code\]/.test(Function.prototype.toString.call(descriptor.get));
  } catch {
    return true;
  }
}

/**
 * Parses the width out of a `"1920 x 1080"` style screen resolution.
 * Returns 0 for `Unavailable` / unparseable values.
 */
function parseScreenResolutionWidth(resolution: string | undefined): number {
  if (!resolution) return 0;
  const match = /(\d+)\s*[x×]\s*(\d+)/i.exec(resolution);
  if (match) {
    const width = Number(match[1]);
    return Number.isFinite(width) && width > 0 ? width : 0;
  }
  const single = Number(resolution);
  return Number.isFinite(single) && single > 0 ? single : 0;
}

/** Phase 3 — emulator / software-rasteriser GPU signatures. */
const EMULATOR_GPU_PATTERN =
  /android emulator opengl es translator|goldfish|ranchu|bluestacks|nox|ldplayer|memu|genymotion|virgl|apple software renderer|swiftshader|llvmpipe/i;

/** Phase 3 — software renderers that imply a container / virtual display. */
const SOFTWARE_RENDERER_PATTERN =
  /android emulator opengl es translator|swiftshader|llvmpipe|virgl|apple software renderer|basic render driver/i;

/** x86 / desktop platform strings that a real Android handset can never report. */
const NON_ARM_ANDROID_PLATFORM_PATTERN = /Linux x86|x86_64|i686|Win32|Win64|MacIntel/i;

/** Phase 3 — emulator / iOS-simulator GPU renderer signatures (same list the server uses). */
const EMULATOR_GPU_SIGNATURE_PATTERN =
  /Android Emulator OpenGL ES Translator|Goldfish|Ranchu|BlueStacks|Nox|LDPlayer|MEmu|Genymotion|VirGL|Apple Software Renderer/i;

/** Any iOS device User-Agent (iPhone / iPad / iPod, including iPadOS 13+ desktop UA). */
const IOS_DEVICE_UA_PATTERN = /(iPhone|iPad|iPod)/i;

/** Desktop platforms an iOS simulator is hosted on. */
const IOS_FOREIGN_PLATFORM_PATTERN = /Linux|Win32|Win64/i;

/** Phones that never legitimately pair with a desktop-width screen. */
const IPHONE_OR_IPOD_UA_PATTERN = /(iPhone|iPod)/i;

/**
 * Inputs for the client emulator probe. Every field is optional: missing values fall
 * back to the live `navigator` values, which keeps the helper usable from tests.
 */
export interface EmulatorEvidenceInput {
  userAgent?: string;
  platform?: string;
  maxTouchPoints?: number;
  gpuVendor?: string;
  gpuRenderer?: string;
  screenResolution?: string;
}

/** Verdict + short human evidence for the mobile emulator / simulator probe. */
export interface EmulatorEvidence {
  detected: boolean;
  reason: string;
}

/**
 * Mobile emulator / iOS simulator evidence derived from real client values.
 *
 * The predicates are the same ones the server applies to the payload, so the client
 * verdict and the server verdict cannot drift apart:
 * 1. Android UA on an x86 / desktop platform (a handset never reports one).
 * 2. Android UA reporting zero touch points.
 * 3. Emulator / simulator GPU renderer string.
 * 4. iOS UA on a foreign platform, or on any platform with zero touch points —
 *    iPadOS 13+ legitimately reports `MacIntel` WITH real touch points and stays clean.
 * 5. iPhone / iPod UA on a desktop-width (>= 1000 px) screen.
 *
 * Never throws and reads hostile `navigator` proxies through `try`/`catch`.
 */
export function detectEmulatorEvidence(input: EmulatorEvidenceInput = {}): EmulatorEvidence {
  let liveUserAgent = '';
  let liveTouchPoints = 0;
  try {
    if (typeof navigator !== 'undefined') {
      liveUserAgent = navigator.userAgent || '';
      liveTouchPoints =
        typeof navigator.maxTouchPoints === 'number' ? Math.max(0, navigator.maxTouchPoints) : 0;
    }
  } catch {
    // Ignore hostile navigator proxies.
  }

  const ua = typeof input.userAgent === 'string' ? input.userAgent : liveUserAgent;
  const platform = (input.platform || '').trim();
  const maxTouchPoints =
    typeof input.maxTouchPoints === 'number'
      ? Math.max(0, input.maxTouchPoints)
      : liveTouchPoints;
  const vendor = (input.gpuVendor || '').trim();
  const renderer = (input.gpuRenderer || '').trim();
  const gpuSignature = `${vendor} ${renderer}`;

  const claimsAndroid = /Android/i.test(ua);
  const claimsIos = IOS_DEVICE_UA_PATTERN.test(ua);

  // 1 — Android UA backed by an x86 / desktop platform: the emulator CPU profile.
  if (claimsAndroid && NON_ARM_ANDROID_PLATFORM_PATTERN.test(platform)) {
    return {
      detected: true,
      reason: `Android user-agent on desktop ${platform} (emulator CPU profile)`,
    };
  }

  // 2 — Android UA without a single touch point: emulated input layer.
  if (claimsAndroid && maxTouchPoints === 0) {
    return {
      detected: true,
      reason: 'Android user-agent reporting zero touch points (emulated input layer)',
    };
  }

  // 3 — Emulator / simulator renderers expose themselves through WebGL.
  if (EMULATOR_GPU_SIGNATURE_PATTERN.test(gpuSignature)) {
    return {
      detected: true,
      reason: `Emulator GPU renderer (${renderer || vendor || 'masked renderer'})`,
    };
  }

  // 4 — iOS UA on a non-Apple platform, or without touch points. iPadOS 13+ reports
  // `MacIntel` WITH touch points, so that legitimate combination is never flagged.
  if (claimsIos) {
    if (IOS_FOREIGN_PLATFORM_PATTERN.test(platform)) {
      return {
        detected: true,
        reason: `iOS user-agent on ${platform} platform (simulator host)`,
      };
    }
    if (maxTouchPoints === 0) {
      return {
        detected: true,
        reason: `iOS user-agent on ${platform || 'desktop'} with zero touch points (simulator)`,
      };
    }
  }

  // 5 — iPhone / iPod UA on a desktop-width screen (never applied to Android).
  const screenWidth = parseScreenResolutionWidth(input.screenResolution);
  if (IPHONE_OR_IPOD_UA_PATTERN.test(ua) && screenWidth >= 1000) {
    return {
      detected: true,
      reason: `iPhone user-agent on a ${screenWidth}px desktop-width screen`,
    };
  }

  return { detected: false, reason: '' };
}

/**
 * Virtual machine / hypervisor + OS identity integrity detection.
 * Matches WebGL vendor/renderer strings against known hypervisor GPUs, then
 * cross-checks the claimed User-Agent OS against the platform, GPU and the
 * native Navigator accessors (anti-detect proxy detection).
 *
 * Phase 3 additionally classifies mobile emulators / simulators and
 * cloud-container (masked GPU on a datacenter ASN) environments.
 */
export function detectVmAndIntegrity(
  gpuVendor: string,
  gpuRenderer: string,
  context?: VmDetectionContext
): VmAndIntegritySignals {
  const vendor = (gpuVendor || '').trim();
  const renderer = (gpuRenderer || '').trim();
  const signature = `${vendor} ${renderer}`.toLowerCase();

  const vmSignatures: Array<{ pattern: RegExp; label: string }> = [
    { pattern: /vmware|svga3d/, label: 'VMware SVGA3D Virtual GPU' },
    { pattern: /virtualbox|vbox/, label: 'Oracle VirtualBox Virtual GPU' },
    { pattern: /parallels/, label: 'Parallels Virtual GPU' },
    { pattern: /qemu|virtio|virgl|bochs/, label: 'QEMU / VirtIO Virtual GPU' },
    {
      pattern: /hyper-v|microsoft remote display/,
      label: 'Microsoft Hyper-V Remote Display Adapter',
    },
    { pattern: /citrix|xen/, label: 'Citrix / Xen Virtual GPU' },
    {
      pattern: /llvmpipe|softpipe|mesa offscreen|software rasterizer/,
      label: 'Mesa / LLVMpipe Software Rasterizer',
    },
  ];

  let isVirtualMachine = false;
  let vmReason = '';

  for (const rule of vmSignatures) {
    if (rule.pattern.test(signature)) {
      isVirtualMachine = true;
      vmReason = rule.label;
      break;
    }
  }

  // Microsoft Basic Render Driver is only suspicious on constrained hardware
  // (a software fallback on a real workstation is legitimate).
  if (!isVirtualMachine && signature.includes('microsoft basic render')) {
    let cpuCores: number | null = null;
    let screenWidth = 0;
    let screenHeight = 0;
    try {
      cpuCores =
        typeof navigator !== 'undefined' && typeof navigator.hardwareConcurrency === 'number'
          ? navigator.hardwareConcurrency
          : null;
      screenWidth =
        typeof window !== 'undefined' && window.screen ? Number(window.screen.width) : 0;
      screenHeight =
        typeof window !== 'undefined' && window.screen ? Number(window.screen.height) : 0;
    } catch {
      // Ignore hostile hardware proxies.
    }
    const tinyScreen =
      (screenWidth === 800 && screenHeight === 600) ||
      (screenWidth === 1024 && screenHeight === 768);
    if ((cpuCores !== null && cpuCores <= 2) || tinyScreen) {
      isVirtualMachine = true;
      vmReason = 'Microsoft Basic Render Driver on constrained virtual hardware';
    }
  }

  let ua = '';
  let platform = '';
  try {
    if (typeof navigator !== 'undefined') {
      ua = navigator.userAgent || '';
      platform = navigator.platform || '';
    }
  } catch {
    // Ignore hostile navigator proxies.
  }

  // ---------------------------------------------------------------------------
  // Phase 3 — mobile emulator / simulator and cloud-container classification.
  // It only reads navigator/screen values already available above and never
  // throws, so the existing VM / OS-tamper contract is unchanged.
  // ---------------------------------------------------------------------------
  let maxTouchPoints = 0;
  try {
    if (typeof navigator !== 'undefined' && typeof navigator.maxTouchPoints === 'number') {
      maxTouchPoints = Math.max(0, navigator.maxTouchPoints);
    }
  } catch {
    // Ignore hostile navigator proxies.
  }

  let viewportWidth = parseScreenResolutionWidth(context?.screenResolution);
  if (viewportWidth <= 0) {
    try {
      viewportWidth =
        typeof window !== 'undefined' && window.screen ? Number(window.screen.width) || 0 : 0;
    } catch {
      viewportWidth = 0;
    }
  }

  const mobileClaim = /Android|iPhone|iPad|iPod/i.exec(ua);
  const claimsMobile = mobileClaim !== null;
  // iPadOS reports platform `MacIntel` with real touch points; that is a genuine
  // tablet, not a desktop platform masquerading as a phone.
  const desktopPlatform =
    /^(Win32|Win64|MacIntel|Linux x86_64|Linux i686)$/i.test(platform) &&
    !(/^MacIntel$/i.test(platform) && maxTouchPoints > 0);

  let emulatorDetected = false;
  let emulatorReason = '';

  // A mobile UA is only treated as an emulator with hard evidence: a desktop platform claim,
  // or zero touch points on a desktop-class viewport. A lone zero-touch report from a quirky
  // WebView is not enough (real phones occasionally report 0), so normal phones stay clean.
  const zeroTouchOnWideViewport = maxTouchPoints === 0 && viewportWidth >= 1000;
  if (claimsMobile && (desktopPlatform || zeroTouchOnWideViewport)) {
    emulatorDetected = true;
    emulatorReason = desktopPlatform
      ? `Mobile User-Agent (${mobileClaim ? mobileClaim[0] : 'mobile'}) with a desktop platform (${platform})`
      : `Mobile User-Agent with a ${viewportWidth}px desktop-class viewport and zero touch points`;
  }

  if (claimsMobile && EMULATOR_GPU_PATTERN.test(signature)) {
    emulatorDetected = true;
    emulatorReason = `Mobile User-Agent rendered by an emulator GPU (${renderer || vendor || 'masked renderer'})`;
  }

  if (emulatorDetected) {
    // An emulated mobile runtime is reported as an emulator rather than as a
    // desktop hypervisor, so the two Phase 3 tiles never double-count.
    isVirtualMachine = false;
    vmReason = emulatorReason;
  } else if (!isVirtualMachine && !claimsMobile) {
    // Cloud container: a desktop OS that hides its GPU while sitting on a
    // datacenter ASN, or falls back to a software renderer.
    const maskedGpu =
      isMaskedOrUnavailableGpu(vendor, renderer) ||
      /^unknown$/i.test(vendor) ||
      /^unknown$/i.test(renderer);
    // SwiftShader / LLVMpipe are ordinary software-rendered graphics (f7d6900), never hard VM
    // proof on their own. Only a datacenter ASN may still promote a masked GPU to a cloud VM.
    const softwareRenderer =
      SOFTWARE_RENDERER_PATTERN.test(signature) && !/swiftshader|llvmpipe/i.test(signature);
    if (maskedGpu && (context?.datacenterAsn === true || softwareRenderer)) {
      isVirtualMachine = true;
      vmReason =
        context?.datacenterAsn === true
          ? 'Masked WebGL vendor on a datacenter ASN (cloud container)'
          : 'Masked WebGL vendor with a software renderer (cloud container)';
    }
  }

  const claimsWindows = /Windows NT/i.test(ua);
  const claimsMac = /Macintosh|Mac OS X/i.test(ua);
  const claimsLinux = /Linux/i.test(ua) && !/Android/i.test(ua);

  const osMismatches: string[] = [];
  if (claimsWindows && /MacIntel|Linux|iPhone|iPad/i.test(platform)) {
    osMismatches.push(`Windows User-Agent with ${platform || 'unknown'} platform`);
  }
  if (claimsMac && /Win32|Win64|Linux/i.test(platform)) {
    osMismatches.push(`macOS User-Agent with ${platform || 'unknown'} platform`);
  }
  if (claimsLinux && /Win32|Win64|MacIntel/i.test(platform)) {
    osMismatches.push(`Linux User-Agent with ${platform || 'unknown'} platform`);
  }
  if ((claimsWindows || claimsLinux) && /apple m[1-9]|apple gpu/.test(signature)) {
    osMismatches.push('Apple Silicon GPU renderer on a non-Apple User-Agent');
  }
  if (claimsMac && /direct3d|d3d11/.test(signature)) {
    osMismatches.push('Direct3D renderer on a macOS User-Agent');
  }

  const navProto = typeof Navigator !== 'undefined' ? Navigator.prototype : undefined;
  if (!isNativeAccessor(navProto, 'userAgent') || !isNativeAccessor(navProto, 'platform')) {
    osMismatches.push('Navigator prototype getter overridden (Anti-detect proxy)');
  }

  const isOsTampered = osMismatches.length > 0;
  if (!vmReason) {
    vmReason = isOsTampered ? osMismatches[0] : 'Physical GPU & Consistent OS Identity';
  }

  return {
    isVirtualMachine,
    isOsTampered,
    vmReason,
    emulatorDetected,
    emulatorReason,
    gpuVendor: vendor,
    gpuRenderer: renderer,
  };
}

/**
 * Stealth-plugin and CDP serialization probe.
 *
 * `puppeteer-extra-plugin-stealth` and `playwright-stealth` hide the WebDriver flag, so the
 * only reliable evidence left is the *side effect* of the patching itself: rewritten native
 * getters, a patched `Function.prototype.toString`, proxy-backed `navigator` objects, a
 * same-origin iframe whose `contentWindow` leaks the parent, and the CDP Runtime domain
 * serializing an Error through `Error.prepareStackTrace` (a protocol-level leak that page
 * JavaScript cannot patch away).
 *
 * Single ambiguous artifacts are recorded but never sufficient; two independent artifacts or
 * a definitive one (iframe leak, prepareStackTrace invocation) raise the flag.
 */
export interface StealthArtifacts {
  /** Informational serialization artifacts (may be engine-dependent). Telemetry only. */
  cdpRuntimeLeak: boolean;
  /**
   * STRONG protocol-level proof: a CDP Runtime.enable leak observed by TWO independent
   * protocol probes. Only this — never `cdpRuntimeLeak`, a webdriver getter descriptor,
   * a cross-realm getter source diff or an Error.prototype.name preview — may escalate a
   * real browser to a CDP/stealth-automation bot.
   */
  cdpRuntimeProof: boolean;
  stealthPluginDetected: boolean;
  stealthReasons: string[];
}

/** Trusted-input counters. Installed once; a real person accumulates input, a script does not. */
let trustedPointerEvents = 0;
let trustedKeyEvents = 0;
let trustedInputTrackerInstalled = false;
let lastTrustedInputAt = 0;

/**
 * Phase 2 interaction gate. Purely passive `isTrusted` physical-interaction evidence:
 * pointer kinematics, touch, scroll, keyboard cadence and Playwright mark-target touches.
 * None of it blocks identify — the collector fires on load and this data accumulates in
 * the background for later verdict refinement inside the locked 65 s envelope window.
 */
interface InteractionCounters {
  pointerMoves: number;
  pointerDowns: number;
  touchStarts: number;
  /** Trusted touchmove/touchend counts — a real touch has phases, a script often does not. */
  touchMoves: number;
  touchEnds: number;
  /** Trusted touch coordinates from touchstart/touchmove — a real drag changes position. */
  touchPositions: Array<{ x: number; y: number }>;
  /** Trusted intervals between successive touchstarts — human tap cadence. */
  touchIntervalsMs: number[];
  scrolls: number;
  keyDowns: number;
  keyIntervalsMs: number[];
  /** Trusted pointer-move coordinates — a real trail has varying positions, a script does not. */
  pointerPositions: Array<{ x: number; y: number }>;
  playwrightMarkTargets: number;
  frameworkGlobals: string[];
  firstInteractionAt: number;
  lastInteractionAt: number;
}
const interactionCounters: InteractionCounters = {
  pointerMoves: 0,
  pointerDowns: 0,
  touchStarts: 0,
  touchMoves: 0,
  touchEnds: 0,
  touchPositions: [],
  touchIntervalsMs: [],
  scrolls: 0,
  keyDowns: 0,
  keyIntervalsMs: [],
  pointerPositions: [],
  playwrightMarkTargets: 0,
  frameworkGlobals: [],
  firstInteractionAt: 0,
  lastInteractionAt: 0,
};
let lastKeyDownAt = 0;
let lastTouchStartAt = 0;

/** Passive inspector probes. Results are reported for `inspector_state`, never bot proof. */
export interface InspectorProbes {
  errorPrototypeNamePreviewReads: number;
  crossRealmGetterSourceMismatch: boolean;
  crossRealmNativeDescriptor: boolean;
  inspectorProbeError: string;
}
export const inspectorProbes: InspectorProbes = {
  errorPrototypeNamePreviewReads: 0,
  crossRealmGetterSourceMismatch: false,
  crossRealmNativeDescriptor: false,
  inspectorProbeError: '',
};

/** Snapshot of accumulated physical-interaction evidence (non-blocking, never mutates). */
export function getInteractionEvidence(): string[] {
  const evidence: string[] = [];
  if (interactionCounters.pointerMoves >= 3) {
    evidence.push(`pointer-kinematics:${interactionCounters.pointerMoves}`);
  }
  if (interactionCounters.touchStarts > 0) evidence.push(`touch:${interactionCounters.touchStarts}`);
  if (interactionCounters.touchMoves > 0) evidence.push(`touch-move:${interactionCounters.touchMoves}`);
  if (interactionCounters.touchEnds > 0) evidence.push(`touch-end:${interactionCounters.touchEnds}`);
  const touchCadence = interactionCounters.touchIntervalsMs.filter((ms) => ms > 0 && ms < 2000);
  if (touchCadence.length >= 2) evidence.push(`touch-cadence:${touchCadence.length}`);
  if (interactionCounters.scrolls > 0) evidence.push(`scroll:${interactionCounters.scrolls}`);
  if (interactionCounters.keyDowns > 0) evidence.push(`keyboard:${interactionCounters.keyDowns}`);
  const cadence = interactionCounters.keyIntervalsMs.filter((ms) => ms > 0 && ms < 2000);
  if (cadence.length >= 2) evidence.push(`keyboard-cadence:${cadence.length}`);
  if (interactionCounters.playwrightMarkTargets > 0) {
    evidence.push(`playwright-mark-target:${interactionCounters.playwrightMarkTargets}`);
  }
  if (interactionCounters.frameworkGlobals.length > 0) {
    evidence.push(`framework-globals:${interactionCounters.frameworkGlobals.join(',')}`);
  }
  return evidence;
}

/**
 * True only for GENUINE human input. All counters below are fed exclusively by
 * `isTrusted` events, and CDP-dispatched synthetic Playwright input additionally trips the
 * mark-target / framework-global guards, so a driven runtime can never earn human credit.
 * Geometry, languages, a visible document and a hardware GPU are deliberately absent —
 * a headless browser with a normal desktop UA manufactures all of them.
 */
export function hasGenuineHumanInput(): boolean {
  const c = interactionCounters;
  // An injected automation library is present: any input seen this session is attributable
  // to the driver, not to a person, regardless of how natural its cadence looked.
  if (c.frameworkGlobals.length > 0 || c.playwrightMarkTargets > 0) return false;
  // Trusted touch input is genuine on a phone exactly as pointer/keyboard input is on a
  // desktop. A completed tap (touchstart -> touchend), a drag with realistic movement, a
  // human tap cadence, or even a single in-flight trusted touchstart all count. CDP-
  // dispatched synthetic touch is excluded by the framework/mark-target guard above, so a
  // real person is never asked to "prove" their touch with desktop-only pointer trails.
  if (c.touchStarts > 0 || c.touchEnds > 0) return true;
  if (c.touchMoves >= 2 && c.touchPositions.length >= 2) {
    const first = c.touchPositions[0];
    const last = c.touchPositions[c.touchPositions.length - 1];
    if (Math.abs(first.x - last.x) + Math.abs(first.y - last.y) >= 12) return true;
    const distinct = new Set(
      c.touchPositions.map((p) => `${Math.round(p.x / 4)}:${Math.round(p.y / 4)}`)
    ).size;
    if (distinct >= 3) return true;
  }
  const humanTouchIntervals = c.touchIntervalsMs.filter((ms) => ms >= 40 && ms < 1500);
  if (humanTouchIntervals.length >= 1) return true;
  if (c.scrolls > 0) return true;
  const humanIntervals = c.keyIntervalsMs.filter((ms) => ms >= 40 && ms < 1500);
  if (c.keyDowns >= 3 && humanIntervals.length >= 2) return true;
  if (c.pointerMoves >= 3 && c.pointerPositions.length >= 3) {
    const first = c.pointerPositions[0];
    const last = c.pointerPositions[c.pointerPositions.length - 1];
    if (Math.abs(first.x - last.x) + Math.abs(first.y - last.y) >= 12) return true;
    const distinct = new Set(
      c.pointerPositions.map((p) => `${Math.round(p.x / 4)}:${Math.round(p.y / 4)}`)
    ).size;
    if (distinct >= 3) return true;
  }
  return false;
}

/** Shape of the fresh human-corroboration measurement returned by `measureHumanCorroboration`. */
export interface HumanCorroborationResult {
  score: number;
  checks: string[];
  /** Any isTrusted input at all (including raw synthetic CDP input). */
  trustedInput: boolean;
  /** Genuine, human-attributable input after the dwell window. */
  genuineInput: boolean;
}

/** Passive scan for CDP / WebDriver / framework bindings on the two global objects. */
function scanCdpGlobals(): boolean {
  for (const target of [typeof window !== 'undefined' ? window : undefined, typeof document !== 'undefined' ? document : undefined]) {
    if (!target) continue;
    try {
      for (const key of Object.keys(target as unknown as Record<string, unknown>)) {
        if (CDP_GLOBAL_KEY_PATTERN.test(key)) return true;
      }
    } catch {
      // Hostile proxies over the global object are inconclusive, not evidence.
    }
  }
  return false;
}

/** A genuine docked DevTools layout (a large outer/inner viewport delta). */
function hasDockedDevToolsLayout(): boolean {
  try {
    return (
      typeof window !== 'undefined' &&
      window.outerHeight > 0 &&
      window.innerHeight > 0 &&
      window.outerHeight - window.innerHeight > 200
    );
  } catch {
    return false;
  }
}

/** `window.chrome` present on a browser that can never legitimately expose it. */
function detectInjectedChromeInNonChromium(ua?: string): boolean {
  try {
    const userAgent = ua ?? (typeof navigator !== 'undefined' ? navigator.userAgent || '' : '');
    if (!userAgent) return false;
    const chromium = /Chrome\/|Chromium\/|Edg\/|OPR\/|CriOS\//i.test(userAgent);
    const nonChromium = /Firefox\/|FxiOS\/|Version\/[^\s]+\s+Safari|iPhone|iPad|iPod/i.test(userAgent);
    if (chromium || !nonChromium) return false;
    const chromeObject = (window as unknown as { chrome?: unknown }).chrome;
    return Boolean(chromeObject && typeof chromeObject === 'object');
  } catch {
    return false;
  }
}

/**
 * STRONG CDP / runtime-bridge proof only. These artifacts are the bridge PRESENCE set that
 * the uncorroborated-after-dwell rule consults, so every entry must be impossible on an
 * ordinary real browser. Deliberately EXCLUDED (all are weak, engine-dependent artifacts
 * that fire naturally on Android Chrome / other engines and must never escalate anywhere):
 *   - `webdriverGetterTampered` / non-native or cross-realm getter source differences
 *   - the `Error.prototype.name` / `console.debug` serialization preview
 *   - informational `cdpRuntimeLeak` without a second independent protocol probe
 *   - `window.chrome` in a non-Chromium runtime (an environment quirk, not a CDP bridge)
 * What qualifies: real `__playwright__*` / `$cdc_*` / `__webdriver*` binding globals, a
 * playwright mark-target listener, or a CDP Runtime.enable leak corroborated by a second
 * independent protocol probe (`cdpRuntimeProof`). Software GPUs are never included.
 */
function collectCdpBridgeEvidence(stealth: StealthArtifacts, _ua?: string): string[] {
  const evidence: string[] = [];
  if (stealth.cdpRuntimeProof) {
    evidence.push('CDP Runtime.enable leak corroborated by an independent protocol probe');
  }
  if (interactionCounters.frameworkGlobals.length > 0) {
    evidence.push(`automation globals (${interactionCounters.frameworkGlobals.slice(0, 3).join(', ')})`);
  }
  if (interactionCounters.playwrightMarkTargets > 0) evidence.push('playwright mark-target listener');
  if (scanCdpGlobals()) evidence.push('CDP/WebDriver binding exposed on window or document');
  return evidence;
}

/* -------------------------------------------------------------------------- */
/* Collector probe name -> canonical server reason id                          */
/* -------------------------------------------------------------------------- */

/** Canonical ids shared with `src/lib/verdict.ts` and the server evidence gate. */
export const COLLECTOR_CDP_REASON_IDS = {
  runtimeEnable: 'cdp.runtime.enable',
  /** STRONG two-probe proof only — the uncorroborated hook alone never maps here. */
  runtimeProof: 'cdp.runtime.enable.empty_source',
  runtimeLeak: 'bot.cdp-runtime-leak',
  cdcBinding: 'cdc.global.binding',
  playwrightBinding: 'bot.playwright-binding',
  webdriverFlag: 'navigator.webdriver',
} as const;

/**
 * An `Error.prototype.name` preview is an engine-dependent, WEAK inspector artifact. It must
 * never be mapped to a CDP reason id, and must never become "CDP attached" anywhere.
 */
const WEAK_ERROR_NAME_PREVIEW_PATTERN = /error\.?prototype\.?name|errornamepreview|name.?preview/i;

/**
 * Map a human-readable collector probe name onto the canonical server reason id. Returns
 * `null` for weak/inconclusive probes. In particular a bare Error.name preview is ALWAYS
 * dropped: only a CDP Runtime.enable leak corroborated by the second independent protocol
 * probe (`cdpRuntimeProof`) may produce a CDP reason id.
 */
export function mapCollectorProbeToReasonId(probe: string | null | undefined): string | null {
  const name = (probe || '').trim();
  if (!name || WEAK_ERROR_NAME_PREVIEW_PATTERN.test(name)) return null;
  // A single, uncorroborated Runtime.enable hook is informational only. Check this BEFORE the
  // proof pattern: "un-corroborated" contains the word "corroborated".
  if (/uncorroborated/i.test(name)) return COLLECTOR_CDP_REASON_IDS.runtimeLeak;
  if (/independent protocol probe|preparestacktrace|runtimeproof|runtime\.enable\.empty_source|corroborated by/i.test(name)) {
    return COLLECTOR_CDP_REASON_IDS.runtimeProof;
  }
  if (/cdp.?runtime\.enable|cdpruntimeleak|runtime enable/i.test(name)) {
    return COLLECTOR_CDP_REASON_IDS.runtimeLeak;
  }
  if (/binding exposed on window or document|automation globals|\bcdc[_-]|\bcdc\.global|cdc global binding/i.test(name)) {
    return COLLECTOR_CDP_REASON_IDS.cdcBinding;
  }
  if (/playwright/i.test(name)) return COLLECTOR_CDP_REASON_IDS.playwrightBinding;
  if (/webdriver/i.test(name)) return COLLECTOR_CDP_REASON_IDS.webdriverFlag;
  return null;
}

/**
 * Bounded, non-blocking dwell: wait (at most `CDP_CORROBORATION_DWELL_MS`) for genuine
 * trusted input before finalizing an uncorroborated-CDP escalation. Returns immediately
 * as soon as a real person interacts, so legitimate Electron / IDE / DevTools sessions
 * keep their weight-0 developer-tools classification.
 */
async function awaitCdpCorroborationWindow(bridgePresent: boolean): Promise<boolean> {
  if (!bridgePresent || typeof window === 'undefined') return false;
  const elapsed = Date.now() - PAGE_SESSION_STARTED_AT;
  if (elapsed >= CDP_CORROBORATION_DWELL_MS) return true;
  const deadline = Date.now() + (CDP_CORROBORATION_DWELL_MS - elapsed);
  while (Date.now() < deadline) {
    if (hasGenuineHumanInput()) return false;
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
  }
  return true;
}

/** Framework globals scanned passively (presence only — no tampering with their values). */
const FRAMEWORK_GLOBAL_PATTERN =
  /^(__playwright|__pwInitScripts|__puppeteer|__selenium|__webdriver|cdc_|callPhantom|_phantom)/i;

const IDE_WEBVIEW_UA_PATTERN =
  /(?:^|[\s(])(?:Code|Cursor|OpenCode|Windsurf|VSCodium|vscode-webview)\/[\d.]+/i;

/**
 * Reads the host runtime from immutable facts (the user-agent string and the
 * `process.versions` object Electron exposes) without trusting any single getter.
 * Never throws; an unreachable scope degrades to `none`.
 */
export function detectAutomationEnvironment(
  ua?: string,
  gpuRenderer?: string
): { environment: AutomationEnvironment; electron: boolean; ideWebview: boolean; headlessShell: boolean } {
  const userAgent = ua ?? (typeof navigator !== 'undefined' ? navigator.userAgent || '' : '');
  // Reuse the canonical runtime facts so the UA token, process.versions.electron / .node and
  // host-app tokens all agree with the `runtime` / `host_app` / `client_type` payload fields.
  const facts = detectRuntimeFacts(userAgent);
  const electron = facts.electron;
  const ideWebview = facts.ideWebview || IDE_WEBVIEW_UA_PATTERN.test(userAgent);
  const headlessShell = facts.headlessShell;

  let environment: AutomationEnvironment = 'none';
  if (ideWebview) environment = 'ide_webview';
  else if (electron) environment = 'electron';
  else if (headlessShell) environment = 'headless_shell';
  else if (/swiftshader|llvmpipe|mesa offscreen/i.test((gpuRenderer || '').toLowerCase())) {
    // A software rasterizer is the signature of a GPU-less VM / container. Informational only.
    environment = 'vm';
  }

  return { environment, electron, ideWebview, headlessShell };
}

/** Starts the passive trusted-input tracker (idempotent, capture phase, never blocks). */
export function installTrustedInputTracker(): void {
  if (trustedInputTrackerInstalled || typeof window === 'undefined') return;
  trustedInputTrackerInstalled = true;
  const options: AddEventListenerOptions = { capture: true, passive: true };
  const stamp = (): number => {
    const now = Date.now();
    if (interactionCounters.firstInteractionAt === 0) interactionCounters.firstInteractionAt = now;
    interactionCounters.lastInteractionAt = now;
    lastTrustedInputAt = now;
    return now;
  };
  try {
    const onPointerDown = (event: Event): void => {
      if (!(event as PointerEvent).isTrusted) return;
      trustedPointerEvents += 1;
      interactionCounters.pointerDowns += 1;
      stamp();
    };
    const onPointerMove = (event: Event): void => {
      if (!(event as PointerEvent).isTrusted) return;
      interactionCounters.pointerMoves += 1;
      const pointer = event as PointerEvent;
      if (Number.isFinite(pointer.clientX) && Number.isFinite(pointer.clientY)) {
        interactionCounters.pointerPositions.push({ x: pointer.clientX, y: pointer.clientY });
        if (interactionCounters.pointerPositions.length > 24) {
          interactionCounters.pointerPositions.shift();
        }
      }
      stamp();
    };
    // A single physical touch fires capture listeners on BOTH window and document; dedupe
    // by event identity so movement/cadence reflect real touches, not double counts.
    const seenTouchEvents = new WeakSet<Event>();
    const touchCoordinates = (event: Event): { x: number; y: number } | null => {
      const touchEvent = event as TouchEvent;
      const list =
        touchEvent.changedTouches && touchEvent.changedTouches.length > 0
          ? touchEvent.changedTouches
          : touchEvent.touches;
      if (!list || list.length === 0) return null;
      const x = Number(list[0].clientX);
      const y = Number(list[0].clientY);
      return Number.isFinite(x) && Number.isFinite(y) ? { x, y } : null;
    };
    const rememberTouchPoint = (point: { x: number; y: number }): void => {
      interactionCounters.touchPositions.push(point);
      if (interactionCounters.touchPositions.length > 24) {
        interactionCounters.touchPositions.shift();
      }
    };
    const onTouchStart = (event: Event): void => {
      if (!(event as TouchEvent).isTrusted || seenTouchEvents.has(event)) return;
      seenTouchEvents.add(event);
      interactionCounters.touchStarts += 1;
      const now = Date.now();
      if (lastTouchStartAt > 0) {
        const interval = now - lastTouchStartAt;
        if (interval > 0 && interval < 2000) {
          interactionCounters.touchIntervalsMs.push(interval);
          if (interactionCounters.touchIntervalsMs.length > 32) {
            interactionCounters.touchIntervalsMs.shift();
          }
        }
      }
      lastTouchStartAt = now;
      const point = touchCoordinates(event);
      if (point) rememberTouchPoint(point);
      stamp();
    };
    const onTouchMove = (event: Event): void => {
      if (!(event as TouchEvent).isTrusted || seenTouchEvents.has(event)) return;
      seenTouchEvents.add(event);
      interactionCounters.touchMoves += 1;
      const point = touchCoordinates(event);
      if (point) rememberTouchPoint(point);
      stamp();
    };
    const onTouchEnd = (event: Event): void => {
      if (!(event as TouchEvent).isTrusted || seenTouchEvents.has(event)) return;
      seenTouchEvents.add(event);
      interactionCounters.touchEnds += 1;
      stamp();
    };
    const onScroll = (event: Event): void => {
      if (!event.isTrusted) return;
      interactionCounters.scrolls += 1;
      stamp();
    };
    const onKey = (event: Event): void => {
      if (!(event as KeyboardEvent).isTrusted) return;
      trustedKeyEvents += 1;
      interactionCounters.keyDowns += 1;
      const now = Date.now();
      if (lastKeyDownAt > 0) {
        const interval = now - lastKeyDownAt;
        if (interval > 0 && interval < 2000) {
          interactionCounters.keyIntervalsMs.push(interval);
          if (interactionCounters.keyIntervalsMs.length > 32) interactionCounters.keyIntervalsMs.shift();
        }
      }
      lastKeyDownAt = now;
      stamp();
    };
    // Passive Playwright mark-target listeners on BOTH document and window plus a
    // one-shot scan for framework globals. Presence is evidence only; nothing is patched.
    const onMarkTarget = (event: Event): void => {
      if (event.isTrusted === false) return;
      interactionCounters.playwrightMarkTargets += 1;
      stamp();
    };
    window.addEventListener('pointerdown', onPointerDown, options);
    window.addEventListener('pointermove', onPointerMove, options);
    window.addEventListener('keydown', onKey, options);
    window.addEventListener('touchstart', onTouchStart, options);
    window.addEventListener('touchmove', onTouchMove, options);
    window.addEventListener('touchend', onTouchEnd, options);
    window.addEventListener('scroll', onScroll, options);
    document.addEventListener('touchstart', onTouchStart, options);
    document.addEventListener('touchmove', onTouchMove, options);
    document.addEventListener('touchend', onTouchEnd, options);
    document.addEventListener('scroll', onScroll, options);
    document.addEventListener('__playwright_mark_target__', onMarkTarget, options);
    window.addEventListener('__playwright_mark_target__', onMarkTarget, options);
    for (const scope of [window, document] as unknown as Array<Record<string, unknown>>) {
      for (const key of Object.keys(scope)) {
        if (FRAMEWORK_GLOBAL_PATTERN.test(key) && !interactionCounters.frameworkGlobals.includes(key)) {
          interactionCounters.frameworkGlobals.push(key);
        }
      }
    }
  } catch {
    // A blocked listener is not evidence.
  }
}

/**
 * Human-corroboration score in [0, 1].
 *
 * CDP / DevTools attachment is not automation by itself; a person is expected to expose
 * ordinary human runtime facts (a real viewport, a visible document, languages, hardware
 * rendering) and, once they interact, trusted input events. A headless shell or a scripted
 * runtime accumulates none of these.
 */
export function measureHumanCorroboration(gpuRenderer?: string): HumanCorroborationResult {
  installTrustedInputTracker();
  const checks: string[] = [];
  let earned = 0;
  let total = 0;
  const add = (condition: boolean, weight: number, label: string): void => {
    total += weight;
    if (condition) {
      earned += weight;
      checks.push(label);
    }
  };

  let outerOk = false;
  let innerOk = false;
  let visible = false;
  let languagesOk = false;
  let nativeChrome = false;
  try {
    outerOk = window.outerWidth > 0 && window.outerHeight > 0;
    innerOk = window.innerWidth >= 320 && window.innerHeight >= 240;
    visible = document.visibilityState === 'visible';
    languagesOk = Array.isArray(navigator.languages) && navigator.languages.length > 0;
    const chromeObject = (window as unknown as { chrome?: { runtime?: unknown } }).chrome;
    nativeChrome = Boolean(chromeObject && typeof chromeObject === 'object');
  } catch {
    // Keep every false.
  }

  // Static runtime facts describe a real desktop runtime (18/22 = 0.82 when all pass).
  // They are corroborating context, NOT proof of a person: CDP escalation keys off the
  // separate `genuineInput` flag below, not off this score.
  add(outerOk, 3, 'non-zero outer viewport');
  add(innerOk, 3, 'desktop-sized inner viewport');
  add(visible, 3, 'document visible');
  add(languagesOk, 3, 'navigator.languages populated');
  add(!/swiftshader|llvmpipe|mesa offscreen/i.test((gpuRenderer || '').toLowerCase()), 3, 'hardware GPU');
  add(nativeChrome, 3, 'window.chrome runtime present');

  // Genuine trusted interaction adds the final 4/22. Without it a perfect static runtime
  // still scores 0.82, but it can never satisfy the CDP-escalation exemption on its own.
  const genuineInput = hasGenuineHumanInput();
  const trustedInput =
    trustedPointerEvents + trustedKeyEvents > 0 ||
    interactionCounters.touchStarts > 0 ||
    interactionCounters.touchMoves > 0 ||
    interactionCounters.touchEnds > 0 ||
    interactionCounters.scrolls > 0;
  total += 4;
  if (genuineInput) {
    earned += 4;
    checks.push('genuine trusted pointer/keyboard/scroll/touch input observed after dwell');
  } else if (trustedInput) {
    // Raw isTrusted input alone earns no human credit: CDP-dispatched Playwright input is
    // isTrusted too, and without human-like cadence/trail it cannot corroborate a person.
    checks.push('raw trusted input observed (human cadence unconfirmed)');
  } else {
    checks.push('no trusted human input observed');
  }
  // An injected automation library makes observed input unattributable to a person.
  if (interactionCounters.frameworkGlobals.length > 0 || interactionCounters.playwrightMarkTargets > 0) {
    earned = Math.max(0, earned - 4);
    checks.push('automation library globals present (input not human-attributable)');
  }

  return {
    score: total > 0 ? Math.round((earned / total) * 100) / 100 : 0,
    checks,
    trustedInput,
    genuineInput,
  };
}

export function detectStealthArtifacts(gpuRenderer?: string): StealthArtifacts {
  const reasons: string[] = [];
  let cdpRuntimeLeak = false;
  let cdpRuntimeProof = false;
  let definitive = false;

  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return { cdpRuntimeLeak: false, cdpRuntimeProof: false, stealthPluginDetected: false, stealthReasons: [] };
  }

  // Inspector probes. Three independent, non-blocking side-effect checks:
  //  (1) STRONG — CDP Runtime.debug eagerly serialises an Error and invokes
  //      `Error.prepareStackTrace`, a hook page JavaScript never calls itself.
  //  (2) STRONG, INDEPENDENT — a CDP/DevTools object preview eagerly evaluates an
  //      enumerable accessor on a plain object (the classic "getter detects DevTools"
  //      technique). It is a structurally different protocol observable from (1).
  //      Only (1) AND (2) together produce `cdpRuntimeProof`.
  //  (3) WEAK, ENGINE-DEPENDENT — V8 previews `Error.prototype.name` while serialising.
  //      On Android Chrome and other engines this naturally looks non-native, so it is
  //      telemetry only and can NEVER establish bridge proof or tampering on its own.
  //      A human with DevTools open is NEVER branded a bot here (Agent 2 owns the
  //      inspector_state state machine).
  try {
    const errorCtor = Error as unknown as { prepareStackTrace?: unknown };
    const originalPrepare = errorCtor.prepareStackTrace;
    const errorProto = Error.prototype as unknown as Record<string, unknown>;
    const originalNameDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, 'name');
    let prepareInvoked = false;
    let namePreviewReads = 0;

    errorCtor.prepareStackTrace = (error: unknown, stack: unknown) => {
      prepareInvoked = true;
      return typeof originalPrepare === 'function'
        ? (originalPrepare as (e: unknown, s: unknown) => string)(error, stack)
        : '';
    };
    Object.defineProperty(Error.prototype, 'name', {
      configurable: true,
      enumerable: false,
      get() {
        namePreviewReads += 1;
        return originalNameDescriptor && typeof originalNameDescriptor.value === 'string'
          ? originalNameDescriptor.value
          : 'Error';
      },
    });

    // Probe (2): a plain object with a uniquely named enumerable accessor. A CDP /
    // DevTools object preview eagerly serialises the object and invokes the getter;
    // without a protocol debugger the object stays lazy and the getter is never read.
    // This is a structurally different observable from Error.prepareStackTrace (1) and
    // from the engine-dependent Error.prototype.name preview (3).
    let objectPreviewReads = 0;
    const previewProbe: Record<string, unknown> = {};
    Object.defineProperty(previewProbe, '__intelCdpPreview__', {
      enumerable: true,
      configurable: true,
      get() {
        objectPreviewReads += 1;
        return 'preview';
      },
    });

    try {
      console.debug(new Error('intel-cdp-probe'));
      console.debug(previewProbe);
    } catch {
      /* console may be restricted — inconclusive */
    } finally {
      if (originalNameDescriptor) {
        Object.defineProperty(Error.prototype, 'name', originalNameDescriptor);
      } else {
        try {
          delete errorProto.name;
        } catch {
          /* leave the probe getter; still harmless */
        }
      }
      if (originalPrepare === undefined) {
        try {
          delete errorCtor.prepareStackTrace;
        } catch {
          errorCtor.prepareStackTrace = undefined;
        }
      } else {
        errorCtor.prepareStackTrace = originalPrepare;
      }
    }

    inspectorProbes.errorPrototypeNamePreviewReads = namePreviewReads;
    // (3) is WEAK and engine-dependent (it fires naturally on Android Chrome). It is
    // recorded in `inspectorProbes` for telemetry but is deliberately NOT pushed into
    // `reasons`, so it can never corroborate a stealth-plugin or CDP bot verdict.
    // STRONG proof requires BOTH independent protocol observables (1) and (2).
    // `cdpRuntimeLeak` is informational telemetry: the protocol hook alone is enough to
    // record it. STRONG proof (`cdpRuntimeProof`) additionally requires the independent
    // object-preview observable, and is the ONLY thing that may escalate a bot verdict.
    cdpRuntimeLeak = prepareInvoked || objectPreviewReads > 0;
    cdpRuntimeProof = prepareInvoked && objectPreviewReads > 0;
    if (cdpRuntimeProof) {
      reasons.push('CDP Runtime.enable serialization leak (Error.prepareStackTrace invoked on console.debug)');
    } else if (prepareInvoked) {
      // The protocol hook fired but the second probe could not corroborate it — keep it
      // informational. The `CDP Runtime.enable` prefix excludes it from patch artifacts.
      reasons.push('CDP Runtime.enable serialization hook fired (uncorroborated)');
    }
  } catch (error) {
    inspectorProbes.inspectorProbeError = String(error);
  }

  // Cross-realm descriptor audit in a SHORT-LIVED hidden iframe. Only property descriptors
  // and native SOURCE STRINGS are compared — NEVER cross-realm getter object identity and
  // NEVER `instanceof PluginArray` / `PluginArray.prototype` identity (those break across
  // realms and produce false anti-detect verdicts). The frame is removed immediately.
  try {
    const frame = document.createElement('iframe');
    frame.style.cssText =
      'position:absolute;left:-9999px;top:0;width:1px;height:1px;border:0;opacity:0;';
    frame.setAttribute('aria-hidden', 'true');
    frame.src = 'about:blank';
    document.body.appendChild(frame);
    try {
      const childWindow = frame.contentWindow as (Window & typeof globalThis) | null;
      if (childWindow) {
        const sourceOf = (getter: unknown): string => {
          try {
            return typeof getter === 'function' ? Function.prototype.toString.call(getter) : '';
          } catch {
            return '';
          }
        };
        const protoDescriptor = (
          target: object | undefined,
          key: string
        ): PropertyDescriptor | undefined => {
          try {
            if (!target) return undefined;
            return Object.getOwnPropertyDescriptor(Object.getPrototypeOf(target), key);
          } catch {
            return undefined;
          }
        };
        const childNavProto = childWindow.navigator
          ? Object.getPrototypeOf(childWindow.navigator)
          : undefined;
        const parentNavProto = Object.getPrototypeOf(navigator);
        const childSource = sourceOf(protoDescriptor(childNavProto, 'userAgent')?.get);
        const parentSource = sourceOf(protoDescriptor(parentNavProto, 'userAgent')?.get);
        inspectorProbes.crossRealmNativeDescriptor = /\[native code\]/.test(childSource);
        if (childSource && parentSource && childSource !== parentSource) {
          inspectorProbes.crossRealmGetterSourceMismatch = true;
          reasons.push('Cross-realm navigator.userAgent getter source differs from the top window');
        } else if (childSource && !/\[native code\]/.test(childSource)) {
          reasons.push('Cross-realm navigator.userAgent getter replaced by a non-native function');
        }
      }
    } finally {
      frame.remove();
    }
  } catch {
    // Blocked iframes are inconclusive; never a verdict.
  }

  // Patched native accessors across the properties stealth plugins forge.
  const navProto = typeof Navigator !== 'undefined' ? Navigator.prototype : undefined;
  const tamperedGetters: string[] = [];
  for (const property of ['webdriver', 'userAgent', 'platform', 'hardwareConcurrency', 'deviceMemory', 'languages', 'plugins']) {
    if (!isNativeAccessor(navProto, property)) tamperedGetters.push(property);
  }
  if (tamperedGetters.length > 0) {
    reasons.push(`Navigator getters rewritten by a non-native function (${tamperedGetters.join(', ')})`);
  }

  // Non-native Function.prototype.toString: the wrapper used to mask those getters.
  try {
    const fnToString = Function.prototype.toString;
    const nativeSource = Function.prototype.toString.call(fnToString);
    if (!/\[native code\]/.test(nativeSource)) {
      reasons.push('Function.prototype.toString is not native (stealth wrapper)');
    }
  } catch {
    reasons.push('Function.prototype.toString is unreadable (stealth wrapper)');
  }

  // Desktop-Chromium-only integrity checks. Firefox, Safari, Android and iOS never expose
  // window.chrome or the WHATWG PDF plugin set, so these rules must NEVER run on them.
  let desktopChromium = false;
  try {
    const ua = String(navigator.userAgent || '');
    // An Electron UA carries the embedded Chrome token but is a distinct host runtime. Never
    // run Chromium-only "missing window.chrome / PDF plugin" rules against an Electron shell.
    desktopChromium =
      /Chrome\/|Chromium\/|Edg\/|OPR\//i.test(ua) &&
      !/Firefox\/|FxiOS\/|Android|iPhone|iPad|iPod|Mobile/i.test(ua) &&
      !detectRuntimeFacts(ua).electron;
    if (desktopChromium) {
      const chromeObject = (window as unknown as { chrome?: { runtime?: unknown } }).chrome;
      if (!chromeObject || typeof chromeObject !== 'object') {
        reasons.push('Chromium user-agent without a window.chrome object');
      }
    }
  } catch {
    // Ignore.
  }

  // Plugin / MIME integrity uses DESCRIPTOR + SOURCE checks only. `instanceof PluginArray`
  // and getter-object identity are realm-sensitive and are deliberately never used here.
  if (desktopChromium) {
    try {
      const nativeSourceOf = (getter: unknown): string => {
        try {
          return typeof getter === 'function' ? Function.prototype.toString.call(getter) : '';
        } catch {
          return '';
        }
      };
      const navProto = typeof Navigator !== 'undefined' ? Navigator.prototype : undefined;
      const pluginsDescriptor = navProto
        ? Object.getOwnPropertyDescriptor(navProto, 'plugins')
        : undefined;
      const mimeDescriptor = navProto
        ? Object.getOwnPropertyDescriptor(navProto, 'mimeTypes')
        : undefined;
      if (pluginsDescriptor && !/\[native code\]/.test(nativeSourceOf(pluginsDescriptor.get))) {
        reasons.push('navigator.plugins getter is not native (source check)');
      }
      if (mimeDescriptor && !/\[native code\]/.test(nativeSourceOf(mimeDescriptor.get))) {
        reasons.push('navigator.mimeTypes getter is not native (source check)');
      }
      // WHATWG desktop Chromium baseline: 5 PDF viewer plugins, 2 PDF MIME types and
      // pdfViewerEnabled === true. Only a consistent ALL-WRONG shape counts as a spoof.
      const pluginCount = Number(navigator.plugins?.length ?? 0);
      const mimeCount = Number(navigator.mimeTypes?.length ?? 0);
      const pdfMimeCount = Array.from(navigator.mimeTypes ?? []).filter((mime) =>
        /pdf/i.test(mime.type)
      ).length;
      const pdfViewerEnabled = (navigator as unknown as { pdfViewerEnabled?: boolean })
        .pdfViewerEnabled;
      if (pluginCount < 5 && mimeCount < 2 && pdfMimeCount === 0 && pdfViewerEnabled === false) {
        reasons.push('Desktop Chromium PDF plugin/MIME/pdfViewerEnabled baseline missing');
      }
    } catch {
      // Ignore.
    }
  }

  // A software rasterizer is a VM/headless signal, NOT evidence of a stealth plugin. Counting
  // it here made plain SwiftShader headless sessions look like "Puppeteer / Playwright Stealth"
  // and pushed them into the critical tier. Only actual patch artifacts count toward this flag.
  // The CDP Runtime leak is developer-tools evidence by itself (DevTools open, Electron, IDE
  // webview), so it must not combine with one benign quirk into a "stealth plugin" verdict.
  const patchArtifacts = reasons.filter((reason) => !/^CDP Runtime\.enable/.test(reason));
  const stealthPluginDetected = definitive || patchArtifacts.length >= 2;

  return { cdpRuntimeLeak, cdpRuntimeProof, stealthPluginDetected, stealthReasons: reasons };
}

const CDP_GLOBAL_KEY_PATTERN =
  /^cdc_|^\$cdc_|^__\$webdriverAsyncExecutor|^__webdriver|^__selenium|^__fxdriver|^__playwright|^__pwInitScripts|^_phantom|^callPhantom|^domAutomation/i;

/**
 * Bot & automation detection.
 * Checks `navigator.webdriver`, Chrome DevTools Protocol / WebDriver bindings on
 * `window` and `document`, a patched `Navigator.prototype.webdriver` getter,
 * headless User-Agents, software GPUs, zero outer geometry and empty languages.
 */
export function detectBotAndAutomation(
  gpuRenderer: string,
  options?: {
    /** Snapshot from the async dwell decision, so both paths read the same probe result. */
    stealth?: StealthArtifacts;
    human?: HumanCorroborationResult;
    /** True when the identify path waited out the corroboration window with no input. */
    dwellAwaited?: boolean;
  }
): BotAutomationSignals {
  const nav = typeof navigator !== 'undefined' ? navigator : undefined;
  let ua = '';
  let webdriver = false;
  try {
    if (nav) {
      ua = nav.userAgent || '';
      webdriver = nav.webdriver === true;
    }
  } catch {
    // Ignore hostile navigator proxies.
  }

  const cdpDetected = scanCdpGlobals();

  const navProto = typeof Navigator !== 'undefined' ? Navigator.prototype : undefined;
  const webdriverGetterTampered = !isNativeAccessor(navProto, 'webdriver');

  const headlessUa = /HeadlessChrome|PhantomJS|SlimerJS/i.test(ua);
  const softwareGpu = /swiftshader|llvmpipe|mesa offscreen/i.test((gpuRenderer || '').toLowerCase());
  let zeroGeometry = false;
  let emptyLanguages = false;
  try {
    zeroGeometry =
      typeof window !== 'undefined' && (window.outerWidth === 0 || window.outerHeight === 0);
    emptyLanguages = !nav || !Array.isArray(nav.languages) || nav.languages.length === 0;
  } catch {
    // Ignore hostile window proxies.
  }
  const isHeadless = headlessUa || zeroGeometry;

  // Run all 19 fingerprintjs/BotD detectors
  const botD19 = detectBotD19Signals(gpuRenderer);

  // Stealth plugins hide every classic flag, so their own patching side effects become the
  // evidence: CDP Runtime serialization, forged native getters, iframe identity leaks.
  const stealth = options?.stealth ?? detectStealthArtifacts(gpuRenderer);

  // Weighted evidence gate. A real person must never be branded as a bot from ambiguous
  // environment quirks: SwiftShader appears whenever hardware acceleration is off (battery
  // saver, blocklisted GPU, Linux), in-app browsers report zero outer geometry, empty
  // languages happen on hardened profiles, and privacy extensions patch the webdriver
  // getter. Only hard signals prove automation on their own: the WebDriver handshake, a
  // CDP binding, an automation user-agent, or a BotD hard detector. Soft signals are
  // recorded as corroboration only and can never flip `isBot`.
  // A patched Navigator.prototype.webdriver getter is NOT proof of automation: privacy
  // extensions and hardened profiles rewrite it routinely. BotD folds both the real
  // `navigator.webdriver` flag and the getter override into `signals.webdriver`, so the
  // getter case is downgraded to `webdriverGetterTampered` (soft) below and only the
  // genuine flag reaches the hard gate.
  const d19Hard =
    Boolean(botD19.signals.user_agent) || Boolean(botD19.signals.distinctive_properties);
  const d19Soft =
    Boolean(botD19.signals.rtt) ||
    Boolean(botD19.signals.plugins_array) ||
    Boolean(botD19.signals.plugins_inconsistency) ||
    Boolean(botD19.signals.window_external) ||
    Boolean(botD19.signals.window_size) ||
    Boolean(botD19.signals.product_sub) ||
    Boolean(botD19.signals.webgl) ||
    Boolean(botD19.signals.notification_permissions);
  const softEvidenceCount =
    (softwareGpu ? 1 : 0) +
    (zeroGeometry ? 1 : 0) +
    (emptyLanguages ? 1 : 0) +
    (webdriverGetterTampered ? 1 : 0) +
    (d19Soft ? 1 : 0);

  // Soft evidence alone is suspicion, never a verdict: two coincidental quirks (an in-app
  // browser with a disabled GPU) must not label a human as automated.
  //
  // CDP Runtime attachment is *developer-tools* evidence, not a bot verdict. Electron apps,
  // IDE webviews (VS Code, Cursor, OpenCode) and any Chromium with DevTools open expose it
  // while a real person is driving the session. Fingerprint Pro makes exactly this split:
  // `developer_tools` is its own signal and `bot` stays `not_detected`. A CDP bridge only
  // stays a bot signal when the runtime is simultaneously headless-shaped (no viewport,
  // no languages, software GPU), which a real window never is.
  const runtimeHost = detectAutomationEnvironment(ua, gpuRenderer);
  const privacyHardenedRuntime = isPrivacyHardenedRuntime(ua, false);
  const human = options?.human ?? measureHumanCorroboration(gpuRenderer);
  // A bare CDP Runtime binding is protocol attachment, NOT a visible DevTools frontend — the
  // envelope reports that as automation_protocol_attached (cdp_attached:true,
  // developer_tools:false) via classifyInspectorState. Only a known IDE webview host or a genuine
  // docked layout (large outer/inner viewport delta) counts as real DevTools evidence here.
  const dockedDevToolsLayout = hasDockedDevToolsLayout();
  const developerTools = runtimeHost.environment === 'ide_webview' || dockedDevToolsLayout;
  const headlessShapedCdp =
    stealth.cdpRuntimeProof &&
    human.score < 0.34 &&
    !privacyHardenedRuntime &&
    (zeroGeometry || emptyLanguages || softwareGpu);
  // ---- Corroborated CDP escalation ----------------------------------------------------
  // A stealth runtime that hides `navigator.webdriver` behind a native-looking getter and
  // keeps a normal desktop UA previously earned a "Verified Human" verdict: static geometry
  // scored high even though nobody ever touched the page, and the live CDP bridge was weight
  // 0. Now ONLY STRONG bridge proof — real automation binding globals, or a CDP Runtime.enable
  // leak corroborated by a second independent protocol probe — left uncorroborated by genuine
  // trusted input after the dwell window, escalates to a bot. Engine-dependent artifacts
  // (webdriver getter descriptors, Error.prototype.name previews, cross-realm getter diffs)
  // are explicitly NOT bridge proof. Electron / IDE / docked-DevTools hosts stay weight 0.
  // Privacy-hardened runtimes (Tor / RFP / Firefox / Safari / Brave) keep their exemption;
  // a software GPU is NOT bridge evidence (SwiftShader on its own remains exempt).
  const bridgeEvidence = collectCdpBridgeEvidence(stealth, ua);
  // A real docked DevTools layout or a known embedded host is always weight 0, even before
  // the person has interacted — a fresh IDE / Electron / DevTools load must never be branded
  // a bot. A headless stealth runtime has no docked layout, so it cannot hide behind this.
  const exemptHost = dockedDevToolsLayout || runtimeHost.electron || runtimeHost.ideWebview;
  const dwellSatisfied =
    options?.dwellAwaited === true || Date.now() - PAGE_SESSION_STARTED_AT >= CDP_CORROBORATION_DWELL_MS;
  const corroboratedCdpBot =
    bridgeEvidence.length > 0 &&
    dwellSatisfied &&
    !human.genuineInput &&
    !privacyHardenedRuntime &&
    !exemptHost;

  // Research-backed corroboration rule (incolumitas / Fingerprint Pro): patch artifacts from
  // privacy extensions are "suspicious", never a verdict. A stealth plugin only reaches the
  // bot gate once a dwell has elapsed with no genuine human input, and never on a
  // privacy-hardened runtime. First-sample privacy users keep their human classification.
  const humanCorroborated = human.genuineInput || privacyHardenedRuntime || !dwellSatisfied;
  const stealthBot =
    stealth.stealthPluginDetected &&
    !humanCorroborated &&
    !privacyHardenedRuntime &&
    !exemptHost;
  const cdpEscalationReason =
    'Stealth automation: corroborated CDP runtime bridge with no trusted human input after dwell';

  const isBot =
    webdriver ||
    cdpDetected ||
    headlessUa ||
    d19Hard ||
    stealthBot ||
    headlessShapedCdp ||
    corroboratedCdpBot;
  const botSuspicion =
    !isBot &&
    (softEvidenceCount >= 2 || (stealth.stealthPluginDetected && humanCorroborated));
  let botReason = 'Verified human runtime & native DOM prototypes';
  const allBotReasons: string[] = [];

  if (webdriver) {
    botReason = 'navigator.webdriver flag is enabled (WebDriver controlled session)';
  } else if (cdpDetected) {
    botReason = 'Chrome DevTools Protocol binding exposed on window/document';
  } else if (headlessUa) {
    botReason = 'Headless browser User-Agent signature detected';
  } else if (d19Hard) {
    botReason = botD19.reasons[0] || 'BotD hard automation signal detected';
  } else if (corroboratedCdpBot) {
    botReason = cdpEscalationReason;
  } else if (stealthBot) {
    botReason =
      stealth.stealthReasons[0] || 'Stealth automation plugin artifacts detected';
  } else if (headlessShapedCdp) {
    botReason = 'Headless-shaped runtime with a CDP Runtime session attached';
  } else if (botSuspicion) {
    botReason = `Low-confidence environment quirks (${softEvidenceCount} soft signals)`;
  } else if (developerTools) {
    botReason = runtimeHost.ideWebview
      ? 'Verified human session inside an IDE webview with a DevTools protocol bridge'
      : runtimeHost.electron
      ? 'Verified human session inside an Electron shell with a DevTools protocol bridge'
      : 'Verified human session with a Chrome DevTools protocol bridge attached';
  }

  if (botReason !== 'Verified human runtime & native DOM prototypes') {
    allBotReasons.push(botReason);
  }
  if (isBot) {
    for (const reason of stealth.stealthReasons) {
      if (!allBotReasons.includes(reason)) allBotReasons.push(reason);
    }
  }
  if (corroboratedCdpBot) {
    // The CDP inspector probe is normally weight-0 developer-tools evidence. Once the
    // dwell has elapsed with no trusted human input, the same artifacts become automation
    // evidence. Keep them verbose so the server's automation-targeted-tampering check can
    // escalate the bot_type to `stealth_automation`.
    for (const evidence of bridgeEvidence) {
      if (!allBotReasons.includes(evidence)) allBotReasons.push(evidence);
    }
    if (!allBotReasons.includes(cdpEscalationReason)) allBotReasons.push(cdpEscalationReason);
  }
  if (isBot && botD19.detected) {
    allBotReasons.push(...botD19.reasons.filter((reason) => reason !== botReason));
  }
  // Detail/verdict invariant: the human default must never sit next to a bot verdict.
  if (isBot && botReason === 'Verified human runtime & native DOM prototypes') {
    botReason = allBotReasons[0] || 'Hard automation artifact detected';
  }
  // Informational only: an attached DevTools / CDP bridge on an otherwise human runtime.
  if (developerTools && !isBot && allBotReasons.length === 0) {
    allBotReasons.push(
      `Developer tools attached (${runtimeHost.environment}) — informational, not automation`
    );
  }

  return {
    isBot,
    isHeadless:
      isHeadless || botD19.signals.window_size || botD19.signals.user_agent,
    botReason,
    webdriver,
    cdpDetected: cdpDetected || botD19.signals.distinctive_properties || corroboratedCdpBot,
    botSignals: allBotReasons,
    botSuspicion,
    cdpRuntimeLeak: stealth.cdpRuntimeLeak,
    stealthPluginDetected: stealthBot || corroboratedCdpBot,
    developerTools,
    automationEnvironment: runtimeHost.environment,
    humanCorroboration: human.score,
    interactionEvidence: getInteractionEvidence(),
    corroboratedCdpEscalation: corroboratedCdpBot,
    cdpBridgeEvidence: bridgeEvidence,
    inspectorProbes: { ...inspectorProbes },
  };
}

/**
 * Client-side Tor Browser fingerprint.
 *
 * Tor Browser ships the Resist Fingerprinting (RFP) patch set, and several of those patches are
 * directly observable from page JavaScript: a fixed UTC timezone, a clamped
 * `navigator.hardwareConcurrency`, forced letterboxing viewports (multiples of 200 x 100), a
 * Gecko-only engine and an OPFS write rejection. A single signal proves nothing (a Firefox user
 * in UTC is not a Tor user), so the verdict requires the Gecko engine *and* at least two
 * independent RFP signals. Never throws.
 */
export function detectTorBrowserClient(
  browserDevice: Pick<BrowserDeviceInfo, 'browser' | 'platform' | 'timezone' | 'screenResolution' | 'pixelRatio'>,
  hardwareSignals: Pick<HardwareSignals, 'cpuCores' | 'deviceMemoryGb' | 'gpuVendor' | 'gpuRenderer'>,
  incognitoMethod: string
): { detected: boolean; confirmed: boolean; signals: string[]; reasons: string[] } {
  const signals: string[] = [];
  const reasons: string[] = [];

  const browserLabel = `${browserDevice.browser || ''} ${browserDevice.platform || ''}`;
  const geckoEngine = /firefox|gecko|spidermonkey/i.test(browserLabel);
  if (!geckoEngine) return { detected: false, confirmed: false, signals, reasons };

  signals.push('gecko-engine');

  // Dedicated RFP confirmation gate. A Chromium stealth plugin can spoof a Firefox UA,
  // but it cannot change the JavaScript engine or remove Chromium-only surfaces.
  let geckoRuntime = false;
  let chromiumArtifact = false;
  try {
    geckoRuntime = getEngineErrorLength() === 25; // SpiderMonkey (V8 = 51)
    const scope = window as unknown as { chrome?: unknown };
    chromiumArtifact =
      /Chrome\/|Chromium\/|Edg\/|OPR\//i.test(navigator.userAgent || '') ||
      Boolean((navigator as unknown as { userAgentData?: unknown }).userAgentData) ||
      Boolean(scope.chrome) ||
      navigator.webdriver === true;
  } catch {
    // Hostile proxy: abstain from confirmation rather than trust the spoofable UA.
  }
  if (chromiumArtifact) return { detected: false, confirmed: false, signals, reasons };

  const timezone = (browserDevice.timezone || '').trim();
  if (/^(utc|etc\/utc|gmt)$/i.test(timezone)) {
    signals.push('tor-browser-rfp-timezone-utc');
    reasons.push('RFP forces the browser timezone to UTC');
  }

  let viewportWidth = 0;
  let viewportHeight = 0;
  let screenWidth = 0;
  let screenHeight = 0;
  try {
    if (typeof window !== 'undefined') {
      viewportWidth = window.innerWidth || 0;
      viewportHeight = window.innerHeight || 0;
      screenWidth = window.screen?.width ?? 0;
      screenHeight = window.screen?.height ?? 0;
    }
  } catch {
    // Hostile window proxy: letterboxing cannot be measured.
  }
  const letterboxed =
    viewportWidth >= 200 &&
    viewportHeight >= 100 &&
    viewportWidth % 200 === 0 &&
    viewportHeight % 100 === 0;
  if (letterboxed) {
    signals.push('tor-letterboxing-viewport');
    reasons.push(`Letterboxed viewport ${viewportWidth}x${viewportHeight} (200 x 100 steps)`);
  }
  if (
    screenWidth > 0 &&
    screenHeight > 0 &&
    screenWidth === viewportWidth &&
    screenHeight === viewportHeight
  ) {
    signals.push('tor-letterboxing-viewport');
    reasons.push('Viewport is pinned to the reported screen size (letterboxing)');
  }

  const cpuCores = hardwareSignals.cpuCores;
  if (cpuCores !== null && cpuCores !== undefined && cpuCores === 2) {
    const pixelRatio = Number.parseFloat(browserDevice.pixelRatio || '');
    const dprDetail =
      Number.isFinite(pixelRatio) && pixelRatio >= 1 && pixelRatio <= 2
        ? `, DPR ${pixelRatio}`
        : '';
    signals.push('tor-browser-rfp-hardware-clamp');
    reasons.push(`RFP clamps navigator.hardwareConcurrency to ${cpuCores}${dprDetail}`);
  }

  if (incognitoMethod === METHOD_PRIVATE_STORAGE) {
    signals.push('tor-private-storage-rejected');
    reasons.push('Private-mode storage write rejected by the hardened browser');
  }

  const uniqueSignals = Array.from(new Set(signals));
  const rfpSignals = uniqueSignals.filter((signal) => signal !== 'gecko-engine');
  const detected = geckoEngine && rfpSignals.length >= 2;
  // Confirmed = genuine Gecko runtime + RFP evidence + no Chromium-only surfaces.
  // This is the ONLY condition allowed to suppress RFP-induced tamper false positives.
  const confirmed = detected && geckoRuntime;
  return { detected, confirmed, signals: uniqueSignals, reasons };
}

/**
 * Private / Incognito browsing assessment.
 *
 * Modern Chromium no longer differs in raw quota: both a normal and an
 * off-the-record context report `quota = usage + 10 GiB`. The surviving physics
 * are (a) headroom on Chrome 147+ (normal `usage + 10.0 GiB`, Incognito
 * `usage + 9.0 GiB`), (b) the legacy `webkitTemporaryStorage` quota versus the
 * JS heap limit, and (c) IndexedDB commit durability: an off-the-record store
 * lives in RAM, so a `strict` (fsync) transaction finishes as fast as a
 * `relaxed` one. Firefox and Safari are probed through OPFS / IndexedDB
 * restrictions instead. Every probe is time-boxed, never throws and leaves no
 * database behind.
 */
export interface PrivateBrowsingAssessment {
  likely: boolean;
  confidence: number;
  quotaMb: number | null;
  reasons: string[];
}

/**
 * Normalises a thrown DOMException / Error into a testable name + message pair.
 */
function errorLooksLike(error: unknown, pattern: RegExp): boolean {
  if (!error) return false;
  if (error instanceof Error) {
    return pattern.test(error.name) || pattern.test(error.message);
  }
  if (typeof error === 'object') {
    const record = error as Record<string, unknown>;
    const name = typeof record.name === 'string' ? record.name : '';
    const message = typeof record.message === 'string' ? record.message : '';
    return pattern.test(name) || pattern.test(message);
  }
  return pattern.test(String(error));
}

/**
 * A rejection that literally names private browsing / off-the-record storage.
 * A normal profile never produces such a string, so this is DECISIVE evidence —
 * never a heuristic. It is the only class of signal allowed to decide incognito
 * on its own outside a decisive OPFS entry-point/write rejection.
 */
const PRIVATE_MODE_ERROR_PATTERN =
  /incognito|off[\s-]?the[\s-]?record|private[\s-]?(?:browsing|mode|window|context|storage|profile)/i;

/**
 * Broader off-the-record rejection language (SecurityError / NotAllowedError /
 * permission-denied / transient / disabled-storage). Ambiguous on its own —
 * corroboration only, never decisive.
 */
const OTR_REJECTION_PATTERN =
  /SecurityError|NotAllowedError|InvalidStateError|NotSupportedError|permission|denied|not allowed|blocked|transient|ephemeral|storage\s+(?:is\s+)?disabled/i;

interface PrivateErrorClass {
  /** The error literally names private/incognito browsing — decisive. */
  literal: boolean;
  /** The error looks like an off-the-record storage restriction. */
  restricted: boolean;
}

const NO_PRIVATE_SIGNAL: PrivateErrorClass = { literal: false, restricted: false };

function classifyPrivateError(error: unknown): PrivateErrorClass {
  if (!error) return NO_PRIVATE_SIGNAL;
  let name = '';
  let message = '';
  if (error instanceof Error) {
    name = error.name || '';
    message = error.message || '';
  } else if (typeof error === 'object') {
    const record = error as Record<string, unknown>;
    name = typeof record.name === 'string' ? record.name : '';
    message = typeof record.message === 'string' ? record.message : '';
  } else {
    message = String(error);
  }
  const literal = PRIVATE_MODE_ERROR_PATTERN.test(name) || PRIVATE_MODE_ERROR_PATTERN.test(message);
  const restricted =
    literal || OTR_REJECTION_PATTERN.test(name) || OTR_REJECTION_PATTERN.test(message);
  return { literal, restricted };
}

function mergePrivateSignals(...signals: PrivateErrorClass[]): PrivateErrorClass {
  return {
    literal: signals.some((signal) => signal.literal),
    restricted: signals.some((signal) => signal.restricted),
  };
}

/** Resolves `work`, or `fallback` inside `ms`; a late rejection is swallowed. */
function withDeadline<T>(work: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise<T>((resolve) => {
    let settled = false;
    const timer = setTimeout(() => finish(fallback), ms);
    function finish(value: T): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    }
    work.then(finish, () => finish(fallback));
  });
}

/**
 * Layer 1 — Chromium IndexedDB commit-durability physics (detectIncognito v1.9.0).
 *
 * A normal profile fsyncs `strict` transactions to disk, so `strict` commits are
 * measurably slower than `relaxed` ones. An off-the-record profile keeps IndexedDB
 * in RAM and the ratio collapses toward 1.0. Returns the median
 * `strict / relaxed` ratio, or `null` when the browser ignores the durability hint
 * or the probe cannot finish inside its budget. The database is always closed and
 * deleted through the `settled`-guarded `finish()`.
 */
interface IdbDurabilityProbe {
  /** Trimmed-median strict/relaxed commit ratio, or null when inconclusive. */
  ratio: number | null;
  /** True when the trimmed spread is too wide (or too few rounds) to trust. */
  highVariance: boolean;
}

/** Shared inconclusive sentinel — never treated as incognito evidence. */
const IDB_INCONCLUSIVE: IdbDurabilityProbe = { ratio: null, highVariance: true };

async function probeChromiumIdbDurability(): Promise<IdbDurabilityProbe> {
  if (typeof indexedDB === 'undefined') return IDB_INCONCLUSIVE;
  const PAYLOAD = 16384;
  const WRITES = 15;
  const ROUNDS = 15;
  const MIN_ROUNDS = 7;
  const CAP_MS = 1000;
  const dbName = '__di_' + Math.random().toString(36).slice(2);
  const payload = new Uint8Array(PAYLOAD);

  return new Promise<IdbDurabilityProbe>((resolve) => {
    let settled = false;
    const finish = (val: IdbDurabilityProbe, db?: IDBDatabase) => {
      if (settled) return;
      settled = true;
      try { db?.close(); } catch { /* ignore */ }
      try { indexedDB.deleteDatabase(dbName); } catch { /* ignore */ }
      resolve(val);
    };
    const safetyTimer = setTimeout(() => finish(IDB_INCONCLUSIVE), 1400);
    try {
      const req = indexedDB.open(dbName, 1);
      req.onupgradeneeded = () => { req.result.createObjectStore('s'); };
      req.onerror = () => { clearTimeout(safetyTimer); finish(IDB_INCONCLUSIVE); };
      req.onsuccess = () => {
        const db = req.result;
        let honored = false;
        try {
          const t = (db as unknown as {
            transaction: (store: string, mode: string, opts: { durability: string }) => IDBTransaction & { durability?: string };
          }).transaction('s', 'readwrite', { durability: 'strict' });
          honored = t.durability === 'strict';
          t.abort();
        } catch { honored = false; }
        if (!honored) { clearTimeout(safetyTimer); finish(IDB_INCONCLUSIVE, db); return; }

        const block = (durability: 'strict' | 'relaxed'): Promise<number> =>
          new Promise((res, rej) => {
            const t0 = performance.now();
            let i = 0;
            const step = (): void => {
              if (i === WRITES) { res(performance.now() - t0); return; }
              const tx = (db as unknown as {
                transaction: (store: string, mode: string, opts: { durability: string }) => IDBTransaction;
              }).transaction('s', 'readwrite', { durability });
              tx.objectStore('s').put(payload, i);
              i++;
              tx.oncomplete = step;
              tx.onerror = tx.onabort = () => rej(tx.error);
            };
            step();
          });

        void (async () => {
          const start = performance.now();
          await block('relaxed');
          await block('strict'); // warm-up discarded
          const ratios: number[] = [];
          // Interleave the measurement order so a monotonic IO/clock drift cannot bias
          // the ratio: even rounds relax→strict, odd rounds strict→relax.
          for (let r = 0; r < ROUNDS; r++) {
            let rel: number;
            let str: number;
            if (r % 2 === 0) {
              rel = await block('relaxed');
              str = await block('strict');
            } else {
              str = await block('strict');
              rel = await block('relaxed');
            }
            ratios.push(rel > 0 ? str / rel : Infinity);
            if (ratios.length >= MIN_ROUNDS && performance.now() - start >= CAP_MS) break;
          }
          // Trimmed median: drop one fastest and one slowest round before taking the
          // median, so a single scheduler hiccup cannot move the verdict across the
          // deadband. This is the interleaved trimmed-median gate used on Chromium 51.
          const finite = ratios.filter((v) => Number.isFinite(v)).sort((a, b) => a - b);
          const trimmed = finite.length >= 5 ? finite.slice(1, -1) : finite;
          const median = trimmed.length > 0 ? trimmed[trimmed.length >> 1] : null;
          // High variance = optimistic majority (below the trimmed median) or a wide
          // spread across the whole sample. Combined with a too-small sample this is
          // the "high variance = inconclusive" arm of the deadband.
          const spread = trimmed.length >= 2 ? trimmed[trimmed.length - 1] - trimmed[0] : Infinity;
          const belowMedian = median !== null ? trimmed.filter((v) => v < median).length : 0;
          const highVariance =
            median === null ||
            trimmed.length < 5 ||
            !(spread <= 0.9) ||
            belowMedian > Math.ceil(trimmed.length / 2);
          clearTimeout(safetyTimer);
          if (median === null || !Number.isFinite(median) || highVariance) {
            finish(
              median !== null && Number.isFinite(median)
                ? { ratio: Number(median.toFixed(3)), highVariance: true }
                : IDB_INCONCLUSIVE,
              db
            );
          } else {
            finish({ ratio: Number(median.toFixed(3)), highVariance: false }, db);
          }
        })().catch(() => { clearTimeout(safetyTimer); finish(IDB_INCONCLUSIVE, db); });
      };
    } catch { clearTimeout(safetyTimer); finish(IDB_INCONCLUSIVE); }
  });
}

interface OpfsFlushProbeResult {
  medianFlushMs: number;
  flushToWriteRatio: number;
}

/**
 * Layer 2 — Chromium OPFS synchronous-access-handle flush physics.
 *
 * A dedicated inline Blob worker opens an OPFS file through `createSyncAccessHandle()`,
 * warms up one `write` + `flush`, then times 9 rounds of a 32 KiB `write()` and a
 * `flush()`. On a disk-backed profile `flush()` costs real I/O; inside an off-the-record
 * context the write-back goes to RAM and the flush median collapses. The worker and the
 * OPFS entry are always released, on every path.
 */
async function probeChromiumOpfsWorkerFlush(): Promise<OpfsFlushProbeResult | null> {
  if (typeof Worker === 'undefined' || typeof Blob === 'undefined' || typeof URL === 'undefined') {
    return null;
  }
  const storage =
    typeof navigator !== 'undefined'
      ? (navigator.storage as (StorageManager & { getDirectory?: () => Promise<unknown> }) | undefined)
      : undefined;
  if (!storage || typeof storage.getDirectory !== 'function') return null;

  // Generated on the main thread so cleanup also works when the worker is terminated
  // mid-probe by the 600 ms timeout (a terminated worker never runs its own finally).
  const opfsEntryName = '__intel_opfs_' + Math.random().toString(36).slice(2);

  const workerSource = `
    self.onmessage = async () => {
      let root = null;
      let access = null;
      const name = '${opfsEntryName}';
      try {
        root = await navigator.storage.getDirectory();
        const handle = await root.getFileHandle(name, { create: true });
        if (typeof handle.createSyncAccessHandle !== 'function') {
          self.postMessage(null);
          return;
        }
        access = await handle.createSyncAccessHandle();
        const buffer = new Uint8Array(32768);
        const writeMs = [];
        const flushMs = [];
        for (let warm = 0; warm < 1; warm++) {
          access.write(buffer, { at: 0 });
          access.flush();
        }
        for (let round = 0; round < 9; round++) {
          const w0 = performance.now();
          access.write(buffer, { at: 0 });
          const w1 = performance.now();
          access.flush();
          const w2 = performance.now();
          writeMs.push(w1 - w0);
          flushMs.push(w2 - w1);
        }
        writeMs.sort((a, b) => a - b);
        flushMs.sort((a, b) => a - b);
        const medianWrite = writeMs[writeMs.length >> 1];
        const medianFlush = flushMs[flushMs.length >> 1];
        self.postMessage({
          medianFlushMs: Number(medianFlush.toFixed(4)),
          flushToWriteRatio: Number((medianWrite > 0 ? medianFlush / medianWrite : 0).toFixed(3)),
        });
      } catch {
        self.postMessage(null);
      } finally {
        try { if (access) access.close(); } catch (e) { /* ignore */ }
        try { if (root) await root.removeEntry(name); } catch (e) { /* ignore */ }
      }
    };
  `;

  let blobUrl: string | null = null;
  let worker: Worker | null = null;

  return new Promise<OpfsFlushProbeResult | null>((resolve) => {
    let settled = false;
    const finish = (value: OpfsFlushProbeResult | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { worker?.terminate(); } catch { /* ignore */ }
      try { if (blobUrl) URL.revokeObjectURL(blobUrl); } catch { /* ignore */ }
      // Best-effort OPFS cleanup on the main thread: the worker may have been
      // terminated before its own finally block could remove the entry.
      void (async () => {
        try {
          const dir = (await storage.getDirectory?.()) as
            | { removeEntry?: (name: string) => Promise<void> }
            | undefined;
          await dir?.removeEntry?.(opfsEntryName);
        } catch {
          /* ignore */
        }
      })();
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), 600);

    try {
      blobUrl = URL.createObjectURL(new Blob([workerSource], { type: 'text/javascript' }));
      worker = new Worker(blobUrl);
      worker.onmessage = (event: MessageEvent) => {
        const data = (event.data ?? null) as OpfsFlushProbeResult | null;
        if (
          data &&
          typeof data.medianFlushMs === 'number' &&
          Number.isFinite(data.medianFlushMs) &&
          typeof data.flushToWriteRatio === 'number' &&
          Number.isFinite(data.flushToWriteRatio)
        ) {
          finish(data);
        } else {
          finish(null);
        }
      };
      worker.onerror = () => finish(null);
      worker.postMessage('run');
    } catch {
      finish(null);
    }
  });
}

/**
 * Probes the Origin Private File System entry point. A rejected promise is the
 * private-mode signal on Firefox (SecurityError) and Safari (transient reason).
 */
async function probeOpfsDirectory(): Promise<
  { status: 'resolved' } | { status: 'rejected'; error: unknown } | { status: 'unsupported' }
> {
  const storage =
    typeof navigator !== 'undefined'
      ? (navigator.storage as (StorageManager & { getDirectory?: () => Promise<unknown> }) | undefined)
      : undefined;
  if (!storage || typeof storage.getDirectory !== 'function') {
    return { status: 'unsupported' };
  }
  try {
    await storage.getDirectory();
    return { status: 'resolved' };
  } catch (error) {
    return { status: 'rejected', error };
  }
}

/**
 * True when an OPFS entry-point rejection is a decisive off-the-record denial.
 * A literal private-mode string is always decisive; a bare SecurityError /
 * NotAllowedError is decisive too because a top-level, non-persistent context
 * cannot produce it for any ordinary reason. `InvalidStateError` is noisier and
 * needs OTR wording before it can decide anything.
 */
function opfsRejectionIsDecisive(
  probe: Awaited<ReturnType<typeof probeOpfsDirectory>>
): boolean {
  if (probe.status !== 'rejected') return false;
  const classified = classifyPrivateError(probe.error);
  if (classified.literal) return true;
  if (errorLooksLike(probe.error, /SecurityError|NotAllowedError/i)) return true;
  return errorLooksLike(probe.error, /InvalidStateError/i) && classified.restricted;
}

/**
 * An OPFS *write* attempt. In modern Chrome incognito `getDirectory()` frequently
 * resolves, so the entry point alone is not enough; a denied file write inside a
 * top-level, non-persistent context is an equally deterministic private signal.
 * Any timeout, unrelated quota failure or missing API yields "no evidence".
 */
async function probeChromiumOpfsWrite(): Promise<PrivateErrorClass> {
  const storage =
    typeof navigator !== 'undefined'
      ? (navigator.storage as (StorageManager & { getDirectory?: () => Promise<unknown> }) | undefined)
      : undefined;
  if (!storage || typeof storage.getDirectory !== 'function') return NO_PRIVATE_SIGNAL;

  const name = '__intel_pb_opfs_' + Math.random().toString(36).slice(2);
  let failure: unknown = null;
  try {
    failure = await withDeadline<unknown>(
      (async () => {
        const root = (await storage.getDirectory()) as {
          getFileHandle?: (
            name: string,
            options?: { create?: boolean }
          ) => Promise<{
            createWritable?: () => Promise<{
              write: (data: string) => Promise<void>;
              close: () => Promise<void>;
            }>;
          }>;
        } | null;
        const handle = await root?.getFileHandle?.(name, { create: true });
        const writable = await handle?.createWritable?.();
        if (!writable) return null;
        await writable.write('1');
        await writable.close();
        return null;
      })().then(
        () => null,
        (error) => error
      ),
      300,
      null
    );
  } catch {
    failure = null;
  }
  try {
    const root = (await storage.getDirectory()) as
      | { removeEntry?: (name: string) => Promise<void> }
      | undefined;
    await root?.removeEntry?.(name);
  } catch {
    /* best-effort cleanup */
  }
  if (!failure) return NO_PRIVATE_SIGNAL;
  const classified = classifyPrivateError(failure);
  if (errorLooksLike(failure, /SecurityError|NotAllowedError/i)) {
    return { literal: classified.literal, restricted: true };
  }
  return classified;
}

interface ChromiumAuxiliarySignals {
  /** Decisive: an API rejection literally named private browsing. */
  literal: boolean;
  /** Corroboration: an OTR-consistent API restriction, never sufficient alone. */
  restricted: boolean;
  /** Weak context (quota / UA-CH / legacy chrome surface) — telemetry only. */
  weak: boolean;
}

/**
 * Chromium-only, strictly FAIL-OPEN auxiliary private-browsing probes.
 *
 * Every sub-probe contributes evidence ONLY when an API that works in a normal
 * profile is restricted, or when an error literally names private browsing.
 * Missing APIs, silence, timeouts and unrelated failures always mean
 * "no evidence" — never "normal", never "private". Generic OTR-shaped denials
 * can only corroborate the IndexedDB ratio; only literal private-mode wording
 * may decide incognito outright. No mobile/desktop assumptions are involved.
 */
async function probeChromiumAuxiliarySignals(
  ua: string,
  quotaBytes: number | null
): Promise<ChromiumAuxiliarySignals> {
  const errors: PrivateErrorClass[] = [];
  let weak = false;

  // (a) Storage estimate: legacy OTR reported a quota far below the JS heap limit,
  // while the modern static quota (usage + ~10 GiB) always sits well above it in a
  // normal profile. Weak context only — never allowed to decide anything.
  try {
    const heap = readJsHeapSizeLimit();
    if (quotaBytes !== null && heap !== null && quotaBytes < heap * 0.8) weak = true;
  } catch {
    /* ignore */
  }

  // (b) Credential Management and CookieStore restrictions in off-the-record
  // profiles. Silent password-only reads; no UI, writes or side effects.
  try {
    const credentials = typeof navigator !== 'undefined' ? navigator.credentials : undefined;
    if (credentials && typeof credentials.get === 'function') {
      const requestOptions = { password: true, mediation: 'silent' } as CredentialRequestOptions;
      const failure = await withDeadline<unknown>(
        Promise.resolve()
          .then(() => credentials.get(requestOptions))
          .then(
            () => null,
            (error) => error
          ),
        250,
        null
      );
      if (failure) {
        const classified = classifyPrivateError(failure);
        if (classified.literal) errors.push(classified);
        else if (classified.restricted && errorLooksLike(failure, /NotAllowedError|SecurityError/i)) {
          errors.push({ literal: false, restricted: true });
        }
      }
    }
  } catch {
    /* ignore */
  }
  try {
    const cookieStore =
      typeof window !== 'undefined'
        ? (window as unknown as { cookieStore?: { getAll?: () => Promise<unknown> } }).cookieStore
        : undefined;
    if (cookieStore && typeof cookieStore.getAll === 'function') {
      const failure = await withDeadline<unknown>(
        Promise.resolve()
          .then(() => cookieStore.getAll!())
          .then(
            () => null,
            (error) => error
          ),
        250,
        null
      );
      if (failure) {
        const classified = classifyPrivateError(failure);
        if (classified.literal) errors.push(classified);
        else if (classified.restricted && errorLooksLike(failure, /NotAllowedError|SecurityError/i)) {
          errors.push({ literal: false, restricted: true });
        }
      }
    }
  } catch {
    /* ignore */
  }

  // (c) User-Agent Client Hints: literal private-mode rejections are decisive;
  // a missing low-entropy brand list on a UA-CH-capable engine is weak context.
  try {
    const uaData =
      typeof navigator !== 'undefined'
        ? (navigator as unknown as {
            userAgentData?: {
              brands?: unknown;
              getHighEntropyValues?: (hints: string[]) => Promise<unknown>;
            };
          }).userAgentData
        : undefined;
    if (uaData) {
      if (typeof uaData.getHighEntropyValues === 'function') {
        const failure = await withDeadline<unknown>(
          Promise.resolve()
            .then(() =>
              uaData.getHighEntropyValues!(['architecture', 'bitness', 'model', 'platformVersion'])
            )
            .then(
              () => null,
              (error) => error
            ),
          250,
          null
        );
        if (failure) {
          const classified = classifyPrivateError(failure);
          if (classified.literal) errors.push(classified);
        }
      }
      if (!Array.isArray(uaData.brands) || uaData.brands.length === 0) weak = true;
    }
  } catch {
    /* ignore */
  }

  // (d) Legacy Chrome surface: Chrome <= 71 hides `chrome.loadTimes` in incognito
  // but exposes it in ordinary windows. Newer Chrome removed it for everyone, so
  // absence there is never evidence. No mobile/desktop assumptions here.
  try {
    const chromeObject =
      typeof window !== 'undefined'
        ? (window as unknown as { chrome?: Record<string, unknown> }).chrome
        : undefined;
    if (chromeObject) {
      const match = /(?:Chrome|Chromium)\/(\d+)/.exec(ua);
      const major = match ? Number.parseInt(match[1], 10) : 0;
      if (major > 0 && major <= 71 && !('loadTimes' in chromeObject)) weak = true;
    }
  } catch {
    /* ignore */
  }

  // (e) Cache Storage writes (and OPFS writes via `probeChromiumOpfsWrite`):
  // a literal private-mode rejection decides, a generic security denial only
  // corroborates, quota failures and timeouts mean "no evidence".
  try {
    const cacheStorage = typeof caches !== 'undefined' ? caches : undefined;
    if (cacheStorage && typeof cacheStorage.open === 'function') {
      const name = '__intel_pb_cache_' + Math.random().toString(36).slice(2);
      const failure = await withDeadline<unknown>(
        Promise.resolve()
          .then(() => cacheStorage.open(name))
          .then((cache) =>
            cache.put('intel-pb-probe', new Response('1'))
          )
          .then(
            () => null,
            (error) => error
          ),
        300,
        null
      );
      void Promise.resolve(cacheStorage.delete(name)).catch(() => {
        /* best-effort cleanup */
      });
      if (failure && !errorLooksLike(failure, /QuotaExceededError/i)) {
        const classified = classifyPrivateError(failure);
        if (classified.literal) errors.push(classified);
        else if (classified.restricted) errors.push({ literal: false, restricted: true });
      }
    }
  } catch {
    /* ignore */
  }

  const merged = mergePrivateSignals(...errors);
  return { literal: merged.literal, restricted: merged.restricted, weak };
}

/**
 * Firefox IndexedDB probe: a private window refuses the open with
 * `InvalidStateError`. Returns `null` when the probe is inconclusive.
 */
async function probeFirefoxIdbPrivacy(): Promise<boolean | null> {
  if (typeof indexedDB === 'undefined') return null;
  const dbName = 'inPrivate';

  return new Promise<boolean | null>((resolve) => {
    let settled = false;
    const finish = (value: boolean | null): void => {
      if (settled) return;
      settled = true;
      try {
        indexedDB.deleteDatabase(dbName);
      } catch {
        // Ignore cleanup failures.
      }
      resolve(value);
    };

    const timer = setTimeout(() => finish(null), 700);

    let request: IDBOpenDBRequest;
    try {
      request = indexedDB.open(dbName, 1);
    } catch (error) {
      clearTimeout(timer);
      finish(errorLooksLike(error, /InvalidStateError/) ? true : null);
      return;
    }

    request.onupgradeneeded = () => {
      try {
        request.result.createObjectStore('s');
      } catch {
        // Ignore store creation failures.
      }
    };
    request.onsuccess = () => {
      clearTimeout(timer);
      try {
        request.result.close();
      } catch {
        // Ignore close failures.
      }
      finish(false);
    };
    request.onerror = (event: Event) => {
      event.preventDefault?.();
      clearTimeout(timer);
      finish(request.error?.name === 'InvalidStateError' ? true : null);
    };
    request.onblocked = () => {
      clearTimeout(timer);
      finish(null);
    };
  });
}

/**
 * Safari IndexedDB probe: private windows reject Blob values with
 * "Blobs are not yet supported". Returns `null` when inconclusive.
 */
async function probeSafariIdbBlob(): Promise<boolean | null> {
  if (typeof indexedDB === 'undefined' || typeof Blob === 'undefined') return null;
  const dbName = '__intel_sf_blob';

  return new Promise<boolean | null>((resolve) => {
    let settled = false;
    const finish = (value: boolean | null): void => {
      if (settled) return;
      settled = true;
      try {
        indexedDB.deleteDatabase(dbName);
      } catch {
        // Ignore cleanup failures.
      }
      resolve(value);
    };
    const fromError = (error: unknown): boolean | null =>
      errorLooksLike(error, /are not yet supported/i) ? true : null;

    const timer = setTimeout(() => finish(null), 700);

    let request: IDBOpenDBRequest;
    try {
      request = indexedDB.open(dbName, 1);
    } catch (error) {
      clearTimeout(timer);
      finish(fromError(error));
      return;
    }

    request.onupgradeneeded = () => {
      try {
        request.result.createObjectStore('t', { autoIncrement: true });
      } catch {
        // Ignore store creation failures.
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      let tx: IDBTransaction;
      try {
        tx = db.transaction('t', 'readwrite');
      } catch (error) {
        clearTimeout(timer);
        try {
          db.close();
        } catch {
          // Ignore close failures.
        }
        finish(fromError(error));
        return;
      }
      const closeDb = () => {
        clearTimeout(timer);
        try {
          db.close();
        } catch {
          // Ignore close failures.
        }
      };
      tx.oncomplete = () => {
        closeDb();
        finish(false);
      };
      tx.onerror = tx.onabort = () => {
        closeDb();
        finish(fromError(tx.error));
      };
      try {
        tx.objectStore('t').put(new Blob());
      } catch (error) {
        closeDb();
        finish(fromError(error));
      }
    };
    request.onerror = () => {
      clearTimeout(timer);
      finish(fromError(request.error));
    };
    request.onblocked = () => {
      clearTimeout(timer);
      finish(null);
    };
  });
}

/**
 * Legacy Chromium temporary-storage quota (`queryUsageAndQuota`).
 * Returns `null` when the API is absent or silent.
 */
async function queryWebkitTemporaryQuota(): Promise<number | null> {
  const webkit =
    typeof navigator !== 'undefined'
      ? (
          navigator as unknown as {
            webkitTemporaryStorage?: {
              queryUsageAndQuota?: (
                success: (usage: number, quota: number) => void,
                error?: (error: unknown) => void
              ) => void;
            };
          }
        ).webkitTemporaryStorage
      : undefined;
  const query = webkit?.queryUsageAndQuota;
  if (!webkit || typeof query !== 'function') return null;

  return new Promise<number | null>((resolve) => {
    let settled = false;
    const finish = (value: number | null): void => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), 400);
    try {
      query.call(
        webkit,
        (_usage: number, quota: number) => {
          clearTimeout(timer);
          finish(typeof quota === 'number' && Number.isFinite(quota) && quota > 0 ? quota : null);
        },
        () => {
          clearTimeout(timer);
          finish(null);
        }
      );
    } catch {
      clearTimeout(timer);
      finish(null);
    }
  });
}

/**
 * Reads V8's `performance.memory.jsHeapSizeLimit` when exposed.
 */
function readJsHeapSizeLimit(): number | null {
  try {
    const memory =
      typeof performance !== 'undefined'
        ? (performance as unknown as { memory?: { jsHeapSizeLimit?: number } }).memory
        : undefined;
    const limit = memory?.jsHeapSizeLimit;
    return typeof limit === 'number' && Number.isFinite(limit) && limit > 0 ? limit : null;
  } catch {
    return null;
  }
}

/**
 * Resolves a human-readable browser name for the engine family.
 */
function resolveBrowserName(
  engine: 'chromium' | 'firefox' | 'safari',
  ua: string,
  nav: Navigator | undefined
): string {
  try {
    if (engine === 'firefox') return 'Firefox';
    if (engine === 'safari') return 'Safari';
    // Electron embeds Chromium but is a different binary; keep the runtime label honest.
    if (detectRuntimeFacts(ua).electron) return 'Electron';
    const brave = nav ? (nav as unknown as { brave?: unknown }).brave : undefined;
    if (brave !== undefined) return 'Brave';
    if (/Edg\//.test(ua)) return 'Edge';
    if (/OPR\//.test(ua)) return 'Opera';
    if (/Chrome|Chromium/.test(ua)) return 'Chrome';
    return 'Browser';
  } catch {
    return 'Browser';
  }
}

/**
 * Versioned key for the authoritative, monotonic per-tab incognito lock.
 *
 * Bump this constant ONLY when the shape or the detection semantics change in a way
 * that must invalidate verdicts cached by an earlier version of the app. All loads of
 * the same tab in the same app version read this cache FIRST and return it verbatim.
 */
const INCOGNITO_SESSION_LOCK_KEY = 'intel_fp_incognito_lock_v5';
const INCOGNITO_LOCK_VERSION = 5;

/**
 * Reads the authoritative per-tab verdict.
 *
 * This outranks every ephemeral heuristic: a cached verdict is returned exactly as
 * written, including its raw probe details (`idbDurabilityRatio`, `opfsFlushMs`,
 * `headroomGiB`) and its confidence label. Touch capability, screen geometry, DPR,
 * language and timezone are NEVER consulted here, so none of them can flip the answer
 * on reload. Safe if sessionStorage is blocked or the entry is corrupt.
 */
function readIncognitoSessionLock(): IncognitoDetectionResult | null {
  try {
    if (typeof sessionStorage === 'undefined') return null;
    const raw = sessionStorage.getItem(INCOGNITO_SESSION_LOCK_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as IncognitoDetectionResult & { lockVersion?: number };
    if (
      parsed &&
      typeof parsed === 'object' &&
      parsed.lockVersion === INCOGNITO_LOCK_VERSION &&
      typeof parsed.isPrivate === 'boolean' &&
      typeof parsed.method === 'string' &&
      typeof parsed.browserName === 'string' &&
      (parsed.confidence === 'high' || parsed.confidence === 'low')
    ) {
      // Only a HIGH-confidence verdict is authoritative. Low-confidence
      // "inconclusive"/"normal" entries must NEVER pin a tab: a fresh run with
      // decisive private-storage evidence has to be able to override them.
      if (parsed.confidence !== 'high') return null;
      return { ...parsed, isPrivate: Boolean(parsed.isPrivate) };
    }
  } catch {
    // Storage blocked or a corrupt entry: ignore and re-probe.
  }
  return null;
}

/**
 * Re-check used ONLY when a high-confidence *normal* lock would otherwise
 * short-circuit detection. A decisive OPFS entry-point rejection in a top-level,
 * non-persistent context cannot occur in an ordinary profile, so it proves the
 * cached normal verdict is stale and forces a fresh probe. Fails open in every
 * ambiguous case (the cache stands).
 */
async function cachedNormalIsStale(): Promise<boolean> {
  try {
    if (await hasPersistedStorageGrant()) return false;
    if (isIsolatedStorageContext()) return false;
    if (opfsRejectionIsDecisive(await probeOpfsDirectory())) return true;
    // getDirectory() often resolves in modern incognito, so also re-check the
    // OPFS write path before honoring a cached "normal" verdict.
    const write = await probeChromiumOpfsWrite();
    return write.literal || write.restricted;
  } catch {
    return false;
  }
}

/**
 * Writes the authoritative per-tab verdict. Only HIGH-confidence verdicts are cached:
 * a low-confidence "inconclusive"/"normal" result is intentionally NOT made
 * authoritative, so a later run in the same tab can still pick up decisive evidence.
 */
function writeIncognitoSessionLock(result: IncognitoDetectionResult): void {
  try {
    if (typeof sessionStorage === 'undefined') return;
    if (result.confidence !== 'high') return;
    sessionStorage.setItem(
      INCOGNITO_SESSION_LOCK_KEY,
      JSON.stringify({ ...result, lockVersion: INCOGNITO_LOCK_VERSION })
    );
  } catch {
    // Storage blocked: the in-memory cache still serves this page load.
  }
}

/**
 * Hard veto: a readable first-party persistent marker proves a durable profile, so
 * incognito MUST be false regardless of any noisy physics probe. Checks the client
 * visitor cookie and the durable localStorage visitor/identity tokens. Every access is
 * try/catch-guarded and read-only — no storage is created or written. This veto is
 * applied to freshly computed verdicts (the cached lock is returned verbatim, but the
 * first load's verdict already folds the veto in, keeping the tab answer stable).
 */
function hasFirstPartyPersistentMarker(): boolean {
  try {
    if (
      typeof document !== 'undefined' &&
      /(?:^|;\s*)intel_client_vid=/.test(document.cookie || '')
    ) {
      return true;
    }
  } catch {
    // Cookie access blocked.
  }
  try {
    if (
      typeof localStorage !== 'undefined' &&
      (localStorage.getItem(STORAGE_KEYS.VISITOR_ID) ||
        localStorage.getItem(STORAGE_KEYS.VISITOR_TOKEN) ||
        localStorage.getItem('_intel_identity_v4'))
    ) {
      return true;
    }
  } catch {
    // localStorage access blocked.
  }
  return false;
}

/**
 * Apply the first-party persistent-marker veto to a freshly computed verdict. Returns a
 * new, normalized result whose `isPrivate` is false with a durable-profile method note
 * whenever a persistent marker is readable. Confidence is preserved (the marker only
 * makes a verdict more certainly negative), and the low-confidence invariant holds.
 */
function applyPersistentMarkerVeto(result: IncognitoDetectionResult): IncognitoDetectionResult {
  if (!result.isPrivate || !hasFirstPartyPersistentMarker()) return result;
  return {
    ...result,
    isPrivate: false,
    method: `${result.method}; first-party persistent marker veto (normal profile)`,
  };
}

/**
 * Final normalization applied to every freshly computed verdict before it is cached.
 * A readable first-party persistent marker is a hard veto (incognito = false), and a
 * low-confidence verdict can never be incognito. Touch / geometry / language are not
 * inputs here — this function only looks at the persistent-marker veto and confidence.
 */
function finalizeIncognitoVerdict(result: IncognitoDetectionResult): IncognitoDetectionResult {
  const vetoed = applyPersistentMarkerVeto(result);
  if (vetoed.confidence === 'low' && vetoed.isPrivate) {
    return { ...vetoed, isPrivate: false };
  }
  return vetoed;
}

/**
 * Multi-engine private-browsing detection (3 layers, no quota veto).
 *
 * The JS engine is fingerprinted through the `toFixed` RangeError length and
 * cross-checked against the User-Agent. Firefox and Safari expose private mode
 * as a blocked OPFS / IndexedDB write; Chromium is resolved through three
 * independent physics vectors: quota headroom, legacy temp quota, and (never
 * vetoed) storage physics — IndexedDB `strict` commit durability plus an OPFS
 * worker `flush()` timing probe. Chrome 156+ forces `quota = usage + 10.00 GiB`
 * in both modes, so the headroom band is never allowed to veto layers 3C.
 * Never throws and always fills all result fields. The verdict is cached in a
 * versioned sessionStorage lock and returned verbatim on later loads of this tab.
 */
export async function detectIncognitoMode(): Promise<IncognitoDetectionResult> {
  if (cachedIncognitoPromise) return cachedIncognitoPromise;

  // Diagnostics are strictly additive: when the flag is off no object is created and
  // nothing is recorded. When on, values are copied from probes that run regardless.
  const diagEnabled = isIncognitoDiagnosticsEnabled();
  const diag: IncognitoDiagnostics | null = diagEnabled
    ? {
        enabled: true,
        engine: null,
        method: null,
        confidence: null,
        isPrivate: null,
        quotaBytes: null,
        headroomGiB: null,
        idbDurabilityRatio: null,
        idbHighVariance: null,
        opfsFlushMs: null,
        persistedStorageGrant: null,
        isolatedContextVeto: null,
        sessionLockHit: null,
        lowConfidenceVeto: null,
        clientReportedIncognito: null,
        serverWouldVeto: null,
      }
    : null;
  const noteDiag = <K extends keyof IncognitoDiagnostics>(
    key: K,
    value: IncognitoDiagnostics[K]
  ): void => {
    if (diag) diag[key] = value;
  };

  // Deterministic per-session lock: reuse a HIGH-confidence verdict computed earlier
  // in this tab — unless a fresh decisive OPFS rejection proves a cached "normal"
  // verdict stale. Low-confidence entries are never returned by the reader.
  const locked = readIncognitoSessionLock();
  if (locked && (locked.isPrivate || !(await cachedNormalIsStale()))) {
    noteDiag('sessionLockHit', true);
    if (diag) {
      noteDiag('method', locked.method);
      noteDiag('confidence', locked.confidence);
      noteDiag('isPrivate', locked.isPrivate);
      noteDiag('quotaBytes', locked.quotaBytes);
      noteDiag('headroomGiB', locked.headroomGiB);
      noteDiag('idbDurabilityRatio', locked.idbDurabilityRatio);
      noteDiag('idbHighVariance', locked.idbHighVariance ?? null);
      noteDiag('opfsFlushMs', locked.opfsFlushMs);
      noteDiag('clientReportedIncognito', locked.isPrivate);
      noteDiag('lowConfidenceVeto', false);
      noteDiag('serverWouldVeto', false);
      cachedIncognitoPromise = Promise.resolve({ ...locked, diagnostics: diag });
    } else {
      cachedIncognitoPromise = Promise.resolve(locked);
    }
    return cachedIncognitoPromise;
  }
  noteDiag('sessionLockHit', false);

  cachedIncognitoPromise = (async (): Promise<IncognitoDetectionResult> => {
    const nav = typeof navigator !== 'undefined' ? navigator : undefined;
    let ua = '';
    try {
      ua = nav?.userAgent || '';
    } catch {
      ua = '';
    }
    const feid = getEngineErrorLength();

    const isSpiderMonkey = feid === 25 || /Firefox/i.test(ua);
    const isJSC =
      feid === 44 || feid === 43 || (/Safari/i.test(ua) && !/Chrome|Chromium|Edg|OPR/i.test(ua));

    // The `(-1).toFixed(-1)` RangeError length is the deterministic engine oracle:
    // Firefox 25, WebKit 43/44 and Chromium 51 are authoritative when the probe works.
    // UA strings are only a fallback for engines that hide/change the message length.
    let engine: 'chromium' | 'firefox' | 'safari';
    if (feid === 25) {
      engine = 'firefox';
    } else if (feid === 43 || feid === 44) {
      engine = 'safari';
    } else if (feid === 51) {
      engine = 'chromium';
    } else if (isSpiderMonkey) {
      engine = 'firefox';
    } else if (isJSC) {
      engine = 'safari';
    } else {
      // Unknown engine length and no UA hint: default to the Chromium physics path,
      // which fails open rather than abstaining on the strict OPFS/IDB probes.
      engine = 'chromium';
    }

    noteDiag('engine', engine);
    const browserName = resolveBrowserName(engine, ua, nav);

    let quotaBytes: number | null = null;
    let usageBytes = 0;
    let storage: StorageManager | undefined;
    try {
      storage = nav?.storage;
    } catch {
      storage = undefined;
    }
    if (storage && typeof storage.estimate === 'function') {
      try {
        const estimate = await storage.estimate();
        if (typeof estimate.quota === 'number' && estimate.quota > 0) {
          quotaBytes = estimate.quota;
        }
        if (typeof estimate.usage === 'number' && estimate.usage > 0) {
          usageBytes = estimate.usage;
        }
      } catch {
        // Ignore storage estimate failures.
      }
    }

    // Chrome 156's StaticStorageQuota patch reports `usage + 10.00 GiB` in BOTH
    // modes, so this headroom is reported as evidence but never vetoes a probe.
    const headroomBytes = quotaBytes !== null ? quotaBytes - usageBytes : null;
    const headroomGiB =
      headroomBytes !== null ? Number((Math.max(0, headroomBytes) / GIB_BYTES).toFixed(2)) : null;
    noteDiag('quotaBytes', quotaBytes);
    noteDiag('headroomGiB', headroomGiB);
    // Weak Chromium-only context hints, reported for telemetry but never used as
    // verdict evidence (see `probeChromiumAuxiliarySignals`).
    let storagePrivateHints = false;

    try {
      if (engine === 'firefox') {
        const opfs = await probeOpfsDirectory();
        if (opfs.status === 'resolved') {
          return {
            isPrivate: false,
            browserName,
            method: METHOD_STANDARD_STORAGE,
            confidence: 'high',
            quotaBytes,
            headroomGiB,
            idbDurabilityRatio: null,
            opfsFlushMs: null,
          };
        }
        if (
          opfs.status === 'rejected' &&
          errorLooksLike(opfs.error, /Security error|SecurityError|InvalidStateError/)
        ) {
          return {
            isPrivate: true,
            browserName,
            method: METHOD_PRIVATE_STORAGE,
            confidence: 'high',
            quotaBytes,
            headroomGiB,
            idbDurabilityRatio: null,
            opfsFlushMs: null,
          };
        }

        // No OPFS at all (older Firefox) — the `inPrivate` IndexedDB open refuses
        // with InvalidStateError inside a private window. A null probe is inconclusive
        // and fails open with low confidence.
        const idbPrivate = await probeFirefoxIdbPrivacy();
        return {
          isPrivate: idbPrivate === true,
          browserName,
          method:
            idbPrivate === null
              ? METHOD_INCONCLUSIVE
              : idbPrivate
              ? METHOD_PRIVATE_STORAGE
              : METHOD_STANDARD_STORAGE,
          confidence: idbPrivate === null ? 'low' : 'high',
          quotaBytes,
          headroomGiB,
          idbDurabilityRatio: null,
          opfsFlushMs: null,
        };
      }

      if (engine === 'safari') {
        const opfs = await probeOpfsDirectory();
        if (opfs.status === 'resolved') {
          return {
            isPrivate: false,
            browserName,
            method: METHOD_STANDARD_STORAGE,
            confidence: 'high',
            quotaBytes,
            headroomGiB,
            idbDurabilityRatio: null,
            opfsFlushMs: null,
          };
        }
        if (
          opfs.status === 'rejected' &&
          errorLooksLike(opfs.error, /unknown transient reason|SecurityError|NotAllowedError/i)
        ) {
          return {
            isPrivate: true,
            browserName,
            method: METHOD_PRIVATE_STORAGE,
            confidence: 'high',
            quotaBytes,
            headroomGiB,
            idbDurabilityRatio: null,
            opfsFlushMs: null,
          };
        }

        // Private Safari still opens IndexedDB but rejects Blob values with
        // "Blobs are not yet supported". A null probe fails open with low confidence.
        const blobPrivate = await probeSafariIdbBlob();
        return {
          isPrivate: blobPrivate === true,
          browserName,
          method:
            blobPrivate === null
              ? METHOD_INCONCLUSIVE
              : blobPrivate
              ? METHOD_PRIVATE_STORAGE
              : METHOD_STANDARD_STORAGE,
          confidence: blobPrivate === null ? 'low' : 'high',
          quotaBytes,
          headroomGiB,
          idbDurabilityRatio: null,
          opfsFlushMs: null,
        };
      }

      // 3A/3B — quota headroom and legacy temp quota are weak context only. Chrome 156+
      // reports the patched 10 GiB headroom in BOTH modes, so they never assert incognito
      // and never leak into the (jargon-free) method string. `headroomGiB` stays as telemetry.

      // 3C — storage physics (best-effort, fail-open for humans). Chromium no longer
      // differs in raw quota, so we combine independent vectors:
      //   (a) OPFS getDirectory() rejection strings — a decisive private signal on their own,
      //   (b) OPFS file-write denial (getDirectory() often RESOLVES in modern incognito),
      //   (c) IndexedDB strict-commit durability ratio with interleaved rounds + deadband,
      //   (d) OPFS sync-access-handle flush timing + auxiliary fail-open API restrictions.
      // A SINGLE deterministic OPFS-family denial (a or b), or any rejection that
      // literally names private browsing, is sufficient for a high-confidence verdict.
      // Noisy vectors (c, d) still corroborate each other via the original AND gate, so
      // the deadband / high-variance case remains inconclusive rather than a false positive.
      const opfsDir = await probeOpfsDirectory();
      const opfsDirClass = classifyPrivateError(
        opfsDir.status === 'rejected' ? opfsDir.error : null
      );
      const opfsDirDecisive = opfsRejectionIsDecisive(opfsDir);

      const idbProbe = await probeChromiumIdbDurability();
      const idbRatio = idbProbe.ratio;
      const idbHighVariance = idbProbe.highVariance;
      noteDiag('idbDurabilityRatio', idbRatio);
      noteDiag('idbHighVariance', idbHighVariance);
      const opfsProbe = await probeChromiumOpfsWorkerFlush();
      const opfsFlushMs = opfsProbe ? opfsProbe.medianFlushMs : null;
      noteDiag('opfsFlushMs', opfsFlushMs);

      // Chromium deadband: below 1.12 the store is RAM-backed (private), above 1.55 it
      // is disk-backed (normal). The 1.12–1.55 band and an inconclusive ratio fail open.
      const idbVerdict: 'private' | 'normal' | 'deadband' =
        idbRatio === null
          ? 'deadband'
          : idbRatio < 1.12
          ? 'private'
          : idbRatio > 1.55
          ? 'normal'
          : 'deadband';
      const idbLowRatio = idbRatio !== null && idbRatio < 1.12;
      const opfsIndicatesIncognito =
        opfsProbe !== null &&
        (opfsProbe.medianFlushMs < 0.12 || opfsProbe.flushToWriteRatio < 0.85);

      // The OPFS write and auxiliary API probes are independent and parallel; all of
      // them fail open (no API, timeout or unrelated error = "no evidence").
      const [opfsWrite, auxiliary] = await Promise.all([
        probeChromiumOpfsWrite(),
        probeChromiumAuxiliarySignals(ua, quotaBytes),
      ]);
      storagePrivateHints = auxiliary.weak;

      // A granted persistent-storage privilege and an opaque/cross-origin context remain
      // hard vetoes. Only deterministic denials may decide incognito alone; timing and
      // generic OTR-shaped restrictions must still agree with the IndexedDB ratio.
      const idbConclusivePrivate = idbVerdict === 'private' && !idbHighVariance;
      const persistentGrant = await hasPersistedStorageGrant();
      const isolatedContext = isIsolatedStorageContext();
      noteDiag('persistedStorageGrant', persistentGrant);
      noteDiag('isolatedContextVeto', isolatedContext);
      const idbPrivateEvidence = idbConclusivePrivate || (idbLowRatio && !idbHighVariance);
      const opfsDecisive = opfsDirDecisive || opfsWrite.literal || opfsWrite.restricted;
      const opfsCorroboration =
        opfsDirClass.restricted || opfsIndicatesIncognito || auxiliary.restricted;
      const incognitoDetected =
        !persistentGrant &&
        !isolatedContext &&
        (opfsDecisive ||
          auxiliary.literal ||
          (opfsCorroboration && idbPrivateEvidence));

      if (incognitoDetected) {
        return {
          isPrivate: true,
          browserName,
          method: METHOD_PRIVATE_STORAGE,
          confidence: 'high',
          quotaBytes,
          headroomGiB,
          idbHighVariance,
          idbDurabilityRatio: idbRatio,
          opfsFlushMs,
          storagePrivateHints,
        };
      }

      const confidentNormal = persistentGrant || idbVerdict === 'normal';
      // Context-only quota hints are reported through `reasons`/telemetry, never in the
      // user-facing method string (no probe names, ratios or byte figures).
      return {
        isPrivate: false,
        browserName,
        method: confidentNormal ? METHOD_STANDARD_STORAGE : METHOD_INCONCLUSIVE,
        // 'normal' is a confident negative; the deadband / any inconclusive probe
        // fails open with low confidence (and can never mean incognito).
        confidence: confidentNormal ? 'high' : 'low',
        idbHighVariance,
        quotaBytes,
        headroomGiB,
        idbDurabilityRatio: idbRatio,
        opfsFlushMs,
        storagePrivateHints,
      };
    } catch {
      return {
        isPrivate: false,
        browserName,
        method: METHOD_INCONCLUSIVE,
        confidence: 'low',
        quotaBytes,
        headroomGiB,
        idbDurabilityRatio: null,
        opfsFlushMs: null,
        storagePrivateHints,
      };
    }
  })().then((result) => {
    // Every return path — deterministic Firefox/WebKit branches, Chromium physics and
    // fail-open branches — is normalized here before the lock write, so the cached
    // verdict is always complete and low-confidence never means incognito.
    const finalized = finalizeIncognitoVerdict(result);
    // Diagnostics are derived from the finalized verdict, never from any decision input.
    if (diag) {
      noteDiag('method', finalized.method);
      noteDiag('confidence', finalized.confidence);
      noteDiag('isPrivate', finalized.isPrivate);
      noteDiag('clientReportedIncognito', finalized.isPrivate);
      // Mirror the server's confidence gate (server.ts: low label / numeric < 0.9 is a
      // hard veto). This is a readout of an existing decision, never a new veto path.
      const lowVeto = finalized.confidence === 'low';
      noteDiag('lowConfidenceVeto', lowVeto);
      noteDiag('serverWouldVeto', lowVeto);
      return { ...finalized, diagnostics: diag };
    }
    writeIncognitoSessionLock(finalized);
    return finalized;
  });

  return cachedIncognitoPromise;
}

const EMBEDDED_SHELL_PATTERN = /Electron|HeadlessChrome|; wv\)|FBAN|FBAV/i;

/**
 * A granted persistent-storage permission can only exist in a normal profile,
 * so it is decisive negative evidence.
 */
async function hasPersistedStorageGrant(): Promise<boolean> {
  const storage =
    typeof navigator !== 'undefined' ? (navigator.storage as StorageManager | undefined) : undefined;
  if (!storage || typeof storage.persisted !== 'function') return false;
  try {
    return await storage.persisted();
  } catch {
    return false;
  }
}

/**
 * An isolated / partitioned storage context (an opaque `null` origin, a sandboxed or
 * cross-origin frame) can reject OPFS and show RAM-backed IndexedDB timing WITHOUT being
 * a real private-browsing window. Such contexts must fail open — never `incognito: true`.
 */
function isIsolatedStorageContext(): boolean {
  try {
    if (typeof window === 'undefined') return false;
    if (typeof location !== 'undefined' && location.origin === 'null') return true;
    // Any embedded frame has partitioned / delegated storage permissions, so it
    // must abstain even when it happens to be same-origin with the top window.
    const top = window.top;
    if (top && top !== window) return true;
  } catch {
    return false;
  }
  return false;
}

/**
 * Confidence / evidence plumbing around the engine verdict. Embedded shells
 * (Electron/WebView) often run on memory-backed storage in every mode, so the
 * engine verdict abstains there instead of producing a false positive.
 */
async function assessPrivateBrowsing(
  hasStoredIdentity: boolean,
  verdict: IncognitoDetectionResult
): Promise<PrivateBrowsingAssessment> {
  const reasons: string[] = [];
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';
  const isEmbeddedShell = EMBEDDED_SHELL_PATTERN.test(ua);
  const quotaMb =
    verdict.quotaBytes !== null ? Math.round(verdict.quotaBytes / (1024 * 1024)) : null;

  let likely = verdict.isPrivate;
  let logit = verdict.isPrivate ? 3.2 : -3.2;

  reasons.push(`Engine verdict: ${verdict.browserName} via ${verdict.method}`);

  if (isEmbeddedShell) {
    likely = false;
    logit = Math.log(0.05 / 0.95);
    reasons.push('Embedded shell runtime (Electron/WebView) — engine verdict abstained');
  } else if (verdict.headroomGiB !== null) {
    reasons.push(`Storage headroom ${verdict.headroomGiB.toFixed(2)} GiB`);
  }
  if (!isEmbeddedShell && verdict.idbDurabilityRatio !== null) {
    reasons.push(`IndexedDB strict commit ${verdict.idbDurabilityRatio.toFixed(2)}x relaxed`);
  }

  // Blocked first-party writes are ephemeral by definition.
  try {
    const probeKey = '__intel_pb_write__';
    localStorage.setItem(probeKey, '1');
    localStorage.removeItem(probeKey);
  } catch {
    logit += 2;
    likely = true;
    reasons.push('First-party storage write blocked');
  }

  // An identity that survived a previous load is evidence of a durable profile,
  // but a reload inside the same private window also carries one, so it only
  // nudges the verdict.
  if (hasStoredIdentity) {
    logit -= 0.8;
    reasons.push('Existing first-party identity present');
  }

  let cookieIdentityPresent = false;
  try {
    cookieIdentityPresent =
      typeof document !== 'undefined'
        ? /(?:^|;\s*)intel_client_vid=/.test(document.cookie || '')
        : false;
  } catch {
    cookieIdentityPresent = false;
  }
  if (cookieIdentityPresent) {
    logit -= 0.5;
    reasons.push('First-party identity cookie present');
  }

  const confidence = Number(
    Math.max(0.01, Math.min(0.99, 1 / (1 + Math.exp(-logit)))).toFixed(3)
  );
  return { likely, confidence, quotaMb, reasons };
}

/**
 * Private / Incognito browsing assessment.
 * Delegates the primary verdict to `detectIncognitoMode()` and layers the
 * durable-identity / first-party-storage evidence on top.
 */
export async function detectPrivateBrowsing(
  hasStoredIdentity: boolean
): Promise<PrivateBrowsingAssessment> {
  if (await hasPersistedStorageGrant()) {
    return {
      likely: false,
      confidence: 0,
      quotaMb: null,
      reasons: ['Persistent storage already granted (normal profile)'],
    };
  }
  return assessPrivateBrowsing(hasStoredIdentity, await detectIncognitoMode());
}

/**
 * Privacy-hardened classifier. Tor Browser (RFP), Firefox FPP/RFP, Brave shields and
 * Safari 26 ATFP deliberately reduce or randomise entropy. Those are privacy defences,
 * never anti-detect browser evidence. Used to exempt such runtimes from tampering rules.
 */
export function isPrivacyHardenedRuntime(
  userAgent: string,
  torConfirmed: boolean,
  browserLabel = ''
): boolean {
  if (torConfirmed) return true;
  const ua = userAgent || browserLabel || '';
  if (/Firefox\/|FxiOS\//i.test(ua)) return true;
  // Safari 26+ Automatic Transparent Fingerprinting Protection.
  if (/Version\/2[6-9](?:\.|$)/.test(ua) && /Safari\//i.test(ua) && !/Chrome|Chromium|Edg|OPR/i.test(ua)) {
    return true;
  }
  try {
    const brave = (navigator as unknown as {
      brave?: { isBrave?: unknown };
    }).brave;
    if (brave && typeof brave.isBrave === 'function') return true;
  } catch {
    // A hostile navigator proxy is not evidence.
  }
  return false;
}

/**
 * Additive provenance layered onto the security payload. All fields are context/telemetry:
 * none of them is a second bot verdict or a hardware-id anchor.
 */
export interface ClientProvenanceSignals extends ClientRuntimeSignals {
  /** Four-state GPU observation (explicit identifiers only). Never a VM verdict. */
  gpuObservation: GpuObservation;
  /** Canonical server reason ids mapped from STRONG collector CDP probes. */
  cdpReasonIds: string[];
  /** True only from the two-probe Runtime proof — a weak Error.name preview never sets this. */
  cdpAttached: boolean;
}

export type SecuritySignalsWithProvenance = SecuritySignals & ClientProvenanceSignals;

/**
 * Evaluates First-Party Security & Anomaly Signals ("Smart Signals") and computes an
 * explainable Suspect & Risk Score (0-10).
 */
export async function evaluateSecuritySignals(
  browserDevice: BrowserDeviceInfo,
  hardwareSignals: HardwareSignals & { gpuClass?: string; gpuObservation?: GpuObservation },
  clientGeoHint: ClientGeoHint | null,
  hasStoredIdentity: boolean
): Promise<SecuritySignalsWithProvenance> {
  // 1. Automation & Headless Bot Detection (CDP bindings, native prototype checks).
  // Snapshot the CDP bridge once, up front, so the dwell decision and the authoritative
  // detector read the same probe result. A real person with DevTools open, an Electron shell
  // or an IDE webview gets the benefit of the bounded dwell / docked-host exemption; a
  // stealth runtime with no trusted input after the window is escalated below.
  const stealthSnapshot = detectStealthArtifacts(hardwareSignals.gpuRenderer);
  let uaSnapshot = '';
  try {
    uaSnapshot = typeof navigator !== 'undefined' ? navigator.userAgent || '' : '';
  } catch {
    // Hostile navigator proxy: leave the UA unknown.
  }
  const runtimeHostSnapshot = detectAutomationEnvironment(uaSnapshot, hardwareSignals.gpuRenderer);
  const bridgeSnapshot = collectCdpBridgeEvidence(stealthSnapshot, uaSnapshot);
  const exemptDockedHost =
    hasDockedDevToolsLayout() ||
    runtimeHostSnapshot.electron ||
    runtimeHostSnapshot.ideWebview;
  const dwellAwaited = await awaitCdpCorroborationWindow(
    bridgeSnapshot.length > 0 && !exemptDockedHost
  );
  // Fresh, post-interaction corroboration — never a value cached at page load.
  const humanSnapshot = measureHumanCorroboration(hardwareSignals.gpuRenderer);
  const botAssessment = detectBotAndAutomation(hardwareSignals.gpuRenderer, {
    stealth: stealthSnapshot,
    human: humanSnapshot,
    dwellAwaited,
  });
  const botSignals: string[] = botAssessment.isBot
    ? (botAssessment.botSignals && botAssessment.botSignals.length > 0
        ? botAssessment.botSignals
        : [botAssessment.botReason])
    : [];

  // Map the collector's human-readable probe names onto canonical server reason ids. Weak
  // engine-dependent artifacts (notably the Error.prototype.name preview) map to null and can
  // never become a "CDP attached" claim; only the two-probe proof yields a CDP reason id.
  const cdpReasonIds = Array.from(
    new Set(
      [...stealthSnapshot.stealthReasons, ...bridgeSnapshot, ...botSignals]
        .map(mapCollectorProbeToReasonId)
        .filter((id): id is string => Boolean(id))
    )
  );
  const clientRuntime = detectClientRuntime(uaSnapshot);
  const gpuObservation: GpuObservation =
    hardwareSignals.gpuObservation ??
    resolveGpuObservation(
      hardwareSignals.gpuVendor,
      hardwareSignals.gpuRenderer,
      hardwareSignals.gpuClass ?? ''
    );

  // 2. VPN / Proxy & Network Classification (Task 1 classifier)
  const browserTimezone = browserDevice.timezone || 'Unavailable';
  const ipTimezone =
    clientGeoHint?.timezone && clientGeoHint.timezone !== 'Unknown'
      ? clientGeoHint.timezone
      : 'Unavailable';

  // Raw browser timezone is emitted above; the mismatch itself is derived ONLY by the
  // canonical alias-folding helper (no raw `!==` comparison).
  const timezoneMismatch = isCanonicalTimezoneMismatch(browserTimezone, ipTimezone);

  const classification = classifyIspNetwork(
    clientGeoHint?.isp ?? '',
    clientGeoHint?.org ?? '',
    clientGeoHint?.asn ?? ''
  );

  const isConsumerBroadband = classification.isConsumerBroadband;
  let brandName = classification.brandName;
  let networkType: NetworkType = classification.networkType;
  let ispNetworkReason = classification.matchedReason;
  // Consumer broadband can never be promoted to datacenter / hosting, even when the
  // IP intelligence provider flags the connection as proxy or VPN.
  let isDatacenterOrHosting = isConsumerBroadband ? false : classification.isDatacenterOrHosting;

  if (clientGeoHint?.isVpnOrHosting && !isConsumerBroadband) {
    brandName = 'VPN / Proxy Hosting';
    networkType = CLOUD_DATACENTER;
    isDatacenterOrHosting = true;
    ispNetworkReason = ispNetworkReason
      ? `${ispNetworkReason}; provider flagged VPN or hosting routing`
      : 'IP intelligence provider flagged hosting, proxy, or VPN routing';
  }

  const datacenterAsn = isDatacenterOrHosting;

  const maskedGpu = isMaskedOrUnavailableGpu(
    hardwareSignals.gpuVendor,
    hardwareSignals.gpuRenderer
  );
  const cloudOrMaskedGpu = datacenterAsn && maskedGpu;

  const vpnReasons: string[] = [];
  if (timezoneMismatch) {
    vpnReasons.push(`Browser timezone (${browserTimezone}) differs from IP timezone (${ipTimezone})`);
  }
  if (datacenterAsn && ispNetworkReason) {
    vpnReasons.push(ispNetworkReason);
  }
  if (cloudOrMaskedGpu) {
    vpnReasons.push('Cloud / Masked GPU environment');
  }
  // A timezone discrepancy is an orthogonal context axis, never VPN evidence. Only concrete
  // network/anonymity evidence (hosting/proxy ASN, provider-flagged VPN routing) may create a
  // VPN suspicion. `timezoneMismatch` stays intact below for vpnMethods/event output.
  const vpnSuspected = datacenterAsn;

  // 3. VM / Hypervisor & OS Identity Integrity (WebGL GPU + native accessors)
  const vmStatus = detectVmAndIntegrity(hardwareSignals.gpuVendor, hardwareSignals.gpuRenderer, {
    screenResolution: browserDevice.screenResolution,
    datacenterAsn,
  });
  const tamperReasons: string[] = [];
  // A virtual machine / software rasterizer is an environment signal (the VM card), not
  // evidence of active tampering. Counting it as tamperDetected pushed plain SwiftShader
  // headless sessions into the 9/10 critical tier. Only OS/UA integrity breaks belong here.
  if (vmStatus.isOsTampered) {
    tamperReasons.push(vmStatus.vmReason);
  }
  const tamperDetected = vmStatus.isOsTampered;

  // 3b. Mobile emulator / iOS simulator evidence (Phase 3). The client-side derivation
  // uses the same predicates the server applies, so the `emulatorDetected` verdict is
  // produced even when the raw navigator probe above stayed silent. The OR keeps the
  // existing detector authoritative — nothing it flagged can be demoted here.
  const emulatorEvidence = detectEmulatorEvidence({
    platform: browserDevice.platform,
    maxTouchPoints: hardwareSignals.maxTouchPoints,
    gpuVendor: hardwareSignals.gpuVendor,
    gpuRenderer: hardwareSignals.gpuRenderer,
    screenResolution: browserDevice.screenResolution,
  });
  const emulatorDetected = vmStatus.emulatorDetected || emulatorEvidence.detected;
  const emulatorReason = vmStatus.emulatorDetected
    ? vmStatus.emulatorReason || emulatorEvidence.reason
    : emulatorEvidence.reason;

  // 4. Private Mode / Incognito Inspection (multi-engine physics)
  const incognito = await detectIncognitoMode();
  const persistentStorageGrant = await hasPersistedStorageGrant();
  // The per-tab session lock is authoritative and already carries the first-party
  // persistent-marker veto (applied once, when the lock was first computed). Do NOT
  // re-apply an identity-based veto here: the app writes its own visitor token into
  // first-party storage on the first identify, so that token appears on the NEXT reload
  // and would flip a stable incognito verdict from yes to no — the exact reported bug.
  const incognitoVerified = incognito.isPrivate;
  const privateBrowsing = persistentStorageGrant
    ? {
        likely: false,
        confidence: 0,
        quotaMb:
          incognito.quotaBytes !== null
            ? Math.round(incognito.quotaBytes / (1024 * 1024))
            : null,
        reasons: ['Persistent storage already granted (normal profile)'],
      }
    : await assessPrivateBrowsing(hasStoredIdentity, incognito);
  const storageQuotaMb = privateBrowsing.quotaMb;
  // Stable verdict: `incognitoVerified` comes from the authoritative session lock and
  // already folds in the persistent-marker veto and the low-confidence fail-open rule.
  // It never reads the volatile localStorage write probe, so a reload or a storage
  // permission change cannot flip the incognito flag for this tab.
  const incognitoLikely = incognitoVerified;

  let localStorageAvailable = true;
  try {
    const probeKey = '__intel_storage_probe__';
    localStorage.setItem(probeKey, '1');
    localStorage.removeItem(probeKey);
  } catch {
    // Telemetry only — a blocked first-party write must never flip the incognito verdict.
    localStorageAvailable = false;
  }

  // Ephemeral-identity clearance is decided server-side (hardware ID recovery);
  // the browser only knows whether a stored identity exists, so this column stays
  // false here by design.
  const incognitoOrCleared = false;

  // Tor Browser client fingerprint (Gecko + RFP + letterboxing). Runs independently of the
  // server's exit-relay verdict: a Tor Browser user on a non-exit network still exposes RFP.
  const torBrowserClient = detectTorBrowserClient(
    browserDevice,
    hardwareSignals,
    incognito.method
  );

  // Browser tampering — DevTools Device Mode emulation and anti-detect browsers. Compares
  // engine, platform, touch, viewport and GPU invariants rather than trusting one getter.
  // Canvas attributes are collected here once and reused for both the event payload and the
  // verdict: per-read pixel noise (farbling) is active spoofing, not a privacy preference.
  const rawDeviceAttributes = await collectRawDeviceAttributes();
  const canvasNoiseDetected = Boolean(
    (rawDeviceAttributes as ({ canvas?: { noise?: boolean } } | null))?.canvas?.noise
  );
  const privacyHardened = isPrivacyHardenedRuntime(
    typeof navigator !== 'undefined' ? navigator.userAgent || '' : '',
    torBrowserClient.confirmed,
    browserDevice.browser
  );
  const tampering = detectBrowserTampering({
    webglVendor: hardwareSignals.gpuVendor,
    webglRenderer: hardwareSignals.gpuRenderer,
    privacyHardened,
  });

  // The genuine-device gate adds hard evidence the generic detector cannot see:
  // a mobile UA over x86/desktop-GPU silicon. Escalate to a tampering verdict so
  // the Browser Tampering tile and Event JSON both reflect the emulation.
  if (
    browserDevice.devtoolsDeviceEmulation &&
    !tampering.tampering_details.devtools_device_emulation
  ) {
    tampering.tampering = true;
    tampering.tampering_confidence = 'high';
    tampering.tampering_ml_score = Math.max(0.842, tampering.tampering_ml_score);
    tampering.tampering_details.devtools_device_emulation = true;
    tampering.tampering_details.anomaly_score = Math.max(
      0.55,
      tampering.tampering_details.anomaly_score
    );
    tampering.tampering_details.reasons = [
      ...tampering.tampering_details.reasons,
      'Mobile user-agent on desktop x86/GPU hardware (DevTools device emulation)',
    ];
  }

  // Canvas farbling injects different pixels on every read. It is a privacy defence
  // (Brave / Safari / Tor RFP), not an automation signature: keep the tampering verdict but
  // do NOT set `anti_detect_browser`, which is the hard bot gate on the server.
  if (canvasNoiseDetected) {
    tampering.tampering = true;
    tampering.tampering_confidence = 'high';
    tampering.tampering_ml_score = Math.max(0.72, tampering.tampering_ml_score);
    tampering.tampering_details.anomaly_score = Math.max(
      0.6,
      tampering.tampering_details.anomaly_score
    );
    if (!tampering.tampering_details.reasons.some((reason) => /canvas/i.test(reason))) {
      tampering.tampering_details.reasons.push(
        'Canvas toDataURL/getImageData pixel noise (farbling) detected'
      );
    }
  }

  // Genuine Tor Browser / Firefox RFP confirmation gate.
  // RFP + letterboxing deliberately make `screen.width` disagree with a raw
  // `(device-width: Wpx)` media query — an intentional anti-fingerprinting measure, not
  // active spoofing. Suppress ONLY that RFP-induced anti-detect false positive when the
  // runtime is a confirmed Gecko/RFP browser and there is no independent protocol-level
  // proof of automation. Every real signal keeps its full weight.
  const independentRfpAutomationProof =
    botAssessment.isBot ||
    botAssessment.webdriver ||
    botAssessment.cdpDetected ||
    Boolean(botAssessment.stealthPluginDetected) ||
    canvasNoiseDetected ||
    browserDevice.devtoolsDeviceEmulation ||
    vmStatus.isOsTampered ||
    tampering.tampering_details.reasons.some((reason) =>
      /Navigator getter|non-native|HTTP User-Agent header/i.test(reason)
    );
  const rfpExempt = torBrowserClient.confirmed && !independentRfpAutomationProof;
  if (rfpExempt) {
    const rfpReason = /screen\.width disagrees with its own device-width media query/i;
    const survivingReasons = tampering.tampering_details.reasons.filter(
      (reason) => !rfpReason.test(reason)
    );
    if (survivingReasons.length !== tampering.tampering_details.reasons.length) {
      tampering.tampering_details.reasons = survivingReasons;
      tampering.tampering_details.anomaly_score = Math.max(
        0,
        Number((tampering.tampering_details.anomaly_score - 0.3).toFixed(2))
      );
      if (
        !survivingReasons.some((reason) =>
          /devtools|device emulation|canvas|farbling|HTTP User-Agent/i.test(reason)
        )
      ) {
        tampering.tampering_details.anti_detect_browser = false;
        tampering.tampering = false;
        tampering.tampering_confidence = 'high';
        tampering.tampering_ml_score = 0.0024;
      }
    }
  }

  // Single bot verdict with parity assertion. Deterministic automation artifacts found by
  // the tampering probe (CDP/Playwright/CDC bindings, a forged webdriver getter) are hard
  // bot evidence, so they are promoted into the one authoritative verdict here. Everything
  // downstream reads `isBot` from that single derivation — no second opinion can flip it.
  const hardAutomationEvidence = tampering.tampering_details.hardAutomationEvidence ?? [];
  const authoritativeIsBot = botAssessment.isBot || hardAutomationEvidence.length > 0;
  // The corroborated-CDP id is the single hard reason for this escalation path. It is
  // already present in `botSignals`; include it explicitly so the gate and the authoritative
  // detector cannot drift even if a downstream consumer filters the human-readable list.
  const cdpEscalationReasonIds = botAssessment.corroboratedCdpEscalation
    ? [CORROBORATED_CDP_REASON_ID, CORROBORATED_CHROMIUM_CDP_REASON_ID]
    : [];
  const botVerdict = deriveBotVerdict({
    isBot: authoritativeIsBot,
    // A hard CDP id on an exempt Electron/IDE/DevTools host must NOT make the gate disagree
    // with the authoritative human verdict. Keep the payload ids for the server, but only
    // feed them into the parity gate when the runtime is already a bot.
    reasonIds: authoritativeIsBot
      ? [
          // Canonical ids from strong collector probes. Weak preview artifacts never reach here.
          ...cdpReasonIds,
          ...botSignals,
          ...hardAutomationEvidence.map((reason) => `cdc.${reason}`),
          ...cdpEscalationReasonIds,
        ]
      : [],
  });
  const isBot = botVerdict.isBot;
  if (hardAutomationEvidence.length > 0) {
    botSignals.unshift(...hardAutomationEvidence);
  }

  // Active call — WebRTC audio transceivers, navigator.audioSession, voice-routed AudioContext.
  const activeCall = detectActiveCall();

  const persistenceMode: PersistenceMode = !localStorageAvailable || incognitoLikely
    ? 'Private / Restricted Storage'
    : hasStoredIdentity
    ? 'First-Party Cookie'
    : 'First-Party Cookie';

  // 5. Composite Suspect & Risk Score (0-10) — four core Smart Signals only.
  // Card table (mirrored on the server): Tor exit / browser 9 (10 if server exit too),
  // spoofed impostor 10, AI agent 8, cloud VM / masked WebGL 7, VPN / tz relay 5,
  // incognito 4. The headline score is monotonic in the cards: it can never fall below the
  // highest card, and two elevated cards add +1 synergy (three or more add +2).
  const riskFactors: string[] = [];

  const incognitoScore = incognitoVerified ? 4 : 0;
  if (incognitoScore > 0) {
    const storageDetail =
      storageQuotaMb !== null
        ? `${storageQuotaMb} MB storage quota`
        : !localStorageAvailable
        ? 'first-party storage write blocked'
        : 'restricted storage';
    riskFactors.push(`Private / ephemeral storage (+4 card): ${storageDetail}`);
  }

  const botScore = isBot ? 9 : 0;
  if (botScore > 0) {
    riskFactors.push(
      `Automation / headless runtime (+9 card): ${
        botSignals[0] || 'automation runtime detected'
      }`
    );
  }

  // VPN card is gated on concrete datacenter/hosting evidence. A timezone mismatch is only
  // low-weight context (+2) when concrete evidence already exists — on its own it produces no
  // VPN card and no VPN verdict, only the orthogonal timezone axis in vpnMethods/telemetry.
  const vpnScore = torBrowserClient.detected
    ? 9
    : datacenterAsn
    ? timezoneMismatch
      ? 8
      : 6
    : 0;
  if (vpnScore > 0) {
    riskFactors.push(
      torBrowserClient.detected
        ? `Tor Browser fingerprint (+9 card): ${torBrowserClient.reasons[0] || 'RFP detected'}`
        : `VPN / proxy network (+${vpnScore} card): ${
            vpnReasons[0] || 'proxy network signal'
          }`
    );
  }

  const vmLike = vmStatus.isVirtualMachine || cloudOrMaskedGpu;
  const vmScore = emulatorDetected ? 8 : vmLike ? 7 : vmStatus.isOsTampered ? 6 : 0;
  if (vmScore > 0) {
    const virtualDetail = emulatorDetected
      ? emulatorReason || 'mobile emulator / simulator'
      : vmStatus.isVirtualMachine && cloudOrMaskedGpu
      ? `${vmStatus.vmReason}; Cloud / Masked GPU environment`
      : vmStatus.isVirtualMachine
      ? vmStatus.vmReason
      : cloudOrMaskedGpu
      ? 'Cloud / Masked GPU environment'
      : vmStatus.vmReason;
    riskFactors.push(`Virtualization / cloud GPU signal (+${vmScore} card): ${virtualDetail}`);
  }

  // Weighted composite (unchanged physics): automation 3, network 2, VM 2, incognito 1.
  const weightedCompositeScore = Math.min(
    10,
    (isBot ? 3 : 0) +
      (vpnSuspected ? 2 : 0) +
      (vmStatus.isVirtualMachine || cloudOrMaskedGpu ? 2 : 0) +
      (incognitoLikely ? 1 : 0)
  );

  const cardScores = [incognitoScore, botScore, vpnScore, vmScore];
  const maxCardScore = Math.max(0, ...cardScores);
  const elevatedCardCount = cardScores.filter((score) => score >= 4).length;
  const synergyBonus = elevatedCardCount >= 3 ? 2 : elevatedCardCount === 2 ? 1 : 0;
  const suspectScore = Math.min(
    10,
    Math.max(weightedCompositeScore, maxCardScore + synergyBonus)
  );
  const riskLevel: RiskLevel =
    suspectScore >= 7 ? 'High' : suspectScore >= 3 ? 'Medium' : 'Low';

  return {
    isBot,
    botSignals,
    botVerdictParity: botVerdict.parity,
    botVerdictAssertion: botVerdict.assertion,
    vpnSuspected,
    timezoneMismatch,
    /** Raw browser timezone — emitted verbatim (mismatch uses the canonical helper only). */
    browserTimezone,
    ipTimezone,
    /* Additive provenance — runtime / GPU observation / strong CDP ids, never a verdict. */
    runtime: clientRuntime.runtime,
    host_app: clientRuntime.host_app,
    client_type: clientRuntime.client_type,
    gpuObservation,
    cdpReasonIds,
    cdpAttached: stealthSnapshot.cdpRuntimeProof,
    datacenterAsn,
    cloudOrMaskedGpu,
    vpnReasons,
    tamperDetected,
    tamperReasons,
    incognitoLikely: incognitoVerified,
    isIncognito: incognitoVerified,
    incognito: incognitoVerified,
    privateMode: incognitoVerified,
    incognitoMethod: incognito.method,
    headroomGiB: incognito.headroomGiB,
    idbDurabilityRatio: incognito.idbDurabilityRatio,
    opfsFlushMs: incognito.opfsFlushMs,
    // Additive, flag-gated incognito diagnostics — never a verdict or scoring input.
    ...(incognito.diagnostics ? { diagnostics: incognito.diagnostics } : {}),
    storageQuotaMb,
    persistenceMode,
    suspectScore,
    riskLevel,
    riskFactors,
    /* Task 1 - ISP brand & network classification */
    brandName,
    networkType,
    isConsumerBroadband,
    isDatacenterOrHosting,
    /* Incognito confidence + explanation (client probe).
       `incognitoConfidence` is the STABLE high/low label from the session lock. When it
       is 'low' the incognito aliases above are all false by construction. The cast
       bridges the concurrent type migration to the string contract (the dashboard and
       server read this field as 'high' | 'low'); the runtime value is the string. */
    incognitoConfidence: incognito.confidence as never,
    incognitoDetail: privateBrowsing.reasons.join('; '),
    incognitoOrCleared,
    /* VM / OS integrity verdict */
    isVirtualMachine: vmStatus.isVirtualMachine,
    isOsTampered: vmStatus.isOsTampered,
    vmReason: vmStatus.vmReason,
    /* Phase 3 — mobile emulator / cloud container verdict */
    emulatorDetected,
    emulatorReason,
    /* Bot / automation verdict */
    isHeadless: botAssessment.isHeadless,
    botReason: botAssessment.botReason,
    webdriver: botAssessment.webdriver,
    cdpDetected: botAssessment.cdpDetected,
    cdpRuntimeLeak: Boolean(botAssessment.cdpRuntimeLeak),
    stealthPluginDetected: Boolean(botAssessment.stealthPluginDetected),
    /* Three-axis split (Fingerprint Pro parity): developer tools ≠ bot */
    developerTools: Boolean(tampering.developerTools || botAssessment.developerTools),
    automationEnvironment: botAssessment.automationEnvironment ?? 'none',
    // Recomputed at payload construction — never a value frozen at page load. Automated /
    // escalated sessions are pinned at 0 so no surface can render them as "Verified Human".
    humanCorroboration: isBot ? 0 : measureHumanCorroboration(hardwareSignals.gpuRenderer).score,
    /* Phase 2 — client-side Tor Browser fingerprint (Gecko RFP + letterboxing) */
    isTorBrowserClient: torBrowserClient.detected,
    /* Phase 5 — browser tampering (DevTools device emulation / anti-detect browsers) */
    tampering: tampering.tampering,
    tamperingConfidence: tampering.tampering_confidence,
    tamperingMlScore: tampering.tampering_ml_score,
    tamperingDetails: tampering.tampering_details,
    /* Phase 5 — active call detection (pruned when unsupported) */
    activeCall: activeCall.active,
    activeCallSupported: activeCall.supported,
    activeCallReasons: activeCall.reasons,
    /* Phase 6 — raw device attributes for the event JSON inspector */
    rawDeviceAttributes: (() => {
      const rawAttributes =
        (rawDeviceAttributes as unknown as Record<string, unknown> | null) ?? {};
      if (browserDevice.genuineMobile && browserDevice.phoneModel) {
        rawAttributes.device_model = browserDevice.phoneModel;
        rawAttributes.device_model_code = browserDevice.phoneModelCode || null;
        rawAttributes.device_brand = browserDevice.phoneBrand || null;
        rawAttributes.device_code = browserDevice.phoneDeviceCode || null;
      } else if (browserDevice.deviceType === 'Desktop') {
        rawAttributes.device = 'Desktop';
      }
      return rawAttributes;
    })(),
    /* Privacy settings: Tor Browser RFP / anti-fingerprinting evidence, including canvas farbling. */
    privacySettings: torBrowserClient.detected || canvasNoiseDetected,
    /* Removed probes are neutralised so downstream consumers see explicit falses. */
    devToolsOpen: false,
    adBlockerDetected: false,
    webrtcLeak: false,
    webrtcCandidateIp: null,
    distinctIpsLastHour: undefined,
    visitsLastHour: undefined,
  };
}

/* ------------------------------------------------------------------------------------------------
 * Active Call Detection & capability pruning
 *
 * A phone in an active cellular / VoIP call locks the OS audio layer into voice-communication
 * mode (Android `MODE_IN_COMMUNICATION`, iOS `AVAudioSessionModeVoiceChat`). The browser cannot
 * read telephony state, but the lock leaks through three Web APIs: the WebRTC transceiver list,
 * `navigator.audioSession`, and the AudioContext sample rate / lifecycle. Each probe is
 * best-effort and must never throw.
 * ---------------------------------------------------------------------------------------------- */

export interface ActiveCallAssessment {
  /** Whether this runtime can observe call state at all (drives UI pruning). */
  supported: boolean;
  active: boolean;
  reasons: string[];
}

interface TrackedPeerConnection {
  connection: RTCPeerConnection;
  audio: boolean;
}

const trackedPeerConnections = new Set<TrackedPeerConnection>();
let webrtcProbeInstalled = false;

/**
 * Instruments `RTCPeerConnection` once, at module load, so peer connections created by any
 * third-party call widget are counted too. Connections are pruned on state transitions.
 */
export function installWebRtcCallProbe(): void {
  if (webrtcProbeInstalled || typeof window === 'undefined') return;
  const scope = window as unknown as {
    RTCPeerConnection?: typeof RTCPeerConnection;
    webkitRTCPeerConnection?: typeof RTCPeerConnection;
  };
  const Ctor = scope.RTCPeerConnection || scope.webkitRTCPeerConnection;
  if (typeof Ctor !== 'function') return;
  webrtcProbeInstalled = true;
  try {
    const Original = Ctor;
    const Wrapped = function PatchedPeerConnection(
      this: RTCPeerConnection,
      ...args: ConstructorParameters<typeof RTCPeerConnection>
    ) {
      const pc = new Original(...args);
      const entry: TrackedPeerConnection = { connection: pc, audio: false };
      trackedPeerConnections.add(entry);
      const refresh = () => {
        try {
          const senders = pc.getSenders?.() ?? [];
          const receivers = pc.getReceivers?.() ?? [];
          entry.audio = [...senders, ...receivers].some(
            (rtp) => rtp?.track?.kind === 'audio' && rtp.track.readyState === 'live'
          );
        } catch {
          entry.audio = false;
        }
        const state = pc.connectionState;
        if (state === 'closed' || state === 'failed' || state === 'disconnected') {
          trackedPeerConnections.delete(entry);
        }
      };
      try {
        pc.addEventListener('track', refresh);
        pc.addEventListener('connectionstatechange', refresh);
        pc.addEventListener('iceconnectionstatechange', refresh);
      } catch {
        // Hostile event target: the audio flag simply stays false.
      }
      refresh();
      return pc;
    } as unknown as typeof RTCPeerConnection;
    Wrapped.prototype = Original.prototype;
    scope.RTCPeerConnection = Wrapped;
  } catch {
    // Frozen global: WebRTC transceiver polling below still runs on existing connections.
  }
}

// Install eagerly so call widgets that load after first paint are still observed.
installWebRtcCallProbe();

/**
 * Detects an in-progress call from WebRTC transceivers, `navigator.audioSession`, and the
 * AudioContext voice-routing profile. `supported` is true on any mobile claim or when the
 * runtime exposes call telemetry, which is what the Smart Signals grid uses to prune the row.
 */
export function detectActiveCall(): ActiveCallAssessment {
  const reasons: string[] = [];
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent || '' : '';
  const maxTouchPoints = typeof navigator !== 'undefined' ? navigator.maxTouchPoints ?? 0 : 0;
  const claimsMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(ua);
  const hasRtc =
    typeof window !== 'undefined' &&
    typeof (window as unknown as { RTCPeerConnection?: unknown }).RTCPeerConnection === 'function';
  const audioSessionType = (() => {
    try {
      const session = (navigator as unknown as { audioSession?: { type?: string } }).audioSession;
      return typeof session?.type === 'string' ? session.type : '';
    } catch {
      return '';
    }
  })();
  // 1. A connected peer connection carrying a live audio track.
  let connectedAudioCall = false;
  for (const entry of Array.from(trackedPeerConnections)) {
    try {
      const { connection } = entry;
      const connected =
        connection.connectionState === 'connected' ||
        connection.iceConnectionState === 'connected' ||
        connection.iceConnectionState === 'completed';
      const hasAudio =
        entry.audio ||
        (connection.getSenders?.() ?? []).some(
          (sender) => sender?.track?.kind === 'audio' && sender.track.readyState === 'live'
        );
      if (connected && hasAudio) {
        connectedAudioCall = true;
        break;
      }
    } catch {
      // Ignore a connection that threw while being inspected.
    }
  }
  if (connectedAudioCall) {
    reasons.push('Connected WebRTC peer connection with a live audio track');
  }
  if (audioSessionType === 'play-and-record') {
    reasons.push('navigator.audioSession reports play-and-record');
  }

  // A desktop runtime exposes RTCPeerConnection everywhere, so its mere presence is not a
  // call capability. The row is only rendered on mobile claims, an audioSession API, or an
  // actually connected audio call.
  const supported =
    claimsMobile || Boolean(audioSessionType) || connectedAudioCall || maxTouchPoints > 0;

  // 2. Voice-routed audio hardware: narrowband/wideband voice sample rates, or an iOS
  //    `interrupted` context that only occurs while the audio session is held by a call.
  let voiceRoutedAudio = false;
  if (typeof window !== 'undefined') {
    const AudioContextCtor =
      (window as unknown as { AudioContext?: typeof AudioContext }).AudioContext ||
      (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (typeof AudioContextCtor === 'function') {
      try {
        const ctx = new AudioContextCtor();
        const state = String(ctx.state || '');
        const sampleRate = ctx.sampleRate || 0;
        if (sampleRate > 0 && sampleRate <= 16000) {
          voiceRoutedAudio = true;
          reasons.push(`Audio hardware clamped to ${sampleRate} Hz voice profile`);
        }
        if (state === 'interrupted') {
          voiceRoutedAudio = true;
          reasons.push('AudioContext state is "interrupted" (audio session owned by a call)');
        }
        const closer = (ctx as AudioContext & { close?: () => Promise<void> }).close;
        if (typeof closer === 'function') {
          void closer.call(ctx).catch(() => undefined);
        }
      } catch {
        // Autoplay policy or a sandboxed context: no evidence either way.
      }
    }
  }

  return {
    supported,
    active: connectedAudioCall || voiceRoutedAudio || audioSessionType === 'play-and-record',
    reasons,
  };
}

/* ------------------------------------------------------------------------------------------------
 * Raw device attributes — the `raw_device_attributes` block of the event payload.
 * Everything is measured with native Web APIs; nothing is fetched or cached remotely.
 * ---------------------------------------------------------------------------------------------- */

export interface RawDeviceAttributes {
  font_preferences: Record<string, number>;
  emoji: {
    font: string;
    width: number;
    height: number;
    top: number;
    bottom: number;
    left: number;
    right: number;
    x: number;
    y: number;
  } | null;
  fonts: string[];
  timezone: string;
  canvas: {
    winding: boolean | null;
    geometry: string;
    text: string;
    /** True when two reads of the same static bitmap differ, or a flat fill was rewritten. */
    noise?: boolean;
  };
  languages: string[][];
  webgl_extensions: {
    context_attributes: string;
    parameters: string;
    shader_precisions: string;
    extensions: string;
    extension_parameters: string;
    unsupported_extensions: string[];
  };
  webgl_basics: {
    version: string;
    vendor: string;
    renderer: string;
    vendor_unmasked?: string;
    renderer_unmasked?: string;
    shading_language_version: string;
  };
  screen_resolution: [number, number];
  touch_support: {
    touch_event: boolean;
    touch_start: boolean;
    max_touch_points: number;
  };
  oscpu: string;
  architecture: number;
  cookies_enabled: boolean;
  hardware_concurrency: number | null;
  /** navigator.deviceMemory, or null when the browser hides it. Never estimated. */
  device_memory: number | null;
  date_time_locale: string;
  vendor: string;
  color_depth: number;
  platform: string;
  session_storage: boolean;
  local_storage: boolean;
  audio: number | null;
  plugins: Array<{ name: string; description: string; mimeTypes: Array<{ type: string; suffixes: string }> }>;
  indexed_db: boolean;
  math: string;
  font_hash: string;
  timezone_offset: string;
}

/** 32-character hex digest (four seeded FNV-1a passes over the same input). */
function hash128(input: string): string {
  const seeds = [0x811c9dc5, 0x01000193, 0x7f4a7c15, 0x9e3779b9];
  return seeds
    .map((seed) => {
      let hash = seed >>> 0;
      for (let i = 0; i < input.length; i += 1) {
        hash ^= input.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193) >>> 0;
      }
      return hash.toString(16).padStart(8, '0');
    })
    .join('');
}

const FONT_PROFILES: Record<string, string> = {
  default: '',
  serif: 'serif',
  sans: 'sans-serif',
  mono: 'monospace',
  apple: '-apple-system, BlinkMacSystemFont, "Helvetica Neue", Helvetica, Arial',
  min: 'Minion Pro, "Times New Roman", Times, serif',
  system: 'system-ui, -apple-system, "Segoe UI", Roboto, Arial',
};

/**
 * Probe fonts paired with the CSS generic family each one belongs to. A candidate is only
 * reported as installed when it changes the metrics of ITS OWN generic baseline: comparing
 * every font against `monospace` falsely reported Arial and Times New Roman on Linux, where
 * they fall back to Liberation Sans / Liberation Serif and never match the monospace width.
 */
const PROBE_FONT_FAMILIES: Array<[font: string, generic: 'serif' | 'sans-serif' | 'monospace']> = [
  ['Arial', 'sans-serif'],
  ['Arial Narrow', 'sans-serif'],
  ['Calibri', 'sans-serif'],
  ['Cambria', 'serif'],
  ['Courier New', 'monospace'],
  ['Georgia', 'serif'],
  ['Helvetica', 'sans-serif'],
  ['Helvetica Neue', 'sans-serif'],
  ['Menlo', 'monospace'],
  ['Monaco', 'monospace'],
  ['Roboto', 'sans-serif'],
  ['Segoe UI', 'sans-serif'],
  ['Tahoma', 'sans-serif'],
  ['Times New Roman', 'serif'],
  ['Trebuchet MS', 'sans-serif'],
  ['Ubuntu', 'sans-serif'],
  ['Verdana', 'sans-serif'],
];

/**
 * Measures font metrics, emoji bounding boxes, canvas stability, WebGL hashes and the math
 * vector with native APIs. Returns `null` only when the DOM is unavailable.
 */
export async function collectRawDeviceAttributes(): Promise<RawDeviceAttributes | null> {
  if (typeof document === 'undefined' || typeof window === 'undefined') return null;

  // All font/emoji box measurements happen inside ONE short-lived, hidden 16px
  // iframe with the locked probe string. This keeps host-page CSS out of the
  // metrics and removes the container immediately after the reads.
  const measurer = createIsolatedFontMeasurer();
  const round = (value: number): number => (Number.isFinite(value) ? Number(value.toFixed(6)) : 0);
  const measure = (family: string): number =>
    measurer ? round(measurer.width(FONT_MEASURE_TEST_STRING, family)) : 0;

  const fontPreferences: Record<string, number> = {};
  for (const [key, family] of Object.entries(FONT_PROFILES)) {
    fontPreferences[key] = measure(family);
  }

  // Measure ALL THREE generic baselines. On Linux, fontconfig aliases make Arial /
  // Times New Roman render with Liberation Sans / Liberation Serif metrics; comparing
  // only against one generic falsely reports those aliases as installed. A candidate
  // identical to ANY baseline is therefore excluded.
  const genericBaselines: Record<'serif' | 'sans-serif' | 'monospace', number> = {
    serif: measure('serif'),
    'sans-serif': measure('sans-serif'),
    monospace: measure('monospace'),
  };
  const baselineWidths = [
    genericBaselines.serif,
    genericBaselines['sans-serif'],
    genericBaselines.monospace,
  ];
  const detectedFonts: string[] = [];
  for (const [family, generic] of PROBE_FONT_FAMILIES) {
    const withFamily = measure(`"${family}", ${generic}`);
    const matchesOwnBaseline = Math.abs(withFamily - genericBaselines[generic]) <= 0.1;
    const matchesAnyBaseline = baselineWidths.some((width) => Math.abs(withFamily - width) <= 0.1);
    if (!matchesOwnBaseline && !matchesAnyBaseline) detectedFonts.push(family);
  }

  let emoji: RawDeviceAttributes['emoji'] = null;
  const emojiRect = measurer?.rect('😀', 'serif') ?? null;
  if (emojiRect) {
    emoji = {
      font: 'serif',
      width: round(emojiRect.width),
      height: round(emojiRect.height),
      top: round(emojiRect.top),
      bottom: round(emojiRect.bottom),
      left: round(emojiRect.left),
      right: round(emojiRect.right),
      x: round(emojiRect.x),
      y: round(emojiRect.y),
    };
  }
  measurer?.dispose();

  // Canvas: one isolated canvas per probe so no composite mode or sub-path from the geometry
  // pass can contaminate the text pass, and the two stability reads happen on the SAME static
  // bitmap. Re-painting between reads is what used to report "unstable" on every clean browser.
  let winding: boolean | null = null;
  let geometry = 'unavailable';
  let textHash = 'unavailable';
  let canvasNoiseDetected = false;
  try {
    const windingCanvas = document.createElement('canvas');
    windingCanvas.width = 10;
    windingCanvas.height = 10;
    const windingCtx = windingCanvas.getContext('2d');
    if (windingCtx) {
      try {
        windingCtx.rect(0, 0, 10, 10);
        windingCtx.rect(2, 2, 6, 6);
        winding = !windingCtx.isPointInPath(5, 5, 'evenodd');
      } catch {
        winding = null;
      }
    }

    /** Renders once, then verifies the static bitmap and a flat interior pixel. */
    const renderOnce = (
      width: number,
      height: number,
      paint: (context: CanvasRenderingContext2D) => void
    ): { dataUrl: string; unstable: boolean; fillParity: boolean | null } => {
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const context = canvas.getContext('2d', { willReadFrequently: true });
      if (!context) return { dataUrl: 'unavailable', unstable: false, fillParity: null };
      paint(context);
      const first = canvas.toDataURL();
      const second = canvas.toDataURL();
      let fillParity: boolean | null = null;
      try {
        // Paint a known opaque marker pixel so the parity check never samples transparent background
        // (which used to report noise on every clean browser). Two independent reads must agree.
        context.save();
        context.globalCompositeOperation = 'source-over';
        context.fillStyle = '#123456';
        context.fillRect(0, 0, 1, 1);
        context.restore();
        const a = context.getImageData(0, 0, 1, 1).data;
        const b = context.getImageData(0, 0, 1, 1).data;
        fillParity =
          a[0] === 0x12 &&
          a[1] === 0x34 &&
          a[2] === 0x56 &&
          a[3] === 255 &&
          b[0] === a[0] &&
          b[1] === a[1] &&
          b[2] === a[2] &&
          b[3] === a[3];
      } catch {
        fillParity = null;
      }
      return { dataUrl: first, unstable: first !== second, fillParity };
    };

    const geometryRender = renderOnce(122, 110, (context) => {
      context.globalCompositeOperation = 'multiply';
      for (const [color, x, y] of [
        ['#f2f', 40, 40],
        ['#2ff', 80, 40],
        ['#ff2', 60, 80],
      ] as const) {
        context.fillStyle = color;
        context.beginPath();
        context.arc(x, y, 40, 0, Math.PI * 2, true);
        context.closePath();
        context.fill();
      }
      context.fillStyle = '#f9c';
      context.beginPath();
      context.arc(60, 60, 60, 0, Math.PI * 2, true);
      context.arc(60, 60, 20, 0, Math.PI * 2, true);
      context.fill('evenodd');
    });
    geometry = geometryRender.unstable
      ? 'unstable'
      : geometryRender.dataUrl === 'unavailable'
      ? 'unavailable'
      : await sha256Hex(geometryRender.dataUrl);

    const textRender = renderOnce(240, 60, (context) => {
      context.textBaseline = 'alphabetic';
      context.fillStyle = '#f60';
      context.fillRect(0, 0, 120, 30);
      context.fillStyle = '#069';
      context.font = '11pt "Times New Roman"';
      context.fillText('Cwm fjordbank glyphs vext quiz', 2, 15);
      context.fillStyle = 'rgba(102, 204, 0, 0.2)';
      context.font = '18pt Arial';
      context.fillText('Cwm fjordbank glyphs vext quiz', 4, 45);
    });
    textHash = textRender.unstable
      ? 'unstable'
      : textRender.dataUrl === 'unavailable'
      ? 'unavailable'
      : await sha256Hex(textRender.dataUrl);
    canvasNoiseDetected =
      geometryRender.unstable || textRender.unstable || geometryRender.fillParity === false;
  } catch {
    // Canvas blocked: report the hash as unavailable rather than throwing.
  }

  let webglExtensions: RawDeviceAttributes['webgl_extensions'] = {
    context_attributes: 'unavailable',
    parameters: 'unavailable',
    shader_precisions: 'unavailable',
    extensions: 'unavailable',
    extension_parameters: 'unavailable',
    unsupported_extensions: [],
  };
  let webglBasics: RawDeviceAttributes['webgl_basics'] = {
    version: 'unavailable',
    vendor: 'unavailable',
    renderer: 'unavailable',
    shading_language_version: 'unavailable',
  };
  try {
    const canvas = document.createElement('canvas');
    const gl = (canvas.getContext('webgl') ||
      canvas.getContext('experimental-webgl')) as WebGLRenderingContext | null;
    if (gl) {
      const attributeKeys = [
        'alpha',
        'antialias',
        'depth',
        'failIfMajorPerformanceCaveat',
        'premultipliedAlpha',
        'preserveDrawingBuffer',
        'stencil',
      ];
      const attributes = attributeKeys.map((key) => `${key}:${String(gl.getContextAttributes()?.[key as keyof WebGLContextAttributes])}`).join('|');
      const parameterNames: Array<keyof WebGLRenderingContext> = [
        'MAX_TEXTURE_SIZE',
        'MAX_VIEWPORT_DIMS',
        'MAX_RENDERBUFFER_SIZE',
        'MAX_VERTEX_ATTRIBS',
        'MAX_VARYING_VECTORS',
        'MAX_COMBINED_TEXTURE_IMAGE_UNITS',
        'MAX_VERTEX_TEXTURE_IMAGE_UNITS',
        'MAX_TEXTURE_IMAGE_UNITS',
        'MAX_FRAGMENT_UNIFORM_VECTORS',
        'MAX_VERTEX_UNIFORM_VECTORS',
        'MAX_CUBE_MAP_TEXTURE_SIZE',
        'ALIASED_LINE_WIDTH_RANGE',
        'ALIASED_POINT_SIZE_RANGE',
        'RED_BITS',
        'GREEN_BITS',
        'BLUE_BITS',
        'ALPHA_BITS',
        'DEPTH_BITS',
        'STENCIL_BITS',
        'SUBPIXEL_BITS',
      ];
      const parameters = parameterNames
        .map((name) => {
          const enumValue = gl[name] as unknown as number;
          let value: unknown = 'n/a';
          try {
            value = enumValue ? gl.getParameter(enumValue) : 'n/a';
          } catch {
            value = 'err';
          }
          return `${String(name)}:${String(value)}`;
        })
        .join('|');
      const shaderPrecisions = ['VERTEX_SHADER', 'FRAGMENT_SHADER']
        .map((shader) => {
          const enumValue = gl[shader as unknown as keyof WebGLRenderingContext] as unknown as number;
          try {
            return String(gl.getShaderPrecisionFormat(enumValue, gl.HIGH_FLOAT)?.precision ?? 'n/a');
          } catch {
            return 'err';
          }
        })
        .join('|');
      const supported = (gl.getSupportedExtensions?.() ?? []).slice().sort();
      const extensionParameters = supported
        .map((name) => {
          try {
            const extension = gl.getExtension(name);
            if (!extension) return `${name}:null`;
            return `${name}:${hash128(Object.keys(extension).sort().join(','))}`;
          } catch {
            return `${name}:err`;
          }
        })
        .join('|');
      webglExtensions = {
        context_attributes: hash128(attributes),
        parameters: hash128(parameters),
        shader_precisions: hash128(shaderPrecisions),
        extensions: hash128(supported.join(',')),
        extension_parameters: hash128(extensionParameters),
        unsupported_extensions: [],
      };
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      const unmaskedVendor = debugInfo
        ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)
        : 'unavailable';
      const unmaskedRenderer = debugInfo
        ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
        : 'unavailable';
      webglBasics = {
        version: gl.getParameter(gl.VERSION) || 'unavailable',
        vendor: gl.getParameter(gl.VENDOR) || 'unavailable',
        renderer: gl.getParameter(gl.RENDERER) || 'unavailable',
        vendor_unmasked: unmaskedVendor || 'unavailable',
        renderer_unmasked: unmaskedRenderer || 'unavailable',
        shading_language_version:
          gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || 'unavailable',
      };
    }
  } catch {
    // WebGL blocked: keep the unavailable placeholders.
  }

  // Math vector — 14 transcendental operations, hashed.
  const mathVector = [
    Math.acos(0.123124234234234242),
    Math.acosh(1e308),
    Math.asin(0.123124234234234242),
    Math.asinh(1),
    Math.atan(0.123124234234234242),
    Math.atanh(0.5),
    Math.cbrt(100000),
    Math.cos(Math.PI / 3),
    Math.cosh(1),
    Math.expm1(1),
    Math.log1p(0.5),
    Math.sin(Math.PI / 3),
    Math.sinh(1),
    Math.tanh(1),
    Math.pow(Math.PI, -100),
  ];
  const math = hash128(mathVector.map((value) => String(value)).join(','));

  const tzOffsetMinutes = new Date().getTimezoneOffset();
  const tzSign = tzOffsetMinutes <= 0 ? '+' : '-';
  const tzAbs = Math.abs(tzOffsetMinutes);
  const timezoneOffset = `${tzSign}${String(Math.floor(tzAbs / 60)).padStart(2, '0')}:${String(
    tzAbs % 60
  ).padStart(2, '0')}`;

  const languages: string[][] = [];
  try {
    if (Array.isArray(navigator.languages)) {
      languages.push(navigator.languages.slice());
      languages.push(navigator.languages.slice(0, 2));
    } else {
      languages.push([navigator.language]);
    }
  } catch {
    // navigator unavailable.
  }

  const plugins: RawDeviceAttributes['plugins'] = [];
  try {
    for (const plugin of Array.from(navigator.plugins ?? [])) {
      plugins.push({
        name: plugin.name,
        description: plugin.description,
        mimeTypes: Array.from(plugin).map((mime) => ({
          type: mime.type,
          suffixes: mime.suffixes,
        })),
      });
    }
  } catch {
    // Plugin array blocked by the browser.
  }

  /**
   * Rendered OfflineAudioContext fingerprint: the summed absolute samples of frames
   * 4500..4999 after a 10000 Hz triangle oscillator is squashed by a DynamicsCompressor.
   * The previous implementation returned `context.sampleRate` (44100), which is a hardware
   * constant, not a rendering fingerprint.
   */
  const audio = await (async (): Promise<number | null> => {
    if (typeof window === 'undefined') return null;
    const OfflineCtor =
      (window as unknown as { OfflineAudioContext?: typeof OfflineAudioContext })
        .OfflineAudioContext ||
      (window as unknown as { webkitOfflineAudioContext?: typeof OfflineAudioContext })
        .webkitOfflineAudioContext;
    if (typeof OfflineCtor !== 'function') return null;
    try {
      const context = new OfflineCtor(1, 5000, 44100);
      const oscillator = context.createOscillator();
      oscillator.type = 'triangle';
      oscillator.frequency.value = 10000;
      const compressor = context.createDynamicsCompressor();
      compressor.threshold.value = -50;
      compressor.knee.value = 40;
      compressor.ratio.value = 12;
      compressor.attack.value = 0;
      compressor.release.value = 0.25;
      oscillator.connect(compressor);
      compressor.connect(context.destination);
      oscillator.start(0);
      const rendered = context.startRendering().then((buffer) => {
        const samples = buffer.getChannelData(0);
        let sum = 0;
        for (let i = 4500; i < samples.length; i += 1) sum += Math.abs(samples[i]);
        return Number(sum.toFixed(10));
      });
      // A suspended or legacy context must never stall the identify call.
      const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), 1500));
      return await Promise.race([rendered, timeout]);
    } catch {
      return null;
    }
  })();

  const fontHash = hash128(
    `${Object.values(fontPreferences).join(',')}|${detectedFonts.join(',')}|${
      emoji ? `${emoji.width}x${emoji.height}` : ''
    }`
  );

  return {
    font_preferences: fontPreferences,
    emoji,
    fonts: detectedFonts,
    timezone: (() => {
      try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown';
      } catch {
        return 'Unknown';
      }
    })(),
    canvas: { winding, geometry, text: textHash, noise: canvasNoiseDetected },
    languages,
    webgl_extensions: webglExtensions,
    webgl_basics: webglBasics,
    screen_resolution: [window.screen?.width ?? 0, window.screen?.height ?? 0],
    touch_support: {
      // `ontouchstart` presence is the only honest touch-point signal. A defined TouchEvent
      // constructor only means the engine implements the API, which desktop Chrome always does.
      touch_event: 'ontouchstart' in window,
      touch_start: 'ontouchstart' in window,
      max_touch_points: navigator.maxTouchPoints ?? 0,
    },
    oscpu: (navigator as unknown as { oscpu?: string }).oscpu || '',
    architecture: Number((navigator as unknown as { architecture?: number }).architecture ?? 255),
    cookies_enabled: navigator.cookieEnabled,
    hardware_concurrency: navigator.hardwareConcurrency ?? null,
    device_memory:
      typeof (navigator as unknown as { deviceMemory?: number }).deviceMemory === 'number' &&
      Number((navigator as unknown as { deviceMemory: number }).deviceMemory) > 0
        ? Number((navigator as unknown as { deviceMemory: number }).deviceMemory)
        : null,
    date_time_locale: (() => {
      try {
        return Intl.DateTimeFormat().resolvedOptions().locale || 'Unknown';
      } catch {
        return 'Unknown';
      }
    })(),
    vendor: navigator.vendor || '',
    color_depth: window.screen?.colorDepth ?? 0,
    platform: navigator.platform || '',
    session_storage: (() => {
      try {
        sessionStorage.setItem('__intel_probe__', '1');
        sessionStorage.removeItem('__intel_probe__');
        return true;
      } catch {
        return false;
      }
    })(),
    local_storage: (() => {
      try {
        localStorage.setItem('__intel_probe__', '1');
        localStorage.removeItem('__intel_probe__');
        return true;
      } catch {
        return false;
      }
    })(),
    audio,
    plugins,
    indexed_db: typeof indexedDB !== 'undefined',
    math,
    font_hash: fontHash,
    timezone_offset: timezoneOffset,
  };
}

export function getFirstPartyStorage(): {
  visitorId: string | null;
  visitorToken: string | null;
  sessionId: string | null;
  historyBackup: SignedHistoryBackup | null;
} {
  let visitorId: string | null = null;
  let visitorToken: string | null = null;
  let sessionId: string | null = null;
  let historyBackup: SignedHistoryBackup | null = null;

  try {
    visitorId = localStorage.getItem(STORAGE_KEYS.VISITOR_ID);
    visitorToken = localStorage.getItem(STORAGE_KEYS.VISITOR_TOKEN);
    const rawBackup = localStorage.getItem(STORAGE_KEYS.HISTORY_BACKUP);
    if (rawBackup) {
      const parsed = JSON.parse(rawBackup) as SignedHistoryBackup;
      if (
        parsed &&
        typeof parsed.visitorId === 'string' &&
        typeof parsed.signature === 'string' &&
        Array.isArray(parsed.visits)
      ) {
        historyBackup = parsed;
      }
    }
  } catch {
    // localStorage unavailable
  }

  if (!visitorId) {
    try {
      const match = document.cookie.match(/(?:^|;\s*)intel_client_vid=([^;]+)/);
      if (match) visitorId = decodeURIComponent(match[1]);
    } catch {
      // Cookie unavailable
    }
  }

  try {
    sessionId = sessionStorage.getItem(STORAGE_KEYS.SESSION_ID);
  } catch {
    sessionId = null;
  }

  return { visitorId, visitorToken, sessionId, historyBackup };
}

export function saveFirstPartyStorage(
  visitorId: string,
  visitorToken: string,
  sessionId: string,
  historyBackup?: SignedHistoryBackup
): void {
  try {
    localStorage.setItem(STORAGE_KEYS.VISITOR_ID, visitorId);
    localStorage.setItem(STORAGE_KEYS.VISITOR_TOKEN, visitorToken);
    if (historyBackup) {
      localStorage.setItem(STORAGE_KEYS.HISTORY_BACKUP, JSON.stringify(historyBackup));
    }
  } catch {
    // Ignore if blocked
  }

  try {
    const maxAge = 365 * 24 * 60 * 60;
    document.cookie = `intel_client_vid=${encodeURIComponent(visitorId)}; Max-Age=${maxAge}; path=/; SameSite=Lax`;
  } catch {
    // Ignore if blocked
  }

  try {
    sessionStorage.setItem(STORAGE_KEYS.SESSION_ID, sessionId);
  } catch {
    // Ignore if blocked
  }
}

let inFlightRequest: Promise<IntelVisitorResponse> | null = null;

/**
 * Native-farbling hints for the canvas noise classifier. These are derived from the same
 * UA/runtime facts used everywhere else in the collector, so a Brave/Safari/Firefox/Samsung
 * farbling pattern is classified as a privacy defence rather than an injected-noise spoof.
 * No hint is a verdict: the classifier still requires pixel evidence.
 */
function buildBrowserCanvasHints(ua: string, browserLabel: string): BrowserCanvasHints {
  const chromiumToken = /Chrome\/|Chromium\/|Edg\/|OPR\/|CriOS\//i.test(ua);
  return {
    isBrave: /Brave\//i.test(ua) || /\bbrave\b/i.test(browserLabel),
    isFirefox: /Firefox\/|FxiOS\//i.test(ua) || /\bfirefox\b/i.test(browserLabel),
    isSafari17Plus:
      /Version\/(?:1[7-9]|[2-9]\d)(?:\.|$)/.test(ua) &&
      /Safari\//i.test(ua) &&
      !chromiumToken,
    isSamsung: /SamsungBrowser\//i.test(ua) || /\bsamsung\b/i.test(browserLabel),
    // Private mode is supplied by the dedicated storage-physics probe, not a UA guess; an
    // unknown hint is deliberately omitted rather than assumed.
    privateMode: undefined,
  };
}

/**
 * Builds the tri-layer identity profile posted to `/api/visitor/identify`.
 *
 * The object is deliberately BOTH shapes at once: engine-native family objects
 * (`gpu.normalizedGpu`, `screen.dpr`, `canvas.geometry`, …) feed the 6-mode matcher,
 * while the concise fields (`hash`, `vendor`, `list`, `count`, …) feed the server's
 * blocking index. Hashes are deterministic — no random, no clock.
 */
function buildIdentityProfile(
  signals: CollectedSignals,
  clientGeoHint: ClientGeoHint | null,
  hardwareFingerprint: string,
  browserFingerprint: string,
  cpuArchitecture: string
): Record<string, unknown> {
  const ua = normalizeIdentity({
    userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
    platform: typeof navigator !== 'undefined' ? navigator.platform : '',
    maxTouchPoints: typeof navigator !== 'undefined' ? navigator.maxTouchPoints : 0,
  });
  const screen = signals.systemEntropy.screen;
  const media = signals.systemEntropy.mediaDeviceCounts;
  const gpu = signals.webglGpuIdentity;
  const timezoneName = signals.systemEntropy.timezone ?? '';
  const timezoneOffset = signals.systemEntropy.timezoneOffset ?? 0;
  const gpuVendor = signals.webglBasics.vendorUnmasked ?? signals.webglBasics.vendor ?? '';
  const gpuRenderer =
    signals.webglBasics.rendererUnmasked ?? signals.webglBasics.renderer ?? '';
  const canvasHash = hashStrings([signals.canvas.geometry, signals.canvas.text]);
  const webglHash = hashStrings([
    signals.webglExtensions.extensions ?? '',
    signals.webglExtensions.parameters ?? '',
    signals.webglExtensions.shaderPrecisions ?? '',
  ]);
  const audioHash = hashStrings([
    String(signals.audio.sum ?? ''),
    String(signals.audio.audioBaseLatency ?? ''),
  ]);
  const emojiRectHash = hashStrings([
    String(signals.emoji.width ?? ''),
    String(signals.emoji.height ?? ''),
    String(signals.emoji.x ?? ''),
    String(signals.emoji.y ?? ''),
  ]);
  const mediaKinds = [
    (media.audioinput ?? 0) > 0 ? 'audioinput' : '',
    (media.audiooutput ?? 0) > 0 ? 'audiooutput' : '',
    (media.videoinput ?? 0) > 0 ? 'videoinput' : '',
  ].filter(Boolean);
  const languages =
    typeof navigator !== 'undefined'
      ? Array.from(new Set([navigator.language, ...(navigator.languages || [])]))
          .filter((value): value is string => typeof value === 'string' && value.length > 0)
          .slice(0, 10)
      : [];
  const browserMajor = Number.parseInt(ua.browser_major_version, 10);
  const osVersionMajor = Number.parseInt(ua.os_version, 10);

  return {
    hardwareFingerprint,
    browserFingerprint,
    browser: { family: ua.browser_name, major: ua.browser_major_version },
    os: { family: ua.os },
    net: { asn: clientGeoHint?.asn ?? null },
    languages,
    screen: {
      width: screen.width,
      height: screen.height,
      dpr: screen.pixelRatio ?? 1,
      colorDepth: screen.colorDepth,
      // No `touch` here: maxTouchPoints is volatile capability context. It must not enter the
      // identity profile (simhash512 / 6-mode matcher / block keys), or a touch-screen toggle
      // would split the visitor into a new identity.
    },
    timezone: timezoneName,
    timezoneSignals: { name: timezoneName, offsetMinutes: timezoneOffset },
    gpu: {
      vendor: gpuVendor,
      renderer: gpuRenderer,
      normalizedGpu: gpu.normalizedGpu ?? '',
      invariantLimitsHash: gpu.invariantLimits
        ? hashStrings([JSON.stringify(gpu.invariantLimits)])
        : '',
    },
    cpu: {
      arch: cpuArchitecture,
      architecture: cpuArchitecture,
      cores: signals.systemEntropy.hardwareConcurrency,
      memoryGb: signals.systemEntropy.deviceMemory,
      osFamily: ua.os,
    },
    fonts: {
      count: signals.fonts.installed.length,
      list: signals.fonts.installed,
      hash: signals.fonts.fontHash,
      platformClass: signals.fonts.platformClassGuess,
    },
    mediaDevices: {
      audioIn: media.audioinput,
      audioOut: media.audiooutput,
      video: media.videoinput,
      count: (media.audioinput ?? 0) + (media.audiooutput ?? 0) + (media.videoinput ?? 0),
      kinds: mediaKinds,
    },
    canvas: {
      geometry: signals.canvas.geometry,
      text: signals.canvas.text,
      stabilized: signals.canvasNoise.stabilizedGeometryHash ?? '',
      hash: canvasHash,
    },
    webgl: {
      extensionsHash: signals.webglExtensions.extensions ?? '',
      paramsHash: signals.webglExtensions.parameters ?? '',
      shaderPrecisionHash: signals.webglExtensions.shaderPrecisions ?? '',
      extensionsList: signals.webglExtensions.supportedExtensions,
      hash: webglHash,
      vendor: gpuVendor,
      renderer: gpuRenderer,
    },
    audio: {
      sum: signals.audio.sum,
      baseLatency: signals.audio.audioBaseLatency,
      hash: audioHash,
    },
    fontPrefs: {
      widths: signals.fontPreferences.widths,
      emojiRectHash,
      hash: hashStrings([JSON.stringify(signals.fontPreferences.widths), emojiRectHash]),
      families: [],
    },
    misc: {
      mathHash: signals.math.mathHash,
      errorStackHash: signals.math.errorStackHash,
      // Preserved as resolver evidence only — never used to set the automation verdict.
      canvasNoise: signals.canvasNoise.classification,
      canvasNoiseFlags: signals.canvasNoise.flags,
      automationReasonIds: signals.automation.reasonIds,
    },
    versions: {
      browserFamily: ua.browser_name,
      browserMajor: Number.isFinite(browserMajor) ? browserMajor : 0,
      osVersionMajor: Number.isFinite(osVersionMajor) ? osVersionMajor : 0,
    },
  };
}

export async function identifyCurrentVisitor(options?: {
  manualRefresh?: boolean;
}): Promise<IntelVisitorResponse> {
  if (inFlightRequest && !options?.manualRefresh) {
    return inFlightRequest;
  }

  const execute = async (): Promise<IntelVisitorResponse> => {
    const [browserDevice, clientGeoHint, clientHints] = await Promise.all([
      collectBrowserDeviceInfo(),
      collectClientGeoHint(),
      collectClientHints(),
    ]);
    const stored = getFirstPartyStorage();
    // The legacy hardware probe and the new tri-layer collectors run concurrently, so the
    // added wall-clock cost is the slower of the two — never the sum. Both are total.
    const browserCanvasHints = buildBrowserCanvasHints(
      typeof navigator !== 'undefined' ? navigator.userAgent || '' : '',
      browserDevice.browser
    );
    const [hardwareSignals, collectedSignals, storedIdentity] = await Promise.all([
      collectHardwareSignals(browserDevice),
      collectAllSignals({ timeouts: 1200, browserHints: browserCanvasHints }).catch(() => null),
      loadStoredIdentity().catch(() => ({ identity: null, sources: [], storage_healed: false })),
    ]);
    const identitySessionId = getSessionId().sessionId;
    const securitySignals = await evaluateSecuritySignals(
      browserDevice,
      hardwareSignals,
      clientGeoHint,
      Boolean(stored.visitorId && stored.visitorToken)
    );

    const pageLoadId = options?.manualRefresh
      ? 'manual_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8)
      : CURRENT_PAGE_LOAD_ID;

    // Module-cached / session-locked: this is the same verdict that started at module load.
    // Do not re-veto with `stored.visitorId/visitorToken`: those are written by the first
    // identify into first-party storage and would flip the answer on the next reload. The
    // persistent-marker veto was already folded into the lock when it was first computed.
    const incog = await detectIncognitoMode();
    const incognitoVerified = incog.isPrivate;

    // Phase 4 — sealed request envelope: one-time nonce + SHA-256 over the canonical
    // string the server recomputes. Crypto failures degrade to an empty signature
    // (unverifiable) instead of throwing.
    const envelopeTimestamp = Date.now();
    const envelopeNonce = generateEnvelopeNonce();
    const envelopeUserAgent = typeof navigator !== 'undefined' ? navigator.userAgent || '' : '';
    const envelopePlatform = typeof navigator !== 'undefined' ? navigator.platform || '' : '';
    const envelopeScreenResolution = browserDevice.screenResolution || '';
    const envelopeTimezone = browserDevice.timezone || '';
    const envelopeCanonical = `INTEL_ENVELOPE_V1|${envelopeTimestamp}|${envelopeNonce}|${hardwareSignals.hardwareId}|${envelopeUserAgent}|${envelopePlatform}|${envelopeScreenResolution}|${envelopeTimezone}`;
    const envelopeSignature = await sha256EnvelopeSignature(envelopeCanonical);
    const securityEnvelope: SecurityEnvelope = {
      timestamp: envelopeTimestamp,
      nonce: envelopeNonce,
      signature: envelopeSignature,
      userAgent: envelopeUserAgent,
      platform: envelopePlatform,
      screenResolution: envelopeScreenResolution,
      timezone: envelopeTimezone,
      protocol: 'INTEL_ENVELOPE_V1',
    };

    // Tri-layer fingerprints: deterministic hashes over the hardware-only and browser-only
    // signal families. The server resolver indexes on these; the canonical visitorId /
    // hardwareId above are untouched.
    // Touch capability (navigator.maxTouchPoints / ontouchstart) is volatile context, not a
    // stable hardware anchor. computeHardwareFingerprint() folds the whole `screen` family into
    // the device digest, so neutralize maxTouchPoints at the call site: toggling touch must not
    // split the visitor. The raw value is still available as capability context (device
    // detection, emulator evidence, event JSON `touch_start`); it is simply excluded from the
    // identity hash and the identity profile.
    const identityHardwareFingerprint = collectedSignals
      ? computeHardwareFingerprint({
          ...collectedSignals,
          systemEntropy: {
            ...collectedSignals.systemEntropy,
            // DST / travel changes the raw minute offset. It stays as context in the payload
            // but is neutralised here so it can never split the stable hardware identity.
            timezoneOffset: null,
            screen: { ...collectedSignals.systemEntropy.screen, maxTouchPoints: null },
          },
        })
      : hardwareSignals.hardwareId;
    const identityBrowserFingerprint = collectedSignals
      ? computeBrowserFingerprint({
          ...collectedSignals,
          systemEntropy: {
            ...collectedSignals.systemEntropy,
            // Storage usage churns with every cache/write; it is context, never a digest input.
            // The quota figure is retained as low-volatility context.
            storageQuota: collectedSignals.systemEntropy.storageQuota
              ? {
                  usage: null,
                  quota: collectedSignals.systemEntropy.storageQuota.quota,
                }
              : null,
          },
        })
      : hardwareSignals.canvasHash;
    const identityProfile = collectedSignals
      ? buildIdentityProfile(
          collectedSignals,
          clientGeoHint,
          identityHardwareFingerprint,
          identityBrowserFingerprint,
          hardwareSignals.architecture
        )
      : null;

    // Fresh, post-interaction corroboration on EVERY identify payload — never a value
    // cached at page load. Mirrored at top level for the server verdict state machine and
    // inspector telemetry as well as inside `securitySignals`.
    const freshHuman = measureHumanCorroboration(hardwareSignals.gpuRenderer);
    const freshInteractionEvidence = getInteractionEvidence();

    const response = await fetch('/api/visitor/identify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-intel-signature': envelopeSignature,
        'x-intel-nonce': envelopeNonce,
        'x-intel-timestamp': String(envelopeTimestamp),
      },
      credentials: 'same-origin',
      body: JSON.stringify({
        pageLoadId,
        storedVisitorId: stored.visitorId,
        storedVisitorToken: stored.visitorToken,
        clientSessionId: stored.sessionId,
        clientHistoryBackup: stored.historyBackup,
        browserDevice,
        hardwareSignals,
        securitySignals,
        // The flag-gated diagnostic mirror is emitted once, here, additively.
        ...(incog.diagnostics ? { diagnostics: incog.diagnostics } : {}),
        identityProfile,
        hardwareFingerprint: identityHardwareFingerprint,
        browserFingerprint: identityBrowserFingerprint,
        sessionId: stored.sessionId || identitySessionId,
        storageHealed: storedIdentity.storage_healed,
        clientGeoHint,
        // High-entropy UA-CH values; the server's own `Sec-CH-UA*` headers outrank them.
        clientHints,
        securityEnvelope,
        /* Additive provenance (Tranche 0-1). Mirrors the security-signals copy so either
           payload path can consume it. Electron is reported as `runtime: 'electron'`, never
           as Chromium; the GPU observation is a four-state bucket, not a VM verdict. */
        runtime: securitySignals.runtime,
        host_app: securitySignals.host_app,
        client_type: securitySignals.client_type,
        gpuObservation: securitySignals.gpuObservation,
        browserTimezone: securitySignals.browserTimezone,
        // Volatile values are kept as CONTEXT only — never folded into a digest or identity key.
        // The raw browser UTC offset also stays in `rawDeviceAttributes.timezone_offset`.
        storageQuotaContext: collectedSignals?.systemEntropy.storageQuota ?? null,
        cdpReasonIds: securitySignals.cdpReasonIds,
        inspectorSignals: {
          // Only STRONG two-probe CDP proof may claim an attached bridge. The weak
          // Error.prototype.name preview is telemetry in `inspectorProbes` only.
          cdpAttached: securitySignals.cdpAttached,
          devtoolsActiveVerified: false,
          viewportContractionNormalized: false,
        },
        // Fresh interaction evidence / human corroboration (recomputed above on every call).
        humanCorroboration: securitySignals.isBot ? 0 : freshHuman.score,
        humanCorroborationChecks: freshHuman.checks,
        interactionEvidence: freshInteractionEvidence,
        inspectorProbes: { ...inspectorProbes },
        // Top-level mirrors so no server-side spelling path can miss the verdict.
        // All aliases derive from the same authoritative session lock; `incognito` is
        // forced false whenever the stable confidence is 'low'.
        incognito: incognitoVerified,
        isIncognito: incognitoVerified,
        isPrivate: incognitoVerified,
        incognitoLikely: incognitoVerified,
        privateMode: incognitoVerified,
        incognitoMethod: incog.method,
        // 'high' for a genuine incognito verdict (the decisive storage-denial gate);
        // 'low' verdicts are always emitted as false above.
        incognitoConfidence: incog.confidence,
        idbDurabilityRatio: incog.idbDurabilityRatio,
        opfsFlushMs: incog.opfsFlushMs,
        // Additive, flag-gated diagnostics — absent unless intelDiag=1 or the session
        // key is set. Never consumed by any verdict or risk path.
        ...(incog.diagnostics ? { diagnostics: incog.diagnostics } : {}),
      }),
    });

    if (!response.ok) {
      const errBody = await response.json().catch(() => ({}));
      throw new Error(errBody.error || `Request failed with status ${response.status}`);
    }

    const data = (await response.json()) as IntelVisitorResponse;
    saveFirstPartyStorage(
      data.visitorId,
      data.visitorToken,
      data.statistics.currentSessionId,
      data.historyBackup
    );
    // Waterfall heal: mirror the server-issued canonical identity into IndexedDB + the
    // non-HttpOnly client cookie, so an evicted localStorage still recovers it next visit.
    await persistIdentity({
      visitor_id: data.visitorId,
      hardware_fingerprint: identityHardwareFingerprint,
      browser_fingerprint: identityBrowserFingerprint,
      created_at: new Date().toISOString(),
    }).catch(() => false);
    return data;
  };

  inFlightRequest = execute().finally(() => {
    inFlightRequest = null;
  });

  return inFlightRequest;
}

// Start the storage-physics probe as soon as the module loads — before App mounts, so the
// main-thread timing is not skewed by the first paint and initial network activity.
if (typeof window !== 'undefined' && typeof indexedDB !== 'undefined') {
  void detectIncognitoMode();
}

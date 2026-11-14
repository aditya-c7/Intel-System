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

export function normalizeTimezoneId(tz: string | null | undefined): string {
  if (!tz || typeof tz !== 'string') return '';
  const cleaned = tz.trim().toLowerCase();
  if (!cleaned || cleaned === 'unknown' || cleaned === 'unavailable') return '';
  return IANA_TIMEZONE_ALIASES[cleaned] || cleaned;
}

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

function cleanIspBrandText(ispText: string, orgText: string): string {
  const candidates = [ispText, orgText];
  for (const candidate of candidates) {
    const cleaned = candidate.replace(/\s+/g, ' ').trim();
    if (!cleaned || UNKNOWN_NETWORK_NAME_PATTERN.test(cleaned)) continue;
    return cleaned;
  }
  return 'Unknown ISP';
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
    brandName: cleanIspBrandText(ispText, orgText),
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

/**
 * 1. Native WebGL GPU Inspector:
 * Queries WEBGL_debug_renderer_info for UNMASKED_VENDOR_WEBGL and UNMASKED_RENDERER_WEBGL,
 * plus MAX_TEXTURE_SIZE.
 */
function inspectWebGlGpu(): {
  gpuVendor: string;
  gpuRenderer: string;
  maxTextureSize: number;
} {
  if (typeof document === 'undefined') {
    return { gpuVendor: 'Unavailable', gpuRenderer: 'Unavailable', maxTextureSize: 0 };
  }

  try {
    const canvas = document.createElement('canvas');
    const gl =
      (canvas.getContext('webgl2') as WebGLRenderingContext | null) ||
      (canvas.getContext('webgl') as WebGLRenderingContext | null) ||
      (canvas.getContext('experimental-webgl') as WebGLRenderingContext | null);

    if (!gl) {
      return { gpuVendor: 'Unavailable', gpuRenderer: 'Unavailable', maxTextureSize: 0 };
    }

    const debugExt = gl.getExtension('WEBGL_debug_renderer_info');
    const rawVendor = debugExt
      ? gl.getParameter(debugExt.UNMASKED_VENDOR_WEBGL)
      : gl.getParameter(gl.VENDOR);
    const rawRenderer = debugExt
      ? gl.getParameter(debugExt.UNMASKED_RENDERER_WEBGL)
      : gl.getParameter(gl.RENDERER);
    const rawMaxTex = gl.getParameter(gl.MAX_TEXTURE_SIZE);

    const loseExt = gl.getExtension('WEBGL_lose_context');
    if (loseExt && typeof loseExt.loseContext === 'function') {
      loseExt.loseContext();
    }

    return {
      gpuVendor: typeof rawVendor === 'string' && rawVendor.trim() ? rawVendor.trim() : 'Standard WebGL Vendor',
      gpuRenderer:
        typeof rawRenderer === 'string' && rawRenderer.trim()
          ? rawRenderer.trim()
          : 'Standard WebGL Renderer',
      maxTextureSize: typeof rawMaxTex === 'number' && Number.isFinite(rawMaxTex) ? rawMaxTex : 0,
    };
  } catch {
    return { gpuVendor: 'Unavailable', gpuRenderer: 'Unavailable', maxTextureSize: 0 };
  }
}

/**
 * 2. Native Canvas 2D Signature:
 * Renders custom geometry, gradients, and multi-font text onto an offscreen <canvas>
 * and hashes the data URL via SHA-256 into a compact 16-char hex signature.
 */
async function computeCanvas2dSignature(): Promise<string> {
  if (typeof document === 'undefined') return 'unavailable';
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 260;
    canvas.height = 64;
    const ctx = canvas.getContext('2d');
    if (!ctx) return 'unavailable';

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

    const dataUrl = canvas.toDataURL('image/png');
    const fullHex = await sha256Hex(dataUrl);
    return fullHex.slice(0, 16);
  } catch {
    return 'restricted';
  }
}

/**
 * 3. Native Web Audio Signature:
 * Uses OfflineAudioContext with a triangle OscillatorNode and DynamicsCompressorNode
 * to render a short in-memory buffer, sums channel data samples, and hashes via SHA-256.
 */
async function computeWebAudioSignature(): Promise<string> {
  if (typeof window === 'undefined') return 'unavailable';
  try {
    const OfflineCtx =
      window.OfflineAudioContext ||
      (window as unknown as { webkitOfflineAudioContext?: typeof OfflineAudioContext })
        .webkitOfflineAudioContext;
    if (!OfflineCtx) return 'unsupported';

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

    if (!renderedBuffer) return 'timeout';

    const channelData = renderedBuffer.getChannelData(0);
    let sampleSum = 0;
    const quantizedSamples: string[] = [];
    for (let i = 450; i < channelData.length; i += 50) {
      const val = channelData[i];
      sampleSum += Math.abs(val);
      quantizedSamples.push(val.toFixed(6));
    }
    const fingerprintPayload = `${sampleSum.toFixed(8)}|${quantizedSamples.join(',')}`;
    const fullHex = await sha256Hex(fingerprintPayload);
    return fullHex.slice(0, 16);
  } catch {
    return 'restricted';
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

export async function collectBrowserDeviceInfo(): Promise<BrowserDeviceInfo> {
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent || '' : '';
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
        ]),
        new Promise<null>((resolve) => setTimeout(() => resolve(null), 150)),
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

  if (isBrave || braveBrand) {
    const ver = braveBrand?.version || (chromeUa ? chromeUa[1] : '');
    browser = ver ? `Brave ${ver}` : 'Brave';
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
    const androidMatch = ua.match(/Android ([\d.]+)/);
    os = androidMatch && androidMatch[1] ? `Android ${androidMatch[1]}` : 'Android';
  } else if (/iPad/i.test(ua) || (/Macintosh/i.test(ua) && maxTouchPoints > 2)) {
    os = 'iPadOS';
  } else if (/iPhone|iPod/i.test(ua) || /iOS/i.test(hintPlatform)) {
    os = 'iOS';
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

  let deviceType: BrowserDeviceInfo['deviceType'] = 'Unknown';
  if (
    /iPad|Tablet|PlayBook|Silk/i.test(ua) ||
    os === 'iPadOS' ||
    (/Android/i.test(ua) && !/Mobile/i.test(ua))
  ) {
    deviceType = 'Tablet';
  } else if (uaData?.mobile === true || /Mobile|iPhone|iPod|Android.*Mobile|Windows Phone/i.test(ua)) {
    deviceType = 'Mobile';
  } else if (
    uaData?.mobile === false ||
    os.startsWith('macOS') ||
    os.startsWith('Windows') ||
    os === 'Linux' ||
    os === 'ChromeOS'
  ) {
    deviceType = 'Desktop';
  }

  const rawPlatform = hintPlatform || (typeof navigator !== 'undefined' ? navigator.platform : '');
  const platform = rawPlatform && rawPlatform.trim() ? rawPlatform.trim() : 'Unavailable';

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
    incognito: incognitoVerdict.isPrivate,
    isIncognito: incognitoVerdict.isPrivate,
    privateMode: incognitoVerdict.isPrivate,
    incognitoMethod: incognitoVerdict.method,
    idbDurabilityRatio: incognitoVerdict.idbDurabilityRatio,
    opfsFlushMs: incognitoVerdict.opfsFlushMs,
  };
}

/**
 * Collects native Hardware & Rendering Entropy and computes a deterministic Stateless
 * Hardware ID (`hwid_<20_hex_chars>`) using SHA-256.
 */
export async function collectHardwareSignals(
  browserDevice: BrowserDeviceInfo
): Promise<HardwareSignals> {
  const [{ gpuVendor, gpuRenderer, maxTextureSize }, canvasHash, audioHash] = await Promise.all([
    Promise.resolve(inspectWebGlGpu()),
    computeCanvas2dSignature(),
    computeWebAudioSignature(),
  ]);

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

  let architecture = browserDevice.platform || 'Standard';
  const uaData =
    nav ? ((nav as unknown as { userAgentData?: NavigatorUAData }).userAgentData ?? null) : null;
  if (uaData && typeof uaData.getHighEntropyValues === 'function') {
    try {
      const entropy = await Promise.race([
        uaData.getHighEntropyValues(['architecture', 'bitness']),
        new Promise<null>((resolve) => setTimeout(() => resolve(null), 120)),
      ]);
      if (entropy?.architecture) {
        architecture = entropy.bitness
          ? `${entropy.architecture} (${entropy.bitness}-bit)`
          : entropy.architecture;
      }
    } catch {
      // Keep platform fallback
    }
  }

  const fingerprintSeed = [
    gpuVendor,
    gpuRenderer,
    String(maxTextureSize),
    browserDevice.screenResolution,
    String(colorDepth),
    browserDevice.pixelRatio,
    String(cpuCores ?? 'na'),
    String(deviceMemoryGb ?? 'na'),
    colorGamut,
    canvasHash,
    audioHash,
    architecture,
  ].join('||');

  const fullDigest = await sha256Hex(fingerprintSeed);
  const hardwareId = `hwid_${fullDigest.slice(0, 20)}`;

  try {
    localStorage.setItem(STORAGE_KEYS.HARDWARE_ID, hardwareId);
  } catch {
    // Ignore storage block
  }

  return {
    hardwareId,
    gpuVendor,
    gpuRenderer,
    maxTextureSize,
    canvasHash,
    audioHash,
    cpuCores,
    deviceMemoryGb,
    colorDepth,
    maxTouchPoints,
    hdrSupported,
    colorGamut,
    architecture,
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
 * Bot & automation verdict.
 */
export interface BotAutomationSignals {
  isBot: boolean;
  isHeadless: boolean;
  botReason: string;
  webdriver: boolean;
  cdpDetected: boolean;
}

/**
 * Incognito / private-browsing verdict produced by the multi-engine physics probe.
 */
export interface IncognitoDetectionResult {
  isPrivate: boolean;
  browserName: string;
  method: string;
  quotaBytes: number | null;
  headroomGiB: number | null;
  idbDurabilityRatio: number | null;
  opfsFlushMs: number | null;
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
  try {
    return parseInt('-1', 10).toFixed(-1).length;
  } catch (error) {
    if (error instanceof Error) {
      return error.message.length;
    }
    return 0;
  }
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
    { pattern: /swiftshader/, label: 'Google SwiftShader Software Renderer' },
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
    const softwareRenderer = SOFTWARE_RENDERER_PATTERN.test(signature);
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

const CDP_GLOBAL_KEY_PATTERN =
  /^cdc_|^\$cdc_|^__\$webdriverAsyncExecutor|^__webdriver|^__selenium|^__fxdriver|^__playwright|^__pwInitScripts|^_phantom|^callPhantom|^domAutomation/i;

/**
 * Bot & automation detection.
 * Checks `navigator.webdriver`, Chrome DevTools Protocol / WebDriver bindings on
 * `window` and `document`, a patched `Navigator.prototype.webdriver` getter,
 * headless User-Agents, software GPUs, zero outer geometry and empty languages.
 */
export function detectBotAndAutomation(gpuRenderer: string): BotAutomationSignals {
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

  let cdpDetected = false;
  const scanTarget = (target: object | undefined): void => {
    if (!target || cdpDetected) return;
    try {
      for (const key of Object.keys(target as Record<string, unknown>)) {
        if (CDP_GLOBAL_KEY_PATTERN.test(key)) {
          cdpDetected = true;
          return;
        }
      }
    } catch {
      // Ignore hostile proxies over the global object.
    }
  };
  scanTarget(typeof window !== 'undefined' ? window : undefined);
  scanTarget(typeof document !== 'undefined' ? document : undefined);

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
  const isHeadless = headlessUa || softwareGpu || zeroGeometry;

  let isBot = false;
  let botReason = 'Verified human runtime & native DOM prototypes';

  if (webdriver) {
    isBot = true;
    botReason = 'navigator.webdriver flag is enabled (WebDriver controlled session)';
  } else if (cdpDetected) {
    isBot = true;
    botReason = 'Chrome DevTools Protocol binding exposed on window/document';
  } else if (webdriverGetterTampered) {
    isBot = true;
    botReason = 'Navigator.prototype.webdriver getter overridden (anti-detect automation patch)';
  } else if (headlessUa) {
    isBot = true;
    botReason = 'Headless browser User-Agent signature detected';
  } else if (softwareGpu) {
    isBot = true;
    botReason = `Software GPU renderer (${gpuRenderer || 'unknown'})`;
  } else if (zeroGeometry) {
    isBot = true;
    botReason = 'Zero outer window geometry (headless viewport)';
  } else if (emptyLanguages) {
    isBot = true;
    botReason = 'navigator.languages array is empty';
  }

  return { isBot, isHeadless, botReason, webdriver, cdpDetected };
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
): { detected: boolean; signals: string[]; reasons: string[] } {
  const signals: string[] = [];
  const reasons: string[] = [];

  const browserLabel = `${browserDevice.browser || ''} ${browserDevice.platform || ''}`;
  const geckoEngine = /firefox|gecko|spidermonkey/i.test(browserLabel);
  if (!geckoEngine) return { detected: false, signals, reasons };

  signals.push('gecko-engine');

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

  if (incognitoMethod === 'firefox-opfs-rejected') {
    signals.push('tor-browser-rfp-opfs-rejected');
    reasons.push('OPFS write rejected by the Gecko private context');
  }

  const uniqueSignals = Array.from(new Set(signals));
  const rfpSignals = uniqueSignals.filter((signal) => signal !== 'gecko-engine');
  const detected = geckoEngine && rfpSignals.length >= 2;
  return { detected, signals: uniqueSignals, reasons };
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
 * Layer 1 — Chromium IndexedDB commit-durability physics (detectIncognito v1.9.0).
 *
 * A normal profile fsyncs `strict` transactions to disk, so `strict` commits are
 * measurably slower than `relaxed` ones. An off-the-record profile keeps IndexedDB
 * in RAM and the ratio collapses toward 1.0. Returns the median
 * `strict / relaxed` ratio, or `null` when the browser ignores the durability hint
 * or the probe cannot finish inside its budget. The database is always closed and
 * deleted through the `settled`-guarded `finish()`.
 */
async function probeChromiumIdbDurability(): Promise<number | null> {
  if (typeof indexedDB === 'undefined') return null;
  const PAYLOAD = 16384;
  const WRITES = 15;
  const ROUNDS = 15;
  const MIN_ROUNDS = 7;
  const CAP_MS = 1000;
  const dbName = '__di_' + Math.random().toString(36).slice(2);
  const payload = new Uint8Array(PAYLOAD);

  return new Promise<number | null>((resolve) => {
    let settled = false;
    const finish = (val: number | null, db?: IDBDatabase) => {
      if (settled) return;
      settled = true;
      try { db?.close(); } catch { /* ignore */ }
      try { indexedDB.deleteDatabase(dbName); } catch { /* ignore */ }
      resolve(val);
    };
    const safetyTimer = setTimeout(() => finish(null), 1400);
    try {
      const req = indexedDB.open(dbName, 1);
      req.onupgradeneeded = () => { req.result.createObjectStore('s'); };
      req.onerror = () => { clearTimeout(safetyTimer); finish(null); };
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
        if (!honored) { clearTimeout(safetyTimer); finish(null, db); return; }

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
          for (let r = 0; r < ROUNDS; r++) {
            const rel = await block('relaxed');
            const str = await block('strict');
            ratios.push(rel > 0 ? str / rel : Infinity);
            if (ratios.length >= MIN_ROUNDS && performance.now() - start >= CAP_MS) break;
          }
          ratios.sort((a, b) => a - b);
          const median = ratios.length > 0 ? ratios[ratios.length >> 1] : null;
          clearTimeout(safetyTimer);
          finish(median !== null && Number.isFinite(median) ? Number(median.toFixed(3)) : null, db);
        })().catch(() => { clearTimeout(safetyTimer); finish(null, db); });
      };
    } catch { clearTimeout(safetyTimer); finish(null); }
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
 * Multi-engine private-browsing detection (3 layers, no quota veto).
 *
 * The JS engine is fingerprinted through the `toFixed` RangeError length and
 * cross-checked against the User-Agent. Firefox and Safari expose private mode
 * as a blocked OPFS / IndexedDB write; Chromium is resolved through three
 * independent physics vectors: quota headroom, legacy temp quota, and (never
 * vetoed) storage physics — IndexedDB `strict` commit durability plus an OPFS
 * worker `flush()` timing probe. Chrome 156+ forces `quota = usage + 10.00 GiB`
 * in both modes, so the headroom band is never allowed to veto layers 3C.
 * Never throws and always fills all seven result fields. The promise is cached
 * at module level, so the eager module-load call and every later caller share
 * one probe run.
 */
export async function detectIncognitoMode(): Promise<IncognitoDetectionResult> {
  if (cachedIncognitoPromise) return cachedIncognitoPromise;

  cachedIncognitoPromise = (async (): Promise<IncognitoDetectionResult> => {
    const nav = typeof navigator !== 'undefined' ? navigator : undefined;
    let ua = '';
    try {
      ua = nav?.userAgent || '';
    } catch {
      ua = '';
    }
    const feid = getEngineErrorLength();

    const isV8 = feid === 51 || /Chrome|Chromium|Edg|OPR|Brave/i.test(ua);
    const isSpiderMonkey = feid === 25 || /Firefox/i.test(ua);
    const isJSC =
      feid === 44 || feid === 43 || (/Safari/i.test(ua) && !/Chrome|Chromium|Edg|OPR/i.test(ua));

    let engine: 'chromium' | 'firefox' | 'safari';
    if (isV8) {
      engine = 'chromium';
    } else if (isSpiderMonkey) {
      engine = 'firefox';
    } else if (isJSC) {
      engine = 'safari';
    } else {
      engine = 'chromium';
    }

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

    try {
      if (engine === 'firefox') {
        const opfs = await probeOpfsDirectory();
        if (opfs.status === 'resolved') {
          return {
            isPrivate: false,
            browserName,
            method: 'firefox-opfs-resolved',
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
            method: 'firefox-opfs-rejected',
            quotaBytes,
            headroomGiB,
            idbDurabilityRatio: null,
            opfsFlushMs: null,
          };
        }

        // No OPFS at all (older Firefox) — the `inPrivate` IndexedDB open refuses
        // with InvalidStateError inside a private window.
        const idbPrivate = await probeFirefoxIdbPrivacy();
        return {
          isPrivate: idbPrivate === true,
          browserName,
          method: 'firefox-idb-probe',
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
            method: 'safari-opfs-resolved',
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
            method: 'safari-opfs-rejected',
            quotaBytes,
            headroomGiB,
            idbDurabilityRatio: null,
            opfsFlushMs: null,
          };
        }

        // Private Safari still opens IndexedDB but rejects Blob values with
        // "Blobs are not yet supported".
        const blobPrivate = await probeSafariIdbBlob();
        return {
          isPrivate: blobPrivate === true,
          browserName,
          method: 'safari-idb-blob',
          quotaBytes,
          headroomGiB,
          idbDurabilityRatio: null,
          opfsFlushMs: null,
        };
      }

      // 3A — quota headroom physics (never a veto, only positive evidence).
      if (headroomBytes !== null && headroomBytes > 0 && headroomBytes < 9.5 * GIB_BYTES) {
        return {
          isPrivate: true,
          browserName,
          method: `chromium-quota-headroom (${headroomGiB} GiB)`,
          quotaBytes,
          headroomGiB,
          idbDurabilityRatio: null,
          opfsFlushMs: null,
        };
      }

      // 3B — legacy temp-storage quota versus the V8 heap ceiling.
      const webkitQuota = await queryWebkitTemporaryQuota();
      const heapLimit = readJsHeapSizeLimit();
      if (
        webkitQuota !== null &&
        heapLimit !== null &&
        webkitQuota < 2 * heapLimit &&
        webkitQuota < 9.5 * GIB_BYTES
      ) {
        return {
          isPrivate: true,
          browserName,
          method: 'chromium-webkit-temp-quota',
          quotaBytes,
          headroomGiB,
          idbDurabilityRatio: null,
          opfsFlushMs: null,
        };
      }

      // 3C — storage physics. This layer is NEVER vetoed by a 10.00 GiB headroom:
      // Chrome 156 reports that headroom in both normal and off-the-record modes.
      const idbRatio = await probeChromiumIdbDurability();
      const opfsProbe = await probeChromiumOpfsWorkerFlush();
      const opfsFlushMs = opfsProbe ? opfsProbe.medianFlushMs : null;

      const idbIndicatesIncognito = idbRatio !== null && idbRatio < 1.3;
      const opfsIndicatesIncognito =
        opfsProbe !== null &&
        (opfsProbe.medianFlushMs < 0.12 || opfsProbe.flushToWriteRatio < 0.85);

      if (
        idbIndicatesIncognito ||
        (idbRatio === null && opfsIndicatesIncognito) ||
        (idbRatio !== null && idbRatio < 1.42 && opfsIndicatesIncognito)
      ) {
        return {
          isPrivate: true,
          browserName,
          method: idbIndicatesIncognito
            ? `idb-memenv-durability-ratio (${idbRatio}x)`
            : `opfs-ram-flush (${opfsFlushMs}ms)`,
          quotaBytes,
          headroomGiB,
          idbDurabilityRatio: idbRatio,
          opfsFlushMs,
        };
      }

      return {
        isPrivate: false,
        browserName,
        method: `disk-persisted-verified (IDB ${idbRatio ?? 'n/a'}x)`,
        quotaBytes,
        headroomGiB,
        idbDurabilityRatio: idbRatio,
        opfsFlushMs,
      };
    } catch {
      return {
        isPrivate: false,
        browserName,
        method: 'probe-error',
        quotaBytes,
        headroomGiB,
        idbDurabilityRatio: null,
        opfsFlushMs: null,
      };
    }
  })();

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
 * Evaluates First-Party Security & Anomaly Signals ("Smart Signals") and computes an
 * explainable Suspect & Risk Score (0-10).
 */
export async function evaluateSecuritySignals(
  browserDevice: BrowserDeviceInfo,
  hardwareSignals: HardwareSignals,
  clientGeoHint: ClientGeoHint | null,
  hasStoredIdentity: boolean
): Promise<SecuritySignals> {
  // 1. Automation & Headless Bot Detection (CDP bindings, native prototype checks)
  const botAssessment = detectBotAndAutomation(hardwareSignals.gpuRenderer);
  const botSignals: string[] = botAssessment.isBot ? [botAssessment.botReason] : [];

  // 2. VPN / Proxy & Network Classification (Task 1 classifier)
  const browserTimezone = browserDevice.timezone || 'Unavailable';
  const ipTimezone =
    clientGeoHint?.timezone && clientGeoHint.timezone !== 'Unknown'
      ? clientGeoHint.timezone
      : 'Unavailable';

  const timezoneMismatch =
    browserTimezone !== 'Unavailable' &&
    ipTimezone !== 'Unavailable' &&
    !areTimezonesEquivalent(browserTimezone, ipTimezone);

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
  const vpnSuspected = timezoneMismatch || datacenterAsn;

  // 3. VM / Hypervisor & OS Identity Integrity (WebGL GPU + native accessors)
  const vmStatus = detectVmAndIntegrity(hardwareSignals.gpuVendor, hardwareSignals.gpuRenderer, {
    screenResolution: browserDevice.screenResolution,
    datacenterAsn,
  });
  const tamperReasons: string[] = [];
  if (vmStatus.isVirtualMachine) {
    tamperReasons.push(vmStatus.vmReason);
  }
  if (vmStatus.isOsTampered && !vmStatus.isVirtualMachine) {
    tamperReasons.push(vmStatus.vmReason);
  }
  const tamperDetected = vmStatus.isOsTampered || vmStatus.isVirtualMachine;

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
  const privateBrowsing = (await hasPersistedStorageGrant())
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
  let incognitoLikely = privateBrowsing.likely;

  let localStorageAvailable = true;
  try {
    const probeKey = '__intel_storage_probe__';
    localStorage.setItem(probeKey, '1');
    localStorage.removeItem(probeKey);
  } catch {
    localStorageAvailable = false;
    incognitoLikely = true;
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
  const tampering = detectBrowserTampering({
    webglVendor: hardwareSignals.gpuVendor,
    webglRenderer: hardwareSignals.gpuRenderer,
  });

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

  const incognitoScore = incognito.isPrivate ? 4 : 0;
  if (incognitoScore > 0) {
    const storageDetail =
      storageQuotaMb !== null
        ? `${storageQuotaMb} MB storage quota`
        : !localStorageAvailable
        ? 'first-party storage write blocked'
        : 'restricted storage';
    riskFactors.push(`Private / ephemeral storage (+4 card): ${storageDetail}`);
  }

  const botScore = botAssessment.isBot ? 9 : 0;
  if (botScore > 0) {
    riskFactors.push(
      `Automation / headless runtime (+9 card): ${
        botSignals[0] || 'automation runtime detected'
      }`
    );
  }

  const vpnScore = torBrowserClient.detected
    ? 9
    : datacenterAsn && timezoneMismatch
    ? 8
    : datacenterAsn
    ? 6
    : timezoneMismatch
    ? 5
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
    (botAssessment.isBot ? 3 : 0) +
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
    isBot: botAssessment.isBot,
    botSignals,
    vpnSuspected,
    timezoneMismatch,
    browserTimezone,
    ipTimezone,
    datacenterAsn,
    cloudOrMaskedGpu,
    vpnReasons,
    tamperDetected,
    tamperReasons,
    incognitoLikely: incognito.isPrivate,
    isIncognito: incognito.isPrivate,
    incognito: incognito.isPrivate,
    privateMode: incognito.isPrivate,
    incognitoMethod: incognito.method,
    headroomGiB: incognito.headroomGiB,
    idbDurabilityRatio: incognito.idbDurabilityRatio,
    opfsFlushMs: incognito.opfsFlushMs,
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
    /* Incognito confidence + explanation (client probe) */
    incognitoConfidence: privateBrowsing.confidence,
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
    /* Phase 2 — client-side Tor Browser fingerprint (Gecko RFP + letterboxing) */
    isTorBrowserClient: torBrowserClient.detected,
    /* Phase 5 — browser tampering (DevTools device emulation / anti-detect browsers) */
    tampering: tampering.tampering,
    tamperingConfidence: tampering.tampering_confidence,
    tamperingMlScore: tampering.tampering_ml_score,
    tamperingDetails: tampering.tampering_details,
    developerTools: false,
    /* Phase 5 — active call detection (pruned when unsupported) */
    activeCall: activeCall.active,
    activeCallSupported: activeCall.supported,
    activeCallReasons: activeCall.reasons,
    /* Phase 6 — raw device attributes for the event JSON inspector */
    rawDeviceAttributes: collectRawDeviceAttributes(),
    /* Privacy settings: Tor Browser RFP / anti-fingerprinting evidence */
    privacySettings: torBrowserClient.detected,
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
  const supported = claimsMobile || hasRtc || Boolean(audioSessionType) || maxTouchPoints > 0;

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

const PROBE_FONT_FAMILIES = [
  'Arial',
  'Courier New',
  'Georgia',
  'Helvetica Neue',
  'Menlo',
  'Monaco',
  'Roboto',
  'Segoe UI',
  'Tahoma',
  'Times New Roman',
  'Trebuchet MS',
  'Verdana',
];

/**
 * Measures font metrics, emoji bounding boxes, canvas stability, WebGL hashes and the math
 * vector with native APIs. Returns `null` only when the DOM is unavailable.
 */
export function collectRawDeviceAttributes(): RawDeviceAttributes | null {
  if (typeof document === 'undefined' || typeof window === 'undefined') return null;

  const makeSpan = (text: string, style: string): HTMLSpanElement | null => {
    try {
      const span = document.createElement('span');
      span.textContent = text;
      span.style.position = 'absolute';
      span.style.left = '-9999px';
      span.style.top = '0';
      span.style.visibility = 'hidden';
      span.style.whiteSpace = 'nowrap';
      span.style.fontSize = '72px';
      if (style) span.style.fontFamily = style;
      document.body.appendChild(span);
      return span;
    } catch {
      return null;
    }
  };

  const measure = (span: HTMLSpanElement | null): number => {
    if (!span) return 0;
    try {
      const width = span.getBoundingClientRect().width;
      return Number.isFinite(width) ? Number(width.toFixed(6)) : 0;
    } catch {
      return 0;
    }
  };

  const fontPreferences: Record<string, number> = {};
  for (const [key, family] of Object.entries(FONT_PROFILES)) {
    const span = makeSpan('mmmmmmmmmmlli', family);
    fontPreferences[key] = measure(span);
    span?.remove();
  }

  const detectedFonts: string[] = [];
  for (const family of PROBE_FONT_FAMILIES) {
    const withFamily = makeSpan('mmmmmmmmmmlli', `"${family}", monospace`);
    const without = makeSpan('mmmmmmmmmmlli', 'monospace');
    const diff = Math.abs(measure(withFamily) - measure(without));
    withFamily?.remove();
    without?.remove();
    if (diff > 0.1) detectedFonts.push(family);
  }

  let emoji: RawDeviceAttributes['emoji'] = null;
  const emojiSpan = makeSpan('😀', 'serif');
  if (emojiSpan) {
    try {
      const rect = emojiSpan.getBoundingClientRect();
      emoji = {
        font: 'serif',
        width: Number(rect.width.toFixed(6)),
        height: Number(rect.height.toFixed(6)),
        top: Number(rect.top.toFixed(6)),
        bottom: Number(rect.bottom.toFixed(6)),
        left: Number(rect.left.toFixed(6)),
        right: Number(rect.right.toFixed(6)),
        x: Number(rect.x.toFixed(6)),
        y: Number(rect.y.toFixed(6)),
      };
    } catch {
      emoji = null;
    }
    emojiSpan.remove();
  }

  // Canvas: winding + double-encoded geometry/text stability (anti-fingerprinting noise).
  let winding: boolean | null = null;
  let geometry = 'unavailable';
  let textHash = 'unavailable';
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 240;
    canvas.height = 60;
    const ctx = canvas.getContext('2d');
    if (ctx) {
      const path = new Path2D('M 10 10 L 100 10 L 100 50 Z');
      try {
        winding = ctx.isPointInPath(path, 50, 20, 'evenodd');
      } catch {
        winding = null;
      }
      const paint = () => {
        ctx.fillStyle = '#f60';
        ctx.fillRect(0, 0, 120, 30);
        ctx.fillStyle = '#069';
        ctx.font = '14px "Arial"';
        ctx.fillText('Intel🔒System', 2, 45);
        ctx.strokeStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.beginPath();
        ctx.arc(60, 30, 20, 0, Math.PI * 2);
        ctx.stroke();
      };
      const read = () => canvas.toDataURL();
      paint();
      const first = read();
      paint();
      const second = read();
      geometry = first === second ? hash128(first) : 'unstable';
      textHash = first === second ? hash128(`${first}|text`) : 'unstable';
    }
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
      webglBasics = {
        version: gl.getParameter(gl.VERSION) || 'unavailable',
        vendor: gl.getParameter(gl.VENDOR) || 'unavailable',
        renderer: gl.getParameter(gl.RENDERER) || 'unavailable',
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

  const audio = (() => {
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
      void context.startRendering();
      return Number(context.sampleRate.toFixed(6));
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
    canvas: { winding, geometry, text: textHash },
    languages,
    webgl_extensions: webglExtensions,
    webgl_basics: webglBasics,
    screen_resolution: [window.screen?.width ?? 0, window.screen?.height ?? 0],
    touch_support: {
      touch_event: 'ontouchstart' in window,
      touch_start: typeof (window as unknown as { TouchEvent?: unknown }).TouchEvent === 'function',
      max_touch_points: navigator.maxTouchPoints ?? 0,
    },
    oscpu: (navigator as unknown as { oscpu?: string }).oscpu || '',
    architecture: Number((navigator as unknown as { architecture?: number }).architecture ?? 255),
    cookies_enabled: navigator.cookieEnabled,
    hardware_concurrency: navigator.hardwareConcurrency ?? null,
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

export async function identifyCurrentVisitor(options?: {
  manualRefresh?: boolean;
}): Promise<IntelVisitorResponse> {
  if (inFlightRequest && !options?.manualRefresh) {
    return inFlightRequest;
  }

  const execute = async (): Promise<IntelVisitorResponse> => {
    const [browserDevice, clientGeoHint] = await Promise.all([
      collectBrowserDeviceInfo(),
      collectClientGeoHint(),
    ]);
    const stored = getFirstPartyStorage();
    const hardwareSignals = await collectHardwareSignals(browserDevice);
    const securitySignals = await evaluateSecuritySignals(
      browserDevice,
      hardwareSignals,
      clientGeoHint,
      Boolean(stored.visitorId && stored.visitorToken)
    );

    const pageLoadId = options?.manualRefresh
      ? 'manual_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8)
      : CURRENT_PAGE_LOAD_ID;

    // Module-cached: this is the same probe run that started at module load.
    const incog = await detectIncognitoMode();

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
        clientGeoHint,
        securityEnvelope,
        // Top-level mirrors so no server-side spelling path can miss the verdict.
        incognito: incog.isPrivate,
        isIncognito: incog.isPrivate,
        privateMode: incog.isPrivate,
        incognitoMethod: incog.method,
        idbDurabilityRatio: incog.idbDurabilityRatio,
        opfsFlushMs: incog.opfsFlushMs,
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

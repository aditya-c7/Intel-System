import type {
  BrowserDeviceInfo,
  HardwareSignals,
  SecuritySignals,
  RiskLevel,
  PersistenceMode,
  IntelVisitorResponse,
  SignedHistoryBackup,
} from '../types/visitor';

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
  /cloudflare|amazon|aws|digitalocean|hetzner|m247|linode|akamai|ovh|microsoft corporation|azure|choopa|vultr|datacamp|leaseweb|packethub|tzulo|cogent|equinix|fastly|scaleway|upcloud|contabo|kamatera|nordvpn|expressvpn|mullvad|proton ag|surfshark|private internet access|cyberghost|ivpn|tor exit|hosting|datacenter|cloud|vps|dedibox/i;

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

  return {
    browser,
    os,
    deviceType,
    platform,
    screenResolution,
    pixelRatio,
    language,
    timezone,
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
 * Evaluates First-Party Security & Anomaly Signals ("Smart Signals") and computes an
 * explainable Suspect & Trust Score (0-100).
 */
export async function evaluateSecuritySignals(
  browserDevice: BrowserDeviceInfo,
  hardwareSignals: HardwareSignals,
  clientGeoHint: ClientGeoHint | null,
  hasStoredIdentity: boolean
): Promise<SecuritySignals> {
  const nav = typeof navigator !== 'undefined' ? navigator : undefined;
  const win = typeof window !== 'undefined' ? (window as unknown as Record<string, unknown>) : {};
  const ua = nav?.userAgent || '';

  // 1. Automation & Headless Bot Detection
  const botSignals: string[] = [];
  if (nav?.webdriver === true) {
    botSignals.push('navigator.webdriver is enabled');
  }
  if (!nav?.languages || nav.languages.length === 0) {
    botSignals.push('navigator.languages array is empty');
  }
  if (
    /SwiftShader|llvmpipe|Mesa OffScreen|Software Rasterizer/i.test(
      hardwareSignals.gpuRenderer
    )
  ) {
    botSignals.push(`Headless virtual GPU renderer (${hardwareSignals.gpuRenderer})`);
  }
  if (
    win.__playwright ||
    win.__pw_manual ||
    win._phantom ||
    win.callPhantom ||
    win.__nightmare ||
    win.domAutomation ||
    win.domAutomationController
  ) {
    botSignals.push('Automation framework runtime global detected');
  }
  if (/Chrome|Chromium/i.test(ua) && !/Edg|OPR|Firefox/i.test(ua) && typeof win.chrome === 'undefined') {
    botSignals.push('Missing window.chrome runtime object on Chromium UA');
  }
  const isBot = botSignals.length > 0;

  // 2. VPN / Proxy & Datacenter Detection
  const browserTimezone = browserDevice.timezone || 'Unavailable';
  const ipTimezone =
    clientGeoHint?.timezone && clientGeoHint.timezone !== 'Unknown'
      ? clientGeoHint.timezone
      : 'Unavailable';

  const timezoneMismatch =
    browserTimezone !== 'Unavailable' &&
    ipTimezone !== 'Unavailable' &&
    !areTimezonesEquivalent(browserTimezone, ipTimezone);

  const dcCheck = isDatacenterOrVpnNetwork(
    clientGeoHint?.isp,
    clientGeoHint?.org,
    clientGeoHint?.asn,
    Boolean(clientGeoHint?.isVpnOrHosting)
  );
  const datacenterAsn = dcCheck.isDatacenter;

  const vpnReasons: string[] = [];
  if (timezoneMismatch) {
    vpnReasons.push(`Browser timezone (${browserTimezone}) differs from IP timezone (${ipTimezone})`);
  }
  if (dcCheck.matchedReason) {
    vpnReasons.push(dcCheck.matchedReason);
  }
  const vpnSuspected = timezoneMismatch || datacenterAsn;

  // 3. Browser & OS Tamper / Spoofing Detection
  const tamperReasons: string[] = [];
  const rawNavPlatform = nav?.platform || '';
  const uaDataPlatform =
    nav && (nav as unknown as { userAgentData?: NavigatorUAData }).userAgentData?.platform
      ? (nav as unknown as { userAgentData: NavigatorUAData }).userAgentData.platform || ''
      : '';

  const claimsIos = /iPhone|iPad|iPod/i.test(ua);
  const claimsAndroid = /Android/i.test(ua);
  const claimsMac = /Macintosh|Mac OS X/i.test(ua) && !claimsIos;
  const claimsWin = /Windows NT/i.test(ua);

  if (claimsIos && /Win32|Win64|Linux x86_64/i.test(rawNavPlatform)) {
    tamperReasons.push(`User-Agent claims iOS but navigator.platform is ${rawNavPlatform}`);
  }
  if (claimsAndroid && /Win32|Win64|MacIntel/i.test(rawNavPlatform)) {
    tamperReasons.push(`User-Agent claims Android but navigator.platform is ${rawNavPlatform}`);
  }
  if ((claimsIos || claimsAndroid) && hardwareSignals.maxTouchPoints === 0) {
    tamperReasons.push('Mobile User-Agent reported with 0 touch points (maxTouchPoints = 0)');
  }
  if (claimsWin && /MacIntel|iPhone|iPad|Linux arm/i.test(rawNavPlatform)) {
    tamperReasons.push(`User-Agent claims Windows but navigator.platform is ${rawNavPlatform}`);
  }
  if (
    claimsWin &&
    /Apple/i.test(hardwareSignals.gpuVendor) &&
    /Apple M[1-9]|Apple GPU/i.test(hardwareSignals.gpuRenderer)
  ) {
    tamperReasons.push('User-Agent claims Windows on Apple Silicon GPU hardware');
  }
  if (claimsMac && /Win32|Win64|Linux/i.test(rawNavPlatform)) {
    tamperReasons.push(`User-Agent claims macOS but navigator.platform is ${rawNavPlatform}`);
  }
  if (
    uaDataPlatform &&
    ((claimsWin && /macOS|Android|iOS|Linux/i.test(uaDataPlatform)) ||
      (claimsMac && /Windows|Android|Linux/i.test(uaDataPlatform)))
  ) {
    tamperReasons.push(`User-Agent OS conflicts with Client Hints platform (${uaDataPlatform})`);
  }
  const tamperDetected = tamperReasons.length > 0;

  // 4. Private Mode / Storage Quota Inspection
  let storageQuotaMb: number | null = null;
  let incognitoLikely = false;
  if (nav?.storage && typeof nav.storage.estimate === 'function') {
    try {
      const estimate = await nav.storage.estimate();
      if (typeof estimate.quota === 'number' && estimate.quota > 0) {
        storageQuotaMb = Math.round(estimate.quota / (1024 * 1024));
        if (storageQuotaMb < 120) {
          incognitoLikely = true;
        }
      }
    } catch {
      // Ignore storage estimate error
    }
  }

  let localStorageAvailable = true;
  try {
    const probeKey = '__intel_storage_probe__';
    localStorage.setItem(probeKey, '1');
    localStorage.removeItem(probeKey);
  } catch {
    localStorageAvailable = false;
    incognitoLikely = true;
  }

  const persistenceMode: PersistenceMode = !localStorageAvailable || incognitoLikely
    ? 'Private / Restricted Storage'
    : hasStoredIdentity
    ? 'First-Party Cookie'
    : 'First-Party Cookie';

  // 5. Composite Suspect & Trust Score (0-100)
  let rawScore = 0;
  const riskFactors: string[] = [];

  if (isBot) {
    rawScore += 45;
    riskFactors.push(`Automation / headless signal (+45): ${botSignals[0]}`);
  }
  if (timezoneMismatch) {
    rawScore += 25;
    riskFactors.push(
      `Timezone mismatch (+25): Browser ${browserTimezone} vs IP ${ipTimezone}`
    );
  }
  if (datacenterAsn) {
    rawScore += 15;
    riskFactors.push(`Datacenter / VPN network (+15): ${dcCheck.matchedReason || 'Hosting ASN'}`);
  }
  if (tamperDetected) {
    rawScore += 15;
    riskFactors.push(`Environment spoofing (+15): ${tamperReasons[0]}`);
  }
  if (incognitoLikely) {
    rawScore += 10;
    riskFactors.push(
      `Restricted / private storage quota (+10)${
        storageQuotaMb !== null ? `: ${storageQuotaMb} MB` : ''
      }`
    );
  }

  const suspectScore = Math.min(100, rawScore);
  const riskLevel: RiskLevel =
    suspectScore >= 60 ? 'High' : suspectScore >= 25 ? 'Medium' : 'Low';

  return {
    isBot,
    botSignals,
    vpnSuspected,
    timezoneMismatch,
    browserTimezone,
    ipTimezone,
    datacenterAsn,
    vpnReasons,
    tamperDetected,
    tamperReasons,
    incognitoLikely,
    storageQuotaMb,
    persistenceMode,
    suspectScore,
    riskLevel,
    riskFactors,
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

    const response = await fetch('/api/visitor/identify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
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

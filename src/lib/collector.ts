import type {
  BrowserDeviceInfo,
  IntelVisitorResponse,
  SignedHistoryBackup,
} from '../types/visitor';

const STORAGE_KEYS = {
  VISITOR_ID: 'intel_fp_vid',
  VISITOR_TOKEN: 'intel_fp_token',
  SESSION_ID: 'intel_fp_sid',
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
  isVpnOrHosting: boolean;
}

/**
 * Queries public IP and network ISP info directly from the visitor's browser as a fallback hint
 * in case the hosting container proxy strips X-Forwarded-For headers.
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
        const rawAsn = conn.asn ? `AS${String(conn.asn).replace(/^AS/i, '')}` : 'Unknown';
        const lat = typeof data.latitude === 'number' && Number.isFinite(data.latitude) ? data.latitude : null;
        const lon = typeof data.longitude === 'number' && Number.isFinite(data.longitude) ? data.longitude : null;
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
  } | null = null;

  if (uaData && typeof uaData.getHighEntropyValues === 'function') {
    try {
      highEntropy = await Promise.race([
        uaData.getHighEntropyValues(['fullVersionList', 'platform', 'platformVersion']),
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
  const chromeBrand = findBrand(/Google Chrome|Chromium/i);

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

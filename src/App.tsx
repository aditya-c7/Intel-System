import { useEffect, useMemo, useState, useCallback } from 'react';
import { identifyCurrentVisitor, detectIncognitoMode, detectEmulatorEvidence } from './lib/collector';
import type { EmulatorEvidence } from './lib/collector';
import type {
  BotSubtype,
  IntelVisitorResponse,
  NetworkType,
  RiskLevel,
  SecuritySignals,
  SmartSignal,
  SmartSignals,
} from './types/visitor';
import { LocationMap } from './components/LocationMap';
import { NetworkStabilityPanel } from './components/NetworkStabilityPanel';
import { CpuActivityPanel } from './components/CpuActivityPanel';
import { SmartSignalsGrid } from './components/SmartSignalsGrid';
import {
  CursorAttributionOverlay,
  resolveCursorIdentity,
} from './components/CursorAttributionOverlay';
import {
  Copy,
  Check,
  RefreshCw,
  AlertCircle,
  Globe,
  MapPin,
  Wifi,
  Monitor,
  Layers,
  History,
  ShieldCheck,
  ShieldAlert,
  Fingerprint,
  Cpu,
  Activity,
  Compass,
  Maximize2,
  Languages,
  KeyRound,
  CalendarClock,
  CircuitBoard,
  HardDrive,
  Palette,
  Bot,
} from 'lucide-react';

/**
 * Formats a stored UTC ISO-8601 timestamp into the visitor's local timezone.
 */
function formatLocalTimestamp(utcIso: string | null | undefined): string {
  if (!utcIso) return 'Unavailable';
  try {
    const date = new Date(utcIso);
    if (Number.isNaN(date.getTime())) return 'Unavailable';
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    }).format(date);
  } catch {
    return utcIso;
  }
}

/**
 * Formats a concise human-friendly timestamp (e.g. "Today, 9:19 PM" or "Nov 08, 9:19 PM").
 */
function formatConciseSeenTimestamp(utcIso: string | null | undefined): string {
  if (!utcIso) return 'Unavailable';
  try {
    const date = new Date(utcIso);
    if (Number.isNaN(date.getTime())) return 'Unavailable';
    const now = new Date();
    const isSameDay =
      date.getFullYear() === now.getFullYear() &&
      date.getMonth() === now.getMonth() &&
      date.getDate() === now.getDate();

    const timeStr = new Intl.DateTimeFormat(undefined, {
      hour: 'numeric',
      minute: '2-digit',
    }).format(date);

    if (isSameDay) {
      return `Today, ${timeStr}`;
    }

    const dateStr = new Intl.DateTimeFormat(undefined, {
      month: 'short',
      day: 'numeric',
    }).format(date);
    return `${dateStr}, ${timeStr}`;
  } catch {
    return 'Unavailable';
  }
}

/**
 * Formats relative time accurately from a real UTC timestamp.
 */
function formatRelativeVisitTime(utcIso: string | null | undefined): string {
  if (!utcIso) return 'Unavailable';
  try {
    const date = new Date(utcIso);
    if (Number.isNaN(date.getTime())) return 'Unavailable';
    const diffSec = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    if (diffSec < 10) return 'Just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    const diffDays = Math.floor(diffHr / 24);
    return `${diffDays}d ago`;
  } catch {
    return 'Unavailable';
  }
}

function formatLocationDisplay(city: string, region: string, country: string): string {
  const parts = [city, region, country].filter(
    (part) => part && part !== 'Unknown' && part !== 'Unavailable'
  );
  if (parts.length === 0) return 'Unavailable';
  const uniqueParts = parts.filter((item, idx) => idx === 0 || item !== parts[idx - 1]);
  return uniqueParts.join(', ');
}

function formatShortLocation(city: string, country: string): string {
  const validCity = city && city !== 'Unknown' && city !== 'Unavailable' ? city : null;
  const validCountry =
    country && country !== 'Unknown' && country !== 'Unavailable' ? country : null;
  if (validCity && validCountry) {
    return validCity === validCountry ? validCity : `${validCity}, ${validCountry}`;
  }
  return validCity || validCountry || 'Unavailable';
}

function formatValidNetworkField(value: string | null | undefined): string {
  if (!value || value === 'Unavailable' || value === 'Unknown') return 'Unknown';
  return value;
}

/**
 * Condenses verbose ISP legal suffixes like "Jio (Reliance Jio Infocomm Limited)"
 * into a crisp display label ("Jio (AS55836)") while preserving full details for tooltips.
 */
function formatCleanIspDisplay(
  isp: string,
  org: string,
  asn: string
): { shortLabel: string; fullTooltip: string } {
  const cleanIsp = isp && isp !== 'Unknown' && isp !== 'Unavailable' ? isp.trim() : 'Unknown ISP';
  const cleanAsn = asn && asn !== 'Unknown' && asn !== 'Unavailable' ? asn.trim() : '';
  const cleanOrg = org && org !== 'Unknown' && org !== 'Unavailable' ? org.trim() : '';

  // Remove parenthetical corporate expansions from the short display label
  let conciseIsp = cleanIsp.replace(/\s*\([^)]*\)/g, '').trim();
  if (!conciseIsp) conciseIsp = cleanIsp;

  // Strip trailing corporate suffixes for scannability
  conciseIsp = conciseIsp
    .replace(/\b(Private|Pvt\.?|Limited|Ltd\.?|Incorporated|Inc\.?|Corporation|Corp\.?|LLC|GmbH|PLC)\b\.?/gi, '')
    .replace(/\s{2,}/g, ' ')
    .replace(/[,-]\s*$/, '')
    .trim();

  const shortLabel = cleanAsn ? `${conciseIsp} (${cleanAsn})` : conciseIsp;
  const fullParts = [cleanIsp, cleanOrg !== cleanIsp ? cleanOrg : '', cleanAsn].filter(Boolean);
  return {
    shortLabel,
    fullTooltip: fullParts.join(' • ') || shortLabel,
  };
}

/**
 * Parses raw WebGL ANGLE (...) renderer strings into clean, human-readable GPU names
 * (e.g., "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)"
 * -> "Intel Iris Xe Graphics").
 */
function formatCleanGpuName(rawRenderer: string | undefined, rawVendor?: string): string {
  if (!rawRenderer || rawRenderer === 'Unavailable') {
    return rawVendor && rawVendor !== 'Unavailable' ? rawVendor : 'Standard GPU';
  }

  let s = rawRenderer.trim();

  // Extract inner content from ANGLE (...) wrapper
  const angleMatch = s.match(/^ANGLE\s*\((.+)\)$/i);
  if (angleMatch) {
    const inner = angleMatch[1];
    const parts = inner
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);
    if (parts.length >= 2) {
      s = parts[1];
    } else if (parts.length === 1) {
      s = parts[0];
    }
  }

  // Strip Metal / Direct3D / Vulkan / OpenGL prefixes & shader model suffixes
  s = s
    .replace(/^ANGLE\s+Metal\s+Renderer:\s*/i, '')
    .replace(/^Mesa\s+DRI\s+/i, '')
    .replace(/\(R\)|\(TM\)|®|™/gi, '')
    .replace(/\(\s*0x[0-9a-fA-F]+\s*\)/g, '')
    .replace(/\bDirect3D\d*\b.*$/i, '')
    .replace(/\bD3D\d+\b.*$/i, '')
    .replace(/\bvs_\d+_\d+\b.*$/i, '')
    .replace(/\bps_\d+_\d+\b.*$/i, '')
    .replace(/\bOpenGL\s+Engine\b/gi, '')
    .replace(/\bUnspecified\s+Version\b/gi, '')
    .replace(/\s*\/.*$/, '')
    .replace(/\s{2,}/g, ' ')
    .replace(/[,-]\s*$/, '')
    .trim();

  return s || rawRenderer;
}

/**
 * Maps legacy 0..100 suspect scores to the current 0..10 scale.
 */
function normalizeLegacyScore(score: number | null | undefined): number {
  const s = typeof score === 'number' && Number.isFinite(score) ? score : 0;
  return s > 10 ? Math.round(s / 10) : s;
}

/**
 * Derives the risk tier from a normalized 0..10 score.
 */
function resolveRiskTier(score: number): RiskLevel {
  if (score >= 7) return 'High';
  if (score >= 3) return 'Medium';
  return 'Low';
}

/**
 * Subtle Swiss-technical badge classes per retail network type.
 */
const NETWORK_TYPE_BADGE_CLASS: Record<NetworkType, string> = {
  'Residential Broadband': 'bg-emerald-50 text-emerald-700 border border-emerald-100',
  'Cellular / 5G': 'bg-blue-50 text-blue-700 border border-blue-100',
  'Mobile Carrier': 'bg-blue-50 text-blue-700 border border-blue-100',
  Satellite: 'bg-violet-50 text-violet-700 border border-violet-100',
  'Cloud / Datacenter': 'bg-slate-100 text-slate-600 border border-slate-200',
  'AI Agent Cloud Network': 'bg-indigo-50 text-indigo-700 border border-indigo-100',
  'VPN / Proxy Relay': 'bg-amber-50 text-amber-700 border border-amber-100',
  'Tor Exit / Anonymity Network': 'bg-rose-50 text-rose-700 border border-rose-100',
  'Unknown Network': 'bg-slate-100 text-slate-600 border border-slate-200',
};

type SignalTone = 'ok' | 'warn' | 'bad';

const TONE_DOT_CLASS: Record<SignalTone, string> = {
  ok: 'bg-emerald-500',
  warn: 'bg-amber-500',
  bad: 'bg-rose-500',
};

const TONE_TEXT_CLASS: Record<SignalTone, string> = {
  ok: 'text-emerald-700',
  warn: 'text-amber-700',
  bad: 'text-rose-700',
};

/**
 * Maps a 0..10 per-signal severity onto the shared risk tier scale.
 */
function resolveSignalRiskTier(severity: number): RiskLevel {
  if (severity >= 7) return 'High';
  if (severity >= 3) return 'Medium';
  return 'Low';
}

interface SignalRowModel {
  key: string;
  dotClass: string;
  title: string;
  caption: string;
  statusLabel: string;
  tooltip: string;
  riskScore: number;
  /** Server-provided `${Tier} Risk • ${score}/10` line, preferred when present. */
  riskLabel?: string;
}

function toneForScore(score: number): SignalTone {
  const tier = resolveSignalRiskTier(score);
  return tier === 'High' ? 'bad' : tier === 'Medium' ? 'warn' : 'ok';
}

function createSignalRow(
  params: Omit<SignalRowModel, 'dotClass'> & {
    tone: SignalTone;
  }
): SignalRowModel {
  const { tone, ...rest } = params;
  return {
    ...rest,
    dotClass: TONE_DOT_CLASS[tone],
  };
}

/**
 * Converts one server-computed Smart Signal into the shared tile model, preserving the
 * server's exact status wording and out-of-10 rating line.
 */
function smartSignalToRow(signal: SmartSignal): SignalRowModel {
  return {
    key: signal.id,
    dotClass: TONE_DOT_CLASS[toneForScore(signal.scoreOutOf10)],
    title: signal.title,
    caption: signal.detail,
    statusLabel: signal.status,
    tooltip: `${signal.title} • ${signal.detail}`,
    riskScore: signal.scoreOutOf10,
    riskLabel: signal.riskLabel,
  };
}

/**
 * Single Swiss technical tile for the Smart Signals core grid.
 */
function SignalRow(row: SignalRowModel & { className?: string }) {
  const riskTier = resolveSignalRiskTier(row.riskScore);
  const riskTone: SignalTone =
    riskTier === 'High' ? 'bad' : riskTier === 'Medium' ? 'warn' : 'ok';

  return (
    <div
      className={`p-3.5 sm:p-4 min-h-[96px] flex flex-col justify-between gap-2 min-w-0 ${row.className ?? ''}`}
      title={row.tooltip}
    >
      <span className="text-xs font-semibold text-[#111827] truncate">
        {row.title}
      </span>

      <span className="flex items-center gap-1.5 min-w-0">
        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${row.dotClass}`} />
        <span className="text-[11px] font-mono font-semibold text-[#111827] truncate">
          {row.statusLabel}
        </span>
      </span>

      <span className="text-[11px] text-slate-500 line-clamp-2">
        {row.caption}
      </span>

      <span
        className={`text-[11px] font-mono font-semibold tabular-nums ${TONE_TEXT_CLASS[riskTone]}`}
      >
        {row.riskLabel ?? `${riskTier} Risk • ${row.riskScore}/10`}
      </span>
    </div>
  );
}

/**
 * Client-side fallback mirror of the server's 4-signal engine. Only used when the API
 * response predates `smartSignals`; scores, statuses and labels match server.ts exactly.
 * `clientEmulator` carries the GAP-1 emulator derivation so Tile 4 reaches the same
 * verdict the server would reach from the same device values.
 */
function buildClientSignalRows(
  signals: SecuritySignals,
  incognitoConfirmed = false,
  clientEmulator?: EmulatorEvidence | null
): SignalRowModel[] {
  const isBotDetected = Boolean(signals.isBot || signals.webdriver || signals.cdpDetected);
  const isHeadlessDetected = Boolean(signals.isHeadless);
  const isDatacenterAsn = Boolean(signals.datacenterAsn);
  const hasTzMismatch = Boolean(signals.timezoneMismatch);
  const isVm = Boolean(signals.isVirtualMachine);
  const isTampered = Boolean(signals.isOsTampered);
  const isEmulator = Boolean(signals.emulatorDetected) || Boolean(clientEmulator?.detected);
  const isRequestTampered = Boolean(signals.tamperedRequest || signals.replayDetected);
  const isTorExit = Boolean(signals.torExitNode);
  const isBlocklisted = Boolean(signals.ipBlocklisted);
  const botSubtype: BotSubtype = signals.botSubtype ?? 'human';
  const isSpoofedCrawler =
    botSubtype === 'bad_bot' && /spoof/i.test(`${signals.botCategory || ''} ${signals.botReason || ''}`);
  const isIncognito =
    incognitoConfirmed ||
    Boolean(
      signals.isIncognito ??
        (signals.incognitoLikely || signals.persistenceMode === 'Hardware ID Recovered')
    );
  const ispBrand = signals.brandName?.trim() || '';

  const incognitoScore = isIncognito ? 4 : 0;
  const botScore =
    botSubtype === 'good_bot'
      ? 2
      : botSubtype === 'ai_agent'
      ? 8
      : botSubtype === 'bad_bot'
      ? isSpoofedCrawler
        ? 10
        : 9
      : isBotDetected
      ? 9
      : isHeadlessDetected
      ? 7
      : 0;
  const vpnScore = isTorExit
    ? 10
    : isBlocklisted
    ? 9
    : isDatacenterAsn && hasTzMismatch
    ? 8
    : isDatacenterAsn
    ? 6
    : hasTzMismatch
    ? 5
    : 0;
  const vmScore = isRequestTampered
    ? 10
    : isEmulator
    ? 8
    : isVm
    ? 7
    : isTampered
    ? 6
    : 0;

  const incognitoDetail = isIncognito
    ? `Ephemeral RAM storage detected (${
        signals.incognitoMethod || 'In-memory LevelDB / Cookie-less known hwid'
      })`
    : `Persistent disk-backed storage verified (${
        signals.incognitoMethod || 'Standard profile'
      })`;
  const botDetail =
    signals.botReason ||
    (botSubtype === 'good_bot'
      ? 'Verified crawler operating from its official provider network'
      : botSubtype === 'ai_agent'
      ? `${signals.botProvider || 'AI agent'} autonomous crawler signature`
      : botSubtype === 'bad_bot'
      ? 'Browser automation / spoofed crawler identity detected'
      : isBotDetected
      ? 'WebDriver / CDP automation runtime detected'
      : isHeadlessDetected
      ? 'Headless rendering context without an attached physical display'
      : 'No automation, WebDriver, CDP hooks, or headless runtime detected');
  const vpnDetail = isTorExit
    ? 'Confirmed active Tor exit relay (Tor Project DNSEL + bulk exit list)'
    : isBlocklisted
    ? (signals.ipBlocklistReasons?.[0] || 'IP flagged on the abuse / tamper blocklist')
    : vpnScore > 0
    ? signals.vpnReasons[0] ||
      (isDatacenterAsn
        ? `Datacenter / hosting ASN detected on ${ispBrand || 'this network'}`
        : `Browser timezone (${signals.browserTimezone}) differs from IP geolocation timezone (${signals.ipTimezone})`)
    : `${ispBrand || 'Standard ISP'} • ${
        signals.networkType ?? 'Residential Broadband'
      } verified against browser timezone ${signals.browserTimezone}`;
  const vmDetail = isRequestTampered
    ? signals.requestIntegrityReason ||
      (signals.replayDetected
        ? 'Duplicate payload nonce (replay attack detected)'
        : 'Payload integrity hash mismatch')
    : isEmulator
    ? signals.emulatorReason ||
      clientEmulator?.reason ||
      'Mobile UA backed by a desktop architecture or emulator GPU'
    : signals.vmReason ||
      (isTampered
        ? signals.tamperReasons[0] || 'Operating-system / User-Agent tampering detected'
        : 'Unmasked physical GPU & consistent OS platform verified');

  return [
    createSignalRow({
      key: 'incognito',
      tone: toneForScore(incognitoScore),
      title: 'Incognito / Private Browsing',
      caption: incognitoDetail,
      statusLabel: isIncognito ? 'Incognito / Private Mode' : 'Standard Window',
      tooltip: `Persistence Mode: ${signals.persistenceMode}`,
      riskScore: incognitoScore,
    }),
    createSignalRow({
      key: 'bot',
      tone: toneForScore(botScore),
      title: 'Bot & Automation Detection',
      caption: botDetail,
      statusLabel:
        botSubtype === 'good_bot'
          ? 'Good Bot · Search Crawler'
          : botSubtype === 'ai_agent'
          ? 'AI Agent · Cloud Browser'
          : botSubtype === 'bad_bot'
          ? isSpoofedCrawler
            ? 'Spoofed Crawler'
            : 'Bot / Automated'
          : isBotDetected
          ? 'Bot / Automated'
          : isHeadlessDetected
          ? 'Cloud / Headless'
          : 'Verified Human',
      tooltip: signals.botSignals.length > 0 ? signals.botSignals.join(' • ') : botDetail,
      riskScore: botScore,
    }),
    createSignalRow({
      key: 'vpn',
      tone: toneForScore(vpnScore),
      title: 'VPN / Proxy & Network Type',
      caption: vpnDetail,
      statusLabel: isTorExit
        ? 'Tor Exit Node'
        : isBlocklisted
        ? 'Blocklisted IP'
        : isDatacenterAsn
        ? 'VPN / Datacenter Proxy'
        : hasTzMismatch
        ? 'VPN / Timezone Relay'
        : ispBrand
        ? `Standard ISP (${ispBrand})`
        : 'Standard ISP',
      tooltip: signals.vpnReasons.length > 0 ? signals.vpnReasons.join(' • ') : vpnDetail,
      riskScore: vpnScore,
    }),
    createSignalRow({
      key: 'vm',
      tone: toneForScore(vmScore),
      title: 'Virtual Machine & OS Integrity',
      caption: vmDetail,
      statusLabel: isRequestTampered
        ? 'Tampered / Replayed'
        : isEmulator
        ? 'Mobile Emulator'
        : isVm
        ? 'Virtual Machine / VM'
        : isTampered
        ? 'Spoofed Environment'
        : 'Physical Hardware',
      tooltip: vmDetail,
      riskScore: vmScore,
    }),
  ];
}

/**
 * Builds the 4-signal core grid. The server-computed smart signals win whenever present;
 * otherwise the identical client-side derivation is used as an accurate fallback.
 *
 * A confirmed incognito verdict (from either side of the payload) may never be downgraded
 * by a stale server tile: when the server still reports a 0/10 incognito tile the row is
 * MERGED — server wording/detail kept, status + score + label forced to the private verdict.
 */
function buildSignalRows(
  signals: SecuritySignals,
  serverSignals?: SmartSignals | null,
  incognitoConfirmed = false,
  clientEmulator?: EmulatorEvidence | null
): SignalRowModel[] {
  if (serverSignals) {
    const rows = [
      serverSignals.incognito,
      serverSignals.bot,
      serverSignals.vpn,
      serverSignals.vm,
    ].map(smartSignalToRow);
    if (incognitoConfirmed && rows[0].riskScore <= 0) {
      rows[0] = {
        ...rows[0],
        statusLabel: 'Incognito / Private Mode',
        riskScore: 4,
        riskLabel: 'Medium Risk • 4/10',
        dotClass: TONE_DOT_CLASS[toneForScore(4)],
      };
    }
    return rows;
  }
  return buildClientSignalRows(signals, incognitoConfirmed, clientEmulator);
}

export default function App() {
  const [data, setData] = useState<IntelVisitorResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<boolean>(false);
  const [copiedHwId, setCopiedHwId] = useState<boolean>(false);
  const [selectedVisitIndex, setSelectedVisitIndex] = useState<number>(0);
  const [visibleVisitsCount, setVisibleVisitsCount] = useState<number>(5);
  const [copiedJson, setCopiedJson] = useState<boolean>(false);

  // Swiss light mode is the only theme: strip any legacy class left by a previous session.
  useEffect(() => {
    document.documentElement.classList.remove('dark');
    document.body?.classList.remove('dark');
    try {
      window.localStorage.removeItem('intel_theme');
    } catch {
      // localStorage unavailable
    }
  }, []);

  const loadVisitorData = useCallback(async (manualRefresh = false) => {
    try {
      if (manualRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }
      setError(null);

      const response = await identifyCurrentVisitor({ manualRefresh });
      setData(response);
      setSelectedVisitIndex(0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load visitor intelligence data.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    // Start the module-cached storage-physics probe before any network panel mounts,
    // so its main-thread timing is not skewed. Never blocks rendering.
    void detectIncognitoMode();
    loadVisitorData(false);
  }, [loadVisitorData]);

  const handleCopyText = async (
    value: string | undefined,
    setter: (v: boolean) => void
  ) => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setter(true);
      setTimeout(() => setter(false), 1500);
    } catch {
      // Ignore clipboard error
    }
  };

  // Compute real counts of distinct IPs and distinct verified locations from actual database visit history
  const uniqueIpCount = data
    ? new Set(
        data.visitHistory
          .map((v) => v.publicIp)
          .filter((ip) => ip && ip !== 'Unavailable')
      ).size || (data.location.publicIp !== 'Unavailable' ? 1 : 0)
    : 0;

  const uniqueLocationCount = data
    ? new Set(
        data.visitHistory
          .map((v) => `${v.city}|${v.region}|${v.country}`)
          .filter((loc) => !loc.startsWith('Unavailable|') && !loc.startsWith('Unknown|'))
      ).size || (data.location.isLocationVerified ? 1 : 0)
    : 0;

  const visits = data?.visitHistory || [];
  const activeVisit = visits[selectedVisitIndex] || visits[0];

  const activeIsp = formatValidNetworkField(
    activeVisit?.isp && activeVisit.isp !== 'Unknown'
      ? activeVisit.isp
      : data?.location.isp
  );
  const activeOrg = formatValidNetworkField(
    activeVisit?.org && activeVisit.org !== 'Unknown'
      ? activeVisit.org
      : data?.location.org
  );
  const activeAsn = formatValidNetworkField(
    activeVisit?.asn && activeVisit.asn !== 'Unknown'
      ? activeVisit.asn
      : data?.location.asn
  );
  const ispDisplay = formatCleanIspDisplay(activeIsp, activeOrg, activeAsn);

  // Retail ISP brand (server-classified) + network type badge for the ISP/ASN tile
  const ispBrandLabel = data?.securitySignals?.brandName || ispDisplay.shortLabel;
  const networkType = data?.securitySignals?.networkType;
  const networkTypeBadgeClass = networkType ? NETWORK_TYPE_BADGE_CLASS[networkType] : '';

  const activeLatitude =
    activeVisit && typeof activeVisit.latitude === 'number'
      ? activeVisit.latitude
      : data?.location.latitude ?? null;
  const activeLongitude =
    activeVisit && typeof activeVisit.longitude === 'number'
      ? activeVisit.longitude
      : data?.location.longitude ?? null;

  const cleanGpuName = data?.hardwareSignals
    ? formatCleanGpuName(data.hardwareSignals.gpuRenderer, data.hardwareSignals.gpuVendor)
    : 'Standard GPU';
  const rawGpuTooltip = data?.hardwareSignals
    ? `${data.hardwareSignals.gpuVendor} • ${data.hardwareSignals.gpuRenderer}`
    : '';

  // 4-signal core grid model (null-safe: renders only inside the data block). The server's
  // computed grid is preferred; the client mirror covers older responses.
  const activeSignals = data?.securitySignals ?? null;
  const serverSmartSignals = data?.smartSignals ?? data?.securitySignals?.smartSignals ?? null;
  // GAP 1 — emulator evidence derived on the client from the same values the server sees,
  // so the Tile 4 fallback can never disagree with the server's own verdict.
  const clientEmulatorEvidence: EmulatorEvidence | null = data
    ? detectEmulatorEvidence({
        platform: data.browserDevice.platform,
        maxTouchPoints: data.hardwareSignals.maxTouchPoints,
        gpuVendor: data.hardwareSignals.gpuVendor,
        gpuRenderer: data.hardwareSignals.gpuRenderer,
        screenResolution: data.browserDevice.screenResolution,
      })
    : null;
  // A private verdict from either side wins — the incognito tile must never fall back to
  // "Standard Window" when the client device object, the client signals, or either server
  // smart-signal copy reports an incognito score.
  const incognitoConfirmed = Boolean(
    data &&
      (data.browserDevice?.incognito ||
        data.browserDevice?.isIncognito ||
        data.browserDevice?.privateMode ||
        data.securitySignals?.isIncognito ||
        data.securitySignals?.incognito ||
        data.securitySignals?.privateMode ||
        data.securitySignals?.incognitoLikely ||
        (data.smartSignals?.incognito?.scoreOutOf10 ?? 0) > 0 ||
        (data.securitySignals?.smartSignals?.incognito?.scoreOutOf10 ?? 0) > 0)
  );
  const signalRows = activeSignals
    ? buildSignalRows(
        activeSignals,
        serverSmartSignals,
        incognitoConfirmed,
        clientEmulatorEvidence
      )
    : [];

  // Normalized 0..10 threat score + derived risk tier (legacy scale converted). The server's
  // top-level mirrors win; older payloads fall back to securitySignals.
  const normalizedSuspectScore = normalizeLegacyScore(
    data?.suspectScore ?? data?.securitySignals?.suspectScore
  );
  const serverRiskBadgeText =
    data?.riskBadgeText ?? data?.securitySignals?.riskBadgeText ?? null;
  // The header may never advertise a lower tier than the worst card: without a server badge,
  // the displayed composite applies the same monotonic card-floor invariant as the server
  // (max card + 1 for two elevated cards, +2 for three or more).
  const worstTileScore = signalRows.reduce((max, row) => Math.max(max, row.riskScore), 0);
  const elevatedTileCount = signalRows.filter((row) => row.riskScore >= 4).length;
  const tileSynergyBonus = elevatedTileCount >= 3 ? 2 : elevatedTileCount === 2 ? 1 : 0;
  const tileFloorScore = Math.min(10, worstTileScore + tileSynergyBonus);
  const displayedRiskScore = serverRiskBadgeText
    ? normalizedSuspectScore
    : Math.max(normalizedSuspectScore, tileFloorScore);
  const riskTier: RiskLevel = serverRiskBadgeText
    ? data?.riskLevel ?? resolveRiskTier(normalizedSuspectScore)
    : resolveRiskTier(displayedRiskScore);
  const riskBadgeText = serverRiskBadgeText ?? `${riskTier} Risk • ${displayedRiskScore}/10`;

  // Calibrated 0-100 composite for the top-centered Risk Meter. Older payloads fall back to
  // the 0-10 card-floor score scaled by ten so the meter always has a value.
  const suspectScore100 = data
    ? Math.max(
        0,
        Math.min(
          100,
          Math.round(
            Number(data.suspectScore100 ?? data.securitySignals?.suspectScore100 ?? displayedRiskScore * 10) || 0
          )
        )
      )
    : 0;

  // Cursor attribution pill: resolved from the first-party bot / agent verdicts.
  const cursorIdentity = resolveCursorIdentity({
    botSubtype: data?.securitySignals.botSubtype ?? null,
    isBot: Boolean(data?.securitySignals.isBot),
    agentId: data?.securitySignals.aiAgent?.agentId ?? null,
    agentName: data?.securitySignals.aiAgent?.agentName ?? null,
    isBrave: Boolean(
      typeof navigator !== 'undefined' &&
        (navigator as unknown as { brave?: { isBrave?: () => boolean } }).brave?.isBrave
    ),
  });

  // API v4 event payload rendered by the bottom inspector. Built exclusively from live
  // first-party values: no invented signals, no third-party fraud labels.
  const eventJson = useMemo(() => {
    if (!data) return null;
    const s = data.securitySignals;
    const firstVisitMs = Date.parse(data.visitHistory[0]?.visitedAtUtc || '') || Date.now();
    const deviceType = data.browserDevice.deviceType;
    const osName = data.browserDevice.os;
    const rawAttributes =
      data.rawDeviceAttributes ?? (s as { rawDeviceAttributes?: unknown }).rawDeviceAttributes ?? null;
    return {
      event_id: `${firstVisitMs}.${data.visitorId.slice(-6)}`,
      timestamp: firstVisitMs,
      source: 'device',
      linked_id: data.statistics.currentSessionId,
      environment_id: 'intel_adityahq_first_party',
      sdk: {
        platform: 'js',
        version: '2.1.0',
        integrations: [
          { name: 'intel-system-express-vercel', version: '2.1.0' },
          { name: 'intel-system-react', version: '19.0.0' },
        ],
      },
      replayed: Boolean(s.replayDetected),
      identification: {
        visitor_id: data.visitorId,
        hardware_id: data.hardwareId,
        confidence: { score: 1, version: 'v2.1' },
        visitor_found: data.isReturning,
        recognition_mode: data.recognitionSource,
        first_seen_at: Date.parse(data.statistics.firstVisitUtc) || null,
        last_seen_at: Date.parse(data.statistics.lastVisitUtc) || null,
      },
      url: typeof window !== 'undefined' ? window.location.href : '',
      ip_address: data.location.publicIp,
      user_agent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
      device: deviceType,
      os: osName,
      os_version: data.browserDevice.platform,
      browser_details: {
        browser_name: data.browserDevice.browser,
        browser_major_version: String(data.browserDevice.browser || '').replace(/\D.*$/, ''),
        browser_full_version: data.browserDevice.browser,
        os: osName,
        os_version: data.browserDevice.platform,
        device: deviceType,
      },
      active_call: Boolean(data.activeCall ?? s.activeCall),
      bot: s.botSubtype === 'bad_bot' || s.botSubtype === 'ai_agent' ? 'bad' : 'not_detected',
      developer_tools: Boolean(s.developerTools),
      ip_blocklist: {
        email_spam: false,
        attack_source: Boolean(s.ipBlocklisted),
        tor_node: Boolean(s.torExitNode),
      },
      ip_info: {
        v4: {
          address: data.location.publicIp,
          geolocation: {
            accuracy_radius: data.location.isLocationVerified ? 100 : null,
            latitude: data.location.latitude,
            longitude: data.location.longitude,
            timezone: data.browserDevice.timezone,
            city_name: data.location.city,
            country_code: data.location.countryCode,
            country_name: data.location.country,
            subdivisions: data.location.region ? [{ name: data.location.region }] : [],
          },
          asn: data.location.asn,
          asn_name: data.location.org,
          asn_type: s.isDatacenterOrHosting ? 'hosting' : 'isp',
          datacenter_result: Boolean(s.isDatacenterOrHosting),
        },
      },
      proxy: Boolean((s as unknown as { proxyDetected?: boolean }).proxyDetected),
      proxy_confidence: 'high',
      incognito: Boolean(s.isIncognito ?? s.incognito ?? s.privateMode),
      privacy_settings: Boolean(
        (s as { privacySettings?: boolean }).privacySettings || s.isTorBrowserClient
      ),
      simulator: Boolean(s.emulatorDetected),
      suspect_score: suspectScore100,
      tampering: Boolean(data.tampering ?? s.tampering),
      tampering_confidence: data.tamperingConfidence ?? 'high',
      tampering_ml_score: s.tamperingMlScore ?? 0.0024,
      tampering_details: data.tamperingDetails ?? {
        anomaly_score: 0,
        anti_detect_browser: false,
        devtools_device_emulation: false,
        reasons: [],
      },
      velocity: data.velocity ?? null,
      virtual_machine: Boolean(s.isVirtualMachine || s.emulatorDetected),
      vpn: Boolean(s.vpnSuspected),
      vpn_confidence: s.vpnSuspected ? 'high' : 'low',
      vpn_methods: {
        timezone_mismatch: Boolean(s.timezoneMismatch),
        public_vpn: Boolean(s.datacenterAsn),
        auxiliary_mobile: false,
        os_mismatch: Boolean(s.isOsTampered),
        relay: Boolean(s.torExitNode),
        ml_prediction: Boolean(s.vpnSuspected),
      },
      high_activity_device: Boolean(data.highActivityDevice ?? s.highActivityDevice),
      rare_device: Boolean(data.rareDevice ?? s.rareDevice),
      rare_device_percentile_bucket:
        data.rareDevicePercentileBucket ?? s.rareDevicePercentileBucket ?? '<p95',
      raw_device_attributes: rawAttributes,
    };
  }, [data, suspectScore100]);

  // Tor / AI attribution surface — rendered above the Smart Signals grid whenever any
  // first-party anonymity or agent identity was resolved for this visit.
  const activeAiAgent = data?.securitySignals?.aiAgent ?? null;
  const torExitDetected = Boolean(data?.securitySignals?.torExitNode);
  const torBrowserClient = Boolean(data?.securitySignals?.isTorBrowserClient);
  const torOperatorLabel = data?.securitySignals?.torOperator || '';
  const showAttributionBanner = Boolean(
    data && (torExitDetected || torBrowserClient || activeAiAgent?.detected)
  );

  return (
    <div className="bg-[#F4F5F7] text-[#111827] min-h-screen flex flex-col">
      {/* Responsive Top Navigation Bar */}
      <header className="bg-white border-b border-[#E5E7EB] px-4 sm:px-6 py-3.5">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4 sm:gap-8">
          <a
            href="#overview"
            className="text-base font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 font-display"
          >
            Intel System
          </a>

          <nav className="hidden md:flex items-center gap-6 text-xs font-medium text-slate-600">
            <a href="#overview" className="hover:text-slate-900 whitespace-nowrap shrink-0">
              Visitor Dashboard
            </a>
            <a href="#signals" className="hover:text-slate-900 whitespace-nowrap shrink-0">
              Smart Signals
            </a>
            <a href="#diagnostics" className="hover:text-slate-900 whitespace-nowrap shrink-0">
              Network &amp; CPU
            </a>
            <a href="#history" className="hover:text-slate-900 whitespace-nowrap shrink-0">
              Visit History
            </a>
          </nav>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => loadVisitorData(true)}
              disabled={loading || refreshing}
              className="inline-flex items-center gap-1.5 px-3 sm:px-3.5 py-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded-md disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              <span>{refreshing ? 'Refreshing...' : 'Record Visit'}</span>
            </button>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-3 sm:px-6 py-4 sm:py-7 space-y-6">
        {/* Top-centered Risk Meter: calibrated 0-100 Suspect Score */}
        <section className="w-full max-w-2xl mx-auto flex flex-col items-center justify-center text-center pt-4 pb-2 px-4">
          <span className="text-[10px] font-mono uppercase tracking-[0.18em] text-slate-500">
            Device Intelligence
          </span>
          <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold ${
                suspectScore100 === 0
                  ? 'bg-[#E6F4EA] border-[#81C995] text-[#137333]'
                  : riskTier === 'High'
                  ? 'bg-[#FCE8E6] border-[#D93025]/40 text-[#D93025]'
                  : riskTier === 'Medium'
                  ? 'bg-[#FEF7E0] border-[#F9AB00]/50 text-[#B06000]'
                  : 'bg-[#E6F4EA] border-[#81C995] text-[#137333]'
              }`}
            >
              {riskTier === 'High' ? (
                <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
              ) : (
                <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
              )}
              {suspectScore100 === 0 ? 'Not detected' : `Suspect Score \u2022 ${suspectScore100}`}
            </span>
            {suspectScore100 > 0 && (
              <span className="text-[11px] font-mono text-slate-500">{riskTier} Risk</span>
            )}
          </div>
          <div className="w-full max-w-md h-2.5 bg-slate-200 rounded-full overflow-hidden mt-3">
            <div
              className={`h-full transition-all duration-300 ${
                riskTier === 'High'
                  ? 'bg-[#D93025]'
                  : riskTier === 'Medium'
                  ? 'bg-[#F9AB00]'
                  : 'bg-[#81C995]'
              }`}
              style={{ width: `${Math.max(2, suspectScore100)}%` }}
            />
          </div>
          <div className="mt-3 flex items-center justify-center gap-3">
            <button
              type="button"
              onClick={() => loadVisitorData(true)}
              disabled={loading || refreshing}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-md disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              <span>{refreshing ? 'Analyzing...' : 'Analyze my browser'}</span>
            </button>
            <a
              href="#raw-json"
              className="text-xs font-medium text-slate-600 hover:text-slate-900 underline underline-offset-2"
            >
              View Event JSON
            </a>
          </div>
        </section>
        {error && (
          <div className="bg-white border border-red-300 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 text-xs text-red-700">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
            <button
              type="button"
              onClick={() => loadVisitorData(true)}
              className="px-3 py-1.5 text-xs font-medium text-slate-800 border border-slate-300 rounded-md hover:bg-slate-50 self-start sm:self-auto whitespace-nowrap shrink-0 cursor-pointer"
            >
              Retry
            </button>
          </div>
        )}

        {loading && !data && (
          <div className="bg-white border border-[#E5E7EB] rounded-2xl p-6 sm:p-8 space-y-6">
            <div className="h-7 w-64 max-w-full bg-slate-100 rounded" />
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-4 border-t border-slate-100">
              <div className="h-16 bg-slate-100 rounded-xl" />
              <div className="h-16 bg-slate-100 rounded-xl" />
              <div className="h-16 bg-slate-100 rounded-xl" />
              <div className="h-16 bg-slate-100 rounded-xl" />
            </div>
            <div className="h-64 bg-slate-100 rounded-xl" />
          </div>
        )}

        {data && (
          <section
            id="overview"
            className="bg-white rounded-2xl border border-[#E5E7EB] shadow-2xs overflow-hidden"
          >
            {/* 1. Simplified Hero Identity Header */}
            <div className="px-4 sm:px-7 py-5 border-b border-[#E5E7EB] flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <h1 className="text-lg sm:text-xl font-bold tracking-tight text-[#111827]">
                    Hello, visitor
                  </h1>
                  <span className="text-xs font-medium text-slate-500">
                    • {data.isReturning ? 'Returning Device' : 'First Observed Visit'}
                  </span>
                </div>
                <p className="text-xs sm:text-[13px] text-slate-500 mt-1">
                  Real-time browser identity, hardware fingerprint, and live connection telemetry.
                </p>
              </div>

              {/* Side-by-Side Interactive Identity Boxes (Visitor ID + Hardware ID) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 w-full lg:w-auto lg:min-w-[520px]">
                {/* Visitor ID Box */}
                <div className="flex items-center justify-between gap-2.5 px-3 py-2 rounded-xl bg-slate-50 border border-[#E5E7EB] min-w-0">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className="w-8 h-8 rounded-lg bg-orange-50/60 border border-[#E5E7EB] flex items-center justify-center shrink-0">
                      <Fingerprint className="w-4 h-4 text-[#F05A28]" />
                    </div>
                    <div className="min-w-0">
                      <span className="block text-[10px] font-mono uppercase tracking-wider text-slate-500">
                        Visitor ID
                      </span>
                      <code
                        className="block text-xs sm:text-[13px] font-bold font-mono tabular-nums text-[#F05A28] truncate"
                        title={data.visitorId}
                      >
                        {data.visitorId}
                      </code>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleCopyText(data.visitorId, setCopiedId)}
                    className="inline-flex items-center justify-center w-7 h-7 text-slate-500 hover:text-slate-900 bg-white hover:bg-slate-100 border border-[#E5E7EB] rounded-md shrink-0 cursor-pointer"
                    title="Copy Visitor ID"
                    aria-label="Copy Visitor ID"
                  >
                    {copiedId ? (
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>

                {/* Hardware ID Box */}
                <div className="flex items-center justify-between gap-2.5 px-3 py-2 rounded-xl bg-slate-50 border border-[#E5E7EB] min-w-0">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className="w-8 h-8 rounded-lg bg-blue-50/60 border border-blue-200 flex items-center justify-center shrink-0">
                      <Cpu className="w-4 h-4 text-[#2563EB]" />
                    </div>
                    <div className="min-w-0">
                      <span className="block text-[10px] font-mono uppercase tracking-wider text-slate-500">
                        Hardware ID
                      </span>
                      <code
                        className="block text-xs sm:text-[13px] font-bold font-mono tabular-nums text-[#2563EB] truncate"
                        title={data.hardwareId}
                      >
                        {data.hardwareId}
                      </code>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleCopyText(data.hardwareId, setCopiedHwId)}
                    className="inline-flex items-center justify-center w-7 h-7 text-slate-500 hover:text-slate-900 bg-white hover:bg-slate-100 border border-[#E5E7EB] rounded-md shrink-0 cursor-pointer"
                    title="Copy Hardware ID"
                    aria-label="Copy Hardware ID"
                  >
                    {copiedHwId ? (
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* 2. 4 KPI Summary Counters with Colored Icon Badges */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 border-b border-[#E5E7EB] divide-y sm:divide-y-0 sm:divide-x divide-[#E5E7EB]">
              {/* KPI 1: Visits */}
              <div className="px-4 sm:px-6 py-3.5 flex items-center gap-3.5 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-orange-50/60 border border-[#E5E7EB] flex items-center justify-center shrink-0">
                  <Activity className="w-4 h-4 text-[#F05A28]" />
                </div>
                <div className="min-w-0">
                  <span className="block text-[11px] font-medium text-slate-500">
                    Total Visits
                  </span>
                  <span className="block text-sm sm:text-base font-bold font-mono tabular-nums text-[#111827] truncate">
                    {data.statistics.totalVisits}{' '}
                    <span className="font-sans font-medium text-xs text-slate-500">
                      {data.statistics.totalVisits === 1 ? 'visit' : 'visits'}
                    </span>
                  </span>
                </div>
              </div>

              {/* KPI 2: Sessions */}
              <div className="px-4 sm:px-6 py-3.5 flex items-center gap-3.5 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-blue-50/60 border border-blue-200 flex items-center justify-center shrink-0">
                  <Layers className="w-4 h-4 text-[#2563EB]" />
                </div>
                <div className="min-w-0">
                  <span className="block text-[11px] font-medium text-slate-500">
                    Active Sessions
                  </span>
                  <span className="block text-sm sm:text-base font-bold font-mono tabular-nums text-[#111827] truncate">
                    {data.statistics.totalSessions}{' '}
                    <span className="font-sans font-medium text-xs text-slate-500">
                      {data.statistics.totalSessions === 1 ? 'session' : 'sessions'}
                    </span>
                  </span>
                </div>
              </div>

              {/* KPI 3: Distinct IPs */}
              <div className="px-4 sm:px-6 py-3.5 flex items-center gap-3.5 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-emerald-50/60 border border-emerald-200 flex items-center justify-center shrink-0">
                  <Globe className="w-4 h-4 text-emerald-600" />
                </div>
                <div className="min-w-0">
                  <span className="block text-[11px] font-medium text-slate-500">
                    Observed IPs
                  </span>
                  <span className="block text-sm sm:text-base font-bold font-mono tabular-nums text-[#111827] truncate">
                    {uniqueIpCount}{' '}
                    <span className="font-sans font-medium text-xs text-slate-500">
                      {uniqueIpCount === 1 ? 'IP address' : 'IP addresses'}
                    </span>
                  </span>
                </div>
              </div>

              {/* KPI 4: Locations */}
              <div className="px-4 sm:px-6 py-3.5 flex items-center gap-3.5 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-indigo-50/60 border border-indigo-200 flex items-center justify-center shrink-0">
                  <MapPin className="w-4 h-4 text-indigo-600" />
                </div>
                <div className="min-w-0">
                  <span className="block text-[11px] font-medium text-slate-500">
                    Locations
                  </span>
                  <span className="block text-sm sm:text-base font-bold font-mono tabular-nums text-[#111827] truncate">
                    {uniqueLocationCount}{' '}
                    <span className="font-sans font-medium text-xs text-slate-500">
                      {uniqueLocationCount === 1 ? 'city' : 'cities'}
                    </span>
                  </span>
                </div>
              </div>
            </div>

            {/* 3. Main 2-Column Split (50% / 50% Equal Width): Left (Location & Network) | Right (Device & Session Summary) */}
            <div className="grid grid-cols-1 lg:grid-cols-2 items-stretch">
              {/* LEFT COLUMN (50% width on lg+): Location Map + 2x2 Where & Network Grid */}
              <div className="w-full flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-[#E5E7EB] min-w-0">
                <div className="px-4 sm:px-6 py-3 bg-[#FAFAFA] border-b border-[#E5E7EB] flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                    <MapPin className="w-3.5 h-3.5 text-[#F05A28]" />
                    <span>Location &amp; Network</span>
                  </span>
                  <span className="text-[11px] font-mono tabular-nums text-slate-500">
                    Visit #{data.statistics.totalVisits - selectedVisitIndex} of{' '}
                    {data.statistics.totalVisits} •{' '}
                    {formatRelativeVisitTime(activeVisit?.visitedAtUtc)}
                  </span>
                </div>

                {/* Interactive Leaflet Map */}
                {activeVisit && (
                  <div className="flex-1 flex flex-col justify-between">
                    <div className="border-b border-[#E5E7EB] h-[215px] sm:h-[235px]">
                      <LocationMap
                        latitude={activeLatitude}
                        longitude={activeLongitude}
                        city={activeVisit.city}
                        region={activeVisit.region}
                        country={activeVisit.country}
                        publicIp={activeVisit.publicIp}
                        timezone={activeVisit.timezone || data.browserDevice.timezone}
                      />
                    </div>

                    {/* Compact 2x2 Icon Grid for Public IP, Location, ISP/ASN, and Recognition */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 divide-y sm:divide-y-0 sm:divide-x divide-[#E5E7EB]">
                      <div className="divide-y divide-[#E5E7EB]">
                        {/* Tile 1: Public IP */}
                        <div className="p-3.5 sm:px-5 flex items-center gap-3 min-w-0">
                          <div className="w-9 h-9 rounded-lg bg-blue-50/60 border border-blue-200 flex items-center justify-center shrink-0">
                            <Globe className="w-4 h-4 text-[#2563EB]" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <span className="block text-[11px] text-slate-500">Public IP</span>
                            <span
                              className="block text-xs sm:text-sm font-bold font-mono tabular-nums text-[#111827] truncate"
                              title={activeVisit.publicIp}
                            >
                              {activeVisit.publicIp}
                            </span>
                          </div>
                        </div>

                        {/* Tile 3: ISP / ASN */}
                        <div className="p-3.5 sm:px-5 flex items-center gap-3 min-w-0">
                          <div className="w-9 h-9 rounded-lg bg-indigo-50/60 border border-indigo-200 flex items-center justify-center shrink-0">
                            <Wifi className="w-4 h-4 text-indigo-600" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <span className="block text-[11px] text-slate-500">ISP / ASN</span>
                            <span className="flex flex-wrap gap-1.5 items-center min-w-0">
                              <span
                                className="text-xs sm:text-sm font-semibold text-[#111827] truncate"
                                title={
                                  networkType
                                    ? `${ispDisplay.fullTooltip} • ${networkType}`
                                    : ispDisplay.fullTooltip
                                }
                              >
                                {ispBrandLabel}
                              </span>
                              {networkType && (
                                <span
                                  className={`text-[10px] font-mono uppercase tracking-wide rounded px-1.5 py-0.5 ${networkTypeBadgeClass}`}
                                  title={`Network type: ${networkType}`}
                                >
                                  {networkType}
                                </span>
                              )}
                            </span>
                          </div>
                        </div>
                      </div>

                      <div className="divide-y divide-[#E5E7EB]">
                        {/* Tile 2: Location */}
                        <div className="p-3.5 sm:px-5 flex items-center gap-3 min-w-0">
                          <div className="w-9 h-9 rounded-lg bg-orange-50/60 border border-[#E5E7EB] flex items-center justify-center shrink-0">
                            <MapPin className="w-4 h-4 text-[#F05A28]" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <span className="block text-[11px] text-slate-500">Location</span>
                            <span
                              className="block text-xs sm:text-sm font-semibold text-[#111827] truncate"
                              title={formatLocationDisplay(
                                activeVisit.city,
                                activeVisit.region,
                                activeVisit.country
                              )}
                            >
                              {formatLocationDisplay(
                                activeVisit.city,
                                activeVisit.region,
                                activeVisit.country
                              )}
                            </span>
                          </div>
                        </div>

                        {/* Tile 4: Recognition */}
                        <div className="p-3.5 sm:px-5 flex items-center gap-3 min-w-0">
                          <div className="w-9 h-9 rounded-lg bg-emerald-50/60 border border-emerald-200 flex items-center justify-center shrink-0">
                            <ShieldCheck className="w-4 h-4 text-emerald-600" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <span className="block text-[11px] text-slate-500">Recognition</span>
                            <span
                              className="block text-xs sm:text-sm font-semibold text-emerald-700 truncate"
                              title={data.recognitionSource}
                            >
                              {data.recognitionSource ===
                              'Hardware Fingerprint (Cookie-less / Incognito)'
                                ? 'Hardware ID Recovered'
                                : data.recognitionSource}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* RIGHT COLUMN (50% width on lg+): Device & Session Summary (2-Column Visual Tile Grid) */}
              <div className="w-full flex flex-col justify-between bg-white min-w-0">
                <div className="px-4 sm:px-6 py-3 bg-[#FAFAFA] border-b border-[#E5E7EB] flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                    <Monitor className="w-3.5 h-3.5 text-[#2563EB]" />
                    <span>Device &amp; Session Summary</span>
                  </span>
                  <span className="text-[11px] font-mono text-slate-500">
                    {data.browserDevice.deviceType}
                  </span>
                </div>

                <div className="p-4 sm:p-6 flex-1 flex flex-col justify-center">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 sm:gap-4 h-full auto-rows-fr">
                    {/* Tile 1: Browser */}
                    <div className="p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-center gap-3.5 min-w-0">
                      <div className="w-9 h-9 rounded-lg bg-blue-50/60 border border-blue-200 flex items-center justify-center shrink-0">
                        <Compass className="w-4 h-4 text-[#2563EB]" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[11px] text-slate-500">Browser</span>
                        <span
                          className="block text-xs sm:text-sm font-semibold text-[#111827] truncate mt-0.5"
                          title={activeVisit?.browser || data.browserDevice.browser}
                        >
                          {activeVisit?.browser || data.browserDevice.browser}
                        </span>
                      </div>
                    </div>

                    {/* Tile 2: OS & Device */}
                    <div className="p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-center gap-3.5 min-w-0">
                      <div className="w-9 h-9 rounded-lg bg-emerald-50/60 border border-emerald-200 flex items-center justify-center shrink-0">
                        <Monitor className="w-4 h-4 text-emerald-600" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[11px] text-slate-500">OS &amp; Device</span>
                        <span
                          className="block text-xs sm:text-sm font-semibold text-[#111827] truncate mt-0.5"
                          title={`${activeVisit?.os || data.browserDevice.os} • ${
                            activeVisit?.deviceType || data.browserDevice.deviceType
                          }`}
                        >
                          {activeVisit?.os || data.browserDevice.os} •{' '}
                          {activeVisit?.deviceType || data.browserDevice.deviceType}
                        </span>
                      </div>
                    </div>

                    {/* Tile 3: Display */}
                    <div className="p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-center gap-3.5 min-w-0">
                      <div className="w-9 h-9 rounded-lg bg-orange-50/60 border border-[#E5E7EB] flex items-center justify-center shrink-0">
                        <Maximize2 className="w-4 h-4 text-[#F05A28]" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[11px] text-slate-500">Display</span>
                        <span
                          className="block text-xs sm:text-sm font-semibold font-mono tabular-nums text-[#111827] truncate mt-0.5"
                          title={`${data.browserDevice.screenResolution} (${data.browserDevice.pixelRatio}) • ${
                            data.hardwareSignals?.colorDepth ?? 24
                          }-bit`}
                        >
                          {data.browserDevice.screenResolution.replace('x', ' × ')} •{' '}
                          {data.hardwareSignals?.colorDepth ?? 24}-bit
                        </span>
                      </div>
                    </div>

                    {/* Tile 4: Locale & Timezone */}
                    <div className="p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-center gap-3.5 min-w-0">
                      <div className="w-9 h-9 rounded-lg bg-indigo-50/60 border border-indigo-200 flex items-center justify-center shrink-0">
                        <Languages className="w-4 h-4 text-indigo-600" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[11px] text-slate-500">
                          Locale &amp; Timezone
                        </span>
                        <span
                          className="block text-xs sm:text-sm font-semibold text-[#111827] truncate mt-0.5"
                          title={`${data.browserDevice.language} • ${data.browserDevice.timezone}`}
                        >
                          {data.browserDevice.language} • {data.browserDevice.timezone}
                        </span>
                      </div>
                    </div>

                    {/* Tile 5: Active Session */}
                    <div className="p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-center gap-3.5 min-w-0">
                      <div className="w-9 h-9 rounded-lg bg-amber-50/60 border border-amber-200 flex items-center justify-center shrink-0">
                        <KeyRound className="w-4 h-4 text-amber-700" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[11px] text-slate-500">Active Session</span>
                        <code
                          className="block text-xs sm:text-sm font-semibold font-mono tabular-nums text-[#111827] truncate mt-0.5"
                          title={data.statistics.currentSessionId}
                        >
                          {data.statistics.currentSessionId}
                        </code>
                      </div>
                    </div>

                    {/* Tile 6: First / Last Seen */}
                    <div className="p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-center gap-3.5 min-w-0">
                      <div className="w-9 h-9 rounded-lg bg-emerald-50/60 border border-emerald-200 flex items-center justify-center shrink-0">
                        <CalendarClock className="w-4 h-4 text-emerald-600" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[11px] text-slate-500">Last Active</span>
                        <span
                          className="block text-xs sm:text-sm font-semibold text-[#111827] truncate mt-0.5"
                          title={`First seen: ${formatLocalTimestamp(
                            data.statistics.firstVisitUtc
                          )} | Last seen: ${formatLocalTimestamp(data.statistics.lastVisitUtc)}`}
                        >
                          {formatConciseSeenTimestamp(data.statistics.lastVisitUtc)}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* Dedicated Smart Signals & Threat Analysis (4-signal core grid) + Hardware & Rendering Entropy (2x3 Grid) */}
        {data && data.securitySignals && data.hardwareSignals && (
          <section
            id="signals"
            className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch"
          >
            {/* LEFT CARD: Smart Signals & Threat Analysis (4-signal core grid) */}
            <div className="bg-white border border-[#E5E7EB] rounded-2xl p-4 sm:p-6 flex flex-col justify-between">
              <div>
                {showAttributionBanner && (
                  <div className="mb-3.5 flex flex-col gap-2">
                    {(torExitDetected || torBrowserClient) && (
                      <div className="flex items-start gap-2.5 rounded-xl border border-rose-200 bg-rose-50/70 px-3 py-2.5">
                        <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                        <div className="min-w-0 flex-1">
                          <span className="block text-xs font-semibold text-rose-700">
                            Tor Anonymity Network
                          </span>
                          <span className="block text-[11px] leading-relaxed text-rose-700/80 font-mono break-words">
                            {[
                              torExitDetected
                                ? `Exit relay ${data.location.publicIp}`
                                : `Client fingerprint on ${data.location.publicIp}`,
                              torOperatorLabel ? `Operator ${torOperatorLabel}` : '',
                              torExitDetected ? 'Server exit-list match' : '',
                              torBrowserClient ? 'Tor Browser RFP + letterboxing' : '',
                            ]
                              .filter(Boolean)
                              .join(' · ')}
                          </span>
                        </div>
                      </div>
                    )}
                    {activeAiAgent?.detected && (
                      <div className="flex items-start gap-2.5 rounded-xl border border-indigo-200 bg-indigo-50/70 px-3 py-2.5">
                        <Bot className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
                        <div className="min-w-0 flex-1">
                          <span className="block text-xs font-semibold text-indigo-700">
                            {activeAiAgent.agentId === 'impostor-spoof'
                              ? 'Spoofed AI Agent (Unverified)'
                              : 'AI Agent Attribution'}
                          </span>
                          <span className="block text-[11px] leading-relaxed text-indigo-700/80 break-words">
                            {[
                              activeAiAgent.agentName,
                              activeAiAgent.operator,
                              activeAiAgent.executionMode,
                              `${activeAiAgent.confidence}${
                                activeAiAgent.verified ? ' (verified)' : ''
                              }`,
                            ]
                              .filter(Boolean)
                              .join(' · ')}
                          </span>
                          {activeAiAgent.evidence[0] && (
                            <span className="block text-[11px] leading-relaxed text-indigo-700/70 font-mono break-words">
                              {activeAiAgent.evidence[0]}
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
                <div className="flex items-center justify-between gap-3 pb-3.5 border-b border-[#E5E7EB] flex-wrap">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-[#2563EB] shrink-0" />
                    <h2 className="text-sm sm:text-base font-semibold text-slate-900">
                      Smart Signals &amp; Threat Analysis
                    </h2>
                  </div>

                  <span
                    className={`inline-flex items-center gap-1.5 text-xs font-mono font-semibold ${
                      riskTier === 'High'
                        ? 'text-rose-700'
                        : riskTier === 'Medium'
                        ? 'text-amber-700'
                        : 'text-emerald-700'
                    }`}
                  >
                    {riskTier === 'High' ? (
                      <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                    ) : (
                      <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                    )}
                    <span>{`${riskTier} Risk \u2022 ${suspectScore100}/100`}</span>
                  </span>
                </div>

                {/* 4-Signal Core Swiss Tile Grid */}
                <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 border border-[#E5E7EB] rounded-xl overflow-hidden">
                  {signalRows.map((row, index) => {
                    const { key, ...rowProps } = row;
                    const tileBorderClass =
                      index === 0
                        ? 'border-b sm:border-r border-[#E5E7EB]'
                        : index === 1
                        ? 'border-b border-[#E5E7EB]'
                        : index === 2
                        ? 'border-b sm:border-b-0 sm:border-r border-[#E5E7EB]'
                        : 'border-[#E5E7EB]';
                    return (
                      <SignalRow
                        key={key}
                        {...rowProps}
                        className={tileBorderClass}
                      />
                    );
                  })}
                </div>

                {/* Granular Smart Signals grid: one deterministic row per signal */}
                <div className="mt-5 pt-4 border-t border-[#E5E7EB]">
                  <div className="flex items-center justify-between gap-3 flex-wrap">
                    <div className="flex items-center gap-2">
                      <Layers className="w-4 h-4 text-[#2563EB] shrink-0" />
                      <h3 className="text-xs sm:text-sm font-semibold text-slate-900">
                        Smart Signals
                      </h3>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">
                      {data.visitHistory.length} {data.visitHistory.length === 1 ? 'record' : 'records'} persisted
                    </span>
                  </div>
                  <SmartSignalsGrid data={data} />
                </div>
              </div>

              {/* Clean Visual Trust Meter Footer Bar */}
              <div className="mt-4 pt-3.5 border-t border-[#E5E7EB] flex items-center justify-between gap-4">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-xs font-medium text-slate-600 whitespace-nowrap">
                    Risk Meter
                  </span>
                  <span className="text-xs font-mono tabular-nums text-slate-500 truncate">
                    • {`${riskTier} Risk \u2022 ${suspectScore100}/100`}
                  </span>
                </div>

                <div className="w-28 sm:w-36 h-2 rounded-full bg-slate-100 overflow-hidden shrink-0 border border-[#E5E7EB]">
                  <div
                    className={`h-full transition-all duration-300 ${
                      riskTier === 'High'
                        ? 'bg-rose-600'
                        : riskTier === 'Medium'
                        ? 'bg-amber-500'
                        : 'bg-emerald-500'
                    }`}
                    style={{
                      width: `${Math.max(2, suspectScore100)}%`,
                    }}
                  />
                </div>
              </div>
            </div>

            {/* RIGHT CARD: Hardware & Rendering Entropy (2x3 Visual Icon Grid) */}
            <div className="bg-white border border-[#E5E7EB] rounded-2xl p-4 sm:p-6 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between gap-3 pb-3.5 border-b border-[#E5E7EB] flex-wrap">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-[#F05A28] shrink-0" />
                    <h2 className="text-sm sm:text-base font-semibold text-slate-900">
                      Hardware &amp; Rendering Entropy
                    </h2>
                  </div>

                  <span className="text-xs font-mono text-slate-500">
                    Native Web API
                  </span>
                </div>

                {/* 2x3 Visual Icon Tile Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 mt-4">
                  {/* Tile 1: Processor */}
                  <div className="p-3.5 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-start gap-3 min-w-0">
                    <div className="w-9 h-9 rounded-lg bg-orange-50/60 border border-[#E5E7EB] flex items-center justify-center shrink-0">
                      <Cpu className="w-4 h-4 text-[#F05A28]" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <span className="block text-[11px] text-slate-500">Processor</span>
                      <span
                        className="block text-xs sm:text-sm font-semibold font-mono tabular-nums text-[#111827] truncate mt-0.5"
                        title={`${
                          data.hardwareSignals.cpuCores
                            ? `${data.hardwareSignals.cpuCores} Logical Cores`
                            : 'Multi-Core'
                        } • ${data.hardwareSignals.architecture}`}
                      >
                        {data.hardwareSignals.cpuCores
                          ? `${data.hardwareSignals.cpuCores} Cores`
                          : 'Multi-Core'}{' '}
                        • {data.hardwareSignals.architecture}
                      </span>
                    </div>
                  </div>

                  {/* Tile 2: Graphics (Clean GPU Name + Max Texture) */}
                  <div
                    className="p-3.5 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-start gap-3 min-w-0"
                    title={rawGpuTooltip}
                  >
                    <div className="w-9 h-9 rounded-lg bg-blue-50/60 border border-blue-200 flex items-center justify-center shrink-0">
                      <CircuitBoard className="w-4 h-4 text-[#2563EB]" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-1.5">
                        <span className="text-[11px] text-slate-500">Graphics (GPU)</span>
                        {data.hardwareSignals.maxTextureSize > 0 && (
                          <span className="text-[10px] font-mono text-slate-400 shrink-0">
                            {data.hardwareSignals.maxTextureSize.toLocaleString()} px
                          </span>
                        )}
                      </div>
                      <span className="block text-xs sm:text-sm font-semibold text-[#111827] truncate mt-0.5">
                        {cleanGpuName}
                      </span>
                    </div>
                  </div>

                  {/* Tile 3: Memory Tier */}
                  <div className="p-3.5 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-start gap-3 min-w-0">
                    <div className="w-9 h-9 rounded-lg bg-emerald-50/60 border border-emerald-200 flex items-center justify-center shrink-0">
                      <HardDrive className="w-4 h-4 text-emerald-600" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <span className="block text-[11px] text-slate-500">Memory Tier</span>
                      <span className="block text-xs sm:text-sm font-semibold font-mono tabular-nums text-[#111827] truncate mt-0.5">
                        {data.hardwareSignals.deviceMemoryGb
                          ? `~${data.hardwareSignals.deviceMemoryGb} GB RAM`
                          : 'Standard RAM'}{' '}
                        • {data.hardwareSignals.colorDepth}-bit
                      </span>
                    </div>
                  </div>

                  {/* Tile 4: Display & Input */}
                  <div className="p-3.5 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-start gap-3 min-w-0">
                    <div className="w-9 h-9 rounded-lg bg-indigo-50/60 border border-indigo-200 flex items-center justify-center shrink-0">
                      <Palette className="w-4 h-4 text-indigo-600" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <span className="block text-[11px] text-slate-500">
                        Display &amp; Input
                      </span>
                      <span
                        className="block text-xs sm:text-sm font-semibold font-mono tabular-nums text-[#111827] break-words leading-snug mt-0.5 min-w-0"
                        title={`${data.hardwareSignals.colorGamut} • ${
                          data.hardwareSignals.hdrSupported ? 'HDR' : 'SDR'
                        } • ${
                          data.hardwareSignals.maxTouchPoints === 0
                            ? 'No Touch'
                            : `${data.hardwareSignals.maxTouchPoints}-pt Touch`
                        }`}
                      >
                        {data.hardwareSignals.colorGamut} •{' '}
                        {data.hardwareSignals.hdrSupported ? 'HDR' : 'SDR'} •{' '}
                        {data.hardwareSignals.maxTouchPoints === 0
                          ? 'No Touch'
                          : `${data.hardwareSignals.maxTouchPoints}-pt Touch`}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Direct GPU Vendor & Raw GPU Renderer Display (Always Visible, No Dropdown) */}
              <div className="mt-4 pt-3.5 border-t border-[#E5E7EB]">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-slate-500 truncate">
                    Vendor:{' '}
                    <strong className="font-semibold text-slate-800">
                      {data.hardwareSignals.gpuVendor}
                    </strong>
                  </span>
                  <span className="text-[11px] font-mono text-slate-400 shrink-0">
                    Raw GPU
                  </span>
                </div>

                <div className="mt-2 p-2.5 rounded-lg bg-slate-50 border border-[#E5E7EB] text-[11px] font-mono text-slate-600 break-all">
                  {data.hardwareSignals.gpuRenderer}
                </div>
              </div>
            </div>
          </section>
        )}

        {/* Network Stability & System CPU Pressure (Responsive Side-by-Side Grid) */}
        <section id="diagnostics" className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
          <NetworkStabilityPanel />
          <CpuActivityPanel />
        </section>

        {/* Full SQLite Visit History Table */}
        {data && (
          <section
            id="history"
            className="bg-white border border-[#E5E7EB] rounded-2xl p-4 sm:p-6"
          >
            <div className="flex items-center justify-between gap-4 pb-3.5 border-b border-[#E5E7EB]">
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-slate-700 shrink-0" />
                <h2 className="text-sm sm:text-base font-semibold text-slate-900">
                  Visit History
                </h2>
              </div>
              <span className="text-xs font-mono tabular-nums text-slate-500">
                {data.visitHistory.length}{' '}
                {data.visitHistory.length === 1 ? 'record' : 'records'}
              </span>
            </div>

            <div className="mt-3 overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-[#E5E7EB] text-slate-500 font-medium">
                    <th className="py-2.5 pr-3">#</th>
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Public IP</th>
                    <th className="py-2.5 px-3">Location</th>
                    <th className="py-2.5 px-3">ISP / ASN</th>
                    <th className="py-2.5 px-3">Signal / Status</th>
                    <th className="py-2.5 pl-3 text-right">Browser &amp; OS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {data.visitHistory.slice(0, visibleVisitsCount).map((visit, index) => {
                    const rowIsp = formatValidNetworkField(visit.isp);
                    const rowOrg = formatValidNetworkField(visit.org);
                    const rowAsn = formatValidNetworkField(visit.asn);
                    const rowIspFormatted = formatCleanIspDisplay(rowIsp, rowOrg, rowAsn);
                    const rowScore = normalizeLegacyScore(visit.suspectScore);
                    const rowRisk: RiskLevel =
                      visit.riskLevel === 'High' ||
                      visit.riskLevel === 'Medium' ||
                      visit.riskLevel === 'Low'
                        ? visit.riskLevel
                        : resolveRiskTier(rowScore);
                    const rowRiskLabel = `${rowRisk === 'Medium' ? 'Med' : rowRisk} • ${rowScore}/10`;
                    const rowRiskDotClass =
                      rowRisk === 'High'
                        ? 'bg-rose-500'
                        : rowRisk === 'Medium'
                        ? 'bg-amber-500'
                        : 'bg-emerald-500';
                    const rowRiskTextClass =
                      rowRisk === 'High'
                        ? 'text-rose-700'
                        : rowRisk === 'Medium'
                        ? 'text-amber-700'
                        : 'text-emerald-700';
                    return (
                      <tr
                        key={visit.visitId}
                        onClick={() => setSelectedVisitIndex(index)}
                        className={`cursor-pointer transition-colors ${
                          selectedVisitIndex === index
                            ? 'bg-orange-50/60'
                            : 'hover:bg-slate-50/80'
                        }`}
                      >
                        <td className="py-2.5 pr-3 font-mono tabular-nums text-slate-500 whitespace-nowrap">
                          {data.statistics.totalVisits - index}
                        </td>
                        <td className="py-2.5 px-3 font-mono tabular-nums text-slate-900 whitespace-nowrap">
                          {formatLocalTimestamp(visit.visitedAtUtc)}
                        </td>
                        <td className="py-2.5 px-3 font-mono tabular-nums text-slate-900 whitespace-nowrap">
                          {visit.publicIp}
                        </td>
                        <td className="py-2.5 px-3 text-slate-800 whitespace-nowrap">
                          {formatShortLocation(visit.city, visit.country)}
                        </td>
                        <td
                          className="py-2.5 px-3 text-slate-800 whitespace-nowrap max-w-[220px] truncate"
                          title={rowIspFormatted.fullTooltip}
                        >
                          {rowIspFormatted.shortLabel}
                        </td>
                        <td
                          className="py-2.5 px-3 whitespace-nowrap"
                          title={`Recognition: ${visit.recognitionSource ?? 'Cookie'}`}
                        >
                          <span
                            className={`inline-flex items-center gap-1.5 font-mono font-semibold tabular-nums ${rowRiskTextClass}`}
                          >
                            <span
                              className={`w-1.5 h-1.5 rounded-full shrink-0 ${rowRiskDotClass}`}
                            />
                            {rowRiskLabel}
                          </span>
                        </td>
                        <td className="py-2.5 pl-3 text-right text-slate-800 whitespace-nowrap">
                          {visit.browser} • {visit.os} ({visit.deviceType})
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {data.visitHistory.length > 5 && (
              <div className="mt-3 pt-3 border-t border-[#E5E7EB] flex flex-wrap items-center justify-between gap-3">
                <span className="text-[11px] font-mono text-slate-500">
                  Showing {Math.min(visibleVisitsCount, data.visitHistory.length)} of{' '}
                  {data.visitHistory.length} visits
                </span>
                <div className="flex items-center gap-2">
                  {visibleVisitsCount < data.visitHistory.length && (
                    <button
                      type="button"
                      onClick={() =>
                        setVisibleVisitsCount((prev) =>
                          Math.min(prev + 5, data.visitHistory.length)
                        )
                      }
                      className="px-3 py-1.5 text-xs font-medium text-slate-800 bg-white border border-slate-300 rounded-md hover:bg-slate-50 cursor-pointer"
                    >
                      Show next 5 visits (+
                      {Math.min(5, data.visitHistory.length - visibleVisitsCount)})
                    </button>
                  )}
                  {visibleVisitsCount > 5 && (
                    <button
                      type="button"
                      onClick={() => setVisibleVisitsCount(5)}
                      className="px-3 py-1.5 text-xs font-medium text-slate-600 bg-white border border-slate-300 rounded-md hover:bg-slate-50 cursor-pointer"
                    >
                      Collapse to latest 5
                    </button>
                  )}
                </div>
              </div>
            )}
          </section>
        )}

        {/* Bottom event inspector: complete API v4 payload built from live signals */}
        <section id="raw-json" className="bg-white border border-[#E5E7EB] rounded-2xl p-4 sm:p-6">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3.5 border-b border-[#E5E7EB]">
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-slate-700 shrink-0" />
              <h2 className="text-sm sm:text-base font-semibold text-slate-900">
                Event JSON
              </h2>
              <span className="text-[11px] font-mono text-slate-500">API v4</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={async () => {
                  if (!eventJson) return;
                  try {
                    await navigator.clipboard.writeText(JSON.stringify(eventJson, null, 2));
                    setCopiedJson(true);
                    setTimeout(() => setCopiedJson(false), 1500);
                  } catch {
                    // Clipboard unavailable
                  }
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-800 bg-white border border-slate-300 rounded-md hover:bg-slate-50 cursor-pointer"
              >
                {copiedJson ? (
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                {copiedJson ? 'Copied' : 'Copy Event JSON'}
              </button>
            </div>
          </div>
          <pre className="mt-3 max-h-[420px] overflow-auto rounded-xl bg-[#F8FAFC] border border-[#E5E7EB] p-3 text-[11px] leading-relaxed font-mono text-slate-700">
{eventJson ? JSON.stringify(eventJson, null, 2) : 'Collecting event payload...'}
          </pre>
        </section>
      </main>

      {/* Cursor attribution: human pointer or remote browser agent pill */}
      <CursorAttributionOverlay identity={cursorIdentity} />
    </div>
  );
}

import { useEffect, useState, useCallback } from 'react';
import { identifyCurrentVisitor } from './lib/collector';
import type {
  IntelVisitorResponse,
  NetworkType,
  RiskLevel,
  SecuritySignals,
} from './types/visitor';
import { LocationMap } from './components/LocationMap';
import { NetworkStabilityPanel } from './components/NetworkStabilityPanel';
import { CpuActivityPanel } from './components/CpuActivityPanel';
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
  Moon,
  Sun,
} from 'lucide-react';

type ThemeMode = 'light' | 'dark';

const THEME_STORAGE_KEY = 'intel_theme';

function resolveInitialTheme(): ThemeMode {
  if (typeof window === 'undefined') return 'light';
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === 'dark' || stored === 'light') return stored;
  } catch {
    // localStorage unavailable
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

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
  Satellite: 'bg-violet-50 text-violet-700 border border-violet-100',
  'Cloud / Datacenter': 'bg-slate-100 text-slate-600 border border-slate-200',
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
        {`${riskTier} Risk • ${row.riskScore}/10`}
      </span>
    </div>
  );
}

/**
 * Builds the 4-signal core grid: Incognito / Private Browsing, Bot &
 * Automation, VPN / Proxy & Network Type, and Virtual Machine &
 * Environment Integrity.
 */
function buildSignalRows(signals: SecuritySignals): SignalRowModel[] {
  const botCloud = Boolean(signals.datacenterAsn && signals.cloudOrMaskedGpu);
  const cloudOrMaskedGpu = Boolean(signals.cloudOrMaskedGpu);
  const incognitoEphemeral =
    signals.incognitoLikely ||
    Boolean(signals.incognitoOrCleared) ||
    signals.persistenceMode === 'Hardware ID Recovered' ||
    signals.persistenceMode === 'Private / Restricted Storage';

  return [
    // Tile 1: Incognito / Private Browsing
    createSignalRow({
      key: 'incognito',
      tone: incognitoEphemeral ? 'warn' : 'ok',
      title: 'Incognito / Private Browsing',
      caption: incognitoEphemeral
        ? 'No persistent first-party storage or cookie survived this session'
        : 'Persistent storage and first-party cookies active',
      statusLabel: incognitoEphemeral ? 'Incognito / Private Mode' : 'Standard Window',
      tooltip: `Persistence Mode: ${signals.persistenceMode}`,
      riskScore: incognitoEphemeral ? 4 : 0,
    }),

    // Tile 2: Bot & Automation
    createSignalRow({
      key: 'bot',
      tone: signals.isBot ? 'bad' : botCloud ? 'warn' : 'ok',
      title: 'Bot & Automation',
      caption:
        signals.botSignals[0] ??
        (signals.isBot
          ? 'Automation runtime hooks detected'
          : botCloud
          ? 'Cloud / Masked GPU environment'
          : 'Interactive human session verified'),
      statusLabel: signals.isBot
        ? 'Bot / Automated'
        : botCloud
        ? 'Cloud / Headless'
        : 'Verified Human',
      tooltip: signals.isBot
        ? signals.botSignals.length > 0
          ? signals.botSignals.join(' • ')
          : 'Automation hooks or headless WebDriver detected'
        : botCloud
        ? 'Datacenter ASN with masked or unavailable WebGL GPU (no automation hooks detected)'
        : 'No automation, headless WebDriver, or virtual GPU hooks detected',
      riskScore: signals.isBot || (signals.datacenterAsn && signals.cloudOrMaskedGpu) ? 8 : 0,
    }),

    // Tile 3: VPN / Proxy & Network Type
    createSignalRow({
      key: 'vpn',
      tone: signals.vpnSuspected ? 'warn' : 'ok',
      title: 'VPN / Proxy & Network Type',
      caption: signals.vpnSuspected
        ? (signals.vpnReasons[0] ?? 'Timezone or datacenter ASN mismatch detected')
        : `${signals.brandName ?? 'Unknown ISP'} • ${
            signals.networkType ?? 'Residential Broadband'
          }`,
      statusLabel: signals.vpnSuspected ? 'VPN / Proxy' : 'Standard ISP',
      tooltip: signals.vpnReasons.length > 0
        ? signals.vpnReasons.join(' • ')
        : `Browser TZ (${signals.browserTimezone}) matches IP TZ (${signals.ipTimezone})`,
      riskScore: signals.vpnSuspected ? 6 : 0,
    }),

    // Tile 4: Virtual Machine & Environment Integrity
    createSignalRow({
      key: 'vm',
      tone: signals.isVirtualMachine ? 'warn' : 'ok',
      title: 'Virtual Machine & Environment Integrity',
      caption: signals.vmReason ?? 'Bare-metal GPU & CPU profile',
      statusLabel: signals.isVirtualMachine ? 'Virtual Machine' : 'Physical Hardware',
      tooltip: signals.vmReason ?? 'No hypervisor or virtualization markers detected',
      riskScore: signals.isVirtualMachine || cloudOrMaskedGpu ? 7 : 0,
    }),
  ];
}

export default function App() {
  const [data, setData] = useState<IntelVisitorResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<boolean>(false);
  const [copiedHwId, setCopiedHwId] = useState<boolean>(false);
  const [selectedVisitIndex, setSelectedVisitIndex] = useState<number>(0);
  const [theme, setTheme] = useState<ThemeMode>(resolveInitialTheme);

  useEffect(() => {
    const isDark = theme === 'dark';
    document.documentElement.classList.toggle('dark', isDark);
    document.body?.classList.toggle('dark', isDark);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // localStorage unavailable
    }
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
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

  // Normalized 0..10 threat score + derived risk tier (legacy scale converted)
  const normalizedSuspectScore = normalizeLegacyScore(data?.securitySignals?.suspectScore);
  const riskTier: RiskLevel = resolveRiskTier(normalizedSuspectScore);

  // 4-signal core grid model (null-safe: renders only inside the data block)
  const activeSignals = data?.securitySignals ?? null;
  const signalRows = activeSignals ? buildSignalRows(activeSignals) : [];

  return (
    <div
      className={`${
        theme === 'dark' ? 'dark bg-[#0b1220] text-[#f1f5f9]' : 'bg-[#F4F5F7] text-[#111827]'
      } min-h-screen flex flex-col transition-colors duration-150`}
    >
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
              onClick={toggleTheme}
              aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              aria-pressed={theme === 'dark'}
              title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              className="inline-flex items-center justify-center w-8 h-8 text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded-md shrink-0 cursor-pointer"
            >
              {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
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
                    <span>{`${riskTier} Risk • ${normalizedSuspectScore}/10`}</span>
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
              </div>

              {/* Clean Visual Trust Meter Footer Bar */}
              <div className="mt-4 pt-3.5 border-t border-[#E5E7EB] flex items-center justify-between gap-4">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-xs font-medium text-slate-600 whitespace-nowrap">
                    Trust Meter
                  </span>
                  <span className="text-xs font-mono tabular-nums text-slate-500 truncate">
                    • {riskTier} Risk (Score {normalizedSuspectScore}/10)
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
                      width: `${Math.max(8, 100 - normalizedSuspectScore * 10)}%`,
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
                  {data.visitHistory.map((visit, index) => {
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
          </section>
        )}
      </main>
    </div>
  );
}

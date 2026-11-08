import { useEffect, useState, useCallback } from 'react';
import { identifyCurrentVisitor } from './lib/collector';
import type { IntelVisitorResponse } from './types/visitor';
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
  Radio,
  Monitor,
  Laptop,
  Clock,
  Calendar,
  Layers,
  History,
  ShieldCheck,
  Building2,
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
 * Formats relative time accurately from a real UTC timestamp.
 */
function formatRelativeVisitTime(utcIso: string | null | undefined): string {
  if (!utcIso) return 'Unavailable';
  try {
    const date = new Date(utcIso);
    if (Number.isNaN(date.getTime())) return 'Unavailable';
    const diffSec = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    if (diffSec < 10) return 'Just now';
    if (diffSec < 60) return `${diffSec} seconds ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin === 1) return '1 minute ago';
    if (diffMin < 60) return `${diffMin} minutes ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr === 1) return '1 hour ago';
    if (diffHr < 24) return `${diffHr} hours ago`;
    const diffDays = Math.floor(diffHr / 24);
    if (diffDays === 1) return '1 day ago';
    return `${diffDays} days ago`;
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
  const validCountry = country && country !== 'Unknown' && country !== 'Unavailable' ? country : null;
  if (validCity && validCountry) {
    return validCity === validCountry ? validCity : `${validCity}, ${validCountry}`;
  }
  return validCity || validCountry || 'Unavailable';
}

function formatValidNetworkField(value: string | null | undefined): string {
  if (!value || value === 'Unavailable' || value === 'Unknown') return 'Unknown';
  return value;
}

export default function App() {
  const [data, setData] = useState<IntelVisitorResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<boolean>(false);
  const [selectedVisitIndex, setSelectedVisitIndex] = useState<number>(0);
  const [theme, setTheme] = useState<ThemeMode>(resolveInitialTheme);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle('dark', theme === 'dark');
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

  const handleCopyVisitorId = async () => {
    if (!data?.visitorId) return;
    try {
      await navigator.clipboard.writeText(data.visitorId);
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 1500);
    } catch {
      // Ignore
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
  const isVpnOrHosting = Boolean(data?.location.isVpnOrHosting);

  const activeLatitude =
    activeVisit && typeof activeVisit.latitude === 'number'
      ? activeVisit.latitude
      : data?.location.latitude ?? null;
  const activeLongitude =
    activeVisit && typeof activeVisit.longitude === 'number'
      ? activeVisit.longitude
      : data?.location.longitude ?? null;

  return (
    <div className="min-h-screen flex flex-col bg-[#F4F5F7] text-[#111827]">
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
              {theme === 'dark' ? (
                <Sun className="w-4 h-4" />
              ) : (
                <Moon className="w-4 h-4" />
              )}
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

      <main className="flex-1 max-w-7xl w-full mx-auto px-3 sm:px-6 py-4 sm:py-8 space-y-6">
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
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4 border-t border-slate-100">
              <div className="h-16 bg-slate-100 rounded" />
              <div className="h-16 bg-slate-100 rounded" />
              <div className="h-16 bg-slate-100 rounded" />
              <div className="h-16 bg-slate-100 rounded" />
            </div>
            <div className="h-56 bg-slate-100 rounded" />
          </div>
        )}

        {data && (
          <section
            id="overview"
            className="bg-white rounded-2xl border border-[#E5E7EB] shadow-2xs overflow-hidden"
          >
            {/* Main 2-Column Split: Left (Visitor Summary, Map, Public IP, Location & ISP) | Right (Device & Visit Specs) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 items-stretch">
              {/* LEFT COLUMN (7 cols on lg+) */}
              <div className="lg:col-span-7 flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-[#E5E7EB]">
                {/* 1. Visitor ID Header */}
                <div className="px-4 sm:px-7 py-5 sm:py-6 border-b border-[#E5E7EB] flex items-center justify-between gap-3 flex-wrap">
                  <div className="flex items-baseline gap-2 flex-wrap min-w-0">
                    <h1 className="text-lg sm:text-[22px] font-semibold tracking-tight text-[#111827]">
                      Hello, visitor ID
                    </h1>
                    <code className="text-lg sm:text-[22px] font-bold font-mono tabular-nums text-[#F05A28] break-all">
                      {data.visitorId}
                    </code>
                  </div>

                  <button
                    type="button"
                    onClick={handleCopyVisitorId}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-500 hover:text-slate-900 border border-[#E5E7EB] rounded hover:bg-slate-50 whitespace-nowrap shrink-0 cursor-pointer"
                    title="Copy Visitor ID"
                  >
                    {copiedId ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>

                {/* 2. 4-Box Summary Strip */}
                <div className="grid grid-cols-2 sm:grid-cols-4 border-b border-[#E5E7EB]">
                  {/* Cell 1: Total Visits */}
                  <div className="p-3.5 sm:p-4 border-r border-b sm:border-b-0 border-[#E5E7EB] shadow-[inset_3px_0_0_0_#F05A28]">
                    <span className="inline-flex items-center gap-1 text-[10px] sm:text-[11px] font-mono tracking-wider uppercase text-slate-500">
                      <Calendar className="w-3 h-3 text-slate-400" /> VISITS
                    </span>
                    <span className="text-xs sm:text-[15px] font-medium text-[#111827] mt-1.5 block">
                      {data.statistics.totalVisits}{' '}
                      {data.statistics.totalVisits === 1 ? 'visit' : 'visits'}
                    </span>
                  </div>

                  {/* Cell 2: Sessions */}
                  <div className="p-3.5 sm:p-4 sm:border-r border-b sm:border-b-0 border-[#E5E7EB]">
                    <span className="inline-flex items-center gap-1 text-[10px] sm:text-[11px] font-mono tracking-wider uppercase text-slate-500">
                      <Layers className="w-3 h-3 text-slate-400" /> SESSIONS
                    </span>
                    <span className="text-xs sm:text-[15px] font-medium text-[#111827] mt-1.5 block">
                      {data.statistics.totalSessions}{' '}
                      {data.statistics.totalSessions === 1 ? 'session' : 'sessions'}
                    </span>
                  </div>

                  {/* Cell 3: IP Address Count */}
                  <div className="p-3.5 sm:p-4 border-r border-[#E5E7EB]">
                    <span className="inline-flex items-center gap-1 text-[10px] sm:text-[11px] font-mono tracking-wider uppercase text-slate-500">
                      <Globe className="w-3 h-3 text-slate-400" /> IP ADDRESS
                    </span>
                    <span className="text-xs sm:text-[15px] font-medium text-[#111827] mt-1.5 block">
                      {uniqueIpCount > 0
                        ? `${uniqueIpCount} ${uniqueIpCount === 1 ? 'IP' : 'IPs'}`
                        : 'Unavailable'}
                    </span>
                  </div>

                  {/* Cell 4: Geolocation Count */}
                  <div className="p-3.5 sm:p-4">
                    <span className="inline-flex items-center gap-1 text-[10px] sm:text-[11px] font-mono tracking-wider uppercase text-slate-500">
                      <MapPin className="w-3 h-3 text-slate-400" /> LOCATION
                    </span>
                    <span className="text-xs sm:text-[15px] font-medium text-[#111827] mt-1.5 block">
                      {uniqueLocationCount > 0
                        ? `${uniqueLocationCount} ${uniqueLocationCount === 1 ? 'location' : 'locations'}`
                        : 'Unavailable'}
                    </span>
                  </div>
                </div>

                {/* 3. PUBLIC IP & LOCATION Header Bar */}
                <div className="px-4 sm:px-7 py-2.5 bg-[#FAFAFA] border-b border-[#E5E7EB] flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-[11px] font-mono tracking-wider uppercase text-slate-600">
                    <Globe className="w-3.5 h-3.5 text-slate-400" /> PUBLIC IP &amp; LOCATION
                  </span>
                  <span className="text-[11px] font-mono tabular-nums text-slate-400">
                    Visit #{data.statistics.totalVisits - selectedVisitIndex} of{' '}
                    {data.statistics.totalVisits}
                  </span>
                </div>

                {/* 4. Visit Details + Leaflet OpenStreetMap + Network Provider (ISP) + Detail Cells */}
                {activeVisit && (
                  <div className="flex-1 grid grid-cols-1 md:grid-cols-2">
                    {/* Top-Left: Location, Timestamp & Network Provider (ISP) */}
                    <div className="p-4 sm:p-5 flex flex-col justify-between border-b border-[#E5E7EB] gap-3">
                      <div>
                        <div className="inline-flex items-center gap-1.5 text-xs font-mono uppercase tracking-wider text-slate-400 mb-0.5">
                          <MapPin className="w-3.5 h-3.5 text-[#F05A28]" />
                          <span>{formatRelativeVisitTime(activeVisit.visitedAtUtc)}</span>
                        </div>
                        <div className="text-base sm:text-[17px] font-semibold text-[#111827]">
                          {formatLocationDisplay(
                            activeVisit.city,
                            activeVisit.region,
                            activeVisit.country
                          )}
                        </div>
                        <div className="text-[11px] font-mono tabular-nums text-slate-500 mt-0.5">
                          {formatLocalTimestamp(activeVisit.visitedAtUtc)}
                        </div>
                      </div>

                      {/* Network Provider (ISP) under Public IP & Location */}
                      <div className="pt-2.5 border-t border-slate-100">
                        <div className="inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-500">
                          <Radio className="w-3 h-3 text-[#2563EB] shrink-0" />
                          <span>Network Provider (ISP)</span>
                        </div>
                        <div className="text-xs sm:text-sm font-semibold text-[#111827] mt-0.5 break-words">
                          {activeIsp}
                          {activeAsn !== 'Unknown' ? (
                            <span className="ml-1.5 font-mono text-[11px] font-medium text-slate-600">
                              ({activeAsn})
                            </span>
                          ) : null}
                        </div>
                        {activeOrg !== 'Unknown' && activeOrg !== activeIsp && (
                          <div className="inline-flex items-center gap-1 text-[11px] text-slate-500 mt-0.5 truncate max-w-full">
                            <Building2 className="w-3 h-3 text-slate-400 shrink-0" />
                            <span className="truncate">{activeOrg}</span>
                          </div>
                        )}
                        {isVpnOrHosting && (
                          <p className="mt-1 text-[10.5px] leading-snug text-amber-800 bg-amber-50 border border-amber-200/80 rounded px-2 py-1">
                            Network associated with observed public IP (VPN, proxy, or corporate network); may differ from underlying ISP.
                          </p>
                        )}
                      </div>
                    </div>

                    {/* Top-Right: Leaflet + OpenStreetMap Free */}
                    <div className="border-b md:border-l border-[#E5E7EB] min-h-[168px]">
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

                    {/* Bottom-Left Stack: Public IP & Browser */}
                    <div className="divide-y divide-[#E5E7EB]">
                      <div className="px-4 sm:px-6 py-3.5 flex items-center justify-between gap-3 text-xs sm:text-sm">
                        <span className="inline-flex items-center gap-1.5 font-semibold text-[#111827] shrink-0">
                          <Globe className="w-3.5 h-3.5 text-slate-400" />
                          <span>Public IP</span>
                        </span>
                        <span className="font-mono tabular-nums text-slate-800 truncate">
                          {activeVisit.publicIp}
                        </span>
                      </div>
                      <div className="px-4 sm:px-6 py-3.5 flex items-center justify-between gap-3 text-xs sm:text-sm">
                        <span className="inline-flex items-center gap-1.5 font-semibold text-[#111827] shrink-0">
                          <Monitor className="w-3.5 h-3.5 text-slate-400" />
                          <span>Browser</span>
                        </span>
                        <span className="text-slate-700 truncate">
                          {activeVisit.browser}
                        </span>
                      </div>
                    </div>

                    {/* Bottom-Right Stack: Operating System & First-Party ID */}
                    <div className="border-t md:border-t-0 md:border-l border-[#E5E7EB] divide-y divide-[#E5E7EB] bg-[#ECFDF5]/65">
                      <div className="px-4 sm:px-6 py-3.5 flex items-center justify-between gap-3 text-xs sm:text-sm">
                        <span className="inline-flex items-center gap-1.5 font-semibold text-[#111827] shrink-0">
                          <Laptop className="w-3.5 h-3.5 text-[#15803D]" />
                          <span>OS &amp; Device</span>
                        </span>
                        <span className="font-medium text-[#15803D] truncate">
                          {activeVisit.os} ({activeVisit.deviceType})
                        </span>
                      </div>
                      <div className="px-4 sm:px-6 py-3.5 flex items-center justify-between gap-3 text-xs sm:text-sm">
                        <span className="inline-flex items-center gap-1.5 font-semibold text-[#111827] shrink-0">
                          <ShieldCheck className="w-3.5 h-3.5 text-[#15803D]" />
                          <span>Recognition</span>
                        </span>
                        <span className="font-medium text-[#15803D] truncate">
                          {data.recognitionSource}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* RIGHT COLUMN (5 cols on lg+): Device & Visit Specs */}
              <div className="lg:col-span-5 flex flex-col justify-between bg-white">
                <div className="px-5 sm:px-7 py-5 sm:py-6 border-b border-[#E5E7EB] flex items-center gap-2">
                  <Laptop className="w-4 h-4 text-slate-700 shrink-0" />
                  <h2 className="text-base sm:text-lg font-semibold tracking-tight text-[#111827]">
                    Device &amp; Visit Specs
                  </h2>
                </div>

                <div className="px-5 sm:px-7 py-3.5 flex-1 flex flex-col justify-center">
                  <dl className="divide-y divide-[#E5E7EB] text-xs sm:text-sm">
                    <div className="py-2.5 flex items-center justify-between gap-3">
                      <dt className="inline-flex items-center gap-1.5 text-slate-500">
                        <Radio className="w-3.5 h-3.5 text-slate-400" />
                        <span>Network Provider (ISP)</span>
                      </dt>
                      <dd className="font-medium text-[#111827] text-right truncate max-w-[230px]">
                        {activeIsp}
                        {activeAsn !== 'Unknown' ? ` (${activeAsn})` : ''}
                      </dd>
                    </div>
                    <div className="py-2.5 flex items-center justify-between gap-3">
                      <dt className="inline-flex items-center gap-1.5 text-slate-500">
                        <Building2 className="w-3.5 h-3.5 text-slate-400" />
                        <span>Organization</span>
                      </dt>
                      <dd className="font-medium text-[#111827] text-right truncate max-w-[230px]">
                        {activeOrg}
                      </dd>
                    </div>
                    <div className="py-2.5 flex items-center justify-between gap-3">
                      <dt className="inline-flex items-center gap-1.5 text-slate-500">
                        <Monitor className="w-3.5 h-3.5 text-slate-400" />
                        <span>Browser &amp; OS</span>
                      </dt>
                      <dd className="font-medium text-[#111827] text-right">
                        {data.browserDevice.browser} / {data.browserDevice.os}
                      </dd>
                    </div>
                    <div className="py-2.5 flex items-center justify-between gap-3">
                      <dt className="inline-flex items-center gap-1.5 text-slate-500">
                        <Laptop className="w-3.5 h-3.5 text-slate-400" />
                        <span>Screen &amp; Platform</span>
                      </dt>
                      <dd className="font-mono tabular-nums text-[#111827] text-right">
                        {data.browserDevice.screenResolution} ({data.browserDevice.platform})
                      </dd>
                    </div>
                    <div className="py-2.5 flex items-center justify-between gap-3">
                      <dt className="inline-flex items-center gap-1.5 text-slate-500">
                        <Globe className="w-3.5 h-3.5 text-slate-400" />
                        <span>Language &amp; Timezone</span>
                      </dt>
                      <dd className="font-mono text-[#111827] text-right truncate max-w-[220px]">
                        {data.browserDevice.language} / {data.browserDevice.timezone}
                      </dd>
                    </div>
                    <div className="py-2.5 flex items-center justify-between gap-3">
                      <dt className="inline-flex items-center gap-1.5 text-slate-500">
                        <Layers className="w-3.5 h-3.5 text-slate-400" />
                        <span>Current Session</span>
                      </dt>
                      <dd className="font-mono tabular-nums text-[#111827] text-right">
                        {data.statistics.currentSessionId}
                      </dd>
                    </div>
                    <div className="py-2.5 flex items-center justify-between gap-3">
                      <dt className="inline-flex items-center gap-1.5 text-slate-500">
                        <Calendar className="w-3.5 h-3.5 text-slate-400" />
                        <span>First Visit</span>
                      </dt>
                      <dd className="font-mono tabular-nums text-[#111827] text-right">
                        {formatLocalTimestamp(data.statistics.firstVisitUtc)}
                      </dd>
                    </div>
                    <div className="py-2.5 flex items-center justify-between gap-3">
                      <dt className="inline-flex items-center gap-1.5 text-slate-500">
                        <Clock className="w-3.5 h-3.5 text-slate-400" />
                        <span>Last Visit</span>
                      </dt>
                      <dd className="font-mono tabular-nums text-[#111827] text-right">
                        {formatLocalTimestamp(data.statistics.lastVisitUtc)}
                      </dd>
                    </div>
                  </dl>
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
                <h2 className="text-sm font-semibold text-slate-900">
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
                    <th className="py-2.5 px-3">Network Provider (ISP)</th>
                    <th className="py-2.5 pl-3 text-right">Browser &amp; OS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {data.visitHistory.map((visit, index) => {
                    const rowIsp = formatValidNetworkField(visit.isp);
                    const rowAsn = formatValidNetworkField(visit.asn);
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
                        <td className="py-2.5 px-3 text-slate-800 whitespace-nowrap">
                          {rowIsp}
                          {rowAsn !== 'Unknown' ? (
                            <span className="ml-1.5 font-mono text-[11px] text-slate-500">
                              ({rowAsn})
                            </span>
                          ) : null}
                        </td>
                        <td className="py-2.5 pl-3 text-right text-slate-800 whitespace-nowrap">
                          {visit.browser} / {visit.os} ({visit.deviceType})
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

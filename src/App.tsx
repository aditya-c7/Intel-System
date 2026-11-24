import { useEffect, useLayoutEffect, useMemo, useRef, useState, useCallback } from 'react';
import { identifyCurrentVisitor, detectIncognitoMode } from './lib/collector';
import type {
  IntelVisitorResponse,
  LocationInfo,
  NetworkType,
  RiskLevel,
  SecuritySignals,
  SmartSignal,
  SmartSignals,
  VisitHistoryRecord,
} from './types/visitor';
import { LocationMap } from './components/LocationMap';
import { NetworkStabilityPanel } from './components/NetworkStabilityPanel';
import { CpuActivityPanel } from './components/CpuActivityPanel';
import { isMobileDevice } from './lib/deviceClass';
import { normalizeIdentity } from './shared/normalization/uaNormalizer';
import {
  SmartSignalsGrid,
  resolveIncognitoVerdict,
  resolveVmVerdict,
  type IncognitoVerdict,
} from './components/SmartSignalsGrid';
import {
  CursorAttributionOverlay,
  resolveAutomationLabel,
  resolveCursorIdentity,
} from './components/CursorAttributionOverlay';
import {
  resolveCanonical,
  quarantineClaim,
  quarantineAttributes,
  isSwiftShader,
  SWIFTSHADER_LABEL,
} from './components/canonical';
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
  EyeOff,
  ChevronRight,
} from 'lucide-react';

/**
 * The dashboard has exactly one theme: the light UI. The legacy bootstrap can add `dark`
 * from a stored/OS preference before React mounts, which used to flash a dark frame. Strip it
 * as early as this module evaluates and again in a pre-paint layout effect so the very first
 * painted frame already matches the light dashboard (no bootstrap dark class can survive).
 */
function enforceLightTheme(): void {
  if (typeof document === 'undefined') return;
  document.documentElement.classList.remove('dark');
  document.body?.classList.remove('dark');
  try {
    window.localStorage.removeItem('intel_theme');
  } catch {
    // localStorage unavailable
  }
}
enforceLightTheme();

/** Edge-computed verdict injected into index.html by the Worker before any JS runs. */
interface InitialVerdict {
  name: string;
  provider: string | null;
  botType: string | null;
  identity: string | null;
  os: string | null;
}

/** Maps a runtime hostOs probe value onto the one canonical family label. */
function mapRuntimeOs(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const key = value.trim().toLowerCase();
  const families: Record<string, string> = {
    linux: 'Linux',
    linux_x64: 'Linux',
    linux_arm: 'Linux',
    macos: 'macOS',
    mac: 'macOS',
    darwin: 'macOS',
    osx: 'macOS',
    windows: 'Windows',
    win: 'Windows',
    win32: 'Windows',
  };
  return families[key] ?? null;
}

/** Second, independent runtime signal: the GPU/ANGLE backend implies an OS family. */
function osHintFromGpuRenderer(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const renderer = value.toLowerCase();
  if (/metal|apple m\d|apple gpu/.test(renderer)) return 'macOS';
  if (/direct3d|d3d1[01]|dxgi|windows/.test(renderer)) return 'Windows';
  if (/vulkan|mesa|glx|x11|wayland|llvmpipe|linux/.test(renderer)) return 'Linux';
  return null;
}

/** Never let a server-side "verified" claim survive on the displayed OS string. */
function stripVerifiedSuffix(value: string | null | undefined): string {
  return (value || '').replace(/\s*\(verified\)\s*$/i, '').trim();
}

/**
 * A "Verified Automation" tier is only honest when the named agent identity itself carries
 * verification (verified/signed). A UA-only claim — e.g. `Unverified · GPTBot` whose identity
 * is `unknown` — must never sit beside a verified tier, so downgrade it to an explicit
 * unverified-claim label. All other tiers (tampered, human, passive) are left untouched.
 */
function sanitizeVerdictTier(
  tier: string | null | undefined,
  agentIdentity: string | null | undefined
): string | null {
  const identity = (agentIdentity || '').trim().toLowerCase();
  const verified = identity === 'verified' || identity === 'signed';
  if (tier === 'Verified Automation' && !verified) return 'Unverified Automation Claim';
  return tier ?? null;
}

/** Module-level reader for the Worker's server-rendered JSON verdict (runs once at import). */
function readInitialVerdict(): InitialVerdict | null {
  if (typeof document === 'undefined') return null;
  const node = document.getElementById('intel-initial-verdict');
  if (!node) return null;
  try {
    const parsed = JSON.parse(node.textContent || '') as Record<string, unknown>;
    if (!parsed || typeof parsed.name !== 'string' || !parsed.name.trim()) return null;
    return {
      name: parsed.name.trim(),
      provider: typeof parsed.provider === 'string' && parsed.provider.trim() ? parsed.provider : null,
      botType: typeof parsed.botType === 'string' && parsed.botType.trim() ? parsed.botType : null,
      identity: typeof parsed.identity === 'string' && parsed.identity.trim() ? parsed.identity : null,
      os: typeof parsed.os === 'string' && parsed.os.trim() ? stripVerifiedSuffix(parsed.os) : null,
    };
  } catch {
    return null;
  }
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

/** A geo/network field that carries a real value rather than a placeholder token. */
function hasUsableGeoValue(value: string | null | undefined): boolean {
  if (!value) return false;
  const normalized = value.trim().toLowerCase();
  return (
    normalized !== '' &&
    normalized !== 'unknown' &&
    normalized !== 'unavailable' &&
    normalized !== 'n/a' &&
    normalized !== 'standard network'
  );
}

/**
 * True once both halves of the network identity are real: a city or country, and a
 * named ISP (a bare `Autonomous System AS…` placeholder does not count). The dashboard
 * keeps polling `/api/intel/geolocation` until this is true.
 */
function isLocationComplete(location: LocationInfo | null | undefined): boolean {
  if (!location) return false;
  const hasPlace = hasUsableGeoValue(location.city) || hasUsableGeoValue(location.country);
  const isp = (location.isp ?? '').trim();
  const hasNetwork = hasUsableGeoValue(isp) && !/^autonomous system\b/i.test(isp);
  return hasPlace && hasNetwork;
}

/** Field-level merge of a refreshed location onto the loaded response + its history. */
function mergeLocationIntoResponse(
  response: IntelVisitorResponse,
  location: LocationInfo
): IntelVisitorResponse {
  const refreshedIp =
    location.publicIp && location.publicIp !== 'Unavailable' ? location.publicIp : '';
  const visitHistory = response.visitHistory.map((visit, index) => {
    const sameNetwork = refreshedIp ? visit.publicIp === refreshedIp : false;
    const visitIsIncomplete =
      !hasUsableGeoValue(visit.city) ||
      !hasUsableGeoValue(visit.country) ||
      !hasUsableGeoValue(visit.isp);
    // The first row is the visit this page load just recorded, which is what the map and
    // tiles render. Update it even when the Tor circuit rotated to a new exit IP between
    // the identify call and the geo retry, plus every older row on the same exit.
    const isCurrentVisit = index === 0;
    if (!isCurrentVisit && !(sameNetwork && visitIsIncomplete)) return visit;
    return {
      ...visit,
      publicIp: refreshedIp || visit.publicIp,
      city: hasUsableGeoValue(location.city) ? location.city : visit.city,
      region: hasUsableGeoValue(location.region) ? location.region : visit.region,
      country: hasUsableGeoValue(location.country) ? location.country : visit.country,
      latitude: location.latitude !== null ? location.latitude : visit.latitude,
      longitude: location.longitude !== null ? location.longitude : visit.longitude,
      isp: hasUsableGeoValue(location.isp) ? location.isp : visit.isp,
      org: hasUsableGeoValue(location.org) ? location.org : visit.org,
      asn: hasUsableGeoValue(location.asn) ? location.asn : visit.asn,
    };
  });

  return {
    ...response,
    location: { ...response.location, ...location },
    visitHistory,
  };
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
  const cleanIsp =
    isp && isp !== 'Unknown' && isp !== 'Unavailable' ? isp.trim() : 'Standard Network';
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
  'Standard Network': 'bg-slate-100 text-slate-600 border border-slate-200',
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
function smartSignalToRow(signal: SmartSignal, incognito?: IncognitoVerdict): SignalRowModel {
  // Incognito is the one tile whose raw server status must be mapped onto the canonical
  // verdict instead of echoed: a stale "Standard Window" status must never read
  // "Not detected" when the server's boolean says private. Every other signal keeps the
  // server's exact status/detail verbatim (including the bot's exact agent name).
  const verdict = signal.id === 'incognito' ? incognito : undefined;
  const statusLabel = verdict?.status ?? signal.status;
  const caption = verdict?.detail ?? signal.detail;
  // Mirror the same canonical verdict on the 0..10 axis (3 private / 0 normal). The server
  // grid already carries these values; this only heals a stale mirror.
  const riskScore = verdict ? (verdict.isIncognito ? 3 : 0) : signal.scoreOutOf10;
  const riskLabel = verdict
    ? `${resolveSignalRiskTier(riskScore)} Risk • ${riskScore}/10`
    : signal.riskLabel;
  return {
    key: signal.id,
    dotClass: TONE_DOT_CLASS[toneForScore(riskScore)],
    title: signal.title,
    caption,
    statusLabel,
    tooltip: `${signal.title} • ${caption}`,
    riskScore,
    riskLabel,
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
 * Builds the 4-signal core grid strictly from the server-computed smart signals.
 *
 * Phase 7 single-truth rule: the client never recomputes a per-card score or a composite
 * score, and never force-overrides a server tile (the old incognito 4/10 override is gone).
 * When the Worker has not yet supplied the grid, each tile reports an honest
 * "Unavailable" state rather than a fabricated number.
 */
const UNAVAILABLE_CARD_TITLES = [
  'Incognito / Private Browsing',
  'Bot & Automation Detection',
  'VPN / Proxy & Network Type',
  'Virtual Machine & OS Integrity',
] as const;

/** Placeholder bot statuses that may be replaced by the server's exact agent name. */
const GENERIC_BOT_STATUSES = new Set([
  'not detected',
  'you are a bot',
  'unavailable',
  'detected',
  'verified crawler',
  'ai agent',
  'n/a',
  'none',
  'unknown',
  'false',
  'low-confidence soft signals',
  'soft signals',
  'weak signals',
  'heuristic',
]);

function buildSignalRows(
  serverSignals?: SmartSignals | null,
  exactBotName?: string | null,
  incognito?: IncognitoVerdict
): SignalRowModel[] {
  const rows: SignalRowModel[] = serverSignals
    ? [serverSignals.incognito, serverSignals.bot, serverSignals.vpn, serverSignals.vm].map(
        (signal) => smartSignalToRow(signal, incognito)
      )
    : UNAVAILABLE_CARD_TITLES.map((title) =>
        createSignalRow({
          key: title,
          tone: 'ok',
          title,
          caption: 'Awaiting canonical signal grid from the Worker',
          statusLabel: 'Unavailable',
          tooltip: 'Server-computed signal grid not present in this response',
          riskScore: 0,
          riskLabel: 'Unavailable',
        })
      );

  // Mirror the server's canonical bot status verbatim. When the server explicitly says there is
  // no bot, keep `Not detected` / `Verified Human` — never let a stale name replace it with a
  // stealth label. `smartSignalToRow` already prints server statuses exactly; only a genuinely
  // generic placeholder may be replaced by the exact agent name.
  const serverBotStatus = (serverSignals?.bot?.status ?? '').trim().toLowerCase();
  const serverSaysNoBot =
    Boolean(serverSignals) &&
    (/^(not detected|verified human|no bot|none|false|unknown|unavailable|n\/a)$/.test(
      serverBotStatus
    ) ||
      /^not detected\b/.test(serverBotStatus));
  const name = exactBotName?.trim();
  const vagueName = /soft signals|low[- ]confidence|weak signals|heuristic|not detected/i.test(name || '');
  if (name && !vagueName && !serverSaysNoBot) {
    const index = rows.findIndex((row) => row.key === 'bot' || row.title === 'Bot & Automation Detection');
    if (index >= 0) {
      const row = rows[index];
      const generic =
        !row.statusLabel.trim() ||
        GENERIC_BOT_STATUSES.has(row.statusLabel.trim().toLowerCase()) ||
        /soft signals|low[- ]confidence|weak signals|heuristic/i.test(row.statusLabel);
      if (generic) {
        rows[index] = {
          ...row,
          statusLabel: name,
          caption:
            row.caption && !GENERIC_BOT_STATUSES.has(row.caption.trim().toLowerCase())
              ? `${row.caption} · ${name}`
              : name,
          tooltip: `${row.title} • ${name}`,
        };
      }
    }
  }
  return rows;
}

interface JsonTreeNodeProps {
  keyName?: string;
  propIndex?: number;
  value: unknown;
  isLast: boolean;
  depth?: number;
}

function JsonTreeNode({ keyName, propIndex, value, isLast, depth = 0 }: JsonTreeNodeProps) {
  const [isExpanded, setIsExpanded] = useState<boolean>(true);

  const prefix = (
    <>
      {keyName !== undefined && (
        <>
          <span style={{ color: '#E53935' }}>{JSON.stringify(keyName)}</span>
          <span style={{ color: '#9CA3AF' }}>: </span>
        </>
      )}
      {propIndex !== undefined && (
        <>
          <span style={{ color: '#808080' }}>{propIndex}</span>
          <span style={{ color: '#9CA3AF' }}>: </span>
        </>
      )}
    </>
  );

  const suffix = !isLast ? <span style={{ color: '#9CA3AF' }}>,</span> : null;

  if (value === null) {
    return (
      <div className="flex items-center min-h-[20px]">
        <span className="inline-block w-3.5 h-3.5 mr-1 shrink-0" aria-hidden="true" />
        {prefix}
        <span style={{ color: '#808080' }}>null</span>
        {suffix}
      </div>
    );
  }

  if (typeof value === 'boolean') {
    return (
      <div className="flex items-center min-h-[20px]">
        <span className="inline-block w-3.5 h-3.5 mr-1 shrink-0" aria-hidden="true" />
        {prefix}
        <span style={{ color: '#9333EA' }}>{String(value)}</span>
        {suffix}
      </div>
    );
  }

  if (typeof value === 'number') {
    return (
      <div className="flex items-center min-h-[20px]">
        <span className="inline-block w-3.5 h-3.5 mr-1 shrink-0" aria-hidden="true" />
        {prefix}
        <span style={{ color: '#4F46E5' }}>{String(value)}</span>
        {suffix}
      </div>
    );
  }

  if (typeof value === 'string') {
    return (
      <div className="flex items-center min-h-[20px]">
        <span className="inline-block w-3.5 h-3.5 mr-1 shrink-0" aria-hidden="true" />
        {prefix}
        <span style={{ color: '#16A34A' }}>{JSON.stringify(value)}</span>
        {suffix}
      </div>
    );
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return (
        <div className="flex items-center min-h-[20px]">
          <span className="inline-block w-3.5 h-3.5 mr-1 shrink-0" aria-hidden="true" />
          {prefix}
          <span style={{ color: '#374151' }}>[]</span>
          {suffix}
        </div>
      );
    }

    return (
      <div>
        <div className="flex items-center min-h-[20px]">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setIsExpanded(!isExpanded);
            }}
            className="inline-flex items-center justify-center w-3.5 h-3.5 mr-1 text-slate-400 hover:text-slate-700 cursor-pointer select-none shrink-0"
            aria-label={isExpanded ? 'Collapse array' : 'Expand array'}
          >
            <ChevronRight
              className={`w-3 h-3 transition-transform duration-150 ${isExpanded ? 'rotate-90' : ''}`}
            />
          </button>
          {prefix}
          {isExpanded ? (
            <span style={{ color: '#374151' }}>[</span>
          ) : (
            <span
              onClick={(e) => {
                e.stopPropagation();
                setIsExpanded(true);
              }}
              className="cursor-pointer select-none"
              style={{ color: '#374151' }}
            >
              […]
            </span>
          )}
          {!isExpanded && suffix}
        </div>
        {isExpanded && (
          <>
            <div className="pl-4">
              {value.map((item, idx) => (
                <JsonTreeNode
                  key={idx}
                  propIndex={idx}
                  value={item}
                  isLast={idx === value.length - 1}
                  depth={depth + 1}
                />
              ))}
            </div>
            <div className="flex items-center min-h-[20px]">
              <span className="inline-block w-3.5 h-3.5 mr-1 shrink-0" aria-hidden="true" />
              <span style={{ color: '#374151' }}>]</span>
              {suffix}
            </div>
          </>
        )}
      </div>
    );
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>);
    if (keys.length === 0) {
      return (
        <div className="flex items-center min-h-[20px]">
          <span className="inline-block w-3.5 h-3.5 mr-1 shrink-0" aria-hidden="true" />
          {prefix}
          <span style={{ color: '#374151' }}>{"{}"}</span>
          {suffix}
        </div>
      );
    }

    return (
      <div>
        <div className="flex items-center min-h-[20px]">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setIsExpanded(!isExpanded);
            }}
            className="inline-flex items-center justify-center w-3.5 h-3.5 mr-1 text-slate-400 hover:text-slate-700 cursor-pointer select-none shrink-0"
            aria-label={isExpanded ? 'Collapse object' : 'Expand object'}
          >
            <ChevronRight
              className={`w-3 h-3 transition-transform duration-150 ${isExpanded ? 'rotate-90' : ''}`}
            />
          </button>
          {prefix}
          {isExpanded ? (
            <span style={{ color: '#374151' }}>{"{"}</span>
          ) : (
            <span
              onClick={(e) => {
                e.stopPropagation();
                setIsExpanded(true);
              }}
              className="cursor-pointer select-none"
              style={{ color: '#374151' }}
            >
              {"{…}"}
            </span>
          )}
          {!isExpanded && suffix}
        </div>
        {isExpanded && (
          <>
            <div className="pl-4">
              {keys.map((k, idx) => (
                <JsonTreeNode
                  key={k}
                  keyName={k}
                  value={(value as Record<string, unknown>)[k]}
                  isLast={idx === keys.length - 1}
                  depth={depth + 1}
                />
              ))}
            </div>
            <div className="flex items-center min-h-[20px]">
              <span className="inline-block w-3.5 h-3.5 mr-1 shrink-0" aria-hidden="true" />
              <span style={{ color: '#374151' }}>{"}"}</span>
              {suffix}
            </div>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="flex items-center min-h-[20px]">
      <span className="inline-block w-3.5 h-3.5 mr-1 shrink-0" aria-hidden="true" />
      {prefix}
      <span style={{ color: '#808080' }}>{String(value)}</span>
      {suffix}
    </div>
  );
}

function JsonPreview({ value }: { value: unknown }) {
  if (value === null || value === undefined) return null;
  return (
    <div className="font-mono text-[11px] leading-relaxed select-text">
      <JsonTreeNode value={value} isLast={true} depth={0} />
    </div>
  );
}

/**
 * Additive, console-only diagnostic hook. Inert unless `?intelDiag=1` is in the URL or
 * sessionStorage `intel_diag_v1` === '1'. When disabled it never touches `window` and never
 * captures response data. No UI, verdict, or network behaviour depends on this.
 */
const INTEL_DIAG_STORAGE_KEY = 'intel_diag_v1';

function isIntelDiagEnabled(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    if (new URLSearchParams(window.location.search).get('intelDiag') === '1') return true;
  } catch {
    // ignore malformed location
  }
  try {
    return window.sessionStorage.getItem(INTEL_DIAG_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

export default function App() {
  const [data, setData] = useState<IntelVisitorResponse | null>(null);
  // Server-rendered edge verdict. Pure fallback — it never seeds `data` or triggers a fetch.
  const [initialVerdict, setInitialVerdict] = useState(readInitialVerdict);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<boolean>(false);
  const [copiedHwId, setCopiedHwId] = useState<boolean>(false);
  const [selectedVisitIndex, setSelectedVisitIndex] = useState<number>(0);
  const [visibleVisitsCount, setVisibleVisitsCount] = useState<number>(5);
  const [copiedJson, setCopiedJson] = useState<boolean>(false);
  // Mobile primary-nav disclosure. The toggle is the only mobile affordance; focus moves to the
  // first link on open and returns to the button on Escape / link activation.
  const [mobileNavOpen, setMobileNavOpen] = useState<boolean>(false);
  const mobileNavButtonRef = useRef<HTMLButtonElement>(null);
  // Monotonic token: a newer load (or unmount) cancels any in-flight geo retry loop.
  const geoPollToken = useRef(0);
  // Flag-gated console diagnostics: the latest identify response's `diagnostics` object.
  // A ref so capturing it never re-renders the dashboard.
  const diagRef = useRef<unknown>(null);

  // Swiss light mode is the only theme: strip any legacy class before the first paint.
  useLayoutEffect(enforceLightTheme, []);

  /**
   * Retries ISP + location until the server has an exact answer.
   *
   * The first identify can land before a rate-limited provider answers, so the tiles
   * briefly show "Unavailable"/"Standard Network". This loop asks the dedicated
   * `/api/intel/geolocation` endpoint (which never replays an incomplete cache entry)
   * with backoff and merges every improvement into the existing view — no new visit is
   * recorded and the counters do not move.
   */
  const pollGeolocation = useCallback(async (visitorId: string, token: number) => {
    const delaysMs = [800, 1500, 2500, 4000, 6000, 9000, 12000, 15000, 20000, 30000, 30000];
    for (const delay of delaysMs) {
      await new Promise((resolve) => setTimeout(resolve, delay));
      if (geoPollToken.current !== token) return;
      try {
        const response = await fetch('/api/intel/geolocation', {
          method: 'GET',
          cache: 'no-store',
          credentials: 'same-origin',
          headers: { Accept: 'application/json' },
        });
        if (!response.ok) continue;
        const payload = (await response.json()) as {
          location?: LocationInfo;
          resolved?: boolean;
        };
        if (!payload?.location || geoPollToken.current !== token) continue;
        setData((previous) => {
          if (!previous || previous.visitorId !== visitorId) return previous;
          return mergeLocationIntoResponse(previous, payload.location as LocationInfo);
        });
        if (payload.resolved) return;
      } catch {
        // Offline / server hiccup: the next backoff step retries.
      }
    }
  }, []);

  const loadVisitorData = useCallback(
    async (manualRefresh = false) => {
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

        // Additive diagnostic capture: only when the flag is on. Reads the `diagnostics`
        // object off the response we already received; no extra calls or re-renders.
        if (isIntelDiagEnabled()) {
          diagRef.current =
            (response as IntelVisitorResponse & { diagnostics?: unknown }).diagnostics ?? null;
        }

        const token = geoPollToken.current + 1;
        geoPollToken.current = token;
        // Only a request the server could tie to a public IP can ever resolve; on a
        // private/LAN origin (local dev) polling would just repeat the same answer.
        if (response.location.isIpVerified && !isLocationComplete(response.location)) {
          void pollGeolocation(response.visitorId, token);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unable to load visitor intelligence data.');
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [pollGeolocation]
  );

  useEffect(() => {
    return () => {
      // Invalidate any retry loop still waiting on its backoff timer.
      geoPollToken.current += 1;
    };
  }, []);

  useEffect(() => {
    // Start the module-cached storage-physics probe before any network panel mounts,
    // so its main-thread timing is not skewed. Never blocks rendering.
    void detectIncognitoMode();
    loadVisitorData(false);
  }, [loadVisitorData]);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const firstLink = document
      .getElementById('primary-navigation')
      ?.querySelector<HTMLAnchorElement>('a');
    firstLink?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMobileNavOpen(false);
        mobileNavButtonRef.current?.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [mobileNavOpen]);

  useEffect(() => {
    // Expose the read-only console helper only when flagged. The closure reads the ref at
    // call time, so it always returns the most recent identify diagnostics (or null).
    if (!isIntelDiagEnabled()) return;
    (window as unknown as { __intelDiag?: () => unknown }).__intelDiag = () => diagRef.current;
  }, []);

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

  // Degraded responses can omit history entirely (for example when the Durable Object store
  // is unavailable). Synthesize the current page load so the map, location tiles and session
  // summary still render instead of disappearing.
  const visits: VisitHistoryRecord[] = data
    ? data.visitHistory.length > 0
      ? data.visitHistory
      : [
          {
            id: 0,
            visitId: 'current',
            visitorId: data.visitorId,
            sessionId: data.statistics.currentSessionId,
            visitedAtUtc: data.statistics.lastVisitUtc,
            publicIp: data.location.publicIp,
            city: data.location.city,
            region: data.location.region,
            country: data.location.country,
            latitude: data.location.latitude,
            longitude: data.location.longitude,
            isp: data.location.isp,
            org: data.location.org,
            asn: data.location.asn,
            browser: data.browserDevice.browser,
            os: data.browserDevice.os,
            deviceType: data.browserDevice.deviceType,
            screenResolution: data.browserDevice.screenResolution,
            language: data.browserDevice.language,
            timezone: data.browserDevice.timezone,
            suspectScore: data.suspectScore,
            // Server-provided history score is echoed verbatim — no client rescoring.
            score10: data.suspectScore,
            riskLevel: data.riskLevel,
            recognitionSource: data.recognitionSource,
          },
        ]
    : [];
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

  const swiftShader = isSwiftShader(data?.hardwareSignals?.gpuRenderer);
  const rawGpuRenderer = data?.hardwareSignals?.gpuRenderer;
  // A real, unmasked WebGL renderer is the GPU line's single source of truth. Masked /
  // unavailable placeholders are never printed as if they were a measured renderer, and the
  // VM tile's software/masked verdict never overwrites an actual reported renderer.
  const hasUnmaskedGpuRenderer =
    typeof rawGpuRenderer === 'string' &&
    rawGpuRenderer.trim() !== '' &&
    !/masked|unavailable|unknown|not available|n\/a/i.test(rawGpuRenderer.trim());
  const cleanGpuName = !data?.hardwareSignals
    ? 'Standard GPU'
    : hasUnmaskedGpuRenderer
    ? (rawGpuRenderer as string).trim()
    : swiftShader
    ? SWIFTSHADER_LABEL
    : formatCleanGpuName(rawGpuRenderer, data.hardwareSignals.gpuVendor);
  const rawGpuTooltip = data?.hardwareSignals && hasUnmaskedGpuRenderer
    ? `${data.hardwareSignals.gpuVendor} • ${(rawGpuRenderer as string).trim()}`
    : '';
  // Anti-spoof integrity. A "Spoofed / Unverified" tag or a raw-attribute quarantine is only
  // honest when the SERVER has authoritatively declared the session tampered. Stealth / bot
  // artifacts are never enough on their own — a clean device must keep its real attributes.
  const tamperingMlScore = data?.securitySignals?.tamperingMlScore;
  // The single canonical envelope. Every panel and the Event JSON below read this object —
  // no client code recomputes a composite score, tier, verdict or quarantine decision.
  const canonical = useMemo(() => resolveCanonical(data), [data]);
  // The server's canonical bot tile is authoritative for "is this a bot". When it explicitly
  // reports no bot, stale bot_type / bot_info mirrors must never resurrect a stealth label in
  // the banner, the cursor pill or the Event JSON.
  const serverBotTile = data?.smartSignals?.bot ?? data?.securitySignals?.smartSignals?.bot ?? null;
  const serverBotStatus = (serverBotTile?.status ?? '').trim().toLowerCase();
  const serverSaysNoBot =
    Boolean(serverBotTile) &&
    (/^(not detected|verified human|no bot|none|false|unknown|unavailable|n\/a)$/.test(
      serverBotStatus
    ) ||
      /^not detected\b/.test(serverBotStatus));
  // One server-authoritative automation label. The semantic bot_type (mirrored into the
  // canonical envelope) outranks any stale aiAgent / Gemini field, so the cursor pill, the
  // attribution banner and the Event JSON can never disagree or name a stealth session as a
  // signed cloud agent.
  // The edge verdict is a fallback for the bot_type before the API response lands.
  const displayBotType = serverSaysNoBot
    ? null
    : data?.bot_type ?? initialVerdict?.botType ?? canonical.automation?.bot_type ?? null;
  // Exact agent name from the Worker's edge verdict (or the server's own bot_info). Never a
  // stale aiAgent fallback — a verdict, once present, is authoritative for the name.
  const exactBotName = serverSaysNoBot
    ? null
    : initialVerdict?.name ?? data?.bot_info?.name ?? null;
  const automationDisplayLabel = resolveAutomationLabel(displayBotType);

  // Quarantine gate: server-authoritative tampering AND explicit spoof evidence. Stealth /
  // bot signals are deliberately excluded — they do not prove the JS getters were patched.
  const smartTampering = (data?.smartSignals as { tampering?: boolean } | undefined)?.tampering;
  const serverTampering =
    typeof smartTampering === 'boolean' ? smartTampering : data?.tampering === true;
  const explicitSpoofEvidence = Boolean(
    data?.tamperingDetails?.anti_detect_browser ||
      data?.tamperingDetails?.devtools_device_emulation ||
      (typeof tamperingMlScore === 'number' && tamperingMlScore >= 0.8) ||
      canonical.tampering?.anti_detect_browser ||
      canonical.tampering?.hard_spec_violation
  );
  const spoofedSpecs = Boolean(serverTampering && explicitSpoofEvidence);
  const spoofedSpecTag = spoofedSpecs ? ' (Spoofed / Unverified)' : '';

  // A browser-vs-IP timezone gap is a NETWORK context signal, never a JS lie. Keep the raw
  // browser timezone visible and annotate the discrepancy on the network axis only.
  const browserTimezoneLabel = data?.browserDevice?.timezone || 'Unavailable';
  const ipTimezoneLabel =
    typeof data?.securitySignals?.ipTimezone === 'string' &&
    data.securitySignals.ipTimezone &&
    data.securitySignals.ipTimezone !== 'Unavailable'
      ? data.securitySignals.ipTimezone
      : null;
  // The ONLY honest mismatch flag is the server's canonical `timezone_mismatch`. A raw
  // browser-vs-IP string compare is deliberately gone: benign IANA aliases such as
  // Asia/Calcutta vs Asia/Kolkata (or an unknown IP zone) must never light up this note.
  const timezoneMismatchContextual =
    typeof canonical.timezoneMismatchCanonical === 'boolean'
      ? canonical.timezoneMismatchCanonical
      : Boolean(canonical.network?.timezone_mismatch);
  const timezoneMismatchVisible = timezoneMismatchContextual;

  const isCurrentVisit = selectedVisitIndex === 0;

  // OS truth: the runtime hardware probe outranks UA-CH / navigator claims. Two independent
  // runtime signals (hostOs + GPU backend) must agree before any "(verified)" suffix is used.
  const hardwareTruth = data?.hardwareSignals as unknown as Record<string, unknown> | undefined;
  const osUaMismatch = Boolean(hardwareTruth?.osUaMismatch);
  const runtimeOsLabel = mapRuntimeOs(hardwareTruth?.hostOs);
  const gpuOsHint = osHintFromGpuRenderer(data?.hardwareSignals?.gpuRenderer);
  const runtimeOsCorroborated =
    runtimeOsLabel !== null && gpuOsHint !== null && runtimeOsLabel === gpuOsHint && !osUaMismatch;

  // Server-verified UA-CH identity for the current session. Kept only as a fallback when the
  // runtime probe cannot name an OS — and never with a "(verified)" suffix of its own.
  const serverBrowserDetails = data?.browser_details;
  const currentBrowserLabel = serverBrowserDetails
    ? [
        serverBrowserDetails.browser_name,
        serverBrowserDetails.browser_full_version !== serverBrowserDetails.browser_name
          ? serverBrowserDetails.browser_full_version
          : '',
      ]
        .filter(Boolean)
        .join(' ')
        .trim()
    : '';
  const currentOsLabel = stripVerifiedSuffix(
    serverBrowserDetails
      ? [serverBrowserDetails.os, serverBrowserDetails.os_version].filter(Boolean).join(' ').trim()
      : ''
  );
  // A past visit keeps its own recorded OS; the current visit's claim comes from UA-CH/JS.
  const claimedOsRaw = isCurrentVisit
    ? currentOsLabel || data?.browserDevice.os || ''
    : activeVisit?.os || data?.browserDevice.os || '';
  const claimedOsFamily =
    mapRuntimeOs(claimedOsRaw) ||
    (/iphone|ipad|ipod|\bios\b/i.test(claimedOsRaw)
      ? 'iOS'
      : /android/i.test(claimedOsRaw)
      ? 'Android'
      : /mac/i.test(claimedOsRaw)
      ? 'macOS'
      : /win/i.test(claimedOsRaw)
      ? 'Windows'
      : /linux/i.test(claimedOsRaw)
      ? 'Linux'
      : null);
  // The nan-sign-bit host-OS/architecture probe is buggy on genuine Linux, so the spoofed-OS
  // badge is deliberately conservative: it needs the silicon arch mismatch AND a second,
  // independent runtime witness. A WebGL backend that contradicts the claimed OS, a verified
  // DevTools device-emulation preset, or an OS-vs-engine contradiction each qualify. An
  // unknown/software hostOs never earns the badge, and a math-ULP mismatch alone never does.
  const rawEngineFamily =
    typeof hardwareTruth?.engine === 'string' ? hardwareTruth.engine.trim().toLowerCase() : '';
  const engineFamily = /chrom|v8|blink/.test(rawEngineFamily)
    ? 'chromium'
    : /webkit|javascriptcore|\bjsc\b/.test(rawEngineFamily)
    ? 'webkit'
    : /firefox|spidermonkey|gecko/.test(rawEngineFamily)
    ? 'firefox'
    : '';
  const osVsEngineContradiction =
    (engineFamily === 'chromium' && claimedOsFamily === 'iOS') ||
    (engineFamily === 'webkit' &&
      (claimedOsFamily === 'Windows' || claimedOsFamily === 'Linux')) ||
    (engineFamily === 'firefox' && claimedOsFamily === 'iOS');
  const gpuContradictsClaim =
    Boolean(gpuOsHint && claimedOsFamily && gpuOsHint !== claimedOsFamily);
  const independentOsProof =
    gpuContradictsClaim ||
    Boolean(data?.tamperingDetails?.devtools_device_emulation) ||
    osVsEngineContradiction;
  const spoofedOsEligible =
    isCurrentVisit &&
    runtimeOsLabel !== null &&
    Boolean(hardwareTruth?.archUaMismatch) &&
    independentOsProof;
  const spoofedOsClaim = spoofedOsEligible ? stripVerifiedSuffix(claimedOsRaw) : '';
  const spoofedOsBlocked = Boolean(spoofedOsClaim && spoofedOsClaim !== 'Unavailable');

  const serverOsLabel = stripVerifiedSuffix(
    isCurrentVisit && currentOsLabel
      ? currentOsLabel
      : activeVisit?.os || data?.browserDevice.os || 'Unavailable'
  );
  const displayOs = runtimeOsLabel
    ? `${runtimeOsLabel}${runtimeOsCorroborated ? ' (verified)' : ''}`
    : serverOsLabel;
  const displayBrowser =
    isCurrentVisit && currentBrowserLabel
      ? currentBrowserLabel
      : activeVisit?.browser || data?.browserDevice.browser || 'Unavailable';
  // Only annotate the tiles when the current session actually shows tampering / stealth
  // evidence — on a clean session the server-verified value is the unremarkable default.
  const showServerVerifiedNote = Boolean(
    isCurrentVisit &&
      (data?.tampering ||
        data?.securitySignals?.tampering ||
        data?.securitySignals?.stealthPluginDetected ||
        data?.tamperingDetails?.anti_detect_browser ||
        data?.tamperingDetails?.devtools_device_emulation ||
        (typeof tamperingMlScore === 'number' && tamperingMlScore >= 0.8) ||
        canonical.tamperingReasons.length > 0)
  );

  // 4-signal core grid model (null-safe: renders only inside the data block). Only the
  // server-computed grid is displayed; a legacy response gets explicit unavailable tiles.
  const serverSmartSignals = data?.smartSignals ?? data?.securitySignals?.smartSignals ?? null;
  // One server-canonical incognito verdict feeds the core grid, the Smart Signals grid, the
  // title chip and the Event JSON, so none of those surfaces can disagree with the server.
  const incognitoVerdict = useMemo(() => resolveIncognitoVerdict(data), [data]);
  const signalRows = buildSignalRows(serverSmartSignals, exactBotName, incognitoVerdict);

  // The headline risk is the server-canonical 0..10 ledger value and its tier — never a
  // client-normalized legacy suspectScore. Tier vocabulary is Low / Elevated / High / Critical.
  type DisplayRiskTier = 'Low' | 'Elevated' | 'High' | 'Critical';
  const canonicalScore10Raw = canonical.riskScore10 as unknown as number | undefined;
  const displayedRiskScore10 =
    typeof canonicalScore10Raw === 'number' && Number.isFinite(canonicalScore10Raw)
      ? canonicalScore10Raw
      : 0;
  const canonicalTierRaw = canonical.riskTier as unknown as DisplayRiskTier | undefined;
  const riskTier: DisplayRiskTier =
    canonicalTierRaw === 'Elevated' ||
    canonicalTierRaw === 'High' ||
    canonicalTierRaw === 'Critical'
      ? canonicalTierRaw
      : 'Low';
  const riskIsHigh = riskTier === 'High' || riskTier === 'Critical';
  const riskIsElevated = riskTier === 'Elevated';
  const riskTone = riskIsHigh ? 'text-rose-700' : riskIsElevated ? 'text-amber-700' : 'text-emerald-700';
  const riskBadgeText = `${riskTier} Risk • ${displayedRiskScore10}/10`;

  // Whenever the canonical tampering axis reports reasons, the header must say so.
  const tamperingDetected = canonical.tamperingReasons.length > 0;

  // Cursor attribution pill: resolved from the first-party bot / agent verdicts. Human
  // visitors resolve to null, so the overlay never mounts for them.
  const cursorIdentity = resolveCursorIdentity({
    botSubtype: data?.securitySignals.botSubtype ?? null,
    isBot: Boolean(data?.securitySignals.isBot),
    // Server-authoritative semantic bot type outranks any stale aiAgent / Gemini claim.
    botType: displayBotType,
    agentId: data?.securitySignals.aiAgent?.agentId ?? initialVerdict?.botType ?? null,
    agentName: data?.securitySignals.aiAgent?.agentName ?? exactBotName ?? null,
    agentVerified: Boolean(data?.securitySignals.aiAgent?.verified),
    // The raw request UA is what the shared agent registry matches for exact pill labels.
    userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : null,
  });

  // ONE canonical inspector state feeds every CDP / DevTools surface. A bare CDP binding is
  // never "Developer Tools", and nothing ever claims a CDP attachment when the canonical
  // envelope says cdp_attached:false. No prose about an attachment is rendered in the UI.
  const canonicalInspectorState = canonical.inspectorState ?? null;
  const canonicalCdpAttached =
    typeof canonical.cdpAttached === 'boolean'
      ? canonical.cdpAttached
      : canonicalInspectorState === 'automation_protocol_attached';
  const canonicalDeveloperTools = canonicalInspectorState === 'devtools_active_verified';

  // API v4 event payload rendered by the bottom inspector. Built exclusively from live
  // first-party values: no invented signals, no third-party fraud labels.
  // Browser/OS fields come from the shared UA-CH normalizer so `os` is always the
  // family ('Windows'), `os_version` the version ('11'), and `browser_major_version`
  // never empty — the previous assembly wrote the display string into `os`,
  // navigator.platform into `os_version`, and regexed the browser name into an
  // empty major version.
  const eventJson = useMemo(() => {
    if (!data) return null;
    const s = data.securitySignals;
    // Only a server-supplied ML score is ever published — never a hard-coded baseline.
    const serverTamperingMl =
      typeof canonical.tampering?.tampering_ml_score === 'number'
        ? canonical.tampering.tampering_ml_score
        : typeof s.tamperingMlScore === 'number'
        ? s.tamperingMlScore
        : null;
    // Edge verdict fallback: a named agent is authoritative, so no stale aiAgent value may
    // ever supply bot / bot_type / bot_info once one of these verdict fields exists.
    const eventBotType = data.bot_type ?? initialVerdict?.botType ?? null;
    const eventBotIdentity =
      initialVerdict?.identity === 'verified' ||
      initialVerdict?.identity === 'signed' ||
      initialVerdict?.identity === 'spoofed'
        ? initialVerdict.identity
        : 'unknown';
    // One bot_info object feeds both the JSON and the verdict-tier sanitizer, so a named but
    // unverified agent can never be printed next to a "Verified Automation" tier.
    const eventBotInfo = automationDisplayLabel
      ? {
          category: 'browser_automation',
          provider: data.bot_info?.provider ?? initialVerdict?.provider ?? 'Unknown',
          name: automationDisplayLabel,
          identity: 'unknown',
        }
      : exactBotName
      ? {
          category: data.bot_info?.category ?? eventBotType ?? 'crawler',
          provider: data.bot_info?.provider ?? initialVerdict?.provider ?? 'Unknown',
          name: exactBotName,
          identity: data.bot_info?.identity ?? eventBotIdentity,
        }
      : s.aiAgent?.detected
      ? {
          category: 'ai_agent',
          provider: s.aiAgent.operator || 'Unknown',
          name: s.aiAgent.agentName,
          identity: s.aiAgent.verified ? 'verified' : 'unknown',
        }
      : null;
    const eventVerdictTier = sanitizeVerdictTier(canonical.verdictTier, eventBotInfo?.identity);
    const vmVerdict = resolveVmVerdict(data);
    // Optional silicon-truth fields are additive: older responses simply omit them.
    const hw = (data.hardwareSignals ?? {}) as unknown as Record<string, unknown>;
    // Canonical network identity is derived only from server-side IP geolocation and the
    // server's ISP classification. The JS `browserDevice` object is spoofable and must never
    // leak into `ip_info` (it used to print a browser timezone inside `geolocation.timezone`).
    const ipGeoTimezone =
      typeof s.ipTimezone === 'string' && s.ipTimezone && s.ipTimezone !== 'Unavailable'
        ? s.ipTimezone
        : null;
    const asnName = s.brandName && s.brandName !== 'Unavailable' ? s.brandName : data.location.org;
    // A commercial VPN egress is not a hosting verdict: the server keeps `datacenterAsn` for
    // any VPN-or-hosting network, so the public-VPN verdict must explicitly win here.
    const publicVpn = Boolean(
      s.publicVpn || s.vpnMethods?.public_vpn || s.networkType === 'VPN / Proxy Relay'
    );
    const isHostingNetwork = Boolean(s.datacenterAsn ?? s.isDatacenterOrHosting) && !publicVpn;
    const firstVisitMs = Date.parse(data.visitHistory[0]?.visitedAtUtc || '') || Date.now();
    const deviceType = data.browserDevice.deviceType;
    const activeCallSupported = Boolean(data.activeCallSupported ?? s.activeCallSupported);
    const fallbackIdentity = normalizeIdentity({
      userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
      platform: typeof navigator !== 'undefined' ? navigator.platform : '',
      maxTouchPoints: typeof navigator !== 'undefined' ? navigator.maxTouchPoints : 0,
    });
    // The server normalizer saw the request's own `Sec-CH-UA*` headers, so its
    // `browser_details` outranks the client-side UA regexes when present.
    const uaIdentity = {
      os: data.browser_details?.os || fallbackIdentity.os,
      os_version: data.browser_details?.os_version ?? fallbackIdentity.os_version,
      browser_name: data.browser_details?.browser_name || fallbackIdentity.browser_name,
      browser_major_version:
        data.browser_details?.browser_major_version || fallbackIdentity.browser_major_version,
      browser_full_version:
        data.browser_details?.browser_full_version || fallbackIdentity.browser_full_version,
    };
    const osName = uaIdentity.os;
    const osVersion = uaIdentity.os_version;
    const rawAttributes =
      data.rawDeviceAttributes ?? (s as { rawDeviceAttributes?: unknown }).rawDeviceAttributes ?? null;
    const rawRecord =
      rawAttributes && typeof rawAttributes === 'object' && !Array.isArray(rawAttributes)
        ? (rawAttributes as Record<string, unknown>)
        : {};
    const pickClaim = (...keys: string[]): unknown => {
      for (const key of keys) {
        const value = rawRecord[key];
        if (value !== undefined && value !== null && value !== '') return value;
      }
      return null;
    };
    const claimedBrowser = data.browserDevice?.browser ?? null;
    const claimedTimezone =
      data.browserDevice?.timezone ?? pickClaim('timezone', 'browser_timezone');
    const claimedFont = pickClaim('fonts', 'font', 'font_family');
    const claimedCanvas = pickClaim('canvas', 'canvas_hash');
    const claimedWebgl =
      pickClaim('webgl', 'webgl_renderer', 'gpu_renderer') ?? data.hardwareSignals?.gpuRenderer ?? null;
    const phoneDetails =
      data.browserDevice.genuineMobile && data.browserDevice.phoneModel
        ? {
            device_model: data.browserDevice.phoneModel,
            device_model_code: data.browserDevice.phoneModelCode ?? null,
            device_brand: data.browserDevice.phoneBrand ?? null,
            device_code: data.browserDevice.phoneDeviceCode ?? null,
          }
        : {};
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
          { name: 'intel-system-cloudflare-worker', version: '2.1.0' },
          { name: 'intel-system-react', version: '19.0.0' },
        ],
      },
      replayed: Boolean(s.replayDetected),
      identification: {
        visitor_id: data.visitorId,
        hardware_id: data.hardwareId,
        // Silicon-grounded truth. A UA/UA-CH architecture is only ever a claim; the hardware
        // anchor comes from the runtime probe and arch_ua_mismatch records a disagreement.
        hardware_arch: hw.architecture ?? null,
        hardware_arch_source: hw.architectureSource ?? null,
        claimed_arch: hw.claimedArchitecture ?? null,
        arch_ua_mismatch: Boolean(hw.archUaMismatch),
        host_os: hw.hostOs ?? null,
        engine: hw.engine ?? null,
        canvas_noise: Boolean(hw.canvasNoise),
        audio_noise: Boolean(hw.audioNoise),
        canvas_coarse_hash: hw.canvasCoarseHash ?? null,
        // Categorical tier only; no numeric confidence is invented on the client and an
        // unseen profile keeps confidence_score null.
        confidence: {
          score: canonical.confidenceScore,
          tier: canonical.confidenceTier,
          calibration_status: canonical.calibrationStatus,
        },
        visitor_found: data.identification?.visitor_found ?? data.isReturning,
        recognition_mode:
          s.persistenceMode === 'Hardware ID Recovered'
            ? 'Hardware ID Recovered'
            : data.recognitionSource,
        first_seen_at: Date.parse(data.statistics.firstVisitUtc) || null,
        last_seen_at: Date.parse(data.statistics.lastVisitUtc) || null,
      },
      url: typeof window !== 'undefined' ? window.location.href : '',
      ip_address: data.location.publicIp,
      user_agent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
      device: deviceType,
      os: osName,
      os_version: osVersion,
      browser_details: {
        browser_name: uaIdentity.browser_name || data.browserDevice.browser,
        browser_major_version: uaIdentity.browser_major_version,
        browser_full_version: uaIdentity.browser_full_version || data.browserDevice.browser,
        os: osName,
        os_version: osVersion,
        device: deviceType,
        ...phoneDetails,
      },
      // Only report call state when the runtime can actually observe it — never print a
      // fabricated "unavailable" capability as if it were a measured signal.
      ...(activeCallSupported ? { active_call: Boolean(data.activeCall ?? s.activeCall) } : {}),
      // `isBot` and `bot` are one source of truth on the server. The fallback mirrors the same
      // derivation so a legacy response can never print bot:"not_detected" next to isBot:true.
      bot:
        data.bot ??
        (exactBotName
          ? eventBotIdentity === 'spoofed'
            ? 'bad'
            : 'good'
          : Boolean(s.isBot) || s.botSubtype === 'bad_bot' || s.botSubtype === 'ai_agent'
          ? 'bad'
          : 'not_detected'),
      // Mirror the authoritative bot_type verbatim. The edge verdict fills in when the API
      // response has not supplied one; no stale aiAgent field is consulted after that.
      bot_type: eventBotType,
      bot_info: eventBotInfo,
      // Developer tools = a real docked DevTools UI / IDE webview, proved ONLY by the
      // canonical envelope's inspector_state. A bare CDP binding / cdpRuntimeLeak /
      // automation_protocol_attached is reported separately and never sets this true.
      developer_tools: canonicalDeveloperTools,
      cdp_attached: canonicalCdpAttached,
      inspector_state: canonicalInspectorState,
      automation_environment: s.automationEnvironment ?? 'none',
      human_corroboration: canonical.humanCorroboration,
      ip_blocklist: {
        // Omit email_spam entirely unless the server actually classified it.
        ...(typeof (s as { emailSpam?: boolean }).emailSpam === 'boolean'
          ? { email_spam: (s as { emailSpam?: boolean }).emailSpam as boolean }
          : {}),
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
            // Server IP-geolocation timezone only — never `browserDevice.timezone`, which is
            // client-controlled and made a Singapore egress print "Asia/Calcutta" in ip_info.
            timezone: ipGeoTimezone,
            city_name: data.location.city,
            country_code: data.location.countryCode,
            country_name: data.location.country,
            subdivisions: data.location.region ? [{ name: data.location.region }] : [],
          },
          asn: data.location.asn,
          // Prefer the server-classified retail brand over the raw geo-provider org string.
          asn_name: asnName,
          asn_type: isHostingNetwork ? 'hosting' : 'isp',
          // Hosting/datacenter ASNs only. A commercial VPN (public_vpn) is not a datacenter.
          datacenter_result: isHostingNetwork,
        },
      },
      proxy: Boolean(canonical?.network?.proxy ?? (s as unknown as { proxyDetected?: boolean }).proxyDetected ?? false),
      proxy_confidence: canonical?.network?.proxy ? 'high' : 'low',
      incognito: incognitoVerdict.isIncognito,
      // Human-only copy in the Event JSON: no IDB ratios / fail-open / raw method strings.
      incognito_status: incognitoVerdict.status,
      incognito_confidence:
        (s as { incognitoConfidence?: 'high' | 'low' }).incognitoConfidence ?? null,
      privacy_settings: Boolean(
        (s as { privacySettings?: boolean }).privacySettings || s.isTorBrowserClient
      ),
      simulator: Boolean(s.emulatorDetected),
      suspect_score: displayedRiskScore10,
      // The complete canonical risk ledger: 0..100 composite, the 0..10 headline and its tier
      // mirrored verbatim from the server, plus every evidence line. Nothing is recomputed.
      risk_ledger: {
        score_0_100: canonical.risk.score_0_100,
        score10: displayedRiskScore10,
        risk_tier: riskTier,
        evidence_ledger: canonical.risk.evidence_ledger,
      },
      // Mirrors the same server-canonical verdict the Virtual Machine tile renders.
      virtual_machine: vmVerdict.state === 'vm',
      tampering: Boolean(data.tampering ?? s.tampering),
      tampering_confidence: data.tamperingConfidence ?? 'high',
      // Published only when the server measured it — no fabricated 0.0024 fallback.
      ...(serverTamperingMl !== null ? { tampering_ml_score: serverTamperingMl } : {}),
      // No fabricated zero/false detail object for a response that never supplied one.
      ...(data.tamperingDetails ? { tampering_details: data.tamperingDetails } : {}),
      velocity: data.velocity ?? null,
      vpn: Boolean(s.vpnSuspected),
      vpn_confidence: s.vpnSuspected ? 'high' : 'low',
      // Server-authoritative method object: the grid tile count is derived from this exact
      // object, so the subtitle can never disagree with #raw-json.
      vpn_methods: {
        // Canonical server timezone_mismatch only; the legacy raw browser/IP compare is gone.
        timezone_mismatch: Boolean(canonical.network?.timezone_mismatch ?? s.vpnMethods?.timezone_mismatch),
        public_vpn: Boolean(s.vpnMethods?.public_vpn),
        auxiliary_mobile: Boolean(s.vpnMethods?.auxiliary_mobile),
        os_mismatch: Boolean(s.vpnMethods?.os_mismatch ?? s.isOsTampered),
        relay: Boolean(s.vpnMethods?.relay ?? s.torExitNode),
        ml_prediction: Boolean(s.vpnMethods?.ml_prediction),
      },
      high_activity_device: Boolean(data.highActivityDevice ?? s.highActivityDevice),
      high_activity_threshold_mode:
        (data as { highActivityThresholdMode?: string }).highActivityThresholdMode ?? null,
      // Reconciled display: a spoofed / emulated OS claim is blocked and the verified host OS
      // is shown. No emulated iOS / Android value is ever presented as the underlying truth.
      reconciled_display: {
        // Same corrected OS the tiles show: runtime truth first, "(verified)" only when two
        // independent runtime signals agree and osUaMismatch is false.
        os: displayOs,
        claimed_os: spoofedOsBlocked ? spoofedOsClaim : null,
        spoofed_os_blocked: spoofedOsBlocked,
        os_source: runtimeOsLabel ? 'runtime_hardware' : 'server',
      },
      timezone_display: {
        browser: browserTimezoneLabel,
        ip_geo: ipTimezoneLabel,
        // Purely contextual: this is a browser-vs-IP network signal, never a VPN/spoof verdict.
        mismatch_contextual_only: timezoneMismatchVisible,
      },
      rare_device: Boolean(data.rareDevice ?? s.rareDevice),
      // No fabricated "<p95" bucket: publish only a server-supplied value.
      ...((data.rareDevicePercentileBucket ?? s.rareDevicePercentileBucket)
        ? {
            rare_device_percentile_bucket:
              data.rareDevicePercentileBucket ?? s.rareDevicePercentileBucket,
          }
        : {}),
      // Spoof quarantine: client-reported browser / font / canvas / WebGL claims are blocked
      // when the session is tampered. Timezone is NEVER quarantined here: a browser-vs-IP
      // timezone difference is a network-context axis (timezone_mismatch), not a JS lie.
      spoof_quarantine: spoofedSpecs
        ? {
            status: 'Quarantined - Tampered Session',
            client_claimed_browser: quarantineClaim(claimedBrowser, true),
            client_claimed_timezone: claimedTimezone,
            timezone_discrepancy:
              canonical.timezoneMismatchCanonical === true ? 'Detected' : 'Not detected',
            timezone_discrepancy_scope: 'network_axis_only',
            font: quarantineClaim(claimedFont, true),
            canvas: quarantineClaim(claimedCanvas, true),
            webgl: quarantineClaim(claimedWebgl, true),
            label: '[Unverified - Tampered Session]',
          }
        : { status: 'None' },
      raw_device_attributes: quarantineAttributes(
        { ...rawRecord, ...phoneDetails },
        spoofedSpecs
      ),
      // Everything below is the single canonical envelope, identical to the DOM panels.
      canonical: {
        source: canonical.source,
        event_id: canonical.eventId,
        verdict_tier: eventVerdictTier,
        browser_tampering: tamperingDetected ? 'Detected' : 'Not detected',
        human_corroboration: canonical.humanCorroboration,
        // All provenance fields, mirrored verbatim from the one canonical envelope.
        server_verified: canonical.serverVerified,
        client_claimed: canonical.clientClaimed,
        reconciled_display: canonical.reconciledDisplay,
        // Publish the raw server os_truth block ONLY when the server supplied that new block.
        // Never substitute stale automation-axis values here — absent means absent.
        ...(canonical.os_truth != null ? { os_truth: canonical.os_truth } : {}),
        verified_agent_id: canonical.verifiedAgentId ?? null,
        signature_status: canonical.signatureStatus ?? null,
        inspector_state: canonicalInspectorState,
        cdp_attached: canonicalCdpAttached,
        developer_tools: canonicalDeveloperTools,
        ...(canonical.gpuObservation != null
          ? { gpu_observation: canonical.gpuObservation }
          : {}),
        ...(canonical.renderer_reported_unverified != null
          ? { renderer_reported_unverified: canonical.renderer_reported_unverified }
          : {}),
        ...(canonical.build_sha != null ? { build_sha: canonical.build_sha } : {}),
        ...(canonical.worker_version != null ? { worker_version: canonical.worker_version } : {}),
        timezone_mismatch_canonical: canonical.timezoneMismatchCanonical ?? null,
        calibration_status: canonical.calibrationStatus,
        identity: {
          match_stage: canonical.identity?.match_stage ?? null,
          match_label: canonical.identity?.match_label ?? null,
          confidence_tier: canonical.confidenceTier,
          confidence_score: canonical.confidenceScore,
          calibration_status: canonical.calibrationStatus,
          ...(canonical.confidence_label != null
            ? { confidence_label: canonical.confidence_label }
            : {}),
        },
        network: {
          hosting_asn: (() => {
            const n = canonical.network;
            return n?.network_ownership === 'hosting_datacenter'
              ? `Hosting / Datacenter ASN${n.bgp_asn ? ` · ${n.bgp_asn}` : ''}${
                  n.bgp_asn_org ? ` · ${n.bgp_asn_org}` : ''
                }`
              : n?.bgp_asn
              ? `ASN ${n.bgp_asn}${n.bgp_asn_org ? ` · ${n.bgp_asn_org}` : ''}`
              : 'Unavailable';
          })(),
          rdap_netblock_org: canonical.network?.rdap_netblock_org ?? null,
          vpn_status: canonical.network?.vpn
            ? `VPN / relay detected (${canonical.network.vpn_confidence ?? 'low'} confidence)`
            : canonical.network?.vpn_confidence === 'high'
            ? 'No VPN detected (high confidence)'
            : 'No VPN detected (low confidence)',
          proxy_rotation: canonical.network?.proxy ? 'Detected' : 'Not detected',
          timezone_discrepancy:
            canonical.timezoneMismatchCanonical === true ? 'Detected' : 'Not detected',
        },
        // Mirror the server-canonical environment axes (client SwiftShader detection only
        // backfills legacy responses without them), so this never disagrees with the VM tile.
        software_renderer:
          canonical.environment?.software_renderer || swiftShader ? SWIFTSHADER_LABEL : null,
        // Same detail-free, server-resolved verdict the Virtual Machine tile shows. The raw
        // smartSignals.vm.detail is deliberately not reproduced: when the status is masked /
        // unavailable it can still claim a verified physical GPU and contradict the status.
        virtual_machine_label: vmVerdict.status,
      },
      // Tri-layer identity evidence from the server resolver + calibrated confidence v2.0.
      identity_layers: data.identity_layers ?? null,
      consistency: data.consistency ?? null,
      // Additive canonical truth mirrors — surfaced verbatim in this detail view only. Each
      // value is the single canonical envelope's pass-through (never re-derived or computed on
      // the client), so every extra field the server supplied — e.g.
      // `vpn_methods.latency_distance_mismatch`, a `proxy_details.proxy_type` of
      // `data_center`/`residential`, or the JA4H-style `network_layer_hash` — is preserved as-is.
      // A mirror the server did not supply stays absent (no fabricated empty object/false/zero),
      // and these spreads come last so a supplied mirror wins over any legacy flat fallback.
      ...(canonical.proxy_details != null ? { proxy_details: canonical.proxy_details } : {}),
      ...(canonical.vpn_methods != null ? { vpn_methods: canonical.vpn_methods } : {}),
      ...(canonical.privacy_settings != null
        ? { privacy_settings: canonical.privacy_settings }
        : {}),
      ...(canonical.stealth_ids != null ? { stealth_ids: canonical.stealth_ids } : {}),
      ...(canonical.tampering_details != null
        ? { tampering_details: canonical.tampering_details }
        : {}),
      ...(canonical.network_layer_hash != null
        ? { network_layer_hash: canonical.network_layer_hash }
        : {}),
      // Remaining additive truth / observation mirrors — published ONLY when the server
      // actually supplied them. Every value is the canonical envelope's verbatim pass-through;
      // no Boolean()/Number() coercion, no default and no client-side re-derivation is applied.
      ...(canonical.gpu_truth_state != null ? { gpu_truth_state: canonical.gpu_truth_state } : {}),
      ...(canonical.gpu_answer_unreliable != null
        ? { gpu_answer_unreliable: canonical.gpu_answer_unreliable }
        : {}),
      ...(canonical.headless_mode != null ? { headless_mode: canonical.headless_mode } : {}),
      ...(canonical.geolocationPermission != null
        ? { geolocationPermission: canonical.geolocationPermission }
        : {}),
      ...(canonical.grantedGeolocation != null
        ? { grantedGeolocation: canonical.grantedGeolocation }
        : {}),
      ...(canonical.accuracy_m != null ? { accuracy_m: canonical.accuracy_m } : {}),
      ...(canonical.privacy_signature_ids != null
        ? { privacy_signature_ids: canonical.privacy_signature_ids }
        : {}),
      ...(canonical.media_preferences != null
        ? { media_preferences: canonical.media_preferences }
        : {}),
      ...(canonical.active_cdp_inspection != null
        ? { active_cdp_inspection: canonical.active_cdp_inspection }
        : {}),
      ...(canonical.id_scope != null ? { id_scope: canonical.id_scope } : {}),
      ...(canonical.context_isolated != null
        ? { context_isolated: canonical.context_isolated }
        : {}),
      ...(canonical.audio_stability_class != null
        ? { audio_stability_class: canonical.audio_stability_class }
        : {}),
      ...(canonical.confidence_stability_key != null
        ? { confidence_stability_key: canonical.confidence_stability_key }
        : {}),
      // Read-only incognito diagnostics: the server's own diagnostic record, exposed verbatim
      // whenever it is present. Deliberately NOT gated on `intel_diag` / sessionStorage and not
      // a client-side session flag — nothing here is fabricated from the flag-gated hook.
      ...(canonical.diagnostics != null ? { diagnostics: canonical.diagnostics } : {}),
      // Additive research / calibration / verification mirrors — published verbatim and
      // only when the canonical envelope actually supplied them. No coercion, no default
      // and no client-side re-derivation; a WBA 'valid' is never inferred from presence.
      ...(canonical.calibration_evidence != null
        ? { calibration_evidence: canonical.calibration_evidence }
        : {}),
      ...(canonical.high_activity_threshold_mode != null
        ? { high_activity_threshold_mode: canonical.high_activity_threshold_mode }
        : {}),
      ...(canonical.high_activity_threshold != null
        ? { high_activity_threshold: canonical.high_activity_threshold }
        : {}),
      ...(canonical.wba_status != null ? { wba_status: canonical.wba_status } : {}),
      ...(canonical.official_bot_feed_match != null
        ? { official_bot_feed_match: canonical.official_bot_feed_match }
        : {}),
      ...(canonical.webgpu_research_disclosure != null
        ? { webgpu_research_disclosure: canonical.webgpu_research_disclosure }
        : {}),
      ...(canonical.benchmark_policy != null
        ? { benchmark_policy: canonical.benchmark_policy }
        : {}),
      // New server provenance / honesty mirrors — published verbatim and ONLY when present.
      // No coercion, no fabricated empty value, no client-side derivation.
      ...(canonical.renderer_reported_unverified != null
        ? { renderer_reported_unverified: canonical.renderer_reported_unverified }
        : {}),
      ...(canonical.build_sha != null ? { build_sha: canonical.build_sha } : {}),
      ...(canonical.worker_version != null ? { worker_version: canonical.worker_version } : {}),
      ...(canonical.confidence_label != null
        ? { confidence_label: canonical.confidence_label }
        : {}),
    };
  }, [
    data,
    incognitoVerdict,
    displayedRiskScore10,
    riskTier,
    canonical,
    canonicalInspectorState,
    canonicalCdpAttached,
    canonicalDeveloperTools,
    displayBotType,
    automationDisplayLabel,
    exactBotName,
    initialVerdict,
    displayOs,
    spoofedOsBlocked,
    spoofedOsClaim,
    runtimeOsLabel,
    timezoneMismatchVisible,
    spoofedSpecs,
    tamperingDetected,
    swiftShader,
  ]);

  // Tor / automation attribution surface above the Smart Signals grid. Agent identity is
  // named only from verified canonical automation proof — a network/ASN label (e.g. a cloud
  // provider) is network information and must never become an agent identity.
  const torExitDetected = Boolean(data?.securitySignals?.torExitNode);
  const torBrowserClient = Boolean(data?.securitySignals?.isTorBrowserClient);
  const canonicalAutomation = canonical.automation;
  const headlessAutomation =
    automationDisplayLabel === 'Headless Browser Automation' ||
    canonicalAutomation?.automation_environment === 'headless_shell';
  // A verified/named edge verdict is a valid banner reason even before (or without) an API
  // response; automation labels stay reserved for actual automation verdicts.
  const bannerVerdictName = !automationDisplayLabel ? exactBotName : null;
  const automationBannerLabel =
    automationDisplayLabel ??
    (headlessAutomation ? 'Headless Browser Automation' : null) ??
    bannerVerdictName;
  const automationOperator =
    canonicalAutomation &&
    canonicalAutomation.operator_verification_method !== 'none' &&
    canonicalAutomation.named_operator
      ? canonicalAutomation.named_operator
      : initialVerdict?.provider ?? 'unknown';
  const showAttributionBanner = Boolean(
    (data || initialVerdict) &&
      (torExitDetected || torBrowserClient || automationBannerLabel || bannerVerdictName)
  );

  return (
    <div className="bg-[#F4F5F7] text-[#111827] min-h-screen flex flex-col">
      {/* Focus ring and reduced-motion policy. Spatial motion is disabled while the final
          state is preserved; focus is always visible with a >=2px non-colour-only outline. */}
      <style>{`
        :where(a, button, [tabindex], summary):focus-visible {
          outline: 2px solid #0f172a;
          outline-offset: 2px;
        }
        @media (prefers-reduced-motion: reduce) {
          *, *::before, *::after {
            animation-duration: 0.01ms !important;
            animation-iteration-count: 1 !important;
            transition-duration: 0.01ms !important;
            scroll-behavior: auto !important;
          }
        }
      `}</style>
      {/* Skip link — the first focusable element on the page. */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-50 focus:rounded-md focus:border focus:border-slate-900 focus:bg-white focus:px-3 focus:py-2 focus:text-xs focus:font-semibold focus:text-slate-900"
      >
        Skip to main content
      </a>
      {/* Responsive Top Navigation Bar */}
      <header className="bg-white border-b border-[#E5E7EB] px-4 sm:px-6 py-3.5">
        <div className="relative max-w-7xl mx-auto flex items-center justify-between gap-4 sm:gap-8">
          <a
            href="#overview"
            className="text-base font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 font-display"
          >
            Intel System
          </a>

          <button
            ref={mobileNavButtonRef}
            type="button"
            aria-expanded={mobileNavOpen}
            aria-controls="primary-navigation"
            aria-label={mobileNavOpen ? 'Close navigation menu' : 'Open navigation menu'}
            onClick={() => setMobileNavOpen((open) => !open)}
            className="md:hidden inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-semibold text-slate-800"
          >
            <span aria-hidden="true">{mobileNavOpen ? '✕' : '☰'}</span>
            {mobileNavOpen ? 'Close' : 'Menu'}
          </button>

          <nav
            id="primary-navigation"
            aria-label="Primary navigation"
            className={`${
              mobileNavOpen
                ? 'absolute left-0 right-0 top-full z-40 flex flex-col gap-2 rounded-b-lg border border-slate-200 bg-white p-3 shadow-md'
                : 'hidden'
            } md:static md:z-auto md:flex md:flex-row md:items-center md:gap-6 md:border-0 md:bg-transparent md:p-0 md:shadow-none text-xs font-medium text-slate-600`}
          >
            <a
              href="#overview"
              onClick={() => setMobileNavOpen(false)}
              className="hover:text-slate-900 whitespace-nowrap shrink-0"
            >
              Visitor Dashboard
            </a>
            <a
              href="#signals"
              onClick={() => setMobileNavOpen(false)}
              className="hover:text-slate-900 whitespace-nowrap shrink-0"
            >
              Smart Signals
            </a>
            <a
              href="#diagnostics"
              onClick={() => setMobileNavOpen(false)}
              className="hover:text-slate-900 whitespace-nowrap shrink-0"
            >
              Network &amp; CPU
            </a>
            <a
              href="#history"
              onClick={() => setMobileNavOpen(false)}
              className="hover:text-slate-900 whitespace-nowrap shrink-0"
            >
              Visit History
            </a>
          </nav>

          {/* One primary CTA lives in the risk header ("Analyze my browser again"); no
              duplicate visit-recording button is rendered here. */}
        </div>
      </header>

      <main
        id="main-content"
        tabIndex={-1}
        className="flex-1 max-w-7xl w-full mx-auto px-3 sm:px-6 py-4 sm:py-7 space-y-6"
      >
        {/* Top-centered Risk Meter: 0-10 suspect score */}
        <section className="w-full max-w-2xl mx-auto flex flex-col items-center justify-center text-center pt-4 pb-2 px-4">
          <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold ${
                riskIsHigh
                  ? 'bg-[#FCE8E6] border-[#D93025]/40 text-[#D93025]'
                  : riskIsElevated
                  ? 'bg-[#FEF7E0] border-[#F9AB00]/50 text-[#B06000]'
                  : 'bg-[#E6F4EA] border-[#81C995] text-[#137333]'
              }`}
            >
              {riskIsHigh ? (
                <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
              ) : (
                <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
              )}
              {riskBadgeText}
            </span>
          </div>
          <div className="w-full max-w-md h-2.5 bg-slate-200 rounded-full overflow-hidden mt-3">
            <div
              className={`h-full transition-all duration-300 ${
                riskIsHigh
                  ? 'bg-[#D93025]'
                  : riskIsElevated
                  ? 'bg-[#F9AB00]'
                  : 'bg-[#81C995]'
              }`}
              style={{ width: `${Math.max(2, displayedRiskScore10 * 10)}%` }}
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
              <span>{refreshing ? 'Analyzing...' : 'Analyze my browser again'}</span>
            </button>
            <a
              href="#raw-json"
              className="text-xs font-medium text-slate-600 hover:text-slate-900 underline underline-offset-2"
            >
              View Event JSON
            </a>
          </div>
        </section>
        {/* Routine progress / errors are announced politely; role="alert" is reserved for
            time-sensitive interruptions and is deliberately not used here. */}
        <span role="status" aria-live="polite" className="sr-only">
          {refreshing ? 'Analyzing browser again' : loading && !data ? 'Loading visitor intelligence' : ''}
        </span>
        {error && (
          <div
            role="status"
            aria-live="polite"
            className="bg-white border border-red-300 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
          >
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
          <div className="space-y-6" role="status" aria-label="Loading device intelligence">
            {/* Overview: hero, map, location tiles, device summary */}
            <section className="bg-white rounded-2xl border border-[#E5E7EB] overflow-hidden">
              <div className="px-4 sm:px-7 py-5 border-b border-[#E5E7EB] flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="space-y-2 min-w-0">
                  <div className="skeleton-shimmer h-6 w-56 max-w-full rounded" />
                  <div className="skeleton-shimmer h-3 w-80 max-w-full rounded" />
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    <div className="skeleton-shimmer h-4 w-36 rounded-full" />
                    <div className="skeleton-shimmer h-4 w-28 rounded-full" />
                    <div className="skeleton-shimmer h-4 w-32 rounded-full" />
                  </div>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 w-full lg:w-auto lg:min-w-[520px]">
                  <div className="skeleton-shimmer h-14 rounded-xl" />
                  <div className="skeleton-shimmer h-14 rounded-xl" />
                </div>
              </div>

              <div className="flex flex-col lg:grid lg:grid-cols-2">
                <div className="border-b lg:border-b-0 lg:border-r border-[#E5E7EB] min-w-0">
                  <div className="px-4 sm:px-6 py-3 border-b border-[#E5E7EB] flex items-center justify-between gap-2">
                    <div className="skeleton-shimmer h-3 w-36 rounded" />
                    <div className="skeleton-shimmer h-3 w-24 rounded" />
                  </div>
                  <div className="skeleton-shimmer h-[215px] sm:h-[235px]" />
                  <div className="grid grid-cols-2">
                    {Array.from({ length: 4 }).map((_, index) => (
                      <div
                        key={`overview-tile-${index}`}
                        className="p-3.5 sm:px-5 border-b border-[#E5E7EB] odd:border-r space-y-2"
                      >
                        <div className="skeleton-shimmer h-2.5 w-16 rounded" />
                        <div className="skeleton-shimmer h-3.5 w-28 max-w-full rounded" />
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-4 sm:p-6">
                  <div className="skeleton-shimmer h-3 w-44 rounded" />
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 sm:gap-3 mt-4">
                    {Array.from({ length: 6 }).map((_, index) => (
                      <div
                        key={`summary-tile-${index}`}
                        className="skeleton-shimmer h-20 sm:h-24 rounded-xl"
                      />
                    ))}
                  </div>
                </div>
              </div>
            </section>

            {/* Hardware and rendering entropy */}
            <section className="bg-white border border-[#E5E7EB] rounded-2xl p-4 sm:p-6 space-y-4">
              <div className="flex items-center justify-between gap-3 pb-3.5 border-b border-[#E5E7EB]">
                <div className="skeleton-shimmer h-4 w-64 max-w-full rounded" />
                <div className="skeleton-shimmer h-3 w-24 rounded" />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {Array.from({ length: 6 }).map((_, index) => (
                  <div
                    key={`hardware-tile-${index}`}
                    className="skeleton-shimmer h-16 rounded-xl"
                  />
                ))}
              </div>
            </section>

            {/* Smart signals */}
            <section className="bg-white border border-[#E5E7EB] rounded-2xl p-4 sm:p-6 space-y-4">
              <div className="flex items-center justify-between gap-3 pb-3.5 border-b border-[#E5E7EB]">
                <div className="skeleton-shimmer h-4 w-52 max-w-full rounded" />
                <div className="skeleton-shimmer h-3 w-20 rounded" />
              </div>
              {/* The edge verdict is already known before the API responds: surface the exact
                  name in the Bot & Automation Detection area instead of a blank skeleton. */}
              {initialVerdict?.name && (
                <div className="text-[11px] font-mono text-slate-600 break-words">
                  Bot &amp; Automation Detection · {initialVerdict.name}
                </div>
              )}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
                {Array.from({ length: 8 }).map((_, index) => (
                  <div
                    key={`signal-tile-${index}`}
                    className="skeleton-shimmer h-24 rounded-xl"
                  />
                ))}
              </div>
            </section>

            {/* Diagnostics: network stability and CPU activity */}
            <section className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
              {Array.from({ length: 2 }).map((_, cardIndex) => (
                <div
                  key={`diagnostics-card-${cardIndex}`}
                  className="bg-white border border-[#E5E7EB] rounded-2xl p-4 sm:p-6 space-y-4"
                >
                  <div className="flex items-center justify-between gap-3 pb-3.5 border-b border-[#E5E7EB]">
                    <div className="skeleton-shimmer h-4 w-40 max-w-full rounded" />
                    <div className="skeleton-shimmer h-3 w-16 rounded" />
                  </div>
                  <div className="grid grid-cols-3 gap-3">
                    {Array.from({ length: 3 }).map((__, tileIndex) => (
                      <div
                        key={`diagnostics-stat-${cardIndex}-${tileIndex}`}
                        className="skeleton-shimmer h-14 rounded-xl"
                      />
                    ))}
                  </div>
                  <div className="skeleton-shimmer h-32 rounded-xl" />
                  <div className="space-y-2">
                    <div className="skeleton-shimmer h-3 w-full rounded" />
                    <div className="skeleton-shimmer h-3 w-5/6 rounded" />
                  </div>
                </div>
              ))}
            </section>

            {/* Visit history table */}
            <section className="bg-white border border-[#E5E7EB] rounded-2xl overflow-hidden">
              <div className="px-4 sm:px-6 py-3.5 border-b border-[#E5E7EB] flex items-center justify-between gap-3">
                <div className="skeleton-shimmer h-4 w-32 rounded" />
                <div className="skeleton-shimmer h-3 w-24 rounded" />
              </div>
              <div className="divide-y divide-[#E5E7EB]">
                {Array.from({ length: 6 }).map((_, rowIndex) => (
                  <div
                    key={`history-row-${rowIndex}`}
                    className="grid grid-cols-6 gap-3 px-4 sm:px-6 py-3.5 items-center"
                  >
                    <div className="skeleton-shimmer h-3 w-6 rounded" />
                    <div className="skeleton-shimmer h-3 w-24 max-w-full rounded" />
                    <div className="skeleton-shimmer h-3 w-28 max-w-full rounded" />
                    <div className="skeleton-shimmer h-3 w-32 max-w-full rounded" />
                    <div className="skeleton-shimmer h-3 w-20 max-w-full rounded" />
                    <div className="skeleton-shimmer h-5 w-16 rounded-full justify-self-end" />
                  </div>
                ))}
              </div>
            </section>

            {/* Raw event JSON */}
            <section className="bg-white border border-[#E5E7EB] rounded-2xl p-4 sm:p-6 space-y-3">
              <div className="skeleton-shimmer h-4 w-44 max-w-full rounded" />
              <div className="skeleton-shimmer h-40 rounded-xl" />
            </section>
          </div>
        )}

        {data && (
          <section
            id="overview"
            className="bg-white rounded-2xl border border-[#E5E7EB] shadow-2xs overflow-hidden flex flex-col lg:grid lg:grid-cols-2 lg:items-stretch"
          >
            {/* 1. Simplified Hero Identity Header */}
            <div className="order-1 lg:col-span-2 px-4 sm:px-7 py-5 border-b border-[#E5E7EB] flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <h1 className="text-lg sm:text-xl font-bold tracking-tight text-[#111827]">
                    Hello, visitor
                  </h1>
                  <span className="text-xs font-medium text-slate-500">
                    • {data.isReturning ? 'Returning Device' : 'First Observed Visit'}
                  </span>
                  {incognitoVerdict.isIncognito && (
                    <span
                      className="inline-flex items-center gap-1 rounded-full border border-violet-200 bg-violet-50 px-2 py-0.5 text-[10px] font-semibold text-violet-700"
                      title="Private browsing window detected"
                    >
                      <EyeOff className="w-3 h-3 shrink-0" />
                      Private window
                    </span>
                  )}
                </div>
                <p className="text-xs sm:text-[13px] text-slate-500 mt-1">
                  Real-time browser identity, hardware fingerprint, and live connection telemetry.
                </p>
                {data.identification ? (
                  <div className="mt-2 flex items-center gap-1.5 flex-wrap">
                    {(() => {
                      // Observable match evidence, NOT a calibrated probability. The copy is
                      // bound verbatim to the server's `confidence_label`. A null / absent label
                      // stays null through to display: a dash + hatch + explicit "unavailable"
                      // legend, NEVER a fabricated 0% (which would claim a measured empty match).
                      const serverLabel =
                        typeof canonical?.confidenceLabel === 'string' &&
                        canonical.confidenceLabel.trim()
                          ? canonical.confidenceLabel.trim()
                          : null;
                      const isUncalibrated = canonical?.calibrationStatus !== 'calibrated';
                      return (
                        <>
                          <span
                            className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold ${
                              serverLabel
                                ? 'border-slate-200 bg-slate-50 text-slate-700'
                                : 'border-dashed border-slate-400 bg-slate-100 text-slate-600'
                            }`}
                            title={
                              serverLabel
                                ? 'Evidence-based match label from the server — not a calibrated probability'
                                : 'Not collected by the server — no match evidence is available (this is not a measured 0%)'
                            }
                          >
                            {!serverLabel && (
                              <span aria-hidden="true" className="font-mono">
                                —
                              </span>
                            )}
                            {serverLabel ?? 'Match evidence unavailable'}
                          </span>
                          {isUncalibrated && (
                            <span
                              className="inline-flex items-center rounded-full border border-amber-300 bg-amber-50 px-2 py-0.5 text-[10px] font-medium text-amber-800"
                              title="No held-out calibration gate has passed for this score"
                            >
                              <span aria-hidden="true" className="mr-1">
                                !
                              </span>
                              uncalibrated
                            </span>
                          )}
                          {/* "why?" path — the authoritative value and its provenance live in
                              the canonical Event JSON below; no new panel is introduced. */}
                          <a
                            href="#raw-json"
                            className="text-[10px] font-medium text-slate-600 underline underline-offset-2 hover:text-slate-900"
                            title="See canonical.identity.confidence_label and calibration_status in the Event JSON"
                          >
                            why?
                          </a>
                        </>
                      );
                    })()}
                  </div>
                ) : null}
                {data.browserDevice.genuineMobile ? (
                  <div className="mt-2 flex justify-center">
                    {data.browserDevice.phoneModel ? (
                      <span className="max-w-full truncate text-sm sm:text-[15px] font-semibold tracking-tight text-[#111827]">
                        {data.browserDevice.phoneModel}
                      </span>
                    ) : (
                      <span
                        className="skeleton-shimmer h-4 w-40 rounded"
                        aria-label="Resolving phone model"
                        role="status"
                      />
                    )}
                  </div>
                ) : null}
              </div>

              {/* Side-by-Side Interactive Identity Boxes (Visitor ID + Hardware ID) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 w-full lg:w-auto lg:min-w-[520px]">
                {/* Visitor ID Box */}
                <div className="flex items-center justify-between gap-2.5 px-3 py-2 rounded-xl bg-slate-50 border border-[#E5E7EB] min-w-0">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className="w-8 h-8 rounded-lg bg-orange-50/40 border border-orange-100 flex items-center justify-center shrink-0">
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
                    <div className="w-8 h-8 rounded-lg bg-blue-50/40 border border-blue-100 flex items-center justify-center shrink-0">
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

            {/* 2. Location & Network: the map sits directly under the hero on mobile and in the left column on desktop */}
            <div className="order-2 lg:col-start-1 lg:row-start-2 w-full flex flex-col lg:border-r border-[#E5E7EB] min-w-0">
                <div className="px-4 sm:px-6 py-3 bg-[#FAFAFA] border-b border-[#E5E7EB] flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                    <MapPin className="w-3.5 h-3.5 text-[#F05A28]" />
                    <span className="whitespace-nowrap">Location &amp; Network</span>
                  </span>
                  <span className="text-[11px] font-mono tabular-nums text-slate-500 whitespace-nowrap">
                    <span className="hidden sm:inline">Visit </span>#
                    {data.statistics.totalVisits - selectedVisitIndex} of{' '}
                    {data.statistics.totalVisits} •{' '}
                    {formatRelativeVisitTime(activeVisit?.visitedAtUtc)}
                  </span>
                </div>

                {activeVisit && (
                  <div className="border-b border-[#E5E7EB] h-[215px] sm:h-[235px]">
                    <LocationMap
                      latitude={activeLatitude}
                      longitude={activeLongitude}
                      city={activeVisit.city}
                      region={activeVisit.region}
                      country={activeVisit.country}
                      countryCode={
                        selectedVisitIndex === 0 ? data.location.countryCode : undefined
                      }
                      publicIp={activeVisit.publicIp}
                      timezone={activeVisit.timezone || data.browserDevice.timezone}
                      networkLabel={
                        selectedVisitIndex === 0 && data.location.isNetworkLocation
                          ? data.location.networkLocation?.label
                          : undefined
                      }
                    />
                  </div>
                )}
            </div>

            {/* 3. Below the Map: Public IP / ISP-ASN / Location / Recognition */}
            {activeVisit && (
              <div className="order-3 lg:col-start-1 lg:row-start-3 w-full lg:border-r border-b lg:border-b-0 border-[#E5E7EB] min-w-0">
                    {/* Compact 2x2 Icon Grid for Public IP, Location, ISP/ASN, and Recognition */}
                    <div className="grid grid-cols-2">
                      <div className="contents">
                        {/* Tile 1: Public IP */}
                        <div className="p-3.5 sm:px-5 flex items-center gap-3 min-w-0 max-[359px]:flex-col max-[359px]:items-start max-[359px]:gap-2.5 border-r border-b border-[#E5E7EB]">
                          <div className="w-9 h-9 rounded-lg bg-blue-50/40 border border-blue-100 flex items-center justify-center shrink-0">
                            <Globe className="w-4 h-4 text-[#2563EB]" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <span className="block text-[11px] text-slate-500">Public IP</span>
                            <span
                              className="block text-xs sm:text-sm font-bold font-mono tabular-nums text-[#111827] break-all leading-snug"
                              title={activeVisit.publicIp}
                            >
                              {activeVisit.publicIp}
                            </span>
                          </div>
                        </div>

                        {/* Tile 3: ISP / ASN */}
                        <div className="p-3.5 sm:px-5 flex items-center gap-3 min-w-0 max-[359px]:flex-col max-[359px]:items-start max-[359px]:gap-2.5 border-b border-[#E5E7EB]">
                          <div className="w-9 h-9 rounded-lg bg-indigo-50/40 border border-indigo-100 flex items-center justify-center shrink-0">
                            <Wifi className="w-4 h-4 text-indigo-600" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <span className="block text-[11px] text-slate-500">ISP / ASN</span>
                            <span className="flex flex-wrap gap-1.5 items-center min-w-0">
                              <span
                                className="text-xs sm:text-sm font-semibold text-[#111827] break-words leading-snug"
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

                      <div className="contents">
                        {/* Tile 2: Location */}
                        <div className="p-3.5 sm:px-5 flex items-center gap-3 min-w-0 max-[359px]:flex-col max-[359px]:items-start max-[359px]:gap-2.5 border-r border-[#E5E7EB]">
                          <div className="w-9 h-9 rounded-lg bg-orange-50/40 border border-orange-100 flex items-center justify-center shrink-0">
                            <MapPin className="w-4 h-4 text-[#F05A28]" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <span className="block text-[11px] text-slate-500">
                              {selectedVisitIndex === 0 && data.location.isNetworkLocation
                                ? data.location.isTorExit
                                  ? 'Exit Node Location'
                                  : 'Network Location'
                                : 'Location'}
                            </span>
                            <span
                              className="block text-xs sm:text-sm font-semibold text-[#111827] break-words leading-snug"
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
                            {selectedVisitIndex === 0 &&
                              data.location.isNetworkLocation &&
                              data.location.networkLocation?.label && (
                                <span
                                  className="mt-1 inline-block text-[10px] font-mono uppercase tracking-wide rounded px-1.5 py-0.5 bg-orange-50 text-[#F05A28] border border-orange-100"
                                  title="This city and pin describe the egress node, not the visitor"
                                >
                                  {data.location.networkLocation.label}
                                </span>
                              )}
                          </div>
                        </div>

                        {/* Tile 4: Recognition */}
                        <div className="p-3.5 sm:px-5 flex items-center gap-3 min-w-0 max-[359px]:flex-col max-[359px]:items-start max-[359px]:gap-2.5">
                          <div className="w-9 h-9 rounded-lg bg-emerald-50/40 border border-emerald-100 flex items-center justify-center shrink-0">
                            <ShieldCheck className="w-4 h-4 text-emerald-600" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <span className="block text-[11px] text-slate-500">Recognition</span>
                            <span
                              className="block text-xs sm:text-sm font-semibold text-emerald-700 break-words leading-snug"
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

              {/* RIGHT COLUMN (50% width on lg+): Device & Session Summary (2-Column Visual Tile Grid) */}
              <div className="order-4 lg:col-start-2 lg:row-start-2 lg:row-span-2 w-full flex flex-col justify-between border-b lg:border-b-0 border-[#E5E7EB] bg-white min-w-0">
                <div className="px-4 sm:px-6 py-3 bg-[#FAFAFA] border-b border-[#E5E7EB] flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                    <Monitor className="w-3.5 h-3.5 text-[#2563EB]" />
                    <span>Device &amp; Session Summary</span>
                  </span>
                  <span className="text-[11px] font-mono text-slate-500">
                    {data.browserDevice.genuineMobile && data.browserDevice.phoneBrand
                      ? `Mobile · ${data.browserDevice.phoneBrand}`
                      : data.browserDevice.deviceType}
                  </span>
                </div>

                <div className="p-4 sm:p-6 flex-1 flex flex-col justify-center">
                  <div className="grid grid-cols-3 sm:grid-cols-2 gap-2 sm:gap-4 h-full auto-rows-fr">
                    {/* Tile 1: Browser */}
                    <div className="p-2.5 sm:p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3.5 min-w-0">
                      <div className="w-7 h-7 sm:w-9 sm:h-9 rounded-lg bg-blue-50/40 border border-blue-100 flex items-center justify-center shrink-0">
                        <Compass className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-[#2563EB]" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[10px] sm:text-[11px] text-slate-500">Browser</span>
                        <span
                          className="block text-[11px] sm:text-sm font-semibold text-[#111827] break-words leading-snug mt-0.5"
                          title={displayBrowser}
                        >
                          {displayBrowser}
                        </span>
                      </div>
                    </div>

                    {/* Tile 2: OS & Device */}
                    <div className="p-2.5 sm:p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3.5 min-w-0">
                      <div className="w-7 h-7 sm:w-9 sm:h-9 rounded-lg bg-emerald-50/40 border border-emerald-100 flex items-center justify-center shrink-0">
                        <Monitor className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-600" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[10px] sm:text-[11px] text-slate-500">OS &amp; Device</span>
                        {data.browserDevice.genuineMobile && !data.browserDevice.phoneDisplayLabel ? (
                          <span className="mt-1 block space-y-1" role="status" aria-label="Resolving device details">
                            <span className="skeleton-shimmer block h-3.5 w-40 max-w-full rounded" />
                            <span className="skeleton-shimmer block h-2.5 w-24 max-w-full rounded" />
                          </span>
                        ) : data.browserDevice.genuineMobile && data.browserDevice.phoneDisplayLabel ? (
                          <>
                            <span
                              className="block text-[11px] sm:text-sm font-semibold text-[#111827] break-words leading-snug mt-0.5"
                              title={data.browserDevice.phoneDisplayLabel}
                            >
                              {data.browserDevice.phoneDisplayLabel}
                            </span>
                            <span className="block text-[10px] sm:text-[11px] text-slate-500 leading-snug">
                              {torBrowserClient && !data.browserDevice.reportedModel
                                ? 'Model hidden by Tor Browser'
                                : `${displayOs} • ${
                                    activeVisit?.deviceType || data.browserDevice.deviceType
                                  }`}
                            </span>
                          </>
                        ) : (
                          <span
                            className="block text-[11px] sm:text-sm font-semibold text-[#111827] break-words leading-snug mt-0.5"
                            title={`${displayOs} • ${
                              activeVisit?.deviceType || data.browserDevice.deviceType
                            }`}
                          >
                            {displayOs}{' '}
                            • {activeVisit?.deviceType || data.browserDevice.deviceType}
                          </span>
                        )}
                        {spoofedOsBlocked && (
                          <span className="mt-0.5 inline-flex w-fit items-center rounded border border-amber-200 bg-amber-50 px-1.5 py-0.5 text-[9px] font-semibold text-amber-800">
                            Spoofed / Emulated OS Blocked: claimed {spoofedOsClaim}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Tile 3: Display */}
                    <div className="p-2.5 sm:p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3.5 min-w-0">
                      <div className="w-7 h-7 sm:w-9 sm:h-9 rounded-lg bg-orange-50/40 border border-orange-100 flex items-center justify-center shrink-0">
                        <Maximize2 className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-[#F05A28]" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[10px] sm:text-[11px] text-slate-500">Display</span>
                        <span
                          className="block text-[11px] sm:text-sm font-semibold font-mono tabular-nums text-[#111827] break-words leading-snug mt-0.5"
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
                    <div className="p-2.5 sm:p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3.5 min-w-0">
                      <div className="w-7 h-7 sm:w-9 sm:h-9 rounded-lg bg-indigo-50/40 border border-indigo-100 flex items-center justify-center shrink-0">
                        <Languages className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-indigo-600" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[10px] sm:text-[11px] text-slate-500">
                          Locale &amp; Timezone
                        </span>
                        <span
                          className="block text-[11px] sm:text-sm font-semibold text-[#111827] break-words leading-snug mt-0.5"
                          title={`${data.browserDevice.language} • ${browserTimezoneLabel}`}
                        >
                          {data.browserDevice.language} • {browserTimezoneLabel}
                        </span>
                        {timezoneMismatchVisible && (
                          <span className="mt-0.5 block text-[9px] leading-snug text-slate-500">
                            Timezone mismatch: browser {browserTimezoneLabel} vs IP{' '}
                            {ipTimezoneLabel ?? 'Unavailable'} — contextual signal only
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Tile 5: Active Session */}
                    <div className="p-2.5 sm:p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3.5 min-w-0">
                      <div className="w-7 h-7 sm:w-9 sm:h-9 rounded-lg bg-amber-50/40 border border-amber-100 flex items-center justify-center shrink-0">
                        <KeyRound className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-amber-700" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[10px] sm:text-[11px] text-slate-500">Active Session</span>
                        <code
                          className="block text-[11px] sm:text-sm font-semibold font-mono tabular-nums text-[#111827] break-all leading-snug mt-0.5"
                          title={data.statistics.currentSessionId}
                        >
                          {data.statistics.currentSessionId}
                        </code>
                      </div>
                    </div>

                    {/* Tile 6: First / Last Seen */}
                    <div className="p-2.5 sm:p-4 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3.5 min-w-0">
                      <div className="w-7 h-7 sm:w-9 sm:h-9 rounded-lg bg-emerald-50/40 border border-emerald-100 flex items-center justify-center shrink-0">
                        <CalendarClock className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-600" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <span className="block text-[10px] sm:text-[11px] text-slate-500">Last Active</span>
                        <span
                          className="block text-[11px] sm:text-sm font-semibold text-[#111827] break-words leading-snug mt-0.5"
                          title={`First seen: ${formatLocalTimestamp(
                            data.statistics.firstVisitUtc
                          )} | Last seen: ${formatLocalTimestamp(data.statistics.lastVisitUtc)}`}
                        >
                          {formatConciseSeenTimestamp(data.statistics.lastVisitUtc)}
                        </span>
                      </div>
                    </div>
                  </div>
                  {showServerVerifiedNote && (
                    <p className="mt-2.5 text-[10px] leading-relaxed text-slate-500">
                      Browser &amp; OS shown from server-verified HTTP / UA-CH headers; the
                      values reported by page scripts may be spoofed.
                    </p>
                  )}
                </div>
              </div>

            {/* 4. 4 KPI Summary Counters: Local History, Active Sessions, Observed IPs, Locations */}
            <div className="order-5 lg:col-span-2 lg:row-start-4 grid grid-cols-2 lg:grid-cols-4 border-t border-[#E5E7EB]">
              {/* KPI 1: honest local-history count (the records actually persisted) */}
              <div className="px-3 sm:px-6 py-3.5 flex items-center gap-3 sm:gap-3.5 min-w-0 border-r border-b lg:border-b-0 border-[#E5E7EB]">
                <div className="w-9 h-9 rounded-lg bg-orange-50/40 border border-orange-100 flex items-center justify-center shrink-0">
                  <Activity className="w-4 h-4 text-[#F05A28]" />
                </div>
                <div className="min-w-0">
                  <span className="block text-[11px] font-medium text-slate-500">
                    Local History
                  </span>
                  <span className="block text-sm sm:text-base font-bold font-mono tabular-nums text-[#111827] leading-tight break-words">
                    {data.visitHistory.length}{' '}
                    <span className="font-sans font-medium text-xs text-slate-500">
                      {data.visitHistory.length === 1
                        ? 'visit in local history'
                        : 'visits in local history'}
                    </span>
                  </span>
                </div>
              </div>

              {/* KPI 2: Sessions */}
              <div className="px-3 sm:px-6 py-3.5 flex items-center gap-3 sm:gap-3.5 min-w-0 border-b lg:border-b-0 lg:border-r border-[#E5E7EB]">
                <div className="w-9 h-9 rounded-lg bg-blue-50/40 border border-blue-100 flex items-center justify-center shrink-0">
                  <Layers className="w-4 h-4 text-[#2563EB]" />
                </div>
                <div className="min-w-0">
                  <span className="block text-[11px] font-medium text-slate-500">
                    Active Sessions
                  </span>
                  <span className="block text-sm sm:text-base font-bold font-mono tabular-nums text-[#111827] leading-tight break-words">
                    {data.statistics.totalSessions}{' '}
                    <span className="font-sans font-medium text-xs text-slate-500">
                      {data.statistics.totalSessions === 1 ? 'session' : 'sessions'}
                    </span>
                  </span>
                </div>
              </div>

              {/* KPI 3: Distinct IPs */}
              <div className="px-3 sm:px-6 py-3.5 flex items-center gap-3 sm:gap-3.5 min-w-0 border-r border-[#E5E7EB]">
                <div className="w-9 h-9 rounded-lg bg-emerald-50/40 border border-emerald-100 flex items-center justify-center shrink-0">
                  <Globe className="w-4 h-4 text-emerald-600" />
                </div>
                <div className="min-w-0">
                  <span className="block text-[11px] font-medium text-slate-500">
                    Observed IPs
                  </span>
                  <span className="block text-sm sm:text-base font-bold font-mono tabular-nums text-[#111827] leading-tight break-words">
                    {uniqueIpCount}{' '}
                    <span className="font-sans font-medium text-xs text-slate-500">
                      {uniqueIpCount === 1 ? 'IP address' : 'IP addresses'}
                    </span>
                  </span>
                </div>
              </div>

              {/* KPI 4: Locations */}
              <div className="px-3 sm:px-6 py-3.5 flex items-center gap-3 sm:gap-3.5 min-w-0">
                <div className="w-9 h-9 rounded-lg bg-indigo-50/40 border border-indigo-100 flex items-center justify-center shrink-0">
                  <MapPin className="w-4 h-4 text-indigo-600" />
                </div>
                <div className="min-w-0">
                  <span className="block text-[11px] font-medium text-slate-500">
                    Locations
                  </span>
                  <span className="block text-sm sm:text-base font-bold font-mono tabular-nums text-[#111827] leading-tight break-words">
                    {uniqueLocationCount}{' '}
                    <span className="font-sans font-medium text-xs text-slate-500">
                      {uniqueLocationCount === 1 ? 'city' : 'cities'}
                    </span>
                  </span>
                </div>
              </div>
            </div>

          </section>
        )}

        {/* Hardware & Rendering Entropy (2x3 Grid) */}
        {data && data.securitySignals && data.hardwareSignals && (
          <section id="hardware">
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
                    <div className="w-9 h-9 rounded-lg bg-orange-50/40 border border-orange-100 flex items-center justify-center shrink-0">
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
                        {spoofedSpecs && (
                          <span className="ml-1.5 text-[9px] font-sans font-medium text-amber-600">
                            (Spoofed / Unverified)
                          </span>
                        )}
                      </span>
                    </div>
                  </div>

                  {/* Tile 2: Graphics (Clean GPU Name + Max Texture) */}
                  <div
                    className="p-3.5 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-start gap-3 min-w-0"
                    title={rawGpuTooltip}
                  >
                    <div className="w-9 h-9 rounded-lg bg-blue-50/40 border border-blue-100 flex items-center justify-center shrink-0">
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
                    <div className="w-9 h-9 rounded-lg bg-emerald-50/40 border border-emerald-100 flex items-center justify-center shrink-0">
                      <HardDrive className="w-4 h-4 text-emerald-600" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <span className="block text-[11px] text-slate-500">Memory Tier</span>
                      <span
                        className="block text-xs sm:text-sm font-semibold font-mono tabular-nums text-[#111827] truncate mt-0.5"
                        title={
                          data.hardwareSignals.deviceMemoryGb
                            ? `${data.hardwareSignals.deviceMemoryGb} GB reported by navigator.deviceMemory${spoofedSpecTag}`
                            : 'navigator.deviceMemory is hidden by this browser'
                        }
                      >
                        {data.hardwareSignals.deviceMemoryGb
                          ? `~${data.hardwareSignals.deviceMemoryGb} GB RAM`
                          : 'Hidden / N/A'}{' '}
                        • {data.hardwareSignals.colorDepth}-bit
                        {spoofedSpecs && data.hardwareSignals.deviceMemoryGb != null && (
                          <span className="ml-1.5 text-[9px] font-sans font-medium text-amber-600">
                            (Spoofed / Unverified)
                          </span>
                        )}
                      </span>
                    </div>
                  </div>

                  {/* Tile 4: Display & Input */}
                  <div className="p-3.5 rounded-xl bg-slate-50/70 border border-[#E5E7EB] flex items-start gap-3 min-w-0">
                    <div className="w-9 h-9 rounded-lg bg-indigo-50/40 border border-indigo-100 flex items-center justify-center shrink-0">
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
                      {hasUnmaskedGpuRenderer ? data.hardwareSignals.gpuVendor : 'Unavailable'}
                    </strong>
                  </span>
                  <span className="text-[11px] font-mono text-slate-400 shrink-0">
                    Raw GPU
                  </span>
                </div>

                <div className="mt-2 p-2.5 rounded-lg bg-slate-50 border border-[#E5E7EB] text-[11px] font-mono text-slate-600 break-all">
                  {hasUnmaskedGpuRenderer ? (rawGpuRenderer as string).trim() : 'Unavailable'}
                </div>
              </div>
            </div>
          </section>
        )}

        {/* Smart Signals & Threat Analysis (4-signal core grid) */}
        {data && data.securitySignals && data.hardwareSignals && (
          <section id="signals">
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
                              torExitDetected ? 'Your IP is a Tor exit node' : '',
                              torBrowserClient ? 'Tor Browser fingerprint detected' : '',
                            ]
                              .filter(Boolean)
                              .join(' · ')}
                          </span>
                        </div>
                      </div>
                    )}
                    {automationBannerLabel && (
                      <div className="flex items-start gap-2.5 rounded-xl border border-indigo-200 bg-indigo-50/70 px-3 py-2.5">
                        <Bot className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
                        <div className="min-w-0 flex-1">
                          <span className="block text-xs font-semibold text-indigo-700">
                            {automationBannerLabel}
                            {automationOperator !== 'unknown'
                              ? ` · Operator ${automationOperator}`
                              : ''}
                          </span>
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

                  <span className={`inline-flex items-center gap-1.5 text-xs font-mono font-semibold ${riskTone}`}>
                    {riskIsHigh ? (
                      <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                    ) : (
                      <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                    )}
                    <span>{riskBadgeText}</span>
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
            </div>

          </section>
        )}

        {/* Network Stability & System CPU Pressure (Responsive Side-by-Side Grid) */}
        <section id="diagnostics" className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
          <NetworkStabilityPanel />
          {/* Real phones expose no compute pressure telemetry, so the panel is omitted there.
              Desktop browsers keep it even when narrowed to a phone-sized viewport. */}
          {!isMobileDevice && <CpuActivityPanel />}
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
                    // ONE server-classified brand source: prefer `securitySignals.brandName`
                    // over the raw geo-provider strings ("Chiron Software" vs "Cox"), so the
                    // history table and the header card can never name the same network
                    // differently. Compare ASNs numerically so "AS22773" and "22773" agree.
                    const asnDigits = (value: string): string => value.replace(/\D/g, '');
                    const brandName = data.securitySignals?.brandName;
                    const brandIsValid = Boolean(
                      brandName && brandName !== 'Unavailable' && brandName !== 'Unknown'
                    );
                    const rowAsnKey = asnDigits(rowAsn);
                    const currentAsnKey = asnDigits(data.location.asn ?? '');
                    const canonicalBrand =
                      brandIsValid &&
                      (index === 0 ||
                        (rowAsnKey !== '' && rowAsnKey === currentAsnKey))
                        ? brandName
                        : undefined;
                    const rowIspFormatted = formatCleanIspDisplay(
                      canonicalBrand || rowIsp,
                      canonicalBrand || rowOrg,
                      rowAsn
                    );
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
                        <td className="py-2.5 px-3 text-slate-800 break-words leading-snug min-w-[140px]">
                          {formatShortLocation(visit.city, visit.country)}
                        </td>
                        <td
                          className="py-2.5 px-3 text-slate-800 break-words leading-snug min-w-[150px]"
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
          <div className="mt-3 max-h-[420px] overflow-auto rounded-xl bg-[#F8FAFC] border border-[#E5E7EB] p-3 text-[11px] leading-relaxed font-mono">
            {eventJson ? <JsonPreview value={eventJson} /> : 'Collecting event payload...'}
          </div>
        </section>
      </main>

      {/* Cursor attribution: human pointer or remote browser agent pill */}
      <CursorAttributionOverlay identity={cursorIdentity} />
    </div>
  );
}

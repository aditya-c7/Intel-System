import type { IntelVisitorResponse } from '../types/visitor';
import type { RiskTier } from '../lib/telemetryContract';
import {
  resolveCanonical,
  isSwiftShader,
  SWIFTSHADER_LABEL,
  confidenceLabelOrNull,
  gpuTruthIsVerified,
} from './canonical';

export type { RiskTier };

/** Narrow an unknown transport value to a plain record without changing it. */
function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * Smart Signals grid.
 *
 * Renders one deterministic row per signal instead of the legacy four broad risk cards.
 * Clean states use the soft mint treatment (#E6F4EA fill, #81C995 accent) and triggered
 * states use the red treatment (#FCE8E6 fill, #D93025 accent); the row label stays neutral.
 * Signals whose platform capability is absent are pruned from the DOM entirely.
 */

export interface SmartSignalRowData {
  key: string;
  label: string;
  status: string;
  triggered: boolean;
  /** Muted/amber state for informational verdicts that are not threats of their own. */
  tone?: 'clean' | 'trigger' | 'neutral';
  detail?: string;
  /** Neutral informational badge (e.g. a signed/verified good-bot identity). Never a verdict. */
  badge?: string;
  /** Row links to the raw event JSON inspector. */
  jsonAnchor?: boolean;
}

/* -------------------------------------------------------------------------- */
/* Incognito — one canonical, jargon-free verdict for every surface            */
/* -------------------------------------------------------------------------- */

/**
 * The only strings a user ever sees for this axis. Raw probe names, ratios, OPFS /
 * IndexedDB internals and quota numbers are never printed — the server detail is
 * reduced to one of these three sanctioned outcomes before it reaches the DOM.
 */
const INCOGNITO_STATUS_ON = 'You are incognito';
const INCOGNITO_STATUS_OFF = 'Not detected';
const INCOGNITO_DETAIL_PRIVATE = 'Ephemeral / private storage detected';
const INCOGNITO_DETAIL_NORMAL = 'Persistent disk-backed storage verified';
const INCOGNITO_DETAIL_INCONCLUSIVE = 'Inconclusive — treated as normal';

export interface IncognitoVerdict {
  /** Server-canonical verdict. Drives the tile label, the chip and the Event JSON. */
  isIncognito: boolean;
  /** A negative verdict from an inconclusive / fail-open probe. */
  lowConfidence: boolean;
  /** Jargon-free status label shared by the grid rows and the Event JSON. */
  status: string;
  /** Exactly one of the three sanctioned storage outcomes. */
  detail: string;
}

/** Reads the canonical Smart Signal wording as a boolean (never echoed verbatim). */
function statusSaysIncognito(status: string | null | undefined): boolean {
  const s = (status || '').trim().toLowerCase();
  if (!s) return false;
  // Explicit negative verdicts win over a stray "private" token in surrounding prose.
  if (/not detected|standard window|not incognito|not private|^no$|^false$|^none$|unavailable/.test(s))
    return false;
  return /incognito|private|ephemeral|detected|^yes$|^true$/.test(s);
}

/** True only for a negative probe whose result was inconclusive / low-confidence. */
function detailIsInconclusive(detail: string | null | undefined): boolean {
  return /inconclusive|indeterminate|fail[-\s]?open|low[-\s]?confidence|unknown|unavailable|storage-check-inconclusive/i.test(
    detail || ''
  );
}

/**
 * Single source of truth for the incognito verdict — ONE verdict, driven ONLY by the
 * server's canonical booleans. Each boolean mirror is a vote and any positive vote wins:
 * a genuine private window can never render "Not detected" because one mirror looked stale.
 * The legacy status prose is consulted only when the response carries no boolean at all,
 * so a stale "Incognito / Private Mode" string can never manufacture a claim that the
 * server's own booleans deny. Every consumer (both grids, the title chip and the Event
 * JSON) reads this same object, and only the sanctioned jargon-free strings below reach
 * the DOM.
 */
export function resolveIncognitoVerdict(
  data: IntelVisitorResponse | null | undefined
): IncognitoVerdict {
  const s = data?.securitySignals;
  const signal = data?.smartSignals?.incognito ?? s?.smartSignals?.incognito ?? null;

  const booleanVotes: Array<boolean | undefined> = [
    s?.isIncognito,
    data?.isIncognito,
    s?.incognito,
    data?.incognito,
    s?.privateMode,
    s?.incognitoLikely,
  ];
  const anyPositive = booleanVotes.some((value) => value === true);
  const hasBoolean = booleanVotes.some((value) => typeof value === 'boolean');
  // Boolean authority always wins; prose is a last-resort fallback for legacy responses
  // that carry no boolean verdict at all (never an override of an explicit false).
  const isIncognito = anyPositive || (!hasBoolean && statusSaysIncognito(signal?.status));

  const rawConfidence = (
    s as { incognitoConfidence?: 'high' | 'low' | number | null } | undefined
  )?.incognitoConfidence;
  const rawDetail =
    (s as { incognitoDetail?: string } | undefined)?.incognitoDetail ??
    (s as { incognitoMethod?: string } | undefined)?.incognitoMethod ??
    signal?.detail ??
    '';
  const lowConfidence =
    !isIncognito &&
    (rawConfidence === 'low' ||
      (typeof rawConfidence === 'number' &&
        Number.isFinite(rawConfidence) &&
        rawConfidence < 0.9) ||
      detailIsInconclusive(rawDetail));

  return {
    isIncognito,
    lowConfidence,
    status: isIncognito ? INCOGNITO_STATUS_ON : INCOGNITO_STATUS_OFF,
    detail: isIncognito
      ? INCOGNITO_DETAIL_PRIVATE
      : lowConfidence
      ? INCOGNITO_DETAIL_INCONCLUSIVE
      : INCOGNITO_DETAIL_NORMAL,
  };
}

const CLEAN = {
  box: 'bg-[#E6F4EA] border-[#81C995]/60 text-[#137333]',
};
const TRIGGER = {
  box: 'bg-[#FCE8E6] border-[#D93025]/40 text-[#D93025]',
};
const NEUTRAL = {
  box: 'bg-[#F8FAFC] border-[#E5E7EB] text-[#475569]',
};

function toneClass(tone: SmartSignalRowData['tone']): string {
  if (tone === 'trigger') return TRIGGER.box;
  if (tone === 'neutral') return NEUTRAL.box;
  return CLEAN.box;
}

/* -------------------------------------------------------------------------- */
/* Bot — verbatim server verdict, exact agent names preserved                  */
/* -------------------------------------------------------------------------- */

export interface BotVerdict {
  /** `smartSignals.bot.status` VERBATIM — never recomputed from raw bot evidence. */
  status: string;
  triggered: boolean;
  detail?: string;
  /** Server-computed 0..10 rating from the same smart signal. */
  score: number;
}

/**
 * Single source of truth for the Bot row. The edge/server already reconciled every raw
 * probe (user-agent, WebDriver, CDP leaks, ASN attribution) into `smartSignals.bot`. Its
 * `status` is printed verbatim so an exact agent name such as
 * `Verified · Googlebot · Google` is preserved character-for-character. Nothing here
 * inspects `isBot`, `botSubtype`, `botSignals`, `bot_info` or any other raw evidence —
 * recomputing a bot verdict on the client is exactly what used to contradict the JSON.
 */
export function resolveBotVerdict(data: IntelVisitorResponse): BotVerdict {
  const signal = data.smartSignals?.bot ?? data.securitySignals?.smartSignals?.bot ?? null;
  const status = signal?.status?.trim() || 'Not detected';
  const rawScore = signal?.scoreOutOf10;
  const score =
    typeof rawScore === 'number' && Number.isFinite(rawScore)
      ? Math.max(0, Math.min(10, rawScore))
      : 0;
  return {
    status,
    triggered: score >= 5,
    detail: signal?.detail?.trim() || undefined,
    score,
  };
}

/**
 * Single source of truth for the Browser Tampering row status. The server's canonical
 * boolean is mirrored at `smartSignals.tampering` / `data.tampering`; the coarse
 * `securitySignals.tampering` is kept only as a legacy fallback. This function deliberately
 * does NOT look at `tamperingDetails` or risk-factor prose, so the tile can never disagree
 * with the authoritative verdict or contradict the surrounding risk text.
 */
function serverTampering(data: IntelVisitorResponse): boolean {
  const smart = data.smartSignals as { tampering?: boolean } | undefined;
  if (typeof smart?.tampering === 'boolean') return smart.tampering;
  if (typeof data.tampering === 'boolean') return data.tampering;
  return Boolean(data.securitySignals?.tampering);
}

/* -------------------------------------------------------------------------- */
/* Virtual Machine — server-canonical verdict                                  */
/* -------------------------------------------------------------------------- */

export type VmVerdictState =
  /** Confirmed hypervisor / emulator runtime. */
  | 'vm'
  /** Software rasterizer only — never VM proof, never physical hardware. */
  | 'software'
  /** GPU / environment not observable — the honest "Not determinable" state. */
  | 'unknown'
  /** Genuine unmasked GPU with consistent platform. */
  | 'physical';

export interface VmVerdict {
  state: VmVerdictState;
  status: string;
  detail?: string;
  /** Canonical 0..10 observation score. Unknown and physical both score 0. */
  score: number;
}

/** Interprets a canonical/server VM status string into one stable four state. */
function interpretVmText(text: string): VmVerdictState | null {
  const t = (text || '').trim().toLowerCase();
  if (!t) return null;
  // Negative / physical verdicts are tested before "detected" so "Not detected" can
  // never be mistaken for a positive VM claim.
  if (/not detected|no virtual|physical|bare metal|native silicon|dedicated hardware|^no$/.test(t))
    return 'physical';
  if (/software|swiftshader|llvmpipe|softpipe|not proven/.test(t)) return 'software';
  // Masked / unavailable / tampered environments are not observations of physical hardware.
  if (
    /unknown|unavailable|indeterminate|inconclusive|masked|replayed|tampered|spoofed|n\/a|^none$/.test(
      t
    )
  )
    return 'unknown';
  if (
    /virtual machine|virtualbox|vmware|\bkvm\b|\bqemu\b|hyper-?v|\bxen\b|container|cloud|\bvm\b|emulator|detected|^yes$/.test(
      t
    )
  )
    return 'vm';
  return null;
}

/**
 * Four-state GPU observation, resolved from the SERVER canonical axes only:
 * `smartSignals.vm.status`, `securitySignals.isVirtualMachine` and
 * `environment.virtual_machine_label` / `software_renderer`.
 *
 *  - `vm`         — a confirmed hypervisor / emulator runtime.
 *  - `software`   — SwiftShader / llvmpipe / masked software rendering; NOT VM proof.
 *  - `physical`   — only a genuine unmasked GPU with a consistent platform.
 *  - `unknown`    — the GPU or environment is unavailable / inconclusive: the status is
 *                   "Not determinable" and the score is 0.
 *
 * A client-side `cloudOrMaskedGpu` / `emulatorDetected` hint is NEVER allowed to promote an
 * unavailable or software-rendered environment into a "Yes" / "Physical Hardware" claim.
 * If the authoritative JSON says the VM verdict is false or unobservable, the row degrades
 * to "Not determinable" instead of contradicting `#raw-json`.
 */
export function resolveVmVerdict(
  data: IntelVisitorResponse,
  canonicalView: ReturnType<typeof resolveCanonical> = resolveCanonical(data)
): VmVerdict {
  const env = canonicalView.environment;
  const signal = data.smartSignals?.vm ?? data.securitySignals?.smartSignals?.vm ?? null;
  const signalStatus = (signal?.status ?? '').trim();
  const signalDetail = (signal?.detail ?? '').trim();
  const label = (env?.virtual_machine_label ?? '').trim();
  const softwareRenderer = Boolean(env?.software_renderer);
  const webglSoftware = isSwiftShader(data.hardwareSignals?.gpuRenderer);
  const isVmFlag = data.securitySignals?.isVirtualMachine;

  const labelState = interpretVmText(label);
  const signalState = interpretVmText(signalStatus);
  const unavailablePattern = /unavailable|masked|indeterminate|inconclusive|^none$|n\/a/i;
  const unavailable = unavailablePattern.test(signalStatus) || unavailablePattern.test(label);

  // Additive GPU truth mirrors gate every physical-hardware claim. A masked, spoofed or
  // otherwise unreliable GPU answer is absence of evidence — it can never read
  // "Physical Hardware" / "Unmasked physical GPU verified", no matter what the raw VM
  // status/detail says. These are server values, never client-derived.
  const gpuTruth =
    typeof canonicalView.gpu_truth_state === 'string'
      ? canonicalView.gpu_truth_state.trim().toLowerCase()
      : '';
  const gpuUnreliable = canonicalView.gpu_answer_unreliable === true;
  const observation = canonicalView.gpuObservation;
  const observationRestricted =
    observation === 'masked_by_privacy' || observation === 'observation_unavailable';
  const truthSaysPhysical =
    (gpuTruth === 'hardware' || gpuTruth === 'physical_hardware') &&
    !gpuUnreliable &&
    !observationRestricted;
  const truthSaysMasked =
    /masked|spoof/i.test(gpuTruth) ||
    /masked|spoof/i.test(signalStatus) ||
    /masked|spoof/i.test(label) ||
    observation === 'masked_by_privacy';
  const truthBlocksPhysical =
    (gpuTruth.length > 0 && !truthSaysPhysical) || observationRestricted || gpuUnreliable || unavailable;

  const gpuVendor = data.hardwareSignals?.gpuVendor ?? '';
  const gpuRenderer = (data.hardwareSignals?.gpuRenderer ?? '').trim();
  const realUnmaskedGpu =
    !webglSoftware &&
    !softwareRenderer &&
    !unavailable &&
    Boolean(gpuVendor) &&
    gpuVendor !== 'Unavailable' &&
    Boolean(gpuRenderer) &&
    gpuRenderer !== 'Unavailable';

  // A raw WebGL renderer string is spoofable JS output, never hardware proof. It is trusted as
  // a hardware anchor ONLY when the server's own GPU truth / observation independently says so.
  // The new `renderer_reported_unverified` server flag is authoritative when present.
  const serverVerifiedHardware =
    truthSaysPhysical || observation === 'hardware_visible';
  const rendererOnlyWebgl =
    gpuRenderer.length > 0 &&
    (canonicalView.renderer_reported_unverified === true || !serverVerifiedHardware);

  let state: VmVerdictState;
  if (isVmFlag === true || signalState === 'vm' || labelState === 'vm') {
    state = 'vm';
  } else if (
    softwareRenderer ||
    webglSoftware ||
    signalState === 'software' ||
    labelState === 'software'
  ) {
    state = 'software';
  } else if ((signalState === 'physical' || labelState === 'physical') && realUnmaskedGpu) {
    state = 'physical';
  } else {
    // No server authority, or an explicitly unavailable / inconclusive observation.
    state = 'unknown';
  }

  // The authoritative JSON verdict is never contradicted: a false VM boolean or an
  // unavailable / masked GPU can never surface as "Yes" / "Physical Hardware". This is
  // the same invariant the server applies when it reconciles `virtual_machine: false`.
  if (isVmFlag === false && (state === 'vm' || state === 'physical')) state = 'unknown';
  if (unavailable && (state === 'vm' || state === 'physical')) state = 'unknown';
  if (state === 'physical' && truthBlocksPhysical) state = 'unknown';
  // "Physical Hardware" requires the server's own hardware anchor. A WebGL-reported renderer
  // string alone is spoofable output and can never promote the tile to a physical claim.
  if (state === 'physical' && (!serverVerifiedHardware || rendererOnlyWebgl)) state = 'unknown';

  // The restricted-GPU label replaces "Not determinable" only when a physical claim was
  // actually blocked: explicitly masked / spoofed answers read "Masked / Unverified", while an
  // unavailable, unknown or merely unreliable answer reads "Unavailable / Browser-Restricted".
  const restrictedGpuStatus = truthSaysMasked
    ? 'Masked / Unverified'
    : truthBlocksPhysical
    ? 'Unavailable / Browser-Restricted'
    : null;
  const hardwareUnverifiable =
    state === 'unknown' &&
    (restrictedGpuStatus !== null ||
      unavailable ||
      observationRestricted ||
      gpuUnreliable ||
      rendererOnlyWebgl);
  // A raw renderer string is spoofable WebGL output. It carries a visible "(unverified)"
  // qualifier unless EVERY server GPU truth axis independently verified physical hardware.
  const rendererQualifier = gpuTruthIsVerified(canonicalView) ? '' : ' (unverified)';
  const reportedRendererStatus =
    gpuRenderer.length > 0 ? `Reported renderer: ${gpuRenderer}${rendererQualifier}` : null;
  // Masked / unavailable observations are absence of evidence: they outrank any raw renderer
  // claim, even when a renderer string was reported by WebGL.
  const status =
    state === 'unknown' && restrictedGpuStatus
      ? restrictedGpuStatus
      : state === 'unknown' && hardwareUnverifiable && reportedRendererStatus
      ? reportedRendererStatus
      : state === 'vm'
      ? signalState === 'vm'
        ? signalStatus
        : 'Virtual Machine'
      : state === 'software'
      ? signalState === 'software'
        ? signalStatus
        : SWIFTSHADER_LABEL
      : state === 'physical'
      ? 'Physical Hardware'
      : 'Not determinable';

  return {
    state,
    status,
    // An unavailable environment has no positive detail to print: the server's raw VM
    // detail can still claim an unmasked physical GPU after its own consistency pass
    // rewrote the status to "GPU Masked / Unavailable", which would contradict the JSON.
    detail:
      state === 'vm' || state === 'software'
        ? signalDetail || undefined
        : hardwareUnverifiable && rendererOnlyWebgl
        ? 'Hardware verification unavailable (renderer reported by WebGL)'
        : undefined,
    score: state === 'vm' ? 6 : state === 'software' ? 3 : 0,
  };
}

/* -------------------------------------------------------------------------- */
/* VPN — concrete methods only; timezone mismatch is context, never a method   */
/* -------------------------------------------------------------------------- */

export interface VpnVerdict {
  status: string;
  triggered: boolean;
  detail?: string;
  /** Count of concrete, tunnel-bearing methods (timezone_mismatch excluded). */
  effectiveCount: number;
  /** Separate context note — shown on its own row, never credited to the VPN verdict. */
  timezoneNote?: string;
}

/** Legacy / partial payloads may omit individual method flags. */
type VpnMethodFlags = {
  timezone_mismatch?: boolean;
  public_vpn?: boolean;
  auxiliary_mobile?: boolean;
  os_mismatch?: boolean;
  relay?: boolean;
  ml_prediction?: boolean;
};

/** Only these server methods represent an actual tunnel / anonymity relay. */
const VPN_TUNNEL_METHODS = [
  'public_vpn',
  'relay',
  'ml_prediction',
  'os_mismatch',
  'auxiliary_mobile',
] as const;

/**
 * Single source of truth for the VPN row. The server's structured `vpn_methods` object is
 * authoritative — `resolveCanonical` prefers the envelope's additive snake_case copy and falls
 * back to the legacy `securitySignals.vpnMethods` mirror, so one server object drives both this
 * verdict and its method count. No flags are merged or invented. `timezone_mismatch` is an
 * orthogonal network axis and is NEVER counted as a VPN method or allowed to trigger the row;
 * the legacy `vpnSuspected` flag (which used to be timezone-only) is likewise ignored unless a
 * concrete method fired. The timezone discrepancy is returned as a separate `timezoneNote` so
 * the UI can show it as context without implying a VPN.
 */
export function resolveVpnVerdict(
  data: IntelVisitorResponse,
  canonicalView: ReturnType<typeof resolveCanonical> = resolveCanonical(data)
): VpnVerdict {
  const signals = data.securitySignals;
  const methods = (canonicalView.vpnMethods ?? signals.vpnMethods ?? {}) as unknown as VpnMethodFlags;
  const effectiveCount = VPN_TUNNEL_METHODS.filter((key) => Boolean(methods[key])).length;
  const timezoneMismatch = Boolean(methods.timezone_mismatch ?? signals.timezoneMismatch);
  const detected = effectiveCount > 0 || Boolean(signals.publicVpn);

  let status = 'Not detected';
  if (detected) {
    if (methods.public_vpn || signals.publicVpn) status = 'Commercial VPN';
    else if (methods.relay) status = 'Tor exit / relay';
    else if (signals.datacenterAsn ?? signals.isDatacenterOrHosting) status = 'Datacenter / hosting';
    else status = 'Detected';
  }

  return {
    status,
    triggered: detected,
    detail: effectiveCount > 1 ? `${effectiveCount} matching network methods` : undefined,
    effectiveCount,
    timezoneNote: timezoneMismatch
      ? 'Browser timezone differs from IP geolocation (context only — not a VPN method)'
      : undefined,
  };
}

/* -------------------------------------------------------------------------- */
/* Inspector — CDP bridge and DevTools are distinct verification states        */
/* -------------------------------------------------------------------------- */

export interface InspectorVerdict {
  cdpAttached: boolean;
  cdpDetail?: string;
  /** True ONLY for a verified, actively docked DevTools inspector. */
  developerTools: boolean;
  inspectorState?: string;
}

/** Resolves the CDP and Developer Tools rows from the canonical inspector state. */
export function resolveInspectorVerdict(data: IntelVisitorResponse): InspectorVerdict {
  const automation = resolveCanonical(data).automation;
  const inspectorState = automation?.inspector_state;
  const developerTools = inspectorState === 'devtools_active_verified';
  const cdpAttached =
    Boolean(automation?.cdp_attached) || inspectorState === 'automation_protocol_attached';
  const cdpDetail =
    inspectorState === 'automation_protocol_attached'
      ? 'Automation protocol attached (no docked DevTools UI)'
      : cdpAttached
      ? inspectorState || undefined
      : undefined;
  return { cdpAttached, cdpDetail, developerTools, inspectorState };
}

/** Thin alias kept stable for App.tsx callers that only need the CDP axis. */
export function resolveCdpVerdict(data: IntelVisitorResponse): InspectorVerdict {
  return resolveInspectorVerdict(data);
}

/** Thin alias kept stable for App.tsx callers that only need the DevTools boolean. */
export function resolveDeveloperToolsVerdict(data: IntelVisitorResponse): boolean {
  return resolveInspectorVerdict(data).developerTools;
}

export function buildSmartSignalRows(data: IntelVisitorResponse): SmartSignalRowData[] {
  const canonicalView = resolveCanonical(data);

  const signals = data.securitySignals;
  const rows: SmartSignalRowData[] = [];

  const city = data.location.city && data.location.city !== 'Unavailable' ? data.location.city : '';
  const region =
    data.location.region && data.location.region !== 'Unavailable' ? data.location.region : '';
  const country =
    data.location.country && data.location.country !== 'Unavailable' ? data.location.country : '';
  const geoParts = [city, region, country].filter(Boolean);
  rows.push({
    key: 'geolocation',
    label: 'Geolocation',
    status: geoParts.length > 0 ? geoParts.join(', ') : 'Unavailable',
    triggered: false,
    tone: geoParts.length > 0 ? 'clean' : 'neutral',
    detail: 'IP Geolocation Estimate',
  });

  const incognito = resolveIncognitoVerdict(data);
  rows.push({
    key: 'incognito',
    label: 'Incognito Mode',
    status: incognito.status,
    triggered: incognito.isIncognito,
    detail: incognito.detail,
  });

  const bot = resolveBotVerdict(data);
  // Additive WBA / official-feed mirrors are surfaced as DETAIL only. The tile's status,
  // trigger and score stay exactly as the server computed them; a status/feed token is
  // printed verbatim and never upgraded into a stronger bot verdict on the client.
  const botEvidenceDetail = [
    canonicalView.wba_status != null ? `WBA ${canonicalView.wba_status}` : null,
    canonicalView.official_bot_feed_match != null &&
    canonicalView.official_bot_feed_match.length > 0
      ? `Official feed match: ${canonicalView.official_bot_feed_match.join(', ')}`
      : null,
  ]
    .filter((part): part is string => part != null)
    .join(' · ');
  // A signed / verified good-bot identity is INFORMATIONAL: it never changes the server's
  // bot status, trigger or score. Read the identity verbatim from the canonical bot_info mirror
  // (or its response fallback) and surface it as a neutral badge only when the server said so.
  const botInfoMirror = asRecord(canonicalView.bot_info) ?? asRecord(data.bot_info);
  const botIdentity =
    typeof botInfoMirror?.identity === 'string' ? botInfoMirror.identity.trim().toLowerCase() : '';
  const signedGoodBot = botIdentity === 'signed' || botIdentity === 'verified';
  rows.push({
    key: 'bot',
    label: 'Bot',
    // Verbatim server status — exact agent names are preserved, never recomputed.
    status: bot.status,
    triggered: bot.triggered,
    detail: [bot.detail, botEvidenceDetail].filter(Boolean).join(' · ') || undefined,
    badge: signedGoodBot ? 'Signed good bot' : undefined,
  });

  // The server's structured `vpn_methods` mirror is the single source of truth. Timezone
  // mismatch is an orthogonal context axis: it is excluded from the method count and can never
  // trigger this row. `resolveVpnVerdict` returns it as a separate note, rendered on its own row.
  const vpn = resolveVpnVerdict(data, canonicalView);
  rows.push({
    key: 'vpn',
    label: 'VPN',
    status: vpn.status,
    triggered: vpn.triggered,
    detail: vpn.detail,
  });
  if (vpn.timezoneNote) {
    rows.push({
      key: 'vpnTimezoneContext',
      label: 'Timezone Context',
      status: 'Differs from IP region',
      triggered: false,
      tone: 'neutral',
      detail: vpn.timezoneNote,
    });
  }

  // The tampering row mirrors the server's canonical verdict; it never recomputes one from
  // raw evidence. `smartSignals.tampering` (when a backend supplies it) and `data.tampering`
  // are both server mirrors; the coarse `securitySignals.tampering` is the legacy fallback.
  const tampering = serverTampering(data);
  // Detail may only describe CONFIRMED tampering. A privacy-hardening exemption reason is
  // not tampering evidence — printing it under "Not detected" would contradict the verdict.
  const tamperReason = data.tamperingDetails?.reasons?.find(
    (reason) => !/privacy[- ]hardened|exempt/i.test(reason)
  );
  rows.push({
    key: 'tampering',
    label: 'Browser Tampering',
    status: tampering ? 'Detected' : 'Not detected',
    triggered: tampering,
    detail: tampering
      ? data.tamperingDetails?.devtools_device_emulation
        ? 'DevTools device emulation'
        : data.tamperingDetails?.anti_detect_browser
        ? 'Anti-detect browser'
        : tamperReason
      : undefined,
  });

  // DevTools and CDP are distinct canonical inspector states. Developer Tools is reported
  // ONLY for a verified, actively docked debugger; a bare CDP bridge is informational and
  // never promoted to DevTools proof (or vice versa).
  const inspector = resolveInspectorVerdict(data);
  rows.push({
    key: 'developerTools',
    label: 'Developer Tools',
    status: inspector.developerTools ? 'Yes' : 'Not detected',
    triggered: inspector.developerTools,
  });

  rows.push({
    key: 'cdpAutomation',
    label: 'CDP / Automation Protocol',
    status: inspector.cdpAttached ? 'Attached' : 'Not detected',
    triggered: false,
    tone: inspector.cdpAttached ? 'neutral' : 'clean',
    detail: inspector.cdpDetail,
  });

  // Four-state GPU observation: Virtual Machine / Software-rendered / Physical Hardware /
  // "Not determinable". A client GPU or emulator hint can never promote an unavailable
  // environment into a "Yes" / Physical Hardware claim that contradicts the JSON.
  const vmVerdict = resolveVmVerdict(data, canonicalView);
  rows.push({
    key: 'virtualMachine',
    label: 'Virtual Machine',
    status: vmVerdict.status,
    triggered: vmVerdict.state === 'vm',
    tone: vmVerdict.state === 'software' || vmVerdict.state === 'unknown' ? 'neutral' : undefined,
    detail: vmVerdict.detail,
  });

  // The server's additive `privacy_settings` mirror is read here — either the plain boolean
  // verdict or the structured signature outcome — as one more server-provided vote beside the
  // legacy flags. An absent mirror leaves those flags unchanged, so older payloads render exactly
  // as before and the tile keeps the same OR semantics as the Event JSON.
  // The structured `privacy_settings` mirror is authoritative when present: its boolean
  // verdict, privacy_hardened flag, signature ids and reason strings are all read from the
  // server object (never re-derived). Legacy flat signals stay as a fallback only, so an older
  // payload that never supplied the structured mirror still renders exactly as before.
  const privacyMirror = asRecord(canonicalView.privacy_settings);
  const privacyFromMirror =
    typeof canonicalView.privacy_settings === 'boolean'
      ? canonicalView.privacy_settings
      : typeof privacyMirror?.privacy_settings === 'boolean'
      ? privacyMirror.privacy_settings
      : typeof privacyMirror?.privacy_hardened === 'boolean'
      ? privacyMirror.privacy_hardened
      : undefined;
  const privacyMirrorReasons = Array.isArray(privacyMirror?.reasons)
    ? privacyMirror.reasons.filter(
        (reason): reason is string => typeof reason === 'string' && reason.trim().length > 0
      )
    : [];
  const privacySignatureIdsRaw =
    canonicalView.privacy_signature_ids ??
    privacyMirror?.privacy_signature_ids ??
    privacyMirror?.signatures;
  const privacySignatureIds = Array.isArray(privacySignatureIdsRaw)
    ? privacySignatureIdsRaw.filter(
        (id): id is string => typeof id === 'string' && id.trim().length > 0
      )
    : [];
  const privacySettings = Boolean(
    privacyFromMirror ||
      signals.privacySettings ||
      signals.isTorBrowserClient ||
      signals.privacyProtected
  );
  rows.push({
    key: 'privacySettings',
    label: 'Privacy Settings',
    status: privacySettings ? 'Yes' : 'Not detected',
    triggered: privacySettings,
    detail:
      privacyMirrorReasons[0] ||
      (privacySignatureIds.length > 0 ? `Signatures: ${privacySignatureIds.join(', ')}` : undefined) ||
      signals.privacyDetail ||
      (signals.isTorBrowserClient ? 'Tor Browser RFP' : undefined) ||
      undefined,
  });

  const torNode = Boolean(signals.torExitNode);
  const blocklisted = Boolean(signals.ipBlocklisted);
  rows.push({
    key: 'ipBlocklist',
    label: 'IP Blocklist',
    status: torNode
      ? 'Your IP is a Tor exit node'
      : blocklisted
      ? 'Your IP is blocklisted'
      : 'Not detected',
    triggered: torNode || blocklisted,
    detail: torNode ? signals.torOperator : blocklisted ? signals.ipBlocklistReasons?.[0] : undefined,
  });

  const envelope = (data as { envelope?: { network?: { proxy?: boolean } } }).envelope;
  // The canonical envelope is authoritative; only older responses without it use legacy flags.
  const proxy = envelope?.network
    ? Boolean(envelope.network.proxy)
    : Boolean(
        (signals as unknown as { proxyDetected?: boolean }).proxyDetected ||
          (signals.networkType === 'VPN / Proxy Relay' && !signals.vpnSuspected)
      );
  // Surface the server's additive `proxy_details` verbatim when it supplied one. Only real
  // reason / type strings reach the tile; a missing mirror falls back to the legacy detail.
  const proxyMirror = canonicalView.proxy_details;
  const proxyMirrorReason =
    typeof proxyMirror?.reason === 'string' && proxyMirror.reason.trim()
      ? proxyMirror.reason
      : Array.isArray(proxyMirror?.reasons)
      ? proxyMirror.reasons.find(
          (reason): reason is string => typeof reason === 'string' && reason.trim().length > 0
        )
      : undefined;
  const proxyType =
    typeof proxyMirror?.proxy_type === 'string' && proxyMirror.proxy_type !== 'none'
      ? proxyMirror.proxy_type.replace(/_/g, ' ')
      : undefined;
  const proxyDetailParts = [proxyMirrorReason, proxyType ? `type: ${proxyType}` : undefined].filter(
    (part): part is string => Boolean(part)
  );
  rows.push({
    key: 'proxy',
    label: 'Proxy Detection',
    status: proxy ? 'Yes' : 'Not detected',
    triggered: proxy,
    detail: proxy
      ? proxyDetailParts.length > 0
        ? proxyDetailParts.join(' · ')
        : signals.proxyReasons?.[0] || signals.networkType || undefined
      : undefined,
  });

  const highActivity = Boolean(data.highActivityDevice ?? signals.highActivityDevice);
  // The server's threshold regime/value is appended verbatim as context only — it never
  // changes the high-activity verdict or its tile status.
  const thresholdDetail =
    canonicalView.high_activity_threshold_mode != null
      ? `Threshold ${canonicalView.high_activity_threshold_mode}${
          canonicalView.high_activity_threshold != null
            ? ` (${canonicalView.high_activity_threshold})`
            : ''
        }`
      : undefined;
  rows.push({
    key: 'highActivityDevice',
    label: 'High-Activity Device',
    status: highActivity ? 'Yes' : 'Not detected',
    triggered: highActivity,
    detail:
      [
        data.velocity ? `${data.velocity.events['24_hours']} events in 24 hours` : undefined,
        thresholdDetail,
      ]
        .filter((part): part is string => part != null)
        .join(' · ') || undefined,
  });

  const rare = Boolean(data.rareDevice ?? signals.rareDevice);
  rows.push({
    key: 'rareDevice',
    label: 'Rare Device',
    status: rare ? 'Yes' : 'Not detected',
    triggered: rare,
    detail: rare && data.rareDevicePercentileBucket
      ? `Hardware rarity ${data.rareDevicePercentileBucket}`
      : undefined,
  });

  // Active call state is observable only in runtimes that expose it; otherwise the row is
  // pruned from the grid entirely instead of advertising an unmeasurable capability.
  const activeCallSupported = Boolean(data.activeCallSupported ?? signals.activeCallSupported);
  if (activeCallSupported) {
    const activeCall = Boolean(data.activeCall ?? signals.activeCall);
    rows.push({
      key: 'activeCall',
      label: 'Active Call Detection',
      status: activeCall ? 'Yes' : 'Not detected',
      triggered: activeCall,
      detail: signals.activeCallReasons?.[0],
    });
  }

  const velocity = data.velocity;
  const velocityStatus = velocity
    ? `${velocity.distinct_ip['24_hours']} IP${
        velocity.distinct_ip['24_hours'] === 1 ? '' : 's'
      }, ${velocity.distinct_linked_id['24_hours']} Linked ID${
        velocity.distinct_linked_id['24_hours'] === 1 ? '' : 's'
      } in the past 24 hours`
    : 'Collecting persistence windows';
  rows.push({
    key: 'velocity',
    label: 'Velocity Signals',
    status: velocityStatus,
    triggered: false,
    tone: 'clean',
  });

  // Both risk tiles mirror the SAME canonical 0-10 headline and tier verbatim from the risk
  // ledger (the exact values App.tsx headlines and publishes to the Event JSON). A missing
  // headline stays unavailable — never a client-derived 0, and no tier is ever derived from
  // a score on the client.
  const rawScore10 = canonicalView.riskScore10;
  const suspectScore10: number | null =
    typeof rawScore10 === 'number' && Number.isFinite(rawScore10) ? rawScore10 : null;
  const riskTier: RiskTier | null = canonicalView.riskTier;
  // Confidence copy is bound to the server's own `confidence_label`, never recomputed from a
  // score. A null / absent / placeholder label means the evidence is unavailable — it is NOT
  // rendered as 0% (a fabricated zero would imply a measured but empty match). Calibration
  // evidence stays an appended detail only; the 0-10 headline is untouched.
  const serverConfidenceLabel = confidenceLabelOrNull(
    canonicalView.confidenceLabel ?? canonicalView.confidence_label
  );
  const confidenceCopy = serverConfidenceLabel ?? 'Match evidence unavailable';
  const calibrationMirror = canonicalView.calibration_evidence;
  const calibrationDetail =
    calibrationMirror != null
      ? [
          calibrationMirror.eligible != null ? `eligible ${calibrationMirror.eligible}` : null,
          calibrationMirror.labeledPairs != null
            ? `labeled pairs ${calibrationMirror.labeledPairs}`
            : null,
          calibrationMirror.ece != null ? `ECE ${calibrationMirror.ece}` : null,
          calibrationMirror.brier != null ? `Brier ${calibrationMirror.brier}` : null,
          calibrationMirror.reason != null ? calibrationMirror.reason : null,
        ]
          .filter((part): part is string => part != null)
          .join(' · ')
      : undefined;
  const riskTone: SmartSignalRowData['tone'] =
    riskTier === 'High' || riskTier === 'Critical'
      ? 'trigger'
      : riskTier === 'Elevated'
      ? 'neutral'
      : riskTier === 'Low'
      ? 'clean'
      : 'neutral';
  rows.push({
    key: 'suspectScore',
    label: 'Suspect Score',
    status: suspectScore10 === null ? 'Unavailable' : `${suspectScore10}/10`,
    triggered: riskTier === 'High' || riskTier === 'Critical',
    tone: suspectScore10 === null ? 'neutral' : riskTone,
    detail: [confidenceCopy, calibrationDetail].filter(Boolean).join(' · '),
  });
  rows.push({
    key: 'riskTier',
    label: 'Risk Tier',
    status: riskTier ?? 'Unavailable',
    triggered: riskTier === 'High' || riskTier === 'Critical',
    tone: riskTone,
    detail: suspectScore10 === null ? 'Unavailable' : `Canonical score ${suspectScore10}/10`,
  });

  // Proximity is EXCLUSIVELY a browser-granted geolocation observation. IP-derived city /
  // geohash zone is never proximity evidence, so neither is read here. The tile requires an
  // explicit granted permission AND real browser-supplied coordinates; without both it
  // reports the same honest no-proximity state regardless of the egress location.
  const proximityTransport = asRecord(data.proximity);
  const permissionRaw =
    canonicalView.geolocationPermission ??
    proximityTransport?.permission ??
    proximityTransport?.geolocationPermission ??
    proximityTransport?.geolocation_permission;
  const permission = typeof permissionRaw === 'string' ? permissionRaw.trim().toLowerCase() : '';
  const grantedRaw =
    canonicalView.grantedGeolocation ??
    proximityTransport?.grantedGeolocation ??
    proximityTransport?.granted_geolocation ??
    proximityTransport?.coordinates;
  const granted = asRecord(grantedRaw);
  // The canonical GrantedGeolocation shape is { lat, lon, accuracyM }; the legacy
  // { latitude, longitude } spelling is accepted as a transport fallback only.
  const grantedLatitude = granted?.lat ?? granted?.latitude;
  const grantedLongitude = granted?.lon ?? granted?.longitude;
  const hasCoordinates =
    typeof grantedLatitude === 'number' &&
    Number.isFinite(grantedLatitude) &&
    typeof grantedLongitude === 'number' &&
    Number.isFinite(grantedLongitude);
  const proximityGranted = permission === 'granted' && hasCoordinates;
  const accuracyRaw =
    canonicalView.accuracy_m ??
    proximityTransport?.accuracy_m ??
    granted?.accuracyM ??
    granted?.accuracy_m;
  const accuracy =
    typeof accuracyRaw === 'number' && Number.isFinite(accuracyRaw) ? accuracyRaw : null;
  const proximityStatus = proximityGranted
    ? `Granted${accuracy !== null ? ` · accuracy ±${accuracy} m` : ''}`
    : 'No proximity (permission required/denied)';
  rows.push({
    key: 'proximity',
    label: 'Proximity Detection',
    status: proximityStatus,
    triggered: false,
    tone: proximityGranted ? 'clean' : 'neutral',
  });

  // Research-only WebGPU disclosure and benchmark policy are appended verbatim as context
  // on this existing evidence-link row (no new panel). They are not verdicts and no probe
  // or claim derivation happens on the client.
  const benchmarkPolicy = canonicalView.benchmark_policy;
  const benchmarkDetail =
    benchmarkPolicy != null
      ? [
          benchmarkPolicy.notEvaluableRate != null
            ? `not-evaluable ${benchmarkPolicy.notEvaluableRate}`
            : null,
          benchmarkPolicy.claim != null ? `claim ${benchmarkPolicy.claim}` : null,
        ]
          .filter((part): part is string => part != null)
          .join(' · ')
      : undefined;
  rows.push({
    key: 'rawDeviceAttributes',
    label: 'Raw Device Attributes',
    status: 'See the JSON below',
    triggered: false,
    tone: 'neutral',
    detail:
      [canonicalView.webgpu_research_disclosure ?? undefined, benchmarkDetail || undefined]
        .filter((part): part is string => part != null)
        .join(' · ') || undefined,
    jsonAnchor: true,
  });

  return rows;
}

export function SmartSignalsGrid({ data }: { data: IntelVisitorResponse }) {
  const rows = buildSmartSignalRows(data);

  return (
    <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-2">
      {rows.map((row) => {
        const content = (
          <>
            <div className="min-w-0">
              <span className="block text-[11px] font-medium text-slate-500">
                {row.label}
                {row.badge && (
                  <span
                    className="ml-1.5 inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-1.5 py-0.5 align-middle text-[9px] font-medium text-slate-600"
                    title="Informational only — signed / verified identity from bot_info"
                  >
                    {row.badge}
                  </span>
                )}
              </span>
              {row.detail && (
                <span className="block text-[10px] text-slate-400 truncate" title={row.detail}>
                  {row.detail}
                </span>
              )}
            </div>
            <span
              className={`inline-flex items-center justify-end text-right max-w-[62%] text-[11px] font-mono font-semibold px-2 py-1 rounded-md border leading-snug shrink-0 ${toneClass(
                row.tone ?? (row.triggered ? 'trigger' : 'clean')
              )}`}
            >
              {row.status}
            </span>
          </>
        );

        return row.jsonAnchor ? (
          <a
            key={row.key}
            href="#raw-json"
            className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg border border-[#E5E7EB] bg-[#F8FAFC] hover:bg-slate-100 transition-colors"
          >
            {content}
          </a>
        ) : (
          <div
            key={row.key}
            className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg border border-[#E5E7EB] bg-[#F8FAFC]"
          >
            {content}
          </div>
        );
      })}
    </div>
  );
}

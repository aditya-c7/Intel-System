/**
 * Phase 7 — single-truth adapter for the canonical telemetry envelope.
 *
 * The Worker/Express backend adds the axes defined in `src/lib/telemetryContract.ts`
 * to the identify response. Those fields may arrive under `telemetry` / `canonical` /
 * `envelope`, or be mirrored at the response root. This module is the ONLY place the
 * dashboard resolves them. Every panel and the Event JSON read the same `CanonicalView`,
 * so no displayed value can disagree with `#raw-json` and nothing is re-derived on the
 * client. Before the backend fields land, every axis degrades to an honest unavailable /
 * warmup state instead of a fabricated score.
 */

import type {
  AutomationAxes,
  CanonicalTelemetryEnvelope,
  EnvironmentAxes,
  GpuObservation,
  IdentityAxes,
  InspectorState,
  InspectorStateTristate,
  NetworkAxes,
  OrthogonalRiskLedger,
  RiskTier,
  TamperingAxes,
  VerdictTier,
} from '../lib/telemetryContract';
import type { IntelVisitorResponse } from '../types/visitor';

export const SWIFTSHADER_LABEL = 'Software-Rendered Graphics (SwiftShader)';

const VERDICT_TIERS: readonly string[] = [
  'Verified Automation',
  'Tampered / Spoofed Environment',
  'Verified Human Interactive Session',
  'Unverified / Passive Session',
];

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function finiteNumber(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

export interface CanonicalView {
  /** True when the backend supplied canonical axes at all. */
  present: boolean;
  source: 'canonical' | 'legacy' | 'empty';
  eventId: string | null;
  risk: OrthogonalRiskLedger;
  /** Verbatim mirror of `risk.evidence_ledger` for the UI / Event JSON (never re-derived). */
  evidenceLedger: OrthogonalRiskLedger['evidence_ledger'];
  /** 0-10 headline mirrored verbatim from the canonical risk ledger (never re-derived). */
  riskScore10: number;
  /** Risk tier mirrored verbatim from the canonical risk ledger. */
  riskTier: RiskTier;
  verdictTier: VerdictTier | null;
  humanCorroboration: 0 | 1 | null;
  identity: IdentityAxes | null;
  automation: AutomationAxes | null;
  tampering: TamperingAxes | null;
  network: NetworkAxes | null;
  environment: EnvironmentAxes | null;
  confidenceTier: string;
  confidenceScore: number | null;
  calibrationStatus: 'uncalibrated' | 'calibrated';
  tamperingReasons: string[];
  serverVerified: Record<string, unknown>;
  clientClaimed: Record<string, unknown>;
  reconciledDisplay: Record<string, unknown>;
  /* Additive agent-identification mirrors (all OPTIONAL — legacy payloads stay valid).
     Read straight from the canonical envelope; the client never re-derives an identity.
     `source` above already carries the envelope resolution source. */
  bot_info?: AutomationAxes['bot_info'];
  aiAgent?: AutomationAxes['aiAgent'];
  verifiedAgentId?: string | null;
  signatureStatus?: string;
  cdpAttached?: boolean;
  inspectorState?: InspectorStateTristate | InspectorState | null;
  /** Server-resolved developer-tools verdict from the automation axis (verbatim). */
  developerTools?: boolean;
  /** Canonical GPU observation bucket from the envelope axis (verbatim). */
  gpuObservation?: GpuObservation | null;
  /** Server timezone-mismatch verdict from the network axis (verbatim). */
  timezoneMismatchCanonical?: boolean;
  osTruth?: Record<string, unknown>;
}

/** Resolve the one canonical envelope from every supported response shape. */
export function resolveCanonical(data: IntelVisitorResponse | null): CanonicalView {
  const base = asRecord(data);
  let env: Record<string, unknown> | null = null;
  let source: CanonicalView['source'] = 'empty';

  if (base) {
    for (const key of ['telemetry', 'canonical', 'envelope', 'canonical_telemetry']) {
      const candidate = asRecord(base[key]);
      if (candidate && (candidate.risk || candidate.verdict_tier || candidate.identity)) {
        env = candidate;
        source = 'canonical';
        break;
      }
    }
    if (!env && (base.risk || base.verdict_tier || base.identity)) {
      env = base;
      source = 'canonical';
    }
    if (!env) source = 'legacy';
  }

  const riskRaw = asRecord(env?.risk);
  // Root-level mirrors (`score_0_100`, `raw_score`, `evidence_ledger`) are accepted only as
  // a transport fallback — never as a source for client-side recomputation.
  const riskRoot: Record<string, unknown> | null = riskRaw
    ? null
    : base && (base.score_0_100 !== undefined || base.raw_score !== undefined)
    ? base
    : null;
  const identityRaw = asRecord(env?.identity);
  const automationRaw = asRecord(env?.automation);
  const tamperingRaw = asRecord(env?.tampering);
  const networkRaw = asRecord(env?.network);
  const environmentRaw = asRecord(env?.environment);

  // The 0-100 ledger is canonical. Before it lands, the server's own
  // `suspectScore100` is the only acceptable server-provided fallback — never a
  // client-side recomputation of the card scores.
  const legacyScore =
    typeof data?.suspectScore100 === 'number' ? finiteNumber(data.suspectScore100) : 0;
  const canonicalScore = riskRaw
    ? finiteNumber(riskRaw.score_0_100)
    : riskRoot
    ? finiteNumber(riskRoot.score_0_100)
    : legacyScore;
  const score = clampScore(canonicalScore);

  // The canonical risk ledger itself is the single source for the 0-10 headline, its tier
  // mirror and the evidence lines. Every value below is an `as unknown as` pass-through from
  // that server axis: the client never rounds a score, derives a tier from the family cards,
  // or tier-shifts a server-supplied value.
  const canonicalRisk = (riskRaw ?? riskRoot) as unknown as OrthogonalRiskLedger | null;
  const riskScore10 = canonicalRisk?.score10 as unknown as number;
  const riskTier = (canonicalRisk?.risk_tier ?? canonicalRisk?.tier) as unknown as RiskTier;
  const evidenceLedger: OrthogonalRiskLedger['evidence_ledger'] = Array.isArray(
    riskRaw?.evidence_ledger ?? riskRoot?.evidence_ledger
  )
    ? ((riskRaw?.evidence_ledger ??
        riskRoot?.evidence_ledger) as unknown as OrthogonalRiskLedger['evidence_ledger'])
    : [];

  const risk: OrthogonalRiskLedger = {
    automation: finiteNumber(riskRaw?.automation),
    tampering: finiteNumber(riskRaw?.tampering),
    network: finiteNumber(riskRaw?.network),
    environment: finiteNumber(riskRaw?.environment),
    velocity: finiteNumber(riskRaw?.velocity),
    raw_score: finiteNumber(riskRaw?.raw_score ?? riskRoot?.raw_score) || score,
    score_0_100: score,
    tier: canonicalRisk?.tier as unknown as RiskTier,
    evidence_ledger: evidenceLedger,
    // Optional server-supplied mirrors — pass-through only, never recomputed on the client.
    score10: riskScore10,
    risk_tier: riskTier,
  };

  const verdict = typeof env?.verdict_tier === 'string' && VERDICT_TIERS.includes(env.verdict_tier)
    ? (env.verdict_tier as VerdictTier)
    : null;

  const automation = automationRaw as unknown as AutomationAxes | null;
  const tampering = tamperingRaw as unknown as TamperingAxes | null;
  const network = networkRaw as unknown as NetworkAxes | null;
  const environment = environmentRaw as unknown as EnvironmentAxes | null;
  const identity = identityRaw as unknown as IdentityAxes | null;

  const corroborationRaw = automationRaw?.human_corroboration ?? base?.human_corroboration;
  const humanCorroboration: 0 | 1 | null =
    corroborationRaw === 1 || corroborationRaw === 0
      ? corroborationRaw
      : typeof data?.securitySignals?.humanCorroboration === 'number'
      ? data.securitySignals.humanCorroboration >= 0.5
        ? 1
        : 0
      : null;

  const tamperingReasons = tamperingRaw
    ? stringArray(tamperingRaw.reasons)
    : stringArray(data?.tamperingDetails?.reasons);

  // Identity confidence is the server's calibrated value from the canonical envelope's
  // `identity` axis. Mirror it verbatim with an `as unknown as` pass-through (0..1 or null):
  // a null score stays null, and the client never applies its own gate, floor or recomputation.
  const confidenceTier = (identityRaw?.confidence_tier ??
    'New Unobserved Profile') as unknown as string;
  const confidenceScore = (identityRaw?.confidence_score ?? null) as unknown as number | null;
  const calibrationStatus = (identityRaw?.calibration_status ?? 'uncalibrated') as unknown as
    | 'uncalibrated'
    | 'calibrated';

  return {
    present: source === 'canonical',
    source,
    eventId: typeof env?.event_id === 'string' ? env.event_id : null,
    risk,
    evidenceLedger,
    riskScore10,
    riskTier,
    verdictTier: verdict,
    humanCorroboration,
    identity,
    automation,
    tampering,
    network,
    environment,
    confidenceTier,
    confidenceScore,
    calibrationStatus,
    tamperingReasons,
    serverVerified: asRecord(env?.server_verified) ?? {},
    clientClaimed: asRecord(env?.client_claimed) ?? {},
    reconciledDisplay: asRecord(env?.reconciled_display) ?? {},
    // Additive mirrors — no recomputation, only pass-through from the one canonical axes.
    bot_info: automation?.bot_info ?? null,
    aiAgent: automation?.aiAgent ?? null,
    verifiedAgentId: automation?.verifiedAgentId ?? null,
    signatureStatus: automation?.signatureStatus,
    cdpAttached: automationRaw?.cdp_attached as unknown as boolean | undefined,
    inspectorState: (env?.inspectorState ?? automationRaw?.inspector_state ?? null) as unknown as
      | InspectorStateTristate
      | InspectorState
      | null,
    developerTools: automationRaw?.developer_tools as unknown as boolean | undefined,
    gpuObservation: (env?.gpuObservation ?? null) as unknown as GpuObservation | null,
    timezoneMismatchCanonical: networkRaw?.timezone_mismatch as unknown as boolean | undefined,
    osTruth: automation
      ? {
          serverVerifiedOs: automation.serverVerifiedOs,
          serverVerifiedBrowser: automation.serverVerifiedBrowser,
          hostOs: automation.hostOs,
          architecture: automation.architecture,
          architectureSource: automation.architectureSource,
          osUaMismatch: automation.osUaMismatch,
          archUaMismatch: automation.archUaMismatch,
          headerMismatch: automation.headerMismatch,
          engine: automation.engine,
        }
      : {},
  };
}

/** Spoof quarantine label used by both the DOM and the Event JSON. */
export function quarantineClaim(value: unknown, blocked: boolean): unknown {
  if (!blocked) return value;
  if (value === null || value === undefined || value === '') {
    return '[Unverified - Tampered Session]';
  }
  return `[Spoofed JS Claim Blocked: Reported ${String(value)}]`;
}

/** Quarantine every client-claimed raw attribute when the session is tampered. */
export function quarantineAttributes(raw: unknown, blocked: boolean): unknown {
  if (!blocked) return raw;
  const record = asRecord(raw);
  if (record) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record)) out[key] = quarantineClaim(record[key], true);
    out._session_integrity = '[Unverified - Tampered Session]';
    return out;
  }
  return quarantineClaim(raw, true);
}

/** Stable network provenance strings derived only from canonical axes. */
export function networkAxes(view: CanonicalView) {
  const n = view.network;
  const hosting =
    n?.network_ownership === 'hosting_datacenter'
      ? `Hosting / Datacenter ASN${n.bgp_asn ? ` · ${n.bgp_asn}` : ''}${
          n.bgp_asn_org ? ` · ${n.bgp_asn_org}` : ''
        }`
      : n?.bgp_asn
      ? `ASN ${n.bgp_asn}${n.bgp_asn_org ? ` · ${n.bgp_asn_org}` : ''}`
      : 'Unavailable';
  const rdap = n?.rdap_netblock_org
    ? `${n.rdap_netblock_org}${
        n.netblock_reassignment_mismatch ? ' · reassignment mismatch' : ''
      }`
    : 'Unavailable';
  // A negative VPN result with low confidence is never upgraded to a residential claim.
  const vpn = n?.vpn
    ? `VPN / relay detected (${n.vpn_confidence ?? 'low'} confidence)`
    : n?.vpn_confidence === 'high'
    ? 'No VPN detected (high confidence)'
    : 'No VPN detected (low confidence)';
  const proxy = n?.proxy
    ? `Proxy rotation detected${n.proxy_type && n.proxy_type !== 'none' ? ` · ${n.proxy_type}` : ''}`
    : 'No proxy rotation detected';
  const timezone = n?.timezone_mismatch ? 'Timezone discrepancy detected' : 'No timezone discrepancy';
  return { hosting, rdap, vpn, proxy, timezone, rdapDiffers: Boolean(n?.rdap_netblock_org && n.bgp_asn_org && n.rdap_netblock_org !== n.bgp_asn_org) };
}

/** True only for software rasterizers — never tampering, never hard VM proof. */
export function isSwiftShader(raw: string | null | undefined): boolean {
  return typeof raw === 'string' && /swiftshader/i.test(raw);
}

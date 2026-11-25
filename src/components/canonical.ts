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
  BenchmarkPolicyMirror,
  CalibrationEvidenceMirror,
  EnvironmentAxes,
  GpuObservation,
  HighActivityThresholdMode,
  IdentityAxes,
  IncognitoDiagnostics,
  InspectorState,
  InspectorStateTristate,
  NetworkAxes,
  OrthogonalRiskLedger,
  PrivacySettingsMirror,
  ProxyDetailsMirror,
  RiskTier,
  StealthSignalsMirror,
  TamperingAxes,
  TamperingDetailsMirror,
  VerdictTier,
  VpnMethodsMirror,
  WbaStatusMirror,
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

/**
 * Transports that may carry the newest server blocks. The resolved canonical envelope is
 * authoritative; the response root, a dedicated `server` / `server_truth` block, the hardware
 * / environment axes and the legacy `securitySignals` mirror are transport fallbacks only.
 * Every value read through here is an `as unknown as` pass-through: a field the server omitted
 * stays undefined and a field it supplied as null stays null.
 */
function serverTransportBlocks(
  base: Record<string, unknown> | null,
  env: Record<string, unknown> | null,
  truthEnv: Record<string, unknown> | null,
  signalExtras: Record<string, unknown>,
  axes: Array<Record<string, unknown> | null>
): Record<string, unknown>[] {
  return [
    truthEnv,
    env,
    asRecord(env?.server),
    asRecord(truthEnv?.server),
    base,
    asRecord(base?.server),
    asRecord(base?.server_truth),
    ...axes,
    signalExtras,
  ].filter((block): block is Record<string, unknown> => block != null);
}

/** First *present* value (undefined means absent; an explicit null is a supplied value). */
function pickServerValue(blocks: Record<string, unknown>[], keys: string[]): unknown {
  for (const block of blocks) {
    for (const key of keys) {
      const value = block[key];
      if (value !== undefined) return value;
    }
  }
  return undefined;
}

export interface CanonicalView {
  /** True when the backend supplied canonical axes at all. */
  present: boolean;
  source: 'canonical' | 'legacy' | 'empty';
  eventId: string | null;
  risk: CanonicalRiskLedger;
  /** Verbatim mirror of `risk.evidence_ledger` for the UI / Event JSON (never re-derived). */
  evidenceLedger: OrthogonalRiskLedger['evidence_ledger'];
  /** 0-10 headline mirrored verbatim from the canonical risk ledger (never re-derived). */
  riskScore10: number | null | undefined;
  /** Risk tier mirrored verbatim from the canonical risk ledger. */
  riskTier: RiskTier | null;
  verdictTier: VerdictTier | null;
  humanCorroboration: 0 | 1 | null;
  identity: IdentityAxes | null;
  automation: AutomationAxes | null;
  tampering: TamperingAxes | null;
  network: NetworkAxes | null;
  environment: EnvironmentAxes | null;
  /** Server identity tier only — null when the identity axis is absent (never fabricated). */
  confidenceTier: string | null;
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
  /** Canonical GPU observation bucket from the envelope axis (verbatim pass-through). */
  gpuObservation?: GpuObservation | null;
  /** Server timezone-mismatch verdict from the network axis (verbatim). */
  timezoneMismatchCanonical?: boolean;
  /** Raw `os_truth` block from the server envelope / new server transport, verbatim. */
  osTruth?: Record<string, unknown>;
  os_truth?: Record<string, unknown> | null;

  /* Newer server provenance / honesty mirrors — ALL OPTIONAL and read-only. As with every
     other additive field here, the value is an `as unknown as` pass-through from the one
     canonical envelope (or its response transports). A field the server did not supply stays
     undefined exactly as the server left it; no Boolean()/Number() coercion, no default and
     no client-side derivation is ever applied. Both snake_case and camelCase spellings are
     exposed so every consumer reads the exact same mirrored value/reference. */
  /** True only when the server says the renderer string came from spoofable WebGL reporting. */
  renderer_reported_unverified?: boolean | null;
  rendererReportedUnverified?: boolean | null;
  /** Source-control revision of the build that emitted the response. */
  build_sha?: string | null;
  buildSha?: string | null;
  /** Version of the worker / edge that emitted the response. */
  worker_version?: string | null;
  workerVersion?: string | null;
  /** Server's human-facing, uncalibrated confidence copy (`Match evidence N%` / null). */
  confidence_label?: string | null;
  confidenceLabel?: string | null;
  /** Additive incognito probe diagnostics mirrored verbatim from the canonical envelope/data. */
  diagnostics?: IncognitoDiagnostics;

  /* Additive truth / observation transports — ALL OPTIONAL and read-only. Each value is an
     `as unknown as` pass-through from the one canonical envelope (or its response mirrors).
     The client never derives, rounds, coerces or fabricates any of them: a server field that
     was not supplied stays undefined exactly as the server left it. */
  /** Server GPU truth bucket (hardware | software_renderer | masked | spoofed_suspect | unknown). */
  gpu_truth_state?: string | null;
  /** True only when the server says the GPU answer is masked / spoofed / unobservable. */
  gpu_answer_unreliable?: boolean | null;
  /** Normalized headless variant ('shell' | 'new' | null) from identity resolution. */
  headless_mode?: string | null;
  /** Explicit browser geolocation permission state (granted / prompt / denied). */
  geolocationPermission?: string | null;
  /** Browser-granted fix only — never IP-derived coordinates. Verbatim server shape. */
  grantedGeolocation?: Record<string, unknown> | null;
  /** Accuracy in metres of the granted geolocation fix (when the server supplied one). */
  accuracy_m?: number | null;
  /** Flat mirror of the fired privacy-signature tokens. Informational only, never a verdict. */
  privacy_signature_ids?: string[] | null;
  /** Structured media-preference readout, verbatim. */
  media_preferences?: Record<string, unknown> | null;
  /** Server's active-CDP-inspection verdict, verbatim (distinct from cdpAttached). */
  active_cdp_inspection?: boolean | null;
  /** Identity-scope verdict, verbatim. */
  id_scope?: string | null;
  /** Isolated-context verdict, verbatim. */
  context_isolated?: boolean | null;
  /** Audio-stability classification, verbatim. */
  audio_stability_class?: string | null;
  /** Confidence-stability key, verbatim. */
  confidence_stability_key?: string | null;

  /* Additive evidence mirrors — all OPTIONAL, verbatim `as unknown as` pass-through from the
     one canonical envelope or the response data. These are transports for server-supplied
     values only: the client never derives, rounds, tier-shifts or computes any of them, and an
     absent value stays absent (undefined) instead of being fabricated. Each value is exposed
     under both the envelope's snake_case spelling and a camelCase alias so every consumer
     reads the exact same mirrored value/reference. */
  proxy_details?: ProxyDetailsMirror | null;
  proxyDetails?: ProxyDetailsMirror | null;
  vpn_methods?: VpnMethodsMirror | null;
  vpnMethods?: VpnMethodsMirror | null;
  privacy_settings?: boolean | PrivacySettingsMirror | null;
  privacySettings?: boolean | PrivacySettingsMirror | null;
  /** Four-tier stealth-evaluation mirror from the canonical envelope, verbatim. */
  stealth_signals?: StealthSignalsMirror | null;
  stealthSignals?: StealthSignalsMirror | null;
  /** Verbatim nested read of `stealth_signals.ids` (the server's observed stealth ids). */
  stealth_ids?: string[] | null;
  stealthIds?: string[] | null;
  tampering_details?: TamperingDetailsMirror | null;
  tamperingDetails?: TamperingDetailsMirror | null;
  network_layer_hash?: string | null;
  networkLayerHash?: string | null;
  /** Shadow-only IDB resolver rule id, mirrored verbatim — never a verdict input. */
  idbTruthRule?: string | null;

  /* Additive research / calibration / verification mirrors — verbatim pass-through only.
     The client never derives, coerces or fabricates any of them; absent stays undefined. */
  calibration_evidence?: CalibrationEvidenceMirror | null;
  high_activity_threshold_mode?: HighActivityThresholdMode | null;
  high_activity_threshold?: number | null;
  wba_status?: WbaStatusMirror;
  official_bot_feed_match?: string[] | null;
  webgpu_research_disclosure?: string | null;
  benchmark_policy?: BenchmarkPolicyMirror | null;
}

/**
 * The server risk ledger with honest absence. A response that omits `score_0_100`, `raw_score`
 * or the tier mirrors must keep them absent (null) — the client never fills them with a
 * fabricated zero or a derived tier.
 */
export type CanonicalRiskLedger = Omit<
  OrthogonalRiskLedger,
  'raw_score' | 'score_0_100' | 'tier' | 'score10' | 'risk_tier'
> & {
  raw_score: number | null;
  score_0_100: number | null;
  tier: RiskTier | null;
  score10?: number | null;
  risk_tier?: RiskTier | null;
};

const CANONICAL_RISK_TIERS: readonly string[] = ['Low', 'Elevated', 'High', 'Critical'];

/** Accept only a server tier from the canonical vocabulary; anything else stays absent. */
function canonicalRiskTier(value: unknown): RiskTier | null {
  return typeof value === 'string' && CANONICAL_RISK_TIERS.includes(value)
    ? (value as RiskTier)
    : null;
}

/**
 * The server-authored match-evidence copy, or null when no evidence label was supplied.
 * Placeholder "unavailable" strings are treated as absence so the UI's dashed unavailable
 * treatment applies; no confidence percentage is ever generated on the client.
 */
export function confidenceLabelOrNull(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (/^(match evidence unavailable|confidence unavailable|unavailable)$/i.test(trimmed)) {
    return null;
  }
  return trimmed;
}

/**
 * True only when EVERY server GPU truth axis independently confirms a physical renderer.
 * A raw WebGL renderer string is spoofable output; it is never hardware proof on its own.
 */
export function gpuTruthIsVerified(view: CanonicalView): boolean {
  const truth =
    typeof view.gpu_truth_state === 'string' ? view.gpu_truth_state.trim().toLowerCase() : '';
  const observation = view.gpuObservation;
  return (
    (truth === 'hardware' || truth === 'physical_hardware') &&
    view.gpu_answer_unreliable !== true &&
    view.renderer_reported_unverified !== true &&
    view.rendererReportedUnverified !== true &&
    observation !== 'masked_by_privacy' &&
    observation !== 'observation_unavailable'
  );
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

  // Additive evidence mirrors — verbatim pass-through, never derived. The resolved canonical
  // envelope is authoritative; root-level and `securitySignals` mirrors are transport fallbacks
  // only. `as unknown as` is used throughout because these fields are intentionally not part of
  // the typed legacy contract yet. No Boolean()/Number() coercion, rounding, tier mapping or
  // default fabrication: a missing field stays undefined exactly as the server left it.
  const signalExtras = (data?.securitySignals ?? {}) as unknown as Record<string, unknown>;
  // Additive truth fields can arrive on the same canonical envelope before its risk / identity
  // axes are populated. Read those transports from the envelope keys without changing the core
  // `source` / `present` decision above (no canonical axis is invented on the client).
  const truthEnv =
    env ??
    asRecord(base?.telemetry) ??
    asRecord(base?.canonical) ??
    asRecord(base?.envelope) ??
    asRecord(base?.canonical_telemetry);

  // Additive incognito diagnostics — verbatim `as unknown as` pass-through from the one
  // canonical envelope (or its data mirrors). Present only when the server supplied it;
  // otherwise undefined. Never re-derived, and never gated on a client-only session flag:
  // this is a read-only server record, not a client-side incognito verdict.
  const diagnosticsRaw =
    truthEnv?.diagnostics ??
    base?.diagnostics ??
    data?.diagnostics ??
    data?.securitySignals?.diagnostics ??
    signalExtras.diagnostics;
  const diagnostics = diagnosticsRaw ? (diagnosticsRaw as unknown as IncognitoDiagnostics) : undefined;
  const proxy_details = (env?.proxy_details ??
    base?.proxy_details ??
    base?.proxyDetails ??
    signalExtras.proxy_details ??
    signalExtras.proxyDetails) as unknown as ProxyDetailsMirror | null | undefined;
  const vpn_methods = (env?.vpn_methods ??
    base?.vpn_methods ??
    base?.vpnMethods ??
    signalExtras.vpn_methods ??
    signalExtras.vpnMethods) as unknown as VpnMethodsMirror | null | undefined;
  const privacy_settings = (env?.privacy_settings ??
    base?.privacy_settings ??
    base?.privacySettings ??
    signalExtras.privacy_settings ??
    signalExtras.privacySettings) as unknown as
    | boolean
    | PrivacySettingsMirror
    | null
    | undefined;
  const stealth_signals = (env?.stealth_signals ??
    base?.stealth_signals ??
    base?.stealthSignals ??
    signalExtras.stealth_signals ??
    signalExtras.stealthSignals) as unknown as StealthSignalsMirror | null | undefined;
  const stealth_ids = (env?.stealth_ids ??
    base?.stealth_ids ??
    base?.stealthIds ??
    stealth_signals?.ids ??
    base?.stealthReasons ??
    signalExtras.stealth_ids ??
    signalExtras.stealthIds ??
    signalExtras.stealthReasons) as unknown as string[] | null | undefined;
  const tampering_details = (env?.tampering_details ??
    base?.tampering_details ??
    base?.tamperingDetails ??
    data?.tamperingDetails ??
    signalExtras.tampering_details ??
    signalExtras.tamperingDetails) as unknown as TamperingDetailsMirror | null | undefined;
  const network_layer_hash = (env?.network_layer_hash ??
    base?.network_layer_hash ??
    base?.networkLayerHash ??
    base?.ja4h ??
    signalExtras.network_layer_hash ??
    signalExtras.networkLayerHash ??
    signalExtras.ja4h) as unknown as string | null | undefined;
  const idbTruthRule = (env?.idbTruthRule ??
    base?.idbTruthRule ??
    diagnostics?.idbTruthRule ??
    data?.diagnostics?.idbTruthRule ??
    data?.securitySignals?.diagnostics?.idbTruthRule) as unknown as string | null | undefined;

  // Additive research / calibration / verification mirrors — verbatim `as unknown as`
  // pass-through from the one canonical envelope (response transports are fallbacks only).
  // No Boolean()/Number() coercion, no re-derivation and no fabricated default: a field the
  // server did not supply stays undefined, and a `wba_status` of 'valid' is never inferred.
  const calibration_evidence = (env?.calibration_evidence ??
    base?.calibration_evidence ??
    signalExtras.calibration_evidence) as unknown as CalibrationEvidenceMirror | null | undefined;
  const high_activity_threshold_mode = (env?.high_activity_threshold_mode ??
    env?.highActivityThresholdMode ??
    base?.high_activity_threshold_mode ??
    base?.highActivityThresholdMode ??
    signalExtras.high_activity_threshold_mode) as unknown as HighActivityThresholdMode | null | undefined;
  const high_activity_threshold = (env?.high_activity_threshold ??
    base?.high_activity_threshold ??
    signalExtras.high_activity_threshold) as unknown as number | null | undefined;
  const wba_status = (env?.wba_status ??
    base?.wba_status ??
    signalExtras.wba_status) as unknown as WbaStatusMirror | undefined;
  const official_bot_feed_match = (env?.official_bot_feed_match ??
    base?.official_bot_feed_match ??
    signalExtras.official_bot_feed_match) as unknown as string[] | null | undefined;
  const webgpu_research_disclosure = (env?.webgpu_research_disclosure ??
    base?.webgpu_research_disclosure ??
    signalExtras.webgpu_research_disclosure) as unknown as string | null | undefined;
  const benchmark_policy = (env?.benchmark_policy ??
    base?.benchmark_policy ??
    signalExtras.benchmark_policy) as unknown as BenchmarkPolicyMirror | null | undefined;

  // Remaining additive truth / observation mirrors — every value below is a verbatim
  // `as unknown as` pass-through from the one canonical envelope or its response transports.
  // No Boolean()/Number() coercion, rounding, tier mapping or default fabrication is applied,
  // so a field the server did not supply stays undefined (and is absent from the Event JSON).
  const hardwareRaw = asRecord(data?.hardwareSignals);
  const browserIdentityRaw = asRecord(data?.browser_details);
  const proximityRaw = asRecord(truthEnv?.proximity ?? base?.proximity ?? data?.proximity);
  const privacyRaw = asRecord(privacy_settings);
  const privacySignalRaw = asRecord(signalExtras.privacySettings);

  // Newer server blocks (os_truth, renderer provenance, build/version, confidence copy).
  // These arrive in the canonical envelope or a dedicated `server` / `server_truth` block —
  // NOT only on the automation axis. Everything below is a verbatim pass-through: no Boolean /
  // Number coercion, no re-derivation and no fabricated default. The automation-derived OS
  // object remains a fallback so older payloads keep every existing mirror.
  const serverBlocks = serverTransportBlocks(
    base,
    env,
    truthEnv,
    signalExtras,
    [hardwareRaw, environmentRaw, automationRaw]
  );
  const rawOsTruth = pickServerValue(serverBlocks, ['os_truth', 'osTruth', 'server_os_truth']);
  const gpuObservationRaw = pickServerValue(serverBlocks, [
    'gpuObservation',
    'gpu_observation',
  ]);
  const rendererReportedUnverified = pickServerValue(serverBlocks, [
    'renderer_reported_unverified',
    'rendererReportedUnverified',
  ]) as unknown as boolean | null | undefined;
  const buildSha = pickServerValue(serverBlocks, [
    'build_sha',
    'buildSha',
  ]) as unknown as string | null | undefined;
  const workerVersion = pickServerValue(serverBlocks, [
    'worker_version',
    'workerVersion',
  ]) as unknown as string | null | undefined;
  // The confidence copy is authored by the identity resolver, so its nested identity block is
  // preferred; the flat envelope / response transports remain fallbacks.
  const identificationRaw = asRecord(base?.identification);
  const confidenceBlocks = [
    identityRaw,
    identificationRaw,
    asRecord(identificationRaw?.confidence),
    ...serverBlocks,
  ].filter((block): block is Record<string, unknown> => block != null);
  const confidenceLabel = pickServerValue(confidenceBlocks, [
    'confidence_label',
    'confidenceLabel',
  ]) as unknown as string | null | undefined;

  const gpu_truth_state = (truthEnv?.gpu_truth_state ??
    truthEnv?.gpuTruthState ??
    base?.gpu_truth_state ??
    base?.gpuTruthState ??
    automationRaw?.gpu_truth_state ??
    environmentRaw?.gpu_truth_state ??
    hardwareRaw?.gpu_truth_state ??
    signalExtras.gpu_truth_state) as unknown as string | null | undefined;
  const gpu_answer_unreliable = (truthEnv?.gpu_answer_unreliable ??
    truthEnv?.gpuAnswerUnreliable ??
    base?.gpu_answer_unreliable ??
    base?.gpuAnswerUnreliable ??
    environmentRaw?.gpu_answer_unreliable ??
    hardwareRaw?.gpu_answer_unreliable ??
    signalExtras.gpu_answer_unreliable) as unknown as boolean | null | undefined;
  const headless_mode = (truthEnv?.headless_mode ??
    truthEnv?.headlessMode ??
    base?.headless_mode ??
    base?.headlessMode ??
    identityRaw?.headless_mode ??
    browserIdentityRaw?.headless_mode ??
    automationRaw?.headless_mode ??
    signalExtras.headless_mode) as unknown as string | null | undefined;
  const geolocationPermission = (proximityRaw?.permission ??
    proximityRaw?.geolocationPermission ??
    proximityRaw?.geolocation_permission ??
    truthEnv?.geolocationPermission ??
    truthEnv?.geolocation_permission ??
    base?.geolocationPermission ??
    base?.geolocation_permission ??
    signalExtras.geolocationPermission ??
    signalExtras.geolocation_permission) as unknown as string | null | undefined;
  const grantedGeolocation = (proximityRaw?.coordinates ??
    proximityRaw?.grantedGeolocation ??
    proximityRaw?.granted_geolocation ??
    truthEnv?.grantedGeolocation ??
    truthEnv?.granted_geolocation ??
    base?.grantedGeolocation ??
    base?.granted_geolocation ??
    signalExtras.grantedGeolocation ??
    signalExtras.granted_geolocation) as unknown as Record<string, unknown> | null | undefined;
  const grantedRaw = asRecord(grantedGeolocation);
  const accuracy_m = (proximityRaw?.accuracy_m ??
    truthEnv?.accuracy_m ??
    truthEnv?.geolocationAccuracyM ??
    base?.accuracy_m ??
    base?.geolocationAccuracyM ??
    grantedRaw?.accuracyM ??
    grantedRaw?.accuracy_m ??
    signalExtras.accuracy_m ??
    signalExtras.geolocationAccuracyM) as unknown as number | null | undefined;
  const privacy_signature_ids = (truthEnv?.privacy_signature_ids ??
    base?.privacy_signature_ids ??
    privacyRaw?.privacy_signature_ids ??
    privacyRaw?.signatures ??
    privacySignalRaw?.privacy_signature_ids ??
    privacySignalRaw?.signatures ??
    signalExtras.privacy_signature_ids) as unknown as string[] | null | undefined;
  const media_preferences = (truthEnv?.media_preferences ??
    truthEnv?.mediaPreferences ??
    base?.media_preferences ??
    base?.mediaPreferences ??
    hardwareRaw?.media_preferences ??
    hardwareRaw?.mediaPreferences ??
    signalExtras.media_preferences ??
    signalExtras.mediaPreferences) as unknown as Record<string, unknown> | null | undefined;
  const active_cdp_inspection = (truthEnv?.active_cdp_inspection ??
    truthEnv?.activeCdpInspection ??
    base?.active_cdp_inspection ??
    base?.activeCdpInspection ??
    automationRaw?.active_cdp_inspection ??
    automationRaw?.activeCdpInspection ??
    signalExtras.active_cdp_inspection ??
    signalExtras.activeCdpInspection) as unknown as boolean | null | undefined;
  const id_scope = (truthEnv?.id_scope ??
    base?.id_scope ??
    identityRaw?.id_scope ??
    browserIdentityRaw?.id_scope ??
    signalExtras.id_scope) as unknown as string | null | undefined;
  const context_isolated = (truthEnv?.context_isolated ??
    base?.context_isolated ??
    identityRaw?.context_isolated ??
    browserIdentityRaw?.context_isolated ??
    signalExtras.context_isolated) as unknown as boolean | null | undefined;
  const audio_stability_class = (truthEnv?.audio_stability_class ??
    base?.audio_stability_class ??
    hardwareRaw?.audio_stability_class ??
    signalExtras.audio_stability_class) as unknown as string | null | undefined;
  const confidence_stability_key = (truthEnv?.confidence_stability_key ??
    base?.confidence_stability_key ??
    identityRaw?.confidence_stability_key ??
    hardwareRaw?.confidence_stability_key ??
    signalExtras.confidence_stability_key) as unknown as string | null | undefined;

  // The 0-100 ledger is canonical. Before it lands, the server's own
  // `suspectScore100` is the only acceptable server-provided fallback — never a
  // client-side recomputation of the card scores. Missing stays null: no finiteNumber(…)=0.
  const score100Raw = (riskRaw
    ? riskRaw.score_0_100
    : riskRoot
    ? riskRoot.score_0_100
    : data?.suspectScore100) as unknown;
  const score: number | null =
    typeof score100Raw === 'number' && Number.isFinite(score100Raw)
      ? clampScore(score100Raw)
      : null;

  // The canonical risk ledger itself is the single source for the 0-10 headline, its tier
  // mirror and the evidence lines. Every value below is an `as unknown as` pass-through from
  // that server axis: the client never rounds a score, derives a tier from the family cards,
  // or tier-shifts a server-supplied value. An absent mirror stays absent; an out-of-vocabulary
  // tier is dropped rather than invented.
  const canonicalRisk = (riskRaw ?? riskRoot) as unknown as OrthogonalRiskLedger | null;
  const riskScore10 = canonicalRisk?.score10 as unknown as number | null | undefined;
  const tier = canonicalRiskTier(canonicalRisk?.tier);
  const riskTier = canonicalRiskTier(canonicalRisk?.risk_tier) ?? tier;
  const evidenceLedger: OrthogonalRiskLedger['evidence_ledger'] = Array.isArray(
    riskRaw?.evidence_ledger ?? riskRoot?.evidence_ledger
  )
    ? ((riskRaw?.evidence_ledger ??
        riskRoot?.evidence_ledger) as unknown as OrthogonalRiskLedger['evidence_ledger'])
    : [];
  // `??` (never `||`): a server-reported raw_score of 0 is a real value, not an absence.
  const rawScoreRaw = (riskRaw?.raw_score ?? riskRoot?.raw_score) as unknown;
  const rawScore: number | null =
    typeof rawScoreRaw === 'number' && Number.isFinite(rawScoreRaw) ? rawScoreRaw : null;

  const risk: CanonicalRiskLedger = {
    automation: finiteNumber(riskRaw?.automation),
    tampering: finiteNumber(riskRaw?.tampering),
    network: finiteNumber(riskRaw?.network),
    environment: finiteNumber(riskRaw?.environment),
    velocity: finiteNumber(riskRaw?.velocity),
    raw_score: rawScore,
    score_0_100: score,
    tier,
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
  // When the identity axis is absent the tier is absent too — no "New Unobserved Profile"
  // tier is fabricated on the client.
  const confidenceTier = (identityRaw?.confidence_tier ?? null) as unknown as string | null;
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
    // Verbatim server observation bucket. The old envelope-only read is kept as the last
    // fallback, but the new server transports above win so a bucket emitted outside the
    // automation axis is no longer silently dropped.
    gpuObservation: (gpuObservationRaw !== undefined
      ? gpuObservationRaw
      : env?.gpuObservation ?? null) as unknown as GpuObservation | null,
    timezoneMismatchCanonical: networkRaw?.timezone_mismatch as unknown as boolean | undefined,
    // The server's `os_truth` block is authoritative when supplied (as-unknown-as pass-through).
    // The previous automation-axis projection is retained as a fallback so legacy payloads keep
    // every existing mirror and no client-side derivation is introduced.
    osTruth: (rawOsTruth !== undefined
      ? rawOsTruth
      : automation
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
      : {}) as unknown as Record<string, unknown>,
    os_truth: rawOsTruth as unknown as Record<string, unknown> | null | undefined,
    // Newer server mirrors — verbatim, both spellings share the exact same value/reference.
    renderer_reported_unverified: rendererReportedUnverified,
    rendererReportedUnverified,
    build_sha: buildSha,
    buildSha,
    worker_version: workerVersion,
    workerVersion,
    confidence_label: confidenceLabel,
    confidenceLabel,
    diagnostics,
    // Additive mirrors: same value/reference on both spellings, no recomputation. The risk
    // headline above (riskScore10 / riskTier / evidenceLedger) stays an independent pure
    // pass-through and is deliberately untouched here.
    proxy_details,
    proxyDetails: proxy_details,
    vpn_methods,
    vpnMethods: vpn_methods,
    privacy_settings,
    privacySettings: privacy_settings,
    stealth_signals,
    stealthSignals: stealth_signals,
    stealth_ids,
    stealthIds: stealth_ids,
    tampering_details,
    tamperingDetails: tampering_details,
    network_layer_hash,
    networkLayerHash: network_layer_hash,
    idbTruthRule,
    // Remaining additive mirrors: verbatim, no recomputation and no fabricated defaults.
    gpu_truth_state,
    gpu_answer_unreliable,
    headless_mode,
    geolocationPermission,
    grantedGeolocation,
    accuracy_m,
    privacy_signature_ids,
    media_preferences,
    active_cdp_inspection,
    id_scope,
    context_isolated,
    audio_stability_class,
    confidence_stability_key,
    // Additive research / calibration / verification mirrors — verbatim, no recomputation.
    calibration_evidence,
    high_activity_threshold_mode,
    high_activity_threshold,
    wba_status,
    official_bot_feed_match,
    webgpu_research_disclosure,
    benchmark_policy,
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

/**
 * Phase 0 — single canonical telemetry contract.
 *
 * Every request is parsed into this shape exactly once. The collector, the Express
 * identify handler, the Cloudflare Worker adapter, the generated API bundle and the
 * React dashboard all read these names; no module may re-derive a parallel verdict.
 *
 * This file is intentionally dependency-free so it can be imported from Node, the
 * browser bundle and the Worker adapter without pulling in platform APIs.
 */

export type RiskFamily = 'automation' | 'tampering' | 'network' | 'environment' | 'velocity';
export type RiskTier = 'Low' | 'Elevated' | 'High' | 'Critical';

export const RISK_FAMILY_CAPS: Readonly<Record<RiskFamily, number>> = {
  automation: 45,
  tampering: 35,
  network: 25,
  environment: 10,
  velocity: 15,
};

/** Exact graded rubric. Components may stack inside a family, subject to its cap. */
export const RISK_RUBRIC = {
  automation: {
    tier_a_hard_proof: 45,
    tier_b_corroborated_stealth: 35,
    none_or_passive: 0,
  },
  tampering: {
    tier_a_spec_header_or_drift: 35,
    tier_b_prototype_or_getter: 30,
    soft_warning: 15,
    none_or_privacy_hardened: 0,
  },
  network: {
    hosting_datacenter_asn: 10,
    commercial_vpn_or_relay: 12,
    rotating_or_residential_proxy: 18,
    timezone_mismatch_standalone: 5,
    timezone_mismatch_marginal: 2,
  },
  environment: {
    swiftshader_software_renderer: 8,
    ephemeral_or_private_storage: 4,
  },
  velocity: {
    high_activity: 12,
    extreme_rotation: 15,
  },
} as const;

export interface RiskEvidenceLine {
  family: RiskFamily;
  component: string;
  points: number;
  reason: string;
}

export interface OrthogonalRiskLedger {
  /** Per-family totals, each already clamped to RISK_FAMILY_CAPS. */
  automation: number;
  tampering: number;
  network: number;
  environment: number;
  velocity: number;
  /** Sum of the five family totals before the global ceiling. */
  raw_score: number;
  /** min(100, raw_score). */
  score_0_100: number;
  tier: RiskTier;
  /** Optional 0-10 headline score supplied by the canonical (server) ledger. */
  score10?: number;
  /** Optional canonical risk-tier mirror; same vocabulary as `tier`. */
  risk_tier?: RiskTier;
  evidence_ledger: RiskEvidenceLine[];
}

export function riskTier(score: number): RiskTier {
  if (score >= 75) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 25) return 'Elevated';
  return 'Low';
}

export function buildRiskLedger(lines: readonly RiskEvidenceLine[]): OrthogonalRiskLedger {
  const totals: Record<RiskFamily, number> = {
    automation: 0,
    tampering: 0,
    network: 0,
    environment: 0,
    velocity: 0,
  };
  for (const line of lines) {
    const safe = Number.isFinite(line.points) ? Math.max(0, line.points) : 0;
    totals[line.family] = Math.min(RISK_FAMILY_CAPS[line.family], totals[line.family] + safe);
  }
  const rawScore = Object.values(totals).reduce((sum, value) => sum + value, 0);
  const score = Math.min(100, Math.round(rawScore));
  return {
    ...totals,
    raw_score: Math.round(rawScore),
    score_0_100: score,
    tier: riskTier(score),
    evidence_ledger: lines.map((line) => ({ ...line })),
  };
}

/* -------------------------------------------------------------------------- */
/* Verdict axes                                                                */
/* -------------------------------------------------------------------------- */

export type VerdictTier =
  | 'Verified Automation'
  | 'Tampered / Spoofed Environment'
  | 'Verified Human Interactive Session'
  | 'Unverified / Passive Session';

export type InspectorState =
  | 'automation_protocol_attached'
  | 'devtools_docked_suspected'
  | 'devtools_active_verified'
  | 'closed';

/**
 * Additive coarse GPU observation bucket for the labeling / calibration record. This is the
 * normalized truth category, not a raw client-supplied WebGL vendor / renderer string, so it
 * can be compared across model and weight-config versions.
 */
export type GpuObservation =
  | 'hardware_visible'
  | 'masked_by_privacy'
  | 'observation_unavailable'
  | 'software_or_virtual';

/** Lowercase alias matching the canonical envelope field name. */
export type gpuObservation = GpuObservation;

/**
 * Additive tri-state inspector signal: positively attached, positively detached, or unknown.
 * Kept separate from the four-valued `InspectorState` so a consumer that only needs certainty
 * never has to interpret the "docked suspected" state.
 */
export type InspectorStateTristate = 'attached' | 'detached' | 'unknown';

/** Lowercase alias matching the canonical envelope field name. */
export type inspectorState = InspectorStateTristate;

export interface AutomationAxes {
  bot: 'not_detected' | 'suspected' | 'bad' | 'good' | 'ai_agent';
  bot_type: string | null;
  named_operator: string | null;
  operator_verification_method: 'rfc9421' | 'signed_agent' | 'allowlist' | 'none';
  automation_environment: string;
  human_corroboration: 0 | 1;
  interaction_evidence: string[];
  inspector_state: InspectorState;
  /** Raw protocol/inspector probe observations (Error.prototype.name preview, console timing). */
  inspector_probes: Record<string, unknown>;
  cdp_attached: boolean;
  developer_tools: boolean;

  /* ------------------------------------------------------------------------ */
  /* Additive agent-identification mirrors (all OPTIONAL — legacy payloads stay valid).
  /* These let the canonical envelope carry the exact named-agent verdict so the
  /* dashboard never re-derives an identity on the client. No envelope shape change.
  /* ------------------------------------------------------------------------ */
  /** Structured bot / AI-agent identification (mirrors the response's `bot_info`). */
  bot_info?: {
    category: string;
    provider: string;
    name: string;
    identity: 'verified' | 'signed' | 'unknown' | 'spoofed';
  } | null;
  /** Granular AI-agent attribution (mirrors `securitySignals.aiAgent`). */
  aiAgent?: {
    detected: boolean;
    agentId: string | null;
    agentName: string;
    operator: string;
    executionMode: string | null;
    verified: boolean;
    confidence: 'Verified' | 'High' | 'Medium';
    riskScore: number;
    evidence: string[];
  } | null;
  /** Which proof source produced the agent verdict (rfc9421 | signed_agent | cidr | fcrdns | ua_claim). */
  source?: string;
  /** Exact canonical registry id of the verified agent, when resolution succeeded. */
  verifiedAgentId?: string | null;
  /** Signature verification status (e.g. `verified` | `signed` | `none`). */
  signatureStatus?: string;

  /* OS / platform truth carried beside the automation verdict. */
  serverVerifiedOs?: string;
  serverVerifiedBrowser?: string;
  hostOs?: string | null;
  architecture?: string;
  architectureSource?: string;
  osUaMismatch?: boolean;
  archUaMismatch?: boolean;
  headerMismatch?: boolean;
  engine?: string;
}

export interface TamperingAxes {
  detected: boolean;
  anti_detect_browser: boolean;
  privacy_hardened: boolean;
  tampering_confidence: 'low' | 'medium' | 'high';
  tampering_ml_score: number;
  spec_violations: string[];
  reasons: string[];
  hard_spec_violation: boolean;
}

export interface NetworkAxes {
  network_ownership: 'residential_isp' | 'mobile_carrier' | 'hosting_datacenter' | 'enterprise' | 'unknown';
  bgp_asn: string | null;
  bgp_asn_org: string | null;
  rdap_netblock_org: string | null;
  netblock_reassignment_mismatch: boolean;
  vpn: boolean;
  vpn_confidence: 'low' | 'medium' | 'high';
  proxy: boolean;
  proxy_type: 'residential_rotating' | 'datacenter' | 'none';
  timezone_mismatch: boolean;
}

export interface EnvironmentAxes {
  software_renderer: boolean;
  software_renderer_label: string | null;
  ephemeral_storage: boolean;
  virtual_machine_label: string | null;
}

export interface IdentityAxes {
  match_stage:
    | 'storage_continuity'
    | 'exact_hardware'
    | 'lsh_fuzzy'
    | 'privacy_hardened'
    | 'new_enrollment';
  match_label: string;
  collision_risk: 'low' | 'high';
  confidence_tier:
    | 'First-Party Continuity Match'
    | 'High-Agreement Hardware Match'
    | 'Probabilistic Fuzzy Match'
    | 'Shared Hardware Class - Ambiguous'
    | 'Privacy-Hardened Profile (Reduced Entropy)'
    | 'New Unobserved Profile';
  /** null until a held-out calibration gate (ECE < 0.05) has passed. */
  confidence_score: number | null;
  calibration_status: 'uncalibrated' | 'calibrated';
}

/**
 * Additive diagnostic readout for incognito / private-mode detection. Every field beyond
 * `enabled` is OPTIONAL and nullable so a partially observed probe still yields a valid
 * record; no consumer re-derives these values from the envelope.
 */
export interface IncognitoDiagnostics {
  enabled: boolean;
  engine?: string | null;
  method?: string | null;
  confidence?: string | null;
  isPrivate?: boolean | null;
  quotaBytes?: number | null;
  headroomGiB?: number | null;
  idbDurabilityRatio?: number | null;
  idbHighVariance?: boolean | null;
  /** Shadow-only IDB resolver rule id; never a verdict input. */
  idbTruthRule?: string | null;
  opfsFlushMs?: number | null;
  persistedStorageGrant?: boolean | null;
  isolatedContextVeto?: boolean | null;
  sessionLockHit?: boolean | null;
  lowConfidenceVeto?: boolean | null;
  clientReportedIncognito?: boolean | null;
  serverWouldVeto?: boolean | null;
}

/* -------------------------------------------------------------------------- */
/* Additive integration mirrors (shapes mirror src/types/visitor.ts)           */
/* -------------------------------------------------------------------------- */

/**
 * These local shapes keep this module dependency-free: `visitor.ts` imports from here, so the
 * canonical envelope cannot import its interfaces back. Every member is OPTIONAL and the
 * vocabulary matches the corresponding `SecuritySignals` / response fields verbatim. Nothing
 * here is re-derived — a producer copies the server verdict across unchanged.
 */

/** Canonical proxy verdict mirror (`proxyDetected` / `proxyReasons` on the visitor response). */
export interface ProxyDetailsMirror {
  proxy?: boolean;
  /** Accepts both the legacy `datacenter` / `none` and the resolver's `data_center` vocabulary. */
  proxy_type?: string | null;
  confidence?: 'low' | 'medium' | 'high';
  reason?: string;
  reasons?: string[];
}

/** Server `vpnMethods` block mirror (the single source of truth for the VPN tile count). */
export interface VpnMethodsMirror {
  timezone_mismatch?: boolean;
  public_vpn?: boolean;
  auxiliary_mobile?: boolean;
  os_mismatch?: boolean;
  relay?: boolean;
  ml_prediction?: boolean;
  origin_country?: string | null;
  reasons?: string[];
}

/** Structured privacy-signature mirror; `privacy_settings` itself is also accepted as a boolean. */
export interface PrivacySettingsMirror {
  privacy_settings?: boolean;
  privacy_hardened?: boolean;
  signatures?: string[];
  suppressAntiDetectPenalty?: boolean;
  confidence?: 'high' | 'medium' | 'low';
  reasons?: string[];
}

/** Four-tier stealth-evaluation mirror (`stealthPluginDetected` on the visitor response). */
export interface StealthSignalsMirror {
  detected?: boolean;
  ids?: string[];
  hard?: string[];
  reasons?: string[];
  stealthPluginDetected?: boolean;
}

/** Mirror of `tamperingDetails` on the visitor response / `TamperingDetails`. */
export interface TamperingDetailsMirror {
  anomaly_score?: number;
  anti_detect_browser?: boolean;
  devtools_device_emulation?: boolean;
  privacy_hardened?: boolean;
  reasons?: string[];
  hardAutomationEvidence?: string[];
}

/** The single response envelope consumed by the dashboard and the Event JSON. */
export interface CanonicalTelemetryEnvelope {
  event_id: string;
  identity: IdentityAxes;
  server_verified: Record<string, unknown>;
  client_claimed: Record<string, unknown>;
  reconciled_display: Record<string, unknown>;
  automation: AutomationAxes;
  tampering: TamperingAxes;
  network: NetworkAxes;
  environment: EnvironmentAxes;
  proximity: { status: 'granted' | 'permission_required' | 'unavailable'; accuracy_m?: number };
  rarity: {
    corpus_n: number;
    prevalence_ci95_upper: number;
    percentile: null | 'p95' | 'p99_plus';
    status: 'suppressed' | 'insufficient' | 'published';
  };
  velocity: Record<string, unknown>;
  risk: OrthogonalRiskLedger;
  verdict_tier: VerdictTier;

  /* ------------------------------------------------------------------------ */
  /* Additive provenance / schema metadata (all OPTIONAL — legacy payloads stay valid).
  /* `risk.score10` and `risk.risk_tier` already ship on OrthogonalRiskLedger; the fields
  /* below only attach versioning, an optional flat evidence mirror and the labeling /
  /* calibration record used by the offline training pipeline. None are re-derived here.
  /* ------------------------------------------------------------------------ */
  /** Version of the canonical envelope schema itself. */
  schemaVersion?: number | string;
  /** Version of the parser that produced this envelope. */
  parserVersion?: string;
  /** Source-control revision of the build that emitted this envelope. */
  buildSha?: string;
  /** Flat scored-line mirror of `risk.evidence_ledger`, carried for transport/debugging. */
  evidenceLedger?: RiskEvidenceLine[];

  /** Ground-truth label assigned to this observation by the labeling pipeline. */
  label?: string;
  /** When the telemetry observation was captured (ISO-8601 timestamp). */
  observation_timestamp?: string;
  /** When the ground-truth label was assigned (ISO-8601 timestamp). */
  label_timestamp?: string;
  /** Who or what produced the label (analyst, model id, rule set, ...). */
  label_source?: string;
  /** Scoring model version used at observation time. */
  model_version?: string;
  /** Calibration artifact version applied to the score. */
  calibration_version?: string;
  /** Hash of the weight configuration used for scoring. */
  weight_config_hash?: string;

  /** Normalized GPU truth bucket, when the observation pipeline supplied one. */
  gpuObservation?: GpuObservation;
  /** Certainty-only inspector attachment signal; legacy four-state values are accepted verbatim. */
  inspectorState?: InspectorStateTristate | InspectorState;
  /** Additive incognito / private-mode diagnostic readout, when the probe pipeline supplied one. */
  diagnostics?: IncognitoDiagnostics;

  /* ------------------------------------------------------------------------ */
  /* Additive integration mirrors (ALL OPTIONAL — legacy payloads stay valid).  */
  /* Each value is copied verbatim from the corresponding visitor-response field */
  /* (src/types/visitor.ts); the envelope never re-derives any of them. The local */
  /* shapes above exist only to keep this file import-free.                      */
  /* ------------------------------------------------------------------------ */
  /** Canonical proxy verdict mirror (`proxyDetected` / `proxyReasons`). */
  proxy_details?: ProxyDetailsMirror | null;
  /** Server `vpnMethods` block mirror. */
  vpn_methods?: VpnMethodsMirror | null;
  /** Privacy-signature / private-browsing mirror (`privacySettings`). */
  privacy_settings?: boolean | PrivacySettingsMirror | null;
  /** Four-tier stealth-evaluation mirror (`stealthPluginDetected`). */
  stealth_signals?: StealthSignalsMirror | null;
  /** Tampering detail mirror (`tamperingDetails`). */
  tampering_details?: TamperingDetailsMirror | null;
  /** Network-layer fingerprint hash, when the edge supplied one. */
  network_layer_hash?: string | null;
}

/* -------------------------------------------------------------------------- */
/* Canonical consistency (pure, non-throwing)                                 */
/* -------------------------------------------------------------------------- */

/** Structural subset needed by `assertCanonicalConsistency`; both the envelope and the
 * graded ledger satisfy it without any cast. */
export interface CanonicalConsistencyView {
  event_id?: string;
  risk: {
    score_0_100: number;
    tier: RiskTier;
    score10?: number;
    risk_tier?: RiskTier;
  };
  identity?: Pick<IdentityAxes, 'match_stage' | 'confidence_tier' | 'confidence_score' | 'calibration_status'> | null;
  label?: string;
  verdict_tier?: VerdictTier;
}

const CANONICAL_RISK_TIERS: ReadonlySet<string> = new Set<RiskTier>(['Low', 'Elevated', 'High', 'Critical']);

/** Mirror of the frozen `score10FromScore100` mapping, kept local so this file stays
 * dependency-free (it is imported by Node, the browser bundle and the Worker adapter). */
function canonicalScore10(score_0_100: number): number {
  if (!Number.isFinite(score_0_100)) return 0;
  return Math.max(0, Math.min(10, Math.round(score_0_100 / 10)));
}

/**
 * Pure invariant check over the canonical view. Returns a list of human-readable issues and
 * NEVER throws, so a malformed legacy payload degrades to diagnostics instead of crashing a
 * client or an adapter. Checks three parity families:
 *
 *   1. score10 parity      — `risk.score10` (when present) vs the frozen 0-100 -> 0-10 mapping.
 *   2. tier parity         — `risk.tier` vs the frozen composite tier boundaries.
 *   3. identity parity     — the `risk.risk_tier` / `label` mirrors and the identity axes agree
 *                            with that same canonical tier (no client re-derivation).
 *
 * An empty array means the view is internally consistent.
 */
export function assertCanonicalConsistency(view: CanonicalConsistencyView): string[] {
  const issues: string[] = [];
  if (!view || typeof view !== 'object') {
    return ['view must be an object'];
  }

  const risk = view.risk;
  if (!risk || typeof risk !== 'object' || !Number.isFinite(risk.score_0_100)) {
    issues.push('risk.score_0_100 must be a finite number');
    return issues;
  }

  const composite = risk.score_0_100;
  const expectedScore10 = canonicalScore10(composite);
  const expectedTier = riskTier(composite);

  /* 1. score10 parity. */
  if (risk.score10 !== undefined) {
    if (typeof risk.score10 !== 'number' || !Number.isFinite(risk.score10)) {
      issues.push('risk.score10 must be a finite number when present');
    } else if (risk.score10 !== expectedScore10) {
      issues.push(`risk.score10=${risk.score10} disagrees with score_0_100=${composite} (expected ${expectedScore10})`);
    }
  }

  /* 2. tier parity. */
  if (!CANONICAL_RISK_TIERS.has(risk.tier)) {
    issues.push(`risk.tier=${String(risk.tier)} is not a canonical risk tier`);
  } else if (risk.tier !== expectedTier) {
    issues.push(`risk.tier=${risk.tier} disagrees with score_0_100=${composite} (expected ${expectedTier})`);
  }

  /* 3a. identity parity — the optional risk_tier mirror and the canonical tier. */
  if (risk.risk_tier !== undefined) {
    if (!CANONICAL_RISK_TIERS.has(risk.risk_tier)) {
      issues.push(`risk.risk_tier=${String(risk.risk_tier)} is not a canonical risk tier`);
    } else if (risk.risk_tier !== expectedTier || risk.risk_tier !== risk.tier) {
      issues.push(`risk.risk_tier=${risk.risk_tier} disagrees with risk.tier=${risk.tier} (expected ${expectedTier})`);
    }
  }

  /* 3b. identity parity — a tier-shaped label must name the same canonical tier. */
  if (typeof view.label === 'string' && CANONICAL_RISK_TIERS.has(view.label) && view.label !== expectedTier) {
    issues.push(`label=${view.label} disagrees with canonical tier ${expectedTier}`);
  }

  /* 3c. identity parity — documented calibration / match-stage invariants. */
  const identity = view.identity;
  if (identity) {
    const calibrated = identity.calibration_status === 'calibrated';
    const hasFiniteScore = typeof identity.confidence_score === 'number' && Number.isFinite(identity.confidence_score);
    if (calibrated && !hasFiniteScore) {
      issues.push('identity.calibration_status=calibrated requires a finite confidence_score');
    }
    if (!calibrated && identity.confidence_score !== null && identity.confidence_score !== undefined) {
      issues.push('identity.calibration_status=uncalibrated requires confidence_score=null');
    }
    if (identity.match_stage === 'new_enrollment' && identity.confidence_tier !== 'New Unobserved Profile') {
      issues.push('new_enrollment match_stage requires New Unobserved Profile confidence_tier');
    }
    if (
      identity.match_stage === 'privacy_hardened' &&
      identity.confidence_tier !== 'Privacy-Hardened Profile (Reduced Entropy)'
    ) {
      issues.push('privacy_hardened match_stage requires Privacy-Hardened Profile (Reduced Entropy) confidence_tier');
    }
  }

  return issues;
}

/* -------------------------------------------------------------------------- */
/* Integrated consistency (pure, non-throwing)                                 */
/* -------------------------------------------------------------------------- */

/**
 * Structural view for `assertIntegratedConsistency`. Every field is optional so a partial
 * integration still yields diagnostics instead of a type error. The canonical `risk` core is
 * the same one `assertCanonicalConsistency` reads; the flat `score10` / `risk_tier` members are
 * the mirrors republished on the visitor response and the Event JSON.
 */
export interface IntegratedConsistencyView {
  /** Canonical risk ledger (or any structurally compatible view). */
  risk?: {
    score_0_100: number;
    tier: RiskTier;
    score10?: number;
    risk_tier?: RiskTier;
  } | null;
  /** Flat 0-10 headline mirror on the visitor response / Event JSON. */
  score10?: number;
  /** Flat canonical-tier mirror on the visitor response. */
  risk_tier?: RiskTier;
  /** Optional tier-shaped label mirror. */
  label?: string;
  /** Extra envelope / response fields are accepted and ignored by this check. */
  [key: string]: unknown;
}

/**
 * Pure, non-throwing parity check over every risk mirror published at more than one
 * integration point. `risk.tier` is the single source of truth for the tier and
 * `canonicalScore10(risk.score_0_100)` for the headline: `risk.score10`, `risk.risk_tier`,
 * the flat `score10` / `risk_tier` mirrors and a tier-shaped `label` must all agree with them.
 *
 * This helper is additive and independent: it never calls or mutates any existing helper and
 * never throws — malformed / hostile payloads degrade to a list of human-readable issues.
 * An empty array means every mirror that is actually present agrees.
 */
export function assertIntegratedConsistency(view: IntegratedConsistencyView): string[] {
  const issues: string[] = [];
  try {
    if (!view || typeof view !== 'object') {
      issues.push('view must be an object');
      return issues;
    }

    const risk = view.risk;
    if (!risk || typeof risk !== 'object' || !Number.isFinite(risk.score_0_100)) {
      issues.push('risk.score_0_100 must be a finite number');
      return issues;
    }

    const composite = risk.score_0_100;
    const expectedScore10 = canonicalScore10(composite);
    const expectedTier = riskTier(composite);

    /* 0. The canonical tier itself must be well-formed before it can be a reference. */
    if (!CANONICAL_RISK_TIERS.has(risk.tier)) {
      issues.push(`risk.tier=${String(risk.tier)} is not a canonical risk tier`);
    } else if (risk.tier !== expectedTier) {
      issues.push(`risk.tier=${risk.tier} disagrees with score_0_100=${composite} (expected ${expectedTier})`);
    }

    /* 1. score10 mirrors (ledger-local and flat response mirror). */
    if (risk.score10 !== undefined) {
      if (typeof risk.score10 !== 'number' || !Number.isFinite(risk.score10)) {
        issues.push('risk.score10 must be a finite number when present');
      } else if (risk.score10 !== expectedScore10) {
        issues.push(`risk.score10=${risk.score10} disagrees with score_0_100=${composite} (expected ${expectedScore10})`);
      }
    }
    if (view.score10 !== undefined) {
      if (typeof view.score10 !== 'number' || !Number.isFinite(view.score10)) {
        issues.push('score10 mirror must be a finite number when present');
      } else if (view.score10 !== expectedScore10) {
        issues.push(`score10 mirror=${view.score10} disagrees with canonical score10=${expectedScore10}`);
      }
    }

    /* 2. tier mirrors (ledger-local and flat response mirror). */
    if (risk.risk_tier !== undefined) {
      if (!CANONICAL_RISK_TIERS.has(risk.risk_tier)) {
        issues.push(`risk.risk_tier=${String(risk.risk_tier)} is not a canonical risk tier`);
      } else if (risk.risk_tier !== expectedTier || risk.risk_tier !== risk.tier) {
        issues.push(`risk.risk_tier=${risk.risk_tier} disagrees with canonical tier ${expectedTier}`);
      }
    }
    if (view.risk_tier !== undefined) {
      if (!CANONICAL_RISK_TIERS.has(view.risk_tier)) {
        issues.push(`risk_tier mirror=${String(view.risk_tier)} is not a canonical risk tier`);
      } else if (view.risk_tier !== expectedTier || view.risk_tier !== risk.tier) {
        issues.push(`risk_tier mirror=${view.risk_tier} disagrees with canonical tier ${expectedTier}`);
      }
    }

    /* 3. A tier-shaped label is a mirror too; other label vocabularies are ignored. */
    if (typeof view.label === 'string' && CANONICAL_RISK_TIERS.has(view.label) && view.label !== expectedTier) {
      issues.push(`label=${view.label} disagrees with canonical tier ${expectedTier}`);
    }
  } catch {
    /* Hostile getters / proxies must never turn a diagnostic helper into a crash. */
    issues.push('integrated consistency check could not read the view');
  }
  return issues;
}

/* -------------------------------------------------------------------------- */
/* Locked numerical gates                                                     */
/* -------------------------------------------------------------------------- */

/** 512-bit binary SimHash: unrelated profiles agree on ~50% of bits. */
export const LSH_CONFIG = {
  bits: 512,
  bands: 32,
  rows: 16,
  expected_random_similarity: 0.5,
} as const;

/** Cloudflare DO SQLite row-write hygiene: bands are written with hardware anchors only. */
export const LSH_WRITE_POLICY = {
  write_on_hardware_anchor_change_only: true,
  without_rowid: true,
  primary_key: ['band_idx', 'band_hash', 'hardware_id'],
} as const;

export interface RarityDecision {
  status: 'suppressed' | 'insufficient' | 'published';
  percentile: null | 'p95' | 'p99_plus';
  corpus_n: number;
  prevalence_ci95_upper: number;
}

/** Exact Clopper-Pearson one-sided upper bound for k successes in n trials. */
export function clopperPearsonUpperBound(k: number, n: number, alpha = 0.05): number {
  if (n <= 0) return 1;
  const successes = Math.max(0, Math.min(n, Math.floor(k)));
  const cdf = (p: number): number => {
    if (p <= 0) return 0;
    if (p >= 1) return 1;
    let term = Math.exp(n * Math.log1p(-p));
    let sum = term;
    for (let i = 1; i <= successes; i += 1) {
      term *= ((n - i + 1) / i) * (p / (1 - p));
      sum += term;
      if (sum > 1) return 1;
    }
    return Math.min(1, sum);
  };
  let low = 0;
  let high = 1;
  for (let i = 0; i < 80; i += 1) {
    const mid = (low + high) / 2;
    if (cdf(mid) > alpha) low = mid;
    else high = mid;
  }
  return (low + high) / 2;
}

/**
 * Operational rarity gates: suppress <250; p95 at 250..999 when the 95% upper bound
 * is <=0.05; >p99 at >=1000 when the 95% upper bound is <=0.01.
 */
export function decideRarity(corpusN: number, observedCount = 1): RarityDecision {
  const n = Math.max(0, Math.floor(corpusN));
  const upper = clopperPearsonUpperBound(observedCount, n, 0.05);
  if (n < 250) return { status: 'suppressed', percentile: null, corpus_n: n, prevalence_ci95_upper: upper };
  if (n >= 1000 && upper <= 0.01) {
    return { status: 'published', percentile: 'p99_plus', corpus_n: n, prevalence_ci95_upper: upper };
  }
  if (upper <= 0.05) {
    return { status: 'published', percentile: 'p95', corpus_n: n, prevalence_ci95_upper: upper };
  }
  return { status: 'insufficient', percentile: null, corpus_n: n, prevalence_ci95_upper: upper };
}

/* -------------------------------------------------------------------------- */
/* Transport truth helpers                                                    */
/* -------------------------------------------------------------------------- */

/** Derive cookie Secure dynamically: Cloudflare HTTPS yes, http://localhost no. */
export function isSecureRequest(input: {
  secure?: boolean;
  xForwardedProto?: string | null;
  cfVisitor?: string | null;
}): boolean {
  if (input.secure === true) return true;
  if (typeof input.xForwardedProto === 'string' && input.xForwardedProto.split(',')[0].trim().toLowerCase() === 'https') {
    return true;
  }
  if (typeof input.cfVisitor === 'string' && /"scheme"\s*:\s*"https"/i.test(input.cfVisitor)) {
    return true;
  }
  return false;
}

/** Preserve the 65-second sealed-envelope freshness window (commit 9471fe4). */
export const ENVELOPE_MAX_AGE_MS = 65_000;
export const ENVELOPE_MAX_FUTURE_SKEW_MS = 300_000;

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

export interface AutomationAxes {
  bot: 'not_detected' | 'suspected' | 'bad' | 'good' | 'ai_agent';
  bot_type: string | null;
  named_operator: string | null;
  operator_verification_method: 'rfc9421' | 'signed_agent' | 'allowlist' | 'none';
  automation_environment: string;
  human_corroboration: 0 | 1;
  interaction_evidence: string[];
  inspector_state: InspectorState;
  cdp_attached: boolean;
  developer_tools: boolean;
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

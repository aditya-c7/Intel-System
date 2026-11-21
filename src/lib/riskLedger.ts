/**
 * Phase 5 — orthogonal risk ledger orchestrator.
 *
 * This module never re-derives scores: it maps raw detection signals to the exact graded
 * rubric in `telemetryContract.ts` and hands the line items to `buildRiskLedger`, which is
 * the single source of truth for per-family caps, the global clamp and the tier boundaries.
 */

import {
  RISK_RUBRIC,
  buildRiskLedger,
  type OrthogonalRiskLedger,
  type RiskEvidenceLine,
  type RiskTier,
} from './telemetryContract';

export interface AutomationRiskSignals {
  /** Tier A: deterministic hard proof (WebDriver, CDP UA override, stealth runtime). */
  tierA?: boolean;
  /** Tier B: corroborated stealth / headless evidence without a hard artifact. */
  tierB?: boolean;
  /** RFC 9421 / signedAgent / verified allowlist proof exempts the automation family. */
  rfc9421SignedAgent?: boolean;
}

export interface TamperingRiskSignals {
  /** Tier A: hard spec/header violation or cross-load hardware drift. */
  tierA?: boolean;
  /** Tier B: prototype/getter tampering or anti-detect footprint. */
  tierB?: boolean;
  /** ±1% soft warning (V8 heap lattice, PDF face). */
  soft?: boolean;
  /** Tor / Brave / Firefox FPP+RFP / Safari 26 ATFP — zero contribution. */
  privacyHardened?: boolean;
}

export interface NetworkRiskSignals {
  hostingDatacenter?: boolean;
  /** True when the hosting +10 component was already billed on a prior evidence line. */
  hostingAlreadyBilled?: boolean;
  vpnOrRelay?: boolean;
  rotatingProxy?: boolean;
  timezoneMismatch?: boolean;
  /** Another network component fired, demoting TZ from +5 standalone to +2 marginal. */
  otherComponentFired?: boolean;
}

export interface EnvironmentRiskSignals {
  swiftshader?: boolean;
  ephemeralOrPrivateStorage?: boolean;
}

export interface VelocityRiskSignals {
  high?: boolean;
  extreme?: boolean;
}

export interface GradedRiskInput {
  automation?: AutomationRiskSignals;
  tampering?: TamperingRiskSignals;
  network?: NetworkRiskSignals;
  environment?: EnvironmentRiskSignals;
  velocity?: VelocityRiskSignals;
}

/**
 * `clamp(round(score_0_100 / 10), 0, 10)` — the one deterministic mapping from the frozen
 * 0–100 composite to the 0–10 headline. Non-finite input scores as 0.
 */
export function score10FromScore100(score_0_100: number): number {
  if (!Number.isFinite(score_0_100)) return 0;
  return Math.max(0, Math.min(10, Math.round(score_0_100 / 10)));
}

/**
 * Low<25, Elevated<50, High<75, Critical>=75 — thresholds identical to the frozen contract's
 * `riskTier`, but exported here so the tier is derived from the same composite as `score10`
 * instead of a separate ad-hoc sum.
 */
export function riskTierFromScore100(score: number): RiskTier {
  if (!Number.isFinite(score)) return 'Low';
  if (score >= 75) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 25) return 'Elevated';
  return 'Low';
}

/**
 * The canonical graded ledger plus the 0–10 headline and tier name, both derived from the
 * SAME `score_0_100` composite. Additive on top of `OrthogonalRiskLedger`, so every existing
 * consumer of the contract type keeps compiling.
 */
export interface GradedRiskLedger extends OrthogonalRiskLedger {
  /** clamp(round(score_0_100 / 10), 0, 10) — single source for the 0–10 headline. */
  score10: number;
  /** Tier derived from `score_0_100` — always consistent with `score10`. */
  risk_tier: RiskTier;
}

/**
 * Build the exact graded ledger. Components stack inside a family but each family is capped
 * by `buildRiskLedger`; the global score is min(100, raw) with Low/Elevated/High/Critical tiers.
 */
export function buildGradedRiskLedger(input: GradedRiskInput = {}): GradedRiskLedger {
  const lines: RiskEvidenceLine[] = [];
  /** Family+component keys already billed — a component can never bill the same family twice. */
  const billed = new Set<string>();
  const push = (family: RiskEvidenceLine['family'], component: string, points: number, reason: string): void => {
    if (points <= 0) return;
    const key = `${family}:${component}`;
    if (billed.has(key)) return;
    billed.add(key);
    lines.push({ family, component, points, reason });
  };

  /* Automation — cap 45, RFC 9421 signed agent is exempt. */
  const auto = input.automation || {};
  if (!auto.rfc9421SignedAgent) {
    if (auto.tierA) {
      push('automation', 'automation.tier_a_hard_proof', RISK_RUBRIC.automation.tier_a_hard_proof, 'hard automation proof');
    } else if (auto.tierB) {
      push('automation', 'automation.tier_b_corroborated_stealth', RISK_RUBRIC.automation.tier_b_corroborated_stealth, 'corroborated stealth');
    } else {
      push('automation', 'automation.none_or_passive', RISK_RUBRIC.automation.none_or_passive, 'no automation evidence');
    }
  }

  /* Tampering — cap 35, privacy-hardened contributes zero. */
  const tamper = input.tampering || {};
  if (!tamper.privacyHardened) {
    if (tamper.tierA) {
      push('tampering', 'tampering.tier_a_spec_header_or_drift', RISK_RUBRIC.tampering.tier_a_spec_header_or_drift, 'hard spec/header/drift violation');
    } else if (tamper.tierB) {
      push('tampering', 'tampering.tier_b_prototype_or_getter', RISK_RUBRIC.tampering.tier_b_prototype_or_getter, 'prototype/getter tampering');
    } else if (tamper.soft) {
      push('tampering', 'tampering.soft_warning', RISK_RUBRIC.tampering.soft_warning, 'soft spec warning');
    }
  }

  /* Network — cap 25. Hosting billed once, never re-billed. TZ is standalone or marginal. */
  const net = input.network || {};
  if (net.hostingDatacenter && !net.hostingAlreadyBilled) {
    push('network', 'network.hosting_datacenter_asn', RISK_RUBRIC.network.hosting_datacenter_asn, 'hosting/datacenter ASN');
  }
  if (net.vpnOrRelay) {
    push('network', 'network.commercial_vpn_or_relay', RISK_RUBRIC.network.commercial_vpn_or_relay, 'commercial VPN / relay');
  }
  if (net.rotatingProxy) {
    push('network', 'network.rotating_or_residential_proxy', RISK_RUBRIC.network.rotating_or_residential_proxy, 'rotating / residential proxy');
  }
  if (net.timezoneMismatch) {
    const otherFired =
      net.otherComponentFired ||
      Boolean(net.hostingDatacenter) ||
      Boolean(net.vpnOrRelay) ||
      Boolean(net.rotatingProxy);
    push(
      'network',
      otherFired ? 'network.timezone_mismatch_marginal' : 'network.timezone_mismatch_standalone',
      otherFired ? RISK_RUBRIC.network.timezone_mismatch_marginal : RISK_RUBRIC.network.timezone_mismatch_standalone,
      otherFired ? 'timezone mismatch (marginal)' : 'timezone mismatch (standalone)'
    );
  }

  /* Environment — cap 10, so swiftshader(8) + ephemeral(4) -> 10. */
  const env = input.environment || {};
  if (env.swiftshader) {
    push('environment', 'environment.swiftshader_software_renderer', RISK_RUBRIC.environment.swiftshader_software_renderer, 'SwiftShader software renderer');
  }
  if (env.ephemeralOrPrivateStorage) {
    push('environment', 'environment.ephemeral_or_private_storage', RISK_RUBRIC.environment.ephemeral_or_private_storage, 'ephemeral / private storage');
  }

  /* Velocity — cap 15, extreme dominates high. */
  const vel = input.velocity || {};
  if (vel.extreme) {
    push('velocity', 'velocity.extreme_rotation', RISK_RUBRIC.velocity.extreme_rotation, 'extreme identity rotation');
  } else if (vel.high) {
    push('velocity', 'velocity.high_activity', RISK_RUBRIC.velocity.high_activity, 'high activity device');
  }

  const ledger = buildRiskLedger(lines);
  return {
    ...ledger,
    score10: score10FromScore100(ledger.score_0_100),
    risk_tier: riskTierFromScore100(ledger.score_0_100),
  };
}

/**
 * Frozen reference tuples from the architecture plan. Exposed for regression checks; the
 * numbers are produced by the same contract primitives, never hard-coded into the ledger.
 */
export const GRADED_RISK_FIXTURES: ReadonlyArray<{
  name: string;
  input: GradedRiskInput;
  expected: readonly [number, number, number, number, number];
}> = [
  {
    name: 'MCP Playwright',
    input: {
      automation: { tierA: true },
      network: { vpnOrRelay: true },
      environment: { swiftshader: true, ephemeralOrPrivateStorage: true },
    },
    expected: [45, 0, 12, 10, 0],
  },
  {
    name: 'spec fuzz',
    input: { tampering: { tierA: true } },
    expected: [0, 35, 0, 0, 0],
  },
  {
    name: 'drift + proxy + velocity',
    input: {
      automation: { tierB: true },
      tampering: { tierA: true },
      network: { rotatingProxy: true },
      environment: { ephemeralOrPrivateStorage: true },
      velocity: { high: true },
    },
    expected: [35, 35, 18, 4, 12],
  },
  {
    name: 'clean human',
    input: {},
    expected: [0, 0, 0, 0, 0],
  },
];

export function verifyGradedRiskFixtures(): {
  name: string;
  ok: boolean;
  ledger: GradedRiskLedger;
  expected: readonly [number, number, number, number, number];
  score_0_100: number;
  score10: number;
  risk_tier: RiskTier;
}[] {
  return GRADED_RISK_FIXTURES.map((fixture) => {
    const ledger = buildGradedRiskLedger(fixture.input);
    const actual: [number, number, number, number, number] = [
      ledger.automation,
      ledger.tampering,
      ledger.network,
      ledger.environment,
      ledger.velocity,
    ];
    /* Independently derive the expected composite from the frozen per-family tuple so the
     * derived 0–10 headline and tier are checked against the baseline, not against themselves. */
    const expectedScore100 = Math.min(100, fixture.expected.reduce((sum, value) => sum + value, 0));
    const expectedScore10 = score10FromScore100(expectedScore100);
    const expectedTier = riskTierFromScore100(expectedScore100);
    const ok =
      actual.every((value, index) => value === fixture.expected[index]) &&
      ledger.score_0_100 === expectedScore100 &&
      ledger.score10 === expectedScore10 &&
      ledger.risk_tier === expectedTier &&
      ledger.tier === expectedTier;
    return {
      name: fixture.name,
      ok,
      ledger,
      expected: fixture.expected,
      score_0_100: ledger.score_0_100,
      score10: ledger.score10,
      risk_tier: ledger.risk_tier,
    };
  });
}

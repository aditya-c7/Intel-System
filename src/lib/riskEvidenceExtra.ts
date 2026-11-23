/**
 * Informational-only, additive risk evidence lines.
 *
 * This helper never participates in scoring: every emitted line has `points: 0`, so appending
 * its output to a canonical `OrthogonalRiskLedger` (or to `buildGradedRiskLedger` output) leaves
 * the 0-100 composite, the 0-10 headline and the risk tier completely untouched.
 *
 * Each `ExtraEvidenceLine` is a valid canonical `RiskEvidenceLine` (it keeps the `component`
 * machine key) plus a stable, human-readable `label` caption. Construction is deterministic:
 * detectors are evaluated in a fixed order and a flag contributes at most one line.
 *
 * The helper is pure and non-throwing even on hostile input: `null`, primitives, throwing getters
 * and throwing Proxy traps simply yield no line for the affected flag. A flag is active only when
 * its value is strictly the boolean `true`, so truthy junk (`1`, `'yes'`, objects) is inert.
 */

import type { RiskEvidenceLine, RiskFamily } from './telemetryContract';

/** A canonical evidence line plus an informational caption. Still a `RiskEvidenceLine`. */
export interface ExtraEvidenceLine extends RiskEvidenceLine {
  /** Stable human-readable caption for this informational line. */
  label: string;
}

/** Optional flags; only strict boolean `true` activates a line. */
export interface ExtraEvidenceInput {
  spoofedBot?: boolean;
  gpuUnreliable?: boolean;
  audioNoisy?: boolean;
  privacyNoise?: boolean;
  proximityDenied?: boolean;
  activeCdp?: boolean;
}

interface ExtraDetector {
  flag: keyof ExtraEvidenceInput;
  family: RiskFamily;
  component: string;
  label: string;
  reason: string;
}

/** Frozen-order detector table: the single source of output order and wording. */
const DETECTORS: readonly ExtraDetector[] = [
  {
    flag: 'spoofedBot',
    family: 'automation',
    component: 'extra.spoofed_bot',
    label: 'Spoofed bot signals',
    reason: 'Informational: self-reported spoofed-bot observation recorded for context; not scored.',
  },
  {
    flag: 'gpuUnreliable',
    family: 'environment',
    component: 'extra.gpu_unreliable',
    label: 'Unreliable GPU signal',
    reason: 'Informational: GPU / renderer reading flagged unreliable for context; not scored.',
  },
  {
    flag: 'audioNoisy',
    family: 'environment',
    component: 'extra.audio_noisy',
    label: 'Noisy audio fingerprint',
    reason: 'Informational: audio fingerprint classified as noisy for context; not scored.',
  },
  {
    flag: 'privacyNoise',
    family: 'tampering',
    component: 'extra.privacy_noise',
    label: 'Privacy-noise signature',
    reason: 'Informational: privacy-hardening noise recorded for context; not scored.',
  },
  {
    flag: 'proximityDenied',
    family: 'environment',
    component: 'extra.proximity_denied',
    label: 'Proximity permission denied',
    reason: 'Informational: proximity / Bluetooth permission denied for context; not scored.',
  },
  {
    flag: 'activeCdp',
    family: 'automation',
    component: 'extra.active_cdp',
    label: 'Active CDP inspection',
    reason: 'Informational: active CDP inspection observed for context; not scored.',
  },
];

/**
 * Read one flag defensively. Property access is isolated in try/catch so a hostile getter or
 * Proxy trap cannot abort construction of the remaining lines, and each flag is read at most
 * once. Only object/function sources are inspected; primitives are inert.
 */
function readFlag(source: unknown, flag: keyof ExtraEvidenceInput): boolean {
  try {
    if (source === null || source === undefined) return false;
    const kind = typeof source;
    if (kind !== 'object' && kind !== 'function') return false;
    return (source as Record<string, unknown>)[flag] === true;
  } catch {
    return false;
  }
}

/**
 * Build the informational extra-evidence ledger.
 *
 * @returns A fresh array of `ExtraEvidenceLine` (a `RiskEvidenceLine` subtype) in fixed order.
 *          Every line has `points: 0`; no scoring input is mutated and nothing can throw.
 */
export function buildExtraEvidenceLines(input?: ExtraEvidenceInput | null): ExtraEvidenceLine[] {
  const lines: ExtraEvidenceLine[] = [];
  for (const detector of DETECTORS) {
    if (!readFlag(input, detector.flag)) continue;
    lines.push({
      family: detector.family,
      component: detector.component,
      points: 0,
      reason: detector.reason,
      label: detector.label,
    });
  }
  return lines;
}

/**
 * Calibrated identity confidence scorer (v2.0) — pure function, zero I/O.
 *
 * C = clamp(B + E − P, 0.10, 0.999)
 *   B — match-tier base confidence (exact/storage, private-mode exact, lenient upgrade,
 *       cross-browser hardware, or clean first-visit).
 *   E — rendering/hardware entropy bonus ∈ [0, 0.014] (deterministic canvas, unmasked
 *       WebGL, font count ≥ 12, deterministic audio).
 *   P — consistency penalty (Brave shields ≈ benign spoofing, Firefox RFP/Tor uniformity,
 *       or genuine spoofing contradictions).
 */

export type ConfidenceMatchMode = 'exact' | 'lenient' | 'cross_browser' | 'hardware' | 'none';

export interface ConfidenceEntropy {
  deterministicCanvas?: boolean;
  unmaskedWebgl?: boolean;
  fontsCount?: number;
  deterministicAudio?: boolean;
}

export interface ConfidenceInput {
  match_mode?: ConfidenceMatchMode | string;
  match_score?: number;
  storage_healed?: boolean;
  incognito?: boolean;
  isMobileIos?: boolean;
  firstSeenDesktop?: boolean;
  entropy?: ConfidenceEntropy;
  consistencyFlags?: string[];
  braveShields?: boolean;
  rfpOrTor?: boolean;
  genuineSpoof?: boolean;
}

export type SpoofLikelihood = 'low' | 'medium' | 'high';

export interface ConfidenceResult {
  score: number;
  version: '2.0';
  breakdown: {
    base_tier: number;
    entropy_bonus: number;
    penalty: number;
    reasons: string[];
  };
  tampering: boolean;
  tampering_ml_score: number;
  spoof_likelihood: SpoofLikelihood;
}

const SCORE_VERSION = '2.0' as const;
const MIN_SCORE = 0.10;
const MAX_SCORE = 0.999;

const MAX_ENTROPY_BONUS = 0.014;

/** Flags whose names implicate hardware-level contradictions (GPU, rendering, fonts…). */
const HARDWARE_FLAG_HINTS = [
  'gpu',
  'canvas',
  'webgl',
  'font',
  'screen',
  'audio',
  'hardware',
  'core',
  'memory',
  'texture',
  'resolution',
  'color_depth',
  'device_memory',
  'cpu',
];

function round4(value: number): number {
  return Math.round(value * 10000) / 10000;
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, value));
}

function isHardwareContradiction(flag: string): boolean {
  const text = String(flag ?? '').toLowerCase();
  if (!text) return false;
  return HARDWARE_FLAG_HINTS.some((hint) => text.includes(hint));
}

function baseTierForMatch(input: ConfidenceInput, reasons: string[]): number {
  const mode = String(input.match_mode ?? 'none');
  const matchScore = clamp(Number(input.match_score ?? 0), 0, 100);
  const entropy = input.entropy ?? {};
  const deterministicHardware = Boolean(entropy.deterministicCanvas) && Boolean(entropy.unmaskedWebgl);

  if (mode === 'exact') {
    if (input.storage_healed) {
      reasons.push('exact_match_storage_confirmed');
      return 0.985;
    }
    // Exact fingerprint match without storage confirmation (incognito / cleared storage):
    // deterministic hardware + browser rendering keeps the tier high but below the
    // storage-confirmed tier.
    reasons.push(
      input.incognito
        ? deterministicHardware
          ? 'exact_match_incognito_deterministic_hardware'
          : 'exact_match_incognito_storage_missing'
        : 'exact_match_storage_missing'
    );
    return 0.960;
  }

  if (mode === 'lenient') {
    // Lenient upgrade match: 0.910 at score 82 rising linearly to 0.960 at score 100.
    const base = 0.910 + (0.05 * (matchScore - 82)) / 18;
    reasons.push(`lenient_upgrade_match_score_${Math.round(matchScore)}`);
    return base;
  }

  if (mode === 'cross_browser' || mode === 'hardware') {
    // Cross-browser hardware match: 0.850 at score 85 rising linearly to 0.910 at 100.
    const base = 0.850 + (0.06 * (matchScore - 85)) / 15;
    reasons.push(`${mode === 'hardware' ? 'hardware_only' : 'cross_browser'}_match_score_${Math.round(matchScore)}`);
    return base;
  }

  // Clean first visit — desktop default 0.900, iOS Safari 0.800 (heavy anti-fingerprinting).
  if (input.isMobileIos) {
    reasons.push('first_visit_ios_safari');
    return 0.800;
  }
  reasons.push(input.firstSeenDesktop ? 'first_visit_clean_desktop' : 'first_visit');
  return 0.900;
}

function entropyBonusFor(input: ConfidenceInput, reasons: string[]): number {
  const entropy = input.entropy ?? {};
  let bonus = 0;
  if (entropy.deterministicCanvas === true) {
    bonus += 0.004;
    reasons.push('entropy_deterministic_canvas');
  }
  if (entropy.unmaskedWebgl === true) {
    bonus += 0.004;
    reasons.push('entropy_unmasked_webgl');
  }
  const fontsCount = Number(entropy.fontsCount ?? 0);
  if (Number.isFinite(fontsCount) && fontsCount >= 12) {
    bonus += 0.003;
    reasons.push(`entropy_fonts_count_${Math.round(fontsCount)}`);
  }
  if (entropy.deterministicAudio === true) {
    bonus += 0.003;
    reasons.push('entropy_deterministic_audio');
  }
  return clamp(bonus, 0, MAX_ENTROPY_BONUS);
}

interface ConsistencyPenalty {
  penalty: number;
  tampering: boolean;
  tamperingMlScore: number;
  spoofLikelihood: SpoofLikelihood;
}

function consistencyPenaltyFor(input: ConfidenceInput, reasons: string[]): ConsistencyPenalty {
  const flags = (Array.isArray(input.consistencyFlags) ? input.consistencyFlags : [])
    .filter((flag): flag is string => typeof flag === 'string' && flag.trim().length > 0);
  const hardwareFlags = flags.filter(isHardwareContradiction);
  const benignFlags = flags.filter((flag) => !isHardwareContradiction(flag));

  // Genuine spoofing contradictions are the strongest tampering signal.
  if (input.genuineSpoof === true) {
    reasons.push('consistency_genuine_spoof');
    for (const flag of flags) reasons.push(`consistency_flag:${flag}`);
    return { penalty: 0.35, tampering: true, tamperingMlScore: 0.9, spoofLikelihood: 'high' };
  }

  // Firefox RFP / Tor Browser uniformity — expected, but blunts the entropy bonus.
  if (input.rfpOrTor === true) {
    reasons.push('consistency_rfp_or_tor_uniformity');
    return { penalty: 0.25, tampering: false, tamperingMlScore: 0, spoofLikelihood: 'medium' };
  }

  // Brave Shields farble canvas/WebGL without hardware contradictions — benign spoofing.
  if (input.braveShields === true && hardwareFlags.length === 0) {
    reasons.push('consistency_brave_shields_no_hardware_contradiction');
    return { penalty: 0.03, tampering: false, tamperingMlScore: 0, spoofLikelihood: 'low' };
  }

  for (const flag of benignFlags) reasons.push(`consistency_flag:${flag}`);
  if (hardwareFlags.length > 0) {
    for (const flag of hardwareFlags) reasons.push(`consistency_hardware_flag:${flag}`);
  }
  return { penalty: 0, tampering: false, tamperingMlScore: 0, spoofLikelihood: 'low' };
}

/** Calibrated confidence in [0.10, 0.999]. Pure function — never throws, no I/O. */
export function scoreConfidence(input: ConfidenceInput): ConfidenceResult {
  try {
    const reasons: string[] = [];
    const baseTier = clamp(baseTierForMatch(input ?? {}, reasons), MIN_SCORE, MAX_SCORE);
    const entropyBonus = entropyBonusFor(input ?? {}, reasons);
    const consistency = consistencyPenaltyFor(input ?? {}, reasons);
    const score = clamp(baseTier + entropyBonus - consistency.penalty, MIN_SCORE, MAX_SCORE);

    return {
      score: round4(score),
      version: SCORE_VERSION,
      breakdown: {
        base_tier: round4(baseTier),
        entropy_bonus: round4(entropyBonus),
        penalty: round4(consistency.penalty),
        reasons,
      },
      tampering: consistency.tampering,
      tampering_ml_score: consistency.tamperingMlScore,
      spoof_likelihood: consistency.spoofLikelihood,
    };
  } catch {
    // Scoring must never break identity resolution — return the conservative floor.
    return {
      score: MIN_SCORE,
      version: SCORE_VERSION,
      breakdown: { base_tier: MIN_SCORE, entropy_bonus: 0, penalty: 0, reasons: ['scorer_fallback'] },
      tampering: false,
      tampering_ml_score: 0,
      spoof_likelihood: 'low',
    };
  }
}

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

/** Legacy v2.0 calibrated confidence in [0.10, 0.999]. Pure function — never throws, no I/O. */
function legacyScoreConfidence(input: ConfidenceInput): ConfidenceResult {
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

/* -------------------------------------------------------------------------- */
/* Evidence-based identity-match confidence (deterministic + auditable)        */
/* -------------------------------------------------------------------------- */

/** Identity-match tiers understood by the evidence-based scorer. */
export type EvidenceMatchTier =
  | 'storage_continuity'
  | 'exact_hardware'
  | 'lsh_fuzzy'
  | 'new_enrollment'
  | 'privacy_hardened';

/**
 * Observable evidence for the weighted identity-match score.
 *
 * Every field is optional: a missing or malformed field contributes ZERO weight and
 * never throws. The six weighted components are
 *   tier base + match_score/100 * 0.25 + anchor ratio * 0.15
 *   + storage-seed adjustment + browser consensus * 0.025 + OS consensus * 0.025,
 * clamped to [0, 1] and rounded to four decimals.
 */
export interface EvidenceConfidenceInput {
  /** Strongest identity ladder rung that actually matched. */
  match_tier?: EvidenceMatchTier | string | null;
  /** Fingerprint match score on the engine's 0..100 scale. */
  match_score?: number | null;
  /** Structural-anchor agreement ratio (matched / total), in [0,1]. */
  structural_anchor_ratio?: number | null;
  /** Raw anchor counts — alternative to `structural_anchor_ratio`. */
  matched_anchors?: number | null;
  total_anchors?: number | null;
  /** Distinct first-party storage seeds observed for the matched hardware. */
  distinct_storage_seeds_count?: number | null;
  /** Browser-family / OS-family agreement between stored and incoming profiles. */
  browser_family_consensus?: boolean | number | null;
  os_family_consensus?: boolean | number | null;

  /* Continuity corroboration. These are camelCase so they cannot collide with the legacy
   * `storage_healed` telemetry field. Every field is optional and absent evidence is ZERO —
   * corroboration is never inferred for an unseen profile. Each present, valid signal adds a
   * small fixed bonus (see `CONTINUITY_CORROBORATION_STEP`), capped in aggregate, and only
   * applies to a tier that actually represents a match (never `new_enrollment` /
   * `privacy_hardened`). */

  /** First-party storage was genuinely recovered/healed for this returning profile. */
  storageHealed?: boolean | number | string | null;
  /** Count of observed return visits for the same profile (e.g. 119). */
  visitContinuity?: number | string | null;
  /** Age of the matched profile in days. */
  profileAgeDays?: number | string | null;
}

/** One auditable component of the evidence-based score. */
export interface ConfidenceComponent {
  /** Stable audit key. */
  name: string;
  /** Normalized evidence value actually used (ratio in [0,1]; seed count is raw). */
  evidence: number;
  /** Fixed weight (or signed adjustment) applied to the evidence. */
  weight: number;
  /** Signed contribution to the final score. */
  contribution: number;
  /** Human-readable explanation of the observed value. */
  detail: string;
}

/** Fixed weights — kept as a constant so the breakdown and the score cannot drift. */
export const EVIDENCE_CONFIDENCE_WEIGHTS = {
  match_score: 0.25,
  structural_anchor: 0.15,
  storage_seed_single: 0.10,
  storage_seed_collision: -0.20,
  browser_family: 0.025,
  os_family: 0.025,
} as const;

const EVIDENCE_TIER_BASE: Record<string, number> = {
  storage_continuity: 0.45,
  exact_hardware: 0.35,
  lsh_fuzzy: 0.20,
  new_enrollment: 0,
  privacy_hardened: 0,
};

/**
 * Tiers that represent a real identity match. Continuity corroboration is only meaningful
 * for these — an unseen / privacy-hardened profile must never receive a fabricated bonus.
 */
const MATCH_TIERS_WITH_EVIDENCE: ReadonlySet<string> = new Set([
  'storage_continuity',
  'exact_hardware',
  'lsh_fuzzy',
]);

/** Each valid continuity signal adds this much; their aggregate is capped below. */
const CONTINUITY_CORROBORATION_STEP = 0.03;
const MAX_CONTINUITY_CORROBORATION = 0.09;

/** Keys that only the evidence-based scorer accepts — used to dispatch the overload. */
const EVIDENCE_ONLY_KEYS = [
  'match_tier',
  'structural_anchor_ratio',
  'matched_anchors',
  'total_anchors',
  'distinct_storage_seeds_count',
  'browser_family_consensus',
  'os_family_consensus',
  'storageHealed',
  'visitContinuity',
  'profileAgeDays',
] as const;

function finiteNumber(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  // Numeric strings are tolerated for wire compatibility; booleans, null, arrays and
  // objects are malformed evidence and must contribute zero.
  if (typeof value === 'string' && value.trim() !== '') {
    const num = Number(value);
    return Number.isFinite(num) ? num : null;
  }
  return null;
}

/**
 * Seed counts are valid non-negative integers. A missing/null field is "no evidence"
 * (zero weight), while a *present but invalid* value (NaN, Infinity, negative, fractional,
 * non-numeric) is defensively treated as a single corroborating seed — never a collision.
 */
function effectiveSeedCount(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  const parsed = finiteNumber(value);
  if (parsed === null || !Number.isInteger(parsed) || parsed < 0) return 1;
  return parsed;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

function hasConsensus(value: unknown): boolean {
  return value === true || value === 1 || value === '1' || value === 'true';
}

/** A continuity count is valid only when it is a finite, strictly positive number. */
function hasPositiveCount(value: unknown): boolean {
  const parsed = finiteNumber(value);
  return parsed !== null && parsed > 0;
}

/**
 * Small, capped corroboration from genuinely observed continuity signals.
 *
 * Absent or malformed signals always contribute zero, and the whole bonus is suppressed for
 * unmatched tiers so this scorer never fabricates confidence for an unseen profile. The
 * returned detail is appended to the storage-seed component, which is the single signed
 * adjustment bucket already used for clamp reconciliation — keeping the breakdown at exactly
 * six components whose contributions sum to the published score.
 */
function continuityCorroborationFor(
  source: EvidenceConfidenceInput,
  tier: string
): { bonus: number; detail: string } {
  if (!MATCH_TIERS_WITH_EVIDENCE.has(tier)) return { bonus: 0, detail: '' };

  const observed: string[] = [];
  let raw = 0;
  if (hasConsensus(source.storageHealed)) {
    raw += CONTINUITY_CORROBORATION_STEP;
    observed.push('storageHealed');
  }
  if (hasPositiveCount(source.visitContinuity)) {
    raw += CONTINUITY_CORROBORATION_STEP;
    observed.push(`visitContinuity=${String(source.visitContinuity)}`);
  }
  if (hasPositiveCount(source.profileAgeDays)) {
    raw += CONTINUITY_CORROBORATION_STEP;
    observed.push(`profileAgeDays=${String(source.profileAgeDays)}`);
  }

  const bonus = round4(Math.min(MAX_CONTINUITY_CORROBORATION, raw));
  if (bonus === 0) return { bonus: 0, detail: '' };
  return {
    bonus,
    detail: `; continuity corroboration +${bonus} (${observed.join(', ')}; capped at ${MAX_CONTINUITY_CORROBORATION})`,
  };
}

function isEvidenceInput(input: unknown): input is EvidenceConfidenceInput {
  if (!input || typeof input !== 'object') return false;
  const obj = input as Record<string, unknown>;
  return EVIDENCE_ONLY_KEYS.some((key) => key in obj);
}

/**
 * Returns the full, ordered component list for a weighted identity-match score.
 * Pure and defensive: any object (including null/undefined/malformed) is accepted and
 * missing fields simply contribute zero.
 */
export function scoreConfidenceBreakdown(input: EvidenceConfidenceInput = {}): ConfidenceComponent[] {
  const source: EvidenceConfidenceInput = input && typeof input === 'object' ? input : {};
  const components: ConfidenceComponent[] = [];

  /* 1 — match-tier base. */
  const tier = typeof source.match_tier === 'string' ? source.match_tier.trim().toLowerCase() : '';
  const base = EVIDENCE_TIER_BASE[tier] ?? 0;
  components.push({
    name: 'match_tier_base',
    evidence: base,
    weight: 1,
    contribution: base,
    detail: tier ? `tier=${tier}` : 'tier missing; zero base',
  });

  /* 2 — engine match score, normalized from the 0..100 scale. */
  const rawMatchScore = finiteNumber(source.match_score);
  const normalizedMatchScore = clamp01((rawMatchScore ?? 0) / 100);
  components.push({
    name: 'match_score',
    evidence: round4(normalizedMatchScore),
    weight: EVIDENCE_CONFIDENCE_WEIGHTS.match_score,
    contribution: round4(normalizedMatchScore * EVIDENCE_CONFIDENCE_WEIGHTS.match_score),
    detail: rawMatchScore === null ? 'match_score missing; zero weight' : `match_score=${rawMatchScore}/100`,
  });

  /* 3 — structural-anchor ratio (direct value first, else matched/total counts). */
  const directRatio = finiteNumber(source.structural_anchor_ratio);
  const matched = finiteNumber(source.matched_anchors);
  const total = finiteNumber(source.total_anchors);
  const derivedRatio = matched !== null && total !== null && total > 0 ? matched / total : null;
  const ratio = clamp01(directRatio ?? derivedRatio ?? 0);
  components.push({
    name: 'structural_anchor_ratio',
    evidence: round4(ratio),
    weight: EVIDENCE_CONFIDENCE_WEIGHTS.structural_anchor,
    contribution: round4(ratio * EVIDENCE_CONFIDENCE_WEIGHTS.structural_anchor),
    detail:
      directRatio !== null
        ? `structural_anchor_ratio=${directRatio}`
        : derivedRatio !== null
        ? `matched_anchors=${matched}, total_anchors=${total}`
        : 'anchor evidence missing; zero weight',
  });

  /* 4 — distinct storage seeds: one corroborates, two or more is a collision. */
  const rawSeeds = source.distinct_storage_seeds_count;
  const seeds = effectiveSeedCount(rawSeeds);
  let seedAdjustment = 0;
  let seedDetail = 'storage seed count missing; zero weight';
  if (seeds === 1) {
    seedAdjustment = EVIDENCE_CONFIDENCE_WEIGHTS.storage_seed_single;
    seedDetail = 'distinct_storage_seeds_count=1';
  } else if (seeds !== null && seeds >= 2) {
    seedAdjustment = EVIDENCE_CONFIDENCE_WEIGHTS.storage_seed_collision;
    seedDetail = `distinct_storage_seeds_count=${seeds} (collision)`;
  } else if (seeds !== null) {
    seedDetail = `distinct_storage_seeds_count=${seeds}`;
  }
  if (rawSeeds !== undefined && rawSeeds !== null && seeds !== finiteNumber(rawSeeds)) {
    seedDetail += '; invalid count defaulted to 1';
  }
  // Continuity corroboration shares the single signed adjustment bucket. `weight` stays the
  // documented seed adjustment (so the rubric never drifts); the corroboration is disclosed in
  // `detail` and added to `contribution` alongside the later clamp reconciliation.
  const corroboration = continuityCorroborationFor(source, tier);
  seedDetail += corroboration.detail;
  const seedComponent: ConfidenceComponent = {
    name: 'distinct_storage_seeds',
    evidence: seeds ?? 0,
    weight: seedAdjustment,
    contribution: round4(seedAdjustment + corroboration.bonus),
    detail: seedDetail,
  };
  components.push(seedComponent);

  /* 5 — browser-family consensus. */
  const browser = hasConsensus(source.browser_family_consensus);
  components.push({
    name: 'browser_family_consensus',
    evidence: browser ? 1 : 0,
    weight: EVIDENCE_CONFIDENCE_WEIGHTS.browser_family,
    contribution: browser ? EVIDENCE_CONFIDENCE_WEIGHTS.browser_family : 0,
    detail: browser ? 'browser family agrees' : 'no browser-family consensus',
  });

  /* 6 — OS-family consensus. */
  const os = hasConsensus(source.os_family_consensus);
  components.push({
    name: 'os_family_consensus',
    evidence: os ? 1 : 0,
    weight: EVIDENCE_CONFIDENCE_WEIGHTS.os_family,
    contribution: os ? EVIDENCE_CONFIDENCE_WEIGHTS.os_family : 0,
    detail: os ? 'OS family agrees' : 'no OS-family consensus',
  });

  // The published score is the clamp of these exact contributions. Fold any clamp
  // adjustment into the single signed component so the six-item audit trail always sums
  // to the published score — no hidden terms, no reconciliation drift.
  const rawTotal = round4(components.reduce((sum, item) => sum + item.contribution, 0));
  const clampedTotal = clamp01(rawTotal);
  const delta = round4(clampedTotal - rawTotal);
  if (delta !== 0) {
    seedComponent.contribution = round4(seedComponent.contribution + delta);
    seedComponent.detail += `; clamp reconciliation ${delta > 0 ? '+' : ''}${delta}`;
  }

  return components;
}

function evidenceScore(input: EvidenceConfidenceInput): number {
  try {
    const raw = scoreConfidenceBreakdown(input).reduce((sum, component) => sum + component.contribution, 0);
    return round4(clamp01(raw));
  } catch {
    // Scoring must never break a response — zero is the honest fallback.
    return 0;
  }
}

/** Display-only band for a numeric evidence score. Calibration remains the caller's call. */
export type EvidenceScoreTier = 'High' | 'Medium-High' | 'Medium' | 'Low' | 'New/Unobserved';

/**
 * Maps an evidence score in [0,1] to its display band. This is deliberately NOT a calibration
 * claim: callers still own `calibration_status` and should keep it `uncalibrated` until a real
 * held-out gate passes. Non-finite and zero scores describe an unseen/unnumbered profile.
 */
export function evidenceScoreToTier(score: number): EvidenceScoreTier {
  if (typeof score !== 'number' || !Number.isFinite(score) || score <= 0) return 'New/Unobserved';
  if (score >= 0.85) return 'High';
  if (score >= 0.65) return 'Medium-High';
  if (score >= 0.40) return 'Medium';
  return 'Low';
}

/**
 * Two input shapes are supported:
 *  - the legacy v2.0 telemetry shape (`match_mode`, entropy, tampering flags…) → `ConfidenceResult`;
 *  - the evidence shape (`match_tier`, anchor/seed/consensus evidence…) → a number in [0,1].
 *
 * The `match_tier` discriminator keeps the legacy overload's return type intact for the
 * resolver, server and verification suite, which all read `.score` / `.spoof_likelihood`.
 */
export function scoreConfidence(input: EvidenceConfidenceInput & { match_tier: EvidenceMatchTier }): number;
export function scoreConfidence(input: ConfidenceInput): ConfidenceResult;
export function scoreConfidence(input: ConfidenceInput | EvidenceConfidenceInput): number | ConfidenceResult {
  if (isEvidenceInput(input)) return evidenceScore(input);
  return legacyScoreConfidence(input as unknown as ConfidenceInput);
}

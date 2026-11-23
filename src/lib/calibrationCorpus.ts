/**
 * Calibration corpus builder — evidence-independent labels, leakage-safe partitions,
 * and an honest 10-bin ECE + Brier report.
 *
 * Research brief (RS1) invariants, all enforced here:
 *  - LABEL INDEPENDENCE: the label `y` is resolved ONLY from a deterministic first-party
 *    cookie / server visitor_id (observed band) or an authenticated login / OAuth subject /
 *    CRM id (strong band). Our own confidence score or threshold can never be a label source.
 *  - LEAKAGE: the score is frozen at decision time; a label is accepted only when its
 *    independent evidence was resolved STRICTLY AFTER that freeze. Records are partitioned
 *    by visitor_id so one browser can never appear in both fit and test. The holdout is never
 *    tuned on (this module performs no tuning at all).
 *  - ECE: 10 equal-width bins, ECE = sum((|B|/n) * |acc(B) - conf(B)|); empty bins add 0
 *    and are still published with their counts.
 *  - SAMPLE SIZE: research says a naive 10-bin ECE is unreliable below 500 pairs and needs
 *    5k-10k for stability, but the LOCKED PROJECT GATE stays at 200 pairs AND ECE <= 0.05.
 *    We emit descriptive warnings instead of changing the gate.
 *  - BRIER is reported alongside ECE; a low ECE does NOT imply high accuracy.
 *
 * The gate constants and the eligibility decision are imported from `rarityHonesty.ts`
 * (single source of truth — never duplicated). This module deliberately has NO
 * `calibration_status` field: it reports the gate inputs and outcome only, so it can never
 * set calibration status directly. Pure and non-throwing: hostile input fails closed.
 */

import {
  CALIBRATION_MIN_LABELED_PAIRS,
  CALIBRATION_MAX_ECE,
  isCalibrationEligible,
} from './rarityHonesty';

/* Re-export the locked thresholds so a single source of truth remains visible to callers. */
export { CALIBRATION_MIN_LABELED_PAIRS, CALIBRATION_MAX_ECE } from './rarityHonesty';

/** Locked bin count for the binary ECE (10 equal-width bins over [0,1]). */
export const CALIBRATION_BIN_COUNT = 10;

/**
 * Allowlist of INDEPENDENT label evidence sources. Anything not listed here — most notably
 * our own model confidence / score threshold — is forbidden as a label source.
 */
export const INDEPENDENT_LABEL_SOURCES: Readonly<Record<string, 'observed' | 'strong'>> =
  Object.freeze({
    // Observed band: deterministic first-party / server identifiers.
    first_party_cookie: 'observed',
    server_visitor_id: 'observed',
    cookie: 'observed',
    visitor_id: 'observed',
    // Strong band: authenticated, first-party identity authorities.
    oauth_subject: 'strong',
    crm_id: 'strong',
    login_subject: 'strong',
    authenticated_login: 'strong',
  });

export type LabelBand = 'observed' | 'strong';
export type Partition = 'fit' | 'test';

/** One decision-time observation plus its later, independent label evidence. */
export interface CalibrationRecord {
  /** Stable audit id; omitted ids are reported as `record[i]` in warnings. */
  id?: string;
  /** Grouping key: the browser/visitor. Identical ids share exactly one partition. */
  visitor_id: string;
  /** The score FROZEN at decision time, in [0,1]. Never recomputed from the label. */
  frozenScore: number;
  /** Decision-time score freeze instant (epoch ms). */
  frozenAt: number;
  /** Instant the independent evidence resolved the label (epoch ms). Must be > frozenAt. */
  labelResolvedAt: number;
  /** Binary outcome derived from independent evidence, never from our score. */
  label: 0 | 1 | boolean;
  /** Independent evidence source (must appear in INDEPENDENT_LABEL_SOURCES). */
  labelSource: string;
  /** Optional authoritative derivation source; when present it must also be allowlisted. */
  labelDerivedFrom?: string;
  /** Deterministic id observed from the independent source (required for audit). */
  deterministicId?: string;
  /** Bot traffic is excluded from the calibration corpus. */
  isBot?: boolean;
  /** Quarantined records are excluded from the calibration corpus. */
  quarantined?: boolean;
  /** Optional explicit partition. Conflicting values for one visitor are leakage. */
  partition?: Partition;
}

export interface CalibrationBin {
  /** Equal-width bin, e.g. "[0.3,0.4)" (last bin is "[0.9,1.0]"). */
  range: string;
  /** Number of held-out pairs in this bin (0 for empty bins, which still publish). */
  count: number;
  /** Mean frozen confidence of the bin (0 for empty bins). */
  confidence: number;
  /** Mean independently-resolved label of the bin (0 for empty bins). */
  accuracy: number;
}

export interface CalibrationCorpusResult {
  /** True only when the imported rarityHonesty gate passes on the held-out metrics. */
  eligible: boolean;
  /** Eligible labeled pairs in the held-out (test) partition — a gate input. */
  labeledPairs: number;
  /** 10-bin expected calibration error on the held-out partition — a gate input. */
  ece: number;
  /** Mean squared error on the held-out partition (always reported beside ECE). */
  brier: number;
  /** Per-bin counts, confidence and accuracy (all 10 bins, including empty ones). */
  bins: CalibrationBin[];
  /** Descriptive warnings (sample size, band mix, rejections, interpretation). */
  warnings: string[];
  /** Human-readable gate outcome. */
  reason: string;
  // NOTE: there is intentionally NO `calibration_status` here. Status is owned solely by
  // the rarityHonesty gate via `isCalibrationEligible`; this builder never sets it.
}

/* -------------------------------------------------------------------------- */
/* Defensive helpers                                                          */
/* -------------------------------------------------------------------------- */

function round4(value: number): number {
  return Math.round(value * 10000) / 10000;
}

function finiteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function binRange(index: number): string {
  const lo = (index / CALIBRATION_BIN_COUNT).toFixed(1);
  const hi = ((index + 1) / CALIBRATION_BIN_COUNT).toFixed(1);
  return index === CALIBRATION_BIN_COUNT - 1 ? `[${lo},${hi}]` : `[${lo},${hi})`;
}

function emptyBins(): CalibrationBin[] {
  return Array.from({ length: CALIBRATION_BIN_COUNT }, (_, index) => ({
    range: binRange(index),
    count: 0,
    confidence: 0,
    accuracy: 0,
  }));
}

function binIndex(score: number): number {
  const index = Math.floor(score * CALIBRATION_BIN_COUNT);
  if (!Number.isFinite(index)) return CALIBRATION_BIN_COUNT - 1;
  return Math.max(0, Math.min(CALIBRATION_BIN_COUNT - 1, index));
}

/** Stable FNV-1a style hash: a visitor always lands in the same deterministic partition. */
function autoPartition(visitorId: string): Partition {
  let hash = 2166136261;
  for (let i = 0; i < visitorId.length; i += 1) {
    hash ^= visitorId.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) % 5 === 0 ? 'test' : 'fit';
}

function binaryLabel(value: unknown): 0 | 1 | null {
  if (value === true || value === 1) return 1;
  if (value === false || value === 0) return 0;
  return null;
}

interface RejectionCounts {
  bot: number;
  quarantined: number;
  badSource: number;
  temporalLeak: number;
  badScore: number;
  badLabel: number;
  missingDeterministicId: number;
  badVisitor: number;
  contradiction: number;
  crossPartition: number;
}

function emptyRejections(): RejectionCounts {
  return {
    bot: 0,
    quarantined: 0,
    badSource: 0,
    temporalLeak: 0,
    badScore: 0,
    badLabel: 0,
    missingDeterministicId: 0,
    badVisitor: 0,
    contradiction: 0,
    crossPartition: 0,
  };
}

function rejectionSummary(counts: RejectionCounts): string {
  const parts: string[] = [];
  if (counts.bot) parts.push(`${counts.bot} bot`);
  if (counts.quarantined) parts.push(`${counts.quarantined} quarantined`);
  if (counts.badSource) parts.push(`${counts.badSource} non-independent label source`);
  if (counts.temporalLeak) parts.push(`${counts.temporalLeak} pre-freeze label (temporal leak)`);
  if (counts.badScore) parts.push(`${counts.badScore} invalid frozen score`);
  if (counts.badLabel) parts.push(`${counts.badLabel} invalid label`);
  if (counts.missingDeterministicId) parts.push(`${counts.missingDeterministicId} missing deterministic id`);
  if (counts.badVisitor) parts.push(`${counts.badVisitor} missing visitor_id`);
  if (counts.contradiction) parts.push(`${counts.contradiction} id contradiction (whole group)`);
  if (counts.crossPartition) parts.push(`${counts.crossPartition} cross-partition browser (whole group)`);
  return parts.length ? ` (filtered: ${parts.join(', ')})` : '';
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Build an honest calibration corpus from decision-time records.
 *
 * Pure and non-throwing. Only independently-labelled, non-bot, non-quarantined records
 * whose label resolves after the score freeze survive. Surviving records are partitioned
 * by visitor_id; gate metrics are computed on the held-out (test) partition only.
 *
 * The returned `eligible` flag is delegated to the imported `isCalibrationEligible` gate
 * using the exact locked constants — this module never sets calibration status directly.
 */
export function buildCalibrationCorpus(records: unknown): CalibrationCorpusResult {
  try {
    const warnings: string[] = [
      'INTERPRETATION: low ECE does not imply accuracy; Brier score is reported alongside for context.',
      'LEAKAGE POLICY: scores frozen at decision time; labels resolved from independent evidence strictly afterwards; partitions grouped by visitor_id; holdout never tuned.',
    ];
    const rejections = emptyRejections();

    if (!Array.isArray(records)) {
      warnings.push('INPUT: records is not an array; treated as an empty corpus.');
    }
    const list: unknown[] = Array.isArray(records) ? records : [];

    /* ---- 1. Per-record validation (input order -> deterministic warnings) ---- */
    const candidates: Array<{ record: CalibrationRecord; partition: Partition }> = [];

    for (let index = 0; index < list.length; index += 1) {
      const raw = list[index];
      const record = raw && typeof raw === 'object' ? (raw as CalibrationRecord) : null;
      const rid = record && typeof record.id === 'string' && record.id ? record.id : `record[${index}]`;

      if (!record) {
        rejections.badVisitor += 1;
        warnings.push(`REJECT [${rid}]: not an object; excluded.`);
        continue;
      }
      if (record.isBot === true) {
        rejections.bot += 1;
        warnings.push(`REJECT [${rid}]: bot record excluded from calibration corpus.`);
        continue;
      }
      if (record.quarantined === true) {
        rejections.quarantined += 1;
        warnings.push(`REJECT [${rid}]: quarantined record excluded from calibration corpus.`);
        continue;
      }
      if (typeof record.visitor_id !== 'string' || record.visitor_id.length === 0) {
        rejections.badVisitor += 1;
        warnings.push(`REJECT [${rid}]: missing/non-string visitor_id; excluded.`);
        continue;
      }

      // Label independence: the authoritative source is `labelDerivedFrom` when supplied,
      // otherwise `labelSource`. Both must be in the independent-evidence allowlist.
      const declaredSource =
        typeof record.labelDerivedFrom === 'string' && record.labelDerivedFrom.length > 0
          ? record.labelDerivedFrom
          : record.labelSource;
      const sourceKey = typeof declaredSource === 'string' ? declaredSource.trim().toLowerCase() : '';
      if (!Object.prototype.hasOwnProperty.call(INDEPENDENT_LABEL_SOURCES, sourceKey)) {
        rejections.badSource += 1;
        warnings.push(
          `LEAKAGE [${rid}]: label source '${String(declaredSource)}' is not an independent evidence source; our own confidence/threshold is forbidden as a label.`
        );
        continue;
      }

      if (typeof record.deterministicId !== 'string' || record.deterministicId.length === 0) {
        rejections.missingDeterministicId += 1;
        warnings.push(`LEAKAGE [${rid}]: missing deterministic id from the independent source; excluded.`);
        continue;
      }

      if (!finiteNumber(record.frozenScore) || record.frozenScore < 0 || record.frozenScore > 1) {
        rejections.badScore += 1;
        warnings.push(`REJECT [${rid}]: frozenScore is not a finite number in [0,1]; excluded.`);
        continue;
      }

      const label = binaryLabel(record.label);
      if (label === null) {
        rejections.badLabel += 1;
        warnings.push(`REJECT [${rid}]: label is not binary (0/1/false/true); excluded.`);
        continue;
      }

      // Temporal leakage: an independent label resolved at/before the freeze is not later
      // evidence and cannot be used (it may have influenced the score).
      if (
        !finiteNumber(record.frozenAt) ||
        !finiteNumber(record.labelResolvedAt) ||
        record.labelResolvedAt <= record.frozenAt
      ) {
        rejections.temporalLeak += 1;
        warnings.push(
          `LEAKAGE [${rid}]: pre-freeze label (temporal leakage) — label resolved at/before the score freeze (frozenAt=${String(record.frozenAt)}, labelResolvedAt=${String(record.labelResolvedAt)}); excluded.`
        );
        continue;
      }

      const explicit = record.partition === 'fit' || record.partition === 'test' ? record.partition : null;
      candidates.push({ record: { ...record, label }, partition: explicit ?? autoPartition(record.visitor_id) });
      void sourceKey; // band is validated above; composition is reported from survivors below
    }

    /* ---- 2. Group by visitor_id: contradictions and cross-partition leakage ---- */
    const groups = new Map<string, Array<{ record: CalibrationRecord; partition: Partition }>>();
    for (const candidate of candidates) {
      const key = candidate.record.visitor_id;
      const group = groups.get(key);
      if (group) group.push(candidate);
      else groups.set(key, [candidate]);
    }

    const survivors: Array<{ record: CalibrationRecord; partition: Partition }> = [];
    for (const [visitorId, group] of groups) {
      // Contradiction: one browser bound to more than one deterministic id.
      const ids = new Set(group.map((member) => member.record.deterministicId as string));
      if (ids.size > 1) {
        rejections.contradiction += group.length;
        warnings.push(
          `CONTRADICTION [${visitorId}]: conflicting deterministic ids ${JSON.stringify([...ids])}; whole group excluded.`
        );
        continue;
      }

      // Leakage: one browser cannot contribute to both fit and test.
      const partitions = new Set<Partition>(group.map((member) => member.partition));
      if (partitions.has('fit') && partitions.has('test')) {
        rejections.crossPartition += group.length;
        warnings.push(
          `LEAKAGE [${visitorId}]: same browser appears in both fit and test partitions; whole group excluded.`
        );
        continue;
      }

      for (const member of group) survivors.push(member);
    }

    /* ---- 3. Held-out metrics (ECE + Brier) ---- */
    const testRecords = survivors
      .filter((member) => member.partition === 'test')
      .map((member) => member.record);

    const bins = emptyBins();
    const scoreSums = new Array<number>(CALIBRATION_BIN_COUNT).fill(0);
    const labelSums = new Array<number>(CALIBRATION_BIN_COUNT).fill(0);

    let brierSum = 0;
    let observedBand = 0;
    let strongBand = 0;

    for (const record of testRecords) {
      const index = binIndex(record.frozenScore);
      bins[index].count += 1;
      scoreSums[index] += record.frozenScore;
      labelSums[index] += binaryLabel(record.label) ?? 0;

      const y = binaryLabel(record.label) ?? 0;
      const error = record.frozenScore - y;
      brierSum += error * error;

      const source =
        typeof record.labelDerivedFrom === 'string' && record.labelDerivedFrom.length > 0
          ? record.labelDerivedFrom
          : record.labelSource;
      const sourceKey = typeof source === 'string' ? source.trim().toLowerCase() : '';
      if (INDEPENDENT_LABEL_SOURCES[sourceKey] === 'strong') strongBand += 1;
      else observedBand += 1;
    }

    const n = testRecords.length;
    let rawEce = 0;
    for (let index = 0; index < CALIBRATION_BIN_COUNT; index += 1) {
      const count = bins[index].count;
      if (count === 0) {
        // Empty bins contribute 0 to ECE and publish zeroed confidence/accuracy.
        bins[index].confidence = 0;
        bins[index].accuracy = 0;
        continue;
      }
      const confidence = scoreSums[index] / count;
      const accuracy = labelSums[index] / count;
      bins[index].confidence = round4(confidence);
      bins[index].accuracy = round4(accuracy);
      rawEce += (count / n) * Math.abs(accuracy - confidence);
    }

    const ece = round4(rawEce);
    const brier = n > 0 ? round4(brierSum / n) : 0;
    const labeledPairs = n;

    // The locked gate is the sole authority for eligibility. No local threshold logic.
    const eligible = isCalibrationEligible({ labeledPairs, heldOutEce: rawEce });

    /* ---- 4. Descriptive warnings (never alter the gate) ---- */
    warnings.push(
      `LABEL SOURCES: observed-band=${observedBand}, strong-band=${strongBand}; labels are independent of the frozen score.`
    );
    if (labeledPairs < 500) {
      warnings.push(
        `SAMPLE SIZE <500: naive 10-bin ECE is unreliable below 500 labeled pairs (current: ${labeledPairs}); treat this estimate as descriptive only.`
      );
    }
    if (labeledPairs < 5000) {
      warnings.push(
        `SAMPLE SIZE 5k-10k: research recommends 5,000-10,000 labeled pairs for a stable calibration estimate (current: ${labeledPairs}); the locked gate of ${CALIBRATION_MIN_LABELED_PAIRS} pairs / ECE<=${CALIBRATION_MAX_ECE} is unchanged.`
      );
    }

    const suffix = rejectionSummary(rejections);
    let reason: string;
    if (eligible) {
      reason =
        `gate passed: ${labeledPairs} labeled pairs (>= ${CALIBRATION_MIN_LABELED_PAIRS}) ` +
        `and held-out ECE ${ece} (<= ${CALIBRATION_MAX_ECE})${suffix}`;
    } else if (labeledPairs < CALIBRATION_MIN_LABELED_PAIRS) {
      reason =
        `insufficient labeled pairs: ${labeledPairs} < ${CALIBRATION_MIN_LABELED_PAIRS} required${suffix}`;
    } else {
      reason =
        `held-out ECE ${ece} exceeds ceiling ${CALIBRATION_MAX_ECE}${suffix}`;
    }

    return { eligible, labeledPairs, ece, brier, bins, warnings, reason };
  } catch (error) {
    // Defensive fallback: a hostile input must never break a caller. Fail closed.
    return {
      eligible: false,
      labeledPairs: 0,
      ece: 0,
      brier: 0,
      bins: emptyBins(),
      warnings: [
        `FATAL: corpus builder failed closed: ${error instanceof Error ? error.message : String(error)}`,
      ],
      reason: 'corpus builder failed closed',
    };
  }
}

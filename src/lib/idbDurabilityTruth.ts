/**
 * Additive, evidence-based resolver for the Chromium IndexedDB commit-durability probe.
 *
 * Observed live distributions (headless Chromium 156, 8 samples, 2026-11-22):
 *   incognito: 0.531 / 0.88 / 1.067 / 1.183
 *   normal:    2.701 / 6.087 / 6.631 / 7.464
 *
 * The old decision required OPFS corroboration for a decisive IDB ratio, but OPFS worker flush
 * is unavailable (`null`) on modern Chromium, so even a clean 0.531 ratio was vetoed. This
 * resolver keeps the hard vetoes and the original deadband, but lets a *strong* RAM signature
 * (ratio <= 1.4) stand on its own, because a disk-backed profile fsyncing `strict` commits
 * cannot produce a ratio below 1 in any observed configuration. Independent OPFS / auxiliary
 * private-mode corroboration still upgrades an otherwise inconclusive deadband verdict.
 *
 * Pure, total, non-throwing, no side effects. Does not alter the 0-10 risk headline, verdict
 * tiers, bot parity or any existing scoring path.
 */

export interface IdbDurabilityInput {
  /** Trimmed-median strict/relaxed commit ratio, or null when inconclusive. */
  ratio?: number | null;
  /** True when the probe reported a wide trimmed spread / too few rounds. */
  highVariance?: boolean | null;
  /** Hard veto: a granted persistent-storage privilege exists only in a normal profile. */
  persistedGrant?: boolean | null;
  /** Hard veto: opaque/partitioned storage contexts must abstain. */
  isolatedContext?: boolean | null;
  /** Any independent OPFS / auxiliary private-mode corroboration. */
  opfsCorroboration?: boolean | null;
}

export interface IdbDurabilityTruth {
  /** Whether the IDB evidence alone establishes an off-the-record profile. */
  incognito: boolean;
  /** 'high' for a decisive ratio, 'low' for deadband/inconclusive (never incognito). */
  confidence: 'high' | 'low';
  /** Machine-readable rule identifier, surfaced only in shadow diagnostics. */
  rule: 'strong_ram_signature' | 'corroborated_private' | 'disk_backed' | 'deadband' | 'vetoed' | 'inconclusive';
  reasons: string[];
}

/**
 * Strong RAM-backed signature. Live incognito samples cluster at 0.531-1.183 while normal
 * profiles measure 2.701-7.464, so 1.40 cleanly separates them with a >2x safety margin.
 */
export const STRONG_RAM_RATIO_MAX = 1.4;
/** Original Chromium private-side deadband boundary, retained as a published threshold constant. */
export const IDB_PRIVATE_RATIO_MAX = 1.12;
/** Disk-backed boundary; slightly widened so the 1.40-1.60 band still fails open. */
export const IDB_NORMAL_RATIO_MIN = 1.6;

function bool(value: unknown): boolean {
  return value === true;
}

/**
 * Whether the first-party persistent-marker veto should override a private verdict.
 *
 * A private window keeps its first-party cookie/localStorage for the lifetime of that private
 * session, so every page after the first carries the marker. The veto must not erase a decisive
 * RAM-backed physics verdict in that case. Normal disk-backed profiles (ratio above the strong
 * RAM boundary), deadband/inconclusive probes and all hard vetoes keep the original marker
 * behavior. Total: all reads are guarded and any failure falls back to applying the veto.
 */
export function shouldApplyMarkerVeto(
  markerPresent: boolean | null | undefined,
  truth: IdbDurabilityTruth,
  ratio: number | null | undefined
): boolean {
  try {
    if (markerPresent !== true) return false;
    if (!truth || typeof truth !== 'object') return true;
    if (
      truth.incognito === true &&
      truth.rule === 'strong_ram_signature' &&
      typeof ratio === 'number' &&
      Number.isFinite(ratio) &&
      ratio <= STRONG_RAM_RATIO_MAX
    ) {
      return false;
    }
    return true;
  } catch {
    return true;
  }
}

export function resolveIdbDurabilityTruth(input: IdbDurabilityInput = {}): IdbDurabilityTruth {
  let source: Record<string, unknown> = {};
  try {
    if (input && typeof input === 'object') source = { ...input };
  } catch {
    source = {};
  }
  let ratio: number | null = null;
  let highVariance = false;
  let persistedGrant = false;
  let isolatedContext = false;
  let opfsCorroboration = false;
  try {
    const raw = source.ratio;
    if (typeof raw === 'number' && Number.isFinite(raw) && raw > 0) ratio = raw;
    highVariance = bool(source.highVariance);
    persistedGrant = bool(source.persistedGrant);
    isolatedContext = bool(source.isolatedContext);
    opfsCorroboration = bool(source.opfsCorroboration);
  } catch {
    ratio = null;
    highVariance = false;
    persistedGrant = false;
    isolatedContext = false;
    opfsCorroboration = false;
  }
  const reasons: string[] = [];

  // Hard vetoes are evaluated first and are never overridden by timing evidence.
  if (persistedGrant || isolatedContext) {
    reasons.push(persistedGrant ? 'persistent-storage grant veto' : 'isolated/partitioned storage context veto');
    return { incognito: false, confidence: 'low', rule: 'vetoed', reasons };
  }

  if (ratio === null) {
    reasons.push('no finite IDB durability ratio');
    return { incognito: false, confidence: 'low', rule: 'inconclusive', reasons };
  }

  if (ratio <= STRONG_RAM_RATIO_MAX) {
    reasons.push(
      `strict/relaxed ratio ${ratio} <= ${STRONG_RAM_RATIO_MAX}: RAM-backed off-the-record store`
    );
    return { incognito: true, confidence: 'high', rule: 'strong_ram_signature', reasons };
  }

  // Independent private-mode corroboration is decisive in the otherwise inconclusive deadband.
  // Evaluate it before the disk-backed branch so a corroborated private verdict is never
  // collapsed into disk_backed/high; the strong-RAM branch above already returns above.
  if (!highVariance && opfsCorroboration && ratio <= IDB_NORMAL_RATIO_MIN) {
    reasons.push(
      `ratio ${ratio} in deadband (<= ${IDB_NORMAL_RATIO_MIN}) with independent private-mode corroboration`
    );
    return { incognito: true, confidence: 'high', rule: 'corroborated_private', reasons };
  }

  if (ratio > IDB_NORMAL_RATIO_MIN) {
    reasons.push(`strict/relaxed ratio ${ratio} > ${IDB_NORMAL_RATIO_MIN}: disk-backed profile`);
    return { incognito: false, confidence: 'high', rule: 'disk_backed', reasons };
  }

  reasons.push(
    `ratio ${ratio} in deadband${highVariance ? ' with high variance' : ''} and no decisive corroboration`
  );
  return { incognito: false, confidence: 'low', rule: 'deadband', reasons };
}

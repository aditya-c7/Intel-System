/**
 * Additive, evidence-based Web Audio stability classification (pure / SHADOW ONLY).
 *
 * This module does not modify, replace or import any existing identity, scoring or
 * confidence path. It exists to answer one narrow question: *may this audio observation
 * be used as an identity anchor?*
 *
 * Design invariants (enforced by code, not just documentation):
 *
 *  - Any repeat-read divergence (two renders that disagree, an invalid read among valid
 *    ones, or a second read path via `copyFromChannel` that disagrees with
 *    `getChannelData`) OR an instrumented/wrapped `getChannelData` OR a silent buffer
 *    that renders non-zero samples yields `stability: 'noisy'` and
 *    `usableForIdentity: false`. The signal is excluded from identity anchors only.
 *  - Noise NEVER rotates an identity id and NEVER drops a confidence score. This result
 *    deliberately carries no `id`, `confidence`, `score` or tier field, and
 *    {@link audioAnchorValue} is an exact pass-through (no `toFixed`, no quantization)
 *    so a *stable* anchor keeps the very same IEEE754 bits it always had. The legacy
 *    `124.04347745512496` baseline must survive byte-for-byte: rounding it to 8 decimals
 *    would silently mint a different anchor and rotate ids.
 *  - A privacy-hardened browser (Brave / Tor / Safari FPD / strict anti-fingerprinting)
 *    is an expected source of injected audio noise. When noise is observed in that
 *    context the result sets `tamperingInconclusive: true`: the noise must not be
 *    presented as evidence of adversarial tampering. Absence of noise is never a
 *    tampering claim either way — this helper stays neutral when there is nothing to
 *    explain.
 *  - No finite render sum means `unavailable` (not `noisy`): there is simply nothing to
 *    anchor. An explicit noise signal nevertheless wins over unavailability, because a
 *    wrapped/instrumented probe is a finding even if its renders also failed.
 *
 * The classifier is total and non-throwing: `null`, primitives, arrays, throwing getters
 * and Proxy-trapped inputs all degrade to a well-formed verdict. It reads no globals,
 * performs no I/O, has no side effects and never mutates its input.
 */

export type AudioStability = 'stable' | 'noisy' | 'unavailable';

/** Signals gathered by the audio probe. Only `=== true` booleans count as positive evidence. */
export interface AudioStabilityInput {
  /** Sums from repeated, identical renders of the OfflineAudioContext graph. */
  renderSums: number[];
  /** True when `getChannelData` was observed to be wrapped/instrumented by a shim. */
  getChannelDataWrapped: boolean;
  /** True when the `copyFromChannel` read path agrees with `getChannelData`. */
  copyFromChannelMatches: boolean;
  /** True when a deliberately silent buffer rendered non-zero samples (fabricated data). */
  silentBufferNonZero: boolean;
  /** True when the browser is known to apply privacy hardening / farbling. */
  privacyHardened: boolean;
}

/**
 * Conservative verdict. `usableForIdentity` is the *only* field that a caller may use to
 * include or exclude this signal; nothing here authorizes an id change or a confidence
 * adjustment.
 */
export interface AudioStabilityTruth {
  stability: AudioStability;
  usableForIdentity: boolean;
  /** Deterministic, human-readable audit trail. Empty for a clean stable/unavailable probe. */
  noiseReasons: string[];
  /** True when observed noise is explained by privacy hardening, i.e. not tampering evidence. */
  tamperingInconclusive: boolean;
}

/** Bound hostile/oversized read arrays so a lying `length` can never stall the classifier. */
const MAX_RENDER_SAMPLES = 4096;

/** Never trust the caller to pass a well-formed object. */
function asSource(input: unknown): Record<string, unknown> | null {
  try {
    if (input !== null && typeof input === 'object' && !Array.isArray(input)) {
      return input as Record<string, unknown>;
    }
  } catch {
    /* hostile proxy */
  }
  return null;
}

/** Strict boolean read: a throwing or absent getter is "no evidence", never `true`. */
function readBool(source: Record<string, unknown> | null, key: string): boolean {
  if (!source) return false;
  try {
    return source[key] === true;
  } catch {
    return false;
  }
}

interface RenderReads {
  /** Finite numeric reads, in order. */
  finite: number[];
  /** Supplied entries that were not finite numbers (NaN, Infinity, strings, objects, holes). */
  invalid: number;
}

/**
 * Defensively copy finite render sums. Values are compared by strict equality only —
 * there is no tolerance band, because any repeat-read divergence excludes the anchor.
 */
function readRenderReads(value: unknown): RenderReads {
  const result: RenderReads = { finite: [], invalid: 0 };
  try {
    if (!Array.isArray(value)) return result;
    const length = value.length;
    if (!Number.isFinite(length) || length <= 0) return result;
    const limit = Math.min(Math.trunc(length), MAX_RENDER_SAMPLES);
    for (let i = 0; i < limit; i++) {
      let entry: unknown;
      try {
        entry = value[i];
      } catch {
        result.invalid += 1;
        continue;
      }
      try {
        if (typeof entry === 'number' && Number.isFinite(entry)) result.finite.push(entry);
        else result.invalid += 1;
      } catch {
        result.invalid += 1;
      }
    }
  } catch {
    /* a throwing length/getter simply leaves the reads we already collected */
  }
  return result;
}

/**
 * Classify audio stability from probe evidence.
 *
 * Precedence: any noise reason => `'noisy'`; otherwise no finite render sum =>
 * `'unavailable'`; otherwise `'stable'`. `usableForIdentity` is true only for `'stable'`.
 *
 * @param input The audio probe signals. A `null`, primitive, array or Proxy input is
 *   treated as empty evidence and returns a well-formed `'unavailable'` verdict.
 * @returns A deterministic verdict with no id/confidence fields.
 */
export function classifyAudioStability(input: AudioStabilityInput): AudioStabilityTruth {
  const source = asSource(input);

  let renderReads: unknown;
  try {
    renderReads = source ? source.renderSums : undefined;
  } catch {
    renderReads = undefined;
  }
  const { finite, invalid } = readRenderReads(renderReads);

  const wrapped = readBool(source, 'getChannelDataWrapped');
  // `false` is an explicit, measured disagreement; a missing/unknown value is not.
  // Read the raw property once so a stateful hostile getter cannot be observed twice.
  let copyRaw: unknown;
  try {
    copyRaw = source ? source.copyFromChannelMatches : undefined;
  } catch {
    copyRaw = undefined;
  }
  const copyMismatch = copyRaw === false;
  const silentNonZero = readBool(source, 'silentBufferNonZero');
  const privacyHardened = readBool(source, 'privacyHardened');

  const noiseReasons: string[] = [];

  if (finite.length > 1) {
    const first = finite[0];
    let diverged = false;
    for (let i = 1; i < finite.length; i++) {
      if (finite[i] !== first) {
        diverged = true;
        break;
      }
    }
    if (diverged) noiseReasons.push('repeat-read divergence: render sums differ between reads');
  }
  if (invalid > 0 && finite.length > 0) {
    noiseReasons.push('non-finite or invalid render read recorded among valid sums');
  }
  if (wrapped) {
    noiseReasons.push('getChannelData is wrapped/instrumented');
  }
  if (copyMismatch) {
    noiseReasons.push('copyFromChannel data does not match getChannelData');
  }
  if (silentNonZero) {
    noiseReasons.push('silent buffer rendered non-zero samples');
  }

  const hasNoise = noiseReasons.length > 0;
  const stability: AudioStability = hasNoise ? 'noisy' : finite.length > 0 ? 'stable' : 'unavailable';

  return {
    stability,
    usableForIdentity: stability === 'stable',
    noiseReasons,
    // Only privacy-hardened *noise* is inconclusive; a clean probe makes no tampering claim.
    tamperingInconclusive: hasNoise && privacyHardened,
  };
}

/**
 * Exact anchor value pass-through: NO rounding, NO `toFixed`, NO requantization.
 *
 * `audioAnchorValue(124.04347745512496)` returns those exact IEEE754 bits. Formatting the
 * sum to 8 decimals (a legacy behavior) would produce `124.04347746` and rotate the id.
 * Non-numeric hostile input yields `NaN` so it can never be minted into a fake anchor.
 */
export function audioAnchorValue(sum: number): number {
  try {
    return typeof sum === 'number' ? sum : Number.NaN;
  } catch {
    return Number.NaN;
  }
}

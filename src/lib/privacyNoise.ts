/**
 * Shadow-only "privacy noise" classifier — additive, pure, zero imports.
 *
 * Nothing in production imports this module yet. It gives a canonical, side-effect-free
 * home to one narrow question: are the canvas/audio/shader noise artifacts in front of us
 * the product of a privacy-hardened browser (Brave / Firefox RFP / Tor / Safari AFP) or of
 * an anti-detect shim? The answer is deliberately conservative — noise alone is ambiguous
 * and is NEVER promoted to either a privacy signature or an anti-detect verdict.
 *
 * Design rules (all total / non-throwing / deterministic):
 *  - `privacyHardened` (an explicit posture claim) or an accepted vendor signature is the
 *    ONLY way to fire `privacy_settings`. Noise by itself never does.
 *  - When `privacyHardened` is set together with noise, the noise is explained away:
 *    `privacy_settings=true`, `anti_detect_browser=false`, `anomaly_score=0`.
 *  - `vendorSignature` is a strict allowlist (Brave, Firefox RFP, Tor, Safari AFP).
 *    Automation artifacts ("cdp", "playwright", ...) and locales ("en-US", ...) are not in
 *    the allowlist, so neither can create a privacy signature or switch on anti-detect.
 *  - Only `hardContradiction` — a fact privacy hardening cannot explain away — sets
 *    `anti_detect_browser=true` and a non-zero `anomaly_score`. It does NOT erase an
 *    already-fired `privacy_settings` (mirrors `privacySignatures.ts` F1).
 *  - `anomaly_score` is always clamped to [0, 1]; no input is trusted. Hostile getters /
 *    proxies and malformed values degrade to safe defaults instead of throwing.
 */

/* -------------------------------------------------------------------------- */
/* Input / output contracts                                                    */
/* -------------------------------------------------------------------------- */

/** All evidence the classifier consumes. Every field is optional and nullable. */
export interface PrivacyNoiseInput {
  /** Explicit privacy-hardened runtime posture (RFP / FPP / AFP / Tor / Shields). */
  privacyHardened?: boolean | null;
  /** Canvas read noise / farbling observed. */
  canvasNoise?: boolean | null;
  /** Audio fingerprint read noise observed. */
  audioNoise?: boolean | null;
  /** WebGL shader precision / renderer noise observed. */
  shaderNoise?: boolean | null;
  /** A physical identity contradiction that privacy hardening cannot explain away. */
  hardContradiction?: boolean | null;
  /** Claimed vendor privacy signature; only the four accepted families count. */
  vendorSignature?: string | null;
}

/** Verdict returned by `classifyPrivacyNoise`. */
export interface PrivacyNoiseResult {
  /** True only on an explicit privacy posture or an accepted vendor signature. */
  privacy_settings: boolean;
  /** True only on a hard contradiction — noise and locale never set this. */
  anti_detect_browser: boolean;
  /** Always in [0, 1]; non-zero only for a hard contradiction. */
  anomaly_score: number;
  /** Human-readable audit trail (never empty on a successfully resolved input). */
  reasons: string[];
}

/* -------------------------------------------------------------------------- */
/* Constants                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Accepted vendor signatures. Keys are normalized (lowercase, alphanumerics only) so
 * "Firefox-RFP", "firefox rfp" and "TOR Browser" all resolve. Anything else — including
 * automation artifacts and locale tags — is ignored.
 */
const ACCEPTED_VENDORS: ReadonlyMap<string, string> = new Map<string, string>([
  ['brave', 'Brave'],
  ['bravenavigator', 'Brave'],
  ['braveshields', 'Brave'],
  ['firefoxrfp', 'Firefox RFP'],
  ['firefoxresistfingerprinting', 'Firefox RFP'],
  ['rfp', 'Firefox RFP'],
  ['tor', 'Tor'],
  ['torbrowser', 'Tor'],
  ['safariafp', 'Safari AFP'],
  ['safariadvancedfingerprintingprotection', 'Safari AFP'],
  ['afp', 'Safari AFP'],
]);

/** Non-zero score assigned to a single hard contradiction (kept well inside 0..1). */
const HARD_CONTRADICTION_SCORE = 0.8;

const EMPTY_INPUT: PrivacyNoiseInput = Object.freeze({});

/* -------------------------------------------------------------------------- */
/* Defensive readers — hostile getters / proxies must never throw out of here  */
/* -------------------------------------------------------------------------- */

function asObject(value: PrivacyNoiseInput | null | undefined): PrivacyNoiseInput {
  return value !== null && typeof value === 'object' ? value : EMPTY_INPUT;
}

/** Property reads may be getters on a hostile object — contain every throw. */
function readField(record: object, key: string): unknown {
  try {
    return (record as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/** Only a literal `true` is evidence; null / undefined / truthy junk stay false. */
function isTrue(record: object, key: string): boolean {
  return readField(record, key) === true;
}

/** Resolve a vendor string to a canonical family, or null when it is not in the allowlist. */
function acceptedVendorFamily(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const key = value.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (key.length === 0) return null;
  return ACCEPTED_VENDORS.get(key) ?? null;
}

function safeDefaults(note: string): PrivacyNoiseResult {
  return {
    privacy_settings: false,
    anti_detect_browser: false,
    anomaly_score: 0,
    reasons: [note],
  };
}

/* -------------------------------------------------------------------------- */
/* Classifier                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Pure, total, deterministic. Returns a structured verdict and NEVER throws, even on
 * null, primitives, arrays, or objects with hostile getters.
 */
export function classifyPrivacyNoise(
  input: PrivacyNoiseInput | null | undefined = {},
): PrivacyNoiseResult {
  try {
    const src = asObject(input);

    const privacyHardened = isTrue(src, 'privacyHardened');
    const canvasNoise = isTrue(src, 'canvasNoise');
    const audioNoise = isTrue(src, 'audioNoise');
    const shaderNoise = isTrue(src, 'shaderNoise');
    const hardContradiction = isTrue(src, 'hardContradiction');
    const rawVendor = readField(src, 'vendorSignature');
    const vendorFamily = acceptedVendorFamily(rawVendor);

    const noiseLabels = [
      canvasNoise ? 'canvas' : '',
      audioNoise ? 'audio' : '',
      shaderNoise ? 'shader' : '',
    ].filter(Boolean);
    const noiseCount = noiseLabels.length;

    const reasons: string[] = [];

    /* 1. Privacy signature: explicit posture or an accepted vendor — never noise alone. */
    const privacySettings = privacyHardened || vendorFamily !== null;

    if (vendorFamily !== null) {
      reasons.push(`Accepted vendor privacy signature: ${vendorFamily}`);
    } else if (rawVendor !== null && rawVendor !== undefined) {
      reasons.push(
        'Unrecognized vendor signature ignored (never a privacy signature or anti-detect evidence)',
      );
    }

    if (privacyHardened) {
      reasons.push(
        noiseCount > 0
          ? `Privacy-hardened runtime explains ${noiseLabels.join('/')} noise (privacy signature, not anti-detect)`
          : 'Explicit privacy-hardened runtime (privacy signature)',
      );
    } else if (noiseCount > 0) {
      reasons.push(
        `${noiseLabels.join('/')} noise observed without privacy evidence; abstaining (noise may be an automation artifact)`,
      );
    }

    if (!privacySettings && noiseCount === 0 && !hardContradiction) {
      reasons.push('No explicit privacy signature or contradiction; abstaining (not guessing)');
    }

    /* 2. Anti-detect: only a hard contradiction can turn this on. */
    const antiDetectBrowser = hardContradiction;
    let rawScore = 0;
    if (hardContradiction) {
      rawScore = HARD_CONTRADICTION_SCORE;
      reasons.push('Hard contradiction present; anti_detect_browser=true and anomaly_score>0');
      if (privacySettings) {
        reasons.push('Hard contradiction cannot be explained away by privacy hardening');
      }
    }

    const anomalyScore = Math.max(0, Math.min(1, Number(rawScore.toFixed(4))));

    return {
      privacy_settings: privacySettings,
      anti_detect_browser: antiDetectBrowser,
      anomaly_score: anomalyScore,
      reasons,
    };
  } catch {
    return safeDefaults('classifyPrivacyNoise: unexpected input; returning safe defaults');
  }
}

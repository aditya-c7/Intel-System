/**
 * Shadow-only, additive anti-detect-exemption resolver — pure, total, zero imports.
 *
 * Nothing in production imports this module yet. It gives a canonical, side-effect-free
 * home to one narrow question: may the legacy anti-detect penalty be suppressed for a
 * runtime whose only suspicious artifacts are privacy-induced noise?
 *
 * Design rules (all total / non-throwing / deterministic):
 *  - `privacyHardened` (an explicit posture claim) or an accepted `vendorSignature`,
 *    together with `noiseOnly` and no automation artifact, is the ONLY path to
 *    `suppressPenalty=true`. Noise by itself, a posture claim without the noise-only
 *    condition, or any automation proof never earns the exemption.
 *  - `automationArtifact` is diagnostic-only: it can NEVER set `anti_detect_browser`,
 *    create a privacy claim, or earn the exemption on its own.
 *  - Only `hardContradiction` — a fact privacy hardening cannot explain away — sets
 *    `anti_detect_browser=true` and a non-zero `anomaly_score`. It wins even when
 *    `privacyHardened` / `vendorSignature` / `noiseOnly` are all present.
 *  - `anomaly_score` is always clamped to [0, 1]; no input is trusted. Hostile getters /
 *    proxies and malformed values degrade to safe defaults instead of throwing.
 */

/* -------------------------------------------------------------------------- */
/* Input / output contracts                                                    */
/* -------------------------------------------------------------------------- */

/**
 * All evidence the resolver consumes. Every field is optional and nullable.
 *
 * `vendorSignature` accepts only a vendor-name string resolved through the strict allowlist
 * below; a bare boolean (including `true`) is never a vendor signature. `automationArtifact`
 * accepts a boolean or a diagnostic token string, where only a literal `true` or a non-empty
 * token is affirmative. Truthy junk is ignored.
 */
export interface AntiDetectExemptionInput {
  /** Explicit privacy-hardened runtime posture (RFP / FPP / AFP / Tor / Shields). */
  privacyHardened?: boolean | null;
  /** Claimed vendor privacy signature (allowlisted vendor name; booleans are ignored). */
  vendorSignature?: string | boolean | null;
  /** A physical identity contradiction that privacy hardening cannot explain away. */
  hardContradiction?: boolean | null;
  /** Deterministic automation artifact (CDP / CDC / Playwright driver binding). */
  automationArtifact?: string | boolean | null;
  /** The observed artifacts are noise-only (privacy farbling), not a hard contradiction. */
  noiseOnly?: boolean | null;
}

/** Verdict returned by `resolveAntiDetectExemption`. */
export interface AntiDetectExemptionResult {
  /** True only on a hard contradiction — noise, automation and posture never set this. */
  anti_detect_browser: boolean;
  /** Always in [0, 1]; non-zero only for a hard contradiction. */
  anomaly_score: number;
  /** True only for (privacyHardened or accepted vendorSignature) with noiseOnly, no contradiction and no automation artifact. */
  suppressPenalty: boolean;
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

const EMPTY_INPUT: AntiDetectExemptionInput = Object.freeze({});

/* -------------------------------------------------------------------------- */
/* Defensive readers — hostile getters / proxies must never throw out of here  */
/* -------------------------------------------------------------------------- */

function asObject(value: AntiDetectExemptionInput | null | undefined): AntiDetectExemptionInput {
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

/**
 * Resolve a vendor signature to a canonical family. Only a non-empty string that resolves
 * through the strict allowlist is accepted; a bare boolean (including `true`) is never a
 * vendor signature. Everything else is null.
 */
function acceptedVendorFamily(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const key = value.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (key.length === 0) return null;
  return ACCEPTED_VENDORS.get(key) ?? null;
}

function safeDefaults(note: string): AntiDetectExemptionResult {
  return {
    anti_detect_browser: false,
    anomaly_score: 0,
    suppressPenalty: false,
    reasons: [note],
  };
}

/* -------------------------------------------------------------------------- */
/* Resolver                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Pure, total, deterministic. Returns a structured verdict and NEVER throws, even on
 * null, primitives, arrays, or objects with hostile getters.
 */
export function resolveAntiDetectExemption(
  input: AntiDetectExemptionInput | null | undefined = {},
): AntiDetectExemptionResult {
  try {
    const src = asObject(input);

    const privacyHardened = isTrue(src, 'privacyHardened');
    const hardContradiction = isTrue(src, 'hardContradiction');
    const noiseOnly = isTrue(src, 'noiseOnly');
    const rawVendor = readField(src, 'vendorSignature');
    const vendorFamily = acceptedVendorFamily(rawVendor);
    const rawAutomation = readField(src, 'automationArtifact');
    const automationPresent = rawAutomation === true ||
      (typeof rawAutomation === 'string' && rawAutomation.trim().length > 0);

    const reasons: string[] = [];

    if (vendorFamily !== null) {
      reasons.push(`Accepted vendor privacy signature: ${vendorFamily}`);
    } else if (rawVendor !== null && rawVendor !== undefined && rawVendor !== false) {
      reasons.push('Unrecognized vendor signature ignored (never a privacy claim or anti-detect evidence)');
    }
    if (privacyHardened) {
      reasons.push('Explicit privacy-hardened runtime posture present');
    }
    if (noiseOnly) {
      reasons.push('Noise-only condition met: artifacts are explained as privacy farbling');
    } else {
      reasons.push('Noise-only condition not met; exemption withheld (abstaining, not guessing)');
    }
    if (automationPresent) {
      reasons.push('Automation artifact present; diagnostic only, never sets anti_detect_browser');
    }

    /* 1. Anti-detect: only a hard contradiction can turn this on — it wins over everything. */
    let antiDetectBrowser = false;
    let rawScore = 0;
    if (hardContradiction) {
      antiDetectBrowser = true;
      rawScore = HARD_CONTRADICTION_SCORE;
      reasons.push('Hard contradiction present; anti_detect_browser=true and anomaly_score>0');
      if (privacyHardened || vendorFamily !== null) {
        reasons.push('Hard contradiction cannot be explained away by privacy hardening or a vendor signature');
      }
    }

    /* 2. Suppression: (posture or vendor) AND noise-only AND no hard contradiction AND no automation. */
    const exemptionBase = privacyHardened || vendorFamily !== null;
    const suppressPenalty = exemptionBase && noiseOnly && !hardContradiction && !automationPresent;
    if (suppressPenalty) {
      reasons.push('Exemption granted: privacy posture/signature with noise-only artifacts; penalty suppressed');
    } else if (!hardContradiction && exemptionBase && noiseOnly && automationPresent) {
      reasons.push('Automation artifact present; exemption withheld (automation proof outranks privacy posture/signature)');
    } else if (!hardContradiction && exemptionBase && !noiseOnly) {
      reasons.push('Privacy posture present but noise-only condition missing; no penalty suppression');
    } else if (!hardContradiction && !exemptionBase && noiseOnly) {
      reasons.push('Noise alone does not earn the exemption (no privacy posture or vendor signature)');
    } else if (!hardContradiction && !exemptionBase) {
      reasons.push('No privacy posture or vendor signature; abstaining (not guessing)');
    }

    const anomalyScore = Math.max(0, Math.min(1, Number(rawScore.toFixed(4))));

    return {
      anti_detect_browser: antiDetectBrowser,
      anomaly_score: anomalyScore,
      suppressPenalty,
      reasons,
    };
  } catch {
    return safeDefaults('resolveAntiDetectExemption: unexpected input; returning safe defaults');
  }
}

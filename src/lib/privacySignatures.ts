/**
 * Shadow-only, additive privacy-signature resolver.
 *
 * This module is intentionally inert: no production caller consumes it yet. It gives a
 * canonical, side-effect-free home to the question "did this runtime expose an *explicit*
 * browser privacy signature, and may the legacy anti-detect penalty be suppressed?"
 * so a later consumer can be diffed against the existing payload without either side
 * re-deriving the facts.
 *
 * Guarantees (mirroring `vpnMethods.ts` / `proxyTruth.ts` / `hardwareTruth.ts`):
 *  - pure and side-effect free at import time; no I/O, no network, no SDK;
 *  - NEVER throws — hostile getters / proxies / malformed values degrade to safe defaults;
 *  - `privacy_settings` is fired ONLY by an explicit vendor signature (Brave, Firefox RFP,
 *    Tor, Safari AFP) or by `reducedEntropy` with at least two independent corroborations;
 *  - `automationArtifact` is diagnostic-only: it can NEVER create a privacy signature or a
 *    corroboration, even when combined with other signals;
 *  - `suppressAntiDetectPenalty` requires a fired privacy signature AND the absence of
 *    `contradictionEvidence`; an uncorroborated suspicion never earns the exemption.
 *
 * Firefox RFP deliberately requires >=2 of its three probes (UTC timezone, rounded viewport,
 * capped core count): a single UTC timezone is ordinary Firefox behaviour, not a signature.
 */

/* -------------------------------------------------------------------------- */
/* Input / output contracts                                                    */
/* -------------------------------------------------------------------------- */

/** A tri-state evidence flag: `true` is the only affirmative value. */
type SignalFlag = boolean | null | undefined;

/** All evidence needed to resolve the shadow privacy-signature verdict. */
export interface PrivacySignalsInput {
  /** Brave's dedicated `navigator.brave.isBrave()` vendor API confirmed positive. */
  braveNavigator?: SignalFlag;
  /** Brave Shields (fingerprinting / tracker protection) reported enabled. */
  braveShields?: SignalFlag;
  /** Firefox Resist Fingerprinting pins the browser timezone to UTC. */
  firefoxRfpUtc?: SignalFlag;
  /** Firefox Resist Fingerprinting rounds the viewport to fixed steps. */
  firefoxRfpRoundedViewport?: SignalFlag;
  /** Firefox Resist Fingerprinting caps `navigator.hardwareConcurrency`. */
  firefoxRfpCoresCapped?: SignalFlag;
  /** The request egresses through a verified Tor exit relay. */
  torExit?: SignalFlag;
  /** Tor Browser letterboxed viewport (200x100 steps, pinned to screen size). */
  torLetterboxing?: SignalFlag;
  /** Safari Advanced/Tracking Fingerprinting Protection (AFP) reported active. */
  safariAfp?: SignalFlag;
  /** Fingerprint surfaces are reduced, but no single vendor has been identified. */
  reducedEntropy?: SignalFlag;
  /** Hardware identifiers are masked / genericised (a corroboration, not a vendor proof). */
  hardwareMasked?: SignalFlag;
  /** Positive evidence that contradicts a privacy claim (stealth plugin / forged signature). */
  contradictionEvidence?: SignalFlag;
  /** Deterministic automation artifact (CDP / CDC / Playwright driver binding). */
  automationArtifact?: SignalFlag;
}

/** Verdict returned by `resolvePrivacySignatures`. */
export interface PrivacySignatureResult {
  /** True only on an explicit vendor signature or reducedEntropy + >=2 corroborations. */
  privacy_settings: boolean;
  /** The confirmed privacy-hardening posture (settings present, no contradiction). */
  privacy_hardened: boolean;
  /** Canonical tokens for every fired privacy signature (never automation/contradiction). */
  signatures: string[];
  /** Legacy anti-detect penalty gate: settings present AND no contradiction evidence. */
  suppressAntiDetectPenalty: boolean;
  /** Strength of the verdict; `low` means no signature or an explicit contradiction. */
  confidence: 'high' | 'medium' | 'low';
  /** Human-readable audit trail. */
  reasons: string[];
}

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                            */
/* -------------------------------------------------------------------------- */

const EMPTY_INPUT: PrivacySignalsInput = Object.freeze({});

const RFP_KEYS = ['firefoxRfpUtc', 'firefoxRfpRoundedViewport', 'firefoxRfpCoresCapped'] as const;

/** Every affirmative privacy signal except `reducedEntropy` itself (and diagnostics). */
const CORROBORATION_KEYS = [
  'braveNavigator',
  'braveShields',
  'firefoxRfpUtc',
  'firefoxRfpRoundedViewport',
  'firefoxRfpCoresCapped',
  'torExit',
  'torLetterboxing',
  'safariAfp',
  'hardwareMasked',
] as const;

const SIGNATURE_TOKEN: Record<(typeof CORROBORATION_KEYS)[number], string> = {
  braveNavigator: 'brave-navigator',
  braveShields: 'brave-shields',
  firefoxRfpUtc: 'firefox-rfp-utc',
  firefoxRfpRoundedViewport: 'firefox-rfp-rounded-viewport',
  firefoxRfpCoresCapped: 'firefox-rfp-cores-capped',
  torExit: 'tor-exit',
  torLetterboxing: 'tor-letterboxing',
  safariAfp: 'safari-afp',
  hardwareMasked: 'hardware-masked',
};

type SignalKey = keyof PrivacySignalsInput;

function asObject(value: PrivacySignalsInput | null | undefined): PrivacySignalsInput {
  return value !== null && typeof value === 'object' ? value : EMPTY_INPUT;
}

/**
 * Read one tri-state flag. Only a literal `true` is evidence; null / undefined / truthy junk
 * stay false. A throwing getter is recorded and treated as absence of evidence, and — crucially
 * — does not abort the read of the remaining fields.
 */
function readFlag(
  src: PrivacySignalsInput,
  key: SignalKey,
  hostile: string[],
): boolean {
  try {
    return src[key] === true;
  } catch {
    hostile.push(key);
    return false;
  }
}

function safeDefaults(note: string): PrivacySignatureResult {
  return {
    privacy_settings: false,
    privacy_hardened: false,
    signatures: [],
    suppressAntiDetectPenalty: false,
    confidence: 'low',
    reasons: [note],
  };
}

/* -------------------------------------------------------------------------- */
/* Canonical resolver                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Resolve the shadow privacy-signature verdict from raw evidence.
 *
 * Vendor families are ranked as explicit proof: Brave (`braveNavigator` or `braveShields`),
 * Firefox RFP (>=2 of its three probes), Tor (`torExit` or `torLetterboxing`) and Safari AFP.
 * Only when no vendor family is present does the generic `reducedEntropy` path apply, and it
 * needs two independent corroborations from `CORROBORATION_KEYS`. Automation and contradiction
 * flags are deliberately excluded from both the proof set and the corroboration count.
 */
export function resolvePrivacySignatures(
  input: PrivacySignalsInput | null | undefined,
): PrivacySignatureResult {
  try {
    const src = asObject(input);
    const hostile: string[] = [];

    // Snapshot every field through guarded reads: one hostile getter must not poison the rest.
    const flag = {} as Record<SignalKey, boolean>;
    const keys: SignalKey[] = [
      'braveNavigator',
      'braveShields',
      'firefoxRfpUtc',
      'firefoxRfpRoundedViewport',
      'firefoxRfpCoresCapped',
      'torExit',
      'torLetterboxing',
      'safariAfp',
      'reducedEntropy',
      'hardwareMasked',
      'contradictionEvidence',
      'automationArtifact',
    ];
    for (const key of keys) flag[key] = readFlag(src, key, hostile);

    const reasons: string[] = [];
    if (hostile.length > 0) {
      reasons.push(`Unreadable signal fields ignored (${hostile.join(', ')})`);
    }

    const signatures: string[] = [];
    const addSignature = (token: string): void => {
      if (!signatures.includes(token)) signatures.push(token);
    };

    // Diagnostic tokens are recorded for every affirmative probe, even ones that are too
    // weak to establish a vendor family on their own (e.g. a lone RFP UTC timezone).
    let corroborationCount = 0;
    for (const key of CORROBORATION_KEYS) {
      if (!flag[key]) continue;
      addSignature(SIGNATURE_TOKEN[key]);
      corroborationCount += 1;
    }
    if (flag.reducedEntropy) addSignature('reduced-entropy');

    const rfpCount = RFP_KEYS.reduce((count, key) => count + (flag[key] ? 1 : 0), 0);
    const firefoxRfp = rfpCount >= 2;
    const brave = flag.braveNavigator || flag.braveShields;
    const tor = flag.torExit || flag.torLetterboxing;
    const safari = flag.safariAfp;

    const vendorFamilies: string[] = [];
    if (brave) vendorFamilies.push('Brave');
    if (firefoxRfp) vendorFamilies.push('Firefox RFP');
    if (tor) vendorFamilies.push('Tor');
    if (safari) vendorFamilies.push('Safari AFP');

    if (brave) {
      reasons.push(
        `Explicit Brave signature (${[
          flag.braveNavigator ? 'brave-navigator' : '',
          flag.braveShields ? 'brave-shields' : '',
        ]
          .filter(Boolean)
          .join(', ')})`,
      );
    }
    if (firefoxRfp) {
      reasons.push(`Explicit Firefox RFP signature (${rfpCount} independent RFP probes)`);
    } else if (rfpCount === 1) {
      reasons.push('Firefox RFP has a single probe; at least two are required for a vendor signature');
    }
    if (tor) {
      reasons.push(
        `Explicit Tor signature (${[
          flag.torExit ? 'tor-exit' : '',
          flag.torLetterboxing ? 'tor-letterboxing' : '',
        ]
          .filter(Boolean)
          .join(', ')})`,
      );
    }
    if (safari) reasons.push('Explicit Safari AFP signature');

    const reducedEntropyPath = flag.reducedEntropy && corroborationCount >= 2;
    if (reducedEntropyPath) {
      reasons.push(
        `reducedEntropy confirmed by ${corroborationCount} independent corroborations`,
      );
    } else if (flag.reducedEntropy) {
      reasons.push(
        `reducedEntropy has ${corroborationCount} corroboration(s); at least two are required`,
      );
    }

    const privacySettings = vendorFamilies.length > 0 || reducedEntropyPath;
    if (!privacySettings) {
      reasons.push('No explicit privacy signature found (abstaining, not guessing)');
    } else if (vendorFamilies.length === 0) {
      reasons.push('privacy_settings=true from the reducedEntropy corroboration path');
    }

    if (flag.hardwareMasked && !flag.reducedEntropy) {
      reasons.push('Hardware masking recorded as corroboration only, not a vendor signature');
    }
    if (flag.automationArtifact) {
      reasons.push('Automation artifact present; never counted as a privacy signature');
    }
    if (flag.contradictionEvidence) {
      reasons.push('Contradiction evidence present; anti-detect suppression withheld');
    }

    // Confidence: two independent vendor families, a canonical vendor proof, or >=3
    // corroborations is high; a single weaker family / exactly 2 corroborations is medium;
    // absence of a signature or any contradiction is low.
    const canonicalVendorProof =
      flag.braveNavigator || flag.safariAfp || flag.torLetterboxing || firefoxRfp;
    let confidence: PrivacySignatureResult['confidence'] = 'low';
    if (privacySettings && !flag.contradictionEvidence) {
      const high =
        vendorFamilies.length >= 2 ||
        canonicalVendorProof ||
        (reducedEntropyPath && corroborationCount >= 3);
      confidence = high ? 'high' : 'medium';
    }

    // The posture flag and the action gate share the same rule today: an explicit signature
    // with no contradiction. They stay separate fields so downstream consumers can read the
    // posture independently of the legacy penalty decision.
    const hardened = privacySettings && !flag.contradictionEvidence;

    return {
      privacy_settings: privacySettings,
      privacy_hardened: hardened,
      signatures,
      suppressAntiDetectPenalty: hardened,
      confidence,
      reasons,
    };
  } catch {
    return safeDefaults('resolvePrivacySignatures: unexpected input; returning safe defaults');
  }
}

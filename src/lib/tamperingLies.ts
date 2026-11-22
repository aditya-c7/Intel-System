/**
 * Additive, shadow-only resolver for cross-scope "tampering lie" observations.
 *
 * This module is deliberately isolated from the canonical verdict pipeline: it neither
 * imports nor mutates any other module, reads no platform API, and changes no published
 * telemetry shape. It mirrors the existing vocabulary (`anomaly_score`,
 * `anti_detect_browser`, `tampering_confidence`, `reasons` — see `TamperingDetails` in
 * `tamperingDetector.ts` and `TamperingAxes` in `telemetryContract.ts`) so a future caller
 * can forward its result verbatim, but nothing calls it yet.
 *
 * Design rules (all total / non-throwing / deterministic):
 *  - Evidence is split into HARD contradictions (a physical identity that cannot be
 *    explained away) and NOISE lies (stealth-shim artifacts that privacy browsers also
 *    produce). `privacyHardened` suppresses ONLY the noise class.
 *  - `automationArtifactOnly` is a decoupling switch: it can NEVER turn on
 *    `anti_detect_browser`. The score and reasons still report the raw evidence.
 *  - `ActiveText rgb(0,102,204)` is the Windows system color; pure red is the
 *    Linux/macOS family. Either one contradicting the claimed OS is a hard contradiction.
 *  - A shader precision profile that implies an OS family is a hard contradiction when it
 *    disagrees with the claimed GPU OS. Cross-platform software profiles abstain.
 *  - `anomaly_score` is always clamped to [0, 1]; no weight is negative and no input is
 *    trusted. Hostile getters / proxies degrade to safe defaults instead of throwing.
 */

/** One scope's navigator-like snapshot. Every field is optional and nullable. */
export interface ScopeObservation {
  ua?: string | null;
  platform?: string | null;
  cores?: number | null;
  memory?: number | null;
  languages?: string | null;
}

/** All observations the shadow resolver consumes. Nothing here is read from a platform API. */
export interface WorkerScopeObservations {
  window?: ScopeObservation | null;
  dedicated?: ScopeObservation | null;
  shared?: ScopeObservation | null;
  service?: ScopeObservation | null;
  activeTextColor?: string | null;
  claimedOs?: string | null;
  shaderPrecisionProfile?: string | null;
  claimedGpuOs?: string | null;
  audioSilentBufferNonZero?: boolean | null;
  audioRepeatReadDiverged?: boolean | null;
  prototypeProxy?: boolean | null;
  iframeStealthTrap?: boolean | null;
  privacyHardened?: boolean | null;
  automationArtifactOnly?: boolean | null;
}

/** Same three-state confidence vocabulary as the canonical tampering axes. */
export interface TamperingLiesResult {
  anomaly_score: number;
  anti_detect_browser: boolean;
  tampering_confidence: 'high' | 'medium' | 'low';
  reasons: string[];
}

type OsFamily = 'windows' | 'macos' | 'linux';
type ActiveTextFamily = 'windows' | 'non-windows';
type ScopeField = 'ua' | 'platform' | 'cores' | 'memory' | 'languages';

const SCOPE_NAMES = ['window', 'dedicated', 'shared', 'service'] as const;
const SCOPE_FIELDS: readonly ScopeField[] = ['ua', 'platform', 'cores', 'memory', 'languages'];

const FIELD_LABELS: Readonly<Record<ScopeField, string>> = {
  ua: 'navigator.userAgent',
  platform: 'navigator.platform',
  cores: 'navigator.hardwareConcurrency',
  memory: 'navigator.deviceMemory',
  languages: 'navigator.languages',
};

const WEIGHTS = Object.freeze({
  ua: 0.25,
  platform: 0.25,
  cores: 0.15,
  memory: 0.15,
  languages: 0.15,
  activeTextOs: 0.3,
  shaderGpuOs: 0.3,
  audioSilent: 0.15,
  audioRepeat: 0.15,
  prototypeProxy: 0.1,
  iframeStealthTrap: 0.1,
});

const SAFE_RESULT: TamperingLiesResult = Object.freeze({
  anomaly_score: 0,
  anti_detect_browser: false,
  tampering_confidence: 'low',
  reasons: [],
}) as TamperingLiesResult;

/* -------------------------------------------------------------------------- */
/* Defensive readers — hostile getters / proxies must never throw out of here  */
/* -------------------------------------------------------------------------- */

function readField(record: unknown, key: string): unknown {
  try {
    if (record === null || record === undefined) return undefined;
    if (typeof record !== 'object' && typeof record !== 'function') return undefined;
    return (record as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function isTrue(record: unknown, key: string): boolean {
  return readField(record, key) === true;
}

function normalizedString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const text = value.trim().toLowerCase();
  return text.length > 0 ? text : null;
}

function normalizedNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function readScope(record: unknown): ScopeObservation {
  return {
    ua: normalizedString(readField(record, 'ua')),
    platform: normalizedString(readField(record, 'platform')),
    cores: normalizedNumber(readField(record, 'cores')),
    memory: normalizedNumber(readField(record, 'memory')),
    languages: normalizedString(readField(record, 'languages')),
  };
}

/** Coarse OS family from a claimed OS / platform string. Unrecognised values abstain. */
function osFamily(value: unknown): OsFamily | null {
  const text = normalizedString(value);
  if (!text) return null;
  if (/\bwin(?:32|64|dows)?\b|\bnt\b/.test(text)) return 'windows';
  if (/mac(?:os|intosh)?|os ?x|darwin|iphone|ipad|ipod|macintel/.test(text)) return 'macos';
  if (/linux|ubuntu|fedora|debian|cros|chrome ?os|android/.test(text)) return 'linux';
  return null;
}

/**
 * ActiveText system color. `rgb(0, 102, 204)` (and its hex spellings) is the Windows
 * default; pure red is the canonical Linux/macOS spoof probe. Anything else abstains.
 */
function activeTextFamily(value: unknown): ActiveTextFamily | null {
  const text = normalizedString(value);
  if (!text) return null;
  const compact = text.replace(/\s+/g, '');
  if (/^(?:rgb\(0,102,204\)|#0066cc|#06c)$/.test(compact)) return 'windows';
  if (/^(?:rgb\(255,0,0\)|#ff0000|#f00|red)$/.test(compact)) return 'non-windows';
  return null;
}

/**
 * OS family implied by a shader precision profile. Cross-platform software profiles
 * (SwiftShader / llvmpipe / software renderers) explicitly abstain — they are never a
 * contradiction, matching the repo's "software rendering is not tampering" rule.
 */
function shaderFamily(value: unknown): OsFamily | null {
  const text = normalizedString(value);
  if (!text) return null;
  if (/swiftshader|subzero|llvmpipe|softpipe|software|0x0000c0de/.test(text)) return null;
  if (/d3d|direct3d|windows|win32|angle[_-]?d3d/.test(text)) return 'windows';
  if (/metal|apple|macos|ios|angle[_-]?metal/.test(text)) return 'macos';
  if (/mesa|linux|x11|egl/.test(text)) return 'linux';
  return null;
}

/* -------------------------------------------------------------------------- */
/* Resolver                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Pure, total, deterministic. Returns a structured verdict for the shadow observations
 * and NEVER throws, even on null, primitives, arrays, or objects with hostile getters.
 */
export function resolveTamperingLies(
  input: WorkerScopeObservations | null | undefined = {}
): TamperingLiesResult {
  try {
    const source = input && typeof input === 'object' ? input : ({} as WorkerScopeObservations);

    let rawScore = 0;
    let hardSignals = 0;
    let noiseSignals = 0;
    const reasons: string[] = [];

    /* 1. HARD: the same-origin scopes must report the same navigator identity. */
    const scopes: Array<{ name: string; data: ScopeObservation }> = [];
    for (const name of SCOPE_NAMES) {
      const raw = readField(source, name);
      if (raw === null || (typeof raw !== 'object' && typeof raw !== 'function')) continue;
      scopes.push({ name, data: readScope(raw) });
    }
    const baseline = scopes[0];
    if (baseline) {
      for (const field of SCOPE_FIELDS) {
        const baseValue = baseline.data[field];
        if (baseValue === null) continue;
        const diverged: string[] = [];
        for (let i = 1; i < scopes.length; i += 1) {
          const other = scopes[i];
          const value = other.data[field];
          if (value !== null && value !== baseValue) diverged.push(other.name);
        }
        if (diverged.length > 0) {
          rawScore += WEIGHTS[field];
          hardSignals += 1;
          for (const scopeName of diverged) {
            reasons.push(
              `cross-scope ${FIELD_LABELS[field]} divergence (${baseline.name} vs ${scopeName})`
            );
          }
        }
      }
    }

    /* 2. HARD: ActiveText color vs the claimed OS. */
    const activeFamily = activeTextFamily(readField(source, 'activeTextColor'));
    const claimedFamily = osFamily(readField(source, 'claimedOs'));
    if (activeFamily && claimedFamily) {
      const contradicts =
        activeFamily === 'windows' ? claimedFamily !== 'windows' : claimedFamily === 'windows';
      if (contradicts) {
        rawScore += WEIGHTS.activeTextOs;
        hardSignals += 1;
        reasons.push(
          `ActiveText color implies ${activeFamily === 'windows' ? 'Windows' : 'Linux/macOS'} but claimed OS is ${claimedFamily}`
        );
      }
    }

    /* 3. HARD: shader precision profile vs the claimed GPU OS. */
    const shaderFamilyValue = shaderFamily(readField(source, 'shaderPrecisionProfile'));
    const gpuFamily = osFamily(readField(source, 'claimedGpuOs'));
    if (shaderFamilyValue && gpuFamily && shaderFamilyValue !== gpuFamily) {
      rawScore += WEIGHTS.shaderGpuOs;
      hardSignals += 1;
      reasons.push(
        `shader precision profile implies ${shaderFamilyValue} but claimed GPU OS is ${gpuFamily}`
      );
    }

    /* 4. NOISE: stealth-shim artifacts. Suppressed wholesale by privacy hardening. */
    const privacyHardened = isTrue(source, 'privacyHardened');
    if (!privacyHardened) {
      const noise: ReadonlyArray<readonly [string, number, string]> = [
        [
          'audioSilentBufferNonZero',
          WEIGHTS.audioSilent,
          'silent audio buffer returned non-zero samples',
        ],
        ['audioRepeatReadDiverged', WEIGHTS.audioRepeat, 'repeated audio reads diverged'],
        ['prototypeProxy', WEIGHTS.prototypeProxy, 'native prototype getters are proxy-wrapped'],
        ['iframeStealthTrap', WEIGHTS.iframeStealthTrap, 'iframe stealth trap detected'],
      ];
      for (const [key, weight, reason] of noise) {
        if (isTrue(source, key)) {
          rawScore += weight;
          noiseSignals += 1;
          reasons.push(reason);
        }
      }
    }

    /* 5. Score / flag / confidence. */
    const finiteRaw = Number.isFinite(rawScore) ? rawScore : 0;
    const anomaly_score = Math.max(0, Math.min(1, Number(finiteRaw.toFixed(4))));

    const automationArtifactOnly = isTrue(source, 'automationArtifactOnly');
    const anySignal = hardSignals > 0 || noiseSignals > 0;
    // Decoupling: this flag can never switch anti_detect_browser on.
    const anti_detect_browser = automationArtifactOnly ? false : anySignal;
    if (automationArtifactOnly) {
      reasons.push('automation-artifact-only observation: anti_detect_browser discounted');
    }

    const tampering_confidence: TamperingLiesResult['tampering_confidence'] =
      hardSignals > 0 || anomaly_score >= 0.5 ? 'high' : anomaly_score >= 0.2 ? 'medium' : 'low';

    return { anomaly_score, anti_detect_browser, tampering_confidence, reasons };
  } catch {
    // Absolute totality guard: a hostile proxy must degrade, never escape as a throw.
    return { ...SAFE_RESULT, reasons: [] };
  }
}

/**
 * Shadow-only stealth-signal evaluator — additive, pure, zero imports (Workers safe).
 *
 * Nothing in production imports this module yet. It mirrors the four-tier evidence
 * taxonomy of `src/lib/verdict.ts` and `src/server/agents/botVerifier.ts`:
 *
 *   hard            — deterministic automation artifacts; sufficient on their own.
 *                     (launch switch, Playwright init scripts / binding leak, CSP
 *                     bypass, Marionette, chrome-headless-shell)
 *   medium          — the three "conditional" probes (runtime enable leak, document
 *                     interception, storage partitioning). They count ONLY when
 *                     explicitly corroborated or paired with another admissible
 *                     signal — never bare, never alone.
 *   weak            — telemetry only; a bare weak signal can never escalate, though
 *                     (exactly like botVerifier's gate) it may corroborate a medium.
 *   developer_tools — a bare CDP binding-globals bridge: reported, weight 0, never a
 *                     bad-bot verdict. Corroborated it promotes to `hard`, matching
 *                     botVerifier's single corroborated-CDP escalation path.
 *
 * The signed-good precedence of botVerifier is preserved through the optional
 * `verifiedGoodBot` argument: a literal `true` forces `detected` to false while the
 * evidence inventory (`ids` / `hard`) is retained for shadow telemetry.
 *
 * Total function over its input: no I/O, no globals, no mutation, never throws.
 */

/* -------------------------------------------------------------------------- */
/* Public types                                                               */
/* -------------------------------------------------------------------------- */

export type StealthSignalId =
  | 'runtimeEnableLeak'
  | 'ipcFloodingProtection'
  | 'documentInterception'
  | 'storagePartitioning'
  | 'cdpBindingGlobals'
  | 'sourceUrlLeak'
  | 'pwInitScripts'
  | 'exposeFunctionLeak'
  | 'bypassCsp'
  | 'popupBlocking'
  | 'marionette'
  | 'chromeHeadlessShell';

export interface StealthObservation {
  id: StealthSignalId;
  observed: boolean;
  /** Independent confirmation of this observation; non-boolean values are ignored. */
  corroborated?: boolean | null;
}

export interface StealthEvaluation {
  detected: boolean;
  /** Distinct observed ids in first-seen order (includes developer-tools evidence). */
  ids: StealthSignalId[];
  /** Hard-tier ids, plus a corroborated CDP bridge; the escalation evidence. */
  hard: StealthSignalId[];
  /** Per-signal reason ids followed by one outcome token, all from the bot taxonomy. */
  reasons: string[];
}

/* -------------------------------------------------------------------------- */
/* Tier tables (mirror of the botVerifier / verdict taxonomy)                 */
/* -------------------------------------------------------------------------- */

const HARD_IDS: ReadonlySet<StealthSignalId> = new Set<StealthSignalId>([
  'ipcFloodingProtection', // launch.ipc-flooding-switch
  'pwInitScripts', // playwright.* init scripts
  'exposeFunctionLeak', // bot.playwright-binding / cdc.global.binding
  'bypassCsp', // injected script defeating CSP
  'marionette', // navigator.webdriver equivalent
  'chromeHeadlessShell', // ua.headless-chrome equivalent
]);

/** The explicit conditional trio: corroboration or a companion is mandatory. */
const MEDIUM_IDS: ReadonlySet<StealthSignalId> = new Set<StealthSignalId>([
  'runtimeEnableLeak',
  'documentInterception',
  'storagePartitioning',
]);

const WEAK_IDS: ReadonlySet<StealthSignalId> = new Set<StealthSignalId>([
  'sourceUrlLeak',
  'popupBlocking',
]);

const DEVELOPER_TOOLS_IDS: ReadonlySet<StealthSignalId> = new Set<StealthSignalId>([
  'cdpBindingGlobals',
]);

const KNOWN_IDS: ReadonlySet<StealthSignalId> = new Set<StealthSignalId>([
  ...HARD_IDS,
  ...MEDIUM_IDS,
  ...WEAK_IDS,
  ...DEVELOPER_TOOLS_IDS,
]);

/**
 * Reason ids: exact botVerifier ids where the artifact is the same, a `stealth.*`
 * id for the new shadow-only probes. Outcome tokens are botVerifier's
 * `automated-runtime`, `developer_tools`, `signed-agent` and `not_detected`.
 */
const SIGNAL_REASON_IDS: Readonly<Record<StealthSignalId, string>> = Object.freeze({
  runtimeEnableLeak: 'stealth.runtime-enable-leak',
  ipcFloodingProtection: 'launch.ipc-flooding-switch',
  documentInterception: 'stealth.document-interception',
  storagePartitioning: 'stealth.storage-partitioning',
  cdpBindingGlobals: 'cdp.runtime.enable',
  sourceUrlLeak: 'cdp.runtime.evaluate.source-url',
  pwInitScripts: 'playwright.init-scripts',
  exposeFunctionLeak: 'bot.playwright-binding',
  bypassCsp: 'stealth.bypass-csp',
  popupBlocking: 'bot.popup-blocking',
  marionette: 'navigator.webdriver',
  chromeHeadlessShell: 'ua.headless-chrome',
});

const MAX_OBSERVATIONS = 10_000;

interface CleanObservation {
  id: StealthSignalId;
  observed: boolean;
  corroborated: boolean | null;
}

/* -------------------------------------------------------------------------- */
/* Defensive normalization                                                    */
/* -------------------------------------------------------------------------- */

/** Property reads may be getters on a hostile object — contain every throw. */
function readField(value: object, key: string): unknown {
  try {
    return (value as unknown as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function mergeCorroboration(a: boolean | null, b: boolean | null): boolean | null {
  if (a === true || b === true) return true;
  if (a === false || b === false) return false;
  return null;
}

function sanitize(observations: unknown): CleanObservation[] {
  const clean: CleanObservation[] = [];
  if (!Array.isArray(observations)) return clean;

  try {
    let seen = 0;
    for (const raw of observations as readonly unknown[]) {
      if (++seen > MAX_OBSERVATIONS) break; // bound hostile proxies / endless iterables
      if (raw === null || typeof raw !== 'object') continue;

      const id = readField(raw, 'id');
      if (typeof id !== 'string' || !KNOWN_IDS.has(id as StealthSignalId)) continue;

      clean.push({
        id: id as StealthSignalId,
        observed: readField(raw, 'observed') === true,
        corroborated: normalizeCorroboration(readField(raw, 'corroborated')),
      });
    }
  } catch {
    // A hostile iterator or proxy threw mid-walk: keep the safely read prefix.
  }
  return clean;
}

function normalizeCorroboration(value: unknown): boolean | null {
  if (value === true) return true;
  if (value === false || value === null) return false;
  return null; // strings, numbers, objects and symbols never count as corroboration
}

function inert(): StealthEvaluation {
  return { detected: false, ids: [], hard: [], reasons: ['not_detected'] };
}

/* -------------------------------------------------------------------------- */
/* Evaluation                                                                 */
/* -------------------------------------------------------------------------- */

function evaluate(observations: unknown, signedGood: boolean): StealthEvaluation {
  // Deduplicate by id, keeping first-seen order; a duplicate may supply corroboration.
  const byId = new Map<StealthSignalId, CleanObservation>();
  for (const entry of sanitize(observations)) {
    const previous = byId.get(entry.id);
    byId.set(
      entry.id,
      previous
        ? {
            id: entry.id,
            observed: previous.observed || entry.observed,
            corroborated: mergeCorroboration(previous.corroborated, entry.corroborated),
          }
        : entry,
    );
  }

  const entries = [...byId.values()].filter((entry) => entry.observed);
  if (entries.length === 0) return inert();

  const ids = entries.map((entry) => entry.id);
  const hard: StealthSignalId[] = [];
  const mediumEntries: CleanObservation[] = [];
  let weakCount = 0;

  for (const entry of entries) {
    if (HARD_IDS.has(entry.id)) {
      hard.push(entry.id);
    } else if (entry.id === 'cdpBindingGlobals' && entry.corroborated === true) {
      // Bare CDP is developer_tools; an independently corroborated bridge is hard.
      hard.push(entry.id);
    } else if (MEDIUM_IDS.has(entry.id)) {
      mediumEntries.push(entry);
    } else if (WEAK_IDS.has(entry.id)) {
      weakCount += 1;
    }
  }

  // A companion must be a real non-developer-tools observation. A bare CDP bridge
  // cannot corroborate a conditional probe any more than it can escalate alone.
  const admissibleCount = hard.length + mediumEntries.length + weakCount;
  let detected = hard.length > 0;
  for (const entry of mediumEntries) {
    if (entry.corroborated === true || admissibleCount >= 2) {
      detected = true;
      break;
    }
  }

  const reasons = ids.map((id) => SIGNAL_REASON_IDS[id]);
  if (signedGood && (detected || ids.length > 0)) {
    // Signed-good precedence (botVerifier step 0): suppress the verdict, keep the evidence.
    reasons.push('signed-agent');
  } else if (detected) {
    reasons.push('automated-runtime');
  } else if (hard.length === 0 && ids.every((id) => DEVELOPER_TOOLS_IDS.has(id))) {
    reasons.push('developer_tools');
  } else {
    reasons.push('not_detected');
  }

  return {
    // A literal `true` forces the signed-good precedence; truthy non-booleans do not.
    detected: signedGood ? false : detected,
    ids,
    hard,
    reasons,
  };
}

/**
 * Evaluate stealth observations into a shadow verdict. Never throws, never mutates
 * its input, and is deterministic for equal inputs.
 *
 * @param observations observations to evaluate (hostile values are ignored safely)
 * @param verifiedGoodBot literal `true` forces `detected: false` (signed-good precedence)
 */
export function evaluateStealthSignals(
  observations: readonly StealthObservation[],
  verifiedGoodBot?: boolean,
): StealthEvaluation {
  try {
    return evaluate(observations, verifiedGoodBot === true);
  } catch {
    return inert();
  }
}

/**
 * Active-CDP state classifier — additive, pure, zero imports (Workers safe).
 *
 * Nothing in production imports this module yet. It answers one narrow question:
 * "what kind of active Chrome-DevTools-Protocol presence do these probes describe?"
 * It deliberately reports *state* rather than a verdict. CDP evidence — however
 * strong — is telemetry only here: this classifier NEVER emits a bad-bot verdict,
 * never infers intent, and has no verdict/isBot/detected field. Its only outputs are
 * `state`, the two neutral flags `cdp_attached` / `developer_tools`, and `reasons`.
 *
 * Signal interpretation (documented so the taxonomy stays stable):
 *   runtimeEnableCount      — observations of the CDP `Runtime.enable` domain activation.
 *                             >= 1 means at least one CDP client attached.
 *   nameGetterCount         — reads of a name getter trap. An elevated count means a
 *                             client is actively interrogating the object graph.
 *   prepareStackTraceCount  — reads of an `Error.prepareStackTrace` trap. An elevated
 *                             count is debugger / developer-tools stack introspection.
 *   secondClientAttached    — a second, independent CDP client is present.
 *   devtoolsAttached        — a docked DevTools front-end is present.
 *
 * Decision precedence (first match wins):
 *   active inspection AND devtools evidence  -> corroborated
 *   active inspection (2nd client + elevated name getter) -> automation_protocol_inspection_active
 *   devtools evidence (docked or stack introspection)     -> docked_devtools (developer_tools true ONLY)
 *   any CDP client (Runtime.enable or 2nd client)          -> automation_protocol_attached
 *   otherwise                                             -> none
 *
 * "Active inspection" intentionally requires BOTH a second client AND an elevated
 * name-getter count: a bare second client, or a bare elevated getter, is not enough.
 * This keeps the classifier conservative and matches the bot-taxonomy rule that CDP
 * signals only escalate when independently corroborated. Even the `corroborated`
 * state is a neutral label — it never becomes a bad-bot verdict.
 *
 * Total function over its input: no I/O, no globals, no mutation, never throws.
 * Hostile values (getters that throw, NaN, negatives, proxies, non-objects) fail
 * closed to the inert `none` state or are ignored field-by-field.
 */

/* -------------------------------------------------------------------------- */
/* Public types                                                               */
/* -------------------------------------------------------------------------- */

export type ActiveCdpState =
  | 'none'
  | 'automation_protocol_attached'
  | 'automation_protocol_inspection_active'
  | 'docked_devtools'
  | 'corroborated';

/** Fields are `unknown` on purpose: callers may supply hostile telemetry values. */
export interface ActiveCdpInput {
  runtimeEnableCount?: unknown;
  nameGetterCount?: unknown;
  prepareStackTraceCount?: unknown;
  secondClientAttached?: unknown;
  devtoolsAttached?: unknown;
}

export interface ActiveCdpResult {
  state: ActiveCdpState;
  /** Neutral CDP-presence flag (true for automation-protocol states and corroborated). */
  cdp_attached: boolean;
  /** Neutral developer-tools flag (true only for docked-devtools / corroborated). */
  developer_tools: boolean;
  /** Evidence tokens in first-seen order, followed by one outcome token equal to `state`. */
  reasons: string[];
}

/** A name-getter count at or above this value counts as "elevated" (active inspection). */
export const ELEVATED_NAME_GETTER_COUNT = 2;
/** A prepareStackTrace count at or above this value counts as elevated debugger inspection. */
export const ELEVATED_PREPARE_STACK_COUNT = 2;

/* -------------------------------------------------------------------------- */
/* Defensive normalization                                                    */
/* -------------------------------------------------------------------------- */

/** Property reads may be getters on a hostile object/proxy — contain every throw. */
function readField(value: unknown, key: string): unknown {
  try {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
      return undefined;
    }
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/** Non-finite, non-number, and < 1 values fail closed to 0; decimals are floored. */
function toCount(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 1) return 0;
  return Math.floor(value);
}

/** Only a literal boolean `true` is treated as an affirmative boolean signal. */
function toBool(value: unknown): boolean {
  return value === true;
}

function inert(): ActiveCdpResult {
  return { state: 'none', cdp_attached: false, developer_tools: false, reasons: ['none'] };
}

/* -------------------------------------------------------------------------- */
/* Classification                                                             */
/* -------------------------------------------------------------------------- */

function classify(input: ActiveCdpInput): ActiveCdpResult {
  const runtimeEnableCount = toCount(readField(input, 'runtimeEnableCount'));
  const nameGetterCount = toCount(readField(input, 'nameGetterCount'));
  const prepareStackTraceCount = toCount(readField(input, 'prepareStackTraceCount'));
  const secondClientAttached = toBool(readField(input, 'secondClientAttached'));
  const devtoolsAttached = toBool(readField(input, 'devtoolsAttached'));

  const cdpClient = runtimeEnableCount >= 1 || secondClientAttached;
  const activeInspection =
    secondClientAttached && nameGetterCount >= ELEVATED_NAME_GETTER_COUNT;
  const devtoolsPresent =
    devtoolsAttached || prepareStackTraceCount >= ELEVATED_PREPARE_STACK_COUNT;

  let state: ActiveCdpState;
  let cdpAttached: boolean;
  let developerTools: boolean;

  if (activeInspection && devtoolsPresent) {
    // Independent automation-inspection and developer-tools evidence agree.
    state = 'corroborated';
    cdpAttached = true;
    developerTools = true;
  } else if (activeInspection) {
    state = 'automation_protocol_inspection_active';
    cdpAttached = true;
    developerTools = false;
  } else if (devtoolsPresent) {
    // Docked DevTools (or debugger stack introspection): developer_tools true ONLY.
    state = 'docked_devtools';
    cdpAttached = false;
    developerTools = true;
  } else if (cdpClient) {
    state = 'automation_protocol_attached';
    cdpAttached = true;
    developerTools = false;
  } else {
    return inert();
  }

  const reasons: string[] = [];
  if (runtimeEnableCount >= 1) reasons.push('runtime_domain_enabled');
  if (secondClientAttached) reasons.push('second_cdp_client');
  if (nameGetterCount >= ELEVATED_NAME_GETTER_COUNT) reasons.push('name_getter_elevated');
  if (prepareStackTraceCount >= ELEVATED_PREPARE_STACK_COUNT) {
    reasons.push('prepare_stack_inspection');
  }
  if (devtoolsAttached) reasons.push('devtools_attached');
  reasons.push(state); // outcome token, always last

  return { state, cdp_attached: cdpAttached, developer_tools: developerTools, reasons };
}

/**
 * Resolve the active-CDP state from probe counters/flags. Never throws, never mutates
 * its input, and is deterministic for equal inputs. Telemetry only — never a bad-bot
 * verdict (there is no verdict field in the result).
 */
export function resolveActiveCdp(input: ActiveCdpInput): ActiveCdpResult {
  try {
    return classify(input);
  } catch {
    return inert();
  }
}

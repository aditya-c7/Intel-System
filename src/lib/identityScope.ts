/**
 * Identity-scope resolver (additive, pure, dependency-free).
 *
 * This module is intentionally inert: no production caller consumes it yet. It gives a canonical,
 * side-effect-free home to one narrow question — "is the identity scope bound to a stable hardware
 * anchor, or to an explicitly salted context?" — so a later consumer can be diffed against the
 * existing identity payload without either side re-deriving the decision.
 *
 * Decision rule (deliberately conservative):
 *  - Only an explicit `contextSaltPresent === true` yields `id_scope: 'context'` with
 *    `context_isolated: true`. A salt is the sole proof that a per-context identity exists.
 *  - Incognito mode is browser UI state, NOT a privacy-isolation guarantee. With no context salt
 *    the scope stays `hardware` and `context_isolated` stays false — including the case where
 *    incognito is combined with a stable hardware anchor. The reason states this explicitly so a
 *    downstream reader cannot mistake "incognito" for "isolated".
 *  - First-party storage survival (or its absence) is recorded as metadata only. It never creates
 *    or removes a scope, and never establishes isolation by itself.
 *
 * Guarantees (mirroring `privacySignatures.ts` / `zeroTrust.ts`):
 *  - pure and side-effect free at import time; no I/O, no network, no SDK, no randomness;
 *  - NEVER throws — hostile getters / proxies / malformed values degrade to the safe fallback;
 *  - only a literal `true` is affirmative (no truthy-junk coercion);
 *  - NEVER mints an identifier: the result has exactly three declarative fields, no id is
 *    generated, stored, or echoed from the input.
 */

/* -------------------------------------------------------------------------- */
/* Input / output contracts                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Raw identity-scope evidence. Fields are `unknown` on purpose: this helper is fed
 * client-reported metadata, so only the literal boolean `true` is ever treated as evidence and
 * every other value (including a throwing getter) is treated as absence of evidence.
 */
export interface IdentityScopeInput {
  /** Browser is in incognito / private mode (UI state, not an isolation guarantee). */
  incognito?: unknown;
  /** First-party storage survived the session (metadata only, never isolation metadata). */
  firstPartyStorageSurvived?: unknown;
  /** A stable hardware anchor was confirmed for this visitor. */
  hardwareAnchorStable?: unknown;
  /** An explicit per-context salt is present — the only affirmative isolation proof. */
  contextSaltPresent?: unknown;
}

/** Verdict returned by `resolveIdentityScope`. Contains no identifier of any kind. */
export interface IdentityScopeResult {
  /** `context` only when an explicit context salt is present; otherwise `hardware`. */
  id_scope: 'hardware' | 'context';
  /** True only for a context-scoped (salt-isolated) identity. */
  context_isolated: boolean;
  /** Human-readable audit trail naming the rule that fired and the evidence it read. */
  reason: string;
}

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                            */
/* -------------------------------------------------------------------------- */

type ScopeKey = keyof IdentityScopeInput;

const EMPTY_INPUT: IdentityScopeInput = Object.freeze({});

/** Read one field through a guarded access. Only literal `true` counts; junk stays false. */
function readFlag(src: IdentityScopeInput, key: ScopeKey, unreadable: string[]): boolean {
  try {
    return (src as Record<ScopeKey, unknown>)[key] === true;
  } catch {
    unreadable.push(key);
    return false;
  }
}

function asObject(value: IdentityScopeInput | null | undefined): IdentityScopeInput {
  return value !== null && typeof value === 'object' ? value : EMPTY_INPUT;
}

function boolText(flag: boolean): 'true' | 'false' {
  return flag ? 'true' : 'false';
}

/* -------------------------------------------------------------------------- */
/* Canonical resolver                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Resolve the identity scope from raw evidence.
 *
 * The context salt has absolute priority: when present, the identity is explicitly scoped to
 * that context and is reported as isolated. In every other case the scope is hardware and
 * isolation is NOT assumed — most importantly when incognito is combined with a stable hardware
 * anchor, which is the "explicit metadata, never presume privacy isolation" rule.
 */
export function resolveIdentityScope(
  input: IdentityScopeInput | null | undefined,
): IdentityScopeResult {
  try {
    const src = asObject(input);
    const unreadable: string[] = [];
    const incognito = readFlag(src, 'incognito', unreadable);
    const firstPartyStorageSurvived = readFlag(src, 'firstPartyStorageSurvived', unreadable);
    const hardwareAnchorStable = readFlag(src, 'hardwareAnchorStable', unreadable);
    const contextSaltPresent = readFlag(src, 'contextSaltPresent', unreadable);

    let id_scope: IdentityScopeResult['id_scope'];
    let context_isolated: boolean;
    let rule: string;

    if (contextSaltPresent) {
      id_scope = 'context';
      context_isolated = true;
      rule = 'context_salt_present: explicit per-context salt isolates the identity scope';
    } else {
      id_scope = 'hardware';
      context_isolated = false;
      if (incognito && hardwareAnchorStable) {
        rule =
          'incognito + stable_hardware_anchor + no_context_salt: hardware scope from explicit metadata; incognito alone never implies privacy isolation and context isolation is NOT assumed';
      } else if (incognito) {
        rule =
          'incognito + no_context_salt: hardware scope from explicit metadata; hardware anchor not confirmed stable and context isolation is NOT assumed';
      } else if (hardwareAnchorStable) {
        rule =
          'no_context_salt: hardware scope on a stable hardware anchor; context isolation is NOT assumed';
      } else {
        rule =
          'no_context_salt: hardware scope fallback; no explicit isolation metadata and context isolation is NOT assumed';
      }
    }

    const metadata =
      `metadata: incognito=${boolText(incognito)}, ` +
      `first_party_storage_survived=${boolText(firstPartyStorageSurvived)}, ` +
      `hardware_anchor_stable=${boolText(hardwareAnchorStable)}, ` +
      `context_salt_present=${boolText(contextSaltPresent)}`;

    const notes = [
      rule,
      metadata,
      'first-party storage survival is not isolation metadata',
      'no identifier was minted',
    ];
    if (unreadable.length > 0) notes.push(`unreadable fields ignored (${unreadable.join(', ')})`);

    return { id_scope, context_isolated, reason: `${notes.join('; ')}.` };
  } catch {
    return {
      id_scope: 'hardware',
      context_isolated: false,
      reason:
        'resolveIdentityScope: unexpected input; hardware scope by default, context isolation NOT assumed; no identifier was minted.',
    };
  }
}

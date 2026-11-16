/**
 * Bot-verdict composition facade — pure function, ZERO imports (Workers safe).
 *
 * Composes the four independent evidence sources of the intel pipeline into a
 * single verdict, in strict precedence order:
 *
 *   1. RFC 9421 Web Bot Auth signature verified      → good / verified-agent.
 *   2. Directory identity explicitly 'spoofed'       → bad / spoofed-impersonation.
 *   3. Directory detected (verified or signed)       → good / agent identity.
 *   4. Client probe 'agent' + hard agent reason ids  → bad / automated-runtime.
 *   5. Client probe 'agent' with weak reasons only   → not_detected / suspected-automation.
 *   6. IP inside a known bot-operator CIDR but the UA does not look like a bot
 *      → known-operator-network (inconclusive: cloud VM or masked operator).
 *   7. UA looks like a bot on its own                → not_detected / suspected-automation.
 *   8. Nothing above fired                           → human-or-unverified.
 *
 * The verdict label is deliberately separate from the reason: the caller can
 * trust `verdict` for gating and still surface `reason_ids` in the UI.
 */

/* -------------------------------------------------------------------------- */
/* Types                                                                       */
/* -------------------------------------------------------------------------- */

export type BotVerdictLabel =
  | 'good'
  | 'bad'
  | 'known-operator-network'
  | 'not_detected'
  | 'human-or-unverified';

export type BotSeverity = 'none' | 'low' | 'medium' | 'high';

export interface BotVerifierWebBotAuth {
  /** RFC 9421 signature verification result for this request. */
  verified?: boolean;
  bot_id?: string | null;
  operator?: string | null;
}

export interface BotVerifierDirectory {
  /** Directory verification status: 'verified' | 'declared' | 'spoofed' | 'unknown'. */
  status?: string | null;
  /** The directory lists this agent (regardless of signature outcome). */
  detected?: boolean;
  /** A signed declaration exists for this agent. */
  signed?: boolean;
  bot_id?: string | null;
  operator?: string | null;
}

export interface BotVerifierClientProbe {
  /** Client-side runtime probe verdict: 'agent' | 'human' | 'unknown' | …. */
  verdict?: string | null;
  /** Probe reason ids; matched (lowercased, substring) against HARD_AGENT_REASON_IDS. */
  reasons?: string[];
}

export interface BotVerdictInput {
  webBotAuth?: BotVerifierWebBotAuth | null;
  directory?: BotVerifierDirectory | null;
  clientProbe?: BotVerifierClientProbe | null;
  /** Resolved IP falls inside an official bot-operator CIDR range. */
  ipInKnownBotCidr?: boolean;
  /** User-agent matches a known bot / crawler pattern. */
  uaLooksLikeBot?: boolean;
}

export interface BotVerdict {
  verdict: BotVerdictLabel;
  /** Primary human-readable reason id for this composition. */
  reason: string;
  /** All reason ids involved (probe reasons are preserved, never dropped). */
  reason_ids: string[];
  /** Directory / signature agent identity, when one is established. */
  agent_verdict: string | null;
  /** Cryptographic or directory-grade verification. */
  verified: boolean;
  severity: BotSeverity;
}

/* -------------------------------------------------------------------------- */
/* Hard agent reason ids                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Probe reason ids that prove an automated runtime on their own. Matching is
 * case-insensitive substring — probe emitters append context ('cdp.session',
 * 'navigator.webdriver=true', …) and the prefixes must still win.
 */
export const HARD_AGENT_REASON_IDS = ['cdp.', 'navigator.webdriver', 'automation user-agent'] as const;

function isHardAgentReason(reasons: string[]): boolean {
  for (const reason of reasons) {
    const text = typeof reason === 'string' ? reason.toLowerCase() : '';
    if (!text) continue;
    for (const hard of HARD_AGENT_REASON_IDS) {
      if (text.includes(hard)) return true;
    }
  }
  return false;
}

/* -------------------------------------------------------------------------- */
/* Composition                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Composes the final bot verdict. Total function over the input — never throws,
 * never returns an empty shape.
 */
export function composeBotVerdict(input: BotVerdictInput): BotVerdict {
  const webBotAuth = input.webBotAuth ?? {};
  const directory = input.directory ?? {};
  const clientProbe = input.clientProbe ?? {};

  const probeReasons = Array.isArray(clientProbe.reasons)
    ? clientProbe.reasons.filter((reason): reason is string => typeof reason === 'string' && reason.length > 0)
    : [];
  const probeVerdict = typeof clientProbe.verdict === 'string' ? clientProbe.verdict.toLowerCase() : '';
  const directoryStatus = typeof directory.status === 'string' ? directory.status.toLowerCase() : '';

  /* 1 — Web Bot Auth: cryptographic proof outranks everything. */
  if (webBotAuth.verified === true) {
    return {
      verdict: 'good',
      reason: 'verified-agent',
      reason_ids: ['verified-agent'],
      agent_verdict: webBotAuth.bot_id || webBotAuth.operator || 'verified-agent',
      verified: true,
      severity: 'none',
    };
  }

  /* 2 — Directory says the identity is forged. */
  if (directoryStatus === 'spoofed') {
    return {
      verdict: 'bad',
      reason: 'spoofed-impersonation',
      reason_ids: ['spoofed-impersonation', ...probeReasons],
      agent_verdict: directory.bot_id || directory.operator || null,
      verified: false,
      severity: 'high',
    };
  }

  /* 3 — Directory detects a known agent (verified or signed). */
  if (directory.detected === true && (directoryStatus === 'verified' || directory.signed === true)) {
    return {
      verdict: 'good',
      reason: directoryStatus === 'verified' ? 'verified-agent' : 'signed-agent',
      reason_ids: [directoryStatus === 'verified' ? 'verified-agent' : 'signed-agent', ...probeReasons],
      agent_verdict: directory.bot_id || directory.operator || null,
      verified: directoryStatus === 'verified',
      severity: 'none',
    };
  }

  /* 4 — Client probe found a hard automated-runtime marker. */
  if (probeVerdict === 'agent' && isHardAgentReason(probeReasons)) {
    return {
      verdict: 'bad',
      reason: 'automated-runtime',
      reason_ids: ['automated-runtime', ...probeReasons],
      agent_verdict: null,
      verified: false,
      severity: 'high',
    };
  }

  /* 5 — Client probe says agent, but only weak evidence. */
  if (probeVerdict === 'agent') {
    return {
      verdict: 'not_detected',
      reason: 'suspected-automation',
      reason_ids: ['suspected-automation', ...probeReasons],
      agent_verdict: null,
      verified: false,
      severity: 'low',
    };
  }

  /* 6 — Known operator network without a bot-shaped UA: inconclusive. */
  if (input.ipInKnownBotCidr === true && input.uaLooksLikeBot !== true) {
    return {
      verdict: 'known-operator-network',
      reason: 'known-operator-network',
      reason_ids: ['known-operator-network', ...probeReasons],
      agent_verdict: null,
      verified: false,
      severity: 'low',
    };
  }

  /* 7 — UA alone looks like a bot. */
  if (input.uaLooksLikeBot === true) {
    return {
      verdict: 'not_detected',
      reason: 'suspected-automation',
      reason_ids: ['suspected-automation', ...probeReasons],
      agent_verdict: null,
      verified: false,
      severity: 'low',
    };
  }

  /* 8 — Nothing implicated the request. */
  return {
    verdict: 'human-or-unverified',
    reason: 'not_detected',
    reason_ids: ['not_detected', ...probeReasons],
    agent_verdict: null,
    verified: false,
    severity: 'none',
  };
}

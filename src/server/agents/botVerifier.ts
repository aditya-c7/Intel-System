/**
 * Bot-verdict composition facade — pure function, ZERO imports (Workers safe).
 *
 * Composes the four independent evidence sources of the intel pipeline into a
 * single verdict, in strict precedence order:
 *
 *   0. WBA signature verified + `signed` identity + assistant/agent category
 *      → good / signed-agent (`bot:'good'`, `identity:'signed'`, `confidence:'high'`).
 *   1. RFC 9421 Web Bot Auth signature verified      → good / verified-agent.
 *   2. Directory identity explicitly 'spoofed'       → bad / spoofed-impersonation.
 *   3. Directory detected (verified or signed)       → good / agent identity.
 *   4. Client probe 'agent' + corroborated automation → bad / automated-runtime.
 *      A bare `cdp.*` bridge is `developer_tools` (weight 0) and CANNOT escalate.
 *   5. Client probe 'agent' with weak reasons only   → not_detected / suspected-automation.
 *   6. IP inside a known bot-operator CIDR but the UA does not look like a bot
 *      → known-operator-network (inconclusive: cloud VM or masked operator).
 *   7. UA looks like a bot on its own                → not_detected / suspected-automation.
 *   8. Nothing above fired                           → human-or-unverified.
 *
 * The evidence weights are the four-tier taxonomy defined in `src/lib/verdict.ts`
 * (`hard` / `medium` / `weak` / `developer_tools`). They are mirrored here so this
 * facade stays import-free and Workers-safe — keep the id tables in sync with
 * that module. Reason ids arrive from two namespaces: the client probe
 * (`src/client/signals/automation.ts`) and the server evidence gate
 * (`src/lib/verdict.ts`). A second probe may corroborate; a bare `cdp.*` may not.
 *
 * The verdict label is deliberately separate from the reason: the caller can
 * trust `verdict` for gating and still surface `reason_ids` in the UI. `bot` is
 * the API-facing signal and `isBot` is its boolean mirror (`bot !== 'not_detected'`),
 * so the bot/isBot parity invariant holds on every return path.
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

/** API-facing bot signal — mirrors `telemetryContract.AutomationAxes['bot']`. */
export type BotSignal = 'not_detected' | 'suspected' | 'bad' | 'good' | 'ai_agent';

/** Directory / signature identity grade. */
export type BotIdentity = 'verified' | 'signed' | 'unknown' | 'spoofed';

export type BotConfidence = 'high' | 'medium' | 'low';

export interface BotVerifierWebBotAuth {
  /** RFC 9421 signature verification result for this request. */
  verified?: boolean;
  bot_id?: string | null;
  operator?: string | null;
  /** WBA identity grade; `signed` enables the signed-good-agent path. */
  identity?: string | null;
  /** Verification status alias used by the WBA verifier (`verified` | `signed` | …). */
  status?: string | null;
  /** Agent category from the registry (`ai_assistant` / `ai_agent` / `assistant` / `agent`). */
  category?: string | null;
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
  /** Directory identity grade; `signed` enables the signed-good-agent path. */
  identity?: string | null;
  /** Agent category from the registry. */
  category?: string | null;
}

export interface BotVerifierClientProbe {
  /** Client-side runtime probe verdict: 'agent' | 'human' | 'unknown' | …. */
  verdict?: string | null;
  /** Probe reason ids; classified with the four-tier weight taxonomy below. */
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
  /** Agent category when only the caller has it (mirrors the registry category). */
  category?: string | null;
}

export interface BotVerdict {
  verdict: BotVerdictLabel;
  /** Primary human-readable reason id for this composition. */
  reason: string;
  /** All reason ids involved (probe reasons are preserved, never dropped). */
  reason_ids: string[];
  /** Directory / signature agent identity, when one is established (exact name, unmodified). */
  agent_verdict: string | null;
  /** Cryptographic or directory-grade verification. */
  verified: boolean;
  severity: BotSeverity;
  /** API-facing bot signal derived from `verdict`. */
  bot: BotSignal;
  /** Boolean mirror of `bot`: false only for `not_detected` (bot/isBot parity). */
  isBot: boolean;
  /** Identity grade attached to this verdict. */
  identity: BotIdentity;
  /** Confidence of this verdict. */
  confidence: BotConfidence;
}

type BotVerdictCore = Omit<BotVerdict, 'bot' | 'isBot' | 'identity' | 'confidence'>;

/* -------------------------------------------------------------------------- */
/* Four-tier reason-weight taxonomy (mirror of src/lib/verdict.ts)             */
/* -------------------------------------------------------------------------- */

export type ReasonWeight = 'hard' | 'medium' | 'weak' | 'developer_tools';
export type ReasonNamespace = 'automation' | 'verdict';

/**
 * The single hard-escalation path for a CDP bridge: emitted only when a runtime
 * bridge is present AND no trusted human input was recorded after the dwell
 * window. A bare `cdp.*` attachment stays in `developer_tools` (weight 0).
 */
export const CORROBORATED_CDP_REASON_ID = 'bot.stealth-automation-uncorroborated';
export const CORROBORATED_CHROMIUM_CDP_REASON_ID = 'bot.chromium-automation-uncorroborated';

/**
 * Probe reason ids that are, by themselves, proof of an automated runtime.
 * NOTE: bare `'cdp.'` is deliberately absent — CDP is weight 0 / unattributed
 * per verdict.ts. Only corroborated automation (the ids below) is hard.
 */
export const HARD_AGENT_REASON_IDS = [
  'navigator.webdriver',
  'automation user-agent', // legacy substring alias for an automation UA
  'ua.headless-chrome',
  'ua.automation-signature',
  'cdp.ua_override.empty_brands',
  'page.ua.cursor',
  'page.platform.cloudflare-workers',
  'launch.ipc-flooding-switch',
  'bot.cdp-tampered',
  'bot.playwright-binding',
  'cdc.global.binding',
  CORROBORATED_CDP_REASON_ID,
  CORROBORATED_CHROMIUM_CDP_REASON_ID,
] as const;

/** CDP Runtime / Network bridge artifacts — reported, never a verdict on their own. */
const DEVELOPER_TOOLS_REASON_IDS: ReadonlySet<string> = new Set([
  'cdp.runtime.enable.empty_source',
  'cdp.network.enable.pre_load_message',
  'bot.cdp-runtime-leak',
]);

/** Meaningful only in pairs, or paired with any weak reason. */
const MEDIUM_REASON_IDS: ReadonlySet<string> = new Set([
  'headless.shell.url_scheme_port',
  'headless.linux.no_pointer',
  'headless.heap-3digit-rounding',
  'headless.font-exact-integers',
  'headless.no-intlyen-key',
  'headless.secch-headless-mismatch',
  'instinct.credentials.wrappers',
  'instinct.geetest.accessor-pair',
  'muse.cloud-browser.password-manager',
  'grok.cloud-computer.environment',
  'codex.prompt.anonymous-native',
  'codex.keyboard.empty-layout-map',
]);

/** Real humans trip these regularly — telemetry only, never sufficient alone. */
const WEAK_REASON_IDS: ReadonlySet<string> = new Set([
  'headless.swiftshader.caveat',
  'launch.no-speech-voices',
  'kinematics.zero_pointer_trail',
  'kinematics.screenshot_offset',
  'playwright.mcp.pressure',
  'chatgpt.badge.active',
  'chatgpt.badge.overlay',
  'claude.marker.active',
  'codex.overlay.shadow-root',
  'input.hidden-document',
  'bot.software-gpu',
  'bot.empty-languages',
  'bot.zero-geometry',
  'bot.rtt-zero',
  'bot.plugins-empty',
  'bot.webdriver-getter-tampered-cdp',
  'bot.webdriver-getter-tampered',
  'bot.automation-getter-tampered',
]);

/** Prefix rules evaluated after the exact sets (first match wins). */
const PREFIX_RULES: ReadonlyArray<{ prefix: string; weight: ReasonWeight }> = [
  { prefix: 'cdp.', weight: 'developer_tools' }, // bare CDP is weight 0
  { prefix: 'playwright.', weight: 'hard' },
  { prefix: 'cdc.', weight: 'hard' },
  { prefix: 'ua.headless', weight: 'hard' },
  { prefix: 'selenium.', weight: 'hard' },
  { prefix: 'webdriver.', weight: 'hard' },
  { prefix: 'headless.', weight: 'medium' },
  { prefix: 'instinct.', weight: 'medium' },
  { prefix: 'muse.', weight: 'medium' },
  { prefix: 'grok.', weight: 'medium' },
  { prefix: 'codex.', weight: 'medium' },
  { prefix: 'kinematics.', weight: 'weak' },
  { prefix: 'behavior.', weight: 'weak' },
  { prefix: 'bot.', weight: 'weak' },
];

/** Reason ids emitted by the client probe (`src/client/signals/automation.ts`). */
const AUTOMATION_REASON_IDS: ReadonlySet<string> = new Set([
  'cdp.runtime.enable',
  'cdp.console.debug',
  'cdp.network.order',
  'launch.no-speech-voices',
  'launch.no-languagedetector',
  'ua.brands-vs-ua-mismatch',
  'headless.any-pointer-none',
  'headless.swiftshader.caveat',
  'headless.no-intlyen-key',
  'headless.chrome-extension-port',
  'headless.heap-3digit-rounding',
  'headless.font-exact-integers',
  'headless.secch-headless-mismatch',
  'behavior.pointer-stale',
  'behavior.zero-pressure',
  'behavior.hidden-input',
  'muse',
  'grok-bot',
  'codex-browser',
  'instinct',
  'chatgpt.badge.active',
  'claude.marker.active',
]);

/** Classify a single reason id into its evidence weight (parity with verdict.ts). */
export function classifyReasonId(reasonId: string): ReasonWeight {
  const id = (reasonId || '').trim().toLowerCase();
  if (!id) return 'weak';
  if ((HARD_AGENT_REASON_IDS as readonly string[]).includes(id)) return 'hard';
  if (id.includes('automation user-agent')) return 'hard'; // legacy substring alias
  if (DEVELOPER_TOOLS_REASON_IDS.has(id)) return 'developer_tools';
  if (MEDIUM_REASON_IDS.has(id)) return 'medium';
  if (WEAK_REASON_IDS.has(id)) return 'weak';
  for (const rule of PREFIX_RULES) {
    if (id.startsWith(rule.prefix)) return rule.weight;
  }
  return 'weak';
}

/** Which emitter produced a reason id: the client probe or the server gate. */
export function reasonNamespace(reasonId: string): ReasonNamespace {
  const id = (reasonId || '').trim().toLowerCase();
  if (!id) return 'verdict';
  if ((HARD_AGENT_REASON_IDS as readonly string[]).some((hard) => hard === id || id.startsWith(hard))) {
    return 'verdict';
  }
  if (AUTOMATION_REASON_IDS.has(id)) return 'automation';
  if (/^(launch\.|behavior\.|cdp\.|ua\.|muse$|grok-bot$|codex-browser$|instinct$|chatgpt\.|claude\.)/.test(id)) {
    return 'automation';
  }
  return 'verdict';
}

export interface GatedAgentEvidence {
  verdict: 'human' | 'uncertain' | 'automated';
  hardReasons: string[];
  mediumReasons: string[];
  weakReasons: string[];
  /** Bare CDP / bridge artifacts — weight 0, never counts toward the gate. */
  developerToolsReasons: string[];
  /** How many reasons came from each namespace (corroboration provenance). */
  namespaces: Record<ReasonNamespace, number>;
}

/**
 * Weight the probe reasons exactly like verdict.ts: automated requires a hard
 * reason, two medium reasons, or one medium plus any weak reason. A bare `cdp.*`
 * lands in `developerToolsReasons` and can never escalate by itself.
 */
export function gateAgentReasons(reasons: ReadonlyArray<string>): GatedAgentEvidence {
  const hardReasons: string[] = [];
  const mediumReasons: string[] = [];
  const weakReasons: string[] = [];
  const developerToolsReasons: string[] = [];
  const namespaces: Record<ReasonNamespace, number> = { automation: 0, verdict: 0 };

  for (const reason of reasons || []) {
    const id = (reason || '').trim();
    if (!id) continue;
    namespaces[reasonNamespace(id)] += 1;
    switch (classifyReasonId(id)) {
      case 'hard':
        hardReasons.push(id);
        break;
      case 'medium':
        mediumReasons.push(id);
        break;
      case 'developer_tools':
        developerToolsReasons.push(id);
        break;
      default:
        weakReasons.push(id);
        break;
    }
  }

  let verdict: GatedAgentEvidence['verdict'] = 'human';
  if (hardReasons.length > 0) verdict = 'automated';
  else if (mediumReasons.length >= 2) verdict = 'automated';
  else if (mediumReasons.length === 1 && weakReasons.length > 0) verdict = 'automated';
  else if (mediumReasons.length === 1) verdict = 'uncertain';

  return { verdict, hardReasons, mediumReasons, weakReasons, developerToolsReasons, namespaces };
}

/** Backwards-compatible helper — true only for corroborated automation. */
function isHardAgentReason(reasons: string[]): boolean {
  return gateAgentReasons(reasons).verdict === 'automated';
}

/* -------------------------------------------------------------------------- */
/* Signed-good-agent helpers                                                    */
/* -------------------------------------------------------------------------- */

const GOOD_AGENT_CATEGORIES: ReadonlySet<string> = new Set([
  'assistant',
  'agent',
  'ai_assistant',
  'ai_agent',
]);

function normalizedCategory(value: unknown): string {
  return typeof value === 'string'
    ? value.trim().toLowerCase().replace(/[\s-]+/g, '_')
    : '';
}

function isAssistantOrAgentCategory(values: unknown[]): boolean {
  return values.some((value) => GOOD_AGENT_CATEGORIES.has(normalizedCategory(value)));
}

function normalizeIdentity(value: unknown): BotIdentity | null {
  const id = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return id === 'verified' || id === 'signed' || id === 'spoofed' || id === 'unknown'
    ? id
    : null;
}

function hasSignedIdentity(values: unknown[]): boolean {
  return values.some((value) => normalizeIdentity(value) === 'signed');
}

/* -------------------------------------------------------------------------- */
/* Composition                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Composes the final bot verdict. Total function over the input — never throws,
 * never returns an empty shape.
 */
export function composeBotVerdict(input: BotVerdictInput): BotVerdict {
  const core = composeBotVerdictCore(input);
  const bot = botSignalFor(core.verdict);
  const explicitIdentity = normalizeIdentity(
    input.webBotAuth?.identity ??
      input.webBotAuth?.status ??
      input.directory?.identity ??
      input.directory?.status
  );
  return {
    ...core,
    bot,
    isBot: bot !== 'not_detected',
    identity: explicitIdentity ?? identityForReason(core.reason),
    confidence: confidenceForReason(core.reason),
  };
}

/** Inner precedence ladder; the public wrapper adds the parity/identity fields. */
function composeBotVerdictCore(input: BotVerdictInput): BotVerdictCore {
  const webBotAuth = input.webBotAuth ?? {};
  const directory = input.directory ?? {};
  const clientProbe = input.clientProbe ?? {};

  const probeReasons = Array.isArray(clientProbe.reasons)
    ? clientProbe.reasons.filter((reason): reason is string => typeof reason === 'string' && reason.length > 0)
    : [];
  const probeVerdict = typeof clientProbe.verdict === 'string' ? clientProbe.verdict.toLowerCase() : '';
  const directoryStatus = typeof directory.status === 'string' ? directory.status.toLowerCase() : '';

  /* 0 — Signed good agent: WBA cryptographic proof + signed identity + an
   *     assistant/agent category. This outranks every bad path (including a
   *     spoofed directory claim and a hard client probe). */
  const signedWba =
    webBotAuth.verified === true &&
    (hasSignedIdentity([webBotAuth.identity, webBotAuth.status]) ||
      hasSignedIdentity([directory.identity, directory.status, directory.signed === true ? 'signed' : null]));
  if (
    signedWba &&
    isAssistantOrAgentCategory([webBotAuth.category, directory.category, input.category])
  ) {
    return {
      verdict: 'good',
      reason: 'signed-agent',
      reason_ids: ['signed-agent', ...probeReasons],
      agent_verdict:
        webBotAuth.bot_id || webBotAuth.operator || directory.bot_id || directory.operator || null,
      verified: true,
      severity: 'none',
    };
  }

  /* 1 — Web Bot Auth: cryptographic proof outranks everything else. */
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

  /* 4 — Client probe found corroborated automated-runtime evidence.
   *     A bare cdp.* reason is developer_tools (weight 0) and cannot get here. */
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

/* -------------------------------------------------------------------------- */
/* Derived parity fields                                                        */
/* -------------------------------------------------------------------------- */

function botSignalFor(label: BotVerdictLabel): BotSignal {
  switch (label) {
    case 'good':
      return 'good';
    case 'bad':
      return 'bad';
    case 'known-operator-network':
      return 'suspected';
    case 'not_detected':
    case 'human-or-unverified':
    default:
      return 'not_detected';
  }
}

function identityForReason(reason: string): BotIdentity {
  switch (reason) {
    case 'verified-agent':
      return 'verified';
    case 'signed-agent':
      return 'signed';
    case 'spoofed-impersonation':
      return 'spoofed';
    default:
      return 'unknown';
  }
}

function confidenceForReason(reason: string): BotConfidence {
  switch (reason) {
    case 'verified-agent':
    case 'signed-agent':
    case 'spoofed-impersonation':
    case 'automated-runtime':
      return 'high';
    default:
      return 'low';
  }
}

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
 *   3.5 Explicit named crawler / AI-agent UA claim with NO valid signature AND an
 *       out-of-list IP (no official CIDR / FCrDNS proof) → bad / spoofed-impersonation.
 *       A UA-only claim cannot mint a verified identity; NEUTRAL + out-of-list is only
 *       an inconclusive "unverified" result for non-crawler UAs. Signed-good still wins.
 *   4. Client probe 'agent' + corroborated automation → bad / automated-runtime.
 *      A bare `cdp.*` bridge is `developer_tools` (weight 0) and CANNOT escalate.
 *   5. Client probe 'agent' with weak reasons only   → not_detected / suspected-automation.
 *   6. IP inside a known bot-operator CIDR but the UA does not look like a bot
 *      → known-operator-network (inconclusive: cloud VM or masked operator).
 *   7. UA looks like a bot on its own                → not_detected / suspected-automation.
 *   8. Nothing above fired                           → human-or-unverified.
 *
 * Additive, non-escalating signal: `activeCdpInspection` records a SECOND external CDP
 * client that enabled the Runtime / Page domains. That is an active protocol-inspection
 * session — not docked human DevTools — and is reported ONLY as the weight-0 reason
 * `bot.cdp-active-inspection` plus the distinct `automation_protocol_inspection_active`
 * state. It is never a bad-bot path and never creates a second taxonomy.
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
  /** RFC 9421 tri-state outcome: `valid` | `invalid` | `neutral` (NEUTRAL falls back to IP/UA). */
  result?: string | null;
  /** Reason code for an INVALID signature — never contributes to a good verdict. */
  invalidReason?: string | null;
  /** Agent category from the registry (`ai_assistant` / `ai_agent` / `assistant` / `agent`). */
  category?: string | null;
  /** Verified trust-anchor agent id (WbaVerification field, additive). */
  agentId?: string | null;
  /* --- additive proof fields published by `src/lib/wbaVerifier.ts` --- */
  /** Proof reason: `signed-agent` on a verified signature, otherwise a tri-state reason. */
  reason?: string | null;
  /** Proof method: `rfc9421` / `signed_agent` / `page_attestation` / `none`. */
  verification_method?: string | null;
  /** Helper tri-state outcome: `VALID` / `INVALID` / `NEUTRAL`. */
  outcome?: string | null;
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

/** Additive shadow stealth evidence (mirrors `StealthEvaluation`). */
export interface BotVerifierStealth {
  /** Evaluator's detected flag; signed-good callers still keep their good verdict. */
  detected?: boolean | null;
  /** Observed stealth signal ids. */
  ids?: ReadonlyArray<string> | null;
  /** Hard-tier stealth ids; only a corroborated CDP bridge appears here. */
  hard?: ReadonlyArray<string> | null;
  /** Ids whose RED sub-variant fired (exact protocol-level condition). */
  confirmed?: ReadonlyArray<string> | null;
  /** Ids the probe could not decide (no CSP, exception): reported at weight 0. */
  inconclusive?: ReadonlyArray<string> | null;
  /** Ids seen only in a soft/YELLOW form (e.g. SwiftShader on a headless-shell host). */
  soft?: ReadonlyArray<string> | null;
  /** Ids observed while DevTools is docked (runtime-enable leak capped at YELLOW). */
  docked?: ReadonlyArray<string> | null;
  /** Attribution for a confirmed source-URL leak. */
  sourceUrlSource?: 'puppeteer' | 'playwright' | null;
}

export interface BotVerdictInput {
  webBotAuth?: BotVerifierWebBotAuth | null;
  directory?: BotVerifierDirectory | null;
  clientProbe?: BotVerifierClientProbe | null;
  /** Shadow stealth-signal evaluation folded into the probe-evidence channel. */
  stealth?: BotVerifierStealth | null;
  /**
   * A SECOND external CDP client has enabled the Runtime / Page domains — an active
   * protocol-inspection session, distinct from docked human DevTools. Purely additive:
   * publishes `bot.cdp-active-inspection` at weight 0 and the distinct active state.
   */
  activeCdpInspection?: boolean;
  /**
   * Resolved IP matches an EXACT published CIDR prefix from an official operator feed
   * (OpenAI / Google / Anthropic / Perplexity), never a whole cloud ASN. Out-of-list
   * means unverified — not proven malicious — and stays inconclusive below.
   */
  ipInKnownBotCidr?: boolean;
  /** User-agent matches a known bot / crawler pattern. */
  uaLooksLikeBot?: boolean;
  /**
   * Raw User-Agent string, when the caller has it. Used only to recognise an EXPLICIT
   * named crawler / AI-agent claim (Googlebot, GPTBot, ClaudeBot, PerplexityBot, …).
   */
  userAgent?: string | null;
  /** Alias for `userAgent`. */
  ua?: string | null;
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
  /**
   * Detection confidence, NOT a claim of malicious intent: `bad` means deterministic
   * automation or identity misrepresentation — a "bad bot" label is not an accusation.
   */
  severity: BotSeverity;
  /** API-facing bot signal derived from `verdict`. */
  bot: BotSignal;
  /** Boolean mirror of `bot`: false only for `not_detected` (bot/isBot parity). */
  isBot: boolean;
  /** Identity grade attached to this verdict. */
  identity: BotIdentity;
  /** Confidence of this verdict. */
  confidence: BotConfidence;
  /**
   * Distinct protocol-inspection state. `automation_protocol_inspection_active` only when
   * `activeCdpInspection` was set; otherwise `automation_protocol_inspection_idle`. It is a
   * separate axis — it never changes the verdict label, `bot` or `isBot`.
   */
  inspection_state: CdpInspectionState;
  /** Alias of `inspection_state` using the full state vocabulary. */
  automation_protocol_inspection_state: CdpInspectionState;
}

type BotVerdictCore = Omit<
  BotVerdict,
  'bot' | 'isBot' | 'identity' | 'confidence' | 'inspection_state' | 'automation_protocol_inspection_state'
>;

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
 * Additive, weight-0 observation: a SECOND external CDP client enabled the Runtime / Page
 * domains. That is an active automation-protocol inspection session — NOT docked human
 * DevTools — and is reported for attribution only. It can never escalate to a bad bot.
 */
export const ACTIVE_CDP_INSPECTION_REASON_ID = 'bot.cdp-active-inspection';

/** Distinct state published on the verdict when `activeCdpInspection` is set on the input. */
export type CdpInspectionState =
  | 'automation_protocol_inspection_active'
  | 'automation_protocol_inspection_idle';
export const ACTIVE_CDP_INSPECTION_STATE: CdpInspectionState = 'automation_protocol_inspection_active';
export const IDLE_CDP_INSPECTION_STATE: CdpInspectionState = 'automation_protocol_inspection_idle';

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
  // Shadow stealth probes mapped into THIS hard tier (no second taxonomy).
  'stealth.bypass-csp',
  'playwright.init-scripts',
  // Confirmed (RED) stealth variants: protocol-level impossibilities. Plain ids stay
  // medium/weak, so page-script / extension / user-setting artifacts cannot escalate.
  'stealth.runtime-enable-protocol',
  'stealth.document-interception-protocol',
  'stealth.storage-partitioning-protocol',
  'stealth.puppeteer-source-url',
  'stealth.playwright-source-url',
  // H3 desktop conjunction (mirror of verdict.ts HARD_REASONS; exact entry wins over
  // the weak `headless.swiftshader.caveat` and the medium `headless.` prefix): a
  // software-GL context returned despite failIfMajorPerformanceCaveat under a
  // desktop-claiming UA-CH platform with zero touch points — a forced headless launch.
  'headless.swiftshader.caveat.desktop',
  'bot.cdp-tampered',
  'bot.playwright-binding',
  // RS-E: cdc_* binding globals are UNATTRIBUTED runtime artifacts (CDP bridge / injected
  // client) — a different evidentiary class from deterministic automation proof. They are
  // recorded in the weight-0 developer_tools tier below and can never disqualify a signed
  // good agent. Only corroborated hard automation can reach `bad`, after every crypto rung.
  CORROBORATED_CDP_REASON_ID,
  CORROBORATED_CHROMIUM_CDP_REASON_ID,
] as const;

/** CDP Runtime / Network bridge artifacts — reported, never a verdict on their own. */
const DEVELOPER_TOOLS_REASON_IDS: ReadonlySet<string> = new Set([
  'cdp.runtime.enable.empty_source',
  'cdp.network.enable.pre_load_message',
  // C1 dedicated-Worker variant (mirror of verdict.ts DEVELOPER_TOOLS_REASONS): the
  // empty-source uncaught-error tell observed inside a Blob Worker realm. Weight 0,
  // corroborating only — never a bot verdict on its own.
  'cdp.runtime.enable.worker',
  'bot.cdp-runtime-leak',
  // RS-E: cdc_* / bare CDP are unattributed runtime artifacts — telemetry-only evidence.
  // Automation is expected for verified agents and cannot disqualify signed good.
  'cdc.global.binding',
  // A second external CDP client driving Runtime / Page: active inspection, weight 0.
  // Exact entry wins over the generic weak `bot.` prefix rule — never a hard path.
  ACTIVE_CDP_INSPECTION_REASON_ID,
  // Inconclusive stealth probes: reported at weight 0, never escalate or corroborate.
  'stealth.inconclusive',
]);

/** Meaningful only in pairs, or paired with any weak reason. */
const MEDIUM_REASON_IDS: ReadonlySet<string> = new Set([
  'headless.shell.url_scheme_port',
  'headless.linux.no_pointer',
  'headless.heap-3digit-rounding',
  'headless.font-exact-integers',
  'headless.no-intlyen-key',
  'headless.secch-headless-mismatch',
  // Notification-permission contract mismatch (mirror of verdict.ts MEDIUM_REASONS):
  // Notification.permission says 'denied' while the Permissions API resolves 'prompt'.
  'headless.notification-contract',
  'instinct.credentials.wrappers',
  'instinct.geetest.accessor-pair',
  'muse.cloud-browser.password-manager',
  'grok.cloud-computer.environment',
  'codex.prompt.anonymous-native',
  'codex.keyboard.empty-layout-map',
  // Conditional stealth probes: corroboration or a companion is mandatory.
  'stealth.runtime-enable-leak',
  'stealth.document-interception',
  'stealth.storage-partitioning',
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
  // Telemetry-only stealth artifacts. Exact entries keep the source-URL leak in
  // `weak` rather than the bare `cdp.` developer_tools prefix — never hard.
  'cdp.runtime.evaluate.source-url',
  'bot.popup-blocking',
]);

/** Prefix rules evaluated after the exact sets (first match wins). */
const PREFIX_RULES: ReadonlyArray<{ prefix: string; weight: ReasonWeight }> = [
  { prefix: 'cdp.', weight: 'developer_tools' }, // bare CDP is weight 0
  // RS-E: cdc_* binding globals are unattributed runtime artifacts (weight 0), not proof
  // of a driven runtime. Exact entries win, so `cdc.global.binding` stays developer_tools.
  { prefix: 'cdc.', weight: 'developer_tools' },
  { prefix: 'playwright.', weight: 'hard' },
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
  'headless.swiftshader.caveat.desktop',
  'headless.notification-contract',
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
  if (/^(launch\.|behavior\.|cdp\.|stealth\.|ua\.|muse$|grok-bot$|codex-browser$|instinct$|chatgpt\.|claude\.)/.test(id)) {
    return 'automation';
  }
  return 'verdict';
}

/* -------------------------------------------------------------------------- */
/* Stealth-signal → existing taxonomy bridge (mirror of src/lib/verdict.ts)      */
/* -------------------------------------------------------------------------- */

/**
 * Maps `src/lib/stealthSignals.ts` signal ids onto the reason ids of THIS taxonomy.
 * A bridge into the four tiers above — not a second weight vocabulary.
 */
export const STEALTH_SIGNAL_REASON_IDS: Readonly<Record<string, string>> = Object.freeze({
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

/**
 * Qualifiers selecting between reason ids that ALREADY live in the four tiers — not a
 * second RED/YELLOW vocabulary. RED (protocol-level impossibility) → hard; YELLOW
 * (reproducible by page scripts / extensions / user settings) → medium/weak;
 * inconclusive → weight-0 developer_tools.
 */
export interface StealthReasonOptions {
  /** The signal's RED sub-variant was observed (exact protocol-level condition). */
  confirmed?: boolean;
  /** DevTools is docked: a runtime-enable leak is capped at YELLOW, never RED. */
  docked?: boolean;
  /** The probe could not decide (no CSP, exception, missing precondition). */
  inconclusive?: boolean;
  /** Only the soft/YELLOW form was seen (e.g. SwiftShader on a headless-shell host). */
  soft?: boolean;
  /** Attribution for a confirmed source-URL leak. */
  source?: 'puppeteer' | 'playwright' | null;
}

/** Reason id for a stealth signal id; a corroborated CDP bridge maps to the single hard id. */
export function stealthReasonId(
  id: string,
  corroborated = false,
  options: StealthReasonOptions = {},
): string | null {
  const base = STEALTH_SIGNAL_REASON_IDS[id];
  if (base === undefined) return null;
  if (options.inconclusive) return 'stealth.inconclusive';

  if (id === 'cdpBindingGlobals') {
    return corroborated ? CORROBORATED_CDP_REASON_ID : base; // bare = developer_tools hint
  }
  if (id === 'sourceUrlLeak') {
    if (options.confirmed) {
      return options.source === 'puppeteer'
        ? 'stealth.puppeteer-source-url'
        : 'stealth.playwright-source-url';
    }
    return base; // bare filename = weak/yellow
  }
  if (id === 'chromeHeadlessShell') {
    return options.soft ? 'headless.swiftshader.caveat' : base; // SwiftShader = weak/yellow
  }
  if (id === 'runtimeEnableLeak') {
    return options.confirmed && !options.docked ? 'stealth.runtime-enable-protocol' : base;
  }
  if (id === 'documentInterception') {
    return options.confirmed ? 'stealth.document-interception-protocol' : base;
  }
  if (id === 'storagePartitioning') {
    return options.confirmed ? 'stealth.storage-partitioning-protocol' : base;
  }
  return base;
}

/** Existing-tier weight for a stealth signal id; null for an unknown id. */
export function stealthReasonWeight(
  id: string,
  corroborated = false,
  options: StealthReasonOptions = {},
): ReasonWeight | null {
  const reason = stealthReasonId(id, corroborated, options);
  return reason === null ? null : classifyReasonId(reason);
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

/** Normalized additive proof string. */
function proofString(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

/**
 * RS-E: a verified RFC 9421 signature is itself a signed-identity proof. The published proof
 * fields (`reason`, `identity`, `verification_method`) let a verified agent win BEFORE the
 * hard-automation rung even when no legacy `identity:'signed'` flag was supplied — automation
 * is expected for verified agents and cannot disqualify signed good.
 */
function hasSignedProof(wba: BotVerifierWebBotAuth): boolean {
  const reason = proofString(wba.reason);
  const method = proofString(wba.verification_method);
  return (
    normalizeIdentity(wba.identity) === 'signed' ||
    reason === 'signed-agent' ||
    method === 'rfc9421' ||
    method === 'signed_agent'
  );
}

/**
 * RFC 9421 tri-state gate. Only a VALID signature grants the good paths; INVALID and
 * NEUTRAL never do. NEUTRAL simply falls through to the IP / UA inconclusive paths.
 * An explicit `result`/`status` overrides the looser `verified` compatibility boolean.
 */
function isWbaValid(wba: BotVerifierWebBotAuth): boolean {
  const outcome = proofString(wba.outcome);
  if (outcome === 'invalid' || outcome === 'neutral') return false;
  if (outcome === 'valid') return true;
  const result = proofString(wba.result);
  if (result === 'invalid' || result === 'neutral') return false;
  if (result === 'valid') return true;
  const status = proofString(wba.status);
  if (status === 'invalid' || status === 'neutral') return false;
  return wba.verified === true;
}

/* -------------------------------------------------------------------------- */
/* Explicit verified-bot claim detection                                       */
/* -------------------------------------------------------------------------- */

/**
 * Brands whose identity is routinely impersonated by a bare User-Agent token. These are
 * the only claims that can be "spoofed": a generic automation UA (HeadlessChrome,
 * Playwright, …) never claims a verification-backed identity and stays inconclusive.
 * Static registry knowledge mirrored here so this facade remains import-free.
 */
const CLAIMED_OFFICIAL_BOT_PATTERN =
  /googlebot|googleother|google-inspectiontool|gptbot|chatgpt-user|oai-searchbot|claudebot|claude-user|claude-searchbot|perplexitybot|perplexity-user|ccbot|bingbot|applebot|meta-externalagent|grokbot|bedrockagentcore|mistralai[_-]?user|manus-user/i;

/** Categories whose *name* is itself a claim to a verification-backed crawler/agent. */
const CLAIMED_BOT_CATEGORIES: ReadonlySet<string> = new Set([
  'ai_crawler',
  'search_crawler',
  'link_preview',
  'crawler',
]);

/**
 * True when the request explicitly claims a named, verification-backed crawler /
 * AI-agent identity — via the caller's `uaLooksLikeBot` flag, a raw UA string, a
 * directory claimed bot id/operator, or a crawler category. A plain human UA is false.
 */
function claimsOfficialBotIdentity(input: BotVerdictInput): boolean {
  if (input.uaLooksLikeBot === true) return true;

  const pieces: string[] = [];
  for (const value of [
    input.userAgent,
    input.ua,
    input.webBotAuth?.bot_id,
    input.webBotAuth?.operator,
    input.directory?.bot_id,
    input.directory?.operator,
  ]) {
    if (typeof value === 'string' && value.length > 0) pieces.push(value);
  }
  const claimedText = pieces.join(' ');
  if (claimedText && CLAIMED_OFFICIAL_BOT_PATTERN.test(claimedText)) return true;

  return [
    input.category,
    input.webBotAuth?.category,
    input.directory?.category,
  ].some((value) => CLAIMED_BOT_CATEGORIES.has(normalizedCategory(value)));
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
  const reasonIdentity = identityForReason(core.reason);
  const inspectionState: CdpInspectionState =
    input.activeCdpInspection === true ? ACTIVE_CDP_INSPECTION_STATE : IDLE_CDP_INSPECTION_STATE;
  return {
    ...core,
    bot,
    isBot: bot !== 'not_detected',
    // Separate, additive axis: never feeds the verdict, `bot` or `isBot`.
    inspection_state: inspectionState,
    automation_protocol_inspection_state: inspectionState,
    // A spoofed-impersonation core result is authoritative: an input-level 'unknown'
    // or 'verified' claim must never downgrade identity='spoofed'. A signed-good core result
    // is equally authoritative for its own reason: identity MUST be 'signed' even when an
    // upstream claim says 'verified' or 'unknown' (RS-E signed-good precedence / parity).
    identity:
      reasonIdentity === 'spoofed'
        ? 'spoofed'
        : core.reason === 'signed-agent'
          ? 'signed'
          : core.reason === 'verified-agent'
            ? 'verified'
            : explicitIdentity ?? reasonIdentity,
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

  // Fold shadow stealth evidence into the SAME probe-evidence channel so the precedence
  // ladder below (signed good > WBA > spoofed > directory > automation) applies unchanged:
  // step 0 still wins over any stealth escalation. No second taxonomy, no second verdict.
  const stealth = input.stealth ?? null;
  const stealthIdsRaw = stealth?.ids;
  const stealthHardRaw = stealth?.hard;
  const stealthIds = Array.isArray(stealthIdsRaw)
    ? stealthIdsRaw.filter((id): id is string => typeof id === 'string' && id.length > 0)
    : [];
  const stealthHard = Array.isArray(stealthHardRaw)
    ? stealthHardRaw.filter((id): id is string => typeof id === 'string')
    : [];
  const stealthDetected = stealth?.detected === true;
  const inList = (list: readonly string[] | null | undefined, id: string): boolean =>
    Array.isArray(list) && (list as readonly string[]).includes(id);
  const stealthReasons: string[] = [];
  for (const id of stealthIds) {
    const reason = stealthReasonId(id, stealthHard.includes(id), {
      confirmed: inList(stealth?.confirmed, id),
      inconclusive: inList(stealth?.inconclusive, id),
      soft: inList(stealth?.soft, id),
      docked: inList(stealth?.docked, id),
      source: stealth?.sourceUrlSource ?? null,
    });
    if (reason && !stealthReasons.includes(reason)) stealthReasons.push(reason);
  }
  // Additive active-CDP-inspection observation. It joins the SAME probe-evidence channel
  // only so it is preserved in `reason_ids`; its weight-0 `developer_tools` classification
  // cannot satisfy the hard/medium gate below. No verdict rung is added or reordered.
  const activeInspectionReasons: string[] =
    input.activeCdpInspection === true ? [ACTIVE_CDP_INSPECTION_REASON_ID] : [];
  const allProbeReasons = [...probeReasons, ...stealthReasons, ...activeInspectionReasons];
  const effectiveProbeVerdict = probeVerdict === 'agent' || stealthDetected ? 'agent' : probeVerdict;

  /* 0 — Signed good agent. RS-E decision order: a VALID WBA signature plus signed identity
   *     (or its published proof fields) plus an assistant/agent category wins BEFORE every
   *     bad rung — including a spoofed directory claim and corroborated hard automation.
   *     Automation is expected for verified agents and cannot disqualify signed good; the
   *     published reason_ids are exactly ['signed-agent'] so ZERO stealth automation reasons
   *     escape this rung. Only a crypto/anchor failure can fall through to the probe ladder. */
  const signedProof = hasSignedProof(webBotAuth);
  const signedWba =
    isWbaValid(webBotAuth) &&
    (signedProof ||
      hasSignedIdentity([webBotAuth.identity, webBotAuth.status]) ||
      hasSignedIdentity([directory.identity, directory.status, directory.signed === true ? 'signed' : null]));
  if (
    signedWba &&
    (signedProof || isAssistantOrAgentCategory([webBotAuth.category, directory.category, input.category]))
  ) {
    return {
      verdict: 'good',
      reason: 'signed-agent',
      reason_ids: ['signed-agent'],
      agent_verdict:
        webBotAuth.bot_id ||
        webBotAuth.agentId ||
        webBotAuth.operator ||
        directory.bot_id ||
        directory.operator ||
        null,
      verified: true,
      severity: 'none',
    };
  }

  /* 1 — Web Bot Auth: a VALID cryptographic proof outranks everything else.
   *     INVALID / NEUTRAL results fall through to the IP / UA paths below. */
  if (isWbaValid(webBotAuth)) {
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
      reason_ids: ['spoofed-impersonation', ...allProbeReasons],
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
      reason_ids: [directoryStatus === 'verified' ? 'verified-agent' : 'signed-agent', ...allProbeReasons],
      agent_verdict: directory.bot_id || directory.operator || null,
      verified: directoryStatus === 'verified',
      severity: 'none',
    };
  }

  /* 3.5 — Spoofed verified-bot identity. An explicit named crawler / AI-agent claim
   *       with NO valid signature (INVALID or NEUTRAL) AND an out-of-list IP (no official
   *       CIDR / FCrDNS proof) is an impersonation, not an inconclusive claim. Signed-good
   *       (steps 0/1) and a genuine directory verification (step 3) still win. NEUTRAL +
   *       out-of-list stays "unverified" only when there is no crawler claim at all. */
  if (
    !isWbaValid(webBotAuth) &&
    input.ipInKnownBotCidr !== true &&
    claimsOfficialBotIdentity(input)
  ) {
    return {
      verdict: 'bad',
      reason: 'spoofed-impersonation',
      reason_ids: ['spoofed-impersonation', ...allProbeReasons],
      agent_verdict:
        webBotAuth.bot_id || webBotAuth.operator || directory.bot_id || directory.operator || null,
      verified: false,
      severity: 'high',
    };
  }

  /* 4 — Client probe found corroborated automated-runtime evidence.
   *     A bare cdp.* reason and `bot.cdp-active-inspection` are developer_tools
   *     (weight 0) and cannot get here on their own. */
  if (effectiveProbeVerdict === 'agent' && isHardAgentReason(allProbeReasons)) {
    return {
      verdict: 'bad',
      reason: 'automated-runtime',
      reason_ids: ['automated-runtime', ...allProbeReasons],
      agent_verdict: null,
      verified: false,
      severity: 'high',
    };
  }

  /* 5 — Client probe says agent, but only weak evidence. */
  if (effectiveProbeVerdict === 'agent') {
    return {
      verdict: 'not_detected',
      reason: 'suspected-automation',
      reason_ids: ['suspected-automation', ...allProbeReasons],
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
      reason_ids: ['known-operator-network', ...allProbeReasons],
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
      reason_ids: ['suspected-automation', ...allProbeReasons],
      agent_verdict: null,
      verified: false,
      severity: 'low',
    };
  }

  /* 8 — Nothing implicated the request. */
  return {
    verdict: 'human-or-unverified',
    reason: 'not_detected',
    reason_ids: ['not_detected', ...allProbeReasons],
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

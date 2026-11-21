/**
 * Weighted automation-verdict gate.
 *
 * The previous verdict promoted ANY single suspicious probe reason to
 * "agent / automated", which flagged real humans on ordinary browsers. Three
 * probes were outright inverted or universal:
 *
 *  1. `headless.shell.url_scheme_port` — regular Chrome RETAINS the explicit
 *     `:0` port on non-special scheme URLs (it is chrome-headless-shell that
 *     drops it), so the old "port === 0" check fired for every Chrome user.
 *  2. `playwright.mcp.pressure` — per the Pointer Events spec a REAL mouse
 *     reports pressure 0.5 while a button is active, so the old
 *     "pressure === 0.5" check fired for every mouse click.
 *  3. `chatgpt.badge.overlay` — any dead-centre click with pressure 0 (Mac
 *     trackpad tap-to-click) fired it, extension shadow roots fired
 *     `codex.overlay.shadow-root`, and SwiftShader (hardware acceleration
 *     disabled — common on real dev machines) fired both the collector and
 *     the probe.
 *
 * The gate below classifies every reason id into three evidence weights and
 * only produces an "automated" verdict when the evidence is corroborated:
 *
 *   hard   — sufficient on its own (CDP runtime/network bindings,
 *            navigator.webdriver, automation user agents, launch switches, and a
 *            CDP bridge left uncorroborated by human input after the dwell window)
 *   medium — meaningful only in pairs, or paired with any weak reason
 *   weak   — never sufficient alone; kept for telemetry/attribution only
 */

import type { VerdictTier } from './telemetryContract';

export type ReasonWeight = 'hard' | 'medium' | 'weak' | 'developer_tools';

/**
 * reason id emitted ONLY when a CDP / runtime bridge is present AND no genuine, trusted
 * human input was recorded after the corroboration dwell window. A bare CDP attachment
 * stays in the weight-0 `developer_tools` tier (Electron / IDE / docked DevTools with a
 * real person driving); this id is the single hard-escalation path for the adversarial
 * case where stealth tooling hides `navigator.webdriver` behind a native-looking getter
 * and uses a normal desktop UA. The server escalates the matching bot signal to
 * `bad` / `stealth_automation`.
 */
export const CORROBORATED_CDP_REASON_ID = 'bot.stealth-automation-uncorroborated';
/** Chromium-flavoured alias retained for parity with the server's `chromium_automation`. */
export const CORROBORATED_CHROMIUM_CDP_REASON_ID = 'bot.chromium-automation-uncorroborated';

export type AutomationVerdict = 'human' | 'uncertain' | 'automated';

export interface GatedAutomationEvidence {
  verdict: AutomationVerdict;
  hardReasons: string[];
  mediumReasons: string[];
  weakReasons: string[];
  /**
   * CDP / DevTools bridge evidence — reported separately and weight 0. It never flips the
   * verdict on its own; only the explicit, corroborated escalation reason ids above do.
   */
  developerToolsReasons: string[];
}

/** Reason ids that are, by themselves, proof of an automated runtime. */
const HARD_REASONS: ReadonlySet<string> = new Set([
  'navigator.webdriver',
  'cdp.ua_override.empty_brands',
  'ua.headless-chrome',
  'ua.automation-signature',
  'page.ua.cursor',
  'page.platform.cloudflare-workers',
  'launch.ipc-flooding-switch',
  // Real Playwright/CDC bindings and protocol-level CDP tamper are deterministic artifacts
  // of a driven runtime. A plain CDP attachment stays in the developer_tools tier (see
  // DEVELOPER_TOOLS_REASONS / the `cdp.` prefix rule); only a *corroborated* CDP bridge is
  // hard evidence here.
  'bot.cdp-tampered',
  'bot.playwright-binding',
  'cdc.global.binding',
  // Corroborated CDP escalation: a runtime bridge with NO trusted human input after the
  // dwell window. Exact ids win over the generic weak `bot.` prefix rule below.
  CORROBORATED_CDP_REASON_ID,
  CORROBORATED_CHROMIUM_CDP_REASON_ID,
]);

/**
 * Developer-tools evidence. A CDP Runtime / Network session is attached to the page by
 * DevTools, an Electron shell or an IDE webview — a real person is often still driving it.
 * Fingerprint Pro reports this as `developer_tools`, not `bot`, and so do we.
 */
const DEVELOPER_TOOLS_REASONS: ReadonlySet<string> = new Set([
  'cdp.runtime.enable.empty_source',
  'cdp.network.enable.pre_load_message',
  'bot.cdp-runtime-leak',
]);

/** Reason ids that need a corroborating companion before an agent verdict. */
const MEDIUM_REASONS: ReadonlySet<string> = new Set([
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

/**
 * Weak reasons: real humans trip these regularly (privacy extensions, disabled
 * hardware acceleration, trackpad taps, minimized windows). They still reach
 * the telemetry beacon for attribution, but can never trigger the verdict on
 * their own.
 */
const WEAK_REASONS: ReadonlySet<string> = new Set([
  'headless.swiftshader.caveat',
  'launch.no-speech-voices',
  'kinematics.zero_pointer_trail',
  'kinematics.screenshot_offset',
  // A real mouse reports pressure 0.5 while a button is active, so this stays weak even
  // though the generic `playwright.` prefix below is now hard evidence (exact set wins).
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
  // Getter-descriptor / serialization artifacts are engine-dependent (they fire naturally
  // on Android Chrome and other engines). They are never bridge proof or tampering proof.
  'bot.webdriver-getter-tampered-cdp',
  'bot.webdriver-getter-tampered',
  'bot.automation-getter-tampered',
]);

/** Prefix rules evaluated after the exact sets (first match wins). */
const PREFIX_RULES: ReadonlyArray<{ prefix: string; weight: ReasonWeight }> = [
  { prefix: 'cdp.', weight: 'developer_tools' },
  // Playwright / CDC bindings are hard automation evidence. Exact-set entries are
  // checked first, so the weak `playwright.mcp.pressure` quirk keeps its soft weight.
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

/** Classify a single reason id into its evidence weight. */
export function classifyReasonId(reasonId: string): ReasonWeight {
  const id = (reasonId || '').trim().toLowerCase();
  if (!id) return 'weak';
  if (HARD_REASONS.has(id)) return 'hard';
  if (DEVELOPER_TOOLS_REASONS.has(id)) return 'developer_tools';
  if (MEDIUM_REASONS.has(id)) return 'medium';
  if (WEAK_REASONS.has(id)) return 'weak';
  for (const rule of PREFIX_RULES) {
    if (id.startsWith(rule.prefix)) return rule.weight;
  }
  return 'weak';
}

/**
 * Gate a list of reason ids into a verdict.
 *
 *   automated — at least one hard reason, or two medium reasons, or one
 *               medium reason plus any weak corroboration
 *   uncertain — exactly one medium reason, no corroboration
 *   human     — only weak evidence (or nothing)
 */
export function gateAutomationEvidence(reasons: ReadonlyArray<string>): GatedAutomationEvidence {
  const hardReasons: string[] = [];
  const mediumReasons: string[] = [];
  const weakReasons: string[] = [];
  const developerToolsReasons: string[] = [];

  for (const reason of reasons || []) {
    const id = (reason || '').trim();
    if (!id) continue;
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

  let verdict: AutomationVerdict = 'human';
  if (hardReasons.length > 0) {
    verdict = 'automated';
  } else if (mediumReasons.length >= 2) {
    verdict = 'automated';
  } else if (mediumReasons.length === 1 && weakReasons.length > 0) {
    verdict = 'automated';
  } else if (mediumReasons.length === 1) {
    verdict = 'uncertain';
  }

  return { verdict, hardReasons, mediumReasons, weakReasons, developerToolsReasons };
}

/* -------------------------------------------------------------------------- */
/* Single-verdict bot derivation with a parity assertion                       */
/* -------------------------------------------------------------------------- */

export interface BotVerdictInput {
  /** The one authoritative boolean verdict produced by the runtime detector. */
  isBot: boolean;
  /** Reason ids emitted by that same detector (used only for the parity check). */
  reasonIds: ReadonlyArray<string>;
}

export interface BotVerdict {
  /** The single derived verdict — every downstream consumer reads this one field. */
  isBot: boolean;
  verdict: AutomationVerdict;
  gated: GatedAutomationEvidence;
  /** True when the gated evidence tier agrees with the authoritative verdict. */
  parity: boolean;
  assertion: string;
}

/**
 * Derive the bot verdict exactly once from the single authoritative signal, then assert
 * that the weighted evidence gate agrees. `isBot` is the runtime detector's verdict —
 * the gate is an independent cross-check, not a second opinion that can silently flip
 * the result. A disagreement is reported in `assertion` (and surfaced as telemetry) but
 * never throws: identify must remain total.
 */
export function deriveBotVerdict(input: BotVerdictInput): BotVerdict {
  const gated = gateAutomationEvidence(input.reasonIds || []);
  const verdictIsBot = gated.verdict === 'automated';
  const parity = verdictIsBot === input.isBot;
  return {
    isBot: input.isBot,
    verdict: gated.verdict,
    gated,
    parity,
    assertion: parity
      ? 'verdict parity ok'
      : `verdict parity mismatch: gated=${gated.verdict} raw=${input.isBot}`,
  };
}

/* -------------------------------------------------------------------------- */
/* Phase 3 — 4-tier Verdict State Machine                                     */
/* -------------------------------------------------------------------------- */

export interface VerdictStateInput {
  /** The gated automation classification (or the server bot verdict mapped onto it). */
  automation: AutomationVerdict;
  /** The reconciled tampering axis. */
  tamperingDetected: boolean;
  /** Whether corroborating human input was actually recorded. */
  humanCorroboration: 0 | 1;
  /** Independent interaction evidence (typing / pointer trail) for this event. */
  hasInteractionEvidence?: boolean;
}

export interface VerdictState {
  verdict_tier: VerdictTier;
  human_corroboration: 0 | 1;
  label: string;
}

/**
 * The 4-tier state machine. `human_corroboration` is forced to 0 on every automated,
 * tampered and passive session — it can only be 1 on a clean session with recorded input.
 */
export function decideVerdictTier(input: VerdictStateInput): VerdictState {
  if (input.tamperingDetected) {
    return {
      verdict_tier: 'Tampered / Spoofed Environment',
      human_corroboration: 0,
      label: 'Tampered / Spoofed Environment',
    };
  }
  if (input.automation === 'automated') {
    return {
      verdict_tier: 'Verified Automation',
      human_corroboration: 0,
      label: 'Verified Automation',
    };
  }
  if (input.humanCorroboration === 1 && input.hasInteractionEvidence !== false) {
    return {
      verdict_tier: 'Verified Human Interactive Session',
      human_corroboration: 1,
      label: 'Verified Human Interactive Session',
    };
  }
  return {
    verdict_tier: 'Unverified / Passive Session',
    human_corroboration: 0,
    label: 'Unverified / Passive Session',
  };
}


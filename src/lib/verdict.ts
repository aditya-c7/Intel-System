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
 *            navigator.webdriver, automation user agents, launch switches)
 *   medium — meaningful only in pairs, or paired with any weak reason
 *   weak   — never sufficient alone; kept for telemetry/attribution only
 */

export type ReasonWeight = 'hard' | 'medium' | 'weak' | 'developer_tools';

export type AutomationVerdict = 'human' | 'uncertain' | 'automated';

export interface GatedAutomationEvidence {
  verdict: AutomationVerdict;
  hardReasons: string[];
  mediumReasons: string[];
  weakReasons: string[];
  /** CDP / DevTools bridge evidence — reported separately, never flips the verdict. */
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
  'bot.webdriver-getter-tampered-cdp',
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
  'bot.webdriver-getter-tampered',
]);

/** Prefix rules evaluated after the exact sets (first match wins). */
const PREFIX_RULES: ReadonlyArray<{ prefix: string; weight: ReasonWeight }> = [
  { prefix: 'cdp.', weight: 'developer_tools' },
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

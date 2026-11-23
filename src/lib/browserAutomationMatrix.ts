/**
 * RS10 browser-automation matrix — additive, shadow-only, pure (zero imports).
 *
 * Ground truth comes from the CONTROLLED LAUNCH CONFIGURATION, never from a vendor
 * verdict. `AUTOMATED` is asserted for known automation stacks; `HUMAN` is asserted
 * only for a stock browser operated by a human, or for verified paid traffic. An
 * unknown stack is always `unknown`, and a vendor verdict is accepted only so the
 * caller can prove it was ignored (`vendorVerdict` is never read).
 *
 * Automation tells are kept strictly separate from machine tells
 * (GPU / fonts / audio / screen / codecs). Tells are prefixed `automation:` or
 * `machine:` and the `axis` field is derived from those prefixes. An attached CDP
 * client is reported with weight 0: it adds a tell but never changes the label or
 * confidence on its own, and this module never claims abuse from CDP alone.
 *
 * Causality table (what the controlled config actually causes):
 *   Runtime.enable                    -> error-stack / prepareStackTrace leaks
 *   Network.enable                    -> iframe postMessage before load
 *   --disable-ipc-flooding-protection -> 201st replaceState accepted
 *   --disable-component-extensions    -> missing Google speech voices (machine/audio)
 *   headless shell                    -> S1-S7
 *   new headless                      -> H2-H4
 *   page.setUserAgent                 -> empty brands
 *
 * Stealth notes: JS patches do NOT remove C1-C3; Patchright removes some flags /
 * Runtime but F1/F3/V1/C3 remain; Nodriver has no webdriver but still uses CDP;
 * Camoufox is engine-level. These are tells, not labels.
 *
 * Deployment discipline: log mode before enforce; a human baseline that flags any
 * control case must fail the run (see `validateHumanBaseline`).
 *
 * Total function over its input: no I/O, no globals, no mutation, never throws.
 */

/* -------------------------------------------------------------------------- */
/* Public types                                                               */
/* -------------------------------------------------------------------------- */

export type AutomationExpectation = 'automated' | 'human' | 'unknown';
export type AutomationAxis = 'automation' | 'machine' | 'both';
export type AutomationConfidence = 'high' | 'medium' | 'low';

export interface AutomationConfigInput {
  stack: unknown;
  headlessMode: unknown;
  flags: unknown;
  cdpClients: unknown;
  humanOperated: unknown;
  source: unknown;
  /** Accepted only so callers can prove it is ignored. Never read, never a label. */
  vendorVerdict?: unknown;
  /** CDP domain methods observed on the launch, e.g. 'Runtime.enable'. Tells only. */
  cdpDomains?: unknown;
  /** page.setUserAgent observed. Adds a tell / hard-config, never a vendor label. */
  userAgentSpoofed?: unknown;
}

export interface AutomationConfigVerdict {
  expected: AutomationExpectation;
  axis: AutomationAxis;
  tells: string[];
  confidence: AutomationConfidence;
  reasons: string[];
}

export interface HumanBaselineInput {
  humanCases: unknown;
  flaggedCases: unknown;
}

export interface HumanBaselineResult {
  valid: boolean;
  falsePositiveRate: number;
  reason: string;
}

/* -------------------------------------------------------------------------- */
/* Published research anchors (RS10)                                          */
/* -------------------------------------------------------------------------- */

export const RS10_RESEARCH = Object.freeze({
  openWaf: Object.freeze({
    browser: 'Chrome 156',
    automatedRuns: 110,
    playwright: '12/12 flagged',
    patchrightDefault: '47/47 flagged',
    patchrightRecommendedHumanized: '0/3 pass',
    puppeteerStealth: '12/12 flagged',
    zendriver: '18/18 flagged',
    camoufox: '1/12 flagged',
    humans: '0/31 flagged',
  }),
  botstopV12: Object.freeze({ min: 83, max: 100, verdict: 'automated' }),
  causality: Object.freeze({
    runtimeEnable: 'error stack / prepareStackTrace leaks',
    networkEnable: 'iframe postMessage before load',
    ipcFlooding: '201st replaceState accepted',
    componentExtensions: 'missing Google speech voices',
    headlessShell: 'S1-S7',
    newHeadless: 'H2-H4',
    setUserAgent: 'empty brands',
  }),
  stealth: Object.freeze({
    jsPatches: 'do not remove C1-C3',
    patchright: 'removes some flags/Runtime; F1/F3/V1/C3 remain',
    nodriver: 'no webdriver but still CDP',
    camoufox: 'engine-level',
  }),
});

/* -------------------------------------------------------------------------- */
/* Stack allowlists                                                           */
/* -------------------------------------------------------------------------- */

export const AUTOMATION_STACKS: readonly string[] = Object.freeze([
  'playwright',
  'playwright_stealth',
  'patchright',
  'puppeteer',
  'puppeteer_stealth',
  'selenium',
  'selenium_uc',
  'nodriver',
  'zendriver',
  'camoufox',
]);

export const HUMAN_STACKS: readonly string[] = Object.freeze(['chrome_human']);

export const KNOWN_STACKS: readonly string[] = Object.freeze([...AUTOMATION_STACKS, ...HUMAN_STACKS]);

const AUTOMATION_STACK_SET: ReadonlySet<string> = new Set(AUTOMATION_STACKS);
const HUMAN_STACK_SET: ReadonlySet<string> = new Set(HUMAN_STACKS);

/* -------------------------------------------------------------------------- */
/* Tell vocabulary — axis is encoded in the prefix and mirrored in this table */
/* -------------------------------------------------------------------------- */

export const TELL_AXIS: Readonly<Record<string, AutomationAxis>> = Object.freeze({
  'automation:stack-playwright': 'automation',
  'automation:stack-playwright_stealth': 'automation',
  'automation:stack-patchright': 'automation',
  'automation:stack-puppeteer': 'automation',
  'automation:stack-puppeteer_stealth': 'automation',
  'automation:stack-selenium': 'automation',
  'automation:stack-selenium_uc': 'automation',
  'automation:stack-nodriver': 'automation',
  'automation:stack-zendriver': 'automation',
  'automation:stack-camoufox': 'automation',
  'automation:headless-shell-S1-S7': 'automation',
  'automation:new-headless-H2-H4': 'automation',
  'automation:runtime-enable-error-stack-leak': 'automation',
  'automation:network-enable-iframe-postmessage-before-load': 'automation',
  'automation:ipc-flooding-replaceState-201': 'automation',
  'automation:cdp-debugging-port': 'automation',
  'automation:cdp-client-attached': 'automation',
  'automation:setUserAgent-empty-brands': 'automation',
  'automation:stealth-js-patches-C1-C3': 'automation',
  'automation:patchright-residual-F1-F3-V1-C3': 'automation',
  'automation:nodriver-no-webdriver-cdp': 'automation',
  'automation:zendriver-cdp': 'automation',
  'automation:camoufox-engine-level': 'automation',
  'automation:selenium-webdriver': 'automation',
  'automation:enable-automation-flag': 'automation',
  'automation:stealth-flag-automation-controlled': 'automation',
  'machine:audio-missing-google-speech-voices': 'machine',
  'machine:gpu-software-renderer': 'machine',
  'machine:screen-override': 'machine',
  'machine:font-override': 'machine',
  'machine:codec-override': 'machine',
});

export const ALL_TELLS: readonly string[] = Object.freeze(Object.keys(TELL_AXIS));

/** Stack -> automation-axis tell (stack label itself is a controlled-config fact). */
const STACK_TELL: Readonly<Record<string, string>> = Object.freeze({
  playwright: 'automation:stack-playwright',
  playwright_stealth: 'automation:stack-playwright_stealth',
  patchright: 'automation:stack-patchright',
  puppeteer: 'automation:stack-puppeteer',
  puppeteer_stealth: 'automation:stack-puppeteer_stealth',
  selenium: 'automation:stack-selenium',
  selenium_uc: 'automation:stack-selenium_uc',
  nodriver: 'automation:stack-nodriver',
  zendriver: 'automation:stack-zendriver',
  camoufox: 'automation:stack-camoufox',
});

/** Per-stack stealth/engine notes — tells only, never labels. */
const STACK_NOTE_TELL: Readonly<Record<string, string>> = Object.freeze({
  playwright_stealth: 'automation:stealth-js-patches-C1-C3',
  puppeteer_stealth: 'automation:stealth-js-patches-C1-C3',
  patchright: 'automation:patchright-residual-F1-F3-V1-C3',
  selenium: 'automation:selenium-webdriver',
  selenium_uc: 'automation:selenium-webdriver',
  nodriver: 'automation:nodriver-no-webdriver-cdp',
  zendriver: 'automation:zendriver-cdp',
  camoufox: 'automation:camoufox-engine-level',
});

interface FlagRule {
  readonly needle: string;
  readonly tell: string;
  readonly reason: string;
  /** Whether this flag is automation config (blocks a clean human baseline). */
  readonly hardAutomation: boolean;
}

const FLAG_RULES: readonly FlagRule[] = Object.freeze([
  { needle: '--disable-ipc-flooding-protection', tell: 'automation:ipc-flooding-replaceState-201', reason: 'causality:ipc-flooding-replaceState-201', hardAutomation: true },
  { needle: '--disable-component-extensions', tell: 'machine:audio-missing-google-speech-voices', reason: 'causality:missing-google-speech-voices', hardAutomation: false },
  { needle: '--remote-debugging-port', tell: 'automation:cdp-debugging-port', reason: 'causality:cdp-debugging-port', hardAutomation: true },
  { needle: '--remote-debugging-pipe', tell: 'automation:cdp-debugging-port', reason: 'causality:cdp-debugging-pipe', hardAutomation: true },
  { needle: '--enable-automation', tell: 'automation:enable-automation-flag', reason: 'flag:enable-automation', hardAutomation: true },
  { needle: '--disable-blink-features=automationcontrolled', tell: 'automation:stealth-flag-automation-controlled', reason: 'flag:automation-controlled-disabled', hardAutomation: true },
  { needle: '--disable-gpu', tell: 'machine:gpu-software-renderer', reason: 'machine:gpu', hardAutomation: false },
  { needle: '--use-gl=swiftshader', tell: 'machine:gpu-software-renderer', reason: 'machine:gpu', hardAutomation: false },
  { needle: '--disable-software-rasterizer', tell: 'machine:gpu-software-renderer', reason: 'machine:gpu', hardAutomation: false },
  { needle: '--window-size=', tell: 'machine:screen-override', reason: 'machine:screen', hardAutomation: false },
  { needle: '--force-device-scale-factor=', tell: 'machine:screen-override', reason: 'machine:screen', hardAutomation: false },
  { needle: '--hide-scrollbars', tell: 'machine:screen-override', reason: 'machine:screen', hardAutomation: false },
  { needle: '--disable-font-subpixel-positioning', tell: 'machine:font-override', reason: 'machine:font', hardAutomation: false },
  { needle: '--font-render-hinting=', tell: 'machine:font-override', reason: 'machine:font', hardAutomation: false },
  { needle: '--disable-accelerated-video-decode', tell: 'machine:codec-override', reason: 'machine:codec', hardAutomation: false },
  { needle: 'videodecode', tell: 'machine:codec-override', reason: 'machine:codec', hardAutomation: false },
]);

/* -------------------------------------------------------------------------- */
/* Defensive normalization                                                    */
/* -------------------------------------------------------------------------- */

/** Property reads may be getters on a hostile object — contain every throw. */
function readField(value: unknown, key: string): unknown {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return undefined;
  try {
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function safeCount(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return 0;
  return Math.floor(value);
}

function readStringArray(value: unknown, maxItems: number, maxLen: number): string[] {
  const out: string[] = [];
  if (typeof value === 'string') {
    const s = value.slice(0, maxLen).trim();
    if (s) out.push(s);
    return out;
  }
  if (!Array.isArray(value)) return out;
  try {
    let seen = 0;
    for (const item of value as readonly unknown[]) {
      if (++seen > maxItems) break;
      if (typeof item !== 'string') continue;
      const s = item.slice(0, maxLen).trim();
      if (s) out.push(s);
    }
  } catch {
    // Hostile iterator / proxy threw mid-walk: keep the safely read prefix.
  }
  return out;
}

type SourceKind = 'controlled' | 'paid' | 'vendor' | 'other';

function sourceKind(value: unknown): SourceKind {
  if (typeof value !== 'string') return 'other';
  const s = value.trim().toLowerCase();
  if (s.includes('vendor')) return 'vendor';
  if (s.includes('paid') || s.includes('verified_traffic') || s.includes('verified-traffic')) return 'paid';
  if (s.includes('controlled') || s.includes('launch_config') || s.includes('launch-config') || s.includes('config')) return 'controlled';
  return 'other';
}

type HeadlessKind = 'shell' | 'new' | null;

function headlessKind(value: unknown): HeadlessKind {
  if (typeof value !== 'string') return null;
  const s = value.trim().toLowerCase();
  if (s === 'headless-shell' || s === 'chrome-headless-shell' || s === 'shell' || s === 'old-headless' || s === 'old_headless') return 'shell';
  if (s === 'new-headless' || s === 'new_headless' || s === 'headless=new' || s === 'new') return 'new';
  return null;
}

function inert(): AutomationConfigVerdict {
  return { expected: 'unknown', axis: 'automation', tells: [], confidence: 'low', reasons: ['internal-error-contained'] };
}

/* -------------------------------------------------------------------------- */
/* classifyAutomationConfig                                                   */
/* -------------------------------------------------------------------------- */

function classifyUnsafe(input: AutomationConfigInput): AutomationConfigVerdict {
  const tells: string[] = [];
  const reasons: string[] = [];
  const tellSeen = new Set<string>();
  const reasonSeen = new Set<string>();

  const addTell = (tell: string): void => {
    if (!Object.prototype.hasOwnProperty.call(TELL_AXIS, tell) || tellSeen.has(tell)) return;
    tellSeen.add(tell);
    tells.push(tell);
  };
  const addReason = (reason: string): void => {
    if (reasonSeen.has(reason)) return;
    reasonSeen.add(reason);
    reasons.push(reason);
  };

  const source = sourceKind(readField(input, 'source'));
  if (source === 'controlled') addReason('controlled-launch-config');
  else if (source === 'paid') addReason('verified-paid-traffic');
  else if (source === 'vendor') addReason('vendor-verdict-ignored');
  else addReason('source-provenance-unknown');

  const rawStack = readField(input, 'stack');
  const stack = typeof rawStack === 'string' ? rawStack.trim() : '';
  const isAutomationStack = AUTOMATION_STACK_SET.has(stack);
  const isHumanStack = HUMAN_STACK_SET.has(stack);
  let hardAutomationConfig = false;

  if (isAutomationStack) {
    addTell(STACK_TELL[stack]);
    addReason('known-automation-stack:' + stack);
    hardAutomationConfig = true;
    const note = STACK_NOTE_TELL[stack];
    if (note) addTell(note);
  } else if (isHumanStack) {
    addReason('stock-browser-stack');
  } else {
    addReason('unknown-stack');
  }

  const headless = headlessKind(readField(input, 'headlessMode'));
  if (headless === 'shell') {
    addTell('automation:headless-shell-S1-S7');
    addReason('headless-shell-S1-S7');
    hardAutomationConfig = true;
  } else if (headless === 'new') {
    addTell('automation:new-headless-H2-H4');
    addReason('new-headless-H2-H4');
    hardAutomationConfig = true;
  }

  const flags = readStringArray(readField(input, 'flags'), 200, 512);
  for (const flag of flags) {
    const lower = flag.toLowerCase();
    for (const rule of FLAG_RULES) {
      if (!lower.includes(rule.needle)) continue;
      addTell(rule.tell);
      addReason(rule.reason);
      if (rule.hardAutomation) hardAutomationConfig = true;
    }
  }

  // Attached CDP client: reported, but weight 0 — never changes label/confidence.
  const cdpClients = safeCount(readField(input, 'cdpClients'));
  if (cdpClients > 0) {
    addTell('automation:cdp-client-attached');
    addReason('cdp-client-weight-0');
  }

  // CDP domain methods produce causality tells, not labels.
  const domains = readStringArray(readField(input, 'cdpDomains'), 50, 128).map((d) => d.toLowerCase());
  if (domains.some((d) => d.includes('runtime.enable'))) {
    addTell('automation:runtime-enable-error-stack-leak');
    addReason('causality:runtime-enable-error-stack');
  }
  if (domains.some((d) => d.includes('network.enable'))) {
    addTell('automation:network-enable-iframe-postmessage-before-load');
    addReason('causality:network-enable-iframe-postmessage');
  }

  if (readField(input, 'userAgentSpoofed') === true) {
    addTell('automation:setUserAgent-empty-brands');
    addReason('causality:setUserAgent-empty-brands');
    hardAutomationConfig = true;
  }

  const humanOperated = readField(input, 'humanOperated') === true;
  if (humanOperated) addReason('human-operated-flag');

  let expected: AutomationExpectation;
  let confidence: AutomationConfidence;

  if (isAutomationStack) {
    // Known stack is controlled-config ground truth, even if a vendor disagrees.
    expected = 'automated';
    confidence = source === 'controlled' ? 'high' : 'medium';
  } else if (isHumanStack && hardAutomationConfig) {
    // Nominal human stack is overridden by actual automation config.
    expected = 'automated';
    confidence = 'medium';
    addReason('automation-config-overrides-human-stack');
  } else if (isHumanStack && humanOperated && (source === 'controlled' || source === 'paid')) {
    expected = 'human';
    confidence = 'high';
    addReason('human-operated-stock-browser');
  } else if (isHumanStack && source === 'paid' && !hardAutomationConfig) {
    expected = 'human';
    confidence = 'high';
    addReason('verified-paid-traffic-human');
  } else if (source === 'vendor' && !isAutomationStack) {
    // The vendor verdict string is deliberately never copied into the label.
    expected = 'unknown';
    confidence = 'low';
    addReason('no-label-from-vendor-verdict');
  } else {
    expected = 'unknown';
    confidence = 'low';
    addReason('insufficient-controlled-config');
  }

  let hasAutomation = false;
  let hasMachine = false;
  for (const tell of tells) {
    const axis = TELL_AXIS[tell] ?? (tell.startsWith('machine:') ? 'machine' : 'automation');
    if (axis === 'machine') hasMachine = true;
    else hasAutomation = true;
  }
  const axis: AutomationAxis = hasAutomation && hasMachine ? 'both' : hasMachine ? 'machine' : 'automation';

  return { expected, axis, tells, confidence, reasons };
}

/**
 * Classify a controlled browser launch config. Pure, deterministic, non-throwing.
 * Hostile values are ignored safely and always yield a well-formed verdict.
 */
export function classifyAutomationConfig(input: AutomationConfigInput): AutomationConfigVerdict {
  try {
    return classifyUnsafe(input);
  } catch {
    return inert();
  }
}

/* -------------------------------------------------------------------------- */
/* validateHumanBaseline                                                      */
/* -------------------------------------------------------------------------- */

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function rate(flagged: number, human: number): number {
  return Number((flagged / human).toFixed(6));
}

/**
 * Validate the human control group. Any flagged human case makes the baseline
 * invalid — the run must fail before enforcement. Log mode first, enforce later.
 */
export function validateHumanBaseline(input: HumanBaselineInput): HumanBaselineResult {
  try {
    const human = readField(input, 'humanCases');
    const flagged = readField(input, 'flaggedCases');

    if (!isCount(human) || human === 0) {
      return {
        valid: false,
        falsePositiveRate: 0,
        reason: 'HUMAN_BASELINE_MISSING: humanCases must be a positive integer; cannot validate the human control group.',
      };
    }
    if (!isCount(flagged)) {
      return {
        valid: false,
        falsePositiveRate: 0,
        reason: 'HUMAN_BASELINE_INVALID_INPUT: flaggedCases must be a finite non-negative integer.',
      };
    }
    if (flagged > human) {
      return {
        valid: false,
        falsePositiveRate: rate(flagged, human),
        reason: `HUMAN_BASELINE_INVALID: flaggedCases (${flagged}) exceeds humanCases (${human}).`,
      };
    }

    const fpRate = rate(flagged, human);
    if (flagged === 0) {
      return {
        valid: true,
        falsePositiveRate: 0,
        reason: `HUMAN_BASELINE_VALID: 0 of ${human} human cases flagged (false-positive-rate 0.000000). Log mode before enforce satisfied.`,
      };
    }
    return {
      valid: false,
      falsePositiveRate: fpRate,
      reason: `HUMAN_BASELINE_INVALID: ${flagged} of ${human} human cases flagged (false-positive-rate ${fpRate.toFixed(6)}). Fail run — human baseline flags.`,
    };
  } catch {
    return {
      valid: false,
      falsePositiveRate: 0,
      reason: 'HUMAN_BASELINE_INVALID_INPUT: input could not be read safely.',
    };
  }
}

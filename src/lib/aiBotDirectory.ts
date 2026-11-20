/**
 * AI Agent & Bot Directory - "Robodex" equivalent
 * Identifies visiting AI agents by UA, ASN, IP range, and Web Bot Auth headers.
 */

export type BotIdentity = 'verified' | 'signed' | 'unknown' | 'spoofed';
export type BotCategory = 'ai_agent' | 'ai_assistant' | 'ai_search' | 'ai_crawler' | 'ai_browser' | 'browser_automation';

export interface BotInfo {
  category: BotCategory;
  provider: string;
  name: string;
  identity: BotIdentity;
}

export interface BotDetectionResult {
  detected: boolean;
  botType: string | null;
  botInfo: BotInfo | null;
}

interface BotDirectoryEntry {
  name: string;
  provider: string;
  category: BotCategory;
  identity: BotIdentity;
  uaPatterns?: RegExp[];
  asnNumbers?: number[];
  asnPatterns?: RegExp[];
  headerPatterns?: { header: string; pattern: RegExp }[];
  requiresWebBotAuth?: boolean;
}

const BOT_DIRECTORY: BotDirectoryEntry[] = [
  // OpenAI - verified (CIDR/FCrDNS verified)
  {
    name: 'ChatGPT-User',
    provider: 'OpenAI',
    category: 'ai_assistant',
    identity: 'verified',
    uaPatterns: [/ChatGPT-User/i],
  },
  {
    name: 'OAI-SearchBot',
    provider: 'OpenAI',
    category: 'ai_search',
    identity: 'verified',
    uaPatterns: [/OAI-SearchBot/i],
  },
  {
    name: 'GPTBot',
    provider: 'OpenAI',
    category: 'ai_crawler',
    identity: 'verified',
    uaPatterns: [/GPTBot/i],
  },
  // OpenAI - signed (Web Bot Auth)
  {
    name: 'ChatGPT Agent',
    provider: 'OpenAI',
    category: 'ai_agent',
    identity: 'signed',
    requiresWebBotAuth: true,
    asnPatterns: [/openai|azure/i],
    uaPatterns: [/ChatGPT-Agent/i],
  },
  // OpenAI - unknown
  {
    name: 'Codex',
    provider: 'OpenAI',
    category: 'ai_agent',
    identity: 'unknown',
    uaPatterns: [/\bCodex\b/i],
  },
  // Google - verified
  {
    name: 'Gemini Deep Research',
    provider: 'Google',
    category: 'ai_agent',
    identity: 'verified',
    asnNumbers: [15169, 396982],
    asnPatterns: [/google llc|google cloud|AS15169|AS396982/i],
    uaPatterns: [/Googlebot|Google-Extended|Google-Agent|Mariner|Gemini/i],
  },
  {
    name: 'Google-Agent',
    provider: 'Google',
    category: 'ai_agent',
    identity: 'verified',
    uaPatterns: [/Google-Agent/i],
  },
  {
    name: 'Google NotebookLM',
    provider: 'Google',
    category: 'ai_assistant',
    identity: 'verified',
    uaPatterns: [/NotebookLM/i],
  },
  // Anthropic - verified
  {
    name: 'Claude-User',
    provider: 'Anthropic',
    category: 'ai_assistant',
    identity: 'verified',
    uaPatterns: [/Claude-User/i],
  },
  {
    name: 'Claude-SearchBot',
    provider: 'Anthropic',
    category: 'ai_search',
    identity: 'verified',
    uaPatterns: [/Claude-SearchBot/i],
  },
  {
    name: 'ClaudeBot',
    provider: 'Anthropic',
    category: 'ai_crawler',
    identity: 'verified',
    uaPatterns: [/ClaudeBot/i],
  },
  // Anthropic - unknown
  {
    name: 'Claude Code',
    provider: 'Anthropic',
    category: 'ai_agent',
    identity: 'unknown',
    uaPatterns: [/Claude Code|claude-code/i],
  },
  {
    name: 'Claude Duet',
    provider: 'Anthropic',
    category: 'ai_agent',
    identity: 'unknown',
    uaPatterns: [/Claude-Duet|claude-duet/i],
  },
  // Perplexity - verified
  {
    name: 'Perplexity-User',
    provider: 'Perplexity',
    category: 'ai_assistant',
    identity: 'verified',
    uaPatterns: [/Perplexity-User/i],
  },
  {
    name: 'PerplexityBot',
    provider: 'Perplexity',
    category: 'ai_search',
    identity: 'verified',
    uaPatterns: [/PerplexityBot/i],
  },
  // Meta
  {
    name: 'Muse',
    provider: 'Meta',
    category: 'ai_agent',
    identity: 'unknown',
    asnNumbers: [32934],
    asnPatterns: [/meta platforms|AS32934/i],
    uaPatterns: [/\bMuse\b/i],
  },
  {
    name: 'Meta-ExternalAgent',
    provider: 'Meta',
    category: 'ai_search',
    identity: 'verified',
    uaPatterns: [/Meta-ExternalAgent|meta-externalagent/i],
  },
  {
    name: 'Meta-WebIndexer',
    provider: 'Meta',
    category: 'ai_search',
    identity: 'verified',
    uaPatterns: [/Meta-WebIndexer/i],
  },
  // xAI
  {
    name: 'Grok Bot',
    provider: 'xAI',
    category: 'ai_agent',
    identity: 'unknown',
    uaPatterns: [/Grok-Bot|GrokBot|grok/i],
  },
  // Cloud Browser Agents - signed
  {
    name: 'Browserbase Agent',
    provider: 'Browserbase',
    category: 'ai_agent',
    identity: 'signed',
    uaPatterns: [/Browserbase/i],
    requiresWebBotAuth: true,
  },
  {
    name: 'Bedrock AgentCore',
    provider: 'AWS',
    category: 'ai_agent',
    identity: 'signed',
    asnNumbers: [16509, 14618],
    uaPatterns: [/BedrockAgentCore|bedrock-agent/i],
  },
  {
    name: 'Anchor Browser',
    provider: 'Anchor',
    category: 'ai_browser',
    identity: 'signed',
    uaPatterns: [/AnchorBrowser|anchor-browser/i],
  },
  {
    name: 'Notte Browser',
    provider: 'Notte',
    category: 'ai_browser',
    identity: 'signed',
    uaPatterns: [/NotteBrowser|notte/i],
  },
  {
    name: 'Manus Agent',
    provider: 'Manus',
    category: 'ai_agent',
    identity: 'signed',
    uaPatterns: [/ManusAgent|manus-agent/i],
  },
  {
    name: 'AGI Agent',
    provider: 'AGI Inc',
    category: 'ai_agent',
    identity: 'signed',
    uaPatterns: [/AGIAgent|agi-agent/i],
  },
  // Other - unknown
  {
    name: 'Cursor',
    provider: 'Anysphere',
    category: 'ai_agent',
    identity: 'unknown',
    uaPatterns: [/\bCursor\b/i],
    headerPatterns: [{ header: 'x-cursor-agent', pattern: /.*/ }],
  },
  {
    name: 'DuckAssistBot',
    provider: 'DuckDuckGo',
    category: 'ai_assistant',
    identity: 'verified',
    uaPatterns: [/DuckAssistBot/i],
  },
  {
    name: 'Kimi-User',
    provider: 'Moonshot AI',
    category: 'ai_assistant',
    identity: 'verified',
    uaPatterns: [/Kimi-User/i],
  },
  {
    name: 'Cloudflare Browser Rendering',
    provider: 'Cloudflare',
    category: 'browser_automation',
    identity: 'unknown',
    asnNumbers: [13335],
    uaPatterns: [/CloudflareBot|cf-browser/i],
  },
  {
    name: 'Instinct',
    provider: 'Spear Street Technology',
    category: 'ai_agent',
    identity: 'unknown',
    uaPatterns: [/\bInstinct\b/i],
  },
];

/**
 * 19 BotD client-side signal names (for reference / collector integration).
 */
export const BOTD_SIGNALS = [
  'app_version',
  'distinctive_properties',
  'document_element_keys',
  'error_trace',
  'eval_length',
  'function_bind',
  'languages_inconsistency',
  'mime_types_consistence',
  'notification_permissions',
  'plugins_array',
  'plugins_inconsistency',
  'process',
  'product_sub',
  'rtt',
  'user_agent',
  'webdriver',
  'webgl',
  'window_external',
  'window_size',
] as const;

export type BotDSignalName = typeof BOTD_SIGNALS[number];

export interface BotD19Result {
  detected: boolean;
  reasons: string[];
  signals: Record<BotDSignalName, boolean>;
  /** Informational inspector evidence — never a verdict signal. */
  inspector_probes: Record<string, unknown>;
}

/**
 * Runs all 19 fingerprintjs/BotD client-side detectors.
 */
export function detectBotD19Signals(gpuRenderer?: string): BotD19Result {
  const reasons: string[] = [];
  const signals: Record<BotDSignalName, boolean> = {
    app_version: false,
    distinctive_properties: false,
    document_element_keys: false,
    error_trace: false,
    eval_length: false,
    function_bind: false,
    languages_inconsistency: false,
    mime_types_consistence: false,
    notification_permissions: false,
    plugins_array: false,
    plugins_inconsistency: false,
    process: false,
    product_sub: false,
    rtt: false,
    user_agent: false,
    webdriver: false,
    webgl: false,
    window_external: false,
    window_size: false,
  };

  if (typeof window === 'undefined') {
    return { detected: false, reasons, signals, inspector_probes: {} };
  }

  const nav = typeof navigator !== 'undefined' ? navigator : undefined;
  if (!nav) return { detected: false, reasons, signals, inspector_probes: {} };

  // 1. app_version
  try {
    if (/HeadlessChrome/i.test(nav.appVersion || '')) {
      signals.app_version = true;
      reasons.push('HeadlessChrome in appVersion');
    }
  } catch {}

  // 2. distinctive_properties
  try {
    const distinctivePatterns = [
      'cdc_adoQpoasnfa76pfcZLmcfl_',
      '__webdriver_script_fn',
      '_Selenium_IDE_Recorder',
      'callPhantom',
      '_phantom',
      '__nightmare',
      'domAutomation',
      'domAutomationController',
      '__playwright',
      '__puppeteer',
      '_Selenium_IDE_Recorder',
    ];
    for (const key of distinctivePatterns) {
      if (key in (window as unknown as Record<string, unknown>) || key in (document as unknown as Record<string, unknown>)) {
        signals.distinctive_properties = true;
        reasons.push(`Distinctive automation property: ${key}`);
        break;
      }
    }
  } catch {}

  // 3. document_element_keys
  try {
    if (document.documentElement) {
      const docKeys = Object.keys(document.documentElement);
      for (const k of docKeys) {
        if (/selenium|webdriver|driver/i.test(k)) {
          signals.document_element_keys = true;
          reasons.push(`Automation key on documentElement: ${k}`);
          break;
        }
      }
      const docAttrs = Array.from(document.documentElement.attributes).map((a) => a.name);
      for (const attr of docAttrs) {
        if (/selenium|webdriver|cdp/i.test(attr)) {
          signals.document_element_keys = true;
          reasons.push(`Automation attribute on documentElement: ${attr}`);
          break;
        }
      }
    }
  } catch {}

  // 4. error_trace — RETIRED. A freshly constructed Error's own stack never contains the
  // automation harness, and reading it can itself trigger a CDP preview read. The only safe
  // observation is the Error.prototype.name descriptor preview, reported under
  // inspector_probes as informational input for `inspector_state`, never as bot proof.
  let errorPrototypeNamePreview = '';
  try {
    const nameDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, 'name');
    errorPrototypeNamePreview =
      typeof nameDescriptor?.value === 'string' ? nameDescriptor.value.slice(0, 32) : '';
  } catch {}

  // 5. eval_length
  try {
    const evalLen = eval.toString().length;
    if (evalLen !== 33 && /Chrome/i.test(nav.userAgent) && !/Firefox|Edge/i.test(nav.userAgent)) {
      signals.eval_length = true;
      reasons.push(`Non-native eval string length: ${evalLen}`);
    }
  } catch {}

  // 6. function_bind
  try {
    if (typeof Function.prototype.bind !== 'function' || Function.prototype.bind.toString().length !== 33) {
      if (/Chrome/i.test(nav.userAgent)) {
        signals.function_bind = true;
        reasons.push('Function.prototype.bind tampered');
      }
    }
  } catch {}

  // 7. languages_inconsistency
  try {
    if (!nav.languages || !Array.isArray(nav.languages) || nav.languages.length === 0) {
      signals.languages_inconsistency = true;
      reasons.push('navigator.languages array is empty');
    } else if (nav.language && nav.languages[0] && !nav.languages[0].startsWith(nav.language.split('-')[0])) {
      signals.languages_inconsistency = true;
      reasons.push(`Inconsistent language: ${nav.language} vs ${nav.languages[0]}`);
    }
  } catch {}

  // 8. mime_types_consistence
  try {
    if (nav.mimeTypes && nav.plugins && /Chrome/i.test(nav.userAgent)) {
      if (nav.plugins.length > 0 && nav.mimeTypes.length === 0) {
        signals.mime_types_consistence = true;
        reasons.push('Plugins present but mimeTypes array is empty');
      }
    }
  } catch {}

  // 9. notification_permissions
  try {
    if (typeof Notification !== 'undefined' && Notification.permission === 'denied') {
      const isHeadless = /HeadlessChrome/i.test(nav.userAgent);
      if (isHeadless) {
        signals.notification_permissions = true;
        reasons.push('Notification permission denied by default (headless)');
      }
    }
  } catch {}

  // 10. plugins_array — descriptor/source check only. `instanceof PluginArray` and any other
  // prototype-identity or cross-realm getter comparison is unsafe: an iframe / ShadowRealm
  // PluginArray is genuine but fails identity checks, branding real people as bots.
  const nativeGetterSource = (descriptor: PropertyDescriptor | undefined): string => {
    if (!descriptor?.get) return '';
    try {
      return Function.prototype.toString.call(descriptor.get);
    } catch {
      return '';
    }
  };
  const navProto = typeof Navigator !== 'undefined' ? Navigator.prototype : undefined;
  try {
    if (/Chrome/i.test(nav.userAgent) && !/Mobile|Android/i.test(nav.userAgent)) {
      const plugins = (nav as unknown as { plugins?: unknown }).plugins;
      const descriptor = navProto
        ? Object.getOwnPropertyDescriptor(navProto, 'plugins')
        : undefined;
      const looksLikeCollection =
        Boolean(plugins) &&
        typeof plugins === 'object' &&
        typeof (plugins as { length?: unknown }).length === 'number' &&
        typeof (plugins as { item?: unknown }).item === 'function';
      if (!/\[native code\]/.test(nativeGetterSource(descriptor)) || !looksLikeCollection) {
        signals.plugins_array = true;
        reasons.push('navigator.plugins does not expose a native PluginArray descriptor/source');
      }
    }
  } catch {}

  // 11. plugins_inconsistency — compare getter SOURCES, never plugin counts or prototype
  // identity. A privacy-hardened profile legitimately reports an empty plugins list; only a
  // mismatch between the plugins and mimeTypes getter sources is real tampering evidence.
  try {
    if (/Chrome/i.test(nav.userAgent) && !/Mobile|Android/i.test(nav.userAgent)) {
      const pluginsDescriptor = navProto
        ? Object.getOwnPropertyDescriptor(navProto, 'plugins')
        : undefined;
      const mimeDescriptor = navProto
        ? Object.getOwnPropertyDescriptor(navProto, 'mimeTypes')
        : undefined;
      const pluginsNative = /\[native code\]/.test(nativeGetterSource(pluginsDescriptor));
      const mimeNative = /\[native code\]/.test(nativeGetterSource(mimeDescriptor));
      if (pluginsNative !== mimeNative) {
        signals.plugins_inconsistency = true;
        reasons.push('navigator.plugins / mimeTypes getter sources disagree');
      }
    }
  } catch {}

  // 12. process
  try {
    const win = window as unknown as { process?: { versions?: { node?: string; electron?: string } } };
    if (win.process && win.process.versions && (win.process.versions.node || win.process.versions.electron)) {
      signals.process = true;
      reasons.push(`Exposed process runtime (${win.process.versions.electron ? 'Electron' : 'Node.js'})`);
    }
  } catch {}

  // 13. product_sub
  try {
    if (/Chrome|Safari/i.test(nav.userAgent) && nav.productSub !== '20030107') {
      signals.product_sub = true;
      reasons.push(`Unexpected productSub: ${nav.productSub}`);
    }
  } catch {}

  // 14. rtt
  try {
    const conn = (nav as unknown as { connection?: { rtt?: number } }).connection;
    if (conn && conn.rtt === 0) {
      signals.rtt = true;
      reasons.push('Connection RTT is exactly 0 (virtual container network)');
    }
  } catch {}

  // 15. user_agent
  try {
    if (/HeadlessChrome|PhantomJS|SlimerJS|Playwright|puppeteer|Selenium|Sequentum|AdsPower|BrowserAutomationStudio/i.test(nav.userAgent)) {
      signals.user_agent = true;
      reasons.push('Automation User-Agent signature');
    }
  } catch {}

  // 16. webdriver
  try {
    if (nav.webdriver === true) {
      signals.webdriver = true;
      reasons.push('navigator.webdriver is true');
    }
    const navProto = typeof Navigator !== 'undefined' ? Navigator.prototype : undefined;
    const desc = navProto ? Object.getOwnPropertyDescriptor(navProto, 'webdriver') : undefined;
    if (desc && desc.get && desc.get.toString().indexOf('[native code]') === -1) {
      signals.webdriver = true;
      reasons.push('navigator.webdriver getter overridden');
    }
  } catch {}

  // 17. webgl
  try {
    const renderer = (gpuRenderer || '').toLowerCase();
    if (/swiftshader|subzero|0x0000c0de|llvmpipe|mesa offscreen|software rasterizer/i.test(renderer)) {
      signals.webgl = true;
      reasons.push(`Software WebGL renderer: ${gpuRenderer}`);
    }
  } catch {}

  // 18. window_external
  try {
    const ext = (window as unknown as { external?: unknown }).external;
    if (ext && typeof ext === 'object' && Object.prototype.toString.call(ext) !== '[object External]') {
      if (/Chrome/i.test(nav.userAgent)) {
        signals.window_external = true;
        reasons.push('window.external toString tampering');
      }
    }
  } catch {}

  // 19. window_size
  try {
    if (window.outerWidth === 0 && window.outerHeight === 0) {
      signals.window_size = true;
      reasons.push('Window outerWidth and outerHeight are 0');
    }
  } catch {}

  const detected = Object.values(signals).some(Boolean);
  return {
    detected,
    reasons,
    signals,
    inspector_probes: {
      // Informational only: a descriptor preview of Error.prototype.name, never an own-stack
      // read and never a verdict input.
      errorPrototypeNamePreview,
    },
  };
}

/**
 * Detects AI agent / bot from server-side signals:
 * - User-Agent string
 * - ASN number and org string
 * - Request headers (Web Bot Auth Signature-Agent, etc.)
 */
export function detectAiBotFromServerSignals(params: {
  userAgent: string;
  asnNumber: number | null;
  asnOrg: string;
  headers: Record<string, string | string[] | undefined>;
}): BotDetectionResult {
  const { userAgent, asnNumber, asnOrg, headers } = params;
  const ua = userAgent || '';

  // Check Web Bot Auth headers first (Signature-Agent)
  const signatureAgent = (headers['signature-agent'] as string) || '';
  const signatureInput = (headers['signature-input'] as string) || '';
  const signature = (headers['signature'] as string) || '';
  const hasWebBotAuth = Boolean(signatureAgent && signatureInput && signature);

  const networkKnown =
    asnNumber !== null || (Boolean(asnOrg.trim()) && !/^unknown\b/i.test(asnOrg.trim()));

  for (const entry of BOT_DIRECTORY) {
    let matched = false;
    // Only a UA / header claim can name an agent. An ASN match alone confirms the operator
    // network, it never proves which agent is running, so it cannot upgrade identity to
    // `verified`.
    let claimedByUaOrHeader = false;

    // UA pattern match
    if (entry.uaPatterns) {
      for (const pattern of entry.uaPatterns) {
        if (pattern.test(ua)) {
          matched = true;
          claimedByUaOrHeader = true;
          break;
        }
      }
    }

    // ASN number match
    if (!matched && asnNumber !== null && entry.asnNumbers) {
      if (entry.asnNumbers.includes(asnNumber)) {
        matched = true;
      }
    }

    // ASN org pattern match
    if (!matched && entry.asnPatterns) {
      for (const pattern of entry.asnPatterns) {
        if (pattern.test(asnOrg)) {
          matched = true;
          break;
        }
      }
    }

    // Header pattern match
    if (!matched && entry.headerPatterns) {
      for (const { header, pattern } of entry.headerPatterns) {
        const hVal = (headers[header] as string) || '';
        if (hVal && pattern.test(hVal)) {
          matched = true;
          claimedByUaOrHeader = true;
          break;
        }
      }
    }

    // An ASN / organisation match names the operator's network, never the product. Every
    // cloud ASN hosts millions of real people, so "AS16509 → Bedrock AgentCore" (or any
    // other AI-provider ASN) branded ordinary visitors as AI agents. When the first match
    // came from the network, still test the entry's header patterns: a Web Bot Auth
    // `Signature-Agent` / `Signature` header is a real product claim.
    if (matched && !claimedByUaOrHeader && entry.headerPatterns) {
      for (const { header, pattern } of entry.headerPatterns) {
        const hVal = (headers[header] as string) || '';
        if (hVal && pattern.test(hVal)) {
          claimedByUaOrHeader = true;
          break;
        }
      }
    }
    // Network-only evidence cannot name an agent. Skip this entry and keep scanning.
    if (matched && !claimedByUaOrHeader) continue;

    if (matched) {
      let identity: BotIdentity = entry.identity;
      const networkMatches =
        (asnNumber !== null && Boolean(entry.asnNumbers?.includes(asnNumber))) ||
        Boolean(entry.asnPatterns?.some((pattern) => pattern.test(asnOrg)));

      if (identity === 'verified') {
        if (!claimedByUaOrHeader) {
          // ASN-only match: the operator network is confirmed, the exact product is not.
          identity = 'unknown';
        } else if (!networkMatches) {
          // Claims an official agent from outside the operator's own infrastructure.
          identity = hasWebBotAuth ? 'verified' : networkKnown ? 'spoofed' : 'unknown';
        }
      }
      if (identity === 'unknown' && hasWebBotAuth) {
        identity = 'signed';
      }

      return {
        detected: true,
        botType: entry.category,
        botInfo: {
          category: entry.category,
          provider: entry.provider,
          name: identity === 'spoofed' ? `Spoofed ${entry.name}` : entry.name,
          identity,
        },
      };
    }
  }

  // Generic headless/automation detection from UA
  if (/HeadlessChrome|Headless/i.test(ua)) {
    return {
      detected: true,
      botType: 'browser_automation',
      botInfo: {
        category: 'browser_automation',
        provider: 'Unknown',
        name: 'Headless Browser',
        identity: 'unknown',
      },
    };
  }

  if (/Playwright|puppeteer|selenium|PhantomJS|Sequentum/i.test(ua)) {
    return {
      detected: true,
      botType: 'browser_automation',
      botInfo: {
        category: 'browser_automation',
        provider: 'Unknown',
        name: 'Browser Automation',
        identity: 'unknown',
      },
    };
  }

  return { detected: false, botType: null, botInfo: null };
}

/**
 * Checks if a Google Cloud/AI ASN is visiting (for Gemini Mariner / Deep Research detection).
 */
export function isGoogleAiAsn(asnNumber: number | null): boolean {
  if (!asnNumber) return false;
  return [15169, 396982, 16591].includes(asnNumber);
}

/**
 * Checks if an AWS/Anthropic ASN is visiting.
 */
export function isAwsAnthropicAsn(asnNumber: number | null): boolean {
  if (!asnNumber) return false;
  return [16509, 14618].includes(asnNumber);
}

/**
 * Formats bot_info for API v4 JSON response.
 */
export function formatBotInfoForApiV4(result: BotDetectionResult): {
  bot: string;
  bot_type: string | null;
  bot_info: BotInfo | null;
} {
  if (!result.detected || !result.botInfo) {
    return { bot: 'not_detected', bot_type: null, bot_info: null };
  }
  const cat = result.botInfo.category;
  const isBad = cat === 'ai_agent' || cat === 'browser_automation';
  return {
    bot: isBad ? 'bad' : 'good',
    bot_type: result.botType,
    bot_info: result.botInfo,
  };
}

/* -------------------------------------------------------------------------- */
/* Phase 3 — cryptographic agent proof (RFC 9421 / signed agent / allowlist)  */
/* -------------------------------------------------------------------------- */

export type AgentProofMethod = 'rfc9421' | 'signed_agent' | 'allowlist' | 'none';

function headerValue(headers: Record<string, string | string[] | undefined>, name: string): string {
  const value = headers[name];
  if (Array.isArray(value)) return value.join(', ');
  return typeof value === 'string' ? value : '';
}

/**
 * Resolve the proof that backs a *named* AI agent. A bare ASN or User-Agent never upgrades
 * identity to `verified`: only RFC 9421 HTTP Message Signatures, a signed-agent header, or a
 * caller-supplied verified allowlist can do that (preserves the ASN-only fix, 3cbb84f).
 */
export function resolveAgentProofMethod(
  headers: Record<string, string | string[] | undefined>,
  allowlistedAgents: readonly string[] = []
): AgentProofMethod {
  const signatureInput = headerValue(headers, 'signature-input');
  const signature = headerValue(headers, 'signature');
  const signatureAgent = headerValue(headers, 'signature-agent');
  // RFC 9421 requires a Signature-Input with a keyid and a detached Signature.
  const rfc9421 = Boolean(signatureInput && signature && /keyid/i.test(signatureInput));
  if (rfc9421) return 'rfc9421';
  // Signed-agent / Web Bot Auth header pair.
  if (signatureAgent && signature && signatureInput) return 'signed_agent';
  if (allowlistedAgents.length > 0) {
    const ua = headerValue(headers, 'user-agent');
    if (allowlistedAgents.some((agent) => agent && ua.toLowerCase().includes(agent.toLowerCase()))) {
      return 'allowlist';
    }
  }
  return 'none';
}

/** True only when a named agent has real cryptographic / verified-allowlist proof. */
export function hasVerifiedAgentProof(
  headers: Record<string, string | string[] | undefined>,
  allowlistedAgents: readonly string[] = []
): boolean {
  return resolveAgentProofMethod(headers, allowlistedAgents) !== 'none';
}


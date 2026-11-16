/**
 * Static bot knowledge base for the AI Crawler / Bot Protection engine.
 *
 * This module is intentionally dependency-free and side-effect free so it can be imported by
 * both the Node middleware and the React client build. Detection IDs mirror Cloudflare's
 * "Verified Bots / AI crawlers" catalogue where one exists; operator-specific IDs in the
 * 90000xxx range are used for crawlers that Cloudflare does not publish an ID for.
 */

export type BotCategory =
  | 'AI Crawler'
  | 'AI Assistant'
  | 'AI Search'
  | 'Search Engine'
  | 'HTTP Client';

export type BotBehavior = 'Training' | 'Agent' | 'Search' | 'Automation';

export type OperatorLabel = 'Direct' | 'Intermediary';

export type UaMatchMode = 'bounded' | 'versioned' | 'exact';

export interface UaTokenDefinition {
  token: string;
  matchMode?: UaMatchMode;
}

export type BotFeedFormat = 'json' | 'amazon_html' | 'sail_toml';

export interface BotFeedDefinition {
  url: string;
  format: BotFeedFormat;
}

export interface BotDefinition {
  id: string;
  displayName: string;
  operator: string;
  cfDetectionIds: string[];
  legacyCategory: string;
  behavior: BotBehavior;
  operatorLabel: OperatorLabel;
  /** Some operators run both first-party and third-party crawlers on shared infrastructure. */
  isMixedPurposeAccountable?: boolean;
  uaTokens: UaTokenDefinition[];
  feedUrls: BotFeedDefinition[];
  /** Reverse-DNS (FCrDNS) suffixes that positively confirm a crawler. */
  fcrdnsSuffixes?: string[];
  /** Soft PTR suffixes accepted without a forward-confirmation lookup. */
  softPtrSuffixes?: string[];
  /** Whether the operator documents dual verification (DNS + published IP feed). */
  dualOrVerification?: boolean;
  /** Hosts that publish an RFC 9421 / Web Bot Auth signature directory. */
  webBotAuthHosts?: string[];
  /** Autonomous systems the operator is known to publish ranges from. */
  expectedAsns?: number[];
  followsRobotsTxt: boolean;
}

/** Ten Toutiao / ByteDance /24 prefixes published for Bytespider. */
export const BYTESPIDER_STATIC_SUBNETS: readonly string[] = [
  '110.249.201.0/24',
  '110.249.202.0/24',
  '111.225.148.0/24',
  '111.225.149.0/24',
  '220.243.135.0/24',
  '220.243.136.0/24',
  '220.243.188.0/24',
  '220.243.189.0/24',
  '60.8.123.0/24',
  '60.8.151.0/24',
] as const;

/** Referer host → canonical operator name, used for attribution when no signed identity exists. */
export const OPERATOR_REFERRER_DOMAINS: Record<string, string> = {
  'chatgpt.com': 'OpenAI',
  'openai.com': 'OpenAI',
  'claude.ai': 'Anthropic',
  'claude.com': 'Anthropic',
  'anthropic.com': 'Anthropic',
  'perplexity.ai': 'Perplexity',
  'mistral.ai': 'Mistral AI',
  'manus.im': 'Manus',
  'google.com': 'Google',
  'gemini.google.com': 'Google',
  'bing.com': 'Microsoft',
  'copilot.microsoft.com': 'Microsoft',
  'meta.ai': 'Meta',
  'meta.com': 'Meta',
  'facebook.com': 'Meta',
  'duckduckgo.com': 'DuckDuckGo',
  'duck.com': 'DuckDuckGo',
  'bytedance.com': 'ByteDance',
  'toutiao.com': 'ByteDance',
  'tiktok.com': 'ByteDance',
  'apple.com': 'Apple',
};

export interface WebBotAuthSigner {
  botId: string;
  operator: string;
  directoryUrl: string;
}

export const WEB_BOT_AUTH_SIGNER_MAP: Record<string, WebBotAuthSigner> = {
  'api.manus.im': {
    botId: 'manus',
    operator: 'Manus',
    directoryUrl: 'https://api.manus.im/.well-known/http-message-signatures-directory',
  },
  'chatgpt.com': {
    botId: 'chatgpt-user',
    operator: 'OpenAI',
    directoryUrl: 'https://chatgpt.com/.well-known/http-message-signatures-directory',
  },
  'agent.bot.goog': {
    botId: 'google-agent',
    operator: 'Google',
    directoryUrl: 'https://agent.bot.goog/.well-known/http-message-signatures-directory',
  },
  'cursorusercontent.com': {
    botId: 'google-agent',
    operator: 'Google',
    directoryUrl: 'https://cursorusercontent.com/.well-known/http-message-signatures-directory',
  },
  'www.meta.com': {
    botId: 'meta-externalagent',
    operator: 'Meta',
    directoryUrl: 'https://www.meta.com/.well-known/http-message-signatures-directory',
  },
  'assistbot.duckduckgo.com': {
    botId: 'duckassistbot',
    operator: 'DuckDuckGo',
    directoryUrl: 'https://assistbot.duckduckgo.com/.well-known/http-message-signatures-directory',
  },
  'web-bot-auth.cloudflare-browser-rendering-085.workers.dev': {
    botId: 'chatgpt-user',
    operator: 'OpenAI',
    directoryUrl:
      'https://web-bot-auth.cloudflare-browser-rendering-085.workers.dev/.well-known/http-message-signatures-directory',
  },
};

export const BOT_REGISTRY: BotDefinition[] = [
  {
    id: 'manus',
    displayName: 'Manus',
    operator: 'Manus',
    cfDetectionIds: ['90000100'],
    legacyCategory: 'AI Assistant',
    behavior: 'Agent',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'Manus', matchMode: 'bounded' }],
    feedUrls: [],
    webBotAuthHosts: ['api.manus.im'],
    followsRobotsTxt: false,
  },
  {
    id: 'gptbot',
    displayName: 'GPTBot',
    operator: 'OpenAI',
    cfDetectionIds: ['123815556', '33563875'],
    legacyCategory: 'AI Crawler',
    behavior: 'Training',
    operatorLabel: 'Direct',
    isMixedPurposeAccountable: true,
    uaTokens: [{ token: 'GPTBot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://openai.com/gptbot.json', format: 'json' }],
    expectedAsns: [8075, 400645],
    followsRobotsTxt: true,
  },
  {
    id: 'chatgpt-user',
    displayName: 'ChatGPT-User',
    operator: 'OpenAI',
    cfDetectionIds: ['132995013', '33563857'],
    legacyCategory: 'AI Assistant',
    behavior: 'Agent',
    operatorLabel: 'Direct',
    isMixedPurposeAccountable: true,
    uaTokens: [{ token: 'ChatGPT-User', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://openai.com/chatgpt-user.json', format: 'json' }],
    webBotAuthHosts: ['chatgpt.com'],
    expectedAsns: [8075, 400645],
    followsRobotsTxt: false,
  },
  {
    id: 'oai-searchbot',
    displayName: 'OAI-SearchBot',
    operator: 'OpenAI',
    cfDetectionIds: ['126255384', '33563986'],
    legacyCategory: 'AI Search',
    behavior: 'Search',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'OAI-SearchBot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://openai.com/searchbot.json', format: 'json' }],
    expectedAsns: [8075, 400645],
    followsRobotsTxt: true,
  },
  {
    id: 'chatgpt',
    displayName: 'ChatGPT',
    operator: 'OpenAI',
    cfDetectionIds: ['90000107'],
    legacyCategory: 'AI Assistant',
    behavior: 'Agent',
    operatorLabel: 'Direct',
    isMixedPurposeAccountable: true,
    uaTokens: [{ token: 'ChatGPT', matchMode: 'bounded' }],
    feedUrls: [],
    webBotAuthHosts: ['chatgpt.com'],
    expectedAsns: [8075, 400645],
    followsRobotsTxt: false,
  },
  {
    id: 'mistralai-user',
    displayName: 'MistralAI-User',
    operator: 'Mistral AI',
    cfDetectionIds: ['90000101'],
    legacyCategory: 'AI Assistant',
    behavior: 'Agent',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'MistralAI-User', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://mistral.ai/mistralai-user-ips.json', format: 'json' }],
    expectedAsns: [212949],
    followsRobotsTxt: false,
  },
  {
    id: 'mistralai-index',
    displayName: 'MistralAI-Index',
    operator: 'Mistral AI',
    cfDetectionIds: ['90000102'],
    legacyCategory: 'AI Search',
    behavior: 'Search',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'MistralAI-Index', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://mistral.ai/mistralai-index-ips.json', format: 'json' }],
    expectedAsns: [212949],
    followsRobotsTxt: true,
  },
  {
    id: 'mistralai-training',
    displayName: 'MistralAI-Training',
    operator: 'Mistral AI',
    cfDetectionIds: ['90000109'],
    legacyCategory: 'AI Crawler',
    behavior: 'Training',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'MistralAI-Training', matchMode: 'bounded' }],
    feedUrls: [],
    expectedAsns: [212949],
    followsRobotsTxt: true,
  },
  {
    id: 'claudebot',
    displayName: 'ClaudeBot',
    operator: 'Anthropic',
    cfDetectionIds: ['33563859'],
    legacyCategory: 'AI Crawler',
    behavior: 'Training',
    operatorLabel: 'Direct',
    isMixedPurposeAccountable: true,
    uaTokens: [{ token: 'ClaudeBot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://claude.com/crawling/bots.json', format: 'json' }],
    followsRobotsTxt: true,
  },
  {
    id: 'claude-searchbot',
    displayName: 'Claude-SearchBot',
    operator: 'Anthropic',
    cfDetectionIds: ['33564301'],
    legacyCategory: 'AI Search',
    behavior: 'Search',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'Claude-SearchBot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://claude.com/.well-known/sail', format: 'sail_toml' }],
    followsRobotsTxt: true,
  },
  {
    id: 'claude-user',
    displayName: 'Claude-User',
    operator: 'Anthropic',
    cfDetectionIds: ['33564303'],
    legacyCategory: 'AI Assistant',
    behavior: 'Agent',
    operatorLabel: 'Direct',
    isMixedPurposeAccountable: true,
    uaTokens: [{ token: 'Claude-User', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://claude.com/.well-known/sail', format: 'sail_toml' }],
    followsRobotsTxt: false,
  },
  {
    id: 'claude-agent',
    displayName: 'Claude-Agent',
    operator: 'Anthropic',
    cfDetectionIds: ['90000103'],
    legacyCategory: 'AI Assistant',
    behavior: 'Agent',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'Claude-Agent', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://claude.com/.well-known/sail', format: 'sail_toml' }],
    followsRobotsTxt: false,
  },
  {
    id: 'applebot',
    displayName: 'Applebot',
    operator: 'Apple',
    cfDetectionIds: ['120424214', '33563845'],
    legacyCategory: 'Search Engine',
    behavior: 'Search',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'Applebot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://search.developer.apple.com/applebot.json', format: 'json' }],
    fcrdnsSuffixes: ['.applebot.apple.com'],
    dualOrVerification: true,
    expectedAsns: [714, 6185],
    followsRobotsTxt: true,
  },
  {
    id: 'googlebot',
    displayName: 'Googlebot',
    operator: 'Google',
    cfDetectionIds: ['120623194', '33554459'],
    legacyCategory: 'Search Engine',
    behavior: 'Search',
    operatorLabel: 'Direct',
    uaTokens: [
      { token: 'Googlebot', matchMode: 'bounded' },
      { token: 'Googlebot-Image', matchMode: 'bounded' },
      { token: 'Googlebot-News', matchMode: 'bounded' },
      { token: 'Googlebot-Video', matchMode: 'bounded' },
    ],
    feedUrls: [
      { url: 'https://www.google.com/common-crawlers.json', format: 'json' },
      { url: 'https://www.google.com/special-crawlers.json', format: 'json' },
    ],
    fcrdnsSuffixes: ['.googlebot.com', '.google.com'],
    dualOrVerification: true,
    expectedAsns: [15169],
    followsRobotsTxt: true,
  },
  {
    id: 'google-cloudvertexbot',
    displayName: 'Google-CloudVertexBot',
    operator: 'Google',
    cfDetectionIds: ['133730073', '33564321'],
    legacyCategory: 'AI Crawler',
    behavior: 'Training',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'Google-CloudVertexBot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://www.google.com/special-crawlers.json', format: 'json' }],
    fcrdnsSuffixes: ['.googlebot.com', '.google.com'],
    dualOrVerification: true,
    expectedAsns: [15169],
    followsRobotsTxt: true,
  },
  {
    id: 'google-agent',
    displayName: 'Google-Agent',
    operator: 'Google',
    cfDetectionIds: ['90000106'],
    legacyCategory: 'AI Assistant',
    behavior: 'Agent',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'Google-Agent', matchMode: 'bounded' }],
    feedUrls: [
      { url: 'https://www.google.com/user-triggered-agents.json', format: 'json' },
      { url: 'https://www.google.com/user-triggered-fetchers.json', format: 'json' },
      { url: 'https://www.google.com/user-triggered-fetchers-google.json', format: 'json' },
    ],
    fcrdnsSuffixes: ['.gae.googleusercontent.com', '.google.com'],
    dualOrVerification: true,
    webBotAuthHosts: ['agent.bot.goog'],
    expectedAsns: [15169],
    followsRobotsTxt: false,
  },
  {
    id: 'amazonbot',
    displayName: 'Amazonbot',
    operator: 'Amazon',
    cfDetectionIds: ['118601807', '33563839'],
    legacyCategory: 'AI Crawler',
    behavior: 'Training',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'Amazonbot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://www.amazon.com/ip-addresses/', format: 'amazon_html' }],
    fcrdnsSuffixes: ['.crawl.amazonbot.amazon'],
    dualOrVerification: true,
    expectedAsns: [16509, 14618],
    followsRobotsTxt: true,
  },
  {
    id: 'amzn-searchbot',
    displayName: 'amzn-searchbot',
    operator: 'Amazon',
    cfDetectionIds: ['90000104'],
    legacyCategory: 'AI Search',
    behavior: 'Search',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'amzn-searchbot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://www.amazon.com/searchbot-ip-addresses/', format: 'amazon_html' }],
    fcrdnsSuffixes: ['.crawl.amazonbot.amazon'],
    expectedAsns: [16509, 14618],
    followsRobotsTxt: true,
  },
  {
    id: 'amzn-user',
    displayName: 'amzn-user',
    operator: 'Amazon',
    cfDetectionIds: ['90000105'],
    legacyCategory: 'AI Assistant',
    behavior: 'Agent',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'amzn-user', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://www.amazon.com/live-ip-addresses/', format: 'amazon_html' }],
    fcrdnsSuffixes: ['.crawl.amazonbot.amazon'],
    expectedAsns: [16509, 14618],
    followsRobotsTxt: false,
  },
  {
    id: 'perplexitybot',
    displayName: 'PerplexityBot',
    operator: 'Perplexity',
    cfDetectionIds: ['33563889'],
    legacyCategory: 'AI Crawler',
    behavior: 'Training',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'PerplexityBot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://www.perplexity.ai/perplexitybot_ips.json', format: 'json' }],
    expectedAsns: [14618, 16509],
    followsRobotsTxt: true,
  },
  {
    id: 'perplexity-user',
    displayName: 'Perplexity-User',
    operator: 'Perplexity',
    cfDetectionIds: ['33564371'],
    legacyCategory: 'AI Assistant',
    behavior: 'Agent',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'Perplexity-User', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://www.perplexity.ai/perplexity-user_ips.json', format: 'json' }],
    expectedAsns: [14618, 16509],
    followsRobotsTxt: false,
  },
  {
    id: 'bytespider',
    displayName: 'Bytespider',
    operator: 'ByteDance',
    cfDetectionIds: ['33563853'],
    legacyCategory: 'AI Crawler',
    behavior: 'Training',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'Bytespider', matchMode: 'bounded' }],
    feedUrls: [],
    softPtrSuffixes: ['.bytedance.com'],
    expectedAsns: [396986, 4837, 4808, 16509],
    followsRobotsTxt: false,
  },
  {
    id: 'bingbot',
    displayName: 'Bingbot',
    operator: 'Microsoft',
    cfDetectionIds: ['117479730', '33554461'],
    legacyCategory: 'Search Engine',
    behavior: 'Search',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'bingbot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://www.bing.com/toolbox/bingbot.json', format: 'json' }],
    fcrdnsSuffixes: ['.search.msn.com'],
    dualOrVerification: true,
    expectedAsns: [8075, 12076],
    followsRobotsTxt: true,
  },
  {
    id: 'duckassistbot',
    displayName: 'DuckAssistBot',
    operator: 'DuckDuckGo',
    cfDetectionIds: ['126666910', '33564037'],
    legacyCategory: 'AI Assistant',
    behavior: 'Agent',
    operatorLabel: 'Direct',
    uaTokens: [{ token: 'DuckAssistBot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://duckduckgo.com/duckassistbot.json', format: 'json' }],
    webBotAuthHosts: ['assistbot.duckduckgo.com'],
    followsRobotsTxt: false,
  },
  {
    id: 'ccbot',
    displayName: 'CCBot',
    operator: 'Common Crawl',
    cfDetectionIds: ['133621792', '33563855'],
    legacyCategory: 'AI Crawler',
    behavior: 'Training',
    operatorLabel: 'Intermediary',
    uaTokens: [{ token: 'CCBot', matchMode: 'bounded' }],
    feedUrls: [{ url: 'https://index.commoncrawl.org/ccbot.json', format: 'json' }],
    fcrdnsSuffixes: ['.crawl.commoncrawl.org'],
    dualOrVerification: true,
    expectedAsns: [16509],
    followsRobotsTxt: true,
  },
  {
    id: 'meta-externalagent',
    displayName: 'meta-externalagent',
    operator: 'Meta',
    cfDetectionIds: ['124581738', '33563982'],
    legacyCategory: 'AI Crawler',
    behavior: 'Training',
    operatorLabel: 'Direct',
    isMixedPurposeAccountable: true,
    uaTokens: [{ token: 'meta-externalagent', matchMode: 'bounded' }],
    feedUrls: [],
    fcrdnsSuffixes: ['.fbsbx.com', '.facebook.com', '.tfbnw.net'],
    webBotAuthHosts: ['www.meta.com'],
    expectedAsns: [32934],
    followsRobotsTxt: true,
  },
  {
    id: 'meta-externalfetcher',
    displayName: 'meta-externalfetcher',
    operator: 'Meta',
    cfDetectionIds: ['132272919', '33563980'],
    legacyCategory: 'AI Assistant',
    behavior: 'Agent',
    operatorLabel: 'Direct',
    isMixedPurposeAccountable: true,
    uaTokens: [{ token: 'meta-externalfetcher', matchMode: 'bounded' }],
    feedUrls: [],
    fcrdnsSuffixes: ['.fbsbx.com', '.facebook.com', '.tfbnw.net'],
    expectedAsns: [32934],
    followsRobotsTxt: false,
  },
];

export const BOT_MAP_BY_ID: Record<string, BotDefinition> = Object.freeze(
  BOT_REGISTRY.reduce<Record<string, BotDefinition>>((acc, bot) => {
    acc[bot.id] = bot;
    return acc;
  }, {})
);

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function tokenRegex(token: UaTokenDefinition): RegExp {
  const escaped = escapeRegex(token.token);
  switch (token.matchMode ?? 'bounded') {
    case 'exact':
      return new RegExp(`^\\s*${escaped}\\s*$`, 'i');
    case 'versioned':
      // TOKEN/1.2 or a bare TOKEN, but never a longer alphanumeric word.
      return new RegExp(
        `(?:^|[^A-Za-z0-9_-])${escaped}(?:/[0-9][0-9A-Za-z._+-]*)?(?:$|[^A-Za-z0-9_-])`,
        'i'
      );
    case 'bounded':
    default:
      return new RegExp(`(?:^|[^A-Za-z0-9_-])${escaped}(?:$|[^A-Za-z0-9_-])`, 'i');
  }
}

const UA_PATTERNS: ReadonlyArray<{ bot: BotDefinition; regexes: RegExp[] }> = BOT_REGISTRY.map(
  (bot) => ({ bot, regexes: bot.uaTokens.map(tokenRegex) })
);

/**
 * Returns the most specific registry entry matching a User-Agent string.
 * Longer tokens are tested first so `Claude-SearchBot` wins over a shorter `Claude` token.
 */
export function matchUserAgentBot(userAgent: string | null | undefined): BotDefinition | null {
  if (typeof userAgent !== 'string' || !userAgent.trim()) return null;
  const ua = userAgent.trim();
  const ordered = [...UA_PATTERNS].sort((a, b) => {
    const aLen = Math.max(...a.bot.uaTokens.map((t) => t.token.length));
    const bLen = Math.max(...b.bot.uaTokens.map((t) => t.token.length));
    return bLen - aLen;
  });
  for (const entry of ordered) {
    if (entry.regexes.some((regex) => regex.test(ua))) return entry.bot;
  }
  return null;
}

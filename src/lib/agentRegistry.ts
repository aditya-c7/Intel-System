/**
 * Canonical agent registry — exact named identification for AI agents, crawlers and policy
 * tokens.
 *
 * DESIGN CONTRACT
 * - Dependency-free and browser-safe: no Node APIs, no imports, no platform globals touched
 *   at module load. Safe to import from the Vite UI, the Cloudflare worker and the server.
 * - Every derived legacy view (GOOD_BOT_UA_RULES, AI_AGENT_UA_RULES, BOT_DIRECTORY, …) is
 *   computed from AGENT_REGISTRY, so there is exactly one source of truth.
 * - "good" bot means search_crawler / link_preview only. Every AI category is "bad" in the
 *   API v4 bot verdict (see aiBotDirectory.formatBotInfoForApiV4).
 */

/* -------------------------------------------------------------------------- */
/* Public types                                                                */
/* -------------------------------------------------------------------------- */

export type AgentCategory =
  | 'search_crawler'
  | 'link_preview'
  | 'ai_crawler'
  | 'ai_search'
  | 'ai_assistant'
  | 'ai_agent'
  | 'ai_browser'
  | 'browser_automation'
  | 'autonomous_agent'
  | 'spoofed'
  | 'policy_token';

export type AgentBucket =
  | 'gemini'
  | 'grok'
  | 'muse'
  | 'perplexity'
  | 'openai'
  | 'claude'
  | 'cloud-browser'
  | 'remote-browser'
  | 'impostor-spoof'
  | 'search-crawler'
  | 'none'
  | 'mistral'
  | 'manus'
  | 'apple'
  | 'amazon'
  | 'microsoft'
  | 'commoncrawl';

/** Superset of CursorAttributionOverlay's CursorIdentityKind plus exact named-agent kinds. */
export type PillKind =
  | 'automated'
  | 'automation'
  | 'cloud'
  | 'firecrawl'
  | 'browseruse'
  | 'skyvern'
  | 'multion'
  | 'hyperbrowser'
  | 'steel'
  | 'airtop'
  | 'notte'
  | 'lightpanda'
  | 'claude'
  | 'gemini'
  | 'grok'
  | 'perplexity'
  | 'muse'
  | 'chatgpt'
  | 'mistral'
  | 'manus'
  | 'googlebot'
  | 'applebot'
  | 'gptbot'
  | 'chatgpt_user'
  | 'oai_search_bot'
  | 'claude_bot'
  | 'claude_user'
  | 'claude_search_bot'
  | 'perplexity_bot'
  | 'perplexity_user'
  | 'amazonbot'
  | 'bingbot';

export type ProofTier = 'rfc9421' | 'signed_agent' | 'cidr' | 'fcrdns' | 'allowlist' | 'ua_claim' | 'automation';

export interface AgentDef {
  id: string;
  provider: string;
  displayName: string;
  category: AgentCategory;
  bucket: AgentBucket;
  /** Ascending: lower rank = more specific UA match wins in findAgentByUa. */
  rank: number;
  which: readonly ('classifier' | 'robodex' | 'attribution' | 'pill')[];
  ua?: {
    patterns: readonly RegExp[];
    /** True when the UA claim is only accepted from the declared operator network. */
    requireNetworkMatch?: boolean;
    network?: RegExp;
  };
  signature?: {
    keyIdNeedles?: readonly string[];
    agentHosts?: readonly string[];
    wbaRequired?: boolean;
    sail?: boolean;
  };
  fcrdnsSuffixes?: readonly string[];
  asns?: readonly number[];
  /** ASN operator-name patterns; corroboration only, never a product claim. */
  asnPatterns?: readonly RegExp[];
  /** Keys into PINNED_PREFIXES / PREFIX_FEEDS.sourceId. */
  feedIds?: readonly string[];
  minProofForVerified: ProofTier;
  executionMode?: string;
  policyToken?: boolean;
  pill?: { kind: PillKind; label?: string };
}

export interface PrefixFeedDef {
  sourceId: string;
  url: string;
  format: 'json' | 'sail-toml' | 'amazon-html' | 'wba-directory' | 'none';
  pinnedKey?: string;
  refreshMs?: number;
  maxBytes?: number;
}

const DAY = 86_400_000;

/** Refresh descriptors for every pinned prefix source. `pinnedKey` names the frozen snapshot. */
export const PREFIX_FEEDS: readonly PrefixFeedDef[] = [
  { sourceId: 'mistral-user', url: 'https://mistral.ai/robots.txt', format: 'none', pinnedKey: 'mistral-user', refreshMs: DAY, maxBytes: 2_000_000 },
  { sourceId: 'mistral-index', url: 'https://mistral.ai/robots.txt', format: 'none', pinnedKey: 'mistral-index', refreshMs: DAY, maxBytes: 2_000_000 },
  { sourceId: 'gptbot', url: 'https://openai.com/gptbot.json', format: 'json', pinnedKey: 'gptbot', refreshMs: DAY, maxBytes: 2_000_000 },
  { sourceId: 'chatgpt-user', url: 'https://openai.com/chatgpt-user.json', format: 'json', pinnedKey: 'chatgpt-user', refreshMs: DAY, maxBytes: 4_000_000 },
  { sourceId: 'searchbot', url: 'https://openai.com/searchbot.json', format: 'json', pinnedKey: 'searchbot', refreshMs: DAY, maxBytes: 2_000_000 },
  { sourceId: 'google-common', url: 'https://developers.google.com/search/apis/ipranges/googlebot.json', format: 'json', pinnedKey: 'google-common', refreshMs: DAY, maxBytes: 8_000_000 },
  { sourceId: 'perplexitybot', url: 'https://www.perplexity.com/perplexitybot.json', format: 'json', pinnedKey: 'perplexitybot', refreshMs: DAY, maxBytes: 2_000_000 },
  { sourceId: 'perplexity-user', url: 'https://www.perplexity.com/perplexity-user.json', format: 'json', pinnedKey: 'perplexity-user', refreshMs: DAY, maxBytes: 2_000_000 },
  { sourceId: 'applebot', url: 'https://search.developer.apple.com/applebot.json', format: 'json', pinnedKey: 'applebot', refreshMs: DAY, maxBytes: 2_000_000 },
  { sourceId: 'bingbot', url: 'https://www.bing.com/toolbox/bingbot.json', format: 'json', pinnedKey: 'bingbot', refreshMs: DAY, maxBytes: 2_000_000 },
  { sourceId: 'ccbot', url: 'https://index.commoncrawl.org/ccbot.json', format: 'json', pinnedKey: 'ccbot', refreshMs: DAY, maxBytes: 2_000_000 },
  { sourceId: 'amazonbot', url: 'https://developer.amazon.com/amazonbot/ip-addresses/', format: 'amazon-html', pinnedKey: 'amazonbot', refreshMs: DAY, maxBytes: 4_000_000 },
  { sourceId: 'amzn-search-bot', url: 'https://developer.amazon.com/amazonbot/searchbot-ip-addresses/', format: 'amazon-html', pinnedKey: 'amzn-search-bot', refreshMs: DAY, maxBytes: 4_000_000 },
  { sourceId: 'amzn-user', url: 'https://developer.amazon.com/amazonbot/live-ip-addresses/', format: 'amazon-html', pinnedKey: 'amzn-user', refreshMs: DAY, maxBytes: 4_000_000 },
  { sourceId: 'claude', url: 'https://claude.com/crawling/bots.json', format: 'json', pinnedKey: 'claude', refreshMs: DAY, maxBytes: 2_000_000 },
  { sourceId: 'claude-agent-sail', url: 'https://claude.com/.well-known/sail', format: 'sail-toml', pinnedKey: 'claude-agent-sail', refreshMs: 3_600_000, maxBytes: 1_000_000 },
  // Web Bot Auth directories carry JWKs, not CIDRs. They are never fetched as prefix feeds;
  // the verifier resolves them through WBA_TRUSTED_SIGNERS / PREFIX_FEEDS format 'none'.
  { sourceId: 'manus-wba', url: 'https://api.manus.im/.well-known/http-message-signatures-directory', format: 'none', refreshMs: DAY, maxBytes: 1_000_000 },
  { sourceId: 'grok-wba', url: 'https://cursorusercontent.com/.well-known/http-message-signatures-directory', format: 'none', refreshMs: DAY, maxBytes: 1_000_000 },
  { sourceId: 'google-extended', url: 'https://developers.google.com/search/docs/crawling-indexing/googlebot', format: 'none', refreshMs: DAY, maxBytes: 1_000_000 },
  { sourceId: 'applebot-extended', url: 'https://support.apple.com/en-us/119829', format: 'none', refreshMs: DAY, maxBytes: 1_000_000 },
];

/* -------------------------------------------------------------------------- */
/* The catalog                                                                 */
/* -------------------------------------------------------------------------- */

const REGISTRY_LITERAL = [
  {
    id: 'manus_bot',
    provider: 'Manus',
    displayName: 'Manus Bot',
    category: 'ai_agent',
    bucket: 'manus',
    rank: 10,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/Manus-User\/1\.0/i, /ManusAgent/i, /manus-agent/i] },
    signature: {
      wbaRequired: true,
      agentHosts: ['api.manus.im', 'manus.im', 'manus.ai'],
      keyIdNeedles: ['manus'],
    },
    feedIds: ['manus-wba'],
    minProofForVerified: 'signed_agent',
    executionMode: 'RFC 9421 Signed Agent',
    pill: { kind: 'manus', label: 'Manus' },
  },
  {
    id: 'mistral_ai_user',
    provider: 'Mistral',
    displayName: 'MistralAI-User',
    category: 'ai_assistant',
    bucket: 'mistral',
    rank: 20,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/MistralAI-User\/1\.0/i] },
    feedIds: ['mistral-user'],
    minProofForVerified: 'cidr',
    executionMode: 'User-Triggered Fetcher',
    pill: { kind: 'mistral', label: 'MistralAI-User' },
  },
  {
    id: 'mistral_ai_index',
    provider: 'Mistral',
    displayName: 'MistralAI-Index',
    category: 'ai_search',
    bucket: 'mistral',
    rank: 30,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/MistralAI-Index\/1\.0/i] },
    feedIds: ['mistral-index'],
    minProofForVerified: 'cidr',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'mistral', label: 'MistralAI-Index' },
  },
  {
    id: 'mistral_ai_training',
    provider: 'Mistral',
    displayName: 'MistralAI-Training',
    category: 'ai_crawler',
    bucket: 'mistral',
    rank: 40,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/MistralAI-Training\/1\.0/i] },
    // No official CIDR feed: a UA claim alone can never upgrade this agent to verified.
    minProofForVerified: 'ua_claim',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'mistral', label: 'MistralAI-Training' },
  },
  {
    id: 'googlebot',
    provider: 'Google',
    displayName: 'Googlebot',
    category: 'search_crawler',
    bucket: 'gemini',
    rank: 50,
    which: ['classifier', 'robodex', 'attribution', 'pill'],
    ua: {
      patterns: [/Googlebot\/2\.1/i],
      requireNetworkMatch: true,
      network: /google|googleusercontent/i,
    },
    fcrdnsSuffixes: ['googlebot.com', 'google.com', 'googleusercontent.com'],
    feedIds: ['google-common'],
    minProofForVerified: 'fcrdns',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'googlebot', label: 'Googlebot' },
  },
  {
    id: 'applebot',
    provider: 'Apple',
    displayName: 'Applebot',
    category: 'search_crawler',
    bucket: 'apple',
    rank: 60,
    which: ['classifier', 'robodex', 'attribution', 'pill'],
    ua: {
      patterns: [/Applebot\/0\.1/i],
      requireNetworkMatch: true,
      network: /apple/i,
    },
    fcrdnsSuffixes: ['applebot.apple.com'],
    feedIds: ['applebot'],
    minProofForVerified: 'fcrdns',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'applebot', label: 'Applebot' },
  },
  {
    id: 'gptbot',
    provider: 'OpenAI',
    displayName: 'GPTBot',
    category: 'ai_crawler',
    bucket: 'openai',
    rank: 70,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/GPTBot\/1\./i, /\bGPTBot\b/i] },
    feedIds: ['gptbot'],
    minProofForVerified: 'cidr',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'gptbot', label: 'GPTBot' },
  },
  {
    id: 'chatgpt_user',
    provider: 'OpenAI',
    displayName: 'ChatGPT-User',
    category: 'ai_assistant',
    bucket: 'openai',
    rank: 80,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/ChatGPT-User\/1\.0/i] },
    feedIds: ['chatgpt-user'],
    minProofForVerified: 'cidr',
    executionMode: 'User-Triggered Fetcher',
    pill: { kind: 'chatgpt_user', label: 'ChatGPT-User' },
  },
  {
    id: 'oai_search_bot',
    provider: 'OpenAI',
    displayName: 'OAI-SearchBot',
    category: 'ai_search',
    bucket: 'openai',
    rank: 90,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/OAI-SearchBot\/1\./i, /\bOAI-SearchBot\b/i] },
    feedIds: ['searchbot'],
    minProofForVerified: 'cidr',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'oai_search_bot', label: 'OAI-SearchBot' },
  },
  {
    id: 'claude_bot',
    provider: 'Anthropic',
    displayName: 'ClaudeBot',
    category: 'ai_crawler',
    bucket: 'claude',
    rank: 100,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/\bClaudeBot\b/i] },
    fcrdnsSuffixes: ['anthropic.com', 'claude.ai'],
    feedIds: ['claude'],
    minProofForVerified: 'cidr',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'claude_bot', label: 'ClaudeBot' },
  },
  {
    id: 'claude_user',
    provider: 'Anthropic',
    displayName: 'Claude-User',
    category: 'ai_assistant',
    bucket: 'claude',
    rank: 110,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/Claude-User/i] },
    feedIds: ['claude'],
    minProofForVerified: 'cidr',
    executionMode: 'User-Triggered Fetcher',
    pill: { kind: 'claude_user', label: 'Claude-User' },
  },
  {
    id: 'claude_search_bot',
    provider: 'Anthropic',
    displayName: 'Claude-SearchBot',
    category: 'ai_search',
    bucket: 'claude',
    rank: 120,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/Claude-SearchBot/i] },
    feedIds: ['claude'],
    minProofForVerified: 'cidr',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'claude_search_bot', label: 'Claude-SearchBot' },
  },
  {
    id: 'claude_agent',
    provider: 'Anthropic',
    displayName: 'Claude Agent',
    category: 'ai_agent',
    bucket: 'claude',
    rank: 130,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/Claude-Agent\/1\.0/i] },
    signature: {
      sail: true,
      agentHosts: ['claude.com'],
      keyIdNeedles: ['claude', 'anthropic', 'sail'],
    },
    feedIds: ['claude-agent-sail'],
    minProofForVerified: 'signed_agent',
    executionMode: 'RFC 9421 Signed Agent',
    pill: { kind: 'claude', label: 'Claude Agent' },
  },
  {
    id: 'perplexity_bot',
    provider: 'Perplexity',
    displayName: 'PerplexityBot',
    category: 'ai_search',
    bucket: 'perplexity',
    rank: 140,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/PerplexityBot\/1\.0/i, /\bPerplexityBot\b/i] },
    feedIds: ['perplexitybot'],
    minProofForVerified: 'cidr',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'perplexity_bot', label: 'PerplexityBot' },
  },
  {
    id: 'perplexity_user',
    provider: 'Perplexity',
    displayName: 'Perplexity-User',
    category: 'ai_assistant',
    bucket: 'perplexity',
    rank: 150,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/Perplexity-User\/1\.0/i, /\bPerplexity-User\b/i] },
    feedIds: ['perplexity-user'],
    minProofForVerified: 'cidr',
    executionMode: 'User-Triggered Fetcher',
    pill: { kind: 'perplexity_user', label: 'Perplexity-User' },
  },
  {
    id: 'amazonbot',
    provider: 'Amazon',
    displayName: 'Amazonbot',
    category: 'ai_crawler',
    bucket: 'amazon',
    rank: 160,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/Amazonbot\/0\.1/i, /\bAmazonbot\b/i] },
    feedIds: ['amazonbot'],
    minProofForVerified: 'cidr',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'amazonbot', label: 'Amazonbot' },
  },
  {
    id: 'amzn_search_bot',
    provider: 'Amazon',
    displayName: 'Amzn-SearchBot',
    category: 'ai_search',
    bucket: 'amazon',
    rank: 170,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/Amzn-SearchBot\/0\.1/i] },
    // Dedicated official sibling feed (searchbot-ip-addresses).
    feedIds: ['amzn-search-bot'],
    minProofForVerified: 'cidr',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'amazonbot', label: 'Amzn-SearchBot' },
  },
  {
    id: 'amzn_user',
    provider: 'Amazon',
    displayName: 'Amzn-User',
    category: 'ai_assistant',
    bucket: 'amazon',
    rank: 180,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/Amzn-User\/0\.1/i] },
    feedIds: ['amzn-user'],
    minProofForVerified: 'cidr',
    executionMode: 'User-Triggered Fetcher',
    pill: { kind: 'amazonbot', label: 'Amzn-User' },
  },
  {
    id: 'bingbot',
    provider: 'Microsoft',
    displayName: 'Bingbot',
    category: 'search_crawler',
    bucket: 'microsoft',
    rank: 190,
    which: ['classifier', 'robodex', 'attribution', 'pill'],
    ua: {
      patterns: [/bingbot\/2\.0/i, /\bbingbot\b/i],
      requireNetworkMatch: true,
      network: /microsoft|bing|msn/i,
    },
    fcrdnsSuffixes: ['search.msn.com'],
    feedIds: ['bingbot'],
    minProofForVerified: 'fcrdns',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'bingbot', label: 'Bingbot' },
  },
  {
    id: 'ccbot',
    provider: 'Common Crawl',
    displayName: 'CCBot',
    category: 'ai_crawler',
    bucket: 'commoncrawl',
    rank: 200,
    which: ['robodex', 'attribution', 'pill'],
    ua: { patterns: [/\bCCBot\b/i] },
    feedIds: ['ccbot'],
    minProofForVerified: 'cidr',
    executionMode: 'Autonomous Crawler',
    pill: { kind: 'automation', label: 'CCBot' },
  },
  /* ---- Legacy directory agents preserved from the pre-registry bot directory ----
     These were previously detected by BOT_DIRECTORY. Keeping them in the single registry
     avoids losing coverage while adding the newly verified crawler catalog above. */
  {
    id: 'chatgpt_agent',
    provider: 'OpenAI',
    displayName: 'ChatGPT Agent',
    category: 'ai_agent',
    bucket: 'openai',
    rank: 805,
    which: ['robodex'],
    ua: { patterns: [/ChatGPT-Agent/i] },
    asnPatterns: [/openai|azure/i],
    minProofForVerified: 'ua_claim',
    executionMode: 'Cloud Browser Agent',
  },
  {
    id: 'codex',
    provider: 'OpenAI',
    displayName: 'Codex',
    category: 'ai_agent',
    bucket: 'openai',
    rank: 806,
    which: ['robodex'],
    ua: { patterns: [/\bCodex\b/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Coding Agent',
  },
  {
    id: 'gemini_deep_research',
    provider: 'Google',
    displayName: 'Gemini Deep Research',
    category: 'ai_agent',
    bucket: 'gemini',
    rank: 807,
    which: ['robodex'],
    ua: { patterns: [/Gemini-Deep-Research|GoogleAgent-Mariner|Mariner|Google-Agent/i] },
    asns: [15169, 396982],
    asnPatterns: [/google llc|google cloud/i],
    minProofForVerified: 'allowlist',
    executionMode: 'User-Triggered Fetcher',
  },
  {
    id: 'google_agent',
    provider: 'Google',
    displayName: 'Google-Agent',
    category: 'ai_agent',
    bucket: 'gemini',
    rank: 808,
    which: ['robodex'],
    ua: { patterns: [/Google-Agent/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'User-Triggered Fetcher',
  },
  {
    id: 'google_notebooklm',
    provider: 'Google',
    displayName: 'Google NotebookLM',
    category: 'ai_assistant',
    bucket: 'gemini',
    rank: 809,
    which: ['robodex'],
    ua: { patterns: [/NotebookLM/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'User-Triggered Fetcher',
  },
  {
    id: 'claude_code',
    provider: 'Anthropic',
    displayName: 'Claude Code',
    category: 'ai_agent',
    bucket: 'claude',
    rank: 810,
    which: ['robodex'],
    ua: { patterns: [/Claude Code|claude-code/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Coding Agent',
  },
  {
    id: 'claude_duet',
    provider: 'Anthropic',
    displayName: 'Claude Duet',
    category: 'ai_agent',
    bucket: 'claude',
    rank: 811,
    which: ['robodex'],
    ua: { patterns: [/Claude-Duet|claude-duet/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Cloud Browser Agent',
  },
  {
    id: 'meta_muse',
    provider: 'Meta',
    displayName: 'Muse',
    category: 'ai_agent',
    bucket: 'muse',
    rank: 812,
    which: ['robodex'],
    ua: { patterns: [/\bMuse\b/i] },
    asns: [32934],
    asnPatterns: [/meta platforms/i],
    minProofForVerified: 'allowlist',
    executionMode: 'Cloud Browser Agent',
  },
  {
    id: 'meta_external_agent',
    provider: 'Meta',
    displayName: 'Meta-ExternalAgent',
    category: 'ai_search',
    bucket: 'muse',
    rank: 813,
    which: ['robodex'],
    ua: { patterns: [/Meta-ExternalAgent|meta-externalagent/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Autonomous Crawler',
  },
  {
    id: 'meta_web_indexer',
    provider: 'Meta',
    displayName: 'Meta-WebIndexer',
    category: 'ai_search',
    bucket: 'muse',
    rank: 814,
    which: ['robodex'],
    ua: { patterns: [/Meta-WebIndexer/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Autonomous Crawler',
  },
  {
    // RFC 9421 Web Bot Auth signed agent. Exact token matches only; higher priority than the
    // unsigned grok_bot claim so a signed GrokAgent resolves to this entry first.
    id: 'grok_agent',
    provider: 'xAI',
    displayName: 'Grok Bot',
    category: 'ai_agent',
    bucket: 'grok',
    rank: 814,
    which: ['classifier', 'robodex', 'attribution', 'pill'],
    ua: { patterns: [/GrokAgent/i, /\bxAI-SearchBot\/1\.0\b/i, /Grok-DeepSearch/i, /Grok-Search/i] },
    signature: {
      wbaRequired: true,
      agentHosts: ['cursorusercontent.com'],
      keyIdNeedles: ['Vuxu4khgzIe0b30Nd6hq2envAuVBFMTDqorSNIUb_Oo'],
    },
    feedIds: ['grok-wba'],
    minProofForVerified: 'signed_agent',
    executionMode: 'RFC 9421 Signed Agent',
    pill: { kind: 'grok', label: 'Grok Bot' },
  },
  {
    // Unsigned UA claim only: no ASN / network corroboration is assumed for xAI traffic.
    // The GrokBot token is version-anchored: the reported xAI crawler string is
    // `Mozilla/5.0 (compatible; GrokBot/1.0; +x.ai/)`. A bare `GrokBot` substring is
    // deliberately NOT accepted — it false-positives on third-party UAs such as
    // `news-tracker/1.0 (...mail.grokbot.com)` and `GrokBot-ArticleSaver/1.0`.
    id: 'grok_bot',
    provider: 'xAI',
    displayName: 'Grok Bot',
    category: 'ai_agent',
    bucket: 'grok',
    rank: 815,
    which: ['robodex'],
    ua: { patterns: [/\bGrokBot\/\d/i, /\bxAI-GrokBot\b/i, /\bxAI-Bot\b/i, /GrokAgent/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Cloud Browser Agent',
  },
  {
    id: 'browserbase_agent',
    provider: 'Browserbase',
    displayName: 'Browserbase Agent',
    category: 'ai_agent',
    bucket: 'cloud-browser',
    rank: 816,
    which: ['robodex'],
    ua: { patterns: [/Browserbase/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Cloud Browser Agent',
  },
  {
    id: 'bedrock_agentcore',
    provider: 'AWS',
    displayName: 'Bedrock AgentCore',
    category: 'ai_agent',
    bucket: 'none',
    rank: 817,
    which: ['robodex'],
    ua: { patterns: [/BedrockAgentCore|bedrock-agent/i] },
    asns: [16509, 14618],
    minProofForVerified: 'allowlist',
    executionMode: 'Cloud Browser Agent',
  },
  {
    id: 'anchor_browser',
    provider: 'Anchor',
    displayName: 'Anchor Browser',
    category: 'ai_browser',
    bucket: 'cloud-browser',
    rank: 818,
    which: ['robodex'],
    ua: { patterns: [/AnchorBrowser|anchor-browser/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Cloud Browser Agent',
  },
  {
    id: 'notte_browser',
    provider: 'Notte',
    displayName: 'Notte Browser',
    category: 'ai_browser',
    bucket: 'cloud-browser',
    rank: 819,
    which: ['robodex'],
    ua: { patterns: [/NotteBrowser|\bnotte\b/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Cloud Browser Agent',
  },
  {
    id: 'agi_agent',
    provider: 'AGI Inc',
    displayName: 'AGI Agent',
    category: 'ai_agent',
    bucket: 'none',
    rank: 820,
    which: ['robodex'],
    ua: { patterns: [/AGIAgent|agi-agent/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Cloud Browser Agent',
  },
  {
    id: 'cursor_agent',
    provider: 'Anysphere',
    displayName: 'Cursor',
    category: 'ai_agent',
    bucket: 'none',
    rank: 821,
    which: ['robodex'],
    ua: { patterns: [/\bCursor\b/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Coding Agent',
  },
  {
    id: 'duck_assist_bot',
    provider: 'DuckDuckGo',
    displayName: 'DuckAssistBot',
    category: 'ai_assistant',
    bucket: 'none',
    rank: 822,
    which: ['robodex'],
    ua: { patterns: [/DuckAssistBot/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'User-Triggered Fetcher',
  },
  {
    id: 'kimi_user',
    provider: 'Moonshot AI',
    displayName: 'Kimi-User',
    category: 'ai_assistant',
    bucket: 'none',
    rank: 823,
    which: ['robodex'],
    ua: { patterns: [/Kimi-User/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'User-Triggered Fetcher',
  },
  {
    id: 'cloudflare_browser_rendering',
    provider: 'Cloudflare',
    displayName: 'Cloudflare Browser Rendering',
    category: 'browser_automation',
    bucket: 'cloud-browser',
    rank: 824,
    which: ['robodex'],
    ua: { patterns: [/CloudflareBot|cf-browser/i] },
    asns: [13335],
    minProofForVerified: 'allowlist',
    executionMode: 'Cloud Browser Agent',
  },
  {
    id: 'instinct',
    provider: 'Spear Street Technology',
    displayName: 'Instinct',
    category: 'ai_agent',
    bucket: 'none',
    rank: 825,
    which: ['robodex'],
    ua: { patterns: [/\bInstinct\b/i] },
    minProofForVerified: 'ua_claim',
    executionMode: 'Cloud Browser Agent',
  },
  {
    // Policy tokens are robots.txt directives, never HTTP user agents. They never visit.
    id: 'google_extended',
    provider: 'Google',
    displayName: 'Google-Extended',
    category: 'policy_token',
    bucket: 'gemini',
    rank: 900,
    which: [],
    ua: { patterns: [/Google-Extended/i] },
    feedIds: ['google-extended'],
    minProofForVerified: 'ua_claim',
    policyToken: true,
  },
  {
    id: 'applebot_extended',
    provider: 'Apple',
    displayName: 'Applebot-Extended',
    category: 'policy_token',
    bucket: 'apple',
    rank: 901,
    which: [],
    ua: { patterns: [/Applebot-Extended/i] },
    feedIds: ['applebot-extended'],
    minProofForVerified: 'ua_claim',
    policyToken: true,
  },
] as const satisfies readonly AgentDef[];

/** Literal union of every catalog id. */
export type AgentId = (typeof REGISTRY_LITERAL)[number]['id'];

/** The catalog, widened to AgentDef so optional fields are accessible in derived views. */
export const AGENT_REGISTRY: readonly AgentDef[] = REGISTRY_LITERAL;

export const AGENT_BY_ID: Record<string, AgentDef> = Object.fromEntries(
  AGENT_REGISTRY.map((agent) => [agent.id, agent])
) as Record<string, AgentDef>;

/* -------------------------------------------------------------------------- */
/* Derived legacy-compatible views                                             */
/* -------------------------------------------------------------------------- */

export interface GoodBotUaRule {
  pattern: RegExp;
  provider: string;
  label: string;
  category?: string;
  network?: RegExp;
}

export interface AiAgentUaRule {
  pattern: RegExp;
  provider: string;
  label: string;
}

export interface BotDirectoryViewEntry {
  name: string;
  provider: string;
  category: string;
  identity: 'verified' | 'signed' | 'unknown' | 'spoofed';
  uaPatterns?: RegExp[];
  asnNumbers?: number[];
  asnPatterns?: RegExp[];
  headerPatterns?: { header: string; pattern: RegExp }[];
  requiresWebBotAuth?: boolean;
}

export interface PillView {
  kind: PillKind;
  label: string;
  provider: string;
}

/** Verified-only crawler rules: a UA claim is accepted only from the declared network. */
export const GOOD_BOT_UA_RULES: GoodBotUaRule[] = AGENT_REGISTRY.flatMap((agent) => {
  if (!agent.ua?.requireNetworkMatch) return [];
  return agent.ua.patterns.map((pattern) => ({
    pattern,
    provider: agent.provider,
    label: agent.displayName,
    category: agent.category,
    network: agent.ua?.network,
  }));
});

/** Named AI-agent UA rules (every non-policy, non-search-crawler catalog entry). */
export const AI_AGENT_UA_RULES: AiAgentUaRule[] = AGENT_REGISTRY.flatMap((agent) => {
  if (agent.policyToken || !agent.category.startsWith('ai_') && agent.category !== 'autonomous_agent' && agent.category !== 'browser_automation') {
    return [];
  }
  if (!agent.ua) return [];
  return agent.ua.patterns.map((pattern) => ({
    pattern,
    provider: agent.provider,
    label: agent.displayName,
  }));
});

/** Signature key-id needle → provider, for Web Bot Auth / RFC 9421 resolution. */
export const BOT_SIGNATURE_KEYID_PROVIDERS: [string, string][] = AGENT_REGISTRY.flatMap((agent) =>
  (agent.signature?.keyIdNeedles ?? []).map((needle) => [needle, agent.provider] as [string, string])
);

/** Every live CIDR-capable prefix source (excludes policy tokens, 'none' and WBA directories). */
export const AI_BOT_CIDR_SOURCES: { id: string; url: string }[] = PREFIX_FEEDS.filter(
  (feed) => feed.format !== 'none' && feed.format !== 'wba-directory'
).map((feed) => ({ id: feed.sourceId, url: feed.url }));

/** FCrDNS suffixes keyed by agent id. */
export const VERIFICATION_SUFFIXES_BY_AGENT: Record<string, string[]> = Object.fromEntries(
  AGENT_REGISTRY.filter((agent) => agent.fcrdnsSuffixes).map((agent) => [agent.id, [...agent.fcrdnsSuffixes!]])
);

function identityFor(agent: AgentDef): 'verified' | 'signed' | 'unknown' {
  switch (agent.minProofForVerified) {
    case 'cidr':
    case 'fcrdns':
    case 'allowlist':
      return 'verified';
    case 'rfc9421':
    case 'signed_agent':
      return 'signed';
    default:
      return 'unknown';
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Structurally compatible with BotDirectoryEntry in aiBotDirectory.ts. */
export const BOT_DIRECTORY: BotDirectoryViewEntry[] = AGENT_REGISTRY.filter((agent) =>
  agent.which.includes('robodex')
).map((agent) => {
  const hosts = agent.signature?.agentHosts ?? [];
  const headerPatterns = hosts.length
    ? [{ header: 'signature-agent', pattern: new RegExp(hosts.map(escapeRegExp).join('|'), 'i') }]
    : undefined;
  return {
    name: agent.displayName,
    provider: agent.provider,
    category: agent.category,
    identity: identityFor(agent),
    uaPatterns: agent.ua ? [...agent.ua.patterns] : undefined,
    asnNumbers: agent.asns ? [...agent.asns] : undefined,
    asnPatterns: agent.asnPatterns ? [...agent.asnPatterns] : undefined,
    requiresWebBotAuth: Boolean(agent.signature?.wbaRequired || agent.signature?.sail),
    headerPatterns,
  };
});

/** Cursor / attribution pills keyed by agent id. */
export const PILLS: Record<string, PillView> = Object.fromEntries(
  AGENT_REGISTRY.filter((agent) => agent.pill).map((agent) => [
    agent.id,
    {
      kind: agent.pill!.kind,
      label: agent.pill!.label || agent.displayName,
      provider: agent.provider,
    },
  ])
);

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

/** Agents sorted by ascending rank — lower rank wins (more specific). */
const BY_RANK: readonly AgentDef[] = [...AGENT_REGISTRY].sort((a, b) => a.rank - b.rank);
const POLICY_TOKENS: readonly AgentDef[] = AGENT_REGISTRY.filter((agent) => agent.policyToken);

function matchesUa(agent: AgentDef, ua: string): boolean {
  if (!agent.ua) return false;
  for (const pattern of agent.ua.patterns) {
    // Patterns are declared with /i and no /g; reset lastIndex for safety.
    pattern.lastIndex = 0;
    if (pattern.test(ua)) return true;
  }
  return false;
}

/**
 * Case-insensitive lookup by User-Agent. Ordered by `rank` ascending; policy tokens are
 * skipped (they are robots.txt directives, never HTTP visits). Returns the most specific
 * (lowest-rank) matching agent, or null.
 */
export function findAgentByUa(ua: string): AgentDef | null {
  const value = typeof ua === 'string' ? ua : '';
  for (const agent of BY_RANK) {
    if (agent.policyToken) continue;
    if (matchesUa(agent, value)) return agent;
  }
  return null;
}

/** True when the supplied token string names a robots.txt policy token. */
export function isPolicyToken(ua: string): boolean {
  const value = typeof ua === 'string' ? ua : '';
  for (const agent of POLICY_TOKENS) {
    if (matchesUa(agent, value)) return true;
  }
  return false;
}

export interface AgentDisplay {
  badge: string;
  name: string;
  provider: string;
  label: string;
}

/**
 * Canonical display for an identified agent and its proof identity. The exact agent name and
 * provider are ALWAYS shown — a failed verification changes only the badge, never the identity.
 */
export function displayFor(
  agent: AgentDef,
  identity: 'verified' | 'signed' | 'unknown' | 'spoofed'
): AgentDisplay {
  const badge =
    identity === 'verified' ? 'Verified'
      : identity === 'signed' ? 'Signed'
        : identity === 'spoofed' ? 'Spoofed'
          : 'Unverified';
  const name = agent.displayName;
  const provider = agent.provider;
  const label = provider ? `${badge} · ${name} · ${provider}` : `${badge} · ${name}`;
  return { badge, name, provider, label };
}

export interface NormalizedFeed {
  prefixes: string[];
  sourceId: string;
  fetchedAt: number;
  creationTime: string | null;
  bytes: number;
  /** Present when a document was rejected or partially parsed (e.g. a bad SAIL prefix). */
  reason?: string;
}

const MAX_FEED_PREFIXES = 5000;
const PREFIX_KEYS = new Set(['ipv4Prefix', 'ipv6Prefix', 'prefix', 'ip_prefix', 'ipv4', 'ipv6']);

function utf8Bytes(body: string): number {
  if (typeof TextEncoder !== 'undefined') {
    try {
      return new TextEncoder().encode(body).length;
    } catch {
      /* fall through */
    }
  }
  return body.length;
}

function isIpv4(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 4 && parts.every(
    (part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255
  );
}

function isIpv6(value: string): boolean {
  if (!value.includes(':') || !/^[0-9a-fA-F:.]+$/.test(value)) return false;
  // At most one compressed-zero run ("::"); everything else is checked during CIDR parsing.
  return value.split('::').length <= 2;
}

/** Validate a CIDR or bare IP and normalize bare IPv4→/32, bare IPv6→/128. */
function normalizePrefix(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!text) return null;
  const slash = text.lastIndexOf('/');
  if (slash >= 0) {
    const ip = text.slice(0, slash);
    const maskText = text.slice(slash + 1);
    if (!/^\d{1,3}$/.test(maskText)) return null;
    const mask = Number(maskText);
    if (isIpv4(ip) && mask >= 0 && mask <= 32) return `${ip}/${mask}`;
    if (isIpv6(ip) && mask >= 0 && mask <= 128) return `${ip}/${mask}`;
    return null;
  }
  if (isIpv4(text)) return `${text}/32`;
  if (isIpv6(text)) return `${text}/128`;
  return null;
}

/** RFC1918 / loopback / link-local / multicast and other non-global IPv4 + IPv6 space. */
function isSpecialPurpose(prefix: string): boolean {
  const slash = prefix.lastIndexOf('/');
  const ip = slash >= 0 ? prefix.slice(0, slash) : prefix;
  if (isIpv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 192 && b === 0) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a >= 224) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  if (/^fe[89ab]/.test(lower)) return true;
  if (/^f[cd]/.test(lower)) return true;
  if (/^ff/.test(lower)) return true;
  return false;
}

/** ISO-8601-ish: accepts optional fractional seconds and optional/absent timezone. */
function isTimestampLike(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?$/.test(value.trim());
}

function creationTimeFromJson(json: unknown): string | null {
  const visited = new Set<object>();
  const visit = (node: unknown): string | null => {
    if (!node || typeof node !== 'object' || visited.has(node as object)) return null;
    visited.add(node as object);
    if (Array.isArray(node)) {
      for (const item of node) {
        const found = visit(item);
        if (found) return found;
      }
      return null;
    }
    const record = node as Record<string, unknown>;
    for (const key of ['creationTime', 'creation_time', 'lastModified', 'modified']) {
      const value = record[key];
      if (typeof value === 'string' && value && isTimestampLike(value)) return value.trim();
    }
    for (const value of Object.values(record)) {
      const found = visit(value);
      if (found) return found;
    }
    return null;
  };
  return visit(json);
}

interface PrefixCollector {
  list: string[];
  seen: Set<string>;
}

function addPrefix(collector: PrefixCollector, raw: unknown): void {
  if (collector.list.length >= MAX_FEED_PREFIXES || typeof raw !== 'string') return;
  const prefix = normalizePrefix(raw);
  if (prefix && !collector.seen.has(prefix)) {
    collector.seen.add(prefix);
    collector.list.push(prefix);
  }
}

/** Recursively harvest prefixes from any feed shape, regardless of key nesting. */
function collectJsonPrefixes(node: unknown, collector: PrefixCollector, visited: Set<object>): void {
  if (!node || typeof node !== 'object' || visited.has(node as object)) return;
  if (collector.list.length >= MAX_FEED_PREFIXES) return;
  visited.add(node as object);
  if (Array.isArray(node)) {
    for (const item of node) {
      if (collector.list.length >= MAX_FEED_PREFIXES) return;
      if (typeof item === 'string') addPrefix(collector, item);
      else collectJsonPrefixes(item, collector, visited);
    }
    return;
  }
  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    if (collector.list.length >= MAX_FEED_PREFIXES) return;
    if (PREFIX_KEYS.has(key) && typeof value === 'string') addPrefix(collector, value);
    else collectJsonPrefixes(value, collector, visited);
  }
}

function parseJsonBody(text: string): unknown {
  // Content-Type is intentionally ignored: official feeds are served as octet-stream too.
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  return JSON.parse(start >= 0 && end > start ? text.slice(start, end + 1) : text);
}

/** Brace-match the JSON object embedded in an HTML <pre><code> feed wrapper. */
function extractEmbeddedJson(text: string): string | null {
  const at = text.search(/creationTime/i);
  if (at < 0) return null;
  const start = text.lastIndexOf('{', at);
  if (start < 0) return null;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}

/**
 * Pure, browser-safe feed normalizer. Dispatches on the source's declared format. Never
 * throws: malformed bodies yield an empty prefix list and, where possible, a reason.
 */
export function normalizeFeed(sourceId: string, body: string, fetchedAt?: number): NormalizedFeed {
  const text = typeof body === 'string' ? body : '';
  const feed = PREFIX_FEEDS.find((entry) => entry.sourceId === sourceId);
  const format = feed?.format ?? 'none';
  const collector: PrefixCollector = { list: [], seen: new Set<string>() };
  let creationTime: string | null = null;
  let reason: string | undefined;

  try {
    if (format === 'json' || format === 'wba-directory') {
      const json = parseJsonBody(text);
      creationTime = creationTimeFromJson(json);
      collectJsonPrefixes(json, collector, new Set<object>());
    } else if (format === 'amazon-html') {
      const embedded = extractEmbeddedJson(text);
      let parsed: unknown = null;
      if (embedded) {
        try {
          parsed = JSON.parse(embedded);
        } catch {
          parsed = null;
        }
      }
      if (parsed) {
        creationTime = creationTimeFromJson(parsed);
        collectJsonPrefixes(parsed, collector, new Set<object>());
      }
      if (collector.list.length === 0) {
        // Fallback: every IPv4-looking token, octet-validated and normalized to /32.
        for (const token of text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []) addPrefix(collector, token);
      }
    } else if (format === 'sail-toml') {
      const modified = text.match(/^\s*modified\s*=\s*["']([^"']+)["']/m);
      if (modified) creationTime = modified[1];
      const lists = text.match(/ipv[46]_prefixes\s*=\s*\[([^\]]*)\]/g) ?? [];
      const local: string[] = [];
      let invalid: string | null = null;
      for (const list of lists) {
        for (const raw of list.match(/["']([^"']+)["']/g) ?? []) {
          const value = raw.replace(/^["']|["']$/g, '');
          const prefix = normalizePrefix(value);
          if (!prefix || isSpecialPurpose(prefix)) {
            invalid = prefix ?? value;
            continue;
          }
          if (!local.includes(prefix)) local.push(prefix);
        }
      }
      if (invalid) {
        // A SAIL document declaring a bad/private prefix is rejected in its entirety.
        reason = `SAIL document rejected: invalid or special-purpose prefix "${invalid}"`;
      } else {
        for (const prefix of local) addPrefix(collector, prefix);
      }
    }
  } catch (error) {
    reason = reason ?? `feed normalization failed: ${error instanceof Error ? error.message : String(error)}`;
    // Keep whatever was parsed before the failure; callers fall back to PINNED_PREFIXES.
  }

  return {
    prefixes: [...collector.list],
    sourceId,
    fetchedAt: typeof fetchedAt === 'number' && Number.isFinite(fetchedAt) ? fetchedAt : Date.now(),
    creationTime,
    bytes: utf8Bytes(text),
    ...(reason ? { reason } : {}),
  };
}

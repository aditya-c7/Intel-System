/**
 * Intel System — pure dual-target UA / Client-Hints normalizer.
 *
 * Pure TypeScript, dual-target (browser + Cloudflare Workers). No Node APIs,
 * no project imports. `normalizeIdentity` is total: it never throws and
 * degrades to an 'Unknown' identity when signals are missing.
 *
 * Source priority:
 *   1. `uaData.fullVersionList` + `uaData.platformVersion` (UA-CH JS API)
 *   2. `secCh` headers ('sec-ch-ua-full-version-list', 'sec-ch-ua-platform', …)
 *   3. UA-string regex fallback
 *
 * Post-normalization invariants (enforced by an internal self-check):
 *   - `browser_major_version` is a non-empty string whenever ANY version
 *     source exists (brands, secCh, or UA regexes).
 *   - `os` never contains digits (family only).
 *   - `os_version` never equals `os`.
 */

/* -------------------------------------------------------------------------- */
/* Public types                                                                */
/* -------------------------------------------------------------------------- */

export interface UaDataHighEntropy {
  architecture?: string;
  bitness?: string;
  formFactors?: string[];
  fullVersionList?: Array<{ brand: string; version: string }>;
  model?: string;
  platform?: string;
  platformVersion?: string;
  uaFullVersion?: string;
  wow64?: boolean;
}

export type PlatformFamily = 'windows' | 'mac' | 'linux' | 'android' | 'ios' | 'unknown';

export type DeviceKind = 'Desktop' | 'Mobile' | 'Tablet' | 'Unknown';

/**
 * P2-17 — headless variant, additive and independent of browser classification.
 *   - 'shell' : `chrome-headless-shell` / `headless_shell` (legacy headless shell binary)
 *   - 'new'   : plain `HeadlessChrome` (modern --headless=new mode)
 *   - null    : no headless signal was present
 */
export type HeadlessMode = 'shell' | 'new' | null;

/**
 * The *runtime* that actually renders the page — distinct from the browser engine.
 * Electron / IDE shells / WebViews embed Chromium, so a UA-CH brand list alone would
 * mislabel them as generic Chromium. Ordered by detection precedence (see
 * `resolveRuntime`).
 */
export type RuntimeKind =
  | 'electron'
  | 'node'
  | 'ide_webview'
  | 'host_app'
  | 'webview'
  | 'browser'
  | 'unknown';

/** Broker-facing classification of the client, derived from `RuntimeKind`. */
export type ClientType =
  | 'desktop_app'
  | 'node'
  | 'ide_shell'
  | 'host_app'
  | 'webview'
  | 'browser'
  | 'unknown';

/**
 * Host-runtime signals that cannot be derived from the UA string alone.
 * Electron exposes `window.process.versions`; the collector reads those values and
 * passes them here. Every field is optional so pure browser callers stay unchanged.
 */
export interface RuntimeSignals {
  /** `process.versions.electron` when the renderer is Electron. */
  electronVersion?: string;
  /** `process.versions.node` when a Node/Electron runtime is present. */
  nodeVersion?: string;
  /** Raw `process.versions` bag (Electron/Node expose this to the renderer). */
  processVersions?: Record<string, string | undefined> | null;
  /** Explicit host-application name (e.g. 'Slack', 'Cursor'). */
  hostApp?: string;
  /** Explicit IDE-shell name (e.g. 'vscode', 'cursor'). */
  ideShell?: string;
  /** True when the collector knows the page is hosted in a WebView. */
  webView?: boolean;
}

export interface NormalizedIdentity {
  os: string;
  os_version: string;
  browser_name: string;
  browser_major_version: string;
  browser_full_version: string;
  device: DeviceKind;
  device_model: string;
  architecture: string;
  bitness: string;
  platformFamily: PlatformFamily;
  /** True when the selected browser came from the HeadlessChrome UA-CH brand. */
  is_headless_brand?: boolean;
  /** Headless variant ('shell' | 'new' | null). Additive field (P2-17). */
  headless_mode?: HeadlessMode;
  /** Host runtime that renders the page (engine-independent). Additive field. */
  runtime?: RuntimeKind;
  /** Host application name when the runtime is an Electron/IDE/WebView shell. */
  host_app?: string;
  /** Broker-facing client classification derived from `runtime`. */
  client_type?: ClientType;
  /** Normalized `Sec-CH-UA-Form-Factors` / UAData `formFactors` values. */
  form_factors?: string[];
  /** True when `Sec-CH-UA-Wow64` / UAData `wow64` reports a 32-bit process on 64-bit OS. */
  wow64?: boolean;
}

export interface NormalizeIdentityInput {
  userAgent?: string;
  platform?: string;
  maxTouchPoints?: number;
  uaData?: UaDataHighEntropy | null;
  secCh?: Record<string, string>;
  /** Host-runtime signals collected from the Electron/Node environment. */
  runtime?: RuntimeSignals | null;
  /** Flat aliases accepted for convenience (map onto `runtime`). */
  electronVersion?: string;
  nodeVersion?: string;
  processVersions?: Record<string, string | undefined> | null;
  hostApp?: string;
  ideShell?: string;
  webView?: boolean;
}

/* -------------------------------------------------------------------------- */
/* Internal helpers — parsing                                                  */
/* -------------------------------------------------------------------------- */

export interface BrandEntry {
  brand: string;
  version: string;
  /** True when this entry is the `HeadlessChrome` UA-CH brand. */
  is_headless_brand?: boolean;
}

interface SecChHints {
  brands: BrandEntry[];
  /** True when the full-version-list header was present (vs major-only). */
  hasFullVersionList: boolean;
  platform: string;
  platformVersion: string;
  model: string;
  architecture: string;
  bitness: string;
  formFactors: string[];
  /** Parsed `Sec-CH-UA-Wow64` (true only for `?1` / `1` / `true`). */
  wow64: boolean;
}

/** GREASE brand filter, per UA-CH spec ('Not.A/Brand', 'Not/A)Brand', …). */
export const GREASE_RE = /not.?a.?brand/i;

const CHROMIUM_PLACEHOLDER = 'chromium';

/**
 * Explicit headless-Chromium tokens. Besides the legacy `HeadlessChrome` UA
 * token/brand, `chrome-headless-shell` also advertises itself as
 * `headless_shell`. Both are concrete browser identities, not generic Chrome.
 */
const HEADLESS_UA_RE = /HeadlessChrome|headless[_-]?shell|chrome[_-]?headless[_-]?shell/i;
const HEADLESS_BRAND_RE = /^(?:headlesschrome|headless[_-]?shell|chrome[_-]?headless[_-]?shell)$/i;
const HEADLESS_VERSION_RE = /(?:HeadlessChrome|headless[_-]?shell|chrome[_-]?headless[_-]?shell)\/([\d.]+)/i;

/**
 * P2-17 — the legacy headless *shell* binary is a distinct product from the
 * modern `HeadlessChrome` (new headless) mode. It advertises itself as
 * `chrome-headless-shell` (UA-CH brand) or `headless_shell` (UA token/brand).
 * These regexes are detection-only and never affect browser resolution.
 */
const HEADLESS_SHELL_UA_RE = /headless[_-]?shell|chrome[_-]?headless[_-]?shell/i;
const HEADLESS_SHELL_BRAND_RE = /^(?:headless[_-]?shell|chrome[_-]?headless[_-]?shell)$/i;

/** Splits an RFC 9651 list on commas that are OUTSIDE quoted strings. */
function splitStructuredList(raw: string): string[] {
  const parts: string[] = [];
  let current = '';
  let inQuotes = false;
  let escaped = false;
  for (const ch of raw) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === '\\' && inQuotes) {
      current += ch;
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      current += ch;
      continue;
    }
    if (ch === ',' && !inQuotes) {
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts;
}

/** Parses one RFC 9651 parameterised list member (bare item + `;name=value` parameters). */
function parseStructuredMember(member: string): { value: string; params: Map<string, string> } | null {
  const text = member.trim();
  if (!text) return null;
  let i = 0;
  let value = '';

  if (text[i] === '"') {
    // Quoted string (the normal UA-CH brand form).
    i += 1;
    let escaped = false;
    let closed = false;
    while (i < text.length) {
      const ch = text[i];
      if (escaped) {
        value += ch;
        escaped = false;
        i += 1;
        continue;
      }
      if (ch === '\\') {
        escaped = true;
        i += 1;
        continue;
      }
      if (ch === '"') {
        closed = true;
        i += 1;
        break;
      }
      value += ch;
      i += 1;
    }
    if (!closed) return null;
  } else {
    // Token form — tolerated for non-conformant emitters.
    while (i < text.length && !/[\s;]/.test(text[i])) {
      value += text[i];
      i += 1;
    }
    if (!value) return null;
  }

  const params = new Map<string, string>();
  while (i < text.length) {
    while (i < text.length && /\s/.test(text[i])) i += 1;
    if (i >= text.length) break;
    if (text[i] !== ';') return null;
    i += 1;
    while (i < text.length && /\s/.test(text[i])) i += 1;
    let key = '';
    while (i < text.length && /[!#$%&'*+\-.^_`|~0-9A-Za-z]/.test(text[i])) {
      key += text[i];
      i += 1;
    }
    if (!key) return null;
    while (i < text.length && /\s/.test(text[i])) i += 1;
    let paramValue = '';
    if (i < text.length && text[i] === '=') {
      i += 1;
      while (i < text.length && /\s/.test(text[i])) i += 1;
      if (text[i] === '"') {
        i += 1;
        let escaped = false;
        let closed = false;
        while (i < text.length) {
          const ch = text[i];
          if (escaped) {
            paramValue += ch;
            escaped = false;
            i += 1;
            continue;
          }
          if (ch === '\\') {
            escaped = true;
            i += 1;
            continue;
          }
          if (ch === '"') {
            closed = true;
            i += 1;
            break;
          }
          paramValue += ch;
          i += 1;
        }
        if (!closed) return null;
      } else {
        while (i < text.length && !/[\s;]/.test(text[i])) {
          paramValue += text[i];
          i += 1;
        }
      }
    }
    params.set(key.toLowerCase(), paramValue);
  }

  return { value, params };
}

/**
 * Canonical RFC 9651 structured-field parser for `Sec-CH-UA` /
 * `Sec-CH-UA-Full-Version-List` brand lists, e.g.
 * `"Chromium";v="126", "Not/A)Brand";v="24", "Google Chrome";v="126"`.
 *
 * This is the ONE brand-list parser in the project: the Express client-hints
 * middleware re-exports it. Never use a bare regex where structured fields are
 * available — commas and escaped quotes inside brand names break those.
 */
export function parseBrandList(raw: string): BrandEntry[] {
  const out: BrandEntry[] = [];
  if (typeof raw !== 'string' || !raw.trim()) return out;
  for (const member of splitStructuredList(raw)) {
    const parsed = parseStructuredMember(member);
    if (!parsed) continue;
    const brand = parsed.value.trim();
    if (!brand) continue;
    const entry: BrandEntry = { brand, version: (parsed.params.get('v') ?? '').trim() };
    if (HEADLESS_BRAND_RE.test(brand)) entry.is_headless_brand = true;
    out.push(entry);
  }
  return out;
}

/** Removes GREASE brands, then the placeholder 'Chromium' if a real brand exists. */
function filterBrands(brands: BrandEntry[]): BrandEntry[] {
  const real = brands.filter((b) => !GREASE_RE.test(b.brand));
  const nonChromium = real.filter((b) => b.brand.toLowerCase() !== CHROMIUM_PLACEHOLDER);
  return nonChromium.length > 0 ? nonChromium : real;
}

/**
 * Redacted and forged versions are not evidence of a verified browser release:
 *   - reduced UA-CH sends `0.0.0.0` (and other all-zero) placeholders;
 *   - spoofed brand lists use sentinel majors such as `999.0.0.0` / `9999`.
 * Treating either as real would publish `Chrome 999.0.0.0` with a bogus
 * verified major. Rejecting them lets resolution fall back to the UA token and
 * to the GREASE-filtered, genuinely versioned brands.
 */
function isPlaceholderVersion(version: string): boolean {
  if (typeof version !== 'string' || !version.trim()) return false;
  const v = version.trim();
  if (/^0+(?:\.0+)*$/.test(v)) return true;
  const major = v.split('.')[0];
  return /^\d+$/.test(major) && Number(major) >= 999;
}

/** True when a brand list contains at least one non-GREASE, non-placeholder brand. */
function hasRealBrand(brands: BrandEntry[]): boolean {
  return brands.some(
    (b) => !!b && !GREASE_RE.test(b.brand) && !isPlaceholderVersion(b.version),
  );
}

function headerValue(secCh: Record<string, string> | undefined, name: string): string {
  if (!secCh) return '';
  const lower = name.toLowerCase();
  for (const key of Object.keys(secCh)) {
    if (key.toLowerCase() === lower) {
      const v = secCh[key];
      return typeof v === 'string' ? v : '';
    }
  }
  return '';
}

function unquote(value: string): string {
  const v = value.trim();
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) return v.slice(1, -1);
  return v;
}

/**
 * Normalizes the structured boolean used by UA-CH (`?1` / `?0`) and its common
 * emitter variants (`1`, `0`, `true`, `false`, quoted). Previously `?1` was kept
 * as a raw string and silently lost when compared to a boolean — causing mobile
 * and WoW64 hints to be ignored. Accepts `?1|1|true` (case-insensitive) as true.
 */
export function parseStructuredBoolean(value: unknown): boolean {
  if (value === true) return true;
  if (typeof value === 'number') return value === 1;
  if (typeof value !== 'string') return false;
  const token = value.trim().replace(/^[?"']+|[?"']+$/g, '').toLowerCase();
  return token === '1' || token === 'true';
}

/** `Sec-CH-UA-Mobile ?1` (and `1` / `true`) → boolean `true`, everywhere. */
export const parseMobileFlag = parseStructuredBoolean;

/** `Sec-CH-UA-Wow64 ?1` (and `1` / `true`) → boolean `true`. */
export const parseWow64 = parseStructuredBoolean;

/**
 * Parses a `Sec-CH-UA-Form-Factors` header or UAData `formFactors` array into a
 * clean list of tokens (`Desktop`, `Tablet`, `Mobile`, …). Reuses the canonical
 * brand-list parser so quoted/escaped values behave identically to UA-CH brands.
 */
export function parseFormFactors(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
      .map((v) => v.trim());
  }
  if (typeof value !== 'string' || !value.trim()) return [];
  return parseBrandList(value)
    .map((entry) => entry.brand.trim())
    .filter((brand) => brand.length > 0);
}

function parseSecCh(secCh: Record<string, string> | undefined): SecChHints {
  const fullListRaw = headerValue(secCh, 'sec-ch-ua-full-version-list');
  const majorListRaw = headerValue(secCh, 'sec-ch-ua');
  const brands = fullListRaw ? parseBrandList(fullListRaw) : parseBrandList(majorListRaw);
  return {
    brands: filterBrands(brands),
    hasFullVersionList: Boolean(fullListRaw),
    platform: unquote(headerValue(secCh, 'sec-ch-ua-platform')),
    platformVersion: unquote(headerValue(secCh, 'sec-ch-ua-platform-version')),
    model: unquote(headerValue(secCh, 'sec-ch-ua-model')),
    architecture: unquote(headerValue(secCh, 'sec-ch-ua-arch')),
    bitness: unquote(headerValue(secCh, 'sec-ch-ua-bitness')),
    formFactors: parseFormFactors(headerValue(secCh, 'sec-ch-ua-form-factors')),
    wow64: parseWow64(headerValue(secCh, 'sec-ch-ua-wow64')),
  };
}

/**
 * P2-17 — derives the headless variant straight from the raw signals, so it is
 * fully additive: it neither reads nor influences `resolveBrowser`. A shell
 * token in the UA or in either brand list wins over a plain HeadlessChrome
 * token; without any headless signal the result is `null`.
 */
function resolveHeadlessMode(
  ua: string,
  uad: UaDataHighEntropy | null,
  secCh: SecChHints,
): HeadlessMode {
  const brands = [...(uad?.fullVersionList ?? []), ...secCh.brands];
  const isShell =
    HEADLESS_SHELL_UA_RE.test(ua) ||
    brands.some((b) => !!b && HEADLESS_SHELL_BRAND_RE.test(b.brand));
  if (isShell) return 'shell';
  const isHeadless =
    HEADLESS_UA_RE.test(ua) ||
    brands.some((b) => !!b && HEADLESS_BRAND_RE.test(b.brand));
  return isHeadless ? 'new' : null;
}

/* -------------------------------------------------------------------------- */
/* Internal helpers — browser brand catalog                                    */
/* -------------------------------------------------------------------------- */

interface BrowserSpec {
  /** Canonical output name. */
  name: string;
  /** Lowercase brand strings (from brands lists) that map to this browser. */
  brands: string[];
  /** UA-string tokens with capture group 1 = version. Checked in order. */
  uaTokens: RegExp[];
}

/**
 * Brand priority (highest first). Electron is handled first: it is a distinct runtime and
 * its `Electron/<version>` UA token outranks the embedded Chromium engine brand. Firefox/
 * Safari sit last because they do not send UA-CH and are only detectable from the UA string.
 * 'Cursor' and 'Manus-User' are AI-agent Chromium forks detected from their UA tokens —
 * they are listed first in the UA regex fallback chain (per spec ordering).
 *
 * Additive modern-browser coverage: Arc and Vivaldi are Chromium forks whose UA carries
 * `Arc/<ver>` / `Vivaldi/<ver>` next to `Chrome/<ver>`; they must be scanned BEFORE the
 * generic Google Chrome / Chromium specs or they would be mislabelled as Chrome. Crawler
 * and AI-agent tokens (Googlebot, GPTBot, ClaudeBot, …) are likewise placed ahead of
 * Google Chrome: several of their UAs embed a `Chrome/<ver>` token but name the agent
 * later in the string. Bots do not emit UA-CH brands, so they are UA-token-only specs
 * (`brands: []`) and intentionally never participate in the brand ladder.
 */
const BROWSER_SPECS: BrowserSpec[] = [
  {
    // Electron is a distinct binary/runtime (it embeds Chromium), not the engine version.
    // Its UA carries `Electron/<version>` alongside `Chrome/<version>`; the Electron token
    // must win over the generic Chromium/Chrome tokens so an Electron 44.9.1 session is
    // labelled `Electron 44.9.1` instead of the embedded `Chromium 152`.
    name: 'Electron',
    brands: ['electron'],
    uaTokens: [/Electron\/([\d.]+)/i],
  },
  {
    name: 'Cursor',
    brands: ['cursor'],
    uaTokens: [/Cursor\/([\d.]+)/],
  },
  {
    name: 'Manus',
    brands: ['manus'],
    uaTokens: [/Manus-User\/([\d.]+)/],
  },
  {
    name: 'Microsoft Edge',
    brands: ['microsoft edge'],
    uaTokens: [/EdgA?\/([\d.]+)/, /EdgiOS\/([\d.]+)/, /Edge\/([\d.]+)/],
  },
  {
    name: 'Opera',
    brands: ['opera', 'opera gx'],
    uaTokens: [/OPR\/([\d.]+)/, /OPX\/([\d.]+)/],
  },
  {
    name: 'Brave',
    brands: ['brave'],
    uaTokens: [/Brave\/([\d.]+)/],
  },
  {
    name: 'Samsung Internet',
    brands: ['samsung internet'],
    uaTokens: [/SamsungBrowser\/([\d.]+)/],
  },
  {
    name: 'Headless Chrome',
    brands: ['headlesschrome', 'headless_shell', 'chrome-headless-shell'],
    uaTokens: [HEADLESS_VERSION_RE],
  },
  {
    // Chromium fork: UA ends with `… Chrome/<ver> Safari/<ver> Arc/<ver>`.
    name: 'Arc',
    brands: ['arc'],
    uaTokens: [/Arc\/([\d.]+)/],
  },
  {
    // Chromium fork: UA ends with `… Chrome/<ver> Safari/<ver> Vivaldi/<ver>`.
    name: 'Vivaldi',
    brands: ['vivaldi'],
    uaTokens: [/Vivaldi\/([\d.]+)/],
  },
  {
    // Search crawler. Smartphone Googlebot UAs also carry a `Chrome/<ver>` token,
    // so this spec must precede Google Chrome in the UA regex scan.
    name: 'Googlebot',
    brands: [],
    uaTokens: [/Googlebot\/([\d.]+)/, /Googlebot-Mobile\/([\d.]+)/, /Googlebot-Image\/([\d.]+)/],
  },
  {
    name: 'GPTBot',
    brands: [],
    uaTokens: [/GPTBot\/([\d.]+)/],
  },
  {
    name: 'ChatGPT-User',
    brands: [],
    uaTokens: [/ChatGPT-User\/([\d.]+)/],
  },
  {
    name: 'OAI-SearchBot',
    brands: [],
    uaTokens: [/OAI-SearchBot\/([\d.]+)/],
  },
  {
    name: 'ClaudeBot',
    brands: [],
    /* Anthropic also emits the lowercase `claudebot/<ver>` spelling. */
    uaTokens: [/ClaudeBot\/([\d.]+)/i],
  },
  {
    name: 'Claude-User',
    brands: [],
    uaTokens: [/Claude-User\/([\d.]+)/],
  },
  {
    name: 'Claude-SearchBot',
    brands: [],
    uaTokens: [/Claude-SearchBot\/([\d.]+)/],
  },
  {
    name: 'PerplexityBot',
    brands: [],
    uaTokens: [/PerplexityBot\/([\d.]+)/],
  },
  {
    name: 'Perplexity-User',
    brands: [],
    uaTokens: [/Perplexity-User\/([\d.]+)/],
  },
  {
    name: 'Google Chrome',
    brands: ['google chrome', 'chrome'],
    uaTokens: [/CriOS\/([\d.]+)/, /Chrome\/([\d.]+)/],
  },
  {
    name: 'Chromium',
    brands: [CHROMIUM_PLACEHOLDER],
    /* P2 browser name: a plain `Chrome/<ver>` token belongs to Google Chrome (or
     * to a higher-precedence fork), NEVER to Chromium. Listing `Chrome/` here made
     * every "UA says Chrome" payload a latent Chromium match — the Google Chrome
     * spec happens to mask it today, but any brand/version path that reaches this
     * spec would mislabel a plain Chrome client. Only a genuine bare `Chromium/<ver>`
     * token identifies unbranded Chromium; a Chromium-only UA-CH brand list paired
     * with a plain `Chrome/<ver>` UA token is resolved as Google Chrome instead
     * (see `isUnbrandedChrome`). */
    uaTokens: [/Chromium\/([\d.]+)/],
  },
  {
    name: 'Firefox',
    brands: ['firefox'],
    uaTokens: [/FxiOS\/([\d.]+)/, /Firefox\/([\d.]+)/],
  },
  {
    name: 'Safari',
    brands: ['safari'],
    uaTokens: [/Version\/([\d.]+).*Safari/],
  },
];

function firstMatch(token: RegExp, ua: string): string | null {
  const m = token.exec(ua);
  if (m === null) return null;
  return (m[1] ?? '').trim() || null;
}

/**
 * Deterministic brand precedence for UA-CH brand lists. HeadlessChrome is
 * checked FIRST (it maps to 'Headless Chrome' and carries
 * `is_headless_brand: true`), then Edge, Brave, Opera, Google Chrome and
 * Chromium. Firefox / Safari do not emit UA-CH and remain UA-only fallbacks;
 * the agent tokens (Cursor / Manus) and Samsung Internet follow the listed
 * browsers. This ordering is independent of the UA-regex chain below.
 *
 * Arc and Vivaldi are inserted ahead of Google Chrome so a fork's own UA-CH
 * brand outranks the shared `Google Chrome` / `Chromium` brands when both are
 * present. All pre-existing relative positions are unchanged. Crawler / AI-agent
 * specs are UA-token-only (`brands: []`) and never enter this ladder.
 */
const BRAND_PRECEDENCE: readonly string[] = [
  'Electron',
  'Headless Chrome',
  'Microsoft Edge',
  'Brave',
  'Opera',
  'Arc',
  'Vivaldi',
  'Google Chrome',
  'Chromium',
  'Cursor',
  'Manus',
  'Samsung Internet',
  'Firefox',
  'Safari',
];

/**
 * Picks the spec matching a brand list (case-insensitive) in the canonical
 * BRAND_PRECEDENCE order. Returns null when no brand maps to a known browser.
 */
function brandToSpec(brands: BrandEntry[]): BrowserSpec | null {
  const matched = BROWSER_SPECS.filter((spec) =>
    brands.some((entry) => spec.brands.indexOf(entry.brand.toLowerCase()) !== -1)
  );
  if (matched.length === 0) return null;
  matched.sort((a, b) => {
    const ai = BRAND_PRECEDENCE.indexOf(a.name);
    const bi = BRAND_PRECEDENCE.indexOf(b.name);
    return (ai < 0 ? 999 : ai) - (bi < 0 ? 999 : bi);
  });
  return matched[0];
}

/** UA-only fallback: scan the specs' tokens in priority order. */
function uaToSpec(ua: string): BrowserSpec | null {
  for (const spec of BROWSER_SPECS) {
    for (const token of spec.uaTokens) {
      if (token.test(ua)) return spec;
    }
  }
  return null;
}

/**
 * G35 — a Chromium-only UA-CH brand list (GREASE is meaningless and the list is
 * judged as a unit) paired with a plain `Chrome/<major>` UA token and NO bare
 * `Chromium/<ver>` token describes an unbranded Chrome build, not Chromium.
 * Requiring Chrome to be the top UA match keeps forks (Edge, Opera, …) intact.
 */
function isUnbrandedChrome(brands: BrandEntry[], ua: string): boolean {
  const real = brands.filter((b) => !!b && !GREASE_RE.test(b.brand));
  if (real.length === 0 || !real.every((b) => b.brand.toLowerCase() === CHROMIUM_PLACEHOLDER)) {
    return false;
  }
  if (/Chromium\/([\d.]+)/i.test(ua)) return false;
  if (!/Chrome\/([\d.]+)/i.test(ua)) return false;
  return uaToSpec(ua)?.name === 'Google Chrome';
}

/** Every UA token that could carry a version for the given canonical name. */
function tokensForName(name: string): RegExp[] {
  const spec = BROWSER_SPECS.find((s) => s.name === name);
  if (spec) return spec.uaTokens;
  /* Extra regexes required by the self-check fallback chain. */
  if (name === 'Manus') return [/Manus-User\/([\d.]+)/];
  return [];
}

/**
 * Keeps the version with more dotted segments (4-part full version wins over
 * a major-only token). Ties keep `preferred`. A UA token may only backfill a
 * major-only brand version when its MAJOR matches the brand's: a frozen or
 * spoofed older UA must never downgrade the authoritative sec-ch-ua major.
 */
function pickFullerVersion(preferred: string, candidate: string | null): string {
  if (!candidate) return preferred;
  if (!preferred) return candidate;
  /* Never replace the authoritative brand major with a mismatched UA major. */
  if (majorOf(candidate) !== majorOf(preferred)) return preferred;
  const a = preferred.split('.').length;
  const b = candidate.split('.').length;
  return b > a ? candidate : preferred;
}

interface BrowserResolution {
  name: string;
  full: string;
  major: string;
  is_headless_brand?: boolean;
}

/**
 * Resolves the browser identity. Strategy:
 *   1. uaData.fullVersionList brands (after GREASE/placeholder filtering).
 *   2. secCh brand headers (full list when present, else major-only).
 *   3. UA-string token scan.
 * When the selected brand version is major-only, the full version is backfilled
 * from a UA token of the SAME major when one exists (a mismatched-major UA token
 * is never allowed to downgrade the authoritative brand major).
 */
function resolveBrowser(
  ua: string,
  uad: UaDataHighEntropy | null,
  secCh: SecChHints,
): BrowserResolution {
  const empty: BrowserResolution = { name: 'Unknown', full: '', major: '' };

  /* A genuine Electron runtime always carries the `Electron/<version>` UA token. Electron
   * is the binary/runtime, not the Chromium engine version it happens to embed, so an
   * Electron 44.9.1 session must be labelled `Electron 44.9.1` — never `Chromium 152`.
   * This token is checked FIRST because UA-CH brand lists only describe the embedded
   * engine (and would otherwise be selected ahead of the UA token below). Non-Electron
   * clients keep the existing UA-CH Chromium version resolution unchanged. */
  const electronVersion = firstMatch(/Electron\/([\d.]+)/i, ua);
  if (electronVersion) {
    return { name: 'Electron', full: electronVersion, major: majorOf(electronVersion) };
  }

  const rawUadBrands = (uad?.fullVersionList ?? []).filter((b) => !!b);
  const allBrands = [...rawUadBrands, ...secCh.brands];

  /* An explicit headless token (UA or UA-CH brand) outranks the generic
   * Chromium / Google Chrome brands the very same binary also advertises.
   * Letting the brand ladder run first relabelled headless sessions as
   * 'Google Chrome'. Electron is still handled above, so its precedence is
   * unchanged. */
  if (HEADLESS_UA_RE.test(ua) || allBrands.some((b) => HEADLESS_BRAND_RE.test(b.brand))) {
    const headlessBrand = allBrands.find((b) => HEADLESS_BRAND_RE.test(b.brand));
    let version = firstMatch(HEADLESS_VERSION_RE, ua) ?? '';
    if (isPlaceholderVersion(version)) version = '';
    if (!version && headlessBrand && !isPlaceholderVersion(headlessBrand.version)) {
      version = headlessBrand.version;
    }
    if (!version) {
      /* Only non-placeholder evidence may fill the version of a headless UA
       * whose token carries none. */
      const versionedBrand = allBrands.find(
        (b) => !GREASE_RE.test(b.brand) && !!b.version && !isPlaceholderVersion(b.version),
      );
      version =
        versionedBrand?.version ??
        firstMatch(/CriOS\/([\d.]+)|Chrome\/([\d.]+)/i, ua) ??
        '';
    }
    if (isPlaceholderVersion(version)) version = '';
    return {
      name: 'Headless Chrome',
      full: version,
      major: majorOf(version),
      is_headless_brand: true,
    };
  }

  const uadBrands = filterBrands(rawUadBrands);
  const candidates: Array<{ brands: BrandEntry[]; source: 'uad' | 'secch' }> = [];
  /* A GREASE-only (or all-placeholder) list is NOT evidence of any browser —
   * never promote the `Chromium` placeholder from such a list to browser_name. */
  if (uadBrands.length > 0 && hasRealBrand(rawUadBrands)) {
    candidates.push({ brands: uadBrands, source: 'uad' });
  }
  if (secCh.brands.length > 0 && hasRealBrand(secCh.brands)) {
    candidates.push({ brands: secCh.brands, source: 'secch' });
  }

  for (const candidate of candidates) {
    const spec = brandToSpec(candidate.brands);
    if (!spec) continue;
    const entry = candidate.brands.find(
      (b) => spec.brands.indexOf(b.brand.toLowerCase()) !== -1 && !isPlaceholderVersion(b.version),
    );
    const headlessBrand = Boolean(entry?.is_headless_brand) || spec.name === 'Headless Chrome';
    let version = entry ? entry.version : '';
    if (isPlaceholderVersion(version)) version = '';
    /* Backfill a major-only brand version from the UA token. */
    if (version && version.indexOf('.') === -1) {
      version = pickFullerVersion(version, findUaVersion(spec, ua));
    }
    if (!version) version = findUaVersion(spec, ua) ?? '';
    if (isPlaceholderVersion(version)) version = '';
    const name =
      spec.name === 'Chromium' && isUnbrandedChrome(candidate.brands, ua)
        ? 'Google Chrome'
        : spec.name;
    return { name, full: version, major: majorOf(version), is_headless_brand: headlessBrand };
  }

  /* No usable brand lists — UA token scan. */
  const uaSpec = ua ? uaToSpec(ua) : null;
  if (uaSpec) {
    const version = findUaVersion(uaSpec, ua) ?? '';
    return {
      name: uaSpec.name,
      full: version,
      major: majorOf(version),
      is_headless_brand: uaSpec.name === 'Headless Chrome',
    };
  }

  /* uaFullVersion without a recognizable brand: report major version only.
   * Redacted `0.0.0.0` is not a real version — fall through to Unknown. */
  const uaFull = (uad?.uaFullVersion ?? '').trim();
  if (uaFull && !isPlaceholderVersion(uaFull)) {
    return { name: 'Unknown', full: uaFull, major: majorOf(uaFull) };
  }

  return empty;
}

function findUaVersion(spec: BrowserSpec, ua: string): string | null {
  for (const token of spec.uaTokens) {
    const v = firstMatch(token, ua);
    if (v) return v;
  }
  return null;
}

function majorOf(version: string): string {
  if (!version) return '';
  const major = version.split('.')[0];
  return /^\d+$/.test(major) ? major : '';
}

/**
 * Version sources the self-check considers: brand lists, secCh brand headers,
 * uaFullVersion, or any recognizable UA browser token.
 */
function versionSourceExists(
  ua: string,
  uad: UaDataHighEntropy | null,
  secCh: SecChHints,
): boolean {
  if (hasRealBrand((uad?.fullVersionList ?? []).filter((b) => !!b))) return true;
  const uaFull = (uad?.uaFullVersion ?? '').trim();
  if (uaFull && !isPlaceholderVersion(uaFull)) return true;
  if (hasRealBrand(secCh.brands)) return true;
  return ua ? uaToSpec(ua) !== null : false;
}

/**
 * Last-resort major-version extraction, used only when a version source exists
 * but the primary resolution produced an empty major. The token matching the
 * already-detected browser name is tried first, then the spec fallback chain:
 * Cursor/, Manus-User/, EdgA?/, OPR/, FxiOS/, Firefox/, CriOS/,
 * HeadlessChrome/, Chrome/, Version/…Safari — plus the additive Arc/, Vivaldi/,
 * Googlebot/, GPTBot/, ChatGPT-User/, OAI-SearchBot/, ClaudeBot/, Claude-User/,
 * Claude-SearchBot/, PerplexityBot/ and Perplexity-User/ tokens.
 */
function fallbackMajorFromUa(browserName: string, ua: string): BrowserResolution {
  if (!ua) return { name: browserName, full: '', major: '' };
  const tokens: RegExp[] = [...tokensForName(browserName)];
  for (const spec of BROWSER_SPECS) {
    for (const token of spec.uaTokens) {
      if (tokens.indexOf(token) === -1) tokens.push(token);
    }
  }
  for (const token of tokens) {
    const v = firstMatch(token, ua);
    if (v) return { name: browserName, full: v, major: majorOf(v) };
  }
  return { name: browserName, full: '', major: '' };
}

/* -------------------------------------------------------------------------- */
/* Internal helpers — OS resolution                                            */
/* -------------------------------------------------------------------------- */

interface OsResolution {
  os: string;
  os_version: string;
  platformFamily: PlatformFamily;
  device: DeviceKind;
  device_model: string;
}

function parseIntSafe(value: string): number | null {
  const m = /^\s*(\d+)/.exec(value ?? '');
  if (m === null) return null;
  const n = parseInt(m[1], 10);
  return isFinite(n) ? n : null;
}

/** Windows 11 begins at UA-CH platformVersion major 13 (Windows 10 = 10). */
const WINDOWS_11_PLATFORM_MAJOR = 13;

/** Unified iPadOS multi-touch threshold (a real iPad reports >= 5 touch points). */
const IPAD_TOUCH_THRESHOLD = 5;

/**
 * Windows UA-CH platformVersion → marketing version.
 *   major ≥ 13 → '11'; 1–12 → '10'; 0.1/0.2/0.3 → '7'/'8'/'8.1'; 0.0 → null.
 */
function windowsVersionFromPlatformVersion(pv: string): string | null {
  const parts = (pv ?? '').trim().split('.');
  const major = parseIntSafe(parts[0] ?? '');
  if (major === null) return null;
  if (major >= WINDOWS_11_PLATFORM_MAJOR) return '11';
  if (major >= 1) return '10';
  const sub = parseIntSafe(parts[1] ?? '');
  if (sub === 1) return '7';
  if (sub === 2) return '8';
  if (sub === 3) return '8.1';
  return null;
}

function windowsVersionFromUa(ua: string): string | null {
  const m = /Windows NT ([\d.]+)/.exec(ua);
  if (m === null) return null;
  const nt = m[1];
  if (nt === '6.1') return '7';
  if (nt === '6.2') return '8';
  if (nt === '6.3') return '8.1';
  if (nt === '10.0') return '10';
  return null;
}

function underscoresToDots(v: string): string {
  return v.replace(/_/g, '.');
}

/**
 * Safari UA carries no macOS version. Heuristic (documented): the macOS major
 * tracks the Safari major minus 3 (Safari 18 ⇒ macOS 15, Safari 17 ⇒ 14, …).
 * The formula's output ≤ 10 (Safari ≤ 13, incl. Intel-clamped UAs that hide
 * the real version) is floored at '10.15' — the last 10.x release. Only the
 * major is reliable, so '.0' is used as the minor.
 */
function macVersionFromSafariUa(ua: string): string | null {
  const safari = /Version\/(\d+)(?:\.(\d+))?.*Safari/.exec(ua);
  if (safari === null) return null;
  const safariMajor = parseIntSafe(safari[1] ?? '');
  if (safariMajor === null) return null;
  /* Safari 26 shipped alongside macOS 26 — Apple aligned the version numbers,
   * so the historical `Safari - 3` heuristic would wrongly report macOS 23. */
  const macMajor = safariMajor >= 26 ? safariMajor : safariMajor - 3;
  if (macMajor <= 10) return '10.15';
  return `${macMajor}.0`;
}

function looksAndroidTablet(model: string, formFactors: string[]): boolean {
  if (formFactors.map((f) => f.toLowerCase()).indexOf('tablet') !== -1) return true;
  return /\b(tab|pad|sm-t|nexus 9|nexus 10|pixel c)\b/i.test(model);
}

function androidModelFromUa(ua: string): string {
  const m = /Android[^;)]*;\s*([^;)]+?)\s*(?:Build\/|\))/.exec(ua);
  const raw = m === null ? '' : (m[1] ?? '').trim();
  if (!raw || raw.toLowerCase() === 'wv') return '';
  return raw;
}

function resolveOs(
  ua: string,
  platformStr: string,
  touch: number,
  uad: UaDataHighEntropy | null,
  secCh: SecChHints,
): OsResolution {
  const uadPlatform = (uad?.platform ?? '').trim();
  const uadPv = (uad?.platformVersion ?? '').trim();
  const formFactors = [...(uad?.formFactors ?? []), ...secCh.formFactors];

  /* --- iOS / iPadOS (checked before macOS: iPad UA looks like macOS) ------- */
  const uaIosPhone = /(?:iPhone|iPod)/.test(ua);
  const uaIpad = /iPad/.test(ua);
  /* iPadOS 13+ masquerades as desktop Safari: `Macintosh` UA, `MacIntel` platform and a
   * multi-touch screen. Chrome's UA-CH platform for the same device is `macOS`, so the
   * touch count alone (with a Macintosh UA) is also accepted — unless there is explicit
   * counter-evidence that this is really a Mac: a macOS platform hint with no tablet
   * form factor / model, or a Safari 26+ Version token (Safari 26 runs on macOS 26).
   * Without such evidence (e.g. a bare UA + touch, as in the frozen iPadOS fixture)
   * the iPadOS classification is unchanged. */
  const safariVersionMatch = /(?:^|[\s;])Version\/(\d+)(?:\.[\d.]+)?.*Safari/.exec(ua);
  const safariMajorNumber = safariVersionMatch === null ? null : parseIntSafe(safariVersionMatch[1] ?? '');
  const noTabletFormFactor = !/\btablet\b/i.test(formFactors.join(' '));
  const explicitMacHint =
    (uadPlatform.toLowerCase() === 'macos' || secCh.platform.toLowerCase() === 'macos') &&
    noTabletFormFactor &&
    !(uad?.model ?? '').trim() &&
    !secCh.model;
  const safari26Mac = safariMajorNumber !== null && safariMajorNumber >= 26 && noTabletFormFactor;
  const macTouch =
    touch >= IPAD_TOUCH_THRESHOLD &&
    (/macintel/i.test(platformStr) || /macintosh/i.test(ua)) &&
    !explicitMacHint &&
    !safari26Mac;
  const macTabletFormFactor =
    touch >= IPAD_TOUCH_THRESHOLD &&
    uadPlatform.toLowerCase() === 'macos' &&
    formFactors.map((f) => f.toLowerCase()).indexOf('tablet') !== -1;

  if (uaIosPhone || uaIpad || macTouch || macTabletFormFactor) {
    let osVersion = '';
    const m = /(?:iPhone|iPad|iPod)[\s\S]*?OS (\d+(?:[_\d]*)?)\s+like/.exec(ua);
    if (m !== null && m[1]) {
      osVersion = underscoresToDots(m[1]);
    } else if (macTabletFormFactor && uadPv) {
      osVersion = underscoresToDots(uadPv);
    }
    const device: DeviceKind = uaIpad || macTouch || macTabletFormFactor ? 'Tablet' : 'Mobile';
    return {
      os: 'iOS',
      os_version: osVersion,
      platformFamily: 'ios',
      device,
      device_model: (uad?.model ?? '').trim(),
    };
  }

  /* --- Android (before Linux: Android UAs contain 'Linux') ----------------- */
  if (uadPlatform === 'Android' || secCh.platform === 'Android' || /Android/.test(ua)) {
    let osVersion = '';
    let model = (uad?.model ?? '').trim() || secCh.model;
    if (uadPlatform === 'Android' || secCh.platform === 'Android') {
      const major = parseIntSafe(uadPv || secCh.platformVersion);
      if (major !== null) osVersion = String(major);
    }
    if (!osVersion) {
      const m = /Android\s+([\d.]+)/.exec(ua);
      if (m !== null) osVersion = majorOf(m[1]);
    }
    if (!model) model = androidModelFromUa(ua);
    const device: DeviceKind = looksAndroidTablet(model, formFactors) ? 'Tablet' : 'Mobile';
    return {
      os: 'Android',
      os_version: osVersion,
      platformFamily: 'android',
      device,
      device_model: model,
    };
  }

  /* --- Windows ------------------------------------------------------------- */
  if (uadPlatform === 'Windows' || secCh.platform === 'Windows' || /Windows NT/.test(ua)) {
    let osVersion =
      windowsVersionFromPlatformVersion(uadPv) ??
      windowsVersionFromPlatformVersion(secCh.platformVersion);
    if (!osVersion) osVersion = windowsVersionFromUa(ua);
    return {
      os: 'Windows',
      os_version: osVersion ?? '',
      platformFamily: 'windows',
      device: 'Desktop',
      device_model: '',
    };
  }

  /* --- macOS --------------------------------------------------------------- */
  if (uadPlatform === 'macOS' || secCh.platform === 'macOS' || /Mac OS X|Macintosh/.test(ua)) {
    let osVersion = uadPv || secCh.platformVersion;
    if (!osVersion) {
      const m = /Mac OS X ([\d_]+)/.exec(ua);
      if (m !== null && m[1]) osVersion = underscoresToDots(m[1]);
    }
    if (!osVersion) osVersion = macVersionFromSafariUa(ua) ?? '';
    return {
      os: 'Mac OS X',
      os_version: osVersion,
      platformFamily: 'mac',
      device: 'Desktop',
      device_model: '',
    };
  }

  /* --- Linux / Chrome OS ---------------------------------------------------- */
  if (
    uadPlatform === 'Linux' ||
    uadPlatform === 'Chrome OS' ||
    secCh.platform === 'Linux' ||
    secCh.platform === 'Chrome OS' ||
    /Linux/.test(ua)
  ) {
    let osVersion = '';
    if (uadPlatform === 'Linux' || uadPlatform === 'Chrome OS') {
      const major = parseIntSafe(uadPv);
      if (major !== null) osVersion = String(major);
    } else if (secCh.platform === 'Linux' || secCh.platform === 'Chrome OS') {
      const major = parseIntSafe(secCh.platformVersion);
      if (major !== null) osVersion = String(major);
    }
    return {
      os: 'Linux',
      os_version: osVersion,
      platformFamily: 'linux',
      device: 'Desktop',
      device_model: '',
    };
  }

  /* --- platform-string fallback -------------------------------------------- */
  const p = platformStr.trim();
  if (/^Win(?:dows)?(32|64|NT)?$/i.test(p)) {
    return { os: 'Windows', os_version: '', platformFamily: 'windows', device: 'Desktop', device_model: '' };
  }
  if (/^Mac/i.test(p)) {
    return { os: 'Mac OS X', os_version: '', platformFamily: 'mac', device: 'Desktop', device_model: '' };
  }
  if (/^Linux/i.test(p)) {
    return { os: 'Linux', os_version: '', platformFamily: 'linux', device: 'Desktop', device_model: '' };
  }
  if (/iPhone|iPod/i.test(p)) {
    return { os: 'iOS', os_version: '', platformFamily: 'ios', device: 'Mobile', device_model: '' };
  }
  if (/iPad/i.test(p)) {
    return { os: 'iOS', os_version: '', platformFamily: 'ios', device: 'Tablet', device_model: '' };
  }

  return {
    os: 'Unknown',
    os_version: '',
    platformFamily: 'unknown',
    device: 'Unknown',
    device_model: '',
  };
}

/* -------------------------------------------------------------------------- */
/* Internal helpers — architecture                                             */
/* -------------------------------------------------------------------------- */

function resolveArchitecture(
  ua: string,
  platformStr: string,
  uad: UaDataHighEntropy | null,
  secCh: SecChHints,
): { architecture: string; bitness: string } {
  const arch = (uad?.architecture ?? secCh.architecture ?? '').trim().toLowerCase();
  const bit = (uad?.bitness ?? secCh.bitness ?? '').trim();
  /* WoW64 may arrive via UAData (`wow64: true`) or `Sec-CH-UA-Wow64: ?1`. */
  const wow64 = uad?.wow64 === true || secCh.wow64 === true;

  if (arch.indexOf('arm') !== -1) {
    return { architecture: bit === '32' ? 'ARM' : 'ARM64', bitness: bit === '32' ? '32' : '64' };
  }
  if (arch.indexOf('x86') !== -1 || arch === 'amd64' || arch === 'x64' || arch === 'ia64') {
    return { architecture: bit === '32' ? 'x86' : 'x86_64', bitness: bit === '32' ? '32' : '64' };
  }
  if (wow64) {
    /* 32-bit process on a 64-bit OS: the OS is still 64-bit x86. */
    return { architecture: 'x86_64', bitness: '64' };
  }

  /* UA / platform-string fallback. */
  const hay = `${ua} ${platformStr}`.toLowerCase();
  if (/arm64|aarch64|armv8/.test(hay)) return { architecture: 'ARM64', bitness: '64' };
  if (/x86_64|x64|win64|wow64|amd64/.test(hay)) return { architecture: 'x86_64', bitness: '64' };
  if (/armv[3-7]|arm;/.test(hay)) return { architecture: 'ARM', bitness: '32' };
  if (/i[3456]86|x86\b/.test(hay)) return { architecture: 'x86', bitness: '32' };
  return { architecture: '', bitness: bit === '32' || bit === '64' ? bit : '' };
}

/* -------------------------------------------------------------------------- */
/* Post-normalization self-check                                               */
/* -------------------------------------------------------------------------- */

/**
 * Final invariant pass:
 *   - if `os` contains digits, split a trailing version off into os_version
 *     ('Windows 11' → os 'Windows', os_version '11'); unmappable → 'Unknown'.
 *   - os_version must never equal os (reset to '' when it does, but only when
 *     the equality is non-trivial, i.e. os is non-empty).
 */
function sanitizeOs(os: string, osVersion: string): { os: string; osVersion: string } {
  let o = (os ?? '').trim();
  let v = (osVersion ?? '').trim();
  if (o && /\d/.test(o)) {
    const m = /^([^\d]+?)\s*([\d][\d.]*)$/.exec(o);
    if (m !== null && m[1].trim()) {
      o = m[1].trim();
      if (!v) v = m[2];
    } else {
      o = 'Unknown';
    }
  }
  if (v && o && v === o) v = '';
  return { os: o, osVersion: v };
}

/* -------------------------------------------------------------------------- */
/* Internal helpers — host runtime ladder                                      */
/* -------------------------------------------------------------------------- */

interface HostAppSpec {
  re: RegExp;
  name: string;
  /** IDE shells are classified as `ide_webview` / `ide_shell`, not generic apps. */
  ide: boolean;
}

/**
 * Embedded shells that all ship a Chromium engine. Their UA tokens are matched
 * in priority order so a host app / IDE is never mislabelled as generic Chromium.
 */
const HOST_APP_SPECS: HostAppSpec[] = [
  { re: /vscode-webview[\s/][\d.]+/i, name: 'Visual Studio Code', ide: true },
  { re: /VSCodium[\s/][\d.]+/i, name: 'VSCodium', ide: true },
  { re: /Windsurf[\s/][\d.]+/i, name: 'Windsurf', ide: true },
  { re: /OpenCode[\s/][\d.]+/i, name: 'OpenCode', ide: true },
  { re: /Cursor[\s/][\d.]+/i, name: 'Cursor', ide: true },
  { re: /(?:^|[\s(])Code[\s/][\d.]+/i, name: 'Visual Studio Code', ide: true },
  { re: /Slack[\s/][\d.]+/i, name: 'Slack', ide: false },
  { re: /Instagram[\s/][\d.]+/i, name: 'Instagram', ide: false },
  { re: /WhatsApp[\s/][\d.]+/i, name: 'WhatsApp', ide: false },
  { re: /(?:FBAV|FBAN)[\s/][\d.]+/i, name: 'Facebook', ide: false },
  { re: /Twitter(?:Android)?[\s/][\d.]+/i, name: 'Twitter', ide: false },
  { re: /Discord[\s/][\d.]+/i, name: 'Discord', ide: false },
  { re: /Teams[\s/][\d.]+/i, name: 'Microsoft Teams', ide: false },
  { re: /Zoom[\s/][\d.]+/i, name: 'Zoom', ide: false },
  { re: /Line[\s/][\d.]+/i, name: 'LINE', ide: false },
  { re: /Snapchat[\s/][\d.]+/i, name: 'Snapchat', ide: false },
  { re: /Notion[\s/][\d.]+/i, name: 'Notion', ide: false },
  { re: /Figma[\s/][\d.]+/i, name: 'Figma', ide: false },
  { re: /LinkedIn[\s/][\d.]+/i, name: 'LinkedIn', ide: false },
];

/** `; wv` token in a WebView UA (Android system webview, in-app browsers). */
const WEBVIEW_UA_RE = /;\s*wv(?:\s|\)|$)/i;

const SHELL_NAME_ALIASES: Record<string, string> = {
  vscode: 'Visual Studio Code',
  'vs-code': 'Visual Studio Code',
  code: 'Visual Studio Code',
  cursor: 'Cursor',
  windsurf: 'Windsurf',
  vscodium: 'VSCodium',
  opencode: 'OpenCode',
};

function normalizeShellName(name: string): string {
  const trimmed = (name ?? '').trim();
  return SHELL_NAME_ALIASES[trimmed.toLowerCase()] ?? trimmed;
}

function hostAppFromUa(ua: string, ideOnly: boolean): HostAppSpec | null {
  for (const spec of HOST_APP_SPECS) {
    if (ideOnly && !spec.ide) continue;
    if (spec.re.test(ua)) return spec;
  }
  return null;
}

function explicitHost(name: string, ideOnly: boolean): HostAppSpec | null {
  const normalized = normalizeShellName(name);
  if (!normalized) return null;
  const lower = normalized.toLowerCase();
  for (const spec of HOST_APP_SPECS) {
    if (ideOnly && !spec.ide) continue;
    if (lower === spec.name.toLowerCase()) return spec;
  }
  return ideOnly ? null : { re: /^$/, name: normalized, ide: false };
}

interface RuntimeResolution {
  runtime: RuntimeKind;
  host_app: string;
  client_type: ClientType;
  /** Browser name used when engine resolution produced only a generic label. */
  preferredBrowserName: string;
}

/**
 * Corroboration for client-supplied flat aliases. A flat alias may override a
 * header/UA-derived identity only when the same signal is also present in a
 * matching UA token or in the trusted (in-process) nested `runtime` bag.
 */
interface AliasEvidence {
  electron: boolean;
  node: boolean;
  hostApp: boolean;
  ideShell: boolean;
  webView: boolean;
}

/** `RuntimeSignals` plus which flat aliases are safe to use. */
interface EffectiveRuntimeSignals extends RuntimeSignals {
  aliasEvidence: AliasEvidence;
}

/** Case/alias-insensitive comparison of two host / IDE shell names. */
function sameShellName(a: string, b: string): boolean {
  const na = normalizeShellName(a.trim()).toLowerCase();
  const nb = normalizeShellName(b.trim()).toLowerCase();
  return na.length > 0 && na === nb;
}

/**
 * Runtime ladder (first match wins):
 *   1. `Electron/<ver>` UA token or `process.versions.electron`
 *   2. `process.versions.node` / nodeVersion
 *   3. IDE-shell tokens (`Code`, `Cursor`, `OpenCode`, `Windsurf`, `VSCodium`, …)
 *   4. WebView `; wv` token / explicit webView flag
 *   5. Host-app tokens (`Slack`, `Instagram`, `WhatsApp`, …)
 *   6. otherwise a plain browser
 *
 * Device/OS resolution is deliberately NOT touched here: `device: Desktop` keeps
 * coming from hardware truth (platform / touch points / UA), never from the runtime.
 */
function resolveRuntime(ua: string, signals: EffectiveRuntimeSignals): RuntimeResolution {
  const ev = signals.aliasEvidence;
  /* UA tokens are server-observed evidence and always usable. Flat aliases are
   * client-supplied: use them only when corroborated by a matching UA token or
   * by the trusted nested `runtime` bag. Never let one flip the runtime alone. */
  const uaElectronToken = firstMatch(/Electron\/([\d.]+)/i, ua) ?? '';
  const aliasElectron = ev.electron ? signals.electronVersion : '';
  const pvElectron = ev.electron ? String(signals.processVersions?.electron ?? '') : '';
  const electronVersion = uaElectronToken || aliasElectron || pvElectron || '';

  const aliasNode = ev.node ? signals.nodeVersion : '';
  const pvNode = ev.node ? String(signals.processVersions?.node ?? '') : '';
  const nodeVersion = aliasNode || pvNode || '';

  /* An explicit host/IDE alias may only become a spec — and therefore a
   * preferredBrowserName — when corroborated. Otherwise only UA-token evidence
   * decides, or the client remains a plain browser. */
  const hostSpec =
    (ev.hostApp ? explicitHost(signals.hostApp ?? '', false) : null) || hostAppFromUa(ua, false);
  const ideSpec =
    (ev.ideShell ? explicitHost(signals.ideShell ?? '', true) : null) || hostAppFromUa(ua, true);
  const trustedHost = ev.hostApp ? signals.hostApp ?? '' : '';
  const webview = (ev.webView && signals.webView === true) || WEBVIEW_UA_RE.test(ua);

  if (electronVersion) {
    return {
      runtime: 'electron',
      host_app: hostSpec?.name || trustedHost || '',
      client_type: 'desktop_app',
      preferredBrowserName: 'Electron',
    };
  }
  if (nodeVersion) {
    return {
      runtime: 'node',
      host_app: hostSpec?.name || trustedHost || '',
      client_type: 'node',
      preferredBrowserName: 'Node.js',
    };
  }
  if (ideSpec) {
    return {
      runtime: 'ide_webview',
      host_app: ideSpec.name,
      client_type: 'ide_shell',
      preferredBrowserName: ideSpec.name,
    };
  }
  if (webview) {
    return {
      runtime: 'webview',
      host_app: hostSpec?.name || trustedHost || '',
      client_type: 'webview',
      preferredBrowserName: hostSpec?.name || 'WebView',
    };
  }
  if (hostSpec) {
    return {
      runtime: 'host_app',
      host_app: hostSpec.name,
      client_type: hostSpec.ide ? 'ide_shell' : 'host_app',
      preferredBrowserName: hostSpec.name,
    };
  }
  return { runtime: 'browser', host_app: '', client_type: 'browser', preferredBrowserName: '' };
}

/** Engine labels that must never stand in for a detected host runtime. */
function isGenericBrowserName(name: string): boolean {
  const n = name.trim().toLowerCase();
  return n === '' || n === 'unknown' || n === 'chromium' || n === 'chrome' || n === 'google chrome';
}

/** Collects runtime signals from the flat aliases and the nested `runtime` bag. */
function runtimeSignalsFromInput(
  input: NormalizeIdentityInput | NormalizeUserAgentInput,
): EffectiveRuntimeSignals {
  const runtime = input.runtime ?? null;
  const processVersions = input.processVersions ?? runtime?.processVersions ?? null;
  const ua = String(input.userAgent ?? '');
  const trustedPv = runtime?.processVersions ?? null;

  /* UA tokens and the nested `runtime` bag (collected in-process) are evidence.
   * Flat aliases — including a flat `processVersions` — are client-supplied and
   * do not corroborate themselves. */
  const uaElectron = /Electron\/([\d.]+)/i.test(ua);
  const uaWebView = WEBVIEW_UA_RE.test(ua);
  const uaHost = hostAppFromUa(ua, false);
  const uaIde = hostAppFromUa(ua, true);
  const trustedElectron = Boolean(runtime?.electronVersion) || Boolean(trustedPv?.electron);
  const trustedNode = Boolean(runtime?.nodeVersion) || Boolean(trustedPv?.node);
  const trustedHost = runtime?.hostApp ?? '';
  const trustedIde = runtime?.ideShell ?? '';
  const trustedWebView = runtime?.webView === true;

  const flatHost = input.hostApp ?? '';
  const flatIde = input.ideShell ?? '';
  /* A flat host alias is corroborated when the trusted collector reported the
   * same host or the UA carries that host's token. With no flat alias, any
   * value present already came from the trusted nested runtime bag. */
  const hostCorroborated = flatHost.trim()
    ? sameShellName(flatHost, trustedHost) ||
      (uaHost !== null && sameShellName(flatHost, uaHost.name))
    : Boolean(trustedHost.trim());
  const ideCorroborated = flatIde.trim()
    ? sameShellName(flatIde, trustedIde) ||
      (uaIde !== null && sameShellName(flatIde, uaIde.name))
    : Boolean(trustedIde.trim());

  return {
    electronVersion: input.electronVersion ?? runtime?.electronVersion ?? processVersions?.electron ?? '',
    nodeVersion: input.nodeVersion ?? runtime?.nodeVersion ?? processVersions?.node ?? '',
    processVersions,
    hostApp: input.hostApp ?? runtime?.hostApp ?? '',
    ideShell: input.ideShell ?? runtime?.ideShell ?? '',
    webView: input.webView ?? runtime?.webView ?? false,
    aliasEvidence: {
      electron: uaElectron || trustedElectron,
      node: trustedNode,
      hostApp: hostCorroborated,
      ideShell: ideCorroborated,
      webView: uaWebView || trustedWebView,
    },
  };
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

const BLANK_IDENTITY: NormalizedIdentity = {
  os: 'Unknown',
  os_version: '',
  browser_name: 'Unknown',
  browser_major_version: '',
  browser_full_version: '',
  device: 'Unknown',
  device_model: '',
  architecture: '',
  bitness: '',
  platformFamily: 'unknown',
  headless_mode: null,
  runtime: 'unknown',
  host_app: '',
  client_type: 'unknown',
  form_factors: [],
  wow64: false,
};

/**
 * Normalizes UA / client hints into the shared identity shape. Never throws.
 * Source priority: uaData.fullVersionList + platformVersion → secCh headers →
 * UA regexes; brand priority: Electron → Edge → Opera → Brave → Samsung Internet →
 * Headless Chrome → Google Chrome → Chromium → Firefox → Safari (plus the
 * Cursor / Manus agent tokens in the UA fallback chain). A genuine `Electron/<version>`
 * UA token is always resolved to `Electron` before any UA-CH brand is considered.
 * Additively, the UA fallback chain also recognises Arc / Vivaldi forks and the
 * Googlebot / GPTBot / ClaudeBot / ChatGPT-User / OAI-SearchBot / Claude-User /
 * Claude-SearchBot / PerplexityBot / Perplexity-User crawler & AI-agent tokens
 * ahead of the generic Google Chrome / Chromium tokens.
 */
export function normalizeIdentity(input: NormalizeIdentityInput): NormalizedIdentity {
  try {
    const ua = (input?.userAgent ?? '').toString();
    const platformStr = (input?.platform ?? '').toString();
    const rawTouch = input?.maxTouchPoints;
    const touch = typeof rawTouch === 'number' && isFinite(rawTouch) ? rawTouch : 0;
    const uad = input?.uaData ?? null;
    const secCh = parseSecCh(input?.secCh);
    const headlessMode = resolveHeadlessMode(ua, uad, secCh);
    const signals = runtimeSignalsFromInput(input ?? {});
    const runtime = resolveRuntime(ua, signals);

    const osRes = resolveOs(ua, platformStr, touch, uad, secCh);
    const browser = resolveBrowser(ua, uad, secCh);
    const archRes = resolveArchitecture(ua, platformStr, uad, secCh);

    /* When the runtime comes from a corroborated `process.versions` / alias (no
     * UA token), keep the version aligned with the runtime instead of the
     * embedded engine's UA. An uncorroborated flat alias must never overwrite
     * a server-observed browser name/version. */
    if (runtime.runtime === 'electron' && !firstMatch(/Electron\/([\d.]+)/i, ua)) {
      const v = signals.aliasEvidence.electron
        ? signals.electronVersion || String(signals.processVersions?.electron ?? '')
        : '';
      if (v.trim()) {
        browser.full = v.trim();
        browser.major = majorOf(v.trim());
      }
    } else if (runtime.runtime === 'node') {
      const v = signals.aliasEvidence.node
        ? signals.nodeVersion || String(signals.processVersions?.node ?? '')
        : '';
      if (v.trim()) {
        browser.full = v.trim();
        browser.major = majorOf(v.trim());
      }
    }

    /* A detected host runtime owns browser_name — never report the embedded
     * Chromium engine as the client when we know it is Electron / an IDE / a
     * WebView / a host app. Existing specific browser labels (Firefox, Safari,
     * Edge, Cursor, Electron, …) are preserved unchanged. */
    const browserName =
      runtime.preferredBrowserName && isGenericBrowserName(browser.name)
        ? runtime.preferredBrowserName
        : browser.name;

    const formFactors = [...(uad?.formFactors ?? []), ...secCh.formFactors];
    const identity: NormalizedIdentity = {
      os: osRes.os,
      os_version: osRes.os_version,
      browser_name: browserName,
      browser_major_version: browser.major,
      browser_full_version: browser.full,
      device: osRes.device,
      device_model: osRes.device_model,
      architecture: archRes.architecture,
      bitness: archRes.bitness,
      platformFamily: osRes.platformFamily,
      headless_mode: headlessMode,
      runtime: runtime.runtime,
      host_app: runtime.host_app,
      client_type: runtime.client_type,
      form_factors: formFactors,
      wow64: uad?.wow64 === true || secCh.wow64 === true,
    };
    if (browser.is_headless_brand) identity.is_headless_brand = true;

    /* Self-check: a version source exists but the major came out empty — walk
     * the fallback chain until a non-empty major is found. */
    if (versionSourceExists(ua, uad, secCh) && !identity.browser_major_version) {
      const fallback = fallbackMajorFromUa(identity.browser_name, ua);
      if (fallback.major) {
        identity.browser_full_version = fallback.full;
        identity.browser_major_version = fallback.major;
      }
    }

    const safe = sanitizeOs(identity.os, identity.os_version);
    identity.os = safe.os;
    identity.os_version = safe.osVersion;

    return identity;
  } catch {
    return { ...BLANK_IDENTITY };
  }
}

/* -------------------------------------------------------------------------- */
/* Public API — camelCase contract (UA + client hints)                        */
/* -------------------------------------------------------------------------- */

/**
 * `Sec-CH-UA*` header values and / or `navigator.userAgentData` high-entropy
 * values. Header-style keys (`'sec-ch-ua-platform'`) are also accepted, so a
 * server can pass `{ ...parsedClientHints, 'sec-ch-ua-platform': 'Windows' }`
 * without reshaping it first.
 */
export interface ClientHintsInput {
  brands?: Array<{ brand: string; version: string }> | string;
  fullVersionList?: Array<{ brand: string; version: string }> | string;
  platform?: string;
  platformVersion?: string;
  architecture?: string;
  /** Alias used by some header parsers (`Sec-CH-UA-Arch`). */
  arch?: string;
  bitness?: string;
  model?: string;
  mobile?: boolean | string;
  formFactors?: string[];
  uaFullVersion?: string;
  wow64?: boolean;
}

export interface NormalizeUserAgentInput {
  userAgent?: string;
  /** Parsed `Sec-CH-UA*` values plus optional high-entropy `userAgentData` values. */
  clientHints?: ClientHintsInput | null;
  /** `navigator.platform` (needed for the iPadOS `MacIntel` check). */
  platform?: string;
  maxTouchPoints?: number;
  /** Host-runtime signals collected from the Electron/Node environment. */
  runtime?: RuntimeSignals | null;
  /** Flat aliases accepted for convenience (map onto `runtime`). */
  electronVersion?: string;
  nodeVersion?: string;
  processVersions?: Record<string, string | undefined> | null;
  hostApp?: string;
  ideShell?: string;
  webView?: boolean;
}

export interface NormalizedUserAgent {
  os: string;
  osVersion: string;
  device: DeviceKind;
  browserName: string;
  browserMajorVersion: string;
  browserFullVersion: string;
  architecture: string;
  bitness: string;
  model: string;
  /** True when the resolved browser came from the HeadlessChrome UA-CH brand. */
  is_headless_brand?: boolean;
  /** Headless variant ('shell' | 'new' | null). Additive field (P2-17). */
  headless_mode?: HeadlessMode;
  /** Host runtime that renders the page (engine-independent). Additive field. */
  runtime?: RuntimeKind;
  /** Host application name when the runtime is an Electron/IDE/WebView shell. */
  host_app?: string;
  /** Broker-facing client classification derived from `runtime`. */
  client_type?: ClientType;
  /** Normalized `Sec-CH-UA-Form-Factors` values. Additive field. */
  formFactors?: string[];
  /** `Sec-CH-UA-Wow64 ?1`. Additive field. */
  wow64?: boolean;
}

const BLANK_USER_AGENT: NormalizedUserAgent = {
  os: 'Unknown',
  osVersion: '',
  device: 'Unknown',
  browserName: 'Unknown',
  browserMajorVersion: '',
  browserFullVersion: '',
  architecture: '',
  bitness: '',
  model: '',
  headless_mode: null,
  runtime: 'unknown',
  host_app: '',
  client_type: 'unknown',
  formFactors: [],
  wow64: false,
};

/** Serialises a brand list back into a `Sec-CH-UA*` structured-field string. */
function serializeBrandList(brands: Array<{ brand: string; version: string }>): string {
  return brands
    .filter((entry) => entry && typeof entry.brand === 'string')
    .map((entry) => `"${entry.brand}";v="${entry.version ?? ''}"`)
    .join(', ');
}

/** Reads a hint from a mixed bag: structured camelCase first, then header keys. */
function readBagKey(hints: ClientHintsInput, key: string): string {
  const bag = hints as unknown as Record<string, unknown>;
  const direct = bag[key];
  if (typeof direct === 'string') return direct;
  const lower = key.toLowerCase();
  for (const candidate of Object.keys(bag)) {
    if (candidate.toLowerCase() === lower) {
      const value = bag[candidate];
      if (typeof value === 'string') return value;
    }
  }
  return '';
}

function hintFromBag(hints: ClientHintsInput, name: string): string {
  const bag = hints as unknown as Record<string, unknown>;
  const structured = bag[name];
  if (typeof structured === 'string') return unquote(structured);
  const headerKey = `sec-ch-ua-${name.replace(/([A-Z])/g, '-$1').toLowerCase()}`;
  return unquote(readBagKey(hints, headerKey));
}

function brandsFromValue(value: unknown): BrandEntry[] {
  if (Array.isArray(value)) {
    return value
      .filter((entry): entry is BrandEntry => Boolean(entry) && typeof (entry as BrandEntry).brand === 'string')
      .map((entry) => ({ brand: entry.brand, version: String(entry.version ?? '') }));
  }
  if (typeof value === 'string') return parseBrandList(value);
  return [];
}

/**
 * Coerces the mixed client-hints bag into the two shapes the core resolver
 * already understands: `uaData` (JS API) and `secCh` (request headers).
 */
function coerceClientHints(hints: ClientHintsInput | null | undefined): {
  uaData: UaDataHighEntropy | null;
  secCh: Record<string, string> | undefined;
} {
  if (!hints || typeof hints !== 'object') return { uaData: null, secCh: undefined };

  const fullVersionList = brandsFromValue(
    hints.fullVersionList && (Array.isArray(hints.fullVersionList) ? hints.fullVersionList.length > 0 : true)
      ? hints.fullVersionList
      : readBagKey(hints, 'sec-ch-ua-full-version-list')
  );
  const brands = brandsFromValue(
    hints.brands && (Array.isArray(hints.brands) ? hints.brands.length > 0 : true)
      ? hints.brands
      : readBagKey(hints, 'sec-ch-ua')
  );
  const platform = hintFromBag(hints, 'platform');
  const platformVersion = hintFromBag(hints, 'platformVersion');
  const architecture = hints.architecture || hintFromBag(hints, 'arch');
  const bitness = hints.bitness ?? hintFromBag(hints, 'bitness');
  const model = hints.model ?? hintFromBag(hints, 'model');
  /* `Sec-CH-UA-Mobile: ?1` used to remain a raw string; normalize once here. */
  const mobileRaw = hints.mobile ?? readBagKey(hints, 'sec-ch-ua-mobile');
  const mobile = parseMobileFlag(mobileRaw);
  const wow64Raw = hints.wow64 ?? readBagKey(hints, 'sec-ch-ua-wow64');
  const wow64 = parseWow64(wow64Raw);
  const formFactors = hints.formFactors?.length
    ? hints.formFactors
    : parseFormFactors(readBagKey(hints, 'sec-ch-ua-form-factors'));

  const secCh: Record<string, string> = {};
  if (brands.length > 0) secCh['sec-ch-ua'] = serializeBrandList(brands);
  if (fullVersionList.length > 0) {
    secCh['sec-ch-ua-full-version-list'] = serializeBrandList(fullVersionList);
  }
  if (platform) secCh['sec-ch-ua-platform'] = `"${platform}"`;
  if (platformVersion) secCh['sec-ch-ua-platform-version'] = `"${platformVersion}"`;
  if (architecture) secCh['sec-ch-ua-arch'] = `"${architecture}"`;
  if (bitness) secCh['sec-ch-ua-bitness'] = `"${bitness}"`;
  if (model) secCh['sec-ch-ua-model'] = `"${model}"`;
  if (mobileRaw !== '' && mobileRaw !== undefined && mobileRaw !== null) {
    secCh['sec-ch-ua-mobile'] = mobile ? '?1' : '?0';
  }
  if (wow64) secCh['sec-ch-ua-wow64'] = '?1';
  if (formFactors.length > 0) {
    secCh['sec-ch-ua-form-factors'] = formFactors.map((f) => `"${f}"`).join(', ');
  }

  const uaData: UaDataHighEntropy = {
    fullVersionList,
    platform,
    platformVersion,
    architecture,
    bitness,
    model,
    formFactors,
    uaFullVersion: hints.uaFullVersion,
    wow64,
  };

  return { uaData, secCh: Object.keys(secCh).length > 0 ? secCh : undefined };
}

/**
 * Canonical camelCase entry point: `{ userAgent, clientHints }` in,
 * `{ os, osVersion, device, browserName, browserMajorVersion, … }` out.
 *
 * `os` is always the family with no digits ('Windows', 'Mac OS X', 'Android',
 * 'iOS', 'Linux'); `osVersion` carries the version ('11', '10', '15.3.1').
 * Total: never throws, degrades to an 'Unknown' identity.
 */
export function normalizeUserAgent(input: NormalizeUserAgentInput): NormalizedUserAgent {
  try {
    const { uaData, secCh } = coerceClientHints(input?.clientHints);
    const identity = normalizeIdentity({
      userAgent: input?.userAgent ?? '',
      platform: input?.platform ?? '',
      maxTouchPoints: input?.maxTouchPoints,
      uaData,
      secCh,
      runtime: input?.runtime,
      electronVersion: input?.electronVersion,
      nodeVersion: input?.nodeVersion,
      processVersions: input?.processVersions,
      hostApp: input?.hostApp,
      ideShell: input?.ideShell,
      webView: input?.webView,
    });

    const mobile = input?.clientHints?.mobile;
    const mobileFlag = parseMobileFlag(mobile);
    const device: DeviceKind =
      identity.device === 'Unknown' && mobileFlag ? 'Mobile' : identity.device;

    return {
      os: identity.os,
      osVersion: identity.os_version,
      device,
      browserName: identity.browser_name,
      browserMajorVersion: identity.browser_major_version,
      browserFullVersion: identity.browser_full_version,
      architecture: identity.architecture,
      bitness: identity.bitness,
      model: identity.device_model,
      is_headless_brand: identity.is_headless_brand,
      headless_mode: identity.headless_mode,
      runtime: identity.runtime,
      host_app: identity.host_app,
      client_type: identity.client_type,
      formFactors: identity.form_factors,
      wow64: identity.wow64,
    };
  } catch {
    return { ...BLANK_USER_AGENT };
  }
}

/** Property read that degrades to `undefined` when a getter throws (hostile proxy). */
function safeGet(bag: Record<string, unknown>, key: string): unknown {
  try {
    return bag[key];
  } catch {
    return undefined;
  }
}

/** Accepts either the camelCase or the snake_case identity shape. */
function readIdentityField(
  value: NormalizedUserAgent | NormalizedIdentity,
  camel: keyof NormalizedUserAgent,
  snake: keyof NormalizedIdentity,
): string {
  try {
    const bag = value as unknown as Record<string, unknown>;
    const raw = safeGet(bag, camel) ?? safeGet(bag, snake);
    return typeof raw === 'string' ? raw.trim() : '';
  } catch {
    return '';
  }
}

/**
 * Post-normalization invariant check. Returns every violation as a readable
 * string (empty array = valid). Rules:
 *   1. `os` must not contain digits (family only, 'Windows' not 'Windows 11').
 *   2. `osVersion` must never equal `os`.
 *   3. `browserMajorVersion` must not be empty when `browserFullVersion` is known.
 *   4. A known full version must yield a numeric major version.
 */
export function validateUserAgentNormalization(
  value: NormalizedUserAgent | NormalizedIdentity,
): string[] {
  const issues: string[] = [];
  try {
    if (!value || typeof value !== 'object') return ['identity must be a non-null object'];

    const os = readIdentityField(value, 'os', 'os');
    const osVersion = readIdentityField(value, 'osVersion', 'os_version');
    const major = readIdentityField(value, 'browserMajorVersion', 'browser_major_version');
    const full = readIdentityField(value, 'browserFullVersion', 'browser_full_version');

    if (os && /\d/.test(os)) {
      issues.push(`os "${os}" contains digits — os must be the family only`);
    }
    if (os && osVersion && os === osVersion) {
      issues.push(`os_version "${osVersion}" must not equal os`);
    }
    if (full && !major) {
      issues.push(`browser_major_version is empty while browser_full_version "${full}" is known`);
    } else if (major && !/^\d+$/.test(major)) {
      issues.push(`browser_major_version "${major}" is not a numeric string`);
    }
  } catch {
    /* Keep the validator total even for a proxy that throws on property access. */
    return ['identity could not be read (throwing getter or proxy)'];
  }

  return issues;
}

/**
 * Throwing variant of `validateUserAgentNormalization`: raises the first
 * violation. Intended for tests and server-side self-audits.
 */
export function assertUserAgentNormalization(
  value: NormalizedUserAgent | NormalizedIdentity,
): void {
  const issues = validateUserAgentNormalization(value);
  if (issues.length > 0) throw new Error(issues[0]);
}

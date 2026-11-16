/**
 * User-Agent Client Hints middleware (Express) + Worker-compatible header bundle.
 *
 * Express path: `clientHintsMiddleware` advertises `Accept-CH` / `Critical-CH` on every
 * response and parses the incoming `sec-ch-ua*` request headers into
 * `(req as any).intelClientHints`.
 *
 * Worker path: `clientHintResponseHeaders()` returns the same headers as a plain object
 * for `worker/index.js`'s fetch handler (see `apiResponse()` / the static-asset branch).
 *
 * Self-contained by design: parsed hints are returned as plain data and the caller
 * (or the shared normalization layer) decides what to do with them.
 */

import type { NextFunction, Request, Response } from 'express';

/** Header value advertised to browsers listing every hint we want on subsequent requests. */
export const CLIENT_HINT_ACCEPT_CH =
  'Sec-CH-UA, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-Mobile';

/** Hints the browser must attach even without an explicit permission grant (Critical-CH). */
export const CLIENT_HINT_CRITICAL_CH =
  'Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List';

export interface ClientHintBrand {
  brand: string;
  version: string;
}

export interface ParsedClientHints {
  brands: ClientHintBrand[];
  platform: string;
  platformVersion: string;
  architecture: string;
  bitness: string;
  model: string;
  mobile: string;
  fullVersionList: ClientHintBrand[];
}

export type ClientHintHeaderBag = Record<string, string | string[] | undefined>;

const EMPTY_HINTS: ParsedClientHints = {
  brands: [],
  platform: '',
  platformVersion: '',
  architecture: '',
  bitness: '',
  model: '',
  mobile: '',
  fullVersionList: [],
};

function readHeaderValue(headers: ClientHintHeaderBag, name: string): string {
  const raw = headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value : '';
}

function unquote(value: string): string {
  let text = value.trim();
  if (text.length >= 2) {
    const first = text[0];
    const last = text[text.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) text = text.slice(1, -1);
  }
  return text.trim();
}

function unescapeToken(value: string): string {
  return value.replace(/\\(.)/g, '$1').trim();
}

/**
 * Parses a structured-fields brand list such as
 * `"Chromium";v="126", "Not/A)Brand";v="24", "Google Chrome";v="126"`.
 * Tolerates unquoted tokens, stray whitespace and escaped characters.
 */
function parseBrandList(raw: string): ClientHintBrand[] {
  const brands: ClientHintBrand[] = [];
  const text = typeof raw === 'string' ? raw.trim() : '';
  if (!text) return brands;
  for (const part of text.split(',')) {
    const entry = part.trim();
    if (!entry) continue;
    const match =
      /^(?:"((?:[^"\\]|\\.)*)"|([^";]*))\s*;\s*v\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^";]*))\s*$/.exec(entry);
    if (!match) continue;
    const brand = match[1] !== undefined ? unescapeToken(match[1]) : match[2].trim();
    const version =
      match[3] !== undefined ? unescapeToken(match[3]) : (match[4] ?? '').trim();
    if (!brand) continue;
    brands.push({ brand, version });
  }
  return brands;
}

function parseMobile(raw: string): string {
  const text = typeof raw === 'string' ? raw.trim() : '';
  if (!text) return '';
  const token = text.replace(/^\?/, '').trim();
  if (token === '1') return 'true';
  if (token === '0') return 'false';
  return token;
}

/**
 * Parses every `sec-ch-ua*` request header into a normalized hints object.
 * Always resolves — malformed headers yield empty strings / lists, never a throw.
 */
export function parseClientHintHeaders(headers: ClientHintHeaderBag): ParsedClientHints {
  try {
    const bag = headers ?? {};
    const brands = parseBrandList(readHeaderValue(bag, 'sec-ch-ua'));
    const fullVersionList = parseBrandList(readHeaderValue(bag, 'sec-ch-ua-full-version-list'));
    return {
      brands,
      platform: unquote(readHeaderValue(bag, 'sec-ch-ua-platform')),
      platformVersion: unquote(readHeaderValue(bag, 'sec-ch-ua-platform-version')),
      architecture: unquote(readHeaderValue(bag, 'sec-ch-ua-arch')),
      bitness: unquote(readHeaderValue(bag, 'sec-ch-ua-bitness')),
      model: unquote(readHeaderValue(bag, 'sec-ch-ua-model')),
      mobile: parseMobile(readHeaderValue(bag, 'sec-ch-ua-mobile')),
      fullVersionList,
    };
  } catch {
    return { ...EMPTY_HINTS, brands: [], fullVersionList: [] };
  }
}

/** Same headers as a plain object for the Worker fetch handler. */
export function clientHintResponseHeaders(): Record<string, string> {
  return {
    'Accept-CH': CLIENT_HINT_ACCEPT_CH,
    'Critical-CH': CLIENT_HINT_CRITICAL_CH,
  };
}

/**
 * Express middleware: advertises Accept-CH / Critical-CH on every response and attaches
 * the parsed hints to `(req as any).intelClientHints`. Never throws.
 */
export function clientHintsMiddleware(req: Request, res: Response, next: NextFunction): void {
  try {
    if (!res.getHeader('Accept-CH')) res.setHeader('Accept-CH', CLIENT_HINT_ACCEPT_CH);
    if (!res.getHeader('Critical-CH')) res.setHeader('Critical-CH', CLIENT_HINT_CRITICAL_CH);
    (req as Request & { intelClientHints?: ParsedClientHints }).intelClientHints =
      parseClientHintHeaders(req.headers as ClientHintHeaderBag);
  } catch {
    // Hint parsing must never break the request pipeline.
  }
  next();
}

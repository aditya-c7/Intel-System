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
import { parseBrandList } from '../../shared/normalization/uaNormalizer';

/**
 * The single Accept-CH set consumed by BOTH the Express middleware and the Worker.
 * Kept deliberately small: only high-entropy hints we actually act on.
 */
export const CLIENT_HINT_ACCEPT_CH =
  'Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-Form-Factors';

/** Critical-CH must be a SUBSET of Accept-CH (RFC 9652). */
export const CLIENT_HINT_CRITICAL_CH =
  'Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version';

/** Match on every hint we advertise so caches never serve a hint-blind variant. */
export const CLIENT_HINT_VARY = 'Sec-CH-UA*';

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
    Vary: CLIENT_HINT_VARY,
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
    if (!res.getHeader('Vary')) res.setHeader('Vary', CLIENT_HINT_VARY);
    (req as Request & { intelClientHints?: ParsedClientHints }).intelClientHints =
      parseClientHintHeaders(req.headers as ClientHintHeaderBag);
  } catch {
    // Hint parsing must never break the request pipeline.
  }
  next();
}

/**
 * Vercel serverless entry point.
 *
 * This file is NOT exposed as a Vercel Function (files starting with "_" inside
 * /api are ignored by Vercel). `npm run build` bundles it together with
 * `server.ts` into the single `api/index.js` function using esbuild, which
 * removes every ESM/TypeScript path-resolution problem on the Vercel Node.js
 * runtime.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import app from '../server';

const API_PREFIX = '/api';

type VercelRequest = IncomingMessage & {
  url?: string;
  originalUrl?: string;
  query?: Record<string, string | string[] | undefined>;
};

/**
 * Vercel rewrites `/api/(.*)` to `/api/index?__ipath=$1` so that this single
 * function can serve every API route. Depending on the routing layer the
 * incoming `req.url` can be either the original path or the rewritten one, so
 * we normalise it here: Express always receives the real route and all original
 * query parameters (token, bytes, s, t, etc.) intact.
 */
function applyRestoredUrlAndQuery(
  req: VercelRequest,
  restoredPath: string,
  params: URLSearchParams
): void {
  params.delete('__ipath');
  const remainingQuery = params.toString();
  const finalUrl = remainingQuery ? `${restoredPath}?${remainingQuery}` : restoredPath;

  req.url = finalUrl;
  req.originalUrl = finalUrl;

  // Clear any pre-cached parseurl metadata set by the serverless wrapper so Express re-parses req.url
  const internalReq = req as unknown as Record<string, unknown>;
  if ('_parsedUrl' in internalReq) {
    delete internalReq._parsedUrl;
  }
  if ('_parsedOriginalUrl' in internalReq) {
    delete internalReq._parsedOriginalUrl;
  }

  // Synchronize req.query so Express handlers reading req.query.token / req.query.bytes / req.query.t
  // always receive the clean query parameters without __ipath even if the runtime defined a getter
  const cleanQuery: Record<string, string | string[]> = {};
  for (const [key, value] of params.entries()) {
    if (key === '__ipath') continue;
    const existing = cleanQuery[key];
    if (existing === undefined) {
      cleanQuery[key] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      cleanQuery[key] = [existing, value];
    }
  }

  try {
    Object.defineProperty(req, 'query', {
      value: cleanQuery,
      writable: true,
      enumerable: true,
      configurable: true,
    });
  } catch {
    try {
      req.query = cleanQuery;
    } catch {
      // Ignore if frozen
    }
  }
}

function restoreOriginalApiUrl(req: VercelRequest): void {
  const rawUrl = typeof req.url === 'string' && req.url.length > 0 ? req.url : '/';

  // Parse the (possibly rewritten) request URL safely. Vercel rewrites `/api/(.*)`
  // to `/api/index?__ipath=$1`, so the rewritten URL carries the real route inside
  // the __ipath query parameter.
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl, 'http://localhost');
  } catch {
    try {
      // Tolerate malformed percent-encoding (e.g. a bare trailing `%`) instead of failing
      parsedUrl = new URL(rawUrl.replace(/%(?![0-9a-fA-F]{2})/g, '%25'), 'http://localhost');
    } catch {
      return; // Leave the request untouched rather than breaking it
    }
  }

  const searchParams = parsedUrl.searchParams;

  // Merge any query parameters pre-parsed by the Vercel runtime into searchParams
  try {
    if (req.query && typeof req.query === 'object') {
      for (const [k, v] of Object.entries(req.query)) {
        if (!searchParams.has(k)) {
          if (typeof v === 'string') {
            searchParams.set(k, v);
          } else if (Array.isArray(v) && typeof v[0] === 'string') {
            searchParams.set(k, v[0]);
          }
        }
      }
    }
  } catch {
    // Ignore getter errors on req.query
  }

  const pathPart = parsedUrl.pathname;
  const rawIpath = searchParams.get('__ipath');

  if (rawIpath !== null) {
    searchParams.delete('__ipath');
    let decodedInjected = rawIpath;
    try {
      if (decodedInjected.includes('%')) {
        decodedInjected = decodeURIComponent(decodedInjected);
      }
    } catch {
      decodedInjected = rawIpath;
    }

    // Handle case where the injected path itself had "?foo=bar" appended
    const [cleanInjectedPath, embeddedQuery] = decodedInjected.split('?');
    if (embeddedQuery) {
      const embeddedParams = new URLSearchParams(embeddedQuery);
      for (const [ek, ev] of embeddedParams.entries()) {
        if (ek !== '__ipath' && !searchParams.has(ek)) {
          searchParams.set(ek, ev);
        }
      }
    }

    const cleanSubpath = cleanInjectedPath.replace(/^\/+/, '').replace(/^api\/+/i, '');
    const restoredPath = cleanSubpath ? `${API_PREFIX}/${cleanSubpath}` : API_PREFIX;
    applyRestoredUrlAndQuery(req, restoredPath, searchParams);
    return;
  }

  // Safety net: if the platform handed us the rewritten path (/api/index) without __ipath,
  // recover the original path from Vercel headers.
  if (pathPart === '/api/index' || pathPart === '/api/index.js') {
    const headerValue =
      (req.headers['x-vercel-original-path'] as string | undefined) ||
      (req.headers['x-original-url'] as string | undefined) ||
      (req.headers['x-rewrite-url'] as string | undefined) ||
      (req.headers['x-matched-path'] as string | undefined);

    if (headerValue) {
      const original = headerValue.startsWith('http')
        ? new URL(headerValue).pathname + new URL(headerValue).search
        : headerValue;
      const normalized = original.startsWith('/') ? original : `/${original}`;
      const normQIdx = normalized.indexOf('?');
      const normPath = normQIdx === -1 ? normalized : normalized.slice(0, normQIdx);
      const normQuery = normQIdx === -1 ? '' : normalized.slice(normQIdx + 1);
      const mergedParams = new URLSearchParams(normQuery);
      for (const [k, v] of searchParams.entries()) {
        if (k !== '__ipath' && !mergedParams.has(k)) {
          mergedParams.set(k, v);
        }
      }
      applyRestoredUrlAndQuery(req, normPath, mergedParams);
      return;
    }
  }

  // Even when req.url already has the original path (/api/...), ensure req.query is synced
  applyRestoredUrlAndQuery(req, pathPart, searchParams);
}

export default function handler(req: VercelRequest, res: ServerResponse): void {
  try {
    restoreOriginalApiUrl(req);
  } catch {
    // Never block a request because of URL normalisation.
  }

  (app as unknown as (request: VercelRequest, response: ServerResponse) => void)(req, res);
}

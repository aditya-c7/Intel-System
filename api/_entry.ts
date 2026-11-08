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
function restoreOriginalApiUrl(req: VercelRequest): void {
  const rawUrl = typeof req.url === 'string' && req.url.length > 0 ? req.url : API_PREFIX;
  const queryIndex = rawUrl.indexOf('?');
  const pathPart = queryIndex === -1 ? rawUrl : rawUrl.slice(0, queryIndex);
  const queryPart = queryIndex === -1 ? '' : rawUrl.slice(queryIndex + 1);

  const params = new URLSearchParams(queryPart);

  // Also merge any query parameters pre-parsed by the serverless platform into req.query
  if (req.query && typeof req.query === 'object') {
    for (const [k, v] of Object.entries(req.query)) {
      if (!params.has(k) && typeof v === 'string') {
        params.set(k, v);
      }
    }
    delete req.query.__ipath;
  }

  const injectedPath = params.get('__ipath');

  if (injectedPath !== null) {
    params.delete('__ipath');
    // Handle case where injectedPath itself accidentally had "?foo=bar" appended
    const [cleanInjectedPath, embeddedQuery] = injectedPath.split('?');
    if (embeddedQuery) {
      const embeddedParams = new URLSearchParams(embeddedQuery);
      for (const [ek, ev] of embeddedParams.entries()) {
        if (!params.has(ek)) {
          params.set(ek, ev);
        }
      }
    }
    const suffix = cleanInjectedPath.replace(/^\/+/, '');
    const restored = suffix ? `${API_PREFIX}/${suffix}` : API_PREFIX;
    const remainingQuery = params.toString();
    const finalUrl = remainingQuery ? `${restored}?${remainingQuery}` : restored;
    req.url = finalUrl;
    req.originalUrl = finalUrl;
    return;
  }

  // Safety net: if the platform handed us the rewritten path (/api/index) but
  // dropped the injected marker, recover the original path from Vercel headers.
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
      for (const [k, v] of params.entries()) {
        if (k !== '__ipath' && !mergedParams.has(k)) {
          mergedParams.set(k, v);
        }
      }
      const qs = mergedParams.toString();
      const finalUrl = qs ? `${normPath}?${qs}` : normPath;
      req.url = finalUrl;
      req.originalUrl = finalUrl;
    }
  }
}

export default function handler(req: VercelRequest, res: ServerResponse): void {
  try {
    restoreOriginalApiUrl(req);
  } catch {
    // Never block a request because of URL normalisation.
  }

  (app as unknown as (request: VercelRequest, response: ServerResponse) => void)(req, res);
}

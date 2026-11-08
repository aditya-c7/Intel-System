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

type VercelRequest = IncomingMessage & { url?: string };

/**
 * Vercel rewrites `/api/(.*)` to `/api/index?__ipath=$1` so that this single
 * function can serve every API route. Depending on the routing layer the
 * incoming `req.url` can be either the original path or the rewritten one, so
 * we normalise it here: Express always receives the real route.
 */
function restoreOriginalApiUrl(req: VercelRequest): void {
  const rawUrl = typeof req.url === 'string' && req.url.length > 0 ? req.url : API_PREFIX;
  const queryIndex = rawUrl.indexOf('?');
  const pathPart = queryIndex === -1 ? rawUrl : rawUrl.slice(0, queryIndex);
  const queryPart = queryIndex === -1 ? '' : rawUrl.slice(queryIndex + 1);

  const params = new URLSearchParams(queryPart);
  const injectedPath = params.get('__ipath');

  if (injectedPath !== null) {
    params.delete('__ipath');
    const suffix = injectedPath.replace(/^\/+/, '');
    const restored = suffix ? `${API_PREFIX}/${suffix}` : API_PREFIX;
    const remainingQuery = params.toString();
    req.url = remainingQuery ? `${restored}?${remainingQuery}` : restored;
    return;
  }

  // Safety net: if the platform handed us the rewritten path but dropped the
  // injected marker, recover the original path from the original URL header
  // (set by the Vercel routing layer when available).
  if (pathPart === '/api/index' || pathPart === '/api/index.js') {
    const headerValue =
      (req.headers['x-vercel-original-path'] as string | undefined) ||
      (req.headers['x-original-url'] as string | undefined) ||
      (req.headers['x-rewrite-url'] as string | undefined);

    if (headerValue) {
      const original = headerValue.startsWith('http')
        ? new URL(headerValue).pathname + new URL(headerValue).search
        : headerValue;
      req.url = original.startsWith('/') ? original : `/${original}`;
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

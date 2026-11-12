import { createServer } from 'node:http';
import { handleAsNodeRequest } from 'cloudflare:node';
import { DurableObject } from 'cloudflare:workers';
import app, { initializeDatabaseSchema, withDatabase } from '../server.ts';

// Workers' node:http adapter uses this as a routing key, not a public TCP port.
const API_PORT = 3000;
createServer(app).listen(API_PORT);

function apiResponse(response) {
  const result = new Response(response.body, response);
  result.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, no-transform');
  result.headers.set('Permissions-Policy', 'compute-pressure=*');
  result.headers.set('X-Content-Type-Options', 'nosniff');
  return result;
}

export class VisitorStore extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    const sql = ctx.storage.sql;
    this.database = {
      exec(query) { sql.exec(query).toArray(); },
      prepare(query) {
        return {
          get: (...values) => sql.exec(query, ...values).toArray()[0],
          all: (...values) => sql.exec(query, ...values).toArray(),
          run: (...values) => {
            sql.exec(query, ...values).toArray();
            return { changes: Number(sql.exec('SELECT changes() AS count').one().count) };
          },
        };
      },
    };
    ctx.storage.transactionSync(() => initializeDatabaseSchema(this.database));
  }

  fetch(request) {
    return withDatabase(this.database, () => handleAsNodeRequest(API_PORT, request));
  }
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname !== '/api' && !pathname.startsWith('/api/')) {
      return env.ASSETS.fetch(request);
    }
    if (!env.VISITOR_HMAC_SECRET || env.VISITOR_HMAC_SECRET.length < 32) {
      return apiResponse(Response.json({ error: 'Configure VISITOR_HMAC_SECRET with at least 32 characters.' }, { status: 503 }));
    }
    try {
      const persistent = pathname === '/api/health' || pathname.startsWith('/api/visitor/');
      const response = persistent
        ? await env.VISITOR_STORE.get(env.VISITOR_STORE.idFromName('visitor-store-v1')).fetch(request)
        : await handleAsNodeRequest(API_PORT, request);
      return apiResponse(response);
    } catch (error) {
      console.error('Worker API failure:', error);
      return apiResponse(Response.json({ error: 'Internal server error.' }, { status: 500 }));
    }
  },
};

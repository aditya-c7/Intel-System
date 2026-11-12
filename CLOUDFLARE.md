# Full-stack Cloudflare deployment

The Vite frontend alone cannot execute server.ts. Static-only hosting can return SPA HTML for GET /api/health and HTTP 405 for POST /api/visitor/identify. This configuration deploys the existing Express routes plus static assets as a Cloudflare Worker.

## Deploy

Use Node.js 22.12 or newer and install development dependencies:

```sh
npm ci
npm run lint
npx --yes wrangler@4.161.0 deploy --dry-run
node scripts/test-worker.mjs
npx --yes wrangler@4.161.0 secret put VISITOR_HMAC_SECRET
npx --yes wrangler@4.161.0 deploy
```

Set VISITOR_HMAC_SECRET to a private random value of at least 32 characters. Keep it stable across deployments. Never commit it. Optional IPINFO_TOKEN can also be configured as a Worker secret. Missing signing configuration returns JSON 503 instead of silently accepting a public fallback secret.

For Workers Builds, use the repository root, Node 22.12+, npm ci as the installation command, and npx --yes wrangler@4.161.0 deploy as the deploy command. Wrangler runs npm run build and scripts/build-worker.mjs automatically. Do not deploy only dist/ or use an assets-only deployment command.

If the existing site is a Cloudflare Pages project, create a Workers application for this repository. After a successful deployment, attach intel.adityahq.me as its Custom Domain and remove the conflicting previous static application's domain association. This commit alone does not change an existing Pages project into a Worker or verify production.

## Storage and compatibility

Visitor and health routes use a SQLite-backed Durable Object. Speed-test traffic bypasses that database. A singleton visitor store is intentionally simple and is not an unlimited-throughput design. The v1 migration creates its storage class on initial deployment.

The build-time adapter reads server.ts, reuses its schema and route logic, and substitutes request-scoped SQLite storage only in the Worker bundle. It fails if expected source markers change. Existing Node/Vercel source and lockfiles remain unchanged. Express is bundled using Node package resolution so browser mappings do not disable its stream dependencies. Native better-sqlite3 is not executed by the Worker.

CI checks the build, deployment dry-run, actual local Workers API execution, authentication, binary transfers, SPA fallback, and visitor history after a complete local restart. A passing build is not proof of a successful production deployment; inspect CI results and then verify the live endpoints.

```sh
curl -i https://intel.adityahq.me/api/health
curl -i -H 'Content-Type: application/json' -d '{}' https://intel.adityahq.me/api/network/speed-test/init
```

Both must return HTTP 200 and JSON. Unknown API paths must return JSON 404. Browser deep links must still load the frontend. Production quotas, Cloudflare account configuration, secrets, and domain routing must also be valid.

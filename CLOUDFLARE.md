# Full-stack Cloudflare deployment

The Vite frontend alone cannot execute server.ts. Static-only hosting can return SPA HTML for GET /api/health and HTTP 405 for POST /api/visitor/identify. This configuration deploys the existing Express routes plus static assets as a Cloudflare Worker.

## Deploy

Use Node.js 22.12 or newer and install development dependencies:

```sh
npm ci
npm run lint
npm run build
node scripts/build-worker.mjs
npx --yes wrangler@4.161.0 deploy --dry-run
node scripts/test-worker.mjs
npx --yes wrangler@4.161.0 secret put VISITOR_HMAC_SECRET
npx --yes wrangler@4.161.0 deploy
```

Set VISITOR_HMAC_SECRET to a private random value of at least 32 characters. Keep it stable across deployments. Never commit it. Optional IPINFO_TOKEN can also be configured as a Worker secret. Missing signing configuration returns JSON 503 instead of silently accepting a public fallback secret.

For Workers Builds, use the repository root, Node 22.12+, npm ci as the installation command, and npx --yes wrangler@4.161.0 deploy as the deploy command. Wrangler runs npm run build and scripts/build-worker.mjs automatically. Do not deploy only dist/ or use an assets-only deployment command.

If the existing site is a Cloudflare Pages project, create a Workers application for this repository. After a successful deployment, attach intel.adityahq.me as its Custom Domain and remove the conflicting previous static application's domain association. This commit alone does not change an existing Pages project into a Worker or verify production.

## Storage and compatibility

Visitor and health routes use the SQLite-backed `VisitorStore` Durable Object. Network RTT monitoring calls GET/HEAD `/api/network/ping`, which does not touch SQLite or Durable Objects.

The build-time adapter reads server.ts, reuses its schema and route logic, and substitutes request-scoped SQLite storage only in the Worker bundle. It fails if expected source markers change. Existing Node/Vercel source and lockfiles remain unchanged. Express is bundled using Node package resolution so browser mappings do not disable its stream dependencies. Native better-sqlite3 is not executed by the Worker.

Static assets are served before the Worker unless the path is under `/api`, so asset requests do not consume Worker invocations.

## Cost model (calculated estimates, not measured quotas)

One idle tab with 5 s RTT monitoring produces about 720 ping requests per hour, all served without SQLite or Durable Objects, and monitoring pauses automatically after 15 minutes until Resume is pressed. Multiple tabs share a same-origin leader lease so only one tab polls; mirroring tabs display the leader's samples without issuing duplicate requests.

These figures are arithmetic estimates from the design, not provider-metered measurements. Cloudflare still charges/holds quota for every incoming Worker invocation that reaches the application, including rejected ones. Plan-level WAF/rate-limiting controls are separate and are not enabled by this repository; verify their availability on your plan before relying on them.

## Verification

CI checks the build, deployment dry-run, actual local Workers API execution, authentication, SPA fallback, and visitor history persistence across a Worker restart. `npm run test:browser` additionally drives a real Chromium against a local Worker to confirm RTT polling and tab-leader handover. It needs a system Chromium (`CHROMIUM_PATH` may point at one) and is skipped when none is installed. A passing build is not proof of a successful production deployment; inspect CI results and then verify the live endpoints.

```sh
curl -i https://intel.adityahq.me/api/health
curl -i https://intel.adityahq.me/api/network/ping
```

Both must return HTTP 200 and JSON. Unknown API paths must return JSON 404. Browser deep links must still load the frontend. Production quotas, Cloudflare account configuration, secrets, and domain routing must also be valid.

Application rejection still consumes an incoming Worker invocation. Inspect real Cloudflare CPU and request metrics after deployment; a local build does not prove compliance with the free-tier per-invocation CPU allowance. Do not insert tokens or secrets into logs, screenshots or issue reports.

## AI Crawl Control (native bot & agent defense)

The Worker also serves native crawler-policy documents and a small analytics/control API on the same Durable-Object SQLite store used for visitor history. The request middleware runs, in order: RFC 9421 Web Bot Auth verification of Ed25519-signed requests against published JWK directories; attribution from published operator CIDR feeds (JSON, Amazon HTML `<code>`, Anthropic SAIL TOML) plus static ByteDance subnets; DNS-based FCrDNS / soft-PTR checks; a client-side agent probe (Botscent `Server-Timing` header, CDP/headless probes, pointer kinematics); and a `Server-Timing` verdict on document navigations. The live `robots.txt`, Content-Signal header, and per-bot edge actions are derived from the persisted zone policy.

### Cloudflare routing

`wrangler.jsonc` sets `run_worker_first` for `/api`, `/api/*`, `/robots.txt`, and `/llms.txt`, so the dynamic policy documents are answered by the Worker rather than static assets. In `worker/index.js`, `/robots.txt`, `/llms.txt`, and everything under `/api/intel/ai-crawl-control/` are forwarded to the `VISITOR_STORE` Durable Object, giving the Express `apiRouter` request-scoped SQLite access. The policy documents are also reachable under the API prefix as aliases.

### API endpoints

- `GET /api/intel/ai-crawl-control/analytics?hours=168` — request/bot/operator stats and violations (the dashboard requests a 168-hour window).
- `POST /api/intel/ai-crawl-control/policy` — update the zone policy; returns the new config and generated robots.txt.
- `POST /api/intel/ai-crawl-control/agent-telemetry` — record client-side agent probe results.
- `POST /api/intel/ai-crawl-control/markdown-playground` — convert HTML into Markdown-for-Agents output.
- `POST /api/intel/ai-crawl-control/sync-feeds` — refresh published operator CIDR feeds.
- `GET /robots.txt` and `GET /llms.txt` — dynamic crawler-policy documents (also available as `/api/intel/ai-crawl-control/robots.txt` and `/api/intel/ai-crawl-control/llms.txt`).

### Verification

```sh
node scripts/test-worker.mjs
npm run build
node scripts/build-worker.mjs
```

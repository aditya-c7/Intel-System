# Full-stack Cloudflare deployment

The Vite frontend alone cannot execute server.ts. Static-only hosting can return SPA HTML for GET /api/health and HTTP 405 for POST /api/visitor/identify. This configuration deploys the existing Express routes plus static assets as a Cloudflare Worker.

## Deploy

Deployment is **manual only — there is no auto-deploy**. The `cloudflare.yml` GitHub Actions workflow runs on every push to `main` and on pull requests, but its `verify` job only builds and checks the project (`npm ci`, lint, build, Worker bundle, `wrangler deploy --dry-run`, and local Worker tests). It has **no `wrangler deploy` step**, so CI never publishes. The deploy command below is the human gate: run it locally only after verification passes. No push-to-deploy or hosted build auto-deploy is configured; adding one would remove the manual gate.

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

Wrangler runs `npm run build` and `scripts/build-worker.mjs` automatically at deploy time from the `build` block in `wrangler.jsonc`. Do not deploy only `dist/` or use an assets-only deployment command. If you use an external build platform, configure it for verification only (`... deploy --dry-run`) and keep `npx --yes wrangler@4.161.0 deploy` as a manual step; do not enable its auto-deploy.

If the existing site is a Cloudflare Pages project, create a Workers application for this repository. After a successful deployment, attach intel.adityahq.me as its Custom Domain and remove the conflicting previous static application's domain association. This commit alone does not change an existing Pages project into a Worker or verify production.

## Storage and compatibility

Visitor and health routes use the SQLite-backed `VisitorStore` Durable Object. Only `/api/visitor/*` and `/api/intel/geolocation` reach the Durable Object; `/api/health` and `/api/network/ping` are answered statelessly. Network RTT monitoring calls GET/HEAD `/api/network/ping`, which does not touch SQLite or Durable Objects.

The build-time adapter reads server.ts, reuses its schema and route logic, and substitutes request-scoped SQLite storage only in the Worker bundle. It fails if expected source markers change. Cloudflare Workers is the only deployment target: there is no Vercel deploy path (legacy `vercel.json` is retained only as an untouched historical artifact). Express is bundled using Node package resolution so browser mappings do not disable its stream dependencies. Native better-sqlite3 is not executed by the Worker.

## Edge routing, SSR injection, and pass-through paths

`wrangler.jsonc` sets `assets.run_worker_first = true` together with `not_found_handling: single-page-application`. The Worker must run **before** the asset layer:

- It injects the SSR bot verdict into every HTML document: the `intel:verdict` / `intel:bot-type` meta tags, the `#intel-initial-verdict` inline JSON, the `X-Intel-Bot-Verdict` / `-Agent` / `-Identity` headers, removal of stale cache validators, and — for verified Web Bot Auth traffic — a 60-second `intel_wba` cookie.
- It routes `/api` and `/api/*` to the Express app (and the Durable Object where needed). With SPA not-found handling, serving assets first would return `index.html` for API paths instead of JSON.
- It performs canonical redirects (`www` → apex, HTTP → HTTPS) and Web Bot Auth verification before producing a response.

Because the Worker runs first, files that must not be rewritten are forwarded straight to the `ASSETS` binding: hashed bundles under `/assets/*` and the crawler/LLM metadata files `/robots.txt`, `/llms.txt`, `/agents.md`, and `/sitemap.xml`. These **pass-through paths** keep the asset layer's own caching and are never UA-branded, but they still pass through the Worker.

**Cost tradeoff:** with `run_worker_first: true`, the Worker is invoked for *every* request, including static assets. Unlike an asset-first setup, asset requests do consume Worker invocations and CPU here. That is the price of correct SSR verdict injection and API routing; do **not** set it to `false`, which breaks SSR injection.

## Rate limits, Web Bot Auth, and secrets

Rate limiting uses the native Workers binding declared in `wrangler.jsonc`: `IDENTIFY_RATE_LIMIT` (top-level `ratelimits`, namespace `1001`, 40 requests per 60 seconds). It applies only to `POST /api/visitor/*`, keyed by `cf-connecting-ip`. Cryptographically verified Web Bot Auth agents and Cloudflare Bot Management verified bots are exempt. Over-limit anonymous requests get HTTP 429 with `Retry-After`. The binding is optional at runtime: if it is absent or the limiter throws, the Worker fails open and the request proceeds.

Web Bot Auth (RFC 9421) verification runs at the edge using the shared `WBA_TRUSTED_SIGNERS` set. Only requests presenting the full `Signature-Agent` / `Signature-Input` / `Signature` triple are verified; any verification failure fails open so an outage never rejects a visitor. A verified signed agent is named from its pinned registry identity, earns a short-lived HMAC-signed `intel_wba` cookie (requires `VISITOR_HMAC_SECRET`), and is exempt from the anonymous limiter. Genuine signature and authority values are re-derived from the inbound request and forwarded in encoded, non-spoofable `x-intel-original-*` headers; client-supplied geo/IP/WBA headers are stripped.

Secrets are set manually with `wrangler secret put`; no auto-deploy pipeline sets them. `VISITOR_HMAC_SECRET` must be a private random value of at least 32 characters, kept stable across deployments, and never committed. Missing or short values return JSON 503 instead of silently using a public fallback, and also disable the `intel_wba` cookie. `IPINFO_TOKEN` is optional. Never put tokens or secrets in logs, screenshots, or issue reports.

`wrangler.jsonc` enables `observability` (`{ "enabled": true }`), so Worker logs and metrics are available in the Cloudflare dashboard. Use them with the verification steps below to confirm real request and CPU usage after deployment.

## Cost model (calculated estimates, not measured quotas)

One idle tab with 5 s RTT monitoring produces about 720 ping requests per hour, all served without SQLite or Durable Objects, and monitoring pauses automatically after 15 minutes until Resume is pressed. Multiple tabs share a same-origin leader lease so only one tab polls; mirroring tabs display the leader's samples without issuing duplicate requests.

These figures are arithmetic estimates from the design, not provider-metered measurements. Cloudflare still charges/holds quota for every incoming Worker invocation that reaches the application, including rejected ones — and with `run_worker_first: true`, static-asset requests also invoke the Worker. Plan-level WAF/rate-limiting controls are separate and are not enabled by this repository; verify their availability on your plan before relying on them.

## Verification

CI checks the build, deployment dry-run, actual local Workers API execution, authentication, SPA fallback, and visitor history persistence across a Worker restart. `npm run test:browser` additionally drives a real Chromium against a local Worker to confirm RTT polling and tab-leader handover. It needs a system Chromium (`CHROMIUM_PATH` may point at one) and is skipped when none is installed. A passing build is not proof of a successful production deployment; inspect CI results and then verify the live endpoints.

```sh
curl -i https://intel.adityahq.me/api/health
curl -i https://intel.adityahq.me/api/network/ping
```

Both must return HTTP 200 and JSON. Unknown API paths must return JSON 404. Browser deep links must still load the frontend. Production quotas, Cloudflare account configuration, secrets, and domain routing must also be valid.

Application rejection still consumes an incoming Worker invocation. Inspect real Cloudflare CPU and request metrics after deployment; a local build does not prove compliance with the free-tier per-invocation CPU allowance. Do not insert tokens or secrets into logs, screenshots or issue reports.

## Local Worker verification

```sh
node scripts/test-worker.mjs
npm run build
node scripts/build-worker.mjs
```

## Incognito diagnostics capture (shadow)

This is a manual, opt-in procedure gated by the same deploy rules as everything else: deploy only via the human gate above after verification passes; there is no auto-deploy.

To capture a shadow diagnostics snapshot:

1. Open https://intel.adityahq.me/?intelDiag=1 in a real private/incognito window (not a regular tab with a spoofed user agent).
2. Open the browser console and run `window.__intelDiag()`.
3. Paste the returned JSON into your report.

The `intelDiag` flag is off by default, adds no UI, and does not affect any verdict or risk score. Never include tokens or secrets in the captured JSON or the report.

## Implementation status

For the honest, code-path-level state of the current integration wave — what is live/integrated, shadow-only, or backlog; the locked constraints (0–10, uncalibrated, zero alarms, no new panels, manual deploy, zero SDK); the phase history; and the diagnostics capture procedure — see [docs/IMPLEMENTATION_STATUS.md](./docs/IMPLEMENTATION_STATUS.md). This deployment guide remains the source of truth for the manual deploy command and Cloudflare configuration.

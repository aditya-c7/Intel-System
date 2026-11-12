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

## Speed-test policy

Speed testing is manual and one-shot: one Start click runs one download phase then one upload phase and stops. There is no automatic repeat, no hidden-tab transfer and no uncapped fallback.

| Control | Default | Runtime override |
|---|---:|---|
| Aggregate download budget per run | 16 MiB | fixed in code |
| Aggregate upload budget per run | 8 MiB | fixed in code |
| Download / upload phase ceiling | 8 s / 6 s | fixed in code |
| Parallel transfer requests per run | 2 | fixed in code |
| Binary payload per request | 256 KiB | fixed in code |
| Admitted requests per run | 400 | fixed in code |
| Start cooldown per visitor | 60 s | `SPEED_TEST_COOLDOWN_SECONDS` (0-3600) |
| Runs per visitor per rolling hour | 6 | `SPEED_TEST_VISITOR_RUNS_PER_HOUR` (1-60) |
| Runs per shared IP per rolling hour | 30 | `SPEED_TEST_IP_RUNS_PER_HOUR` (1-300) |
| Site-wide admitted transfer per UTC day | 256 MiB | `SPEED_TEST_DAILY_BUDGET_MIB` (24-4096) |
| Signed run token lifetime | 120 s | fixed in code |
| Kill switch | off | `SPEED_TEST_DISABLED=1` (or `SPEED_TEST_KILL_SWITCH`) |

Runtime values are read from bindings at request time, never baked into the bundle. Set them with `npx wrangler secret put SPEED_TEST_DISABLED` or as text variables in the Worker settings; after changing them, reload the dashboard. The kill switch disables only bandwidth tests. Visitor identification, history, health, CPU data, RTT ping and static assets keep working.

At most 24 MiB of application payload is authorized per run, and total traffic also includes headers, control calls and transport overhead. Short capped tests are estimates for the path to this Worker and may not saturate fast links. The UI labels results accordingly.

## Durable control plane

`SpeedTestStore` is a second SQLite-backed Durable Object bound as `SPEED_TEST_STORE` (migration `v2`, which only adds a class and does not touch `VisitorStore`). It stores only small metadata: hashed visitor/IP quota keys, rolling-hour admission timestamps, per-run byte counters, request counters, stream-slot leases and the UTC-day reservation total. Payload bytes never pass through it; download/upload traffic is streamed directly by the Worker.

- Admission is atomic in the DO: cooldown, per-visitor limit, per-IP limit and a full-run reservation against the daily budget. The full 24 MiB is reserved at admission and unused reservations are retained until UTC day rollover, so cancelling or replaying cannot create refund or admission loopholes.
- Each transfer request reserves bytes and a stream slot before the Worker forwards it. The signed per-request grant (HMAC keyed by the run token) tells the adapted backend exactly how many bytes it may serve or accept. Client-supplied internal headers are stripped at the edge.
- Byte counters are per run; a request that would cross the run budget is denied with 429 `BUDGET_EXHAUSTED`, which the client treats as a normal phase endpoint. Replaying an accepted request cannot refund served bytes.
- Stream slots use a 15 s lease plus release-on-response-close so an aborted client cannot hold capacity forever. A run-level request counter caps retries and denied attempts.
- Expired runs, slots and admission rows are purged lazily and by a 10-minute DO alarm. Unknown tokens never create rows. Quota keys are HMACed, and tokens/secrets are never logged.
- If the DO binding is unavailable, init/download/upload fail closed with JSON 503 `CONTROL_PLANE_UNAVAILABLE`. Ping, health, identity, history and CPU data are unaffected.
- Node-only development (`npm run dev`, Vercel files) uses an in-memory adapter with the same policy constants. It is not a durable, cross-instance safeguard and is not used by the Worker deployment.

429 responses include `Retry-After` and a machine-readable `code`. Clients must not retry 401/403/429, exhausted budgets, disabled tests or configuration errors, and a retry must reuse the remaining run budget rather than starting a new run.

## Storage and compatibility

Visitor and health routes use the SQLite-backed `VisitorStore` Durable Object. Ping does not touch SQLite or Durable Objects. Speed-test coordination writes only small counters to `SpeedTestStore`; binary payloads stay out of both databases. Both stores are intentionally simple singletons and are not unlimited-throughput designs.

The build-time adapter reads server.ts, reuses its schema and route logic, and substitutes request-scoped SQLite storage only in the Worker bundle. It fails if expected source markers change. Existing Node/Vercel source and lockfiles remain unchanged. Express is bundled using Node package resolution so browser mappings do not disable its stream dependencies. Native better-sqlite3 is not executed by the Worker.

Static assets are served before the Worker unless the path is under `/api`, so asset requests do not consume Worker invocations.

## Cost model (calculated estimates, not measured quotas)

Per explicit speed test with a full 16 MiB download and 8 MiB upload, 256 KiB requests and 2 streams:

| Operation | Estimate |
|---|---:|
| Worker invocations (init + 96 transfers + complete + monitoring pings) | ~100-110 |
| DO requests (admit + reserve/release per transfer + complete + alarm flush) | ~200 |
| SQLite writes in `SpeedTestStore` | ~200 small upserts |
| Application payload | 24 MiB |

One idle tab with 5 s RTT monitoring produces about 720 ping requests per hour, all served without SQLite or Durable Objects, and monitoring pauses automatically after 15 minutes until Resume is pressed. Multiple tabs share a same-origin leader lease so only one tab polls. Opening additional tabs does not multiply speed-test runs; each run still needs an explicit Start and admission.

These figures are arithmetic estimates from the policy, not provider-metered measurements. Cloudflare still charges/holds quota for every incoming Worker invocation that reaches the application, including rejected ones, so application quotas cannot protect against a hostile request flood. Plan-level WAF/rate-limiting controls are separate and are not enabled by this repository; verify their availability on your plan before relying on them.

## Verification

CI checks the build, deployment dry-run, actual local Workers API execution, authentication, durable quotas across a full local restart, per-run byte budgets under parallel and replayed requests, token tampering/expiry, upload media-type and size validation, the kill switch, SPA fallback, and visitor history persistence. A passing build is not proof of a successful production deployment; inspect CI results and then verify the live endpoints.

```sh
curl -i https://intel.adityahq.me/api/health
curl -i -H 'Content-Type: application/json' -d '{}' https://intel.adityahq.me/api/network/speed-test/init
```

Both must return HTTP 200 and JSON. Unknown API paths must return JSON 404. Browser deep links must still load the frontend. Production quotas, Cloudflare account configuration, secrets, and domain routing must also be valid.

Application rejection still consumes an incoming Worker invocation. Inspect real Cloudflare CPU and request metrics after deployment; a local build does not prove compliance with the free-tier per-invocation CPU allowance. Do not insert tokens or secrets into logs, screenshots or issue reports.

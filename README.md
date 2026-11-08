# Intel System

First-party visitor identification, IP/ISP geolocation, network stability, multi-stream
throughput and CPU pressure telemetry.

- **Frontend:** React 19 + TypeScript + Tailwind CSS v4 + Vite (`src/`)
- **Backend:** Express + SQLite (`server.ts`), with an in-memory fallback
- **Deployment:** single Vercel Function (`api/index.js`) + static Vite build (`dist/`)

## Local development

```bash
npm install
npm run dev          # http://localhost:3000 (Express + Vite middleware)
```

## Production build

```bash
npm run build        # vite build -> dist/  &&  esbuild -> api/index.js
npm start            # serves dist/ + the API on port 3000
```

`scripts/build-api.mjs` bundles `api/_entry.ts` (which imports `server.ts`) into the
single ESM function `api/index.js`. Pre-bundling avoids every `ERR_MODULE_NOT_FOUND`
and TypeScript/ESM path-resolution problem on the Vercel Node.js runtime.

## Deploying to Vercel

1. Import the repository in Vercel. The committed `vercel.json` provides the build
   command, output directory, function settings, headers and rewrites.
2. Add the environment variable **`VISITOR_HMAC_SECRET`** (Project → Settings →
   Environment Variables) with a fixed random string. It signs visitor tokens, speed
   test tokens and the client-side history backup. It must stay the same across
   deployments and serverless instances, otherwise returning visitors will lose their
   history.
3. Optional: `IPINFO_TOKEN` for richer ISP/ASN lookups, `APP_URL` for region labels.
4. Deploy. No other configuration is required.

### Notes for Vercel

- `vercel.json` rewrites `/api/(.*)` to the single function
  `/api/index?__ipath=$1`. `api/_entry.ts` restores the original URL before handing the
  request to Express, so routing works regardless of how the platform forwards the
  rewritten path.
- The function handles raw `application/octet-stream` upload streams and also the case
  where the platform has already buffered the body into `req.body`.
- The download/upload payloads are capped at 2 MB per request (well below Vercel's
  4.5 MB limit) and the client never requests more than 1 MB per stream chunk.
- The serverless database tries SQLite in `os.tmpdir()` and transparently falls back to
  an in-memory store when the native `better-sqlite3` binary is unavailable. Visitor
  history is additionally carried in a server-signed `historyBackup` stored in the
  browser, so it survives cold starts.
- `Permissions-Policy: compute-pressure=*` is sent for every route so the CPU Pressure
  panel works.

## Environment variables

| Name | Required | Purpose |
| --- | --- | --- |
| `VISITOR_HMAC_SECRET` | Recommended | Fixed HMAC secret for visitor/token/history signatures |
| `IPINFO_TOKEN` | No | Enhanced IP/ISP lookups |
| `APP_URL` | No | Region label hint |

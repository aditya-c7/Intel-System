# Intel System Vercel Serverless & Dual-Runtime Architecture

This plan upgrades the Intel System backend, storage engine, and deployment routing so the repository deploys and runs without errors on **Vercel** (Static CDN + Serverless Functions) while remaining 100% compatible with persistent Node servers (local development, Cloud Run, Railway, and Render).

### User Review & Critical Decisions

> [!IMPORTANT]
> Both architectural choices from our clarification step are locked in below. Review the plan and click **Proceed** to apply these changes across the codebase.

- **Confirmed Decision 1 (Visitor History & Storage Persistence)**: **Hybrid Client Storage + Serverless `/tmp` SQLite**. On persistent servers, SQLite writes to the local data directory; on Vercel's read-only `/var/task` filesystem, the server automatically uses `/tmp` (with an automatic in-memory fallback if native SQLite bindings are unavailable in a given serverless image) AND synchronizes HMAC-verified visit history snapshots with the browser's first-party storage so returning visitors never lose their visit count or history across serverless cold starts.
- **Confirmed Decision 2 (Deployment Runtime Compatibility)**: **Dual-Runtime Support (Vercel Serverless + Standard Node Server)**. The Express API application is exported as a reusable handler mounted by Vercel's `/api` serverless runtime via rewrite rules, while still running as a standalone Node/Vite server on port 3000 when executed directly.

---

### 1. Overview & Core Concept

- **What It Does**: Eliminates every point of failure when deploying the Intel System repository to Vercel:
  1. Exposes all `/api/visitor/*`, `/api/network/*`, and `/api/health` endpoints through a Vercel-compatible serverless entry point and routing configuration.
  2. Prevents the `EROFS: read-only file system` crash on Vercel by detecting serverless/read-only environments and routing database storage to `/tmp` with a pure JavaScript in-memory fallback if native C++ bindings are stripped.
  3. Preserves returning visitor recognition, visit counts, session counts, and historical visit logs across serverless cold starts by pairing HMAC-signed client history snapshots with server-side persistence.
  4. Keeps Download and Upload speed-test stream payloads safely within Vercel's 4.5 MB serverless body limit while sustaining the full 10-second analysis (5s Download + 5s Upload) and 10-second cooldown cycle.
- **Target Audience / Persona**: Public visitors across desktop and mobile devices inspecting their real-time IP, ISP/ASN, geolocation map, network RTT stability, 4-stream throughput, and hardware CPU pressure on a production Vercel deployment.
- **Key Value**: Zero-config `git push` deployment to Vercel with zero 404 API errors, zero read-only disk crashes, and uninterrupted visitor history retention.

---

### 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Zero-State Arrival & Instant Recognition**: Visitor opens the Vercel deployment URL; the frontend collects browser/device signals, client geo hints, and any existing first-party visitor credentials + signed visit history backup, then calls `/api/visitor/identify`.
  2. **Cold-Start Resilient History Restoration**: Even if the request hits a fresh Vercel serverless instance whose `/tmp` directory was just initialized, the server verifies the HMAC signature on the visitor's ID and rehydrates their previous visits before recording the new visit, returning accurate `totalVisits`, `totalSessions`, and `visitHistory`.
  3. **Live Network RTT & 10s Speed Analysis + 10s Cooldown**: The Network Stability graph measures HTTP RTT every 1.5s, while the Server Speed Test runs a 5.0s multi-stream Download test and 5.0s multi-stream Upload test (updating the odometer counter every 250ms) followed by a 10.0s cooldown pause.
  4. **Click-Only Historical Graph Inspection**: Clicking or tapping a point on either the Network Stability graph or the CPU Activity step-line graph pins a detailed inspection popup for that timestamp without hover popups.
- **Visual Identity & Theme**:
  - *Aesthetic Direction*: Existing clean, high-contrast utilitarian telemetry interface preserved without redesign.
  - *Color Palette & Mood*: Crisp light neutral background (`#F8FAFC`), white structural cards (`#FFFFFF`) with `1px` borders (`#E5E7EB`), primary blue telemetry lines (`#2563EB`), emerald nominal indicators (`#059669`), and red alert states (`#DC2626`).
  - *Typography & Hierarchy*: Clean sans-serif headings and labels paired with `font-mono tabular-nums` for IP addresses, ASN identifiers, latency figures, timestamps, and rolling odometer counters.
  - *Component Styling & Layout*: Responsive 12-column grid with dynamic `ResizeObserver` 1:1 SVG chart viewports (`236px` height) so graphs never shrink or squeeze on mobile viewports.

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1: Serverless Entry Point & Request Routing**
  - *Chosen Approach*: Decouple the Express API app creation from `app.listen()` so that Vercel invokes the Express app directly as a serverless handler for all `/api/*` routes, while static assets (`dist/`) are served directly by Vercel's edge network with `Permissions-Policy: compute-pressure=()` / `compute-pressure=*` headers configured.
  - *Why*: Vercel does not run long-lived `app.listen()` processes; exporting the Express app for `/api/*` while only calling `listen()` outside Vercel allows the exact same codebase to run on both Vercel and standard Node hosts.
  - *Alternatives Considered*: Rewriting every Express route into separate Vercel-only function handlers was passed over because it would break single-process local development and duplicate business logic.
- **Decision 2: Three-Tier Resilient Storage Engine (Disk SQLite -> `/tmp` SQLite -> In-Memory Map + Signed Client Sync)**
  - *Chosen Approach*:
    1. Use writable `/tmp` on Vercel (`process.env.VERCEL`) or whenever the project root is read-only.
    2. Wrap native `better-sqlite3` initialization in a safe loader with an automatic in-memory store fallback so even if Vercel's bundler omits native C++ bindings for a specific Node version, the API never crashes with a 500 error.
    3. Store the visitor's recent `visitHistory` (up to 35 compact records) and aggregate counters in `localStorage` alongside an HMAC signature generated by the server. When `/api/visitor/identify` runs on a fresh serverless cold start, the server verifies the HMAC signature and restores missing visits into its storage before recording the current visit.
  - *Why*: Guarantees 100% uptime and accurate returning-visitor history on Vercel Hobby/Pro plans without requiring external database credentials.
- **Decision 3: Vercel Payload & Region Detection Compatibility**
  - *Chosen Approach*: Cap individual `/api/network/download` and `/api/network/upload` stream requests at `2 MB` (well below Vercel's 4.5 MB serverless body limit) and detect Vercel edge/serverless headers (`x-vercel-ip-city`, `x-vercel-ip-country`, `x-vercel-ip-country-region`, `x-vercel-ip-latitude`, `x-vercel-ip-longitude`, `x-vercel-id`) in addition to existing proxy headers.
  - *Why*: Prevents `413 FUNCTION_PAYLOAD_TOO_LARGE` errors on Vercel while providing instant, zero-latency IP and coordinate detection when hosted on Vercel's edge network.

---

### 4. Technical Architecture & Data Strategy *(Technical Reference)*

- **Architecture & Component Diagram**:

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                        Browser Client (React + Vite)                       │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐  │
│  │ Public IP, ISP &     │  │ Network Stability    │  │ CPU Activity     │  │
│  │ Leaflet OSM Map      │  │ (5m RTT + 10s/10s    │  │ (W3C Compute     │  │
│  │ + Device/Visit Specs │  │  Odometer Speed Test)│  │  Pressure Graph) │  │
│  └──────────┬───────────┘  └──────────┬───────────┘  └──────────────────┘  │
│             │                         │                                    │
│  ┌──────────┴─────────────────────────┴─────────────────────────────────┐  │
│  │ First-Party Collector (localStorage ID + HMAC Token + Signed History)│  │
│  └────────────────────────────────────┬─────────────────────────────────┘  │
└───────────────────────────────────────┼────────────────────────────────────┘
                                        │ HTTPS (/api/*)
                                        ▼
┌────────────────────────────────────────────────────────────────────────────┐
│             Dual-Runtime Routing Layer (Vercel CDN / Node Server)          │
│  ┌────────────────────────────────────┐ ┌────────────────────────────────┐ │
│  │ Vercel Serverless Entry (/api/*)   │ │ Standalone Node/Vite Server    │ │
│  │ + Static CDN + Permissions-Policy  │ │ (Port 3000 Dev & Container)    │ │
│  └─────────────────┬──────────────────┘ └───────────────┬────────────────┘ │
│                    └──────────────────┬─────────────────┘                  │
│                                       ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                  Shared Express API Application                      │  │
│  │  • POST /api/visitor/identify (Vercel Header + Geo + History Sync)   │  │
│  │  • GET  /api/network/ping     (Low-overhead RTT Responder)           │  │
│  │  • POST /api/network/speed-test/init & /complete (Signed Token)      │  │
│  │  • GET  /api/network/download & POST /api/network/upload (<2MB/req)  │  │
│  └────────────────────────────────────┬─────────────────────────────────┘  │
│                                       ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │      Resilient Storage Adapter (Local Disk / Vercel /tmp / Memory)   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

- **Data Model & State**:
  - **Signed History Sync Payload**:
    - `cachedVisits`: Compact array of previously recorded `VisitHistoryRecord` items stored in `localStorage` under `intel_fp_history`.
    - `historySignature`: Server-generated HMAC-SHA256 signature over `visitorId + totalVisits + cachedVisits` stored in `localStorage` under `intel_fp_history_sig`.
  - **Storage Adapter Interface**:
    - Unifies `visitors`, `visits`, and `verified_geo_cache_v3` operations behind a clean synchronous interface backed by SQLite (`./data/intel_system.db` locally or `/tmp/intel_system.db` on Vercel) with automatic fallback to an in-memory store if native bindings cannot initialize.
- **Interactive Component & State Mapping**:
  - **Identification & Rehydration Flow**: On page load or manual refresh, `identifyCurrentVisitor()` sends `storedVisitorId`, `storedVisitorToken`, `clientSessionId`, `cachedHistory` (visits + signature), `browserDevice`, and `clientGeoHint` to `/api/visitor/identify`. If the serverless instance lost its `/tmp` state, it validates `historySignature`, restores the historical visits into the active store, inserts the new visit if `pageLoadId` is new, computes accurate `totalVisits` and `totalSessions`, signs the updated history, and returns the complete `IntelVisitorResponse`.
  - **Vercel Geolocation & Header Extraction**: `extractVisitorIp()` and `lookupVerifiedGeolocation()` check Vercel's injected headers (`x-vercel-forwarded-for`, `x-vercel-ip-city`, `x-vercel-ip-country-region`, `x-vercel-ip-country`, `x-vercel-ip-latitude`, `x-vercel-ip-longitude`) alongside standard proxy headers and multi-provider ISP/ASN lookup (`ipwho.is`, `ipapi.co`, `freeipapi.com`).
  - **Stateless Multi-Stream Speed Test**: `/api/network/download` and `/api/network/upload` validate the HMAC-signed speed test token (`testId.expiresAtMs.vHash.sig`) statlessly across any serverless instance, capping individual request chunks at `2 MB` so Vercel never rejects requests with `413 Payload Too Large`.

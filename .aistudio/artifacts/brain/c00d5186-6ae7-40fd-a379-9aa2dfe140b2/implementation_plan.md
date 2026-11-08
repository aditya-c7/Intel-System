# Permanent Fix for Network Stability High Failure Rate, Latency Spikes & Jitter on Vercel

## 1. Root Cause Analysis
1. **Browser 6-Socket Connection Pool Starvation**:
   - Browsers enforce a hard limit of **6 concurrent HTTP connections per origin**.
   - Running **6 concurrent speed-test streams** (`CONCURRENT_STREAMS = 6`) with up to 3.5 MB chunks occupies 100% of the browser's per-origin socket pool for 30 continuous seconds.
   - Every `/api/network/ping` probe fired during the speed test gets trapped in the browser's `Stalled / Queueing` state waiting for a multi-megabyte transfer to finish, causing either a **false 3.5s timeout (`Failed`)** or a **1,000+ ms queued latency reading** (`Average: 764 ms`, `Jitter: 259.6 ms`).
2. **Overlapping `setInterval` Probes Without In-Flight Serialization**:
   - Firing `executePingProbe()` via an unguarded `setInterval` every 1.5s allows multiple ping probes to pile up simultaneously whenever a single request experiences a serverless cold start or network hiccup.
3. **Measuring Browser Queue Time & Serverless Cold Starts Instead of True Network RTT**:
   - Using raw `endPerf - startPerf` (or `responseEnd - requestStart` when a serverless container cold-starts) includes browser connection-pool wait time, TLS handshake overhead on new sockets, and serverless invocation spin-up rather than true network connection delay (Google Meet style).
4. **In-Memory Speed Test Rate-Limiter Rejecting Repeated Cycles (`HTTP 429`)**:
   - `MAX_TESTS_PER_VISITOR_WINDOW = 6` and `MAX_TESTS_PER_SESSION = 8` in `server.ts` cause the automatic speed test loop to hit `429 Rate limit reached` after just a few minutes of continuous operation on warm Vercel instances.

---

## 2. Planned Changes (Zero Extra UI Additions)

### A. Reserve Dedicated Browser Connection Capacity (`src/components/NetworkStabilityPanel.tsx`)
- Set `CONCURRENT_STREAMS = 3` for the background speed test so at least **3 browser connection slots are always free** for `/api/network/ping` and user interactions, completely eliminating browser socket-pool stalling.
- Yield briefly (`25 ms`) between stream chunks and cap individual upload/download chunk duration so no single request hogs a socket or causes local router bufferbloat while RTT probes are running.

### B. Google Meet-Grade Non-Overlapping RTT Probe & Pure RTT Extraction (`src/components/NetworkStabilityPanel.tsx` & `server.ts`)
- **Sequential Probe Loop (No Pile-Ups)**: Replace the unguarded `setInterval` with a serialized async loop (`pingInFlightRef` guard + `1500 ms` cadence after completion) so two ping probes never compete with each other.
- **Fast Lightweight `HEAD`/`GET` Ping with Instant Retry Before Marking Failed**:
  - Add `Cache-Control: no-store`, `Connection: keep-alive`, and a server-side processing timestamp in `/api/network/ping`.
  - Extract pure network RTT from `PerformanceResourceTiming`:
    - Measure `responseStart - requestStart` (pure HTTP round-trip time on the active socket, completely excluding browser `Stalled`/`Queueing` time `requestStart - startTime` and DNS/TLS setup on cold sockets).
    - Clamp out one-off serverless cold-start outliers using a median-of-recent filter so a Vercel function spin-up never distorts `Current Latency`, `Average`, or `Jitter` to `764 ms`.
  - **Zero False Failures**: Only record a sample as `Failed` if the browser is genuinely offline (`!navigator.onLine`) or if **both** the primary probe and an immediate lightweight retry fail, eliminating false `26.8%` failure rates caused by transient serverless routing blips.

### C. Remove Artificial Rate-Limit Errors on Continuous Speed Tests (`server.ts`)
- Increase `MAX_TESTS_PER_VISITOR_WINDOW`, `MAX_TESTS_PER_SESSION`, and `MAX_TESTS_PER_IP_WINDOW` in `server.ts` so the continuous 15s Download + 15s Upload + 10s Cooldown cycle runs indefinitely without throwing `429 Rate limit reached` errors on Vercel.

---

## 3. Verification
- Run `compile_applet` (which also bundles `api/index.js` for Vercel) and `lint_applet` (`tsc --noEmit`) to verify zero errors.
- Restart the server and verify smooth, lag-free RTT graphing with `0%` false failure rate, accurate latency/jitter metrics, and accurate Download/Upload speeds.

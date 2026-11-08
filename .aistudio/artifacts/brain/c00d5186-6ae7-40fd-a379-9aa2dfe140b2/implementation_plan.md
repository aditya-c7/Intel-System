# System Load Gauge Badges & Ookla-Grade 15s/15s Speed Test Engine

This plan integrates the four **System load** gauge badges (**Normal** in green, **Moderate** in yellow, **High** in orange, and **Heavy** in red) prominently at the top of the **CPU Activity** panel, and upgrades the **Server Speed Test** to an **Ookla-style multi-stream throughput engine** running **15 seconds for Download** and **15 seconds for Upload** followed by a **10-second cooldown** with accurate high-RTT Vercel compensation.

### User Review & Critical Decisions

> [!IMPORTANT]
> Both of your confirmed preferences are incorporated below. Click **Proceed** to implement these updates across the codebase and rebuild the Vercel bundle.

- **Confirmed Decision 1 (System Load Gauge Badge Placement & States)**: Display the circular **System load** gauge badge prominently at the top of the **CPU Activity** section with all four states:
  - **Normal** (`nominal`): Soft green circle (`#DCFCE7`) with green gauge & left-angled needle (`#15803D`).
  - **Moderate** (`fair`): Soft yellow-amber circle (`#FEF3C7`) with amber-brown gauge & slightly left-angled needle (`#B45309`).
  - **High** (`serious`): Soft orange-peach circle (`#FFEDD5`) with deep orange-brown gauge & right-angled needle (`#C2410C`).
  - **Heavy** (`critical`): Soft red-rose circle (`#FEE2E2`) with crimson red gauge & far-right needle (`#B91C1C`).
- **Confirmed Decision 2 (Ookla-Style 15s Download + 15s Upload + 10s Cooldown Schedule)**: Run a full **15-second Download analysis** and **15-second Upload analysis** to finalize accurate results, pause for a **10-second cooldown**, and then repeat smoothly.

---

### 1. Overview & Core Concept

- **What It Does**:
  1. **System Load Visual Indicator**: Renders the exact gauge icon design from your reference images (semi-circular dial with base line and angled needle inside a tinted circle) beside the **System load** title and live state subtitle (**Normal**, **Moderate**, **High**, **Heavy**).
  2. **Root-Cause Fix for Low Speed Test Readings on Vercel**:
     - Previously, your `~250 ms` HTTP RTT to the serverless function was included inside every small chunk's duration (`requestStart -> responseEnd`), plus an artificial `100 ms` delay between chunks. Over a 250 ms link, waiting 250 ms for TTFB on a 512 KB chunk capped throughput at ~14 Mbps regardless of your actual broadband speed.
     - The upgraded engine uses **Ookla's methodology**: it opens **6 concurrent streams**, uses larger streaming payloads (`1 MB` to `3.5 MB`, safely under Vercel's 4.5 MB cap), removes all artificial sleep delays, measures **pure payload transfer time** (from first byte received `responseStart` to final byte `responseEnd` on Download, and active `xhr.upload.onprogress` byte-stream intervals on Upload, excluding serverless invocation/TTFB wait time), and applies **Ookla's Trimmed Mean** (discarding the bottom 30% TCP slow-start ramp-up samples and top 8% buffer spikes).
- **Target Audience / Persona**: Visitors on any broadband or mobile connection worldwide accessing the Vercel deployment who expect accurate ISP-grade throughput measurements and clear CPU load visual feedback.
- **Key Value**: True broadband Download and Upload speed measurement unaffected by 250 ms serverless RTT, paired with instant visual recognition of system CPU load.

---

### 2. User Experience & Visual Design

- **Key User Flows**:
  1. **CPU Activity System Load Badge**: At the top of the CPU Activity card, the visitor immediately sees the circular **System load** gauge icon and state label (**Normal** in green, **Moderate** in yellow, **High** in orange, **Heavy** in red) alongside Last Observation and Recorded Observations, followed by the 5-minute rolling step-line graph.
  2. **15s Download -> 15s Upload -> 10s Cooldown Speed Test**:
     - **Phase 1 (0s to 15s)**: `Analyzing Download (15s)...` runs 6 parallel streams, smoothly rolling the Download `<OdometerNumber />` every `250 ms` as TCP windows scale up to full line speed, then locks in the finalized Download speed at 15.0 seconds.
     - **Phase 2 (15s to 30s)**: `Analyzing Upload (15s)...` runs 6 parallel upload streams, smoothly rolling the Upload `<OdometerNumber />` every `250 ms`, then locks in the finalized Upload speed at 30.0 seconds.
     - **Phase 3 (30s to 40s)**: `Updated HH:MM:SS` holds the finalized Download and Upload speeds during a 10.0-second cooldown before starting the next cycle.
- **Visual Identity & Theme**:
  - *System Load Gauge SVG*: Custom precision vector gauge matching the reference attachments: a rounded semi-circular meter arch (`stroke-width="2.2"`), flat bottom chord, and a tapered central pointer needle whose rotation angle (`-42°`, `-16°`, `+18°`, `+42°`) and color palette transition smoothly with the active CPU pressure level.

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1: Ookla Trimmed-Mean & Pure Payload Transfer Window Calculation**
  - *Chosen Approach*: Track active byte reception windows (`firstBytePerf -> lastBytePerf` per stream and 500ms sliding-window bandwidth buckets across all 6 concurrent workers). Discard the lowest 30% ramp-up buckets and highest 8% burst buckets to compute the sustained trimmed mean.
  - *Why*: On Vercel Serverless Functions, each HTTP request incurs a 150 ms to 300 ms TTFB routing/invocation delay before bytes begin flowing. Excluding TTFB handshake latency and TCP slow-start ramp-up is the exact reason Speedtest by Ookla reports true broadband capacity instead of RTT-throttled averages.
- **Decision 2: Server Concurrency & Token TTL Scaling (`server.ts` & `api/index.js`)**
  - *Chosen Approach*: Increase `SPEED_TEST_CONCURRENT_STREAMS` allowance on the server to `12` concurrent streams per token, increase `SPEED_TEST_TOKEN_TTL_MS` to `120,000 ms` (2 minutes) so a 30-second test (15s Download + 15s Upload) never expires mid-run, and increase per-stream download/upload caps to `3.5 MB` (safely below Vercel's 4.5 MB limit).
  - *Why*: Ensures 6 parallel streams can overlap and pipeline requests for the full 30-second active test without ever hitting `429 Concurrent stream limit exceeded` or token expiration on Vercel.

---

### 4. Technical Architecture & Data Strategy *(Technical Reference)*

- **Architecture & Component Diagram**:

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                   Intel System Frontend (React + Vite)                     │
│                                                                            │
│  ┌──────────────────────────────────┐  ┌────────────────────────────────┐  │
│  │ NetworkStabilityPanel.tsx        │  │ CpuActivityPanel.tsx           │  │
│  │ • 5m Live HTTP RTT Line Graph    │  │ • System Load Gauge Badge:     │  │
│  │ • Ookla-Grade Speed Engine:      │  │   - Normal   (Green  #15803D)  │  │
│  │   - 15.0s Download (6 streams)   │  │   - Moderate (Amber  #B45309)  │  │
│  │   - 15.0s Upload   (6 streams)   │  │   - High     (Orange #C2410C)  │  │
│  │   - 10.0s Cooldown Pause         │  │   - Heavy    (Red    #B91C1C)  │  │
│  │   - TTFB-Excluded Trimmed Mean   │  │ • 5m Step-Line Graph (Click)   │  │
│  │   - 250ms Odometer Digit Roll    │  │ • W3C PressureObserver ("cpu") │  │
│  └────────────────┬─────────────────┘  └────────────────────────────────┘  │
└───────────────────┼────────────────────────────────────────────────────────┘
                    │ 6 Parallel Streams (x-speedtest-token, <=3.5MB/chunk)
                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│            Vercel Serverless Function (api/index.js <- server.ts)          │
│  • POST /api/network/speed-test/init (120s Token TTL, 12-Stream Allowance) │
│  • GET  /api/network/download        (High-Entropy Binary Stream <=3.5MB)  │
│  • POST /api/network/upload          (Buffered + Stream Receiver <=3.5MB)  │
└────────────────────────────────────────────────────────────────────────────┘
```

- **Data Model & State**:
  - **System Load Badge Mapping (`CpuActivityPanel.tsx`)**:
    - `nominal` -> Display Level `Normal` (Green badge `#DCFCE7`, icon `#15803D`, needle `-42deg`)
    - `fair` -> Display Level `Moderate` (Yellow badge `#FEF3C7`, icon `#B45309`, needle `-16deg`)
    - `serious` -> Display Level `High` (Orange badge `#FFEDD5`, icon `#C2410C`, needle `+18deg`)
    - `critical` -> Display Level `Heavy` (Red badge `#FEE2E2`, icon `#B91C1C`, needle `+42deg`)
  - **Throughput Bucket Sampler (`NetworkStabilityPanel.tsx`)**:
    - Collects active transfer throughput samples every `250 ms` across 6 concurrent streams over the 15-second Download phase and 15-second Upload phase, excluding TTFB wait time (`requestStart` to first byte), and computes the Ookla trimmed mean (60th to 92nd percentile of sustained samples) for live odometer display and finalized results.

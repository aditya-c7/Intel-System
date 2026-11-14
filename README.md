
<div align="center">

# Intel System

### Real-time Visitor Intelligence & Browser Fingerprinting

*Know the visitor. Understand the device. Inspect the network.*

[![Live Demo](https://img.shields.io/badge/Live_Demo-Explore-22C55E?logo=cloudflare&logoColor=white)](https://intel.adityahq.me)
[![Visitor Identity](https://img.shields.io/badge/Visitor_Identity-First--Party-2563EB)](#visitor-intelligence)
[![Threat Signals](https://img.shields.io/badge/Threat_Signals-Multi--Signal-DC2626)](#threat-analysis)
[![Network](https://img.shields.io/badge/Network-Real--Time-0891B2)](#network--device-intelligence)
[![Visit History](https://img.shields.io/badge/Visit_History-Persistent-059669)](#visit-history)
[![Deployment](https://img.shields.io/badge/Deployment-Cloudflare_Workers-F38020?logo=cloudflare&logoColor=white)](https://developers.cloudflare.com/workers/)

</div>

Intel System is a first-party visitor intelligence dashboard that brings browser identity, hardware fingerprinting, network telemetry, and threat signals into one interface.

## Features

### Visitor intelligence
- Persistent Visitor ID (`vid_`) and Hardware ID (`hwid_`).
- Returning visitor and session recognition.
- Visit statistics, observed IPs, and location tracking.
- Hardware-based identity recovery.

### Threat analysis

Four Smart Signals cards rate each visit from `0/10` to `10/10`, and the granular Smart Signals grid breaks the same evidence into individual rows. The server computes both and the dashboard mirrors the rules client-side, so the tiles and the composite meter never disagree.

- **Incognito / Private Browsing** — `Standard Window 0/10` · `Incognito / Private Mode 4/10`; decided by a per-engine storage-physics probe (IndexedDB strict-commit durability, OPFS flush timing and quota headroom on Chromium; blocked OPFS / IndexedDB writes on Firefox and Safari).
- **Bot & Automation Detection** — `Verified Human 0/10` · `Good Bot · Search Crawler 2/10` · `AI Agent · Cloud Browser 8/10` · `Bot / Automated 9/10` · `Spoofed Crawler 10/10`.
  - Bot subtyping separates human, good bot, AI agent and bad bot. A crawler User-Agent only earns `Good Bot` once it is verified against its operator ASN; an LLM / agent crawler UA grades as `AI Agent`; `navigator.webdriver`, CDP bindings, headless rendering and a crawler UA arriving from a non-operator network grade as `Bot / Automated` or `Spoofed Crawler`.
- **VPN / Proxy & Network Type** — `Standard ISP 0/10` · `VPN / Timezone Relay 5/10` · `VPN / Datacenter Proxy 6–8/10` · `Blocklisted IP 9/10` · `Tor Exit Node 10/10`.
  - Tor exits are resolved in real time through the Tor Project DNSEL (`<reversed-ip>.dnsel.torproject.org` → `127.0.0.2`), backed by a cached `torbulkexitlist` fallback and DoH resolution. No external API key is required.
- **Virtual Machine & OS Integrity** — `Physical Hardware 0/10` · `Spoofed Environment 6/10` · `Virtual Machine / VM 7–8/10` · `Mobile Emulator 8/10` · `Tampered / Replayed 10/10`.
  - Mobile emulators and iOS simulators are flagged by cross-checking the User-Agent, `navigator.platform`, touch points, screen width and the WebGL renderer; cloud containers by a masked GPU on a datacenter ASN.
- **Sealed request envelope** — every identification payload carries a SHA-256 signature, a `±60 s` timestamp window and a one-time nonce, with replay detection and a per-IP abuse blocklist. Stale, modified or replayed requests report `Tampered / Replayed 10/10`.
- **Browser tampering** — DevTools Dimensions emulation and anti-detect browsers are caught by cross-checking independent invariants: a mobile User-Agent against `navigator.platform`, the JavaScript engine (`eval.toString().length`, `window.chrome`, `webkitPersistentStorage`), `navigator.maxTouchPoints`, `outerWidth` versus `screen.width`, the unmasked WebGL renderer, `matchMedia('(device-width: …)')` versus `screen.width`, replaced `Navigator.prototype` getters, and the JS versus HTTP User-Agent. An iOS User-Agent with exactly one touch point or a desktop GPU is flagged; a genuine iPadOS `MacIntel` device with real touch points is not.
- **Docked DevTools** — a `160 px` outer/inner viewport delta reports `Developer Tools: Yes`.
- **Active call detection** — WebRTC transceivers with a live audio track, `navigator.audioSession` and a voice-routed `AudioContext` (8 kHz / 16 kHz, or `interrupted`) detect an in-progress call. The row is pruned from the DOM when the platform cannot observe call state.
- **Privacy settings** — Tor Browser RFP, letterboxed viewports, Brave Shields and canvas anti-fingerprinting noise.
- **Velocity and rarity** — SQLite aggregations over `5 minutes`, `1 hour` and `24 hours` windows count distinct IPs, linked sessions, countries, events and per-IP events. `High-Activity Device` trips at 20+ events or 3+ IPs in 24 hours; `Rare Device` compares the device configuration against a 30-day baseline with `p95-p99` and `>p99` buckets.

### Smart Signals grid and risk score
- A granular grid renders one row per signal with deterministic statuses: `Not detected`, `You are incognito`, `You are a bot`, `You are using a VPN`, `Your IP is a Tor exit node`.
- The top-centered Risk Meter shows the Suspect Score on a `0–10` scale, matching every tile. The server also publishes the calibrated additive `0–100` score in the event payload. Weights are additive and clamped: bot 45, replay 35, tampering 25, VPN 14 (plus 4 for multiple methods), blocklist 12, virtual machine 12, proxy 10, simulator 10, active call 10, privacy settings 8, incognito 6, high activity 6, developer tools 5, rare device 4.
- `Analyze my browser` re-runs collection without a page reload, so a DevTools device preset is reflected immediately.
- The Event JSON inspector at `#raw-json` renders and copies the live API v4 payload, including the raw device attributes (fonts, emoji metrics, canvas stability, WebGL hashes, math vector).

### Network & device intelligence
- Public IP, ISP, ASN, and geolocation.
- Interactive Leaflet map.
- Browser, OS, CPU, GPU, memory, and display information.
- Live RTT, jitter, and failed-HTTP-probe monitoring (5s while visible, paused when hidden or offline) on a fixed `0–1000 ms` axis.
- CPU pressure monitoring through the W3C Compute Pressure API, with a 1 Hz heartbeat so a steady load never freezes the timeline; the panel is pruned on mobile and unsupported browsers.
- Cursor attribution overlay: the pointer carries a `Human`, `Brave`, `Instinct`, `Claude-User`, `Gemini`, `Grok`, `Perplexity`, `Muse` or `ChatGPT-User` pill, and remote agents that click or focus without moving a pointer are attributed at the interacted element.

### Visit history
- Persistent first-party visit records.
- Session, timestamp, IP, location, and device details.
- Latest five visits by default with `Show next 5 visits` and `Collapse to latest 5`.
- Server-signed history backup for serverless continuity.

> Browser fingerprinting and threat detection rely on heuristic signals. Results can vary with browser privacy settings, proxies, extensions, and platform capabilities.

Deployment, storage and cost details are documented in [CLOUDFLARE.md](./CLOUDFLARE.md).

## Tech

React 19 · TypeScript · Tailwind CSS v4 · Vite · Express · Cloudflare Workers · SQLite-backed Durable Objects · Leaflet


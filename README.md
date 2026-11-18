<div align="center">

# Intel System

### Real-time Visitor Intelligence & Browser Fingerprinting

*Know the visitor. Understand the device. Inspect the network.*

[![Live Demo](https://img.shields.io/badge/Live_Demo-Explore-22C55E?logo=cloudflare&logoColor=white)](https://intel.adityahq.me)
[![Visitor Identity](https://img.shields.io/badge/Visitor_Identity-First--Party-2563EB)](#what-it-does)
[![Threat Signals](https://img.shields.io/badge/Threat_Signals-Multi--Signal-DC2626)](#what-it-detects)
[![Network](https://img.shields.io/badge/Network-Real--Time-0891B2)](#dashboard)
[![Visit History](https://img.shields.io/badge/Visit_History-Persistent-059669)](#dashboard)
[![Deployment](https://img.shields.io/badge/Deployment-Cloudflare_Workers-F38020?logo=cloudflare&logoColor=white)](https://developers.cloudflare.com/workers/)

</div>

## What it does

Intel System turns a browser visit into an explainable intelligence profile. It combines first-party identity signals, hardware and rendering fingerprints, network telemetry, privacy indicators, and behavioural context to assess whether a visitor is human, automated, private, proxied, or emulated.

Identity is resolved in three layers: a persistent Visitor ID, a deterministic hardware fingerprint, and a browser fingerprint. The server matches them through exact, hardware, cross-browser, and lenient modes, returns the winning mode with a calibrated confidence score, and records the visit as history.

Every analysis runs through a signed first-party API request, is scored across granular signals, and is rendered in a real-time dashboard.

## Why it's different

- **First-party and transparent:** visitor signals are collected and processed through your own API, with no third-party tracking dependency.
- **Tri-layer identity:** a persistent Visitor ID, a hardware-only fingerprint, and a browser-only fingerprint are matched independently, so a visitor is still recognised after a browser change while a genuinely new device stays new.
- **Multi-layer analysis:** combines browser identity, hardware fingerprints, network intelligence, privacy settings, and behavioural signals.
- **Explainable scoring:** each signal has a visible status and score, the four core cards rate `0/10` to `10/10`, and the API payload also carries a `0-100` composite with the velocity, rarity and tampering evidence behind it.
- **Persistent visitor history:** a storage waterfall (localStorage, IndexedDB, cookie mirror, HTTP cache) keeps the visitor ID through storage wipes, a server-signed backup restores history when the store is empty, and hardware-ID recovery covers private windows where DOM storage starts blank.
- **Serverless with a write budget:** only `POST /api/visitor/identify` writes to the Durable Object; health and RTT ping are answered statelessly, and every read and write degrades gracefully instead of returning a `500` when the daily write quota is exhausted.

### Local Worker verification

Verify the Worker locally with `node scripts/test-worker.mjs`, and build it with `npm run build` and `node scripts/build-worker.mjs`; see [CLOUDFLARE.md](./CLOUDFLARE.md#local-worker-verification).

## What it detects

| Area | What Intel System checks |
|---|---|
| Visitor identity | Persistent Visitor ID, hardware fingerprint, browser fingerprint, returning visitors, exact, hardware, cross-browser, and lenient matches, calibrated confidence, sessions, visit totals, observed IPs, and geolocation history |
| Incognito / private browsing | IndexedDB durability, OPFS flush timing, and storage quota behaviour |
| Bots and automation | User-Agent and Client Hints consistency, operator ASN, reverse DNS, WebDriver and CDP bindings, headless-rendering signals, and a weighted evidence gate so weak quirks never mark a person automated |
| AI agents and crawlers | ChatGPT-User, OAI-SearchBot, GPTBot, ChatGPT Agent, Codex, Gemini Deep Research, Google-Agent, Google NotebookLM, Claude-User, Claude-SearchBot, ClaudeBot, Claude Code, Claude Duet, Perplexity-User, PerplexityBot, Grok Bot, Meta-ExternalAgent, Meta-WebIndexer, Muse, Kimi-User, Cursor, Manus Agent, AGI Agent, Browserbase Agent, Anchor Browser, Notte Browser, Bedrock AgentCore, Cloudflare Browser Rendering, DuckAssistBot, Instinct, and verified Googlebot traffic, with operator and execution-mode attribution |
| Remote browser agents | Firecrawl, Browserbase, Browser Use, Skyvern, MultiOn, Hyperbrowser, Steel, Airtop, Notte, Lightpanda, Browserless, and managed scraping fleets |
| VPN, proxy, and Tor | Cloudflare edge country, Tor exit nodes (`T1` plus DNSEL), Tor relays, datacenter ASN, timezone mismatch, proxy headers, forwarded-IP chains, and exit-node location reported separately from the visitor |
| Network classification | Tor anonymity network, AI-agent cloud network, datacenter or hosting ASN, VPN or proxy relay on a residential line, cellular, satellite, and standard ISP traffic |
| Hardware and rendering entropy | CPU cores, memory, GPU vendor and renderer, max texture size, canvas stability, WebGL limits and hashes, audio fingerprint, font inventory, font preferences, emoji metrics, and math vectors |
| Virtual machines and emulators | GPU vendor and renderer, platform, touch points, screen dimensions, and emulator markers |
| Browser tampering | DevTools device emulation, anti-detect browsers, replaced Navigator getters, and JavaScript versus HTTP User-Agent or Client Hints mismatches |
| Developer tools | Docked DevTools through outer and inner viewport differences |
| Active calls | WebRTC audio tracks, `navigator.audioSession`, and voice-routed AudioContext state |
| Privacy settings | Tor Browser RFP, letterboxed viewports, Brave Shields, and canvas anti-fingerprinting noise |
| Behaviour and rarity | Distinct IPs, linked sessions, countries, and events across 5-minute, 1-hour, and 24-hour windows; high activity at 20+ events in 24 hours and rare-device comparison against a 30-day baseline with at least 20 visits |

The four core cards and the granular signal grid rate visits from `0/10` to `10/10`. The server computes both views, and the dashboard mirrors the same rules client-side so the displayed scores stay consistent. The payload also exposes the `0-100` composite and the velocity, rarity and tampering inputs behind it.

<details>
<summary><strong>Sealed request and tamper protection</strong></summary>

Every payload includes a SHA-256 integrity hash over a canonical `INTEL_ENVELOPE_V1` string, a 5-minute freshness window, and a one-time nonce with a 15-minute replay cache. Stale, modified, or replayed requests are reported as `Tampered / Replayed 10/10`.

Browser-tampering checks cross-reference the mobile User-Agent with `navigator.platform`, the JavaScript engine, `navigator.maxTouchPoints`, `outerWidth` versus `screen.width`, the unmasked WebGL renderer, `matchMedia` versus `screen.width`, replaced `Navigator.prototype` getters, and the JavaScript-versus-HTTP User-Agent. High-entropy Client Hints (`Sec-CH-UA-Platform-Version`, `Sec-CH-UA-Arch`, `Sec-CH-UA-Model`, and `Sec-CH-UA-Full-Version-List`) are normalised on the server, so Windows 11 is not mistaken for Windows 10 and Android versions come from the platform version rather than the reduced UA string. A genuine iPadOS `MacIntel` device with real touch points remains clean.

Proxy signals include `Proxy-Authorization`, `Proxy-Connection`, a non-CDN `Via` header, an upstream `Forwarded` address, and a three-hop public `X-Forwarded-For` chain. The dashboard identifies the proving header when proxy detection triggers.

Only `POST /api/visitor/identify` writes to storage. `GET /api/health`, `GET /api/network/ping`, and `GET /api/intel/geolocation` perform no row writes, and a blocked daily write quota returns a normal `200` with cached or signed-backup data instead of an error.

Location is resolved from Cloudflare `request.cf` first, then a provider consensus, and a map pin is drawn only when its coordinate fits the reported country. For Tor, VPN and proxy traffic the city and pin describe the egress node and are labelled as such, never as the visitor's physical location.

</details>

## Dashboard

- **Identity header:** visitor and hardware identity, returning or first-seen state, calibrated confidence with version, the winning match mode, and the consistency verdict.
- **Risk meter:** the Suspect Score and risk tier, next to the four core cards for incognito, automation, network, and virtualisation.
- **Visitor overview:** device tiles for browser, OS and device, display, locale and timezone, active session, first and last seen, plus public IP, location, ISP and ASN, recognition source, and phone model when the device exposes one.
- **Hardware & rendering entropy:** browser, OS, CPU, GPU, memory, display, fonts, emoji metrics, canvas stability, WebGL hashes, and math-vector attributes.
- **Smart Signals & threat analysis:** deterministic signal rows, four core risk cards, and a granular signal grid.
- **Network stability & CPU activity:** public IP, ISP, ASN, interactive Leaflet geolocation map, live RTT, jitter, packet loss, failed HTTP probes, and Compute Pressure-based CPU activity on desktop Chromium.
- **Visit history:** persistent session, timestamp, IP, location, and device records; latest five visits by default with expand/collapse controls.
- **Event JSON inspector:** renders and copies the live API v4 payload, including raw device attributes and identity layers.
- **Cursor attribution overlay:** appears only for non-human visitors. It identifies agents such as Gemini, Grok, Claude, Perplexity, ChatGPT, and Muse, while human visitors retain the native cursor.

## How it works

```mermaid
flowchart TD
  subgraph Browser["Browser"]
    direction TB
    C1["Signal<br/>collectors<br/>canvas, WebGL,<br/>audio, fonts,<br/>emoji, math"]
    C2["Device, privacy,<br/>tampering,<br/>active calls"]
    C3["RTT and CPU<br/>pressure"]
    C4["Storage<br/>waterfall<br/>localStorage,<br/>IndexedDB,<br/>cookie, HTTP<br/>cache"]
    ID["Tri-layer<br/>identity"]
    ENV["Sealed<br/>envelope<br/>timestamp,<br/>nonce, SHA-256"]
    C1 --> ID
    C2 --> ID
    C4 --> ID
    ID --> ENV
  end

  subgraph Validate["Request validation"]
    direction TB
    V1["Verify hash"] --> V2["Check window"] --> V3["Check nonce"]
  end

  subgraph Intel["Intelligence layer"]
    direction TB
    NET["Edge geo, ASN,<br/>Cymru, DNSEL"] --> CLASSIFY["Bot, AI agent,<br/>proxy, VM"]
    CLASSIFY --> RESOLVE["Identity<br/>resolver"]
    RESOLVE --> SCORE["Signal<br/>scores<br/>0-100"]
  end

  ENV --> ROUTE["Cloudflare<br/>Worker"]
  ROUTE -->|"identify"| API["POST<br/>/api/visitor/<br/>identify"]
  ROUTE -->|"geolocation"| GEOAPI["GET<br/>/api/intel/<br/>geolocation"]
  ROUTE -->|"health, ping"| EDGE["Stateless<br/>response"]

  API --> V1
  V3 -->|"valid"| NET
  V3 -->|"stale/replay"| REJECT["Tampered 10/10"]

  NET -->|"cache write"| GEO[("Geo cache")]
  GEOAPI -->|"cache read"| GEO
  SCORE --> PERSIST["Persist visit<br/>and identity"]
  PERSIST --> DO[("Durable Object<br/>SQLite")]
  DO --> RESPONSE["Identity,<br/>confidence,<br/>history,<br/>backup"]
  RESPONSE --> UI["Dashboard and<br/>Event JSON v4"]
  C3 --> UI
```

One signed payload goes in. The Worker verifies it, resolves the network through edge headers, a bundled ASN registry, and Team Cymru DNS, classifies the visitor, resolves identity through the fingerprint ladder, scores every signal, stores the visit, and returns the same evidence the dashboard renders. Health, RTT ping, and history reads are answered without a row write.

## Try it

Open the [live demo](https://intel.adityahq.me) and select **Analyze my browser**.

| Test | What to observe |
|---|---|
| Normal browsing | Identity, device, network, and signal panels populate with a low-risk profile |
| Incognito or private window | Privacy and storage-related signals change |
| VPN or proxy | Network type, ASN, timezone, and proxy signals are reassessed |
| DevTools device emulation | Tampering and device-consistency signals respond immediately |
| Repeated visits | Visitor recognition, visit totals, and history update |
| Reload in a second browser | The hardware fingerprint can still resolve the same visitor through a cross-browser match |

## Tech stack

![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-7-3178C6?logo=typescript&logoColor=white)
![Express](https://img.shields.io/badge/Express-API-000000?logo=express&logoColor=white)
![Cloudflare Workers](https://img.shields.io/badge/Cloudflare_Workers-Edge-F38020?logo=cloudflare&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Durable_Objects-003B57?logo=sqlite&logoColor=white)
![Leaflet](https://img.shields.io/badge/Leaflet-Maps-199900?logo=leaflet&logoColor=white)

## Deployment

Deployment, storage, and cost details are documented in [CLOUDFLARE.md](./CLOUDFLARE.md). Only `/api/visitor/*` and `/api/intel/geolocation` reach the Durable Object; `/api/health` and `/api/network/ping` are answered statelessly, so periodic monitors and the 5-second RTT probe never consume row writes.

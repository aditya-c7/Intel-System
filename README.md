
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
- Incognito and storage-persistence signals.
- Bot and browser automation detection.
- VPN, proxy, and datacenter indicators.
- Virtual machine and software-rendering detection.
- Explainable risk scoring and trust meter.

### Network & device intelligence
- Public IP, ISP, ASN, and geolocation.
- Interactive Leaflet map.
- Browser, OS, CPU, GPU, memory, and display information.
- Live RTT, jitter, and failed-HTTP-probe monitoring (5s while visible, paused when hidden or offline).
- Manual one-shot speed tests with server-enforced budgets, cooldown, cancellation, and a kill switch.
- CPU pressure monitoring through the W3C Compute Pressure API.

### Visit history
- Persistent first-party visit records.
- Session, timestamp, IP, location, and device details.
- Server-signed history backup for serverless continuity.

> Browser fingerprinting and threat detection rely on heuristic signals. Results can vary with browser privacy settings, proxies, extensions, and platform capabilities.

Speed tests are estimates for the path to this server, not guaranteed ISP line speeds. One explicit Start runs one bounded download phase and one bounded upload phase (16 MiB / 8 MiB and 8 s / 6 s by default), then stops. There is no automatic repeat and no hidden-tab transfer. Limits, runtime configuration, durable quotas, and cost tradeoffs are documented in [CLOUDFLARE.md](./CLOUDFLARE.md).

## Tech

React 19 · TypeScript · Tailwind CSS v4 · Vite · Express · Cloudflare Workers · SQLite-backed Durable Objects · Leaflet


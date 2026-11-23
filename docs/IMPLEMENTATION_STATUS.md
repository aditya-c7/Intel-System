# Implementation status (post-integration-wave, incl. remaining-fix wave)

This document records what is **actually present in the tree** after the current integration
and remaining-fix waves. It is a presence/absence report, not a quality or deployment guarantee.
It deliberately does **not** claim a feature is live because a file for it exists.

Scope note: the wave is composed of the commits ending at `e881115`
(`fix(ci): skip browser harness when system Chrome cannot launch`), including `ac8d220`
(`feat(v3): integrate SOTA truth signals across collector, edge, server and UI`) and `a550397`
(`fix(p0): correct incognito physics, bot/CDP flags, spoofed identity and UA coherence`),
**plus a set of still-uncommitted working-tree changes** — the *remaining-fix wave*. That
uncommitted set is in active flux (files and call sites appear and change between reads);
classifications below are by *code path*, and the file list at the moment of writing is reported
in [Appendix A](#appendix-a-working-tree-at-time-of-writing). Nothing here was committed, pushed,
or built by the author of this document. Where a helper is only imported (or only called by its
own test), that is stated explicitly rather than implied to be live.

---

## 1. Locked constraints (do not relax without an explicit decision)

These are the invariants of the wave. Each is enforced in code or in the deploy procedure, not
just stated here. The remaining-fix wave preserves all six.

| # | Constraint | What it means in this tree | Where it is held |
|---|---|---|---|
| 1 | **0–10** | The four core cards keep their explicitly labelled `0/10`–`10/10` per-card scale. The single risk truth is the canonical `0–100` orthogonal ledger; `score10`, `risk_tier` and `riskBadgeText` are mirrors *of* that ledger, never a second computation. No new numeric scale was introduced. The new extra-evidence lines carry `points: 0`, the active-CDP reason is `developer_tools` / weight 0, and audio stability is excluded from the hardware-id seed — none of them add points or rotate an id. | `src/lib/telemetryContract.ts` (`canonicalScore10`, `riskTier`, `assertIntegratedConsistency`), `src/components/canonical.ts`, `api/index.js` / `worker/index.js` ledger mirrors, `src/components/SmartSignalsGrid.tsx` (reads the canonical headline; local derivation only as a legacy fallback), `src/lib/riskEvidenceExtra.ts`, `src/lib/verdict.ts` |
| 2 | **Uncalibrated** | Confidence stays `uncalibrated` by default. The gate requires **≥ 200 human-labeled pairs AND held-out ECE ≤ 0.05**; until both hold, labels read `Match evidence X%`, never `Confidence X%`. No labeled corpus exists in this repo, so nothing is calibrated today. `confidenceStability.ts` quantizes a score for *stability* only and explicitly owns no calibration gate. | `src/lib/rarityHonesty.ts` (`CALIBRATION_MIN_LABELED_PAIRS = 200`, `CALIBRATION_MAX_ECE = 0.05`, `calibrationStatusFor`, `confidenceLabel`), `src/lib/confidenceStability.ts` (`CALIBRATION_GATE_OWNER = 'rarityHonesty.calibrationStatusFor'`) |
| 3 | **Zero alarms** | No Durable Object alarms, cron triggers, timers or scheduling of any kind were added. Health and ping are answered on request; the DO is warmed on first fetch, not by a scheduled event. | `worker/index.js` ("No alarms / crons are used — this is the only bootstrap path"), `src/lib/velocityThresholds.ts`, `src/lib/identityTiers.ts` |
| 4 | **No new panels** | No new dashboard panel/component was added in this wave. Additive fields are verbatim transports into **existing** tiles/rows/detail views (e.g. the GPU-truth gate and privacy/proximity readouts inside `SmartSignalsGrid` and the mirrors in `App.tsx`); `intelDiag` diagnostics add no UI at all. | `src/App.tsx` and `src/components/SmartSignalsGrid.tsx` change only existing views; no new panel component exists in the wave's diff |
| 5 | **Manual deploy** | CI verifies and dry-runs only; there is no `wrangler deploy` step and no push/hosted auto-deploy. A human runs the command in §5 after verification passes. | `CLOUDFLARE.md` "Deploy"; `.github/workflows/cloudflare.yml` `verify` job only |
| 6 | **Zero SDK** | The wave adds no third-party SDK. New modules are pure, dependency-free, do no I/O/network/DOM probing and never throw on hostile input. Existing project dependencies (e.g. Leaflet) are unchanged. | Header comments of `src/lib/audioTruth.ts`, `src/lib/gpuTruth.ts`, `src/lib/geoProximityBridge.ts`, `src/lib/privacyNoise.ts`, `src/lib/confidenceStability.ts`, `src/lib/activeCdp.ts`, `src/lib/identityScope.ts`, `src/lib/riskEvidenceExtra.ts`, `src/lib/antiDetectExemption.ts`, `src/lib/mediaPreferences.ts`, `src/lib/entropyMatrix.ts`, `src/lib/calibrationEngine.ts` |

---

## 2. Live / integrated (in a production code path)

| Feature | State | Notes |
|---|---|---|
| Canonical single-source risk | **Live** | One `0–100` ledger (`score_0_100`, `tier`, evidence ledger) is the risk truth. `score10`/`risk_tier`/`riskBadgeText` mirrors are published from it in `api/index.js`; the dashboard binds panels and the Event JSON inspector to the envelope and does not recompute risk client-side. |
| 0–10 core cards | **Live** | Incognito / automation / network / virtualisation cards keep their labelled per-card `0/10`–`10/10` scale. |
| Evidence-based identity confidence, uncalibrated | **Live** | `src/lib/rarityHonesty.ts` publishes a deterministic score for real matches and `null` for unseen profiles; uncalibrated wording is used. No calibrated claim is emitted. |
| Real-incognito recognition + mobile false-automation fix | **Live** | Committed in `1182be2` / `3cc9623`. |
| IDB durability resolver + marker-veto guard | **Live** | `src/lib/idbDurabilityTruth.ts` `resolveIdbDurabilityTruth` plus new `shouldApplyMarkerVeto`, consumed by `src/lib/collector.ts` `applyPersistentMarkerVeto`, so a decisive RAM-backed verdict is not erased by a private-session marker. |
| UA normalization: Arc, Vivaldi, crawler/AI-agent tokens, bare Chromium 156 token | **Live** | `src/shared/normalization/uaNormalizer.ts` and its compiled copy in `api/index.js`. Ordering keeps existing classifications unchanged; ASN sample-prefix update is also in the compiled bundle. |
| Worker edge behaviour | **Live** | SSR verdict injection, `run_worker_first`, canonical redirects, WBA verification, signed `intel_wba` cookie, native rate-limit binding, Durable Object for `/api/visitor/*` + `/api/intel/geolocation`, stateless `/api/health` + `/api/network/ping`, pass-through asset/metadata paths. Documented in `CLOUDFLARE.md`. |
| Additive edge hardening | **Live** | JA4H-style header recomputed from real inbound headers (`x-intel-ja4h`), lower-case bot-verdict header aliases, and `apiResponseWithVerdict` on the 429/503/500 API paths. |
| Optional strict origin check | **Live but off by default** | Only the exact `intelStrictOrigin=1` query flag activates it; otherwise a no-op, and missing/unparseable Origin fails open. Native routes, `/assets/*` and pass-through files are excluded. |
| RTT single-leader lease / CI stability | **Live** | Commits `565bf77`, `4ac3daf`, `bc52ffe` publish one canonical headline and avoid duplicate/mount-time polling. |
| Flag-gated incognito diagnostics pass-through | **Live code path, opt-in, inert** | `intelDiag=1` → `x-intel-diag: 1` → server echo → `window.__intelDiag()`. Off by default, adds no UI, never affects a verdict or score. See §7. |
| Additive mirrors read by existing UI | **Live transport only** | `proxy_details`, `vpn_methods`, `privacy_settings`, `stealth_ids`, `tampering_details`, `network_layer_hash`, `idbTruthRule` are verbatim passes into existing views; missing values stay absent. They are not new signals and do not change tiers. |
| **Audio identity stability** (remaining-fix wave) | **Live in collector** | `src/lib/audioTruth.ts` `classifyAudioStability` + `audioAnchorValue` are called by `src/lib/collector.ts` `computeWebAudioSignature`. The render sum is an exact IEEE754 pass-through (no `toFixed`/requantization), so the legacy `124.04347745512496` anchor keeps its bits. Repeat-read divergence, wrapped `getChannelData`, a `copyFromChannel` mismatch or a silent buffer rendering non-zero yields `noisy`/`usableForIdentity: false`. **Any audio-derived value (float, hash or stability class) was removed from the hardware-id seed** — noise cannot rotate an id and never drops a confidence score. `noiseReasons`, `tamperingInconclusive` and `audio_stability_class` are telemetry/mirrors only. |
| **GPU truth from spoofable strings** (remaining-fix wave) | **Live in collector + UI gate** | `src/lib/gpuTruth.ts` `resolveGpuTruthState` is called by `collector.ts` `collectHardwareSignals`. Masked (`gl.VENDOR`/`gl.RENDERER`) and unmasked (`WEBGL_debug_renderer_info`) strings are now captured separately, with `debugExtensionAvailable` and a capability-derived `shaderPrecisionProfile`. The five states are `hardware` / `software_renderer` / `masked` / `spoofed_suspect` / `unknown`; **SwiftShader/llvmpipe is a capability, never a VM verdict**. `hardware` requires a real unmasked manufacturer identifier. `SmartSignalsGrid.resolveVmVerdict` blocks a "Physical Hardware" label when the mirror is masked/spoofed/unreliable and substitutes "Masked / Unverified" or "Unavailable / Browser-Restricted". `tamperingDetector.ts` publishes `gpu_answer_unreliable` as a 0.5 shadow warning, never a hardware anchor. (`server.ts` imports the resolver but has no call site in this snapshot.) |
| **Geolocation permission bridge** (remaining-fix wave) | **Live in server** | `src/lib/geoProximityBridge.ts` `resolveProximity` is called by the `server.ts` identify route. Permission must be **exactly** `'granted'` plus finite lat/lon and `accuracyM > 0`; `ipCity` is accepted for shape compatibility but never read, so there is **no IP fallback** and no IP→confidence path. The result (`honestProximity`, accuracy-derived confidence) is published as `proximity` in the envelope/response and omitted entirely when denied/invalid. The `SmartSignalsGrid` proximity tile now requires granted permission **and** real browser coordinates; an IP-derived zone is never proximity evidence. (`proximityBodyField` is not called — see §3.) |
| **Privacy noise suppression** (remaining-fix wave) | **Live in collector + server + tampering** | `classifyPrivacyNoise` is called in `collector.ts` and `server.ts`; `resolveAntiDetectExemption` is called in `server.ts`, where `reconciledAntiDetectBrowser` is set from the privacy-noise verdict and the exemption. Only a `privacyHardened` posture or an allowlisted vendor signature fires `privacy_settings`; only `hardContradiction` sets `anti_detect_browser` and a non-zero anomaly score; privacy posture + `noiseOnly` can suppress the legacy penalty. `tamperingDetector.ts` (T9/T11) keeps canvas farbling as a tamper signal but adds no anomaly points and no anti-detect flag under privacy hardening, strips 0.5 soft warnings from the shadow score, and keeps `cdc_*`/webdriver/CDP artifacts artifact-only. `privacy_signature_ids` are published as informational mirrors. |
| **Active CDP inspection** (remaining-fix wave) | **Live, neutral** | `src/lib/activeCdp.ts` `resolveActiveCdp` is called in `server.ts`; its neutral `state` and `reasons` are published as `active_cdp_inspection` / `active_cdp_reasons` mirrors. `server.ts` now passes `activeCdpInspection` into `composeBotVerdict` and `decideVerdictTier`, so the weight-0 reason `bot.cdp-active-inspection` and the separate `protocol_inspection_state` / `inspection_state` axis are live. It can never become a bad-bot verdict. |
| **Headless shell / new granularity** (remaining-fix wave) | **Live** | `src/shared/normalization/uaNormalizer.ts` adds `headless_mode: 'shell' \| 'new' \| null` (P2-17), derived from raw UA/UA-CH/Sec-CH tokens and independent of `resolveBrowser`. `server.ts` publishes `headless_mode` verbatim in the envelope and identify response (the legacy boolean `isHeadless` remains for compatibility). |
| **Extra evidence lines, `points: 0`** (remaining-fix wave) | **Live** | `src/lib/riskEvidenceExtra.ts` `buildExtraEvidenceLines` emits fixed-order, informative `ExtraEvidenceLine`s (a `RiskEvidenceLine` subtype) with `points: 0`. `server.ts` appends them to `riskLedger.evidence_ledger` **after scoring**, so they are visible in the Event JSON and cannot change the 0–100 composite, 0–10 headline or tier. |
| **Confidence stability** (remaining-fix wave) | **Live** | `src/lib/confidenceStability.ts` `stabilizeConfidence` quantizes a `(visitorId, hardwareId)` pair's `rawScore` to `STABILITY_QUANTUM = 0.05`, ignoring volatile bot/audio/privacy/network channels, and never reads or emits a calibration status. `server.ts` calls it in the identity-confidence path and publishes `confidence_stability_key`; `calibration_status` remains solely owned by `rarityHonesty`. |
| **Identity scope metadata** (remaining-fix wave) | **Live** | `src/lib/identityScope.ts` `resolveIdentityScope` reports `id_scope: 'hardware' \| 'context'` and `context_isolated`, with an explicit context salt as the sole isolation proof (incognito alone is never isolation). `server.ts` calls it from incognito/storage/hardware-anchor state and publishes both fields in the envelope and identify response. |
| **Media preferences** (remaining-fix wave) | **Live** | `src/lib/mediaPreferences.ts` `resolveMediaPreferences` produces an informational `matchMedia` record (theme/motion/contrast/locale/timezone) that is never a verdict, score or identity seed. `collector.ts` feeds it from real `matchMedia`/locale/timezone probes and `server.ts` publishes `media_preferences` verbatim in the envelope and identify response. |

---

## 3. Shadow-only (present, but not a verdict/score input and not promoted)

| Item | What it is | Why it is not live |
|---|---|---|
| `src/lib/calibrationEngine.ts` | Additive evidence record (four weighted signals → descriptive `evidence_score`) plus `confidenceLabelFor`. Owns **no** gate of its own; `calibration_status` comes only from `rarityHonesty`. | Not imported by any production module; referenced only by its own test (`scripts/test-calibration-engine.ts`). Purely descriptive — explicitly cannot promote a record to calibrated. Ships as `uncalibrated`. |
| `src/lib/entropyMatrix.ts` | Pure FingerprintJS-v5-style entropy normalizers (fonts, emoji, WebGL, audio, canvas, keyboard, CSS, math, DOM blockers). No probing, no hashing, no scoring. | Its own header states: "Nothing in production imports this module yet; it is a shadow evaluation surface only." Test: `scripts/test-entropy-matrix.ts`. |
| `tampering_lies` in `src/lib/tamperingDetector.ts` | Additive cross-scope "tampering lie" verdict from `resolveTamperingLies`. | Explicitly never consumed by the canonical `tampering` verdict, `anti_detect_browser` flag, ML score, risk score or verdict tier. Empty/zero when no observations are supplied. (The T9/T11 *privacy-noise* corrections in the same file are live — see §2.) |
| `assertIntegratedConsistency` in `src/lib/telemetryContract.ts` | Pure, non-throwing parity check across risk mirrors. | Defined and unit-tested but not wired into a live gate; it reports issues, it does not enforce them. |
| Stealth-signal → taxonomy bridge (`stealthReasonId`, `STEALTH_SIGNAL_REASON_IDS` in `verdict.ts` / `botVerifier.ts` and the compiled bundle) | Mirrors stealth probe ids into the **existing** four-tier reason taxonomy (no second vocabulary). | These are mapping helpers/parity code. `composeBotVerdict` in `botVerifier.ts` is called by `server.ts`, but no live producer feeds its `stealth` input; treat the folded stealth reasoning there as parity work, not a deployed detector change. The client-side stealth artifacts in `collector.ts` remain the existing detection path. |
| Additional shadow truth modules (`identityTiers.ts`, `networkEdge.ts`, `proximityAdapter.ts`, `vmIntegrity.ts`, `zeroTrust.ts`, `hexProximity.ts`, `velocityThresholds.ts`, `privacySignatures.ts`, `stealthSignals.ts`, `tamperingLies.ts`, `specInvariants.ts`) | Dependency-free, total functions over untrusted input; no alarms, no SDK, no I/O. | Evaluation surfaces with dedicated shadow test scripts; additive and not wired to a new verdict, panel or alarm. `specInvariants.ts` is the pure home for GPU-observation/inspector invariants used by helpers, not a new verdict. |
| `intelDiag` diagnostics bundle | Console-only hook, collector probes, server echo, header mirror. | Additive and flag-gated; never scored, no UI. It is a capture facility, not a feature. |
| `proximityBodyField` in `src/lib/geoProximityBridge.ts` | Returns a fresh, namespaced `hex_proximity` body field for a v4 API body, never an IP-derived field. | The bridge's `resolveProximity` is live in `server.ts`, but this emitter has no call site in this snapshot; the server spreads the resolved `proximity` object directly. |

---

## 4. Backlog / explicitly not present

- **Calibration.** There is no labeled-pair corpus (≥ 200) and no held-out ECE measurement (≤ 0.05). All identity confidence therefore remains uncalibrated; `confidenceLabelFor` will return `Match evidence X%` in production until such data exists. Do not claim calibrated confidence.
- **Promotion of remaining shadow modules.** `entropyMatrix`, `calibrationEngine` and other pure evaluators remain shadow-only. `riskEvidenceExtra`, `confidenceStability`, `identityScope` and `mediaPreferences` were promoted in the final wiring pass and are now live (see §2).
- **Additive transport fields.** `gpu_truth_state`, `headless_mode`, `id_scope`, `context_isolated`, `audio_stability_class`, `confidence_stability_key` and `media_preferences` are now produced by collector/server and published verbatim in the envelope and identify response. A missing value still reads as "no data", never as a verdict.
- **Verdict-side active-CDP state is neutral by design.** `server.ts` now passes `activeCdpInspection` into `composeBotVerdict` and `decideVerdictTier`, but the reason is weight-0 `developer_tools` and the state is a separate axis — it can never create a bad-bot verdict.
- **No auto-deploy, no new panels, no alarms, no SDK.** These are locked out by design (§1), not deferred tasks to be silently added.
- **Live verification of this wave is still pending.** The build/CI/dry-run steps must pass and a human must deploy (§5); only then can the live endpoints and Cloudflare metrics be checked. A local build is not proof of a successful production deployment.
- **No verified production state is asserted here.** This document makes no claim about what is currently serving on `intel.adityahq.me`.

---

## 5. Manual deploy command

Deployment is **manual only** — there is no auto-deploy. Run the full sequence locally only after
CI verification passes (verbatim from `CLOUDFLARE.md`):

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

Notes: use Node.js 22.12+; the CI `verify` job (`npm ci`, lint, build, Worker bundle, dry-run,
local Worker tests) never publishes. Wrangler also runs `npm run build` and
`scripts/build-worker.mjs` at deploy time from `wrangler.jsonc`. Keep `VISITOR_HMAC_SECRET` private
(≥ 32 chars, stable across deploys, never committed); a missing/short value returns JSON 503 and
disables the `intel_wba` cookie. Do not deploy only `dist/` or use an assets-only command.

---

## 6. Benchmark report location (shadow/offline)

The frozen benchmark corpus and its harness are the report surface for the truth/helper modules:

- **Harness:** `scripts/test-benchmark15.ts`, run with `npx tsx scripts/test-benchmark15.ts`.
- **Frozen fixture:** `scripts/fixtures/benchmark15.json` (`schema_version: 1`, `frozen: true`, 15 cases).
- **Output:** a per-case PASS / FAIL / SKIP trace followed by a `RESULT` line on **stdout**. The harness
  writes **no report file** — the console output is the report. A missing helper is reported as SKIP
  with an explicit reason; any FAIL exits non-zero.
- **Policy:** SHADOW-OFFLINE — pure, already-in-repo helper modules only; the only I/O is reading the
  frozen fixture. No live requests, browser, deploy, writes, timers or randomness. Expectations are
  golden: never edit an expected value to make a case green — fix the implementation instead.

This harness and fixture are also the regression reference for the additive modules added in the
remaining-fix wave (most of which are now wired into production — see §2); a passing local benchmark
is not a production-deployment signal.

---

## 7. Diagnostics capture procedure (shadow, manual, opt-in)

Gated by the same deploy rules — deploy only via §5; no auto-deploy.

1. Open <https://intel.adityahq.me/?intelDiag=1> in a **real private/incognito window** (not a regular tab with a spoofed user agent).
2. Open the browser console and run `window.__intelDiag()`.
3. Paste the returned JSON into your report.

The `intelDiag` flag is off by default, adds no UI, and does not affect any verdict or risk score.
Never include tokens or secrets in the captured JSON or the report. For local verification:
`node scripts/test-worker.mjs`, `npm run build`, `node scripts/build-worker.mjs`.

---

## 8. Phase-by-phase table

Chronological (oldest first). "Class" = LIVE, SHADOW or MIXED as defined above.

| Phase | Commit(s) / state | What landed | Class |
|---|---|---|---|
| A — Truth & scoring baseline | `3cc9623`, `7fbb8b1`, `1182be2`, `b11488e`, `565bf77` | Mobile false-automation fix; evidence-based match percentage with consistent risk math; honest confidence percentage + real incognito recognition; single-source risk/confidence/timezone/GPU/inspector truth with release harness; canonical risk headline published. | LIVE |
| B — RTT leader stability | `4ac3daf`, `bc52ffe` | Removed unguarded mount-time RTT probe; leader exclusivity measured within a window instead of cumulatively. | LIVE |
| C — Diagnostics wave 1 | `3e05a66`, `062626b` | Additive flag-gated incognito diagnostics pass-through; capture procedure documented in `CLOUDFLARE.md`. | LIVE (opt-in, inert) |
| D — Truth helpers & UA156 | `44eba11`, `b1df7c6` | Proxy-truth helper, UA Chromium-156 regression, shadow test scripts; canonical VPN methods helper + proxy/VPN truth suites. | MIXED (UA fix LIVE; helpers SHADOW) |
| E — Server echo & parity | `88b77b6` | Server diagnostics echo, Chromium 156 fix, parity invariants. | MIXED (echo LIVE; parity SHADOW) |
| F — Collector diagnostics & CI | `5906114` | Collector diagnostics probes, diag suite, CI wiring. | LIVE probes behind flag / SHADOW data |
| G — IDB resolver & additive modules | `e689472`, `499d5e9` | Preserve incognito session lock under the diagnostics flag; evidence-based IDB durability resolver; additive "SOTA" shadow modules. | MIXED (resolver LIVE; modules SHADOW) |
| H — Integration wave | `ac8d220`, `a550397`, `e881115` | SOTA truth signals integrated across collector/edge/server/UI; P0 incognito physics, bot/CDP flags, spoofed identity and UA coherence; CI browser-harness launch guard. | MIXED — see §2/§3 |
| I - Remaining-fix wave (uncommitted working tree) | HEAD = `e881115` + uncommitted changes | Audio identity stability (exact anchor + seed exclusion); GPU truth from masked/unmasked strings with UI hardware gate; permission-gated geolocation bridge with no IP fallback; privacy-noise suppression in collector/server/tampering; active-CDP state classifier + weight-0 reason/axis; headless shell/new granularity; extra `points: 0` evidence, `confidenceStability`, `identityScope`, `mediaPreferences`, `antiDetectExemption` wired into production; additive mirrors in envelope/canonical/response types and existing UI. | MIXED - primarily wired (§2); remaining shadow evaluators listed in §3; **uncommitted** |

---

## Appendix A: working tree at time of writing

Captured with `git status --short` (branch `main`, HEAD `e881115`). Because other work was
proceeding concurrently, this list is a snapshot, not a guarantee: files, imports and call sites
were still appearing between reads.

Modified: `api/index.js`, `server.ts`, `src/App.tsx`, `src/components/SmartSignalsGrid.tsx`,
`src/components/canonical.ts`, `src/lib/collector.ts`, `src/lib/specInvariants.ts`,
`src/lib/tamperingDetector.ts`, `src/lib/telemetryContract.ts`, `src/lib/verdict.ts`,
`src/server/agents/botVerifier.ts`, `src/shared/normalization/uaNormalizer.ts`,
`src/types/visitor.ts`.

Untracked (remaining-fix modules and their shadow suites): `src/lib/activeCdp.ts`,
`src/lib/antiDetectExemption.ts`, `src/lib/audioTruth.ts`, `src/lib/confidenceStability.ts`,
`src/lib/geoProximityBridge.ts`, `src/lib/gpuTruth.ts`, `src/lib/identityScope.ts`,
`src/lib/mediaPreferences.ts`, `src/lib/privacyNoise.ts`, `src/lib/riskEvidenceExtra.ts`;
`scripts/test-active-cdp.ts`, `scripts/test-anti-detect-exemption.ts`, `scripts/test-audio-truth.ts`,
`scripts/test-confidence-stability.ts`, `scripts/test-geo-bridge.ts`, `scripts/test-gpu-truth.ts`,
`scripts/test-identity-scope.ts`, `scripts/test-media-preferences.ts`, `scripts/test-privacy-noise.ts`,
`scripts/test-risk-evidence-extra.ts`.

None of these changes were committed, pushed or built as part of writing this document.

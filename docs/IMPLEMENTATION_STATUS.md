# Implementation status (post-integration-wave)

This document records what is **actually present in the tree** after the current integration
wave. It is a presence/absence report, not a quality or deployment guarantee. It deliberately
does **not** claim a feature is live because a file for it exists.

Scope note: the wave is composed of the commits ending at `499d5e9`
(`feat(incognito): evidence-based IDB resolver plus additive SOTА shadow modules`) **plus a set of
still-uncommitted working-tree changes**. The uncommitted set is in active flux (files appear and
change between reads); the classifications below are by *code path*, and the exact file list at
the moment of writing is reported in [Appendix A](#appendix-a-working-tree-at-time-of-writing).
Nothing here was committed, pushed, or built by the author of this document.

---

## 1. Locked constraints (do not relax without an explicit decision)

These are the invariants of the wave. Each is enforced in code or in the deploy procedure, not
just stated here.

| # | Constraint | What it means in this tree | Where it is held |
|---|---|---|---|
| 1 | **0–10** | The four core cards keep their explicitly labelled `0/10`–`10/10` per-card scale. The single risk truth is the canonical `0–100` orthogonal ledger; `score10`, `risk_tier` and `riskBadgeText` are mirrors *of* that ledger, never a second computation. No new numeric scale was introduced. | `src/lib/telemetryContract.ts` (`canonicalScore10`, `riskTier`, `assertIntegratedConsistency`), `src/components/canonical.ts`, `api/index.js` / `worker/index.js` ledger mirrors, `src/components/SmartSignalsGrid.tsx` (reads the canonical headline; local derivation only as a legacy fallback) |
| 2 | **Uncalibrated** | Confidence stays `uncalibrated` by default. The gate requires **≥ 200 human-labeled pairs AND held-out ECE ≤ 0.05**; until both hold, labels read `Match evidence X%`, never `Confidence X%`. No labeled corpus exists in this repo, so nothing is calibrated today. | `src/lib/rarityHonesty.ts` (`CALIBRATION_MIN_LABELED_PAIRS = 200`, `CALIBRATION_MAX_ECE = 0.05`, `calibrationStatusFor`, `confidenceLabel`) and the new `src/lib/calibrationEngine.ts`, which imports the gate rather than duplicating it |
| 3 | **Zero alarms** | No Durable Object alarms, cron triggers, timers or scheduling of any kind were added. Health and ping are answered on request; the DO is warmed on first fetch, not by a scheduled event. | `worker/index.js` ("No alarms / crons are used — this is the only bootstrap path"), `src/lib/velocityThresholds.ts`, `src/lib/identityTiers.ts` |
| 4 | **No new panels** | No new dashboard panel/component was added in this wave. Additive fields are verbatim transports into **existing** tiles/rows/detail views; the `intelDiag` diagnostics add no UI at all. | `src/App.tsx` and `src/components/SmartSignalsGrid.tsx` change only existing views; no new panel component exists in the wave's diff |
| 5 | **Manual deploy** | CI verifies and dry-runs only; there is no `wrangler deploy` step and no push/hosted auto-deploy. A human runs the command in §5 after verification passes. | `CLOUDFLARE.md` "Deploy"; `.github/workflows/cloudflare.yml` `verify` job only |
| 6 | **Zero SDK** | The wave adds no third-party SDK. New modules are pure, dependency-free, do no I/O/network/DOM probing and never throw on hostile input. Existing project dependencies (e.g. Leaflet) are unchanged. | Header comments of `src/lib/entropyMatrix.ts`, `src/lib/calibrationEngine.ts`, `src/lib/zeroTrust.ts`, `src/lib/vmIntegrity.ts`, `src/lib/hexProximity.ts`, `src/lib/networkEdge.ts` |

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
| Flag-gated incognito diagnostics pass-through | **Live code path, opt-in, inert** | `intelDiag=1` → `x-intel-diag: 1` → server echo → `window.__intelDiag()`. Off by default, adds no UI, never affects a verdict or score. See §6. |
| Additive mirrors read by existing UI | **Live transport only** | `proxy_details`, `vpn_methods`, `privacy_settings`, `stealth_ids`, `tampering_details`, `network_layer_hash`, `idbTruthRule` are verbatim passes into existing views; missing values stay absent. They are not new signals and do not change tiers. |

---

## 3. Shadow-only (present, but not a verdict/score input and not promoted)

| Item | What it is | Why it is not live |
|---|---|---|
| `src/lib/calibrationEngine.ts` | Additive evidence record (four weighted signals → descriptive `evidence_score`) plus `confidenceLabelFor`. Owns **no** gate of its own; `calibration_status` comes only from `rarityHonesty`. | Not imported by any production module; referenced only by its own test (`scripts/test-calibration-engine.ts`). Purely descriptive — explicitly cannot promote a record to calibrated. Ships as `uncalibrated`. |
| `src/lib/entropyMatrix.ts` | Pure FingerprintJS-v5-style entropy normalizers (fonts, emoji, WebGL, audio, canvas, keyboard, CSS, math, DOM blockers). No probing, no hashing, no scoring. | Its own header states: "Nothing in production imports this module yet; it is a shadow evaluation surface only." Test: `scripts/test-entropy-matrix.ts`. |
| `tampering_lies` in `src/lib/tamperingDetector.ts` | Additive cross-scope "tampering lie" verdict from `resolveTamperingLies`. | Explicitly never consumed by the canonical `tampering` verdict, `anti_detect_browser` flag, ML score, risk score or verdict tier. Empty/zero when no observations are supplied. |
| `assertIntegratedConsistency` in `src/lib/telemetryContract.ts` | Pure, non-throwing parity check across risk mirrors. | Defined and unit-tested but not wired into a live gate; it reports issues, it does not enforce them. |
| Stealth-signal → taxonomy bridge (`stealthReasonId`, `STEALTH_SIGNAL_REASON_IDS` in `verdict.ts` / `botVerifier.ts` and the compiled bundle) | Mirrors stealth probe ids into the **existing** four-tier reason taxonomy (no second vocabulary). | These are mapping helpers/parity code. `composeBotVerdict` in `botVerifier.ts` is not called by `server.ts`, and no live producer feeds its `stealth` input; treat the folded stealth reasoning there as parity work, not a deployed detector change. The client-side stealth artifacts in `collector.ts` remain the existing detection path. |
| Additional shadow truth modules (`identityTiers.ts`, `networkEdge.ts`, `proximityAdapter.ts`, `vmIntegrity.ts`, `zeroTrust.ts`, `hexProximity.ts`, `velocityThresholds.ts`, `privacySignatures.ts`, `stealthSignals.ts`, `tamperingLies.ts`) | Dependency-free, total functions over untrusted input; no alarms, no SDK, no I/O. | Evaluation surfaces with dedicated shadow test scripts; additive and not wired to a new verdict, panel or alarm. |
| `intelDiag` diagnostics bundle | Console-only hook, collector probes, server echo, header mirror. | Additive and flag-gated; never scored, no UI. It is a capture facility, not a feature. |

---

## 4. Backlog / explicitly not present

- **Calibration.** There is no labeled-pair corpus (≥ 200) and no held-out ECE measurement (≤ 0.05). All identity confidence therefore remains uncalibrated; `confidenceLabelFor` will return `Match evidence X%` in production until such data exists. Do not claim calibrated confidence.
- **Promotion of shadow modules.** `entropyMatrix`, `calibrationEngine`, `tampering_lies` and the other additive evaluators are not scheduled for promotion by this document. Promotion would be a separate decision with its own review.
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

## 6. Diagnostics capture procedure (shadow, manual, opt-in)

Gated by the same deploy rules — deploy only via §5; no auto-deploy.

1. Open <https://intel.adityahq.me/?intelDiag=1> in a **real private/incognito window** (not a regular tab with a spoofed user agent).
2. Open the browser console and run `window.__intelDiag()`.
3. Paste the returned JSON into your report.

The `intelDiag` flag is off by default, adds no UI, and does not affect any verdict or risk score.
Never include tokens or secrets in the captured JSON or the report. For local verification:
`node scripts/test-worker.mjs`, `npm run build`, `node scripts/build-worker.mjs`.

---

## 7. Phase-by-phase table

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
| H — Current wave (uncommitted working tree) | HEAD = `499d5e9` + uncommitted changes | `calibrationEngine`, `entropyMatrix` + more pure evaluators and their test scripts; stealth→taxonomy bridge; additive canonical mirrors in envelope/UI; JA4H header, lower-case verdict headers, opt-in strict-origin, API diagnostics echo, score mirrors. | MIXED — see §2/§3; **uncommitted** |

---

## Appendix A: working tree at time of writing

Captured with `git status --short` (branch `main`, up to date with `origin/main`, HEAD `499d5e9`).
Because other work was proceeding concurrently, this list is a snapshot, not a guarantee.

Modified: `api/index.js`, `server.ts`, `src/App.tsx`, `src/components/SmartSignalsGrid.tsx`,
`src/components/canonical.ts`, `src/lib/collector.ts`, `src/lib/idbDurabilityTruth.ts`,
`src/lib/specInvariants.ts`, `src/lib/tamperingDetector.ts`, `src/lib/telemetryContract.ts`,
`src/lib/verdict.ts`, `src/server/agents/botVerifier.ts`, `src/shared/normalization/uaNormalizer.ts`,
`worker/index.js`.

Untracked: `scripts/test-calibration-engine.ts`, `scripts/test-entropy-matrix.ts`,
`scripts/test-identity-tiers.ts`, `scripts/test-network-edge.ts`,
`scripts/test-proximity-adapter.ts`, `scripts/test-vm-integrity.ts`,
`src/lib/calibrationEngine.ts`, `src/lib/entropyMatrix.ts`, `src/lib/identityTiers.ts`,
`src/lib/networkEdge.ts`, `src/lib/proximityAdapter.ts`, `src/lib/vmIntegrity.ts`.

None of these changes were committed, pushed or built as part of writing this document.

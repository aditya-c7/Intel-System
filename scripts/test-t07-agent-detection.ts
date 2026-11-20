/**
 * T-07 — automation gating: CDP / DevTools is NOT a bot verdict.
 *
 * Primary sources:
 *  - Fingerprint Pro exposes `developer_tools` as a separate signal from `bot`
 *    (not_detected | good | bad).
 *  - FingerprintJS BotD has no CDP / Runtime.enable probe at all.
 *  - incolumitas.com (2026-11-10) measured Runtime.enable false positives on paying
 *    customers (C2: 1/88, C3: 26/51) and ships every CDP signal at weight 0:
 *    "An attached client is not a bot."
 *
 * The gate therefore records CDP evidence in `developerToolsReasons` and keeps the
 * verdict `human` unless an independent automation artifact is present.
 */

import assert from 'node:assert/strict';
import { gateAutomationEvidence, classifyReasonId } from '../src/lib/verdict';

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

/* -------------------------------------------------------------------------- */
/* Part A — CDP Runtime.enable / Network.enable is developer-tools evidence   */
/* -------------------------------------------------------------------------- */

section('T-07A CDP evidence never flips the verdict on its own');

const cdpEvidence = gateAutomationEvidence(['cdp.runtime.enable', 'cdp.network.order']);
assert.equal(cdpEvidence.verdict, 'human', 'CDP probes alone must stay human');
assert.equal(cdpEvidence.hardReasons.length, 0, 'CDP must not be hard automation evidence');
assert.ok(
  cdpEvidence.developerToolsReasons.includes('cdp.runtime.enable'),
  'Runtime.enable is developer-tools evidence'
);
assert.ok(
  cdpEvidence.developerToolsReasons.includes('cdp.network.order'),
  'Network.enable is developer-tools evidence'
);
assert.equal(classifyReasonId('cdp.console.debug'), 'developer_tools');
console.log('PASS  CDP → developer_tools, verdict human');

/* -------------------------------------------------------------------------- */
/* Part B — real automation still wins                                        */
/* -------------------------------------------------------------------------- */

section('T-07B independent automation artifacts still produce automated');

const webdriverEvidence = gateAutomationEvidence(['navigator.webdriver', 'cdp.runtime.enable']);
assert.equal(webdriverEvidence.verdict, 'automated', 'navigator.webdriver is deterministic');
assert.ok(webdriverEvidence.hardReasons.includes('navigator.webdriver'));
assert.ok(webdriverEvidence.developerToolsReasons.includes('cdp.runtime.enable'));
console.log('PASS  WebDriver + CDP → automated with developer_tools recorded');

const uaEvidence = gateAutomationEvidence(['ua.automation-signature']);
assert.equal(uaEvidence.verdict, 'automated', 'Automation UA is deterministic');
assert.equal(classifyReasonId('ua.headless-chrome'), 'hard');
console.log('PASS  automation user-agent → automated');

const overrideEvidence = gateAutomationEvidence(['cdp.ua_override.empty_brands', 'cdp.runtime.enable']);
assert.equal(overrideEvidence.verdict, 'automated', 'UA override via CDP is proof of automation');
assert.ok(overrideEvidence.hardReasons.includes('cdp.ua_override.empty_brands'));
console.log('PASS  CDP UA override → automated');

/* -------------------------------------------------------------------------- */
/* Part C — weak environment quirks stay human                                */
/* -------------------------------------------------------------------------- */

section('T-07C weak environment quirks stay human');

const softOnly = gateAutomationEvidence(['headless.swiftshader.caveat', 'playwright.mcp.pressure']);
assert.equal(softOnly.verdict, 'human', 'soft quirks alone must never label a person automated');
console.log('PASS  weak quirks alone stay human');

const electronLike = gateAutomationEvidence(['bot.software-gpu', 'bot.empty-languages']);
assert.equal(electronLike.verdict, 'human', 'software GPU + languages is not automation');
console.log('PASS  Electron-style environment quirks stay human');

console.log('\nT-07: 7 passed, 0 failed');

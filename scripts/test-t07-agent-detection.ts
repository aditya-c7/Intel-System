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
import { classifyReasonId as classifyAgentReasonId } from '../src/server/agents/botVerifier';

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

/* -------------------------------------------------------------------------- */
/* Part D — C1 dedicated-Worker variant stays weight 0                        */
/* -------------------------------------------------------------------------- */

section('T-07D cdp.runtime.enable.worker is developer_tools, corroborating only');

assert.equal(classifyReasonId('cdp.runtime.enable.worker'), 'developer_tools');
const workerEvidence = gateAutomationEvidence(['cdp.runtime.enable.worker']);
assert.equal(workerEvidence.verdict, 'human', 'a worker-scope bridge alone must stay human');
assert.ok(
  workerEvidence.developerToolsReasons.includes('cdp.runtime.enable.worker'),
  'the worker variant is recorded as developer-tools evidence'
);
// Corroborating only: paired with the window-scope bridge it is still weight 0.
const workerPaired = gateAutomationEvidence([
  'cdp.runtime.enable.worker',
  'cdp.runtime.enable',
]);
assert.equal(workerPaired.verdict, 'human', 'two weight-0 bridges still never escalate');
console.log('PASS  worker C1 variant → developer_tools, verdict human');

/* -------------------------------------------------------------------------- */
/* Part E — Notification contract mismatch is medium                          */
/* -------------------------------------------------------------------------- */

section('T-07E headless.notification-contract is medium (needs a companion)');

assert.equal(classifyReasonId('headless.notification-contract'), 'medium');
const loneContract = gateAutomationEvidence(['headless.notification-contract']);
assert.equal(loneContract.verdict, 'uncertain', 'a lone medium reason is uncertain, not automated');
const corroboratedContract = gateAutomationEvidence([
  'headless.notification-contract',
  'launch.no-speech-voices',
]);
assert.equal(
  corroboratedContract.verdict,
  'automated',
  'one medium plus weak corroboration automates'
);
console.log('PASS  headless.notification-contract → medium');

/* -------------------------------------------------------------------------- */
/* Part F — SwiftShader desktop conjunction is hard, exact entry wins         */
/* -------------------------------------------------------------------------- */

section('T-07F headless.swiftshader.caveat.desktop is hard');

assert.equal(classifyReasonId('headless.swiftshader.caveat.desktop'), 'hard');
assert.equal(
  classifyReasonId('headless.swiftshader.caveat'),
  'weak',
  'the plain caveat stays weak — exact entries are checked first'
);
const desktopConjunction = gateAutomationEvidence(['headless.swiftshader.caveat.desktop']);
assert.equal(desktopConjunction.verdict, 'automated', 'the desktop conjunction escalates alone');
assert.ok(desktopConjunction.hardReasons.includes('headless.swiftshader.caveat.desktop'));
console.log('PASS  SwiftShader desktop conjunction → hard; plain caveat stays weak');

/* -------------------------------------------------------------------------- */
/* Part G — the cyclic-native tamper id never bot-flags                       */
/* -------------------------------------------------------------------------- */

section('T-07G tamper.cyclic-native-absent stays on the tampering axis');

assert.equal(
  classifyReasonId('tamper.cyclic-native-absent'),
  'weak',
  'no weight-table entry: the id is owned by the tampering axis, not the bot gate'
);
const tamperOnly = gateAutomationEvidence(['tamper.cyclic-native-absent']);
assert.equal(tamperOnly.verdict, 'human', 'the tamper id must never flip the bot gate');
console.log('PASS  tamper.cyclic-native-absent → weak in the bot gate (tampering axis owns it)');

/* -------------------------------------------------------------------------- */
/* Part H — botVerifier weight tables stay in sync with verdict.ts            */
/* -------------------------------------------------------------------------- */

section('T-07H botVerifier and verdict classify the new ids identically');

// botVerifier mirrors the verdict tables by contract (its header REQUIRES the sync);
// every new reason id must classify identically in both implementations.
const syncedIds = [
  'cdp.runtime.enable.worker',
  'headless.notification-contract',
  'headless.swiftshader.caveat.desktop',
  'tamper.cyclic-native-absent',
];
for (const id of syncedIds) {
  assert.equal(
    classifyAgentReasonId(id),
    classifyReasonId(id),
    `botVerifier and verdict must classify ${id} identically`
  );
}
console.log('PASS  botVerifier/verdict table parity for all new ids');

console.log('\nT-07: 12 passed, 0 failed');

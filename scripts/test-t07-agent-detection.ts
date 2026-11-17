/**
 * T-07 — CDP automation gating.
 *
 * CDP Runtime.enable / Network.enable evidence must be hard automation proof
 * (bot === "bad" in the dashboard payload).
 */

import assert from 'node:assert/strict';
import { gateAutomationEvidence } from '../src/lib/verdict';

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

/* -------------------------------------------------------------------------- */
/* Part A — CDP Runtime.enable + Network.enable                               */
/* -------------------------------------------------------------------------- */

section('T-07A CDP automation evidence gate');

const cdpEvidence = gateAutomationEvidence(['cdp.runtime.enable', 'cdp.network.order']);
assert.equal(cdpEvidence.verdict, 'automated', 'CDP probes must produce an automated verdict');
assert.ok(
  cdpEvidence.hardReasons.includes('cdp.runtime.enable'),
  'Runtime.enable must be classified as hard evidence'
);
assert.ok(
  cdpEvidence.hardReasons.includes('cdp.network.order'),
  'Network.enable must be classified as hard evidence'
);
console.log('PASS  CDP reasons are hard evidence → automated verdict');

const softOnly = gateAutomationEvidence(['headless.swiftshader.caveat', 'playwright.mcp.pressure']);
assert.equal(softOnly.verdict, 'human', 'soft quirks alone must never label a person automated');
console.log('PASS  weak quirks alone stay human');

console.log('\nT-07: 2 passed, 0 failed');

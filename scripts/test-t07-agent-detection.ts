/**
 * T-07 — CDP automation gating and RFC 9421 Web Bot Auth verification.
 *
 * Part A: CDP Runtime.enable / Network.enable evidence must be hard automation
 *         proof (bot === "bad" in the dashboard payload).
 * Part B: a correctly signed Ed25519 Web Bot Auth request must verify, and a
 *         tampered signature must fail. Uses a synthetic signer directory so the
 *         test is hermetic (no network).
 */

import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { gateAutomationEvidence } from '../src/lib/verdict';
import { WebBotAuthVerifier } from '../src/server/ai-protection/web-bot-auth';

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

/* -------------------------------------------------------------------------- */
/* Part B — RFC 9421 Ed25519 Web Bot Auth                                     */
/* -------------------------------------------------------------------------- */

section('T-07B Web Bot Auth Ed25519 signature');

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicJwk = publicKey.export({ format: 'jwk' }) as {
  kty: string;
  crv: string;
  x: string;
  kid?: string;
};

const stubDb = {
  prepare: () => ({
    all: () => [{ jwk: JSON.stringify({ ...publicJwk, kid: 'test-key' }) }],
    run: () => undefined,
  }),
} as unknown as ConstructorParameters<typeof WebBotAuthVerifier>[0];

const verifier = new WebBotAuthVerifier(stubDb);
const signerHost = 'api.manus.im';
const signatureAgent = `"https://${signerHost}"`;
const created = Math.floor(Date.now() / 1000);
const rawParams = `("@authority" "signature-agent");created=${created};keyid="test-key";tag="web-bot-auth"`;
const signatureInput = `sig1=${rawParams}`;

const signatureBase =
  `"@authority": ${signerHost}\n` +
  `"signature-agent": ${signatureAgent}\n` +
  `"@signature-params": ${rawParams}\n`;

function signedHeaders(): Record<string, string> {
  const signature = sign(null, Buffer.from(signatureBase, 'utf8'), privateKey).toString('base64');
  return {
    'signature-agent': signatureAgent,
    'signature-input': signatureInput,
    signature: `sig1=:${signature}:`,
  };
}

const verified = await verifier.verifyRequest({
  method: 'GET',
  authority: signerHost,
  pathWithQuery: '/',
  headers: signedHeaders(),
});
assert.equal(verified.present, true, 'signed request must be detected');
assert.equal(verified.verified, true, `signature must verify (${verified.errorDetail ?? verified.reason})`);
assert.equal(verified.signerHost, signerHost);
console.log(`PASS  verified Web Bot Auth request (${verified.operator ?? signerHost})`);

const tampered = await verifier.verifyRequest({
  method: 'GET',
  authority: 'evil.example',
  pathWithQuery: '/',
  headers: signedHeaders(),
});
assert.equal(tampered.verified, false, 'a signature covering a different authority must fail');
console.log('PASS  tampered request rejected');

console.log('\nT-07: 4 passed, 0 failed');

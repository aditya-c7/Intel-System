/**
 * RS4 Web Bot Auth verification suite (dependency-free; WebCrypto only, no network).
 *
 *   npx tsx scripts/test-web-bot-auth.ts
 *
 * Uses scripts/fixtures/web-bot-auth.json (RFC 8037 Ed25519 vector) and injected
 * fetch/crypto. Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 */

import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildSignatureBase,
  directoryUrlFor,
  enforcePolicy,
  jwkThumbprint,
  parseSignatureHeaders,
  resolveOutcome,
  verifyWebBotAuthRequest,
  type DirectoryCache,
  type FetchLike,
  type FetchLikeResponse,
  type SubtleLike,
} from '../src/lib/webBotAuth';

/* -------------------------------------------------------------------------- */
/* Fixture                                                                     */
/* -------------------------------------------------------------------------- */

interface FixtureCase {
  id: string;
  expect: 'NEUTRAL' | 'INVALID' | 'VALID';
  reason?: string;
  input?: string;
  rawInput?: string;
  rawSignature?: string;
  rawAgent?: string;
  signatureLabel?: string;
  fetchFails?: boolean;
}

interface Fixture {
  vector: { name: string; kty: string; crv: string; x: string; d: string; keyid: string };
  context: {
    authority: string;
    nowMs: number;
    created: number;
    expires: number;
    agentUrl: string;
    directoryUrl: string;
    agentLegacy: string;
    agentDictionary: string;
  };
  validInput: string;
  cases: FixtureCase[];
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(readFileSync(path.join(here, 'fixtures', 'web-bot-auth.json'), 'utf8')) as Fixture;
const subtle = webcrypto.subtle as unknown as SubtleLike;
const { x, d, keyid } = fx.vector;
const { authority, nowMs, created, expires, agentLegacy, agentDictionary, directoryUrl } = fx.context;

/* -------------------------------------------------------------------------- */
/* Reporting                                                                   */
/* -------------------------------------------------------------------------- */

let passed = 0;
let failed = 0;

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function check(id: string, label: string, body: () => void | Promise<void>): Promise<void> {
  try {
    await body();
    passed += 1;
    console.log(`PASS  [${id}] ${label}`);
  } catch (error) {
    failed += 1;
    console.error(`FAIL  [${id}] ${label}\n      ${describeError(error)}`);
  }
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

/* -------------------------------------------------------------------------- */
/* Crypto + stub helpers                                                        */
/* -------------------------------------------------------------------------- */

const privateKey = await webcrypto.subtle.importKey(
  'jwk',
  { kty: 'OKP', crv: 'Ed25519', x, d } as unknown as JsonWebKey,
  { name: 'Ed25519' },
  false,
  ['sign'],
);
const secondKeyPair = (await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
const secondJwk = (await webcrypto.subtle.exportKey('jwk', secondKeyPair.privateKey)) as JsonWebKey;

async function signWith(
  key: CryptoKey,
  base: string,
): Promise<ArrayBuffer> {
  return webcrypto.subtle.sign('Ed25519', key, new TextEncoder().encode(base));
}

async function signatureB64(base: string, key: CryptoKey = privateKey): Promise<string> {
  return Buffer.from(await signWith(key, base)).toString('base64');
}

const DUMMY_B64 = 'A'.repeat(86) + '=='; // 64 zero bytes
function dummySignature(label = 'sig1'): string {
  return `${label}=:${DUMMY_B64}:`;
}

interface DirectoryArtifacts {
  body: string;
  headers: Record<string, string>;
  directoryInput: string;
  directoryBase: string;
}

async function buildDirectory(options: {
  keys?: unknown[];
  x?: string;
  keyid?: string;
  tag?: string;
  digestBad?: boolean;
  omitDigest?: boolean;
  omitSignature?: boolean;
  signer?: CryptoKey;
} = {}): Promise<DirectoryArtifacts> {
  const keys = options.keys ?? [{ kty: 'OKP', crv: 'Ed25519', x: options.x ?? x }];
  const body = JSON.stringify({ keys });
  const realDigest = Buffer.from(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(body))).toString('base64');
  const digestHeader = `sha-256=:${options.digestBad ? Buffer.alloc(32).toString('base64') : realDigest}:`;
  const member =
    `("@authority" "content-digest");created=${created};expires=${expires};` +
    `keyid="${options.keyid ?? keyid}";tag="${options.tag ?? 'http-message-signatures-directory'}"`;
  const directoryInput = `dir1=${member}`;
  const directoryBase =
    `"@authority": ${new URL(directoryUrl).host}\n` +
    `"content-digest": ${digestHeader}\n` +
    `"@signature-params": ${member}`;
  const dirSig = await signatureB64(directoryBase, options.signer ?? privateKey);
  const headers: Record<string, string> = {
    'signature-input': directoryInput,
    'cache-control': 'max-age=300',
  };
  if (!options.omitDigest) headers['content-digest'] = digestHeader;
  if (!options.omitSignature) headers['signature'] = `dir1=:${dirSig}:`;
  return { body, headers, directoryInput, directoryBase };
}

interface FetchCall {
  url: string;
  init?: { redirect?: string; signal?: unknown };
}

function stubFetch(
  directory: DirectoryArtifacts,
  calls: FetchCall[],
  fail = false,
  overrideBody?: string,
): FetchLike {
  return (url, init) => {
    calls.push({ url, init: init as FetchCall['init'] });
    if (fail) return Promise.reject(new Error('network down'));
    const response: FetchLikeResponse = {
      ok: true,
      status: 200,
      headers: directory.headers,
      text: async () => overrideBody ?? directory.body,
    };
    return Promise.resolve(response);
  };
}

async function buildValidRequest(
  agent: string = agentLegacy,
  authorityValue: string = authority,
  input: string = fx.validInput,
): Promise<{ rawSignature: string; rawInput: string; rawAgent: string; authority: string; base: string }> {
  const parsed = parseSignatureHeaders(dummySignature(), input, agent);
  const base = buildSignatureBase(parsed, {
    '@authority': authorityValue,
    'signature-agent': parsed.agentComponentValue as string,
  });
  assert.ok(base !== null, 'signature base must be buildable');
  return {
    rawSignature: `sig1=:${await signatureB64(base as string)}:`,
    rawInput: input,
    rawAgent: agent,
    authority: authorityValue,
    base: base as string,
  };
}

function verifyRequest(
  request: { rawSignature: string; rawInput: string; rawAgent: string; authority: string },
  fetcher: FetchLike,
  cache?: DirectoryCache,
): Promise<ReturnType<typeof resolveOutcome>> {
  return verifyWebBotAuthRequest({ ...request, nowMs, subtle, fetch: fetcher, cache });
}

/* -------------------------------------------------------------------------- */
/* Tests                                                                       */
/* -------------------------------------------------------------------------- */

async function run(): Promise<void> {
  section('A. Exports and RFC 8037 thumbprint');

  await check('A1', 'all required helpers are exported', () => {
    for (const fn of [parseSignatureHeaders, buildSignatureBase, jwkThumbprint, enforcePolicy, resolveOutcome, verifyWebBotAuthRequest, directoryUrlFor]) {
      assert.equal(typeof fn, 'function');
    }
  });

  await check('A2', 'jwkThumbprint matches the RFC 8037 vector keyid', async () => {
    assert.equal(await jwkThumbprint(x, subtle), keyid);
    assert.equal(keyid, 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
  });

  await check('A3', 'thumbprint is unpadded base64url and x-sensitive', async () => {
    const other = await jwkThumbprint(secondJwk.x as string, subtle);
    assert.notEqual(other, keyid);
    assert.match(other, /^[A-Za-z0-9_-]{43}$/);
    assert.ok(!other.includes('='));
  });

  section('B. Structured-field parsing (legacy + dictionary)');

  await check('B1', 'valid legacy headers parse fully', () => {
    const p = parseSignatureHeaders(dummySignature(), fx.validInput, agentLegacy);
    assert.equal(p.error, null);
    assert.equal(p.present, true);
    assert.equal(p.label, 'sig1');
    assert.deepEqual(p.covered, ['@authority', 'signature-agent']);
    assert.equal(p.rawInputValue, fx.validInput.slice('sig1='.length));
    assert.equal(p.params.alg, 'ed25519');
    assert.equal(p.params.tag, 'web-bot-auth');
    assert.equal(p.params.keyid, keyid);
    assert.equal(p.params.created, created);
    assert.equal(p.params.expires, expires);
    assert.equal(p.agentUrl, fx.context.agentUrl);
    assert.equal(p.agentForm, 'legacy');
    assert.equal(p.agentComponentValue, agentLegacy);
  });

  await check('B2', 'Signature byte sequence decodes to 64 bytes', () => {
    const p = parseSignatureHeaders(dummySignature(), fx.validInput, agentLegacy);
    assert.ok(p.signatureBytes);
    assert.equal(p.signatureBytes.length, 64);
    assert.equal(p.signatureBytes[0], 0);
  });

  await check('B3', 'covered component names are lowercased, raw input preserved', () => {
    const input = 'sig1=("@AUTHORITY" "SIGNATURE-AGENT");created=1618884480;expires=1618884600;' +
      `keyid="${keyid}";alg="ed25519";tag="web-bot-auth"`;
    const p = parseSignatureHeaders(dummySignature(), input, agentLegacy);
    assert.equal(p.error, null);
    assert.deepEqual(p.covered, ['@authority', 'signature-agent']);
    assert.ok(p.rawInputValue?.includes('"@AUTHORITY"'));
    assert.equal(enforcePolicy(p, nowMs).ok, true);
  });

  await check('B4', 'draft dictionary Signature-Agent form is accepted', () => {
    const p = parseSignatureHeaders(dummySignature(), fx.validInput, agentDictionary);
    assert.equal(p.error, null);
    assert.equal(p.agentForm, 'dictionary');
    assert.equal(p.agentUrl, fx.context.agentUrl);
    assert.equal(p.agentComponentValue, agentDictionary);
  });

  section('C. Fixture INVALID cases (structured fields + policy)');

  for (const c of fx.cases.filter((item) => item.expect === 'INVALID')) {
    await check(`C:${c.id}`, `INVALID ${c.id} -> ${c.reason}`, () => {
      const rawSig = 'rawSignature' in c ? (c.rawSignature as string) : dummySignature(c.signatureLabel ?? 'sig1');
      const rawInput = c.rawInput ?? c.input ?? fx.validInput;
      const agent = 'rawAgent' in c ? (c.rawAgent as string) : agentLegacy;
      const parsed = parseSignatureHeaders(rawSig, rawInput, agent);
      const policy = enforcePolicy(parsed, nowMs);
      assert.equal(policy.ok, false, `expected rejection, got ${JSON.stringify(policy)}`);
      assert.equal(policy.reason, c.reason);
      assert.equal(resolveOutcome({ state: 'policy_error', reason: policy.reason as string }).kind, 'INVALID');
    });
  }

  section('D. Signature base (RS4 layout)');

  await check('D1', 'base has no trailing newline and exact line layout', () => {
    const p = parseSignatureHeaders(dummySignature(), fx.validInput, agentLegacy);
    const base = buildSignatureBase(p, { '@authority': authority, 'signature-agent': agentLegacy });
    assert.equal(
      base,
      `"@authority": ${authority}\n` +
        `"signature-agent": ${agentLegacy}\n` +
        `"@signature-params": ${fx.validInput.slice('sig1='.length)}`,
    );
    assert.ok(base && !base.endsWith('\n'));
  });

  await check('D2', 'component order follows the covered list', () => {
    const input = 'sig1=("signature-agent" "@authority");created=1618884480;expires=1618884600;' +
      `keyid="${keyid}";alg="ed25519";tag="web-bot-auth"`;
    const p = parseSignatureHeaders(dummySignature(), input, agentLegacy);
    const base = buildSignatureBase(p, { '@authority': authority, 'signature-agent': agentLegacy }) as string;
    assert.ok(base.startsWith(`"signature-agent": ${agentLegacy}\n"@authority": ${authority}\n`));
  });

  await check('D3', 'non-ASCII values and missing components are rejected', () => {
    const p = parseSignatureHeaders(dummySignature(), fx.validInput, agentLegacy);
    assert.equal(buildSignatureBase(p, { '@authority': authority, 'signature-agent': '"https://é.example"' }), null);
    assert.equal(buildSignatureBase(p, { '@authority': authority }), null);
    assert.equal(buildSignatureBase(p, undefined as unknown as Record<string, string>), null);
  });

  await check('D4', 'directoryUrlFor appends the well-known path once', () => {
    assert.equal(directoryUrlFor(fx.context.agentUrl), directoryUrl);
    assert.equal(directoryUrlFor(directoryUrl), directoryUrl);
  });

  section('E. Outcome resolver (NEUTRAL / VALID / INVALID only)');

  await check('E1', 'absent -> NEUTRAL', () => {
    const out = resolveOutcome({ state: 'absent' });
    assert.equal(out.kind, 'NEUTRAL');
    assert.equal(out.reason, 'no_signature');
  });

  await check('E2', 'unverifiable -> NEUTRAL, never VALID', () => {
    const out = resolveOutcome({ state: 'unverified', reason: 'directory_fetch_failed' });
    assert.equal(out.kind, 'NEUTRAL');
    assert.equal(out.reason, 'directory_fetch_failed');
  });

  await check('E3', 'parse/policy/mismatch -> INVALID with reason', () => {
    assert.deepEqual(resolveOutcome({ state: 'parse_error', reason: 'bad_header' }), { kind: 'INVALID', reason: 'bad_header' });
    assert.deepEqual(resolveOutcome({ state: 'policy_error', reason: 'expired' }), { kind: 'INVALID', reason: 'expired' });
    assert.deepEqual(resolveOutcome({ state: 'signature_mismatch' }), { kind: 'INVALID', reason: 'signature_mismatch' });
  });

  await check('E4', 'verified -> VALID with full metadata', () => {
    const out = resolveOutcome({
      state: 'verified', keyid, agentUrl: fx.context.agentUrl, directoryUrl, keySource: 'directory', verifiedAtMs: nowMs,
    });
    assert.equal(out.kind, 'VALID');
    if (out.kind === 'VALID') {
      assert.equal(out.keyid, keyid);
      assert.equal(out.directoryUrl, directoryUrl);
      assert.equal(out.keySource, 'directory');
      assert.equal(out.verifiedAtMs, nowMs);
    }
  });

  await check('E5', 'no outcome is ever labelled malicious', () => {
    const outcomes = [
      resolveOutcome({ state: 'absent' }),
      resolveOutcome({ state: 'unverified', reason: 'x' }),
      resolveOutcome({ state: 'signature_mismatch' }),
      resolveOutcome({ state: 'verified', keyid, agentUrl: '', directoryUrl: '', keySource: 'cache', verifiedAtMs: 0 }),
    ];
    for (const outcome of outcomes) {
      assert.ok(['NEUTRAL', 'VALID', 'INVALID'].includes(outcome.kind));
      assert.ok(!JSON.stringify(outcome).toLowerCase().includes('malicious'));
    }
  });

  section('F. Async verification with injected fetch + WebCrypto');

  const directory = await buildDirectory();

  await check('F1', 'real Ed25519 signature + signed directory -> VALID', async () => {
    const req = await buildValidRequest();
    const calls: FetchCall[] = [];
    const out = await verifyRequest(req, stubFetch(directory, calls), new Map());
    assert.equal(out.kind, 'VALID', JSON.stringify(out));
    if (out.kind === 'VALID') {
      assert.equal(out.keyid, keyid);
      assert.equal(out.agentUrl, fx.context.agentUrl);
      assert.equal(out.directoryUrl, directoryUrl);
      assert.equal(out.keySource, 'directory');
    }
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, directoryUrl);
    assert.equal(calls[0].init?.redirect, 'error');
    assert.notEqual(calls[0].init?.signal, undefined);
  });

  await check('F2', 'tampered signature -> INVALID signature_mismatch', async () => {
    const req = await buildValidRequest(agentLegacy, 'other.example'); // signed for a different authority
    const out = await verifyRequest({ ...req, authority }, stubFetch(directory, []), new Map());
    assert.equal(out.kind, 'INVALID');
    if (out.kind === 'INVALID') assert.equal(out.reason, 'signature_mismatch');
  });

  await check('F3', 'no signature headers -> NEUTRAL no_signature', async () => {
    const c = fx.cases.find((item) => item.id === 'neutral-no-signature') as FixtureCase;
    const out = await verifyRequest(
      { rawSignature: c.rawSignature as string, rawInput: c.rawInput as string, rawAgent: c.rawAgent as string, authority },
      stubFetch(directory, []),
      new Map(),
    );
    assert.equal(out.kind, 'NEUTRAL');
    if (out.kind === 'NEUTRAL') assert.equal(out.reason, c.reason);
  });

  await check('F4', 'dictionary Signature-Agent form verifies end-to-end', async () => {
    const req = await buildValidRequest(agentDictionary);
    const out = await verifyRequest(req, stubFetch(directory, []), new Map());
    assert.equal(out.kind, 'VALID', JSON.stringify(out));
  });

  await check('F5', 'fetch failure -> NEUTRAL, never INVALID/malicious', async () => {
    const c = fx.cases.find((item) => item.id === 'neutral-directory-unavailable') as FixtureCase;
    assert.equal(c.fetchFails, true);
    const req = await buildValidRequest();
    const out = await verifyRequest(req, stubFetch(directory, [], true), new Map());
    assert.equal(out.kind, 'NEUTRAL');
    if (out.kind === 'NEUTRAL') assert.equal(out.reason, c.reason);
  });

  await check('F6', 'Content-Digest mismatch -> NEUTRAL', async () => {
    const bad = await buildDirectory({ digestBad: true });
    const req = await buildValidRequest();
    const out = await verifyRequest(req, stubFetch(bad, []), new Map());
    assert.equal(out.kind, 'NEUTRAL');
    if (out.kind === 'NEUTRAL') assert.equal(out.reason, 'content_digest_mismatch');
  });

  await check('F7', 'missing Content-Digest -> NEUTRAL', async () => {
    const bad = await buildDirectory({ omitDigest: true });
    const req = await buildValidRequest();
    const out = await verifyRequest(req, stubFetch(bad, []), new Map());
    assert.equal(out.kind, 'NEUTRAL');
    if (out.kind === 'NEUTRAL') assert.equal(out.reason, 'missing_content_digest');
  });

  await check('F8', 'missing directory possession signature -> NEUTRAL', async () => {
    const bad = await buildDirectory({ omitSignature: true });
    const req = await buildValidRequest();
    const out = await verifyRequest(req, stubFetch(bad, []), new Map());
    assert.equal(out.kind, 'NEUTRAL');
    if (out.kind === 'NEUTRAL') assert.equal(out.reason, 'missing_directory_signature');
  });

  await check('F9', 'wrong directory signature tag -> NEUTRAL', async () => {
    const bad = await buildDirectory({ tag: 'web-bot-auth' });
    const req = await buildValidRequest();
    const out = await verifyRequest(req, stubFetch(bad, []), new Map());
    assert.equal(out.kind, 'NEUTRAL');
    if (out.kind === 'NEUTRAL') assert.equal(out.reason, 'invalid_directory_signature_tag');
  });

  await check('F10', '>100 directory keys -> NEUTRAL', async () => {
    const bad = await buildDirectory({ keys: Array.from({ length: 101 }, () => ({ kty: 'OKP', crv: 'Ed25519', x })) });
    const req = await buildValidRequest();
    const out = await verifyRequest(req, stubFetch(bad, []), new Map());
    assert.equal(out.kind, 'NEUTRAL');
    if (out.kind === 'NEUTRAL') assert.equal(out.reason, 'too_many_directory_keys');
  });

  await check('F11', '>64KB directory body -> NEUTRAL', async () => {
    const req = await buildValidRequest();
    const oversized = directory.body + ' '.repeat(70_000);
    const out = await verifyRequest(req, stubFetch(directory, [], false, oversized), new Map());
    assert.equal(out.kind, 'NEUTRAL');
    if (out.kind === 'NEUTRAL') assert.equal(out.reason, 'directory_too_large');
  });

  await check('F12', 'authentic directory without the requested keyid -> NEUTRAL', async () => {
    const other = await buildDirectory({
      x: secondJwk.x as string,
      keyid, // claims the vector kid, but publishes only the second key
      signer: secondKeyPair.privateKey,
    });
    const req = await buildValidRequest();
    const out = await verifyRequest(req, stubFetch(other, []), new Map());
    assert.equal(out.kind, 'NEUTRAL');
    if (out.kind === 'NEUTRAL') assert.equal(out.reason, 'keyid_not_published');
  });

  await check('F13', 'stale cached key survives a transient fetch failure (rotation overlap)', async () => {
    const req = await buildValidRequest();
    const cache: DirectoryCache = new Map();
    const first = await verifyRequest(req, stubFetch(directory, []), cache);
    assert.equal(first.kind, 'VALID');
    for (const [key, entry] of cache) cache.set(key, { ...entry, expiresAtMs: nowMs - 1 });
    const second = await verifyRequest(req, stubFetch(directory, [], true), cache);
    assert.equal(second.kind, 'VALID', JSON.stringify(second));
    if (second.kind === 'VALID') assert.equal(second.keySource, 'cache');
  });

  await check('F14', 'negative cache is <=5 min and suppresses immediate refetch', async () => {
    const cache: DirectoryCache = new Map();
    const req = await buildValidRequest();
    const first = await verifyRequest(req, stubFetch(directory, [], true), cache);
    assert.equal(first.kind, 'NEUTRAL');
    const entry = Array.from(cache.values())[0];
    assert.equal(entry.kind, 'negative');
    assert.ok(entry.expiresAtMs - nowMs > 0 && entry.expiresAtMs - nowMs <= 300_000);
    const calls: FetchCall[] = [];
    const second = await verifyRequest(req, stubFetch(directory, calls), cache);
    assert.equal(second.kind, 'NEUTRAL');
    if (second.kind === 'NEUTRAL') assert.equal(second.reason, 'directory_negative_cache');
    assert.equal(calls.length, 0);
  });

  await check('F15', 'expired signature is INVALID before any fetch', async () => {
    const c = fx.cases.find((item) => item.id === 'invalid-expired') as FixtureCase;
    const req = await buildValidRequest(agentLegacy, authority, c.input as string);
    const calls: FetchCall[] = [];
    const out = await verifyWebBotAuthRequest({
      ...req, nowMs, subtle, cache: new Map(), fetch: stubFetch(directory, calls),
    });
    assert.equal(out.kind, 'INVALID');
    if (out.kind === 'INVALID') assert.equal(out.reason, c.reason);
    assert.equal(calls.length, 0);
  });

  section('G. Purity / determinism');

  await check('G1', 'buildSignatureBase does not mutate parsed state', () => {
    const p = parseSignatureHeaders(dummySignature(), fx.validInput, agentLegacy);
    const before = JSON.stringify(p);
    buildSignatureBase(p, { '@authority': authority, 'signature-agent': agentLegacy });
    assert.equal(JSON.stringify(p), before);
  });

  await check('G2', 'enforcePolicy and resolveOutcome are deterministic', () => {
    const p = parseSignatureHeaders(dummySignature(), fx.validInput, agentLegacy);
    assert.deepEqual(enforcePolicy(p, nowMs), enforcePolicy(p, nowMs));
    const state = { state: 'unverified' as const, reason: 'x' };
    assert.deepEqual(resolveOutcome(state), resolveOutcome(state));
  });

  await check('G3', 'duplicate header arrays are rejected, not ambiguously accepted', () => {
    const p = parseSignatureHeaders([dummySignature(), dummySignature()], fx.validInput, agentLegacy);
    assert.equal(p.error, 'duplicate_signature_header');
    const q = parseSignatureHeaders(dummySignature(), fx.validInput, [agentLegacy, agentLegacy]);
    assert.equal(q.error, 'duplicate_signature_agent');
  });
}

/* -------------------------------------------------------------------------- */

let runFailed = false;
try {
  await run();
} catch (error) {
  runFailed = true;
  console.error(`FAIL  [fatal] unexpected error: ${describeError(error)}`);
} finally {
  const failedTotal = failed + (runFailed ? 1 : 0);
  if (failedTotal === 0) {
    console.log(`\nRESULT: PASS — ${passed} passed, 0 failed`);
  } else {
    console.log(`\nRESULT: FAIL — ${passed} passed, ${failedTotal} failed`);
    process.exitCode = 1;
  }
}

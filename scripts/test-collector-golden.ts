/**
 * Collector golden-master harness (WEB RESEARCH R5) — byte-identical pins.
 *
 *   npx tsx scripts/test-collector-golden.ts
 *   GOLDEN_UPDATE=1 npx tsx scripts/test-collector-golden.ts   # local regeneration ONLY
 *
 * A golden record is `versioned inputs + expected raw bytes + SHA-256 + verdict
 * label`. Every comparison is byte-identical over `stableStringify` output —
 * never a loose deep-equal. The fixture pins:
 *
 *   - stableStringify of collector payloads (null, unicode, -0, duplicate JSON
 *     keys, equal/UTF-16-colliding sort keys, long arrays, sorted object keys);
 *   - computeHardwareFingerprint / computeBrowserFingerprint on a frozen,
 *     versioned CollectedSignals input;
 *   - collectAllSignals minus its volatile `meta` family.
 *
 * All browser globals are replaced with fixed deterministic stubs and TZ is
 * pinned to UTC, so the bytes are portable across hosts. Additive flags default
 * off; turning them on must yield ZERO golden diffs (flag-off parity). CI never
 * writes goldens: `--update` / `GOLDEN_UPDATE=1` is refused when CI is detected.
 *
 * The expectations in scripts/fixtures/collector-golden.json are golden. Never
 * edit an expected value to make a failing case green — fix the implementation
 * instead (or regenerate locally with an explicit, reviewed update).
 */

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import {
  collectAllSignals,
  computeBrowserFingerprint,
  computeHardwareFingerprint,
  stableHash32,
  stableStringify,
} from '../src/client/signals/index.ts';
import type { CollectedSignals } from '../src/client/signals/index.ts';

// Must be set before any collector reads Intl / Date. Imports above do not
// touch those APIs at module-evaluation time, so top-level order is sufficient.
process.env.TZ = 'UTC';

// V8's Math.pow result differs in the last digit between Node 22 (CI) and Node 24
// (local). Normalize to 15 significant digits inside this harness only, so golden
// bytes are host-independent. Production collectors are untouched.
const ORIGINAL_MATH_POW = Math.pow;
Math.pow = (base: number, exponent: number): number => {
  const value = ORIGINAL_MATH_POW(base, exponent);
  return Number.isFinite(value) ? Number(value.toPrecision(15)) : value;
};

const FIXTURE_URL = new URL('./fixtures/collector-golden.json', import.meta.url);
const SCHEMA_VERSION = 2;
const GOLDEN_TIMEOUT_MS = 50;
const CONTRACT_GETS = 8;

/* -------------------------------------------------------------------------- */
/* Types                                                                       */
/* -------------------------------------------------------------------------- */

type CaseKind = 'stableStringify' | 'hardwareFingerprint' | 'browserFingerprint' | 'collectAllSignals';

interface CaseSpec {
  id: string;
  name: string;
  kind: CaseKind;
  verdict: string;
}

interface Expected {
  raw_bytes: string;
  sha256: string;
  digest: string;
}

interface GoldenCase extends CaseSpec {
  input: unknown;
  expected: Expected;
}

interface GoldenFixture {
  schema_version: number;
  title: string;
  frozen: boolean;
  offline: boolean;
  generated_on: string;
  note: string;
  determinism: Record<string, unknown>;
  flags: Record<string, unknown>;
  inputs: Record<string, unknown>;
  cases: GoldenCase[];
}

interface HarnessFlags {
  /** Additive-only diagnostics: changes verbosity, never canonical bytes. */
  additiveDiagnostics: boolean;
  /** Pass explicit default options to collectAllSignals (semantic no-op). */
  explicitEmptyOptions: boolean;
}

interface Evaluated {
  rawBytes: string;
  digest: string;
}

const FLAGS_OFF: HarnessFlags = Object.freeze({ additiveDiagnostics: false, explicitEmptyOptions: false });
const FLAGS_ON: HarnessFlags = Object.freeze({ additiveDiagnostics: true, explicitEmptyOptions: true });

/* -------------------------------------------------------------------------- */
/* Deterministic environment                                                   */
/* -------------------------------------------------------------------------- */

interface SavedGlobal {
  key: string;
  descriptor: PropertyDescriptor | undefined;
}

function navigatorStub(): Record<string, unknown> {
  return {
    platform: 'GoldenPlatform',
    userAgent: 'GoldenUA/1.0',
    language: 'en-US',
    languages: ['en-US'],
    vendor: 'GoldenVendor',
    hardwareConcurrency: 8,
    deviceMemory: 8,
    maxTouchPoints: 0,
    webdriver: false,
    userAgentData: { platform: 'GoldenPlatform', architecture: 'x86', bitness: '64', mobile: false },
    mediaDevices: {
      enumerateDevices: async () => [{ kind: 'audioinput' }, { kind: 'audiooutput' }, { kind: 'videoinput' }],
    },
    storage: { estimate: async () => ({ usage: 1024, quota: 2048 }) },
    permissions: { query: async () => ({ state: 'prompt' }) },
  };
}

function screenStub(): Record<string, unknown> {
  return {
    width: 1920,
    height: 1080,
    availWidth: 1920,
    availHeight: 1040,
    colorDepth: 24,
    pixelRatio: 1,
    maxTouchPoints: 0,
  };
}

function windowStub(nav: Record<string, unknown>): Record<string, unknown> {
  return {
    devicePixelRatio: 1,
    outerWidth: 1920,
    outerHeight: 1080,
    innerWidth: 1900,
    innerHeight: 1000,
    location: { search: '', href: 'https://golden.test/' },
    navigator: nav,
    screen: screenStub(),
    matchMedia: () => ({ matches: false }),
    speechSynthesis: { getVoices: () => [] },
    prompt: '',
    onerror: null,
    addEventListener() { /* no-op */ },
    removeEventListener() { /* no-op */ },
  };
}

/** Install fixed browser globals; remove DOM/audio surfaces so collectors take
 * their deterministic "unavailable" fallback paths. Returns a restore token. */
function installDeterministicGlobals(): SavedGlobal[] {
  const globalObj = globalThis as unknown as Record<string, unknown>;
  const nav = navigatorStub();
  const values: Record<string, unknown> = {
    navigator: nav,
    screen: screenStub(),
    window: windowStub(nav),
  };
  const removed = ['document', 'OfflineAudioContext', 'AudioContext', 'RTCPeerConnection', 'localStorage', 'sessionStorage', 'indexedDB', 'location'];
  const saved: SavedGlobal[] = [];
  for (const key of [...Object.keys(values), ...removed]) {
    saved.push({ key, descriptor: Object.getOwnPropertyDescriptor(globalObj, key) });
  }
  for (const [key, value] of Object.entries(values)) {
    Object.defineProperty(globalObj, key, { configurable: true, writable: true, value });
  }
  for (const key of removed) {
    delete globalObj[key];
  }
  return saved;
}

function restoreGlobals(saved: SavedGlobal[]): void {
  const globalObj = globalThis as unknown as Record<string, unknown>;
  for (const entry of saved) {
    if (entry.descriptor) Object.defineProperty(globalObj, entry.key, entry.descriptor);
    else delete globalObj[entry.key];
  }
}

async function withDeterministicGlobals<T>(fn: () => Promise<T>): Promise<T> {
  const saved = installDeterministicGlobals();
  try {
    return await fn();
  } finally {
    restoreGlobals(saved);
  }
}

/* -------------------------------------------------------------------------- */
/* Versioned inputs                                                            */
/* -------------------------------------------------------------------------- */

function syntheticSignals(): CollectedSignals {
  return {
    canvas: {
      winding: true,
      geometry: 'a'.repeat(32),
      text: 'b'.repeat(32),
      geometryUnstable: false,
      textUnstable: null,
      geometryDataUrl: null,
      textDataUrl: null,
    },
    canvasNoise: {
      classification: 'clean',
      maxChannelDelta: 0,
      stabilizedGeometryHash: 'c'.repeat(32),
      flags: [],
    },
    fonts: {
      installed: ['Arial', 'Helvetica', 'Segoe UI', '🚀 Font'],
      fontHash: 'd'.repeat(32),
      platformClassGuess: 'windows',
    },
    fontPreferences: {
      widths: { default: 16, apple: 16, serif: 16, sans: 16, mono: 13, min: 8, system: 16 },
      widthsExactIntegers: true,
    },
    emoji: { font: 'sans-serif', width: 16, height: 18, top: 0, bottom: 0, left: 0, right: 16, x: 0, y: 0 },
    webglBasics: {
      version: 'WebGL 2.0',
      vendor: 'WebKit',
      renderer: 'WebKit WebGL',
      shadingLanguageVersion: 'WebGL GLSL ES 3.00',
      vendorUnmasked: 'GoldenVendor',
      rendererUnmasked: 'Golden GPU 4090',
    },
    webglExtensions: {
      contextAttributes: 'e'.repeat(32),
      parameters: 'f'.repeat(32),
      shaderPrecisions: '0'.repeat(32),
      extensions: '1'.repeat(32),
      extensionParameters: '2'.repeat(32),
      supportedExtensions: ['EXT_a', 'EXT_b'],
      unsupportedExtensions: ['EXT_z'],
    },
    webglGpuIdentity: {
      normalizedGpu: 'Golden GPU 4090',
      normalizedGpuHash: '3'.repeat(32),
      invariantLimits: {
        maxTextureSize: 16384,
        maxCubeMapTextureSize: 16384,
        maxRenderbufferSize: 16384,
        maxViewportDims: [16384, 16384],
        max3dTextureSize: 2048,
        maxArrayTextureLayers: 2048,
        aliasedPointSizeRange: [1, 1024],
      },
    },
    audio: {
      sum: 123.456,
      code: 0,
      audioBaseLatency: 0.01,
      listenerForwardXMaxValue: 1,
      biquadGainMaxValue: 1,
      compressorAttackDefault: 0.003,
      oscillatorDetuneMax: 1200,
    },
    math: {
      values: { sin: '0.84', cos: '0.53', tan: '1.58' },
      mathHash: '4'.repeat(32),
      errorStackFunctions: ['message', 'stack'],
      errorStackHash: '5'.repeat(32),
    },
    systemEntropy: {
      timezone: 'UTC',
      timezoneOffset: 0,
      deviceMemory: 8,
      hardwareConcurrency: 8,
      screen: { width: 1920, height: 1080, colorDepth: 24, pixelRatio: 1, maxTouchPoints: 0 },
      mediaDeviceCounts: { audioinput: 1, audiooutput: 1, videoinput: 1 },
      storageQuota: { usage: 1024, quota: 2048 },
      applePayAvailable: false,
      speechVoicesCount: 3,
      permissions: { geolocation: 'prompt', notifications: 'prompt', camera: 'prompt', microphone: 'prompt' },
    },
    automation: {
      reasonIds: ['C', 'V'],
      weakReasonIds: ['launch.no-speech-voices'],
      agentName: null,
      shapes: ['chrome'],
    },
    meta: {
      collectedAt: '2026-11-24T00:00:00.000Z',
      totalDurationMs: 12,
      timingsMs: { canvas: 1, fonts: 2 },
    },
  };
}

const CASE_SPECS: readonly CaseSpec[] = Object.freeze([
  { id: 'SS-N01', name: 'stableStringify: top-level null', kind: 'stableStringify', verdict: 'stable' },
  { id: 'SS-N02', name: 'stableStringify: nested null / dropped undefined', kind: 'stableStringify', verdict: 'stable' },
  { id: 'SS-U01', name: 'stableStringify: unicode (emoji, CJK, combining, U+2028)', kind: 'stableStringify', verdict: 'stable' },
  { id: 'SS-Z01', name: 'stableStringify: negative zero', kind: 'stableStringify', verdict: 'stable' },
  { id: 'SS-D01', name: 'stableStringify: duplicate JSON keys (last wins)', kind: 'stableStringify', verdict: 'stable' },
  { id: 'SS-K01', name: 'stableStringify: equal/colliding sort keys (UTF-16 order)', kind: 'stableStringify', verdict: 'stable-sort' },
  { id: 'SS-A01', name: 'stableStringify: long array (512 elements)', kind: 'stableStringify', verdict: 'stable' },
  { id: 'SS-S01', name: 'stableStringify: sorted object keys', kind: 'stableStringify', verdict: 'stable-sort' },
  { id: 'FP-HW-01', name: 'computeHardwareFingerprint (hardware-bound)', kind: 'hardwareFingerprint', verdict: 'hardware-bound' },
  { id: 'FP-BR-01', name: 'computeBrowserFingerprint (engine-bound)', kind: 'browserFingerprint', verdict: 'engine-bound' },
  { id: 'COL-01', name: 'collectAllSignals minus volatile meta', kind: 'collectAllSignals', verdict: 'stable-no-meta' },
]);

/** Declarative, versioned inputs. Markers are expanded by resolveInput so the
 * fixture can express values JSON cannot carry natively (-0, undefined, JSON
 * text with duplicate keys, generated long arrays, shared signal objects). */
const INPUTS_BY_ID: Readonly<Record<string, unknown>> = Object.freeze({
  'SS-N01': null,
  'SS-N02': { z: null, a: [null, { y: null, x: 1 }], drop: { $undefined: true } },
  'SS-U01': { label: 'café 🚀 日本語 e\u0301\u2028line', emoji: '👍🏽', quote: 'a"b\\c' },
  'SS-Z01': { zero: 0, neg: { $negZero: true }, arr: [{ $negZero: true }, -1, 0] },
  'SS-D01': { $raw_json: '{"b":1,"a":2,"a":3,"b":4}' },
  'SS-K01': { A: 1, a: 2, 'é': 3, 'e\u0301': 4, '10': 5, '2': 6, 'á': 7 },
  'SS-A01': { $range: 512 },
  'SS-S01': { zeta: 1, alpha: 2, mid: 3, beta: 4 },
  'FP-HW-01': { $inputRef: 'signals' },
  'FP-BR-01': { $inputRef: 'signals' },
  'COL-01': { timeouts: GOLDEN_TIMEOUT_MS },
});

function resolveInput(input: unknown, fixture: GoldenFixture): unknown {
  if (input === null || typeof input !== 'object') return input;
  if (Array.isArray(input)) return input.map((item) => resolveInput(item, fixture));
  const obj = input as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(obj, '$negZero')) return -0;
  if (Object.prototype.hasOwnProperty.call(obj, '$undefined')) return undefined;
  if (Object.prototype.hasOwnProperty.call(obj, '$raw_json')) return JSON.parse(String(obj.$raw_json));
  if (Object.prototype.hasOwnProperty.call(obj, '$range')) {
    return Array.from({ length: Number(obj.$range) }, (_, i) => i);
  }
  if (Object.prototype.hasOwnProperty.call(obj, '$inputRef')) {
    return (fixture.inputs ?? {})[String(obj.$inputRef)];
  }
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) out[key] = resolveInput(value, fixture);
  return out;
}

/* -------------------------------------------------------------------------- */
/* Evaluation                                                                  */
/* -------------------------------------------------------------------------- */

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

async function evaluateCase(fixture: GoldenFixture, c: GoldenCase, flags: HarnessFlags): Promise<Evaluated> {
  switch (c.kind) {
    case 'stableStringify': {
      const value = resolveInput(c.input, fixture);
      const rawBytes = stableStringify(value);
      return { rawBytes, digest: stableHash32(rawBytes) };
    }
    case 'hardwareFingerprint': {
      const signals = resolveInput(c.input, fixture) as CollectedSignals;
      return { rawBytes: stableStringify(signals), digest: computeHardwareFingerprint(signals) };
    }
    case 'browserFingerprint': {
      const signals = resolveInput(c.input, fixture) as CollectedSignals;
      return { rawBytes: stableStringify(signals), digest: computeBrowserFingerprint(signals) };
    }
    case 'collectAllSignals': {
      const inputObj = (resolveInput(c.input, fixture) ?? {}) as Record<string, unknown>;
      const timeouts = typeof inputObj.timeouts === 'number' ? inputObj.timeouts : GOLDEN_TIMEOUT_MS;
      const opts = flags.explicitEmptyOptions
        ? { timeouts, browserHints: {}, secChBrands: [] as string[] }
        : { timeouts };
      const collected = await collectAllSignals(opts);
      const { meta: _volatileMeta, ...stablePayload } = collected;
      const rawBytes = stableStringify(stablePayload);
      return { rawBytes, digest: stableHash32(rawBytes) };
    }
    default:
      throw new Error(`unknown case kind: ${(c as GoldenCase).kind}`);
  }
}

function expectedFrom(evaluated: Evaluated): Expected {
  return {
    raw_bytes: evaluated.rawBytes,
    sha256: sha256Hex(evaluated.rawBytes),
    digest: evaluated.digest,
  };
}

/* -------------------------------------------------------------------------- */
/* Fixture loading — load-once / get-N contract                                */
/* -------------------------------------------------------------------------- */

let fixtureReads = 0;
let cachedFixture: GoldenFixture | null = null;

async function loadFixtureOnce(): Promise<GoldenFixture> {
  if (cachedFixture) return cachedFixture;
  fixtureReads++;
  const text = await readFile(FIXTURE_URL, 'utf8');
  cachedFixture = JSON.parse(text) as GoldenFixture;
  return cachedFixture;
}

async function runContractTest(): Promise<boolean> {
  const seen: GoldenFixture[] = [];
  for (let i = 0; i < CONTRACT_GETS; i++) seen.push(await loadFixtureOnce());
  seen.push(...(await Promise.all(Array.from({ length: CONTRACT_GETS }, () => loadFixtureOnce()))));
  const identical = seen.every((fixture) => fixture === seen[0]);
  const ok = fixtureReads === 1 && identical && seen.length === CONTRACT_GETS * 2;
  console.log(
    `[${ok ? 'PASS' : 'FAIL'}] CONTRACT load-once/get-${CONTRACT_GETS * 2}: reads=${fixtureReads} identical=${identical}`
  );
  return ok;
}

/* -------------------------------------------------------------------------- */
/* CI write policy                                                             */
/* -------------------------------------------------------------------------- */

function isCI(): boolean {
  return Boolean(process.env.CI || process.env.GITHUB_ACTIONS || process.env.CONTINUOUS_INTEGRATION);
}

function wantsUpdate(): boolean {
  return process.argv.includes('--update') || process.env.GOLDEN_UPDATE === '1';
}

/** Pure policy check — CI must never write goldens. */
function assertGoldenWritable(update: boolean, ci: boolean): void {
  if (update && ci) throw new Error('CI must not write goldens (refusing --update / GOLDEN_UPDATE=1)');
}

function runPolicyTests(): boolean {
  let ok = true;
  let ciBlocked = false;
  try {
    assertGoldenWritable(true, true);
  } catch {
    ciBlocked = true;
  }
  let ciVerifyAllowed = true;
  try {
    assertGoldenWritable(false, true);
  } catch {
    ciVerifyAllowed = false;
  }
  let localUpdateAllowed = true;
  try {
    assertGoldenWritable(true, false);
  } catch {
    localUpdateAllowed = false;
  }
  ok = ciBlocked && ciVerifyAllowed && localUpdateAllowed;
  console.log(
    `[${ok ? 'PASS' : 'FAIL'}] POLICY ci-write-blocked=${ciBlocked} ci-verify-allowed=${ciVerifyAllowed} local-update-allowed=${localUpdateAllowed}`
  );
  return ok;
}

/* -------------------------------------------------------------------------- */
/* Fixture construction (local regeneration only)                              */
/* -------------------------------------------------------------------------- */

function buildFixture(): GoldenFixture {
  const cases: GoldenCase[] = CASE_SPECS.map((spec) => ({
    ...spec,
    input: INPUTS_BY_ID[spec.id] ?? null,
    expected: { raw_bytes: '', sha256: '', digest: '' },
  }));
  return {
    schema_version: SCHEMA_VERSION,
    title: 'Collector golden master — stableStringify / fingerprints / collectAllSignals',
    frozen: true,
    offline: true,
    generated_on: '2026-11-24',
    note:
      'Versioned inputs + expected raw bytes + SHA-256 + verdict label. Comparisons are byte-identical over stableStringify. Browser globals and TZ are pinned. Additive flags default off and must produce zero golden diffs when on. CI must not write goldens; regenerate locally with GOLDEN_UPDATE=1 only after review.',
    determinism: {
      timezone: 'UTC',
      navigator: { platform: 'GoldenPlatform', hardwareConcurrency: 8, deviceMemory: 8, maxTouchPoints: 0 },
      screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24 },
      window: { outerWidth: 1920, outerHeight: 1080, innerWidth: 1900, innerHeight: 1000, devicePixelRatio: 1 },
      collectAllSignalsTimeoutMs: GOLDEN_TIMEOUT_MS,
      removedGlobals: ['document', 'OfflineAudioContext', 'AudioContext', 'RTCPeerConnection', 'localStorage', 'sessionStorage', 'indexedDB'],
    },
    flags: {
      default: 'off',
      on_names: ['additiveDiagnostics', 'explicitEmptyOptions'],
      expected_golden_diffs: 0,
      note: 'Flag-on passes explicit empty browserHints/secChBrands and additive diagnostics; canonical bytes must be unchanged.',
    },
    inputs: { signals: syntheticSignals() },
    cases,
  };
}

/* -------------------------------------------------------------------------- */
/* Verification                                                                */
/* -------------------------------------------------------------------------- */

async function runVerification(fixture: GoldenFixture): Promise<boolean> {
  if (fixture.schema_version !== SCHEMA_VERSION) {
    console.error(`FAIL schema_version: expected ${SCHEMA_VERSION}, found ${fixture.schema_version}`);
    return false;
  }
  let allPassed = true;
  let goldenDiffs = 0;
  for (const c of fixture.cases) {
    const off = await evaluateCase(fixture, c, FLAGS_OFF);
    const on = await evaluateCase(fixture, c, FLAGS_ON);
    const selfHashOk = c.expected.sha256 === sha256Hex(c.expected.raw_bytes);
    const offMatches =
      off.rawBytes === c.expected.raw_bytes &&
      off.digest === c.expected.digest &&
      sha256Hex(off.rawBytes) === c.expected.sha256;
    const onMatches =
      on.rawBytes === c.expected.raw_bytes &&
      on.digest === c.expected.digest &&
      sha256Hex(on.rawBytes) === c.expected.sha256;
    const parityOk = off.rawBytes === on.rawBytes && off.digest === on.digest;
    if (!parityOk) goldenDiffs++;
    const ok = selfHashOk && offMatches && onMatches && parityOk;
    if (!ok) allPassed = false;
    const detail = ok
      ? `bytes=${off.rawBytes.length}B sha=${c.expected.sha256.slice(0, 12)} digest=${c.expected.digest}`
      : `off(len=${off.rawBytes.length},sha=${sha256Hex(off.rawBytes)}) on(len=${on.rawBytes.length},sha=${sha256Hex(on.rawBytes)}) expected(sha=${c.expected.sha256}) selfHash=${selfHashOk}`;
    console.log(`[${ok ? 'PASS' : 'FAIL'}] ${c.id} ${c.verdict} ${c.name} :: ${detail}`);
  }
  const expectedDiffs = Number(fixture.flags?.expected_golden_diffs ?? 0);
  const parityOverall = goldenDiffs === expectedDiffs;
  if (!parityOverall) allPassed = false;
  console.log(
    `[${parityOverall ? 'PASS' : 'FAIL'}] FLAG-OFF PARITY: golden diffs flag-on vs off = ${goldenDiffs} (expected ${expectedDiffs})`
  );
  return allPassed;
}

/* -------------------------------------------------------------------------- */
/* Entry point                                                                 */
/* -------------------------------------------------------------------------- */

async function main(): Promise<number> {
  const update = wantsUpdate();
  const ci = isCI();
  assertGoldenWritable(update, ci);

  let fixture: GoldenFixture;
  if (update) {
    fixture = buildFixture();
    await withDeterministicGlobals(async () => {
      for (const c of fixture.cases) c.expected = expectedFrom(await evaluateCase(fixture, c, FLAGS_OFF));
    });
    await writeFile(FIXTURE_URL, `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');
    console.log(`GOLDENS UPDATED (local only): ${fixture.cases.length} cases written to collector-golden.json`);
  } else {
    fixture = await loadFixtureOnce();
  }

  let ok = true;
  ok = (await runContractTest()) && ok;
  ok = runPolicyTests() && ok;
  ok = (await withDeterministicGlobals(() => runVerification(fixture))) && ok;

  console.log(
    `RESULT collector-golden: ${ok ? 'PASS' : 'FAIL'} — ${fixture.cases.length} cases, schema v${fixture.schema_version}, flags default off`
  );
  return ok ? 0 : 1;
}

main()
  .then((code) => process.exit(code))
  .catch((error: unknown) => {
    console.error('FAIL collector-golden: unexpected error', error);
    process.exit(1);
  });

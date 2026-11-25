/**
 * Regression suite for the three-tier identity backlog helpers.
 *
 * Covers the strategy-only contract (no fabricated ids), stable high-recall group keys,
 * and the hardware-invariant pure-FNV 512-bit profile — including hostile input,
 * volatility exclusion and determinism.
 *
 *   npx tsx scripts/test-identity-tiers.ts
 */
import assert from 'node:assert/strict';

import {
  resolveHardwareSimHashProfile,
  resolveSupplementaryHighRecall,
  resolveVisitorIdentityTier,
  WEBGPU_RESEARCH_ONLY_NOTE,
  WEBGPU_STATIC_ENTROPY,
  VOLATILE_SIGNAL_KEYS,
  type HardwareSimHashProfile,
  type VisitorIdentityTier,
} from '../src/lib/identityTiers';
import { deriveSupplementaryCohort } from '../src/lib/supplementaryCohort';

let passed = 0;
const failures: string[] = [];

function check(name: string, verify: () => void): void {
  try {
    verify();
    passed += 1;
    console.log(`  PASS  ${name}`);
  } catch (error) {
    failures.push(name);
    console.error(`  FAIL  ${name}`);
    console.error(`        ${error instanceof Error ? error.message : String(error)}`);
  }
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

/* -------------------------------------------------------------------------- */
/* 1. Tier 1 — strategy only, never an id                                      */
/* -------------------------------------------------------------------------- */

section('1. resolveVisitorIdentityTier — strategy only');

check('first-party storage continuity -> precision / high with a reason', () => {
  const result: VisitorIdentityTier = resolveVisitorIdentityTier({
    storageVisitorId: 'real-visitor-id',
    storageValid: true,
  });
  assert.equal(result.visitor_id_strategy, 'precision');
  assert.equal(result.confidence, 'high');
  assert.ok(result.reason.includes('first_party_storage_valid'));
});

check('result has exactly the three strategy fields and never an id', () => {
  const result = resolveVisitorIdentityTier({
    storageVisitorId: 'v-123',
    exactHardwareId: 'hw-456',
    storageValid: true,
  });
  assert.deepEqual(Object.keys(result).sort(), ['confidence', 'reason', 'visitor_id_strategy']);
  assert.ok(!Object.prototype.hasOwnProperty.call(result, 'visitorId'));
  assert.ok(!Object.prototype.hasOwnProperty.call(result, 'visitor_id'));
  assert.ok(!JSON.stringify(result).includes('v-123'), 'supplied visitor id must never be echoed');
  assert.ok(!JSON.stringify(result).includes('hw-456'), 'supplied hardware id must never be echoed');
});

check('exact hardware with two distinct seeds -> precision / high', () => {
  const result = resolveVisitorIdentityTier({ exactHardwareId: 'hw', distinctStorageSeedsCount: 2 });
  assert.equal(result.visitor_id_strategy, 'precision');
  assert.equal(result.confidence, 'high');
  assert.ok(result.reason.includes('distinct_storage_seeds_consensus'));
});

check('exact hardware with a single seed -> high_recall / medium', () => {
  const result = resolveVisitorIdentityTier({ exactHardwareId: 'hw', distinctStorageSeedsCount: 1 });
  assert.equal(result.visitor_id_strategy, 'high_recall');
  assert.equal(result.confidence, 'medium');
  assert.ok(result.reason.includes('single_storage_seed_insufficient_for_precision'));
});

check('tampering overrides even valid storage -> high_recall / low', () => {
  const result = resolveVisitorIdentityTier({
    storageVisitorId: 'v-1',
    storageValid: true,
    tamperingDetected: true,
  });
  assert.equal(result.visitor_id_strategy, 'high_recall');
  assert.equal(result.confidence, 'low');
  assert.ok(result.reason.includes('tampering_detected'));
  assert.ok(result.reason.includes('untrusted_environment_requires_high_recall'));
});

check('anti-detect browser also forces high_recall / low', () => {
  const result = resolveVisitorIdentityTier({ storageValid: true, storageVisitorId: 'v', antiDetectBrowser: true });
  assert.equal(result.visitor_id_strategy, 'high_recall');
  assert.equal(result.confidence, 'low');
  assert.ok(result.reason.includes('anti_detect_browser'));
});

check('privacy hardening blocks hardware precision', () => {
  const result = resolveVisitorIdentityTier({
    exactHardwareId: 'hw',
    distinctStorageSeedsCount: 5,
    privacyHardened: true,
  });
  assert.equal(result.visitor_id_strategy, 'high_recall');
  assert.equal(result.confidence, 'low');
  assert.ok(result.reason.includes('privacy_hardened_blocks_hardware_precision'));
});

check('strong fuzzy match -> precision / medium', () => {
  const result = resolveVisitorIdentityTier({
    matchStage: 'lsh_fuzzy',
    matchSimilarity: 0.97,
    collisionDensity: 1,
    structuralAnchorRatio: 0.9,
  });
  assert.equal(result.visitor_id_strategy, 'precision');
  assert.equal(result.confidence, 'medium');
  assert.ok(result.reason.includes('high_similarity_low_collision_strong_anchor'));
});

check('fuzzy collision density >= 2 blocks precision', () => {
  const result = resolveVisitorIdentityTier({
    matchStage: 'lsh_fuzzy',
    matchSimilarity: 0.99,
    collisionDensity: 2,
    structuralAnchorRatio: 1,
  });
  assert.equal(result.visitor_id_strategy, 'high_recall');
  assert.ok(result.reason.includes('collision_density_blocks_precision'));
});

check('no evidence / new enrollment -> high_recall / low', () => {
  const result = resolveVisitorIdentityTier({});
  assert.equal(result.visitor_id_strategy, 'high_recall');
  assert.equal(result.confidence, 'low');
  assert.ok(result.reason.includes('insufficient_evidence_new_enrollment'));
});

check('hostile primitives never throw and degrade to high_recall / low', () => {
  for (const input of [null, undefined, 42, 'string', true, [], () => 1, Symbol('x')]) {
    let result: VisitorIdentityTier | undefined;
    assert.doesNotThrow(() => {
      result = resolveVisitorIdentityTier(input);
    }, `input ${String(input)} must not throw`);
    assert.equal(result?.visitor_id_strategy, 'high_recall');
    assert.equal(result?.confidence, 'low');
    assert.deepEqual(Object.keys(result ?? {}).sort(), ['confidence', 'reason', 'visitor_id_strategy']);
  }
});

check('throwing getter / proxy input never throws', () => {
  const hostile = new Proxy({}, {
    get() {
      throw new Error('hostile getter');
    },
  });
  let result: VisitorIdentityTier | undefined;
  assert.doesNotThrow(() => {
    result = resolveVisitorIdentityTier(hostile);
  });
  assert.equal(result?.visitor_id_strategy, 'high_recall');
  assert.equal(result?.confidence, 'low');
});

check('NaN / Infinity / negative / fractional seeds never fabricate precision', () => {
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -5, 1.9]) {
    const result = resolveVisitorIdentityTier({ exactHardwareId: 'hw', distinctStorageSeedsCount: bad });
    assert.equal(result.visitor_id_strategy, 'high_recall', `seed ${String(bad)}`);
  }
});

check('pathologically long id string is bounded, never echoed, never throws', () => {
  const huge = 'x'.repeat(1_000_000);
  let result: VisitorIdentityTier | undefined;
  assert.doesNotThrow(() => {
    result = resolveVisitorIdentityTier({ storageVisitorId: huge, storageValid: 1 as unknown as boolean });
  });
  assert.equal(result?.visitor_id_strategy, 'high_recall');
  assert.ok(!JSON.stringify(result).includes(huge));
});

check('tier decision is deterministic across repeated calls', () => {
  const signals = { storageValid: true, storageVisitorId: 'v', antiDetectBrowser: false };
  assert.deepEqual(resolveVisitorIdentityTier(signals), resolveVisitorIdentityTier(signals));
});

/* -------------------------------------------------------------------------- */
/* 2. Tier 2 — stable group keys, no minted ids                                */
/* -------------------------------------------------------------------------- */

section('2. resolveSupplementaryHighRecall — group keys only');

const STABLE_SIGNALS = {
  architecture: 'x86_64',
  browserFamily: 'chromium',
  deviceClass: 'desktop',
  engine: 'chromium',
  gpuArchFamily: 'x86',
  gpuRenderer: 'ANGLE (NVIDIA)',
  gpuVendor: 'Google Inc. (NVIDIA)',
  hostOs: 'windows',
  osFamily: 'windows',
  hardwareConcurrency: 8,
  deviceMemory: 8,
};

check('returns stable descriptive group keys from stable feature groups', () => {
  const keys = resolveSupplementaryHighRecall(STABLE_SIGNALS);
  assert.ok(keys.length > 5, `expected several group keys, got ${keys.length}`);
  assert.ok(keys.includes('grp:arch:x86_64'));
  assert.ok(keys.includes('grp:os:windows'));
  assert.ok(keys.includes('grp:engine:chromium'));
  assert.ok(keys.includes('grp:cores:5-8'));
});

check('group keys are sorted, unique and namespaced (not opaque ids)', () => {
  const keys = resolveSupplementaryHighRecall(STABLE_SIGNALS);
  assert.deepEqual(keys, Array.from(new Set(keys)).sort());
  for (const key of keys) {
    assert.match(key, /^grp:/, `key ${key} must be a namespaced group label`);
    assert.ok(key.length < 128, `key ${key} must be a short descriptive cohort label`);
  }
});

check('no supplied visitor/hardware id is echoed as a group key', () => {
  const keys = resolveSupplementaryHighRecall({
    ...STABLE_SIGNALS,
    storageVisitorId: 'secret-visitor',
    exactHardwareId: 'secret-hardware',
  });
  assert.ok(!keys.some((key) => key.includes('secret-visitor')));
  assert.ok(!keys.some((key) => key.includes('secret-hardware')));
});

check('volatile signals do not change the group keys', () => {
  const base = resolveSupplementaryHighRecall(STABLE_SIGNALS);
  const noisy = resolveSupplementaryHighRecall({
    ...STABLE_SIGNALS,
    canvasNoise: Math.random(),
    canvasHash: 'random-per-session',
    storageQuota: 1234567,
    timezoneOffset: -480,
    audioSum: 99.9,
  });
  assert.deepEqual(base, noisy);
});

check('empty / hostile input yields the deterministic fallback key without throwing', () => {
  for (const input of [undefined, null, 7, 'x', [], { canvasNoise: 1, storageQuota: 2, timezoneOffset: 3 }]) {
    let keys: string[] | undefined;
    assert.doesNotThrow(() => {
      keys = resolveSupplementaryHighRecall(input);
    });
    assert.deepEqual(keys, ['grp:unclassified']);
  }
});

check('supplementary keys are deterministic', () => {
  assert.deepEqual(resolveSupplementaryHighRecall(STABLE_SIGNALS), resolveSupplementaryHighRecall(STABLE_SIGNALS));
});

/* -------------------------------------------------------------------------- */
/* 3. Tier 3 — hardware-invariant vector + pure FNV 512-bit hash               */
/* -------------------------------------------------------------------------- */

section('3. resolveHardwareSimHashProfile — normalized + pure FNV');

const HARDWARE_SIGNALS = {
  architecture: 'x86_64',
  browserFamily: 'Chromium',
  deviceClass: 'desktop',
  deviceMemory: 8.1,
  engine: 'chromium',
  gpuArchFamily: 'x86',
  gpuRenderer: 'ANGLE (NVIDIA)',
  gpuVendor: 'Google Inc. (NVIDIA)',
  hardwareConcurrency: 8,
  hostOs: 'windows',
  osFamily: 'windows',
  platform: 'Win32',
};

check('hash is a 512-bit-shaped (128-char) lowercase hex string', () => {
  const profile: HardwareSimHashProfile = resolveHardwareSimHashProfile(HARDWARE_SIGNALS);
  assert.equal(typeof profile.hash512, 'string');
  assert.equal(profile.hash512.length, 128, '512 bits = 128 hex chars');
  assert.match(profile.hash512, /^[0-9a-f]{128}$/, 'must be lowercase hex only');
});

check('feature vector holds only normalized, whitelisted stable keys', () => {
  const profile = resolveHardwareSimHashProfile(HARDWARE_SIGNALS);
  assert.ok(profile.features.architecture === 'x86_64');
  assert.ok(profile.features.browser_family === 'chromium', 'values must be normalized lowercase');
  assert.ok(profile.features.memory_gb_bucket === '8', 'memory must be quantized');
  assert.ok(profile.features.cpu_cores_bucket === '5-8', 'cores must be bucketed');
  assert.deepEqual(profile.usedKeys, Object.keys(profile.features).sort());
  for (const key of Object.keys(profile.features)) {
    assert.ok(!VOLATILE_SIGNAL_KEYS.has(key), `volatile key ${key} leaked into features`);
  }
});

check('same signals produce an identical profile (determinism)', () => {
  const a = resolveHardwareSimHashProfile(HARDWARE_SIGNALS);
  const b = resolveHardwareSimHashProfile(HARDWARE_SIGNALS);
  assert.deepEqual(a, b);
  assert.equal(a.hash512, b.hash512);
});

check('object key insertion order does not affect the hash', () => {
  const a = resolveHardwareSimHashProfile(HARDWARE_SIGNALS);
  const reordered = {
    platform: 'Win32',
    osFamily: 'windows',
    hostOs: 'windows',
    hardwareConcurrency: 8,
    gpuVendor: 'Google Inc. (NVIDIA)',
    gpuRenderer: 'ANGLE (NVIDIA)',
    gpuArchFamily: 'x86',
    engine: 'chromium',
    deviceMemory: 8.1,
    deviceClass: 'desktop',
    browserFamily: 'Chromium',
    architecture: 'x86_64',
  };
  const b = resolveHardwareSimHashProfile(reordered);
  assert.equal(a.hash512, b.hash512);
});

check('volatile signals never change the profile hash or features', () => {
  const clean = resolveHardwareSimHashProfile(HARDWARE_SIGNALS);
  const noisy = resolveHardwareSimHashProfile({
    ...HARDWARE_SIGNALS,
    canvasNoise: Math.random(),
    canvasHash: `per-session-${Date.now()}`,
    storageQuota: 987654321,
    timezoneOffset: -480,
    audioSum: 42.42,
  });
  assert.equal(clean.hash512, noisy.hash512, 'volatile noise must not change the hash');
  assert.deepEqual(clean.features, noisy.features, 'volatile noise must not change features');
});

check('detected volatile keys are reported but excluded', () => {
  const profile = resolveHardwareSimHashProfile({
    ...HARDWARE_SIGNALS,
    canvasNoise: 'noise',
    storageQuota: 100,
    timezoneOffset: 60,
  });
  assert.deepEqual(profile.ignoredVolatileKeys, ['canvasNoise', 'storageQuota', 'timezoneOffset']);
  for (const key of profile.ignoredVolatileKeys) {
    assert.ok(!Object.prototype.hasOwnProperty.call(profile.features, key));
  }
});

check('different hardware produces a different hash', () => {
  const intel = resolveHardwareSimHashProfile(HARDWARE_SIGNALS);
  const arm = resolveHardwareSimHashProfile({
    ...HARDWARE_SIGNALS,
    architecture: 'arm64',
    gpuArchFamily: 'arm',
    gpuVendor: 'Apple',
    gpuRenderer: 'Apple M2',
    hostOs: 'macos',
  });
  assert.notEqual(intel.hash512, arm.hash512);
});

check('numeric bucket jitter is stable (8 vs 8.2 memory, 8 vs 8.5 cores)', () => {
  const a = resolveHardwareSimHashProfile({ deviceMemory: 8, hardwareConcurrency: 8 });
  const b = resolveHardwareSimHashProfile({ deviceMemory: 8.2, hardwareConcurrency: 8.5 });
  assert.equal(a.hash512, b.hash512);
  assert.deepEqual(a.features, b.features);
});

check('hostile / empty input is safe, schema-valid and deterministic', () => {
  for (const input of [null, undefined, 3, 'x', [], Symbol('s'), new Proxy({}, { get() { throw new Error('no'); } })]) {
    let profile: HardwareSimHashProfile | undefined;
    assert.doesNotThrow(() => {
      profile = resolveHardwareSimHashProfile(input);
    });
    assert.match(profile?.hash512 ?? '', /^[0-9a-f]{128}$/);
    assert.deepEqual(profile?.features, {});
    assert.deepEqual(profile?.usedKeys, []);
    assert.deepEqual(profile?.ignoredVolatileKeys, []);
  }
  assert.equal(resolveHardwareSimHashProfile({}).hash512, resolveHardwareSimHashProfile({}).hash512);
});

check('unicode / oversized stable tokens are normalized without throwing', () =>  {
  const a = resolveHardwareSimHashProfile({ architecture: '  ARM64\u00a0 ' });
  const b = resolveHardwareSimHashProfile({ architecture: 'arm64' });
  assert.equal(a.hash512, b.hash512, 'whitespace normalization must be canonical');
  assert.doesNotThrow(() => resolveHardwareSimHashProfile({ gpuRenderer: 'ß'.repeat(50_000) }));
});

check('volatile-only signals yield the empty-vector FNV hash (no fabricated hardware)', () => {
  const profile = resolveHardwareSimHashProfile({ canvasNoise: 1, storageQuota: 2, timezoneOffset: 3 });
  assert.deepEqual(profile.features, {});
  assert.equal(profile.hash512, resolveHardwareSimHashProfile({}).hash512);
  assert.deepEqual(profile.ignoredVolatileKeys, ['canvasNoise', 'storageQuota', 'timezoneOffset']);
});

check('all three helpers are side-effect free on a frozen signal object', () => {
  const frozen = Object.freeze({ ...STABLE_SIGNALS, storageVisitorId: 'v', storageValid: true });
  const snapshot = JSON.stringify(frozen);
  assert.doesNotThrow(() => {
    resolveVisitorIdentityTier(frozen);
    resolveSupplementaryHighRecall(frozen);
    resolveHardwareSimHashProfile(frozen);
  });
  assert.equal(JSON.stringify(frozen), snapshot, 'input signals must not be mutated');
});

/* -------------------------------------------------------------------------- */
/* 4. Research-boundary compliance                                             */
/* -------------------------------------------------------------------------- */

section('4. Research-boundary compliance (WebGPU / heuristic framing)');

const WEBGPU_SIGNALS = {
  webgpuFeatures: new Set(['depth24plus', 'timestamp-query', 'texture-compression-bc']),
  webgpuLimits: {
    maxComputeWorkgroupSizeX: 256,
    maxComputeWorkgroupSizeY: 256,
    maxComputeWorkgroupSizeZ: 64,
    maxComputeWorkgroupsPerDimension: 65535,
  },
};

check('WebGPU static features + limits enter the profile deterministically', () => {
  const withGpu = resolveHardwareSimHashProfile({ ...HARDWARE_SIGNALS, ...WEBGPU_SIGNALS });
  const withoutGpu = resolveHardwareSimHashProfile(HARDWARE_SIGNALS);
  assert.ok(withGpu.usedKeys.includes('webgpu_features'));
  assert.ok(withGpu.usedKeys.includes('webgpu_limits_compute_wg_x'));
  assert.ok(withGpu.usedKeys.includes('webgpu_limits_compute_wg_y'));
  assert.ok(withGpu.usedKeys.includes('webgpu_limits_compute_wg_z'));
  assert.ok(withGpu.usedKeys.includes('webgpu_limits_dispatch_dim'));
  assert.equal(withGpu.features.webgpu_features, 'depth24plus,texture-compression-bc,timestamp-query');
  assert.notEqual(withGpu.hash512, withoutGpu.hash512, 'WebGPU static surface must affect the hash');
  assert.deepEqual(withGpu, resolveHardwareSimHashProfile({ ...HARDWARE_SIGNALS, ...WEBGPU_SIGNALS }));
});

check('WebGPU features Set and array produce the same normalized vector', () => {
  const asSet = resolveHardwareSimHashProfile({
    webgpuFeatures: new Set(['b', 'a', 'b']),
  });
  const asArray = resolveHardwareSimHashProfile({ webgpuFeatures: ['a', 'b'] });
  assert.equal(asSet.hash512, asArray.hash512, 'dedupe + sort must canonicalize feature sets');
});

check('empty / missing adapter.info never fabricates WebGPU identity', () => {
  const empty = resolveHardwareSimHashProfile({ webgpuAdapterInfo: {} });
  const missing = resolveHardwareSimHashProfile({});
  assert.equal(empty.hash512, missing.hash512);
  assert.ok(!empty.usedKeys.some((key) => key.startsWith('webgpu_adapter')));
});

check('non-empty adapter.info is incorporated as a static hint', () => {
  const profile = resolveHardwareSimHashProfile({
    webgpuAdapterInfo: { vendor: 'nvidia', architecture: 'ampere', device: '', description: null },
  });
  assert.equal(profile.features.webgpu_adapter_vendor, 'nvidia');
  assert.equal(profile.features.webgpu_adapter_arch, 'ampere');
  assert.ok(!profile.usedKeys.includes('webgpu_adapter_device'), 'empty field must be omitted');
  assert.ok(!profile.usedKeys.includes('webgpu_adapter_desc'), 'null field must be omitted');
});

check('atomic-contention signals are research_only and NEVER hashed', () => {
  const base = resolveHardwareSimHashProfile(HARDWARE_SIGNALS);
  const research = resolveHardwareSimHashProfile({
    ...HARDWARE_SIGNALS,
    drawnApart: 0.71,
    lockedApart: { auroc: 0.6 },
    atomicHistogram: [1, 2, 3],
  });
  assert.equal(research.hash512, base.hash512, 'research-only signals must not enter the hash');
  assert.deepEqual(research.features, base.features);
  assert.equal(research.researchOnly.atomicContentionWebGpu, 'research_only');
  assert.deepEqual(research.researchOnly.referencedSignals, ['atomicHistogram', 'drawnApart', 'lockedApart']);
  assert.ok(research.researchOnly.note.includes('57/80'));
  assert.ok(research.researchOnly.note.includes('32ms'));
  assert.ok(research.researchOnly.note.includes('NOT a cryptographic or stable hardware id'));
  assert.equal(research.researchOnly.note, WEBGPU_RESEARCH_ONLY_NOTE);
  assert.deepEqual(base.researchOnly.referencedSignals, [], 'no disclosure when no research signal supplied');
});

check('profile is explicitly labeled heuristic, not a verified device identity', () => {
  const profile = resolveHardwareSimHashProfile(HARDWARE_SIGNALS);
  assert.equal(profile.heuristic, true);
  assert.equal(profile.verifiedDeviceIdentity, false);
  assert.ok(
    JSON.stringify(profile).includes('not a verified device identity'),
    'must carry an explicit non-verified disclaimer',
  );
  assert.ok(!JSON.stringify(profile).includes('"verifiedDeviceIdentity":true'));
});

check('WebGPU static entropy is the documented ~5.19 bits / 122 sets figure', () => {
  assert.equal(WEBGPU_STATIC_ENTROPY.bits, 5.19);
  assert.equal(WEBGPU_STATIC_ENTROPY.anonymitySets, 122);
  assert.match(WEBGPU_STATIC_ENTROPY.surface, /maxComputeWorkgroupSizeX/);
  assert.match(WEBGPU_STATIC_ENTROPY.note, /not a verified device identity/);
  const profile = resolveHardwareSimHashProfile(HARDWARE_SIGNALS);
  assert.deepEqual(profile.webgpuStaticEntropy, WEBGPU_STATIC_ENTROPY);
});

check('timezone NAME is incorporated but timezone OFFSET stays volatile', () => {
  assert.ok(!VOLATILE_SIGNAL_KEYS.has('timezone'), 'IANA timezone name is browser-invariant');
  assert.ok(VOLATILE_SIGNAL_KEYS.has('timezoneOffset'), 'offset changes with DST — must be volatile');
  const named = resolveHardwareSimHashProfile({ timezone: 'America/New_York' });
  assert.equal(named.features.timezone_name, 'america/new_york');
  const jitterA = resolveHardwareSimHashProfile({ timezone: 'America/New_York', timezoneOffset: -240 });
  const jitterB = resolveHardwareSimHashProfile({ timezone: 'America/New_York', timezoneOffset: -300 });
  assert.equal(jitterA.hash512, jitterB.hash512);
  assert.ok(jitterA.ignoredVolatileKeys.includes('timezoneOffset'));
});

check('audio HARDWARE traits are stable while audioSum fingerprint is volatile', () => {
  const traits = resolveHardwareSimHashProfile({ audioSampleRate: 48000, audioOutputChannels: 2 });
  assert.equal(traits.features.audio_sample_rate, '48000');
  assert.equal(traits.features.audio_channels, '2');
  const a = resolveHardwareSimHashProfile({ audioSampleRate: 48000, audioSum: 123.456 });
  const b = resolveHardwareSimHashProfile({ audioSampleRate: 48000, audioSum: 999.111 });
  assert.equal(a.hash512, b.hash512, 'audioSum must not change the hash');
  assert.ok(a.ignoredVolatileKeys.includes('audioSum'));
});

check('screen geometry, color profile and system fonts enter the profile', () => {
  const profile = resolveHardwareSimHashProfile({
    screenWidth: 1920,
    screenHeight: 1080,
    colorDepth: 24,
    pixelDepth: 24,
    fontCount: 63,
    systemFonts: ['Arial', 'Helvetica', 'arial'],
  });
  assert.equal(profile.features.screen_width, '1920');
  assert.equal(profile.features.screen_height, '1080');
  assert.equal(profile.features.color_depth, '24');
  assert.equal(profile.features.pixel_depth, '24');
  assert.equal(profile.features.font_count, '50-99');
  assert.equal(profile.features.font_list, 'arial,helvetica');
});

check('GPU renderer family is a coarse stable bucket', () => {
  const nvidia = resolveHardwareSimHashProfile({ gpuRenderer: 'ANGLE (NVIDIA GeForce RTX 4090)' });
  const renamed = resolveHardwareSimHashProfile({ gpuRenderer: 'NVIDIA RTX 3080' });
  assert.equal(nvidia.features.gpu_renderer_family, 'nvidia');
  assert.equal(renamed.features.gpu_renderer_family, 'nvidia');
  const software = resolveHardwareSimHashProfile({ gpuRenderer: 'SwiftShader Device' });
  assert.equal(software.features.gpu_renderer_family, 'software');
});

/* -------------------------------------------------------------------------- */
/* 5. Supplementary cohort — shadow-only, non-canonical derivation             */
/* -------------------------------------------------------------------------- */

section('5. deriveSupplementaryCohort — shadow-only cohort key');

check('result has exactly four fields, shadow status and a namespaced cohort key', () => {
  const result = deriveSupplementaryCohort(STABLE_SIGNALS);
  assert.deepEqual(Object.keys(result).sort(), ['cohort_key', 'evidence_score', 'status', 'version']);
  assert.equal(result.status, 'shadow');
  assert.equal(result.version, '1');
  assert.match(result.cohort_key, /^cohort:v1:[0-9a-f]{32}$/);
  assert.ok(Number.isInteger(result.evidence_score));
  assert.ok(result.evidence_score > 0 && result.evidence_score <= 100);
});

check('no canonical/supplied id is echoed and no visitor_id field is minted', () => {
  const secrets = {
    storageVisitorId: 'secret-visitor-id-123',
    exactHardwareId: 'secret-hardware-id-456',
    hardware_fingerprint: 'secret-hw-fp-789',
    browser_fingerprint: 'secret-browser-fp-abc',
    session_id: 'secret-session-def',
    visitor_id: 'secret-canonical-ghi',
  };
  const result = deriveSupplementaryCohort({ ...STABLE_SIGNALS, ...secrets });
  const serialized = JSON.stringify(result);
  for (const secret of Object.values(secrets)) {
    assert.ok(!serialized.includes(secret), `must not echo ${secret}`);
  }
  for (const field of ['visitor_id', 'visitorId', 'hardware_fingerprint', 'browser_fingerprint', 'session_id']) {
    assert.ok(!Object.prototype.hasOwnProperty.call(result, field), `must not mint ${field}`);
  }
  assert.ok(!result.cohort_key.includes('secret'), 'cohort key must be an opaque hash, not a raw id');
});

check('volatile inputs (screen/timezone/canvas/quota/audio/fonts) do not change the cohort key', () => {
  const base = deriveSupplementaryCohort(STABLE_SIGNALS);
  const noisy = deriveSupplementaryCohort({
    ...STABLE_SIGNALS,
    screenWidth: 3840,
    screenHeight: 2160,
    colorDepth: 30,
    pixelDepth: 30,
    timezone: 'Asia/Tokyo',
    timezoneOffset: 540,
    canvasNoise: Math.random(),
    canvasHash: 'per-session-noise',
    storageQuota: 987654321,
    audioSum: 42.42,
    systemFonts: ['Comic Sans MS'],
    fontCount: 3,
  });
  assert.equal(noisy.cohort_key, base.cohort_key, 'volatile noise must not move the cohort key');
  assert.deepEqual(noisy, base, 'the entire shadow result must be stable');
});

check('shadow cohort derivation is deterministic and insertion-order independent', () => {
  const a = deriveSupplementaryCohort(STABLE_SIGNALS);
  assert.deepEqual(a, deriveSupplementaryCohort(STABLE_SIGNALS));
  const reversed: Record<string, unknown> = {};
  for (const key of Object.keys(STABLE_SIGNALS).reverse()) reversed[key] = STABLE_SIGNALS[key as keyof typeof STABLE_SIGNALS];
  assert.deepEqual(deriveSupplementaryCohort(reversed), a);
});

check('different stable cohorts produce different keys', () => {
  const base = deriveSupplementaryCohort(STABLE_SIGNALS);
  const arm = deriveSupplementaryCohort({
    ...STABLE_SIGNALS,
    architecture: 'arm64',
    gpuArchFamily: 'arm',
    gpuVendor: 'Apple',
    hostOs: 'macos',
    osFamily: 'macos',
  });
  assert.notEqual(arm.cohort_key, base.cohort_key);
  assert.equal(arm.status, 'shadow');
});

check('empty and hostile input fails closed without throwing', () => {
  const hostile: unknown[] = [
    undefined,
    null,
    7,
    'x',
    [],
    Symbol('s'),
    new Proxy({}, { get() { throw new Error('no'); } }),
    { canvasNoise: 1, storageQuota: 2, timezoneOffset: 3 },
  ];
  for (const input of hostile) {
    let result: ReturnType<typeof deriveSupplementaryCohort> | undefined;
    assert.doesNotThrow(() => {
      result = deriveSupplementaryCohort(input);
    });
    assert.equal(result?.cohort_key, 'cohort:unclassified');
    assert.equal(result?.evidence_score, 0);
    assert.equal(result?.status, 'shadow');
    assert.deepEqual(Object.keys(result ?? {}).sort(), ['cohort_key', 'evidence_score', 'status', 'version']);
  }
});

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`FAILED: ${failures.join(' | ')}`);
  process.exitCode = 1;
}

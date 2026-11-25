/**
 * Collector performance report harness (WEB RESEARCH R5) — REPORT ONLY.
 *
 *   npx tsx scripts/test-collector-perf.ts
 *
 * Times the same pinned surfaces as scripts/test-collector-golden.ts:
 * `stableStringify`, `computeHardwareFingerprint`, `computeBrowserFingerprint`
 * and `collectAllSignals` (minus volatile meta), under the same fixed globals
 * and UTC timezone. It prints min / p50 / p95 / max per workload.
 *
 * LATENCY IS NOT GATED: there is no threshold and no hard-fail on timing. The
 * only failure condition is a workload throwing (a correctness failure). This
 * file never reads or writes golden fixtures.
 */

import { performance } from 'node:perf_hooks';
import {
  collectAllSignals,
  computeBrowserFingerprint,
  computeHardwareFingerprint,
  stableStringify,
} from '../src/client/signals/index.ts';
import type { CollectedSignals } from '../src/client/signals/index.ts';

process.env.TZ = 'UTC';

/* -------------------------------------------------------------------------- */
/* Deterministic environment (mirrors the golden harness)                      */
/* -------------------------------------------------------------------------- */

interface SavedGlobal {
  key: string;
  descriptor: PropertyDescriptor | undefined;
}

function installDeterministicGlobals(): SavedGlobal[] {
  const globalObj = globalThis as unknown as Record<string, unknown>;
  const nav: Record<string, unknown> = {
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
  const screen = {
    width: 1920,
    height: 1080,
    availWidth: 1920,
    availHeight: 1040,
    colorDepth: 24,
    pixelRatio: 1,
    maxTouchPoints: 0,
  };
  const values: Record<string, unknown> = {
    navigator: nav,
    screen,
    window: {
      devicePixelRatio: 1,
      outerWidth: 1920,
      outerHeight: 1080,
      innerWidth: 1900,
      innerHeight: 1000,
      location: { search: '', href: 'https://golden.test/' },
      navigator: nav,
      screen,
      matchMedia: () => ({ matches: false }),
      speechSynthesis: { getVoices: () => [] },
      prompt: '',
      onerror: null,
      addEventListener() { /* no-op */ },
      removeEventListener() { /* no-op */ },
    },
  };
  const removed = [
    'document',
    'OfflineAudioContext',
    'AudioContext',
    'RTCPeerConnection',
    'localStorage',
    'sessionStorage',
    'indexedDB',
    'location',
  ];
  const saved: SavedGlobal[] = [];
  for (const key of [...Object.keys(values), ...removed]) {
    saved.push({ key, descriptor: Object.getOwnPropertyDescriptor(globalObj, key) });
  }
  for (const [key, value] of Object.entries(values)) {
    Object.defineProperty(globalObj, key, { configurable: true, writable: true, value });
  }
  for (const key of removed) delete globalObj[key];
  return saved;
}

function restoreGlobals(saved: SavedGlobal[]): void {
  const globalObj = globalThis as unknown as Record<string, unknown>;
  for (const entry of saved) {
    if (entry.descriptor) Object.defineProperty(globalObj, entry.key, entry.descriptor);
    else delete globalObj[entry.key];
  }
}

function perfSignals(): CollectedSignals {
  return {
    canvas: { winding: true, geometry: 'a'.repeat(32), text: 'b'.repeat(32), geometryUnstable: false, textUnstable: null, geometryDataUrl: null, textDataUrl: null },
    canvasNoise: { classification: 'clean', maxChannelDelta: 0, stabilizedGeometryHash: 'c'.repeat(32), flags: [] },
    fonts: { installed: ['Arial', 'Helvetica', 'Segoe UI', '🚀 Font'], fontHash: 'd'.repeat(32), platformClassGuess: 'windows' },
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
    meta: { collectedAt: '2026-11-24T00:00:00.000Z', totalDurationMs: 12, timingsMs: { canvas: 1, fonts: 2 } },
  };
}

/* -------------------------------------------------------------------------- */
/* Measurement                                                                 */
/* -------------------------------------------------------------------------- */

interface Workload {
  name: string;
  iterations: number;
  warmup: number;
  run: () => void | Promise<void>;
}

interface Report {
  name: string;
  iterations: number;
  warmup: number;
  min: number;
  p50: number;
  p95: number;
  max: number;
  error: string | null;
}

function percentile(sorted: number[], q: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1));
  return sorted[idx];
}

function fmt(ms: number): string {
  return ms.toFixed(3);
}

async function measure(workload: Workload): Promise<Report> {
  const samples: number[] = [];
  let error: string | null = null;
  try {
    for (let i = 0; i < workload.warmup; i++) await workload.run();
    for (let i = 0; i < workload.iterations; i++) {
      const start = performance.now();
      await workload.run();
      samples.push(performance.now() - start);
    }
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
  }
  samples.sort((a, b) => a - b);
  return {
    name: workload.name,
    iterations: workload.iterations,
    warmup: workload.warmup,
    min: samples.length > 0 ? samples[0] : 0,
    p50: percentile(samples, 0.5),
    p95: percentile(samples, 0.95),
    max: samples.length > 0 ? samples[samples.length - 1] : 0,
    error,
  };
}

async function main(): Promise<number> {
  const saved = installDeterministicGlobals();
  const signals = perfSignals();
  const stablePayload = { ...signals };
  delete (stablePayload as Partial<CollectedSignals>).meta;

  const workloads: Workload[] = [
    {
      name: 'stableStringify(payload)',
      iterations: 200,
      warmup: 10,
      run: () => { stableStringify(stablePayload); },
    },
    {
      name: 'computeHardwareFingerprint',
      iterations: 200,
      warmup: 10,
      run: () => { computeHardwareFingerprint(signals); },
    },
    {
      name: 'computeBrowserFingerprint',
      iterations: 200,
      warmup: 10,
      run: () => { computeBrowserFingerprint(signals); },
    },
    {
      name: 'collectAllSignals(-meta)',
      iterations: 20,
      warmup: 2,
      run: async () => {
        const collected = await collectAllSignals({ timeouts: 5 });
        const { meta: _volatileMeta, ...stable } = collected;
        stableStringify(stable);
      },
    },
  ];

  const reports: Report[] = [];
  try {
    for (const workload of workloads) reports.push(await measure(workload));
  } finally {
    restoreGlobals(saved);
  }

  console.log('WORKLOAD                       ITER  WARM   MIN(ms)  P50(ms)  P95(ms)  MAX(ms)');
  for (const r of reports) {
    const errTag = r.error ? ` ERROR=${r.error}` : '';
    console.log(
      `${r.name.padEnd(30)} ${String(r.iterations).padStart(4)}  ${String(r.warmup).padStart(4)}  ` +
        `${fmt(r.min).padStart(7)}  ${fmt(r.p50).padStart(7)}  ${fmt(r.p95).padStart(7)}  ${fmt(r.max).padStart(7)}${errTag}`
    );
  }
  const failed = reports.filter((r) => r.error !== null);
  console.log(
    `RESULT collector-perf: ${failed.length === 0 ? 'PASS' : 'FAIL'} — ${reports.length} workloads, ${failed.length} execution errors; REPORT-ONLY (no latency gate, no golden writes).`
  );
  return failed.length === 0 ? 0 : 1;
}

main()
  .then((code) => process.exit(code))
  .catch((error: unknown) => {
    console.error('FAIL collector-perf: unexpected error', error);
    process.exit(1);
  });

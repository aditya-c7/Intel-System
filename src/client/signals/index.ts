/**
 * Signal orchestrator — runs every collector under a per-collector timeout
 * (never throws, always returns CollectedSignals) and computes the tri-layer
 * digests:
 *
 *   - hardware fingerprint: ONLY hardware-bound families. Stable across
 *     Chrome/Safari/Firefox/Brave on the same machine ("Benny the Doorman"
 *     hardware-vs-engine tagging): webgl_gpu_identity, platform, timezone,
 *     fonts, media_devices, architecture — 6 hardware families.
 *   - browser fingerprint: all engine-bound families (what the engine does,
 *     not what the hardware is): audio, audio_base_latency, canvas,
 *     webgl_params/extensions/precisions, font_preferences, emoji (css_probe
 *     analog), math, error_stack_engine, speech_voices, storage_quota,
 *     apple_pay, screen_frame — the ~20 engine families.
 *
 * Note: the blueprint folds screen geometry into the hardware digest (Benny
 * tags `screen` as engine-bound); we follow the blueprint and document the
 * divergence. Platform/architecture values are read from navigator at digest
 * time (UA strings never leave the client — only the digest does).
 */

import { getCanvasFingerprint } from './canvas';
import { classifyCanvasNoise } from './canvasClassifier';
import { collectFontSignals } from './fonts';
import { collectFontPreferenceSignals } from './fontPreferences';
import { collectEmojiSignals } from './emoji';
import { getWebglBasics, getWebglExtensions, getWebglGpuIdentity } from './webgl';
import { collectAudioSignals, collectAudioBaseLatency } from './audio';
import { collectMathSignals } from './math';
import { collectSystemEntropySignals } from './systemEntropy';
import { collectAutomationSignals, startKinematicsTracker } from './automation';
import { stableHash32, stableStringify, errorMessage } from './hash';
import { loadSources, type Component, type Source } from './loader';
import type {
  AudioSignals,
  AutomationSignals,
  BrowserCanvasHints,
  CanvasNoiseReport,
  CanvasSignals,
  CollectedSignals,
  EmojiSignals,
  FontPreferenceSignals,
  FontSignals,
  KinematicsTracker,
  MathSignals,
  SystemEntropySignals,
  WebglBasics,
  WebglExtensions,
  WebglGpuIdentity,
} from './types';

export const DEFAULT_TIMEOUT_MS = 1500;

export interface CollectAllOptions {
  /** Per-collector wall-clock budget in ms (default 1500). */
  timeouts?: number;
  /** Native-farbling hints for the canvas noise classifier. */
  browserHints?: BrowserCanvasHints;
  /** Sec-CH-UA brand list (server header) for the S7 headless mismatch probe. */
  secChBrands?: string[];
}

function nowMs(): number {
  try {
    return performance.now();
  } catch {
    return Date.now();
  }
}

interface Timings {
  record: Record<string, number>;
}

/** Runs a collector under a timeout; on timeout or error returns a fallback
 * payload annotated with the failure reason. Never rejects. */
async function withTimeout<T>(
  name: string,
  timings: Timings,
  task: () => T | Promise<T>,
  timeoutMs: number,
  fallbackFactory: () => T
): Promise<T> {
  const started = nowMs();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      Promise.resolve().then(task),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`timeout after ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
    return result;
  } catch (error) {
    const fallback = fallbackFactory();
    const marker = fallback as { error?: string };
    if (!marker.error) marker.error = errorMessage(error);
    return fallback;
  } finally {
    if (timer) clearTimeout(timer);
    timings.record[name] = Math.round(nowMs() - started);
  }
}

// Fallback payloads (typed minimal shapes; error text is added by withTimeout).
const fallbackCanvas = (): CanvasSignals => ({
  winding: null,
  geometry: '',
  text: '',
  geometryUnstable: null,
  textUnstable: null,
  geometryDataUrl: null,
  textDataUrl: null,
});
const fallbackCanvasNoise = (): CanvasNoiseReport => ({
  classification: null,
  maxChannelDelta: null,
  stabilizedGeometryHash: null,
  flags: [],
});
const fallbackFonts = (): FontSignals => ({ installed: [], fontHash: '', platformClassGuess: 'unknown' });
const fallbackFontPreferences = (): FontPreferenceSignals => ({
  widths: { default: null, apple: null, serif: null, sans: null, mono: null, min: null, system: null },
  widthsExactIntegers: false,
});
const fallbackEmoji = (): EmojiSignals => ({
  font: null,
  width: null,
  height: null,
  top: null,
  bottom: null,
  left: null,
  right: null,
  x: null,
  y: null,
});
const fallbackWebglBasics = (): WebglBasics => ({
  version: null,
  vendor: null,
  renderer: null,
  shadingLanguageVersion: null,
  vendorUnmasked: null,
  rendererUnmasked: null,
});
const fallbackWebglExtensions = (): WebglExtensions => ({
  contextAttributes: null,
  parameters: null,
  shaderPrecisions: null,
  extensions: null,
  extensionParameters: null,
  supportedExtensions: [],
  unsupportedExtensions: [],
});
const fallbackWebglGpuIdentity = (): WebglGpuIdentity => ({
  normalizedGpu: null,
  normalizedGpuHash: null,
  invariantLimits: null,
});
const fallbackAudio = (): AudioSignals => ({
  sum: null,
  code: -2,
  audioBaseLatency: null,
  listenerForwardXMaxValue: null,
  biquadGainMaxValue: null,
  compressorAttackDefault: null,
  oscillatorDetuneMax: null,
});
const fallbackMath = (): MathSignals => ({
  values: {},
  mathHash: '',
  errorStackFunctions: [],
  errorStackHash: '',
});
const fallbackSystemEntropy = (): SystemEntropySignals => ({
  timezone: null,
  timezoneOffset: null,
  deviceMemory: null,
  hardwareConcurrency: null,
  screen: { width: null, height: null, colorDepth: null, pixelRatio: null, maxTouchPoints: null },
  mediaDeviceCounts: { audioinput: null, audiooutput: null, videoinput: null },
  storageQuota: null,
  applePayAvailable: null,
  speechVoicesCount: null,
  permissions: { geolocation: null, notifications: null, camera: null, microphone: null },
});
const fallbackAutomation = (): AutomationSignals => ({
  reasonIds: [],
  weakReasonIds: [],
  agentName: null,
  shapes: [],
});

/* -------------------------------------------------------------------------- */
/* Two-phase source path — FingerprintJS v5 `load()` / `getComponents()`       */
/* -------------------------------------------------------------------------- */

/** Shared context handed to every source of one `loadAll()` call. */
export interface SignalSourceOptions {
  /** One shared cache per load; sources may cross-reference values by key. */
  cache: Record<string, unknown>;
  /** Collector options forwarded from `loadAll`. */
  options: CollectAllOptions;
  /** Started at load time so behavior during phase 1 is captured too. */
  kinematics: KinematicsTracker;
}

function flagEnabled(value: unknown): boolean {
  return value === true || value === 'true' || value === 1 || value === '1';
}

/**
 * Reads the `FP_TWO_PHASE_SOURCES` switch (default OFF). A `globalThis` value
 * wins so Node/tsx tests can toggle it; Vite `import.meta.env` is the fallback
 * for browser builds.
 */
export function twoPhaseSourcesEnabled(): boolean {
  const fromGlobal = (globalThis as { FP_TWO_PHASE_SOURCES?: unknown }).FP_TWO_PHASE_SOURCES;
  if (fromGlobal !== undefined) return flagEnabled(fromGlobal);
  try {
    const env = (import.meta as unknown as { env?: Record<string, unknown> }).env;
    if (env) {
      const fromEnv = env.FP_TWO_PHASE_SOURCES ?? env.VITE_FP_TWO_PHASE_SOURCES;
      if (fromEnv !== undefined) return flagEnabled(fromEnv);
    }
  } catch {
    // `import.meta.env` does not exist outside Vite; the global flag is the switch.
  }
  return false;
}

interface CanvasGroup {
  canvas: CanvasSignals;
  noise: CanvasNoiseReport;
}

function cacheValue<T>(ctx: SignalSourceOptions, key: string, value: T): T {
  ctx.cache[key] = value;
  return value;
}

/**
 * Built-in sources in FIXED DECLARATION ORDER. Async sources come first so
 * they overlap the synchronous ones; the automation source is two-stage and
 * reads its phase-1 dependencies from the shared cache at get time.
 */
const signalSources = {
  audio: async (): Promise<AudioSignals> => {
    const signals = await collectAudioSignals();
    signals.audioBaseLatency = await collectAudioBaseLatency();
    return signals;
  },
  canvas: (ctx: SignalSourceOptions): CanvasGroup =>
    cacheValue(ctx, 'canvasGroup', (() => {
      const canvas = getCanvasFingerprint();
      const noise = classifyCanvasNoise(canvas, ctx.options.browserHints);
      return { canvas, noise };
    })()),
  fonts: (ctx: SignalSourceOptions): FontSignals => cacheValue(ctx, 'fonts', collectFontSignals()),
  fontPreferences: (ctx: SignalSourceOptions): FontPreferenceSignals =>
    cacheValue(ctx, 'fontPreferences', collectFontPreferenceSignals()),
  emoji: (): EmojiSignals => collectEmojiSignals(),
  webglBasics: (ctx: SignalSourceOptions): WebglBasics => cacheValue(ctx, 'webglBasics', getWebglBasics()),
  webglExtensions: (): WebglExtensions => getWebglExtensions(),
  webglGpuIdentity: (ctx: SignalSourceOptions): WebglGpuIdentity =>
    cacheValue(ctx, 'webglGpuIdentity', getWebglGpuIdentity()),
  math: (): Promise<MathSignals> => collectMathSignals(),
  systemEntropy: (): Promise<SystemEntropySignals> => collectSystemEntropySignals(),
  automation: (ctx: SignalSourceOptions) => async (): Promise<AutomationSignals> => {
    const fonts = ctx.cache.fonts as FontSignals | undefined;
    const fontPreferences = ctx.cache.fontPreferences as FontPreferenceSignals | undefined;
    const webglBasics = ctx.cache.webglBasics as WebglBasics | undefined;
    const webglGpuIdentity = ctx.cache.webglGpuIdentity as WebglGpuIdentity | undefined;
    return collectAutomationSignals({
      fontsInstalled: fonts?.installed,
      fontWidthsExact: fontPreferences?.widthsExactIntegers,
      rendererUnmasked: webglBasics?.rendererUnmasked ?? webglGpuIdentity?.normalizedGpu,
      secChBrands: ctx.options.secChBrands,
    });
  },
} satisfies Record<string, Source<SignalSourceOptions, unknown>>;

/** A component error is mapped onto the same annotated fallback the legacy path uses. */
function unwrapComponent<T>(component: Component<T> | undefined, fallbackFactory: () => T): T {
  if (component && 'value' in component) return component.value;
  const fallback = fallbackFactory() as { error?: string };
  if (component && 'error' in component) {
    if (!fallback.error) fallback.error = errorMessage(component.error);
  } else {
    fallback.error = 'source returned no component';
  }
  return fallback as T;
}

/**
 * Phase 1 — start every source (one shared cache) and return `getComponents()`.
 * Phase 2 — `getComponents()` assembles the same `CollectedSignals` shape as
 * `collectAllSignals`, so neither digests nor the payload key set change.
 */
export function loadAll(options?: CollectAllOptions): () => Promise<CollectedSignals> {
  const started = nowMs();
  const ctx: SignalSourceOptions = {
    cache: {},
    options: options ?? {},
    kinematics: startKinematicsTracker(),
  };
  const getComponents = loadSources(signalSources, ctx, []);

  return async function getComponentsAsSignals(): Promise<CollectedSignals> {
    const components = await getComponents();
    const timingsMs: Record<string, number> = {};
    for (const key of Object.keys(components) as (keyof typeof components)[]) {
      timingsMs[key] = components[key].duration;
    }

    const canvasGroup = unwrapComponent(components.canvas, () => ({
      canvas: fallbackCanvas(),
      noise: fallbackCanvasNoise(),
    }));

    const automation = unwrapComponent(components.automation, fallbackAutomation);
    const kinematicReasons = ctx.kinematics.drain();
    ctx.kinematics.stop();
    automation.reasonIds = Array.from(new Set([...automation.reasonIds, ...kinematicReasons]));

    return {
      canvas: canvasGroup.canvas,
      canvasNoise: canvasGroup.noise,
      fonts: unwrapComponent(components.fonts, fallbackFonts),
      fontPreferences: unwrapComponent(components.fontPreferences, fallbackFontPreferences),
      emoji: unwrapComponent(components.emoji, fallbackEmoji),
      webglBasics: unwrapComponent(components.webglBasics, fallbackWebglBasics),
      webglExtensions: unwrapComponent(components.webglExtensions, fallbackWebglExtensions),
      webglGpuIdentity: unwrapComponent(components.webglGpuIdentity, fallbackWebglGpuIdentity),
      audio: unwrapComponent(components.audio, fallbackAudio),
      math: unwrapComponent(components.math, fallbackMath),
      systemEntropy: unwrapComponent(components.systemEntropy, fallbackSystemEntropy),
      automation,
      meta: {
        collectedAt: new Date().toISOString(),
        totalDurationMs: Math.round(nowMs() - started),
        timingsMs,
      },
    };
  };
}

/**
 * Runs every collector. Best results occur after DOM ready (collectors
 * attach elements to document.body). Each collector is independent and
 * individually timeout-bounded; a slow or failing collector never blocks or
 * poisons the others.
 */
export async function collectAllSignals(opts?: CollectAllOptions): Promise<CollectedSignals> {
  // Flag-gated two-phase path. When OFF (the default) the legacy body below is
  // unchanged and behavior is byte-identical to before this loader existed.
  if (twoPhaseSourcesEnabled()) {
    return loadAll(opts)();
  }

  const timeoutMs = opts?.timeouts ?? DEFAULT_TIMEOUT_MS;
  const timings: Timings = { record: {} };
  const started = nowMs();
  const kinematics = startKinematicsTracker();

  // Batch 1 — independent collectors run concurrently.
  const [canvasGroup, fonts, fontPreferences, emoji, webglBasics, webglExtensions, webglGpuIdentity, audio, math, systemEntropy] =
    await Promise.all([
      withTimeout(
        'canvas',
        timings,
        () => {
          const canvas = getCanvasFingerprint();
          const noise = classifyCanvasNoise(canvas, opts?.browserHints);
          return { canvas, noise };
        },
        timeoutMs,
        () => ({ canvas: fallbackCanvas(), noise: fallbackCanvasNoise() })
      ),
      withTimeout('fonts', timings, () => collectFontSignals(), timeoutMs, fallbackFonts),
      withTimeout(
        'fontPreferences',
        timings,
        () => collectFontPreferenceSignals(),
        timeoutMs,
        fallbackFontPreferences
      ),
      withTimeout('emoji', timings, () => collectEmojiSignals(), timeoutMs, fallbackEmoji),
      withTimeout('webglBasics', timings, () => getWebglBasics(), timeoutMs, fallbackWebglBasics),
      withTimeout('webglExtensions', timings, () => getWebglExtensions(), timeoutMs, fallbackWebglExtensions),
      withTimeout('webglGpuIdentity', timings, () => getWebglGpuIdentity(), timeoutMs, fallbackWebglGpuIdentity),
      withTimeout(
        'audio',
        timings,
        async () => {
          const signals = await collectAudioSignals();
          signals.audioBaseLatency = await collectAudioBaseLatency();
          return signals;
        },
        timeoutMs,
        fallbackAudio
      ),
      withTimeout('math', timings, () => collectMathSignals(), timeoutMs, fallbackMath),
      withTimeout(
        'systemEntropy',
        timings,
        () => collectSystemEntropySignals(),
        timeoutMs,
        fallbackSystemEntropy
      ),
    ]);

  // Batch 2 — automation consumes batch-1 outputs (fonts, font widths,
  // renderer string, Sec-CH-UA brands).
  const automation = await withTimeout(
    'automation',
    timings,
    () =>
      collectAutomationSignals({
        fontsInstalled: fonts.installed,
        fontWidthsExact: fontPreferences.widthsExactIntegers,
        rendererUnmasked: webglBasics.rendererUnmasked ?? webglGpuIdentity.normalizedGpu,
        secChBrands: opts?.secChBrands,
      }),
    timeoutMs,
    fallbackAutomation
  );

  // Fold kinematic behavior evidence into the automation reasons.
  const kinematicReasons = kinematics.drain();
  kinematics.stop();
  automation.reasonIds = Array.from(new Set([...automation.reasonIds, ...kinematicReasons]));

  return {
    canvas: canvasGroup.canvas,
    canvasNoise: canvasGroup.noise,
    fonts,
    fontPreferences,
    emoji,
    webglBasics,
    webglExtensions,
    webglGpuIdentity,
    audio,
    math,
    systemEntropy,
    automation,
    meta: {
      collectedAt: new Date().toISOString(),
      totalDurationMs: Math.round(nowMs() - started),
      timingsMs: timings.record,
    },
  };
}

function readUADataPlatform(): Record<string, string | boolean | number | null> {
  const uaData = (navigator as Navigator & { userAgentData?: { platform?: string; architecture?: string; bitness?: string; mobile?: boolean } })
    .userAgentData;
  return {
    navigatorPlatform: typeof navigator.platform === 'string' && navigator.platform.length > 0 ? navigator.platform : null,
    uaDataPlatform: uaData?.platform ?? null,
    uaDataArchitecture: uaData?.architecture ?? null,
    uaDataBitness: uaData?.bitness ?? null,
    uaDataMobile: uaData?.mobile ?? null,
  };
}

function readScreenFrame(): Record<string, number | null> {
  const frame: Record<string, number | null> = {};
  try {
    frame.availWidth = typeof screen.availWidth === 'number' ? screen.availWidth : null;
  } catch {
    frame.availWidth = null;
  }
  try {
    frame.availHeight = typeof screen.availHeight === 'number' ? screen.availHeight : null;
  } catch {
    frame.availHeight = null;
  }
  try {
    frame.outerWidth = typeof window.outerWidth === 'number' ? window.outerWidth : null;
  } catch {
    frame.outerWidth = null;
  }
  try {
    frame.outerHeight = typeof window.outerHeight === 'number' ? window.outerHeight : null;
  } catch {
    frame.outerHeight = null;
  }
  try {
    frame.innerWidth = typeof window.innerWidth === 'number' ? window.innerWidth : null;
  } catch {
    frame.innerWidth = null;
  }
  try {
    frame.innerHeight = typeof window.innerHeight === 'number' ? window.innerHeight : null;
  } catch {
    frame.innerHeight = null;
  }
  return frame;
}

/**
 * HARDWARE-BOUND digest (32-char hex) over 6 families — stable across
 * browsers on the same machine:
 *
 *  1. webgl_gpu_identity — normalized GPU model + invariant limits
 *     (max texture/cubemap/renderbuffer sizes, viewport dims, 3D texture
 *     size, array texture layers, aliased point size range)
 *  2. platform           — navigator.platform + UA-CH platform/architecture/
 *     bitness/mobile (read at digest time; never transported raw)
 *  3. architecture       — hardwareConcurrency (cores) + deviceMemory
 *  4. timezone           — IANA timezone + minutes offset
 *  5. fonts              — sorted installed-font list
 *  6. media_devices      — device counts + screen geometry/colorDepth/
 *     maxTouchPoints (blueprint folds screen into hardware; Benny tags it
 *     engine-bound — divergence documented)
 */
export function computeHardwareFingerprint(signals: CollectedSignals): string {
  const payload = {
    webgl_gpu_identity: {
      normalizedGpu: signals.webglGpuIdentity.normalizedGpu,
      invariantLimits: signals.webglGpuIdentity.invariantLimits,
    },
    platform: readUADataPlatform(),
    architecture: {
      hardwareConcurrency: signals.systemEntropy.hardwareConcurrency,
      deviceMemory: signals.systemEntropy.deviceMemory,
    },
    timezone: {
      timezone: signals.systemEntropy.timezone,
      timezoneOffset: signals.systemEntropy.timezoneOffset,
    },
    fonts: {
      installed: signals.fonts.installed,
    },
    media_devices: {
      counts: signals.systemEntropy.mediaDeviceCounts,
      screen: signals.systemEntropy.screen,
    },
  };
  return stableHash32(stableStringify(payload));
}

/**
 * ENGINE-BOUND digest (32-char hex) over the engine families — differ per
 * browser even on identical hardware:
 *
 *  canvas (geometry+text hashes), webgl_params (limit parameters + context
 *  attributes), webgl extensions, webgl shader precisions, webgl
 *  extension parameters, masked vendor/renderer strings, audio sum + static
 *  ranges + base latency, font preference widths, emoji rect, math values,
 *  error-stack engine, speech voices count, storage quota, apple pay,
 *  screen frame (avail/outer/inner geometry at digest time).
 */
export function computeBrowserFingerprint(signals: CollectedSignals): string {
  const payload = {
    canvas: {
      geometry: signals.canvas.geometry,
      text: signals.canvas.text,
    },
    webgl: {
      basics: {
        version: signals.webglBasics.version,
        vendor: signals.webglBasics.vendor,
        renderer: signals.webglBasics.renderer,
        shadingLanguageVersion: signals.webglBasics.shadingLanguageVersion,
      },
      contextAttributes: signals.webglExtensions.contextAttributes,
      parameters: signals.webglExtensions.parameters,
      extensions: signals.webglExtensions.extensions,
      shaderPrecisions: signals.webglExtensions.shaderPrecisions,
      extensionParameters: signals.webglExtensions.extensionParameters,
    },
    audio: {
      sum: signals.audio.sum,
      ranges: {
        listenerForwardXMaxValue: signals.audio.listenerForwardXMaxValue,
        biquadGainMaxValue: signals.audio.biquadGainMaxValue,
        compressorAttackDefault: signals.audio.compressorAttackDefault,
        oscillatorDetuneMax: signals.audio.oscillatorDetuneMax,
      },
      audioBaseLatency: signals.audio.audioBaseLatency,
    },
    font_preferences: signals.fontPreferences,
    emoji: signals.emoji,
    math: {
      values: signals.math.values,
      errorStackHash: signals.math.errorStackHash,
    },
    speech_voices: signals.systemEntropy.speechVoicesCount,
    storage_quota: signals.systemEntropy.storageQuota,
    apple_pay: signals.systemEntropy.applePayAvailable,
    screen_frame: readScreenFrame(),
  };
  return stableHash32(stableStringify(payload));
}

// Convenience re-exports for host-app consumers.
export { getCanvasFingerprint, measureCanvasWinding } from './canvas';
export { classifyCanvasNoise } from './canvasClassifier';
export { collectFontSignals } from './fonts';
export { collectFontPreferenceSignals } from './fontPreferences';
export { collectEmojiSignals } from './emoji';
export { getWebglBasics, getWebglExtensions, getWebglGpuIdentity, normalizeGpuRenderer } from './webgl';
export { collectAudioSignals, collectAudioBaseLatency } from './audio';
export { collectMathSignals } from './math';
export { collectSystemEntropySignals } from './systemEntropy';
export { collectAutomationSignals, startKinematicsTracker } from './automation';
export {
  stableHash32,
  stableStringify,
  hashBytes32,
  hashStrings,
  sha256Bytes,
} from './hash';
export type {
  AudioSignals,
  AutomationCollectArgs,
  AutomationSignals,
  BrowserCanvasHints,
  CanvasNoiseClassification,
  CanvasNoiseReport,
  CanvasSignals,
  CollectedSignals,
  EmojiSignals,
  FontPreferencePreset,
  FontPreferenceSignals,
  FontSignals,
  KinematicsTracker,
  MathSignals,
  SystemEntropySignals,
  WebglBasics,
  WebglExtensions,
  WebglGpuIdentity,
  WebglInvariantLimits,
} from './types';

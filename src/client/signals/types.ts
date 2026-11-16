/**
 * Types for the high-entropy client signal collectors.
 *
 * Every collector is TOTAL: it never throws and always returns a payload.
 * Optional `error?: string` fields carry a human-readable failure reason
 * (including per-collector timeouts applied by the orchestrator).
 */

// ---------------------------------------------------------------------------
// Canvas
// ---------------------------------------------------------------------------

export interface CanvasSignals {
  /** Stage-1 winding support (`!isPointInPath(5,5,'evenodd')` after two rects). */
  winding: boolean | null;
  /** 32-char hex digest of the geometry-stage data URL ('' when unavailable). */
  geometry: string;
  /** 32-char hex digest of the text-stage data URL ('' when unavailable). */
  text: string;
  /** True when two static `toDataURL()` reads of the geometry bitmap differed. */
  geometryUnstable: boolean | null;
  /** True when two static `toDataURL()` reads of the text bitmap differed. */
  textUnstable: boolean | null;
  /** The PNG data URLs themselves (client-side only; strip before transport). */
  geometryDataUrl: string | null;
  textDataUrl: string | null;
  error?: string;
}

export type CanvasNoiseClassification =
  | 'clean'
  | 'canvas_read_hook_noisy'
  | 'canvas_noise_uniform'
  | 'browser_farbling'
  /** No usable data (collection failure / no pixels readable). */
  | 'unknown';

export interface CanvasNoiseReport {
  classification: CanvasNoiseClassification | null;
  /** Largest per-channel deviation from clean ground-truth pixel values. */
  maxChannelDelta: number | null;
  /** Hash of the geometry bitmap with the 2 least-significant bits masked. */
  stabilizedGeometryHash: string | null;
  flags: string[];
  error?: string;
}

export interface BrowserCanvasHints {
  isBrave?: boolean;
  isFirefox?: boolean;
  isSafari17Plus?: boolean;
  isSamsung?: boolean;
  privateMode?: boolean;
}

// ---------------------------------------------------------------------------
// Fonts
// ---------------------------------------------------------------------------

export interface FontSignals {
  /** Sorted list of fonts detected as installed. */
  installed: string[];
  /** 32-char hex digest of the sorted installed list. */
  fontHash: string;
  platformClassGuess: 'windows' | 'mac' | 'linux' | 'unknown';
  error?: string;
}

export type FontPreferencePreset = 'default' | 'apple' | 'serif' | 'sans' | 'mono' | 'min' | 'system';

export interface FontPreferenceSignals {
  widths: Record<FontPreferencePreset, number | null>;
  /** All non-null widths are exact integers (headless-shell hint on Linux). */
  widthsExactIntegers: boolean;
  error?: string;
}

// ---------------------------------------------------------------------------
// Emoji
// ---------------------------------------------------------------------------

export interface EmojiSignals {
  /** Computed `font-family` of the probe span (declared value). */
  font: string | null;
  width: number | null;
  height: number | null;
  top: number | null;
  bottom: number | null;
  left: number | null;
  right: number | null;
  x: number | null;
  y: number | null;
  error?: string;
}

// ---------------------------------------------------------------------------
// WebGL
// ---------------------------------------------------------------------------

export interface WebglBasics {
  version: string | null;
  vendor: string | null;
  renderer: string | null;
  shadingLanguageVersion: string | null;
  /** Via WEBGL_debug_renderer_info (hardware identity). */
  vendorUnmasked: string | null;
  rendererUnmasked: string | null;
  error?: string;
}

export interface WebglExtensions {
  /** Hash of getContextAttributes(). */
  contextAttributes: string | null;
  /** Hash of implementation limit parameters. */
  parameters: string | null;
  /** Hash of the 12 shader-precision tuples. */
  shaderPrecisions: string | null;
  /** Hash of the sorted supported-extension list. */
  extensions: string | null;
  /** Hash of per-extension parameter probes. */
  extensionParameters: string | null;
  supportedExtensions: string[];
  /** Well-known extensions NOT supported by this context. */
  unsupportedExtensions: string[];
  error?: string;
}

export interface WebglInvariantLimits {
  maxTextureSize: number | null;
  maxCubeMapTextureSize: number | null;
  maxRenderbufferSize: number | null;
  maxViewportDims: number[] | null;
  /** WebGL2-only (null on WebGL1-only contexts). */
  max3dTextureSize: number | null;
  /** WebGL2-only (null on WebGL1-only contexts). */
  maxArrayTextureLayers: number | null;
  aliasedPointSizeRange: number[] | null;
}

export interface WebglGpuIdentity {
  /** Canonical GPU model, e.g. 'NVIDIA GeForce RTX 4090' or 'Apple M4'. */
  normalizedGpu: string | null;
  normalizedGpuHash: string | null;
  invariantLimits: WebglInvariantLimits | null;
  error?: string;
}

// ---------------------------------------------------------------------------
// Audio
// ---------------------------------------------------------------------------

export interface AudioSignals {
  /** Sum of |sample| over OfflineAudioContext frames 4500..4999 (channel 0). */
  sum: number | null;
  /** 0 = ok, -1 = legacy/suspended context, -2 = unsupported, -3 = render timeout. */
  code: number;
  audioBaseLatency: number | null;
  listenerForwardXMaxValue: number | null;
  biquadGainMaxValue: number | null;
  compressorAttackDefault: number | null;
  oscillatorDetuneMax: number | null;
  error?: string;
}

// ---------------------------------------------------------------------------
// Math / engine
// ---------------------------------------------------------------------------

export interface MathSignals {
  /** Function name -> stringified result (24 FingerprintJS probes). */
  values: Record<string, string>;
  mathHash: string;
  /** Sorted own-property names of engine error instances. */
  errorStackFunctions: string[];
  errorStackHash: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// System entropy
// ---------------------------------------------------------------------------

export interface SystemEntropySignals {
  timezone: string | null;
  timezoneOffset: number | null;
  deviceMemory: number | null;
  hardwareConcurrency: number | null;
  screen: {
    width: number | null;
    height: number | null;
    colorDepth: number | null;
    pixelRatio: number | null;
    maxTouchPoints: number | null;
  };
  mediaDeviceCounts: {
    audioinput: number | null;
    audiooutput: number | null;
    videoinput: number | null;
  };
  storageQuota: { usage: number | null; quota: number | null } | null;
  applePayAvailable: boolean | null;
  speechVoicesCount: number | null;
  permissions: {
    geolocation: PermissionState | null;
    notifications: PermissionState | null;
    camera: PermissionState | null;
    microphone: PermissionState | null;
  };
  error?: string;
}

// ---------------------------------------------------------------------------
// Automation / agent shapes
// ---------------------------------------------------------------------------

export interface AutomationSignals {
  /** Emitted reason IDs (C, V, F, UA, H, S and behavior families, e.g. 'cdp.runtime.enable'). */
  reasonIds: string[];
  /** Weak reason IDs (low confidence on their own, e.g. 'launch.no-speech-voices'). */
  weakReasonIds: string[];
  /** Primary product shape name, or null. */
  agentName: string | null;
  /** All matched product shape IDs. */
  shapes: string[];
  error?: string;
}

export interface KinematicsTracker {
  stop(): void;
  /** Returns accumulated reason IDs and clears the buffer. */
  drain(): string[];
}

export interface AutomationCollectArgs {
  /** Installed fonts (sorted) from fonts.ts — muse/grok-bot shapes. */
  fontsInstalled?: string[];
  /** From fontPreferences.ts — S5 headless.font-exact-integers. */
  fontWidthsExact?: boolean;
  /** Raw unmasked WebGL renderer string — SwiftShader-based shapes. */
  rendererUnmasked?: string | null;
  /** Sec-CH-UA brand list from the server response headers — S7. */
  secChBrands?: string[];
}

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

export interface CollectedSignals {
  canvas: CanvasSignals;
  canvasNoise: CanvasNoiseReport;
  fonts: FontSignals;
  fontPreferences: FontPreferenceSignals;
  emoji: EmojiSignals;
  webglBasics: WebglBasics;
  webglExtensions: WebglExtensions;
  webglGpuIdentity: WebglGpuIdentity;
  audio: AudioSignals;
  math: MathSignals;
  systemEntropy: SystemEntropySignals;
  automation: AutomationSignals;
  meta: {
    collectedAt: string;
    totalDurationMs: number;
    /** Per-collector wall-clock durations in ms. */
    timingsMs: Record<string, number>;
  };
}

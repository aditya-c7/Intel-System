/**
 * Canvas noise classifier.
 *
 * Consumes the output of `getCanvasFingerprint()` plus optional browser
 * hints and classifies how the canvas bitmap is being perturbed:
 *
 *  - 'clean'                 — flat regions match ground truth exactly.
 *  - 'canvas_read_hook_noisy'— static `toDataURL()` reads differ (a read hook
 *                              injects noise per read; the collector already
 *                              proved instability by reading twice).
 *  - 'canvas_noise_uniform'  — flat-interior pixels perturbed with a small
 *                              (max channel delta ≤ 2) uniform amplitude on a
 *                              browser that does not natively farble.
 *  - 'browser_farbling'      — perturbation consistent with Brave farbling,
 *                              Safari 17+ private-mode noise, Firefox RFP or
 *                              Samsung Internet's algorithmic noise, given
 *                              the supplied `browserHints`.
 *  - 'unknown'               — no usable pixel evidence.
 *
 * Ground truth (clean renders):
 *  - geometry canvas: pixels (10,10), (2,2), (119,2), (2,107), (119,107) are
 *    fully transparent [0,0,0,0] (verified against circle/ring geometry).
 *  - text canvas: the top strip row y=0, x∈[100,161] above the #f60 bar is
 *    transparent (no glyph ascends that high at 11pt/18pt with these
 *    baselines).
 *  - the #f60 bar interior must be exactly [255,102,0,255]. Because the
 *    11pt line's emoji can reach into the left part of the bar, bar pixels
 *    are used only when they are LOCALLY CONSTANT (whole 3x3 neighborhood
 *    identical) and near the expected color — glyph interiors/edges never
 *    masquerade as noise. When no locally-constant pixels survive (dense
 *    noise), amplitude is estimated robustly from the delta distribution.
 */

import {
  createCanvasContext,
  renderGeometryInto,
  renderTextInto,
  CANVAS_GEOMETRY_SIZE,
  CANVAS_TEXT_SIZE,
} from './canvas';
import { hashBytes32, errorMessage } from './hash';
import type {
  BrowserCanvasHints,
  CanvasNoiseClassification,
  CanvasNoiseReport,
  CanvasSignals,
} from './types';

const GT_TRANSPARENT = [0, 0, 0, 0] as const;
const GT_BAR = [255, 102, 0, 255] as const;
/** Max distance from ground truth for a flat pixel to count as "near" it. */
const NEAR_GT_LIMIT = 8;
/** Spec band for uniform low-amplitude noise. */
const UNIFORM_NOISE_MAX_DELTA = 2;

const GEOMETRY_TRANSPARENT_POINTS = [
  [10, 10],
  [2, 2],
  [119, 2],
  [2, 107],
  [119, 107],
] as const;

function channelDelta(a: readonly number[], b: readonly number[]): number {
  return Math.max(Math.abs(a[0] - b[0]), Math.abs(a[1] - b[1]), Math.abs(a[2] - b[2]), Math.abs(a[3] - b[3]));
}

interface PixelSample {
  r: number;
  g: number;
  b: number;
  a: number;
}

function pixelAt(data: ImageData, x: number, y: number): PixelSample {
  const index = (y * data.width + x) * 4;
  const values = data.data;
  return { r: values[index], g: values[index + 1], b: values[index + 2], a: values[index + 3] };
}

interface BarAnalysis {
  /** Max per-channel delta of locally-constant near-GT bar pixels. */
  flatDelta: number | null;
  /** Robust amplitude estimate when no flat interior survives (dense noise). */
  denseDelta: number | null;
  flags: string[];
}

function analyzeBarRegion(data: ImageData): BarAnalysis {
  const flags: string[] = [];
  const width = data.width;
  // Locally-constant candidates: interior of the bar so the 3x3 window stays
  // inside it (bar spans x∈[100,162), y∈[1,21)).
  const candidates: PixelSample[] = [];
  for (let y = 2; y <= 19; y++) {
    for (let x = 103; x <= 159; x++) {
      const center = pixelAt(data, x, y);
      let constant = true;
      for (let dy = -1; dy <= 1 && constant; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          const n = pixelAt(data, x + dx, y + dy);
          if (n.r !== center.r || n.g !== center.g || n.b !== center.b || n.a !== center.a) {
            constant = false;
            break;
          }
        }
      }
      if (constant) candidates.push(center);
    }
  }

  if (candidates.length === 0) {
    // Every pixel differs from at least one neighbor => dense per-pixel noise.
    // Estimate amplitude with a low percentile so minority glyph overlap
    // cannot inflate it.
    const deltas: number[] = [];
    for (let y = 2; y <= 18; y += 2) {
      for (let x = 104; x <= 158; x += 2) {
        deltas.push(channelDelta([pixelAt(data, x, y).r, pixelAt(data, x, y).g, pixelAt(data, x, y).b, pixelAt(data, x, y).a], GT_BAR));
      }
    }
    deltas.sort((a, b) => a - b);
    const p25 = deltas.length > 0 ? deltas[Math.floor((deltas.length - 1) * 0.25)] : null;
    flags.push('bar.no_flat_interior');
    return { flatDelta: null, denseDelta: p25, flags };
  }

  let maxDelta: number | null = null;
  let nearCount = 0;
  let farCount = 0;
  for (const pixel of candidates) {
    const delta = channelDelta([pixel.r, pixel.g, pixel.b, pixel.a], GT_BAR);
    if (delta <= NEAR_GT_LIMIT) {
      nearCount++;
      if (maxDelta === null || delta > maxDelta) maxDelta = delta;
    } else {
      farCount++;
    }
  }
  if (nearCount === 0 && farCount > 0) {
    // Bar area exists but none of it matches ground truth: overdrawn or fully
    // re-colored; cannot measure amplitude from this region.
    flags.push('bar.ground_truth_missing');
    return { flatDelta: null, denseDelta: null, flags };
  }
  if (nearCount > 0 && farCount > 0) flags.push('bar.partial_overlap');
  return { flatDelta: maxDelta, denseDelta: null, flags };
}

function analyzeTransparentRegion(data: ImageData): number | null {
  let maxDelta: number | null = null;
  for (const [x, y] of GEOMETRY_TRANSPARENT_POINTS) {
    const pixel = pixelAt(data, x, y);
    const delta = channelDelta([pixel.r, pixel.g, pixel.b, pixel.a], GT_TRANSPARENT);
    if (maxDelta === null || delta > maxDelta) maxDelta = delta;
  }
  // Text canvas top strip (row 0 over the bar) — guaranteed transparent.
  for (let x = 100; x <= 161; x++) {
    const pixel = pixelAt(data, x, 0);
    const delta = channelDelta([pixel.r, pixel.g, pixel.b, pixel.a], GT_TRANSPARENT);
    if (maxDelta === null || delta > maxDelta) maxDelta = delta;
  }
  return maxDelta;
}

/** Re-renders the geometry bitmap with the 2 LSBs of every byte masked. */
function computeStabilizedGeometryHash(): string | null {
  const bundle = createCanvasContext(CANVAS_GEOMETRY_SIZE.width, CANVAS_GEOMETRY_SIZE.height, true);
  if (!bundle) return null;
  try {
    if (!renderGeometryInto(bundle.context)) return null;
    const data = bundle.context.getImageData(0, 0, CANVAS_GEOMETRY_SIZE.width, CANVAS_GEOMETRY_SIZE.height);
    const masked = new Uint8Array(data.data.length);
    for (let i = 0; i < data.data.length; i++) masked[i] = data.data[i] & 0xfc;
    return hashBytes32(masked);
  } catch {
    return null;
  } finally {
    try {
      bundle.canvas.remove();
    } catch {
      /* ignore */
    }
  }
}

/**
 * Classifies canvas noise. `signals` is the collector output (contains the
 * double-read instability flags and the data URLs); `browserHints` biases
 * perturbation with amplitude toward native farbling.
 */
export function classifyCanvasNoise(
  signals?: CanvasSignals | null,
  browserHints?: BrowserCanvasHints
): CanvasNoiseReport {
  const report: CanvasNoiseReport = {
    classification: null,
    maxChannelDelta: null,
    stabilizedGeometryHash: null,
    flags: [],
  };

  try {
    if (signals?.geometryUnstable) report.flags.push('read.geometry_unstable');
    if (signals?.textUnstable) report.flags.push('read.text_unstable');

    // Fresh renders for pixel analysis (preferred approach per blueprint: the
    // classifier re-renders through the exported render functions).
    let transparentDelta: number | null = null;
    let bar: BarAnalysis | null = null;
    let pixelError: string | null = null;
    try {
      const geometryBundle = createCanvasContext(CANVAS_GEOMETRY_SIZE.width, CANVAS_GEOMETRY_SIZE.height, true);
      if (geometryBundle) {
        try {
          if (renderGeometryInto(geometryBundle.context)) {
            const data = geometryBundle.context.getImageData(0, 0, CANVAS_GEOMETRY_SIZE.width, CANVAS_GEOMETRY_SIZE.height);
            transparentDelta = analyzeTransparentRegion(data);
          } else {
            pixelError = 'geometry re-render failed';
          }
        } finally {
          try {
            geometryBundle.canvas.remove();
          } catch {
            /* ignore */
          }
        }
      } else {
        pixelError = 'canvas 2d context unavailable';
      }

      const textBundle = createCanvasContext(CANVAS_TEXT_SIZE.width, CANVAS_TEXT_SIZE.height, true);
      if (textBundle) {
        try {
          if (renderTextInto(textBundle.context)) {
            const data = textBundle.context.getImageData(0, 0, CANVAS_TEXT_SIZE.width, CANVAS_TEXT_SIZE.height);
            bar = analyzeBarRegion(data);
          } else if (!pixelError) {
            pixelError = 'text re-render failed';
          }
        } finally {
          try {
            textBundle.canvas.remove();
          } catch {
            /* ignore */
          }
        }
      }
    } catch (err) {
      pixelError = errorMessage(err);
    }

    report.flags.push(...(bar?.flags ?? []));

    const deltas = [transparentDelta, bar?.flatDelta, bar?.denseDelta].filter(
      (value): value is number => typeof value === 'number'
    );
    report.maxChannelDelta = deltas.length > 0 ? Math.max(...deltas) : null;

    // Classification priority: read-hook instability wins (it is proof of a
    // hooking layer regardless of amplitude).
    if (signals?.geometryUnstable || signals?.textUnstable) {
      report.classification = 'canvas_read_hook_noisy';
    } else if (report.maxChannelDelta === null) {
      report.classification = 'unknown';
      if (pixelError && !report.error) report.error = pixelError;
    } else if (report.maxChannelDelta === 0) {
      report.classification = 'clean';
    } else {
      const hints = browserHints ?? {};
      if (hints.isBrave) {
        report.classification = 'browser_farbling';
        report.flags.push('hints.brave');
      } else if (hints.isSafari17Plus) {
        report.classification = 'browser_farbling';
        report.flags.push('hints.safari17_plus');
        if (hints.privateMode) report.flags.push('hints.private_mode');
      } else if (hints.isSamsung) {
        report.classification = 'browser_farbling';
        report.flags.push('hints.samsung');
      } else if (hints.isFirefox) {
        // Firefox perturbs canvas under resistFingerprinting / ETP strict;
        // without a direct RFP probe we treat noise + Firefox hint as farbling.
        report.classification = 'browser_farbling';
        report.flags.push('hints.firefox_rfp_heuristic');
      } else if (report.maxChannelDelta <= UNIFORM_NOISE_MAX_DELTA) {
        report.classification = 'canvas_noise_uniform';
      } else {
        // Stable-but-stronger noise with no native-farbling hint: still an
        // injected-noise pattern, flagged for its larger amplitude.
        report.classification = 'canvas_noise_uniform';
        report.flags.push('noise.amplitude_high');
      }
    }

    // Stabilized digest: mask the 2 least-significant bits of every byte so
    // uniform ±1..±2 perturbations fold onto the same quantized image.
    if (report.maxChannelDelta !== null && report.maxChannelDelta <= UNIFORM_NOISE_MAX_DELTA) {
      const stabilized = computeStabilizedGeometryHash();
      report.stabilizedGeometryHash = stabilized;
      if (stabilized !== null) report.flags.push('stabilized.masked_lsb2');
    }
  } catch (err) {
    report.error = errorMessage(err);
    if (report.classification === null) report.classification = 'unknown';
  }

  return report;
}

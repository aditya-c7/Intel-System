/**
 * Deterministic Canvas 2D fingerprint — FingerprintJS algorithm with the
 * classic instability bugs fixed by using THREE fully isolated canvases:
 *
 *   Stage 1  winding   — dedicated 10x10 canvas
 *   Stage 2  geometry  — fresh 122x110 canvas (multiply blending)
 *   Stage 3  text      — fresh 240x60 canvas (#f60 bar + two text lines)
 *
 * In upstream FingerprintJS the winding test reuses the shared 1x1 canvas and
 * the geometry image reuses the text canvas (resize cleans it). Reusing a
 * canvas leaks path/composite state between stages and has produced flakes,
 * so every stage here renders into its own fresh canvas. The double-read
 * verification (`toDataURL()` twice on the SAME static bitmap, no redraw in
 * between) detects canvas-read hooks: differing reads => unstable => the
 * browser injects noise at read time.
 *
 * This collector never bails out per browser brand (no Safari/Firefox
 * version skips like upstream); readback verification + the noise classifier
 * in `canvasClassifier.ts` handle farbling/noise instead.
 */

import { stableHash32, errorMessage } from './hash';
import type { CanvasSignals } from './types';

export const CANVAS_GEOMETRY_SIZE = { width: 122, height: 110 } as const;
export const CANVAS_TEXT_SIZE = { width: 240, height: 60 } as const;

export interface CanvasContextBundle {
  canvas: HTMLCanvasElement;
  context: CanvasRenderingContext2D;
}

/**
 * Creates an isolated canvas + 2d context. Returns null when unsupported
 * (also covers `toDataURL` availability). `willReadFrequently` hints the
 * engine to use a CPU-backed store — used by the pixel classifier.
 */
export function createCanvasContext(
  width: number,
  height: number,
  willReadFrequently?: boolean
): CanvasContextBundle | null {
  try {
    if (typeof document === 'undefined' || !document.createElement) return null;
    const canvas = document.createElement('canvas');
    // Resizing cleans the bitmap; set both sizes explicitly.
    canvas.width = width;
    canvas.height = height;
    const settings: CanvasRenderingContext2DSettings = willReadFrequently
      ? { willReadFrequently: true }
      : {};
    const context = canvas.getContext('2d', settings);
    if (!context) return null;
    if (typeof canvas.toDataURL !== 'function') return null;
    return { canvas, context };
  } catch {
    return null;
  }
}

/**
 * Stage 1: winding support. `rect(0,0,10,10)` + `rect(2,2,6,6)`; the point
 * (5,5) is covered by both rects, so under 'evenodd' it is NOT in the path.
 * Returns null when canvas support is missing.
 */
export function measureCanvasWinding(): boolean | null {
  const bundle = createCanvasContext(10, 10);
  if (!bundle) return null;
  const { context } = bundle;
  try {
    context.rect(0, 0, 10, 10);
    context.rect(2, 2, 6, 6);
    return !context.isPointInPath(5, 5, 'evenodd');
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
 * Stage 2: geometry image — three multiply-blended circles plus a #f9c
 * even-odd ring. Deterministic across engines with identical code paths.
 */
export function renderGeometryInto(context: CanvasRenderingContext2D): boolean {
  try {
    context.globalCompositeOperation = 'multiply';
    for (const [color, x, y] of [
      ['#f2f', 40, 40],
      ['#2ff', 80, 40],
      ['#ff2', 60, 80],
    ] as const) {
      context.fillStyle = color;
      context.beginPath();
      context.arc(x, y, 40, 0, Math.PI * 2, true);
      context.closePath();
      context.fill();
    }
    // Ring: two concentric arcs filled with 'evenodd'. (The blueprint keeps
    // the multiply composite active here, exactly like the reference.)
    context.fillStyle = '#f9c';
    context.beginPath();
    context.arc(60, 60, 60, 0, Math.PI * 2, true);
    context.arc(60, 60, 20, 0, Math.PI * 2, true);
    context.fill('evenodd');
    return true;
  } catch {
    return false;
  }
}

/**
 * Stage 3: text image — solid #f60 bar, one line of 'Cwm fjordbank gly 😃'
 * in 11pt Times New Roman (explicit built-in font, no font-preference bleed)
 * and the same text in translucent 18pt Arial. The emoji is the surrogate
 * pair fromCharCode(55357, 56835) with nothing to its right (per upstream:
 * a bare emoji changes with document encoding; trailing text kills perf).
 */
export function renderTextInto(context: CanvasRenderingContext2D): boolean {
  try {
    context.textBaseline = 'alphabetic';
    context.fillStyle = '#f60';
    context.fillRect(100, 1, 62, 20);

    context.fillStyle = '#069';
    context.font = '11pt "Times New Roman"';
    const printedText = `Cwm fjordbank gly ${String.fromCharCode(55357, 56835) /* 😃 */}`;
    context.fillText(printedText, 2, 15);

    context.fillStyle = 'rgba(102, 204, 0, 0.2)';
    context.font = '18pt Arial';
    context.fillText(printedText, 4, 45);
    return true;
  } catch {
    return false;
  }
}

/** Reads a static bitmap twice; differing reads indicate a canvas-read hook. */
function readStableDataUrl(canvas: HTMLCanvasElement): {
  first: string | null;
  unstable: boolean | null;
} {
  try {
    const first = canvas.toDataURL();
    const second = canvas.toDataURL();
    return { first, unstable: first !== second };
  } catch {
    return { first: null, unstable: null };
  }
}

/**
 * Collects the three-stage canvas fingerprint.
 * Total: always returns a payload; failures surface in `error`.
 */
export function getCanvasFingerprint(): CanvasSignals {
  const result: CanvasSignals = {
    winding: null,
    geometry: '',
    text: '',
    geometryUnstable: null,
    textUnstable: null,
    geometryDataUrl: null,
    textDataUrl: null,
  };

  try {
    result.winding = measureCanvasWinding();

    // Geometry stage — fresh, isolated canvas.
    const geometryBundle = createCanvasContext(CANVAS_GEOMETRY_SIZE.width, CANVAS_GEOMETRY_SIZE.height);
    if (geometryBundle) {
      const rendered = renderGeometryInto(geometryBundle.context);
      if (!rendered && !result.error) result.error = 'geometry render failed';
      const read = readStableDataUrl(geometryBundle.canvas);
      result.geometryDataUrl = read.first;
      result.geometryUnstable = read.unstable;
      result.geometry = read.first ? stableHash32(read.first) : '';
      try {
        geometryBundle.canvas.remove();
      } catch {
        /* ignore */
      }
    } else if (!result.error) {
      result.error = 'canvas 2d context unavailable';
    }

    // Text stage — another fresh, isolated canvas.
    const textBundle = createCanvasContext(CANVAS_TEXT_SIZE.width, CANVAS_TEXT_SIZE.height);
    if (textBundle) {
      const rendered = renderTextInto(textBundle.context);
      if (!rendered && !result.error) result.error = 'text render failed';
      const read = readStableDataUrl(textBundle.canvas);
      result.textDataUrl = read.first;
      result.textUnstable = read.unstable;
      result.text = read.first ? stableHash32(read.first) : '';
      try {
        textBundle.canvas.remove();
      } catch {
        /* ignore */
      }
    } else if (!result.error) {
      result.error = 'canvas 2d context unavailable';
    }
  } catch (err) {
    result.error = errorMessage(err);
  }

  return result;
}

/**
 * Font preference probe — measures sub-pixel text widths for 7 font stacks
 * (FingerprintJS `fontPreferences`-style presets) inside a SHORT-LIVED, hidden,
 * isolated 16px `about:blank` iframe. On desktop browsers the resulting widths
 * are fractional; headless-shell builds on Linux disable sub-pixel text
 * positioning, so every width comes back an exact integer.
 * `widthsExactIntegers` is therefore a headless hint, mainly meaningful on
 * Linux (integer widths are unremarkable on many mobile/round-UI setups).
 *
 * Isolation matters: a 4000px-wide block in the host document can inherit page
 * CSS (zoom, transforms, writing-mode, custom @font-face rules) and can pollute
 * layout. The iframe gives every measurement a clean 16px root.
 */

import { errorMessage } from './hash';
import type { FontPreferencePreset, FontPreferenceSignals } from './types';

/** Exact probe text required by the locked font metric contract. */
export const FONT_MEASURE_TEST_STRING = 'mmMwWLliI0fiflO&1';
/** Isolated measurement root font size. */
export const FONT_MEASURE_FONT_SIZE_PX = 16;

const PRESETS: readonly FontPreferencePreset[] = ['default', 'apple', 'serif', 'sans', 'mono', 'min', 'system'];

interface PresetStyle {
  fontFamily: string;
}

const PRESET_STYLES: Record<FontPreferencePreset, PresetStyle> = {
  default: { fontFamily: 'sans-serif' },
  apple: { fontFamily: '-apple-system-body' },
  serif: { fontFamily: 'serif' },
  sans: { fontFamily: 'sans-serif' },
  mono: { fontFamily: 'monospace' },
  min: { fontFamily: 'monospace' },
  system: { fontFamily: 'system-ui' },
};

export interface FontMeasurementRect {
  width: number;
  height: number;
  top: number;
  bottom: number;
  left: number;
  right: number;
  x: number;
  y: number;
}

/**
 * Isolated font-measurement surface. All reads go through
 * `getBoundingClientRect()` on a single span in a hidden iframe. Returns null
 * when the DOM is unavailable or the iframe document is inaccessible (CSP);
 * callers must degrade to no measurement, never throw.
 */
export interface IsolatedFontMeasurer {
  width(text: string, fontFamily: string): number;
  rect(text: string, fontFamily: string): FontMeasurementRect | null;
  dispose(): void;
}

/** Creates a hidden, same-origin `about:blank` iframe with a clean 16px root. */
export function createIsolatedFontMeasurer(): IsolatedFontMeasurer | null {
  if (typeof document === 'undefined') return null;
  let frame: HTMLIFrameElement | null = null;
  try {
    frame = document.createElement('iframe');
    frame.setAttribute('aria-hidden', 'true');
    frame.tabIndex = -1;
    frame.style.cssText =
      'position:absolute;left:-99999px;top:0;width:1px;height:1px;border:0;opacity:0;pointer-events:none;';
    frame.src = 'about:blank';
    const parent = document.body ?? document.documentElement;
    if (!parent) return null;
    parent.appendChild(frame);

    const doc: Document | null =
      frame.contentDocument ?? frame.contentWindow?.document ?? null;
    if (!doc) throw new Error('isolated font iframe document unavailable');
    doc.open();
    doc.write(
      '<!doctype html><html><head><meta charset="utf-8"><style>' +
        'html,body{margin:0;padding:0;font-size:16px;line-height:normal;}' +
        '#probe{position:absolute;left:0;top:0;white-space:nowrap;visibility:hidden;}' +
        '</style></head><body><span id="probe"></span></body></html>'
    );
    doc.close();

    const probe = doc.getElementById('probe') as HTMLElement | null;
    if (!probe) throw new Error('isolated font iframe probe span unavailable');

    const apply = (text: string, fontFamily: string): void => {
      probe.textContent = text;
      probe.style.fontFamily = fontFamily || 'sans-serif';
      probe.style.fontSize = `${FONT_MEASURE_FONT_SIZE_PX}px`;
    };
    const finite = (value: number): number => (Number.isFinite(value) ? value : 0);

    return {
      width(text, fontFamily) {
        try {
          apply(text, fontFamily);
          return finite(probe.getBoundingClientRect().width);
        } catch {
          return 0;
        }
      },
      rect(text, fontFamily) {
        try {
          apply(text, fontFamily);
          const r = probe.getBoundingClientRect();
          return {
            width: finite(r.width),
            height: finite(r.height),
            top: finite(r.top),
            bottom: finite(r.bottom),
            left: finite(r.left),
            right: finite(r.right),
            x: finite(r.x),
            y: finite(r.y),
          };
        } catch {
          return null;
        }
      },
      dispose() {
        try {
          frame?.remove();
        } catch {
          /* frame removal is best-effort */
        }
      },
    };
  } catch {
    try {
      frame?.remove();
    } catch {
      /* ignore */
    }
    return null;
  }
}

/**
 * Total: always returns a payload. Every width is measured inside the isolated
 * iframe with the locked probe string and `getBoundingClientRect().width`.
 */
export function collectFontPreferenceSignals(): FontPreferenceSignals {
  const result: FontPreferenceSignals = {
    widths: {
      default: null,
      apple: null,
      serif: null,
      sans: null,
      mono: null,
      min: null,
      system: null,
    },
    widthsExactIntegers: true,
  };

  const measurer = createIsolatedFontMeasurer();
  if (!measurer) {
    result.error = 'isolated 16px font iframe unavailable';
    result.widthsExactIntegers = false;
    return result;
  }

  try {
    for (const preset of PRESETS) {
      result.widths[preset] = measurer.width(FONT_MEASURE_TEST_STRING, PRESET_STYLES[preset].fontFamily);
    }
    const nonNull = PRESETS.map((preset) => result.widths[preset]).filter(
      (value): value is number => typeof value === 'number'
    );
    if (nonNull.length === 0) {
      result.widthsExactIntegers = false;
      if (!result.error) result.error = 'no measurable font preference widths';
    } else {
      result.widthsExactIntegers = nonNull.every((value) => Number.isInteger(value));
    }
  } catch (err) {
    result.error = errorMessage(err);
  } finally {
    measurer.dispose();
  }

  return result;
}

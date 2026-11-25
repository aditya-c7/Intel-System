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

// ---------------------------------------------------------------------------
// FingerprintJS v5 font-preferences probe — additive research surface
//
// The legacy collector above is deliberately untouched: the object it returns
// is fed WHOLE into the browser digest (`font_preferences`), so no new key may
// be added to it. Everything below is exposed only through NEW exports.
// ---------------------------------------------------------------------------

/** v5 default probe text (m/w widest, plus ligatures). */
export const FONT_PREFERENCES_V5_TEST_STRING = 'mmMwWLliI0fiflO&1';
/** v5 `withNaturalFonts` container width — wide enough for Android font scaling. */
export const FONT_PREFERENCES_V5_CONTAINER_WIDTH_PX = 4000;

export type FontPreferencePresetV5 = 'default' | 'apple' | 'serif' | 'sans' | 'mono' | 'min' | 'system';

/** Writable subset of CSS styles used by the v5 presets. */
export interface FontPreferenceV5PresetStyle {
  font?: string;
  fontFamily?: string;
  fontSize?: string;
}

/** Exact FPJS v5 preset styles (random but persistent keys). */
export const FONT_PREFERENCES_V5_PRESETS: Readonly<
  Record<FontPreferencePresetV5, Readonly<FontPreferenceV5PresetStyle>>
> = {
  default: {},
  apple: { font: '-apple-system-body' },
  serif: { fontFamily: 'serif' },
  sans: { fontFamily: 'sans-serif' },
  mono: { fontFamily: 'monospace' },
  min: { fontSize: '1px' },
  system: { fontFamily: 'system-ui' },
};

/** Result of the FingerprintJS v5 font-preferences probe. */
export interface FontPreferenceSignalsV5 {
  /** `getBoundingClientRect().width` per preset (V5-normalized where applicable). */
  widths: Record<FontPreferencePresetV5, number | null>;
  error?: string;
}

interface V5BrowserHints {
  isAndroid: boolean;
  isChromium: boolean;
  isChromium128OrNewer: boolean;
  isWebKit: boolean;
}

/** Best-effort UA equivalent of the FPJS `utils/browser` checks used by v5. */
function readV5BrowserHints(): V5BrowserHints {
  const ua = typeof navigator === 'undefined' ? '' : navigator.userAgent;
  const isAndroid = /Android/i.test(ua);
  const chromiumMatch = /(?:Chrome|Chromium|CriOS)\/(\d+)/i.exec(ua);
  const isChromium = chromiumMatch !== null;
  const isChromium128OrNewer = isChromium && Number(chromiumMatch![1]) >= 128;
  const isWebKit = !isChromium && /AppleWebKit/i.test(ua);
  return { isAndroid, isChromium, isChromium128OrNewer, isWebKit };
}

/** FPJS `normalizeFontMeasurement`: Android rounds to whole numbers, else floor to 3dp. */
export function normalizeFontMeasurementV5(value: number, isAndroid: boolean): number {
  const decimals = isAndroid ? 0 : 3;
  const pow = Math.pow(10, decimals);
  return Math.floor(value * pow) / pow;
}

/**
 * FPJS `withNaturalFonts`: a wide, zoom-independent, srcdoc iframe so Android
 * system fonts and desktop zoom modes cannot change the measured widths.
 */
async function withV5NaturalFontsIframe<T>(
  action: (doc: Document, body: HTMLElement, iframeWindow: Window) => T,
  containerWidthPx = FONT_PREFERENCES_V5_CONTAINER_WIDTH_PX
): Promise<T | null> {
  if (typeof document === 'undefined' || !document.body) return null;
  const iframe = document.createElement('iframe');
  const hints = readV5BrowserHints();
  try {
    await new Promise<void>((resolve, reject) => {
      iframe.onload = () => resolve();
      iframe.onerror = () => reject(new Error('v5 natural-fonts iframe failed to load'));
      const style = iframe.style;
      style.setProperty('display', 'block', 'important');
      style.position = 'absolute';
      style.top = '0';
      style.left = '0';
      style.visibility = 'hidden';
      // srcdoc is required to set the viewport meta on Android Firefox.
      iframe.srcdoc =
        '<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">';
      document.body.appendChild(iframe);
    });
    const iframeWindow = iframe.contentWindow as Window | null;
    const doc = iframeWindow?.document ?? null;
    const body = doc?.body ?? null;
    if (!iframeWindow || !doc || !body) return null;

    const bodyStyle = body.style;
    bodyStyle.width = `${containerWidthPx}px`;
    bodyStyle.setProperty('text-size-adjust', 'none');
    bodyStyle.setProperty('-webkit-text-size-adjust', 'none');

    if (hints.isChromium) {
      const dpr = iframeWindow.devicePixelRatio || 1;
      bodyStyle.zoom = `${1 / dpr}`;
    } else if (hints.isWebKit) {
      bodyStyle.zoom = 'reset';
    }

    const linesOfText = doc.createElement('div');
    linesOfText.textContent = [...Array((containerWidthPx / 20) << 0)].map(() => 'word').join(' ');
    body.appendChild(linesOfText);

    return action(doc, body, iframeWindow);
  } finally {
    try {
      iframe.remove();
    } catch {
      /* best effort */
    }
  }
}

/**
 * FingerprintJS v5 `getFontPreferences()` as a PURE ADDITIVE helper.
 *
 * Uses `getBoundingClientRect().width` only (never offsetWidth, never height),
 * the exact 7 v5 presets, and FPJS zoom normalization: Chromium 128+ multiplies
 * by devicePixelRatio and floors (Android: whole numbers, else 3 decimals);
 * all other engines use the raw width.
 */
export async function collectFontPreferenceSignalsV5(): Promise<FontPreferenceSignalsV5> {
  const result: FontPreferenceSignalsV5 = {
    widths: {
      default: null,
      apple: null,
      serif: null,
      sans: null,
      mono: null,
      min: null,
      system: null,
    },
  };
  try {
    const hints = readV5BrowserHints();
    const presets = Object.keys(FONT_PREFERENCES_V5_PRESETS) as FontPreferencePresetV5[];
    const sizes = await withV5NaturalFontsIframe((doc, body, iframeWindow) => {
      const elements: Record<string, HTMLElement> = {};
      // Create every element first: interleaving DOM writes and layout reads is slow.
      for (const key of presets) {
        const presetStyle = FONT_PREFERENCES_V5_PRESETS[key];
        const element = doc.createElement('span');
        element.textContent = FONT_PREFERENCES_V5_TEST_STRING;
        element.style.whiteSpace = 'nowrap';
        if (presetStyle.font !== undefined) element.style.font = presetStyle.font;
        if (presetStyle.fontFamily !== undefined) element.style.fontFamily = presetStyle.fontFamily;
        if (presetStyle.fontSize !== undefined) element.style.fontSize = presetStyle.fontSize;
        elements[key] = element;
        body.appendChild(doc.createElement('br'));
        body.appendChild(element);
      }

      const measured: Partial<Record<FontPreferencePresetV5, number>> = {};
      for (const key of presets) {
        const rawWidth = elements[key].getBoundingClientRect().width;
        measured[key] =
          hints.isChromium && hints.isChromium128OrNewer
            ? normalizeFontMeasurementV5(rawWidth * iframeWindow.devicePixelRatio, hints.isAndroid)
            : rawWidth;
      }
      return measured;
    });
    if (!sizes) {
      result.error = 'v5 natural-fonts iframe unavailable';
      return result;
    }
    for (const key of presets) {
      const value = sizes[key];
      result.widths[key] = typeof value === 'number' && Number.isFinite(value) ? value : null;
    }
  } catch (err) {
    result.error = errorMessage(err);
  }
  return result;
}

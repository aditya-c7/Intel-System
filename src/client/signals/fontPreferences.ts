/**
 * Font preference probe — measures sub-pixel text widths for 7 font stacks
 * (FingerprintJS `fontPreferences`-style presets). On desktop browsers the
 * resulting widths are fractional; headless-shell builds on Linux disable
 * sub-pixel text positioning, so every width comes back an exact integer.
 * `widthsExactIntegers` is therefore a headless hint, mainly meaningful on
 * Linux (integer widths are unremarkable on many mobile/round-UI setups).
 */

import { errorMessage } from './hash';
import type { FontPreferencePreset, FontPreferenceSignals } from './types';

const TEST_STRING = 'mmMwWLliI0O&1mmMwWLliI0O&1mmMwWLliI0O&1';
const CONTAINER_WIDTH = '4000px';
const PRESETS: readonly FontPreferencePreset[] = ['default', 'apple', 'serif', 'sans', 'mono', 'min', 'system'];

interface PresetStyle {
  fontFamily: string;
  fontSize: string;
}

const PRESET_STYLES: Record<FontPreferencePreset, PresetStyle> = {
  default: { fontFamily: 'sans-serif', fontSize: '48px' },
  apple: { fontFamily: '-apple-system-body', fontSize: '48px' },
  serif: { fontFamily: 'serif', fontSize: '48px' },
  sans: { fontFamily: 'sans-serif', fontSize: '48px' },
  mono: { fontFamily: 'monospace', fontSize: '48px' },
  min: { fontFamily: 'monospace', fontSize: '4px' },
  system: { fontFamily: 'system-ui', fontSize: '48px' },
};

/**
 * Total: always returns a payload. The container is a hidden 4000px-wide
 * absolutely-positioned block (visibility:hidden keeps layout intact) and
 * every span is removed with it afterwards.
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

  try {
    const parent = document.body ?? document.documentElement;
    if (!parent) {
      result.error = 'no document body to attach the measurement container';
      return result;
    }

    const container = document.createElement('div');
    container.style.cssText =
      `position:absolute;left:-99999px;top:0;width:${CONTAINER_WIDTH};height:200px;` +
      'overflow:hidden;visibility:hidden;white-space:nowrap;pointer-events:none;';
    parent.appendChild(container);

    const spans: HTMLSpanElement[] = [];
    try {
      for (const preset of PRESETS) {
        const style = PRESET_STYLES[preset];
        const span = document.createElement('span');
        span.textContent = TEST_STRING;
        span.style.cssText =
          'display:inline-block;white-space:nowrap;margin:0;padding:0;border:0;';
        span.style.fontFamily = style.fontFamily;
        span.style.fontSize = style.fontSize;
        container.appendChild(span);
        spans.push(span);
        const rect = span.getBoundingClientRect();
        result.widths[preset] = Number.isFinite(rect.width) ? rect.width : null;
      }

      const nonNull = PRESETS.map((preset) => result.widths[preset]).filter(
        (value): value is number => typeof value === 'number'
      );
      if (nonNull.length === 0) {
        result.widthsExactIntegers = false;
        if (!result.error) result.error = 'no measurable font preference widths';
      } else {
        // Headless-shell hint: all widths exact integers.
        result.widthsExactIntegers = nonNull.every((value) => Number.isInteger(value));
      }
    } finally {
      try {
        container.remove();
      } catch {
        spans.length = 0; // container removal cascades; nothing left to clean
      }
    }
  } catch (err) {
    result.error = errorMessage(err);
  }

  return result;
}

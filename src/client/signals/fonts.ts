/**
 * Font-installed probe — 67 fonts measured inside a hidden same-origin
 * iframe so the host page's stylesheet cannot interfere with measurements.
 *
 * Method (FingerprintJS standard): render the test string 'mmMwWLliI0O&1'
 * at 72px in `"<candidate>", <base>` and compare offsetWidth/offsetHeight
 * against the `<base>`-only baseline, for every base font in
 * ['monospace', 'sans-serif', 'serif']. The candidate is installed when any
 * base font yields a different width OR height (a missing font falls back
 * to the base and reproduces the baseline exactly).
 */

import { hashStrings, errorMessage } from './hash';
import type { FontSignals } from './types';

const TEST_STRING = 'mmMwWLliI0O&1';
const FONT_SIZE = '72px';
const BASE_FONTS = ['monospace', 'sans-serif', 'serif'] as const;

/** The 52 standard FingerprintJS probe fonts. */
const STANDARD_FONTS = [
  'sans-serif-thin', 'ARNO PRO', 'Agency FB', 'Arabic Typesetting', 'Arial Unicode MS',
  'AvantGarde Bk BT', 'BankGothic Md BT', 'Batang', 'Bitstream Vera Sans Mono', 'Calibri',
  'Century', 'Century Gothic', 'Clarendon', 'EUROSTILE', 'Franklin Gothic',
  'Futura Bk BT', 'Futura Md BT', 'GOTHAM', 'Gill Sans', 'HELV',
  'Haettenschweiler', 'Helvetica Neue', 'Humanst521 BT', 'Leelawadee', 'Letter Gothic',
  'Levenim MT', 'Lucida Bright', 'Lucida Sans', 'Menlo', 'MS Mincho',
  'MS Outlook', 'MS Reference Specialty', 'MS UI Gothic', 'MT Extra', 'MYRIAD PRO',
  'Marlett', 'Meiryo UI', 'Microsoft Uighur', 'Minion Pro', 'Monotype Corsiva',
  'PMingLiU', 'Pristina', 'SCRIPTINA', 'Segoe UI Light', 'Serifa',
  'SimHei', 'Small Fonts', 'Staccato222 BT', 'TRAJAN PRO', 'Univers CE 55 Medium',
  'Vrinda', 'ZWAdobeF',
] as const;

/** 15 additional high-signal fonts (Linux/Windows/mac markers). */
const EXTENDED_FONTS = [
  'Ubuntu', 'Droid Sans', 'Cambria', 'Liberation Sans', 'Arimo',
  'Arial', 'Arial Black', 'Arial Narrow', 'Helvetica', 'aakar',
  'Times New Roman', 'Courier New', 'Segoe UI', 'San Francisco', 'Cantarell',
] as const;

const ALL_FONTS: readonly string[] = [...STANDARD_FONTS, ...EXTENDED_FONTS];

type PlatformClass = FontSignals['platformClassGuess'];

interface Measurement {
  width: number;
  height: number;
}

interface HiddenFrame {
  iframe: HTMLIFrameElement;
  doc: Document;
  body: HTMLElement;
}

/** Hides the iframe with display:none; switches to an offscreen-visible
 * variant if a display:none frame cannot be measured (some engines skip
 * layout entirely for display:none frames). */
function applyFrameStyle(iframe: HTMLIFrameElement, visibleFallback: boolean): void {
  if (visibleFallback) {
    iframe.style.cssText =
      'position:absolute;left:-99999px;top:0;width:600px;height:400px;border:0;' +
      'visibility:hidden;opacity:0;pointer-events:none;';
  } else {
    iframe.style.cssText = 'display:none;border:0;width:600px;height:400px;';
  }
  iframe.setAttribute('aria-hidden', 'true');
  iframe.setAttribute('title', '');
}

function getHiddenFrame(visibleFallback: boolean): HiddenFrame | null {
  try {
    const iframe = document.createElement('iframe');
    applyFrameStyle(iframe, visibleFallback);
    const parent = document.body ?? document.documentElement;
    if (!parent) return null;
    parent.appendChild(iframe);
    const doc = iframe.contentDocument;
    if (!doc) {
      try {
        iframe.remove();
      } catch {
        /* ignore */
      }
      return null;
    }
    const body = (doc.body ?? doc.documentElement) as HTMLElement | null;
    if (!body) {
      try {
        iframe.remove();
      } catch {
        /* ignore */
      }
      return null;
    }
    return { iframe, doc, body };
  } catch {
    return null;
  }
}

function measure(doc: Document, body: HTMLElement, fontFamily: string): Measurement {
  const span = doc.createElement('span');
  span.textContent = TEST_STRING;
  span.style.cssText =
    `position:absolute;left:-99999px;top:0;white-space:nowrap;font-size:${FONT_SIZE};` +
    'letter-spacing:normal;margin:0;padding:0;border:0;';
  span.style.fontFamily = fontFamily;
  body.appendChild(span);
  const width = span.offsetWidth;
  const height = span.offsetHeight;
  try {
    span.remove();
  } catch {
    /* ignore */
  }
  return { width, height };
}

function quoteFontName(name: string): string {
  return `"${name.replace(/["\\]/g, '')}"`;
}

interface MeasureOutcome {
  baselines: Map<string, Measurement>;
  installed: Set<string>;
  usable: boolean;
}

function measureAll(doc: Document, body: HTMLElement): MeasureOutcome {
  const baselines = new Map<string, Measurement>();
  for (const base of BASE_FONTS) baselines.set(base, measure(doc, body, base));

  const installed = new Set<string>();
  for (const candidate of ALL_FONTS) {
    const quoted = quoteFontName(candidate);
    for (const base of BASE_FONTS) {
      const baseline = baselines.get(base);
      if (!baseline) continue;
      let combined: Measurement;
      try {
        combined = measure(doc, body, `${quoted}, ${base}`);
      } catch {
        continue;
      }
      if (combined.width !== baseline.width || combined.height !== baseline.height) {
        installed.add(candidate);
        break;
      }
    }
  }

  let usable = false;
  for (const base of BASE_FONTS) {
    const baseline = baselines.get(base);
    if (baseline && baseline.width > 0) usable = true;
  }
  return { baselines, installed, usable };
}

/** Heuristic platform class from marker fonts (weighted scoring). */
function guessPlatformClass(installed: ReadonlySet<string>): PlatformClass {
  const has = (font: string): boolean => installed.has(font);
  const scores: Record<PlatformClass, number> = { windows: 0, mac: 0, linux: 0, unknown: 0 };
  // Windows markers (spec: Segoe UI / Calibri present → windows)
  if (has('Segoe UI')) scores.windows += 2;
  if (has('Calibri')) scores.windows += 1;
  if (has('Segoe UI Light')) scores.windows += 1;
  // mac markers (spec: San Francisco / Menlo present → mac)
  if (has('San Francisco')) scores.mac += 2;
  if (has('Menlo')) scores.mac += 1;
  if (has('Helvetica Neue')) scores.mac += 1;
  // Linux markers (spec: Ubuntu / Liberation present → linux)
  if (has('Ubuntu')) scores.linux += 2;
  if (has('Liberation Sans')) scores.linux += 1;
  if (has('Cantarell')) scores.linux += 1;
  if (has('aakar')) scores.linux += 1;

  let best: PlatformClass = 'unknown';
  let bestScore = 0;
  let ties = 0;
  for (const key of ['windows', 'mac', 'linux'] as const) {
    if (scores[key] > bestScore) {
      best = key;
      bestScore = scores[key];
      ties = 0;
    } else if (scores[key] > 0 && scores[key] === bestScore) {
      ties++;
    }
  }
  return bestScore > 0 && ties === 0 ? best : 'unknown';
}

/** Total: always returns a payload. */
export function collectFontSignals(): FontSignals {
  const result: FontSignals = { installed: [], fontHash: '', platformClassGuess: 'unknown' };

  try {
    let installed: Set<string> | null = null;
    let frame: HiddenFrame | null = null;

    // Primary attempt: display:none iframe (blueprint). If layout is skipped
    // (all baselines zero-width), retry with an offscreen-visible frame.
    for (const visibleFallback of [false, true]) {
      frame = getHiddenFrame(visibleFallback);
      if (!frame) continue;
      const outcome = measureAll(frame.doc, frame.body);
      if (outcome.usable) {
        installed = outcome.installed;
        break;
      }
      try {
        frame.iframe.remove();
      } catch {
        /* ignore */
      }
      frame = null;
    }

    if (frame) {
      try {
        frame.iframe.remove();
      } catch {
        /* ignore */
      }
    }

    if (!installed) {
      result.error = 'font measurement iframe unavailable';
      return result;
    }

    const sorted = Array.from(installed).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    result.installed = sorted;
    result.fontHash = hashStrings(sorted);
    result.platformClassGuess = guessPlatformClass(installed);
  } catch (err) {
    result.error = errorMessage(err);
  }

  return result;
}

// ---------------------------------------------------------------------------
// FingerprintJS v5 font probe — additive research surface
//
// The block above is the legacy collector and is intentionally left untouched:
// `installed`, `fontHash` and `platformClassGuess` (the hardware-digest inputs)
// are byte-identical. Everything below mirrors FPJS v5 `src/sources/fonts.ts`
// and is exposed only through NEW exports so no existing digest can change.
// ---------------------------------------------------------------------------

/**
 * v5 probe string: `m`/`w` maximise width, `LLi` separates matching fonts.
 * NOTE: the task brief said `mmMwWLliI0&1`; the actual FPJS v5 source
 * (src/sources/fonts.ts on master, and v4) uses `mmMwWLliI0O&1` with an extra
 * capital `O` before `&`. This is the researched exact value; change this
 * single constant if the brief's spelling is required instead.
 */
export const FONTS_V5_TEST_STRING = 'mmMwWLliI0O&1';
/** v5 renders at 48px by setting the iframe BODY font-size (spans inherit it). */
export const FONTS_V5_TEXT_SIZE = '48px';
/** v5 generic fallback families, compared in this order. */
export const FONTS_V5_BASE_FONTS = ['monospace', 'sans-serif', 'serif'] as const;

/** Exact 52-name FingerprintJS v5 font list, in source order. */
export const FONTS_V5_FONT_LIST = [
  'sans-serif-thin',
  'ARNO PRO',
  'Agency FB',
  'Arabic Typesetting',
  'Arial Unicode MS',
  'AvantGarde Bk BT',
  'BankGothic Md BT',
  'Batang',
  'Bitstream Vera Sans Mono',
  'Calibri',
  'Century',
  'Century Gothic',
  'Clarendon',
  'EUROSTILE',
  'Franklin Gothic',
  'Futura Bk BT',
  'Futura Md BT',
  'GOTHAM',
  'Gill Sans',
  'HELV',
  'Haettenschweiler',
  'Helvetica Neue',
  'Humanst521 BT',
  'Leelawadee',
  'Letter Gothic',
  'Levenim MT',
  'Lucida Bright',
  'Lucida Sans',
  'Menlo',
  'MS Mincho',
  'MS Outlook',
  'MS Reference Specialty',
  'MS UI Gothic',
  'MT Extra',
  'MYRIAD PRO',
  'Marlett',
  'Meiryo UI',
  'Microsoft Uighur',
  'Minion Pro',
  'Monotype Corsiva',
  'PMingLiU',
  'Pristina',
  'SCRIPTINA',
  'Segoe UI Light',
  'Serifa',
  'SimHei',
  'Small Fonts',
  'Staccato222 BT',
  'TRAJAN PRO',
  'Univers CE 55 Medium',
  'Vrinda',
  'ZWAdobeF',
] as const;

/** Result of the FingerprintJS v5 font probe. */
export interface FontSignalsV5 {
  /** Installed fonts in FONTS_V5_FONT_LIST order (FPJS does not sort). */
  installedV5: string[];
  /** Hash of `installedV5` (stable for cross-session comparison only). */
  fontHashV5: string;
  error?: string;
}

/**
 * FPJS `withIframe`: a layout-capable (`display:block !important`) hidden
 * iframe. Unlike the legacy probe this is async so the iframe document is
 * fully loaded before any offsetWidth/offsetHeight read.
 */
async function withV5FontsIframe<T>(action: (doc: Document, body: HTMLElement) => T): Promise<T | null> {
  if (typeof document === 'undefined' || !document.body) return null;
  const iframe = document.createElement('iframe');
  try {
    await new Promise<void>((resolve, reject) => {
      iframe.onload = () => resolve();
      iframe.onerror = () => reject(new Error('v5 font iframe failed to load'));
      const style = iframe.style;
      style.setProperty('display', 'block', 'important'); // required for layout
      style.position = 'absolute';
      style.top = '0';
      style.left = '0';
      style.visibility = 'hidden';
      iframe.src = 'about:blank';
      document.body.appendChild(iframe);
    });
    const doc = iframe.contentDocument ?? iframe.contentWindow?.document ?? null;
    const body = doc?.body ?? null;
    if (!doc || !body) return null;
    return action(doc, body);
  } finally {
    try {
      iframe.remove();
    } catch {
      /* best effort */
    }
  }
}

/**
 * FingerprintJS v5 `getFonts()` as a PURE ADDITIVE helper.
 *
 * Differences from the legacy collector: 48px body font-size (not 72px on the
 * span), candidate family string `'${font}',${base}` (single quotes, no
 * space), the exact 52-name v5 list, and results preserved in fontList order.
 * A candidate is installed iff ANY base gives a different width OR height.
 */
export async function collectFontSignalsV5(): Promise<FontSignalsV5> {
  const result: FontSignalsV5 = { installedV5: [], fontHashV5: '' };
  try {
    const installed = await withV5FontsIframe((doc, holder) => {
      holder.style.fontSize = FONTS_V5_TEXT_SIZE;

      const spansContainer = doc.createElement('div');
      spansContainer.style.setProperty('visibility', 'hidden', 'important');

      const createSpan = (fontFamily: string): HTMLSpanElement => {
        const span = doc.createElement('span');
        const { style } = span;
        style.position = 'absolute';
        style.top = '0';
        style.left = '0';
        style.fontFamily = fontFamily;
        span.textContent = FONTS_V5_TEST_STRING;
        spansContainer.appendChild(span);
        return span;
      };

      const baseSpans = FONTS_V5_BASE_FONTS.map((base) => createSpan(base));
      const fontSpans: Record<string, HTMLSpanElement[]> = {};
      for (const font of FONTS_V5_FONT_LIST) {
        fontSpans[font] = FONTS_V5_BASE_FONTS.map((base) => createSpan(`'${font}',${base}`));
      }

      holder.appendChild(spansContainer);

      const defaultWidth: Record<string, number> = {};
      const defaultHeight: Record<string, number> = {};
      for (let index = 0; index < FONTS_V5_BASE_FONTS.length; index++) {
        defaultWidth[FONTS_V5_BASE_FONTS[index]] = baseSpans[index].offsetWidth;
        defaultHeight[FONTS_V5_BASE_FONTS[index]] = baseSpans[index].offsetHeight;
      }

      return FONTS_V5_FONT_LIST.filter((font) =>
        FONTS_V5_BASE_FONTS.some(
          (base, baseFontIndex) =>
            fontSpans[font][baseFontIndex].offsetWidth !== defaultWidth[base] ||
            fontSpans[font][baseFontIndex].offsetHeight !== defaultHeight[base]
        )
      );
    });
    if (!installed) {
      result.error = 'v5 font measurement iframe unavailable';
      return result;
    }
    result.installedV5 = [...installed];
    result.fontHashV5 = hashStrings(result.installedV5);
  } catch (err) {
    result.error = errorMessage(err);
  }
  return result;
}

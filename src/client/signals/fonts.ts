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

/**
 * Emoji probe — renders '😂' in an offscreen span and measures the layout
 * rect (the actual emoji font chosen by the engine — Apple Color Emoji,
 * Segoe UI Emoji, Noto Color Emoji... — changes the box, which is the
 * engine-bound entropy). The declared `font-family` stack is reported too.
 */

import { errorMessage } from './hash';
import type { EmojiSignals } from './types';

const EMOJI = '\u{1F602}'; // 😂
const EMOJI_FONT_STACK =
  "'Apple Color Emoji','Segoe UI Emoji','Noto Color Emoji','Twemoji Mozilla','EmojiOne Color','Android Emoji',sans-serif";

/** Total: always returns a payload. */
export function collectEmojiSignals(): EmojiSignals {
  const result: EmojiSignals = {
    font: null,
    width: null,
    height: null,
    top: null,
    bottom: null,
    left: null,
    right: null,
    x: null,
    y: null,
  };

  try {
    const parent = document.body ?? document.documentElement;
    if (!parent) {
      result.error = 'no document body to attach the emoji probe';
      return result;
    }

    const span = document.createElement('span');
    span.textContent = EMOJI;
    span.style.cssText =
      'position:absolute;left:-99999px;top:0;white-space:nowrap;margin:0;padding:0;' +
      'border:0;font-size:16px;line-height:normal;';
    span.style.fontFamily = EMOJI_FONT_STACK;
    parent.appendChild(span);

    try {
      result.font = window.getComputedStyle(span).fontFamily || null;
      const rect = span.getBoundingClientRect();
      result.width = Number.isFinite(rect.width) ? rect.width : null;
      result.height = Number.isFinite(rect.height) ? rect.height : null;
      result.top = Number.isFinite(rect.top) ? rect.top : null;
      result.bottom = Number.isFinite(rect.bottom) ? rect.bottom : null;
      result.left = Number.isFinite(rect.left) ? rect.left : null;
      result.right = Number.isFinite(rect.right) ? rect.right : null;
      result.x = Number.isFinite(rect.x) ? rect.x : null;
      result.y = Number.isFinite(rect.y) ? rect.y : null;
    } finally {
      try {
        span.remove();
      } catch {
        /* ignore */
      }
    }
  } catch (err) {
    result.error = errorMessage(err);
  }

  return result;
}

/* ---------------------------------------------------------------------------
 * Additive emoji shaping metrics.
 *
 * FingerprintJS v5 has no emoji source, so nothing here feeds the legacy
 * `emoji` rect probe or the browser digest. Instead this captures the engine's
 * emoji *shaper*: whether a multi-codepoint ZWJ family collapses to one glyph
 * (and how its width compares to the same codepoints written unjoined), plus
 * canvas `measureText` boxes for a spread of single / ZWJ / flag / VS16 emoji.
 * Both are read twice; disagreement is reported as noise rather than averaged.
 * ------------------------------------------------------------------------- */

/** Widths (32px, 3 decimals) used to detect ZWJ family composition. */
export interface EmojiCompositionMetrics {
  /** Single emoji '😂' — the unit from the legacy probe. */
  single: number | null;
  /** '👨‍👩‍👧‍👦' with U+200D joiners (one glyph when the shaper supports it). */
  familyJoined: number | null;
  /** '👨👩👧👦' — same codepoints, no joiners (always four glyphs). */
  familyUnjoined: number | null;
  /** familyJoined / single; ~4 means four separate glyphs, ~1 means joined. */
  joinedToSingle: number | null;
  /** familyJoined / familyUnjoined; <1 is direct evidence of ZWJ joining. */
  joinedToUnjoined: number | null;
}

/** Canvas `measureText` box for one emoji, 32px, rounded to 3 decimals. */
export interface EmojiTextMetrics {
  width: number | null;
  ascent: number | null;
  descent: number | null;
  left: number | null;
  right: number | null;
}

export interface EmojiExtrasSignals {
  zwj: EmojiCompositionMetrics;
  /** First pass, keyed by sample name. */
  textMetrics: Record<string, EmojiTextMetrics>;
  /** Second pass — identical to `textMetrics` on a stable engine. */
  textMetricsRepeat: Record<string, EmojiTextMetrics>;
  noise: {
    /** True when both passes produced identical metrics for every glyph. */
    stable: boolean;
    /** Sample names whose two passes differed. */
    unstableGlyphs: string[];
  };
  error?: string;
}

const ZWJ_SINGLE = EMOJI; // 😂
const ZWJ_FAMILY =
  '\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}'; // 👨‍👩‍👧‍👦
const ZWJ_FAMILY_UNJOINED = '\u{1F468}\u{1F469}\u{1F467}\u{1F466}'; // 👨👩👧👦

/** ~30 glyphs: singles, ZWJ sequences, regional flags and VS16 sequences. */
const EMOJI_TEXT_SAMPLES: ReadonlyArray<readonly [string, string]> = [
  ['grinning', '\u{1F600}'],
  ['smile', '\u{1F604}'],
  ['joy', '\u{1F602}'],
  ['heartEyes', '\u{1F60D}'],
  ['rofl', '\u{1F923}'],
  ['sob', '\u{1F62D}'],
  ['smileWithHearts', '\u{1F970}'],
  ['thinking', '\u{1F914}'],
  ['melting', '\u{1FAE0}'],
  ['saluting', '\u{1FAE1}'],
  ['heartHands', '\u{1FAF6}'],
  ['indexUp', '\u{1FAF5}'],
  ['adult', '\u{1F9D1}'],
  ['man', '\u{1F468}'],
  ['woman', '\u{1F469}'],
  ['girl', '\u{1F467}'],
  ['boy', '\u{1F466}'],
  ['baby', '\u{1F476}'],
  ['oldMan', '\u{1F474}'],
  ['oldWoman', '\u{1F475}'],
  ['rainbowFlag', '\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}'],
  ['transFlag', '\u{1F3F3}\u{FE0F}\u{200D}\u{26A7}\u{FE0F}'],
  ['flagUS', '\u{1F1FA}\u{1F1F8}'],
  ['flagGB', '\u{1F1EC}\u{1F1E7}'],
  ['soccer', '\u{26BD}'],
  ['party', '\u{1F389}'],
  ['rocket', '\u{1F680}'],
  ['redHeart', '\u{2764}\u{FE0F}'],
  ['sparkles', '\u{2728}'],
  ['technologist', '\u{1F9D1}\u{200D}\u{1F4BB}'],
];

function round3(value: number): number | null {
  return Number.isFinite(value) ? Math.round(value * 1000) / 1000 : null;
}

function measureSpanWidth(text: string): number | null {
  const parent = document.body ?? document.documentElement;
  if (!parent) return null;
  const span = document.createElement('span');
  span.textContent = text;
  span.style.cssText =
    'position:absolute;left:-99999px;top:0;white-space:nowrap;margin:0;padding:0;' +
    'border:0;font-size:32px;line-height:normal;';
  span.style.fontFamily = EMOJI_FONT_STACK;
  parent.appendChild(span);
  try {
    return round3(span.getBoundingClientRect().width);
  } finally {
    try {
      span.remove();
    } catch {
      /* ignore */
    }
  }
}

function readTextMetrics(ctx: CanvasRenderingContext2D, glyph: string): EmojiTextMetrics {
  const m = ctx.measureText(glyph);
  return {
    width: round3(m.width),
    ascent: round3(m.actualBoundingBoxAscent),
    descent: round3(m.actualBoundingBoxDescent),
    left: round3(m.actualBoundingBoxLeft),
    right: round3(m.actualBoundingBoxRight),
  };
}

function sameMetrics(a: EmojiTextMetrics, b: EmojiTextMetrics): boolean {
  return (
    a.width === b.width &&
    a.ascent === b.ascent &&
    a.descent === b.descent &&
    a.left === b.left &&
    a.right === b.right
  );
}

/** Total: never throws; always returns the additive payload with an `error` on failure. */
export function collectEmojiExtrasSignals(): EmojiExtrasSignals {
  const result: EmojiExtrasSignals = {
    zwj: {
      single: null,
      familyJoined: null,
      familyUnjoined: null,
      joinedToSingle: null,
      joinedToUnjoined: null,
    },
    textMetrics: {},
    textMetricsRepeat: {},
    noise: { stable: true, unstableGlyphs: [] },
  };

  try {
    try {
      const single = measureSpanWidth(ZWJ_SINGLE);
      const joined = measureSpanWidth(ZWJ_FAMILY);
      const unjoined = measureSpanWidth(ZWJ_FAMILY_UNJOINED);
      result.zwj.single = single;
      result.zwj.familyJoined = joined;
      result.zwj.familyUnjoined = unjoined;
      result.zwj.joinedToSingle = single && joined ? round3(joined / single) : null;
      result.zwj.joinedToUnjoined = unjoined && joined ? round3(joined / unjoined) : null;
    } catch (err) {
      result.error = errorMessage(err);
    }

    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      if (!ctx) throw new Error('2d context unavailable');
      ctx.font = `32px ${EMOJI_FONT_STACK}`;
      for (const [name, glyph] of EMOJI_TEXT_SAMPLES) {
        const first = readTextMetrics(ctx, glyph);
        const second = readTextMetrics(ctx, glyph);
        result.textMetrics[name] = first;
        result.textMetricsRepeat[name] = second;
        if (!sameMetrics(first, second)) result.noise.unstableGlyphs.push(name);
      }
      result.noise.stable = result.noise.unstableGlyphs.length === 0;
    } catch (err) {
      if (!result.error) result.error = errorMessage(err);
    }
  } catch (err) {
    if (!result.error) result.error = errorMessage(err);
  }

  return result;
}

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

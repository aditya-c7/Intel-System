/**
 * Audio fingerprint — OfflineAudioContext oscillator->compressor pipeline
 * (FingerprintJS algorithm, return-code protocol added):
 *
 *   context(1, 5000, 44100); triangle oscillator @ 10000 Hz; compressor with
 *   threshold -50, knee 40, ratio 12, attack 0, release 0.25; sum |sample|
 *   over frames 4500..4999 of channel 0.
 *
 * Codes: 0 = ok, -1 = legacy/suspended context, -2 = unsupported, -3 = the
 * render promise did not settle within 1.5 s. Also reports static node
 * ranges (AudioListener.forwardX.maxValue, BiquadFilterNode gain max,
 * compressor attack default, oscillator detune max) and AudioContext
 * baseLatency — all engine-bound values.
 */

import { errorMessage } from './hash';
import type { AudioSignals } from './types';

const RENDER_TIMEOUT_MS = 1500;
const FRAMES_START = 4500;
const FRAMES_END = 5000;

interface WindowWithLegacyAudio {
  OfflineAudioContext?: typeof OfflineAudioContext;
  webkitOfflineAudioContext?: typeof OfflineAudioContext;
}

interface LegacyRenderable {
  oncomplete: ((event: { renderedBuffer: AudioBuffer }) => void) | null;
}

function startRender(context: OfflineAudioContext): Promise<AudioBuffer> {
  return new Promise<AudioBuffer>((resolve, reject) => {
    let settled = false;
    const settle = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      fn();
    };
    try {
      const maybePromise = context.startRendering() as unknown;
      if (maybePromise && typeof (maybePromise as Promise<AudioBuffer>).then === 'function') {
        (maybePromise as Promise<AudioBuffer>).then(
          (buffer) => settle(() => resolve(buffer)),
          (error: unknown) => settle(() => reject(error instanceof Error ? error : new Error(String(error))))
        );
      } else {
        // Legacy WebKit startRendering(): results arrive via oncomplete.
        (context as unknown as LegacyRenderable).oncomplete = (event) =>
          settle(() => resolve(event.renderedBuffer));
      }
    } catch (error) {
      settle(() => reject(error instanceof Error ? error : new Error(String(error))));
    }
  });
}

function readNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/**
 * AudioContext baseLatency — requires a real (non-offline) context. May be
 * suspended without a user gesture; baseLatency is still reported. The
 * context is closed immediately after the read.
 */
export async function collectAudioBaseLatency(): Promise<number | null> {
  try {
    const AudioCtor = window.AudioContext;
    if (!AudioCtor) return null;
    const context = new AudioCtor();
    const latency = readNumber(context.baseLatency);
    try {
      void context.close();
    } catch {
      /* ignore */
    }
    return latency;
  } catch {
    return null;
  }
}

/** Total: always returns a payload. */
export async function collectAudioSignals(): Promise<AudioSignals> {
  const result: AudioSignals = {
    sum: null,
    code: -2,
    audioBaseLatency: null,
    listenerForwardXMaxValue: null,
    biquadGainMaxValue: null,
    compressorAttackDefault: null,
    oscillatorDetuneMax: null,
  };

  try {
    const scope = window as unknown as WindowWithLegacyAudio;
    const OfflineCtor = scope.OfflineAudioContext ?? scope.webkitOfflineAudioContext;
    if (!OfflineCtor) {
      result.error = 'OfflineAudioContext unsupported';
      return result;
    }

    let context: OfflineAudioContext | null = null;
    try {
      context = new OfflineCtor(1, FRAMES_END, 44100);
    } catch {
      context = null;
    }
    if (!context) {
      result.error = 'could not create OfflineAudioContext';
      return result;
    }

    // -1: legacy/suspended context state (rendering is still attempted).
    if (context.state === 'suspended') result.code = -1;

    try {
      const oscillator = context.createOscillator();
      oscillator.type = 'triangle';
      oscillator.frequency.value = 10000;

      const compressor = context.createDynamicsCompressor();
      compressor.threshold.value = -50;
      compressor.knee.value = 40;
      compressor.ratio.value = 12;
      compressor.attack.value = 0;
      compressor.release.value = 0.25;

      oscillator.connect(compressor);
      compressor.connect(context.destination);
      oscillator.start(0);

      // Static node ranges (read alongside the pipeline).
      try {
        const listener = context.listener as unknown as { forwardX?: { maxValue?: number } };
        result.listenerForwardXMaxValue = readNumber(listener?.forwardX?.maxValue);
      } catch {
        /* ignore */
      }
      try {
        result.biquadGainMaxValue = readNumber(context.createBiquadFilter().gain.maxValue);
      } catch {
        /* ignore */
      }
      try {
        result.compressorAttackDefault = readNumber(compressor.attack.defaultValue);
      } catch {
        /* ignore */
      }
      try {
        result.oscillatorDetuneMax = readNumber(oscillator.detune.maxValue);
      } catch {
        /* ignore */
      }

      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const rendered = await Promise.race([
          startRender(context),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error('render timeout')), RENDER_TIMEOUT_MS);
          }),
        ]);
        const buffer = rendered as AudioBuffer;
        const data = buffer.getChannelData(0);
        let accumulated = 0;
        for (let i = FRAMES_START; i < FRAMES_END; i++) accumulated += Math.abs(data[i]);
        if (!Number.isFinite(accumulated)) {
          result.code = -2;
          result.error = 'non-finite audio sum';
          return result;
        }
        result.sum = accumulated;
        if (result.code !== -1) result.code = 0;
      } catch (err) {
        if (errorMessage(err) === 'render timeout') {
          result.code = -3;
          result.error = 'audio render timeout';
        } else {
          result.code = -2;
          result.error = errorMessage(err);
        }
        return result;
      } finally {
        if (timer) clearTimeout(timer);
      }
    } finally {
      // OfflineAudioContext releases itself after rendering; close() is an
      // AudioContext-only API and must not be called here.
    }
  } catch (err) {
    result.code = -2;
    result.error = errorMessage(err);
  }

  return result;
}

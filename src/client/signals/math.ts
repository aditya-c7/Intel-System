/**
 * Math engine fingerprint — 24 deterministic float probes (16 native + 8
 * deliberately naive polyfills, matching the FingerprintJS definitions).
 * Different engines / libm versions round these differently, which is the
 * entropy; the polyfills' *inaccuracy* is intentional and stable per engine.
 *
 * Also collects the error-stack engine shape: own property names of Error /
 * RangeError / SyntaxError / TypeError instances, a DOMException, and an
 * error thrown from an async function (V8/JavaScriptCore/SpiderMonkey each
 * expose a different set, e.g. Firefox adds fileName/lineNumber/columnNumber).
 */

import { stableHash32, stableStringify, hashStrings, errorMessage } from './hash';
import type { MathSignals } from './types';

// FingerprintJS-standard polyfill implementations (intentionally naive).
const acoshPf = (x: number): number => Math.log(x + Math.sqrt(x * x - 1));
const asinhPf = (x: number): number => Math.log(x + Math.sqrt(x * x + 1));
const atanhPf = (x: number): number => Math.log((1 + x) / (1 - x)) / 2;
const sinhPf = (x: number): number => Math.exp(x) - 1 / Math.exp(x);
const coshPf = (x: number): number => (Math.exp(x) + Math.exp(-x)) / 2;
const expm1Pf = (x: number): number => Math.exp(x) - 1 / Math.exp(x);
const tanhPf = (x: number): number => (Math.exp(2 * x) - 1) / (Math.exp(2 * x) + 1);
const log1pPf = (x: number): number => Math.log(1 + x);

function collectMathValues(): Record<string, string> {
  const values: Record<string, string> = {
    acos: String(Math.acos(0.123124234234234242)),
    acosh: String(Math.acosh(1e308)),
    acoshPf: String(acoshPf(1e308)),
    asin: String(Math.asin(0.123124234234234242)),
    asinh: String(Math.asinh(1)),
    asinhPf: String(asinhPf(1)),
    atan: String(Math.atan(2)),
    atanh: String(Math.atanh(0.5)),
    atanhPf: String(atanhPf(0.5)),
    cos: String(Math.cos(10.000000000123)),
    cosh: String(Math.cosh(1)),
    coshPf: String(coshPf(1)),
    exp: String(Math.exp(1)),
    expm1: String(Math.expm1(1)),
    expm1Pf: String(expm1Pf(1)),
    log1p: String(Math.log1p(10)),
    log1pPf: String(log1pPf(10)),
    pow: String(Math.pow(Math.PI, -100)),
    sin: String(Math.sin(-1e300)),
    sinh: String(Math.sinh(1)),
    sinhPf: String(sinhPf(1)),
    tan: String(Math.tan(-1e300)),
    tanh: String(Math.tanh(1)),
    tanhPf: String(tanhPf(1)),
  };
  return values;
}

function addOwnPropertyNames(target: Set<string>, error: unknown): void {
  try {
    if (!error || typeof error !== 'object') return;
    for (const name of Object.getOwnPropertyNames(error)) target.add(name);
  } catch {
    /* ignore */
  }
}

async function getThrownAsyncError(): Promise<unknown> {
  try {
    await (async () => {
      throw new Error('async stack probe');
    })();
    return null;
  } catch (error) {
    return error;
  }
}

async function collectErrorStackFunctions(): Promise<string[]> {
  const names = new Set<string>();
  addOwnPropertyNames(names, new Error('probe'));
  addOwnPropertyNames(names, new RangeError('probe'));
  addOwnPropertyNames(names, new SyntaxError('probe'));
  addOwnPropertyNames(names, new TypeError('probe'));
  try {
    addOwnPropertyNames(names, new DOMException('probe', 'DataCloneError'));
  } catch {
    /* older engines */
  }
  const asyncError = await getThrownAsyncError();
  if (asyncError) addOwnPropertyNames(names, asyncError);
  return Array.from(names).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** Total (async): always returns a payload. */
export async function collectMathSignals(): Promise<MathSignals> {
  const result: MathSignals = {
    values: {},
    mathHash: '',
    errorStackFunctions: [],
    errorStackHash: '',
  };

  try {
    try {
      result.values = collectMathValues();
      result.mathHash = stableHash32(stableStringify(result.values));
    } catch (err) {
      if (!result.error) result.error = errorMessage(err);
    }

    try {
      result.errorStackFunctions = await collectErrorStackFunctions();
      result.errorStackHash = hashStrings(result.errorStackFunctions);
    } catch (err) {
      if (!result.error) result.error = errorMessage(err);
    }
  } catch (err) {
    result.error = errorMessage(err);
  }

  // Additive v5 probe set. It is deliberately NOT written into `values`,
  // `mathHash`, `errorStackFunctions` or `errorStackHash`, so the browser
  // digest (which selects only `values` + `errorStackHash`) is byte-identical.
  try {
    (result as MathSignals & { mathV5?: MathV5Signals }).mathV5 = collectMathV5Signals();
  } catch {
    /* additive field must never poison the legacy payload */
  }

  return result;
}

/* ---------------------------------------------------------------------------
 * FingerprintJS v5 `src/sources/math.ts` — exact 24-probe reproduction.
 *
 * The legacy collector above uses alphabetised keys, stringified outputs and
 * several inputs/formulas that differ from v5: `acoshPf(1e308)` (v5 uses
 * 1e154), `atan(2)` (v5 uses 0.5), the `pow` key (v5 calls it `powPI` and puts
 * it last), and the sinhPf / coshPf / expm1Pf polyfills. This additive slice
 * reproduces the v5 declaration order and formulas verbatim, including the
 * `() => 0` native fallbacks, without touching the digest-bearing fields.
 * ------------------------------------------------------------------------- */

const M = Math;
const fallbackFn: (value: number) => number = () => 0;

/** The 24 v5 probes as raw numbers, in FingerprintJS v5 declaration order. */
export function getMathV5Values(): Record<string, number> {
  // Native operations (v5 falls back to zero if one is missing).
  const acos = M.acos || fallbackFn;
  const acosh = M.acosh || fallbackFn;
  const asin = M.asin || fallbackFn;
  const asinh = M.asinh || fallbackFn;
  const atanh = M.atanh || fallbackFn;
  const atan = M.atan || fallbackFn;
  const sin = M.sin || fallbackFn;
  const sinh = M.sinh || fallbackFn;
  const cos = M.cos || fallbackFn;
  const cosh = M.cosh || fallbackFn;
  const tan = M.tan || fallbackFn;
  const tanh = M.tanh || fallbackFn;
  const exp = M.exp || fallbackFn;
  const expm1 = M.expm1 || fallbackFn;
  const log1p = M.log1p || fallbackFn;

  // v5 polyfills — intentionally naive and reproduced exactly.
  const powPI = (value: number): number => M.pow(M.PI, value);
  const acoshPf = (value: number): number => M.log(value + M.sqrt(value * value - 1));
  const asinhPf = (value: number): number => M.log(value + M.sqrt(value * value + 1));
  const atanhPf = (value: number): number => M.log((1 + value) / (1 - value)) / 2;
  // v5 precedence is `exp(x) - (1 / exp(x)) / 2`; do not "fix" it.
  const sinhPf = (value: number): number => M.exp(value) - 1 / M.exp(value) / 2;
  const coshPf = (value: number): number => (M.exp(value) + 1 / M.exp(value)) / 2;
  const expm1Pf = (value: number): number => M.exp(value) - 1;
  const tanhPf = (value: number): number => (M.exp(2 * value) - 1) / (M.exp(2 * value) + 1);
  const log1pPf = (value: number): number => M.log(1 + value);

  return {
    acos: acos(0.123124234234234242),
    acosh: acosh(1e308),
    acoshPf: acoshPf(1e154), // 1e308 will not work for the polyfill
    asin: asin(0.123124234234234242),
    asinh: asinh(1),
    asinhPf: asinhPf(1),
    atanh: atanh(0.5),
    atanhPf: atanhPf(0.5),
    atan: atan(0.5),
    sin: sin(-1e300),
    sinh: sinh(1),
    sinhPf: sinhPf(1),
    cos: cos(10.000000000123),
    cosh: cosh(1),
    coshPf: coshPf(1),
    tan: tan(-1e300),
    tanh: tanh(1),
    tanhPf: tanhPf(1),
    exp: exp(1),
    expm1: expm1(1),
    expm1Pf: expm1Pf(1),
    log1p: log1p(10),
    log1pPf: log1pPf(10),
    powPI: powPI(-100),
  };
}

export interface MathV5Signals {
  /** 24 raw values in v5 key order (not stringified like legacy `values`). */
  valuesV5: Record<string, number>;
  /** Additive digest; never replaces `mathHash`. */
  mathHashV5: string;
  error?: string;
}

/** Total: the additive v5 probe set, independent of the legacy result. */
export function collectMathV5Signals(): MathV5Signals {
  const result: MathV5Signals = { valuesV5: {}, mathHashV5: '' };
  try {
    result.valuesV5 = getMathV5Values();
    result.mathHashV5 = stableHash32(stableStringify(result.valuesV5));
  } catch (err) {
    result.error = errorMessage(err);
  }
  return result;
}

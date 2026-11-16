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

  return result;
}

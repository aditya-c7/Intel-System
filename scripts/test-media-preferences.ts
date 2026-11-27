/**
 * Regression suite for src/lib/mediaPreferences.ts (SHADOW-ONLY additive helper).
 *
 * Pins the documented invariants:
 *  - the record is additive and strictly informational: it has exactly the nine nullable
 *    preference fields plus `notes`, and no verdict / anti-detect / identity-hash field;
 *  - booleans accept only literal true/false; CSS values normalize to a canonical vocabulary;
 *    locale and timezone use the repo's canonical normalizers;
 *  - hostile getters, proxies, boxed values and primitives degrade to null per field WITHOUT
 *    throwing and without hiding the remaining readable fields;
 *  - the resolver is pure and deterministic: input is untouched and repeated calls agree.
 *
 *   npx tsx scripts/test-media-preferences.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 */

import assert from 'node:assert/strict';

import {
  resolveMediaPreferences,
  MEDIA_PREFERENCES_INFORMATIONAL_NOTE,
  type MediaPreferencesInput,
  type MediaPreferencesResult,
} from '../src/lib/mediaPreferences';

/* -------------------------------------------------------------------------- */
/* Reporting                                                                   */
/* -------------------------------------------------------------------------- */

let passed = 0;
let failed = 0;

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function check(id: string, label: string, body: () => void): void {
  try {
    body();
    passed += 1;
    console.log(`PASS  [${id}] ${label}`);
  } catch (error) {
    failed += 1;
    console.error(`FAIL  [${id}] ${label}\n      ${describeError(error)}`);
  }
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

/** Object whose every property read throws: proves totality on hostile input. */
function hostileInput(): MediaPreferencesInput {
  return new Proxy(
    {},
    {
      get(): never {
        throw new Error('hostile getter');
      },
    },
  ) as MediaPreferencesInput;
}

/** A value that cannot be safely stringified, to prove we never call toString on raw input. */
function unstringifiable(): { toString(): never } {
  return {
    toString(): never {
      throw new Error('hostile toString');
    },
  };
}

const EXPECTED_KEYS = [
  'forced_colors',
  'reduced_motion',
  'reduced_transparency',
  'monochrome',
  'inverted_colors',
  'color_scheme',
  'contrast',
  'locale',
  'timezone',
  'notes',
];

function defaultRecord(): MediaPreferencesResult {
  return {
    forced_colors: null,
    reduced_motion: null,
    reduced_transparency: null,
    monochrome: null,
    inverted_colors: null,
    color_scheme: null,
    contrast: null,
    locale: null,
    timezone: null,
    notes: [MEDIA_PREFERENCES_INFORMATIONAL_NOTE],
  };
}

/* -------------------------------------------------------------------------- */

function run(): void {
  check('setup', 'resolveMediaPreferences is exported as a function', () => {
    assert.equal(typeof resolveMediaPreferences, 'function');
    assert.equal(typeof MEDIA_PREFERENCES_INFORMATIONAL_NOTE, 'string');
  });

  section('A. Shape and defaults');

  check('A1', 'empty input yields exactly the additive nullable record plus the info note', () => {
    const result = resolveMediaPreferences({});
    assert.deepEqual(Object.keys(result), EXPECTED_KEYS);
    assert.deepEqual(result, defaultRecord());
  });

  check('A2', 'null / undefined / primitives / arrays / functions all yield safe defaults', () => {
    const inputs: unknown[] = [null, undefined, 7, 'x', true, [], () => 1];
    for (const input of inputs) {
      assert.doesNotThrow(() => {
        const result = resolveMediaPreferences(input as MediaPreferencesInput);
        assert.deepEqual(result, defaultRecord(), `input=${String(input)}`);
      });
    }
  });

  section('B. Boolean media features');

  check('B1', 'literal booleans are carried through, including an explicit false', () => {
    const result = resolveMediaPreferences({
      forcedColors: true,
      reducedMotion: false,
      reducedTransparency: true,
      monochrome: false,
      invertedColors: true,
    });
    assert.equal(result.forced_colors, true);
    assert.equal(result.reduced_motion, false);
    assert.equal(result.reduced_transparency, true);
    assert.equal(result.monochrome, false);
    assert.equal(result.inverted_colors, true);
    assert.deepEqual(result.notes, [MEDIA_PREFERENCES_INFORMATIONAL_NOTE]);
  });

  check('B2', 'truthy junk and boxed values never become booleans', () => {
    for (const value of [1, 0, 'true', 'false', {}, [], unstringifiable()]) {
      const result = resolveMediaPreferences({
        forcedColors: value as unknown as boolean,
        reducedMotion: value as unknown as boolean,
        reducedTransparency: value as unknown as boolean,
      });
      assert.equal(result.forced_colors, null);
      assert.equal(result.reduced_motion, null);
      assert.equal(result.reduced_transparency, null);
      assert.equal(result.notes.length, 4, 'three rejection notes plus the info note');
    }
  });

  check('B3', '(monochrome: 0) / (inverted-colors) reads store the raw match verbatim', () => {
    // The '(monochrome: 0)' match is the INVERSE monochrome read: true = color display,
    // false = monochrome display. The resolver stores the raw query answer, it never
    // flips polarity, and absence stays null without a note.
    assert.equal(resolveMediaPreferences({ monochrome: true }).monochrome, true);
    assert.equal(resolveMediaPreferences({ monochrome: false }).monochrome, false);
    assert.equal(resolveMediaPreferences({ invertedColors: true }).inverted_colors, true);
    assert.equal(resolveMediaPreferences({ invertedColors: false }).inverted_colors, false);
    const absent = resolveMediaPreferences({});
    assert.equal(absent.monochrome, null);
    assert.equal(absent.inverted_colors, null);
    assert.ok(!absent.notes.some((n) => n.includes('monochrome')));
    assert.ok(!absent.notes.some((n) => n.includes('invertedColors')));
    // Junk never becomes a boolean and is reported, not propagated.
    for (const value of [1, 'true', {}, null]) {
      const result = resolveMediaPreferences({
        monochrome: value as unknown as boolean,
        invertedColors: value as unknown as boolean,
      });
      assert.equal(result.monochrome, null, `monochrome=${String(value)}`);
      assert.equal(result.inverted_colors, null, `invertedColors=${String(value)}`);
    }
    const junky = resolveMediaPreferences({ monochrome: 1, invertedColors: 'false' } as unknown as MediaPreferencesInput);
    assert.ok(junky.notes.some((n) => n.includes('monochrome: expected a boolean')));
    assert.ok(junky.notes.some((n) => n.includes('invertedColors: expected a boolean')));
  });

  section('C. prefers-color-scheme');

  check('C1', 'color scheme is trimmed and lowercased to its canonical value', () => {
    const result = resolveMediaPreferences({ colorScheme: '  DARK ' });
    assert.equal(result.color_scheme, 'dark');
    assert.ok(result.notes.some((n) => n.includes('colorScheme: normalized to dark')));
  });

  check('C2', 'legacy normal alias maps to no-preference', () => {
    const result = resolveMediaPreferences({ colorScheme: 'Normal' });
    assert.equal(result.color_scheme, 'no-preference');
    assert.ok(result.notes.some((n) => n.includes('colorScheme: normalized to no-preference')));
  });

  check('C3', 'an unrecognised color scheme is rejected with a note', () => {
    const result = resolveMediaPreferences({ colorScheme: 'ultra-violet' });
    assert.equal(result.color_scheme, null);
    assert.ok(result.notes.some((n) => n.includes('colorScheme: unrecognised value ignored')));
  });

  check('C4', 'non-string / empty color scheme values are rejected without throwing', () => {
    for (const value of [42, {}, true, '   ']) {
      let result: MediaPreferencesResult | undefined;
      assert.doesNotThrow(() => {
        result = resolveMediaPreferences({ colorScheme: value as unknown as string });
      });
      assert.equal(result?.color_scheme, null);
      assert.ok((result?.notes.length ?? 0) > 1);
    }
  });

  section('D. prefers-contrast');

  check('D1', 'all canonical contrast values round-trip', () => {
    for (const value of ['no-preference', 'more', 'less', 'forced']) {
      const result = resolveMediaPreferences({ contrast: value });
      assert.equal(result.contrast, value);
      assert.deepEqual(result.notes, [MEDIA_PREFERENCES_INFORMATIONAL_NOTE]);
    }
  });

  check('D2', 'legacy high / low / normal contrast aliases map to canonical values', () => {
    assert.equal(resolveMediaPreferences({ contrast: 'HIGH' }).contrast, 'more');
    assert.equal(resolveMediaPreferences({ contrast: 'low' }).contrast, 'less');
    assert.equal(resolveMediaPreferences({ contrast: 'normal' }).contrast, 'no-preference');
  });

  check('D3', 'an unrecognised contrast value is rejected with a note', () => {
    const result = resolveMediaPreferences({ contrast: 'sparkly' });
    assert.equal(result.contrast, null);
    assert.ok(result.notes.some((n) => n.includes('contrast: unrecognised value ignored')));
  });

  section('E. Locale');

  check('E1', 'locale underscores and casing are normalized to a BCP-47 shape', () => {
    const result = resolveMediaPreferences({ locale: 'en_us' });
    assert.equal(result.locale, 'en-US');
    assert.ok(result.notes.some((n) => n.includes('locale: normalized to en-US')));
  });

  check('E2', 'script and region subtags are preserved and correctly cased', () => {
    assert.equal(resolveMediaPreferences({ locale: 'zh-Hant-TW' }).locale, 'zh-Hant-TW');
    assert.equal(resolveMediaPreferences({ locale: 'en-US-u-ca-gregory' }).locale, 'en-US-u-ca-gregory');
  });

  check('E3', 'junk locales and embedded control characters are rejected', () => {
    for (const value of ['not a locale!', 'a', 'en\u0000US', 'x'.repeat(80)]) {
      const result = resolveMediaPreferences({ locale: value });
      assert.equal(result.locale, null, `locale=${value}`);
      assert.ok(result.notes.some((n) => n.includes('locale: unrecognised value ignored')));
    }
  });

  section('F. Timezone');

  check('F1', 'legacy IANA aliases fold to the canonical zone through the shared resolver', () => {
    const result = resolveMediaPreferences({ timezone: 'Asia/Calcutta' });
    assert.equal(result.timezone, 'Asia/Kolkata');
    assert.ok(result.notes.some((n) => n.includes('timezone: normalized to Asia/Kolkata')));
  });

  check('F2', 'an already-canonical timezone is preserved without a normalization note', () => {
    const result = resolveMediaPreferences({ timezone: 'UTC' });
    assert.equal(result.timezone, 'UTC');
    assert.deepEqual(result.notes, [MEDIA_PREFERENCES_INFORMATIONAL_NOTE]);
  });

  check('F3', 'an unknown timezone is rejected with a note', () => {
    const result = resolveMediaPreferences({ timezone: 'Mars/Olympus' });
    assert.equal(result.timezone, null);
    assert.ok(result.notes.some((n) => n.includes('timezone: unrecognised value ignored')));
  });

  check('F4', 'non-string timezone values are rejected without throwing', () => {
    const result = resolveMediaPreferences({ timezone: 123 as unknown as string });
    assert.equal(result.timezone, null);
    assert.ok(result.notes.some((n) => n.includes('timezone: expected a string')));
  });

  section('G. Fully populated record');

  check('G1', 'a complete observation resolves every field deterministically', () => {
    const input: MediaPreferencesInput = {
      forcedColors: false,
      reducedMotion: true,
      reducedTransparency: false,
      monochrome: false,
      invertedColors: false,
      colorScheme: 'dark',
      contrast: 'more',
      locale: 'en-GB',
      timezone: 'Europe/London',
    };
    const result = resolveMediaPreferences(input);
    assert.equal(result.forced_colors, false);
    assert.equal(result.reduced_motion, true);
    assert.equal(result.reduced_transparency, false);
    assert.equal(result.monochrome, false);
    assert.equal(result.inverted_colors, false);
    assert.equal(result.color_scheme, 'dark');
    assert.equal(result.contrast, 'more');
    assert.equal(result.locale, 'en-GB');
    assert.equal(result.timezone, 'Europe/London');
    assert.deepEqual(result.notes, [MEDIA_PREFERENCES_INFORMATIONAL_NOTE]);
  });

  section('H. Hostile input');

  check('H1', 'an all-getters-throw proxy never throws and degrades every field to null', () => {
    let result: MediaPreferencesResult | undefined;
    assert.doesNotThrow(() => {
      result = resolveMediaPreferences(hostileInput());
    });
    assert.deepEqual(Object.keys(result ?? {}), EXPECTED_KEYS);
    for (const key of EXPECTED_KEYS) {
      if (key === 'notes') continue;
      assert.equal((result as unknown as Record<string, unknown>)[key], null, `field ${key}`);
    }
    assert.equal(result?.notes.length, 10, 'nine unreadable-field notes plus the info note');
    assert.ok(result?.notes.every((n) => n.includes('unreadable field ignored') || n === MEDIA_PREFERENCES_INFORMATIONAL_NOTE));
  });

  check('H2', 'one hostile getter does not hide the readable fields', () => {
    const input = {
      get forcedColors(): boolean {
        throw new Error('hostile forcedColors');
      },
      reducedMotion: true,
      get colorScheme(): string {
        throw new Error('hostile colorScheme');
      },
      contrast: 'less',
      get locale(): string {
        throw new Error('hostile locale');
      },
      timezone: 'UTC',
    };
    let result: MediaPreferencesResult | undefined;
    assert.doesNotThrow(() => {
      result = resolveMediaPreferences(input);
    });
    assert.equal(result?.reduced_motion, true);
    assert.equal(result?.contrast, 'less');
    assert.equal(result?.timezone, 'UTC');
    assert.equal(result?.forced_colors, null);
    assert.equal(result?.color_scheme, null);
    assert.equal(result?.locale, null);
    assert.ok(result?.notes.some((n) => n.includes('forcedColors: unreadable field ignored')));
    assert.ok(result?.notes.some((n) => n.includes('colorScheme: unreadable field ignored')));
    assert.ok(result?.notes.some((n) => n.includes('locale: unreadable field ignored')));
  });

  check('H3', 'hostile toString values are never invoked by the resolver', () => {
    const boom = unstringifiable();
    let result: MediaPreferencesResult | undefined;
    assert.doesNotThrow(() => {
      result = resolveMediaPreferences({
        forcedColors: boom as unknown as boolean,
        colorScheme: boom as unknown as string,
        contrast: boom as unknown as string,
        locale: boom as unknown as string,
        timezone: boom as unknown as string,
      });
    });
    assert.equal(result?.forced_colors, null);
    assert.equal(result?.color_scheme, null);
    assert.equal(result?.contrast, null);
    assert.equal(result?.locale, null);
    assert.equal(result?.timezone, null);
  });

  section('I. Informational-only contract, purity and determinism');

  check('I1', 'record carries no verdict, anti-detect, score or identity-hash field', () => {
    const result = resolveMediaPreferences({ colorScheme: 'dark', reducedMotion: true });
    for (const forbidden of [
      'anti_detect_browser',
      'bot',
      'verdict',
      'verdict_tier',
      'risk',
      'score',
      'identity_hash',
    ]) {
      assert.equal(Object.prototype.hasOwnProperty.call(result, forbidden), false, `field ${forbidden}`);
      assert.equal(forbidden in result, false, `field ${forbidden} in prototype chain`);
    }
    assert.equal(
      result.notes[result.notes.length - 1],
      MEDIA_PREFERENCES_INFORMATIONAL_NOTE,
    );
    assert.ok(MEDIA_PREFERENCES_INFORMATIONAL_NOTE.includes('Informational only'));
  });

  check('I2', 'resolver does not mutate its input', () => {
    const input: MediaPreferencesInput = {
      forcedColors: true,
      colorScheme: '  Dark ',
      contrast: 'high',
      locale: 'en_us',
      timezone: 'Asia/Calcutta',
    };
    const before = JSON.stringify(input);
    resolveMediaPreferences(input);
    assert.equal(JSON.stringify(input), before, 'input object must be untouched');
    assert.deepEqual(Object.keys(input), ['forcedColors', 'colorScheme', 'contrast', 'locale', 'timezone']);
  });

  check('I3', 'repeated calls on the same input return the same record', () => {
    const input: MediaPreferencesInput = {
      reducedMotion: true,
      colorScheme: 'DARK',
      contrast: 'HIGH',
      locale: 'EN_us',
      timezone: 'asia/calcutta',
    };
    assert.deepEqual(resolveMediaPreferences(input), resolveMediaPreferences(input));
  });
}

/* -------------------------------------------------------------------------- */

let runFailed = false;
try {
  run();
} catch (error) {
  // Absolute last-resort guard: even a catastrophic failure is reported, not thrown.
  runFailed = true;
  console.error(`FAIL  [fatal] unexpected error: ${describeError(error)}`);
} finally {
  const failedTotal = failed + (runFailed ? 1 : 0);
  if (failedTotal === 0) {
    console.log(`\nRESULT: PASS — ${passed} passed, 0 failed`);
  } else {
    console.log(`\nRESULT: FAIL — ${passed} passed, ${failedTotal} failed`);
    process.exitCode = 1;
  }
}

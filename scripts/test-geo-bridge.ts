/**
 * Regression suite for src/lib/geoProximityBridge.ts (permission-gated bridge).
 *
 * Pins the documented invariants:
 *  - permission must be EXACTLY 'granted'; denied / prompt / coerced => null
 *  - granted fix needs finite lat/lon and accuracyM > 0, else `invalid_fix`
 *  - ipCity is NEVER consulted (structural + behavioral no-IP guarantee)
 *  - confidence is derived from accuracy only; coordinates affect only the id
 *  - hostile input (throwing getters, proxies, symbols, primitives) never throws
 *  - the additive API v4 `hex_proximity` field is emitted only for a fixed result
 *
 *   npx tsx scripts/test-geo-bridge.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 * The whole run is wrapped so no assertion/import error ever escapes uncaught.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  REASON_INVALID_FIX,
  REASON_OK,
  REASON_PERMISSION_REQUIRED,
  proximityBodyField,
  resolveProximity,
  type ResolveProximityInput,
  type ResolveProximityResult,
} from '../src/lib/geoProximityBridge';

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

const ID_PATTERN = /^hex_[0-9a-f]{32}$/;

function fix(
  overrides: Partial<ResolveProximityInput> = {},
  permission: unknown = 'granted'
): ResolveProximityInput {
  return {
    permission,
    lat: 52.37,
    lon: 4.89,
    accuracyM: 12,
    ...overrides,
  };
}

function resultOf(input: ResolveProximityInput | null | undefined): ResolveProximityResult {
  return resolveProximity(input);
}

function proxOf(input: ResolveProximityInput) {
  return resolveProximity(input).proximity;
}

/* -------------------------------------------------------------------------- */

function run(): void {
  section('0. Exports & source-shape guarantees');

  check('S1', 'both functions and all three reason tokens are exported', () => {
    assert.equal(typeof resolveProximity, 'function');
    assert.equal(typeof proximityBodyField, 'function');
    assert.equal(typeof REASON_PERMISSION_REQUIRED, 'string');
    assert.equal(typeof REASON_INVALID_FIX, 'string');
    assert.equal(typeof REASON_OK, 'string');
  });

  check('S2', 'failure reason tokens have the exact required values', () => {
    assert.equal(REASON_PERMISSION_REQUIRED, 'permission_required');
    assert.equal(REASON_INVALID_FIX, 'invalid_fix');
    assert.equal(REASON_OK, 'ok');
  });

  check('S3', 'bridge imports only hexProximity — no network / geohash modules', () => {
    const source = readFileSync(new URL('../src/lib/geoProximityBridge.ts', import.meta.url), 'utf8');
    const imports = source.split('\n').filter((line) => line.trimStart().startsWith('import'));
    assert.ok(imports.length > 0);
    for (const line of imports) {
      assert.ok(!/geohash|\bhttp\b|node:https|node:dns|\bfetch\b|XMLHttpRequest|geoip/i.test(line), line);
    }
    assert.match(source, /from '\.\/hexProximity'/);
  });

  check('S4', 'resolveProximity body never references ipCity (structural no-IP proof)', () => {
    const source = readFileSync(new URL('../src/lib/geoProximityBridge.ts', import.meta.url), 'utf8');
    const start = source.indexOf('export function resolveProximity');
    const end = source.indexOf('export function proximityBodyField');
    assert.ok(start >= 0 && end > start);
    const body = source.slice(start, end);
    assert.ok(!body.includes('ipCity'), 'resolveProximity must never read ipCity');
    assert.match(body, /proximityFromGeolocation\(/, 'only the browser-fix delegate may produce proximity');
  });

  section('A. Permission gate (denied / prompt / coerced)');

  check('A1', 'null input -> permission_required + null proximity', () => {
    const result = resultOf(null);
    assert.equal(result.proximity, null);
    assert.equal(result.reason, REASON_PERMISSION_REQUIRED);
  });

  check('A2', 'undefined input -> permission_required', () => {
    const result = resultOf(undefined);
    assert.equal(result.proximity, null);
    assert.equal(result.reason, REASON_PERMISSION_REQUIRED);
  });

  check('A3', 'primitive inputs (string / number / symbol / boolean / function) -> permission_required, no throw', () => {
    const hostile: unknown[] = ['granted', 42, Symbol('geo'), true, () => 'granted'];
    for (const value of hostile) {
      let result: ResolveProximityResult | undefined;
      assert.doesNotThrow(() => {
        result = resultOf(value as ResolveProximityInput);
      });
      assert.equal(result?.proximity, null, `input=${String(value)}`);
      assert.equal(result?.reason, REASON_PERMISSION_REQUIRED);
    }
  });

  check('A4', 'explicitly denied permission -> permission_required even with a valid fix', () => {
    const result = resultOf(fix({}, 'denied'));
    assert.equal(result.proximity, null);
    assert.equal(result.reason, REASON_PERMISSION_REQUIRED);
  });

  check('A5', 'prompt permission -> permission_required even with a valid fix', () => {
    const result = resultOf(fix({}, 'prompt'));
    assert.equal(result.proximity, null);
    assert.equal(result.reason, REASON_PERMISSION_REQUIRED);
  });

  check('A6', 'permission must be EXACTLY granted (no case fold / trim / coercion)', () => {
    for (const state of ['GRANTED', 'Granted', 'granted ', ' granted', 'allow', '1', '', new String('granted')]) {
      const result = resultOf(fix({}, state));
      assert.equal(result.proximity, null, `state=${String(state)}`);
      assert.equal(result.reason, REASON_PERMISSION_REQUIRED, `state=${String(state)}`);
    }
  });

  check('A7', 'hostile permission getter throws -> permission_required, never throws', () => {
    const input = fix();
    Object.defineProperty(input, 'permission', {
      get(): string {
        throw new Error('hostile permission getter');
      },
    });
    let result: ResolveProximityResult | undefined;
    assert.doesNotThrow(() => {
      result = resultOf(input);
    });
    assert.equal(result?.proximity, null);
    assert.equal(result?.reason, REASON_PERMISSION_REQUIRED);
  });

  section('B. Invalid fix (granted but unusable)');

  check('B1', 'granted + NaN lat -> invalid_fix', () => {
    const result = resultOf(fix({ lat: Number.NaN }));
    assert.equal(result.proximity, null);
    assert.equal(result.reason, REASON_INVALID_FIX);
  });

  check('B2', 'granted + infinite lat/lon -> invalid_fix', () => {
    for (const lat of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      const result = resultOf(fix({ lat }));
      assert.equal(result.proximity, null);
      assert.equal(result.reason, REASON_INVALID_FIX);
    }
    const badLon = resultOf(fix({ lon: Number.POSITIVE_INFINITY }));
    assert.equal(badLon.proximity, null);
    assert.equal(badLon.reason, REASON_INVALID_FIX);
  });

  check('B3', 'granted + accuracyM 0 -> invalid_fix (strictly greater than 0 required)', () => {
    const result = resultOf(fix({ accuracyM: 0 }));
    assert.equal(result.proximity, null);
    assert.equal(result.reason, REASON_INVALID_FIX);
  });

  check('B4', 'granted + negative accuracyM -> invalid_fix', () => {
    const result = resultOf(fix({ accuracyM: -5 }));
    assert.equal(result.proximity, null);
    assert.equal(result.reason, REASON_INVALID_FIX);
  });

  check('B5', 'granted + non-number lat/lon/accuracyM -> invalid_fix', () => {
    const cases: Partial<ResolveProximityInput>[] = [
      { lat: '52.37' },
      { lon: '4.89' },
      { accuracyM: '12' },
      { lat: null },
      { accuracyM: true },
      { lat: Symbol('lat') },
    ];
    for (const overrides of cases) {
      const result = resultOf(fix(overrides));
      assert.equal(result.proximity, null, `overrides=${JSON.stringify(String(Object.keys(overrides)))}`);
      assert.equal(result.reason, REASON_INVALID_FIX);
    }
  });

  check('B6', 'granted + missing fix fields -> invalid_fix', () => {
    const inputs: ResolveProximityInput[] = [
      { permission: 'granted' },
      { permission: 'granted', lat: 1, lon: 2 },
      { permission: 'granted', lat: 1, accuracyM: 3 },
      { permission: 'granted', lon: 2, accuracyM: 3 },
    ];
    for (const input of inputs) {
      const result = resultOf(input);
      assert.equal(result.proximity, null);
      assert.equal(result.reason, REASON_INVALID_FIX);
    }
  });

  check('B7', 'granted + hostile coordinate getters -> invalid_fix, never throws', () => {
    const input: ResolveProximityInput = {
      permission: 'granted',
      ipCity: 'Amsterdam',
      get lat(): number {
        throw new Error('hostile lat getter');
      },
      get lon(): number {
        throw new Error('hostile lon getter');
      },
      get accuracyM(): number {
        throw new Error('hostile accuracy getter');
      },
    };
    let result: ResolveProximityResult | undefined;
    assert.doesNotThrow(() => {
      result = resultOf(input);
    });
    assert.equal(result?.proximity, null);
    assert.equal(result?.reason, REASON_INVALID_FIX);
  });

  check('B8', 'granted + out-of-WGS-84 coordinates -> invalid_fix (delegated validation)', () => {
    for (const overrides of [{ lat: 91 }, { lat: -91 }, { lon: 181 }, { lon: -181 }]) {
      const result = resultOf(fix(overrides));
      assert.equal(result.proximity, null, `overrides=${JSON.stringify(overrides)}`);
      assert.equal(result.reason, REASON_INVALID_FIX);
    }
  });

  section('C. Granted + valid fix');

  check('C1', 'valid fix -> full proximity shape including accuracy_m', () => {
    const result = resultOf(fix());
    assert.notEqual(result.proximity, null);
    assert.deepEqual(Object.keys(result.proximity!), ['id', 'precision_radius', 'confidence', 'accuracy_m']);
    assert.match(result.proximity!.id, ID_PATTERN);
    assert.equal(result.proximity!.accuracy_m, 12);
  });

  check('C2', 'success reason is the stable REASON_OK token', () => {
    assert.equal(resultOf(fix()).reason, REASON_OK);
  });

  check('C3', 'valid fix is deterministic across calls', () => {
    const first = proxOf(fix());
    const second = proxOf(fix());
    assert.deepEqual(first, second);
    assert.match(first!.id, ID_PATTERN);
  });

  check('C4', 'precision_radius tracks the accuracy tier', () => {
    const tiers = [
      [5, 10],
      [30, 75],
      [100, 200],
      [500, 1000],
      [5000, 5000],
    ] as const;
    for (const [accuracyM, radius] of tiers) {
      const proximity = proxOf(fix({ accuracyM }));
      assert.equal(proximity!.precision_radius, radius, `accuracyM=${accuracyM}`);
    }
  });

  check('C5', 'accuracy_m is the raw reported accuracy, not transformed', () => {
    for (const accuracyM of [0.001, 0.5, 1, 12, 4999.75]) {
      assert.equal(proxOf(fix({ accuracyM }))!.accuracy_m, accuracyM);
    }
    // Values above the published precision cap abstain instead of claiming false precision.
    assert.equal(proxOf(fix({ accuracyM: 9999.75 })), null);
  });

  check('C6', 'id is coordinate-free and salted (one-way pseudonym)', () => {
    const proximity = proxOf(fix())!;
    assert.match(proximity.id, ID_PATTERN);
    assert.ok(!proximity.id.includes('52.37'));
    assert.ok(!proximity.id.includes('4.89'));
    assert.ok(!proximity.id.includes('|'));
  });

  section('D. Confidence derived from accuracy only');

  check('D1', 'same coordinates + different accuracy -> different confidence (monotone)', () => {
    const tight = proxOf(fix({ accuracyM: 1 }))!;
    const loose = proxOf(fix({ accuracyM: 1000 }))!;
    assert.ok(tight.confidence > loose.confidence);
    assert.notEqual(tight.confidence, loose.confidence);
  });

  check('D2', 'same accuracy + different coordinates -> identical confidence', () => {
    const a = proxOf(fix({ lat: 52.37, lon: 4.89, accuracyM: 12 }))!;
    const b = proxOf(fix({ lat: -33.87, lon: 151.21, accuracyM: 12 }))!;
    assert.equal(a.confidence, b.confidence);
    assert.notEqual(a.id, b.id, 'coordinates must still change the cell id');
  });

  check('D3', 'confidence is always finite and within [0,1]', () => {
    for (const accuracyM of [0.001, 1, 12, 1000, 5000]) {
      const confidence = proxOf(fix({ accuracyM }))!.confidence;
      assert.equal(typeof confidence, 'number');
      assert.ok(Number.isFinite(confidence));
      assert.ok(confidence >= 0 && confidence <= 1, `accuracyM=${accuracyM}`);
    }
    assert.equal(proxOf(fix({ accuracyM: 1e9 })), null);
  });

  check('D4', 'tiny coordinate change shares a coarse cell; distant point does not', () => {
    const base = proxOf(fix({ lat: 48.85, lon: 2.35, accuracyM: 5000 }))!;
    const nearby = proxOf(fix({ lat: 48.85 + 1e-9, lon: 2.35 + 1e-9, accuracyM: 5000 }))!;
    const distant = proxOf(fix({ lat: -33.87, lon: 151.21, accuracyM: 5000 }))!;
    assert.equal(base.id, nearby.id);
    assert.notEqual(base.id, distant.id);
  });

  section('E. Spoofed input & no-IP guarantee');

  check('E1', 'ipCity with denied permission still -> permission_required, null', () => {
    const result = resultOf(fix({ ipCity: 'Amsterdam' }, 'denied'));
    assert.equal(result.proximity, null);
    assert.equal(result.reason, REASON_PERMISSION_REQUIRED);
  });

  check('E2', 'ipCity with granted fix -> identical proximity to the same fix without ipCity', () => {
    const withCity = proxOf(fix({ ipCity: 'Amsterdam' }))!;
    const withoutCity = proxOf(fix())!;
    assert.deepEqual(withCity, withoutCity);
  });

  check('E3', 'varying ipCity never changes the serialized proximity', () => {
    const baseline = JSON.stringify(proxOf(fix())!);
    for (const ipCity of ['Amsterdam', 'Sydney', 'Pyongyang', '', '1.2.3.4', { city: 'Paris' }, null]) {
      const actual = JSON.stringify(proxOf(fix({ ipCity }))!);
      assert.equal(actual, baseline, `ipCity=${String(ipCity)}`);
    }
  });

  check('E4', 'ipCity alone (no fix) cannot create proximity -> invalid_fix', () => {
    const result = resultOf({ permission: 'granted', ipCity: 'Amsterdam' });
    assert.equal(result.proximity, null);
    assert.equal(result.reason, REASON_INVALID_FIX);
  });

  check('E5', 'a throwing ipCity getter is never triggered (ipCity is never read)', () => {
    const input: ResolveProximityInput = fix();
    Object.defineProperty(input, 'ipCity', {
      get(): string {
        throw new Error('ipCity getter must never be read');
      },
    });
    let result: ResolveProximityResult | undefined;
    assert.doesNotThrow(() => {
      result = resultOf(input);
    });
    assert.equal(result?.reason, REASON_OK);
    assert.match(result!.proximity!.id, ID_PATTERN);
  });

  check('E6', 'spoofed permission token with ipCity cannot produce proximity', () => {
    for (const permission of ['GRANTED', 'granted ', 'prompt', 'denied']) {
      const result = resultOf(fix({ ipCity: 'Amsterdam' }, permission));
      assert.equal(result.proximity, null, `permission=${String(permission)}`);
      assert.equal(result.reason, REASON_PERMISSION_REQUIRED);
    }
  });

  check('E7', 'failure reasons are exact tokens with no city/IP data embedded', () => {
    const reasons = [
      resultOf(fix({ ipCity: 'Amsterdam' }, 'denied')).reason,
      resultOf(fix({ ipCity: 'Amsterdam' }, 'prompt')).reason,
      resultOf(fix({ ipCity: 'Amsterdam', lat: Number.NaN })).reason,
      resultOf(fix({ ipCity: '1.2.3.4', accuracyM: 0 })).reason,
    ];
    for (const reason of reasons) {
      assert.ok(reason === REASON_PERMISSION_REQUIRED || reason === REASON_INVALID_FIX, reason);
      assert.ok(!/amsterdam|1\.2\.3\.4|ip/i.test(reason), reason);
    }
  });

  section('F. Hostile input totality');

  check('F1', 'proxy whose has/get throw never escapes as an exception', () => {
    const hostile = new Proxy({}, {
      has(): boolean {
        throw new Error('hostile has');
      },
      get(): never {
        throw new Error('hostile get');
      },
    }) as ResolveProximityInput;
    let result: ResolveProximityResult | undefined;
    assert.doesNotThrow(() => {
      result = resultOf(hostile);
    });
    assert.equal(result?.proximity, null);
    assert.equal(result?.reason, REASON_PERMISSION_REQUIRED);
  });

  check('F2', 'granted fix with a hostile toString on input object never throws', () => {
    const input: ResolveProximityInput = fix();
    Object.defineProperty(input, 'toString', {
      value(): string {
        throw new Error('hostile toString');
      },
    });
    let result: ResolveProximityResult | undefined;
    assert.doesNotThrow(() => {
      result = resultOf(input);
    });
    assert.equal(result?.reason, REASON_OK);
  });

  check('F3', 'frozen / sealed input still resolves normally', () => {
    const frozen = Object.freeze(fix({ lat: 48.85, lon: 2.35, accuracyM: 30 }));
    assert.equal(resultOf(frozen).reason, REASON_OK);
    const sealed = Object.seal(fix({ lat: 48.85, lon: 2.35, accuracyM: 30 }));
    assert.equal(resultOf(sealed).reason, REASON_OK);
  });

  check('F4', 'repeated hostile calls are stable and never mutate input', () => {
    const input = fix();
    const before = JSON.stringify({ permission: input.permission, lat: input.lat, lon: input.lon, accuracyM: input.accuracyM });
    const a = resultOf(input);
    const b = resultOf(input);
    assert.deepEqual(a, b);
    const after = JSON.stringify({ permission: input.permission, lat: input.lat, lon: input.lon, accuracyM: input.accuracyM });
    assert.equal(after, before);
  });

  section('G. Additive API v4 body field');

  check('G1', 'v4 + resolved result -> exact hex_proximity shape', () => {
    const result = resultOf(fix());
    const field = proximityBodyField(result, 4)!;
    assert.deepEqual(Object.keys(field), ['hex_proximity']);
    assert.deepEqual(Object.keys(field.hex_proximity), ['id', 'precision_radius', 'confidence', 'accuracy_m']);
    assert.equal(field.hex_proximity.id, result.proximity!.id);
    assert.equal(field.hex_proximity.accuracy_m, 12);
  });

  check('G2', 'apiVersion omitted defaults to v4 and still emits the field', () => {
    const field = proximityBodyField(resultOf(fix()));
    assert.ok(field);
    assert.match(field!.hex_proximity.id, ID_PATTERN);
  });

  check('G3', 'all explicit v4 tokens are accepted', () => {
    const result = resultOf(fix());
    for (const version of [4, '4', 'v4', '4.0', 'v4.0', ' V4 ']) {
      const field = proximityBodyField(result, version);
      assert.ok(field, `version=${String(version)}`);
      assert.equal(field!.hex_proximity.id, result.proximity!.id);
    }
  });

  check('G4', 'non-v4 versions -> undefined (no field)', () => {
    const result = resultOf(fix());
    for (const version of [3, '3', 'v3', 5, undefined, null, {}, [], '4.1']) {
      assert.equal(proximityBodyField(result, version), undefined, `version=${String(version)}`);
    }
  });

  check('G5', 'denied / invalid / null results -> undefined field', () => {
    const denied = resultOf(fix({}, 'denied'));
    const invalid = resultOf(fix({ accuracyM: 0 }));
    assert.equal(denied.proximity, null);
    assert.equal(invalid.proximity, null);
    for (const result of [denied, invalid, null, undefined, {}]) {
      assert.equal(proximityBodyField(result as ResolveProximityResult | null | undefined, 4), undefined);
    }
  });

  check('G6', 'malformed / hostile proximity -> undefined, never throws', () => {
    const malformed = [
      { proximity: { id: '', precision_radius: 10, confidence: 0.5, accuracy_m: 12 } },
      { proximity: { id: 'hex_x', precision_radius: Number.NaN, confidence: 0.5, accuracy_m: 12 } },
      { proximity: { id: 'hex_x', precision_radius: 10, confidence: 0.5, accuracy_m: -1 } },
      { proximity: 'not-an-object' },
    ];
    for (const value of malformed) {
      assert.equal(proximityBodyField(value as unknown as ResolveProximityResult, 4), undefined);
    }
    const hostile = {
      proximity: {
        get id(): string {
          throw new Error('hostile id');
        },
      },
    } as unknown as ResolveProximityResult;
    assert.doesNotThrow(() => assert.equal(proximityBodyField(hostile, 4), undefined));
  });

  check('G7', 'hostile apiVersion never throws', () => {
    const result = resultOf(fix());
    const hostile = {
      toString(): string {
        throw new Error('hostile version');
      },
    };
    assert.doesNotThrow(() => {
      assert.equal(proximityBodyField(result, hostile), undefined);
      assert.equal(proximityBodyField(result, Symbol('v4')), undefined);
    });
  });

  check('G8', 'returned field is a fresh copy, not an alias of the source', () => {
    const result = resultOf(fix());
    const before = JSON.stringify(result);
    const field = proximityBodyField(result, 4)!;
    field.hex_proximity.confidence = 0;
    field.hex_proximity.id = 'tampered';
    assert.equal(JSON.stringify(result), before);
  });

  section('H. End-to-end & emitted-field no-IP guarantee');

  check('H1', 'denied permission never reaches the API body', () => {
    for (const state of ['denied', 'prompt', 'GRANTED', undefined]) {
      const result = resultOf(fix({ ipCity: 'Amsterdam', permission: state }));
      assert.equal(result.proximity, null, `state=${String(state)}`);
      assert.equal(proximityBodyField(result, 4), undefined);
    }
  });

  check('H2', 'granted permission populates the additive field end-to-end', () => {
    const result = resultOf(fix({ lat: 48.85, lon: 2.35, accuracyM: 30, ipCity: 'Paris' }));
    assert.equal(result.reason, REASON_OK);
    const field = proximityBodyField(result)!;
    assert.ok(field);
    assert.equal(field.hex_proximity.id, result.proximity!.id);
    assert.equal(field.hex_proximity.precision_radius, result.proximity!.precision_radius);
    assert.equal(field.hex_proximity.confidence, result.proximity!.confidence);
    assert.equal(field.hex_proximity.accuracy_m, 30);
  });

  check('H3', 'emitted field leaks no IP / city / raw-coordinate data', () => {
    const field = proximityBodyField(resultOf(fix({ ipCity: '1.2.3.4' })))!;
    const serialized = JSON.stringify(field);
    for (const forbidden of ['ip', 'city', 'geohash', '1.2.3.4', 'latitude', 'longitude', '52.37', '4.89', 'proof', 'verified', 'identity']) {
      assert.ok(!serialized.includes(forbidden), `field leaked ${forbidden}: ${serialized}`);
    }
  });
}

/* -------------------------------------------------------------------------- */

let runFailed = false;
try {
  run();
} catch (error) {
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

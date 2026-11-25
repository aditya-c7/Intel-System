/**
 * Regression suite for src/lib/proximityAdapter.ts (permission-gated bridge).
 *
 * Pins the documented invariants:
 *  - denied / unavailable / prompt permission always yields proximity:null
 *  - granted + browser coordinates delegates to hexProximity (salted cell id)
 *  - hostile input (throwing getters, symbols, primitives) never throws
 *  - NO IP fallback on any path (machine-checkable reason marker)
 *  - the additive API v4 body field appears only for v4 + a resolved proximity
 *
 *   npx tsx scripts/test-proximity-adapter.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  NO_IP_FALLBACK_MARKER,
  PROXIMITY_SALT_VERSION,
  proximityBodyField,
  proximityFromPermission,
  versionedSalt,
  type GeolocationPermissionInput,
  type HexProximity,
} from '../src/lib/proximityAdapter';

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

const SALT = 'adapter-test-salt';
const ID_PATTERN = /^hex_[0-9a-f]{32}$/;

function granted(
  latitude: number,
  longitude: number,
  accuracy: number,
  permission = 'granted'
): GeolocationPermissionInput {
  return { permission, position: { coords: { latitude, longitude, accuracy } } };
}

function proximityOf(input: GeolocationPermissionInput, salt = SALT): HexProximity | null {
  return proximityFromPermission(input, salt).proximity;
}

function hostileCoords(): GeolocationPermissionInput {
  return {
    permission: 'granted',
    position: {
      coords: {
        get latitude(): number {
          throw new Error('hostile latitude getter');
        },
        get longitude(): number {
          throw new Error('hostile longitude getter');
        },
        get accuracy(): number {
          throw new Error('hostile accuracy getter');
        },
      },
    },
  };
}

function knownProximity(): HexProximity {
  return proximityOf(granted(52.37, 4.89, 12))!;
}

/* -------------------------------------------------------------------------- */

function run(): void {
  section('0. Exports');

  check('S1', 'adapter exports both functions', () => {
    assert.equal(typeof proximityFromPermission, 'function');
    assert.equal(typeof proximityBodyField, 'function');
  });

  check('S2', 'no-IP audit marker is exported and non-empty', () => {
    assert.equal(typeof NO_IP_FALLBACK_MARKER, 'string');
    assert.match(NO_IP_FALLBACK_MARKER, /no IP-geolocation fallback used/i);
  });

  check('S3', 'adapter source imports no network / geohash modules', () => {
    const source = readFileSync(new URL('../src/lib/proximityAdapter.ts', import.meta.url), 'utf8');
    const imports = source.split('\n').filter((line) => line.trimStart().startsWith('import'));
    assert.ok(imports.length > 0);
    for (const line of imports) {
      assert.ok(!/geohash|\bhttp\b|node:https|node:dns|\bfetch\b|XMLHttpRequest/.test(line), line);
    }
    assert.match(source, /from '\.\/hexProximity'/);
  });

  section('A. Denied / unavailable permission');

  check('A1', 'null geolocation -> proximity null + denial reason + no-IP marker', () => {
    const result = proximityFromPermission(null, SALT);
    assert.equal(result.proximity, null);
    assert.match(result.reason, /permission decision unavailable/i);
    assert.match(result.reason, /no IP-geolocation fallback used/i);
  });

  check('A2', 'undefined geolocation -> proximity null', () => {
    const result = proximityFromPermission(undefined, SALT);
    assert.equal(result.proximity, null);
    assert.match(result.reason, /no IP-geolocation fallback used/i);
  });

  check('A3', 'explicitly denied permission -> proximity null + denied reason', () => {
    const result = proximityFromPermission(granted(52.37, 4.89, 12, 'denied'), SALT);
    assert.equal(result.proximity, null);
    assert.match(result.reason, /permission denied/i);
    assert.match(result.reason, /no IP-geolocation fallback used/i);
  });

  check('A4', 'prompt permission -> proximity null (not yet granted)', () => {
    const result = proximityFromPermission(granted(52.37, 4.89, 12, 'prompt'), SALT);
    assert.equal(result.proximity, null);
    assert.match(result.reason, /not granted/i);
  });

  check('A5', 'missing / unknown permission -> proximity null', () => {
    for (const state of [undefined, '', 'UNKNOWN', 'allow']) {
      const input: GeolocationPermissionInput = { position: { coords: { latitude: 1, longitude: 2, accuracy: 3 } } };
      if (state !== undefined) input.permission = state;
      const result = proximityFromPermission(input, SALT);
      assert.equal(result.proximity, null, `state=${String(state)}`);
      assert.match(result.reason, /not granted/i);
      if (state === undefined || state === '') assert.match(result.reason, /state=unknown/i);
    }
  });

  check('A6', 'a valid position cannot override a denied permission', () => {
    const result = proximityFromPermission(granted(0, 0, 0, 'denied'), SALT);
    assert.equal(result.proximity, null);
    assert.match(result.reason, /denied/i);
  });

  section('B. Granted permission');

  check('B1', 'granted + valid fix -> full ProximityResult shape', () => {
    const result = proximityFromPermission(granted(52.37, 4.89, 12), SALT);
    assert.notEqual(result.proximity, null);
    assert.match(result.proximity!.id, ID_PATTERN);
    assert.equal(result.proximity!.precision_radius, 75);
    assert.ok(result.proximity!.confidence > 0 && result.proximity!.confidence <= 1);
  });

  check('B2', 'granted reason records permission and the no-IP guarantee', () => {
    const result = proximityFromPermission(granted(52.37, 4.89, 12), SALT);
    assert.match(result.reason, /permission granted/i);
    assert.match(result.reason, /browser geolocation accepted/i);
    assert.match(result.reason, /no IP-geolocation fallback used$/);
  });

  check('B3', 'precision_radius tracks the reported accuracy tier', () => {
    const tiers = [
      [5, 10],
      [30, 75],
      [100, 200],
      [500, 1000],
      [5000, 5000],
    ] as const;
    for (const [accuracy, radius] of tiers) {
      const result = proximityFromPermission(granted(10, 20, accuracy), SALT);
      assert.equal(result.proximity!.precision_radius, radius, `accuracy=${accuracy}`);
    }
  });

  check('B4', 'same permission decision + salt -> deterministic id', () => {
    const first = proximityOf(granted(52.37, 4.89, 12), SALT);
    const second = proximityOf(granted(52.37, 4.89, 12), SALT);
    assert.deepEqual(first, second);
    assert.match(first!.id, ID_PATTERN);
  });

  check('B5', 'changing the salt changes the granted cell id', () => {
    const a = proximityOf(granted(52.37, 4.89, 12), 'salt-a');
    const b = proximityOf(granted(52.37, 4.89, 12), 'salt-b');
    assert.notEqual(a, b);
  });

  check('B6', 'confidence is accuracy-derived and monotone', () => {
    const tight = proximityOf(granted(1, 1, 0))!;
    const loose = proximityOf(granted(1, 1, 1000))!;
    assert.ok(tight.confidence >= 0 && tight.confidence <= 1);
    assert.ok(loose.confidence >= 0 && loose.confidence <= 1);
    assert.ok(tight.confidence > loose.confidence);
  });

  section('C. Hostile / invalid input');

  check('C1', 'granted but invalid coordinates -> proximity null, never an IP fallback', () => {
    const bad = [
      granted(Number.NaN, 4.89, 12),
      granted(91, 0, 12),
      granted(0, -181, 12),
      granted(0, 0, -5),
    ];
    for (const input of bad) {
      const result = proximityFromPermission(input, SALT);
      assert.equal(result.proximity, null);
      assert.match(result.reason, /no IP-geolocation fallback used/i);
    }
  });

  check('C2', 'granted but missing coords / accuracy -> proximity null', () => {
    const inputs: GeolocationPermissionInput[] = [
      { permission: 'granted' },
      { permission: 'granted', position: null },
      { permission: 'granted', position: { coords: null } },
      { permission: 'granted', position: { coords: { latitude: 1, longitude: 2 } } },
    ];
    for (const input of inputs) {
      const result = proximityFromPermission(input, SALT);
      assert.equal(result.proximity, null);
      assert.match(result.reason, /invalid|unavailable/i);
      assert.match(result.reason, /no IP-geolocation fallback used/i);
    }
  });

  check('C3', 'hostile permission getter never throws', () => {
    const hostile: GeolocationPermissionInput = {
      get permission(): string {
        throw new Error('hostile permission getter');
      },
      position: { coords: { latitude: 1, longitude: 2, accuracy: 3 } },
    };
    let result: ReturnType<typeof proximityFromPermission> | undefined;
    assert.doesNotThrow(() => {
      result = proximityFromPermission(hostile, SALT);
    });
    assert.equal(result?.proximity, null);
    assert.match(result!.reason, /no IP-geolocation fallback used/i);
  });

  check('C4', 'hostile coordinate getters never throw', () => {
    let result: ReturnType<typeof proximityFromPermission> | undefined;
    assert.doesNotThrow(() => {
      result = proximityFromPermission(hostileCoords(), SALT);
    });
    assert.equal(result?.proximity, null);
    assert.match(result!.reason, /no IP-geolocation fallback used/i);
  });

  check('C5', 'primitive geolocation inputs (string / number / symbol / boolean) never throw', () => {
    const hostile: unknown[] = ['granted', 42, true, Symbol('geo'), () => 'granted'];
    for (const value of hostile) {
      let result: ReturnType<typeof proximityFromPermission> | undefined;
      assert.doesNotThrow(() => {
        result = proximityFromPermission(value as GeolocationPermissionInput, SALT);
      });
      assert.equal(result?.proximity, null, `input=${String(value)}`);
    }
  });

  check('C6', 'hostile salt never throws and stays coordinate-free', () => {
    const hostileSalt = {
      toString(): string {
        throw new Error('hostile salt');
      },
    } as unknown as string;
    let id: string | null = null;
    assert.doesNotThrow(() => {
      const proximity = proximityOf(granted(52.37, 4.89, 12), hostileSalt);
      id = proximity ? proximity.id : null;
    });
    assert.match(id!, ID_PATTERN);
    assert.ok(!id!.includes('52.37'));
    assert.ok(!id!.includes('4.89'));
  });

  section('D. Additive API v4 body field');

  check('D1', 'v4 + resolved proximity -> hex_proximity field with exact shape', () => {
    const proximity = knownProximity();
    const field = proximityBodyField(proximity, 4);
    assert.deepEqual(Object.keys(field!), ['hex_proximity']);
    assert.deepEqual(Object.keys(field!.hex_proximity), ['id', 'precision_radius', 'confidence']);
    assert.equal(field!.hex_proximity.id, proximity!.id);
    assert.match(field!.hex_proximity.id, ID_PATTERN);
  });

  check('D2', 'all explicit v4 tokens are accepted', () => {
    const proximity = knownProximity();
    for (const version of [4, '4', 'v4', '4.0', 'v4.0']) {
      const field = proximityBodyField(proximity, version);
      assert.ok(field, `version=${String(version)}`);
      assert.equal(field!.hex_proximity.id, proximity!.id);
    }
  });

  check('D3', 'non-v4 versions -> undefined (no field)', () => {
    const proximity = knownProximity();
    for (const version of [3, '3', 'v3', 5, undefined, null, {}, []]) {
      assert.equal(proximityBodyField(proximity, version), undefined, `version=${String(version)}`);
    }
  });

  check('D4', 'missing proximity (permission denied) -> undefined field', () => {
    const denied = proximityFromPermission(granted(52.37, 4.89, 12, 'denied'), SALT);
    assert.equal(denied.proximity, null);
    for (const version of [4, 'v4']) {
      assert.equal(proximityBodyField(denied.proximity, version), undefined);
    }
    assert.equal(proximityBodyField(null, 4), undefined);
    assert.equal(proximityBodyField(undefined, 4), undefined);
  });

  check('D5', 'structurally invalid proximity -> undefined, hostile proximity never throws', () => {
    const malformed = [
      { id: '', precision_radius: 10, confidence: 0.5 },
      { id: 'hex_x', precision_radius: Number.NaN, confidence: 0.5 },
      { id: 'hex_x', precision_radius: 10, confidence: Number.POSITIVE_INFINITY },
      'not-an-object',
    ] as unknown as HexProximity[];
    for (const value of malformed) {
      assert.equal(proximityBodyField(value, 4), undefined);
    }
    const hostile = {
      get id(): string {
        throw new Error('hostile id');
      },
    } as unknown as HexProximity;
    assert.doesNotThrow(() => assert.equal(proximityBodyField(hostile, 4), undefined));
  });

  check('D6', 'hostile apiVersion never throws', () => {
    const proximity = knownProximity();
    const hostile = {
      toString(): string {
        throw new Error('hostile version');
      },
    };
    assert.doesNotThrow(() => {
      assert.equal(proximityBodyField(proximity, hostile), undefined);
      assert.equal(proximityBodyField(proximity, Symbol('v4')), undefined);
    });
  });

  check('D7', 'returned field is a fresh copy, not an alias of the input', () => {
    const proximity = knownProximity();
    const before = JSON.stringify(proximity);
    const field = proximityBodyField(proximity, 4)!;
    field.hex_proximity.confidence = 0;
    assert.equal(JSON.stringify(proximity), before);
  });

  section('E. End-to-end & no-IP guarantee');

  check('E1', 'denied permission never reaches the API body', () => {
    for (const state of [null, undefined, 'denied', 'prompt']) {
      const input = state && typeof state === 'object' ? null : granted(1, 2, 3, String(state));
      const result = proximityFromPermission(input as GeolocationPermissionInput | null, SALT);
      assert.equal(result.proximity, null);
      assert.equal(proximityBodyField(result.proximity, 4), undefined);
    }
  });

  check('E2', 'granted permission populates the additive field end-to-end', () => {
    const result = proximityFromPermission(granted(48.85, 2.35, 30), SALT);
    assert.notEqual(result.proximity, null);
    const field = proximityBodyField(result.proximity, 4);
    assert.ok(field);
    assert.equal(field!.hex_proximity.id, result.proximity!.id);
    assert.equal(field!.hex_proximity.precision_radius, result.proximity!.precision_radius);
  });

  check('E3', 'no IP fallback: fields and reasons contain no IP-derived data', () => {
    const reasons = [
      proximityFromPermission(null, SALT).reason,
      proximityFromPermission(granted(1, 2, 3, 'denied'), SALT).reason,
      proximityFromPermission(granted(1, 2, 3, 'prompt'), SALT).reason,
      proximityFromPermission(granted(Number.NaN, 2, 3), SALT).reason,
      proximityFromPermission(granted(1, 2, 3), SALT).reason,
    ];
    for (const reason of reasons) {
      assert.match(reason, /no IP-geolocation fallback used/i);
    }

    const field = proximityBodyField(knownProximity(), 4)!;
    const serialized = JSON.stringify(field);
    for (const forbidden of ['ip', 'geohash', 'zone_label', 'latitude', 'longitude', 'prox_']) {
      assert.ok(!serialized.includes(forbidden), `field leaked ${forbidden}: ${serialized}`);
    }
  });

  section('F. Research brief: grid guards, versioned salt, pseudonymity');

  check('F1', 'WGS-84 boundaries (poles / antimeridian) are guarded, never an IP fallback', () => {
    const accepted = [
      [90, 0],
      [-90, 0],
      [0, 180],
      [0, -180],
      [89.999, 179.999],
      [0, -179.999],
    ];
    for (const [lat, lon] of accepted) {
      const result = proximityFromPermission(granted(lat, lon, 1000), SALT);
      assert.notEqual(result.proximity, null, `lat=${lat} lon=${lon}`);
      assert.match(result.proximity!.id, ID_PATTERN);
    }
    const rejected = [
      [90.001, 0],
      [-90.001, 0],
      [0, 180.001],
      [0, -180.001],
    ];
    for (const [lat, lon] of rejected) {
      const result = proximityFromPermission(granted(lat, lon, 1000), SALT);
      assert.equal(result.proximity, null, `lat=${lat} lon=${lon}`);
      assert.match(result.reason, /no IP-geolocation fallback used/i);
    }
  });

  check('F2', 'salt versioning re-keys every cell id; same version is deterministic', () => {
    assert.equal(PROXIMITY_SALT_VERSION, 'v1');
    assert.equal(versionedSalt('secret'), 'v1|secret');
    assert.equal(versionedSalt('secret', 'v2'), 'v2|secret');

    const point = granted(48.85, 2.35, 30);
    const v1a = proximityOf(point, versionedSalt('secret'));
    const v1b = proximityOf(point, versionedSalt('secret'));
    const v2 = proximityOf(point, versionedSalt('secret', 'v2'));
    assert.deepEqual(v1a, v1b);
    assert.notEqual(v1a!.id, v2!.id);
  });

  check('F3', 'cell id is a pseudonym, never a proof or identity claim', () => {
    const proximity = knownProximity();
    const serialized = JSON.stringify(proximityBodyField(proximity, 4)!);
    for (const forbidden of ['proof', 'verified', 'identity', 'match', 'latitude', 'longitude']) {
      assert.ok(!serialized.includes(forbidden), `pseudonym leaked ${forbidden}: ${serialized}`);
    }
    assert.match(proximity!.id, ID_PATTERN);
    assert.ok(!proximity!.id.includes('52.37'));
    assert.ok(!proximity!.id.includes('4.89'));
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

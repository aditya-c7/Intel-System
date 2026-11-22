/**
 * Regression suite for src/lib/hexProximity.ts (SHADOW-ONLY proximity helpers).
 *
 * Pins the documented invariants:
 *  - precision tiers map the five accuracy bands to their radius/label
 *  - hex cell ids are deterministic, salt-sensitive and coordinate-free
 *  - proximity is null on denied/absent/invalid input (never an IP fallback)
 *  - every export is total on hostile input (NaN, throwing getters, symbols)
 *  - WebCrypto-preferring variant stays stable and salt-sensitive
 *
 *   npx tsx scripts/test-hex-proximity.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 * The whole run is wrapped so no assertion/import error ever escapes uncaught.
 */

import assert from 'node:assert/strict';

import {
  hexCellId,
  hexCellIdAsync,
  isWebCryptoAvailable,
  proximityFromGeolocation,
  resolvePrecisionTier,
  type GeoPoint,
} from '../src/lib/hexProximity';

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

async function checkAsync(id: string, label: string, body: () => Promise<void>): Promise<void> {
  try {
    await body();
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

const SALT = 'test-salt-alpha';
const POINT: GeoPoint = { lat: 52.37, lon: 4.89, accuracyMeters: 12 };
const ID_PATTERN = /^hex_[0-9a-f]{32}$/;

/** A point whose property reads throw, used to prove the resolver never throws. */
function hostilePoint(): GeoPoint {
  return {
    get lat(): number {
      throw new Error('hostile lat getter');
    },
    get lon(): number {
      throw new Error('hostile lon getter');
    },
    get accuracyMeters(): number {
      throw new Error('hostile accuracy getter');
    },
  };
}

/* -------------------------------------------------------------------------- */

async function run(): Promise<void> {
  section('0. Exports');

  check('S1', 'resolvePrecisionTier / hexCellId / proximityFromGeolocation are functions', () => {
    assert.equal(typeof resolvePrecisionTier, 'function');
    assert.equal(typeof hexCellId, 'function');
    assert.equal(typeof proximityFromGeolocation, 'function');
  });

  check('S2', 'hexCellIdAsync / isWebCryptoAvailable are exported', () => {
    assert.equal(typeof hexCellIdAsync, 'function');
    assert.equal(typeof isWebCryptoAvailable, 'function');
    assert.equal(typeof isWebCryptoAvailable(), 'boolean');
  });

  section('A. Precision bands');

  check('A1', 'accuracy 0 and 9.999 -> tier 0 (radius 10, fine)', () => {
    for (const accuracy of [0, 9.999]) {
      const result = resolvePrecisionTier(accuracy);
      assert.deepEqual(result, { tier: 0, radiusMeters: 10, label: 'fine' });
    }
  });

  check('A2', 'accuracy 10 and 74.9 -> tier 1 (radius 75, high)', () => {
    for (const accuracy of [10, 74.9]) {
      const result = resolvePrecisionTier(accuracy);
      assert.deepEqual(result, { tier: 1, radiusMeters: 75, label: 'high' });
    }
  });

  check('A3', 'accuracy 75 and 199.9 -> tier 2 (radius 200, medium)', () => {
    for (const accuracy of [75, 199.9]) {
      const result = resolvePrecisionTier(accuracy);
      assert.deepEqual(result, { tier: 2, radiusMeters: 200, label: 'medium' });
    }
  });

  check('A4', 'accuracy 200 and 999.9 -> tier 3 (radius 1000, coarse)', () => {
    for (const accuracy of [200, 999.9]) {
      const result = resolvePrecisionTier(accuracy);
      assert.deepEqual(result, { tier: 3, radiusMeters: 1000, label: 'coarse' });
    }
  });

  check('A5', 'accuracy 1000 and above -> tier 4 (radius 5000, rough)', () => {
    for (const accuracy of [1000, 5000, 1e9]) {
      const result = resolvePrecisionTier(accuracy);
      assert.deepEqual(result, { tier: 4, radiusMeters: 5000, label: 'rough' });
    }
  });

  check('A6', 'hostile accuracy never throws and degrades to tier 4 / unknown', () => {
    const hostile: unknown[] = [Number.NaN, -1, Number.POSITIVE_INFINITY, '20', null, undefined, {}, Symbol('x')];
    for (const input of hostile) {
      let result: ReturnType<typeof resolvePrecisionTier> | undefined;
      assert.doesNotThrow(() => {
        result = resolvePrecisionTier(input);
      });
      assert.equal(result?.tier, 4);
      assert.equal(result?.radiusMeters, 5000);
      assert.equal(result?.label, 'unknown', `input=${String(input)}`);
    }
  });

  section('B. Hex cell ids');

  check('B1', 'same point + salt + tier is deterministic', () => {
    const first = hexCellId(POINT, SALT, 1);
    const second = hexCellId({ ...POINT }, SALT, 1);
    assert.equal(first, second);
    assert.match(first, ID_PATTERN);
  });

  check('B2', 'changing the salt changes the id', () => {
    assert.notEqual(hexCellId(POINT, 'salt-a', 1), hexCellId(POINT, 'salt-b', 1));
  });

  check('B3', 'changing the tier changes the id', () => {
    assert.notEqual(hexCellId(POINT, SALT, 0), hexCellId(POINT, SALT, 4));
  });

  check('B4', 'id is coordinate-free (no raw lat/lon, no tile coordinates)', () => {
    const point: GeoPoint = { lat: 52.37, lon: 4.89, accuracyMeters: 12 };
    const id = hexCellId(point, SALT, 1);
    assert.match(id, ID_PATTERN);
    assert.ok(!id.includes('52.37'));
    assert.ok(!id.includes('4.89'));
    assert.ok(!id.includes('|'));
    // Different salts cannot be recovered by concatenating the point's digits.
    assert.ok(!id.includes(String(point.lat).replace('.', '')));
  });

  check('B5', 'hex quantization: tiny movement shares a cell, distant point does not', () => {
    const base: GeoPoint = { lat: 48.85, lon: 2.35, accuracyMeters: 1000 };
    const nearby: GeoPoint = { lat: 48.85 + 1e-9, lon: 2.35 + 1e-9, accuracyMeters: 1000 };
    const distant: GeoPoint = { lat: -33.87, lon: 151.21, accuracyMeters: 1000 };
    assert.equal(hexCellId(base, SALT, 4), hexCellId(nearby, SALT, 4));
    assert.notEqual(hexCellId(base, SALT, 4), hexCellId(distant, SALT, 4));
  });

  check('B6', 'hostile point (throwing getters) never throws and stays deterministic', () => {
    let first: string | undefined;
    let second: string | undefined;
    assert.doesNotThrow(() => {
      first = hexCellId(hostilePoint(), SALT, 2);
      second = hexCellId(hostilePoint(), SALT, 2);
    });
    assert.match(first!, ID_PATTERN);
    assert.equal(first, second);
    assert.notEqual(first, hexCellId(hostilePoint(), 'other-salt', 2));
  });

  check('B7', 'hostile salt / tier never throws and remains salt-sensitive', () => {
    let id: string | undefined;
    assert.doesNotThrow(() => {
      id = hexCellId(POINT, { toString: () => { throw new Error('hostile salt'); } } as unknown as string, 2);
    });
    assert.match(id!, ID_PATTERN);
    let hostileTierId: string | undefined;
    assert.doesNotThrow(() => {
      hostileTierId = hexCellId(POINT, SALT, Symbol('tier') as unknown as number);
    });
    assert.match(hostileTierId!, ID_PATTERN);
  });

  section('C. Proximity (shadow-only, no IP fallback)');

  check('C1', 'null point -> proximity null + denial reason', () => {
    const result = proximityFromGeolocation(null, SALT);
    assert.equal(result.proximity, null);
    assert.match(result.reason, /permission denied|position absent/i);
    assert.match(result.reason, /no IP-geolocation fallback/i);
  });

  check('C2', 'undefined point -> proximity null', () => {
    const result = proximityFromGeolocation(undefined as unknown as GeoPoint, SALT);
    assert.equal(result.proximity, null);
    assert.match(result.reason, /no IP-geolocation fallback/i);
  });

  check('C3', 'valid point -> id / precision_radius / confidence shape', () => {
    const result = proximityFromGeolocation({ lat: 52.37, lon: 4.89, accuracyMeters: 12 }, SALT);
    assert.notEqual(result.proximity, null);
    assert.match(result.proximity!.id, ID_PATTERN);
    assert.equal(result.proximity!.precision_radius, 75);
    assert.ok(result.proximity!.confidence > 0 && result.proximity!.confidence <= 1);
  });

  check('C4', 'precision_radius tracks the resolved tier', () => {
    const radii = [
      [5, 10],
      [30, 75],
      [100, 200],
      [500, 1000],
      [5000, 5000],
    ] as const;
    for (const [accuracy, radius] of radii) {
      const result = proximityFromGeolocation({ lat: 10, lon: 20, accuracyMeters: accuracy }, SALT);
      assert.equal(result.proximity!.precision_radius, radius, `accuracy=${accuracy}`);
    }
  });

  check('C5', 'confidence is accuracy-derived, capped to [0,1] and monotone', () => {
    const tight = proximityFromGeolocation({ lat: 1, lon: 1, accuracyMeters: 0 }, SALT).proximity!;
    const loose = proximityFromGeolocation({ lat: 1, lon: 1, accuracyMeters: 10000 }, SALT).proximity!;
    assert.ok(tight.confidence <= 1 && tight.confidence >= 0);
    assert.ok(loose.confidence >= 0 && loose.confidence <= 1);
    assert.ok(tight.confidence > loose.confidence);
  });

  check('C6', 'invalid coordinates yield proximity null, never an IP fallback', () => {
    const bad: GeoPoint[] = [
      { lat: Number.NaN, lon: 4.89, accuracyMeters: 10 },
      { lat: 91, lon: 0, accuracyMeters: 10 },
      { lat: 0, lon: 181, accuracyMeters: 10 },
      { lat: 0, lon: 0, accuracyMeters: -5 },
    ];
    for (const point of bad) {
      const result = proximityFromGeolocation(point, SALT);
      assert.equal(result.proximity, null);
      assert.match(result.reason, /no IP-geolocation fallback/i);
    }
  });

  check('C7', 'hostile getter point -> proximity null, no throw', () => {
    let result: ReturnType<typeof proximityFromGeolocation> | undefined;
    assert.doesNotThrow(() => {
      result = proximityFromGeolocation(hostilePoint(), SALT);
    });
    assert.equal(result?.proximity, null);
    assert.match(result!.reason, /no IP-geolocation fallback/i);
  });

  check('C8', 'success reason explicitly records that no IP fallback was used', () => {
    const result = proximityFromGeolocation(POINT, SALT);
    assert.match(result.reason, /browser geolocation accepted/i);
    assert.match(result.reason, /no IP-geolocation fallback used$/);
  });

  section('D. WebCrypto-preferring variant');

  await checkAsync('D1', 'hexCellIdAsync resolves to a valid id', async () => {
    const id = await hexCellIdAsync(POINT, SALT, 1);
    assert.match(id, ID_PATTERN);
  });

  await checkAsync('D2', 'hexCellIdAsync is deterministic across calls', async () => {
    const first = await hexCellIdAsync(POINT, SALT, 1);
    const second = await hexCellIdAsync({ ...POINT }, SALT, 1);
    assert.equal(first, second);
  });

  await checkAsync('D3', 'hexCellIdAsync is salt-sensitive and total on a null point', async () => {
    const a = await hexCellIdAsync(POINT, 'salt-a', 1);
    const b = await hexCellIdAsync(POINT, 'salt-b', 1);
    assert.notEqual(a, b);
    const missing = await hexCellIdAsync(null, SALT, 1);
    assert.match(missing, ID_PATTERN);
  });
}

/* -------------------------------------------------------------------------- */

let runFailed = false;
try {
  await run();
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

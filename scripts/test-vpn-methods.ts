/**
 * Regression suite for src/lib/vpnMethods.ts (SHADOW-ONLY truth helpers).
 *
 * Pins the documented invariants of the canonical `vpnMethods` resolver and its parity
 * diagnostic:
 *  - Asia/Calcutta vs Asia/Kolkata (and case/spacing variants) => timezone_mismatch false
 *  - genuinely different zone identities (even at the same UTC offset) => true
 *  - an unresolved / null / sentinel side => false (absence of evidence, never a mismatch)
 *  - publicVpn / relay / osMismatch / mlPrediction are passed through only on literal true
 *  - origin_country comes exclusively from the verified ipCountry param, never from a timezone
 *  - vpnMethodsParityIssue reports each genuine divergence and stays total on bad input
 *
 *   npx tsx scripts/test-vpn-methods.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 * The whole run is wrapped so no assertion/import error ever escapes uncaught.
 */

import assert from 'node:assert/strict';

import {
  resolveVpnMethods,
  vpnMethodsParityIssue,
  type ResolvedVpnMethods,
  type VpnMethodsInput,
} from '../src/lib/vpnMethods';

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

/** Input with a hostile getter, used to prove both exports never throw. */
function hostileInput(): VpnMethodsInput {
  return {
    get browserTimezone(): string {
      throw new Error('hostile getter');
    },
  } as VpnMethodsInput;
}

/* -------------------------------------------------------------------------- */

function run(): void {
  // Fail loudly (not silently) if the expected exports are not functions.
  for (const [name, value] of [
    ['resolveVpnMethods', resolveVpnMethods],
    ['vpnMethodsParityIssue', vpnMethodsParityIssue],
  ] as const) {
    check('setup', `${name} is exported as a function`, () => {
      assert.equal(typeof value, 'function');
    });
  }

  section('A. Canonical timezone identity');

  check('A1', 'Asia/Calcutta vs Asia/Kolkata => timezone_mismatch false (both directions)', () => {
    for (const [browserTimezone, ipTimezone] of [
      ['Asia/Calcutta', 'Asia/Kolkata'],
      ['Asia/Kolkata', 'Asia/Calcutta'],
    ]) {
      const verdict = resolveVpnMethods({ browserTimezone, ipTimezone });
      assert.equal(
        verdict.timezone_mismatch,
        false,
        `${browserTimezone} vs ${ipTimezone} must not be a mismatch`
      );
      assert.ok(
        verdict.reasons.some((reason) => reason.includes('same canonical identity')),
        JSON.stringify(verdict.reasons)
      );
    }
  });

  check('A2', 'clearly different countries => timezone_mismatch true', () => {
    const verdict = resolveVpnMethods({
      browserTimezone: 'Asia/Kolkata',
      ipTimezone: 'America/New_York',
    });
    assert.equal(verdict.timezone_mismatch, true);
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('canonical identities differ')),
      JSON.stringify(verdict.reasons)
    );
  });

  check('A3', 'shared UTC+8 offset lookalikes are still a real mismatch', () => {
    const verdict = resolveVpnMethods({
      browserTimezone: 'Asia/Singapore',
      ipTimezone: 'Asia/Hong_Kong',
    });
    assert.equal(verdict.timezone_mismatch, true);
  });

  check('A4', 'case / whitespace variants of the same zone => false', () => {
    const verdict = resolveVpnMethods({
      browserTimezone: '  asia/calcutta  ',
      ipTimezone: 'ASIA/KOLKATA',
    });
    assert.equal(verdict.timezone_mismatch, false);
  });

  check('A5', 'the legacy canonicalMismatch hint is diagnostic-only, never authoritative', () => {
    const aliasPair = resolveVpnMethods({
      browserTimezone: 'Asia/Calcutta',
      ipTimezone: 'Asia/Kolkata',
      canonicalMismatch: true,
    });
    assert.equal(aliasPair.timezone_mismatch, false);
    assert.ok(
      aliasPair.reasons.some((reason) => reason.includes('canonicalMismatch=true hint ignored')),
      JSON.stringify(aliasPair.reasons)
    );

    const realMismatch = resolveVpnMethods({
      browserTimezone: 'Asia/Kolkata',
      ipTimezone: 'America/New_York',
      canonicalMismatch: false,
    });
    assert.equal(realMismatch.timezone_mismatch, true);
    assert.ok(
      realMismatch.reasons.some((reason) => reason.includes('canonicalMismatch=false hint ignored')),
      JSON.stringify(realMismatch.reasons)
    );
  });

  section('B. Unresolved / absent timezone side');

  check('B1', 'null, undefined, empty and sentinel sides => false', () => {
    const noEvidence = [null, undefined, '', '   ', 'Unavailable', 'Unknown', 'N/A', 'local'];
    for (const side of noEvidence) {
      for (const [browserTimezone, ipTimezone] of [
        [side, 'Asia/Kolkata'],
        ['Asia/Kolkata', side],
        [side, side],
      ]) {
        const verdict = resolveVpnMethods({ browserTimezone, ipTimezone });
        assert.equal(
          verdict.timezone_mismatch,
          false,
          `side=${JSON.stringify(side)} must not manufacture a mismatch`
        );
      }
    }
  });

  check('B2', 'an unknown IANA name on one side => false', () => {
    const verdict = resolveVpnMethods({
      browserTimezone: 'Not/AReal_Zone',
      ipTimezone: 'Asia/Kolkata',
    });
    assert.equal(verdict.timezone_mismatch, false);
  });

  check('B3', 'no timezone fields at all => false with an unresolved-side reason', () => {
    const verdict = resolveVpnMethods({});
    assert.equal(verdict.timezone_mismatch, false);
    assert.ok(
      verdict.reasons.some((reason) => reason.includes('unresolved timezone side')),
      JSON.stringify(verdict.reasons)
    );
  });

  section('C. Concrete method flags passed through');

  check('C1', 'verified true flags are mirrored one-for-one', () => {
    const verdict = resolveVpnMethods({
      publicVpn: true,
      relay: true,
      osMismatch: true,
      mlPrediction: true,
    });
    assert.equal(verdict.public_vpn, true);
    assert.equal(verdict.relay, true);
    assert.equal(verdict.os_mismatch, true);
    assert.equal(verdict.ml_prediction, true);
  });

  check('C2', 'false / null / absent flags stay false', () => {
    const verdict = resolveVpnMethods({
      publicVpn: false,
      relay: null,
      osMismatch: undefined,
      // mlPrediction intentionally absent
    });
    assert.equal(verdict.public_vpn, false);
    assert.equal(verdict.relay, false);
    assert.equal(verdict.os_mismatch, false);
    assert.equal(verdict.ml_prediction, false);
  });

  check('C3', 'truthy junk is not a verified true flag', () => {
    const verdict = resolveVpnMethods({
      publicVpn: 1,
      relay: 'true',
      osMismatch: {},
      mlPrediction: [],
    } as unknown as VpnMethodsInput);
    assert.equal(verdict.public_vpn, false);
    assert.equal(verdict.relay, false);
    assert.equal(verdict.os_mismatch, false);
    assert.equal(verdict.ml_prediction, false);
  });

  check('C4', 'every fired flag gets an audit reason', () => {
    const verdict = resolveVpnMethods({
      publicVpn: true,
      relay: true,
      osMismatch: true,
      mlPrediction: true,
    });
    for (const fragment of [
      'public_vpn=true from verified publicVpn flag',
      'relay=true from verified relay flag',
      'os_mismatch=true from verified osMismatch flag',
      'ml_prediction=true from verified mlPrediction flag',
    ]) {
      assert.ok(verdict.reasons.includes(fragment), `${fragment} missing from ${JSON.stringify(verdict.reasons)}`);
    }
  });

  section('D. origin_country is never invented');

  check('D1', 'a verified ISO alpha-2 ipCountry is passed through (normalized)', () => {
    for (const [ipCountry, expected] of [
      ['IN', 'IN'],
      [' in ', 'IN'],
      ['us', 'US'],
    ]) {
      const verdict = resolveVpnMethods({ ipCountry });
      assert.equal(verdict.origin_country, expected, `ipCountry=${JSON.stringify(ipCountry)}`);
      assert.ok(
        verdict.reasons.some((reason) => reason.includes('taken from the verified ipCountry param')),
        JSON.stringify(verdict.reasons)
      );
    }
  });

  check('D2', 'a timezone never manufactures a country', () => {
    for (const input of [
      { browserTimezone: 'Asia/Kolkata', ipTimezone: 'Asia/Calcutta' },
      { browserTimezone: 'America/New_York', ipTimezone: 'Asia/Kolkata' },
      { browserTimezone: 'Asia/Kolkata', ipTimezone: 'Asia/Kolkata', publicVpn: true, relay: true },
      {},
    ]) {
      const verdict = resolveVpnMethods(input);
      assert.equal(verdict.origin_country, null, `input=${JSON.stringify(input)}`);
      assert.ok(
        verdict.reasons.some((reason) => reason.includes('never inferred from timezone')),
        JSON.stringify(verdict.reasons)
      );
    }
  });

  check('D3', 'placeholder and malformed country codes are rejected', () => {
    for (const ipCountry of ['XX', 'T1', 'xx', 'USA', 'U', '1N', 'IN-', '', '  ', 'India']) {
      const verdict = resolveVpnMethods({ ipCountry });
      assert.equal(verdict.origin_country, null, `ipCountry=${JSON.stringify(ipCountry)}`);
    }
  });

  section('E. Parity divergence diagnostics');

  check('E1', 'every divergent method flag is reported', () => {
    const resolved = resolveVpnMethods({
      publicVpn: true,
      relay: true,
      osMismatch: true,
      mlPrediction: true,
    });
    const issues = vpnMethodsParityIssue(
      {
        timezone_mismatch: false,
        public_vpn: false,
        relay: false,
        os_mismatch: false,
        ml_prediction: false,
      },
      resolved
    );
    for (const key of ['public_vpn', 'relay', 'os_mismatch', 'ml_prediction']) {
      assert.ok(
        issues.some((issue) => issue.startsWith(`${key}: existing=false resolved=true`)),
        `${key} divergence missing from ${JSON.stringify(issues)}`
      );
    }
    assert.equal(
      issues.some((issue) => issue.startsWith('timezone_mismatch:')),
      false,
      'timezone_mismatch must not be reported when both sides are false'
    );
  });

  check('E2', 'a timezone_mismatch divergence is reported too', () => {
    const resolved = resolveVpnMethods({
      browserTimezone: 'Asia/Kolkata',
      ipTimezone: 'America/New_York',
    });
    const issues = vpnMethodsParityIssue({ timezone_mismatch: false }, resolved);
    assert.ok(
      issues.some((issue) => issue === 'timezone_mismatch: existing=false resolved=true'),
      JSON.stringify(issues)
    );
  });

  check('E3', 'an origin_country divergence is reported', () => {
    const resolved = resolveVpnMethods({ ipCountry: 'IN' });
    const issues = vpnMethodsParityIssue({ origin_country: 'US' }, resolved);
    assert.ok(
      issues.some((issue) => issue === 'origin_country: existing=US resolved=IN'),
      JSON.stringify(issues)
    );
  });

  check('E4', 'matching blocks produce no issues', () => {
    const resolved: ResolvedVpnMethods = resolveVpnMethods({
      browserTimezone: 'Asia/Calcutta',
      ipTimezone: 'Asia/Kolkata',
      ipCountry: 'IN',
      publicVpn: true,
    });
    assert.deepEqual(vpnMethodsParityIssue(resolved, resolved), []);
    assert.deepEqual(
      vpnMethodsParityIssue(
        { timezone_mismatch: false, public_vpn: true, origin_country: 'in' },
        resolved
      ),
      []
    );
  });

  check('E5', 'partial / malformed legacy fields fail closed to false', () => {
    const resolved = resolveVpnMethods({});
    // Deliberately malformed string value: must fail closed, with a cast so the test can feed
    // a legacy/hostile shape that the typed API would otherwise reject at compile time.
    assert.deepEqual(
      vpnMethodsParityIssue(
        { publicVpn: true, relay: 'true' } as unknown as Parameters<typeof vpnMethodsParityIssue>[0],
        resolved
      ),
      []
    );
    assert.deepEqual(vpnMethodsParityIssue({}, resolved), []);
  });

  check('E6', 'parityIssue never throws on hostile inputs', () => {
    let issues: string[] | undefined;
    assert.doesNotThrow(() => {
      issues = vpnMethodsParityIssue(hostileInput(), resolveVpnMethods({}));
    });
    assert.ok(Array.isArray(issues));
    let issuesFromHostileResolved: string[] | undefined;
    assert.doesNotThrow(() => {
      issuesFromHostileResolved = vpnMethodsParityIssue({}, hostileInput() as unknown as ResolvedVpnMethods);
    });
    assert.ok(Array.isArray(issuesFromHostileResolved));
  });

  section('F. Totality on malformed input');

  check('F1', 'null / primitive / array inputs degrade to safe defaults', () => {
    for (const input of [null, undefined, 42, 'vpn', []]) {
      const verdict = resolveVpnMethods(input as unknown as VpnMethodsInput);
      assert.equal(verdict.timezone_mismatch, false);
      assert.equal(verdict.public_vpn, false);
      assert.equal(verdict.relay, false);
      assert.equal(verdict.os_mismatch, false);
      assert.equal(verdict.ml_prediction, false);
      assert.equal(verdict.origin_country, null);
      assert.ok(verdict.reasons.length > 0, 'reasons must never be empty');
    }
  });

  check('F2', 'a hostile getter degrades to safe defaults without throwing', () => {
    let verdict: ResolvedVpnMethods | undefined;
    assert.doesNotThrow(() => {
      verdict = resolveVpnMethods(hostileInput());
    });
    assert.equal(verdict?.timezone_mismatch, false);
    assert.equal(verdict?.origin_country, null);
    assert.ok((verdict?.reasons.length ?? 0) > 0);
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

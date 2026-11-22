/**
 * Regression suite for src/lib/proxyTruth.ts (SHADOW-ONLY truth helpers).
 *
 * Pins the documented invariants of the additive proxy "second opinion":
 *  - datacenter evidence => proxy:true / proxy_type:'data_center'
 *  - a verified good bot is never relabelled a data-center proxy
 *  - no evidence (or null/absent/malformed signals) => proxy:false, low confidence
 *  - residential is claimed only with an explicit residential signal
 *  - proxyDetailsParityIssue reports real divergence and stays total on bad input
 *
 *   npx tsx scripts/test-proxy-truth.ts
 *
 * Prints PASS/FAIL per assertion and a final RESULT line; exits non-zero on failure.
 * The whole run is wrapped so no assertion/import error ever escapes uncaught.
 */

import assert from 'node:assert/strict';

import {
  proxyDetailsParityIssue,
  resolveProxyDetails,
  type ProxyDetails,
  type ProxyDetailsInput,
} from '../src/lib/proxyTruth';

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

/** A verdict with a hostile getter, used to prove the resolver never throws. */
function hostileInput(): ProxyDetailsInput {
  return {
    get datacenterResult(): boolean {
      throw new Error('hostile getter');
    },
  } as ProxyDetailsInput;
}

/* -------------------------------------------------------------------------- */

function run(): void {
  // Fail loudly (not silently) if the expected exports are not functions.
  for (const [name, value] of [
    ['resolveProxyDetails', resolveProxyDetails],
    ['proxyDetailsParityIssue', proxyDetailsParityIssue],
  ] as const) {
    check('setup', `${name} is exported as a function`, () => {
      assert.equal(typeof value, 'function');
    });
  }

  section('A. Datacenter evidence');

  check('A1', 'datacenterResult + datacenter ASN => proxy true / data_center', () => {
    const verdict = resolveProxyDetails({ datacenterResult: true, asnType: 'datacenter', asn: 16509 });
    assert.equal(verdict.proxy, true);
    assert.equal(verdict.proxy_type, 'data_center');
    assert.equal(verdict.confidence, 'high');
    assert.match(verdict.reason, /datacenterResult=true/);
    assert.match(verdict.reason, /ASN 16509/);
    assert.match(verdict.reason, /hosting\/datacenter/i);
  });

  check('A2', 'a bare datacenter/cloud ASN label is reason-only, never a flag', () => {
    for (const asnType of ['datacenter', 'data_center', 'cloud', 'hosting', 'cdn']) {
      const verdict = resolveProxyDetails({ asnType });
      assert.equal(verdict.proxy, false, `asnType=${asnType} must not flag proxy`);
      assert.equal(verdict.proxy_type, null, `asnType=${asnType} must not emit a type`);
    }
  });

  check('A3', 'data_center takes precedence over a residential signal, with both audited', () => {
    const verdict = resolveProxyDetails({
      datacenterResult: true,
      asnType: 'datacenter',
      knownProxyPrefix: true,
    });
    assert.equal(verdict.proxy_type, 'data_center');
    assert.match(verdict.reason, /known-proxy-prefix signal also present/);
  });

  section('B. Verified good-bot exemption');

  check('B1', 'verified good bot is never flagged as a data-center proxy', () => {
    for (const asnType of ['datacenter', 'cloud', undefined]) {
      const verdict = resolveProxyDetails({ datacenterResult: true, verifiedGoodBot: true, asnType });
      assert.equal(verdict.proxy, false, `asnType=${asnType} must not flag a verified good bot`);
      assert.equal(verdict.proxy_type, null);
      assert.match(verdict.reason, /suppressed by verified good-bot exemption/);
    }
  });

  check('B2', 'exemption is scoped: it does not erase residential or VPN evidence', () => {
    const vpn = resolveProxyDetails({ verifiedGoodBot: true, vpn: true });
    assert.equal(vpn.proxy, true);
    assert.equal(vpn.proxy_type, null);

    const residential = resolveProxyDetails({ verifiedGoodBot: true, asnType: 'residential' });
    assert.equal(residential.proxy, true);
    assert.equal(residential.proxy_type, 'residential');
  });

  section('C. No evidence / absent signals');

  check('C1', 'empty, null, primitive and array inputs all yield proxy:false', () => {
    const inputs: unknown[] = [{}, null, undefined, 42, 'datacenter', []];
    for (const input of inputs) {
      const verdict = resolveProxyDetails(input as ProxyDetailsInput);
      assert.equal(verdict.proxy, false, `input=${JSON.stringify(input)}`);
      assert.equal(verdict.proxy_type, null);
      assert.equal(verdict.confidence, 'low');
      assert.ok(verdict.reason.length > 0, 'reason must be a non-empty audit string');
    }
  });

  check('C2', 'explicit false / null signals are treated as no evidence', () => {
    const verdict = resolveProxyDetails({
      datacenterResult: false,
      vpn: false,
      knownProxyPrefix: false,
      verifiedGoodBot: false,
      asnType: null,
      asn: null,
    });
    assert.equal(verdict.proxy, false);
    assert.equal(verdict.proxy_type, null);
    assert.equal(verdict.confidence, 'low');
    assert.match(verdict.reason, /no proxy evidence/);
  });

  check('C3', 'a non-evidence ASN label (ISP/mobile) never implies proxy', () => {
    for (const asnType of ['isp', 'mobile', 'consumer_isp']) {
      // 'consumer_isp' contains a residential token; use only labels with no
      // residential token here to keep this assertion about absence of evidence.
      if (asnType === 'consumer_isp') continue;
      const verdict = resolveProxyDetails({ asnType, asn: 12345 });
      assert.equal(verdict.proxy, false, `asnType=${asnType}`);
      assert.equal(verdict.proxy_type, null);
    }
  });

  check('C4', 'a hostile getter never throws and degrades to no evidence', () => {
    let verdict: ProxyDetails | undefined;
    assert.doesNotThrow(() => {
      verdict = resolveProxyDetails(hostileInput());
    });
    assert.equal(verdict?.proxy, false);
    assert.equal(verdict?.proxy_type, null);
  });

  section('D. Residential requires an explicit signal');

  check('D1', 'a lone VPN signal yields proxy:true with an unknown type', () => {
    const verdict = resolveProxyDetails({ vpn: true });
    assert.equal(verdict.proxy, true);
    assert.equal(verdict.proxy_type, null);
    assert.equal(verdict.confidence, 'medium');
  });

  check('D2', 'knownProxyPrefix => residential with high confidence', () => {
    const verdict = resolveProxyDetails({ knownProxyPrefix: true });
    assert.equal(verdict.proxy, true);
    assert.equal(verdict.proxy_type, 'residential');
    assert.equal(verdict.confidence, 'high');
    assert.match(verdict.reason, /known proxy prefix/);
  });

  check('D3', 'explicit residential ASN label => residential with medium confidence', () => {
    for (const asnType of ['residential', 'residential_rotating', '  RESIDENTIAL ', 'home_broadband']) {
      const verdict = resolveProxyDetails({ asnType });
      assert.equal(verdict.proxy, true, `asnType=${asnType}`);
      assert.equal(verdict.proxy_type, 'residential', `asnType=${asnType}`);
      assert.equal(verdict.confidence, 'medium');
    }
  });

  check('D4', 'an ISP/hosting ASN + VPN still never claims residential', () => {
    const verdict = resolveProxyDetails({ asnType: 'isp', vpn: true, asn: 12345 });
    assert.equal(verdict.proxy, true);
    assert.equal(verdict.proxy_type, null);
  });

  section('E. Parity divergence diagnostics');

  check('E1', 'a proxy-flag divergence is reported', () => {
    const resolved = resolveProxyDetails({ datacenterResult: true });
    const issues = proxyDetailsParityIssue(false, resolved);
    assert.ok(
      issues.some((issue) => issue.includes('proxy divergence: existing=false, resolved=true')),
      JSON.stringify(issues)
    );
  });

  check('E2', 'a proxy_type divergence is reported (legacy aliases normalized)', () => {
    const resolved = resolveProxyDetails({ knownProxyPrefix: true }); // residential
    const issues = proxyDetailsParityIssue({ proxy: true, proxy_type: 'datacenter' }, resolved);
    assert.ok(
      issues.some((issue) => issue.includes('proxy_type divergence') && issue.includes('data_center')),
      JSON.stringify(issues)
    );
  });

  check('E3', 'matching legacy values produce no issues', () => {
    const resolved = resolveProxyDetails({ datacenterResult: true });
    assert.deepEqual(proxyDetailsParityIssue({ proxy: true, proxy_type: 'datacenter' }, resolved), []);
    assert.deepEqual(proxyDetailsParityIssue(true, resolved), []);
  });

  check('E4', 'legacy "none" normalizes to null and matches a no-proxy verdict', () => {
    const resolved = resolveProxyDetails({});
    assert.deepEqual(proxyDetailsParityIssue({ proxy: false, proxy_type: 'none' }, resolved), []);
  });

  check('E5', 'unrecognized legacy shapes / missing resolved yield informational issues', () => {
    const resolved = resolveProxyDetails({});
    assert.ok(proxyDetailsParityIssue('not-a-signal', resolved).some((i) => i.includes('unrecognized shape')));
    assert.ok(proxyDetailsParityIssue(false, null).some((i) => i.includes('missing or invalid')));
    // Unknown proxy_type strings are skipped, not flagged as divergence.
    assert.deepEqual(
      proxyDetailsParityIssue({ proxy: false, proxy_type: 'mystery_type' }, resolveProxyDetails({})),
      []
    );
  });

  check('E6', 'parityIssue never throws on hostile inputs', () => {
    let issues: string[] | undefined;
    assert.doesNotThrow(() => {
      issues = proxyDetailsParityIssue(hostileInput(), resolveProxyDetails({}));
    });
    assert.ok(Array.isArray(issues));
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

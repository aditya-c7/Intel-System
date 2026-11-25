import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkLightDistance, normalizeRtt, resolveProxyTruth } from '../src/lib/networkTruth.ts';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/network-truth.json', import.meta.url), 'utf8')) as {
  schema_version: number;
  frozen: boolean;
  cases: Array<{ id: string; name: string; input: Record<string, unknown>; expected: Record<string, unknown> }>;
};

let passed = 0;
let failed = 0;
function check(id: string, name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`PASS  ${id} ${name}`);
  } catch (error) {
    failed++;
    console.log(`FAIL  ${id} ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

assert.equal(fixture.schema_version, 2);
assert.equal(fixture.frozen, true);

for (const item of fixture.cases) {
  check(item.id, item.name, () => {
    const input = item.input;
    if (item.id.startsWith('NT-01') || item.id.startsWith('NT-02') || item.id.startsWith('NT-03') || item.id.startsWith('NT-04')) {
      const result = normalizeRtt(input as never);
      for (const [key, value] of Object.entries(item.expected)) {
        assert.deepEqual((result as unknown as Record<string, unknown>)[key], value, `${key}`);
      }
    } else if (item.id.startsWith('NT-05') || item.id.startsWith('NT-06') || item.id.startsWith('NT-07') || item.id.startsWith('NT-08')) {
      const result = resolveProxyTruth(input as never);
      for (const [key, value] of Object.entries(item.expected)) {
        assert.deepEqual((result as unknown as Record<string, unknown>)[key], value, `${key}`);
      }
    } else {
      const result = checkLightDistance(input as never);
      for (const [key, value] of Object.entries(item.expected)) {
        assert.deepEqual((result as unknown as Record<string, unknown>)[key], value, `${key}`);
      }
    }
  });
}

check('NT-H1', 'hostile inputs never throw', () => {
  assert.doesNotThrow(() => normalizeRtt(null));
  assert.doesNotThrow(() => resolveProxyTruth('x' as never));
  assert.doesNotThrow(() => checkLightDistance([] as never));
});

check('NT-H2', 'transport selects one RTT field only', () => {
  const r = normalizeRtt({ httpProtocol: 'HTTP/3', clientTcpRtt: 99, clientQuicRtt: 10 });
  assert.equal(r.rtt_ms, 10);
  assert.equal(r.rtt_source, 'clientQuicRtt');
});

check('NT-H3', 'light distance never claims too slow', () => {
  const r = checkLightDistance({ rttMs: 2000, claimedDistanceKm: 3000 });
  assert.equal(r.too_fast_for_distance, false);
  assert.match(r.note, /never a VPN\/proxy verdict/);
});

console.log(`\nnetwork-truth: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;

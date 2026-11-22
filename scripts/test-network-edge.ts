/**
 * Network-edge shadow suite (dependency-free).
 *
 *   npx tsx scripts/test-network-edge.ts
 *
 * Covers the JA4H-style header digest (determinism, order sensitivity, duplicate
 * counting, non-reversibility, hostile input), the edge-derived TLS-lite vector
 * (labelling, additive normalization, no fabricated values), and the combined
 * network-layer hash (explicit 'unavailable', partial availability, determinism).
 */
import {
  EDGE_TLS_LABEL,
  TLS_FIELDS,
  ja4hStyleHash,
  networkLayerDetail,
  networkLayerHash,
  tlsLiteVector,
  type Ja4hStyleInput,
  type NetworkLayerInput,
  type TlsLiteInput,
} from '../src/lib/networkEdge.ts';

let passed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail = ''): void {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}${detail ? ` (${detail})` : ''}`);
    return;
  }
  failures.push(name);
  console.log(`  FAIL  ${name}${detail ? ` (${detail})` : ''}`);
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

function noThrow<T>(fn: () => T): T | null {
  try {
    return fn();
  } catch {
    return null;
  }
}

const HEADERS = {
  method: 'GET',
  version: 'HTTP/2',
  headerNames: ['accept', 'user-agent', 'accept-language'],
  acceptLanguage: 'en-US,en;q=0.9',
  cookiePresent: false,
  refererPresent: true,
} satisfies Ja4hStyleInput;

const TLS: TlsLiteInput = {
  tlsVersion: 'TLS 1.3',
  ciphersSha1: 'a'.repeat(40),
  extensionsSha1: 'b'.repeat(40),
  requestPriority: 'u=0, i',
  edgeL4: 'QUIC',
};

/* -------------------------------------------------------------------------- */
/* ja4hStyleHash                                                               */
/* -------------------------------------------------------------------------- */
section('ja4hStyleHash — JA4H-style, NOT JA3/JA4');

const base = ja4hStyleHash(HEADERS);
check('returns a fixed-width 32-character lowercase hex digest', /^[0-9a-f]{32}$/.test(base), base);
check('same input is deterministic', base === ja4hStyleHash(HEADERS));

check(
  'HTTP method is case-normalized (GET == get)',
  base === ja4hStyleHash({ ...HEADERS, method: 'get' })
);
check(
  'header names are case-normalized (Accept == accept)',
  base === ja4hStyleHash({ ...HEADERS, headerNames: ['ACCEPT', 'USER-AGENT', 'ACCEPT-LANGUAGE'] })
);

const reordered = ja4hStyleHash({
  ...HEADERS,
  headerNames: ['user-agent', 'accept', 'accept-language'],
});
check('header ORDER is preserved (swapping two names changes the hash)', reordered !== base);

const duplicate = ja4hStyleHash({ ...HEADERS, headerNames: ['accept', 'accept'] });
const single = ja4hStyleHash({ ...HEADERS, headerNames: ['accept'] });
check('duplicates are counted (two "accept" != one "accept")', duplicate !== single);
check(
  'duplicate count is distinct from a different header name',
  duplicate !== ja4hStyleHash({ ...HEADERS, headerNames: ['accept', 'user-agent'] })
);

check('changing the method changes the hash', ja4hStyleHash({ ...HEADERS, method: 'POST' }) !== base);
check('changing the version changes the hash', ja4hStyleHash({ ...HEADERS, version: 'HTTP/1.1' }) !== base);
check(
  'changing Accept-Language changes the hash',
  ja4hStyleHash({ ...HEADERS, acceptLanguage: 'fr-FR' }) !== base
);
check('cookie presence toggles the hash', ja4hStyleHash({ ...HEADERS, cookiePresent: true }) !== base);
check(
  'referer presence toggles the hash',
  ja4hStyleHash({ ...HEADERS, refererPresent: false }) !== base
);

const emptyHash = ja4hStyleHash({});
const explicitUnavailable = ja4hStyleHash({
  method: 'unavailable',
  version: 'unavailable',
  headerNames: [],
  acceptLanguage: 'unavailable',
  cookiePresent: false,
  refererPresent: false,
});
check(
  'missing fields are encoded as explicit "unavailable", never invented defaults',
  emptyHash === explicitUnavailable,
  emptyHash
);

const secret = 'X-Super-Secret-Header-9f3c1';
const secretHash = ja4hStyleHash({ ...HEADERS, headerNames: [secret] });
check('digest is non-reversible (raw header value is not embedded)', !secretHash.includes(secret));

const hostileHashes = noThrow(() => [
  ja4hStyleHash(null as unknown as Ja4hStyleInput),
  ja4hStyleHash(42 as unknown as Ja4hStyleInput),
  ja4hStyleHash('GET' as unknown as Ja4hStyleInput),
  ja4hStyleHash({ method: 123 as unknown as string, headerNames: 7 as unknown as string[] }),
  ja4hStyleHash({ headerNames: [null, 5, {}, {}] as unknown as string[] }),
]);
check(
  'hostile field types do not throw and always return a string',
  hostileHashes !== null && hostileHashes.every((h) => typeof h === 'string' && h.length > 0)
);

const throwingGetter = noThrow(() =>
  ja4hStyleHash({
    get method(): string {
      throw new Error('hostile getter');
    },
    version: 'HTTP/2',
  })
);
check('a throwing getter is contained and yields "unavailable"', throwingGetter === 'unavailable', throwingGetter ?? 'threw');

const hostileNames = noThrow(() =>
  ja4hStyleHash({ headerNames: [null, 'accept', {}, 'accept'] as unknown as string[] })
);
check(
  'hostile header-name arrays are counted deterministically without throwing',
  hostileNames !== null &&
    hostileNames === ja4hStyleHash({ headerNames: [null, 'accept', {}, 'accept'] as unknown as string[] })
);

/* -------------------------------------------------------------------------- */
/* tlsLiteVector — edge-derived TLS components, NEVER JA3/JA4                 */
/* -------------------------------------------------------------------------- */
section('tlsLiteVector — edge-derived TLS components');

const vector = tlsLiteVector(TLS);
check('label is exactly "edge-derived TLS components"', vector.label === EDGE_TLS_LABEL, vector.label);
check(
  'serialized vector makes no JA3/JA4 claim',
  !/ja\s*[-_]?\s*[34]\b/i.test(JSON.stringify(vector)),
  JSON.stringify(vector)
);
check(
  'all five supplied fields are reported available',
  vector.available.length === TLS_FIELDS.length && vector.unavailable.length === 0
);
check(
  'every component is a bounded weight in [0,1)',
  TLS_FIELDS.every((f) => vector.components[f] >= 0 && vector.components[f] < 1)
);
check(
  'score is the mean of additive components and bounded [0,1)',
  Math.abs(vector.score - TLS_FIELDS.reduce((s, f) => s + vector.components[f], 0) / TLS_FIELDS.length) < 1e-6 &&
    vector.score >= 0 &&
    vector.score < 1,
  String(vector.score)
);

const emptyVector = tlsLiteVector({});
check(
  'all-missing input lists every field as unavailable with zero weights',
  emptyVector.available.length === 0 &&
    emptyVector.unavailable.length === TLS_FIELDS.length &&
    TLS_FIELDS.every((f) => emptyVector.components[f] === 0),
  JSON.stringify(emptyVector.unavailable)
);
check(
  'all-missing input yields "unavailable" digest and zero score — no fabricated fingerprint',
  emptyVector.digest === 'unavailable' && emptyVector.score === 0
);

const badSha = tlsLiteVector({ ciphersSha1: 'deadbeef', extensionsSha1: 'xyz' });
check(
  'malformed SHA-1 values are treated as unavailable, not hashed as real data',
  badSha.unavailable.includes('ciphersSha1') &&
    badSha.unavailable.includes('extensionsSha1') &&
    badSha.components.ciphersSha1 === 0 &&
    badSha.components.extensionsSha1 === 0
);
check(
  'valid 40-hex SHA-1 is accepted case-insensitively',
  tlsLiteVector({ ciphersSha1: 'A'.repeat(40) }).digest === tlsLiteVector({ ciphersSha1: 'a'.repeat(40) }).digest
);

check('TLS vector is deterministic', JSON.stringify(tlsLiteVector(TLS)) === JSON.stringify(vector));
check(
  'changing a TLS component changes the vector digest',
  tlsLiteVector({ ...TLS, tlsVersion: 'TLS 1.2' }).digest !== vector.digest
);

const hostileVector = noThrow(() => tlsLiteVector(null as unknown as TlsLiteInput));
check(
  'hostile TLS input does not throw and reports all-unavailable vector',
  hostileVector !== null && hostileVector.digest === 'unavailable' && hostileVector.label === EDGE_TLS_LABEL
);

/* -------------------------------------------------------------------------- */
/* networkLayerHash / networkLayerDetail                                      */
/* -------------------------------------------------------------------------- */
section('networkLayerHash — combined, no fabricated values');

const combined: NetworkLayerInput = { ja4h: HEADERS, tls: TLS };
const combinedHash = networkLayerHash(combined);
check('combined hash is a fixed-width digest when data is available', /^[0-9a-f]{32}$/.test(combinedHash), combinedHash);
check('combined hash is deterministic', combinedHash === networkLayerHash(combined));
check(
  'changing the JA4H layer changes the combined hash',
  networkLayerHash({ ...combined, ja4h: { ...HEADERS, method: 'POST' } }) !== combinedHash
);
check(
  'changing the TLS layer changes the combined hash',
  networkLayerHash({ ...combined, tls: { ...TLS, tlsVersion: 'TLS 1.2' } }) !== combinedHash
);

check(
  'no inputs at all yields the literal "unavailable" (never a fake fingerprint)',
  networkLayerHash({}) === 'unavailable' && networkLayerHash(null as unknown as NetworkLayerInput) === 'unavailable'
);

const tlsOnly = networkLayerDetail({ tls: TLS });
check(
  'with only TLS data, the ja4h layer is explicitly "unavailable"',
  tlsOnly.ja4h === 'unavailable' && tlsOnly.unavailable.includes('ja4h') && !tlsOnly.unavailable.includes('tls')
);
check(
  'partial availability still emits a real combined digest',
  tlsOnly.available && /^[0-9a-f]{32}$/.test(tlsOnly.hash)
);

const ja4hOnly = networkLayerDetail({ ja4h: HEADERS });
check(
  'with only header data, the TLS layer is explicitly "unavailable"',
  ja4hOnly.tls.digest === 'unavailable' && ja4hOnly.unavailable.includes('tls')
);

check(
  'detail.ja4h matches the standalone JA4H-style digest',
  networkLayerDetail(combined).ja4h === ja4hStyleHash(HEADERS)
);
check(
  'combined digest is non-reversible (raw tokens are not embedded)',
  !combinedHash.includes(secret) && !combinedHash.includes('QUIC') && !combinedHash.includes('HTTP/2')
);

const hostileCombined = noThrow(() => networkLayerDetail({ ja4h: 5 as unknown as Ja4hStyleInput, tls: 'x' as unknown as TlsLiteInput }));
check(
  'hostile combined input does not throw and degrades to "unavailable"',
  hostileCombined !== null && hostileCombined.hash === 'unavailable' && hostileCombined.available === false
);

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log(`FAILED: ${failures.join(' | ')}`);
  process.exit(1);
}

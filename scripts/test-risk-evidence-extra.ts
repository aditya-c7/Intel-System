/**
 * Informational extra-evidence regression suite (dependency-free).
 *
 *   npx tsx scripts/test-risk-evidence-extra.ts
 *
 * Pins six properties of `buildExtraEvidenceLines`: fixed detector order, one line per active
 * flag, the informational `{ family, points: 0, reason, label }` shape, determinism, non-throwing
 * behavior on hostile input, and strict neutrality of the 0-10 headline math.
 */
import { buildExtraEvidenceLines, type ExtraEvidenceInput, type ExtraEvidenceLine } from '../src/lib/riskEvidenceExtra.ts';
import { buildGradedRiskLedger, score10FromScore100 } from '../src/lib/riskLedger.ts';
import { buildRiskLedger, type RiskEvidenceLine, type RiskFamily } from '../src/lib/telemetryContract.ts';

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

const ALL_TRUE: ExtraEvidenceInput = {
  spoofedBot: true,
  gpuUnreliable: true,
  audioNoisy: true,
  privacyNoise: true,
  proximityDenied: true,
  activeCdp: true,
};

const EXPECTED_COMPONENTS = [
  'extra.spoofed_bot',
  'extra.gpu_unreliable',
  'extra.audio_noisy',
  'extra.privacy_noise',
  'extra.proximity_denied',
  'extra.active_cdp',
] as const;

const EXPECTED_FAMILIES: readonly RiskFamily[] = [
  'automation',
  'environment',
  'environment',
  'tampering',
  'environment',
  'automation',
];

const VALID_FAMILIES = new Set<string>(['automation', 'tampering', 'network', 'environment', 'velocity']);

function componentsOf(lines: readonly ExtraEvidenceLine[]): string[] {
  return lines.map((line) => line.component);
}

/* -------------------------------------------------------------------------- */
/* Empty / default inputs                                                      */
/* -------------------------------------------------------------------------- */
section('Empty and default inputs');

check('no argument yields no lines', buildExtraEvidenceLines().length === 0);
check('undefined input yields no lines', buildExtraEvidenceLines(undefined).length === 0);
check('null input yields no lines', buildExtraEvidenceLines(null).length === 0);
check('empty object yields no lines', buildExtraEvidenceLines({}).length === 0);

const allFalse: ExtraEvidenceInput = {
  spoofedBot: false,
  gpuUnreliable: false,
  audioNoisy: false,
  privacyNoise: false,
  proximityDenied: false,
  activeCdp: false,
};
check('all-false input yields no lines', buildExtraEvidenceLines(allFalse).length === 0);

/* -------------------------------------------------------------------------- */
/* One line per active flag                                                    */
/* -------------------------------------------------------------------------- */
section('One line per active flag');

const singleFlags: readonly (keyof ExtraEvidenceInput)[] = [
  'spoofedBot',
  'gpuUnreliable',
  'audioNoisy',
  'privacyNoise',
  'proximityDenied',
  'activeCdp',
];
singleFlags.forEach((flag, index) => {
  const lines = buildExtraEvidenceLines({ [flag]: true });
  check(
    `${flag} alone yields exactly its own line`,
    lines.length === 1 &&
      lines[0].component === EXPECTED_COMPONENTS[index] &&
      lines[0].family === EXPECTED_FAMILIES[index] &&
      lines[0].points === 0,
    JSON.stringify(lines)
  );
});

const allLines = buildExtraEvidenceLines(ALL_TRUE);
check('all six flags yield exactly six lines', allLines.length === 6, String(allLines.length));
check(
  'detector order is fixed and deterministic',
  JSON.stringify(componentsOf(allLines)) === JSON.stringify(EXPECTED_COMPONENTS),
  componentsOf(allLines).join(', ')
);
check(
  'families match the fixed detector table',
  JSON.stringify(allLines.map((line) => line.family)) === JSON.stringify(EXPECTED_FAMILIES)
);

/* -------------------------------------------------------------------------- */
/* Informational shape                                                         */
/* -------------------------------------------------------------------------- */
section('Informational shape');

check(
  'every line carries points exactly 0',
  allLines.every((line) => line.points === 0 && Object.is(line.points, 0))
);
check(
  'every line has a non-empty reason',
  allLines.every((line) => typeof line.reason === 'string' && line.reason.trim().length > 0)
);
check(
  'every reason explicitly states informational / not scored',
  allLines.every((line) => /informational/i.test(line.reason) && /not scored/i.test(line.reason))
);
check(
  'every line has a non-empty label',
  allLines.every((line) => typeof line.label === 'string' && line.label.trim().length > 0)
);
check(
  'every line has a non-empty component machine key',
  allLines.every((line) => typeof line.component === 'string' && line.component.trim().length > 0)
);
check(
  'every family is a canonical RiskFamily',
  allLines.every((line) => VALID_FAMILIES.has(line.family))
);
check('components are unique', new Set(componentsOf(allLines)).size === 6);
check('labels are unique', new Set(allLines.map((line) => line.label)).size === 6);
check(
  'every line is a structurally valid RiskEvidenceLine',
  allLines.every(
    (line: ExtraEvidenceLine): line is ExtraEvidenceLine & RiskEvidenceLine =>
      typeof line.family === 'string' && typeof line.component === 'string' && typeof line.points === 'number' && typeof line.reason === 'string'
  )
);

/* -------------------------------------------------------------------------- */
/* Determinism / purity                                                        */
/* -------------------------------------------------------------------------- */
section('Determinism and purity');

const first = buildExtraEvidenceLines(ALL_TRUE);
const second = buildExtraEvidenceLines(ALL_TRUE);
check('two calls with the same input are deeply equal', JSON.stringify(first) === JSON.stringify(second));
check('two calls return distinct arrays and objects', first !== second && first[0] !== second[0]);

const inputSnapshot = JSON.stringify(ALL_TRUE);
buildExtraEvidenceLines(ALL_TRUE);
check('input object is not mutated', JSON.stringify(ALL_TRUE) === inputSnapshot);

/* -------------------------------------------------------------------------- */
/* Hostile input is non-throwing                                               */
/* -------------------------------------------------------------------------- */
section('Hostile input');

const hostileGetters = {
  get spoofedBot(): boolean {
    throw new Error('spoofedBot getter exploded');
  },
  gpuUnreliable: true,
  get audioNoisy(): boolean {
    throw new Error('audioNoisy getter exploded');
  },
  privacyNoise: true,
  proximityDenied: false,
  activeCdp: true,
} as unknown as ExtraEvidenceInput;
const hostileResult = noThrow(() => buildExtraEvidenceLines(hostileGetters));
check(
  'throwing getters are contained; other flags still build',
  hostileResult !== null &&
    JSON.stringify(componentsOf(hostileResult)) ===
      JSON.stringify(['extra.gpu_unreliable', 'extra.privacy_noise', 'extra.active_cdp']),
  hostileResult ? componentsOf(hostileResult).join(', ') : 'threw'
);

const throwingProxy = new Proxy(
  {},
  {
    get(): never {
      throw new Error('proxy trap exploded');
    },
  }
) as unknown as ExtraEvidenceInput;
const proxyResult = noThrow(() => buildExtraEvidenceLines(throwingProxy));
check('a fully throwing Proxy yields no lines without throwing', proxyResult !== null && proxyResult.length === 0);

const truthyJunk = {
  spoofedBot: 1,
  gpuUnreliable: 'yes',
  audioNoisy: {},
  privacyNoise: [],
  proximityDenied: 0,
  activeCdp: new Boolean(true),
} as unknown as ExtraEvidenceInput;
check('truthy non-boolean values are inert (strict true only)', buildExtraEvidenceLines(truthyJunk).length === 0);

const stringInput = noThrow(() => buildExtraEvidenceLines('spoofedBot' as unknown as ExtraEvidenceInput));
check('string primitive input is inert and non-throwing', stringInput !== null && stringInput.length === 0);

const numberInput = noThrow(() => buildExtraEvidenceLines(123 as unknown as ExtraEvidenceInput));
check('number primitive input is inert and non-throwing', numberInput !== null && numberInput.length === 0);

const arrayInput = noThrow(() => buildExtraEvidenceLines([true, true] as unknown as ExtraEvidenceInput));
check('array input is inert and non-throwing', arrayInput !== null && arrayInput.length === 0);

/* -------------------------------------------------------------------------- */
/* 0-10 headline math is untouched                                             */
/* -------------------------------------------------------------------------- */
section('Score neutrality');

const neutralLedger = buildRiskLedger(allLines as readonly RiskEvidenceLine[]);
check(
  'extra lines alone produce a zero ledger',
  neutralLedger.raw_score === 0 &&
    neutralLedger.score_0_100 === 0 &&
    neutralLedger.automation === 0 &&
    neutralLedger.tampering === 0 &&
    neutralLedger.network === 0 &&
    neutralLedger.environment === 0 &&
    neutralLedger.velocity === 0 &&
    neutralLedger.tier === 'Low',
  JSON.stringify(neutralLedger)
);

const base = buildGradedRiskLedger({
  automation: { tierA: true },
  network: { vpnOrRelay: true },
  environment: { swiftshader: true, ephemeralOrPrivateStorage: true },
});
const merged = buildRiskLedger([...base.evidence_ledger, ...(allLines as readonly RiskEvidenceLine[])]);
check('appending extra lines preserves the 0-100 composite', merged.score_0_100 === base.score_0_100, `${merged.score_0_100} vs ${base.score_0_100}`);
check('appending extra lines preserves the 0-10 headline', score10FromScore100(merged.score_0_100) === base.score10, `${base.score10}`);
check('appending extra lines preserves the tier', merged.tier === base.risk_tier && base.risk_tier === 'High');
check('appending extra lines preserves all per-family totals', merged.automation === base.automation && merged.network === base.network && merged.environment === base.environment);

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log(`FAILED: ${failures.join(' | ')}`);
  process.exit(1);
}

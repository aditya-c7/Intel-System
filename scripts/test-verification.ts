/**
 * Cross-session verification harness (plan section 6.2).
 *
 * Dependency-free: pure assertions over the shared matching engine and the
 * server confidence scorer, so it runs anywhere `tsx` runs.
 *
 *   npm run test:verify
 *
 * Each case maps to a scenario in the architectural plan:
 *   T-02 storage wipe / incognito persistence
 *   T-03 browser major upgrade drift
 *   T-04 cross-browser same-machine switch
 *   T-06 Brave shields vs uniform canvas spoofing
 * plus the individual similarity kernels they depend on.
 */
import {
  compareFingerprints,
  hammingSimilarity64,
  jaccardSet,
  simhash64,
  type ComparisonInput,
  type MatchMode,
} from '../src/shared/matching/compareFingerprints';
import { scoreConfidence } from '../src/server/identity/confidenceScorer';
import {
  CALIBRATION_MAX_ECE,
  CALIBRATION_MIN_LABELED_PAIRS,
  computeHonestIdentityConfidence,
  confidenceBandForScore,
} from '../src/lib/rarityHonesty';
import { buildGradedRiskLedger } from '../src/lib/riskLedger';
import { normalizeGpuRenderer } from '../src/client/signals/webgl';
import {
  RISK_FAMILY_CAPS,
  LSH_CONFIG,
  buildRiskLedger,
  clopperPearsonUpperBound,
  decideRarity,
  isSecureRequest,
  type RiskEvidenceLine,
} from '../src/lib/telemetryContract';
import { canonicalTimezone, timezonesEquivalent } from '../src/lib/timezone';
import {
  gpuObservationIsHardwareAnchor,
  resolveGpuObservation,
  type GpuObservation,
} from '../src/lib/specInvariants';

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

const CANVAS_GEO = 'db3c1462576a399a03ae93d0ab9eb5c4';
const CANVAS_TEXT = '70c3d3f7eb4408dc37a6bf8af1c51029';
const AUDIO_SUM = 124.04347745512496;

/** A complete Windows 11 / Chrome desktop profile: every family comparable. */
function windowsProfile(): ComparisonInput {
  return {
    gpu: { normalizedGpu: 'nvidia geforce rtx 4070', invariantLimitsHash: 'limits-16384-32767' },
    cpu: { arch: 'x86_64', cores: 8, memoryGb: 8, osFamily: 'Windows' },
    screen: { width: 1920, height: 1080, dpr: 1, colorDepth: 24, touch: 0 },
    timezone: { name: 'Asia/Kolkata', offsetMinutes: -330 },
    fonts: {
      list: ['Arial', 'Calibri', 'Cambria', 'Segoe UI', 'Tahoma', 'Verdana'],
      hash: 'font-hash-win',
      platformClass: 'windows',
    },
    mediaDevices: { audioIn: 2, audioOut: 3, video: 1 },
    canvas: { geometry: CANVAS_GEO, text: CANVAS_TEXT },
    webgl: { extensionsHash: 'ext-hash', paramsHash: 'param-hash', shaderPrecisionHash: 'prec-hash' },
    audio: { sum: AUDIO_SUM, baseLatency: 0.005333333333333333 },
    fontPrefs: {
      widths: { default: 147.5625, sans: 144.015625, mono: 133.0625 },
      emojiRectHash: 'emoji-rect',
    },
    misc: { mathHash: 'math-hash', errorStackHash: 'error-stack-hash' },
    versions: { browserFamily: 'chrome', browserMajor: 153, osVersionMajor: 11 },
  };
}

/** Clone helper that keeps every nested object independent. */
function clone(input: ComparisonInput): ComparisonInput {
  return JSON.parse(JSON.stringify(input)) as ComparisonInput;
}

function hardViolations(result: { constraintViolations: string[] }): string[] {
  return result.constraintViolations.filter((v) => v.startsWith('hard_') || v.includes('mismatch'));
}

/* -------------------------------------------------------------------------- */
/* Kernels                                                                     */
/* -------------------------------------------------------------------------- */

section('Kernels: Jaccard, SimHash, Hamming');

check('jaccard identical sets -> 1', jaccardSet(['Arial', 'Calibri'], ['arial', 'calibri']) === 1);
check('jaccard disjoint sets -> 0', jaccardSet(['Arial'], ['Wingdings']) === 0);
check(
  'jaccard half overlap -> 1/3',
  Math.abs(jaccardSet(['a', 'b'], ['b', 'c']) - 1 / 3) < 1e-12,
  String(jaccardSet(['a', 'b'], ['b', 'c'])),
);

const featuresA = { 'MAX_TEXTURE_SIZE': '16384', 'MAX_VIEWPORT_DIMS': '32767,32767', vendor: 'nvidia' };
const featuresB = { vendor: 'nvidia', 'MAX_VIEWPORT_DIMS': '32767,32767', 'MAX_TEXTURE_SIZE': '16384' };
const simA = simhash64(featuresA);
const simB = simhash64(featuresB);
check('simhash is key-order independent', simA === simB, `${simA} vs ${simB}`);
check('simhash of identical features -> similarity 1', hammingSimilarity64(simA, simB) === 1);
check('simhash is 64-bit hex', /^[0-9a-f]{16}$/.test(simA), simA);
check(
  'simhash of different features drifts',
  hammingSimilarity64(simA, simhash64({ a: '1', b: '2', c: '3' })) < 1,
);

section('Kernels: fuzzy tolerances');

const zoomed = clone(windowsProfile());
zoomed.screen = { width: 1536, height: 864, dpr: 1, colorDepth: 24, touch: 0 };
const zoomResult = compareFingerprints(windowsProfile(), zoomed, 'lenient');
check(
  '1.25x browser zoom scores 0.85 on screen',
  Math.abs(zoomResult.perFamily.screen.similarity - 0.85) < 1e-9,
  String(zoomResult.perFamily.screen.similarity),
);

const audioDrift = clone(windowsProfile());
audioDrift.audio = { sum: AUDIO_SUM + 1e-6, baseLatency: 0.005333333333333333 };
const audioResult = compareFingerprints(windowsProfile(), audioDrift, 'lenient');
check(
  'sub-1e-4 audio drift scores 0.90',
  Math.abs(audioResult.perFamily.audio.similarity - 0.9) < 1e-9,
  String(audioResult.perFamily.audio.similarity),
);

section('Kernels: GPU identity normalization');

const gpuCases: Array<[string, string, string]> = [
  [
    'NVIDIA Direct3D ANGLE',
    'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11)',
    'NVIDIA GeForce RTX 4090',
  ],
  [
    'Apple Metal ANGLE',
    'ANGLE (Apple, ANGLE Metal Renderer: Apple M4, Unspecified Version)',
    'Apple M4',
  ],
  [
    'Intel Direct3D ANGLE',
    'ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)',
    'Intel UHD Graphics 630',
  ],
  [
    'nested SwiftShader ANGLE',
    'ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)',
    'SwiftShader',
  ],
  ['llvmpipe', 'llvmpipe (LLVM 17.0.6, 256 bits)', 'llvmpipe'],
  ['bare GPU name', 'Apple M2', 'Apple M2'],
];
for (const [label, raw, expected] of gpuCases) {
  const actual = normalizeGpuRenderer(raw);
  check(`gpu normalization: ${label}`, actual === expected, `${actual}`);
}
check(
  'nested parentheses never leak into the GPU identity',
  !/[()]/.test(String(normalizeGpuRenderer(gpuCases[3][1]))),
  String(normalizeGpuRenderer(gpuCases[3][1])),
);

/* -------------------------------------------------------------------------- */
/* T-02 Storage wipe / incognito                                              */
/* -------------------------------------------------------------------------- */

section('T-02 storage wipe and incognito persistence');

const stored = windowsProfile();
const incognito = clone(stored); // identical hashes, storage was cleared
const t02 = compareFingerprints(stored, incognito, 'exact');
check('exact mode matches on identical hashes', t02.match, `score ${t02.matchScore}`);
check('exact mode reaches 100', t02.matchScore === 100, String(t02.matchScore));
check('no constraint violations', t02.constraintViolations.length === 0, t02.constraintViolations.join(','));

const t02Confidence = scoreConfidence({
  match_mode: 'exact',
  match_score: 100,
  storage_healed: false,
  incognito: true,
  entropy: {
    deterministicCanvas: true,
    unmaskedWebgl: true,
    fontsCount: 6,
    deterministicAudio: true,
  },
});
check(
  'incognito confidence >= 0.960',
  t02Confidence.score >= 0.96,
  String(t02Confidence.score),
);
check('incognito stays low spoof risk', t02Confidence.spoof_likelihood === 'low');
check('incognito is not tampering', t02Confidence.tampering === false);

/* -------------------------------------------------------------------------- */
/* T-03 Browser major upgrade drift                                           */
/* -------------------------------------------------------------------------- */

section('T-03 browser major upgrade drift (Chrome 152 -> 153)');

const before = windowsProfile();
before.versions = { browserFamily: 'chrome', browserMajor: 152, osVersionMajor: 11 };
const after = clone(before);
after.versions = { browserFamily: 'chrome', browserMajor: 153, osVersionMajor: 11 };
after.canvas = { geometry: CANVAS_GEO, text: 'f0e1d2c3b4a5968778695a4b3c2d1e0f' };
after.audio = { sum: AUDIO_SUM + 0.00002, baseLatency: 0.005333333333333333 };

const t03 = compareFingerprints(before, after, 'lenient');
check('lenient mode matches after an upgrade', t03.match, `score ${t03.matchScore}`);
check('no hard constraint violations', hardViolations(t03).length === 0, hardViolations(t03).join(','));
check(
  'canvas text drift is tolerated and noted',
  t03.constraintViolations.some((v) => v.includes('drift')),
  t03.constraintViolations.join(','),
);
check('hardware still matches', t03.hardwareMatch);

const t03Confidence = scoreConfidence({
  match_mode: 'lenient',
  match_score: t03.matchScore,
  entropy: { deterministicCanvas: true, unmaskedWebgl: true, fontsCount: 12, deterministicAudio: true },
});
check(
  'upgrade confidence stays in the lenient band',
  t03Confidence.score >= 0.91 && t03Confidence.score <= 0.999,
  String(t03Confidence.score),
);

const downgrade = clone(before);
downgrade.versions = { browserFamily: 'chrome', browserMajor: 151, osVersionMajor: 11 };
const t03Down = compareFingerprints(before, downgrade, 'lenient');
check(
  'version downgrade is flagged',
  t03Down.constraintViolations.some((v) => v.includes('downgrade')),
  t03Down.constraintViolations.join(','),
);
check('version downgrade vetoes the match', t03Down.match === false, `score ${t03Down.matchScore}`);

/* -------------------------------------------------------------------------- */
/* T-04 Cross-browser same machine                                            */
/* -------------------------------------------------------------------------- */

section('T-04 cross-browser switch on the same machine');

const chrome = windowsProfile();
const firefox = clone(chrome);
/* Same physical hardware, different engine output. */
firefox.canvas = { geometry: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', text: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' };
firefox.webgl = { extensionsHash: 'ff-ext', paramsHash: 'ff-params', shaderPrecisionHash: 'ff-prec' };
firefox.audio = { sum: 35.7491455078125, baseLatency: 0.01 };
firefox.fontPrefs = { widths: { default: 149.25, sans: 146.5, mono: 135.5 }, emojiRectHash: 'ff-emoji' };
firefox.misc = { mathHash: 'ff-math', errorStackHash: 'ff-error' };
firefox.versions = { browserFamily: 'firefox', browserMajor: 149, osVersionMajor: 11 };

const t04 = compareFingerprints(chrome, firefox, 'cross-browser');
check('cross-browser mode matches the same machine', t04.match, `score ${t04.matchScore}`);
check('cross-browser mode reports a hardware match', t04.hardwareMatch);
check('cross-browser score >= 85', t04.matchScore >= 85, String(t04.matchScore));
check('no hard constraint violations', hardViolations(t04).length === 0, hardViolations(t04).join(','));
check(
  'engine families carry zero weight in cross-browser mode',
  t04.perFamily.canvas.weight === 0 &&
    t04.perFamily.webgl.weight === 0 &&
    t04.perFamily.audio.weight === 0 &&
    t04.perFamily.fontPrefs.weight === 0 &&
    t04.perFamily.misc.weight === 0,
  String(t04.perFamily.canvas.weight),
);
check(
  'engine drift cannot lower the cross-browser score',
  compareFingerprints(chrome, clone(chrome), 'cross-browser').matchScore === t04.matchScore,
  `${t04.matchScore}`,
);

const t04Confidence = scoreConfidence({
  match_mode: 'cross_browser',
  match_score: t04.matchScore,
  entropy: { deterministicCanvas: true, unmaskedWebgl: true, fontsCount: 12 },
});
check('cross-browser confidence >= 0.850', t04Confidence.score >= 0.85, String(t04Confidence.score));

const differentMachine = clone(chrome);
differentMachine.gpu = { normalizedGpu: 'intel iris xe', invariantLimitsHash: 'limits-8192-16384' };
differentMachine.screen = { width: 1366, height: 768, dpr: 1, colorDepth: 24, touch: 0 };
differentMachine.cpu = { arch: 'x86_64', cores: 4, memoryGb: 4, osFamily: 'Windows' };
const t04Negative = compareFingerprints(chrome, differentMachine, 'cross-browser');
check(
  'a different machine does not match in cross-browser mode',
  t04Negative.match === false,
  `score ${t04Negative.matchScore}`,
);

/* -------------------------------------------------------------------------- */
/* T-06 Brave shields vs uniform canvas spoofing                              */
/* -------------------------------------------------------------------------- */

section('T-06 Brave shields vs uniform canvas noise');

const braveA = clone(windowsProfile());
braveA.audio = { sum: 124.04321, baseLatency: 0.005333333333333333, braveFlag: true };
const braveB = clone(windowsProfile());
braveB.audio = { sum: 123.99812, baseLatency: 0.005333333333333333, braveFlag: true };
/* A version jump larger than the drift window keeps the drift allowance off, so
 * the Brave audio exclusion is observable on its own. */
braveB.versions = { browserFamily: 'chrome', browserMajor: 160, osVersionMajor: 11 };
const t06a = compareFingerprints(braveA, braveB, 'strict');
check('Brave farbling still matches the same profile', t06a.match, `score ${t06a.matchScore}`);
check(
  'Brave audio farbling is excluded from the denominator',
  t06a.diffVector[8] === -1,
  `diffVector[audio]=${t06a.diffVector[8]}`,
);

const t06aConfidence = scoreConfidence({
  match_mode: 'exact',
  match_score: t06a.matchScore,
  braveShields: true,
  entropy: { deterministicCanvas: true, unmaskedWebgl: true, fontsCount: 12, deterministicAudio: false },
});
check('Brave confidence >= 0.920', t06aConfidence.score >= 0.92, String(t06aConfidence.score));
check('Brave keeps low spoof risk', t06aConfidence.spoof_likelihood === 'low');
check('Brave is not tampering', t06aConfidence.tampering === false);

const t06bConfidence = scoreConfidence({
  match_mode: 'none',
  match_score: 0,
  consistencyFlags: ['canvas_noise_uniform', 'gpu_vendor_mismatch'],
  genuineSpoof: true,
  entropy: { deterministicCanvas: false, unmaskedWebgl: false, fontsCount: 8, deterministicAudio: false },
});
check('uniform canvas noise is tampering', t06bConfidence.tampering === true);
check('uniform canvas noise scores <= 0.650', t06bConfidence.score <= 0.65, String(t06bConfidence.score));
check('uniform canvas noise is high spoof risk', t06bConfidence.spoof_likelihood === 'high');
check(
  'uniform canvas noise sets a tampering ml score >= 0.85',
  t06bConfidence.tampering_ml_score >= 0.85,
  String(t06bConfidence.tampering_ml_score),
);

/* -------------------------------------------------------------------------- */
/* Mode plumbing                                                              */
/* -------------------------------------------------------------------------- */

section('Mode plumbing');

const modes: MatchMode[] = ['exact', 'strict', 'lenient', 'cross-browser', 'hardware-only', 'engine-only'];
for (const mode of modes) {
  const result = compareFingerprints(windowsProfile(), windowsProfile(), mode);
  check(`identical profiles match in ${mode} mode`, result.match, `score ${result.matchScore}`);
}

/* -------------------------------------------------------------------------- */
/* Phase 0 — frozen canonical contract baseline                               */
/* -------------------------------------------------------------------------- */

section('Phase 0 canonical contract baseline');

const capSum = Object.values(RISK_FAMILY_CAPS).reduce((sum, value) => sum + value, 0);
check('risk caps sum to 130 (clamp required)', capSum === 130, String(capSum));

function ledgerFrom(tuple: readonly [number, number, number, number, number]) {
  const names = ['automation', 'tampering', 'network', 'environment', 'velocity'] as const;
  const lines: RiskEvidenceLine[] = [];
  tuple.forEach((points, index) => {
    if (points > 0) {
      lines.push({ family: names[index], component: `baseline_${names[index]}`, points, reason: 'phase-0 fixture' });
    }
  });
  return buildRiskLedger(lines);
}

const mcpLedger = ledgerFrom([45, 0, 12, 10, 0]);
check('MCP Playwright ledger raw 67 / High', mcpLedger.raw_score === 67 && mcpLedger.score_0_100 === 67 && mcpLedger.tier === 'High', JSON.stringify(mcpLedger));
const specLedger = ledgerFrom([0, 35, 0, 0, 0]);
check('spec fuzz ledger raw 35 / Elevated', specLedger.raw_score === 35 && specLedger.tier === 'Elevated', JSON.stringify(specLedger));
const driftLedger = ledgerFrom([35, 35, 18, 4, 12]);
check('drift+proxy ledger raw 104 clamped 100 / Critical', driftLedger.raw_score === 104 && driftLedger.score_0_100 === 100 && driftLedger.tier === 'Critical', JSON.stringify(driftLedger));
const cleanLedger = ledgerFrom([0, 0, 0, 0, 0]);
check('clean human ledger 0 / Low', cleanLedger.raw_score === 0 && cleanLedger.tier === 'Low');

/* New derived headline fields: same frozen tuples, checked through the graded builder. */
const gradedFixtures = [
  { input: { automation: { tierA: true }, network: { vpnOrRelay: true }, environment: { swiftshader: true, ephemeralOrPrivateStorage: true } }, score100: 67, score10: 7, tier: 'High' },
  { input: { tampering: { tierA: true } }, score100: 35, score10: 4, tier: 'Elevated' },
  { input: { automation: { tierB: true }, tampering: { tierA: true }, network: { rotatingProxy: true }, environment: { ephemeralOrPrivateStorage: true }, velocity: { high: true } }, score100: 100, score10: 10, tier: 'Critical' },
  { input: {}, score100: 0, score10: 0, tier: 'Low' },
] as const;
for (const fixture of gradedFixtures) {
  const graded = buildGradedRiskLedger(fixture.input);
  check(
    `graded ledger ${fixture.score100}: score10=${fixture.score10} / ${fixture.tier}`,
    graded.score_0_100 === fixture.score100 &&
      graded.score10 === fixture.score10 &&
      graded.risk_tier === fixture.tier &&
      graded.tier === fixture.tier,
    JSON.stringify(graded),
  );
}

check('512-bit SimHash config locked', LSH_CONFIG.bits === 512 && LSH_CONFIG.bands === 32 && LSH_CONFIG.rows === 16);
check('singleton Clopper-Pearson upper ~4.74/n', Math.abs(clopperPearsonUpperBound(1, 1000, 0.05) - 0.00474) < 0.0005, String(clopperPearsonUpperBound(1, 1000, 0.05)));
check('rarity suppressed below N=250', decideRarity(249).status === 'suppressed');
check('rarity p95 allowed at N=250', decideRarity(250).percentile === 'p95');
check('rarity p99 unlocked at N=1000', decideRarity(1000).percentile === 'p99_plus');
check('cookie secure from forwarded https', isSecureRequest({ xForwardedProto: 'https' }) === true);
check('cookie insecure on local http', isSecureRequest({ xForwardedProto: 'http', secure: false }) === false);
check('audio baseline fixture unchanged', AUDIO_SUM === 124.04347745512496);

/* -------------------------------------------------------------------------- */
/* Confidence score mirrors — single-sourced, no fabricated numbers            */
/* -------------------------------------------------------------------------- */

section('Confidence score mirror consistency');

const mirrorGate = {
  labeledPairs: CALIBRATION_MIN_LABELED_PAIRS + 300,
  heldOutEce: CALIBRATION_MAX_ECE / 5,
};
const mirrorEvidence = {
  matchScore: 100,
  structuralAnchorRatio: 1,
  browserFamilyConsensus: true,
  osFamilyConsensus: true,
} as const;
const mirrorClean = computeHonestIdentityConfidence({
  ...mirrorGate,
  ...mirrorEvidence,
  matchStage: 'lsh_fuzzy',
  distinctStorageSeedsCount: 0,
});
const mirrorCollision = computeHonestIdentityConfidence({
  ...mirrorGate,
  ...mirrorEvidence,
  matchStage: 'lsh_fuzzy',
  distinctStorageSeedsCount: 2,
});
check(
  'honest confidence mirror matches the raw evidence score',
  mirrorClean.confidence_score === 0.65 && mirrorCollision.confidence_score === 0.45,
  `${mirrorClean.confidence_score}/${mirrorCollision.confidence_score}`,
);
check(
  'collision mirror differs by exactly 0.20',
  Math.round(
    ((mirrorClean.confidence_score ?? 0) - (mirrorCollision.confidence_score ?? 0)) * 10000
  ) / 10000 === 0.2,
);
check(
  'confidence band mirror agrees with the published tier',
  confidenceBandForScore(mirrorClean.confidence_score ?? 0) === mirrorClean.confidence_tier &&
    confidenceBandForScore(mirrorCollision.confidence_score ?? 0) === mirrorCollision.confidence_tier,
);
check(
  'new profile keeps confidence_score null in the mirror',
  computeHonestIdentityConfidence({ ...mirrorGate, matchStage: 'new_enrollment' }).confidence_score ===
    null,
);
check(
  'legacy scoreConfidence callers still get spoof/tampering fields',
  (() => {
    const result = scoreConfidence({ match_mode: 'exact', match_score: 100, storage_healed: true });
    return (
      result.version === '2.0' &&
      typeof result.tampering === 'boolean' &&
      typeof result.tampering_ml_score === 'number' &&
      (result.spoof_likelihood === 'low' ||
        result.spoof_likelihood === 'medium' ||
        result.spoof_likelihood === 'high')
    );
  })(),
);

/* -------------------------------------------------------------------------- */
/* Tranche 0-1 — canonical timezone aliases                                    */
/* -------------------------------------------------------------------------- */

section('Tranche 0-1: timezone alias equivalence');

/** Local expected values: legacy IANA alias -> canonical IANA identifier. */
const TIMEZONE_ALIAS_EXPECTATIONS: ReadonlyArray<readonly [string, string]> = [
  ['Asia/Calcutta', 'Asia/Kolkata'],
  ['Europe/Kiev', 'Europe/Kyiv'],
  ['Asia/Katmandu', 'Asia/Kathmandu'],
  ['US/Pacific', 'America/Los_Angeles'],
];

for (const [alias, canonical] of TIMEZONE_ALIAS_EXPECTATIONS) {
  check(
    `canonical timezone ${alias} -> ${canonical}`,
    canonicalTimezone(alias) === canonical,
    String(canonicalTimezone(alias)),
  );
  check(`timezone alias equivalence ${alias} === ${canonical}`, timezonesEquivalent(alias, canonical));
}

check(
  'a shared UTC offset is not timezone equivalence (Singapore vs Hong Kong)',
  timezonesEquivalent('Asia/Singapore', 'Asia/Hong_Kong') === false,
);
check(
  'unresolvable timezones never fabricate equivalence',
  timezonesEquivalent('Unknown', 'Unknown') === false,
);

/* -------------------------------------------------------------------------- */
/* Tranche 0-1 — GPU observation honesty                                       */
/* -------------------------------------------------------------------------- */

section('Tranche 0-1: GPU observation buckets');

const SWIFTSHADER_RENDERER =
  'ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)';

const swiftObservation: GpuObservation = resolveGpuObservation(
  'Google Inc. (Google)',
  SWIFTSHADER_RENDERER,
  't16|h|e3',
);
check(
  'SwiftShader is software_or_virtual, never a hardware anchor / VM proof',
  swiftObservation === 'software_or_virtual' && gpuObservationIsHardwareAnchor(swiftObservation) === false,
  swiftObservation,
);

const maskedObservation: GpuObservation = resolveGpuObservation('', '', 't16|h|e3');
check(
  'unmasked-info extension absence with real capabilities is masked_by_privacy',
  maskedObservation === 'masked_by_privacy' && gpuObservationIsHardwareAnchor(maskedObservation) === false,
  maskedObservation,
);

const unavailableObservation: GpuObservation = resolveGpuObservation('', '', null);
check(
  'extension absence without capability data is observation_unavailable',
  unavailableObservation === 'observation_unavailable' &&
    gpuObservationIsHardwareAnchor(unavailableObservation) === false,
  unavailableObservation,
);

const hardwareObservation: GpuObservation = resolveGpuObservation(
  'NVIDIA',
  'NVIDIA GeForce RTX 4070',
  't16|h|e3',
);
check(
  'an explicit unmasked GPU is the only hardware_visible anchor',
  hardwareObservation === 'hardware_visible' && gpuObservationIsHardwareAnchor(hardwareObservation),
  hardwareObservation,
);

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log(`FAILED: ${failures.join(' | ')}`);
  process.exit(1);
}

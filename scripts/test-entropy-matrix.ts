/**
 * Entropy-matrix normalizer suite (dependency-free, shadow-only).
 *
 *   npx tsx scripts/test-entropy-matrix.ts
 *
 * Covers all nine FingerprintJS-v5-style surface normalizers: happy-path records with the
 * three-way status, canonical sorting/dedup, numeric clamping/rounding, explicit block flags,
 * hostile/wrong-typed/proxy inputs (non-throwing), and determinism (repeat calls and
 * input-order independence). No browser probes, no hashing, no risk scoring.
 */
import {
  ENTROPY_NOTES,
  FJS_V5_HIGH_VALUE_SOURCES,
  RESEARCH_ONLY_NOTE,
  normalizeAudioDriver,
  normalizeCanvasSurfaces,
  normalizeCssVector,
  normalizeDomBlockers,
  normalizeEmojiMetrics,
  normalizeFontPreferences,
  normalizeKeyboardLayout,
  normalizeMathConstants,
  normalizeWebGpuSurfaces,
  normalizeWebglSurfaces,
} from '../src/lib/entropyMatrix.ts';
import {
  EMOJI_DOMRECT_METRICS,
  FONT_PREFERENCE_PRESETS,
  FPJS15_VECTOR_KEYS,
  FJS_V5_HIGH_VALUE_FONT_FAMILIES,
  LOCATION_INFO_FIELDS,
  buildFjsV5ParitySnapshot,
} from '../src/lib/fjsV5Parity.ts';

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

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/* -------------------------------------------------------------------------- */
/* Font preferences                                                            */
/* -------------------------------------------------------------------------- */
section('normalizeFontPreferences');

const fonts = normalizeFontPreferences({ fonts: ['Arial', 'Verdana', 'arial', '  Courier New ', '', 42] });
check('fonts are canonicalized (deduped, trimmed, sorted)', fonts.status === 'ok' && same(fonts.fonts, ['Arial', 'Courier New', 'Verdana']), JSON.stringify(fonts.fonts));
check('font count mirrors normalized list', fonts.count === fonts.fonts.length, String(fonts.count));
check('a delimited font string is accepted', normalizeFontPreferences('Helvetica,Georgia|Helvetica').status === 'ok', 'string input');
check('empty font input is unavailable', normalizeFontPreferences([]).status === 'unavailable', 'empty array');
check('explicit block flag yields blocked fonts', normalizeFontPreferences({ blocked: true, fonts: ['Arial'] }).status === 'blocked', 'blocked flag');
check('fonts are order-independent (determinism)', same(fonts.fonts, normalizeFontPreferences({ fonts: ['  Courier New ', 'Verdana', 'Arial', 'arial'] }).fonts), 'shuffled input');

/* -------------------------------------------------------------------------- */
/* Emoji metrics                                                               */
/* -------------------------------------------------------------------------- */
section('normalizeEmojiMetrics');

const emoji = normalizeEmojiMetrics({ glyphs: ['😀', '🚀', '😀'], width: 17.25, height: 18 });
check('emoji glyphs deduped and width/height kept', emoji.status === 'ok' && emoji.glyphs.length === 2 && emoji.width === 17.25 && emoji.height === 18, JSON.stringify(emoji));
check('emoji width ignores non-finite values', normalizeEmojiMetrics({ glyphs: ['😀'], width: Number.NaN }).width === null, 'NaN width');
check('missing emoji data is unavailable', normalizeEmojiMetrics({}).status === 'unavailable', 'empty object');
check('emoji error flag yields blocked', normalizeEmojiMetrics({ glyphs: ['😀'], error: 'threw' }).status === 'blocked', 'error flag');

/* -------------------------------------------------------------------------- */
/* WebGL surfaces                                                              */
/* -------------------------------------------------------------------------- */
section('normalizeWebglSurfaces');

const webgl = normalizeWebglSurfaces({
  basics: { vendor: 'WebKit', renderer: 'WebKit WebGL', version: 'WebGL 1.0' },
  extensions: ['EXT_blend_minmax', 'OES_texture_float', 'EXT_blend_minmax'],
  shaderPrecision: {
    fragment: { precision: 'highp', rangeMin: 127, rangeMax: 127 },
    vertex: { precision: 'mediump', rangeMin: 15, rangeMax: 15 },
  },
});
check('webgl basics + precision normalize to ok', webgl.status === 'ok' && webgl.vendor === 'WebKit' && webgl.precision.fragment?.precision === 'highp', JSON.stringify(webgl.precision));
check('webgl extensions canonicalized', same(webgl.extensions, ['EXT_blend_minmax', 'OES_texture_float']), JSON.stringify(webgl.extensions));
check('shader precision range integers retained', webgl.precision.vertex?.rangeMin === 15 && webgl.precision.fragment?.rangeMax === 127, 'ranges');
const webglMap = normalizeWebglSurfaces({ basics: {}, extensions: { OES_texture_float: true, WEBGL_debug: false }, shaderPrecision: {} });
check('webgl extension map keeps only enabled keys', same(webglMap.extensions, ['OES_texture_float']), JSON.stringify(webglMap.extensions));
check('unmasked vendor fields are normalized', normalizeWebglSurfaces({ basics: { unmaskedVendor: 'Google Inc.', unmaskedRenderer: 'ANGLE' } }).unmaskedVendor === 'Google Inc.', 'unmasked fields');
check('empty webgl input is unavailable', normalizeWebglSurfaces({}).status === 'unavailable', 'empty object');
check('blocked webgl basics yields blocked surface', normalizeWebglSurfaces({ basics: { blocked: true }, extensions: ['X'] }).status === 'blocked', 'basics blocked');

/* -------------------------------------------------------------------------- */
/* Audio driver                                                                */
/* -------------------------------------------------------------------------- */
section('normalizeAudioDriver');

const audio = normalizeAudioDriver({ sampleRate: 48000, baseLatency: 0.00012345678, outputLatency: 0.01, maxChannelCount: 2 });
check('audio driver values normalize and latencies round to 9dp', audio.status === 'ok' && audio.sampleRate === 48000 && audio.baseLatency === 0.000123457 && audio.maxChannelCount === 2, JSON.stringify(audio));
check('out-of-range sampleRate is nulled but surface stays ok', normalizeAudioDriver({ sampleRate: -5, baseLatency: 0.002 }).sampleRate === null, 'negative sampleRate');
check('out-of-range-only audio is unavailable', normalizeAudioDriver({ sampleRate: 0 }).status === 'unavailable', 'only invalid value');
check('audio block flag yields blocked', normalizeAudioDriver({ sampleRate: 48000, blocked: true }).status === 'blocked', 'blocked flag');
check('audio empty input is unavailable', normalizeAudioDriver({}).status === 'unavailable', 'empty object');

/* -------------------------------------------------------------------------- */
/* Canvas surfaces (no hashing)                                                */
/* -------------------------------------------------------------------------- */
section('normalizeCanvasSurfaces');

const canvas = normalizeCanvasSurfaces({ winding: 'counter-clockwise', geometry: { w: 10.5, h: 20.25 }, text: '  Hello   World  ' });
check('canvas winding normalizes to ccw token', canvas.status === 'ok' && canvas.winding === 'ccw', canvas.winding ?? 'null');
check('canvas geometry is a bounded descriptor, not a hash', canvas.geometry === 'h=20.25;w=10.5', canvas.geometry ?? 'null');
check('canvas text is whitespace-normalized, not hashed', canvas.text === 'Hello World', canvas.text ?? 'null');
check('canvas reason set records no-hashing', canvas.reasons.includes('no-hashing'), JSON.stringify(canvas.reasons));
check('boolean winding maps to cw/ccw', normalizeCanvasSurfaces({ winding: true }).winding === 'cw', 'true -> cw');
check('empty canvas input is unavailable', normalizeCanvasSurfaces({}).status === 'unavailable', 'empty object');
check('canvas error flag yields blocked', normalizeCanvasSurfaces({ text: 'x', error: new Error('x') }).status === 'blocked', 'error flag');

/* -------------------------------------------------------------------------- */
/* Keyboard layout                                                             */
/* -------------------------------------------------------------------------- */
section('normalizeKeyboardLayout');

const keyboard = normalizeKeyboardLayout({ layout: 'en-US', keys: ['Shift', 'a', 'Shift', 'z'] });
check('keyboard keys deduped and sorted, layout kept', keyboard.status === 'ok' && keyboard.layout === 'en-US' && same(keyboard.keys, ['a', 'Shift', 'z']), JSON.stringify(keyboard.keys));
check('raw keyboard string is split into glyph tokens', same(normalizeKeyboardLayout('az').keys, ['a', 'z']), 'string input');
check('keyboard order-independent (determinism)', same(keyboard.keys, normalizeKeyboardLayout({ layout: 'en-US', keys: ['z', 'a', 'Shift'] }).keys), 'shuffled keys');
check('empty keyboard input is unavailable', normalizeKeyboardLayout([]).status === 'unavailable', 'empty array');
check('keyboard denied flag yields blocked', normalizeKeyboardLayout({ keys: ['a'], denied: true }).status === 'blocked', 'denied flag');

/* -------------------------------------------------------------------------- */
/* CSS vector                                                                  */
/* -------------------------------------------------------------------------- */
section('normalizeCssVector');

const css = normalizeCssVector({ grid: true, flex: 1, backdropFilter: true, disabled: false, emptyString: '' });
check('css vector keeps only enabled features', css.status === 'ok' && same(css.features, ['backdropFilter', 'flex', 'grid']), JSON.stringify(css.features));
check('css feature array is canonicalized', same(normalizeCssVector(['grid', 'flex', 'grid']).features, ['flex', 'grid']), 'array input');
check('empty css vector is unavailable', normalizeCssVector({}).status === 'unavailable', 'empty object');
check('css block flag yields blocked', normalizeCssVector({ features: ['grid'], blocked: 'blocked' }).status === 'blocked', 'blocked string flag');

/* -------------------------------------------------------------------------- */
/* Math constants                                                              */
/* -------------------------------------------------------------------------- */
section('normalizeMathConstants');

const math = normalizeMathConstants({ sin: 0.8414709848078965, PI: Math.PI, random: 0.12345, bogus: 'x' });
check('math keeps whitelisted finite keys only', math.status === 'ok' && math.constants.sin === 0.841470984808 && 'PI' in math.constants && !('random' in math.constants) && !('bogus' in math.constants), JSON.stringify(math.constants));
check('math values rounded to 12dp (stable)', math.constants.PI === Number(Math.PI.toFixed(12)), String(math.constants.PI));
check('math constants emitted in deterministic key order', same(Object.keys(normalizeMathConstants({ PI: Math.PI, sin: 0.5 }).constants), ['PI', 'sin']), 'sorted keys');
check('empty math input is unavailable', normalizeMathConstants({}).status === 'unavailable', 'empty object');
check('math exception flag yields blocked', normalizeMathConstants({ sin: 0.5, threw: true }).status === 'blocked', 'threw flag');

/* -------------------------------------------------------------------------- */
/* DOM blockers                                                                */
/* -------------------------------------------------------------------------- */
section('normalizeDomBlockers');

const blockers = normalizeDomBlockers({ blocked: ['navigator.plugins', 'window.localStorage', 'navigator.plugins'] });
check('dom blockers deduped and sorted', blockers.status === 'blocked' && same(blockers.blocked, ['navigator.plugins', 'window.localStorage']), JSON.stringify(blockers.blocked));
check('dom blocker count mirrors list', blockers.count === blockers.blocked.length, String(blockers.count));
check('no blockers with input is ok (not blocked)', normalizeDomBlockers({ blocked: [] }).status === 'ok', 'empty blockers');
check('empty dom input is unavailable', normalizeDomBlockers({}).status === 'unavailable', 'empty object');

/* -------------------------------------------------------------------------- */
/* WebGPU deployable slice + research notes                                    */
/* -------------------------------------------------------------------------- */
section('normalizeWebGpuSurfaces + research notes');

const webgpu = normalizeWebGpuSurfaces({
  adapterInfo: { vendor: 'acme', architecture: 'ampere', device: 'gpu-1', description: 42 },
  features: new Set(['timestamp-query', 'shader-f16', 'timestamp-query']),
  limits: {
    maxComputeWorkgroupSizeX: 256,
    maxComputeWorkgroupSizeY: 256,
    maxComputeWorkgroupSizeZ: 64,
    maxComputeWorkgroupsPerDimension: 65535,
  },
});
check('webgpu normalizes adapter.info fields', webgpu.status === 'ok' && webgpu.adapter.vendor === 'acme' && webgpu.adapter.architecture === 'ampere' && webgpu.adapter.device === 'gpu-1', JSON.stringify(webgpu.adapter));
check('webgpu non-string description is ignored', webgpu.adapter.description === null, 'numeric description');
check('webgpu Set features are deduped and sorted', same(webgpu.features, ['shader-f16', 'timestamp-query']), JSON.stringify(webgpu.features));
check('webgpu compute limits normalize', webgpu.limits.maxComputeWorkgroupSizeX === 256 && webgpu.limits.maxComputeWorkgroupSizeZ === 64 && webgpu.limits.maxComputeWorkgroupsPerDimension === 65535, JSON.stringify(webgpu.limits));
check('webgpu timestamp-query derived from features', webgpu.timestampQuery === 'available', String(webgpu.timestampQuery));
check('webgpu record carries fjs-v5-no-webgpu note', webgpu.notes.includes('fjs-v5-no-webgpu'), JSON.stringify(webgpu.notes));

const webgpuEmptyAdapter = normalizeWebGpuSurfaces({ adapterInfo: {}, features: ['shader-f16'], limits: {} });
check('empty adapter.info is allowed, not an error', webgpuEmptyAdapter.status === 'ok' && webgpuEmptyAdapter.adapter.vendor === null && webgpuEmptyAdapter.reasons.includes('empty-adapter-info'), JSON.stringify(webgpuEmptyAdapter.reasons));
check('webgpu explicitly unavailable timestamp is honored', normalizeWebGpuSurfaces({ features: ['shader-f16'], timestampQuery: false }).timestampQuery === 'unavailable', 'explicit false');
check('webgpu invalid limits are nulled but surface stays ok', normalizeWebGpuSurfaces({ limits: { maxComputeWorkgroupSizeX: -1 }, features: ['x'] }).limits.maxComputeWorkgroupSizeX === null, 'negative limit');
check('empty webgpu input is unavailable', normalizeWebGpuSurfaces({}).status === 'unavailable', 'empty object');
check('webgpu error flag yields blocked', normalizeWebGpuSurfaces({ features: ['x'], error: new Error('no adapter') }).status === 'blocked', 'error flag');

check('research_only note is explicit and not implemented', RESEARCH_ONLY_NOTE.id === 'research_only' && RESEARCH_ONLY_NOTE.implemented === false, JSON.stringify(RESEARCH_ONLY_NOTE));
check('research-only note names the excluded techniques', /contention/i.test(RESEARCH_ONLY_NOTE.text) && /ML/i.test(RESEARCH_ONLY_NOTE.text), 'note text');
check('webgl-after-canvas ordering note is exposed', ENTROPY_NOTES.webglAfterCanvas.id === 'webgl-after-canvas' && /AFTER canvas/i.test(ENTROPY_NOTES.webglAfterCanvas.text), 'ordering note');
check('FJS v5 has no WebGPU source (per note)', ENTROPY_NOTES.noWebgpuInFjsV5.id === 'fjs-v5-no-webgpu' && /(NO WebGPU|no WebGPU)/i.test(ENTROPY_NOTES.noWebgpuInFjsV5.text), 'no-webgpu note');
check('static WebGPU ~5.19 bits is descriptive, not a risk score', ENTROPY_NOTES.staticWebGpuEstimate.estimatedBits === 5.19 && ENTROPY_NOTES.staticWebGpuEstimate.riskScore === false, JSON.stringify(ENTROPY_NOTES.staticWebGpuEstimate));
check('FJS v5 inventory lists high-value sources', ['fonts', 'fontPreferences', 'domBlockers', 'audioBaseLatency', 'webGlBasics', 'webGlExtensions', 'screenFrame', 'colorGamut', 'userAgentData', 'touchSupport'].every((source) => (FJS_V5_HIGH_VALUE_SOURCES as readonly string[]).includes(source)), `${FJS_V5_HIGH_VALUE_SOURCES.length} sources`);
check('FJS v5 inventory does not include WebGPU', !(FJS_V5_HIGH_VALUE_SOURCES as readonly string[]).includes('webgpu'), 'no webgpu in inventory');

/* -------------------------------------------------------------------------- */
/* Hostile input — never throws, always a well-formed record                   */
/* -------------------------------------------------------------------------- */
section('hostile input (non-throwing)');

const hostileProxy = new Proxy({}, { get() { throw new Error('hostile getter'); }, ownKeys() { throw new Error('hostile keys'); } });

const hostileCases: Array<[string, () => unknown]> = [
  ['fonts', () => normalizeFontPreferences(hostileProxy)],
  ['emoji', () => normalizeEmojiMetrics(hostileProxy)],
  ['webgl', () => normalizeWebglSurfaces(hostileProxy as never)],
  ['audio', () => normalizeAudioDriver(hostileProxy as never)],
  ['canvas', () => normalizeCanvasSurfaces(hostileProxy as never)],
  ['keyboard', () => normalizeKeyboardLayout(hostileProxy)],
  ['css', () => normalizeCssVector(hostileProxy)],
  ['math', () => normalizeMathConstants(hostileProxy)],
  ['dom-blockers', () => normalizeDomBlockers(hostileProxy)],
  ['webgpu', () => normalizeWebGpuSurfaces(hostileProxy as never)],
  ['null fonts', () => normalizeFontPreferences(null)],
  ['number emoji', () => normalizeEmojiMetrics(42)],
  ['string webgl', () => normalizeWebglSurfaces('bad' as never)],
  ['array audio', () => normalizeAudioDriver([1, 2, 3] as never)],
  ['null canvas', () => normalizeCanvasSurfaces(null)],
  ['number keyboard', () => normalizeKeyboardLayout(99)],
  ['number css', () => normalizeCssVector(7)],
  ['array math', () => normalizeMathConstants([1, 2] as never)],
  ['null dom-blockers', () => normalizeDomBlockers(null)],
  ['null webgpu', () => normalizeWebGpuSurfaces(null)],
];

let hostileOk = 0;
for (const [name, fn] of hostileCases) {
  const result = noThrow(fn);
  const wellFormed = result !== null &&
    typeof result === 'object' &&
    'surface' in result &&
    'status' in result &&
    ['ok', 'unavailable', 'blocked'].includes((result as { status: string }).status) &&
    Array.isArray((result as unknown as { reasons: unknown }).reasons);
  if (wellFormed) hostileOk += 1;
  else console.log(`  hostile case failed: ${name}`);
}
check('all hostile inputs return well-formed records without throwing', hostileOk === hostileCases.length, `${hostileOk}/${hostileCases.length}`);

const cycle: unknown = { fonts: [] };
(cycle as { self?: unknown }).self = cycle;
check('cyclic object input does not throw', noThrow(() => normalizeFontPreferences(cycle))?.status === 'unavailable', 'cyclic fonts');

/* -------------------------------------------------------------------------- */
/* Determinism — repeated calls are byte-identical                             */
/* -------------------------------------------------------------------------- */
section('determinism');

const suites: Array<[string, () => unknown]> = [
  ['fonts', () => normalizeFontPreferences({ fonts: ['Arial', 'Verdana', 'arial'] })],
  ['emoji', () => normalizeEmojiMetrics({ glyphs: ['😀', '🚀'], width: 17.25 })],
  ['webgl', () => normalizeWebglSurfaces({ basics: { vendor: 'WebKit' }, extensions: ['A', 'B'] })],
  ['audio', () => normalizeAudioDriver({ sampleRate: 44100, baseLatency: 0.001 })],
  ['canvas', () => normalizeCanvasSurfaces({ winding: 'cw', geometry: { w: 1 }, text: 'x' })],
  ['keyboard', () => normalizeKeyboardLayout({ keys: ['a', 'b'] })],
  ['css', () => normalizeCssVector({ flex: true, grid: true })],
  ['math', () => normalizeMathConstants({ sin: 0.5, PI: Math.PI })],
  ['dom-blockers', () => normalizeDomBlockers({ blocked: ['a', 'b'] })],
  ['webgpu', () => normalizeWebGpuSurfaces({ adapterInfo: { vendor: 'acme' }, features: ['a', 'b'] })],
];

let deterministicOk = 0;
for (const [name, fn] of suites) {
  if (same(fn(), fn())) deterministicOk += 1;
  else console.log(`  non-deterministic: ${name}`);
}
check('repeated normalization is byte-identical for all surfaces', deterministicOk === suites.length, `${deterministicOk}/${suites.length}`);

/* -------------------------------------------------------------------------- */
/* FJS-v5 parity snapshot (additive shadow surface — checks added only)        */
/* -------------------------------------------------------------------------- */
section('buildFjsV5ParitySnapshot (shadow parity)');

// Existing normalizers above are untouched; these checks only READ the new snapshot.
const paritySample = {
  fonts: { installed: ['Arial', 'Segoe UI'], platformClassGuess: 'windows' },
  rawFonts: ['Verdana'],
  fontPreferences: { widths: { default: 42.5, apple: 43, serif: null }, widthsExactIntegers: false },
  emoji: { font: 'serif', width: 17.25, height: 18, x: 0, top: null },
  math: { values: { acos: '0.123', sin: '-0.5' }, vector: [1, 2] },
  location: { publicIp: '203.0.113.7', city: 'Test', latitude: null, isVpnOrHosting: false },
  battery: { level: 0.9 },
  keyboard: { keys: ['a'] },
};

const parity = buildFjsV5ParitySnapshot(paritySample);

check('snapshot surface is stable and namespaced', parity.surface === 'fjs-v5-parity' && parity.status === 'ok', parity.status);
check('snapshot is deterministic (repeat calls byte-identical)', same(parity, buildFjsV5ParitySnapshot(paritySample)), 'repeat call');
check('snapshot is input-order independent for detection sets', same(
  buildFjsV5ParitySnapshot({ fonts: { installed: ['Arial', 'Verdana'], platformClassGuess: 'linux' } }).fontCoverage.families,
  buildFjsV5ParitySnapshot({ fonts: { installed: ['Verdana', 'Arial'], platformClassGuess: 'linux' } }).fontCoverage.families
), 'shuffled detections');
check('16 canonical high-value families, each with a 3-way status',
  FJS_V5_HIGH_VALUE_FONT_FAMILIES.length === 16 && parity.fontCoverage.families.length === 16 &&
  parity.fontCoverage.families.every((entry) => ['present', 'derived', 'absent'].includes(entry.status)),
  `${FJS_V5_HIGH_VALUE_FONT_FAMILIES.length} families`);
check('literal detections are the only "present" families',
  same(parity.fontCoverage.families.filter((f) => f.status === 'present').map((f) => f.family), ['Arial', 'Segoe UI', 'Verdana']),
  JSON.stringify(parity.fontCoverage.families.filter((f) => f.status === 'present').map((f) => f.family)));
check('platform-class markers are labelled derived, never detected',
  parity.fontCoverage.families.some((f) => f.status === 'derived' && !f.detected && f.reason === 'derived-from-platform-class-marker') &&
  parity.fontCoverage.families.every((f) => !f.detected || f.reason === 'direct-detection'),
  `derived=${parity.fontCoverage.counts.derived}`);
check('family counts mirror the family list',
  parity.fontCoverage.counts.present + parity.fontCoverage.counts.derived + parity.fontCoverage.counts.absent === 16 &&
  parity.fontCoverage.counts.present === parity.fontCoverage.families.filter((f) => f.status === 'present').length,
  JSON.stringify(parity.fontCoverage.counts));
check('no fabricated detection: detected=true implies literal input membership',
  parity.fontCoverage.families.every((f) =>
    !f.detected || ['arial', 'segoe ui', 'verdana'].includes(f.family.toLowerCase())),
  'detection provenance');
check('emoji reports DOMRect metric presence from the existing shape',
  EMOJI_DOMRECT_METRICS.length === 8 && same(parity.emoji.present, ['width', 'height', 'x']) &&
  parity.emoji.status === 'present' && parity.emoji.declaredFontStack,
  JSON.stringify(parity.emoji.present));
check('math reports FPJS 15-vector presence without emitting values',
  FPJS15_VECTOR_KEYS.length === 15 && parity.math.count === 3 &&
  same(parity.math.present, ['acos', 'acosh', 'sin']) &&
  !('values' in parity.math) && !('hash' in parity.math),
  JSON.stringify(parity.math.present));
check('fontPreferences reports the 7 presets and integer flag',
  FONT_PREFERENCE_PRESETS.length === 7 && same(parity.fontPreferences.measured, ['default', 'apple']) &&
  parity.fontPreferences.widthsExactIntegers === false && parity.fontPreferences.status === 'present',
  JSON.stringify(parity.fontPreferences.measured));
check('geoFields reports LocationInfo field parity',
  LOCATION_INFO_FIELDS.length === 14 && parity.geoFields.status === 'partial' &&
  ['city', 'isVpnOrHosting', 'publicIp'].every((f) => parity.geoFields.present.includes(f)) &&
  ['asn', 'country', 'isp'].every((f) => parity.geoFields.missing.includes(f)),
  JSON.stringify(parity.geoFields.present));
check('battery is honestly absent (no client producer)',
  parity.battery.status === 'absent' && parity.battery.consumer === 'none' && parity.battery.dataProvided === true,
  JSON.stringify(parity.battery));
check('keyboard is honestly descriptive (no verdict consumer)',
  parity.keyboard.status === 'descriptive' && parity.keyboard.consumer === 'none' && parity.keyboard.dataProvided === true,
  JSON.stringify(parity.keyboard));

// Additive-only: no mutation of the caller's payload, envelope fields, or scores.
const frozenInput = Object.freeze({
  fonts: Object.freeze({ installed: Object.freeze(['Arial']) }),
  location: Object.freeze({ publicIp: '198.51.100.1' }),
  envelope: Object.freeze({ timestamp: 1, nonce: 'n', hardwareId: 'h', userAgent: 'ua', platform: 'p', screenResolution: 's', timezone: 't' }),
  risk: Object.freeze({ score_0_100: 42 }),
});
const beforeFrozen = JSON.stringify(frozenInput);
const frozenSnapshot = buildFjsV5ParitySnapshot(frozenInput);
check('snapshot never mutates its input (additive read-only)', JSON.stringify(frozenInput) === beforeFrozen, 'frozen input');
check('snapshot emits no envelope/verdict/score/hash fields',
  !Object.keys(frozenSnapshot).some((k) =>
    ['timestamp', 'nonce', 'hardwareId', 'userAgent', 'platform', 'screenResolution', 'timezone', 'risk', 'score', 'verdict', 'confidence', 'hash', 'digest'].includes(k)),
  Object.keys(frozenSnapshot).join(','));

// Hostile / wrong-typed inputs fail closed with empty or absent descriptors.
const hostileParityProxy = new Proxy({}, { get() { throw new Error('hostile getter'); }, ownKeys() { throw new Error('hostile keys'); } });
const hostileParityCases: Array<[string, unknown]> = [
  ['proxy', hostileParityProxy],
  ['null', null],
  ['number', 42],
  ['string', 'bad'],
  ['array', [1, 2, 3]],
  ['hostile nested', { fonts: hostileParityProxy, emoji: hostileParityProxy, math: hostileParityProxy, location: hostileParityProxy }],
];

let hostileParityOk = 0;
for (const [name, input] of hostileParityCases) {
  const result = noThrow(() => buildFjsV5ParitySnapshot(input));
  const wellFormed = result !== null &&
    result.surface === 'fjs-v5-parity' &&
    result.fontCoverage.families.length === 16 &&
    result.fontCoverage.families.every((f) => f.status === 'absent' && !f.detected) &&
    result.emoji.status === 'absent' && result.math.status === 'absent' &&
    result.fontPreferences.status === 'absent' && result.geoFields.status === 'absent' &&
    result.battery.status === 'absent' && result.keyboard.status === 'descriptive';
  if (wellFormed) hostileParityOk += 1;
  else console.log(`  hostile parity case failed: ${name}`);
}
check('hostile/null/wrong-typed input fails closed with empty descriptors',
  hostileParityOk === hostileParityCases.length, `${hostileParityOk}/${hostileParityCases.length}`);

const cyclicParity: Record<string, unknown> = {};
cyclicParity.self = cyclicParity;
cyclicParity.fonts = cyclicParity;
check('cyclic parity input does not throw and fails closed',
  noThrow(() => buildFjsV5ParitySnapshot(cyclicParity))?.fontCoverage.counts.present === 0, 'cyclic fonts');
check('empty parity input is unavailable, not fabricated',
  buildFjsV5ParitySnapshot({}).status === 'unavailable' &&
  buildFjsV5ParitySnapshot({}).fontCoverage.counts.absent === 16, 'empty input');

/* -------------------------------------------------------------------------- */

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log(`FAILED: ${failures.join(' | ')}`);
  process.exit(1);
}

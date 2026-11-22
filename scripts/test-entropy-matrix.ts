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

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log(`FAILED: ${failures.join(' | ')}`);
  process.exit(1);
}

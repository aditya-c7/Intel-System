/**
 * WebGL collectors — three independent probes over throwaway contexts:
 *
 *  - getWebglBasics():      version/vendor/renderer strings (masked +
 *                           unmasked via WEBGL_debug_renderer_info).
 *  - getWebglExtensions():  five hashed groups (context attributes,
 *                           implementation limits, shader precisions,
 *                           supported extensions, per-extension parameters)
 *                           plus unsupportedExtensions.
 *  - getWebglGpuIdentity(): canonical GPU model (wrapper syntax stripped)
 *                           and invariant hardware limits.
 *
 * Contexts are created on detached canvases and never kept alive. A WebGL2
 * context is preferred (it also answers every WebGL1 query); WebGL2-only
 * limits are null on WebGL1-only browsers.
 */

import { stableHash32, stableStringify, hashStrings, errorMessage } from './hash';
import type {
  WebglInvariantLimits,
  WebglGpuIdentity,
  WebglBasics,
  WebglExtensions,
} from './types';

const UNMASKED_VENDOR_WEBGL = 0x9245;
const UNMASKED_RENDERER_WEBGL = 0x9246;
const MAX_3D_TEXTURE_SIZE = 0x8073;
const MAX_ARRAY_TEXTURE_LAYERS = 0x88ff;
const MAX_TEXTURE_MAX_ANISOTROPY_EXT = 0x84ff;
const MAX_COLOR_ATTACHMENTS_WEBGL = 0x8cdf;
const MAX_DRAW_BUFFERS_WEBGL = 0x8824;
const QUERY_COUNTER_BITS_EXT = 0x8864;
const TIMESTAMP_EXT = 0x927e;
const MAX_VIEWS_OVR = 0x9631;
const IMPLEMENTATION_COLOR_READ_FORMAT = 0x8b4b;
const IMPLEMENTATION_COLOR_READ_TYPE = 0x8b4c;

interface WebglContextBundle {
  gl: WebGLRenderingContext;
  isWebgl2: boolean;
  canvas: HTMLCanvasElement;
}

function acquireContext(): WebglContextBundle | null {
  try {
    const canvas = document.createElement('canvas');
    const gl2 = canvas.getContext('webgl2') as WebGL2RenderingContext | null;
    if (gl2) return { gl: gl2 as unknown as WebGLRenderingContext, isWebgl2: true, canvas };
    const gl1 = (canvas.getContext('webgl') ??
      canvas.getContext('experimental-webgl')) as WebGLRenderingContext | null;
    if (gl1) return { gl: gl1, isWebgl2: false, canvas };
    return null;
  } catch {
    return null;
  }
}

function disposeContext(bundle: WebglContextBundle | null): void {
  if (!bundle) return;
  try {
    const lose = bundle.gl.getExtension('WEBGL_lose_context');
    lose?.loseContext?.();
  } catch {
    /* ignore */
  }
  try {
    bundle.canvas.remove();
  } catch {
    /* ignore */
  }
}

function safeGetParameter(gl: WebGLRenderingContext, key: number): unknown {
  let value: unknown = null;
  try {
    value = gl.getParameter(key);
  } catch {
    value = null;
  }
  // Drain INVALID_OPERATION side effects (WebGL2 read-format/type queries
  // without a bound read framebuffer).
  try {
    gl.getError();
  } catch {
    /* ignore */
  }
  return value;
}

function normalizeParam(value: unknown): unknown {
  if (value instanceof Float32Array || value instanceof Int32Array || value instanceof Uint32Array) {
    return Array.from(value);
  }
  if (typeof value === 'number' || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  return value ?? null;
}

// ---------------------------------------------------------------------------
// getWebglBasics
// ---------------------------------------------------------------------------

/** Total: always returns a payload. */
export function getWebglBasics(): WebglBasics {
  const result: WebglBasics = {
    version: null,
    vendor: null,
    renderer: null,
    shadingLanguageVersion: null,
    vendorUnmasked: null,
    rendererUnmasked: null,
  };

  const bundle = acquireContext();
  if (!bundle) {
    result.error = 'webgl context unavailable';
    return result;
  }

  try {
    const { gl } = bundle;
    const readString = (key: number): string | null => {
      const value = safeGetParameter(gl, key);
      return typeof value === 'string' ? value : null;
    };
    result.version = readString(gl.VERSION);
    result.vendor = readString(gl.VENDOR);
    result.renderer = readString(gl.RENDERER);
    result.shadingLanguageVersion = readString(gl.SHADING_LANGUAGE_VERSION);

    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info') as
      | { UNMASKED_VENDOR_WEBGL?: number; UNMASKED_RENDERER_WEBGL?: number }
      | null;
    if (debugInfo) {
      const vendorKey = debugInfo.UNMASKED_VENDOR_WEBGL ?? UNMASKED_VENDOR_WEBGL;
      const rendererKey = debugInfo.UNMASKED_RENDERER_WEBGL ?? UNMASKED_RENDERER_WEBGL;
      result.vendorUnmasked = readString(vendorKey);
      result.rendererUnmasked = readString(rendererKey);
    }
  } catch (err) {
    result.error = errorMessage(err);
  } finally {
    disposeContext(bundle);
  }

  return result;
}

// ---------------------------------------------------------------------------
// getWebglExtensions
// ---------------------------------------------------------------------------

/** Well-known extensions; anything absent from getSupportedExtensions() is reported. */
const COMMON_EXTENSIONS = [
  'ANGLE_instanced_arrays',
  'EXT_blend_minmax',
  'EXT_color_buffer_float',
  'EXT_color_buffer_half_float',
  'EXT_disjoint_timer_query',
  'EXT_disjoint_timer_query_webgl2',
  'EXT_float_blend',
  'EXT_frag_depth',
  'EXT_shader_texture_lod',
  'EXT_sRGB',
  'EXT_texture_compression_bptc',
  'EXT_texture_compression_rgtc',
  'EXT_texture_filter_anisotropic',
  'EXT_texture_norm16',
  'KHR_parallel_shader_compile',
  'OES_element_index_uint',
  'OES_fbo_render_mipmap',
  'OES_standard_derivatives',
  'OES_texture_float',
  'OES_texture_float_linear',
  'OES_texture_half_float',
  'OES_texture_half_float_linear',
  'OES_vertex_array_object',
  'OVR_multiview2',
  'WEBGL_color_buffer_float',
  'WEBGL_compressed_texture_astc',
  'WEBGL_compressed_texture_etc',
  'WEBGL_compressed_texture_etc1',
  'WEBGL_compressed_texture_pvrtc',
  'WEBGL_compressed_texture_s3tc',
  'WEBGL_compressed_texture_s3tc_srgb',
  'WEBGL_debug_renderer_info',
  'WEBGL_debug_shaders',
  'WEBGL_depth_texture',
  'WEBGL_draw_buffers',
  'WEBGL_lose_context',
];

function getContextAttributesHash(gl: WebGLRenderingContext): string | null {
  try {
    const attributes = gl.getContextAttributes();
    return attributes ? stableHash32(stableStringify(attributes)) : null;
  } catch {
    return null;
  }
}

function collectLimitParameters(gl: WebGLRenderingContext, isWebgl2: boolean): Record<string, unknown> {
  const names: Array<[string, number]> = [
    ['ALIASED_LINE_WIDTH_RANGE', gl.ALIASED_LINE_WIDTH_RANGE],
    ['ALIASED_POINT_SIZE_RANGE', gl.ALIASED_POINT_SIZE_RANGE],
    ['ALPHA_BITS', gl.ALPHA_BITS],
    ['BLUE_BITS', gl.BLUE_BITS],
    ['DEPTH_BITS', gl.DEPTH_BITS],
    ['GREEN_BITS', gl.GREEN_BITS],
    ['RED_BITS', gl.RED_BITS],
    ['STENCIL_BITS', gl.STENCIL_BITS],
    ['IMPLEMENTATION_COLOR_READ_FORMAT', IMPLEMENTATION_COLOR_READ_FORMAT],
    ['IMPLEMENTATION_COLOR_READ_TYPE', IMPLEMENTATION_COLOR_READ_TYPE],
    ['MAX_COMBINED_TEXTURE_IMAGE_UNITS', gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS],
    ['MAX_CUBE_MAP_TEXTURE_SIZE', gl.MAX_CUBE_MAP_TEXTURE_SIZE],
    ['MAX_FRAGMENT_UNIFORM_VECTORS', gl.MAX_FRAGMENT_UNIFORM_VECTORS],
    ['MAX_RENDERBUFFER_SIZE', gl.MAX_RENDERBUFFER_SIZE],
    ['MAX_TEXTURE_IMAGE_UNITS', gl.MAX_TEXTURE_IMAGE_UNITS],
    ['MAX_TEXTURE_SIZE', gl.MAX_TEXTURE_SIZE],
    ['MAX_VARYING_VECTORS', gl.MAX_VARYING_VECTORS],
    ['MAX_VERTEX_ATTRIBS', gl.MAX_VERTEX_ATTRIBS],
    ['MAX_VERTEX_TEXTURE_IMAGE_UNITS', gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS],
    ['MAX_VERTEX_UNIFORM_VECTORS', gl.MAX_VERTEX_UNIFORM_VECTORS],
    ['MAX_VIEWPORT_DIMS', gl.MAX_VIEWPORT_DIMS],
  ];
  if (isWebgl2) {
    names.push(['MAX_3D_TEXTURE_SIZE', MAX_3D_TEXTURE_SIZE]);
    names.push(['MAX_ARRAY_TEXTURE_LAYERS', MAX_ARRAY_TEXTURE_LAYERS]);
  }
  const values: Record<string, unknown> = {};
  for (const [name, key] of names) {
    values[name] = normalizeParam(safeGetParameter(gl, key));
  }
  return values;
}

function collectShaderPrecisions(gl: WebGLRenderingContext): Record<string, number[] | null> {
  const shaders: Array<[string, number]> = [
    ['vertex', gl.VERTEX_SHADER],
    ['fragment', gl.FRAGMENT_SHADER],
  ];
  const precisionTypes: Array<[string, number]> = [
    ['high_float', gl.HIGH_FLOAT],
    ['medium_float', gl.MEDIUM_FLOAT],
    ['low_float', gl.LOW_FLOAT],
    ['high_int', gl.HIGH_INT],
    ['medium_int', gl.MEDIUM_INT],
    ['low_int', gl.LOW_INT],
  ];
  const tuples: Record<string, number[] | null> = {};
  for (const [shaderName, shaderType] of shaders) {
    for (const [precisionName, precisionType] of precisionTypes) {
      const key = `${shaderName}_${precisionName}`;
      try {
        const format = gl.getShaderPrecisionFormat(shaderType, precisionType);
        tuples[key] = format ? [format.rangeMin, format.rangeMax, format.precision] : null;
      } catch {
        tuples[key] = null;
      }
    }
  }
  return tuples;
}

function collectExtensionParameters(gl: WebGLRenderingContext): Record<string, unknown> {
  const result: Record<string, unknown> = {
    anisotropyMax: null,
    drawBuffersMaxColorAttachments: null,
    drawBuffersMaxDrawBuffers: null,
    timerQueryCounterBits: null,
    timerQueryTimestamp: null,
    multiviewMaxViews: null,
  };

  const readFrom = (extensionName: string, constant: number): unknown => {
    const extension = gl.getExtension(extensionName) as unknown;
    if (!extension) return null;
    return normalizeParam(safeGetParameter(gl, constant));
  };

  try {
    const anisotropic = gl.getExtension('EXT_texture_filter_anisotropic') as
      | { MAX_TEXTURE_MAX_ANISOTROPY_EXT?: number }
      | null;
    if (anisotropic) {
      result.anisotropyMax = normalizeParam(
        safeGetParameter(gl, anisotropic.MAX_TEXTURE_MAX_ANISOTROPY_EXT ?? MAX_TEXTURE_MAX_ANISOTROPY_EXT)
      );
    }
  } catch {
    /* ignore */
  }
  try {
    result.drawBuffersMaxColorAttachments = readFrom('WEBGL_draw_buffers', MAX_COLOR_ATTACHMENTS_WEBGL);
  } catch {
    /* ignore */
  }
  try {
    result.drawBuffersMaxDrawBuffers = readFrom('WEBGL_draw_buffers', MAX_DRAW_BUFFERS_WEBGL);
  } catch {
    /* ignore */
  }
  try {
    result.timerQueryCounterBits = readFrom('EXT_disjoint_timer_query', QUERY_COUNTER_BITS_EXT);
  } catch {
    /* ignore */
  }
  try {
    result.timerQueryTimestamp = readFrom('EXT_disjoint_timer_query', TIMESTAMP_EXT);
  } catch {
    /* ignore */
  }
  try {
    result.multiviewMaxViews = readFrom('OVR_multiview2', MAX_VIEWS_OVR);
  } catch {
    /* ignore */
  }

  return result;
}

/** Total: always returns a payload. */
export function getWebglExtensions(): WebglExtensions {
  const result: WebglExtensions = {
    contextAttributes: null,
    parameters: null,
    shaderPrecisions: null,
    extensions: null,
    extensionParameters: null,
    supportedExtensions: [],
    unsupportedExtensions: [],
  };

  const bundle = acquireContext();
  if (!bundle) {
    result.error = 'webgl context unavailable';
    return result;
  }

  try {
    const { gl, isWebgl2 } = bundle;
    result.contextAttributes = getContextAttributesHash(gl);
    result.parameters = stableHash32(stableStringify(collectLimitParameters(gl, isWebgl2)));
    result.shaderPrecisions = stableHash32(stableStringify(collectShaderPrecisions(gl)));
    result.extensionParameters = stableHash32(stableStringify(collectExtensionParameters(gl)));

    const supported = (gl.getSupportedExtensions() ?? []).slice().sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    result.supportedExtensions = supported;
    result.extensions = hashStrings(supported);
    const supportedSet = new Set(supported);
    result.unsupportedExtensions = COMMON_EXTENSIONS.filter((name) => !supportedSet.has(name));
  } catch (err) {
    result.error = errorMessage(err);
  } finally {
    disposeContext(bundle);
  }

  return result;
}

// ---------------------------------------------------------------------------
// getWebglGpuIdentity
// ---------------------------------------------------------------------------

const ANGLE_SHAPE = /^angle\s*\((.*)\)\s*$/i;

/**
 * Software rasterizers are named inconsistently across drivers and browser
 * builds ("SwiftShader Device (Subzero)", "Google SwiftShader", "SwiftShader
 * driver"). Collapsing them to one canonical label keeps virtual machines
 * fingerprinted consistently instead of by driver build detail.
 */
/**
 * Display label for software rasterizers. SwiftShader is a legitimate software
 * GL implementation (common when hardware acceleration is disabled on a real
 * development machine): it is reported transparently, but it is NEVER browser
 * tampering and NEVER, by itself, proof of a virtual machine. See f851c63 / f7d6900.
 */
export const SOFTWARE_RENDERED_LABEL = 'Software-Rendered Graphics (SwiftShader)';

const SOFTWARE_RENDERERS: Array<[RegExp, string]> = [
  [/swiftshader/i, 'SwiftShader'],
  [/llvmpipe/i, 'llvmpipe'],
  [/software\s+rasterizer/i, 'Software Rasterizer'],
  [/basic\s+render\s+driver/i, 'Microsoft Basic Render Driver'],
];
const WRAPPER_TOKENS =
  /angle|direct3d\s*\d*|d3d\s*\d*|metal|vulkan|opengl(\s+es)?\s*[\d.]*|webgl\s*\d*|gles\s*[\d.]*|\bengine\b/gi;

/**
 * Normalizes `renderer_unmasked` down to the canonical GPU model:
 *  - ANGLE wrapper: "ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11
 *    vs_5_0 ps_5_0, D3D11)" -> "NVIDIA GeForce RTX 4090"
 *  - parenthesized device ids / LLVM versions stripped: "llvmpipe (LLVM
 *    17.0.6, 256 bits)" -> "llvmpipe"
 *  - plain renderer strings pass through: "Apple M4" -> "Apple M4"
 */
/**
 * Splits an ANGLE inner descriptor on the commas that separate its top-level
 * fields. Commas nested inside parentheses belong to the model fragment.
 */
function splitTopLevel(value: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  for (const char of value) {
    if (char === '(') depth += 1;
    else if (char === ')') depth = Math.max(0, depth - 1);
    if (char === ',' && depth === 0) {
      parts.push(current.trim());
      current = '';
      continue;
    }
    current += char;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

/**
 * Removes parenthesized fragments from the inside out. Drivers nest them
 * ("Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE))"), and a single
 * pass leaves dangling brackets that corrupt the canonical GPU name.
 */
function stripNestedParens(value: string): string {
  let out = value;
  for (let pass = 0; pass < 8 && out.indexOf('(') !== -1; pass += 1) {
    const next = out.replace(/\([^()]*\)/g, ' ');
    if (next === out) break;
    out = next;
  }
  return out.replace(/[()]/g, ' ');
}

/**
 * Longest alphabetic fragment inside nested parentheses. ANGLE sometimes hides
 * the real device there ("Vulkan 1.3.0 (SwiftShader Device ...)"), so it is the
 * fallback whenever the outer fragment cleans down to a version string.
 */
function innerDeviceCandidate(value: string): string {
  let best = '';
  const pattern = /\(([^()]*)\)/g;
  let match = pattern.exec(value);
  while (match) {
    const fragment = match[1]
      .replace(/\b(?:unspecified version|swiftshader driver)\b/gi, ' ')
      .trim();
    if (/[a-z]{4,}/i.test(fragment) && fragment.length > best.length) best = fragment;
    match = pattern.exec(value);
  }
  return best;
}

export function normalizeGpuRenderer(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  let value = trimmed;
  try {
    for (const [pattern, label] of SOFTWARE_RENDERERS) {
      if (pattern.test(trimmed)) return label;
    }
    const angleMatch = value.match(ANGLE_SHAPE);
    let innerCandidate = '';
    if (angleMatch) {
      const parts = splitTopLevel(angleMatch[1]);
      innerCandidate = innerDeviceCandidate(angleMatch[1]);
      // ANGLE inner layout: "<vendor>, <model + wrapper suffix>, <backend>".
      value = parts.length >= 3 ? parts[1] : angleMatch[1];
    }
    const clean = (input: string): string =>
      stripNestedParens(input)
        .replace(WRAPPER_TOKENS, ' ')
        .replace(/renderer\s*:/gi, ' ')
        .replace(/unspecified\s+version/gi, ' ')
        .replace(/vs_\d+_\d+/gi, ' ')
        .replace(/ps_\d+_\d+/gi, ' ')
        .replace(/\d+\s*bits/gi, ' ')
        .replace(/\b\d+\.\d+(?:\.\d+)*\b/g, ' ')
        .replace(/\s+/g, ' ')
        .replace(/^[\s,\-]+|[\s,\-]+$/g, '')
        .trim();
    value = clean(value);
    // A fragment made of a bare version ("1.3.0") is not a device identity.
    if (!/[a-z]{2,}/i.test(value) && innerCandidate) value = clean(innerCandidate);
  } catch {
    return trimmed;
  }
  return value.length > 0 ? value : trimmed;
}

function readInvariantLimits(gl: WebGLRenderingContext, isWebgl2: boolean): WebglInvariantLimits {
  const readNumber = (key: number): number | null => {
    const value = normalizeParam(safeGetParameter(gl, key));
    return typeof value === 'number' ? value : null;
  };
  const readRange = (key: number): number[] | null => {
    const value = normalizeParam(safeGetParameter(gl, key));
    return Array.isArray(value) && value.every((item) => typeof item === 'number') ? (value as number[]) : null;
  };
  const limits: WebglInvariantLimits = {
    maxTextureSize: readNumber(gl.MAX_TEXTURE_SIZE),
    maxCubeMapTextureSize: readNumber(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
    maxRenderbufferSize: readNumber(gl.MAX_RENDERBUFFER_SIZE),
    maxViewportDims: readRange(gl.MAX_VIEWPORT_DIMS),
    max3dTextureSize: isWebgl2 ? readNumber(MAX_3D_TEXTURE_SIZE) : null,
    maxArrayTextureLayers: isWebgl2 ? readNumber(MAX_ARRAY_TEXTURE_LAYERS) : null,
    aliasedPointSizeRange: readRange(gl.ALIASED_POINT_SIZE_RANGE),
  };
  return limits;
}

/** Total: always returns a payload. */
export function getWebglGpuIdentity(): WebglGpuIdentity {
  const result: WebglGpuIdentity = {
    normalizedGpu: null,
    normalizedGpuHash: null,
    invariantLimits: null,
  };

  const bundle = acquireContext();
  if (!bundle) {
    result.error = 'webgl context unavailable';
    return result;
  }

  try {
    const { gl, isWebgl2 } = bundle;
    result.invariantLimits = readInvariantLimits(gl, isWebgl2);

    let rendererUnmasked: string | null = null;
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info') as
      | { UNMASKED_RENDERER_WEBGL?: number }
      | null;
    if (debugInfo) {
      const value = safeGetParameter(gl, debugInfo.UNMASKED_RENDERER_WEBGL ?? UNMASKED_RENDERER_WEBGL);
      rendererUnmasked = typeof value === 'string' ? value : null;
    }
    if (!rendererUnmasked) {
      const masked = safeGetParameter(gl, gl.RENDERER);
      rendererUnmasked = typeof masked === 'string' ? masked : null;
    }
    const normalized = normalizeGpuRenderer(rendererUnmasked);
    result.normalizedGpu = normalized;
    result.normalizedGpuHash = normalized ? stableHash32(normalized) : null;
  } catch (err) {
    result.error = errorMessage(err);
  } finally {
    disposeContext(bundle);
  }

  return result;
}

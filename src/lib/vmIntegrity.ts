/**
 * Three-state VM / hardware integrity resolver (pure, additive, dependency-free).
 *
 * This module is a *shadow* evaluator: it imports nothing from the server, the Worker, or any
 * third-party SDK, never mutates its inputs, and never throws. It exists so the VM/hardware
 * trust rules can be reasoned about and tested in isolation before anything is wired into a
 * request path.
 *
 * Trust model (deliberately conservative — false positives are worse than abstention):
 *   - `virtual_machine` is tri-state: `true` (direct hypervisor evidence), `false` (only when
 *     real manufacturer silicon is reported), or `null` (unknown / withheld).
 *   - SwiftShader / llvmpipe / any software rasteriser sets `software_renderer: true` but is
 *     NOT virtual-machine proof: `virtual_machine` stays `null`. The exemption is preserved
 *     even when weak environment hints (low cores, low memory, high jitter, odd audio) are
 *     present, because those hints are never sufficient to promote software rendering to a VM.
 *   - VMware / VirtualBox / QEMU / Parallels / VirtIO (and kin) are direct hypervisor
 *     signatures and yield `classification: 'hypervisor'`.
 *   - Absence of evidence yields `classification: 'unknown'` with `virtual_machine: null`.
 *     A physical verdict is NEVER asserted from the mere absence of VM evidence; when it is
 *     emitted at all it requires positive silicon evidence and its confidence is capped below
 *     `high` (GPU strings are spoofable claims, not anchors).
 *   - Numeric/WebGPU signals are weak corroboration only: they add reasons and can lower the
 *     confidence of a physical verdict, but can never create a VM verdict on their own.
 *
 * There is intentionally no risk score and no 0-10 weighting anywhere in this module.
 */

export type VmIntegrityConfidence = 'high' | 'medium' | 'low';
export type VmIntegrityClassification = 'hypervisor' | 'software_renderer' | 'physical' | 'unknown';

export interface VmIntegrityInput {
  gpuVendor?: string;
  gpuRenderer?: string;
  webgpuLimits?: Record<string, unknown>;
  audioSampleRate?: number;
  audioOutputLatency?: number;
  maxChannelCount?: number;
  cores?: number;
  memory?: number;
  renderedFramesJitter?: number;
}

export interface VmIntegrityResult {
  virtual_machine: boolean | null;
  software_renderer: boolean;
  confidence: VmIntegrityConfidence;
  classification: VmIntegrityClassification;
  reasons: string[];
}

interface SignatureRule {
  pattern: RegExp;
  label: string;
}

/** Direct hypervisor GPU signatures. No /g flag — `.test` must be stateless. */
const HYPERVISOR_SIGNATURES: ReadonlyArray<SignatureRule> = [
  { pattern: /vmware|svga3d/i, label: 'VMware SVGA3D virtual GPU' },
  { pattern: /virtualbox|\bvbox\b/i, label: 'Oracle VirtualBox virtual GPU' },
  { pattern: /qemu|\bkvm\b|virtio|virgl|bochs/i, label: 'QEMU / KVM / VirtIO virtual GPU' },
  { pattern: /parallels/i, label: 'Parallels virtual GPU' },
  { pattern: /hyper-?v|microsoft remote display/i, label: 'Microsoft Hyper-V remote display' },
  { pattern: /citrix|\bxen\b/i, label: 'Citrix / Xen virtual GPU' },
];

/** Software rasterisers. SwiftShader is the canonical example and stays VM-exempt. */
const SOFTWARE_SIGNATURES: ReadonlyArray<SignatureRule> = [
  { pattern: /swiftshader|subzero|0x0000c0de/i, label: 'SwiftShader software rasteriser' },
  { pattern: /llvmpipe|softpipe|mesa offscreen/i, label: 'Mesa software rasteriser (llvmpipe/softpipe)' },
  { pattern: /software rasterizer|software renderer|software rendering/i, label: 'generic software rasteriser' },
  { pattern: /basic render driver|microsoft basic render/i, label: 'Microsoft Basic Render Driver (software)' },
  { pattern: /apple software renderer/i, label: 'Apple software renderer' },
];

/** Real manufacturer silicon. Used only to permit a (capped-confidence) physical verdict. */
const SILICON_SIGNATURES: ReadonlyArray<SignatureRule> = [
  { pattern: /nvidia|geforce|quadro|\brtx\b|\bgtx\b/i, label: 'NVIDIA silicon' },
  { pattern: /radeon|\bamd\b/i, label: 'AMD Radeon silicon' },
  { pattern: /\bintel\b|iris|uhd graphics|hd graphics|arc graphics/i, label: 'Intel silicon' },
  { pattern: /apple m[1-9]|apple gpu/i, label: 'Apple Silicon' },
  { pattern: /adreno|mali|powervr|videocore|imagination/i, label: 'mobile GPU silicon' },
];

function safeText(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function safeNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** Read a property defensively — a hostile object may expose a throwing getter. */
function getField(bag: unknown, key: string): unknown {
  try {
    if (bag && typeof bag === 'object') return (bag as Record<string, unknown>)[key];
  } catch {
    // Hostile getter — treat the field as absent.
  }
  return undefined;
}

function readText(bag: unknown, key: string): string {
  try {
    return safeText(getField(bag, key));
  } catch {
    return '';
  }
}

function readNumber(bag: unknown, key: string): number | null {
  try {
    return safeNumber(getField(bag, key));
  } catch {
    return null;
  }
}

function findMatch(signature: string, rules: ReadonlyArray<SignatureRule>): string | null {
  for (const rule of rules) {
    try {
      if (rule.pattern.test(signature)) return rule.label;
    } catch {
      // A malformed pattern must never take down the resolver.
    }
  }
  return null;
}

function withheld(reasons: string[]): VmIntegrityResult {
  return {
    virtual_machine: null,
    software_renderer: false,
    confidence: 'low',
    classification: 'unknown',
    reasons: reasons.length ? reasons : ['VM verdict withheld: no usable evidence'],
  };
}

/**
 * Resolve a three-state VM / hardware integrity verdict from the supplied signals.
 *
 * The function is total: any hostile or non-shaped input degrades to `unknown` rather than
 * throwing. Numeric signals are weak hints only — they can annotate `reasons` and reduce the
 * confidence of a physical verdict, but they never set `virtual_machine` to `true`.
 */
export function resolveVmIntegrity(input: VmIntegrityInput = {}): VmIntegrityResult {
  try {
    const bag: unknown = input && typeof input === 'object' ? input : {};
    const vendor = readText(bag, 'gpuVendor');
    const renderer = readText(bag, 'gpuRenderer');
    const signature = `${vendor} ${renderer}`.trim().toLowerCase();
    const reasons: string[] = [];

    const limits = getField(bag, 'webgpuLimits');
    const cores = readNumber(bag, 'cores');
    const memory = readNumber(bag, 'memory');
    const audioSampleRate = readNumber(bag, 'audioSampleRate');
    const audioOutputLatency = readNumber(bag, 'audioOutputLatency');
    const maxChannelCount = readNumber(bag, 'maxChannelCount');
    const jitter = readNumber(bag, 'renderedFramesJitter');
    const webgpuMaxTexture = readNumber(limits, 'maxTextureDimension2D');
    const webgpuMaxBuffer = readNumber(limits, 'maxBufferSize');

    // Weak, non-decisive environment hints. They are collected for attribution only.
    const weakNotes: string[] = [];
    if (cores !== null && cores > 0 && cores <= 2) weakNotes.push(`low core count (${cores})`);
    if (memory !== null && memory >= 0 && memory <= 2) weakNotes.push(`low memory (${memory}GB)`);
    if (
      audioSampleRate !== null &&
      audioSampleRate > 0 &&
      audioSampleRate !== 44100 &&
      audioSampleRate !== 48000
    ) {
      weakNotes.push(`atypical audio sample rate (${audioSampleRate}Hz)`);
    }
    if (audioOutputLatency !== null && (audioOutputLatency <= 0 || audioOutputLatency > 0.5)) {
      weakNotes.push(`atypical audio output latency (${audioOutputLatency}s)`);
    }
    if (maxChannelCount !== null && (maxChannelCount <= 0 || maxChannelCount > 32)) {
      weakNotes.push(`atypical max channel count (${maxChannelCount})`);
    }
    if (jitter !== null && jitter > 0.05) weakNotes.push(`elevated rendered-frame jitter (${jitter})`);
    if (webgpuMaxTexture !== null && webgpuMaxTexture > 0 && webgpuMaxTexture < 4096) {
      weakNotes.push(`low WebGPU maxTextureDimension2D (${webgpuMaxTexture})`);
    }
    if (webgpuMaxBuffer !== null && webgpuMaxBuffer > 0 && webgpuMaxBuffer < 268435456) {
      weakNotes.push(`low WebGPU maxBufferSize (${webgpuMaxBuffer})`);
    }
    if (weakNotes.length) {
      reasons.push(`Weak environment hints (never a VM or physical claim on their own): ${weakNotes.join('; ')}`);
    }

    const vmLabel = findMatch(signature, HYPERVISOR_SIGNATURES);
    const swLabel = findMatch(signature, SOFTWARE_SIGNATURES);
    const siliconLabel = findMatch(signature, SILICON_SIGNATURES);
    const software_renderer = swLabel !== null;

    // 1. Direct hypervisor evidence wins. A software rasteriser may coexist (e.g. a VMware
    //    GPU fallBack), so the software flag is retained but does not drive the VM verdict.
    if (vmLabel) {
      reasons.push(`Hypervisor GPU signature matched: ${vmLabel}`);
      if (software_renderer) {
        reasons.push(`Software rasteriser also present (${swLabel}); recorded, VM verdict driven by hypervisor signature`);
      }
      return {
        virtual_machine: true,
        software_renderer,
        confidence: 'high',
        classification: 'hypervisor',
        reasons,
      };
    }

    // 2. Software rasteriser: the SwiftShader exemption. No auto-true VM verdict, regardless
    //    of how "virtual-looking" the weak numeric hints are.
    if (swLabel) {
      reasons.push(`Software rasteriser signature matched: ${swLabel}`);
      if (siliconLabel) {
        reasons.push(`A manufacturer-sounding token (${siliconLabel}) was seen but is overridden by the software rasteriser signature`);
      }
      reasons.push('Software rendering is NOT virtual-machine proof; virtual_machine withheld as null');
      return {
        virtual_machine: null,
        software_renderer: true,
        confidence: 'high',
        classification: 'software_renderer',
        reasons,
      };
    }

    // 3. Physical, but only on positive silicon evidence — never on absence of VM evidence.
    //    Confidence is capped below 'high' because GPU strings are spoofable claims.
    if (siliconLabel) {
      reasons.push(`Manufacturer GPU silicon reported: ${siliconLabel}`);
      if (weakNotes.length) {
        reasons.push('Constrained/atypical environment hints lower confidence; physical verdict is not asserted confidently');
        return {
          virtual_machine: false,
          software_renderer: false,
          confidence: 'low',
          classification: 'physical',
          reasons,
        };
      }
      reasons.push('Physical verdict capped at medium confidence; hypervisor/software strings are spoofable claims, not anchors');
      return {
        virtual_machine: false,
        software_renderer: false,
        confidence: 'medium',
        classification: 'physical',
        reasons,
      };
    }

    // 4. No usable evidence — abstain. Absence of VM evidence is never a physical claim.
    reasons.push('No hypervisor, software-rasteriser, or manufacturer-silicon signature found');
    reasons.push('Absence of VM evidence is never a confident physical claim; verdict withheld as unknown');
    return withheld(reasons);
  } catch {
    return withheld(['Resolver guard: hostile input caused an internal error; verdict withheld as unknown']);
  }
}

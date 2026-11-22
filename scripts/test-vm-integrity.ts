/**
 * Three-state VM / hardware integrity resolver suite (dependency-free).
 *
 *   npx tsx scripts/test-vm-integrity.ts
 *
 * Covers every classification branch, the tri-state `virtual_machine` field, confidence caps,
 * the preserved SwiftShader/llvmpipe exemption (including under hostile numeric hints), and
 * non-throwing behaviour on hostile / non-shaped inputs.
 */
import { resolveVmIntegrity, type VmIntegrityResult } from '../src/lib/vmIntegrity.ts';

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

function brief(r: VmIntegrityResult | null): string {
  return r
    ? `vm=${String(r.virtual_machine)} sw=${r.software_renderer} ${r.classification}/${r.confidence}`
    : 'threw';
}

/* -------------------------------------------------------------------------- */
/* Hypervisor signatures                                                       */
/* -------------------------------------------------------------------------- */
section('hypervisor classification');

const vmware = resolveVmIntegrity({ gpuVendor: 'VMware', gpuRenderer: 'VMware SVGA3D' });
check('VMware renderer is a hypervisor', vmware.classification === 'hypervisor' && vmware.virtual_machine === true, brief(vmware));
check('hypervisor verdict is high confidence', vmware.confidence === 'high', brief(vmware));
check('hypervisor result has reasons', vmware.reasons.length > 0, vmware.reasons.join(' | '));

const vbox = resolveVmIntegrity({ gpuRenderer: 'VirtualBox Graphics Adapter' });
check('VirtualBox renderer is a hypervisor', vbox.classification === 'hypervisor' && vbox.virtual_machine === true, brief(vbox));

const qemu = resolveVmIntegrity({ gpuRenderer: 'QEMU VirtIO GPU Device' });
check('QEMU/VirtIO renderer is a hypervisor', qemu.classification === 'hypervisor' && qemu.virtual_machine === true, brief(qemu));

const parallels = resolveVmIntegrity({ gpuRenderer: 'Parallels Display Adapter' });
check('Parallels renderer is a hypervisor', parallels.classification === 'hypervisor' && parallels.virtual_machine === true, brief(parallels));

const hyperv = resolveVmIntegrity({ gpuRenderer: 'Microsoft Hyper-V Remote Display Adapter' });
check('Hyper-V renderer is a hypervisor', hyperv.classification === 'hypervisor' && hyperv.virtual_machine === true, brief(hyperv));

const hypervisorNoSoftware = resolveVmIntegrity({ gpuRenderer: 'VMware SVGA3D' });
check('a pure hypervisor signature does not set software_renderer', hypervisorNoSoftware.software_renderer === false, brief(hypervisorNoSoftware));

const hypervisorPlusSoftware = resolveVmIntegrity({ gpuRenderer: 'VMware SVGA3D / SwiftShader fallback' });
check(
  'hypervisor wins classification while software flag is preserved',
  hypervisorPlusSoftware.classification === 'hypervisor' &&
    hypervisorPlusSoftware.virtual_machine === true &&
    hypervisorPlusSoftware.software_renderer === true,
  brief(hypervisorPlusSoftware)
);

/* -------------------------------------------------------------------------- */
/* Software renderer — the preserved SwiftShader exemption                     */
/* -------------------------------------------------------------------------- */
section('software renderer / SwiftShader exemption');

const swiftshader = resolveVmIntegrity({ gpuVendor: 'Google Inc. (Google)', gpuRenderer: 'Google SwiftShader' });
check('SwiftShader is a software renderer', swiftshader.software_renderer === true && swiftshader.classification === 'software_renderer', brief(swiftshader));
check('SwiftShader does NOT auto-set virtual_machine to true', swiftshader.virtual_machine === null, brief(swiftshader));
check('SwiftShader exemption reason is explicit', swiftshader.reasons.some((r) => /NOT virtual-machine proof|withheld as null/i.test(r)), swiftshader.reasons.join(' | '));

const llvmpipe = resolveVmIntegrity({ gpuRenderer: 'llvmpipe (LLVM 17.0.6, 256 bits)' });
check('llvmpipe is a software renderer with VM withheld', llvmpipe.software_renderer === true && llvmpipe.virtual_machine === null && llvmpipe.classification === 'software_renderer', brief(llvmpipe));

const softwareRasterizer = resolveVmIntegrity({ gpuRenderer: 'Mesa OffScreen Software Rasterizer' });
check('generic software rasterizer is classified as software_renderer', softwareRasterizer.classification === 'software_renderer' && softwareRasterizer.software_renderer === true, brief(softwareRasterizer));

const swiftUnderHostileHints = resolveVmIntegrity({
  gpuRenderer: 'SwiftShader Device (Subzero)',
  cores: 1,
  memory: 0.5,
  audioSampleRate: 11025,
  audioOutputLatency: 0.9,
  maxChannelCount: 0,
  renderedFramesJitter: 0.8,
  webgpuLimits: { maxTextureDimension2D: 512, maxBufferSize: 1024 },
});
check(
  'SwiftShader exemption survives low cores/memory/jitter/audio hints',
  swiftUnderHostileHints.software_renderer === true &&
    swiftUnderHostileHints.virtual_machine === null &&
    swiftUnderHostileHints.classification === 'software_renderer',
  brief(swiftUnderHostileHints)
);

const spoofedSilicon = resolveVmIntegrity({ gpuVendor: 'Google Inc.', gpuRenderer: 'SwiftShader masquerading as NVIDIA GeForce RTX 4090' });
check(
  'software signature overrides a spoofed manufacturer token',
  spoofedSilicon.classification === 'software_renderer' && spoofedSilicon.virtual_machine === null,
  brief(spoofedSilicon)
);

/* -------------------------------------------------------------------------- */
/* Physical verdicts (capped confidence, never from absence of evidence)       */
/* -------------------------------------------------------------------------- */
section('physical classification');

const nvidia = resolveVmIntegrity({ gpuVendor: 'NVIDIA Corporation', gpuRenderer: 'NVIDIA GeForce RTX 3080' });
check('NVIDIA silicon is a physical verdict', nvidia.classification === 'physical' && nvidia.virtual_machine === false && nvidia.software_renderer === false, brief(nvidia));
check('physical verdict is never high confidence', nvidia.confidence !== 'high', brief(nvidia));

const amd = resolveVmIntegrity({ gpuRenderer: 'AMD Radeon RX 6700 XT' });
check('AMD silicon is a physical verdict', amd.classification === 'physical' && amd.virtual_machine === false, brief(amd));

const appleSilicon = resolveVmIntegrity({ gpuRenderer: 'Apple M2 Pro' });
check('Apple Silicon is a physical verdict', appleSilicon.classification === 'physical' && appleSilicon.virtual_machine === false, brief(appleSilicon));

const mobileSilicon = resolveVmIntegrity({ gpuVendor: 'ARM', gpuRenderer: 'Mali-G615 MC6' });
check('mobile GPU silicon is a physical verdict', mobileSilicon.classification === 'physical' && mobileSilicon.virtual_machine === false, brief(mobileSilicon));

const physicalWithHints = resolveVmIntegrity({ gpuRenderer: 'Intel(R) UHD Graphics 620', cores: 2, memory: 2, renderedFramesJitter: 0.7 });
check('physical verdict with constrained hints is demoted to low confidence', physicalWithHints.classification === 'physical' && physicalWithHints.confidence === 'low', brief(physicalWithHints));

/* -------------------------------------------------------------------------- */
/* Unknown / abstention                                                        */
/* -------------------------------------------------------------------------- */
section('unknown / abstention');

const empty = resolveVmIntegrity({});
check('empty input is unknown', empty.classification === 'unknown' && empty.virtual_machine === null && empty.software_renderer === false, brief(empty));
check('empty input is never a confident physical claim', empty.classification !== 'physical' && empty.confidence !== 'high', brief(empty));
check('empty input reason explains abstention', empty.reasons.some((r) => /never a confident physical claim|withheld as unknown/i.test(r)), empty.reasons.join(' | '));

const weakOnly = resolveVmIntegrity({ cores: 1, memory: 0.5, audioSampleRate: 11025, audioOutputLatency: 0.9, maxChannelCount: 0, renderedFramesJitter: 0.9, webgpuLimits: { maxTextureDimension2D: 256 } });
check('weak hints alone never create a VM verdict', weakOnly.classification === 'unknown' && weakOnly.virtual_machine === null, brief(weakOnly));
check('weak hints are recorded without promoting classification', weakOnly.reasons.some((r) => /Weak environment hints/i.test(r)), weakOnly.reasons.join(' | '));

const vague = resolveVmIntegrity({ gpuVendor: 'unknown', gpuRenderer: 'unknown' });
check('unknown GPU strings stay unknown', vague.classification === 'unknown' && vague.virtual_machine === null, brief(vague));

const audioOnly = resolveVmIntegrity({ audioSampleRate: 11025, audioOutputLatency: -1, maxChannelCount: 999 });
check('atypical audio values alone do not imply a VM', audioOnly.virtual_machine === null && audioOnly.classification === 'unknown', brief(audioOnly));

/* -------------------------------------------------------------------------- */
/* Output-shape invariants                                                     */
/* -------------------------------------------------------------------------- */
section('output-shape invariants');

const all = [vmware, vbox, qemu, parallels, hyperv, swiftshader, llvmpipe, nvidia, amd, appleSilicon, mobileSilicon, empty, weakOnly, vague];
const confidences = new Set(all.map((r) => r.confidence));
const classifications = new Set(all.map((r) => r.classification));
const vmStates = new Set(all.map((r) => r.virtual_machine));
check('confidence is always one of high/medium/low', [...confidences].every((c) => c === 'high' || c === 'medium' || c === 'low'), [...confidences].join(','));
check(
  'classification is always one of the four states',
  [...classifications].every((c) => c === 'hypervisor' || c === 'software_renderer' || c === 'physical' || c === 'unknown'),
  [...classifications].join(',')
);
check('virtual_machine is genuinely tri-state across cases', vmStates.has(true) && vmStates.has(false) && vmStates.has(null), [...vmStates].map(String).join(','));
check('every result carries at least one reason', all.every((r) => Array.isArray(r.reasons) && r.reasons.length > 0), `${all.filter((r) => r.reasons.length === 0).length} empty`);
check('no result contains a risk score or numeric score field', all.every((r) => !Object.keys(r).some((k) => /risk|score|rank|weight/i.test(k))), Object.keys(all[0]).join(','));

/* -------------------------------------------------------------------------- */
/* Hostile / non-shaped input (non-throwing totality)                          */
/* -------------------------------------------------------------------------- */
section('hostile input / totality');

const nullInput = noThrow(() => resolveVmIntegrity(null as unknown as Parameters<typeof resolveVmIntegrity>[0]));
check('null input does not throw and abstains', nullInput !== null && nullInput.classification === 'unknown' && nullInput.virtual_machine === null, brief(nullInput));

const primitiveInput = noThrow(() => resolveVmIntegrity(42 as unknown as Parameters<typeof resolveVmIntegrity>[0]));
check('primitive input does not throw and abstains', primitiveInput !== null && primitiveInput.classification === 'unknown', brief(primitiveInput));

const hostileTypes = noThrow(() =>
  resolveVmIntegrity({
    gpuVendor: 123 as unknown as string,
    gpuRenderer: { toString: () => 'VMware' } as unknown as string,
    webgpuLimits: [] as unknown as Record<string, unknown>,
    audioSampleRate: Number.NaN,
    audioOutputLatency: '0.2' as unknown as number,
    maxChannelCount: Number.POSITIVE_INFINITY,
    cores: '8' as unknown as number,
    memory: {} as unknown as number,
    renderedFramesJitter: Number.NEGATIVE_INFINITY,
  })
);
check('hostile field types do not throw', hostileTypes !== null, brief(hostileTypes));
check('hostile field types degrade to unknown, never a VM claim', hostileTypes !== null && hostileTypes.virtual_machine === null && hostileTypes.classification === 'unknown', brief(hostileTypes));

const throwingGetter = noThrow(() => {
  const input = {} as Parameters<typeof resolveVmIntegrity>[0];
  Object.defineProperty(input, 'gpuRenderer', {
    get(): string {
      throw new Error('hostile getter');
    },
  });
  return resolveVmIntegrity(input);
});
check('a throwing property getter does not escape the resolver', throwingGetter !== null && throwingGetter.classification === 'unknown', brief(throwingGetter));

const throwingLimits = noThrow(() => {
  const limits = {} as Record<string, unknown>;
  Object.defineProperty(limits, 'maxTextureDimension2D', {
    get(): number {
      throw new Error('hostile limit getter');
    },
  });
  return resolveVmIntegrity({ gpuRenderer: 'NVIDIA GeForce GTX 1650', webgpuLimits: limits });
});
check('a throwing WebGPU-limit getter does not throw', throwingLimits !== null && throwingLimits.classification === 'physical', brief(throwingLimits));

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log(`FAILED: ${failures.join(' | ')}`);
  process.exit(1);
}

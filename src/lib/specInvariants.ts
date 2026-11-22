/**
 * Phase 3 — canonical spec-invariant checks (pure, dependency-free).
 *
 * Every function here is pure and total: it never throws and never reads a platform API.
 * The collector / server may call these with whatever it parsed; the functions return a
 * structured verdict that the tampering invariant and the canonical inspector / GPU-observation
 * helpers use. This module is the single source for GPU observation truth and inspector state.
 *
 * Design rules that must not regress:
 *  - deviceMemory is the real power-of-two set. Desktop Chrome legitimately reports 16 and
 *    32 GB, so there is deliberately NO 8 GB cap.
 *  - SwiftShader / software rendering is not tampering (commit f7d6900).
 *  - Tor / Brave / Firefox FPP+RFP / Safari 26 ATFP are privacy-hardened, not spoofers.
 *  - `tampering.detected === (reasons.length > 0 || hard_spec_violation)` is an exact
 *    invariant after privacy / SwiftShader reasons have been filtered out.
 */

import type {
  // Legacy 4-state vocabulary from the telemetry contract. Aliased so this module can own the
  // canonical 3-state `InspectorState` below without breaking the existing classifier's callers.
  InspectorState as LegacyInspectorState,
  TamperingAxes,
} from './telemetryContract';

export type SpecSeverity = 'hard' | 'soft';

export interface SpecViolation {
  id: string;
  severity: SpecSeverity;
  detail: string;
}

/* -------------------------------------------------------------------------- */
/* Privacy / software-renderer classification                                  */
/* -------------------------------------------------------------------------- */

/** Privacy-hardened browsers deliberately flatten entropy; they are never spoofers. */
export function isPrivacyHardenedUserAgent(userAgent: string): boolean {
  const ua = String(userAgent || '').toLowerCase();
  if (!ua) return false;
  if (/\btor\b|tor browser/.test(ua)) return true;
  if (/\bbrave\b|bravechrom/.test(ua)) return true;
  // Firefox FPP / RFP is part of the Gecko engine, no explicit UA token is required — callers
  // pass a `firefoxFpp` / `resistFingerprinting` flag for that. We still accept a UA hint.
  if (/firefox/.test(ua) && /fpp|rfp|resistfingerprinting/.test(ua)) return true;
  // Safari 26 Advanced Tracking and Fingerprint Protection.
  if (/safari/.test(ua) && /atfp|advanced.*fingerprint|version\/26/.test(ua)) return true;
  return false;
}

export interface PrivacyContext {
  privacyHardened?: boolean;
  firefoxFpp?: boolean;
  resistFingerprinting?: boolean;
  safariAtfp?: boolean;
  torBrowser?: boolean;
  braveShields?: boolean;
  userAgent?: string;
}

export function resolvePrivacyHardened(ctx: PrivacyContext = {}): boolean {
  return Boolean(
    ctx.privacyHardened ||
      ctx.firefoxFpp ||
      ctx.resistFingerprinting ||
      ctx.safariAtfp ||
      ctx.torBrowser ||
      ctx.braveShields ||
      isPrivacyHardenedUserAgent(ctx.userAgent || '')
  );
}

export function isSwiftShaderRenderer(renderer: string): boolean {
  return /swiftshader|subzero|0x0000c0de|llvmpipe|mesa offscreen|software rasterizer/i.test(
    String(renderer || '')
  );
}

/* -------------------------------------------------------------------------- */
/* GPU observation — the single source for GPU truth                           */
/* -------------------------------------------------------------------------- */

/**
 * How much we actually observed about the GPU. This is deliberately an *observation* class,
 * not a machine-identification verdict:
 *  - software_or_virtual REQUIRES an explicit, named identifier in the vendor/renderer string.
 *  - a missing `WEBGL_debug_renderer_info` extension only ever means masked_by_privacy or
 *    observation_unavailable; it is NEVER proof of a virtual machine.
 */
export type GpuObservation =
  | 'hardware_visible'
  | 'masked_by_privacy'
  | 'observation_unavailable'
  | 'software_or_virtual';

/** Explicit, named software / virtual rasteriser identifiers. Nothing here is inferred. */
const SOFTWARE_OR_VIRTUAL_GPU_IDENTIFIER =
  /swiftshader|subzero|llvmpipe|softpipe|mesa offscreen|software rasterizer|software renderer|0x0000c0de|vmware|virtualbox|\bvbox\b|qemu|hyper-?v|microsoft basic render|basic render driver|apple software renderer|virgl/i;

/** Google's SwiftShader fallback is reported under this exact vendor string. */
const GOOGLE_SOFTWARE_VENDOR = /^google inc\.?\s*\(\s*google\s*\)$/i;

/** Placeholder values written when the unmasked-info extension is absent or WebGL failed. */
const GPU_NAME_PLACEHOLDER =
  /^(?:unavailable|unknown|n\/?a|none|null|undefined|standard webgl (?:vendor|renderer)|webkit webgl(?: (?:renderer|vendor))?|webgl(?: (?:vendor|renderer))?|generic (?:renderer|vendor)|mozilla)/i;

function normalizedGpuValue(value: string | null | undefined): string {
  return typeof value === 'string' ? value.trim() : '';
}

function isGpuNamePlaceholder(value: string): boolean {
  return !value || GPU_NAME_PLACEHOLDER.test(value);
}

function hasGpuCapabilityClass(value: string | null | undefined): boolean {
  const text = normalizedGpuValue(value).toLowerCase();
  return Boolean(text) && !['na', 'none', 'null', 'undefined', 'unknown'].includes(text);
}

/**
 * Pure, total resolver for GPU observation truth. `capabilityClass` is the coarse,
 * spoof-resistant capability bucket (e.g. `t16|h|e3`); it is used ONLY to distinguish privacy
 * masking from a genuinely unavailable probe. It is never used to claim software/virtual.
 */
export function resolveGpuObservation(
  vendor: string | null | undefined,
  renderer: string | null | undefined,
  capabilityClass: string | null | undefined
): GpuObservation {
  const v = normalizedGpuValue(vendor);
  const r = normalizedGpuValue(renderer);
  const combined = `${v} ${r}`;

  // 1. Only explicit identifiers may claim software / virtual rendering.
  if (SOFTWARE_OR_VIRTUAL_GPU_IDENTIFIER.test(combined) || GOOGLE_SOFTWARE_VENDOR.test(v)) {
    return 'software_or_virtual';
  }

  const noVendor = isGpuNamePlaceholder(v);
  const noRenderer = isGpuNamePlaceholder(r);
  const capabilitiesPresent = hasGpuCapabilityClass(capabilityClass);

  // 2. An explicit, non-placeholder name was observed -> hardware identity is visible.
  if (!noVendor || !noRenderer) return 'hardware_visible';

  // 3. No usable name (extension masked / probe unavailable). Capabilities decide the bucket:
  //    real capability limits => privacy masking; no capability data => unavailable. Absence of
  //    the extension is NEVER rendered as VM / software proof.
  return capabilitiesPresent ? 'masked_by_privacy' : 'observation_unavailable';
}

/** Only a directly observed hardware identity may serve as a hardware anchor. */
export function gpuObservationIsHardwareAnchor(observation: GpuObservation): boolean {
  return observation === 'hardware_visible';
}

/** Zero-contradiction guard: a masked/unavailable/software observation must not be promoted. */
export function checkGpuObservationInvariants(input: {
  gpu_observation: GpuObservation;
  claimed_hardware_anchor?: boolean;
}): string[] {
  const contradictions: string[] = [];
  if (input.claimed_hardware_anchor === true && !gpuObservationIsHardwareAnchor(input.gpu_observation)) {
    contradictions.push(
      `a '${input.gpu_observation}' GPU observation cannot be used as a hardware identity anchor`
    );
  }
  return contradictions;
}

/* -------------------------------------------------------------------------- */
/* The eight spec invariants                                                   */
/* -------------------------------------------------------------------------- */

/** Valid navigator.deviceMemory values. 16 / 32 are explicitly legal on desktop Chrome. */
export const DEVICE_MEMORY_DOMAIN = [0.25, 0.5, 1, 2, 4, 8, 16, 32] as const;

export function checkDeviceMemory(
  value: number | null | undefined,
  context: { privacyHardened?: boolean } = {}
): SpecViolation[] {
  if (value === null || value === undefined) return [];
  if (!Number.isFinite(value) || !(DEVICE_MEMORY_DOMAIN as readonly number[]).includes(value)) {
    return [
      {
        id: 'spec.device_memory.domain',
        severity: context.privacyHardened ? 'soft' : 'hard',
        detail: `navigator.deviceMemory ${String(value)} is outside the power-of-two domain {0.25,0.5,1,2,4,8,16,32}`,
      },
    ];
  }
  // 16 / 32 are allowed everywhere; there is intentionally no 8 GB ceiling.
  return [];
}

export function checkNetworkRtt(
  rtt: number | null | undefined,
  context: { privacyHardened?: boolean } = {}
): SpecViolation[] {
  if (rtt === null || rtt === undefined) return [];
  if (!Number.isFinite(rtt) || rtt < 0) {
    return [
      { id: 'spec.network_information.rtt_domain', severity: 'hard', detail: `rtt ${String(rtt)} is not a finite non-negative number` },
    ];
  }
  // 0 is explicitly allowed (NetworkInformation reports 0 on fresh connections).
  if (rtt === 0) return [];
  if (Math.abs(rtt % 25) > 1e-9) {
    return [
      {
        id: 'spec.network_information.rtt_quantization',
        severity: context.privacyHardened ? 'soft' : 'hard',
        detail: `rtt ${rtt} is not a multiple of 25`,
      },
    ];
  }
  return [];
}

export interface BatteryLike {
  charging?: boolean;
  chargingTime?: number;
  dischargingTime?: number;
  level?: number;
}

/** BatteryManager mutually-exclusive charging / discharging times. */
export function checkBatteryManager(battery: BatteryLike | null | undefined): SpecViolation[] {
  if (!battery) return [];
  const charging = battery.charging;
  const hasChargingTime = Number.isFinite(battery.chargingTime);
  const hasDischargingTime = Number.isFinite(battery.dischargingTime);
  const violations: SpecViolation[] = [];
  // Both finite at once (or both infinite at once) is impossible on a real BatteryManager.
  if (hasChargingTime && hasDischargingTime) {
    violations.push({
      id: 'spec.battery_manager.mutual_exclusion',
      severity: 'hard',
      detail: 'chargingTime and dischargingTime are both finite',
    });
  }
  if (charging === true && hasDischargingTime) {
    violations.push({
      id: 'spec.battery_manager.charging_state',
      severity: 'hard',
      detail: 'a charging battery cannot report a finite dischargingTime',
    });
  }
  if (charging === false && hasChargingTime) {
    violations.push({
      id: 'spec.battery_manager.discharging_state',
      severity: 'hard',
      detail: 'a discharging battery cannot report a finite chargingTime',
    });
  }
  return violations;
}

/** V8 heap-limit lattice tolerance: > 1% deviation is a SOFT warning only. */
export function checkJsHeapSizeLimit(
  observed: number | null | undefined,
  expected: number | null | undefined
): SpecViolation[] {
  if (!observed || !expected || !Number.isFinite(observed) || !Number.isFinite(expected)) return [];
  const deviation = Math.abs(observed - expected) / Math.max(1, expected);
  if (deviation > 0.01) {
    return [
      {
        id: 'spec.v8.js_heap_size_limit',
        severity: 'soft',
        detail: `performance.memory.jsHeapSizeLimit deviates ${(deviation * 100).toFixed(2)}% from the V8 lattice (soft warning only)`,
      },
    ];
  }
  return [];
}

export type WebglBackend = 'direct3d' | 'metal' | 'mesa' | 'swiftshader' | 'vulkan' | 'unknown';

export function classifyWebglBackend(renderer: string): WebglBackend {
  const text = String(renderer || '').toLowerCase();
  if (/swiftshader|subzero|0x0000c0de/.test(text)) return 'swiftshader';
  if (/direct3d|d3d11|d3d12|\bd3d\b/.test(text)) return 'direct3d';
  if (/metal/.test(text)) return 'metal';
  if (/mesa|llvmpipe/.test(text)) return 'mesa';
  if (/vulkan/.test(text)) return 'vulkan';
  return 'unknown';
}

/** WebGL backend vs declared OS family. Cross-platform software backends are always legal. */
export function checkWebglBackendAgainstOs(
  renderer: string,
  osFamily: string,
  context: { privacyHardened?: boolean } = {}
): SpecViolation[] {
  const backend = classifyWebglBackend(renderer);
  const os = String(osFamily || '').toLowerCase();
  if (backend === 'swiftshader' || backend === 'vulkan' || backend === 'unknown') return [];
  const osMatches =
    (backend === 'direct3d' && /windows|win32|win64/.test(os)) ||
    (backend === 'metal' && /macos|mac os|ios|ipad|iphone/.test(os)) ||
    (backend === 'mesa' && /linux|ubuntu|fedora|debian|chrome ?os/.test(os));
  if (!osMatches) {
    return [
      {
        id: 'spec.webgl.backend_os_mismatch',
        severity: context.privacyHardened ? 'soft' : 'hard',
        detail: `WebGL backend ${backend} is inconsistent with OS ${osFamily || 'unknown'}`,
      },
    ];
  }
  return [];
}

/** Desktop Chrome exposes a PDF viewer face; mobile builds do not. Soft: enterprise builds vary. */
export function checkPdfPluginFace(
  deviceKind: 'pc' | 'mobile' | 'tablet' | 'unknown',
  hasPdfFace: boolean | null | undefined
): SpecViolation[] {
  if (deviceKind === 'unknown' || hasPdfFace === null || hasPdfFace === undefined) return [];
  const desktopWithoutPdf = deviceKind === 'pc' && hasPdfFace === false;
  const mobileWithPdf = (deviceKind === 'mobile' || deviceKind === 'tablet') && hasPdfFace === true;
  if (desktopWithoutPdf || mobileWithPdf) {
    return [
      {
        id: 'spec.pdf_plugin.face',
        severity: 'soft',
        detail: `PDF plugin face (${hasPdfFace}) disagrees with device kind ${deviceKind}`,
      },
    ];
  }
  return [];
}

export interface TransportIdentity {
  httpPlatform?: string;
  httpPlatformVersion?: string;
  jsPlatform?: string;
  userAgent?: string;
}

/** HTTP / UA-CH vs JS platform reconciliation, including the Windows 11 NT 10.0 mapping. */
export function checkHttpUaChReconciliation(
  transport: TransportIdentity,
  context: { privacyHardened?: boolean } = {}
): SpecViolation[] {
  const http = String(transport.httpPlatform || '').toLowerCase();
  const js = String(transport.jsPlatform || '').toLowerCase();
  if (!http || !js) return [];
  const family = (value: string): string => {
    if (/win/.test(value)) return 'windows';
    if (/mac|iphone|ipad|ipod/.test(value)) return 'apple';
    if (/android/.test(value)) return 'android';
    if (/linux|cros|chrome ?os/.test(value)) return 'linux';
    return '';
  };
  const httpFamily = family(http);
  const jsFamily = family(js);
  // Windows 11 reports NT 10.0 and a UA-CH platformVersion >= 13; both still map to "windows",
  // so a Win10 label in JS must not be flagged as a spoof.
  if (httpFamily && jsFamily && httpFamily !== jsFamily) {
    return [
      {
        id: 'spec.transport.platform_reconciliation',
        severity: context.privacyHardened ? 'soft' : 'hard',
        detail: `HTTP/UA-CH platform ${http} disagrees with JS platform ${js}`,
      },
    ];
  }
  return [];
}

export interface HardwareSnapshot {
  gpu?: string;
  cpuCores?: number | null;
  memoryGb?: number | null;
  screen?: string;
  platform?: string;
}

/** Cross-load hardware drift; privacy browsers legitimately rotate entropy between loads. */
export function checkHardwareDrift(
  current: HardwareSnapshot,
  previous: HardwareSnapshot,
  context: { privacyHardened?: boolean } = {}
): SpecViolation[] {
  if (context.privacyHardened) return [];
  const violations: SpecViolation[] = [];
  const compare = (key: keyof HardwareSnapshot, label: string): void => {
    const a = current[key];
    const b = previous[key];
    if (a === undefined || b === undefined || a === null || b === null) return;
    if (String(a) !== String(b)) {
      violations.push({
        id: `spec.hardware_drift.${label}`,
        severity: 'hard',
        detail: `${label} drifted from ${String(b)} to ${String(a)} across loads`,
      });
    }
  };
  compare('gpu', 'gpu');
  compare('cpuCores', 'cpuCores');
  compare('memoryGb', 'memoryGb');
  compare('screen', 'screen');
  compare('platform', 'platform');
  return violations;
}

/* -------------------------------------------------------------------------- */
/* Aggregation + exact tampering invariant                                     */
/* -------------------------------------------------------------------------- */

export interface SpecInvariantInput extends PrivacyContext {
  deviceMemoryGb?: number | null;
  networkRtt?: number | null;
  battery?: BatteryLike | null;
  jsHeapSizeLimit?: number | null;
  expectedJsHeapSizeLimit?: number | null;
  webglRenderer?: string;
  /** Unmasked WebGL vendor string, when the client captured it. */
  webglVendor?: string;
  /** Coarse, capability-derived GPU class (e.g. `t16|h|e3`); not a spoofable string. */
  gpuCapabilityClass?: string;
  osFamily?: string;
  deviceKind?: 'pc' | 'mobile' | 'tablet' | 'unknown';
  hasPdfFace?: boolean | null;
  transport?: TransportIdentity;
  currentHardware?: HardwareSnapshot;
  previousHardware?: HardwareSnapshot;
}

export interface SpecInvariantResult {
  violations: SpecViolation[];
  reasons: string[];
  hardViolations: string[];
  softViolations: string[];
  hard_spec_violation: boolean;
  privacy_hardened: boolean;
  software_renderer: boolean;
  /** Canonical GPU observation class; masked / unavailable is never VM proof. */
  gpu_observation: GpuObservation;
}

export function evaluateSpecInvariants(input: SpecInvariantInput = {}): SpecInvariantResult {
  const privacyHardened = resolvePrivacyHardened(input);
  const softwareRenderer = isSwiftShaderRenderer(input.webglRenderer || '');
  const gpuObservation = resolveGpuObservation(
    input.webglVendor,
    input.webglRenderer,
    input.gpuCapabilityClass
  );
  const violations: SpecViolation[] = [
    ...checkDeviceMemory(input.deviceMemoryGb, { privacyHardened }),
    ...checkNetworkRtt(input.networkRtt, { privacyHardened }),
    ...checkBatteryManager(input.battery),
    ...checkJsHeapSizeLimit(input.jsHeapSizeLimit, input.expectedJsHeapSizeLimit),
    ...checkWebglBackendAgainstOs(input.webglRenderer || '', input.osFamily || '', { privacyHardened }),
    ...checkPdfPluginFace(input.deviceKind || 'unknown', input.hasPdfFace),
    ...checkHttpUaChReconciliation(input.transport || {}, { privacyHardened }),
    ...checkHardwareDrift(input.currentHardware || {}, input.previousHardware || {}, { privacyHardened }),
  ];
  const hard = violations.filter((v) => v.severity === 'hard');
  const soft = violations.filter((v) => v.severity === 'soft');
  return {
    violations,
    reasons: violations.map((v) => v.detail),
    hardViolations: hard.map((v) => v.id),
    softViolations: soft.map((v) => v.id),
    hard_spec_violation: hard.length > 0,
    privacy_hardened: privacyHardened,
    software_renderer: softwareRenderer,
    gpu_observation: gpuObservation,
  };
}

/**
 * Enforce the exact tampering invariant after privacy / SwiftShader exemptions.
 *
 * `tampering.detected === (reasons.length > 0 || hard_spec_violation)` — with the exemption
 * applied by filtering the *reasons* and neutralizing hard spec violations that are purely
 * privacy-induced before the equality is evaluated.
 */
export function enforceTamperingInvariant(input: {
  reasons?: readonly string[];
  hard_spec_violation?: boolean;
  privacy_hardened?: boolean;
  software_renderer?: boolean;
}): Pick<TamperingAxes, 'detected' | 'reasons' | 'hard_spec_violation' | 'privacy_hardened'> {
  const privacy = Boolean(input.privacy_hardened);
  const swiftshader = Boolean(input.software_renderer);
  const rawReasons = (input.reasons || []).filter((r) => typeof r === 'string' && r.trim());
  const reasons = rawReasons.filter((reason) => {
    if (privacy && /privacy|rfp|fpp|brave|tor|atfp|fingerprint.?protection/i.test(reason)) return false;
    if (swiftshader && /swiftshader|software.?render|llvmpipe|mesa offscreen/i.test(reason)) return false;
    return true;
  });
  // A hard spec violation caused solely by a privacy browser is exempt; any independent hard
  // violation survives.
  const hard_spec_violation = Boolean(input.hard_spec_violation) && !privacy;
  const detected = reasons.length > 0 || hard_spec_violation;
  return { detected, reasons, hard_spec_violation, privacy_hardened: privacy };
}

/* -------------------------------------------------------------------------- */
/* Inspector state — canonical 3-state vocabulary (legacy 4-state preserved)   */
/* -------------------------------------------------------------------------- */

/**
 * Canonical inspector state. This is the single source consumed by the flag resolver and
 * by the verdict guard: `no` = no inspector; `yes-unattributed` = an inspector was observed
 * but cannot be attributed to a confirmed CDP+DevTools pair; `yes-corroborated` = the CDP
 * binding and the DevTools canary were both observed.
 */
export type InspectorState = 'no' | 'yes-unattributed' | 'yes-corroborated';

/** Legacy alias for callers that still speak the 4-state telemetry-contract vocabulary. */
export type LegacyInspectorStateAlias = LegacyInspectorState;

export interface InspectorSignals {
  /** A CDP Runtime/Network protocol binding was observed on this load. */
  cdpAttached?: boolean;
  /** Token-scoped source-map canary confirmed a live DevTools frontend. */
  devtoolsActiveVerified?: boolean;
  /** Mid-session viewport contraction that survives zoom normalization. */
  viewportContractionNormalized?: boolean;
}

/**
 * Map either vocabulary onto the canonical 3-state value. A bare CDP binding, a suspected
 * docked DevTools or a verified DevTools canary are all `yes-unattributed` on their own: only
 * CDP corroborated by the DevTools canary is `yes-corroborated`.
 */
export function toInspectorState(state: InspectorState | LegacyInspectorState): InspectorState {
  switch (state) {
    case 'yes-corroborated':
      return 'yes-corroborated';
    case 'yes-unattributed':
    case 'automation_protocol_attached':
    case 'devtools_docked_suspected':
    case 'devtools_active_verified':
      return 'yes-unattributed';
    case 'no':
    case 'closed':
    default:
      return 'no';
  }
}

/** Resolve the canonical state directly from the raw, passive inspector probes. */
export function resolveInspectorState(signals: InspectorSignals = {}): InspectorState {
  const cdp = Boolean(signals.cdpAttached);
  const devtools = Boolean(signals.devtoolsActiveVerified);
  if (cdp && devtools) return 'yes-corroborated';
  if (cdp || devtools || Boolean(signals.viewportContractionNormalized)) return 'yes-unattributed';
  return 'no';
}

/**
 * Canonical flag resolver.
 *  - no                 -> neither flag.
 *  - yes-unattributed   -> cdp_attached:false, developer_tools:true (an unattributed CDP signal
 *                          is honest DevTools telemetry, never a confirmed CDP attachment).
 *  - yes-corroborated   -> both flags true (CDP and DevTools agree).
 * Legacy 4-state inputs are normalised first, so both vocabularies agree exactly.
 */
export function inspectorFlagsForState(
  state: InspectorState | LegacyInspectorState
): { cdp_attached: boolean; developer_tools: boolean } {
  switch (toInspectorState(state)) {
    case 'yes-corroborated':
      return { cdp_attached: true, developer_tools: true };
    case 'yes-unattributed':
      return { cdp_attached: false, developer_tools: true };
    case 'no':
    default:
      return { cdp_attached: false, developer_tools: false };
  }
}

/**
 * Legacy 4-state classifier, kept compatible for existing callers (same inputs, same outputs).
 * New code should prefer `resolveInspectorState` and then `inspectorFlagsForState`.
 */
export function classifyInspectorState(signals: InspectorSignals = {}): LegacyInspectorState {
  if (signals.cdpAttached) return 'automation_protocol_attached';
  if (signals.devtoolsActiveVerified) return 'devtools_active_verified';
  if (signals.viewportContractionNormalized) return 'devtools_docked_suspected';
  return 'closed';
}

/** A "Verified Human" verdict is permitted only when no inspector was observed at all. */
export function permitsHumanVerdict(state: InspectorState | LegacyInspectorState): boolean {
  return toInspectorState(state) === 'no';
}

export interface InspectorInvariantInput {
  inspector_state: InspectorState | LegacyInspectorState;
  cdp_attached?: boolean;
  developer_tools?: boolean;
  /** Optional verdict tier to cross-check against the inspector state. */
  verdict_tier?: string | null;
}

export interface InspectorInvariantResult {
  consistent: boolean;
  contradictions: string[];
  canonical_state: InspectorState;
  expected_flags: { cdp_attached: boolean; developer_tools: boolean };
  permits_human_verdict: boolean;
}

/**
 * Zero-contradiction checker: the reported flags and verdict must agree with the state.
 * An empty `contradictions` array is the invariant — flags cannot drift from the state, and a
 * "Verified Human" verdict can never be rendered while an inspector is present.
 */
export function checkInspectorInvariants(input: InspectorInvariantInput): InspectorInvariantResult {
  const canonical_state = toInspectorState(input.inspector_state);
  const expected_flags = inspectorFlagsForState(canonical_state);
  const contradictions: string[] = [];

  if (
    input.cdp_attached !== undefined &&
    Boolean(input.cdp_attached) !== expected_flags.cdp_attached
  ) {
    contradictions.push(
      `cdp_attached=${Boolean(input.cdp_attached)} contradicts inspector_state '${canonical_state}' (expected ${expected_flags.cdp_attached})`
    );
  }
  if (
    input.developer_tools !== undefined &&
    Boolean(input.developer_tools) !== expected_flags.developer_tools
  ) {
    contradictions.push(
      `developer_tools=${Boolean(input.developer_tools)} contradicts inspector_state '${canonical_state}' (expected ${expected_flags.developer_tools})`
    );
  }

  const permits_human_verdict = permitsHumanVerdict(canonical_state);
  const tier = typeof input.verdict_tier === 'string' ? input.verdict_tier : '';
  if (!permits_human_verdict && /verified\s+human/i.test(tier)) {
    contradictions.push(
      `"Verified Human" verdict is forbidden while inspector_state is '${canonical_state}'`
    );
  }

  return {
    consistent: contradictions.length === 0,
    contradictions,
    canonical_state,
    expected_flags,
    permits_human_verdict,
  };
}

/** Boolean convenience wrapper around `checkInspectorInvariants`. */
export function hasInspectorContradictions(input: InspectorInvariantInput): boolean {
  return checkInspectorInvariants(input).contradictions.length > 0;
}

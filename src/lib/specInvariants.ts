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
  NetworkAxes,
  TamperingAxes,
} from './telemetryContract';
import { timezonesEquivalent, timezoneMismatchContext } from './timezone';

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

/* -------------------------------------------------------------------------- */
/* Shadow parity — proxy / VPN truth diagnostics (additive)                     */
/* -------------------------------------------------------------------------- */

/** The published `vpn_methods` mirror, narrowed to the flag shadow parity inspects. */
export interface ShadowVpnMethods {
  timezone_mismatch?: boolean | null;
  [key: string]: unknown;
}

/**
 * Everything the shadow-parity check needs. All fields are optional: the checker reports only
 * contradictions it can actually observe, so partial payloads yield fewer diagnostics, never a
 * guessed verdict. Both the canonical network axis and the flat mirrors are accepted.
 */
export interface ShadowProxyVpnInput {
  /** Canonical network axis (verbatim from the envelope), when available. */
  network?: Partial<NetworkAxes> | null;
  /** Explicit datacenter truth; when present it overrides `network.network_ownership`. */
  datacenterAsn?: boolean | null;
  /** Published proxy flag; only an explicit `false` counts as "published as proxy:false". */
  proxy?: boolean | null;
  /** Server `vpn_methods` mirror (camelCase spelling). */
  vpnMethods?: ShadowVpnMethods | null;
  /** Server `vpn_methods` mirror (snake_case spelling). */
  vpn_methods?: ShadowVpnMethods | null;
  /** Published canonical timezone flag, used when no `vpn_methods` mirror was supplied. */
  timezoneMismatch?: boolean | null;
  /** Raw timezone strings resolved through the shared canonical IANA resolver. */
  browserTimezone?: string | null;
  ipTimezone?: string | null;
  /** Verified good-bot / crawler network exemption for a datacenter ASN. */
  verifiedGoodBot?: boolean | null;
  botSubtype?: string | null;
  /** snake_case / raw-payload aliases, accepted so callers can forward server fields verbatim. */
  datacenter_asn?: boolean | null;
  datacenter_result?: boolean | null;
  asn_type?: string | null;
  network_ownership?: NetworkAxes['network_ownership'] | null;
  good_bot_exempt?: boolean | null;
  verified_good_bot?: boolean | null;
  bot_subtype?: string | null;
  browser_timezone?: string | null;
  ip_timezone?: string | null;
  timezone_mismatch?: boolean | null;
}

/** Defensive field read: hostile getters / proxies can throw, and this module must stay total. */
function shadowField(record: unknown, key: string): unknown {
  try {
    if (record === null || record === undefined) return undefined;
    if (typeof record !== 'object' && typeof record !== 'function') return undefined;
    return (record as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function shadowBool(record: unknown, key: string): boolean | undefined {
  const value = shadowField(record, key);
  return typeof value === 'boolean' ? value : undefined;
}

/**
 * Detects shadow-parity contradictions between the published proxy / VPN mirrors and the
 * canonical truth they are supposed to shadow:
 *  1. a datacenter / hosting ASN published as `proxy:false` with no verified-good-bot exemption;
 *  2. a real canonical timezone mismatch published as `vpn_methods.timezone_mismatch=false`;
 *  3. a legacy alias pair (e.g. `Asia/Calcutta` vs `Asia/Kolkata`) published as `=true`.
 *
 * Pure and total: returns diagnostics and never throws. Absence of evidence is never a diagnostic
 * — a flag is inspected only when it was explicitly published as a boolean.
 */
export function checkShadowProxyVpnInvariants(input: ShadowProxyVpnInput = {}): string[] {
  try {
    const source = input && typeof input === 'object' ? input : ({} as ShadowProxyVpnInput);
    const diagnostics: string[] = [];
    const network = shadowField(source, 'network');

    // 1. Datacenter ASN published as proxy:false without the verified-good-bot exemption.
    const explicitDatacenter =
      shadowBool(source, 'datacenterAsn') ??
      shadowBool(source, 'datacenter_asn') ??
      shadowBool(source, 'datacenter_result');
    const ownership = shadowField(network, 'network_ownership') ?? shadowField(source, 'network_ownership');
    const asnType = shadowField(source, 'asn_type');
    const datacenterAsnLabel =
      typeof asnType === 'string' && /datacenter|data[_-]?center|hosting|cloud/i.test(asnType);
    const datacenter =
      explicitDatacenter === true ||
      (explicitDatacenter === undefined &&
        (ownership === 'hosting_datacenter' || datacenterAsnLabel));
    const publishedProxy = shadowBool(source, 'proxy') ?? shadowBool(network, 'proxy');
    const goodBotExempt =
      shadowBool(source, 'verifiedGoodBot') === true ||
      shadowBool(source, 'verified_good_bot') === true ||
      shadowBool(source, 'good_bot_exempt') === true ||
      shadowField(source, 'botSubtype') === 'good_bot' ||
      shadowField(source, 'bot_subtype') === 'good_bot';
    if (datacenter && publishedProxy === false && !goodBotExempt) {
      diagnostics.push(
        'datacenter/hosting ASN is published as proxy:false without a verified-good-bot exemption'
      );
    }

    // 2 & 3. Canonical timezone truth vs the published vpn_methods mirror.
    const browserTz = shadowField(source, 'browserTimezone') ?? shadowField(source, 'browser_timezone');
    const ipTz = shadowField(source, 'ipTimezone') ?? shadowField(source, 'ip_timezone');
    if (typeof browserTz === 'string' && typeof ipTz === 'string') {
      const canonical = timezoneMismatchContext(browserTz, ipTz);
      const methods = shadowField(source, 'vpnMethods') ?? shadowField(source, 'vpn_methods');
      const publishedMismatch =
        shadowBool(methods, 'timezone_mismatch') ??
        shadowBool(source, 'timezoneMismatch') ??
        shadowBool(source, 'timezone_mismatch') ??
        shadowBool(network, 'timezone_mismatch');

      if (canonical.mismatch && publishedMismatch === false) {
        diagnostics.push(
          `canonical timezone mismatch (${String(canonical.canonicalBrowser)} vs ${String(canonical.canonicalIp)}) is published as vpn_methods.timezone_mismatch=false`
        );
      }

      // An alias pair resolves to one canonical zone despite different raw spellings, so a
      // published mismatch=true is a false positive (Calcutta/Kolkata). Unresolved zones are
      // never treated as an alias pair — absence of evidence is not a contradiction.
      const rawSpellingsDiffer = browserTz.trim() !== ipTz.trim();
      if (rawSpellingsDiffer && publishedMismatch === true && timezonesEquivalent(browserTz, ipTz)) {
        diagnostics.push(
          `timezone alias pair (${browserTz} / ${ipTz} -> ${String(canonical.canonicalBrowser)}) is published as vpn_methods.timezone_mismatch=true`
        );
      }
    }

    return diagnostics;
  } catch {
    return [];
  }
}

/* -------------------------------------------------------------------------- */
/* Integrated fields — additive invariant helpers                              */
/* -------------------------------------------------------------------------- */

/**
 * Read a published boolean that may arrive flat, or as an EventV4-style
 * `DetectionSignal` (`{ detected }`). Only a literal `true`/`false` is evidence;
 * `shadowField` / `shadowBool` keep hostile getters from escaping as a throw.
 */
function integratedBool(record: unknown, key: string): boolean | undefined {
  const value = shadowField(record, key);
  if (typeof value === 'boolean') return value;
  return shadowBool(value, 'detected');
}

/** Explicit verified-good-bot / crawler exemption for a datacenter label. */
function integratedGoodBotExempt(source: unknown): boolean {
  return (
    shadowBool(source, 'verified_good_bot') === true ||
    shadowBool(source, 'verifiedGoodBot') === true ||
    shadowBool(source, 'good_bot_exempt') === true ||
    shadowBool(source, 'goodBotExempt') === true ||
    shadowField(source, 'bot_subtype') === 'good_bot' ||
    shadowField(source, 'botSubtype') === 'good_bot'
  );
}

function integratedDatacenterLabel(value: unknown): boolean {
  return (
    typeof value === 'string' &&
    /datacenter|data[_-]?center|hosting|cloud/i.test(value)
  );
}

/**
 * The fields the privacy / anti-detect invariant inspects. Every field is optional: a partial
 * payload yields only the diagnostics it can actually support. `privacy_settings` accepts both
 * the flat boolean and the EventV4 `DetectionSignal` shape; `anti_detect_browser` also accepts
 * the canonical `tampering` axis and the flat `tampering_details` mirror.
 */
export interface PrivacyAntiDetectInput {
  privacy_settings?: boolean | { detected?: boolean | null } | null;
  privacySettings?: boolean | { detected?: boolean | null } | null;
  anti_detect_browser?: boolean | null;
  antiDetectBrowser?: boolean | null;
  tampering?: { anti_detect_browser?: boolean | null } | null;
  tampering_details?: { anti_detect_browser?: boolean | null } | null;
  tamperingDetails?: { anti_detect_browser?: boolean | null } | null;
  /** Explicit evidence that the privacy signature is forged / contradicted. */
  contradiction_evidence?: boolean | null;
  contradictionEvidence?: boolean | null;
  forged_privacy_signature?: boolean | null;
  [key: string]: unknown;
}

/**
 * Privacy hardening must never *fabricate* an anti-detect-browser finding. A fired
 * `privacy_settings` signature (Brave / Firefox RFP / Tor / Safari AFP / corroborated reduced
 * entropy) suppresses the legacy anti-detect penalty unless the signature itself is explicitly
 * contradicted. This is purely additive: it never touches the privacy/SwiftShader exemptions in
 * `evaluateSpecInvariants` / `enforceTamperingInvariant`, and it reports only when both flags were
 * explicitly published as booleans. Pure and total — never throws.
 */
export function checkPrivacySettingsAntiDetectInvariants(
  input: PrivacyAntiDetectInput = {}
): string[] {
  try {
    const source = input && typeof input === 'object' ? input : ({} as PrivacyAntiDetectInput);
    const privacySettings =
      integratedBool(source, 'privacy_settings') ?? integratedBool(source, 'privacySettings');
    const antiDetect =
      integratedBool(source, 'anti_detect_browser') ??
      integratedBool(source, 'antiDetectBrowser') ??
      shadowBool(shadowField(source, 'tampering'), 'anti_detect_browser') ??
      shadowBool(shadowField(source, 'tampering_details'), 'anti_detect_browser') ??
      shadowBool(shadowField(source, 'tamperingDetails'), 'anti_detect_browser');
    const contradicted =
      shadowBool(source, 'contradiction_evidence') === true ||
      shadowBool(source, 'contradictionEvidence') === true ||
      shadowBool(source, 'forged_privacy_signature') === true;

    const diagnostics: string[] = [];
    if (privacySettings === true && antiDetect === true && !contradicted) {
      diagnostics.push(
        'privacy_settings=true must not fabricate anti_detect_browser=true without explicit contradiction evidence (a forged/contradicted privacy signature)'
      );
    }
    return diagnostics;
  } catch {
    return [];
  }
}

/** Alias for callers that name the check after the two axes rather than the published field. */
export const checkPrivacyAntiDetectInvariants = checkPrivacySettingsAntiDetectInvariants;

/**
 * Fields for the `proxy_details` vs datacenter-truth invariant. Datacenter truth can come from the
 * explicit result/asn booleans, the canonical network ownership axis, or an ASN type label; the
 * published proxy details can come from the nested mirror (`proxy_details` / `proxyDetails`) or
 * the flat `proxy` / `proxy_type` mirrors. All are optional.
 */
export interface ProxyDetailsDatacenterInput {
  proxy_details?: {
    proxy?: boolean | null;
    proxy_type?: string | null;
    proxyType?: string | null;
    [key: string]: unknown;
  } | null;
  proxyDetails?: ProxyDetailsDatacenterInput['proxy_details'];
  proxy?: boolean | null;
  proxy_type?: string | null;
  proxyType?: string | null;
  datacenter_result?: boolean | null;
  datacenterResult?: boolean | null;
  datacenter_asn?: boolean | null;
  datacenterAsn?: boolean | null;
  asn_type?: string | null;
  asnType?: string | null;
  network?: Partial<NetworkAxes> | null;
  network_ownership?: NetworkAxes['network_ownership'] | null;
  verified_good_bot?: boolean | null;
  verifiedGoodBot?: boolean | null;
  good_bot_exempt?: boolean | null;
  goodBotExempt?: boolean | null;
  bot_subtype?: string | null;
  botSubtype?: string | null;
  [key: string]: unknown;
}

/**
 * `proxy_details` must never contradict datacenter truth without the verified-good-bot
 * exemption. With an explicit datacenter/hosting truth and no exemption, a published
 * `proxy:false` or a residential/none `proxy_type` is a contradiction; conversely, with explicit
 * non-datacenter (residential / mobile-carrier) truth, a `data_center` claim is a fabrication.
 * Absence of evidence is never a contradiction: only explicitly published booleans/labels are
 * inspected, and the good-bot exemption suppresses the datacenter claim in both directions.
 * Pure and total — never throws.
 */
export function checkProxyDetailsDatacenterInvariants(
  input: ProxyDetailsDatacenterInput = {}
): string[] {
  try {
    const source = input && typeof input === 'object' ? input : ({} as ProxyDetailsDatacenterInput);
    if (integratedGoodBotExempt(source)) return [];

    const explicitDatacenter =
      shadowBool(source, 'datacenter_result') ??
      shadowBool(source, 'datacenterResult') ??
      shadowBool(source, 'datacenter_asn') ??
      shadowBool(source, 'datacenterAsn');
    const network = shadowField(source, 'network');
    const ownership = shadowField(network, 'network_ownership') ?? shadowField(source, 'network_ownership');
    const datacenterLabel =
      integratedDatacenterLabel(shadowField(source, 'asn_type')) ||
      integratedDatacenterLabel(shadowField(source, 'asnType'));
    const datacenter =
      explicitDatacenter === true ||
      (explicitDatacenter === undefined && (ownership === 'hosting_datacenter' || datacenterLabel));
    const nonDatacenter =
      explicitDatacenter === false ||
      (explicitDatacenter === undefined &&
        (ownership === 'residential_isp' || ownership === 'mobile_carrier'));

    const details = shadowField(source, 'proxy_details') ?? shadowField(source, 'proxyDetails');
    const publishedProxy = shadowBool(details, 'proxy') ?? shadowBool(source, 'proxy');
    const rawType =
      shadowField(details, 'proxy_type') ??
      shadowField(details, 'proxyType') ??
      shadowField(source, 'proxy_type') ??
      shadowField(source, 'proxyType');
    const publishedType =
      typeof rawType === 'string' ? rawType.trim().toLowerCase().replace(/[\s-]+/g, '_') : null;
    const claimsDataCenter = publishedType === 'data_center' || publishedType === 'datacenter';
    const claimsResidential =
      publishedType === 'residential' ||
      publishedType === 'residential_rotating' ||
      publishedType === 'residential_proxy';
    const claimsNone = publishedType === 'none' || publishedType === 'null' || publishedType === '';

    const diagnostics: string[] = [];
    if (datacenter) {
      if (publishedProxy === false) {
        diagnostics.push(
          'proxy_details.proxy=false contradicts datacenter/hosting truth without a verified-good-bot exemption'
        );
      }
      if (claimsResidential || claimsNone) {
        diagnostics.push(
          `proxy_details.proxy_type=${String(publishedType)} contradicts datacenter/hosting truth without a verified-good-bot exemption`
        );
      }
    } else if (nonDatacenter && claimsDataCenter) {
      diagnostics.push(
        'proxy_details.proxy_type=data_center contradicts explicit non-datacenter truth without a verified-good-bot exemption'
      );
    }
    return diagnostics;
  } catch {
    return [];
  }
}

/** Alias for callers that name the check after the contradiction it reports. */
export const checkProxyDetailsDatacenterContradictions = checkProxyDetailsDatacenterInvariants;

/**
 * Fields for the `vpn_methods.timezone_mismatch` parity invariant. The resolved side always comes
 * from the shared canonical IANA resolver (`timezoneMismatchContext` / `timezonesEquivalent`),
 * never from a raw string compare or a UTC-offset coincidence.
 */
export interface VpnMethodsTimezoneInput {
  vpn_methods?: { timezone_mismatch?: boolean | null; [key: string]: unknown } | null;
  vpnMethods?: VpnMethodsTimezoneInput['vpn_methods'];
  timezone_mismatch?: boolean | null;
  timezoneMismatch?: boolean | null;
  network?: { timezone_mismatch?: boolean | null } | null;
  browser_timezone?: string | null;
  browserTimezone?: string | null;
  ip_timezone?: string | null;
  ipTimezone?: string | null;
  [key: string]: unknown;
}

/**
 * Canonical-resolver parity for the published `vpn_methods.timezone_mismatch` flag. Reports only
 * when the flag was explicitly published and both timezone strings were supplied:
 *  - a real canonical mismatch (two distinct canonical zone identities) published as `false`;
 *  - a `true` flag that the canonical resolver does not support (an alias pair such as
 *    Asia/Calcutta vs Asia/Kolkata, or identical zones).
 * An unresolved side is absence of evidence, never a manufactured mismatch. Pure and total —
 * never throws. This is intentionally independent of the existing shadow-parity checker so no
 * existing check or severity is modified.
 */
export function checkVpnMethodsTimezoneInvariants(
  input: VpnMethodsTimezoneInput = {}
): string[] {
  try {
    const source = input && typeof input === 'object' ? input : ({} as VpnMethodsTimezoneInput);
    const published =
      shadowBool(shadowField(source, 'vpn_methods'), 'timezone_mismatch') ??
      shadowBool(shadowField(source, 'vpnMethods'), 'timezone_mismatch') ??
      shadowBool(source, 'timezone_mismatch') ??
      shadowBool(source, 'timezoneMismatch') ??
      shadowBool(shadowField(source, 'network'), 'timezone_mismatch');
    if (published === undefined) return [];

    const browserTz = shadowField(source, 'browser_timezone') ?? shadowField(source, 'browserTimezone');
    const ipTz = shadowField(source, 'ip_timezone') ?? shadowField(source, 'ipTimezone');
    if (typeof browserTz !== 'string' || typeof ipTz !== 'string') return [];

    const canonical = timezoneMismatchContext(browserTz, ipTz);
    const diagnostics: string[] = [];
    if (canonical.mismatch && published === false) {
      diagnostics.push(
        `vpn_methods.timezone_mismatch=false contradicts the canonical resolver (${String(canonical.canonicalBrowser)} vs ${String(canonical.canonicalIp)})`
      );
    } else if (
      published === true &&
      !canonical.mismatch &&
      canonical.canonicalBrowser !== null &&
      canonical.canonicalIp !== null &&
      timezonesEquivalent(browserTz, ipTz)
    ) {
      diagnostics.push(
        `vpn_methods.timezone_mismatch=true is not supported by the canonical resolver (${browserTz} / ${ipTz} -> ${String(canonical.canonicalBrowser)}); parity must use canonical identities, not raw string inequality`
      );
    }
    return diagnostics;
  } catch {
    return [];
  }
}

/** Alias for callers that name the check "timezone parity". */
export const checkVpnMethodsTimezoneParity = checkVpnMethodsTimezoneInvariants;

/** Combined input for the one-call convenience wrapper below. */
export type IntegratedFieldInput = PrivacyAntiDetectInput &
  ProxyDetailsDatacenterInput &
  VpnMethodsTimezoneInput;

/**
 * Convenience wrapper that runs all three integrated-field invariants and concatenates their
 * diagnostics. It is additive: it does not feed the core spec verdict, and it never throws.
 */
export function checkIntegratedFieldInvariants(
  input: IntegratedFieldInput = {}
): string[] {
  try {
    return [
      ...checkPrivacySettingsAntiDetectInvariants(input),
      ...checkProxyDetailsDatacenterInvariants(input),
      ...checkVpnMethodsTimezoneInvariants(input),
    ];
  } catch {
    return [];
  }
}

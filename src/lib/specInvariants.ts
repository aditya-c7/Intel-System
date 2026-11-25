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

/**
 * Defensive object normalization for public entries: an explicit `null`, primitive or other
 * non-object value becomes an empty record. This preserves every rule and threshold — it only
 * removes the throw so each helper stays total as documented.
 */
function asRecord<T extends object>(value: T | null | undefined): T {
  return value !== null && typeof value === 'object' ? value : ({} as T);
}

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
  try {
    const source = asRecord(ctx);
    return Boolean(
      source.privacyHardened ||
        source.firefoxFpp ||
        source.resistFingerprinting ||
        source.safariAtfp ||
        source.torBrowser ||
        source.braveShields ||
        isPrivacyHardenedUserAgent(source.userAgent || '')
    );
  } catch {
    return false;
  }
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
  try {
    const source = asRecord(input);
    const contradictions: string[] = [];
    if (source.claimed_hardware_anchor === true && !gpuObservationIsHardwareAnchor(source.gpu_observation)) {
      contradictions.push(
        `a '${source.gpu_observation}' GPU observation cannot be used as a hardware identity anchor`
      );
    }
    return contradictions;
  } catch {
    return [];
  }
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
  try {
    const source = asRecord(context);
    if (value === null || value === undefined) return [];
    if (!Number.isFinite(value) || !(DEVICE_MEMORY_DOMAIN as readonly number[]).includes(value)) {
      return [
        {
          id: 'spec.device_memory.domain',
          severity: source.privacyHardened ? 'soft' : 'hard',
          detail: `navigator.deviceMemory ${String(value)} is outside the power-of-two domain {0.25,0.5,1,2,4,8,16,32}`,
        },
      ];
    }
    // 16 / 32 are allowed everywhere; there is intentionally no 8 GB ceiling.
    return [];
  } catch {
    return [];
  }
}

export function checkNetworkRtt(
  rtt: number | null | undefined,
  context: { privacyHardened?: boolean } = {}
): SpecViolation[] {
  try {
    const source = asRecord(context);
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
          severity: source.privacyHardened ? 'soft' : 'hard',
          detail: `rtt ${rtt} is not a multiple of 25`,
        },
      ];
    }
    return [];
  } catch {
    return [];
  }
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
  try {
    const source = asRecord(context);
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
          severity: source.privacyHardened ? 'soft' : 'hard',
          detail: `WebGL backend ${backend} is inconsistent with OS ${osFamily || 'unknown'}`,
        },
      ];
    }
    return [];
  } catch {
    return [];
  }
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
  try {
    const source = asRecord(transport);
    const privacySource = asRecord(context);
    const http = String(source.httpPlatform || '').toLowerCase();
    const js = String(source.jsPlatform || '').toLowerCase();
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
          severity: privacySource.privacyHardened ? 'soft' : 'hard',
          detail: `HTTP/UA-CH platform ${http} disagrees with JS platform ${js}`,
        },
      ];
    }
    return [];
  } catch {
    return [];
  }
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
  try {
    const source = asRecord(context);
    const currentSnapshot = asRecord(current);
    const previousSnapshot = asRecord(previous);
    if (source.privacyHardened) return [];
    const violations: SpecViolation[] = [];
    const compare = (key: keyof HardwareSnapshot, label: string): void => {
      const a = currentSnapshot[key];
      const b = previousSnapshot[key];
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
  } catch {
    return [];
  }
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
  try {
    const source = asRecord(input);
    const privacyHardened = resolvePrivacyHardened(source);
    const softwareRenderer = isSwiftShaderRenderer(source.webglRenderer || '');
    const gpuObservation = resolveGpuObservation(
      source.webglVendor,
      source.webglRenderer,
      source.gpuCapabilityClass
    );
    const violations: SpecViolation[] = [
      ...checkDeviceMemory(source.deviceMemoryGb, { privacyHardened }),
      ...checkNetworkRtt(source.networkRtt, { privacyHardened }),
      ...checkBatteryManager(source.battery),
      ...checkJsHeapSizeLimit(source.jsHeapSizeLimit, source.expectedJsHeapSizeLimit),
      ...checkWebglBackendAgainstOs(source.webglRenderer || '', source.osFamily || '', { privacyHardened }),
      ...checkPdfPluginFace(source.deviceKind || 'unknown', source.hasPdfFace),
      ...checkHttpUaChReconciliation(source.transport || {}, { privacyHardened }),
      ...checkHardwareDrift(source.currentHardware || {}, source.previousHardware || {}, { privacyHardened }),
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
  } catch {
    return {
      violations: [],
      reasons: [],
      hardViolations: [],
      softViolations: [],
      hard_spec_violation: false,
      privacy_hardened: false,
      software_renderer: false,
      gpu_observation: 'observation_unavailable',
    };
  }
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
  try {
    const source = asRecord(input);
    const privacy = Boolean(source.privacy_hardened);
    const swiftshader = Boolean(source.software_renderer);
    const rawReasons = (source.reasons || []).filter((r) => typeof r === 'string' && r.trim());
    const reasons = rawReasons.filter((reason) => {
      if (privacy && /privacy|rfp|fpp|brave|tor|atfp|fingerprint.?protection/i.test(reason)) return false;
      if (swiftshader && /swiftshader|software.?render|llvmpipe|mesa offscreen/i.test(reason)) return false;
      return true;
    });
    // A hard spec violation caused solely by a privacy browser is exempt; any independent hard
    // violation survives.
    const hard_spec_violation = Boolean(source.hard_spec_violation) && !privacy;
    const detected = reasons.length > 0 || hard_spec_violation;
    return { detected, reasons, hard_spec_violation, privacy_hardened: privacy };
  } catch {
    return { detected: false, reasons: [], hard_spec_violation: false, privacy_hardened: false };
  }
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
  /**
   * Server-side aliases accepted so a caller can forward its raw security signals verbatim.
   * `strongCdpProof` is the protocol-level CDP binding (maps to `cdpAttached`); the others are
   * DevTools-UI evidence only and can never, on their own, claim `cdp_attached`.
   */
  strongCdpProof?: boolean | null;
  developerTools?: boolean | null;
  cdpRuntimeLeak?: boolean | null;
  automationEnvironment?: string | null;
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

/**
 * Resolve the inspector state directly from the raw, passive inspector probes.
 *
 * A corroborated CDP+UI pair is `yes-corroborated`. A bare / automation-protocol CDP binding is
 * `yes-unattributed` — the canonical state whose flags are cdp_attached:true, developer_tools:false.
 * Pure DevTools-UI evidence (a verified canary or a normalized docked-layout contraction) keeps its
 * legacy `devtools_*` spelling so the asymmetric developer_tools:true / cdp_attached:false mapping
 * is preserved end-to-end. No evidence resolves to `no`.
 */
export function resolveInspectorState(
  signals: InspectorSignals = {}
): InspectorState | LegacyInspectorState {
  try {
    const source = asRecord(signals);
    // Only a protocol-level binding (cdpAttached / strongCdpProof) is CDP proof. A runtime leak,
    // an electron / IDE host or a docked layout is DevTools-UI evidence only and can never attach
    // CDP on its own.
    const cdp = Boolean(source.cdpAttached) || Boolean(source.strongCdpProof);
    const verifiedUi = Boolean(source.devtoolsActiveVerified);
    if (cdp && verifiedUi) return 'yes-corroborated';
    if (cdp) return 'yes-unattributed';
    if (verifiedUi || Boolean(source.developerTools)) return 'devtools_active_verified';
    if (
      Boolean(source.cdpRuntimeLeak) ||
      source.automationEnvironment === 'electron' ||
      source.automationEnvironment === 'ide_webview' ||
      Boolean(source.viewportContractionNormalized)
    ) {
      return 'devtools_docked_suspected';
    }
    return 'no';
  } catch {
    return 'no';
  }
}

/**
 * Canonical flag resolver. The two axes are deliberately asymmetric so each observation stays on
 * its own truth axis:
 *  - yes-unattributed / automation_protocol_attached (bare or automation-protocol CDP binding)
 *                          -> cdp_attached:true, developer_tools:false.
 *  - devtools_docked_suspected / devtools_active_verified (docked DevTools / verified UI canary)
 *                          -> cdp_attached:false, developer_tools:true.
 *  - yes-corroborated   -> both flags true (CDP and DevTools UI canary agree).
 *  - no / closed        -> neither flag.
 * The raw spelling is inspected (not `toInspectorState`): the canonical 3-state vocabulary folds
 * both asymmetric cases into `yes-unattributed`, so normalising first would lose the distinction.
 */
export function inspectorFlagsForState(
  state: InspectorState | LegacyInspectorState
): { cdp_attached: boolean; developer_tools: boolean } {
  switch (state) {
    case 'yes-corroborated':
      return { cdp_attached: true, developer_tools: true };
    case 'yes-unattributed':
    case 'automation_protocol_attached':
      return { cdp_attached: true, developer_tools: false };
    case 'devtools_docked_suspected':
    case 'devtools_active_verified':
      return { cdp_attached: false, developer_tools: true };
    case 'no':
    case 'closed':
    default:
      return { cdp_attached: false, developer_tools: false };
  }
}

/**
 * Legacy 4-state classifier, kept compatible for existing callers (same inputs, same outputs).
 * New code should prefer `resolveInspectorState` and then `inspectorFlagsForState`.
 */
export function classifyInspectorState(signals: InspectorSignals = {}): LegacyInspectorState {
  try {
    const source = asRecord(signals);
    if (source.cdpAttached) return 'automation_protocol_attached';
    if (source.devtoolsActiveVerified) return 'devtools_active_verified';
    if (source.viewportContractionNormalized) return 'devtools_docked_suspected';
    return 'closed';
  } catch {
    return 'closed';
  }
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
  try {
    const source = asRecord(input);
    const canonical_state = toInspectorState(source.inspector_state);
    // Check the raw spelling: the canonical 3-state value folds bare CDP and docked DevTools into
    // the same bucket, so normalising first would erase the asymmetric flag mapping.
    const expected_flags = inspectorFlagsForState(source.inspector_state);
    const contradictions: string[] = [];

    if (
      source.cdp_attached !== undefined &&
      Boolean(source.cdp_attached) !== expected_flags.cdp_attached
    ) {
      contradictions.push(
        `cdp_attached=${Boolean(source.cdp_attached)} contradicts inspector_state '${canonical_state}' (expected ${expected_flags.cdp_attached})`
      );
    }
    if (
      source.developer_tools !== undefined &&
      Boolean(source.developer_tools) !== expected_flags.developer_tools
    ) {
      contradictions.push(
        `developer_tools=${Boolean(source.developer_tools)} contradicts inspector_state '${canonical_state}' (expected ${expected_flags.developer_tools})`
      );
    }

    const permits_human_verdict = permitsHumanVerdict(canonical_state);
    const tier = typeof source.verdict_tier === 'string' ? source.verdict_tier : '';
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
  } catch {
    return {
      consistent: true,
      contradictions: [],
      canonical_state: 'no',
      expected_flags: { cdp_attached: false, developer_tools: false },
      permits_human_verdict: true,
    };
  }
}

/** Boolean convenience wrapper around `checkInspectorInvariants`. */
export function hasInspectorContradictions(input: InspectorInvariantInput): boolean {
  try {
    return checkInspectorInvariants(input).contradictions.length > 0;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Canonical inspector flags — one-call resolver (additive)                     */
/* -------------------------------------------------------------------------- */

/** The one-call resolver's result: both canonical flags plus the inspector state string. */
export interface CanonicalInspectorFlags {
  cdp_attached: boolean;
  developer_tools: boolean;
  inspector_state: InspectorState | LegacyInspectorState;
}

/**
 * Inputs accepted by the one-call resolver. An already-resolved `inspector_state` or a published
 * flag pair is honoured; otherwise raw passive probes (including the server's signal aliases) are
 * forwarded to `resolveInspectorState`. All reads are defensive so hostile getters cannot throw.
 */
export interface CanonicalInspectorFlagsInput extends InspectorSignals {
  strongCdpProof?: boolean | null;
  developerTools?: boolean | null;
  cdpRuntimeLeak?: boolean | null;
  automationEnvironment?: string | null;
  inspector_state?: InspectorState | LegacyInspectorState | null;
  cdp_attached?: boolean | null;
  developer_tools?: boolean | null;
  [key: string]: unknown;
}

const INSPECTOR_STATE_VALUES: ReadonlySet<string> = new Set<string>([
  'no',
  'yes-unattributed',
  'yes-corroborated',
  'closed',
  'automation_protocol_attached',
  'devtools_docked_suspected',
  'devtools_active_verified',
]);

function isInspectorStateValue(value: unknown): value is InspectorState | LegacyInspectorState {
  return typeof value === 'string' && INSPECTOR_STATE_VALUES.has(value);
}

/**
 * Additive, total one-call resolver for `cdp_attached`, `developer_tools` and `inspector_state`.
 *
 * The returned flags are derived from the same state that is returned, so feeding the result back
 * into `checkInspectorInvariants` is always consistent. Mapping:
 *  - bare / automation-protocol CDP -> cdp_attached:true, developer_tools:false;
 *  - docked / verified DevTools UI  -> cdp_attached:false, developer_tools:true;
 *  - corroborated CDP + UI canary   -> both true;
 *  - no evidence                    -> both false.
 * Never throws: any failure resolves to the safe `no` verdict.
 */
export function canonicalInspectorFlags(
  input: CanonicalInspectorFlagsInput = {}
): CanonicalInspectorFlags {
  try {
    const source =
      input && typeof input === 'object' ? (input as CanonicalInspectorFlagsInput) : ({} as CanonicalInspectorFlagsInput);

    // 1. An explicitly resolved state is authoritative; its flags follow from that exact spelling.
    const rawState = shadowField(source, 'inspector_state');
    if (isInspectorStateValue(rawState)) {
      return { ...inspectorFlagsForState(rawState), inspector_state: rawState };
    }

    // 2. Otherwise derive the state from published flags (when present, they win per axis) or
    //    from the raw passive probes. Only a verified canary corroborates a CDP binding.
    const publishedCdp = shadowBool(source, 'cdp_attached');
    const publishedDevtools = shadowBool(source, 'developer_tools');
    const environment = shadowField(source, 'automationEnvironment');
    const state = resolveInspectorState({
      cdpAttached:
        publishedCdp ??
        (shadowBool(source, 'cdpAttached') === true || shadowBool(source, 'strongCdpProof') === true),
      devtoolsActiveVerified:
        publishedDevtools ??
        (shadowBool(source, 'devtoolsActiveVerified') === true ||
          shadowBool(source, 'developerTools') === true),
      viewportContractionNormalized: shadowBool(source, 'viewportContractionNormalized'),
      cdpRuntimeLeak: shadowBool(source, 'cdpRuntimeLeak'),
      automationEnvironment: typeof environment === 'string' ? environment : undefined,
    });
    return { ...inspectorFlagsForState(state), inspector_state: state };
  } catch {
    return { cdp_attached: false, developer_tools: false, inspector_state: 'no' };
  }
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

/* -------------------------------------------------------------------------- */
/* Remaining benchmark defects — additive invariant helpers                    */
/* -------------------------------------------------------------------------- */

/**
 * First explicitly published value across a list of records and aliases. `null`/`undefined`
 * are absence of evidence, so a literal `false`/`0`/`''` still wins. Every read is guarded by
 * `shadowField`, so hostile getters / proxies cannot escape as a throw.
 */
function integratedPick(records: readonly unknown[], keys: readonly string[]): unknown {
  for (const record of records) {
    for (const key of keys) {
      const value = shadowField(record, key);
      if (value !== undefined && value !== null) return value;
    }
  }
  return undefined;
}

function integratedPickBool(records: readonly unknown[], keys: readonly string[]): boolean | undefined {
  const value = integratedPick(records, keys);
  if (typeof value === 'boolean') return value;
  return shadowBool(value, 'detected');
}

function integratedPickText(records: readonly unknown[], keys: readonly string[]): string {
  const value = integratedPick(records, keys);
  return typeof value === 'string' ? value.trim() : '';
}

function integratedPickNumber(records: readonly unknown[], keys: readonly string[]): number | undefined {
  const value = integratedPick(records, keys);
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

/** Text may arrive as a flat string or as a list of reason tokens. */
function integratedPickTokens(records: readonly unknown[], keys: readonly string[]): string {
  const parts: string[] = [];
  for (const record of records) {
    for (const key of keys) {
      const value = shadowField(record, key);
      if (typeof value === 'string') parts.push(value);
      else if (Array.isArray(value)) {
        try {
          for (const item of value as readonly unknown[]) {
            if (typeof item === 'string') parts.push(item);
          }
        } catch {
          /* hostile iterator: keep the safely read prefix */
        }
      }
    }
  }
  return parts.join(' ');
}

function integratedFiniteArray(value: unknown): number[] {
  const finite: number[] = [];
  if (!Array.isArray(value)) return finite;
  try {
    let seen = 0;
    for (const item of value as readonly unknown[]) {
      if (++seen > 4096) break;
      if (typeof item === 'number' && Number.isFinite(item)) finite.push(item);
    }
  } catch {
    /* hostile iterator: keep the safely read prefix */
  }
  return finite;
}

/* -------------------------------------------------------------------------- */
/* GPU truth                                                                   */
/* -------------------------------------------------------------------------- */

/** Fields accepted by the GPU-truth invariant. All optional; absence is never a diagnostic. */
export interface GpuTruthInvariantInput {
  gpu_truth_state?: string | null;
  gpuTruthState?: string | null;
  gpu_observation?: GpuObservation | string | null;
  gpuObservation?: GpuObservation | string | null;
  claimed_hardware_anchor?: boolean | null;
  hardware_claim?: boolean | null;
  hardwareClaim?: boolean | null;
  physical_gpu_claim?: boolean | null;
  physicalGpuClaim?: boolean | null;
  unmasked_physical_gpu?: boolean | null;
  unmaskedPhysicalGpu?: boolean | null;
  gpu_label?: string | null;
  gpuLabel?: string | null;
  gpu_claim?: string | null;
  status?: string | null;
  detail?: string | null;
  reasons?: readonly string[] | string | null;
  vendor?: string | null;
  renderer?: string | null;
  unmaskedVendor?: string | null;
  unmaskedRenderer?: string | null;
  debugExtensionAvailable?: boolean | null;
  webgl_debug_renderer_info?: boolean | null;
  stealthTemplate?: boolean | null;
  stealth_template?: boolean | null;
  gpuTemplate?: boolean | null;
  shaderPrecisionProfile?: string | null;
  privacyHardened?: boolean | null;
  [key: string]: unknown;
}

/** Known stealth-template renderer/vendor strings and generic "manufacturer" templates. */
const INVARIANT_STEALTH_GPU_TEMPLATE =
  /intel\s*(?:\(r\))?\s*iris\s*opengl\s*engine|intel\s*opengl\s*engine|\bintel\s+inc\.?\b.*\b(?:generic|opengl|basic)\s+(?:renderer|engine)|\bgeneric\s+(?:opengl|webgl)?\s*renderer|\bconstant\s+webgl\b/i;

/** A positive hardware claim in a human-readable label/detail, with negation guarded. */
function integratedHardwareClaimText(text: string): boolean {
  if (!text) return false;
  const claim =
    /unmasked\s+(?:physical\s+)?gpu|physical\s+(?:hardware|gpu)|hardware\s+(?:anchor|identity|gpu|acceleration)|(?:is|verified|real)\s+hardware|hardware_visible/i;
  const denial = /\b(?:not|never|cannot|no|non)[-\s]|masked|unavailable|unknown|software|unverified/i;
  // Check clause by clause so "masked/unavailable — not physical hardware" is not a claim.
  const clauses = text.split(/[.;!?\n]| - | — /);
  return clauses.some((clause) => claim.test(clause) && !denial.test(clause));
}

/**
 * Zero-contradiction guard for GPU truth. It adds three diagnostics, and ONLY three:
 *  1. an unmasked/physical-hardware claim backed solely by spoofable masked
 *     `gl.getParameter` strings (no usable `WEBGL_debug_renderer_info` identity);
 *  2. the same class of hardware claim while the debug extension is masked / unavailable;
 *  3. a stealth-template GPU string accepted as hardware.
 *
 * Software / SwiftShader renderers are never flagged as hardware claims here, and masking by
 * itself (with no hardware claim) is never a diagnostic. Pure and total — never throws.
 */
export function checkGpuTruthInvariants(input: GpuTruthInvariantInput = {}): string[] {
  try {
    const source = input && typeof input === 'object' ? input : ({} as GpuTruthInvariantInput);
    const records: unknown[] = [
      source,
      shadowField(source, 'gpu'),
      shadowField(source, 'gpu_truth'),
      shadowField(source, 'gpuTruth'),
      shadowField(source, 'hardwareSignals'),
      shadowField(source, 'webgl'),
    ];
    const diagnostics: string[] = [];

    const truthState = integratedPickText(records, ['gpu_truth_state', 'gpuTruthState', 'state']);
    const observation = integratedPickText(records, ['gpu_observation', 'gpuObservation', 'observation']);
    const unmaskedVendor = integratedPickText(records, [
      'unmaskedVendor', 'unmasked_vendor', 'vendor_unmasked', 'UNMASKED_VENDOR_WEBGL',
    ]);
    const unmaskedRenderer = integratedPickText(records, [
      'unmaskedRenderer', 'unmasked_renderer', 'renderer_unmasked', 'UNMASKED_RENDERER_WEBGL',
    ]);
    const maskedVendor = integratedPickText(records, ['vendor', 'maskedVendor']);
    const maskedRenderer = integratedPickText(records, ['renderer', 'maskedRenderer']);
    const debugAvailable = integratedPickBool(records, [
      'debugExtensionAvailable', 'debug_extension_available', 'webgl_debug_renderer_info',
      'unmaskedInfoAvailable',
    ]);
    const templateFlag = integratedPickBool(records, [
      'stealthTemplate', 'stealth_template', 'gpuTemplate', 'gpu_template', 'spoofedGpuTemplate',
    ]);
    const claimTokens = integratedPickTokens(records, [
      'gpu_label', 'gpuLabel', 'gpu_claim', 'gpuClaim', 'claim', 'status', 'detail', 'label',
      'reason', 'reasons', 'diagnostic',
    ]);

    // A claim may be an explicit boolean, an explicit truth state, or a human-readable label.
    const claimFlag =
      integratedPickBool(records, [
        'claimed_hardware_anchor', 'hardware_claim', 'hardwareClaim', 'physical_gpu_claim',
        'physicalGpuClaim', 'unmasked_physical_gpu', 'unmaskedPhysicalGpu', 'claimsUnmaskedGpu',
        'physical_hardware', 'physicalHardware',
      ]) === true;
    const truthHardware =
      truthState === 'hardware' || observation === 'hardware_visible' || claimFlag;
    const claim =
      claimFlag ||
      integratedHardwareClaimText(claimTokens) ||
      (truthHardware && (truthState === 'hardware' || observation === 'hardware_visible'));

    const usableUnmasked = (value: string): boolean => {
      const text = normalizedGpuValue(value);
      if (isGpuNamePlaceholder(text)) return false;
      if (SOFTWARE_OR_VIRTUAL_GPU_IDENTIFIER.test(text) || GOOGLE_SOFTWARE_VENDOR.test(text)) return false;
      return true;
    };
    const hasUnmaskedIdentity = usableUnmasked(unmaskedVendor) || usableUnmasked(unmaskedRenderer);
    const maskedStringsPresent = Boolean(normalizedGpuValue(maskedVendor) || normalizedGpuValue(maskedRenderer));
    const maskedState =
      debugAvailable === false ||
      truthState === 'masked' ||
      truthState === 'unknown' ||
      observation === 'masked_by_privacy' ||
      observation === 'observation_unavailable';

    // 1 & 2. A hardware claim is only admissible with a real, unmasked identity. Masked
    // strings from gl.getParameter (and a masked/absent debug extension) are spoofable and
    // can never establish "physical hardware".
    if (claim && !hasUnmaskedIdentity && maskedStringsPresent) {
      diagnostics.push(
        "an 'unmasked physical GPU' hardware claim is backed only by spoofable masked gl.getParameter strings; no WEBGL_debug_renderer_info identity was observed"
      );
    }
    if (claim && !hasUnmaskedIdentity && maskedState) {
      diagnostics.push(
        'a masked/unavailable WEBGL_debug_renderer_info extension cannot support a physical-hardware claim'
      );
    }

    // 3. Known forged GPU strings (stealth templates) are not hardware anchors, even when a
    // resolver promoted them to `hardware`.
    const templateString =
      INVARIANT_STEALTH_GPU_TEMPLATE.test(`${maskedVendor} ${maskedRenderer}`) ||
      INVARIANT_STEALTH_GPU_TEMPLATE.test(`${unmaskedVendor} ${unmaskedRenderer}`);
    if ((templateFlag === true || templateString) && (truthHardware || claim)) {
      diagnostics.push(
        'a stealth-template GPU string must not be accepted as a hardware / unmasked physical GPU observation'
      );
    }
    return diagnostics;
  } catch {
    return [];
  }
}

/* -------------------------------------------------------------------------- */
/* Audio identity                                                             */
/* -------------------------------------------------------------------------- */

export interface AudioIdentityInvariantInput {
  stability?: string | null;
  audio_stability?: string | null;
  usableForIdentity?: boolean | null;
  noiseReasons?: readonly string[] | string | null;
  renderSums?: readonly number[] | null;
  getChannelDataWrapped?: boolean | null;
  copyFromChannelMatches?: boolean | null;
  silentBufferNonZero?: boolean | null;
  audioSilentBufferNonZero?: boolean | null;
  audioRepeatReadDiverged?: boolean | null;
  audioNoise?: boolean | null;
  audio_noise?: boolean | null;
  privacyHardened?: boolean | null;
  tamperingInconclusive?: boolean | null;
  identity_rotated?: boolean | null;
  identityRotated?: boolean | null;
  visitor_id_changed?: boolean | null;
  visitorIdChanged?: boolean | null;
  id_changed?: boolean | null;
  identity_before?: string | null;
  identity_after?: string | null;
  visitor_id_before?: string | null;
  visitor_id_after?: string | null;
  confidence_dropped?: boolean | null;
  confidenceDropped?: boolean | null;
  confidence_drop?: number | null;
  confidence_before?: number | null;
  confidence_after?: number | null;
  score_before?: number | null;
  score_after?: number | null;
  confidence_delta?: number | null;
  [key: string]: unknown;
}

/**
 * Noise in the audio fingerprint may only *exclude* that signal from the identity anchor.
 * It can never rotate an identity or lower a confidence score. Reports a contradiction only
 * when both sides were actually observed: noise/repeat-read divergence plus a published
 * rotation or confidence drop. Pure and total — never throws.
 */
export function checkAudioIdentityInvariants(input: AudioIdentityInvariantInput = {}): string[] {
  try {
    const source = input && typeof input === 'object' ? input : ({} as AudioIdentityInvariantInput);
    const records: unknown[] = [
      source,
      shadowField(source, 'audio'),
      shadowField(source, 'audio_truth'),
      shadowField(source, 'audioTruth'),
      shadowField(source, 'audioStability'),
      shadowField(source, 'identity'),
      shadowField(source, 'confidence'),
    ];
    const diagnostics: string[] = [];

    const stability = integratedPickText(records, ['stability', 'audio_stability', 'audioStability']);
    const noiseReasons = integratedPickTokens(records, ['noiseReasons', 'noise_reasons']);
    const sums = integratedFiniteArray(integratedPick(records, ['renderSums', 'render_sums']));
    let divergent = false;
    if (sums.length > 1) {
      const first = sums[0];
      for (let i = 1; i < sums.length; i += 1) {
        if (sums[i] !== first) {
          divergent = true;
          break;
        }
      }
    } else if (Array.isArray(integratedPick(records, ['renderSums', 'render_sums'])) && sums.length === 0) {
      // No finite render at all is "unavailable", never noise on its own.
      divergent = false;
    }
    const noise =
      stability === 'noisy' ||
      Boolean(noiseReasons.trim()) ||
      divergent ||
      integratedPickBool(records, [
        'audioNoise', 'audio_noise', 'noiseObserved', 'getChannelDataWrapped',
        'silentBufferNonZero', 'audioSilentBufferNonZero', 'audioRepeatReadDiverged',
      ]) === true ||
      integratedPickBool(records, ['usableForIdentity', 'usable_for_identity']) === false
        ? true
        : integratedPickBool(records, ['copyFromChannelMatches', 'copy_from_channel_matches']) === false;
    if (!noise) return [];

    const beforeId = integratedPickText(records, [
      'identity_before', 'identityBefore', 'visitor_id_before', 'visitorIdBefore',
    ]);
    const afterId = integratedPickText(records, [
      'identity_after', 'identityAfter', 'visitor_id_after', 'visitorIdAfter',
    ]);
    const rotated =
      integratedPickBool(records, [
        'identity_rotated', 'identityRotated', 'visitor_id_changed', 'visitorIdChanged',
        'id_changed', 'idChanged', 'identity_changed',
      ]) === true ||
      (Boolean(beforeId) && Boolean(afterId) && beforeId !== afterId);
    if (rotated) {
      diagnostics.push(
        'audio noise / repeat-read divergence must never rotate the identity: noise may only remove the audio anchor'
      );
    }

    const beforeScore = integratedPickNumber(records, [
      'confidence_before', 'confidenceBefore', 'score_before', 'scoreBefore', 'rawScore',
    ]);
    const afterScore = integratedPickNumber(records, [
      'confidence_after', 'confidenceAfter', 'score_after', 'scoreAfter', 'confidence',
    ]);
    const dropped =
      integratedPickBool(records, ['confidence_dropped', 'confidenceDropped', 'confidenceDrop']) === true ||
      (beforeScore !== undefined && afterScore !== undefined && afterScore < beforeScore) ||
      (integratedPickNumber(records, ['confidence_drop', 'confidence_delta', 'confidenceDelta']) ?? 0) < 0;
    if (dropped) {
      diagnostics.push(
        'audio noise / repeat-read divergence must never drop a confidence score: only anchor eligibility may change'
      );
    }
    return diagnostics;
  } catch {
    return [];
  }
}

/* -------------------------------------------------------------------------- */
/* Privacy noise                                                              */
/* -------------------------------------------------------------------------- */

export interface PrivacyNoiseInvariantInput {
  privacyHardened?: boolean | null;
  privacy_hardened?: boolean | null;
  privacySettings?: boolean | { detected?: boolean | null } | null;
  privacy_settings?: boolean | { detected?: boolean | null } | null;
  vendorSignature?: string | null;
  vendor_signature?: string | null;
  braveShields?: boolean | null;
  torBrowser?: boolean | null;
  firefoxFpp?: boolean | null;
  resistFingerprinting?: boolean | null;
  safariAtfp?: boolean | null;
  userAgent?: string | null;
  canvasNoise?: boolean | null;
  audioNoise?: boolean | null;
  shaderNoise?: boolean | null;
  noiseObserved?: boolean | null;
  audioPrivacyNoise?: boolean | null;
  audioSilentBufferNonZero?: boolean | null;
  prototypeProxy?: boolean | null;
  iframeStealthTrap?: boolean | null;
  hardContradiction?: boolean | null;
  contradiction_evidence?: boolean | null;
  contradictionEvidence?: boolean | null;
  forged_privacy_signature?: boolean | null;
  anti_detect_browser?: boolean | null;
  antiDetectBrowser?: boolean | null;
  anomaly_score?: number | null;
  anomalyScore?: number | null;
  tampering?: { anti_detect_browser?: boolean | null } | null;
  tampering_details?: { anti_detect_browser?: boolean | null } | null;
  [key: string]: unknown;
}

/** Accepted vendor signatures whose noise is an expected privacy defence, not anti-detect. */
const INVARIANT_ACCEPTED_PRIVACY_VENDOR =
  /brave|braveshields|firefox[-\s]?(?:rfp|fpp|resistfingerprinting)|torbrowser|\btor\b|safari[-\s]?(?:afp|advanced)|resistfingerprinting/i;

/**
 * Noise from a privacy-hardened browser (Brave / Firefox RFP / Tor / Safari AFP) must never be
 * scored as `anti_detect_browser` nor raise `anomaly_score`. An explicit hard contradiction /
 * forged-signature finding is the sole exemption. Does not feed the core spec verdict and does
 * not change any privacy / SwiftShader exemption. Pure and total — never throws.
 */
export function checkPrivacyNoiseInvariants(input: PrivacyNoiseInvariantInput = {}): string[] {
  try {
    const source = input && typeof input === 'object' ? input : ({} as PrivacyNoiseInvariantInput);
    const records: unknown[] = [
      source,
      shadowField(source, 'privacy'),
      shadowField(source, 'privacy_settings'),
      shadowField(source, 'privacySettings'),
      shadowField(source, 'tampering'),
      shadowField(source, 'tampering_details'),
      shadowField(source, 'tamperingDetails'),
    ];
    const diagnostics: string[] = [];

    const vendor = integratedPickText(records, ['vendorSignature', 'vendor_signature']);
    const privacyContext: PrivacyContext = {
      privacyHardened: integratedPickBool(records, ['privacyHardened', 'privacy_hardened']) ?? false,
      firefoxFpp: integratedPickBool(records, ['firefoxFpp', 'firefox_fpp']) ?? false,
      resistFingerprinting: integratedPickBool(records, ['resistFingerprinting', 'resist_fingerprinting']) ?? false,
      safariAtfp: integratedPickBool(records, ['safariAtfp', 'safari_afp']) ?? false,
      torBrowser: integratedPickBool(records, ['torBrowser', 'tor_browser']) ?? false,
      braveShields: integratedPickBool(records, ['braveShields', 'brave_shields']) ?? false,
      userAgent: integratedPickText(records, ['userAgent', 'user_agent']),
    };
    const privacyEvidence =
      resolvePrivacyHardened(privacyContext) ||
      INVARIANT_ACCEPTED_PRIVACY_VENDOR.test(vendor) ||
      integratedBool(source, 'privacy_settings') === true ||
      integratedBool(source, 'privacySettings') === true;
    const noise =
      integratedPickBool(records, [
        'canvasNoise', 'canvas_noise', 'audioNoise', 'audio_noise', 'shaderNoise', 'shader_noise',
        'noiseObserved', 'audioPrivacyNoise', 'audioSilentBufferNonZero', 'prototypeProxy',
        'iframeStealthTrap',
      ]) === true;
    if (!privacyEvidence) return [];

    const exempt =
      integratedPickBool(records, [
        'hardContradiction', 'hard_contradiction', 'contradiction_evidence', 'contradictionEvidence',
        'forged_privacy_signature', 'forgedPrivacySignature',
      ]) === true;
    if (exempt) return [];

    const antiDetect = integratedBool(source, 'anti_detect_browser') ??
      integratedBool(source, 'antiDetectBrowser') ??
      integratedPickBool(records, ['anti_detect_browser', 'antiDetectBrowser']) === true;
    const anomalyScore = integratedPickNumber(records, ['anomaly_score', 'anomalyScore']);
    if (!noise && antiDetect !== true && !(anomalyScore !== undefined && anomalyScore > 0)) return [];

    if (antiDetect === true) {
      diagnostics.push(
        'privacy-hardened noise must not be scored as anti_detect_browser=true without a hard contradiction'
      );
    }
    if (anomalyScore !== undefined && anomalyScore > 0) {
      diagnostics.push(
        'privacy-hardened noise must not raise anomaly_score above 0 without a hard contradiction'
      );
    }
    return diagnostics;
  } catch {
    return [];
  }
}

/* -------------------------------------------------------------------------- */
/* Geolocation proximity                                                      */
/* -------------------------------------------------------------------------- */

export interface GeolocationProximityInvariantInput {
  permission?: string | null;
  geolocation_permission?: string | null;
  geolocationPermission?: string | null;
  geo_permission?: string | null;
  lat?: number | null;
  lon?: number | null;
  latitude?: number | null;
  longitude?: number | null;
  accuracyM?: number | null;
  accuracy_m?: number | null;
  ipCity?: unknown;
  ip_city?: unknown;
  city?: unknown;
  proximity?: unknown;
  hex_proximity?: unknown;
  hexProximity?: unknown;
  proximity_populated?: boolean | null;
  proximityPopulated?: boolean | null;
  proximity_source?: string | null;
  proximitySource?: string | null;
  source?: string | null;
  position?: unknown;
  coords?: unknown;
  geolocation?: unknown;
  result?: unknown;
  proximityResult?: unknown;
  [key: string]: unknown;
}

/** True only for the exact string `granted` — no trim, case-fold or coercion. */
function integratedPermissionGranted(value: unknown): boolean {
  return typeof value === 'string' && value === 'granted';
}

function integratedHasValue(value: unknown): boolean {
  if (value === undefined || value === null || value === false) return false;
  if (typeof value === 'string') return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

/**
 * Permission gate for proximity. Two contradictions are reported:
 *  1. a proximity populated from an IP city while geolocation permission is not `granted`;
 *  2. granted browser coordinates that were ignored (no proximity derived from the fix, or
 *     an IP/geoip source substituted for the granted fix).
 * Absence of a fix with no published proximity is never a diagnostic. Pure and total.
 */
export function checkGeolocationProximityInvariants(
  input: GeolocationProximityInvariantInput = {}
): string[] {
  try {
    const source = input && typeof input === 'object' ? input : ({} as GeolocationProximityInvariantInput);
    const geo = shadowField(source, 'geolocation');
    const position = shadowField(source, 'position') ?? shadowField(geo, 'position');
    const coords = shadowField(source, 'coords') ?? shadowField(position, 'coords');
    const records: unknown[] = [
      source, geo, position, coords,
      shadowField(source, 'result'), shadowField(source, 'proximityResult'),
    ];
    const diagnostics: string[] = [];

    const permissionRaw = integratedPick(records, [
      'permission', 'geolocation_permission', 'geolocationPermission', 'geo_permission',
    ]);
    const granted = integratedPermissionGranted(permissionRaw);

    const lat = integratedPickNumber(records, ['lat', 'latitude']);
    const lon = integratedPickNumber(records, ['lon', 'longitude']);
    const accuracyM = integratedPickNumber(records, ['accuracyM', 'accuracy_m', 'accuracy']);
    const hasValidFix =
      lat !== undefined && lat >= -90 && lat <= 90 &&
      lon !== undefined && lon >= -180 && lon <= 180 &&
      accuracyM !== undefined && accuracyM > 0;

    const published = integratedPick(records, [
      'proximity', 'hex_proximity', 'hexProximity', 'proximity_populated', 'proximityPopulated',
    ]);
    const publishedProximity = integratedHasValue(published);
    const sourceLabel = integratedPickText(records, [
      'proximity_source', 'proximitySource', 'source', 'reason',
    ]).toLowerCase();
    const ipDerived = /\bip\b|geoip|ip[-\s_]?(?:city|geolocat|lookup)|city[-\s_]?lookup/i.test(sourceLabel);

    if (!granted && publishedProximity) {
      diagnostics.push(
        "proximity must not be populated from an IP city when geolocation permission is not exactly 'granted'"
      );
    }
    if (granted && hasValidFix && (!publishedProximity || ipDerived)) {
      diagnostics.push(
        'granted browser coordinates were ignored: proximity must derive from the granted fix, never from IP geolocation'
      );
    }
    return diagnostics;
  } catch {
    return [];
  }
}

/* -------------------------------------------------------------------------- */
/* Active CDP inspector                                                       */
/* -------------------------------------------------------------------------- */

export interface ActiveCdpInvariantInput {
  activeCdpInspection?: boolean | null;
  active_cdp_inspection?: boolean | null;
  secondClientAttached?: boolean | null;
  second_client_attached?: boolean | null;
  secondCdpInspector?: boolean | null;
  second_cdp_inspector?: boolean | null;
  runtimeEnableCount?: number | null;
  nameGetterCount?: number | null;
  prepareStackTraceCount?: number | null;
  state?: string | null;
  activeCdpState?: string | null;
  inspector_state?: string | null;
  inspectorState?: string | null;
  cdp_attached?: boolean | null;
  developer_tools?: boolean | null;
  cdpAttached?: boolean | null;
  strongCdpProof?: boolean | null;
  developerTools?: boolean | null;
  devtoolsActiveVerified?: boolean | null;
  devtoolsAttached?: boolean | null;
  reason_ids?: readonly string[] | string | null;
  reasons?: readonly string[] | string | null;
  [key: string]: unknown;
}

/** Inspector spellings that represent DevTools UI evidence only, never a protocol binding. */
const DEVTOOLS_ONLY_STATES: ReadonlySet<string> = new Set([
  'devtools_active_verified', 'devtools_docked_suspected', 'docked_devtools',
]);

/**
 * A second, actively inspecting CDP client is protocol attachment evidence. It must be
 * published on the `cdp_attached` axis; it can never be relabelled `developer_tools` unless a
 * verified DevTools UI canary corroborates it (`yes-corroborated` / `corroborated`). Pure and
 * total — never throws, and never changes the existing inspector mapping.
 */
export function checkActiveCdpInvariants(input: ActiveCdpInvariantInput = {}): string[] {
  try {
    const source = input && typeof input === 'object' ? input : ({} as ActiveCdpInvariantInput);
    const records: unknown[] = [
      source,
      shadowField(source, 'activeCdp'),
      shadowField(source, 'active_cdp'),
      shadowField(source, 'automation'),
      shadowField(source, 'inspector'),
    ];
    const diagnostics: string[] = [];

    const state = integratedPickText(records, [
      'state', 'activeCdpState', 'active_cdp_state', 'inspector_state', 'inspectorState',
    ]);
    const reasonTokens = integratedPickTokens(records, ['reason_ids', 'reasonIds', 'reasons']);
    const secondClient = integratedPickBool(records, [
      'secondClientAttached', 'second_client_attached', 'secondCdpInspector', 'second_cdp_inspector',
      'activeCdpInspection', 'active_cdp_inspection',
    ]) === true;
    const runtimeCount = integratedPickNumber(records, ['runtimeEnableCount', 'runtime_enable_count']) ?? 0;
    const nameCount = integratedPickNumber(records, ['nameGetterCount', 'name_getter_count']) ?? 0;
    const prepareCount = integratedPickNumber(records, ['prepareStackTraceCount', 'prepare_stack_trace_count']) ?? 0;
    const cdpProbe =
      integratedPickBool(records, ['cdpAttached', 'cdpAttachedProof', 'strongCdpProof']) === true;
    const activeCdp =
      secondClient ||
      prepareCount > 0 ||
      (secondClient && runtimeCount > 0) ||
      reasonTokens.includes('bot.cdp-active-inspection') ||
      state === 'automation_protocol_inspection_active' ||
      state === 'automation_protocol_attached' ||
      state === 'yes-unattributed' ||
      state === 'yes-corroborated' ||
      cdpProbe;
    if (!activeCdp) return [];

    const uiVerified =
      integratedPickBool(records, ['devtoolsActiveVerified', 'devtoolsAttached', 'developerTools']) === true;
    const publishedCdp = integratedPickBool(records, ['cdp_attached', 'cdpAttachedPublished']);
    const publishedDevtools = integratedPickBool(records, ['developer_tools', 'developerToolsPublished']);
    const corroborated =
      state === 'corroborated' || state === 'yes-corroborated' ||
      (publishedCdp === true && publishedDevtools === true) ||
      (cdpProbe && uiVerified && state !== 'automation_protocol_inspection_active');
    if (corroborated) return [];

    if (publishedDevtools === true || DEVTOOLS_ONLY_STATES.has(state)) {
      diagnostics.push(
        'a second active CDP inspector must not be published as developer_tools: protocol attachment belongs on the cdp_attached axis'
      );
    }
    if (publishedCdp === false || state === 'no' || state === 'closed' || DEVTOOLS_ONLY_STATES.has(state)) {
      diagnostics.push(
        'an active CDP inspector cannot be collapsed to no inspector / cdp_attached=false'
      );
    }
    return diagnostics;
  } catch {
    return [];
  }
}

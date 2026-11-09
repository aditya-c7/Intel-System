export interface BrowserDeviceInfo {
  browser: string;
  os: string;
  deviceType: 'Desktop' | 'Mobile' | 'Tablet' | 'Unknown';
  platform: string;
  screenResolution: string;
  pixelRatio: string;
  language: string;
  timezone: string;
}

export interface HardwareSignals {
  hardwareId: string;
  gpuVendor: string;
  gpuRenderer: string;
  maxTextureSize: number;
  canvasHash: string;
  audioHash: string;
  cpuCores: number | null;
  deviceMemoryGb: number | null;
  colorDepth: number;
  maxTouchPoints: number;
  hdrSupported: boolean;
  colorGamut: 'P3' | 'sRGB' | 'Rec2020';
  architecture: string;
}

export type RiskLevel = 'Low' | 'Medium' | 'High';

export type PersistenceMode =
  | 'First-Party Cookie'
  | 'Hardware ID Recovered'
  | 'Private / Restricted Storage';

export type NetworkType =
  | 'Residential Broadband'
  | 'Cellular / 5G'
  | 'Satellite'
  | 'Cloud / Datacenter';

export interface IspNetworkClassification {
  brandName: string;
  networkType: NetworkType;
  isConsumerBroadband: boolean;
  isDatacenterOrHosting: boolean;
  matchedReason: string | null;
}

/* -------------------------------------------------------------------------- */
/* Smart Signals — 4-signal threat grid, every tile rated strictly out of 10   */
/* -------------------------------------------------------------------------- */

export type SmartSignalId = 'incognito' | 'bot' | 'vpn' | 'vm';

export type SmartSignalLevel = 'low' | 'medium' | 'high';

export interface SmartSignal {
  id: SmartSignalId;
  title: string;
  status: string;
  /** Strictly 0..10, one decimal-free integer scale. */
  scoreOutOf10: number;
  /** e.g. `Low Risk • 0/10`, `Medium Risk • 4/10`, `High Risk • 8/10`. */
  riskLabel: string;
  level: SmartSignalLevel;
  detail: string;
}

export interface SmartSignals {
  incognito: SmartSignal;
  bot: SmartSignal;
  vpn: SmartSignal;
  vm: SmartSignal;
}

export interface SecuritySignals {
  isBot: boolean;
  botSignals: string[];
  vpnSuspected: boolean;
  timezoneMismatch: boolean;
  browserTimezone: string;
  ipTimezone: string;
  datacenterAsn: boolean;
  cloudOrMaskedGpu?: boolean;
  vpnReasons: string[];
  tamperDetected: boolean;
  tamperReasons: string[];
  incognitoLikely: boolean;
  /** 0..1 confidence from the composite private-browsing probe. */
  incognitoConfidence?: number;
  /** Human-readable evidence list for the incognito verdict. */
  incognitoDetail?: string;
  storageQuotaMb: number | null;
  persistenceMode: PersistenceMode;
  /** Threat / risk rating on a 0/10 to 10/10 scale (Task 2). */
  suspectScore: number;
  riskLevel: RiskLevel;
  riskFactors: string[];

  /* Task 1 — ISP brand & network classification (server-computed, mirrored client-side) */
  brandName?: string;
  networkType?: NetworkType;
  isConsumerBroadband?: boolean;
  isDatacenterOrHosting?: boolean;

  /* Task 3 — deep technical detection payloads */
  webrtcLeak?: boolean;
  webrtcCandidateIp?: string | null;
  webrtcDetail?: string;
  privacyProtected?: boolean;
  privacyDetail?: string;
  adBlockerDetected?: boolean;
  canvasFarblingDetected?: boolean;
  incognitoOrCleared?: boolean;
  isVirtualMachine?: boolean;
  vmReason?: string;
  devToolsOpen?: boolean;
  distinctIpsLastHour?: number;
  visitsLastHour?: number;

  /* Final 4-signal upgrade: private browsing, bot, network, VM integrity */
  isIncognito?: boolean;
  /** Which physical probe produced the incognito verdict. */
  incognitoMethod?: string;
  /** `quota - usage`, in GiB (10.0 normal vs 9.0 private on Chromium 147+). */
  headroomGiB?: number | null;
  /** IndexedDB strict/relaxed commit ratio (< 1.25 means RAM-backed, i.e. private). */
  idbDurabilityRatio?: number | null;
  isHeadless?: boolean;
  botReason?: string;
  webdriver?: boolean;
  cdpDetected?: boolean;
  isOsTampered?: boolean;
  /** Server-computed 4-signal grid, each tile rated out of 10. */
  smartSignals?: SmartSignals;
  /** Composite badge text, e.g. `Medium Risk • 4/10`. */
  riskBadgeText?: string;
}

export interface LocationInfo {
  publicIp: string;
  city: string;
  region: string;
  country: string;
  countryCode: string;
  latitude: number | null;
  longitude: number | null;
  isp: string;
  org: string;
  asn: string;
  timezone?: string;
  isVpnOrHosting: boolean;
  isIpVerified: boolean;
  isLocationVerified: boolean;
}

export interface VisitStatistics {
  firstVisitUtc: string;
  lastVisitUtc: string;
  previousVisitUtc: string | null;
  totalVisits: number;
  totalSessions: number;
  currentSessionId: string;
  sessionTimeoutMinutes: number;
}

export interface VisitHistoryRecord {
  id: number;
  visitId: string;
  visitorId: string;
  sessionId: string;
  visitedAtUtc: string;
  publicIp: string;
  city: string;
  region: string;
  country: string;
  latitude: number | null;
  longitude: number | null;
  isp: string;
  org: string;
  asn: string;
  browser: string;
  os: string;
  deviceType: string;
  screenResolution: string;
  language: string;
  timezone: string;
  suspectScore?: number;
  riskLevel?: RiskLevel;
  recognitionSource?: string;
}

export interface SignedHistoryBackup {
  visitorId: string;
  hardwareId?: string;
  totalVisits: number;
  totalSessions: number;
  firstVisitUtc: string;
  visits: VisitHistoryRecord[];
  signature: string;
}

export type RecognitionSource =
  | 'First-Party Cookie'
  | 'First-Party LocalStorage'
  | 'Hardware Fingerprint (Cookie-less / Incognito)'
  | 'New First-Party ID';

export interface IntelVisitorResponse {
  visitorId: string;
  visitorToken: string;
  hardwareId: string;
  isReturning: boolean;
  recognitionSource: RecognitionSource;
  location: LocationInfo;
  browserDevice: BrowserDeviceInfo;
  hardwareSignals: HardwareSignals;
  securitySignals: SecuritySignals;
  statistics: VisitStatistics;
  visitHistory: VisitHistoryRecord[];
  historyBackup?: SignedHistoryBackup;
  /* Mirrored at the top level so clients can read them without digging. */
  isIncognito?: boolean;
  suspectScore?: number;
  riskLevel?: RiskLevel;
  riskBadgeText?: string;
  smartSignals?: SmartSignals;
}

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
  storageQuotaMb: number | null;
  persistenceMode: PersistenceMode;
  suspectScore: number;
  riskLevel: RiskLevel;
  riskFactors: string[];
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
}

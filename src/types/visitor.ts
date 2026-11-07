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
}

export interface IntelVisitorResponse {
  visitorId: string;
  visitorToken: string;
  isReturning: boolean;
  recognitionSource: 'First-Party Cookie' | 'First-Party LocalStorage' | 'New First-Party ID';
  location: LocationInfo;
  browserDevice: BrowserDeviceInfo;
  statistics: VisitStatistics;
  visitHistory: VisitHistoryRecord[];
}

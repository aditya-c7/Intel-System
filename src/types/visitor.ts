import type {
  GpuObservation,
  InspectorStateTristate,
  RiskEvidenceLine,
  RiskTier,
} from '../lib/telemetryContract';
import type { ClientType, RuntimeKind } from '../shared/normalization/uaNormalizer';

export interface BrowserDeviceInfo {
  browser: string;
  os: string;
  deviceType: 'Desktop' | 'Mobile' | 'Tablet' | 'Unknown';
  platform: string;
  screenResolution: string;
  pixelRatio: string;
  language: string;
  timezone: string;
  /* Genuine-device gate (hardware invariants, never viewport width). */
  deviceKind?: 'pc' | 'mobile' | 'tablet';
  /** True only when platform + CPU + GPU + finger input all confirm mobile silicon. */
  genuineMobile?: boolean;
  /** Mobile UA running on desktop hardware (Chrome DevTools device preset). */
  devtoolsDeviceEmulation?: boolean;
  /** Browser-reported Android model code (UA-CH `model` or UA Build token). */
  reportedModel?: string;
  /* Exact catalog resolution — present only for genuine mobile visitors. */
  phoneBrand?: string;
  phoneModel?: string;
  phoneModelCode?: string;
  phoneDeviceCode?: string;
  phoneDisplayLabel?: string;
  /* Storage-physics incognito verdict mirrored onto the device info. */
  incognito?: boolean;
  isIncognito?: boolean;
  privateMode?: boolean;
  incognitoMethod?: string;
  idbDurabilityRatio?: number | null;
  opfsFlushMs?: number | null;
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
  /* --- Silicon-grounded truth (additive, optional — older payloads stay valid) ------- */
  /** How `architecture` was determined: 'webgl-silicon' | 'platform-consensus' | 'ua-ch-consensus'. */
  architectureSource?: string;
  /** The UA/UA-CH architecture claim kept beside the silicon truth. */
  claimedArchitecture?: string;
  /** True when the silicon arch family contradicts the claimed UA/UA-CH arch. */
  archUaMismatch?: boolean;
  /** True when the `Math.tanh(0.8)` host-OS probe contradicts the claimed UA OS. */
  osUaMismatch?: boolean;
  /** Host OS family resolved from the libm ULP probe: windows | macos | linux | unknown. */
  hostOs?: string;
  /** JS engine family from the `(-1).toFixed(-1)` RangeError length. */
  engine?: string;
  /** Raw RangeError message length (51 V8, 25 SpiderMonkey, 43/44 JavaScriptCore). */
  engineErrorLength?: number;
  /** WebGL-derived CPU family: x86 | arm | software | unknown. */
  gpuArchFamily?: string;
  /** True when two reads of the same static canvas produced different pixels. */
  canvasNoise?: boolean;
  /** True when two renders of the same offline audio graph produced different sums. */
  audioNoise?: boolean;
  /** 8x8 coarse-quantized canvas digest (structural, collision-resistant anchor). */
  canvasCoarseHash?: string | null;
}

export type RiskLevel = 'Low' | 'Medium' | 'High';

/** Multi-window SQLite aggregations backing the Velocity Signals row. */
export interface VelocityWindowCounts {
  '5_minutes': number;
  '1_hour': number;
  '24_hours': number;
}

export interface VelocitySignals {
  distinct_ip: VelocityWindowCounts;
  distinct_linked_id: VelocityWindowCounts;
  distinct_country: VelocityWindowCounts;
  events: VelocityWindowCounts;
  ip_events: VelocityWindowCounts;
  distinct_ip_by_linked_id: VelocityWindowCounts;
  distinct_visitor_id_by_linked_id: VelocityWindowCounts;
}

export type PersistenceMode =
  | 'First-Party Cookie'
  | 'Hardware ID Recovered'
  | 'Private / Restricted Storage';

export type NetworkType =
  | 'Residential Broadband'
  | 'Cellular / 5G'
  | 'Satellite'
  | 'Cloud / Datacenter'
  | 'Tor Exit / Anonymity Network'
  | 'AI Agent Cloud Network'
  | 'VPN / Proxy Relay'
  | 'Mobile Carrier'
  | 'Standard Network';

export interface IspNetworkClassification {
  brandName: string;
  networkType: NetworkType;
  isConsumerBroadband: boolean;
  isDatacenterOrHosting: boolean;
  matchedReason: string | null;
}

/**
 * Granular attribution for autonomous agents. Produced by the server from RFC 9421 Web Bot
 * Auth headers, official CIDR ranges, forward-confirmed reverse DNS and cloud-VM telemetry.
 */
export interface AiAgentAttribution {
  detected: boolean;
  agentId:
    | 'gemini'
    | 'grok'
    | 'grok_agent'
    | 'muse'
    | 'perplexity'
    | 'openai'
    | 'claude'
    | 'cloud-browser'
    | 'remote-browser'
    | 'impostor-spoof'
    | 'mistral'
    | 'manus'
    | 'googlebot'
    | 'applebot'
    | 'amazonbot'
    | 'bingbot'
    | 'oai_search_bot'
    | 'claude_bot'
    | 'claude_user'
    | 'claude_search_bot'
    | 'perplexity_bot'
    | 'perplexity_user'
    | 'mistral_ai_index'
    | 'mistral_ai_training'
    | null;
  agentName: string;
  operator: string;
  executionMode:
    | 'RFC 9421 Signed Agent'
    | 'User-Triggered Fetcher'
    | 'Silent Cloud VM Browser'
    | 'Autonomous Crawler'
    | 'Remote Browser Agent'
    | 'Spoofed Impostor'
    | null;
  verified: boolean;
  confidence: 'Verified' | 'High' | 'Medium';
  riskScore: number;
  evidence: string[];
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

/**
 * Phase 1 — bot classification outcome. `good_bot` covers verified search /
 * preview crawlers from their official ASN, `ai_agent` covers LLM crawlers and
 * autonomous cloud-browser agents, `bad_bot` covers automation and spoofed UA.
 */
export type BotSubtype = 'human' | 'good_bot' | 'ai_agent' | 'bad_bot';

export interface BotInfo {
  category: string;
  provider: string;
  name: string;
  identity: 'verified' | 'signed' | 'unknown' | 'spoofed';
}

/**
 * Phase 4 — one-time cryptographic envelope attached to every identification
 * payload. The server recomputes `signature` over the canonical string
 * `INTEL_ENVELOPE_V1|timestamp|nonce|hardwareId|userAgent|platform|screenResolution|timezone`
 * and rejects stale, modified or replayed requests.
 */
export interface SecurityEnvelope {
  timestamp: number;
  nonce: string;
  signature: string;
  userAgent: string;
  platform: string;
  screenResolution: string;
  timezone: string;
  protocol: string;
}

/**
 * Additive, optional structured diagnostics for the incognito / private-browsing
 * verdict. Every member except `enabled` is optional and nullable so older
 * payloads and partial collectors stay valid; no existing field is changed.
 */
export interface IncognitoDiagnostics {
  enabled: boolean;
  engine?: string | null;
  method?: string | null;
  confidence?: string | null;
  isPrivate?: boolean | null;
  quotaBytes?: number | null;
  headroomGiB?: number | null;
  idbDurabilityRatio?: number | null;
  idbHighVariance?: boolean | null;
  opfsFlushMs?: number | null;
  persistedStorageGrant?: boolean | null;
  isolatedContextVeto?: boolean | null;
  sessionLockHit?: boolean | null;
  lowConfidenceVeto?: boolean | null;
  clientReportedIncognito?: boolean | null;
  serverWouldVeto?: boolean | null;
}

export interface SecuritySignals {
  isBot: boolean;
  botSignals: string[];
  /** Parity assertion between the single authoritative bot verdict and the evidence gate. */
  botVerdictParity?: boolean;
  botVerdictAssertion?: string;
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

  /* Automation depth — protocol-level leaks and stealth-plugin artifacts */
  cdpRuntimeLeak?: boolean;
  stealthPluginDetected?: boolean;
  /** Host runtime of the page: `none`, `electron`, `ide_webview`, `headless_shell`, `vm`. */
  automationEnvironment?: string;
  /** 0–1 confidence that a real person is driving this runtime. */
  humanCorroboration?: number;

  /* Network anonymity methods — the single source of truth for the VPN tile count */
  /** True only for a real commercial VPN provider, never for plain hosting/datacenter. */
  publicVpn?: boolean;
  vpnMethods?: {
    timezone_mismatch: boolean;
    public_vpn: boolean;
    auxiliary_mobile: boolean;
    os_mismatch: boolean;
    relay: boolean;
    ml_prediction: boolean;
  };

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
  /** Alias of `isIncognito` (collector / server cross-mode verdict). */
  incognito?: boolean;
  /** Alias of `isIncognito`. */
  privateMode?: boolean;
  /** Which physical probe produced the incognito verdict. */
  incognitoMethod?: string;
  /** `quota - usage`, in GiB (2dp; Chrome 156 reports 10.00 in every mode). */
  headroomGiB?: number | null;
  /** IndexedDB strict/relaxed commit ratio (< 1.30 means RAM-backed, i.e. private). */
  idbDurabilityRatio?: number | null;
  /** Median OPFS sync-access-handle `flush()` time in ms from the worker probe. */
  opfsFlushMs?: number | null;
  /** Additive structured incognito probe diagnostics nested beside the flat mirrors. */
  diagnostics?: IncognitoDiagnostics;
  isHeadless?: boolean;
  botReason?: string;
  webdriver?: boolean;
  cdpDetected?: boolean;
  isOsTampered?: boolean;

  /* Server-verified identity — headers outrank the client payload. */
  /** Browser name + full version resolved from Sec-CH-UA / UA-CH / User-Agent. */
  serverVerifiedBrowser?: string;
  /** OS family + version resolved from Sec-CH-UA / UA-CH / User-Agent. */
  serverVerifiedOs?: string;
  /** True when the client-reported browser / OS family conflicts with the header identity. */
  headerMismatch?: boolean;
  /** Human-readable evidence for `headerMismatch`. */
  headerMismatchReason?: string;

  /* Phase 1 — bot / AI-agent subtype classification (server-computed) */
  botSubtype?: BotSubtype;
  botProvider?: string;
  botCategory?: string;
  botIdentityConfidence?: number;
  botInfo?: BotInfo | null;

  /* Phase 2 — authoritative Tor exit relay + local abuse blocklist */
  torExitNode?: boolean;
  ipBlocklisted?: boolean;
  ipBlocklistReasons?: string[];
  /** Explicit proxy relay markers observed on the request (Via / Forwarded / proxy auth). */
  proxyDetected?: boolean;
  proxyReasons?: string[];
  /** Client-side Tor Browser fingerprint (Gecko RFP + letterboxing). */
  isTorBrowserClient?: boolean;
  /** Tri-state server verdict: an anonymous relay known to be an exit node or a relay. */
  torVerdict?: 'exit' | 'relay' | 'no' | 'unknown';
  /** Relay operator / ASN attribution for the Tor exit. */
  torOperator?: string;
  /** Granular AI-agent attribution (Gemini, Grok, Muse, Perplexity, OpenAI, Claude, cloud). */
  aiAgent?: AiAgentAttribution | null;

  /* Phase 3 — mobile emulator / simulator and cloud-container detection */
  emulatorDetected?: boolean;
  emulatorReason?: string;

  /* Phase 4 — sealed request envelope verdicts */
  tamperedRequest?: boolean;
  replayDetected?: boolean;
  requestIntegrityReason?: string;
  requestNonce?: string;
  /** Server-computed 4-signal grid, each tile rated out of 10. */
  smartSignals?: SmartSignals;
  /** Composite badge text, e.g. `Medium Risk • 4/10`. */
  riskBadgeText?: string;

  /* Phase 5 — browser tampering (DevTools Device Mode / anti-detect browsers) */
  tampering?: boolean;
  tamperingConfidence?: 'low' | 'medium' | 'high';
  tamperingMlScore?: number;
  tamperingDetails?: {
    anomaly_score: number;
    anti_detect_browser: boolean;
    devtools_device_emulation: boolean;
    reasons: string[];
    /** True when the runtime is a confirmed privacy-hardened browser (RFP/FPP/ATFP). */
    privacy_hardened?: boolean;
    /** Strongly-corroborated CDP/Playwright/CDC artifacts promoted to the bot gate. Weak,
     * engine-dependent artifacts never appear here on their own. */
    hardAutomationEvidence?: string[];
  };
  developerTools?: boolean;

  /* Phase 5 — active call detection (supported ⇒ the row is rendered) */
  activeCall?: boolean;
  activeCallSupported?: boolean;
  activeCallReasons?: string[];

  /* Phase 5 — privacy settings (Tor Browser RFP / Brave Shields / canvas noise) */
  privacySettings?: boolean;

  /* Phase 6 — raw device attributes (font, emoji, canvas, WebGL, math entropy) */
  rawDeviceAttributes?: unknown;

  /* Phase 2 — SQLite velocity windows and 0–100 calibrated score (server-computed) */
  velocity?: VelocitySignals;
  suspectScore100?: number;
  highActivityDevice?: boolean;
  rareDevice?: boolean;
  rareDevicePercentileBucket?: string;

  /* Additive canonical-risk mirrors — OPTIONAL, never re-derived on the client. */
  /** 0–10 headline mirrored verbatim from the canonical ledger. */
  score10?: number;
  /** Canonical tier mirrored verbatim from the canonical ledger. */
  risk_tier?: RiskTier;
  /** Flat scored-line mirror of `risk.evidence_ledger`. */
  evidence_ledger?: RiskEvidenceLine[];
}

export type LocationSource = 'edge' | 'provider' | 'consensus' | 'tor-relay' | 'none';

export type LocationPrecision = 'city' | 'region' | 'country' | 'unknown';

/**
 * Physical/network location of the egress node, kept separate from the visitor's claimed
 * location. For Tor, VPN and proxy connections only this object is factual: the exit
 * relay's city is not the user's city.
 */
export interface NetworkLocationInfo {
  label: string;
  city: string;
  region: string;
  country: string;
  countryCode: string;
  latitude: number | null;
  longitude: number | null;
  isp: string;
  org: string;
  asn: string;
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
  /** How the location was resolved. `edge` is `request.cf`, the most trustworthy source. */
  locationSource?: LocationSource;
  /** Best precision actually available. Coordinates are never a point, even at `city`. */
  locationPrecision?: LocationPrecision;
  /** True when the request arrived over the Tor network (`T1` or a verified exit). */
  isTor?: boolean;
  /** True only for a verified exit relay, never for a middle relay. */
  isTorExit?: boolean;
  /** VPN / proxy indicator reported by a provider or inferred from the network. */
  isProxyOrVpn?: boolean;
  /** True when `city`/coordinates describe the exit node, not the visitor. */
  isNetworkLocation?: boolean;
  /** Egress-node details, populated for Tor / VPN / proxy connections. */
  networkLocation?: NetworkLocationInfo;

  /* Additive geo-enrichment fields (canonical contract) — all OPTIONAL. Values come only
     from the edge / provider; an unavailable value is never replaced with an invented one. */
  /** ISO continent code (e.g. `NA`). The edge may report a full name instead. */
  continent_code?: string;
  /** Postal / ZIP code reported by the geo provider. */
  postal_code?: string;
  /** ISO-3166-2 subdivision code (e.g. `CA`), not the human-readable `region` name. */
  subdivision_iso?: string;
  /** Accuracy radius in kilometres, or null when the provider supplied none. */
  accuracy_radius?: number | null;
  /** Routed BGP prefix for the egress ASN (e.g. `73.136.0.0/13`). */
  asn_network?: string;
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
  score10?: number;
  riskLevel?: RiskLevel;
  botName?: string;
  recognitionSource?: string;
  cloudOrMaskedGpu?: boolean;
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
  /**
   * Server-normalized UA / client-hints identity. `os` is the OS family only and the
   * version lives in `os_version`; `browser_details` is the v4 event shape.
   */
  os?: string;
  os_version?: string;
  browser_details?: {
    browser_name: string;
    browser_full_version: string;
    browser_major_version: string;
    os: string;
    os_version: string;
    device: string;
    device_model?: string;
  };
  hardwareSignals: HardwareSignals;
  securitySignals: SecuritySignals;
  statistics: VisitStatistics;
  visitHistory: VisitHistoryRecord[];
  historyBackup?: SignedHistoryBackup;
  /* Mirrored at the top level so clients can read them without digging. */
  isIncognito?: boolean;
  incognito?: boolean;
  /** Additive structured incognito probe diagnostics mirrored from the collector. */
  diagnostics?: IncognitoDiagnostics;
  suspectScore?: number;
  riskLevel?: RiskLevel;
  riskBadgeText?: string;
  smartSignals?: SmartSignals;
  /* API v4 mirrors */
  suspectScore100?: number;
  velocity?: VelocitySignals;
  highActivityDevice?: boolean;
  rareDevice?: boolean;
  rareDevicePercentileBucket?: string;
  tampering?: boolean;
  tamperingConfidence?: 'low' | 'medium' | 'high';
  tamperingDetails?: {
    anomaly_score: number;
    anti_detect_browser: boolean;
    devtools_device_emulation: boolean;
    reasons: string[];
    /** True when the runtime is a confirmed privacy-hardened browser (RFP/FPP/ATFP). */
    privacy_hardened?: boolean;
    /** Strongly-corroborated CDP/Playwright/CDC artifacts promoted to the bot gate. Weak,
     * engine-dependent artifacts never appear here on their own. */
    hardAutomationEvidence?: string[];
  };
  activeCall?: boolean;
  activeCallSupported?: boolean;
  rawDeviceAttributes?: unknown;
  /** Phase 4 — a reused nonce is reported here instead of as an HTTP error. */
  replayed?: boolean;
  tampered?: boolean;
  requestIntegrityReason?: string;
  /** Fix 5 — synchronous geohash / metro-zone proximity result. */
  proximity?: import('../lib/geohash').ProximityInfo;
  /** Fix 8 — structured bot & AI agent identification ("Robodex" + BotD). */
  bot?: string;
  bot_type?: string | null;
  bot_info?: BotInfo | null;
  /** Tri-layer identity: canonical ID + resolver match evidence (never replaces visitorId). */
  identity_layers?: {
    visitor_id: string;
    hardware_fingerprint: string;
    browser_fingerprint: string;
    session_id: string;
    storage_healed: boolean;
    match_mode: string;
    match_score: number;
    visitor_found: boolean;
    supplementary_visitor_id?: string;
    supplementary_confidence?: number;
  };
  /** Calibrated identification confidence (v2.0, clamped to [0.10, 0.999]). */
  identification?: {
    confidence: { score: number; version: string };
    visitor_found: boolean;
    tampering: boolean;
    spoof_likelihood: 'low' | 'medium' | 'high';
    /* Additive label / calibration mirrors — OPTIONAL, mirrored from the canonical envelope. */
    /** Human-facing label for the published score. */
    label?: string;
    /** Held-out calibration gate status. */
    calibration_status?: 'uncalibrated' | 'calibrated';
    /** Human-facing confidence label (`Confidence N%` / `Match evidence N%`). */
    confidence_label?: string;
    /** Version of the calibration artifact applied to the score. */
    calibration_version?: string;
  };
  /** Cross-signal consistency verdict derived from the resolver's constraint violations. */
  consistency?: {
    score: number;
    spoof_likelihood: 'low' | 'medium' | 'high';
    flags: string[];
    agent_verdict: string;
    /** Optional human-facing label mirrored from the canonical envelope. */
    label?: string;
  };

  /* ------------------------------------------------------------------------ */
  /* Additive canonical-contract fields — ALL OPTIONAL. Legacy payloads stay valid.
     Every value below is mirrored verbatim from the server's canonical envelope; the
     dashboard never re-derives any of them. See src/lib/telemetryContract.ts and
     src/shared/normalization/uaNormalizer.ts for the source vocabulary. */
  /** Host runtime that renders the page (engine-independent: electron, node, webview, …). */
  runtime?: RuntimeKind;
  /** Host application name when the runtime is an Electron / IDE / WebView shell. */
  host_app?: string;
  /** Broker-facing client classification derived from `runtime`. */
  client_type?: ClientType;
  /** True when the UA source (HTTP header vs client hints / JS) disagreed. */
  ua_source_mismatch?: boolean;
  /** Normalized GPU truth bucket from the labeling / calibration pipeline. */
  gpuObservation?: GpuObservation;
  /** Certainty-only inspector attachment signal carried by the canonical envelope. */
  inspectorState?: InspectorStateTristate;
  /** Flat inspector probe flags carried beside the canonical automation verdict. */
  inspectorFlags?: {
    cdp_attached?: boolean;
    developer_tools?: boolean;
  };
  /** Version of the canonical envelope schema. */
  schemaVersion?: number;
  /** Version of the parser that produced the canonical payload. */
  parserVersion?: string;
  /** Source-control revision of the build that emitted the payload. */
  buildSha?: string;

  /* Flat risk mirrors — the canonical OrthogonalRiskLedger is the single source. */
  /** Flat scored-line mirror of `risk.evidence_ledger`. */
  evidence_ledger?: RiskEvidenceLine[];
  /** camelCase alias of `evidence_ledger` used by the canonical envelope. */
  evidenceLedger?: RiskEvidenceLine[];
  /** 0–10 headline score mirrored verbatim from the canonical ledger. */
  score10?: number;
  /** Canonical risk tier mirrored verbatim from the canonical ledger. */
  risk_tier?: RiskTier;

  /* Labeling / calibration provenance used by the offline training pipeline. */
  /** Ground-truth label assigned to this observation. */
  label?: string;
  /** When the telemetry observation was captured (ISO-8601). */
  observation_timestamp?: string;
  /** When the ground-truth label was assigned (ISO-8601). */
  label_timestamp?: string;
  /** Who or what produced the label (analyst, model id, rule set, …). */
  label_source?: string;
  /** Scoring model version used at observation time. */
  model_version?: string;
  /** Calibration artifact version applied to the score. */
  calibration_version?: string;
  /** Hash of the weight configuration used for scoring. */
  weight_config_hash?: string;

  /* Geo-enrichment mirrors of `location`, using the canonical snake_case names. */
  continent_code?: string;
  postal_code?: string;
  subdivision_iso?: string;
  accuracy_radius?: number | null;
  asn_network?: string;
}

/**
 * Intel System — shared event contract, Fingerprint Pro Server API v4 shape.
 *
 * Pure TypeScript, dual-target (browser + Cloudflare Workers). No Node APIs,
 * no project imports, no runtime dependencies. Field names follow the Pro
 * Server API v4 snake_case convention:
 * https://docs.fingerprint.com/reference/server-api-get-event
 *
 * The ONLY throwing function in this module is `assertEventV4Sanity`, which
 * throws a single, precise Error on the first failed sanity rule. Everything
 * else (including `assertionFailures`) is total and never throws.
 */

/* -------------------------------------------------------------------------- */
/* Core Pro-shaped sections                                                    */
/* -------------------------------------------------------------------------- */

/**
 * `os` is the OS family only ('Windows', 'Mac OS X', 'Android', 'iOS',
 * 'Linux') — never 'Windows 11'. `os_version` carries the version only
 * ('11'). `browser_major_version` is a non-empty numeric string whenever a
 * full version exists.
 */
export interface BrowserDetails {
  browser_name: string;
  browser_full_version: string;
  browser_major_version: string;
  os: string;
  os_version: string;
  device: string;
  device_model?: string;
}

export interface IpGeolocationV4 {
  city: string;
  country: string;
  country_name?: string;
  latitude: number;
  longitude: number;
  postcode: string;
}

/** Same shape as the v4 geolocation, but `postcode` is optional. */
export interface IpGeolocationV6 {
  city: string;
  country: string;
  country_name?: string;
  latitude: number;
  longitude: number;
  postcode?: string;
}

export interface IpInfoV4 {
  address: string;
  geolocation: IpGeolocationV4;
  /** Numeric AS number as a string, e.g. '7922'. */
  asn: string;
  asn_name: string;
  /** Anonymized routed network, e.g. '73.136.0.0/13'. */
  asn_network: string;
  asn_type: string;
  datacenter_result: boolean;
  datacenter_name?: string;
}

export interface IpInfoV6 {
  address: string;
  geolocation: IpGeolocationV6;
  asn: string;
  asn_name: string;
  asn_network: string;
  asn_type: string;
  datacenter_result: boolean;
  datacenter_name?: string;
}

export interface IpInfo {
  v4?: IpInfoV4;
  v6?: IpInfoV6;
}

export interface IdentificationConfidence {
  /** Calibrated 0..1 identification confidence. */
  score: number;
  version: '2.0';
}

export interface EventIdentification {
  confidence: IdentificationConfidence;
  visitor_found: boolean;
}

/** Generic Smart-Signal-shaped block: {detected, result?}. */
export interface DetectionSignal {
  detected: boolean;
  result?: string | null;
}

/* -------------------------------------------------------------------------- */
/* Intel System extensions                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Multi-layer identity modes. This mirrors the matching engine's modes plus a
 * 'none' sentinel used when no match attempt has been recorded yet.
 */
export type IntelMatchMode =
  | 'exact'
  | 'cross-browser'
  | 'hardware-only'
  | 'engine-only'
  | 'strict'
  | 'lenient'
  | 'none';

export interface IntelIdentityLayers {
  visitor_id: string;
  hardware_fingerprint: string;
  browser_fingerprint: string;
  session_id: string;
  storage_healed: boolean;
  match_mode: IntelMatchMode;
  /** 0..100 weighted match score for the recorded mode. */
  match_score: number;
}

export interface IntelConsistency {
  /** 0..100 cross-signal consistency score. */
  score: number;
  spoof_likelihood: 'low' | 'medium' | 'high';
  flags: string[];
  agent_verdict: string;
}

/** Mirrors the Pro API `supplementary_id_high_recall` section. */
export interface IntelSupplementaryIdHighRecall {
  visitor_id: string;
  /** `version` is a string ('2.0', or 'Not Supported' when unsupported). */
  confidence: { score: number; version: string };
}

export interface IntelSystemExtensions {
  identity_layers: IntelIdentityLayers;
  consistency: IntelConsistency;
  raw_device_attributes: Record<string, unknown>;
  supplementary_id_high_recall?: IntelSupplementaryIdHighRecall;
}

/* -------------------------------------------------------------------------- */
/* Top-level event                                                             */
/* -------------------------------------------------------------------------- */

export interface EventV4Meta {
  event_id?: string;
  timestamp?: number;
  url?: string;
  linked_id?: string;
  source?: string;
  user_agent?: string;
  ip_address?: string;
  [key: string]: unknown;
}

/**
 * Fingerprint Pro Server API v4-shaped identification event, extended with the
 * IntelSystemExtensions block. The `IntelSystemExtensions` key is intentionally
 * capitalized (Pro-compatible JSON passthrough of the Intel extension).
 */
export interface EventV4 {
  visitor_id: string;
  browser_details: BrowserDetails;
  ip_info: IpInfo;
  identification: EventIdentification;
  vpn: DetectionSignal;
  bot: DetectionSignal;
  tampering: DetectionSignal;
  developer_tools: DetectionSignal;
  virtual_machine: DetectionSignal;
  incognito: DetectionSignal;
  cloned: DetectionSignal;
  tor: DetectionSignal;
  privacy_settings: DetectionSignal;
  device: DetectionSignal;
  meta?: EventV4Meta;
  IntelSystemExtensions?: IntelSystemExtensions;
}

/* -------------------------------------------------------------------------- */
/* Sanity assertions                                                           */
/* -------------------------------------------------------------------------- */

/** Known placeholder ASN name meaning "no real attribution available". */
export const ASN_PLACEHOLDER_NAME = 'Standard Network';

/** Inclusive confidence band required by the platform. */
export const CONFIDENCE_MIN = 0.1;
export const CONFIDENCE_MAX = 0.999;

function isNumericAsn(asn: unknown): boolean {
  return typeof asn === 'string' && /^\s*\d+\s*$/.test(asn);
}

/**
 * Collects every sanity failure as a human-readable string. Never throws —
 * malformed / partial events simply produce failure entries (or none).
 */
function collectSanityFailures(ev: EventV4): string[] {
  const failures: string[] = [];

  if (ev === null || ev === undefined || typeof ev !== 'object') {
    return ['EventV4 sanity: event must be a non-null object'];
  }

  /* browser_details: os family hygiene + version split */
  const bd = ev.browser_details as BrowserDetails | undefined;
  if (bd !== null && bd !== undefined && typeof bd === 'object') {
    const os = typeof bd.os === 'string' ? bd.os.trim() : '';
    const osVersion = typeof bd.os_version === 'string' ? bd.os_version.trim() : '';

    if (os && /\d/.test(os)) {
      failures.push(
        `EventV4 sanity: browser_details.os "${os}" contains digits — os must be the family only (e.g. 'Windows'), version goes to os_version`,
      );
    }
    if (os && osVersion && os === osVersion) {
      failures.push(
        `EventV4 sanity: browser_details.os ("${os}") must not equal browser_details.os_version`,
      );
    }

    const full =
      typeof bd.browser_full_version === 'string' ? bd.browser_full_version.trim() : '';
    const major =
      typeof bd.browser_major_version === 'string' ? bd.browser_major_version.trim() : '';
    if (full) {
      if (!major) {
        failures.push(
          `EventV4 sanity: browser_major_version must be a non-empty numeric string when browser_full_version "${full}" is present`,
        );
      } else if (!/^\d+$/.test(major)) {
        failures.push(
          `EventV4 sanity: browser_major_version "${major}" must be a numeric string`,
        );
      }
    }
  }

  /* ip_info: numeric ASN requires a real attribution name */
  const ip = ev.ip_info as IpInfo | undefined;
  const ipBlocks: Array<IpInfoV4 | IpInfoV6 | undefined> = [ip?.v4, ip?.v6];
  for (const block of ipBlocks) {
    if (block === null || block === undefined || typeof block !== 'object') continue;
    if (isNumericAsn(block.asn)) {
      const name = typeof block.asn_name === 'string' ? block.asn_name.trim() : '';
      if (!name) {
        failures.push(
          `EventV4 sanity: asn_name must not be empty for numeric asn "${block.asn}"`,
        );
      } else if (name === ASN_PLACEHOLDER_NAME) {
        failures.push(
          `EventV4 sanity: asn_name must not be the placeholder "${ASN_PLACEHOLDER_NAME}" for numeric asn "${block.asn}"`,
        );
      }
    }
  }

  /* identification confidence band */
  const confidence = ev.identification?.confidence as IdentificationConfidence | undefined;
  if (confidence !== null && confidence !== undefined && typeof confidence === 'object') {
    const score = confidence.score;
    if (typeof score !== 'number' || !isFinite(score)) {
      failures.push(
        'EventV4 sanity: identification.confidence.score must be a finite number',
      );
    } else if (score < CONFIDENCE_MIN || score > CONFIDENCE_MAX) {
      failures.push(
        `EventV4 sanity: identification.confidence.score ${score} is outside the inclusive band [${CONFIDENCE_MIN}, ${CONFIDENCE_MAX}]`,
      );
    }
  }

  return failures;
}

/**
 * Throws a precise Error on the first sanity rule the event violates.
 * Checks run in this order:
 *   1. os contains a digit
 *   2. os === os_version
 *   3. full version present but major version empty / non-numeric
 *   4. numeric asn with empty or placeholder asn_name
 *   5. confidence.score outside [0.10, 0.999]
 * A non-object event throws a structural error first.
 */
export function assertEventV4Sanity(ev: EventV4): void {
  const failures = collectSanityFailures(ev);
  if (failures.length > 0) {
    throw new Error(failures[0]);
  }
}

/**
 * Same rules as `assertEventV4Sanity`, but returns the failure list without
 * throwing — intended for dashboards / telemetry. Never throws.
 */
export function assertionFailures(ev: EventV4): string[] {
  try {
    return collectSanityFailures(ev);
  } catch {
    /* defensive: never throw from the non-asserting variant */
    return ['EventV4 sanity: internal error while validating event'];
  }
}

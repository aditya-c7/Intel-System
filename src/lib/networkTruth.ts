/**
 * Additive, pure network-truth helpers (no network calls, no timers, no SDK).
 * Values are evidence only: they never change risk score, verdict, or tier.
 *
 * Canonical RTT normalizer: mirrors worker/index.js `normalizedRtt` (lowercase
 * transports, one selected source, no cross-transport fallback) and extends it
 * with an explicit 'unknown' transport and a 1-2000 ms sanity range.
 */

/** Lowercase to match the Worker's emitted `rtt_transport` values. */
export type RttTransport = 'quic' | 'tcp' | 'unknown';
export type RttStatus = 'measured' | 'no-data' | 'invalid';
export type RecencyBucket = 'fresh' | 'recent' | 'aged' | 'stale' | 'unknown';

export interface NormalizedRtt {
  rtt_ms: number | null;
  rtt_transport: RttTransport;
  rtt_source: 'clientTcpRtt' | 'clientQuicRtt' | null;
  status: RttStatus;
  label: string;
}

export interface RttInput {
  httpProtocol?: string | null;
  clientTcpRtt?: number | null;
  clientQuicRtt?: number | null;
  /** Optional request.cf transport hint (an object in the Worker; strings accepted safely). */
  edgeL4?: unknown;
}

/**
 * Read a fixed set of properties from an untrusted input in one guarded pass.
 * Any throwing getter / proxy trap degrades the whole source to `{}` (empty source),
 * and the returned bag is a plain object so later reads cannot throw.
 */
function readGuarded(input: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!input || typeof input !== 'object') return {};
  try {
    const source = input as Record<string, unknown>;
    const bag: Record<string, unknown> = {};
    for (const key of keys) bag[key] = source[key];
    return bag;
  } catch {
    return {};
  }
}

/** Non-array object check that itself tolerates hostile proxies. */
function isRecord(value: unknown): value is Record<string, unknown> {
  try {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  } catch {
    return false;
  }
}

/**
 * Worker fallback QUIC signal: a non-empty, non-array `request.cf.edgeL4` object.
 * String forms (e.g. 'quic' / 'h3') are accepted defensively; anything that throws
 * is treated as no signal.
 */
function hasQuicEdgeHint(edgeL4: unknown): boolean {
  try {
    if (isRecord(edgeL4)) return Object.keys(edgeL4).length > 0;
    if (typeof edgeL4 === 'string') return /quic|h3/i.test(edgeL4);
  } catch {
    return false;
  }
  return false;
}

/** 0, negatives, NaN and non-numbers are all "no data", not a measurement. */
function positiveFinite(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : null;
}

export function normalizeRtt(input: RttInput | null | undefined): NormalizedRtt {
  const source = readGuarded(input, ['httpProtocol', 'clientTcpRtt', 'clientQuicRtt', 'edgeL4']);
  const protocol = typeof source.httpProtocol === 'string' ? source.httpProtocol : '';
  const isQuicProtocol = /http\/3|quic|h3/i.test(protocol);
  const isTcpProtocol = /http\/(1|2)/i.test(protocol);

  // Protocol is authoritative. edgeL4 is the Worker's fallback hint for deployments
  // where httpProtocol is not populated; it never overrides an explicit HTTP/1 or 2.
  let transport: RttTransport = 'unknown';
  let sourceName: 'clientTcpRtt' | 'clientQuicRtt' | null = null;
  if (isQuicProtocol) {
    transport = 'quic';
    sourceName = 'clientQuicRtt';
  } else if (isTcpProtocol) {
    transport = 'tcp';
    sourceName = 'clientTcpRtt';
  } else if (hasQuicEdgeHint(source.edgeL4)) {
    transport = 'quic';
    sourceName = 'clientQuicRtt';
  }

  const tcp = positiveFinite(source.clientTcpRtt);
  const quic = positiveFinite(source.clientQuicRtt);
  // Exactly one transport's field is read; there is deliberately NO cross-transport
  // fallback (a QUIC request never borrows a TCP round trip, and vice versa).
  const value = sourceName === 'clientQuicRtt' ? quic : sourceName === 'clientTcpRtt' ? tcp : null;

  if (value === null) {
    return {
      rtt_ms: null,
      rtt_transport: transport,
      rtt_source: sourceName,
      status: 'no-data',
      label: transport === 'quic'
        ? 'QUIC RTT not available (0 is a placeholder, not a measurement)'
        : transport === 'tcp'
          ? 'TCP RTT not available'
          : 'RTT not available (transport unknown; no cross-transport fallback)',
    };
  }
  const invalid = value < 1 || value > 2000;
  return {
    rtt_ms: invalid ? null : value,
    rtt_transport: transport,
    rtt_source: sourceName,
    status: invalid ? 'invalid' : 'measured',
    label: invalid ? 'RTT outside 1-2000 ms sanity range' : 'edge-derived smoothed RTT (ms)',
  };
}

export interface ProxyTruthInput {
  classification?: string | null;
  provider?: string | null;
  last_seen?: string | null;
  percent_days_seen?: number | null;
  source_tier?: string | null;
  confidence?: number | null;
  coverage?: number | null;
  nowMs?: number;
  raw?: Record<string, unknown> | null;
}

export interface ProxyTruth {
  classification: string;
  provider: string | null;
  last_seen: string | null;
  recency_days: number | null;
  recency_bucket: RecencyBucket;
  status: 'observed' | 'unattributed' | 'stale' | 'unknown' | 'conflict';
  source_tier: string | null;
  confidence: number | null;
  coverage: number | null;
  percent_days_seen: number | null;
  note: string;
}

/** Fixed-clock friendly: explicit `nowMs` wins; Date.now() is the fallback only. */
function clockNow(source: Record<string, unknown>): number {
  try {
    return typeof source.nowMs === 'number' && Number.isFinite(source.nowMs) ? source.nowMs : Date.now();
  } catch {
    return 0;
  }
}

export function resolveProxyTruth(input: ProxyTruthInput | null | undefined): ProxyTruth {
  const source = readGuarded(input, [
    'classification', 'provider', 'last_seen', 'percent_days_seen',
    'source_tier', 'confidence', 'coverage', 'nowMs',
  ]);
  const now = clockNow(source);
  const classification = typeof source.classification === 'string' && source.classification.trim() ? source.classification.trim() : 'unknown';
  const provider = typeof source.provider === 'string' && source.provider.trim() ? source.provider.trim() : null;
  const lastSeen = typeof source.last_seen === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(source.last_seen) ? source.last_seen : null;
  let recencyDays: number | null = null;
  let bucket: RecencyBucket = 'unknown';
  let futureDated = false;
  if (lastSeen) {
    let parsed = NaN;
    try {
      parsed = Date.parse(`${lastSeen}T00:00:00Z`);
    } catch {
      parsed = NaN;
    }
    if (Number.isFinite(parsed)) {
      const ageDays = Math.floor((now - parsed) / 86_400_000);
      if (ageDays < 0) {
        // A future observation has no honest data age: never report it as 'fresh'.
        futureDated = true;
      } else {
        recencyDays = ageDays;
        bucket = ageDays <= 7 ? 'fresh' : ageDays <= 30 ? 'recent' : ageDays <= 90 ? 'aged' : 'stale';
      }
    }
  }
  const confidence = typeof source.confidence === 'number' && Number.isFinite(source.confidence) ? source.confidence : null;
  const coverage = typeof source.coverage === 'number' && Number.isFinite(source.coverage) ? source.coverage : null;
  const pct = typeof source.percent_days_seen === 'number' && Number.isFinite(source.percent_days_seen) ? source.percent_days_seen : null;
  // 'conflict' stays declared but is never invented: no mutually-exclusive authoritative
  // flag model is defined here, and this helper must not manufacture a verdict.
  const status: ProxyTruth['status'] = futureDated || !classification || classification === 'unknown'
    ? 'unknown'
    : !provider
      ? 'unattributed'
      : bucket === 'stale'
        ? 'stale'
        : 'observed';
  return {
    classification,
    provider,
    last_seen: lastSeen,
    recency_days: recencyDays,
    recency_bucket: bucket,
    status,
    source_tier: typeof source.source_tier === 'string' ? source.source_tier : null,
    confidence,
    coverage,
    percent_days_seen: pct,
    note: 'recency_days is data age, not user activity; confidence is source quality, not probability',
  };
}

export interface LightDistanceInput {
  rttMs?: number | null;
  claimedDistanceKm?: number | null;
  geoUncertaintyKm?: number | null;
}

export interface LightDistanceTruth {
  claimed_distance_km: number | null;
  floor_rtt_ms: number | null;
  tolerance_ms: number | null;
  too_fast_for_distance: boolean | null;
  check_status: 'ok' | 'insufficient_distance' | 'no_rtt' | 'no_geo';
  note: string;
}

/** JA4L-style, too-fast-only check. Never flags "too slow" and never sets a verdict. */
export function checkLightDistance(input: LightDistanceInput | null | undefined): LightDistanceTruth {
  const source = readGuarded(input, ['rttMs', 'claimedDistanceKm', 'geoUncertaintyKm']);
  const rtt = positiveFinite(source.rttMs);
  const distance = typeof source.claimedDistanceKm === 'number' && Number.isFinite(source.claimedDistanceKm) && source.claimedDistanceKm >= 0 ? source.claimedDistanceKm : null;
  if (rtt === null) return { claimed_distance_km: distance, floor_rtt_ms: null, tolerance_ms: null, too_fast_for_distance: null, check_status: 'no_rtt', note: 'no measured RTT' };
  if (distance === null) return { claimed_distance_km: null, floor_rtt_ms: null, tolerance_ms: null, too_fast_for_distance: null, check_status: 'no_geo', note: 'no geolocation/colo distance' };
  const uncertainty = typeof source.geoUncertaintyKm === 'number' && Number.isFinite(source.geoUncertaintyKm) ? Math.max(0, source.geoUncertaintyKm) : 200;
  const dMin = Math.max(0, distance - uncertainty);
  const floor = dMin / 103;
  if (floor < 25) return { claimed_distance_km: distance, floor_rtt_ms: floor, tolerance_ms: null, too_fast_for_distance: null, check_status: 'insufficient_distance', note: 'distance too small for a stable light-distance check' };
  const tolerance = Math.max(5, 0.1 * floor);
  const tooFast = rtt < floor - tolerance;
  return { claimed_distance_km: distance, floor_rtt_ms: floor, tolerance_ms: tolerance, too_fast_for_distance: tooFast, check_status: 'ok', note: 'informational only; never a VPN/proxy verdict' };
}

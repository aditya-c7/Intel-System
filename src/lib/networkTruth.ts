/**
 * Additive, pure network-truth helpers (no network calls, no timers, no SDK).
 * Values are evidence only: they never change risk score, verdict, or tier.
 */

export type RttTransport = 'TCP' | 'QUIC' | 'unknown';
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
}

export function normalizeRtt(input: RttInput | null | undefined): NormalizedRtt {
  const source = input && typeof input === 'object' ? input : {};
  const protocol = typeof source.httpProtocol === 'string' ? source.httpProtocol : '';
  const isHttp3 = /http\/3|quic|h3/i.test(protocol);
  const transport: RttTransport = isHttp3 ? 'QUIC' : ((/http\/(1|2)/i.test(protocol) ? 'TCP' : 'unknown'));
  const tcp = typeof source.clientTcpRtt === 'number' && Number.isFinite(source.clientTcpRtt) && source.clientTcpRtt > 0 ? source.clientTcpRtt : null;
  const quic = typeof source.clientQuicRtt === 'number' && Number.isFinite(source.clientQuicRtt) && source.clientQuicRtt > 0 ? source.clientQuicRtt : null;
  const sourceName: 'clientTcpRtt' | 'clientQuicRtt' | null = isHttp3 ? 'clientQuicRtt' : (/http\/(1|2)/i.test(protocol) ? 'clientTcpRtt' : null);
  const value = sourceName === 'clientQuicRtt' ? quic : sourceName === 'clientTcpRtt' ? tcp : null;
  if (value === null) {
    return {
      rtt_ms: null,
      rtt_transport: transport,
      rtt_source: sourceName,
      status: 'no-data',
      label: transport === 'QUIC' ? 'QUIC RTT not available (0 is a placeholder, not a measurement)' : 'TCP RTT not available',
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

export function resolveProxyTruth(input: ProxyTruthInput | null | undefined): ProxyTruth {
  const source = input && typeof input === 'object' ? input : {};
  const now = typeof source.nowMs === 'number' && Number.isFinite(source.nowMs) ? source.nowMs : Date.now();
  const classification = typeof source.classification === 'string' && source.classification.trim() ? source.classification.trim() : 'unknown';
  const provider = typeof source.provider === 'string' && source.provider.trim() ? source.provider.trim() : null;
  const lastSeen = typeof source.last_seen === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(source.last_seen) ? source.last_seen : null;
  let recencyDays: number | null = null;
  let bucket: RecencyBucket = 'unknown';
  if (lastSeen) {
    const parsed = Date.parse(`${lastSeen}T00:00:00Z`);
    if (Number.isFinite(parsed)) {
      recencyDays = Math.max(0, Math.floor((now - parsed) / 86_400_000));
      bucket = recencyDays <= 7 ? 'fresh' : recencyDays <= 30 ? 'recent' : recencyDays <= 90 ? 'aged' : 'stale';
    }
  }
  const confidence = typeof source.confidence === 'number' && Number.isFinite(source.confidence) ? source.confidence : null;
  const coverage = typeof source.coverage === 'number' && Number.isFinite(source.coverage) ? source.coverage : null;
  const pct = typeof source.percent_days_seen === 'number' && Number.isFinite(source.percent_days_seen) ? source.percent_days_seen : null;
  const status: ProxyTruth['status'] = !classification || classification === 'unknown'
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
  const source = input && typeof input === 'object' ? input : {};
  const rtt = typeof source.rttMs === 'number' && Number.isFinite(source.rttMs) && source.rttMs > 0 ? source.rttMs : null;
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

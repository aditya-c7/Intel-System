/**
 * Lightweight, dependency-free geohash encoder (Fix 5).
 *
 * Proximity Detection must resolve synchronously from the server-resolved IP
 * coordinates — never wait on an optional browser geolocation callback that may
 * never fire. The standard base32 geohash alphabet is used, so the zone id is
 * stable across providers and runtime bundles.
 */

const GEOHASH_BASE32 = '0123456789bcdefghjkmnpqrstuvwxyz';

/** True when both coordinates are finite and inside the WGS-84 range. */
export function isValidCoordinate(
  latitude: number | null | undefined,
  longitude: number | null | undefined
): boolean {
  return (
    typeof latitude === 'number' &&
    typeof longitude === 'number' &&
    Number.isFinite(latitude) &&
    Number.isFinite(longitude) &&
    Math.abs(latitude) <= 90 &&
    Math.abs(longitude) <= 180
  );
}

/**
 * Encodes a coordinate pair to a standard geohash string. Returns `null` for
 * invalid input so callers can render the explicit unresolved fallback.
 */
export function encodeGeohash(
  latitude: number | null | undefined,
  longitude: number | null | undefined,
  precision = 6
): string | null {
  if (!isValidCoordinate(latitude, longitude)) return null;
  const chars = Math.max(1, Math.min(12, Math.floor(precision)));
  let latMin = -90;
  let latMax = 90;
  let lonMin = -180;
  let lonMax = 180;
  let hash = '';
  let bits = 0;
  let bitCount = 0;
  let even = true;

  while (hash.length < chars) {
    if (even) {
      const mid = (lonMin + lonMax) / 2;
      if (longitude! >= mid) {
        bits = (bits << 1) | 1;
        lonMin = mid;
      } else {
        bits = bits << 1;
        lonMax = mid;
      }
    } else {
      const mid = (latMin + latMax) / 2;
      if (latitude! >= mid) {
        bits = (bits << 1) | 1;
        latMin = mid;
      } else {
        bits = bits << 1;
        latMax = mid;
      }
    }
    even = !even;
    bitCount += 1;
    if (bitCount === 5) {
      hash += GEOHASH_BASE32[bits];
      bits = 0;
      bitCount = 0;
    }
  }
  return hash;
}

/** `52.37°N, 4.89°E` — the human half of the Metro Zone tile. */
export function formatCoordinatePair(
  latitude: number | null | undefined,
  longitude: number | null | undefined
): string {
  if (!isValidCoordinate(latitude, longitude)) return '';
  const lat = `${Math.abs(latitude!).toFixed(2)}°${latitude! >= 0 ? 'N' : 'S'}`;
  const lon = `${Math.abs(longitude!).toFixed(2)}°${longitude! >= 0 ? 'E' : 'W'}`;
  return `${lat}, ${lon}`;
}

export interface ProximityInfo {
  /** `prox_<geohash>` or `prox_unresolved`. */
  id: string;
  /** Always a 6-character geohash when coordinates resolved. */
  geohash: string | null;
  /** `Zone u173zq · 52.37°N, 4.89°E` */
  zone_label: string;
  /** 5 km — deliberately coarse so the tile never exposes a precise address. */
  precision_radius: number;
  confidence: number;
  resolved: boolean;
}

/** Builds the API v4 `proximity` object from the resolved IP coordinates. */
export function buildProximityInfo(
  latitude: number | null | undefined,
  longitude: number | null | undefined
): ProximityInfo {
  const geohash = encodeGeohash(latitude, longitude, 6);
  if (!geohash) {
    return {
      id: 'prox_unresolved',
      geohash: null,
      zone_label: 'Zone Unresolved (IP-only)',
      precision_radius: 5000,
      confidence: 0,
      resolved: false,
    };
  }
  const coords = formatCoordinatePair(latitude, longitude);
  return {
    id: `prox_${geohash}`,
    geohash,
    zone_label: `Zone ${geohash}${coords ? ` · ${coords}` : ''}`,
    precision_radius: 5000,
    confidence: 0.92,
    resolved: true,
  };
}

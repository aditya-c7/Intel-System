import { useEffect, useRef } from 'react';
import L from 'leaflet';
import {
  COUNTRY_GEO,
  isCoordinateConsistentWithCountry,
  type CountryGeo,
} from '../lib/countryGeo';

interface LocationMapProps {
  latitude: number | null;
  longitude: number | null;
  city: string;
  region: string;
  country: string;
  countryCode?: string;
  publicIp: string;
  timezone?: string;
  /** Set for Tor / VPN / proxy connections: the pin is the egress node, not the visitor. */
  networkLabel?: string;
}

/** Country-name variants that GeoIP providers and edge headers actually emit. */
const COUNTRY_ALIASES: Record<string, string> = {
  'united states of america': 'US',
  usa: 'US',
  us: 'US',
  'great britain': 'GB',
  uk: 'GB',
  'united kingdom of great britain and northern ireland': 'GB',
  russia: 'RU',
  'russian federation': 'RU',
  'south korea': 'KR',
  'republic of korea': 'KR',
  'north korea': 'KP',
  'czech republic': 'CZ',
  czechia: 'CZ',
  uae: 'AE',
  'united arab emirates': 'AE',
  'the netherlands': 'NL',
  holland: 'NL',
  turkey: 'TR',
  turkiye: 'TR',
  'ivory coast': 'CI',
  "cote d'ivoire": 'CI',
  vietnam: 'VN',
  'viet nam': 'VN',
  'hong kong': 'HK',
  macau: 'MO',
  macao: 'MO',
  taiwan: 'TW',
  'taiwan, province of china': 'TW',
};

function normalizeName(value: string): string {
  return (value || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

function findCountry(countryCode?: string, countryNameValue?: string): CountryGeo | null {
  const code = (countryCode || '').trim().toUpperCase();
  if (code && COUNTRY_GEO[code]) return COUNTRY_GEO[code];

  const normalized = normalizeName(countryNameValue || '');
  if (!normalized) return null;

  const alias = COUNTRY_ALIASES[normalized];
  if (alias && COUNTRY_GEO[alias]) return COUNTRY_GEO[alias];

  for (const entry of Object.values(COUNTRY_GEO)) {
    if (normalizeName(entry.name) === normalized) return entry;
  }
  return null;
}

function validCoordinate(latitude: number | null, longitude: number | null): boolean {
  return (
    typeof latitude === 'number' &&
    typeof longitude === 'number' &&
    Number.isFinite(latitude) &&
    Number.isFinite(longitude) &&
    Math.abs(latitude) <= 90 &&
    Math.abs(longitude) <= 180
  );
}

function countryZoom(geo: CountryGeo): number {
  const span = Math.max(geo.maxLat - geo.minLat, geo.maxLng - geo.minLng);
  if (span > 45) return 3;
  if (span > 20) return 4;
  if (span > 8) return 5;
  return 6;
}

/**
 * Resolves a pin that can never contradict the reported country.
 *
 * Order: a coordinate that fits the reported country, then the country's own interior
 * point, then an unlabelled coordinate. There is deliberately no timezone or hardcoded
 * India fallback: placing a visitor in a country the lookup never reported is worse than
 * showing no pin at all.
 */
function resolveMapCoordinates(
  latitude: number | null,
  longitude: number | null,
  countryCode: string | undefined,
  countryName: string
): { lat: number; lng: number; zoom: number } | null {
  const geo = findCountry(countryCode, countryName);
  const hasCoordinate = validCoordinate(latitude, longitude);

  if (hasCoordinate && (!geo || isCoordinateConsistentWithCountry(latitude, longitude, geo.code))) {
    return {
      lat: latitude as number,
      lng: longitude as number,
      zoom: countryName && countryName !== 'Unknown' ? 10 : 8,
    };
  }

  if (geo) {
    return { lat: geo.lat, lng: geo.lng, zoom: countryZoom(geo) };
  }

  if (hasCoordinate) {
    return { lat: latitude as number, lng: longitude as number, zoom: 8 };
  }

  return null;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function isMeaningful(value: string): boolean {
  const normalized = (value || '').trim().toLowerCase();
  return Boolean(normalized) && normalized !== 'unknown' && normalized !== 'unavailable';
}

export function LocationMap({
  latitude,
  longitude,
  city,
  region,
  country,
  countryCode,
  publicIp,
  networkLabel,
}: LocationMapProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const markerRef = useRef<L.Marker | null>(null);

  const resolved = resolveMapCoordinates(latitude, longitude, countryCode, country);
  const lat = resolved?.lat ?? 20;
  const lng = resolved?.lng ?? 0;
  const zoom = resolved?.zoom ?? 2;

  const locationParts = [city, region, country].filter(isMeaningful);
  const baseLabel =
    locationParts.length > 0
      ? locationParts.filter((v, i) => i === 0 || v !== locationParts[i - 1]).join(', ')
      : 'Approximate Location';
  const labelText = networkLabel ? `${networkLabel} · ${baseLabel}` : baseLabel;

  useEffect(() => {
    if (!containerRef.current) return;

    if (!mapRef.current) {
      const map = L.map(containerRef.current, {
        center: [lat, lng],
        zoom,
        zoomControl: true,
        attributionControl: false,
        scrollWheelZoom: false,
      });

      // OpenStreetMap Free standard tile layer (subject to OSM tile usage policy)
      L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution:
          '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors',
      }).addTo(map);

      mapRef.current = map;

      setTimeout(() => {
        map.invalidateSize();
      }, 120);
    }

    if (!resolved) {
      if (markerRef.current) {
        markerRef.current.remove();
        markerRef.current = null;
      }
      mapRef.current.setView([lat, lng], zoom, { animate: false });
      return;
    }

    if (!markerRef.current) {
      const pinIcon = L.divIcon({
        className: 'intel-leaflet-pin',
        html: `<div style="width:18px;height:18px;border-radius:9999px;background:#F05A28;border:3px solid #FFFFFF;box-shadow:0 2px 6px rgba(15,23,42,0.35);"></div>`,
        iconSize: [18, 18],
        iconAnchor: [9, 9],
      });
      markerRef.current = L.marker([lat, lng], { icon: pinIcon }).addTo(mapRef.current);
    } else {
      markerRef.current.setLatLng([lat, lng]);
    }

    markerRef.current.bindPopup(
      `<div style="font-family:sans-serif;font-size:12px;line-height:1.4;"><strong>${escapeHtml(
        labelText
      )}</strong><br/><span style="font-family:monospace;opacity:0.75;">IP: ${escapeHtml(
        publicIp
      )}</span></div>`
    );

    mapRef.current.setView([lat, lng], zoom, { animate: true });
  }, [lat, lng, zoom, labelText, publicIp, Boolean(resolved)]);

  useEffect(() => {
    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
        markerRef.current = null;
      }
    };
  }, []);

  return (
    <div className="relative w-full h-full min-h-[168px] bg-slate-100 overflow-hidden z-0">
      <div ref={containerRef} className="w-full h-full min-h-[168px]" />
      {!resolved && (
        <div className="absolute inset-0 z-[500] flex flex-col items-center justify-center gap-1 bg-slate-100/95 text-center px-4">
          <span className="text-xs font-semibold text-slate-700">Location unavailable</span>
          <span className="text-[11px] text-slate-500">
            No country was reported for this IP, so no pin is plotted.
          </span>
        </div>
      )}
    </div>
  );
}

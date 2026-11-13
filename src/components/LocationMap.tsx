import { useEffect, useRef } from 'react';
import L from 'leaflet';

interface LocationMapProps {
  latitude: number | null;
  longitude: number | null;
  city: string;
  region: string;
  country: string;
  publicIp: string;
  timezone?: string;
}

const CITY_COORDINATES: Record<string, [number, number]> = {
  bengaluru: [12.9716, 77.5946],
  bangalore: [12.9716, 77.5946],
  mumbai: [19.076, 72.8777],
  delhi: [28.6139, 77.209],
  'new delhi': [28.6139, 77.209],
  hyderabad: [17.385, 78.4867],
  chennai: [13.0827, 80.2707],
  kolkata: [22.5726, 88.3639],
  pune: [18.5204, 73.8567],
  ahmedabad: [23.0225, 72.5714],
  singapore: [1.3521, 103.8198],
  london: [51.5072, -0.1276],
  'new york': [40.7128, -74.006],
  'san francisco': [37.7749, -122.4194],
  tokyo: [35.6762, 139.6503],
  sydney: [-33.8688, 151.2093],
};

const TIMEZONE_COORDINATES: Record<string, [number, number]> = {
  'Asia/Kolkata': [12.9716, 77.5946],
  'Asia/Calcutta': [12.9716, 77.5946],
  'Asia/Singapore': [1.3521, 103.8198],
  'Asia/Tokyo': [35.6762, 139.6503],
  'Europe/London': [51.5072, -0.1276],
  'America/New_York': [40.7128, -74.006],
  'America/Los_Angeles': [37.7749, -122.4194],
};

function resolveMapCoordinates(
  latitude: number | null,
  longitude: number | null,
  city: string,
  timezone?: string
): { lat: number; lng: number; zoom: number } {
  if (
    typeof latitude === 'number' &&
    typeof longitude === 'number' &&
    Number.isFinite(latitude) &&
    Number.isFinite(longitude)
  ) {
    return { lat: latitude, lng: longitude, zoom: 11 };
  }

  const normalizedCity = (city || '').trim().toLowerCase();
  if (normalizedCity && CITY_COORDINATES[normalizedCity]) {
    const [lat, lng] = CITY_COORDINATES[normalizedCity];
    return { lat, lng, zoom: 10 };
  }

  if (timezone && TIMEZONE_COORDINATES[timezone]) {
    const [lat, lng] = TIMEZONE_COORDINATES[timezone];
    return { lat, lng, zoom: 9 };
  }

  return { lat: 20.5937, lng: 78.9629, zoom: 4 };
}

export function LocationMap({
  latitude,
  longitude,
  city,
  region,
  country,
  publicIp,
  timezone,
}: LocationMapProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const markerRef = useRef<L.Marker | null>(null);

  const { lat, lng, zoom } = resolveMapCoordinates(latitude, longitude, city, timezone);

  const locationParts = [city, region, country].filter(
    (p) => p && p !== 'Unknown' && p !== 'Unavailable'
  );
  const labelText =
    locationParts.length > 0
      ? locationParts.filter((v, i) => i === 0 || v !== locationParts[i - 1]).join(', ')
      : 'Approximate Location';

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

      const pinIcon = L.divIcon({
        className: 'intel-leaflet-pin',
        html: `<div style="width:18px;height:18px;border-radius:9999px;background:#F05A28;border:3px solid #FFFFFF;box-shadow:0 2px 6px rgba(15,23,42,0.35);"></div>`,
        iconSize: [18, 18],
        iconAnchor: [9, 9],
      });

      const marker = L.marker([lat, lng], { icon: pinIcon }).addTo(map);
      marker.bindPopup(
        `<div style="font-family:sans-serif;font-size:12px;line-height:1.4;"><strong>${labelText}</strong><br/><span style="font-family:monospace;opacity:0.75;">IP: ${publicIp}</span></div>`
      );

      mapRef.current = map;
      markerRef.current = marker;

      setTimeout(() => {
        map.invalidateSize();
      }, 120);
    } else {
      mapRef.current.setView([lat, lng], zoom, { animate: true });
      if (markerRef.current) {
        markerRef.current.setLatLng([lat, lng]);
        markerRef.current.setPopupContent(
          `<div style="font-family:sans-serif;font-size:12px;line-height:1.4;"><strong>${labelText}</strong><br/><span style="font-family:monospace;opacity:0.75;">IP: ${publicIp}</span></div>`
        );
      }
    }
  }, [lat, lng, zoom, labelText, publicIp]);

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
    </div>
  );
}

// Honest phone-model resolution for genuine mobile visitors.
// - Input: the browser-reported device model captured by the genuine-mobile gate
//   (UA-CH `model`, or the Android UA Build token as a fallback).
// - Match rule: EXACT model-code lookup against the generated Google Play
//   catalog. No fuzzy matching, no screen-dimension inference — this module
//   never reads width/height/aspect ratio/devicePixelRatio.
// - Unmapped, empty, missing, or ambiguous model => null. The UI then shows the
//   brand/model it can prove, or nothing at all, instead of inventing a phone.
import type { DeviceSnapshot } from './deviceDetect';
import { detectDeviceLabel } from './deviceDetect';
import {
  lookupAndroidPhone,
  normalizeModelCode,
  type AndroidPhoneEntry,
} from '../data/androidPhoneModels';

/** Display name: marketing name when it already starts with the brand, else "Brand Model". */
export function formatPhoneLabel(entry: AndroidPhoneEntry): string {
  const brand = entry.retailBrand.trim();
  const marketing = entry.marketingName.trim();
  if (!brand || !marketing) return marketing || brand || entry.modelCode;
  if (marketing.toLowerCase().startsWith(brand.toLowerCase())) return marketing;
  return `${brand} ${marketing}`;
}

/** e.g. "OnePlus Nord CE 5 (CPH2661)" or "Samsung Galaxy S24 Ultra (SM-S928B)". */
export function formatPhoneDisplayLabel(entry: AndroidPhoneEntry): string {
  const label = formatPhoneLabel(entry);
  return entry.modelCode ? `${label} (${entry.modelCode})` : label;
}

/**
 * Exact, unambiguous resolution of a reported model code; null when unmapped/ambiguous.
 *
 * Only cosmetic UA decorations are stripped between attempts (Samsung Internet's
 * `SAMSUNG ` prefix, dual-SIM `/DS` suffix); every attempt is still an exact
 * catalog hit, so no guessing is introduced.
 */
export function resolvePhoneModel(reportedModel?: string): AndroidPhoneEntry | null {
  const base = normalizeModelCode(reportedModel ?? '');
  if (!base) return null;
  const variants = new Set<string>([base]);
  const decorated = base
    .replace(/^SAMSUNG[\s-]+/i, '')
    .replace(/\/DS$/i, '')
    .replace(/_DS$/i, '')
    .trim();
  if (decorated) variants.add(decorated);
  for (const candidate of variants) {
    const entry = lookupAndroidPhone(candidate);
    if (entry) return entry;
  }
  return null;
}

/**
 * Display label for the identity header.
 * mobile  → exact marketing name when the model maps unambiguously.
 * tablet/pc → the existing device label, completely unchanged.
 */
export function getPhoneDisplayLabel(info: DeviceSnapshot): string {
  if (info.kind !== 'mobile') return detectDeviceLabel(info);
  const entry = resolvePhoneModel(info.reportedModel);
  return entry ? formatPhoneDisplayLabel(entry) : 'Mobile device';
}

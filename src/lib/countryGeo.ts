/**
 * Country-accurate fallback map anchors.
 *
 * An IP geolocation result is only as trustworthy as the country it names, so a raw
 * latitude/longitude may never be plotted in a country the lookup did not report. This
 * module provides, for every ISO 3166-1 alpha-2 country that can appear in a GeoIP
 * `country_code` field, a centroid anchor plus an equivalent-circle bounding box derived
 * from the country's area. Callers can validate a coordinate against the reported country
 * and fall back to `countryAnchor()` when it does not fit.
 *
 * Data source: world-countries@5.0.0 (https://cdn.jsdelivr.net/npm/world-countries@5.0.0/countries.json).
 * Generated at build time from `cca2`, `name.common`, `latlng` and `area`; the literal below is
 * checked in so the module stays dependency-free, side-effect free and synchronous for both the
 * browser bundle and the Cloudflare Worker bundle.
 */

export interface CountryGeo {
  code: string;
  name: string;
  lat: number;
  lng: number;
  minLat: number;
  maxLat: number;
  minLng: number;
  maxLng: number;
  crossesAntimeridian: boolean;
}

/** Keyed by uppercase ISO 3166-1 alpha-2 code. */
export const COUNTRY_GEO: Record<string, CountryGeo> = {
  AD: { code: 'AD', name: 'Andorra', lat: 42.5, lng: 1.5, minLat: 42.15, maxLat: 42.85, minLng: 1.15, maxLng: 1.85, crossesAntimeridian: false },
  AE: { code: 'AE', name: 'United Arab Emirates', lat: 24, lng: 54, minLat: 22.5346, maxLat: 25.4654, minLng: 52.3959, maxLng: 55.6041, crossesAntimeridian: false },
  AF: { code: 'AF', name: 'Afghanistan', lat: 33, lng: 65, minLat: 28.9069, maxLat: 37.0931, minLng: 60.1195, maxLng: 69.8805, crossesAntimeridian: false },
  AG: { code: 'AG', name: 'Antigua and Barbuda', lat: 17.05, lng: -61.8, minLat: 16.7, maxLat: 17.4, minLng: -62.15, maxLng: -61.45, crossesAntimeridian: false },
  AI: { code: 'AI', name: 'Anguilla', lat: 18.25, lng: -63.1667, minLat: 17.9, maxLat: 18.6, minLng: -63.5167, maxLng: -62.8167, crossesAntimeridian: false },
  AL: { code: 'AL', name: 'Albania', lat: 41, lng: 20, minLat: 40.1407, maxLat: 41.8593, minLng: 18.8614, maxLng: 21.1386, crossesAntimeridian: false },
  AM: { code: 'AM', name: 'Armenia', lat: 40, lng: 45, minLat: 39.1259, maxLat: 40.8741, minLng: 43.859, maxLng: 46.141, crossesAntimeridian: false },
  AO: { code: 'AO', name: 'Angola', lat: -12.5, lng: 18.5, minLat: -18.1589, maxLat: -6.8411, minLng: 12.7037, maxLng: 24.2963, crossesAntimeridian: false },
  AQ: { code: 'AQ', name: 'Antarctica', lat: -90, lng: 0, minLat: -90, maxLat: -71.0366, minLng: -90, maxLng: 90, crossesAntimeridian: false },
  AR: { code: 'AR', name: 'Argentina', lat: -34, lng: -64, minLat: -42.4509, maxLat: -25.5491, minLng: -74.1937, maxLng: -53.8063, crossesAntimeridian: false },
  AS: { code: 'AS', name: 'American Samoa', lat: -14.3333, lng: -170, minLat: -14.6833, maxLat: -13.9833, minLng: -170.35, maxLng: -169.65, crossesAntimeridian: false },
  AT: { code: 'AT', name: 'Austria', lat: 47.3333, lng: 13.3333, minLat: 45.8656, maxLat: 48.8011, minLng: 11.1676, maxLng: 15.499, crossesAntimeridian: false },
  AU: { code: 'AU', name: 'Australia', lat: -27, lng: 133, minLat: -41.0563, maxLat: -12.9437, minLng: 117.2242, maxLng: 148.7758, crossesAntimeridian: false },
  AW: { code: 'AW', name: 'Aruba', lat: 12.5, lng: -69.9667, minLat: 12.15, maxLat: 12.85, minLng: -70.3167, maxLng: -69.6167, crossesAntimeridian: false },
  AX: { code: 'AX', name: 'Åland Islands', lat: 60.1167, lng: 19.9, minLat: 59.7667, maxLat: 60.4667, minLng: 19.4957, maxLng: 20.3043, crossesAntimeridian: false },
  AZ: { code: 'AZ', name: 'Azerbaijan', lat: 40.5, lng: 47.5, minLat: 39.0085, maxLat: 41.9915, minLng: 45.5386, maxLng: 49.4614, crossesAntimeridian: false },
  BA: { code: 'BA', name: 'Bosnia and Herzegovina', lat: 44, lng: 18, minLat: 42.8531, maxLat: 45.1469, minLng: 16.4056, maxLng: 19.5944, crossesAntimeridian: false },
  BB: { code: 'BB', name: 'Barbados', lat: 13.1667, lng: -59.5333, minLat: 12.8167, maxLat: 13.5167, minLng: -59.8833, maxLng: -59.1833, crossesAntimeridian: false },
  BD: { code: 'BD', name: 'Bangladesh', lat: 24, lng: 90, minLat: 22.0531, maxLat: 25.9469, minLng: 87.8688, maxLng: 92.1312, crossesAntimeridian: false },
  BE: { code: 'BE', name: 'Belgium', lat: 50.8333, lng: 4, minLat: 49.9478, maxLat: 51.7189, minLng: 2.5979, maxLng: 5.4021, crossesAntimeridian: false },
  BF: { code: 'BF', name: 'Burkina Faso', lat: 13, lng: -2, minLat: 10.3521, maxLat: 15.6479, minLng: -4.7176, maxLng: 0.7176, crossesAntimeridian: false },
  BG: { code: 'BG', name: 'Bulgaria', lat: 43, lng: 25, minLat: 41.3124, maxLat: 44.6876, minLng: 22.6925, maxLng: 27.3075, crossesAntimeridian: false },
  BH: { code: 'BH', name: 'Bahrain', lat: 26, lng: 50.55, minLat: 25.65, maxLat: 26.35, minLng: 50.2, maxLng: 50.9, crossesAntimeridian: false },
  BI: { code: 'BI', name: 'Burundi', lat: -3.5, lng: 30, minLat: -4.3456, maxLat: -2.6544, minLng: 29.1529, maxLng: 30.8471, crossesAntimeridian: false },
  BJ: { code: 'BJ', name: 'Benin', lat: 9.5, lng: 2.25, minLat: 7.7992, maxLat: 11.2008, minLng: 0.5255, maxLng: 3.9745, crossesAntimeridian: false },
  BL: { code: 'BL', name: 'Saint Barthélemy', lat: 18.5, lng: -63.4167, minLat: 18.15, maxLat: 18.85, minLng: -63.7667, maxLng: -63.0667, crossesAntimeridian: false },
  BM: { code: 'BM', name: 'Bermuda', lat: 32.3333, lng: -64.75, minLat: 31.9833, maxLat: 32.6833, minLng: -65.1, maxLng: -64.4, crossesAntimeridian: false },
  BN: { code: 'BN', name: 'Brunei', lat: 4.5, lng: 114.6667, minLat: 4.1152, maxLat: 4.8848, minLng: 114.2807, maxLng: 115.0527, crossesAntimeridian: false },
  BO: { code: 'BO', name: 'Bolivia', lat: -17, lng: -65, minLat: -22.3121, maxLat: -11.6879, minLng: -70.5548, maxLng: -59.4452, crossesAntimeridian: false },
  BQ: { code: 'BQ', name: 'Caribbean Netherlands', lat: 12.18, lng: -68.25, minLat: 11.83, maxLat: 12.53, minLng: -68.6, maxLng: -67.9, crossesAntimeridian: false },
  BR: { code: 'BR', name: 'Brazil', lat: -10, lng: -55, minLat: -24.7898, maxLat: 4.7898, minLng: -70.018, maxLng: -39.982, crossesAntimeridian: false },
  BS: { code: 'BS', name: 'Bahamas', lat: 24.25, lng: -76, minLat: 23.6515, maxLat: 24.8485, minLng: -76.6564, maxLng: -75.3436, crossesAntimeridian: false },
  BT: { code: 'BT', name: 'Bhutan', lat: 27.5, lng: 90.5, minLat: 26.5069, maxLat: 28.4931, minLng: 89.3804, maxLng: 91.6196, crossesAntimeridian: false },
  BV: { code: 'BV', name: 'Bouvet Island', lat: -54.4333, lng: 3.4, minLat: -54.7833, maxLat: -54.0833, minLng: 3.05, maxLng: 3.75, crossesAntimeridian: false },
  BW: { code: 'BW', name: 'Botswana', lat: -22, lng: 24, minLat: -25.8665, maxLat: -18.1335, minLng: 19.8299, maxLng: 28.1701, crossesAntimeridian: false },
  BY: { code: 'BY', name: 'Belarus', lat: 53, lng: 28, minLat: 50.6908, maxLat: 55.3092, minLng: 24.1629, maxLng: 31.8371, crossesAntimeridian: false },
  BZ: { code: 'BZ', name: 'Belize', lat: 17.25, lng: -88.75, minLat: 16.4819, maxLat: 18.0181, minLng: -89.5542, maxLng: -87.9458, crossesAntimeridian: false },
  CA: { code: 'CA', name: 'Canada', lat: 60, lng: -95, minLat: 43.9853, maxLat: 76.0147, minLng: -127.0294, maxLng: -62.9706, crossesAntimeridian: false },
  CC: { code: 'CC', name: 'Cocos (Keeling) Islands', lat: -12.5, lng: 96.8333, minLat: -12.85, maxLat: -12.15, minLng: 96.4833, maxLng: 97.1833, crossesAntimeridian: false },
  CD: { code: 'CD', name: 'DR Congo', lat: 0, lng: 25, minLat: -7.7609, maxLat: 7.7609, minLng: 17.2391, maxLng: 32.7609, crossesAntimeridian: false },
  CF: { code: 'CF', name: 'Central African Republic', lat: 7, lng: 21, minLat: 2.9997, maxLat: 11.0003, minLng: 16.9697, maxLng: 25.0303, crossesAntimeridian: false },
  CG: { code: 'CG', name: 'Republic of the Congo', lat: -1, lng: 15, minLat: -3.9639, maxLat: 1.9639, minLng: 12.0356, maxLng: 17.9644, crossesAntimeridian: false },
  CH: { code: 'CH', name: 'Switzerland', lat: 47, lng: 8, minLat: 45.9702, maxLat: 48.0298, minLng: 6.4901, maxLng: 9.5099, crossesAntimeridian: false },
  CI: { code: 'CI', name: 'Ivory Coast', lat: 8, lng: -5, minLat: 5.122, maxLat: 10.878, minLng: -7.9063, maxLng: -2.0937, crossesAntimeridian: false },
  CK: { code: 'CK', name: 'Cook Islands', lat: -21.2333, lng: -159.7667, minLat: -21.5833, maxLat: -20.8833, minLng: -160.1167, maxLng: -159.4167, crossesAntimeridian: false },
  CL: { code: 'CL', name: 'Chile', lat: -30, lng: -71, minLat: -34.407, maxLat: -25.593, minLng: -76.0888, maxLng: -65.9112, crossesAntimeridian: false },
  CM: { code: 'CM', name: 'Cameroon', lat: 6, lng: 12, minLat: 2.5054, maxLat: 9.4946, minLng: 8.4861, maxLng: 15.5139, crossesAntimeridian: false },
  CN: { code: 'CN', name: 'China', lat: 35, lng: 105, minLat: 19.2096, maxLat: 50.7904, minLng: 85.7235, maxLng: 124.2765, crossesAntimeridian: false },
  CO: { code: 'CO', name: 'Colombia', lat: 4, lng: -72, minLat: -1.4155, maxLat: 9.4155, minLng: -77.4287, maxLng: -66.5713, crossesAntimeridian: false },
  CR: { code: 'CR', name: 'Costa Rica', lat: 10, lng: -84, minLat: 8.8543, maxLat: 11.1457, minLng: -85.1634, maxLng: -82.8366, crossesAntimeridian: false },
  CU: { code: 'CU', name: 'Cuba', lat: 21.5, lng: -80, minLat: 19.82, maxLat: 23.18, minLng: -81.8057, maxLng: -78.1943, crossesAntimeridian: false },
  CV: { code: 'CV', name: 'Cape Verde', lat: 16, lng: -24, minLat: 15.65, maxLat: 16.35, minLng: -24.35, maxLng: -23.65, crossesAntimeridian: false },
  CW: { code: 'CW', name: 'Curaçao', lat: 12.1167, lng: -68.9333, minLat: 11.7667, maxLat: 12.4667, minLng: -69.2833, maxLng: -68.5833, crossesAntimeridian: false },
  CX: { code: 'CX', name: 'Christmas Island', lat: -10.5, lng: 105.6667, minLat: -10.85, maxLat: -10.15, minLng: 105.3167, maxLng: 106.0167, crossesAntimeridian: false },
  CY: { code: 'CY', name: 'Cyprus', lat: 35, lng: 33, minLat: 34.5125, maxLat: 35.4875, minLng: 32.4049, maxLng: 33.5951, crossesAntimeridian: false },
  CZ: { code: 'CZ', name: 'Czechia', lat: 49.75, lng: 15.5, minLat: 48.3267, maxLat: 51.1733, minLng: 13.2972, maxLng: 17.7028, crossesAntimeridian: false },
  DE: { code: 'DE', name: 'Germany', lat: 51, lng: 9, minLat: 47.9713, maxLat: 54.0287, minLng: 4.1874, maxLng: 13.8126, crossesAntimeridian: false },
  DJ: { code: 'DJ', name: 'Djibouti', lat: 11.5, lng: 43, minLat: 10.728, maxLat: 12.272, minLng: 42.2122, maxLng: 43.7878, crossesAntimeridian: false },
  DK: { code: 'DK', name: 'Denmark', lat: 56, lng: 10, minLat: 54.9479, maxLat: 57.0521, minLng: 8.1185, maxLng: 11.8815, crossesAntimeridian: false },
  DM: { code: 'DM', name: 'Dominica', lat: 15.4167, lng: -61.3333, minLat: 15.0667, maxLat: 15.7667, minLng: -61.6833, maxLng: -60.9833, crossesAntimeridian: false },
  DO: { code: 'DO', name: 'Dominican Republic', lat: 19, lng: -70.6667, minLat: 17.8819, maxLat: 20.1181, minLng: -71.8492, maxLng: -69.4841, crossesAntimeridian: false },
  DZ: { code: 'DZ', name: 'Algeria', lat: 28, lng: 3, minLat: 20.1783, maxLat: 35.8217, minLng: -5.8586, maxLng: 11.8586, crossesAntimeridian: false },
  EC: { code: 'EC', name: 'Ecuador', lat: -2, lng: -77.5, minLat: -4.6667, maxLat: 0.6667, minLng: -80.1683, maxLng: -74.8317, crossesAntimeridian: false },
  EE: { code: 'EE', name: 'Estonia', lat: 59, lng: 26, minLat: 57.9222, maxLat: 60.0778, minLng: 23.9073, maxLng: 28.0927, crossesAntimeridian: false },
  EG: { code: 'EG', name: 'Egypt', lat: 27, lng: 30, minLat: 21.9256, maxLat: 32.0744, minLng: 24.3049, maxLng: 35.6951, crossesAntimeridian: false },
  EH: { code: 'EH', name: 'Western Sahara', lat: 24.5, lng: -13, minLat: 21.8861, maxLat: 27.1139, minLng: -15.8726, maxLng: -10.1274, crossesAntimeridian: false },
  ER: { code: 'ER', name: 'Eritrea', lat: 15, lng: 39, minLat: 13.262, maxLat: 16.738, minLng: 37.2007, maxLng: 40.7993, crossesAntimeridian: false },
  ES: { code: 'ES', name: 'Spain', lat: 40, lng: -4, minLat: 36.3948, maxLat: 43.6052, minLng: -8.7062, maxLng: 0.7062, crossesAntimeridian: false },
  ET: { code: 'ET', name: 'Ethiopia', lat: 8, lng: 38, minLat: 2.6741, maxLat: 13.3259, minLng: 32.6217, maxLng: 43.3783, crossesAntimeridian: false },
  FI: { code: 'FI', name: 'Finland', lat: 64, lng: 26, minLat: 61.0516, maxLat: 66.9484, minLng: 19.2743, maxLng: 32.7257, crossesAntimeridian: false },
  FJ: { code: 'FJ', name: 'Fiji', lat: -18, lng: 175, minLat: -18.6851, maxLat: -17.3149, minLng: 174.2797, maxLng: 175.7203, crossesAntimeridian: true },
  FK: { code: 'FK', name: 'Falkland Islands', lat: -51.75, lng: -59, minLat: -52.3092, maxLat: -51.1908, minLng: -59.9032, maxLng: -58.0968, crossesAntimeridian: false },
  FM: { code: 'FM', name: 'Micronesia', lat: 6.9167, lng: 158.25, minLat: 6.5667, maxLat: 7.2667, minLng: 157.9, maxLng: 158.6, crossesAntimeridian: false },
  FO: { code: 'FO', name: 'Faroe Islands', lat: 62, lng: -7, minLat: 61.65, maxLat: 62.35, minLng: -7.4029, maxLng: -6.5971, crossesAntimeridian: false },
  FR: { code: 'FR', name: 'France', lat: 46, lng: 2, minLat: 42.2356, maxLat: 49.7644, minLng: -3.4191, maxLng: 7.4191, crossesAntimeridian: false },
  GA: { code: 'GA', name: 'Gabon', lat: -1, lng: 11.75, minLat: -3.6221, maxLat: 1.6221, minLng: 9.1275, maxLng: 14.3725, crossesAntimeridian: false },
  GB: { code: 'GB', name: 'United Kingdom', lat: 54, lng: -2, minLat: 51.5022, maxLat: 56.4978, minLng: -6.2496, maxLng: 2.2496, crossesAntimeridian: false },
  GD: { code: 'GD', name: 'Grenada', lat: 12.1167, lng: -61.6667, minLat: 11.7667, maxLat: 12.4667, minLng: -62.0167, maxLng: -61.3167, crossesAntimeridian: false },
  GE: { code: 'GE', name: 'Georgia', lat: 42, lng: 43.5, minLat: 40.662, maxLat: 43.338, minLng: 41.6995, maxLng: 45.3005, crossesAntimeridian: false },
  GF: { code: 'GF', name: 'French Guiana', lat: 4, lng: -53, minLat: 2.5352, maxLat: 5.4648, minLng: -54.4684, maxLng: -51.5316, crossesAntimeridian: false },
  GG: { code: 'GG', name: 'Guernsey', lat: 49.4667, lng: -2.5833, minLat: 49.1167, maxLat: 49.8167, minLng: -2.9333, maxLng: -2.2333, crossesAntimeridian: false },
  GH: { code: 'GH', name: 'Ghana', lat: 8, lng: -2, minLat: 5.5247, maxLat: 10.4753, minLng: -4.4996, maxLng: 0.4996, crossesAntimeridian: false },
  GI: { code: 'GI', name: 'Gibraltar', lat: 36.1333, lng: -5.35, minLat: 35.7833, maxLat: 36.4833, minLng: -5.7, maxLng: -5, crossesAntimeridian: false },
  GL: { code: 'GL', name: 'Greenland', lat: 72, lng: -40, minLat: 64.5408, maxLat: 79.4592, minLng: -64.1383, maxLng: -15.8617, crossesAntimeridian: false },
  GM: { code: 'GM', name: 'Gambia', lat: 13.4667, lng: -16.5667, minLat: 12.9427, maxLat: 13.9907, minLng: -17.1055, maxLng: -16.0279, crossesAntimeridian: false },
  GN: { code: 'GN', name: 'Guinea', lat: 11, lng: -10, minLat: 8.487, maxLat: 13.513, minLng: -12.56, maxLng: -7.44, crossesAntimeridian: false },
  GP: { code: 'GP', name: 'Guadeloupe', lat: 16.25, lng: -61.5833, minLat: 15.9, maxLat: 16.6, minLng: -61.9333, maxLng: -61.2333, crossesAntimeridian: false },
  GQ: { code: 'GQ', name: 'Equatorial Guinea', lat: 2, lng: 10, minLat: 1.1512, maxLat: 2.8488, minLng: 9.1506, maxLng: 10.8494, crossesAntimeridian: false },
  GR: { code: 'GR', name: 'Greece', lat: 39, lng: 22, minLat: 37.1587, maxLat: 40.8413, minLng: 19.6307, maxLng: 24.3693, crossesAntimeridian: false },
  GS: { code: 'GS', name: 'South Georgia', lat: -54.5, lng: -37, minLat: -54.85, maxLat: -54.15, minLng: -37.5453, maxLng: -36.4547, crossesAntimeridian: false },
  GT: { code: 'GT', name: 'Guatemala', lat: 15.5, lng: -90.25, minLat: 13.8276, maxLat: 17.1724, minLng: -91.9855, maxLng: -88.5145, crossesAntimeridian: false },
  GU: { code: 'GU', name: 'Guam', lat: 13.4667, lng: 144.7833, minLat: 13.1167, maxLat: 13.8167, minLng: 144.4333, maxLng: 145.1333, crossesAntimeridian: false },
  GW: { code: 'GW', name: 'Guinea-Bissau', lat: 12, lng: -15, minLat: 11.0367, maxLat: 12.9633, minLng: -15.9848, maxLng: -14.0152, crossesAntimeridian: false },
  GY: { code: 'GY', name: 'Guyana', lat: 5, lng: -59, minLat: 2.6502, maxLat: 7.3498, minLng: -61.3588, maxLng: -56.6412, crossesAntimeridian: false },
  HK: { code: 'HK', name: 'Hong Kong', lat: 22.267, lng: 114.188, minLat: 21.917, maxLat: 22.617, minLng: 113.838, maxLng: 114.538, crossesAntimeridian: false },
  HM: { code: 'HM', name: 'Heard Island and McDonald Islands', lat: -53.1, lng: 72.5167, minLat: -53.45, maxLat: -52.75, minLng: 72.1667, maxLng: 72.8667, crossesAntimeridian: false },
  HN: { code: 'HN', name: 'Honduras', lat: 15, lng: -86.5, minLat: 13.3001, maxLat: 16.6999, minLng: -88.2598, maxLng: -84.7402, crossesAntimeridian: false },
  HR: { code: 'HR', name: 'Croatia', lat: 45.1667, lng: 15.5, minLat: 43.961, maxLat: 46.3724, minLng: 13.7899, maxLng: 17.2101, crossesAntimeridian: false },
  HT: { code: 'HT', name: 'Haiti', lat: 19, lng: -72.4167, minLat: 18.1557, maxLat: 19.8443, minLng: -73.3096, maxLng: -71.5237, crossesAntimeridian: false },
  HU: { code: 'HU', name: 'Hungary', lat: 47, lng: 20, minLat: 45.4542, maxLat: 48.5458, minLng: 17.7334, maxLng: 22.2666, crossesAntimeridian: false },
  ID: { code: 'ID', name: 'Indonesia', lat: -5, lng: 120, minLat: -11.9944, maxLat: 1.9944, minLng: 112.9789, maxLng: 127.0211, crossesAntimeridian: false },
  IE: { code: 'IE', name: 'Ireland', lat: 53, lng: -8, minLat: 51.6565, maxLat: 54.3435, minLng: -10.2325, maxLng: -5.7675, crossesAntimeridian: false },
  IL: { code: 'IL', name: 'Israel', lat: 31.47, lng: 35.13, minLat: 30.7396, maxLat: 32.2004, minLng: 34.2736, maxLng: 35.9864, crossesAntimeridian: false },
  IM: { code: 'IM', name: 'Isle of Man', lat: 54.25, lng: -4.5, minLat: 53.9, maxLat: 54.6, minLng: -4.85, maxLng: -4.15, crossesAntimeridian: false },
  IN: { code: 'IN', name: 'India', lat: 20, lng: 77, minLat: 10.8105, maxLat: 29.1895, minLng: 67.2208, maxLng: 86.7792, crossesAntimeridian: false },
  IO: { code: 'IO', name: 'British Indian Ocean Territory', lat: -6, lng: 71.5, minLat: -6.35, maxLat: -5.65, minLng: 71.15, maxLng: 71.85, crossesAntimeridian: false },
  IQ: { code: 'IQ', name: 'Iraq', lat: 33, lng: 44, minLat: 29.6446, maxLat: 36.3554, minLng: 39.9991, maxLng: 48.0009, crossesAntimeridian: false },
  IR: { code: 'IR', name: 'Iran', lat: 32, lng: 53, minLat: 25.4934, maxLat: 38.5066, minLng: 45.3275, maxLng: 60.6725, crossesAntimeridian: false },
  IS: { code: 'IS', name: 'Iceland', lat: 65, lng: -18, minLat: 63.3734, maxLat: 66.6266, minLng: -21.8488, maxLng: -14.1512, crossesAntimeridian: false },
  IT: { code: 'IT', name: 'Italy', lat: 42.8333, lng: 12.8333, minLat: 40.0512, maxLat: 45.6155, minLng: 9.0395, maxLng: 16.6271, crossesAntimeridian: false },
  JE: { code: 'JE', name: 'Jersey', lat: 49.25, lng: -2.1667, minLat: 48.9, maxLat: 49.6, minLng: -2.5167, maxLng: -1.8167, crossesAntimeridian: false },
  JM: { code: 'JM', name: 'Jamaica', lat: 18.25, lng: -77.5, minLat: 17.7187, maxLat: 18.7813, minLng: -78.0595, maxLng: -76.9405, crossesAntimeridian: false },
  JO: { code: 'JO', name: 'Jordan', lat: 31, lng: 36, minLat: 29.4851, maxLat: 32.5149, minLng: 34.2327, maxLng: 37.7673, crossesAntimeridian: false },
  JP: { code: 'JP', name: 'Japan', lat: 36, lng: 138, minLat: 32.8843, maxLat: 39.1157, minLng: 134.1488, maxLng: 141.8512, crossesAntimeridian: false },
  KE: { code: 'KE', name: 'Kenya', lat: 1, lng: 38, minLat: -2.861, maxLat: 4.861, minLng: 34.1384, maxLng: 41.8616, crossesAntimeridian: false },
  KG: { code: 'KG', name: 'Kyrgyzstan', lat: 41, lng: 75, minLat: 38.7337, maxLat: 43.2663, minLng: 71.9971, maxLng: 78.0029, crossesAntimeridian: false },
  KH: { code: 'KH', name: 'Cambodia', lat: 13, lng: 105, minLat: 10.8436, maxLat: 15.1564, minLng: 102.7869, maxLng: 107.2131, crossesAntimeridian: false },
  KI: { code: 'KI', name: 'Kiribati', lat: 1.4167, lng: 173, minLat: 1.0667, maxLat: 1.7667, minLng: 172.65, maxLng: 173.35, crossesAntimeridian: true },
  KM: { code: 'KM', name: 'Comoros', lat: -12.1667, lng: 44.25, minLat: -12.5167, maxLat: -11.8167, minLng: 43.9, maxLng: 44.6, crossesAntimeridian: false },
  KN: { code: 'KN', name: 'Saint Kitts and Nevis', lat: 17.3333, lng: -62.75, minLat: 16.9833, maxLat: 17.6833, minLng: -63.1, maxLng: -62.4, crossesAntimeridian: false },
  KP: { code: 'KP', name: 'North Korea', lat: 40, lng: 127, minLat: 38.2404, maxLat: 41.7596, minLng: 124.703, maxLng: 129.297, crossesAntimeridian: false },
  KR: { code: 'KR', name: 'South Korea', lat: 37, lng: 127.5, minLat: 35.3956, maxLat: 38.6044, minLng: 125.4911, maxLng: 129.5089, crossesAntimeridian: false },
  KW: { code: 'KW', name: 'Kuwait', lat: 29.5, lng: 45.75, minLat: 28.8235, maxLat: 30.1765, minLng: 44.9727, maxLng: 46.5273, crossesAntimeridian: false },
  KY: { code: 'KY', name: 'Cayman Islands', lat: 19.5, lng: -80.5, minLat: 19.15, maxLat: 19.85, minLng: -80.85, maxLng: -80.15, crossesAntimeridian: false },
  KZ: { code: 'KZ', name: 'Kazakhstan', lat: 48, lng: 68, minLat: 39.6338, maxLat: 56.3662, minLng: 55.4969, maxLng: 80.5031, crossesAntimeridian: false },
  LA: { code: 'LA', name: 'Laos', lat: 18, lng: 105, minLat: 15.5337, maxLat: 20.4663, minLng: 102.4068, maxLng: 107.5932, crossesAntimeridian: false },
  LB: { code: 'LB', name: 'Lebanon', lat: 33.8333, lng: 35.8333, minLat: 33.3152, maxLat: 34.3515, minLng: 35.2096, maxLng: 36.4571, crossesAntimeridian: false },
  LC: { code: 'LC', name: 'Saint Lucia', lat: 13.8833, lng: -60.9667, minLat: 13.5333, maxLat: 14.2333, minLng: -61.3167, maxLng: -60.6167, crossesAntimeridian: false },
  LI: { code: 'LI', name: 'Liechtenstein', lat: 47.2667, lng: 9.5333, minLat: 46.9167, maxLat: 47.6167, minLng: 9.1833, maxLng: 9.8833, crossesAntimeridian: false },
  LK: { code: 'LK', name: 'Sri Lanka', lat: 7, lng: 81, minLat: 5.7018, maxLat: 8.2982, minLng: 79.6921, maxLng: 82.3079, crossesAntimeridian: false },
  LR: { code: 'LR', name: 'Liberia', lat: 6.5, lng: -9.5, minLat: 4.8086, maxLat: 8.1914, minLng: -11.2023, maxLng: -7.7977, crossesAntimeridian: false },
  LS: { code: 'LS', name: 'Lesotho', lat: -29.5, lng: 28.5, minLat: -30.383, maxLat: -28.617, minLng: 27.4855, maxLng: 29.5145, crossesAntimeridian: false },
  LT: { code: 'LT', name: 'Lithuania', lat: 56, lng: 24, minLat: 54.7049, maxLat: 57.2951, minLng: 21.684, maxLng: 26.316, crossesAntimeridian: false },
  LU: { code: 'LU', name: 'Luxembourg', lat: 49.75, lng: 6.1667, minLat: 49.4, maxLat: 50.1, minLng: 5.7678, maxLng: 6.5656, crossesAntimeridian: false },
  LV: { code: 'LV', name: 'Latvia', lat: 57, lng: 25, minLat: 55.7123, maxLat: 58.2877, minLng: 22.6356, maxLng: 27.3644, crossesAntimeridian: false },
  LY: { code: 'LY', name: 'Libya', lat: 25, lng: 17, minLat: 18.2772, maxLat: 31.7228, minLng: 9.5822, maxLng: 24.4178, crossesAntimeridian: false },
  MA: { code: 'MA', name: 'Morocco', lat: 32, lng: -5, minLat: 28.6132, maxLat: 35.3868, minLng: -8.9936, maxLng: -1.0064, crossesAntimeridian: false },
  MC: { code: 'MC', name: 'Monaco', lat: 43.7333, lng: 7.4, minLat: 43.3833, maxLat: 44.0833, minLng: 7.05, maxLng: 7.75, crossesAntimeridian: false },
  MD: { code: 'MD', name: 'Moldova', lat: 47, lng: 29, minLat: 46.0676, maxLat: 47.9324, minLng: 27.6328, maxLng: 30.3672, crossesAntimeridian: false },
  ME: { code: 'ME', name: 'Montenegro', lat: 42.5, lng: 19.3, minLat: 41.9044, maxLat: 43.0956, minLng: 18.4921, maxLng: 20.1079, crossesAntimeridian: false },
  MF: { code: 'MF', name: 'Saint Martin', lat: 18.0833, lng: -63.95, minLat: 17.7333, maxLat: 18.4333, minLng: -64.3, maxLng: -63.6, crossesAntimeridian: false },
  MG: { code: 'MG', name: 'Madagascar', lat: -20, lng: 47, minLat: -23.8832, maxLat: -16.1168, minLng: 42.8676, maxLng: 51.1324, crossesAntimeridian: false },
  MH: { code: 'MH', name: 'Marshall Islands', lat: 9, lng: 168, minLat: 8.65, maxLat: 9.35, minLng: 167.65, maxLng: 168.35, crossesAntimeridian: false },
  MK: { code: 'MK', name: 'North Macedonia', lat: 41.8333, lng: 22, minLat: 41.0206, maxLat: 42.646, minLng: 20.9093, maxLng: 23.0907, crossesAntimeridian: false },
  ML: { code: 'ML', name: 'Mali', lat: 17, lng: -4, minLat: 11.3559, maxLat: 22.6441, minLng: -9.902, maxLng: 1.902, crossesAntimeridian: false },
  MM: { code: 'MM', name: 'Myanmar', lat: 22, lng: 98, minLat: 17.8312, maxLat: 26.1688, minLng: 93.5038, maxLng: 102.4962, crossesAntimeridian: false },
  MN: { code: 'MN', name: 'Mongolia', lat: 46, lng: 105, minLat: 39.6615, maxLat: 52.3385, minLng: 95.8754, maxLng: 114.1246, crossesAntimeridian: false },
  MO: { code: 'MO', name: 'Macau', lat: 22.1667, lng: 113.55, minLat: 21.8167, maxLat: 22.5167, minLng: 113.2, maxLng: 113.9, crossesAntimeridian: false },
  MP: { code: 'MP', name: 'Northern Mariana Islands', lat: 15.2, lng: 145.75, minLat: 14.85, maxLat: 15.55, minLng: 145.4, maxLng: 146.1, crossesAntimeridian: false },
  MQ: { code: 'MQ', name: 'Martinique', lat: 14.6667, lng: -61, minLat: 14.3167, maxLat: 15.0167, minLng: -61.35, maxLng: -60.65, crossesAntimeridian: false },
  MR: { code: 'MR', name: 'Mauritania', lat: 20, lng: -12, minLat: 14.8546, maxLat: 25.1454, minLng: -17.4756, maxLng: -6.5244, crossesAntimeridian: false },
  MS: { code: 'MS', name: 'Montserrat', lat: 16.75, lng: -62.2, minLat: 16.4, maxLat: 17.1, minLng: -62.55, maxLng: -61.85, crossesAntimeridian: false },
  MT: { code: 'MT', name: 'Malta', lat: 35.8333, lng: 14.5833, minLat: 35.4833, maxLat: 36.1833, minLng: 14.2333, maxLng: 14.9333, crossesAntimeridian: false },
  MU: { code: 'MU', name: 'Mauritius', lat: -20.2833, lng: 57.55, minLat: -20.6333, maxLat: -19.9333, minLng: 57.2, maxLng: 57.9, crossesAntimeridian: false },
  MV: { code: 'MV', name: 'Maldives', lat: 3.25, lng: 73, minLat: 2.9, maxLat: 3.6, minLng: 72.65, maxLng: 73.35, crossesAntimeridian: false },
  MW: { code: 'MW', name: 'Malawi', lat: -13.5, lng: 34, minLat: -15.2445, maxLat: -11.7555, minLng: 32.2059, maxLng: 35.7941, crossesAntimeridian: false },
  MX: { code: 'MX', name: 'Mexico', lat: 23, lng: -102, minLat: 15.8966, maxLat: 30.1034, minLng: -109.7168, maxLng: -94.2832, crossesAntimeridian: false },
  MY: { code: 'MY', name: 'Malaysia', lat: 2.5, lng: 112.5, minLat: -0.415, maxLat: 5.415, minLng: 109.5822, maxLng: 115.4178, crossesAntimeridian: false },
  MZ: { code: 'MZ', name: 'Mozambique', lat: -18.25, lng: 35, minLat: -22.7876, maxLat: -13.7124, minLng: 30.222, maxLng: 39.778, crossesAntimeridian: false },
  NA: { code: 'NA', name: 'Namibia', lat: -22, lng: 17, minLat: -26.6051, maxLat: -17.3949, minLng: 12.0332, maxLng: 21.9668, crossesAntimeridian: false },
  NC: { code: 'NC', name: 'New Caledonia', lat: -21.5, lng: 165.5, minLat: -22.1907, maxLat: -20.8093, minLng: 164.7576, maxLng: 166.2424, crossesAntimeridian: false },
  NE: { code: 'NE', name: 'Niger', lat: 16, lng: 8, minLat: 10.2952, maxLat: 21.7048, minLng: 2.0653, maxLng: 13.9347, crossesAntimeridian: false },
  NF: { code: 'NF', name: 'Norfolk Island', lat: -29.0333, lng: 167.95, minLat: -29.3833, maxLat: -28.6833, minLng: 167.6, maxLng: 168.3, crossesAntimeridian: false },
  NG: { code: 'NG', name: 'Nigeria', lat: 10, lng: 8, minLat: 5.1288, maxLat: 14.8712, minLng: 3.0537, maxLng: 12.9463, crossesAntimeridian: false },
  NI: { code: 'NI', name: 'Nicaragua', lat: 13, lng: -85, minLat: 11.17, maxLat: 14.83, minLng: -86.8781, maxLng: -83.1219, crossesAntimeridian: false },
  NL: { code: 'NL', name: 'Netherlands', lat: 52.5, lng: 5.75, minLat: 51.4632, maxLat: 53.5368, minLng: 4.0469, maxLng: 7.4531, crossesAntimeridian: false },
  NO: { code: 'NO', name: 'Norway', lat: 62, lng: 10, minLat: 59.116, maxLat: 64.884, minLng: 3.857, maxLng: 16.143, crossesAntimeridian: false },
  NP: { code: 'NP', name: 'Nepal', lat: 28, lng: 84, minLat: 26.0556, maxLat: 29.9444, minLng: 81.7979, maxLng: 86.2021, crossesAntimeridian: false },
  NR: { code: 'NR', name: 'Nauru', lat: -0.5333, lng: 166.9167, minLat: -0.8833, maxLat: -0.1833, minLng: 166.5667, maxLng: 167.2667, crossesAntimeridian: false },
  NU: { code: 'NU', name: 'Niue', lat: -19.0333, lng: -169.8667, minLat: -19.3833, maxLat: -18.6833, minLng: -170.2167, maxLng: -169.5167, crossesAntimeridian: false },
  NZ: { code: 'NZ', name: 'New Zealand', lat: -41, lng: 174, minLat: -43.6358, maxLat: -38.3642, minLng: 170.5076, maxLng: 177.4924, crossesAntimeridian: true },
  OM: { code: 'OM', name: 'Oman', lat: 21, lng: 57, minLat: 18.1804, maxLat: 23.8196, minLng: 53.9798, maxLng: 60.0202, crossesAntimeridian: false },
  PA: { code: 'PA', name: 'Panama', lat: 9, lng: -80, minLat: 7.6082, maxLat: 10.3918, minLng: -81.4092, maxLng: -78.5908, crossesAntimeridian: false },
  PE: { code: 'PE', name: 'Peru', lat: -10, lng: -76, minLat: -15.7457, maxLat: -4.2543, minLng: -81.8343, maxLng: -70.1657, crossesAntimeridian: false },
  PF: { code: 'PF', name: 'French Polynesia', lat: -15, lng: -140, minLat: -15.35, maxLat: -14.65, minLng: -140.35, maxLng: -139.65, crossesAntimeridian: true },
  PG: { code: 'PG', name: 'Papua New Guinea', lat: -6, lng: 147, minLat: -9.448, maxLat: -2.552, minLng: 143.533, maxLng: 150.467, crossesAntimeridian: false },
  PH: { code: 'PH', name: 'Philippines', lat: 13, lng: 122, minLat: 10.0346, maxLat: 15.9654, minLng: 118.9566, maxLng: 125.0434, crossesAntimeridian: false },
  PK: { code: 'PK', name: 'Pakistan', lat: 30, lng: 70, minLat: 25.2405, maxLat: 34.7595, minLng: 64.5042, maxLng: 75.4958, crossesAntimeridian: false },
  PL: { code: 'PL', name: 'Poland', lat: 52, lng: 20, minLat: 49.166, maxLat: 54.834, minLng: 15.3968, maxLng: 24.6032, crossesAntimeridian: false },
  PM: { code: 'PM', name: 'Saint Pierre and Miquelon', lat: 46.8333, lng: -56.3333, minLat: 46.4833, maxLat: 47.1833, minLng: -56.6833, maxLng: -55.9833, crossesAntimeridian: false },
  PN: { code: 'PN', name: 'Pitcairn Islands', lat: -25.0667, lng: -130.1, minLat: -25.4167, maxLat: -24.7167, minLng: -130.45, maxLng: -129.75, crossesAntimeridian: false },
  PR: { code: 'PR', name: 'Puerto Rico', lat: 18.25, lng: -66.5, minLat: 17.7727, maxLat: 18.7273, minLng: -67.0026, maxLng: -65.9974, crossesAntimeridian: false },
  PS: { code: 'PS', name: 'Palestine', lat: 31.9, lng: 35.2, minLat: 31.5003, maxLat: 32.2997, minLng: 34.7292, maxLng: 35.6708, crossesAntimeridian: false },
  PT: { code: 'PT', name: 'Portugal', lat: 39.5, lng: -8, minLat: 37.962, maxLat: 41.038, minLng: -9.9932, maxLng: -6.0068, crossesAntimeridian: false },
  PW: { code: 'PW', name: 'Palau', lat: 7.5, lng: 134.5, minLat: 7.15, maxLat: 7.85, minLng: 134.15, maxLng: 134.85, crossesAntimeridian: false },
  PY: { code: 'PY', name: 'Paraguay', lat: -23, lng: -58, minLat: -26.2323, maxLat: -19.7677, minLng: -61.5115, maxLng: -54.4885, crossesAntimeridian: false },
  QA: { code: 'QA', name: 'Qatar', lat: 25.5, lng: 51.25, minLat: 24.9545, maxLat: 26.0455, minLng: 50.6456, maxLng: 51.8544, crossesAntimeridian: false },
  RE: { code: 'RE', name: 'Réunion', lat: -21.15, lng: 55.5, minLat: -21.5, maxLat: -20.8, minLng: 55.15, maxLng: 55.85, crossesAntimeridian: false },
  RO: { code: 'RO', name: 'Romania', lat: 46, lng: 25, minLat: 43.5254, maxLat: 48.4746, minLng: 21.4377, maxLng: 28.5623, crossesAntimeridian: false },
  RS: { code: 'RS', name: 'Serbia', lat: 44, lng: 21, minLat: 42.4935, maxLat: 45.5065, minLng: 18.9057, maxLng: 23.0943, crossesAntimeridian: false },
  RU: { code: 'RU', name: 'Russia', lat: 60, lng: 100, minLat: 39.0431, maxLat: 80.9569, minLng: 58.0861, maxLng: 141.9139, crossesAntimeridian: true },
  RW: { code: 'RW', name: 'Rwanda', lat: -2, lng: 30, minLat: -2.8225, maxLat: -1.1775, minLng: 29.177, maxLng: 30.823, crossesAntimeridian: false },
  SA: { code: 'SA', name: 'Saudi Arabia', lat: 25, lng: 45, minLat: 17.5691, maxLat: 32.4309, minLng: 36.8009, maxLng: 53.1991, crossesAntimeridian: false },
  SB: { code: 'SB', name: 'Solomon Islands', lat: -8, lng: 159, minLat: -8.8615, maxLat: -7.1385, minLng: 158.13, maxLng: 159.87, crossesAntimeridian: false },
  SC: { code: 'SC', name: 'Seychelles', lat: -4.5833, lng: 55.6667, minLat: -4.9333, maxLat: -4.2333, minLng: 55.3167, maxLng: 56.0167, crossesAntimeridian: false },
  SD: { code: 'SD', name: 'Sudan', lat: 15, lng: 30, minLat: 8.0397, maxLat: 21.9603, minLng: 22.7941, maxLng: 37.2059, crossesAntimeridian: false },
  SE: { code: 'SE', name: 'Sweden', lat: 62, lng: 15, minLat: 58.599, maxLat: 65.401, minLng: 7.7558, maxLng: 22.2442, crossesAntimeridian: false },
  SG: { code: 'SG', name: 'Singapore', lat: 1.3667, lng: 103.8, minLat: 1.0167, maxLat: 1.7167, minLng: 103.45, maxLng: 104.15, crossesAntimeridian: false },
  SH: { code: 'SH', name: 'Saint Helena, Ascension and Tristan da Cunha', lat: -15.95, lng: -5.72, minLat: -16.3, maxLat: -15.6, minLng: -6.07, maxLng: -5.37, crossesAntimeridian: false },
  SI: { code: 'SI', name: 'Slovenia', lat: 46.1167, lng: 14.8167, minLat: 45.395, maxLat: 46.8383, minLng: 13.7757, maxLng: 15.8577, crossesAntimeridian: false },
  SJ: { code: 'SJ', name: 'Svalbard and Jan Mayen', lat: 78, lng: 20, minLat: 77.65, maxLat: 78.35, minLng: 19.65, maxLng: 20.35, crossesAntimeridian: false },
  SK: { code: 'SK', name: 'Slovakia', lat: 48.6667, lng: 19.5, minLat: 47.5444, maxLat: 49.789, minLng: 17.8007, maxLng: 21.1993, crossesAntimeridian: false },
  SL: { code: 'SL', name: 'Sierra Leone', lat: 8.5, lng: -11.5, minLat: 7.1425, maxLat: 9.8575, minLng: -12.8726, maxLng: -10.1274, crossesAntimeridian: false },
  SM: { code: 'SM', name: 'San Marino', lat: 43.7667, lng: 12.4167, minLat: 43.4167, maxLat: 44.1167, minLng: 12.0667, maxLng: 12.7667, crossesAntimeridian: false },
  SN: { code: 'SN', name: 'Senegal', lat: 14, lng: -14, minLat: 11.7521, maxLat: 16.2479, minLng: -16.3167, maxLng: -11.6833, crossesAntimeridian: false },
  SO: { code: 'SO', name: 'Somalia', lat: 10, lng: 49, minLat: 5.9529, maxLat: 14.0471, minLng: 44.8905, maxLng: 53.1095, crossesAntimeridian: false },
  SR: { code: 'SR', name: 'Suriname', lat: 4, lng: -56, minLat: 1.9487, maxLat: 6.0513, minLng: -58.0563, maxLng: -53.9437, crossesAntimeridian: false },
  SS: { code: 'SS', name: 'South Sudan', lat: 7, lng: 30, minLat: 3.0101, maxLat: 10.9899, minLng: 25.9802, maxLng: 34.0198, crossesAntimeridian: false },
  ST: { code: 'ST', name: 'São Tomé and Príncipe', lat: 1, lng: 7, minLat: 0.65, maxLat: 1.35, minLng: 6.65, maxLng: 7.35, crossesAntimeridian: false },
  SV: { code: 'SV', name: 'El Salvador', lat: 13.8333, lng: -88.9167, minLat: 13.0982, maxLat: 14.5685, minLng: -89.6738, maxLng: -88.1595, crossesAntimeridian: false },
  SX: { code: 'SX', name: 'Sint Maarten', lat: 18.0333, lng: -63.05, minLat: 17.6833, maxLat: 18.3833, minLng: -63.4, maxLng: -62.7, crossesAntimeridian: false },
  SY: { code: 'SY', name: 'Syria', lat: 35, lng: 38, minLat: 32.819, maxLat: 37.181, minLng: 35.3375, maxLng: 40.6625, crossesAntimeridian: false },
  SZ: { code: 'SZ', name: 'Eswatini', lat: -26.5, lng: 31.5, minLat: -27.1678, maxLat: -25.8322, minLng: 30.7537, maxLng: 32.2463, crossesAntimeridian: false },
  TC: { code: 'TC', name: 'Turks and Caicos Islands', lat: 21.75, lng: -71.5833, minLat: 21.4, maxLat: 22.1, minLng: -71.9333, maxLng: -71.2333, crossesAntimeridian: false },
  TD: { code: 'TD', name: 'Chad', lat: 15, lng: 19, minLat: 9.2571, maxLat: 20.7429, minLng: 13.0545, maxLng: 24.9455, crossesAntimeridian: false },
  TF: { code: 'TF', name: 'French Southern and Antarctic Lands', lat: -49.25, lng: 69.167, minLat: -49.6961, maxLat: -48.8039, minLng: 68.4836, maxLng: 69.8504, crossesAntimeridian: false },
  TG: { code: 'TG', name: 'Togo', lat: 8, lng: 1.1667, minLat: 6.7923, maxLat: 9.2077, minLng: -0.0529, maxLng: 2.3863, crossesAntimeridian: false },
  TH: { code: 'TH', name: 'Thailand', lat: 15, lng: 100, minLat: 11.3695, maxLat: 18.6305, minLng: 96.2415, maxLng: 103.7585, crossesAntimeridian: false },
  TJ: { code: 'TJ', name: 'Tajikistan', lat: 39, lng: 71, minLat: 37.0828, maxLat: 40.9172, minLng: 68.533, maxLng: 73.467, crossesAntimeridian: false },
  TK: { code: 'TK', name: 'Tokelau', lat: -9, lng: -172, minLat: -9.35, maxLat: -8.65, minLng: -172.35, maxLng: -171.65, crossesAntimeridian: false },
  TL: { code: 'TL', name: 'Timor-Leste', lat: -8.8333, lng: 125.9167, minLat: -9.4514, maxLat: -8.2152, minLng: 125.2911, maxLng: 126.5422, crossesAntimeridian: false },
  TM: { code: 'TM', name: 'Turkmenistan', lat: 40, lng: 60, minLat: 36.4592, maxLat: 43.5408, minLng: 55.3778, maxLng: 64.6222, crossesAntimeridian: false },
  TN: { code: 'TN', name: 'Tunisia', lat: 34, lng: 9, minLat: 31.95, maxLat: 36.05, minLng: 6.5272, maxLng: 11.4728, crossesAntimeridian: false },
  TO: { code: 'TO', name: 'Tonga', lat: -20, lng: -175, minLat: -20.35, maxLat: -19.65, minLng: -175.35, maxLng: -174.65, crossesAntimeridian: false },
  TR: { code: 'TR', name: 'Turkey', lat: 39, lng: 35, minLat: 34.5137, maxLat: 43.4863, minLng: 29.2272, maxLng: 40.7728, crossesAntimeridian: false },
  TT: { code: 'TT', name: 'Trinidad and Tobago', lat: 11, lng: -61, minLat: 10.637, maxLat: 11.363, minLng: -61.3698, maxLng: -60.6302, crossesAntimeridian: false },
  TV: { code: 'TV', name: 'Tuvalu', lat: -8, lng: 178, minLat: -8.35, maxLat: -7.65, minLng: 177.65, maxLng: 178.35, crossesAntimeridian: true },
  TW: { code: 'TW', name: 'Taiwan', lat: 23.5, lng: 121, minLat: 22.5358, maxLat: 24.4642, minLng: 119.9486, maxLng: 122.0514, crossesAntimeridian: false },
  TZ: { code: 'TZ', name: 'Tanzania', lat: -6, lng: 35, minLat: -10.9271, maxLat: -1.0729, minLng: 30.0458, maxLng: 39.9542, crossesAntimeridian: false },
  UA: { code: 'UA', name: 'Ukraine', lat: 49, lng: 32, minLat: 45.0628, maxLat: 52.9372, minLng: 25.9987, maxLng: 38.0013, crossesAntimeridian: false },
  UG: { code: 'UG', name: 'Uganda', lat: 1, lng: 32, minLat: -1.4909, maxLat: 3.4909, minLng: 29.5087, maxLng: 34.4913, crossesAntimeridian: false },
  UM: { code: 'UM', name: 'United States Minor Outlying Islands', lat: 19.3, lng: 166.6333, minLat: 18.95, maxLat: 19.65, minLng: 166.2833, maxLng: 166.9833, crossesAntimeridian: false },
  US: { code: 'US', name: 'United States', lat: 38, lng: -97, minLat: 22.4839, maxLat: 53.5161, minLng: -116.6902, maxLng: -77.3098, crossesAntimeridian: true },
  UY: { code: 'UY', name: 'Uruguay', lat: -33, lng: -56, minLat: -35.1564, maxLat: -30.8436, minLng: -58.5712, maxLng: -53.4288, crossesAntimeridian: false },
  UZ: { code: 'UZ', name: 'Uzbekistan', lat: 41, lng: 64, minLat: 37.61, maxLat: 44.39, minLng: 59.5082, maxLng: 68.4918, crossesAntimeridian: false },
  VA: { code: 'VA', name: 'Vatican City', lat: 41.9, lng: 12.45, minLat: 41.55, maxLat: 42.25, minLng: 12.1, maxLng: 12.8, crossesAntimeridian: false },
  VC: { code: 'VC', name: 'Saint Vincent and the Grenadines', lat: 13.25, lng: -61.2, minLat: 12.9, maxLat: 13.6, minLng: -61.55, maxLng: -60.85, crossesAntimeridian: false },
  VE: { code: 'VE', name: 'Venezuela', lat: 8, lng: -66, minLat: 3.1482, maxLat: 12.8518, minLng: -70.8995, maxLng: -61.1005, crossesAntimeridian: false },
  VG: { code: 'VG', name: 'British Virgin Islands', lat: 18.4314, lng: -64.6231, minLat: 18.0814, maxLat: 18.7814, minLng: -64.973, maxLng: -64.2731, crossesAntimeridian: false },
  VI: { code: 'VI', name: 'United States Virgin Islands', lat: 18.35, lng: -64.9333, minLat: 18, maxLat: 18.7, minLng: -65.2833, maxLng: -64.5833, crossesAntimeridian: false },
  VN: { code: 'VN', name: 'Vietnam', lat: 16.1667, lng: 107.8333, minLat: 13.2499, maxLat: 19.0835, minLng: 104.7965, maxLng: 110.8702, crossesAntimeridian: false },
  VU: { code: 'VU', name: 'Vanuatu', lat: -16, lng: 167, minLat: -16.5595, maxLat: -15.4405, minLng: 166.4179, maxLng: 167.5821, crossesAntimeridian: false },
  WF: { code: 'WF', name: 'Wallis and Futuna', lat: -13.3, lng: -176.2, minLat: -13.65, maxLat: -12.95, minLng: -176.55, maxLng: -175.85, crossesAntimeridian: true },
  WS: { code: 'WS', name: 'Samoa', lat: -13.5833, lng: -172.3333, minLat: -13.9333, maxLat: -13.2333, minLng: -172.6833, maxLng: -171.9833, crossesAntimeridian: false },
  XK: { code: 'XK', name: 'Kosovo', lat: 42.6667, lng: 21.1667, minLat: 42.1373, maxLat: 43.196, minLng: 20.4468, maxLng: 21.8865, crossesAntimeridian: false },
  YE: { code: 'YE', name: 'Yemen', lat: 15, lng: 48, minLat: 11.3174, maxLat: 18.6826, minLng: 44.1875, maxLng: 51.8125, crossesAntimeridian: false },
  YT: { code: 'YT', name: 'Mayotte', lat: -12.8333, lng: 45.1667, minLat: -13.1833, maxLat: -12.4833, minLng: 44.8167, maxLng: 45.5167, crossesAntimeridian: false },
  ZA: { code: 'ZA', name: 'South Africa', lat: -29, lng: 24, minLat: -34.6004, maxLat: -23.3996, minLng: 17.5968, maxLng: 30.4032, crossesAntimeridian: false },
  ZM: { code: 'ZM', name: 'Zambia', lat: -15, lng: 30, minLat: -19.3968, maxLat: -10.6032, minLng: 25.4481, maxLng: 34.5519, crossesAntimeridian: false },
  ZW: { code: 'ZW', name: 'Zimbabwe', lat: -20, lng: 30, minLat: -23.1681, maxLat: -16.8319, minLng: 26.6285, maxLng: 33.3715, crossesAntimeridian: false },
};

const INVALID_COUNTRY_CODES = new Set<string>(['', 'T1', 'XX']);
const EARTH_RADIUS_KM = 6371.0088;
const COUNTRY_LIST: CountryGeo[] = Object.keys(COUNTRY_GEO).map((key) => COUNTRY_GEO[key]);

function isFiniteNumber(value: number | null | undefined): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

/** Uppercases/trims a code and rejects placeholders that are not real countries. */
function resolveCode(code: string | null | undefined): string | null {
  if (typeof code !== 'string') return null;
  const normalised = code.trim().toUpperCase();
  if (normalised.length !== 2) return null;
  if (INVALID_COUNTRY_CODES.has(normalised)) return null;
  return Object.prototype.hasOwnProperty.call(COUNTRY_GEO, normalised) ? normalised : null;
}

/** Wraps any longitude into [-180, 180). */
function normaliseLongitude(lng: number): number {
  return ((lng + 540) % 360) - 180;
}

/** Great-circle distance in kilometres; never throws for finite input. */
function haversineKm(lat1: number, lng1: number, lat2: number, lng2: number): number {
  const toRad = Math.PI / 180;
  const dLat = (lat2 - lat1) * toRad;
  const dLng = (lng2 - lng1) * toRad;
  const sinLat = Math.sin(dLat / 2);
  const sinLng = Math.sin(dLng / 2);
  const a = Math.min(
    1,
    Math.max(0, sinLat * sinLat + Math.cos(lat1 * toRad) * Math.cos(lat2 * toRad) * sinLng * sinLng),
  );
  return 2 * EARTH_RADIUS_KM * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

/** Centroid anchor for a country code, or null when the code is not a real country. */
export function countryAnchor(code: string | null | undefined): { lat: number; lng: number } | null {
  const key = resolveCode(code);
  if (key === null) return null;
  const geo = COUNTRY_GEO[key];
  return { lat: geo.lat, lng: geo.lng };
}

/** English display name for a country code, or an empty string when unknown. */
export function countryName(code: string | null | undefined): string {
  const key = resolveCode(code);
  if (key === null) return '';
  return COUNTRY_GEO[key].name;
}

/**
 * Bounding boxes for countries whose territory crosses the antimeridian. A single legal
 * box cannot represent them, but accepting every longitude would let a provider coordinate
 * from the other side of the planet pass validation. Each box is
 * `[minLat, maxLat, minLng, maxLng]` and real territory (including Alaska, Hawaii, Puerto
 * Rico, Chukotka and the Pacific islands) is covered.
 */
const ANTIMERIDIAN_BOXES: Record<string, Array<[number, number, number, number]>> = {
  US: [
    [51, 72, -180, -129],
    [18, 23.5, -161, -154],
    [17.5, 53.6, -125, -64.4],
  ],
  RU: [
    [41, 82, 19, 180],
    [60, 72, -180, -168],
  ],
  NZ: [
    [-48, -33, 165, 180],
    [-48, -33, -180, -175],
  ],
  FJ: [
    [-20, -12, 175, 180],
    [-20, -12, -180, -178],
  ],
  KI: [
    [-13, 5, 172, 180],
    [-13, 5, -180, -150],
  ],
  TV: [
    [-12, -5, 176, 180],
    [-12, -5, -180, -179],
  ],
  WF: [
    [-15, -13, -180, -176],
    [-15, -13, 176, 180],
  ],
};

/**
 * True when the coordinate plausibly belongs to the country. Non-finite input, placeholder
 * codes (`T1`, `XX`, ``) and unknown codes are always rejected. Antimeridian countries are
 * checked against their real territory boxes.
 */
export function isCoordinateConsistentWithCountry(
  lat: number | null | undefined,
  lng: number | null | undefined,
  code: string | null | undefined,
): boolean {
  if (!isFiniteNumber(lat) || !isFiniteNumber(lng)) return false;
  const key = resolveCode(code);
  if (key === null) return false;
  const geo = COUNTRY_GEO[key];
  const normalisedLng = normaliseLongitude(lng);

  const boxes = ANTIMERIDIAN_BOXES[key];
  if (boxes) {
    return boxes.some(
      ([minLat, maxLat, minLng, maxLng]) =>
        lat >= minLat && lat <= maxLat && normalisedLng >= minLng && normalisedLng <= maxLng,
    );
  }

  if (lat < geo.minLat || lat > geo.maxLat) return false;
  if (geo.crossesAntimeridian) return true;
  return normalisedLng >= geo.minLng && normalisedLng <= geo.maxLng;
}

/** Country whose anchor is closest by haversine distance, or null for invalid input. */
export function nearestCountryCode(
  lat: number | null | undefined,
  lng: number | null | undefined,
): string | null {
  if (!isFiniteNumber(lat) || !isFiniteNumber(lng)) return null;
  if (lat < -90 || lat > 90) return null;
  const normalisedLng = normaliseLongitude(lng);
  let bestCode: string | null = null;
  let bestDistance = Infinity;
  for (const geo of COUNTRY_LIST) {
    const distance = haversineKm(lat, normalisedLng, geo.lat, geo.lng);
    if (distance < bestDistance) {
      bestDistance = distance;
      bestCode = geo.code;
    }
  }
  return bestCode;
}

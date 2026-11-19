import { createRequire as __intelCreateRequire } from 'node:module';
const require = __intelCreateRequire(import.meta.url);

// server.ts
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import net from "net";
import os from "os";
import path from "path";
import fs from "fs";
import dns from "node:dns/promises";
import { createRequire } from "module";
import dotenv from "dotenv";

// src/lib/countryGeo.ts
var COUNTRY_GEO = {
  AD: { code: "AD", name: "Andorra", lat: 42.5, lng: 1.5, minLat: 42.15, maxLat: 42.85, minLng: 1.15, maxLng: 1.85, crossesAntimeridian: false },
  AE: { code: "AE", name: "United Arab Emirates", lat: 24, lng: 54, minLat: 22.5346, maxLat: 25.4654, minLng: 52.3959, maxLng: 55.6041, crossesAntimeridian: false },
  AF: { code: "AF", name: "Afghanistan", lat: 33, lng: 65, minLat: 28.9069, maxLat: 37.0931, minLng: 60.1195, maxLng: 69.8805, crossesAntimeridian: false },
  AG: { code: "AG", name: "Antigua and Barbuda", lat: 17.05, lng: -61.8, minLat: 16.7, maxLat: 17.4, minLng: -62.15, maxLng: -61.45, crossesAntimeridian: false },
  AI: { code: "AI", name: "Anguilla", lat: 18.25, lng: -63.1667, minLat: 17.9, maxLat: 18.6, minLng: -63.5167, maxLng: -62.8167, crossesAntimeridian: false },
  AL: { code: "AL", name: "Albania", lat: 41, lng: 20, minLat: 40.1407, maxLat: 41.8593, minLng: 18.8614, maxLng: 21.1386, crossesAntimeridian: false },
  AM: { code: "AM", name: "Armenia", lat: 40, lng: 45, minLat: 39.1259, maxLat: 40.8741, minLng: 43.859, maxLng: 46.141, crossesAntimeridian: false },
  AO: { code: "AO", name: "Angola", lat: -12.5, lng: 18.5, minLat: -18.1589, maxLat: -6.8411, minLng: 12.7037, maxLng: 24.2963, crossesAntimeridian: false },
  AQ: { code: "AQ", name: "Antarctica", lat: -90, lng: 0, minLat: -90, maxLat: -71.0366, minLng: -90, maxLng: 90, crossesAntimeridian: false },
  AR: { code: "AR", name: "Argentina", lat: -34, lng: -64, minLat: -42.4509, maxLat: -25.5491, minLng: -74.1937, maxLng: -53.8063, crossesAntimeridian: false },
  AS: { code: "AS", name: "American Samoa", lat: -14.3333, lng: -170, minLat: -14.6833, maxLat: -13.9833, minLng: -170.35, maxLng: -169.65, crossesAntimeridian: false },
  AT: { code: "AT", name: "Austria", lat: 47.3333, lng: 13.3333, minLat: 45.8656, maxLat: 48.8011, minLng: 11.1676, maxLng: 15.499, crossesAntimeridian: false },
  AU: { code: "AU", name: "Australia", lat: -27, lng: 133, minLat: -41.0563, maxLat: -12.9437, minLng: 117.2242, maxLng: 148.7758, crossesAntimeridian: false },
  AW: { code: "AW", name: "Aruba", lat: 12.5, lng: -69.9667, minLat: 12.15, maxLat: 12.85, minLng: -70.3167, maxLng: -69.6167, crossesAntimeridian: false },
  AX: { code: "AX", name: "\xC5land Islands", lat: 60.1167, lng: 19.9, minLat: 59.7667, maxLat: 60.4667, minLng: 19.4957, maxLng: 20.3043, crossesAntimeridian: false },
  AZ: { code: "AZ", name: "Azerbaijan", lat: 40.5, lng: 47.5, minLat: 39.0085, maxLat: 41.9915, minLng: 45.5386, maxLng: 49.4614, crossesAntimeridian: false },
  BA: { code: "BA", name: "Bosnia and Herzegovina", lat: 44, lng: 18, minLat: 42.8531, maxLat: 45.1469, minLng: 16.4056, maxLng: 19.5944, crossesAntimeridian: false },
  BB: { code: "BB", name: "Barbados", lat: 13.1667, lng: -59.5333, minLat: 12.8167, maxLat: 13.5167, minLng: -59.8833, maxLng: -59.1833, crossesAntimeridian: false },
  BD: { code: "BD", name: "Bangladesh", lat: 24, lng: 90, minLat: 22.0531, maxLat: 25.9469, minLng: 87.8688, maxLng: 92.1312, crossesAntimeridian: false },
  BE: { code: "BE", name: "Belgium", lat: 50.8333, lng: 4, minLat: 49.9478, maxLat: 51.7189, minLng: 2.5979, maxLng: 5.4021, crossesAntimeridian: false },
  BF: { code: "BF", name: "Burkina Faso", lat: 13, lng: -2, minLat: 10.3521, maxLat: 15.6479, minLng: -4.7176, maxLng: 0.7176, crossesAntimeridian: false },
  BG: { code: "BG", name: "Bulgaria", lat: 43, lng: 25, minLat: 41.3124, maxLat: 44.6876, minLng: 22.6925, maxLng: 27.3075, crossesAntimeridian: false },
  BH: { code: "BH", name: "Bahrain", lat: 26, lng: 50.55, minLat: 25.65, maxLat: 26.35, minLng: 50.2, maxLng: 50.9, crossesAntimeridian: false },
  BI: { code: "BI", name: "Burundi", lat: -3.5, lng: 30, minLat: -4.3456, maxLat: -2.6544, minLng: 29.1529, maxLng: 30.8471, crossesAntimeridian: false },
  BJ: { code: "BJ", name: "Benin", lat: 9.5, lng: 2.25, minLat: 7.7992, maxLat: 11.2008, minLng: 0.5255, maxLng: 3.9745, crossesAntimeridian: false },
  BL: { code: "BL", name: "Saint Barth\xE9lemy", lat: 18.5, lng: -63.4167, minLat: 18.15, maxLat: 18.85, minLng: -63.7667, maxLng: -63.0667, crossesAntimeridian: false },
  BM: { code: "BM", name: "Bermuda", lat: 32.3333, lng: -64.75, minLat: 31.9833, maxLat: 32.6833, minLng: -65.1, maxLng: -64.4, crossesAntimeridian: false },
  BN: { code: "BN", name: "Brunei", lat: 4.5, lng: 114.6667, minLat: 4.1152, maxLat: 4.8848, minLng: 114.2807, maxLng: 115.0527, crossesAntimeridian: false },
  BO: { code: "BO", name: "Bolivia", lat: -17, lng: -65, minLat: -22.3121, maxLat: -11.6879, minLng: -70.5548, maxLng: -59.4452, crossesAntimeridian: false },
  BQ: { code: "BQ", name: "Caribbean Netherlands", lat: 12.18, lng: -68.25, minLat: 11.83, maxLat: 12.53, minLng: -68.6, maxLng: -67.9, crossesAntimeridian: false },
  BR: { code: "BR", name: "Brazil", lat: -10, lng: -55, minLat: -24.7898, maxLat: 4.7898, minLng: -70.018, maxLng: -39.982, crossesAntimeridian: false },
  BS: { code: "BS", name: "Bahamas", lat: 24.25, lng: -76, minLat: 23.6515, maxLat: 24.8485, minLng: -76.6564, maxLng: -75.3436, crossesAntimeridian: false },
  BT: { code: "BT", name: "Bhutan", lat: 27.5, lng: 90.5, minLat: 26.5069, maxLat: 28.4931, minLng: 89.3804, maxLng: 91.6196, crossesAntimeridian: false },
  BV: { code: "BV", name: "Bouvet Island", lat: -54.4333, lng: 3.4, minLat: -54.7833, maxLat: -54.0833, minLng: 3.05, maxLng: 3.75, crossesAntimeridian: false },
  BW: { code: "BW", name: "Botswana", lat: -22, lng: 24, minLat: -25.8665, maxLat: -18.1335, minLng: 19.8299, maxLng: 28.1701, crossesAntimeridian: false },
  BY: { code: "BY", name: "Belarus", lat: 53, lng: 28, minLat: 50.6908, maxLat: 55.3092, minLng: 24.1629, maxLng: 31.8371, crossesAntimeridian: false },
  BZ: { code: "BZ", name: "Belize", lat: 17.25, lng: -88.75, minLat: 16.4819, maxLat: 18.0181, minLng: -89.5542, maxLng: -87.9458, crossesAntimeridian: false },
  CA: { code: "CA", name: "Canada", lat: 60, lng: -95, minLat: 43.9853, maxLat: 76.0147, minLng: -127.0294, maxLng: -62.9706, crossesAntimeridian: false },
  CC: { code: "CC", name: "Cocos (Keeling) Islands", lat: -12.5, lng: 96.8333, minLat: -12.85, maxLat: -12.15, minLng: 96.4833, maxLng: 97.1833, crossesAntimeridian: false },
  CD: { code: "CD", name: "DR Congo", lat: 0, lng: 25, minLat: -7.7609, maxLat: 7.7609, minLng: 17.2391, maxLng: 32.7609, crossesAntimeridian: false },
  CF: { code: "CF", name: "Central African Republic", lat: 7, lng: 21, minLat: 2.9997, maxLat: 11.0003, minLng: 16.9697, maxLng: 25.0303, crossesAntimeridian: false },
  CG: { code: "CG", name: "Republic of the Congo", lat: -1, lng: 15, minLat: -3.9639, maxLat: 1.9639, minLng: 12.0356, maxLng: 17.9644, crossesAntimeridian: false },
  CH: { code: "CH", name: "Switzerland", lat: 47, lng: 8, minLat: 45.9702, maxLat: 48.0298, minLng: 6.4901, maxLng: 9.5099, crossesAntimeridian: false },
  CI: { code: "CI", name: "Ivory Coast", lat: 8, lng: -5, minLat: 5.122, maxLat: 10.878, minLng: -7.9063, maxLng: -2.0937, crossesAntimeridian: false },
  CK: { code: "CK", name: "Cook Islands", lat: -21.2333, lng: -159.7667, minLat: -21.5833, maxLat: -20.8833, minLng: -160.1167, maxLng: -159.4167, crossesAntimeridian: false },
  CL: { code: "CL", name: "Chile", lat: -30, lng: -71, minLat: -34.407, maxLat: -25.593, minLng: -76.0888, maxLng: -65.9112, crossesAntimeridian: false },
  CM: { code: "CM", name: "Cameroon", lat: 6, lng: 12, minLat: 2.5054, maxLat: 9.4946, minLng: 8.4861, maxLng: 15.5139, crossesAntimeridian: false },
  CN: { code: "CN", name: "China", lat: 35, lng: 105, minLat: 19.2096, maxLat: 50.7904, minLng: 85.7235, maxLng: 124.2765, crossesAntimeridian: false },
  CO: { code: "CO", name: "Colombia", lat: 4, lng: -72, minLat: -1.4155, maxLat: 9.4155, minLng: -77.4287, maxLng: -66.5713, crossesAntimeridian: false },
  CR: { code: "CR", name: "Costa Rica", lat: 10, lng: -84, minLat: 8.8543, maxLat: 11.1457, minLng: -85.1634, maxLng: -82.8366, crossesAntimeridian: false },
  CU: { code: "CU", name: "Cuba", lat: 21.5, lng: -80, minLat: 19.82, maxLat: 23.18, minLng: -81.8057, maxLng: -78.1943, crossesAntimeridian: false },
  CV: { code: "CV", name: "Cape Verde", lat: 16, lng: -24, minLat: 15.65, maxLat: 16.35, minLng: -24.35, maxLng: -23.65, crossesAntimeridian: false },
  CW: { code: "CW", name: "Cura\xE7ao", lat: 12.1167, lng: -68.9333, minLat: 11.7667, maxLat: 12.4667, minLng: -69.2833, maxLng: -68.5833, crossesAntimeridian: false },
  CX: { code: "CX", name: "Christmas Island", lat: -10.5, lng: 105.6667, minLat: -10.85, maxLat: -10.15, minLng: 105.3167, maxLng: 106.0167, crossesAntimeridian: false },
  CY: { code: "CY", name: "Cyprus", lat: 35, lng: 33, minLat: 34.5125, maxLat: 35.4875, minLng: 32.4049, maxLng: 33.5951, crossesAntimeridian: false },
  CZ: { code: "CZ", name: "Czechia", lat: 49.75, lng: 15.5, minLat: 48.3267, maxLat: 51.1733, minLng: 13.2972, maxLng: 17.7028, crossesAntimeridian: false },
  DE: { code: "DE", name: "Germany", lat: 51, lng: 9, minLat: 47.9713, maxLat: 54.0287, minLng: 4.1874, maxLng: 13.8126, crossesAntimeridian: false },
  DJ: { code: "DJ", name: "Djibouti", lat: 11.5, lng: 43, minLat: 10.728, maxLat: 12.272, minLng: 42.2122, maxLng: 43.7878, crossesAntimeridian: false },
  DK: { code: "DK", name: "Denmark", lat: 56, lng: 10, minLat: 54.9479, maxLat: 57.0521, minLng: 8.1185, maxLng: 11.8815, crossesAntimeridian: false },
  DM: { code: "DM", name: "Dominica", lat: 15.4167, lng: -61.3333, minLat: 15.0667, maxLat: 15.7667, minLng: -61.6833, maxLng: -60.9833, crossesAntimeridian: false },
  DO: { code: "DO", name: "Dominican Republic", lat: 19, lng: -70.6667, minLat: 17.8819, maxLat: 20.1181, minLng: -71.8492, maxLng: -69.4841, crossesAntimeridian: false },
  DZ: { code: "DZ", name: "Algeria", lat: 28, lng: 3, minLat: 20.1783, maxLat: 35.8217, minLng: -5.8586, maxLng: 11.8586, crossesAntimeridian: false },
  EC: { code: "EC", name: "Ecuador", lat: -2, lng: -77.5, minLat: -4.6667, maxLat: 0.6667, minLng: -80.1683, maxLng: -74.8317, crossesAntimeridian: false },
  EE: { code: "EE", name: "Estonia", lat: 59, lng: 26, minLat: 57.9222, maxLat: 60.0778, minLng: 23.9073, maxLng: 28.0927, crossesAntimeridian: false },
  EG: { code: "EG", name: "Egypt", lat: 27, lng: 30, minLat: 21.9256, maxLat: 32.0744, minLng: 24.3049, maxLng: 35.6951, crossesAntimeridian: false },
  EH: { code: "EH", name: "Western Sahara", lat: 24.5, lng: -13, minLat: 21.8861, maxLat: 27.1139, minLng: -15.8726, maxLng: -10.1274, crossesAntimeridian: false },
  ER: { code: "ER", name: "Eritrea", lat: 15, lng: 39, minLat: 13.262, maxLat: 16.738, minLng: 37.2007, maxLng: 40.7993, crossesAntimeridian: false },
  ES: { code: "ES", name: "Spain", lat: 40, lng: -4, minLat: 36.3948, maxLat: 43.6052, minLng: -8.7062, maxLng: 0.7062, crossesAntimeridian: false },
  ET: { code: "ET", name: "Ethiopia", lat: 8, lng: 38, minLat: 2.6741, maxLat: 13.3259, minLng: 32.6217, maxLng: 43.3783, crossesAntimeridian: false },
  FI: { code: "FI", name: "Finland", lat: 64, lng: 26, minLat: 61.0516, maxLat: 66.9484, minLng: 19.2743, maxLng: 32.7257, crossesAntimeridian: false },
  FJ: { code: "FJ", name: "Fiji", lat: -18, lng: 175, minLat: -18.6851, maxLat: -17.3149, minLng: 174.2797, maxLng: 175.7203, crossesAntimeridian: true },
  FK: { code: "FK", name: "Falkland Islands", lat: -51.75, lng: -59, minLat: -52.3092, maxLat: -51.1908, minLng: -59.9032, maxLng: -58.0968, crossesAntimeridian: false },
  FM: { code: "FM", name: "Micronesia", lat: 6.9167, lng: 158.25, minLat: 6.5667, maxLat: 7.2667, minLng: 157.9, maxLng: 158.6, crossesAntimeridian: false },
  FO: { code: "FO", name: "Faroe Islands", lat: 62, lng: -7, minLat: 61.65, maxLat: 62.35, minLng: -7.4029, maxLng: -6.5971, crossesAntimeridian: false },
  FR: { code: "FR", name: "France", lat: 46, lng: 2, minLat: 42.2356, maxLat: 49.7644, minLng: -3.4191, maxLng: 7.4191, crossesAntimeridian: false },
  GA: { code: "GA", name: "Gabon", lat: -1, lng: 11.75, minLat: -3.6221, maxLat: 1.6221, minLng: 9.1275, maxLng: 14.3725, crossesAntimeridian: false },
  GB: { code: "GB", name: "United Kingdom", lat: 54, lng: -2, minLat: 51.5022, maxLat: 56.4978, minLng: -6.2496, maxLng: 2.2496, crossesAntimeridian: false },
  GD: { code: "GD", name: "Grenada", lat: 12.1167, lng: -61.6667, minLat: 11.7667, maxLat: 12.4667, minLng: -62.0167, maxLng: -61.3167, crossesAntimeridian: false },
  GE: { code: "GE", name: "Georgia", lat: 42, lng: 43.5, minLat: 40.662, maxLat: 43.338, minLng: 41.6995, maxLng: 45.3005, crossesAntimeridian: false },
  GF: { code: "GF", name: "French Guiana", lat: 4, lng: -53, minLat: 2.5352, maxLat: 5.4648, minLng: -54.4684, maxLng: -51.5316, crossesAntimeridian: false },
  GG: { code: "GG", name: "Guernsey", lat: 49.4667, lng: -2.5833, minLat: 49.1167, maxLat: 49.8167, minLng: -2.9333, maxLng: -2.2333, crossesAntimeridian: false },
  GH: { code: "GH", name: "Ghana", lat: 8, lng: -2, minLat: 5.5247, maxLat: 10.4753, minLng: -4.4996, maxLng: 0.4996, crossesAntimeridian: false },
  GI: { code: "GI", name: "Gibraltar", lat: 36.1333, lng: -5.35, minLat: 35.7833, maxLat: 36.4833, minLng: -5.7, maxLng: -5, crossesAntimeridian: false },
  GL: { code: "GL", name: "Greenland", lat: 72, lng: -40, minLat: 64.5408, maxLat: 79.4592, minLng: -64.1383, maxLng: -15.8617, crossesAntimeridian: false },
  GM: { code: "GM", name: "Gambia", lat: 13.4667, lng: -16.5667, minLat: 12.9427, maxLat: 13.9907, minLng: -17.1055, maxLng: -16.0279, crossesAntimeridian: false },
  GN: { code: "GN", name: "Guinea", lat: 11, lng: -10, minLat: 8.487, maxLat: 13.513, minLng: -12.56, maxLng: -7.44, crossesAntimeridian: false },
  GP: { code: "GP", name: "Guadeloupe", lat: 16.25, lng: -61.5833, minLat: 15.9, maxLat: 16.6, minLng: -61.9333, maxLng: -61.2333, crossesAntimeridian: false },
  GQ: { code: "GQ", name: "Equatorial Guinea", lat: 2, lng: 10, minLat: 1.1512, maxLat: 2.8488, minLng: 9.1506, maxLng: 10.8494, crossesAntimeridian: false },
  GR: { code: "GR", name: "Greece", lat: 39, lng: 22, minLat: 37.1587, maxLat: 40.8413, minLng: 19.6307, maxLng: 24.3693, crossesAntimeridian: false },
  GS: { code: "GS", name: "South Georgia", lat: -54.5, lng: -37, minLat: -54.85, maxLat: -54.15, minLng: -37.5453, maxLng: -36.4547, crossesAntimeridian: false },
  GT: { code: "GT", name: "Guatemala", lat: 15.5, lng: -90.25, minLat: 13.8276, maxLat: 17.1724, minLng: -91.9855, maxLng: -88.5145, crossesAntimeridian: false },
  GU: { code: "GU", name: "Guam", lat: 13.4667, lng: 144.7833, minLat: 13.1167, maxLat: 13.8167, minLng: 144.4333, maxLng: 145.1333, crossesAntimeridian: false },
  GW: { code: "GW", name: "Guinea-Bissau", lat: 12, lng: -15, minLat: 11.0367, maxLat: 12.9633, minLng: -15.9848, maxLng: -14.0152, crossesAntimeridian: false },
  GY: { code: "GY", name: "Guyana", lat: 5, lng: -59, minLat: 2.6502, maxLat: 7.3498, minLng: -61.3588, maxLng: -56.6412, crossesAntimeridian: false },
  HK: { code: "HK", name: "Hong Kong", lat: 22.267, lng: 114.188, minLat: 21.917, maxLat: 22.617, minLng: 113.838, maxLng: 114.538, crossesAntimeridian: false },
  HM: { code: "HM", name: "Heard Island and McDonald Islands", lat: -53.1, lng: 72.5167, minLat: -53.45, maxLat: -52.75, minLng: 72.1667, maxLng: 72.8667, crossesAntimeridian: false },
  HN: { code: "HN", name: "Honduras", lat: 15, lng: -86.5, minLat: 13.3001, maxLat: 16.6999, minLng: -88.2598, maxLng: -84.7402, crossesAntimeridian: false },
  HR: { code: "HR", name: "Croatia", lat: 45.1667, lng: 15.5, minLat: 43.961, maxLat: 46.3724, minLng: 13.7899, maxLng: 17.2101, crossesAntimeridian: false },
  HT: { code: "HT", name: "Haiti", lat: 19, lng: -72.4167, minLat: 18.1557, maxLat: 19.8443, minLng: -73.3096, maxLng: -71.5237, crossesAntimeridian: false },
  HU: { code: "HU", name: "Hungary", lat: 47, lng: 20, minLat: 45.4542, maxLat: 48.5458, minLng: 17.7334, maxLng: 22.2666, crossesAntimeridian: false },
  ID: { code: "ID", name: "Indonesia", lat: -5, lng: 120, minLat: -11.9944, maxLat: 1.9944, minLng: 112.9789, maxLng: 127.0211, crossesAntimeridian: false },
  IE: { code: "IE", name: "Ireland", lat: 53, lng: -8, minLat: 51.6565, maxLat: 54.3435, minLng: -10.2325, maxLng: -5.7675, crossesAntimeridian: false },
  IL: { code: "IL", name: "Israel", lat: 31.47, lng: 35.13, minLat: 30.7396, maxLat: 32.2004, minLng: 34.2736, maxLng: 35.9864, crossesAntimeridian: false },
  IM: { code: "IM", name: "Isle of Man", lat: 54.25, lng: -4.5, minLat: 53.9, maxLat: 54.6, minLng: -4.85, maxLng: -4.15, crossesAntimeridian: false },
  IN: { code: "IN", name: "India", lat: 20, lng: 77, minLat: 10.8105, maxLat: 29.1895, minLng: 67.2208, maxLng: 86.7792, crossesAntimeridian: false },
  IO: { code: "IO", name: "British Indian Ocean Territory", lat: -6, lng: 71.5, minLat: -6.35, maxLat: -5.65, minLng: 71.15, maxLng: 71.85, crossesAntimeridian: false },
  IQ: { code: "IQ", name: "Iraq", lat: 33, lng: 44, minLat: 29.6446, maxLat: 36.3554, minLng: 39.9991, maxLng: 48.0009, crossesAntimeridian: false },
  IR: { code: "IR", name: "Iran", lat: 32, lng: 53, minLat: 25.4934, maxLat: 38.5066, minLng: 45.3275, maxLng: 60.6725, crossesAntimeridian: false },
  IS: { code: "IS", name: "Iceland", lat: 65, lng: -18, minLat: 63.3734, maxLat: 66.6266, minLng: -21.8488, maxLng: -14.1512, crossesAntimeridian: false },
  IT: { code: "IT", name: "Italy", lat: 42.8333, lng: 12.8333, minLat: 40.0512, maxLat: 45.6155, minLng: 9.0395, maxLng: 16.6271, crossesAntimeridian: false },
  JE: { code: "JE", name: "Jersey", lat: 49.25, lng: -2.1667, minLat: 48.9, maxLat: 49.6, minLng: -2.5167, maxLng: -1.8167, crossesAntimeridian: false },
  JM: { code: "JM", name: "Jamaica", lat: 18.25, lng: -77.5, minLat: 17.7187, maxLat: 18.7813, minLng: -78.0595, maxLng: -76.9405, crossesAntimeridian: false },
  JO: { code: "JO", name: "Jordan", lat: 31, lng: 36, minLat: 29.4851, maxLat: 32.5149, minLng: 34.2327, maxLng: 37.7673, crossesAntimeridian: false },
  JP: { code: "JP", name: "Japan", lat: 36, lng: 138, minLat: 32.8843, maxLat: 39.1157, minLng: 134.1488, maxLng: 141.8512, crossesAntimeridian: false },
  KE: { code: "KE", name: "Kenya", lat: 1, lng: 38, minLat: -2.861, maxLat: 4.861, minLng: 34.1384, maxLng: 41.8616, crossesAntimeridian: false },
  KG: { code: "KG", name: "Kyrgyzstan", lat: 41, lng: 75, minLat: 38.7337, maxLat: 43.2663, minLng: 71.9971, maxLng: 78.0029, crossesAntimeridian: false },
  KH: { code: "KH", name: "Cambodia", lat: 13, lng: 105, minLat: 10.8436, maxLat: 15.1564, minLng: 102.7869, maxLng: 107.2131, crossesAntimeridian: false },
  KI: { code: "KI", name: "Kiribati", lat: 1.4167, lng: 173, minLat: 1.0667, maxLat: 1.7667, minLng: 172.65, maxLng: 173.35, crossesAntimeridian: true },
  KM: { code: "KM", name: "Comoros", lat: -12.1667, lng: 44.25, minLat: -12.5167, maxLat: -11.8167, minLng: 43.9, maxLng: 44.6, crossesAntimeridian: false },
  KN: { code: "KN", name: "Saint Kitts and Nevis", lat: 17.3333, lng: -62.75, minLat: 16.9833, maxLat: 17.6833, minLng: -63.1, maxLng: -62.4, crossesAntimeridian: false },
  KP: { code: "KP", name: "North Korea", lat: 40, lng: 127, minLat: 38.2404, maxLat: 41.7596, minLng: 124.703, maxLng: 129.297, crossesAntimeridian: false },
  KR: { code: "KR", name: "South Korea", lat: 37, lng: 127.5, minLat: 35.3956, maxLat: 38.6044, minLng: 125.4911, maxLng: 129.5089, crossesAntimeridian: false },
  KW: { code: "KW", name: "Kuwait", lat: 29.5, lng: 45.75, minLat: 28.8235, maxLat: 30.1765, minLng: 44.9727, maxLng: 46.5273, crossesAntimeridian: false },
  KY: { code: "KY", name: "Cayman Islands", lat: 19.5, lng: -80.5, minLat: 19.15, maxLat: 19.85, minLng: -80.85, maxLng: -80.15, crossesAntimeridian: false },
  KZ: { code: "KZ", name: "Kazakhstan", lat: 48, lng: 68, minLat: 39.6338, maxLat: 56.3662, minLng: 55.4969, maxLng: 80.5031, crossesAntimeridian: false },
  LA: { code: "LA", name: "Laos", lat: 18, lng: 105, minLat: 15.5337, maxLat: 20.4663, minLng: 102.4068, maxLng: 107.5932, crossesAntimeridian: false },
  LB: { code: "LB", name: "Lebanon", lat: 33.8333, lng: 35.8333, minLat: 33.3152, maxLat: 34.3515, minLng: 35.2096, maxLng: 36.4571, crossesAntimeridian: false },
  LC: { code: "LC", name: "Saint Lucia", lat: 13.8833, lng: -60.9667, minLat: 13.5333, maxLat: 14.2333, minLng: -61.3167, maxLng: -60.6167, crossesAntimeridian: false },
  LI: { code: "LI", name: "Liechtenstein", lat: 47.2667, lng: 9.5333, minLat: 46.9167, maxLat: 47.6167, minLng: 9.1833, maxLng: 9.8833, crossesAntimeridian: false },
  LK: { code: "LK", name: "Sri Lanka", lat: 7, lng: 81, minLat: 5.7018, maxLat: 8.2982, minLng: 79.6921, maxLng: 82.3079, crossesAntimeridian: false },
  LR: { code: "LR", name: "Liberia", lat: 6.5, lng: -9.5, minLat: 4.8086, maxLat: 8.1914, minLng: -11.2023, maxLng: -7.7977, crossesAntimeridian: false },
  LS: { code: "LS", name: "Lesotho", lat: -29.5, lng: 28.5, minLat: -30.383, maxLat: -28.617, minLng: 27.4855, maxLng: 29.5145, crossesAntimeridian: false },
  LT: { code: "LT", name: "Lithuania", lat: 56, lng: 24, minLat: 54.7049, maxLat: 57.2951, minLng: 21.684, maxLng: 26.316, crossesAntimeridian: false },
  LU: { code: "LU", name: "Luxembourg", lat: 49.75, lng: 6.1667, minLat: 49.4, maxLat: 50.1, minLng: 5.7678, maxLng: 6.5656, crossesAntimeridian: false },
  LV: { code: "LV", name: "Latvia", lat: 57, lng: 25, minLat: 55.7123, maxLat: 58.2877, minLng: 22.6356, maxLng: 27.3644, crossesAntimeridian: false },
  LY: { code: "LY", name: "Libya", lat: 25, lng: 17, minLat: 18.2772, maxLat: 31.7228, minLng: 9.5822, maxLng: 24.4178, crossesAntimeridian: false },
  MA: { code: "MA", name: "Morocco", lat: 32, lng: -5, minLat: 28.6132, maxLat: 35.3868, minLng: -8.9936, maxLng: -1.0064, crossesAntimeridian: false },
  MC: { code: "MC", name: "Monaco", lat: 43.7333, lng: 7.4, minLat: 43.3833, maxLat: 44.0833, minLng: 7.05, maxLng: 7.75, crossesAntimeridian: false },
  MD: { code: "MD", name: "Moldova", lat: 47, lng: 29, minLat: 46.0676, maxLat: 47.9324, minLng: 27.6328, maxLng: 30.3672, crossesAntimeridian: false },
  ME: { code: "ME", name: "Montenegro", lat: 42.5, lng: 19.3, minLat: 41.9044, maxLat: 43.0956, minLng: 18.4921, maxLng: 20.1079, crossesAntimeridian: false },
  MF: { code: "MF", name: "Saint Martin", lat: 18.0833, lng: -63.95, minLat: 17.7333, maxLat: 18.4333, minLng: -64.3, maxLng: -63.6, crossesAntimeridian: false },
  MG: { code: "MG", name: "Madagascar", lat: -20, lng: 47, minLat: -23.8832, maxLat: -16.1168, minLng: 42.8676, maxLng: 51.1324, crossesAntimeridian: false },
  MH: { code: "MH", name: "Marshall Islands", lat: 9, lng: 168, minLat: 8.65, maxLat: 9.35, minLng: 167.65, maxLng: 168.35, crossesAntimeridian: false },
  MK: { code: "MK", name: "North Macedonia", lat: 41.8333, lng: 22, minLat: 41.0206, maxLat: 42.646, minLng: 20.9093, maxLng: 23.0907, crossesAntimeridian: false },
  ML: { code: "ML", name: "Mali", lat: 17, lng: -4, minLat: 11.3559, maxLat: 22.6441, minLng: -9.902, maxLng: 1.902, crossesAntimeridian: false },
  MM: { code: "MM", name: "Myanmar", lat: 22, lng: 98, minLat: 17.8312, maxLat: 26.1688, minLng: 93.5038, maxLng: 102.4962, crossesAntimeridian: false },
  MN: { code: "MN", name: "Mongolia", lat: 46, lng: 105, minLat: 39.6615, maxLat: 52.3385, minLng: 95.8754, maxLng: 114.1246, crossesAntimeridian: false },
  MO: { code: "MO", name: "Macau", lat: 22.1667, lng: 113.55, minLat: 21.8167, maxLat: 22.5167, minLng: 113.2, maxLng: 113.9, crossesAntimeridian: false },
  MP: { code: "MP", name: "Northern Mariana Islands", lat: 15.2, lng: 145.75, minLat: 14.85, maxLat: 15.55, minLng: 145.4, maxLng: 146.1, crossesAntimeridian: false },
  MQ: { code: "MQ", name: "Martinique", lat: 14.6667, lng: -61, minLat: 14.3167, maxLat: 15.0167, minLng: -61.35, maxLng: -60.65, crossesAntimeridian: false },
  MR: { code: "MR", name: "Mauritania", lat: 20, lng: -12, minLat: 14.8546, maxLat: 25.1454, minLng: -17.4756, maxLng: -6.5244, crossesAntimeridian: false },
  MS: { code: "MS", name: "Montserrat", lat: 16.75, lng: -62.2, minLat: 16.4, maxLat: 17.1, minLng: -62.55, maxLng: -61.85, crossesAntimeridian: false },
  MT: { code: "MT", name: "Malta", lat: 35.8333, lng: 14.5833, minLat: 35.4833, maxLat: 36.1833, minLng: 14.2333, maxLng: 14.9333, crossesAntimeridian: false },
  MU: { code: "MU", name: "Mauritius", lat: -20.2833, lng: 57.55, minLat: -20.6333, maxLat: -19.9333, minLng: 57.2, maxLng: 57.9, crossesAntimeridian: false },
  MV: { code: "MV", name: "Maldives", lat: 3.25, lng: 73, minLat: 2.9, maxLat: 3.6, minLng: 72.65, maxLng: 73.35, crossesAntimeridian: false },
  MW: { code: "MW", name: "Malawi", lat: -13.5, lng: 34, minLat: -15.2445, maxLat: -11.7555, minLng: 32.2059, maxLng: 35.7941, crossesAntimeridian: false },
  MX: { code: "MX", name: "Mexico", lat: 23, lng: -102, minLat: 15.8966, maxLat: 30.1034, minLng: -109.7168, maxLng: -94.2832, crossesAntimeridian: false },
  MY: { code: "MY", name: "Malaysia", lat: 2.5, lng: 112.5, minLat: -0.415, maxLat: 5.415, minLng: 109.5822, maxLng: 115.4178, crossesAntimeridian: false },
  MZ: { code: "MZ", name: "Mozambique", lat: -18.25, lng: 35, minLat: -22.7876, maxLat: -13.7124, minLng: 30.222, maxLng: 39.778, crossesAntimeridian: false },
  NA: { code: "NA", name: "Namibia", lat: -22, lng: 17, minLat: -26.6051, maxLat: -17.3949, minLng: 12.0332, maxLng: 21.9668, crossesAntimeridian: false },
  NC: { code: "NC", name: "New Caledonia", lat: -21.5, lng: 165.5, minLat: -22.1907, maxLat: -20.8093, minLng: 164.7576, maxLng: 166.2424, crossesAntimeridian: false },
  NE: { code: "NE", name: "Niger", lat: 16, lng: 8, minLat: 10.2952, maxLat: 21.7048, minLng: 2.0653, maxLng: 13.9347, crossesAntimeridian: false },
  NF: { code: "NF", name: "Norfolk Island", lat: -29.0333, lng: 167.95, minLat: -29.3833, maxLat: -28.6833, minLng: 167.6, maxLng: 168.3, crossesAntimeridian: false },
  NG: { code: "NG", name: "Nigeria", lat: 10, lng: 8, minLat: 5.1288, maxLat: 14.8712, minLng: 3.0537, maxLng: 12.9463, crossesAntimeridian: false },
  NI: { code: "NI", name: "Nicaragua", lat: 13, lng: -85, minLat: 11.17, maxLat: 14.83, minLng: -86.8781, maxLng: -83.1219, crossesAntimeridian: false },
  NL: { code: "NL", name: "Netherlands", lat: 52.5, lng: 5.75, minLat: 51.4632, maxLat: 53.5368, minLng: 4.0469, maxLng: 7.4531, crossesAntimeridian: false },
  NO: { code: "NO", name: "Norway", lat: 62, lng: 10, minLat: 59.116, maxLat: 64.884, minLng: 3.857, maxLng: 16.143, crossesAntimeridian: false },
  NP: { code: "NP", name: "Nepal", lat: 28, lng: 84, minLat: 26.0556, maxLat: 29.9444, minLng: 81.7979, maxLng: 86.2021, crossesAntimeridian: false },
  NR: { code: "NR", name: "Nauru", lat: -0.5333, lng: 166.9167, minLat: -0.8833, maxLat: -0.1833, minLng: 166.5667, maxLng: 167.2667, crossesAntimeridian: false },
  NU: { code: "NU", name: "Niue", lat: -19.0333, lng: -169.8667, minLat: -19.3833, maxLat: -18.6833, minLng: -170.2167, maxLng: -169.5167, crossesAntimeridian: false },
  NZ: { code: "NZ", name: "New Zealand", lat: -41, lng: 174, minLat: -43.6358, maxLat: -38.3642, minLng: 170.5076, maxLng: 177.4924, crossesAntimeridian: true },
  OM: { code: "OM", name: "Oman", lat: 21, lng: 57, minLat: 18.1804, maxLat: 23.8196, minLng: 53.9798, maxLng: 60.0202, crossesAntimeridian: false },
  PA: { code: "PA", name: "Panama", lat: 9, lng: -80, minLat: 7.6082, maxLat: 10.3918, minLng: -81.4092, maxLng: -78.5908, crossesAntimeridian: false },
  PE: { code: "PE", name: "Peru", lat: -10, lng: -76, minLat: -15.7457, maxLat: -4.2543, minLng: -81.8343, maxLng: -70.1657, crossesAntimeridian: false },
  PF: { code: "PF", name: "French Polynesia", lat: -15, lng: -140, minLat: -15.35, maxLat: -14.65, minLng: -140.35, maxLng: -139.65, crossesAntimeridian: true },
  PG: { code: "PG", name: "Papua New Guinea", lat: -6, lng: 147, minLat: -9.448, maxLat: -2.552, minLng: 143.533, maxLng: 150.467, crossesAntimeridian: false },
  PH: { code: "PH", name: "Philippines", lat: 13, lng: 122, minLat: 10.0346, maxLat: 15.9654, minLng: 118.9566, maxLng: 125.0434, crossesAntimeridian: false },
  PK: { code: "PK", name: "Pakistan", lat: 30, lng: 70, minLat: 25.2405, maxLat: 34.7595, minLng: 64.5042, maxLng: 75.4958, crossesAntimeridian: false },
  PL: { code: "PL", name: "Poland", lat: 52, lng: 20, minLat: 49.166, maxLat: 54.834, minLng: 15.3968, maxLng: 24.6032, crossesAntimeridian: false },
  PM: { code: "PM", name: "Saint Pierre and Miquelon", lat: 46.8333, lng: -56.3333, minLat: 46.4833, maxLat: 47.1833, minLng: -56.6833, maxLng: -55.9833, crossesAntimeridian: false },
  PN: { code: "PN", name: "Pitcairn Islands", lat: -25.0667, lng: -130.1, minLat: -25.4167, maxLat: -24.7167, minLng: -130.45, maxLng: -129.75, crossesAntimeridian: false },
  PR: { code: "PR", name: "Puerto Rico", lat: 18.25, lng: -66.5, minLat: 17.7727, maxLat: 18.7273, minLng: -67.0026, maxLng: -65.9974, crossesAntimeridian: false },
  PS: { code: "PS", name: "Palestine", lat: 31.9, lng: 35.2, minLat: 31.5003, maxLat: 32.2997, minLng: 34.7292, maxLng: 35.6708, crossesAntimeridian: false },
  PT: { code: "PT", name: "Portugal", lat: 39.5, lng: -8, minLat: 37.962, maxLat: 41.038, minLng: -9.9932, maxLng: -6.0068, crossesAntimeridian: false },
  PW: { code: "PW", name: "Palau", lat: 7.5, lng: 134.5, minLat: 7.15, maxLat: 7.85, minLng: 134.15, maxLng: 134.85, crossesAntimeridian: false },
  PY: { code: "PY", name: "Paraguay", lat: -23, lng: -58, minLat: -26.2323, maxLat: -19.7677, minLng: -61.5115, maxLng: -54.4885, crossesAntimeridian: false },
  QA: { code: "QA", name: "Qatar", lat: 25.5, lng: 51.25, minLat: 24.9545, maxLat: 26.0455, minLng: 50.6456, maxLng: 51.8544, crossesAntimeridian: false },
  RE: { code: "RE", name: "R\xE9union", lat: -21.15, lng: 55.5, minLat: -21.5, maxLat: -20.8, minLng: 55.15, maxLng: 55.85, crossesAntimeridian: false },
  RO: { code: "RO", name: "Romania", lat: 46, lng: 25, minLat: 43.5254, maxLat: 48.4746, minLng: 21.4377, maxLng: 28.5623, crossesAntimeridian: false },
  RS: { code: "RS", name: "Serbia", lat: 44, lng: 21, minLat: 42.4935, maxLat: 45.5065, minLng: 18.9057, maxLng: 23.0943, crossesAntimeridian: false },
  RU: { code: "RU", name: "Russia", lat: 60, lng: 100, minLat: 39.0431, maxLat: 80.9569, minLng: 58.0861, maxLng: 141.9139, crossesAntimeridian: true },
  RW: { code: "RW", name: "Rwanda", lat: -2, lng: 30, minLat: -2.8225, maxLat: -1.1775, minLng: 29.177, maxLng: 30.823, crossesAntimeridian: false },
  SA: { code: "SA", name: "Saudi Arabia", lat: 25, lng: 45, minLat: 17.5691, maxLat: 32.4309, minLng: 36.8009, maxLng: 53.1991, crossesAntimeridian: false },
  SB: { code: "SB", name: "Solomon Islands", lat: -8, lng: 159, minLat: -8.8615, maxLat: -7.1385, minLng: 158.13, maxLng: 159.87, crossesAntimeridian: false },
  SC: { code: "SC", name: "Seychelles", lat: -4.5833, lng: 55.6667, minLat: -4.9333, maxLat: -4.2333, minLng: 55.3167, maxLng: 56.0167, crossesAntimeridian: false },
  SD: { code: "SD", name: "Sudan", lat: 15, lng: 30, minLat: 8.0397, maxLat: 21.9603, minLng: 22.7941, maxLng: 37.2059, crossesAntimeridian: false },
  SE: { code: "SE", name: "Sweden", lat: 62, lng: 15, minLat: 58.599, maxLat: 65.401, minLng: 7.7558, maxLng: 22.2442, crossesAntimeridian: false },
  SG: { code: "SG", name: "Singapore", lat: 1.3667, lng: 103.8, minLat: 1.0167, maxLat: 1.7167, minLng: 103.45, maxLng: 104.15, crossesAntimeridian: false },
  SH: { code: "SH", name: "Saint Helena, Ascension and Tristan da Cunha", lat: -15.95, lng: -5.72, minLat: -16.3, maxLat: -15.6, minLng: -6.07, maxLng: -5.37, crossesAntimeridian: false },
  SI: { code: "SI", name: "Slovenia", lat: 46.1167, lng: 14.8167, minLat: 45.395, maxLat: 46.8383, minLng: 13.7757, maxLng: 15.8577, crossesAntimeridian: false },
  SJ: { code: "SJ", name: "Svalbard and Jan Mayen", lat: 78, lng: 20, minLat: 77.65, maxLat: 78.35, minLng: 19.65, maxLng: 20.35, crossesAntimeridian: false },
  SK: { code: "SK", name: "Slovakia", lat: 48.6667, lng: 19.5, minLat: 47.5444, maxLat: 49.789, minLng: 17.8007, maxLng: 21.1993, crossesAntimeridian: false },
  SL: { code: "SL", name: "Sierra Leone", lat: 8.5, lng: -11.5, minLat: 7.1425, maxLat: 9.8575, minLng: -12.8726, maxLng: -10.1274, crossesAntimeridian: false },
  SM: { code: "SM", name: "San Marino", lat: 43.7667, lng: 12.4167, minLat: 43.4167, maxLat: 44.1167, minLng: 12.0667, maxLng: 12.7667, crossesAntimeridian: false },
  SN: { code: "SN", name: "Senegal", lat: 14, lng: -14, minLat: 11.7521, maxLat: 16.2479, minLng: -16.3167, maxLng: -11.6833, crossesAntimeridian: false },
  SO: { code: "SO", name: "Somalia", lat: 10, lng: 49, minLat: 5.9529, maxLat: 14.0471, minLng: 44.8905, maxLng: 53.1095, crossesAntimeridian: false },
  SR: { code: "SR", name: "Suriname", lat: 4, lng: -56, minLat: 1.9487, maxLat: 6.0513, minLng: -58.0563, maxLng: -53.9437, crossesAntimeridian: false },
  SS: { code: "SS", name: "South Sudan", lat: 7, lng: 30, minLat: 3.0101, maxLat: 10.9899, minLng: 25.9802, maxLng: 34.0198, crossesAntimeridian: false },
  ST: { code: "ST", name: "S\xE3o Tom\xE9 and Pr\xEDncipe", lat: 1, lng: 7, minLat: 0.65, maxLat: 1.35, minLng: 6.65, maxLng: 7.35, crossesAntimeridian: false },
  SV: { code: "SV", name: "El Salvador", lat: 13.8333, lng: -88.9167, minLat: 13.0982, maxLat: 14.5685, minLng: -89.6738, maxLng: -88.1595, crossesAntimeridian: false },
  SX: { code: "SX", name: "Sint Maarten", lat: 18.0333, lng: -63.05, minLat: 17.6833, maxLat: 18.3833, minLng: -63.4, maxLng: -62.7, crossesAntimeridian: false },
  SY: { code: "SY", name: "Syria", lat: 35, lng: 38, minLat: 32.819, maxLat: 37.181, minLng: 35.3375, maxLng: 40.6625, crossesAntimeridian: false },
  SZ: { code: "SZ", name: "Eswatini", lat: -26.5, lng: 31.5, minLat: -27.1678, maxLat: -25.8322, minLng: 30.7537, maxLng: 32.2463, crossesAntimeridian: false },
  TC: { code: "TC", name: "Turks and Caicos Islands", lat: 21.75, lng: -71.5833, minLat: 21.4, maxLat: 22.1, minLng: -71.9333, maxLng: -71.2333, crossesAntimeridian: false },
  TD: { code: "TD", name: "Chad", lat: 15, lng: 19, minLat: 9.2571, maxLat: 20.7429, minLng: 13.0545, maxLng: 24.9455, crossesAntimeridian: false },
  TF: { code: "TF", name: "French Southern and Antarctic Lands", lat: -49.25, lng: 69.167, minLat: -49.6961, maxLat: -48.8039, minLng: 68.4836, maxLng: 69.8504, crossesAntimeridian: false },
  TG: { code: "TG", name: "Togo", lat: 8, lng: 1.1667, minLat: 6.7923, maxLat: 9.2077, minLng: -0.0529, maxLng: 2.3863, crossesAntimeridian: false },
  TH: { code: "TH", name: "Thailand", lat: 15, lng: 100, minLat: 11.3695, maxLat: 18.6305, minLng: 96.2415, maxLng: 103.7585, crossesAntimeridian: false },
  TJ: { code: "TJ", name: "Tajikistan", lat: 39, lng: 71, minLat: 37.0828, maxLat: 40.9172, minLng: 68.533, maxLng: 73.467, crossesAntimeridian: false },
  TK: { code: "TK", name: "Tokelau", lat: -9, lng: -172, minLat: -9.35, maxLat: -8.65, minLng: -172.35, maxLng: -171.65, crossesAntimeridian: false },
  TL: { code: "TL", name: "Timor-Leste", lat: -8.8333, lng: 125.9167, minLat: -9.4514, maxLat: -8.2152, minLng: 125.2911, maxLng: 126.5422, crossesAntimeridian: false },
  TM: { code: "TM", name: "Turkmenistan", lat: 40, lng: 60, minLat: 36.4592, maxLat: 43.5408, minLng: 55.3778, maxLng: 64.6222, crossesAntimeridian: false },
  TN: { code: "TN", name: "Tunisia", lat: 34, lng: 9, minLat: 31.95, maxLat: 36.05, minLng: 6.5272, maxLng: 11.4728, crossesAntimeridian: false },
  TO: { code: "TO", name: "Tonga", lat: -20, lng: -175, minLat: -20.35, maxLat: -19.65, minLng: -175.35, maxLng: -174.65, crossesAntimeridian: false },
  TR: { code: "TR", name: "Turkey", lat: 39, lng: 35, minLat: 34.5137, maxLat: 43.4863, minLng: 29.2272, maxLng: 40.7728, crossesAntimeridian: false },
  TT: { code: "TT", name: "Trinidad and Tobago", lat: 11, lng: -61, minLat: 10.637, maxLat: 11.363, minLng: -61.3698, maxLng: -60.6302, crossesAntimeridian: false },
  TV: { code: "TV", name: "Tuvalu", lat: -8, lng: 178, minLat: -8.35, maxLat: -7.65, minLng: 177.65, maxLng: 178.35, crossesAntimeridian: true },
  TW: { code: "TW", name: "Taiwan", lat: 23.5, lng: 121, minLat: 22.5358, maxLat: 24.4642, minLng: 119.9486, maxLng: 122.0514, crossesAntimeridian: false },
  TZ: { code: "TZ", name: "Tanzania", lat: -6, lng: 35, minLat: -10.9271, maxLat: -1.0729, minLng: 30.0458, maxLng: 39.9542, crossesAntimeridian: false },
  UA: { code: "UA", name: "Ukraine", lat: 49, lng: 32, minLat: 45.0628, maxLat: 52.9372, minLng: 25.9987, maxLng: 38.0013, crossesAntimeridian: false },
  UG: { code: "UG", name: "Uganda", lat: 1, lng: 32, minLat: -1.4909, maxLat: 3.4909, minLng: 29.5087, maxLng: 34.4913, crossesAntimeridian: false },
  UM: { code: "UM", name: "United States Minor Outlying Islands", lat: 19.3, lng: 166.6333, minLat: 18.95, maxLat: 19.65, minLng: 166.2833, maxLng: 166.9833, crossesAntimeridian: false },
  US: { code: "US", name: "United States", lat: 38, lng: -97, minLat: 22.4839, maxLat: 53.5161, minLng: -116.6902, maxLng: -77.3098, crossesAntimeridian: true },
  UY: { code: "UY", name: "Uruguay", lat: -33, lng: -56, minLat: -35.1564, maxLat: -30.8436, minLng: -58.5712, maxLng: -53.4288, crossesAntimeridian: false },
  UZ: { code: "UZ", name: "Uzbekistan", lat: 41, lng: 64, minLat: 37.61, maxLat: 44.39, minLng: 59.5082, maxLng: 68.4918, crossesAntimeridian: false },
  VA: { code: "VA", name: "Vatican City", lat: 41.9, lng: 12.45, minLat: 41.55, maxLat: 42.25, minLng: 12.1, maxLng: 12.8, crossesAntimeridian: false },
  VC: { code: "VC", name: "Saint Vincent and the Grenadines", lat: 13.25, lng: -61.2, minLat: 12.9, maxLat: 13.6, minLng: -61.55, maxLng: -60.85, crossesAntimeridian: false },
  VE: { code: "VE", name: "Venezuela", lat: 8, lng: -66, minLat: 3.1482, maxLat: 12.8518, minLng: -70.8995, maxLng: -61.1005, crossesAntimeridian: false },
  VG: { code: "VG", name: "British Virgin Islands", lat: 18.4314, lng: -64.6231, minLat: 18.0814, maxLat: 18.7814, minLng: -64.973, maxLng: -64.2731, crossesAntimeridian: false },
  VI: { code: "VI", name: "United States Virgin Islands", lat: 18.35, lng: -64.9333, minLat: 18, maxLat: 18.7, minLng: -65.2833, maxLng: -64.5833, crossesAntimeridian: false },
  VN: { code: "VN", name: "Vietnam", lat: 16.1667, lng: 107.8333, minLat: 13.2499, maxLat: 19.0835, minLng: 104.7965, maxLng: 110.8702, crossesAntimeridian: false },
  VU: { code: "VU", name: "Vanuatu", lat: -16, lng: 167, minLat: -16.5595, maxLat: -15.4405, minLng: 166.4179, maxLng: 167.5821, crossesAntimeridian: false },
  WF: { code: "WF", name: "Wallis and Futuna", lat: -13.3, lng: -176.2, minLat: -13.65, maxLat: -12.95, minLng: -176.55, maxLng: -175.85, crossesAntimeridian: true },
  WS: { code: "WS", name: "Samoa", lat: -13.5833, lng: -172.3333, minLat: -13.9333, maxLat: -13.2333, minLng: -172.6833, maxLng: -171.9833, crossesAntimeridian: false },
  XK: { code: "XK", name: "Kosovo", lat: 42.6667, lng: 21.1667, minLat: 42.1373, maxLat: 43.196, minLng: 20.4468, maxLng: 21.8865, crossesAntimeridian: false },
  YE: { code: "YE", name: "Yemen", lat: 15, lng: 48, minLat: 11.3174, maxLat: 18.6826, minLng: 44.1875, maxLng: 51.8125, crossesAntimeridian: false },
  YT: { code: "YT", name: "Mayotte", lat: -12.8333, lng: 45.1667, minLat: -13.1833, maxLat: -12.4833, minLng: 44.8167, maxLng: 45.5167, crossesAntimeridian: false },
  ZA: { code: "ZA", name: "South Africa", lat: -29, lng: 24, minLat: -34.6004, maxLat: -23.3996, minLng: 17.5968, maxLng: 30.4032, crossesAntimeridian: false },
  ZM: { code: "ZM", name: "Zambia", lat: -15, lng: 30, minLat: -19.3968, maxLat: -10.6032, minLng: 25.4481, maxLng: 34.5519, crossesAntimeridian: false },
  ZW: { code: "ZW", name: "Zimbabwe", lat: -20, lng: 30, minLat: -23.1681, maxLat: -16.8319, minLng: 26.6285, maxLng: 33.3715, crossesAntimeridian: false }
};
var INVALID_COUNTRY_CODES = /* @__PURE__ */ new Set(["", "T1", "XX"]);
var COUNTRY_LIST = Object.keys(COUNTRY_GEO).map((key) => COUNTRY_GEO[key]);
function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}
function resolveCode(code) {
  if (typeof code !== "string") return null;
  const normalised = code.trim().toUpperCase();
  if (normalised.length !== 2) return null;
  if (INVALID_COUNTRY_CODES.has(normalised)) return null;
  return Object.prototype.hasOwnProperty.call(COUNTRY_GEO, normalised) ? normalised : null;
}
function normaliseLongitude(lng) {
  return (lng + 540) % 360 - 180;
}
var ANTIMERIDIAN_BOXES = {
  US: [
    [51, 72, -180, -129],
    [18, 23.5, -161, -154],
    [17.5, 53.6, -125, -64.4]
  ],
  RU: [
    [41, 82, 19, 180],
    [60, 72, -180, -168]
  ],
  NZ: [
    [-48, -33, 165, 180],
    [-48, -33, -180, -175]
  ],
  FJ: [
    [-20, -12, 175, 180],
    [-20, -12, -180, -178]
  ],
  KI: [
    [-13, 5, 172, 180],
    [-13, 5, -180, -150]
  ],
  TV: [
    [-12, -5, 176, 180],
    [-12, -5, -180, -179]
  ],
  WF: [
    [-15, -13, -180, -176],
    [-15, -13, 176, 180]
  ]
};
function isCoordinateConsistentWithCountry(lat, lng, code) {
  if (!isFiniteNumber(lat) || !isFiniteNumber(lng)) return false;
  const key = resolveCode(code);
  if (key === null) return false;
  const geo = COUNTRY_GEO[key];
  const normalisedLng = normaliseLongitude(lng);
  const boxes = ANTIMERIDIAN_BOXES[key];
  if (boxes) {
    return boxes.some(
      ([minLat, maxLat, minLng, maxLng]) => lat >= minLat && lat <= maxLat && normalisedLng >= minLng && normalisedLng <= maxLng
    );
  }
  if (lat < geo.minLat || lat > geo.maxLat) return false;
  if (geo.crossesAntimeridian) return true;
  return normalisedLng >= geo.minLng && normalisedLng <= geo.maxLng;
}

// src/lib/geoFallbacks.ts
var MISSING_TOKENS = /* @__PURE__ */ new Set([
  "",
  "unknown",
  "unavailable",
  "n/a",
  "na",
  "null",
  "undefined",
  "-",
  "xx"
]);
function isMissingGeoValue(value) {
  if (typeof value !== "string") return true;
  return MISSING_TOKENS.has(value.trim().toLowerCase());
}
var COUNTRY_NAME_FALLBACK = {
  AE: "United Arab Emirates",
  AR: "Argentina",
  AT: "Austria",
  AU: "Australia",
  BD: "Bangladesh",
  BE: "Belgium",
  BG: "Bulgaria",
  BR: "Brazil",
  CA: "Canada",
  CH: "Switzerland",
  CL: "Chile",
  CN: "China",
  CO: "Colombia",
  CZ: "Czechia",
  DE: "Germany",
  DK: "Denmark",
  EG: "Egypt",
  ES: "Spain",
  FI: "Finland",
  FR: "France",
  GB: "United Kingdom",
  GR: "Greece",
  HK: "Hong Kong",
  HU: "Hungary",
  ID: "Indonesia",
  IE: "Ireland",
  IL: "Israel",
  IN: "India",
  IT: "Italy",
  JP: "Japan",
  KE: "Kenya",
  KR: "South Korea",
  LK: "Sri Lanka",
  LT: "Lithuania",
  LU: "Luxembourg",
  MY: "Malaysia",
  MX: "Mexico",
  NG: "Nigeria",
  NL: "The Netherlands",
  NO: "Norway",
  NP: "Nepal",
  NZ: "New Zealand",
  PE: "Peru",
  PH: "Philippines",
  PK: "Pakistan",
  PL: "Poland",
  PT: "Portugal",
  RO: "Romania",
  RU: "Russia",
  SA: "Saudi Arabia",
  SE: "Sweden",
  SG: "Singapore",
  SK: "Slovakia",
  TH: "Thailand",
  TR: "Turkey",
  TW: "Taiwan",
  UA: "Ukraine",
  US: "United States",
  VN: "Vietnam",
  ZA: "South Africa"
};
var cachedRegionDisplayNames;
function getRegionDisplayNames() {
  if (cachedRegionDisplayNames !== void 0) return cachedRegionDisplayNames;
  try {
    const ctor = Intl.DisplayNames;
    cachedRegionDisplayNames = ctor ? new ctor(["en"], { type: "region" }) : null;
  } catch {
    cachedRegionDisplayNames = null;
  }
  return cachedRegionDisplayNames;
}
function countryNameFromCode(raw) {
  if (typeof raw !== "string") return "";
  const trimmed = raw.trim();
  if (!trimmed) return "";
  const upper = trimmed.toUpperCase();
  if (upper === "XX" || upper === "T1") return "";
  if (upper.length !== 2) {
    if (isMissingGeoValue(trimmed)) return "";
    return trimmed;
  }
  const fallback = COUNTRY_NAME_FALLBACK[upper];
  try {
    const display = getRegionDisplayNames();
    const resolved = display?.of(upper);
    if (resolved && resolved !== upper) return resolved;
  } catch {
  }
  return fallback || upper;
}
function headerValue(headers, names) {
  for (const name of names) {
    const raw = headers[name] ?? headers[name.toLowerCase()];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}
function decodeCity(raw) {
  if (!raw) return "";
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}
function normalizeAsnLabel(raw) {
  if (typeof raw !== "string") return "";
  const match = raw.trim().match(/^(?:as)?\s*(\d{1,10})$/i);
  return match ? `AS${match[1]}` : "";
}
function parseLat(raw) {
  if (!raw) return null;
  const value = Number.parseFloat(raw);
  return Number.isFinite(value) && Math.abs(value) <= 90 ? value : null;
}
function parseLng(raw) {
  if (!raw) return null;
  const value = Number.parseFloat(raw);
  return Number.isFinite(value) && Math.abs(value) <= 180 ? value : null;
}
function normalizeCountryCode(raw) {
  if (typeof raw !== "string") return "";
  const upper = raw.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(upper)) return "";
  if (upper === "XX" || upper === "T1") return "";
  return upper;
}
function parseEdgeGeoPayload(raw) {
  if (!raw) return null;
  try {
    const decoded = JSON.parse(decodeURIComponent(raw));
    if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) return null;
    return decoded;
  } catch {
    return null;
  }
}
function payloadText(payload, key) {
  const value = payload[key];
  return typeof value === "string" ? value.trim() : "";
}
function readEdgeGeoHeaders(headers) {
  const signedPayload = parseEdgeGeoPayload(headerValue(headers, ["x-intel-edge-geo"]));
  if (signedPayload) {
    const rawCountry = payloadText(signedPayload, "country");
    const isTorNetwork2 = /^t1$/i.test(rawCountry);
    const countryCode2 = normalizeCountryCode(rawCountry);
    const city2 = decodeCity(payloadText(signedPayload, "city"));
    const region2 = payloadText(signedPayload, "region");
    return {
      city: isMissingGeoValue(city2) ? "" : city2,
      region: isMissingGeoValue(region2) ? "" : region2,
      country: countryNameFromCode(countryCode2),
      countryCode: countryCode2,
      timezone: isMissingGeoValue(payloadText(signedPayload, "timezone")) ? "" : payloadText(signedPayload, "timezone"),
      latitude: parseLat(payloadText(signedPayload, "latitude")),
      longitude: parseLng(payloadText(signedPayload, "longitude")),
      asn: normalizeAsnLabel(payloadText(signedPayload, "asn")),
      organization: payloadText(signedPayload, "organization"),
      postalCode: payloadText(signedPayload, "postalCode"),
      isTorNetwork: isTorNetwork2,
      trusted: true,
      source: "cloudflare"
    };
  }
  const vercelCountryCode = headerValue(headers, [
    "x-vercel-ip-country",
    "x-vercel-ip-country-code"
  ]);
  const cloudflareCountryCode = headerValue(headers, ["cf-ipcountry"]);
  const rawCountryCode = vercelCountryCode || cloudflareCountryCode;
  const isTorNetwork = /^t1$/i.test(rawCountryCode);
  const countryCode = normalizeCountryCode(rawCountryCode);
  const city = decodeCity(
    headerValue(headers, ["x-vercel-ip-city"]) || decodeCity(headerValue(headers, ["cf-ipcity"]))
  );
  const region = headerValue(headers, [
    "x-vercel-ip-country-region",
    "cf-region",
    "cf-region-code"
  ]);
  const timezone = headerValue(headers, ["x-vercel-ip-timezone", "cf-timezone"]);
  const latitude = parseLat(headerValue(headers, ["x-vercel-ip-latitude", "cf-iplatitude"]));
  const longitude = parseLng(headerValue(headers, ["x-vercel-ip-longitude", "cf-iplongitude"]));
  const asn = normalizeAsnLabel(
    headerValue(headers, ["x-vercel-ip-as-number", "x-vercel-ip-asn", "cf-asn"])
  );
  const organization = headerValue(headers, ["x-vercel-ip-as-organization"]);
  const postalCode = headerValue(headers, ["x-vercel-ip-postal-code", "cf-postal-code"]);
  const source = headerValue(headers, ["x-vercel-id", "x-vercel-ip-country"]) ? "vercel" : headerValue(headers, ["cf-ipcountry", "cf-ray"]) ? "cloudflare" : "none";
  return {
    city: isMissingGeoValue(city) ? "" : city,
    region: isMissingGeoValue(region) ? "" : region,
    country: countryNameFromCode(countryCode),
    countryCode,
    timezone: isMissingGeoValue(timezone) ? "" : timezone,
    latitude,
    longitude,
    asn,
    organization: isMissingGeoValue(organization) ? "" : organization,
    postalCode: isMissingGeoValue(postalCode) ? "" : postalCode,
    isTorNetwork,
    trusted: false,
    source
  };
}
var CLOUD_ASN_ORG = {
  AS15169: "Google LLC",
  AS396982: "Google Cloud",
  AS19527: "Google LLC",
  AS16591: "Google Fiber",
  AS16509: "Amazon.com, Inc.",
  AS14618: "Amazon.com, Inc.",
  AS8987: "Amazon.com, Inc.",
  AS8075: "Microsoft Corporation",
  AS8068: "Microsoft Corporation",
  AS20940: "Akamai Technologies",
  AS63949: "Akamai / Linode",
  AS13335: "Cloudflare, Inc.",
  AS132892: "Cloudflare, Inc.",
  AS14061: "DigitalOcean, LLC",
  AS24940: "Hetzner Online GmbH",
  AS16276: "OVH SAS",
  AS20473: "Vultr Holdings",
  AS31898: "Oracle Cloud",
  AS45102: "Alibaba Cloud",
  AS132203: "Tencent Cloud",
  AS32934: "Meta Platforms, Inc.",
  AS714: "Apple Inc.",
  AS2906: "Netflix, Inc."
};
function cloudProviderOrgForAsn(rawAsn) {
  const asn = normalizeAsnLabel(rawAsn);
  return asn ? CLOUD_ASN_ORG[asn] || "" : "";
}
function meaningful(value) {
  return typeof value === "string" && !isMissingGeoValue(value);
}
function mergeLocationWithEdge(location, edge) {
  const edgeCountryCode = normalizeCountryCode(edge.countryCode);
  const providerCountryCode = normalizeCountryCode(location.countryCode);
  const countryCode = edgeCountryCode || providerCountryCode;
  const providerCountryAgrees = !edgeCountryCode || !providerCountryCode || edgeCountryCode === providerCountryCode;
  const country = countryNameFromCode(countryCode) || (providerCountryAgrees && meaningful(location.country) ? location.country : "") || edge.country || countryNameFromCode(location.country) || "Unknown";
  const asn = edge.asn || normalizeAsnLabel(location.asn);
  const edgeOrg = meaningful(edge.organization) ? edge.organization : cloudProviderOrgForAsn(edge.asn);
  const providerIspUsable = providerCountryAgrees && meaningful(location.isp);
  const isp = providerIspUsable ? location.isp : edgeOrg || (meaningful(location.org) ? location.org : meaningful(location.isp) ? location.isp : asn ? `Autonomous System ${asn}` : "Unknown");
  const org = meaningful(location.org) && providerCountryAgrees ? location.org : edgeOrg || isp;
  const providerHasCoords = providerCountryAgrees && typeof location.latitude === "number" && typeof location.longitude === "number";
  let latitude = providerHasCoords ? location.latitude : null;
  let longitude = providerHasCoords ? location.longitude : null;
  const providerCoordsUsable = latitude !== null && longitude !== null && (!countryCode || isCoordinateConsistentWithCountry(latitude, longitude, countryCode));
  if (!providerCoordsUsable) {
    latitude = null;
    longitude = null;
  }
  if (latitude === null && edge.latitude !== null && edge.longitude !== null && (!countryCode || isCoordinateConsistentWithCountry(edge.latitude, edge.longitude, countryCode))) {
    latitude = edge.latitude;
    longitude = edge.longitude;
  }
  const providerLocationTrusted = providerCountryAgrees && (!providerHasCoords || providerCoordsUsable) && (!edgeCountryCode || Boolean(providerCountryCode) || providerCoordsUsable);
  const city = providerLocationTrusted && meaningful(location.city) ? location.city : edge.city || "Unknown";
  const region = providerLocationTrusted && meaningful(location.region) ? location.region : edge.region || "Unknown";
  const timezone = meaningful(location.timezone) ? location.timezone : edge.timezone || void 0;
  const locationPrecision = meaningful(city) && !isMissingGeoValue(city) ? "city" : meaningful(region) && !isMissingGeoValue(region) ? "region" : countryCode ? "country" : "unknown";
  const hasCountry = Boolean(countryCode) || meaningful(country) && country !== "Unknown";
  return {
    ...location,
    city,
    region,
    country,
    countryCode: countryCode.toUpperCase(),
    latitude,
    longitude,
    timezone,
    isp,
    org,
    asn,
    isTor: Boolean(location.isTor) || edge.isTorNetwork,
    isTorExit: Boolean(location.isTorExit) || edge.isTorNetwork,
    locationSource: edgeCountryCode ? "edge" : location.locationSource ?? "provider",
    locationPrecision,
    isLocationVerified: hasCountry
  };
}

// src/lib/geohash.ts
var GEOHASH_BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz";
function isValidCoordinate(latitude, longitude) {
  return typeof latitude === "number" && typeof longitude === "number" && Number.isFinite(latitude) && Number.isFinite(longitude) && Math.abs(latitude) <= 90 && Math.abs(longitude) <= 180;
}
function encodeGeohash(latitude, longitude, precision = 6) {
  if (!isValidCoordinate(latitude, longitude)) return null;
  const chars = Math.max(1, Math.min(12, Math.floor(precision)));
  let latMin = -90;
  let latMax = 90;
  let lonMin = -180;
  let lonMax = 180;
  let hash = "";
  let bits = 0;
  let bitCount = 0;
  let even = true;
  while (hash.length < chars) {
    if (even) {
      const mid = (lonMin + lonMax) / 2;
      if (longitude >= mid) {
        bits = bits << 1 | 1;
        lonMin = mid;
      } else {
        bits = bits << 1;
        lonMax = mid;
      }
    } else {
      const mid = (latMin + latMax) / 2;
      if (latitude >= mid) {
        bits = bits << 1 | 1;
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
function formatCoordinatePair(latitude, longitude) {
  if (!isValidCoordinate(latitude, longitude)) return "";
  const lat = `${Math.abs(latitude).toFixed(2)}\xB0${latitude >= 0 ? "N" : "S"}`;
  const lon = `${Math.abs(longitude).toFixed(2)}\xB0${longitude >= 0 ? "E" : "W"}`;
  return `${lat}, ${lon}`;
}
function buildProximityInfo(latitude, longitude) {
  const geohash = encodeGeohash(latitude, longitude, 6);
  if (!geohash) {
    return {
      id: "prox_unresolved",
      geohash: null,
      zone_label: "Zone Unresolved (IP-only)",
      precision_radius: 5e3,
      confidence: 0,
      resolved: false
    };
  }
  const coords = formatCoordinatePair(latitude, longitude);
  return {
    id: `prox_${geohash}`,
    geohash,
    zone_label: `Zone ${geohash}${coords ? ` \xB7 ${coords}` : ""}`,
    precision_radius: 5e3,
    confidence: 0.92,
    resolved: true
  };
}

// src/lib/aiBotDirectory.ts
var BOT_DIRECTORY = [
  // OpenAI - verified (CIDR/FCrDNS verified)
  {
    name: "ChatGPT-User",
    provider: "OpenAI",
    category: "ai_assistant",
    identity: "verified",
    uaPatterns: [/ChatGPT-User/i]
  },
  {
    name: "OAI-SearchBot",
    provider: "OpenAI",
    category: "ai_search",
    identity: "verified",
    uaPatterns: [/OAI-SearchBot/i]
  },
  {
    name: "GPTBot",
    provider: "OpenAI",
    category: "ai_crawler",
    identity: "verified",
    uaPatterns: [/GPTBot/i]
  },
  // OpenAI - signed (Web Bot Auth)
  {
    name: "ChatGPT Agent",
    provider: "OpenAI",
    category: "ai_agent",
    identity: "signed",
    requiresWebBotAuth: true,
    asnPatterns: [/openai|azure/i],
    uaPatterns: [/ChatGPT-Agent/i]
  },
  // OpenAI - unknown
  {
    name: "Codex",
    provider: "OpenAI",
    category: "ai_agent",
    identity: "unknown",
    uaPatterns: [/\bCodex\b/i]
  },
  // Google - verified
  {
    name: "Gemini Deep Research",
    provider: "Google",
    category: "ai_agent",
    identity: "verified",
    asnNumbers: [15169, 396982],
    asnPatterns: [/google llc|google cloud|AS15169|AS396982/i],
    uaPatterns: [/Googlebot|Google-Extended|Google-Agent|Mariner|Gemini/i]
  },
  {
    name: "Google-Agent",
    provider: "Google",
    category: "ai_agent",
    identity: "verified",
    uaPatterns: [/Google-Agent/i]
  },
  {
    name: "Google NotebookLM",
    provider: "Google",
    category: "ai_assistant",
    identity: "verified",
    uaPatterns: [/NotebookLM/i]
  },
  // Anthropic - verified
  {
    name: "Claude-User",
    provider: "Anthropic",
    category: "ai_assistant",
    identity: "verified",
    uaPatterns: [/Claude-User/i]
  },
  {
    name: "Claude-SearchBot",
    provider: "Anthropic",
    category: "ai_search",
    identity: "verified",
    uaPatterns: [/Claude-SearchBot/i]
  },
  {
    name: "ClaudeBot",
    provider: "Anthropic",
    category: "ai_crawler",
    identity: "verified",
    uaPatterns: [/ClaudeBot/i]
  },
  // Anthropic - unknown
  {
    name: "Claude Code",
    provider: "Anthropic",
    category: "ai_agent",
    identity: "unknown",
    uaPatterns: [/Claude Code|claude-code/i]
  },
  {
    name: "Claude Duet",
    provider: "Anthropic",
    category: "ai_agent",
    identity: "unknown",
    uaPatterns: [/Claude-Duet|claude-duet/i]
  },
  // Perplexity - verified
  {
    name: "Perplexity-User",
    provider: "Perplexity",
    category: "ai_assistant",
    identity: "verified",
    uaPatterns: [/Perplexity-User/i]
  },
  {
    name: "PerplexityBot",
    provider: "Perplexity",
    category: "ai_search",
    identity: "verified",
    uaPatterns: [/PerplexityBot/i]
  },
  // Meta
  {
    name: "Muse",
    provider: "Meta",
    category: "ai_agent",
    identity: "unknown",
    asnNumbers: [32934],
    asnPatterns: [/meta platforms|AS32934/i],
    uaPatterns: [/\bMuse\b/i]
  },
  {
    name: "Meta-ExternalAgent",
    provider: "Meta",
    category: "ai_search",
    identity: "verified",
    uaPatterns: [/Meta-ExternalAgent|meta-externalagent/i]
  },
  {
    name: "Meta-WebIndexer",
    provider: "Meta",
    category: "ai_search",
    identity: "verified",
    uaPatterns: [/Meta-WebIndexer/i]
  },
  // xAI
  {
    name: "Grok Bot",
    provider: "xAI",
    category: "ai_agent",
    identity: "unknown",
    uaPatterns: [/Grok-Bot|GrokBot|grok/i]
  },
  // Cloud Browser Agents - signed
  {
    name: "Browserbase Agent",
    provider: "Browserbase",
    category: "ai_agent",
    identity: "signed",
    uaPatterns: [/Browserbase/i],
    requiresWebBotAuth: true
  },
  {
    name: "Bedrock AgentCore",
    provider: "AWS",
    category: "ai_agent",
    identity: "signed",
    asnNumbers: [16509, 14618],
    uaPatterns: [/BedrockAgentCore|bedrock-agent/i]
  },
  {
    name: "Anchor Browser",
    provider: "Anchor",
    category: "ai_browser",
    identity: "signed",
    uaPatterns: [/AnchorBrowser|anchor-browser/i]
  },
  {
    name: "Notte Browser",
    provider: "Notte",
    category: "ai_browser",
    identity: "signed",
    uaPatterns: [/NotteBrowser|notte/i]
  },
  {
    name: "Manus Agent",
    provider: "Manus",
    category: "ai_agent",
    identity: "signed",
    uaPatterns: [/ManusAgent|manus-agent/i]
  },
  {
    name: "AGI Agent",
    provider: "AGI Inc",
    category: "ai_agent",
    identity: "signed",
    uaPatterns: [/AGIAgent|agi-agent/i]
  },
  // Other - unknown
  {
    name: "Cursor",
    provider: "Anysphere",
    category: "ai_agent",
    identity: "unknown",
    uaPatterns: [/\bCursor\b/i],
    headerPatterns: [{ header: "x-cursor-agent", pattern: /.*/ }]
  },
  {
    name: "DuckAssistBot",
    provider: "DuckDuckGo",
    category: "ai_assistant",
    identity: "verified",
    uaPatterns: [/DuckAssistBot/i]
  },
  {
    name: "Kimi-User",
    provider: "Moonshot AI",
    category: "ai_assistant",
    identity: "verified",
    uaPatterns: [/Kimi-User/i]
  },
  {
    name: "Cloudflare Browser Rendering",
    provider: "Cloudflare",
    category: "browser_automation",
    identity: "unknown",
    asnNumbers: [13335],
    uaPatterns: [/CloudflareBot|cf-browser/i]
  },
  {
    name: "Instinct",
    provider: "Spear Street Technology",
    category: "ai_agent",
    identity: "unknown",
    uaPatterns: [/\bInstinct\b/i]
  }
];
function detectAiBotFromServerSignals(params) {
  const { userAgent, asnNumber, asnOrg, headers } = params;
  const ua = userAgent || "";
  const signatureAgent = headers["signature-agent"] || "";
  const signatureInput = headers["signature-input"] || "";
  const signature = headers["signature"] || "";
  const hasWebBotAuth = Boolean(signatureAgent && signatureInput && signature);
  const networkKnown = asnNumber !== null || Boolean(asnOrg.trim()) && !/^unknown\b/i.test(asnOrg.trim());
  for (const entry of BOT_DIRECTORY) {
    let matched = false;
    let claimedByUaOrHeader = false;
    if (entry.uaPatterns) {
      for (const pattern of entry.uaPatterns) {
        if (pattern.test(ua)) {
          matched = true;
          claimedByUaOrHeader = true;
          break;
        }
      }
    }
    if (!matched && asnNumber !== null && entry.asnNumbers) {
      if (entry.asnNumbers.includes(asnNumber)) {
        matched = true;
      }
    }
    if (!matched && entry.asnPatterns) {
      for (const pattern of entry.asnPatterns) {
        if (pattern.test(asnOrg)) {
          matched = true;
          break;
        }
      }
    }
    if (!matched && entry.headerPatterns) {
      for (const { header, pattern } of entry.headerPatterns) {
        const hVal = headers[header] || "";
        if (hVal && pattern.test(hVal)) {
          matched = true;
          claimedByUaOrHeader = true;
          break;
        }
      }
    }
    if (matched) {
      let identity = entry.identity;
      const networkMatches = asnNumber !== null && Boolean(entry.asnNumbers?.includes(asnNumber)) || Boolean(entry.asnPatterns?.some((pattern) => pattern.test(asnOrg)));
      if (identity === "verified") {
        if (!claimedByUaOrHeader) {
          identity = "unknown";
        } else if (!networkMatches) {
          identity = hasWebBotAuth ? "verified" : networkKnown ? "spoofed" : "unknown";
        }
      }
      if (identity === "unknown" && hasWebBotAuth) {
        identity = "signed";
      }
      return {
        detected: true,
        botType: entry.category,
        botInfo: {
          category: entry.category,
          provider: entry.provider,
          name: identity === "spoofed" ? `Spoofed ${entry.name}` : entry.name,
          identity
        }
      };
    }
  }
  if (/HeadlessChrome|Headless/i.test(ua)) {
    return {
      detected: true,
      botType: "browser_automation",
      botInfo: {
        category: "browser_automation",
        provider: "Unknown",
        name: "Headless Browser",
        identity: "unknown"
      }
    };
  }
  if (/Playwright|puppeteer|selenium|PhantomJS|Sequentum/i.test(ua)) {
    return {
      detected: true,
      botType: "browser_automation",
      botInfo: {
        category: "browser_automation",
        provider: "Unknown",
        name: "Browser Automation",
        identity: "unknown"
      }
    };
  }
  return { detected: false, botType: null, botInfo: null };
}

// src/server/middleware/clientHints.ts
var CLIENT_HINT_ACCEPT_CH = "Sec-CH-UA, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-Mobile";
var CLIENT_HINT_CRITICAL_CH = "Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List";
var EMPTY_HINTS = {
  brands: [],
  platform: "",
  platformVersion: "",
  architecture: "",
  bitness: "",
  model: "",
  mobile: "",
  fullVersionList: []
};
function readHeaderValue(headers, name) {
  const raw = headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === "string" ? value : "";
}
function unquote(value) {
  let text = value.trim();
  if (text.length >= 2) {
    const first = text[0];
    const last = text[text.length - 1];
    if (first === '"' && last === '"' || first === "'" && last === "'") text = text.slice(1, -1);
  }
  return text.trim();
}
function unescapeToken(value) {
  return value.replace(/\\(.)/g, "$1").trim();
}
function parseBrandList(raw) {
  const brands = [];
  const text = typeof raw === "string" ? raw.trim() : "";
  if (!text) return brands;
  for (const part of text.split(",")) {
    const entry = part.trim();
    if (!entry) continue;
    const match = /^(?:"((?:[^"\\]|\\.)*)"|([^";]*))\s*;\s*v\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^";]*))\s*$/.exec(entry);
    if (!match) continue;
    const brand = match[1] !== void 0 ? unescapeToken(match[1]) : match[2].trim();
    const version = match[3] !== void 0 ? unescapeToken(match[3]) : (match[4] ?? "").trim();
    if (!brand) continue;
    brands.push({ brand, version });
  }
  return brands;
}
function parseMobile(raw) {
  const text = typeof raw === "string" ? raw.trim() : "";
  if (!text) return "";
  const token = text.replace(/^\?/, "").trim();
  if (token === "1") return "true";
  if (token === "0") return "false";
  return token;
}
function parseClientHintHeaders(headers) {
  try {
    const bag = headers ?? {};
    const brands = parseBrandList(readHeaderValue(bag, "sec-ch-ua"));
    const fullVersionList = parseBrandList(readHeaderValue(bag, "sec-ch-ua-full-version-list"));
    return {
      brands,
      platform: unquote(readHeaderValue(bag, "sec-ch-ua-platform")),
      platformVersion: unquote(readHeaderValue(bag, "sec-ch-ua-platform-version")),
      architecture: unquote(readHeaderValue(bag, "sec-ch-ua-arch")),
      bitness: unquote(readHeaderValue(bag, "sec-ch-ua-bitness")),
      model: unquote(readHeaderValue(bag, "sec-ch-ua-model")),
      mobile: parseMobile(readHeaderValue(bag, "sec-ch-ua-mobile")),
      fullVersionList
    };
  } catch {
    return { ...EMPTY_HINTS, brands: [], fullVersionList: [] };
  }
}
function clientHintsMiddleware(req, res, next) {
  try {
    if (!res.getHeader("Accept-CH")) res.setHeader("Accept-CH", CLIENT_HINT_ACCEPT_CH);
    if (!res.getHeader("Critical-CH")) res.setHeader("Critical-CH", CLIENT_HINT_CRITICAL_CH);
    req.intelClientHints = parseClientHintHeaders(req.headers);
  } catch {
  }
  next();
}

// src/shared/normalization/uaNormalizer.ts
var GREASE_RE = /not.?a.?brand/i;
var CHROMIUM_PLACEHOLDER = "chromium";
function parseBrandList2(raw) {
  const out = [];
  if (!raw) return out;
  const re = /"([^"]*)"\s*;\s*v\s*=\s*"([^"]*)"/g;
  let m = re.exec(raw);
  while (m !== null) {
    const brand = (m[1] ?? "").trim();
    if (brand) out.push({ brand, version: (m[2] ?? "").trim() });
    m = re.exec(raw);
  }
  return out;
}
function filterBrands(brands) {
  const real = brands.filter((b) => !GREASE_RE.test(b.brand));
  const nonChromium = real.filter((b) => b.brand.toLowerCase() !== CHROMIUM_PLACEHOLDER);
  return nonChromium.length > 0 ? nonChromium : real;
}
function headerValue2(secCh, name) {
  if (!secCh) return "";
  const lower = name.toLowerCase();
  for (const key of Object.keys(secCh)) {
    if (key.toLowerCase() === lower) {
      const v = secCh[key];
      return typeof v === "string" ? v : "";
    }
  }
  return "";
}
function unquote2(value) {
  const v = value.trim();
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) return v.slice(1, -1);
  return v;
}
function parseSecCh(secCh) {
  const fullListRaw = headerValue2(secCh, "sec-ch-ua-full-version-list");
  const majorListRaw = headerValue2(secCh, "sec-ch-ua");
  const brands = fullListRaw ? parseBrandList2(fullListRaw) : parseBrandList2(majorListRaw);
  return {
    brands: filterBrands(brands),
    hasFullVersionList: Boolean(fullListRaw),
    platform: unquote2(headerValue2(secCh, "sec-ch-ua-platform")),
    platformVersion: unquote2(headerValue2(secCh, "sec-ch-ua-platform-version")),
    model: unquote2(headerValue2(secCh, "sec-ch-ua-model")),
    architecture: unquote2(headerValue2(secCh, "sec-ch-ua-arch")),
    bitness: unquote2(headerValue2(secCh, "sec-ch-ua-bitness")),
    formFactors: unquote2(headerValue2(secCh, "sec-ch-ua-form-factors")).split(",").map((f) => unquote2(f)).filter((f) => f.length > 0)
  };
}
var BROWSER_SPECS = [
  {
    name: "Cursor",
    brands: ["cursor"],
    uaTokens: [/Cursor\/([\d.]+)/]
  },
  {
    name: "Manus",
    brands: ["manus"],
    uaTokens: [/Manus-User\/([\d.]+)/]
  },
  {
    name: "Microsoft Edge",
    brands: ["microsoft edge"],
    uaTokens: [/EdgA?\/([\d.]+)/, /EdgiOS\/([\d.]+)/, /Edge\/([\d.]+)/]
  },
  {
    name: "Opera",
    brands: ["opera", "opera gx"],
    uaTokens: [/OPR\/([\d.]+)/, /OPX\/([\d.]+)/]
  },
  {
    name: "Brave",
    brands: ["brave"],
    uaTokens: [/Brave\/([\d.]+)/]
  },
  {
    name: "Samsung Internet",
    brands: ["samsung internet"],
    uaTokens: [/SamsungBrowser\/([\d.]+)/]
  },
  {
    name: "Headless Chrome",
    brands: ["headlesschrome"],
    uaTokens: [/HeadlessChrome\/([\d.]+)/]
  },
  {
    name: "Google Chrome",
    brands: ["google chrome", "chrome"],
    uaTokens: [/CriOS\/([\d.]+)/, /Chrome\/([\d.]+)/]
  },
  {
    name: "Chromium",
    brands: [CHROMIUM_PLACEHOLDER],
    uaTokens: [/Chrome\/([\d.]+)/]
  },
  {
    name: "Firefox",
    brands: ["firefox"],
    uaTokens: [/FxiOS\/([\d.]+)/, /Firefox\/([\d.]+)/]
  },
  {
    name: "Safari",
    brands: ["safari"],
    uaTokens: [/Version\/([\d.]+).*Safari/]
  }
];
function firstMatch(token, ua) {
  const m = token.exec(ua);
  if (m === null) return null;
  return (m[1] ?? "").trim() || null;
}
function brandToSpec(brands) {
  for (const spec of BROWSER_SPECS) {
    for (const entry of brands) {
      if (spec.brands.indexOf(entry.brand.toLowerCase()) !== -1) return spec;
    }
  }
  return null;
}
function uaToSpec(ua) {
  for (const spec of BROWSER_SPECS) {
    for (const token of spec.uaTokens) {
      if (token.test(ua)) return spec;
    }
  }
  return null;
}
function tokensForName(name) {
  const spec = BROWSER_SPECS.find((s) => s.name === name);
  if (spec) return spec.uaTokens;
  if (name === "Manus") return [/Manus-User\/([\d.]+)/];
  return [];
}
function pickFullerVersion(preferred, candidate) {
  if (!candidate) return preferred;
  if (!preferred) return candidate;
  const a = preferred.split(".").length;
  const b = candidate.split(".").length;
  return b > a ? candidate : preferred;
}
function resolveBrowser(ua, uad, secCh) {
  const empty = { name: "Unknown", full: "", major: "" };
  const uadBrands = filterBrands((uad?.fullVersionList ?? []).filter((b) => !!b));
  const candidates = [];
  if (uadBrands.length > 0) candidates.push({ brands: uadBrands, source: "uad" });
  if (secCh.brands.length > 0) candidates.push({ brands: secCh.brands, source: "secch" });
  for (const candidate of candidates) {
    const spec = brandToSpec(candidate.brands);
    if (!spec) continue;
    const entry = candidate.brands.find(
      (b) => spec.brands.indexOf(b.brand.toLowerCase()) !== -1
    );
    let version = entry ? entry.version : "";
    if (version && version.indexOf(".") === -1) {
      version = pickFullerVersion(version, findUaVersion(spec, ua));
    }
    if (!version) version = findUaVersion(spec, ua) ?? "";
    return { name: spec.name, full: version, major: majorOf(version) };
  }
  const uaSpec = ua ? uaToSpec(ua) : null;
  if (uaSpec) {
    const version = findUaVersion(uaSpec, ua) ?? "";
    return { name: uaSpec.name, full: version, major: majorOf(version) };
  }
  const uaFull = (uad?.uaFullVersion ?? "").trim();
  if (uaFull) return { name: "Unknown", full: uaFull, major: majorOf(uaFull) };
  return empty;
}
function findUaVersion(spec, ua) {
  for (const token of spec.uaTokens) {
    const v = firstMatch(token, ua);
    if (v) return v;
  }
  return null;
}
function majorOf(version) {
  if (!version) return "";
  const major = version.split(".")[0];
  return /^\d+$/.test(major) ? major : "";
}
function versionSourceExists(ua, uad, secCh) {
  if ((uad?.fullVersionList ?? []).length > 0) return true;
  if ((uad?.uaFullVersion ?? "").trim()) return true;
  if (secCh.brands.length > 0) return true;
  return ua ? uaToSpec(ua) !== null : false;
}
function fallbackMajorFromUa(browserName, ua) {
  if (!ua) return { name: browserName, full: "", major: "" };
  const tokens = [...tokensForName(browserName)];
  for (const spec of BROWSER_SPECS) {
    for (const token of spec.uaTokens) {
      if (tokens.indexOf(token) === -1) tokens.push(token);
    }
  }
  for (const token of tokens) {
    const v = firstMatch(token, ua);
    if (v) return { name: browserName, full: v, major: majorOf(v) };
  }
  return { name: browserName, full: "", major: "" };
}
function parseIntSafe(value) {
  const m = /^\s*(\d+)/.exec(value ?? "");
  if (m === null) return null;
  const n = parseInt(m[1], 10);
  return isFinite(n) ? n : null;
}
function windowsVersionFromPlatformVersion(pv) {
  const parts = (pv ?? "").trim().split(".");
  const major = parseIntSafe(parts[0] ?? "");
  if (major === null) return null;
  if (major >= 13) return "11";
  if (major >= 1) return "10";
  const sub = parseIntSafe(parts[1] ?? "");
  if (sub === 1) return "7";
  if (sub === 2) return "8";
  if (sub === 3) return "8.1";
  return null;
}
function windowsVersionFromUa(ua) {
  const m = /Windows NT ([\d.]+)/.exec(ua);
  if (m === null) return null;
  const nt = m[1];
  if (nt === "6.1") return "7";
  if (nt === "6.2") return "8";
  if (nt === "6.3") return "8.1";
  if (nt === "10.0") return "10";
  return null;
}
function underscoresToDots(v) {
  return v.replace(/_/g, ".");
}
function macVersionFromSafariUa(ua) {
  const safari = /Version\/(\d+)(?:\.(\d+))?.*Safari/.exec(ua);
  if (safari === null) return null;
  const safariMajor = parseIntSafe(safari[1] ?? "");
  if (safariMajor === null) return null;
  const macMajor = safariMajor - 3;
  if (macMajor <= 10) return "10.15";
  return `${macMajor}.0`;
}
function looksAndroidTablet(model, formFactors) {
  if (formFactors.map((f) => f.toLowerCase()).indexOf("tablet") !== -1) return true;
  return /\b(tab|pad|sm-t|nexus 9|nexus 10|pixel c)\b/i.test(model);
}
function androidModelFromUa(ua) {
  const m = /Android[^;)]*;\s*([^;)]+?)\s*(?:Build\/|\))/.exec(ua);
  const raw = m === null ? "" : (m[1] ?? "").trim();
  if (!raw || raw.toLowerCase() === "wv") return "";
  return raw;
}
function resolveOs(ua, platformStr, touch, uad, secCh) {
  const uadPlatform = (uad?.platform ?? "").trim();
  const uadPv = (uad?.platformVersion ?? "").trim();
  const formFactors = [...uad?.formFactors ?? [], ...secCh.formFactors];
  const uaIosPhone = /(?:iPhone|iPod)/.test(ua);
  const uaIpad = /iPad/.test(ua);
  const macTouch = touch > 1 && (/macintel/i.test(platformStr) || /macintosh/i.test(ua));
  const macTabletFormFactor = uadPlatform.toLowerCase() === "macos" && formFactors.map((f) => f.toLowerCase()).indexOf("tablet") !== -1;
  if (uaIosPhone || uaIpad || macTouch || macTabletFormFactor) {
    let osVersion = "";
    const m = /(?:iPhone|iPad|iPod)[\s\S]*?OS (\d+(?:[_\d]*)?)\s+like/.exec(ua);
    if (m !== null && m[1]) {
      osVersion = underscoresToDots(m[1]);
    } else if (macTabletFormFactor && uadPv) {
      osVersion = underscoresToDots(uadPv);
    }
    const device = uaIpad || macTouch || macTabletFormFactor ? "Tablet" : "Mobile";
    return {
      os: "iOS",
      os_version: osVersion,
      platformFamily: "ios",
      device,
      device_model: (uad?.model ?? "").trim()
    };
  }
  if (uadPlatform === "Android" || secCh.platform === "Android" || /Android/.test(ua)) {
    let osVersion = "";
    let model = (uad?.model ?? "").trim() || secCh.model;
    if (uadPlatform === "Android" || secCh.platform === "Android") {
      const major = parseIntSafe(uadPv || secCh.platformVersion);
      if (major !== null) osVersion = String(major);
    }
    if (!osVersion) {
      const m = /Android\s+([\d.]+)/.exec(ua);
      if (m !== null) osVersion = majorOf(m[1]);
    }
    if (!model) model = androidModelFromUa(ua);
    const device = looksAndroidTablet(model, formFactors) ? "Tablet" : "Mobile";
    return {
      os: "Android",
      os_version: osVersion,
      platformFamily: "android",
      device,
      device_model: model
    };
  }
  if (uadPlatform === "Windows" || secCh.platform === "Windows" || /Windows NT/.test(ua)) {
    let osVersion = windowsVersionFromPlatformVersion(uadPv) ?? windowsVersionFromPlatformVersion(secCh.platformVersion);
    if (!osVersion) osVersion = windowsVersionFromUa(ua);
    return {
      os: "Windows",
      os_version: osVersion ?? "",
      platformFamily: "windows",
      device: "Desktop",
      device_model: ""
    };
  }
  if (uadPlatform === "macOS" || secCh.platform === "macOS" || /Mac OS X|Macintosh/.test(ua)) {
    let osVersion = uadPv || secCh.platformVersion;
    if (!osVersion) {
      const m = /Mac OS X ([\d_]+)/.exec(ua);
      if (m !== null && m[1]) osVersion = underscoresToDots(m[1]);
    }
    if (!osVersion) osVersion = macVersionFromSafariUa(ua) ?? "";
    return {
      os: "Mac OS X",
      os_version: osVersion,
      platformFamily: "mac",
      device: "Desktop",
      device_model: ""
    };
  }
  if (uadPlatform === "Linux" || uadPlatform === "Chrome OS" || secCh.platform === "Linux" || secCh.platform === "Chrome OS" || /Linux/.test(ua)) {
    let osVersion = "";
    if (uadPlatform === "Linux" || uadPlatform === "Chrome OS") {
      const major = parseIntSafe(uadPv);
      if (major !== null) osVersion = String(major);
    } else if (secCh.platform === "Linux" || secCh.platform === "Chrome OS") {
      const major = parseIntSafe(secCh.platformVersion);
      if (major !== null) osVersion = String(major);
    }
    return {
      os: "Linux",
      os_version: osVersion,
      platformFamily: "linux",
      device: "Desktop",
      device_model: ""
    };
  }
  const p = platformStr.trim();
  if (/^Win(?:dows)?(32|64|NT)?$/i.test(p)) {
    return { os: "Windows", os_version: "", platformFamily: "windows", device: "Desktop", device_model: "" };
  }
  if (/^Mac/i.test(p)) {
    return { os: "Mac OS X", os_version: "", platformFamily: "mac", device: "Desktop", device_model: "" };
  }
  if (/^Linux/i.test(p)) {
    return { os: "Linux", os_version: "", platformFamily: "linux", device: "Desktop", device_model: "" };
  }
  if (/iPhone|iPod/i.test(p)) {
    return { os: "iOS", os_version: "", platformFamily: "ios", device: "Mobile", device_model: "" };
  }
  if (/iPad/i.test(p)) {
    return { os: "iOS", os_version: "", platformFamily: "ios", device: "Tablet", device_model: "" };
  }
  return {
    os: "Unknown",
    os_version: "",
    platformFamily: "unknown",
    device: "Unknown",
    device_model: ""
  };
}
function resolveArchitecture(ua, platformStr, uad, secCh) {
  const arch = (uad?.architecture ?? secCh.architecture ?? "").trim().toLowerCase();
  const bit = (uad?.bitness ?? secCh.bitness ?? "").trim();
  const wow64 = uad?.wow64 === true;
  if (arch.indexOf("arm") !== -1) {
    return { architecture: bit === "32" ? "ARM" : "ARM64", bitness: bit === "32" ? "32" : "64" };
  }
  if (arch.indexOf("x86") !== -1 || arch === "amd64" || arch === "x64" || arch === "ia64") {
    return { architecture: bit === "32" ? "x86" : "x86_64", bitness: bit === "32" ? "32" : "64" };
  }
  if (wow64) {
    return { architecture: "x86_64", bitness: "64" };
  }
  const hay = `${ua} ${platformStr}`.toLowerCase();
  if (/arm64|aarch64|armv8/.test(hay)) return { architecture: "ARM64", bitness: "64" };
  if (/x86_64|x64|win64|wow64|amd64/.test(hay)) return { architecture: "x86_64", bitness: "64" };
  if (/armv[3-7]|arm;/.test(hay)) return { architecture: "ARM", bitness: "32" };
  if (/i[3456]86|x86\b/.test(hay)) return { architecture: "x86", bitness: "32" };
  return { architecture: "", bitness: bit === "32" || bit === "64" ? bit : "" };
}
function sanitizeOs(os2, osVersion) {
  let o = (os2 ?? "").trim();
  let v = (osVersion ?? "").trim();
  if (o && /\d/.test(o)) {
    const m = /^([^\d]+?)\s*([\d][\d.]*)$/.exec(o);
    if (m !== null && m[1].trim()) {
      o = m[1].trim();
      if (!v) v = m[2];
    } else {
      o = "Unknown";
    }
  }
  if (v && o && v === o) v = "";
  return { os: o, osVersion: v };
}
var BLANK_IDENTITY = {
  os: "Unknown",
  os_version: "",
  browser_name: "Unknown",
  browser_major_version: "",
  browser_full_version: "",
  device: "Unknown",
  device_model: "",
  architecture: "",
  bitness: "",
  platformFamily: "unknown"
};
function normalizeIdentity(input) {
  try {
    const ua = (input?.userAgent ?? "").toString();
    const platformStr = (input?.platform ?? "").toString();
    const rawTouch = input?.maxTouchPoints;
    const touch = typeof rawTouch === "number" && isFinite(rawTouch) ? rawTouch : 0;
    const uad = input?.uaData ?? null;
    const secCh = parseSecCh(input?.secCh);
    const osRes = resolveOs(ua, platformStr, touch, uad, secCh);
    const browser = resolveBrowser(ua, uad, secCh);
    const archRes = resolveArchitecture(ua, platformStr, uad, secCh);
    const identity = {
      os: osRes.os,
      os_version: osRes.os_version,
      browser_name: browser.name,
      browser_major_version: browser.major,
      browser_full_version: browser.full,
      device: osRes.device,
      device_model: osRes.device_model,
      architecture: archRes.architecture,
      bitness: archRes.bitness,
      platformFamily: osRes.platformFamily
    };
    if (versionSourceExists(ua, uad, secCh) && !identity.browser_major_version) {
      const fallback = fallbackMajorFromUa(identity.browser_name, ua);
      if (fallback.major) {
        identity.browser_full_version = fallback.full;
        identity.browser_major_version = fallback.major;
      }
    }
    const safe = sanitizeOs(identity.os, identity.os_version);
    identity.os = safe.os;
    identity.os_version = safe.osVersion;
    return identity;
  } catch {
    return { ...BLANK_IDENTITY };
  }
}
var BLANK_USER_AGENT = {
  os: "Unknown",
  osVersion: "",
  device: "Unknown",
  browserName: "Unknown",
  browserMajorVersion: "",
  browserFullVersion: "",
  architecture: "",
  bitness: "",
  model: ""
};
function serializeBrandList(brands) {
  return brands.filter((entry) => entry && typeof entry.brand === "string").map((entry) => `"${entry.brand}";v="${entry.version ?? ""}"`).join(", ");
}
function readBagKey(hints, key) {
  const bag = hints;
  const direct = bag[key];
  if (typeof direct === "string") return direct;
  const lower = key.toLowerCase();
  for (const candidate of Object.keys(bag)) {
    if (candidate.toLowerCase() === lower) {
      const value = bag[candidate];
      if (typeof value === "string") return value;
    }
  }
  return "";
}
function hintFromBag(hints, name) {
  const bag = hints;
  const structured = bag[name];
  if (typeof structured === "string") return unquote2(structured);
  const headerKey = `sec-ch-ua-${name.replace(/([A-Z])/g, "-$1").toLowerCase()}`;
  return unquote2(readBagKey(hints, headerKey));
}
function brandsFromValue(value) {
  if (Array.isArray(value)) {
    return value.filter((entry) => Boolean(entry) && typeof entry.brand === "string").map((entry) => ({ brand: entry.brand, version: String(entry.version ?? "") }));
  }
  if (typeof value === "string") return parseBrandList2(value);
  return [];
}
function coerceClientHints(hints) {
  if (!hints || typeof hints !== "object") return { uaData: null, secCh: void 0 };
  const fullVersionList = brandsFromValue(
    hints.fullVersionList && (Array.isArray(hints.fullVersionList) ? hints.fullVersionList.length > 0 : true) ? hints.fullVersionList : readBagKey(hints, "sec-ch-ua-full-version-list")
  );
  const brands = brandsFromValue(
    hints.brands && (Array.isArray(hints.brands) ? hints.brands.length > 0 : true) ? hints.brands : readBagKey(hints, "sec-ch-ua")
  );
  const platform = hintFromBag(hints, "platform");
  const platformVersion = hintFromBag(hints, "platformVersion");
  const architecture = hints.architecture || hintFromBag(hints, "arch");
  const bitness = hints.bitness ?? hintFromBag(hints, "bitness");
  const model = hints.model ?? hintFromBag(hints, "model");
  const mobileRaw = hints.mobile;
  const mobile = typeof mobileRaw === "boolean" ? mobileRaw : String(mobileRaw ?? hintFromBag(hints, "mobile")) === "?1";
  const secCh = {};
  if (brands.length > 0) secCh["sec-ch-ua"] = serializeBrandList(brands);
  if (fullVersionList.length > 0) {
    secCh["sec-ch-ua-full-version-list"] = serializeBrandList(fullVersionList);
  }
  if (platform) secCh["sec-ch-ua-platform"] = `"${platform}"`;
  if (platformVersion) secCh["sec-ch-ua-platform-version"] = `"${platformVersion}"`;
  if (architecture) secCh["sec-ch-ua-arch"] = `"${architecture}"`;
  if (bitness) secCh["sec-ch-ua-bitness"] = `"${bitness}"`;
  if (model) secCh["sec-ch-ua-model"] = `"${model}"`;
  if (hints.formFactors && hints.formFactors.length > 0) {
    secCh["sec-ch-ua-form-factors"] = hints.formFactors.map((f) => `"${f}"`).join(", ");
  }
  const uaData = {
    fullVersionList,
    platform,
    platformVersion,
    architecture,
    bitness,
    model,
    formFactors: hints.formFactors,
    uaFullVersion: hints.uaFullVersion,
    wow64: hints.wow64
  };
  return { uaData, secCh: Object.keys(secCh).length > 0 ? secCh : void 0 };
}
function normalizeUserAgent(input) {
  try {
    const { uaData, secCh } = coerceClientHints(input?.clientHints);
    const identity = normalizeIdentity({
      userAgent: input?.userAgent ?? "",
      platform: input?.platform ?? "",
      maxTouchPoints: input?.maxTouchPoints,
      uaData,
      secCh
    });
    const mobile = input?.clientHints?.mobile;
    const mobileFlag = mobile === true || mobile === "true" || mobile === "?1";
    const device = identity.device === "Unknown" && mobileFlag ? "Mobile" : identity.device;
    return {
      os: identity.os,
      osVersion: identity.os_version,
      device,
      browserName: identity.browser_name,
      browserMajorVersion: identity.browser_major_version,
      browserFullVersion: identity.browser_full_version,
      architecture: identity.architecture,
      bitness: identity.bitness,
      model: identity.device_model
    };
  } catch {
    return { ...BLANK_USER_AGENT };
  }
}

// src/server/network/asnRegistry.json
var asnRegistry_default = [
  {
    asn: 55836,
    asn_name: "Reliance Jio Infocomm Limited",
    handle: "RELIANCEJIO-IN",
    asn_type: "isp",
    datacenter_result: false,
    sample_prefixes: ["49.44.63.0/24", "49.44.88.0/22"]
  },
  {
    asn: 24560,
    asn_name: "Bharti Airtel Ltd., Telemedia Services",
    handle: "ORG-BAL1-AP",
    asn_type: "isp",
    datacenter_result: false,
    sample_prefixes: []
  },
  {
    asn: 9498,
    asn_name: "Bharti Airtel Ltd.",
    handle: "ORG-BAL1-AP",
    asn_type: "mobile",
    datacenter_result: false,
    sample_prefixes: []
  },
  {
    asn: 9829,
    asn_name: "Bharat Sanchar Nigam Ltd.",
    handle: "ORG-BSNL1-AP",
    asn_type: "isp",
    datacenter_result: false,
    sample_prefixes: ["117.192.0.0/13"]
  },
  {
    asn: 714,
    asn_name: "Apple Inc.",
    handle: "APPLEC-1-Z",
    asn_type: "isp",
    datacenter_result: false,
    sample_prefixes: ["17.0.0.0/8"]
  },
  {
    asn: 6185,
    asn_name: "Apple Inc.",
    handle: "APPLEC-1-Z",
    asn_type: "isp",
    datacenter_result: false,
    sample_prefixes: []
  },
  {
    asn: 32934,
    asn_name: "Meta Platforms, Inc.",
    handle: "THEFA-3",
    asn_type: "datacenter",
    datacenter_result: false,
    sample_prefixes: ["31.13.64.0/18", "157.240.0.0/16", "179.60.192.0/22", "69.171.240.0/20", "173.252.64.0/18", "185.89.216.0/22"]
  },
  {
    asn: 13335,
    asn_name: "Cloudflare, Inc.",
    handle: "CLOUDFLARENET",
    asn_type: "cdn",
    datacenter_result: true,
    sample_prefixes: ["1.1.1.0/24", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/12", "141.101.0.0/16", "162.158.0.0/16", "172.64.0.0/13", "198.41.128.0/17"]
  },
  {
    asn: 15169,
    asn_name: "Google LLC",
    handle: "GOGL",
    asn_type: "cloud",
    datacenter_result: true,
    sample_prefixes: ["8.8.4.0/24", "8.8.8.0/24", "34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/12", "74.125.0.0/16", "104.196.0.0/16", "130.211.0.0/16", "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19"]
  },
  {
    asn: 16509,
    asn_name: "Amazon.com, Inc.",
    handle: "AMAZON-4",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: ["52.0.0.0/8", "54.0.0.0/8"]
  },
  {
    asn: 14618,
    asn_name: "Amazon.com, Inc.",
    handle: "AMAZO-4",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: []
  },
  {
    asn: 8075,
    asn_name: "Microsoft Corporation",
    handle: "MSFT",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: ["13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "52.136.0.0/13", "104.40.0.0/13", "168.61.0.0/16"]
  },
  {
    asn: 12076,
    asn_name: "Microsoft Corporation",
    handle: "MSFT",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: ["13.107.0.0/16"]
  },
  {
    asn: 14061,
    asn_name: "DigitalOcean, LLC",
    handle: "DO-13",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: [
      "46.101.0.0/16",
      "68.183.0.0/16",
      "104.131.0.0/16",
      "104.236.0.0/16",
      "128.199.0.0/16",
      "134.209.0.0/16",
      "138.68.0.0/16",
      "139.59.0.0/16",
      "143.198.0.0/16",
      "157.245.0.0/16",
      "159.65.0.0/16",
      "159.89.0.0/16",
      "161.35.0.0/16",
      "165.22.0.0/16",
      "167.71.0.0/16",
      "167.99.0.0/16",
      "174.138.0.0/16",
      "178.128.0.0/16"
    ]
  },
  {
    asn: 16276,
    asn_name: "OVH SAS",
    handle: "ORG-OS3-RIPE",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: ["5.196.0.0/16", "51.68.0.0/16", "51.75.0.0/16", "51.77.0.0/16", "51.83.0.0/16", "51.89.0.0/16", "54.36.0.0/16", "54.37.0.0/16", "54.38.0.0/16"]
  },
  {
    asn: 24940,
    asn_name: "Hetzner Online GmbH",
    handle: "ORG-HOA1-RIPE",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: [
      "5.9.0.0/16",
      "46.4.0.0/16",
      "49.12.0.0/16",
      "49.13.0.0/16",
      "65.21.0.0/16",
      "65.108.0.0/15",
      "78.46.0.0/15",
      "88.198.0.0/16",
      "88.99.0.0/16",
      "94.130.0.0/16",
      "95.216.0.0/15",
      "116.202.0.0/15",
      "135.181.0.0/16",
      "144.76.0.0/16",
      "148.251.0.0/16",
      "157.90.0.0/16",
      "159.69.0.0/16",
      "162.55.0.0/16",
      "167.235.0.0/16",
      "168.119.0.0/16"
    ]
  },
  {
    asn: 9009,
    asn_name: "M247 Ltd",
    handle: "ORG-MES6-RIPE",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: ["37.19.208.0/20", "146.70.0.0/16"]
  },
  {
    asn: 51167,
    asn_name: "Contabo GmbH",
    handle: "ORG-GG22-RIPE",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: ["5.189.128.0/19", "62.171.128.0/17", "173.212.192.0/18"]
  },
  {
    asn: 20473,
    asn_name: "The Constant Company, LLC",
    handle: "CHOOP-1",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: [
      "45.32.0.0/16",
      "45.63.0.0/16",
      "45.76.0.0/16",
      "45.77.0.0/16",
      "64.176.0.0/17",
      "66.42.0.0/16",
      "78.141.192.0/18",
      "95.179.128.0/17",
      "108.61.0.0/16",
      "139.180.128.0/17",
      "144.202.0.0/16",
      "149.28.0.0/16",
      "167.179.0.0/16",
      "207.148.0.0/16",
      "209.250.224.0/19"
    ]
  },
  {
    asn: 63949,
    asn_name: "Akamai Technologies, Inc.",
    handle: "ORG-ATI1-AP",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: ["45.79.0.0/16", "139.162.0.0/16", "172.104.0.0/15", "172.105.0.0/16"]
  },
  {
    asn: 399358,
    asn_name: "Anthropic, PBC",
    handle: "AP-2440",
    asn_type: "ai_operator",
    datacenter_result: true,
    sample_prefixes: []
  },
  {
    asn: 401518,
    asn_name: "OpenAI OpCo, LLC",
    handle: "OOL-15",
    asn_type: "ai_operator",
    datacenter_result: true,
    sample_prefixes: []
  },
  {
    asn: 401864,
    asn_name: "OpenAI OpCo, LLC",
    handle: "OOL-15",
    asn_type: "ai_operator",
    datacenter_result: true,
    sample_prefixes: []
  },
  {
    asn: 400645,
    asn_name: "OpenAI",
    handle: "ANL-362",
    asn_type: "datacenter",
    datacenter_result: true,
    sample_prefixes: ["130.250.218.0/24"]
  },
  {
    asn: 212949,
    asn_name: "Mistral AI",
    handle: "ORG-KS338-RIPE",
    asn_type: "ai_operator",
    datacenter_result: true,
    sample_prefixes: []
  },
  {
    asn: 396986,
    asn_name: "ByteDance",
    handle: "BYTED",
    asn_type: "ai_operator",
    datacenter_result: true,
    sample_prefixes: []
  }
];

// src/server/network/asnEnricher.ts
var REGISTRY = asnRegistry_default;
var REGISTRY_BY_ASN = /* @__PURE__ */ new Map();
for (const entry of REGISTRY) REGISTRY_BY_ASN.set(entry.asn, entry);
var REGISTRY_PREFIXES = (() => {
  const ranges = [];
  for (const entry of REGISTRY) {
    for (const prefix of entry.sample_prefixes ?? []) {
      const parsed = parseIpv4Prefix(prefix);
      if (parsed) ranges.push({ ...parsed, prefix, entry });
    }
  }
  ranges.sort((a, b) => b.prefixLength - a.prefixLength);
  return ranges;
})();
function parseIpv4(text) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text.trim());
  if (!match) return null;
  const octets = [match[1], match[2], match[3], match[4]].map((part) => Number.parseInt(part, 10));
  if (octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return null;
  return (octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]) >>> 0;
}
function parseIpv4Prefix(prefix) {
  const [addressPart, lengthPart] = prefix.split("/");
  const base = parseIpv4(addressPart ?? "");
  const prefixLength = Number.parseInt(lengthPart ?? "", 10);
  if (base === null || !Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 32) return null;
  const mask = prefixLength === 0 ? 0 : 4294967295 << 32 - prefixLength >>> 0;
  const first = (base & mask) >>> 0;
  const last = (first | mask ^ 4294967295) >>> 0;
  return { first, last, prefixLength };
}
function ipv4InRanges(ip) {
  const value = parseIpv4(ip);
  if (value === null) return null;
  for (const range of REGISTRY_PREFIXES) {
    if (value >= range.first && value <= range.last) return range;
  }
  return null;
}
function registryEntryForAsn(asn) {
  const value = typeof asn === "number" ? asn : Number.parseInt(String(asn ?? "").replace(/^\s*as/i, ""), 10);
  if (!Number.isInteger(value) || value <= 0) return null;
  return REGISTRY_BY_ASN.get(value) ?? null;
}
function registryEntryForIp(ip) {
  const match = ipv4InRanges(ip);
  return match ? { entry: match.entry, prefix: match.prefix } : null;
}
var CACHE_LIMIT = 500;
var ASN_META_TTL_MS = 7 * 24 * 60 * 60 * 1e3;
var IP_LOOKUP_TTL_MS = 24 * 60 * 60 * 1e3;
var NEGATIVE_TTL_MS = 30 * 1e3;
var CACHE = /* @__PURE__ */ new Map();
function cacheGet(key) {
  const slot = CACHE.get(key);
  if (!slot) return void 0;
  if (slot.expiresAt <= Date.now()) {
    CACHE.delete(key);
    return void 0;
  }
  CACHE.delete(key);
  CACHE.set(key, slot);
  return slot.value;
}
function cacheSet(key, value, ttlMs) {
  CACHE.delete(key);
  CACHE.set(key, { value, expiresAt: Date.now() + ttlMs });
  while (CACHE.size > CACHE_LIMIT) {
    const oldest = CACHE.keys().next();
    if (oldest.done) break;
    CACHE.delete(oldest.value);
  }
}
function cleanCymruAsName(raw) {
  let name = String(raw ?? "");
  name = name.replace(/^"+|"+$/g, "").trim();
  name = name.replace(/,\s*[A-Za-z]{2}\s*$/, "");
  name = name.replace(/^[A-Za-z0-9][A-Za-z0-9-]{0,40}\s+-\s+/, (match, offset, text) => {
    const remainder = text.slice(offset + match.length);
    return remainder.trim() ? "" : match;
  });
  if (!name.trim()) name = String(raw ?? "").replace(/^"+|"+$/g, "").trim();
  return name.replace(/\s+/g, " ").trim();
}
function cleanEdgeAsOrg(raw) {
  return String(raw ?? "").replace(/^[Aa][Ss]\d+\s+/, "").replace(/\s+/g, " ").trim();
}
var HOSTING_NAME_HINTS = [
  "amazon web services",
  "aws",
  "azure",
  "google cloud",
  "oracle cloud",
  "alibaba cloud",
  "tencent cloud",
  "digitalocean",
  "linode",
  "vultr",
  "hetzner",
  "ovh",
  "contabo",
  "m247",
  "leaseweb",
  "scaleway",
  "cloudflare",
  "akamai",
  "fastly",
  "datacenter",
  "data center",
  "hosting",
  "colocation",
  "vps",
  "anthropic",
  "openai",
  "mistral",
  "bytedance"
];
var MOBILE_NAME_HINTS = [
  "airtel",
  "jio",
  "vodafone",
  "idea cellular",
  "verizon",
  "t-mobile",
  "tmobile",
  "at&t",
  "sprint",
  "boost mobile",
  "metro",
  "mint mobile",
  "google fi",
  "o2 uk",
  "orange",
  "movistar",
  "telcel",
  "safaricom",
  "docomo",
  "softbank",
  "kddi",
  "sk telecom",
  "cellular",
  "mobile"
];
function heuristicAsnType(name) {
  const text = String(name ?? "").toLowerCase();
  if (!text) return { type: "isp", datacenter: false };
  if (HOSTING_NAME_HINTS.some((hint) => text.includes(hint))) return { type: "datacenter", datacenter: true };
  if (MOBILE_NAME_HINTS.some((hint) => text.includes(hint))) return { type: "mobile", datacenter: false };
  return { type: "isp", datacenter: false };
}
function ipv4ReverseOctets(ip) {
  const value = parseIpv4(ip);
  if (value === null) return [];
  return [
    String(value >>> 24 & 255),
    String(value >>> 16 & 255),
    String(value >>> 8 & 255),
    String(value & 255)
  ].reverse();
}
function expandIpv6Groups(ip) {
  const text = String(ip ?? "").trim().toLowerCase();
  if (!text || !text.includes(":") || !/^[0-9a-f:.]+$/.test(text)) return null;
  if (text.includes("%")) return null;
  const halves = text.split("::");
  if (halves.length > 2) return null;
  let head = halves[0] ? halves[0].split(":") : [];
  let tail = halves[1] ? halves[1].split(":") : [];
  const unfoldIpv4Tail = (tokens) => {
    const last = tokens[tokens.length - 1] ?? "";
    if (!last.includes(".")) return tokens;
    const parts = last.split(".");
    if (parts.length !== 4) return [];
    const values2 = parts.map((part) => Number.parseInt(part, 10));
    if (values2.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return [];
    return tokens.slice(0, -1).concat([values2[0] << 8 | values2[1], values2[2] << 8 | values2[3]].map((v) => v.toString(16)));
  };
  head = unfoldIpv4Tail(head);
  tail = unfoldIpv4Tail(tail);
  if (head.length === 0 && halves[0]) return null;
  if (tail.length === 0 && halves[1]) return null;
  const fill = 8 - head.length - tail.length;
  if (fill < 0) return null;
  if (halves.length === 1 && fill !== 0) return null;
  const groups = halves.length === 2 ? [...head, ...new Array(fill).fill("0"), ...tail] : [...head, ...tail];
  if (groups.length !== 8) return null;
  const values = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    values.push(Number.parseInt(group, 16));
  }
  return values;
}
function ipv6ReverseNibbles(ip) {
  const groups = expandIpv6Groups(ip);
  if (!groups) return [];
  const nibbles = [];
  for (const value of groups) {
    for (const shift of [12, 8, 4, 0]) nibbles.push((value >> shift & 15).toString(16));
  }
  return nibbles.reverse();
}
var CYMRU_TIMEOUT_MS = 1500;
var DOH_ENDPOINTS = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];
function withBudget(task, fallback, ms) {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve(fallback);
    }, ms);
    task.then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(fallback);
      }
    );
  });
}
async function dnsTxtRecords(name) {
  try {
    const dns2 = await import("node:dns/promises");
    if (!dns2 || typeof dns2.resolveTxt !== "function") return [];
    const lookup = dns2.resolveTxt(name).then(
      (records2) => records2.map((chunks) => chunks.join(""))
    );
    const records = await withBudget(lookup, [], CYMRU_TIMEOUT_MS);
    return records.filter((record) => typeof record === "string" && record.length > 0);
  } catch {
    return [];
  }
}
async function cymruTextRecords(name) {
  const fromDns = await dnsTxtRecords(name);
  if (fromDns.length > 0) return fromDns;
  return dohTextRecords(name);
}
async function dohTextRecords(name) {
  if (typeof fetch !== "function") return [];
  const signal = typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(CYMRU_TIMEOUT_MS) : void 0;
  for (const endpoint of DOH_ENDPOINTS) {
    try {
      const response = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=TXT`, {
        headers: { accept: "application/dns-json" },
        signal
      });
      if (!response.ok) continue;
      const payload = await response.json();
      const answers = Array.isArray(payload?.Answer) ? payload.Answer : [];
      const records = answers.filter((answer) => typeof answer?.data === "string" && answer.data.length > 0).map((answer) => answer.data);
      if (records.length) return records;
    } catch {
    }
  }
  return [];
}
function firstCymruRecord(raw) {
  return String(raw ?? "").replace(/^"+|"+$/g, "").split(/"\s*"/)[0] ?? "";
}
var CYMRU_DATE_FIELD = /^\d{4}-\d{2}-\d{2}$/;
var CYMRU_REGISTRY_FIELD = /^(?:apnic|arin|ripe|ripe-ncc|afrinic|lacnic|iana|arin-.*)$/i;
function pickCymruAsName(fields) {
  const candidates = [fields[4], fields[5], fields[fields.length - 1]].map((value) => String(value ?? "").trim()).filter((value) => value.length > 0);
  for (const candidate of candidates) {
    if (/[A-Za-z]/.test(candidate) && !CYMRU_DATE_FIELD.test(candidate) && !CYMRU_REGISTRY_FIELD.test(candidate)) {
      return candidate;
    }
  }
  return "";
}
function parseCymruOriginLine(raw) {
  const fields = firstCymruRecord(raw).split("|").map((field) => field.trim());
  const asn = Number.parseInt(fields[0] ?? "", 10);
  if (!Number.isInteger(asn) || asn <= 0 || asn > 4294967295) return null;
  return { asn, network: fields[1] ?? "", cc: (fields[2] ?? "").toUpperCase().slice(0, 2) };
}
async function lookupCymruByIp(ip) {
  const text = String(ip ?? "").trim();
  if (!text) return null;
  const name = text.includes(":") ? `${ipv6ReverseNibbles(text).join(".")}.origin6.asn.cymru.com` : `${ipv4ReverseOctets(text).join(".")}.origin.asn.cymru.com`;
  if (name.startsWith(".origin") || name.endsWith(".origin") || name.startsWith(".") || name.endsWith(".")) return null;
  for (const record of await cymruTextRecords(name)) {
    const parsed = parseCymruOriginLine(record);
    if (parsed) return parsed;
  }
  return null;
}
async function lookupCymruAsName(asn) {
  const key = `asname:${asn}`;
  const cached = cacheGet(key);
  if (cached !== void 0) return typeof cached === "string" ? cached : null;
  for (const record of await cymruTextRecords(`AS${asn}.asn.cymru.com`)) {
    const fields = firstCymruRecord(record).split("|").map((field) => field.trim());
    const rawName = pickCymruAsName(fields);
    if (rawName) {
      cacheSet(key, rawName, ASN_META_TTL_MS);
      return rawName;
    }
  }
  cacheSet(key, null, NEGATIVE_TTL_MS);
  return null;
}
var EMPTY_NETWORK = () => ({
  asn: "",
  asn_name: "",
  asn_network: "",
  asn_type: "isp",
  datacenter_result: false,
  source: "none"
});
function cloneResult(result) {
  return { ...result };
}
function toAsnNumber(value) {
  if (typeof value === "number" && Number.isInteger(value) && value > 0 && value <= 4294967295) return value;
  if (typeof value === "string") {
    const parsed = Number.parseInt(value.replace(/^\s*[Aa][Ss]/, "").trim(), 10);
    if (Number.isInteger(parsed) && parsed > 0 && parsed <= 4294967295) return parsed;
  }
  return null;
}
async function resolveAsnOrganization(asn) {
  const number = toAsnNumber(asn);
  const empty = {
    asn: number === null ? "" : String(number),
    asn_name: "",
    asn_type: "isp",
    datacenter_result: false,
    source: "none"
  };
  if (number === null) return empty;
  const cacheKey = `asnorg:${number}`;
  const cached = cacheGet(cacheKey);
  if (cached !== void 0 && typeof cached === "object" && cached !== null) {
    return { ...cached };
  }
  const entry = registryEntryForAsn(number);
  if (entry) {
    const result = {
      asn: String(number),
      asn_name: entry.asn_name,
      asn_type: entry.asn_type,
      datacenter_result: entry.datacenter_result,
      source: "registry"
    };
    cacheSet(cacheKey, result, ASN_META_TTL_MS);
    return result;
  }
  try {
    const rawName = await lookupCymruAsName(number);
    if (rawName) {
      const name = cleanCymruAsName(rawName);
      if (name) {
        const heuristic = heuristicAsnType(name);
        const result = {
          asn: String(number),
          asn_name: name,
          asn_type: heuristic.type,
          datacenter_result: heuristic.datacenter,
          source: "cymru"
        };
        cacheSet(cacheKey, result, ASN_META_TTL_MS);
        return result;
      }
    }
  } catch {
  }
  cacheSet(cacheKey, empty, NEGATIVE_TTL_MS);
  return empty;
}
async function enrichNetwork(ip, edge = {}) {
  try {
    const ipClean = String(ip ?? "").trim();
    const cacheKey = `ip:${ipClean}`;
    const cached = cacheGet(cacheKey);
    if (cached !== void 0 && typeof cached === "object" && cached !== null) {
      return cloneResult(cached);
    }
    const edgeAsn = toAsnNumber(edge?.asn);
    const edgeOrg = String(edge?.asOrganization ?? "").trim();
    if (edgeAsn && edgeOrg) {
      const entry = registryEntryForAsn(edgeAsn);
      const heuristic = entry ? null : heuristicAsnType(cleanEdgeAsOrg(edgeOrg));
      const result = {
        asn: String(edgeAsn),
        asn_name: cleanEdgeAsOrg(edgeOrg),
        asn_network: registryEntryForIp(ipClean)?.prefix ?? "",
        asn_type: entry?.asn_type ?? heuristic?.type ?? "isp",
        datacenter_result: entry ? entry.datacenter_result : heuristic?.datacenter ?? false,
        source: "edge"
      };
      cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
      return result;
    }
    const prefixMatch = registryEntryForIp(ipClean);
    if (prefixMatch) {
      const result = {
        asn: String(prefixMatch.entry.asn),
        asn_name: prefixMatch.entry.asn_name,
        asn_network: prefixMatch.prefix,
        asn_type: prefixMatch.entry.asn_type,
        datacenter_result: prefixMatch.entry.datacenter_result,
        source: "registry"
      };
      cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
      return result;
    }
    if (edgeAsn) {
      const entry = registryEntryForAsn(edgeAsn);
      if (entry) {
        const result = {
          asn: String(edgeAsn),
          asn_name: entry.asn_name,
          asn_network: "",
          asn_type: entry.asn_type,
          datacenter_result: entry.datacenter_result,
          source: "registry"
        };
        cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
        return result;
      }
      const byAsn = await resolveAsnOrganization(edgeAsn);
      if (byAsn.source !== "none") {
        const result = {
          asn: String(edgeAsn),
          asn_name: byAsn.asn_name,
          asn_network: registryEntryForIp(ipClean)?.prefix ?? "",
          asn_type: byAsn.asn_type,
          datacenter_result: byAsn.datacenter_result,
          source: byAsn.source
        };
        cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
        return result;
      }
    }
    if (edgeOrg) {
      const heuristic = heuristicAsnType(edgeOrg);
      const result = {
        asn: "",
        asn_name: cleanEdgeAsOrg(edgeOrg),
        asn_network: "",
        asn_type: heuristic.type,
        datacenter_result: heuristic.datacenter,
        source: "edge"
      };
      cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
      return result;
    }
    const cymru = await lookupCymruByIp(ipClean);
    if (cymru) {
      const entry = registryEntryForAsn(cymru.asn);
      let asnName = entry?.asn_name ?? "";
      let asnType = entry?.asn_type;
      let datacenter = entry?.datacenter_result;
      if (!asnName) {
        const rawName = await lookupCymruAsName(cymru.asn);
        if (rawName) {
          asnName = cleanCymruAsName(rawName);
          const heuristic = heuristicAsnType(asnName);
          asnType = heuristic.type;
          datacenter = heuristic.datacenter;
        }
      }
      const result = {
        asn: String(cymru.asn),
        asn_name: asnName,
        asn_network: cymru.network || "",
        asn_type: asnType ?? "isp",
        datacenter_result: datacenter ?? false,
        source: "cymru"
      };
      cacheSet(cacheKey, result, IP_LOOKUP_TTL_MS);
      return result;
    }
    const empty = EMPTY_NETWORK();
    cacheSet(cacheKey, empty, NEGATIVE_TTL_MS);
    return empty;
  } catch {
    return EMPTY_NETWORK();
  }
}

// src/server/identity/identityIndex.ts
var IDENTITY_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS visitor_profiles (
  visitor_id TEXT PRIMARY KEY,
  profile_json TEXT,
  hardware_fingerprint TEXT,
  created_at_utc TEXT NOT NULL,
  updated_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_visitor_profiles_hw ON visitor_profiles(hardware_fingerprint);
CREATE INDEX IF NOT EXISTS idx_visitor_profiles_updated ON visitor_profiles(updated_at_utc);

CREATE TABLE IF NOT EXISTS identity_blocks (
  bucket_key TEXT NOT NULL,
  visitor_id TEXT NOT NULL,
  created_at_utc TEXT NOT NULL,
  updated_at_utc TEXT NOT NULL,
  PRIMARY KEY (bucket_key, visitor_id)
);
CREATE INDEX IF NOT EXISTS idx_identity_blocks_key ON identity_blocks(bucket_key);
CREATE INDEX IF NOT EXISTS idx_identity_blocks_visitor ON identity_blocks(visitor_id);

CREATE TABLE IF NOT EXISTS visitor_links (
  visitor_id TEXT NOT NULL,
  hardware_fingerprint TEXT NOT NULL,
  link_mode TEXT,
  link_score REAL,
  created_at_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  PRIMARY KEY (visitor_id, hardware_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_visitor_links_hw ON visitor_links(hardware_fingerprint);
`;
function ensureIdentitySchema(db2) {
  db2.exec(IDENTITY_SCHEMA_SQL);
}
function normalizeText(value) {
  if (typeof value !== "string") return "";
  return value.trim().toLowerCase();
}
function normalizeInt(value) {
  const num = typeof value === "number" ? value : Number(value);
  return Number.isFinite(num) ? Math.floor(num) : null;
}
function hexHash(text) {
  return fnv1a64(text).toString(16).padStart(16, "0");
}
function networkBucket(net2) {
  const ip = normalizeText(net2?.ip);
  const asn = normalizeText(net2?.asn);
  if (ip) {
    const octets = ip.split(".");
    if (octets.length === 4 && octets.every((o) => /^\d{1,3}$/.test(o))) {
      return octets.slice(0, 3).join(".");
    }
  }
  return asn || "unknown";
}
function screenBucket(screen) {
  const width = normalizeInt(screen?.width);
  const height = normalizeInt(screen?.height);
  return width !== null && height !== null ? `${width}x${height}` : "unknown";
}
var FNV_OFFSET_64 = 0xcbf29ce484222325n;
var FNV_PRIME_64 = 0x00000100000001b3n;
var MASK_64 = 0xffffffffffffffffn;
function fnv1a64(input) {
  let hash = FNV_OFFSET_64;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= BigInt(input.charCodeAt(i) & 255);
    hash = hash * FNV_PRIME_64 & MASK_64;
  }
  return hash;
}
function simhash64(tokens) {
  const votes = new Array(64).fill(0);
  for (const token of tokens) {
    const hash = fnv1a64(normalizeText(token));
    for (let bit = 0; bit < 64; bit += 1) {
      votes[bit] += hash >> BigInt(bit) & 1n ? 1 : -1;
    }
  }
  let out = 0n;
  for (let bit = 0; bit < 64; bit += 1) {
    if (votes[bit] > 0) out |= 1n << BigInt(bit);
  }
  return out;
}
function bandHex(simhash, band) {
  const slice = simhash >> BigInt(band * 16) & 0xffffn;
  return slice.toString(16).padStart(4, "0");
}
function canonicalIdentityFeatures(profile) {
  const tokens = [];
  const push = (prefix, value) => {
    const text = normalizeText(value);
    if (text) tokens.push(`${prefix}:${text}`);
  };
  push("hw", profile.hardwareFingerprint);
  const gpu = [normalizeText(profile.gpu?.vendor), normalizeText(profile.gpu?.renderer)].filter(Boolean).join("|");
  if (gpu) tokens.push(`gpu:${gpu}`);
  push("os", profile.os?.family);
  push("tz", profile.timezone);
  const screen = screenBucket(profile.screen);
  if (screen !== "unknown") tokens.push(`screen:${screen}`);
  const fontsCount = normalizeInt(profile.fonts?.count);
  if (fontsCount !== null && fontsCount > 0) tokens.push(`fonts:${fontsCount}`);
  const cores = normalizeInt(profile.cpu?.cores);
  if (cores !== null && cores > 0) tokens.push(`cpu:${cores}`);
  push("cpuarch", profile.cpu?.architecture);
  push("canvas", profile.canvas?.hash);
  push("webgl", profile.webgl?.hash);
  push("audio", profile.audio?.hash);
  push("browser", profile.browser?.family);
  const langs = (profile.languages ?? []).map((lang) => normalizeText(lang)).filter(Boolean).slice(0, 6).join(",");
  if (langs) tokens.push(`langs:${langs}`);
  return tokens;
}
var MIN_TOKENS_FOR_BANDS = 3;
function blockKeysFor(profile) {
  const keys = /* @__PURE__ */ new Set();
  const hardware = normalizeText(profile.hardwareFingerprint);
  if (hardware) keys.add(`hw_hash:${hexHash(hardware)}`);
  const gpuText = [normalizeText(profile.gpu?.vendor), normalizeText(profile.gpu?.renderer)].filter(Boolean).join("|");
  const osFamily = normalizeText(profile.os?.family);
  const timezone = normalizeText(profile.timezone);
  if (gpuText && (osFamily || timezone)) {
    keys.add(`block_gpu:${hexHash(gpuText)}:${osFamily}:${timezone}`);
  }
  const net2 = networkBucket(profile.net);
  const screen = screenBucket(profile.screen);
  if (net2 !== "unknown" || screen !== "unknown") {
    keys.add(`block_net:${net2}:${screen}`);
  }
  const tokens = canonicalIdentityFeatures(profile);
  if (tokens.length >= MIN_TOKENS_FOR_BANDS) {
    const simhash = simhash64(tokens);
    for (let band = 0; band < 4; band += 1) keys.add(`band_${band}:${bandHex(simhash, band)}`);
  }
  return [...keys];
}
function upsertBlocks(db2, visitorId, keys, nowUtc) {
  const statement = db2.prepare(
    `INSERT OR IGNORE INTO identity_blocks (bucket_key, visitor_id, created_at_utc, updated_at_utc)
     VALUES (?, ?, ?, ?)`
  );
  for (const key of keys) {
    if (typeof key !== "string" || key.length === 0) continue;
    try {
      statement.run(key, visitorId, nowUtc, nowUtc);
    } catch {
    }
  }
}
function sanitizeLimit(limit) {
  const num = Math.floor(limit);
  return Number.isFinite(num) && num > 0 ? Math.min(num, 500) : 200;
}
function findCandidates(db2, keys, limit = 200) {
  const capped = sanitizeLimit(limit);
  const perKey = Math.max(10, Math.ceil(capped / 2));
  const seen = /* @__PURE__ */ new Map();
  const statement = db2.prepare(
    `SELECT visitor_id FROM identity_blocks WHERE bucket_key = ? ORDER BY updated_at_utc DESC LIMIT ${perKey}`
  );
  for (const key of keys) {
    if (typeof key !== "string" || key.length === 0) continue;
    let rows = [];
    try {
      rows = statement.all(key);
    } catch {
      continue;
    }
    for (const row of rows) {
      const candidateId = typeof row?.visitor_id === "string" ? row.visitor_id : "";
      if (!candidateId) continue;
      if (!seen.has(candidateId)) seen.set(candidateId, candidateId);
    }
  }
  return [...seen.keys()].slice(0, capped);
}
function loadVisitorProfile(db2, visitorId) {
  if (typeof visitorId !== "string" || visitorId.length === 0) return null;
  try {
    const row = db2.prepare("SELECT * FROM visitor_profiles WHERE visitor_id = ?").get(visitorId);
    if (!row || typeof row.visitor_id !== "string") return null;
    let profile = null;
    if (typeof row.profile_json === "string" && row.profile_json.length > 0) {
      try {
        profile = JSON.parse(row.profile_json);
      } catch {
        profile = null;
      }
    }
    return {
      visitor_id: row.visitor_id,
      hardware_fingerprint: typeof row.hardware_fingerprint === "string" ? row.hardware_fingerprint : null,
      profile,
      profile_json: typeof row.profile_json === "string" ? row.profile_json : null,
      created_at_utc: typeof row.created_at_utc === "string" ? row.created_at_utc : "",
      updated_at_utc: typeof row.updated_at_utc === "string" ? row.updated_at_utc : ""
    };
  } catch {
    return null;
  }
}

// src/shared/matching/compareFingerprints.ts
var FAMILY_ORDER = [
  "gpu",
  "cpu",
  "screen",
  "timezone",
  "fonts",
  "mediaDevices",
  "canvas",
  "webgl",
  "audio",
  "fontPrefs",
  "misc"
];
var WEIGHT_MATRIX = {
  exact: {
    gpu: 15,
    cpu: 10,
    screen: 8,
    timezone: 5,
    fonts: 10,
    mediaDevices: 2,
    canvas: 15,
    webgl: 10,
    audio: 10,
    fontPrefs: 7,
    misc: 8
  },
  strict: {
    gpu: 18,
    cpu: 12,
    screen: 10,
    timezone: 6,
    fonts: 12,
    mediaDevices: 2,
    canvas: 14,
    webgl: 8,
    audio: 8,
    fontPrefs: 5,
    misc: 5
  },
  lenient: {
    gpu: 22,
    cpu: 15,
    screen: 12,
    timezone: 8,
    fonts: 13,
    mediaDevices: 4,
    canvas: 8,
    webgl: 6,
    audio: 5,
    fontPrefs: 4,
    misc: 3
  },
  "cross-browser": {
    gpu: 30,
    cpu: 20,
    screen: 16,
    timezone: 12,
    fonts: 16,
    mediaDevices: 6,
    canvas: 0,
    webgl: 0,
    audio: 0,
    fontPrefs: 0,
    misc: 0
  },
  "hardware-only": {
    gpu: 32,
    cpu: 22,
    screen: 18,
    timezone: 12,
    fonts: 10,
    mediaDevices: 6,
    canvas: 0,
    webgl: 0,
    audio: 0,
    fontPrefs: 0,
    misc: 0
  },
  "engine-only": {
    gpu: 0,
    cpu: 0,
    screen: 0,
    timezone: 0,
    fonts: 10,
    mediaDevices: 0,
    canvas: 25,
    webgl: 20,
    audio: 18,
    fontPrefs: 12,
    misc: 15
  }
};
var MODE_THRESHOLDS = {
  exact: 100,
  strict: 92,
  lenient: 82,
  "cross-browser": 85,
  "hardware-only": 88,
  "engine-only": 85
};
function jaccardSet(a, b) {
  const norm = (list) => (list ?? []).filter((x) => typeof x === "string" && x.trim().length > 0).map((x) => x.trim().toLowerCase());
  const setA = new Set(norm(a));
  const setB = new Set(norm(b));
  if (setA.size === 0 && setB.size === 0) return 1;
  if (setA.size === 0 || setB.size === 0) return 0;
  let intersection = 0;
  for (const item of setA) if (setB.has(item)) intersection += 1;
  const union = setA.size + setB.size - intersection;
  return union === 0 ? 0 : intersection / union;
}
var FNV_OFFSET_B = 2166136261 ^ 3735928559;
var OS_FONT_TABLE = {
  windows: [
    "arial",
    "calibri",
    "cambria",
    "candara",
    "comic sans ms",
    "consolas",
    "constantia",
    "corbel",
    "courier new",
    "georgia",
    "impact",
    "lucida console",
    "lucida sans unicode",
    "microsoft sans serif",
    "palatino linotype",
    "segoe ui",
    "tahoma",
    "times new roman",
    "trebuchet ms",
    "verdana"
  ],
  mac: [
    "american typewriter",
    "andale mono",
    "arial",
    "arial black",
    "arial narrow",
    "avenir next",
    "baskerville",
    "big caslon",
    "chalkboard",
    "chalkduster",
    "cochin",
    "comic sans ms",
    "courier",
    "courier new",
    "didot",
    "futura",
    "geneva",
    "georgia",
    "gill sans",
    "helvetica",
    "helvetica neue",
    "impact",
    "lucida grande",
    "menlo",
    "monaco",
    "optima",
    "palatino",
    "tahoma",
    "times",
    "times new roman",
    "trebuchet ms",
    "verdana"
  ],
  linux: [
    "dejavu sans",
    "dejavu sans mono",
    "dejavu serif",
    "liberation mono",
    "liberation sans",
    "liberation serif",
    "noto sans",
    "noto serif",
    "ubuntu"
  ],
  android: ["roboto", "noto sans", "noto serif", "droid sans", "droid serif"],
  ios: [
    "american typewriter",
    "andale mono",
    "arial",
    "arial black",
    "arial narrow",
    "baskerville",
    "cochin",
    "comic sans ms",
    "courier",
    "courier new",
    "georgia",
    "helvetica",
    "helvetica neue",
    "impact",
    "menlo",
    "palatino",
    "tahoma",
    "times new roman",
    "trebuchet ms",
    "verdana",
    "snell roundhand"
  ]
};
function isOsShippedOn(font, platformClass) {
  const list = OS_FONT_TABLE[platformClass.toLowerCase()];
  if (!list) return true;
  return list.indexOf(font) !== -1;
}
function str(v) {
  return typeof v === "string" ? v.trim() : "";
}
function gpuSim(s, i) {
  const a = s.gpu;
  const b = i.gpu;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const ga = str(a.normalizedGpu).toLowerCase();
  const gb = str(b.normalizedGpu).toLowerCase();
  if (ga && gb) return ga === gb ? 1 : 0;
  const ha = str(a.invariantLimitsHash).toLowerCase();
  const hb = str(b.invariantLimitsHash).toLowerCase();
  if (ha && hb) return ha === hb ? 0.6 : 0;
  return null;
}
function cpuSim(s, i) {
  const a = s.cpu;
  const b = i.cpu;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  let comparable = 0;
  let matched = 0;
  const archA = str(a.arch).toLowerCase();
  const archB = str(b.arch).toLowerCase();
  if (archA && archB) {
    comparable += 1;
    if (archA !== archB) return 0;
    matched += 1;
  }
  if (a.cores !== null && a.cores !== void 0 && b.cores !== null && b.cores !== void 0) {
    comparable += 1;
    if (a.cores === b.cores) matched += 1;
  }
  if (a.memoryGb !== null && a.memoryGb !== void 0 && b.memoryGb !== null && b.memoryGb !== void 0) {
    comparable += 1;
    if (a.memoryGb === b.memoryGb) matched += 1;
  }
  return comparable === 0 ? null : matched / comparable;
}
function screenSim(s, i) {
  const a = s.screen;
  const b = i.screen;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const w1 = typeof a.width === "number" ? a.width : 0;
  const h1 = typeof a.height === "number" ? a.height : 0;
  const w2 = typeof b.width === "number" ? b.width : 0;
  const h2 = typeof b.height === "number" ? b.height : 0;
  if (!w1 || !h1 || !w2 || !h2) return 0;
  if (w1 === w2 && h1 === h2) return 1;
  const dpr1 = typeof a.dpr === "number" && a.dpr > 0 ? a.dpr : 1;
  const dpr2 = typeof b.dpr === "number" && b.dpr > 0 ? b.dpr : 1;
  const r1 = w1 / h1;
  const r2 = w2 / h2;
  if (Math.abs(r1 - r2) > 0.02) return 0;
  const nearMultiplier = (x) => ZOOM_MULTIPLIERS.some((m) => Math.abs(x - m) <= 0.02 * m);
  const raw = w2 / w1;
  const dprScaled = w2 * dpr2 / (w1 * dpr1);
  if (nearMultiplier(raw) || nearMultiplier(1 / raw) || nearMultiplier(dprScaled) || nearMultiplier(1 / dprScaled)) {
    return 0.85;
  }
  return 0;
}
var ZOOM_MULTIPLIERS = [0.75, 0.8, 0.9, 1.1, 1.25, 1.5];
function timezoneSim(s, i) {
  const a = s.timezone;
  const b = i.timezone;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const nameA = str(a.name).toLowerCase();
  const nameB = str(b.name).toLowerCase();
  if (nameA && nameB) return nameA === nameB ? 1 : 0;
  const oA = typeof a.offsetMinutes === "number" ? a.offsetMinutes : null;
  const oB = typeof b.offsetMinutes === "number" ? b.offsetMinutes : null;
  if (oA !== null && oB !== null) return Math.abs(oA - oB) <= 1 ? 0.7 : 0;
  return null;
}
function fontsSim(s, i, mode) {
  const a = s.fonts;
  const b = i.fonts;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const listA = Array.isArray(a.list) ? a.list : [];
  const listB = Array.isArray(b.list) ? b.list : [];
  if (mode === "cross-browser") {
    const pcA = str(a.platformClass).toLowerCase();
    const pcB = str(b.platformClass).toLowerCase();
    const filteredA = listA.filter(
      (f) => isOsShippedOn(f.toLowerCase(), pcA) && isOsShippedOn(f.toLowerCase(), pcB)
    );
    const filteredB = listB.filter(
      (f) => isOsShippedOn(f.toLowerCase(), pcA) && isOsShippedOn(f.toLowerCase(), pcB)
    );
    const useA = filteredA.length > 0 ? filteredA : listA;
    const useB = filteredB.length > 0 ? filteredB : listB;
    const j = jaccardSet(useA, useB);
    return j >= 0.85 ? 1 : j * 0.5;
  }
  return jaccardSet(listA, listB);
}
function mediaDeviceBit(v) {
  if (v === null || v === void 0) return null;
  if (typeof v === "boolean") return v ? "1" : "0";
  if (typeof v === "number" && isFinite(v)) return v > 0 ? "1" : "0";
  return null;
}
function mediaDevicesSim(s, i) {
  const a = s.mediaDevices;
  const b = i.mediaDevices;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const pairs = [
    [a.audioIn, b.audioIn],
    [a.audioOut, b.audioOut],
    [a.video, b.video]
  ];
  let comparable = 0;
  let matched = 0;
  for (const [x, y] of pairs) {
    const vx = mediaDeviceBit(x);
    const vy = mediaDeviceBit(y);
    if (vx === null || vy === null) continue;
    comparable += 1;
    if (vx === vy) matched += 1;
  }
  return comparable === 0 ? null : matched / comparable;
}
function canvasSim(s, i, mode) {
  const a = s.canvas;
  const b = i.canvas;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const geoWeight = mode === "lenient" ? 2 : 1;
  let total = 0;
  let matched = 0;
  const geoA = str(a.geometry);
  const geoB = str(b.geometry);
  if (geoA && geoB) {
    total += geoWeight;
    if (geoA === geoB) matched += geoWeight;
  }
  const textA = str(a.text);
  const textB = str(b.text);
  if (textA && textB) {
    total += 1;
    if (textA === textB) matched += 1;
  }
  const stA = str(a.stabilized);
  const stB = str(b.stabilized);
  if (stA && stB) {
    total += 1;
    if (stA === stB) matched += 1;
  }
  return total === 0 ? null : matched / total;
}
function webglSim(s, i) {
  const a = s.webgl;
  const b = i.webgl;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const pairs = [
    [a.extensionsHash, b.extensionsHash],
    [a.paramsHash, b.paramsHash],
    [a.shaderPrecisionHash, b.shaderPrecisionHash]
  ];
  let comparable = 0;
  let matched = 0;
  for (const [x, y] of pairs) {
    const vx = str(x);
    const vy = str(y);
    if (!vx || !vy) continue;
    comparable += 1;
    if (vx.toLowerCase() === vy.toLowerCase()) matched += 1;
  }
  return comparable === 0 ? null : matched / comparable;
}
function audioSim(s, i) {
  const a = s.audio;
  const b = i.audio;
  if (a !== null && a !== void 0 && a.braveFlag === true || b !== null && b !== void 0 && b.braveFlag === true) {
    return null;
  }
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const sumA = a.sum;
  const sumB = b.sum;
  const hasA = typeof sumA === "number" && isFinite(sumA);
  const hasB = typeof sumB === "number" && isFinite(sumB);
  if (!hasA && !hasB) return null;
  if (!hasA || !hasB) return 0;
  const delta = Math.abs(sumA - sumB);
  const scale = Math.max(Math.abs(sumA), Math.abs(sumB), 1e-12);
  const relative = delta / scale;
  let score;
  if (relative < 1e-9) score = 1;
  else if (relative < 1e-4) score = 0.9;
  else score = 0;
  const blA = a.baseLatency;
  const blB = b.baseLatency;
  if (typeof blA === "number" && isFinite(blA) && blA > 0 && typeof blB === "number" && isFinite(blB) && blB > 0) {
    const rel = Math.abs(blA - blB) / Math.max(blA, blB);
    if (rel >= 1e-4) score = Math.min(score, 0.5);
  }
  return score;
}
function fontPrefsSim(s, i) {
  const a = s.fontPrefs;
  const b = i.fontPrefs;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  const widthsA = a.widths && typeof a.widths === "object" ? a.widths : {};
  const widthsB = b.widths && typeof b.widths === "object" ? b.widths : {};
  const keys = Object.keys(widthsA).filter((k) => Object.prototype.hasOwnProperty.call(widthsB, k));
  let widthComparable = 0;
  let widthMatched = 0;
  for (const k of keys) {
    const x = widthsA[k];
    const y = widthsB[k];
    if (x === null || x === void 0 || y === null || y === void 0) continue;
    if (typeof x !== "number" || typeof y !== "number") continue;
    widthComparable += 1;
    if (Math.abs(x - y) < 1e-9) widthMatched += 1;
  }
  const widthRatio = widthComparable === 0 ? null : widthMatched / widthComparable;
  const emojiA = str(a.emojiRectHash);
  const emojiB = str(b.emojiRectHash);
  const emojiEq = emojiA && emojiB ? emojiA.toLowerCase() === emojiB.toLowerCase() ? 1 : 0 : null;
  if (widthRatio === null && emojiEq === null) return null;
  if (widthRatio === null) return emojiEq;
  if (emojiEq === null) return widthRatio;
  return 0.5 * widthRatio + 0.5 * emojiEq;
}
function miscSim(s, i) {
  const a = s.misc;
  const b = i.misc;
  if (!a && !b) return null;
  if (!a || !b) return 0;
  let comparable = 0;
  let matched = 0;
  const mA = str(a.mathHash);
  const mB = str(b.mathHash);
  if (mA && mB) {
    comparable += 1;
    if (mA.toLowerCase() === mB.toLowerCase()) matched += 1;
  }
  const eA = str(a.errorStackHash);
  const eB = str(b.errorStackHash);
  if (eA && eB) {
    comparable += 1;
    if (eA.toLowerCase() === eB.toLowerCase()) matched += 1;
  }
  return comparable === 0 ? null : matched / comparable;
}
var FAMILY_KERNELS = {
  gpu: (s, i) => gpuSim(s, i),
  cpu: (s, i) => cpuSim(s, i),
  screen: (s, i) => screenSim(s, i),
  timezone: (s, i) => timezoneSim(s, i),
  fonts: (s, i, mode) => fontsSim(s, i, mode),
  mediaDevices: (s, i) => mediaDevicesSim(s, i),
  canvas: (s, i, mode) => canvasSim(s, i, mode),
  webgl: (s, i) => webglSim(s, i),
  audio: (s, i) => audioSim(s, i),
  fontPrefs: (s, i) => fontPrefsSim(s, i),
  misc: (s, i) => miscSim(s, i)
};
var HARD_VIOLATION_OS = "os_family_mismatch";
var HARD_VIOLATION_ARCH = "cpu_arch_mismatch";
var VIOLATION_DOWNGRADE = "version_downgrade_anomaly";
var NOTE_DRIFT = "version_upgrade_drift_allowed";
function normalizeArch(arch) {
  const a = (arch ?? "").trim().toLowerCase();
  if (a === "amd64" || a === "x64" || a === "x86-64" || a === "x86_64" || a === "wow64") return "x86_64";
  if (a === "arm64" || a === "aarch64") return "arm64";
  if (a === "i386" || a === "i486" || a === "i586" || a === "i686" || a === "x86") return "x86";
  if (a.indexOf("arm") !== -1) return "arm";
  return a;
}
function hardwareSignalsMatch(raws) {
  const checks = [];
  const gpu = raws.gpu;
  if (gpu !== null) checks.push(gpu >= 0.6);
  const screen = raws.screen;
  if (screen !== null) checks.push(screen >= 0.85);
  const cpu = raws.cpu;
  if (cpu !== null) checks.push(cpu > 0);
  if (checks.length === 0) return false;
  return checks.every(Boolean);
}
function audioDrifted(s, i) {
  const a = s.audio;
  const b = i.audio;
  if (!a || !b) return false;
  const sumA = a.sum;
  const sumB = b.sum;
  if (typeof sumA !== "number" || !isFinite(sumA) || typeof sumB !== "number" || !isFinite(sumB)) return false;
  const scale = Math.max(Math.abs(sumA), Math.abs(sumB), 1e-12);
  return Math.abs(sumA - sumB) / scale >= 1e-4;
}
function round3(x) {
  return Math.round(x * 1e3) / 1e3;
}
function blankPerFamily(weights) {
  const out = {};
  for (const family of FAMILY_ORDER) {
    out[family] = { similarity: -1, weight: weights[family], contribution: 0 };
  }
  return out;
}
function compareFingerprints(stored, incoming, mode) {
  const safeMode = WEIGHT_MATRIX[mode] ? mode : "exact";
  const weights = WEIGHT_MATRIX[safeMode];
  const s = stored && typeof stored === "object" ? stored : {};
  const i = incoming && typeof incoming === "object" ? incoming : {};
  const raws = {};
  for (const family of FAMILY_ORDER) {
    let sim = null;
    try {
      sim = FAMILY_KERNELS[family](s, i, safeMode);
    } catch {
      sim = null;
    }
    raws[family] = sim === null || !isFinite(sim) ? null : Math.max(0, Math.min(1, sim));
  }
  const violations = [];
  const vs = s.versions;
  const vi = i.versions;
  const famA = str(vs?.browserFamily).toLowerCase();
  const famB = str(vi?.browserFamily).toLowerCase();
  const sameFamily = Boolean(famA && famB && famA === famB);
  const majorA = vs && typeof vs.browserMajor === "number" && isFinite(vs.browserMajor) ? vs.browserMajor : null;
  const majorB = vi && typeof vi.browserMajor === "number" && isFinite(vi.browserMajor) ? vi.browserMajor : null;
  let driftAllowed = false;
  if (sameFamily && majorA !== null && majorB !== null) {
    const delta = majorB - majorA;
    if (delta < 0) {
      violations.push(VIOLATION_DOWNGRADE);
    } else if (delta <= 3 && hardwareSignalsMatch(raws)) {
      driftAllowed = true;
    }
  }
  if (driftAllowed) {
    const canvasBoth = Boolean(s.canvas && i.canvas);
    const canvasDrift = canvasBoth && str(s.canvas.geometry) && str(s.canvas.geometry) === str(i.canvas.geometry) && str(s.canvas.text) && str(i.canvas.text) && str(s.canvas.text) !== str(i.canvas.text);
    const audioDrift = audioDrifted(s, i);
    if (canvasDrift) {
      raws.canvas = 1;
      violations.push(NOTE_DRIFT);
    } else if (audioDrift) {
      raws.audio = 1;
      violations.push(NOTE_DRIFT);
    }
  }
  const osA = str(s.cpu?.osFamily).toLowerCase();
  const osB = str(i.cpu?.osFamily).toLowerCase();
  const archA = normalizeArch(str(s.cpu?.arch));
  const archB = normalizeArch(str(i.cpu?.arch));
  const osMismatch = Boolean(osA && osB && osA !== osB);
  const archMismatch = Boolean(archA && archB && archA !== archB);
  if (osMismatch) violations.push(HARD_VIOLATION_OS);
  if (archMismatch) violations.push(HARD_VIOLATION_ARCH);
  const perFamily = blankPerFamily(weights);
  let weighted = 0;
  let weightSum = 0;
  const diffVector = [];
  for (const family of FAMILY_ORDER) {
    const sim = raws[family];
    const weight = weights[family];
    if (sim === null) {
      diffVector.push(-1);
      continue;
    }
    diffVector.push(round3(sim));
    perFamily[family].similarity = round3(sim);
    perFamily[family].contribution = weight * sim;
    weighted += weight * sim;
    weightSum += weight;
  }
  const matchScore = weightSum > 0 ? round3(weighted / weightSum * 100) : 0;
  let veto = false;
  if (safeMode !== "engine-only" && (osMismatch || archMismatch)) veto = true;
  if (safeMode !== "engine-only" && violations.indexOf(VIOLATION_DOWNGRADE) !== -1) veto = true;
  const threshold = MODE_THRESHOLDS[safeMode];
  let match = !veto && matchScore >= threshold;
  if (safeMode === "exact" && weightSum < 100) match = false;
  const hwFamilies = ["gpu", "cpu", "screen"];
  let hwWeighted = 0;
  let hwWeightSum = 0;
  for (const family of hwFamilies) {
    const sim = raws[family];
    if (sim === null) continue;
    hwWeighted += weights[family] * sim;
    hwWeightSum += weights[family];
  }
  let hardwareMatch = hwWeightSum > 0 ? hwWeighted / hwWeightSum >= 0.85 : false;
  if (safeMode === "cross-browser" && (raws.fonts ?? 0) >= 0.85) hardwareMatch = true;
  return {
    matchScore,
    match,
    hardwareMatch,
    mode: safeMode,
    constraintViolations: violations,
    diffVector,
    perFamily
  };
}
function bestMode(stored, incoming) {
  const order = ["lenient", "cross-browser", "hardware-only"];
  let best = null;
  for (const mode of order) {
    try {
      const result = compareFingerprints(stored, incoming, mode);
      if (result.match) return mode;
      if (best === null || result.matchScore > best.score) {
        best = { mode, score: result.matchScore };
      }
    } catch {
    }
  }
  return best === null ? "lenient" : best.mode;
}

// src/server/identity/confidenceScorer.ts
var SCORE_VERSION = "2.0";
var MIN_SCORE = 0.1;
var MAX_SCORE = 0.999;
var MAX_ENTROPY_BONUS = 0.014;
var HARDWARE_FLAG_HINTS = [
  "gpu",
  "canvas",
  "webgl",
  "font",
  "screen",
  "audio",
  "hardware",
  "core",
  "memory",
  "texture",
  "resolution",
  "color_depth",
  "device_memory",
  "cpu"
];
function round4(value) {
  return Math.round(value * 1e4) / 1e4;
}
function clamp(value, min, max) {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, value));
}
function isHardwareContradiction(flag) {
  const text = String(flag ?? "").toLowerCase();
  if (!text) return false;
  return HARDWARE_FLAG_HINTS.some((hint) => text.includes(hint));
}
function baseTierForMatch(input, reasons) {
  const mode = String(input.match_mode ?? "none");
  const matchScore = clamp(Number(input.match_score ?? 0), 0, 100);
  const entropy = input.entropy ?? {};
  const deterministicHardware = Boolean(entropy.deterministicCanvas) && Boolean(entropy.unmaskedWebgl);
  if (mode === "exact") {
    if (input.storage_healed) {
      reasons.push("exact_match_storage_confirmed");
      return 0.985;
    }
    reasons.push(
      input.incognito ? deterministicHardware ? "exact_match_incognito_deterministic_hardware" : "exact_match_incognito_storage_missing" : "exact_match_storage_missing"
    );
    return 0.96;
  }
  if (mode === "lenient") {
    const base = 0.91 + 0.05 * (matchScore - 82) / 18;
    reasons.push(`lenient_upgrade_match_score_${Math.round(matchScore)}`);
    return base;
  }
  if (mode === "cross_browser" || mode === "hardware") {
    const base = 0.85 + 0.06 * (matchScore - 85) / 15;
    reasons.push(`${mode === "hardware" ? "hardware_only" : "cross_browser"}_match_score_${Math.round(matchScore)}`);
    return base;
  }
  if (input.isMobileIos) {
    reasons.push("first_visit_ios_safari");
    return 0.8;
  }
  reasons.push(input.firstSeenDesktop ? "first_visit_clean_desktop" : "first_visit");
  return 0.9;
}
function entropyBonusFor(input, reasons) {
  const entropy = input.entropy ?? {};
  let bonus = 0;
  if (entropy.deterministicCanvas === true) {
    bonus += 4e-3;
    reasons.push("entropy_deterministic_canvas");
  }
  if (entropy.unmaskedWebgl === true) {
    bonus += 4e-3;
    reasons.push("entropy_unmasked_webgl");
  }
  const fontsCount = Number(entropy.fontsCount ?? 0);
  if (Number.isFinite(fontsCount) && fontsCount >= 12) {
    bonus += 3e-3;
    reasons.push(`entropy_fonts_count_${Math.round(fontsCount)}`);
  }
  if (entropy.deterministicAudio === true) {
    bonus += 3e-3;
    reasons.push("entropy_deterministic_audio");
  }
  return clamp(bonus, 0, MAX_ENTROPY_BONUS);
}
function consistencyPenaltyFor(input, reasons) {
  const flags = (Array.isArray(input.consistencyFlags) ? input.consistencyFlags : []).filter((flag) => typeof flag === "string" && flag.trim().length > 0);
  const hardwareFlags = flags.filter(isHardwareContradiction);
  const benignFlags = flags.filter((flag) => !isHardwareContradiction(flag));
  if (input.genuineSpoof === true) {
    reasons.push("consistency_genuine_spoof");
    for (const flag of flags) reasons.push(`consistency_flag:${flag}`);
    return { penalty: 0.35, tampering: true, tamperingMlScore: 0.9, spoofLikelihood: "high" };
  }
  if (input.rfpOrTor === true) {
    reasons.push("consistency_rfp_or_tor_uniformity");
    return { penalty: 0.25, tampering: false, tamperingMlScore: 0, spoofLikelihood: "medium" };
  }
  if (input.braveShields === true && hardwareFlags.length === 0) {
    reasons.push("consistency_brave_shields_no_hardware_contradiction");
    return { penalty: 0.03, tampering: false, tamperingMlScore: 0, spoofLikelihood: "low" };
  }
  for (const flag of benignFlags) reasons.push(`consistency_flag:${flag}`);
  if (hardwareFlags.length > 0) {
    for (const flag of hardwareFlags) reasons.push(`consistency_hardware_flag:${flag}`);
  }
  return { penalty: 0, tampering: false, tamperingMlScore: 0, spoofLikelihood: "low" };
}
function scoreConfidence(input) {
  try {
    const reasons = [];
    const baseTier = clamp(baseTierForMatch(input ?? {}, reasons), MIN_SCORE, MAX_SCORE);
    const entropyBonus = entropyBonusFor(input ?? {}, reasons);
    const consistency = consistencyPenaltyFor(input ?? {}, reasons);
    const score = clamp(baseTier + entropyBonus - consistency.penalty, MIN_SCORE, MAX_SCORE);
    return {
      score: round4(score),
      version: SCORE_VERSION,
      breakdown: {
        base_tier: round4(baseTier),
        entropy_bonus: round4(entropyBonus),
        penalty: round4(consistency.penalty),
        reasons
      },
      tampering: consistency.tampering,
      tampering_ml_score: consistency.tamperingMlScore,
      spoof_likelihood: consistency.spoofLikelihood
    };
  } catch {
    return {
      score: MIN_SCORE,
      version: SCORE_VERSION,
      breakdown: { base_tier: MIN_SCORE, entropy_bonus: 0, penalty: 0, reasons: ["scorer_fallback"] },
      tampering: false,
      tampering_ml_score: 0,
      spoof_likelihood: "low"
    };
  }
}

// src/server/identity/resolver.ts
function normalizeText2(value) {
  if (typeof value !== "string") return "";
  return value.trim().toLowerCase();
}
function parseMajor(value) {
  const text = normalizeText2(value);
  const match = /^(\d{1,5})/.exec(text);
  return match ? Number.parseInt(match[1], 10) : null;
}
function clampScore(score) {
  const num = typeof score === "number" ? score : Number(score);
  if (!Number.isFinite(num)) return 0;
  return Math.min(100, Math.max(0, Math.round(num * 100) / 100));
}
function confidenceHint(mode, score, isMobileIos) {
  return scoreConfidence({ match_mode: mode, match_score: score, isMobileIos }).score;
}
var LADDER_TIERS = [
  { mode: "hardware", min: 88, priority: 3 },
  { mode: "cross_browser", min: 85, priority: 2 },
  { mode: "lenient", min: 82, priority: 1 }
];
var EXACT_PRIORITY = 4;
var ENGINE_MODE_TIERS = {
  exact: { mode: "exact", min: 100, priority: EXACT_PRIORITY },
  strict: { mode: "lenient", min: 82, priority: 1 },
  lenient: { mode: "lenient", min: 82, priority: 1 },
  "cross-browser": { mode: "cross_browser", min: 85, priority: 2 },
  "hardware-only": { mode: "hardware", min: 88, priority: 3 },
  "engine-only": { mode: "cross_browser", min: 85, priority: 2 }
};
function tierForScore(score) {
  for (const tier of LADDER_TIERS) {
    if (score >= tier.min) return tier;
  }
  return null;
}
function normalizeComparison(raw) {
  const obj = raw && typeof raw === "object" ? raw : {};
  const score = clampScore(obj["match_score"] ?? obj["matchScore"] ?? obj["score"] ?? obj["similarity"]);
  const violationsRaw = obj["constraintViolations"] ?? obj["constraint_violations"] ?? obj["violations"];
  const violations = Array.isArray(violationsRaw) ? violationsRaw.filter((item) => typeof item === "string") : [];
  const engineMode = typeof obj["mode"] === "string" ? obj["mode"] : null;
  return { score, violations, engineMode };
}
var NEUTRAL_COMPARISON = { score: 0, violations: [], engineMode: null };
function engineInput(profile) {
  const source = profile ?? {};
  const adapted = { ...source };
  const timezone = source["timezone"];
  const timezoneSignals = source["timezoneSignals"];
  if ((timezone === null || timezone === void 0 || typeof timezone === "string") && timezoneSignals && typeof timezoneSignals === "object") {
    adapted["timezone"] = timezoneSignals;
  }
  return adapted;
}
async function runEngine(incoming, stored) {
  const engine = compareFingerprints;
  if (typeof engine !== "function") return NEUTRAL_COMPARISON;
  const storedInput = engineInput(stored);
  const incomingInput = engineInput(incoming);
  const pickMode = () => {
    try {
      const mode = bestMode(storedInput, incomingInput);
      return typeof mode === "string" ? mode : "";
    } catch {
      return "";
    }
  };
  const attempts = [
    () => engine(storedInput, incomingInput, pickMode()),
    () => engine(storedInput, incomingInput),
    () => engine(incomingInput, storedInput),
    () => engine({ stored: storedInput, incoming: incomingInput })
  ];
  for (const attempt of attempts) {
    try {
      const raw = await Promise.resolve(attempt());
      if (raw && typeof raw === "object") {
        return normalizeComparison(raw);
      }
    } catch {
    }
  }
  return NEUTRAL_COMPARISON;
}
var ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
var ID_LENGTH = 20;
function randomIdByte() {
  const cryptoRef = globalThis.crypto;
  if (typeof cryptoRef?.getRandomValues !== "function") return null;
  const buffer = new Uint8Array(1);
  for (let attempt = 0; attempt < 32; attempt += 1) {
    cryptoRef.getRandomValues(buffer);
    const byte = buffer[0];
    if (byte < 248) return byte;
  }
  return null;
}
function createLcgBytes() {
  let seed = (Date.now() ^ Math.floor(Math.random() * 4294967295)) >>> 0;
  return () => {
    seed = Math.imul(seed, 1664525) + 1013904223 >>> 0;
    return seed >>> 16 & 255;
  };
}
function idFromByte(byte) {
  return ID_ALPHABET[byte % ID_ALPHABET.length];
}
function mintVisitorId() {
  const lcg = createLcgBytes();
  let id = "";
  while (id.length < ID_LENGTH) {
    const byte = randomIdByte() ?? lcg();
    id += idFromByte(byte);
  }
  return id;
}
function generateVisitorId(db2) {
  const attempts = 4;
  for (let i = 0; i < attempts; i += 1) {
    const candidate = mintVisitorId();
    if (!db2) return candidate;
    try {
      const row = db2.prepare("SELECT visitor_id FROM visitor_profiles WHERE visitor_id = ?").get(candidate);
      if (!row || row.visitor_id !== candidate) return candidate;
    } catch {
      return candidate;
    }
  }
  return (mintVisitorId() + Date.now().toString(36).slice(-4)).slice(0, ID_LENGTH);
}
function upsertVisitorProfile(db2, visitorId, profile, hardwareFingerprint, nowUtc) {
  db2.prepare(
    `INSERT INTO visitor_profiles (visitor_id, profile_json, hardware_fingerprint, created_at_utc, updated_at_utc)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(visitor_id) DO UPDATE SET
       profile_json = COALESCE(excluded.profile_json, visitor_profiles.profile_json),
       hardware_fingerprint = COALESCE(excluded.hardware_fingerprint, visitor_profiles.hardware_fingerprint),
       updated_at_utc = excluded.updated_at_utc`
  ).run(visitorId, profile ? JSON.stringify(profile) : null, hardwareFingerprint, nowUtc, nowUtc);
}
function upsertVisitorLink(db2, visitorId, hardwareFingerprint, linkMode, linkScore, nowUtc) {
  const hardware = normalizeText2(hardwareFingerprint);
  if (!hardware) return;
  try {
    db2.prepare(
      `INSERT INTO visitor_links (visitor_id, hardware_fingerprint, link_mode, link_score, created_at_utc, last_seen_utc)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(visitor_id, hardware_fingerprint) DO UPDATE SET
         link_mode = excluded.link_mode,
         link_score = excluded.link_score,
         last_seen_utc = excluded.last_seen_utc`
    ).run(visitorId, hardware, linkMode, linkScore, nowUtc, nowUtc);
  } catch {
  }
}
var RENDERING_HASH_KEYS = ["canvas", "webgl", "audio"];
function versionsOf(profile) {
  if (!profile) return {};
  const versions = profile.versions;
  return versions && typeof versions === "object" ? versions : {};
}
function browserMajorOf(profile) {
  if (!profile) return null;
  const versions = versionsOf(profile);
  if (typeof versions.browserMajor === "number" && Number.isFinite(versions.browserMajor)) {
    return Math.floor(versions.browserMajor);
  }
  return parseMajor(profile.browser?.major);
}
function browserFamilyOf(profile) {
  if (!profile) return "";
  const family = versionsOf(profile).browserFamily;
  return typeof family === "string" && family.trim() ? family.trim() : normalizeText2(profile.browser?.family);
}
function healStoredProfile(stored, incoming) {
  const storedProfile = stored.profile;
  if (!storedProfile || typeof storedProfile !== "object") return { healed: false, nextProfile: null };
  let healed = false;
  const next = { ...storedProfile };
  const incomingMajor = browserMajorOf(incoming);
  const storedMajor = browserMajorOf(storedProfile);
  const driftAllowed = incomingMajor === null || storedMajor === null || incomingMajor >= storedMajor;
  if (incomingMajor !== null && storedMajor !== null && incomingMajor > storedMajor) {
    const storedBrowser = storedProfile.browser ?? {};
    next["browser"] = {
      ...storedBrowser,
      family: browserFamilyOf(incoming) || browserFamilyOf(storedProfile) || null,
      major: incoming.browser?.major ?? String(incomingMajor)
    };
    const incomingVersions = { ...versionsOf(incoming) };
    if (typeof incomingVersions.browserMajor === "number" || typeof versionsOf(storedProfile).browserMajor === "number") {
      next["versions"] = {
        ...versionsOf(storedProfile),
        ...incomingVersions,
        browserMajor: incomingMajor
      };
    }
    healed = true;
  }
  if (driftAllowed) {
    for (const key of RENDERING_HASH_KEYS) {
      const incomingHash = normalizeText2(incoming[key]?.hash);
      const storedHash = normalizeText2(storedProfile[key]?.hash);
      if (incomingHash && incomingHash !== storedHash) {
        next[key] = { ...storedProfile[key], hash: incomingHash };
        healed = true;
      }
    }
  }
  const incomingHw = normalizeText2(incoming.hardwareFingerprint);
  const storedHw = normalizeText2(stored.hardware_fingerprint) || normalizeText2(storedProfile.hardwareFingerprint);
  if (incomingHw && !storedHw) {
    next["hardwareFingerprint"] = incoming.hardwareFingerprint ?? null;
    healed = true;
  }
  return { healed, nextProfile: healed ? next : null };
}
function persistHeal(db2, stored, incoming, nowUtc) {
  const { healed, nextProfile } = healStoredProfile(stored, incoming);
  if (!healed || !nextProfile) return false;
  const incomingHw = normalizeText2(incoming.hardwareFingerprint);
  const hardware = normalizeText2(stored.hardware_fingerprint) || incomingHw || null;
  try {
    db2.prepare(
      "UPDATE visitor_profiles SET profile_json = ?, hardware_fingerprint = ?, updated_at_utc = ? WHERE visitor_id = ?"
    ).run(JSON.stringify(nextProfile), hardware, nowUtc, stored.visitor_id);
    return true;
  } catch {
    return false;
  }
}
function degradedResult(db2, input, reason, nowUtc) {
  let visitorId = generateVisitorId(db2 ?? void 0);
  try {
    if (db2) {
      upsertVisitorProfile(db2, visitorId, input.profile ?? null, normalizeText2(input.profile?.hardwareFingerprint) || null, nowUtc);
      upsertBlocks(db2, visitorId, blockKeysFor(input.profile ?? {}), nowUtc);
    }
  } catch {
    visitorId = generateVisitorId();
  }
  return {
    visitor_id: visitorId,
    match_mode: "none",
    match_score: 0,
    is_new: true,
    isNew: true,
    confidence_hint: confidenceHint("none", 0, Boolean(input.isMobileIos)),
    healed: false,
    reasons: [],
    degraded: true,
    degraded_reason: reason
  };
}
async function resolveVisitor(db2, input) {
  const nowUtc = (/* @__PURE__ */ new Date()).toISOString();
  try {
    ensureIdentitySchema(db2);
    const profile = input.profile && typeof input.profile === "object" ? input.profile : {};
    const incomingHw = normalizeText2(profile.hardwareFingerprint);
    const storageVisitorId = normalizeText2(input.storageVisitorId) || "";
    const keys = blockKeysFor(profile);
    if (storageVisitorId) {
      const stored = loadVisitorProfile(db2, storageVisitorId);
      if (stored) {
        const storedHw = normalizeText2(stored.hardware_fingerprint) || normalizeText2(stored.profile?.hardwareFingerprint);
        if (!incomingHw || !storedHw || incomingHw === storedHw) {
          upsertBlocks(db2, storageVisitorId, keys, nowUtc);
          return {
            visitor_id: storageVisitorId,
            match_mode: "exact",
            match_score: 100,
            is_new: false,
            isNew: false,
            confidence_hint: confidenceHint("exact", 100, Boolean(input.isMobileIos)),
            healed: false,
            reasons: []
          };
        }
      }
    }
    const candidateIds = findCandidates(db2, keys, 200);
    let best = null;
    for (const candidateId of candidateIds) {
      const stored = loadVisitorProfile(db2, candidateId);
      if (!stored) continue;
      if (stored.profile_json && stored.profile_json.includes("version_downgrade_anomaly")) continue;
      const storedHw = normalizeText2(stored.hardware_fingerprint) || normalizeText2(stored.profile?.hardwareFingerprint);
      if (incomingHw && storedHw && incomingHw === storedHw) {
        best = {
          id: candidateId,
          stored,
          mode: "exact",
          score: 100,
          violations: [],
          priority: EXACT_PRIORITY
        };
        break;
      }
      const { score, violations, engineMode } = await runEngine(profile, stored.profile);
      if (violations.includes("version_downgrade_anomaly")) continue;
      const tier = engineMode && ENGINE_MODE_TIERS[engineMode] || tierForScore(score);
      if (!tier || score < tier.min) continue;
      if (!best || tier.priority > best.priority || tier.priority === best.priority && score > best.score) {
        best = { id: candidateId, stored, mode: tier.mode, score, violations, priority: tier.priority };
      }
    }
    if (best) {
      const healed = persistHeal(db2, best.stored, profile, nowUtc);
      if (incomingHw) {
        upsertVisitorLink(db2, best.id, incomingHw, best.mode, best.score, nowUtc);
      }
      upsertBlocks(db2, best.id, keys, nowUtc);
      return {
        visitor_id: best.id,
        match_mode: best.mode,
        match_score: best.score,
        is_new: false,
        isNew: false,
        confidence_hint: confidenceHint(best.mode, best.score, Boolean(input.isMobileIos)),
        healed,
        reasons: best.violations,
        supplementary: best.mode === "cross_browser" ? { visitor_id: best.id, confidence_hint: 0.95 } : void 0
      };
    }
    const visitorId = generateVisitorId(db2);
    upsertVisitorProfile(db2, visitorId, profile, incomingHw || null, nowUtc);
    upsertBlocks(db2, visitorId, keys, nowUtc);
    return {
      visitor_id: visitorId,
      match_mode: "none",
      match_score: 0,
      is_new: true,
      isNew: true,
      confidence_hint: confidenceHint("none", 0, Boolean(input.isMobileIos)),
      healed: false,
      reasons: []
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message.slice(0, 200) : "identity resolver failure";
    return degradedResult(db2, input, reason, nowUtc);
  }
}

// server.ts
dotenv.config();
var PORT = Number(process.env.PORT) || 3e3;
var SESSION_TIMEOUT_MINUTES = 30;
var SESSION_EXPIRATION_MS = SESSION_TIMEOUT_MINUTES * 60 * 1e3;
var IS_SERVERLESS_RUNTIME = Boolean(
  process.env.VERCEL || process.env.VERCEL_ENV || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY
);
var HMAC_SECRET = process.env.VISITOR_HMAC_SECRET || "intel-system-first-party-hmac-secret-2026";
function createInMemoryDbAdapter() {
  const visitorsMap = /* @__PURE__ */ new Map();
  const visitsList = [];
  const geoCacheMap = /* @__PURE__ */ new Map();
  let autoIncrementId = 1;
  return {
    exec: () => {
    },
    prepare: (sql) => {
      const normalized = sql.replace(/\s+/g, " ").trim();
      return {
        get: (...params) => {
          if (normalized.includes("FROM verified_geo_cache_v3 WHERE ip_address = ?")) {
            const ip = String(params[0] || "");
            return geoCacheMap.get(ip);
          }
          if (normalized.includes("SELECT COUNT(*) AS count FROM visitors")) {
            return { count: visitorsMap.size };
          }
          if (normalized.includes("SELECT COUNT(*) AS count FROM visits")) {
            return { count: visitsList.length };
          }
          if (normalized.includes("SELECT * FROM visitors WHERE visitor_id = ?")) {
            const vid = String(params[0] || "");
            return visitorsMap.get(vid);
          }
          if (normalized.includes("SELECT * FROM visitors WHERE hardware_id = ?")) {
            const hwid = String(params[0] || "");
            if (!hwid || !hwid.startsWith("hwid_")) return void 0;
            const matches = Array.from(visitorsMap.values()).filter((v) => v.hardware_id === hwid).sort((a, b) => b.updated_at_utc.localeCompare(a.updated_at_utc));
            return matches[0];
          }
          if (normalized.includes("FROM visits WHERE visitor_id = ? AND page_load_id = ?")) {
            const vid = String(params[0] || "");
            const plId = String(params[1] || "");
            const found = visitsList.find(
              (v) => v.visitor_id === vid && v.page_load_id === plId
            );
            return found ? {
              visit_id: found.visit_id,
              session_id: found.session_id,
              visited_at_utc: found.visited_at_utc
            } : void 0;
          }
          if (normalized.includes("COUNT(*) AS total_visits") && normalized.includes("FROM visits WHERE visitor_id = ?")) {
            const vid = String(params[0] || "");
            const userVisits = visitsList.filter((v) => v.visitor_id === vid);
            if (userVisits.length === 0) {
              return {
                total_visits: 0,
                first_visit_utc: null,
                last_visit_utc: null,
                total_sessions: 0
              };
            }
            const sortedAsc = [...userVisits].sort(
              (a, b) => a.visited_at_utc.localeCompare(b.visited_at_utc)
            );
            const sessions = new Set(userVisits.map((v) => v.session_id));
            return {
              total_visits: userVisits.length,
              first_visit_utc: sortedAsc[0].visited_at_utc,
              last_visit_utc: sortedAsc[sortedAsc.length - 1].visited_at_utc,
              total_sessions: sessions.size
            };
          }
          if (normalized.includes("LIMIT 1 OFFSET 1")) {
            const vid = String(params[0] || "");
            const userVisits = visitsList.filter((v) => v.visitor_id === vid).sort((a, b) => b.visited_at_utc.localeCompare(a.visited_at_utc) || b.id - a.id);
            return userVisits.length > 1 ? { visited_at_utc: userVisits[1].visited_at_utc } : void 0;
          }
          return void 0;
        },
        all: (...params) => {
          if (normalized.includes("FROM visits WHERE visitor_id = ?")) {
            const vid = String(params[0] || "");
            return visitsList.filter((v) => v.visitor_id === vid).sort((a, b) => b.visited_at_utc.localeCompare(a.visited_at_utc) || b.id - a.id).slice(0, 50);
          }
          return [];
        },
        run: (...params) => {
          if (normalized.includes("INSERT OR REPLACE INTO verified_geo_cache_v3")) {
            const row = {
              ip_address: String(params[0] || ""),
              city: String(params[1] || "Unknown"),
              region: String(params[2] || "Unknown"),
              country: String(params[3] || "Unknown"),
              country_code: String(params[4] || ""),
              latitude: typeof params[5] === "number" ? params[5] : null,
              longitude: typeof params[6] === "number" ? params[6] : null,
              isp: String(params[7] || "Unknown"),
              org: String(params[8] || "Unknown"),
              asn: String(params[9] || "Unknown"),
              is_vpn_or_hosting: Number(params[10] || 0),
              verified_at_ms: Number(params[11] || Date.now())
            };
            geoCacheMap.set(row.ip_address, row);
            return { changes: 1 };
          }
          if (normalized.includes("INSERT INTO visitors") || normalized.includes("INSERT OR REPLACE INTO visitors")) {
            const hasHwCol = normalized.includes("hardware_id");
            const row = hasHwCol ? {
              visitor_id: String(params[0] || ""),
              hmac_token: String(params[1] || ""),
              hardware_id: String(params[2] || ""),
              created_at_utc: String(params[3] || ""),
              updated_at_utc: String(params[4] || ""),
              active_session_id: String(params[5] || ""),
              last_activity_utc: String(params[6] || "")
            } : {
              visitor_id: String(params[0] || ""),
              hmac_token: String(params[1] || ""),
              hardware_id: "",
              created_at_utc: String(params[2] || ""),
              updated_at_utc: String(params[3] || ""),
              active_session_id: String(params[4] || ""),
              last_activity_utc: String(params[5] || "")
            };
            visitorsMap.set(row.visitor_id, row);
            return { changes: 1 };
          }
          if (normalized.includes("UPDATE visitors")) {
            const hasHwUpdate = normalized.includes("hardware_id = ?");
            const vid = String(hasHwUpdate ? params[4] : params[3] || "");
            const existing = visitorsMap.get(vid);
            if (existing) {
              existing.updated_at_utc = String(params[0] || existing.updated_at_utc);
              existing.active_session_id = String(params[1] || existing.active_session_id);
              existing.last_activity_utc = String(params[2] || existing.last_activity_utc);
              if (hasHwUpdate && typeof params[3] === "string" && params[3]) {
                existing.hardware_id = params[3];
              }
              return { changes: 1 };
            }
            return { changes: 0 };
          }
          if (normalized.includes("INSERT OR IGNORE INTO visits")) {
            const visitId = String(params[0] || "");
            const visitorId = String(params[1] || "");
            const pageLoadId = String(params[3] || "");
            const duplicate = visitsList.some(
              (v) => v.visit_id === visitId || v.visitor_id === visitorId && v.page_load_id === pageLoadId
            );
            if (duplicate) {
              return { changes: 0 };
            }
            visitsList.push({
              id: autoIncrementId++,
              visit_id: visitId,
              visitor_id: visitorId,
              session_id: String(params[2] || ""),
              page_load_id: pageLoadId,
              visited_at_utc: String(params[4] || ""),
              public_ip: String(params[5] || "Unavailable"),
              city: String(params[6] || "Unknown"),
              region: String(params[7] || "Unknown"),
              country: String(params[8] || "Unknown"),
              latitude: typeof params[9] === "number" ? params[9] : null,
              longitude: typeof params[10] === "number" ? params[10] : null,
              isp: String(params[11] || "Unknown"),
              org: String(params[12] || "Unknown"),
              asn: String(params[13] || "Unknown"),
              browser: String(params[14] || "Unknown"),
              os: String(params[15] || "Unknown"),
              device_type: String(params[16] || "Unknown"),
              screen_resolution: String(params[17] || "Unavailable"),
              language: String(params[18] || "Unavailable"),
              timezone: String(params[19] || "Unavailable"),
              suspect_score: typeof params[20] === "number" ? params[20] : null,
              risk_level: typeof params[21] === "string" ? params[21] : null,
              score10: typeof params[22] === "number" ? params[22] : null,
              bot_name: typeof params[23] === "string" ? params[23] : null,
              recognition_source: typeof params[24] === "string" ? params[24] : null
            });
            return { changes: 1 };
          }
          if (normalized.includes("UPDATE visits") && normalized.includes("suspect_score = ?")) {
            const visitId = String(params[5] || "");
            const target = visitsList.find((v) => v.visit_id === visitId);
            if (!target) return { changes: 0 };
            target.suspect_score = typeof params[0] === "number" ? params[0] : null;
            target.risk_level = typeof params[1] === "string" ? params[1] : null;
            target.score10 = typeof params[2] === "number" ? params[2] : null;
            target.bot_name = typeof params[3] === "string" ? params[3] : null;
            target.recognition_source = typeof params[4] === "string" ? params[4] : null;
            return { changes: 1 };
          }
          return { changes: 0 };
        }
      };
    }
  };
}
function initializeDatabase() {
  if (process.env.INTEL_FORCE_MEMORY_DB === "1") {
    return createInMemoryDbAdapter();
  }
  let targetDir = path.join(os.tmpdir(), "intel-system-data");
  if (!IS_SERVERLESS_RUNTIME) {
    try {
      const localDataDir = path.resolve(process.cwd(), "data");
      if (!fs.existsSync(localDataDir)) {
        fs.mkdirSync(localDataDir, { recursive: true });
      }
      fs.accessSync(localDataDir, fs.constants.W_OK);
      targetDir = localDataDir;
    } catch {
      targetDir = path.join(os.tmpdir(), "intel-system-data");
    }
  }
  try {
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }
    const dbPath = path.join(targetDir, "intel_system.db");
    const requireModule = createRequire(import.meta.url);
    const BetterSqlite3 = requireModule("better-sqlite3");
    const sqliteDb = new BetterSqlite3(dbPath);
    sqliteDb.pragma("journal_mode = WAL");
    sqliteDb.pragma("foreign_keys = ON");
    sqliteDb.exec(`
      CREATE TABLE IF NOT EXISTS visitors (
        visitor_id TEXT PRIMARY KEY,
        hmac_token TEXT NOT NULL,
        hardware_id TEXT NOT NULL DEFAULT '',
        created_at_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL,
        active_session_id TEXT NOT NULL,
        last_activity_utc TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        visit_id TEXT UNIQUE NOT NULL,
        visitor_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        page_load_id TEXT NOT NULL,
        visited_at_utc TEXT NOT NULL,
        public_ip TEXT NOT NULL,
        city TEXT NOT NULL,
        region TEXT NOT NULL,
        country TEXT NOT NULL,
        latitude REAL,
        longitude REAL,
        isp TEXT NOT NULL DEFAULT 'Unknown',
        org TEXT NOT NULL DEFAULT 'Unknown',
        asn TEXT NOT NULL DEFAULT 'Unknown',
        browser TEXT NOT NULL,
        os TEXT NOT NULL,
        device_type TEXT NOT NULL,
        screen_resolution TEXT NOT NULL,
        language TEXT NOT NULL,
        timezone TEXT NOT NULL,
        suspect_score REAL,
        risk_level TEXT,
        score10 REAL,
        bot_name TEXT,
        recognition_source TEXT,
        UNIQUE(visitor_id, page_load_id),
        FOREIGN KEY (visitor_id) REFERENCES visitors(visitor_id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_visits_visitor_utc ON visits(visitor_id, visited_at_utc DESC, id DESC);

      CREATE TABLE IF NOT EXISTS verified_geo_cache_v3 (
        ip_address TEXT PRIMARY KEY,
        city TEXT NOT NULL,
        region TEXT NOT NULL,
        country TEXT NOT NULL,
        country_code TEXT NOT NULL,
        latitude REAL,
        longitude REAL,
        isp TEXT NOT NULL,
        org TEXT NOT NULL,
        asn TEXT NOT NULL,
        is_vpn_or_hosting INTEGER NOT NULL DEFAULT 0,
        timezone TEXT,
        verified_at_ms INTEGER NOT NULL
      );

      ${IDENTITY_SCHEMA_SQL}

      DROP TABLE IF EXISTS ai_bot_cidr_ranges;
      DROP TABLE IF EXISTS ai_bot_dns_cache;
      DROP TABLE IF EXISTS ai_bot_jwk_cache;
      DROP TABLE IF EXISTS ai_bot_requests;
      DROP TABLE IF EXISTS ai_operator_referrals;
      DROP TABLE IF EXISTS ai_zone_config;
    `);
    try {
      sqliteDb.exec(`ALTER TABLE visitors ADD COLUMN hardware_id TEXT NOT NULL DEFAULT ''`);
    } catch {
    }
    try {
      sqliteDb.exec(`CREATE INDEX IF NOT EXISTS idx_visitors_hwid ON visitors(hardware_id)`);
    } catch {
    }
    for (const col of ["isp", "org", "asn"]) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} TEXT NOT NULL DEFAULT 'Unknown'`);
      } catch {
      }
    }
    for (const col of ["latitude", "longitude"]) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} REAL`);
      } catch {
      }
      try {
        sqliteDb.exec(`ALTER TABLE verified_geo_cache_v3 ADD COLUMN ${col} REAL`);
      } catch {
      }
    }
    try {
      sqliteDb.exec(`ALTER TABLE verified_geo_cache_v3 ADD COLUMN timezone TEXT`);
    } catch {
    }
    for (const col of ["suspect_score", "score10"]) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} REAL`);
      } catch {
      }
    }
    for (const col of ["risk_level", "bot_name", "recognition_source"]) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} TEXT`);
      } catch {
      }
    }
    return sqliteDb;
  } catch {
    return createInMemoryDbAdapter();
  }
}
var db = initializeDatabase();
function signVisitorId(visitorId) {
  return crypto.createHmac("sha256", HMAC_SECRET).update(visitorId).digest("hex");
}
function verifyVisitorToken(visitorId, token) {
  if (!visitorId || !token || typeof visitorId !== "string" || typeof token !== "string") {
    return false;
  }
  const expected = signVisitorId(visitorId);
  if (expected.length !== token.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(token, "hex"));
  } catch {
    return false;
  }
}
function computeHistoryBackupSignature(visitorId, totalVisits, totalSessions, firstVisitUtc, visits, legacyDigest = false) {
  const visitDigest = visits.map(
    (v) => legacyDigest ? `${v.visitId}:${v.sessionId}:${v.visitedAtUtc}:${v.publicIp}` : `${v.visitId}:${v.sessionId}:${v.visitedAtUtc}:${v.publicIp}:${typeof v.suspectScore === "number" ? v.suspectScore : 0}:${v.riskLevel ?? "Low"}:${v.botName ?? ""}`
  ).join("|");
  const payload = `hist:${visitorId}:${totalVisits}:${totalSessions}:${firstVisitUtc}:${visitDigest}`;
  return crypto.createHmac("sha256", HMAC_SECRET).update(payload).digest("hex");
}
function createSignedHistoryBackup(visitorId, totalVisits, totalSessions, firstVisitUtc, visits, hardwareId) {
  const compactVisits = visits.slice(0, 35);
  const signature = computeHistoryBackupSignature(
    visitorId,
    totalVisits,
    totalSessions,
    firstVisitUtc,
    compactVisits
  );
  return {
    visitorId,
    hardwareId,
    totalVisits,
    totalSessions,
    firstVisitUtc,
    visits: compactVisits,
    signature
  };
}
function verifySignedHistoryBackup(expectedVisitorId, backup) {
  if (!backup || typeof backup !== "object" || backup.visitorId !== expectedVisitorId || typeof backup.signature !== "string" || typeof backup.totalVisits !== "number" || typeof backup.totalSessions !== "number" || typeof backup.firstVisitUtc !== "string" || !Array.isArray(backup.visits)) {
    return false;
  }
  const expectedSig = computeHistoryBackupSignature(
    backup.visitorId,
    backup.totalVisits,
    backup.totalSessions,
    backup.firstVisitUtc,
    backup.visits
  );
  const legacySig = computeHistoryBackupSignature(
    backup.visitorId,
    backup.totalVisits,
    backup.totalSessions,
    backup.firstVisitUtc,
    backup.visits,
    true
  );
  const matches = [expectedSig, legacySig].some((candidate) => {
    if (candidate.length !== backup.signature.length) return false;
    try {
      return crypto.timingSafeEqual(
        Buffer.from(candidate, "hex"),
        Buffer.from(backup.signature, "hex")
      );
    } catch {
      return false;
    }
  });
  return matches;
}
function generateVisitorId2() {
  return "vid_" + crypto.randomBytes(10).toString("hex");
}
function generateSessionId() {
  return "ses_" + crypto.randomBytes(6).toString("hex");
}
function generateVisitId() {
  return "vst_" + crypto.randomBytes(8).toString("hex");
}
function normalizeIpCandidate(raw) {
  if (!raw || typeof raw !== "string") return null;
  let candidate = raw.trim().replace(/^["']|["']$/g, "");
  if (!candidate) return null;
  if (candidate.toLowerCase().startsWith("for=")) {
    candidate = candidate.slice(4).trim().replace(/^["']|["']$/g, "");
  }
  if (candidate.startsWith("[")) {
    const closeBracket = candidate.indexOf("]");
    if (closeBracket !== -1) {
      candidate = candidate.slice(1, closeBracket);
    }
  } else {
    const colonCount = (candidate.match(/:/g) || []).length;
    if (colonCount === 1 && candidate.includes(".")) {
      candidate = candidate.split(":")[0];
    }
  }
  if (candidate.toLowerCase().startsWith("::ffff:")) {
    candidate = candidate.slice(7);
  }
  const zoneIdx = candidate.indexOf("%");
  if (zoneIdx !== -1) {
    candidate = candidate.slice(0, zoneIdx);
  }
  const ipVersion = net.isIP(candidate);
  if (ipVersion === 0) return null;
  return candidate;
}
function isPublicRoutableIp(ip) {
  if (!ip) return false;
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split(".").map((n) => parseInt(n, 10));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false;
    return true;
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower === "::" || lower === "0:0:0:0:0:0:0:1" || lower === "0:0:0:0:0:0:0:0") {
      return false;
    }
    if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) {
      return false;
    }
    if (lower.startsWith("fc") || lower.startsWith("fd")) {
      return false;
    }
    if (lower.startsWith("ff")) {
      return false;
    }
    return true;
  }
  return false;
}
function extractVisitorIp(req) {
  const singleHeaders = [
    "cf-connecting-ip",
    "x-vercel-forwarded-for",
    "x-vercel-proxied-for"
  ];
  for (const headerName of singleHeaders) {
    const rawVal = req.headers[headerName];
    if (typeof rawVal === "string" && rawVal.trim()) {
      const firstHop = rawVal.split(",")[0];
      const normalized = normalizeIpCandidate(firstHop);
      if (normalized && isPublicRoutableIp(normalized)) {
        return { ip: normalized, isPublic: true };
      }
    }
  }
  const xff = req.headers["x-forwarded-for"];
  const xffList = Array.isArray(xff) ? xff.join(",") : typeof xff === "string" ? xff : "";
  if (xffList) {
    const hops = xffList.split(",");
    for (const hop of hops) {
      const normalized = normalizeIpCandidate(hop);
      if (normalized && isPublicRoutableIp(normalized)) {
        return { ip: normalized, isPublic: true };
      }
    }
  }
  const forwarded = req.headers["forwarded"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    const segments = forwarded.split(/[,;]/);
    for (const seg of segments) {
      if (seg.trim().toLowerCase().startsWith("for=")) {
        const normalized = normalizeIpCandidate(seg.trim());
        if (normalized && isPublicRoutableIp(normalized)) {
          return { ip: normalized, isPublic: true };
        }
      }
    }
  }
  const fallbackHeaders = ["x-real-ip", "x-client-ip", "x-appengine-user-ip"];
  for (const headerName of fallbackHeaders) {
    const rawVal = req.headers[headerName];
    if (typeof rawVal === "string" && rawVal.trim()) {
      const normalized = normalizeIpCandidate(rawVal.split(",")[0]);
      if (normalized && isPublicRoutableIp(normalized)) {
        return { ip: normalized, isPublic: true };
      }
    }
  }
  const socketIp = normalizeIpCandidate(req.socket?.remoteAddress);
  if (socketIp && isPublicRoutableIp(socketIp)) {
    return { ip: socketIp, isPublic: true };
  }
  return { ip: "Unavailable", isPublic: false };
}
function normalizeIspAndOrg(rawIspInput, rawOrgInput, rawAsnInput, explicitHostingOrVpnFlag = false) {
  let cleanIsp = typeof rawIspInput === "string" ? rawIspInput.trim() : "";
  let cleanOrg = typeof rawOrgInput === "string" ? rawOrgInput.trim() : "";
  let cleanAsn = "";
  if (typeof rawAsnInput === "number" && Number.isFinite(rawAsnInput)) {
    cleanAsn = `AS${rawAsnInput}`;
  } else if (typeof rawAsnInput === "string" && rawAsnInput.trim()) {
    const trimmedAsn = rawAsnInput.trim();
    cleanAsn = /^AS\d+/i.test(trimmedAsn) ? trimmedAsn.toUpperCase() : `AS${trimmedAsn}`;
  }
  const stripEmbeddedAsn = (text) => {
    const match = text.match(/^(AS\d+)\s+(.+)$/i);
    if (match) {
      return { asnFound: match[1].toUpperCase(), rest: match[2].trim() };
    }
    return { asnFound: "", rest: text };
  };
  if (cleanIsp) {
    const parsed = stripEmbeddedAsn(cleanIsp);
    if (!cleanAsn && parsed.asnFound) cleanAsn = parsed.asnFound;
    cleanIsp = parsed.rest;
  }
  if (cleanOrg) {
    const parsed = stripEmbeddedAsn(cleanOrg);
    if (!cleanAsn && parsed.asnFound) cleanAsn = parsed.asnFound;
    cleanOrg = parsed.rest;
  }
  const combinedSource = `${cleanIsp} ${cleanOrg}`.trim();
  if (!combinedSource || combinedSource.toLowerCase() === "unknown") {
    return {
      isp: "Unknown",
      org: "Unknown",
      asn: cleanAsn || "Unknown",
      isVpnOrHosting: explicitHostingOrVpnFlag
    };
  }
  const lower = combinedSource.toLowerCase();
  let recognizableBrand = null;
  if (/\bjio\b|reliance jio/i.test(combinedSource)) {
    recognizableBrand = "Jio";
  } else if (/\bairtel\b|bharti airtel|bharti hexacom/i.test(combinedSource)) {
    recognizableBrand = "Airtel";
  } else if (/\bbsnl\b|bharat sanchar|national internet backbone/i.test(combinedSource)) {
    recognizableBrand = "BSNL";
  } else if (/\bact\b|act fibernet|atria convergence|beam telecom/i.test(combinedSource)) {
    recognizableBrand = "ACT";
  } else if (/vodafone idea|\bvodafone\b|\bidea cellular\b/i.test(combinedSource)) {
    recognizableBrand = "Vodafone Idea";
  } else if (/tata play fiber|tata teleservices|tata communications/i.test(combinedSource)) {
    recognizableBrand = "Tata";
  } else if (/\bhathway\b/i.test(combinedSource)) {
    recognizableBrand = "Hathway";
  } else if (/\bexcitel\b/i.test(combinedSource)) {
    recognizableBrand = "Excitel";
  } else if (/\bmtnl\b|mahanagar telephone/i.test(combinedSource)) {
    recognizableBrand = "MTNL";
  } else if (/\brailwire\b|\brailtel\b/i.test(combinedSource)) {
    recognizableBrand = "RailWire";
  } else if (/\byou broadband\b/i.test(combinedSource)) {
    recognizableBrand = "YOU Broadband";
  } else if (/\basianet\b/i.test(combinedSource)) {
    recognizableBrand = "Asianet";
  } else if (/\balliance broadband\b/i.test(combinedSource)) {
    recognizableBrand = "Alliance Broadband";
  }
  const primaryProvider = cleanIsp || cleanOrg;
  let formattedIsp = primaryProvider;
  if (recognizableBrand) {
    if (primaryProvider.toLowerCase() === recognizableBrand.toLowerCase()) {
      formattedIsp = recognizableBrand;
    } else {
      formattedIsp = `${recognizableBrand} (${primaryProvider})`;
    }
  }
  const hostingOrVpnKeywords = [
    "google",
    "gcp",
    "as15169",
    "as396982",
    "mullvad",
    "nordvpn",
    "expressvpn",
    "protonvpn",
    "surfshark",
    "cyberghost",
    "m247",
    "datacamp",
    "tzulo",
    "digitalocean",
    "linode",
    "vultr",
    "choopa",
    "hetzner",
    "ovh",
    "leaseweb",
    "amazon",
    "aws",
    "cloudflare",
    "microsoft corporation",
    "azure",
    "oracle",
    "akamai",
    "fastly",
    "zscaler",
    "netskope",
    "palo alto networks"
  ];
  const asnAndSourceLower = `${lower} ${(cleanAsn || "").toLowerCase()}`;
  const isVpnOrHosting = explicitHostingOrVpnFlag || hostingOrVpnKeywords.some((kw) => asnAndSourceLower.includes(kw));
  return {
    isp: formattedIsp || "Unknown",
    org: cleanOrg || cleanIsp || "Unknown",
    asn: cleanAsn || "Unknown",
    isVpnOrHosting
  };
}
var CLOUD_PROVIDER_ASN_NUMBERS = /* @__PURE__ */ new Set([
  396178,
  15169,
  16509,
  14618,
  13335,
  14061,
  9009,
  60068,
  24940,
  63949,
  16276,
  8075,
  20473
]);
var TOR_OPERATOR_ASN_SET = /* @__PURE__ */ new Set([
  "AS215125",
  // Church of Cyberology / Nothing to Hide
  "AS60729",
  // Zwiebelfreunde e.V. / Torservers.net
  "AS208323",
  // Foundation for Applied Privacy
  "AS396507",
  // Emerald Onion
  "AS200052",
  // Artikel10 e.V.
  "AS206848",
  // CCC Stuttgart / Chaos Computer Club
  "AS205100",
  // F3 Netze e.V.
  "AS199695"
  // Nos Oignons
]);
var TOR_OPERATOR_ORG_PATTERN = /\b(church of cyberology|cyberology|nothing to hide|nothingtohide|hart voor internetvrijheid|zwiebelfreunde|torservers|emerald onion|emeraldonion|applied privacy|applied-privacy|nos oignons|nos-oignons|artikel10|f3\s?netze|ccc stuttgart|r0cket|tor\s?exit|tor\s?relay)\b/i;
var TOR_OPERATOR_IPV4_CIDRS = ["192.42.116.0/24"];
var TOR_OPERATOR_IPV6_PREFIXES = ["2001:67c:e60::/48", "2a02:898:256::/48"];
var TOR_OPERATOR_REVERSE_DNS_PATTERN = /\b(tor-?exit|tor-?relay|exit-?node|nothingtohide\.nl|hartvoorinternetvrijheid\.nl|cyberology\.(nl|church)|torservers\.net|emeraldonion\.org|applied-privacy\.net|artikel10\.org|nos-oignons\.net|tor\.r0cket\.net)\b/i;
var VPN_PROXY_PATTERN = /\b(vpn|nordvpn|expressvpn|surfshark|cyberghost|private internet access|proton\s?vpn|mullvad|windscribe|ipvanish|hide\.?me|hola vpn|psiphon|packet hub|packethub|tor ?guard|proxy|socks5|smart dns)\b/i;
var MOBILE_CARRIER_PATTERN = /\b(mobile|cellular|wireless|5g|4g|lte|t-mobile|tmobile|verizon wireless|cellco|vodafone|orange s\.?a|telefonica|movistar|claro|tim s\.?p\.?a|mtn)\b/i;
function matchesTorOperatorAsn(asn) {
  const clean = typeof asn === "string" ? asn.trim().toUpperCase() : "";
  if (!clean) return false;
  return TOR_OPERATOR_ASN_SET.has(clean.startsWith("AS") ? clean : `AS${clean}`);
}
function classifyIspNetwork(isp, org, asn) {
  const cleanIsp = typeof isp === "string" ? isp.trim() : "";
  const cleanOrg = typeof org === "string" ? org.trim() : "";
  const cleanAsn = typeof asn === "string" ? asn.trim().toUpperCase() : "";
  const keywordHaystack = `${cleanIsp} ${cleanOrg}`;
  const asnNumbers = /* @__PURE__ */ new Set();
  const asnTokenRegex = /\bAS(\d{1,10})\b/gi;
  let asnTokenMatch;
  while ((asnTokenMatch = asnTokenRegex.exec(`${cleanAsn} ${keywordHaystack}`)) !== null) {
    const parsedAsn = Number.parseInt(asnTokenMatch[1], 10);
    if (Number.isFinite(parsedAsn)) asnNumbers.add(parsedAsn);
  }
  const matchConsumerRule = (brand, networkType, asns, keywords) => {
    const asnHit = asns.find((a) => asnNumbers.has(a));
    const keywordHit = keywords !== null && keywords.test(keywordHaystack);
    if (asnHit === void 0 && !keywordHit) return null;
    return {
      brandName: brand,
      networkType,
      isConsumerBroadband: true,
      isDatacenterOrHosting: false,
      matchedReason: asnHit !== void 0 ? `ASN AS${asnHit}` : `ISP metadata keyword ${String(keywords)}`
    };
  };
  const mobileHomeMatch = () => matchConsumerRule("Verizon 5G Home", "Cellular / 5G", [6167, 22394], /cellco|verizon wireless/i) || matchConsumerRule("T-Mobile 5G Home", "Cellular / 5G", [21928], /t-mobile|tmobile/i);
  const satelliteMatch = () => matchConsumerRule("Starlink (SpaceX)", "Satellite", [14593], /starlink|spacex/i);
  const residentialMatch = () => (
    // US consumer broadband (Residential Broadband)
    matchConsumerRule("Xfinity (Comcast)", "Residential Broadband", [7922, 7015, 7016], /comcast|xfinity/i) || matchConsumerRule("Spectrum (Charter)", "Residential Broadband", [20115, 11426, 10796], /charter|spectrum/i) || matchConsumerRule("AT&T Fiber", "Residential Broadband", [7018, 20057], /at&t|att services|sbcglobal/i) || matchConsumerRule("Verizon Fios", "Residential Broadband", [701, 19262], /fios|mci communications|verizon online/i) || matchConsumerRule("Optimum", "Residential Broadband", [6128, 19108], /optimum|cablevision|altice|suddenlink/i) || matchConsumerRule("Cox", "Residential Broadband", [22773], /\bcox\b/i) || matchConsumerRule("Frontier / CenturyLink", "Residential Broadband", [5650, 209], null) || matchConsumerRule("Google Fiber", "Residential Broadband", [16591], /google fiber|gfiber/i) || // India consumer broadband (Residential Broadband)
    matchConsumerRule("Jio (Reliance Jio)", "Residential Broadband", [55836], /reliance jio|\bjio\b/i) || matchConsumerRule("Airtel Xstream", "Residential Broadband", [24560, 45609, 9498], /bharti airtel|\bairtel\b/i) || matchConsumerRule("ACT Fibernet", "Residential Broadband", [24309], /act fibernet|atria convergence/i) || matchConsumerRule("BSNL Broadband", "Residential Broadband", [9829], /\bbsnl\b|bharat sanchar/i) || matchConsumerRule("Tata Play / Hathway", "Residential Broadband", [], /tata play|tata sky broadband|hathway|excitel/i)
  );
  const asnTokenHits = Array.from(asnNumbers).map((n) => `AS${n}`);
  const torAsnHit = asnTokenHits.find((token) => matchesTorOperatorAsn(token));
  const torOrgHit = TOR_OPERATOR_ORG_PATTERN.test(keywordHaystack);
  if (torAsnHit !== void 0 || torOrgHit) {
    return {
      brandName: cleanIsp && !/^unknown( isp)?$/i.test(cleanIsp) ? cleanIsp : cleanOrg && !/^unknown( isp)?$/i.test(cleanOrg) ? cleanOrg : "Tor Relay Operator",
      networkType: "Cloud / Datacenter",
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: torAsnHit !== void 0 ? `Tor operator ASN ${torAsnHit}` : "Tor operator organisation"
    };
  }
  const cloudAsnHit = Array.from(asnNumbers).find((n) => CLOUD_PROVIDER_ASN_NUMBERS.has(n));
  const cloudKeywords = /google llc|google cloud|amazonaws|cloudflare|digitalocean|hetzner|m247|datacamp|linode|ovh|choopa|vultr|leaseweb|hostinger|contabo|akamai|oracle cloud|alibaba|aliyun|tencent cloud/i;
  if (cloudAsnHit !== void 0 || cloudKeywords.test(keywordHaystack)) {
    return {
      // Prefer the real operator name (Google LLC, Amazon.com, Inc., Microsoft
      // Corporation, Cloudflare, Inc.) so an unresolved provider lookup never surfaces a
      // generic or anonymous cloud label.
      brandName: cloudProviderOrgForAsn(`AS${cloudAsnHit ?? ""}`) || (cleanIsp && !/^unknown( isp)?$/i.test(cleanIsp) ? cleanIsp : cleanOrg && !/^unknown( isp)?$/i.test(cleanOrg) ? cleanOrg : "Cloud Provider / Datacenter"),
      networkType: "Cloud / Datacenter",
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: cloudAsnHit !== void 0 ? `ASN AS${cloudAsnHit}` : `ISP metadata keyword ${String(cloudKeywords)}`
    };
  }
  if (VPN_PROXY_PATTERN.test(keywordHaystack)) {
    return {
      brandName: cleanIsp || cleanOrg || "VPN / Proxy Provider",
      networkType: "VPN / Proxy Relay",
      isConsumerBroadband: false,
      isDatacenterOrHosting: false,
      matchedReason: "VPN / proxy provider keyword"
    };
  }
  const mobileHome = mobileHomeMatch();
  if (mobileHome) return mobileHome;
  if (MOBILE_CARRIER_PATTERN.test(keywordHaystack)) {
    return {
      brandName: cleanIsp || cleanOrg || "Mobile Carrier",
      networkType: "Mobile Carrier",
      isConsumerBroadband: false,
      isDatacenterOrHosting: false,
      matchedReason: "Cellular carrier keyword"
    };
  }
  const satellite = satelliteMatch();
  if (satellite) return satellite;
  const residential = residentialMatch();
  if (residential) return residential;
  return {
    brandName: cleanIsp && !/^(unknown|unknown isp|n\/a)$/i.test(cleanIsp) ? cleanIsp : cleanOrg && !/^(unknown|unknown isp|n\/a)$/i.test(cleanOrg) ? cleanOrg : asnTokenHits[0] ?? "Standard Network",
    networkType: "Standard Network",
    isConsumerBroadband: false,
    isDatacenterOrHosting: false,
    matchedReason: null
  };
}
function applyNetworkOverrides(base, context) {
  const torNetwork = context.torExit;
  if (torNetwork) {
    return {
      ...base,
      networkType: "Tor Exit / Anonymity Network",
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || "Tor anonymity network"
    };
  }
  if (context.aiAgentDetected && base.networkType === "Cloud / Datacenter") {
    return {
      ...base,
      networkType: "AI Agent Cloud Network",
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || "AI agent cloud infrastructure"
    };
  }
  if (context.datacenterVm && base.networkType !== "Cloud / Datacenter") {
    return {
      ...base,
      networkType: "Cloud / Datacenter",
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || "Cloud VM / masked GPU footprint"
    };
  }
  if (context.vpnSuspected && base.networkType === "Residential Broadband") {
    return {
      ...base,
      networkType: "VPN / Proxy Relay",
      isConsumerBroadband: false,
      matchedReason: base.matchedReason || "VPN indicator on a residential line"
    };
  }
  if (base.networkType === "Residential Broadband" && !base.isConsumerBroadband) {
    return { ...base, networkType: "Standard Network" };
  }
  return base;
}
function readRequestHeader(headers, name) {
  if (!headers) return "";
  const direct = headers[name.toLowerCase()];
  const raw = Array.isArray(direct) ? direct.join(", ") : direct;
  return typeof raw === "string" ? raw.trim() : "";
}
function detectProxyHeaders(headers, resolvedIp) {
  const reasons = [];
  if (!headers) return { detected: false, reasons };
  if (readRequestHeader(headers, "proxy-authorization")) {
    reasons.push("Proxy-Authorization header");
  }
  if (readRequestHeader(headers, "proxy-connection")) {
    reasons.push("Proxy-Connection header");
  }
  const via = readRequestHeader(headers, "via").toLowerCase();
  if (via && !/varnish|vegur|cloudflare|akamai|fastly|vercel|netlify/.test(via)) {
    reasons.push(`Via header (${via.slice(0, 80)})`);
  }
  const forwarded = readRequestHeader(headers, "forwarded");
  if (forwarded) {
    for (const segment of forwarded.split(/[,;]/)) {
      const match = /for="?\[?([0-9a-f:.]+)\]?"?/i.exec(segment.trim());
      const hop = match?.[1]?.replace(/^::ffff:/, "");
      if (hop && hop !== resolvedIp && isPublicRoutableIp(hop)) {
        reasons.push(`Forwarded header names upstream relay ${hop}`);
        break;
      }
    }
  }
  const xff = readRequestHeader(headers, "x-forwarded-for");
  if (xff) {
    const hops = new Set(
      xff.split(",").map((hop) => normalizeIpCandidate(hop)).filter((hop) => Boolean(hop) && isPublicRoutableIp(hop))
    );
    if (hops.size >= 3) {
      reasons.push(`X-Forwarded-For chain with ${hops.size} public hops`);
    }
  }
  return { detected: reasons.length > 0, reasons };
}
function detectUaFamily(userAgent) {
  const ua = userAgent.toLowerCase();
  if (!ua) return "";
  if (/edg\//.test(ua)) return "edge";
  if (/opr\/|opera/.test(ua)) return "opera";
  if (/firefox\/|fxios/.test(ua)) return "firefox";
  if (/chrome\/|crios|chromium\//.test(ua)) return "chrome";
  if (/safari\//.test(ua)) return "safari";
  if (/^curl\//.test(ua)) return "curl";
  if (/postmanruntime/.test(ua)) return "postman";
  if (/python-requests|python-urllib|aiohttp/.test(ua)) return "python";
  if (/^wget\//.test(ua)) return "wget";
  if (/^node-fetch|undici|axios/.test(ua)) return "node";
  return "";
}
function detectUaOs(userAgent) {
  const ua = userAgent.toLowerCase();
  if (/windows nt|win32|win64/.test(ua)) return "windows";
  if (/android/.test(ua)) return "android";
  if (/iphone|ipad|ipod/.test(ua)) return "ios";
  if (/macintosh|mac os x/.test(ua)) return "macos";
  if (/cros/.test(ua)) return "chromeos";
  if (/linux|x11/.test(ua)) return "linux";
  return "";
}
function userAgentsCompatible(headerUserAgent, payloadUserAgent) {
  const header = headerUserAgent.trim();
  const payload = payloadUserAgent.trim();
  if (!header || !payload || header === payload) return true;
  const shorter = header.length <= payload.length ? header : payload;
  const longer = header.length <= payload.length ? payload : header;
  if (shorter.length >= 24 && longer.startsWith(shorter)) return true;
  const headerFamily = detectUaFamily(header);
  const payloadFamily = detectUaFamily(payload);
  if (headerFamily && payloadFamily && headerFamily !== payloadFamily) return false;
  const headerOs = detectUaOs(header);
  const payloadOs = detectUaOs(payload);
  if (headerOs && payloadOs && headerOs !== payloadOs) return false;
  return true;
}
var GOOD_BOT_UA_RULES = [
  {
    pattern: /googlebot/i,
    provider: "Google",
    label: "Googlebot",
    category: "Search Crawler",
    network: /google/i
  },
  {
    pattern: /bingbot|bingpreview/i,
    provider: "Microsoft",
    label: "Bingbot",
    category: "Search Crawler",
    network: /microsoft|\bbing\b/i
  },
  {
    pattern: /applebot/i,
    provider: "Apple",
    label: "Applebot",
    category: "Search Crawler",
    network: /\bapple\b/i
  },
  {
    pattern: /duckduckbot/i,
    provider: "DuckDuckGo",
    label: "DuckDuckBot",
    category: "Search Crawler",
    network: /duckduckgo/i
  },
  {
    pattern: /linkedinbot/i,
    provider: "LinkedIn",
    label: "LinkedInBot",
    category: "Link Preview",
    network: /linkedin/i
  },
  {
    pattern: /twitterbot/i,
    provider: "X (Twitter)",
    label: "Twitterbot",
    category: "Link Preview",
    network: /twitter|\bx corp\b/i
  },
  {
    pattern: /slackbot/i,
    provider: "Slack",
    label: "Slackbot",
    category: "Link Preview",
    network: /slack/i
  },
  {
    pattern: /vercelbot/i,
    provider: "Vercel",
    label: "Vercelbot",
    category: "Link Preview",
    network: /vercel/i
  }
];
var AI_AGENT_UA_RULES = [
  { pattern: /gptbot/i, provider: "OpenAI", label: "GPTBot" },
  { pattern: /chatgpt-user/i, provider: "OpenAI", label: "ChatGPT-User" },
  { pattern: /oai-searchbot/i, provider: "OpenAI", label: "OAI-SearchBot" },
  { pattern: /claudebot/i, provider: "Anthropic", label: "ClaudeBot" },
  { pattern: /claude-web/i, provider: "Anthropic", label: "Claude-Web" },
  { pattern: /anthropic-ai/i, provider: "Anthropic", label: "Anthropic-AI" },
  { pattern: /perplexitybot/i, provider: "Perplexity", label: "PerplexityBot" },
  { pattern: /perplexity-user/i, provider: "Perplexity", label: "Perplexity-User" },
  { pattern: /google-extended/i, provider: "Google", label: "Google-Extended" },
  { pattern: /ccbot/i, provider: "Common Crawl", label: "CCBot" },
  { pattern: /bytespider/i, provider: "ByteDance", label: "Bytespider" },
  { pattern: /cohere-ai/i, provider: "Cohere", label: "Cohere-AI" },
  { pattern: /meta-externalagent/i, provider: "Meta", label: "Meta-ExternalAgent" },
  { pattern: /headlesschrome/i, provider: "Cloud Browser Agent", label: "Headless Chrome" }
];
var AUTOMATION_UA_PATTERN = /playwright|puppeteer|selenium|cypress|phantomjs/i;
var BOT_SIGNATURE_KEYID_PROVIDERS = [
  ["openai", "OpenAI"],
  ["anthropic", "Anthropic"],
  ["perplexity", "Perplexity"],
  ["google", "Google"],
  ["microsoft", "Microsoft"],
  ["apple", "Apple"],
  ["amazon", "Amazon"],
  ["cloudflare", "Cloudflare"],
  ["web-bot-auth", "Web Bot Auth Directory"]
];
var DATACENTER_NETWORK_PATTERN = /\b(amazon|amazonaws|aws|google cloud|azure|microsoft azure|digitalocean|hetzner|linode|akamai|ovh|vultr|oracle cloud|alibaba|aliyun|tencent|leaseweb|contabo|m247|choopa|datacamp)\b/i;
var KNOWN_AI_CRAWLER_REASON = "LLM crawler user-agent signature";
function classifyBotTraffic(headers, network, client) {
  const ua = readRequestHeader(headers, "user-agent");
  const acceptLanguage = readRequestHeader(headers, "accept-language");
  const secFetchSite = readRequestHeader(headers, "sec-fetch-site");
  const secFetchMode = readRequestHeader(headers, "sec-fetch-mode");
  const secFetchDest = readRequestHeader(headers, "sec-fetch-dest");
  const networkHaystack = [network.org, network.isp, network.asn].filter((part) => typeof part === "string" && part.trim().length > 0).join(" ");
  const clientSignals = Array.isArray(client.botSignals) ? client.botSignals.filter((s) => typeof s === "string" && s.trim().length > 0) : [];
  for (const rule of GOOD_BOT_UA_RULES) {
    if (!rule.pattern.test(ua)) continue;
    if (rule.network.test(networkHaystack)) {
      return {
        subtype: "good_bot",
        label: rule.label,
        provider: rule.provider,
        category: rule.category,
        confidence: 0.97,
        reasons: [
          `${rule.label} user-agent matched`,
          `Network identity (${networkHaystack || "unknown"}) matches ${rule.provider}`
        ]
      };
    }
    return {
      subtype: "bad_bot",
      label: "Spoofed Crawler",
      provider: `Unverified ${rule.provider} claim`,
      category: "Spoofed Identity",
      confidence: 0.99,
      reasons: [
        `${rule.label} user-agent presented`,
        `Network identity (${networkHaystack || "unknown"}) does not belong to ${rule.provider}`
      ]
    };
  }
  for (const rule of AI_AGENT_UA_RULES) {
    if (!rule.pattern.test(ua)) continue;
    return {
      subtype: "ai_agent",
      label: rule.label,
      provider: rule.provider,
      category: rule.provider === "Cloud Browser Agent" ? "Autonomous Agent" : "AI Crawler",
      confidence: rule.provider === "Cloud Browser Agent" ? 0.85 : 0.92,
      reasons: [
        `${rule.label} user-agent matched`,
        networkHaystack ? `Network identity: ${networkHaystack}` : "Network identity unavailable"
      ]
    };
  }
  const signatureInput = readRequestHeader(headers, "signature-input");
  const signatureHeader = readRequestHeader(headers, "signature");
  if (signatureInput && signatureHeader) {
    const keyIdMatch = /keyid\s*=\s*"([^"]+)"/i.exec(signatureInput);
    const keyId = keyIdMatch ? keyIdMatch[1].trim().slice(0, 80) : "";
    const keyIdLower = keyId.toLowerCase();
    const namedOperator = BOT_SIGNATURE_KEYID_PROVIDERS.find(
      ([needle]) => keyIdLower.includes(needle)
    );
    return {
      subtype: "ai_agent",
      label: "Web Bot Auth Agent",
      provider: namedOperator ? namedOperator[1] : keyId || "RFC 9421 Signer",
      category: "Autonomous Agent",
      confidence: 0.9,
      reasons: [
        "RFC 9421 Signature / Signature-Input headers present (Web Bot Auth)",
        keyId ? `Agent key identifier: ${keyId}` : "Agent key identifier not published"
      ]
    };
  }
  const datacenterNetwork = DATACENTER_NETWORK_PATTERN.test(networkHaystack);
  const automationRuntimeDetected = Boolean(client.webdriver || client.cdpDetected);
  if (automationRuntimeDetected && datacenterNetwork) {
    return {
      subtype: "ai_agent",
      label: "Cloud Browser Agent",
      provider: "Cloud Browser Agent",
      category: "Autonomous Agent",
      confidence: 0.78,
      reasons: [
        client.webdriver ? "WebDriver runtime binding present" : "CDP runtime binding present",
        `Datacenter ASN hosting the agent (${networkHaystack})`
      ]
    };
  }
  if (client.stealthPluginDetected || client.cdpRuntimeLeak) {
    const reasons = [];
    if (client.cdpRuntimeLeak) {
      reasons.push("CDP Runtime.enable serialization leak (Error.prepareStackTrace invoked)");
    }
    if (client.stealthPluginDetected) {
      reasons.push("Stealth plugin artifacts (rewritten native getters / iframe identity leak)");
    }
    for (const signal of clientSignals.slice(0, 2)) reasons.push(signal);
    return {
      subtype: "bad_bot",
      label: client.stealthPluginDetected ? "Puppeteer / Playwright Stealth" : "HeadlessChrome / CDP Automation",
      provider: client.stealthPluginDetected ? "Stealth Automation (Puppeteer/Playwright)" : "Chromium",
      category: "Automation",
      confidence: 0.94,
      reasons
    };
  }
  const isDesktopChromeOrSafari = /chrome\/|crios\/|safari\//i.test(ua) && !/mobile|android|iphone|ipad/i.test(ua);
  const missingFetchMetadata = !secFetchSite && !secFetchMode && !secFetchDest;
  const headerAnomaly = isDesktopChromeOrSafari && missingFetchMetadata && !acceptLanguage;
  const headlessUa = /headlesschrome|phantomjs|slimerjs/i.test(ua);
  const corroboratedClientBot = Boolean(client.isBot) && Boolean(client.webdriver || client.cdpDetected || headlessUa);
  if (corroboratedClientBot || client.webdriver || client.cdpDetected || AUTOMATION_UA_PATTERN.test(ua) || headerAnomaly) {
    const reasons = [];
    if (client.isBot) reasons.push("Client reported an automated runtime");
    if (client.webdriver) reasons.push("WebDriver handshake detected");
    if (client.cdpDetected) reasons.push("Chrome DevTools Protocol binding detected");
    if (AUTOMATION_UA_PATTERN.test(ua)) reasons.push("Automation framework signature in user-agent");
    if (headerAnomaly) {
      reasons.push("Desktop browser user-agent without accept-language or sec-fetch metadata");
    }
    for (const signal of clientSignals.slice(0, 2)) reasons.push(signal);
    return {
      subtype: "bad_bot",
      label: AUTOMATION_UA_PATTERN.test(ua) ? "Automation Runtime" : "Automation / Header Anomaly",
      provider: "Unattributed Automation",
      category: "Automation",
      confidence: client.isBot || automationRuntimeDetected ? 0.93 : 0.7,
      reasons: reasons.length > 0 ? reasons : ["Automated traffic signature detected"]
    };
  }
  return {
    subtype: "human",
    label: "Verified Human",
    provider: "None",
    category: "Human Interaction",
    confidence: 0.6,
    reasons: ["Interactive browser profile without automation signatures"]
  };
}
var AI_BOT_CIDR_SOURCES = [
  { id: "chatgpt-user", url: "https://openai.com/chatgpt-user.json" },
  { id: "gptbot", url: "https://openai.com/gptbot.json" },
  { id: "searchbot", url: "https://openai.com/searchbot.json" },
  {
    id: "google-common",
    url: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"
  },
  {
    id: "google-user-triggered",
    url: "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json"
  },
  {
    id: "google-user-triggered-google",
    url: "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json"
  }
];
var AI_BOT_CIDR_SYNC_INTERVAL_MS = 6 * 60 * 60 * 1e3;
var AI_BOT_CIDR_TIMEOUT_MS = 1e4;
var AI_AUTH_DIRECTORY_TIMEOUT_MS = 1500;
var AI_AUTH_DIRECTORY_TTL_MS = 60 * 60 * 1e3;
var AI_FORWARD_DNS_TIMEOUT_MS = 1200;
var AI_FORWARD_DNS_TTL_MS = 60 * 60 * 1e3;
var AI_VERDICT_TABLE_MAX_ENTRIES = 1e4;
var aiBotPrefixTable = /* @__PURE__ */ new Map();
var aiBotCidrLastSyncMs = 0;
var aiBotCidrSyncInFlight = null;
var aiBotCidrTimer = null;
var aiAuthDirectoryCache = /* @__PURE__ */ new Map();
var aiForwardConfirmedDnsCache = /* @__PURE__ */ new Map();
function extractAiPrefixes(payload) {
  const prefixes = [];
  const visit = (value, depth) => {
    if (depth > 4 || value === null || typeof value !== "object") return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    const record = value;
    for (const key of ["ipv4Prefix", "ipv6Prefix", "prefix"]) {
      const raw = record[key];
      if (typeof raw === "string" && raw.includes("/")) prefixes.push(raw.trim());
    }
    for (const nested of Object.values(record)) {
      if (nested && typeof nested === "object") visit(nested, depth + 1);
    }
  };
  visit(payload, 0);
  return Array.from(new Set(prefixes));
}
async function syncAiBotCidrs() {
  const next = /* @__PURE__ */ new Map();
  await Promise.all(
    AI_BOT_CIDR_SOURCES.map(async (source) => {
      const body = await fetchTextWithTimeout(
        source.url,
        AI_BOT_CIDR_TIMEOUT_MS,
        "application/json"
      );
      if (!body) return;
      try {
        const prefixes = extractAiPrefixes(JSON.parse(body));
        if (prefixes.length > 0) next.set(source.id, prefixes);
      } catch {
      }
    })
  );
  if (next.size === 0) return;
  const merged = new Map(aiBotPrefixTable);
  for (const [id, prefixes] of next) merged.set(id, prefixes);
  aiBotPrefixTable = merged;
  aiBotCidrLastSyncMs = Date.now();
}
function runAiBotCidrSync() {
  if (aiBotCidrSyncInFlight) return aiBotCidrSyncInFlight;
  aiBotCidrSyncInFlight = syncAiBotCidrs().catch(() => void 0).finally(() => {
    aiBotCidrSyncInFlight = null;
  });
  return aiBotCidrSyncInFlight;
}
function ensureAiBotCidrSync() {
  if (aiBotCidrTimer === null) {
    void runAiBotCidrSync();
    aiBotCidrTimer = setInterval(() => {
      void runAiBotCidrSync();
    }, AI_BOT_CIDR_SYNC_INTERVAL_MS);
    const handle = aiBotCidrTimer;
    if (typeof handle.unref === "function") handle.unref();
    return;
  }
  if (Date.now() - aiBotCidrLastSyncMs >= AI_BOT_CIDR_SYNC_INTERVAL_MS) {
    void runAiBotCidrSync();
  }
}
try {
  ensureAiBotCidrSync();
} catch {
}
function matchesAiPrefixTable(ip, ids) {
  return ids.some((id) => ipMatchesCidrList(ip, aiBotPrefixTable.get(id) ?? []));
}
function firstHttpsUrl(text) {
  const match = /https?:\/\/[^\s",;)]+/i.exec(text);
  return match ? match[0].replace(/[.;]+$/, "") : null;
}
function resolveSignatureAgentOperator(host, label) {
  const lowerHost = host.toLowerCase();
  const lowerLabel = label.toLowerCase();
  if (lowerHost === "agent.bot.goog" || lowerHost.endsWith(".bot.goog") || lowerHost.endsWith("bot.goog") || lowerLabel === "g") {
    return "google";
  }
  if (lowerHost.endsWith("openai.com") || lowerHost.endsWith("chatgpt.com")) return "openai";
  if (lowerHost.endsWith("perplexity.ai")) return "perplexity";
  if (lowerHost.endsWith("anthropic.com") || lowerHost.endsWith("claude.ai")) return "anthropic";
  if (lowerHost.endsWith("browserbase.com")) return "browserbase";
  if (lowerHost.endsWith("anchorbrowser.io")) return "anchorbrowser";
  if (lowerHost.endsWith("x.ai") || lowerHost.endsWith("grok.com")) return "xai";
  if (lowerHost.endsWith("meta.com") || lowerHost.endsWith("facebook.com")) return "meta";
  return null;
}
function parseWebBotAuthHeaders(headers) {
  const signatureInput = readRequestHeader(headers, "signature-input");
  const signature = readRequestHeader(headers, "signature");
  const signatureAgent = readRequestHeader(headers, "signature-agent");
  const labelMatch = /^\s*([A-Za-z0-9_-]+)\s*=/.exec(signatureInput);
  const keyIdMatch = /keyid\s*=\s*"([^"]+)"/i.exec(signatureInput);
  const tagMatch = /tag\s*=\s*"([^"]+)"/i.exec(signatureInput);
  const agentUrl = signatureAgent ? firstHttpsUrl(signatureAgent) : null;
  let agentHost = "";
  if (agentUrl) {
    try {
      agentHost = new URL(agentUrl).hostname.toLowerCase();
    } catch {
      agentHost = "";
    }
  }
  const label = labelMatch ? labelMatch[1] : "";
  return {
    present: Boolean(signatureInput && signature),
    label,
    keyId: keyIdMatch ? keyIdMatch[1].trim().slice(0, 160) : "",
    tag: tagMatch ? tagMatch[1].trim().slice(0, 80) : "",
    agentUrl,
    agentHost,
    operator: resolveSignatureAgentOperator(agentHost, label)
  };
}
async function fetchWebBotAuthDirectory(agentUrl) {
  let origin = "";
  try {
    origin = new URL(agentUrl).origin;
  } catch {
    return null;
  }
  const nowMs = Date.now();
  const cached = aiAuthDirectoryCache.get(origin);
  if (cached && cached.expiresAtMs > nowMs) {
    return { clientName: cached.clientName, trigger: cached.trigger };
  }
  const body = await fetchTextWithTimeout(
    `${origin}/.well-known/http-message-signatures-directory`,
    AI_AUTH_DIRECTORY_TIMEOUT_MS,
    "application/json"
  );
  if (!body) return null;
  let clientName = "";
  let trigger = null;
  const visit = (value, depth) => {
    if (depth > 4 || value === null || typeof value !== "object") return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    const record = value;
    if (!clientName) {
      const name = record.client_name ?? record.clientName;
      if (typeof name === "string" && name.trim()) clientName = name.trim().slice(0, 120);
    }
    if (trigger === null) {
      const rawTrigger = record.trigger;
      if (typeof rawTrigger === "string" && /fetcher|crawler/i.test(rawTrigger)) {
        trigger = /fetcher/i.test(rawTrigger) ? "fetcher" : "crawler";
      }
    }
    for (const nested of Object.values(record)) {
      if (nested && typeof nested === "object") visit(nested, depth + 1);
    }
  };
  try {
    visit(JSON.parse(body), 0);
  } catch {
    return null;
  }
  if (!clientName && trigger === null) return null;
  if (aiAuthDirectoryCache.size > 500) aiAuthDirectoryCache.clear();
  aiAuthDirectoryCache.set(origin, {
    clientName,
    trigger,
    expiresAtMs: nowMs + AI_AUTH_DIRECTORY_TTL_MS
  });
  return { clientName, trigger };
}
async function resolveForwardConfirmedReverseDns(ip) {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return [];
  const nowMs = Date.now();
  const cached = aiForwardConfirmedDnsCache.get(normalized);
  if (cached && cached.expiresAtMs > nowMs) return cached.names;
  const reverseNames = await resolveTorReverseDns(normalized);
  const isV4 = isIpv4Literal(normalized);
  const confirmed = [];
  const forwardLookup = async (name) => {
    if (!/^[a-z0-9.-]+$/i.test(name)) return [];
    let timeoutHandle;
    try {
      const lookup = (isV4 ? dns.resolve4(name) : dns.resolve6(name)).catch(
        () => []
      );
      const timeout = new Promise((resolve) => {
        timeoutHandle = setTimeout(() => resolve([]), AI_FORWARD_DNS_TIMEOUT_MS);
      });
      const addresses = await Promise.race([lookup, timeout]);
      return Array.isArray(addresses) ? addresses : [];
    } catch {
      return [];
    } finally {
      if (timeoutHandle !== void 0) clearTimeout(timeoutHandle);
    }
  };
  for (const name of reverseNames.slice(0, 3)) {
    const addresses = await forwardLookup(name);
    if (addresses.some((address) => normalizeIpAddress(address) === normalized)) {
      confirmed.push(name);
    }
  }
  if (aiForwardConfirmedDnsCache.size > AI_VERDICT_TABLE_MAX_ENTRIES) {
    aiForwardConfirmedDnsCache.clear();
  }
  aiForwardConfirmedDnsCache.set(normalized, {
    names: confirmed,
    expiresAtMs: nowMs + AI_FORWARD_DNS_TTL_MS
  });
  return confirmed;
}
function hostMatchesSuffix(names, suffixes) {
  return names.some((name) => {
    const lower = name.toLowerCase().replace(/\.$/, "");
    return suffixes.some((suffix) => lower === suffix || lower.endsWith(`.${suffix}`));
  });
}
function asnDigits(asn) {
  if (typeof asn !== "string") return "";
  const match = /(\d{1,10})/.exec(asn);
  return match ? match[1] : "";
}
function asnIn(asn, digits) {
  const value = asnDigits(asn);
  return value.length > 0 && digits.includes(value);
}
var GOOGLE_VERIFICATION_SUFFIXES = ["googlebot.com", "google.com"];
var OPENAI_VERIFICATION_SUFFIXES = ["openai.com", "chatgpt.com"];
var PERPLEXITY_VERIFICATION_SUFFIXES = ["perplexity.ai"];
var ANTHROPIC_VERIFICATION_SUFFIXES = ["anthropic.com", "claude.ai"];
var XAI_VERIFICATION_SUFFIXES = ["x.ai", "grok.com"];
var META_VERIFICATION_SUFFIXES = ["facebook.com", "meta.com", "fb.com"];
var GCP_ASNS = ["15169", "396982"];
var XAI_ASNS = ["400562", "13414"];
var META_ASNS = ["32934", "63293"];
var AWS_ASNS = ["16509", "14618"];
var AZURE_ASNS = ["8075"];
var PERPLEXITY_ASNS = ["209242"];
var NO_AI_AGENT = {
  detected: false,
  agentId: null,
  agentName: "",
  operator: "",
  executionMode: null,
  verified: false,
  confidence: "Medium",
  riskScore: 0,
  evidence: []
};
function aiAgentResult(partial) {
  return {
    detected: true,
    riskScore: partial.riskScore ?? (partial.agentId === "impostor-spoof" ? 10 : 8),
    ...partial
  };
}
async function resolveAiAgentIdentity(input) {
  const ua = input.userAgent || readRequestHeader(input.headers, "user-agent");
  if (!ua) return NO_AI_AGENT;
  const webBotAuth = parseWebBotAuthHeaders(input.headers);
  const referer = `${readRequestHeader(input.headers, "referer")} ${readRequestHeader(
    input.headers,
    "origin"
  )}`;
  const networkHaystack = [input.network.org, input.network.isp, input.network.asn].filter((part) => typeof part === "string" && part.trim().length > 0).join(" \xB7 ");
  let confirmedNamesPromise = null;
  const confirmedNames = () => {
    if (confirmedNamesPromise === null) {
      confirmedNamesPromise = resolveForwardConfirmedReverseDns(input.publicIp);
    }
    return confirmedNamesPromise;
  };
  const gpuRenderer = (input.client.gpuRenderer || "").toLowerCase();
  const maskedGpu = !gpuRenderer || gpuRenderer === "unavailable" || /swiftshader|llvmpipe|mesa|software|generic|^standard/.test(gpuRenderer);
  const idbRatio = typeof input.client.idbDurabilityRatio === "number" ? input.client.idbDurabilityRatio : null;
  const clientAutomation = Boolean(
    input.client.webdriver || input.client.cdpDetected || input.client.isBot && input.client.isHeadless
  );
  const desktopChrome = /chrome\//i.test(ua) && !/mobile|android|iphone|ipad/i.test(ua);
  const screen = (input.client.screenResolution || "").toLowerCase();
  const claudeComputerUseViewport = screen.includes("1024x768") || screen.includes("1280x800") || screen.includes("1280\xD7800");
  const silentCloudTelemetry = Boolean(
    input.client.isVirtualMachine || idbRatio !== null && idbRatio > 0.95 && maskedGpu || desktopChrome && clientAutomation && maskedGpu
  );
  const signatureEvidence = webBotAuth.present ? [
    "RFC 9421 Signature / Signature-Input headers present (Web Bot Auth)",
    webBotAuth.label ? `Signature label: ${webBotAuth.label}` : "",
    webBotAuth.agentUrl ? `Signature-Agent: ${webBotAuth.agentUrl}` : "",
    webBotAuth.keyId ? `keyid: ${webBotAuth.keyId}` : ""
  ].filter(Boolean) : [];
  const directoryHint = webBotAuth.agentUrl ? await fetchWebBotAuthDirectory(webBotAuth.agentUrl) : null;
  const directoryEvidence = directoryHint ? [
    directoryHint.clientName ? `Agent directory client_name: ${directoryHint.clientName}` : "",
    directoryHint.trigger ? `Agent trigger: ${directoryHint.trigger}` : ""
  ].filter(Boolean) : [];
  const remoteBrowserUa = /firecrawl|browserbase|browser[-_ ]?use|skyvern|multion|hyperbrowser|steel[-_ ]?browser|airtop|\bnotte\b|lightpanda|browserless|scrapingbee|scrapfly|zenrows|brightdata|oxylabs|\bzyte\b/i;
  if (remoteBrowserUa.test(ua)) {
    const remoteOperator = /firecrawl/i.test(ua) ? "Firecrawl" : /browserbase/i.test(ua) ? "Browserbase" : /browser[-_ ]?use/i.test(ua) ? "Browser Use" : /skyvern/i.test(ua) ? "Skyvern" : /multion/i.test(ua) ? "MultiOn" : /hyperbrowser/i.test(ua) ? "Hyperbrowser" : /steel[-_ ]?browser/i.test(ua) ? "Steel" : /airtop/i.test(ua) ? "Airtop" : /notte/i.test(ua) ? "Notte" : /lightpanda/i.test(ua) ? "Lightpanda" : /browserless/i.test(ua) ? "Browserless" : /scrapingbee/i.test(ua) ? "ScrapingBee" : /scrapfly/i.test(ua) ? "Scrapfly" : /zenrows/i.test(ua) ? "ZenRows" : /brightdata/i.test(ua) ? "Bright Data" : /oxylabs/i.test(ua) ? "Oxylabs" : "Zyte";
    return aiAgentResult({
      agentId: "remote-browser",
      agentName: `${remoteOperator} Remote Browser Agent`,
      operator: remoteOperator,
      executionMode: "Remote Browser Agent",
      verified: false,
      confidence: clientAutomation ? "High" : "Medium",
      evidence: [
        `Remote browser agent user-agent: ${ua.slice(0, 120)}`,
        clientAutomation ? "Automation runtime flags confirmed the harness (WebDriver / CDP / headless)" : "User-agent claim without an automation flag",
        networkHaystack ? `Network identity: ${networkHaystack}` : ""
      ].filter(Boolean)
    });
  }
  if (/\bgooglebot\b/i.test(ua)) {
    const googleCidr = matchesAiPrefixTable(input.publicIp, [
      "google-common",
      "google-user-triggered",
      "google-user-triggered-google"
    ]);
    const googleDnsNames = await confirmedNames();
    const googleDns = hostMatchesSuffix(googleDnsNames, GOOGLE_VERIFICATION_SUFFIXES);
    const googleRangesLoaded = (aiBotPrefixTable.get("google-common")?.length ?? 0) > 0;
    if (googleCidr || googleDns) {
      return aiAgentResult({
        agentId: "gemini",
        agentName: "Googlebot (Verified Google Crawler)",
        operator: "Google LLC",
        executionMode: "Autonomous Crawler",
        verified: true,
        confidence: "Verified",
        evidence: [
          `Googlebot user-agent: ${ua.slice(0, 120)}`,
          googleCidr ? "Source IP matched a Google official crawler CIDR range" : "",
          googleDns ? "FCrDNS matched *.googlebot.com / *.google.com" : ""
        ].filter(Boolean)
      });
    }
    const googleOwnedNetwork = asnIn(input.network.asn, GCP_ASNS) || /google/i.test(input.network.org || "");
    if (googleRangesLoaded && !googleOwnedNetwork) {
      return aiAgentResult({
        agentId: "impostor-spoof",
        agentName: "Spoofed Google Bot Impostor (Unverified IP)",
        operator: "Unverified Google claim",
        executionMode: "Spoofed Impostor",
        verified: false,
        confidence: "Verified",
        evidence: [
          `Googlebot user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not inside Google's official crawler ranges`,
          "Forward-confirmed reverse DNS does not resolve to googlebot.com / google.com"
        ]
      });
    }
    return NO_AI_AGENT;
  }
  const geminiUa = /Gemini-Deep-Research|GoogleAgent-Mariner|Google-NotebookLM|Google-CloudVertexBot|Google-Extended|GoogleOther(-Image|-Video)?|Google-InspectionTool/i.test(
    ua
  );
  if (webBotAuth.operator === "google" || geminiUa) {
    const googleCidr = matchesAiPrefixTable(input.publicIp, [
      "google-common",
      "google-user-triggered",
      "google-user-triggered-google"
    ]);
    const googleDnsNames = await confirmedNames();
    const googleDns = hostMatchesSuffix(googleDnsNames, GOOGLE_VERIFICATION_SUFFIXES);
    const googleRangesLoaded = (aiBotPrefixTable.get("google-common")?.length ?? 0) > 0;
    const verified = webBotAuth.operator === "google" || googleCidr || googleDns;
    if (geminiUa && !verified && googleRangesLoaded) {
      return aiAgentResult({
        agentId: "impostor-spoof",
        agentName: "Spoofed Google Gemini Agent (Unverified IP)",
        operator: "Unverified Google claim",
        executionMode: "Spoofed Impostor",
        verified: false,
        confidence: "Verified",
        evidence: [
          `Gemini / Google agent user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not inside Google's official crawler ranges`,
          "Forward-confirmed reverse DNS does not resolve to googlebot.com / google.com"
        ]
      });
    }
    return aiAgentResult({
      agentId: "gemini",
      agentName: directoryHint?.clientName || (verified ? "Google Gemini (Mariner / Deep Research)" : "Google Gemini / Cloud Agent (GCP VM)"),
      operator: "Google LLC",
      executionMode: webBotAuth.operator === "google" ? "RFC 9421 Signed Agent" : geminiUa && !clientAutomation ? "User-Triggered Fetcher" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : googleRangesLoaded || googleDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "google" ? signatureEvidence : [],
        ...geminiUa ? [`Google AI agent user-agent: ${ua.slice(0, 120)}`] : [],
        ...googleCidr ? ["Source IP matched a Google official crawler CIDR range"] : [],
        ...googleDns ? ["FCrDNS matched *.googlebot.com / *.google.com"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  if ((asnIn(input.network.asn, GCP_ASNS) || hostMatchesSuffix(await confirmedNames(), ["googleusercontent.com"])) && (webBotAuth.present || silentCloudTelemetry)) {
    return aiAgentResult({
      agentId: "gemini",
      agentName: "Google Gemini / Cloud Agent (GCP VM)",
      operator: "Google LLC",
      executionMode: webBotAuth.present ? "RFC 9421 Signed Agent" : "Silent Cloud VM Browser",
      verified: webBotAuth.present,
      confidence: webBotAuth.present ? "Verified" : "High",
      evidence: [
        ...signatureEvidence,
        ...asnIn(input.network.asn, GCP_ASNS) ? [`Google Cloud ASN (${input.network.asn}) hosting the browser`] : ["Reverse DNS matched *.googleusercontent.com"],
        ...silentCloudTelemetry ? ["Cloud-VM browser telemetry (masked WebGL / ephemeral storage)"] : []
      ]
    });
  }
  const grokUa = /GrokBot|xAI-GrokBot|Grok-Search|xAI-Bot|\bGrok\b/i.test(ua);
  const grokReferer = /grok\.com|x\.ai/i.test(referer);
  if (webBotAuth.operator === "xai" || grokUa || grokReferer) {
    const xaiDnsNames = await confirmedNames();
    const xaiDns = hostMatchesSuffix(xaiDnsNames, XAI_VERIFICATION_SUFFIXES);
    const xaiAsn = asnIn(input.network.asn, XAI_ASNS);
    const verified = webBotAuth.operator === "xai" || xaiDns || xaiAsn;
    return aiAgentResult({
      agentId: "grok",
      agentName: directoryHint?.clientName || "xAI Grok Bot",
      operator: "xAI",
      executionMode: webBotAuth.operator === "xai" ? "RFC 9421 Signed Agent" : grokReferer && !grokUa ? "Silent Cloud VM Browser" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : xaiDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "xai" ? signatureEvidence : [],
        ...grokUa ? [`Grok user-agent: ${ua.slice(0, 120)}`] : [],
        ...grokReferer ? [`Referer / Origin points at grok.com or x.ai`] : [],
        ...xaiAsn ? [`xAI / X Corp ASN ${input.network.asn}`] : [],
        ...xaiDns ? ["FCrDNS matched *.x.ai / *.grok.com"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  const museUa = /\bMuseBot\b|\bMuse\b|Meta-ExternalAgent|Meta-ExternalFetcher|FacebookBot/i.test(ua);
  if (webBotAuth.operator === "meta" || museUa) {
    const metaDnsNames = await confirmedNames();
    const metaDns = hostMatchesSuffix(metaDnsNames, META_VERIFICATION_SUFFIXES);
    const metaAsn = asnIn(input.network.asn, META_ASNS);
    const verified = webBotAuth.operator === "meta" || metaDns || metaAsn;
    return aiAgentResult({
      agentId: "muse",
      agentName: directoryHint?.clientName || "Meta Muse",
      operator: "Meta Platforms",
      executionMode: webBotAuth.operator === "meta" ? "RFC 9421 Signed Agent" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : metaDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "meta" ? signatureEvidence : [],
        ...museUa ? [`Meta / Muse user-agent: ${ua.slice(0, 120)}`] : [],
        ...metaAsn ? [`Meta Platforms ASN ${input.network.asn}`] : [],
        ...metaDns ? ["FCrDNS matched *.facebook.com / *.meta.com"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  if (asnIn(input.network.asn, META_ASNS) && desktopChrome && silentCloudTelemetry) {
    return aiAgentResult({
      agentId: "muse",
      agentName: "Meta Muse (Cloud VM Browser Agent)",
      operator: "Meta Platforms",
      executionMode: "Silent Cloud VM Browser",
      verified: false,
      confidence: "High",
      evidence: [
        `Meta Platforms ASN (${input.network.asn}) hosting a desktop Chrome session`,
        "Virtual machine / cloud browser telemetry (masked WebGL, Linux platform or ephemeral storage)"
      ]
    });
  }
  const perplexityUa = /PerplexityBot|Perplexity-User/i.test(ua);
  if (webBotAuth.operator === "perplexity" || perplexityUa) {
    const perplexityDnsNames = await confirmedNames();
    const perplexityDns = hostMatchesSuffix(
      perplexityDnsNames,
      PERPLEXITY_VERIFICATION_SUFFIXES
    );
    const perplexityAsn = asnIn(input.network.asn, PERPLEXITY_ASNS);
    const verified = webBotAuth.operator === "perplexity" || perplexityDns || perplexityAsn;
    return aiAgentResult({
      agentId: "perplexity",
      agentName: directoryHint?.clientName || "Perplexity AI Agent",
      operator: "Perplexity AI",
      executionMode: webBotAuth.operator === "perplexity" ? "RFC 9421 Signed Agent" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : perplexityDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "perplexity" ? signatureEvidence : [],
        ...perplexityUa ? [`Perplexity user-agent: ${ua.slice(0, 120)}`] : [],
        ...perplexityAsn ? [`Perplexity ASN ${input.network.asn}`] : [],
        ...perplexityDns ? ["FCrDNS matched *.perplexity.ai"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  if (asnIn(input.network.asn, AWS_ASNS) && clientAutomation && (webBotAuth.present || hostMatchesSuffix(await confirmedNames(), PERPLEXITY_VERIFICATION_SUFFIXES))) {
    return aiAgentResult({
      agentId: "perplexity",
      agentName: "Perplexity AI (PerplexityBot / Stealth Agent)",
      operator: "Perplexity AI",
      executionMode: webBotAuth.present ? "RFC 9421 Signed Agent" : "Silent Cloud VM Browser",
      verified: webBotAuth.present,
      confidence: webBotAuth.present ? "Verified" : "Medium",
      evidence: [
        ...signatureEvidence,
        `AWS ASN (${input.network.asn}) hosting a headless Chromium session`,
        "RFC 9421 headers or Perplexity network attribution"
      ]
    });
  }
  const openAiUa = /ChatGPT-User|OAI-SearchBot|GPTBot/i.test(ua);
  if (webBotAuth.operator === "openai" || openAiUa) {
    const openAiDnsNames = await confirmedNames();
    const openAiDns = hostMatchesSuffix(openAiDnsNames, OPENAI_VERIFICATION_SUFFIXES);
    const openAiCidr = matchesAiPrefixTable(input.publicIp, ["chatgpt-user", "gptbot", "searchbot"]);
    const openAiRangesLoaded = (aiBotPrefixTable.get("chatgpt-user")?.length ?? 0) > 0 || (aiBotPrefixTable.get("gptbot")?.length ?? 0) > 0;
    const verified = webBotAuth.operator === "openai" || openAiDns || openAiCidr;
    return aiAgentResult({
      agentId: "openai",
      agentName: directoryHint?.clientName || "OpenAI ChatGPT Agent / Operator",
      operator: "OpenAI",
      executionMode: webBotAuth.operator === "openai" ? "RFC 9421 Signed Agent" : /chatgpt-user/i.test(ua) ? "User-Triggered Fetcher" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : openAiRangesLoaded || openAiDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "openai" ? signatureEvidence : [],
        ...openAiUa ? [`OpenAI user-agent: ${ua.slice(0, 120)}`] : [],
        ...openAiCidr ? ["Source IP matched an official OpenAI JSON prefix list"] : [],
        ...openAiDns ? ["FCrDNS matched *.openai.com / *.chatgpt.com"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  if (asnIn(input.network.asn, AZURE_ASNS) && webBotAuth.present) {
    return aiAgentResult({
      agentId: "openai",
      agentName: "OpenAI ChatGPT Agent / Operator",
      operator: "OpenAI",
      executionMode: "RFC 9421 Signed Agent",
      verified: true,
      confidence: "Verified",
      evidence: [
        ...signatureEvidence,
        `Microsoft Azure ASN (${input.network.asn}) hosting the signed agent`
      ]
    });
  }
  const claudeUa = /Claude-User|Claude-SearchBot|ClaudeBot|anthropic-ai/i.test(ua);
  if (webBotAuth.operator === "anthropic" || claudeUa) {
    const anthropicDnsNames = await confirmedNames();
    const anthropicDns = hostMatchesSuffix(anthropicDnsNames, ANTHROPIC_VERIFICATION_SUFFIXES);
    const verified = webBotAuth.operator === "anthropic" || anthropicDns;
    if (claudeUa && !verified && anthropicDns) {
      return aiAgentResult({
        agentId: "impostor-spoof",
        agentName: "Spoofed Anthropic Claude Agent (Unverified IP)",
        operator: "Unverified Anthropic claim",
        executionMode: "Spoofed Impostor",
        verified: false,
        confidence: "Verified",
        evidence: [
          `Claude user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not on Anthropic infrastructure`
        ]
      });
    }
    return aiAgentResult({
      agentId: "claude",
      agentName: directoryHint?.clientName || "Anthropic Claude (Claude-User / Computer Use)",
      operator: "Anthropic",
      executionMode: webBotAuth.operator === "anthropic" ? "RFC 9421 Signed Agent" : /claude-user/i.test(ua) ? "User-Triggered Fetcher" : "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : anthropicDnsNames.length > 0 ? "High" : "Medium",
      evidence: [
        ...webBotAuth.operator === "anthropic" ? signatureEvidence : [],
        ...claudeUa ? [`Claude user-agent: ${ua.slice(0, 120)}`] : [],
        ...anthropicDns ? ["FCrDNS matched *.anthropic.com / *.claude.ai"] : [],
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from headers"] : [],
        ...directoryEvidence
      ]
    });
  }
  if ((asnIn(input.network.asn, AWS_ASNS) || asnIn(input.network.asn, GCP_ASNS)) && claudeComputerUseViewport && /llvmpipe|mesa|swiftshader|software/i.test(gpuRenderer) && clientAutomation) {
    return aiAgentResult({
      agentId: "claude",
      agentName: "Anthropic Claude (Claude-User / Computer Use)",
      operator: "Anthropic",
      executionMode: "Silent Cloud VM Browser",
      verified: false,
      confidence: "Medium",
      evidence: [
        `Cloud ASN (${input.network.asn}) hosting a Linux X11 / Xvfb framebuffer`,
        `Viewport ${input.client.screenResolution} matches a Claude computer-use desktop`,
        "Software WebGL renderer (llvmpipe / Mesa) with an automated session"
      ]
    });
  }
  const cloudBrowserOperator = webBotAuth.operator === "browserbase" ? { name: "Browserbase Cloud Agent", operator: "Browserbase" } : webBotAuth.operator === "anchorbrowser" ? { name: "Anchor Browser AI Agent", operator: "Anchor Browser" } : null;
  if (webBotAuth.present || cloudBrowserOperator) {
    const handle = webBotAuth.agentHost || webBotAuth.keyId || "unattributed signer";
    return aiAgentResult({
      agentId: "cloud-browser",
      agentName: directoryHint?.clientName || cloudBrowserOperator?.name || "AI Agent \xB7 Cloud Browser (RFC 9421 Signed)",
      operator: cloudBrowserOperator?.operator || "Unattributed Cloud Browser",
      executionMode: "RFC 9421 Signed Agent",
      verified: webBotAuth.present,
      confidence: webBotAuth.present ? "Verified" : "High",
      evidence: [
        ...signatureEvidence,
        ...cloudBrowserOperator ? [`Signature-Agent operator: ${handle}`] : [],
        ...!cloudBrowserOperator ? [`Signed agent handle: ${handle}`] : [],
        ...networkHaystack ? [`Network identity: ${networkHaystack}`] : [],
        ...directoryEvidence
      ]
    });
  }
  const officialBotClaim = /googlebot|googleother|gemini-deep-research|gptbot|chatgpt-user|perplexitybot|perplexity-user|claudebot|claude-user|grokbot|meta-externalagent|muse/i.test(
    ua
  );
  if (officialBotClaim) {
    return aiAgentResult({
      agentId: "impostor-spoof",
      agentName: "Spoofed AI Bot Impostor (Unverified IP)",
      operator: "Unverified AI crawler claim",
      executionMode: "Spoofed Impostor",
      verified: false,
      confidence: "Verified",
      evidence: [
        `Official AI crawler user-agent claim: ${ua.slice(0, 120)}`,
        `Source IP ${input.publicIp} could not be verified via CIDR or FCrDNS`
      ]
    });
  }
  return NO_AI_AGENT;
}
var EMULATOR_GPU_SIGNATURE_PATTERN = /android emulator opengl es translator|goldfish|ranchu|bluestacks|nox|ldplayer|memu|genymotion|virgl|apple software renderer/i;
var NON_ARM_ANDROID_PLATFORM_PATTERN = /linux x86|x86_64|i[3-6]86|win32|win64|macintel/i;
var IOS_DEVICE_UA_PATTERN = /(iphone|ipad|ipod)/i;
var IOS_FOREIGN_PLATFORM_PATTERN = /linux|win32|win64/i;
var IPHONE_OR_IPOD_UA_PATTERN = /(iphone|ipod)/i;
function parseScreenResolutionWidth(resolution) {
  const match = /(\d+)\s*[x×]\s*(\d+)/i.exec(resolution || "");
  if (match) {
    const width = Number.parseInt(match[1], 10);
    return Number.isFinite(width) && width > 0 ? width : 0;
  }
  const single = Number.parseInt(resolution || "", 10);
  return Number.isFinite(single) && single > 0 ? single : 0;
}
function classifyEmulatorFromSignals(input) {
  const ua = typeof input.userAgent === "string" ? input.userAgent : "";
  const claimedOs = typeof input.os === "string" ? input.os : "";
  const platform = (input.platform || "").trim();
  const maxTouchPoints = typeof input.maxTouchPoints === "number" ? Math.max(0, input.maxTouchPoints) : 0;
  const vendor = (input.gpuVendor || "").trim();
  const renderer = (input.gpuRenderer || "").trim();
  const gpuSignature = `${vendor} ${renderer}`;
  const claimsAndroid = /android/i.test(ua) || /android/i.test(claimedOs);
  const claimsIos = IOS_DEVICE_UA_PATTERN.test(ua) || /ipad|ios/i.test(claimedOs);
  if (claimsAndroid && NON_ARM_ANDROID_PLATFORM_PATTERN.test(platform)) {
    return {
      detected: true,
      reason: `Android user-agent on desktop ${platform} (emulator CPU profile)`
    };
  }
  if (claimsAndroid && maxTouchPoints === 0) {
    return {
      detected: true,
      reason: "Android user-agent reporting zero touch points (emulated input layer)"
    };
  }
  if (EMULATOR_GPU_SIGNATURE_PATTERN.test(gpuSignature)) {
    return {
      detected: true,
      reason: `Emulator GPU renderer (${renderer || vendor || "masked renderer"})`
    };
  }
  if (claimsIos) {
    if (IOS_FOREIGN_PLATFORM_PATTERN.test(platform)) {
      return { detected: true, reason: `iOS user-agent on ${platform} platform (simulator host)` };
    }
    if (maxTouchPoints === 0) {
      return {
        detected: true,
        reason: `iOS user-agent on ${platform || "desktop"} with zero touch points (simulator)`
      };
    }
  }
  const screenWidth = parseScreenResolutionWidth(input.screenResolution);
  if (IPHONE_OR_IPOD_UA_PATTERN.test(ua) && screenWidth >= 1e3) {
    return { detected: true, reason: `iPhone user-agent on a ${screenWidth}px desktop-width screen` };
  }
  return { detected: false, reason: "" };
}
var TOR_DNS_TIMEOUT_MS = 600;
var TOR_DOH_TIMEOUT_MS = 1200;
var TOR_DOH_ENDPOINTS = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"];
var TOR_BULK_LIST_URL = "https://check.torproject.org/torbulkexitlist";
var TOR_EXIT_ADDRESSES_URL = "https://check.torproject.org/exit-addresses";
var TOR_ONIONOO_DETAILS_URL = "https://onionoo.torproject.org/details";
var TOR_BULK_LIST_MAX_ENTRIES = 2e4;
var TOR_INTELLIGENCE_SYNC_INTERVAL_MS = 30 * 60 * 1e3;
var TOR_INTELLIGENCE_SYNC_TIMEOUT_MS = 1e4;
var TOR_LIVE_LOOKUP_TIMEOUT_MS = 1800;
var TOR_REVERSE_DNS_TIMEOUT_MS = 1200;
var TOR_VERDICT_CACHE_TTL_MS = 30 * 60 * 1e3;
var TOR_VERDICT_CACHE_MAX_ENTRIES = 5e3;
var TOR_OPERATOR_PREFIX_CACHE_TTL_MS = 6 * 60 * 60 * 1e3;
var torIpv4ExitSet = /* @__PURE__ */ new Set();
var torIpv6ExitSet = /* @__PURE__ */ new Set();
var torIpv6Prefix64Set = /* @__PURE__ */ new Set();
var torIpv6Prefix48Set = /* @__PURE__ */ new Set();
var torRelayMetadataMap = /* @__PURE__ */ new Map();
var torIntelligenceLastSyncMs = 0;
var torIntelligenceSyncInFlight = null;
var torIntelligenceTimer = null;
var torVerdictCache = /* @__PURE__ */ new Map();
var torReverseDnsCache = /* @__PURE__ */ new Map();
function normalizeIpAddress(rawIp) {
  if (typeof rawIp !== "string") return "";
  let value = rawIp.trim();
  if (!value) return "";
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);
  const zoneIndex = value.indexOf("%");
  if (zoneIndex >= 0) value = value.slice(0, zoneIndex);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (mapped) value = mapped[1];
  return value.toLowerCase();
}
function isIpv6Hextet(value) {
  return /^[0-9a-f]{1,4}$/.test(value);
}
function expandIpv6Address(ip) {
  let value = normalizeIpAddress(ip);
  if (!value || !value.includes(":")) return null;
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    if (lastColon < 0) return null;
    const tail2 = value.slice(lastColon + 1);
    if (!isIpv4Literal(tail2)) return null;
    const [a, b, c, d] = tail2.split(".").map((octet) => Number.parseInt(octet, 10));
    value = `${value.slice(0, lastColon + 1)}${(a << 8 | b).toString(16)}:${(c << 8 | d).toString(16)}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (halves.length === 2) {
    if (head.length + tail.length > 7) return null;
    const zeros = new Array(8 - head.length - tail.length).fill("0");
    const hextets = [...head, ...zeros, ...tail];
    if (!hextets.every(isIpv6Hextet)) return null;
    return hextets.map((hextet) => hextet.replace(/^0+(?=.)/, "")).join(":");
  }
  if (head.length !== 8 || !head.every(isIpv6Hextet)) return null;
  return head.map((hextet) => hextet.replace(/^0+(?=.)/, "")).join(":");
}
function ipv4ToInt(ip) {
  if (!isIpv4Literal(ip)) return null;
  const octets = ip.split(".").map((octet) => Number.parseInt(octet, 10));
  return octets[0] * 16777216 + octets[1] * 65536 + octets[2] * 256 + octets[3] >>> 0 >>> 0;
}
function ipv4MatchesCidr(ip, cidr) {
  const slash = cidr.indexOf("/");
  const base = (slash >= 0 ? cidr.slice(0, slash) : cidr).trim();
  const bits = slash >= 0 ? Number.parseInt(cidr.slice(slash + 1), 10) : 32;
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  if (bits === 0) return true;
  const mask = 4294967295 << 32 - bits >>> 0;
  return (ipInt & mask) >>> 0 === (baseInt & mask) >>> 0;
}
function ipv6MatchesCidr(ip, cidr) {
  const slash = cidr.lastIndexOf("/");
  const base = (slash >= 0 ? cidr.slice(0, slash) : cidr).trim();
  const bits = slash >= 0 ? Number.parseInt(cidr.slice(slash + 1), 10) : 128;
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return false;
  const ipExpanded = expandIpv6Address(ip);
  const baseExpanded = expandIpv6Address(base);
  if (!ipExpanded || !baseExpanded) return false;
  const ipHextets = ipExpanded.split(":");
  const baseHextets = baseExpanded.split(":");
  const fullHextets = Math.floor(bits / 16);
  for (let index = 0; index < fullHextets; index += 1) {
    if (ipHextets[index] !== baseHextets[index]) return false;
  }
  const remainingBits = bits % 16;
  if (remainingBits === 0) return true;
  const mask = 65535 << 16 - remainingBits & 65535;
  const ipValue = Number.parseInt(ipHextets[fullHextets], 16);
  const baseValue = Number.parseInt(baseHextets[fullHextets], 16);
  return (ipValue & mask) === (baseValue & mask);
}
function ipMatchesCidrList(ip, cidrList) {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return false;
  const isV4 = isIpv4Literal(normalized);
  for (const cidr of cidrList) {
    if (typeof cidr !== "string") continue;
    const candidate = cidr.trim();
    if (!candidate) continue;
    if (isV4) {
      if (ipv4MatchesCidr(normalized, candidate)) return true;
    } else if (ipv6MatchesCidr(normalized, candidate)) {
      return true;
    }
  }
  return false;
}
function extractEmbeddedIpv4FromIpv6(ip) {
  const expanded = expandIpv6Address(ip);
  if (!expanded) return null;
  const tail = expanded.split(":").slice(4);
  if (tail.length !== 4 || !tail.every((hextet) => /^\d{1,3}$/.test(hextet))) return null;
  const octets = tail.map((hextet) => Number.parseInt(hextet, 10));
  if (octets.some((octet) => octet > 255)) return null;
  return octets.join(".");
}
function isTorOperatorPrefix(ip) {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return false;
  if (isIpv4Literal(normalized)) return ipMatchesCidrList(normalized, TOR_OPERATOR_IPV4_CIDRS);
  return ipMatchesCidrList(normalized, TOR_OPERATOR_IPV6_PREFIXES);
}
function splitTorAddressPort(entry) {
  const trimmed = entry.trim();
  if (!trimmed) return "";
  if (trimmed.startsWith("[")) {
    const close = trimmed.indexOf("]");
    if (close > 0) return trimmed.slice(1, close);
  }
  const firstColon = trimmed.indexOf(":");
  const lastColon = trimmed.lastIndexOf(":");
  if (firstColon > 0 && firstColon === lastColon) return trimmed.slice(0, lastColon);
  return trimmed;
}
async function fetchTextWithTimeout(url, timeoutMs, accept) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { accept }
    });
    if (!response.ok) return null;
    return await response.text();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
function torRelayMetadataFromOnionoo(relay) {
  return {
    nickname: typeof relay.nickname === "string" ? relay.nickname : "",
    fingerprint: typeof relay.fingerprint === "string" ? relay.fingerprint : "",
    as: typeof relay.as === "string" ? relay.as : void 0,
    asName: typeof relay.as_name === "string" ? relay.as_name : void 0,
    country: typeof relay.country === "string" ? relay.country : void 0,
    flags: Array.isArray(relay.flags) ? relay.flags.filter((flag) => typeof flag === "string") : []
  };
}
async function syncTorIntelligence() {
  const nextIpv4 = /* @__PURE__ */ new Set();
  const nextIpv6 = /* @__PURE__ */ new Set();
  const nextPrefix64 = /* @__PURE__ */ new Set();
  const nextPrefix48 = /* @__PURE__ */ new Set();
  const nextMetadata = /* @__PURE__ */ new Map();
  const remember = (key, metadata) => {
    if (!nextMetadata.has(key)) nextMetadata.set(key, metadata);
  };
  const addIpv4 = (rawIp, metadata) => {
    if (typeof rawIp !== "string") return;
    const ip = normalizeIpAddress(rawIp);
    if (!isIpv4Literal(ip)) return;
    nextIpv4.add(ip);
    if (metadata) remember(ip, metadata);
  };
  const addIpv6 = (rawIp, metadata) => {
    if (typeof rawIp !== "string") return;
    const ip = normalizeIpAddress(rawIp);
    const expanded = expandIpv6Address(ip);
    if (!expanded) return;
    nextIpv6.add(ip);
    nextIpv6.add(expanded);
    const hextets = expanded.split(":");
    nextPrefix64.add(hextets.slice(0, 4).join(":"));
    nextPrefix48.add(hextets.slice(0, 3).join(":"));
    if (metadata) {
      remember(ip, metadata);
      remember(expanded, metadata);
    }
  };
  const [bulkList, exitAddresses, onionoo] = await Promise.all([
    fetchTextWithTimeout(TOR_BULK_LIST_URL, TOR_INTELLIGENCE_SYNC_TIMEOUT_MS, "text/plain"),
    fetchTextWithTimeout(TOR_EXIT_ADDRESSES_URL, TOR_INTELLIGENCE_SYNC_TIMEOUT_MS, "text/plain"),
    fetchTextWithTimeout(
      `${TOR_ONIONOO_DETAILS_URL}?search=running:true&fields=nickname,fingerprint,or_addresses,exit_addresses,flags,as,as_name,country`,
      TOR_INTELLIGENCE_SYNC_TIMEOUT_MS,
      "application/json"
    )
  ]);
  if (bulkList) {
    for (const line of bulkList.split(/\r?\n/)) {
      const candidate = line.trim();
      if (!candidate || candidate.startsWith("#")) continue;
      addIpv4(candidate, null);
      if (nextIpv4.size >= TOR_BULK_LIST_MAX_ENTRIES) break;
    }
  }
  if (exitAddresses) {
    let fingerprint = "";
    for (const line of exitAddresses.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith("ExitNode ")) {
        fingerprint = trimmed.slice("ExitNode ".length).trim();
        continue;
      }
      if (!trimmed.startsWith("ExitAddress ")) continue;
      const address = trimmed.split(/\s+/)[1] ?? "";
      addIpv4(address, {
        nickname: fingerprint ? `exit-${fingerprint.slice(0, 8)}` : "",
        fingerprint,
        flags: ["Exit"]
      });
    }
  }
  if (onionoo) {
    try {
      const parsed = JSON.parse(onionoo);
      const relays = Array.isArray(parsed.relays) ? parsed.relays : [];
      for (const relay of relays) {
        const flags = Array.isArray(relay.flags) ? relay.flags.filter((flag) => typeof flag === "string") : [];
        if (!flags.includes("Exit")) continue;
        const metadata = torRelayMetadataFromOnionoo(relay);
        const exitAddressesForRelay = Array.isArray(relay.exit_addresses) ? relay.exit_addresses : [];
        for (const address of exitAddressesForRelay) addIpv4(address, metadata);
        const orAddresses = Array.isArray(relay.or_addresses) ? relay.or_addresses : [];
        for (const entry of orAddresses) {
          if (typeof entry !== "string") continue;
          const host = splitTorAddressPort(entry);
          if (!host) continue;
          if (isIpv4Literal(host)) addIpv4(host, metadata);
          else addIpv6(host, metadata);
        }
      }
    } catch {
    }
  }
  if (nextIpv4.size === 0 && nextIpv6.size === 0) return;
  torIpv4ExitSet = nextIpv4;
  torIpv6ExitSet = nextIpv6;
  torIpv6Prefix64Set = nextPrefix64;
  torIpv6Prefix48Set = nextPrefix48;
  torRelayMetadataMap = nextMetadata;
  torIntelligenceLastSyncMs = Date.now();
}
function runTorIntelligenceSync() {
  if (torIntelligenceSyncInFlight) return torIntelligenceSyncInFlight;
  torIntelligenceSyncInFlight = syncTorIntelligence().catch(() => void 0).finally(() => {
    torIntelligenceSyncInFlight = null;
  });
  return torIntelligenceSyncInFlight;
}
function ensureTorIntelligenceSync() {
  if (torIntelligenceTimer === null) {
    void runTorIntelligenceSync();
    torIntelligenceTimer = setInterval(() => {
      void runTorIntelligenceSync();
    }, TOR_INTELLIGENCE_SYNC_INTERVAL_MS);
    const handle = torIntelligenceTimer;
    if (typeof handle.unref === "function") handle.unref();
    return;
  }
  if (Date.now() - torIntelligenceLastSyncMs >= TOR_INTELLIGENCE_SYNC_INTERVAL_MS) {
    void runTorIntelligenceSync();
  }
}
try {
  ensureTorIntelligenceSync();
} catch {
}
function lookupTorRelayMetadata(ip) {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return null;
  const direct = torRelayMetadataMap.get(normalized);
  if (direct) return direct;
  const expanded = expandIpv6Address(normalized);
  if (!expanded) return null;
  return torRelayMetadataMap.get(expanded) ?? null;
}
function describeTorRelay(ip) {
  const metadata = lookupTorRelayMetadata(ip);
  if (!metadata) return null;
  const organization = metadata.asName || metadata.nickname;
  const asn = metadata.as ? metadata.as.startsWith("AS") ? metadata.as : `AS${metadata.as}` : "";
  if (organization && asn) return `${organization} \xB7 ${asn}`;
  return organization || asn || null;
}
function pruneTorVerdictCache(nowMs) {
  for (const [ip, entry] of torVerdictCache) {
    if (entry.expiresAtMs <= nowMs) torVerdictCache.delete(ip);
  }
  while (torVerdictCache.size >= TOR_VERDICT_CACHE_MAX_ENTRIES) {
    const oldestKey = torVerdictCache.keys().next().value;
    if (typeof oldestKey !== "string") break;
    torVerdictCache.delete(oldestKey);
  }
}
var SUSPICIOUS_IP_TTL_MS = 24 * 60 * 60 * 1e3;
var SUSPICIOUS_IP_MAX_ENTRIES = 1e4;
var SUSPICIOUS_IP_BLOCK_THRESHOLD = 2;
var suspiciousIpLedger = /* @__PURE__ */ new Map();
var suspiciousIpReasons = /* @__PURE__ */ new Map();
var suspiciousIpStrikes = /* @__PURE__ */ new Map();
function isIpv4Literal(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed)) return false;
  return trimmed.split(".").every((octet) => {
    const parsed = Number.parseInt(octet, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 255;
  });
}
async function resolveTorDnsel(ipv4) {
  const queryName = `${ipv4.split(".").reverse().join(".")}.dnsel.torproject.org`;
  let resolved = false;
  let isTorExit = false;
  let timeoutHandle;
  try {
    const lookup = dns.resolve4(queryName).catch((error) => {
      const code = typeof error?.code === "string" ? error.code : "";
      if (code === "ENOTFOUND" || code === "ENODATA" || code === "ENOTIMP") {
        return [];
      }
      return null;
    });
    const timeout = new Promise((resolve) => {
      timeoutHandle = setTimeout(() => resolve(null), TOR_DNS_TIMEOUT_MS);
    });
    const records = await Promise.race([lookup, timeout]);
    if (Array.isArray(records)) {
      resolved = true;
      isTorExit = records.includes("127.0.0.2");
    }
  } catch {
    resolved = false;
  } finally {
    if (timeoutHandle !== void 0) clearTimeout(timeoutHandle);
  }
  if (!resolved) {
    for (const endpoint of TOR_DOH_ENDPOINTS) {
      const answers = await resolveAOverDoh(endpoint, queryName);
      if (answers) {
        resolved = true;
        isTorExit = answers.includes("127.0.0.2");
        break;
      }
    }
  }
  return resolved ? isTorExit : null;
}
async function resolveTorReverseDns(ip) {
  const nowMs = Date.now();
  const cached = torReverseDnsCache.get(ip);
  if (cached && cached.expiresAtMs > nowMs) return cached.names;
  let names = [];
  let timeoutHandle;
  try {
    const lookup = dns.reverse(ip).catch(() => []);
    const timeout = new Promise((resolve) => {
      timeoutHandle = setTimeout(() => resolve([]), TOR_REVERSE_DNS_TIMEOUT_MS);
    });
    const records = await Promise.race([lookup, timeout]);
    if (Array.isArray(records)) {
      names = records.filter((name) => typeof name === "string");
    }
  } catch {
    names = [];
  } finally {
    if (timeoutHandle !== void 0) clearTimeout(timeoutHandle);
  }
  if (torReverseDnsCache.size > TOR_VERDICT_CACHE_MAX_ENTRIES) torReverseDnsCache.clear();
  torReverseDnsCache.set(ip, {
    names,
    expiresAtMs: nowMs + TOR_OPERATOR_PREFIX_CACHE_TTL_MS
  });
  return names;
}
async function lookupOnionooRelay(target) {
  const url = `${TOR_ONIONOO_DETAILS_URL}?search=${encodeURIComponent(
    target
  )}&fields=nickname,fingerprint,or_addresses,exit_addresses,flags,as`;
  const body = await fetchTextWithTimeout(url, TOR_LIVE_LOOKUP_TIMEOUT_MS, "application/json");
  if (!body) return null;
  let relays = [];
  try {
    const parsed = JSON.parse(body);
    relays = Array.isArray(parsed.relays) ? parsed.relays : [];
  } catch {
    return null;
  }
  const targetExpanded = expandIpv6Address(target);
  const targetPrefix64 = targetExpanded ? targetExpanded.split(":").slice(0, 4).join(":") : null;
  let matched = false;
  let isExit = false;
  for (const relay of relays) {
    const addresses = [];
    if (Array.isArray(relay.exit_addresses)) {
      for (const address of relay.exit_addresses) {
        if (typeof address === "string") addresses.push(address);
      }
    }
    if (Array.isArray(relay.or_addresses)) {
      for (const entry of relay.or_addresses) {
        if (typeof entry !== "string") continue;
        const host = splitTorAddressPort(entry);
        if (host) addresses.push(host);
      }
    }
    const hasMatch = addresses.some((address) => {
      const normalized = normalizeIpAddress(address);
      if (!normalized) return false;
      if (normalized === target) return true;
      const expanded = expandIpv6Address(normalized);
      if (!expanded) return false;
      if (targetExpanded && expanded === targetExpanded) return true;
      return targetPrefix64 !== null && expanded.split(":").slice(0, 4).join(":") === targetPrefix64;
    });
    if (!hasMatch) continue;
    matched = true;
    const flags = Array.isArray(relay.flags) ? relay.flags.filter((flag) => typeof flag === "string") : [];
    if (flags.includes("Exit")) {
      isExit = true;
      break;
    }
  }
  return { matched, isExit };
}
async function resolveTorExitVerdict(ip) {
  const cleanIp = normalizeIpAddress(ip);
  if (!cleanIp) return "unknown";
  const isV4 = isIpv4Literal(cleanIp);
  const expanded = isV4 ? null : expandIpv6Address(cleanIp);
  if (!isV4 && expanded === null) return "unknown";
  if (isV4 && torIpv4ExitSet.has(cleanIp)) return "exit";
  if (expanded !== null && (torIpv6ExitSet.has(cleanIp) || torIpv6ExitSet.has(expanded))) {
    return "exit";
  }
  if (!isV4) {
    const embeddedIpv4 = extractEmbeddedIpv4FromIpv6(cleanIp);
    if (embeddedIpv4 !== null) {
      if (torIpv4ExitSet.has(embeddedIpv4)) return "exit";
      if (ipMatchesCidrList(embeddedIpv4, TOR_OPERATOR_IPV4_CIDRS)) return "exit";
    }
  }
  if (isTorOperatorPrefix(cleanIp)) return "relay";
  const reverseNames = await resolveTorReverseDns(cleanIp);
  if (reverseNames.some((name) => TOR_OPERATOR_REVERSE_DNS_PATTERN.test(name))) return "relay";
  const nowMs = Date.now();
  const cached = torVerdictCache.get(cleanIp);
  if (cached && cached.expiresAtMs > nowMs) {
    return cached.verdict === "exit" ? "exit" : cached.verdict === "relay" ? "relay" : "not_exit";
  }
  let liveVerdict = "unknown";
  if (isV4) {
    const [dnsel, onionoo] = await Promise.all([
      resolveTorDnsel(cleanIp),
      lookupOnionooRelay(cleanIp)
    ]);
    if (dnsel === true) {
      liveVerdict = "exit";
    } else if (onionoo && onionoo.matched) {
      liveVerdict = onionoo.isExit ? "exit" : "relay";
    } else if (dnsel === false || onionoo && !onionoo.matched) {
      liveVerdict = "no";
    }
  } else {
    const onionoo = await lookupOnionooRelay(expanded ?? cleanIp);
    if (onionoo && onionoo.matched) liveVerdict = onionoo.isExit ? "exit" : "relay";
    else if (onionoo && !onionoo.matched) liveVerdict = "no";
  }
  if (liveVerdict !== "unknown") {
    pruneTorVerdictCache(nowMs);
    torVerdictCache.set(cleanIp, {
      verdict: liveVerdict,
      expiresAtMs: nowMs + TOR_VERDICT_CACHE_TTL_MS
    });
  }
  return liveVerdict === "exit" ? "exit" : liveVerdict === "relay" ? "relay" : liveVerdict === "no" ? "not_exit" : "unknown";
}
function matchesTorOperatorHint(location) {
  const haystack = [location.isp, location.org, location.asn].filter((part) => typeof part === "string" && part.trim().length > 0).join(" ");
  if (haystack.length > 0 && TOR_OPERATOR_ORG_PATTERN.test(haystack)) return true;
  if (matchesTorOperatorAsn(location.asn || "")) return true;
  const ip = typeof location.publicIp === "string" ? normalizeIpAddress(location.publicIp) : "";
  return ip.length > 0 && isTorOperatorPrefix(ip);
}
function relayOperatorLabel(location) {
  const rawAsn = typeof location.asn === "string" ? location.asn.trim().toUpperCase() : "";
  const asn = rawAsn ? rawAsn.startsWith("AS") ? rawAsn : `AS${rawAsn}` : "";
  const name = [location.isp, location.org].find(
    (value) => typeof value === "string" && value.trim().length > 0 && !/^unknown/i.test(value.trim())
  ) ?? "";
  if (name && asn) return `${name} \xB7 ${asn}`;
  return name || asn || null;
}
async function resolveTorExitStatus(publicIp, location, prefetched, trustedTorNetwork = false) {
  const relay = lookupTorRelayMetadata(publicIp);
  const operator = describeTorRelay(publicIp) ?? relayOperatorLabel(location);
  if (trustedTorNetwork) {
    return {
      isExit: true,
      isRelay: true,
      verdict: "exit",
      viaOperatorHint: false,
      operator,
      relay
    };
  }
  if (isTorBulkListed(publicIp)) {
    return {
      isExit: true,
      isRelay: true,
      verdict: "exit",
      viaOperatorHint: false,
      operator,
      relay
    };
  }
  const verdict = await (prefetched ?? resolveTorExitVerdict(publicIp));
  if (verdict === "exit") {
    return { isExit: true, isRelay: true, verdict, viaOperatorHint: false, operator, relay };
  }
  if (verdict === "relay") {
    return { isExit: false, isRelay: true, verdict, viaOperatorHint: false, operator, relay };
  }
  if (verdict === "unknown" && matchesTorOperatorHint({ ...location, publicIp })) {
    return {
      isExit: false,
      isRelay: true,
      verdict: "relay",
      viaOperatorHint: true,
      operator: operator ?? relayOperatorLabel(location),
      relay
    };
  }
  return { isExit: false, isRelay: false, verdict, viaOperatorHint: false, operator: null, relay: null };
}
async function resolveAOverDoh(endpoint, name) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TOR_DOH_TIMEOUT_MS);
  try {
    const response = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=A`, {
      headers: { accept: "application/dns-json" },
      signal: controller.signal
    });
    if (!response.ok) return null;
    const payload = await response.json();
    if (payload.Status === 3) return [];
    if (payload.Status !== 0) return null;
    const answers = Array.isArray(payload.Answer) ? payload.Answer : [];
    return answers.filter((entry) => entry.type === 1 && typeof entry.data === "string").map((entry) => String(entry.data).trim());
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
function isTorBulkListed(ip) {
  const cleanIp = normalizeIpAddress(ip);
  if (!cleanIp) return false;
  if (isIpv4Literal(cleanIp)) return torIpv4ExitSet.has(cleanIp);
  const expanded = expandIpv6Address(cleanIp);
  if (!expanded) return false;
  return torIpv6ExitSet.has(cleanIp) || torIpv6ExitSet.has(expanded);
}
async function refreshTorBulkList() {
  ensureTorIntelligenceSync();
  if (torIntelligenceSyncInFlight) return;
  if (Date.now() - torIntelligenceLastSyncMs < TOR_INTELLIGENCE_SYNC_INTERVAL_MS) return;
  await runTorIntelligenceSync();
}
function flagSuspiciousIp(ip, reason) {
  const cleanIp = typeof ip === "string" ? ip.trim() : "";
  if (!cleanIp || cleanIp === "Unavailable") return;
  const nowMs = Date.now();
  for (const [knownIp, expiresAtMs] of suspiciousIpLedger) {
    if (expiresAtMs <= nowMs) {
      suspiciousIpLedger.delete(knownIp);
      suspiciousIpReasons.delete(knownIp);
      suspiciousIpStrikes.delete(knownIp);
    }
  }
  while (suspiciousIpLedger.size >= SUSPICIOUS_IP_MAX_ENTRIES) {
    const oldestKey = suspiciousIpLedger.keys().next().value;
    if (typeof oldestKey !== "string") break;
    suspiciousIpLedger.delete(oldestKey);
    suspiciousIpReasons.delete(oldestKey);
    suspiciousIpStrikes.delete(oldestKey);
  }
  const cleanReason = reason.trim().slice(0, 180);
  const existingReasons = suspiciousIpReasons.get(cleanIp) ?? [];
  if (cleanReason && !existingReasons.includes(cleanReason) && existingReasons.length < 5) {
    existingReasons.push(cleanReason);
  }
  suspiciousIpReasons.set(cleanIp, existingReasons);
  const strikes = existingReasons.length;
  suspiciousIpStrikes.set(cleanIp, strikes);
  suspiciousIpLedger.set(cleanIp, nowMs + SUSPICIOUS_IP_TTL_MS);
}
function lookupSuspiciousIp(ip) {
  const cleanIp = typeof ip === "string" ? ip.trim() : "";
  if (!cleanIp) return { blocklisted: false, reasons: [] };
  const expiresAtMs = suspiciousIpLedger.get(cleanIp);
  if (expiresAtMs === void 0) return { blocklisted: false, reasons: [] };
  if (expiresAtMs <= Date.now()) {
    suspiciousIpLedger.delete(cleanIp);
    suspiciousIpReasons.delete(cleanIp);
    suspiciousIpStrikes.delete(cleanIp);
    return { blocklisted: false, reasons: [] };
  }
  const strikes = suspiciousIpStrikes.get(cleanIp) ?? 0;
  if (strikes < SUSPICIOUS_IP_BLOCK_THRESHOLD) {
    return { blocklisted: false, reasons: [] };
  }
  return {
    blocklisted: true,
    reasons: [...suspiciousIpReasons.get(cleanIp) ?? []]
  };
}
var ENVELOPE_FRESHNESS_WINDOW_MS = 3e5;
var NONCE_TTL_MS = 15 * 60 * 1e3;
var NONCE_CACHE_MAX_ENTRIES = 5e3;
var seenEnvelopeNonces = /* @__PURE__ */ new Map();
function sha256HexLower(input) {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex").toLowerCase();
}
function normalizePlatformKey(value) {
  const folded = value.replace(/"/g, "").trim().toLowerCase();
  if (!folded) return "";
  if (/windows|win32|win64|winnt/.test(folded)) return "windows";
  if (/mac|macintosh|macintel/.test(folded)) return "macos";
  if (/android/.test(folded)) return "android";
  if (/ipad/.test(folded)) return "ipados";
  if (/iphone|ios/.test(folded)) return "ios";
  if (/chrome ?os|cros/.test(folded)) return "chromeos";
  if (/linux|x11/.test(folded)) return "linux";
  return "";
}
function rememberEnvelopeNonce(nonce, nowMs) {
  for (const [knownNonce, expiresAtMs] of seenEnvelopeNonces) {
    if (expiresAtMs <= nowMs) seenEnvelopeNonces.delete(knownNonce);
  }
  const seenAtMs = seenEnvelopeNonces.get(nonce);
  if (seenAtMs !== void 0 && seenAtMs > nowMs) return true;
  while (seenEnvelopeNonces.size >= NONCE_CACHE_MAX_ENTRIES) {
    const oldestKey = seenEnvelopeNonces.keys().next().value;
    if (typeof oldestKey !== "string") break;
    seenEnvelopeNonces.delete(oldestKey);
  }
  seenEnvelopeNonces.set(nonce, nowMs + NONCE_TTL_MS);
  return false;
}
function verifySecurityEnvelope(args) {
  const { envelope, headers, hardwareId, nowMs } = args;
  const reasons = [];
  let tamperedRequest = false;
  const headerSignature = readRequestHeader(headers, "x-intel-signature");
  const headerNonce = readRequestHeader(headers, "x-intel-nonce");
  const headerTimestamp = readRequestHeader(headers, "x-intel-timestamp");
  const envNonce = typeof envelope?.nonce === "string" ? envelope.nonce.trim() : "";
  const requestNonce = (envNonce || headerNonce).slice(0, 128);
  const envSignature = typeof envelope?.signature === "string" && envelope.signature.trim() ? envelope.signature.trim() : headerSignature;
  const envTimestamp = typeof envelope?.timestamp === "number" && Number.isFinite(envelope.timestamp) ? envelope.timestamp : Number.parseFloat(headerTimestamp);
  const timestamp = Number.isFinite(envTimestamp) && envTimestamp > 0 ? envTimestamp : 0;
  const envelopeUserAgent = typeof envelope?.userAgent === "string" ? envelope.userAgent.trim() : "";
  const envelopePlatform = typeof envelope?.platform === "string" ? envelope.platform.trim() : "";
  const envelopeScreenResolution = typeof envelope?.screenResolution === "string" ? envelope.screenResolution.trim() : "";
  const envelopeTimezone = typeof envelope?.timezone === "string" ? envelope.timezone.trim() : "";
  if (envelope && envSignature && timestamp > 0 && requestNonce) {
    const canonical = [
      "INTEL_ENVELOPE_V1",
      String(timestamp),
      requestNonce,
      hardwareId,
      envelopeUserAgent,
      envelopePlatform,
      envelopeScreenResolution,
      envelopeTimezone
    ].join("|");
    if (sha256HexLower(canonical) !== envSignature.toLowerCase()) {
      tamperedRequest = true;
      reasons.push("Payload integrity hash mismatch");
    }
  }
  if (timestamp > 0 && Math.abs(nowMs - timestamp) > ENVELOPE_FRESHNESS_WINDOW_MS) {
    tamperedRequest = true;
    reasons.push("Expired or replayed payload timestamp (>5m)");
  }
  let replayDetected = false;
  if (requestNonce) {
    replayDetected = rememberEnvelopeNonce(requestNonce, nowMs);
    if (replayDetected) reasons.push("Duplicate payload nonce (Replay Attack detected)");
  }
  const headerUserAgent = readRequestHeader(headers, "user-agent");
  if (headerUserAgent && envelopeUserAgent && !userAgentsCompatible(headerUserAgent, envelopeUserAgent)) {
    tamperedRequest = true;
    reasons.push("HTTP User-Agent header contradicts JS payload");
  }
  const clientHintPlatform = readRequestHeader(headers, "sec-ch-ua-platform");
  const payloadPlatformKey = normalizePlatformKey(envelopePlatform);
  const clientHintPlatformKey = normalizePlatformKey(clientHintPlatform);
  const androidEquivalent = /android/i.test(headerUserAgent) && (payloadPlatformKey === "linux" && clientHintPlatformKey === "android" || payloadPlatformKey === "android" && clientHintPlatformKey === "linux");
  const chromeOsEquivalent = /cros/i.test(headerUserAgent) && (payloadPlatformKey === "linux" && clientHintPlatformKey === "chromeos" || payloadPlatformKey === "chromeos" && clientHintPlatformKey === "linux");
  const platformPairCompatible = androidEquivalent || chromeOsEquivalent;
  if (payloadPlatformKey && clientHintPlatformKey && payloadPlatformKey !== clientHintPlatformKey && !platformPairCompatible) {
    tamperedRequest = true;
    reasons.push("HTTP User-Agent header contradicts JS payload");
  }
  return {
    tamperedRequest,
    replayDetected,
    requestIntegrityReason: Array.from(new Set(reasons)).join("; "),
    requestNonce
  };
}
function normalizeLegacySuspectScore(rawSuspectScore) {
  if (!Number.isFinite(rawSuspectScore)) return 0;
  if (rawSuspectScore <= 10) return Math.max(0, rawSuspectScore);
  return Math.max(0, Math.min(10, Math.round(rawSuspectScore / 10)));
}
var VELOCITY_WINDOW_MS = {
  "5_minutes": 5 * 60 * 1e3,
  "1_hour": 60 * 60 * 1e3,
  "24_hours": 24 * 60 * 60 * 1e3
};
var EMPTY_WINDOW = { "5_minutes": 0, "1_hour": 0, "24_hours": 0 };
var EMPTY_VELOCITY = {
  distinct_ip: { ...EMPTY_WINDOW },
  distinct_linked_id: { ...EMPTY_WINDOW },
  distinct_country: { ...EMPTY_WINDOW },
  events: { ...EMPTY_WINDOW },
  ip_events: { ...EMPTY_WINDOW },
  distinct_ip_by_linked_id: { ...EMPTY_WINDOW },
  distinct_visitor_id_by_linked_id: { ...EMPTY_WINDOW }
};
function computeVelocitySignals(db2, visitorId, publicIp, sessionId) {
  const now = Date.now();
  const iso = (ms) => new Date(now - ms).toISOString();
  const fiveMinuteCutoff = iso(VELOCITY_WINDOW_MS["5_minutes"]);
  const oneHourCutoff = iso(VELOCITY_WINDOW_MS["1_hour"]);
  const dayCutoff = iso(VELOCITY_WINDOW_MS["24_hours"]);
  try {
    const row = db2.prepare(
      `SELECT
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS ip_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS ip_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS ip_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN session_id END) AS linked_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN session_id END) AS linked_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN session_id END) AS linked_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN country END) AS country_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN country END) AS country_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN country END) AS country_24h,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS events_5m,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS events_1h,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS events_24h
         FROM visits
         WHERE visitor_id = ?`
    ).get(
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      visitorId
    );
    const num = (value) => {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : 0;
    };
    const ipEventsRow = db2.prepare(
      `SELECT
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS ip_events_5m,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS ip_events_1h,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS ip_events_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS ip_visitors_24h
         FROM visits
         WHERE public_ip = ?`
    ).get(fiveMinuteCutoff, oneHourCutoff, dayCutoff, dayCutoff, publicIp);
    const linkedIpRow = db2.prepare(
      `SELECT
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS linked_ips_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS linked_ips_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS linked_ips_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS linked_visitors_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS linked_visitors_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS linked_visitors_24h
         FROM visits
         WHERE session_id = ?`
    ).get(
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      fiveMinuteCutoff,
      oneHourCutoff,
      dayCutoff,
      sessionId
    );
    const velocity = row ? {
      distinct_ip: {
        "5_minutes": num(row.ip_5m),
        "1_hour": num(row.ip_1h),
        "24_hours": num(row.ip_24h)
      },
      distinct_linked_id: {
        "5_minutes": num(row.linked_5m),
        "1_hour": num(row.linked_1h),
        "24_hours": num(row.linked_24h)
      },
      distinct_country: {
        "5_minutes": num(row.country_5m),
        "1_hour": num(row.country_1h),
        "24_hours": num(row.country_24h)
      },
      events: {
        "5_minutes": num(row.events_5m),
        "1_hour": num(row.events_1h),
        "24_hours": num(row.events_24h)
      },
      ip_events: {
        "5_minutes": num(ipEventsRow?.ip_events_5m),
        "1_hour": num(ipEventsRow?.ip_events_1h),
        "24_hours": num(ipEventsRow?.ip_events_24h)
      },
      distinct_ip_by_linked_id: {
        "5_minutes": num(linkedIpRow?.linked_ips_5m),
        "1_hour": num(linkedIpRow?.linked_ips_1h),
        "24_hours": num(linkedIpRow?.linked_ips_24h)
      },
      distinct_visitor_id_by_linked_id: {
        "5_minutes": num(linkedIpRow?.linked_visitors_5m),
        "1_hour": num(linkedIpRow?.linked_visitors_1h),
        "24_hours": num(linkedIpRow?.linked_visitors_24h)
      }
    } : { ...EMPTY_VELOCITY };
    return {
      velocity,
      events24h: velocity.events["24_hours"],
      distinctIps24h: velocity.distinct_ip["24_hours"]
    };
  } catch {
    return { velocity: { ...EMPTY_VELOCITY }, events24h: 0, distinctIps24h: 0 };
  }
}
function computeDeviceRarity(db2, browserDevice) {
  try {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1e3).toISOString();
    const row = db2.prepare(
      `SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN screen_resolution = ? AND browser = ? AND os = ? THEN 1 ELSE 0 END) AS matching
         FROM visits
         WHERE visited_at_utc >= ?`
    ).get(
      browserDevice.screenResolution,
      browserDevice.browser,
      browserDevice.os,
      cutoff
    );
    const total = Number(row?.total) || 0;
    const matching = Number(row?.matching) || 0;
    if (total < 20) {
      return { rareDevice: false, bucket: "<p95", share: 1, sampleSize: total };
    }
    const share = matching / total;
    const bucket = share <= 0.01 ? ">p99" : share <= 0.05 ? "p95-p99" : "<p95";
    return { rareDevice: bucket !== "<p95", bucket, share, sampleSize: total };
  } catch {
    return { rareDevice: false, bucket: "<p95", share: 1, sampleSize: 0 };
  }
}
function computeSuspectScore100(input) {
  let score = 0;
  if (input.bot) score += 45;
  if (input.replayed) score += 35;
  if (input.tampering) score += 25;
  if (input.vpn) score += 10 + (input.vpnMethodCount > 1 ? 4 : 0);
  if (input.blocklisted) score += 12;
  if (input.virtualMachine) score += 12;
  if (input.proxy) score += 10;
  if (input.simulator) score += 10;
  if (input.activeCall) score += 10;
  if (input.privacySettings) score += 8;
  if (input.incognito) score += 6;
  if (input.highActivityDevice) score += 6;
  if (input.developerTools) score += 5;
  if (input.rareDevice) score += 4;
  return Math.max(0, Math.min(100, Math.round(score)));
}
async function lookupVerifiedGeolocation(visitorIp, isPublic, options) {
  const empty = (verified) => ({
    publicIp: verified ? visitorIp : "Unavailable",
    city: "Unavailable",
    region: "Unavailable",
    country: "Unavailable",
    countryCode: "",
    latitude: null,
    longitude: null,
    isp: "Unknown",
    org: "Unknown",
    asn: "Unknown",
    isVpnOrHosting: false,
    isIpVerified: verified,
    isLocationVerified: false
  });
  if (!isPublic || !visitorIp || visitorIp === "Unavailable") {
    return empty(false);
  }
  const edge = options?.edge;
  const edgeHasCoords = edge !== null && edge !== void 0 && edge.latitude !== null && edge.longitude !== null && Boolean(edge.countryCode);
  const edgeHasCity = Boolean(edge?.countryCode && edge.city);
  if (edge && (edgeHasCoords || edgeHasCity)) {
    const net2 = normalizeIspAndOrg(edge.organization, edge.organization, edge.asn, false);
    return {
      publicIp: visitorIp,
      city: edge.city || "Unknown",
      region: edge.region || "Unknown",
      country: edge.country || countryNameFromCode(edge.countryCode),
      countryCode: edge.countryCode,
      latitude: edge.latitude,
      longitude: edge.longitude,
      isp: net2.isp,
      org: net2.org,
      asn: net2.asn || edge.asn || "Unknown",
      timezone: edge.timezone || void 0,
      isVpnOrHosting: false,
      isIpVerified: true,
      isLocationVerified: true,
      locationSource: "edge",
      locationPrecision: edge.city ? "city" : "country",
      isTor: edge.isTorNetwork,
      isTorExit: edge.isTorNetwork
    };
  }
  const nowMs = Date.now();
  let cached;
  try {
    cached = db.prepare(
      "SELECT city, region, country, country_code, latitude, longitude, isp, org, asn, is_vpn_or_hosting, timezone, verified_at_ms FROM verified_geo_cache_v3 WHERE ip_address = ?"
    ).get(visitorIp);
  } catch {
    cached = void 0;
  }
  const cachedHasLocation = Boolean(cached) && (!isMissingGeoValue(cached?.city) || !isMissingGeoValue(cached?.country));
  const cachedHasNetwork = Boolean(cached) && !isMissingGeoValue(cached?.isp) && !/^autonomous system\b/i.test(cached?.isp ?? "") && cached?.isp !== "Standard Network";
  const cachedIsComplete = cachedHasLocation && cachedHasNetwork && typeof cached?.latitude === "number" && typeof cached?.longitude === "number";
  if (cached && nowMs - cached.verified_at_ms < 6 * 3600 * 1e3 && cachedIsComplete) {
    return {
      publicIp: visitorIp,
      city: cached.city,
      region: cached.region,
      country: cached.country,
      countryCode: cached.country_code,
      latitude: cached.latitude,
      longitude: cached.longitude,
      isp: cached.isp,
      org: cached.org,
      asn: cached.asn,
      timezone: cached.timezone || void 0,
      isVpnOrHosting: Boolean(cached.is_vpn_or_hosting),
      isIpVerified: true,
      isLocationVerified: !isMissingGeoValue(cached.city) || !isMissingGeoValue(cached.country),
      locationSource: "provider",
      locationPrecision: !isMissingGeoValue(cached.city) ? "city" : !isMissingGeoValue(cached.region) ? "region" : !isMissingGeoValue(cached.country) ? "country" : "unknown"
    };
  }
  const cleanField = (val) => {
    if (typeof val !== "string") return "Unknown";
    const trimmed = val.trim();
    return trimmed.length > 0 ? trimmed : "Unknown";
  };
  const cleanText = (val) => typeof val === "string" ? val.trim() : "";
  const finiteNumber = (val) => typeof val === "number" && Number.isFinite(val) ? val : null;
  const network = (isp, org, asn, hostile = false) => normalizeIspAndOrg(isp, org, asn, hostile);
  const build = (input) => ({
    publicIp: visitorIp,
    ...input,
    isIpVerified: true,
    isLocationVerified: !isMissingGeoValue(input.city) || !isMissingGeoValue(input.country),
    locationSource: "provider",
    locationPrecision: !isMissingGeoValue(input.city) ? "city" : !isMissingGeoValue(input.region) ? "region" : !isMissingGeoValue(input.country) ? "country" : "unknown"
  });
  const persist = (location) => {
    try {
      db.prepare(
        `INSERT OR REPLACE INTO verified_geo_cache_v3 (
          ip_address, city, region, country, country_code, latitude, longitude, isp, org, asn, is_vpn_or_hosting, timezone, verified_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        visitorIp,
        location.city,
        location.region,
        location.country,
        location.countryCode,
        location.latitude,
        location.longitude,
        location.isp,
        location.org,
        location.asn,
        location.isVpnOrHosting ? 1 : 0,
        location.timezone ?? null,
        nowMs
      );
    } catch {
    }
  };
  const PROVIDER_TIMEOUT_MS = 4e3;
  const probe = async (url, parse) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
    try {
      const resp = await fetch(url, {
        signal: controller.signal,
        headers: { Accept: "application/json", "User-Agent": "IntelSystem/1.0" }
      });
      if (!resp.ok) return null;
      const data = await resp.json();
      const parsed = parse(data);
      return parsed && scoreGeoLocation(parsed) > 0 ? parsed : null;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  };
  const probeIpWho = () => probe(`https://ipwho.is/${encodeURIComponent(visitorIp)}`, (data) => {
    if (data.success === false) return null;
    const providerIp = normalizeIpCandidate(typeof data.ip === "string" ? data.ip : "");
    if (!providerIp || providerIp.toLowerCase() !== visitorIp.toLowerCase()) return null;
    const conn = data.connection || {};
    const sec = data.security || {};
    const net2 = network(conn.isp, conn.org, conn.asn, Boolean(sec.vpn || sec.proxy || sec.tor || sec.hosting));
    const providerTimezone = data.timezone?.id;
    const location = build({
      city: cleanField(data.city),
      region: cleanField(data.region),
      country: cleanField(data.country),
      countryCode: cleanText(data.country_code).toUpperCase(),
      latitude: finiteNumber(data.latitude),
      longitude: finiteNumber(data.longitude),
      isp: net2.isp,
      org: net2.org,
      asn: net2.asn,
      isVpnOrHosting: net2.isVpnOrHosting,
      timezone: cleanText(providerTimezone) || void 0
    });
    return location;
  });
  const probeIpApi = () => probe(`https://ipapi.co/${encodeURIComponent(visitorIp)}/json/`, (data) => {
    if (data.error) return null;
    const providerIp = normalizeIpCandidate(typeof data.ip === "string" ? data.ip : "");
    if (providerIp && providerIp.toLowerCase() !== visitorIp.toLowerCase()) return null;
    const net2 = network(data.org, data.org, data.asn);
    return build({
      city: cleanField(data.city),
      region: cleanField(data.region),
      country: cleanField(data.country_name || data.country),
      countryCode: cleanText(data.country_code).toUpperCase(),
      latitude: finiteNumber(data.latitude),
      longitude: finiteNumber(data.longitude),
      isp: net2.isp,
      org: net2.org,
      asn: net2.asn,
      isVpnOrHosting: net2.isVpnOrHosting,
      timezone: cleanText(data.timezone) || void 0
    });
  });
  const probeFreeIpApi = () => probe(`https://free.freeipapi.com/api/v1/json/${encodeURIComponent(visitorIp)}`, (data) => {
    const providerIp = normalizeIpCandidate(
      typeof data.ipAddress === "string" ? data.ipAddress : typeof data.ip === "string" ? data.ip : ""
    );
    if (!providerIp || providerIp.toLowerCase() !== visitorIp.toLowerCase()) return null;
    const net2 = network(data.asnOrganization, data.asnOrganization, data.asn, Boolean(data.isProxy));
    const timezones = Array.isArray(data.timeZones) ? data.timeZones : [];
    return build({
      city: cleanField(data.cityName),
      region: cleanField(data.regionName),
      country: cleanField(data.countryName),
      countryCode: cleanText(data.countryCode).toUpperCase(),
      latitude: finiteNumber(data.latitude),
      longitude: finiteNumber(data.longitude),
      isp: net2.isp,
      org: net2.org,
      asn: net2.asn,
      isVpnOrHosting: net2.isVpnOrHosting,
      timezone: cleanText(timezones[0]) || void 0
    });
  });
  const probeIpInfo = () => probe(`https://ipinfo.io/${encodeURIComponent(visitorIp)}/json`, (data) => {
    const providerIp = normalizeIpCandidate(typeof data.ip === "string" ? data.ip : "");
    if (providerIp && providerIp.toLowerCase() !== visitorIp.toLowerCase()) return null;
    const countryCodeRaw = cleanText(data.country).toUpperCase();
    const country = countryNameFromCode(countryCodeRaw) || cleanField(data.country);
    const locParts = typeof data.loc === "string" ? data.loc.split(",") : [];
    const latitude = locParts[0] ? Number.parseFloat(locParts[0]) : null;
    const longitude = locParts[1] ? Number.parseFloat(locParts[1]) : null;
    const orgRaw = cleanText(data.org);
    const asnMatch = /^(AS\d+)\s+(.+)$/i.exec(orgRaw);
    const orgName = asnMatch?.[2] || orgRaw;
    const net2 = network(orgName, orgName, asnMatch?.[1] || "");
    return build({
      city: cleanField(data.city),
      region: cleanField(data.region),
      country,
      countryCode: countryCodeRaw,
      latitude: Number.isFinite(latitude) ? latitude : null,
      longitude: Number.isFinite(longitude) ? longitude : null,
      isp: net2.isp,
      org: net2.org,
      asn: net2.asn,
      isVpnOrHosting: net2.isVpnOrHosting,
      timezone: cleanText(data.timezone) || void 0
    });
  });
  const settled = await Promise.allSettled([
    probeIpWho(),
    probeIpApi(),
    probeFreeIpApi(),
    probeIpInfo()
  ]);
  const candidates = settled.filter((entry) => entry.status === "fulfilled").map((entry) => entry.value).filter((entry) => entry !== null).sort((a, b) => scoreGeoLocation(b) - scoreGeoLocation(a));
  const best = candidates[0];
  if (best) {
    if (options?.cacheWrite !== false) persist(best);
    return best;
  }
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
    const resp = await fetch(
      `https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(visitorIp)}`,
      {
        signal: controller.signal,
        headers: { Accept: "application/json", "User-Agent": "IntelSystem/1.0" }
      }
    );
    clearTimeout(timer);
    if (resp.ok) {
      const data = await resp.json();
      const asnNumber = data.data?.asns?.[0]?.asn;
      if (typeof asnNumber === "number" && Number.isFinite(asnNumber)) {
        const asn = `AS${asnNumber}`;
        const org = cloudProviderOrgForAsn(asn) || asn;
        const netDetails = normalizeIspAndOrg(org, org, asn, false);
        const location = build({
          city: "Unavailable",
          region: "Unavailable",
          country: "Unavailable",
          countryCode: "",
          latitude: null,
          longitude: null,
          isp: netDetails.isp,
          org: netDetails.org,
          asn: netDetails.asn,
          isVpnOrHosting: false
        });
        if (options?.cacheWrite !== false) persist(location);
        return location;
      }
    }
  } catch {
  }
  return empty(true);
}
function scoreGeoLocation(location) {
  let score = 0;
  if (!isMissingGeoValue(location.city)) score += 8;
  if (!isMissingGeoValue(location.country)) score += 4;
  if (!isMissingGeoValue(location.isp) && !/^autonomous system\b/i.test(location.isp) && location.isp !== "Standard Network") {
    score += 2;
  }
  if (typeof location.latitude === "number" && typeof location.longitude === "number") {
    score += 1;
  }
  return score;
}
function applyTorRelayFallback(location, visitorIp) {
  const hasCity = !isMissingGeoValue(location.city);
  const hasCountry = !isMissingGeoValue(location.country);
  if (hasCity && hasCountry) return location;
  const relay = lookupTorRelayMetadata(visitorIp);
  if (!relay) return location;
  const countryCode = (relay.country ?? "").trim().toUpperCase();
  const countryName = countryCode ? countryNameFromCode(countryCode) || countryCode : "";
  const relayAsn = normalizeAsnLabel(relay.as) || "";
  const relayIsp = (relay.asName ?? "").trim();
  const existingIspIsReal = !isMissingGeoValue(location.isp) && !/^autonomous system\b/i.test(location.isp) && location.isp !== "Standard Network";
  const isp = existingIspIsReal ? location.isp : relayIsp || relayAsn || location.isp;
  if (!countryName && !relayAsn && !relayIsp) return location;
  return {
    ...location,
    country: hasCountry ? location.country : countryName || location.country,
    countryCode: location.countryCode || countryCode,
    isp,
    org: !isMissingGeoValue(location.org) ? location.org : isp,
    asn: normalizeAsnLabel(location.asn) || relayAsn || location.asn,
    isVpnOrHosting: true,
    isTor: true,
    isLocationVerified: hasCity || Boolean(countryName)
  };
}
async function resolveLocationWithTorFallback(visitorIp, isPublic, options) {
  const location = await lookupVerifiedGeolocation(visitorIp, isPublic, options);
  return applyTorRelayFallback(location, visitorIp);
}
function sanitizeBrowserDevice(input) {
  const safeStr = (val, fallback) => {
    if (typeof val !== "string") return fallback;
    const t = val.trim();
    return t.length > 0 ? t.slice(0, 120) : fallback;
  };
  const validDeviceTypes = ["Desktop", "Mobile", "Tablet", "Unknown"];
  const rawType = input?.deviceType;
  const deviceType = rawType && validDeviceTypes.includes(rawType) ? rawType : "Unknown";
  const incognitoAlias = typeof input?.incognito === "boolean" || typeof input?.isIncognito === "boolean" || typeof input?.privateMode === "boolean" ? Boolean(input?.incognito ?? input?.isIncognito ?? input?.privateMode) : void 0;
  const incognitoMethod = typeof input?.incognitoMethod === "string" && input.incognitoMethod.trim() ? input.incognitoMethod.trim().slice(0, 120) : void 0;
  const idbDurabilityRatio = typeof input?.idbDurabilityRatio === "number" && Number.isFinite(input.idbDurabilityRatio) ? Number(input.idbDurabilityRatio) : void 0;
  const opfsFlushMs = typeof input?.opfsFlushMs === "number" && Number.isFinite(input.opfsFlushMs) ? Number(input.opfsFlushMs) : void 0;
  const deviceKind = input?.deviceKind === "mobile" || input?.deviceKind === "tablet" || input?.deviceKind === "pc" ? input.deviceKind : void 0;
  const genuineMobile = typeof input?.genuineMobile === "boolean" ? input.genuineMobile : void 0;
  const devtoolsDeviceEmulation = typeof input?.devtoolsDeviceEmulation === "boolean" ? input.devtoolsDeviceEmulation : void 0;
  const optStr = (val, max = 96) => {
    if (typeof val !== "string") return void 0;
    const t = val.trim();
    return t ? t.slice(0, max) : void 0;
  };
  const mobileFieldsAllowed = deviceKind === "mobile" && genuineMobile === true;
  return {
    browser: safeStr(input?.browser, "Unknown"),
    os: safeStr(input?.os, "Unknown"),
    deviceType,
    platform: safeStr(input?.platform, "Unavailable"),
    screenResolution: safeStr(input?.screenResolution, "Unavailable"),
    pixelRatio: safeStr(input?.pixelRatio, "Unavailable"),
    language: safeStr(input?.language, "Unavailable"),
    timezone: safeStr(input?.timezone, "Unavailable"),
    deviceKind,
    genuineMobile,
    devtoolsDeviceEmulation,
    reportedModel: optStr(input?.reportedModel),
    phoneBrand: mobileFieldsAllowed ? optStr(input?.phoneBrand) : void 0,
    phoneModel: mobileFieldsAllowed ? optStr(input?.phoneModel) : void 0,
    phoneModelCode: mobileFieldsAllowed ? optStr(input?.phoneModelCode) : void 0,
    phoneDeviceCode: mobileFieldsAllowed ? optStr(input?.phoneDeviceCode) : void 0,
    phoneDisplayLabel: mobileFieldsAllowed ? optStr(input?.phoneDisplayLabel) : void 0,
    incognito: incognitoAlias,
    isIncognito: incognitoAlias,
    privateMode: incognitoAlias,
    incognitoMethod,
    idbDurabilityRatio,
    opfsFlushMs
  };
}
function detectServerRegion(req) {
  const envRegion = process.env.VERCEL_REGION || process.env.CLOUD_RUN_REGION || "";
  const appUrl = process.env.APP_URL || "";
  const vercelIdHeader = req ? String(req.headers["x-vercel-id"] || "") : "";
  const hostHeader = req ? String(req.headers["x-forwarded-host"] || req.headers.host || "") : "";
  const combined = `${envRegion} ${vercelIdHeader} ${appUrl} ${hostHeader}`.toLowerCase();
  const regionNames = {
    "bom1": "bom1 (Mumbai, India)",
    "sin1": "sin1 (Singapore)",
    "hnd1": "hnd1 (Tokyo, Japan)",
    "icn1": "icn1 (Seoul, South Korea)",
    "syd1": "syd1 (Sydney, Australia)",
    "fra1": "fra1 (Frankfurt, Germany)",
    "lhr1": "lhr1 (London, UK)",
    "cdg1": "cdg1 (Paris, France)",
    "iad1": "iad1 (Washington, D.C., USA)",
    "sfo1": "sfo1 (San Francisco, USA)",
    "pdx1": "pdx1 (Portland, USA)",
    "cle1": "cle1 (Cleveland, USA)",
    "gru1": "gru1 (Sao Paulo, Brazil)",
    "asia-southeast1": "asia-southeast1 (Singapore)",
    "asia-south1": "asia-south1 (Mumbai, India)",
    "asia-south2": "asia-south2 (Delhi, India)",
    "asia-east1": "asia-east1 (Taiwan)",
    "asia-northeast1": "asia-northeast1 (Tokyo, Japan)",
    "europe-west1": "europe-west1 (Belgium)",
    "europe-west2": "europe-west2 (London, UK)",
    "us-central1": "us-central1 (Iowa, USA)",
    "us-east1": "us-east1 (South Carolina, USA)",
    "us-west1": "us-west1 (Oregon, USA)"
  };
  for (const [code, label] of Object.entries(regionNames)) {
    if (combined.includes(code)) {
      return { regionCode: code, regionLabel: label };
    }
  }
  return {
    regionCode: "global-edge",
    regionLabel: "Global Edge Network"
  };
}
var app = express();
app.set("trust proxy", true);
app.use(cookieParser());
app.use(clientHintsMiddleware);
app.use((_req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "compute-pressure=*, ch-ua-model=(self), ch-ua-platform-version=(self), ch-ua-arch=(self), ch-ua-form-factors=(self)"
  );
  next();
});
var handleNetworkHeadPing = (_req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Timing-Allow-Origin", "*");
  res.status(200).end();
};
var handleNetworkPing = (_req, res) => {
  const serverTimestamp = Date.now();
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Timing-Allow-Origin", "*");
  res.status(200).json({ ok: true, serverTimestamp, serverTimestampMs: serverTimestamp });
};
app.head("/api/network/ping", handleNetworkHeadPing);
app.get("/api/network/ping", handleNetworkPing);
app.get("/api/intel/geolocation", async (req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  try {
    const { ip: visitorIp, isPublic } = extractVisitorIp(req);
    const edgeGeo = extractEdgeGeo(req);
    let location = mergeLocationWithEdge(
      await resolveLocationWithTorFallback(visitorIp, isPublic, { cacheWrite: false, edge: edgeGeo }),
      edgeGeo
    );
    const edgeAsnNumber = Number.parseInt(edgeGeo.asn.replace(/^AS/i, ""), 10);
    const enrichedNetwork = await enrichNetwork(visitorIp, {
      asn: Number.isInteger(edgeAsnNumber) && edgeAsnNumber > 0 ? edgeAsnNumber : void 0,
      country: edgeGeo.countryCode || void 0
    });
    const placeholderIspBefore = isMissingGeoValue(location.isp) || /^autonomous system\b/i.test(location.isp) || location.isp === "Standard Network";
    const placeholderOrgBefore = isMissingGeoValue(location.org) || location.org === "Standard Network";
    if (enrichedNetwork.source !== "none") {
      location = {
        ...location,
        asn: normalizeAsnLabel(location.asn) || normalizeAsnLabel(enrichedNetwork.asn) || location.asn,
        isp: placeholderIspBefore && enrichedNetwork.asn_name ? enrichedNetwork.asn_name : location.isp,
        org: placeholderOrgBefore && enrichedNetwork.asn_name ? enrichedNetwork.asn_name : location.org,
        isVpnOrHosting: location.isVpnOrHosting || enrichedNetwork.datacenter_result
      };
    }
    const knownAsnLabel = normalizeAsnLabel(location.asn) || normalizeAsnLabel(edgeGeo.asn) || "";
    const stillPlaceholder = isMissingGeoValue(location.isp) || /^autonomous system\b/i.test(location.isp) || location.isp === "Standard Network";
    if (knownAsnLabel && stillPlaceholder) {
      const byAsn = await resolveAsnOrganization(knownAsnLabel);
      location = {
        ...location,
        asn: knownAsnLabel,
        isp: byAsn.asn_name || knownAsnLabel,
        org: isMissingGeoValue(location.org) || location.org === "Standard Network" ? byAsn.asn_name || knownAsnLabel : location.org,
        isVpnOrHosting: location.isVpnOrHosting || byAsn.datacenter_result
      };
    }
    const hasLocation = !isMissingGeoValue(location.city) || !isMissingGeoValue(location.country);
    const hasNetwork = !isMissingGeoValue(location.isp) && !/^autonomous system\b/i.test(location.isp) && location.isp !== "Standard Network";
    const resolved = location.isIpVerified && hasLocation && hasNetwork;
    const hasCountry = Boolean(location.countryCode) || !isMissingGeoValue(location.country);
    res.json({
      location: {
        ...location,
        isTor: Boolean(location.isTor) || edgeGeo.isTorNetwork,
        isTorExit: Boolean(location.isTorExit) || edgeGeo.isTorNetwork,
        locationSource: location.locationSource ?? (edgeGeo.countryCode ? "edge" : "provider"),
        locationPrecision: !isMissingGeoValue(location.city) ? "city" : !isMissingGeoValue(location.region) ? "region" : hasCountry ? "country" : "unknown",
        isLocationVerified: hasCountry
      },
      resolved,
      checkedAt: (/* @__PURE__ */ new Date()).toISOString()
    });
  } catch {
    res.status(500).json({ error: "Geolocation lookup failed." });
  }
});
app.use(express.json({ limit: "512kb" }));
app.get("/api/health", async (req, res) => {
  let visitorsCount = null;
  let visitsCount = null;
  try {
    visitorsCount = db.prepare("SELECT COUNT(*) AS count FROM visitors").get().count;
    visitsCount = db.prepare("SELECT COUNT(*) AS count FROM visits").get().count;
  } catch {
  }
  const { regionCode, regionLabel } = detectServerRegion(req);
  const torCheckIp = typeof req.query.torCheck === "string" ? normalizeIpCandidate(req.query.torCheck) : null;
  if (torCheckIp && (isIpv4Literal(torCheckIp) || expandIpv6Address(torCheckIp) !== null)) {
    const startedAtMs = Date.now();
    ensureTorIntelligenceSync();
    const verdict = await resolveTorExitVerdict(torCheckIp);
    const relay = lookupTorRelayMetadata(torCheckIp);
    res.json({
      status: "ok",
      visitorsCount,
      visitsCount,
      regionCode,
      regionLabel,
      torCheck: {
        ip: torCheckIp,
        exitNode: verdict === "exit",
        verdict,
        bulkListed: isTorBulkListed(torCheckIp),
        operatorPrefix: isTorOperatorPrefix(torCheckIp),
        embeddedIpv4: extractEmbeddedIpv4FromIpv6(torCheckIp),
        operator: describeTorRelay(torCheckIp),
        relayOperatorAsn: relay?.as ?? null,
        relayOperatorName: relay?.asName ?? null,
        consensusIpv4Exits: torIpv4ExitSet.size,
        consensusIpv6Exits: torIpv6ExitSet.size,
        consensusSyncedAtMs: torIntelligenceLastSyncMs || null,
        latencyMs: Date.now() - startedAtMs
      }
    });
    return;
  }
  res.json({ status: "ok", visitorsCount, visitsCount, regionCode, regionLabel });
});
function extractEdgeGeo(req) {
  return readEdgeGeoHeaders(req.headers);
}
var SERVER_TIMEZONE_ALIAS_MAP = {
  "asia/calcutta": "asia/kolkata",
  "asia/katmandu": "asia/kathmandu",
  "asia/rangoon": "asia/yangon",
  "asia/saigon": "asia/ho_chi_minh",
  "europe/kiev": "europe/kyiv",
  "us/eastern": "america/new_york",
  "us/central": "america/chicago",
  "us/mountain": "america/denver",
  "us/pacific": "america/los_angeles",
  "etc/utc": "utc",
  "etc/gmt": "utc"
};
var TIMEZONE_ALIAS_MAP = {
  "Asia/Calcutta": "Asia/Kolkata",
  "Asia/Katmandu": "Asia/Kathmandu",
  "Asia/Saigon": "Asia/Ho_Chi_Minh",
  "Asia/Rangoon": "Asia/Yangon",
  "Europe/Kiev": "Europe/Kyiv",
  "Europe/Uzhgorod": "Europe/Kyiv",
  "Europe/Zaporozhye": "Europe/Kyiv",
  "US/Eastern": "America/New_York",
  "US/Central": "America/Chicago",
  "US/Mountain": "America/Denver",
  "US/Pacific": "America/Los_Angeles"
};
function normalizeTimezone(tz) {
  if (!tz || typeof tz !== "string") return "";
  const trimmed = tz.trim();
  if (!trimmed) return "";
  return TIMEZONE_ALIAS_MAP[trimmed] || trimmed;
}
function normalizeServerTimezoneId(tz) {
  if (!tz || typeof tz !== "string") return "";
  const canonical = normalizeTimezone(tz).toLowerCase();
  if (!canonical || canonical === "unknown" || canonical === "unavailable") return "";
  return SERVER_TIMEZONE_ALIAS_MAP[canonical] || canonical;
}
function sanitizeHardwareSignals(raw, browserDevice) {
  const safeStr = (val, fallback, maxLen = 140) => typeof val === "string" && val.trim().length > 0 ? val.trim().slice(0, maxLen) : fallback;
  const rawHwId = safeStr(raw?.hardwareId, "", 40);
  const validHwId = /^hwid_[0-9a-f]{16,32}$/i.test(rawHwId) ? rawHwId.toLowerCase() : "hwid_" + crypto.createHash("sha256").update(
    `${browserDevice.os}|${browserDevice.screenResolution}|${browserDevice.pixelRatio}|${safeStr(raw?.gpuRenderer, "gpu")}|${safeStr(raw?.canvasHash, "canvas")}`
  ).digest("hex").slice(0, 20);
  const cpuCores = typeof raw?.cpuCores === "number" && Number.isFinite(raw.cpuCores) && raw.cpuCores > 0 ? Math.min(256, Math.round(raw.cpuCores)) : null;
  const deviceMemoryGb = typeof raw?.deviceMemoryGb === "number" && Number.isFinite(raw.deviceMemoryGb) && raw.deviceMemoryGb > 0 ? Number(raw.deviceMemoryGb) : null;
  const maxTouchPoints = typeof raw?.maxTouchPoints === "number" && Number.isFinite(raw.maxTouchPoints) && raw.maxTouchPoints >= 0 ? Math.min(64, Math.round(raw.maxTouchPoints)) : 0;
  const colorDepth = typeof raw?.colorDepth === "number" && Number.isFinite(raw.colorDepth) && raw.colorDepth > 0 ? Math.min(64, Math.round(raw.colorDepth)) : 24;
  const maxTextureSize = typeof raw?.maxTextureSize === "number" && Number.isFinite(raw.maxTextureSize) && raw.maxTextureSize >= 0 ? Math.round(raw.maxTextureSize) : 0;
  return {
    hardwareId: validHwId,
    gpuVendor: safeStr(raw?.gpuVendor, "Standard WebGL Vendor", 120),
    gpuRenderer: safeStr(raw?.gpuRenderer, "Standard Hardware Renderer", 160),
    maxTextureSize,
    canvasHash: safeStr(raw?.canvasHash, "unavailable", 40),
    audioHash: safeStr(raw?.audioHash, "unavailable", 40),
    cpuCores,
    deviceMemoryGb,
    colorDepth,
    maxTouchPoints,
    hdrSupported: Boolean(raw?.hdrSupported),
    colorGamut: raw?.colorGamut === "Rec2020" || raw?.colorGamut === "P3" || raw?.colorGamut === "sRGB" ? raw.colorGamut : "sRGB",
    architecture: safeStr(raw?.architecture, browserDevice.os, 80)
  };
}
function sanitizeAndReinforceSecuritySignals(raw, browserDevice, hardwareSignals, location, ipTimezoneHint, recognitionSource, baseClassification, velocity, incognitoContext = {}, requestContext = {}) {
  const safeStrArray = (arr) => Array.isArray(arr) ? arr.filter((item) => typeof item === "string" && item.trim().length > 0).map((s) => s.trim().slice(0, 180)).slice(0, 10) : [];
  const webdriver = Boolean(raw?.webdriver);
  const cdpDetected = Boolean(raw?.cdpDetected);
  const isHeadless = Boolean(raw?.isHeadless);
  const botReason = typeof raw?.botReason === "string" && raw.botReason.trim() ? raw.botReason.trim().slice(0, 200) : "";
  const botSignals = safeStrArray(raw?.botSignals);
  const clientAutomationDetected = Boolean(raw?.isBot || webdriver || cdpDetected);
  const botClassification = requestContext.botClassification ?? classifyBotTraffic(
    requestContext.headers,
    { org: location.org, isp: location.isp, asn: location.asn },
    {
      isBot: clientAutomationDetected,
      isHeadless,
      webdriver,
      cdpDetected,
      botSignals,
      cdpRuntimeLeak: Boolean(raw?.cdpRuntimeLeak),
      stealthPluginDetected: Boolean(raw?.stealthPluginDetected)
    }
  );
  const botSubtype = botClassification.subtype;
  const spoofedCrawler = botClassification.subtype === "bad_bot" && botClassification.label === "Spoofed Crawler";
  const isBot = botSubtype === "bad_bot" || botSubtype === "ai_agent";
  const browserTimezone = typeof raw?.browserTimezone === "string" && raw.browserTimezone.trim() ? raw.browserTimezone.trim().slice(0, 80) : browserDevice.timezone || "UTC";
  const ipTimezone = ipTimezoneHint || (typeof raw?.ipTimezone === "string" && raw.ipTimezone.trim() && raw.ipTimezone !== "Unavailable" ? raw.ipTimezone.trim().slice(0, 80) : "Unavailable");
  const normBrowserTz = normalizeServerTimezoneId(browserTimezone);
  const normIpTz = normalizeServerTimezoneId(ipTimezone);
  const serverTzMismatch = Boolean(normBrowserTz && normIpTz && normBrowserTz !== normIpTz);
  const timezoneMismatch = Boolean(raw?.timezoneMismatch) || serverTzMismatch;
  const isGpuMaskedOrUnavailable = !hardwareSignals.gpuVendor || hardwareSignals.gpuVendor === "Unavailable" || /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuVendor) || !hardwareSignals.gpuRenderer || hardwareSignals.gpuRenderer === "Unavailable" || /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuRenderer);
  const clientTorBrowser = Boolean(requestContext.clientTorBrowser ?? raw?.isTorBrowserClient);
  const classification = applyNetworkOverrides(baseClassification, {
    torExit: Boolean(requestContext.torExitNode || requestContext.torRelay),
    torOperatorHint: Boolean(requestContext.torOperatorHint),
    isTorBrowserClient: clientTorBrowser,
    aiAgentDetected: Boolean(requestContext.aiAgent?.detected),
    datacenterVm: Boolean(raw?.isVirtualMachine) && (baseClassification.isDatacenterOrHosting || isGpuMaskedOrUnavailable),
    vpnSuspected: Boolean(raw?.vpnSuspected) || timezoneMismatch
  });
  const isCloudOrDatacenterNetwork = classification.isDatacenterOrHosting || Boolean(location.isVpnOrHosting);
  const datacenterAsn = classification.isConsumerBroadband ? false : isCloudOrDatacenterNetwork;
  const vpnReasons = safeStrArray(raw?.vpnReasons);
  if (timezoneMismatch && !vpnReasons.some((r) => r.toLowerCase().includes("timezone"))) {
    vpnReasons.push(
      `Browser timezone (${browserTimezone}) differs from IP geolocation timezone (${ipTimezone})`
    );
  }
  if (datacenterAsn && !vpnReasons.some((r) => r.toLowerCase().includes("datacenter") || r.toLowerCase().includes("asn"))) {
    vpnReasons.push(
      `Network ASN / ISP (${location.isp}${location.asn !== "Unknown" ? ` \u2022 ${location.asn}` : ""}) matches cloud/hosting or VPN infrastructure`
    );
  }
  if (datacenterAsn && isGpuMaskedOrUnavailable && !vpnReasons.some((r) => /Cloud \/ Masked GPU/i.test(r))) {
    vpnReasons.push("Cloud / Masked GPU environment");
  }
  const torExitNode = Boolean(requestContext.torExitNode);
  const torOperatorHint = Boolean(requestContext.torOperatorHint);
  const clientTzCanonical = normalizeTimezone(browserTimezone);
  const ipTzCanonical = normalizeTimezone(ipTimezone === "Unavailable" ? "" : ipTimezone);
  const hasTzMismatch = Boolean(
    clientTzCanonical && ipTzCanonical && clientTzCanonical.toLowerCase() !== ipTzCanonical.toLowerCase()
  );
  const networkHaystackForVpn = `${location.isp} ${location.org}`;
  const commercialVpnProvider = !classification.isConsumerBroadband && VPN_PROXY_PATTERN.test(networkHaystackForVpn) && !/\bcloud\b|\bhosting\b|\bdatacenter\b|\bdata center\b/i.test(networkHaystackForVpn);
  const vpnMethods = {
    timezone_mismatch: hasTzMismatch,
    public_vpn: commercialVpnProvider,
    auxiliary_mobile: false,
    os_mismatch: Boolean(raw?.isOsTampered),
    relay: Boolean(torExitNode),
    ml_prediction: Boolean(raw?.vpnSuspected) && !commercialVpnProvider && !hasTzMismatch
  };
  const vpnSuspected = Object.values(vpnMethods).some(Boolean) || datacenterAsn && botSubtype !== "good_bot";
  const tamperDetected = Boolean(raw?.tamperDetected || requestContext.tamperedRequest);
  const tamperReasons = safeStrArray(raw?.tamperReasons);
  if (requestContext.tamperedRequest && requestContext.requestIntegrityReason && !tamperReasons.includes(requestContext.requestIntegrityReason)) {
    tamperReasons.unshift(requestContext.requestIntegrityReason);
    tamperReasons.splice(10);
  }
  const incognitoLikely = Boolean(raw?.incognitoLikely);
  const storageQuotaMb = typeof raw?.storageQuotaMb === "number" && Number.isFinite(raw.storageQuotaMb) && raw.storageQuotaMb > 0 ? Math.round(raw.storageQuotaMb) : null;
  const webrtcCandidateIp = typeof raw?.webrtcCandidateIp === "string" && raw.webrtcCandidateIp.trim() ? raw.webrtcCandidateIp.trim().slice(0, 64) : null;
  const webrtcDetail = typeof raw?.webrtcDetail === "string" && raw.webrtcDetail.trim() ? raw.webrtcDetail.trim().slice(0, 200) : "";
  const privacyProtected = Boolean(raw?.privacyProtected);
  const privacyDetail = typeof raw?.privacyDetail === "string" && raw.privacyDetail.trim() ? raw.privacyDetail.trim().slice(0, 200) : "";
  const canvasFarblingDetected = Boolean(raw?.canvasFarblingDetected);
  const isVirtualMachine = Boolean(raw?.isVirtualMachine);
  const isOsTampered = Boolean(raw?.isOsTampered);
  const vmReason = typeof raw?.vmReason === "string" && raw.vmReason.trim() ? raw.vmReason.trim().slice(0, 200) : "";
  const incognitoMethod = typeof raw?.incognitoMethod === "string" && raw.incognitoMethod.trim() ? raw.incognitoMethod.trim().slice(0, 120) : "";
  const headroomGiB = typeof raw?.headroomGiB === "number" && Number.isFinite(raw.headroomGiB) ? Number(raw.headroomGiB) : null;
  const idbDurabilityRatio = typeof raw?.idbDurabilityRatio === "number" && Number.isFinite(raw.idbDurabilityRatio) ? Number(raw.idbDurabilityRatio) : null;
  const opfsFlushMs = typeof raw?.opfsFlushMs === "number" && Number.isFinite(raw.opfsFlushMs) ? Number(raw.opfsFlushMs) : null;
  const cloudOrMaskedGpu = Boolean(
    raw?.cloudOrMaskedGpu
  );
  const serverEmulator = classifyEmulatorFromSignals({
    userAgent: requestContext.requestUserAgent || readRequestHeader(requestContext.headers, "user-agent") || "",
    os: browserDevice.os,
    platform: browserDevice.platform,
    maxTouchPoints: hardwareSignals.maxTouchPoints,
    gpuVendor: hardwareSignals.gpuVendor,
    gpuRenderer: hardwareSignals.gpuRenderer,
    screenResolution: browserDevice.screenResolution
  });
  const clientEmulatorReported = Boolean(raw?.emulatorDetected);
  const emulatorDetected = clientEmulatorReported || serverEmulator.detected;
  const clientEmulatorReason = typeof raw?.emulatorReason === "string" && raw.emulatorReason.trim() ? raw.emulatorReason.trim().slice(0, 200) : "";
  const emulatorReason = emulatorDetected ? serverEmulator.detected ? serverEmulator.reason : clientEmulatorReason : "";
  const tamperedRequest = Boolean(requestContext.tamperedRequest);
  const replayDetected = Boolean(requestContext.replayDetected);
  const requestIntegrityReason = typeof requestContext.requestIntegrityReason === "string" ? requestContext.requestIntegrityReason.trim().slice(0, 240) : "";
  const requestNonce = typeof requestContext.requestNonce === "string" ? requestContext.requestNonce.slice(0, 128) : "";
  const ipBlocklisted = Boolean(requestContext.ipBlocklisted);
  const ipBlocklistReasons = Array.isArray(requestContext.ipBlocklistReasons) ? requestContext.ipBlocklistReasons.filter((reason) => typeof reason === "string" && reason.trim().length > 0).map((reason) => reason.trim().slice(0, 180)).slice(0, 5) : [];
  let persistenceMode = "First-Party Cookie";
  if (recognitionSource === "Hardware Fingerprint (Cookie-less / Incognito)") {
    persistenceMode = "Hardware ID Recovered";
  } else if (incognitoLikely) {
    persistenceMode = "Private / Restricted Storage";
  }
  const incognitoOrCleared = Boolean(raw?.incognitoOrCleared) || recognitionSource === "Hardware Fingerprint (Cookie-less / Incognito)" || persistenceMode === "Hardware ID Recovered";
  const clientReportedIncognito = Boolean(incognitoContext.clientReportedIncognito) || incognitoLikely;
  const isIncognito = clientReportedIncognito;
  const tierFor = (score) => score >= 7 ? "High" : score >= 3 ? "Medium" : "Low";
  const levelFor = (score) => score >= 7 ? "high" : score >= 3 ? "medium" : "low";
  const incognitoScore = isIncognito ? 4 : 0;
  const incognitoSignal = {
    id: "incognito",
    title: "Incognito / Private Browsing",
    status: isIncognito ? "Incognito / Private Mode" : "Standard Window",
    scoreOutOf10: incognitoScore,
    riskLabel: `${tierFor(incognitoScore)} Risk \u2022 ${incognitoScore}/10`,
    level: levelFor(incognitoScore),
    // The physical proof must match the verdict: a private tile always quotes the client's
    // own storage-commit probe method, a normal tile quotes the verified disk-backed path.
    detail: isIncognito ? `Ephemeral RAM storage detected (${incognitoMethod || "In-memory LevelDB / 10 GiB decoy quota"})` : `Persistent disk-backed storage verified (${incognitoMethod || "Standard profile"})`
  };
  const aiAgent = requestContext.aiAgent ?? null;
  const spoofedImpostor = aiAgent?.agentId === "impostor-spoof" || botSubtype === "bad_bot" && spoofedCrawler;
  const botScore = spoofedImpostor ? 10 : botSubtype === "bad_bot" ? 9 : botSubtype === "ai_agent" ? 8 : botSubtype === "good_bot" ? 2 : 0;
  const botStatus = spoofedImpostor ? "Spoofed AI Impostor" : botSubtype === "bad_bot" ? "Bot / Automated" : aiAgent?.detected && aiAgent.agentName ? aiAgent.agentName : botSubtype === "ai_agent" ? "AI Agent \xB7 Cloud Browser" : botSubtype === "good_bot" ? "Good Bot \xB7 Search Crawler" : "Verified Human";
  const aiAgentDetail = aiAgent?.detected && aiAgent.agentName ? `${aiAgent.agentName} \u2014 ${aiAgent.operator}${aiAgent.executionMode ? ` \xB7 ${aiAgent.executionMode}` : ""} \xB7 ${aiAgent.confidence}${aiAgent.verified ? " (verified)" : ""}: ${aiAgent.evidence[0] || "agent identity attributed from request headers"}` : "";
  const botDetail = botSubtype === "human" && !aiAgent?.detected ? "Verified human interactive session" : aiAgentDetail ? aiAgentDetail : botSubtype === "ai_agent" ? `${botClassification.provider} ${botClassification.label} \u2014 ${botClassification.reasons[0] || KNOWN_AI_CRAWLER_REASON}` : botSubtype === "good_bot" ? `${botClassification.provider} ${botClassification.label} verified against its official network \u2014 ${botClassification.reasons[1] || "ASN / organisation match"}` : botReason || botClassification.reasons[0] || (spoofedCrawler ? "Crawler user-agent claimed from a network that does not belong to the operator" : "WebDriver / CDP automation runtime detected");
  const botSignal = {
    id: "bot",
    title: "Bot & Automation Detection",
    status: botStatus,
    scoreOutOf10: botScore,
    riskLabel: `${tierFor(botScore)} Risk \u2022 ${botScore}/10`,
    level: levelFor(botScore),
    detail: botDetail
  };
  const isDatacenterAsn = datacenterAsn;
  const verifiedCrawlerNetwork = botSubtype === "good_bot" && isDatacenterAsn;
  const ispBrand = classification.brandName || location.isp || "Standard Network";
  const asnSuffix = location.asn !== "Unknown" ? ` \u2022 ${location.asn}` : "";
  const asnLabel = location.asn && location.asn !== "Unknown" ? /^AS/i.test(location.asn) ? location.asn.toUpperCase() : `AS${location.asn}` : "AS unknown";
  const asnOrOrg = `${asnLabel} \xB7 ${location.org !== "Unknown" ? location.org : ispBrand}`;
  const torBrowserClient = clientTorBrowser;
  const torRelayNetwork = requestContext.torVerdict === "relay" || requestContext.torRelay === true;
  const torAnonymity = torExitNode || torBrowserClient;
  const torOperatorLabel = requestContext.torOperator ?? describeTorRelay(location.publicIp) ?? null;
  const vpnScore = torAnonymity ? torExitNode && torBrowserClient ? 10 : 9 : ipBlocklisted ? 9 : verifiedCrawlerNetwork ? 2 : torRelayNetwork ? 6 : aiAgent?.detected ? 8 : isDatacenterAsn && hasTzMismatch ? 8 : isDatacenterAsn ? 6 : hasTzMismatch ? 5 : 0;
  const vpnStatus = torAnonymity ? torExitNode && torBrowserClient ? "Tor Exit Node & Tor Browser" : torExitNode ? "Tor Exit Node" : "Tor Browser (Onion Routing / RFP)" : ipBlocklisted ? "Blocklisted IP" : verifiedCrawlerNetwork ? "Verified Crawler Network" : torRelayNetwork ? "Tor Relay (Non-Exit)" : aiAgent?.detected ? "AI Agent Cloud Network" : isDatacenterAsn ? "VPN / Datacenter Proxy" : hasTzMismatch ? "VPN / Timezone Relay" : "Standard ISP";
  const vpnDetail = torAnonymity ? `${torExitNode ? "Confirmed active Tor exit relay" : "Tor Browser fingerprint (Gecko RFP + letterboxing)"} (${location.publicIp} \xB7 ${torOperatorLabel || asnOrOrg})${torOperatorHint ? " \u2014 DNSEL unreachable, operator attribution used" : ""}${torExitNode && torBrowserClient ? " \xB7 server exit IP and client RFP both matched (10/10)" : ""}` : ipBlocklisted ? "IP flagged on abuse / tamper blocklist" : verifiedCrawlerNetwork ? `${botClassification.provider} crawler operating from its own ${ispBrand}${asnSuffix} \u2014 crawler infrastructure, not a consumer proxy` : torRelayNetwork ? `Tor relay network (${torOperatorLabel || asnOrOrg}) \u2014 part of the Tor network but not an exit egress` : aiAgent?.detected ? `${aiAgent.agentName} (${aiAgent.operator}) \u2014 ${aiAgent.executionMode || "AI agent"} traffic from ${ispBrand}${asnSuffix}` : isDatacenterAsn && hasTzMismatch ? `Datacenter ASN (${ispBrand}${asnSuffix}) combined with a browser/IP timezone mismatch (${clientTzCanonical} vs ${ipTzCanonical})` : isDatacenterAsn ? `Datacenter / hosting ASN detected on ${ispBrand}${asnSuffix}` : hasTzMismatch ? `Browser timezone (${browserTimezone}) differs from IP geolocation timezone (${ipTimezone})` : `${ispBrand} \u2022 ${classification.networkType} (${asnLabel}) verified against browser timezone ${browserTimezone}`;
  const vpnSignal = {
    id: "vpn",
    title: "VPN / Proxy & Network Type",
    status: vpnStatus,
    scoreOutOf10: vpnScore,
    riskLabel: `${tierFor(vpnScore)} Risk \u2022 ${vpnScore}/10`,
    level: levelFor(vpnScore),
    detail: vpnDetail
  };
  const isVm = isVirtualMachine;
  const isTampered = isOsTampered;
  const cloudContainerVm = datacenterAsn && (isGpuMaskedOrUnavailable || cloudOrMaskedGpu);
  const vmLike = isVm || cloudContainerVm;
  const vmScore = tamperedRequest || replayDetected ? 10 : emulatorDetected ? 8 : vmLike ? 7 : isTampered ? 6 : 0;
  const vmStatus = tamperedRequest || replayDetected ? "Tampered / Replayed" : emulatorDetected ? "Mobile Emulator" : vmLike ? "Virtual Machine / VM" : isTampered ? "Spoofed Environment" : "Physical Hardware";
  const vmDetail = tamperedRequest || replayDetected ? requestIntegrityReason || "Sealed request envelope failed verification" : emulatorDetected ? emulatorReason || vmReason || "Mobile emulator / simulator runtime detected" : vmLike ? vmReason || (cloudContainerVm ? `Cloud container on ${ispBrand}${asnSuffix} exposed an unavailable / masked GPU` : "Hypervisor CPUID / virtualised GPU footprint detected") : isTampered ? vmReason || tamperReasons[0] || "Operating-system / User-Agent tampering detected" : "Unmasked physical GPU & consistent OS platform verified";
  const vmSignal = {
    id: "vm",
    title: "Virtual Machine & OS Integrity",
    status: vmStatus,
    scoreOutOf10: vmScore,
    riskLabel: `${tierFor(vmScore)} Risk \u2022 ${vmScore}/10`,
    level: levelFor(vmScore),
    detail: vmDetail
  };
  const smartSignals = {
    incognito: incognitoSignal,
    bot: botSignal,
    vpn: vpnSignal,
    vm: vmSignal
  };
  const integrityViolation = Boolean(tamperedRequest || replayDetected);
  const networkPoints = torExitNode ? 5 : verifiedCrawlerNetwork ? 0 : isDatacenterAsn ? 3 : hasTzMismatch ? 2 : 0;
  const rawCompositePoints = (isBot ? 5 : isHeadless ? 4 : 0) + networkPoints + (vmScore > 0 ? 3 : 0) + (isIncognito ? 2 : 0) + (integrityViolation ? 2 : 0);
  const weightedCompositeScore = Math.min(10, rawCompositePoints);
  const cardScores = [incognitoScore, botScore, vpnScore, vmScore];
  const maxCardScore = Math.max(0, ...cardScores);
  const elevatedCardCount = cardScores.filter((score) => score >= 4).length;
  const synergyBonus = elevatedCardCount >= 3 ? 2 : elevatedCardCount === 2 ? 1 : 0;
  const suspectScore = Math.min(
    10,
    Math.max(weightedCompositeScore, maxCardScore + synergyBonus)
  );
  const riskLevel = tierFor(suspectScore);
  const riskBadgeText = `${riskLevel} Risk \u2022 ${suspectScore}/10`;
  const riskFactors = [];
  if (isBot) {
    riskFactors.push(
      `Automated browser / bot runtime detected (+5): ${botReason || botClassification.reasons[0] || botSignals[0] || "WebDriver / CDP automation signatures"}`
    );
  } else if (isHeadless) {
    riskFactors.push(
      `Headless browser environment (+4): ${botReason || "no physical display attached"}`
    );
  }
  if (torAnonymity) {
    riskFactors.push(
      `${torExitNode ? "Confirmed Tor exit relay" : "Tor Browser fingerprint"} (+${torExitNode && torBrowserClient ? 10 : 9} card): ${torExitNode ? torOperatorHint ? "exit-operator attribution" : "Tor Project DNSEL / consensus exit list" : "Gecko RFP + letterboxing detected on the client"} ${location.publicIp}`
    );
  } else if (torRelayNetwork) {
    riskFactors.push(
      `Tor relay network (+6 card): ${torOperatorLabel || asnOrOrg} \u2014 relay, not an exit egress`
    );
  } else if (verifiedCrawlerNetwork) {
  } else if (isDatacenterAsn) {
    riskFactors.push(
      `Datacenter / hosting network detected (+3): ${vpnReasons[0] || ispBrand}`
    );
  } else if (hasTzMismatch) {
    riskFactors.push(
      `Browser timezone differs from IP geolocation (+2): ${clientTzCanonical} vs ${ipTzCanonical}`
    );
  }
  if (aiAgent?.detected) {
    riskFactors.push(
      `${aiAgent.agentId === "impostor-spoof" ? "Spoofed AI bot impostor (10/10)" : "AI agent attributed (8/10)"}: ${aiAgent.agentName} \xB7 ${aiAgent.operator} \xB7 ${aiAgent.confidence}`
    );
  }
  if (vmScore > 0) {
    const duplicatesIntegrityReason = integrityViolation && vmSignal.detail === (requestIntegrityReason || "tampered or replayed payload");
    if (!duplicatesIntegrityReason) {
      riskFactors.push(`Virtual machine / tampered OS (+3): ${vmSignal.detail}`);
    }
  }
  if (isIncognito) {
    riskFactors.push(`Incognito / ephemeral storage (+2): ${incognitoSignal.detail}`);
  }
  if (integrityViolation) {
    riskFactors.push(
      `Sealed request envelope failed verification (+2): ${requestIntegrityReason || "tampered or replayed payload"}`
    );
  }
  const proxyAssessment = detectProxyHeaders(requestContext.headers, location.publicIp);
  const securitySignalsCore = {
    isBot,
    botSignals,
    vpnSuspected,
    timezoneMismatch,
    datacenterAsn,
    vpnReasons,
    browserTimezone,
    ipTimezone,
    tamperDetected,
    tamperReasons,
    incognitoLikely,
    storageQuotaMb,
    persistenceMode,
    suspectScore,
    riskLevel,
    riskFactors
  };
  return {
    ...securitySignalsCore,
    ...{
      cloudOrMaskedGpu,
      // Task 1 — ISP brand & network classification from the server-resolved location
      brandName: classification.brandName,
      networkType: classification.networkType,
      isConsumerBroadband: classification.isConsumerBroadband,
      isDatacenterOrHosting: classification.isDatacenterOrHosting,
      // Task 3 — deep technical detection signals
      webrtcLeak: false,
      webrtcCandidateIp,
      webrtcDetail,
      privacyProtected,
      privacyDetail,
      // Deprecated scoring inputs kept inert for response-shape backward compatibility.
      adBlockerDetected: false,
      devToolsOpen: false,
      canvasFarblingDetected,
      isVirtualMachine,
      vmReason,
      isOsTampered,
      incognitoOrCleared,
      // Client-side composite private-browsing probe (confidence 0..1 + evidence)
      incognitoConfidence: Math.max(
        0,
        Math.min(
          1,
          typeof raw?.incognitoConfidence === "number" && Number.isFinite(raw.incognitoConfidence) ? raw.incognitoConfidence : 0
        )
      ),
      incognitoDetail: typeof raw?.incognitoDetail === "string" ? raw.incognitoDetail.trim().slice(0, 240) : "",
      // Final 4-signal upgrade — private browsing, bot, network, VM integrity
      isIncognito,
      incognito: isIncognito,
      privateMode: isIncognito,
      incognitoMethod,
      headroomGiB,
      idbDurabilityRatio,
      opfsFlushMs,
      isHeadless,
      botReason,
      webdriver,
      cdpDetected,
      // Protocol-level and stealth-plugin evidence reaches the payload, the grid and the JSON.
      cdpRuntimeLeak: Boolean(raw?.cdpRuntimeLeak),
      stealthPluginDetected: Boolean(raw?.stealthPluginDetected),
      // The single source of truth for `vpn_methods`: the UI derives its count from this object.
      vpnMethods,
      smartSignals,
      riskBadgeText,
      // Phase 1 — bot / AI-agent subtype classification
      botSubtype,
      botProvider: botClassification.provider,
      botCategory: botClassification.category,
      botIdentityConfidence: botClassification.confidence,
      // Phase 2 — Tor exit relay + local abuse blocklist
      torExitNode,
      isTorBrowserClient: clientTorBrowser,
      torVerdict: requestContext.torVerdict ?? (torExitNode ? "exit" : "unknown"),
      torOperator: requestContext.torOperator ?? describeTorRelay(location.publicIp) ?? (torExitNode ? relayOperatorLabel(location) : null),
      aiAgent: requestContext.aiAgent ?? null,
      ipBlocklisted,
      ipBlocklistReasons,
      // Phase 5 — explicit proxy relay markers (Via / Forwarded / Proxy-Authorization chains)
      proxyDetected: proxyAssessment.detected,
      proxyReasons: proxyAssessment.reasons,
      // Phase 3 — mobile emulator / simulator verdict
      emulatorDetected,
      emulatorReason,
      // Phase 5 — browser tampering / docked DevTools (client-probed, echoed for the grid)
      tampering: Boolean(raw?.tampering),
      tamperingConfidence: raw?.tamperingConfidence || "high",
      tamperingMlScore: typeof raw?.tamperingMlScore === "number" ? raw.tamperingMlScore : 24e-4,
      tamperingDetails: raw?.tamperingDetails,
      developerTools: Boolean(raw?.developerTools),
      privacySettings: Boolean(raw?.privacySettings || clientTorBrowser),
      // Phase 4 — sealed request envelope verdicts
      tamperedRequest,
      replayDetected,
      requestIntegrityReason,
      requestNonce,
      // Task 3 — visit velocity / IP rotation (display only, never scored)
      distinctIpsLastHour: velocity.distinctIpsLastHour,
      visitsLastHour: velocity.visitsLastHour
    }
  };
}
function mergeRequestClientHints(headers, body) {
  const h = headers ?? null;
  const b = body && typeof body === "object" ? body : null;
  const firstText = (...values) => {
    for (const value of values) {
      if (typeof value === "string" && value.trim()) return value.trim();
    }
    return "";
  };
  const firstList = (a, bb) => {
    if (Array.isArray(a) && a.length > 0) return a;
    if (Array.isArray(bb) && bb.length > 0) return bb;
    if (typeof bb === "string" && bb.trim()) return bb;
    return void 0;
  };
  return {
    brands: firstList(h?.brands, b?.brands),
    fullVersionList: firstList(h?.fullVersionList, b?.fullVersionList),
    platform: firstText(h?.platform, b?.platform),
    platformVersion: firstText(h?.platformVersion, b?.platformVersion),
    architecture: firstText(h?.architecture, b?.architecture, b?.arch),
    bitness: firstText(h?.bitness, b?.bitness),
    model: firstText(h?.model, b?.model),
    mobile: b?.mobile ?? h?.mobile,
    formFactors: Array.isArray(b?.formFactors) ? b.formFactors : void 0,
    uaFullVersion: b?.uaFullVersion,
    wow64: typeof b?.wow64 === "boolean" ? b.wow64 : void 0
  };
}
app.post("/api/visitor/identify", async (req, res) => {
  try {
    void refreshTorBulkList();
    const requestBody = req.body || {};
    const {
      pageLoadId,
      storedVisitorId,
      storedVisitorToken,
      clientSessionId,
      clientHistoryBackup,
      browserDevice: rawBrowserDevice,
      hardwareSignals: rawHardwareSignals,
      securitySignals: rawSecuritySignals,
      clientGeoHint
    } = requestBody;
    const safePageLoadId = typeof pageLoadId === "string" && pageLoadId.trim().length > 0 ? pageLoadId.trim().slice(0, 80) : "pl_" + crypto.randomBytes(8).toString("hex");
    const browserDevice = sanitizeBrowserDevice(rawBrowserDevice);
    const hardwareSignals = sanitizeHardwareSignals(rawHardwareSignals, browserDevice);
    const hardwareId = hardwareSignals.hardwareId;
    const uaIdentity = normalizeUserAgent({
      userAgent: typeof req.headers["user-agent"] === "string" ? req.headers["user-agent"] : "",
      platform: typeof rawBrowserDevice?.platform === "string" ? rawBrowserDevice.platform : "",
      maxTouchPoints: hardwareSignals.maxTouchPoints,
      clientHints: mergeRequestClientHints(
        req.intelClientHints,
        requestBody.clientHints
      )
    });
    if (uaIdentity.os !== "Unknown" && /^unknown|^$/i.test(browserDevice.os || "")) {
      browserDevice.os = uaIdentity.os;
    }
    if (uaIdentity.browserName !== "Unknown" && /^unknown|^$/i.test(browserDevice.browser || "")) {
      browserDevice.browser = uaIdentity.browserName;
    }
    let { ip: extractedIp, isPublic } = extractVisitorIp(req);
    if (!isPublic && clientGeoHint && typeof clientGeoHint.ip === "string") {
      const normalizedHintIp = normalizeIpCandidate(clientGeoHint.ip);
      if (normalizedHintIp && isPublicRoutableIp(normalizedHintIp)) {
        extractedIp = normalizedHintIp;
        isPublic = true;
      }
    }
    const torLookupPromise = resolveTorExitVerdict(extractedIp).catch(
      () => "unknown"
    );
    const edgeGeo = extractEdgeGeo(req);
    let location = mergeLocationWithEdge(
      await resolveLocationWithTorFallback(extractedIp, isPublic, { edge: edgeGeo }),
      edgeGeo
    );
    if (isPublic && clientGeoHint && normalizeIpCandidate(clientGeoHint.ip)?.toLowerCase() === extractedIp.toLowerCase()) {
      const hintNet = normalizeIspAndOrg(
        clientGeoHint.isp,
        clientGeoHint.org,
        clientGeoHint.asn,
        Boolean(clientGeoHint.isVpnOrHosting)
      );
      const hintLat = typeof clientGeoHint.latitude === "number" && Number.isFinite(clientGeoHint.latitude) ? clientGeoHint.latitude : edgeGeo.latitude;
      const hintLon = typeof clientGeoHint.longitude === "number" && Number.isFinite(clientGeoHint.longitude) ? clientGeoHint.longitude : edgeGeo.longitude;
      const hintCity = typeof clientGeoHint.city === "string" ? clientGeoHint.city.trim() : "";
      const hintRegion = typeof clientGeoHint.region === "string" ? clientGeoHint.region.trim() : "";
      const hintCountry = typeof clientGeoHint.country === "string" ? clientGeoHint.country.trim() : "";
      const hintCountryCode = typeof clientGeoHint.countryCode === "string" ? clientGeoHint.countryCode.trim() : "";
      const ispIsPlaceholder = isMissingGeoValue(location.isp) || /^autonomous system\b/i.test(location.isp);
      location = {
        ...location,
        city: isMissingGeoValue(location.city) ? hintCity || edgeGeo.city || "Unknown" : location.city,
        region: isMissingGeoValue(location.region) ? hintRegion || edgeGeo.region || "Unknown" : location.region,
        country: isMissingGeoValue(location.country) ? countryNameFromCode(hintCountryCode) || hintCountry || edgeGeo.country || "Unknown" : location.country,
        countryCode: location.countryCode || hintCountryCode.toUpperCase() || edgeGeo.countryCode,
        latitude: location.latitude !== null ? location.latitude : hintLat,
        longitude: location.longitude !== null ? location.longitude : hintLon,
        isp: ispIsPlaceholder ? hintNet.isp : location.isp,
        org: isMissingGeoValue(location.org) ? hintNet.org : location.org,
        asn: normalizeAsnLabel(location.asn) || hintNet.asn || edgeGeo.asn,
        isVpnOrHosting: location.isVpnOrHosting || hintNet.isVpnOrHosting,
        isIpVerified: true,
        isLocationVerified: location.isLocationVerified || Boolean(hintCity || hintCountry || hintLat !== null)
      };
    }
    const edgeAsnNumber = Number.parseInt(edgeGeo.asn.replace(/^AS/i, ""), 10);
    const enrichedNetwork = await enrichNetwork(extractedIp, {
      asn: Number.isInteger(edgeAsnNumber) && edgeAsnNumber > 0 ? edgeAsnNumber : void 0,
      country: edgeGeo.countryCode || void 0
    });
    const placeholderIspBefore = isMissingGeoValue(location.isp) || /^autonomous system\b/i.test(location.isp) || location.isp === "Standard Network";
    const placeholderOrgBefore = isMissingGeoValue(location.org) || location.org === "Standard Network";
    if (enrichedNetwork.source !== "none") {
      const resolvedAsn = normalizeAsnLabel(enrichedNetwork.asn);
      location = {
        ...location,
        asn: normalizeAsnLabel(location.asn) || resolvedAsn || location.asn,
        isp: placeholderIspBefore && enrichedNetwork.asn_name ? enrichedNetwork.asn_name : location.isp,
        org: placeholderOrgBefore && enrichedNetwork.asn_name ? enrichedNetwork.asn_name : location.org,
        isVpnOrHosting: location.isVpnOrHosting || enrichedNetwork.datacenter_result
      };
    }
    const knownAsnLabel = normalizeAsnLabel(location.asn) || normalizeAsnLabel(edgeGeo.asn) || "";
    const stillPlaceholder = isMissingGeoValue(location.isp) || /^autonomous system\b/i.test(location.isp) || location.isp === "Standard Network";
    if (knownAsnLabel && stillPlaceholder) {
      const byAsn = await resolveAsnOrganization(knownAsnLabel);
      location = {
        ...location,
        asn: knownAsnLabel,
        isp: byAsn.asn_name || knownAsnLabel,
        org: isMissingGeoValue(location.org) || location.org === "Standard Network" ? byAsn.asn_name || knownAsnLabel : location.org,
        isVpnOrHosting: location.isVpnOrHosting || byAsn.datacenter_result
      };
    }
    const classification = classifyIspNetwork(location.isp, location.org, location.asn);
    const cookieVid = req.cookies?.intel_http_vid;
    const cookieToken = req.cookies?.intel_http_token;
    let existingVisitor;
    let recognitionSource = "New First-Party ID";
    let existingHwidVisitor = false;
    const cookieVerified = Boolean(cookieVid && verifyVisitorToken(cookieVid, cookieToken));
    const storageVerified = Boolean(
      storedVisitorId && verifyVisitorToken(storedVisitorId, storedVisitorToken)
    );
    const verifiedVid = cookieVerified ? cookieVid : storageVerified ? storedVisitorId : null;
    const verifiedToken = cookieVerified ? cookieToken : storageVerified ? storedVisitorToken : null;
    if (verifiedVid && verifiedToken) {
      recognitionSource = cookieVerified ? "First-Party Cookie" : "First-Party LocalStorage";
      try {
        existingVisitor = db.prepare("SELECT * FROM visitors WHERE visitor_id = ?").get(verifiedVid);
      } catch {
        existingVisitor = void 0;
      }
      const validHistoryBackup = clientHistoryBackup && verifySignedHistoryBackup(verifiedVid, clientHistoryBackup) ? clientHistoryBackup : null;
      if (!existingVisitor) {
        const nowIso = (/* @__PURE__ */ new Date()).toISOString();
        const restoredFirstUtc = validHistoryBackup?.firstVisitUtc || nowIso;
        const latestBackupVisit = validHistoryBackup?.visits?.[0];
        const restoredLastUtc = latestBackupVisit?.visitedAtUtc || nowIso;
        const restoredSessionId = clientSessionId || latestBackupVisit?.sessionId || generateSessionId();
        try {
          db.prepare(
            `INSERT INTO visitors (
              visitor_id, hmac_token, hardware_id, created_at_utc, updated_at_utc, active_session_id, last_activity_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).run(
            verifiedVid,
            verifiedToken,
            hardwareId,
            restoredFirstUtc,
            restoredLastUtc,
            restoredSessionId,
            restoredLastUtc
          );
          existingVisitor = db.prepare("SELECT * FROM visitors WHERE visitor_id = ?").get(verifiedVid);
        } catch {
        }
      }
      if (validHistoryBackup && validHistoryBackup.visits.length > 0) {
        const orderedAsc = [...validHistoryBackup.visits].reverse();
        for (const histVisit of orderedAsc) {
          try {
            const histVisitId = typeof histVisit.visitId === "string" && histVisit.visitId.trim() ? histVisit.visitId.trim() : generateVisitId();
            const histVisitedAt = typeof histVisit.visitedAtUtc === "string" && histVisit.visitedAtUtc.trim() ? histVisit.visitedAtUtc : (/* @__PURE__ */ new Date()).toISOString();
            db.prepare(
              `INSERT OR IGNORE INTO visits (
                visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
                public_ip, city, region, country, latitude, longitude, isp, org, asn,
                browser, os, device_type, screen_resolution, language, timezone,
                suspect_score, risk_level, score10, bot_name, recognition_source
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            ).run(
              histVisitId,
              verifiedVid,
              typeof histVisit.sessionId === "string" && histVisit.sessionId ? histVisit.sessionId : clientSessionId || generateSessionId(),
              `rehydrated_${histVisitId}`,
              histVisitedAt,
              histVisit.publicIp || "Unavailable",
              histVisit.city || "Unknown",
              histVisit.region || "Unknown",
              histVisit.country || "Unknown",
              typeof histVisit.latitude === "number" ? histVisit.latitude : null,
              typeof histVisit.longitude === "number" ? histVisit.longitude : null,
              histVisit.isp || "Unknown",
              histVisit.org || "Unknown",
              histVisit.asn || "Unknown",
              histVisit.browser || "Unknown",
              histVisit.os || "Unknown",
              histVisit.deviceType || "Unknown",
              histVisit.screenResolution || "Unavailable",
              histVisit.language || "Unavailable",
              histVisit.timezone || "Unavailable",
              typeof histVisit.suspectScore === "number" ? histVisit.suspectScore : null,
              histVisit.riskLevel || null,
              typeof histVisit.score10 === "number" ? histVisit.score10 : typeof histVisit.suspectScore === "number" ? histVisit.suspectScore : null,
              histVisit.botName || null,
              histVisit.recognitionSource || null
            );
          } catch {
          }
        }
      }
    } else if (hardwareId) {
      let hwMatchedVisitor;
      try {
        hwMatchedVisitor = db.prepare("SELECT * FROM visitors WHERE hardware_id = ?").get(hardwareId);
      } catch {
        hwMatchedVisitor = void 0;
      }
      if (hwMatchedVisitor) {
        existingVisitor = hwMatchedVisitor;
        existingHwidVisitor = true;
        recognitionSource = "Hardware Fingerprint (Cookie-less / Incognito)";
      }
    }
    const nowUtc = (/* @__PURE__ */ new Date()).toISOString();
    const nowMs = Date.now();
    let visitorId;
    let visitorToken;
    let currentSessionId;
    let currentVisitId = "";
    let isReturning = false;
    if (existingVisitor || verifiedVid) {
      visitorId = existingVisitor ? existingVisitor.visitor_id : verifiedVid;
      visitorToken = existingVisitor ? existingVisitor.hmac_token : verifiedToken;
      isReturning = true;
      const lastActivityMs = existingVisitor ? new Date(existingVisitor.last_activity_utc).getTime() : NaN;
      const isExpiredByInactivity = Number.isNaN(lastActivityMs) || nowMs - lastActivityMs > SESSION_EXPIRATION_MS;
      const isSameClientSession = Boolean(clientSessionId) && Boolean(existingVisitor) && clientSessionId === existingVisitor.active_session_id;
      let existingPageLoadVisit;
      try {
        existingPageLoadVisit = db.prepare("SELECT visit_id, session_id, visited_at_utc FROM visits WHERE visitor_id = ? AND page_load_id = ?").get(visitorId, safePageLoadId);
      } catch {
        existingPageLoadVisit = void 0;
      }
      if (existingPageLoadVisit) {
        currentSessionId = existingPageLoadVisit.session_id;
        currentVisitId = existingPageLoadVisit.visit_id;
      } else {
        if (isExpiredByInactivity || !isSameClientSession) {
          currentSessionId = generateSessionId();
        } else {
          currentSessionId = existingVisitor.active_session_id;
        }
        if (existingVisitor) {
          const visitId = generateVisitId();
          currentVisitId = visitId;
          try {
            db.prepare(
              `INSERT OR IGNORE INTO visits (
                visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
                public_ip, city, region, country, latitude, longitude, isp, org, asn,
                browser, os, device_type, screen_resolution, language, timezone
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            ).run(
              visitId,
              visitorId,
              currentSessionId,
              safePageLoadId,
              nowUtc,
              location.publicIp,
              location.city,
              location.region,
              location.country,
              location.latitude,
              location.longitude,
              location.isp,
              location.org,
              location.asn,
              browserDevice.browser,
              browserDevice.os,
              browserDevice.deviceType,
              browserDevice.screenResolution,
              browserDevice.language,
              browserDevice.timezone
            );
          } catch {
          }
          try {
            db.prepare(
              `UPDATE visitors
               SET updated_at_utc = ?, active_session_id = ?, last_activity_utc = ?, hardware_id = ?
               WHERE visitor_id = ?`
            ).run(nowUtc, currentSessionId, nowUtc, hardwareId, visitorId);
          } catch {
          }
        }
      }
    } else {
      visitorId = generateVisitorId2();
      visitorToken = signVisitorId(visitorId);
      currentSessionId = generateSessionId();
      isReturning = false;
      try {
        db.prepare(
          `INSERT INTO visitors (
            visitor_id, hmac_token, hardware_id, created_at_utc, updated_at_utc, active_session_id, last_activity_utc
          ) VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).run(visitorId, visitorToken, hardwareId, nowUtc, nowUtc, currentSessionId, nowUtc);
      } catch {
      }
      const visitId = generateVisitId();
      currentVisitId = visitId;
      try {
        db.prepare(
          `INSERT OR IGNORE INTO visits (
            visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
            public_ip, city, region, country, latitude, longitude, isp, org, asn,
            browser, os, device_type, screen_resolution, language, timezone
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          visitId,
          visitorId,
          currentSessionId,
          safePageLoadId,
          nowUtc,
          location.publicIp,
          location.city,
          location.region,
          location.country,
          location.latitude,
          location.longitude,
          location.isp,
          location.org,
          location.asn,
          browserDevice.browser,
          browserDevice.os,
          browserDevice.deviceType,
          browserDevice.screenResolution,
          browserDevice.language,
          browserDevice.timezone
        );
      } catch {
      }
    }
    const cookieOptions = {
      maxAge: 365 * 24 * 60 * 60 * 1e3,
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      secure: Boolean(process.env.VERCEL) || process.env.NODE_ENV === "production"
    };
    res.cookie("intel_http_vid", visitorId, cookieOptions);
    res.cookie("intel_http_token", visitorToken, cookieOptions);
    res.cookie("_intel_vid_client", visitorId, { ...cookieOptions, httpOnly: false });
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    let statsAgg;
    let prevVisitRow;
    try {
      statsAgg = db.prepare(
        `SELECT
            COUNT(*) AS total_visits,
            MIN(visited_at_utc) AS first_visit_utc,
            MAX(visited_at_utc) AS last_visit_utc,
            COUNT(DISTINCT session_id) AS total_sessions
           FROM visits
           WHERE visitor_id = ?`
      ).get(visitorId);
      prevVisitRow = db.prepare(
        `SELECT visited_at_utc
           FROM visits
           WHERE visitor_id = ?
           ORDER BY visited_at_utc DESC, id DESC
           LIMIT 1 OFFSET 1`
      ).get(visitorId);
    } catch {
      statsAgg = {
        total_visits: 0,
        first_visit_utc: null,
        last_visit_utc: null,
        total_sessions: 0
      };
      prevVisitRow = void 0;
    }
    const validBackupForStats = clientHistoryBackup && verifySignedHistoryBackup(visitorId, clientHistoryBackup) ? clientHistoryBackup : null;
    const dbTotalVisits = Number(statsAgg.total_visits) || 1;
    const mergedTotalVisits = validBackupForStats ? Math.max(dbTotalVisits, validBackupForStats.totalVisits) : dbTotalVisits;
    const dbTotalSessions = Number(statsAgg.total_sessions) || 1;
    const mergedTotalSessions = validBackupForStats ? Math.max(dbTotalSessions, validBackupForStats.totalSessions) : dbTotalSessions;
    const mergedFirstVisitUtc = validBackupForStats && validBackupForStats.firstVisitUtc && validBackupForStats.firstVisitUtc < (statsAgg.first_visit_utc || nowUtc) ? validBackupForStats.firstVisitUtc : statsAgg.first_visit_utc || nowUtc;
    const statistics = {
      firstVisitUtc: mergedFirstVisitUtc,
      lastVisitUtc: statsAgg.last_visit_utc || nowUtc,
      previousVisitUtc: prevVisitRow ? prevVisitRow.visited_at_utc : null,
      totalVisits: mergedTotalVisits,
      totalSessions: mergedTotalSessions,
      currentSessionId,
      sessionTimeoutMinutes: SESSION_TIMEOUT_MINUTES
    };
    if (statistics.totalVisits > 1) {
      isReturning = true;
    }
    let rawVisits = [];
    try {
      rawVisits = db.prepare(
        `SELECT
            id, visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
            public_ip, city, region, country, latitude, longitude, isp, org, asn,
            browser, os, device_type, screen_resolution, language, timezone,
            suspect_score, risk_level, score10, bot_name, recognition_source
           FROM visits
           WHERE visitor_id = ?
           ORDER BY visited_at_utc DESC, id DESC
           LIMIT 50`
      ).all(visitorId);
    } catch {
      rawVisits = [];
    }
    if (rawVisits.length === 0) {
      const backupVisits = validBackupForStats?.visits ?? [];
      rawVisits = backupVisits.map((visit) => ({
        id: visit.id,
        visit_id: visit.visitId,
        visitor_id: visitorId,
        session_id: visit.sessionId,
        page_load_id: `backup_${visit.visitId}`,
        visited_at_utc: visit.visitedAtUtc,
        public_ip: visit.publicIp,
        city: visit.city,
        region: visit.region,
        country: visit.country,
        latitude: visit.latitude,
        longitude: visit.longitude,
        isp: visit.isp,
        org: visit.org,
        asn: visit.asn,
        browser: visit.browser,
        os: visit.os,
        device_type: visit.deviceType,
        screen_resolution: visit.screenResolution,
        language: visit.language,
        timezone: visit.timezone,
        suspect_score: visit.suspectScore ?? null,
        risk_level: visit.riskLevel ?? null,
        score10: visit.score10 ?? null,
        bot_name: visit.botName ?? null,
        recognition_source: visit.recognitionSource ?? null
      }));
      rawVisits.unshift({
        id: 0,
        visit_id: currentVisitId || `backup_${safePageLoadId}`,
        visitor_id: visitorId,
        session_id: currentSessionId,
        page_load_id: safePageLoadId,
        visited_at_utc: nowUtc,
        public_ip: location.publicIp,
        city: location.city,
        region: location.region,
        country: location.country,
        latitude: location.latitude,
        longitude: location.longitude,
        isp: location.isp,
        org: location.org,
        asn: location.asn,
        browser: browserDevice.browser,
        os: browserDevice.os,
        device_type: browserDevice.deviceType,
        screen_resolution: browserDevice.screenResolution,
        language: browserDevice.language,
        timezone: browserDevice.timezone,
        suspect_score: null,
        risk_level: null,
        score10: null,
        bot_name: null,
        recognition_source: recognitionSource
      });
    }
    const ipTimezoneHint = typeof clientGeoHint?.timezone === "string" && clientGeoHint.timezone.trim() || edgeGeo.timezone || "";
    const oneHourAgoMs = Date.now() - 3600 * 1e3;
    const lastHourVisitRows = rawVisits.filter((r) => {
      const visitedAtMs = Date.parse(String(r.visited_at_utc || ""));
      return Number.isFinite(visitedAtMs) && visitedAtMs >= oneHourAgoMs;
    });
    const lastHourIpSet = /* @__PURE__ */ new Set();
    for (const lastHourRow of lastHourVisitRows) {
      const lastHourIp = String(lastHourRow.public_ip || "").trim();
      if (lastHourIp && lastHourIp !== "Unavailable") lastHourIpSet.add(lastHourIp);
    }
    const currentVisitIp = String(location.publicIp || "").trim();
    if (currentVisitIp && currentVisitIp !== "Unavailable") {
      lastHourIpSet.add(currentVisitIp);
    }
    const visitsLastHour = Math.max(1, lastHourVisitRows.length);
    const distinctIpsLastHour = lastHourIpSet.size;
    const bodyVisitorId = storageVerified ? storedVisitorId ?? null : null;
    const historyBackupValid = Boolean(validBackupForStats);
    const hadPersistentClientState = Boolean(cookieVid || bodyVisitorId || historyBackupValid);
    const clientReportedIncognito = Boolean(
      requestBody.incognito ?? requestBody.isIncognito ?? requestBody.privateMode ?? requestBody.browserInfo?.incognito ?? requestBody.browserInfo?.isIncognito ?? requestBody.telemetry?.incognito ?? requestBody.telemetry?.isIncognito ?? rawSecuritySignals?.isIncognito ?? rawSecuritySignals?.incognito ?? rawSecuritySignals?.privateMode ?? rawSecuritySignals?.incognitoLikely
    );
    let crossSessionEphemeral = false;
    if (!hadPersistentClientState && !existingHwidVisitor && hardwareId) {
      try {
        const sevenDaysAgoUtc = new Date(Date.now() - 7 * 24 * 3600 * 1e3).toISOString();
        const earlierDeviceVisit = db.prepare(
          `SELECT v.visitor_id
             FROM visits v
             JOIN visitors pv ON pv.visitor_id = v.visitor_id
             WHERE v.visitor_id != ?
               AND pv.hardware_id = ?
               AND v.public_ip = ?
               AND v.screen_resolution = ?
               AND v.browser = ?
               AND v.os = ?
               AND v.visited_at_utc >= ?
             ORDER BY v.visited_at_utc DESC
             LIMIT 1`
        ).get(
          visitorId,
          hardwareId,
          location.publicIp,
          browserDevice.screenResolution,
          browserDevice.browser,
          browserDevice.os,
          sevenDaysAgoUtc
        );
        crossSessionEphemeral = Boolean(earlierDeviceVisit);
      } catch {
        crossSessionEphemeral = false;
      }
    }
    const securitySignalsInput = rawSecuritySignals || requestBody.incognitoMethod ? {
      ...rawSecuritySignals ?? {},
      // Top-level method spelling is honoured when securitySignals omitted it.
      incognitoMethod: rawSecuritySignals?.incognitoMethod ?? requestBody.incognitoMethod
    } : rawSecuritySignals;
    const rawRequestHeaders = req.headers;
    const envelopeVerdict = verifySecurityEnvelope({
      envelope: requestBody.securityEnvelope,
      headers: rawRequestHeaders,
      hardwareId,
      nowMs
    });
    const headerRequestUserAgent = readRequestHeader(rawRequestHeaders, "user-agent");
    const envelopeRequestUserAgent = typeof requestBody.securityEnvelope?.userAgent === "string" ? requestBody.securityEnvelope.userAgent.trim() : "";
    const headerCarriesBotSignature = Boolean(headerRequestUserAgent) && (AUTOMATION_UA_PATTERN.test(headerRequestUserAgent) || GOOD_BOT_UA_RULES.some((rule) => rule.pattern.test(headerRequestUserAgent)) || AI_AGENT_UA_RULES.some((rule) => rule.pattern.test(headerRequestUserAgent)));
    const fullRequestUserAgent = headerCarriesBotSignature ? headerRequestUserAgent : envelopeRequestUserAgent || headerRequestUserAgent;
    const botClassification = classifyBotTraffic(
      { ...rawRequestHeaders, "user-agent": fullRequestUserAgent },
      { org: location.org, isp: location.isp, asn: location.asn },
      {
        isBot: Boolean(
          rawSecuritySignals?.isBot || rawSecuritySignals?.webdriver || rawSecuritySignals?.cdpDetected
        ),
        isHeadless: Boolean(rawSecuritySignals?.isHeadless),
        webdriver: Boolean(rawSecuritySignals?.webdriver),
        cdpDetected: Boolean(rawSecuritySignals?.cdpDetected),
        botSignals: Array.isArray(rawSecuritySignals?.botSignals) ? rawSecuritySignals.botSignals : []
      }
    );
    const torLookupTarget = location.publicIp.trim().toLowerCase();
    const torStatus = await resolveTorExitStatus(
      location.publicIp,
      location,
      torLookupTarget === extractedIp.trim().toLowerCase() ? torLookupPromise : void 0,
      edgeGeo.isTorNetwork
    );
    const torExitNode = torStatus.isExit;
    const isTorExit = torStatus.isExit;
    const isTor = isTorExit || edgeGeo.isTorNetwork || Boolean(location.isTor);
    const networkTypeLabel = String(classification.networkType || "");
    const isProxyOrVpn = Boolean(location.isProxyOrVpn) || isTorExit || /vpn|proxy/i.test(networkTypeLabel);
    const isNetworkLocation = isTorExit || /vpn|proxy|tor/i.test(networkTypeLabel);
    const hasCountryForLocation = Boolean(location.countryCode) || !isMissingGeoValue(location.country);
    const resolvedPrecision = !isMissingGeoValue(location.city) ? "city" : !isMissingGeoValue(location.region) ? "region" : hasCountryForLocation ? "country" : "unknown";
    location = {
      ...location,
      isTor,
      isTorExit,
      isProxyOrVpn,
      locationSource: location.locationSource ?? "provider",
      locationPrecision: resolvedPrecision,
      isNetworkLocation,
      networkLocation: isNetworkLocation ? {
        label: isTorExit ? "Tor exit node" : isProxyOrVpn ? "VPN / proxy egress" : "Network egress",
        city: !isMissingGeoValue(location.city) ? location.city : "Unknown",
        region: !isMissingGeoValue(location.region) ? location.region : "Unknown",
        country: location.country,
        countryCode: location.countryCode,
        latitude: location.latitude,
        longitude: location.longitude,
        isp: location.isp,
        org: location.org,
        asn: location.asn
      } : location.networkLocation,
      isLocationVerified: hasCountryForLocation
    };
    const aiAgent = await resolveAiAgentIdentity({
      headers: rawRequestHeaders,
      userAgent: fullRequestUserAgent,
      network: { isp: location.isp, org: location.org, asn: location.asn },
      publicIp: location.publicIp,
      client: {
        isBot: Boolean(rawSecuritySignals?.isBot),
        isHeadless: Boolean(rawSecuritySignals?.isHeadless),
        webdriver: Boolean(rawSecuritySignals?.webdriver),
        cdpDetected: Boolean(rawSecuritySignals?.cdpDetected),
        isVirtualMachine: Boolean(rawSecuritySignals?.isVirtualMachine),
        gpuVendor: hardwareSignals.gpuVendor,
        gpuRenderer: hardwareSignals.gpuRenderer,
        idbDurabilityRatio: rawSecuritySignals?.idbDurabilityRatio ?? null,
        screenResolution: browserDevice.screenResolution,
        platform: browserDevice.platform,
        botSignals: Array.isArray(rawSecuritySignals?.botSignals) ? rawSecuritySignals.botSignals : []
      }
    });
    const attributedBotClassification = aiAgent.detected && aiAgent.agentId === "impostor-spoof" ? {
      subtype: "bad_bot",
      label: "Spoofed AI Bot",
      provider: aiAgent.operator,
      category: "Spoofed Identity",
      confidence: 0.99,
      reasons: aiAgent.evidence.slice(0, 3)
    } : aiAgent.detected && aiAgent.agentId !== null ? {
      subtype: "ai_agent",
      label: aiAgent.agentName,
      provider: aiAgent.operator,
      category: "AI Agent",
      confidence: aiAgent.verified ? 0.99 : 0.85,
      reasons: aiAgent.evidence.slice(0, 3)
    } : null;
    const effectiveBotClassification = attributedBotClassification ?? botClassification;
    const signedPayloadTampered = /Payload integrity hash mismatch/i.test(
      envelopeVerdict.requestIntegrityReason
    );
    if (signedPayloadTampered) {
      flagSuspiciousIp(
        location.publicIp,
        envelopeVerdict.requestIntegrityReason || "Tampered request payload"
      );
    }
    if (envelopeVerdict.replayDetected) {
      flagSuspiciousIp(location.publicIp, "Replayed payload nonce");
    }
    if (effectiveBotClassification.subtype === "bad_bot" && effectiveBotClassification.label === "Spoofed Crawler") {
      flagSuspiciousIp(location.publicIp, "Spoofed crawler user-agent");
    } else if (aiAgent.agentId === "impostor-spoof") {
      flagSuspiciousIp(location.publicIp, "Spoofed AI bot user-agent");
    }
    const blocklist = lookupSuspiciousIp(location.publicIp);
    const securitySignals = sanitizeAndReinforceSecuritySignals(
      securitySignalsInput,
      browserDevice,
      hardwareSignals,
      location,
      ipTimezoneHint,
      recognitionSource,
      classification,
      { visitsLastHour, distinctIpsLastHour },
      {
        hadPersistentClientState,
        existingHwidVisitor,
        clientReportedIncognito,
        crossSessionEphemeral
      },
      {
        headers: rawRequestHeaders,
        requestUserAgent: fullRequestUserAgent,
        tamperedRequest: envelopeVerdict.tamperedRequest,
        replayDetected: envelopeVerdict.replayDetected,
        requestIntegrityReason: envelopeVerdict.requestIntegrityReason,
        requestNonce: envelopeVerdict.requestNonce,
        torExitNode,
        torRelay: torStatus.isRelay,
        torVerdict: torStatus.verdict,
        torOperator: torStatus.operator,
        torOperatorHint: torStatus.viaOperatorHint,
        clientTorBrowser: Boolean(rawSecuritySignals?.isTorBrowserClient),
        aiAgent,
        ipBlocklisted: blocklist.blocklisted,
        ipBlocklistReasons: blocklist.reasons,
        botClassification: effectiveBotClassification
      }
    );
    const velocityReport = computeVelocitySignals(
      db,
      visitorId,
      location.publicIp,
      currentSessionId
    );
    const rarityReport = computeDeviceRarity(db, browserDevice);
    const highActivityDevice = velocityReport.events24h >= 20;
    const clientTampering = rawSecuritySignals?.tampering ?? null;
    const tamperingAssessment = clientTampering === null ? null : {
      tampering: Boolean(clientTampering),
      confidence: rawSecuritySignals?.tamperingConfidence || "high",
      mlScore: typeof rawSecuritySignals?.tamperingMlScore === "number" ? rawSecuritySignals.tamperingMlScore : 24e-4,
      details: rawSecuritySignals?.tamperingDetails ?? {
        anomaly_score: 0,
        anti_detect_browser: false,
        devtools_device_emulation: false,
        reasons: []
      }
    };
    const activeCallSupported = Boolean(rawSecuritySignals?.activeCallSupported);
    const activeCall = activeCallSupported && Boolean(rawSecuritySignals?.activeCall);
    const privacySettings = Boolean(
      rawSecuritySignals?.privacySettings || rawSecuritySignals?.isTorBrowserClient || securitySignals.privacyProtected
    );
    const developerTools = Boolean(rawSecuritySignals?.developerTools);
    const suspectScore100 = computeSuspectScore100({
      bot: Boolean(securitySignals.isBot),
      replayed: Boolean(securitySignals.replayDetected),
      tampering: Boolean(tamperingAssessment?.tampering),
      vpn: Boolean(securitySignals.vpnSuspected),
      vpnMethodCount: Array.isArray(securitySignals.vpnReasons) ? securitySignals.vpnReasons.length : 0,
      blocklisted: Boolean(securitySignals.torExitNode || securitySignals.ipBlocklisted),
      virtualMachine: Boolean(
        securitySignals.isVirtualMachine || securitySignals.cloudOrMaskedGpu || securitySignals.emulatorDetected
      ),
      proxy: Boolean(
        securitySignals.proxyDetected
      ),
      simulator: Boolean(securitySignals.emulatorDetected),
      activeCall,
      privacySettings,
      incognito: Boolean(securitySignals.isIncognito),
      highActivityDevice,
      developerTools,
      rareDevice: rarityReport.rareDevice
    });
    const currentBotName = (aiAgent?.detected ? aiAgent.agentName : "") || (effectiveBotClassification.subtype !== "human" ? `${effectiveBotClassification.provider} ${effectiveBotClassification.label}`.trim() : "");
    const visitHistory = rawVisits.map((r) => {
      const storedScore10 = typeof r.score10 === "number" && Number.isFinite(r.score10) ? Math.max(0, Math.min(10, Math.round(r.score10))) : null;
      const storedSuspectScore = typeof r.suspect_score === "number" && Number.isFinite(r.suspect_score) ? normalizeLegacySuspectScore(r.suspect_score) : storedScore10;
      const isCurrentVisitRow = String(r.page_load_id || "") === safePageLoadId;
      const rowSuspectScore = storedSuspectScore !== null ? storedSuspectScore : isCurrentVisitRow ? securitySignals.suspectScore : 0;
      const storedRiskLevel = r.risk_level === "High" || r.risk_level === "Medium" || r.risk_level === "Low" ? r.risk_level : null;
      const rowRiskLevel = storedRiskLevel ?? (rowSuspectScore >= 7 ? "High" : rowSuspectScore >= 3 ? "Medium" : "Low");
      const rowRecognitionSource = typeof r.recognition_source === "string" && r.recognition_source ? r.recognition_source : isCurrentVisitRow ? recognitionSource : "Cookie";
      const rowBotName = typeof r.bot_name === "string" && r.bot_name ? r.bot_name : isCurrentVisitRow ? currentBotName : "";
      const rowCloudOrMaskedGpu = isCurrentVisitRow ? Boolean(
        securitySignals.cloudOrMaskedGpu
      ) : false;
      return {
        id: Number(r.id),
        visitId: String(r.visit_id),
        visitorId: String(r.visitor_id),
        sessionId: String(r.session_id),
        visitedAtUtc: String(r.visited_at_utc),
        publicIp: String(r.public_ip),
        city: String(r.city),
        region: String(r.region),
        country: String(r.country),
        latitude: typeof r.latitude === "number" && Number.isFinite(r.latitude) ? r.latitude : null,
        longitude: typeof r.longitude === "number" && Number.isFinite(r.longitude) ? r.longitude : null,
        isp: String(r.isp || "Unknown"),
        org: String(r.org || "Unknown"),
        asn: String(r.asn || "Unknown"),
        browser: String(r.browser),
        os: String(r.os),
        deviceType: String(r.device_type),
        screenResolution: String(r.screen_resolution),
        language: String(r.language),
        timezone: String(r.timezone),
        suspectScore: rowSuspectScore,
        score10: Math.max(0, Math.min(10, Math.round(rowSuspectScore))),
        riskLevel: rowRiskLevel,
        botName: rowBotName || void 0,
        recognitionSource: rowRecognitionSource,
        cloudOrMaskedGpu: rowCloudOrMaskedGpu
      };
    });
    if (currentVisitId) {
      try {
        db.prepare(
          `UPDATE visits
           SET suspect_score = ?, risk_level = ?, score10 = ?, bot_name = ?, recognition_source = ?
           WHERE visit_id = ?`
        ).run(
          securitySignals.suspectScore,
          securitySignals.riskLevel,
          Math.max(0, Math.min(10, Math.round(securitySignals.suspectScore))),
          currentBotName || null,
          recognitionSource,
          currentVisitId
        );
      } catch {
      }
    }
    const historyBackup = createSignedHistoryBackup(
      visitorId,
      statistics.totalVisits,
      statistics.totalSessions,
      statistics.firstVisitUtc,
      visitHistory,
      hardwareId
    );
    const asnNumMatch = (location.asn || "").match(/\d+/);
    const asnNumber = asnNumMatch ? Number.parseInt(asnNumMatch[0], 10) : null;
    const robodexResult = detectAiBotFromServerSignals({
      userAgent: fullRequestUserAgent,
      asnNumber,
      asnOrg: `${location.org} ${location.isp}`,
      headers: rawRequestHeaders
    });
    let botInfo = null;
    let botType = null;
    let botVerdict = "not_detected";
    if (robodexResult.detected && robodexResult.botInfo) {
      botInfo = robodexResult.botInfo;
      botType = robodexResult.botType;
      botVerdict = botInfo?.identity === "spoofed" || botInfo?.identity === "unknown" ? "bad" : botType === "ai_agent" || botType === "ai_browser" || botType === "browser_automation" ? "bad" : "good";
    } else if (aiAgent.detected) {
      const isImpostor = aiAgent.agentId === "impostor-spoof";
      botInfo = {
        category: isImpostor ? "browser_automation" : "ai_agent",
        provider: aiAgent.operator || "Unknown",
        name: aiAgent.agentName,
        identity: isImpostor ? "spoofed" : aiAgent.verified ? aiAgent.executionMode === "RFC 9421 Signed Agent" ? "signed" : "verified" : "unknown"
      };
      botType = "ai_agent";
      botVerdict = "bad";
    } else if (effectiveBotClassification.subtype === "bad_bot") {
      botInfo = {
        category: "browser_automation",
        provider: effectiveBotClassification.provider || "Unknown",
        name: effectiveBotClassification.label || "Automated Tool",
        identity: "unknown"
      };
      botType = "browser_automation";
      botVerdict = "bad";
    } else if (effectiveBotClassification.subtype === "good_bot") {
      botInfo = {
        category: "ai_crawler",
        provider: effectiveBotClassification.provider || "Search Engine",
        name: effectiveBotClassification.label || "Search Crawler",
        identity: "verified"
      };
      botType = "ai_crawler";
      botVerdict = "good";
    }
    if (botInfo) {
      securitySignals.botInfo = botInfo;
    }
    const rawIdentityProfile = requestBody.identityProfile && typeof requestBody.identityProfile === "object" ? requestBody.identityProfile : null;
    const fallbackIdentityProfile = {
      hardwareFingerprint: hardwareId,
      browser: { family: browserDevice.browser },
      os: { family: browserDevice.os },
      timezone: browserDevice.timezone,
      gpu: { vendor: hardwareSignals.gpuVendor, renderer: hardwareSignals.gpuRenderer },
      canvas: { hash: hardwareSignals.canvasHash },
      audio: { hash: hardwareSignals.audioHash },
      cpu: { cores: hardwareSignals.cpuCores },
      languages: browserDevice.language ? [browserDevice.language] : [],
      net: { ip: extractedIp, asn: location.asn }
    };
    const identityProfile = rawIdentityProfile ?? fallbackIdentityProfile;
    const identityHardwareFingerprint = typeof requestBody.hardwareFingerprint === "string" && requestBody.hardwareFingerprint.trim().length > 0 ? requestBody.hardwareFingerprint.trim() : typeof identityProfile.hardwareFingerprint === "string" && identityProfile.hardwareFingerprint.trim().length > 0 ? identityProfile.hardwareFingerprint.trim() : hardwareId;
    const identityBrowserFingerprint = typeof requestBody.browserFingerprint === "string" && requestBody.browserFingerprint.trim().length > 0 ? requestBody.browserFingerprint.trim() : typeof identityProfile.browserFingerprint === "string" ? identityProfile.browserFingerprint.trim() : "";
    const identitySessionId = typeof requestBody.sessionId === "string" && requestBody.sessionId.trim().length > 0 ? requestBody.sessionId.trim().slice(0, 80) : currentSessionId;
    const storageHealed = Boolean(requestBody.storageHealed);
    const isMobileIos = browserDevice.deviceKind !== "pc" && /ios|iphone|ipad|ipod/i.test(`${browserDevice.os} ${browserDevice.platform}`);
    let resolvedIdentity = {
      visitor_id: visitorId,
      match_mode: "none",
      match_score: 0,
      is_new: !existingVisitor,
      isNew: !existingVisitor,
      confidence_hint: 0,
      healed: false,
      reasons: []
    };
    try {
      ensureIdentitySchema(db);
      upsertVisitorProfile(db, visitorId, identityProfile, identityHardwareFingerprint, nowUtc);
      upsertBlocks(db, visitorId, blockKeysFor(identityProfile), nowUtc);
      if (existingVisitor || verifiedVid) {
        resolvedIdentity = await resolveVisitor(db, {
          profile: identityProfile,
          storageVisitorId: verifiedVid ?? null,
          isMobileIos
        });
      }
    } catch {
    }
    const visitorFound = Boolean(existingVisitor) || !resolvedIdentity.is_new;
    const identityConfidence = scoreConfidence({
      match_mode: resolvedIdentity.match_mode,
      match_score: resolvedIdentity.match_score,
      storage_healed: storageHealed || resolvedIdentity.healed,
      incognito: securitySignals.isIncognito,
      isMobileIos,
      firstSeenDesktop: !isReturning,
      consistencyFlags: resolvedIdentity.reasons,
      rfpOrTor: Boolean(securitySignals.torExitNode) || Boolean(securitySignals.isTorBrowserClient),
      genuineSpoof: botVerdict === "bad" && botInfo?.identity === "spoofed"
    });
    const identityConsistencyFlags = Array.from(new Set(resolvedIdentity.reasons));
    const identityConsistency = {
      score: Math.max(
        0,
        Math.min(100, Math.round(identityConfidence.score * 100) - identityConsistencyFlags.length * 10)
      ),
      spoof_likelihood: identityConfidence.spoof_likelihood,
      flags: identityConsistencyFlags,
      agent_verdict: String(
        securitySignals.botSubtype || (securitySignals.isBot ? "automated" : "human")
      )
    };
    const payload = {
      visitorId,
      visitorToken,
      hardwareId,
      isReturning,
      recognitionSource,
      location,
      // Fix 5 — deterministic proximity from the IP coordinates, resolved synchronously.
      proximity: buildProximityInfo(location.latitude, location.longitude),
      // Fix 8 — structured bot & AI agent identification ("Robodex" + BotD).
      bot: botVerdict,
      bot_type: botType,
      bot_info: botInfo,
      browserDevice,
      // Server-normalized UA / client-hints identity. `os` is the family only and the
      // version lives in `os_version`; `browser_details` mirrors the event contract so
      // `browser_major_version` is never empty when a full version is known.
      os: uaIdentity.os,
      os_version: uaIdentity.osVersion,
      browser_details: {
        browser_name: uaIdentity.browserName,
        browser_full_version: uaIdentity.browserFullVersion,
        browser_major_version: uaIdentity.browserMajorVersion,
        os: uaIdentity.os,
        os_version: uaIdentity.osVersion,
        device: uaIdentity.device,
        device_model: uaIdentity.model || browserDevice.reportedModel || browserDevice.phoneModel || ""
      },
      hardwareSignals,
      securitySignals,
      statistics,
      visitHistory,
      historyBackup,
      // Top-level mirrors so clients can read the 4-signal verdict without digging.
      isIncognito: securitySignals.isIncognito,
      incognito: securitySignals.isIncognito,
      suspectScore: securitySignals.suspectScore,
      riskLevel: securitySignals.riskLevel,
      riskBadgeText: securitySignals.riskBadgeText,
      smartSignals: securitySignals.smartSignals,
      // API v4 mirrors: 0-100 calibrated composite, velocity windows and device rarity.
      suspectScore100,
      velocity: velocityReport.velocity,
      highActivityDevice,
      rareDevice: rarityReport.rareDevice,
      rareDevicePercentileBucket: rarityReport.bucket,
      tampering: tamperingAssessment?.tampering ?? false,
      tamperingConfidence: tamperingAssessment?.confidence ?? "high",
      tamperingDetails: tamperingAssessment?.details,
      activeCall,
      activeCallSupported,
      rawDeviceAttributes: rawSecuritySignals?.rawDeviceAttributes ?? null,
      // Tri-layer identity: canonical visitor ID plus the resolver's match evidence. The
      // resolver never replaces the canonical ID here — it only reports mode/score and,
      // for cross-browser stitches, a supplementary link.
      identity_layers: {
        visitor_id: visitorId,
        hardware_fingerprint: identityHardwareFingerprint,
        browser_fingerprint: identityBrowserFingerprint,
        session_id: identitySessionId,
        storage_healed: storageHealed || resolvedIdentity.healed,
        match_mode: resolvedIdentity.match_mode,
        match_score: resolvedIdentity.match_score,
        visitor_found: visitorFound,
        supplementary_visitor_id: resolvedIdentity.supplementary?.visitor_id,
        supplementary_confidence: resolvedIdentity.supplementary?.confidence_hint
      },
      identification: {
        confidence: {
          score: identityConfidence.score,
          version: identityConfidence.version
        },
        visitor_found: visitorFound,
        tampering: identityConfidence.tampering,
        spoof_likelihood: identityConfidence.spoof_likelihood
      },
      consistency: identityConsistency,
      // Phase 4 verdicts mirrored at the top level. A duplicate nonce is reported as
      // `replayed: true` inside a normal 200 payload — it is never an HTTP error that
      // would break the in-page Record Visit / Analyze button.
      replayed: envelopeVerdict.replayDetected,
      tampered: envelopeVerdict.tamperedRequest,
      requestIntegrityReason: envelopeVerdict.requestIntegrityReason
    };
    res.json(payload);
  } catch (err) {
    console.error("Error in /api/visitor/identify:", err);
    res.status(500).json({ error: "Unable to process visitor identification request." });
  }
});
app.get("/api/visitor/history/:visitorId", (req, res) => {
  const requestedVisitorId = req.params.visitorId;
  const headerToken = req.headers["x-visitor-token"];
  const cookieVid = req.cookies?.intel_http_vid;
  const cookieToken = req.cookies?.intel_http_token;
  const authorizedByHeader = verifyVisitorToken(requestedVisitorId, headerToken);
  const authorizedByCookie = cookieVid === requestedVisitorId && verifyVisitorToken(cookieVid, cookieToken);
  if (!authorizedByHeader && !authorizedByCookie) {
    res.status(403).json({
      error: "Forbidden: You are not authorized to access another visitor\u2019s records."
    });
    return;
  }
  let rawVisits = [];
  try {
    rawVisits = db.prepare(
      `SELECT
          id, visit_id, visitor_id, session_id, visited_at_utc,
          public_ip, city, region, country, isp, org, asn,
          browser, os, device_type, screen_resolution, language, timezone,
          suspect_score, risk_level, score10, bot_name, recognition_source
         FROM visits
         WHERE visitor_id = ?
         ORDER BY visited_at_utc DESC, id DESC
         LIMIT 50`
    ).all(requestedVisitorId);
  } catch {
    rawVisits = [];
  }
  const visits = rawVisits.map((row) => {
    const storedScore10 = typeof row.score10 === "number" && Number.isFinite(row.score10) ? Math.max(0, Math.min(10, Math.round(row.score10))) : null;
    const storedSuspectScore = typeof row.suspect_score === "number" && Number.isFinite(row.suspect_score) ? normalizeLegacySuspectScore(row.suspect_score) : storedScore10 ?? 0;
    const storedRecognitionSource = typeof row.recognition_source === "string" && row.recognition_source.trim() ? row.recognition_source : "Cookie";
    const storedRiskLevel = row.risk_level === "High" || row.risk_level === "Medium" || row.risk_level === "Low" ? row.risk_level : null;
    const rowRiskLevel = storedRiskLevel ?? (storedSuspectScore >= 7 ? "High" : storedSuspectScore >= 3 ? "Medium" : "Low");
    return {
      ...row,
      suspectScore: storedSuspectScore,
      score10: Math.max(0, Math.min(10, Math.round(storedSuspectScore))),
      riskLevel: rowRiskLevel,
      botName: typeof row.bot_name === "string" && row.bot_name ? row.bot_name : void 0,
      recognitionSource: storedRecognitionSource
    };
  });
  res.json({ visitorId: requestedVisitorId, visits });
});
app.get("/api/intel/identity-ping", (req, res) => {
  res.setHeader("Cache-Control", "private, max-age=0, must-revalidate");
  res.setHeader("Vary", "Cookie");
  const presented = typeof req.headers["if-none-match"] === "string" ? req.headers["if-none-match"] : "";
  if (presented) {
    res.setHeader("ETag", presented);
    res.status(304).end();
    return;
  }
  const cookies = req.cookies ?? {};
  const cookieVisitor = typeof cookies["_intel_vid_client"] === "string" && cookies["_intel_vid_client"].trim() || typeof cookies["intel_http_vid"] === "string" && cookies["intel_http_vid"].trim() || "";
  if (!cookieVisitor) {
    res.status(204).end();
    return;
  }
  const etag = `"${crypto.createHash("sha256").update(cookieVisitor).digest("base64url")}"`;
  res.setHeader("ETag", etag);
  res.json({
    identity: {
      visitor_id: cookieVisitor,
      hardware_fingerprint: "",
      browser_fingerprint: "",
      created_at: (/* @__PURE__ */ new Date()).toISOString()
    }
  });
});
app.use("/api", (_req, res) => {
  res.status(404).json({ error: "API endpoint not found." });
});
app.use(
  (err, _req, res, _next) => {
    console.error("Unhandled API error:", err);
    if (!res.headersSent) {
      res.status(500).json({ error: "Internal server error." });
    }
  }
);
async function startStandaloneServer() {
  if (process.env.NODE_ENV !== "production") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Intel System running on http://0.0.0.0:${PORT}`);
  });
}
if (!IS_SERVERLESS_RUNTIME) {
  startStandaloneServer();
}
var server_default = app;

// api/_entry.ts
var API_PREFIX = "/api";
function applyRestoredUrlAndQuery(req, restoredPath, params) {
  params.delete("__ipath");
  const remainingQuery = params.toString();
  const finalUrl = remainingQuery ? `${restoredPath}?${remainingQuery}` : restoredPath;
  req.url = finalUrl;
  req.originalUrl = finalUrl;
  const internalReq = req;
  if ("_parsedUrl" in internalReq) {
    delete internalReq._parsedUrl;
  }
  if ("_parsedOriginalUrl" in internalReq) {
    delete internalReq._parsedOriginalUrl;
  }
  const cleanQuery = {};
  for (const [key, value] of params.entries()) {
    if (key === "__ipath") continue;
    const existing = cleanQuery[key];
    if (existing === void 0) {
      cleanQuery[key] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      cleanQuery[key] = [existing, value];
    }
  }
  try {
    Object.defineProperty(req, "query", {
      value: cleanQuery,
      writable: true,
      enumerable: true,
      configurable: true
    });
  } catch {
    try {
      req.query = cleanQuery;
    } catch {
    }
  }
}
function restoreOriginalApiUrl(req) {
  const rawUrl = typeof req.url === "string" && req.url.length > 0 ? req.url : "/";
  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl, "http://localhost");
  } catch {
    try {
      parsedUrl = new URL(rawUrl.replace(/%(?![0-9a-fA-F]{2})/g, "%25"), "http://localhost");
    } catch {
      return;
    }
  }
  const searchParams = parsedUrl.searchParams;
  try {
    if (req.query && typeof req.query === "object") {
      for (const [k, v] of Object.entries(req.query)) {
        if (!searchParams.has(k)) {
          if (typeof v === "string") {
            searchParams.set(k, v);
          } else if (Array.isArray(v) && typeof v[0] === "string") {
            searchParams.set(k, v[0]);
          }
        }
      }
    }
  } catch {
  }
  const pathPart = parsedUrl.pathname;
  const rawIpath = searchParams.get("__ipath");
  if (rawIpath !== null) {
    searchParams.delete("__ipath");
    let decodedInjected = rawIpath;
    try {
      if (decodedInjected.includes("%")) {
        decodedInjected = decodeURIComponent(decodedInjected);
      }
    } catch {
      decodedInjected = rawIpath;
    }
    const [cleanInjectedPath, embeddedQuery] = decodedInjected.split("?");
    if (embeddedQuery) {
      const embeddedParams = new URLSearchParams(embeddedQuery);
      for (const [ek, ev] of embeddedParams.entries()) {
        if (ek !== "__ipath" && !searchParams.has(ek)) {
          searchParams.set(ek, ev);
        }
      }
    }
    const cleanSubpath = cleanInjectedPath.replace(/^\/+/, "").replace(/^api\/+/i, "");
    const restoredPath = cleanSubpath ? `${API_PREFIX}/${cleanSubpath}` : API_PREFIX;
    applyRestoredUrlAndQuery(req, restoredPath, searchParams);
    return;
  }
  if (pathPart === "/api/index" || pathPart === "/api/index.js") {
    const headerValue3 = req.headers["x-vercel-original-path"] || req.headers["x-original-url"] || req.headers["x-rewrite-url"] || req.headers["x-matched-path"];
    if (headerValue3) {
      const original = headerValue3.startsWith("http") ? new URL(headerValue3).pathname + new URL(headerValue3).search : headerValue3;
      const normalized = original.startsWith("/") ? original : `/${original}`;
      const normQIdx = normalized.indexOf("?");
      const normPath = normQIdx === -1 ? normalized : normalized.slice(0, normQIdx);
      const normQuery = normQIdx === -1 ? "" : normalized.slice(normQIdx + 1);
      const mergedParams = new URLSearchParams(normQuery);
      for (const [k, v] of searchParams.entries()) {
        if (k !== "__ipath" && !mergedParams.has(k)) {
          mergedParams.set(k, v);
        }
      }
      applyRestoredUrlAndQuery(req, normPath, mergedParams);
      return;
    }
  }
  applyRestoredUrlAndQuery(req, pathPart, searchParams);
}
function handler(req, res) {
  try {
    restoreOriginalApiUrl(req);
  } catch {
  }
  server_default(req, res);
}
export {
  handler as default
};

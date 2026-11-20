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

// src/lib/agentRegistry.ts
var DAY = 864e5;
var PREFIX_FEEDS = [
  { sourceId: "mistral-user", url: "https://mistral.ai/robots.txt", format: "none", pinnedKey: "mistral-user", refreshMs: DAY, maxBytes: 2e6 },
  { sourceId: "mistral-index", url: "https://mistral.ai/robots.txt", format: "none", pinnedKey: "mistral-index", refreshMs: DAY, maxBytes: 2e6 },
  { sourceId: "gptbot", url: "https://openai.com/gptbot.json", format: "json", pinnedKey: "gptbot", refreshMs: DAY, maxBytes: 2e6 },
  { sourceId: "chatgpt-user", url: "https://openai.com/chatgpt-user.json", format: "json", pinnedKey: "chatgpt-user", refreshMs: DAY, maxBytes: 4e6 },
  { sourceId: "searchbot", url: "https://openai.com/searchbot.json", format: "json", pinnedKey: "searchbot", refreshMs: DAY, maxBytes: 2e6 },
  { sourceId: "google-common", url: "https://developers.google.com/search/apis/ipranges/googlebot.json", format: "json", pinnedKey: "google-common", refreshMs: DAY, maxBytes: 8e6 },
  { sourceId: "perplexitybot", url: "https://www.perplexity.com/perplexitybot.json", format: "json", pinnedKey: "perplexitybot", refreshMs: DAY, maxBytes: 2e6 },
  { sourceId: "perplexity-user", url: "https://www.perplexity.com/perplexity-user.json", format: "json", pinnedKey: "perplexity-user", refreshMs: DAY, maxBytes: 2e6 },
  { sourceId: "applebot", url: "https://search.developer.apple.com/applebot.json", format: "json", pinnedKey: "applebot", refreshMs: DAY, maxBytes: 2e6 },
  { sourceId: "bingbot", url: "https://www.bing.com/toolbox/bingbot.json", format: "json", pinnedKey: "bingbot", refreshMs: DAY, maxBytes: 2e6 },
  { sourceId: "ccbot", url: "https://index.commoncrawl.org/ccbot.json", format: "json", pinnedKey: "ccbot", refreshMs: DAY, maxBytes: 2e6 },
  { sourceId: "amazonbot", url: "https://developer.amazon.com/amazonbot/ip-addresses/", format: "amazon-html", pinnedKey: "amazonbot", refreshMs: DAY, maxBytes: 4e6 },
  { sourceId: "amzn-search-bot", url: "https://developer.amazon.com/amazonbot/searchbot-ip-addresses/", format: "amazon-html", pinnedKey: "amzn-search-bot", refreshMs: DAY, maxBytes: 4e6 },
  { sourceId: "amzn-user", url: "https://developer.amazon.com/amazonbot/live-ip-addresses/", format: "amazon-html", pinnedKey: "amzn-user", refreshMs: DAY, maxBytes: 4e6 },
  { sourceId: "claude", url: "https://claude.com/crawling/bots.json", format: "json", pinnedKey: "claude", refreshMs: DAY, maxBytes: 2e6 },
  { sourceId: "claude-agent-sail", url: "https://claude.com/.well-known/sail", format: "sail-toml", pinnedKey: "claude-agent-sail", refreshMs: 36e5, maxBytes: 1e6 },
  { sourceId: "manus-wba", url: "https://api.manus.im/.well-known/http-message-signatures-directory", format: "wba-directory", refreshMs: DAY, maxBytes: 1e6 },
  { sourceId: "google-extended", url: "https://developers.google.com/search/docs/crawling-indexing/googlebot", format: "none", refreshMs: DAY, maxBytes: 1e6 },
  { sourceId: "applebot-extended", url: "https://support.apple.com/en-us/119829", format: "none", refreshMs: DAY, maxBytes: 1e6 }
];
var REGISTRY_LITERAL = [
  {
    id: "manus_bot",
    provider: "Manus",
    displayName: "Manus Bot",
    category: "ai_agent",
    bucket: "manus",
    rank: 10,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/Manus-User\/1\.0/i, /ManusAgent/i, /manus-agent/i] },
    signature: {
      wbaRequired: true,
      agentHosts: ["api.manus.im"],
      keyIdNeedles: ["manus"]
    },
    feedIds: ["manus-wba"],
    minProofForVerified: "signed_agent",
    executionMode: "Remote Browser Agent",
    pill: { kind: "manus", label: "Manus" }
  },
  {
    id: "mistral_ai_user",
    provider: "Mistral",
    displayName: "MistralAI-User",
    category: "ai_assistant",
    bucket: "mistral",
    rank: 20,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/MistralAI-User\/1\.0/i] },
    feedIds: ["mistral-user"],
    minProofForVerified: "cidr",
    executionMode: "User-Triggered Fetcher",
    pill: { kind: "mistral", label: "MistralAI-User" }
  },
  {
    id: "mistral_ai_index",
    provider: "Mistral",
    displayName: "MistralAI-Index",
    category: "ai_search",
    bucket: "mistral",
    rank: 30,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/MistralAI-Index\/1\.0/i] },
    feedIds: ["mistral-index"],
    minProofForVerified: "cidr",
    executionMode: "Autonomous Crawler",
    pill: { kind: "mistral", label: "MistralAI-Index" }
  },
  {
    id: "mistral_ai_training",
    provider: "Mistral",
    displayName: "MistralAI-Training",
    category: "ai_crawler",
    bucket: "mistral",
    rank: 40,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/MistralAI-Training\/1\.0/i] },
    // No official CIDR feed: a UA claim alone can never upgrade this agent to verified.
    minProofForVerified: "ua_claim",
    executionMode: "Autonomous Crawler",
    pill: { kind: "mistral", label: "MistralAI-Training" }
  },
  {
    id: "googlebot",
    provider: "Google",
    displayName: "Googlebot",
    category: "search_crawler",
    bucket: "gemini",
    rank: 50,
    which: ["classifier", "robodex", "attribution", "pill"],
    ua: {
      patterns: [/Googlebot\/2\.1/i],
      requireNetworkMatch: true,
      network: /google|googleusercontent/i
    },
    fcrdnsSuffixes: ["googlebot.com", "google.com", "googleusercontent.com"],
    feedIds: ["google-common"],
    minProofForVerified: "fcrdns",
    executionMode: "Autonomous Crawler",
    pill: { kind: "googlebot", label: "Googlebot" }
  },
  {
    id: "applebot",
    provider: "Apple",
    displayName: "Applebot",
    category: "search_crawler",
    bucket: "apple",
    rank: 60,
    which: ["classifier", "robodex", "attribution", "pill"],
    ua: {
      patterns: [/Applebot\/0\.1/i],
      requireNetworkMatch: true,
      network: /apple/i
    },
    fcrdnsSuffixes: ["applebot.apple.com"],
    feedIds: ["applebot"],
    minProofForVerified: "fcrdns",
    executionMode: "Autonomous Crawler",
    pill: { kind: "applebot", label: "Applebot" }
  },
  {
    id: "gptbot",
    provider: "OpenAI",
    displayName: "GPTBot",
    category: "ai_crawler",
    bucket: "openai",
    rank: 70,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/GPTBot\/1\./i, /\bGPTBot\b/i] },
    feedIds: ["gptbot"],
    minProofForVerified: "cidr",
    executionMode: "Autonomous Crawler",
    pill: { kind: "gptbot", label: "GPTBot" }
  },
  {
    id: "chatgpt_user",
    provider: "OpenAI",
    displayName: "ChatGPT-User",
    category: "ai_assistant",
    bucket: "openai",
    rank: 80,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/ChatGPT-User\/1\.0/i] },
    feedIds: ["chatgpt-user"],
    minProofForVerified: "cidr",
    executionMode: "User-Triggered Fetcher",
    pill: { kind: "chatgpt_user", label: "ChatGPT-User" }
  },
  {
    id: "oai_search_bot",
    provider: "OpenAI",
    displayName: "OAI-SearchBot",
    category: "ai_search",
    bucket: "openai",
    rank: 90,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/OAI-SearchBot\/1\./i, /\bOAI-SearchBot\b/i] },
    feedIds: ["searchbot"],
    minProofForVerified: "cidr",
    executionMode: "Autonomous Crawler",
    pill: { kind: "oai_search_bot", label: "OAI-SearchBot" }
  },
  {
    id: "claude_bot",
    provider: "Anthropic",
    displayName: "ClaudeBot",
    category: "ai_crawler",
    bucket: "claude",
    rank: 100,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/\bClaudeBot\b/i] },
    fcrdnsSuffixes: ["anthropic.com", "claude.ai"],
    feedIds: ["claude"],
    minProofForVerified: "cidr",
    executionMode: "Autonomous Crawler",
    pill: { kind: "claude_bot", label: "ClaudeBot" }
  },
  {
    id: "claude_user",
    provider: "Anthropic",
    displayName: "Claude-User",
    category: "ai_assistant",
    bucket: "claude",
    rank: 110,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/Claude-User/i] },
    feedIds: ["claude"],
    minProofForVerified: "cidr",
    executionMode: "User-Triggered Fetcher",
    pill: { kind: "claude_user", label: "Claude-User" }
  },
  {
    id: "claude_search_bot",
    provider: "Anthropic",
    displayName: "Claude-SearchBot",
    category: "ai_search",
    bucket: "claude",
    rank: 120,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/Claude-SearchBot/i] },
    feedIds: ["claude"],
    minProofForVerified: "cidr",
    executionMode: "Autonomous Crawler",
    pill: { kind: "claude_search_bot", label: "Claude-SearchBot" }
  },
  {
    id: "claude_agent",
    provider: "Anthropic",
    displayName: "Claude Agent",
    category: "ai_agent",
    bucket: "claude",
    rank: 130,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/Claude-Agent\/1\.0/i] },
    signature: {
      sail: true,
      agentHosts: ["claude.com"],
      keyIdNeedles: ["claude", "anthropic", "sail"]
    },
    feedIds: ["claude-agent-sail"],
    minProofForVerified: "signed_agent",
    executionMode: "RFC 9421 Signed Agent",
    pill: { kind: "claude", label: "Claude Agent" }
  },
  {
    id: "perplexity_bot",
    provider: "Perplexity",
    displayName: "PerplexityBot",
    category: "ai_search",
    bucket: "perplexity",
    rank: 140,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/PerplexityBot\/1\.0/i, /\bPerplexityBot\b/i] },
    feedIds: ["perplexitybot"],
    minProofForVerified: "cidr",
    executionMode: "Autonomous Crawler",
    pill: { kind: "perplexity_bot", label: "PerplexityBot" }
  },
  {
    id: "perplexity_user",
    provider: "Perplexity",
    displayName: "Perplexity-User",
    category: "ai_assistant",
    bucket: "perplexity",
    rank: 150,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/Perplexity-User\/1\.0/i, /\bPerplexity-User\b/i] },
    feedIds: ["perplexity-user"],
    minProofForVerified: "cidr",
    executionMode: "User-Triggered Fetcher",
    pill: { kind: "perplexity_user", label: "Perplexity-User" }
  },
  {
    id: "amazonbot",
    provider: "Amazon",
    displayName: "Amazonbot",
    category: "ai_crawler",
    bucket: "amazon",
    rank: 160,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/Amazonbot\/0\.1/i, /\bAmazonbot\b/i] },
    feedIds: ["amazonbot"],
    minProofForVerified: "cidr",
    executionMode: "Autonomous Crawler",
    pill: { kind: "amazonbot", label: "Amazonbot" }
  },
  {
    id: "amzn_search_bot",
    provider: "Amazon",
    displayName: "Amzn-SearchBot",
    category: "ai_search",
    bucket: "amazon",
    rank: 170,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/Amzn-SearchBot\/0\.1/i] },
    // Dedicated official sibling feed (searchbot-ip-addresses).
    feedIds: ["amzn-search-bot"],
    minProofForVerified: "cidr",
    executionMode: "Autonomous Crawler",
    pill: { kind: "amazonbot", label: "Amzn-SearchBot" }
  },
  {
    id: "amzn_user",
    provider: "Amazon",
    displayName: "Amzn-User",
    category: "ai_assistant",
    bucket: "amazon",
    rank: 180,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/Amzn-User\/0\.1/i] },
    feedIds: ["amzn-user"],
    minProofForVerified: "cidr",
    executionMode: "User-Triggered Fetcher",
    pill: { kind: "amazonbot", label: "Amzn-User" }
  },
  {
    id: "bingbot",
    provider: "Microsoft",
    displayName: "Bingbot",
    category: "search_crawler",
    bucket: "microsoft",
    rank: 190,
    which: ["classifier", "robodex", "attribution", "pill"],
    ua: {
      patterns: [/bingbot\/2\.0/i, /\bbingbot\b/i],
      requireNetworkMatch: true,
      network: /microsoft|bing|msn/i
    },
    fcrdnsSuffixes: ["search.msn.com"],
    feedIds: ["bingbot"],
    minProofForVerified: "fcrdns",
    executionMode: "Autonomous Crawler",
    pill: { kind: "bingbot", label: "Bingbot" }
  },
  {
    id: "ccbot",
    provider: "Common Crawl",
    displayName: "CCBot",
    category: "ai_crawler",
    bucket: "commoncrawl",
    rank: 200,
    which: ["robodex", "attribution", "pill"],
    ua: { patterns: [/\bCCBot\b/i] },
    feedIds: ["ccbot"],
    minProofForVerified: "cidr",
    executionMode: "Autonomous Crawler",
    pill: { kind: "automation", label: "CCBot" }
  },
  /* ---- Legacy directory agents preserved from the pre-registry bot directory ----
     These were previously detected by BOT_DIRECTORY. Keeping them in the single registry
     avoids losing coverage while adding the newly verified crawler catalog above. */
  {
    id: "chatgpt_agent",
    provider: "OpenAI",
    displayName: "ChatGPT Agent",
    category: "ai_agent",
    bucket: "openai",
    rank: 805,
    which: ["robodex"],
    ua: { patterns: [/ChatGPT-Agent/i] },
    asnPatterns: [/openai|azure/i],
    minProofForVerified: "ua_claim",
    executionMode: "Cloud Browser Agent"
  },
  {
    id: "codex",
    provider: "OpenAI",
    displayName: "Codex",
    category: "ai_agent",
    bucket: "openai",
    rank: 806,
    which: ["robodex"],
    ua: { patterns: [/\bCodex\b/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Coding Agent"
  },
  {
    id: "gemini_deep_research",
    provider: "Google",
    displayName: "Gemini Deep Research",
    category: "ai_agent",
    bucket: "gemini",
    rank: 807,
    which: ["robodex"],
    ua: { patterns: [/Gemini-Deep-Research|GoogleAgent-Mariner|Mariner|Google-Agent/i] },
    asns: [15169, 396982],
    asnPatterns: [/google llc|google cloud/i],
    minProofForVerified: "allowlist",
    executionMode: "User-Triggered Fetcher"
  },
  {
    id: "google_agent",
    provider: "Google",
    displayName: "Google-Agent",
    category: "ai_agent",
    bucket: "gemini",
    rank: 808,
    which: ["robodex"],
    ua: { patterns: [/Google-Agent/i] },
    minProofForVerified: "ua_claim",
    executionMode: "User-Triggered Fetcher"
  },
  {
    id: "google_notebooklm",
    provider: "Google",
    displayName: "Google NotebookLM",
    category: "ai_assistant",
    bucket: "gemini",
    rank: 809,
    which: ["robodex"],
    ua: { patterns: [/NotebookLM/i] },
    minProofForVerified: "ua_claim",
    executionMode: "User-Triggered Fetcher"
  },
  {
    id: "claude_code",
    provider: "Anthropic",
    displayName: "Claude Code",
    category: "ai_agent",
    bucket: "claude",
    rank: 810,
    which: ["robodex"],
    ua: { patterns: [/Claude Code|claude-code/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Coding Agent"
  },
  {
    id: "claude_duet",
    provider: "Anthropic",
    displayName: "Claude Duet",
    category: "ai_agent",
    bucket: "claude",
    rank: 811,
    which: ["robodex"],
    ua: { patterns: [/Claude-Duet|claude-duet/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Cloud Browser Agent"
  },
  {
    id: "meta_muse",
    provider: "Meta",
    displayName: "Muse",
    category: "ai_agent",
    bucket: "muse",
    rank: 812,
    which: ["robodex"],
    ua: { patterns: [/\bMuse\b/i] },
    asns: [32934],
    asnPatterns: [/meta platforms/i],
    minProofForVerified: "allowlist",
    executionMode: "Cloud Browser Agent"
  },
  {
    id: "meta_external_agent",
    provider: "Meta",
    displayName: "Meta-ExternalAgent",
    category: "ai_search",
    bucket: "muse",
    rank: 813,
    which: ["robodex"],
    ua: { patterns: [/Meta-ExternalAgent|meta-externalagent/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Autonomous Crawler"
  },
  {
    id: "meta_web_indexer",
    provider: "Meta",
    displayName: "Meta-WebIndexer",
    category: "ai_search",
    bucket: "muse",
    rank: 814,
    which: ["robodex"],
    ua: { patterns: [/Meta-WebIndexer/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Autonomous Crawler"
  },
  {
    id: "grok_bot",
    provider: "xAI",
    displayName: "Grok Bot",
    category: "ai_agent",
    bucket: "grok",
    rank: 815,
    which: ["robodex"],
    ua: { patterns: [/Grok-Bot|GrokBot|\bgrok\b/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Cloud Browser Agent"
  },
  {
    id: "browserbase_agent",
    provider: "Browserbase",
    displayName: "Browserbase Agent",
    category: "ai_agent",
    bucket: "cloud-browser",
    rank: 816,
    which: ["robodex"],
    ua: { patterns: [/Browserbase/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Cloud Browser Agent"
  },
  {
    id: "bedrock_agentcore",
    provider: "AWS",
    displayName: "Bedrock AgentCore",
    category: "ai_agent",
    bucket: "none",
    rank: 817,
    which: ["robodex"],
    ua: { patterns: [/BedrockAgentCore|bedrock-agent/i] },
    asns: [16509, 14618],
    minProofForVerified: "allowlist",
    executionMode: "Cloud Browser Agent"
  },
  {
    id: "anchor_browser",
    provider: "Anchor",
    displayName: "Anchor Browser",
    category: "ai_browser",
    bucket: "cloud-browser",
    rank: 818,
    which: ["robodex"],
    ua: { patterns: [/AnchorBrowser|anchor-browser/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Cloud Browser Agent"
  },
  {
    id: "notte_browser",
    provider: "Notte",
    displayName: "Notte Browser",
    category: "ai_browser",
    bucket: "cloud-browser",
    rank: 819,
    which: ["robodex"],
    ua: { patterns: [/NotteBrowser|\bnotte\b/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Cloud Browser Agent"
  },
  {
    id: "agi_agent",
    provider: "AGI Inc",
    displayName: "AGI Agent",
    category: "ai_agent",
    bucket: "none",
    rank: 820,
    which: ["robodex"],
    ua: { patterns: [/AGIAgent|agi-agent/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Cloud Browser Agent"
  },
  {
    id: "cursor_agent",
    provider: "Anysphere",
    displayName: "Cursor",
    category: "ai_agent",
    bucket: "none",
    rank: 821,
    which: ["robodex"],
    ua: { patterns: [/\bCursor\b/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Coding Agent"
  },
  {
    id: "duck_assist_bot",
    provider: "DuckDuckGo",
    displayName: "DuckAssistBot",
    category: "ai_assistant",
    bucket: "none",
    rank: 822,
    which: ["robodex"],
    ua: { patterns: [/DuckAssistBot/i] },
    minProofForVerified: "ua_claim",
    executionMode: "User-Triggered Fetcher"
  },
  {
    id: "kimi_user",
    provider: "Moonshot AI",
    displayName: "Kimi-User",
    category: "ai_assistant",
    bucket: "none",
    rank: 823,
    which: ["robodex"],
    ua: { patterns: [/Kimi-User/i] },
    minProofForVerified: "ua_claim",
    executionMode: "User-Triggered Fetcher"
  },
  {
    id: "cloudflare_browser_rendering",
    provider: "Cloudflare",
    displayName: "Cloudflare Browser Rendering",
    category: "browser_automation",
    bucket: "cloud-browser",
    rank: 824,
    which: ["robodex"],
    ua: { patterns: [/CloudflareBot|cf-browser/i] },
    asns: [13335],
    minProofForVerified: "allowlist",
    executionMode: "Cloud Browser Agent"
  },
  {
    id: "instinct",
    provider: "Spear Street Technology",
    displayName: "Instinct",
    category: "ai_agent",
    bucket: "none",
    rank: 825,
    which: ["robodex"],
    ua: { patterns: [/\bInstinct\b/i] },
    minProofForVerified: "ua_claim",
    executionMode: "Cloud Browser Agent"
  },
  {
    // Policy tokens are robots.txt directives, never HTTP user agents. They never visit.
    id: "google_extended",
    provider: "Google",
    displayName: "Google-Extended",
    category: "policy_token",
    bucket: "gemini",
    rank: 900,
    which: [],
    ua: { patterns: [/Google-Extended/i] },
    feedIds: ["google-extended"],
    minProofForVerified: "ua_claim",
    policyToken: true
  },
  {
    id: "applebot_extended",
    provider: "Apple",
    displayName: "Applebot-Extended",
    category: "policy_token",
    bucket: "apple",
    rank: 901,
    which: [],
    ua: { patterns: [/Applebot-Extended/i] },
    feedIds: ["applebot-extended"],
    minProofForVerified: "ua_claim",
    policyToken: true
  }
];
var AGENT_REGISTRY = REGISTRY_LITERAL;
var AGENT_BY_ID = Object.fromEntries(
  AGENT_REGISTRY.map((agent) => [agent.id, agent])
);
var GOOD_BOT_UA_RULES = AGENT_REGISTRY.flatMap((agent) => {
  if (!agent.ua?.requireNetworkMatch) return [];
  return agent.ua.patterns.map((pattern) => ({
    pattern,
    provider: agent.provider,
    label: agent.displayName,
    category: agent.category,
    network: agent.ua?.network
  }));
});
var AI_AGENT_UA_RULES = AGENT_REGISTRY.flatMap((agent) => {
  if (agent.policyToken || !agent.category.startsWith("ai_") && agent.category !== "autonomous_agent" && agent.category !== "browser_automation") {
    return [];
  }
  if (!agent.ua) return [];
  return agent.ua.patterns.map((pattern) => ({
    pattern,
    provider: agent.provider,
    label: agent.displayName
  }));
});
var BOT_SIGNATURE_KEYID_PROVIDERS = AGENT_REGISTRY.flatMap(
  (agent) => (agent.signature?.keyIdNeedles ?? []).map((needle) => [needle, agent.provider])
);
var AI_BOT_CIDR_SOURCES = PREFIX_FEEDS.filter(
  (feed) => feed.format !== "none"
).map((feed) => ({ id: feed.sourceId, url: feed.url }));
var VERIFICATION_SUFFIXES_BY_AGENT = Object.fromEntries(
  AGENT_REGISTRY.filter((agent) => agent.fcrdnsSuffixes).map((agent) => [agent.id, [...agent.fcrdnsSuffixes]])
);
function identityFor(agent) {
  switch (agent.minProofForVerified) {
    case "cidr":
    case "fcrdns":
    case "allowlist":
      return "verified";
    case "rfc9421":
    case "signed_agent":
      return "signed";
    default:
      return "unknown";
  }
}
function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
var BOT_DIRECTORY = AGENT_REGISTRY.filter(
  (agent) => agent.which.includes("robodex")
).map((agent) => {
  const hosts = agent.signature?.agentHosts ?? [];
  const headerPatterns = hosts.length ? [{ header: "signature-agent", pattern: new RegExp(hosts.map(escapeRegExp).join("|"), "i") }] : void 0;
  return {
    name: agent.displayName,
    provider: agent.provider,
    category: agent.category,
    identity: identityFor(agent),
    uaPatterns: agent.ua ? [...agent.ua.patterns] : void 0,
    asnNumbers: agent.asns ? [...agent.asns] : void 0,
    asnPatterns: agent.asnPatterns ? [...agent.asnPatterns] : void 0,
    requiresWebBotAuth: Boolean(agent.signature?.wbaRequired || agent.signature?.sail),
    headerPatterns
  };
});
var PILLS = Object.fromEntries(
  AGENT_REGISTRY.filter((agent) => agent.pill).map((agent) => [
    agent.id,
    {
      kind: agent.pill.kind,
      label: agent.pill.label || agent.displayName,
      provider: agent.provider
    }
  ])
);
var BY_RANK = [...AGENT_REGISTRY].sort((a, b) => a.rank - b.rank);
var POLICY_TOKENS = AGENT_REGISTRY.filter((agent) => agent.policyToken);
function matchesUa(agent, ua) {
  if (!agent.ua) return false;
  for (const pattern of agent.ua.patterns) {
    pattern.lastIndex = 0;
    if (pattern.test(ua)) return true;
  }
  return false;
}
function findAgentByUa(ua) {
  const value = typeof ua === "string" ? ua : "";
  for (const agent of BY_RANK) {
    if (agent.policyToken) continue;
    if (matchesUa(agent, value)) return agent;
  }
  return null;
}
function isPolicyToken(ua) {
  const value = typeof ua === "string" ? ua : "";
  for (const agent of POLICY_TOKENS) {
    if (matchesUa(agent, value)) return true;
  }
  return false;
}
function displayFor(agent, identity) {
  const badge = identity === "verified" ? "Verified" : identity === "signed" ? "Signed" : identity === "spoofed" ? "Spoofed" : "Unverified";
  const name = agent.displayName;
  const provider = agent.provider;
  const label = provider ? `${badge} \xB7 ${name} \xB7 ${provider}` : `${badge} \xB7 ${name}`;
  return { badge, name, provider, label };
}
var MAX_FEED_PREFIXES = 5e3;
var PREFIX_KEYS = /* @__PURE__ */ new Set(["ipv4Prefix", "ipv6Prefix", "prefix", "ip_prefix", "ipv4", "ipv6"]);
function utf8Bytes(body) {
  if (typeof TextEncoder !== "undefined") {
    try {
      return new TextEncoder().encode(body).length;
    } catch {
    }
  }
  return body.length;
}
function isIpv4(value) {
  const parts = value.split(".");
  return parts.length === 4 && parts.every(
    (part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255
  );
}
function isIpv6(value) {
  if (!value.includes(":") || !/^[0-9a-fA-F:.]+$/.test(value)) return false;
  return value.split("::").length <= 2;
}
function normalizePrefix(value) {
  if (typeof value !== "string") return null;
  const text = value.trim();
  if (!text) return null;
  const slash = text.lastIndexOf("/");
  if (slash >= 0) {
    const ip = text.slice(0, slash);
    const maskText = text.slice(slash + 1);
    if (!/^\d{1,3}$/.test(maskText)) return null;
    const mask = Number(maskText);
    if (isIpv4(ip) && mask >= 0 && mask <= 32) return `${ip}/${mask}`;
    if (isIpv6(ip) && mask >= 0 && mask <= 128) return `${ip}/${mask}`;
    return null;
  }
  if (isIpv4(text)) return `${text}/32`;
  if (isIpv6(text)) return `${text}/128`;
  return null;
}
function isSpecialPurpose(prefix) {
  const slash = prefix.lastIndexOf("/");
  const ip = slash >= 0 ? prefix.slice(0, slash) : prefix;
  if (isIpv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 192 && b === 0) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a >= 224) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1") return true;
  if (/^fe[89ab]/.test(lower)) return true;
  if (/^f[cd]/.test(lower)) return true;
  if (/^ff/.test(lower)) return true;
  return false;
}
function isTimestampLike(value) {
  return /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?$/.test(value.trim());
}
function creationTimeFromJson(json) {
  const visited = /* @__PURE__ */ new Set();
  const visit = (node) => {
    if (!node || typeof node !== "object" || visited.has(node)) return null;
    visited.add(node);
    if (Array.isArray(node)) {
      for (const item of node) {
        const found = visit(item);
        if (found) return found;
      }
      return null;
    }
    const record = node;
    for (const key of ["creationTime", "creation_time", "lastModified", "modified"]) {
      const value = record[key];
      if (typeof value === "string" && value && isTimestampLike(value)) return value.trim();
    }
    for (const value of Object.values(record)) {
      const found = visit(value);
      if (found) return found;
    }
    return null;
  };
  return visit(json);
}
function addPrefix(collector, raw) {
  if (collector.list.length >= MAX_FEED_PREFIXES || typeof raw !== "string") return;
  const prefix = normalizePrefix(raw);
  if (prefix && !collector.seen.has(prefix)) {
    collector.seen.add(prefix);
    collector.list.push(prefix);
  }
}
function collectJsonPrefixes(node, collector, visited) {
  if (!node || typeof node !== "object" || visited.has(node)) return;
  if (collector.list.length >= MAX_FEED_PREFIXES) return;
  visited.add(node);
  if (Array.isArray(node)) {
    for (const item of node) {
      if (collector.list.length >= MAX_FEED_PREFIXES) return;
      if (typeof item === "string") addPrefix(collector, item);
      else collectJsonPrefixes(item, collector, visited);
    }
    return;
  }
  for (const [key, value] of Object.entries(node)) {
    if (collector.list.length >= MAX_FEED_PREFIXES) return;
    if (PREFIX_KEYS.has(key) && typeof value === "string") addPrefix(collector, value);
    else collectJsonPrefixes(value, collector, visited);
  }
}
function parseJsonBody(text) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  return JSON.parse(start >= 0 && end > start ? text.slice(start, end + 1) : text);
}
function extractEmbeddedJson(text) {
  const at = text.search(/creationTime/i);
  if (at < 0) return null;
  const start = text.lastIndexOf("{", at);
  if (start < 0) return null;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}
function normalizeFeed(sourceId, body, fetchedAt) {
  const text = typeof body === "string" ? body : "";
  const feed = PREFIX_FEEDS.find((entry) => entry.sourceId === sourceId);
  const format = feed?.format ?? "none";
  const collector = { list: [], seen: /* @__PURE__ */ new Set() };
  let creationTime = null;
  let reason;
  try {
    if (format === "json" || format === "wba-directory") {
      const json = parseJsonBody(text);
      creationTime = creationTimeFromJson(json);
      collectJsonPrefixes(json, collector, /* @__PURE__ */ new Set());
    } else if (format === "amazon-html") {
      const embedded = extractEmbeddedJson(text);
      let parsed = null;
      if (embedded) {
        try {
          parsed = JSON.parse(embedded);
        } catch {
          parsed = null;
        }
      }
      if (parsed) {
        creationTime = creationTimeFromJson(parsed);
        collectJsonPrefixes(parsed, collector, /* @__PURE__ */ new Set());
      }
      if (collector.list.length === 0) {
        for (const token of text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []) addPrefix(collector, token);
      }
    } else if (format === "sail-toml") {
      const modified = text.match(/^\s*modified\s*=\s*["']([^"']+)["']/m);
      if (modified) creationTime = modified[1];
      const lists = text.match(/ipv[46]_prefixes\s*=\s*\[([^\]]*)\]/g) ?? [];
      const local = [];
      let invalid = null;
      for (const list of lists) {
        for (const raw of list.match(/["']([^"']+)["']/g) ?? []) {
          const value = raw.replace(/^["']|["']$/g, "");
          const prefix = normalizePrefix(value);
          if (!prefix || isSpecialPurpose(prefix)) {
            invalid = prefix ?? value;
            continue;
          }
          if (!local.includes(prefix)) local.push(prefix);
        }
      }
      if (invalid) {
        reason = `SAIL document rejected: invalid or special-purpose prefix "${invalid}"`;
      } else {
        for (const prefix of local) addPrefix(collector, prefix);
      }
    }
  } catch (error) {
    reason = reason ?? `feed normalization failed: ${error instanceof Error ? error.message : String(error)}`;
  }
  return {
    prefixes: [...collector.list],
    sourceId,
    fetchedAt: typeof fetchedAt === "number" && Number.isFinite(fetchedAt) ? fetchedAt : Date.now(),
    creationTime,
    bytes: utf8Bytes(text),
    ...reason ? { reason } : {}
  };
}

// src/lib/aiBotDirectory.ts
var BOT_DIRECTORY2 = BOT_DIRECTORY.map((entry) => ({
  ...entry,
  category: entry.category
}));
function detectAiBotFromServerSignals(params) {
  const { userAgent, asnNumber, asnOrg, headers } = params;
  const ua = userAgent || "";
  const signatureAgent = headers["signature-agent"] || "";
  const signatureInput = headers["signature-input"] || "";
  const signature = headers["signature"] || "";
  const hasWebBotAuth = Boolean(signatureAgent && signatureInput && signature);
  const networkKnown = asnNumber !== null || Boolean(asnOrg.trim()) && !/^unknown\b/i.test(asnOrg.trim());
  for (const entry of BOT_DIRECTORY2) {
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
    if (matched && !claimedByUaOrHeader && entry.headerPatterns) {
      for (const { header, pattern } of entry.headerPatterns) {
        const hVal = headers[header] || "";
        if (hVal && pattern.test(hVal)) {
          claimedByUaOrHeader = true;
          break;
        }
      }
    }
    if (matched && !claimedByUaOrHeader) continue;
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
function headerValue2(headers, name) {
  const value = headers[name];
  if (Array.isArray(value)) return value.join(", ");
  return typeof value === "string" ? value : "";
}
function resolveAgentProofMethod(headers, allowlistedAgents = []) {
  const signatureInput = headerValue2(headers, "signature-input");
  const signature = headerValue2(headers, "signature");
  const signatureAgent = headerValue2(headers, "signature-agent");
  const rfc9421 = Boolean(signatureInput && signature && /keyid/i.test(signatureInput));
  if (rfc9421) return "rfc9421";
  if (signatureAgent && signature && signatureInput) return "signed_agent";
  if (allowlistedAgents.length > 0) {
    const ua = headerValue2(headers, "user-agent");
    if (allowlistedAgents.some((agent) => agent && ua.toLowerCase().includes(agent.toLowerCase()))) {
      return "allowlist";
    }
  }
  return "none";
}

// src/shared/normalization/uaNormalizer.ts
var GREASE_RE = /not.?a.?brand/i;
var CHROMIUM_PLACEHOLDER = "chromium";
function splitStructuredList(raw) {
  const parts = [];
  let current = "";
  let inQuotes = false;
  let escaped = false;
  for (const ch of raw) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\" && inQuotes) {
      current += ch;
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      current += ch;
      continue;
    }
    if (ch === "," && !inQuotes) {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts;
}
function parseStructuredMember(member) {
  const text = member.trim();
  if (!text) return null;
  let i = 0;
  let value = "";
  if (text[i] === '"') {
    i += 1;
    let escaped = false;
    let closed = false;
    while (i < text.length) {
      const ch = text[i];
      if (escaped) {
        value += ch;
        escaped = false;
        i += 1;
        continue;
      }
      if (ch === "\\") {
        escaped = true;
        i += 1;
        continue;
      }
      if (ch === '"') {
        closed = true;
        i += 1;
        break;
      }
      value += ch;
      i += 1;
    }
    if (!closed) return null;
  } else {
    while (i < text.length && !/[\s;]/.test(text[i])) {
      value += text[i];
      i += 1;
    }
    if (!value) return null;
  }
  const params = /* @__PURE__ */ new Map();
  while (i < text.length) {
    while (i < text.length && /\s/.test(text[i])) i += 1;
    if (i >= text.length) break;
    if (text[i] !== ";") return null;
    i += 1;
    while (i < text.length && /\s/.test(text[i])) i += 1;
    let key = "";
    while (i < text.length && /[!#$%&'*+\-.^_`|~0-9A-Za-z]/.test(text[i])) {
      key += text[i];
      i += 1;
    }
    if (!key) return null;
    while (i < text.length && /\s/.test(text[i])) i += 1;
    let paramValue = "";
    if (i < text.length && text[i] === "=") {
      i += 1;
      while (i < text.length && /\s/.test(text[i])) i += 1;
      if (text[i] === '"') {
        i += 1;
        let escaped = false;
        let closed = false;
        while (i < text.length) {
          const ch = text[i];
          if (escaped) {
            paramValue += ch;
            escaped = false;
            i += 1;
            continue;
          }
          if (ch === "\\") {
            escaped = true;
            i += 1;
            continue;
          }
          if (ch === '"') {
            closed = true;
            i += 1;
            break;
          }
          paramValue += ch;
          i += 1;
        }
        if (!closed) return null;
      } else {
        while (i < text.length && !/[\s;]/.test(text[i])) {
          paramValue += text[i];
          i += 1;
        }
      }
    }
    params.set(key.toLowerCase(), paramValue);
  }
  return { value, params };
}
function parseBrandList(raw) {
  const out = [];
  if (typeof raw !== "string" || !raw.trim()) return out;
  for (const member of splitStructuredList(raw)) {
    const parsed = parseStructuredMember(member);
    if (!parsed) continue;
    const brand = parsed.value.trim();
    if (!brand) continue;
    const entry = { brand, version: (parsed.params.get("v") ?? "").trim() };
    if (brand.toLowerCase() === "headlesschrome") entry.is_headless_brand = true;
    out.push(entry);
  }
  return out;
}
function filterBrands(brands) {
  const real = brands.filter((b) => !GREASE_RE.test(b.brand));
  const nonChromium = real.filter((b) => b.brand.toLowerCase() !== CHROMIUM_PLACEHOLDER);
  return nonChromium.length > 0 ? nonChromium : real;
}
function headerValue3(secCh, name) {
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
function unquote(value) {
  const v = value.trim();
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) return v.slice(1, -1);
  return v;
}
function parseSecCh(secCh) {
  const fullListRaw = headerValue3(secCh, "sec-ch-ua-full-version-list");
  const majorListRaw = headerValue3(secCh, "sec-ch-ua");
  const brands = fullListRaw ? parseBrandList(fullListRaw) : parseBrandList(majorListRaw);
  return {
    brands: filterBrands(brands),
    hasFullVersionList: Boolean(fullListRaw),
    platform: unquote(headerValue3(secCh, "sec-ch-ua-platform")),
    platformVersion: unquote(headerValue3(secCh, "sec-ch-ua-platform-version")),
    model: unquote(headerValue3(secCh, "sec-ch-ua-model")),
    architecture: unquote(headerValue3(secCh, "sec-ch-ua-arch")),
    bitness: unquote(headerValue3(secCh, "sec-ch-ua-bitness")),
    formFactors: unquote(headerValue3(secCh, "sec-ch-ua-form-factors")).split(",").map((f) => unquote(f)).filter((f) => f.length > 0)
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
var BRAND_PRECEDENCE = [
  "Headless Chrome",
  "Microsoft Edge",
  "Brave",
  "Opera",
  "Google Chrome",
  "Chromium",
  "Cursor",
  "Manus",
  "Samsung Internet",
  "Firefox",
  "Safari"
];
function brandToSpec(brands) {
  const matched = BROWSER_SPECS.filter(
    (spec) => brands.some((entry) => spec.brands.indexOf(entry.brand.toLowerCase()) !== -1)
  );
  if (matched.length === 0) return null;
  matched.sort((a, b) => {
    const ai = BRAND_PRECEDENCE.indexOf(a.name);
    const bi = BRAND_PRECEDENCE.indexOf(b.name);
    return (ai < 0 ? 999 : ai) - (bi < 0 ? 999 : bi);
  });
  return matched[0];
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
    const headlessBrand = Boolean(entry?.is_headless_brand) || spec.name === "Headless Chrome";
    let version = entry ? entry.version : "";
    if (version && version.indexOf(".") === -1) {
      version = pickFullerVersion(version, findUaVersion(spec, ua));
    }
    if (!version) version = findUaVersion(spec, ua) ?? "";
    return { name: spec.name, full: version, major: majorOf(version), is_headless_brand: headlessBrand };
  }
  const uaSpec = ua ? uaToSpec(ua) : null;
  if (uaSpec) {
    const version = findUaVersion(uaSpec, ua) ?? "";
    return {
      name: uaSpec.name,
      full: version,
      major: majorOf(version),
      is_headless_brand: uaSpec.name === "Headless Chrome"
    };
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
    if (browser.is_headless_brand) identity.is_headless_brand = true;
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
  if (typeof structured === "string") return unquote(structured);
  const headerKey = `sec-ch-ua-${name.replace(/([A-Z])/g, "-$1").toLowerCase()}`;
  return unquote(readBagKey(hints, headerKey));
}
function brandsFromValue(value) {
  if (Array.isArray(value)) {
    return value.filter((entry) => Boolean(entry) && typeof entry.brand === "string").map((entry) => ({ brand: entry.brand, version: String(entry.version ?? "") }));
  }
  if (typeof value === "string") return parseBrandList(value);
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
      model: identity.device_model,
      is_headless_brand: identity.is_headless_brand
    };
  } catch {
    return { ...BLANK_USER_AGENT };
  }
}

// src/server/middleware/clientHints.ts
var CLIENT_HINT_ACCEPT_CH = "Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-Form-Factors";
var CLIENT_HINT_CRITICAL_CH = "Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version";
var CLIENT_HINT_VARY = "Sec-CH-UA*";
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
function unquote2(value) {
  let text = value.trim();
  if (text.length >= 2) {
    const first = text[0];
    const last = text[text.length - 1];
    if (first === '"' && last === '"' || first === "'" && last === "'") text = text.slice(1, -1);
  }
  return text.trim();
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
      platform: unquote2(readHeaderValue(bag, "sec-ch-ua-platform")),
      platformVersion: unquote2(readHeaderValue(bag, "sec-ch-ua-platform-version")),
      architecture: unquote2(readHeaderValue(bag, "sec-ch-ua-arch")),
      bitness: unquote2(readHeaderValue(bag, "sec-ch-ua-bitness")),
      model: unquote2(readHeaderValue(bag, "sec-ch-ua-model")),
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
    if (!res.getHeader("Vary")) res.setHeader("Vary", CLIENT_HINT_VARY);
    req.intelClientHints = parseClientHintHeaders(req.headers);
  } catch {
  }
  next();
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
function subnetOf(ip) {
  const text = String(ip ?? "").trim();
  const ipv4 = parseIpv4(text);
  if (ipv4 !== null) {
    const octets = [
      ipv4 >>> 24 & 255,
      ipv4 >>> 16 & 255,
      ipv4 >>> 8 & 255,
      ipv4 & 255
    ];
    return `${octets[0]}.${octets[1]}.${octets[2]}/24`;
  }
  const groups = expandIpv6Groups(text);
  if (!groups) return "";
  const firstFour = groups.slice(0, 4).map((value) => value.toString(16)).join(":");
  return `${firstFour}::/64`;
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
  if (gpuText && osFamily) {
    keys.add(`block_gpu:${hexHash(gpuText)}:${osFamily}`);
  }
  const net2 = networkBucket(profile.net);
  if (net2 !== "unknown") {
    keys.add(`block_net:${net2}`);
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
    matched_visitor_id: null,
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
            matched_visitor_id: storageVisitorId,
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
        matched_visitor_id: best.id,
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
      matched_visitor_id: null,
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

// src/lib/telemetryContract.ts
var RISK_FAMILY_CAPS = {
  automation: 45,
  tampering: 35,
  network: 25,
  environment: 10,
  velocity: 15
};
var RISK_RUBRIC = {
  automation: {
    tier_a_hard_proof: 45,
    tier_b_corroborated_stealth: 35,
    none_or_passive: 0
  },
  tampering: {
    tier_a_spec_header_or_drift: 35,
    tier_b_prototype_or_getter: 30,
    soft_warning: 15,
    none_or_privacy_hardened: 0
  },
  network: {
    hosting_datacenter_asn: 10,
    commercial_vpn_or_relay: 12,
    rotating_or_residential_proxy: 18,
    timezone_mismatch_standalone: 5,
    timezone_mismatch_marginal: 2
  },
  environment: {
    swiftshader_software_renderer: 8,
    ephemeral_or_private_storage: 4
  },
  velocity: {
    high_activity: 12,
    extreme_rotation: 15
  }
};
function riskTier(score) {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Elevated";
  return "Low";
}
function buildRiskLedger(lines) {
  const totals = {
    automation: 0,
    tampering: 0,
    network: 0,
    environment: 0,
    velocity: 0
  };
  for (const line of lines) {
    const safe = Number.isFinite(line.points) ? Math.max(0, line.points) : 0;
    totals[line.family] = Math.min(RISK_FAMILY_CAPS[line.family], totals[line.family] + safe);
  }
  const rawScore = Object.values(totals).reduce((sum, value) => sum + value, 0);
  const score = Math.min(100, Math.round(rawScore));
  return {
    ...totals,
    raw_score: Math.round(rawScore),
    score_0_100: score,
    tier: riskTier(score),
    evidence_ledger: lines.map((line) => ({ ...line }))
  };
}
var LSH_CONFIG = {
  bits: 512,
  bands: 32,
  rows: 16,
  expected_random_similarity: 0.5
};
var LSH_WRITE_POLICY = {
  write_on_hardware_anchor_change_only: true,
  without_rowid: true,
  primary_key: ["band_idx", "band_hash", "hardware_id"]
};
function clopperPearsonUpperBound(k, n, alpha = 0.05) {
  if (n <= 0) return 1;
  const successes = Math.max(0, Math.min(n, Math.floor(k)));
  const cdf = (p) => {
    if (p <= 0) return 0;
    if (p >= 1) return 1;
    let term = Math.exp(n * Math.log1p(-p));
    let sum = term;
    for (let i = 1; i <= successes; i += 1) {
      term *= (n - i + 1) / i * (p / (1 - p));
      sum += term;
      if (sum > 1) return 1;
    }
    return Math.min(1, sum);
  };
  let low = 0;
  let high = 1;
  for (let i = 0; i < 80; i += 1) {
    const mid = (low + high) / 2;
    if (cdf(mid) > alpha) low = mid;
    else high = mid;
  }
  return (low + high) / 2;
}
function decideRarity(corpusN, observedCount = 1) {
  const n = Math.max(0, Math.floor(corpusN));
  const upper = clopperPearsonUpperBound(observedCount, n, 0.05);
  if (n < 250) return { status: "suppressed", percentile: null, corpus_n: n, prevalence_ci95_upper: upper };
  if (n >= 1e3 && upper <= 0.01) {
    return { status: "published", percentile: "p99_plus", corpus_n: n, prevalence_ci95_upper: upper };
  }
  if (upper <= 0.05) {
    return { status: "published", percentile: "p95", corpus_n: n, prevalence_ci95_upper: upper };
  }
  return { status: "insufficient", percentile: null, corpus_n: n, prevalence_ci95_upper: upper };
}
function isSecureRequest(input) {
  if (input.secure === true) return true;
  if (typeof input.xForwardedProto === "string" && input.xForwardedProto.split(",")[0].trim().toLowerCase() === "https") {
    return true;
  }
  if (typeof input.cfVisitor === "string" && /"scheme"\s*:\s*"https"/i.test(input.cfVisitor)) {
    return true;
  }
  return false;
}
var ENVELOPE_MAX_AGE_MS = 65e3;
var ENVELOPE_MAX_FUTURE_SKEW_MS = 3e5;

// src/lib/specInvariants.ts
function isPrivacyHardenedUserAgent(userAgent) {
  const ua = String(userAgent || "").toLowerCase();
  if (!ua) return false;
  if (/\btor\b|tor browser/.test(ua)) return true;
  if (/\bbrave\b|bravechrom/.test(ua)) return true;
  if (/firefox/.test(ua) && /fpp|rfp|resistfingerprinting/.test(ua)) return true;
  if (/safari/.test(ua) && /atfp|advanced.*fingerprint|version\/26/.test(ua)) return true;
  return false;
}
function resolvePrivacyHardened(ctx = {}) {
  return Boolean(
    ctx.privacyHardened || ctx.firefoxFpp || ctx.resistFingerprinting || ctx.safariAtfp || ctx.torBrowser || ctx.braveShields || isPrivacyHardenedUserAgent(ctx.userAgent || "")
  );
}
function isSwiftShaderRenderer(renderer) {
  return /swiftshader|subzero|0x0000c0de|llvmpipe|mesa offscreen|software rasterizer/i.test(
    String(renderer || "")
  );
}
var DEVICE_MEMORY_DOMAIN = [0.25, 0.5, 1, 2, 4, 8, 16, 32];
function checkDeviceMemory(value, context = {}) {
  if (value === null || value === void 0) return [];
  if (!Number.isFinite(value) || !DEVICE_MEMORY_DOMAIN.includes(value)) {
    return [
      {
        id: "spec.device_memory.domain",
        severity: context.privacyHardened ? "soft" : "hard",
        detail: `navigator.deviceMemory ${String(value)} is outside the power-of-two domain {0.25,0.5,1,2,4,8,16,32}`
      }
    ];
  }
  return [];
}
function checkNetworkRtt(rtt, context = {}) {
  if (rtt === null || rtt === void 0) return [];
  if (!Number.isFinite(rtt) || rtt < 0) {
    return [
      { id: "spec.network_information.rtt_domain", severity: "hard", detail: `rtt ${String(rtt)} is not a finite non-negative number` }
    ];
  }
  if (rtt === 0) return [];
  if (Math.abs(rtt % 25) > 1e-9) {
    return [
      {
        id: "spec.network_information.rtt_quantization",
        severity: context.privacyHardened ? "soft" : "hard",
        detail: `rtt ${rtt} is not a multiple of 25`
      }
    ];
  }
  return [];
}
function checkBatteryManager(battery) {
  if (!battery) return [];
  const charging = battery.charging;
  const hasChargingTime = Number.isFinite(battery.chargingTime);
  const hasDischargingTime = Number.isFinite(battery.dischargingTime);
  const violations = [];
  if (hasChargingTime && hasDischargingTime) {
    violations.push({
      id: "spec.battery_manager.mutual_exclusion",
      severity: "hard",
      detail: "chargingTime and dischargingTime are both finite"
    });
  }
  if (charging === true && hasDischargingTime) {
    violations.push({
      id: "spec.battery_manager.charging_state",
      severity: "hard",
      detail: "a charging battery cannot report a finite dischargingTime"
    });
  }
  if (charging === false && hasChargingTime) {
    violations.push({
      id: "spec.battery_manager.discharging_state",
      severity: "hard",
      detail: "a discharging battery cannot report a finite chargingTime"
    });
  }
  return violations;
}
function checkJsHeapSizeLimit(observed, expected) {
  if (!observed || !expected || !Number.isFinite(observed) || !Number.isFinite(expected)) return [];
  const deviation = Math.abs(observed - expected) / Math.max(1, expected);
  if (deviation > 0.01) {
    return [
      {
        id: "spec.v8.js_heap_size_limit",
        severity: "soft",
        detail: `performance.memory.jsHeapSizeLimit deviates ${(deviation * 100).toFixed(2)}% from the V8 lattice (soft warning only)`
      }
    ];
  }
  return [];
}
function classifyWebglBackend(renderer) {
  const text = String(renderer || "").toLowerCase();
  if (/swiftshader|subzero|0x0000c0de/.test(text)) return "swiftshader";
  if (/direct3d|d3d11|d3d12|\bd3d\b/.test(text)) return "direct3d";
  if (/metal/.test(text)) return "metal";
  if (/mesa|llvmpipe/.test(text)) return "mesa";
  if (/vulkan/.test(text)) return "vulkan";
  return "unknown";
}
function checkWebglBackendAgainstOs(renderer, osFamily, context = {}) {
  const backend = classifyWebglBackend(renderer);
  const os2 = String(osFamily || "").toLowerCase();
  if (backend === "swiftshader" || backend === "vulkan" || backend === "unknown") return [];
  const osMatches = backend === "direct3d" && /windows|win32|win64/.test(os2) || backend === "metal" && /macos|mac os|ios|ipad|iphone/.test(os2) || backend === "mesa" && /linux|ubuntu|fedora|debian|chrome ?os/.test(os2);
  if (!osMatches) {
    return [
      {
        id: "spec.webgl.backend_os_mismatch",
        severity: context.privacyHardened ? "soft" : "hard",
        detail: `WebGL backend ${backend} is inconsistent with OS ${osFamily || "unknown"}`
      }
    ];
  }
  return [];
}
function checkPdfPluginFace(deviceKind, hasPdfFace) {
  if (deviceKind === "unknown" || hasPdfFace === null || hasPdfFace === void 0) return [];
  const desktopWithoutPdf = deviceKind === "pc" && hasPdfFace === false;
  const mobileWithPdf = (deviceKind === "mobile" || deviceKind === "tablet") && hasPdfFace === true;
  if (desktopWithoutPdf || mobileWithPdf) {
    return [
      {
        id: "spec.pdf_plugin.face",
        severity: "soft",
        detail: `PDF plugin face (${hasPdfFace}) disagrees with device kind ${deviceKind}`
      }
    ];
  }
  return [];
}
function checkHttpUaChReconciliation(transport, context = {}) {
  const http = String(transport.httpPlatform || "").toLowerCase();
  const js = String(transport.jsPlatform || "").toLowerCase();
  if (!http || !js) return [];
  const family = (value) => {
    if (/win/.test(value)) return "windows";
    if (/mac|iphone|ipad|ipod/.test(value)) return "apple";
    if (/android/.test(value)) return "android";
    if (/linux|cros|chrome ?os/.test(value)) return "linux";
    return "";
  };
  const httpFamily = family(http);
  const jsFamily = family(js);
  if (httpFamily && jsFamily && httpFamily !== jsFamily) {
    return [
      {
        id: "spec.transport.platform_reconciliation",
        severity: context.privacyHardened ? "soft" : "hard",
        detail: `HTTP/UA-CH platform ${http} disagrees with JS platform ${js}`
      }
    ];
  }
  return [];
}
function checkHardwareDrift(current, previous, context = {}) {
  if (context.privacyHardened) return [];
  const violations = [];
  const compare = (key, label) => {
    const a = current[key];
    const b = previous[key];
    if (a === void 0 || b === void 0 || a === null || b === null) return;
    if (String(a) !== String(b)) {
      violations.push({
        id: `spec.hardware_drift.${label}`,
        severity: "hard",
        detail: `${label} drifted from ${String(b)} to ${String(a)} across loads`
      });
    }
  };
  compare("gpu", "gpu");
  compare("cpuCores", "cpuCores");
  compare("memoryGb", "memoryGb");
  compare("screen", "screen");
  compare("platform", "platform");
  return violations;
}
function evaluateSpecInvariants(input = {}) {
  const privacyHardened = resolvePrivacyHardened(input);
  const softwareRenderer = isSwiftShaderRenderer(input.webglRenderer || "");
  const violations = [
    ...checkDeviceMemory(input.deviceMemoryGb, { privacyHardened }),
    ...checkNetworkRtt(input.networkRtt, { privacyHardened }),
    ...checkBatteryManager(input.battery),
    ...checkJsHeapSizeLimit(input.jsHeapSizeLimit, input.expectedJsHeapSizeLimit),
    ...checkWebglBackendAgainstOs(input.webglRenderer || "", input.osFamily || "", { privacyHardened }),
    ...checkPdfPluginFace(input.deviceKind || "unknown", input.hasPdfFace),
    ...checkHttpUaChReconciliation(input.transport || {}, { privacyHardened }),
    ...checkHardwareDrift(input.currentHardware || {}, input.previousHardware || {}, { privacyHardened })
  ];
  const hard = violations.filter((v) => v.severity === "hard");
  const soft = violations.filter((v) => v.severity === "soft");
  return {
    violations,
    reasons: violations.map((v) => v.detail),
    hardViolations: hard.map((v) => v.id),
    softViolations: soft.map((v) => v.id),
    hard_spec_violation: hard.length > 0,
    privacy_hardened: privacyHardened,
    software_renderer: softwareRenderer
  };
}
function enforceTamperingInvariant(input) {
  const privacy = Boolean(input.privacy_hardened);
  const swiftshader = Boolean(input.software_renderer);
  const rawReasons = (input.reasons || []).filter((r) => typeof r === "string" && r.trim());
  const reasons = rawReasons.filter((reason) => {
    if (privacy && /privacy|rfp|fpp|brave|tor|atfp|fingerprint.?protection/i.test(reason)) return false;
    if (swiftshader && /swiftshader|software.?render|llvmpipe|mesa offscreen/i.test(reason)) return false;
    return true;
  });
  const hard_spec_violation = Boolean(input.hard_spec_violation) && !privacy;
  const detected = reasons.length > 0 || hard_spec_violation;
  return { detected, reasons, hard_spec_violation, privacy_hardened: privacy };
}
function classifyInspectorState(signals = {}) {
  if (signals.cdpAttached) return "automation_protocol_attached";
  if (signals.devtoolsActiveVerified) return "devtools_active_verified";
  if (signals.viewportContractionNormalized) return "devtools_docked_suspected";
  return "closed";
}
function inspectorFlagsForState(state) {
  return {
    cdp_attached: state === "automation_protocol_attached",
    developer_tools: state === "devtools_docked_suspected" || state === "devtools_active_verified"
  };
}

// src/lib/riskLedger.ts
function buildGradedRiskLedger(input = {}) {
  const lines = [];
  const push = (family, component, points, reason) => {
    if (points > 0) lines.push({ family, component, points, reason });
  };
  const auto = input.automation || {};
  if (!auto.rfc9421SignedAgent) {
    if (auto.tierA) {
      push("automation", "automation.tier_a_hard_proof", RISK_RUBRIC.automation.tier_a_hard_proof, "hard automation proof");
    } else if (auto.tierB) {
      push("automation", "automation.tier_b_corroborated_stealth", RISK_RUBRIC.automation.tier_b_corroborated_stealth, "corroborated stealth");
    } else {
      push("automation", "automation.none_or_passive", RISK_RUBRIC.automation.none_or_passive, "no automation evidence");
    }
  }
  const tamper = input.tampering || {};
  if (!tamper.privacyHardened) {
    if (tamper.tierA) {
      push("tampering", "tampering.tier_a_spec_header_or_drift", RISK_RUBRIC.tampering.tier_a_spec_header_or_drift, "hard spec/header/drift violation");
    } else if (tamper.tierB) {
      push("tampering", "tampering.tier_b_prototype_or_getter", RISK_RUBRIC.tampering.tier_b_prototype_or_getter, "prototype/getter tampering");
    } else if (tamper.soft) {
      push("tampering", "tampering.soft_warning", RISK_RUBRIC.tampering.soft_warning, "soft spec warning");
    }
  }
  const net2 = input.network || {};
  if (net2.hostingDatacenter && !net2.hostingAlreadyBilled) {
    push("network", "network.hosting_datacenter_asn", RISK_RUBRIC.network.hosting_datacenter_asn, "hosting/datacenter ASN");
  }
  if (net2.vpnOrRelay) {
    push("network", "network.commercial_vpn_or_relay", RISK_RUBRIC.network.commercial_vpn_or_relay, "commercial VPN / relay");
  }
  if (net2.rotatingProxy) {
    push("network", "network.rotating_or_residential_proxy", RISK_RUBRIC.network.rotating_or_residential_proxy, "rotating / residential proxy");
  }
  if (net2.timezoneMismatch) {
    const otherFired = net2.otherComponentFired || Boolean(net2.hostingDatacenter) || Boolean(net2.vpnOrRelay) || Boolean(net2.rotatingProxy);
    push(
      "network",
      otherFired ? "network.timezone_mismatch_marginal" : "network.timezone_mismatch_standalone",
      otherFired ? RISK_RUBRIC.network.timezone_mismatch_marginal : RISK_RUBRIC.network.timezone_mismatch_standalone,
      otherFired ? "timezone mismatch (marginal)" : "timezone mismatch (standalone)"
    );
  }
  const env = input.environment || {};
  if (env.swiftshader) {
    push("environment", "environment.swiftshader_software_renderer", RISK_RUBRIC.environment.swiftshader_software_renderer, "SwiftShader software renderer");
  }
  if (env.ephemeralOrPrivateStorage) {
    push("environment", "environment.ephemeral_or_private_storage", RISK_RUBRIC.environment.ephemeral_or_private_storage, "ephemeral / private storage");
  }
  const vel = input.velocity || {};
  if (vel.extreme) {
    push("velocity", "velocity.extreme_rotation", RISK_RUBRIC.velocity.extreme_rotation, "extreme identity rotation");
  } else if (vel.high) {
    push("velocity", "velocity.high_activity", RISK_RUBRIC.velocity.high_activity, "high activity device");
  }
  return buildRiskLedger(lines);
}
var GRADED_RISK_FIXTURES = [
  {
    name: "MCP Playwright",
    input: {
      automation: { tierA: true },
      network: { vpnOrRelay: true },
      environment: { swiftshader: true, ephemeralOrPrivateStorage: true }
    },
    expected: [45, 0, 12, 10, 0]
  },
  {
    name: "spec fuzz",
    input: { tampering: { tierA: true } },
    expected: [0, 35, 0, 0, 0]
  },
  {
    name: "drift + proxy + velocity",
    input: {
      automation: { tierB: true },
      tampering: { tierA: true },
      network: { rotatingProxy: true },
      environment: { ephemeralOrPrivateStorage: true },
      velocity: { high: true }
    },
    expected: [35, 35, 18, 4, 12]
  },
  {
    name: "clean human",
    input: {},
    expected: [0, 0, 0, 0, 0]
  }
];
function verifyGradedRiskFixtures() {
  return GRADED_RISK_FIXTURES.map((fixture) => {
    const ledger = buildGradedRiskLedger(fixture.input);
    const actual = [
      ledger.automation,
      ledger.tampering,
      ledger.network,
      ledger.environment,
      ledger.velocity
    ];
    const ok = actual.every((value, index) => value === fixture.expected[index]);
    return { name: fixture.name, ok, ledger, expected: fixture.expected };
  });
}

// src/lib/rarityHonesty.ts
function computeHonestRarity(corpusN, observedCount = 1) {
  const decision = decideRarity(corpusN, observedCount);
  return {
    ...decision,
    corpus_n: decision.corpus_n,
    prevalence_ci95_upper: decision.prevalence_ci95_upper,
    score_contribution: decision.status === "published" ? 1 : 0
  };
}
function computeHonestProximity(input = {}) {
  const permission = String(input.permission || "").toLowerCase();
  if (permission !== "granted" || !input.grantedCoordinates) {
    return { status: permission === "denied" ? "unavailable" : "permission_required" };
  }
  const result = { status: "granted" };
  if (typeof input.accuracyM === "number" && Number.isFinite(input.accuracyM)) {
    result.accuracy_m = input.accuracyM;
  }
  result.coordinates = input.grantedCoordinates;
  return result;
}
var CALIBRATION_MIN_LABELED_PAIRS = 200;
var CALIBRATION_MAX_ECE = 0.05;
var TIER_BY_STAGE = {
  storage_continuity: "First-Party Continuity Match",
  exact_hardware: "High-Agreement Hardware Match",
  lsh_fuzzy: "Probabilistic Fuzzy Match",
  privacy_hardened: "Privacy-Hardened Profile (Reduced Entropy)",
  new_enrollment: "New Unobserved Profile"
};
function computeHonestIdentityConfidence(input) {
  const confidence_tier = TIER_BY_STAGE[input.matchStage] || "New Unobserved Profile";
  const calibrated = input.labeledPairs >= CALIBRATION_MIN_LABELED_PAIRS && Number.isFinite(input.heldOutEce) && input.heldOutEce < CALIBRATION_MAX_ECE;
  if (!calibrated) {
    return { confidence_score: null, confidence_tier, calibration_status: "uncalibrated" };
  }
  const raw = typeof input.calibratedScore === "number" && Number.isFinite(input.calibratedScore) ? input.calibratedScore : null;
  return {
    confidence_score: raw === null ? null : Math.max(0, Math.min(1, raw)),
    confidence_tier,
    calibration_status: "calibrated"
  };
}

// src/lib/identityEngine.ts
var MASK64 = (1n << 64n) - 1n;
var FNV_OFFSET = 0xcbf29ce484222325n;
var FNV_PRIME = 0x100000001b3n;
var SEEDS = [
  0x9e3779b97f4a7c15n,
  0xbf58476d1ce4e5b9n,
  0x94d049bb133111ebn,
  0x7f4a7c15bf58476dn,
  0x2545f4914f6cdd1dn,
  0xd6e8feb86659fd93n,
  0x9e3779b185ebca87n,
  0xa0761d6478bd642fn
];
function fnv64(input, seed) {
  let h = (FNV_OFFSET ^ seed) & MASK64;
  for (let i = 0; i < input.length; i += 1) {
    h ^= BigInt(input.charCodeAt(i));
    h = h * FNV_PRIME & MASK64;
  }
  return h;
}
function tokenWords(token) {
  return SEEDS.map((seed) => fnv64(token, seed));
}
function simhash512(features) {
  const tokens = [];
  if (typeof features === "string") {
    if (features) tokens.push(features);
  } else {
    for (const key of Object.keys(features || {}).sort()) {
      const value = features[key];
      if (value === null || value === void 0) continue;
      tokens.push(`${key}=${typeof value === "object" ? JSON.stringify(value) : String(value)}`);
    }
  }
  const weights = new Array(LSH_CONFIG.bits).fill(0);
  for (const token of tokens) {
    const words = tokenWords(token);
    for (let w = 0; w < 8; w += 1) {
      const word = words[w];
      for (let bit = 0; bit < 64; bit += 1) {
        const idx = w * 64 + bit;
        weights[idx] += word >> BigInt(bit) & 1n ? 1 : -1;
      }
    }
  }
  let result = 0n;
  for (let i = LSH_CONFIG.bits - 1; i >= 0; i -= 1) {
    result <<= 1n;
    if (weights[i] >= 0) result |= 1n;
  }
  return result & (1n << BigInt(LSH_CONFIG.bits)) - 1n;
}
function simhashToHex(hash) {
  return (hash & (1n << BigInt(LSH_CONFIG.bits)) - 1n).toString(16).padStart(LSH_CONFIG.bits / 4, "0");
}
function hammingSimilarity512(a, b) {
  let diff = (a ^ b) & (1n << BigInt(LSH_CONFIG.bits)) - 1n;
  let distance = 0;
  while (diff) {
    distance += Number(diff & 1n);
    diff >>= 1n;
  }
  return 1 - distance / LSH_CONFIG.bits;
}
function bandHashes(hash) {
  const bands = [];
  for (let idx = 0; idx < LSH_CONFIG.bands; idx += 1) {
    const slice = hash >> BigInt(idx * LSH_CONFIG.rows) & (1n << BigInt(LSH_CONFIG.rows)) - 1n;
    bands.push({ band_idx: idx, band_hash: slice.toString(16).padStart(LSH_CONFIG.rows / 4, "0") });
  }
  return bands;
}
var LSH_THRESHOLDS = {
  minSimilarity: 0.88,
  minMargin: 0.1,
  maxCollisionDensity: 2
};
function decideLshFuzzyMatch(input) {
  const candidates = (input.candidates || []).slice();
  const candidateCount = candidates.length;
  if (candidateCount === 0) {
    return {
      match: false,
      bestHardwareId: null,
      bestVisitorId: null,
      similarity: 0,
      margin: 0,
      collisionDensity: 0,
      candidateCount,
      reason: "no LSH candidates retrieved",
      stage: "new_enrollment"
    };
  }
  const scored = candidates.map((candidate) => ({ candidate, similarity: hammingSimilarity512(input.query, candidate.simhash) })).sort((a, b) => b.similarity - a.similarity);
  const best = scored[0];
  const runnerUp = scored.length > 1 ? scored[1].similarity : 0;
  const margin = best.similarity - runnerUp;
  const collisionDensity = scored.filter((entry) => entry.candidate.simhash === best.candidate.simhash).length;
  let reason = "accepted";
  let match = true;
  if (best.similarity < LSH_THRESHOLDS.minSimilarity) {
    match = false;
    reason = `similarity ${best.similarity.toFixed(4)} < ${LSH_THRESHOLDS.minSimilarity}`;
  } else if (margin < LSH_THRESHOLDS.minMargin && scored.length > 1) {
    match = false;
    reason = `margin ${margin.toFixed(4)} < ${LSH_THRESHOLDS.minMargin}`;
  } else if (collisionDensity >= LSH_THRESHOLDS.maxCollisionDensity) {
    match = false;
    reason = `collision density ${collisionDensity} >= ${LSH_THRESHOLDS.maxCollisionDensity}`;
  }
  return {
    match,
    bestHardwareId: match ? best.candidate.hardwareId : null,
    bestVisitorId: match ? best.candidate.visitorId || best.candidate.hardwareId : null,
    similarity: best.similarity,
    margin,
    collisionDensity,
    candidateCount,
    reason,
    stage: match ? "lsh_fuzzy" : "new_enrollment"
  };
}
function structuralAnchorFeatures(anchor) {
  return {
    canvas_coarse: (anchor.canvasCoarseHash || "").trim() || "na",
    arch: (anchor.architecture || "").trim() || "na",
    gpu_vendor: (anchor.gpuVendor || "").trim() || "na",
    gpu_renderer: (anchor.gpuRenderer || "").trim() || "na"
  };
}
function structuralAnchorHash(anchor) {
  return simhash512(structuralAnchorFeatures(anchor));
}
function resolveIdentityStage(input = {}) {
  if (input.storageValid && input.storageVisitorId) {
    return {
      stage: "storage_continuity",
      matchLabel: input.storageVisitorId,
      visitorId: input.storageVisitorId,
      collisionRisk: "low",
      confidenceTier: "First-Party Continuity Match"
    };
  }
  if (input.exactHardwareId && (input.distinctStorageSeedsCount ?? 0) >= 2) {
    return {
      stage: "exact_hardware",
      matchLabel: input.exactHardwareId,
      // Only a hardware id is known here; the caller's own visitor id stays canonical.
      visitorId: null,
      collisionRisk: "low",
      confidenceTier: "High-Agreement Hardware Match"
    };
  }
  const query = input.query !== void 0 ? input.query : input.structuralAnchor ? structuralAnchorHash(input.structuralAnchor) : void 0;
  if (query !== void 0 && input.candidates && input.candidates.length > 0) {
    const fuzzy = decideLshFuzzyMatch({ query, candidates: input.candidates });
    if (fuzzy.match && fuzzy.bestHardwareId) {
      return {
        stage: "lsh_fuzzy",
        matchLabel: fuzzy.bestHardwareId,
        visitorId: fuzzy.bestVisitorId,
        collisionRisk: fuzzy.collisionDensity >= 2 ? "high" : "low",
        confidenceTier: "Probabilistic Fuzzy Match",
        fuzzy
      };
    }
  }
  if (input.privacyHardened) {
    return {
      stage: "privacy_hardened",
      matchLabel: "privacy-degraded",
      visitorId: null,
      collisionRisk: "high",
      confidenceTier: "Privacy-Hardened Profile (Reduced Entropy)"
    };
  }
  return {
    stage: "new_enrollment",
    matchLabel: "",
    visitorId: null,
    collisionRisk: "low",
    confidenceTier: "New Unobserved Profile"
  };
}

// src/lib/verdict.ts
function decideVerdictTier(input) {
  if (input.tamperingDetected) {
    return {
      verdict_tier: "Tampered / Spoofed Environment",
      human_corroboration: 0,
      label: "Tampered / Spoofed Environment"
    };
  }
  if (input.automation === "automated") {
    return {
      verdict_tier: "Verified Automation",
      human_corroboration: 0,
      label: "Verified Automation"
    };
  }
  if (input.humanCorroboration === 1 && input.hasInteractionEvidence !== false) {
    return {
      verdict_tier: "Verified Human Interactive Session",
      human_corroboration: 1,
      label: "Verified Human Interactive Session"
    };
  }
  return {
    verdict_tier: "Unverified / Passive Session",
    human_corroboration: 0,
    label: "Unverified / Passive Session"
  };
}

// src/lib/agentFeedSnapshots.ts
var PINNED_PREFIXES = {
  /** 4 prefixes */
  "mistral-user": [
    "20.240.160.161/32",
    "20.240.160.1/32",
    "20.240.194.83/32",
    "51.12.243.114/32"
  ],
  /** 2 prefixes */
  "mistral-index": [
    "135.225.57.92/32",
    "20.240.192.194/32"
  ],
  /** 18 prefixes */
  "gptbot": [
    "132.196.86.0/24",
    "172.182.202.0/25",
    "172.182.207.0/25",
    "20.125.66.80/28",
    "20.171.206.0/24",
    "20.171.207.0/24",
    "4.227.36.0/25",
    "52.230.152.0/24",
    "74.7.175.128/25",
    "74.7.227.0/25",
    "74.7.227.128/25",
    "74.7.228.0/25",
    "74.7.230.0/25",
    "74.7.241.0/25",
    "74.7.241.128/25",
    "74.7.242.0/25",
    "74.7.243.128/25",
    "74.7.244.0/25"
  ],
  /** 237 prefixes */
  "chatgpt-user": [
    "104.208.184.192/28",
    "104.210.139.192/28",
    "104.210.139.224/28",
    "128.85.198.32/28",
    "13.65.138.112/28",
    "13.67.72.16/28",
    "13.71.2.208/28",
    "13.76.116.80/28",
    "13.76.32.208/28",
    "13.83.167.128/28",
    "13.83.237.176/28",
    "132.196.82.48/28",
    "134.138.52.128/28",
    "134.138.52.16/28",
    "134.138.52.64/28",
    "134.138.52.96/28",
    "134.138.57.176/28",
    "134.138.57.64/28",
    "134.138.57.80/28",
    "134.138.58.32/28",
    "134.149.233.80/28",
    "134.33.102.192/28",
    "135.116.136.160/28",
    "135.13.64.240/28",
    "135.220.73.208/28",
    "135.220.73.240/28",
    "135.222.99.32/28",
    "135.237.131.208/28",
    "135.237.133.48/28",
    "137.135.191.176/28",
    "138.91.46.96/28",
    "145.132.136.96/28",
    "158.158.5.32/28",
    "168.63.252.240/28",
    "172.162.248.64/28",
    "172.170.1.80/28",
    "172.170.225.0/28",
    "172.170.241.80/28",
    "172.172.206.48/28",
    "172.175.152.224/28",
    "172.178.140.144/28",
    "172.178.141.112/28",
    "172.178.141.128/28",
    "172.183.143.224/28",
    "172.183.222.128/28",
    "172.192.112.208/28",
    "172.197.160.192/28",
    "172.197.203.16/28",
    "172.198.161.128/28",
    "172.198.58.176/28",
    "172.198.78.192/28",
    "172.198.79.112/28",
    "172.199.137.80/28",
    "172.204.28.224/28",
    "172.204.96.80/28",
    "172.205.189.192/28",
    "172.206.38.240/28",
    "172.207.1.32/28",
    "172.212.172.160/28",
    "172.215.215.32/28",
    "191.232.238.96/28",
    "191.233.197.0/28",
    "191.233.199.160/28",
    "191.234.167.144/28",
    "191.235.99.160/28",
    "191.237.249.64/28",
    "20.102.212.144/28",
    "20.113.211.112/28",
    "20.113.225.112/28",
    "20.125.112.224/28",
    "20.125.144.144/28",
    "20.161.75.208/28",
    "20.168.7.192/28",
    "20.169.73.32/28",
    "20.169.73.64/28",
    "20.169.78.128/28",
    "20.169.78.160/28",
    "20.169.78.192/28",
    "20.169.78.48/28",
    "20.169.78.64/28",
    "20.169.86.224/28",
    "20.169.86.240/28",
    "20.170.184.16/28",
    "20.170.184.32/28",
    "20.170.184.48/28",
    "20.170.184.64/28",
    "20.170.184.80/28",
    "20.172.29.32/28",
    "20.199.211.160/28",
    "20.199.242.0/28",
    "20.200.212.240/28",
    "20.206.101.192/28",
    "20.210.211.192/28",
    "20.212.62.208/28",
    "20.215.187.208/28",
    "20.215.219.128/28",
    "20.215.219.160/28",
    "20.215.219.208/28",
    "20.218.30.240/28",
    "20.219.161.192/28",
    "20.219.184.96/28",
    "20.219.71.192/28",
    "20.222.36.192/28",
    "20.227.140.32/28",
    "20.228.106.176/28",
    "20.235.87.224/28",
    "20.249.63.208/28",
    "20.250.136.64/28",
    "20.250.6.128/28",
    "20.254.201.208/28",
    "20.45.178.144/28",
    "20.55.229.144/28",
    "20.57.199.192/28",
    "20.63.180.96/28",
    "20.63.221.64/28",
    "20.78.130.48/28",
    "20.83.243.176/28",
    "20.98.18.80/28",
    "23.101.217.176/28",
    "23.102.140.144/28",
    "23.102.141.32/28",
    "23.98.142.176/28",
    "23.98.186.176/28",
    "23.98.186.192/28",
    "23.98.186.64/28",
    "23.98.186.96/28",
    "4.151.119.48/28",
    "4.151.71.176/28",
    "4.189.118.208/28",
    "4.189.119.48/28",
    "4.197.115.112/28",
    "4.197.22.112/28",
    "4.197.64.0/28",
    "4.197.64.16/28",
    "4.197.64.48/28",
    "4.197.64.64/28",
    "4.201.232.64/28",
    "4.205.128.176/28",
    "4.218.24.64/28",
    "4.226.200.16/28",
    "4.226.226.32/28",
    "40.116.73.208/28",
    "40.119.36.240/28",
    "40.124.161.0/28",
    "40.74.200.208/28",
    "40.81.234.144/28",
    "40.81.67.96/28",
    "40.84.221.208/28",
    "40.84.221.224/28",
    "48.221.184.80/28",
    "48.221.184.96/28",
    "48.221.40.176/28",
    "51.116.2.80/28",
    "51.116.221.96/28",
    "51.57.0.96/28",
    "51.57.158.112/28",
    "51.57.158.96/28",
    "51.59.24.64/28",
    "51.59.24.80/28",
    "51.59.48.80/28",
    "51.8.155.112/28",
    "51.8.155.48/28",
    "52.148.129.32/28",
    "52.156.77.144/28",
    "52.159.227.32/28",
    "52.159.249.96/28",
    "52.161.49.96/28",
    "52.165.212.48/28",
    "52.172.129.160/28",
    "52.173.219.112/28",
    "52.173.219.96/28",
    "52.173.221.16/28",
    "52.173.221.176/28",
    "52.173.221.208/28",
    "52.173.234.16/28",
    "52.173.234.80/28",
    "52.183.217.240/28",
    "52.190.137.144/28",
    "52.190.137.16/28",
    "52.190.139.48/28",
    "52.190.142.64/28",
    "52.190.190.16/28",
    "52.190.251.112/28",
    "52.225.75.208/28",
    "52.231.30.48/28",
    "52.231.34.176/28",
    "52.231.39.144/28",
    "52.231.50.64/28",
    "52.236.94.144/28",
    "52.241.146.208/28",
    "52.242.132.224/28",
    "52.242.132.240/28",
    "52.255.109.144/28",
    "52.255.109.80/28",
    "52.255.109.96/28",
    "52.255.111.0/28",
    "52.255.111.80/28",
    "57.154.174.112/28",
    "57.154.175.0/28",
    "57.154.187.32/28",
    "68.154.28.96/28",
    "68.220.57.64/28",
    "70.153.189.192/28",
    "70.153.32.16/28",
    "70.153.32.32/28",
    "70.153.87.224/28",
    "70.156.152.96/28",
    "74.161.200.96/28",
    "74.224.217.64/28",
    "74.226.253.160/28",
    "74.248.37.160/28",
    "74.7.35.112/28",
    "74.7.35.48/28",
    "74.7.36.64/28",
    "74.7.36.80/28",
    "74.7.36.96/28",
    "85.211.128.16/28",
    "85.211.128.32/28",
    "9.129.0.0/16",
    "9.160.128.16/28",
    "9.160.128.64/28",
    "9.160.163.128/28",
    "9.160.34.144/28",
    "9.160.36.16/28",
    "9.160.96.16/28",
    "9.163.101.48/28",
    "9.205.128.32/28",
    "9.205.128.48/28",
    "9.205.25.128/28",
    "9.205.30.128/28",
    "9.205.30.144/28",
    "9.205.30.176/28",
    "9.205.8.48/28",
    "9.205.8.64/28",
    "9.223.181.208/28",
    "9.234.96.192/28",
    "9.234.97.96/28"
  ],
  /** 39 prefixes */
  "searchbot": [
    "104.210.140.128/28",
    "13.66.216.176/28",
    "135.234.64.0/24",
    "172.182.193.224/28",
    "172.182.193.80/28",
    "172.182.194.144/28",
    "172.182.194.32/28",
    "172.182.195.48/28",
    "172.182.209.208/28",
    "172.182.211.192/28",
    "172.182.213.192/28",
    "172.182.224.0/28",
    "172.203.190.112/28",
    "172.203.190.128/28",
    "172.203.190.80/28",
    "20.14.99.96/28",
    "20.168.18.32/28",
    "20.169.6.224/28",
    "20.169.7.48/28",
    "20.169.77.0/25",
    "20.171.123.64/28",
    "20.171.53.224/28",
    "20.25.151.224/28",
    "20.42.10.176/28",
    "23.102.145.48/28",
    "4.227.36.0/25",
    "40.67.175.0/25",
    "40.90.214.16/28",
    "51.8.102.0/24",
    "74.7.175.128/25",
    "74.7.228.0/25",
    "74.7.228.128/25",
    "74.7.229.0/25",
    "74.7.229.128/25",
    "74.7.230.0/25",
    "74.7.241.128/25",
    "74.7.242.128/25",
    "74.7.243.0/25",
    "74.7.244.0/25"
  ],
  /** 317 prefixes */
  "google-common": [
    "2001:4860:4801:10::/64",
    "2001:4860:4801:11::/64",
    "2001:4860:4801:12::/64",
    "2001:4860:4801:13::/64",
    "2001:4860:4801:14::/64",
    "2001:4860:4801:15::/64",
    "2001:4860:4801:16::/64",
    "2001:4860:4801:17::/64",
    "2001:4860:4801:18::/64",
    "2001:4860:4801:19::/64",
    "2001:4860:4801:1a::/64",
    "2001:4860:4801:1b::/64",
    "2001:4860:4801:1c::/64",
    "2001:4860:4801:1d::/64",
    "2001:4860:4801:1e::/64",
    "2001:4860:4801:1f::/64",
    "2001:4860:4801:20::/64",
    "2001:4860:4801:21::/64",
    "2001:4860:4801:22::/64",
    "2001:4860:4801:23::/64",
    "2001:4860:4801:24::/64",
    "2001:4860:4801:25::/64",
    "2001:4860:4801:26::/64",
    "2001:4860:4801:27::/64",
    "2001:4860:4801:28::/64",
    "2001:4860:4801:29::/64",
    "2001:4860:4801:2::/64",
    "2001:4860:4801:2a::/64",
    "2001:4860:4801:2b::/64",
    "2001:4860:4801:2c::/64",
    "2001:4860:4801:2d::/64",
    "2001:4860:4801:2e::/64",
    "2001:4860:4801:2f::/64",
    "2001:4860:4801:30::/64",
    "2001:4860:4801:31::/64",
    "2001:4860:4801:32::/64",
    "2001:4860:4801:33::/64",
    "2001:4860:4801:34::/64",
    "2001:4860:4801:35::/64",
    "2001:4860:4801:36::/64",
    "2001:4860:4801:37::/64",
    "2001:4860:4801:38::/64",
    "2001:4860:4801:39::/64",
    "2001:4860:4801:3a::/64",
    "2001:4860:4801:3b::/64",
    "2001:4860:4801:3c::/64",
    "2001:4860:4801:3d::/64",
    "2001:4860:4801:3e::/64",
    "2001:4860:4801:3f::/64",
    "2001:4860:4801:40::/64",
    "2001:4860:4801:41::/64",
    "2001:4860:4801:42::/64",
    "2001:4860:4801:43::/64",
    "2001:4860:4801:44::/64",
    "2001:4860:4801:45::/64",
    "2001:4860:4801:46::/64",
    "2001:4860:4801:47::/64",
    "2001:4860:4801:48::/64",
    "2001:4860:4801:49::/64",
    "2001:4860:4801:4a::/64",
    "2001:4860:4801:4b::/64",
    "2001:4860:4801:4c::/64",
    "2001:4860:4801:4d::/64",
    "2001:4860:4801:4e::/64",
    "2001:4860:4801:50::/64",
    "2001:4860:4801:51::/64",
    "2001:4860:4801:52::/64",
    "2001:4860:4801:53::/64",
    "2001:4860:4801:54::/64",
    "2001:4860:4801:55::/64",
    "2001:4860:4801:56::/64",
    "2001:4860:4801:57::/64",
    "2001:4860:4801:58::/64",
    "2001:4860:4801:59::/64",
    "2001:4860:4801:60::/64",
    "2001:4860:4801:61::/64",
    "2001:4860:4801:62::/64",
    "2001:4860:4801:63::/64",
    "2001:4860:4801:64::/64",
    "2001:4860:4801:65::/64",
    "2001:4860:4801:66::/64",
    "2001:4860:4801:67::/64",
    "2001:4860:4801:68::/64",
    "2001:4860:4801:69::/64",
    "2001:4860:4801:6a::/64",
    "2001:4860:4801:6b::/64",
    "2001:4860:4801:6c::/64",
    "2001:4860:4801:6d::/64",
    "2001:4860:4801:6e::/64",
    "2001:4860:4801:6f::/64",
    "2001:4860:4801:70::/64",
    "2001:4860:4801:71::/64",
    "2001:4860:4801:72::/64",
    "2001:4860:4801:73::/64",
    "2001:4860:4801:74::/64",
    "2001:4860:4801:75::/64",
    "2001:4860:4801:76::/64",
    "2001:4860:4801:77::/64",
    "2001:4860:4801:78::/64",
    "2001:4860:4801:79::/64",
    "2001:4860:4801:7a::/64",
    "2001:4860:4801:7b::/64",
    "2001:4860:4801:7c::/64",
    "2001:4860:4801:7d::/64",
    "2001:4860:4801:7e::/64",
    "2001:4860:4801:7f::/64",
    "2001:4860:4801:80::/64",
    "2001:4860:4801:81::/64",
    "2001:4860:4801:82::/64",
    "2001:4860:4801:83::/64",
    "2001:4860:4801:84::/64",
    "2001:4860:4801:85::/64",
    "2001:4860:4801:86::/64",
    "2001:4860:4801:87::/64",
    "2001:4860:4801:88::/64",
    "2001:4860:4801:90::/64",
    "2001:4860:4801:91::/64",
    "2001:4860:4801:92::/64",
    "2001:4860:4801:93::/64",
    "2001:4860:4801:94::/64",
    "2001:4860:4801:95::/64",
    "2001:4860:4801:96::/64",
    "2001:4860:4801:97::/64",
    "2001:4860:4801:a0::/64",
    "2001:4860:4801:a1::/64",
    "2001:4860:4801:a2::/64",
    "2001:4860:4801:a3::/64",
    "2001:4860:4801:a4::/64",
    "2001:4860:4801:a5::/64",
    "2001:4860:4801:a6::/64",
    "2001:4860:4801:a7::/64",
    "2001:4860:4801:a8::/64",
    "2001:4860:4801:a9::/64",
    "2001:4860:4801:aa::/64",
    "2001:4860:4801:ab::/64",
    "2001:4860:4801:ac::/64",
    "2001:4860:4801:ad::/64",
    "2001:4860:4801:ae::/64",
    "2001:4860:4801:b0::/64",
    "2001:4860:4801:b1::/64",
    "2001:4860:4801:b2::/64",
    "2001:4860:4801:b3::/64",
    "2001:4860:4801:b4::/64",
    "2001:4860:4801:b5::/64",
    "2001:4860:4801:b6::/64",
    "2001:4860:4801:c::/64",
    "2001:4860:4801:f::/64",
    "192.178.4.0/27",
    "192.178.4.128/27",
    "192.178.4.160/27",
    "192.178.4.192/27",
    "192.178.4.224/27",
    "192.178.4.32/27",
    "192.178.4.64/27",
    "192.178.4.96/27",
    "192.178.5.0/27",
    "192.178.6.0/27",
    "192.178.6.128/27",
    "192.178.6.160/27",
    "192.178.6.192/27",
    "192.178.6.224/27",
    "192.178.6.32/27",
    "192.178.6.64/27",
    "192.178.6.96/27",
    "192.178.7.0/27",
    "192.178.7.128/27",
    "192.178.7.160/27",
    "192.178.7.192/27",
    "192.178.7.224/27",
    "192.178.7.32/27",
    "192.178.7.64/27",
    "192.178.7.96/27",
    "34.100.182.96/28",
    "34.101.50.144/28",
    "34.118.254.0/28",
    "34.118.66.0/28",
    "34.126.178.96/28",
    "34.146.150.144/28",
    "34.147.110.144/28",
    "34.151.74.144/28",
    "34.152.50.64/28",
    "34.154.114.144/28",
    "34.155.98.32/28",
    "34.165.18.176/28",
    "34.175.160.64/28",
    "34.176.130.16/28",
    "34.22.85.0/27",
    "34.64.82.64/28",
    "34.65.242.112/28",
    "34.80.50.80/28",
    "34.88.194.0/28",
    "34.89.10.80/28",
    "34.89.198.80/28",
    "34.96.162.48/28",
    "35.247.243.240/28",
    "66.249.64.0/27",
    "66.249.64.128/27",
    "66.249.64.160/27",
    "66.249.64.192/27",
    "66.249.64.224/27",
    "66.249.64.32/27",
    "66.249.64.64/27",
    "66.249.64.96/27",
    "66.249.65.0/27",
    "66.249.65.128/27",
    "66.249.65.160/27",
    "66.249.65.192/27",
    "66.249.65.224/27",
    "66.249.65.32/27",
    "66.249.65.64/27",
    "66.249.65.96/27",
    "66.249.66.0/27",
    "66.249.66.128/27",
    "66.249.66.160/27",
    "66.249.66.192/27",
    "66.249.66.224/27",
    "66.249.66.32/27",
    "66.249.66.64/27",
    "66.249.66.96/27",
    "66.249.67.0/27",
    "66.249.67.32/27",
    "66.249.67.64/27",
    "66.249.68.0/27",
    "66.249.68.128/27",
    "66.249.68.160/27",
    "66.249.68.192/27",
    "66.249.68.224/27",
    "66.249.68.32/27",
    "66.249.68.64/27",
    "66.249.68.96/27",
    "66.249.69.0/27",
    "66.249.69.128/27",
    "66.249.69.160/27",
    "66.249.69.192/27",
    "66.249.69.224/27",
    "66.249.69.32/27",
    "66.249.69.64/27",
    "66.249.69.96/27",
    "66.249.70.0/27",
    "66.249.70.128/27",
    "66.249.70.160/27",
    "66.249.70.192/27",
    "66.249.70.224/27",
    "66.249.70.32/27",
    "66.249.70.64/27",
    "66.249.70.96/27",
    "66.249.71.0/27",
    "66.249.71.128/27",
    "66.249.71.160/27",
    "66.249.71.192/27",
    "66.249.71.224/27",
    "66.249.71.32/27",
    "66.249.71.64/27",
    "66.249.71.96/27",
    "66.249.72.0/27",
    "66.249.72.128/27",
    "66.249.72.160/27",
    "66.249.72.192/27",
    "66.249.72.224/27",
    "66.249.72.32/27",
    "66.249.72.64/27",
    "66.249.72.96/27",
    "66.249.73.0/27",
    "66.249.73.128/27",
    "66.249.73.160/27",
    "66.249.73.192/27",
    "66.249.73.224/27",
    "66.249.73.32/27",
    "66.249.73.64/27",
    "66.249.73.96/27",
    "66.249.74.0/27",
    "66.249.74.128/27",
    "66.249.74.160/27",
    "66.249.74.192/27",
    "66.249.74.224/27",
    "66.249.74.32/27",
    "66.249.74.64/27",
    "66.249.74.96/27",
    "66.249.75.0/27",
    "66.249.75.128/27",
    "66.249.75.160/27",
    "66.249.75.192/27",
    "66.249.75.224/27",
    "66.249.75.32/27",
    "66.249.75.64/27",
    "66.249.75.96/27",
    "66.249.76.0/27",
    "66.249.76.128/27",
    "66.249.76.160/27",
    "66.249.76.192/27",
    "66.249.76.224/27",
    "66.249.76.32/27",
    "66.249.76.64/27",
    "66.249.76.96/27",
    "66.249.77.0/27",
    "66.249.77.128/27",
    "66.249.77.160/27",
    "66.249.77.192/27",
    "66.249.77.224/27",
    "66.249.77.32/27",
    "66.249.77.64/27",
    "66.249.77.96/27",
    "66.249.78.0/27",
    "66.249.78.128/27",
    "66.249.78.160/27",
    "66.249.78.192/27",
    "66.249.78.224/27",
    "66.249.78.32/27",
    "66.249.78.64/27",
    "66.249.78.96/27",
    "66.249.79.0/27",
    "66.249.79.128/27",
    "66.249.79.160/27",
    "66.249.79.192/27",
    "66.249.79.224/27",
    "66.249.79.32/27",
    "66.249.79.64/27"
  ],
  /** 21 prefixes */
  "perplexitybot": [
    "107.20.236.150/32",
    "18.210.92.235/32",
    "18.97.1.228/32",
    "18.97.9.100/32",
    "18.97.9.101/32",
    "18.97.9.102/32",
    "18.97.9.103/32",
    "18.97.9.96/32",
    "18.97.9.97/32",
    "18.97.9.98/32",
    "18.97.9.99/32",
    "3.222.232.239/32",
    "3.224.62.45/32",
    "3.41.218.160/32",
    "3.41.218.161/32",
    "3.41.218.162/32",
    "3.41.218.163/32",
    "3.41.218.164/32",
    "3.41.218.165/32",
    "3.41.218.166/32",
    "3.41.218.167/32"
  ],
  /** 10 prefixes */
  "perplexity-user": [
    "18.97.43.80/32",
    "18.97.43.81/32",
    "18.97.43.82/32",
    "18.97.43.83/32",
    "18.97.43.84/32",
    "18.97.43.85/32",
    "18.97.43.86/32",
    "18.97.43.87/32",
    "34.193.163.52/32",
    "44.208.221.197/32"
  ],
  /** 24 prefixes */
  "applebot": [
    "17.241.208.160/27",
    "17.241.193.160/27",
    "17.241.200.160/27",
    "17.166.192.48/28",
    "17.166.240.48/28",
    "17.166.248.48/28",
    "17.166.20.0/24",
    "17.166.21.0/24",
    "17.166.22.0/24",
    "17.166.23.0/24",
    "17.166.24.0/24",
    "17.166.25.0/24",
    "17.166.232.0/24",
    "17.166.233.0/24",
    "17.166.234.0/24",
    "17.166.235.0/24",
    "17.166.236.0/24",
    "17.166.237.0/24",
    "17.166.150.0/24",
    "17.166.151.0/24",
    "17.166.152.0/24",
    "17.166.153.0/24",
    "17.166.154.0/24",
    "17.166.155.0/24"
  ],
  /** 29 prefixes */
  "bingbot": [
    "157.55.39.0/24",
    "207.46.13.0/24",
    "40.77.167.0/24",
    "13.66.139.0/24",
    "13.66.144.0/24",
    "52.167.144.0/24",
    "13.67.10.16/28",
    "13.69.66.240/28",
    "13.71.172.224/28",
    "139.217.52.0/28",
    "52.130.224.112/28",
    "191.233.204.224/28",
    "20.36.108.32/28",
    "20.43.120.16/28",
    "40.79.131.208/28",
    "40.79.186.176/28",
    "52.231.148.0/28",
    "20.79.107.240/28",
    "51.105.67.0/28",
    "20.125.163.80/28",
    "40.77.188.0/22",
    "65.55.210.0/24",
    "199.30.24.0/23",
    "40.77.202.0/24",
    "40.77.139.0/25",
    "20.74.197.0/28",
    "20.15.133.160/27",
    "40.77.177.0/24",
    "40.77.178.0/23"
  ],
  /** 5 prefixes */
  "ccbot": [
    "2600:1f28:365:8000::/56",
    "3.41.188.32/29",
    "18.97.9.168/29",
    "18.97.14.80/29",
    "18.97.14.88/30"
  ],
  /** 1292 prefixes */
  "amazonbot": [
    "3.81.245.78/32",
    "3.81.253.213/32",
    "3.85.116.107/32",
    "3.86.129.126/32",
    "3.88.96.254/32",
    "3.88.245.236/32",
    "3.89.170.186/32",
    "3.89.176.255/32",
    "3.90.73.206/32",
    "3.91.138.117/32",
    "3.91.140.8/32",
    "3.92.37.4/32",
    "3.92.253.216/32",
    "3.93.98.99/32",
    "3.93.211.16/32",
    "3.93.222.50/32",
    "3.93.253.174/32",
    "3.94.40.182/32",
    "3.94.46.239/32",
    "3.94.75.111/32",
    "3.94.156.104/32",
    "3.94.157.25/32",
    "3.94.199.128/32",
    "3.208.33.245/32",
    "3.208.47.73/32",
    "3.208.129.204/32",
    "3.208.146.193/32",
    "3.208.156.9/32",
    "3.208.224.218/32",
    "3.209.2.17/32",
    "3.209.156.113/32",
    "3.209.174.110/32",
    "3.209.187.64/32",
    "3.209.221.199/32",
    "3.210.29.96/32",
    "3.210.114.189/32",
    "3.210.115.187/32",
    "3.210.123.121/32",
    "3.210.152.134/32",
    "3.210.223.61/32",
    "3.211.16.169/32",
    "3.211.90.118/32",
    "3.211.105.134/32",
    "3.211.181.86/32",
    "3.211.184.174/32",
    "3.211.196.5/32",
    "3.212.18.59/32",
    "3.212.32.46/32",
    "3.212.86.97/32",
    "3.212.136.194/32",
    "3.212.144.73/32",
    "3.212.205.90/32",
    "3.212.219.113/32",
    "3.212.237.74/32",
    "3.213.46.222/32",
    "3.213.80.185/32",
    "3.213.85.234/32",
    "3.213.106.226/32",
    "3.213.142.248/32",
    "3.213.213.161/32",
    "3.214.176.44/32",
    "3.214.218.132/32",
    "3.215.14.122/32",
    "3.215.59.93/32",
    "3.215.156.193/32",
    "3.215.221.125/32",
    "3.216.13.10/32",
    "3.216.86.144/32",
    "3.216.199.69/32",
    "3.216.227.216/32",
    "3.216.250.224/32",
    "3.217.47.0/32",
    "3.217.82.254/32",
    "3.217.171.106/32",
    "3.217.190.160/32",
    "3.217.211.204/32",
    "3.218.20.222/32",
    "3.218.35.239/32",
    "3.218.103.254/32",
    "3.218.147.175/32",
    "3.218.202.170/32",
    "3.219.80.71/32",
    "3.219.81.66/32",
    "3.219.118.96/32",
    "3.219.145.31/32",
    "3.220.55.106/32",
    "3.220.70.171/32",
    "3.220.138.53/32",
    "3.220.148.166/32",
    "3.220.175.119/32",
    "3.220.202.135/32",
    "3.221.48.218/32",
    "3.221.50.71/32",
    "3.221.156.96/32",
    "3.221.222.168/32",
    "3.221.232.188/32",
    "3.221.244.28/32",
    "3.222.85.38/32",
    "3.222.134.229/32",
    "3.222.144.151/32",
    "3.222.186.80/32",
    "3.222.190.107/32",
    "3.222.230.205/32",
    "3.223.38.249/32",
    "3.223.61.36/32",
    "3.223.107.167/32",
    "3.223.122.95/32",
    "3.223.134.5/32",
    "3.223.181.32/32",
    "3.223.229.145/32",
    "3.223.245.78/32",
    "3.224.104.67/32",
    "3.224.157.127/32",
    "3.224.191.210/32",
    "3.224.205.25/32",
    "3.224.215.150/32",
    "3.224.220.101/32",
    "3.225.9.97/32",
    "3.225.12.172/32",
    "3.225.45.252/32",
    "3.225.50.29/32",
    "3.226.34.98/32",
    "3.226.101.249/32",
    "3.226.106.93/32",
    "3.226.115.242/32",
    "3.226.160.157/32",
    "3.226.184.56/32",
    "3.227.62.11/32",
    "3.227.96.103/32",
    "3.227.180.70/32",
    "3.228.111.48/32",
    "3.228.140.40/32",
    "3.228.150.65/32",
    "3.229.2.217/32",
    "3.229.62.67/32",
    "3.229.65.105/32",
    "3.229.95.193/32",
    "3.229.128.107/32",
    "3.229.164.203/32",
    "3.229.181.245/32",
    "3.230.14.171/32",
    "3.230.43.143/32",
    "3.230.54.110/32",
    "3.230.69.161/32",
    "3.230.161.52/32",
    "3.230.224.6/32",
    "3.231.72.210/32",
    "3.231.180.166/32",
    "3.231.192.213/32",
    "3.231.193.38/32",
    "3.231.193.169/32",
    "3.232.39.98/32",
    "3.232.82.72/32",
    "3.232.84.110/32",
    "3.232.102.111/32",
    "3.232.145.99/32",
    "3.232.202.209/32",
    "3.232.208.252/32",
    "3.233.110.127/32",
    "3.234.87.64/32",
    "3.234.94.166/32",
    "3.235.215.92/32",
    "3.239.194.129/32",
    "13.216.71.17/32",
    "13.216.200.208/32",
    "13.216.205.205/32",
    "13.217.73.235/32",
    "13.219.57.118/32",
    "13.223.39.7/32",
    "13.223.113.242/32",
    "13.223.134.105/32",
    "13.223.215.220/32",
    "18.204.83.102/32",
    "18.204.89.56/32",
    "18.204.152.114/32",
    "18.204.239.30/32",
    "18.205.91.101/32",
    "18.205.127.11/32",
    "18.205.173.53/32",
    "18.205.213.231/32",
    "18.206.47.187/32",
    "18.206.80.86/32",
    "18.207.79.144/32",
    "18.207.89.138/32",
    "18.208.11.93/32",
    "18.208.15.146/32",
    "18.208.113.192/32",
    "18.209.82.211/32",
    "18.209.137.234/32",
    "18.209.198.85/32",
    "18.209.201.119/32",
    "18.210.56.100/32",
    "18.210.58.238/32",
    "18.210.77.56/32",
    "18.210.120.208/32",
    "18.210.147.97/32",
    "18.211.32.162/32",
    "18.211.39.188/32",
    "18.211.76.162/32",
    "18.211.148.239/32",
    "18.211.161.73/32",
    "18.211.191.113/32",
    "18.211.217.198/32",
    "18.211.242.14/32",
    "18.213.27.222/32",
    "18.213.70.100/32",
    "18.213.86.182/32",
    "18.213.87.246/32",
    "18.213.102.186/32",
    "18.213.123.90/32",
    "18.213.133.156/32",
    "18.213.188.154/32",
    "18.213.191.165/32",
    "18.213.240.226/32",
    "18.214.7.8/32",
    "18.214.17.122/32",
    "18.214.78.166/32",
    "18.214.106.155/32",
    "18.214.124.6/32",
    "18.214.138.148/32",
    "18.214.186.220/32",
    "18.214.195.55/32",
    "18.214.238.178/32",
    "18.214.251.19/32",
    "18.215.24.66/32",
    "18.215.31.42/32",
    "18.215.49.176/32",
    "18.215.77.19/32",
    "18.215.112.101/32",
    "18.215.119.68/32",
    "18.232.11.247/32",
    "18.232.12.157/32",
    "18.232.36.1/32",
    "18.232.191.232/32",
    "18.232.204.128/32",
    "18.233.22.168/32",
    "18.233.24.238/32",
    "18.235.81.246/32",
    "18.235.158.19/32",
    "23.20.146.223/32",
    "23.20.149.71/32",
    "23.20.178.124/32",
    "23.21.119.232/32",
    "23.21.148.226/32",
    "23.21.175.228/32",
    "23.21.179.27/32",
    "23.21.179.35/32",
    "23.21.179.120/32",
    "23.21.204.95/32",
    "23.21.205.230/32",
    "23.21.207.129/32",
    "23.21.210.40/32",
    "23.21.225.190/32",
    "23.21.227.240/32",
    "23.21.228.180/32",
    "23.21.250.48/32",
    "23.22.19.198/32",
    "23.22.20.228/32",
    "23.22.35.162/32",
    "23.22.59.87/32",
    "23.22.105.143/32",
    "23.22.141.240/32",
    "23.22.146.41/32",
    "23.22.148.181/32",
    "23.22.230.70/32",
    "23.23.14.241/32",
    "23.23.99.55/32",
    "23.23.103.31/32",
    "23.23.104.107/32",
    "23.23.137.202/32",
    "23.23.169.144/32",
    "23.23.180.225/32",
    "23.23.212.212/32",
    "23.23.213.182/32",
    "23.23.214.190/32",
    "23.23.224.159/32",
    "32.192.16.179/32",
    "32.192.112.25/32",
    "32.192.146.164/32",
    "32.192.158.119/32",
    "32.192.170.30/32",
    "32.193.7.60/32",
    "32.193.117.94/32",
    "32.193.200.204/32",
    "32.194.54.130/32",
    "32.194.70.253/32",
    "32.194.84.196/32",
    "32.194.189.87/32",
    "32.194.241.222/32",
    "32.195.25.4/32",
    "32.195.30.1/32",
    "32.195.79.67/32",
    "32.195.82.105/32",
    "32.195.85.141/32",
    "32.195.96.205/32",
    "32.195.127.227/32",
    "32.195.171.51/32",
    "32.195.185.225/32",
    "32.196.5.45/32",
    "32.196.13.177/32",
    "32.196.78.138/32",
    "32.196.99.18/32",
    "32.196.127.32/32",
    "32.196.172.181/32",
    "32.196.219.86/32",
    "32.196.220.178/32",
    "32.197.0.57/32",
    "32.197.29.81/32",
    "32.197.74.42/32",
    "32.197.108.117/32",
    "32.197.176.179/32",
    "32.198.237.6/32",
    "32.198.246.135/32",
    "32.199.124.50/32",
    "34.192.55.180/32",
    "34.192.67.98/32",
    "34.192.125.239/32",
    "34.192.126.103/32",
    "34.192.215.69/32",
    "34.192.221.205/32",
    "34.193.2.57/32",
    "34.193.23.131/32",
    "34.193.220.170/32",
    "34.193.228.159/32",
    "34.194.14.255/32",
    "34.194.95.99/32",
    "34.194.100.135/32",
    "34.194.165.45/32",
    "34.194.209.245/32",
    "34.194.225.116/32",
    "34.194.226.74/32",
    "34.194.233.48/32",
    "34.194.243.75/32",
    "34.195.60.66/32",
    "34.195.144.83/32",
    "34.195.170.146/32",
    "34.195.185.14/32",
    "34.195.191.37/32",
    "34.195.248.30/32",
    "34.196.6.199/32",
    "34.196.6.240/32",
    "34.196.30.12/32",
    "34.196.49.100/32",
    "34.196.114.170/32",
    "34.196.190.12/32",
    "34.196.237.236/32",
    "34.197.28.78/32",
    "34.197.96.67/32",
    "34.197.179.252/32",
    "34.198.44.69/32",
    "34.199.54.89/32",
    "34.199.72.6/32",
    "34.199.167.166/32",
    "34.199.252.22/32",
    "34.200.36.216/32",
    "34.200.86.246/32",
    "34.200.133.183/32",
    "34.200.169.0/32",
    "34.201.181.54/32",
    "34.202.16.142/32",
    "34.202.88.37/32",
    "34.202.103.152/32",
    "34.202.112.188/32",
    "34.202.153.229/32",
    "34.202.164.232/32",
    "34.202.182.197/32",
    "34.202.210.13/32",
    "34.203.105.116/32",
    "34.203.111.15/32",
    "34.203.118.32/32",
    "34.203.118.85/32",
    "34.203.172.148/32",
    "34.203.201.219/32",
    "34.204.150.196/32",
    "34.204.233.120/32",
    "34.205.10.151/32",
    "34.205.117.127/32",
    "34.205.122.5/32",
    "34.205.123.23/32",
    "34.205.163.103/32",
    "34.205.170.13/32",
    "34.205.175.100/32",
    "34.205.199.8/32",
    "34.205.234.123/32",
    "34.206.193.60/32",
    "34.206.205.131/32",
    "34.206.212.24/32",
    "34.206.229.66/32",
    "34.206.249.188/32",
    "34.224.9.144/32",
    "34.224.132.215/32",
    "34.224.201.217/32",
    "34.224.224.155/32",
    "34.224.232.175/32",
    "34.225.24.180/32",
    "34.225.79.179/32",
    "34.225.87.80/32",
    "34.225.138.57/32",
    "34.225.243.131/32",
    "34.226.56.197/32",
    "34.226.89.140/32",
    "34.227.156.153/32",
    "34.227.233.168/32",
    "34.227.234.246/32",
    "34.228.105.150/32",
    "34.230.124.21/32",
    "34.230.161.23/32",
    "34.230.175.224/32",
    "34.230.208.4/32",
    "34.230.245.58/32",
    "34.231.11.219/32",
    "34.231.45.47/32",
    "34.231.77.232/32",
    "34.231.118.144/32",
    "34.231.130.193/32",
    "34.231.156.59/32",
    "34.231.181.240/32",
    "34.231.219.196/32",
    "34.232.103.129/32",
    "34.232.115.106/32",
    "34.232.173.22/32",
    "34.232.249.216/32",
    "34.233.111.76/32",
    "34.233.114.237/32",
    "34.233.164.201/32",
    "34.233.171.240/32",
    "34.233.219.155/32",
    "34.234.10.40/32",
    "34.234.60.110/32",
    "34.234.121.216/32",
    "34.234.190.75/32",
    "34.234.197.175/32",
    "34.234.200.207/32",
    "34.234.206.30/32",
    "34.234.235.23/32",
    "34.235.75.8/32",
    "34.235.173.180/32",
    "34.235.178.44/32",
    "34.235.239.240/32",
    "34.236.26.60/32",
    "34.236.41.241/32",
    "34.236.82.22/32",
    "34.236.89.150/32",
    "34.236.91.13/32",
    "34.236.135.14/32",
    "34.236.185.101/32",
    "34.236.189.117/32",
    "34.236.252.251/32",
    "34.237.89.221/32",
    "34.238.45.183/32",
    "34.238.144.226/32",
    "34.239.85.139/32",
    "34.239.197.197/32",
    "34.239.229.196/32",
    "35.153.42.147/32",
    "35.153.86.40/32",
    "35.153.86.200/32",
    "35.153.155.149/32",
    "35.153.218.211/32",
    "35.168.73.117/32",
    "35.168.151.95/32",
    "35.168.238.50/32",
    "35.169.89.12/32",
    "35.169.102.85/32",
    "35.169.119.108/32",
    "35.169.209.75/32",
    "35.169.240.53/32",
    "35.170.40.230/32",
    "35.170.103.34/32",
    "35.170.116.99/32",
    "35.170.195.233/32",
    "35.170.205.140/32",
    "35.170.215.163/32",
    "35.171.117.160/32",
    "35.171.122.241/32",
    "35.171.141.42/32",
    "35.171.173.150/32",
    "35.172.91.0/32",
    "35.172.125.172/32",
    "35.173.18.61/32",
    "35.173.38.202/32",
    "35.173.60.40/32",
    "35.173.88.80/32",
    "35.173.97.68/32",
    "35.174.141.243/32",
    "35.174.150.32/32",
    "35.174.185.174/32",
    "35.174.187.247/32",
    "35.174.253.85/32",
    "35.175.85.189/32",
    "44.193.102.198/32",
    "44.193.115.232/32",
    "44.194.6.175/32",
    "44.194.64.226/32",
    "44.194.108.197/32",
    "44.194.134.53/32",
    "44.194.139.149/32",
    "44.195.50.71/32",
    "44.195.132.139/32",
    "44.195.142.56/32",
    "44.195.145.102/32",
    "44.195.163.77/32",
    "44.195.225.95/32",
    "44.196.2.129/32",
    "44.196.35.207/32",
    "44.196.118.6/32",
    "44.196.161.7/32",
    "44.197.65.237/32",
    "44.197.76.210/32",
    "44.198.40.214/32",
    "44.198.105.10/32",
    "44.198.154.81/32",
    "44.198.223.49/32",
    "44.198.231.31/32",
    "44.199.175.190/32",
    "44.205.43.166/32",
    "44.205.65.19/32",
    "44.205.74.196/32",
    "44.205.120.22/32",
    "44.205.156.100/32",
    "44.205.180.155/32",
    "44.205.192.249/32",
    "44.206.65.8/32",
    "44.206.93.215/32",
    "44.206.213.217/32",
    "44.207.29.72/32",
    "44.207.69.106/32",
    "44.207.155.89/32",
    "44.207.207.36/32",
    "44.207.209.230/32",
    "44.207.241.206/32",
    "44.207.252.58/32",
    "44.208.89.66/32",
    "44.208.131.254/32",
    "44.208.193.63/32",
    "44.208.212.174/32",
    "44.208.220.225/32",
    "44.208.223.68/32",
    "44.208.245.240/32",
    "44.209.24.209/32",
    "44.209.35.147/32",
    "44.209.80.115/32",
    "44.209.89.189/32",
    "44.209.108.13/32",
    "44.209.187.99/32",
    "44.209.254.112/32",
    "44.210.60.235/32",
    "44.210.199.190/32",
    "44.210.204.255/32",
    "44.210.213.220/32",
    "44.210.226.29/32",
    "44.211.3.154/32",
    "44.211.10.233/32",
    "44.212.106.171/32",
    "44.212.131.50/32",
    "44.212.145.46/32",
    "44.212.232.231/32",
    "44.212.242.70/32",
    "44.213.36.21/32",
    "44.213.159.215/32",
    "44.213.202.136/32",
    "44.213.202.160/32",
    "44.214.19.8/32",
    "44.214.224.199/32",
    "44.214.227.26/32",
    "44.214.237.175/32",
    "44.215.61.66/32",
    "44.215.168.29/32",
    "44.215.181.176/32",
    "44.215.210.112/32",
    "44.215.227.72/32",
    "44.215.231.15/32",
    "44.215.235.20/32",
    "44.215.239.33/32",
    "44.216.105.106/32",
    "44.216.172.204/32",
    "44.216.237.125/32",
    "44.217.12.90/32",
    "44.217.44.195/32",
    "44.217.174.180/32",
    "44.217.177.142/32",
    "44.217.255.167/32",
    "44.218.6.93/32",
    "44.218.79.142/32",
    "44.218.120.180/32",
    "44.218.170.184/32",
    "44.219.46.88/32",
    "44.219.74.122/32",
    "44.219.243.132/32",
    "44.220.2.97/32",
    "44.220.21.130/32",
    "44.221.19.65/32",
    "44.221.37.41/32",
    "44.221.105.234/32",
    "44.221.106.162/32",
    "44.221.138.137/32",
    "44.221.180.179/32",
    "44.221.227.90/32",
    "44.222.9.101/32",
    "44.223.115.10/32",
    "44.223.116.149/32",
    "44.223.116.180/32",
    "44.223.193.255/32",
    "44.223.227.26/32",
    "44.223.232.55/32",
    "50.16.43.55/32",
    "50.16.72.185/32",
    "50.16.216.166/32",
    "50.16.247.74/32",
    "50.16.248.61/32",
    "50.17.115.150/32",
    "50.17.193.48/32",
    "50.17.228.207/32",
    "50.17.246.254/32",
    "50.19.46.134/32",
    "50.19.64.10/32",
    "50.19.78.178/32",
    "50.19.79.213/32",
    "50.19.102.70/32",
    "50.19.106.86/32",
    "50.19.167.76/32",
    "50.19.221.48/32",
    "50.19.243.82/32",
    "50.19.251.21/32",
    "52.0.41.164/32",
    "52.0.63.151/32",
    "52.0.81.156/32",
    "52.0.101.108/32",
    "52.0.105.244/32",
    "52.0.108.238/32",
    "52.0.178.92/32",
    "52.0.218.219/32",
    "52.1.75.30/32",
    "52.1.84.252/32",
    "52.1.100.136/32",
    "52.1.106.130/32",
    "52.1.157.90/32",
    "52.2.4.213/32",
    "52.2.11.133/32",
    "52.2.39.252/32",
    "52.2.47.27/32",
    "52.2.58.41/32",
    "52.2.63.204/32",
    "52.2.83.227/32",
    "52.2.191.202/32",
    "52.3.26.180/32",
    "52.3.74.68/32",
    "52.3.78.144/32",
    "52.3.102.51/32",
    "52.3.104.214/32",
    "52.3.127.170/32",
    "52.3.130.157/32",
    "52.3.155.146/32",
    "52.3.156.186/32",
    "52.3.188.146/32",
    "52.4.76.156/32",
    "52.4.128.0/32",
    "52.4.143.63/32",
    "52.4.201.109/32",
    "52.4.213.199/32",
    "52.4.229.9/32",
    "52.4.238.8/32",
    "52.5.13.52/32",
    "52.5.165.11/32",
    "52.5.175.224/32",
    "52.5.221.152/32",
    "52.5.232.250/32",
    "52.5.233.62/32",
    "52.5.242.243/32",
    "52.6.5.24/32",
    "52.6.89.179/32",
    "52.6.97.88/32",
    "52.6.173.78/32",
    "52.6.216.39/32",
    "52.6.232.201/32",
    "52.6.255.193/32",
    "52.7.13.44/32",
    "52.7.13.143/32",
    "52.7.33.248/32",
    "52.7.78.54/32",
    "52.7.101.58/32",
    "52.7.232.91/32",
    "52.20.8.32/32",
    "52.20.88.157/32",
    "52.20.98.185/32",
    "52.20.137.159/32",
    "52.20.137.229/32",
    "52.20.157.145/32",
    "52.20.159.75/32",
    "52.20.203.24/32",
    "52.20.205.113/32",
    "52.20.240.226/32",
    "52.21.26.34/32",
    "52.21.46.201/32",
    "52.21.50.209/32",
    "52.21.62.139/32",
    "52.21.85.213/32",
    "52.21.109.236/32",
    "52.21.184.211/32",
    "52.21.187.65/32",
    "52.21.223.189/32",
    "52.22.2.95/32",
    "52.22.64.232/32",
    "52.22.87.224/32",
    "52.23.91.14/32",
    "52.23.112.144/32",
    "52.44.148.203/32",
    "52.44.157.127/32",
    "52.44.174.136/32",
    "52.44.229.124/32",
    "52.45.15.233/32",
    "52.45.29.57/32",
    "52.45.77.169/32",
    "52.45.92.83/32",
    "52.45.184.225/32",
    "52.45.190.80/32",
    "52.45.194.165/32",
    "52.54.15.103/32",
    "52.54.45.70/32",
    "52.54.54.197/32",
    "52.54.67.48/32",
    "52.54.95.127/32",
    "52.54.157.23/32",
    "52.54.249.218/32",
    "52.55.108.228/32",
    "52.55.208.70/32",
    "52.70.123.241/32",
    "52.70.138.176/32",
    "52.70.166.208/32",
    "52.70.169.120/32",
    "52.70.170.85/32",
    "52.70.184.86/32",
    "52.70.209.13/32",
    "52.70.240.171/32",
    "52.70.249.201/32",
    "52.70.251.201/32",
    "52.71.46.142/32",
    "52.71.123.230/32",
    "52.71.139.1/32",
    "52.71.203.206/32",
    "52.71.216.196/32",
    "52.71.218.25/32",
    "52.72.165.106/32",
    "52.72.240.198/32",
    "52.73.6.26/32",
    "52.73.52.182/32",
    "52.73.59.127/32",
    "52.73.132.106/32",
    "52.73.142.41/32",
    "52.86.84.160/32",
    "52.86.125.110/32",
    "52.86.135.254/32",
    "52.87.216.1/32",
    "52.90.14.235/32",
    "52.91.123.6/32",
    "52.200.39.39/32",
    "52.200.54.136/32",
    "52.200.58.199/32",
    "52.200.72.138/32",
    "52.200.93.170/32",
    "52.200.115.159/32",
    "52.200.142.199/32",
    "52.200.146.144/32",
    "52.200.245.197/32",
    "52.200.251.20/32",
    "52.201.0.89/32",
    "52.201.9.130/32",
    "52.201.35.30/32",
    "52.201.64.62/32",
    "52.201.155.215/32",
    "52.201.158.126/32",
    "52.201.173.132/32",
    "52.202.52.82/32",
    "52.202.229.247/32",
    "52.202.233.37/32",
    "52.202.248.123/32",
    "52.203.65.83/32",
    "52.203.68.145/32",
    "52.203.92.216/32",
    "52.203.110.191/32",
    "52.203.152.231/32",
    "52.203.175.146/32",
    "52.203.203.38/32",
    "52.203.237.170/32",
    "52.204.15.176/32",
    "52.204.37.237/32",
    "52.204.71.8/32",
    "52.204.81.148/32",
    "52.204.89.12/32",
    "52.204.174.139/32",
    "52.204.217.5/32",
    "52.204.253.129/32",
    "52.205.113.104/32",
    "52.205.141.124/32",
    "52.205.222.214/32",
    "52.205.246.252/32",
    "52.206.4.37/32",
    "52.206.52.236/32",
    "52.206.59.204/32",
    "52.206.64.59/32",
    "52.206.147.195/32",
    "52.206.204.50/32",
    "52.207.28.157/32",
    "52.207.47.227/32",
    "54.80.1.215/32",
    "54.80.73.122/32",
    "54.80.120.78/32",
    "54.80.121.108/32",
    "54.80.136.167/32",
    "54.80.185.200/32",
    "54.81.11.133/32",
    "54.81.14.82/32",
    "54.81.45.126/32",
    "54.81.134.131/32",
    "54.81.191.5/32",
    "54.81.238.39/32",
    "54.82.109.15/32",
    "54.83.11.233/32",
    "54.83.23.103/32",
    "54.83.56.1/32",
    "54.83.180.239/32",
    "54.83.199.241/32",
    "54.83.240.58/32",
    "54.84.88.22/32",
    "54.84.93.8/32",
    "54.84.102.81/32",
    "54.84.147.79/32",
    "54.84.161.62/32",
    "54.84.169.196/32",
    "54.84.205.220/32",
    "54.84.250.51/32",
    "54.85.7.119/32",
    "54.85.109.140/32",
    "54.85.126.86/32",
    "54.85.223.45/32",
    "54.85.241.125/32",
    "54.86.59.155/32",
    "54.86.197.92/32",
    "54.86.234.119/32",
    "54.86.239.192/32",
    "54.87.4.126/32",
    "54.87.62.248/32",
    "54.87.95.7/32",
    "54.87.236.2/32",
    "54.88.84.219/32",
    "54.88.188.59/32",
    "54.88.247.44/32",
    "54.89.90.224/32",
    "54.90.8.255/32",
    "54.90.21.233/32",
    "54.90.26.89/32",
    "54.90.244.132/32",
    "54.91.122.193/32",
    "54.92.171.106/32",
    "54.144.22.233/32",
    "54.144.42.14/32",
    "54.144.44.182/32",
    "54.144.185.255/32",
    "54.144.247.210/32",
    "54.145.82.217/32",
    "54.146.67.173/32",
    "54.146.84.169/32",
    "54.146.102.185/32",
    "54.146.119.126/32",
    "54.146.167.72/32",
    "54.146.185.99/32",
    "54.147.80.137/32",
    "54.147.136.146/32",
    "54.147.182.90/32",
    "54.147.238.89/32",
    "54.152.21.44/32",
    "54.152.30.242/32",
    "54.152.163.42/32",
    "54.152.194.33/32",
    "54.156.55.147/32",
    "54.156.124.2/32",
    "54.156.208.198/32",
    "54.156.234.172/32",
    "54.156.248.117/32",
    "54.157.84.74/32",
    "54.157.99.244/32",
    "54.157.174.108/32",
    "54.158.43.170/32",
    "54.158.139.192/32",
    "54.158.155.182/32",
    "54.159.18.27/32",
    "54.159.98.248/32",
    "54.159.140.186/32",
    "54.159.223.204/32",
    "54.159.245.22/32",
    "54.160.47.239/32",
    "54.160.118.78/32",
    "54.160.136.135/32",
    "54.161.158.222/32",
    "54.161.238.223/32",
    "54.161.253.173/32",
    "54.162.58.185/32",
    "54.162.69.192/32",
    "54.162.70.124/32",
    "54.163.33.176/32",
    "54.163.136.244/32",
    "54.163.169.168/32",
    "54.163.213.42/32",
    "54.164.106.236/32",
    "54.164.208.167/32",
    "54.165.11.5/32",
    "54.165.99.177/32",
    "54.165.161.174/32",
    "54.166.104.83/32",
    "54.166.126.132/32",
    "54.166.181.246/32",
    "54.167.14.199/32",
    "54.167.32.123/32",
    "54.167.81.78/32",
    "54.172.35.126/32",
    "54.172.157.35/32",
    "54.172.235.198/32",
    "54.173.224.14/32",
    "54.174.244.224/32",
    "54.175.220.249/32",
    "54.197.52.174/32",
    "54.197.82.195/32",
    "54.197.102.71/32",
    "54.197.114.76/32",
    "54.197.178.107/32",
    "54.198.33.233/32",
    "54.198.34.175/32",
    "54.204.12.115/32",
    "54.204.35.170/32",
    "54.204.62.163/32",
    "54.204.120.7/32",
    "54.204.178.26/32",
    "54.205.137.46/32",
    "54.205.150.0/32",
    "54.205.205.14/32",
    "54.208.10.176/32",
    "54.208.120.99/32",
    "54.208.131.189/32",
    "54.209.6.230/32",
    "54.209.100.30/32",
    "54.210.51.58/32",
    "54.210.77.145/32",
    "54.210.152.179/32",
    "54.210.155.69/32",
    "54.211.13.212/32",
    "54.211.195.14/32",
    "54.221.203.24/32",
    "54.221.211.160/32",
    "54.221.239.88/32",
    "54.221.245.154/32",
    "54.221.254.95/32",
    "54.224.80.42/32",
    "54.224.242.33/32",
    "54.225.81.20/32",
    "54.225.98.148/32",
    "54.225.148.123/32",
    "54.225.181.161/32",
    "54.225.199.17/32",
    "54.225.201.2/32",
    "54.226.95.110/32",
    "54.226.117.47/32",
    "54.226.201.45/32",
    "54.227.251.182/32",
    "54.234.122.80/32",
    "54.235.81.195/32",
    "54.235.125.129/32",
    "54.235.158.162/32",
    "54.235.172.96/32",
    "54.235.172.108/32",
    "54.235.191.179/32",
    "54.235.199.187/32",
    "54.236.90.11/32",
    "54.236.95.142/32",
    "54.236.100.102/32",
    "54.236.100.106/32",
    "54.236.102.157/32",
    "54.236.227.238/32",
    "54.237.219.210/32",
    "54.243.63.52/32",
    "54.243.204.71/32",
    "54.243.211.244/32",
    "67.202.25.8/32",
    "72.44.42.254/32",
    "75.101.156.93/32",
    "98.80.17.126/32",
    "98.80.60.233/32",
    "98.80.89.155/32",
    "98.80.130.239/32",
    "98.82.38.120/32",
    "98.82.39.241/32",
    "98.82.40.168/32",
    "98.82.42.197/32",
    "98.82.59.253/32",
    "98.82.63.147/32",
    "98.82.66.172/32",
    "98.82.67.109/32",
    "98.82.70.65/32",
    "98.82.88.135/32",
    "98.82.107.102/32",
    "98.82.214.73/32",
    "98.82.224.29/32",
    "98.82.226.145/32",
    "98.83.8.142/32",
    "98.83.10.183/32",
    "98.83.59.126/32",
    "98.83.72.38/32",
    "98.83.94.113/32",
    "98.83.101.133/32",
    "98.83.176.66/32",
    "98.83.177.42/32",
    "98.83.178.66/32",
    "98.83.225.16/32",
    "98.83.225.157/32",
    "98.83.226.125/32",
    "98.83.250.208/32",
    "98.84.60.17/32",
    "98.84.70.201/32",
    "98.84.131.195/32",
    "98.84.184.80/32",
    "98.84.192.142/32",
    "98.84.200.43/32",
    "98.84.206.170/32",
    "98.85.17.171/32",
    "98.85.32.206/32",
    "98.85.36.128/32",
    "98.85.170.76/32",
    "98.86.65.222/32",
    "98.86.80.124/32",
    "98.86.132.251/32",
    "98.86.203.217/32",
    "98.86.212.51/32",
    "98.87.77.225/32",
    "98.87.133.23/32",
    "98.87.141.21/32",
    "98.87.182.7/32",
    "98.87.207.126/32",
    "98.87.213.181/32",
    "98.87.238.5/32",
    "98.87.250.62/32",
    "98.88.57.244/32",
    "98.88.187.143/32",
    "98.89.99.238/32",
    "98.89.106.231/32",
    "98.89.197.159/32",
    "98.89.209.185/32",
    "98.90.98.103/32",
    "98.90.110.79/32",
    "98.90.125.157/32",
    "98.90.148.129/32",
    "98.90.215.62/32",
    "98.90.249.120/32",
    "98.91.44.166/32",
    "98.91.72.186/32",
    "98.91.94.136/32",
    "98.91.104.214/32",
    "98.91.110.187/32",
    "98.91.111.24/32",
    "98.91.143.225/32",
    "98.94.138.179/32",
    "98.94.142.186/32",
    "98.95.124.8/32",
    "100.24.90.135/32",
    "100.24.134.117/32",
    "100.24.149.244/32",
    "100.24.167.60/32",
    "100.25.9.234/32",
    "100.25.96.137/32",
    "100.25.103.91/32",
    "100.25.120.246/32",
    "100.26.7.250/32",
    "100.27.71.33/32",
    "100.27.79.68/32",
    "100.27.149.198/32",
    "100.27.153.9/32",
    "100.27.161.155/32",
    "100.28.44.58/32",
    "100.28.49.152/32",
    "100.28.57.133/32",
    "100.28.118.16/32",
    "100.28.133.214/32",
    "100.28.204.82/32",
    "100.28.245.118/32",
    "100.29.34.97/32",
    "100.29.48.32/32",
    "100.29.63.24/32",
    "100.29.70.220/32",
    "100.29.74.61/32",
    "100.29.107.38/32",
    "100.29.116.208/32",
    "100.29.126.60/32",
    "100.29.128.75/32",
    "100.29.148.60/32",
    "100.29.155.89/32",
    "100.29.160.53/32",
    "100.29.164.142/32",
    "100.29.164.178/32",
    "100.30.8.247/32",
    "100.30.43.47/32",
    "100.30.51.229/32",
    "100.30.88.88/32",
    "100.30.157.22/32",
    "100.31.32.118/32",
    "100.31.229.251/32",
    "100.48.38.64/32",
    "100.48.40.16/32",
    "100.48.126.46/32",
    "100.48.145.68/32",
    "100.48.254.147/32",
    "100.49.9.181/32",
    "100.49.11.239/32",
    "100.49.26.210/32",
    "100.49.87.166/32",
    "100.50.57.146/32",
    "100.50.82.187/32",
    "100.50.88.53/32",
    "100.50.92.12/32",
    "100.50.101.121/32",
    "100.50.195.113/32",
    "100.50.204.204/32",
    "100.51.28.129/32",
    "100.51.30.134/32",
    "100.51.131.3/32",
    "100.51.145.133/32",
    "100.51.173.237/32",
    "100.51.246.38/32",
    "100.51.251.51/32",
    "100.52.10.132/32",
    "100.52.56.144/32",
    "100.52.80.224/32",
    "100.52.115.57/32",
    "100.52.138.120/32",
    "100.52.138.205/32",
    "100.55.106.152/32",
    "100.55.188.3/32",
    "100.55.234.220/32",
    "100.56.51.40/32",
    "100.56.99.138/32",
    "100.56.112.244/32",
    "100.56.127.196/32",
    "100.56.142.210/32",
    "100.56.151.105/32",
    "100.56.195.235/32",
    "100.57.46.166/32",
    "100.57.60.108/32",
    "100.57.69.236/32",
    "100.57.70.187/32",
    "100.57.145.59/32",
    "100.57.194.146/32",
    "100.57.211.199/32",
    "100.57.216.250/32",
    "100.57.246.13/32",
    "100.58.4.37/32",
    "100.58.45.198/32",
    "100.59.145.242/32",
    "100.59.209.89/32",
    "100.59.227.61/32",
    "100.60.1.224/32",
    "100.60.51.118/32",
    "100.60.153.145/32",
    "100.60.159.110/32",
    "100.60.164.156/32",
    "100.60.181.98/32",
    "100.60.212.69/32",
    "100.60.218.80/32",
    "100.60.224.239/32",
    "100.60.230.7/32",
    "100.60.230.43/32",
    "100.61.20.229/32",
    "100.61.24.214/32",
    "100.61.64.186/32",
    "100.61.110.40/32",
    "100.61.251.108/32",
    "100.61.252.112/32",
    "100.62.132.114/32",
    "100.62.191.85/32",
    "100.62.205.149/32",
    "100.62.208.199/32",
    "100.62.224.15/32",
    "100.62.247.207/32",
    "100.63.9.237/32",
    "100.63.38.186/32",
    "100.63.167.112/32",
    "100.63.217.53/32",
    "100.63.226.160/32",
    "100.63.227.156/32",
    "100.63.236.174/32",
    "100.63.239.85/32",
    "107.20.25.33/32",
    "107.20.181.148/32",
    "107.20.224.184/32",
    "107.20.255.194/32",
    "107.21.4.76/32",
    "107.21.49.20/32",
    "107.21.171.94/32",
    "107.22.54.180/32",
    "107.22.208.39/32",
    "107.22.219.12/32",
    "107.23.62.75/32",
    "107.23.208.98/32",
    "174.129.20.137/32",
    "174.129.115.115/32",
    "174.129.131.108/32",
    "174.129.189.60/32",
    "174.129.242.195/32",
    "184.72.84.154/32",
    "184.72.95.195/32",
    "184.72.140.245/32",
    "184.73.35.182/32",
    "184.73.47.24/32",
    "184.73.68.20/32",
    "184.73.98.121/32",
    "184.73.126.164/32",
    "184.73.167.217/32",
    "184.73.175.194/32",
    "184.73.195.18/32",
    "184.73.216.192/32",
    "184.73.232.51/32",
    "184.73.239.35/32",
    "184.192.10.131/32",
    "184.192.13.104/32",
    "184.192.16.41/32",
    "184.192.17.38/32",
    "184.192.22.162/32",
    "184.192.32.200/32",
    "184.192.37.104/32",
    "184.192.45.148/32",
    "184.192.57.50/32",
    "184.192.58.249/32",
    "184.192.60.239/32",
    "184.192.65.160/32",
    "184.192.71.112/32",
    "184.192.75.146/32",
    "184.192.76.56/32",
    "184.192.87.53/32",
    "184.192.89.251/32",
    "184.192.90.88/32",
    "184.192.91.223/32",
    "184.192.111.161/32",
    "184.192.114.128/32",
    "184.192.119.173/32",
    "184.192.123.97/32",
    "184.192.124.134/32",
    "184.192.127.115/32",
    "184.192.132.218/32",
    "184.192.133.10/32",
    "184.192.138.135/32",
    "184.192.139.185/32",
    "184.192.142.177/32",
    "184.192.142.248/32",
    "184.192.145.41/32",
    "184.192.150.219/32",
    "184.192.153.80/32",
    "184.192.160.199/32",
    "184.192.161.161/32",
    "184.192.163.135/32",
    "184.192.166.248/32",
    "184.192.167.118/32",
    "184.192.172.179/32",
    "184.192.174.76/32",
    "184.192.175.55/32",
    "184.192.176.204/32",
    "184.192.180.115/32",
    "184.192.184.46/32",
    "184.192.189.128/32",
    "184.192.199.116/32",
    "184.192.199.181/32",
    "184.192.200.93/32",
    "184.192.200.176/32",
    "184.192.200.235/32",
    "184.192.202.136/32",
    "184.192.203.238/32",
    "184.192.210.213/32",
    "184.192.212.143/32",
    "184.192.212.212/32",
    "184.192.218.172/32",
    "184.192.228.95/32",
    "184.192.232.81/32",
    "184.192.232.184/32",
    "184.192.233.81/32",
    "184.192.233.216/32",
    "184.192.234.12/32",
    "184.192.234.21/32",
    "184.192.234.129/32",
    "184.192.234.200/32",
    "184.192.234.218/32",
    "184.192.234.235/32",
    "184.192.235.64/32",
    "184.192.235.146/32",
    "184.192.235.180/32",
    "184.192.236.147/32",
    "184.192.236.194/32",
    "184.192.236.219/32"
  ],
  /** 816 prefixes */
  "amzn-search-bot": [
    "3.82.67.224/32",
    "3.82.90.168/32",
    "3.83.75.212/32",
    "3.85.141.163/32",
    "3.86.74.89/32",
    "3.89.17.222/32",
    "3.89.155.158/32",
    "3.90.92.205/32",
    "3.90.117.221/32",
    "3.91.142.95/32",
    "3.91.164.253/32",
    "3.92.140.162/32",
    "3.93.116.95/32",
    "3.93.120.17/32",
    "3.94.185.94/32",
    "3.208.37.94/32",
    "3.208.113.39/32",
    "3.209.57.4/32",
    "3.209.71.33/32",
    "3.209.162.193/32",
    "3.210.17.17/32",
    "3.210.117.45/32",
    "3.210.238.203/32",
    "3.210.239.195/32",
    "3.211.100.186/32",
    "3.211.143.75/32",
    "3.211.158.39/32",
    "3.211.227.132/32",
    "3.212.138.251/32",
    "3.212.155.47/32",
    "3.213.103.242/32",
    "3.213.110.122/32",
    "3.213.117.114/32",
    "3.213.253.252/32",
    "3.214.51.149/32",
    "3.214.131.136/32",
    "3.214.235.2/32",
    "3.214.252.9/32",
    "3.215.155.189/32",
    "3.215.205.141/32",
    "3.216.26.183/32",
    "3.216.221.144/32",
    "3.216.244.57/32",
    "3.216.253.252/32",
    "3.217.20.26/32",
    "3.217.34.58/32",
    "3.217.34.183/32",
    "3.217.63.43/32",
    "3.217.66.30/32",
    "3.217.161.64/32",
    "3.218.2.114/32",
    "3.218.37.5/32",
    "3.219.6.124/32",
    "3.219.192.9/32",
    "3.219.192.12/32",
    "3.219.223.95/32",
    "3.220.71.23/32",
    "3.221.35.158/32",
    "3.221.56.120/32",
    "3.221.61.12/32",
    "3.221.116.68/32",
    "3.221.121.46/32",
    "3.221.167.25/32",
    "3.221.254.28/32",
    "3.222.16.22/32",
    "3.222.19.80/32",
    "3.222.127.245/32",
    "3.222.196.181/32",
    "3.222.252.213/32",
    "3.223.42.33/32",
    "3.223.100.234/32",
    "3.223.139.87/32",
    "3.223.155.74/32",
    "3.223.242.201/32",
    "3.224.45.108/32",
    "3.224.73.194/32",
    "3.224.123.189/32",
    "3.224.159.71/32",
    "3.224.205.7/32",
    "3.224.216.148/32",
    "3.225.111.192/32",
    "3.225.136.217/32",
    "3.225.200.77/32",
    "3.225.209.122/32",
    "3.226.3.62/32",
    "3.226.50.226/32",
    "3.226.139.230/32",
    "3.226.196.238/32",
    "3.226.229.153/32",
    "3.227.142.177/32",
    "3.227.227.6/32",
    "3.228.117.65/32",
    "3.228.151.92/32",
    "3.228.206.225/32",
    "3.229.67.114/32",
    "3.229.72.127/32",
    "3.229.219.29/32",
    "3.230.59.35/32",
    "3.230.179.91/32",
    "3.230.230.154/32",
    "3.230.250.35/32",
    "3.230.253.54/32",
    "3.231.178.162/32",
    "3.231.188.44/32",
    "3.232.18.244/32",
    "3.232.204.221/32",
    "3.232.253.211/32",
    "3.233.175.168/32",
    "3.233.189.187/32",
    "3.234.13.59/32",
    "3.234.28.73/32",
    "3.234.152.213/32",
    "13.216.24.101/32",
    "13.216.102.104/32",
    "13.216.187.148/32",
    "13.216.196.168/32",
    "13.219.54.187/32",
    "13.219.152.101/32",
    "13.219.170.211/32",
    "13.219.196.61/32",
    "13.222.91.251/32",
    "13.223.109.92/32",
    "13.223.163.204/32",
    "13.223.222.73/32",
    "18.204.69.251/32",
    "18.204.90.3/32",
    "18.205.13.0/32",
    "18.205.44.190/32",
    "18.205.140.254/32",
    "18.205.180.59/32",
    "18.206.50.226/32",
    "18.206.66.34/32",
    "18.206.69.92/32",
    "18.206.202.183/32",
    "18.207.88.6/32",
    "18.208.43.113/32",
    "18.208.95.0/32",
    "18.209.135.224/32",
    "18.209.142.234/32",
    "18.209.178.202/32",
    "18.210.45.73/32",
    "18.210.115.131/32",
    "18.210.225.20/32",
    "18.211.141.154/32",
    "18.213.84.33/32",
    "18.213.133.4/32",
    "18.213.249.250/32",
    "18.214.84.4/32",
    "18.214.124.101/32",
    "18.214.125.232/32",
    "18.214.186.114/32",
    "18.214.206.100/32",
    "18.215.42.159/32",
    "18.215.99.115/32",
    "18.215.135.45/32",
    "18.215.215.162/32",
    "18.233.44.129/32",
    "18.233.214.108/32",
    "18.233.235.66/32",
    "18.234.249.23/32",
    "18.235.234.69/32",
    "23.20.194.146/32",
    "23.21.30.253/32",
    "23.21.72.195/32",
    "23.21.115.175/32",
    "23.21.214.230/32",
    "23.21.236.157/32",
    "23.21.254.26/32",
    "23.22.4.24/32",
    "23.22.245.96/32",
    "23.22.246.84/32",
    "23.23.97.185/32",
    "23.23.138.175/32",
    "23.23.169.169/32",
    "23.23.188.58/32",
    "23.23.201.125/32",
    "23.23.214.73/32",
    "32.193.207.248/32",
    "32.193.230.132/32",
    "32.194.42.66/32",
    "32.196.238.12/32",
    "32.197.85.247/32",
    "32.197.106.56/32",
    "32.198.161.214/32",
    "32.199.114.136/32",
    "32.199.225.217/32",
    "34.192.94.60/32",
    "34.192.213.30/32",
    "34.192.224.176/32",
    "34.193.28.138/32",
    "34.193.137.18/32",
    "34.193.176.214/32",
    "34.194.81.161/32",
    "34.194.96.61/32",
    "34.194.165.188/32",
    "34.194.196.150/32",
    "34.194.236.194/32",
    "34.194.237.29/32",
    "34.195.79.160/32",
    "34.195.90.205/32",
    "34.195.194.181/32",
    "34.196.22.75/32",
    "34.196.127.79/32",
    "34.196.221.51/32",
    "34.197.25.140/32",
    "34.197.27.62/32",
    "34.197.154.32/32",
    "34.197.240.80/32",
    "34.197.246.201/32",
    "34.198.33.203/32",
    "34.198.41.184/32",
    "34.198.117.140/32",
    "34.198.223.196/32",
    "34.199.0.168/32",
    "34.199.2.135/32",
    "34.199.111.130/32",
    "34.199.134.92/32",
    "34.200.55.56/32",
    "34.200.59.71/32",
    "34.200.178.28/32",
    "34.200.190.72/32",
    "34.201.89.57/32",
    "34.201.229.234/32",
    "34.201.230.145/32",
    "34.203.29.230/32",
    "34.203.33.121/32",
    "34.204.31.92/32",
    "34.204.82.126/32",
    "34.204.145.175/32",
    "34.204.234.171/32",
    "34.206.13.250/32",
    "34.206.127.169/32",
    "34.206.160.62/32",
    "34.206.189.108/32",
    "34.207.31.244/32",
    "34.207.190.20/32",
    "34.224.5.130/32",
    "34.224.43.52/32",
    "34.224.104.19/32",
    "34.224.135.86/32",
    "34.224.242.232/32",
    "34.225.204.15/32",
    "34.225.220.51/32",
    "34.225.241.157/32",
    "34.226.77.125/32",
    "34.226.171.86/32",
    "34.226.176.13/32",
    "34.227.89.68/32",
    "34.227.210.84/32",
    "34.227.211.218/32",
    "34.228.0.97/32",
    "34.228.124.71/32",
    "34.229.27.119/32",
    "34.229.55.190/32",
    "34.230.225.128/32",
    "34.231.91.210/32",
    "34.231.191.101/32",
    "34.231.198.5/32",
    "34.232.233.214/32",
    "34.233.138.154/32",
    "34.233.177.9/32",
    "34.233.191.178/32",
    "34.233.249.54/32",
    "34.234.21.24/32",
    "34.234.177.179/32",
    "34.234.182.15/32",
    "34.234.221.209/32",
    "34.235.6.168/32",
    "34.235.19.146/32",
    "34.235.221.79/32",
    "34.235.227.102/32",
    "34.236.65.219/32",
    "34.236.66.23/32",
    "34.236.163.131/32",
    "34.237.22.79/32",
    "34.237.37.16/32",
    "34.238.12.204/32",
    "34.238.63.49/32",
    "34.238.66.168/32",
    "34.238.75.183/32",
    "34.238.132.4/32",
    "34.239.77.160/32",
    "34.239.87.171/32",
    "34.239.90.1/32",
    "34.239.253.240/32",
    "35.153.187.89/32",
    "35.168.48.89/32",
    "35.168.75.176/32",
    "35.168.147.87/32",
    "35.168.181.24/32",
    "35.169.1.17/32",
    "35.169.2.39/32",
    "35.169.2.149/32",
    "35.169.74.227/32",
    "35.169.106.154/32",
    "35.169.110.137/32",
    "35.170.104.4/32",
    "35.170.105.219/32",
    "35.170.123.50/32",
    "35.170.123.152/32",
    "35.171.37.0/32",
    "35.171.77.201/32",
    "35.171.190.227/32",
    "35.171.199.44/32",
    "35.171.200.29/32",
    "35.172.15.28/32",
    "35.172.125.46/32",
    "35.172.188.13/32",
    "35.173.101.225/32",
    "35.173.123.161/32",
    "35.174.28.56/32",
    "35.175.65.253/32",
    "35.175.132.11/32",
    "44.193.34.148/32",
    "44.193.96.92/32",
    "44.194.47.12/32",
    "44.194.84.22/32",
    "44.194.124.103/32",
    "44.194.165.181/32",
    "44.195.71.32/32",
    "44.195.217.176/32",
    "44.196.9.78/32",
    "44.196.83.48/32",
    "44.196.116.215/32",
    "44.196.118.139/32",
    "44.196.235.241/32",
    "44.197.4.190/32",
    "44.197.254.236/32",
    "44.198.66.156/32",
    "44.198.230.203/32",
    "44.199.62.58/32",
    "44.199.112.216/32",
    "44.199.145.199/32",
    "44.205.173.56/32",
    "44.205.208.84/32",
    "44.206.81.21/32",
    "44.206.127.11/32",
    "44.206.217.175/32",
    "44.207.64.241/32",
    "44.208.55.64/32",
    "44.208.90.52/32",
    "44.208.239.245/32",
    "44.209.121.79/32",
    "44.209.167.138/32",
    "44.209.243.164/32",
    "44.210.22.203/32",
    "44.210.41.97/32",
    "44.210.169.22/32",
    "44.210.170.50/32",
    "44.210.179.109/32",
    "44.210.189.34/32",
    "44.210.225.188/32",
    "44.211.6.49/32",
    "44.212.202.62/32",
    "44.212.207.23/32",
    "44.212.241.192/32",
    "44.212.251.138/32",
    "44.213.56.230/32",
    "44.213.206.151/32",
    "44.213.211.166/32",
    "44.213.228.74/32",
    "44.213.241.45/32",
    "44.215.74.155/32",
    "44.215.99.191/32",
    "44.215.159.243/32",
    "44.215.171.38/32",
    "44.216.105.237/32",
    "44.216.173.42/32",
    "44.216.177.139/32",
    "44.216.239.225/32",
    "44.217.43.241/32",
    "44.217.64.212/32",
    "44.217.156.115/32",
    "44.217.164.115/32",
    "44.217.204.19/32",
    "44.217.221.211/32",
    "44.217.223.236/32",
    "44.217.237.69/32",
    "44.217.251.254/32",
    "44.218.56.203/32",
    "44.218.61.226/32",
    "44.218.248.140/32",
    "44.218.253.125/32",
    "44.219.149.9/32",
    "44.219.225.200/32",
    "44.219.225.212/32",
    "44.221.129.95/32",
    "44.221.203.99/32",
    "44.221.241.220/32",
    "44.221.244.76/32",
    "44.223.253.120/32",
    "50.17.88.23/32",
    "50.19.98.34/32",
    "50.19.173.230/32",
    "52.0.114.157/32",
    "52.0.207.54/32",
    "52.0.236.109/32",
    "52.1.97.122/32",
    "52.1.233.104/32",
    "52.2.191.37/32",
    "52.3.17.185/32",
    "52.3.30.234/32",
    "52.3.62.173/32",
    "52.3.91.235/32",
    "52.3.193.39/32",
    "52.3.251.73/32",
    "52.4.189.224/32",
    "52.4.251.246/32",
    "52.5.12.245/32",
    "52.5.20.105/32",
    "52.5.45.215/32",
    "52.5.113.11/32",
    "52.6.24.217/32",
    "52.6.54.116/32",
    "52.6.57.17/32",
    "52.6.171.10/32",
    "52.6.216.48/32",
    "52.6.231.0/32",
    "52.7.48.229/32",
    "52.7.126.210/32",
    "52.7.171.101/32",
    "52.7.225.39/32",
    "52.7.227.80/32",
    "52.7.249.12/32",
    "52.20.27.34/32",
    "52.20.85.108/32",
    "52.20.124.247/32",
    "52.20.158.171/32",
    "52.20.234.254/32",
    "52.21.93.114/32",
    "52.21.99.253/32",
    "52.21.133.215/32",
    "52.22.52.60/32",
    "52.22.75.143/32",
    "52.22.233.217/32",
    "52.23.69.1/32",
    "52.44.115.134/32",
    "52.44.199.164/32",
    "52.45.83.81/32",
    "52.45.194.99/32",
    "52.45.211.110/32",
    "52.54.130.150/32",
    "52.55.107.99/32",
    "52.70.16.42/32",
    "52.70.37.172/32",
    "52.70.95.48/32",
    "52.70.226.93/32",
    "52.71.16.223/32",
    "52.71.72.39/32",
    "52.71.144.112/32",
    "52.71.159.156/32",
    "52.71.205.86/32",
    "52.71.243.5/32",
    "52.72.227.157/32",
    "52.73.35.133/32",
    "52.87.75.190/32",
    "52.87.216.218/32",
    "52.200.64.94/32",
    "52.200.125.80/32",
    "52.200.198.83/32",
    "52.200.202.121/32",
    "52.200.244.204/32",
    "52.201.26.95/32",
    "52.201.77.2/32",
    "52.201.114.98/32",
    "52.201.149.75/32",
    "52.202.15.97/32",
    "52.202.30.225/32",
    "52.202.160.12/32",
    "52.202.182.148/32",
    "52.202.234.14/32",
    "52.203.139.107/32",
    "52.203.235.174/32",
    "52.204.1.121/32",
    "52.204.203.171/32",
    "52.205.16.194/32",
    "52.206.29.234/32",
    "52.206.59.229/32",
    "52.206.116.153/32",
    "52.206.129.89/32",
    "52.206.188.45/32",
    "52.207.6.18/32",
    "52.207.43.63/32",
    "54.80.143.10/32",
    "54.81.2.245/32",
    "54.81.15.167/32",
    "54.81.32.142/32",
    "54.81.126.112/32",
    "54.82.2.214/32",
    "54.83.18.137/32",
    "54.83.58.194/32",
    "54.83.126.221/32",
    "54.83.172.18/32",
    "54.84.71.94/32",
    "54.84.83.113/32",
    "54.84.160.219/32",
    "54.84.185.230/32",
    "54.85.38.148/32",
    "54.85.95.196/32",
    "54.85.178.213/32",
    "54.87.216.234/32",
    "54.87.255.90/32",
    "54.88.60.135/32",
    "54.88.236.97/32",
    "54.89.16.186/32",
    "54.89.45.9/32",
    "54.89.69.250/32",
    "54.89.70.93/32",
    "54.90.18.3/32",
    "54.90.28.43/32",
    "54.90.227.223/32",
    "54.91.249.2/32",
    "54.92.148.34/32",
    "54.92.203.235/32",
    "54.145.34.70/32",
    "54.145.161.111/32",
    "54.146.71.85/32",
    "54.147.14.240/32",
    "54.147.66.130/32",
    "54.147.119.34/32",
    "54.147.229.64/32",
    "54.157.89.253/32",
    "54.157.138.252/32",
    "54.157.208.183/32",
    "54.158.133.188/32",
    "54.158.154.192/32",
    "54.159.237.70/32",
    "54.160.45.52/32",
    "54.161.25.53/32",
    "54.161.157.185/32",
    "54.162.54.187/32",
    "54.162.153.212/32",
    "54.163.22.228/32",
    "54.163.82.179/32",
    "54.163.123.236/32",
    "54.165.95.216/32",
    "54.165.171.73/32",
    "54.165.202.67/32",
    "54.165.205.16/32",
    "54.166.24.13/32",
    "54.166.70.223/32",
    "54.167.5.166/32",
    "54.167.94.112/32",
    "54.167.133.42/32",
    "54.167.188.181/32",
    "54.172.50.210/32",
    "54.172.92.66/32",
    "54.172.176.34/32",
    "54.173.156.58/32",
    "54.173.160.86/32",
    "54.173.161.122/32",
    "54.174.127.227/32",
    "54.174.161.242/32",
    "54.175.167.28/32",
    "54.196.187.118/32",
    "54.204.10.196/32",
    "54.204.14.125/32",
    "54.204.105.49/32",
    "54.204.159.166/32",
    "54.204.189.191/32",
    "54.205.6.162/32",
    "54.205.7.250/32",
    "54.205.137.236/32",
    "54.208.186.113/32",
    "54.208.229.84/32",
    "54.209.33.199/32",
    "54.209.59.28/32",
    "54.209.67.252/32",
    "54.209.139.3/32",
    "54.210.16.158/32",
    "54.210.47.231/32",
    "54.210.51.122/32",
    "54.221.233.6/32",
    "54.224.159.224/32",
    "54.225.210.250/32",
    "54.225.211.168/32",
    "54.225.220.226/32",
    "54.226.54.148/32",
    "54.227.95.204/32",
    "54.227.122.71/32",
    "54.227.250.126/32",
    "54.234.109.91/32",
    "54.234.156.138/32",
    "54.234.227.173/32",
    "54.235.183.179/32",
    "54.235.187.99/32",
    "54.236.77.176/32",
    "54.236.90.239/32",
    "54.236.146.97/32",
    "54.236.180.98/32",
    "54.236.184.238/32",
    "54.236.251.98/32",
    "54.237.229.245/32",
    "54.242.155.65/32",
    "54.243.78.23/32",
    "54.243.119.155/32",
    "54.243.128.188/32",
    "54.243.172.250/32",
    "54.243.185.76/32",
    "54.243.211.63/32",
    "72.44.45.175/32",
    "75.101.144.251/32",
    "98.80.36.221/32",
    "98.80.83.102/32",
    "98.82.61.199/32",
    "98.82.68.7/32",
    "98.82.78.131/32",
    "98.82.83.103/32",
    "98.82.193.30/32",
    "98.82.238.39/32",
    "98.83.194.21/32",
    "98.83.194.176/32",
    "98.84.79.84/32",
    "98.84.86.216/32",
    "98.84.185.30/32",
    "98.84.242.117/32",
    "98.85.153.239/32",
    "98.85.191.237/32",
    "98.85.194.38/32",
    "98.86.33.14/32",
    "98.86.38.110/32",
    "98.86.69.65/32",
    "98.86.83.164/32",
    "98.86.93.251/32",
    "98.86.101.20/32",
    "98.86.133.40/32",
    "98.86.217.46/32",
    "98.87.182.1/32",
    "98.87.203.235/32",
    "98.87.218.210/32",
    "98.88.3.219/32",
    "98.88.4.13/32",
    "98.88.4.160/32",
    "98.88.43.210/32",
    "98.88.67.17/32",
    "98.88.114.29/32",
    "98.88.146.174/32",
    "98.88.180.222/32",
    "98.88.186.79/32",
    "98.88.219.59/32",
    "98.88.224.25/32",
    "98.88.234.184/32",
    "98.88.240.41/32",
    "98.89.74.239/32",
    "98.89.89.208/32",
    "98.89.110.216/32",
    "98.89.176.131/32",
    "98.89.191.68/32",
    "98.89.198.186/32",
    "98.89.238.137/32",
    "98.89.254.223/32",
    "98.89.255.185/32",
    "98.90.1.201/32",
    "98.90.53.3/32",
    "98.90.53.72/32",
    "98.90.93.167/32",
    "98.90.129.48/32",
    "98.90.132.132/32",
    "98.90.144.220/32",
    "98.90.155.195/32",
    "98.90.166.177/32",
    "98.90.171.206/32",
    "98.90.212.161/32",
    "98.91.3.186/32",
    "98.91.9.192/32",
    "98.91.81.246/32",
    "98.91.91.18/32",
    "98.91.104.211/32",
    "98.91.120.100/32",
    "98.91.142.137/32",
    "98.91.147.104/32",
    "98.91.150.214/32",
    "98.91.160.54/32",
    "98.91.171.8/32",
    "98.94.116.10/32",
    "98.94.126.135/32",
    "98.94.137.118/32",
    "98.94.149.8/32",
    "98.94.158.230/32",
    "98.94.164.245/32",
    "98.94.174.49/32",
    "98.94.174.228/32",
    "98.94.180.226/32",
    "98.94.182.242/32",
    "98.94.188.12/32",
    "98.94.193.28/32",
    "98.94.196.171/32",
    "98.94.202.176/32",
    "98.94.203.213/32",
    "98.94.208.188/32",
    "98.94.209.71/32",
    "98.94.216.122/32",
    "98.94.225.199/32",
    "98.94.225.207/32",
    "98.94.228.253/32",
    "98.94.237.222/32",
    "98.94.240.137/32",
    "98.94.246.215/32",
    "98.94.252.84/32",
    "98.94.253.137/32",
    "98.95.1.231/32",
    "98.95.7.71/32",
    "98.95.20.69/32",
    "98.95.23.214/32",
    "98.95.23.228/32",
    "98.95.34.178/32",
    "98.95.37.200/32",
    "98.95.38.161/32",
    "98.95.39.39/32",
    "98.95.44.247/32",
    "98.95.49.54/32",
    "98.95.55.232/32",
    "98.95.56.98/32",
    "98.95.56.240/32",
    "98.95.62.182/32",
    "98.95.65.140/32",
    "98.95.74.218/32",
    "98.95.89.44/32",
    "98.95.91.59/32",
    "98.95.100.253/32",
    "98.95.104.207/32",
    "98.95.106.159/32",
    "98.95.110.94/32",
    "98.95.120.52/32",
    "98.95.126.63/32",
    "98.95.129.148/32",
    "98.95.130.0/32",
    "98.95.145.11/32",
    "98.95.148.56/32",
    "98.95.150.125/32",
    "98.95.156.127/32",
    "98.95.159.241/32",
    "98.95.161.76/32",
    "98.95.161.103/32",
    "98.95.162.121/32",
    "98.95.174.52/32",
    "98.95.175.92/32",
    "100.24.190.202/32",
    "100.25.17.231/32",
    "100.25.30.152/32",
    "100.25.127.167/32",
    "100.25.153.201/32",
    "100.25.199.161/32",
    "100.26.122.24/32",
    "100.27.85.243/32",
    "100.28.152.127/32",
    "100.28.177.247/32",
    "100.29.59.194/32",
    "100.29.157.182/32",
    "100.31.22.225/32",
    "100.31.34.200/32",
    "100.48.0.143/32",
    "100.48.137.73/32",
    "100.48.162.26/32",
    "100.49.196.199/32",
    "100.50.44.58/32",
    "100.50.76.106/32",
    "100.50.108.84/32",
    "100.50.153.151/32",
    "100.51.22.85/32",
    "100.51.81.206/32",
    "100.51.156.79/32",
    "100.52.70.176/32",
    "100.55.111.152/32",
    "100.55.191.83/32",
    "100.56.25.168/32",
    "100.57.68.185/32",
    "100.58.26.90/32",
    "100.58.39.170/32",
    "100.58.52.102/32",
    "100.58.57.149/32",
    "100.58.58.209/32",
    "100.59.72.83/32",
    "100.59.254.242/32",
    "100.60.14.30/32",
    "100.60.123.70/32",
    "100.60.141.252/32",
    "100.60.170.171/32",
    "100.60.204.184/32",
    "100.60.204.250/32",
    "100.61.92.1/32",
    "100.62.13.116/32",
    "100.62.157.123/32",
    "100.62.179.212/32",
    "100.62.186.188/32",
    "107.20.21.185/32",
    "107.20.124.65/32",
    "107.20.132.237/32",
    "107.20.164.28/32",
    "107.20.195.185/32",
    "107.21.9.54/32",
    "107.21.62.197/32",
    "107.22.6.189/32",
    "107.22.145.162/32",
    "107.22.199.65/32",
    "107.23.25.176/32",
    "107.23.41.220/32",
    "174.129.228.153/32",
    "184.72.137.83/32",
    "184.73.10.164/32",
    "184.73.154.145/32",
    "184.192.3.139/32",
    "184.192.68.254/32",
    "184.192.125.80/32",
    "184.192.132.1/32",
    "184.192.160.224/32",
    "184.192.172.115/32",
    "184.192.201.21/32",
    "184.192.207.91/32",
    "184.192.211.188/32",
    "184.192.212.181/32",
    "184.192.213.86/32",
    "184.192.213.200/32",
    "184.192.214.49/32",
    "184.192.214.62/32",
    "184.192.215.194/32"
  ],
  /** 1023 prefixes */
  "amzn-user": [
    "100.24.86.21/32",
    "100.24.94.158/32",
    "100.25.233.255/32",
    "100.26.69.34/32",
    "100.27.118.106/32",
    "100.27.157.160/32",
    "100.27.158.82/32",
    "100.27.169.147/32",
    "100.27.91.246/32",
    "100.28.104.194/32",
    "100.28.113.237/32",
    "100.28.151.241/32",
    "100.28.33.208/32",
    "100.29.104.31/32",
    "100.29.106.130/32",
    "100.29.122.28/32",
    "100.29.92.161/32",
    "107.20.201.23/32",
    "107.20.42.162/32",
    "107.21.114.117/32",
    "107.21.229.211/32",
    "107.22.218.90/32",
    "107.22.241.68/32",
    "107.22.255.3/32",
    "107.22.55.149/32",
    "107.22.87.58/32",
    "107.23.190.53/32",
    "107.23.242.35/32",
    "107.23.56.227/32",
    "13.216.113.150/32",
    "13.216.136.62/32",
    "13.216.143.182/32",
    "13.216.152.158/32",
    "13.216.162.32/32",
    "13.216.169.197/32",
    "13.216.27.246/32",
    "13.217.158.72/32",
    "13.218.255.40/32",
    "13.219.0.206/32",
    "13.219.122.158/32",
    "13.219.125.104/32",
    "13.219.138.92/32",
    "13.219.15.124/32",
    "13.219.173.86/32",
    "13.219.211.133/32",
    "13.219.48.105/32",
    "13.222.48.80/32",
    "13.222.68.90/32",
    "13.223.10.22/32",
    "13.223.112.99/32",
    "13.223.12.55/32",
    "13.223.123.7/32",
    "13.223.125.191/32",
    "13.223.127.163/32",
    "13.223.135.149/32",
    "13.223.141.183/32",
    "13.223.143.171/32",
    "13.223.208.86/32",
    "13.223.212.171/32",
    "13.223.219.110/32",
    "13.223.222.177/32",
    "13.223.237.145/32",
    "13.223.32.32/32",
    "13.223.33.67/32",
    "174.129.24.225/32",
    "18.204.129.185/32",
    "18.204.147.58/32",
    "18.204.174.34/32",
    "18.204.200.202/32",
    "18.204.77.144/32",
    "18.205.121.5/32",
    "18.205.170.69/32",
    "18.205.179.96/32",
    "18.205.207.200/32",
    "18.205.94.193/32",
    "18.206.10.25/32",
    "18.206.102.242/32",
    "18.206.103.117/32",
    "18.206.31.0/32",
    "18.206.49.169/32",
    "18.206.63.178/32",
    "18.206.75.17/32",
    "18.206.80.142/32",
    "18.207.68.55/32",
    "18.207.71.20/32",
    "18.207.79.53/32",
    "18.208.49.162/32",
    "18.208.68.221/32",
    "18.208.96.116/32",
    "18.209.149.152/32",
    "18.209.155.76/32",
    "18.209.183.128/32",
    "18.209.189.61/32",
    "18.210.135.253/32",
    "18.210.143.14/32",
    "18.210.177.112/32",
    "18.210.211.84/32",
    "18.210.58.248/32",
    "18.210.79.138/32",
    "18.210.88.179/32",
    "18.211.100.116/32",
    "18.211.172.15/32",
    "18.211.184.127/32",
    "18.211.228.10/32",
    "18.213.102.71/32",
    "18.213.108.226/32",
    "18.213.174.38/32",
    "18.213.18.100/32",
    "18.213.225.24/32",
    "18.214.155.227/32",
    "18.214.160.25/32",
    "18.214.180.93/32",
    "18.214.202.10/32",
    "18.214.208.13/32",
    "18.214.236.252/32",
    "18.214.32.251/32",
    "18.214.97.194/32",
    "18.215.133.216/32",
    "18.215.19.140/32",
    "18.215.37.82/32",
    "18.215.81.159/32",
    "18.232.221.67/32",
    "18.233.242.106/32",
    "18.233.247.66/32",
    "18.233.254.6/32",
    "18.233.44.115/32",
    "18.233.52.165/32",
    "18.235.117.231/32",
    "18.235.176.68/32",
    "184.72.220.200/32",
    "184.72.231.109/32",
    "184.72.242.66/32",
    "184.73.1.121/32",
    "184.73.212.232/32",
    "23.20.14.164/32",
    "23.20.14.43/32",
    "23.20.157.74/32",
    "23.20.190.101/32",
    "23.21.161.204/32",
    "23.21.164.86/32",
    "23.21.226.79/32",
    "23.21.74.3/32",
    "23.21.78.102/32",
    "23.22.140.49/32",
    "23.22.164.241/32",
    "23.22.236.99/32",
    "23.22.87.173/32",
    "23.22.87.189/32",
    "23.23.111.110/32",
    "23.23.152.43/32",
    "23.23.16.236/32",
    "23.23.201.145/32",
    "23.23.209.179/32",
    "3.208.167.128/32",
    "3.208.247.204/32",
    "3.208.46.236/32",
    "3.209.130.7/32",
    "3.210.93.112/32",
    "3.211.144.3/32",
    "3.211.145.5/32",
    "3.211.153.227/32",
    "3.211.177.14/32",
    "3.211.189.40/32",
    "3.211.192.237/32",
    "3.211.199.193/32",
    "3.211.22.7/32",
    "3.211.99.154/32",
    "3.212.148.16/32",
    "3.212.151.142/32",
    "3.212.155.239/32",
    "3.212.155.80/32",
    "3.212.20.54/32",
    "3.212.203.251/32",
    "3.212.205.155/32",
    "3.213.119.107/32",
    "3.213.132.166/32",
    "3.213.183.18/32",
    "3.213.192.229/32",
    "3.213.205.133/32",
    "3.213.223.246/32",
    "3.213.23.95/32",
    "3.213.74.26/32",
    "3.213.80.230/32",
    "3.214.107.231/32",
    "3.214.110.59/32",
    "3.214.154.139/32",
    "3.214.173.19/32",
    "3.214.189.85/32",
    "3.214.213.94/32",
    "3.215.193.161/32",
    "3.215.254.248/32",
    "3.215.8.42/32",
    "3.215.85.254/32",
    "3.216.16.254/32",
    "3.216.24.167/32",
    "3.216.83.21/32",
    "3.217.124.227/32",
    "3.217.155.115/32",
    "3.217.166.57/32",
    "3.217.186.68/32",
    "3.217.47.198/32",
    "3.217.54.78/32",
    "3.217.93.234/32",
    "3.218.11.113/32",
    "3.218.125.55/32",
    "3.218.140.139/32",
    "3.218.177.210/32",
    "3.218.184.146/32",
    "3.218.191.159/32",
    "3.218.226.239/32",
    "3.218.255.41/32",
    "3.218.35.149/32",
    "3.218.68.30/32",
    "3.219.10.249/32",
    "3.219.103.72/32",
    "3.219.249.170/32",
    "3.219.27.100/32",
    "3.219.52.199/32",
    "3.219.98.171/32",
    "3.220.134.7/32",
    "3.220.2.22/32",
    "3.220.89.3/32",
    "3.221.105.67/32",
    "3.221.110.107/32",
    "3.221.204.121/32",
    "3.221.221.12/32",
    "3.221.252.69/32",
    "3.222.193.181/32",
    "3.222.195.11/32",
    "3.222.22.183/32",
    "3.222.57.253/32",
    "3.223.130.34/32",
    "3.223.132.246/32",
    "3.223.148.78/32",
    "3.223.173.19/32",
    "3.223.212.88/32",
    "3.223.245.225/32",
    "3.223.37.137/32",
    "3.224.3.11/32",
    "3.224.66.185/32",
    "3.224.95.40/32",
    "3.225.112.119/32",
    "3.225.130.6/32",
    "3.225.214.36/32",
    "3.225.250.64/32",
    "3.225.254.186/32",
    "3.225.27.26/32",
    "3.226.118.11/32",
    "3.226.168.167/32",
    "3.226.198.163/32",
    "3.226.230.216/32",
    "3.226.55.191/32",
    "3.226.85.33/32",
    "3.227.129.67/32",
    "3.227.179.202/32",
    "3.227.195.183/32",
    "3.228.145.87/32",
    "3.228.187.171/32",
    "3.228.43.75/32",
    "3.228.90.152/32",
    "3.229.141.83/32",
    "3.229.147.55/32",
    "3.229.204.29/32",
    "3.229.206.235/32",
    "3.229.254.1/32",
    "3.229.69.123/32",
    "3.229.88.194/32",
    "3.230.138.76/32",
    "3.230.149.251/32",
    "3.230.15.20/32",
    "3.230.29.144/32",
    "3.230.47.56/32",
    "3.230.52.168/32",
    "3.230.90.160/32",
    "3.230.99.92/32",
    "3.231.179.13/32",
    "3.231.88.131/32",
    "3.232.137.33/32",
    "3.232.180.42/32",
    "3.232.19.149/32",
    "3.232.197.101/32",
    "3.232.20.91/32",
    "3.232.221.166/32",
    "3.232.235.15/32",
    "3.232.240.88/32",
    "3.233.103.22/32",
    "3.233.121.160/32",
    "3.233.183.168/32",
    "3.233.218.90/32",
    "3.233.93.65/32",
    "3.234.161.147/32",
    "3.234.185.44/32",
    "3.234.47.132/32",
    "3.234.77.32/32",
    "3.234.8.148/32",
    "3.235.12.133/32",
    "3.235.125.9/32",
    "3.81.194.188/32",
    "3.81.253.151/32",
    "3.82.135.179/32",
    "3.82.29.30/32",
    "3.84.64.201/32",
    "3.85.182.19/32",
    "3.86.137.101/32",
    "3.87.104.37/32",
    "3.88.92.27/32",
    "3.89.14.22/32",
    "3.89.14.224/32",
    "3.89.213.23/32",
    "3.91.124.128/32",
    "3.92.14.207/32",
    "3.93.132.173/32",
    "3.94.154.72/32",
    "3.94.216.37/32",
    "3.94.225.17/32",
    "3.94.226.92/32",
    "3.94.34.209/32",
    "3.95.79.208/32",
    "3.95.81.91/32",
    "3.95.96.198/32",
    "34.192.141.13/32",
    "34.192.213.97/32",
    "34.192.238.32/32",
    "34.192.33.34/32",
    "34.192.98.253/32",
    "34.193.131.3/32",
    "34.194.118.119/32",
    "34.194.149.187/32",
    "34.194.219.117/32",
    "34.194.219.191/32",
    "34.194.47.173/32",
    "34.195.225.185/32",
    "34.195.23.213/32",
    "34.195.45.53/32",
    "34.196.142.152/32",
    "34.196.155.48/32",
    "34.196.169.196/32",
    "34.196.187.85/32",
    "34.196.42.137/32",
    "34.196.80.7/32",
    "34.197.143.174/32",
    "34.197.149.47/32",
    "34.197.153.75/32",
    "34.197.175.171/32",
    "34.197.2.163/32",
    "34.197.201.73/32",
    "34.197.209.185/32",
    "34.197.73.235/32",
    "34.198.130.224/32",
    "34.198.143.69/32",
    "34.198.162.37/32",
    "34.198.56.37/32",
    "34.198.82.162/32",
    "34.199.156.195/32",
    "34.199.25.251/32",
    "34.200.114.155/32",
    "34.200.159.199/32",
    "34.200.169.53/32",
    "34.200.192.85/32",
    "34.200.203.147/32",
    "34.200.205.234/32",
    "34.200.74.100/32",
    "34.200.81.78/32",
    "34.200.86.207/32",
    "34.202.2.123/32",
    "34.202.30.230/32",
    "34.202.41.56/32",
    "34.202.49.146/32",
    "34.203.149.5/32",
    "34.203.99.163/32",
    "34.204.104.43/32",
    "34.204.215.184/32",
    "34.204.57.203/32",
    "34.205.201.97/32",
    "34.205.238.95/32",
    "34.206.101.22/32",
    "34.206.135.181/32",
    "34.207.48.202/32",
    "34.207.52.183/32",
    "34.224.114.26/32",
    "34.224.120.185/32",
    "34.224.190.94/32",
    "34.225.108.229/32",
    "34.225.133.0/32",
    "34.225.171.229/32",
    "34.226.125.221/32",
    "34.226.51.110/32",
    "34.226.56.238/32",
    "34.226.69.93/32",
    "34.227.118.181/32",
    "34.227.131.153/32",
    "34.227.239.141/32",
    "34.227.42.212/32",
    "34.228.109.18/32",
    "34.230.156.160/32",
    "34.230.234.54/32",
    "34.230.255.232/32",
    "34.231.114.104/32",
    "34.231.184.75/32",
    "34.231.68.10/32",
    "34.231.81.35/32",
    "34.232.184.48/32",
    "34.232.187.124/32",
    "34.232.47.104/32",
    "34.233.148.122/32",
    "34.233.151.134/32",
    "34.233.255.1/32",
    "34.233.36.75/32",
    "34.233.48.215/32",
    "34.233.97.140/32",
    "34.234.14.185/32",
    "34.234.154.134/32",
    "34.235.11.182/32",
    "34.236.104.213/32",
    "34.236.123.186/32",
    "34.236.132.205/32",
    "34.236.132.67/32",
    "34.236.164.210/32",
    "34.236.166.107/32",
    "34.236.209.30/32",
    "34.236.214.169/32",
    "34.236.224.25/32",
    "34.236.253.178/32",
    "34.237.147.161/32",
    "34.237.191.141/32",
    "34.237.207.92/32",
    "34.237.208.14/32",
    "34.237.227.70/32",
    "34.237.232.130/32",
    "34.237.80.208/32",
    "34.237.99.86/32",
    "34.238.107.122/32",
    "34.238.18.3/32",
    "34.238.71.63/32",
    "34.239.15.203/32",
    "34.239.188.168/32",
    "34.239.195.85/32",
    "34.239.206.162/32",
    "34.239.68.202/32",
    "35.153.10.9/32",
    "35.153.107.141/32",
    "35.153.113.217/32",
    "35.153.124.65/32",
    "35.153.197.87/32",
    "35.153.36.100/32",
    "35.168.104.113/32",
    "35.168.183.119/32",
    "35.168.44.111/32",
    "35.169.122.102/32",
    "35.169.198.60/32",
    "35.169.212.245/32",
    "35.169.251.66/32",
    "35.169.56.220/32",
    "35.170.223.99/32",
    "35.171.215.147/32",
    "35.171.218.156/32",
    "35.171.77.2/32",
    "35.172.188.66/32",
    "35.172.62.192/32",
    "35.172.84.121/32",
    "35.173.12.118/32",
    "35.173.12.250/32",
    "35.173.140.109/32",
    "35.173.160.101/32",
    "35.173.172.43/32",
    "35.173.53.155/32",
    "35.174.214.80/32",
    "35.174.229.240/32",
    "35.174.232.222/32",
    "35.174.97.70/32",
    "35.175.22.142/32",
    "35.175.34.176/32",
    "35.175.43.19/32",
    "44.193.128.83/32",
    "44.193.136.188/32",
    "44.193.149.106/32",
    "44.193.163.140/32",
    "44.193.21.207/32",
    "44.194.163.207/32",
    "44.194.194.219/32",
    "44.194.203.102/32",
    "44.194.222.211/32",
    "44.194.70.31/32",
    "44.195.151.174/32",
    "44.195.16.2/32",
    "44.195.178.236/32",
    "44.195.228.45/32",
    "44.195.245.78/32",
    "44.195.248.164/32",
    "44.195.96.4/32",
    "44.196.132.20/32",
    "44.196.15.171/32",
    "44.196.210.221/32",
    "44.196.236.142/32",
    "44.197.30.79/32",
    "44.197.95.23/32",
    "44.198.105.147/32",
    "44.198.125.78/32",
    "44.198.131.235/32",
    "44.198.134.204/32",
    "44.198.205.87/32",
    "44.198.237.57/32",
    "44.205.109.175/32",
    "44.205.197.17/32",
    "44.205.215.215/32",
    "44.205.36.200/32",
    "44.205.58.205/32",
    "44.205.68.181/32",
    "44.206.129.15/32",
    "44.206.15.195/32",
    "44.206.184.47/32",
    "44.206.40.110/32",
    "44.206.84.82/32",
    "44.207.127.111/32",
    "44.207.135.147/32",
    "44.207.169.172/32",
    "44.207.194.222/32",
    "44.207.229.212/32",
    "44.207.26.24/32",
    "44.207.83.128/32",
    "44.208.104.56/32",
    "44.208.16.208/32",
    "44.208.200.219/32",
    "44.208.203.166/32",
    "44.208.236.62/32",
    "44.208.56.213/32",
    "44.208.77.108/32",
    "44.208.83.208/32",
    "44.208.85.236/32",
    "44.209.162.73/32",
    "44.210.192.115/32",
    "44.212.148.132/32",
    "44.212.198.85/32",
    "44.212.239.227/32",
    "44.213.158.218/32",
    "44.213.163.24/32",
    "44.214.194.234/32",
    "44.214.207.7/32",
    "44.214.212.218/32",
    "44.214.32.136/32",
    "44.214.62.148/32",
    "44.215.161.26/32",
    "44.215.216.21/32",
    "44.215.224.27/32",
    "44.215.24.160/32",
    "44.215.63.87/32",
    "44.215.7.194/32",
    "44.215.81.252/32",
    "44.215.84.21/32",
    "44.215.89.216/32",
    "44.216.100.41/32",
    "44.216.104.198/32",
    "44.216.243.74/32",
    "44.216.5.127/32",
    "44.216.58.133/32",
    "44.216.7.31/32",
    "44.217.121.202/32",
    "44.217.152.47/32",
    "44.217.158.120/32",
    "44.217.254.94/32",
    "44.218.132.213/32",
    "44.218.149.105/32",
    "44.218.169.19/32",
    "44.218.183.161/32",
    "44.218.187.96/32",
    "44.218.200.142/32",
    "44.218.30.160/32",
    "44.218.99.76/32",
    "44.219.115.49/32",
    "44.219.143.106/32",
    "44.219.23.147/32",
    "44.219.64.51/32",
    "44.220.9.209/32",
    "44.221.111.36/32",
    "44.221.132.209/32",
    "44.221.185.185/32",
    "44.221.223.252/32",
    "44.221.225.24/32",
    "44.221.244.31/32",
    "44.221.99.201/32",
    "44.222.28.176/32",
    "44.222.60.175/32",
    "44.223.220.158/32",
    "44.223.230.228/32",
    "50.16.147.3/32",
    "50.16.231.180/32",
    "50.16.4.171/32",
    "50.17.1.240/32",
    "50.17.134.19/32",
    "50.17.153.9/32",
    "50.17.191.57/32",
    "50.17.207.81/32",
    "50.17.230.96/32",
    "50.19.126.63/32",
    "50.19.204.59/32",
    "50.19.251.209/32",
    "50.19.29.68/32",
    "50.19.35.165/32",
    "50.19.59.54/32",
    "52.0.129.197/32",
    "52.0.175.66/32",
    "52.0.190.163/32",
    "52.0.192.213/32",
    "52.0.194.51/32",
    "52.0.29.253/32",
    "52.0.31.88/32",
    "52.0.92.85/32",
    "52.1.178.161/32",
    "52.1.245.227/32",
    "52.1.58.136/32",
    "52.2.182.123/32",
    "52.2.196.120/32",
    "52.2.240.114/32",
    "52.2.253.241/32",
    "52.20.100.136/32",
    "52.20.139.63/32",
    "52.20.29.92/32",
    "52.200.116.93/32",
    "52.200.28.69/32",
    "52.200.8.184/32",
    "52.200.84.90/32",
    "52.201.206.154/32",
    "52.201.41.193/32",
    "52.201.98.75/32",
    "52.202.101.32/32",
    "52.202.103.180/32",
    "52.202.121.224/32",
    "52.202.216.228/32",
    "52.202.253.248/32",
    "52.202.35.1/32",
    "52.202.37.123/32",
    "52.203.152.175/32",
    "52.203.209.127/32",
    "52.203.244.55/32",
    "52.203.32.72/32",
    "52.203.86.132/32",
    "52.204.124.205/32",
    "52.204.162.207/32",
    "52.204.226.159/32",
    "52.204.226.207/32",
    "52.204.226.223/32",
    "52.204.64.101/32",
    "52.204.78.168/32",
    "52.204.81.241/32",
    "52.205.135.221/32",
    "52.205.246.20/32",
    "52.205.27.163/32",
    "52.206.102.51/32",
    "52.206.130.42/32",
    "52.206.143.135/32",
    "52.206.169.224/32",
    "52.206.181.180/32",
    "52.206.46.172/32",
    "52.206.52.116/32",
    "52.206.60.64/32",
    "52.206.61.139/32",
    "52.207.120.139/32",
    "52.207.133.220/32",
    "52.207.16.197/32",
    "52.207.61.91/32",
    "52.207.72.172/32",
    "52.21.106.0/32",
    "52.21.120.37/32",
    "52.21.146.37/32",
    "52.21.166.33/32",
    "52.21.48.195/32",
    "52.22.150.64/32",
    "52.22.196.44/32",
    "52.22.210.122/32",
    "52.22.89.200/32",
    "52.23.133.109/32",
    "52.23.146.199/32",
    "52.23.51.117/32",
    "52.23.97.153/32",
    "52.3.104.17/32",
    "52.3.239.250/32",
    "52.3.70.186/32",
    "52.4.106.28/32",
    "52.4.161.44/32",
    "52.4.20.22/32",
    "52.4.200.143/32",
    "52.4.229.83/32",
    "52.4.5.89/32",
    "52.44.145.57/32",
    "52.44.222.44/32",
    "52.44.93.127/32",
    "52.45.105.249/32",
    "52.45.162.115/32",
    "52.45.180.161/32",
    "52.45.82.146/32",
    "52.45.91.149/32",
    "52.5.101.193/32",
    "52.5.11.240/32",
    "52.5.126.84/32",
    "52.5.139.177/32",
    "52.5.158.30/32",
    "52.5.237.111/32",
    "52.5.241.167/32",
    "52.5.71.38/32",
    "52.5.9.202/32",
    "52.5.91.235/32",
    "52.54.128.50/32",
    "52.54.247.126/32",
    "52.54.73.166/32",
    "52.55.118.104/32",
    "52.55.174.246/32",
    "52.55.203.221/32",
    "52.6.108.202/32",
    "52.7.157.23/32",
    "52.7.217.144/32",
    "52.7.224.72/32",
    "52.7.23.251/32",
    "52.7.57.117/32",
    "52.7.66.242/32",
    "52.70.155.245/32",
    "52.70.247.71/32",
    "52.71.225.8/32",
    "52.71.39.142/32",
    "52.71.50.120/32",
    "52.71.70.228/32",
    "52.72.232.179/32",
    "52.72.73.184/32",
    "52.73.115.59/32",
    "52.73.158.87/32",
    "52.73.197.50/32",
    "52.73.206.11/32",
    "52.73.215.66/32",
    "52.86.118.49/32",
    "52.86.198.100/32",
    "52.86.235.69/32",
    "52.86.53.42/32",
    "52.86.86.102/32",
    "52.87.0.229/32",
    "52.87.118.241/32",
    "52.87.127.40/32",
    "52.87.52.141/32",
    "52.87.74.18/32",
    "54.144.163.59/32",
    "54.144.165.228/32",
    "54.144.166.248/32",
    "54.145.100.187/32",
    "54.145.120.66/32",
    "54.145.201.55/32",
    "54.145.202.232/32",
    "54.146.124.96/32",
    "54.146.217.77/32",
    "54.146.78.43/32",
    "54.147.28.169/32",
    "54.152.240.110/32",
    "54.152.250.63/32",
    "54.152.62.114/32",
    "54.156.101.5/32",
    "54.156.218.150/32",
    "54.156.228.126/32",
    "54.156.60.28/32",
    "54.156.75.181/32",
    "54.157.127.12/32",
    "54.157.17.251/32",
    "54.157.60.117/32",
    "54.157.89.202/32",
    "54.157.93.108/32",
    "54.158.126.53/32",
    "54.158.87.246/32",
    "54.159.127.105/32",
    "54.159.41.249/32",
    "54.159.73.59/32",
    "54.160.29.53/32",
    "54.161.82.218/32",
    "54.162.184.206/32",
    "54.163.119.115/32",
    "54.163.119.23/32",
    "54.163.149.34/32",
    "54.163.156.179/32",
    "54.163.96.5/32",
    "54.164.253.209/32",
    "54.165.187.237/32",
    "54.165.237.175/32",
    "54.166.114.87/32",
    "54.166.123.195/32",
    "54.166.147.9/32",
    "54.166.168.104/32",
    "54.166.186.204/32",
    "54.166.203.36/32",
    "54.166.221.13/32",
    "54.166.51.59/32",
    "54.167.145.47/32",
    "54.167.149.221/32",
    "54.167.157.19/32",
    "54.167.167.144/32",
    "54.167.254.156/32",
    "54.172.147.40/32",
    "54.172.181.132/32",
    "54.172.223.244/32",
    "54.172.235.19/32",
    "54.173.251.40/32",
    "54.173.254.186/32",
    "54.173.3.145/32",
    "54.173.73.223/32",
    "54.174.132.51/32",
    "54.174.156.91/32",
    "54.174.185.149/32",
    "54.174.185.64/32",
    "54.174.239.164/32",
    "54.174.255.71/32",
    "54.174.33.240/32",
    "54.174.79.6/32",
    "54.175.137.98/32",
    "54.175.225.187/32",
    "54.175.92.255/32",
    "54.196.107.151/32",
    "54.196.38.144/32",
    "54.197.112.73/32",
    "54.197.64.106/32",
    "54.198.102.234/32",
    "54.198.16.172/32",
    "54.198.232.105/32",
    "54.198.233.242/32",
    "54.204.105.187/32",
    "54.204.223.93/32",
    "54.204.35.237/32",
    "54.204.59.63/32",
    "54.204.80.55/32",
    "54.205.119.2/32",
    "54.205.136.35/32",
    "54.205.160.25/32",
    "54.205.201.74/32",
    "54.205.208.13/32",
    "54.205.213.166/32",
    "54.205.3.125/32",
    "54.205.40.225/32",
    "54.205.45.210/32",
    "54.208.132.243/32",
    "54.208.179.143/32",
    "54.208.246.64/32",
    "54.208.27.202/32",
    "54.209.190.9/32",
    "54.209.191.8/32",
    "54.209.36.112/32",
    "54.209.9.33/32",
    "54.210.131.110/32",
    "54.210.198.121/32",
    "54.210.31.211/32",
    "54.210.80.37/32",
    "54.211.199.50/32",
    "54.211.75.0/32",
    "54.211.78.165/32",
    "54.221.237.132/32",
    "54.221.32.154/32",
    "54.224.116.206/32",
    "54.224.224.135/32",
    "54.224.240.158/32",
    "54.224.53.14/32",
    "54.225.113.76/32",
    "54.225.145.181/32",
    "54.225.162.45/32",
    "54.225.169.17/32",
    "54.225.221.30/32",
    "54.225.67.8/32",
    "54.225.71.221/32",
    "54.226.73.182/32",
    "54.227.13.229/32",
    "54.227.28.87/32",
    "54.234.167.100/32",
    "54.235.211.99/32",
    "54.235.213.173/32",
    "54.236.112.173/32",
    "54.236.158.242/32",
    "54.236.167.56/32",
    "54.236.239.164/32",
    "54.237.184.17/32",
    "54.237.29.9/32",
    "54.242.10.253/32",
    "54.242.167.254/32",
    "54.243.110.227/32",
    "54.243.144.14/32",
    "54.243.201.33/32",
    "54.243.209.16/32",
    "54.243.211.8/32",
    "54.80.175.67/32",
    "54.80.198.127/32",
    "54.80.234.89/32",
    "54.80.243.130/32",
    "54.80.45.194/32",
    "54.80.71.176/32",
    "54.80.74.44/32",
    "54.81.154.68/32",
    "54.81.165.33/32",
    "54.81.246.115/32",
    "54.82.11.240/32",
    "54.82.116.145/32",
    "54.82.165.97/32",
    "54.82.184.206/32",
    "54.82.79.140/32",
    "54.83.14.168/32",
    "54.83.178.173/32",
    "54.83.238.70/32",
    "54.83.29.252/32",
    "54.83.61.93/32",
    "54.84.247.173/32",
    "54.84.255.139/32",
    "54.84.42.70/32",
    "54.84.58.86/32",
    "54.84.96.236/32",
    "54.85.116.136/32",
    "54.85.13.251/32",
    "54.85.152.251/32",
    "54.85.173.232/32",
    "54.85.182.11/32",
    "54.85.182.74/32",
    "54.85.183.163/32",
    "54.85.42.248/32",
    "54.86.102.52/32",
    "54.86.113.36/32",
    "54.86.128.12/32",
    "54.86.173.205/32",
    "54.86.200.206/32",
    "54.86.235.24/32",
    "54.86.41.234/32",
    "54.87.147.32/32",
    "54.87.230.73/32",
    "54.87.231.234/32",
    "54.87.82.164/32",
    "54.88.17.4/32",
    "54.88.231.214/32",
    "54.89.1.163/32",
    "54.89.197.100/32",
    "54.89.37.100/32",
    "54.89.57.217/32",
    "54.90.15.96/32",
    "54.90.160.213/32",
    "54.90.251.223/32",
    "54.91.222.113/32",
    "54.91.68.167/32",
    "54.91.90.149/32",
    "54.92.230.27/32",
    "67.202.14.197/32",
    "75.101.211.35/32",
    "98.80.55.141/32",
    "98.82.243.141/32",
    "98.82.255.249/32",
    "98.82.55.41/32",
    "98.83.170.172/32",
    "98.83.18.54/32",
    "98.83.191.241/32",
    "98.83.248.195/32",
    "98.83.46.92/32",
    "98.83.70.133/32",
    "98.83.89.12/32",
    "98.84.242.231/32",
    "98.85.106.40/32",
    "98.85.137.77/32",
    "98.85.140.218/32",
    "98.85.146.158/32",
    "98.85.211.76/32",
    "98.85.214.32/32",
    "98.85.218.4/32",
    "98.85.238.47/32",
    "98.85.246.245/32",
    "98.86.129.100/32",
    "98.86.184.138/32",
    "98.86.187.75/32",
    "98.86.188.104/32",
    "98.86.192.5/32",
    "98.86.205.54/32",
    "98.86.207.121/32",
    "98.86.207.186/32",
    "98.86.212.136/32",
    "98.86.212.35/32",
    "98.86.214.58/32",
    "98.86.218.208/32",
    "98.86.24.23/32",
    "98.86.249.175/32",
    "98.86.25.36/32",
    "98.86.27.21/32",
    "98.86.29.203/32",
    "98.86.4.188/32",
    "98.86.50.127/32",
    "98.86.51.12/32",
    "98.86.54.86/32",
    "98.86.60.7/32",
    "98.86.78.84/32",
    "98.86.80.106/32",
    "98.87.100.94/32",
    "98.87.110.161/32",
    "98.87.115.179/32",
    "98.87.119.92/32",
    "98.87.125.106/32",
    "98.87.130.228/32",
    "98.87.132.166/32",
    "98.87.141.217/32",
    "98.87.145.207/32",
    "98.87.177.122/32",
    "98.87.178.41/32",
    "98.87.179.143/32",
    "98.87.179.166/32",
    "98.87.179.77/32",
    "98.87.180.162/32",
    "98.87.180.251/32",
    "98.87.180.82/32",
    "98.87.182.201/32",
    "98.87.182.37/32",
    "98.87.182.62/32",
    "98.87.183.122/32",
    "98.87.183.61/32",
    "98.87.184.100/32",
    "98.87.184.28/32",
    "98.87.30.184/32",
    "98.87.36.115/32",
    "98.87.39.1/32",
    "98.87.44.13/32",
    "98.87.48.159/32",
    "98.87.52.210/32",
    "98.87.54.118/32",
    "98.87.63.1/32",
    "98.87.68.53/32",
    "98.87.69.247/32",
    "98.87.70.113/32",
    "98.87.73.104/32",
    "98.87.83.39/32",
    "98.87.91.253/32",
    "98.87.92.12/32",
    "98.87.95.193/32",
    "98.87.95.44/32"
  ],
  /** 14 prefixes */
  "claude": [
    "216.73.216.0/22",
    "34.162.230.222/32",
    "34.162.244.71/32",
    "34.162.191.81/32",
    "34.162.86.102/32",
    "136.79.143.251/32",
    "136.83.20.215/32",
    "34.162.111.78/32",
    "34.162.90.102/32",
    "34.162.27.34/32",
    "34.152.124.140/32",
    "34.153.21.190/32",
    "34.186.252.4/32",
    "34.162.153.71/32"
  ],
  /** 10 prefixes */
  "claude-agent-sail": [
    "136.71.21.147/32",
    "34.31.25.14/32",
    "34.67.187.248/32",
    "34.71.122.171/32",
    "34.70.177.231/32",
    "34.66.255.143/32",
    "34.68.65.207/32",
    "34.171.207.92/32",
    "34.60.73.195/32",
    "153.61.208.16/32"
  ]
};

// server.ts
var GOOD_BOT_UA_RULES2 = GOOD_BOT_UA_RULES;
var AI_AGENT_UA_RULES2 = AI_AGENT_UA_RULES;
var BOT_SIGNATURE_KEYID_PROVIDERS2 = BOT_SIGNATURE_KEYID_PROVIDERS;
var AI_BOT_CIDR_SOURCES2 = AI_BOT_CIDR_SOURCES;
function registryLookup(value, key) {
  if (!value || typeof value !== "object") return void 0;
  const asRecord = value;
  if (Object.prototype.hasOwnProperty.call(asRecord, key)) return asRecord[key];
  const getter = value.get;
  if (typeof getter === "function") return getter.call(value, key);
  return void 0;
}
function asLocalAgent(agent) {
  const raw = agent && typeof agent === "object" ? agent : {};
  const signature = raw.signature;
  return {
    ...raw,
    fcrdnsSuffixes: raw.fcrdnsSuffixes ? [...raw.fcrdnsSuffixes] : void 0,
    feedIds: raw.feedIds ? [...raw.feedIds] : void 0,
    asns: raw.asns ? raw.asns.map(String) : void 0,
    signatureHosts: signature?.agentHosts ? [...signature.agentHosts] : void 0,
    keyIdNeedles: signature?.keyIdNeedles ? [...signature.keyIdNeedles] : void 0
  };
}
var REGISTRY_AGENT_LIST = Array.isArray(AGENT_REGISTRY) ? AGENT_REGISTRY.map(asLocalAgent) : Object.values(AGENT_REGISTRY ?? {}).map(asLocalAgent);
function lookupAgent(id) {
  if (!id) return null;
  const direct = registryLookup(AGENT_BY_ID, id);
  if (direct) return asLocalAgent(direct);
  const needle = id.toLowerCase();
  return REGISTRY_AGENT_LIST.find(
    (agent) => String(agent.id || "").toLowerCase() === needle || String(agent.displayName || "").toLowerCase() === needle || String(agent.provider || "").toLowerCase() === needle
  ) ?? null;
}
var findRegistryAgent = (ua) => findAgentByUa(ua) ?? null;
var isRegistryPolicyToken = (ua) => Boolean(isPolicyToken(ua));
var registryDisplay = (agent, identity) => displayFor(
  agent,
  identity
);
var normalizeRegistryFeed = (sourceId, body) => normalizeFeed(
  sourceId,
  body
);
function operatorIdFromName(name) {
  const lower = name.toLowerCase();
  if (/google/.test(lower)) return "google";
  if (/openai|chatgpt/.test(lower)) return "openai";
  if (/perplexity/.test(lower)) return "perplexity";
  if (/anthropic|claude/.test(lower)) return "anthropic";
  if (/xai|grok|\bx\b/.test(lower)) return "xai";
  if (/meta|facebook/.test(lower)) return "meta";
  if (/browserbase/.test(lower)) return "browserbase";
  if (/anchor\s?browser/.test(lower)) return "anchorbrowser";
  return lower.replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "") || "unknown";
}
var FALLBACK_VERIFICATION_SUFFIXES = {
  google: ["googlebot.com", "google.com"],
  openai: ["openai.com", "chatgpt.com"],
  perplexity: ["perplexity.ai"],
  anthropic: ["anthropic.com", "claude.ai"],
  xai: ["x.ai", "grok.com"],
  meta: ["facebook.com", "meta.com", "fb.com"]
};
var FALLBACK_ASNS = {
  google: ["15169", "396982"],
  xai: ["400562", "13414"],
  meta: ["32934", "63293"],
  aws: ["16509", "14618"],
  azure: ["8075"],
  perplexity: ["209242"]
};
var FALLBACK_SIGNATURE_HOSTS = [
  ["openai.com", "openai"],
  ["chatgpt.com", "openai"],
  ["perplexity.ai", "perplexity"],
  ["anthropic.com", "anthropic"],
  ["claude.ai", "anthropic"],
  ["browserbase.com", "browserbase"],
  ["anchorbrowser.io", "anchorbrowser"],
  ["x.ai", "xai"],
  ["grok.com", "xai"],
  ["meta.com", "meta"],
  ["facebook.com", "meta"]
];
function suffixesForAgent(...keys) {
  const found = [];
  const add = (value) => {
    if (Array.isArray(value)) {
      for (const item of value) if (typeof item === "string" && item.trim()) found.push(item.trim());
    }
  };
  for (const key of keys) {
    add(registryLookup(VERIFICATION_SUFFIXES_BY_AGENT, key));
    add(registryLookup(VERIFICATION_SUFFIXES_BY_AGENT, key.toLowerCase()));
    add(lookupAgent(key)?.fcrdnsSuffixes);
  }
  const needles = keys.map((key) => key.toLowerCase());
  for (const agent of REGISTRY_AGENT_LIST) {
    if (needles.some(
      (key) => key === String(agent.id || "").toLowerCase() || key === String(agent.provider || "").toLowerCase() || key === String(agent.displayName || "").toLowerCase()
    )) {
      add(agent.fcrdnsSuffixes);
    }
  }
  if (found.length === 0) {
    for (const key of keys) add(FALLBACK_VERIFICATION_SUFFIXES[key.toLowerCase()]);
  }
  return Array.from(new Set(found));
}
function asnsForAgent(...keys) {
  const found = [];
  const add = (value) => {
    if (Array.isArray(value)) {
      for (const item of value) {
        const digits = typeof item === "number" ? String(item) : typeof item === "string" ? item : "";
        if (digits.trim()) found.push(digits.trim());
      }
    }
  };
  for (const key of keys) add(lookupAgent(key)?.asns);
  if (found.length === 0) {
    for (const key of keys) add(FALLBACK_ASNS[key.toLowerCase()]);
  }
  return Array.from(new Set(found));
}
var SIGNATURE_HOST_RULES = (() => {
  const rules = FALLBACK_SIGNATURE_HOSTS.map(([host, operator]) => ({ host, operator }));
  for (const agent of REGISTRY_AGENT_LIST) {
    const operator = operatorIdFromName(agent.provider || agent.id);
    for (const rawHost of agent.signatureHosts ?? []) {
      if (typeof rawHost === "string" && rawHost.trim()) {
        rules.push({ host: rawHost.trim().toLowerCase(), operator });
      }
    }
  }
  for (const rawEntry of BOT_DIRECTORY ?? []) {
    const entry = rawEntry && typeof rawEntry === "object" ? rawEntry : {};
    const hosts = entry.signatureHosts ?? entry.hosts ?? entry.domains ?? entry.verificationSuffixes;
    const name = entry.provider ?? entry.operator ?? entry.name;
    if (Array.isArray(hosts) && typeof name === "string") {
      const operator = operatorIdFromName(name);
      for (const rawHost of hosts) {
        if (typeof rawHost === "string" && rawHost.trim()) {
          rules.push({ host: rawHost.trim().toLowerCase(), operator });
        }
      }
    }
  }
  return rules;
})();
function isGoodCrawlerCategory(category) {
  const value = String(category || "").toLowerCase();
  return value === "search_crawler" || value === "search crawler" || value === "link_preview" || value === "link preview";
}
function pinnedPrefixEntries() {
  const entries = [];
  const add = (id, value) => {
    const prefixes = Array.isArray(value) ? value.filter((item) => typeof item === "string" && item.includes("/")) : [];
    if (prefixes.length > 0) entries.push([id, prefixes]);
  };
  const pinned = PINNED_PREFIXES;
  if (Array.isArray(pinned)) {
    for (const item of pinned) {
      if (typeof item === "string") {
        if (item.includes("/")) add("pinned", [item]);
        continue;
      }
      const record = item && typeof item === "object" ? item : {};
      const id = typeof record.id === "string" ? record.id : typeof record.sourceId === "string" ? record.sourceId : typeof record.agentId === "string" ? record.agentId : "pinned";
      add(id, record.prefixes ?? record.prefix ?? record.cidrs ?? record.ranges);
    }
  } else if (pinned && typeof pinned === "object") {
    for (const [id, prefixes] of Object.entries(pinned)) add(id, prefixes);
  }
  return entries;
}
function prefixesFromNormalizedFeed(normalized, sourceId) {
  const found = [];
  const add = (value) => {
    if (typeof value === "string") {
      if (value.includes("/")) found.push(value.trim());
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) add(item);
      return;
    }
    if (value && typeof value === "object") {
      const record = value;
      for (const key of ["prefixes", "prefix", "cidrs", "ranges", "ipv4Prefix", "ipv6Prefix"]) {
        if (record[key] !== void 0) add(record[key]);
      }
    }
  };
  if (normalized && typeof normalized === "object" && !Array.isArray(normalized)) {
    const feedKey = registryLookup(PREFIX_FEEDS, sourceId);
    const match = registryLookup(normalized, sourceId) ?? (typeof feedKey === "string" ? registryLookup(normalized, feedKey) : void 0);
    if (match !== void 0) add(match);
    else {
      const compact = sourceId.replace(/[^a-z0-9]/gi, "").toLowerCase();
      for (const [key, value] of Object.entries(normalized)) {
        if (key.toLowerCase() === sourceId.toLowerCase() || key.replace(/[^a-z0-9]/gi, "").toLowerCase() === compact) {
          add(value);
        }
      }
    }
  } else {
    add(normalized);
  }
  return Array.from(new Set(found));
}
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
  const hardwareAnchorsMap = /* @__PURE__ */ new Map();
  const lshBandsMap = /* @__PURE__ */ new Map();
  const rdapPrefixMap = /* @__PURE__ */ new Map();
  const schemaMigrations = /* @__PURE__ */ new Set();
  let autoIncrementId = 1;
  return {
    exec: () => {
    },
    prepare: (sql) => {
      const normalized = sql.replace(/\s+/g, " ").trim();
      return {
        get: (...params) => {
          if (normalized.includes("AS events_24h") && normalized.includes("FROM visits WHERE visitor_id = ?")) {
            const vid = String(params[12] || "");
            const cutoffs = [String(params[0] || ""), String(params[1] || ""), String(params[2] || "")];
            const rows = visitsList.filter((v) => v.visitor_id === vid);
            const inWindow = (cutoff) => rows.filter((v) => v.visited_at_utc >= cutoff);
            const distinct = (cutoff, pick) => new Set(inWindow(cutoff).map(pick)).size;
            return {
              ip_5m: distinct(cutoffs[0], (v) => v.public_ip),
              ip_1h: distinct(cutoffs[1], (v) => v.public_ip),
              ip_24h: distinct(cutoffs[2], (v) => v.public_ip),
              linked_5m: distinct(cutoffs[0], (v) => v.session_id),
              linked_1h: distinct(cutoffs[1], (v) => v.session_id),
              linked_24h: distinct(cutoffs[2], (v) => v.session_id),
              country_5m: distinct(cutoffs[0], (v) => v.country),
              country_1h: distinct(cutoffs[1], (v) => v.country),
              country_24h: distinct(cutoffs[2], (v) => v.country),
              events_5m: inWindow(cutoffs[0]).length,
              events_1h: inWindow(cutoffs[1]).length,
              events_24h: inWindow(cutoffs[2]).length
            };
          }
          if (normalized.includes("AS ip_events_24h")) {
            const cutoffs = [String(params[0] || ""), String(params[1] || ""), String(params[2] || "")];
            const publicIp = String(params[4] || "");
            const rows = visitsList.filter((v) => v.public_ip === publicIp);
            const inWindow = (cutoff) => rows.filter((v) => v.visited_at_utc >= cutoff);
            return {
              ip_events_5m: inWindow(cutoffs[0]).length,
              ip_events_1h: inWindow(cutoffs[1]).length,
              ip_events_24h: inWindow(cutoffs[2]).length,
              ip_visitors_24h: new Set(inWindow(cutoffs[2]).map((v) => v.visitor_id)).size
            };
          }
          if (normalized.includes("AS linked_ips_5m")) {
            const cutoffs = [String(params[0] || ""), String(params[1] || ""), String(params[2] || "")];
            const sessionId = String(params[6] || "");
            const rows = visitsList.filter((v) => v.session_id === sessionId);
            const inWindow = (cutoff) => rows.filter((v) => v.visited_at_utc >= cutoff);
            const distinct = (cutoff, pick) => new Set(inWindow(cutoff).map(pick)).size;
            return {
              linked_ips_5m: distinct(cutoffs[0], (v) => v.public_ip),
              linked_ips_1h: distinct(cutoffs[1], (v) => v.public_ip),
              linked_ips_24h: distinct(cutoffs[2], (v) => v.public_ip),
              linked_visitors_5m: distinct(cutoffs[0], (v) => v.visitor_id),
              linked_visitors_1h: distinct(cutoffs[1], (v) => v.visitor_id),
              linked_visitors_24h: distinct(cutoffs[2], (v) => v.visitor_id)
            };
          }
          if (normalized.includes("intel:dailyhardware")) {
            const cutoff = String(params[0] || "");
            const activeHardware = new Set(
              Array.from(visitorsMap.values()).filter((v) => v.updated_at_utc >= cutoff && v.hardware_id).map((v) => v.hardware_id)
            );
            return { n: activeHardware.size };
          }
          if (normalized.includes("FROM hardware_anchors WHERE hardware_id = ?")) {
            return hardwareAnchorsMap.get(String(params[0] || ""));
          }
          if (normalized.includes("FROM identity_lsh_bands WHERE band_idx = ? AND band_hash = ?")) {
            return lshBandsMap.get(`${params[0]}:${params[1]}`);
          }
          if (normalized.includes("FROM rdap_prefix_cache WHERE prefix = ?")) {
            return rdapPrefixMap.get(String(params[0] || ""));
          }
          if (normalized.includes("FROM schema_migrations WHERE version = ?")) {
            return schemaMigrations.has(String(params[0] || "")) ? { version: String(params[0]) } : void 0;
          }
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
          if (normalized.includes("intel:subnets24h")) {
            const vid = String(params[0] || "");
            const cutoff = String(params[1] || "");
            return visitsList.filter((v) => v.visitor_id === vid && v.visited_at_utc >= cutoff).map((v) => ({ public_ip: v.public_ip }));
          }
          if (normalized.includes("intel:dailyevents")) {
            const cutoff = String(params[0] || "");
            const counts = /* @__PURE__ */ new Map();
            for (const visit of visitsList) {
              if (visit.visited_at_utc < cutoff) continue;
              counts.set(visit.visitor_id, (counts.get(visit.visitor_id) || 0) + 1);
            }
            return Array.from(counts, ([visitor_id, events]) => ({ visitor_id, events }));
          }
          if (normalized.includes("FROM identity_lsh_bands WHERE band_idx = ?")) {
            const idx = Number(params[0]);
            const bandHash = typeof params[1] === "string" ? params[1] : null;
            return Array.from(lshBandsMap.values()).filter(
              (row) => row.band_idx === idx && (bandHash === null || row.band_hash === bandHash)
            );
          }
          if (normalized.includes("FROM schema_migrations")) {
            return Array.from(schemaMigrations).map((version) => ({ version }));
          }
          if (normalized.includes("FROM visits WHERE visitor_id = ?")) {
            const vid = String(params[0] || "");
            return visitsList.filter((v) => v.visitor_id === vid).sort((a, b) => b.visited_at_utc.localeCompare(a.visited_at_utc) || b.id - a.id).slice(0, 50);
          }
          return [];
        },
        run: (...params) => {
          if (normalized.includes("INSERT OR REPLACE INTO hardware_anchors")) {
            const row = {
              hardware_id: String(params[0] || ""),
              visitor_id: String(params[1] || ""),
              simhash: String(params[2] || ""),
              distinct_storage_seeds_count: Number(params[3] ?? 1),
              first_seen_utc: String(params[4] || ""),
              updated_at_utc: String(params[5] || "")
            };
            hardwareAnchorsMap.set(row.hardware_id, row);
            return { changes: 1 };
          }
          if (normalized.includes("INSERT OR IGNORE INTO identity_lsh_bands")) {
            const band_idx = Number(params[0]);
            const band_hash = String(params[1] || "");
            const hardware_id = String(params[2] || "");
            const key = `${band_idx}:${band_hash}`;
            if (lshBandsMap.has(key)) return { changes: 0 };
            lshBandsMap.set(key, { band_idx, band_hash, hardware_id });
            return { changes: 1 };
          }
          if (normalized.includes("INSERT OR REPLACE INTO rdap_prefix_cache")) {
            rdapPrefixMap.set(String(params[0] || ""), {
              prefix: String(params[0] || ""),
              org: String(params[1] || ""),
              asn: String(params[2] || ""),
              fetched_at_ms: Number(params[3] || Date.now())
            });
            return { changes: 1 };
          }
          if (normalized.includes("INSERT OR IGNORE INTO schema_migrations")) {
            const version = String(params[0] || "");
            if (schemaMigrations.has(version)) return { changes: 0 };
            schemaMigrations.add(version);
            return { changes: 1 };
          }
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

      /* Phase 4 \u2014 canonical identity tables. Old tables are intentionally kept for rollback. */
      CREATE TABLE IF NOT EXISTS hardware_anchors (
        hardware_id TEXT PRIMARY KEY,
        visitor_id TEXT NOT NULL,
        simhash TEXT NOT NULL DEFAULT '',
        distinct_storage_seeds_count INTEGER NOT NULL DEFAULT 1,
        first_seen_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS identity_lsh_bands (
        band_idx INTEGER NOT NULL,
        band_hash TEXT NOT NULL,
        hardware_id TEXT NOT NULL,
        PRIMARY KEY (band_idx, band_hash, hardware_id)
      ) WITHOUT ROWID;

      CREATE TABLE IF NOT EXISTS rdap_prefix_cache (
        prefix TEXT PRIMARY KEY,
        org TEXT NOT NULL DEFAULT '',
        asn TEXT NOT NULL DEFAULT '',
        fetched_at_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at_utc TEXT NOT NULL
      );

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
var CORROBORATION_MAX_ENTRIES = 5e3;
var corroborationLedger = /* @__PURE__ */ new Map();
function rememberPassiveVisit(entry) {
  if (corroborationLedger.size >= CORROBORATION_MAX_ENTRIES) {
    const oldest = corroborationLedger.keys().next().value;
    if (oldest) corroborationLedger.delete(oldest);
  }
  corroborationLedger.set(entry.eventId, entry);
}
var RATE_LIMIT_WINDOW_MS = 6e4;
var RATE_LIMIT_MAX_REQUESTS = 60;
var RATE_LIMIT_MAX_KEYS = 5e3;
var rateLimitBuckets = /* @__PURE__ */ new Map();
function isLoopbackAddress(candidate) {
  const ip = normalizeIpCandidate(candidate);
  if (!ip) return false;
  if (ip === "::1" || ip === "0:0:0:0:0:0:0:1" || ip === "::" || ip === "0:0:0:0:0:0:0:0") {
    return true;
  }
  return /^127\./.test(ip) || ip === "127.0.0.1" || ip.toLowerCase() === "localhost";
}
function rateLimitClientKey(req) {
  const { ip: routedIp } = extractVisitorIp(req);
  if (routedIp && routedIp !== "Unavailable") return `ip:${routedIp}`;
  const socketIp = normalizeIpCandidate(req.socket?.remoteAddress);
  return socketIp ? `socket:${socketIp}` : "unknown";
}
function identifyRateLimit(req, res, next) {
  if (process.env.INTEL_DISABLE_RATE_LIMIT === "1") {
    next();
    return;
  }
  const forwarded = readRequestHeader(req.headers, "x-forwarded-for");
  const directCandidates = [
    req.socket?.remoteAddress,
    req.ip,
    forwarded.split(",")[0],
    readRequestHeader(req.headers, "x-real-ip")
  ];
  if (directCandidates.some((candidate) => isLoopbackAddress(candidate)) && !isPublicRoutableIp(normalizeIpCandidate(forwarded.split(",")[0]))) {
    next();
    return;
  }
  const key = rateLimitClientKey(req);
  const now = Date.now();
  const recent = (rateLimitBuckets.get(key) ?? []).filter(
    (timestamp) => now - timestamp < RATE_LIMIT_WINDOW_MS
  );
  if (recent.length >= RATE_LIMIT_MAX_REQUESTS) {
    const oldest = recent[0] ?? now;
    const retryAfter = Math.max(1, Math.ceil((oldest + RATE_LIMIT_WINDOW_MS - now) / 1e3));
    res.setHeader("Retry-After", String(retryAfter));
    res.status(429).json({
      error: "Too Many Requests",
      retry_after_seconds: retryAfter
    });
    return;
  }
  recent.push(now);
  if (rateLimitBuckets.size >= RATE_LIMIT_MAX_KEYS) {
    const oldestKey = rateLimitBuckets.keys().next().value;
    if (oldestKey) rateLimitBuckets.delete(oldestKey);
  }
  rateLimitBuckets.set(key, recent);
  next();
}
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
  20473,
  11878,
  // Tzulo — hosting network rented by VPN providers, not a VPN operator itself
  212238
  // CDNEXT / Datacamp — hosting network, not a VPN operator itself
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
var VPN_PROXY_PATTERN = /\b(vpn|nordvpn|expressvpn|surfshark|cyberghost|cyberzone|private internet access|proton(?:\s?vpn)?|mullvad|31173|windscribe|ipvanish|hide\.?me|hola vpn|psiphon|packet hub|packethub|tor ?guard|proxy|socks5|smart dns)\b/i;
var HOSTING_EGRESS_PATTERN = /\b(m247|datacamp|cdnext|tzulo|cloudflare|amazonaws|amazon|aws|google cloud|google llc|azure|microsoft|digitalocean|hetzner|linode|ovh|choopa|vultr|leaseweb|hostinger|contabo|akamai|oracle cloud|alibaba|aliyun|tencent cloud|latitude|hosting|hosted|datacenter|data center|cloud)\b/i;
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
  const cloudKeywords = /google llc|google cloud|amazonaws|cloudflare|digitalocean|hetzner|m247|datacamp|datapacket|cdnext|cdn77|tzulo|linode|ovh|choopa|vultr|leaseweb|hostinger|contabo|akamai|oracle cloud|alibaba|aliyun|tencent cloud/i;
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
var AUTOMATION_UA_PATTERN = /playwright|puppeteer|selenium|cypress|phantomjs/i;
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
  const hardAutomation = Boolean(
    client.stealthPluginDetected || client.antiDetectBrowser || client.automationTargetedTampering
  );
  if (hardAutomation) {
    const reasons = [];
    if (client.automationTargetedTampering) {
      reasons.push(
        `Automation-targeted tampering artifacts (${(client.automationTamperingReasons || []).slice(0, 2).join("; ") || "webdriver / playwright / CDC / CDP getter wrappers"})`
      );
    }
    if (client.stealthPluginDetected) {
      reasons.push("Stealth plugin artifacts (rewritten native getters / iframe identity leak)");
    }
    if (client.antiDetectBrowser) {
      reasons.push("Anti-detect browser footprint (spoofed screen / patched navigator getters)");
    }
    if (typeof client.tamperingMlScore === "number" && client.tamperingMlScore >= 0.5) {
      reasons.push(`Browser tampering ML score ${client.tamperingMlScore.toFixed(3)}`);
    }
    for (const signal of clientSignals.slice(0, 2)) reasons.push(signal);
    return {
      subtype: "bad_bot",
      label: client.automationTargetedTampering ? "Stealth Automation" : client.antiDetectBrowser ? "Anti-Detect Browser" : client.stealthPluginDetected ? "Puppeteer / Playwright Stealth" : "HeadlessChrome / CDP Automation",
      provider: client.automationTargetedTampering ? "Stealth Automation" : client.antiDetectBrowser ? "Anti-Detect Browser" : client.stealthPluginDetected ? "Stealth Automation (Puppeteer/Playwright)" : "Chromium",
      category: "Automation",
      confidence: 0.94,
      reasons: reasons.length > 0 ? reasons : ["Hard automation artifact reported by client"]
    };
  }
  for (const rule of GOOD_BOT_UA_RULES2) {
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
  for (const rule of AI_AGENT_UA_RULES2) {
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
    const namedOperator = BOT_SIGNATURE_KEYID_PROVIDERS2.find(
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
  const developerToolsAttached = Boolean(
    client.developerTools || client.cdpRuntimeLeak || client.automationEnvironment === "electron" || client.automationEnvironment === "ide_webview"
  );
  return {
    subtype: "human",
    label: "Verified Human",
    provider: "None",
    category: developerToolsAttached ? "Developer Tools" : "Human Interaction",
    confidence: 0.6,
    reasons: developerToolsAttached ? [
      "Interactive browser profile without automation signatures",
      `Developer tools attached (${client.automationEnvironment || "cdp"}) \u2014 informational`
    ] : ["Interactive browser profile without automation signatures"]
  };
}
var AI_BOT_CIDR_SYNC_INTERVAL_MS = 6 * 60 * 60 * 1e3;
var AI_BOT_CIDR_TIMEOUT_MS = 1e4;
var AI_AUTH_DIRECTORY_TIMEOUT_MS = 1500;
var AI_AUTH_DIRECTORY_TTL_MS = 60 * 60 * 1e3;
var AI_FORWARD_DNS_TIMEOUT_MS = 1200;
var AI_FORWARD_DNS_TTL_MS = 60 * 60 * 1e3;
var AI_VERDICT_TABLE_MAX_ENTRIES = 1e4;
var aiBotPrefixTable = new Map(pinnedPrefixEntries());
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
    AI_BOT_CIDR_SOURCES2.map(async (source) => {
      const body = await fetchTextWithTimeout(
        source.url,
        AI_BOT_CIDR_TIMEOUT_MS,
        "application/json"
      );
      if (!body) return;
      try {
        const parsed = JSON.parse(body);
        const prefixes = Array.from(
          /* @__PURE__ */ new Set([
            ...extractAiPrefixes(parsed),
            ...prefixesFromNormalizedFeed(normalizeRegistryFeed(source.id, body), source.id)
          ])
        );
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
    try {
      aiBotCidrTimer = setInterval(() => {
        void runAiBotCidrSync();
      }, AI_BOT_CIDR_SYNC_INTERVAL_MS);
      const handle = aiBotCidrTimer;
      if (typeof handle.unref === "function") handle.unref();
    } catch {
    }
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
  for (const rule of SIGNATURE_HOST_RULES) {
    if (lowerHost === rule.host || lowerHost.endsWith(`.${rule.host}`) || lowerHost.endsWith(rule.host)) {
      return rule.operator;
    }
  }
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
var GOOGLE_VERIFICATION_SUFFIXES = suffixesForAgent("googlebot", "google", "gemini");
var OPENAI_VERIFICATION_SUFFIXES = suffixesForAgent("gptbot", "chatgpt-user", "openai");
var PERPLEXITY_VERIFICATION_SUFFIXES = suffixesForAgent("perplexitybot", "perplexity");
var ANTHROPIC_VERIFICATION_SUFFIXES = suffixesForAgent("claudebot", "anthropic");
var XAI_VERIFICATION_SUFFIXES = suffixesForAgent("grokbot", "xai");
var META_VERIFICATION_SUFFIXES = suffixesForAgent("muse", "meta-externalagent", "meta");
var GCP_ASNS = asnsForAgent("googlebot", "google", "gemini");
var XAI_ASNS = asnsForAgent("grok", "xai");
var META_ASNS = asnsForAgent("muse", "meta");
var AWS_ASNS = asnsForAgent("aws");
var AZURE_ASNS = asnsForAgent("azure");
var PERPLEXITY_ASNS = asnsForAgent("perplexitybot", "perplexity");
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
function proofTierSatisfied(minProof, proofs) {
  const tier = String(minProof ?? "verified").toLowerCase();
  if (/^(none|any|0|ua_claim|automation|claim|ua)$/.test(tier)) return true;
  if (/^(rfc9421|signed_agent|signature|wba|sail|signed|jws|4)$/.test(tier)) return proofs.signature;
  if (/^(cidr|feed|ip|network|3)$/.test(tier)) return proofs.feed || proofs.signature;
  if (/^(fcrdns|dns|reverse|2)$/.test(tier)) return proofs.fcrdns || proofs.signature;
  return proofs.feed || proofs.fcrdns || proofs.signature;
}
function signatureMatchesAgent(webBotAuth, agent) {
  if (!webBotAuth.present) return false;
  const operatorId = operatorIdFromName(agent.provider || agent.id);
  if (webBotAuth.operator === operatorId) return true;
  const haystack = `${webBotAuth.agentHost} ${webBotAuth.keyId} ${webBotAuth.label}`.toLowerCase();
  if (!haystack.trim()) return false;
  if (agent.signatureHosts?.some((host) => haystack.includes(String(host).toLowerCase()))) return true;
  if (agent.keyIdNeedles?.some((needle) => webBotAuth.keyId.toLowerCase().includes(String(needle).toLowerCase()))) {
    return true;
  }
  return haystack.includes(String(agent.provider || "").toLowerCase()) || haystack.includes(agent.id.toLowerCase());
}
async function resolveAiAgentIdentity(input) {
  const ua = input.userAgent || readRequestHeader(input.headers, "user-agent");
  if (!ua) return NO_AI_AGENT;
  if (isRegistryPolicyToken(ua)) return NO_AI_AGENT;
  const registryMatch = findRegistryAgent(ua);
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
  const authoritativeAutomation = Boolean(
    input.client.hardAutomationSignals || input.client.automationTargetedTampering || input.client.webdriver || input.client.cdpDetected || input.client.isBot && input.client.isHeadless || (input.client.botSignals || []).some(
      (signal) => /stealth|headless|chromium|puppeteer|playwright|webdriver/i.test(signal)
    )
  );
  if (authoritativeAutomation && !webBotAuth.present) {
    return NO_AI_AGENT;
  }
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
  if ((asnIn(input.network.asn, GCP_ASNS) || hostMatchesSuffix(await confirmedNames(), ["googleusercontent.com"])) && (webBotAuth.present || silentCloudTelemetry && clientAutomation)) {
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
  if (asnIn(input.network.asn, META_ASNS) && desktopChrome && silentCloudTelemetry && clientAutomation) {
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
    if (openAiUa && !verified && (openAiRangesLoaded || openAiDnsNames.length > 0)) {
      return aiAgentResult({
        agentId: "impostor-spoof",
        agentName: "Spoofed AI Bot Impostor (Unverified IP)",
        operator: "Unverified OpenAI claim",
        executionMode: "Spoofed Impostor",
        verified: false,
        confidence: "Verified",
        evidence: [
          `OpenAI user-agent claim: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not on OpenAI infrastructure`
        ]
      });
    }
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
    if (claudeUa && !verified) {
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
  if ((webBotAuth.present || cloudBrowserOperator) && !registryMatch) {
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
  if (registryMatch) {
    const agent = asLocalAgent(registryMatch);
    if (isRegistryPolicyToken(ua) || agent.policyToken === true) {
      return NO_AI_AGENT;
    }
    const agentRecord = agent;
    const suffixesRaw = agent.fcrdnsSuffixes ?? registryLookup(agentRecord, "verificationSuffixes") ?? registryLookup(agentRecord, "fcrdnsSuffixes");
    const suffixes = Array.isArray(suffixesRaw) ? suffixesRaw.filter((item) => typeof item === "string" && item.length > 0) : suffixesForAgent(agent.id, agent.provider);
    const feedIdsRaw = agent.feedIds ?? registryLookup(agentRecord, "feedIds");
    const feedIds = Array.isArray(feedIdsRaw) ? feedIdsRaw.filter((item) => typeof item === "string" && item.length > 0) : [];
    const registryDnsNames = suffixes.length > 0 ? await confirmedNames() : [];
    const proofs = {
      feed: feedIds.length > 0 && matchesAiPrefixTable(input.publicIp, feedIds),
      fcrdns: hostMatchesSuffix(registryDnsNames, suffixes),
      signature: signatureMatchesAgent(webBotAuth, agent)
    };
    let verified = proofTierSatisfied(agent.minProofForVerified, proofs);
    if (/mistral[\s_-]?ai[\s_-]?training/i.test(agent.id)) verified = false;
    if (/manus/i.test(agent.id) && !proofs.signature) verified = false;
    return aiAgentResult({
      agentId: agent.id,
      agentName: agent.displayName,
      operator: agent.provider,
      executionMode: agent.executionMode || "Autonomous Crawler",
      verified,
      confidence: verified ? "Verified" : "Medium",
      riskScore: verified ? 2 : 8,
      evidence: [
        `Named agent user-agent claim: ${ua.slice(0, 120)}`,
        proofs.feed ? "Source IP matched a registry-published crawler CIDR prefix" : "",
        proofs.fcrdns ? "FCrDNS matched the operator verification suffix" : "",
        proofs.signature ? "RFC 9421 / SAIL signature attributed to the operator" : "",
        ...!verified ? ["Verification sources unavailable \u2014 identity inferred from the user-agent claim"] : [],
        ...directoryEvidence
      ].filter(Boolean)
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
  if (timestamp > 0 && nowMs - timestamp > ENVELOPE_MAX_AGE_MS) {
    tamperedRequest = true;
    reasons.push("Expired or replayed payload timestamp (>65s)");
  } else if (timestamp > 0 && timestamp - nowMs > ENVELOPE_MAX_FUTURE_SKEW_MS) {
    tamperedRequest = true;
    reasons.push("Payload timestamp too far in the future");
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
    const dailyHardwareRow = db2.prepare(
      `/* intel:dailyhardware */ SELECT COUNT(DISTINCT hardware_id) AS n FROM visitors WHERE updated_at_utc >= ?`
    ).get(dayCutoff);
    const subnetRows = db2.prepare(
      `/* intel:subnets24h */ SELECT public_ip FROM visits WHERE visitor_id = ? AND visited_at_utc >= ?`
    ).all(visitorId, dayCutoff);
    const dailyEventRows = db2.prepare(
      `/* intel:dailyevents */ SELECT visitor_id, COUNT(*) AS events FROM visits WHERE visited_at_utc >= ? GROUP BY visitor_id`
    ).all(dayCutoff);
    const eventValues = dailyEventRows.map((entry) => Number(entry.events)).filter((value) => Number.isFinite(value) && value > 0).sort((a, b) => a - b);
    const p98Events24h = eventValues.length > 0 ? eventValues[Math.max(
      0,
      Math.min(eventValues.length - 1, Math.ceil(eventValues.length * 0.98) - 1)
    )] : 0;
    const distinctSubnets24h = new Set(
      subnetRows.map((entry) => subnetOf(String(entry.public_ip || ""))).filter((bucket) => bucket.length > 0)
    ).size;
    const distinctDailyHardware = Math.max(0, Number(dailyHardwareRow?.n ?? 0));
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
      events1h: velocity.events["1_hour"],
      distinctIps24h: velocity.distinct_ip["24_hours"],
      distinctSubnets24h,
      distinctDailyHardware,
      p98Events24h
    };
  } catch {
    return {
      velocity: { ...EMPTY_VELOCITY },
      events24h: 0,
      events1h: 0,
      distinctIps24h: 0,
      distinctSubnets24h: 0,
      distinctDailyHardware: 0,
      p98Events24h: 0
    };
  }
}
function computeDeviceRarity(db2, browserDevice) {
  const honestSuppressed = computeHonestRarity(0, 0);
  try {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1e3).toISOString();
    const row = db2.prepare(
      `SELECT COUNT(DISTINCT hardware_id) AS total
         FROM visits
         WHERE visited_at_utc >= ? AND hardware_id IS NOT NULL AND hardware_id != ''`
    ).get(cutoff);
    const total = Number(row?.total) || 0;
    const matching = total > 0 ? 1 : 0;
    const honest = computeHonestRarity(total, matching);
    if (total < 20) {
      return { rareDevice: false, bucket: "<p95", share: 1, sampleSize: total, matching, honest };
    }
    const share = matching / total;
    const bucket = honest.status === "published" && honest.percentile === "p99_plus" ? ">p99" : honest.status === "published" && honest.percentile === "p95" ? "p95-p99" : "<p95";
    return { rareDevice: bucket !== "<p95", bucket, share, sampleSize: total, matching, honest };
  } catch {
    return { rareDevice: false, bucket: "<p95", share: 1, sampleSize: 0, matching: 0, honest: honestSuppressed };
  }
}
function computeCanonicalRiskLedger(input) {
  return buildGradedRiskLedger(input);
}
function writeHardwareAnchorAndBands(db2, hardwareId, visitorId, simhashHex, nowUtc, distinctStorageSeedsCount) {
  if (!hardwareId) return false;
  try {
    const existing = db2.prepare(
      "SELECT simhash, distinct_storage_seeds_count, visitor_id, first_seen_utc FROM hardware_anchors WHERE hardware_id = ?"
    ).get(hardwareId);
    const changed = !existing || existing.simhash !== simhashHex || Number(existing.distinct_storage_seeds_count) !== distinctStorageSeedsCount || existing.visitor_id !== visitorId;
    if (!changed) return false;
    const firstSeen = existing?.first_seen_utc || nowUtc;
    db2.prepare(
      `INSERT OR REPLACE INTO hardware_anchors
        (hardware_id, visitor_id, simhash, distinct_storage_seeds_count, first_seen_utc, updated_at_utc)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(hardwareId, visitorId, simhashHex, distinctStorageSeedsCount, firstSeen, nowUtc);
    if (LSH_WRITE_POLICY.write_on_hardware_anchor_change_only) {
      let hash;
      try {
        hash = BigInt(`0x${simhashHex || "0"}`);
      } catch {
        hash = 0n;
      }
      const bands = bandHashes(hash);
      for (const band of bands.slice(0, LSH_CONFIG.bands)) {
        db2.prepare(
          `INSERT OR IGNORE INTO identity_lsh_bands (band_idx, band_hash, hardware_id) VALUES (?, ?, ?)`
        ).run(band.band_idx, band.band_hash, hardwareId);
      }
    }
    return true;
  } catch {
    return false;
  }
}
function retrieveLshCandidates(db2, profile) {
  try {
    const hash = simhash512(profile);
    const hardwareIds = /* @__PURE__ */ new Set();
    for (const band of bandHashes(hash)) {
      const rows = db2.prepare("SELECT hardware_id FROM identity_lsh_bands WHERE band_idx = ? AND band_hash = ?").all(band.band_idx, band.band_hash);
      for (const row of rows) if (row.hardware_id) hardwareIds.add(row.hardware_id);
    }
    const candidates = [];
    for (const hardwareId of hardwareIds) {
      const anchor = db2.prepare("SELECT hardware_id, visitor_id, simhash FROM hardware_anchors WHERE hardware_id = ?").get(hardwareId);
      if (!anchor?.simhash) continue;
      try {
        candidates.push({
          hardwareId,
          simhash: BigInt(`0x${anchor.simhash}`),
          visitorId: anchor.visitor_id ?? null
        });
      } catch {
      }
    }
    return candidates;
  } catch {
    return [];
  }
}
function structuralAnchorsMatch(db2, profile, candidateVisitorId, identityHardwareFingerprint) {
  try {
    const row = db2.prepare("SELECT profile_json, hardware_fingerprint FROM visitor_profiles WHERE visitor_id = ?").get(candidateVisitorId);
    if (!row) return { matched: false, reasons: [] };
    if (typeof row.hardware_fingerprint === "string" && row.hardware_fingerprint.length > 0 && row.hardware_fingerprint === identityHardwareFingerprint) {
      return { matched: true, reasons: ["exact hardware fingerprint anchor"] };
    }
    if (typeof row.profile_json !== "string") return { matched: false, reasons: [] };
    const stored = JSON.parse(row.profile_json);
    const current = profile;
    const nested = (value, key) => value && typeof value === "object" ? value[key] : void 0;
    const pairs = [
      { label: "gpu vendor", current: nested(current.gpu, "vendor"), stored: nested(stored.gpu, "vendor"), hard: false },
      { label: "gpu renderer", current: nested(current.gpu, "renderer"), stored: nested(stored.gpu, "renderer"), hard: true },
      { label: "canvas hash", current: nested(current.canvas, "hash"), stored: nested(stored.canvas, "hash"), hard: true },
      { label: "audio hash", current: nested(current.audio, "hash"), stored: nested(stored.audio, "hash"), hard: true },
      { label: "cpu cores", current: nested(current.cpu, "cores"), stored: nested(stored.cpu, "cores"), hard: true },
      { label: "os family", current: nested(current.os, "family"), stored: nested(stored.os, "family"), hard: false },
      { label: "browser family", current: nested(current.browser, "family"), stored: nested(stored.browser, "family"), hard: false }
    ];
    let matches = 0;
    let hardMatches = 0;
    const reasons = [];
    for (const pair of pairs) {
      if (pair.current !== void 0 && pair.current !== null && String(pair.current) === String(pair.stored)) {
        matches += 1;
        if (pair.hard) hardMatches += 1;
        reasons.push(pair.label);
      }
    }
    return { matched: matches >= 2 && hardMatches >= 1, reasons };
  } catch {
    return { matched: false, reasons: [] };
  }
}
function persistRdapNetblockOrg(db2, asn, org) {
  if (!asn || asn === "Unknown" || !org || org === "Unknown") return null;
  try {
    const prefix = normalizeAsnLabel(asn) || asn;
    db2.prepare(
      `INSERT OR REPLACE INTO rdap_prefix_cache (prefix, org, asn, fetched_at_ms) VALUES (?, ?, ?, ?)`
    ).run(prefix, org, asn, Date.now());
    return org;
  } catch {
    return null;
  }
}
function markSchemaMigration(db2, version) {
  try {
    db2.prepare("INSERT OR IGNORE INTO schema_migrations (version, applied_at_utc) VALUES (?, ?)").run(
      version,
      (/* @__PURE__ */ new Date()).toISOString()
    );
  } catch {
  }
}
function assertFrozenRiskTuples() {
  for (const fixture of verifyGradedRiskFixtures()) {
    const actual = [
      fixture.ledger.automation,
      fixture.ledger.tampering,
      fixture.ledger.network,
      fixture.ledger.environment,
      fixture.ledger.velocity
    ];
    const capSum = Object.values(RISK_FAMILY_CAPS).reduce((sum, value) => sum + value, 0);
    const ok = fixture.ok && actual.every((value, index) => value === fixture.expected[index]) && capSum === 130;
    if (!ok) {
      console.error(
        "Frozen graded-risk tuple check failed:",
        fixture.name,
        JSON.stringify(actual),
        "expected",
        fixture.expected
      );
    }
  }
}
assertFrozenRiskTuples();
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
  const rawIncognitoMethod = typeof input?.incognitoMethod === "string" && input.incognitoMethod.trim() ? input.incognitoMethod.trim().slice(0, 120) : void 0;
  const incognitoMethod = humanIncognitoMethod(
    rawIncognitoMethod,
    Boolean(incognitoAlias),
    storageProbeInconclusive(rawIncognitoMethod)
  );
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
    incognitoMethod
    // Storage probe internals are never part of a user-visible browser payload.
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
function readEdgeTransport(req) {
  const unavailable = {
    tlsVersion: "",
    tlsCipher: "",
    clientTcpRtt: null,
    httpProtocol: "",
    colo: ""
  };
  try {
    const raw = req.headers["x-intel-edge-geo"];
    if (typeof raw === "string" && raw) {
      const parsed = JSON.parse(decodeURIComponent(raw));
      unavailable.tlsVersion = typeof parsed.tlsVersion === "string" ? parsed.tlsVersion : "";
      unavailable.tlsCipher = typeof parsed.tlsCipher === "string" ? parsed.tlsCipher : "";
      unavailable.clientTcpRtt = typeof parsed.clientTcpRtt === "number" && Number.isFinite(parsed.clientTcpRtt) ? parsed.clientTcpRtt : null;
      unavailable.httpProtocol = typeof parsed.httpProtocol === "string" ? parsed.httpProtocol : "";
      unavailable.colo = typeof parsed.colo === "string" ? parsed.colo : "";
    }
  } catch {
  }
  return { ...unavailable, ja3: "Unavailable", ja4t: "Unavailable", os_mismatch: "Unavailable" };
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
  const safeNullableStr = (val, maxLen = 120) => typeof val === "string" && val.trim().length > 0 ? val.trim().slice(0, maxLen) : null;
  const rawHardwareExtras = raw ?? {};
  const rawHwId = safeStr(raw?.hardwareId, "", 40);
  const validHwId = /^hwid_[0-9a-f]{16,32}$/i.test(rawHwId) ? rawHwId.toLowerCase() : "hwid_" + crypto.createHash("sha256").update(
    `${browserDevice.os}|${browserDevice.screenResolution}|${browserDevice.pixelRatio}|${safeStr(raw?.gpuRenderer, "gpu")}|${safeStr(raw?.canvasHash, "canvas")}`
  ).digest("hex").slice(0, 20);
  const cpuCores = typeof raw?.cpuCores === "number" && Number.isFinite(raw.cpuCores) && raw.cpuCores > 0 ? Math.min(256, Math.round(raw.cpuCores)) : null;
  const deviceMemoryGb = typeof raw?.deviceMemoryGb === "number" && Number.isFinite(raw.deviceMemoryGb) && raw.deviceMemoryGb > 0 ? Number(raw.deviceMemoryGb) : null;
  const maxTouchPoints = typeof raw?.maxTouchPoints === "number" && Number.isFinite(raw.maxTouchPoints) && raw.maxTouchPoints >= 0 ? Math.min(64, Math.round(raw.maxTouchPoints)) : 0;
  const colorDepth = typeof raw?.colorDepth === "number" && Number.isFinite(raw.colorDepth) && raw.colorDepth > 0 ? Math.min(64, Math.round(raw.colorDepth)) : 24;
  const maxTextureSize = typeof raw?.maxTextureSize === "number" && Number.isFinite(raw.maxTextureSize) && raw.maxTextureSize >= 0 ? Math.round(raw.maxTextureSize) : 0;
  const runtimeOs = inferRuntimeOsVerdict(
    {
      hostOs: safeStr(rawHardwareExtras.hostOs, "", 120),
      gpuRenderer: safeStr(raw?.gpuRenderer, "", 160),
      gpuVendor: safeStr(raw?.gpuVendor, "", 120),
      gpuArchFamily: safeStr(rawHardwareExtras.gpuArchFamily, "", 40),
      architectureSource: safeStr(rawHardwareExtras.architectureSource, "", 80),
      engine: safeStr(rawHardwareExtras.engine, "", 120),
      architecture: safeStr(raw?.architecture, "", 80)
    },
    browserDevice.os
  );
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
    architecture: safeStr(raw?.architecture, browserDevice.os, 80),
    // Silicon-grounded truth: runtime-probed architecture / host OS plus the UA claim and its
    // mismatch verdicts. These are pass-through only — never derived from the User-Agent here.
    architectureSource: safeStr(rawHardwareExtras.architectureSource, "", 80),
    claimedArchitecture: safeStr(rawHardwareExtras.claimedArchitecture, "", 80),
    hostOs: runtimeOs.authoritative && runtimeOs.family ? runtimeOs.family : safeStr(rawHardwareExtras.hostOs, "", 120),
    claimedOs: safeStr(rawHardwareExtras.hostOs, "", 120),
    osProof: runtimeOs.evidence,
    engine: safeStr(rawHardwareExtras.engine, "", 120),
    engineErrorLength: typeof rawHardwareExtras.engineErrorLength === "number" && Number.isFinite(rawHardwareExtras.engineErrorLength) ? Math.max(0, Math.min(512, Math.round(rawHardwareExtras.engineErrorLength))) : void 0,
    gpuArchFamily: safeStr(rawHardwareExtras.gpuArchFamily, "", 40),
    canvasNoise: Boolean(rawHardwareExtras.canvasNoise),
    audioNoise: Boolean(rawHardwareExtras.audioNoise),
    canvasCoarseHash: safeNullableStr(rawHardwareExtras.canvasCoarseHash, 40),
    archUaMismatch: Boolean(rawHardwareExtras.archUaMismatch),
    osUaMismatch: runtimeOs.uaMismatch
  };
}
var AUTOMATION_TAMPERING_REASON_PATTERN = /\b(webdriver[\w$-]*|playwright[\w$-]*|puppeteer[\w$-]*|selenium[\w$-]*|cdc_[a-z0-9_$]+|cdc\b|__webdriver[\w$]*|__playwright[\w$]*|__pwInitscripts[\w$]*|__puppeteer[\w$]*|getter[\s._-]*(?:cdp|devtools|tamper|wrapper)|(?:cdp|devtools)[\s._-]*getter)\b/i;
function detectAutomationTargetedTampering(reasons, botSignals) {
  const collect = (value) => Array.isArray(value) ? value.filter(
    (item) => typeof item === "string" && item.trim().length > 0 && AUTOMATION_TAMPERING_REASON_PATTERN.test(item)
  ).map((item) => item.trim().slice(0, 180)).slice(0, 8) : [];
  const matched = Array.from(/* @__PURE__ */ new Set([...collect(reasons), ...collect(botSignals)]));
  return { detected: matched.length > 0, reasons: matched };
}
function isTimezoneMismatchReason(reason) {
  return /\btime[\s_-]?zone\b/i.test(reason);
}
function isBotFromVerdict(botVerdict) {
  return Boolean(botVerdict) && botVerdict !== "not_detected";
}
function assertBotVerdictParity(serialized, botVerdict) {
  const expected = isBotFromVerdict(botVerdict);
  const mirrors = [serialized.isBot, serialized.securitySignalsIsBot].filter(
    (value) => typeof value === "boolean"
  );
  const parity = mirrors.every((value) => value === expected) && (!serialized.envelopeBot || serialized.envelopeBot === botVerdict);
  if (!parity) {
    console.error("[invariant] isBot / botVerdict parity violation", { serialized, botVerdict, expected });
  }
  return parity;
}
function hasIndependentAutomationProof(raw, requestContext) {
  const rawExtras = raw ?? {};
  return Boolean(
    raw?.stealthPluginDetected || raw?.webdriver || raw?.cdpDetected || raw?.isBot || raw?.canvasFarblingDetected || raw?.replayDetected || raw?.tamperedRequest || rawExtras.automationTargetedTampering || detectAutomationTargetedTampering(rawExtras.tamperingReasons ?? raw?.tamperingDetails?.reasons, raw?.botSignals).detected || requestContext?.tamperedRequest || requestContext?.replayDetected
  );
}
function isConfirmedTorRfpClient(raw, requestContext) {
  return Boolean(requestContext?.clientTorBrowser ?? raw?.isTorBrowserClient) && !hasIndependentAutomationProof(raw, requestContext);
}
var RFP_DEVICE_WIDTH_REASON = /screen\.width disagrees with its own device-width media query/i;
function rfpExemptTamperingDetails(raw) {
  const details = raw?.tamperingDetails ?? {
    anomaly_score: 0,
    anti_detect_browser: false,
    devtools_device_emulation: false,
    reasons: []
  };
  return {
    ...details,
    anti_detect_browser: false,
    reasons: details.reasons.filter((reason) => !RFP_DEVICE_WIDTH_REASON.test(reason)),
    anomaly_score: Math.min(details.anomaly_score, 0.39)
  };
}
function sanitizeAndReinforceSecuritySignals(raw, browserDevice, hardwareSignals, location, ipTimezoneHint, recognitionSource, baseClassification, velocity, incognitoContext = {}, requestContext = {}) {
  const safeStrArray = (arr) => Array.isArray(arr) ? arr.filter((item) => typeof item === "string" && item.trim().length > 0).map((s) => s.trim().slice(0, 180)).slice(0, 10) : [];
  const rfpExempt = isConfirmedTorRfpClient(raw, requestContext);
  const clientTorBrowser = Boolean(requestContext.clientTorBrowser ?? raw?.isTorBrowserClient);
  const tamperingResponse = rfpExempt ? false : Boolean(raw?.tampering);
  const tamperingDetailsResponse = rfpExempt ? rfpExemptTamperingDetails(raw) : raw?.tamperingDetails;
  const webdriver = Boolean(raw?.webdriver);
  const cdpDetected = Boolean(raw?.cdpDetected);
  const isHeadless = Boolean(raw?.isHeadless);
  const rawBotReason = typeof raw?.botReason === "string" && raw.botReason.trim() ? raw.botReason.trim().slice(0, 200) : "";
  const botSignals = safeStrArray(raw?.botSignals);
  const clientAutomationDetected = Boolean(raw?.isBot || webdriver || cdpDetected);
  const automationTampering = detectAutomationTargetedTampering(
    [
      ...raw?.tamperingReasons ?? [],
      ...tamperingDetailsResponse?.reasons ?? []
    ],
    botSignals
  );
  const automationTargetedTampering = Boolean(requestContext.automationTargetedTampering) || automationTampering.detected;
  const antiDetectBrowser = rfpExempt ? false : Boolean(raw?.tamperingDetails?.anti_detect_browser);
  const tamperingMlScore = typeof raw?.tamperingMlScore === "number" && Number.isFinite(raw.tamperingMlScore) ? raw.tamperingMlScore : 0;
  const mlTampering = rfpExempt ? false : tamperingMlScore >= 0.5;
  const developerToolsAttached = Boolean(
    raw?.developerTools || raw?.cdpRuntimeLeak || raw?.automationEnvironment === "electron" || raw?.automationEnvironment === "ide_webview"
  );
  const stealthAutomation = Boolean(
    raw?.stealthPluginDetected || antiDetectBrowser || automationTargetedTampering
  );
  const activeDeception = Boolean(
    raw?.stealthPluginDetected || antiDetectBrowser || automationTargetedTampering
  );
  const hardAutomationReasons = [];
  if (automationTargetedTampering) {
    hardAutomationReasons.push(
      `Automation-targeted tampering (${automationTampering.reasons.slice(0, 2).join("; ") || "webdriver / playwright / CDC / CDP getter wrappers"})`
    );
  }
  if (raw?.cdpRuntimeLeak) {
    hardAutomationReasons.push("CDP Runtime.enable serialization leak");
  }
  if (raw?.stealthPluginDetected) {
    hardAutomationReasons.push("Stealth plugin artifacts (non-native getters / iframe leak)");
  }
  if (antiDetectBrowser) {
    hardAutomationReasons.push("Anti-detect browser footprint (tamperingDetails)");
  }
  if (mlTampering) {
    hardAutomationReasons.push(`Browser tampering ML score ${tamperingMlScore.toFixed(3)}`);
  }
  const rawBotClassification = requestContext.botClassification ?? classifyBotTraffic(
    requestContext.headers,
    { org: location.org, isp: location.isp, asn: location.asn },
    {
      isBot: clientAutomationDetected,
      isHeadless,
      webdriver,
      cdpDetected,
      botSignals,
      cdpRuntimeLeak: Boolean(raw?.cdpRuntimeLeak),
      stealthPluginDetected: Boolean(raw?.stealthPluginDetected),
      developerTools: developerToolsAttached,
      automationEnvironment: raw?.automationEnvironment,
      humanCorroboration: raw?.humanCorroboration,
      antiDetectBrowser,
      tamperingMlScore,
      automationTargetedTampering,
      automationTamperingReasons: automationTampering.reasons
    }
  );
  const botClassification = stealthAutomation && rawBotClassification.subtype !== "bad_bot" ? {
    subtype: "bad_bot",
    label: antiDetectBrowser ? "Anti-Detect Browser" : "Stealth / CDP Automation",
    provider: antiDetectBrowser ? "Anti-Detect Browser" : "Stealth Automation (Puppeteer/Playwright)",
    category: "Automation",
    confidence: 0.94,
    reasons: hardAutomationReasons.length > 0 ? hardAutomationReasons : ["Hard automation artifact reported by client"]
  } : rawBotClassification;
  const botSubtype = botClassification.subtype;
  const botReason = (botSubtype === "bad_bot" || botSubtype === "ai_agent") && (!rawBotReason || /verified human|native dom/i.test(rawBotReason)) ? hardAutomationReasons[0] || botClassification.reasons[0] || "Automation runtime detected" : rawBotReason;
  const spoofedCrawler = botClassification.subtype === "bad_bot" && botClassification.label === "Spoofed Crawler";
  const isBot = requestContext.botVerdict ? isBotFromVerdict(requestContext.botVerdict) : botSubtype === "bad_bot" || botSubtype === "ai_agent";
  const browserTimezone = typeof raw?.browserTimezone === "string" && raw.browserTimezone.trim() ? raw.browserTimezone.trim().slice(0, 80) : browserDevice.timezone || "UTC";
  const ipTimezone = ipTimezoneHint || (typeof raw?.ipTimezone === "string" && raw.ipTimezone.trim() && raw.ipTimezone !== "Unavailable" ? raw.ipTimezone.trim().slice(0, 80) : "Unavailable");
  const normBrowserTz = normalizeServerTimezoneId(browserTimezone);
  const normIpTz = normalizeServerTimezoneId(ipTimezone);
  const serverTzMismatch = Boolean(normBrowserTz && normIpTz && normBrowserTz !== normIpTz);
  const timezoneMismatch = Boolean(raw?.timezoneMismatch) || serverTzMismatch;
  const isGpuMaskedOrUnavailable = !hardwareSignals.gpuVendor || hardwareSignals.gpuVendor === "Unavailable" || /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuVendor) || !hardwareSignals.gpuRenderer || hardwareSignals.gpuRenderer === "Unavailable" || /^Standard (GPU|WebGL|Hardware)/i.test(hardwareSignals.gpuRenderer);
  const concreteVpnNetworkEvidence = Boolean(requestContext.torExitNode || requestContext.torRelay) || !baseClassification.isConsumerBroadband && Boolean(baseClassification.isDatacenterOrHosting || location.isVpnOrHosting);
  const classification = applyNetworkOverrides(baseClassification, {
    torExit: Boolean(requestContext.torExitNode || requestContext.torRelay),
    torOperatorHint: Boolean(requestContext.torOperatorHint),
    isTorBrowserClient: clientTorBrowser,
    aiAgentDetected: Boolean(requestContext.aiAgent?.detected),
    datacenterVm: Boolean(raw?.isVirtualMachine) && (baseClassification.isDatacenterOrHosting || isGpuMaskedOrUnavailable),
    // A timezone mismatch is its own orthogonal axis, never a commercial VPN signal. The raw
    // client `vpnSuspected` is deliberately NOT used here — only concrete network evidence.
    vpnSuspected: concreteVpnNetworkEvidence
  });
  const isCloudOrDatacenterNetwork = classification.isDatacenterOrHosting || Boolean(location.isVpnOrHosting);
  const datacenterAsn = classification.isConsumerBroadband ? false : isCloudOrDatacenterNetwork;
  const vpnReasons = safeStrArray(raw?.vpnReasons).filter((reason) => !/time[_ -]?zone/i.test(reason));
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
  const commercialVpnProvider = !baseClassification.isConsumerBroadband && baseClassification.networkType === "VPN / Proxy Relay" && VPN_PROXY_PATTERN.test(networkHaystackForVpn) && !HOSTING_EGRESS_PATTERN.test(networkHaystackForVpn);
  const verifiedProxyRelay = detectProxyHeaders(requestContext.headers, location.publicIp).detected;
  const concreteVpnEvidence = commercialVpnProvider || Boolean(requestContext.torExitNode || requestContext.torRelay) || verifiedProxyRelay;
  const vpnMethods = {
    timezone_mismatch: hasTzMismatch,
    public_vpn: commercialVpnProvider,
    auxiliary_mobile: false,
    os_mismatch: Boolean(raw?.isOsTampered),
    relay: Boolean(torExitNode),
    // A client ML verdict is accepted ONLY when an independent, concrete relay signal
    // corroborates it (provider-owned VPN, Tor relay or verified proxy chain). Never ASN alone,
    // never timezone alone — both are orthogonal axes, not tunnels.
    ml_prediction: Boolean(raw?.vpnSuspected) && concreteVpnEvidence
  };
  const vpnSuspected = vpnMethods.public_vpn || vpnMethods.relay || vpnMethods.ml_prediction || vpnMethods.os_mismatch;
  const rawTamperReasons = safeStrArray(raw?.tamperReasons);
  const timezoneOnlyTamper = rawTamperReasons.length > 0 && rawTamperReasons.every((reason) => isTimezoneMismatchReason(reason));
  const tamperDetected = Boolean(
    !timezoneOnlyTamper && raw?.tamperDetected || requestContext.tamperedRequest
  );
  const tamperReasons = rawTamperReasons.filter((reason) => !isTimezoneMismatchReason(reason));
  if (requestContext.tamperedRequest && requestContext.requestIntegrityReason && !tamperReasons.includes(requestContext.requestIntegrityReason)) {
    tamperReasons.unshift(requestContext.requestIntegrityReason);
    tamperReasons.splice(10);
  }
  const rawIncognitoConfidence = raw?.incognitoConfidence;
  const incognitoConfidenceHigh = rawIncognitoConfidence === "high" || typeof rawIncognitoConfidence === "number" && rawIncognitoConfidence >= 0.9;
  const incognitoLikely = incognitoConfidenceHigh && Boolean(raw?.incognitoLikely);
  const incognitoConfidenceLabel = incognitoConfidenceHigh ? "high" : "low";
  const storageQuotaMb = typeof raw?.storageQuotaMb === "number" && Number.isFinite(raw.storageQuotaMb) && raw.storageQuotaMb > 0 ? Math.round(raw.storageQuotaMb) : null;
  const webrtcCandidateIp = typeof raw?.webrtcCandidateIp === "string" && raw.webrtcCandidateIp.trim() ? raw.webrtcCandidateIp.trim().slice(0, 64) : null;
  const webrtcDetail = typeof raw?.webrtcDetail === "string" && raw.webrtcDetail.trim() ? raw.webrtcDetail.trim().slice(0, 200) : "";
  const privacyProtected = Boolean(raw?.privacyProtected);
  const privacyDetail = typeof raw?.privacyDetail === "string" && raw.privacyDetail.trim() ? raw.privacyDetail.trim().slice(0, 200) : "";
  const canvasFarblingDetected = Boolean(raw?.canvasFarblingDetected);
  const clientReportedVm = Boolean(raw?.isVirtualMachine);
  const isOsTampered = Boolean(raw?.isOsTampered);
  const vmReason = typeof raw?.vmReason === "string" && raw.vmReason.trim() ? raw.vmReason.trim().slice(0, 200) : "";
  const rawIncognitoMethod = typeof raw?.incognitoMethod === "string" && raw.incognitoMethod.trim() ? raw.incognitoMethod.trim().slice(0, 120) : "";
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
  const incognitoMethod = humanIncognitoMethod(
    rawIncognitoMethod,
    isIncognito,
    storageProbeInconclusive(rawIncognitoMethod)
  );
  const tierFor = (score) => score >= 7 ? "High" : score >= 3 ? "Medium" : "Low";
  const levelFor = (score) => score >= 7 ? "high" : score >= 3 ? "medium" : "low";
  const incognitoScore = isIncognito ? 3 : 0;
  const incognitoSignal = {
    id: "incognito",
    title: "Incognito / Private Browsing",
    status: isIncognito ? "Incognito / Private Mode" : "Standard Window",
    scoreOutOf10: incognitoScore,
    riskLabel: `${tierFor(incognitoScore)} Risk \u2022 ${incognitoScore}/10`,
    level: levelFor(incognitoScore),
    // Human-readable probe outcome only. Ratio numbers, "fail-open", IDB and other diagnostic
    // internals stay out of every user-visible surface.
    detail: isIncognito ? "Ephemeral / private storage detected" : humanIncognitoMethod(incognitoMethod, false, storageProbeInconclusive(incognitoMethod))
  };
  const aiAgent = requestContext.aiAgent ?? null;
  const registryAgent = requestContext.registryAgent ?? null;
  const spoofedImpostor = aiAgent?.agentId === "impostor-spoof" || botSubtype === "bad_bot" && spoofedCrawler;
  const registryCategory = registryAgent?.category || "";
  const verifiedNamedAgent = Boolean(registryAgent && aiAgent?.verified);
  const verifiedGoodCrawler = verifiedNamedAgent && isGoodCrawlerCategory(registryCategory);
  const verifiedAiAgent = verifiedNamedAgent && !isGoodCrawlerCategory(registryCategory);
  const botScore = spoofedImpostor ? 10 : activeDeception ? 9 : botSubtype === "bad_bot" ? 7 : verifiedGoodCrawler ? 0 : verifiedAiAgent ? 2 : botSubtype === "ai_agent" ? 7 : botSubtype === "good_bot" ? 2 : 0;
  const tileRuntimeOs = inferRuntimeOsVerdict(
    {
      hostOs: hardwareSignals.hostOs,
      gpuRenderer: hardwareSignals.gpuRenderer,
      gpuVendor: hardwareSignals.gpuVendor,
      gpuArchFamily: hardwareSignals.gpuArchFamily,
      architectureSource: hardwareSignals.architectureSource,
      engine: hardwareSignals.engine,
      architecture: hardwareSignals.architecture
    },
    browserDevice.os
  );
  const registryIdentity = spoofedImpostor ? "spoofed" : aiAgent?.verified ? /signed/i.test(String(aiAgent.executionMode || "")) ? "signed" : "verified" : "unknown";
  const automationLabel = String(botClassification.label || "");
  const headlessAutomation = /headless|chromium|puppeteer|playwright/i.test(automationLabel) || /headless/i.test(hardAutomationReasons.join(" "));
  const rawBotStatus = (
    // A named agent is ALWAYS shown by its exact registry name, including when its claim
    // failed verification — the identity badge (Spoofed / Unverified) carries that fact.
    registryAgent ? registryDisplay(registryAgent, registryIdentity).label : stealthAutomation || botSubtype === "bad_bot" ? headlessAutomation ? "Headless Browser Automation" : "Stealth Automation" : aiAgent?.detected && aiAgent.agentName ? aiAgent.agentName : botSubtype === "ai_agent" ? automationLabel || "AI Agent" : botSubtype === "good_bot" ? automationLabel || "Search Crawler" : "Verified Human"
  );
  const botStatus = crispBotStatus(rawBotStatus, tileRuntimeOs);
  const aiAgentDetail = aiAgent?.detected && aiAgent.agentName ? `${aiAgent.agentName} \u2014 ${aiAgent.operator}${aiAgent.executionMode ? ` \xB7 ${aiAgent.executionMode}` : ""} \xB7 ${aiAgent.confidence}${aiAgent.verified ? " (verified)" : ""}: ${aiAgent.evidence[0] || "agent identity attributed from request headers"}` : "";
  const registryBotDetail = registryAgent && aiAgent?.detected ? `${registryAgent.displayName} \u2014 ${registryAgent.provider}${registryAgent.category ? ` \xB7 ${registryAgent.category}` : ""} \xB7 ${aiAgent.verified ? "verified by first-party evidence" : "unverified identity claim"}: ${aiAgent.evidence.find(
    (line) => /CIDR|FCrDNS|signature|SAIL|Web Bot Auth/i.test(line)
  ) || aiAgent.evidence[0] || "agent identity attributed from request headers"}` : "";
  const botDetail = scrubOsClaim(
    stealthAutomation ? `${hardAutomationReasons.join("; ") || "Stealth / anti-detect automation runtime detected"} \u2014 hard automation artifact, never a verified human` : botSubtype === "human" && !aiAgent?.detected ? developerToolsAttached ? `Verified human interactive session \xB7 developer tools attached${raw?.automationEnvironment && raw.automationEnvironment !== "none" ? ` (${raw.automationEnvironment})` : ""}` : "Verified human interactive session" : registryBotDetail ? registryBotDetail : aiAgentDetail ? aiAgentDetail : botSubtype === "ai_agent" ? `${botClassification.provider} ${botClassification.label} \u2014 ${botClassification.reasons[0] || KNOWN_AI_CRAWLER_REASON}` : botSubtype === "good_bot" ? `${botClassification.provider} ${botClassification.label} verified against its official network \u2014 ${botClassification.reasons[1] || "ASN / organisation match"}` : botReason || botClassification.reasons[0] || (spoofedCrawler ? "Crawler user-agent claimed from a network that does not belong to the operator" : "WebDriver / CDP automation runtime detected"),
    tileRuntimeOs
  );
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
  const concreteTunnelVerdict = Boolean(
    vpnMethods.public_vpn || vpnMethods.relay || vpnMethods.ml_prediction
  );
  const vpnScore = torAnonymity ? 9 : ipBlocklisted ? 9 : verifiedCrawlerNetwork ? 2 : torRelayNetwork ? 6 : aiAgent?.detected ? 7 : concreteTunnelVerdict ? 6 : isDatacenterAsn && hasTzMismatch ? 4 : isDatacenterAsn ? 3 : hasTzMismatch ? 2 : 0;
  const vpnStatus = torAnonymity ? torExitNode && torBrowserClient ? "Tor Exit Node & Tor Browser" : torExitNode ? "Tor Exit Node" : "Tor Browser (Onion Routing / RFP)" : ipBlocklisted ? "Blocklisted IP" : verifiedCrawlerNetwork ? "Verified Crawler Network" : torRelayNetwork ? "Tor Relay (Non-Exit)" : aiAgent?.detected ? "AI Agent Cloud Network" : concreteTunnelVerdict ? "VPN / Proxy Relay" : isDatacenterAsn ? "Datacenter / Hosting Network" : hasTzMismatch ? "Not detected" : "Standard ISP";
  const vpnDetail = torAnonymity ? `${torExitNode ? "Confirmed active Tor exit relay" : "Tor Browser fingerprint (Gecko RFP + letterboxing)"} (${location.publicIp} \xB7 ${torOperatorLabel || asnOrOrg})${torOperatorHint ? " \u2014 DNSEL unreachable, operator attribution used" : ""}${torExitNode && torBrowserClient ? " \xB7 server exit IP and client RFP both matched" : ""}` : ipBlocklisted ? "IP flagged on abuse / tamper blocklist" : verifiedCrawlerNetwork ? `${botClassification.provider} crawler operating from its own ${ispBrand}${asnSuffix} \u2014 crawler infrastructure, not a consumer proxy` : torRelayNetwork ? `Tor relay network (${torOperatorLabel || asnOrOrg}) \u2014 part of the Tor network but not an exit egress` : aiAgent?.detected ? `${aiAgent.agentName} (${aiAgent.operator}) \u2014 ${aiAgent.executionMode || "AI agent"} traffic from ${ispBrand}${asnSuffix}` : concreteTunnelVerdict ? vpnMethods.public_vpn ? `Verified commercial VPN provider on ${ispBrand}${asnSuffix}` : vpnMethods.relay ? `Tor relay / anonymity infrastructure (${torOperatorLabel || asnOrOrg})` : `Verified proxy-chain / relay evidence on ${ispBrand}${asnSuffix}` : isDatacenterAsn && hasTzMismatch ? `Datacenter ASN (${ispBrand}${asnSuffix}) \u2014 network ownership observation; the timezone difference is reported on the network axis only` : isDatacenterAsn ? `Datacenter / hosting ASN detected on ${ispBrand}${asnSuffix}` : hasTzMismatch ? "Not detected \u2014 no VPN, proxy or relay evidence. Timezone difference is a separate network observation." : `${ispBrand} \u2022 ${classification.networkType} (${asnLabel}) verified against browser timezone ${browserTimezone}`;
  const vpnSignal = {
    id: "vpn",
    title: "VPN / Proxy & Network Type",
    status: vpnStatus,
    scoreOutOf10: vpnScore,
    riskLabel: `${tierFor(vpnScore)} Risk \u2022 ${vpnScore}/10`,
    level: levelFor(vpnScore),
    detail: vpnDetail
  };
  const HYPERVISOR_GPU_PATTERN = /virtualbox|\bvbox\b|vmware|svga3d|\bqemu\b|virtio|virgl|\bbochs\b|hyper-?v|microsoft remote display|parallels|citrix|\bxen\b/i;
  const gpuSignatureText = `${hardwareSignals.gpuVendor || ""} ${hardwareSignals.gpuRenderer || ""}`;
  const hypervisorGpuProof = HYPERVISOR_GPU_PATTERN.test(gpuSignatureText);
  const cloudContainerVmReason = /cloud container|datacenter asn|masked webgl|software renderer/i.test(
    vmReason
  );
  const hostVirtualizationProof = hypervisorGpuProof || clientReportedVm && !cloudContainerVmReason && !isGpuMaskedOrUnavailable;
  const isVm = hostVirtualizationProof && !emulatorDetected;
  const vmReasonVerdict = isVm ? vmReason && !cloudContainerVmReason ? vmReason : hypervisorGpuProof ? "Hypervisor-specific GPU signature detected in the WebGL vendor / renderer" : "Host-level virtualization evidence detected" : "";
  const isTampered = isOsTampered;
  const vmLike = isVm;
  const vmScore = tamperedRequest || replayDetected ? 10 : emulatorDetected ? 8 : vmLike || isTampered ? 6 : 0;
  const vmStatus = tamperedRequest || replayDetected ? "Tampered / Replayed" : emulatorDetected ? "Mobile Emulator" : vmLike ? "Virtual Machine / VM" : isTampered ? "Spoofed Environment" : "Physical Hardware";
  const vmDetail = tamperedRequest || replayDetected ? requestIntegrityReason || "Sealed request envelope failed verification" : emulatorDetected ? emulatorReason || vmReason || "Mobile emulator / simulator runtime detected" : vmLike ? vmReasonVerdict : isTampered ? vmReason || tamperReasons[0] || "Operating-system / User-Agent tampering detected" : "Unmasked physical GPU & consistent OS platform verified";
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
  let calibratedScore = 0;
  if (isIncognito) calibratedScore = Math.max(calibratedScore, 3);
  if (raw?.developerTools) calibratedScore = Math.max(calibratedScore, 3);
  if (hasTzMismatch) calibratedScore = Math.max(calibratedScore, 2);
  if (raw?.proxyDetected) calibratedScore = Math.max(calibratedScore, 4);
  if (isDatacenterAsn) {
    calibratedScore = Math.max(calibratedScore, hasTzMismatch ? 4 : 3);
  }
  if (vmScore > 0) calibratedScore = Math.max(calibratedScore, vmScore);
  if (isHeadless && !isBot) calibratedScore = Math.max(calibratedScore, 6);
  if (isBot) calibratedScore = Math.max(calibratedScore, activeDeception ? 9 : 7);
  if (ipBlocklisted) calibratedScore = Math.max(calibratedScore, 8);
  if (tamperDetected || tamperingResponse) calibratedScore = Math.max(calibratedScore, 9);
  if (integrityViolation) calibratedScore = Math.max(calibratedScore, 9);
  if (torExitNode) calibratedScore = Math.max(calibratedScore, 9);
  if (activeDeception) calibratedScore = Math.max(calibratedScore, 9);
  if (spoofedImpostor) calibratedScore = 10;
  const weightedCompositeScore = Math.min(10, calibratedScore);
  const cardScores = [incognitoScore, botScore, vpnScore, vmScore];
  const maxCardScore = Math.max(0, ...cardScores);
  const elevatedCardCount = cardScores.filter((score) => score >= 4).length;
  const synergyBonus = elevatedCardCount >= 3 ? 2 : elevatedCardCount === 2 ? 1 : 0;
  const criticalDeception = Boolean(
    activeDeception || spoofedImpostor || tamperDetected || tamperingResponse || integrityViolation || torExitNode
  );
  const cardFloorScore = Math.max(weightedCompositeScore, maxCardScore + synergyBonus);
  const suspectScore = criticalDeception ? Math.min(10, cardFloorScore) : Math.min(8, cardFloorScore);
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
      `${torExitNode ? "Confirmed Tor exit relay" : "Tor Browser fingerprint"} (+9 card): ${torExitNode ? torOperatorHint ? "exit-operator attribution" : "Tor Project DNSEL / consensus exit list" : "Gecko RFP + letterboxing detected on the client"} ${location.publicIp}`
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
      // Corrected verdicts only: a cloud ASN / masked GPU never reaches these host-level fields.
      isVirtualMachine: isVm,
      vmReason: vmReasonVerdict,
      isOsTampered,
      incognitoOrCleared,
      // Client-side private-browsing probe. The collector emits a stable 'high' | 'low' label;
      // preserve it verbatim so 'low' can never be mistaken for an incognito verdict. The cast
      // bridges the legacy numeric type declaration while the shared type migrates to the label.
      incognitoConfidence: incognitoConfidenceLabel,
      incognitoDetail: humanIncognitoMethod(
        typeof raw?.incognitoDetail === "string" ? raw.incognitoDetail : rawIncognitoMethod,
        isIncognito,
        storageProbeInconclusive(rawIncognitoMethod)
      ),
      // Final 4-signal upgrade — private browsing, bot, network, VM integrity
      isIncognito,
      incognito: isIncognito,
      privateMode: isIncognito,
      incognitoMethod,
      headroomGiB,
      // Ratio / flush diagnostics stay internal: only the human storage outcome is serialized.
      idbDurabilityRatio: null,
      opfsFlushMs: null,
      isHeadless,
      botReason,
      webdriver,
      cdpDetected,
      // Protocol-level and stealth-plugin evidence reaches the payload, the grid and the JSON.
      cdpRuntimeLeak: Boolean(raw?.cdpRuntimeLeak),
      stealthPluginDetected: Boolean(raw?.stealthPluginDetected),
      automationTargetedTampering,
      automationTamperingReasons: automationTampering.reasons,
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
      tampering: tamperingResponse,
      tamperingConfidence: raw?.tamperingConfidence || "high",
      tamperingMlScore: rfpExempt ? 24e-4 : typeof raw?.tamperingMlScore === "number" ? raw.tamperingMlScore : 24e-4,
      tamperingDetails: tamperingDetailsResponse,
      developerTools: developerToolsAttached,
      automationEnvironment: raw?.automationEnvironment || "none",
      humanCorroboration: typeof raw?.humanCorroboration === "number" && Number.isFinite(raw.humanCorroboration) ? Math.max(0, Math.min(1, raw.humanCorroboration)) : 0,
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
app.post("/api/visitor/identify", identifyRateLimit, async (req, res) => {
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
      // Cloudflare terminates TLS in front of the origin: req.secure is false there but the
      // forwarded proto / cf-visitor header proves HTTPS. http://localhost stays insecure.
      secure: isSecureRequest({
        secure: req.secure,
        xForwardedProto: req.headers["x-forwarded-proto"],
        cfVisitor: req.headers["cf-visitor"]
      })
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
    const oneHourAgoMs = Date.now() - VELOCITY_WINDOW_MS["1_hour"];
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
    const rawIncognitoConfidence = rawSecuritySignals?.incognitoConfidence ?? requestBody.incognitoConfidence;
    const incognitoConfidenceHigh = rawIncognitoConfidence === "high" || typeof rawIncognitoConfidence === "number" && rawIncognitoConfidence >= 0.9;
    const clientReportedIncognito = incognitoConfidenceHigh && Boolean(
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
    const headerCarriesBotSignature = Boolean(headerRequestUserAgent) && (AUTOMATION_UA_PATTERN.test(headerRequestUserAgent) || GOOD_BOT_UA_RULES2.some((rule) => rule.pattern.test(headerRequestUserAgent)) || AI_AGENT_UA_RULES2.some((rule) => rule.pattern.test(headerRequestUserAgent)));
    const fullRequestUserAgent = headerCarriesBotSignature ? headerRequestUserAgent : envelopeRequestUserAgent || headerRequestUserAgent;
    const rfpExemptRequest = isConfirmedTorRfpClient(rawSecuritySignals);
    const developerToolsSignals = Boolean(
      rawSecuritySignals?.developerTools || rawSecuritySignals?.cdpRuntimeLeak || rawSecuritySignals?.automationEnvironment === "electron" || rawSecuritySignals?.automationEnvironment === "ide_webview"
    );
    const handlerAutomationTampering = detectAutomationTargetedTampering(
      [
        ...rawSecuritySignals?.tamperingDetails?.reasons ?? [],
        ...rawSecuritySignals?.tamperReasons ?? []
      ],
      rawSecuritySignals?.botSignals
    );
    const automationTargetedTampering = handlerAutomationTampering.detected || Boolean(
      rawSecuritySignals?.automationTargetedTampering
    );
    const hardAutomationSignals = (!rfpExemptRequest || automationTargetedTampering) && Boolean(
      automationTargetedTampering || rawSecuritySignals?.stealthPluginDetected || rawSecuritySignals?.tamperingDetails?.anti_detect_browser
    );
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
        botSignals: Array.isArray(rawSecuritySignals?.botSignals) ? rawSecuritySignals.botSignals : [],
        cdpRuntimeLeak: Boolean(rawSecuritySignals?.cdpRuntimeLeak),
        stealthPluginDetected: Boolean(rawSecuritySignals?.stealthPluginDetected),
        developerTools: developerToolsSignals,
        automationEnvironment: rawSecuritySignals?.automationEnvironment,
        humanCorroboration: rawSecuritySignals?.humanCorroboration,
        antiDetectBrowser: rfpExemptRequest ? false : Boolean(rawSecuritySignals?.tamperingDetails?.anti_detect_browser),
        tamperingMlScore: rfpExemptRequest ? 0 : typeof rawSecuritySignals?.tamperingMlScore === "number" ? rawSecuritySignals.tamperingMlScore : 0,
        automationTargetedTampering,
        automationTamperingReasons: handlerAutomationTampering.reasons
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
    void ensureAiBotCidrSync();
    let aiAgent = await resolveAiAgentIdentity({
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
        botSignals: Array.isArray(rawSecuritySignals?.botSignals) ? rawSecuritySignals.botSignals : [],
        // A hard / stealth automation verdict must suppress cloud-VM agent attribution
        // (verified RFC 9421 signed agents remain exempt inside the resolver).
        hardAutomationSignals,
        automationTargetedTampering
      }
    });
    const registryUaMatch = findRegistryAgent(fullRequestUserAgent);
    const registryAgent = registryUaMatch ? asLocalAgent(registryUaMatch) : lookupAgent(aiAgent.agentId);
    if (registryUaMatch) {
      aiAgent = {
        ...aiAgent,
        agentName: asLocalAgent(registryUaMatch).displayName,
        operator: asLocalAgent(registryUaMatch).provider
      };
    }
    const attributedBotClassification = aiAgent.detected && aiAgent.agentId === "impostor-spoof" ? {
      subtype: "bad_bot",
      label: "Spoofed AI Bot",
      provider: aiAgent.operator,
      category: "Spoofed Identity",
      confidence: 0.99,
      reasons: aiAgent.evidence.slice(0, 3)
    } : aiAgent.detected && aiAgent.agentId !== null ? {
      subtype: registryAgent && aiAgent.verified && isGoodCrawlerCategory(registryAgent.category) ? "good_bot" : "ai_agent",
      label: aiAgent.agentName,
      provider: aiAgent.operator,
      category: registryAgent?.category || "AI Agent",
      confidence: aiAgent.verified ? 0.99 : 0.85,
      reasons: aiAgent.evidence.slice(0, 3)
    } : null;
    const effectiveBotClassification = hardAutomationSignals && attributedBotClassification?.subtype !== "bad_bot" ? botClassification : attributedBotClassification ?? botClassification;
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
        registryAgent,
        ipBlocklisted: blocklist.blocklisted,
        ipBlocklistReasons: blocklist.reasons,
        botClassification: effectiveBotClassification,
        automationTargetedTampering
      }
    );
    const serverVerifiedBrowser = uaIdentity.browserName && uaIdentity.browserName !== "Unknown" ? `${uaIdentity.browserName}${uaIdentity.browserFullVersion ? ` ${uaIdentity.browserFullVersion}` : ""}` : browserDevice.browser;
    const runtimeOsVerdict = inferRuntimeOsVerdict(
      {
        hostOs: hardwareSignals.hostOs,
        gpuRenderer: hardwareSignals.gpuRenderer,
        gpuVendor: hardwareSignals.gpuVendor,
        gpuArchFamily: hardwareSignals.gpuArchFamily,
        architectureSource: hardwareSignals.architectureSource,
        engine: hardwareSignals.engine,
        architecture: hardwareSignals.architecture
      },
      uaIdentity.os && uaIdentity.os !== "Unknown" ? uaIdentity.os : browserDevice.os
    );
    const runtimeOsAuthoritative = runtimeOsVerdict.authoritative && !rfpExemptRequest;
    const uaOsLabel = uaIdentity.os && uaIdentity.os !== "Unknown" ? `${uaIdentity.os}${uaIdentity.osVersion ? ` ${uaIdentity.osVersion}` : ""}` : browserDevice.os;
    const uaOsFamily = osFamilyFromText(uaOsLabel);
    const conflictingRuntimeClaim = Boolean(
      runtimeOsVerdict.family && uaOsFamily && uaOsFamily !== runtimeOsVerdict.family
    );
    const serverVerifiedOs = runtimeOsAuthoritative && runtimeOsVerdict.family ? runtimeOsVerdict.label : conflictingRuntimeClaim && !/\(claimed\)$/i.test(uaOsLabel) ? `${uaOsLabel} (claimed)` : uaOsLabel;
    const osFamilyKey = (value) => {
      const text = String(value || "").toLowerCase();
      if (!text || text === "unknown") return "";
      if (/mac os x|macos|macintosh|\bmac\b/.test(text)) return "macos";
      if (/iphone|ipad|ipod|ipados|\bios\b/.test(text)) return "ios";
      if (/android/.test(text)) return "android";
      if (/windows|win32|win64/.test(text)) return "windows";
      if (/linux|ubuntu|fedora|debian|chrome ?os/.test(text)) return "linux";
      return text.replace(/[^a-z0-9]/g, "");
    };
    const browserFamilyKey = (value) => {
      const text = String(value || "").toLowerCase();
      if (!text || text === "unknown") return "";
      if (/edg(e|a|ios)?\b|edge/.test(text)) return "edge";
      if (/opera|\bopr\b/.test(text)) return "opera";
      if (/firefox|fxios/.test(text)) return "firefox";
      if (/crios|chrome|chromium/.test(text)) return "chrome";
      if (/safari/.test(text)) return "safari";
      return text.replace(/[^a-z0-9]/g, "");
    };
    const serverOsFamily = osFamilyKey(serverVerifiedOs);
    const clientOsFamily = osFamilyKey(browserDevice.os);
    const serverBrowserFamily = browserFamilyKey(serverVerifiedBrowser);
    const clientBrowserFamily = browserFamilyKey(browserDevice.browser);
    const headerMismatch = Boolean(
      serverOsFamily && clientOsFamily && serverOsFamily !== clientOsFamily || serverBrowserFamily && clientBrowserFamily && serverBrowserFamily !== clientBrowserFamily
    );
    securitySignals.serverVerifiedBrowser = serverVerifiedBrowser;
    securitySignals.serverVerifiedOs = serverVerifiedOs;
    securitySignals.headerMismatch = headerMismatch;
    securitySignals.headerMismatchReason = headerMismatch ? `Server headers report ${serverVerifiedBrowser} on ${serverVerifiedOs}, but the client reported ${browserDevice.browser} on ${browserDevice.os}` : "";
    const velocityReport = computeVelocitySignals(
      db,
      visitorId,
      location.publicIp,
      currentSessionId
    );
    const rarityReport = computeDeviceRarity(db, browserDevice);
    const SMALL_CORPUS_DAILY_HARDWARE_LIMIT = 100;
    const FIXED_HIGH_ACTIVITY_EVENTS_24H = 12;
    const FIXED_HIGH_ACTIVITY_EVENTS_1H = 8;
    const FIXED_HIGH_ACTIVITY_DISTINCT_SUBNETS = 3;
    const highActivityThresholdMode = velocityReport.distinctDailyHardware < SMALL_CORPUS_DAILY_HARDWARE_LIMIT ? "fixed_small_corpus" : "p98";
    const highActivityThreshold = highActivityThresholdMode === "fixed_small_corpus" ? FIXED_HIGH_ACTIVITY_EVENTS_24H : Math.max(1, velocityReport.p98Events24h);
    const highActivityDevice = highActivityThresholdMode === "fixed_small_corpus" ? velocityReport.events24h >= FIXED_HIGH_ACTIVITY_EVENTS_24H || velocityReport.events1h >= FIXED_HIGH_ACTIVITY_EVENTS_1H || velocityReport.distinctSubnets24h >= FIXED_HIGH_ACTIVITY_DISTINCT_SUBNETS : velocityReport.events24h >= highActivityThreshold;
    const rawTamperingReasons = Array.isArray(rawSecuritySignals?.tamperingDetails?.reasons) ? rawSecuritySignals.tamperingDetails.reasons.filter(
      (reason) => typeof reason === "string" && reason.trim().length > 0
    ) : [];
    const nonTimezoneTamperingReasons = rawTamperingReasons.filter(
      (reason) => !isTimezoneMismatchReason(reason)
    );
    const timezoneOnlyTampering = rawTamperingReasons.length > 0 && nonTimezoneTamperingReasons.length === 0 && Boolean(securitySignals.timezoneMismatch);
    const clientTampering = timezoneOnlyTampering ? false : rawSecuritySignals?.tampering ?? null;
    const rfpExemptResponse = isConfirmedTorRfpClient(rawSecuritySignals, {
      clientTorBrowser: Boolean(rawSecuritySignals?.isTorBrowserClient),
      tamperedRequest: envelopeVerdict.tamperedRequest,
      replayDetected: envelopeVerdict.replayDetected
    });
    const tamperingAssessment = clientTampering === null ? null : {
      tampering: rfpExemptResponse ? false : Boolean(clientTampering),
      confidence: rawSecuritySignals?.tamperingConfidence || "high",
      mlScore: rfpExemptResponse ? 24e-4 : typeof rawSecuritySignals?.tamperingMlScore === "number" ? rawSecuritySignals.tamperingMlScore : 24e-4,
      details: rfpExemptResponse ? {
        ...rfpExemptTamperingDetails(rawSecuritySignals),
        reasons: nonTimezoneTamperingReasons.filter(
          (reason) => !RFP_DEVICE_WIDTH_REASON.test(reason)
        )
      } : {
        ...rawSecuritySignals?.tamperingDetails ?? {
          anomaly_score: 0,
          anti_detect_browser: false,
          devtools_device_emulation: false
        },
        reasons: nonTimezoneTamperingReasons
      }
    };
    const activeCallSupported = Boolean(rawSecuritySignals?.activeCallSupported);
    const activeCall = activeCallSupported && Boolean(rawSecuritySignals?.activeCall);
    const privacySettings = Boolean(
      rawSecuritySignals?.privacySettings || rawSecuritySignals?.isTorBrowserClient || securitySignals.privacyProtected
    );
    const developerTools = Boolean(rawSecuritySignals?.developerTools);
    const rawExtras = rawSecuritySignals || {};
    const specAssessment = evaluateSpecInvariants({
      deviceMemoryGb: hardwareSignals.deviceMemoryGb,
      networkRtt: typeof rawExtras.networkRtt === "number" ? rawExtras.networkRtt : null,
      battery: rawExtras.battery || null,
      jsHeapSizeLimit: typeof rawExtras.jsHeapSizeLimit === "number" ? rawExtras.jsHeapSizeLimit : null,
      expectedJsHeapSizeLimit: typeof rawExtras.expectedJsHeapSizeLimit === "number" ? rawExtras.expectedJsHeapSizeLimit : null,
      webglRenderer: hardwareSignals.gpuRenderer,
      osFamily: browserDevice.os,
      deviceKind: browserDevice.deviceKind,
      hasPdfFace: typeof rawExtras.pdfViewerEnabled === "boolean" ? rawExtras.pdfViewerEnabled : null,
      transport: {
        httpPlatform: typeof rawExtras.httpPlatform === "string" ? rawExtras.httpPlatform : "",
        httpPlatformVersion: typeof rawExtras.httpPlatformVersion === "string" ? rawExtras.httpPlatformVersion : "",
        jsPlatform: browserDevice.platform
      },
      privacyHardened: Boolean(rfpExemptResponse),
      userAgent: fullRequestUserAgent
    });
    const privacyHardened = Boolean(
      rfpExemptResponse || specAssessment.privacy_hardened || resolvePrivacyHardened({
        userAgent: fullRequestUserAgent,
        torBrowser: Boolean(rawSecuritySignals?.isTorBrowserClient),
        braveShields: Boolean(rawExtras.braveShields),
        firefoxFpp: Boolean(rawExtras.firefoxFpp),
        resistFingerprinting: Boolean(rawExtras.resistFingerprinting),
        safariAtfp: Boolean(rawExtras.safariAtfp)
      })
    );
    if (runtimeOsAuthoritative && runtimeOsVerdict.uaMismatch && !privacyHardened) {
      specAssessment.hardViolations = Array.from(
        /* @__PURE__ */ new Set([...specAssessment.hardViolations, "os_ua_mismatch"])
      );
    }
    const reconciledTampering = enforceTamperingInvariant({
      reasons: [
        ...tamperingAssessment?.details?.reasons || [],
        ...specAssessment.softViolations,
        ...specAssessment.hardViolations
      ],
      hard_spec_violation: specAssessment.hard_spec_violation,
      privacy_hardened: privacyHardened,
      software_renderer: specAssessment.software_renderer
    });
    const agentProofMethod = resolveAgentProofMethod(rawRequestHeaders);
    const rfc9421SignedAgent = Boolean(
      aiAgent?.detected && (agentProofMethod === "rfc9421" || agentProofMethod === "signed_agent" || aiAgent.executionMode === "RFC 9421 Signed Agent")
    );
    const hostingDatacenter = Boolean(
      securitySignals.datacenterAsn || /cloud|datacenter|hosting/i.test(networkTypeLabel)
    );
    const vpnOrRelay = Boolean(
      securitySignals.vpnSuspected || securitySignals.publicVpn || isTorExit || torStatus.isRelay
    );
    const rotatingProxy = Boolean(
      securitySignals.proxyDetected
    );
    const timezoneMismatch = Boolean(securitySignals.timezoneMismatch);
    const swiftshader = specAssessment.software_renderer;
    const ephemeralStorage = Boolean(securitySignals.isIncognito);
    const highActivity = highActivityDevice;
    const extremeRotation = velocityReport.distinctIps24h >= 10;
    const tamperingTierA = Boolean(
      reconciledTampering.detected && (reconciledTampering.hard_spec_violation || tamperingAssessment?.tampering || securitySignals.tamperedRequest || securitySignals.replayDetected)
    );
    const tamperingTierB = Boolean(
      !tamperingTierA && reconciledTampering.detected && securitySignals.tamperDetected
    );
    const tamperingSoft = Boolean(
      !tamperingTierA && !tamperingTierB && specAssessment.softViolations.length > 0
    );
    const riskLedger = computeCanonicalRiskLedger({
      automation: {
        tierA: Boolean(securitySignals.isBot || hardAutomationSignals),
        tierB: Boolean(!securitySignals.isBot && developerTools),
        rfc9421SignedAgent
      },
      tampering: {
        tierA: tamperingTierA,
        tierB: tamperingTierB,
        soft: tamperingSoft,
        privacyHardened
      },
      network: {
        hostingDatacenter,
        vpnOrRelay,
        rotatingProxy,
        timezoneMismatch,
        otherComponentFired: hostingDatacenter || vpnOrRelay || rotatingProxy
      },
      environment: { swiftshader, ephemeralOrPrivateStorage: ephemeralStorage },
      velocity: { high: highActivity, extreme: extremeRotation }
    });
    const suspectScore100 = riskLedger.score_0_100;
    const currentBotName = hardAutomationSignals ? `${effectiveBotClassification.provider} ${effectiveBotClassification.label}`.trim() : (aiAgent?.detected ? aiAgent.agentName : "") || (effectiveBotClassification.subtype !== "human" ? `${effectiveBotClassification.provider} ${effectiveBotClassification.label}`.trim() : "");
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
    const positiveSpoofExclusion = (aiAgent?.evidence || []).some(
      (line) => /is not (on|inside)\b/i.test(line)
    );
    if (hardAutomationSignals) {
      botInfo = {
        category: "browser_automation",
        provider: effectiveBotClassification.provider || "Unknown",
        name: effectiveBotClassification.label || "Automated Tool",
        identity: "unknown"
      };
      botType = automationTargetedTampering ? "stealth_automation" : "browser_automation";
      botVerdict = "bad";
    } else if (aiAgent.detected && registryAgent && aiAgent.agentId !== "impostor-spoof") {
      botInfo = {
        category: registryAgent.category || "ai_agent",
        provider: registryAgent.provider || "Unknown",
        name: registryAgent.displayName || aiAgent.agentName,
        identity: aiAgent.verified ? /signed/i.test(String(aiAgent.executionMode || "")) ? "signed" : "verified" : "unknown"
      };
      botType = registryAgent.id;
      botVerdict = aiAgent.verified && isGoodCrawlerCategory(registryAgent.category) ? "good" : "bad";
    } else if (robodexResult.detected && robodexResult.botInfo) {
      botInfo = robodexResult.botInfo;
      botType = robodexResult.botType;
      botVerdict = botInfo?.identity === "spoofed" || botInfo?.identity === "unknown" ? "bad" : botType === "ai_agent" || botType === "ai_browser" || botType === "browser_automation" ? "bad" : "good";
    } else if (aiAgent.detected) {
      const isImpostor = aiAgent.agentId === "impostor-spoof";
      botInfo = {
        category: isImpostor ? "browser_automation" : "ai_agent",
        provider: aiAgent.operator || "Unknown",
        name: aiAgent.agentName,
        identity: isImpostor ? positiveSpoofExclusion ? "spoofed" : "unknown" : aiAgent.verified ? aiAgent.executionMode === "RFC 9421 Signed Agent" ? "signed" : "verified" : "unknown"
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
    } else if (effectiveBotClassification.subtype === "ai_agent") {
      botInfo = {
        category: "ai_agent",
        provider: effectiveBotClassification.provider || "AI Agent",
        name: effectiveBotClassification.label || "AI Agent",
        identity: "unknown"
      };
      botType = "ai_agent";
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
    if (automationTargetedTampering) {
      botInfo = {
        category: "browser_automation",
        provider: effectiveBotClassification.provider || "Stealth Automation",
        name: effectiveBotClassification.label || "Stealth Automation",
        identity: "unknown"
      };
      botType = "stealth_automation";
      botVerdict = "bad";
    }
    const signedAgentIdentity = Boolean(
      aiAgent?.verified && /signed/i.test(String(aiAgent.executionMode || ""))
    );
    const lingeringCloudAgentLabel = aiAgent?.agentId === "gemini" || /google gemini|cloud agent/i.test(botInfo?.name || "");
    if (lingeringCloudAgentLabel && !signedAgentIdentity && (hardAutomationSignals || botVerdict === "bad" || /stealth|headless|chromium/i.test(String(botType || "")))) {
      securitySignals.aiAgent = null;
      const headlessVariant = /headless|chromium/i.test(String(botType || ""));
      botInfo = {
        category: "browser_automation",
        provider: "Stealth Automation",
        name: headlessVariant ? "Headless Automation" : "Stealth Automation",
        identity: "unknown"
      };
      botType = headlessVariant ? "headless_automation" : "stealth_automation";
      botVerdict = "bad";
    }
    if (botInfo) {
      securitySignals.botInfo = botInfo;
    }
    const canonicalIsBot = isBotFromVerdict(botVerdict);
    securitySignals.isBot = canonicalIsBot;
    assertBotVerdictParity(
      { isBot: canonicalIsBot, securitySignalsIsBot: securitySignals.isBot, envelopeBot: botVerdict },
      botVerdict
    );
    hardwareSignals.incognitoConfidence = incognitoConfidenceHigh ? "high" : "low";
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
    const lshIdentityProfile = {
      ...identityProfile
    };
    delete lshIdentityProfile.screen;
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
      markSchemaMigration(db, "v4-canonical-identity");
      upsertVisitorProfile(db, visitorId, identityProfile, identityHardwareFingerprint, nowUtc);
      upsertBlocks(db, visitorId, blockKeysFor(identityProfile), nowUtc);
      const anchorHash = simhash512(lshIdentityProfile);
      const anchorHashHex = simhashToHex(anchorHash);
      const existingAnchor = db.prepare("SELECT distinct_storage_seeds_count FROM hardware_anchors WHERE hardware_id = ?").get(identityHardwareFingerprint);
      const distinctSeeds = Math.max(
        1,
        Number(existingAnchor?.distinct_storage_seeds_count ?? 0) + (existingVisitor || verifiedVid ? 1 : 0)
      );
      writeHardwareAnchorAndBands(
        db,
        identityHardwareFingerprint,
        visitorId,
        anchorHashHex,
        nowUtc,
        distinctSeeds
      );
      if (existingVisitor || verifiedVid) {
        resolvedIdentity = await resolveVisitor(db, {
          profile: identityProfile,
          storageVisitorId: verifiedVid ?? null,
          isMobileIos
        });
      }
    } catch {
    }
    let visitorFound = Boolean(existingVisitor) || !resolvedIdentity.is_new;
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
    const eventId = safePageLoadId;
    const collectorInspectorProbes = rawExtras.inspectorProbes && typeof rawExtras.inspectorProbes === "object" ? rawExtras.inspectorProbes : {};
    const collectorInteractionEvidence = Array.isArray(rawExtras.interactionEvidence) ? rawExtras.interactionEvidence.filter((item) => typeof item === "string" && item.trim().length > 0).map((item) => item.trim().slice(0, 160)).slice(0, 24) : [];
    rememberPassiveVisit({
      eventId,
      visitorId,
      createdAtMs: Date.now(),
      bot: botVerdict,
      tamperingDetected: Boolean(
        reconciledTampering.detected || securitySignals.tamperedRequest
      ),
      corroborated: false
    });
    const edgeTransport = readEdgeTransport(req);
    const inspectorState = classifyInspectorState({
      cdpAttached: Boolean(rawSecuritySignals?.cdpDetected || rawSecuritySignals?.cdpRuntimeLeak),
      devtoolsActiveVerified: Boolean(rawExtras.devtoolsActiveVerified),
      viewportContractionNormalized: Boolean(rawExtras.viewportContractionNormalized)
    });
    const inspectorFlags = inspectorFlagsForState(inspectorState);
    const automationVerdict = securitySignals.isBot || botVerdict === "bad" || hardAutomationSignals ? "automated" : securitySignals.botSubtype === "human" || botVerdict === "not_detected" ? "human" : "uncertain";
    const verdictState = decideVerdictTier({
      automation: automationVerdict,
      tamperingDetected: reconciledTampering.detected || Boolean(securitySignals.tamperedRequest),
      humanCorroboration: 0,
      hasInteractionEvidence: false
    });
    const identityStage = resolveIdentityStage({
      storageVisitorId: verifiedVid || storedVisitorId,
      storageValid: Boolean(existingVisitor || verifiedVid),
      exactHardwareId: hardwareId,
      distinctStorageSeedsCount: existingVisitor || verifiedVid ? 2 : 1,
      privacyHardened,
      query: simhash512(lshIdentityProfile),
      candidates: retrieveLshCandidates(db, lshIdentityProfile)
    });
    const freshUnanchoredContext = !existingVisitor && !verifiedVid && !storageVerified && !existingHwidVisitor;
    if (identityStage.stage === "lsh_fuzzy" && identityStage.visitorId && identityStage.visitorId !== visitorId && identityStage.visitorId !== identityStage.matchLabel) {
      try {
        const fuzzyAnchor = db.prepare(
          "SELECT MAX(distinct_storage_seeds_count) AS max_seeds FROM hardware_anchors WHERE visitor_id = ?"
        ).get(identityStage.visitorId);
        const structuralMatch = freshUnanchoredContext ? structuralAnchorsMatch(
          db,
          identityProfile,
          String(identityStage.visitorId),
          identityHardwareFingerprint
        ) : null;
        if (fuzzyAnchor && Number(fuzzyAnchor.max_seeds ?? 0) < 2 && (!freshUnanchoredContext || Boolean(structuralMatch?.matched))) {
          const provisionalVisitorId = visitorId;
          visitorId = String(identityStage.visitorId);
          visitorToken = signVisitorId(visitorId);
          isReturning = true;
          visitorFound = true;
          try {
            db.prepare(
              "UPDATE visits SET visitor_id = ? WHERE visitor_id = ? AND page_load_id = ?"
            ).run(visitorId, provisionalVisitorId, safePageLoadId);
            db.prepare(
              `UPDATE visitors
               SET hardware_id = ?, active_session_id = ?, last_activity_utc = ?, updated_at_utc = ?
               WHERE visitor_id = ?`
            ).run(hardwareId, currentSessionId, nowUtc, nowUtc, visitorId);
          } catch {
          }
          resolvedIdentity = {
            ...resolvedIdentity,
            visitor_id: visitorId,
            is_new: false,
            isNew: false
          };
        }
      } catch {
      }
    }
    const identityConfidenceHonest = computeHonestIdentityConfidence({
      labeledPairs: Number(rawExtras.calibrationLabeledPairs ?? 0),
      heldOutEce: Number(rawExtras.calibrationHeldOutEce ?? 1),
      matchStage: identityStage.stage,
      calibratedScore: identityConfidence.score
    });
    const networkOwnership = hostingDatacenter ? "hosting_datacenter" : /cellular|mobile|5g|carrier/i.test(networkTypeLabel) ? "mobile_carrier" : /enterprise|business/i.test(networkTypeLabel) ? "enterprise" : /broadband|residential|consumer/i.test(networkTypeLabel) ? "residential_isp" : "unknown";
    const vpnConfidence = isTorExit || torStatus.isRelay ? "high" : vpnOrRelay && Array.isArray(securitySignals.vpnReasons) && securitySignals.vpnReasons.length > 1 ? "medium" : vpnOrRelay ? "low" : "low";
    const asnOrg = String(normalizeAsnLabel(location.asn) || location.org || "");
    const cachedRdapOrg = persistRdapNetblockOrg(db, String(location.asn || ""), asnOrg);
    const rdapNetblockOrg = typeof rawExtras.rdapNetblockOrg === "string" && rawExtras.rdapNetblockOrg ? rawExtras.rdapNetblockOrg : cachedRdapOrg;
    const netblockReassignmentMismatch = Boolean(
      rdapNetblockOrg && asnOrg && rdapNetblockOrg.toLowerCase() !== asnOrg.toLowerCase() && !asnOrg.toLowerCase().includes(rdapNetblockOrg.toLowerCase())
    );
    const geolocationPermission = typeof rawExtras.geolocationPermission === "string" ? rawExtras.geolocationPermission : "prompt";
    const grantedCoords = rawExtras.grantedGeolocation && typeof rawExtras.grantedGeolocation === "object" && typeof rawExtras.grantedGeolocation.latitude === "number" && typeof rawExtras.grantedGeolocation.longitude === "number" ? rawExtras.grantedGeolocation : null;
    const honestProximity = computeHonestProximity({
      permission: geolocationPermission,
      accuracyM: typeof rawExtras.geolocationAccuracyM === "number" ? rawExtras.geolocationAccuracyM : void 0,
      grantedCoordinates: grantedCoords
    });
    const rarityDecision = decideRarity(rarityReport.sampleSize, rarityReport.matching);
    const rarityUpper = clopperPearsonUpperBound(
      rarityReport.matching,
      rarityReport.sampleSize,
      0.05
    );
    const invariantEnvelope = {
      event_id: eventId,
      identity: {
        match_stage: identityStage.stage,
        match_label: identityStage.matchLabel,
        collision_risk: identityStage.collisionRisk,
        confidence_tier: identityConfidenceHonest.confidence_tier,
        confidence_score: identityConfidenceHonest.confidence_score,
        calibration_status: identityConfidenceHonest.calibration_status
      },
      server_verified: {
        browser: serverVerifiedBrowser,
        os: serverVerifiedOs,
        cf_transport: edgeTransport,
        agent_proof_method: agentProofMethod
      },
      client_claimed: {
        browser: browserDevice.browser,
        os: browserDevice.os
      },
      reconciled_display: {
        browser: serverVerifiedBrowser,
        os: serverVerifiedOs
      },
      automation: {
        bot: botVerdict === "not_detected" ? "not_detected" : botVerdict,
        // Derived from the exact same verdict as the top-level / securitySignals mirrors.
        isBot: canonicalIsBot,
        bot_type: botType,
        named_operator: rfc9421SignedAgent ? aiAgent?.operator || null : null,
        operator_verification_method: agentProofMethod,
        automation_environment: String(rawSecuritySignals?.automationEnvironment || "none"),
        human_corroboration: 0,
        // Collector's passive, isTrusted interaction evidence — mirrored verbatim, never
        // promoted to a proof by itself (corroboration stays 0 until the dedicated update).
        interaction_evidence: collectorInteractionEvidence,
        inspector_probes: collectorInspectorProbes,
        inspector_state: inspectorState,
        cdp_attached: inspectorFlags.cdp_attached,
        // automation_protocol_attached explicitly reports developer_tools:false (CDP binding,
        // not a docked DevTools frontend); only the docked/verified states set it true.
        developer_tools: inspectorState === "automation_protocol_attached" ? false : inspectorFlags.developer_tools || developerToolsSignals
      },
      tampering: {
        detected: reconciledTampering.detected,
        anti_detect_browser: Boolean(rawSecuritySignals?.tamperingDetails?.anti_detect_browser),
        privacy_hardened: privacyHardened,
        tampering_confidence: tamperingAssessment?.confidence || "high",
        tampering_ml_score: tamperingAssessment?.mlScore || 0,
        spec_violations: specAssessment.hardViolations,
        reasons: reconciledTampering.reasons,
        hard_spec_violation: reconciledTampering.hard_spec_violation
      },
      network: {
        network_ownership: networkOwnership,
        bgp_asn: location.asn && location.asn !== "Unknown" ? location.asn : null,
        bgp_asn_org: asnOrg || null,
        rdap_netblock_org: rdapNetblockOrg,
        netblock_reassignment_mismatch: netblockReassignmentMismatch,
        vpn: vpnOrRelay,
        vpn_confidence: vpnConfidence,
        proxy: rotatingProxy,
        proxy_type: rotatingProxy ? "residential_rotating" : isProxyOrVpn ? "datacenter" : "none",
        timezone_mismatch: timezoneMismatch
      },
      environment: {
        software_renderer: swiftshader,
        // SwiftShader is software rendering only (f7d6900) — never hard VM proof, never tampering.
        software_renderer_label: swiftshader ? `Software-rendered: ${hardwareSignals.gpuRenderer || "SwiftShader"}` : null,
        ephemeral_storage: ephemeralStorage,
        virtual_machine_label: securitySignals.isVirtualMachine ? securitySignals.vmReason || "Virtual Machine" : null
      },
      proximity: honestProximity,
      rarity: {
        corpus_n: rarityDecision.corpus_n,
        prevalence_ci95_upper: rarityUpper,
        percentile: rarityDecision.percentile,
        status: rarityDecision.status
      },
      velocity: velocityReport.velocity,
      risk: riskLedger,
      verdict_tier: verdictState.verdict_tier
    };
    const payload = {
      visitorId,
      visitorToken,
      hardwareId,
      isReturning,
      recognitionSource,
      location,
      // Phase 6 — proximity is permission-gated. IP coordinates are never proximity evidence;
      // the canonical envelope and this mirror share the same honest result.
      proximity: honestProximity,
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
      highActivityThresholdMode,
      highActivityThreshold,
      // Single-source-of-truth bot flag + inspector axes mirrored from the canonical envelope.
      isBot: canonicalIsBot,
      cdp_attached: inspectorFlags.cdp_attached,
      inspector_state: inspectorState,
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
      requestIntegrityReason: envelopeVerdict.requestIntegrityReason,
      // Phase 3–6 canonical mirrors. The single envelope above is the source of truth; these
      // top-level mirrors keep existing clients working without any parallel scoring math.
      envelope: invariantEnvelope,
      verdict_tier: verdictState.verdict_tier,
      human_corroboration: verdictState.human_corroboration,
      raw_score: riskLedger.raw_score,
      score_0_100: riskLedger.score_0_100,
      evidence_ledger: riskLedger.evidence_ledger
    };
    res.json(payload);
  } catch (err) {
    console.error("Error in /api/visitor/identify:", err);
    res.status(500).json({ error: "Unable to process visitor identification request." });
  }
});
app.post("/api/visitor/corroborate", identifyRateLimit, (req, res) => {
  try {
    const body = req.body || {};
    const eventId = typeof body.event_id === "string" ? body.event_id.trim().slice(0, 80) : "";
    const visitorId = typeof body.visitorId === "string" ? body.visitorId.trim() : "";
    if (!eventId || !verifyVisitorToken(visitorId, body.visitorToken)) {
      res.status(403).json({ error: "Forbidden", human_corroboration: 0 });
      return;
    }
    const entry = corroborationLedger.get(eventId);
    if (!entry || entry.visitorId !== visitorId) {
      res.status(404).json({ error: "Unknown event_id", human_corroboration: 0 });
      return;
    }
    const fresh = Date.now() - entry.createdAtMs <= ENVELOPE_MAX_AGE_MS;
    const storedVisit = db.prepare("SELECT visit_id, bot_name, risk_level FROM visits WHERE visitor_id = ? AND page_load_id = ?").get(visitorId, eventId);
    const eligible = fresh && Boolean(storedVisit) && entry.bot === "not_detected" && !entry.tamperingDetected && !entry.corroborated;
    if (eligible) {
      entry.corroborated = true;
      res.json({
        event_id: eventId,
        human_corroboration: 1,
        verdict_tier: "Verified Human Interactive Session"
      });
      return;
    }
    res.json({
      event_id: eventId,
      human_corroboration: 0,
      verdict_tier: "Unverified / Passive Session",
      reason: !fresh ? "outside_65s_window" : !storedVisit ? "no_stored_visit" : entry.bot !== "not_detected" ? "automated" : "tampered"
    });
  } catch (err) {
    console.error("Error in /api/visitor/corroborate:", err);
    res.status(500).json({ error: "Unable to process corroboration update.", human_corroboration: 0 });
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
  const existingVary = res.getHeader("Vary");
  const varyValues = typeof existingVary === "string" ? existingVary.split(",").map((item) => item.trim()).filter(Boolean) : [];
  for (const value of ["Cookie", "Sec-CH-UA*"]) {
    if (!varyValues.some((item) => item.toLowerCase() === value.toLowerCase())) varyValues.push(value);
  }
  res.setHeader("Vary", varyValues.join(", "));
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
function osFamilyFromText(value) {
  const text = String(value || "").toLowerCase();
  if (!text) return null;
  if (/iphone|ipad|ipod|ios/.test(text)) return "ios";
  if (/android/.test(text)) return "android";
  if (/mac ?os|macos|macintosh|\bmac\b/.test(text)) return "macos";
  if (/windows|win32|win64|\bwin\b/.test(text)) return "windows";
  if (/linux|ubuntu|fedora|debian|chrome ?os|\blinux\b/.test(text)) return "linux";
  return null;
}
var RUNTIME_OS_LABELS = {
  linux: "Linux",
  macos: "macOS",
  windows: "Windows",
  ios: "iOS",
  android: "Android"
};
function inferRuntimeOsVerdict(input, uaOs) {
  const hostFamily = osFamilyFromText(String(input.hostOs || ""));
  const gpuText = `${input.gpuRenderer || ""} ${input.gpuVendor || ""} ${input.gpuArchFamily || ""}`.toLowerCase();
  let glFamily = null;
  if (/direct3d|d3d ?1[12]|dxgi/.test(gpuText)) glFamily = "windows";
  else if (/metal|apple gpu|apple m[1-9]/.test(gpuText)) glFamily = "macos";
  else if (/mesa|llvmpipe|softpipe|gallium|\bx11\b|wayland/.test(gpuText)) glFamily = "linux";
  else if (/android/.test(gpuText)) glFamily = "android";
  else if (/ios|iphone|ipad/.test(gpuText)) glFamily = "ios";
  const probeText = `${input.architectureSource || ""} ${input.engine || ""} ${input.architecture || ""}`.toLowerCase();
  const highConfidenceProbe = /high[- ]?confidence|math|timing|probe|silicon/.test(probeText);
  const probeFamily = highConfidenceProbe ? osFamilyFromText(probeText) || hostFamily : null;
  const proofs = [];
  if (hostFamily) proofs.push(hostFamily);
  if (glFamily) proofs.push(glFamily);
  if (probeFamily) proofs.push(probeFamily);
  const counts = /* @__PURE__ */ new Map();
  for (const proof of proofs) counts.set(proof, (counts.get(proof) ?? 0) + 1);
  let family = null;
  let best = 0;
  for (const [candidate, count] of counts) {
    if (count > best || count === best && candidate === hostFamily) {
      family = candidate;
      best = count;
    }
  }
  const authoritative = Boolean(family && best >= 2);
  const uaFamily = osFamilyFromText(uaOs);
  return {
    family,
    label: family ? RUNTIME_OS_LABELS[family] : "",
    authoritative,
    uaMismatch: authoritative && Boolean(uaFamily && family && uaFamily !== family),
    evidence: [
      hostFamily ? `Runtime host probe: ${RUNTIME_OS_LABELS[hostFamily]}` : "",
      glFamily ? `WebGL backend: ${RUNTIME_OS_LABELS[glFamily]}` : "",
      probeFamily ? `High-confidence runtime probe: ${RUNTIME_OS_LABELS[probeFamily]}` : ""
    ].filter(Boolean)
  };
}
function humanIncognitoMethod(rawMethod, isIncognito, probeInconclusive) {
  if (isIncognito) return "Ephemeral / private storage detected";
  if (probeInconclusive) return "Storage probe inconclusive (treated as normal)";
  return "Persistent disk-backed storage verified";
}
function storageProbeInconclusive(method) {
  return /inconclusive|fail[- ]?open|indeterminate|unknown|unavailable|low[- ]?confidence/i.test(
    String(method || "")
  );
}
function scrubOsClaim(text, runtimeOs) {
  if (!runtimeOs?.authoritative || !runtimeOs.family) return String(text || "");
  const correct = RUNTIME_OS_LABELS[runtimeOs.family];
  return String(text || "").replace(
    /\b(macOS|Mac OS|Windows|Linux|iOS|Android)\b/gi,
    (match) => match.toLowerCase() === correct.toLowerCase() ? match : correct
  );
}
function crispBotStatus(status, runtimeOs) {
  let value = String(status || "").trim();
  value = value.replace(/\s*\(?(?:low[- ]?confidence|soft signals?|heuristic|probable|possible)\)?/gi, "").replace(/\s{2,}/g, " ").trim();
  value = scrubOsClaim(value, runtimeOs);
  return value || "Automated Traffic";
}
function documentBotVerdict(ua) {
  if (!ua) return { verdict: "not_detected", agent: "" };
  const match = findRegistryAgent(ua);
  if (!match) {
    if (GOOD_BOT_UA_RULES2.some((rule) => rule.pattern.test(ua))) return { verdict: "good", agent: "" };
    if (AI_AGENT_UA_RULES2.some((rule) => rule.pattern.test(ua))) return { verdict: "bad", agent: "" };
    return { verdict: AUTOMATION_UA_PATTERN.test(ua) ? "bad" : "not_detected", agent: "" };
  }
  const agent = asLocalAgent(match);
  if (isRegistryPolicyToken(ua) || agent.policyToken === true) {
    return { verdict: "not_detected", agent: "" };
  }
  return {
    verdict: isGoodCrawlerCategory(agent.category) ? "good" : "bad",
    agent: agent.displayName || ""
  };
}
function escapeHtmlAttribute(value) {
  return String(value).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
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
    app.use((req, res, next) => {
      if (req.method !== "GET" || req.path !== "/") {
        next();
        return;
      }
      const ua = String(req.headers["user-agent"] || "");
      const verdict = documentBotVerdict(ua);
      res.setHeader("X-Intel-Bot-Verdict", verdict.verdict);
      res.setHeader("X-Intel-Bot-Agent", verdict.agent);
      res.setHeader("Cache-Control", "no-store");
      const meta = `<meta name="intel:verdict" content="${escapeHtmlAttribute(
        verdict.verdict
      )}" data-agent="${escapeHtmlAttribute(verdict.agent)}">`;
      fs.readFile(path.join(distPath, "index.html"), "utf8", (readError, html) => {
        if (readError || typeof html !== "string") {
          next();
          return;
        }
        const injected = /<\/head>/i.test(html) ? html.replace(/<\/head>/i, `${meta}</head>`) : `${meta}${html}`;
        res.type("html").send(injected);
      });
    });
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
    const headerValue4 = req.headers["x-vercel-original-path"] || req.headers["x-original-url"] || req.headers["x-rewrite-url"] || req.headers["x-matched-path"];
    if (headerValue4) {
      const original = headerValue4.startsWith("http") ? new URL(headerValue4).pathname + new URL(headerValue4).search : headerValue4;
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

#!/usr/bin/env node
/*
 * scripts/generate-phone-models.mjs
 *
 * WHAT
 *   Generates the phone-model lookup data used by the site from Google's
 *   official supported-device catalog:
 *
 *     https://storage.googleapis.com/play_public/supported_devices.html
 *
 *   That catalog is the source of truth for the `model` value Android reports
 *   in User-Agent Client Hints (Build.MODEL), which is what device matching
 *   is done against.
 *
 *   Outputs (pretty-printed, 2-space indent, trailing newline):
 *     - src/data/generated/androidPhoneModels.json       (full data + stats)
 *     - src/data/generated/androidPhoneModels.meta.json  (summary + note)
 *
 * HOW TO RE-RUN
 *   New devices ship constantly; re-run this periodically to pick them up:
 *
 *       npm run phones:generate
 *
 *   (equivalently: node scripts/generate-phone-models.mjs)
 *
 * BUILD POLICY
 *   Intentionally NOT part of the production build: the site must never depend
 *   on external network access at build time. It only reads the committed JSON
 *   files produced here.
 *
 * PIPELINE (zero npm dependencies, Node built-ins only)
 *   1. download the HTML (fetch + AbortController, 60 s timeout, UTF-8 text)
 *   2. regex-parse <tr> rows and <td> cells (no DOM parser on purpose)
 *   3. normalize cells (strip tags, decode entities, collapse whitespace,
 *      trim surrounding whitespace, then surrounding "single/"double quotes)
 *   4. exclude non-phone rows: emptyModelCode, noDisplayName, then a fixed
 *      first-match-wins keyword list (conservative; tweak when regenerating)
 *   5. deduplicate fully identical rows, then resolve each model code:
 *      unambiguous -> ONE phones entry (variants collapsed, most frequent
 *      deviceCode wins); ambiguous -> recorded in `ambiguous`, no entry
 *
 * ACCOUNTING (holds by construction; rows collapsed into resolved entries are
 * absorbed and therefore do not appear separately in the stats):
 *   totalEntries === phoneEntries + excludedEntries + duplicateRows + ambiguousRows
 *   excludedEntries === sum(excludedBreakdown)  (malformed rows included)
 */

import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE_URL = 'https://storage.googleapis.com/play_public/supported_devices.html';
const FETCH_TIMEOUT_MS = 60_000;

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GEN_DIR = path.join(REPO_ROOT, 'src', 'data', 'generated');
const DATA_PATH = path.join(GEN_DIR, 'androidPhoneModels.json');
const META_PATH = path.join(GEN_DIR, 'androidPhoneModels.meta.json');

const META_NOTE =
  "Regenerated from Google's supported-device catalog. Rerun `npm run phones:generate` periodically to include newly released devices.";

/**
 * Conservative keyword filters against obvious non-phone categories
 * (chromebooks, TVs, wearables, cars, routers, speakers/displays, tablets).
 * First match wins; applied case-insensitively to
 * "retailBrand + ' ' + marketingName + ' ' + deviceCode + ' ' + modelCode".
 * They are intentionally blunt - tweak them when regenerating.
 */
const CATEGORY_FILTERS = [
  ['chromebook', /chromebook|chromebox|chromebase/i],
  ['tv', /\btv\b|android ?tv|bravia|fire ?tv|nexus player|chromecast|freestyle|projector|roku|magic ?box/i],
  ['wearable', /\bwatch\b|\bband\b|\bwear\b|pebble|amazfit|ticwatch|fitbit|galaxy (?:watch|fit)|skagen|fossil hand|\bfit\b/i],
  ['automotive', /automotive|carplay|android ?auto|mbux|head ?unit|vehicle|\b(?:bmw|audi|mercedes.?benz|mercedes|porsche|volkswagen|toyota|ford|volvo|skoda|seat|renault|opel|peugeot|citroen|alpine)\b/i],
  ['router', /\brouter\b|\bcpe\b|\bmodem\b|hotspot|\bmifi\b|\bgateway\b|access ?point|repeater|\bwlan\b/i],
  ['audioOrSmartDisplay', /\bbuds\b|earbuds|headphones|soundbar|\bspeaker\b|nest (?:hub|mini|cam|doorbell|wifi)|smart ?(?:display|speaker)|home ?hub|home ?pod/i],
  ['tablet', /\btablet\b|\btab\b|\bpad\b|mediapad|boox|e-?reader/i],
];

// Keys in the exact order required by the JSON schema.
const REASON_ORDER = [
  'malformedRow',
  'emptyModelCode',
  'noDisplayName',
  'chromebook',
  'tv',
  'wearable',
  'automotive',
  'router',
  'audioOrSmartDisplay',
  'tablet',
];

// -- small helpers -----------------------------------------------------------

const quirks = { quotedCellValues: 0, cellsWithNbsp: 0 };

function bump(map, value) {
  map.set(value, (map.get(value) ?? 0) + 1);
}

function codePointToChar(code, raw) {
  if (!Number.isInteger(code) || code <= 0 || code > 0x10ffff) return raw;
  return String.fromCodePoint(code);
}

function stripTags(input) {
  return input.replace(/<[^>]*>/g, '');
}

// Minimal entity map (named: lt/gt/quot/apos + numeric dec/hex); &amp; is decoded
// last so double-escaped text like "&amp;lt;" survives as "&lt;".
const NAMED_ENTITIES = { lt: '<', gt: '>', quot: '"', apos: "'" };

function decodeEntities(input) {
  return input
    .replace(/&(lt|gt|quot|apos);/g, (whole, name) => NAMED_ENTITIES[name] ?? whole)
    .replace(/&#x([0-9A-Fa-f]+);/g, (whole, hex) => codePointToChar(parseInt(hex, 16), whole))
    .replace(/&#(\d+);/g, (whole, dec) => codePointToChar(parseInt(dec, 10), whole))
    .replace(/&amp;/g, '&');
}

function cleanCell(rawHtml) {
  if (/<\s*(?:i)?nbsp/i.test(rawHtml) || /&nbsp;/i.test(rawHtml)) quirks.cellsWithNbsp++;
  let text = stripTags(rawHtml);
  text = decodeEntities(text);
  text = text.replace(/[\s\u00A0]+/g, ' ').trim();
  // Trim matched surrounding double/single quotes (repeatedly). Everything else
  // is kept verbatim: original casing, punctuation like '+', etc.
  for (;;) {
    if (text.length >= 2 && (text[0] === '"' || text[0] === "'") && text[text.length - 1] === text[0]) {
      quirks.quotedCellValues++;
      text = text.slice(1, -1).trim();
      continue;
    }
    break;
  }
  return text;
}

// -- fetch -------------------------------------------------------------------

async function fetchCatalogText(url) {
  // Explicit AbortController timeout, as required (60 s).
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new Error(`timed out after ${FETCH_TIMEOUT_MS / 1000}s`)),
    FETCH_TIMEOUT_MS,
  );
  try {
    const response = await fetch(url, {
      headers: { accept: 'text/html', 'user-agent': 'phones-generate (+site data refresh)' },
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText || ''}`.trim());
    }
    // The body is genuinely UTF-8; fetch as text.
    return await response.text();
  } finally {
    clearTimeout(timer);
  }
}

// -- parse -------------------------------------------------------------------

function parseCatalog(html) {
  const result = { headerRows: 0, dataRows: 0, malformedRow: 0, rows: [] };
  for (const rowMatch of html.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)) {
    const inner = rowMatch[1];
    // Skip the header row (the row containing <th> cells) without counting it.
    if (/<th\b/i.test(inner)) {
      result.headerRows++;
      continue;
    }
    const cells = [...inner.matchAll(/<td\b[^>]*>([\s\S]*?)<\/td>/gi)].map((m) => cleanCell(m[1]));
    if (cells.length !== 4) {
      result.malformedRow++;
      continue;
    }
    result.rows.push({
      retailBrand: cells[0],
      marketingName: cells[1],
      deviceCode: cells[2],
      modelCode: cells[3],
    });
    result.dataRows++;
  }
  return result;
}

// -- exclusion ---------------------------------------------------------------

function classifyRow(row, counters) {
  // Nothing to report/match -> nothing we can use.
  if (row.modelCode === '') {
    counters.emptyModelCode++;
    return false;
  }
  // No display name (both retail brand and marketing name empty).
  if (row.retailBrand === '' && row.marketingName === '') {
    counters.noDisplayName++;
    return false;
  }
  const combined = `${row.retailBrand} ${row.marketingName} ${row.deviceCode} ${row.modelCode}`;
  for (const [reason, pattern] of CATEGORY_FILTERS) {
    if (pattern.test(combined)) {
      counters[reason]++;
      return false;
    }
  }
  return true;
}

// -- dedup + grouping --------------------------------------------------------

function deduplicateRows(rows) {
  const seen = new Map();
  const unique = [];
  let duplicateRows = 0;
  for (const row of rows) {
    const key = [row.retailBrand, row.marketingName, row.deviceCode, row.modelCode].join('\u0000');
    if (seen.has(key)) {
      duplicateRows++;
      continue;
    }
    seen.set(key, unique.length);
    unique.push(row);
  }
  return { unique, duplicateRows };
}

function groupByModelCode(rows) {
  const byModel = new Map(); // exact (case-sensitive) modelCode -> rows[] in catalog order
  for (const row of rows) {
    const list = byModel.get(row.modelCode);
    if (list) list.push(row);
    else byModel.set(row.modelCode, [row]);
  }
  return [...byModel.entries()];
}

function pickDisplay(map) {
  // Most frequent value; ties go to the first occurrence (insertion order).
  let best = '';
  let bestCount = -1;
  for (const [value, count] of map) {
    if (count > bestCount) {
      best = value;
      bestCount = count;
    }
  }
  return best;
}

// -- model-code resolution ---------------------------------------------------

/**
 * Distinct variants within one modelCode group, keyed by
 * (retailBrand.toLowerCase(), marketingName.toLowerCase()). Rows that differ
 * only in deviceCode share one variant (the normal "same board, several
 * builds" case); display strings keep catalog casing.
 */
function buildVariants(rows) {
  const variants = new Map();
  for (const row of rows) {
    const key = `${row.retailBrand.toLowerCase()}\u0000${row.marketingName.toLowerCase()}`;
    let variant = variants.get(key);
    if (!variant) {
      variant = {
        brandLower: row.retailBrand.toLowerCase(),
        marketingLower: row.marketingName.toLowerCase(),
        brandRaw: new Map(),
        marketingRaw: new Map(),
        deviceRaw: new Map(),
        rowCount: 0,
      };
      variants.set(key, variant);
    }
    variant.rowCount++;
    bump(variant.brandRaw, row.retailBrand);
    bump(variant.marketingRaw, row.marketingName);
    bump(variant.deviceRaw, row.deviceCode);
  }
  return [...variants.values()];
}

function dominantRawCase(candidates) {
  // Most frequent raw string among candidates (first occurrence wins ties).
  const counts = new Map();
  for (const value of candidates) bump(counts, value);
  return pickDisplay(counts);
}

function finalizeUnambiguous(modelCode, rows, winnerMarketingLower, brandLower) {
  // Rows representing the resolved (modelCode, brand, marketing) triple. Rows
  // with an empty marketing name are treated as missing data, not competitors.
  let pool = rows.filter(
    (row) =>
      row.retailBrand.toLowerCase() === brandLower &&
      (row.marketingName.toLowerCase() === winnerMarketingLower || row.marketingName === ''),
  );
  if (pool.length === 0) pool = rows; // safety net; should not happen
  const marketingRows = pool.filter((row) => row.marketingName.toLowerCase() === winnerMarketingLower);
  return {
    status: 'unambiguous',
    entry: {
      retailBrand: dominantRawCase(pool.map((r) => r.retailBrand)),
      marketingName: dominantRawCase(marketingRows.map((r) => r.marketingName)),
      deviceCode: dominantRawCase(pool.map((r) => r.deviceCode)),
      modelCode,
    },
  };
}

/**
 * Resolution rules (first match wins):
 *   1. all non-empty marketingName variants equal (case-insensitive)          -> unambiguous
 *   2. same retailBrand + exactly one distinct non-empty marketingName        -> unambiguous
 *   3. same retailBrand, several names, one strictly dominant (>=2 rows and
 *      strictly beats runner-up by row frequency)                             -> unambiguous
 *   4. anything else                                                          -> ambiguous
 */
function resolveGroup(modelCode, rows) {
  const variants = buildVariants(rows);
  const ambiguous = (reason) => ({
    status: 'ambiguous',
    reason,
    variants: variants.map((v) => ({
      retailBrand: pickDisplay(v.brandRaw),
      marketingName: pickDisplay(v.marketingRaw),
      deviceCode: pickDisplay(v.deviceRaw),
    })),
  });

  // marketingName keys in first-seen order (lower-cased, non-empty).
  const nonEmptyMarketing = [];
  for (const row of rows) {
    const key = row.marketingName.toLowerCase();
    if (key !== '' && !nonEmptyMarketing.includes(key)) nonEmptyMarketing.push(key);
  }
  const brandKeys = [];
  for (const row of rows) {
    const key = row.retailBrand.toLowerCase();
    if (!brandKeys.includes(key)) brandKeys.push(key);
  }

  // Rule 4 shortcut: no variant has a non-empty marketing name to display.
  if (nonEmptyMarketing.length === 0) return ambiguous('no non-empty marketing name');

  if (nonEmptyMarketing.length === 1) {
    const winner = nonEmptyMarketing[0];
    if (brandKeys.length === 1) {
      // Rules 1 + 2 (covers single-row groups too - trivially unambiguous).
      return finalizeUnambiguous(modelCode, rows, winner, brandKeys[0]);
    }
    // Rule 1 across different brands: display the shared marketing name; the
    // displayed brand comes from the rows that actually carry that name.
    const brandCase = dominantRawCase(
      rows.filter((row) => row.marketingName.toLowerCase() === winner).map((row) => row.retailBrand),
    );
    return finalizeUnambiguous(modelCode, rows, winner, brandCase.toLowerCase());
  }

  // Two or more distinct non-empty marketing names.
  if (brandKeys.length === 1) {
    // Rule 3: strictly dominant marketing name by row frequency.
    const counts = new Map();
    for (const key of nonEmptyMarketing) {
      counts.set(key, rows.filter((row) => row.marketingName.toLowerCase() === key).length);
    }
    const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]); // stable -> ties keep first occurrence
    const [topKey, topCount] = ranked[0];
    const runnerUp = ranked[1]?.[1] ?? 0;
    if (topCount >= 2 && topCount > runnerUp) {
      return finalizeUnambiguous(modelCode, rows, topKey, brandKeys[0]);
    }
    return ambiguous('same brand with competing marketing names, none strictly dominant');
  }
  // Rule 4.
  return ambiguous('model code shared by different brands with different marketing names');
}

// -- stats + files -----------------------------------------------------------

function sumCounts(counters) {
  return REASON_ORDER.reduce((total, key) => total + (counters[key] ?? 0), 0);
}

function assertDataShape(data) {
  const stats = data.stats;
  if (stats.totalEntries !== stats.phoneEntries + stats.excludedEntries + stats.duplicateRows + stats.ambiguousRows) {
    throw new Error('invariant failed: totalEntries !== phoneEntries + excludedEntries + duplicateRows + ambiguousRows');
  }
  if (stats.excludedEntries !== sumCounts(stats.excludedBreakdown)) {
    throw new Error('invariant failed: excludedEntries !== sum(excludedBreakdown)');
  }
  if (data.phones.length !== stats.phoneEntries) {
    throw new Error('invariant failed: phones.length !== phoneEntries');
  }
  if (data.ambiguous.length !== stats.ambiguousModelCodes) {
    throw new Error('invariant failed: ambiguous.length !== ambiguousModelCodes');
  }
  for (const phone of data.phones) {
    // Contract: marketingName (and modelCode, the group key) must be non-empty.
    // deviceCode/retailBrand may legitimately be empty in the catalog.
    if (!phone.marketingName || !phone.modelCode) {
      throw new Error(`invariant failed: phone entry with missing field (${JSON.stringify(phone)})`);
    }
  }
  const modelCodes = new Set(data.phones.map((p) => p.modelCode));
  if (modelCodes.size !== data.phones.length) {
    throw new Error('invariant failed: duplicate modelCode in phones[]');
  }
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function statKb(filePath) {
  const info = await stat(filePath);
  return (info.size / 1024).toFixed(1);
}

function sameKeys(actual, expected) {
  return JSON.stringify(Object.keys(actual)) === JSON.stringify(expected);
}

/**
 * Post-write verification: re-read both files, JSON.parse them, and check the
 * arithmetic, key order, and spot lookups (a Pixel and a Samsung Galaxy device
 * that are guaranteed to be in Google's catalog).
 */
async function verifyWrittenFiles(dataValue, metaValue) {
  const dataText = await readFile(DATA_PATH, 'utf8');
  const metaText = await readFile(META_PATH, 'utf8');
  const dataRead = JSON.parse(dataText);
  const metaRead = JSON.parse(metaText);
  const findings = [];
  const fail = (what, detail) => findings.push({ ok: false, what, detail, fatal: true });
  const line = (ok, what, detail) => findings.push({ ok, what, detail, fatal: !ok });

  try {
    // Byte-level check: re-serializing the computed objects must reproduce the
    // stored bytes exactly, so what TypeScript code reads matches what we built.
    const dataSerialized = `${JSON.stringify(dataValue, null, 2)}\n`;
    const metaSerialized = `${JSON.stringify(metaValue, null, 2)}\n`;
    line(dataText === dataSerialized, 'androidPhoneModels.json round-tries byte-for-byte',
      dataText === dataSerialized ? 'stored json matches computed value' : 'stored bytes differ from computed value');
    line(metaText === metaSerialized, 'meta.json round-tries byte-for-byte',
      metaText === metaSerialized ? 'stored json matches computed value' : 'stored bytes differ from computed value');

    assertDataShape(dataRead);
    line(true, 'stats arithmetic',
      `totalEntries=${dataRead.stats.totalEntries} = phoneEntries(${dataRead.stats.phoneEntries}) + excludedEntries(${dataRead.stats.excludedEntries}) + duplicateRows(${dataRead.stats.duplicateRows}) + ambiguousRows(${dataRead.stats.ambiguousRows})`);
    line(true, 'excludedBreakdown sum', `excludedEntries=${dataRead.stats.excludedEntries} === breakdown sum`);
    line(true, 'phones/ambiguous lengths', `phones=${dataRead.phones.length}, ambiguous=${dataRead.ambiguous.length}`);

    line(sameKeys(dataRead, ['schemaVersion', 'sourceUrl', 'generatedAt', 'stats', 'phones', 'ambiguous']),
      'data file key order', 'schemaVersion, sourceUrl, generatedAt, stats, phones, ambiguous');
    line(sameKeys(dataRead.stats, ['totalEntries', 'phoneEntries', 'excludedEntries', 'duplicateRows', 'ambiguousRows', 'ambiguousModelCodes', 'excludedBreakdown']),
      'stats key order', 'totalEntries, phoneEntries, excludedEntries, duplicateRows, ambiguousRows, ambiguousModelCodes, excludedBreakdown');
    line(sameKeys(dataRead.stats.excludedBreakdown, REASON_ORDER), 'excludedBreakdown key order', REASON_ORDER.join(', '));
    line(sameKeys(metaRead, ['sourceUrl', 'generatedAt', 'totalEntries', 'phoneEntries', 'excludedEntries', 'ambiguousModelCodes', 'excludedBreakdown', 'note']),
      'meta key order', 'sourceUrl, generatedAt, totalEntries, phoneEntries, excludedEntries, ambiguousModelCodes, excludedBreakdown, note');
    line(dataRead.phones.length > 0 && sameKeys(dataRead.phones[0], ['retailBrand', 'marketingName', 'deviceCode', 'modelCode']),
      'phone entry key order', 'retailBrand, marketingName, deviceCode, modelCode');
    line(dataRead.generatedAt === metaRead.generatedAt && dataRead.sourceUrl === metaRead.sourceUrl,
      'sourceUrl/generatedAt consistent across files', `generatedAt=${metaRead.generatedAt}`);
    line(metaRead.note === META_NOTE && dataRead.schemaVersion === 1, 'meta note text + schemaVersion', 'schemaVersion=1, note text verbatim');

    // Spot lookups: device families we KNOW must be in the catalog.
    const pixel =
      dataRead.phones.find((p) => /^Pixel (?:6|7|8|9|10)/i.test(p.modelCode)) ??
      dataRead.phones.find((p) => /^Pixel (?:6|7|8|9|10)/i.test(p.marketingName));
    const samsung =
      dataRead.phones.find((p) => /^SM-S9/i.test(p.modelCode)) ??
      dataRead.phones.find((p) => /^SM-S9/i.test(p.deviceCode));
    line(Boolean(pixel), 'spot check: Pixel',
      pixel
        ? `modelCode '${pixel.modelCode}' -> marketingName '${pixel.marketingName}' (device '${pixel.deviceCode}', brand '${pixel.retailBrand}')`
        : 'NOT FOUND - data looks wrong, a Pixel entry should exist');
    line(Boolean(samsung), 'spot check: Samsung Galaxy S',
      samsung
        ? `modelCode '${samsung.modelCode}' -> marketingName '${samsung.marketingName}' (device '${samsung.deviceCode}', brand '${samsung.retailBrand}')`
        : 'NOT FOUND - data looks wrong, a Samsung Galaxy S entry should exist');
    const plusEntry = dataRead.phones.find((p) => /\+/.test(p.marketingName));
    line(Boolean(plusEntry), 'spot check: "+" punctuation preserved',
      plusEntry ? `marketingName '${plusEntry.marketingName}' (modelCode '${plusEntry.modelCode}')` : 'no marketing name containing "+"');
  } catch (error) {
    fail('verification exception', error && error.message ? error.message : String(error));
  }
  return findings;
}

// -- report ------------------------------------------------------------------

function printReport(context, findings, dataRead) {
  const q = context;
  const out = [];
  out.push('='.repeat(78));
  out.push(' phones:generate - supported-device catalog report');
  out.push('='.repeat(78));
  out.push(`source                  : ${SOURCE_URL}`);
  out.push(`generatedAt             : ${q.generatedAt}`);
  out.push('');
  out.push('catalog parsing');
  out.push(`  <tr> blocks           : ${q.rowBlocks}`);
  out.push(`  header rows skipped   : ${q.headerRows}`);
  out.push(`  data rows (non-header): ${q.dataRows}`);
  out.push(`  malformed rows        : ${q.malformedRow} (not exactly 4 <td> cells)`);
  out.push(`  well-formed rows      : ${q.dataRows - q.malformedRow}`);
  out.push('');
  out.push('exclusion (first match wins, applied to raw well-formed rows)');
  for (const reason of REASON_ORDER) {
    const label = reason === 'malformedRow' ? 'malformedRow (parse stage)' : reason;
    out.push(`  ${reason.padEnd(19)}: ${q.counters[reason]}`);
  }
  out.push(`  ${'excludedEntries'.padEnd(19)}: ${q.excludedEntries}`);
  const survivors = q.dataRows - q.malformedRow - (q.excludedEntries - q.malformedRow);
  out.push(`  phone-row survivors   : ${survivors}`);
  out.push('');
  out.push('duplicates & resolution');
  out.push(`  duplicateRows         : ${q.duplicateRows} (fully identical 4-field rows)`);
  out.push(`  unique survivor rows  : ${q.uniqueRows}`);
  out.push(`  rows in resolved groups: ${q.rowsInResolvedGroups} -> collapsed to phoneEntries ${q.phoneEntries}`);
  out.push(`  rows in ambiguous groups: ${q.ambiguousRows} across ${q.ambiguousModelCodes} model code(s)`);
  out.push('');
  out.push('stats written');
  out.push(
    `  totalEntries = ${q.phoneEntries} + ${q.excludedEntries} + ${q.duplicateRows} + ${q.ambiguousRows} = ${q.totalEntries}`,
  );
  out.push(`  phoneEntries           : ${q.phoneEntries}`);
  out.push(`  excludedEntries        : ${q.excludedEntries}`);
  out.push(`  duplicateRows          : ${q.duplicateRows}`);
  out.push(`  ambiguousRows          : ${q.ambiguousRows}`);
  out.push(`  ambiguousModelCodes    : ${q.ambiguousModelCodes}`);
  out.push('');
  out.push(`distinct retailBrand values across phones: ${q.distinctBrands}`);
  out.push('');
  out.push(`sample resolved phones (${context.picks.length})`);
  for (const [i, p] of context.picks.entries()) {
    out.push(`  ${i + 1}. ${p.modelCode} -> ${p.marketingName} [${p.retailBrand} / ${p.deviceCode}]`);
  }
  if (dataRead.ambiguous.length > 0) {
    out.push('');
    out.push(`sample ambiguous model codes (up to 5 of ${dataRead.ambiguous.length})`);
    for (const item of dataRead.ambiguous.slice(0, 5)) {
      const variantText = item.variants
        .map((v) => `'${v.retailBrand}'/'${v.marketingName}'/'${v.deviceCode}'`)
        .join(' | ');
      out.push(`  - ${item.modelCode}: ${variantText}`);
    }
  }
  out.push('');
  out.push('quirks observed during this run');
  out.push(`  cells trimmed of surrounding quotes        : ${quirks.quotedCellValues}`);
  out.push(`  cells containing "&nbsp;" (left verbatim)  : ${quirks.cellsWithNbsp}`);
  out.push(`  phone entries with empty retailBrand       : ${q.emptyBrandPhones}`);
  if (q.residualTablets.length > 0) {
    out.push(`  possible residual tablets (Nexus 7/9/10/Q, Pixel C):`);
    for (const p of q.residualTablets.slice(0, 5)) {
      out.push(`    ${p.modelCode} -> ${p.marketingName}`);
    }
  }
  out.push('');
  out.push('verification (files re-read, JSON.parsed)');
  for (const f of findings) {
    out.push(`  [${f.ok ? 'OK' : 'FAIL'}] ${f.what}: ${f.detail}`);
  }
  out.push('');
  out.push('files');
  out.push(`  ${DATA_PATH} (${q.dataKb} KB)`);
  out.push(`  ${META_PATH} (${q.metaKb} KB)`);
  out.push('='.repeat(78));
  console.log(out.join('\n'));
}

// -- main --------------------------------------------------------------------

function reportFailure(problem) {
  console.error('ERROR: could not generate the phone-model data files. Nothing was written.');
  console.error(`  problem: ${problem}`);
  console.error('  Things to try, in order:');
  console.error(`    1. Check your internet connection/VPN - this URL must be reachable over HTTPS:`);
  console.error(`         ${SOURCE_URL}`);
  console.error('    2. If you are behind a proxy, set HTTPS_PROXY (and NODE_USE_ENV_PROXY=1 so Node\'s fetch honors it), e.g.:');
  console.error('         set HTTPS_PROXY=http://proxy.example:8080 && set NODE_USE_ENV_PROXY=1 && node scripts/generate-phone-models.mjs');
  console.error('    3. Re-run the generator:');
  console.error('         npm run phones:generate');
}

async function main() {
  let html;
  try {
    html = await fetchCatalogText(SOURCE_URL);
  } catch (error) {
    const cause =
      error && error.name === 'AbortError'
        ? `download aborted: ${error.message || 'timeout'}`
        : `download failed: ${error && error.message ? error.message : String(error)}`;
    reportFailure(`${cause} (check internet access / HTTPS_PROXY for ${SOURCE_URL})`);
    return 1;
  }

  const counters = {};
  for (const key of REASON_ORDER) counters[key] = 0;

  const parsed = parseCatalog(html);
  counters.malformedRow = parsed.malformedRow;
  if (parsed.dataRows === 0 && parsed.malformedRow === 0) {
    reportFailure('parsed 0 rows from the catalog - its HTML structure may have changed or the download was truncated');
    return 1;
  }

  // Exclusion first (each raw row gets at most one reason), then dedupe.
  const phoneRows = [];
  for (const row of parsed.rows) {
    if (classifyRow(row, counters)) phoneRows.push(row);
  }
  const { unique, duplicateRows } = deduplicateRows(phoneRows);
  const groups = groupByModelCode(unique);

  const phones = [];
  const ambiguous = [];
  let ambiguousRows = 0;
  let rowsInResolvedGroups = 0;
  for (const [modelCode, rows] of groups) {
    const resolution = resolveGroup(modelCode, rows);
    if (resolution.status === 'unambiguous') {
      phones.push(resolution.entry);
      rowsInResolvedGroups += rows.length;
    } else {
      ambiguous.push({ modelCode, variants: resolution.variants });
      ambiguousRows += rows.length;
    }
  }

  const phoneEntries = phones.length;
  if (phoneEntries === 0) {
    reportFailure('0 phone entries were resolved - filters or catalog format need review');
    return 1;
  }

  const excludedBreakdown = {};
  for (const key of REASON_ORDER) excludedBreakdown[key] = counters[key];
  const excludedEntries = sumCounts(counters);
  const totalEntries = phoneEntries + excludedEntries + duplicateRows + ambiguousRows;

  const generatedAt = new Date().toISOString();
  const dataValue = {
    schemaVersion: 1,
    sourceUrl: SOURCE_URL,
    generatedAt,
    stats: {
      totalEntries,
      phoneEntries,
      excludedEntries,
      duplicateRows,
      ambiguousRows,
      ambiguousModelCodes: ambiguous.length,
      excludedBreakdown,
    },
    phones,
    ambiguous,
  };
  const metaValue = {
    sourceUrl: SOURCE_URL,
    generatedAt,
    totalEntries,
    phoneEntries,
    excludedEntries,
    ambiguousModelCodes: ambiguous.length,
    excludedBreakdown,
    note: META_NOTE,
  };

  // Validate everything BEFORE touching the filesystem (failure => no writes).
  try {
    assertDataShape(dataValue);
  } catch (error) {
    console.error(`ERROR: generated data failed internal sanity checks - nothing was written. ${error && error.message ? error.message : String(error)}`);
    return 1;
  }

  await mkdir(GEN_DIR, { recursive: true });
  await writeJson(DATA_PATH, dataValue);
  await writeJson(META_PATH, metaValue);

  // Post-write verification on the actual stored bytes.
  const findings = await verifyWrittenFiles(dataValue, metaValue);

  // Extra report figures.
  const picks = [];
  const wanted = [
    (p) => /^SM-S9/.test(p.modelCode),
    (p) => /^Pixel (?:6|7|8|9|10)/i.test(p.modelCode),
    (p) => /Redmi/i.test(p.marketingName),
    (p) => /\+/.test(p.marketingName),
    (p) => /Galaxy/i.test(p.marketingName),
  ];
  const pickedCodes = new Set();
  for (const predicate of wanted) {
    if (picks.length >= 5) break;
    const found = phones.find((p) => predicate(p) && !pickedCodes.has(p.modelCode));
    if (found) {
      picks.push(found);
      pickedCodes.add(found.modelCode);
    }
  }
  for (const p of phones) {
    if (picks.length >= 5) break;
    if (!pickedCodes.has(p.modelCode)) {
      picks.push(p);
      pickedCodes.add(p.modelCode);
    }
  }

  const context = {
    generatedAt,
    counters,
    dataRows: parsed.dataRows,
    malformedRow: parsed.malformedRow,
    headerRows: parsed.headerRows,
    rowBlocks: parsed.dataRows + parsed.malformedRow + parsed.headerRows,
    excludedEntries,
    duplicateRows,
    uniqueRows: unique.length,
    rowsInResolvedGroups,
    phoneEntries,
    ambiguousRows,
    ambiguousModelCodes: ambiguous.length,
    totalEntries,
    distinctBrands: new Set(phones.map((p) => p.retailBrand)).size,
    emptyBrandPhones: phones.filter((p) => p.retailBrand === '').length,
    residualTablets: phones.filter((p) => /\bnexus (?:7|9|10|q)\b|\bpixel c\b/i.test(`${p.marketingName} ${p.modelCode}`)),
    picks,
    dataKb: await statKb(DATA_PATH),
    metaKb: await statKb(META_PATH),
  };

  printReport(context, findings, { ambiguous });

  const failed = findings.some((f) => !f.ok);
  if (failed) {
    console.error('VERIFICATION FAILED for at least one check above - review the generated files before trusting them.');
    return 1;
  }
  return 0;
}

let exitCode = 1;
try {
  exitCode = await main();
} catch (error) {
  reportFailure(error && error.message ? error.message : String(error));
  exitCode = 1;
}
if (exitCode !== 0) process.exit(1);

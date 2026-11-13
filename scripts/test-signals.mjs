#!/usr/bin/env node
/**
 * Smart Signals integration harness.
 *
 * Exercises the four server-side "Smart Signals" engines — bot / automation, Tor &
 * network reputation, mobile emulator / VM detection and the sealed request envelope —
 * through the real `POST /api/visitor/identify` endpoint of a running dev server.
 *
 * It sends nothing but ordinary HTTP requests: every request carries a freshly signed
 * `INTEL_ENVELOPE_V1` envelope (exactly the canonical string the server recomputes), the
 * same browser headers a real Chrome build sends, and a spoofable `x-forwarded-for`
 * visitor IP. No npm dependencies, no imports from the app, no writes to disk.
 *
 * Usage:
 *   node scripts/test-signals.mjs                 # against http://127.0.0.1:3000
 *   INTEL_BASE_URL=http://127.0.0.1:3100 node scripts/test-signals.mjs
 *   node scripts/test-signals.mjs --verbose       # dump every Smart Signals verdict
 *
 * Exit code 1 when any assertion fails.
 */

import { createHash, randomBytes } from 'node:crypto';

const BASE_URL = (process.env.INTEL_BASE_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');
const IDENTIFY_URL = `${BASE_URL}/api/visitor/identify`;
const TOR_BULK_LIST_URL = 'https://check.torproject.org/torbulkexitlist';
const TOR_FALLBACK_EXIT_IP = '171.25.193.25';
const ENVELOPE_PROTOCOL = 'INTEL_ENVELOPE_V1';
const VERBOSE = process.argv.includes('--verbose');
const REQUEST_TIMEOUT_MS = 25_000;

/* -------------------------------------------------------------------------- */
/* Assertion bookkeeping                                                       */
/* -------------------------------------------------------------------------- */

let passed = 0;
const failures = []; // { caseId, label, expected, actual, excerpt }
const caseStatus = new Map(); // caseId -> { title, ok, excerpt }

function check(caseId, label, condition, expected, actual) {
  if (condition) {
    passed += 1;
    console.log(`PASS  [${caseId}] ${label}`);
    return true;
  }
  failures.push({
    caseId,
    label,
    expected,
    actual: typeof actual === 'string' ? actual : JSON.stringify(actual),
    excerpt: caseStatus.get(caseId)?.excerpt,
  });
  caseStatus.get(caseId).ok = false;
  console.log(
    `FAIL  [${caseId}] ${label}\n        expected: ${expected}\n        actual  : ${
      typeof actual === 'string' ? actual : JSON.stringify(actual)
    }`
  );
  return false;
}

function excerptOf(json) {
  const ss = json?.securitySignals || {};
  const tiles = ss.smartSignals || json?.smartSignals || {};
  const tile = (t) =>
    t ? { status: t.status, scoreOutOf10: t.scoreOutOf10, riskLabel: t.riskLabel, detail: t.detail } : null;
  return {
    bot: tile(tiles.bot),
    vpn: tile(tiles.vpn),
    vm: tile(tiles.vm),
    incognito: tile(tiles.incognito),
    botSubtype: ss.botSubtype,
    botProvider: ss.botProvider,
    torExitNode: ss.torExitNode,
    ipBlocklisted: ss.ipBlocklisted,
    ipBlocklistReasons: ss.ipBlocklistReasons,
    replayDetected: ss.replayDetected,
    tamperedRequest: ss.tamperedRequest,
    requestIntegrityReason: ss.requestIntegrityReason,
    emulatorDetected: ss.emulatorDetected,
    suspectScore: ss.suspectScore ?? json?.suspectScore,
    location: json?.location,
  };
}

/* -------------------------------------------------------------------------- */
/* Request construction                                                        */
/* -------------------------------------------------------------------------- */

const UA = {
  windowsChrome:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  linuxChrome:
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  androidChrome:
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
  googlebot: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  gptbot:
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)',
  headlessChrome:
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/126.0.0.0 Safari/537.36',
};

const GPU = {
  vendor: 'Google Inc. (NVIDIA)',
  renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
};

/** `hwid_` + 32 lowercase hex chars is the only shape the server accepts verbatim. */
function makeHardwareId() {
  return 'hwid_' + randomBytes(16).toString('hex');
}

function sha256Hex(input) {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * The sealed envelope contract: the SHA-256 of
 * INTEL_ENVELOPE_V1|timestamp|nonce|hardwareId|userAgent|platform|screenResolution|timezone
 * The server recomputes this after sanitizing the body, so `hardwareId` must be the exact
 * value the sanitizer keeps (hwid_ + 16..32 hex, lowercase).
 */
function sealEnvelope({ hardwareId, userAgent, platform, screenResolution, timezone, nonce, timestamp }) {
  const canonical = [
    ENVELOPE_PROTOCOL,
    String(timestamp),
    nonce,
    hardwareId,
    userAgent,
    platform,
    screenResolution,
    timezone,
  ].join('|');
  return {
    timestamp,
    nonce,
    signature: sha256Hex(canonical),
    userAgent,
    platform,
    screenResolution,
    timezone,
    protocol: ENVELOPE_PROTOCOL,
  };
}

function baseBrowserDevice(overrides = {}) {
  return {
    browser: 'Chrome',
    os: 'Windows',
    deviceType: 'Desktop',
    platform: 'Win32',
    screenResolution: '1920x1080',
    pixelRatio: '1',
    language: 'en-US',
    timezone: 'Asia/Kolkata',
    ...overrides,
  };
}

function baseHardwareSignals(hardwareId, overrides = {}) {
  return {
    hardwareId,
    gpuVendor: GPU.vendor,
    gpuRenderer: GPU.renderer,
    maxTextureSize: 16384,
    canvasHash: 'a1b2c3d4e5f60718',
    audioHash: '08f7e6d5c4b3a291',
    cpuCores: 8,
    deviceMemoryGb: 8,
    colorDepth: 24,
    maxTouchPoints: 0,
    hdrSupported: true,
    colorGamut: 'sRGB',
    architecture: 'x86',
    ...overrides,
  };
}

/** A clean, non-suspicious client verdict (the shape a real Chrome collector posts). */
function baseSecuritySignals(overrides = {}) {
  return {
    emulatorDetected: false,
    emulatorReason: '',
    isVirtualMachine: false,
    vmReason: '',
    cloudOrMaskedGpu: false,
    isBot: false,
    webdriver: false,
    cdpDetected: false,
    isHeadless: false,
    botSignals: [],
    incognitoOrCleared: false,
    privacyProtected: false,
    tamperDetected: false,
    tamperReasons: [],
    ...overrides,
  };
}

const BROWSER_HEADERS = {
  accept: 'application/json',
  'accept-language': 'en-US,en;q=0.9',
  'sec-fetch-site': 'same-origin',
  'sec-fetch-mode': 'cors',
  'sec-fetch-dest': 'empty',
  'sec-ch-ua': '"Chromium";v="126", "Not.A/Brand";v="24"',
  'sec-ch-ua-mobile': '?0',
};

/**
 * Builds one ready-to-send identify request. The returned object is exactly what goes on the
 * wire, so a replay test can simply send the same object twice.
 *
 * @param {object} opts
 * @param {string} opts.ip               visitor IP placed in x-forwarded-for
 * @param {string} opts.ua               signed user agent (envelope + body identity)
 * @param {string} [opts.platform]       navigator.platform
 * @param {string} [opts.timezone]       browser timezone
 * @param {object} [opts.browserDevice]  full override of the browserDevice object
 * @param {object} [opts.hardwareSignals] full override of the hardwareSignals object
 * @param {object} [opts.securitySignals] client-computed flags
 * @param {string} [opts.headerUserAgent] raw user-agent header when it must differ from the envelope
 * @param {object} [opts.headers]        extra / overriding headers
 * @param {(body: object) => void} [opts.mutateBody] post-signing body mutation (tamper tests)
 * @param {string} [opts.nonce]
 * @param {number} [opts.timestamp]
 */
function buildIdentifyRequest(opts) {
  const hardwareId = opts.hardwareSignals?.hardwareId ?? makeHardwareId();
  const hardwareSignals = opts.hardwareSignals
    ? { ...baseHardwareSignals(hardwareId), ...opts.hardwareSignals }
    : baseHardwareSignals(hardwareId);
  // The sanitizer lowercases a valid hwid, so sign the lowercase form.
  hardwareSignals.hardwareId = String(hardwareSignals.hardwareId).toLowerCase();

  const browserDevice = opts.browserDevice
    ? { ...baseBrowserDevice(), ...opts.browserDevice }
    : baseBrowserDevice();
  if (opts.platform) browserDevice.platform = opts.platform;
  if (opts.timezone) browserDevice.timezone = opts.timezone;

  const nonce = opts.nonce ?? randomBytes(16).toString('hex');
  const timestamp = opts.timestamp ?? Date.now();

  const envelope = sealEnvelope({
    hardwareId: hardwareSignals.hardwareId,
    userAgent: opts.ua,
    platform: browserDevice.platform,
    screenResolution: browserDevice.screenResolution,
    timezone: browserDevice.timezone,
    nonce,
    timestamp,
  });

  const body = {
    pageLoadId: `pl_test_${randomBytes(6).toString('hex')}`,
    browserDevice,
    hardwareSignals,
    securitySignals: opts.securitySignals ?? baseSecuritySignals(),
    securityEnvelope: envelope,
  };
  if (opts.mutateBody) opts.mutateBody(body);

  const headers = {
    'content-type': 'application/json',
    ...BROWSER_HEADERS,
    'user-agent': opts.headerUserAgent ?? opts.ua,
    'x-forwarded-for': opts.ip,
    'x-intel-signature': envelope.signature,
    'x-intel-nonce': envelope.nonce,
    'x-intel-timestamp': String(envelope.timestamp),
    ...(opts.headers || {}),
  };

  return { body, headers };
}

/** Sends one prepared identify request and returns the parsed JSON. */
async function sendIdentify(request) {
  const response = await fetch(IDENTIFY_URL, {
    method: 'POST',
    headers: request.headers,
    body: JSON.stringify(request.body),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const text = await response.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { error: 'Non-JSON response', raw: text.slice(0, 400) };
  }
  return { status: response.status, json };
}

/** Builds + sends in one call. */
async function postIdentify(opts) {
  return sendIdentify(buildIdentifyRequest(opts));
}

function ssOf(json) {
  return json?.securitySignals || {};
}

function tilesOf(json) {
  const ss = ssOf(json);
  return ss.smartSignals || json?.smartSignals || {};
}

/* -------------------------------------------------------------------------- */
/* Tor exit list                                                              */
/* -------------------------------------------------------------------------- */

async function resolveTorExitIp() {
  try {
    const response = await fetch(TOR_BULK_LIST_URL, {
      headers: { accept: 'text/plain' },
      signal: AbortSignal.timeout(12_000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = await response.text();
    const ips = body
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(line));
    if (ips.length === 0) throw new Error('empty exit list');
    // Prefer the long-lived exit used by the fallback so repeated runs stay stable.
    const exitIp = ips.includes(TOR_FALLBACK_EXIT_IP) ? TOR_FALLBACK_EXIT_IP : ips[0];
    console.log(`Tor exit list: ${ips.length} relays fetched; using ${exitIp}`);
    return exitIp;
  } catch (error) {
    console.warn(
      `WARN  Tor bulk exit list unreachable (${error.message}); falling back to ${TOR_FALLBACK_EXIT_IP}`
    );
    return TOR_FALLBACK_EXIT_IP;
  }
}

/* -------------------------------------------------------------------------- */
/* Cases                                                                      */
/* -------------------------------------------------------------------------- */

async function caseA(torExitIp) {
  const id = 'A';
  caseStatus.set(id, { title: 'Tor exit node', ok: true });
  const { status, json } = await postIdentify({
    ip: torExitIp,
    ua: UA.windowsChrome,
    timezone: 'UTC',
  });
  caseStatus.get(id).excerpt = excerptOf(json);
  check(id, 'HTTP 200', status === 200, '200', status);
  const ss = ssOf(json);
  const vpn = tilesOf(json).vpn || {};
  check(id, 'vpn.status is "Tor Exit Node"', vpn.status === 'Tor Exit Node', 'Tor Exit Node', vpn.status);
  check(id, 'vpn.scoreOutOf10 is 10', vpn.scoreOutOf10 === 10, 10, vpn.scoreOutOf10);
  check(id, 'torExitNode is true', ss.torExitNode === true, true, ss.torExitNode);
}

async function caseB() {
  const id = 'B';
  caseStatus.set(id, { title: 'Spoofed crawler (Googlebot UA, residential IP)', ok: true });
  const { status, json } = await postIdentify({
    ip: '49.36.0.1',
    ua: UA.googlebot,
    platform: 'Linux x86_64',
    timezone: 'Asia/Kolkata',
    browserDevice: { browser: 'Googlebot', os: 'Linux', deviceType: 'Desktop' },
    hardwareSignals: { architecture: 'x86' },
  });
  caseStatus.get(id).excerpt = excerptOf(json);
  check(id, 'HTTP 200', status === 200, '200', status);
  const ss = ssOf(json);
  const bot = tilesOf(json).bot || {};
  check(id, 'botSubtype is "bad_bot"', ss.botSubtype === 'bad_bot', 'bad_bot', ss.botSubtype);
  check(id, 'bot.scoreOutOf10 is 10', bot.scoreOutOf10 === 10, 10, bot.scoreOutOf10);
  check(id, 'bot.status mentions "Spoofed"', /Spoofed/.test(String(bot.status)), 'contains "Spoofed"', bot.status);
}

async function caseC() {
  const id = 'C';
  caseStatus.set(id, { title: 'Verified crawler (Googlebot UA, official Google IP)', ok: true });
  const { status, json } = await postIdentify({
    ip: '66.249.66.1',
    ua: UA.googlebot,
    platform: 'Linux x86_64',
    timezone: 'UTC',
    browserDevice: { browser: 'Googlebot', os: 'Linux', deviceType: 'Desktop' },
  });
  caseStatus.get(id).excerpt = excerptOf(json);
  check(id, 'HTTP 200', status === 200, '200', status);
  const ss = ssOf(json);
  const bot = tilesOf(json).bot || {};
  check(id, 'botSubtype is "good_bot"', ss.botSubtype === 'good_bot', 'good_bot', ss.botSubtype);
  check(id, 'bot.scoreOutOf10 is 2', bot.scoreOutOf10 === 2, 2, bot.scoreOutOf10);
  check(id, 'bot.status contains "Good Bot"', /Good Bot/.test(String(bot.status)), 'contains "Good Bot"', bot.status);
}

async function caseD() {
  const id = 'D';
  caseStatus.set(id, { title: 'AI agent (GPTBot)', ok: true });
  const { status, json } = await postIdentify({
    ip: '49.36.4.1',
    ua: UA.gptbot,
    platform: 'Linux x86_64',
    timezone: 'UTC',
    browserDevice: { browser: 'GPTBot', os: 'Linux', deviceType: 'Desktop' },
  });
  caseStatus.get(id).excerpt = excerptOf(json);
  check(id, 'HTTP 200', status === 200, '200', status);
  const ss = ssOf(json);
  const bot = tilesOf(json).bot || {};
  check(id, 'botSubtype is "ai_agent"', ss.botSubtype === 'ai_agent', 'ai_agent', ss.botSubtype);
  check(id, 'bot.scoreOutOf10 is 8', bot.scoreOutOf10 === 8, 8, bot.scoreOutOf10);
  check(id, 'bot.status contains "AI Agent"', /AI Agent/.test(String(bot.status)), 'contains "AI Agent"', bot.status);
}

async function caseE() {
  const id = 'E';
  caseStatus.set(id, { title: 'Headless automation (HeadlessChrome UA)', ok: true });
  const { status, json } = await postIdentify({
    ip: '49.36.6.1',
    ua: UA.headlessChrome,
    platform: 'Linux x86_64',
    timezone: 'UTC',
    browserDevice: { browser: 'Chrome', os: 'Linux', deviceType: 'Desktop' },
    headers: { 'sec-ch-ua-platform': '"Linux"' },
    securitySignals: baseSecuritySignals({ isHeadless: true, botSignals: ['Headless UA token'] }),
  });
  caseStatus.get(id).excerpt = excerptOf(json);
  check(id, 'HTTP 200', status === 200, '200', status);
  const ss = ssOf(json);
  const bot = tilesOf(json).bot || {};
  // HeadlessChrome is an explicit AI_AGENT_UA_RULES entry ("Cloud Browser Agent"),
  // which is checked before the generic automation rule, so the exact verdict is ai_agent/8.
  check(id, 'botSubtype is "ai_agent"', ss.botSubtype === 'ai_agent', 'ai_agent', ss.botSubtype);
  check(id, 'bot.scoreOutOf10 is 8', bot.scoreOutOf10 === 8, 8, bot.scoreOutOf10);
  check(id, 'bot.status contains "AI Agent"', /AI Agent/.test(String(bot.status)), 'contains "AI Agent"', bot.status);
  check(
    id,
    'bot.scoreOutOf10 is at least 8',
    typeof bot.scoreOutOf10 === 'number' && bot.scoreOutOf10 >= 8,
    '>= 8',
    bot.scoreOutOf10
  );
}

async function caseH() {
  const id = 'H';
  caseStatus.set(id, { title: 'Mobile emulator (Android UA, zero touch points, emulator GPU)', ok: true });
  const { status, json } = await postIdentify({
    ip: '49.36.12.1',
    ua: UA.androidChrome,
    platform: 'Linux x86_64',
    timezone: 'Asia/Kolkata',
    browserDevice: {
      browser: 'Chrome',
      os: 'Android',
      deviceType: 'Mobile',
      screenResolution: '1080x2400',
      pixelRatio: '2.625',
    },
    hardwareSignals: {
      gpuVendor: 'Google LLC',
      gpuRenderer: 'Android Emulator OpenGL ES Translator (Google LLC, Android Emulator)',
      maxTouchPoints: 0,
      cpuCores: 4,
      deviceMemoryGb: 2,
      architecture: 'arm64',
    },
    headers: { 'sec-ch-ua-platform': '"Android"', 'sec-ch-ua-mobile': '?1' },
    // In the real collector this verdict is computed in the browser (touch points vs. UA and
    // an emulator GPU string); the harness posts the probe result the client would send.
    securitySignals: baseSecuritySignals({
      emulatorDetected: true,
      emulatorReason: 'Android user-agent with zero touch points and emulator GPU renderer',
    }),
  });
  caseStatus.get(id).excerpt = excerptOf(json);
  check(id, 'HTTP 200', status === 200, '200', status);
  const ss = ssOf(json);
  const vm = tilesOf(json).vm || {};
  check(id, 'emulatorDetected is true', ss.emulatorDetected === true, true, ss.emulatorDetected);
  check(id, 'vm.status is "Mobile Emulator"', vm.status === 'Mobile Emulator', 'Mobile Emulator', vm.status);
  check(id, 'vm.scoreOutOf10 is 8', vm.scoreOutOf10 === 8, 8, vm.scoreOutOf10);
}

async function caseI() {
  const id = 'I';
  caseStatus.set(id, { title: 'Cloud container (datacenter IP, masked GPU)', ok: true });
  const { status, json } = await postIdentify({
    ip: '34.82.0.1',
    ua: UA.windowsChrome,
    platform: 'Linux x86_64',
    timezone: 'America/Los_Angeles',
    browserDevice: { browser: 'Chrome', os: 'Linux', deviceType: 'Desktop' },
    hardwareSignals: {
      gpuVendor: 'Unavailable',
      gpuRenderer: 'Unavailable',
      maxTouchPoints: 0,
      architecture: 'x86',
    },
    headers: { 'sec-ch-ua-platform': '"Linux"' },
  });
  caseStatus.get(id).excerpt = excerptOf(json);
  check(id, 'HTTP 200', status === 200, '200', status);
  const ss = ssOf(json);
  const vm = tilesOf(json).vm || {};
  check(id, 'datacenterAsn is true', ss.datacenterAsn === true, true, ss.datacenterAsn);
  check(
    id,
    'vm.status is "Virtual Machine / VM"',
    vm.status === 'Virtual Machine / VM',
    'Virtual Machine / VM',
    vm.status
  );
  check(
    id,
    'vm.scoreOutOf10 is 7 or 8',
    vm.scoreOutOf10 === 7 || vm.scoreOutOf10 === 8,
    '7 or 8',
    vm.scoreOutOf10
  );
}

async function caseJ() {
  const id = 'J';
  caseStatus.set(id, { title: 'Clean human (Windows Chrome, residential IP)', ok: true });
  const { status, json } = await postIdentify({
    ip: '49.36.2.1',
    ua: UA.windowsChrome,
    platform: 'Win32',
    timezone: 'Asia/Kolkata',
    headers: { 'sec-ch-ua-platform': '"Windows"', 'sec-ch-ua-mobile': '?0' },
  });
  caseStatus.get(id).excerpt = excerptOf(json);
  check(id, 'HTTP 200', status === 200, '200', status);
  const ss = ssOf(json);
  const tiles = tilesOf(json);
  check(id, 'botSubtype is "human"', ss.botSubtype === 'human', 'human', ss.botSubtype);
  check(id, 'bot.status is "Verified Human"', (tiles.bot || {}).status === 'Verified Human', 'Verified Human', (tiles.bot || {}).status);
  check(id, 'bot.scoreOutOf10 is 0', (tiles.bot || {}).scoreOutOf10 === 0, 0, (tiles.bot || {}).scoreOutOf10);
  check(id, 'vm.scoreOutOf10 is 0', (tiles.vm || {}).scoreOutOf10 === 0, 0, (tiles.vm || {}).scoreOutOf10);
  check(id, 'tamperedRequest is false', ss.tamperedRequest === false, false, ss.tamperedRequest);
  check(id, 'replayDetected is false', ss.replayDetected === false, false, ss.replayDetected);
}

async function caseK() {
  const id = 'K';
  caseStatus.set(id, { title: 'Header / body contradiction (envelope Windows, header Linux)', ok: true });
  const { status, json } = await postIdentify({
    ip: '49.36.14.1',
    // The signed payload claims Windows Chrome...
    ua: UA.windowsChrome,
    platform: 'Win32',
    timezone: 'Asia/Kolkata',
    // ...while the raw HTTP header claims Linux Chrome.
    headerUserAgent: UA.linuxChrome,
    headers: { 'sec-ch-ua-platform': '"Windows"' },
  });
  caseStatus.get(id).excerpt = excerptOf(json);
  check(id, 'HTTP 200', status === 200, '200', status);
  const ss = ssOf(json);
  check(id, 'tamperedRequest is true', ss.tamperedRequest === true, true, ss.tamperedRequest);
  check(
    id,
    'requestIntegrityReason mentions the User-Agent mismatch',
    /user-agent/i.test(String(ss.requestIntegrityReason)),
    'reason contains "User-Agent"',
    ss.requestIntegrityReason
  );
  check(
    id,
    'reason is not a payload hash mismatch',
    !/Payload integrity hash mismatch/i.test(String(ss.requestIntegrityReason)),
    'no "Payload integrity hash mismatch"',
    ss.requestIntegrityReason
  );
  check(
    id,
    'vm status is "Tampered / Replayed"',
    (tilesOf(json).vm || {}).status === 'Tampered / Replayed',
    'Tampered / Replayed',
    (tilesOf(json).vm || {}).status
  );
}

async function caseF() {
  const id = 'F';
  caseStatus.set(id, { title: 'Tampered payload (body hardwareId altered after signing)', ok: true });
  const { status, json } = await postIdentify({
    ip: '49.36.8.1',
    ua: UA.windowsChrome,
    platform: 'Win32',
    timezone: 'Asia/Kolkata',
    headers: { 'sec-ch-ua-platform': '"Windows"' },
    mutateBody: (body) => {
      // Only the BODY changes; the envelope signature (and headers) still cover the original id.
      body.hardwareSignals = { ...body.hardwareSignals, hardwareId: makeHardwareId() };
    },
  });
  caseStatus.get(id).excerpt = excerptOf(json);
  check(id, 'HTTP 200', status === 200, '200', status);
  const ss = ssOf(json);
  const vm = tilesOf(json).vm || {};
  check(id, 'tamperedRequest is true', ss.tamperedRequest === true, true, ss.tamperedRequest);
  check(
    id,
    'requestIntegrityReason is the payload hash mismatch',
    /Payload integrity hash mismatch/i.test(String(ss.requestIntegrityReason)),
    'contains "Payload integrity hash mismatch"',
    ss.requestIntegrityReason
  );
  check(id, 'vm.status is "Tampered / Replayed"', vm.status === 'Tampered / Replayed', 'Tampered / Replayed', vm.status);
  check(id, 'vm.scoreOutOf10 is 10', vm.scoreOutOf10 === 10, 10, vm.scoreOutOf10);
}

async function caseG() {
  const id = 'G';
  caseStatus.set(id, { title: 'Replay (identical signed request sent twice)', ok: true });
  const request = buildIdentifyRequest({
    ip: '49.36.10.1',
    ua: UA.windowsChrome,
    platform: 'Win32',
    timezone: 'Asia/Kolkata',
    headers: { 'sec-ch-ua-platform': '"Windows"' },
  });

  const first = await sendIdentify(request);
  check(id, 'first send HTTP 200', first.status === 200, '200', first.status);
  const firstSs = ssOf(first.json);
  const second = await sendIdentify(request);
  // The second response replaces the excerpt so a failure shows the replay verdict.
  caseStatus.get(id).excerpt = { first: excerptOf(first.json), second: excerptOf(second.json) };

  check(id, 'first send replayDetected is false', firstSs.replayDetected === false, false, firstSs.replayDetected);
  check(id, 'second send HTTP 200', second.status === 200, '200', second.status);
  const secondSs = ssOf(second.json);
  const vm = tilesOf(second.json).vm || {};
  check(id, 'second send replayDetected is true', secondSs.replayDetected === true, true, secondSs.replayDetected);
  check(
    id,
    'second requestIntegrityReason reports the duplicate nonce',
    /Duplicate payload nonce/i.test(String(secondSs.requestIntegrityReason)),
    'contains "Duplicate payload nonce"',
    secondSs.requestIntegrityReason
  );
  check(id, 'second vm.scoreOutOf10 is 10', vm.scoreOutOf10 === 10, 10, vm.scoreOutOf10);
  check(id, 'second vm.status is "Tampered / Replayed"', vm.status === 'Tampered / Replayed', 'Tampered / Replayed', vm.status);
}

/* -------------------------------------------------------------------------- */
/* Runner                                                                     */
/* -------------------------------------------------------------------------- */

function printSummary(startedAtMs) {
  const caseIds = [...caseStatus.keys()];
  const failedCases = caseIds.filter((caseId) => caseStatus.get(caseId).ok === false);
  console.log('\n' + '-'.repeat(78));
  for (const caseId of caseIds) {
    const entry = caseStatus.get(caseId);
    console.log(`${entry.ok ? 'PASS' : 'FAIL'}  ${caseId}  ${entry.title}`);
  }
  console.log('-'.repeat(78));
  console.log(
    `Assertions: ${passed} passed, ${failures.length} failed • Cases: ${
      caseIds.length - failedCases.length
    }/${caseIds.length} passed • ${((Date.now() - startedAtMs) / 1000).toFixed(1)}s`
  );
  if (failures.length > 0) {
    console.log('\nFailure details:');
    for (const failure of failures) {
      console.log(`\n[${failure.caseId}] ${failure.label}`);
      console.log(`  expected: ${failure.expected}`);
      console.log(`  actual  : ${failure.actual}`);
      if (failure.excerpt) {
        console.log('  securitySignals excerpt:');
        console.log(
          JSON.stringify(failure.excerpt, null, 2)
            .split('\n')
            .map((line) => '    ' + line)
            .join('\n')
        );
      }
    }
    console.log(`\nRESULT: FAIL (${failures.length} assertion${failures.length === 1 ? '' : 's'} failed)`);
    return 1;
  }
  console.log('\nRESULT: PASS — all Smart Signals assertions passed.');
  return 0;
}

async function main() {
  const startedAtMs = Date.now();
  console.log('Smart Signals integration harness');
  console.log(`Target: ${IDENTIFY_URL}\n`);

  // Fail fast with a readable message when the dev server is not running.
  try {
    const probe = await fetch(BASE_URL, { signal: AbortSignal.timeout(5000) });
    if (probe.status >= 500) throw new Error(`HTTP ${probe.status}`);
  } catch (error) {
    console.error(`Cannot reach ${BASE_URL}: ${error.message}`);
    console.error('Start the dev server first (it is expected to be already running on port 3000).');
    process.exit(1);
  }

  const torExitIp = await resolveTorExitIp();

  // Sequential on purpose: the nonce cache, the Tor DNS cache and the per-IP abuse ledger
  // are process-global, so concurrent requests would make the verdicts order-dependent.
  // F (tamper) and G (replay) run last because they poison the per-IP ledger.
  const cases = [
    { id: 'A', title: 'Tor exit node', run: () => caseA(torExitIp) },
    { id: 'B', title: 'Spoofed crawler (Googlebot UA, residential IP)', run: caseB },
    { id: 'C', title: 'Verified crawler (Googlebot UA, official Google IP)', run: caseC },
    { id: 'D', title: 'AI agent (GPTBot)', run: caseD },
    { id: 'E', title: 'Headless automation (HeadlessChrome UA)', run: caseE },
    { id: 'H', title: 'Mobile emulator (Android UA, zero touch points, emulator GPU)', run: caseH },
    { id: 'I', title: 'Cloud container (datacenter IP, masked GPU)', run: caseI },
    { id: 'J', title: 'Clean human (Windows Chrome, residential IP)', run: caseJ },
    { id: 'K', title: 'Header / body contradiction (envelope Windows, header Linux)', run: caseK },
    { id: 'F', title: 'Tampered payload (body hardwareId altered after signing)', run: caseF },
    { id: 'G', title: 'Replay (identical signed request sent twice)', run: caseG },
  ];

  for (const { id: caseId, title, run } of cases) {
    const entry = caseStatus.get(caseId);
    console.log(`\n--- ${caseId}: ${entry?.title ?? title} ---`);
    try {
      await run();
    } catch (error) {
      const entry = caseStatus.get(caseId);
      if (entry) entry.ok = false;
      failures.push({
        caseId,
        label: 'case threw an exception',
        expected: 'no exception',
        actual: error?.message || String(error),
        excerpt: caseStatus.get(caseId)?.excerpt,
      });
      console.log(`FAIL  [${caseId}] case threw: ${error?.message || error}`);
    }
  }

  if (VERBOSE) {
    console.log('\nVerdict excerpts:');
    for (const [caseId, entry] of caseStatus) {
      console.log(`\n[${caseId}] ${entry.title}`);
      console.log(JSON.stringify(entry.excerpt, null, 2));
    }
  }

  process.exit(printSummary(startedAtMs));
}

main().catch((error) => {
  console.error('Harness crashed:', error);
  process.exit(1);
});

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import puppeteer from 'puppeteer-core';

/**
 * Browser-level identity verification (plan scenarios T-01 and T-05).
 *
 * Loads the real dashboard in Chromium, captures the identify request the
 * collector actually sends, and asserts the signal payload the way the server
 * and the plan expect it:
 *
 *   - canvas geometry/text are deterministic 32-character hex digests, never
 *     "unstable", and identical across page loads;
 *   - the font, WebGL, audio and math probes all produce entropy;
 *   - os/os_version are not swapped and browser_major_version is never empty;
 *   - a plain desktop browser is not labelled bot.
 *
 * Usage:
 *   INTEL_BASE_URL=http://127.0.0.1:4611 node scripts/test-identity-browser.mjs
 */

const BASE_URL = (process.env.INTEL_BASE_URL || 'http://127.0.0.1:4622').replace(/\/+$/, '');
const HEX32 = /^[0-9a-f]{32}$/i;
const RUNS = Number(process.env.INTEL_RUNS || 2);

function chromiumPath() {
  const candidates = [
    process.env.CHROMIUM_PATH,
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
  ].filter(Boolean);
  return candidates.find((candidate) => existsSync(candidate)) || null;
}

let passed = 0;
const failures = [];

function check(name, condition, detail = '') {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}${detail ? ` (${detail})` : ''}`);
    return;
  }
  failures.push(name);
  console.log(`  FAIL  ${name}${detail ? ` (${detail})` : ''}`);
}

const executablePath = chromiumPath();
assert.ok(executablePath, 'A system Chromium binary is required (CHROMIUM_PATH)');

const browser = await puppeteer.launch({
  executablePath,
  headless: true,
  // A real person's browser does not expose the WebDriver handshake. The flag
  // clears navigator.webdriver so the probe sees a normal desktop session.
  args: [
    '--no-sandbox',
    '--disable-gpu',
    '--enable-unsafe-swiftshader',
    '--disable-dev-shm-usage',
    '--disable-blink-features=AutomationControlled',
  ],
});

/** Loads the dashboard once and returns the identify request/response pair. */
async function capture() {
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 1000 });
  await page.setUserAgent(
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36',
  );

  let captured = null;
  page.on('response', async (response) => {
    if (response.url().includes('/api/visitor/identify') && !captured) {
      try {
        const body = response.request().postData();
        captured = {
          payload: body ? JSON.parse(body) : {},
          response: await response.json(),
        };
      } catch {
        /* ignore non-JSON responses */
      }
    }
  });

  await page.goto(BASE_URL, { waitUntil: 'networkidle2', timeout: 60_000 });
  for (let i = 0; i < 40 && !captured; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  await page.close();
  assert.ok(captured, 'The dashboard never posted an identify request');
  return captured;
}

try {
  const runs = [];
  for (let i = 0; i < Math.max(1, RUNS); i += 1) runs.push(await capture());

  const first = runs[0];
  const payload = first.payload || {};
  const event = first.response || {};
  if (process.env.INTEL_DUMP) {
    console.log('PAYLOAD KEYS:', Object.keys(payload).join(', '));
    console.log(JSON.stringify(payload.identityProfile, null, 1).slice(0, 5000));
  }

  /* The collector sends the tri-layer profile under `identityProfile`; the
   * server echoes a flattened copy as rawDeviceAttributes. */
  const raw =
    payload.identityProfile ||
    payload.rawDeviceAttributes ||
    payload.deviceAttributes ||
    payload.signals?.rawDeviceAttributes ||
    payload.raw ||
    {};

  console.log(`\n=== T-01 deterministic client signals (${BASE_URL}) ===`);

  const canvas = raw.canvas || {};
  const geometry = String(canvas.geometry ?? canvas.geometry_hash ?? '');
  const text = String(canvas.text ?? canvas.text_hash ?? '');
  check('canvas geometry is a 32-character hex digest', HEX32.test(geometry), geometry || 'missing');
  check('canvas text is a 32-character hex digest', HEX32.test(text), text || 'missing');
  check('canvas is never reported unstable', canvas.unstable !== true && !/unstable/i.test(geometry + text));

  const fonts = raw.fonts || raw.font_list || {};
  const fontList = Array.isArray(fonts) ? fonts : fonts.list || [];
  check('the font probe returns installed fonts', fontList.length > 0, `${fontList.length} fonts`);

  const webgl = raw.webgl || raw.webgl_extensions || raw.webglExtensions || {};
  check(
    'webgl extension, parameter and precision hashes are present',
    Boolean(webgl.extensionsHash && webgl.paramsHash && webgl.shaderPrecisionHash),
  );

  const audio = raw.audio;
  const audioSum = typeof audio === 'number' ? audio : audio?.sum;
  check('audio renders a non-zero sum', typeof audioSum === 'number' && audioSum > 0, String(audioSum));

  const misc = raw.misc || {};
  check('math and error-stack entropy are present', Boolean(misc.mathHash && misc.errorStackHash));
  check(
    'the hardware and browser fingerprints are 32-character hex digests',
    HEX32.test(String(raw.hardwareFingerprint || raw.hardware_fingerprint || '')) &&
      HEX32.test(String(raw.browserFingerprint || raw.browser_fingerprint || '')),
    String(raw.hardwareFingerprint || raw.hardware_fingerprint),
  );

  if (runs.length > 1) {
    console.log(`\n=== T-01b canvas determinism across ${runs.length} loads ===`);
    for (const run of runs.slice(1)) {
      const other = (run.payload?.identityProfile || {}).canvas || {};
      check(
        'canvas geometry is stable between page loads',
        String(other.geometry ?? '') === geometry,
        `${String(other.geometry ?? '').slice(0, 12)} vs ${geometry.slice(0, 12)}`,
      );
      check(
        'canvas text is stable between page loads',
        String(other.text ?? '') === text,
        `${String(other.text ?? '').slice(0, 12)} vs ${text.slice(0, 12)}`,
      );
    }
  }

  console.log('\n=== T-05 normalized identity ===');
  const browserDetails = event.browserDevice || event.browser_details || {};
  const os = String(browserDetails.os ?? raw.os?.family ?? '');
  const osVersion = String(browserDetails.os_version ?? raw.os?.version ?? '');
  const browserMajor = String(raw.browser?.major ?? browserDetails.browser_major_version ?? '');
  check('os carries no version digits', os.length > 0 && !/\d/.test(os), os || 'missing');
  check('os_version is not a copy of os', osVersion !== os, `${os} / ${osVersion}`);
  check('browser major version is populated', /^\d+$/.test(browserMajor), browserMajor || 'missing');

  console.log('\n=== Verdict for a plain desktop browser ===');
  check('bot verdict is not bad', event.bot !== 'bad', String(event.bot));
  check(
    'consistency does not claim automation',
    !event.consistency || event.consistency.agent_verdict === 'human',
    String(event.consistency?.agent_verdict),
  );
  check(
    'identification confidence is present',
    typeof event.identification?.confidence?.score === 'number',
    String(event.identification?.confidence?.score),
  );
} finally {
  await browser.close();
}

console.log(`\nRESULT: ${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log(`FAILED: ${failures.join(' | ')}`);
  process.exit(1);
}

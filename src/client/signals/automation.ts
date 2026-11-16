/**
 * Automation / agent-shape probe set (2026 CDP + headless + product agents).
 *
 * Reason ID families:
 *   C*        Chrome DevTools Protocol usage (Runtime.enable / console /
 *             Network.enable orderings)
 *   V*        launch-environment evidence (WEAK alone)
 *   F*        on-device AI API surface evidence
 *   UA/H/S    headless & stealth traces
 *   behavior. kinematic input evidence (pointer/pressure/visibility)
 *
 * Product shapes (muse, grok-bot, codex-browser, instinct, chatgpt/claude
 * badges) are composed from multi-signal conjunctions; `agentName` carries
 * the primary product shape while `shapes` carries every match.
 *
 * Every detector is defensive: failures are inconclusive, never fatal.
 */

import { getWebglBasics } from './webgl';
import { errorMessage } from './hash';
import type {
  AutomationCollectArgs,
  AutomationSignals,
  KinematicsTracker,
} from './types';

// Reason IDs (exact strings, part of the contract with the scoring layer).
export const REASONS = {
  cdpRuntimeEnable: 'cdp.runtime.enable',
  cdpConsoleDebug: 'cdp.console.debug',
  cdpNetworkOrder: 'cdp.network.order',
  launchNoSpeechVoices: 'launch.no-speech-voices',
  launchNoLanguageDetector: 'launch.no-languagedetector',
  uaBrandsMismatch: 'ua.brands-vs-ua-mismatch',
  headlessAnyPointerNone: 'headless.any-pointer-none',
  headlessSwiftshaderCaveat: 'headless.swiftshader.caveat',
  headlessNoIntlyenKey: 'headless.no-intlyen-key',
  headlessChromeExtensionPort: 'headless.chrome-extension-port',
  headlessHeap3digitRounding: 'headless.heap-3digit-rounding',
  headlessFontExactIntegers: 'headless.font-exact-integers',
  headlessSecchMismatch: 'headless.secch-headless-mismatch',
  behaviorPointerStale: 'behavior.pointer-stale',
  behaviorZeroPressure: 'behavior.zero-pressure',
  behaviorHiddenInput: 'behavior.hidden-input',
} as const;

// Product shape IDs.
export const SHAPES = {
  muse: 'muse',
  grokBot: 'grok-bot',
  codexBrowser: 'codex-browser',
  instinct: 'instinct',
  chatgptBadge: 'chatgpt.badge.active',
  claudeMarker: 'claude.marker.active',
} as const;

const SWIFTSHADER_PATTERN = /swiftshader|llvmpipe|software\s*renderer|software\s*rasterizer|basic\s*render/i;
const MOBILE_UA_PATTERN = /Mobi|Android|iPhone|iPad|iPod/i;

interface UABrand {
  brand: string;
  version?: string;
}

interface UADataLike {
  brands?: UABrand[];
  platform?: string;
  mobile?: boolean;
}

interface NavigatorWithExtras {
  userAgentData?: UADataLike;
  keyboard?: {
    getLayoutMap?: () => Promise<Map<string, string>>;
  };
}

interface WindowWithLegacy {
  LanguageDetector?: {
    availability?: () => Promise<string> | string;
  };
}

interface HeapMemoryInfo {
  jsHeapSizeLimit?: number;
}

function getNavigatorExtras(): NavigatorWithExtras {
  return navigator as NavigatorWithExtras;
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values));
}

function parseChromeMajor(ua: string): number | null {
  const match = ua.match(/Chrom(?:e|ium)\/(\d+)/);
  return match ? Number.parseInt(match[1], 10) : null;
}

function speechVoiceCount(): number {
  try {
    if (!window.speechSynthesis || typeof window.speechSynthesis.getVoices !== 'function') return 0;
    return window.speechSynthesis.getVoices().length;
  } catch {
    return 0;
  }
}

function readRendererUnmasked(fallback: string | null | undefined): string {
  if (typeof fallback === 'string' && fallback.length > 0) return fallback;
  try {
    const basics = getWebglBasics();
    return basics.rendererUnmasked ?? basics.renderer ?? '';
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------
// C1 — cdp.runtime.enable
// ---------------------------------------------------------------------------

/**
 * Injects `eval('__cdp_probe__')` on a zero timer with a temporary
 * `window.onerror`. The uncaught ReferenceError reports the script URL of
 * the evaluation context; with CDP `Runtime.enable` active the error source
 * is empty (the exception is attributed to the CDP evaluation realm), while
 * a plain page reports the page URL. Restores the previous handler and
 * passes through unrelated errors untouched.
 */
async function detectCdpRuntimeEnable(): Promise<boolean | null> {
  return new Promise<boolean | null>((resolve) => {
    let finished = false;
    const previousHandler = window.onerror;

    const finish = (value: boolean | null): void => {
      if (finished) return;
      finished = true;
      clearTimeout(safetyTimer);
      if (window.onerror === probeHandler) window.onerror = previousHandler;
      resolve(value);
    };

    const probeHandler: OnErrorEventHandler = (message, source, lineno, colno, error) => {
      if (typeof message === 'string' && message.includes('__cdp_probe__')) {
        const flagged = !source; // empty script URL => Runtime.enable active
        finish(flagged);
        return true; // suppress our own probe's console noise
      }
      if (typeof previousHandler === 'function') {
        return previousHandler(message, source, lineno, colno, error);
      }
      return undefined;
    };

    const safetyTimer = setTimeout(() => finish(false), 250);
    window.onerror = probeHandler;
    setTimeout(() => {
      try {
        eval('__cdp_probe__');
      } catch {
        // Deliberate: the ReferenceError must surface through window.onerror.
      }
    }, 0);
  });
}

// ---------------------------------------------------------------------------
// C2 — cdp.console.debug
// ---------------------------------------------------------------------------

/**
 * With a CDP console consumer attached, `console.debug(error)` serializes
 * the argument eagerly, which forces V8 to format the lazy `.stack` and
 * invoke `Error.prepareStackTrace`. Without an attached consumer the error
 * object is passed through untouched and the hook never fires. We install a
 * marker `prepareStackTrace`, call `console.debug(new Error())`, restore,
 * and check again after a tick for asynchronous serialization pipelines.
 */
async function detectCdpConsoleDebug(): Promise<boolean | null> {
  try {
    const errorCtor = Error as unknown as {
      prepareStackTrace?: (error: Error, frames: unknown) => string;
    };
    const previous = errorCtor.prepareStackTrace;
    let invoked = false;
    errorCtor.prepareStackTrace = () => {
      invoked = true;
      return '';
    };
    try {
      console.debug(new Error('intel-cdp-console-probe'));
    } catch {
      /* console itself may be restricted */
    }
    errorCtor.prepareStackTrace = previous;
    const immediate = invoked;
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    return immediate || invoked;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// C3 — cdp.network.order
// ---------------------------------------------------------------------------

/**
 * Same-origin (about:blank) iframe probe: the parent registers a `message`
 * listener and a `load` listener BEFORE appending the frame, then
 * immediately writes an inline script that posts a message to the parent.
 * Blueprint heuristic: when CDP `Network.enable` is active the frame commit
 * is delayed by instrumentation, so the inline message lands BEFORE the
 * frame's `load` event; an uninstrumented commit completes first and the
 * message arrives after. Only the message-before-load ordering is flagged
 * (conservative direction per blueprint — calibrate against reference
 * browsers in production before treating it as high confidence).
 */
async function detectCdpNetworkOrder(): Promise<boolean | null> {
  try {
    const parent = document.body ?? document.documentElement;
    if (!parent || !document.createElement) return null;

    let messageSeen = false;
    let loadSeen = false;
    let messageBeforeLoad = false;

    const iframe = document.createElement('iframe');
    iframe.style.cssText =
      'position:absolute;left:-9999px;top:0;width:10px;height:10px;border:0;opacity:0;';
    iframe.setAttribute('aria-hidden', 'true');

    const onMessage = (event: MessageEvent): void => {
      try {
        if (event.source && event.source === iframe.contentWindow) {
          messageSeen = true;
          if (!loadSeen) messageBeforeLoad = true;
        }
      } catch {
        /* ignore */
      }
    };

    const onLoad = (): void => {
      loadSeen = true;
    };

    window.addEventListener('message', onMessage, true);
    iframe.addEventListener('load', onLoad);

    let wroteScript = false;
    try {
      parent.appendChild(iframe);
      const doc = iframe.contentDocument;
      if (doc) {
        doc.open();
        doc.write('<scr' + 'ipt>parent.postMessage("intel-cdp-order-probe","*")</scr' + 'ipt>');
        doc.close();
        wroteScript = true;
      }
    } catch {
      wroteScript = false; // CSP / inaccessible document — inconclusive
    }

    try {
      await new Promise<void>((resolve) => setTimeout(resolve, 300));
    } finally {
      window.removeEventListener('message', onMessage, true);
      try {
        iframe.remove();
      } catch {
        /* ignore */
      }
    }

    if (!wroteScript || !messageSeen) return null;
    return messageBeforeLoad;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// V1 / F3 / F4 / H2 / H3 / H4 / S1 / S4 / S7
// ---------------------------------------------------------------------------

/** WEAK signal: no 'Google '-prefixed speech voices (a normal desktop Chrome
 * install ships several). Zero voices also happens legitimately (first call
 * before voiceschanged, locked-down environments) — hence weak. */
function detectNoSpeechVoices(): boolean {
  try {
    const voices = window.speechSynthesis?.getVoices?.() ?? [];
    return !voices.some((voice) => voice.name.startsWith('Google '));
  } catch {
    return false;
  }
}

/**
 * F3: the on-device LanguageDetector API surface exists but reports its
 * model as unavailable — observed on agent builds that ship the API surface
 * without the model bundle.
 */
async function detectLanguageDetectorUnavailable(): Promise<boolean | null> {
  try {
    const detector = (window as unknown as WindowWithLegacy).LanguageDetector;
    if (!detector || typeof detector.availability !== 'function') return null;
    const availability = await detector.availability();
    return availability === 'unavailable';
  } catch {
    return null;
  }
}

/** F4: navigator.userAgentData brands contradict the UA string family. */
function detectBrandsUaMismatch(): boolean | null {
  try {
    const ua = navigator.userAgent;
    const brands = getNavigatorExtras().userAgentData?.brands ?? [];
    if (brands.length === 0) return null; // UA-CH absent (Firefox/Safari): no evidence

    const brandNames = brands.map((brand) => String(brand.brand ?? ''));
    const uaIsChromium = /Chrom(?:e|ium)\//.test(ua);
    const uaIsFirefox = /Firefox\//.test(ua) || /FxiOS\//.test(ua);
    const uaIsSafariOnly = /AppleWebKit\//.test(ua) && !uaIsChromium;
    if (uaIsFirefox || uaIsSafariOnly) return true; // brands only exist on Chromium

    const edgeInUA = /Edg(?:e|A|iOS)?\//.test(ua);
    const edgeInBrands = brandNames.some((name) => /Microsoft Edge/i.test(name));
    if (edgeInUA !== edgeInBrands && (edgeInUA || edgeInBrands)) return true;

    const operaInUA = /OPR\//.test(ua);
    const operaInBrands = brandNames.some((name) => /Opera|OPR/i.test(name));
    if (operaInUA !== operaInBrands && (operaInUA || operaInBrands)) return true;

    return false;
  } catch {
    return null;
  }
}

/** H2: desktop UA but no pointer of any kind is available. */
function detectAnyPointerNone(): boolean | null {
  try {
    if (MOBILE_UA_PATTERN.test(navigator.userAgent)) return null;
    return window.matchMedia('(any-pointer: none)').matches === true;
  } catch {
    return null;
  }
}

/**
 * H3: with `failIfMajorPerformanceCaveat: true` Chrome refuses a context on
 * a software renderer. If a context IS returned and reports a
 * SwiftShader/llvmpipe renderer, the launch is forcing software WebGL —
 * a headless/automation signature.
 */
function detectSwiftShaderCaveat(): boolean | null {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl', { failIfMajorPerformanceCaveat: true }) as WebGLRenderingContext | null;
    try {
      if (!gl) return false; // caveat honored: not forced software rendering
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info') as
        | { UNMASKED_RENDERER_WEBGL?: number }
        | null;
      const key = debugInfo?.UNMASKED_RENDERER_WEBGL ?? 0x9246;
      const value = (() => {
        try {
          return gl.getParameter(key);
        } catch {
          return null;
        }
      })();
      const renderer = typeof value === 'string' ? value : '';
      if (SWIFTSHADER_PATTERN.test(renderer)) return true;
      const masked = (() => {
        try {
          return gl.getParameter(gl.RENDERER);
        } catch {
          return '';
        }
      })();
      return SWIFTSHADER_PATTERN.test(typeof masked === 'string' ? masked : '');
    } finally {
      try {
        canvas.remove();
      } catch {
        /* ignore */
      }
    }
  } catch {
    return null;
  }
}

interface KeyboardProbe {
  flagged: boolean | null;
  mapEmpty: boolean;
}

/**
 * H4: navigator.keyboard.getLayoutMap() returns an empty/missing KeyQ entry
 * on headless builds. Conservative: an absent API (Firefox/Safari) is NOT
 * evidence, and a non-'q' KeyQ value is NOT flagged either (real AZERTY &
 * friends) — only a missing entry or an empty map flags.
 */
async function probeKeyboardLayout(): Promise<KeyboardProbe> {
  try {
    const keyboard = getNavigatorExtras().keyboard;
    if (!keyboard || typeof keyboard.getLayoutMap !== 'function') {
      return { flagged: null, mapEmpty: false };
    }
    const map = await keyboard.getLayoutMap();
    const empty = map.size === 0;
    const missingKeyQ = !map.has('KeyQ');
    return { flagged: empty || missingKeyQ, mapEmpty: empty };
  } catch {
    return { flagged: null, mapEmpty: false };
  }
}

/**
 * S1: `new URL('chrome-extension://x:0')`. Observed behavior in plain
 * Chrome: the :0 port is RETAINED — href === 'chrome-extension://x:0/'.
 * Automated builds with patched URL parsing strip the non-special port and
 * produce 'chrome-extension://x/'. Conservative per blueprint: flag ONLY the
 * stripped form ('://x/' present without '://x:0'); parse failures are
 * inconclusive.
 */
function detectChromeExtensionPort(): boolean | null {
  try {
    const href = new URL('chrome-extension://x:0').href;
    if (!href) return null;
    const stripped = href.includes('://x/') && !href.includes('://x:0');
    return stripped;
  } catch {
    return null;
  }
}

/**
 * S4: headless variants round jsHeapSizeLimit to 3 significant digits
 * (exact multiples of 1,000,000). Plain Chrome reports values like
 * 4294701760 which never pass this test.
 */
function detectHeap3digitRounding(): boolean | null {
  try {
    const memory = (performance as unknown as { memory?: HeapMemoryInfo }).memory;
    const limit = memory?.jsHeapSizeLimit;
    if (typeof limit !== 'number' || limit <= 0) return null;
    return limit % 1_000_000 === 0;
  } catch {
    return null;
  }
}

/**
 * S7: Sec-CH-UA brands (server-provided) disagree with the UA string about
 * HeadlessChrome. Only evaluated when the brand list was supplied.
 */
function detectSecChHeadlessMismatch(secChBrands?: string[]): boolean | null {
  try {
    if (!secChBrands || secChBrands.length === 0) return null;
    const uaHeadless = /HeadlessChrome/i.test(navigator.userAgent);
    const brandHeadless = secChBrands.some((brand) => /HeadlessChrome/i.test(String(brand)));
    return uaHeadless !== brandHeadless;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Product shapes
// ---------------------------------------------------------------------------

function isScreen1280x800(): boolean {
  try {
    return screen.width === 1280 && screen.height === 800;
  } catch {
    return false;
  }
}

function detectMuseShape(args: AutomationCollectArgs, renderer: string): boolean {
  const fonts = args.fontsInstalled ?? [];
  const chromeMajor = parseChromeMajor(navigator.userAgent);
  return (
    isScreen1280x800() &&
    fonts.includes('Ubuntu') &&
    fonts.includes('Droid Sans') &&
    !fonts.includes('Cambria') &&
    SWIFTSHADER_PATTERN.test(renderer) &&
    chromeMajor !== null &&
    chromeMajor >= 139
  );
}

function detectGrokBotShape(
  renderer: string,
  caveat: boolean | null,
  chromeExtensionReferrer: boolean
): boolean {
  const ua = navigator.userAgent;
  const signs = [
    /Linux x86_64/.test(ua) && !/Android/i.test(ua),
    SWIFTSHADER_PATTERN.test(renderer),
    /Grok/i.test(ua) || chromeExtensionReferrer,
    isScreen1280x800(),
    speechVoiceCount() === 0,
    caveat === true,
  ];
  return signs.filter(Boolean).length >= 5;
}

function detectCodexShape(promptMentionsCodex: boolean, keyboardMapEmpty: boolean): boolean {
  let htmlChildShadowRoot = false;
  try {
    const root = document.documentElement;
    htmlChildShadowRoot =
      !!root &&
      (root.shadowRoot !== null ||
        Array.from(root.children ?? []).some((child) => (child as Element).shadowRoot !== null));
  } catch {
    htmlChildShadowRoot = false;
  }
  const signs = [promptMentionsCodex, keyboardMapEmpty, htmlChildShadowRoot];
  return signs.filter(Boolean).length >= 2;
}

function detectInstinctShape(): boolean {
  for (const name of ['initGeetest', 'initGeetest4']) {
    try {
      const descriptor = Object.getOwnPropertyDescriptor(window, name);
      if (descriptor && typeof descriptor.get === 'function' && typeof descriptor.set === 'function') {
        return true;
      }
    } catch {
      /* ignore */
    }
  }
  return false;
}

/**
 * chatgpt.badge.active / claude.marker.active — fixed-position overlays or
 * open-shadow-root hosts whose attributes carry the product name. Note for
 * self-hosting: the scan reads live element attributes, so unrelated page
 * attributes containing these tokens can in theory co-fire; the fixed/
 * shadow-host requirement keeps that risk low.
 */
function detectOverlayMarker(token: RegExp): boolean {
  try {
    const elements = document.querySelectorAll('*');
    const limit = Math.min(elements.length, 4000);
    for (let i = 0; i < limit; i++) {
      const element = elements[i];
      let hasToken = false;
      try {
        for (const attribute of Array.from(element.attributes)) {
          if (token.test(attribute.name) || token.test(attribute.value)) {
            hasToken = true;
            break;
          }
        }
      } catch {
        /* ignore */
      }
      if (!hasToken) continue;
      const shadowHost = (element as Element).shadowRoot !== null;
      let fixed = false;
      try {
        if (element instanceof HTMLElement) fixed = getComputedStyle(element).position === 'fixed';
      } catch {
        /* ignore */
      }
      if (shadowHost || fixed) return true;
    }
  } catch {
    /* ignore */
  }
  return false;
}

// ---------------------------------------------------------------------------
// Kinematics tracker
// ---------------------------------------------------------------------------

const POINTER_WINDOW_MS = 2000;
const POINTER_STALE_MAX_MOVES = 2;

/**
 * Records kinematic evidence around real input:
 *  - behavior.pointer-stale   — ≤ 2 trusted pointermove events in the 2 s
 *                               window before a pointerdown (teleporting
 *                               cursor).
 *  - behavior.zero-pressure   — trusted pointerdown reports pressure === 0
 *                               (spec default for an active pointer is 0.5;
 *                               synthetic events commonly send 0).
 *  - behavior.hidden-input    — trusted input while document.hidden.
 *
 * `drain()` returns and clears accumulated IDs; the orchestrator merges them
 * into AutomationSignals.reasonIds (deduplicated).
 */
export function startKinematicsTracker(): KinematicsTracker {
  const moveTimes: number[] = [];
  const reasons: string[] = [];
  let stopped = false;

  const prune = (now: number): void => {
    while (moveTimes.length > 0 && now - moveTimes[0] > POINTER_WINDOW_MS) moveTimes.shift();
  };

  const onPointerMove = (event: Event): void => {
    try {
      if (!(event as PointerEvent).isTrusted) return;
      const now = performance.now();
      prune(now);
      moveTimes.push(now);
    } catch {
      /* ignore */
    }
  };

  const onPointerDown = (event: Event): void => {
    try {
      const pointerEvent = event as PointerEvent;
      if (!pointerEvent.isTrusted) return;
      const now = performance.now();
      prune(now);
      if (moveTimes.length <= POINTER_STALE_MAX_MOVES) reasons.push(REASONS.behaviorPointerStale);
      if (pointerEvent.pressure === 0) reasons.push(REASONS.behaviorZeroPressure);
      if (document.hidden) reasons.push(REASONS.behaviorHiddenInput);
    } catch {
      /* ignore */
    }
  };

  const onClick = (event: Event): void => {
    try {
      if (!(event as PointerEvent).isTrusted) return;
      if (document.hidden) reasons.push(REASONS.behaviorHiddenInput);
    } catch {
      /* ignore */
    }
  };

  const listenerOptions: AddEventListenerOptions = { capture: true, passive: true };
  try {
    document.addEventListener('pointermove', onPointerMove, listenerOptions);
  } catch {
    /* ignore */
  }
  try {
    document.addEventListener('pointerdown', onPointerDown, listenerOptions);
  } catch {
    /* ignore */
  }
  try {
    document.addEventListener('click', onClick, listenerOptions);
  } catch {
    /* ignore */
  }

  return {
    stop(): void {
      if (stopped) return;
      stopped = true;
      try {
        document.removeEventListener('pointermove', onPointerMove, listenerOptions);
      } catch {
        /* ignore */
      }
      try {
        document.removeEventListener('pointerdown', onPointerDown, listenerOptions);
      } catch {
        /* ignore */
      }
      try {
        document.removeEventListener('click', onClick, listenerOptions);
      } catch {
        /* ignore */
      }
    },
    drain(): string[] {
      const drained = [...reasons];
      reasons.length = 0;
      return drained;
    },
  };
}

// ---------------------------------------------------------------------------
// Main collector
// ---------------------------------------------------------------------------

/** Agent-name priority across product shapes (first match wins). */
const AGENT_NAME_PRIORITY: readonly string[] = [
  SHAPES.muse,
  SHAPES.grokBot,
  SHAPES.codexBrowser,
  SHAPES.instinct,
];

/**
 * Total (async): always returns an AutomationSignals payload. Runtime is
 * bounded (~C1 50ms + C3 300ms + layout/LD probes), so the orchestrator's
 * 1500ms timeout comfortably covers it.
 */
export async function collectAutomationSignals(
  args: AutomationCollectArgs = {}
): Promise<AutomationSignals> {
  const reasons: string[] = [];
  const weak: string[] = [];
  const shapes: string[] = [];

  try {
    const ua = navigator.userAgent;

    // --- cheap passive checks -------------------------------------------
    if (detectNoSpeechVoices()) {
      weak.push(REASONS.launchNoSpeechVoices);
      reasons.push(REASONS.launchNoSpeechVoices);
    }

    if (detectBrandsUaMismatch() === true) reasons.push(REASONS.uaBrandsMismatch);

    if (detectAnyPointerNone() === true) reasons.push(REASONS.headlessAnyPointerNone);

    if (detectHeap3digitRounding() === true) reasons.push(REASONS.headlessHeap3digitRounding);

    if (args.fontWidthsExact === true) reasons.push(REASONS.headlessFontExactIntegers);

    if (detectSecChHeadlessMismatch(args.secChBrands) === true) {
      reasons.push(REASONS.headlessSecchMismatch);
    }

    if (detectChromeExtensionPort() === true) reasons.push(REASONS.headlessChromeExtensionPort);

    const renderer = readRendererUnmasked(args.rendererUnmasked);
    const caveat = detectSwiftShaderCaveat();
    if (caveat === true) reasons.push(REASONS.headlessSwiftshaderCaveat);

    // --- shapes that only need sync inputs -------------------------------
    const referrer = (() => {
      try {
        return document.referrer ?? '';
      } catch {
        return '';
      }
    })();
    if (detectMuseShape(args, renderer)) shapes.push(SHAPES.muse);
    if (detectGrokBotShape(renderer, caveat, /cursorusercontent\.com/.test(referrer))) {
      shapes.push(SHAPES.grokBot);
    }
    if (detectInstinctShape()) shapes.push(SHAPES.instinct);
    if (detectOverlayMarker(/chatgpt/i)) shapes.push(SHAPES.chatgptBadge);
    if (detectOverlayMarker(/claude/i)) shapes.push(SHAPES.claudeMarker);

    // --- async probes -----------------------------------------------------
    const [runtimeEnable, consoleDebug, networkOrder, languageDetector, keyboard] = await Promise.all([
      detectCdpRuntimeEnable(),
      detectCdpConsoleDebug(),
      detectCdpNetworkOrder(),
      detectLanguageDetectorUnavailable(),
      probeKeyboardLayout(),
    ]);

    if (runtimeEnable === true) reasons.push(REASONS.cdpRuntimeEnable);
    if (consoleDebug === true) reasons.push(REASONS.cdpConsoleDebug);
    if (networkOrder === true) reasons.push(REASONS.cdpNetworkOrder);
    if (languageDetector === true) reasons.push(REASONS.launchNoLanguageDetector);
    if (keyboard.flagged === true) reasons.push(REASONS.headlessNoIntlyenKey);

    let promptMentionsCodex = false;
    try {
      promptMentionsCodex = /codex/i.test(String(window.prompt));
    } catch {
      promptMentionsCodex = false;
    }
    if (detectCodexShape(promptMentionsCodex, keyboard.mapEmpty)) shapes.push(SHAPES.codexBrowser);
  } catch (err) {
    return {
      reasonIds: unique(reasons),
      weakReasonIds: unique(weak),
      agentName: null,
      shapes: unique(shapes),
      error: errorMessage(err),
    };
  }

  const shapesFinal = unique(shapes);
  const agentName = AGENT_NAME_PRIORITY.find((name) => shapesFinal.includes(name)) ?? null;

  return {
    reasonIds: unique(reasons),
    weakReasonIds: unique(weak),
    agentName,
    shapes: shapesFinal,
  };
}

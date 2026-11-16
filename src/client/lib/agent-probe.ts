/**
 * AI Browser Agent / Bot Detection — CLIENT PROBE (passive).
 *
 * Runs entirely in the browser and produces a low-cardinality verdict made ONLY of
 * boolean reason IDs plus an optional agent name. No raw fingerprint values
 * (user-agent strings, WebGL renderer strings, screen dimensions, timing numbers,
 * DOM attribute values, font measurements, etc.) are ever stored or transmitted.
 *
 * The single optional telemetry beacon posts:
 *   { agent_name: string | null, reasons: string[], path: string }
 */

import { gateAutomationEvidence } from '../../lib/verdict';

export interface AgentVerdict {
  type: 'agent' | 'human';
  agent_name?: string;
  reasons: string[];
}

interface ServerTimingLike {
  name: string;
  description?: string;
  duration?: number;
}

interface UADataBrand {
  brand: string;
  version?: string;
}

interface UADataLike {
  brands?: UADataBrand[];
  platform?: string;
  mobile?: boolean;
}

interface KeyboardLike {
  getLayoutMap?: () => Promise<Map<string, string>>;
}

interface PublicKeyCredentialLike {
  get?: unknown;
  create?: unknown;
  isUserVerifyingPlatformAuthenticatorAvailable?: unknown;
  isConditionalMediationAvailable?: unknown;
}

const DEFAULT_TELEMETRY_ENDPOINT = '/api/intel/ai-crawl-control/agent-telemetry';

const CLAUDE_SELECTORS =
  '[id*="claude-extension"], [data-claude-marker], link[rel*="icon"][data-claude]';
const CHATGPT_SELECTORS =
  '[id*="chatgpt-badge"], [data-chatgpt-extension], [class*="chatgpt-overlay"]';

/** Immediately invoke a probe body without ever letting it break the host page. */
function safe(fn: () => void): void {
  try {
    fn();
  } catch {
    /* intentional swallow: detection must be invisible and non-disruptive */
  }
}

/** Wrap a callback so errors thrown later (timeouts, observers) are also swallowed. */
function guard<T extends (...args: any[]) => any>(
  fn: T
): (...args: Parameters<T>) => void {
  return function (this: unknown, ...args: any[]): void {
    try {
      fn.apply(this, args);
    } catch {
      /* intentional swallow */
    }
  } as (...args: Parameters<T>) => void;
}

/** Reflective helper for navigator.userAgentData without depending on non-standard DOM types. */
function getUAData(): UADataLike | undefined {
  return (navigator as Navigator & { userAgentData?: UADataLike }).userAgentData;
}

/** True for Linux x86_64 user agents / platforms (cloud-browser fleets). */
function isLinuxX64(): boolean {
  try {
    const ua = navigator.userAgent || '';
    const platform = navigator.platform || '';
    const blob = `${ua} ${platform}`;
    return /linux/i.test(blob) && /x86[_-]?64|amd64|\bx64\b/i.test(blob);
  } catch {
    return false;
  }
}

/** WebGL renderer check — returns a boolean only, never the renderer string. */
function checkSwiftShaderRenderer(): boolean {
  try {
    const canvas = document.createElement('canvas');
    const gl = (canvas.getContext('webgl') ||
      canvas.getContext('experimental-webgl')) as WebGLRenderingContext | null;
    if (!gl) return false;
    const ext = gl.getExtension('WEBGL_debug_renderer_info') as
      | { UNMASKED_RENDERER_WEBGL: number }
      | null;
    if (!ext) return false;
    const renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
    return typeof renderer === 'string' && /swiftshader/i.test(renderer);
  } catch {
    return false;
  }
}

/** Canvas font-availability check — returns a boolean only, never measured widths. */
function hasCanvasFont(font: string): boolean {
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (!ctx) return false;
    const bases = ['monospace', 'sans-serif', 'serif'];
    const text = 'mmmmmmmmmmlli';
    const size = '72px';
    const widthOf = (family: string): number => {
      ctx.font = `${size} ${family}`;
      return ctx.measureText(text).width;
    };
    const baseWidths = bases.map(widthOf);
    return bases.some(
      (base, index) => widthOf(`"${font}", ${base}`) !== baseWidths[index]
    );
  } catch {
    return false;
  }
}

/** Native functions stringify with `[native code]`; injected wrappers do not. */
function isNativeFunction(fn: unknown): boolean {
  if (typeof fn !== 'function') return false;
  try {
    return /\[native code\]/.test(Function.prototype.toString.call(fn));
  } catch {
    return false;
  }
}

/** Walk the prototype chain to find the property descriptor for a method. */
function getPropertyDescriptor(obj: object | null, key: string): PropertyDescriptor | undefined {
  let current: object | null = obj;
  while (current) {
    const descriptor = Object.getOwnPropertyDescriptor(current, key);
    if (descriptor) return descriptor;
    current = Object.getPrototypeOf(current) as object | null;
  }
  return undefined;
}

/** True when a method has been replaced by a non-native wrapper (or accessor). */
function isWrappedMethod(obj: object | undefined, key: string): boolean {
  if (!obj) return false;
  const descriptor = getPropertyDescriptor(obj, key);
  if (!descriptor) return false;
  const fn = 'value' in descriptor ? descriptor.value : descriptor.get || descriptor.set;
  return typeof fn === 'function' && !isNativeFunction(fn);
}

/** True when both GeeTest global entry points are exposed as accessor getters. */
function hasGeetestAccessors(): boolean {
  try {
    const w = window as unknown as Record<string, unknown>;
    const d1 = Object.getOwnPropertyDescriptor(w, 'initGeetest');
    const d2 = Object.getOwnPropertyDescriptor(w, 'initGeetest4');
    return Boolean(d1 && d1.get && d2 && d2.get);
  } catch {
    return false;
  }
}

/** True when several 1Password-style accessor properties exist on window. */
function hasOnePasswordAccessors(): boolean {
  try {
    const w = window as unknown as Record<string, unknown>;
    let accessors = 0;
    const consider = (key: string | symbol): void => {
      if (typeof key !== 'string' || !/onepassword|1password/i.test(key)) return;
      const descriptor = Object.getOwnPropertyDescriptor(w, key);
      if (descriptor && (descriptor.get || descriptor.set)) accessors += 1;
    };
    Object.getOwnPropertyNames(w).forEach(consider);
    Object.getOwnPropertySymbols(w).forEach(consider);
    return accessors >= 2;
  } catch {
    return false;
  }
}

/** Anonymous native prompt shape (e.g. function () { [native code] }). */
function hasAnonymousNativePrompt(): boolean {
  try {
    if (typeof window.prompt !== 'function') return false;
    const source = Function.prototype.toString.call(window.prompt);
    return /\[native code\]/.test(source) && /^function\s*\(/.test(source.trim());
  } catch {
    return false;
  }
}

/** Open shadow roots on documentElement or on non-HEAD/BODY direct children. */
function hasOverlayShadowRoot(): boolean {
  try {
    const root = document.documentElement;
    if (!root) return false;
    const carriesVisibleShadow = (host: Element): boolean =>
      Boolean(host.shadowRoot && host.shadowRoot.children.length > 0);
    if (carriesVisibleShadow(root)) return true;
    for (const child of Array.from(root.children)) {
      if (child.tagName === 'HEAD' || child.tagName === 'BODY') continue;
      if (carriesVisibleShadow(child)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

/** One module-level controller prevents duplicate observers/listeners in React StrictMode. */
let singletonController: { getVerdict: () => AgentVerdict } | null = null;

export function startIntelAgentProbe(
  telemetryEndpoint: string = DEFAULT_TELEMETRY_ENDPOINT
): { getVerdict: () => AgentVerdict } {
  if (singletonController) return singletonController;

  if (
    typeof window === 'undefined' ||
    typeof document === 'undefined' ||
    typeof navigator === 'undefined'
  ) {
    return { getVerdict: (): AgentVerdict => ({ type: 'human', reasons: [] }) };
  }

  const reasons: string[] = [];
  const agentScores = new Map<string, number>();
  let beaconScheduled = false;

  function registerAgent(name: string, score = 10): void {
    safe(() => {
      const trimmed = (name || '').trim();
      if (!trimmed) return;
      if (score > (agentScores.get(trimmed) ?? -1)) agentScores.set(trimmed, score);
    });
  }

  function pickAgentName(): string | undefined {
    let best: string | undefined;
    let bestScore = -1;
    agentScores.forEach((score, name) => {
      if (score > bestScore) {
        bestScore = score;
        best = name;
      }
    });
    return best;
  }

  function scheduleBeacon(): void {
    if (beaconScheduled) return;
    beaconScheduled = true;
    setTimeout(
      guard(() => {
        try {
          const payload = {
            agent_name: pickAgentName() ?? null,
            reasons: reasons.slice(),
            path: location.pathname,
          };
          void fetch(telemetryEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            keepalive: true,
          }).catch(() => {});
        } catch {
          /* telemetry is best-effort only */
        }
      }),
      350
    );
  }

  function addReason(reason: string, agent?: string, agentScore?: number): void {
    safe(() => {
      const id = (reason || '').trim();
      if (!id) return;
      if (!reasons.includes(id)) {
        reasons.push(id);
        scheduleBeacon();
      }
      if (agent) registerAgent(agent, agentScore);
    });
  }

  function getVerdict(): AgentVerdict {
    if (reasons.length === 0) return { type: 'human', reasons: [] };
    // Weighted gate: a single weak reason (SwiftShader with hardware acceleration
    // off, extension shadow roots, stale pointer trails) must never brand a real
    // person as an agent. Hard reasons alone, two medium reasons, or one medium
    // plus weak corroboration are required for an agent verdict.
    const gated = gateAutomationEvidence(reasons);
    if (gated.verdict !== 'automated') {
      return { type: 'human', reasons: reasons.slice() };
    }
    const verdict: AgentVerdict = { type: 'agent', reasons: reasons.slice() };
    const name = pickAgentName();
    if (name) verdict.agent_name = name;
    return verdict;
  }

  // ---- Probe 1: Server-Timing `botscent` header ---------------------------------------
  safe(() => {
    const nav = performance.getEntriesByType('navigation')[0] as
      | (PerformanceEntry & { serverTiming?: readonly ServerTimingLike[] })
      | undefined;
    const entries = nav?.serverTiming;
    if (!entries || !Array.isArray(entries)) return;
    for (const entry of entries) {
      if (!entry || entry.name !== 'botscent') continue;
      const parts: string[] = String(entry.description || '').split(';');
      // Expected: 1;<resolvedName>;<durationMs>;<reasons CSV>
      if (parts.length < 4 || parts[0].trim() !== '1') continue;
      const resolvedName = (parts[1] || '').trim();
      const csvReasons = (parts[3] || '')
        .split(',')
        .map((token) => token.trim())
        .filter(Boolean);
      csvReasons.forEach((token) => addReason(token));
      if (resolvedName) registerAgent(resolvedName, 100);
    }
  });

  // ---- Probe 2: navigator.webdriver ----------------------------------------------------
  safe(() => {
    if (navigator.webdriver === true) addReason('navigator.webdriver');
  });

  // ---- Probe 3: Cursor / Cloudflare browser-run user agents -----------------------------
  safe(() => {
    const ua = navigator.userAgent || '';
    if (ua.includes('Cursor/')) addReason('page.ua.cursor', 'cursor-browser');
    if (ua.includes('Kitesurf/') || (navigator.platform || '').includes('Cloudflare Workers')) {
      addReason('page.platform.cloudflare-workers', 'cloudflare-browser-run');
    }
  });

  // ---- Probe 4: Credentials / GeeTest wrappers + 1Password cloud-browser combo ----------
  function runInstitutionalProbe(): void {
    safe(() => {
      const nav = navigator as Navigator & {
        credentials?: { get?: unknown; create?: unknown };
      };
      const credentials = nav.credentials;
      let wrapped = false;
      if (credentials) {
        wrapped =
          isWrappedMethod(credentials as object, 'get') ||
          isWrappedMethod(credentials as object, 'create');
      }
      const pkc = (window as unknown as { PublicKeyCredential?: PublicKeyCredentialLike })
        .PublicKeyCredential;
      if (!wrapped && pkc) {
        for (const method of [
          'get',
          'create',
          'isUserVerifyingPlatformAuthenticatorAvailable',
          'isConditionalMediationAvailable',
        ]) {
          if (isWrappedMethod(pkc as object, method)) {
            wrapped = true;
            break;
          }
        }
      }
      if (wrapped) addReason('instinct.credentials.wrappers', 'instinct');
    });

    safe(() => {
      if (hasGeetestAccessors()) addReason('instinct.geetest.accessor-pair', 'instinct');
    });

    safe(() => {
      if (isLinuxX64() && hasOnePasswordAccessors() && checkSwiftShaderRenderer()) {
        addReason('muse.cloud-browser.password-manager', 'muse');
      }
    });
  }
  runInstitutionalProbe();
  setTimeout(guard(runInstitutionalProbe), 1500);
  setTimeout(guard(runInstitutionalProbe), 5000);

  // ---- Probe 5: Codex joint rule (at least 2 of 3) --------------------------------------
  const codexFlags = { prompt: false, shadow: false, keyboard: false };
  function evaluateCodex(): void {
    safe(() => {
      const count =
        (codexFlags.prompt ? 1 : 0) +
        (codexFlags.shadow ? 1 : 0) +
        (codexFlags.keyboard ? 1 : 0);
      if (count >= 2) registerAgent('codex-browser');
    });
  }
  safe(() => {
    if (hasAnonymousNativePrompt()) {
      codexFlags.prompt = true;
      addReason('codex.prompt.anonymous-native');
      evaluateCodex();
    }
  });
  safe(() => {
    if (hasOverlayShadowRoot()) {
      codexFlags.shadow = true;
      addReason('codex.overlay.shadow-root');
      evaluateCodex();
    }
  });
  safe(() => {
    const keyboard = (navigator as Navigator & { keyboard?: KeyboardLike }).keyboard;
    if (keyboard && typeof keyboard.getLayoutMap === 'function') {
      void keyboard
        .getLayoutMap()
        .then(
          guard((map: Map<string, string>) => {
            if (map && map.size === 0) {
              codexFlags.keyboard = true;
              addReason('codex.keyboard.empty-layout-map');
              evaluateCodex();
            }
          })
        )
        .catch(() => {});
    }
  });

  // ---- Probe 6: Extension DOM markers + mutation observer -------------------------------
  function runExtensionMarkerProbe(): void {
    safe(() => {
      if (document.querySelector(CLAUDE_SELECTORS)) {
        addReason('claude.marker.active', 'claude-chrome');
      }
    });
    safe(() => {
      if (document.querySelector(CHATGPT_SELECTORS)) {
        addReason('chatgpt.badge.active', 'chatgpt-chrome');
      }
    });
  }
  runExtensionMarkerProbe();
  safe(() => {
    const observer = new MutationObserver(guard(runExtensionMarkerProbe));
    observer.observe(document.documentElement || document, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: [
        'id',
        'class',
        'rel',
        'data-claude',
        'data-claude-marker',
        'data-chatgpt-extension',
      ],
    });
  });

  // ---- Probe 7: Grok cloud computer at first idle ---------------------------------------
  setTimeout(
    guard(() => {
      if (!isLinuxX64()) return;
      let signals = 0;
      safe(() => {
        if (window.screen && window.screen.width === 1280 && window.screen.height === 800) {
          signals += 1;
        }
      });
      safe(() => {
        const brands = getUAData()?.brands ?? [];
        if (brands.some((brand) => /google chrome/i.test(brand.brand || ''))) signals += 1;
      });
      safe(() => {
        if (hasCanvasFont('Ubuntu')) signals += 1;
      });
      safe(() => {
        if (hasCanvasFont('Droid Sans')) signals += 1;
      });
      safe(() => {
        if (hasCanvasFont('Cambria')) signals += 1;
      });
      if (signals >= 4 && checkSwiftShaderRenderer()) {
        addReason('grok.cloud-computer.environment', 'grok-bot');
      }
    }),
    250
  );

  // ---- Probe 8: CDP / headless probes at 400ms ------------------------------------------
  setTimeout(
    guard(() => {
      // S1 — chrome-headless-shell DROPS the explicit `:0` port on the
      // non-special chrome-extension scheme, while regular Chrome retains it.
      // Flag only the drop: the old "port === '0'" check fired for every
      // ordinary Chrome user and was the main "person shown as automated" bug.
      safe(() => {
        if (new URL('chrome-extension://x:0').port === '') {
          addReason('headless.shell.url_scheme_port');
        }
      });

      // H2 — Linux with no fine pointer.
      safe(() => {
        if (isLinuxX64() && window.matchMedia('(any-pointer: none)').matches) {
          addReason('headless.linux.no_pointer');
        }
      });

      // F4 — CDP user-agent override leaves brands empty.
      safe(() => {
        const brands = getUAData()?.brands;
        if (Array.isArray(brands) && brands.length === 0) {
          addReason('cdp.ua_override.empty_brands');
        }
      });

      // C1 — eval ReferenceError reported with an empty source URL while Runtime is enabled.
      safe(() => {
        const previous = window.onerror;
        let captured = false;
        const restore = (): void => {
          safe(() => {
            window.onerror = previous;
          });
        };
        window.onerror = (_message, source) => {
          if (source === '' || source == null) captured = true;
          restore();
          if (captured) addReason('cdp.runtime.enable.empty_source');
          return true;
        };
        // Fresh task: the error must be genuinely uncaught to reach window.onerror.
        setTimeout(
          guard(() => {
            // ReferenceError is intentional; do not wrap the throwing line in try/catch.
            // @ts-expect-error intentionally undefined symbol used only as a probe trigger
            intelCdpProbeMissingSymbol;
          }),
          0
        );
        setTimeout(guard(restore), 500);
      });
    }),
    400
  );

  // ---- Probe 9: C3 — pre-load inline iframe postMessage ---------------------------------
  setTimeout(
    guard(() => {
      const iframe = document.createElement('iframe');
      iframe.style.cssText =
        'position:absolute;left:-9999px;width:0;height:0;border:0;opacity:0;pointer-events:none';
      let order = '';
      let finished = false;

      const cleanup = (): void => {
        safe(() => {
          window.removeEventListener('message', onMessage);
          iframe.removeEventListener('load', onLoad);
          iframe.remove();
        });
      };
      const maybeFinish = (): void => {
        if (finished) return;
        if (!order.includes('m') || !order.includes('l')) return;
        finished = true;
        cleanup();
        if (order.indexOf('m') < order.indexOf('l')) {
          addReason('cdp.network.enable.pre_load_message');
        }
      };
      const onMessage = (event: MessageEvent): void => {
        safe(() => {
          if (event.source !== iframe.contentWindow) return;
          if (event.data !== 'intel-c3-probe') return;
          order += 'm';
          maybeFinish();
        });
      };
      const onLoad = (): void => {
        safe(() => {
          order += 'l';
          maybeFinish();
        });
      };
      window.addEventListener('message', onMessage);
      iframe.addEventListener('load', onLoad);
      iframe.srcdoc = "<script>parent.postMessage('intel-c3-probe','*');</script>";
      (document.body || document.documentElement).appendChild(iframe);
      setTimeout(
        guard(() => {
          if (!order.includes('l')) order += 'l';
          maybeFinish();
          cleanup();
        }),
        800
      );
    }),
    600
  );

  // ---- Probe 9b: Headless UA, H3 SwiftShader caveat and launch switches (F1/V1) ------------
  setTimeout(
    guard(() => {
      if (/HeadlessChrome\//i.test(navigator.userAgent)) addReason('ua.headless-chrome', 'claude-cowork');
      try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl', {
          failIfMajorPerformanceCaveat: true,
        }) as WebGLRenderingContext | null;
        const debug = gl?.getExtension('WEBGL_debug_renderer_info');
        const renderer = debug ? String(gl?.getParameter(debug.UNMASKED_RENDERER_WEBGL) ?? '') : '';
        if (/SwiftShader/i.test(renderer)) addReason('headless.swiftshader.caveat');
      } catch {
        /* WebGL unavailable */
      }

      // F1: Chromium with --disable-ipc-flooding-protection accepts the 201st replaceState.
      let ipcFloodAccepted = false;
      try {
        for (let i = 0; i <= 200; i += 1) history.replaceState(null, '', location.href);
        ipcFloodAccepted = true;
      } catch {
        /* normal Blink blocks the flood */
      }
      if (ipcFloodAccepted) {
        addReason('launch.ipc-flooding-switch');
        safe(() => {
          if (typeof speechSynthesis !== 'undefined' && speechSynthesis.getVoices().length === 0) {
            addReason('launch.no-speech-voices');
          }
        });
      }
    }),
    450
  );

  // ---- Probe 10: Pointer kinematics (passive listeners) ----------------------------------
  safe(() => {
    let movesSinceLastClick = 0;
    let zeroTrailHits = 0;

    function checkHiddenFocus(): void {
      safe(() => {
        if (document.hidden && document.hasFocus()) addReason('input.hidden-document');
      });
    }

    document.addEventListener('pointermove', guard(() => {
      movesSinceLastClick += 1;
    }), { passive: true });

    document.addEventListener(
      'pointerdown',
      guard((event: PointerEvent) => {
        if (!event.isTrusted || event.pointerType !== 'mouse') return;
        // A real mouse reports pressure 0.5 whenever a button is active (Pointer
        // Events spec), so pressure alone proves nothing. It only counts as a
        // Playwright-MCP-style signature when the pointer trail is also stale.
        const staleTrail = movesSinceLastClick <= 1;
        if (event.pressure === 0.5 && staleTrail) {
          addReason('playwright.mcp.pressure');
        }
        if (staleTrail && (event.pressure === 0 || event.pressure === 0.5)) {
          zeroTrailHits += 1;
          if (zeroTrailHits >= 3) addReason('kinematics.zero_pointer_trail');
        }
        movesSinceLastClick = 0;
        checkHiddenFocus();
      }),
      { passive: true }
    );

    document.addEventListener(
      'click',
      guard((event: MouseEvent) => {
        const target = event.target as HTMLElement | null;
        if (!target || typeof target.getBoundingClientRect !== 'function') return;
        const rect = target.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        if (rect.width > 300 && Math.abs(event.clientX - centerX) > 230) {
          addReason('kinematics.screenshot_offset');
        }
        // ChatGPT Work: 319px-wide window and clicks within 1px of the element
        // centre with zero synthetic pressure. The 319px gate is mandatory — a
        // human trackpad tap also lands dead-centre with zero pressure.
        const offset = Math.hypot(event.clientX - centerX, event.clientY - centerY);
        if (window.innerWidth === 319 && offset <= 1 && (event as PointerEvent).pressure === 0) {
          addReason('chatgpt.badge.overlay', 'chatgpt-work');
        }
      }),
      { passive: true }
    );

    document.addEventListener('keydown', guard(checkHiddenFocus), { passive: true });
  });

  singletonController = { getVerdict };
  return singletonController;
}

import { useEffect, useRef, useState } from 'react';
import { PILLS, findAgentByUa, AGENT_REGISTRY } from '../lib/agentRegistry';

/**
 * Cursor attribution overlay.
 *
 * The overlay is rendered for non-human visitors only. A human gets the native cursor and
 * nothing else: no pill, no listeners, no ghost pointer. A remote browser agent that drives a
 * page over CDP gets an attributed cursor pill, either tracking its dispatched pointer moves or
 * parked on the element it clicked / focused when it never moved a real pointer.
 *
 * The identity comes from the first-party server verdict, never from pointer behaviour alone,
 * so a human with an unusual input device can never be labelled as an agent.
 */

export type CursorIdentityKind =
  | 'automated'
  | 'automation'
  | 'cloud'
  | 'firecrawl'
  | 'browseruse'
  | 'skyvern'
  | 'multion'
  | 'hyperbrowser'
  | 'steel'
  | 'airtop'
  | 'notte'
  | 'lightpanda'
  | 'claude'
  | 'gemini'
  | 'grok'
  | 'perplexity'
  | 'muse'
  | 'chatgpt';

export interface CursorIdentity {
  kind: CursorIdentityKind;
  /** Visible pill label, e.g. `Claude-User` or `Firecrawl`. */
  label: string;
}

const PILL_STYLES: Record<CursorIdentityKind, string> = {
  automated: 'bg-[#FCE8E6] border-[#F6AEA9] text-[#A50E0E]',
  automation: 'bg-[#FCE8E6] border-[#F6AEA9] text-[#A50E0E]',
  cloud: 'bg-[#F1F3F4] border-[#DADCE0] text-[#3C4043]',
  firecrawl: 'bg-[#FFF1E5] border-[#FFCC9B] text-[#B33C00]',
  browseruse: 'bg-[#E8F0FE] border-[#D2E3FC] text-[#174EA6]',
  skyvern: 'bg-[#F3E8FD] border-[#D8B4FE] text-[#6B21A8]',
  multion: 'bg-[#E6F4EA] border-[#CEEAD6] text-[#137333]',
  hyperbrowser: 'bg-[#E4F7FB] border-[#CBF0F8] text-[#007B83]',
  steel: 'bg-[#EEF2F7] border-[#CBD5E1] text-[#334155]',
  airtop: 'bg-[#FEF7E0] border-[#FDE293] text-[#8A5A00]',
  notte: 'bg-[#EDE9FE] border-[#C4B5FD] text-[#5B21B6]',
  lightpanda: 'bg-[#F1F5F9] border-[#CBD5E1] text-[#1E293B]',
  claude: 'bg-[#E6F4EA] border-[#CEEAD6] text-[#137333]',
  gemini: 'bg-[#E8F0FE] border-[#D2E3FC] text-[#174EA6]',
  grok: 'bg-[#F1F3F4] border-[#DADCE0] text-[#111111]',
  perplexity: 'bg-[#E4F7FB] border-[#CBF0F8] text-[#007B83]',
  muse: 'bg-[#FCE8E6] border-[#FAD2CF] text-[#3C4043]',
  chatgpt: 'bg-[#E6F4EA] border-[#CEEAD6] text-[#0D652D]',
};

function CursorEmblem({ kind }: { kind: CursorIdentityKind }) {
  if (kind === 'automated' || kind === 'automation' || kind === 'cloud') {
    return (
      <svg viewBox="0 0 16 16" className="w-3 h-3 shrink-0" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
        <circle cx="8" cy="3.5" r="1.8" fill="currentColor" stroke="none" />
        <path d="M8 5.6v4.2M8 9.8l-2.4 3.4M8 9.8l2.4 3.4M8 6.6L4.8 8.4M8 6.6l3.2 1.8" />
      </svg>
    );
  }
  // Agent marks: a four-point sparkle with per-identity rotation/colour inherited from the pill.
  return (
    <svg viewBox="0 0 16 16" className="w-3 h-3 shrink-0" aria-hidden="true">
      <path
        d="M8 1.2 9.5 6.5 14.8 8 9.5 9.5 8 14.8 6.5 9.5 1.2 8 6.5 6.5Z"
        fill="currentColor"
      />
      <circle cx="8" cy="8" r="1.5" fill="#FFFFFF" fillOpacity="0.75" />
    </svg>
  );
}

export function CursorAttributionOverlay({ identity }: { identity: CursorIdentity | null }) {
  const [position, setPosition] = useState<{ x: number; y: number } | null>(null);
  const [visible, setVisible] = useState(false);
  const rafRef = useRef<number | null>(null);
  const pendingRef = useRef<{ x: number; y: number } | null>(null);
  const enabled = identity !== null;

  useEffect(() => {
    // Humans keep their native cursor: no listeners are attached at all.
    if (!enabled || typeof window === 'undefined') return;

    // Coalesce pointer movement into one animation frame.
    const flush = () => {
      rafRef.current = null;
      const next = pendingRef.current;
      if (next) setPosition(next);
    };

    const moveTo = (x: number, y: number) => {
      if (!Number.isFinite(x) || !Number.isFinite(y)) return;
      pendingRef.current = { x, y };
      if (rafRef.current === null) {
        rafRef.current = window.requestAnimationFrame(flush);
      }
      setVisible(true);
    };

    const onPointerMove = (event: PointerEvent | MouseEvent) => {
      if (event.clientX === 0 && event.clientY === 0) return;
      moveTo(event.clientX, event.clientY);
    };

    const centreOf = (target: EventTarget | null): { x: number; y: number } | null => {
      if (!(target instanceof Element)) return null;
      const rect = target.getBoundingClientRect();
      if (rect.width <= 0 && rect.height <= 0) return null;
      return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
    };

    // Synthetic interactions: agents that never move a pointer still get attributed.
    const onSyntheticInteraction = (event: Event) => {
      const point = centreOf(event.target);
      if (point) moveTo(point.x, point.y);
    };

    const onMouseDown = (event: MouseEvent) => {
      if (event.clientX === 0 && event.clientY === 0) {
        onSyntheticInteraction(event);
        return;
      }
      moveTo(event.clientX, event.clientY);
    };

    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('mousedown', onMouseDown, true);
    document.addEventListener('click', onSyntheticInteraction, true);
    document.addEventListener('focusin', onSyntheticInteraction, true);

    return () => {
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('mousedown', onMouseDown, true);
      document.removeEventListener('click', onSyntheticInteraction, true);
      document.removeEventListener('focusin', onSyntheticInteraction, true);
      if (rafRef.current !== null) {
        window.cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [enabled]);

  if (!identity || !visible || !position) return null;

  return (
    <div
      className="fixed left-0 top-0 z-[60] pointer-events-none select-none"
      style={{
        transform: `translate3d(${position.x}px, ${position.y}px, 0)`,
        transition: 'transform 180ms cubic-bezier(0.22, 1, 0.36, 1)',
      }}
      aria-hidden="true"
    >
      <svg
        viewBox="0 0 24 24"
        className="w-4 h-4 -ml-0.5 -mt-0.5 drop-shadow-sm"
        fill="#111827"
        stroke="#FFFFFF"
        strokeWidth="1.4"
        strokeLinejoin="round"
      >
        <path d="M4 2.5 20 11l-7.2 1.6L9.4 20Z" />
      </svg>
      <span
        className={`absolute left-3.5 top-3 inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold shadow-sm whitespace-nowrap ${PILL_STYLES[identity.kind]}`}
        style={{ transition: 'background-color 180ms ease, color 180ms ease' }}
      >
        <CursorEmblem kind={identity.kind} />
        {identity.label}
      </span>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Shared agent registry — single source of truth for exact pill labels       */
/* -------------------------------------------------------------------------- */

type RegistryRow = Record<string, unknown>;

function asRecord(value: unknown): RegistryRow {
  return value && typeof value === 'object' ? (value as RegistryRow) : {};
}

function firstString(record: RegistryRow, ...keys: string[]): string {
  for (const key of keys) {
    const candidate = record[key];
    if (typeof candidate === 'string' && candidate.trim()) return candidate.trim();
  }
  return '';
}

interface RegistryPill {
  id: string;
  label: string;
}

/** Flattens the registry's PILLS table regardless of whether it is a Map, array or record. */
function registryPills(): RegistryPill[] {
  const pills: unknown = PILLS;
  if (!pills) return [];
  if (pills instanceof Map) {
    return Array.from(pills.entries()).map(([key, value]) => ({
      id: String(key).toLowerCase(),
      label: typeof value === 'string' ? value : firstString(asRecord(value), 'label', 'pill', 'name'),
    }));
  }
  if (Array.isArray(pills)) {
    return pills.map((entry) => {
      const row = asRecord(entry);
      return {
        id: firstString(row, 'id', 'agentId', 'key', 'slug', 'name').toLowerCase(),
        label: firstString(row, 'label', 'pill', 'name'),
      };
    });
  }
  return Object.entries(pills as RegistryRow).map(([key, value]) => ({
    id: key.toLowerCase(),
    label: typeof value === 'string' ? value : firstString(asRecord(value), 'label', 'pill', 'name'),
  }));
}

/** Canonical displayName from the registry — e.g. `Manus Bot`, not the short pill `Manus`. */
function displayNameForId(id: string): string {
  const needle = id.trim().toLowerCase();
  const agent = AGENT_REGISTRY.find((entry) => entry.id.toLowerCase() === needle);
  return agent?.displayName ?? '';
}

/** Exact pill label for a registry id, falling back to a legacy label only if unregistered. */
function pillLabelFor(id: string, fallback: string): string {
  const needle = id.trim().toLowerCase();
  const exact = displayNameForId(needle);
  if (exact) return exact;
  const match = registryPills().find((pill) => pill.id === needle || pill.label.toLowerCase() === needle);
  return match?.label || fallback;
}

/**
 * Resolves a named agent from the raw request user-agent (authoritative at the edge) or,
 * when that is unavailable, from a verified agent id / name. PILLS supplies the exact label.
 */
function registryPillFor(input: {
  userAgent?: string | null;
  agentId?: string | null;
  agentName?: string | null;
}): RegistryPill | null {
  const ua = (input.userAgent || '').trim();
  if (ua) {
    let found: unknown = null;
    try {
      found = findAgentByUa(ua);
    } catch {
      found = null;
    }
    if (found) {
      const row = asRecord(found);
      const id = firstString(row, 'id', 'agentId', 'key', 'slug', 'name').toLowerCase();
      const label = firstString(row, 'displayName', 'name', 'label');
      const pill = pillLabelFor(id, label);
      if (pill) return { id, label: pill };
    }
  }

  const id = (input.agentId || '').trim().toLowerCase();
  if (id) {
    const label = pillLabelFor(id, '');
    if (label) return { id, label };
  }

  const name = (input.agentName || '').trim().toLowerCase();
  if (name) {
    const match = registryPills().find(
      (pill) =>
        pill.label.toLowerCase().includes(name) ||
        name.includes(pill.label.toLowerCase()) ||
        pill.id.includes(name)
    );
    if (match) return match;
  }
  return null;
}

/** Maps a registry id/label onto the existing pill style kinds without breaking any of them. */
function registryKind(pill: RegistryPill): CursorIdentityKind {
  const key = `${pill.id} ${pill.label}`.toLowerCase();
  if (key.includes('claude')) return 'claude';
  if (key.includes('gemini')) return 'gemini';
  if (key.includes('grok')) return 'grok';
  if (key.includes('perplexity')) return 'perplexity';
  if (key.includes('muse')) return 'muse';
  if (key.includes('chatgpt') || key.includes('openai') || key.includes('gpt-')) return 'chatgpt';
  if (key.includes('firecrawl')) return 'firecrawl';
  if (key.includes('browser use') || key.includes('browser-use') || key.includes('browseruse'))
    return 'browseruse';
  if (key.includes('skyvern')) return 'skyvern';
  if (key.includes('multion')) return 'multion';
  if (key.includes('hyperbrowser')) return 'hyperbrowser';
  if (key.includes('steel')) return 'steel';
  if (key.includes('airtop')) return 'airtop';
  if (key.includes('notte')) return 'notte';
  if (key.includes('lightpanda')) return 'lightpanda';
  // Crawlers and other named bots get the neutral "cloud" emblem; they keep their exact
  // registry label but never a fabricated signed-agent identity.
  return 'cloud';
}

/** Brand pill for a named remote browser harness; null when the name is unknown. */
function remoteBrowserIdentity(name: string): CursorIdentity | null {
  if (name.includes('firecrawl'))
    return { kind: 'firecrawl', label: pillLabelFor('firecrawl', 'Firecrawl') };
  if (name.includes('browser use') || name.includes('browser-use') || name.includes('browseruse'))
    return { kind: 'browseruse', label: pillLabelFor('browseruse', 'Browser Use') };
  if (name.includes('skyvern')) return { kind: 'skyvern', label: pillLabelFor('skyvern', 'Skyvern') };
  if (name.includes('multion')) return { kind: 'multion', label: pillLabelFor('multion', 'MultiOn') };
  if (name.includes('hyperbrowser'))
    return { kind: 'hyperbrowser', label: pillLabelFor('hyperbrowser', 'Hyperbrowser') };
  if (name.includes('steel')) return { kind: 'steel', label: pillLabelFor('steel', 'Steel') };
  if (name.includes('airtop')) return { kind: 'airtop', label: pillLabelFor('airtop', 'Airtop') };
  if (name.includes('notte')) return { kind: 'notte', label: pillLabelFor('notte', 'Notte') };
  if (name.includes('lightpanda'))
    return { kind: 'lightpanda', label: pillLabelFor('lightpanda', 'Lightpanda') };
  return null;
}

/** Semantic `bot_type` values that denote browser automation, never a signed agent. */
const AUTOMATION_BOT_TYPES = new Set([
  'automation',
  'browser_automation',
  'stealth_automation',
  'chromium_automation',
  'chromium',
  'cdp_automation',
  'playwright',
  'puppeteer',
  'selenium',
  'ai_browser',
]);

/** True only for a server-authoritative automation bot_type (never `ai_agent` / a crawler). */
export function isAutomationBotType(botType: string | null | undefined): boolean {
  const type = (botType || '').trim().toLowerCase();
  if (!type || type === 'ai_agent' || type === 'human' || type === 'ai_crawler') return false;
  return type.startsWith('headless') || AUTOMATION_BOT_TYPES.has(type);
}

/**
 * The one canonical display label for an automation verdict, shared by the cursor pill,
 * the attribution banner and the Event JSON so they can never disagree. Returns `null`
 * for humans, genuine signed agents and verified crawlers.
 */
export function resolveAutomationLabel(botType: string | null | undefined): string | null {
  const type = (botType || '').trim().toLowerCase();
  if (!isAutomationBotType(type)) return null;
  return type.startsWith('headless') ? 'Headless Browser Automation' : 'Stealth Automation';
}

/**
 * Maps a resolved visitor verdict onto the pill the overlay renders.
 *
 * Returns `null` for every human visitor, including Brave and other privacy browsers: a human
 * is never named and never gets a synthetic cursor.
 */
export function resolveCursorIdentity(input: {
  botSubtype?: string | null;
  isBot?: boolean;
  botType?: string | null;
  agentId?: string | null;
  agentName?: string | null;
  /** Raw request user-agent. The registry resolves exact named agents from it. */
  userAgent?: string | null;
  /** True when the agent id/name came from a verified signed-agent verdict, not a stale mirror. */
  agentVerified?: boolean;
}): CursorIdentity | null {
  const automationLabel = resolveAutomationLabel(input.botType);

  // A named agent resolved from the *raw request UA* is authoritative at the edge; so is a
  // verified signed-agent claim. Only when neither exists may an automation bot_type win —
  // that keeps stealth automation authoritative without letting a stale aiAgent/Gemini field
  // replace a real named crawler with "Automated" (or mint a bogus Gemini label).
  const uaAgent = (input.userAgent || '').trim()
    ? (() => {
        try {
          return findAgentByUa((input.userAgent || '').trim());
        } catch {
          return null;
        }
      })()
    : null;
  const authoritativeNamedAgent = Boolean(
    uaAgent || (input.agentVerified && (input.agentId || input.agentName))
  );
  if (automationLabel && !authoritativeNamedAgent) {
    return { kind: 'automation', label: automationLabel };
  }

  // Registry lookup first — PILLS supplies the exact label (e.g. `Manus Bot`,
  // `MistralAI-User`, `Googlebot`) so every surface spells the agent identically.
  const pill = registryPillFor(input);
  if (pill) {
    return { kind: registryKind(pill), label: pill.label };
  }

  const agent = (input.agentId || '').toLowerCase();
  const agentName = (input.agentName || '').toLowerCase();

  // Legacy signed-agent kinds are preserved as a fallback when the registry has no entry.
  if (agent === 'claude' || agentName.includes('claude'))
    return { kind: 'claude', label: pillLabelFor('claude', 'Claude-User') };
  if (agent === 'gemini' || agentName.includes('gemini'))
    return { kind: 'gemini', label: pillLabelFor('gemini', 'Gemini') };
  if (agent === 'grok' || agentName.includes('grok'))
    return { kind: 'grok', label: pillLabelFor('grok', 'Grok') };
  if (agent === 'perplexity' || agentName.includes('perplexity'))
    return { kind: 'perplexity', label: pillLabelFor('perplexity', 'Perplexity') };
  if (agent === 'muse' || agentName.includes('muse'))
    return { kind: 'muse', label: pillLabelFor('muse', 'Muse') };
  if (agent === 'openai' || agentName.includes('chatgpt') || agentName.includes('gpt'))
    return { kind: 'chatgpt', label: pillLabelFor('chatgpt', 'ChatGPT-User') };

  const remoteBrand = remoteBrowserIdentity(agentName);
  if (remoteBrand) return remoteBrand;

  if (agent === 'cloud-browser' || agent === 'remote-browser')
    return { kind: 'cloud', label: pillLabelFor('remotebrowser', 'Remote Browser') };

  // A named agent was detected but has no registry pill: keep its exact name rather than
  // collapsing to "Automated" — the name comes from the server's authoritative verdict.
  if (authoritativeNamedAgent && input.agentName && input.agentName !== 'unknown') {
    return { kind: 'cloud', label: input.agentName.trim() };
  }

  // Any other automated visitor still gets attribution, but never the human cursor.
  if (input.isBot || input.botSubtype === 'bad_bot' || input.botSubtype === 'ai_agent')
    return { kind: 'automation', label: automationLabel || 'Automated' };

  return null;
}

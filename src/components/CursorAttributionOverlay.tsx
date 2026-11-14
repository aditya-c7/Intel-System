import { useEffect, useRef, useState } from 'react';

/**
 * Cursor attribution overlay.
 *
 * Human visitors produce a continuous `pointermove` stream. Remote browser AI agents driving
 * a page over CDP jump straight to a target and fire `click` / `focusin` with no intermediate
 * pointer movement, so the overlay also binds those capture-phase events and parks the cursor
 * on the interacted element's bounding-box centre. The position is animated with a short
 * cubic-bezier transition instead of a per-frame spring so it stays cheap on low-end devices.
 */

export type CursorIdentityKind =
  | 'human'
  | 'brave'
  | 'instinct'
  | 'claude'
  | 'gemini'
  | 'grok'
  | 'perplexity'
  | 'muse'
  | 'chatgpt';

export interface CursorIdentity {
  kind: CursorIdentityKind;
  /** Visible pill label, e.g. `Claude-User`. */
  label: string;
}

const PILL_STYLES: Record<CursorIdentityKind, string> = {
  human: 'bg-[#F3F4F6] border-[#D1D5DB] text-[#374151]',
  brave: 'bg-white border-slate-300 text-slate-800',
  instinct: 'bg-[#FCE8E6] border-[#F6AEA9] text-[#A50E0E]',
  claude: 'bg-[#E6F4EA] border-[#CEEAD6] text-[#137333]',
  gemini: 'bg-[#E8F0FE] border-[#D2E3FC] text-[#174EA6]',
  grok: 'bg-[#F1F3F4] border-[#DADCE0] text-[#111111]',
  perplexity: 'bg-[#E4F7FB] border-[#CBF0F8] text-[#007B83]',
  muse: 'bg-[#FCE8E6] border-[#FAD2CF] text-[#3C4043]',
  chatgpt: 'bg-[#E6F4EA] border-[#CEEAD6] text-[#0D652D]',
};

function CursorEmblem({ kind }: { kind: CursorIdentityKind }) {
  if (kind === 'human') {
    return (
      <svg viewBox="0 0 16 16" className="w-3 h-3 shrink-0" aria-hidden="true">
        <circle cx="8" cy="5.2" r="2.5" fill="currentColor" />
        <path d="M2.8 14c0-2.7 2.3-4.6 5.2-4.6s5.2 1.9 5.2 4.6" fill="currentColor" />
      </svg>
    );
  }
  if (kind === 'instinct') {
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

export function CursorAttributionOverlay({ identity }: { identity: CursorIdentity }) {
  const [position, setPosition] = useState<{ x: number; y: number } | null>(null);
  const [visible, setVisible] = useState(false);
  const rafRef = useRef<number | null>(null);
  const pendingRef = useRef<{ x: number; y: number } | null>(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;

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
  }, []);

  if (!visible || !position) return null;

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

/** Maps a resolved visitor verdict onto the pill the overlay renders. */
export function resolveCursorIdentity(input: {
  botSubtype?: string | null;
  isBot?: boolean;
  agentId?: string | null;
  agentName?: string | null;
  isBrave?: boolean;
}): CursorIdentity {
  const agent = (input.agentId || '').toLowerCase();
  const agentName = (input.agentName || '').toLowerCase();
  if (agent === 'claude' || agentName.includes('claude')) return { kind: 'claude', label: 'Claude-User' };
  if (agent === 'gemini' || agentName.includes('gemini')) return { kind: 'gemini', label: 'Gemini' };
  if (agent === 'grok' || agentName.includes('grok')) return { kind: 'grok', label: 'Grok' };
  if (agent === 'perplexity' || agentName.includes('perplexity'))
    return { kind: 'perplexity', label: 'Perplexity' };
  if (agent === 'muse' || agentName.includes('muse')) return { kind: 'muse', label: 'Muse' };
  if (agent === 'openai' || agentName.includes('chatgpt') || agentName.includes('gpt'))
    return { kind: 'chatgpt', label: 'ChatGPT-User' };
  if (input.isBot || input.botSubtype === 'bad_bot' || agent === 'cloud-browser')
    return { kind: 'instinct', label: 'Instinct' };
  if (input.isBrave) return { kind: 'brave', label: 'Brave' };
  return { kind: 'human', label: 'Human' };
}

/**
 * networkTruthShadow.ts — additive, SHADOW-ONLY description of network truth signals.
 *
 * This module is deliberately inert. It is pure, deterministic, dependency-free and performs
 * ZERO I/O (no network, no timers, no randomness, no DOM, no globals). Its single export builds
 * an OPTIONAL, namespaced, descriptive diagnostic from shapes the identify handler already
 * has (edge transport, resolved geo, proxy details, an observed RTT). It is published only as
 * a flag-gated mirror and is NEVER read into a score, a graded ledger, a risk tier, a bot
 * verdict, an identity decision or a trust/verification claim.
 *
 * Design invariants (enforced by code, not just documentation):
 *
 *  - Nothing here is a verdict. `quicNormalized.status` / `effectiveRttSource.source` are
 *    factual observations of supplied signals; `lightDistance.direction` is prose. There are
 *    no booleans that assert proxy/VPN truth, no probabilities, no scores and no tier labels.
 *  - `proxyProvider` / `proxyObservedAt` are emitted ONLY when a genuine, bounded value was
 *    supplied. No provider name or observation time is ever fabricated from an ASN, colo or
 *    timestamp of the request itself.
 *  - The light-distance block is explicitly labelled an APPROXIMATION and explicitly NOT
 *    JA4L. It asserts no mismatch and claims no verified distance reference (none exists).
 *  - Total function: any input (null, primitives, arrays, throwing getters, hostile strings)
 *    returns `undefined` or a bounded descriptive record and NEVER throws or mutates input.
 */

/** The only permitted label for the light-distance caveat — an approximation, never JA4L. */
export const LIGHT_DISTANCE_LABEL = 'RTT-based light-distance estimate (approximation; not JA4L)' as const;

/** Tokens that explicitly mean "not observed" and must never be surfaced as genuine values. */
const UNAVAILABLE_TOKENS: ReadonlySet<string> = new Set([
  'unavailable',
  'unknown',
  'n/a',
  'na',
  'null',
  'none',
  '-',
  'not available',
]);

/* -------------------------------------------------------------------------- */
/* Public shapes                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Permissive input view. Every field is `unknown` on purpose: callers pass existing edge /
 * geo / proxy objects verbatim, and the readers below decide what is genuinely usable.
 */
export interface NetworkTruthShadowInput {
  /** Edge-transport fields (the server's `readEdgeTransport` output / worker edge-geo payload). */
  edgeTransport?: {
    httpProtocol?: unknown;
    edgeL4?: unknown;
    clientTcpRtt?: unknown;
    clientQuicRtt?: unknown;
    colo?: unknown;
  } | null;
  /** Resolved geolocation fields, used ONLY to write a descriptive direction. */
  geo?: {
    countryCode?: unknown;
    country?: unknown;
  } | null;
  /** Proxy-details shape; provider / recency are optional and only used when genuinely present. */
  proxyDetails?: {
    provider?: unknown;
    observedAt?: unknown;
    observed_at?: unknown;
    [key: string]: unknown;
  } | null;
  /** Any positive real RTT sample already observed by the caller (edge or client reported). */
  observedRttMs?: unknown;
}

export interface NetworkTruthQuicNormalization {
  /** Factual observation of the supplied signals — not a proxy/VPN/bot verdict. */
  status: 'quic_signal_present' | 'no_quic_signal';
  /** Which genuinely supplied field carried the QUIC signal. */
  basis: 'httpProtocol' | 'edgeL4' | 'none';
  /** Human-readable description; no trust claim. */
  label: string;
  /** Present only when a 0 ms TCP RTT on QUIC was normalized away as a placeholder. */
  zeroTcpRttNote?: string;
}

export interface NetworkTruthRttSource {
  /** Which genuinely supplied field provided the effective RTT, or 'unavailable'. */
  source: 'clientQuicRtt' | 'clientTcpRtt' | 'clientReportedRtt' | 'unavailable';
  /** Human-readable description; no measurement is invented when the source is unavailable. */
  label: string;
}

export interface NetworkTruthEdgeTransport {
  quicNormalized: NetworkTruthQuicNormalization;
  effectiveRttSource: NetworkTruthRttSource;
  /** Edge colo, present only when genuinely supplied. */
  colo?: string;
}

export interface NetworkTruthLightDistance {
  /** Always the fixed approximation / not-JA4L label. */
  label: typeof LIGHT_DISTANCE_LABEL;
  /** Descriptive direction only; no mismatch is asserted and no reference is trusted. */
  direction: string;
  /** Explicit caveat: descriptive approximation, no trust claim, never a gate input. */
  note: string;
}

export interface NetworkTruthShadow {
  /** Proxy provider name, present ONLY when a genuine bounded string was supplied. */
  proxyProvider?: string;
  /** ISO-8601 observation time, present ONLY when a genuine timestamp was supplied. */
  proxyObservedAt?: string;
  /** Descriptive edge-transport normalization, present only when an edge/RTT signal exists. */
  edgeTransport?: NetworkTruthEdgeTransport;
  /** Descriptive light-distance caveat, present only when a geo/edge/RTT signal exists. */
  lightDistance?: NetworkTruthLightDistance;
}

/* -------------------------------------------------------------------------- */
/* Defensive readers (never call valueOf / toString on untrusted values)       */
/* -------------------------------------------------------------------------- */

function isRecord(value: unknown): value is Record<string, unknown> {
  try {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  } catch {
    return false;
  }
}

/** Trimmed plain-text read; non-strings and over-long strings are treated as absent. */
function safeText(value: unknown, maxLength: number): string {
  try {
    if (typeof value !== 'string') return '';
    const text = value.trim();
    if (!text || text.length > maxLength) return '';
    if (UNAVAILABLE_TOKENS.has(text.toLowerCase())) return '';
    return text;
  } catch {
    return '';
  }
}

/** Genuine provider label: bounded plain text, never an "unavailable" token. */
function genuineProvider(value: unknown): string | undefined {
  const text = safeText(value, 120);
  return text || undefined;
}

/** Genuine ISO-8601 observation time: strict shape + real calendar parse. */
function genuineObservationTime(value: unknown): string | undefined {
  try {
    if (typeof value === 'string') {
      const text = value.trim();
      if (!text || text.length > 40) return undefined;
      if (!/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?$/.test(text)) {
        return undefined;
      }
      const ms = Date.parse(text);
      return Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
    }
    // Epoch milliseconds only, with a sanity range; 0 / seconds-scale values are not accepted.
    if (typeof value === 'number' && Number.isFinite(value) && value > 1e12 && value < 1e14) {
      return new Date(value).toISOString();
    }
  } catch {
    // Ignore and fail closed.
  }
  return undefined;
}

/** Positive finite RTT; 0 is a placeholder, not a measurement. */
function positiveRtt(value: unknown): number | undefined {
  try {
    if (typeof value === 'number' && Number.isFinite(value) && value > 0) return value;
  } catch {
    // Ignore and fail closed.
  }
  return undefined;
}

/* -------------------------------------------------------------------------- */
/* Public builder                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Build an optional, purely descriptive network-truth shadow record.
 *
 * Returns `undefined` when nothing genuine was supplied (so a conditional-spread caller emits
 * no new key at all). When something is available, only the genuinely observed members appear.
 * The result is deterministic for identical inputs and contains no verdict, score, tier or
 * trust/verification claim.
 */
export function buildNetworkTruthShadow(input?: unknown): NetworkTruthShadow | undefined {
  try {
    if (!isRecord(input)) return undefined;
    const bag = input as NetworkTruthShadowInput;

    let edgeRaw: unknown;
    let geoRaw: unknown;
    let proxyRaw: unknown;
    let observedRttRaw: unknown;
    try {
      edgeRaw = bag.edgeTransport;
      geoRaw = bag.geo;
      proxyRaw = bag.proxyDetails;
      observedRttRaw = bag.observedRttMs;
    } catch {
      return undefined;
    }
    const edge = isRecord(edgeRaw) ? edgeRaw : null;
    const geo = isRecord(geoRaw) ? geoRaw : null;
    const proxy = isRecord(proxyRaw) ? proxyRaw : null;

    let httpProtocol = '';
    let edgeL4 = '';
    let colo = '';
    let tcpRtt: number | undefined;
    let quicRtt: number | undefined;
    let tcpRttIsZero = false;
    try {
      httpProtocol = safeText(edge?.httpProtocol, 64);
      edgeL4 = safeText(edge?.edgeL4, 32);
      colo = safeText(edge?.colo, 16);
      const rawTcp = edge?.clientTcpRtt;
      const rawQuic = edge?.clientQuicRtt;
      tcpRtt = positiveRtt(rawTcp);
      quicRtt = positiveRtt(rawQuic);
      tcpRttIsZero = rawTcp === 0;
    } catch {
      return undefined;
    }

    const isQuic = /HTTP\/3|QUIC/i.test(httpProtocol) || /^quic$/i.test(edgeL4);
    const observedRtt = positiveRtt(observedRttRaw);

    // Proxy provider / recency: only genuine, bounded values, never inferred from other fields.
    let proxyProvider: string | undefined;
    let proxyObservedAt: string | undefined;
    if (proxy) {
      try {
        proxyProvider = genuineProvider(proxy.provider);
        proxyObservedAt = genuineObservationTime(proxy.observedAt ?? proxy.observed_at);
      } catch {
        // A throwing getter must not surface a fabricated value.
        proxyProvider = undefined;
        proxyObservedAt = undefined;
      }
    }

    // Descriptive edge-transport block.
    let edgeTransport: NetworkTruthEdgeTransport | undefined;
    const hasEdgeSignal = Boolean(
      httpProtocol || edgeL4 || colo || tcpRtt || quicRtt || tcpRttIsZero || observedRtt
    );
    if (hasEdgeSignal) {
      const quicBasis = /HTTP\/3|QUIC/i.test(httpProtocol)
        ? 'httpProtocol'
        : /^quic$/i.test(edgeL4)
        ? 'edgeL4'
        : 'none';
      const quicNormalized: NetworkTruthQuicNormalization = {
        status: isQuic ? 'quic_signal_present' : 'no_quic_signal',
        basis: quicBasis,
        label: isQuic
          ? `QUIC/HTTP/3 transport signal normalized from edge ${quicBasis}`
          : 'No QUIC/HTTP/3 signal observed in the supplied edge transport fields',
        ...(isQuic && tcpRttIsZero
          ? { zeroTcpRttNote: 'A 0 ms TCP RTT on QUIC is a placeholder, normalized to unavailable' }
          : {}),
      };
      const rttSource: NetworkTruthRttSource =
        quicRtt !== undefined
          ? { source: 'clientQuicRtt', label: 'Positive edge-observed QUIC RTT preferred on HTTP/3' }
          : tcpRtt !== undefined
          ? {
              source: 'clientTcpRtt',
              label: 'Positive edge-observed TCP RTT (no positive QUIC RTT supplied)',
            }
          : observedRtt !== undefined
          ? {
              source: 'clientReportedRtt',
              label: 'Positive client-reported RTT sample (fallback, not edge-observed)',
            }
          : { source: 'unavailable', label: 'No positive real RTT sample supplied' };
      edgeTransport = {
        quicNormalized,
        effectiveRttSource: rttSource,
        ...(colo ? { colo } : {}),
      };
    }

    // Descriptive light-distance caveat. It never asserts a mismatch: with no trusted distance
    // reference a contradiction cannot be established, so this is prose about direction only.
    let lightDistance: NetworkTruthLightDistance | undefined;
    let countryLabel: string | undefined;
    try {
      countryLabel = geo ? safeText(geo.countryCode, 80) || safeText(geo.country, 80) || undefined : undefined;
    } catch {
      countryLabel = undefined;
    }
    if (hasEdgeSignal || countryLabel) {
      const direction = colo && countryLabel
        ? `client → edge colo ${colo}; resolved geo ${countryLabel} (descriptive only, no mismatch asserted)`
        : colo
        ? `client → edge colo ${colo} (no resolved geo to compare; direction not independently checked)`
        : countryLabel
        ? `client → resolved geo ${countryLabel} (no edge colo to compare; direction not independently checked)`
        : 'client → server (single-hop RTT; direction not independently observable)';
      lightDistance = {
        label: LIGHT_DISTANCE_LABEL,
        direction,
        note: 'Descriptive approximation only: no mismatch asserted, no trust claim, never a gate input.',
      };
    }

    const shadow: NetworkTruthShadow = {};
    if (proxyProvider) shadow.proxyProvider = proxyProvider;
    if (proxyObservedAt) shadow.proxyObservedAt = proxyObservedAt;
    if (edgeTransport) shadow.edgeTransport = edgeTransport;
    if (lightDistance) shadow.lightDistance = lightDistance;
    return Object.keys(shadow).length > 0 ? shadow : undefined;
  } catch {
    return undefined;
  }
}

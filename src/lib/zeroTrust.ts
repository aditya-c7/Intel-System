/**
 * Zero-trust shadow helpers (additive, pure, dependency-free).
 *
 * These functions are deliberately standalone: they do not import the server, the Worker, or
 * any third-party SDK, and they never mutate their inputs or throw. They encode the trust rules
 * that the existing sealed-envelope path already uses (65-second freshness window, one-shot
 * nonce, 5-minute future-skew tolerance) so a shadow evaluation can be reasoned about and
 * tested in isolation before anything is wired into a request path.
 *
 * Trust model:
 *   - Transport headers (Origin / Referer) are the only corroboration for client-reported
 *     `location.href` / `document.referrer`. A contradiction is always fatal — a client payload
 *     can never "approve" its own lie.
 *   - Missing headers are a legacy compatibility case: accept, but say so in the reason.
 *   - Replay detection is independent of freshness: an already-seen nonce is a replay even
 *     when the timestamp is still inside the window.
 */

export interface OriginCheckInput {
  origin?: string | null;
  referer?: string | null;
  clientUrl?: string | null;
  clientReferrer?: string | null;
  nowMs?: number;
}

export interface ReplayWindowStatus {
  fresh: boolean;
  duplicate: boolean;
  reason: string;
}

export interface IpReplayRate {
  attack_source: boolean;
  ratio: number;
}

/** Mirrors ENVELOPE_MAX_FUTURE_SKEW_MS in src/lib/telemetryContract.ts (5 minutes). */
const FUTURE_SKEW_MS = 300_000;

/** Mirrors ENVELOPE_MAX_AGE_MS in src/lib/telemetryContract.ts (65 seconds). */
const DEFAULT_MAX_AGE_MS = 65_000;

function finiteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function safeText(value: unknown): string {
  return typeof value === 'string' && value.trim() ? value.trim() : '';
}

function parseUrl(value: string): URL | null {
  if (!value) return null;
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

/** Opaque `null` origins (sandboxed frames, data: URLs) cannot corroborate anything. */
function isHttpOrigin(url: URL | null): url is URL {
  return Boolean(
    url && (url.protocol === 'http:' || url.protocol === 'https:') && url.origin !== 'null'
  );
}

/** The fragment is stripped from real Referer headers, so it must not take part in matching. */
function refererKey(url: URL): string {
  return `${url.origin}${url.pathname}${url.search}`;
}

/**
 * A Referer header may be reduced to its origin by `Referrer-Policy:
 * strict-origin-when-cross-origin` (the policy the Worker emits), so an origin-only header is
 * compatible with any client referrer on that origin. A longer header must be a path prefix on
 * a segment boundary of the client value — never a loose substring match.
 */
function refererCompatible(header: URL, client: URL): boolean {
  if (header.origin !== client.origin) return false;
  const h = refererKey(header);
  const c = refererKey(client);
  if (h === c) return true;
  if (h === header.origin || h === `${header.origin}/`) return true;
  if (!c.startsWith(h)) return false;
  const next = c.charAt(h.length);
  return next === '' || next === '/' || next === '?' || next === '#';
}

/**
 * Strict origin/referer cross-check.
 *
 * Rejects when a present transport header contradicts the matching client-reported value;
 * accepts (with an explanatory reason) when headers are absent or unusable. Client values are
 * never allowed to override a contradiction.
 */
export function checkStrictOrigin(input: OriginCheckInput): { ok: boolean; reason: string } {
  const bag = (input && typeof input === 'object' ? input : {}) as OriginCheckInput;
  const originText = safeText(bag.origin);
  const refererText = safeText(bag.referer);
  const clientUrlText = safeText(bag.clientUrl);
  const clientReferrerText = safeText(bag.clientReferrer);

  const notes: string[] = [];
  if (bag.nowMs !== undefined && finiteNumber(bag.nowMs) === null) {
    notes.push('invalid nowMs ignored');
  }

  const originUrl = parseUrl(originText);
  const refererUrl = parseUrl(refererText);
  const clientUrl = parseUrl(clientUrlText);
  const clientReferrer = parseUrl(clientReferrerText);

  if (originText && !isHttpOrigin(originUrl)) notes.push('unusable Origin header ignored');
  if (refererText && !isHttpOrigin(refererUrl)) notes.push('unusable Referer header ignored');
  if (clientUrlText && !isHttpOrigin(clientUrl)) notes.push('unusable client url ignored');
  if (clientReferrerText && !isHttpOrigin(clientReferrer)) {
    notes.push('unusable client referrer ignored');
  }

  const contradictions: string[] = [];
  if (isHttpOrigin(originUrl) && isHttpOrigin(clientUrl) && originUrl.origin !== clientUrl.origin) {
    contradictions.push(`Origin ${originUrl.origin} contradicts client url ${clientUrl.origin}`);
  }
  if (
    isHttpOrigin(refererUrl) &&
    isHttpOrigin(clientReferrer) &&
    !refererCompatible(refererUrl, clientReferrer)
  ) {
    contradictions.push(
      `Referer ${refererKey(refererUrl)} contradicts client referrer ${refererKey(clientReferrer)}`
    );
  }

  const suffix = notes.length ? `; ${notes.join('; ')}` : '';
  if (contradictions.length > 0) {
    return { ok: false, reason: `${contradictions.join('; ')}${suffix}` };
  }

  const headersPresent = Boolean(originText || refererText);
  const corroborated =
    (isHttpOrigin(originUrl) && isHttpOrigin(clientUrl)) ||
    (isHttpOrigin(refererUrl) && isHttpOrigin(clientReferrer));

  const base = !headersPresent
    ? 'legacy: no Origin/Referer headers; client-reported url/referrer accepted without corroboration'
    : corroborated
      ? 'Origin/Referer headers corroborate client-reported url/referrer'
      : 'Origin/Referer headers present but not comparable with the client report; no contradiction found';

  return { ok: true, reason: `${base}${suffix}` };
}

/**
 * Freshness + one-shot-nonce status for a sealed envelope.
 *
 * A timestamp is fresh while its age is within `maxAgeMs` (inclusive — the Worker's 65s
 * boundary) and it is no more than five minutes in the future (the existing skew tolerance).
 * A previously seen nonce is reported as a duplicate independently of freshness.
 */
export function replayWindowStatus(
  timestampMs: number,
  nowMs: number,
  seenNonce?: string | null,
  maxAgeMs = DEFAULT_MAX_AGE_MS
): ReplayWindowStatus {
  const duplicate = typeof seenNonce === 'string' && seenNonce.trim().length > 0;
  const timestamp = finiteNumber(timestampMs);
  const now = finiteNumber(nowMs);
  const configuredMaxAge = finiteNumber(maxAgeMs);
  const maxAge =
    configuredMaxAge !== null && configuredMaxAge >= 0 ? configuredMaxAge : DEFAULT_MAX_AGE_MS;

  if (timestamp === null || now === null || timestamp <= 0) {
    return {
      fresh: false,
      duplicate,
      reason: `invalid timestamp or clock${duplicate ? '; duplicate nonce (replay)' : ''}`,
    };
  }

  const age = now - timestamp;
  const stale = age > maxAge;
  const future = -age > FUTURE_SKEW_MS;
  const fresh = !stale && !future;

  const parts: string[] = [];
  if (stale) parts.push(`stale by ${Math.round(age)}ms (max ${maxAge}ms)`);
  else if (future) parts.push(`timestamp ${Math.round(-age)}ms in the future (max ${FUTURE_SKEW_MS}ms)`);
  else parts.push(`within ${maxAge}ms freshness window`);
  if (duplicate) parts.push('duplicate nonce (replay)');

  return { fresh, duplicate, reason: parts.join('; ') };
}

/**
 * Share of replayed events over a window. `attack_source` needs both statistical mass and a
 * dominant ratio: 20+ observations and at least 75% replays. The small-sample guard prevents a
 * handful of retries (e.g. 3 of 4 from a flaky client) from being labelled an attack source.
 */
export function ipReplayRate(replayed: number, total: number, windowDays = 7): IpReplayRate {
  void windowDays; // descriptive window only; the decision depends solely on the counts.
  const countOf = (value: number): number => {
    const n = finiteNumber(value);
    return n !== null && n > 0 ? n : 0;
  };
  const replayedCount = countOf(replayed);
  const totalCount = countOf(total);
  const ratio = totalCount > 0 ? Math.min(1, replayedCount / totalCount) : 0;
  return { attack_source: totalCount >= 20 && ratio >= 0.75, ratio };
}

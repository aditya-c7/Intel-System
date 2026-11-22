/**
 * Phase 1 — proxy "truth gap" helpers (SHADOW ONLY; no consumer yet).
 *
 * This module is deliberately *additive*. It does not modify, replace or import any
 * existing proxy/VPN verdict, and it is not referenced anywhere yet. Its purpose is to
 * provide a conservative, auditable second opinion that can later be compared against a
 * legacy proxy flag via {@link proxyDetailsParityIssue}.
 *
 * Design invariants (all enforced by code, not just documentation):
 *
 *  - `proxy_type: 'data_center'` is emitted **ONLY** when `datacenterResult === true`
 *    AND `verifiedGoodBot !== true`. A verified good bot (a known-benign crawler/bot) is
 *    an explicit exemption and must never be relabelled as a data-center proxy. A bare
 *    `asnType: 'datacenter'`/`'cloud'` value is NOT sufficient on its own — it is used for
 *    the human-readable `reason` only, never as the flag itself.
 *  - `proxy_type: 'residential'` is emitted **ONLY** with an explicit residential signal:
 *    `knownProxyPrefix === true` or an ASN type that literally denotes residential
 *    service. A plain ISP/mobile/hosting ASN, or a lone `vpn === true`, never upgrades to
 *    a residential claim.
 *  - `proxy: false` is returned whenever there is no positive evidence; absence of a
 *    signal is never treated as proof of a proxy, and a `null` signal is treated exactly
 *    like an absent one.
 *  - No numeric/ML score is invented. `confidence` is a categorical strength of the
 *    *evidence that was supplied*, not a calibrated probability and not a network-derived
 *    score. No network calls, timers, randomness, DOM access, or side effects occur.
 *  - Both exported functions are total: any input shape (including `null`, arrays,
 *    primitives, getters that throw) returns a value and never throws.
 */

/** The subset of provider/network signals this resolver is allowed to look at. */
export interface ProxyDetailsInput {
  /**
   * Provider/hosting "is this a datacenter egress?" result. `true` is the *only* signal
   * that may produce `proxy_type: 'data_center'` (and only when not exempted).
   * `false`/`null`/absent are all treated as "no datacenter evidence".
   */
  datacenterResult?: boolean | null;

  /**
   * ASN classification label (e.g. `'isp'`, `'mobile'`, `'datacenter'`, `'cloud'`,
   * `'residential'`, `'residential_rotating'`). Only an explicit residential label may
   * contribute a residential proxy finding; datacenter/cloud labels are reason-only.
   * Comparison is case-insensitive and whitespace-tolerant.
   */
  asnType?: string | null;

  /**
   * Autonomous System number, used *only* to enrich the human-readable `reason`
   * (e.g. `"ASN 12345"`). It is never itself evidence of a proxy and never affects the
   * `proxy`, `proxy_type` or `confidence` fields. Non-finite/non-positive values are
   * ignored.
   */
  asn?: number | null;

  /**
   * A VPN/relay signal. On its own it yields `proxy: true` with an *unknown* type
   * (`proxy_type: null`) — it never manufactures a data-center or residential label.
   */
  vpn?: boolean | null;

  /**
   * Explicit "verified good bot" exemption. When `true`, it suppresses the data-center
   * flag even if `datacenterResult === true`. It does not suppress other evidence.
   */
  verifiedGoodBot?: boolean | null;

  /**
   * Explicit "this prefix is a known proxy prefix" signal. `true` is a strong, direct
   * residential-capable proxy signal and also raises evidence confidence to `'high'`.
   */
  knownProxyPrefix?: boolean | null;
}

/** A conservative, auditable proxy verdict produced solely from supplied signals. */
export interface ProxyDetails {
  /** `true` only when at least one positive proxy signal was supplied. */
  proxy: boolean;
  /**
   * The only two labels this resolver is permitted to emit. `'data_center'` requires
   * `datacenterResult === true && verifiedGoodBot !== true`; `'residential'` requires an
   * explicit residential signal. `null` means "proxy evidence exists but its type cannot
   * be honestly classified" (e.g. a lone VPN signal), or "no proxy" (see `proxy`).
   */
  proxy_type: 'data_center' | 'residential' | null;
  /**
   * Categorical strength of the supplied evidence, NOT a probability/ML score:
   *  - `'high'`   — direct signal (datacenter result, or a known proxy prefix);
   *  - `'medium'` — indirect/rated signal (VPN, or a residential ASN label);
   *  - `'low'`    — no positive evidence (the returned `proxy: false` is a weak
   *                 assertion, not a confident "no proxy" claim).
   */
  confidence: 'low' | 'medium' | 'high';
  /**
   * Deterministic, human-readable audit trail for the verdict. Always a non-empty
   * string; derived only from the supplied signals in a fixed order, so identical
   * inputs always produce an identical string.
   */
  reason: string;
}

/** Result of normalizing a legacy/`existing` proxy view for parity comparison. */
interface ExistingProxyView {
  /** The legacy boolean proxy flag, or `null` when it could not be determined. */
  proxy: boolean | null;
  /**
   * The normalized legacy proxy type: `'data_center'`, `'residential'`, `null` (no type),
   * or `undefined` (the field was absent/unrecognized and must not be compared).
   */
  proxyType: ProxyDetails['proxy_type'] | undefined;
}

/** ASN-type labels that count as an *explicit* residential service signal. */
const RESIDENTIAL_ASN_TOKENS: readonly string[] = [
  'residential',
  'residential_rotating',
  'residential_proxy',
  'residential_isp',
  'home',
  'home_broadband',
  'broadband',
  'consumer',
];

/** ASN-type labels that are reason-only context; they can never flag `'data_center'`. */
const DATACENTER_ASN_TOKENS: readonly string[] = [
  'datacenter',
  'data_center',
  'data center',
  'cloud',
  'cdn',
  'hosting',
];

/** Canonicalize an untrusted label for comparison. Never throws. */
function normalizeLabel(value: unknown): string {
  try {
    return typeof value === 'string' ? value.trim().toLowerCase() : '';
  } catch {
    return '';
  }
}

/** True when an ASN label explicitly denotes residential service. Never throws. */
function isResidentialAsnType(value: unknown): boolean {
  const label = normalizeLabel(value);
  if (!label) return false;
  return RESIDENTIAL_ASN_TOKENS.some((token) => label === token || label.includes(token));
}

/** True when an ASN label denotes hosting/datacenter (reason-only, never a flag). Never throws. */
function isDatacenterAsnType(value: unknown): boolean {
  const label = normalizeLabel(value);
  if (!label) return false;
  return DATACENTER_ASN_TOKENS.some((token) => label.includes(token));
}

/** Format an ASN for the reason string, or return `null` when unusable. Never throws. */
function usableAsn(value: unknown): number | null {
  try {
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return null;
    return Math.trunc(value);
  } catch {
    return null;
  }
}

/**
 * Derive a conservative proxy verdict from supplied signals.
 *
 * The function is pure and total. It reads no globals, performs no I/O and mutates
 * nothing; malformed or hostile inputs degrade to "no evidence" instead of throwing.
 *
 * Resolution order (first match wins for `proxy_type`):
 *  1. `dataCenterEvidence` = `datacenterResult === true && verifiedGoodBot !== true`
 *     → `proxy_type: 'data_center'`, `'high'` confidence.
 *  2. `residentialEvidence` = `knownProxyPrefix === true` or an explicit residential
 *     ASN label → `proxy_type: 'residential'`, `'high'` if known-prefix else `'medium'`.
 *  3. `vpn === true` (and none of the above) → `proxy: true` with an unknown `proxy_type`
 *     and `'medium'` confidence.
 *  4. Otherwise → `proxy: false`, `proxy_type: null`, `'low'` confidence.
 *
 * A `verifiedGoodBot === true` exemption is scoped to the data-center flag only; it does
 * not erase a residential or VPN signal. If both datacenter and residential evidence are
 * present, the data-center rule (1) takes precedence and both signals appear in `reason`.
 *
 * @param input The provider/network signals to evaluate. Defaults to `{}`. A `null`,
 *   primitive or array input is treated as an empty object.
 * @returns A deterministic {@link ProxyDetails} verdict with a non-empty audit `reason`.
 */
export function resolveProxyDetails(input: ProxyDetailsInput = {}): ProxyDetails {
  // Defensive normalization: never trust the caller to pass a well-formed object.
  let source: ProxyDetailsInput;
  try {
    source = input && typeof input === 'object' && !Array.isArray(input)
      ? (input as ProxyDetailsInput)
      : {};
  } catch {
    source = {};
  }

  let datacenterResult: unknown;
  let verifiedGoodBot: unknown;
  let knownProxyPrefix: unknown;
  let vpn: unknown;
  let asnType: unknown;
  let asn: unknown;
  try {
    datacenterResult = source.datacenterResult;
    verifiedGoodBot = source.verifiedGoodBot;
    knownProxyPrefix = source.knownProxyPrefix;
    vpn = source.vpn;
    asnType = source.asnType;
    asn = source.asn;
  } catch {
    // A throwing getter must not escape this module.
    datacenterResult = verifiedGoodBot = knownProxyPrefix = vpn = asnType = asn = undefined;
  }

  const datacenterEvidence = datacenterResult === true && verifiedGoodBot !== true;
  const hasKnownProxyPrefix = knownProxyPrefix === true;
  const residentialAsn = isResidentialAsnType(asnType);
  const residentialEvidence = hasKnownProxyPrefix || residentialAsn;
  const vpnEvidence = vpn === true;

  const reasons: string[] = [];
  let proxyType: ProxyDetails['proxy_type'];
  let confidence: ProxyDetails['confidence'];

  if (datacenterEvidence) {
    proxyType = 'data_center';
    confidence = 'high';
    reasons.push('datacenterResult=true with no verified good-bot exemption');
    const asnValue = usableAsn(asn);
    if (asnValue !== null) reasons.push(`ASN ${asnValue}`);
    if (isDatacenterAsnType(asnType)) reasons.push('ASN type is hosting/datacenter');
  } else if (residentialEvidence) {
    proxyType = 'residential';
    confidence = hasKnownProxyPrefix ? 'high' : 'medium';
    if (hasKnownProxyPrefix) reasons.push('explicit known proxy prefix');
    if (residentialAsn) reasons.push(`residential ASN type "${normalizeLabel(asnType)}"`);
    const asnValue = usableAsn(asn);
    if (asnValue !== null) reasons.push(`ASN ${asnValue}`);
  } else if (vpnEvidence) {
    proxyType = null;
    confidence = 'medium';
    reasons.push('VPN/relay signal present but proxy type is not classifiable');
  } else {
    proxyType = null;
    confidence = 'low';
    reasons.push('no proxy evidence among supplied signals');
  }

  // The verified-good-bot exemption is explicitly audited when it actually suppressed a
  // would-be data-center finding (i.e. datacenterResult was true but the bot flag was set).
  if (verifiedGoodBot === true && datacenterResult === true && !datacenterEvidence) {
    reasons.push('data_center flag suppressed by verified good-bot exemption');
  }
  // Surface a residential signal even when the data-center rule took precedence, so the
  // audit trail never hides contradictory evidence.
  if (datacenterEvidence && residentialEvidence) {
    reasons.push(hasKnownProxyPrefix
      ? 'residential known-proxy-prefix signal also present (data_center takes precedence)'
      : `residential ASN type "${normalizeLabel(asnType)}" also present (data_center takes precedence)`);
  }

  return {
    proxy: datacenterEvidence || residentialEvidence || vpnEvidence,
    proxy_type: proxyType,
    confidence,
    reason: reasons.join('; '),
  };
}

/**
 * Normalize a legacy/`existing` proxy signal into a comparable view.
 *
 * Accepts a boolean (the legacy `proxy` flag) or an object exposing `proxy` and/or
 * `proxy_type`. Any other shape returns `null` so the caller can report that parity was
 * not evaluable. Unknown `proxy_type` strings normalize to `undefined` (do not compare).
 */
function readExistingProxyView(existing: unknown): ExistingProxyView | null {
  try {
    if (typeof existing === 'boolean') {
      return { proxy: existing, proxyType: undefined };
    }
    if (existing && typeof existing === 'object' && !Array.isArray(existing)) {
      const raw = existing as Record<string, unknown>;
      const proxy = typeof raw.proxy === 'boolean' ? raw.proxy : null;
      let proxyType: ProxyDetails['proxy_type'] | undefined;
      const typeLabel = normalizeLabel(raw.proxy_type);
      if (!typeLabel || typeLabel === 'none') {
        proxyType = null;
      } else if (
        typeLabel === 'data_center' ||
        typeLabel === 'datacenter' ||
        typeLabel === 'data centre'
      ) {
        proxyType = 'data_center';
      } else if (
        typeLabel === 'residential' ||
        typeLabel === 'residential_rotating' ||
        typeLabel === 'residential_proxy'
      ) {
        proxyType = 'residential';
      } else {
        proxyType = undefined;
      }
      return { proxy, proxyType };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Report additive diagnostics where a legacy proxy signal diverges from a resolved
 * {@link ProxyDetails} verdict. No divergence yields an empty array; this function never
 * throws and never mutates either argument.
 *
 * Comparisons performed:
 *  - `proxy` boolean: reported when the legacy flag is a determinable boolean and differs
 *    from `resolved.proxy`. (Non-boolean/absent legacy flags are not guessed.)
 *  - `proxy_type`: reported when the legacy label is recognized/normalizable and differs
 *    from `resolved.proxy_type`. `'none'` normalizes to `null`; `'datacenter'`/`'residential_rotating'`
 *    normalize to `'data_center'`/`'residential'` respectively. Unrecognized labels are
 *    skipped rather than flagged as a false divergence.
 *  - An unrecognized `existing` shape yields a single informational diagnostic so the
 *    caller knows parity could not be evaluated.
 *
 * @param existing The legacy proxy signal: a boolean flag, or an object with `proxy`
 *   and/or `proxy_type`. Any other value is handled defensively.
 * @param resolved The resolved verdict from {@link resolveProxyDetails}. A missing or
 *   malformed value produces an informational diagnostic rather than throwing.
 * @returns A (possibly empty) list of human-readable divergence diagnostics.
 */
export function proxyDetailsParityIssue(
  existing: unknown,
  resolved: ProxyDetails | null | undefined
): string[] {
  try {
    const issues: string[] = [];
    const resolvedView =
      resolved && typeof resolved === 'object' && !Array.isArray(resolved)
        ? (resolved as ProxyDetails)
        : null;
    if (!resolvedView) {
      issues.push('resolved proxy details are missing or invalid; parity not evaluated');
      return issues;
    }

    const existingView = readExistingProxyView(existing);
    if (!existingView) {
      issues.push('existing proxy signal has an unrecognized shape; parity not evaluated');
      return issues;
    }

    if (existingView.proxy !== null && existingView.proxy !== resolvedView.proxy) {
      issues.push(
        `proxy divergence: existing=${existingView.proxy}, resolved=${resolvedView.proxy}`
      );
    }

    if (
      existingView.proxyType !== undefined &&
      existingView.proxyType !== resolvedView.proxy_type
    ) {
      issues.push(
        `proxy_type divergence: existing=${String(existingView.proxyType)}, resolved=${String(resolvedView.proxy_type)}`
      );
    }

    return issues;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return [`proxy parity could not be evaluated: ${message}`];
  }
}

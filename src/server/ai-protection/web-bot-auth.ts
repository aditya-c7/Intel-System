/**
 * RFC 9421 "HTTP Message Signatures" verification for the Web Bot Auth draft.
 *
 * A signed request carries `Signature-Input`, `Signature` and `Signature-Agent` headers. The
 * public key is discovered from the signer's
 * `/.well-known/http-message-signatures-directory` and cached by RFC 7638 JWK thumbprint.
 * All cryptography uses Web Crypto so the module runs unchanged in Cloudflare Workers.
 */

import { WEB_BOT_AUTH_SIGNER_MAP } from './registry.js';
import { runTransaction, type AIBotDatabase } from './schema.js';

export type WebBotAuthReason =
  | 'signer.web-bot-auth.verified'
  | 'signer.web-bot-auth.declared'
  | 'none';

export interface WebBotAuthResult {
  present: boolean;
  verified: boolean;
  botId?: string;
  operator?: string;
  signerHost?: string;
  keyId?: string;
  reason: WebBotAuthReason;
  errorDetail?: string;
}

export type WebBotAuthHeaderBag = Record<string, string | string[] | undefined>;

export interface WebBotAuthRequest {
  method: string;
  authority: string;
  pathWithQuery: string;
  scheme?: string;
  headers: WebBotAuthHeaderBag;
}

interface SignatureInputParts {
  label: string;
  components: string[];
  keyId: string;
  tag: string;
  created: number | null;
  expires: number | null;
  /** Inner list + parameters exactly as sent, used for the `@signature-params` line. */
  rawParams: string;
}

interface Jwk {
  kty: string;
  crv?: string;
  x?: string;
  kid?: string;
  alg?: string;
  [key: string]: unknown;
}

const DIRECTORY_TIMEOUT_MS = 8000;
const CLOCK_SKEW_SECONDS = 60;

function readHeader(headers: WebBotAuthHeaderBag, name: string): string {
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (key.toLowerCase() !== target) continue;
    if (Array.isArray(value)) return value.join(', ');
    return typeof value === 'string' ? value : '';
  }
  return '';
}

function stripQuotes(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/""/g, '"');
  }
  return trimmed;
}

function parseSignatureInput(raw: string): SignatureInputParts | null {
  const match = /^\s*([A-Za-z0-9_-]+)\s*=\s*\(([^)]*)\)([\s\S]*)$/.exec(raw);
  if (!match) return null;
  const components = [...match[2].matchAll(/"([^"]+)"/g)].map((item) => item[1].toLowerCase());
  const params: Record<string, string> = {};
  for (const part of match[3].split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    params[part.slice(0, eq).trim().toLowerCase()] = stripQuotes(part.slice(eq + 1));
  }
  const asNumber = (value: string | undefined): number | null => {
    if (!value || !/^\d+$/.test(value.trim())) return null;
    const parsed = Number.parseInt(value.trim(), 10);
    return Number.isFinite(parsed) ? parsed : null;
  };
  const equals = raw.indexOf('=');
  return {
    label: match[1],
    components,
    keyId: params.keyid ?? '',
    tag: (params.tag ?? '').toLowerCase(),
    created: asNumber(params.created),
    expires: asNumber(params.expires),
    rawParams: equals >= 0 ? raw.slice(equals + 1).trim() : '',
  };
}

/** Returns the lower-cased signer host from a quoted `Signature-Agent` URL. */
export function parseSignatureAgentHost(raw: string): string | null {
  let value = (raw ?? '').trim();
  while (value.startsWith('<') && value.endsWith('>')) value = value.slice(1, -1).trim();
  if (!value.startsWith('"') || !value.endsWith('"') || value.length < 3) return null;
  const url = value.slice(1, -1);
  if (!/^https:\/\//i.test(url)) return null;
  try {
    return new URL(url).hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64ToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(`${normalized}${'='.repeat((4 - (normalized.length % 4)) % 4)}`);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer as ArrayBuffer;
}

function componentValue(
  name: string,
  request: WebBotAuthRequest,
  headers: WebBotAuthHeaderBag
): string | null {
  const scheme = (request.scheme || 'https').toLowerCase();
  const authority = request.authority.trim();
  switch (name) {
    case '@authority':
      return authority;
    case '@scheme':
      return scheme;
    case '@method':
      return (request.method || 'GET').toUpperCase();
    case '@target-uri':
      return `${scheme}://${authority}${request.pathWithQuery || '/'}`;
    case '@request-target':
      return request.pathWithQuery || '/';
    case '@path':
      return (request.pathWithQuery || '/').split('?')[0];
    case '@query': {
      const index = (request.pathWithQuery || '').indexOf('?');
      return index >= 0 ? request.pathWithQuery.slice(index) : '?';
    }
    default: {
      const value = readHeader(headers, name);
      return value ? value.replace(/\s+/g, ' ').trim() : null;
    }
  }
}

function signatureBase(
  components: string[],
  request: WebBotAuthRequest,
  headers: WebBotAuthHeaderBag,
  rawParams: string
): string | null {
  const lines: string[] = [];
  for (const component of components) {
    const value = componentValue(component, request, headers);
    if (value === null) return null;
    lines.push(`"${component}": ${value}\n`);
  }
  // RFC 9421 §2.5: the signature base always ends with the `@signature-params`
  // line. Omitting it made every genuine Web Bot Auth signature fail verification.
  if (!rawParams) return null;
  lines.push(`"@signature-params": ${rawParams}\n`);
  return lines.join('');
}

function collectEd25519Keys(node: unknown, depth: number, output: Jwk[]): void {
  if (depth > 8 || node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) collectEd25519Keys(item, depth + 1, output);
    return;
  }
  const record = node as Record<string, unknown>;
  if (
    String(record.kty).toUpperCase() === 'OKP' &&
    String(record.crv ?? 'Ed25519').toLowerCase() === 'ed25519' &&
    typeof record.x === 'string'
  ) {
    output.push({ ...record, kty: 'OKP', crv: 'Ed25519', x: record.x } as Jwk);
  }
  for (const value of Object.values(record)) collectEd25519Keys(value, depth + 1, output);
}

export class WebBotAuthVerifier {
  /** RFC 7638 thumbprint over the three required Ed25519 JWK members. */
  static async computeEd25519JwkThumbprint(jwk: Pick<Jwk, 'kty' | 'crv' | 'x'>): Promise<string> {
    const canonical = JSON.stringify({
      crv: jwk.crv ?? 'Ed25519',
      kty: jwk.kty ?? 'OKP',
      x: jwk.x ?? '',
    });
    const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
    return bytesToBase64Url(new Uint8Array(digest));
  }

  constructor(private readonly db: AIBotDatabase) {}

  private getCachedKeys(host: string, keyId: string): Jwk[] {
    const rows = keyId
      ? (this.db
          .prepare('SELECT jwk FROM ai_bot_jwk_cache WHERE host = ? AND kid = ?')
          .all(host, keyId) as Array<Record<string, any>>)
      : (this.db.prepare('SELECT jwk FROM ai_bot_jwk_cache WHERE host = ?').all(host) as Array<Record<string, any>>);
    const keys: Jwk[] = [];
    for (const row of rows) {
      try {
        keys.push(JSON.parse(String(row.jwk)) as Jwk);
      } catch {
        // Skip corrupt cache rows.
      }
    }
    return keys;
  }

  /** Fetches and caches every Ed25519 key published by a signer's directory. */
  async refreshDirectoryKeys(host: string): Promise<number> {
    const normalizedHost = host.toLowerCase().replace(/:\d+$/, '');
    const directoryUrl =
      WEB_BOT_AUTH_SIGNER_MAP[normalizedHost]?.directoryUrl ??
      `https://${normalizedHost}/.well-known/http-message-signatures-directory`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DIRECTORY_TIMEOUT_MS);
    try {
      const response = await fetch(directoryUrl, {
        signal: controller.signal,
        headers: { accept: 'application/json', 'user-agent': 'IntelSystem-AI-Bot-Protection/1.0' },
      });
      if (!response.ok) return 0;
      const payload = (await response.json()) as unknown;
      const keys: Jwk[] = [];
      collectEd25519Keys(payload, 0, keys);
      if (!keys.length) return 0;
      const upsert = this.db.prepare(
        `INSERT INTO ai_bot_jwk_cache (thumbprint, host, kid, jwk, algorithm, observed_at_utc)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(thumbprint) DO UPDATE SET
           host = excluded.host,
           kid = excluded.kid,
           jwk = excluded.jwk,
           algorithm = excluded.algorithm,
           observed_at_utc = excluded.observed_at_utc`
      );
      const thumbprints = await Promise.all(
        keys.map((jwk) => WebBotAuthVerifier.computeEd25519JwkThumbprint(jwk))
      );
      const now = new Date().toISOString();
      runTransaction(this.db, () => {
        keys.forEach((jwk, index) => {
          upsert.run(
            thumbprints[index],
            normalizedHost,
            jwk.kid ?? null,
            JSON.stringify(jwk),
            jwk.alg ?? 'Ed25519',
            now
          );
        });
      });
      return keys.length;
    } catch {
      return 0;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Refreshes all directories declared in the signer registry. */
  async refreshAllDirectories(): Promise<number> {
    let total = 0;
    await Promise.all(
      Object.keys(WEB_BOT_AUTH_SIGNER_MAP).map(async (host) => {
        total += await this.refreshDirectoryKeys(host).catch(() => 0);
      })
    );
    return total;
  }

  /** Verifies a request; the returned result shape is stable for analytics and edge decisions. */
  async verifyRequest(request: WebBotAuthRequest): Promise<WebBotAuthResult> {
    const signatureInput = readHeader(request.headers, 'signature-input');
    const signature = readHeader(request.headers, 'signature');
    const signatureAgent = readHeader(request.headers, 'signature-agent');
    const present = Boolean(signatureInput && signature && signatureAgent);
    if (!present) return { present: false, verified: false, reason: 'none' };

    const signerHost = parseSignatureAgentHost(signatureAgent);
    if (!signerHost) {
      return {
        present,
        verified: false,
        reason: 'signer.web-bot-auth.declared',
        errorDetail: 'Signature-Agent must be a double-quoted https:// URL',
      };
    }

    const parsed = parseSignatureInput(signatureInput);
    if (!parsed) {
      return {
        present,
        verified: false,
        signerHost,
        reason: 'signer.web-bot-auth.declared',
        errorDetail: 'Malformed Signature-Input header',
      };
    }
    if (parsed.tag !== 'web-bot-auth') {
      return {
        present,
        verified: false,
        signerHost,
        keyId: parsed.keyId || undefined,
        reason: 'signer.web-bot-auth.declared',
        errorDetail: `Signature tag must be "web-bot-auth" (received "${parsed.tag || 'none'}")`,
      };
    }
    const hasAuthority = parsed.components.includes('@authority') || parsed.components.includes('@target-uri');
    const hasSigner = parsed.components.includes('signature-agent');
    if (!hasAuthority || !hasSigner) {
      return {
        present,
        verified: false,
        signerHost,
        keyId: parsed.keyId || undefined,
        reason: 'signer.web-bot-auth.declared',
        errorDetail: 'Signature must cover @authority (or @target-uri) and signature-agent',
      };
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    if (parsed.created !== null && parsed.created > nowSeconds + CLOCK_SKEW_SECONDS) {
      return {
        present,
        verified: false,
        signerHost,
        keyId: parsed.keyId || undefined,
        reason: 'signer.web-bot-auth.declared',
        errorDetail: 'Signature created timestamp is in the future',
      };
    }
    if (parsed.expires !== null && parsed.expires < nowSeconds - CLOCK_SKEW_SECONDS) {
      return {
        present,
        verified: false,
        signerHost,
        keyId: parsed.keyId || undefined,
        reason: 'signer.web-bot-auth.declared',
        errorDetail: 'Signature has expired',
      };
    }
    if (parsed.created !== null && parsed.expires !== null && parsed.created > parsed.expires) {
      return {
        present,
        verified: false,
        signerHost,
        keyId: parsed.keyId || undefined,
        reason: 'signer.web-bot-auth.declared',
        errorDetail: 'Signature created timestamp is after expires',
      };
    }

    const signatureMatch = new RegExp(`(?:^|,)\\s*${parsed.label}\\s*=\\s*:([A-Za-z0-9+/=_-]+):`).exec(signature);
    if (!signatureMatch) {
      return {
        present,
        verified: false,
        signerHost,
        keyId: parsed.keyId || undefined,
        reason: 'signer.web-bot-auth.declared',
        errorDetail: 'Signature header is not a labelled RFC 9421 byte-sequence value',
      };
    }

    const base = signatureBase(parsed.components, request, request.headers, parsed.rawParams);
    if (!base) {
      return {
        present,
        verified: false,
        signerHost,
        keyId: parsed.keyId || undefined,
        reason: 'signer.web-bot-auth.declared',
        errorDetail: 'A covered component could not be reconstructed',
      };
    }

    let keys = this.getCachedKeys(signerHost, parsed.keyId);
    if (!keys.length) {
      await this.refreshDirectoryKeys(signerHost);
      keys = this.getCachedKeys(signerHost, parsed.keyId);
    }
    if (!keys.length) {
      return {
        present,
        verified: false,
        signerHost,
        keyId: parsed.keyId || undefined,
        reason: 'signer.web-bot-auth.declared',
        errorDetail: 'No verification key is available for the declared signer',
      };
    }

    const signatureBytes = base64ToBytes(signatureMatch[1]);
    const dataBytes = new TextEncoder().encode(base);
    let verified = false;
    for (const jwk of keys) {
      if (!jwk.x) continue;
      try {
        const key = await globalThis.crypto.subtle.importKey(
          'jwk',
          { kty: 'OKP', crv: 'Ed25519', x: jwk.x } as JsonWebKey,
          { name: 'Ed25519' },
          false,
          ['verify']
        );
        if (
          await globalThis.crypto.subtle.verify(
            'Ed25519',
            key,
            toArrayBuffer(signatureBytes),
            toArrayBuffer(dataBytes)
          )
        ) {
          verified = true;
          break;
        }
      } catch {
        // Try the next published key.
      }
    }

    if (!verified) {
      return {
        present,
        verified: false,
        signerHost,
        keyId: parsed.keyId || undefined,
        reason: 'signer.web-bot-auth.declared',
        errorDetail: 'Signature did not verify against any published key',
      };
    }

    const signer = WEB_BOT_AUTH_SIGNER_MAP[signerHost];
    return {
      present: true,
      verified: true,
      ...(signer ? { botId: signer.botId, operator: signer.operator } : {}),
      signerHost,
      keyId: parsed.keyId || undefined,
      reason: 'signer.web-bot-auth.verified',
    };
  }
}

/**
 * IP-prefix synchronisation and network-based bot verification.
 *
 * Ranges come from three sources, in descending order of trust:
 *   1. Web Bot Auth signatures (handled in web-bot-auth.ts)
 *   2. Published operator feeds (JSON / Amazon HTML / SAIL TOML) and static operator subnets
 *   3. Forward-confirmed reverse DNS (FCrDNS) and soft PTR records
 */

import dns from 'node:dns/promises';
import {
  BOT_MAP_BY_ID,
  BOT_REGISTRY,
  BYTESPIDER_STATIC_SUBNETS,
  type BotDefinition,
  type BotFeedFormat,
} from './registry.js';
import type { AIBotDatabase } from './schema.js';

export interface ParsedCidr {
  cidr: string;
  version: 4 | 6;
  bits: number;
  network: bigint;
  mask: bigint;
  networkHex: string;
  maskHex: string;
}

export interface MemoryRange {
  botId: string;
  network: bigint;
  mask: bigint;
  bits: number;
  version: 4 | 6;
  cidr: string;
  source: string;
}

export interface IpMatchResult {
  matched: boolean;
  botId?: string;
  operator?: string;
  cidr?: string;
  verificationMethod?: string;
  /** True when the IP belongs to a different bot than the one claimed in the User-Agent. */
  spoofed?: boolean;
}

export interface DnsCacheEntry {
  ip: string;
  hostname: string | null;
  forwardIp: string | null;
  verificationMethod: string | null;
  botId: string | null;
  source: string | null;
  observedAtUtc: string;
  expiresAtUtc: string;
}

const FEED_TIMEOUT_MS = 8000;
const DNS_TIMEOUT_MS = 1500;
const DNS_TTL_MS = 6 * 60 * 60 * 1000;

function isIpv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number.parseInt(part, 10) <= 255);
}

function expandIpv6(value: string): string[] | null {
  let normalized = value.trim().replace(/%.*$/, '').toLowerCase();
  if (normalized.includes('.')) {
    const lastColon = normalized.lastIndexOf(':');
    if (lastColon < 0) return null;
    const tail = normalized.slice(lastColon + 1);
    if (!isIpv4(tail)) return null;
    const [a, b, c, d] = tail.split('.').map((octet) => Number.parseInt(octet, 10));
    normalized = `${normalized.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = normalized.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  let hextets: string[];
  if (halves.length === 2) {
    const zeros = 8 - head.length - tail.length;
    if (zeros < 0) return null;
    hextets = [...head, ...new Array<string>(zeros).fill('0'), ...tail];
  } else {
    hextets = head;
  }
  if (hextets.length !== 8 || !hextets.every((part) => /^[0-9a-f]{1,4}$/.test(part))) return null;
  return hextets.map((part) => part.replace(/^0+(?=.)/, ''));
}

function bigIntToIp(value: bigint, version: 4 | 6): string {
  if (version === 4) {
    const octets: number[] = [];
    for (let shift = 24; shift >= 0; shift -= 8) octets.push(Number((value >> BigInt(shift)) & 0xffn));
    return octets.join('.');
  }
  const hextets: string[] = [];
  for (let shift = 112; shift >= 0; shift -= 16) {
    hextets.push(((value >> BigInt(shift)) & 0xffffn).toString(16));
  }
  return hextets.join(':');
}

function countMaskBits(mask: bigint, width: number): number {
  let value = mask;
  let bits = 0;
  for (let i = 0; i < width; i += 1) {
    if ((value & 1n) === 0n) break;
    bits += 1;
    value >>= 1n;
  }
  return bits;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

export class IpVerificationEngine {
  private readonly ranges: MemoryRange[] = [];

  constructor(private readonly db: AIBotDatabase) {}

  /** Converts an IPv4 or IPv6 literal into a 32/128-bit unsigned integer. */
  static ipToBigInt(ip: string): bigint | null {
    if (typeof ip !== 'string') return null;
    const value = ip.trim().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
    if (!value) return null;
    if (value.includes(':')) {
      const hextets = expandIpv6(value);
      if (!hextets) return null;
      let result = 0n;
      for (const hextet of hextets) result = (result << 16n) | BigInt(`0x${hextet}`);
      return result;
    }
    if (!isIpv4(value)) return null;
    let result = 0n;
    for (const octet of value.split('.')) result = (result << 8n) | BigInt(Number.parseInt(octet, 10));
    return result;
  }

  /** Parses `192.0.2.0/24`, `2001:db8::/32` or a bare IPv4 literal (treated as /32). */
  static parseCidrBlock(block: string): ParsedCidr | null {
    if (typeof block !== 'string') return null;
    const trimmed = block.trim();
    if (!trimmed) return null;
    const slash = trimmed.lastIndexOf('/');
    const base = slash >= 0 ? trimmed.slice(0, slash).trim() : trimmed;
    const version: 4 | 6 = base.includes(':') ? 6 : 4;
    const width = version === 4 ? 32 : 128;
    let bits = slash >= 0 ? Number.parseInt(trimmed.slice(slash + 1), 10) : width;
    if (!Number.isInteger(bits) || bits < 0 || bits > width) return null;
    const address = IpVerificationEngine.ipToBigInt(base);
    if (address === null) return null;
    const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(width - bits);
    const network = address & mask;
    const networkHex = network.toString(16).padStart(width / 4, '0');
    const maskHex = mask.toString(16).padStart(width / 4, '0');
    return {
      cidr: `${bigIntToIp(network, version)}/${bits}`,
      version,
      bits,
      network,
      mask,
      networkHex,
      maskHex,
    };
  }

  /** Inserts the ten documented Bytespider /24 prefixes (idempotent). */
  seedStaticSubnets(): void {
    const now = new Date().toISOString();
    const insert = this.db.prepare(
      `INSERT OR IGNORE INTO ai_bot_cidr_ranges (bot_id, network, mask, cidr, source, created_at_utc)
       VALUES (?, ?, ?, ?, 'static', ?)`
    );
    const run = this.db.transaction(() => {
      for (const subnet of BYTESPIDER_STATIC_SUBNETS) {
        const parsed = IpVerificationEngine.parseCidrBlock(subnet);
        if (!parsed) continue;
        insert.run('bytespider', parsed.networkHex, parsed.maskHex, parsed.cidr, now);
      }
    });
    run();
    this.reloadMemoryRanges();
  }

  /** Reloads all persisted prefixes into the synchronous in-memory matcher. */
  reloadMemoryRanges(): void {
    const rows = this.db
      .prepare('SELECT bot_id, network, mask, cidr, source FROM ai_bot_cidr_ranges')
      .all() as Array<Record<string, any>>;
    const next: MemoryRange[] = [];
    for (const row of rows) {
      try {
        const network = BigInt(`0x${String(row.network)}`);
        const mask = BigInt(`0x${String(row.mask)}`);
        const version: 4 | 6 = String(row.network).replace(/^0x/, '').length <= 8 ? 4 : 6;
        next.push({
          botId: String(row.bot_id),
          network,
          mask,
          bits: countMaskBits(mask, version === 4 ? 32 : 128),
          version,
          cidr: String(row.cidr),
          source: String(row.source ?? 'feed'),
        });
      } catch {
        // A malformed persisted row is simply ignored.
      }
    }
    this.ranges.splice(0, this.ranges.length, ...next);
  }

  /** Synchronous, hot-path CIDR lookup used by the request middleware. */
  matchIpInMemory(clientIp: string, claimedBotId?: string | null): IpMatchResult {
    const address = IpVerificationEngine.ipToBigInt(clientIp);
    if (address === null) return { matched: false };

    const candidates: Array<{ address: bigint; version: 4 | 6 }> = [{ address, version: clientIp.includes(':') ? 6 : 4 }];
    // IPv4-mapped IPv6 addresses also match the operator's IPv4 ranges.
    if (candidates[0].version === 6 && (address >> 32n) === 0xffffn) {
      candidates.push({ address: address & 0xffffffffn, version: 4 });
    }

    let claimedMatch: MemoryRange | null = null;
    let anyMatch: MemoryRange | null = null;
    for (const range of this.ranges) {
      for (const candidate of candidates) {
        if (range.version !== candidate.version) continue;
        if ((candidate.address & range.mask) !== range.network) continue;
        anyMatch = range;
        if (claimedBotId && range.botId === claimedBotId) claimedMatch = range;
        break;
      }
      if (claimedMatch) break;
    }

    const chosen = claimedMatch ?? anyMatch;
    if (!chosen) return { matched: false };
    const spoofed = Boolean(claimedBotId && chosen.botId !== claimedBotId);
    const bot: BotDefinition | undefined = BOT_MAP_BY_ID[chosen.botId];
    return {
      matched: true,
      botId: chosen.botId,
      operator: bot?.operator,
      cidr: chosen.cidr,
      verificationMethod: chosen.source === 'static' ? 'static_cidr' : 'cidr',
      spoofed,
    };
  }

  /** Extracts normalised CIDR strings from an operator's published feed payload. */
  static extractCidrsFromPayload(payload: unknown, format: BotFeedFormat): string[] {
    const found = new Set<string>();
    const add = (value: unknown): void => {
      if (typeof value !== 'string') return;
      const candidate = value.trim().replace(/^["'\s]+|["'\s]+$/g, '');
      if (!candidate) return;
      const parsed = IpVerificationEngine.parseCidrBlock(candidate);
      if (parsed) found.add(parsed.cidr);
    };

    if (format === 'json') {
      let parsed: unknown = payload;
      if (typeof payload === 'string') {
        try {
          parsed = JSON.parse(payload) as unknown;
        } catch {
          return [];
        }
      }
      const interestingKeys = new Set([
        'ipv4prefix',
        'ip_prefix',
        'ipv6prefix',
        'cidr',
        'prefix',
        'ipv4',
        'ipv6',
        'network',
      ]);
      const visit = (node: unknown, depth: number): void => {
        if (depth > 12 || node === null || node === undefined) return;
        if (Array.isArray(node)) {
          for (const item of node) visit(item, depth + 1);
          return;
        }
        if (typeof node === 'object') {
          for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
            if (interestingKeys.has(key.toLowerCase())) {
              if (Array.isArray(value)) value.forEach(add);
              else add(value);
            }
            visit(value, depth + 1);
          }
          return;
        }
        add(node);
      };
      visit(parsed, 0);
    } else if (format === 'amazon_html') {
      const text = decodeEntities(typeof payload === 'string' ? payload : String(payload ?? ''));
      let match: RegExpExecArray | null;
      const codeRegex = /<code\b[^>]*>([\s\S]*?)<\/code>/gi;
      while ((match = codeRegex.exec(text)) !== null) {
        const cleaned = decodeEntities(match[1].replace(/<[^>]+>/g, ' '));
        for (const line of cleaned.split(/[\r\n,;\s]+/)) add(line);
      }
      const loose = /(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?|(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\/\d{1,3}/gi;
      const looseMatches = text.match(loose);
      if (looseMatches) for (const item of looseMatches) add(item);
    } else {
      const text = typeof payload === 'string' ? payload : String(payload ?? '');
      for (const rawLine of text.split(/[\r\n]+/)) {
        const line = rawLine.replace(/#.*$/, '').trim();
        if (!line) continue;
        for (const token of line.match(/(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?|(?:[0-9a-f:]+:\d+)(?:\/\d{1,3})?/gi) ?? []) {
          add(token.replace(/["',\[\]]/g, ''));
        }
      }
    }

    return [...found];
  }

  /** Fetches every published feed in the registry and replaces the cached prefixes. */
  async syncAllOfficialFeeds(): Promise<{ updatedBots: number; totalPrefixes: number }> {
    const urlCache = new Map<string, string[]>();
    const fetchFeed = async (url: string, format: BotFeedFormat): Promise<string[]> => {
      const key = `${format}:${url}`;
      const cached = urlCache.get(key);
      if (cached) return cached;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FEED_TIMEOUT_MS);
      try {
        const response = await fetch(url, {
          signal: controller.signal,
          headers: { 'user-agent': 'IntelSystem-AI-Bot-Protection/1.0 (+feed-sync)' },
        });
        if (!response.ok) return [];
        const body = await response.text();
        let payload: unknown = body;
        if (format === 'json') {
          try {
            payload = JSON.parse(body) as unknown;
          } catch {
            return [];
          }
        }
        const cidrs = IpVerificationEngine.extractCidrsFromPayload(payload, format);
        urlCache.set(key, cidrs);
        return cidrs;
      } catch {
        return [];
      } finally {
        clearTimeout(timer);
      }
    };

    const deleteFeedRanges = this.db.prepare("DELETE FROM ai_bot_cidr_ranges WHERE bot_id = ? AND source = 'feed'");
    const insertRange = this.db.prepare(
      `INSERT OR IGNORE INTO ai_bot_cidr_ranges (bot_id, network, mask, cidr, source, created_at_utc)
       VALUES (?, ?, ?, ?, 'feed', ?)`
    );

    let updatedBots = 0;
    let totalPrefixes = 0;
    const sync = async (): Promise<void> => {
      for (const bot of BOT_REGISTRY) {
        if (!bot.feedUrls.length) continue;
        const cidrs: string[] = [];
        for (const feed of bot.feedUrls) {
          cidrs.push(...(await fetchFeed(feed.url, feed.format)));
        }
        const unique = [...new Set(cidrs)].slice(0, 5000);
        deleteFeedRanges.run(bot.id);
        const now = new Date().toISOString();
        for (const cidr of unique) {
          const parsed = IpVerificationEngine.parseCidrBlock(cidr);
          if (!parsed) continue;
          insertRange.run(bot.id, parsed.networkHex, parsed.maskHex, parsed.cidr, now);
          totalPrefixes += 1;
        }
        if (unique.length > 0) updatedBots += 1;
      }
    };
    await sync();
    this.reloadMemoryRanges();
    return { updatedBots, totalPrefixes };
  }

  /** Reads a cached FCrDNS decision, if any. */
  lookupDnsCache(ip: string): DnsCacheEntry | null {
    const row = this.db.prepare('SELECT * FROM ai_bot_dns_cache WHERE ip = ?').get(ip) as Record<string, any> | undefined;
    if (!row) return null;
    return {
      ip: String(row.ip),
      hostname: row.hostname ? String(row.hostname) : null,
      forwardIp: row.forward_ip ? String(row.forward_ip) : null,
      verificationMethod: row.verification_method ? String(row.verification_method) : null,
      botId: row.bot_id ? String(row.bot_id) : null,
      source: row.source ? String(row.source) : null,
      observedAtUtc: String(row.observed_at_utc),
      expiresAtUtc: String(row.expires_at_utc),
    };
  }

  /** Queues an IP for a background reverse/forward DNS check without blocking the request. */
  scheduleDnsLookup(ip: string): void {
    if (!IpVerificationEngine.ipToBigInt(ip)) return;
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT OR IGNORE INTO ai_bot_dns_cache
          (ip, hostname, forward_ip, verification_method, bot_id, source, observed_at_utc, expires_at_utc)
         VALUES (?, NULL, NULL, NULL, NULL, 'pending', ?, ?)`
      )
      .run(ip, now, now);
  }

  saveDnsCache(entry: DnsCacheEntry): void {
    this.db
      .prepare(
        `INSERT INTO ai_bot_dns_cache
          (ip, hostname, forward_ip, verification_method, bot_id, source, observed_at_utc, expires_at_utc)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(ip) DO UPDATE SET
           hostname = excluded.hostname,
           forward_ip = excluded.forward_ip,
           verification_method = excluded.verification_method,
           bot_id = excluded.bot_id,
           source = excluded.source,
           observed_at_utc = excluded.observed_at_utc,
           expires_at_utc = excluded.expires_at_utc`
      )
      .run(
        entry.ip,
        entry.hostname,
        entry.forwardIp,
        entry.verificationMethod,
        entry.botId,
        entry.source,
        entry.observedAtUtc,
        entry.expiresAtUtc
      );
  }

  /** Processes expired/pending DNS cache rows. Intended to be fired in the background. */
  async checkCachedDns(): Promise<void> {
    const now = new Date().toISOString();
    const rows = this.db
      .prepare(
        `SELECT ip, source FROM ai_bot_dns_cache
         WHERE expires_at_utc <= ? OR source = 'pending'
         ORDER BY observed_at_utc ASC LIMIT 40`
      )
      .all(now) as Array<Record<string, any>>;

    for (const row of rows) {
      await this.resolveSingleIp(String(row.ip)).catch(() => undefined);
    }
  }

  private async resolveSingleIp(ip: string): Promise<void> {
    const now = new Date();
    const nowIso = now.toISOString();
    const expiresAtUtc = new Date(now.getTime() + DNS_TTL_MS).toISOString();
    const base: DnsCacheEntry = {
      ip,
      hostname: null,
      forwardIp: null,
      verificationMethod: null,
      botId: null,
      source: 'dns',
      observedAtUtc: nowIso,
      expiresAtUtc,
    };

    let hostname: string | null = null;
    try {
      const names = await withTimeout(dns.reverse(ip), DNS_TIMEOUT_MS);
      hostname = names.find((name) => name.trim().endsWith('.'))?.replace(/\.$/, '').toLowerCase() ?? null;
    } catch {
      hostname = null;
    }
    if (!hostname) {
      // Negative results expire quickly so a transient failure does not pin the IP forever.
      base.expiresAtUtc = new Date(now.getTime() + 60_000).toISOString();
      this.saveDnsCache(base);
      return;
    }

    for (const bot of BOT_REGISTRY) {
      for (const suffix of bot.softPtrSuffixes ?? []) {
        if (hostname.endsWith(suffix.toLowerCase())) {
          this.saveDnsCache({
            ...base,
            hostname,
            verificationMethod: 'soft_ptr',
            botId: bot.id,
            source: 'dns_soft_ptr',
          });
          return;
        }
      }
    }

    for (const bot of BOT_REGISTRY) {
      const suffix = (bot.fcrdnsSuffixes ?? []).find((item) => hostname!.endsWith(item.toLowerCase()));
      if (!suffix) continue;
      try {
        const addresses = await withTimeout(dns.resolve4(hostname), DNS_TIMEOUT_MS);
        if (addresses.includes(ip)) {
          this.saveDnsCache({
            ...base,
            hostname,
            forwardIp: ip,
            verificationMethod: 'fcrdns',
            botId: bot.id,
            source: 'dns_fcrdns',
          });
          return;
        }
      } catch {
        // A PTR without a matching A record is not FCrDNS; keep trying other bot definitions.
      }
    }

    base.hostname = hostname;
    base.verificationMethod = 'ptr_unverified';
    base.expiresAtUtc = new Date(now.getTime() + 60_000).toISOString();
    this.saveDnsCache(base);
  }
}

function decodeEntities(text: string): string {
  return text
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;/gi, "'")
    .replace(/&#x0*27;/gi, "'")
    .replace(/&#(\d+);/g, (_match, decimal: string) => String.fromCharCode(Number.parseInt(decimal, 10)))
    .replace(/&#x([0-9a-f]+);/gi, (_match, hex: string) => String.fromCodePoint(Number.parseInt(hex, 16)));
}

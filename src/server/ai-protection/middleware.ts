/**
 * Request middleware and analytics API for the AI bot protection engine.
 *
 * Worker-safe: only Express types/values and Web APIs are used; all persistence flows through
 * the injected Durable-Object SQLite adapter.
 */

import express, { type NextFunction, type Request, type Response } from 'express';
import {
  BOT_MAP_BY_ID,
  OPERATOR_REFERRER_DOMAINS,
  matchUserAgentBot,
  type BotDefinition,
} from './registry.js';
import { initAIBotSchema, type AIBotDatabase } from './schema.js';
import { IpVerificationEngine } from './ip-sync.js';
import { WebBotAuthVerifier } from './web-bot-auth.js';
import { BotPreferenceSyncEngine, type AccessEvaluation, type ZoneConfig } from './bot-preference-sync.js';
import { applyMarkdownResponseHeaders, convertHtmlToAgentMarkdown } from './markdown-for-agents.js';

export interface AIProtectionSystem {
  middleware: (req: Request, res: Response, next: NextFunction) => Promise<void>;
  apiRouter: express.Router;
  ipEngine: IpVerificationEngine;
  webBotAuth: WebBotAuthVerifier;
  preferenceSync: BotPreferenceSyncEngine;
}

type VerificationStatus = 'verified' | 'declared' | 'spoofed' | 'unknown' | 'client_probed';

interface RequestContext {
  bot: BotDefinition | null;
  status: VerificationStatus;
  method: string;
  reasons: string[];
  evaluation: AccessEvaluation;
  bytesSent: number;
  clientIp: string;
  userAgent: string;
  referrerDomain: string | null;
  referralOperator: string | null;
  signal: string;
}

const ROBOTS_PATHS = new Set(['/robots.txt', '/api/intel/ai-crawl-control/robots.txt']);
const LLMS_PATHS = new Set(['/llms.txt', '/api/intel/ai-crawl-control/llms.txt']);

/** Cloudflare-style URI pattern: two path levels plus a wildcard, root becomes `/*`. */
export function computeCloudflareUriPattern(uri: string): string {
  const clean = String(uri || '/').split('?')[0];
  const segments = clean.split('/').filter(Boolean);
  if (segments.length === 0) return '/*';
  if (segments.length === 1) return `/${segments[0]}`;
  return `/${segments[0]}/${segments[1]}/*`;
}

function utf8Length(text: string): number {
  return new TextEncoder().encode(text).length;
}

function chunkToText(chunk: unknown): string {
  if (typeof chunk === 'string') return chunk;
  if (chunk === null || chunk === undefined) return '';
  if (chunk instanceof Uint8Array) return new TextDecoder().decode(chunk);
  return String(chunk);
}

function extractClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  const first = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  const fromHeader = typeof first === 'string' ? first.split(',')[0].trim() : '';
  if (fromHeader) return fromHeader;
  return String(req.ip || req.socket?.remoteAddress || '');
}

function extractReferrerDomain(req: Request): string | null {
  const raw = req.headers.referer ?? req.headers.referrer;
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function headerValue(req: Request, name: string): string {
  const raw = req.headers[name];
  const value = Array.isArray(raw) ? raw.join(', ') : raw;
  return typeof value === 'string' ? value : '';
}

function verdictFor(ctx: RequestContext): string {
  const label = ctx.bot?.id ?? 'unknown';
  return `${ctx.status}:${label}|${ctx.method}`;
}

function buildLlmsTxt(config: ZoneConfig, signal?: string): string {
  return [
    '# AI crawl control',
    '',
    `> Content-Signal: ${signal ?? `use=${config.contentUseSignal}`}`,
    '',
    'This site publishes machine-readable content and an explicit crawlers policy.',
    '',
    'See /robots.txt for per-bot directives and training opt-outs.',
    '',
  ].join('\n');
}

export function createAIProtectionSystem(db: AIBotDatabase): AIProtectionSystem {
  // Cloudflare Workers inject a request-scoped Durable-Object database, so schema creation
  // must happen inside a request — never at module import time. It is idempotent.
  const ipEngine = new IpVerificationEngine(db);
  const webBotAuth = new WebBotAuthVerifier(db);
  const preferenceSync = new BotPreferenceSyncEngine(db);

  try {
    ipEngine.seedStaticSubnets();
    ipEngine.reloadMemoryRanges();
  } catch {
    // A read-only adapter must not prevent the request middleware from being installed.
  }

  let backgroundStarted = false;
  const startBackgroundOnce = (): void => {
    if (backgroundStarted) return;
    backgroundStarted = true;
    void ipEngine.syncAllOfficialFeeds().catch(() => undefined);
    void webBotAuth.refreshAllDirectories().catch(() => undefined);
    void ipEngine.checkCachedDns().catch(() => undefined);
  };

  const insertRequest = (ctx: RequestContext, reqPath: string, method: string, httpStatus: number): void => {
    try {
      db.prepare(
        `INSERT INTO ai_bot_requests (
           observed_at_utc, bot_id, operator, verification_status, verification_method, client_ip,
           user_agent, request_path, request_method, http_status, bytes_sent, referrer_domain,
           referral_operator, robots_violation, violated_directive, reasons, content_signal, edge_action
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        new Date().toISOString(),
        ctx.bot?.id ?? null,
        ctx.bot?.operator ?? ctx.referralOperator,
        ctx.status,
        ctx.method,
        ctx.clientIp || null,
        ctx.userAgent.slice(0, 1500) || null,
        reqPath.slice(0, 2000),
        method,
        httpStatus,
        ctx.bytesSent,
        ctx.referrerDomain,
        ctx.referralOperator,
        ctx.evaluation.robotsViolation ? 1 : 0,
        ctx.evaluation.violatedDirective ?? null,
        JSON.stringify(ctx.reasons),
        ctx.signal,
        ctx.evaluation.edgeAction
      );
    } catch {
      // Logging must never break a response.
    }
  };

  const middleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      initAIBotSchema(db);
      startBackgroundOnce();
      const reqPath = req.path || '/';
      const config = preferenceSync.getZoneConfig();
      const signal = preferenceSync.buildContentSignalHeader(config);
      if (!res.getHeader('Content-Signal')) res.setHeader('Content-Signal', signal);

      const clientIp = extractClientIp(req);
      const userAgent = headerValue(req, 'user-agent');
      const referrerDomain = extractReferrerDomain(req);
      const referralOperator = referrerDomain ? OPERATOR_REFERRER_DOMAINS[referrerDomain] ?? null : null;
      const claimedBot = matchUserAgentBot(userAgent);

      let bot: BotDefinition | null = claimedBot;
      let status: VerificationStatus = claimedBot ? 'declared' : 'unknown';
      let method = claimedBot ? 'user_agent' : 'none';
      const reasons: string[] = [];
      const isVerified = (): boolean => status === 'verified';

      // 1. Web Bot Auth always wins when a valid signature is present.
      const hasSignatureHeaders = Boolean(
        req.headers['signature-input'] && req.headers['signature'] && req.headers['signature-agent']
      );
      if (hasSignatureHeaders) {
        const authority = String(req.headers.host || 'localhost');
        const result = await webBotAuth.verifyRequest({
          method: req.method,
          authority,
          pathWithQuery: req.originalUrl || req.url || reqPath,
          scheme: req.protocol || 'https',
          headers: req.headers as Record<string, string | string[] | undefined>,
        });
        if (result.verified) {
          const signerBot = (result.botId && BOT_MAP_BY_ID[result.botId]) || null;
          if (signerBot) bot = signerBot;
          status = 'verified';
          method = 'web_bot_auth';
          reasons.push(result.reason);
          if (result.keyId) reasons.push(`keyid=${result.keyId}`);
        } else {
          status = 'spoofed';
          method = 'web_bot_auth';
          reasons.push(result.errorDetail ?? result.reason);
        }
      }

      // 2. Published IP ranges / static operator subnets.
      if (!isVerified()) {
        const match = ipEngine.matchIpInMemory(clientIp, bot?.id);
        if (match.matched) {
          const matchedBot = match.botId ? BOT_MAP_BY_ID[match.botId] ?? null : null;
          if (matchedBot && (!bot || !hasSignatureHeaders)) bot = matchedBot;
          status = match.spoofed ? 'spoofed' : 'verified';
          method = match.verificationMethod ?? 'cidr';
          reasons.push(match.spoofed ? `cidr_mismatch:${match.cidr}` : `cidr:${match.cidr}`);
        }
      }

      // 3. FCrDNS / soft-PTR fallback from the background DNS cache.
      if (!isVerified() && clientIp) {
        const cached = ipEngine.lookupDnsCache(clientIp);
        if (cached?.verificationMethod === 'fcrdns' || cached?.verificationMethod === 'soft_ptr') {
          const dnsBot = cached.botId ? BOT_MAP_BY_ID[cached.botId] ?? null : null;
          if (dnsBot && (!bot || dnsBot.id === bot.id)) bot = dnsBot;
          status = 'verified';
          method = cached.verificationMethod;
          reasons.push(`${cached.verificationMethod}:${cached.hostname ?? 'unknown'}`);
        } else if (!cached) {
          ipEngine.scheduleDnsLookup(clientIp);
          void ipEngine.checkCachedDns().catch(() => undefined);
        }
      }

      if (status === 'declared') reasons.push('user_agent_only');
      if (status === 'spoofed') reasons.push('identity_not_proven');

      const paymentHeaderPresent = Boolean(
        headerValue(req, 'x-payment') || headerValue(req, 'payment') || headerValue(req, 'x-payment-credential')
      );
      const evaluation = preferenceSync.evaluateAccessAndRobotsCompliance(bot, isVerified(), reqPath, paymentHeaderPresent);
      if (evaluation.robotsViolation && evaluation.violatedDirective) reasons.push(evaluation.violatedDirective);

      const ctx: RequestContext = {
        bot,
        status,
        method,
        reasons,
        evaluation,
        bytesSent: 0,
        clientIp,
        userAgent,
        referrerDomain,
        referralOperator,
        signal,
      };

      if (referralOperator && referrerDomain) {
        try {
          db.prepare(
            `INSERT INTO ai_operator_referrals (
               observed_at_utc, bot_id, operator, referrer_domain, referrer_url, request_path, occurrences
             ) VALUES (?, ?, ?, ?, ?, ?, 1)`
          ).run(
            new Date().toISOString(),
            bot?.id ?? null,
            referralOperator,
            referrerDomain,
            String(req.headers.referer ?? '').slice(0, 2000),
            reqPath.slice(0, 2000)
          );
        } catch {
          // Referral logging is best-effort.
        }
      }

      // Document navigations get a Server-Timing verdict without exposing the full decision tree.
      const accept = headerValue(req, 'accept');
      if (/text\/html/i.test(accept) || (!reqPath.startsWith('/api') && req.method === 'GET')) {
        res.setHeader('Server-Timing', `botscent;desc="${verdictFor(ctx).replace(/"/g, "'")}"`);
      }

      // Byte accounting + Markdown-for-Agents response interception.
      const wantsMarkdown =
        config.markdownForAgentsEnabled &&
        /\btext\/markdown\b/i.test(accept) &&
        !reqPath.startsWith('/api') &&
        !ROBOTS_PATHS.has(reqPath) &&
        !LLMS_PATHS.has(reqPath);
      const originalWrite = res.write.bind(res);
      const originalEnd = res.end.bind(res);
      let markdownBuffer = '';
      let finished = false;

      (res as any).write = (chunk: unknown, encoding?: unknown, callback?: unknown): boolean => {
        const text = chunkToText(chunk);
        ctx.bytesSent += utf8Length(text);
        if (wantsMarkdown) {
          markdownBuffer += text;
          if (typeof encoding === 'function') encoding();
          return true;
        }
        if (typeof encoding === 'function') return originalWrite(chunk as any, encoding as any);
        if (typeof callback === 'function') return originalWrite(chunk as any, encoding as any, callback as any);
        return encoding === undefined ? originalWrite(chunk as any) : originalWrite(chunk as any, encoding as any);
      };

      (res as any).end = (chunk?: unknown, encoding?: unknown, callback?: unknown): unknown => {
        if (finished) return res;
        finished = true;
        if (chunk !== null && chunk !== undefined) {
          const text = chunkToText(chunk);
          ctx.bytesSent += utf8Length(text);
          if (wantsMarkdown) markdownBuffer += text;
        }
        if (wantsMarkdown) {
          const converted = convertHtmlToAgentMarkdown(markdownBuffer);
          if (converted.converted) {
            applyMarkdownResponseHeaders(res, signal);
            ctx.bytesSent = converted.byteLength;
            return typeof encoding === 'function'
              ? originalEnd(converted.markdown as any, encoding as any)
              : originalEnd(converted.markdown as any);
          }
        }
        if (typeof encoding === 'function') return originalEnd(chunk as any, encoding as any);
        if (typeof callback === 'function') return originalEnd(chunk as any, encoding as any, callback as any);
        return chunk === undefined ? originalEnd() : originalEnd(chunk as any);
      };

      res.on('finish', () => {
        insertRequest(ctx, reqPath, req.method, res.statusCode);
      });

      // Dynamic robots.txt / llms.txt (also exposed under /api by apiRouter).
      if (ROBOTS_PATHS.has(reqPath)) {
        const robotsTxt = preferenceSync.generateRobotsTxt(config);
        ctx.bytesSent = utf8Length(robotsTxt);
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.status(200).send(robotsTxt);
        return;
      }
      if (LLMS_PATHS.has(reqPath)) {
        const llmsTxt = buildLlmsTxt(config, signal);
        ctx.bytesSent = utf8Length(llmsTxt);
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.status(200).send(llmsTxt);
        return;
      }

      // Policy enforcement.
      if (evaluation.edgeAction === 'block_403') {
        const code = config.blockStatusCode >= 400 && config.blockStatusCode < 600 ? config.blockStatusCode : 403;
        res.status(code).type('text/plain').send(config.blockResponseBody);
        return;
      }
      if (evaluation.edgeAction === 'charge_402') {
        res.status(402).json({
          error: 'payment_required',
          price: config.priceUsd,
          bot: bot?.id ?? null,
          contentSignal: signal,
        });
        return;
      }
      if (evaluation.edgeAction === 'disallow_training') {
        res.setHeader('X-AI-Policy', 'training_disallowed');
      }

      next();
    } catch (error) {
      next(error as Error);
    }
  };

  const apiRouter = express.Router();
  apiRouter.use(express.json({ limit: '256kb' }));
  apiRouter.use((_req, _res, next) => {
    try {
      initAIBotSchema(db);
    } catch {
      // A read-only adapter must never fail the API route before it can answer.
    }
    next();
  });

  apiRouter.get('/robots.txt', (_req, res) => {
    const config = preferenceSync.getZoneConfig();
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Signal', preferenceSync.buildContentSignalHeader(config));
    res.status(200).send(preferenceSync.generateRobotsTxt(config));
  });

  apiRouter.get('/llms.txt', (_req, res) => {
    const config = preferenceSync.getZoneConfig();
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Signal', preferenceSync.buildContentSignalHeader(config));
    res.status(200).send(buildLlmsTxt(config, preferenceSync.buildContentSignalHeader(config)));
  });

  apiRouter.post('/agent-telemetry', (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const reasons = Array.isArray(body.reasons) ? body.reasons.filter((item) => typeof item === 'string') : [];
    if (!reasons.length) {
      res.status(204).end();
      return;
    }
    try {
      db.prepare(
        `INSERT INTO ai_bot_requests (
           observed_at_utc, bot_id, operator, verification_status, verification_method, client_ip,
           user_agent, request_path, request_method, http_status, bytes_sent, robots_violation,
           reasons, content_signal, edge_action
         ) VALUES (?, ?, NULL, 'client_probed', 'client_sdk', ?, ?, ?, 'POST', 204, 0, 0, ?, ?, 'allow')`
      ).run(
        new Date().toISOString(),
        typeof body.botId === 'string' ? body.botId : null,
        extractClientIp(req) || null,
        headerValue(req, 'user-agent').slice(0, 1500) || null,
        typeof body.path === 'string' ? body.path : '/',
        JSON.stringify(reasons),
        preferenceSync.buildContentSignalHeader()
      );
      res.status(202).json({ recorded: true });
    } catch {
      res.status(500).json({ error: 'telemetry_persistence_failed' });
    }
  });

  apiRouter.get('/analytics', (_req, res) => {
    let rows: Array<Record<string, any>> = [];
    let referrals: Array<Record<string, any>> = [];
    try {
      rows = db.prepare('SELECT * FROM ai_bot_requests').all() as Array<Record<string, any>>;
      referrals = db.prepare('SELECT * FROM ai_operator_referrals').all() as Array<Record<string, any>>;
    } catch {
      rows = [];
      referrals = [];
    }

    const number = (value: unknown): number => {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : 0;
    };
    const byBot = new Map<string, { botId: string; displayName: string; operator: string; requests: number; bytes: number }>();
    const byOperator = new Map<string, { operator: string; requests: number; bytes: number }>();
    const byStatus: Record<string, number> = {};
    const byPattern = new Map<string, number>();
    const violations: Array<Record<string, unknown>> = [];
    let bytes = 0;
    let verified = 0;
    const since = Date.now() - 24 * 60 * 60 * 1000;
    let last24h = 0;

    for (const row of rows) {
      const botId = row.bot_id ? String(row.bot_id) : 'unknown';
      const operator = row.operator ? String(row.operator) : 'Unknown';
      const rowBytes = number(row.bytes_sent);
      bytes += rowBytes;
      if (row.verification_status === 'verified') verified += 1;
      if (Date.parse(String(row.observed_at_utc)) >= since) last24h += 1;

      const botEntry = byBot.get(botId) ?? {
        botId,
        displayName: BOT_MAP_BY_ID[botId]?.displayName ?? botId,
        operator,
        requests: 0,
        bytes: 0,
      };
      botEntry.requests += 1;
      botEntry.bytes += rowBytes;
      byBot.set(botId, botEntry);

      const operatorEntry = byOperator.get(operator) ?? { operator, requests: 0, bytes: 0 };
      operatorEntry.requests += 1;
      operatorEntry.bytes += rowBytes;
      byOperator.set(operator, operatorEntry);

      const status = String(row.verification_status ?? 'unknown');
      byStatus[status] = (byStatus[status] ?? 0) + 1;
      const pattern = computeCloudflareUriPattern(String(row.request_path ?? '/'));
      byPattern.set(pattern, (byPattern.get(pattern) ?? 0) + 1);
      if (number(row.robots_violation) > 0) {
        violations.push({
          botId,
          operator,
          path: row.request_path,
          directive: row.violated_directive,
          status,
          observedAt: row.observed_at_utc,
        });
      }
    }

    const config = preferenceSync.getZoneConfig();
    const isAllowed = (row: Record<string, any>): boolean => {
      const status = Number(row.http_status);
      return status >= 200 && status < 400;
    };
    const rowsForBot = (botId: string): Array<Record<string, any>> =>
      rows.filter((row) => (row.bot_id ? String(row.bot_id) : 'unknown') === botId);
    const lastSeen = (matched: Array<Record<string, any>>): number =>
      matched.reduce((max, row) => Math.max(max, Date.parse(String(row.observed_at_utc)) || 0), 0);

    // The dashboard consumes the Cloudflare-style snake_case contract; keep the original
    // camelCase fields as aliases so existing integrations are unaffected.
    const snakeSummary = {
      total_requests: rows.length,
      allowed_requests: rows.filter(isAllowed).length,
      unsuccessful_requests: rows.filter((row) => !isAllowed(row)).length,
      total_bytes: bytes,
      markdown_served_count: rows.filter((row) =>
        String(row.edge_action ?? '').toLowerCase().includes('markdown')
      ).length,
      robots_violations_count: violations.length,
    };
    const snakeCrawlers = [...byBot.values()]
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 50)
      .map((entry) => {
        const matched = rowsForBot(entry.botId);
        const definition = BOT_MAP_BY_ID[entry.botId];
        return {
          ...entry,
          bot_id: entry.botId,
          bot_display_name: entry.displayName,
          cf_detection_id: definition?.cfDetectionIds?.[0] ?? null,
          legacy_category: definition?.legacyCategory ?? 'Unknown',
          behavior: definition?.behavior ?? 'Unknown',
          operator_label: definition?.operatorLabel ?? 'Unknown',
          verification_status: matched[0]?.verification_status ?? 'unknown',
          verification_method: matched[0]?.verification_method ?? 'none',
          total_requests: entry.requests,
          allowed_requests: matched.filter(isAllowed).length,
          unsuccessful_requests: matched.filter((row) => !isAllowed(row)).length,
          data_transfer_bytes: entry.bytes,
          robots_violations: matched.filter((row) => Number(row.robots_violation) > 0).length,
          last_seen_ms: lastSeen(matched),
        };
      });
    const referralsByOperator = new Map<string, number>();
    for (const referral of referrals) {
      const operator = String(referral.operator ?? 'Unknown');
      referralsByOperator.set(operator, (referralsByOperator.get(operator) ?? 0) + 1);
    }
    const snakeOperators = [...byOperator.values()]
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 25)
      .map((entry) => {
        const matched = rows.filter((row) => (row.operator ? String(row.operator) : 'Unknown') === entry.operator);
        return {
          ...entry,
          total_requests: entry.requests,
          allowed_requests: matched.filter(isAllowed).length,
          unsuccessful_requests: matched.filter((row) => !isAllowed(row)).length,
          data_transfer_bytes: entry.bytes,
          referrals: referralsByOperator.get(entry.operator) ?? 0,
        };
      });
    const statusCodes = rows.map((row) => Number(row.http_status) || 0);
    const snakeStatusDistribution = {
      status_2xx: statusCodes.filter((code) => code >= 200 && code < 300).length,
      status_3xx: statusCodes.filter((code) => code >= 300 && code < 400).length,
      status_4xx: statusCodes.filter((code) => code >= 400 && code < 500).length,
      status_403_blocked: statusCodes.filter((code) => code === 403).length,
      status_402_charged: statusCodes.filter((code) => code === 402).length,
      status_5xx: statusCodes.filter((code) => code >= 500).length,
    };
    const patternStats = new Map<string, { total: number; allowed: number; bytes: number }>();
    for (const row of rows) {
      const pattern = computeCloudflareUriPattern(String(row.request_path ?? '/'));
      const stat = patternStats.get(pattern) ?? { total: 0, allowed: 0, bytes: 0 };
      stat.total += 1;
      if (isAllowed(row)) stat.allowed += 1;
      stat.bytes += number(row.bytes_sent);
      patternStats.set(pattern, stat);
    }
    const snakeUriPatterns = [...patternStats.entries()]
      .map(([pattern, stat]) => ({
        uri_pattern: pattern,
        pattern,
        total_requests: stat.total,
        requests: stat.total,
        allowed_requests: stat.allowed,
        unsuccessful_requests: stat.total - stat.allowed,
        data_transfer_bytes: stat.bytes,
      }))
      .sort((a, b) => b.total_requests - a.total_requests)
      .slice(0, 50);

    res.json({
      summary: {
        ...snakeSummary,
        totalRequests: rows.length,
        verifiedRequests: verified,
        verificationRate: rows.length ? Number((verified / rows.length).toFixed(4)) : 0,
        uniqueBots: byBot.size,
        bytesServed: bytes,
        last24hRequests: last24h,
        referralsRecorded: referrals.length,
      },
      crawlers: snakeCrawlers,
      operators: snakeOperators,
      statusDistribution: { ...snakeStatusDistribution, ...byStatus },
      uriPatterns: snakeUriPatterns,
      violations: violations.slice(0, 100),
      zoneConfig: {
        ...config,
        policy_search: config.searchPolicy,
        policy_agent: config.agentPolicy,
        policy_training: config.trainingPolicy,
        content_signal: preferenceSync.buildContentSignalHeader(config),
      },
      liveRobotsTxt: preferenceSync.generateRobotsTxt(config),
    });
  });

  apiRouter.post('/policy', (req, res) => {
    const body = (req.body ?? {}) as Record<string, any>;
    try {
      if (body.customPolicy && typeof body.customPolicy.botId === 'string') {
        preferenceSync.upsertCustomPolicy(
          body.customPolicy.botId,
          String(body.customPolicy.action ?? 'block'),
          body.customPolicy.note == null ? null : String(body.customPolicy.note)
        );
      }
      const patch: Record<string, unknown> = { ...body };
      delete patch.customPolicy;
      // Accept both the dashboard's short keys and the internal camelCase names.
      const alias = (names: string[]): unknown => {
        for (const name of names) if (patch[name] !== undefined) return patch[name];
        return undefined;
      };
      const search = alias(['search', 'policy_search', 'search_policy']);
      const agent = alias(['agent', 'policy_agent', 'agent_policy']);
      const training = alias(['training', 'policy_training', 'training_policy']);
      if (search !== undefined) patch.searchPolicy = search;
      if (agent !== undefined) patch.agentPolicy = agent;
      if (training !== undefined) patch.trainingPolicy = training;
      const config = preferenceSync.updateZoneConfig(patch as any);
      res.json({ config, robotsTxt: preferenceSync.generateRobotsTxt(config) });
    } catch {
      res.status(500).json({ error: 'policy_update_failed' });
    }
  });

  apiRouter.post('/markdown-playground', (req, res) => {
    const html = (req.body ?? {}).html;
    if (typeof html !== 'string') {
      res.status(400).json({ error: 'html must be a string' });
      return;
    }
    const result = convertHtmlToAgentMarkdown(html);
    const contentSignal = preferenceSync.buildContentSignalHeader();
    res.json({
      ...result,
      content_signal: contentSignal,
      contentSignal,
      contentSignalHeader: contentSignal,
    });
  });

  apiRouter.post('/sync-feeds', async (_req, res) => {
    try {
      const feeds = await ipEngine.syncAllOfficialFeeds();
      const keys = await webBotAuth.refreshAllDirectories();
      ipEngine.reloadMemoryRanges();
      res.json({ ...feeds, refreshedSignerKeys: keys });
    } catch {
      res.status(500).json({ error: 'feed_sync_failed' });
    }
  });

  return { middleware, apiRouter, ipEngine, webBotAuth, preferenceSync };
}

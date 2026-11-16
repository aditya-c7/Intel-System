/**
 * Content-signal negotiation, robots.txt generation and edge policy evaluation.
 *
 * The zone configuration is persisted in `ai_zone_config` (single row, id = 1) so the parent
 * application can expose it through an admin API without redeploying.
 */

import { BOT_REGISTRY, type BotDefinition } from './registry.js';
import type { AIBotDatabase } from './schema.js';

export type ZonePolicy = 'allow' | 'disallow' | 'charge';
export type EdgeAction = 'allow' | 'block_403' | 'charge_402' | 'disallow_training';

export interface ZoneConfig {
  id: number;
  botPreferenceSyncEnabled: boolean;
  markdownForAgentsEnabled: boolean;
  searchPolicy: ZonePolicy;
  agentPolicy: ZonePolicy;
  trainingPolicy: ZonePolicy;
  contentUseSignal: string;
  blockStatusCode: number;
  blockResponseBody: string;
  priceUsd: number;
  customRobotsAppend: string;
  updatedAtUtc: string;
}

export type ZoneConfigPatch = Partial<Omit<ZoneConfig, 'id' | 'updatedAtUtc'>>;

export interface AccessEvaluation {
  edgeAction: EdgeAction;
  robotsViolation: boolean;
  violatedDirective?: string;
}

const DEFAULT_CONFIG: ZoneConfig = {
  id: 1,
  botPreferenceSyncEnabled: true,
  markdownForAgentsEnabled: true,
  searchPolicy: 'allow',
  agentPolicy: 'allow',
  trainingPolicy: 'disallow',
  contentUseSignal: 'reference',
  blockStatusCode: 403,
  blockResponseBody: 'Access denied: automated crawling policy violation.',
  priceUsd: 0.015,
  customRobotsAppend: '',
  updatedAtUtc: '',
};

function asPolicy(value: unknown, fallback: ZonePolicy): ZonePolicy {
  return value === 'allow' || value === 'disallow' || value === 'charge' ? value : fallback;
}

function rowToConfig(row: Record<string, any> | undefined): ZoneConfig {
  if (!row) return { ...DEFAULT_CONFIG };
  return {
    id: 1,
    botPreferenceSyncEnabled: Number(row.bot_preference_sync_enabled ?? 1) !== 0,
    markdownForAgentsEnabled: Number(row.markdown_for_agents_enabled ?? 1) !== 0,
    searchPolicy: asPolicy(row.search_policy, 'allow'),
    agentPolicy: asPolicy(row.agent_policy, 'allow'),
    trainingPolicy: asPolicy(row.training_policy, 'disallow'),
    contentUseSignal: String(row.content_use_signal ?? 'reference'),
    blockStatusCode: Number(row.block_status_code ?? 403),
    blockResponseBody: String(row.block_response_body ?? DEFAULT_CONFIG.blockResponseBody),
    priceUsd: Number(row.price_usd ?? 0.015),
    customRobotsAppend: String(row.custom_robots_append ?? ''),
    updatedAtUtc: String(row.updated_at_utc ?? ''),
  };
}

export function isAlwaysAllowedPath(reqPath: string): boolean {
  const normalized = (reqPath || '/').split('?')[0];
  return (
    normalized === '/robots.txt' ||
    normalized === '/llms.txt' ||
    normalized === '/.well-known' ||
    normalized.startsWith('/.well-known/')
  );
}

export class BotPreferenceSyncEngine {
  private cachedConfig: ZoneConfig | null = null;

  constructor(private readonly db: AIBotDatabase) {}

  getZoneConfig(forceRefresh = false): ZoneConfig {
    if (this.cachedConfig && !forceRefresh) return this.cachedConfig;
    const row = this.db.prepare('SELECT * FROM ai_zone_config WHERE id = 1').get() as Record<string, any> | undefined;
    this.cachedConfig = rowToConfig(row);
    return this.cachedConfig;
  }

  updateZoneConfig(patch: ZoneConfigPatch): ZoneConfig {
    const current = this.getZoneConfig(true);
    const next: ZoneConfig = {
      ...current,
      ...patch,
      id: 1,
      updatedAtUtc: new Date().toISOString(),
    };
    next.searchPolicy = asPolicy(next.searchPolicy, current.searchPolicy);
    next.agentPolicy = asPolicy(next.agentPolicy, current.agentPolicy);
    next.trainingPolicy = asPolicy(next.trainingPolicy, current.trainingPolicy);

    this.db
      .prepare(
        `UPDATE ai_zone_config SET
           bot_preference_sync_enabled = ?, markdown_for_agents_enabled = ?, search_policy = ?,
           agent_policy = ?, training_policy = ?, content_use_signal = ?, block_status_code = ?,
           block_response_body = ?, price_usd = ?, custom_robots_append = ?, updated_at_utc = ?
         WHERE id = 1`
      )
      .run(
        next.botPreferenceSyncEnabled ? 1 : 0,
        next.markdownForAgentsEnabled ? 1 : 0,
        next.searchPolicy,
        next.agentPolicy,
        next.trainingPolicy,
        next.contentUseSignal,
        next.blockStatusCode,
        next.blockResponseBody,
        next.priceUsd,
        next.customRobotsAppend,
        next.updatedAtUtc
      );
    this.cachedConfig = next;
    return next;
  }

  getCustomPolicies(): Array<{ botId: string; action: string; note: string | null }> {
    const rows = this.db.prepare('SELECT bot_id, action, note FROM ai_bot_custom_policies').all() as Array<
      Record<string, any>
    >;
    return rows.map((row) => ({
      botId: String(row.bot_id),
      action: String(row.action),
      note: row.note === null || row.note === undefined ? null : String(row.note),
    }));
  }

  upsertCustomPolicy(botId: string, action: string, note?: string | null): void {
    this.db
      .prepare(
        `INSERT INTO ai_bot_custom_policies (bot_id, action, note, created_at_utc)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(bot_id) DO UPDATE SET action = excluded.action, note = excluded.note`
      )
      .run(botId, action, note ?? null, new Date().toISOString());
  }

  /** `search=..., ai-input=..., ai-train=..., use=reference` as used by Cloudflare's Content-Signal draft. */
  buildContentSignalHeader(config: ZoneConfig = this.getZoneConfig()): string {
    // Content-Signal is a yes/no declaration (Cloudflare convention), not an allow/disallow
    // policy name. `charge` still permits the crawl, so it maps to yes.
    const signal = (policy: ZonePolicy): string =>
      policy === 'allow' || policy === 'charge' ? 'yes' : 'no';
    return [
      `search=${signal(config.searchPolicy)}`,
      `ai-input=${signal(config.agentPolicy)}`,
      `ai-train=${signal(config.trainingPolicy)}`,
      `use=${config.contentUseSignal || 'reference'}`,
    ].join(', ');
  }

  /** Builds a live robots.txt with content signals and per-bot policy groups. */
  generateRobotsTxt(config: ZoneConfig = this.getZoneConfig()): string {
    const lines: string[] = [
      '# Generated by Intel System AI bot protection',
      `# Content-Signal: ${this.buildContentSignalHeader(config)}`,
      `Content-Signal: ${this.buildContentSignalHeader(config)}`,
      '',
      'User-agent: *',
      'Allow: /',
      'Allow: /robots.txt',
      'Allow: /llms.txt',
      'Allow: /.well-known/',
      '',
    ];

    const policyFor = (bot: BotDefinition): ZonePolicy => {
      switch (bot.behavior) {
        case 'Training':
          if (bot.isMixedPurposeAccountable) return 'allow';
          return config.trainingPolicy;
        case 'Agent':
          return config.agentPolicy;
        case 'Search':
          return config.searchPolicy;
        default:
          return 'allow';
      }
    };

    for (const bot of BOT_REGISTRY) {
      const policy = policyFor(bot);
      const tokens = bot.uaTokens.length ? bot.uaTokens : [{ token: bot.displayName }];
      for (const token of tokens) {
        lines.push(`User-agent: ${token.token}`);
        if (policy === 'disallow') {
          lines.push('Disallow: /');
        } else if (policy === 'charge') {
          lines.push('Disallow: /');
          lines.push(`# Monetised access available at $${config.priceUsd.toFixed(3)} per request`);
        } else {
          lines.push('Allow: /');
        }
        lines.push('Allow: /robots.txt');
        lines.push('Allow: /llms.txt');
        lines.push('Allow: /.well-known/');
        lines.push('');
      }
    }

    if (config.trainingPolicy === 'disallow') {
      lines.push('User-agent: Applebot-Extended', 'Disallow: /', '');
      lines.push('User-agent: Google-Extended', 'Disallow: /', '');
    }

    const custom = this.getCustomPolicies();
    for (const policy of custom) {
      lines.push(`User-agent: ${policy.botId}`);
      lines.push(policy.action === 'allow' ? 'Allow: /' : 'Disallow: /');
      if (policy.note) lines.push(`# ${policy.note.replace(/[\r\n]+/g, ' ')}`);
      lines.push('');
    }

    if (config.customRobotsAppend.trim()) {
      lines.push('# Custom site policy', config.customRobotsAppend.trim(), '');
    }

    return `${lines.join('\n').replace(/\n{3,}/g, '\n\n').trim()}\n`;
  }

  /**
   * Decides the edge action for a request and reports whether it conflicts with the live
   * robots.txt. Accountable mixed-purpose crawlers are deliberately exempt from training blocks.
   */
  evaluateAccessAndRobotsCompliance(
    bot: BotDefinition | null,
    isVerified: boolean,
    reqPath: string,
    paymentHeaderPresent: boolean
  ): AccessEvaluation {
    const config = this.getZoneConfig();
    if (isAlwaysAllowedPath(reqPath)) return { edgeAction: 'allow', robotsViolation: false };
    if (!bot) return { edgeAction: 'allow', robotsViolation: false };

    const custom = this.getCustomPolicies().find((policy) => policy.botId === bot.id);
    if (custom) {
      if (custom.action === 'block') {
        return {
          edgeAction: 'block_403',
          robotsViolation: true,
          violatedDirective: `Custom policy: block ${bot.id}`,
        };
      }
      if (custom.action === 'charge' && !paymentHeaderPresent) {
        return {
          edgeAction: 'charge_402',
          robotsViolation: true,
          violatedDirective: `Custom policy: charge ${bot.id}`,
        };
      }
      if (custom.action === 'disallow_training' && !bot.isMixedPurposeAccountable) {
        return {
          edgeAction: 'disallow_training',
          robotsViolation: true,
          violatedDirective: 'Disallow: /',
        };
      }
      if (custom.action === 'allow') return { edgeAction: 'allow', robotsViolation: false };
    }

    // A crawler that claims a Web Bot Auth identity must prove it; otherwise the identity is spoofed.
    if (bot.webBotAuthHosts?.length && !isVerified) {
      return {
        edgeAction: 'block_403',
        robotsViolation: true,
        violatedDirective: 'verification_required (Web Bot Auth)',
      };
    }

    // Operators that publish authoritative IP lists are verifiable by definition. A request
    // claiming one of those identities from an unlisted IP is a spoof, regardless of the
    // configured training/search policy — never let a fake GPTBot through on policy grounds.
    if (!isVerified && bot.feedUrls?.length) {
      return {
        edgeAction: 'block_403',
        robotsViolation: true,
        violatedDirective: `verification_required (published IP ranges for ${bot.id})`,
      };
    }

    const applyPolicy = (policy: ZonePolicy, directive: string): AccessEvaluation => {
      if (policy === 'disallow') return { edgeAction: 'block_403', robotsViolation: true, violatedDirective: directive };
      if (policy === 'charge') {
        return paymentHeaderPresent
          ? { edgeAction: 'allow', robotsViolation: false }
          : { edgeAction: 'charge_402', robotsViolation: true, violatedDirective: directive };
      }
      return { edgeAction: 'allow', robotsViolation: false };
    };

    switch (bot.behavior) {
      case 'Training':
        if (config.trainingPolicy === 'disallow' && bot.isMixedPurposeAccountable) {
          return { edgeAction: 'allow', robotsViolation: false };
        }
        if (config.trainingPolicy === 'disallow') {
          return {
            edgeAction: 'disallow_training',
            robotsViolation: true,
            violatedDirective: `User-agent: ${bot.uaTokens[0]?.token ?? bot.id}\nDisallow: /`,
          };
        }
        return applyPolicy(config.trainingPolicy, 'ai-train=disallow');
      case 'Agent':
        return applyPolicy(config.agentPolicy, 'ai-input=disallow');
      case 'Search':
        return applyPolicy(config.searchPolicy, 'search=disallow');
      case 'Automation':
      default:
        return { edgeAction: 'allow', robotsViolation: false };
    }
  }
}

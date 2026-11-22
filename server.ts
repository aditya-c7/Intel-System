import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import net from 'net';
import os from 'os';
import path from 'path';
import fs from 'fs';
import dns from 'node:dns/promises';
import { createRequire } from 'module';
import dotenv from 'dotenv';
import type {
  AiAgentAttribution,
  BrowserDeviceInfo,
  BotSubtype,
  HardwareSignals,
  IspNetworkClassification,
  SecurityEnvelope,
  SecuritySignals,
  RiskLevel,
  PersistenceMode,
  LocationInfo,
  VisitStatistics,
  VisitHistoryRecord,
  SignedHistoryBackup,
  IntelVisitorResponse,
  IncognitoDiagnostics,
  SmartSignal,
  SmartSignals,
  SmartSignalLevel,
  VelocitySignals,
  VelocityWindowCounts,
} from './src/types/visitor';
import {
  cloudProviderOrgForAsn,
  countryNameFromCode,
  isMissingGeoValue,
  mergeLocationWithEdge,
  normalizeAsnLabel,
  parseContinentValue,
  readEdgeGeoHeaders,
  type EdgeGeoHeaders,
  type EdgeHeaderBag,
} from './src/lib/geoFallbacks';
import {
  canonicalTimezone,
  timezonesEquivalent,
  timezoneMismatchContext,
} from './src/lib/timezone';
import { buildProximityInfo } from './src/lib/geohash';
import { detectAiBotFromServerSignals } from './src/lib/aiBotDirectory';
import { clientHintsMiddleware, type ParsedClientHints } from './src/server/middleware/clientHints';
import {
  normalizeUserAgent,
  type ClientHintsInput,
} from './src/shared/normalization/uaNormalizer';
import { enrichNetwork, resolveAsnOrganization, subnetOf } from './src/server/network/asnEnricher';
import { ensureIdentitySchema, blockKeysFor, upsertBlocks, IDENTITY_SCHEMA_SQL } from './src/server/identity/identityIndex';
import { resolveVisitor, upsertVisitorProfile, type ResolverProfile, type ResolveVisitorResult } from './src/server/identity/resolver';
import { scoreConfidence } from './src/server/identity/confidenceScorer';
import type { BotInfo } from './src/types/visitor';
import {
  RISK_FAMILY_CAPS,
  buildRiskLedger,
  LSH_CONFIG,
  LSH_WRITE_POLICY,
  clopperPearsonUpperBound,
  decideRarity,
  isSecureRequest,
  ENVELOPE_MAX_AGE_MS,
  ENVELOPE_MAX_FUTURE_SKEW_MS,
  type RiskEvidenceLine,
  type OrthogonalRiskLedger,
  type CanonicalTelemetryEnvelope,
  type VerdictTier,
  type InspectorState,
  type RiskTier,
} from './src/lib/telemetryContract';
import {
  evaluateSpecInvariants,
  enforceTamperingInvariant,
  classifyInspectorState,
  inspectorFlagsForState,
  resolvePrivacyHardened,
} from './src/lib/specInvariants';
import {
  buildGradedRiskLedger,
  verifyGradedRiskFixtures,
  type GradedRiskLedger,
} from './src/lib/riskLedger';
import {
  computeHonestRarity,
  computeHonestProximity,
  computeHonestIdentityConfidence,
  confidenceLabel,
} from './src/lib/rarityHonesty';
import {
  simhash512,
  simhashToHex,
  bandHashes,
  resolveIdentityStage,
} from './src/lib/identityEngine';
import { decideVerdictTier } from './src/lib/verdict';
import { resolveAgentProofMethod } from './src/lib/aiBotDirectory';
import {
  AGENT_REGISTRY as REGISTRY_AGENTS,
  AGENT_BY_ID as REGISTRY_AGENT_BY_ID,
  GOOD_BOT_UA_RULES as REGISTRY_GOOD_BOT_UA_RULES,
  AI_AGENT_UA_RULES as REGISTRY_AI_AGENT_UA_RULES,
  BOT_SIGNATURE_KEYID_PROVIDERS as REGISTRY_SIGNATURE_KEYID_PROVIDERS,
  AI_BOT_CIDR_SOURCES as REGISTRY_AI_BOT_CIDR_SOURCES,
  VERIFICATION_SUFFIXES_BY_AGENT as REGISTRY_VERIFICATION_SUFFIXES,
  BOT_DIRECTORY as REGISTRY_BOT_DIRECTORY,
  PILLS as REGISTRY_PILLS,
  findAgentByUa,
  isPolicyToken,
  displayFor,
  normalizeFeed,
  PREFIX_FEEDS as REGISTRY_PREFIX_FEEDS,
  type AgentDef,
  type ProofTier,
} from './src/lib/agentRegistry';
import { PINNED_PREFIXES as REGISTRY_PINNED_PREFIXES } from './src/lib/agentFeedSnapshots';
import {
  verifyWebBotAuth,
  parseWbaHeaders,
  buildSignatureBase,
  computeJwkThumbprint,
  WBA_TRUSTED_SIGNERS,
  type WbaParsed,
  type WbaVerification,
  type WbaStatus,
  type WbaTrustedSigner,
  type WbaVerifyOptions,
} from './src/lib/wbaVerifier';
// Shadow-only, additive truth helpers. Every verdict they produce is a SECOND OPINION:
// nothing below reads these values into the 0-10 headline, the 0-100 ledger, the verdict
// tier, the bot/isBot gate, the uncalibrated confidence gate or the blocklist/auth flow.
import { resolveProxyDetails, type ProxyDetails } from './src/lib/proxyTruth';
import { resolveVpnMethods } from './src/lib/vpnMethods';
import { checkStrictOrigin, ipReplayRate, replayWindowStatus } from './src/lib/zeroTrust';

/* -------------------------------------------------------------------------- */
/* Shared agent registry adapter                                                */
/*   The registry is the single source of truth for every named crawler. The    */
/*   local aliases below keep the legacy call sites stable and degrade safely    */
/*   when a registry lookup is missing data.                                     */
/* -------------------------------------------------------------------------- */

interface GoodBotUaRule {
  pattern: RegExp;
  provider: string;
  label: string;
  category: string;
  network: RegExp;
}
interface AiAgentUaRule {
  pattern: RegExp;
  provider: string;
  label: string;
}
type SignatureKeyidProvider = [string, string];
interface CidrFeedSource {
  id: string;
  url: string;
}
type AiBotCidrSourceId = string;

/** Locally normalized view of a registry agent (extra verification metadata is optional). */
interface LocalAgentDef {
  id: string;
  displayName: string;
  provider: string;
  category: string;
  executionMode?: string | null;
  policyToken?: boolean;
  minProofForVerified?: ProofTier | string;
  fcrdnsSuffixes?: string[];
  asns?: string[];
  signatureHosts?: string[];
  keyIdNeedles?: string[];
  feedIds?: string[];
}

const GOOD_BOT_UA_RULES: GoodBotUaRule[] = REGISTRY_GOOD_BOT_UA_RULES as unknown as GoodBotUaRule[];
const AI_AGENT_UA_RULES: AiAgentUaRule[] = REGISTRY_AI_AGENT_UA_RULES as unknown as AiAgentUaRule[];
const BOT_SIGNATURE_KEYID_PROVIDERS: SignatureKeyidProvider[] =
  REGISTRY_SIGNATURE_KEYID_PROVIDERS as unknown as SignatureKeyidProvider[];
const AI_BOT_CIDR_SOURCES: CidrFeedSource[] = REGISTRY_AI_BOT_CIDR_SOURCES as unknown as CidrFeedSource[];

/** Reads a value from either a plain record or a Map without depending on its declared type. */
function registryLookup(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object') return undefined;
  const asRecord = value as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(asRecord, key)) return asRecord[key];
  const getter = (value as { get?: (lookupKey: string) => unknown }).get;
  if (typeof getter === 'function') return getter.call(value, key);
  return undefined;
}

function asLocalAgent(agent: AgentDef): LocalAgentDef {
  const raw = (agent && typeof agent === 'object' ? agent : {}) as AgentDef &
    Record<string, unknown>;
  const signature = raw.signature as
    | { agentHosts?: readonly string[]; keyIdNeedles?: readonly string[] }
    | undefined;
  return {
    ...(raw as unknown as LocalAgentDef),
    fcrdnsSuffixes: raw.fcrdnsSuffixes ? [...raw.fcrdnsSuffixes] : undefined,
    feedIds: raw.feedIds ? [...raw.feedIds] : undefined,
    asns: raw.asns ? raw.asns.map(String) : undefined,
    signatureHosts: signature?.agentHosts ? [...signature.agentHosts] : undefined,
    keyIdNeedles: signature?.keyIdNeedles ? [...signature.keyIdNeedles] : undefined,
  };
}

const REGISTRY_AGENT_LIST: LocalAgentDef[] = Array.isArray(REGISTRY_AGENTS)
  ? (REGISTRY_AGENTS as unknown as AgentDef[]).map(asLocalAgent)
  : Object.values((REGISTRY_AGENTS ?? {}) as unknown as Record<string, AgentDef>).map(asLocalAgent);

function lookupAgent(id: string | null | undefined): LocalAgentDef | null {
  if (!id) return null;
  const direct = registryLookup(REGISTRY_AGENT_BY_ID, id);
  if (direct) return asLocalAgent(direct as AgentDef);
  const needle = id.toLowerCase();
  return (
    REGISTRY_AGENT_LIST.find(
      (agent) =>
        String(agent.id || '').toLowerCase() === needle ||
        String(agent.displayName || '').toLowerCase() === needle ||
        String(agent.provider || '').toLowerCase() === needle
    ) ?? null
  );
}

const findRegistryAgent = (ua: string): AgentDef | null =>
  (findAgentByUa as unknown as (value: string) => AgentDef | null | undefined)(ua) ?? null;

const isRegistryPolicyToken = (ua: string): boolean =>
  Boolean((isPolicyToken as unknown as (value: string) => boolean | undefined)(ua));

const registryDisplay = (agent: AgentDef, identity: string): { label: string } =>
  (displayFor as unknown as (value: AgentDef, agentIdentity: string) => { label: string })(
    agent,
    identity
  );

const normalizeRegistryFeed = (sourceId: string, body: string): { prefixes: string[] } =>
  (normalizeFeed as unknown as (id: string, text: string) => { prefixes: string[] })(
    sourceId,
    body
  );

/** Legacy operator union — widened to a string so newly registered operators stay compatible. */
type AiAgentOperatorId =
  | 'google'
  | 'openai'
  | 'perplexity'
  | 'anthropic'
  | 'xai'
  | 'meta'
  | 'browserbase'
  | 'anchorbrowser'
  | (string & {});

function operatorIdFromName(name: string): AiAgentOperatorId {
  const lower = name.toLowerCase();
  if (/google/.test(lower)) return 'google';
  if (/openai|chatgpt/.test(lower)) return 'openai';
  if (/perplexity/.test(lower)) return 'perplexity';
  if (/anthropic|claude/.test(lower)) return 'anthropic';
  if (/xai|grok|\bx\b/.test(lower)) return 'xai';
  if (/meta|facebook/.test(lower)) return 'meta';
  if (/browserbase/.test(lower)) return 'browserbase';
  if (/anchor\s?browser/.test(lower)) return 'anchorbrowser';
  return lower.replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'unknown';
}

/** Fallbacks preserve the exact verification behaviour of already-handled providers. */
const FALLBACK_VERIFICATION_SUFFIXES: Record<string, string[]> = {
  google: ['googlebot.com', 'google.com'],
  openai: ['openai.com', 'chatgpt.com'],
  perplexity: ['perplexity.ai'],
  anthropic: ['anthropic.com', 'claude.ai'],
  xai: ['x.ai', 'grok.com'],
  meta: ['facebook.com', 'meta.com', 'fb.com'],
};
const FALLBACK_ASNS: Record<string, string[]> = {
  google: ['15169', '396982'],
  xai: ['400562', '13414'],
  meta: ['32934', '63293'],
  aws: ['16509', '14618'],
  azure: ['8075'],
  perplexity: ['209242'],
};
const FALLBACK_SIGNATURE_HOSTS: Array<[string, AiAgentOperatorId]> = [
  ['openai.com', 'openai'],
  ['chatgpt.com', 'openai'],
  ['perplexity.ai', 'perplexity'],
  ['anthropic.com', 'anthropic'],
  ['claude.ai', 'anthropic'],
  ['browserbase.com', 'browserbase'],
  ['anchorbrowser.io', 'anchorbrowser'],
  // xAI / Grok attribution is pinned exclusively in WBA_TRUSTED_SIGNERS inside wbaVerifier;
  // x.ai / grok.com / cursorusercontent.com are NOT generic host→operator rules (anti-spoof).
  ['meta.com', 'meta'],
  ['facebook.com', 'meta'],
];

function suffixesForAgent(...keys: string[]): string[] {
  const found: string[] = [];
  const add = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const item of value) if (typeof item === 'string' && item.trim()) found.push(item.trim());
    }
  };
  for (const key of keys) {
    add(registryLookup(REGISTRY_VERIFICATION_SUFFIXES, key));
    add(registryLookup(REGISTRY_VERIFICATION_SUFFIXES, key.toLowerCase()));
    add(lookupAgent(key)?.fcrdnsSuffixes);
  }
  const needles = keys.map((key) => key.toLowerCase());
  for (const agent of REGISTRY_AGENT_LIST) {
    if (
      needles.some(
        (key) =>
          key === String(agent.id || '').toLowerCase() ||
          key === String(agent.provider || '').toLowerCase() ||
          key === String(agent.displayName || '').toLowerCase()
      )
    ) {
      add(agent.fcrdnsSuffixes);
    }
  }
  if (found.length === 0) {
    for (const key of keys) add(FALLBACK_VERIFICATION_SUFFIXES[key.toLowerCase()]);
  }
  return Array.from(new Set(found));
}

function asnsForAgent(...keys: string[]): string[] {
  const found: string[] = [];
  const add = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const item of value) {
        const digits = typeof item === 'number' ? String(item) : typeof item === 'string' ? item : '';
        if (digits.trim()) found.push(digits.trim());
      }
    }
  };
  for (const key of keys) add(lookupAgent(key)?.asns);
  if (found.length === 0) {
    for (const key of keys) add(FALLBACK_ASNS[key.toLowerCase()]);
  }
  return Array.from(new Set(found));
}

const SIGNATURE_HOST_RULES: Array<{ host: string; operator: AiAgentOperatorId }> = (() => {
  const rules = FALLBACK_SIGNATURE_HOSTS.map(([host, operator]) => ({ host, operator }));
  for (const agent of REGISTRY_AGENT_LIST) {
    const operator = operatorIdFromName(agent.provider || agent.id);
    for (const rawHost of agent.signatureHosts ?? []) {
      if (typeof rawHost === 'string' && rawHost.trim()) {
        rules.push({ host: rawHost.trim().toLowerCase(), operator });
      }
    }
  }
  for (const rawEntry of (REGISTRY_BOT_DIRECTORY ?? []) as unknown as Array<unknown>) {
    const entry = rawEntry && typeof rawEntry === 'object' ? (rawEntry as Record<string, unknown>) : {};
    const hosts = entry.signatureHosts ?? entry.hosts ?? entry.domains ?? entry.verificationSuffixes;
    const name = entry.provider ?? entry.operator ?? entry.name;
    if (Array.isArray(hosts) && typeof name === 'string') {
      const operator = operatorIdFromName(name);
      for (const rawHost of hosts) {
        if (typeof rawHost === 'string' && rawHost.trim()) {
          rules.push({ host: rawHost.trim().toLowerCase(), operator });
        }
      }
    }
  }
  return rules;
})();

/** Category helpers shared by the attribution engine, the tile and the response state machine. */
function isGoodCrawlerCategory(category: string | undefined): boolean {
  const value = String(category || '').toLowerCase();
  return value === 'search_crawler' || value === 'search crawler' || value === 'link_preview' || value === 'link preview';
}
function isAiAgentCategory(category: string | undefined): boolean {
  return /^ai[_\s-]/i.test(String(category || ''));
}

/** Pin the verified-prefix table at module load so the very first request already has data. */
function pinnedPrefixEntries(): Array<[string, string[]]> {
  const entries: Array<[string, string[]]> = [];
  const add = (id: string, value: unknown): void => {
    const prefixes = Array.isArray(value)
      ? value.filter((item): item is string => typeof item === 'string' && item.includes('/'))
      : [];
    if (prefixes.length > 0) entries.push([id, prefixes]);
  };
  const pinned: unknown = REGISTRY_PINNED_PREFIXES;
  if (Array.isArray(pinned)) {
    for (const item of pinned) {
      if (typeof item === 'string') {
        if (item.includes('/')) add('pinned', [item]);
        continue;
      }
      const record = item && typeof item === 'object' ? (item as Record<string, unknown>) : {};
      const id =
        typeof record.id === 'string'
          ? record.id
          : typeof record.sourceId === 'string'
          ? record.sourceId
          : typeof record.agentId === 'string'
          ? record.agentId
          : 'pinned';
      add(id, record.prefixes ?? record.prefix ?? record.cidrs ?? record.ranges);
    }
  } else if (pinned && typeof pinned === 'object') {
    for (const [id, prefixes] of Object.entries(pinned as Record<string, unknown>)) add(id, prefixes);
  }
  return entries;
}

/** Normalizes the registry feed payload into the prefix-list shape used by `AiBotCidrSource`. */
function prefixesFromNormalizedFeed(normalized: unknown, sourceId: string): string[] {
  const found: string[] = [];
  const add = (value: unknown): void => {
    if (typeof value === 'string') {
      if (value.includes('/')) found.push(value.trim());
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) add(item);
      return;
    }
    if (value && typeof value === 'object') {
      const record = value as Record<string, unknown>;
      for (const key of ['prefixes', 'prefix', 'cidrs', 'ranges', 'ipv4Prefix', 'ipv6Prefix']) {
        if (record[key] !== undefined) add(record[key]);
      }
    }
  };
  if (normalized && typeof normalized === 'object' && !Array.isArray(normalized)) {
    const feedKey = registryLookup(REGISTRY_PREFIX_FEEDS, sourceId);
    const match = registryLookup(normalized, sourceId) ?? (typeof feedKey === 'string' ? registryLookup(normalized, feedKey) : undefined);
    if (match !== undefined) add(match);
    else {
      const compact = sourceId.replace(/[^a-z0-9]/gi, '').toLowerCase();
      for (const [key, value] of Object.entries(normalized as Record<string, unknown>)) {
        if (key.toLowerCase() === sourceId.toLowerCase() || key.replace(/[^a-z0-9]/gi, '').toLowerCase() === compact) {
          add(value);
        }
      }
    }
  } else {
    add(normalized);
  }
  return Array.from(new Set(found));
}

dotenv.config();

const PORT = Number(process.env.PORT) || 3000;

/**
 * Build provenance for the parser / worker halves. Mirrored into `/api/health` and the
 * identify envelope so a response can be traced to the exact deployed parser and build.
 * `GIT_SHA` is injected by CI; every field degrades to an explicit sentinel, never a guess.
 */
const BUILD_SHA = process.env.GIT_SHA || 'unknown';
const PARSER_VERSION = process.env.PARSER_VERSION || 'tranche-0-1';
const WORKER_VERSION = process.env.WORKER_VERSION || 'tranche-0-1';

const SESSION_TIMEOUT_MINUTES = 30;
const SESSION_EXPIRATION_MS = SESSION_TIMEOUT_MINUTES * 60 * 1000;

const IS_SERVERLESS_RUNTIME = Boolean(
  process.env.VERCEL ||
    process.env.VERCEL_ENV ||
    process.env.AWS_LAMBDA_FUNCTION_NAME ||
    process.env.NETLIFY
);

const HMAC_SECRET =
  process.env.VISITOR_HMAC_SECRET ||
  'intel-system-first-party-hmac-secret-2026';

interface VisitorRow {
  visitor_id: string;
  hmac_token: string;
  hardware_id: string;
  created_at_utc: string;
  updated_at_utc: string;
  active_session_id: string;
  last_activity_utc: string;
}

interface VisitRow {
  id: number;
  visit_id: string;
  visitor_id: string;
  session_id: string;
  page_load_id: string;
  visited_at_utc: string;
  public_ip: string;
  city: string;
  region: string;
  country: string;
  latitude: number | null;
  longitude: number | null;
  isp: string;
  org: string;
  asn: string;
  browser: string;
  os: string;
  device_type: string;
  screen_resolution: string;
  language: string;
  timezone: string;
  suspect_score?: number | null;
  risk_level?: string | null;
  score10?: number | null;
  bot_name?: string | null;
  recognition_source?: string | null;
}

/** Additive edge-geo parity fields threaded into LocationInfo / Event JSON without guessing. */
type EdgeEnrichedLocation = LocationInfo & {
  continent?: string;
  continentCode?: string;
  postalCode?: string;
  subdivisionIso?: string;
  accuracyRadiusKm?: number | null;
  asnNetwork?: string;
};

interface GeoCacheRow {
  ip_address: string;
  city: string;
  region: string;
  country: string;
  country_code: string;
  latitude: number | null;
  longitude: number | null;
  isp: string;
  org: string;
  asn: string;
  is_vpn_or_hosting: number;
  verified_at_ms: number;
}

interface PreparedStatementShim {
  get: (...params: unknown[]) => unknown;
  all: (...params: unknown[]) => unknown[];
  run: (...params: unknown[]) => { changes: number };
}

interface DatabaseAdapter {
  prepare: (sql: string) => PreparedStatementShim;
  exec: (sql: string) => void;
}

interface HardwareAnchorRow {
  hardware_id: string;
  visitor_id: string;
  simhash: string;
  distinct_storage_seeds_count: number;
  first_seen_utc: string;
  updated_at_utc: string;
}

function createInMemoryDbAdapter(): DatabaseAdapter {
  const visitorsMap = new Map<string, VisitorRow>();
  const visitsList: VisitRow[] = [];
  const geoCacheMap = new Map<string, GeoCacheRow>();
  // Phase 4 canonical tables mirrored in the shim for rollback / forced-memory parity.
  const hardwareAnchorsMap = new Map<string, HardwareAnchorRow>();
  const lshBandsMap = new Map<string, { band_idx: number; band_hash: string; hardware_id: string }>();
  const rdapPrefixMap = new Map<string, { prefix: string; org: string; asn: string; fetched_at_ms: number }>();
  const schemaMigrations = new Set<string>();
  let autoIncrementId = 1;

  return {
    exec: () => {},
    prepare: (sql: string): PreparedStatementShim => {
      const normalized = sql.replace(/\s+/g, ' ').trim();

      return {
        get: (...params: unknown[]) => {
          if (normalized.includes('AS events_24h') && normalized.includes('FROM visits WHERE visitor_id = ?')) {
            const vid = String(params[12] || '');
            const cutoffs = [String(params[0] || ''), String(params[1] || ''), String(params[2] || '')];
            const rows = visitsList.filter((v) => v.visitor_id === vid);
            const inWindow = (cutoff: string) => rows.filter((v) => v.visited_at_utc >= cutoff);
            const distinct = (cutoff: string, pick: (v: VisitRow) => string) =>
              new Set(inWindow(cutoff).map(pick)).size;
            return {
              ip_5m: distinct(cutoffs[0], (v) => v.public_ip),
              ip_1h: distinct(cutoffs[1], (v) => v.public_ip),
              ip_24h: distinct(cutoffs[2], (v) => v.public_ip),
              linked_5m: distinct(cutoffs[0], (v) => v.session_id),
              linked_1h: distinct(cutoffs[1], (v) => v.session_id),
              linked_24h: distinct(cutoffs[2], (v) => v.session_id),
              country_5m: distinct(cutoffs[0], (v) => v.country),
              country_1h: distinct(cutoffs[1], (v) => v.country),
              country_24h: distinct(cutoffs[2], (v) => v.country),
              events_5m: inWindow(cutoffs[0]).length,
              events_1h: inWindow(cutoffs[1]).length,
              events_24h: inWindow(cutoffs[2]).length,
            };
          }
          if (normalized.includes('AS ip_events_24h')) {
            const cutoffs = [String(params[0] || ''), String(params[1] || ''), String(params[2] || '')];
            const publicIp = String(params[4] || '');
            const rows = visitsList.filter((v) => v.public_ip === publicIp);
            const inWindow = (cutoff: string) => rows.filter((v) => v.visited_at_utc >= cutoff);
            return {
              ip_events_5m: inWindow(cutoffs[0]).length,
              ip_events_1h: inWindow(cutoffs[1]).length,
              ip_events_24h: inWindow(cutoffs[2]).length,
              ip_visitors_24h: new Set(inWindow(cutoffs[2]).map((v) => v.visitor_id)).size,
            };
          }
          if (normalized.includes('AS linked_ips_5m')) {
            const cutoffs = [String(params[0] || ''), String(params[1] || ''), String(params[2] || '')];
            const sessionId = String(params[6] || '');
            const rows = visitsList.filter((v) => v.session_id === sessionId);
            const inWindow = (cutoff: string) => rows.filter((v) => v.visited_at_utc >= cutoff);
            const distinct = (cutoff: string, pick: (v: VisitRow) => string) =>
              new Set(inWindow(cutoff).map(pick)).size;
            return {
              linked_ips_5m: distinct(cutoffs[0], (v) => v.public_ip),
              linked_ips_1h: distinct(cutoffs[1], (v) => v.public_ip),
              linked_ips_24h: distinct(cutoffs[2], (v) => v.public_ip),
              linked_visitors_5m: distinct(cutoffs[0], (v) => v.visitor_id),
              linked_visitors_1h: distinct(cutoffs[1], (v) => v.visitor_id),
              linked_visitors_24h: distinct(cutoffs[2], (v) => v.visitor_id),
            };
          }
          if (normalized.includes('intel:dailyhardware')) {
            const cutoff = String(params[0] || '');
            const activeHardware = new Set(
              Array.from(visitorsMap.values())
                .filter((v) => v.updated_at_utc >= cutoff && v.hardware_id)
                .map((v) => v.hardware_id)
            );
            return { n: activeHardware.size };
          }
          if (normalized.includes('FROM hardware_anchors WHERE hardware_id = ?')) {
            return hardwareAnchorsMap.get(String(params[0] || ''));
          }
          if (normalized.includes('FROM identity_lsh_bands WHERE band_idx = ? AND band_hash = ?')) {
            return lshBandsMap.get(`${params[0]}:${params[1]}`);
          }
          if (normalized.includes('FROM rdap_prefix_cache WHERE prefix = ?')) {
            return rdapPrefixMap.get(String(params[0] || ''));
          }
          if (normalized.includes('FROM schema_migrations WHERE version = ?')) {
            return schemaMigrations.has(String(params[0] || '')) ? { version: String(params[0]) } : undefined;
          }
          if (normalized.includes('FROM verified_geo_cache_v3 WHERE ip_address = ?')) {
            const ip = String(params[0] || '');
            return geoCacheMap.get(ip);
          }
          if (normalized.includes('SELECT COUNT(*) AS count FROM visitors')) {
            return { count: visitorsMap.size };
          }
          if (normalized.includes('SELECT COUNT(*) AS count FROM visits')) {
            return { count: visitsList.length };
          }
          if (normalized.includes('SELECT * FROM visitors WHERE visitor_id = ?')) {
            const vid = String(params[0] || '');
            return visitorsMap.get(vid);
          }
          if (normalized.includes('SELECT * FROM visitors WHERE hardware_id = ?')) {
            const hwid = String(params[0] || '');
            if (!hwid || !hwid.startsWith('hwid_')) return undefined;
            const matches = Array.from(visitorsMap.values())
              .filter((v) => v.hardware_id === hwid)
              .sort((a, b) => b.updated_at_utc.localeCompare(a.updated_at_utc));
            return matches[0];
          }
          if (
            normalized.includes('FROM visits WHERE visitor_id = ? AND page_load_id = ?')
          ) {
            const vid = String(params[0] || '');
            const plId = String(params[1] || '');
            const found = visitsList.find(
              (v) => v.visitor_id === vid && v.page_load_id === plId
            );
            return found
              ? {
                  visit_id: found.visit_id,
                  session_id: found.session_id,
                  visited_at_utc: found.visited_at_utc,
                }
              : undefined;
          }
          if (normalized.includes('COUNT(*) AS total_visits') && normalized.includes('FROM visits WHERE visitor_id = ?')) {
            const vid = String(params[0] || '');
            const userVisits = visitsList.filter((v) => v.visitor_id === vid);
            if (userVisits.length === 0) {
              return {
                total_visits: 0,
                first_visit_utc: null,
                last_visit_utc: null,
                total_sessions: 0,
              };
            }
            const sortedAsc = [...userVisits].sort((a, b) =>
              a.visited_at_utc.localeCompare(b.visited_at_utc)
            );
            const sessions = new Set(userVisits.map((v) => v.session_id));
            return {
              total_visits: userVisits.length,
              first_visit_utc: sortedAsc[0].visited_at_utc,
              last_visit_utc: sortedAsc[sortedAsc.length - 1].visited_at_utc,
              total_sessions: sessions.size,
            };
          }
          if (normalized.includes('LIMIT 1 OFFSET 1')) {
            const vid = String(params[0] || '');
            const userVisits = visitsList
              .filter((v) => v.visitor_id === vid)
              .sort((a, b) => b.visited_at_utc.localeCompare(a.visited_at_utc) || b.id - a.id);
            return userVisits.length > 1
              ? { visited_at_utc: userVisits[1].visited_at_utc }
              : undefined;
          }
          return undefined;
        },

        all: (...params: unknown[]) => {
          if (normalized.includes('intel:subnets24h')) {
            const vid = String(params[0] || '');
            const cutoff = String(params[1] || '');
            return visitsList
              .filter((v) => v.visitor_id === vid && v.visited_at_utc >= cutoff)
              .map((v) => ({ public_ip: v.public_ip }));
          }
          if (normalized.includes('intel:dailyevents')) {
            const cutoff = String(params[0] || '');
            const counts = new Map<string, number>();
            for (const visit of visitsList) {
              if (visit.visited_at_utc < cutoff) continue;
              counts.set(visit.visitor_id, (counts.get(visit.visitor_id) || 0) + 1);
            }
            return Array.from(counts, ([visitor_id, events]) => ({ visitor_id, events }));
          }
          if (normalized.includes('FROM identity_lsh_bands WHERE band_idx = ?')) {
            const idx = Number(params[0]);
            const bandHash = typeof params[1] === 'string' ? params[1] : null;
            return Array.from(lshBandsMap.values()).filter(
              (row) => row.band_idx === idx && (bandHash === null || row.band_hash === bandHash)
            );
          }
          if (normalized.includes('FROM schema_migrations')) {
            return Array.from(schemaMigrations).map((version) => ({ version }));
          }
          if (normalized.includes('FROM visits WHERE visitor_id = ?')) {
            const vid = String(params[0] || '');
            return visitsList
              .filter((v) => v.visitor_id === vid)
              .sort((a, b) => b.visited_at_utc.localeCompare(a.visited_at_utc) || b.id - a.id)
              .slice(0, 50);
          }
          return [];
        },

        run: (...params: unknown[]) => {
          if (normalized.includes('INSERT OR REPLACE INTO hardware_anchors')) {
            const row: HardwareAnchorRow = {
              hardware_id: String(params[0] || ''),
              visitor_id: String(params[1] || ''),
              simhash: String(params[2] || ''),
              distinct_storage_seeds_count: Number(params[3] ?? 1),
              first_seen_utc: String(params[4] || ''),
              updated_at_utc: String(params[5] || ''),
            };
            hardwareAnchorsMap.set(row.hardware_id, row);
            return { changes: 1 };
          }
          if (normalized.includes('INSERT OR IGNORE INTO identity_lsh_bands')) {
            const band_idx = Number(params[0]);
            const band_hash = String(params[1] || '');
            const hardware_id = String(params[2] || '');
            const key = `${band_idx}:${band_hash}`;
            if (lshBandsMap.has(key)) return { changes: 0 };
            lshBandsMap.set(key, { band_idx, band_hash, hardware_id });
            return { changes: 1 };
          }
          if (normalized.includes('INSERT OR REPLACE INTO rdap_prefix_cache')) {
            rdapPrefixMap.set(String(params[0] || ''), {
              prefix: String(params[0] || ''),
              org: String(params[1] || ''),
              asn: String(params[2] || ''),
              fetched_at_ms: Number(params[3] || Date.now()),
            });
            return { changes: 1 };
          }
          if (normalized.includes('INSERT OR IGNORE INTO schema_migrations')) {
            const version = String(params[0] || '');
            if (schemaMigrations.has(version)) return { changes: 0 };
            schemaMigrations.add(version);
            return { changes: 1 };
          }
          if (normalized.includes('INSERT OR REPLACE INTO verified_geo_cache_v3')) {
            const row: GeoCacheRow = {
              ip_address: String(params[0] || ''),
              city: String(params[1] || 'Unknown'),
              region: String(params[2] || 'Unknown'),
              country: String(params[3] || 'Unknown'),
              country_code: String(params[4] || ''),
              latitude: typeof params[5] === 'number' ? params[5] : null,
              longitude: typeof params[6] === 'number' ? params[6] : null,
              isp: String(params[7] || 'Unknown'),
              org: String(params[8] || 'Unknown'),
              asn: String(params[9] || 'Unknown'),
              is_vpn_or_hosting: Number(params[10] || 0),
              verified_at_ms: Number(params[11] || Date.now()),
            };
            geoCacheMap.set(row.ip_address, row);
            return { changes: 1 };
          }
          if (normalized.includes('INSERT INTO visitors') || normalized.includes('INSERT OR REPLACE INTO visitors')) {
            const hasHwCol = normalized.includes('hardware_id');
            const row: VisitorRow = hasHwCol
              ? {
                  visitor_id: String(params[0] || ''),
                  hmac_token: String(params[1] || ''),
                  hardware_id: String(params[2] || ''),
                  created_at_utc: String(params[3] || ''),
                  updated_at_utc: String(params[4] || ''),
                  active_session_id: String(params[5] || ''),
                  last_activity_utc: String(params[6] || ''),
                }
              : {
                  visitor_id: String(params[0] || ''),
                  hmac_token: String(params[1] || ''),
                  hardware_id: '',
                  created_at_utc: String(params[2] || ''),
                  updated_at_utc: String(params[3] || ''),
                  active_session_id: String(params[4] || ''),
                  last_activity_utc: String(params[5] || ''),
                };
            visitorsMap.set(row.visitor_id, row);
            return { changes: 1 };
          }
          if (normalized.includes('UPDATE visitors')) {
            const hasHwUpdate = normalized.includes('hardware_id = ?');
            const vid = String(hasHwUpdate ? params[4] : params[3] || '');
            const existing = visitorsMap.get(vid);
            if (existing) {
              existing.updated_at_utc = String(params[0] || existing.updated_at_utc);
              existing.active_session_id = String(params[1] || existing.active_session_id);
              existing.last_activity_utc = String(params[2] || existing.last_activity_utc);
              if (hasHwUpdate && typeof params[3] === 'string' && params[3]) {
                existing.hardware_id = params[3];
              }
              return { changes: 1 };
            }
            return { changes: 0 };
          }
          if (normalized.includes('INSERT OR IGNORE INTO visits')) {
            const visitId = String(params[0] || '');
            const visitorId = String(params[1] || '');
            const pageLoadId = String(params[3] || '');
            const duplicate = visitsList.some(
              (v) =>
                v.visit_id === visitId ||
                (v.visitor_id === visitorId && v.page_load_id === pageLoadId)
            );
            if (duplicate) {
              return { changes: 0 };
            }
            visitsList.push({
              id: autoIncrementId++,
              visit_id: visitId,
              visitor_id: visitorId,
              session_id: String(params[2] || ''),
              page_load_id: pageLoadId,
              visited_at_utc: String(params[4] || ''),
              public_ip: String(params[5] || 'Unavailable'),
              city: String(params[6] || 'Unknown'),
              region: String(params[7] || 'Unknown'),
              country: String(params[8] || 'Unknown'),
              latitude: typeof params[9] === 'number' ? params[9] : null,
              longitude: typeof params[10] === 'number' ? params[10] : null,
              isp: String(params[11] || 'Unknown'),
              org: String(params[12] || 'Unknown'),
              asn: String(params[13] || 'Unknown'),
              browser: String(params[14] || 'Unknown'),
              os: String(params[15] || 'Unknown'),
              device_type: String(params[16] || 'Unknown'),
              screen_resolution: String(params[17] || 'Unavailable'),
              language: String(params[18] || 'Unavailable'),
              timezone: String(params[19] || 'Unavailable'),
              suspect_score: typeof params[20] === 'number' ? params[20] : null,
              risk_level: typeof params[21] === 'string' ? params[21] : null,
              score10: typeof params[22] === 'number' ? params[22] : null,
              bot_name: typeof params[23] === 'string' ? params[23] : null,
              recognition_source: typeof params[24] === 'string' ? params[24] : null,
            });
            return { changes: 1 };
          }
          if (normalized.includes('UPDATE visits') && normalized.includes('suspect_score = ?')) {
            const visitId = String(params[5] || '');
            const target = visitsList.find((v) => v.visit_id === visitId);
            if (!target) return { changes: 0 };
            target.suspect_score = typeof params[0] === 'number' ? params[0] : null;
            target.risk_level = typeof params[1] === 'string' ? params[1] : null;
            target.score10 = typeof params[2] === 'number' ? params[2] : null;
            target.bot_name = typeof params[3] === 'string' ? params[3] : null;
            target.recognition_source = typeof params[4] === 'string' ? params[4] : null;
            return { changes: 1 };
          }
          return { changes: 0 };
        },
      };
    },
  };
}

function initializeDatabase(): DatabaseAdapter {
  if (process.env.INTEL_FORCE_MEMORY_DB === '1') {
    return createInMemoryDbAdapter();
  }

  let targetDir = path.join(os.tmpdir(), 'intel-system-data');
  if (!IS_SERVERLESS_RUNTIME) {
    try {
      const localDataDir = path.resolve(process.cwd(), 'data');
      if (!fs.existsSync(localDataDir)) {
        fs.mkdirSync(localDataDir, { recursive: true });
      }
      fs.accessSync(localDataDir, fs.constants.W_OK);
      targetDir = localDataDir;
    } catch {
      targetDir = path.join(os.tmpdir(), 'intel-system-data');
    }
  }

  try {
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }
    const dbPath = path.join(targetDir, 'intel_system.db');
    const requireModule = createRequire(import.meta.url);
    const BetterSqlite3 = requireModule('better-sqlite3') as new (
      filename: string
    ) => DatabaseAdapter & { pragma: (str: string) => void };

    const sqliteDb = new BetterSqlite3(dbPath);
    sqliteDb.pragma('journal_mode = WAL');
    sqliteDb.pragma('foreign_keys = ON');

    sqliteDb.exec(`
      CREATE TABLE IF NOT EXISTS visitors (
        visitor_id TEXT PRIMARY KEY,
        hmac_token TEXT NOT NULL,
        hardware_id TEXT NOT NULL DEFAULT '',
        created_at_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL,
        active_session_id TEXT NOT NULL,
        last_activity_utc TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        visit_id TEXT UNIQUE NOT NULL,
        visitor_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        page_load_id TEXT NOT NULL,
        visited_at_utc TEXT NOT NULL,
        public_ip TEXT NOT NULL,
        city TEXT NOT NULL,
        region TEXT NOT NULL,
        country TEXT NOT NULL,
        latitude REAL,
        longitude REAL,
        isp TEXT NOT NULL DEFAULT 'Unknown',
        org TEXT NOT NULL DEFAULT 'Unknown',
        asn TEXT NOT NULL DEFAULT 'Unknown',
        browser TEXT NOT NULL,
        os TEXT NOT NULL,
        device_type TEXT NOT NULL,
        screen_resolution TEXT NOT NULL,
        language TEXT NOT NULL,
        timezone TEXT NOT NULL,
        suspect_score REAL,
        risk_level TEXT,
        score10 REAL,
        bot_name TEXT,
        recognition_source TEXT,
        UNIQUE(visitor_id, page_load_id),
        FOREIGN KEY (visitor_id) REFERENCES visitors(visitor_id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_visits_visitor_utc ON visits(visitor_id, visited_at_utc DESC, id DESC);

      CREATE TABLE IF NOT EXISTS verified_geo_cache_v3 (
        ip_address TEXT PRIMARY KEY,
        city TEXT NOT NULL,
        region TEXT NOT NULL,
        country TEXT NOT NULL,
        country_code TEXT NOT NULL,
        latitude REAL,
        longitude REAL,
        isp TEXT NOT NULL,
        org TEXT NOT NULL,
        asn TEXT NOT NULL,
        is_vpn_or_hosting INTEGER NOT NULL DEFAULT 0,
        timezone TEXT,
        verified_at_ms INTEGER NOT NULL
      );

      ${IDENTITY_SCHEMA_SQL}

      /* Phase 4 — canonical identity tables. Old tables are intentionally kept for rollback. */
      CREATE TABLE IF NOT EXISTS hardware_anchors (
        hardware_id TEXT PRIMARY KEY,
        visitor_id TEXT NOT NULL,
        simhash TEXT NOT NULL DEFAULT '',
        distinct_storage_seeds_count INTEGER NOT NULL DEFAULT 1,
        first_seen_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS identity_lsh_bands (
        band_idx INTEGER NOT NULL,
        band_hash TEXT NOT NULL,
        hardware_id TEXT NOT NULL,
        PRIMARY KEY (band_idx, band_hash, hardware_id)
      ) WITHOUT ROWID;

      CREATE TABLE IF NOT EXISTS rdap_prefix_cache (
        prefix TEXT PRIMARY KEY,
        org TEXT NOT NULL DEFAULT '',
        asn TEXT NOT NULL DEFAULT '',
        fetched_at_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at_utc TEXT NOT NULL
      );

      DROP TABLE IF EXISTS ai_bot_cidr_ranges;
      DROP TABLE IF EXISTS ai_bot_dns_cache;
      DROP TABLE IF EXISTS ai_bot_jwk_cache;
      DROP TABLE IF EXISTS ai_bot_requests;
      DROP TABLE IF EXISTS ai_operator_referrals;
      DROP TABLE IF EXISTS ai_zone_config;
    `);

    try {
      sqliteDb.exec(`ALTER TABLE visitors ADD COLUMN hardware_id TEXT NOT NULL DEFAULT ''`);
    } catch {
      // Column already exists
    }
    try {
      sqliteDb.exec(`CREATE INDEX IF NOT EXISTS idx_visitors_hwid ON visitors(hardware_id)`);
    } catch {
      // Ignore index error
    }

    for (const col of ['isp', 'org', 'asn']) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} TEXT NOT NULL DEFAULT 'Unknown'`);
      } catch {
        // Column already exists
      }
    }
    for (const col of ['latitude', 'longitude']) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} REAL`);
      } catch {
        // Column already exists
      }
      try {
        sqliteDb.exec(`ALTER TABLE verified_geo_cache_v3 ADD COLUMN ${col} REAL`);
      } catch {
        // Column already exists
      }
    }
    try {
      sqliteDb.exec(`ALTER TABLE verified_geo_cache_v3 ADD COLUMN timezone TEXT`);
    } catch {
      // Column already exists
    }
    // Per-visit risk persistence (Fix 7): survive serverless cold starts with the exact
    // score, level and bot attribution that were shown when the visit happened.
    for (const col of ['suspect_score', 'score10']) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} REAL`);
      } catch {
        // Column already exists
      }
    }
    for (const col of ['risk_level', 'bot_name', 'recognition_source']) {
      try {
        sqliteDb.exec(`ALTER TABLE visits ADD COLUMN ${col} TEXT`);
      } catch {
        // Column already exists
      }
    }

    return sqliteDb;
  } catch {
    return createInMemoryDbAdapter();
  }
}

const db = initializeDatabase();

/**
 * Lightweight, bounded corroboration ledger keyed by event_id (page load id). Identify records
 * a passive entry here; the corroboration endpoint upgrades it to 1 only for a clean, fresh
 * stored visit. Kept in-process so it never adds a Durable Object row write.
 */
interface CorroborationEntry {
  eventId: string;
  visitorId: string;
  createdAtMs: number;
  bot: string;
  tamperingDetected: boolean;
  corroborated: boolean;
}
const CORROBORATION_MAX_ENTRIES = 5000;
const corroborationLedger = new Map<string, CorroborationEntry>();
function rememberPassiveVisit(entry: CorroborationEntry): void {
  if (corroborationLedger.size >= CORROBORATION_MAX_ENTRIES) {
    const oldest = corroborationLedger.keys().next().value;
    if (oldest) corroborationLedger.delete(oldest);
  }
  corroborationLedger.set(entry.eventId, entry);
}

/* -------------------------------------------------------------------------- */
/* In-memory sliding-window rate limit for identify / corroborate              */
/* -------------------------------------------------------------------------- */

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 60;
const RATE_LIMIT_MAX_KEYS = 5000;
const rateLimitBuckets = new Map<string, number[]>();

function isLoopbackAddress(candidate: string | null | undefined): boolean {
  const ip = normalizeIpCandidate(candidate);
  if (!ip) return false;
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1' || ip === '::' || ip === '0:0:0:0:0:0:0:0') {
    return true;
  }
  return /^127\./.test(ip) || ip === '127.0.0.1' || ip.toLowerCase() === 'localhost';
}

function rateLimitClientKey(req: express.Request): string {
  const { ip: routedIp } = extractVisitorIp(req);
  if (routedIp && routedIp !== 'Unavailable') return `ip:${routedIp}`;
  const socketIp = normalizeIpCandidate(req.socket?.remoteAddress);
  return socketIp ? `socket:${socketIp}` : 'unknown';
}

/** Express middleware: bounded per-client sliding window with a numeric Retry-After. */
export function identifyRateLimit(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  if (process.env.INTEL_DISABLE_RATE_LIMIT === '1') {
    next();
    return;
  }
  const forwarded = readRequestHeader(req.headers as RawHeaderBag, 'x-forwarded-for');
  const directCandidates = [
    req.socket?.remoteAddress,
    req.ip,
    forwarded.split(',')[0],
    readRequestHeader(req.headers as RawHeaderBag, 'x-real-ip'),
  ];
  // Loopback callers (local dev, health checks, unit tests) are never throttled. A client that
  // supplies a public routed IP via a trusted edge header is throttled on that IP instead.
  if (
    directCandidates.some((candidate) => isLoopbackAddress(candidate)) &&
    !isPublicRoutableIp(normalizeIpCandidate(forwarded.split(',')[0]))
  ) {
    next();
    return;
  }

  const key = rateLimitClientKey(req);
  const now = Date.now();
  const recent = (rateLimitBuckets.get(key) ?? []).filter(
    (timestamp) => now - timestamp < RATE_LIMIT_WINDOW_MS
  );
  if (recent.length >= RATE_LIMIT_MAX_REQUESTS) {
    const oldest = recent[0] ?? now;
    const retryAfter = Math.max(1, Math.ceil((oldest + RATE_LIMIT_WINDOW_MS - now) / 1000));
    res.setHeader('Retry-After', String(retryAfter));
    res.status(429).json({
      error: 'Too Many Requests',
      retry_after_seconds: retryAfter,
    });
    return;
  }
  recent.push(now);
  if (rateLimitBuckets.size >= RATE_LIMIT_MAX_KEYS) {
    const oldestKey = rateLimitBuckets.keys().next().value;
    if (oldestKey) rateLimitBuckets.delete(oldestKey);
  }
  rateLimitBuckets.set(key, recent);
  next();
}

function signVisitorId(visitorId: string): string {
  return crypto.createHmac('sha256', HMAC_SECRET).update(visitorId).digest('hex');
}

function verifyVisitorToken(visitorId: string | undefined | null, token: string | undefined | null): boolean {
  if (!visitorId || !token || typeof visitorId !== 'string' || typeof token !== 'string') {
    return false;
  }
  const expected = signVisitorId(visitorId);
  if (expected.length !== token.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(token, 'hex'));
  } catch {
    return false;
  }
}

function computeHistoryBackupSignature(
  visitorId: string,
  totalVisits: number,
  totalSessions: number,
  firstVisitUtc: string,
  visits: VisitHistoryRecord[],
  legacyDigest = false
): string {
  const visitDigest = visits
    .map((v) =>
      legacyDigest
        ? `${v.visitId}:${v.sessionId}:${v.visitedAtUtc}:${v.publicIp}`
        : `${v.visitId}:${v.sessionId}:${v.visitedAtUtc}:${v.publicIp}:${
            typeof v.suspectScore === 'number' ? v.suspectScore : 0
          }:${v.riskLevel ?? 'Low'}:${v.botName ?? ''}`
    )
    .join('|');
  const payload = `hist:${visitorId}:${totalVisits}:${totalSessions}:${firstVisitUtc}:${visitDigest}`;
  return crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
}

function createSignedHistoryBackup(
  visitorId: string,
  totalVisits: number,
  totalSessions: number,
  firstVisitUtc: string,
  visits: VisitHistoryRecord[],
  hardwareId?: string
): SignedHistoryBackup {
  const compactVisits = visits.slice(0, 35);
  const signature = computeHistoryBackupSignature(
    visitorId,
    totalVisits,
    totalSessions,
    firstVisitUtc,
    compactVisits
  );
  return {
    visitorId,
    hardwareId,
    totalVisits,
    totalSessions,
    firstVisitUtc,
    visits: compactVisits,
    signature,
  };
}

function verifySignedHistoryBackup(
  expectedVisitorId: string,
  backup: SignedHistoryBackup | null | undefined
): boolean {
  if (
    !backup ||
    typeof backup !== 'object' ||
    backup.visitorId !== expectedVisitorId ||
    typeof backup.signature !== 'string' ||
    typeof backup.totalVisits !== 'number' ||
    typeof backup.totalSessions !== 'number' ||
    typeof backup.firstVisitUtc !== 'string' ||
    !Array.isArray(backup.visits)
  ) {
    return false;
  }
  const expectedSig = computeHistoryBackupSignature(
    backup.visitorId,
    backup.totalVisits,
    backup.totalSessions,
    backup.firstVisitUtc,
    backup.visits
  );
  // Backups minted before score persistence used the shorter digest. Accept either so an
  // existing visitor is never dropped after deploying this change.
  const legacySig = computeHistoryBackupSignature(
    backup.visitorId,
    backup.totalVisits,
    backup.totalSessions,
    backup.firstVisitUtc,
    backup.visits,
    true
  );
  const matches = [expectedSig, legacySig].some((candidate) => {
    if (candidate.length !== backup.signature.length) return false;
    try {
      return crypto.timingSafeEqual(
        Buffer.from(candidate, 'hex'),
        Buffer.from(backup.signature, 'hex')
      );
    } catch {
      return false;
    }
  });
  return matches;
}

function generateVisitorId(): string {
  return 'vid_' + crypto.randomBytes(10).toString('hex');
}

function generateSessionId(): string {
  return 'ses_' + crypto.randomBytes(6).toString('hex');
}

function generateVisitId(): string {
  return 'vst_' + crypto.randomBytes(8).toString('hex');
}

export function normalizeIpCandidate(raw: string | undefined | null): string | null {
  if (!raw || typeof raw !== 'string') return null;
  let candidate = raw.trim().replace(/^["']|["']$/g, '');
  if (!candidate) return null;

  if (candidate.toLowerCase().startsWith('for=')) {
    candidate = candidate.slice(4).trim().replace(/^["']|["']$/g, '');
  }

  if (candidate.startsWith('[')) {
    const closeBracket = candidate.indexOf(']');
    if (closeBracket !== -1) {
      candidate = candidate.slice(1, closeBracket);
    }
  } else {
    const colonCount = (candidate.match(/:/g) || []).length;
    if (colonCount === 1 && candidate.includes('.')) {
      candidate = candidate.split(':')[0];
    }
  }

  if (candidate.toLowerCase().startsWith('::ffff:')) {
    candidate = candidate.slice(7);
  }

  const zoneIdx = candidate.indexOf('%');
  if (zoneIdx !== -1) {
    candidate = candidate.slice(0, zoneIdx);
  }

  const ipVersion = net.isIP(candidate);
  if (ipVersion === 0) return null;
  return candidate;
}

export function isPublicRoutableIp(ip: string | null): boolean {
  if (!ip) return false;
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split('.').map((n) => parseInt(n, 10));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false;
    return true;
  }

  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::' || lower === '0:0:0:0:0:0:0:1' || lower === '0:0:0:0:0:0:0:0') {
      return false;
    }
    if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
      return false;
    }
    if (lower.startsWith('fc') || lower.startsWith('fd')) {
      return false;
    }
    if (lower.startsWith('ff')) {
      return false;
    }
    return true;
  }

  return false;
}

export function extractVisitorIp(req: express.Request): { ip: string; isPublic: boolean } {
  // Trust order matters. `cf-connecting-ip` is written by Cloudflare and cannot be set by
  // the client, so it is checked first. Vercel's forwarded headers are platform-written but
  // only when the request actually came through Vercel. Everything a client can freely send
  // (`x-real-ip`, `x-client-ip`, an arbitrary `x-forwarded-for`) is checked later and is
  // never allowed to outrank a platform-verified address.
  const singleHeaders = [
    'cf-connecting-ip',
    'x-vercel-forwarded-for',
    'x-vercel-proxied-for',
  ];

  for (const headerName of singleHeaders) {
    const rawVal = req.headers[headerName];
    if (typeof rawVal === 'string' && rawVal.trim()) {
      const firstHop = rawVal.split(',')[0];
      const normalized = normalizeIpCandidate(firstHop);
      if (normalized && isPublicRoutableIp(normalized)) {
        return { ip: normalized, isPublic: true };
      }
    }
  }

  const xff = req.headers['x-forwarded-for'];
  const xffList = Array.isArray(xff) ? xff.join(',') : typeof xff === 'string' ? xff : '';
  if (xffList) {
    const hops = xffList.split(',');
    for (const hop of hops) {
      const normalized = normalizeIpCandidate(hop);
      if (normalized && isPublicRoutableIp(normalized)) {
        return { ip: normalized, isPublic: true };
      }
    }
  }

  const forwarded = req.headers['forwarded'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    const segments = forwarded.split(/[,;]/);
    for (const seg of segments) {
      if (seg.trim().toLowerCase().startsWith('for=')) {
        const normalized = normalizeIpCandidate(seg.trim());
        if (normalized && isPublicRoutableIp(normalized)) {
          return { ip: normalized, isPublic: true };
        }
      }
    }
  }

  const fallbackHeaders = ['x-real-ip', 'x-client-ip', 'x-appengine-user-ip'];
  for (const headerName of fallbackHeaders) {
    const rawVal = req.headers[headerName];
    if (typeof rawVal === 'string' && rawVal.trim()) {
      const normalized = normalizeIpCandidate(rawVal.split(',')[0]);
      if (normalized && isPublicRoutableIp(normalized)) {
        return { ip: normalized, isPublic: true };
      }
    }
  }

  const socketIp = normalizeIpCandidate(req.socket?.remoteAddress);
  if (socketIp && isPublicRoutableIp(socketIp)) {
    return { ip: socketIp, isPublic: true };
  }

  return { ip: 'Unavailable', isPublic: false };
}

/**
 * Formats recognizable ISP names (Jio, Airtel, BSNL, ACT, Vodafone Idea, etc.)
 * strictly when the geolocation provider's ISP or Organization string identifies them.
 * Never guesses based on country, city, or IP prefix.
 */
export function normalizeIspAndOrg(
  rawIspInput: unknown,
  rawOrgInput: unknown,
  rawAsnInput: unknown,
  explicitHostingOrVpnFlag = false
): {
  isp: string;
  org: string;
  asn: string;
  isVpnOrHosting: boolean;
} {
  let cleanIsp = typeof rawIspInput === 'string' ? rawIspInput.trim() : '';
  let cleanOrg = typeof rawOrgInput === 'string' ? rawOrgInput.trim() : '';
  let cleanAsn = '';

  if (typeof rawAsnInput === 'number' && Number.isFinite(rawAsnInput)) {
    cleanAsn = `AS${rawAsnInput}`;
  } else if (typeof rawAsnInput === 'string' && rawAsnInput.trim()) {
    const trimmedAsn = rawAsnInput.trim();
    cleanAsn = /^AS\d+/i.test(trimmedAsn) ? trimmedAsn.toUpperCase() : `AS${trimmedAsn}`;
  }

  // Strip leading AS number if embedded in org string (e.g. "AS55836 Reliance Jio Infocomm Limited")
  const stripEmbeddedAsn = (text: string): { asnFound: string; rest: string } => {
    const match = text.match(/^(AS\d+)\s+(.+)$/i);
    if (match) {
      return { asnFound: match[1].toUpperCase(), rest: match[2].trim() };
    }
    return { asnFound: '', rest: text };
  };

  if (cleanIsp) {
    const parsed = stripEmbeddedAsn(cleanIsp);
    if (!cleanAsn && parsed.asnFound) cleanAsn = parsed.asnFound;
    cleanIsp = parsed.rest;
  }
  if (cleanOrg) {
    const parsed = stripEmbeddedAsn(cleanOrg);
    if (!cleanAsn && parsed.asnFound) cleanAsn = parsed.asnFound;
    cleanOrg = parsed.rest;
  }

  const combinedSource = `${cleanIsp} ${cleanOrg}`.trim();
  if (!combinedSource || combinedSource.toLowerCase() === 'unknown') {
    return {
      isp: 'Unknown',
      org: 'Unknown',
      asn: cleanAsn || 'Unknown',
      isVpnOrHosting: explicitHostingOrVpnFlag,
    };
  }

  const lower = combinedSource.toLowerCase();
  let recognizableBrand: string | null = null;

  if (/\bjio\b|reliance jio/i.test(combinedSource)) {
    recognizableBrand = 'Jio';
  } else if (/\bairtel\b|bharti airtel|bharti hexacom/i.test(combinedSource)) {
    recognizableBrand = 'Airtel';
  } else if (/\bbsnl\b|bharat sanchar|national internet backbone/i.test(combinedSource)) {
    recognizableBrand = 'BSNL';
  } else if (/\bact\b|act fibernet|atria convergence|beam telecom/i.test(combinedSource)) {
    recognizableBrand = 'ACT';
  } else if (/vodafone idea|\bvodafone\b|\bidea cellular\b/i.test(combinedSource)) {
    recognizableBrand = 'Vodafone Idea';
  } else if (/tata play fiber|tata teleservices|tata communications/i.test(combinedSource)) {
    recognizableBrand = 'Tata';
  } else if (/\bhathway\b/i.test(combinedSource)) {
    recognizableBrand = 'Hathway';
  } else if (/\bexcitel\b/i.test(combinedSource)) {
    recognizableBrand = 'Excitel';
  } else if (/\bmtnl\b|mahanagar telephone/i.test(combinedSource)) {
    recognizableBrand = 'MTNL';
  } else if (/\brailwire\b|\brailtel\b/i.test(combinedSource)) {
    recognizableBrand = 'RailWire';
  } else if (/\byou broadband\b/i.test(combinedSource)) {
    recognizableBrand = 'YOU Broadband';
  } else if (/\basianet\b/i.test(combinedSource)) {
    recognizableBrand = 'Asianet';
  } else if (/\balliance broadband\b/i.test(combinedSource)) {
    recognizableBrand = 'Alliance Broadband';
  }

  const primaryProvider = cleanIsp || cleanOrg;
  let formattedIsp = primaryProvider;

  if (recognizableBrand) {
    if (primaryProvider.toLowerCase() === recognizableBrand.toLowerCase()) {
      formattedIsp = recognizableBrand;
    } else {
      formattedIsp = `${recognizableBrand} (${primaryProvider})`;
    }
  }

  const hostingOrVpnKeywords = [
    'google',
    'gcp',
    'as15169',
    'as396982',
    'mullvad',
    'nordvpn',
    'expressvpn',
    'protonvpn',
    'surfshark',
    'cyberghost',
    'm247',
    'datacamp',
    'tzulo',
    'digitalocean',
    'linode',
    'vultr',
    'choopa',
    'hetzner',
    'ovh',
    'leaseweb',
    'amazon',
    'aws',
    'cloudflare',
    'microsoft corporation',
    'azure',
    'oracle',
    'akamai',
    'fastly',
    'zscaler',
    'netskope',
    'palo alto networks',
  ];

  const asnAndSourceLower = `${lower} ${(cleanAsn || '').toLowerCase()}`;
  const isVpnOrHosting =
    explicitHostingOrVpnFlag || hostingOrVpnKeywords.some((kw) => asnAndSourceLower.includes(kw));

  return {
    isp: formattedIsp || 'Unknown',
    org: cleanOrg || cleanIsp || 'Unknown',
    asn: cleanAsn || 'Unknown',
    isVpnOrHosting,
  };
}

/** ASN numbers of the major cloud / hosting providers used by the network classification. */
const CLOUD_PROVIDER_ASN_NUMBERS = new Set<number>([
  396178, 15169, 16509, 14618, 13335, 14061, 9009, 60068, 24940, 63949, 16276, 8075, 20473,
  11878, // Tzulo — hosting network rented by VPN providers, not a VPN operator itself
  212238, // CDNEXT / Datacamp — hosting network, not a VPN operator itself
]);

/**
 * Public Tor relay operators. An address routed through one of these ASNs is anonymity
 * infrastructure even before any DNS answer arrives, so the network badge must never present
 * it as consumer broadband.
 */
const TOR_OPERATOR_ASN_SET = new Set<string>([
  'AS215125', // Church of Cyberology / Nothing to Hide
  'AS60729', // Zwiebelfreunde e.V. / Torservers.net
  'AS208323', // Foundation for Applied Privacy
  'AS396507', // Emerald Onion
  'AS200052', // Artikel10 e.V.
  'AS206848', // CCC Stuttgart / Chaos Computer Club
  'AS205100', // F3 Netze e.V.
  'AS199695', // Nos Oignons
]);

const TOR_OPERATOR_ORG_PATTERN =
  /\b(church of cyberology|cyberology|nothing to hide|nothingtohide|hart voor internetvrijheid|zwiebelfreunde|torservers|emerald onion|emeraldonion|applied privacy|applied-privacy|nos oignons|nos-oignons|artikel10|f3\s?netze|ccc stuttgart|r0cket|tor\s?exit|tor\s?relay)\b/i;

/** Prefixes dedicated to Tor relay operators. */
const TOR_OPERATOR_IPV4_CIDRS = ['192.42.116.0/24'];
const TOR_OPERATOR_IPV6_PREFIXES = ['2001:67c:e60::/48', '2a02:898:256::/48'];

/** Reverse-DNS hostnames that only Tor relay operators publish. */
const TOR_OPERATOR_REVERSE_DNS_PATTERN =
  /\b(tor-?exit|tor-?relay|exit-?node|nothingtohide\.nl|hartvoorinternetvrijheid\.nl|cyberology\.(nl|church)|torservers\.net|emeraldonion\.org|applied-privacy\.net|artikel10\.org|nos-oignons\.net|tor\.r0cket\.net)\b/i;

// Provider-owned VPN / privacy brands and ASNs (Proton AG, Mullvad's 31173 Services AB,
// NordVPN / PacketHub, Surfshark / Cyberzone, ...) are genuine commercial VPNs. Generic
// hosting operators are deliberately NOT listed here — see HOSTING_EGRESS_PATTERN below.
const VPN_PROXY_PATTERN =
  /\b(vpn|nordvpn|expressvpn|surfshark|cyberghost|cyberzone|private internet access|proton(?:\s?vpn)?|mullvad|31173|windscribe|ipvanish|hide\.?me|hola vpn|psiphon|packet hub|packethub|tor ?guard|proxy|socks5|smart dns)\b/i;

/**
 * General hosting / datacenter / CDN operators that commonly RENT capacity to VPN services but
 * are NOT commercial VPN providers themselves (2026 cross-check: Netify, GeoIPHub, iplogs,
 * AbstractAPI). A match here must keep the egress a datacenter result — `public_vpn` is reserved
 * for provider-run ASNs (Proton AG, Mullvad/31173, NordVPN/PacketHub, Surfshark/Cyberzone, ...).
 */
const HOSTING_EGRESS_PATTERN =
  /\b(m247|datacamp|cdnext|tzulo|cloudflare|amazonaws|amazon|aws|google cloud|google llc|azure|microsoft|digitalocean|hetzner|linode|ovh|choopa|vultr|leaseweb|hostinger|contabo|akamai|oracle cloud|alibaba|aliyun|tencent cloud|latitude|hosting|hosted|datacenter|data center|cloud)\b/i;

// Indian carriers (Jio / Airtel) are intentionally absent: their branded consumer rules label
// them as Residential Broadband, and the mobile step must not pre-empt those.
const MOBILE_CARRIER_PATTERN =
  /\b(mobile|cellular|wireless|5g|4g|lte|t-mobile|tmobile|verizon wireless|cellco|vodafone|orange s\.?a|telefonica|movistar|claro|tim s\.?p\.?a|mtn)\b/i;

function matchesTorOperatorAsn(asn: string): boolean {
  const clean = typeof asn === 'string' ? asn.trim().toUpperCase() : '';
  if (!clean) return false;
  return TOR_OPERATOR_ASN_SET.has(clean.startsWith('AS') ? clean : `AS${clean}`);
}

/**
 * Server-side mirror of the collector's ISP brand and network-type classifier (Task 1).
 *
 * Intentionally a self-contained copy so the Node API bundle never imports the browser
 * collector module; brand names, network types and consumer / hosting flags must match
 * the client helper exactly. Consumer broadband rules are evaluated BEFORE the
 * cloud / datacenter rule so that e.g. Google Fiber (AS16591) is never swallowed by the
 * generic 'google' cloud keywords.
 *
 * Classification priority is strict and descending: consumer broadband is only ever returned
 * when the ISP positively matches an explicit consumer ISP rule. Every unrecognised network
 * falls back to 'Standard Network' (brand 'Unresolved Network') — never to
 * 'Residential Broadband' or an anonymity label.
 */
export function classifyIspNetwork(isp: string, org: string, asn: string): IspNetworkClassification {
  const cleanIsp = typeof isp === 'string' ? isp.trim() : '';
  const cleanOrg = typeof org === 'string' ? org.trim() : '';
  const cleanAsn = typeof asn === 'string' ? asn.trim().toUpperCase() : '';
  const keywordHaystack = `${cleanIsp} ${cleanOrg}`;

  const asnNumbers = new Set<number>();
  const asnTokenRegex = /\bAS(\d{1,10})\b/gi;
  let asnTokenMatch: RegExpExecArray | null;
  while ((asnTokenMatch = asnTokenRegex.exec(`${cleanAsn} ${keywordHaystack}`)) !== null) {
    const parsedAsn = Number.parseInt(asnTokenMatch[1], 10);
    if (Number.isFinite(parsedAsn)) asnNumbers.add(parsedAsn);
  }

  const matchConsumerRule = (
    brand: string,
    networkType: IspNetworkClassification['networkType'],
    asns: number[],
    keywords: RegExp | null
  ): IspNetworkClassification | null => {
    const asnHit = asns.find((a) => asnNumbers.has(a));
    const keywordHit = keywords !== null && keywords.test(keywordHaystack);
    if (asnHit === undefined && !keywordHit) return null;
    return {
      brandName: brand,
      networkType,
      isConsumerBroadband: true,
      isDatacenterOrHosting: false,
      matchedReason:
        asnHit !== undefined ? `ASN AS${asnHit}` : `ISP metadata keyword ${String(keywords)}`,
    };
  };

  // Branded consumer rules are closures so each family can be evaluated at its exact priority
  // slot (mobile home / satellite / residential) after Tor, cloud, VPN and mobile verdicts.
  const mobileHomeMatch = (): IspNetworkClassification | null =>
    matchConsumerRule('Verizon 5G Home', 'Cellular / 5G', [6167, 22394], /cellco|verizon wireless/i) ||
    matchConsumerRule('T-Mobile 5G Home', 'Cellular / 5G', [21928], /t-mobile|tmobile/i);

  const satelliteMatch = (): IspNetworkClassification | null =>
    matchConsumerRule('Starlink (SpaceX)', 'Satellite', [14593], /starlink|spacex/i);

  const residentialMatch = (): IspNetworkClassification | null =>
    // US consumer broadband (Residential Broadband)
    matchConsumerRule('Xfinity (Comcast)', 'Residential Broadband', [7922, 7015, 7016], /comcast|xfinity/i) ||
    matchConsumerRule('Spectrum (Charter)', 'Residential Broadband', [20115, 11426, 10796], /charter|spectrum/i) ||
    matchConsumerRule('AT&T Fiber', 'Residential Broadband', [7018, 20057], /at&t|att services|sbcglobal/i) ||
    matchConsumerRule('Verizon Fios', 'Residential Broadband', [701, 19262], /fios|mci communications|verizon online/i) ||
    matchConsumerRule('Optimum', 'Residential Broadband', [6128, 19108], /optimum|cablevision|altice|suddenlink/i) ||
    matchConsumerRule('Cox', 'Residential Broadband', [22773], /\bcox\b/i) ||
    matchConsumerRule('Frontier / CenturyLink', 'Residential Broadband', [5650, 209], null) ||
    matchConsumerRule('Google Fiber', 'Residential Broadband', [16591], /google fiber|gfiber/i) ||
    // India consumer broadband (Residential Broadband)
    matchConsumerRule('Jio (Reliance Jio)', 'Residential Broadband', [55836], /reliance jio|\bjio\b/i) ||
    matchConsumerRule('Airtel Xstream', 'Residential Broadband', [24560, 45609, 9498], /bharti airtel|\bairtel\b/i) ||
    matchConsumerRule('ACT Fibernet', 'Residential Broadband', [24309], /act fibernet|atria convergence/i) ||
    matchConsumerRule('BSNL Broadband', 'Residential Broadband', [9829], /\bbsnl\b|bharat sanchar/i) ||
    matchConsumerRule('Tata Play / Hathway', 'Residential Broadband', [], /tata play|tata sky broadband|hathway|excitel/i);

  // Tor relay operators, before any hosting rule: anonymity infrastructure must never be
  // reported as a consumer connection or a generic cloud host.
  // Tor relay operators run their relays on their own hosting ASNs. An ASN / organisation
  // match is NOT proof that this visitor is on the Tor network, so the operator is labelled
  // neutrally here. Only a verified exit verdict (`torDetection.isTorExit === true`) may
  // upgrade the network type to `Tor Exit / Anonymity Network` in applyNetworkOverrides.
  const asnTokenHits = Array.from(asnNumbers).map((n) => `AS${n}`);
  const torAsnHit = asnTokenHits.find((token) => matchesTorOperatorAsn(token));
  const torOrgHit = TOR_OPERATOR_ORG_PATTERN.test(keywordHaystack);
  if (torAsnHit !== undefined || torOrgHit) {
    return {
      brandName:
        cleanIsp && !/^unknown( isp)?$/i.test(cleanIsp)
          ? cleanIsp
          : cleanOrg && !/^unknown( isp)?$/i.test(cleanOrg)
          ? cleanOrg
          : 'Tor Relay Operator',
      networkType: 'Cloud / Datacenter',
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason:
        torAsnHit !== undefined ? `Tor operator ASN ${torAsnHit}` : 'Tor operator organisation',
    };
  }

  // Cloud / datacenter — only reached when no consumer rule matched above.
  const cloudAsnHit = Array.from(asnNumbers).find((n) => CLOUD_PROVIDER_ASN_NUMBERS.has(n));
  const cloudKeywords =
    /google llc|google cloud|amazonaws|cloudflare|digitalocean|hetzner|m247|datacamp|datapacket|cdnext|cdn77|tzulo|linode|ovh|choopa|vultr|leaseweb|hostinger|contabo|akamai|oracle cloud|alibaba|aliyun|tencent cloud/i;
  if (cloudAsnHit !== undefined || cloudKeywords.test(keywordHaystack)) {
    return {
      // Prefer the real operator name (Google LLC, Amazon.com, Inc., Microsoft
      // Corporation, Cloudflare, Inc.) so an unresolved provider lookup never surfaces a
      // generic or anonymous cloud label.
      brandName:
        cloudProviderOrgForAsn(`AS${cloudAsnHit ?? ''}`) ||
        (cleanIsp && !/^unknown( isp)?$/i.test(cleanIsp)
          ? cleanIsp
          : cleanOrg && !/^unknown( isp)?$/i.test(cleanOrg)
          ? cleanOrg
          : 'Cloud Provider / Datacenter'),
      networkType: 'Cloud / Datacenter',
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason:
        cloudAsnHit !== undefined
          ? `ASN AS${cloudAsnHit}`
          : `ISP metadata keyword ${String(cloudKeywords)}`,
    };
  }

  // Commercial VPN / privacy proxy.
  if (VPN_PROXY_PATTERN.test(keywordHaystack)) {
    return {
      brandName: cleanIsp || cleanOrg || 'VPN / Proxy Provider',
      networkType: 'VPN / Proxy Relay',
      isConsumerBroadband: false,
      isDatacenterOrHosting: false,
      matchedReason: 'VPN / proxy provider keyword',
    };
  }

  // Mobile carrier — branded 5G home products keep their Sharp 'Cellular / 5G' label.
  const mobileHome = mobileHomeMatch();
  if (mobileHome) return mobileHome;
  if (MOBILE_CARRIER_PATTERN.test(keywordHaystack)) {
    return {
      brandName: cleanIsp || cleanOrg || 'Mobile Carrier',
      networkType: 'Mobile Carrier',
      isConsumerBroadband: false,
      isDatacenterOrHosting: false,
      matchedReason: 'Cellular carrier keyword',
    };
  }

  // Satellite consumer links.
  const satellite = satelliteMatch();
  if (satellite) return satellite;

  // Residential broadband — ONLY on a positive branded / ASN match, never as a default.
  const residential = residentialMatch();
  if (residential) return residential;

  // Unknown / unrecognised network: never claim residential broadband without positive proof.
  // A known numeric ASN is labelled `AS<number>`; "Standard Network" is reserved for a
  // request where no network identity exists at all.
  return {
    brandName:
      cleanIsp && !/^(unknown|unknown isp|n\/a)$/i.test(cleanIsp)
        ? cleanIsp
        : cleanOrg && !/^(unknown|unknown isp|n\/a)$/i.test(cleanOrg)
        ? cleanOrg
        : asnTokenHits[0] ?? 'Standard Network',
    networkType: 'Standard Network',
    isConsumerBroadband: false,
    isDatacenterOrHosting: false,
    matchedReason: null,
  };
}

/**
 * Reconciles the operator-level classification with the verdicts produced by the Tor, AI-agent
 * and VM engines. Priority is strict: Tor anonymity > AI agent cloud > datacenter/VM > VPN >
 * mobile > residential > unknown.
 */
function applyNetworkOverrides(
  base: IspNetworkClassification,
  context: {
    torExit: boolean;
    torOperatorHint: boolean;
    isTorBrowserClient: boolean;
    aiAgentDetected: boolean;
    datacenterVm: boolean;
    vpnSuspected: boolean;
  }
): IspNetworkClassification {
  // Strict: an anonymity-network label requires a verified Tor exit verdict. An operator
  // ASN match or a Tor Browser fingerprint alone must never relabel a normal connection.
  const torNetwork = context.torExit;
  if (torNetwork) {
    return {
      ...base,
      networkType: 'Tor Exit / Anonymity Network',
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || 'Tor anonymity network',
    };
  }
  if (context.aiAgentDetected && base.networkType === 'Cloud / Datacenter') {
    return {
      ...base,
      networkType: 'AI Agent Cloud Network',
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || 'AI agent cloud infrastructure',
    };
  }
  if (context.datacenterVm && base.networkType !== 'Cloud / Datacenter') {
    return {
      ...base,
      networkType: 'Cloud / Datacenter',
      isConsumerBroadband: false,
      isDatacenterOrHosting: true,
      matchedReason: base.matchedReason || 'Cloud VM / masked GPU footprint',
    };
  }
  if (context.vpnSuspected && base.networkType === 'Residential Broadband') {
    return {
      ...base,
      networkType: 'VPN / Proxy Relay',
      isConsumerBroadband: false,
      matchedReason: base.matchedReason || 'VPN indicator on a residential line',
    };
  }
  if (base.networkType === 'Residential Broadband' && !base.isConsumerBroadband) {
    return { ...base, networkType: 'Standard Network' };
  }
  return base;
}

/* -------------------------------------------------------------------------- */
/* Phase 1 — bot / AI-agent subtype classification                            */
/* -------------------------------------------------------------------------- */

type RawHeaderBag = Record<string, string | string[] | undefined>;

interface BotClassification {
  subtype: BotSubtype;
  label: string;
  provider: string;
  category: string;
  confidence: number;
  reasons: string[];
}

interface BotNetworkIdentity {
  org?: string;
  isp?: string;
  asn?: string;
}

interface BotClientSignals {
  isBot?: boolean;
  isHeadless?: boolean;
  webdriver?: boolean;
  cdpDetected?: boolean;
  botSignals?: string[];
  /** Protocol-level CDP Runtime serialization leak reported by the page. */
  cdpRuntimeLeak?: boolean;
  /** Stealth plugin artifacts (non-native getters, iframe leak, proxy chain). */
  stealthPluginDetected?: boolean;
  /** A CDP / DevTools bridge is attached (developer-tools evidence, not a bot verdict). */
  developerTools?: boolean;
  /** Host runtime reported by the client: electron / ide_webview / headless_shell / vm / none. */
  automationEnvironment?: string;
  /** 0–1 client confidence that a real person drives the runtime. */
  humanCorroboration?: number;
  /** Client tamperingDetails.anti_detect_browser — hard proof of an anti-detect browser. */
  antiDetectBrowser?: boolean;
  /** Client tampering_ml_score; >= 0.5 is a hard automation escalation. */
  tamperingMlScore?: number;
  /** Automation-targeted tampering artifacts found in tamperingDetails.reasons / botSignals. */
  automationTargetedTampering?: boolean;
  /** The matched artifact strings, for the tile / risk detail. */
  automationTamperingReasons?: string[];
  /** Real async Web Bot Auth verification result (or page-attestation equivalent). */
  webBotAuth?: WbaVerification | null;
}

/** Reads a header case-insensitively, collapsing repeated headers into a comma list. */
function readRequestHeader(headers: RawHeaderBag | null | undefined, name: string): string {
  if (!headers) return '';
  const direct = headers[name.toLowerCase()];
  const raw = Array.isArray(direct) ? direct.join(', ') : direct;
  return typeof raw === 'string' ? raw.trim() : '';
}

/**
 * First-party proxy detection from request headers. A browser never talks to an origin through
 * an explicit proxy without one of these markers, so their presence is direct evidence that the
 * connection was relayed. Edge/CDN hops added by the hosting platform are excluded by name.
 */
function detectProxyHeaders(
  headers: RawHeaderBag | null | undefined,
  resolvedIp: string
): { detected: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (!headers) return { detected: false, reasons };

  if (readRequestHeader(headers, 'proxy-authorization')) {
    reasons.push('Proxy-Authorization header');
  }
  if (readRequestHeader(headers, 'proxy-connection')) {
    reasons.push('Proxy-Connection header');
  }

  // `Via` is added by forward and reverse proxies alike. The hosting edge uses its own product
  // names, which are removed here so a platform hop is never reported as a user proxy.
  const via = readRequestHeader(headers, 'via').toLowerCase();
  if (via && !/varnish|vegur|cloudflare|akamai|fastly|vercel|netlify/.test(via)) {
    reasons.push(`Via header (${via.slice(0, 80)})`);
  }

  // RFC 7239: a public `for=` address that is not the resolved client is an upstream relay.
  const forwarded = readRequestHeader(headers, 'forwarded');
  if (forwarded) {
    for (const segment of forwarded.split(/[,;]/)) {
      const match = /for="?\[?([0-9a-f:.]+)\]?"?/i.exec(segment.trim());
      const hop = match?.[1]?.replace(/^::ffff:/, '');
      if (hop && hop !== resolvedIp && isPublicRoutableIp(hop)) {
        reasons.push(`Forwarded header names upstream relay ${hop}`);
        break;
      }
    }
  }

  // A three-hop public chain cannot be produced by a single edge hop. Two public addresses are
  // the normal client + edge pair, so only longer chains are reported.
  const xff = readRequestHeader(headers, 'x-forwarded-for');
  if (xff) {
    const hops = new Set(
      xff
        .split(',')
        .map((hop) => normalizeIpCandidate(hop))
        .filter((hop): hop is string => Boolean(hop) && isPublicRoutableIp(hop))
    );
    if (hops.size >= 3) {
      reasons.push(`X-Forwarded-For chain with ${hops.size} public hops`);
    }
  }

  return { detected: reasons.length > 0, reasons };
}

/** Coarse browser / tool family used to compare a signed UA with the HTTP header. */
function detectUaFamily(userAgent: string): string {
  const ua = userAgent.toLowerCase();
  if (!ua) return '';
  if (/edg\//.test(ua)) return 'edge';
  if (/opr\/|opera/.test(ua)) return 'opera';
  if (/firefox\/|fxios/.test(ua)) return 'firefox';
  if (/chrome\/|crios|chromium\//.test(ua)) return 'chrome';
  if (/safari\//.test(ua)) return 'safari';
  if (/^curl\//.test(ua)) return 'curl';
  if (/postmanruntime/.test(ua)) return 'postman';
  if (/python-requests|python-urllib|aiohttp/.test(ua)) return 'python';
  if (/^wget\//.test(ua)) return 'wget';
  if (/^node-fetch|undici|axios/.test(ua)) return 'node';
  return '';
}

/** Coarse operating-system family used to compare a signed UA with the HTTP header. */
function detectUaOs(userAgent: string): string {
  const ua = userAgent.toLowerCase();
  if (/windows nt|win32|win64/.test(ua)) return 'windows';
  if (/android/.test(ua)) return 'android';
  if (/iphone|ipad|ipod/.test(ua)) return 'ios';
  if (/macintosh|mac os x/.test(ua)) return 'macos';
  if (/cros/.test(ua)) return 'chromeos';
  if (/linux|x11/.test(ua)) return 'linux';
  return '';
}

/**
 * Compares the HTTP User-Agent header with the signed payload UA. Edge proxies may
 * truncate long header values (Vercel cuts them at ~67 chars), so an exact match is not
 * required: a clean prefix relationship is the same client, otherwise the browser family
 * and OS must agree. Unknown signatures never trigger a tamper verdict.
 */
function userAgentsCompatible(headerUserAgent: string, payloadUserAgent: string): boolean {
  const header = headerUserAgent.trim();
  const payload = payloadUserAgent.trim();
  if (!header || !payload || header === payload) return true;
  const shorter = header.length <= payload.length ? header : payload;
  const longer = header.length <= payload.length ? payload : header;
  if (shorter.length >= 24 && longer.startsWith(shorter)) return true;
  const headerFamily = detectUaFamily(header);
  const payloadFamily = detectUaFamily(payload);
  if (headerFamily && payloadFamily && headerFamily !== payloadFamily) return false;
  const headerOs = detectUaOs(header);
  const payloadOs = detectUaOs(payload);
  if (headerOs && payloadOs && headerOs !== payloadOs) return false;
  return true;
}

const AUTOMATION_UA_PATTERN = /playwright|puppeteer|selenium|cypress|phantomjs/i;

const DATACENTER_NETWORK_PATTERN =
  /\b(amazon|amazonaws|aws|google cloud|azure|microsoft azure|digitalocean|hetzner|linode|akamai|ovh|vultr|oracle cloud|alibaba|aliyun|tencent|leaseweb|contabo|m247|choopa|datacamp)\b/i;

const KNOWN_AI_CRAWLER_REASON = 'LLM crawler user-agent signature';

/**
 * Phase 1 — resolves the request identity into one of `human`, `good_bot`, `ai_agent`
 * or `bad_bot`. A search-crawler UA is only trusted when the network identity matches the
 * crawler operator; every other claim of that UA is a spoof. Automation runtimes and
 * header-incomplete desktop browsers fall through to `bad_bot`. Never throws.
 */
function classifyBotTraffic(
  headers: RawHeaderBag | null | undefined,
  network: BotNetworkIdentity,
  client: BotClientSignals
): BotClassification {
  const ua = readRequestHeader(headers, 'user-agent');
  const acceptLanguage = readRequestHeader(headers, 'accept-language');
  const secFetchSite = readRequestHeader(headers, 'sec-fetch-site');
  const secFetchMode = readRequestHeader(headers, 'sec-fetch-mode');
  const secFetchDest = readRequestHeader(headers, 'sec-fetch-dest');
  const networkHaystack = [network.org, network.isp, network.asn]
    .filter((part): part is string => typeof part === 'string' && part.trim().length > 0)
    .join(' ');
  const clientSignals = Array.isArray(client.botSignals)
    ? client.botSignals.filter((s): s is string => typeof s === 'string' && s.trim().length > 0)
    : [];

  // HARD INVARIANT — a stealth / anti-detect runtime is proof of automation and must never be
  // labelled "Verified Human". These client artifacts are checked BEFORE every UA rule so no
  // crawler, agent or interactive-browser path can downgrade the verdict. `anti_detect_browser`
  // and a >= 0.5 tampering ML score arrive from the collector's browser-tampering assessment.
  //
  // A bare CDP Runtime leak is deliberately NOT in this set. Electron apps, IDE webviews
  // (VS Code, Cursor, OpenCode) and any Chromium with DevTools open expose it while a real
  // person is driving the session — Fingerprint Pro reports it as `developer_tools`, never as
  // `bot`. Only the WebDriver handshake, an automation UA, a spinning runtime binding, an
  // anti-detect footprint or stealth-plugin artifacts prove automation on their own.
  const hardAutomation = Boolean(
    client.stealthPluginDetected || client.antiDetectBrowser || client.automationTargetedTampering
  );
  if (hardAutomation) {
    const reasons: string[] = [];
    if (client.automationTargetedTampering) {
      reasons.push(
        `Automation-targeted tampering artifacts (${(client.automationTamperingReasons || []).slice(0, 2).join('; ') || 'webdriver / playwright / CDC / CDP getter wrappers'})`
      );
    }
    if (client.stealthPluginDetected) {
      reasons.push('Stealth plugin artifacts (rewritten native getters / iframe identity leak)');
    }
    if (client.antiDetectBrowser) {
      reasons.push('Anti-detect browser footprint (spoofed screen / patched navigator getters)');
    }
    if (typeof client.tamperingMlScore === 'number' && client.tamperingMlScore >= 0.5) {
      reasons.push(`Browser tampering ML score ${client.tamperingMlScore.toFixed(3)}`);
    }
    for (const signal of clientSignals.slice(0, 2)) reasons.push(signal);
    return {
      subtype: 'bad_bot',
      label: client.automationTargetedTampering
        ? 'Stealth Automation'
        : client.antiDetectBrowser
        ? 'Anti-Detect Browser'
        : client.stealthPluginDetected
        ? 'Puppeteer / Playwright Stealth'
        : 'HeadlessChrome / CDP Automation',
      provider: client.automationTargetedTampering
        ? 'Stealth Automation'
        : client.antiDetectBrowser
        ? 'Anti-Detect Browser'
        : client.stealthPluginDetected
        ? 'Stealth Automation (Puppeteer/Playwright)'
        : 'Chromium',
      category: 'Automation',
      confidence: 0.94,
      reasons: reasons.length > 0 ? reasons : ['Hard automation artifact reported by client'],
    };
  }

  for (const rule of GOOD_BOT_UA_RULES) {
    if (!rule.pattern.test(ua)) continue;
    if (rule.network.test(networkHaystack)) {
      return {
        subtype: 'good_bot',
        label: rule.label,
        provider: rule.provider,
        category: rule.category,
        confidence: 0.97,
        reasons: [
          `${rule.label} user-agent matched`,
          `Network identity (${networkHaystack || 'unknown'}) matches ${rule.provider}`,
        ],
      };
    }
    return {
      subtype: 'bad_bot',
      label: 'Spoofed Crawler',
      provider: `Unverified ${rule.provider} claim`,
      category: 'Spoofed Identity',
      confidence: 0.99,
      reasons: [
        `${rule.label} user-agent presented`,
        `Network identity (${networkHaystack || 'unknown'}) does not belong to ${rule.provider}`,
      ],
    };
  }

  for (const rule of AI_AGENT_UA_RULES) {
    if (!rule.pattern.test(ua)) continue;
    return {
      subtype: 'ai_agent',
      label: rule.label,
      provider: rule.provider,
      category: rule.provider === 'Cloud Browser Agent' ? 'Autonomous Agent' : 'AI Crawler',
      confidence: rule.provider === 'Cloud Browser Agent' ? 0.85 : 0.92,
      reasons: [
        `${rule.label} user-agent matched`,
        networkHaystack ? `Network identity: ${networkHaystack}` : 'Network identity unavailable',
      ],
    };
  }

  // RFC 9421 HTTP Message Signatures ("Web Bot Auth"): an agent that signs its request with a
  // `Signature` + `Signature-Input` pair is self-identifying as automated even when its
  // User-Agent imitates a desktop browser. Browsers never emit these headers. `keyid` names the
  // operator, so the tile can attribute it instead of printing a generic automation verdict.
  const signatureInput = readRequestHeader(headers, 'signature-input');
  const signatureHeader = readRequestHeader(headers, 'signature');
  if (signatureInput && signatureHeader) {
    const keyIdMatch = /keyid\s*=\s*"([^"]+)"/i.exec(signatureInput);
    const keyId = keyIdMatch ? keyIdMatch[1].trim().slice(0, 80) : '';
    // Header presence is NOT verification. Only a real Ed25519 result may attribute a named
    // operator; an unverified / spoofed signature is always reported as unattributed.
    const wba = client.webBotAuth;
    const verified = Boolean(wba?.verified);
    const namedOperator =
      verified && wba?.operator ? String(wba.operator) : 'Unattributed RFC 9421 Signer';
    return {
      subtype: 'ai_agent',
      label: 'Web Bot Auth Agent',
      provider: namedOperator,
      category: 'Autonomous Agent',
      confidence: verified ? 0.9 : 0.85,
      reasons: [
        verified
          ? 'RFC 9421 Web Bot Auth signature verified (tag=web-bot-auth, Ed25519)'
          : 'RFC 9421 Signature / Signature-Input headers present (Web Bot Auth) — signature NOT verified',
        keyId ? `Agent key identifier: ${keyId}` : 'Agent key identifier not published',
      ],
    };
  }

  const datacenterNetwork = DATACENTER_NETWORK_PATTERN.test(networkHaystack);  const automationRuntimeDetected = Boolean(client.webdriver || client.cdpDetected);
  if (automationRuntimeDetected && datacenterNetwork) {
    return {
      subtype: 'ai_agent',
      label: 'Cloud Browser Agent',
      provider: 'Cloud Browser Agent',
      category: 'Autonomous Agent',
      confidence: 0.78,
      reasons: [
        client.webdriver ? 'WebDriver runtime binding present' : 'CDP runtime binding present',
        `Datacenter ASN hosting the agent (${networkHaystack})`,
      ],
    };
  }

  // Stealth / anti-detect artifacts are resolved by the hard-automation gate at the top of this
  // function so they cannot be downgraded by any UA rule below.

  const isDesktopChromeOrSafari =
    /chrome\/|crios\/|safari\//i.test(ua) && !/mobile|android|iphone|ipad/i.test(ua);
  const missingFetchMetadata = !secFetchSite && !secFetchMode && !secFetchDest;
  // Only a UA that claims a real desktop browser but supplies neither a language nor any
  // fetch metadata is treated as automation. Requiring both keep older Safari builds (which
  // predate Sec-Fetch support) and language-stripping privacy setups out of the bot verdict.
  const headerAnomaly = isDesktopChromeOrSafari && missingFetchMetadata && !acceptLanguage;

  // A bare client `isBot` flag is not enough: old bundles could set it from a patched
  // Navigator getter. Require the flag to be corroborated by a runtime binding or a
  // headless user-agent before the server upgrades it to a bad-bot verdict.
  const headlessUa = /headlesschrome|phantomjs|slimerjs/i.test(ua);
  const corroboratedClientBot =
    Boolean(client.isBot) && Boolean(client.webdriver || client.cdpDetected || headlessUa);
  if (
    corroboratedClientBot ||
    client.webdriver ||
    client.cdpDetected ||
    AUTOMATION_UA_PATTERN.test(ua) ||
    headerAnomaly
  ) {
    const reasons: string[] = [];
    if (client.isBot) reasons.push('Client reported an automated runtime');
    if (client.webdriver) reasons.push('WebDriver handshake detected');
    if (client.cdpDetected) reasons.push('Chrome DevTools Protocol binding detected');
    if (AUTOMATION_UA_PATTERN.test(ua)) reasons.push('Automation framework signature in user-agent');
    if (headerAnomaly) {
      reasons.push('Desktop browser user-agent without accept-language or sec-fetch metadata');
    }
    for (const signal of clientSignals.slice(0, 2)) reasons.push(signal);
    return {
      subtype: 'bad_bot',
      label: AUTOMATION_UA_PATTERN.test(ua) ? 'Automation Runtime' : 'Automation / Header Anomaly',
      provider: 'Unattributed Automation',
      category: 'Automation',
      confidence: client.isBot || automationRuntimeDetected ? 0.93 : 0.7,
      reasons: reasons.length > 0 ? reasons : ['Automated traffic signature detected'],
    };
  }

  const developerToolsAttached = Boolean(
    client.developerTools ||
      client.cdpRuntimeLeak ||
      client.automationEnvironment === 'electron' ||
      client.automationEnvironment === 'ide_webview'
  );
  return {
    subtype: 'human',
    label: 'Verified Human',
    provider: 'None',
    category: developerToolsAttached ? 'Developer Tools' : 'Human Interaction',
    confidence: 0.6,
    reasons: developerToolsAttached
      ? [
          'Interactive browser profile without automation signatures',
          `Developer tools attached (${client.automationEnvironment || 'cdp'}) — informational`,
        ]
      : ['Interactive browser profile without automation signatures'],
  };
}

/* -------------------------------------------------------------------------- */
/* Phase 1b — AI agent attribution                                             */
/*   official CIDR sync (OpenAI / Google JSON) + RFC 9421 Web Bot Auth + FCrDNS */
/* -------------------------------------------------------------------------- */

const AI_BOT_CIDR_SYNC_INTERVAL_MS = 6 * 60 * 60 * 1000;
const AI_BOT_CIDR_TIMEOUT_MS = 10000;
const AI_AUTH_DIRECTORY_TIMEOUT_MS = 1500;
const AI_AUTH_DIRECTORY_TTL_MS = 60 * 60 * 1000;
const AI_FORWARD_DNS_TIMEOUT_MS = 1200;
const AI_FORWARD_DNS_TTL_MS = 60 * 60 * 1000;
const AI_VERDICT_TABLE_MAX_ENTRIES = 10000;

// Seeded from the registry's pinned prefixes so the first request already has verification data.
let aiBotPrefixTable = new Map<string, string[]>(pinnedPrefixEntries());
let aiBotCidrLastSyncMs = 0;
let aiBotCidrSyncInFlight: Promise<void> | null = null;
let aiBotCidrTimer: ReturnType<typeof setInterval> | null = null;

const aiAuthDirectoryCache = new Map<
  string,
  { clientName: string; trigger: string | null; expiresAtMs: number }
>();
const aiForwardConfirmedDnsCache = new Map<string, { names: string[]; expiresAtMs: number }>();

/** Extracts every `ipv4Prefix` / `ipv6Prefix` / `prefix` from a Google/OpenAI JSON payload. */
export function extractAiPrefixes(payload: unknown): string[] {
  const prefixes: string[] = [];
  const visit = (value: unknown, depth: number): void => {
    if (depth > 4 || value === null || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    const record = value as Record<string, unknown>;
    for (const key of ['ipv4Prefix', 'ipv6Prefix', 'prefix']) {
      const raw = record[key];
      if (typeof raw === 'string' && raw.includes('/')) prefixes.push(raw.trim());
    }
    for (const nested of Object.values(record)) {
      if (nested && typeof nested === 'object') visit(nested, depth + 1);
    }
  };
  visit(payload, 0);
  return Array.from(new Set(prefixes));
}

async function syncAiBotCidrs(): Promise<void> {
  const next = new Map<string, string[]>();
  await Promise.all(
    AI_BOT_CIDR_SOURCES.map(async (source) => {
      const body = await fetchTextWithTimeout(
        source.url,
        AI_BOT_CIDR_TIMEOUT_MS,
        'application/json'
      );
      if (!body) return;
      try {
        const parsed = JSON.parse(body) as unknown;
        // The registry feed normalizer understands provider-specific payload shapes; the raw
        // extractor stays as a fallback so a feed shape change cannot blank verified ranges.
        const prefixes = Array.from(
          new Set([
            ...extractAiPrefixes(parsed),
            ...prefixesFromNormalizedFeed(normalizeRegistryFeed(source.id, body), source.id),
          ])
        );
        if (prefixes.length > 0) next.set(source.id, prefixes);
      } catch {
        // Malformed payload: this provider keeps its previous prefix list.
      }
    })
  );
  if (next.size === 0) return;
  // Merge so a provider that fails one refresh keeps its previously verified ranges.
  const merged = new Map(aiBotPrefixTable);
  for (const [id, prefixes] of next) merged.set(id, prefixes);
  aiBotPrefixTable = merged;
  aiBotCidrLastSyncMs = Date.now();
}

function runAiBotCidrSync(): Promise<void> {
  if (aiBotCidrSyncInFlight) return aiBotCidrSyncInFlight;
  aiBotCidrSyncInFlight = syncAiBotCidrs()
    .catch(() => undefined)
    .finally(() => {
      aiBotCidrSyncInFlight = null;
    });
  return aiBotCidrSyncInFlight;
}

function ensureAiBotCidrSync(): void {
  if (aiBotCidrTimer === null) {
    // Non-blocking and deduplicated by `runAiBotCidrSync`'s in-flight guard.
    void runAiBotCidrSync();
    try {
      aiBotCidrTimer = setInterval(() => {
        void runAiBotCidrSync();
      }, AI_BOT_CIDR_SYNC_INTERVAL_MS);
      const handle = aiBotCidrTimer as unknown as { unref?: () => void };
      if (typeof handle.unref === 'function') handle.unref();
    } catch {
      // Workers / edge isolation reject global timers; requests re-arm via the TTL check below.
    }
  }
  if (Date.now() - aiBotCidrLastSyncMs >= AI_BOT_CIDR_SYNC_INTERVAL_MS) {
    void runAiBotCidrSync();
  }
}

// Workers reject global-scope timers; requests lazily re-arm the daemon there.
try {
  ensureAiBotCidrSync();
} catch {
  // Started on the first request instead.
}

function matchesAiPrefixTable(ip: string, ids: AiBotCidrSourceId[]): boolean {
  return ids.some((id) => ipMatchesCidrList(ip, aiBotPrefixTable.get(id) ?? []));
}

interface WebBotAuthInfo {
  /** Both `Signature` and `Signature-Input` are present → a signature was presented. */
  present: boolean;
  label: string;
  keyId: string;
  tag: string;
  agentUrl: string | null;
  agentHost: string;
  operator: AiAgentOperatorId | null;
  /** True only after real Ed25519 verification (or a valid replayed page attestation). */
  verified: boolean;
  /** WbaStatus string from the verifier, e.g. 'verified' / 'invalid' / 'absent'. */
  verifyStatus: string;
  /** Verified registry agent id from the trusted signer table (e.g. grok_agent / manus_bot). */
  verifiedAgentId: string | null;
  /** Verified operator from the trusted signer table (e.g. xAI / Manus). */
  verifiedOperator: string | null;
  /** Human-readable verification evidence lines. */
  verificationEvidence: string[];
}

function firstHttpsUrl(text: string): string | null {
  const match = /https?:\/\/[^\s",;)]+/i.exec(text);
  return match ? match[0].replace(/[.;]+$/, '') : null;
}

function resolveSignatureAgentOperator(host: string, label: string): AiAgentOperatorId | null {
  const lowerHost = host.toLowerCase();
  const lowerLabel = label.toLowerCase();
  // Google's labelled `g=` signature and its `*.bot.goog` Signature-Agent hosts are a
  // first-party special case that predates the registry.
  if (
    lowerHost === 'agent.bot.goog' ||
    lowerHost.endsWith('.bot.goog') ||
    lowerHost.endsWith('bot.goog') ||
    lowerLabel === 'g'
  ) {
    return 'google';
  }
  for (const rule of SIGNATURE_HOST_RULES) {
    if (lowerHost === rule.host || lowerHost.endsWith(`.${rule.host}`) || lowerHost.endsWith(rule.host)) {
      return rule.operator;
    }
  }
  return null;
}

/**
 * Parses the RFC 9421 Web Bot Auth headers. Labelled signatures (`g=("@authority" ...)`) and a
 * `Signature-Agent` URI both identify the operator; the `keyid` names the exact key.
 */
export function parseWebBotAuthHeaders(headers: RawHeaderBag | null | undefined): WebBotAuthInfo {
  // Thin wrapper around the shared RFC 9421 parser. Header presence alone is NOT verification;
  // the async Ed25519 result is merged in by `withWbaVerification` at request time.
  const parsed: WbaParsed = parseWbaHeaders(headers ?? {});
  const signatureInput = readRequestHeader(headers, 'signature-input');
  const signature = readRequestHeader(headers, 'signature');
  const signatureAgent = readRequestHeader(headers, 'signature-agent');
  const labelMatch = /^\s*([A-Za-z0-9_-]+)\s*=/.exec(signatureInput);
  const keyIdMatch = /keyid\s*=\s*"([^"]+)"/i.exec(signatureInput);
  const tagMatch = /tag\s*=\s*"([^"]+)"/i.exec(signatureInput);
  const agentUrl = parsed.agentOrigin || (signatureAgent ? firstHttpsUrl(signatureAgent) : null);
  let agentHost = parsed.agentHost || '';
  if (!agentHost && agentUrl) {
    try {
      agentHost = new URL(agentUrl).hostname.toLowerCase();
    } catch {
      agentHost = '';
    }
  }
  const label = parsed.label || (labelMatch ? labelMatch[1] : '');
  return {
    present: parsed.present && Boolean(signature),
    label,
    keyId: parsed.keyId || (keyIdMatch ? keyIdMatch[1].trim().slice(0, 160) : ''),
    tag: parsed.tag || (tagMatch ? tagMatch[1].trim().slice(0, 80) : ''),
    agentUrl,
    agentHost,
    operator: resolveSignatureAgentOperator(agentHost, label),
    verified: false,
    verifyStatus: 'absent',
    verifiedAgentId: null,
    verifiedOperator: null,
    verificationEvidence: [],
  };
}

/**
 * Merge a real async WBA verification result (or a valid page attestation) into the parsed
 * header info. Only a `verified` result may set `verified: true`.
 */
function withWbaVerification(
  base: WebBotAuthInfo,
  verification: WbaVerification | null | undefined
): WebBotAuthInfo {
  if (!verification || !verification.verified) {
    return {
      ...base,
      verified: false,
      verifyStatus: verification ? String(verification.status) : 'absent',
      verifiedAgentId: null,
      verifiedOperator: null,
      verificationEvidence: verification ? [...verification.evidence] : [],
    };
  }
  return {
    ...base,
    verified: true,
    verifyStatus: String(verification.status),
    verifiedAgentId: verification.agentId || null,
    verifiedOperator: verification.operator || null,
    verificationEvidence: [...verification.evidence],
  };
}

/**
 * Validates the short-lived `intel_wba` cookie written by the Worker after a VERIFIED
 * Web Bot Auth page load. Unsigned subresources ( Manus RUM beacons, scripts, etc.) can
 * inherit that signed identity for at most 60 seconds. Missing, expired, mis-bound or
 * unsigned cookies fail open to null — never an identity claim.
 */
function verifyPageAttestation(
  headers: RawHeaderBag | null | undefined,
  authority: string,
  userAgent: string,
  publicIp: string
): WbaVerification | null {
  try {
    const secret = process.env.VISITOR_HMAC_SECRET;
    if (!secret || secret.length < 32) return null;
    const cookie = readRequestHeader(headers, 'cookie');
    const match = /(?:^|;\s*)intel_wba=([^;]+)/.exec(cookie);
    if (!match) return null;
    const parts = match[1].split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
    const expected = crypto.createHmac('sha256', secret).update(parts[0]).digest('base64url');
    if (expected !== parts[1]) return null;
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as {
      op?: string; agentId?: string; host?: string;
      uaHash?: string; ipHash?: string; exp?: number;
    };
    const now = Date.now();
    if (!payload.exp || payload.exp <= now || payload.exp > now + 60_000) return null;
    if (!payload.op || !payload.agentId || payload.host !== authority) return null;
    const uaHash = crypto.createHash('sha256').update(userAgent || '').digest('hex').slice(0, 16);
    const ipHash = crypto.createHash('sha256').update(publicIp || '').digest('hex').slice(0, 16);
    if (payload.uaHash !== uaHash || payload.ipHash !== ipHash) return null;
    const signer = payload.op === 'Manus' ? 'api.manus.im' : 'cursorusercontent.com';
    return {
      status: 'verified',
      verified: true,
      operator: payload.op,
      agentId: payload.agentId,
      signerHost: signer,
      keyId: null,
      keySource: null,
      evidence: [`Signed page-load attestation replayed within 60s (${signer})`],
      checkedAtMs: now,
    };
  } catch {
    return null;
  }
}

/** Best-effort client-name / trigger lookup from the agent's signature directory (1 h cache). */
async function fetchWebBotAuthDirectory(
  agentUrl: string
): Promise<{ clientName: string; trigger: string | null } | null> {
  let origin = '';
  try {
    origin = new URL(agentUrl).origin;
  } catch {
    return null;
  }
  const nowMs = Date.now();
  const cached = aiAuthDirectoryCache.get(origin);
  if (cached && cached.expiresAtMs > nowMs) {
    return { clientName: cached.clientName, trigger: cached.trigger };
  }

  const body = await fetchTextWithTimeout(
    `${origin}/.well-known/http-message-signatures-directory`,
    AI_AUTH_DIRECTORY_TIMEOUT_MS,
    'application/json'
  );
  if (!body) return null;

  let clientName = '';
  let trigger: string | null = null;
  const visit = (value: unknown, depth: number): void => {
    if (depth > 4 || value === null || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    const record = value as Record<string, unknown>;
    if (!clientName) {
      const name = record.client_name ?? record.clientName;
      if (typeof name === 'string' && name.trim()) clientName = name.trim().slice(0, 120);
    }
    if (trigger === null) {
      const rawTrigger = record.trigger;
      if (typeof rawTrigger === 'string' && /fetcher|crawler/i.test(rawTrigger)) {
        trigger = /fetcher/i.test(rawTrigger) ? 'fetcher' : 'crawler';
      }
    }
    for (const nested of Object.values(record)) {
      if (nested && typeof nested === 'object') visit(nested, depth + 1);
    }
  };
  try {
    visit(JSON.parse(body) as unknown, 0);
  } catch {
    return null;
  }
  if (!clientName && trigger === null) return null;

  if (aiAuthDirectoryCache.size > 500) aiAuthDirectoryCache.clear();
  aiAuthDirectoryCache.set(origin, {
    clientName,
    trigger,
    expiresAtMs: nowMs + AI_AUTH_DIRECTORY_TTL_MS,
  });
  return { clientName, trigger };
}

/** Forward-confirmed reverse DNS for the visitor IP. Cached for one hour. */
async function resolveForwardConfirmedReverseDns(ip: string): Promise<string[]> {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return [];
  const nowMs = Date.now();
  const cached = aiForwardConfirmedDnsCache.get(normalized);
  if (cached && cached.expiresAtMs > nowMs) return cached.names;

  const reverseNames = await resolveTorReverseDns(normalized);
  const isV4 = isIpv4Literal(normalized);
  const confirmed: string[] = [];

  const forwardLookup = async (name: string): Promise<string[]> => {
    if (!/^[a-z0-9.-]+$/i.test(name)) return [];
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    try {
      const lookup = (isV4 ? dns.resolve4(name) : dns.resolve6(name)).catch(
        () => [] as string[]
      );
      const timeout = new Promise<string[]>((resolve) => {
        timeoutHandle = setTimeout(() => resolve([]), AI_FORWARD_DNS_TIMEOUT_MS);
      });
      const addresses = await Promise.race([lookup, timeout]);
      return Array.isArray(addresses) ? addresses : [];
    } catch {
      return [];
    } finally {
      if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
    }
  };

  for (const name of reverseNames.slice(0, 3)) {
    const addresses = await forwardLookup(name);
    if (addresses.some((address) => normalizeIpAddress(address) === normalized)) {
      confirmed.push(name);
    }
  }

  if (aiForwardConfirmedDnsCache.size > AI_VERDICT_TABLE_MAX_ENTRIES) {
    aiForwardConfirmedDnsCache.clear();
  }
  aiForwardConfirmedDnsCache.set(normalized, {
    names: confirmed,
    expiresAtMs: nowMs + AI_FORWARD_DNS_TTL_MS,
  });
  return confirmed;
}

/** True when any FCrDNS hostname ends with one of the operator-owned suffixes. */
function hostMatchesSuffix(names: readonly string[], suffixes: readonly string[]): boolean {
  return names.some((name) => {
    const lower = name.toLowerCase().replace(/\.$/, '');
    return suffixes.some((suffix) => lower === suffix || lower.endsWith(`.${suffix}`));
  });
}

function asnDigits(asn: string | undefined): string {
  if (typeof asn !== 'string') return '';
  const match = /(\d{1,10})/.exec(asn);
  return match ? match[1] : '';
}

function asnIn(asn: string | undefined, digits: readonly string[]): boolean {
  const value = asnDigits(asn);
  return value.length > 0 && digits.includes(value);
}

// Verification metadata is derived from the shared registry (with validated legacy fallbacks).
const GOOGLE_VERIFICATION_SUFFIXES = suffixesForAgent('googlebot', 'google', 'gemini');
const OPENAI_VERIFICATION_SUFFIXES = suffixesForAgent('gptbot', 'chatgpt-user', 'openai');
const PERPLEXITY_VERIFICATION_SUFFIXES = suffixesForAgent('perplexitybot', 'perplexity');
const ANTHROPIC_VERIFICATION_SUFFIXES = suffixesForAgent('claudebot', 'anthropic');
const XAI_VERIFICATION_SUFFIXES = suffixesForAgent('grokbot', 'xai');
const META_VERIFICATION_SUFFIXES = suffixesForAgent('muse', 'meta-externalagent', 'meta');

const GCP_ASNS = asnsForAgent('googlebot', 'google', 'gemini');
const XAI_ASNS = asnsForAgent('grok', 'xai');
const META_ASNS = asnsForAgent('muse', 'meta');
const AWS_ASNS = asnsForAgent('aws');
const AZURE_ASNS = asnsForAgent('azure');
const PERPLEXITY_ASNS = asnsForAgent('perplexitybot', 'perplexity');

interface AiAgentResolverClient {
  isBot?: boolean;
  isHeadless?: boolean;
  webdriver?: boolean;
  cdpDetected?: boolean;
  isVirtualMachine?: boolean;
  gpuVendor?: string;
  gpuRenderer?: string;
  idbDurabilityRatio?: number | null;
  screenResolution?: string;
  platform?: string;
  botSignals?: string[];
  /** Authoritative automation verdict from the handler (hard / stealth artifacts). */
  hardAutomationSignals?: boolean;
  automationTargetedTampering?: boolean;
}

interface AiAgentResolverInput {
  headers: RawHeaderBag | null | undefined;
  userAgent: string;
  network: { isp?: string; org?: string; asn?: string };
  publicIp: string;
  client: AiAgentResolverClient;
  /** Real async Web Bot Auth verification result (or page-attestation equivalent). */
  webBotAuth?: WbaVerification | null;
  /** Original request authority from the Worker (used for page-attestation replay). */
  originalAuthority?: string | null;
}

const NO_AI_AGENT: AiAgentAttribution = {
  detected: false,
  agentId: null,
  agentName: '',
  operator: '',
  executionMode: null,
  verified: false,
  confidence: 'Medium',
  riskScore: 0,
  evidence: [],
};

/** Registry agents introduce new agent ids / execution modes beyond the legacy union. */
type ExtendedAgentAttribution = Omit<AiAgentAttribution, 'agentId' | 'executionMode'> & {
  agentId: string | null;
  executionMode: string | null;
};

function aiAgentResult(
  partial: Omit<ExtendedAgentAttribution, 'detected' | 'riskScore'> &
    Partial<Pick<ExtendedAgentAttribution, 'riskScore'>>
): AiAgentAttribution {
  return {
    detected: true,
    riskScore: partial.riskScore ?? (partial.agentId === 'impostor-spoof' ? 10 : 8),
    ...partial,
  } as unknown as AiAgentAttribution;
}

/**
 * Decides whether the registry's minimum proof tier is satisfied. String tiers are compared by
 * rank; numeric tiers (0..4) and uncommon aliases are handled as well so a registry change in
 * proof-tier naming cannot silently over-verify an agent.
 */
function proofTierSatisfied(
  minProof: ProofTier | string | undefined,
  proofs: { feed: boolean; fcrdns: boolean; signature: boolean }
): boolean {
  const tier = String(minProof ?? 'verified').toLowerCase();
  // Legacy aliases plus the registry's ProofTier union ('rfc9421' | 'signed_agent' | 'cidr' |
  // 'fcrdns' | 'allowlist' | 'ua_claim' | 'automation').
  if (/^(none|any|0|ua_claim|automation|claim|ua)$/.test(tier)) return true;
  if (/^(rfc9421|signed_agent|signature|wba|sail|signed|jws|4)$/.test(tier)) return proofs.signature;
  if (/^(cidr|feed|ip|network|3)$/.test(tier)) return proofs.feed || proofs.signature;
  if (/^(fcrdns|dns|reverse|2)$/.test(tier)) return proofs.fcrdns || proofs.signature;
  return proofs.feed || proofs.fcrdns || proofs.signature;
}

/**
 * True only when a CRYPTOGRAPHICALLY VERIFIED signature is bound to this exact registry agent.
 * Loose host / keyid substring matching is deliberately gone: an unsigned signature header can
 * name any operator it likes, so it must never contribute to `verified`.
 */
function signatureMatchesAgent(webBotAuth: WebBotAuthInfo, agent: LocalAgentDef): boolean {
  if (!webBotAuth.verified) return false;
  const expectedOperator = operatorIdFromName(agent.provider || agent.id);
  if (webBotAuth.verifiedOperator) {
    const verifiedOperator = operatorIdFromName(webBotAuth.verifiedOperator);
    if (verifiedOperator === expectedOperator) return true;
  }
  if (webBotAuth.verifiedAgentId) {
    const verifiedAgent = webBotAuth.verifiedAgentId.toLowerCase();
    const agentId = String(agent.id || '').toLowerCase();
    if (verifiedAgent === agentId || verifiedAgent === agentId.replace(/[_-]/g, '')) return true;
  }
  if (webBotAuth.operator && webBotAuth.operator === expectedOperator && webBotAuth.verifiedAgentId) {
    return true;
  }
  return false;
}

/**
 * Attributable identity of an autonomous agent. Verification only ever comes from first-party
 * evidence: RFC 9421 Web Bot Auth, an official CIDR range synced from the vendor's own JSON, or
 * forward-confirmed reverse DNS. A User-Agent string on its own is a claim, never proof, so a
 * failed claim is reported as a spoofed impostor.
 */
export async function resolveAiAgentIdentity(input: AiAgentResolverInput): Promise<AiAgentAttribution> {
  const ua = input.userAgent || readRequestHeader(input.headers, 'user-agent');
  if (!ua) return NO_AI_AGENT;
  // Robots.txt policy tokens are directives, never HTTP visits.
  if (isRegistryPolicyToken(ua)) return NO_AI_AGENT;
  // Named registry agents are resolved by Rule H below (with their own proof-tier rules), so a
  // generic signed-browser rule must not pre-empt their exact identity or verification verdict.
  const registryMatch = findRegistryAgent(ua);

  const webBotAuth = withWbaVerification(
    parseWebBotAuthHeaders(input.headers),
    input.webBotAuth ?? null
  );
  // A valid 60s page-load attestation can carry verification even with no RFC 9421 triple.
  const pageAttestation = webBotAuth.verified && !webBotAuth.present;
  const referer = `${readRequestHeader(input.headers, 'referer')} ${readRequestHeader(
    input.headers,
    'origin'
  )}`;
  const networkHaystack = [input.network.org, input.network.isp, input.network.asn]
    .filter((part): part is string => typeof part === 'string' && part.trim().length > 0)
    .join(' · ');

  let confirmedNamesPromise: Promise<string[]> | null = null;
  const confirmedNames = (): Promise<string[]> => {
    if (confirmedNamesPromise === null) {
      confirmedNamesPromise = resolveForwardConfirmedReverseDns(input.publicIp);
    }
    return confirmedNamesPromise;
  };

  const gpuRenderer = (input.client.gpuRenderer || '').toLowerCase();
  const maskedGpu =
    !gpuRenderer ||
    gpuRenderer === 'unavailable' ||
    /swiftshader|llvmpipe|mesa|software|generic|^standard/.test(gpuRenderer);
  const idbRatio =
    typeof input.client.idbDurabilityRatio === 'number' ? input.client.idbDurabilityRatio : null;
  // Corroborated automation only: a lone `isBot` bit (or a headless layout hint from an
  // in-app browser) must not feed the cloud-VM / agent attribution rules.
  const clientAutomation = Boolean(
    input.client.webdriver ||
      input.client.cdpDetected ||
      (input.client.isBot && input.client.isHeadless)
  );
  const desktopChrome =
    /chrome\//i.test(ua) && !/mobile|android|iphone|ipad/i.test(ua);
  const screen = (input.client.screenResolution || '').toLowerCase();
  const claudeComputerUseViewport =
    screen.includes('1024x768') || screen.includes('1280x800') || screen.includes('1280×800');
  const silentCloudTelemetry = Boolean(
    input.client.isVirtualMachine ||
      (idbRatio !== null && idbRatio > 0.95 && maskedGpu) ||
      (desktopChrome && clientAutomation && maskedGpu)
  );

  const signatureEvidence = webBotAuth.verified
    ? [
        ...webBotAuth.verificationEvidence,
        'RFC 9421 Web Bot Auth signature verified (tag=web-bot-auth, Ed25519)',
        webBotAuth.verifiedAgentId ? `Verified agent id: ${webBotAuth.verifiedAgentId}` : '',
        webBotAuth.verifiedOperator ? `Verified operator: ${webBotAuth.verifiedOperator}` : '',
      ].filter(Boolean)
    : webBotAuth.present
    ? [
        'RFC 9421 Signature / Signature-Input headers present (Web Bot Auth) — signature NOT verified',
        webBotAuth.label ? `Signature label: ${webBotAuth.label}` : '',
        webBotAuth.agentUrl ? `Signature-Agent: ${webBotAuth.agentUrl}` : '',
        webBotAuth.keyId ? `keyid: ${webBotAuth.keyId}` : '',
      ].filter(Boolean)
    : [];

  const directoryHint = webBotAuth.agentUrl
    ? await fetchWebBotAuthDirectory(webBotAuth.agentUrl)
    : null;
  const directoryEvidence = directoryHint
    ? [
        directoryHint.clientName ? `Agent directory client_name: ${directoryHint.clientName}` : '',
        directoryHint.trigger ? `Agent trigger: ${directoryHint.trigger}` : '',
      ].filter(Boolean)
    : [];

  // An authoritative automation verdict OWNS the label. A stealth / headless Chromium session
  // must never be attributed to a named cloud agent (e.g. "Google Gemini / Cloud Agent (GCP VM)")
  // from a cloud ASN plus masked-GPU / SwiftShader telemetry: that is a runtime observation, not
  // an identity. Only a cryptographically signed RFC 9421 agent keeps its real attribution; the
  // identify handler maps every other authoritative automation session to neutral stealth labels.
  const authoritativeAutomation = Boolean(
    input.client.hardAutomationSignals ||
      input.client.automationTargetedTampering ||
      input.client.webdriver ||
      input.client.cdpDetected ||
      (input.client.isBot && input.client.isHeadless) ||
      (input.client.botSignals || []).some((signal) =>
        /stealth|headless|chromium|puppeteer|playwright|webdriver/i.test(signal)
      )
  );
  if (authoritativeAutomation && !webBotAuth.verified && !pageAttestation) {
    return NO_AI_AGENT;
  }

  /* ---------- Rule 0 — remote browser / computer-use harnesses -------------- */
  // Scraping and agent harnesses (Firecrawl, Browser Use, Skyvern, MultiOn, Steel, Airtop,
  // Hyperbrowser, Notte, Lightpanda, Browserless and the managed scraping fleets) announce
  // themselves in the User-Agent because their target sites expect attribution. There is no
  // vendor CIDR table for them, so the claim is reported as a named remote browser agent with
  // high confidence rather than as a spoof, and the cursor overlay only renders for these
  // non-human sessions.
  const remoteBrowserUa =
    /firecrawl|browserbase|browser[-_ ]?use|skyvern|multion|hyperbrowser|steel[-_ ]?browser|airtop|\bnotte\b|lightpanda|browserless|scrapingbee|scrapfly|zenrows|brightdata|oxylabs|\bzyte\b/i;
  if (remoteBrowserUa.test(ua)) {
    const remoteOperator = /firecrawl/i.test(ua)
      ? 'Firecrawl'
      : /browserbase/i.test(ua)
      ? 'Browserbase'
      : /browser[-_ ]?use/i.test(ua)
      ? 'Browser Use'
      : /skyvern/i.test(ua)
      ? 'Skyvern'
      : /multion/i.test(ua)
      ? 'MultiOn'
      : /hyperbrowser/i.test(ua)
      ? 'Hyperbrowser'
      : /steel[-_ ]?browser/i.test(ua)
      ? 'Steel'
      : /airtop/i.test(ua)
      ? 'Airtop'
      : /notte/i.test(ua)
      ? 'Notte'
      : /lightpanda/i.test(ua)
      ? 'Lightpanda'
      : /browserless/i.test(ua)
      ? 'Browserless'
      : /scrapingbee/i.test(ua)
      ? 'ScrapingBee'
      : /scrapfly/i.test(ua)
      ? 'Scrapfly'
      : /zenrows/i.test(ua)
      ? 'ZenRows'
      : /brightdata/i.test(ua)
      ? 'Bright Data'
      : /oxylabs/i.test(ua)
      ? 'Oxylabs'
      : 'Zyte';
    return aiAgentResult({
      agentId: 'remote-browser',
      agentName: `${remoteOperator} Remote Browser Agent`,
      operator: remoteOperator,
      executionMode: 'Remote Browser Agent',
      verified: false,
      confidence: clientAutomation ? 'High' : 'Medium',
      evidence: [
        `Remote browser agent user-agent: ${ua.slice(0, 120)}`,
        clientAutomation
          ? 'Automation runtime flags confirmed the harness (WebDriver / CDP / headless)'
          : 'User-agent claim without an automation flag',
        networkHaystack ? `Network identity: ${networkHaystack}` : '',
      ].filter(Boolean),
    });
  }

  /* --------------- Rule A (prelude) — Googlebot verification ---------------- */
  // Googlebot is a search crawler, not an LLM agent, but a spoofed claim must still be caught.
  // Only flag a spoof when at least one authoritative source actually answered.
  if (/\bgooglebot\b/i.test(ua)) {
    const googleCidr = matchesAiPrefixTable(input.publicIp, [
      'google-common',
      'google-user-triggered',
      'google-user-triggered-google',
    ]);
    const googleDnsNames = await confirmedNames();
    const googleDns = hostMatchesSuffix(googleDnsNames, GOOGLE_VERIFICATION_SUFFIXES);
    const googleRangesLoaded = (aiBotPrefixTable.get('google-common')?.length ?? 0) > 0;
    if (googleCidr || googleDns) {
      return aiAgentResult({
        agentId: 'gemini',
        agentName: 'Googlebot (Verified Google Crawler)',
        operator: 'Google LLC',
        executionMode: 'Autonomous Crawler',
        verified: true,
        confidence: 'Verified',
        evidence: [
          `Googlebot user-agent: ${ua.slice(0, 120)}`,
          googleCidr ? 'Source IP matched a Google official crawler CIDR range' : '',
          googleDns ? 'FCrDNS matched *.googlebot.com / *.google.com' : '',
        ].filter(Boolean),
      });
    }
    const googleOwnedNetwork =
      asnIn(input.network.asn, GCP_ASNS) || /google/i.test(input.network.org || '');
    if (googleRangesLoaded && !googleOwnedNetwork) {
      return aiAgentResult({
        agentId: 'impostor-spoof',
        agentName: 'Spoofed Google Bot Impostor (Unverified IP)',
        operator: 'Unverified Google claim',
        executionMode: 'Spoofed Impostor',
        verified: false,
        confidence: 'Verified',
        evidence: [
          `Googlebot user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not inside Google's official crawler ranges`,
          'Forward-confirmed reverse DNS does not resolve to googlebot.com / google.com',
        ],
      });
    }
    return NO_AI_AGENT;
  }

  /* ---------------------------- Rule A — Gemini ---------------------------- */
  const geminiUa =
    /Gemini-Deep-Research|GoogleAgent-Mariner|Google-NotebookLM|Google-CloudVertexBot|Google-Extended|GoogleOther(-Image|-Video)?|Google-InspectionTool/i.test(
      ua
    );
  if (webBotAuth.operator === 'google' || geminiUa) {
    const googleCidr = matchesAiPrefixTable(input.publicIp, [
      'google-common',
      'google-user-triggered',
      'google-user-triggered-google',
    ]);
    const googleDnsNames = await confirmedNames();
    const googleDns = hostMatchesSuffix(googleDnsNames, GOOGLE_VERIFICATION_SUFFIXES);
    const googleRangesLoaded = (aiBotPrefixTable.get('google-common')?.length ?? 0) > 0;
    const verified =
      (webBotAuth.verified && webBotAuth.operator === 'google') || googleCidr || googleDns;
    if (geminiUa && !verified && googleRangesLoaded) {
      return aiAgentResult({
        agentId: 'impostor-spoof',
        agentName: 'Spoofed Google Gemini Agent (Unverified IP)',
        operator: 'Unverified Google claim',
        executionMode: 'Spoofed Impostor',
        verified: false,
        confidence: 'Verified',
        evidence: [
          `Gemini / Google agent user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not inside Google's official crawler ranges`,
          'Forward-confirmed reverse DNS does not resolve to googlebot.com / google.com',
        ],
      });
    }
    return aiAgentResult({
      agentId: 'gemini',
      agentName:
        directoryHint?.clientName ||
        (verified
          ? 'Google Gemini (Mariner / Deep Research)'
          : 'Google Gemini / Cloud Agent (GCP VM)'),
      operator: 'Google LLC',
      executionMode: webBotAuth.operator === 'google'
        ? 'RFC 9421 Signed Agent'
        : geminiUa && !clientAutomation
        ? 'User-Triggered Fetcher'
        : 'Autonomous Crawler',
      verified,
      confidence: verified
        ? 'Verified'
        : googleRangesLoaded || googleDnsNames.length > 0
        ? 'High'
        : 'Medium',
      evidence: [
        ...(webBotAuth.operator === 'google' ? signatureEvidence : []),
        ...(geminiUa ? [`Google AI agent user-agent: ${ua.slice(0, 120)}`] : []),
        ...(googleCidr ? ['Source IP matched a Google official crawler CIDR range'] : []),
        ...(googleDns ? ['FCrDNS matched *.googlebot.com / *.google.com'] : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from headers'] : []),
        ...directoryEvidence,
      ],
    });
  }
  if (
    (asnIn(input.network.asn, GCP_ASNS) ||
      hostMatchesSuffix(await confirmedNames(), ['googleusercontent.com'])) &&
    (webBotAuth.present || (silentCloudTelemetry && clientAutomation))
  ) {
    return aiAgentResult({
      agentId: 'gemini',
      agentName: 'Google Gemini / Cloud Agent (GCP VM)',
      operator: 'Google LLC',
      executionMode: webBotAuth.verified ? 'RFC 9421 Signed Agent' : 'Silent Cloud VM Browser',
      verified: webBotAuth.verified,
      confidence: webBotAuth.verified ? 'Verified' : 'High',
      evidence: [
        ...signatureEvidence,
        ...(asnIn(input.network.asn, GCP_ASNS)
          ? [`Google Cloud ASN (${input.network.asn}) hosting the browser`]
          : ['Reverse DNS matched *.googleusercontent.com']),
        ...(silentCloudTelemetry
          ? ['Cloud-VM browser telemetry (masked WebGL / ephemeral storage)']
          : []),
      ],
    });
  }

  /* ------------------------------ Rule B — Grok ----------------------------- */
  // Only a REAL, cryptographically verified WBA signature bound to the pinned grok_agent key
  // earns a signed Grok identity. Network / referer / UA tokens are claims, never proof.
  const grokUa = /GrokAgent|GrokBot|xAI-GrokBot|Grok-Search|xAI-SearchBot|xAI-Bot|\bGrok\b/i.test(ua);
  const grokSigned =
    webBotAuth.verified &&
    (webBotAuth.verifiedAgentId?.toLowerCase() === 'grok_agent' ||
      webBotAuth.verifiedOperator?.toLowerCase() === 'xai');
  if (grokSigned) {
    return aiAgentResult({
      agentId: 'grok_agent',
      agentName: 'Grok Bot',
      operator: 'xAI',
      executionMode: 'RFC 9421 Signed Agent',
      verified: true,
      confidence: 'Verified',
      riskScore: 2,
      evidence: [...signatureEvidence, 'identity: signed', ...directoryEvidence],
    });
  }
  // Unsigned Grok tokens are handled by Rule H below as the registry's generic grok_bot entry
  // (unverified claim, score 7). `grokReferer` is NOT a trigger — a referer can be forged by any
  // page, so it is emitted only as non-triggering corroboration when a signed claim already hit.
  const grokReferer = /grok\.com|x\.ai/i.test(referer);
  void grokReferer;
  // xAI ASN / FCrDNS are corroboration ONLY — xAI publishes no authoritative ranges, so they can
  // never set `verified` and never manufacture a named Grok attribution on their own.
  const xaiCorroboration: string[] = [];
  if (xaiCorroboration.length > 0) {
    // Intentionally inert: kept so the corroboration strings remain reviewable evidence.
  }
  const xaiAsn = asnIn(input.network.asn, XAI_ASNS);
  if (xaiAsn && (grokUa || grokSigned)) {
    xaiCorroboration.push(
      `xAI-associated ASN ${input.network.asn} (corroboration only — xAI publishes no authoritative ranges)`
    );
  }
  const xaiDnsNames = grokUa ? await confirmedNames() : [];
  if (hostMatchesSuffix(xaiDnsNames, XAI_VERIFICATION_SUFFIXES)) {
    xaiCorroboration.push(
      'xAI-associated FCrDNS (corroboration only — xAI publishes no authoritative ranges)'
    );
  }
  void xaiCorroboration;

  /* ------------------------------ Rule C — Muse ----------------------------- */
  const museUa = /\bMuseBot\b|\bMuse\b|Meta-ExternalAgent|Meta-ExternalFetcher|FacebookBot/i.test(ua);
  if (webBotAuth.operator === 'meta' || museUa) {
    const metaDnsNames = await confirmedNames();
    const metaDns = hostMatchesSuffix(metaDnsNames, META_VERIFICATION_SUFFIXES);
    const metaAsn = asnIn(input.network.asn, META_ASNS);
    const verified =
      (webBotAuth.verified && webBotAuth.operator === 'meta') || metaDns || metaAsn;
    return aiAgentResult({
      agentId: 'muse',
      agentName: directoryHint?.clientName || 'Meta Muse',
      operator: 'Meta Platforms',
      executionMode: webBotAuth.operator === 'meta' ? 'RFC 9421 Signed Agent' : 'Autonomous Crawler',
      verified,
      confidence: verified ? 'Verified' : metaDnsNames.length > 0 ? 'High' : 'Medium',
      evidence: [
        ...(webBotAuth.operator === 'meta' ? signatureEvidence : []),
        ...(museUa ? [`Meta / Muse user-agent: ${ua.slice(0, 120)}`] : []),
        ...(metaAsn ? [`Meta Platforms ASN ${input.network.asn}`] : []),
        ...(metaDns ? ['FCrDNS matched *.facebook.com / *.meta.com'] : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from headers'] : []),
        ...directoryEvidence,
      ],
    });
  }
  if (asnIn(input.network.asn, META_ASNS) && desktopChrome && silentCloudTelemetry && clientAutomation) {
    return aiAgentResult({
      agentId: 'muse',
      agentName: 'Meta Muse (Cloud VM Browser Agent)',
      operator: 'Meta Platforms',
      executionMode: 'Silent Cloud VM Browser',
      verified: false,
      confidence: 'High',
      evidence: [
        `Meta Platforms ASN (${input.network.asn}) hosting a desktop Chrome session`,
        'Virtual machine / cloud browser telemetry (masked WebGL, Linux platform or ephemeral storage)',
      ],
    });
  }

  /* --------------------------- Rule D — Perplexity -------------------------- */
  const perplexityUa = /PerplexityBot|Perplexity-User/i.test(ua);
  if (webBotAuth.operator === 'perplexity' || perplexityUa) {
    const perplexityDnsNames = await confirmedNames();
    const perplexityDns = hostMatchesSuffix(
      perplexityDnsNames,
      PERPLEXITY_VERIFICATION_SUFFIXES
    );
    const perplexityAsn = asnIn(input.network.asn, PERPLEXITY_ASNS);
    const verified =
      (webBotAuth.verified && webBotAuth.operator === 'perplexity') || perplexityDns || perplexityAsn;
    return aiAgentResult({
      agentId: 'perplexity',
      agentName: directoryHint?.clientName || 'Perplexity AI Agent',
      operator: 'Perplexity AI',
      executionMode: webBotAuth.operator === 'perplexity'
        ? 'RFC 9421 Signed Agent'
        : 'Autonomous Crawler',
      verified,
      confidence: verified ? 'Verified' : perplexityDnsNames.length > 0 ? 'High' : 'Medium',
      evidence: [
        ...(webBotAuth.operator === 'perplexity' ? signatureEvidence : []),
        ...(perplexityUa ? [`Perplexity user-agent: ${ua.slice(0, 120)}`] : []),
        ...(perplexityAsn ? [`Perplexity ASN ${input.network.asn}`] : []),
        ...(perplexityDns ? ['FCrDNS matched *.perplexity.ai'] : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from headers'] : []),
        ...directoryEvidence,
      ],
    });
  }
  if (
    asnIn(input.network.asn, AWS_ASNS) &&
    clientAutomation &&
    (webBotAuth.present ||
      hostMatchesSuffix(await confirmedNames(), PERPLEXITY_VERIFICATION_SUFFIXES))
  ) {
    return aiAgentResult({
      agentId: 'perplexity',
      agentName: 'Perplexity AI (PerplexityBot / Stealth Agent)',
      operator: 'Perplexity AI',
      executionMode: webBotAuth.verified ? 'RFC 9421 Signed Agent' : 'Silent Cloud VM Browser',
      verified: webBotAuth.verified,
      confidence: webBotAuth.verified ? 'Verified' : 'Medium',
      evidence: [
        ...signatureEvidence,
        `AWS ASN (${input.network.asn}) hosting a headless Chromium session`,
        'RFC 9421 headers or Perplexity network attribution',
      ],
    });
  }

  /* ----------------------------- Rule E — OpenAI ---------------------------- */
  const openAiUa = /ChatGPT-User|OAI-SearchBot|GPTBot/i.test(ua);
  if (webBotAuth.operator === 'openai' || openAiUa) {
    const openAiDnsNames = await confirmedNames();
    const openAiDns = hostMatchesSuffix(openAiDnsNames, OPENAI_VERIFICATION_SUFFIXES);
    const openAiCidr = matchesAiPrefixTable(input.publicIp, ['chatgpt-user', 'gptbot', 'searchbot']);
    const openAiRangesLoaded =
      (aiBotPrefixTable.get('chatgpt-user')?.length ?? 0) > 0 ||
      (aiBotPrefixTable.get('gptbot')?.length ?? 0) > 0;
    const verified =
      (webBotAuth.verified && webBotAuth.operator === 'openai') || openAiDns || openAiCidr;
    // An official OpenAI UA from an IP that the loaded verification sources positively exclude
    // is an impostor. When those sources are merely unavailable, keep the attribution but do
    // not claim a verified spoof.
    if (openAiUa && !verified && (openAiRangesLoaded || openAiDnsNames.length > 0)) {
      return aiAgentResult({
        agentId: 'impostor-spoof',
        agentName: 'Spoofed AI Bot Impostor (Unverified IP)',
        operator: 'Unverified OpenAI claim',
        executionMode: 'Spoofed Impostor',
        verified: false,
        confidence: 'Verified',
        evidence: [
          `OpenAI user-agent claim: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not on OpenAI infrastructure`,
        ],
      });
    }
    return aiAgentResult({
      agentId: 'openai',
      agentName: directoryHint?.clientName || 'OpenAI ChatGPT Agent / Operator',
      operator: 'OpenAI',
      executionMode: webBotAuth.operator === 'openai'
        ? 'RFC 9421 Signed Agent'
        : /chatgpt-user/i.test(ua)
        ? 'User-Triggered Fetcher'
        : 'Autonomous Crawler',
      verified,
      confidence: verified
        ? 'Verified'
        : openAiRangesLoaded || openAiDnsNames.length > 0
        ? 'High'
        : 'Medium',
      evidence: [
        ...(webBotAuth.operator === 'openai' ? signatureEvidence : []),
        ...(openAiUa ? [`OpenAI user-agent: ${ua.slice(0, 120)}`] : []),
        ...(openAiCidr ? ['Source IP matched an official OpenAI JSON prefix list'] : []),
        ...(openAiDns ? ['FCrDNS matched *.openai.com / *.chatgpt.com'] : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from headers'] : []),
        ...directoryEvidence,
      ],
    });
  }
  if (asnIn(input.network.asn, AZURE_ASNS) && webBotAuth.verified) {
    return aiAgentResult({
      agentId: 'openai',
      agentName: 'OpenAI ChatGPT Agent / Operator',
      operator: 'OpenAI',
      executionMode: 'RFC 9421 Signed Agent',
      verified: true,
      confidence: 'Verified',
      evidence: [
        ...signatureEvidence,
        `Microsoft Azure ASN (${input.network.asn}) hosting the signed agent`,
      ],
    });
  }

  /* ----------------------------- Rule F — Claude ---------------------------- */
  const claudeUa = /Claude-User|Claude-SearchBot|ClaudeBot|anthropic-ai/i.test(ua);
  if (webBotAuth.operator === 'anthropic' || claudeUa) {
    const anthropicDnsNames = await confirmedNames();
    const anthropicDns = hostMatchesSuffix(anthropicDnsNames, ANTHROPIC_VERIFICATION_SUFFIXES);
    const verified =
      (webBotAuth.verified && webBotAuth.operator === 'anthropic') || anthropicDns;
    // Anthropic has no published CIDR table here, so the only verification is FCrDNS. An
    // official Claude crawler has a matching forward-confirmed name; a spoof on an arbitrary IP
    // does not. Treat any unverified Claude UA as an impostor rather than attributing it to
    // Anthropic with a misleading "Medium" confidence.
    if (claudeUa && !verified) {
      return aiAgentResult({
        agentId: 'impostor-spoof',
        agentName: 'Spoofed Anthropic Claude Agent (Unverified IP)',
        operator: 'Unverified Anthropic claim',
        executionMode: 'Spoofed Impostor',
        verified: false,
        confidence: 'Verified',
        evidence: [
          `Claude user-agent presented: ${ua.slice(0, 120)}`,
          `Source IP ${input.publicIp} is not on Anthropic infrastructure`,
        ],
      });
    }
    return aiAgentResult({
      agentId: 'claude',
      agentName: directoryHint?.clientName || 'Anthropic Claude (Claude-User / Computer Use)',
      operator: 'Anthropic',
      executionMode: webBotAuth.operator === 'anthropic'
        ? 'RFC 9421 Signed Agent'
        : /claude-user/i.test(ua)
        ? 'User-Triggered Fetcher'
        : 'Autonomous Crawler',
      verified,
      confidence: verified ? 'Verified' : anthropicDnsNames.length > 0 ? 'High' : 'Medium',
      evidence: [
        ...(webBotAuth.operator === 'anthropic' ? signatureEvidence : []),
        ...(claudeUa ? [`Claude user-agent: ${ua.slice(0, 120)}`] : []),
        ...(anthropicDns ? ['FCrDNS matched *.anthropic.com / *.claude.ai'] : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from headers'] : []),
        ...directoryEvidence,
      ],
    });
  }
  if (
    (asnIn(input.network.asn, AWS_ASNS) || asnIn(input.network.asn, GCP_ASNS)) &&
    claudeComputerUseViewport &&
    /llvmpipe|mesa|swiftshader|software/i.test(gpuRenderer) &&
    clientAutomation
  ) {
    return aiAgentResult({
      agentId: 'claude',
      agentName: 'Anthropic Claude (Claude-User / Computer Use)',
      operator: 'Anthropic',
      executionMode: 'Silent Cloud VM Browser',
      verified: false,
      confidence: 'Medium',
      evidence: [
        `Cloud ASN (${input.network.asn}) hosting a Linux X11 / Xvfb framebuffer`,
        `Viewport ${input.client.screenResolution} matches a Claude computer-use desktop`,
        'Software WebGL renderer (llvmpipe / Mesa) with an automated session',
      ],
    });
  }

  /* -------------------- Rule G — signed cloud browser ---------------------- */
  const cloudBrowserOperator =
    webBotAuth.operator === 'browserbase'
      ? { name: 'Browserbase Cloud Agent', operator: 'Browserbase' }
      : webBotAuth.operator === 'anchorbrowser'
      ? { name: 'Anchor Browser AI Agent', operator: 'Anchor Browser' }
      : null;
  if ((webBotAuth.verified || cloudBrowserOperator) && !registryMatch) {
    const handle = webBotAuth.agentHost || webBotAuth.keyId || 'unattributed signer';
    return aiAgentResult({
      agentId: 'cloud-browser',
      agentName:
        directoryHint?.clientName ||
        cloudBrowserOperator?.name ||
        'AI Agent · Cloud Browser (RFC 9421 Signed)',
      operator: cloudBrowserOperator?.operator || 'Unattributed Cloud Browser',
      executionMode: 'RFC 9421 Signed Agent',
      verified: webBotAuth.verified,
      confidence: webBotAuth.verified ? 'Verified' : 'High',
      evidence: [
        ...signatureEvidence,
        ...(cloudBrowserOperator ? [`Signature-Agent operator: ${handle}`] : []),
        ...(!cloudBrowserOperator ? [`Signed agent handle: ${handle}`] : []),
        ...(networkHaystack ? [`Network identity: ${networkHaystack}`] : []),
        ...directoryEvidence,
      ],
    });
  }

  /* ---------- Rule H — registry-backed generic agent attribution ----------- */
  // Every named crawler in the shared registry must be attributable with its exact display
  // name, even when it has no bespoke rule above. Only first-party proof (a published CIDR
  // prefix, forward-confirmed reverse DNS or a matching RFC 9421 / SAIL signature) can turn
  // the UA claim into a verified identity; the registry's minimum proof tier is honoured.
  if (registryMatch) {
    const agent = asLocalAgent(registryMatch);
    if (isRegistryPolicyToken(ua) || agent.policyToken === true) {
      return NO_AI_AGENT;
    }
    const agentRecord = agent as unknown as Record<string, unknown>;
    const suffixesRaw =
      agent.fcrdnsSuffixes ??
      registryLookup(agentRecord, 'verificationSuffixes') ??
      registryLookup(agentRecord, 'fcrdnsSuffixes');
    const suffixes = Array.isArray(suffixesRaw)
      ? suffixesRaw.filter((item): item is string => typeof item === 'string' && item.length > 0)
      : suffixesForAgent(agent.id, agent.provider);
    const feedIdsRaw = agent.feedIds ?? registryLookup(agentRecord, 'feedIds');
    const feedIds = Array.isArray(feedIdsRaw)
      ? feedIdsRaw.filter((item): item is string => typeof item === 'string' && item.length > 0)
      : [];
    const registryDnsNames = suffixes.length > 0 ? await confirmedNames() : [];
    const proofs = {
      feed: feedIds.length > 0 && matchesAiPrefixTable(input.publicIp, feedIds),
      fcrdns: hostMatchesSuffix(registryDnsNames, suffixes),
      signature: signatureMatchesAgent(webBotAuth, agent),
    };
    let verified = proofTierSatisfied(agent.minProofForVerified, proofs);
    // Training scrapers hold no first-party verification path here, and an unsigned browser
    // harness may only ever be an unproven claim.
    if (/mistral[\s_-]?ai[\s_-]?training/i.test(agent.id)) verified = false;
    if (/manus/i.test(agent.id) && !proofs.signature) verified = false;
    const isManusClaim = /manus/i.test(agent.id);
    const isGrokClaim = /grok/i.test(agent.id);

    return aiAgentResult({
      agentId: agent.id,
      agentName: agent.displayName,
      operator: agent.provider,
      executionMode: agent.executionMode || 'Autonomous Crawler',
      verified,
      confidence: verified ? 'Verified' : 'Medium',
      riskScore: verified ? 2 : isManusClaim || isGrokClaim ? 7 : 8,
      evidence: [
        `Named agent user-agent claim: ${ua.slice(0, 120)}`,
        proofs.feed ? 'Source IP matched a registry-published crawler CIDR prefix' : '',
        proofs.fcrdns ? 'FCrDNS matched the operator verification suffix' : '',
        proofs.signature ? 'RFC 9421 / SAIL signature attributed to the operator' : '',
        ...(isManusClaim
          ? [
              verified
                ? 'RFC 9421 Web Bot Auth signature verified (tag=web-bot-auth, Ed25519)'
                : 'Manus-User/1.0 token present in User-Agent — no verifiable signature; unverified identity claim',
            ]
          : []),
        ...(isGrokClaim && !verified
          ? ['Grok token present in User-Agent — no verifiable signature; unverified identity claim']
          : []),
        ...(!verified ? ['Verification sources unavailable — identity inferred from the user-agent claim'] : []),
        ...directoryEvidence,
      ].filter(Boolean),
    });
  }

  /* ------------------ Rule I — spoofed impostor (fallback) ----------------- */
  const officialBotClaim =
    /googlebot|googleother|gemini-deep-research|gptbot|chatgpt-user|perplexitybot|perplexity-user|claudebot|claude-user|grokbot|meta-externalagent|muse/i.test(
      ua
    );
  if (officialBotClaim) {
    return aiAgentResult({
      agentId: 'impostor-spoof',
      agentName: 'Spoofed AI Bot Impostor (Unverified IP)',
      operator: 'Unverified AI crawler claim',
      executionMode: 'Spoofed Impostor',
      verified: false,
      confidence: 'Verified',
      evidence: [
        `Official AI crawler user-agent claim: ${ua.slice(0, 120)}`,
        `Source IP ${input.publicIp} could not be verified via CIDR or FCrDNS`,
      ],
    });
  }

  return NO_AI_AGENT;
}

/* -------------------------------------------------------------------------- */
/* Phase 3 — server-side emulator / simulator re-verification                  */
/* -------------------------------------------------------------------------- */

/**
 * The client probe in `src/lib/collector.ts` reports `emulatorDetected` inside the payload, but a
 * client is free to omit or forge that flag. These are the same predicates re-applied on the
 * server to the sanitized payload (the signed User-Agent, `navigator.platform`, touch capability
 * and the WebGL renderer string), so an emulated runtime cannot hide by lying about the verdict.
 */
const EMULATOR_GPU_SIGNATURE_PATTERN =
  /android emulator opengl es translator|goldfish|ranchu|bluestacks|nox|ldplayer|memu|genymotion|virgl|apple software renderer/i;
/** x86 / desktop platform strings a real Android handset can never report. */
const NON_ARM_ANDROID_PLATFORM_PATTERN = /linux x86|x86_64|i[3-6]86|win32|win64|macintel/i;
const IOS_DEVICE_UA_PATTERN = /(iphone|ipad|ipod)/i;
const IOS_FOREIGN_PLATFORM_PATTERN = /linux|win32|win64/i;
const IPHONE_OR_IPOD_UA_PATTERN = /(iphone|ipod)/i;

/** `1920x1080` / `1920 × 1080` → viewport width in CSS pixels (0 when unparsable). */
function parseScreenResolutionWidth(resolution: string): number {
  const match = /(\d+)\s*[x×]\s*(\d+)/i.exec(resolution || '');
  if (match) {
    const width = Number.parseInt(match[1], 10);
    return Number.isFinite(width) && width > 0 ? width : 0;
  }
  const single = Number.parseInt(resolution || '', 10);
  return Number.isFinite(single) && single > 0 ? single : 0;
}

/**
 * Server-side mirror of `detectEmulatorEvidence()`: Android UA on an x86/desktop platform or with
 * zero touch points, an emulator/simulator GPU renderer, an iOS UA on a foreign platform or with
 * no touch points (iPadOS 13+ reports `MacIntel` WITH touch points and stays clean), and an
 * iPhone/iPod UA on a desktop-width screen.
 */
function classifyEmulatorFromSignals(input: {
  userAgent: string;
  /** Client-claimed OS family; used as the claim source when the header is generic. */
  os?: string;
  platform: string;
  maxTouchPoints: number;
  gpuVendor: string;
  gpuRenderer: string;
  screenResolution: string;
}): { detected: boolean; reason: string } {
  const ua = typeof input.userAgent === 'string' ? input.userAgent : '';
  const claimedOs = typeof input.os === 'string' ? input.os : '';
  const platform = (input.platform || '').trim();
  const maxTouchPoints =
    typeof input.maxTouchPoints === 'number' ? Math.max(0, input.maxTouchPoints) : 0;
  const vendor = (input.gpuVendor || '').trim();
  const renderer = (input.gpuRenderer || '').trim();
  const gpuSignature = `${vendor} ${renderer}`;

  const claimsAndroid = /android/i.test(ua) || /android/i.test(claimedOs);
  const claimsIos = IOS_DEVICE_UA_PATTERN.test(ua) || /ipad|ios/i.test(claimedOs);

  if (claimsAndroid && NON_ARM_ANDROID_PLATFORM_PATTERN.test(platform)) {
    return {
      detected: true,
      reason: `Android user-agent on desktop ${platform} (emulator CPU profile)`,
    };
  }
  if (claimsAndroid && maxTouchPoints === 0) {
    return {
      detected: true,
      reason: 'Android user-agent reporting zero touch points (emulated input layer)',
    };
  }
  if (EMULATOR_GPU_SIGNATURE_PATTERN.test(gpuSignature)) {
    return {
      detected: true,
      reason: `Emulator GPU renderer (${renderer || vendor || 'masked renderer'})`,
    };
  }
  if (claimsIos) {
    if (IOS_FOREIGN_PLATFORM_PATTERN.test(platform)) {
      return { detected: true, reason: `iOS user-agent on ${platform} platform (simulator host)` };
    }
    if (maxTouchPoints === 0) {
      return {
        detected: true,
        reason: `iOS user-agent on ${platform || 'desktop'} with zero touch points (simulator)`,
      };
    }
  }
  const screenWidth = parseScreenResolutionWidth(input.screenResolution);
  if (IPHONE_OR_IPOD_UA_PATTERN.test(ua) && screenWidth >= 1000) {
    return { detected: true, reason: `iPhone user-agent on a ${screenWidth}px desktop-width screen` };
  }

  return { detected: false, reason: '' };
}

/* -------------------------------------------------------------------------- */
/* Phase 2 — Tor exit relay resolution and local abuse blocklist               */
/* -------------------------------------------------------------------------- */

const TOR_DNS_TIMEOUT_MS = 600;
const TOR_DOH_TIMEOUT_MS = 1200;
const TOR_DOH_ENDPOINTS = ['https://dns.google/resolve', 'https://cloudflare-dns.com/dns-query'];
const TOR_BULK_LIST_URL = 'https://check.torproject.org/torbulkexitlist';
const TOR_EXIT_ADDRESSES_URL = 'https://check.torproject.org/exit-addresses';
const TOR_ONIONOO_DETAILS_URL = 'https://onionoo.torproject.org/details';
const TOR_BULK_LIST_MAX_ENTRIES = 20000;
/** Full consensus refresh cadence (bulk list + exit-addresses + Onionoo details). */
const TOR_INTELLIGENCE_SYNC_INTERVAL_MS = 30 * 60 * 1000;
const TOR_INTELLIGENCE_SYNC_TIMEOUT_MS = 10000;
const TOR_BULK_TIMEOUT_MS = TOR_INTELLIGENCE_SYNC_TIMEOUT_MS;
const TOR_LIVE_LOOKUP_TIMEOUT_MS = 1800;
const TOR_REVERSE_DNS_TIMEOUT_MS = 1200;
const TOR_VERDICT_CACHE_TTL_MS = 30 * 60 * 1000;
const TOR_VERDICT_CACHE_MAX_ENTRIES = 5000;
const TOR_OPERATOR_PREFIX_CACHE_TTL_MS = 6 * 60 * 60 * 1000;

interface TorRelayMetadata {
  nickname: string;
  fingerprint: string;
  as?: string;
  asName?: string;
  country?: string;
  flags: string[];
}

/**
 * Hot in-memory consensus tables. Replaced by reference (never mutated in place) so an in-flight
 * request either sees the complete previous snapshot or the complete new one, never a half-filled
 * set.
 */
let torIpv4ExitSet = new Set<string>();
let torIpv6ExitSet = new Set<string>();
let torIpv6Prefix64Set = new Set<string>();
let torIpv6Prefix48Set = new Set<string>();
let torRelayMetadataMap = new Map<string, TorRelayMetadata>();

let torIntelligenceLastSyncMs = 0;
let torIntelligenceSyncInFlight: Promise<void> | null = null;
let torIntelligenceTimer: ReturnType<typeof setInterval> | null = null;

const torVerdictCache = new Map<
  string,
  { verdict: 'exit' | 'relay' | 'no'; expiresAtMs: number }
>();
const torReverseDnsCache = new Map<string, { names: string[]; expiresAtMs: number }>();

/* -------------------------------------------------------------------------- */
/* Dual-stack IP normalization (IPv4 + IPv6, mapped / bracketed / zoned forms) */
/* -------------------------------------------------------------------------- */

/** Canonicalizes an IP literal: trims, drops brackets, zone ids and maps `::ffff:` to IPv4. */
export function normalizeIpAddress(rawIp: string): string {
  if (typeof rawIp !== 'string') return '';
  let value = rawIp.trim();
  if (!value) return '';
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
  const zoneIndex = value.indexOf('%');
  if (zoneIndex >= 0) value = value.slice(0, zoneIndex);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (mapped) value = mapped[1];
  return value.toLowerCase();
}

function isIpv6Hextet(value: string): boolean {
  return /^[0-9a-f]{1,4}$/.test(value);
}

/**
 * Expands `::` compression into a canonical 8-hextet string so `/64` (first 4 hextets) and
 * `/48` (first 3 hextets) prefixes can be extracted deterministically.
 */
export function expandIpv6Address(ip: string): string | null {
  let value = normalizeIpAddress(ip);
  if (!value || !value.includes(':')) return null;

  // Rewrite a dotted-quad tail (`::ffff:192.0.2.1`) as two hextets before compression expands.
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    if (lastColon < 0) return null;
    const tail = value.slice(lastColon + 1);
    if (!isIpv4Literal(tail)) return null;
    const [a, b, c, d] = tail.split('.').map((octet) => Number.parseInt(octet, 10));
    value = `${value.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${(
      (c << 8) |
      d
    ).toString(16)}`;
  }

  const halves = value.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if (halves.length === 2) {
    if (head.length + tail.length > 7) return null;
    const zeros = new Array<string>(8 - head.length - tail.length).fill('0');
    const hextets = [...head, ...zeros, ...tail];
    if (!hextets.every(isIpv6Hextet)) return null;
    return hextets.map((hextet) => hextet.replace(/^0+(?=.)/, '')).join(':');
  }
  if (head.length !== 8 || !head.every(isIpv6Hextet)) return null;
  return head.map((hextet) => hextet.replace(/^0+(?=.)/, '')).join(':');
}

function ipv4ToInt(ip: string): number | null {
  if (!isIpv4Literal(ip)) return null;
  const octets = ip.split('.').map((octet) => Number.parseInt(octet, 10));
  return (
    ((octets[0] * 0x1000000 + octets[1] * 0x10000 + octets[2] * 0x100 + octets[3]) >>> 0) >>> 0
  );
}

function ipv4MatchesCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf('/');
  const base = (slash >= 0 ? cidr.slice(0, slash) : cidr).trim();
  const bits = slash >= 0 ? Number.parseInt(cidr.slice(slash + 1), 10) : 32;
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) >>> 0 === (baseInt & mask) >>> 0;
}

function ipv6MatchesCidr(ip: string, cidr: string): boolean {
  const slash = cidr.lastIndexOf('/');
  const base = (slash >= 0 ? cidr.slice(0, slash) : cidr).trim();
  const bits = slash >= 0 ? Number.parseInt(cidr.slice(slash + 1), 10) : 128;
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return false;
  const ipExpanded = expandIpv6Address(ip);
  const baseExpanded = expandIpv6Address(base);
  if (!ipExpanded || !baseExpanded) return false;
  const ipHextets = ipExpanded.split(':');
  const baseHextets = baseExpanded.split(':');
  const fullHextets = Math.floor(bits / 16);
  for (let index = 0; index < fullHextets; index += 1) {
    if (ipHextets[index] !== baseHextets[index]) return false;
  }
  const remainingBits = bits % 16;
  if (remainingBits === 0) return true;
  const mask = (0xffff << (16 - remainingBits)) & 0xffff;
  const ipValue = Number.parseInt(ipHextets[fullHextets], 16);
  const baseValue = Number.parseInt(baseHextets[fullHextets], 16);
  return (ipValue & mask) === (baseValue & mask);
}

/** Fast dual-stack CIDR matcher shared by the Tor operator ranges and the AI bot prefix lists. */
export function ipMatchesCidrList(ip: string, cidrList: readonly string[]): boolean {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return false;
  const isV4 = isIpv4Literal(normalized);
  for (const cidr of cidrList) {
    if (typeof cidr !== 'string') continue;
    const candidate = cidr.trim();
    if (!candidate) continue;
    if (isV4) {
      if (ipv4MatchesCidr(normalized, candidate)) return true;
    } else if (ipv6MatchesCidr(normalized, candidate)) {
      return true;
    }
  }
  return false;
}

/**
 * Tier 2 — dual-stack operators such as Church of Cyberology embed the relay's IPv4 address in
 * the last four hextets (`2001:67c:e60:c0c:192:42:116:110` → `192.42.116.110`).
 */
export function extractEmbeddedIpv4FromIpv6(ip: string): string | null {
  const expanded = expandIpv6Address(ip);
  if (!expanded) return null;
  const tail = expanded.split(':').slice(4);
  if (tail.length !== 4 || !tail.every((hextet) => /^\d{1,3}$/.test(hextet))) return null;
  const octets = tail.map((hextet) => Number.parseInt(hextet, 10));
  if (octets.some((octet) => octet > 255)) return null;
  return octets.join('.');
}

function isTorOperatorPrefix(ip: string): boolean {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return false;
  if (isIpv4Literal(normalized)) return ipMatchesCidrList(normalized, TOR_OPERATOR_IPV4_CIDRS);
  return ipMatchesCidrList(normalized, TOR_OPERATOR_IPV6_PREFIXES);
}

/** Splits an Onionoo `or_addresses` entry (`1.2.3.4:443`, `[2001:db8::1]:443`). */
function splitTorAddressPort(entry: string): string {
  const trimmed = entry.trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('[')) {
    const close = trimmed.indexOf(']');
    if (close > 0) return trimmed.slice(1, close);
  }
  const firstColon = trimmed.indexOf(':');
  const lastColon = trimmed.lastIndexOf(':');
  if (firstColon > 0 && firstColon === lastColon) return trimmed.slice(0, lastColon);
  return trimmed;
}

async function fetchTextWithTimeout(
  url: string,
  timeoutMs: number,
  accept: string
): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { accept },
    });
    if (!response.ok) return null;
    return await response.text();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/* -------------------------------------------------------------------------- */
/* Tier 1 — background Tor consensus synchronization (IPv4 + IPv6 exits)       */
/* -------------------------------------------------------------------------- */

interface OnionooRelay {
  nickname?: string;
  fingerprint?: string;
  as?: string;
  as_name?: string;
  country?: string;
  flags?: unknown;
  or_addresses?: unknown;
  exit_addresses?: unknown;
}

function torRelayMetadataFromOnionoo(relay: OnionooRelay): TorRelayMetadata {
  return {
    nickname: typeof relay.nickname === 'string' ? relay.nickname : '',
    fingerprint: typeof relay.fingerprint === 'string' ? relay.fingerprint : '',
    as: typeof relay.as === 'string' ? relay.as : undefined,
    asName: typeof relay.as_name === 'string' ? relay.as_name : undefined,
    country: typeof relay.country === 'string' ? relay.country : undefined,
    flags: Array.isArray(relay.flags)
      ? relay.flags.filter((flag): flag is string => typeof flag === 'string')
      : [],
  };
}

/** Downloads every source and swaps all tables in one atomic reference update. */
async function syncTorIntelligence(): Promise<void> {
  const nextIpv4 = new Set<string>();
  const nextIpv6 = new Set<string>();
  const nextPrefix64 = new Set<string>();
  const nextPrefix48 = new Set<string>();
  const nextMetadata = new Map<string, TorRelayMetadata>();

  const remember = (key: string, metadata: TorRelayMetadata): void => {
    if (!nextMetadata.has(key)) nextMetadata.set(key, metadata);
  };

  const addIpv4 = (rawIp: unknown, metadata: TorRelayMetadata | null): void => {
    if (typeof rawIp !== 'string') return;
    const ip = normalizeIpAddress(rawIp);
    if (!isIpv4Literal(ip)) return;
    nextIpv4.add(ip);
    if (metadata) remember(ip, metadata);
  };

  const addIpv6 = (rawIp: unknown, metadata: TorRelayMetadata | null): void => {
    if (typeof rawIp !== 'string') return;
    const ip = normalizeIpAddress(rawIp);
    const expanded = expandIpv6Address(ip);
    if (!expanded) return;
    nextIpv6.add(ip);
    nextIpv6.add(expanded);
    const hextets = expanded.split(':');
    nextPrefix64.add(hextets.slice(0, 4).join(':'));
    nextPrefix48.add(hextets.slice(0, 3).join(':'));
    if (metadata) {
      remember(ip, metadata);
      remember(expanded, metadata);
    }
  };

  const [bulkList, exitAddresses, onionoo] = await Promise.all([
    fetchTextWithTimeout(TOR_BULK_LIST_URL, TOR_INTELLIGENCE_SYNC_TIMEOUT_MS, 'text/plain'),
    fetchTextWithTimeout(TOR_EXIT_ADDRESSES_URL, TOR_INTELLIGENCE_SYNC_TIMEOUT_MS, 'text/plain'),
    fetchTextWithTimeout(
      `${TOR_ONIONOO_DETAILS_URL}?search=running:true&fields=nickname,fingerprint,or_addresses,exit_addresses,flags,as,as_name,country`,
      TOR_INTELLIGENCE_SYNC_TIMEOUT_MS,
      'application/json'
    ),
  ]);

  if (bulkList) {
    for (const line of bulkList.split(/\r?\n/)) {
      const candidate = line.trim();
      if (!candidate || candidate.startsWith('#')) continue;
      addIpv4(candidate, null);
      if (nextIpv4.size >= TOR_BULK_LIST_MAX_ENTRIES) break;
    }
  }

  if (exitAddresses) {
    let fingerprint = '';
    for (const line of exitAddresses.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith('ExitNode ')) {
        fingerprint = trimmed.slice('ExitNode '.length).trim();
        continue;
      }
      if (!trimmed.startsWith('ExitAddress ')) continue;
      const address = trimmed.split(/\s+/)[1] ?? '';
      addIpv4(address, {
        nickname: fingerprint ? `exit-${fingerprint.slice(0, 8)}` : '',
        fingerprint,
        flags: ['Exit'],
      });
    }
  }

  if (onionoo) {
    try {
      const parsed = JSON.parse(onionoo) as { relays?: unknown };
      const relays = Array.isArray(parsed.relays) ? (parsed.relays as OnionooRelay[]) : [];
      for (const relay of relays) {
        const flags = Array.isArray(relay.flags)
          ? relay.flags.filter((flag): flag is string => typeof flag === 'string')
          : [];
        // Only exit-capable relays can be an anonymity egress.
        if (!flags.includes('Exit')) continue;
        const metadata = torRelayMetadataFromOnionoo(relay);
        const exitAddressesForRelay = Array.isArray(relay.exit_addresses)
          ? relay.exit_addresses
          : [];
        for (const address of exitAddressesForRelay) addIpv4(address, metadata);
        const orAddresses = Array.isArray(relay.or_addresses) ? relay.or_addresses : [];
        for (const entry of orAddresses) {
          if (typeof entry !== 'string') continue;
          const host = splitTorAddressPort(entry);
          if (!host) continue;
          if (isIpv4Literal(host)) addIpv4(host, metadata);
          else addIpv6(host, metadata);
        }
      }
    } catch {
      // Malformed payload: keep the previous snapshot rather than publishing a partial one.
    }
  }

  if (nextIpv4.size === 0 && nextIpv6.size === 0) return;

  torIpv4ExitSet = nextIpv4;
  torIpv6ExitSet = nextIpv6;
  torIpv6Prefix64Set = nextPrefix64;
  torIpv6Prefix48Set = nextPrefix48;
  torRelayMetadataMap = nextMetadata;
  torIntelligenceLastSyncMs = Date.now();
}

function runTorIntelligenceSync(): Promise<void> {
  if (torIntelligenceSyncInFlight) return torIntelligenceSyncInFlight;
  torIntelligenceSyncInFlight = syncTorIntelligence()
    .catch(() => undefined)
    .finally(() => {
      torIntelligenceSyncInFlight = null;
    });
  return torIntelligenceSyncInFlight;
}

function ensureTorIntelligenceSync(): void {
  if (torIntelligenceTimer === null) {
    void runTorIntelligenceSync();
    torIntelligenceTimer = setInterval(() => {
      void runTorIntelligenceSync();
    }, TOR_INTELLIGENCE_SYNC_INTERVAL_MS);
    const handle = torIntelligenceTimer as unknown as { unref?: () => void };
    if (typeof handle.unref === 'function') handle.unref();
    return;
  }
  // The timer exists but a runtime can evict timers; re-arm a straggling refresh.
  if (Date.now() - torIntelligenceLastSyncMs >= TOR_INTELLIGENCE_SYNC_INTERVAL_MS) {
    void runTorIntelligenceSync();
  }
}

// Workers reject global-scope timers, so this is best-effort at boot and lazily re-armed on the
// first request in runtimes that refuse it.
try {
  ensureTorIntelligenceSync();
} catch {
  // Started on the first request instead.
}

function lookupTorRelayMetadata(ip: string): TorRelayMetadata | null {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) return null;
  const direct = torRelayMetadataMap.get(normalized);
  if (direct) return direct;
  const expanded = expandIpv6Address(normalized);
  if (!expanded) return null;
  return torRelayMetadataMap.get(expanded) ?? null;
}

/** Human-readable operator label, e.g. `Church of Cyberology · AS215125`. */
function describeTorRelay(ip: string): string | null {
  const metadata = lookupTorRelayMetadata(ip);
  if (!metadata) return null;
  const organization = metadata.asName || metadata.nickname;
  const asn = metadata.as ? (metadata.as.startsWith('AS') ? metadata.as : `AS${metadata.as}`) : '';
  if (organization && asn) return `${organization} · ${asn}`;
  return organization || asn || null;
}

function pruneTorVerdictCache(nowMs: number): void {
  for (const [ip, entry] of torVerdictCache) {
    if (entry.expiresAtMs <= nowMs) torVerdictCache.delete(ip);
  }
  while (torVerdictCache.size >= TOR_VERDICT_CACHE_MAX_ENTRIES) {
    const oldestKey = torVerdictCache.keys().next().value;
    if (typeof oldestKey !== 'string') break;
    torVerdictCache.delete(oldestKey);
  }
}

const SUSPICIOUS_IP_TTL_MS = 24 * 60 * 60 * 1000;
const SUSPICIOUS_IP_MAX_ENTRIES = 10000;
// A single anomalous request is not enough to brand an IP: residential lines are shared and a
// single stale tab, clock glitch or one-off probe must never show a visitor as blocklisted.
// Only repeated, independent evidence promotes an entry into the visible blocklist.
const SUSPICIOUS_IP_BLOCK_THRESHOLD = 2;
const suspiciousIpLedger = new Map<string, number>();
const suspiciousIpReasons = new Map<string, string[]>();
const suspiciousIpStrikes = new Map<string, number>();

function isIpv4Literal(value: string): boolean {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed)) return false;
  return trimmed.split('.').every((octet) => {
    const parsed = Number.parseInt(octet, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 255;
  });
}

type TorExitVerdict = 'exit' | 'relay' | 'not_exit' | 'unknown';

/**
 * Authoritative per-IP Tor DNSEL query (`<reversed-octets>.dnsel.torproject.org`). Only
 * `127.0.0.2` means "exit relay". Native resolver first, DNS-over-HTTPS as fallback for hosts
 * whose own resolver refuses direct A queries. Returns null when no resolver produced an answer.
 */
async function resolveTorDnsel(ipv4: string): Promise<boolean | null> {
  const queryName = `${ipv4.split('.').reverse().join('.')}.dnsel.torproject.org`;
  let resolved = false;
  let isTorExit = false;

  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
  try {
    const lookup = dns.resolve4(queryName).catch((error: NodeJS.ErrnoException) => {
      // A missing record is a definitive "not an exit relay"; a refused or timed-out query
      // says nothing about the address and must fall through to DNS-over-HTTPS.
      const code = typeof error?.code === 'string' ? error.code : '';
      if (code === 'ENOTFOUND' || code === 'ENODATA' || code === 'ENOTIMP') {
        return [] as string[];
      }
      return null;
    });
    const timeout = new Promise<string[] | null>((resolve) => {
      timeoutHandle = setTimeout(() => resolve(null), TOR_DNS_TIMEOUT_MS);
    });
    const records = await Promise.race([lookup, timeout]);
    if (Array.isArray(records)) {
      resolved = true;
      isTorExit = records.includes('127.0.0.2');
    }
  } catch {
    resolved = false;
  } finally {
    if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
  }

  if (!resolved) {
    for (const endpoint of TOR_DOH_ENDPOINTS) {
      const answers = await resolveAOverDoh(endpoint, queryName);
      if (answers) {
        resolved = true;
        isTorExit = answers.includes('127.0.0.2');
        break;
      }
    }
  }

  return resolved ? isTorExit : null;
}

/** Reverse DNS (PTR) with a hard timeout. Never throws: some runtimes refuse PTR lookups. */
async function resolveTorReverseDns(ip: string): Promise<string[]> {
  const nowMs = Date.now();
  const cached = torReverseDnsCache.get(ip);
  if (cached && cached.expiresAtMs > nowMs) return cached.names;

  let names: string[] = [];
  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
  try {
    const lookup = dns.reverse(ip).catch(() => [] as string[]);
    const timeout = new Promise<string[]>((resolve) => {
      timeoutHandle = setTimeout(() => resolve([]), TOR_REVERSE_DNS_TIMEOUT_MS);
    });
    const records = await Promise.race([lookup, timeout]);
    if (Array.isArray(records)) {
      names = records.filter((name): name is string => typeof name === 'string');
    }
  } catch {
    names = [];
  } finally {
    if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
  }

  if (torReverseDnsCache.size > TOR_VERDICT_CACHE_MAX_ENTRIES) torReverseDnsCache.clear();
  torReverseDnsCache.set(ip, {
    names,
    expiresAtMs: nowMs + TOR_OPERATOR_PREFIX_CACHE_TTL_MS,
  });
  return names;
}

/**
 * Tier 4 live Onionoo lookup. `search=<ip>` matches both `or_addresses` and `exit_addresses` for
 * IPv4, but Onionoo's `exit_addresses` field is IPv4-only, so the /64 prefix comparison below is
 * what resolves IPv6 exits.
 */
async function lookupOnionooRelay(
  target: string
): Promise<{ matched: boolean; isExit: boolean } | null> {
  const url = `${TOR_ONIONOO_DETAILS_URL}?search=${encodeURIComponent(
    target
  )}&fields=nickname,fingerprint,or_addresses,exit_addresses,flags,as`;
  const body = await fetchTextWithTimeout(url, TOR_LIVE_LOOKUP_TIMEOUT_MS, 'application/json');
  if (!body) return null;
  let relays: OnionooRelay[] = [];
  try {
    const parsed = JSON.parse(body) as { relays?: unknown };
    relays = Array.isArray(parsed.relays) ? (parsed.relays as OnionooRelay[]) : [];
  } catch {
    return null;
  }

  const targetExpanded = expandIpv6Address(target);
  const targetPrefix64 = targetExpanded ? targetExpanded.split(':').slice(0, 4).join(':') : null;
  let matched = false;
  let isExit = false;

  for (const relay of relays) {
    const addresses: string[] = [];
    if (Array.isArray(relay.exit_addresses)) {
      for (const address of relay.exit_addresses) {
        if (typeof address === 'string') addresses.push(address);
      }
    }
    if (Array.isArray(relay.or_addresses)) {
      for (const entry of relay.or_addresses) {
        if (typeof entry !== 'string') continue;
        const host = splitTorAddressPort(entry);
        if (host) addresses.push(host);
      }
    }

    const hasMatch = addresses.some((address) => {
      const normalized = normalizeIpAddress(address);
      if (!normalized) return false;
      if (normalized === target) return true;
      const expanded = expandIpv6Address(normalized);
      if (!expanded) return false;
      if (targetExpanded && expanded === targetExpanded) return true;
      return targetPrefix64 !== null && expanded.split(':').slice(0, 4).join(':') === targetPrefix64;
    });
    if (!hasMatch) continue;
    matched = true;
    const flags = Array.isArray(relay.flags)
      ? relay.flags.filter((flag): flag is string => typeof flag === 'string')
      : [];
    if (flags.includes('Exit')) {
      isExit = true;
      break;
    }
  }

  return { matched, isExit };
}

/**
 * Resolves the Tor verdict for an IPv4 *or* IPv6 visitor, in strict order of authority:
 *
 * 1. Tier 1 — synced consensus sets (IPv4 exit list / Onionoo IPv4+IPv6 exits)
 * 2. Tier 2 — IPv4 address embedded in the last four hextets of an IPv6 address
 * 3. Tier 3 — dedicated relay-operator prefix, then reverse DNS
 * 4. Tier 4 — live DNSEL (IPv4) + Onionoo, cached for 30 minutes
 *
 * A relay that is part of the Tor network but is not an exit returns `'relay'`; only `'exit'`
 * means traffic could leave the network at that address.
 */
export async function resolveTorExitVerdict(ip: string): Promise<TorExitVerdict> {
  const cleanIp = normalizeIpAddress(ip);
  if (!cleanIp) return 'unknown';
  const isV4 = isIpv4Literal(cleanIp);
  const expanded = isV4 ? null : expandIpv6Address(cleanIp);
  if (!isV4 && expanded === null) return 'unknown';

  /* Tier 1 — consensus tables, O(1). */
  if (isV4 && torIpv4ExitSet.has(cleanIp)) return 'exit';
  if (expanded !== null && (torIpv6ExitSet.has(cleanIp) || torIpv6ExitSet.has(expanded))) {
    return 'exit';
  }

  /* Tier 2 — embedded IPv4-in-IPv6 (Church of Cyberology et al.). */
  if (!isV4) {
    const embeddedIpv4 = extractEmbeddedIpv4FromIpv6(cleanIp);
    if (embeddedIpv4 !== null) {
      if (torIpv4ExitSet.has(embeddedIpv4)) return 'exit';
      if (ipMatchesCidrList(embeddedIpv4, TOR_OPERATOR_IPV4_CIDRS)) return 'exit';
    }
  }

  /* Tier 3 — dedicated operator prefix, then reverse DNS. */
  if (isTorOperatorPrefix(cleanIp)) return 'relay';
  const reverseNames = await resolveTorReverseDns(cleanIp);
  if (reverseNames.some((name) => TOR_OPERATOR_REVERSE_DNS_PATTERN.test(name))) return 'relay';

  /* Tier 4 — cached live lookup. */
  const nowMs = Date.now();
  const cached = torVerdictCache.get(cleanIp);
  if (cached && cached.expiresAtMs > nowMs) {
    return cached.verdict === 'exit' ? 'exit' : cached.verdict === 'relay' ? 'relay' : 'not_exit';
  }

  let liveVerdict: 'exit' | 'relay' | 'no' | 'unknown' = 'unknown';

  if (isV4) {
    const [dnsel, onionoo] = await Promise.all([
      resolveTorDnsel(cleanIp),
      lookupOnionooRelay(cleanIp),
    ]);
    if (dnsel === true) {
      liveVerdict = 'exit';
    } else if (onionoo && onionoo.matched) {
      liveVerdict = onionoo.isExit ? 'exit' : 'relay';
    } else if (dnsel === false || (onionoo && !onionoo.matched)) {
      // At least one authoritative source answered: the address is not part of the network.
      liveVerdict = 'no';
    }
  } else {
    const onionoo = await lookupOnionooRelay(expanded ?? cleanIp);
    if (onionoo && onionoo.matched) liveVerdict = onionoo.isExit ? 'exit' : 'relay';
    else if (onionoo && !onionoo.matched) liveVerdict = 'no';
  }

  if (liveVerdict !== 'unknown') {
    pruneTorVerdictCache(nowMs);
    torVerdictCache.set(cleanIp, {
      verdict: liveVerdict,
      expiresAtMs: nowMs + TOR_VERDICT_CACHE_TTL_MS,
    });
  }

  return liveVerdict === 'exit' ? 'exit' : liveVerdict === 'relay' ? 'relay' : liveVerdict === 'no' ? 'not_exit' : 'unknown';
}

/** Boolean wrapper used by diagnostics; `unknown` degrades to `false`. */
async function isTorExitNode(ip: string): Promise<boolean> {
  return (await resolveTorExitVerdict(ip)) === 'exit';
}

/**
 * Operator fallback for the `unknown` DNSEL verdict: a relay operator ASN, organisation name or
 * the operator's dedicated prefix. Never used to overrule a definitive DNS answer.
 */
function matchesTorOperatorHint(location: {
  isp?: string;
  org?: string;
  asn?: string;
  publicIp?: string;
}): boolean {
  const haystack = [location.isp, location.org, location.asn]
    .filter((part): part is string => typeof part === 'string' && part.trim().length > 0)
    .join(' ');
  if (haystack.length > 0 && TOR_OPERATOR_ORG_PATTERN.test(haystack)) return true;
  if (matchesTorOperatorAsn(location.asn || '')) return true;
  const ip = typeof location.publicIp === 'string' ? normalizeIpAddress(location.publicIp) : '';
  return ip.length > 0 && isTorOperatorPrefix(ip);
}

/** IP / ASN / organisation operator label, independent of the Onionoo consensus. */
function relayOperatorLabel(location: {
  isp?: string;
  org?: string;
  asn?: string;
}): string | null {
  const rawAsn = typeof location.asn === 'string' ? location.asn.trim().toUpperCase() : '';
  const asn = rawAsn ? (rawAsn.startsWith('AS') ? rawAsn : `AS${rawAsn}`) : '';
  const name =
    [location.isp, location.org].find(
      (value): value is string =>
        typeof value === 'string' && value.trim().length > 0 && !/^unknown/i.test(value.trim())
    ) ?? '';
  if (name && asn) return `${name} · ${asn}`;
  return name || asn || null;
}

/**
 * Resolves the Tor verdict from every first-party layer, in strict order of authority:
 * synced consensus tables (IPv4 + IPv6) → DNSEL / Onionoo → operator ASN / prefix fallback.
 * The three outputs are distinct on purpose: a relay is part of the network but is not an
 * egress, so only `isExit` may drive the exit-node risk weights.
 */
interface TorExitStatus {
  isExit: boolean;
  isRelay: boolean;
  verdict: TorExitVerdict;
  viaOperatorHint: boolean;
  operator: string | null;
  relay: TorRelayMetadata | null;
}

async function resolveTorExitStatus(
  publicIp: string,
  location: { isp?: string; org?: string; asn?: string },
  prefetched?: Promise<TorExitVerdict>,
  trustedTorNetwork = false
): Promise<TorExitStatus> {
  const relay = lookupTorRelayMetadata(publicIp);
  const operator = describeTorRelay(publicIp) ?? relayOperatorLabel(location);

  // Cloudflare reports `T1` as the country for requests that arrive over the Tor network.
  // A Tor client can only reach the origin through an exit relay, so `T1` is an exit
  // verdict on its own and does not need the DNSEL round trip.
  if (trustedTorNetwork) {
    return {
      isExit: true,
      isRelay: true,
      verdict: 'exit',
      viaOperatorHint: false,
      operator,
      relay,
    };
  }

  if (isTorBulkListed(publicIp)) {
    return {
      isExit: true,
      isRelay: true,
      verdict: 'exit',
      viaOperatorHint: false,
      operator,
      relay,
    };
  }

  const verdict = await (prefetched ?? resolveTorExitVerdict(publicIp));
  if (verdict === 'exit') {
    return { isExit: true, isRelay: true, verdict, viaOperatorHint: false, operator, relay };
  }
  if (verdict === 'relay') {
    return { isExit: false, isRelay: true, verdict, viaOperatorHint: false, operator, relay };
  }
  if (verdict === 'unknown' && matchesTorOperatorHint({ ...location, publicIp })) {
    // Operator attribution proves relay infrastructure, never egress. Strict policy: only a
    // bulk-list or live DNSEL `exit` verdict may set `isExit`, so a normal customer of a
    // Tor-friendly hosting ASN is never labelled as a Tor exit.
    return {
      isExit: false,
      isRelay: true,
      verdict: 'relay',
      viaOperatorHint: true,
      operator: operator ?? relayOperatorLabel(location),
      relay,
    };
  }
  return { isExit: false, isRelay: false, verdict, viaOperatorHint: false, operator: null, relay: null };
}

/** Minimal DNS-over-HTTPS A-record lookup (JSON API). Returns null on any transport error. */
async function resolveAOverDoh(endpoint: string, name: string): Promise<string[] | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TOR_DOH_TIMEOUT_MS);
  try {
    const response = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=A`, {
      headers: { accept: 'application/dns-json' },
      signal: controller.signal,
    });
    if (!response.ok) return null;
    const payload = (await response.json()) as {
      Status?: number;
      Answer?: Array<{ type?: number; data?: string }>;
    };
    // Status 3 (NXDOMAIN) and an empty answer section are definitive negatives: the address is
    // not on the exit list. Servfail / refused are transport-quality problems and stay unknown.
    if (payload.Status === 3) return [];
    if (payload.Status !== 0) return null;
    const answers = Array.isArray(payload.Answer) ? payload.Answer : [];
    return answers
      .filter((entry) => entry.type === 1 && typeof entry.data === 'string')
      .map((entry) => String(entry.data).trim());
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Exact dual-stack membership in the synced consensus sets (no prefix heuristics here). */
function isTorBulkListed(ip: string): boolean {
  const cleanIp = normalizeIpAddress(ip);
  if (!cleanIp) return false;
  if (isIpv4Literal(cleanIp)) return torIpv4ExitSet.has(cleanIp);
  const expanded = expandIpv6Address(cleanIp);
  if (!expanded) return false;
  return torIpv6ExitSet.has(cleanIp) || torIpv6ExitSet.has(expanded);
}

/**
 * Kept as the request-path entry point: starts the background consensus daemon on first use and
 * forces a refresh when the last snapshot is older than the sync interval. A page load never
 * waits for this download — the per-IP lookup is authoritative and already tiered.
 */
async function refreshTorBulkList(): Promise<void> {
  ensureTorIntelligenceSync();
  if (torIntelligenceSyncInFlight) return;
  if (Date.now() - torIntelligenceLastSyncMs < TOR_INTELLIGENCE_SYNC_INTERVAL_MS) return;
  await runTorIntelligenceSync();
}

function flagSuspiciousIp(ip: string, reason: string): void {
  const cleanIp = typeof ip === 'string' ? ip.trim() : '';
  if (!cleanIp || cleanIp === 'Unavailable') return;

  const nowMs = Date.now();
  for (const [knownIp, expiresAtMs] of suspiciousIpLedger) {
    if (expiresAtMs <= nowMs) {
      suspiciousIpLedger.delete(knownIp);
      suspiciousIpReasons.delete(knownIp);
      suspiciousIpStrikes.delete(knownIp);
    }
  }
  while (suspiciousIpLedger.size >= SUSPICIOUS_IP_MAX_ENTRIES) {
    const oldestKey = suspiciousIpLedger.keys().next().value;
    if (typeof oldestKey !== 'string') break;
    suspiciousIpLedger.delete(oldestKey);
    suspiciousIpReasons.delete(oldestKey);
    suspiciousIpStrikes.delete(oldestKey);
  }

  const cleanReason = reason.trim().slice(0, 180);
  const existingReasons = suspiciousIpReasons.get(cleanIp) ?? [];
  if (cleanReason && !existingReasons.includes(cleanReason) && existingReasons.length < 5) {
    existingReasons.push(cleanReason);
  }
  suspiciousIpReasons.set(cleanIp, existingReasons);
  // Strikes count distinct reasons; the same reason repeated (for example a cached page that
  // keeps resending one stale envelope) never escalates on its own.
  const strikes = existingReasons.length;
  suspiciousIpStrikes.set(cleanIp, strikes);
  suspiciousIpLedger.set(cleanIp, nowMs + SUSPICIOUS_IP_TTL_MS);
}

function lookupSuspiciousIp(ip: string): { blocklisted: boolean; reasons: string[] } {
  const cleanIp = typeof ip === 'string' ? ip.trim() : '';
  if (!cleanIp) return { blocklisted: false, reasons: [] };
  const expiresAtMs = suspiciousIpLedger.get(cleanIp);
  if (expiresAtMs === undefined) return { blocklisted: false, reasons: [] };
  if (expiresAtMs <= Date.now()) {
    suspiciousIpLedger.delete(cleanIp);
    suspiciousIpReasons.delete(cleanIp);
    suspiciousIpStrikes.delete(cleanIp);
    return { blocklisted: false, reasons: [] };
  }
  const strikes = suspiciousIpStrikes.get(cleanIp) ?? 0;
  if (strikes < SUSPICIOUS_IP_BLOCK_THRESHOLD) {
    return { blocklisted: false, reasons: [] };
  }
  return {
    blocklisted: true,
    reasons: [...(suspiciousIpReasons.get(cleanIp) ?? [])],
  };
}

/* -------------------------------------------------------------------------- */
/* Phase 4 — sealed request envelope verification                             */
/* -------------------------------------------------------------------------- */

// Freshness windows are the canonical values imported from telemetryContract.ts above
// (ENVELOPE_MAX_AGE_MS = 65s, ENVELOPE_MAX_FUTURE_SKEW_MS = 5m). Do not redeclare them here.
const NONCE_TTL_MS = 15 * 60 * 1000;
const NONCE_CACHE_MAX_ENTRIES = 5000;
const seenEnvelopeNonces = new Map<string, number>();

interface EnvelopeVerdict {
  tamperedRequest: boolean;
  replayDetected: boolean;
  requestIntegrityReason: string;
  requestNonce: string;
  /** True only when the payload integrity hash actually verified for a signed envelope. */
  signatureVerified: boolean;
}

function sha256HexLower(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex').toLowerCase();
}

/** Folds navigator.platform / `sec-ch-ua-platform` spellings onto one comparison key. */
function normalizePlatformKey(value: string): string {
  const folded = value.replace(/"/g, '').trim().toLowerCase();
  if (!folded) return '';
  if (/windows|win32|win64|winnt/.test(folded)) return 'windows';
  if (/mac|macintosh|macintel/.test(folded)) return 'macos';
  if (/android/.test(folded)) return 'android';
  if (/ipad/.test(folded)) return 'ipados';
  if (/iphone|ios/.test(folded)) return 'ios';
  if (/chrome ?os|cros/.test(folded)) return 'chromeos';
  if (/linux|x11/.test(folded)) return 'linux';
  return '';
}

function rememberEnvelopeNonce(nonce: string, nowMs: number): boolean {
  for (const [knownNonce, expiresAtMs] of seenEnvelopeNonces) {
    if (expiresAtMs <= nowMs) seenEnvelopeNonces.delete(knownNonce);
  }
  const seenAtMs = seenEnvelopeNonces.get(nonce);
  if (seenAtMs !== undefined && seenAtMs > nowMs) return true;

  while (seenEnvelopeNonces.size >= NONCE_CACHE_MAX_ENTRIES) {
    const oldestKey = seenEnvelopeNonces.keys().next().value;
    if (typeof oldestKey !== 'string') break;
    seenEnvelopeNonces.delete(oldestKey);
  }
  seenEnvelopeNonces.set(nonce, nowMs + NONCE_TTL_MS);
  return false;
}

/**
 * Phase 4 — verifies the sealed request envelope. A missing signature is accepted (older
 * cached bundles), but a present-and-wrong signature, a stale timestamp or a header that
 * contradicts the JS payload marks the request tampered. A reused nonce is a replay.
 */
function verifySecurityEnvelope(args: {
  envelope: Partial<SecurityEnvelope> | null | undefined;
  headers: RawHeaderBag | null | undefined;
  hardwareId: string;
  nowMs: number;
}): EnvelopeVerdict {
  const { envelope, headers, hardwareId, nowMs } = args;
  const reasons: string[] = [];
  let tamperedRequest = false;
  let signatureVerified = false;

  const headerSignature = readRequestHeader(headers, 'x-intel-signature');
  const headerNonce = readRequestHeader(headers, 'x-intel-nonce');
  const headerTimestamp = readRequestHeader(headers, 'x-intel-timestamp');

  const envNonce = typeof envelope?.nonce === 'string' ? envelope.nonce.trim() : '';
  const requestNonce = (envNonce || headerNonce).slice(0, 128);

  const envSignature =
    typeof envelope?.signature === 'string' && envelope.signature.trim()
      ? envelope.signature.trim()
      : headerSignature;

  const envTimestamp =
    typeof envelope?.timestamp === 'number' && Number.isFinite(envelope.timestamp)
      ? envelope.timestamp
      : Number.parseFloat(headerTimestamp);
  const timestamp = Number.isFinite(envTimestamp) && envTimestamp > 0 ? envTimestamp : 0;

  const envelopeUserAgent =
    typeof envelope?.userAgent === 'string' ? envelope.userAgent.trim() : '';
  const envelopePlatform = typeof envelope?.platform === 'string' ? envelope.platform.trim() : '';
  const envelopeScreenResolution =
    typeof envelope?.screenResolution === 'string' ? envelope.screenResolution.trim() : '';
  const envelopeTimezone =
    typeof envelope?.timezone === 'string' ? envelope.timezone.trim() : '';

  // Payload integrity: only a present body signature is verified, and only when the fields the
  // canonical string needs (timestamp + nonce) are present. A signature carried only in headers
  // without an envelope object, or without a nonce, is unverifiable rather than tampered.
  if (envelope && envSignature && timestamp > 0 && requestNonce) {
    const canonical = [
      'INTEL_ENVELOPE_V1',
      String(timestamp),
      requestNonce,
      hardwareId,
      envelopeUserAgent,
      envelopePlatform,
      envelopeScreenResolution,
      envelopeTimezone,
    ].join('|');
    signatureVerified = sha256HexLower(canonical) === envSignature.toLowerCase();
    if (!signatureVerified) {
      tamperedRequest = true;
      reasons.push('Payload integrity hash mismatch');
    }
  }

  // Freshness: a timestamp-less payload is unverifiable, not tampered. A signed payload older
  // than 65 seconds is expired; a client clock ahead by up to five minutes is tolerated.
  if (timestamp > 0 && nowMs - timestamp > ENVELOPE_MAX_AGE_MS) {
    tamperedRequest = true;
    reasons.push('Expired or replayed payload timestamp (>65s)');
  } else if (timestamp > 0 && timestamp - nowMs > ENVELOPE_MAX_FUTURE_SKEW_MS) {
    tamperedRequest = true;
    reasons.push('Payload timestamp too far in the future');
  }

  // Replay: a nonce may be used exactly once inside the 15-minute window.
  let replayDetected = false;
  if (requestNonce) {
    replayDetected = rememberEnvelopeNonce(requestNonce, nowMs);
    if (replayDetected) reasons.push('Duplicate payload nonce (Replay Attack detected)');
  }

  // Header cross-check: the raw HTTP headers must agree with the signed JS payload.
  // Edge proxies (including Vercel) may truncate long User-Agent headers, so an exact
  // string comparison is unsafe. Compare the browser family and OS instead, and treat a
  // prefix relationship as compatible (truncated header).
  const headerUserAgent = readRequestHeader(headers, 'user-agent');
  if (headerUserAgent && envelopeUserAgent && !userAgentsCompatible(headerUserAgent, envelopeUserAgent)) {
    tamperedRequest = true;
    reasons.push('HTTP User-Agent header contradicts JS payload');
  }

  const clientHintPlatform = readRequestHeader(headers, 'sec-ch-ua-platform');
  const payloadPlatformKey = normalizePlatformKey(envelopePlatform);
  const clientHintPlatformKey = normalizePlatformKey(clientHintPlatform);
  // navigator.platform reports "Linux armv8l" on Android and "Linux x86_64" on Chrome OS while
  // the client hint reports "Android" / "Chrome OS" — those pairs are the same platform.
  const androidEquivalent =
    /android/i.test(headerUserAgent) &&
    ((payloadPlatformKey === 'linux' && clientHintPlatformKey === 'android') ||
      (payloadPlatformKey === 'android' && clientHintPlatformKey === 'linux'));
  const chromeOsEquivalent =
    /cros/i.test(headerUserAgent) &&
    ((payloadPlatformKey === 'linux' && clientHintPlatformKey === 'chromeos') ||
      (payloadPlatformKey === 'chromeos' && clientHintPlatformKey === 'linux'));
  const platformPairCompatible = androidEquivalent || chromeOsEquivalent;
  if (
    payloadPlatformKey &&
    clientHintPlatformKey &&
    payloadPlatformKey !== clientHintPlatformKey &&
    !platformPairCompatible
  ) {
    tamperedRequest = true;
    reasons.push('HTTP User-Agent header contradicts JS payload');
  }

  return {
    tamperedRequest,
    replayDetected,
    requestIntegrityReason: Array.from(new Set(reasons)).join('; '),
    requestNonce,
    signatureVerified,
  };
}

/**
 * Task 2b — per-visit suspect scores stored before the 0..10 normalization used a 0..100
 * scale. Any stored value above 10 is treated as legacy and rescaled to 0..10
 * (Math.round(value / 10), clamped); values already within 0..10 pass through untouched.
 */
function normalizeLegacySuspectScore(rawSuspectScore: number): number {
  if (!Number.isFinite(rawSuspectScore)) return 0;
  if (rawSuspectScore <= 10) return Math.max(0, rawSuspectScore);
  return Math.max(0, Math.min(10, Math.round(rawSuspectScore / 10)));
}

const VELOCITY_WINDOW_MS = {
  '5_minutes': 5 * 60 * 1000,
  '1_hour': 60 * 60 * 1000,
  '24_hours': 24 * 60 * 60 * 1000,
} as const;

interface VelocityReport {
  velocity: VelocitySignals;
  events24h: number;
  events1h: number;
  distinctIps24h: number;
  /** Distinct /24 (IPv4) or /64 (IPv6) subnets seen for this visitor in the last 24h. */
  distinctSubnets24h: number;
  /** Distinct hardware ids active in the last 24h — selects fixed_small_corpus vs p98. */
  distinctDailyHardware: number;
  /** 98th percentile of per-visitor daily event counts (large-corpus threshold). */
  p98Events24h: number;
}

const EMPTY_WINDOW: VelocityWindowCounts = { '5_minutes': 0, '1_hour': 0, '24_hours': 0 };

const EMPTY_VELOCITY: VelocitySignals = {
  distinct_ip: { ...EMPTY_WINDOW },
  distinct_linked_id: { ...EMPTY_WINDOW },
  distinct_country: { ...EMPTY_WINDOW },
  events: { ...EMPTY_WINDOW },
  ip_events: { ...EMPTY_WINDOW },
  distinct_ip_by_linked_id: { ...EMPTY_WINDOW },
  distinct_visitor_id_by_linked_id: { ...EMPTY_WINDOW },
};

/**
 * Multi-window SQLite velocity aggregation backing the `velocity` object and the
 * High-Activity Device signal. Cutoffs are ISO-8601 UTC instants so they compare directly
 * against the stored `visited_at_utc` text. A matcher-less in-memory adapter or a query
 * failure degrades to the zero-filled report rather than failing the identify request.
 */
function computeVelocitySignals(
  db: DatabaseAdapter,
  visitorId: string,
  publicIp: string,
  sessionId: string
): VelocityReport {
  const now = Date.now();
  const iso = (ms: number) => new Date(now - ms).toISOString();
  const fiveMinuteCutoff = iso(VELOCITY_WINDOW_MS['5_minutes']);
  const oneHourCutoff = iso(VELOCITY_WINDOW_MS['1_hour']);
  const dayCutoff = iso(VELOCITY_WINDOW_MS['24_hours']);

  try {
    const row = db
      .prepare(
        `SELECT
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS ip_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS ip_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS ip_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN session_id END) AS linked_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN session_id END) AS linked_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN session_id END) AS linked_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN country END) AS country_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN country END) AS country_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN country END) AS country_24h,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS events_5m,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS events_1h,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS events_24h
         FROM visits
         WHERE visitor_id = ?`
      )
      .get(
        fiveMinuteCutoff,
        oneHourCutoff,
        dayCutoff,
        fiveMinuteCutoff,
        oneHourCutoff,
        dayCutoff,
        fiveMinuteCutoff,
        oneHourCutoff,
        dayCutoff,
        fiveMinuteCutoff,
        oneHourCutoff,
        dayCutoff,
        visitorId
      ) as Record<string, unknown> | undefined;

    const num = (value: unknown): number => {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : 0;
    };

    const ipEventsRow = db
      .prepare(
        `SELECT
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS ip_events_5m,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS ip_events_1h,
          SUM(CASE WHEN visited_at_utc >= ? THEN 1 ELSE 0 END) AS ip_events_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS ip_visitors_24h
         FROM visits
         WHERE public_ip = ?`
      )
      .get(fiveMinuteCutoff, oneHourCutoff, dayCutoff, dayCutoff, publicIp) as
      | Record<string, unknown>
      | undefined;

    const linkedIpRow = db
      .prepare(
        `SELECT
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS linked_ips_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS linked_ips_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN public_ip END) AS linked_ips_24h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS linked_visitors_5m,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS linked_visitors_1h,
          COUNT(DISTINCT CASE WHEN visited_at_utc >= ? THEN visitor_id END) AS linked_visitors_24h
         FROM visits
         WHERE session_id = ?`
      )
      .get(
        fiveMinuteCutoff,
        oneHourCutoff,
        dayCutoff,
        fiveMinuteCutoff,
        oneHourCutoff,
        dayCutoff,
        sessionId
      ) as Record<string, unknown> | undefined;

    // High-activity threshold inputs. A small daily hardware corpus uses a fixed rule so a
    // low-traffic site still spots one rotating device; above the corpus limit the 98th
    // percentile of per-visitor daily events becomes the threshold instead.
    const dailyHardwareRow = db
      .prepare(
        `/* intel:dailyhardware */ SELECT COUNT(DISTINCT hardware_id) AS n FROM visitors WHERE updated_at_utc >= ?`
      )
      .get(dayCutoff) as { n?: number } | undefined;
    const subnetRows = db
      .prepare(
        `/* intel:subnets24h */ SELECT public_ip FROM visits WHERE visitor_id = ? AND visited_at_utc >= ?`
      )
      .all(visitorId, dayCutoff) as Array<{ public_ip?: string }>;
    const dailyEventRows = db
      .prepare(
        `/* intel:dailyevents */ SELECT visitor_id, COUNT(*) AS events FROM visits WHERE visited_at_utc >= ? GROUP BY visitor_id`
      )
      .all(dayCutoff) as Array<{ events?: number }>;
    const eventValues = dailyEventRows
      .map((entry) => Number(entry.events))
      .filter((value) => Number.isFinite(value) && value > 0)
      .sort((a, b) => a - b);
    const p98Events24h =
      eventValues.length > 0
        ? eventValues[
            Math.max(
              0,
              Math.min(eventValues.length - 1, Math.ceil(eventValues.length * 0.98) - 1)
            )
          ]
        : 0;
    const distinctSubnets24h = new Set(
      subnetRows
        .map((entry) => subnetOf(String(entry.public_ip || '')))
        .filter((bucket) => bucket.length > 0)
    ).size;
    const distinctDailyHardware = Math.max(0, Number(dailyHardwareRow?.n ?? 0));

    const velocity: VelocitySignals = row
      ? {
          distinct_ip: {
            '5_minutes': num(row.ip_5m),
            '1_hour': num(row.ip_1h),
            '24_hours': num(row.ip_24h),
          },
          distinct_linked_id: {
            '5_minutes': num(row.linked_5m),
            '1_hour': num(row.linked_1h),
            '24_hours': num(row.linked_24h),
          },
          distinct_country: {
            '5_minutes': num(row.country_5m),
            '1_hour': num(row.country_1h),
            '24_hours': num(row.country_24h),
          },
          events: {
            '5_minutes': num(row.events_5m),
            '1_hour': num(row.events_1h),
            '24_hours': num(row.events_24h),
          },
          ip_events: {
            '5_minutes': num(ipEventsRow?.ip_events_5m),
            '1_hour': num(ipEventsRow?.ip_events_1h),
            '24_hours': num(ipEventsRow?.ip_events_24h),
          },
          distinct_ip_by_linked_id: {
            '5_minutes': num(linkedIpRow?.linked_ips_5m),
            '1_hour': num(linkedIpRow?.linked_ips_1h),
            '24_hours': num(linkedIpRow?.linked_ips_24h),
          },
          distinct_visitor_id_by_linked_id: {
            '5_minutes': num(linkedIpRow?.linked_visitors_5m),
            '1_hour': num(linkedIpRow?.linked_visitors_1h),
            '24_hours': num(linkedIpRow?.linked_visitors_24h),
          },
        }
      : { ...EMPTY_VELOCITY };

    return {
      velocity,
      events24h: velocity.events['24_hours'],
      events1h: velocity.events['1_hour'],
      distinctIps24h: velocity.distinct_ip['24_hours'],
      distinctSubnets24h,
      distinctDailyHardware,
      p98Events24h,
    };
  } catch {
    return {
      velocity: { ...EMPTY_VELOCITY },
      events24h: 0,
      events1h: 0,
      distinctIps24h: 0,
      distinctSubnets24h: 0,
      distinctDailyHardware: 0,
      p98Events24h: 0,
    };
  }
}

interface DeviceRarityReport {
  rareDevice: boolean;
  bucket: '<p95' | 'p95-p99' | '>p99';
  share: number;
  sampleSize: number;
  matching: number;
  /** Phase 6 — honest rarity with corpus_n / CI upper bound / zero suppressed contribution. */
  honest: ReturnType<typeof computeHonestRarity>;
}

/**
 * Statistical rarity of this device configuration over the canonical `visits` corpus. The
 * published percentile now comes from decideRarity(corpusN, k) with the exact Clopper-Pearson
 * bound; below N=250 the result is suppressed and contributes ZERO to the risk ledger.
 */
function computeDeviceRarity(
  db: DatabaseAdapter,
  browserDevice: BrowserDeviceInfo
): DeviceRarityReport {
  const honestSuppressed = computeHonestRarity(0, 0);
  try {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    // Corpus size must be distinct hardware profiles, not raw visits, or a single active
    // visitor inflates N into a false p95/p99 claim. Screen/browser strings are volatile
    // and must not define the rarity cohort.
    const row = db
      .prepare(
        `SELECT COUNT(DISTINCT hardware_id) AS total
         FROM visits
         WHERE visited_at_utc >= ? AND hardware_id IS NOT NULL AND hardware_id != ''`
      )
      .get(cutoff) as Record<string, unknown> | undefined;
    const total = Number(row?.total) || 0;
    // This device's own anchor is the singleton observation used by the exact CI gate.
    const matching = total > 0 ? 1 : 0;
    const honest = computeHonestRarity(total, matching);
    if (total < 20) {
      return { rareDevice: false, bucket: '<p95', share: 1, sampleSize: total, matching, honest };
    }
    const share = matching / total;
    // The legacy bucket mirrors the published percentile; a suppressed decision never asserts
    // rarity, so real humans are never penalised by a tiny corpus.
    const bucket: DeviceRarityReport['bucket'] =
      honest.status === 'published' && honest.percentile === 'p99_plus'
        ? '>p99'
        : honest.status === 'published' && honest.percentile === 'p95'
        ? 'p95-p99'
        : '<p95';
    return { rareDevice: bucket !== '<p95', bucket, share, sampleSize: total, matching, honest };
  } catch {
    return { rareDevice: false, bucket: '<p95', share: 1, sampleSize: 0, matching: 0, honest: honestSuppressed };
  }
}

/**
 * Phase 5 — the 0–100 score is no longer an ad-hoc additive sum. It is the clamped total of the
 * orthogonal graded ledger from telemetryContract.ts (via the riskLedger orchestrator). Every
 * family is capped, raw_score is preserved, and RFC 9421 signed agents are exempt from the
 * automation family.
 */
function computeCanonicalRiskLedger(
  input: Parameters<typeof buildGradedRiskLedger>[0]
): GradedRiskLedger {
  return buildGradedRiskLedger(input);
}

function computeSuspectScore100(input: Parameters<typeof buildGradedRiskLedger>[0]): number {
  return computeCanonicalRiskLedger(input).score_0_100;
}

/** Maps the canonical 4-way risk tier onto the legacy 3-way public `RiskLevel`. */
function riskLevelFromTier(tier: RiskTier): RiskLevel {
  return tier === 'Critical' || tier === 'High' ? 'High' : tier === 'Elevated' ? 'Medium' : 'Low';
}

/** tierFor() agreement check: the 0–10 headline and the tier must describe the same band. */
function riskLevelFromScore10(score10: number): RiskLevel {
  return score10 >= 7 ? 'High' : score10 >= 3 ? 'Medium' : 'Low';
}

/**
 * Runtime assertion: the canonical graded ledger's score10 / risk_tier are the ONLY source for
 * the public suspectScore / riskLevel / riskBadgeText. Any divergence is logged loudly (never
 * silently reconciled) so a parallel scoring path can never resurrect itself.
 */
function assertRiskHeadlineConsistency(args: {
  score10: number;
  risk_tier: RiskTier;
  suspectScore: number;
  riskLevel: RiskLevel;
}): boolean {
  const expectedLevel = riskLevelFromTier(args.risk_tier);
  const ok =
    args.suspectScore === args.score10 &&
    args.riskLevel === expectedLevel &&
    riskLevelFromScore10(args.score10) === expectedLevel;
  if (!ok) {
    console.error('[invariant] risk headline diverges from canonical ledger', {
      ledger: { score10: args.score10, risk_tier: args.risk_tier },
      published: { suspectScore: args.suspectScore, riskLevel: args.riskLevel },
    });
  }
  return ok;
}

/**
 * Phase 4 — write identity_lsh_bands ONLY when a hardware_anchors row is inserted or changed.
 * A routine repeat visit never touches the bands table (DO daily row-write quota hygiene).
 * Uses the locked LSH_CONFIG / LSH_WRITE_POLICY from telemetryContract.ts.
 */
function writeHardwareAnchorAndBands(
  db: DatabaseAdapter,
  hardwareId: string,
  visitorId: string,
  simhashHex: string,
  nowUtc: string,
  distinctStorageSeedsCount: number
): boolean {
  if (!hardwareId) return false;
  try {
    const existing = db
      .prepare(
        'SELECT simhash, distinct_storage_seeds_count, visitor_id, first_seen_utc FROM hardware_anchors WHERE hardware_id = ?'
      )
      .get(hardwareId) as
      | { simhash: string; distinct_storage_seeds_count: number; visitor_id: string; first_seen_utc: string }
      | undefined;
    const changed =
      !existing ||
      existing.simhash !== simhashHex ||
      Number(existing.distinct_storage_seeds_count) !== distinctStorageSeedsCount ||
      existing.visitor_id !== visitorId;
    if (!changed) return false;
    const firstSeen = existing?.first_seen_utc || nowUtc;
    db.prepare(
      `INSERT OR REPLACE INTO hardware_anchors
        (hardware_id, visitor_id, simhash, distinct_storage_seeds_count, first_seen_utc, updated_at_utc)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(hardwareId, visitorId, simhashHex, distinctStorageSeedsCount, firstSeen, nowUtc);
    if (LSH_WRITE_POLICY.write_on_hardware_anchor_change_only) {
      let hash: bigint;
      try {
        hash = BigInt(`0x${simhashHex || '0'}`);
      } catch {
        hash = 0n;
      }
      const bands = bandHashes(hash);
      for (const band of bands.slice(0, LSH_CONFIG.bands)) {
        db.prepare(
          `INSERT OR IGNORE INTO identity_lsh_bands (band_idx, band_hash, hardware_id) VALUES (?, ?, ?)`
        ).run(band.band_idx, band.band_hash, hardwareId);
      }
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Retrieve fuzzy candidates from the canonical LSH band index. Candidate retrieval is a pure
 * read; the collision-density guard in decideLshFuzzyMatch is deliberately independent of how
 * many rows this function returns.
 */
function retrieveLshCandidates(
  db: DatabaseAdapter,
  profile: Record<string, unknown>
): Array<{ hardwareId: string; simhash: bigint; visitorId?: string | null }> {
  try {
    const hash = simhash512(profile);
    const hardwareIds = new Set<string>();
    for (const band of bandHashes(hash)) {
      const rows = db
        .prepare('SELECT hardware_id FROM identity_lsh_bands WHERE band_idx = ? AND band_hash = ?')
        .all(band.band_idx, band.band_hash) as Array<{ hardware_id: string }>;
      for (const row of rows) if (row.hardware_id) hardwareIds.add(row.hardware_id);
    }
    const candidates: Array<{ hardwareId: string; simhash: bigint; visitorId?: string | null }> = [];
    for (const hardwareId of hardwareIds) {
      const anchor = db
        .prepare('SELECT hardware_id, visitor_id, simhash FROM hardware_anchors WHERE hardware_id = ?')
        .get(hardwareId) as { hardware_id: string; visitor_id?: string | null; simhash: string } | undefined;
      if (!anchor?.simhash) continue;
      try {
        candidates.push({
          hardwareId,
          simhash: BigInt(`0x${anchor.simhash}`),
          visitorId: anchor.visitor_id ?? null,
        });
      } catch {
        // A corrupt anchor hash is skipped, never a reason to fail identification.
      }
    }
    return candidates;
  } catch {
    return [];
  }
}

/**
 * Local, additive input shape for the honest identity-confidence wrapper. The shared
 * `computeHonestIdentityConfidence` signature is owned by another module, so this extends it
 * *locally* with the real resolver evidence without weakening the shared type. Every added
 * field is optional and both casing variants are supplied by the caller, which keeps the call
 * compatible with either shared-field naming convention.
 */
interface ResolverBackedHonestConfidenceInput {
  labeledPairs: number;
  heldOutEce: number;
  matchStage:
    | 'storage_continuity'
    | 'exact_hardware'
    | 'lsh_fuzzy'
    | 'privacy_hardened'
    | 'new_enrollment';
  calibratedScore: number;
  /** All six weighted evidence components are wired explicitly (no component left implicit). */
  match_tier?: string;
  matchScore?: number;
  match_score?: number;
  match_mode?: string;
  structural_anchor_ratio?: number;
  structuralAnchorRatio?: number;
  matched_anchors?: number;
  total_anchors?: number;
  /** Continuity corroboration (capped, matched tiers only). */
  storageHealed?: boolean;
  visitContinuity?: number;
  profileAgeDays?: number;
  distinct_storage_seeds_count?: number;
  distinctStorageSeedsCount?: number;
  browser_family_consensus?: boolean;
  browserFamilyConsensus?: boolean;
  os_family_consensus?: boolean;
  osFamilyConsensus?: boolean;
  storage_valid?: boolean;
  storageValid?: boolean;
  storage_healed?: boolean;
  incognito?: boolean;
  isMobileIos?: boolean;
  firstSeenDesktop?: boolean;
  consistencyFlags?: string[];
  rfpOrTor?: boolean;
  genuineSpoof?: boolean;
}

/**
 * A fresh, storage-less context may only inherit a canonical visitor through the fuzzy path when
 * stable structural anchors actually agree with the candidate's stored profile. Volatile axes
 * (screen, DPR, touch, IP, timezone) are deliberately excluded: they change between reloads and
 * resizes and must never mint a returning visitor out of an unrelated fresh profile.
 */
function structuralAnchorsMatch(
  db: DatabaseAdapter,
  profile: ResolverProfile,
  candidateVisitorId: string,
  identityHardwareFingerprint: string
): { matched: boolean; reasons: string[] } {
  try {
    const row = db
      .prepare('SELECT profile_json, hardware_fingerprint FROM visitor_profiles WHERE visitor_id = ?')
      .get(candidateVisitorId) as
      | { profile_json?: unknown; hardware_fingerprint?: unknown }
      | undefined;
    if (!row) return { matched: false, reasons: [] };
    if (
      typeof row.hardware_fingerprint === 'string' &&
      row.hardware_fingerprint.length > 0 &&
      row.hardware_fingerprint === identityHardwareFingerprint
    ) {
      return { matched: true, reasons: ['exact hardware fingerprint anchor'] };
    }
    if (typeof row.profile_json !== 'string') return { matched: false, reasons: [] };
    const stored = JSON.parse(row.profile_json) as Record<string, unknown>;
    const current = profile as unknown as Record<string, unknown>;
    const nested = (value: unknown, key: string): unknown =>
      value && typeof value === 'object' ? (value as Record<string, unknown>)[key] : undefined;
    const pairs: Array<{ label: string; current: unknown; stored: unknown; hard: boolean }> = [
      { label: 'gpu vendor', current: nested(current.gpu, 'vendor'), stored: nested(stored.gpu, 'vendor'), hard: false },
      { label: 'gpu renderer', current: nested(current.gpu, 'renderer'), stored: nested(stored.gpu, 'renderer'), hard: true },
      { label: 'canvas hash', current: nested(current.canvas, 'hash'), stored: nested(stored.canvas, 'hash'), hard: true },
      { label: 'audio hash', current: nested(current.audio, 'hash'), stored: nested(stored.audio, 'hash'), hard: true },
      { label: 'cpu cores', current: nested(current.cpu, 'cores'), stored: nested(stored.cpu, 'cores'), hard: true },
      { label: 'os family', current: nested(current.os, 'family'), stored: nested(stored.os, 'family'), hard: false },
      { label: 'browser family', current: nested(current.browser, 'family'), stored: nested(stored.browser, 'family'), hard: false },
    ];
    let matches = 0;
    let hardMatches = 0;
    const reasons: string[] = [];
    for (const pair of pairs) {
      if (
        pair.current !== undefined &&
        pair.current !== null &&
        String(pair.current) === String(pair.stored)
      ) {
        matches += 1;
        if (pair.hard) hardMatches += 1;
        reasons.push(pair.label);
      }
    }
    // A cross-cloud LSH candidate needs >=3 structural anchors (including >=1 hard anchor)
    // before a storage-less context may inherit its canonical visitor id. Two anchors in a
    // homogeneous container collide far too often to mint a "returning device".
    return { matched: matches >= 3 && hardMatches >= 1, reasons };
  } catch {
    return { matched: false, reasons: [] };
  }
}

/**
 * Independent-axis corroboration for a storage-less hardware / LSH match. A homogeneous
 * software-rendered cloud container can clone the same WebGL / canvas / audio hashes across
 * unrelated visitors, so a bare hardware hit may only inherit another visitor's canonical id
 * when the stored profile's browser + OS family AND the visitor's ASN history agree. The gate
 * fails closed: any missing, unreadable or disagreeing axis blocks the adoption.
 */
function hardwareOnlyMatchCorroborated(
  db: DatabaseAdapter,
  candidateVisitorId: string,
  browserFamily: string,
  osFamily: string,
  asn: string
): boolean {
  if (!candidateVisitorId || !browserFamily || !osFamily || !asn || asn === 'Unknown') return false;
  try {
    const row = db
      .prepare('SELECT profile_json FROM visitor_profiles WHERE visitor_id = ?')
      .get(candidateVisitorId) as { profile_json?: unknown } | undefined;
    if (typeof row?.profile_json !== 'string') return false;
    const stored = JSON.parse(row.profile_json) as Record<string, unknown>;
    const nested = (value: unknown, key: string): unknown =>
      value && typeof value === 'object' ? (value as Record<string, unknown>)[key] : undefined;
    const storedBrowserFamily = browserFamilyKey(
      String(nested(nested(stored, 'browser'), 'family') ?? '')
    );
    const storedOsFamily = osFamilyKey(String(nested(nested(stored, 'os'), 'family') ?? ''));
    if (!storedBrowserFamily || !storedOsFamily) return false;
    if (storedBrowserFamily !== browserFamily || storedOsFamily !== osFamily) return false;
    return Boolean(
      db
        .prepare('SELECT 1 FROM visits WHERE visitor_id = ? AND asn = ? LIMIT 1')
        .get(candidateVisitorId, asn)
    );
  } catch {
    return false;
  }
}

/**
 * Persist the BGP ASN and its resolved RDAP netblock organisation in the same cache row so
 * both facts are always read back together; a reassignment mismatch is reported when the
 * cached netblock org diverges from the live ASN org.
 */
function persistRdapNetblockOrg(
  db: DatabaseAdapter,
  asn: string,
  org: string
): string | null {
  if (!asn || asn === 'Unknown' || !org || org === 'Unknown') return null;
  try {
    const prefix = normalizeAsnLabel(asn) || asn;
    db.prepare(
      `INSERT OR REPLACE INTO rdap_prefix_cache (prefix, org, asn, fetched_at_ms) VALUES (?, ?, ?, ?)`
    ).run(prefix, org, asn, Date.now());
    return org;
  } catch {
    return null;
  }
}

/** Idempotent schema-version marker — used from the Worker's blockConcurrencyWhile-style init. */
function markSchemaMigration(db: DatabaseAdapter, version: string): void {
  try {
    db.prepare('INSERT OR IGNORE INTO schema_migrations (version, applied_at_utc) VALUES (?, ?)').run(
      version,
      new Date().toISOString()
    );
  } catch {
    // A marker write must never fail a request.
  }
}

/**
 * Startup self-check (non-throwing): the four frozen tuples must still be produced by the
 * canonical rubric. Uses the contract helpers directly so any drift is logged immediately.
 */
function assertFrozenRiskTuples(): void {
  for (const fixture of verifyGradedRiskFixtures()) {
    // The fixture carries its own frozen tuple, so names can never drift out of sync.
    const actual: readonly number[] = [
      fixture.ledger.automation,
      fixture.ledger.tampering,
      fixture.ledger.network,
      fixture.ledger.environment,
      fixture.ledger.velocity,
    ];
    const capSum = Object.values(RISK_FAMILY_CAPS).reduce((sum, value) => sum + value, 0);
    const ok =
      fixture.ok &&
      actual.every((value, index) => value === fixture.expected[index]) &&
      capSum === 130;
    if (!ok) {
      console.error(
        'Frozen graded-risk tuple check failed:',
        fixture.name,
        JSON.stringify(actual),
        'expected',
        fixture.expected
      );
    }
  }
}
assertFrozenRiskTuples();

async function lookupVerifiedGeolocation(
  visitorIp: string,
  isPublic: boolean,
  options?: { cacheWrite?: boolean; edge?: EdgeGeoHeaders }
): Promise<LocationInfo> {
  const empty = (verified: boolean): LocationInfo => ({
    publicIp: verified ? visitorIp : 'Unavailable',
    city: 'Unavailable',
    region: 'Unavailable',
    country: 'Unavailable',
    countryCode: '',
    latitude: null,
    longitude: null,
    isp: 'Unknown',
    org: 'Unknown',
    asn: 'Unknown',
    isVpnOrHosting: false,
    isIpVerified: verified,
    isLocationVerified: false,
  });

  if (!isPublic || !visitorIp || visitorIp === 'Unavailable') {
    return empty(false);
  }

  // The Cloudflare edge already resolved this request from `request.cf`. When it carries a
  // city or coordinates, that answer is authoritative and consistent, and it removes a
  // 4-provider waterfall (and its latency) from the critical path. A country-only edge
  // answer still probes the providers, because they may know the city.
  const edge = options?.edge;
  const edgeHasCoords =
    edge !== null &&
    edge !== undefined &&
    edge.latitude !== null &&
    edge.longitude !== null &&
    Boolean(edge.countryCode);
  const edgeHasCity = Boolean(edge?.countryCode && edge.city);
  if (edge && (edgeHasCoords || edgeHasCity)) {
    const net = normalizeIspAndOrg(edge.organization, edge.organization, edge.asn, false);
    return {
      publicIp: visitorIp,
      city: edge.city || 'Unknown',
      region: edge.region || 'Unknown',
      country: edge.country || countryNameFromCode(edge.countryCode),
      countryCode: edge.countryCode,
      latitude: edge.latitude,
      longitude: edge.longitude,
      isp: net.isp,
      org: net.org,
      asn: net.asn || edge.asn || 'Unknown',
      timezone: edge.timezone || undefined,
      isVpnOrHosting: false,
      isIpVerified: true,
      isLocationVerified: true,
      locationSource: 'edge',
      locationPrecision: edge.city ? 'city' : 'country',
      isTor: edge.isTorNetwork,
      isTorExit: edge.isTorNetwork,
    };
  }

  const nowMs = Date.now();
  let cached:
    | {
        city: string;
        region: string;
        country: string;
        country_code: string;
        latitude: number | null;
        longitude: number | null;
        isp: string;
        org: string;
        asn: string;
        is_vpn_or_hosting: number;
        timezone: string | null;
        verified_at_ms: number;
      }
    | undefined;
  try {
    cached = db
      .prepare(
        'SELECT city, region, country, country_code, latitude, longitude, isp, org, asn, is_vpn_or_hosting, timezone, verified_at_ms FROM verified_geo_cache_v3 WHERE ip_address = ?'
      )
      .get(visitorIp) as typeof cached;
  } catch {
    // An unreadable store (e.g. a blocked daily Durable Object quota) must never fail
    // geolocation: fall through to the provider cascade instead.
    cached = undefined;
  }

  // Only a COMPLETE cache entry may short-circuit the provider cascade. A miss that
  // recorded "Unavailable" city/country (provider rate-limit, cold start, ISP-only RIPE
  // answer) is deliberately treated as absent, so the next request — the client retry
  // loop — queries the providers again instead of replaying the miss for six hours.
  const cachedHasLocation =
    Boolean(cached) &&
    (!isMissingGeoValue(cached?.city) || !isMissingGeoValue(cached?.country));
  const cachedHasNetwork =
    Boolean(cached) &&
    !isMissingGeoValue(cached?.isp) &&
    !/^autonomous system\b/i.test(cached?.isp ?? '') &&
    cached?.isp !== 'Standard Network';
  const cachedIsComplete =
    cachedHasLocation &&
    cachedHasNetwork &&
    typeof cached?.latitude === 'number' &&
    typeof cached?.longitude === 'number';

  if (cached && nowMs - cached.verified_at_ms < 6 * 3600 * 1000 && cachedIsComplete) {
    return {
      publicIp: visitorIp,
      city: cached.city,
      region: cached.region,
      country: cached.country,
      countryCode: cached.country_code,
      latitude: cached.latitude,
      longitude: cached.longitude,
      isp: cached.isp,
      org: cached.org,
      asn: cached.asn,
      timezone: cached.timezone || undefined,
      isVpnOrHosting: Boolean(cached.is_vpn_or_hosting),
      isIpVerified: true,
      isLocationVerified:
        !isMissingGeoValue(cached.city) || !isMissingGeoValue(cached.country),
      locationSource: 'provider',
      locationPrecision: !isMissingGeoValue(cached.city)
        ? 'city'
        : !isMissingGeoValue(cached.region)
        ? 'region'
        : !isMissingGeoValue(cached.country)
        ? 'country'
        : 'unknown',
    };
  }

  const cleanField = (val: unknown): string => {
    if (typeof val !== 'string') return 'Unknown';
    const trimmed = val.trim();
    return trimmed.length > 0 ? trimmed : 'Unknown';
  };
  const cleanText = (val: unknown): string => (typeof val === 'string' ? val.trim() : '');
  const finiteNumber = (val: unknown): number | null =>
    typeof val === 'number' && Number.isFinite(val) ? val : null;
  const network = (
    isp: unknown,
    org: unknown,
    asn: unknown,
    hostile = false
  ): ReturnType<typeof normalizeIspAndOrg> =>
    normalizeIspAndOrg(isp, org, asn, hostile);

  const build = (input: {
    city: string;
    region: string;
    country: string;
    countryCode: string;
    latitude: number | null;
    longitude: number | null;
    isp: string;
    org: string;
    asn: string;
    isVpnOrHosting: boolean;
    timezone?: string;
  }): LocationInfo => ({
    publicIp: visitorIp,
    ...input,
    isIpVerified: true,
    isLocationVerified: !isMissingGeoValue(input.city) || !isMissingGeoValue(input.country),
    locationSource: 'provider',
    locationPrecision: !isMissingGeoValue(input.city)
      ? 'city'
      : !isMissingGeoValue(input.region)
      ? 'region'
      : !isMissingGeoValue(input.country)
      ? 'country'
      : 'unknown',
  });

  /** Cache write shared by every provider; a failed write never loses the answer. */
  const persist = (location: LocationInfo): void => {
    try {
      db.prepare(
        `INSERT OR REPLACE INTO verified_geo_cache_v3 (
          ip_address, city, region, country, country_code, latitude, longitude, isp, org, asn, is_vpn_or_hosting, timezone, verified_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        visitorIp,
        location.city,
        location.region,
        location.country,
        location.countryCode,
        location.latitude,
        location.longitude,
        location.isp,
        location.org,
        location.asn,
        location.isVpnOrHosting ? 1 : 0,
        location.timezone ?? null,
        nowMs
      );
    } catch {
      // Cache failure is non-fatal: the resolved answer is still returned.
    }
  };

  /**
   * Providers run in PARALLEL with a shared 6 s budget instead of five sequential 3 s
   * calls. On a high-latency Tor circuit a sequential cascade used to exhaust the budget
   * on the first two providers, leaving only RIPE's ASN — i.e. an ISP with no location.
   * Parallel probes make a usable answer far more likely and cap the whole lookup at 6 s.
   */
  const PROVIDER_TIMEOUT_MS = 4000;
  const probe = async (url: string, parse: (data: Record<string, unknown>) => LocationInfo | null): Promise<LocationInfo | null> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
    try {
      const resp = await fetch(url, {
        signal: controller.signal,
        headers: { Accept: 'application/json', 'User-Agent': 'IntelSystem/1.0' },
      });
      if (!resp.ok) return null;
      const data = (await resp.json()) as Record<string, unknown>;
      const parsed = parse(data);
      return parsed && scoreGeoLocation(parsed) > 0 ? parsed : null;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  };

  // Provider 1: ipwho.is
  const probeIpWho = () =>
    probe(`https://ipwho.is/${encodeURIComponent(visitorIp)}`, (data) => {
      if (data.success === false) return null;
      const providerIp = normalizeIpCandidate(typeof data.ip === 'string' ? data.ip : '');
      if (!providerIp || providerIp.toLowerCase() !== visitorIp.toLowerCase()) return null;
      const conn = (data.connection as Record<string, unknown>) || {};
      const sec = (data.security as Record<string, unknown>) || {};
      const net = network(conn.isp, conn.org, conn.asn, Boolean(sec.vpn || sec.proxy || sec.tor || sec.hosting));
      const providerTimezone = (data.timezone as Record<string, unknown> | undefined)?.id;
      const location = build({
        city: cleanField(data.city),
        region: cleanField(data.region),
        country: cleanField(data.country),
        countryCode: cleanText(data.country_code).toUpperCase(),
        latitude: finiteNumber(data.latitude),
        longitude: finiteNumber(data.longitude),
        isp: net.isp,
        org: net.org,
        asn: net.asn,
        isVpnOrHosting: net.isVpnOrHosting,
        timezone: cleanText(providerTimezone) || undefined,
      });
      return location;
    });

  // Provider 2: ipapi.co
  const probeIpApi = () =>
    probe(`https://ipapi.co/${encodeURIComponent(visitorIp)}/json/`, (data) => {
      if (data.error) return null;
      const providerIp = normalizeIpCandidate(typeof data.ip === 'string' ? data.ip : '');
      if (providerIp && providerIp.toLowerCase() !== visitorIp.toLowerCase()) return null;
      const net = network(data.org, data.org, data.asn);
      return build({
        city: cleanField(data.city),
        region: cleanField(data.region),
        country: cleanField(data.country_name || data.country),
        countryCode: cleanText(data.country_code).toUpperCase(),
        latitude: finiteNumber(data.latitude),
        longitude: finiteNumber(data.longitude),
        isp: net.isp,
        org: net.org,
        asn: net.asn,
        isVpnOrHosting: net.isVpnOrHosting,
        timezone: cleanText(data.timezone) || undefined,
      });
    });

  // Provider 3: freeipapi.com
  const probeFreeIpApi = () =>
    probe(`https://free.freeipapi.com/api/v1/json/${encodeURIComponent(visitorIp)}`, (data) => {
      const providerIp = normalizeIpCandidate(
        typeof data.ipAddress === 'string'
          ? data.ipAddress
          : typeof data.ip === 'string'
          ? data.ip
          : ''
      );
      if (!providerIp || providerIp.toLowerCase() !== visitorIp.toLowerCase()) return null;
      const net = network(data.asnOrganization, data.asnOrganization, data.asn, Boolean(data.isProxy));
      const timezones = Array.isArray(data.timeZones) ? data.timeZones : [];
      return build({
        city: cleanField(data.cityName),
        region: cleanField(data.regionName),
        country: cleanField(data.countryName),
        countryCode: cleanText(data.countryCode).toUpperCase(),
        latitude: finiteNumber(data.latitude),
        longitude: finiteNumber(data.longitude),
        isp: net.isp,
        org: net.org,
        asn: net.asn,
        isVpnOrHosting: net.isVpnOrHosting,
        timezone: cleanText(timezones[0]) || undefined,
      });
    });

  // Provider 4: ipinfo.io — the org string carries `AS15169 Google LLC`.
  const probeIpInfo = () =>
    probe(`https://ipinfo.io/${encodeURIComponent(visitorIp)}/json`, (data) => {
      const providerIp = normalizeIpCandidate(typeof data.ip === 'string' ? data.ip : '');
      if (providerIp && providerIp.toLowerCase() !== visitorIp.toLowerCase()) return null;
      const countryCodeRaw = cleanText(data.country).toUpperCase();
      const country = countryNameFromCode(countryCodeRaw) || cleanField(data.country);
      const locParts = typeof data.loc === 'string' ? data.loc.split(',') : [];
      const latitude = locParts[0] ? Number.parseFloat(locParts[0]) : null;
      const longitude = locParts[1] ? Number.parseFloat(locParts[1]) : null;
      const orgRaw = cleanText(data.org);
      const asnMatch = /^(AS\d+)\s+(.+)$/i.exec(orgRaw);
      const orgName = asnMatch?.[2] || orgRaw;
      const net = network(orgName, orgName, asnMatch?.[1] || '');
      return build({
        city: cleanField(data.city),
        region: cleanField(data.region),
        country,
        countryCode: countryCodeRaw,
        latitude: Number.isFinite(latitude) ? latitude : null,
        longitude: Number.isFinite(longitude) ? longitude : null,
        isp: net.isp,
        org: net.org,
        asn: net.asn,
        isVpnOrHosting: net.isVpnOrHosting,
        timezone: cleanText(data.timezone) || undefined,
      });
    });

  const settled = await Promise.allSettled([
    probeIpWho(),
    probeIpApi(),
    probeFreeIpApi(),
    probeIpInfo(),
  ]);
  const candidates = settled
    .filter((entry): entry is PromiseFulfilledResult<LocationInfo | null> => entry.status === 'fulfilled')
    .map((entry) => entry.value)
    .filter((entry): entry is LocationInfo => entry !== null)
    // Best answer wins: city > country > ISP > coordinates. Ties keep provider order.
    .sort((a, b) => scoreGeoLocation(b) - scoreGeoLocation(a));

  const best = candidates[0];
  if (best) {
    if (options?.cacheWrite !== false) persist(best);
    return best;
  }

  // Provider 5: RIPE Stat prefix overview — ASN attribution when no provider returned geo.
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
    const resp = await fetch(
      `https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(visitorIp)}`,
      {
        signal: controller.signal,
        headers: { Accept: 'application/json', 'User-Agent': 'IntelSystem/1.0' },
      }
    );
    clearTimeout(timer);

    if (resp.ok) {
      const data = (await resp.json()) as {
        data?: { asns?: Array<{ asn?: number }> };
      };
      const asnNumber = data.data?.asns?.[0]?.asn;
      if (typeof asnNumber === 'number' && Number.isFinite(asnNumber)) {
        const asn = `AS${asnNumber}`;
        // Never label a numeric ASN "Standard Network": the AS label is honest.
        const org = cloudProviderOrgForAsn(asn) || asn;
        const netDetails = normalizeIspAndOrg(org, org, asn, false);
        const location = build({
          city: 'Unavailable',
          region: 'Unavailable',
          country: 'Unavailable',
          countryCode: '',
          latitude: null,
          longitude: null,
          isp: netDetails.isp,
          org: netDetails.org,
          asn: netDetails.asn,
          isVpnOrHosting: false,
        });
        if (options?.cacheWrite !== false) persist(location);
        return location;
      }
    }
  } catch {
    // Ignore
  }

  return empty(true);
}

/** Preference score for competing provider payloads (higher is better). */
function scoreGeoLocation(location: LocationInfo): number {
  let score = 0;
  if (!isMissingGeoValue(location.city)) score += 8;
  if (!isMissingGeoValue(location.country)) score += 4;
  if (
    !isMissingGeoValue(location.isp) &&
    !/^autonomous system\b/i.test(location.isp) &&
    location.isp !== 'Standard Network'
  ) {
    score += 2;
  }
  if (typeof location.latitude === 'number' && typeof location.longitude === 'number') {
    score += 1;
  }
  return score;
}

/**
 * Tor exit relays: Onionoo carries the relay's country and operator even when every
 * IP-geolocation provider is rate-limited or only returns an ASN. Without this, a Tor
 * visitor could see an ISP but "Unavailable" for location. Country is the honest floor:
 * the exit relay's country, never the user's claimed city.
 */
function applyTorRelayFallback(location: LocationInfo, visitorIp: string): LocationInfo {
  const hasCity = !isMissingGeoValue(location.city);
  const hasCountry = !isMissingGeoValue(location.country);
  if (hasCity && hasCountry) return location;

  const relay = lookupTorRelayMetadata(visitorIp);
  if (!relay) return location;

  const countryCode = (relay.country ?? '').trim().toUpperCase();
  const countryName = countryCode ? countryNameFromCode(countryCode) || countryCode : '';
  const relayAsn = normalizeAsnLabel(relay.as) || '';
  const relayIsp = (relay.asName ?? '').trim();
  const existingIspIsReal =
    !isMissingGeoValue(location.isp) &&
    !/^autonomous system\b/i.test(location.isp) &&
    location.isp !== 'Standard Network';
  const isp = existingIspIsReal ? location.isp : relayIsp || relayAsn || location.isp;

  if (!countryName && !relayAsn && !relayIsp) return location;

  return {
    ...location,
    country: hasCountry ? location.country : countryName || location.country,
    countryCode: location.countryCode || countryCode,
    isp,
    org: !isMissingGeoValue(location.org) ? location.org : isp,
    asn: normalizeAsnLabel(location.asn) || relayAsn || location.asn,
    isVpnOrHosting: true,
    isTor: true,
    isLocationVerified: hasCity || Boolean(countryName),
  };
}

async function resolveLocationWithTorFallback(
  visitorIp: string,
  isPublic: boolean,
  options?: { cacheWrite?: boolean; edge?: EdgeGeoHeaders }
): Promise<LocationInfo> {
  const location = await lookupVerifiedGeolocation(visitorIp, isPublic, options);
  return applyTorRelayFallback(location, visitorIp);
}
function sanitizeBrowserDevice(input: Partial<BrowserDeviceInfo> | undefined): BrowserDeviceInfo {
  const safeStr = (val: unknown, fallback: string): string => {
    if (typeof val !== 'string') return fallback;
    const t = val.trim();
    return t.length > 0 ? t.slice(0, 120) : fallback;
  };

  const validDeviceTypes = ['Desktop', 'Mobile', 'Tablet', 'Unknown'] as const;
  const rawType = input?.deviceType;
  const deviceType: BrowserDeviceInfo['deviceType'] =
    rawType && validDeviceTypes.includes(rawType) ? rawType : 'Unknown';

  // The collector mirrors its storage-physics verdict onto the device object; these
  // aliases are carried through untouched so the client tile can read them.
  const incognitoAlias =
    typeof input?.incognito === 'boolean' ||
    typeof input?.isIncognito === 'boolean' ||
    typeof input?.privateMode === 'boolean'
      ? Boolean(input?.incognito || input?.isIncognito || input?.privateMode)
      : undefined;
  const rawIncognitoMethod =
    typeof input?.incognitoMethod === 'string' && input.incognitoMethod.trim()
      ? input.incognitoMethod.trim().slice(0, 120)
      : undefined;
  const incognitoMethod = humanIncognitoMethod(
    rawIncognitoMethod,
    Boolean(incognitoAlias),
    storageProbeInconclusive(rawIncognitoMethod)
  );
  const idbDurabilityRatio =
    typeof input?.idbDurabilityRatio === 'number' && Number.isFinite(input.idbDurabilityRatio)
      ? Number(input.idbDurabilityRatio)
      : undefined;
  const opfsFlushMs =
    typeof input?.opfsFlushMs === 'number' && Number.isFinite(input.opfsFlushMs)
      ? Number(input.opfsFlushMs)
      : undefined;

  // Genuine-device gate + exact phone-model fields. Only accepted for visitors the
  // client classified as mobile, so a desktop payload can never inject a phone name.
  const deviceKind =
    input?.deviceKind === 'mobile' || input?.deviceKind === 'tablet' || input?.deviceKind === 'pc'
      ? input.deviceKind
      : undefined;
  const genuineMobile =
    typeof input?.genuineMobile === 'boolean' ? input.genuineMobile : undefined;
  const devtoolsDeviceEmulation =
    typeof input?.devtoolsDeviceEmulation === 'boolean'
      ? input.devtoolsDeviceEmulation
      : undefined;
  const optStr = (val: unknown, max = 96): string | undefined => {
    if (typeof val !== 'string') return undefined;
    const t = val.trim();
    return t ? t.slice(0, max) : undefined;
  };
  const mobileFieldsAllowed = deviceKind === 'mobile' && genuineMobile === true;

  return {
    browser: safeStr(input?.browser, 'Unknown'),
    os: safeStr(input?.os, 'Unknown'),
    deviceType,
    platform: safeStr(input?.platform, 'Unavailable'),
    screenResolution: safeStr(input?.screenResolution, 'Unavailable'),
    pixelRatio: safeStr(input?.pixelRatio, 'Unavailable'),
    language: safeStr(input?.language, 'Unavailable'),
    timezone: safeStr(input?.timezone, 'Unavailable'),
    deviceKind,
    genuineMobile,
    devtoolsDeviceEmulation,
    reportedModel: optStr(input?.reportedModel),
    phoneBrand: mobileFieldsAllowed ? optStr(input?.phoneBrand) : undefined,
    phoneModel: mobileFieldsAllowed ? optStr(input?.phoneModel) : undefined,
    phoneModelCode: mobileFieldsAllowed ? optStr(input?.phoneModelCode) : undefined,
    phoneDeviceCode: mobileFieldsAllowed ? optStr(input?.phoneDeviceCode) : undefined,
    phoneDisplayLabel: mobileFieldsAllowed ? optStr(input?.phoneDisplayLabel) : undefined,
    incognito: incognitoAlias,
    isIncognito: incognitoAlias,
    privateMode: incognitoAlias,
    incognitoMethod,
    // Storage probe internals are never part of a user-visible browser payload.
  };
}

function detectServerRegion(req?: express.Request): {
  regionCode: string;
  regionLabel: string;
} {
  const envRegion =
    process.env.VERCEL_REGION ||
    process.env.CLOUD_RUN_REGION ||
    '';
  const appUrl = process.env.APP_URL || '';
  const vercelIdHeader = req ? String(req.headers['x-vercel-id'] || '') : '';
  const hostHeader = req ? String(req.headers['x-forwarded-host'] || req.headers.host || '') : '';
  const combined = `${envRegion} ${vercelIdHeader} ${appUrl} ${hostHeader}`.toLowerCase();

  const regionNames: Record<string, string> = {
    'bom1': 'bom1 (Mumbai, India)',
    'sin1': 'sin1 (Singapore)',
    'hnd1': 'hnd1 (Tokyo, Japan)',
    'icn1': 'icn1 (Seoul, South Korea)',
    'syd1': 'syd1 (Sydney, Australia)',
    'fra1': 'fra1 (Frankfurt, Germany)',
    'lhr1': 'lhr1 (London, UK)',
    'cdg1': 'cdg1 (Paris, France)',
    'iad1': 'iad1 (Washington, D.C., USA)',
    'sfo1': 'sfo1 (San Francisco, USA)',
    'pdx1': 'pdx1 (Portland, USA)',
    'cle1': 'cle1 (Cleveland, USA)',
    'gru1': 'gru1 (Sao Paulo, Brazil)',
    'asia-southeast1': 'asia-southeast1 (Singapore)',
    'asia-south1': 'asia-south1 (Mumbai, India)',
    'asia-south2': 'asia-south2 (Delhi, India)',
    'asia-east1': 'asia-east1 (Taiwan)',
    'asia-northeast1': 'asia-northeast1 (Tokyo, Japan)',
    'europe-west1': 'europe-west1 (Belgium)',
    'europe-west2': 'europe-west2 (London, UK)',
    'us-central1': 'us-central1 (Iowa, USA)',
    'us-east1': 'us-east1 (South Carolina, USA)',
    'us-west1': 'us-west1 (Oregon, USA)',
  };

  for (const [code, label] of Object.entries(regionNames)) {
    if (combined.includes(code)) {
      return { regionCode: code, regionLabel: label };
    }
  }

  return {
    regionCode: 'global-edge',
    regionLabel: 'Global Edge Network',
  };
}

export const app = express();
app.set('trust proxy', true);
app.use(cookieParser());

// Advertise Accept-CH / Critical-CH and parse every incoming `sec-ch-ua*` hint into
// `(req as any).intelClientHints` for the shared UA normalizer. Critical-CH makes the
// high-entropy hints arrive on the FIRST navigation instead of after a reload.
app.use(clientHintsMiddleware);
// Ask mobile Chromium browsers to expose UA-CH model/architecture hints, and keep
// Compute Pressure available.
app.use((_req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'compute-pressure=*, ch-ua-model=(self), ch-ua-platform-version=(self), ch-ua-arch=(self), ch-ua-form-factors=(self)'
  );
  next();
});

const handleNetworkHeadPing = (_req: express.Request, res: express.Response) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Timing-Allow-Origin', '*');
  res.status(200).end();
};

const handleNetworkPing = (_req: express.Request, res: express.Response) => {
  const serverTimestamp = Date.now();
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Timing-Allow-Origin', '*');
  res.status(200).json({ ok: true, serverTimestamp, serverTimestampMs: serverTimestamp });
};

app.head('/api/network/ping', handleNetworkHeadPing);
app.get('/api/network/ping', handleNetworkPing);

/**
 * ISP + location retry endpoint.
 *
 * The identify response can legitimately arrive before a rate-limited provider answers,
 * leaving `city`/`country` as "Unavailable" and the ISP as "Unknown". The dashboard then
 * polls this endpoint with backoff until both resolve. It never creates a visit and never
 * serves an incomplete cache entry (see `lookupVerifiedGeolocation`).
 */
app.get('/api/intel/geolocation', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  try {
    const { ip: visitorIp, isPublic } = extractVisitorIp(req);
    const edgeGeo = extractEdgeGeo(req);

    let location = mergeLocationWithEdge(
      await resolveLocationWithTorFallback(visitorIp, isPublic, { cacheWrite: false, edge: edgeGeo }),
      edgeGeo
    );

    // Same four-tier ASN enrichment as the identify handler: edge headers → bundled
    // registry → Team Cymru. A placeholder ISP is replaced by the resolved operator.
    const edgeAsnNumber = Number.parseInt(edgeGeo.asn.replace(/^AS/i, ''), 10);
    const enrichedNetwork = await enrichNetwork(visitorIp, {
      asn: Number.isInteger(edgeAsnNumber) && edgeAsnNumber > 0 ? edgeAsnNumber : undefined,
      country: edgeGeo.countryCode || undefined,
    });
    const placeholderIspBefore =
      isMissingGeoValue(location.isp) ||
      /^autonomous system\b/i.test(location.isp) ||
      location.isp === 'Standard Network';
    const placeholderOrgBefore =
      isMissingGeoValue(location.org) || location.org === 'Standard Network';
    if (enrichedNetwork.source !== 'none') {
      location = {
        ...location,
        asn: normalizeAsnLabel(location.asn) || normalizeAsnLabel(enrichedNetwork.asn) || location.asn,
        isp:
          placeholderIspBefore && enrichedNetwork.asn_name
            ? enrichedNetwork.asn_name
            : location.isp,
        org:
          placeholderOrgBefore && enrichedNetwork.asn_name
            ? enrichedNetwork.asn_name
            : location.org,
        isVpnOrHosting: location.isVpnOrHosting || enrichedNetwork.datacenter_result,
      };
    }

    const knownAsnLabel =
      normalizeAsnLabel(location.asn) || normalizeAsnLabel(edgeGeo.asn) || '';
    const stillPlaceholder =
      isMissingGeoValue(location.isp) ||
      /^autonomous system\b/i.test(location.isp) ||
      location.isp === 'Standard Network';
    if (knownAsnLabel && stillPlaceholder) {
      const byAsn = await resolveAsnOrganization(knownAsnLabel);
      location = {
        ...location,
        asn: knownAsnLabel,
        isp: byAsn.asn_name || knownAsnLabel,
        org:
          isMissingGeoValue(location.org) || location.org === 'Standard Network'
            ? byAsn.asn_name || knownAsnLabel
            : location.org,
        isVpnOrHosting: location.isVpnOrHosting || byAsn.datacenter_result,
      };
    }

    const hasLocation =
      !isMissingGeoValue(location.city) || !isMissingGeoValue(location.country);
    const hasNetwork =
      !isMissingGeoValue(location.isp) &&
      !/^autonomous system\b/i.test(location.isp) &&
      location.isp !== 'Standard Network';
    const resolved = location.isIpVerified && hasLocation && hasNetwork;
    const hasCountry = Boolean(location.countryCode) || !isMissingGeoValue(location.country);

    res.json({
      location: {
        ...location,
        isTor: Boolean(location.isTor) || edgeGeo.isTorNetwork,
        isTorExit: Boolean(location.isTorExit) || edgeGeo.isTorNetwork,
        locationSource: location.locationSource ?? (edgeGeo.countryCode ? 'edge' : 'provider'),
        locationPrecision: !isMissingGeoValue(location.city)
          ? 'city'
          : !isMissingGeoValue(location.region)
          ? 'region'
          : hasCountry
          ? 'country'
          : 'unknown',
        isLocationVerified: hasCountry,
      },
      resolved,
      checkedAt: new Date().toISOString(),
    });
  } catch {
    res.status(500).json({ error: 'Geolocation lookup failed.' });
  }
});

app.use(express.json({ limit: '512kb' }));

app.get('/api/health', async (req, res) => {
  let visitorsCount: number | null = null;
  let visitsCount: number | null = null;
  try {
    visitorsCount = (
      db.prepare('SELECT COUNT(*) AS count FROM visitors').get() as { count: number }
    ).count;
    visitsCount = (
      db.prepare('SELECT COUNT(*) AS count FROM visits').get() as { count: number }
    ).count;
  } catch {
    // Health must answer even when the stateless edge has no Durable-Object database context.
  }
  const { regionCode, regionLabel } = detectServerRegion(req);

  // Diagnostics: `?torCheck=<ipv4>` reports whether the Tor Project exit list resolves this
  // address from the server's network, so the relay reputation path can be verified directly.
  const torCheckIp =
    typeof req.query.torCheck === 'string' ? normalizeIpCandidate(req.query.torCheck) : null;
  if (torCheckIp && (isIpv4Literal(torCheckIp) || expandIpv6Address(torCheckIp) !== null)) {
    const startedAtMs = Date.now();
    ensureTorIntelligenceSync();
    const verdict = await resolveTorExitVerdict(torCheckIp);
    const relay = lookupTorRelayMetadata(torCheckIp);
    res.json({
      status: 'ok',
      visitorsCount,
      visitsCount,
      regionCode,
      regionLabel,
      parser_version: PARSER_VERSION,
      build_sha: BUILD_SHA,
      worker_version: WORKER_VERSION,
      torCheck: {
        ip: torCheckIp,
        exitNode: verdict === 'exit',
        verdict,
        bulkListed: isTorBulkListed(torCheckIp),
        operatorPrefix: isTorOperatorPrefix(torCheckIp),
        embeddedIpv4: extractEmbeddedIpv4FromIpv6(torCheckIp),
        operator: describeTorRelay(torCheckIp),
        relayOperatorAsn: relay?.as ?? null,
        relayOperatorName: relay?.asName ?? null,
        consensusIpv4Exits: torIpv4ExitSet.size,
        consensusIpv6Exits: torIpv6ExitSet.size,
        consensusSyncedAtMs: torIntelligenceLastSyncMs || null,
        latencyMs: Date.now() - startedAtMs,
      },
    });
    return;
  }

  res.json({
    status: 'ok',
    visitorsCount,
    visitsCount,
    regionCode,
    regionLabel,
    parser_version: PARSER_VERSION,
    build_sha: BUILD_SHA,
    worker_version: WORKER_VERSION,
  });
});

/**
 * Vercel + Cloudflare edge geolocation. The heavy lifting lives in
 * `src/lib/geoFallbacks.ts` so the same normalisation is shared with the collector.
 */
function extractEdgeGeo(req: express.Request): EdgeGeoHeaders {
  return readEdgeGeoHeaders(req.headers as EdgeHeaderBag);
}

/**
 * All-plan Cloudflare request.cf transport fields are exposed by the Worker on the sealed
 * `x-intel-edge-geo` header. JA3 / JA4T and raw TCP-SYN OS fingerprints are deliberately
 * "Unavailable" without Cloudflare Bot Management — we never fabricate them.
 */
function readEdgeTransport(req: express.Request): {
  tlsVersion: string;
  tlsCipher: string;
  clientTcpRtt: number | null;
  httpProtocol: string;
  colo: string;
  ja3: 'Unavailable';
  ja4t: 'Unavailable';
  os_mismatch: 'Unavailable';
} {
  const unavailable = {
    tlsVersion: '',
    tlsCipher: '',
    clientTcpRtt: null as number | null,
    httpProtocol: '',
    colo: '',
  };
  try {
    const raw = req.headers['x-intel-edge-geo'];
    if (typeof raw === 'string' && raw) {
      const parsed = JSON.parse(decodeURIComponent(raw)) as Record<string, unknown>;
      unavailable.tlsVersion = typeof parsed.tlsVersion === 'string' ? parsed.tlsVersion : '';
      unavailable.tlsCipher = typeof parsed.tlsCipher === 'string' ? parsed.tlsCipher : '';
      unavailable.clientTcpRtt =
        typeof parsed.clientTcpRtt === 'number' && Number.isFinite(parsed.clientTcpRtt)
          ? parsed.clientTcpRtt
          : null;
      unavailable.httpProtocol = typeof parsed.httpProtocol === 'string' ? parsed.httpProtocol : '';
      unavailable.colo = typeof parsed.colo === 'string' ? parsed.colo : '';
    }
  } catch {
    // A malformed or absent edge header is not a security signal.
  }
  return { ...unavailable, ja3: 'Unavailable', ja4t: 'Unavailable', os_mismatch: 'Unavailable' };
}

/**
 * Timezone truth is owned by `src/lib/timezone.ts` (shared with the browser and the ledger).
 * The frozen alias table there resolves legacy IANA backward aliases (`Asia/Calcutta` →
 * `Asia/Kolkata`) so a spelling difference can never manufacture a VPN / timezone-relay signal.
 * `timezoneMismatchContext` is the single canonical verdict used by vpn_methods, the envelope,
 * the risk ledger and the UI flags. A mismatch is true only when BOTH sides resolve and their
 * canonical identities genuinely differ — Calcutta vs Kolkata is therefore ALWAYS false.
 */
if (!timezonesEquivalent('Asia/Calcutta', 'Asia/Kolkata')) {
  console.error(
    '[invariant] canonical timezone regression: Asia/Calcutta must be equivalent to Asia/Kolkata'
  );
}
/** Display-safe canonical id (empty string when the input carries no resolvable zone). */
function normalizeTimezone(tz?: string | null): string {
  return canonicalTimezone(tz) ?? '';
}

/**
 * Four-state GPU observation. A masked / unavailable renderer is an honest `unknown`, never a
 * physical-hardware claim and never hypervisor proof. This is a local defensive mirror of the
 * shared `resolveGpuTruth` helper (specInvariants); it is kept here so the API bundle stays
 * correct until that helper lands, and has identical semantics.
 */
export type GpuTruthState =
  | 'physical_hardware'
  | 'software_renderer'
  | 'virtual_gpu'
  | 'unknown';

const SOFTWARE_RENDERER_TRUTH_PATTERN =
  /swiftshader|llvmpipe|softpipe|software|masked|unavailable|basic render driver|microsoft basic render|mesa offscreen|software rasterizer|apple software renderer|virgl/i;
const HYPERVISOR_GPU_TRUTH_PATTERN =
  /virtualbox|\bvbox\b|vmware|svga3d|\bqemu\b|virtio|virgl|\bbochs\b|hyper-?v|microsoft remote display|parallels|citrix|\bxen\b/i;

export function resolveGpuTruth(
  vendor: string | null | undefined,
  renderer: string | null | undefined
): GpuTruthState {
  const text = `${typeof vendor === 'string' ? vendor : ''} ${
    typeof renderer === 'string' ? renderer : ''
  }`.toLowerCase();
  // Software markers win over hypervisor markers (virgl is both): software is a fact, a
  // hypervisor is an inference from the same string.
  if (SOFTWARE_RENDERER_TRUTH_PATTERN.test(text)) return 'software_renderer';
  if (HYPERVISOR_GPU_TRUTH_PATTERN.test(text)) return 'virtual_gpu';
  const cleanRenderer = typeof renderer === 'string' ? renderer.trim() : '';
  if (
    cleanRenderer.length > 3 &&
    !/^(standard|unknown|unavailable|masked|google inc\.?)\b/i.test(cleanRenderer)
  ) {
    return 'physical_hardware';
  }
  return 'unknown';
}

/**
 * Collector hardware-truth fields that intentionally live outside the legacy HardwareSignals
 * interface. They are echoed verbatim (bounded / typed) so a UA-CH architecture claim can never
 * overwrite the runtime-probed silicon ground truth in the dashboard or the Event JSON.
 */
type ExtendedHardwareSignals = HardwareSignals & {
  incognitoConfidence?: number;
  /** Original client OS claim, retained for telemetry only (never used for display). */
  claimedOs?: string;
  /** Human-readable evidence for the runtime OS authority (telemetry only). */
  osProof?: string[];
  /** Four-state GPU observation derived from the raw unmasked renderer. */
  gpuTruthState?: GpuTruthState;
};

function sanitizeHardwareSignals(
  raw: Partial<ExtendedHardwareSignals> | null | undefined,
  browserDevice: BrowserDeviceInfo
): ExtendedHardwareSignals {
  const safeStr = (val: unknown, fallback: string, maxLen = 140): string =>
    typeof val === 'string' && val.trim().length > 0 ? val.trim().slice(0, maxLen) : fallback;
  const safeNullableStr = (val: unknown, maxLen = 120): string | null =>
    typeof val === 'string' && val.trim().length > 0 ? val.trim().slice(0, maxLen) : null;
  const rawHardwareExtras = (raw ?? {}) as Record<string, unknown>;

  const rawHwId = safeStr(raw?.hardwareId, '', 40);
  const validHwId = /^hwid_[0-9a-f]{16,32}$/i.test(rawHwId)
    ? rawHwId.toLowerCase()
    : 'hwid_' +
      crypto
        .createHash('sha256')
        .update(
          `${browserDevice.os}|${browserDevice.screenResolution}|${browserDevice.pixelRatio}|${safeStr(raw?.gpuRenderer, 'gpu')}|${safeStr(raw?.canvasHash, 'canvas')}`
        )
        .digest('hex')
        .slice(0, 20);

  const cpuCores =
    typeof raw?.cpuCores === 'number' && Number.isFinite(raw.cpuCores) && raw.cpuCores > 0
      ? Math.min(256, Math.round(raw.cpuCores))
      : null;

  const deviceMemoryGb =
    typeof raw?.deviceMemoryGb === 'number' &&
    Number.isFinite(raw.deviceMemoryGb) &&
    raw.deviceMemoryGb > 0
      ? Number(raw.deviceMemoryGb)
      : null;

  const maxTouchPoints =
    typeof raw?.maxTouchPoints === 'number' &&
    Number.isFinite(raw.maxTouchPoints) &&
    raw.maxTouchPoints >= 0
      ? Math.min(64, Math.round(raw.maxTouchPoints))
      : 0;

  const colorDepth =
    typeof raw?.colorDepth === 'number' && Number.isFinite(raw.colorDepth) && raw.colorDepth > 0
      ? Math.min(64, Math.round(raw.colorDepth))
      : 24;

  const maxTextureSize =
    typeof raw?.maxTextureSize === 'number' &&
    Number.isFinite(raw.maxTextureSize) &&
    raw.maxTextureSize >= 0
      ? Math.round(raw.maxTextureSize)
      : 0;

  // Runtime evidence (WebGL backend + host/math probes) owns the OS label. A lone client
  // `hostOs` claim stays telemetry-only and never promotes a UA OS to "(verified)".
  const runtimeOs = inferRuntimeOsVerdict(
    {
      hostOs: safeStr(rawHardwareExtras.hostOs, '', 120),
      gpuRenderer: safeStr(raw?.gpuRenderer, '', 160),
      gpuVendor: safeStr(raw?.gpuVendor, '', 120),
      gpuArchFamily: safeStr(rawHardwareExtras.gpuArchFamily, '', 40),
      architectureSource: safeStr(rawHardwareExtras.architectureSource, '', 80),
      engine: safeStr(rawHardwareExtras.engine, '', 120),
      architecture: safeStr(raw?.architecture, '', 80),
    },
    browserDevice.os
  );

  // Prefer the raw, unmasked renderer over a masked / placeholder string. The collector reads
  // WEBGL_debug_renderer_info, but additive telemetry fields may also carry the unmasked value;
  // a generic "Standard WebGL Renderer" must never hide a real unmasked renderer.
  const webglBasics = rawHardwareExtras.webglBasics as Record<string, unknown> | undefined;
  const gpuPlaceholderPattern = /^(standard|unknown|unavailable|masked|n\/a)\b/i;
  const usableGpuText = (value: unknown): string => {
    const text = typeof value === 'string' ? value.trim() : '';
    return text.length > 3 && !gpuPlaceholderPattern.test(text) ? text : '';
  };
  const gpuRenderer =
    [
      rawHardwareExtras.gpuRendererUnmasked,
      rawHardwareExtras.unmaskedRenderer,
      rawHardwareExtras.rawGpuRenderer,
      webglBasics?.renderer_unmasked,
      raw?.gpuRenderer,
    ]
      .map(usableGpuText)
      .find(Boolean) || safeStr(raw?.gpuRenderer, 'Standard Hardware Renderer', 160);
  const gpuVendor =
    [
      rawHardwareExtras.gpuVendorUnmasked,
      rawHardwareExtras.unmaskedVendor,
      webglBasics?.vendor_unmasked,
      raw?.gpuVendor,
    ]
      .map(usableGpuText)
      .find(Boolean) || safeStr(raw?.gpuVendor, 'Standard WebGL Vendor', 120);
  const gpuTruthState = resolveGpuTruth(gpuVendor, gpuRenderer);

  // Honest hardware truth: a SwiftShader / llvmpipe / software (or masked / unavailable)
  // renderer cannot name a real GPU architecture, and a nan-sign-bit architecture probe is not
  // a hardware fact. Force the architecture-derived spoof flags off so a software-rendered
  // cloud container is never labelled "spoofed / emulated OS" on architecture alone.
  const softwareRendererTruth = gpuTruthState === 'software_renderer';
  const rawGpuArchFamily = safeStr(rawHardwareExtras.gpuArchFamily, '', 40);
  // A software renderer must never report a real silicon family (x86 / nvidia / arm).
  const gpuArchFamily = softwareRendererTruth
    ? /^(software|unknown)$/i.test(rawGpuArchFamily)
      ? rawGpuArchFamily.toLowerCase()
      : 'software'
    : rawGpuArchFamily;
  const archTruthSource = safeStr(rawHardwareExtras.architectureSource, '', 80).toLowerCase();
  const archTruthValue = safeStr(raw?.architecture, '', 80).trim().toLowerCase();
  const untrustedArchTruth =
    archTruthSource === 'nan-sign-bit' ||
    /^(unknown|software|nan)$/.test(archTruthValue) ||
    /^(unknown|software|nan)$/.test(gpuArchFamily.toLowerCase());

  return {
    hardwareId: validHwId,
    gpuVendor,
    gpuRenderer,
    gpuTruthState,
    maxTextureSize,
    canvasHash: safeStr(raw?.canvasHash, 'unavailable', 40),
    audioHash: safeStr(raw?.audioHash, 'unavailable', 40),
    cpuCores,
    deviceMemoryGb,
    colorDepth,
    maxTouchPoints,
    hdrSupported: Boolean(raw?.hdrSupported),
    colorGamut:
      raw?.colorGamut === 'Rec2020' || raw?.colorGamut === 'P3' || raw?.colorGamut === 'sRGB'
        ? raw.colorGamut
        : 'sRGB',
    architecture: safeStr(raw?.architecture, browserDevice.os, 80),
    // Silicon-grounded truth: runtime-probed architecture / host OS plus the UA claim and its
    // mismatch verdicts. These are pass-through only — never derived from the User-Agent here.
    architectureSource: safeStr(rawHardwareExtras.architectureSource, '', 80),
    claimedArchitecture: safeStr(rawHardwareExtras.claimedArchitecture, '', 80),
    hostOs: runtimeOs.authoritative && runtimeOs.family ? runtimeOs.family : safeStr(rawHardwareExtras.hostOs, '', 120),
    claimedOs: safeStr(rawHardwareExtras.hostOs, '', 120),
    osProof: runtimeOs.evidence,
    engine: safeStr(rawHardwareExtras.engine, '', 120),
    engineErrorLength:
      typeof rawHardwareExtras.engineErrorLength === 'number' &&
      Number.isFinite(rawHardwareExtras.engineErrorLength)
        ? Math.max(0, Math.min(512, Math.round(rawHardwareExtras.engineErrorLength)))
        : undefined,
    gpuArchFamily,
    canvasNoise: Boolean(rawHardwareExtras.canvasNoise),
    audioNoise: Boolean(rawHardwareExtras.audioNoise),
    canvasCoarseHash: safeNullableStr(rawHardwareExtras.canvasCoarseHash, 40),
    // Never raise an arch/OS spoof banner from a nan-derived or software "architecture".
    archUaMismatch: untrustedArchTruth ? false : Boolean(rawHardwareExtras.archUaMismatch),
    osUaMismatch: untrustedArchTruth ? false : runtimeOs.uaMismatch,
  };
}

/**
 * Incognito cross-mode context, resolved by the identify handler before any row is written:
 * a hardware-fingerprint recovery with no surviving cookie / localStorage state is proof of an
 * ephemeral (private) browsing context even when the client probe stays silent.
 */
interface IncognitoCrossModeContext {
  hadPersistentClientState?: boolean;
  existingHwidVisitor?: boolean;
  /** Any high-confidence client incognito spelling (resolved by the identify handler). */
  clientReportedIncognito?: boolean;
  /** The resolver's stable confidence label, so top-level-only claims stay consistent in the sanitizer. */
  incognitoConfidenceHigh?: boolean;
  /** Case B — an earlier visit by this same physical device (last 7 days) used a different visitor id. */
  crossSessionEphemeral?: boolean;
}

/**
 * Phase 1/2/4 request context, resolved by the identify handler before sanitization:
 * sealed-envelope verdicts, Tor / blocklist lookups and the resolved bot classification.
 * Everything is optional so older callers keep the previous behaviour.
 */
interface RequestIntegrityContext {
  headers?: RawHeaderBag;
  /** The signed / full User-Agent used for Phase 1 + Phase 3 identity checks. */
  requestUserAgent?: string;
  tamperedRequest?: boolean;
  replayDetected?: boolean;
  requestIntegrityReason?: string;
  requestNonce?: string;
  /** Real edge-observed RTT (ms) for the additive RTT-based light-distance estimate only. */
  clientTcpRttMs?: number | null;
  torExitNode?: boolean;
  /** True when the address belongs to the Tor network (exit *or* relay). */
  torRelay?: boolean;
  /** Resolved tri-state Tor verdict (drives the anonymity-network badge). */
  torVerdict?: TorExitVerdict;
  /** Relay operator label, e.g. `Church of Cyberology · AS215125`. */
  torOperator?: string | null;
  /** Client-side Tor Browser fingerprint (Gecko RFP + letterboxing). */
  clientTorBrowser?: boolean;
  /** Granular AI-agent attribution resolved by the AI attribution engine. */
  aiAgent?: AiAgentAttribution | null;
  /** Shared-registry definition behind the attributed agent (exact display name + category). */
  registryAgent?: LocalAgentDef | null;
  /** Canonical bot verdict resolved before sanitization; the single source of truth for isBot. */
  botVerdict?: string;
  /** Automation-targeted tampering escalation resolved from reasons + botSignals. */
  automationTargetedTampering?: boolean;
  /** Strong protocol-level CDP proof; weak Error-preview / getter artifacts never set this. */
  strongCdpProof?: boolean;
  /** Corroborated CDP bridge escalation (CDP + stealth artifact, or no human corroboration). */
  corroboratedCdpEscalation?: boolean;
  /** True when the Tor verdict came from the operator-name fallback, not a DNS answer. */
  torOperatorHint?: boolean;
  ipBlocklisted?: boolean;
  ipBlocklistReasons?: string[];
  botClassification?: BotClassification;
  /** Real async Web Bot Auth verification result (or page-attestation equivalent). */
  webBotAuth?: WbaVerification | null;
}

/**
 * Automation-targeted tampering is distinct from a generic "the browser looks modified"
 * anomaly. A reason / bot signal that names WebDriver, Playwright/Puppeteer, a Selenium CDC
 * property or a patched CDP getter is direct proof of an automation runtime being hidden, so
 * it escalates to `bad` / `stealth_automation` and permanently pins human_corroboration at 0.
 * A bare CDP Runtime leak (`cdp.runtime.enable`) is deliberately NOT in this set — DevTools,
 * Electron and IDE webviews emit it while a real person drives the session.
 */
const AUTOMATION_TAMPERING_REASON_PATTERN =
  /\b(webdriver[\w$-]*|playwright[\w$-]*|puppeteer[\w$-]*|selenium[\w$-]*|cdc_[a-z0-9_$]+|cdc\b|__webdriver[\w$]*|__playwright[\w$]*|__pwInitscripts[\w$]*|__puppeteer[\w$]*|getter[\s._-]*(?:cdp|devtools|tamper|wrapper)|(?:cdp|devtools)[\s._-]*getter)\b/i;

function detectAutomationTargetedTampering(
  reasons: unknown,
  botSignals: unknown
): { detected: boolean; reasons: string[] } {
  const collect = (value: unknown): string[] =>
    Array.isArray(value)
      ? value
          .filter(
            (item): item is string =>
              typeof item === 'string' &&
              item.trim().length > 0 &&
              AUTOMATION_TAMPERING_REASON_PATTERN.test(item)
          )
          .map((item) => item.trim().slice(0, 180))
          .slice(0, 8)
      : [];
  const matched = Array.from(new Set([...collect(reasons), ...collect(botSignals)]));
  return { detected: matched.length > 0, reasons: matched };
}

/**
 * STRONG CDP / automation-protocol proof — the only client evidence allowed to raise a CDP
 * bridge from the weight-0 developer-tools axis to an automation verdict.
 *
 * Deliberately excluded as WEAK, engine-dependent artifacts that genuine browsers (notably
 * Android Chrome / Jio / OnePlus) emit all the time:
 *   - an `Error.prototype.name` preview read / `Runtime.enable` serialization leak
 *   - a patched or non-native `navigator.webdriver` getter (privacy extensions do this)
 *   - a substring match such as "cdp" inside an inspector error preview
 *   - the free-text "webdriver getter tampering" corroboration string
 * A runtime reporting only those stays human. Real proof is a protocol binding injected into
 * the page (CDC / Playwright / Selenium / WebDriver globals), a confirmed cross-realm
 * automation leak, or a protocol-level reason id from the weighted evidence gate.
 */
const STRONG_CDP_PROOF_REASON_PATTERN =
  /^(?:navigator\.webdriver\b|cdc[._$]|\$cdc_|playwright[._]|puppeteer[._]|selenium[._]|webdriver[._]|cdp\.ua_override\.|bot\.playwright-binding)|\b(?:automation driver binding|CDP\/WebDriver binding exposed|automation globals|confirmed cross-realm automation identity leak)\b/i;

function hasStrongCdpProof(
  raw: Partial<SecuritySignals> | null | undefined,
  extras: Record<string, unknown> = {}
): boolean {
  // `navigator.webdriver === true` is the WebDriver handshake itself, not a getter preview.
  if (raw?.webdriver === true) return true;
  const reasons: unknown[] = [
    ...(Array.isArray(raw?.botSignals) ? raw.botSignals : []),
    ...(Array.isArray(raw?.tamperReasons) ? raw.tamperReasons : []),
    ...(Array.isArray(raw?.tamperingDetails?.reasons) ? raw.tamperingDetails.reasons : []),
    ...(Array.isArray((raw?.tamperingDetails as { hardAutomationEvidence?: unknown } | null)
      ?.hardAutomationEvidence)
      ? (raw?.tamperingDetails as { hardAutomationEvidence: unknown[] }).hardAutomationEvidence
      : []),
    ...(Array.isArray(extras.hardAutomationEvidence) ? extras.hardAutomationEvidence : []),
    ...(Array.isArray(extras.cdpBridgeEvidence) ? extras.cdpBridgeEvidence : []),
  ];
  return reasons.some(
    (reason) =>
      typeof reason === 'string' && STRONG_CDP_PROOF_REASON_PATTERN.test(reason.trim())
  );
}

/**
 * Client-reported post-interaction human corroboration is a float in [0, 1] carried in the
 * sealed request's raw signals. Accept it only when finite; NaN / Infinity / out-of-range
 * values collapse to 0 so a malformed value can never manufacture a trusted human verdict.
 */
function clampHumanCorroboration(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

interface CorroboratedCdpAssessment {
  escalate: boolean;
  botType: 'stealth_automation' | 'chromium_automation' | null;
  reasons: string[];
}

/**
 * Server-side corroborated CDP escalation.
 *
 * A bare CDP bridge (a `Runtime.enable` serialization leak, a debugger binding or an
 * `automation_protocol` inspector probe) is developer-tools evidence: Electron shells and IDE
 * webviews (VS Code, Cursor, OpenCode) expose it while a real person drives the session, so it
 * carries ZERO automation weight on its own. The bridge is promoted to an automation verdict
 * only when it is independently corroborated by a stealth / anti-detect / tampering artifact,
 * OR when there is no trusted post-interaction human-input evidence after dwell.
 *
 * Verified RFC 9421 agents are exempt (handled by the caller) and a genuinely docked DevTools
 * frontend with trusted interaction never escalates. STRONG protocol-level CDP proof is now
 * mandatory: Electron / IDE / docked hosts and ordinary mobile or desktop browsers stay at
 * weight 0 unless a real binding/protocol artifact is present. Weak Error.name previews and
 * webdriver-getter tampering strings alone can never escalate.
 */
function assessCorroboratedCdp(args: {
  cdpBridge: boolean;
  strongCdpProof: boolean;
  inspectorState: InspectorState;
  dockedWithHumanInteraction: boolean;
  stealthArtifact: boolean;
  trustedHumanCorroboration: number;
  hasTrustedInteractionEvidence: boolean;
  signedAgentExempt: boolean;
}): CorroboratedCdpAssessment {
  const reasons: string[] = [];
  if (
    !args.cdpBridge ||
    !args.strongCdpProof ||
    args.signedAgentExempt ||
    args.dockedWithHumanInteraction
  ) {
    return { escalate: false, botType: null, reasons };
  }
  if (args.stealthArtifact) {
    reasons.push('CDP automation bridge corroborated by stealth / tampering artifacts');
    return { escalate: true, botType: 'stealth_automation', reasons };
  }
  if (args.trustedHumanCorroboration < 0.5 && !args.hasTrustedInteractionEvidence) {
    reasons.push('CDP automation bridge without trusted post-interaction human corroboration');
    return { escalate: true, botType: 'chromium_automation', reasons };
  }
  return { escalate: false, botType: null, reasons };
}

/** A timezone / timezone-mismatch note is an orthogonal network axis, never tamper evidence. */
function isTimezoneMismatchReason(reason: string): boolean {
  return /\btime[\s_-]?zone\b/i.test(reason);
}

/** One authoritative inspector verdict shared by the escalation gate, envelope and top level. */
interface ResolvedInspectorState {
  inspector_state: InspectorState;
  cdp_attached: boolean;
  developer_tools: boolean;
  detail: string;
}

/**
 * Single source of truth for `cdp_attached`, `developer_tools` and `inspector_state`.
 *
 * `cdp_attached` requires STRONG protocol-level proof (a real CDP/WebDriver binding). A weak
 * `cdpRuntimeLeak` / Error-preview read is only developer-tools telemetry: it can set
 * `developer_tools` (any DevTools / IDE / docked attach) but NEVER `cdp_attached`, and its
 * human-readable detail must never say "CDP attached".
 */
function resolveInspectorState(signals: {
  strongCdpProof?: boolean;
  developerTools?: boolean;
  cdpRuntimeLeak?: boolean;
  automationEnvironment?: string;
  devtoolsActiveVerified?: boolean;
  viewportContractionNormalized?: boolean;
}): ResolvedInspectorState {
  const inspector_state = classifyInspectorState({
    cdpAttached: Boolean(signals.strongCdpProof),
    devtoolsActiveVerified: Boolean(signals.devtoolsActiveVerified),
    viewportContractionNormalized: Boolean(signals.viewportContractionNormalized),
  });
  const cdp_attached = inspector_state === 'automation_protocol_attached';
  // Any DevTools / IDE-webview / docked attach is developer-tools evidence — including a weak
  // runtime leak. The CDP protocol state carries developer_tools:false by contract (the binding
  // is reported on the cdp_attached axis instead).
  const developer_tools =
    !cdp_attached &&
    Boolean(
      signals.developerTools ||
        signals.cdpRuntimeLeak ||
        signals.automationEnvironment === 'electron' ||
        signals.automationEnvironment === 'ide_webview' ||
        signals.devtoolsActiveVerified ||
        signals.viewportContractionNormalized
    );
  const detail = cdp_attached
    ? 'CDP protocol attached; no docked DevTools UI'
    : inspector_state === 'devtools_active_verified'
    ? 'Docked DevTools frontend verified active'
    : inspector_state === 'devtools_docked_suspected'
    ? 'Docked DevTools frontend suspected'
    : developer_tools
    ? 'Developer tools / inspector probe observed (no CDP protocol proof)'
    : 'No inspector / DevTools attachment detected';
  return { inspector_state, cdp_attached, developer_tools, detail };
}

/**
 * Single source of truth for the public `isBot` flag: it is ALWAYS derived from the canonical
 * bot verdict, never from a raw client boolean or a stale per-tile subtype.
 */
export function isBotFromVerdict(botVerdict: string | null | undefined): boolean {
  return Boolean(botVerdict) && botVerdict !== 'not_detected';
}

/** Runtime parity assertion — every serialized isBot mirror must agree with botVerdict. */
export function assertBotVerdictParity(
  serialized: { isBot?: boolean; securitySignalsIsBot?: boolean; envelopeBot?: string },
  botVerdict: string | null | undefined
): boolean {
  const expected = isBotFromVerdict(botVerdict);
  const mirrors = [serialized.isBot, serialized.securitySignalsIsBot].filter(
    (value): value is boolean => typeof value === 'boolean'
  );
  const parity =
    mirrors.every((value) => value === expected) &&
    (!serialized.envelopeBot || serialized.envelopeBot === botVerdict);
  if (!parity) {
    console.error('[invariant] isBot / botVerdict parity violation', { serialized, botVerdict, expected });
  }
  return parity;
}

/**
 * A genuine Tor Browser / Firefox RFP runtime only earns an exemption from RFP-induced
 * anti-detect false positives while there is NO independent protocol-level proof of
 * automation. CDP leaks, stealth plugins, WebDriver bindings, canvas farbling and
 * tampered/replayed envelopes are engine- or protocol-level facts a privacy preference
 * cannot explain, so they always keep their full weight.
 */
function hasIndependentAutomationProof(
  raw: Partial<SecuritySignals> | null | undefined,
  requestContext?: {
    tamperedRequest?: boolean;
    replayDetected?: boolean;
    strongCdpProof?: boolean;
  } | null
): boolean {
  const rawExtras = (raw ?? {}) as Record<string, unknown>;
  const strongCdpProof = Boolean(
    requestContext?.strongCdpProof ?? hasStrongCdpProof(raw, rawExtras)
  );
  return Boolean(
    (strongCdpProof &&
      (raw?.stealthPluginDetected ||
        raw?.cdpDetected ||
        raw?.isBot ||
        rawExtras.automationTargetedTampering ||
        detectAutomationTargetedTampering(
          rawExtras.tamperingReasons ?? raw?.tamperingDetails?.reasons,
          raw?.botSignals
        ).detected)) ||
      raw?.webdriver ||
      strongCdpProof ||
      raw?.canvasFarblingDetected ||
      raw?.replayDetected ||
      raw?.tamperedRequest ||
      requestContext?.tamperedRequest ||
      requestContext?.replayDetected
  );
}

function isConfirmedTorRfpClient(
  raw: Partial<SecuritySignals> | null | undefined,
  requestContext?: {
    clientTorBrowser?: boolean;
    tamperedRequest?: boolean;
    replayDetected?: boolean;
    strongCdpProof?: boolean;
  } | null
): boolean {
  return (
    Boolean(requestContext?.clientTorBrowser ?? raw?.isTorBrowserClient) &&
    !hasIndependentAutomationProof(raw, requestContext)
  );
}

const RFP_DEVICE_WIDTH_REASON = /screen\.width disagrees with its own device-width media query/i;

function rfpExemptTamperingDetails(raw: Partial<SecuritySignals> | null | undefined) {
  const details = raw?.tamperingDetails ?? {
    anomaly_score: 0,
    anti_detect_browser: false,
    devtools_device_emulation: false,
    reasons: [],
  };
  return {
    ...details,
    anti_detect_browser: false,
    reasons: details.reasons.filter((reason) => !RFP_DEVICE_WIDTH_REASON.test(reason)),
    anomaly_score: Math.min(details.anomaly_score, 0.39),
  };
}

function sanitizeAndReinforceSecuritySignals(
  raw: Partial<SecuritySignals> | null | undefined,
  browserDevice: BrowserDeviceInfo,
  hardwareSignals: HardwareSignals,
  location: LocationInfo,
  ipTimezoneHint: string,
  recognitionSource: IntelVisitorResponse['recognitionSource'],
  baseClassification: IspNetworkClassification,
  velocity: { visitsLastHour: number; distinctIpsLastHour: number },
  incognitoContext: IncognitoCrossModeContext = {},
  requestContext: RequestIntegrityContext = {}
): SecuritySignals {
  const safeStrArray = (arr: unknown): string[] =>
    Array.isArray(arr)
      ? arr
          .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
          .map((s) => s.trim().slice(0, 180))
          .slice(0, 10)
      : [];

  // Confirmed Tor Browser / RFP client: suppress only RFP-induced anti-detect false
  // positives. Hard automation proof below vetoes the exemption entirely.
  const rfpExempt = isConfirmedTorRfpClient(raw, requestContext);
  const clientTorBrowser = Boolean(requestContext.clientTorBrowser ?? raw?.isTorBrowserClient);
  const tamperingResponse = rfpExempt ? false : Boolean(raw?.tampering);
  const tamperingDetailsResponse = rfpExempt ? rfpExemptTamperingDetails(raw) : raw?.tamperingDetails;

  // Bot / automation: client flags plus the server-side identity classification. Only STRONG
  // protocol-level CDP proof promotes a client's isBot / cdpDetected / stealth claims: a real
  // Android Chrome session reports Error.name previews and getter quirks that must stay human.
  const rawExtrasForProof = (raw ?? {}) as Record<string, unknown>;
  const strongCdpProof = Boolean(
    requestContext.strongCdpProof ?? hasStrongCdpProof(raw, rawExtrasForProof)
  );
  const webdriver = Boolean(raw?.webdriver);
  const cdpDetected = strongCdpProof && Boolean(raw?.cdpDetected);
  const verifiedIsBot = strongCdpProof && Boolean(raw?.isBot);
  const verifiedStealthPlugin = strongCdpProof && Boolean(raw?.stealthPluginDetected);
  const isHeadless = Boolean(raw?.isHeadless);
  const rawBotReason =
    typeof raw?.botReason === 'string' && raw.botReason.trim()
      ? raw.botReason.trim().slice(0, 200)
      : '';
  const botSignals = safeStrArray(raw?.botSignals);
  const clientAutomationDetected = Boolean(verifiedIsBot || webdriver || cdpDetected);

  // Automation-targeted tampering (webdriver / playwright / CDC / patched CDP getters) is hard
  // proof of a hidden automation runtime. It is read from the tampering reasons AND the bot
  // signals so a client that files the evidence under either bucket cannot avoid escalation.
  const automationTampering = detectAutomationTargetedTampering(
    [
      ...((raw as (Partial<SecuritySignals> & { tamperingReasons?: string[] }) | null | undefined)
        ?.tamperingReasons ?? []),
      ...(tamperingDetailsResponse?.reasons ?? []),
    ],
    botSignals
  );
  // Weak getter / Error-preview artifacts are telemetry only; they escalate only when genuine
  // CDP protocol proof exists. A clean mobile browser reporting only those stays human.
  const automationTargetedTampering = strongCdpProof && (
    Boolean(requestContext.automationTargetedTampering) || automationTampering.detected
  );

  // Hard automation artifacts — the exact same set classifyBotTraffic gates on. One source of
  // truth for the tile score, the composite, the echoed signals and the subtype escalation.
  const antiDetectBrowser = rfpExempt
    ? false
    : Boolean(raw?.tamperingDetails?.anti_detect_browser);
  const tamperingMlScore =
    typeof raw?.tamperingMlScore === 'number' && Number.isFinite(raw.tamperingMlScore)
      ? raw.tamperingMlScore
      : 0;
  const mlTampering = rfpExempt ? false : tamperingMlScore >= 0.5;
  // Developer-tools evidence is its own axis (Fingerprint Pro parity). A CDP Runtime leak
  // means DevTools, an Electron shell or an IDE webview is attached — not that the session
  // is automated. It is reported as `developer_tools` and never escalates the bot verdict.
  const developerToolsAttached = Boolean(
    raw?.developerTools ||
      raw?.cdpRuntimeLeak ||
      raw?.automationEnvironment === 'electron' ||
      raw?.automationEnvironment === 'ide_webview'
  );
  const stealthAutomation = Boolean(
    verifiedStealthPlugin ||
      antiDetectBrowser ||
      automationTargetedTampering ||
      requestContext.corroboratedCdpEscalation
  );
  // A bare CDP Runtime leak proves automation, but it is not active deception: stock Playwright
  // and Puppeteer always emit it. Only plugin patches, an anti-detect footprint, automation-
  // targeted tampering, a tampering model score, or a CDP bridge corroborated by a stealth
  // artifact / an absence of trusted human input justify the critical 9/10 tier.
  const activeDeception = Boolean(
    verifiedStealthPlugin ||
      antiDetectBrowser ||
      automationTargetedTampering ||
      requestContext.corroboratedCdpEscalation
  );
  const hardAutomationReasons: string[] = [];
  if (automationTargetedTampering) {
    hardAutomationReasons.push(
      `Automation-targeted tampering (${automationTampering.reasons.slice(0, 2).join('; ') || 'webdriver / playwright / CDC / CDP getter wrappers'})`
    );
  }
  if (strongCdpProof && raw?.cdpRuntimeLeak) {
    hardAutomationReasons.push('CDP Runtime.enable serialization leak');
  }
  if (verifiedStealthPlugin) {
    hardAutomationReasons.push('Stealth plugin artifacts (non-native getters / iframe leak)');
  }
  if (antiDetectBrowser) {
    hardAutomationReasons.push('Anti-detect browser footprint (tamperingDetails)');
  }
  if (mlTampering) {
    hardAutomationReasons.push(`Browser tampering ML score ${tamperingMlScore.toFixed(3)}`);
  }
  if (requestContext.corroboratedCdpEscalation) {
    hardAutomationReasons.push(
      'Corroborated CDP automation bridge (no trusted post-interaction human corroboration)'
    );
  }

  const rawBotClassification: BotClassification =
    requestContext.botClassification ??
    classifyBotTraffic(
      requestContext.headers,
      { org: location.org, isp: location.isp, asn: location.asn },
      {
        isBot: clientAutomationDetected,
        isHeadless,
        webdriver,
        cdpDetected,
        botSignals,
        cdpRuntimeLeak: Boolean(raw?.cdpRuntimeLeak),
        stealthPluginDetected: verifiedStealthPlugin,
        developerTools: developerToolsAttached,
        automationEnvironment: raw?.automationEnvironment,
        humanCorroboration: raw?.humanCorroboration,
        antiDetectBrowser,
        tamperingMlScore,
        automationTargetedTampering,
        automationTamperingReasons: automationTampering.reasons,
      }
    );
  // Defensive escalation: even if an older caller supplied a human / good-bot classification,
  // a hard automation artifact can never be rendered as "Verified Human".
  const botClassification: BotClassification =
    stealthAutomation && rawBotClassification.subtype !== 'bad_bot'
      ? {
          subtype: 'bad_bot',
          label: antiDetectBrowser ? 'Anti-Detect Browser' : 'Stealth / CDP Automation',
          provider: antiDetectBrowser
            ? 'Anti-Detect Browser'
            : 'Stealth Automation (Puppeteer/Playwright)',
          category: 'Automation',
          confidence: 0.94,
          reasons:
            hardAutomationReasons.length > 0
              ? hardAutomationReasons
              : ['Hard automation artifact reported by client'],
        }
      : rawBotClassification;
  const botSubtype: BotSubtype = botClassification.subtype;
  // The detail text must always agree with the verdict. A stale "Verified human runtime"
  // string from an older bundle must not sit next to a "You are a bot" tile.
  const botReason =
    (botSubtype === 'bad_bot' || botSubtype === 'ai_agent') &&
    (!rawBotReason || /verified human|native dom/i.test(rawBotReason))
      ? hardAutomationReasons[0] ||
        botClassification.reasons[0] ||
        'Automation runtime detected'
      : rawBotReason;
  const spoofedCrawler =
    botClassification.subtype === 'bad_bot' && botClassification.label === 'Spoofed Crawler';
  // The gated subtype is the single source of truth for the public `isBot` flag. Keeping
  // the raw client booleans in this union re-introduced false positives (a privacy
  // extension patching a Navigator getter, a stale headless hint) even when the verdict
  // gate had already decided the session was human.
  const isBot = requestContext.botVerdict
    ? isBotFromVerdict(requestContext.botVerdict)
    : botSubtype === 'bad_bot' || botSubtype === 'ai_agent';

  const browserTimezone =
    typeof raw?.browserTimezone === 'string' && raw.browserTimezone.trim()
      ? raw.browserTimezone.trim().slice(0, 80)
      : browserDevice.timezone || 'UTC';

  const ipTimezone =
    ipTimezoneHint ||
    (typeof raw?.ipTimezone === 'string' && raw.ipTimezone.trim() && raw.ipTimezone !== 'Unavailable'
      ? raw.ipTimezone.trim().slice(0, 80)
      : 'Unavailable');

  // ONE canonical timezone verdict, shared by vpn_methods.timezone_mismatch, the envelope's
  // network axis, the risk ledger and the UI flags. Legacy IANA aliases resolve to a single
  // identity (Asia/Calcutta vs Asia/Kolkata => mismatch:false); an unresolved side is absence
  // of evidence, never a mismatch. A raw client `timezoneMismatch` boolean is not authoritative.
  const timezoneVerdict = timezoneMismatchContext(browserTimezone, ipTimezone);
  const clientTzCanonical = timezoneVerdict.canonicalBrowser ?? normalizeTimezone(browserTimezone);
  const ipTzCanonical = timezoneVerdict.canonicalIp ?? '';
  const hasTzMismatch = timezoneVerdict.mismatch;
  const timezoneMismatch = hasTzMismatch;

  // Task 1/2 — the datacenter label now comes from the mirrored ISP classification instead
  // of the old bare-keyword regex (which mis-flagged e.g. Google Fiber AS16591 as cloud
  // because of the generic 'google' keyword).
  // Four-state GPU truth from one resolver: a software / masked / unavailable renderer is never
  // "Physical Hardware" and never hypervisor proof on its own.
  const gpuTruthState = resolveGpuTruth(hardwareSignals.gpuVendor, hardwareSignals.gpuRenderer);
  const isGpuMaskedOrUnavailable = gpuTruthState === 'unknown';
  const softwareRenderedGpu = gpuTruthState === 'software_renderer';
  const virtualGpuSignature = gpuTruthState === 'virtual_gpu';
  // "Physical Hardware" is only assertable with a real unmasked GPU string and no software marker.
  const hasRealUnmaskedGpu = gpuTruthState === 'physical_hardware';

  // Strict priority reconciliation: Tor anonymity > AI agent cloud > datacenter/VM > VPN >
  // mobile > residential > unknown. The base classifier is network-only; these verdicts are
  // first-party evidence that outranks ISP metadata.
  // A client payload may carry a legacy `vpnSuspected` derived purely from a timezone mismatch.
  // Never let that relabel a residential line to "VPN / Proxy Relay": require concrete network
  // evidence (hosting/VPN ASN or a verified Tor relay). Timezone stays an orthogonal axis.
  const concreteVpnNetworkEvidence =
    Boolean(requestContext.torExitNode || requestContext.torRelay) ||
    (!baseClassification.isConsumerBroadband &&
      Boolean(baseClassification.isDatacenterOrHosting || location.isVpnOrHosting));
  const classification = applyNetworkOverrides(baseClassification, {
    torExit: Boolean(requestContext.torExitNode || requestContext.torRelay),
    torOperatorHint: Boolean(requestContext.torOperatorHint),
    isTorBrowserClient: clientTorBrowser,
    aiAgentDetected: Boolean(requestContext.aiAgent?.detected),
    datacenterVm:
      Boolean(raw?.isVirtualMachine) &&
      (baseClassification.isDatacenterOrHosting || isGpuMaskedOrUnavailable),
    // A timezone mismatch is its own orthogonal axis, never a commercial VPN signal. The raw
    // client `vpnSuspected` is deliberately NOT used here — only concrete network evidence.
    vpnSuspected: concreteVpnNetworkEvidence,
  });

  const isCloudOrDatacenterNetwork =
    classification.isDatacenterOrHosting || Boolean(location.isVpnOrHosting);

  // Consumer broadband is never a datacenter / hosting network, even when the geo provider
  // (or a legacy cached flag) tagged the IP as hosting.
  const datacenterAsn = classification.isConsumerBroadband
    ? false
    : isCloudOrDatacenterNetwork;
  // Timezone difference is an orthogonal network-axis note, never a VPN / proxy method.
  const vpnReasons = safeStrArray(raw?.vpnReasons).filter((reason) => !/time[_ -]?zone/i.test(reason));
  if (
    datacenterAsn &&
    !vpnReasons.some((r) => r.toLowerCase().includes('datacenter') || r.toLowerCase().includes('asn'))
  ) {
    vpnReasons.push(
      `Network ASN / ISP (${location.isp}${location.asn !== 'Unknown' ? ` • ${location.asn}` : ''}) matches cloud/hosting or VPN infrastructure`
    );
  }
  if (
    datacenterAsn &&
    isGpuMaskedOrUnavailable &&
    !vpnReasons.some((r) => /Cloud \/ Masked GPU/i.test(r))
  ) {
    vpnReasons.push('Cloud / Masked GPU environment');
  }
  // Phase 2 verdicts are consumed by the network boolean below, so they are resolved first.
  const torExitNode = Boolean(requestContext.torExitNode);
  const torOperatorHint = Boolean(requestContext.torOperatorHint);

  // A confirmed Tor exit relay is a network-reputation verdict in its own right; it must reach
  // `vpnSuspected` even when the relay sits on a residential ASN. The canonical timezone verdict
  // was resolved once above and is reused verbatim by vpn_methods below.

  // A commercial VPN provider is not the same claim as a cloud/datacenter egress. Only a
  // provider-owned VPN brand/ASN match may set `public_vpn`; generic hosting operators such as
  // M247, Datacamp/CDNEXT, Tzulo, Cloudflare, AWS/GCP/Azure/Alibaba or Hetzner rent capacity to
  // VPN services but are not VPN providers themselves, so they stay a datacenter result.
  // Crucially this uses the BASE (pre-override) ISP classification: applyNetworkOverrides() can
  // promote a residential line with a timezone mismatch to `VPN / Proxy Relay`, and that must
  // never be reported as a commercial VPN.
  const networkHaystackForVpn = `${location.isp} ${location.org}`;
  const commercialVpnProvider =
    !baseClassification.isConsumerBroadband &&
    baseClassification.networkType === 'VPN / Proxy Relay' &&
    VPN_PROXY_PATTERN.test(networkHaystackForVpn) &&
    !HOSTING_EGRESS_PATTERN.test(networkHaystackForVpn);
  // Concrete tunnel evidence only. Verified proxy-chain headers (Via / Proxy-Authorization /
  // RFC 7239 Forwarded / a >=3-hop public XFF chain) are first-party relay proof — the XFF rule
  // also covers a genuine rotating-proxy chain. A hosting ASN and a timezone mismatch are NOT
  // tunnel evidence and never appear in this set.
  const verifiedProxyRelay = detectProxyHeaders(requestContext.headers, location.publicIp).detected;
  const concreteVpnEvidence =
    commercialVpnProvider ||
    Boolean(requestContext.torExitNode || requestContext.torRelay) ||
    verifiedProxyRelay;
  // Shadow-only canonical vpnMethods resolver. Its output is additive: the six legacy flags
  // above remain the single source for the VPN tile, vpnSuspected and the risk ledger. Only an
  // explicit verified IP-geolocation country may become origin_country; a timezone is never
  // turned into a country, and a legacy mismatch hint is diagnostic-only inside the resolver.
  const shadowVpnVerdict = resolveVpnMethods({
    browserTimezone,
    ipTimezone,
    canonicalMismatch: hasTzMismatch,
    ipCountry: location.countryCode,
    publicVpn: commercialVpnProvider,
    relay: Boolean(torExitNode),
    osMismatch: Boolean(raw?.isOsTampered),
    mlPrediction: Boolean(raw?.vpnSuspected) && concreteVpnEvidence,
  });
  // Real RTT only: an edge-observed clientTcpRtt (preferred) or a positive
  // navigator.connection.rtt sample. rtt === 0 means "unknown" in the Network Information
  // API and is never treated as a measurement.
  const rawSignalBagForRtt = (raw ?? {}) as Record<string, unknown>;
  const clientReportedRtt =
    typeof rawSignalBagForRtt.networkRtt === 'number' && Number.isFinite(rawSignalBagForRtt.networkRtt)
      ? rawSignalBagForRtt.networkRtt
      : null;
  const observedRttMs =
    typeof requestContext.clientTcpRttMs === 'number' &&
    Number.isFinite(requestContext.clientTcpRttMs) &&
    requestContext.clientTcpRttMs > 0
      ? requestContext.clientTcpRttMs
      : clientReportedRtt !== null && clientReportedRtt > 0
      ? clientReportedRtt
      : null;
  // km = (RTT_ms / 2) * 1000 * 0.206 / p with a path factor p ~= 1.5..2. This is an
  // APPROXIMATION ("RTT-based light-distance estimate"), NOT JA4L and not a fingerprint/ladder.
  // With no verified client<->server distance reference a contradiction can never be proven, so
  // we never assert a mismatch: emit an explicit non-claim only when a real RTT exists, and omit
  // the field entirely otherwise. No points are charged anywhere from this object.
  const latencyBasis =
    observedRttMs !== null
      ? {
          label: 'RTT-based light-distance estimate (approximation)',
          rtt_ms: Math.round(observedRttMs),
          estimated_distance_km_low: Math.round(((observedRttMs / 2) * 1000 * 0.206) / 2),
          estimated_distance_km_high: Math.round(((observedRttMs / 2) * 1000 * 0.206) / 1.5),
          note: 'Approximation from real RTT only; not JA4L; no mismatch asserted without a verified distance reference',
        }
      : null;
  const vpnMethods = {
    timezone_mismatch: hasTzMismatch,
    public_vpn: commercialVpnProvider,
    auxiliary_mobile: false,
    os_mismatch: Boolean(raw?.isOsTampered),
    relay: Boolean(torExitNode),
    // A client ML verdict is accepted ONLY when an independent, concrete relay signal
    // corroborates it (provider-owned VPN, Tor relay or verified proxy chain). Never ASN alone,
    // never timezone alone — both are orthogonal axes, not tunnels.
    ml_prediction: Boolean(raw?.vpnSuspected) && concreteVpnEvidence,
    // Additive shadow fields — never read by the tile score, composite, ledger or tier.
    origin_country: shadowVpnVerdict.origin_country,
    reasons: shadowVpnVerdict.reasons,
    ...(latencyBasis ? { latency_distance_mismatch: { mismatch: false, ...latencyBasis } } : {}),
  };
  // Runtime parity assertion: the vpn_methods mirror and the serialised security-signal flag
  // must agree with the single canonical timezone verdict (Calcutta vs Kolkata is always false).
  if (vpnMethods.timezone_mismatch !== timezoneMismatch) {
    console.error('[invariant] timezone mismatch parity violation', {
      vpnMethodsTimezoneMismatch: vpnMethods.timezone_mismatch,
      timezoneMismatch,
      browserTimezone,
      ipTimezone,
      clientTzCanonical,
      ipTzCanonical,
    });
  }
  // The umbrella VPN verdict counts only concrete VPN/anonymity methods. timezone_mismatch stays
  // an orthogonal axis in vpnMethods (and in the telemetry/network panel) and never promotes a
  // residential line to a commercial VPN on its own. A cloud/datacenter ASN is network ownership,
  // not a tunnel, so it is reported honestly by the network tile/ledger and never sets
  // `vpnSuspected`. The raw client `vpnSuspected` is neutralized above (network relabel) and here
  // (ML path), so it cannot resurrect a timezone-only or hosting-ASN verdict.
  const vpnSuspected =
    vpnMethods.public_vpn ||
    vpnMethods.relay ||
    vpnMethods.ml_prediction ||
    vpnMethods.os_mismatch;

  // A timezone / timezone-mismatch note is an orthogonal network axis. It must never be
  // reported as tampering or spoofing evidence, even when a legacy client files it here.
  const rawTamperReasons = safeStrArray(raw?.tamperReasons);
  const timezoneOnlyTamper =
    rawTamperReasons.length > 0 && rawTamperReasons.every((reason) => isTimezoneMismatchReason(reason));
  // A genuine client-reported OS/UA-vs-platform contradiction is tampering evidence, not just a
  // VM/environment note. It must set the boolean so the +3 "tampered OS" risk factor can never
  // be charged without a matching tamper verdict (points-without-boolean).
  const clientOsTampered = Boolean(raw?.isOsTampered);
  const tamperDetected = Boolean(
    (!timezoneOnlyTamper && raw?.tamperDetected) ||
      requestContext.tamperedRequest ||
      clientOsTampered
  );
  const tamperReasons = rawTamperReasons.filter((reason) => !isTimezoneMismatchReason(reason));
  if (
    requestContext.tamperedRequest &&
    requestContext.requestIntegrityReason &&
    !tamperReasons.includes(requestContext.requestIntegrityReason)
  ) {
    tamperReasons.unshift(requestContext.requestIntegrityReason);
    tamperReasons.splice(10);
  }

  // Accept ANY client incognito spelling when the collector's stable label is 'high'. A genuine
  // Chrome private window posts `isIncognito` / `incognito` / `privateMode` (top-level,
  // browserInfo, telemetry or securitySignals) without necessarily setting the legacy
  // `incognitoLikely` flag, so that single field is never required. A 'low' label / numeric < 0.9
  // is a hard veto: a new/cleared profile, a context change or a touch/geometry probe is never
  // incognito proof. The identify handler passes its gated verdict + label through the context so
  // top-level-only claims (whose confidence lives outside `securitySignals`) stay consistent too.
  const rawIncognito = raw as
    | (Partial<SecuritySignals> & { incognitoConfidence?: unknown })
    | null
    | undefined;
  const rawIncognitoConfidence: unknown = rawIncognito?.incognitoConfidence;
  const lowConfidenceVeto =
    rawIncognitoConfidence === 'low' ||
    (typeof rawIncognitoConfidence === 'number' && rawIncognitoConfidence < 0.9);
  const incognitoConfidenceHigh =
    !lowConfidenceVeto &&
    (incognitoContext.incognitoConfidenceHigh === true ||
      rawIncognitoConfidence === 'high' ||
      (typeof rawIncognitoConfidence === 'number' && rawIncognitoConfidence >= 0.9));
  // OR, never `??`: an explicit false on one spelling must not shadow a true on another.
  const clientIncognitoClaim = Boolean(
    incognitoContext.clientReportedIncognito ||
      rawIncognito?.isIncognito ||
      rawIncognito?.incognito ||
      rawIncognito?.privateMode ||
      rawIncognito?.incognitoLikely
  );
  const incognitoLikely = incognitoConfidenceHigh && clientIncognitoClaim;
  // Echo the same stable label the collector emits; 'low' never reads as incognito downstream.
  const incognitoConfidenceLabel: 'high' | 'low' = incognitoConfidenceHigh ? 'high' : 'low';
  const storageQuotaMb =
    typeof raw?.storageQuotaMb === 'number' &&
    Number.isFinite(raw.storageQuotaMb) &&
    raw.storageQuotaMb > 0
      ? Math.round(raw.storageQuotaMb)
      : null;

  // Task 3 — deep technical detection signals read off the raw collector payload with the
  // same forward-compat wrapping the original cloudOrMaskedGpu pass-through used, so
  // absent / unknown fields normalize to safe defaults instead of undefined. The deprecated
  // DevTools / ad-blocker / WebRTC / visit-velocity points are no longer scored: their fields
  // survive as inert values purely for response-shape backward compatibility.
  const webrtcCandidateIp =
    typeof raw?.webrtcCandidateIp === 'string' && raw.webrtcCandidateIp.trim()
      ? raw.webrtcCandidateIp.trim().slice(0, 64)
      : null;
  const webrtcDetail =
    typeof raw?.webrtcDetail === 'string' && raw.webrtcDetail.trim()
      ? raw.webrtcDetail.trim().slice(0, 200)
      : '';
  const privacyProtected = Boolean(raw?.privacyProtected);
  const privacyDetail =
    typeof raw?.privacyDetail === 'string' && raw.privacyDetail.trim()
      ? raw.privacyDetail.trim().slice(0, 200)
      : '';
  const canvasFarblingDetected = Boolean(raw?.canvasFarblingDetected);
  // Raw client claim only — re-verified against host-level proof in the VM tile before it is
  // allowed to reach `securitySignals.isVirtualMachine` or the envelope.
  const clientReportedVm = Boolean(raw?.isVirtualMachine);
  const isOsTampered = clientOsTampered;
  const vmReason =
    typeof raw?.vmReason === 'string' && raw.vmReason.trim()
      ? raw.vmReason.trim().slice(0, 200)
      : '';
  const rawIncognitoMethod =
    typeof raw?.incognitoMethod === 'string' && raw.incognitoMethod.trim()
      ? raw.incognitoMethod.trim().slice(0, 120)
      : '';
  const headroomGiB =
    typeof raw?.headroomGiB === 'number' && Number.isFinite(raw.headroomGiB)
      ? Number(raw.headroomGiB)
      : null;
  const idbDurabilityRatio =
    typeof raw?.idbDurabilityRatio === 'number' && Number.isFinite(raw.idbDurabilityRatio)
      ? Number(raw.idbDurabilityRatio)
      : null;
  const opfsFlushMs =
    typeof raw?.opfsFlushMs === 'number' && Number.isFinite(raw.opfsFlushMs)
      ? Number(raw.opfsFlushMs)
      : null;
  // Forward-compatibility pass-through for the masked GPU flag (kept as pure pass-through so
  // the per-visit history row mapping keeps reading securitySignals.cloudOrMaskedGpu).
  const cloudOrMaskedGpu = Boolean(
    (raw as (Partial<SecuritySignals> & { cloudOrMaskedGpu?: boolean }) | null | undefined)
      ?.cloudOrMaskedGpu
  );

  // Phase 3 — mobile emulator / simulator verdict. The client probe is authoritative when it
  // fires, but it is re-derived here from the signed payload so a client that omits or forges
  // `emulatorDetected` still gets the same verdict.
  const serverEmulator = classifyEmulatorFromSignals({
    userAgent:
      requestContext.requestUserAgent ||
      readRequestHeader(requestContext.headers, 'user-agent') ||
      '',
    os: browserDevice.os,
    platform: browserDevice.platform,
    maxTouchPoints: hardwareSignals.maxTouchPoints,
    gpuVendor: hardwareSignals.gpuVendor,
    gpuRenderer: hardwareSignals.gpuRenderer,
    screenResolution: browserDevice.screenResolution,
  });
  const clientEmulatorReported = Boolean(raw?.emulatorDetected);
  const emulatorDetected = clientEmulatorReported || serverEmulator.detected;
  const clientEmulatorReason =
    typeof raw?.emulatorReason === 'string' && raw.emulatorReason.trim()
      ? raw.emulatorReason.trim().slice(0, 200)
      : '';
  const emulatorReason = emulatorDetected
    ? serverEmulator.detected
      ? serverEmulator.reason
      : clientEmulatorReason
    : '';

  // Phase 2 / 4 — sealed-envelope and network reputation verdicts resolved by the handler.
  const tamperedRequest = Boolean(requestContext.tamperedRequest);
  const replayDetected = Boolean(requestContext.replayDetected);
  const requestIntegrityReason =
    typeof requestContext.requestIntegrityReason === 'string'
      ? requestContext.requestIntegrityReason.trim().slice(0, 240)
      : '';
  const requestNonce =
    typeof requestContext.requestNonce === 'string' ? requestContext.requestNonce.slice(0, 128) : '';
  const ipBlocklisted = Boolean(requestContext.ipBlocklisted);
  const ipBlocklistReasons = Array.isArray(requestContext.ipBlocklistReasons)
    ? requestContext.ipBlocklistReasons
        .filter((reason): reason is string => typeof reason === 'string' && reason.trim().length > 0)
        .map((reason) => reason.trim().slice(0, 180))
        .slice(0, 5)
    : [];

  // Persistence mode resolution order is fixed: hardware-fingerprint recovery wins, then a
  // private / restricted storage context, else a first-party cookie.
  let persistenceMode: SecuritySignals['persistenceMode'] = 'First-Party Cookie';
  if (recognitionSource === 'Hardware Fingerprint (Cookie-less / Incognito)') {
    persistenceMode = 'Hardware ID Recovered';
  } else if (incognitoLikely) {
    persistenceMode = 'Private / Restricted Storage';
  }

  // Incognito cross-reference: a device recognized purely through its hardware fingerprint
  // means no first-party cookie / storage token survived — treat as incognito or cleared.
  // Exhaustive: raw client flag, the hardware-fingerprint recognition path, or a persistence
  // mode that resolves to 'Hardware ID Recovered' all count as incognito / cleared storage.
  const incognitoOrCleared =
    Boolean(raw?.incognitoOrCleared) ||
    recognitionSource === 'Hardware Fingerprint (Cookie-less / Incognito)' ||
    persistenceMode === 'Hardware ID Recovered';

  // Final incognito verdict: the client's own storage probe, or the server-side cross-session
  // proof — an ephemeral context with no surviving cookie / localStorage / signed backup.
  // The Incognito tile is driven by the client's physical storage-commit probe. The
  // server-side "known hardware without cookies" correlation is deliberately not enough on
  // its own: a brand-new browser profile, cleared cookies or a cookie-blocking extension is
  // indistinguishable from a private window and must not be labelled Incognito.
  // Every downstream mirror (top-level isIncognito, securitySignals.*, envelope, smart signal and
  // history) derives from this single gated verdict so they can never disagree. The context flag
  // is already confidence-gated by the identify handler and is re-gated here via incognitoLikely.
  const clientReportedIncognito = incognitoLikely;
  const isIncognito = clientReportedIncognito;
  // Storage diagnostics are reduced to one of three human outcomes before serialization.
  const incognitoMethod = humanIncognitoMethod(
    rawIncognitoMethod,
    isIncognito,
    storageProbeInconclusive(rawIncognitoMethod)
  );

  const tierFor = (score: number): RiskLevel =>
    score >= 7 ? 'High' : score >= 3 ? 'Medium' : 'Low';
  const levelFor = (score: number): SmartSignalLevel =>
    score >= 7 ? 'high' : score >= 3 ? 'medium' : 'low';

  /* ---- 4-signal Smart Signals grid, every tile rated strictly out of 10 ---- */

  // Tile 1 — Incognito / Private Browsing (3). A lone private window is a benign anomaly.
  const incognitoScore = isIncognito ? 3 : 0;
  const incognitoSignal: SmartSignal = {
    id: 'incognito',
    title: 'Incognito / Private Browsing',
    status: isIncognito ? 'Incognito / Private Mode' : 'Standard Window',
    scoreOutOf10: incognitoScore,
    riskLabel: `${tierFor(incognitoScore)} Risk • ${incognitoScore}/10`,
    level: levelFor(incognitoScore),
    // Human-readable probe outcome only. Ratio numbers, "fail-open", IDB and other diagnostic
    // internals stay out of every user-visible surface.
    detail: isIncognito
      ? 'Ephemeral / private storage detected'
      : humanIncognitoMethod(incognitoMethod, false, storageProbeInconclusive(incognitoMethod)),
  };

  // Tile 2 — Bot & Automation Detection (10 spoofed impostor / 9 stealth automation /
  // 7 unverified automation / 2 verified AI agent / 0 verified search crawler).
  // A registry-named crawler is shown with its exact display name, provider and proof.
  const aiAgent = requestContext.aiAgent ?? null;
  const registryAgent = requestContext.registryAgent ?? null;
  const spoofedImpostor =
    aiAgent?.agentId === 'impostor-spoof' ||
    (botSubtype === 'bad_bot' && spoofedCrawler);
  const registryCategory = registryAgent?.category || '';
  const verifiedNamedAgent = Boolean(registryAgent && aiAgent?.verified);
  const verifiedGoodCrawler = verifiedNamedAgent && isGoodCrawlerCategory(registryCategory);
  const verifiedAiAgent = verifiedNamedAgent && !isGoodCrawlerCategory(registryCategory);
  // Calibrated scale: a spoofed impostor is 10, hard automation artifacts (stealth plugins,
  // CDP leak, anti-detect browser, ML score >= 0.5) are 9, an unverified automation or agent
  // claim is 7, a verified named AI agent is 2 and a verified search crawler is 0. Only 9-10
  // means confirmed active deception. The hard-automation check comes first so a stale
  // human / good-bot / agent classification can never suppress the escalation on the tile.
  const botScore = spoofedImpostor
    ? 10
    : activeDeception
    ? 9
    : botSubtype === 'bad_bot'
    ? 7
    : verifiedGoodCrawler
    ? 0
    : verifiedAiAgent
    ? 2
    : botSubtype === 'ai_agent'
    ? 7
    : botSubtype === 'good_bot'
    ? 2
    : 0;
  const tileRuntimeOs = inferRuntimeOsVerdict(
    {
      hostOs: (hardwareSignals as ExtendedHardwareSignals).hostOs,
      gpuRenderer: hardwareSignals.gpuRenderer,
      gpuVendor: hardwareSignals.gpuVendor,
      gpuArchFamily: (hardwareSignals as ExtendedHardwareSignals).gpuArchFamily,
      architectureSource: (hardwareSignals as ExtendedHardwareSignals).architectureSource,
      engine: (hardwareSignals as ExtendedHardwareSignals).engine,
      architecture: hardwareSignals.architecture,
    },
    browserDevice.os
  );
  const registryIdentity = spoofedImpostor
    ? 'spoofed'
    : aiAgent?.verified
    ? /signed/i.test(String(aiAgent.executionMode || ''))
      ? 'signed'
      : 'verified'
    : 'unknown';
  const automationLabel = String(botClassification.label || '');
  const headlessAutomation =
    /headless|chromium|puppeteer|playwright/i.test(automationLabel) ||
    /headless/i.test(hardAutomationReasons.join(' '));
  // The tile status is always an exact bot / agent type — never a vague confidence phrase.
  const rawBotStatus =
    // A named agent is ALWAYS shown by its exact registry name, including when its claim
    // failed verification — the identity badge (Spoofed / Unverified) carries that fact.
    registryAgent
      ? registryDisplay(registryAgent as unknown as AgentDef, registryIdentity).label
      : stealthAutomation || botSubtype === 'bad_bot'
      ? headlessAutomation
        ? 'Headless Browser Automation'
        : 'Stealth Automation'
      : aiAgent?.detected && aiAgent.agentName
    ? aiAgent.agentName
    : botSubtype === 'ai_agent'
    ? automationLabel || 'AI Agent'
    : botSubtype === 'good_bot'
    ? automationLabel || 'Search Crawler'
    : 'Verified Human';
  const botStatus = crispBotStatus(rawBotStatus, tileRuntimeOs);
  const aiAgentDetail =
    aiAgent?.detected && aiAgent.agentName
      ? `${aiAgent.agentName} — ${aiAgent.operator}${
          aiAgent.executionMode ? ` · ${aiAgent.executionMode}` : ''
        } · ${aiAgent.confidence}${aiAgent.verified ? ' (verified)' : ''}: ${
          aiAgent.evidence[0] || 'agent identity attributed from request headers'
        }`
      : '';
  const registryBotDetail =
    registryAgent && aiAgent?.detected
      ? `${registryAgent.displayName} — ${registryAgent.provider}${
          registryAgent.category ? ` · ${registryAgent.category}` : ''
        } · ${aiAgent.verified ? 'verified by first-party evidence' : 'unverified identity claim'}: ${
          aiAgent.evidence.find((line) =>
            /CIDR|FCrDNS|signature|SAIL|Web Bot Auth/i.test(line)
          ) ||
          aiAgent.evidence[0] ||
          'agent identity attributed from request headers'
        }`
      : '';
  const botDetail = scrubOsClaim(
    stealthAutomation
    ? `${hardAutomationReasons.join('; ') || 'Stealth / anti-detect automation runtime detected'} — hard automation artifact, never a verified human`
    : botSubtype === 'human' && !aiAgent?.detected
      ? developerToolsAttached
        ? `Verified human interactive session · ${
            // Only STRONG protocol proof may say "CDP attached". A weak runtime leak / Error
            // preview is developer-tools telemetry and must never claim a CDP attachment.
            requestContext.strongCdpProof
              ? 'CDP protocol attached; no docked DevTools UI'
              : 'developer tools / inspector probe attached (no CDP protocol proof)'
          }${
            raw?.automationEnvironment && raw.automationEnvironment !== 'none'
              ? ` (${raw.automationEnvironment})`
              : ''
          }`
        : 'Verified human interactive session'
      : registryBotDetail
      ? registryBotDetail
      : aiAgentDetail
      ? aiAgentDetail
      : botSubtype === 'ai_agent'
      ? `${botClassification.provider} ${botClassification.label} — ${
          botClassification.reasons[0] || KNOWN_AI_CRAWLER_REASON
        }`
      : botSubtype === 'good_bot'
      ? `${botClassification.provider} ${botClassification.label} verified against its official network — ${
          botClassification.reasons[1] || 'ASN / organisation match'
        }`
      : botReason ||
        botClassification.reasons[0] ||
        (spoofedCrawler
          ? 'Crawler user-agent claimed from a network that does not belong to the operator'
          : 'WebDriver / CDP automation runtime detected'),
    tileRuntimeOs
  );

  const botSignal: SmartSignal = {
    id: 'bot',
    title: 'Bot & Automation Detection',
    status: botStatus,
    scoreOutOf10: botScore,
    riskLabel: `${tierFor(botScore)} Risk • ${botScore}/10`,
    level: levelFor(botScore),
    detail: botDetail,
  };

  // Tile 3 — VPN / Proxy & Network Type (10 Tor / 9 blocklisted / 7 AI agent / 6 relay /
  // 4 datacenter + timezone mismatch / 3 datacenter / 2 timezone only / 0)
  const isDatacenterAsn = datacenterAsn;
  // A verified search crawler legitimately runs on its operator's own datacenter ASN. Scoring
  // that as a consumer-facing "VPN / datacenter proxy" is a false positive produced by two
  // engines disagreeing about the same network, so the tile drops to a low-risk crawler state.
  const verifiedCrawlerNetwork = botSubtype === 'good_bot' && isDatacenterAsn;
  const ispBrand = classification.brandName || location.isp || 'Standard Network';
  const asnSuffix = location.asn !== 'Unknown' ? ` • ${location.asn}` : '';
  const asnLabel =
    location.asn && location.asn !== 'Unknown'
      ? /^AS/i.test(location.asn)
        ? location.asn.toUpperCase()
        : `AS${location.asn}`
      : 'AS unknown';
  const asnOrOrg = `${asnLabel} · ${location.org !== 'Unknown' ? location.org : ispBrand}`;
  const torBrowserClient = clientTorBrowser;
  const torRelayNetwork = requestContext.torVerdict === 'relay' || requestContext.torRelay === true;
  const torAnonymity = torExitNode || torBrowserClient;
  const torOperatorLabel =
    requestContext.torOperator ?? describeTorRelay(location.publicIp) ?? null;
  // Calibrated network scale: anonymity infrastructure stays critical (9-10), a relay is 6, an
  // attributed AI agent is 7, and a bare cloud egress is 3 (4 with a timezone mismatch) so a
  // plain datacenter IP is never presented as a commercial VPN.
  // 10/10 is reserved for active deception (tampering, replay, spoofed impostor).
  // A genuine Tor exit + RFP client is an anonymity/network reputation result, capped at 9.
  // The tile's "VPN" language is reserved for the corrected concrete tunnel verdict. A bare
  // hosting ASN is reported as network ownership and a timezone mismatch as an orthogonal locale
  // axis — neither is a tunnel, even though both still carry a small network-reputation weight.
  const concreteTunnelVerdict = Boolean(
    vpnMethods.public_vpn || vpnMethods.relay || vpnMethods.ml_prediction
  );
  const vpnScore = torAnonymity
    ? 9
    : ipBlocklisted
    ? 9
    : verifiedCrawlerNetwork
    ? 2
    : torRelayNetwork
    ? 6
    : aiAgent?.detected
    ? 7
    : concreteTunnelVerdict
    ? 6
    : isDatacenterAsn && hasTzMismatch
    ? 4
    : isDatacenterAsn
    ? 3
    : hasTzMismatch
    ? 2
    : 0;
  const vpnStatus = torAnonymity
    ? torExitNode && torBrowserClient
      ? 'Tor Exit Node & Tor Browser'
      : torExitNode
      ? 'Tor Exit Node'
      : 'Tor Browser (Onion Routing / RFP)'
    : ipBlocklisted
    ? 'Blocklisted IP'
    : verifiedCrawlerNetwork
    ? 'Verified Crawler Network'
    : torRelayNetwork
    ? 'Tor Relay (Non-Exit)'
    : aiAgent?.detected
    ? 'AI Agent Cloud Network'
    : concreteTunnelVerdict
    ? 'VPN / Proxy Relay'
    : isDatacenterAsn
    ? 'Datacenter / Hosting Network'
    : hasTzMismatch
    ? 'Not detected'
    : 'Standard ISP';
  const vpnDetail = torAnonymity
    ? `${torExitNode ? 'Confirmed active Tor exit relay' : 'Tor Browser fingerprint (Gecko RFP + letterboxing)'} (${
        location.publicIp
      } · ${torOperatorLabel || asnOrOrg})${
        torOperatorHint ? ' — DNSEL unreachable, operator attribution used' : ''
      }${torExitNode && torBrowserClient ? ' · server exit IP and client RFP both matched' : ''}`
    : ipBlocklisted
    ? 'IP flagged on abuse / tamper blocklist'
    : verifiedCrawlerNetwork
    ? `${botClassification.provider} crawler operating from its own ${ispBrand}${asnSuffix} — crawler infrastructure, not a consumer proxy`
    : torRelayNetwork
    ? `Tor relay network (${torOperatorLabel || asnOrOrg}) — part of the Tor network but not an exit egress`
    : aiAgent?.detected
    ? `${aiAgent.agentName} (${aiAgent.operator}) — ${aiAgent.executionMode || 'AI agent'} traffic from ${ispBrand}${asnSuffix}`
    : concreteTunnelVerdict
    ? vpnMethods.public_vpn
      ? `Verified commercial VPN provider on ${ispBrand}${asnSuffix}`
      : vpnMethods.relay
      ? `Tor relay / anonymity infrastructure (${torOperatorLabel || asnOrOrg})`
      : `Verified proxy-chain / relay evidence on ${ispBrand}${asnSuffix}`
    : isDatacenterAsn && hasTzMismatch
    ? `Datacenter ASN (${ispBrand}${asnSuffix}) — network ownership observation; the timezone difference is reported on the network axis only`
    : isDatacenterAsn
    ? `Datacenter / hosting ASN detected on ${ispBrand}${asnSuffix}`
    : hasTzMismatch
    ? 'Not detected — no VPN, proxy or relay evidence. Timezone difference is a separate network observation.'
    : `${ispBrand} • ${classification.networkType} (${asnLabel}) verified against browser timezone ${browserTimezone}`;

  const vpnSignal: SmartSignal = {
    id: 'vpn',
    title: 'VPN / Proxy & Network Type',
    status: vpnStatus,
    scoreOutOf10: vpnScore,
    riskLabel: `${tierFor(vpnScore)} Risk • ${vpnScore}/10`,
    level: levelFor(vpnScore),
    detail: vpnDetail,
  };

  // Tile 4 — Virtual Machine, Emulator & OS Integrity (10 replayed or tampered payload /
  // 8 emulator / 6 genuine hypervisor host or spoofed environment / 0 physical hardware).
  // A cloud/datacenter ASN is NETWORK OWNERSHIP, not a hypervisor. A missing / masked GPU string
  // or SwiftShader software rendering is likewise not VM proof (f7d6900 / f851c63). The VM
  // verdict therefore requires at least one INDEPENDENT host-level proof: a hypervisor-specific
  // GPU signature (VirtualBox / VMware / QEMU / VirtIO / Hyper-V guest / Parallels / Xen), a
  // genuine emulator verdict, or host CPU / SMBIOS virtualization evidence reported by the
  // collector. Sealed-envelope tampering / replay is escalated below and never needs the network.
  // Use the same four-state resolver as the hardware sanitizer so the VM tile can never claim a
  // hypervisor from a software / masked renderer string.
  const hypervisorGpuProof = virtualGpuSignature;
  // The collector's "masked GPU on a datacenter ASN (cloud container)" verdict is a network
  // observation, never a hypervisor signature — it alone must never carry the VM tile.
  const cloudContainerVmReason = /cloud container|datacenter asn|masked webgl|software renderer/i.test(
    vmReason
  );
  const hostVirtualizationProof =
    hypervisorGpuProof ||
    (clientReportedVm && !cloudContainerVmReason && !isGpuMaskedOrUnavailable && !softwareRenderedGpu);
  // Emulators are reported as their own tier and never double-counted as a desktop hypervisor.
  const isVm = hostVirtualizationProof && !emulatorDetected;
  const vmReasonVerdict = isVm
    ? vmReason && !cloudContainerVmReason
      ? vmReason
      : hypervisorGpuProof
      ? 'Hypervisor-specific GPU signature detected in the WebGL vendor / renderer'
      : 'Host-level virtualization evidence detected'
    : '';
  const isTampered = isOsTampered;
  // Single source of truth: this exact `isVm` verdict is serialized to
  // securitySignals.isVirtualMachine and envelope.environment.virtual_machine_label. Every VM
  // tile field below is a strict rendering of it — no independent "Yes / Physical Hardware"
  // claim may diverge from the boolean in the JSON.
  const vmLike = isVm;
  // A genuine hypervisor host / spoofed environment is 6, an emulator 8, cryptographic tampering
  // 10. A software renderer is an honest environment observation (3), NEVER a confirmed VM and
  // NEVER "Physical Hardware". An UNKNOWN / masked / unavailable renderer is absence of evidence,
  // so it scores 0 — a bare cloud egress scores 0 on this tile too.
  const vmScore = tamperedRequest || replayDetected
    ? 10
    : emulatorDetected
    ? 8
    : vmLike
    ? 6
    : isTampered
    ? 6
    : softwareRenderedGpu
    ? 3
    : hasRealUnmaskedGpu
    ? 0
    : 0;
  let vmStatus =
    tamperedRequest || replayDetected
      ? 'Tampered / Replayed'
      : emulatorDetected
      ? 'Mobile Emulator'
      : vmLike
      ? 'Virtual Machine / VM'
      : isTampered
      ? 'Spoofed Environment'
      : softwareRenderedGpu
      ? 'Software-Rendered Graphics (SwiftShader)'
      : hasRealUnmaskedGpu
      ? 'Physical Hardware'
      : 'GPU Masked / Unavailable';
  const vmDetail =
    tamperedRequest || replayDetected
      ? requestIntegrityReason || 'Sealed request envelope failed verification'
      : emulatorDetected
      ? emulatorReason || vmReason || 'Mobile emulator / simulator runtime detected'
      : vmLike
      ? vmReasonVerdict
      : isTampered
      ? vmReason || tamperReasons[0] || 'Operating-system / User-Agent tampering detected'
      : softwareRenderedGpu
      ? 'Software-rendered graphics — virtualization likely, not proven; virtual machine not confirmed'
      : hasRealUnmaskedGpu
      ? 'Unmasked physical GPU & consistent OS platform verified'
      : 'GPU vendor / renderer unavailable — physical hardware cannot be verified';

  // Consistency invariant: when the JSON verdict says `virtual_machine: false`, the tile must
  // never read "Virtual Machine / VM" or "Physical Hardware" as a confirmed claim. A software /
  // unavailable renderer is reported honestly, never as an unmasked physical GPU.
  if (
    (!isVm && vmStatus === 'Virtual Machine / VM') ||
    (vmStatus === 'Physical Hardware' && gpuTruthState !== 'physical_hardware')
  ) {
    vmStatus = softwareRenderedGpu
      ? 'Software-Rendered Graphics (SwiftShader)'
      : 'GPU Masked / Unavailable';
  }

  const vmSignal: SmartSignal = {
    id: 'vm',
    title: 'Virtual Machine & OS Integrity',
    status: vmStatus,
    scoreOutOf10: vmScore,
    riskLabel: `${tierFor(vmScore)} Risk • ${vmScore}/10`,
    level: levelFor(vmScore),
    detail: vmDetail,
  };

  const smartSignals: SmartSignals = {
    incognito: incognitoSignal,
    bot: botSignal,
    vpn: vpnSignal,
    vm: vmSignal,
  };

  // Composite — bot/headless 5|4, network 3|2, VM/tampered-OS 3, incognito 2,
  // sealed-envelope tamper or replay 2 (strictly ≤ 10).
  const integrityViolation = Boolean(tamperedRequest || replayDetected);
  // Network weight: a confirmed exit relay (5) outranks generic hosting (3); a verified
  // crawler's own network costs nothing; a plain timezone relay is worth 2.
  const networkPoints = torExitNode
    ? 5
    : verifiedCrawlerNetwork
    ? 0
    : isDatacenterAsn
    ? 3
    : hasTzMismatch
    ? 2
    : 0;
  // Calibrated 0-10 risk tiers. Each tier is a floor, so no single weak signal can saturate the
  // headline: 0-2 authentic browser, 3-4 one benign anomaly (private window, cloud egress with a
  // timezone mismatch), 5-6 cloud VM / software renderer, 7-8 automation or an attributed agent,
  // 9-10 confirmed active deception (stealth plugins, tampering, replay, Tor exit, impostor).
  let calibratedScore = 0;
  if (isIncognito) calibratedScore = Math.max(calibratedScore, 3);
  if (raw?.developerTools) calibratedScore = Math.max(calibratedScore, 3);
  if (hasTzMismatch) calibratedScore = Math.max(calibratedScore, 2);
  if (raw?.proxyDetected) calibratedScore = Math.max(calibratedScore, 4);
  if (isDatacenterAsn) {
    calibratedScore = Math.max(calibratedScore, hasTzMismatch ? 4 : 3);
  }
  if (vmScore > 0) calibratedScore = Math.max(calibratedScore, vmScore);
  if (isHeadless && !isBot) calibratedScore = Math.max(calibratedScore, 6);
  if (isBot) calibratedScore = Math.max(calibratedScore, activeDeception ? 9 : 7);
  if (ipBlocklisted) calibratedScore = Math.max(calibratedScore, 8);
  if (tamperDetected || tamperingResponse) calibratedScore = Math.max(calibratedScore, 9);
  if (integrityViolation) calibratedScore = Math.max(calibratedScore, 9);
  if (torExitNode) calibratedScore = Math.max(calibratedScore, 9);
  if (activeDeception) calibratedScore = Math.max(calibratedScore, 9);
  if (spoofedImpostor) calibratedScore = 10;
  const weightedCompositeScore = Math.min(10, calibratedScore);
  // Monotonic card-floor invariant: the headline score can never be lower than the highest
  // individual card. Two elevated cards add +1 synergy, three or more add +2. This is why a
  // 4/10 Incognito card next to a 5/10 VPN card can never be summarised as "4/10".
  const cardScores = [incognitoScore, botScore, vpnScore, vmScore];
  const maxCardScore = Math.max(0, ...cardScores);
  const elevatedCardCount = cardScores.filter((score) => score >= 4).length;
  const synergyBonus = elevatedCardCount >= 3 ? 2 : elevatedCardCount === 2 ? 1 : 0;
  // 9-10 are reserved for active deception (stealth / anti-detect, tampering, replay, a
  // confirmed Tor exit or a spoofed impostor). The card-floor synergy alone must never promote
  // a plain headless / cloud-VM / timezone-relay session to a critical headline — cap the
  // non-deception path at 8 so those combinations cannot saturate at 10.
  const criticalDeception = Boolean(
    activeDeception ||
      spoofedImpostor ||
      tamperDetected ||
      tamperingResponse ||
      integrityViolation ||
      torExitNode
  );
  const cardFloorScore = Math.max(weightedCompositeScore, maxCardScore + synergyBonus);
  const suspectScore = criticalDeception
    ? Math.min(10, cardFloorScore)
    : Math.min(8, cardFloorScore);
  const riskLevel: SecuritySignals['riskLevel'] = tierFor(suspectScore);
  const riskBadgeText = `${riskLevel} Risk • ${suspectScore}/10`;

  // Risk factors mirror the composite weights that actually fired. The deprecated DevTools /
  // ad-blocker / WebRTC / visit-velocity points are intentionally absent.
  const riskFactors: string[] = [];
  if (isBot) {
    riskFactors.push(
      `Automated browser / bot runtime detected (+5): ${
        botReason ||
        botClassification.reasons[0] ||
        botSignals[0] ||
        'WebDriver / CDP automation signatures'
      }`
    );
  } else if (isHeadless) {
    riskFactors.push(
      `Headless browser environment (+4): ${botReason || 'no physical display attached'}`
    );
  }
  if (torAnonymity) {
    riskFactors.push(
      `${torExitNode ? 'Confirmed Tor exit relay' : 'Tor Browser fingerprint'} (+9 card): ${
        torExitNode
          ? torOperatorHint
            ? 'exit-operator attribution'
            : 'Tor Project DNSEL / consensus exit list'
          : 'Gecko RFP + letterboxing detected on the client'
      } ${location.publicIp}`
    );
  } else if (torRelayNetwork) {
    riskFactors.push(
      `Tor relay network (+6 card): ${torOperatorLabel || asnOrOrg} — relay, not an exit egress`
    );
  } else if (verifiedCrawlerNetwork) {
    // Verified crawler infrastructure is intentional and unweighted.
  } else if (isDatacenterAsn) {
    riskFactors.push(
      `Datacenter / hosting network detected (+3): ${vpnReasons[0] || ispBrand}`
    );
  } else if (hasTzMismatch) {
    riskFactors.push(
      `Browser timezone differs from IP geolocation (+2): ${clientTzCanonical} vs ${ipTzCanonical}`
    );
  }
  if (aiAgent?.detected) {
    riskFactors.push(
      `${aiAgent.agentId === 'impostor-spoof' ? 'Spoofed AI bot impostor (10/10)' : 'AI agent attributed (8/10)'}: ${
        aiAgent.agentName
      } · ${aiAgent.operator} · ${aiAgent.confidence}`
    );
  }
  if (vmScore > 0) {
    // When the VM tile was maxed by the sealed-envelope verdict, the integrity factor below
    // already reports the same evidence — never list one finding twice.
    const duplicatesIntegrityReason =
      integrityViolation && vmSignal.detail === (requestIntegrityReason || 'tampered or replayed payload');
    if (!duplicatesIntegrityReason) {
      // "tampered OS" is only asserted when the tampering boolean actually fired (the client
      // reported a genuine UA/platform contradiction). A bare VM / software-rendered cloud
      // environment is a lower-confidence environment observation, never an OS-deception claim.
      riskFactors.push(
        isTampered
          ? `Tampered OS (+3): ${vmSignal.detail}`
          : `Virtual machine / software-rendered environment (+3): ${vmSignal.detail}`
      );
    }
  }
  if (isIncognito) {
    riskFactors.push(`Incognito / ephemeral storage (+2): ${incognitoSignal.detail}`);
  }
  if (integrityViolation) {
    riskFactors.push(
      `Sealed request envelope failed verification (+2): ${
        requestIntegrityReason || 'tampered or replayed payload'
      }`
    );
  }

  const proxyAssessment = detectProxyHeaders(requestContext.headers, location.publicIp);

  // Shadow-only second opinion from proxyTruth. It is NEVER read by suspectScore, the graded
  // ledger, the verdict tier, isBot or the legacy proxyDetected flag. A verified good bot is an
  // explicit exemption for the data_center label; a bare hosting/cloud ASN stays reason-only and
  // cannot manufacture a residential claim.
  const proxyAsnMatch = String(location.asn || '').match(/\d+/);
  const proxyDetails: ProxyDetails = resolveProxyDetails({
    datacenterResult: datacenterAsn,
    verifiedGoodBot: verifiedGoodCrawler || botSubtype === 'good_bot',
    asnType: datacenterAsn ? 'datacenter' : undefined,
    asn: proxyAsnMatch ? Number.parseInt(proxyAsnMatch[0], 10) : null,
    vpn: concreteVpnEvidence || proxyAssessment.detected,
    knownProxyPrefix: false,
  });

  const securitySignalsCore: SecuritySignals = {
    isBot,
    botSignals,
    vpnSuspected,
    timezoneMismatch,
    datacenterAsn,
    vpnReasons,
    browserTimezone,
    ipTimezone,
    tamperDetected,
    tamperReasons,
    incognitoLikely,
    storageQuotaMb,
    persistenceMode,
    suspectScore,
    riskLevel,
    riskFactors,
  };

  // Forward-compatibility pass-through: newly introduced collector fields are never stripped
  // during sanitization. Values are spread from a typed object so this stays strict-clean
  // even when the shared SecuritySignals interface lags behind the collector.
  return {
    ...securitySignalsCore,
    ...({
      // The UI's separate "Virtual Machine" row ORs this flag with isVirtualMachine. Keep it
      // consistent with the honest host-level VM verdict so it can never print "Yes" while
      // isVirtualMachine (and envelope.environment.virtual_machine_label) says false. Software
      // rendering is reported by the renderer itself, not by this VM-consistency flag.
      cloudOrMaskedGpu: isVm ? cloudOrMaskedGpu : false,
      // Task 1 — ISP brand & network classification from the server-resolved location
      brandName: classification.brandName,
      networkType: classification.networkType,
      isConsumerBroadband: classification.isConsumerBroadband,
      isDatacenterOrHosting: classification.isDatacenterOrHosting,
      // Task 3 — deep technical detection signals
      webrtcLeak: false,
      webrtcCandidateIp,
      webrtcDetail,
      privacyProtected,
      privacyDetail,
      // Deprecated scoring inputs kept inert for response-shape backward compatibility.
      adBlockerDetected: false,
      devToolsOpen: false,
      canvasFarblingDetected,
      // Corrected verdicts only: a cloud ASN / masked GPU never reaches these host-level fields.
      isVirtualMachine: isVm,
      vmReason: vmReasonVerdict,
      isOsTampered,
      incognitoOrCleared,
      // Client-side private-browsing probe. The collector emits a stable 'high' | 'low' label;
      // preserve it verbatim so 'low' can never be mistaken for an incognito verdict. The cast
      // bridges the legacy numeric type declaration while the shared type migrates to the label.
      incognitoConfidence: incognitoConfidenceLabel as unknown as number,
      incognitoDetail: humanIncognitoMethod(
        typeof raw?.incognitoDetail === 'string' ? raw.incognitoDetail : rawIncognitoMethod,
        isIncognito,
        storageProbeInconclusive(rawIncognitoMethod)
      ),
      // Final 4-signal upgrade — private browsing, bot, network, VM integrity
      isIncognito,
      incognito: isIncognito,
      privateMode: isIncognito,
      incognitoMethod,
      headroomGiB,
      // Ratio / flush diagnostics stay internal: only the human storage outcome is serialized.
      idbDurabilityRatio: null,
      opfsFlushMs: null,
      isHeadless,
      botReason,
      webdriver,
      cdpDetected,
      // Protocol-level and stealth-plugin evidence reaches the payload, the grid and the JSON.
      cdpRuntimeLeak: Boolean(raw?.cdpRuntimeLeak),
      stealthPluginDetected: verifiedStealthPlugin,
      automationTargetedTampering,
      automationTamperingReasons: automationTampering.reasons,
      // The single source of truth for `vpn_methods`: the UI derives its count from this object.
      vpnMethods,
      smartSignals,
      riskBadgeText,
      // Phase 1 — bot / AI-agent subtype classification
      botSubtype,
      botProvider: botClassification.provider,
      botCategory: botClassification.category,
      botIdentityConfidence: botClassification.confidence,
      // Phase 2 — Tor exit relay + local abuse blocklist
      torExitNode,
      isTorBrowserClient: clientTorBrowser,
      torVerdict: requestContext.torVerdict ?? (torExitNode ? 'exit' : 'unknown'),
      torOperator:
        requestContext.torOperator ??
        describeTorRelay(location.publicIp) ??
        (torExitNode ? relayOperatorLabel(location) : null),
      aiAgent: requestContext.aiAgent ?? null,
      ipBlocklisted,
      ipBlocklistReasons,
      // Phase 5 — explicit proxy relay markers (Via / Forwarded / Proxy-Authorization chains)
      proxyDetected: proxyAssessment.detected,
      proxyReasons: proxyAssessment.reasons,
      // Additive proxy truth second opinion (never a verdict input).
      proxy_details: proxyDetails,
      // Phase 3 — mobile emulator / simulator verdict
      emulatorDetected,
      emulatorReason,
      // Phase 5 — browser tampering / docked DevTools (client-probed, echoed for the grid)
      tampering: tamperingResponse,
      tamperingConfidence: (raw?.tamperingConfidence || 'high') as
        | 'low'
        | 'medium'
        | 'high',
      tamperingMlScore: rfpExempt
        ? 0.0024
        : typeof raw?.tamperingMlScore === 'number'
        ? raw.tamperingMlScore
        : 0.0024,
      tamperingDetails: tamperingDetailsResponse,
      developerTools: developerToolsAttached,
      automationEnvironment: raw?.automationEnvironment || 'none',
      humanCorroboration:
        typeof raw?.humanCorroboration === 'number' && Number.isFinite(raw.humanCorroboration)
          ? Math.max(0, Math.min(1, raw.humanCorroboration))
          : 0,
      privacySettings: Boolean(raw?.privacySettings || clientTorBrowser),
      // Phase 4 — sealed request envelope verdicts
      tamperedRequest,
      replayDetected,
      requestIntegrityReason,
      requestNonce,
      // Task 3 — visit velocity / IP rotation (display only, never scored)
      distinctIpsLastHour: velocity.distinctIpsLastHour,
      visitsLastHour: velocity.visitsLastHour,
    } as Partial<SecuritySignals> & { cloudOrMaskedGpu?: boolean; proxy_details?: ProxyDetails }),
  };
}

/**
 * Merges the server-parsed `Sec-CH-UA*` headers with the optional client payload.
 * Header values are browser-generated and therefore win; the client payload only
 * fills gaps (mainly high-entropy `model`, `architecture` and `bitness` values that
 * desktop headers never carry).
 */
function mergeRequestClientHints(
  headers: ParsedClientHints | null | undefined,
  body: ClientHintsInput | null | undefined
): ClientHintsInput {
  const h = headers ?? null;
  const b = body && typeof body === 'object' ? body : null;
  const firstText = (...values: Array<string | undefined | null>): string => {
    for (const value of values) {
      if (typeof value === 'string' && value.trim()) return value.trim();
    }
    return '';
  };
  const firstList = (
    a: Array<{ brand: string; version: string }> | undefined | null,
    bb: Array<{ brand: string; version: string }> | string | undefined | null
  ): Array<{ brand: string; version: string }> | string | undefined => {
    if (Array.isArray(a) && a.length > 0) return a;
    if (Array.isArray(bb) && bb.length > 0) return bb;
    if (typeof bb === 'string' && bb.trim()) return bb;
    return undefined;
  };

  return {
    brands: firstList(h?.brands, b?.brands),
    fullVersionList: firstList(h?.fullVersionList, b?.fullVersionList),
    platform: firstText(h?.platform, b?.platform),
    platformVersion: firstText(h?.platformVersion, b?.platformVersion),
    architecture: firstText(h?.architecture, b?.architecture, b?.arch),
    bitness: firstText(h?.bitness, b?.bitness),
    model: firstText(h?.model, b?.model),
    mobile: b?.mobile ?? h?.mobile,
    formFactors: Array.isArray(b?.formFactors) ? b.formFactors : undefined,
    uaFullVersion: b?.uaFullVersion,
    wow64: typeof b?.wow64 === 'boolean' ? b.wow64 : undefined,
  };
}

app.post('/api/visitor/identify', identifyRateLimit, async (req, res) => {
  try {
    // Start the hourly bulk Tor exit-list refresh immediately so it overlaps the geolocation
    // work below. It is deliberately not awaited: the per-IP DNSEL query is authoritative and
    // fast, and a page load must never wait on a list download.
    void refreshTorBulkList();
    const requestBody = (req.body || {}) as {
      pageLoadId?: string;
      storedVisitorId?: string | null;
      storedVisitorToken?: string | null;
      clientSessionId?: string | null;
      clientHistoryBackup?: SignedHistoryBackup | null;
      browserDevice?: Partial<BrowserDeviceInfo>;
      hardwareSignals?: Partial<ExtendedHardwareSignals> | null;
      securitySignals?: Partial<SecuritySignals> | null;
      /** Tri-layer identity bundle from the client signal orchestrator (new clients). */
      identityProfile?: Record<string, unknown> | null;
      hardwareFingerprint?: string | null;
      browserFingerprint?: string | null;
      sessionId?: string | null;
      storageHealed?: boolean;
      /** Phase 4 — sealed request envelope (timestamp / nonce / signature + JS payload identity). */
      securityEnvelope?: Partial<SecurityEnvelope> | null;
      /**
       * High-entropy UA-CH values resolved from `navigator.userAgentData`
       * (`fullVersionList`, `platformVersion`, `architecture`, `bitness`, `model`).
       * They complement the `Sec-CH-UA*` request headers, which remain authoritative.
       */
      clientHints?: ClientHintsInput | null;
      clientGeoHint?: {
        ip?: string;
        city?: string;
        region?: string;
        country?: string;
        countryCode?: string;
        latitude?: number | null;
        longitude?: number | null;
        isp?: string;
        org?: string;
        asn?: string;
        timezone?: string;
        isVpnOrHosting?: boolean;
      } | null;
      /** Alternate / legacy incognito spellings a client may post at the top level. */
      incognito?: boolean;
      isIncognito?: boolean;
      privateMode?: boolean;
      incognitoMethod?: string;
      /** Stable high/low probe label (new clients); a low label is never incognito. */
      incognitoConfidence?: 'high' | 'low' | number | null;
      idbDurabilityRatio?: number | null;
      opfsFlushMs?: number | null;
      browserInfo?: { incognito?: boolean; isIncognito?: boolean } | null;
      telemetry?: { incognito?: boolean; isIncognito?: boolean } | null;
      /** Additive incognito probe diagnostics (flag-gated via `diagnostics.enabled`). */
      diagnostics?: IncognitoDiagnostics | null;
    };

    const {
      pageLoadId,
      storedVisitorId,
      storedVisitorToken,
      clientSessionId,
      clientHistoryBackup,
      browserDevice: rawBrowserDevice,
      hardwareSignals: rawHardwareSignals,
      securitySignals: rawSecuritySignals,
      clientGeoHint,
    } = requestBody;

    const safePageLoadId =
      typeof pageLoadId === 'string' && pageLoadId.trim().length > 0
        ? pageLoadId.trim().slice(0, 80)
        : 'pl_' + crypto.randomBytes(8).toString('hex');

    const browserDevice = sanitizeBrowserDevice(rawBrowserDevice);
    const hardwareSignals = sanitizeHardwareSignals(rawHardwareSignals, browserDevice);
    const hardwareId = hardwareSignals.hardwareId;

    // Authoritative browser / OS identity. The request's own `Sec-CH-UA*` headers are
    // generated by the browser, so they outrank the client payload; missing hints fall
    // back to the high-entropy values the client resolved from `navigator.userAgentData`
    // and finally to the User-Agent string. `os` is always the family and the version
    // always lands in `os_version` — never the inverse.
    const uaIdentity = normalizeUserAgent({
      userAgent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : '',
      platform: typeof rawBrowserDevice?.platform === 'string' ? rawBrowserDevice.platform : '',
      maxTouchPoints: hardwareSignals.maxTouchPoints,
      clientHints: mergeRequestClientHints(
        (req as express.Request & { intelClientHints?: ParsedClientHints }).intelClientHints,
        requestBody.clientHints
      ),
    });
    if (uaIdentity.os !== 'Unknown' && /^unknown|^$/i.test(browserDevice.os || '')) {
      browserDevice.os = uaIdentity.os;
    }
    if (uaIdentity.browserName !== 'Unknown' && /^unknown|^$/i.test(browserDevice.browser || '')) {
      browserDevice.browser = uaIdentity.browserName;
    }

    let { ip: extractedIp, isPublic } = extractVisitorIp(req);

    if (!isPublic && clientGeoHint && typeof clientGeoHint.ip === 'string') {
      const normalizedHintIp = normalizeIpCandidate(clientGeoHint.ip);
      if (normalizedHintIp && isPublicRoutableIp(normalizedHintIp)) {
        extractedIp = normalizedHintIp;
        isPublic = true;
      }
    }

    // Phase 2 — the authoritative Tor DNSEL query is started here so its network round trip
    // overlaps the geolocation lookups below instead of being serialized after them. A cold
    // cache costs a DNS query; a warm one resolves from the 10-minute per-IP cache.
    const torLookupPromise: Promise<TorExitVerdict> = resolveTorExitVerdict(extractedIp).catch(
      () => 'unknown' as TorExitVerdict
    );

    // Edge headers (Vercel / Cloudflare) are merged field by field onto whatever the
    // provider cascade returned. A rate-limited or cold-start provider can no longer blank
    // the location: city / region / country / lat / lon / timezone survive from the edge.
    const edgeGeo = extractEdgeGeo(req);
    let location = mergeLocationWithEdge(
      await resolveLocationWithTorFallback(extractedIp, isPublic, { edge: edgeGeo }),
      edgeGeo
    );

    if (
      isPublic &&
      clientGeoHint &&
      normalizeIpCandidate(clientGeoHint.ip)?.toLowerCase() === extractedIp.toLowerCase()
    ) {
      const hintNet = normalizeIspAndOrg(
        clientGeoHint.isp,
        clientGeoHint.org,
        clientGeoHint.asn,
        Boolean(clientGeoHint.isVpnOrHosting)
      );
      const hintLat =
        typeof clientGeoHint.latitude === 'number' && Number.isFinite(clientGeoHint.latitude)
          ? clientGeoHint.latitude
          : edgeGeo.latitude;
      const hintLon =
        typeof clientGeoHint.longitude === 'number' && Number.isFinite(clientGeoHint.longitude)
          ? clientGeoHint.longitude
          : edgeGeo.longitude;
      const hintCity = typeof clientGeoHint.city === 'string' ? clientGeoHint.city.trim() : '';
      const hintRegion =
        typeof clientGeoHint.region === 'string' ? clientGeoHint.region.trim() : '';
      const hintCountry =
        typeof clientGeoHint.country === 'string' ? clientGeoHint.country.trim() : '';
      const hintCountryCode =
        typeof clientGeoHint.countryCode === 'string'
          ? clientGeoHint.countryCode.trim()
          : '';
      // `Autonomous System ASxxxxx` is a placeholder, not a resolved ISP: a trusted client
      // hint is allowed to replace it.
      const ispIsPlaceholder =
        isMissingGeoValue(location.isp) || /^autonomous system\b/i.test(location.isp);

      location = {
        ...location,
        city: isMissingGeoValue(location.city)
          ? hintCity || edgeGeo.city || 'Unknown'
          : location.city,
        region: isMissingGeoValue(location.region)
          ? hintRegion || edgeGeo.region || 'Unknown'
          : location.region,
        country: isMissingGeoValue(location.country)
          ? countryNameFromCode(hintCountryCode) || hintCountry || edgeGeo.country || 'Unknown'
          : location.country,
        countryCode:
          location.countryCode ||
          hintCountryCode.toUpperCase() ||
          edgeGeo.countryCode,
        latitude: location.latitude !== null ? location.latitude : hintLat,
        longitude: location.longitude !== null ? location.longitude : hintLon,
        isp: ispIsPlaceholder ? hintNet.isp : location.isp,
        org: isMissingGeoValue(location.org) ? hintNet.org : location.org,
        asn: normalizeAsnLabel(location.asn) || hintNet.asn || edgeGeo.asn,
        isVpnOrHosting: location.isVpnOrHosting || hintNet.isVpnOrHosting,
        isIpVerified: true,
        isLocationVerified:
          location.isLocationVerified ||
          Boolean(hintCity || hintCountry || hintLat !== null),
      };
    }

    // Zero-cost 4-tier ASN enrichment (edge headers → bundled registry → Team Cymru over
    // DNS TXT / DNS-over-HTTPS). A placeholder ISP ("Standard Network" /
    // "Autonomous System AS…") is replaced by the resolved operator name. When a numeric
    // ASN is known but every name lookup fails, the network is labelled `AS<number>`
    // rather than "Standard Network"; a real ISP name is never overwritten.
    const edgeAsnNumber = Number.parseInt(edgeGeo.asn.replace(/^AS/i, ''), 10);
    const enrichedNetwork = await enrichNetwork(extractedIp, {
      asn: Number.isInteger(edgeAsnNumber) && edgeAsnNumber > 0 ? edgeAsnNumber : undefined,
      country: edgeGeo.countryCode || undefined,
    });
    const placeholderIspBefore =
      isMissingGeoValue(location.isp) ||
      /^autonomous system\b/i.test(location.isp) ||
      location.isp === 'Standard Network';
    const placeholderOrgBefore =
      isMissingGeoValue(location.org) || location.org === 'Standard Network';
    if (enrichedNetwork.source !== 'none') {
      const resolvedAsn = normalizeAsnLabel(enrichedNetwork.asn);
      location = {
        ...location,
        asn: normalizeAsnLabel(location.asn) || resolvedAsn || location.asn,
        isp:
          placeholderIspBefore && enrichedNetwork.asn_name
            ? enrichedNetwork.asn_name
            : location.isp,
        org:
          placeholderOrgBefore && enrichedNetwork.asn_name
            ? enrichedNetwork.asn_name
            : location.org,
        isVpnOrHosting: location.isVpnOrHosting || enrichedNetwork.datacenter_result,
      };
    }

    // Numeric ASN known, organisation still unknown: resolve the name only, then degrade
    // to `AS<number>`. The Tor / bot engines read `location.asn`, so the label stays exact.
    const knownAsnLabel =
      normalizeAsnLabel(location.asn) || normalizeAsnLabel(edgeGeo.asn) || '';
    const stillPlaceholder =
      isMissingGeoValue(location.isp) ||
      /^autonomous system\b/i.test(location.isp) ||
      location.isp === 'Standard Network';
    if (knownAsnLabel && stillPlaceholder) {
      const byAsn = await resolveAsnOrganization(knownAsnLabel);
      location = {
        ...location,
        asn: knownAsnLabel,
        isp: byAsn.asn_name || knownAsnLabel,
        org:
          isMissingGeoValue(location.org) || location.org === 'Standard Network'
            ? byAsn.asn_name || knownAsnLabel
            : location.org,
        isVpnOrHosting: location.isVpnOrHosting || byAsn.datacenter_result,
      };
    }

    // Geo parity — thread the edge's real (never fabricated) fields through LocationInfo so the
    // Event JSON and the envelope can stop inventing accuracy_radius / subdivisions. Everything
    // is additive and sourced from the Worker-sealed edge headers or the ASN enrichment result.
    const continent = parseContinentValue(edgeGeo.continent);
    const edgeGeoParity: EdgeEnrichedLocation = {
      ...location,
      continent: continent.name || undefined,
      continentCode: continent.code || undefined,
      postalCode: edgeGeo.postalCode || undefined,
      subdivisionIso: edgeGeo.regionCode || undefined,
      accuracyRadiusKm:
        typeof edgeGeo.accuracyRadius === 'number' && Number.isFinite(edgeGeo.accuracyRadius)
          ? edgeGeo.accuracyRadius
          : null,
      asnNetwork: edgeGeo.asnNetwork || enrichedNetwork.asn_network || undefined,
    };
    location = edgeGeoParity;

    // Task 1 — the classification is derived from the SERVER-RESOLVED location only (the
    // clientGeoHint ISP / org / ASN was merged into this location above when trusted), so it
    // is the authoritative source; the client hint is never classified separately.
    const classification = classifyIspNetwork(location.isp, location.org, location.asn);

    const cookieVid = req.cookies?.intel_http_vid as string | undefined;
    const cookieToken = req.cookies?.intel_http_token as string | undefined;

    let existingVisitor: VisitorRow | undefined;
    let recognitionSource: IntelVisitorResponse['recognitionSource'] = 'New First-Party ID';
    // True only when this request recovered an ALREADY EXISTING row purely by hardware
    // fingerprint — i.e. no cookie / localStorage identity survived.
    let existingHwidVisitor = false;
    // A storage-less hardware hit that failed the corroboration gate must still be reported
    // honestly as a possible hardware match, never as a verified returning device.
    let rejectedHardwareOnlyMatch = false;

    const cookieVerified = Boolean(cookieVid && verifyVisitorToken(cookieVid, cookieToken));
    const storageVerified = Boolean(
      storedVisitorId && verifyVisitorToken(storedVisitorId, storedVisitorToken)
    );

    const verifiedVid = cookieVerified
      ? cookieVid!
      : storageVerified
      ? storedVisitorId!
      : null;
    const verifiedToken = cookieVerified
      ? cookieToken!
      : storageVerified
      ? storedVisitorToken!
      : null;

    if (verifiedVid && verifiedToken) {
      recognitionSource = cookieVerified ? 'First-Party Cookie' : 'First-Party LocalStorage';
      try {
        existingVisitor = db
          .prepare('SELECT * FROM visitors WHERE visitor_id = ?')
          .get(verifiedVid) as VisitorRow | undefined;
      } catch {
        // Unreadable store (blocked daily quota): keep the verified identity from the client.
        existingVisitor = undefined;
      }

      // Serverless cold-start rehydration: if HMAC token is valid, restore visitor & signed history backup into db
      const validHistoryBackup =
        clientHistoryBackup &&
        verifySignedHistoryBackup(verifiedVid, clientHistoryBackup)
          ? clientHistoryBackup
          : null;

      if (!existingVisitor) {
        const nowIso = new Date().toISOString();
        const restoredFirstUtc = validHistoryBackup?.firstVisitUtc || nowIso;
        const latestBackupVisit = validHistoryBackup?.visits?.[0];
        const restoredLastUtc = latestBackupVisit?.visitedAtUtc || nowIso;
        const restoredSessionId =
          clientSessionId || latestBackupVisit?.sessionId || generateSessionId();

        try {
          db.prepare(
            `INSERT INTO visitors (
              visitor_id, hmac_token, hardware_id, created_at_utc, updated_at_utc, active_session_id, last_activity_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).run(
            verifiedVid,
            verifiedToken,
            hardwareId,
            restoredFirstUtc,
            restoredLastUtc,
            restoredSessionId,
            restoredLastUtc
          );

          existingVisitor = db
            .prepare('SELECT * FROM visitors WHERE visitor_id = ?')
            .get(verifiedVid) as VisitorRow | undefined;
        } catch {
          // quota / transient DB failure: response still succeeds
        }
      }

      if (validHistoryBackup && validHistoryBackup.visits.length > 0) {
        const orderedAsc = [...validHistoryBackup.visits].reverse();
        for (const histVisit of orderedAsc) {
          // Legacy backups may omit newer columns. better-sqlite3 rejects `undefined`
          // bindings, which used to surface as a 500 on the in-page Analyze / Record Visit
          // button, so every field is coerced to a SQLite-safe value.
          try {
            const histVisitId =
              typeof histVisit.visitId === 'string' && histVisit.visitId.trim()
                ? histVisit.visitId.trim()
                : generateVisitId();
            const histVisitedAt =
              typeof histVisit.visitedAtUtc === 'string' && histVisit.visitedAtUtc.trim()
                ? histVisit.visitedAtUtc
                : new Date().toISOString();
            db.prepare(
              `INSERT OR IGNORE INTO visits (
                visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
                public_ip, city, region, country, latitude, longitude, isp, org, asn,
                browser, os, device_type, screen_resolution, language, timezone,
                suspect_score, risk_level, score10, bot_name, recognition_source
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            ).run(
              histVisitId,
              verifiedVid,
              typeof histVisit.sessionId === 'string' && histVisit.sessionId
                ? histVisit.sessionId
                : clientSessionId || generateSessionId(),
              `rehydrated_${histVisitId}`,
              histVisitedAt,
              histVisit.publicIp || 'Unavailable',
              histVisit.city || 'Unknown',
              histVisit.region || 'Unknown',
              histVisit.country || 'Unknown',
              typeof histVisit.latitude === 'number' ? histVisit.latitude : null,
              typeof histVisit.longitude === 'number' ? histVisit.longitude : null,
              histVisit.isp || 'Unknown',
              histVisit.org || 'Unknown',
              histVisit.asn || 'Unknown',
              histVisit.browser || 'Unknown',
              histVisit.os || 'Unknown',
              histVisit.deviceType || 'Unknown',
              histVisit.screenResolution || 'Unavailable',
              histVisit.language || 'Unavailable',
              histVisit.timezone || 'Unavailable',
              typeof histVisit.suspectScore === 'number' ? histVisit.suspectScore : null,
              histVisit.riskLevel || null,
              typeof histVisit.score10 === 'number'
                ? histVisit.score10
                : typeof histVisit.suspectScore === 'number'
                ? histVisit.suspectScore
                : null,
              histVisit.botName || null,
              histVisit.recognitionSource || null
            );
          } catch {
            // quota / transient DB failure: response still succeeds
          }
        }
      }
    } else if (hardwareId) {
      // Cookie-less / Incognito recovery: look up visitor by deterministic Hardware ID (hwid_...)
      let hwMatchedVisitor: VisitorRow | undefined;
      try {
        hwMatchedVisitor = db
          .prepare('SELECT * FROM visitors WHERE hardware_id = ?')
          .get(hardwareId) as VisitorRow | undefined;
      } catch {
        // Unreadable store (blocked daily quota): treat as an unknown device.
        hwMatchedVisitor = undefined;
      }

      if (hwMatchedVisitor) {
        // A storage-less hardware hit inherits another visitor's id only when independent axes
        // agree. Software-rendered cloud containers clone hardware hashes across unrelated
        // visitors, so they are never allowed to adopt a foreign canonical id here.
        const softwareRenderer = /swiftshader|llvmpipe|softpipe|software|masked|unavailable/i.test(
          String(hardwareSignals.gpuRenderer || '') + ' ' + String(hardwareSignals.gpuVendor || '')
        );
        const homogeneousContainer =
          softwareRenderer &&
          (classification.isDatacenterOrHosting || Boolean(rawSecuritySignals?.isHeadless));
        const corroborated =
          !homogeneousContainer &&
          hardwareOnlyMatchCorroborated(
            db,
            hwMatchedVisitor.visitor_id,
            browserFamilyKey(browserDevice.browser),
            osFamilyKey(browserDevice.os),
            location.asn
          );
        if (corroborated) {
          existingVisitor = hwMatchedVisitor;
          existingHwidVisitor = true;
          recognitionSource = 'Hardware Fingerprint (Cookie-less / Incognito)';
        } else {
          rejectedHardwareOnlyMatch = true;
        }
      }
    }

    const nowUtc = new Date().toISOString();
    const nowMs = Date.now();

    let visitorId: string;
    let visitorToken: string;
    let currentSessionId: string;
    let currentVisitId = '';
    let isReturning = false;

    if (existingVisitor || verifiedVid) {
      visitorId = existingVisitor ? existingVisitor.visitor_id : verifiedVid!;
      visitorToken = existingVisitor ? existingVisitor.hmac_token : verifiedToken!;
      isReturning = true;

      const lastActivityMs = existingVisitor
        ? new Date(existingVisitor.last_activity_utc).getTime()
        : NaN;
      const isExpiredByInactivity =
        Number.isNaN(lastActivityMs) || nowMs - lastActivityMs > SESSION_EXPIRATION_MS;
      const isSameClientSession =
        Boolean(clientSessionId) &&
        Boolean(existingVisitor) &&
        clientSessionId === existingVisitor!.active_session_id;

      let existingPageLoadVisit:
        | { visit_id: string; session_id: string; visited_at_utc: string }
        | undefined;
      try {
        existingPageLoadVisit = db
          .prepare('SELECT visit_id, session_id, visited_at_utc FROM visits WHERE visitor_id = ? AND page_load_id = ?')
          .get(visitorId, safePageLoadId) as typeof existingPageLoadVisit;
      } catch {
        // Unreadable store (blocked daily quota): treat every load as a new visit.
        existingPageLoadVisit = undefined;
      }

      if (existingPageLoadVisit) {
        currentSessionId = existingPageLoadVisit.session_id;
        currentVisitId = existingPageLoadVisit.visit_id;
      } else {
        if (isExpiredByInactivity || !isSameClientSession) {
          currentSessionId = generateSessionId();
        } else {
          currentSessionId = existingVisitor!.active_session_id;
        }

        // When the rehydration INSERT above was rejected (daily write quota), there is no
        // row to update: skip the follow-up writes instead of retrying a write that will
        // fail again. The identity is still returned to the client.
        if (existingVisitor) {
          const visitId = generateVisitId();
          currentVisitId = visitId;
          try {
            db.prepare(
              `INSERT OR IGNORE INTO visits (
                visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
                public_ip, city, region, country, latitude, longitude, isp, org, asn,
                browser, os, device_type, screen_resolution, language, timezone
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            ).run(
              visitId,
              visitorId,
              currentSessionId,
              safePageLoadId,
              nowUtc,
              location.publicIp,
              location.city,
              location.region,
              location.country,
              location.latitude,
              location.longitude,
              location.isp,
              location.org,
              location.asn,
              browserDevice.browser,
              browserDevice.os,
              browserDevice.deviceType,
              browserDevice.screenResolution,
              browserDevice.language,
              browserDevice.timezone
            );
          } catch {
            // quota / transient DB failure: response still succeeds
          }

          try {
            db.prepare(
              `UPDATE visitors
               SET updated_at_utc = ?, active_session_id = ?, last_activity_utc = ?, hardware_id = ?
               WHERE visitor_id = ?`
            ).run(nowUtc, currentSessionId, nowUtc, hardwareId, visitorId);
          } catch {
            // quota / transient DB failure: response still succeeds
          }
        }
      }
    } else {
      visitorId = generateVisitorId();
      visitorToken = signVisitorId(visitorId);
      currentSessionId = generateSessionId();
      isReturning = false;

      try {
        db.prepare(
          `INSERT INTO visitors (
            visitor_id, hmac_token, hardware_id, created_at_utc, updated_at_utc, active_session_id, last_activity_utc
          ) VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).run(visitorId, visitorToken, hardwareId, nowUtc, nowUtc, currentSessionId, nowUtc);
      } catch {
        // quota / transient DB failure: response still succeeds
      }

      const visitId = generateVisitId();
      currentVisitId = visitId;
      try {
        db.prepare(
          `INSERT OR IGNORE INTO visits (
            visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
            public_ip, city, region, country, latitude, longitude, isp, org, asn,
            browser, os, device_type, screen_resolution, language, timezone
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          visitId,
          visitorId,
          currentSessionId,
          safePageLoadId,
          nowUtc,
          location.publicIp,
          location.city,
          location.region,
          location.country,
          location.latitude,
          location.longitude,
          location.isp,
          location.org,
          location.asn,
          browserDevice.browser,
          browserDevice.os,
          browserDevice.deviceType,
          browserDevice.screenResolution,
          browserDevice.language,
          browserDevice.timezone
        );
      } catch {
        // quota / transient DB failure: response still succeeds
      }
    }

    const cookieOptions = {
      maxAge: 365 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: 'lax' as const,
      path: '/',
      // Cloudflare terminates TLS in front of the origin: req.secure is false there but the
      // forwarded proto / cf-visitor header proves HTTPS. http://localhost stays insecure.
      secure: isSecureRequest({
        secure: req.secure,
        xForwardedProto: req.headers['x-forwarded-proto'] as string | undefined,
        cfVisitor: req.headers['cf-visitor'] as string | undefined,
      }),
    };
    res.cookie('intel_http_vid', visitorId, cookieOptions);
    res.cookie('intel_http_token', visitorToken, cookieOptions);
    // Non-HttpOnly mirror used by the client storage waterfall when localStorage
    // and IndexedDB are unavailable (private mode, storage eviction).
    res.cookie('_intel_vid_client', visitorId, { ...cookieOptions, httpOnly: false });
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');

    let statsAgg: {
      total_visits: number;
      first_visit_utc: string | null;
      last_visit_utc: string | null;
      total_sessions: number;
    };
    let prevVisitRow: { visited_at_utc: string } | undefined;
    try {
      statsAgg = db
        .prepare(
          `SELECT
            COUNT(*) AS total_visits,
            MIN(visited_at_utc) AS first_visit_utc,
            MAX(visited_at_utc) AS last_visit_utc,
            COUNT(DISTINCT session_id) AS total_sessions
           FROM visits
           WHERE visitor_id = ?`
        )
        .get(visitorId) as typeof statsAgg;

      prevVisitRow = db
        .prepare(
          `SELECT visited_at_utc
           FROM visits
           WHERE visitor_id = ?
           ORDER BY visited_at_utc DESC, id DESC
           LIMIT 1 OFFSET 1`
        )
        .get(visitorId) as { visited_at_utc: string } | undefined;
    } catch {
      // Unreadable store (blocked daily quota): fall back to the client's signed backup.
      statsAgg = {
        total_visits: 0,
        first_visit_utc: null,
        last_visit_utc: null,
        total_sessions: 0,
      };
      prevVisitRow = undefined;
    }

    const validBackupForStats =
      clientHistoryBackup && verifySignedHistoryBackup(visitorId, clientHistoryBackup)
        ? clientHistoryBackup
        : null;

    const dbTotalVisits = Number(statsAgg.total_visits) || 1;
    const mergedTotalVisits = validBackupForStats
      ? Math.max(dbTotalVisits, validBackupForStats.totalVisits)
      : dbTotalVisits;

    const dbTotalSessions = Number(statsAgg.total_sessions) || 1;
    const mergedTotalSessions = validBackupForStats
      ? Math.max(dbTotalSessions, validBackupForStats.totalSessions)
      : dbTotalSessions;

    const mergedFirstVisitUtc =
      validBackupForStats &&
      validBackupForStats.firstVisitUtc &&
      validBackupForStats.firstVisitUtc < (statsAgg.first_visit_utc || nowUtc)
        ? validBackupForStats.firstVisitUtc
        : statsAgg.first_visit_utc || nowUtc;

    const statistics: VisitStatistics = {
      firstVisitUtc: mergedFirstVisitUtc,
      lastVisitUtc: statsAgg.last_visit_utc || nowUtc,
      previousVisitUtc: prevVisitRow ? prevVisitRow.visited_at_utc : null,
      totalVisits: mergedTotalVisits,
      totalSessions: mergedTotalSessions,
      currentSessionId,
      sessionTimeoutMinutes: SESSION_TIMEOUT_MINUTES,
    };

    if (statistics.totalVisits > 1) {
      isReturning = true;
    }

    let rawVisits: Array<Record<string, unknown>> = [];
    try {
      rawVisits = db
        .prepare(
          `SELECT
            id, visit_id, visitor_id, session_id, page_load_id, visited_at_utc,
            public_ip, city, region, country, latitude, longitude, isp, org, asn,
            browser, os, device_type, screen_resolution, language, timezone,
            suspect_score, risk_level, score10, bot_name, recognition_source
           FROM visits
           WHERE visitor_id = ?
           ORDER BY visited_at_utc DESC, id DESC
           LIMIT 50`
        )
        .all(visitorId) as Array<Record<string, unknown>>;
    } catch {
      // Unreadable store (blocked daily quota): keep the response, just without history rows.
      rawVisits = [];
    }

    // A blocked Durable Object quota rejects reads as well as writes, which used to return an
    // empty Visit History even though the client still holds a server-signed backup of its
    // visits. Use that verified backup and always include the current page load, so the table,
    // map and location tiles keep rendering while the store is unavailable.
    if (rawVisits.length === 0) {
      const backupVisits = validBackupForStats?.visits ?? [];
      rawVisits = backupVisits.map((visit) => ({
        id: visit.id,
        visit_id: visit.visitId,
        visitor_id: visitorId,
        session_id: visit.sessionId,
        page_load_id: `backup_${visit.visitId}`,
        visited_at_utc: visit.visitedAtUtc,
        public_ip: visit.publicIp,
        city: visit.city,
        region: visit.region,
        country: visit.country,
        latitude: visit.latitude,
        longitude: visit.longitude,
        isp: visit.isp,
        org: visit.org,
        asn: visit.asn,
        browser: visit.browser,
        os: visit.os,
        device_type: visit.deviceType,
        screen_resolution: visit.screenResolution,
        language: visit.language,
        timezone: visit.timezone,
        suspect_score: visit.suspectScore ?? null,
        risk_level: visit.riskLevel ?? null,
        score10: visit.score10 ?? null,
        bot_name: visit.botName ?? null,
        recognition_source: visit.recognitionSource ?? null,
      }));

      rawVisits.unshift({
        id: 0,
        visit_id: currentVisitId || `backup_${safePageLoadId}`,
        visitor_id: visitorId,
        session_id: currentSessionId,
        page_load_id: safePageLoadId,
        visited_at_utc: nowUtc,
        public_ip: location.publicIp,
        city: location.city,
        region: location.region,
        country: location.country,
        latitude: location.latitude,
        longitude: location.longitude,
        isp: location.isp,
        org: location.org,
        asn: location.asn,
        browser: browserDevice.browser,
        os: browserDevice.os,
        device_type: browserDevice.deviceType,
        screen_resolution: browserDevice.screenResolution,
        language: browserDevice.language,
        timezone: browserDevice.timezone,
        suspect_score: null,
        risk_level: null,
        score10: null,
        bot_name: null,
        recognition_source: recognitionSource,
      });
    }

    const ipTimezoneHint =
      (typeof clientGeoHint?.timezone === 'string' && clientGeoHint.timezone.trim()) ||
      edgeGeo.timezone ||
      '';

    // Task 3 — visit velocity / IP rotation across the last hour. The window comes from the
    // same canonical VELOCITY_WINDOW_MS constant used by the SQL aggregation over `visits`,
    // so the two velocity views cannot drift apart. rawVisits is fetched AFTER the current
    // visit is inserted, so the visit being logged right now is already part of the window.
    const oneHourAgoMs = Date.now() - VELOCITY_WINDOW_MS['1_hour'];
    const lastHourVisitRows = rawVisits.filter((r) => {
      const visitedAtMs = Date.parse(String(r.visited_at_utc || ''));
      return Number.isFinite(visitedAtMs) && visitedAtMs >= oneHourAgoMs;
    });
    const lastHourIpSet = new Set<string>();
    for (const lastHourRow of lastHourVisitRows) {
      const lastHourIp = String(lastHourRow.public_ip || '').trim();
      if (lastHourIp && lastHourIp !== 'Unavailable') lastHourIpSet.add(lastHourIp);
    }
    const currentVisitIp = String(location.publicIp || '').trim();
    if (currentVisitIp && currentVisitIp !== 'Unavailable') {
      lastHourIpSet.add(currentVisitIp);
    }
    const visitsLastHour = Math.max(1, lastHourVisitRows.length);
    const distinctIpsLastHour = lastHourIpSet.size;

    // Incognito cross-mode inputs. Persistent client state means a verified first-party cookie,
    // a verified body visitor id, or a valid signed history backup. When none of those survived
    // AND this request recovered an existing hardware-ID row, the browsing context is ephemeral.
    const bodyVisitorId = storageVerified ? storedVisitorId ?? null : null;
    const historyBackupValid = Boolean(validBackupForStats);
    const hadPersistentClientState = Boolean(cookieVid || bodyVisitorId || historyBackupValid);

    // Accept every incognito spelling this app (and its legacy payloads) can post:
    // top-level, browserInfo.*, telemetry.*, securitySignals.* and any alias. The stable
    // 'high' | 'low' label gates them all; a 'low' label / numeric < 0.9 is a hard veto that a
    // fresh / cleared profile or a touch/geometry probe can never override.
    // Use OR (never `??`): an explicit false on one spelling must not shadow a genuine true on
    // another. This is what lets a real Chrome private window (`isIncognito: true`, high label,
    // no legacy `incognitoLikely`) survive into every mirror. Legacy numeric >= 0.9 is 'high'.
    const rawIncognitoConfidence: unknown = (
      rawSecuritySignals as (Partial<SecuritySignals> & { incognitoConfidence?: unknown }) | null | undefined
    )?.incognitoConfidence ?? requestBody.incognitoConfidence;
    const lowConfidenceVeto =
      rawIncognitoConfidence === 'low' ||
      (typeof rawIncognitoConfidence === 'number' && rawIncognitoConfidence < 0.9);
    const incognitoConfidenceHigh =
      !lowConfidenceVeto &&
      (rawIncognitoConfidence === 'high' ||
        (typeof rawIncognitoConfidence === 'number' && rawIncognitoConfidence >= 0.9));
    const clientReportedIncognito = incognitoConfidenceHigh && Boolean(
      requestBody.incognito || requestBody.isIncognito || requestBody.privateMode ||
      requestBody.browserInfo?.incognito || requestBody.browserInfo?.isIncognito ||
      requestBody.telemetry?.incognito || requestBody.telemetry?.isIncognito ||
      rawSecuritySignals?.isIncognito || rawSecuritySignals?.incognito ||
      rawSecuritySignals?.privateMode || rawSecuritySignals?.incognitoLikely
    );

    // Additive incognito diagnostics passthrough. Gated by `diagnostics.enabled` on the raw
    // identify body. This block ONLY builds an inert readout: it never feeds the gate above,
    // the verdict, any score, the incognito boolean, or any history row. The client-supplied
    // values are echoed verbatim (no re-derivation); only the two explicitly server-side
    // fields are overwritten here from the EXISTING gate input above, without changing that
    // gate. A low confidence label (or numeric < 0.9) is the server's hard veto, so both
    // readout fields report that same gate result (shadow fixture: deadband -> both true).
    const rawDiagnostics = requestBody.diagnostics;
    const diagnostics: IncognitoDiagnostics | undefined =
      rawDiagnostics && typeof rawDiagnostics === 'object' && rawDiagnostics.enabled === true
        ? {
            // Verbatim client pass-through.
            ...rawDiagnostics,
            // Server-computed from the existing gate input (read-only; gate unchanged).
            lowConfidenceVeto,
            serverWouldVeto: lowConfidenceVeto,
          }
        : undefined;

    // Fingerprint.com-style ephemeral-storage correlation. Only meaningful when NO persistent
    // client state survived (no verified cookie, no verified body visitor id, no signed backup).
    // Case A is the existing `hwid_...` lookup hit (`existingHwidVisitor`). Case B looks for an
    // earlier visit by this same physical device inside the last 7 days that belongs to a
    // DIFFERENT visitor id — `visitors.hardware_id` is the persisted GPU-derived identity
    // column (there is no GPU renderer column on `visits`), so it is matched together with the
    // per-visit columns the schema actually has: public_ip, screen_resolution, browser, os.
    let crossSessionEphemeral = false;
    if (!hadPersistentClientState && !existingHwidVisitor && hardwareId) {
      try {
        const sevenDaysAgoUtc = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
        const earlierDeviceVisit = db
          .prepare(
            `SELECT v.visitor_id
             FROM visits v
             JOIN visitors pv ON pv.visitor_id = v.visitor_id
             WHERE v.visitor_id != ?
               AND pv.hardware_id = ?
               AND v.public_ip = ?
               AND v.screen_resolution = ?
               AND v.browser = ?
               AND v.os = ?
               AND v.visited_at_utc >= ?
             ORDER BY v.visited_at_utc DESC
             LIMIT 1`
          )
          .get(
            visitorId,
            hardwareId,
            location.publicIp,
            browserDevice.screenResolution,
            browserDevice.browser,
            browserDevice.os,
            sevenDaysAgoUtc
          ) as { visitor_id: string } | undefined;
        crossSessionEphemeral = Boolean(earlierDeviceVisit);
      } catch {
        // A correlation query failure must never 500 the identify endpoint.
        crossSessionEphemeral = false;
      }
    }

    const securitySignalsInput: Partial<SecuritySignals> | null | undefined =
      rawSecuritySignals || requestBody.incognitoMethod
        ? {
            ...(rawSecuritySignals ?? {}),
            // Top-level method spelling is honoured when securitySignals omitted it.
            incognitoMethod: rawSecuritySignals?.incognitoMethod ?? requestBody.incognitoMethod,
          }
        : rawSecuritySignals;

    // Phase 4 — sealed request envelope verification runs BEFORE sanitization so every tile,
    // the composite score and the blocklist see the same verdict.
    const rawRequestHeaders = req.headers as RawHeaderBag;
    const envelopeVerdict = verifySecurityEnvelope({
      envelope: requestBody.securityEnvelope,
      headers: rawRequestHeaders,
      hardwareId,
      nowMs,
    });

    // Post-interaction human corroboration. The client reports a 0..1 confidence that a real
    // person is driving this runtime, carried in the sealed request's raw signals. It is
    // clamped / finiteness-checked and only TRUSTED when a clean, signed envelope is present:
    // a bare client flag without a valid envelope is capped low so it cannot manufacture human
    // corroboration. This same trusted value feeds the canonical envelope and the CDP gate.
    const rawSignalExtras = (rawSecuritySignals || {}) as Record<string, unknown>;
    // New clients post interaction evidence / inspector probes at the top level; older clients
    // nest them inside securitySignals. Merge both so genuine interaction is never invisible.
    const topLevelExtras = requestBody as unknown as Record<string, unknown>;
    const clientExtras: Record<string, unknown> = { ...topLevelExtras, ...rawSignalExtras };
    const claimedHumanCorroboration = clampHumanCorroboration(
      rawSecuritySignals?.humanCorroboration ??
        rawSignalExtras.humanCorroboration ??
        topLevelExtras.humanCorroboration
    );
    // Trust the client number only behind an actually verified, clean envelope. A valid signed
    // envelope with real interaction can still earn human_corroboration 1 below; a bare client
    // flag is capped low and automated / tampered sessions stay 0 via decideVerdictTier.
    const envelopeSignedAndClean = Boolean(
      requestBody.securityEnvelope &&
        envelopeVerdict.signatureVerified &&
        envelopeVerdict.requestNonce &&
        !envelopeVerdict.tamperedRequest &&
        !envelopeVerdict.replayDetected
    );
    const trustedHumanCorroboration = envelopeSignedAndClean
      ? claimedHumanCorroboration
      : Math.min(claimedHumanCorroboration, 0.2);
    const earlyInteractionEvidence = Array.isArray(clientExtras.interactionEvidence)
      ? (clientExtras.interactionEvidence as unknown[]).filter(
          (item): item is string => typeof item === 'string' && item.trim().length > 0
        ).length
      : 0;
    const hasTrustedInteractionEvidence =
      envelopeSignedAndClean && earlyInteractionEvidence > 0;

    /* ---- Additive zero-trust + network-fingerprint shadow diagnostics ------------
     * These are OBSERVATIONS ONLY. Nothing here is wired into auth, the blocklist, the
     * 0-10 headline, the 0-100 graded ledger, the verdict tier or isBot. The strict-origin
     * check is opt-in via env and even when enabled it only reports (`enforced: false`);
     * no request is ever rejected by this block.
     */
    const strictOriginOptIn =
      process.env.INTEL_STRICT_ORIGIN === '1' ||
      process.env.INTEL_ZERO_TRUST_STRICT_ORIGIN === '1';
    const firstClientText = (...values: unknown[]): string | null => {
      for (const value of values) {
        if (typeof value === 'string' && value.trim()) return value.trim();
      }
      return null;
    };
    const envelopeExtra = (requestBody.securityEnvelope ?? {}) as Record<string, unknown>;
    const strictOriginResult = checkStrictOrigin({
      origin: readRequestHeader(rawRequestHeaders, 'origin'),
      referer: readRequestHeader(rawRequestHeaders, 'referer'),
      clientUrl: firstClientText(
        clientExtras.clientUrl,
        clientExtras.documentUrl,
        clientExtras.pageUrl,
        clientExtras.href,
        envelopeExtra.url
      ),
      clientReferrer: firstClientText(
        clientExtras.clientReferrer,
        clientExtras.documentReferrer,
        clientExtras.referrer
      ),
      nowMs,
    });
    const envTimestampRaw = envelopeExtra.timestamp;
    const envelopeTimestampMs =
      typeof envTimestampRaw === 'number' && Number.isFinite(envTimestampRaw) && envTimestampRaw > 0
        ? envTimestampRaw
        : Number.parseFloat(readRequestHeader(rawRequestHeaders, 'x-intel-timestamp'));
    const replayWindow = replayWindowStatus(
      envelopeTimestampMs,
      nowMs,
      envelopeVerdict.replayDetected ? envelopeVerdict.requestNonce : null,
      ENVELOPE_MAX_AGE_MS
    );
    const ipLedgerReasons = suspiciousIpReasons.get(location.publicIp) ?? [];
    const replayLedgerReasons = ipLedgerReasons.filter((reason) => /replay/i.test(reason));
    const replayRate = ipReplayRate(replayLedgerReasons.length, ipLedgerReasons.length, 7);
    const zeroTrustShadow = {
      strict_origin: {
        enabled: strictOriginOptIn,
        ok: strictOriginResult.ok,
        reason: strictOriginResult.reason,
        // Purely additive: never enforced, never changes the existing auth flow.
        enforced: false,
      },
      replay_window: {
        fresh: replayWindow.fresh,
        duplicate: replayWindow.duplicate,
        reason: replayWindow.reason,
      },
      replay_rate: {
        ...replayRate,
        replays: replayLedgerReasons.length,
        observations: ipLedgerReasons.length,
        window_days: 7,
        note: 'Replay share over the in-process abuse ledger; diagnostic only, never a verdict input',
      },
    };
    const edgeTransportForTrust = readEdgeTransport(req);
    const networkFingerprintShadow = {
      // A Worker cannot observe raw wire order and Cloudflare rewrites headers, so an exact
      // JA4H is never asserted. Keep only the honestly computable, distinctly-labelled value.
      network_layer_hash: null,
      network_layer_hash_label:
        'JA4H-style HTTP-header fingerprint (not exact JA4H: raw wire order is unavailable to Workers and Cloudflare rewrites headers)',
      // All-plan Cloudflare TLS-lite components: never JA3/JA4, never a JA3/JA4-shaped hash.
      edge_tls: {
        label: 'edge-derived TLS components',
        tlsVersion: edgeTransportForTrust.tlsVersion || null,
        tlsCipher: edgeTransportForTrust.tlsCipher || null,
        clientTcpRttMs: edgeTransportForTrust.clientTcpRtt,
        httpProtocol: edgeTransportForTrust.httpProtocol || null,
        colo: edgeTransportForTrust.colo || null,
        ja3: edgeTransportForTrust.ja3,
        ja4t: edgeTransportForTrust.ja4t,
        // cf.botManagement.ja3Hash / ja4 are Enterprise-only: null-guarded, never claimed on free.
        cfJa4Enterprise: null,
        note: 'Free-plan TLS-lite components only; Enterprise cf.botManagement hashes are not claimed',
      },
    };

    // STRONG protocol-level CDP proof is the only path to `cdp_attached` / CDP escalation.
    // Error.name preview reads, a `cdpRuntimeLeak`, a patched webdriver getter or a substring
    // match inside an inspector probe preview are weak, engine-dependent mobile artifacts: they
    // are developer-tools telemetry and MUST NOT attach CDP or brand a real phone as automation.
    const strongCdpProof = hasStrongCdpProof(rawSecuritySignals, clientExtras);
    // ONE inspector verdict for the escalation gate, the envelope and the top-level mirrors.
    const earlyInspector = resolveInspectorState({
      strongCdpProof,
      developerTools: Boolean(rawSecuritySignals?.developerTools),
      cdpRuntimeLeak: Boolean(rawSecuritySignals?.cdpRuntimeLeak),
      automationEnvironment:
        typeof rawSecuritySignals?.automationEnvironment === 'string'
          ? rawSecuritySignals.automationEnvironment
          : undefined,
      devtoolsActiveVerified: Boolean(clientExtras.devtoolsActiveVerified),
      viewportContractionNormalized: Boolean(clientExtras.viewportContractionNormalized),
    });
    const earlyInspectorState = earlyInspector.inspector_state;
    const cdpBridge = strongCdpProof;
    const dockedWithHumanInteraction = Boolean(
      rawSecuritySignals?.developerTools ||
        clientExtras.devtoolsActiveVerified ||
        rawSecuritySignals?.automationEnvironment === 'electron' ||
        rawSecuritySignals?.automationEnvironment === 'ide_webview' ||
        earlyInspectorState === 'devtools_docked_suspected' ||
        earlyInspectorState === 'devtools_active_verified'
    ) &&
      (trustedHumanCorroboration >= 0.5 || hasTrustedInteractionEvidence);
    // Phase 1 — bot identity is resolved from the raw headers plus the server network identity.
    // Edge proxies truncate long User-Agent headers, so the signed envelope carries the full UA;
    // fall back to the raw header for older clients. A crawler/automation signature in the raw
    // header always wins so a spoofed envelope cannot mask a bot.
    // The Workers→Node adapter truncates comma-containing UA strings at the first comma.
    // The Worker forwards the complete value encoded in `x-intel-original-ua`; prefer it so
    // `…(KHTML, like Gecko; compatible; GPTBot…)` survives intact on the API path too.
    const encodedOriginalUa = readRequestHeader(rawRequestHeaders, 'x-intel-original-ua');
    let headerRequestUserAgent = readRequestHeader(rawRequestHeaders, 'user-agent');
    if (encodedOriginalUa) {
      try {
        headerRequestUserAgent = decodeURIComponent(encodedOriginalUa) || headerRequestUserAgent;
      } catch {
        // Malformed encoding: keep the plain header.
      }
    }
    const envelopeRequestUserAgent =
      typeof requestBody.securityEnvelope?.userAgent === 'string'
        ? requestBody.securityEnvelope.userAgent.trim()
        : '';
    const headerCarriesBotSignature =
      Boolean(headerRequestUserAgent) &&
      (AUTOMATION_UA_PATTERN.test(headerRequestUserAgent) ||
        GOOD_BOT_UA_RULES.some((rule) => rule.pattern.test(headerRequestUserAgent)) ||
        AI_AGENT_UA_RULES.some((rule) => rule.pattern.test(headerRequestUserAgent)));
    const fullRequestUserAgent = headerCarriesBotSignature
      ? headerRequestUserAgent
      : envelopeRequestUserAgent || headerRequestUserAgent;
    // Hard automation artifacts reach BOTH this first classification (which drives the final
    // bot_info / bot_type / history verdict) and the sanitizer's per-tile escalation. Omitting
    // them here used to leave the final classification as "Verified Human" even when the bot
    // tile was escalated — the two paths now read the exact same client fields.
    const rfpExemptRequest = isConfirmedTorRfpClient(rawSecuritySignals, {
      clientTorBrowser: Boolean(rawSecuritySignals?.isTorBrowserClient),
      tamperedRequest: envelopeVerdict.tamperedRequest,
      replayDetected: envelopeVerdict.replayDetected,
      strongCdpProof,
    });
    // Developer-tools evidence is a separate axis from automation (Fingerprint Pro parity).
    const developerToolsSignals = Boolean(
      rawSecuritySignals?.developerTools ||
        rawSecuritySignals?.cdpRuntimeLeak ||
        rawSecuritySignals?.automationEnvironment === 'electron' ||
        rawSecuritySignals?.automationEnvironment === 'ide_webview'
    );
    // Automation-targeted tampering is checked BEFORE the RFP exemption: a WebDriver /
    // Playwright / CDC / patched-CDP-getter artifact is protocol-level proof a privacy
    // preference cannot explain, so it can never be downgraded to "Verified Human".
    const handlerAutomationTampering = detectAutomationTargetedTampering(
      [
        ...(rawSecuritySignals?.tamperingDetails?.reasons ?? []),
        ...(rawSecuritySignals?.tamperReasons ?? []),
      ],
      rawSecuritySignals?.botSignals
    );
    // Weak webdriver-getter / Error-preview strings are NOT hard automation proof on their own;
    // they only accompany a genuine protocol-level CDP binding. A clean phone reporting just
    // those artifacts must stay human.
    const automationTargetedTampering = strongCdpProof && (
      handlerAutomationTampering.detected ||
      Boolean(
        (rawSecuritySignals as (Partial<SecuritySignals> & { automationTargetedTampering?: boolean }) | null)
          ?.automationTargetedTampering
      )
    );
    let hardAutomationSignals =
      (!rfpExemptRequest || automationTargetedTampering) &&
      Boolean(
        automationTargetedTampering ||
          (strongCdpProof && rawSecuritySignals?.stealthPluginDetected) ||
          rawSecuritySignals?.tamperingDetails?.anti_detect_browser
      );
    // Verify Web Bot Auth once, against the ORIGINAL public authority. Workers rewrites the
    // internal Host and may strip comma-bearing headers, so use the encoded originals that
    // worker/index.js forwards, falling back to the plain headers on the Node dev server.
    const decodeEdgeHeader = (name: string): string => {
      const value = readRequestHeader(rawRequestHeaders, name);
      if (!value) return '';
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    };
    const wbaAuthority =
      decodeEdgeHeader('x-intel-original-authority') || String(req.headers.host || '');
    const wbaHeaderBag: Record<string, string | string[] | undefined> = {
      ...rawRequestHeaders,
      'signature-agent':
        decodeEdgeHeader('x-intel-original-signature-agent') ||
        readRequestHeader(rawRequestHeaders, 'signature-agent'),
      'signature-input':
        decodeEdgeHeader('x-intel-original-signature-input') ||
        readRequestHeader(rawRequestHeaders, 'signature-input'),
      'signature':
        decodeEdgeHeader('x-intel-original-signature') ||
        readRequestHeader(rawRequestHeaders, 'signature'),
    };
    let requestWba: WbaVerification | null = null;
    try {
      requestWba = await verifyWebBotAuth({
        headers: wbaHeaderBag,
        authority: wbaAuthority,
        trust: WBA_TRUSTED_SIGNERS,
      });
    } catch {
      requestWba = null;
    }
    const pageAttestation =
      requestWba && requestWba.verified
        ? null
        : verifyPageAttestation(
            rawRequestHeaders,
            wbaAuthority,
            fullRequestUserAgent,
            location.publicIp
          );
    const effectiveWba: WbaVerification | null =
      requestWba && requestWba.verified ? requestWba : pageAttestation;

    // Corroborated CDP escalation. A CDP bridge alone (Runtime leak / inspector probe) is
    // developer-tools evidence with ZERO automation weight, so docked Electron / IDE sessions
    // with genuine interaction stay human. Real mobile / desktop browsers stay human unless
    // STRONG CDP protocol proof exists; only then do stealth artifacts or an absence of trusted
    // post-interaction corroboration promote the bridge. Verified RFC 9421 agents are exempt.
    const corroboratedCdp = assessCorroboratedCdp({
      cdpBridge,
      strongCdpProof,
      inspectorState: earlyInspectorState,
      dockedWithHumanInteraction,
      stealthArtifact: Boolean(
        automationTargetedTampering ||
          (strongCdpProof && rawSecuritySignals?.stealthPluginDetected) ||
          (!rfpExemptRequest && rawSecuritySignals?.tamperingDetails?.anti_detect_browser)
      ),
      trustedHumanCorroboration,
      hasTrustedInteractionEvidence,
      signedAgentExempt: Boolean(effectiveWba?.verified || pageAttestation?.verified),
    });
    if (corroboratedCdp.escalate) {
      hardAutomationSignals = true;
    }

    const botClassification = classifyBotTraffic(
      { ...rawRequestHeaders, 'user-agent': fullRequestUserAgent },
      { org: location.org, isp: location.isp, asn: location.asn },
      {
        isBot: Boolean(
          (strongCdpProof && rawSecuritySignals?.isBot) ||
            rawSecuritySignals?.webdriver ||
            (strongCdpProof && rawSecuritySignals?.cdpDetected)
        ),
        isHeadless: Boolean(rawSecuritySignals?.isHeadless),
        webdriver: Boolean(rawSecuritySignals?.webdriver),
        cdpDetected: strongCdpProof && Boolean(rawSecuritySignals?.cdpDetected),
        botSignals: Array.isArray(rawSecuritySignals?.botSignals)
          ? rawSecuritySignals.botSignals
          : [],
        cdpRuntimeLeak: Boolean(rawSecuritySignals?.cdpRuntimeLeak),
        stealthPluginDetected: strongCdpProof && Boolean(rawSecuritySignals?.stealthPluginDetected),
        developerTools: developerToolsSignals,
        automationEnvironment: rawSecuritySignals?.automationEnvironment,
        humanCorroboration: rawSecuritySignals?.humanCorroboration,
        antiDetectBrowser: rfpExemptRequest
          ? false
          : Boolean(rawSecuritySignals?.tamperingDetails?.anti_detect_browser),
        tamperingMlScore: rfpExemptRequest
          ? 0
          : typeof rawSecuritySignals?.tamperingMlScore === 'number'
          ? rawSecuritySignals.tamperingMlScore
          : 0,
        automationTargetedTampering,
        automationTamperingReasons: handlerAutomationTampering.reasons,
        webBotAuth: effectiveWba,
      }
    );

    // Phase 2 — the per-IP DNSEL query started before geolocation is authoritative for the
    // extracted address; if the geo provider reported a different address, that one is checked.
    const torLookupTarget = location.publicIp.trim().toLowerCase();
    const torStatus = await resolveTorExitStatus(
      location.publicIp,
      location,
      torLookupTarget === extractedIp.trim().toLowerCase() ? torLookupPromise : undefined,
      edgeGeo.isTorNetwork
    );
    const torExitNode = torStatus.isExit;

    // Location semantics. Country is the only field that is reliable for every network
    // type, so it is what `isLocationVerified` certifies. When the request came over Tor,
    // the resolved city and coordinates belong to the exit relay, not the visitor: they are
    // exposed separately as `networkLocation` so the UI can label them honestly.
    const isTorExit = torStatus.isExit;
    const isTor = isTorExit || edgeGeo.isTorNetwork || Boolean(location.isTor);
    const networkTypeLabel = String(classification.networkType || '');
    const isProxyOrVpn =
      Boolean(location.isProxyOrVpn) ||
      isTorExit ||
      /vpn|proxy/i.test(networkTypeLabel);
    const isNetworkLocation = isTorExit || /vpn|proxy|tor/i.test(networkTypeLabel);
    const hasCountryForLocation =
      Boolean(location.countryCode) || !isMissingGeoValue(location.country);
    const resolvedPrecision: LocationInfo['locationPrecision'] =
      !isMissingGeoValue(location.city)
        ? 'city'
        : !isMissingGeoValue(location.region)
        ? 'region'
        : hasCountryForLocation
        ? 'country'
        : 'unknown';

    location = {
      ...location,
      isTor,
      isTorExit,
      isProxyOrVpn,
      locationSource: location.locationSource ?? 'provider',
      locationPrecision: resolvedPrecision,
      isNetworkLocation,
      networkLocation: isNetworkLocation
        ? {
            label: isTorExit ? 'Tor exit node' : isProxyOrVpn ? 'VPN / proxy egress' : 'Network egress',
            city: !isMissingGeoValue(location.city) ? location.city : 'Unknown',
            region: !isMissingGeoValue(location.region) ? location.region : 'Unknown',
            country: location.country,
            countryCode: location.countryCode,
            latitude: location.latitude,
            longitude: location.longitude,
            isp: location.isp,
            org: location.org,
            asn: location.asn,
          }
        : location.networkLocation,
      isLocationVerified: hasCountryForLocation,
    };

    // Phase 1b — granular AI-agent attribution. CIDR / FCrDNS / RFC 9421 verification is only
    // attempted when the request actually claims an agent identity, so a normal page load pays
    // no DNS cost. Workers reject global timers, so re-arm the TTL-guarded, non-blocking feed
    // sync here as well; Node keeps its module-load daemon.
    void ensureAiBotCidrSync();
    let aiAgent = await resolveAiAgentIdentity({
      headers: rawRequestHeaders,
      userAgent: fullRequestUserAgent,
      webBotAuth: effectiveWba,
      originalAuthority: wbaAuthority,
      network: { isp: location.isp, org: location.org, asn: location.asn },
      publicIp: location.publicIp,
      client: {
        isBot: strongCdpProof && Boolean(rawSecuritySignals?.isBot),
        isHeadless: Boolean(rawSecuritySignals?.isHeadless),
        webdriver: Boolean(rawSecuritySignals?.webdriver),
        cdpDetected: strongCdpProof && Boolean(rawSecuritySignals?.cdpDetected),
        isVirtualMachine: Boolean(rawSecuritySignals?.isVirtualMachine),
        gpuVendor: hardwareSignals.gpuVendor,
        gpuRenderer: hardwareSignals.gpuRenderer,
        idbDurabilityRatio: rawSecuritySignals?.idbDurabilityRatio ?? null,
        screenResolution: browserDevice.screenResolution,
        platform: browserDevice.platform,
        botSignals: Array.isArray(rawSecuritySignals?.botSignals)
          ? rawSecuritySignals.botSignals
          : [],
        // A hard / stealth automation verdict must suppress cloud-VM agent attribution
        // (verified RFC 9421 signed agents remain exempt inside the resolver).
        hardAutomationSignals,
        automationTargetedTampering,
      },
    });

    // Resolve the registry definition behind the attributed agent. A User-Agent match is the
    // most specific source (e.g. GPTBot instead of a generic OpenAI operator), with the agent
    // id as a fallback for signed / telemetry-only attributions.
    // Match the registry from the UA even for a failed/spoofed claim. The identity badge
    // carries the verification failure; the NAME must still be the exact agent token so the
    // dashboard never falls back to a generic "Spoofed AI Impostor" string.
    const registryUaMatch = findRegistryAgent(fullRequestUserAgent);
    const registryAgent = registryUaMatch
      ? asLocalAgent(registryUaMatch)
      : lookupAgent(aiAgent.agentId);
    if (registryUaMatch) {
      // The exact registry display name and provider must reach every surface: the smart-signal
      // card, securitySignals.aiAgent, bot_info and the response mirrors.
      aiAgent = {
        ...aiAgent,
        agentName: asLocalAgent(registryUaMatch).displayName,
        operator: asLocalAgent(registryUaMatch).provider,
      };
    }

    // The attribution engine is authoritative over the generic classifier for AI identities:
    // a named agent replaces the generic label, and a failed official-bot claim becomes a
    // spoofed impostor (10/10) instead of a neutral crawler verdict. Verified search crawlers
    // and link previews keep their legitimate good_bot subtype; every ai_* category stays bad.
    const attributedBotClassification: BotClassification | null =
      aiAgent.detected && aiAgent.agentId === 'impostor-spoof'
        ? {
            subtype: 'bad_bot',
            label: 'Spoofed AI Bot',
            provider: aiAgent.operator,
            category: 'Spoofed Identity',
            confidence: 0.99,
            reasons: aiAgent.evidence.slice(0, 3),
          }
        : aiAgent.detected && aiAgent.agentId !== null
        ? {
            subtype:
              registryAgent && aiAgent.verified && isGoodCrawlerCategory(registryAgent.category)
                ? 'good_bot'
                : 'ai_agent',
            label: aiAgent.agentName,
            provider: aiAgent.operator,
            category: registryAgent?.category || 'AI Agent',
            confidence: aiAgent.verified ? 0.99 : 0.85,
            reasons: aiAgent.evidence.slice(0, 3),
          }
        : null;
    // A hard automation artifact always wins the final verdict: it must reach bot_info,
    // bot_type and the history rows, not just the per-tile score. An AI-agent attribution is
    // still preserved on `securitySignals.aiAgent`, and its impostor-spoof bad_bot verdict is
    // compatible with the escalation, so only a non-bot attribution is overridden here.
    // A corroborated CDP bridge supplies its own neutral stealth / Chromium-automation identity
    // so the sanitizer's bot tile can never render it as "Verified Human".
    const effectiveBotClassification: BotClassification = corroboratedCdp.escalate
      ? {
          subtype: 'bad_bot',
          label:
            corroboratedCdp.botType === 'stealth_automation'
              ? 'Stealth Automation'
              : 'Headless / CDP Automation',
          provider: 'Stealth Automation',
          category: 'Automation',
          confidence: 0.93,
          reasons: corroboratedCdp.reasons,
        }
      : hardAutomationSignals && attributedBotClassification?.subtype !== 'bad_bot'
      ? botClassification
      : attributedBotClassification ?? botClassification;

    // Only cryptographic tampering (modified signed payload) and nonce replay poison the IP
    // ledger. A User-Agent header mismatch is deliberately excluded: edge proxies can rewrite
    // or truncate headers, so it must never blocklist an otherwise normal visitor.
    const signedPayloadTampered = /Payload integrity hash mismatch/i.test(
      envelopeVerdict.requestIntegrityReason
    );
    if (signedPayloadTampered) {
      flagSuspiciousIp(
        location.publicIp,
        envelopeVerdict.requestIntegrityReason || 'Tampered request payload'
      );
    }
    if (envelopeVerdict.replayDetected) {
      flagSuspiciousIp(location.publicIp, 'Replayed payload nonce');
    }
    if (
      effectiveBotClassification.subtype === 'bad_bot' &&
      effectiveBotClassification.label === 'Spoofed Crawler'
    ) {
      flagSuspiciousIp(location.publicIp, 'Spoofed crawler user-agent');
    } else if (aiAgent.agentId === 'impostor-spoof') {
      flagSuspiciousIp(location.publicIp, 'Spoofed AI bot user-agent');
    }
    const blocklist = lookupSuspiciousIp(location.publicIp);

    const securitySignals = sanitizeAndReinforceSecuritySignals(
      securitySignalsInput,
      browserDevice,
      hardwareSignals,
      location,
      ipTimezoneHint,
      recognitionSource,
      classification,
      { visitsLastHour, distinctIpsLastHour },
      {
        hadPersistentClientState,
        existingHwidVisitor,
        clientReportedIncognito,
        incognitoConfidenceHigh,
        crossSessionEphemeral,
      },
      {
        headers: rawRequestHeaders,
        requestUserAgent: fullRequestUserAgent,
        tamperedRequest: envelopeVerdict.tamperedRequest,
        replayDetected: envelopeVerdict.replayDetected,
        requestIntegrityReason: envelopeVerdict.requestIntegrityReason,
        requestNonce: envelopeVerdict.requestNonce,
        // Real edge RTT feeds only the labelled RTT-based light-distance estimate in vpn_methods.
        clientTcpRttMs: edgeTransportForTrust.clientTcpRtt,
        torExitNode,
        torRelay: torStatus.isRelay,
        torVerdict: torStatus.verdict,
        torOperator: torStatus.operator,
        torOperatorHint: torStatus.viaOperatorHint,
        clientTorBrowser: Boolean(rawSecuritySignals?.isTorBrowserClient),
        aiAgent,
        registryAgent,
        ipBlocklisted: blocklist.blocklisted,
        ipBlocklistReasons: blocklist.reasons,
        botClassification: effectiveBotClassification,
        automationTargetedTampering,
        strongCdpProof,
        corroboratedCdpEscalation: corroboratedCdp.escalate,
      }
    );

    // Consistency — the location's hosting flag must agree with the authoritative network
    // classification used everywhere else. A cloud/datacenter egress must never report
    // isVpnOrHosting=false while datacenterAsn=true (or the reverse for consumer broadband).
    location = { ...location, isVpnOrHosting: Boolean(securitySignals.datacenterAsn) };

    // Server-verified identity — header-resolved UA / client hints outrank the client payload.
    // `serverVerifiedBrowser` / `serverVerifiedOs` carry the full resolved identity; the
    // `headerMismatch` verdict is a tolerant FAMILY comparison (not a string equality check) so
    // harmless version / vendor suffix differences never fire a false mismatch.
    const serverVerifiedBrowser =
      uaIdentity.browserName && uaIdentity.browserName !== 'Unknown'
        ? `${uaIdentity.browserName}${
            uaIdentity.browserFullVersion ? ` ${uaIdentity.browserFullVersion}` : ''
          }`
        : browserDevice.browser;
    // Runtime OS authority: when two independent runtime proofs agree, the host OS wins over
    // the UA / Sec-CH-UA claim. Otherwise the UA value is a claim only and is labelled as such.
    const runtimeOsVerdict = inferRuntimeOsVerdict(
      {
        hostOs: (hardwareSignals as ExtendedHardwareSignals).hostOs,
        gpuRenderer: hardwareSignals.gpuRenderer,
        gpuVendor: hardwareSignals.gpuVendor,
        gpuArchFamily: (hardwareSignals as ExtendedHardwareSignals).gpuArchFamily,
        architectureSource: (hardwareSignals as ExtendedHardwareSignals).architectureSource,
        engine: (hardwareSignals as ExtendedHardwareSignals).engine,
        architecture: hardwareSignals.architecture,
      },
      uaIdentity.os && uaIdentity.os !== 'Unknown' ? uaIdentity.os : browserDevice.os
    );
    const runtimeOsAuthoritative = runtimeOsVerdict.authoritative && !rfpExemptRequest;
    const uaOsLabel =
      uaIdentity.os && uaIdentity.os !== 'Unknown'
        ? `${uaIdentity.os}${uaIdentity.osVersion ? ` ${uaIdentity.osVersion}` : ''}`
        : browserDevice.os;
    const uaOsFamily = osFamilyFromText(uaOsLabel);
    const conflictingRuntimeClaim = Boolean(
      runtimeOsVerdict.family && uaOsFamily && uaOsFamily !== runtimeOsVerdict.family
    );
    const serverVerifiedOs = runtimeOsAuthoritative && runtimeOsVerdict.family
      ? runtimeOsVerdict.label
      : conflictingRuntimeClaim && !/\(claimed\)$/i.test(uaOsLabel)
      ? `${uaOsLabel} (claimed)`
      : uaOsLabel;
    const serverOsFamily = osFamilyKey(serverVerifiedOs);
    const clientOsFamily = osFamilyKey(browserDevice.os);
    const serverBrowserFamily = browserFamilyKey(serverVerifiedBrowser);
    const clientBrowserFamily = browserFamilyKey(browserDevice.browser);
    const headerMismatch = Boolean(
      (serverOsFamily && clientOsFamily && serverOsFamily !== clientOsFamily) ||
        (serverBrowserFamily && clientBrowserFamily && serverBrowserFamily !== clientBrowserFamily)
    );
    securitySignals.serverVerifiedBrowser = serverVerifiedBrowser;
    securitySignals.serverVerifiedOs = serverVerifiedOs;
    securitySignals.headerMismatch = headerMismatch;
    securitySignals.headerMismatchReason = headerMismatch
      ? `Server headers report ${serverVerifiedBrowser} on ${serverVerifiedOs}, but the client reported ${browserDevice.browser} on ${browserDevice.os}`
      : '';

    // Phase 2 — SQLite velocity windows, device rarity and the calibrated 0–100 Suspect Score.
    // These are additive to the 0–10 per-tile grid: the tiles keep their own calibrated scale
    // while the Risk Meter consumes the 0–100 composite.
    const velocityReport = computeVelocitySignals(
      db,
      visitorId,
      location.publicIp,
      currentSessionId
    );
    const rarityReport = computeDeviceRarity(db, browserDevice);
    // High-activity threshold mode. A small daily-hardware corpus has no stable percentile, so
    // use the fixed rule: 12+ events/24h, 8+ events/1h, or 3+ distinct /24-/64 subnets. Once at
    // least 100 distinct devices are active in a day, switch to the 98th percentile of the
    // per-visitor daily event distribution. Per-IP event counts alone never flag a device.
    const SMALL_CORPUS_DAILY_HARDWARE_LIMIT = 100;
    const FIXED_HIGH_ACTIVITY_EVENTS_24H = 12;
    const FIXED_HIGH_ACTIVITY_EVENTS_1H = 8;
    const FIXED_HIGH_ACTIVITY_DISTINCT_SUBNETS = 3;
    const highActivityThresholdMode: 'fixed_small_corpus' | 'p98' =
      velocityReport.distinctDailyHardware < SMALL_CORPUS_DAILY_HARDWARE_LIMIT
        ? 'fixed_small_corpus'
        : 'p98';
    const highActivityThreshold =
      highActivityThresholdMode === 'fixed_small_corpus'
        ? FIXED_HIGH_ACTIVITY_EVENTS_24H
        : Math.max(1, velocityReport.p98Events24h);
    const highActivityDevice =
      highActivityThresholdMode === 'fixed_small_corpus'
        ? velocityReport.events24h >= FIXED_HIGH_ACTIVITY_EVENTS_24H ||
          velocityReport.events1h >= FIXED_HIGH_ACTIVITY_EVENTS_1H ||
          velocityReport.distinctSubnets24h >= FIXED_HIGH_ACTIVITY_DISTINCT_SUBNETS
        : velocityReport.events24h >= highActivityThreshold;

    // A timezone mismatch is a network axis, never tampering evidence. If the client filed its
    // timezone note under tamperingDetails.reasons, strip those reason strings and do not let a
    // timezone-only tampering boolean reach the tampering / spoofing verdicts.
    const rawTamperingReasons = Array.isArray(rawSecuritySignals?.tamperingDetails?.reasons)
      ? rawSecuritySignals.tamperingDetails.reasons.filter(
          (reason): reason is string => typeof reason === 'string' && reason.trim().length > 0
        )
      : [];
    const nonTimezoneTamperingReasons = rawTamperingReasons.filter(
      (reason) => !isTimezoneMismatchReason(reason)
    );
    const timezoneOnlyTampering =
      rawTamperingReasons.length > 0 &&
      nonTimezoneTamperingReasons.length === 0 &&
      Boolean(securitySignals.timezoneMismatch);
    const clientTampering = timezoneOnlyTampering ? false : rawSecuritySignals?.tampering ?? null;
    const rfpExemptResponse = isConfirmedTorRfpClient(rawSecuritySignals, {
      clientTorBrowser: Boolean(rawSecuritySignals?.isTorBrowserClient),
      tamperedRequest: envelopeVerdict.tamperedRequest,
      replayDetected: envelopeVerdict.replayDetected,
    });
    const tamperingAssessment =
      clientTampering === null
        ? null
        : {
            tampering: rfpExemptResponse ? false : Boolean(clientTampering),
            confidence: (rawSecuritySignals?.tamperingConfidence || 'high') as
              | 'low'
              | 'medium'
              | 'high',
            mlScore: rfpExemptResponse
              ? 0.0024
              : typeof rawSecuritySignals?.tamperingMlScore === 'number'
              ? rawSecuritySignals.tamperingMlScore
              : 0.0024,
            details: rfpExemptResponse
              ? {
                  ...rfpExemptTamperingDetails(rawSecuritySignals),
                  reasons: nonTimezoneTamperingReasons.filter(
                    (reason) => !RFP_DEVICE_WIDTH_REASON.test(reason)
                  ),
                }
              : {
                  ...(rawSecuritySignals?.tamperingDetails ?? {
                    anomaly_score: 0,
                    anti_detect_browser: false,
                    devtools_device_emulation: false,
                  }),
                  reasons: nonTimezoneTamperingReasons,
                },
          };
    const activeCallSupported = Boolean(rawSecuritySignals?.activeCallSupported);
    const activeCall = activeCallSupported && Boolean(rawSecuritySignals?.activeCall);
    const privacySettings = Boolean(
      rawSecuritySignals?.privacySettings ||
        rawSecuritySignals?.isTorBrowserClient ||
        securitySignals.privacyProtected
    );
    const developerTools = Boolean(rawSecuritySignals?.developerTools);
    const rawExtras = (rawSecuritySignals || {}) as Record<string, unknown>;

    // Phase 3 — run the eight pure spec invariants before reconciling tampering / inspector.
    const specAssessment = evaluateSpecInvariants({
      deviceMemoryGb: hardwareSignals.deviceMemoryGb,
      networkRtt: typeof rawExtras.networkRtt === 'number' ? rawExtras.networkRtt : null,
      battery:
        (rawExtras.battery as {
          charging?: boolean;
          chargingTime?: number;
          dischargingTime?: number;
          level?: number;
        }) || null,
      jsHeapSizeLimit: typeof rawExtras.jsHeapSizeLimit === 'number' ? rawExtras.jsHeapSizeLimit : null,
      expectedJsHeapSizeLimit:
        typeof rawExtras.expectedJsHeapSizeLimit === 'number' ? rawExtras.expectedJsHeapSizeLimit : null,
      webglRenderer: hardwareSignals.gpuRenderer,
      osFamily: browserDevice.os,
      deviceKind: browserDevice.deviceKind,
      hasPdfFace: typeof rawExtras.pdfViewerEnabled === 'boolean' ? rawExtras.pdfViewerEnabled : null,
      transport: {
        httpPlatform: typeof rawExtras.httpPlatform === 'string' ? rawExtras.httpPlatform : '',
        httpPlatformVersion:
          typeof rawExtras.httpPlatformVersion === 'string' ? rawExtras.httpPlatformVersion : '',
        jsPlatform: browserDevice.platform,
      },
      privacyHardened: Boolean(rfpExemptResponse),
      userAgent: fullRequestUserAgent,
    });
    const privacyHardened = Boolean(
      rfpExemptResponse ||
        specAssessment.privacy_hardened ||
        resolvePrivacyHardened({
          userAgent: fullRequestUserAgent,
          torBrowser: Boolean(rawSecuritySignals?.isTorBrowserClient),
          braveShields: Boolean(rawExtras.braveShields),
          firefoxFpp: Boolean(rawExtras.firefoxFpp),
          resistFingerprinting: Boolean(rawExtras.resistFingerprinting),
          safariAtfp: Boolean(rawExtras.safariAtfp),
        })
    );
    // A UA OS that contradicts two agreeing runtime proofs is a spec violation. Privacy-hardened
    // / Tor / RFP sessions are exempt: reduced-entropy probes cannot authoritatively name an OS.
    // Never raise a spoofed-OS / emulated-OS banner from a nan-sign-bit or software arch source.
    const archTruthSource = String(
      (hardwareSignals as ExtendedHardwareSignals).architectureSource || ''
    ).toLowerCase();
    const archTruthValue = String(hardwareSignals.architecture || '').toLowerCase();
    const gpuArchTruth = String(
      (hardwareSignals as ExtendedHardwareSignals).gpuArchFamily || ''
    ).toLowerCase();
    const untrustedArchTruth =
      archTruthSource === 'nan-sign-bit' ||
      /^(unknown|software|nan)$/.test(archTruthValue) ||
      /^(unknown|software|nan)$/.test(gpuArchTruth);
    if (
      runtimeOsAuthoritative &&
      runtimeOsVerdict.uaMismatch &&
      !privacyHardened &&
      !untrustedArchTruth
    ) {
      specAssessment.hardViolations = Array.from(
        new Set([...specAssessment.hardViolations, 'os_ua_mismatch'])
      );
    }
    const reconciledTampering = enforceTamperingInvariant({
      reasons: [
        ...(tamperingAssessment?.details?.reasons || []),
        ...specAssessment.softViolations,
        ...specAssessment.hardViolations,
      ],
      hard_spec_violation: specAssessment.hard_spec_violation,
      privacy_hardened: privacyHardened,
      software_renderer: specAssessment.software_renderer,
    });

    // Consistency — tampering points and the tampering boolean must agree. Genuine tampering
    // factors (UA/header contradiction, canvas read noise, emulator-GPU signature, spec
    // violations) are carried on the single tampering verdict with matching reasons. No
    // tampering points are charged while every tampering boolean is false.
    const tamperingFactorReasons: string[] = Array.from(
      new Set(
        [
          ...(headerMismatch && securitySignals.headerMismatchReason
            ? [securitySignals.headerMismatchReason]
            : []),
          ...(hardwareSignals.canvasNoise ? ['Canvas read noise detected'] : []),
          ...(securitySignals.emulatorDetected &&
          securitySignals.emulatorReason &&
          /gpu|renderer|webgl/i.test(securitySignals.emulatorReason)
            ? [securitySignals.emulatorReason]
            : []),
          ...specAssessment.softViolations,
          ...specAssessment.hardViolations,
        ].filter((reason): reason is string => typeof reason === 'string' && reason.length > 0)
      )
    );
    let effectiveTamperingDetected = Boolean(
      tamperingAssessment?.tampering ||
        securitySignals.tamperDetected ||
        securitySignals.tamperedRequest ||
        reconciledTampering.detected
    );
    if (tamperingFactorReasons.length > 0 && !effectiveTamperingDetected) {
      effectiveTamperingDetected = true;
      securitySignals.tamperDetected = true;
      securitySignals.tamperReasons = Array.from(
        new Set([...(securitySignals.tamperReasons || []), ...tamperingFactorReasons])
      ).slice(0, 10);
    }

    // Named AI agents need RFC 9421 / signed-agent / allowlist proof; ASN alone never qualifies.
    const agentProofMethod = resolveAgentProofMethod(rawRequestHeaders);
    const rfc9421SignedAgent = Boolean(
      aiAgent?.detected &&
        (agentProofMethod === 'rfc9421' ||
          agentProofMethod === 'signed_agent' ||
          (aiAgent as { executionMode?: string }).executionMode === 'RFC 9421 Signed Agent')
    );

    const hostingDatacenter = Boolean(
      securitySignals.datacenterAsn || /cloud|datacenter|hosting/i.test(networkTypeLabel)
    );
    const vpnOrRelay = Boolean(
      securitySignals.vpnSuspected || securitySignals.publicVpn || isTorExit || torStatus.isRelay
    );
    const rotatingProxy = Boolean(
      (securitySignals as SecuritySignals & { proxyDetected?: boolean }).proxyDetected
    );
    const timezoneMismatch = Boolean(securitySignals.timezoneMismatch);
    const swiftshader = specAssessment.software_renderer;
    const ephemeralStorage = Boolean(securitySignals.isIncognito);
    const highActivity = highActivityDevice;
    const extremeRotation = velocityReport.distinctIps24h >= 10;
    const tamperingTierA = Boolean(
      reconciledTampering.detected &&
        (reconciledTampering.hard_spec_violation ||
          tamperingAssessment?.tampering ||
          securitySignals.tamperedRequest ||
          securitySignals.replayDetected)
    );
    const tamperingTierB = Boolean(
      !tamperingTierA && reconciledTampering.detected && securitySignals.tamperDetected
    );
    const tamperingSoft = Boolean(
      !tamperingTierA &&
        !tamperingTierB &&
        specAssessment.softViolations.length > 0 &&
        effectiveTamperingDetected
    );

    const riskLedger = computeCanonicalRiskLedger({
      automation: {
        tierA: Boolean(securitySignals.isBot || hardAutomationSignals),
        tierB: Boolean(!securitySignals.isBot && developerTools),
        rfc9421SignedAgent,
      },
      tampering: {
        tierA: tamperingTierA,
        tierB: tamperingTierB,
        soft: tamperingSoft,
        privacyHardened,
      },
      network: {
        hostingDatacenter,
        vpnOrRelay,
        rotatingProxy,
        timezoneMismatch,
        otherComponentFired: hostingDatacenter || vpnOrRelay || rotatingProxy,
      },
      environment: { swiftshader, ephemeralOrPrivateStorage: ephemeralStorage },
      velocity: { high: highActivity, extreme: extremeRotation },
    });
    const suspectScore100 = riskLedger.score_0_100;

    // Canonical ledger is the SINGLE source for the public headline. The earlier heuristic
    // `securitySignals.suspectScore` is retained only as a cross-check, then overwritten so the
    // response, history row, DB persistence and risk badge all report the exact graded result.
    const canonicalScore10 = riskLedger.score10;
    const canonicalRiskLevel = riskLevelFromTier(riskLedger.risk_tier);
    securitySignals.suspectScore = canonicalScore10;
    securitySignals.riskLevel = canonicalRiskLevel;
    (securitySignals as unknown as Record<string, unknown>).riskBadgeText =
      `${canonicalRiskLevel} Risk • ${canonicalScore10}/10`;
    // Check the values actually published AFTER reconciliation. The legacy heuristic score is
    // intentionally discarded above; asserting before the overwrite only logged an expected
    // divergence on every deception-heavy request.
    assertRiskHeadlineConsistency({
      score10: canonicalScore10,
      risk_tier: riskLedger.risk_tier,
      suspectScore: securitySignals.suspectScore,
      riskLevel: securitySignals.riskLevel,
    });

    // Every history row always carries suspectScore / riskLevel / recognitionSource so the UI
    // never renders `undefined`. Stored per-visit risk data is used when present; the current
    // visit falls back to the just-computed security signals; legacy rows use safe defaults.
    const currentBotName = hardAutomationSignals
      ? `${effectiveBotClassification.provider} ${effectiveBotClassification.label}`.trim()
      : (aiAgent?.detected ? aiAgent.agentName : '') ||
        (effectiveBotClassification.subtype !== 'human'
          ? `${effectiveBotClassification.provider} ${effectiveBotClassification.label}`.trim()
          : '');

    const visitHistory = rawVisits.map((r) => {
      // Task 2b — legacy rows stored per-visit scores on a 0..100 scale; values above 10 are
      // rescaled so stored scores always render on the same 0..10 scale as the current visit.
      const storedScore10 =
        typeof r.score10 === 'number' && Number.isFinite(r.score10)
          ? Math.max(0, Math.min(10, Math.round(r.score10)))
          : null;
      const storedSuspectScore =
        typeof r.suspect_score === 'number' && Number.isFinite(r.suspect_score)
          ? normalizeLegacySuspectScore(r.suspect_score)
          : storedScore10;
      const isCurrentVisitRow = String(r.page_load_id || '') === safePageLoadId;
      const rowSuspectScore =
        storedSuspectScore !== null
          ? storedSuspectScore
          : isCurrentVisitRow
          ? securitySignals.suspectScore
          : 0;
      const storedRiskLevel =
        r.risk_level === 'High' || r.risk_level === 'Medium' || r.risk_level === 'Low'
          ? (r.risk_level as RiskLevel)
          : null;
      const rowRiskLevel: RiskLevel =
        storedRiskLevel ??
        (rowSuspectScore >= 7 ? 'High' : rowSuspectScore >= 3 ? 'Medium' : 'Low');
      const rowRecognitionSource =
        typeof r.recognition_source === 'string' && r.recognition_source
          ? r.recognition_source
          : isCurrentVisitRow
          ? recognitionSource
          : 'Cookie';
      const rowBotName =
        typeof r.bot_name === 'string' && r.bot_name
          ? r.bot_name
          : isCurrentVisitRow
          ? currentBotName
          : '';
      const rowCloudOrMaskedGpu = isCurrentVisitRow
        ? Boolean(
            (securitySignals as SecuritySignals & { cloudOrMaskedGpu?: boolean }).cloudOrMaskedGpu
          )
        : false;

      return {
        id: Number(r.id),
        visitId: String(r.visit_id),
        visitorId: String(r.visitor_id),
        sessionId: String(r.session_id),
        visitedAtUtc: String(r.visited_at_utc),
        publicIp: String(r.public_ip),
        city: String(r.city),
        region: String(r.region),
        country: String(r.country),
        latitude: typeof r.latitude === 'number' && Number.isFinite(r.latitude) ? r.latitude : null,
        longitude: typeof r.longitude === 'number' && Number.isFinite(r.longitude) ? r.longitude : null,
        isp: String(r.isp || 'Unknown'),
        org: String(r.org || 'Unknown'),
        asn: String(r.asn || 'Unknown'),
        browser: String(r.browser),
        os: String(r.os),
        deviceType: String(r.device_type),
        screenResolution: String(r.screen_resolution),
        language: String(r.language),
        timezone: String(r.timezone),
        suspectScore: rowSuspectScore,
        score10: Math.max(0, Math.min(10, Math.round(rowSuspectScore))),
        riskLevel: rowRiskLevel,
        botName: rowBotName || undefined,
        recognitionSource: rowRecognitionSource,
        cloudOrMaskedGpu: rowCloudOrMaskedGpu,
      };
    });

    // Persist this visit's final risk verdict *after* the per-visit history fallback was read,
    // so the next request (or a cold start) restores the exact same High • 10/10 row.
    if (currentVisitId) {
      try {
        db.prepare(
          `UPDATE visits
           SET suspect_score = ?, risk_level = ?, score10 = ?, bot_name = ?, recognition_source = ?
           WHERE visit_id = ?`
        ).run(
          securitySignals.suspectScore,
          securitySignals.riskLevel,
          Math.max(0, Math.min(10, Math.round(securitySignals.suspectScore))),
          currentBotName || null,
          recognitionSource,
          currentVisitId
        );
      } catch {
        // A scoring write must never fail the identification response.
      }
    }

    const historyBackup = createSignedHistoryBackup(
      visitorId,
      statistics.totalVisits,
      statistics.totalSessions,
      statistics.firstVisitUtc,
      visitHistory,
      hardwareId
    );

    // Fix 8 — Robodex Bot Directory & structured bot_info evaluation
    const asnNumMatch = (location.asn || '').match(/\d+/);
    const asnNumber = asnNumMatch ? Number.parseInt(asnNumMatch[0], 10) : null;
    const robodexResult = detectAiBotFromServerSignals({
      userAgent: fullRequestUserAgent,
      asnNumber,
      asnOrg: `${location.org} ${location.isp}`,
      headers: rawRequestHeaders,
    });

    let botInfo: BotInfo | null = null;
    let botType: string | null = null;
    let botVerdict = 'not_detected';
    // A "spoofed" identity needs a loaded feed / DNS answer that positively excludes the IP;
    // unavailable verification sources alone must degrade to "unknown", never to a spoof.
    const positiveSpoofExclusion = (aiAgent?.evidence || []).some((line) =>
      /is not (on|inside)\b/i.test(line)
    );

    if (hardAutomationSignals) {
      // A stealth / anti-detect runtime is always an automation verdict — never let a crawler
      // directory match or an AI-agent attribution report this session as human / good.
      botInfo = {
        category: 'browser_automation',
        provider: effectiveBotClassification.provider || 'Unknown',
        name: effectiveBotClassification.label || 'Automated Tool',
        identity: 'unknown',
      };
      botType = corroboratedCdp.escalate
        ? (corroboratedCdp.botType ?? 'chromium_automation')
        : automationTargetedTampering
        ? 'stealth_automation'
        : 'browser_automation';
      botVerdict = 'bad';
    } else if (aiAgent.detected && registryAgent && aiAgent.agentId !== 'impostor-spoof') {
      // Registry-backed named agent: the exact display name, provider and category flow into
      // bot_info / bot_type / botVerdict so every bot surface agrees with the smart-signal tile.
      botInfo = {
        category: registryAgent.category || 'ai_agent',
        provider: registryAgent.provider || 'Unknown',
        name: registryAgent.displayName || aiAgent.agentName,
        identity: aiAgent.verified
          ? /signed/i.test(String(aiAgent.executionMode || ''))
            ? 'signed'
            : 'verified'
          : 'unknown',
      };
      botType = registryAgent.id;
      // Every ai_* category is always bad; only verified search crawlers / link previews
      // may receive the good verdict.
      botVerdict =
        aiAgent.verified && isGoodCrawlerCategory(registryAgent.category) ? 'good' : 'bad';
    } else if (robodexResult.detected && robodexResult.botInfo) {
      botInfo = robodexResult.botInfo;
      botType = robodexResult.botType;
      // An unverified or spoofed claim is never a "good" bot. Verified crawlers and
      // assistants keep the good verdict; signed agent runtimes are always flagged.
      botVerdict =
        botInfo?.identity === 'spoofed' || botInfo?.identity === 'unknown'
          ? 'bad'
          : botType === 'ai_agent' ||
            botType === 'ai_browser' ||
            botType === 'browser_automation'
          ? 'bad'
          : 'good';
    } else if (aiAgent.detected) {
      const isImpostor = aiAgent.agentId === 'impostor-spoof';
      botInfo = {
        category: isImpostor ? 'browser_automation' : 'ai_agent',
        provider: aiAgent.operator || 'Unknown',
        name: aiAgent.agentName,
        identity: isImpostor
          ? positiveSpoofExclusion
            ? 'spoofed'
            : 'unknown'
          : aiAgent.verified
          ? aiAgent.executionMode === 'RFC 9421 Signed Agent'
            ? 'signed'
            : 'verified'
          : 'unknown',
      };
      botType = 'ai_agent';
      botVerdict = 'bad';
    } else if (effectiveBotClassification.subtype === 'bad_bot') {
      botInfo = {
        category: 'browser_automation',
        provider: effectiveBotClassification.provider || 'Unknown',
        name: effectiveBotClassification.label || 'Automated Tool',
        identity: 'unknown',
      };
      botType = 'browser_automation';
      botVerdict = 'bad';
    } else if (effectiveBotClassification.subtype === 'ai_agent') {
      // A named autonomous / LLM crawler UA is still a bot even when the attribution engines
      // could not name an operator. Without this branch isBot (subtype-derived) and botVerdict
      // (directory-derived) used to disagree, breaking the single-source-of-truth invariant.
      botInfo = {
        category: 'ai_agent',
        provider: effectiveBotClassification.provider || 'AI Agent',
        name: effectiveBotClassification.label || 'AI Agent',
        identity: 'unknown',
      };
      botType = 'ai_agent';
      botVerdict = 'bad';
    } else if (effectiveBotClassification.subtype === 'good_bot') {
      botInfo = {
        category: 'ai_crawler',
        provider: effectiveBotClassification.provider || 'Search Engine',
        name: effectiveBotClassification.label || 'Search Crawler',
        identity: 'verified',
      };
      botType = 'ai_crawler';
      botVerdict = 'good';
    }

    if (automationTargetedTampering) {
      // Final authority: automation-targeted tampering always pins the bad / stealth verdict
      // and a zero human corroboration, regardless of any directory / agent attribution.
      botInfo = {
        category: 'browser_automation',
        provider: effectiveBotClassification.provider || 'Stealth Automation',
        name: effectiveBotClassification.label || 'Stealth Automation',
        identity: 'unknown',
      };
      botType = 'stealth_automation';
      botVerdict = 'bad';
    }

    // Final label authority: if any attribution engine / directory still produced a Gemini or
    // generic "Cloud Agent" label on a session the automation verdict owns, replace it with a
    // neutral stealth / headless automation identity everywhere it is serialized. A verified
    // RFC 9421 signed agent is the sole exemption and keeps its real attribution.
    const signedAgentIdentity = Boolean(
      aiAgent?.verified && /signed/i.test(String(aiAgent.executionMode || ''))
    );
    const lingeringCloudAgentLabel =
      aiAgent?.agentId === 'gemini' || /google gemini|cloud agent/i.test(botInfo?.name || '');
    if (
      lingeringCloudAgentLabel &&
      !signedAgentIdentity &&
      (hardAutomationSignals ||
        botVerdict === 'bad' ||
        /stealth|headless|chromium/i.test(String(botType || '')))
    ) {
      securitySignals.aiAgent = null;
      const headlessVariant = /headless|chromium/i.test(String(botType || ''));
      botInfo = {
        category: 'browser_automation',
        provider: 'Stealth Automation',
        name: headlessVariant ? 'Headless Automation' : 'Stealth Automation',
        identity: 'unknown',
      };
      botType = headlessVariant ? 'headless_automation' : 'stealth_automation';
      botVerdict = 'bad';
    }

    if (botInfo) {
      securitySignals.botInfo = botInfo;
    }

    // Single source of truth: every serialized isBot mirror is derived from botVerdict, and the
    // parity assertion runs on the exact values that go out over the wire.
    const canonicalIsBot = isBotFromVerdict(botVerdict);
    securitySignals.isBot = canonicalIsBot;
    assertBotVerdictParity(
      { isBot: canonicalIsBot, securitySignalsIsBot: securitySignals.isBot, envelopeBot: botVerdict },
      botVerdict
    );

    // The composite incognito confidence lives on securitySignals, but the dashboard reads the
    // hardware-truth object. Mirror the same stable 'high' | 'low' label there so both views
    // agree; 'low' (or an unknown value) never reads as an incognito verdict. The cast bridges
    // the legacy numeric type declaration during the shared-type migration.
    (hardwareSignals as ExtendedHardwareSignals).incognitoConfidence = (incognitoConfidenceHigh
      ? 'high'
      : 'low') as unknown as number;

    /* ------------------------------------------------------------------ */
    /* Tri-layer identity resolution + calibrated confidence (v2.0)        */
    /* ------------------------------------------------------------------ */
    // The client-side collector echoes its tri-layer identity profile. Older clients omit it,
    // so a compatible fallback profile is assembled from the canonical hardware signals —
    // resolution never depends on the new payload shape being present.
    const rawIdentityProfile =
      requestBody.identityProfile && typeof requestBody.identityProfile === 'object'
        ? (requestBody.identityProfile as unknown as ResolverProfile)
        : null;
    const fallbackIdentityProfile: ResolverProfile = {
      hardwareFingerprint: hardwareId,
      browser: { family: browserDevice.browser },
      os: { family: browserDevice.os },
      timezone: browserDevice.timezone,
      gpu: { vendor: hardwareSignals.gpuVendor, renderer: hardwareSignals.gpuRenderer },
      canvas: { hash: hardwareSignals.canvasHash },
      audio: { hash: hardwareSignals.audioHash },
      cpu: { cores: hardwareSignals.cpuCores },
      languages: browserDevice.language ? [browserDevice.language] : [],
      net: { ip: extractedIp, asn: location.asn },
    };
    const identityProfile = rawIdentityProfile ?? fallbackIdentityProfile;
    // Screen geometry / DPR / touch are volatile context. Exclude the whole `screen` block from
    // the SimHash used for LSH bands and candidate retrieval so display changes cannot split a
    // visitor; the full profile is still stored for the 6-mode matcher and block keys.
    const lshIdentityProfile: Record<string, unknown> = {
      ...(identityProfile as unknown as Record<string, unknown>),
    };
    delete lshIdentityProfile.screen;
    const identityHardwareFingerprint =
      typeof requestBody.hardwareFingerprint === 'string' &&
      requestBody.hardwareFingerprint.trim().length > 0
        ? requestBody.hardwareFingerprint.trim()
        : typeof identityProfile.hardwareFingerprint === 'string' &&
          identityProfile.hardwareFingerprint.trim().length > 0
        ? identityProfile.hardwareFingerprint.trim()
        : hardwareId;
    const identityBrowserFingerprint =
      typeof requestBody.browserFingerprint === 'string' &&
      requestBody.browserFingerprint.trim().length > 0
        ? requestBody.browserFingerprint.trim()
        : typeof identityProfile.browserFingerprint === 'string'
        ? identityProfile.browserFingerprint.trim()
        : '';
    const identitySessionId =
      typeof requestBody.sessionId === 'string' && requestBody.sessionId.trim().length > 0
        ? requestBody.sessionId.trim().slice(0, 80)
        : currentSessionId;
    const storageHealed = Boolean(requestBody.storageHealed);
    const isMobileIos =
      browserDevice.deviceKind !== 'pc' &&
      /ios|iphone|ipad|ipod/i.test(`${browserDevice.os} ${browserDevice.platform}`);

    // Persist the canonical visitor's profile before resolving, so the storage path and the
    // blocking index both point at the ID this request is actually using. A brand-new visitor
    // never runs the resolver's "fresh identity" branch (it would mint a second ID).
    let resolvedIdentity: ResolveVisitorResult = {
      visitor_id: visitorId,
      match_mode: 'none',
      match_score: 0,
      is_new: !existingVisitor,
      isNew: !existingVisitor,
      confidence_hint: 0,
      healed: false,
      reasons: [],
    };
    try {
      // Idempotent: existing deployments get the identity tables on first request even if
      // the process booted before this schema version.
      ensureIdentitySchema(db);
      markSchemaMigration(db, 'v4-canonical-identity');
      upsertVisitorProfile(db, visitorId, identityProfile, identityHardwareFingerprint, nowUtc);
      upsertBlocks(db, visitorId, blockKeysFor(identityProfile), nowUtc);
      // 512-bit SimHash over the canonical identity profile. Bands are written only when the
      // hardware anchor actually changes, never on a routine repeat visit.
      const anchorHash = simhash512(lshIdentityProfile);
      const anchorHashHex = simhashToHex(anchorHash);
      // distinct_storage_seeds_count: a single storage seed cannot safely merge on hardware.
      const existingAnchor = db
        .prepare('SELECT distinct_storage_seeds_count FROM hardware_anchors WHERE hardware_id = ?')
        .get(identityHardwareFingerprint) as { distinct_storage_seeds_count?: number } | undefined;
      const distinctSeeds = Math.max(
        1,
        Number(existingAnchor?.distinct_storage_seeds_count ?? 0) + (existingVisitor || verifiedVid ? 1 : 0)
      );
      writeHardwareAnchorAndBands(
        db,
        identityHardwareFingerprint,
        visitorId,
        anchorHashHex,
        nowUtc,
        distinctSeeds
      );
      if (existingVisitor || verifiedVid) {
        resolvedIdentity = await resolveVisitor(db, {
          profile: identityProfile,
          storageVisitorId: verifiedVid ?? null,
          isMobileIos,
        });
      }
    } catch {
      // Identity persistence is additive: a failure must never fail the visitor response.
    }
    let visitorFound = Boolean(existingVisitor) || !resolvedIdentity.is_new;

    const identityConfidence = scoreConfidence({
      match_mode: resolvedIdentity.match_mode,
      match_score: resolvedIdentity.match_score,
      storage_healed: storageHealed || resolvedIdentity.healed,
      incognito: securitySignals.isIncognito,
      isMobileIos,
      firstSeenDesktop: !isReturning,
      consistencyFlags: resolvedIdentity.reasons,
      rfpOrTor:
        Boolean(securitySignals.torExitNode) || Boolean(securitySignals.isTorBrowserClient),
      genuineSpoof: botVerdict === 'bad' && botInfo?.identity === 'spoofed',
    });
    const identityConsistencyFlags = Array.from(new Set(resolvedIdentity.reasons));
    const identityConsistency = {
      score: Math.max(
        0,
        Math.min(100, Math.round(identityConfidence.score * 100) - identityConsistencyFlags.length * 10)
      ),
      spoof_likelihood: identityConfidence.spoof_likelihood,
      flags: identityConsistencyFlags,
      agent_verdict: String(
        securitySignals.botSubtype || (securitySignals.isBot ? 'automated' : 'human')
      ),
    };

    /* ------------------------------------------------------------------ */
    /* Phase 6 — canonical telemetry envelope (one shape, no parallel math) */
    /* ------------------------------------------------------------------ */
    const eventId = safePageLoadId;
    const collectorInspectorProbes =
      clientExtras.inspectorProbes && typeof clientExtras.inspectorProbes === 'object'
        ? (clientExtras.inspectorProbes as Record<string, unknown>)
        : {};
    const collectorInteractionEvidence = Array.isArray(clientExtras.interactionEvidence)
      ? (clientExtras.interactionEvidence as unknown[])
          .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
          .map((item) => item.trim().slice(0, 160))
          .slice(0, 24)
      : [];
    rememberPassiveVisit({
      eventId,
      visitorId,
      createdAtMs: Date.now(),
      bot: botVerdict,
      tamperingDetected: Boolean(
        reconciledTampering.detected || securitySignals.tamperedRequest
      ),
      corroborated: false,
    });
    // Single inspector verdict, resolved once by resolveInspectorState() and mirrored verbatim.
    const inspectorState = earlyInspector.inspector_state;
    const inspectorFlags = {
      cdp_attached: earlyInspector.cdp_attached,
      developer_tools: earlyInspector.developer_tools,
    };
    const inspectorDetail = earlyInspector.detail;
    if (inspectorFlags.cdp_attached !== (inspectorState === 'automation_protocol_attached')) {
      console.error('[invariant] inspector CDP parity violation', { inspectorState, inspectorFlags });
    }
    const automationVerdict =
      securitySignals.isBot || botVerdict === 'bad' || hardAutomationSignals
        ? 'automated'
        : securitySignals.botSubtype === 'human' || botVerdict === 'not_detected'
        ? 'human'
        : 'uncertain';
    // Human corroboration comes only from an envelope-backed client signal OR real recorded
    // interaction on that signed session — a clean person is never pinned at 0 merely because
    // the numeric score landed under 0.5. decideVerdictTier still forces 0 on every automated /
    // tampered session, so a bot inherits nothing.
    const humanCorroborationClaim: 0 | 1 =
      trustedHumanCorroboration >= 0.5 || hasTrustedInteractionEvidence ? 1 : 0;
    const verdictState = decideVerdictTier({
      automation: automationVerdict as 'human' | 'uncertain' | 'automated',
      tamperingDetected: reconciledTampering.detected || Boolean(securitySignals.tamperedRequest),
      humanCorroboration: humanCorroborationClaim,
      hasInteractionEvidence:
        collectorInteractionEvidence.length > 0 || trustedHumanCorroboration >= 0.5,
    });
    // An unverified UA-only agent/automation CLAIM must never be labelled "Verified Automation"
    // next to identity:'unknown'. Only hard artifacts or a cryptographically verified RFC 9421
    // agent earn the "Verified Automation" tier; an unverified claim is reported honestly.
    const unverifiedAutomationClaim = Boolean(
      verdictState.verdict_tier === 'Verified Automation' &&
        botVerdict === 'bad' &&
        !hardAutomationSignals &&
        !rfc9421SignedAgent &&
        botInfo?.identity !== 'signed' &&
        botInfo?.identity !== 'verified'
    );
    const effectiveVerdictTier: VerdictTier = unverifiedAutomationClaim
      ? ('Unverified Automation Claim' as VerdictTier)
      : verdictState.verdict_tier;

    const identityStage = resolveIdentityStage({
      storageVisitorId: verifiedVid || storedVisitorId,
      storageValid: Boolean(existingVisitor || verifiedVid),
      exactHardwareId: hardwareId,
      distinctStorageSeedsCount: existingVisitor || verifiedVid ? 2 : 1,
      privacyHardened,
      query: simhash512(lshIdentityProfile),
      candidates: retrieveLshCandidates(db, lshIdentityProfile),
    });

    // Recognition honesty — resolved BEFORE any hardware / LSH adoption so the corroboration
    // gate can refuse to mint a returning visitor out of a cross-cloud collision. A hardware-only
    // anchor is not a verified "Returning Device" unless independent axes agree: browser family,
    // platform/OS family and the matched visitor's ASN history. In a homogeneous cloud/headless
    // container with software rendering even structural matches are collision-prone, so the
    // label is downgraded to "possible hardware match" at <= 0.6 confidence. A stable
    // first-party-cookie / persistent-profile return is never hardware-only and is untouched.
    const hardwareOnlyMatch =
      rejectedHardwareOnlyMatch ||
      identityStage.stage === 'lsh_fuzzy' ||
      recognitionSource === 'Hardware Fingerprint (Cookie-less / Incognito)';
    const browserFamilyCorroborated = Boolean(
      serverBrowserFamily && clientBrowserFamily && serverBrowserFamily === clientBrowserFamily
    );
    const osFamilyCorroborated = Boolean(
      serverOsFamily && clientOsFamily && serverOsFamily === clientOsFamily
    );
    // Corroborate against the visitor we would actually adopt (the LSH candidate, or the
    // storage-less hardware hit), not against a cookie visitor that may not exist here.
    const corroboratingVisitorId =
      identityStage.stage === 'lsh_fuzzy' && identityStage.visitorId
        ? String(identityStage.visitorId)
        : existingVisitor?.visitor_id ?? null;
    // A storage-less / hardware-only return needs THREE independent axes to agree: browser
    // family, OS family AND the candidate's ASN history (hardwareOnlyMatchCorroborated), plus at
    // least 3 structural anchors with one hard anchor (structuralAnchorsMatch). Stable first-
    // party cookie returns are not hardware-only and are deliberately exempt from this gate.
    const structuralAnchorsCorroborated = !hardwareOnlyMatch
      ? true
      : Boolean(
          corroboratingVisitorId &&
            structuralAnchorsMatch(
              db,
              identityProfile,
              corroboratingVisitorId,
              identityHardwareFingerprint
            ).matched
        );
    const recognitionCorroborated = Boolean(
      browserFamilyCorroborated &&
        osFamilyCorroborated &&
        corroboratingVisitorId &&
        structuralAnchorsCorroborated &&
        hardwareOnlyMatchCorroborated(
          db,
          corroboratingVisitorId,
          serverBrowserFamily || clientBrowserFamily,
          serverOsFamily || clientOsFamily,
          location.asn
        )
    );
    const softwareRenderedEnvironment = Boolean(
      specAssessment.software_renderer ||
        /swiftshader|llvmpipe|softpipe|software|masked|unavailable/i.test(
          String(hardwareSignals.gpuRenderer || '') + ' ' + String(hardwareSignals.gpuVendor || '')
        )
    );
    const homogeneousContainer =
      softwareRenderedEnvironment && (hostingDatacenter || Boolean(securitySignals.isHeadless));
    const downgradeRecognition = hardwareOnlyMatch && (!recognitionCorroborated || homogeneousContainer);

    // A probabilistic fuzzy match must supply the final visitor ID. When a screen/DPR change makes
    // blockKeysFor miss, an earlier lookup mints a fresh ID while the envelope still reports
    // "Probabilistic Fuzzy Match". Adopt the matched hardware anchor's canonical visitor so the
    // returned identity agrees with its telemetry. The locked distinct_storage_seeds_count < 2
    // guard is preserved: a single-seed anchor is safe, while a multi-seed (shared hardware class)
    // anchor can never become canonical through this path.
    // A genuinely fresh context (no cookie / storage token / signed backup and no exact hardware
    // anchor hit) must not silently adopt an old visitor from a probabilistic LSH match alone.
    const freshUnanchoredContext =
      !existingVisitor && !verifiedVid && !storageVerified && !existingHwidVisitor;
    if (
      identityStage.stage === 'lsh_fuzzy' &&
      identityStage.visitorId &&
      identityStage.visitorId !== visitorId &&
      identityStage.visitorId !== identityStage.matchLabel
    ) {
      try {
        // The matched candidate now carries the canonical visitor id directly. `matchLabel` is
        // kept only for envelope telemetry. The guard still reads the locked anchor seed count.
        const fuzzyAnchor = db
          .prepare(
            'SELECT MAX(distinct_storage_seeds_count) AS max_seeds FROM hardware_anchors WHERE visitor_id = ?'
          )
          .get(identityStage.visitorId) as { max_seeds?: number } | undefined;
        const structuralMatch = freshUnanchoredContext
          ? structuralAnchorsMatch(
              db,
              identityProfile,
              String(identityStage.visitorId),
              identityHardwareFingerprint
            )
          : null;
        if (
          fuzzyAnchor &&
          Number(fuzzyAnchor.max_seeds ?? 0) < 2 &&
          (!freshUnanchoredContext || Boolean(structuralMatch?.matched)) &&
          // A hardware-only / LSH anchor may adopt another visitor's id only when the
          // browser + OS + ASN-history axes agree, and never inside a homogeneous
          // software-rendered cloud container.
          recognitionCorroborated &&
          !homogeneousContainer
        ) {
          // The visit row was already inserted under the freshly minted ID earlier in this
          // request. Re-key it to the recovered visitor so history/velocity and the response
          // agree; otherwise the dashboard shows a new ID with an empty visit history.
          const provisionalVisitorId = visitorId;
          visitorId = String(identityStage.visitorId);
          visitorToken = signVisitorId(visitorId);
          isReturning = true;
          visitorFound = true;
          try {
            db.prepare(
              'UPDATE visits SET visitor_id = ? WHERE visitor_id = ? AND page_load_id = ?'
            ).run(visitorId, provisionalVisitorId, safePageLoadId);
            db.prepare(
              `UPDATE visitors
               SET hardware_id = ?, active_session_id = ?, last_activity_utc = ?, updated_at_utc = ?
               WHERE visitor_id = ?`
            ).run(hardwareId, currentSessionId, nowUtc, nowUtc, visitorId);
          } catch {
            // Best-effort re-key: the response still reports the recovered identity.
          }
          resolvedIdentity = {
            ...resolvedIdentity,
            visitor_id: visitorId,
            is_new: false,
            isNew: false,
          };
        }
      } catch {
        // Best effort: a failed anchor lookup must never fail or change the visitor response.
      }
    }

    // The honest identity-confidence wrapper is fed the *real* resolver evidence: match stage,
    // resolver match score, structural-anchor agreement, distinct storage-seed count,
    // browser/OS family consensus and storage validity. Its finite score is the single
    // authoritative value; the deterministic scoreConfidence result is only the fallback.
    const storageValidForConfidence = Boolean(existingVisitor || verifiedVid);
    const hardwareMatchForConfidence = identityStage.stage === 'exact_hardware';
    const probabilisticMatchForConfidence = identityStage.stage === 'lsh_fuzzy';
    const matchScoreForConfidence = Number.isFinite(resolvedIdentity.match_score)
      ? resolvedIdentity.match_score
      : 0;

    let distinctStorageSeedsForConfidence = storageValidForConfidence ? 2 : 1;
    try {
      const anchorSeeds = db
        .prepare('SELECT distinct_storage_seeds_count FROM hardware_anchors WHERE hardware_id = ?')
        .get(identityHardwareFingerprint) as { distinct_storage_seeds_count?: number } | undefined;
      if (anchorSeeds && Number.isFinite(Number(anchorSeeds.distinct_storage_seeds_count))) {
        distinctStorageSeedsForConfidence = Math.max(1, Number(anchorSeeds.distinct_storage_seeds_count));
      }
    } catch {
      // Best effort: the resolver-consistent fallback above is already honest.
    }

    const TOTAL_IDENTITY_ANCHORS = 7;
    let matchedAnchorsForConfidence = storageValidForConfidence ? TOTAL_IDENTITY_ANCHORS : 0;
    if (corroboratingVisitorId) {
      const anchorEvidence = structuralAnchorsMatch(
        db,
        identityProfile,
        corroboratingVisitorId,
        identityHardwareFingerprint
      );
      // structuralAnchorsMatch compares 7 stable anchor pairs; an exact stored hardware
      // fingerprint counts as a full (1.0) anchor agreement.
      matchedAnchorsForConfidence = anchorEvidence.reasons.some((reason) =>
        reason.includes('hardware fingerprint')
      )
        ? TOTAL_IDENTITY_ANCHORS
        : Math.min(TOTAL_IDENTITY_ANCHORS, anchorEvidence.reasons.length);
    }
    const structuralAnchorRatioForConfidence =
      matchedAnchorsForConfidence / TOTAL_IDENTITY_ANCHORS;
    const profileAgeDaysForConfidence = (() => {
      const firstMs = Date.parse(statistics.firstVisitUtc);
      if (!Number.isFinite(firstMs)) return 0;
      return Math.max(0, Math.floor((Date.now() - firstMs) / 86_400_000));
    })();

    const honestConfidenceInput: ResolverBackedHonestConfidenceInput = {
      labeledPairs: Number(rawExtras.calibrationLabeledPairs ?? 0),
      heldOutEce: Number(rawExtras.calibrationHeldOutEce ?? 1),
      matchStage: identityStage.stage,
      // All six weighted evidence components (tier base, match score, anchor ratio, storage
      // seeds, browser consensus, OS consensus) are supplied explicitly and auditable.
      match_tier: identityStage.stage,
      calibratedScore: identityConfidence.score,
      matchScore: matchScoreForConfidence,
      match_score: matchScoreForConfidence,
      match_mode: resolvedIdentity.match_mode,
      structural_anchor_ratio: structuralAnchorRatioForConfidence,
      structuralAnchorRatio: structuralAnchorRatioForConfidence,
      matched_anchors: matchedAnchorsForConfidence,
      total_anchors: TOTAL_IDENTITY_ANCHORS,
      storageHealed: Boolean(storageHealed || resolvedIdentity.healed),
      visitContinuity: statistics.totalVisits,
      profileAgeDays: profileAgeDaysForConfidence,
      distinct_storage_seeds_count: distinctStorageSeedsForConfidence,
      distinctStorageSeedsCount: distinctStorageSeedsForConfidence,
      browser_family_consensus: browserFamilyCorroborated,
      browserFamilyConsensus: browserFamilyCorroborated,
      os_family_consensus: osFamilyCorroborated,
      osFamilyConsensus: osFamilyCorroborated,
      storage_valid: storageValidForConfidence,
      storageValid: storageValidForConfidence,
      storage_healed: storageHealed || resolvedIdentity.healed,
      incognito: securitySignals.isIncognito,
      isMobileIos,
      firstSeenDesktop: !isReturning,
      consistencyFlags: resolvedIdentity.reasons,
      rfpOrTor: Boolean(securitySignals.torExitNode) || Boolean(securitySignals.isTorBrowserClient),
      genuineSpoof: botVerdict === 'bad' && botInfo?.identity === 'spoofed',
    };
    // The shared signature is owned by another module; this cast keeps the call compatible with
    // both the current and the resolver-backed signature without duplicating its scoring math.
    const honestConfidenceSeed = computeHonestIdentityConfidence(
      honestConfidenceInput as unknown as Parameters<typeof computeHonestIdentityConfidence>[0]
    );

    const deterministicConfidenceScore = Math.max(0, Math.min(1, identityConfidence.score));
    // Honest-calibration invariant: a genuinely new/unenrolled profile (no storage AND no
    // hardware/fuzzy anchor) has no evidence for a numeric probability and stays `null`.
    const genuinelyNewProfile =
      !storageValidForConfidence && !hardwareMatchForConfidence && !probabilisticMatchForConfidence;
    // Caps expressed exactly once: probabilistic/ambiguous matches are capped at 0.6; verified
    // first-party-cookie and exact-hardware returning visits keep their real score.
    const capsAtZeroSix = probabilisticMatchForConfidence || downgradeRecognition;
    let finalIdentityConfidenceScore: number | null = null;
    if (!genuinelyNewProfile) {
      const seeded =
        typeof honestConfidenceSeed.confidence_score === 'number' &&
        Number.isFinite(honestConfidenceSeed.confidence_score)
          ? honestConfidenceSeed.confidence_score
          : deterministicConfidenceScore;
      const clamped = Math.max(0, Math.min(1, seeded));
      finalIdentityConfidenceScore = capsAtZeroSix ? Math.min(0.6, clamped) : clamped;
    }

    const identityConfidenceHonest = {
      ...honestConfidenceSeed,
      confidence_score: finalIdentityConfidenceScore,
      // No held-out calibration gate has passed: the numeric value is observable evidence
      // strength, never a probability. The human-facing label says "Match evidence", not
      // "Confidence"/probability.
      calibration_status: 'uncalibrated' as const,
      confidence_label: confidenceLabel(finalIdentityConfidenceScore, false),
      ...(downgradeRecognition
        ? { confidence_tier: 'Shared Hardware Class - Ambiguous' as const }
        : {}),
    };

    // A downgraded storage-less cloud / hardware-class collision must never be reported as a
    // verified returning device (this also clears the UI's "Returning Device" chip).
    if (downgradeRecognition) {
      isReturning = false;
    }
    const recognitionLabel = downgradeRecognition
      ? 'possible hardware match'
      : 'returning device';

    const networkOwnership: 'residential_isp' | 'mobile_carrier' | 'hosting_datacenter' | 'enterprise' | 'unknown' =
      hostingDatacenter
        ? 'hosting_datacenter'
        : /cellular|mobile|5g|carrier/i.test(networkTypeLabel)
        ? 'mobile_carrier'
        : /enterprise|business/i.test(networkTypeLabel)
        ? 'enterprise'
        : /broadband|residential|consumer/i.test(networkTypeLabel)
        ? 'residential_isp'
        : 'unknown';
    // vpn_confidence is high only for a confirmed Tor exit list hit or a verified Layer-4 relay
    // signal. A timezone mismatch alone is contextual and can never reach high.
    const vpnConfidence: 'low' | 'medium' | 'high' = isTorExit || torStatus.isRelay
      ? 'high'
      : vpnOrRelay && Array.isArray(securitySignals.vpnReasons) && securitySignals.vpnReasons.length > 1
      ? 'medium'
      : vpnOrRelay
      ? 'low'
      : 'low';
    const asnOrg = String(normalizeAsnLabel(location.asn) || location.org || '');
    const cachedRdapOrg = persistRdapNetblockOrg(db, String(location.asn || ''), asnOrg);
    const rdapNetblockOrg =
      typeof rawExtras.rdapNetblockOrg === 'string' && rawExtras.rdapNetblockOrg
        ? rawExtras.rdapNetblockOrg
        : cachedRdapOrg;
    const netblockReassignmentMismatch = Boolean(
      rdapNetblockOrg &&
        asnOrg &&
        rdapNetblockOrg.toLowerCase() !== asnOrg.toLowerCase() &&
        !asnOrg.toLowerCase().includes(rdapNetblockOrg.toLowerCase())
    );

    const geolocationPermission =
      typeof rawExtras.geolocationPermission === 'string' ? rawExtras.geolocationPermission : 'prompt';
    const grantedCoords =
      rawExtras.grantedGeolocation &&
      typeof rawExtras.grantedGeolocation === 'object' &&
      typeof (rawExtras.grantedGeolocation as Record<string, unknown>).latitude === 'number' &&
      typeof (rawExtras.grantedGeolocation as Record<string, unknown>).longitude === 'number'
        ? (rawExtras.grantedGeolocation as { latitude: number; longitude: number })
        : null;
    const honestProximity = computeHonestProximity({
      permission: geolocationPermission,
      accuracyM: typeof rawExtras.geolocationAccuracyM === 'number' ? rawExtras.geolocationAccuracyM : undefined,
      grantedCoordinates: grantedCoords,
    });

    // The published rarity gates come straight from decideRarity / clopperPearsonUpperBound.
    const rarityDecision = decideRarity(rarityReport.sampleSize, rarityReport.matching);
    const rarityUpper = clopperPearsonUpperBound(
      rarityReport.matching,
      rarityReport.sampleSize,
      0.05
    );
    const edgeTransport = readEdgeTransport(req);
    // Additive shadow mirrors — verbatim pass-through only. None of these values are read back
    // into the 0-10 headline, the 0-100 graded ledger, the verdict tier, isBot or auth.
    const shadowProxyDetails =
      (securitySignals as SecuritySignals & { proxy_details?: ProxyDetails }).proxy_details ?? null;
    const shadowVpnMethods = securitySignals.vpnMethods ?? null;
    const invariantEnvelope = {
      event_id: eventId,
      identity: {
        match_stage: identityStage.stage,
        match_label: identityStage.matchLabel,
        collision_risk: identityStage.collisionRisk,
        confidence_tier: identityConfidenceHonest.confidence_tier,
        confidence_score: identityConfidenceHonest.confidence_score,
        calibration_status: identityConfidenceHonest.calibration_status,
        // Evidence label only — no probability language until a calibration gate passes.
        confidence_label: identityConfidenceHonest.confidence_label,
      },
      server_verified: {
        browser: serverVerifiedBrowser,
        os: serverVerifiedOs,
        cf_transport: edgeTransport,
        agent_proof_method: agentProofMethod,
      },
      client_claimed: {
        browser: browserDevice.browser,
        os: browserDevice.os,
      },
      reconciled_display: {
        browser: serverVerifiedBrowser,
        os: serverVerifiedOs,
      },
      automation: {
        bot: botVerdict === 'not_detected' ? 'not_detected' : botVerdict,
        // Derived from the exact same verdict as the top-level / securitySignals mirrors.
        isBot: canonicalIsBot,
        bot_type: botType,
        named_operator: rfc9421SignedAgent ? aiAgent?.operator || null : null,
        operator_verification_method: agentProofMethod,
        automation_environment: String(rawSecuritySignals?.automationEnvironment || 'none'),
        // Client post-interaction corroboration, clamped / finite-checked and envelope-gated;
        // decideVerdictTier already pins it to 0 on automated / tampered sessions.
        human_corroboration: verdictState.human_corroboration,
        // Collector's passive, isTrusted interaction evidence — mirrored verbatim; it never
        // promotes a probe to proof on its own.
        interaction_evidence: collectorInteractionEvidence,
        inspector_probes: collectorInspectorProbes,
        inspector_state: inspectorState,
        cdp_attached: inspectorFlags.cdp_attached,
        // Explicit explanation for a bare CDP bridge so `cdp_attached: true` can never be
        // misread as "DevTools open" (which stays false for automation_protocol_attached).
        inspector_detail: inspectorDetail,
        // Single resolved value: any DevTools / IDE / docked attach (including a weak runtime
        // leak) sets this true, while a bare CDP protocol binding stays on the cdp_attached axis.
        developer_tools: inspectorFlags.developer_tools,
      },
      tampering: {
        detected: reconciledTampering.detected || effectiveTamperingDetected,
        anti_detect_browser: Boolean(rawSecuritySignals?.tamperingDetails?.anti_detect_browser),
        privacy_hardened: privacyHardened,
        tampering_confidence: tamperingAssessment?.confidence || 'high',
        tampering_ml_score: tamperingAssessment?.mlScore || 0,
        spec_violations: specAssessment.hardViolations,
        reasons: Array.from(new Set([...reconciledTampering.reasons, ...tamperingFactorReasons])),
        hard_spec_violation: reconciledTampering.hard_spec_violation,
      },
      network: {
        network_ownership: networkOwnership,
        bgp_asn: location.asn && location.asn !== 'Unknown' ? location.asn : null,
        bgp_asn_org: asnOrg || null,
        rdap_netblock_org: rdapNetblockOrg,
        netblock_reassignment_mismatch: netblockReassignmentMismatch,
        vpn: vpnOrRelay,
        vpn_confidence: vpnConfidence,
        proxy: rotatingProxy,
        proxy_type: rotatingProxy ? 'residential_rotating' : isProxyOrVpn ? 'datacenter' : 'none',
        timezone_mismatch: timezoneMismatch,
      },
      environment: {
        software_renderer: swiftshader,
        // SwiftShader is software rendering only (f7d6900) — never hard VM proof, never tampering.
        software_renderer_label: swiftshader
          ? `Software-rendered: ${hardwareSignals.gpuRenderer || 'SwiftShader'}`
          : null,
        ephemeral_storage: ephemeralStorage,
        virtual_machine_label: securitySignals.isVirtualMachine ? securitySignals.vmReason || 'Virtual Machine' : null,
      },
      proximity: honestProximity,
      rarity: {
        corpus_n: rarityDecision.corpus_n,
        prevalence_ci95_upper: rarityUpper,
        percentile: rarityDecision.percentile,
        status: rarityDecision.status,
      },
      velocity: velocityReport.velocity,
      risk: riskLedger,
      verdict_tier: effectiveVerdictTier,
      // Additive incognito diagnostics — verbatim, flag-gated pass-through (never scored).
      ...(diagnostics ? { diagnostics } : {}),
      // Additive shadow truth mirrors. proxy_details / vpn_methods match the shapes the
      // dashboard adapter already reads; the zero-trust and fingerprint blocks are diagnostics
      // only (strict-origin is opt-in and never enforced here).
      proxy_details: shadowProxyDetails,
      vpn_methods: shadowVpnMethods,
      zero_trust: zeroTrustShadow,
      network_fingerprint_truth: networkFingerprintShadow,
    } as unknown as CanonicalTelemetryEnvelope;

    const payload: IntelVisitorResponse & {
      envelope: CanonicalTelemetryEnvelope;
      verdict_tier: VerdictTier;
      human_corroboration: 0 | 1;
      raw_score: number;
      score_0_100: number;
      evidence_ledger: OrthogonalRiskLedger['evidence_ledger'];
      /** Honest recognition mirror: "possible hardware match" vs "returning device". */
      recognitionLabel: string;
      recognitionCorroborated: boolean;
      /** Canonical bot flag — always `bot !== 'not_detected'`. */
      isBot: boolean;
      /** Inspector axes mirrored from the envelope so the identify response is self-contained. */
      cdp_attached: boolean;
      inspector_state: InspectorState;
      inspector_detail: string;
      /** Which high-activity rule produced `highActivityDevice`. */
      highActivityThresholdMode: 'fixed_small_corpus' | 'p98';
      highActivityThreshold: number;
      /** Additive shadow truth mirrors — verbatim, never scored or enforced. */
      proxy_details: ProxyDetails | null;
      vpn_methods: unknown;
      zero_trust: unknown;
      network_fingerprint_truth: unknown;
    } = {
      visitorId,
      visitorToken,
      hardwareId,
      isReturning,
      recognitionSource,
      // Recognition honesty mirror for the UI: "possible hardware match" when an LSH /
      // hardware-only anchor lacks browser + OS + ASN-history corroboration (or sits in a
      // software-rendered cloud container), otherwise "returning device".
      recognitionLabel,
      recognitionCorroborated,
      location,
      // Phase 6 — proximity is permission-gated. IP coordinates are never proximity evidence;
      // the canonical envelope and this mirror share the same honest result.
      proximity: honestProximity as unknown as import('./src/lib/geohash').ProximityInfo,
      // Fix 8 — structured bot & AI agent identification ("Robodex" + BotD).
      bot: botVerdict,
      bot_type: botType,
      bot_info: botInfo,
      browserDevice,
      // Server-normalized UA / client-hints identity. `os` is the family only and the
      // version lives in `os_version`; `browser_details` mirrors the event contract so
      // `browser_major_version` is never empty when a full version is known.
      os: uaIdentity.os,
      os_version: uaIdentity.osVersion,
      browser_details: {
        browser_name: uaIdentity.browserName,
        browser_full_version: uaIdentity.browserFullVersion,
        browser_major_version: uaIdentity.browserMajorVersion,
        os: uaIdentity.os,
        os_version: uaIdentity.osVersion,
        device: uaIdentity.device,
        device_model:
          uaIdentity.model || browserDevice.reportedModel || browserDevice.phoneModel || '',
      },
      hardwareSignals,
      securitySignals,
      statistics,
      visitHistory,
      historyBackup,
      // Top-level mirrors so clients can read the 4-signal verdict without digging.
      isIncognito: securitySignals.isIncognito,
      incognito: securitySignals.isIncognito,
      // Additive, flag-gated console diagnostics — inert pass-through, never scored.
      ...(diagnostics ? { diagnostics } : {}),
      suspectScore: securitySignals.suspectScore,
      riskLevel: securitySignals.riskLevel,
      riskBadgeText: securitySignals.riskBadgeText,
      smartSignals: securitySignals.smartSignals,
      // API v4 mirrors: 0-100 calibrated composite, velocity windows and device rarity.
      suspectScore100,
      velocity: velocityReport.velocity,
      highActivityDevice,
      highActivityThresholdMode,
      highActivityThreshold,
      // Single-source-of-truth bot flag + inspector axes mirrored from the canonical envelope.
      isBot: canonicalIsBot,
      cdp_attached: inspectorFlags.cdp_attached,
      inspector_state: inspectorState,
      rareDevice: rarityReport.rareDevice,
      rareDevicePercentileBucket: rarityReport.bucket,
      tampering: effectiveTamperingDetected,
      tamperingConfidence: tamperingAssessment?.confidence ?? 'high',
      tamperingDetails: tamperingFactorReasons.length
        ? {
            anomaly_score: tamperingAssessment?.details?.anomaly_score ?? 0,
            anti_detect_browser: Boolean(tamperingAssessment?.details?.anti_detect_browser),
            devtools_device_emulation: Boolean(
              tamperingAssessment?.details?.devtools_device_emulation
            ),
            reasons: Array.from(
              new Set([
                ...(tamperingAssessment?.details?.reasons ?? []),
                ...tamperingFactorReasons,
              ])
            ),
          }
        : tamperingAssessment?.details,
      activeCall,
      activeCallSupported,
      rawDeviceAttributes: rawSecuritySignals?.rawDeviceAttributes ?? null,
      // Tri-layer identity: canonical visitor ID plus the resolver's match evidence. The
      // resolver never replaces the canonical ID here — it only reports mode/score and,
      // for cross-browser stitches, a supplementary link.
      identity_layers: {
        visitor_id: visitorId,
        hardware_fingerprint: identityHardwareFingerprint,
        browser_fingerprint: identityBrowserFingerprint,
        session_id: identitySessionId,
        storage_healed: storageHealed || resolvedIdentity.healed,
        match_mode: resolvedIdentity.match_mode,
        match_score: resolvedIdentity.match_score,
        visitor_found: visitorFound,
        supplementary_visitor_id: resolvedIdentity.supplementary?.visitor_id,
        supplementary_confidence: resolvedIdentity.supplementary?.confidence_hint,
      },
      identification: {
        confidence: {
          // Mirror the exact honest/envelope value so both top-level and canonical views agree.
          // The legacy type declares `number`; the cast preserves the runtime value (including
          // `null` for genuinely new profiles) without editing a type owned by another module.
          score: identityConfidenceHonest.confidence_score as number,
          version: identityConfidence.version,
          calibration_status: identityConfidenceHonest.calibration_status,
          confidence_label: identityConfidenceHonest.confidence_label,
        } as unknown as { score: number; version: string },
        visitor_found: visitorFound,
        tampering: identityConfidence.tampering,
        spoof_likelihood: identityConfidence.spoof_likelihood,
      },
      consistency: identityConsistency,
      // Phase 4 verdicts mirrored at the top level. A duplicate nonce is reported as
      // `replayed: true` inside a normal 200 payload — it is never an HTTP error that
      // would break the in-page Record Visit / Analyze button.
      replayed: envelopeVerdict.replayDetected,
      tampered: envelopeVerdict.tamperedRequest,
      requestIntegrityReason: envelopeVerdict.requestIntegrityReason,
      // Additive shadow truth mirrors — the exact same references carried in the envelope.
      proxy_details: shadowProxyDetails,
      vpn_methods: shadowVpnMethods,
      zero_trust: zeroTrustShadow,
      network_fingerprint_truth: networkFingerprintShadow,
      // Phase 3–6 canonical mirrors. The single envelope above is the source of truth; these
      // top-level mirrors keep existing clients working without any parallel scoring math.
      envelope: invariantEnvelope,
      verdict_tier: effectiveVerdictTier,
      human_corroboration: verdictState.human_corroboration,
      /** Human-readable inspector explanation (mirrors envelope.automation.inspector_detail). */
      inspector_detail: inspectorDetail,
      raw_score: riskLedger.raw_score,
      score_0_100: riskLedger.score_0_100,
      evidence_ledger: riskLedger.evidence_ledger,
    };

    res.json(payload);
  } catch (err) {
    console.error('Error in /api/visitor/identify:', err);
    res.status(500).json({ error: 'Unable to process visitor identification request.' });
  }
});

/**
 * Phase 3 — lightweight, non-blocking corroboration update tied to event_id.
 * Upgrades human_corroboration 0 -> 1 ONLY when the stored visit is `bot === "not_detected"`,
 * `tampering.detected === false`, the visitor token is valid, the visit row exists, and the
 * event is still inside the 65-second sealed-envelope freshness window.
 */
app.post('/api/visitor/corroborate', identifyRateLimit, (req, res) => {
  try {
    const body = (req.body || {}) as { event_id?: string; visitorId?: string; visitorToken?: string };
    const eventId = typeof body.event_id === 'string' ? body.event_id.trim().slice(0, 80) : '';
    const visitorId = typeof body.visitorId === 'string' ? body.visitorId.trim() : '';
    if (!eventId || !verifyVisitorToken(visitorId, body.visitorToken)) {
      res.status(403).json({ error: 'Forbidden', human_corroboration: 0 });
      return;
    }
    const entry = corroborationLedger.get(eventId);
    if (!entry || entry.visitorId !== visitorId) {
      res.status(404).json({ error: 'Unknown event_id', human_corroboration: 0 });
      return;
    }
    const fresh = Date.now() - entry.createdAtMs <= ENVELOPE_MAX_AGE_MS;
    const storedVisit = db
      .prepare('SELECT visit_id, bot_name, risk_level FROM visits WHERE visitor_id = ? AND page_load_id = ?')
      .get(visitorId, eventId) as { visit_id: string; bot_name?: string | null; risk_level?: string | null } | undefined;
    const eligible =
      fresh &&
      Boolean(storedVisit) &&
      entry.bot === 'not_detected' &&
      !entry.tamperingDetected &&
      !entry.corroborated;
    if (eligible) {
      entry.corroborated = true;
      res.json({
        event_id: eventId,
        human_corroboration: 1,
        verdict_tier: 'Verified Human Interactive Session',
      });
      return;
    }
    res.json({
      event_id: eventId,
      human_corroboration: 0,
      verdict_tier: 'Unverified / Passive Session',
      reason: !fresh
        ? 'outside_65s_window'
        : !storedVisit
        ? 'no_stored_visit'
        : entry.bot !== 'not_detected'
        ? 'automated'
        : 'tampered',
    });
  } catch (err) {
    console.error('Error in /api/visitor/corroborate:', err);
    res.status(500).json({ error: 'Unable to process corroboration update.', human_corroboration: 0 });
  }
});

app.get('/api/visitor/history/:visitorId', (req, res) => {
  const requestedVisitorId = req.params.visitorId;
  const headerToken = req.headers['x-visitor-token'] as string | undefined;
  const cookieVid = req.cookies?.intel_http_vid as string | undefined;
  const cookieToken = req.cookies?.intel_http_token as string | undefined;

  const authorizedByHeader = verifyVisitorToken(requestedVisitorId, headerToken);
  const authorizedByCookie =
    cookieVid === requestedVisitorId && verifyVisitorToken(cookieVid, cookieToken);

  if (!authorizedByHeader && !authorizedByCookie) {
    res.status(403).json({
      error: 'Forbidden: You are not authorized to access another visitor’s records.',
    });
    return;
  }

  let rawVisits: Array<Record<string, unknown>> = [];
  try {
    rawVisits = db
      .prepare(
        `SELECT
          id, visit_id, visitor_id, session_id, visited_at_utc,
          public_ip, city, region, country, isp, org, asn,
          browser, os, device_type, screen_resolution, language, timezone,
          suspect_score, risk_level, score10, bot_name, recognition_source
         FROM visits
         WHERE visitor_id = ?
         ORDER BY visited_at_utc DESC, id DESC
         LIMIT 50`
      )
      .all(requestedVisitorId) as Array<Record<string, unknown>>;
  } catch {
    // Unreadable store (blocked daily quota): answer with an empty history, never a 500.
    rawVisits = [];
  }

  // Every row always carries suspectScore / riskLevel / recognitionSource (with safe defaults
  // for legacy rows that have no stored per-visit risk record). Task 2b — legacy 0..100
  // scores above 10 are rescaled so every response speaks the 0..10 scale.
  const visits = rawVisits.map((row) => {
    const storedScore10 =
      typeof row.score10 === 'number' && Number.isFinite(row.score10)
        ? Math.max(0, Math.min(10, Math.round(row.score10)))
        : null;
    const storedSuspectScore =
      typeof row.suspect_score === 'number' && Number.isFinite(row.suspect_score)
        ? normalizeLegacySuspectScore(row.suspect_score)
        : storedScore10 ?? 0;
    const storedRecognitionSource =
      typeof row.recognition_source === 'string' && row.recognition_source.trim()
        ? row.recognition_source
        : 'Cookie';
    const storedRiskLevel =
      row.risk_level === 'High' || row.risk_level === 'Medium' || row.risk_level === 'Low'
        ? (row.risk_level as RiskLevel)
        : null;
    const rowRiskLevel: RiskLevel =
      storedRiskLevel ??
      (storedSuspectScore >= 7 ? 'High' : storedSuspectScore >= 3 ? 'Medium' : 'Low');

    return {
      ...row,
      suspectScore: storedSuspectScore,
      score10: Math.max(0, Math.min(10, Math.round(storedSuspectScore))),
      riskLevel: rowRiskLevel,
      botName: typeof row.bot_name === 'string' && row.bot_name ? row.bot_name : undefined,
      recognitionSource: storedRecognitionSource,
    };
  });

  res.json({ visitorId: requestedVisitorId, visits });
});

/**
 * HTTP-cache identity fallback.
 *
 * The HTTP disk cache survives a cookie/localStorage/IndexedDB wipe, so a
 * conditional request can still recover the visitor id after full DOM storage
 * loss. The endpoint returns the id with a strong ETag; revalidation answers
 * 304 and the browser replays the cached body. Without an `If-None-Match`
 * presented there is nothing to revalidate, so the response is `204`.
 */
app.get('/api/intel/identity-ping', (req, res) => {
  res.setHeader('Cache-Control', 'private, max-age=0, must-revalidate');
  // Merge, never replace: clientHintsMiddleware already added `Vary: Sec-CH-UA*`, and dropping
  // it would let a shared cache serve one client's UA-CH-negotiated identity to another.
  const existingVary = res.getHeader('Vary');
  const varyValues =
    typeof existingVary === 'string'
      ? existingVary.split(',').map((item) => item.trim()).filter(Boolean)
      : [];
  for (const value of ['Cookie', 'Sec-CH-UA*']) {
    if (!varyValues.some((item) => item.toLowerCase() === value.toLowerCase())) varyValues.push(value);
  }
  res.setHeader('Vary', varyValues.join(', '));
  const presented = typeof req.headers['if-none-match'] === 'string' ? req.headers['if-none-match'] : '';
  if (presented) {
    res.setHeader('ETag', presented);
    res.status(304).end();
    return;
  }
  const cookies = (req.cookies ?? {}) as Record<string, unknown>;
  const cookieVisitor =
    (typeof cookies['_intel_vid_client'] === 'string' && cookies['_intel_vid_client'].trim()) ||
    (typeof cookies['intel_http_vid'] === 'string' && cookies['intel_http_vid'].trim()) ||
    '';
  if (!cookieVisitor) {
    res.status(204).end();
    return;
  }
  const etag = `"${crypto.createHash('sha256').update(cookieVisitor).digest('base64url')}"`;
  res.setHeader('ETag', etag);
  res.json({
    identity: {
      visitor_id: cookieVisitor,
      hardware_fingerprint: '',
      browser_fingerprint: '',
      created_at: new Date().toISOString(),
    },
  });
});

// Explicit JSON 404 for unknown API routes (instead of the SPA fallback HTML).
app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'API endpoint not found.' });
});

// Central error handler so a thrown error never leaves the serverless function
// in an undefined state (recommended by Vercel for Express apps).
app.use(
  (
    err: unknown,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction
  ) => {
    console.error('Unhandled API error:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Internal server error.' });
    }
  }
);

/* -------------------------------------------------------------------------- */
/* Runtime OS authority + user-facing text normalization                       */
/* -------------------------------------------------------------------------- */

type RuntimeOsFamily = 'linux' | 'macos' | 'windows' | 'ios' | 'android';

interface RuntimeOsVerdict {
  family: RuntimeOsFamily | null;
  label: string;
  /** True only when two independent runtime proofs agree. */
  authoritative: boolean;
  uaMismatch: boolean;
  evidence: string[];
}

function osFamilyFromText(value: string): RuntimeOsFamily | null {
  const text = String(value || '').toLowerCase();
  if (!text) return null;
  if (/iphone|ipad|ipod|ios/.test(text)) return 'ios';
  if (/android/.test(text)) return 'android';
  if (/mac ?os|macos|macintosh|\bmac\b/.test(text)) return 'macos';
  if (/windows|win32|win64|\bwin\b/.test(text)) return 'windows';
  if (/linux|ubuntu|fedora|debian|chrome ?os|\blinux\b/.test(text)) return 'linux';
  return null;
}

/**
 * Coarse, stable family keys shared by the header-mismatch verdict and the storage-less
 * hardware-match corroboration gate. Both paths must normalize browser / OS labels the same way.
 */
function osFamilyKey(value: string): string {
  const text = String(value || '').toLowerCase();
  if (!text || text === 'unknown') return '';
  if (/mac os x|macos|macintosh|\bmac\b/.test(text)) return 'macos';
  if (/iphone|ipad|ipod|ipados|\bios\b/.test(text)) return 'ios';
  if (/android/.test(text)) return 'android';
  if (/windows|win32|win64/.test(text)) return 'windows';
  if (/linux|ubuntu|fedora|debian|chrome ?os/.test(text)) return 'linux';
  return text.replace(/[^a-z0-9]/g, '');
}

function browserFamilyKey(value: string): string {
  const text = String(value || '').toLowerCase();
  if (!text || text === 'unknown') return '';
  if (/edg(e|a|ios)?\b|edge/.test(text)) return 'edge';
  if (/opera|\bopr\b/.test(text)) return 'opera';
  if (/firefox|fxios/.test(text)) return 'firefox';
  if (/crios|chrome|chromium/.test(text)) return 'chrome';
  if (/safari/.test(text)) return 'safari';
  return text.replace(/[^a-z0-9]/g, '');
}

const RUNTIME_OS_LABELS: Record<RuntimeOsFamily, string> = {
  linux: 'Linux',
  macos: 'macOS',
  windows: 'Windows',
  ios: 'iOS',
  android: 'Android',
};

/**
 * Runtime OS evidence must outrank UA / Sec-CH-UA claims. A single probe is only a claim;
 * `authoritative` requires two independent runtime proofs (host probe + WebGL backend, or
 * host probe + high-confidence math/timing probe, or two agreeing backend probes).
 */
function inferRuntimeOsVerdict(
  input: {
    hostOs?: string;
    gpuRenderer?: string;
    gpuVendor?: string;
    gpuArchFamily?: string;
    architectureSource?: string;
    engine?: string;
    architecture?: string;
  },
  uaOs: string
): RuntimeOsVerdict {
  const hostFamily = osFamilyFromText(String(input.hostOs || ''));
  const gpuText = `${input.gpuRenderer || ''} ${input.gpuVendor || ''} ${input.gpuArchFamily || ''}`.toLowerCase();
  let glFamily: RuntimeOsFamily | null = null;
  if (/direct3d|d3d ?1[12]|dxgi/.test(gpuText)) glFamily = 'windows';
  else if (/metal|apple gpu|apple m[1-9]/.test(gpuText)) glFamily = 'macos';
  else if (/mesa|llvmpipe|softpipe|gallium|\bx11\b|wayland/.test(gpuText)) glFamily = 'linux';
  else if (/android/.test(gpuText)) glFamily = 'android';
  else if (/ios|iphone|ipad/.test(gpuText)) glFamily = 'ios';

  const probeText = `${input.architectureSource || ''} ${input.engine || ''} ${input.architecture || ''}`.toLowerCase();
  const highConfidenceProbe = /high[- ]?confidence|math|timing|probe|silicon/.test(probeText);
  const probeFamily = highConfidenceProbe ? osFamilyFromText(probeText) || hostFamily : null;

  const proofs: RuntimeOsFamily[] = [];
  if (hostFamily) proofs.push(hostFamily);
  if (glFamily) proofs.push(glFamily);
  if (probeFamily) proofs.push(probeFamily);
  const counts = new Map<RuntimeOsFamily, number>();
  for (const proof of proofs) counts.set(proof, (counts.get(proof) ?? 0) + 1);
  let family: RuntimeOsFamily | null = null;
  let best = 0;
  for (const [candidate, count] of counts) {
    if (count > best || (count === best && candidate === hostFamily)) {
      family = candidate;
      best = count;
    }
  }
  const authoritative = Boolean(family && best >= 2);
  const uaFamily = osFamilyFromText(uaOs);
  return {
    family,
    label: family ? RUNTIME_OS_LABELS[family] : '',
    authoritative,
    uaMismatch: authoritative && Boolean(uaFamily && family && uaFamily !== family),
    evidence: [
      hostFamily ? `Runtime host probe: ${RUNTIME_OS_LABELS[hostFamily]}` : '',
      glFamily ? `WebGL backend: ${RUNTIME_OS_LABELS[glFamily]}` : '',
      probeFamily ? `High-confidence runtime probe: ${RUNTIME_OS_LABELS[probeFamily]}` : '',
    ].filter(Boolean),
  };
}

/** Internal storage diagnostics never reach a user-visible string. */
function humanIncognitoMethod(
  rawMethod: string | null | undefined,
  isIncognito: boolean,
  probeInconclusive: boolean
): string {
  // The collector's stable method strings map to fixed, jargon-free labels: no probe names,
  // ratios or byte figures are ever printed. The boolean verdict stays authoritative for the
  // incognito claim, so a bare method string (or a low-confidence probe) cannot manufacture one;
  // `private-storage-detected` simply resolves to the same safe label as a true verdict,
  // `standard-storage` to the normal one and `storage-check-inconclusive` to the inconclusive one.
  if (isIncognito) return 'Ephemeral / private storage detected';
  const method = String(rawMethod || '').trim().toLowerCase();
  if (probeInconclusive || method === 'storage-check-inconclusive') {
    return 'Storage probe inconclusive (treated as normal)';
  }
  return 'Persistent disk-backed storage verified';
}

function storageProbeInconclusive(method: string | null | undefined): boolean {
  return /inconclusive|fail[- ]?open|indeterminate|unknown|unavailable|low[- ]?confidence/i.test(
    String(method || '')
  );
}

/** Replaces a stale OS claim with the runtime-proven OS when runtime evidence is authoritative. */
function scrubOsClaim(text: string, runtimeOs: RuntimeOsVerdict | null): string {
  if (!runtimeOs?.authoritative || !runtimeOs.family) return String(text || '');
  const correct = RUNTIME_OS_LABELS[runtimeOs.family];
  return String(text || '').replace(/\b(macOS|Mac OS|Windows|Linux|iOS|Android)\b/gi, (match) =>
    match.toLowerCase() === correct.toLowerCase() ? match : correct
  );
}

/** Removes vague confidence language and a stale OS claim from a tile status. */
function crispBotStatus(status: string, runtimeOs: RuntimeOsVerdict | null): string {
  let value = String(status || '').trim();
  value = value
    .replace(/\s*\(?(?:low[- ]?confidence|soft signals?|heuristic|probable|possible)\)?/gi, '')
    .replace(/\s{2,}/g, ' ')
    .trim();
  value = scrubOsClaim(value, runtimeOs);
  return value || 'Automated Traffic';
}

/** UA-only verdict for the served document; no network lookups, so it never delays navigation. */
function documentBotVerdict(ua: string): { verdict: string; agent: string } {
  if (!ua) return { verdict: 'not_detected', agent: '' };
  const match = findRegistryAgent(ua);
  if (!match) {
    if (GOOD_BOT_UA_RULES.some((rule) => rule.pattern.test(ua))) return { verdict: 'good', agent: '' };
    if (AI_AGENT_UA_RULES.some((rule) => rule.pattern.test(ua))) return { verdict: 'bad', agent: '' };
    return { verdict: AUTOMATION_UA_PATTERN.test(ua) ? 'bad' : 'not_detected', agent: '' };
  }
  const agent = asLocalAgent(match);
  if (isRegistryPolicyToken(ua) || agent.policyToken === true) {
    return { verdict: 'not_detected', agent: '' };
  }
  return {
    verdict: isGoodCrawlerCategory(agent.category) ? 'good' : 'bad',
    agent: agent.displayName || '',
  };
}

function escapeHtmlAttribute(value: string): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function startStandaloneServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    // Document-visibility instrumentation: expose the registry UA verdict to crawlers and to
    // the page itself. Runs before express.static so it applies to the served index.html only
    // for GET /; the Worker bundle has its own equivalent and is untouched by this middleware.
    app.use((req, res, next) => {
      if (req.method !== 'GET' || req.path !== '/') {
        next();
        return;
      }
      const ua = String(req.headers['user-agent'] || '');
      const verdict = documentBotVerdict(ua);
      res.setHeader('X-Intel-Bot-Verdict', verdict.verdict);
      res.setHeader('X-Intel-Bot-Agent', verdict.agent);
      res.setHeader('Cache-Control', 'no-store');
      const meta = `<meta name="intel:verdict" content="${escapeHtmlAttribute(
        verdict.verdict
      )}" data-agent="${escapeHtmlAttribute(verdict.agent)}">`;
      fs.readFile(path.join(distPath, 'index.html'), 'utf8', (readError, html) => {
        if (readError || typeof html !== 'string') {
          next();
          return;
        }
        const injected = /<\/head>/i.test(html)
          ? html.replace(/<\/head>/i, `${meta}</head>`)
          : `${meta}${html}`;
        res.type('html').send(injected);
      });
    });
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Intel System running on http://0.0.0.0:${PORT}`);
  });
}

if (!IS_SERVERLESS_RUNTIME) {
  startStandaloneServer();
}

export default app;

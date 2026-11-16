/**
 * SQLite persistence for the AI bot protection engine.
 *
 * `better-sqlite3` is an OPTIONAL dependency. Nothing in this module touches it at import time:
 * the native module is loaded lazily inside `initAIBotDatabase()` and any failure falls back to a
 * small, fully functional in-memory adapter that understands the SQL emitted by this engine.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

/** A single prepared statement, compatible with better-sqlite3's positional parameter API. */
export interface AIBotStatement {
  get(...params: unknown[]): any;
  all(...params: unknown[]): any[];
  run(...params: unknown[]): { changes: number; lastInsertRowid?: number | bigint };
}

/** The adapter accepted by every module in this directory. */
export interface AIBotDatabase {
  prepare(sql: string): AIBotStatement;
  exec(sql: string): void;
  pragma(name: string, value?: string | number): unknown;
  transaction<T extends (...args: any[]) => any>(fn: T): T;
  close(): void;
}

interface NativeDatabase {
  prepare(sql: string): AIBotStatement;
  exec(sql: string): void;
  pragma(name: string, value?: string | number): unknown;
  transaction<T extends (...args: any[]) => any>(fn: T): T;
  close(): void;
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS ai_bot_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  observed_at_utc TEXT NOT NULL,
  bot_id TEXT,
  operator TEXT,
  verification_status TEXT NOT NULL,
  verification_method TEXT,
  client_ip TEXT,
  user_agent TEXT,
  request_path TEXT,
  request_method TEXT,
  http_status INTEGER,
  bytes_sent INTEGER NOT NULL DEFAULT 0,
  referrer_domain TEXT,
  referral_operator TEXT,
  robots_violation INTEGER NOT NULL DEFAULT 0,
  violated_directive TEXT,
  reasons TEXT,
  content_signal TEXT,
  edge_action TEXT
);
CREATE INDEX IF NOT EXISTS idx_bot_requests_bot ON ai_bot_requests(bot_id);
CREATE INDEX IF NOT EXISTS idx_bot_requests_status ON ai_bot_requests(verification_status);
CREATE INDEX IF NOT EXISTS idx_bot_requests_time ON ai_bot_requests(observed_at_utc);
CREATE INDEX IF NOT EXISTS idx_bot_requests_ip ON ai_bot_requests(client_ip);
CREATE INDEX IF NOT EXISTS idx_bot_requests_operator ON ai_bot_requests(operator);
CREATE INDEX IF NOT EXISTS idx_bot_requests_path ON ai_bot_requests(request_path);

CREATE TABLE IF NOT EXISTS ai_operator_referrals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  observed_at_utc TEXT NOT NULL,
  bot_id TEXT,
  operator TEXT NOT NULL,
  referrer_domain TEXT NOT NULL,
  referrer_url TEXT,
  request_path TEXT,
  occurrences INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_referrals_operator ON ai_operator_referrals(operator);
CREATE INDEX IF NOT EXISTS idx_referrals_domain ON ai_operator_referrals(referrer_domain);

CREATE TABLE IF NOT EXISTS ai_bot_cidr_ranges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bot_id TEXT NOT NULL,
  network TEXT NOT NULL,
  mask TEXT NOT NULL,
  cidr TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at_utc TEXT NOT NULL,
  UNIQUE(bot_id, cidr)
);
CREATE INDEX IF NOT EXISTS idx_cidr_bot ON ai_bot_cidr_ranges(bot_id);

CREATE TABLE IF NOT EXISTS ai_bot_dns_cache (
  ip TEXT PRIMARY KEY,
  hostname TEXT,
  forward_ip TEXT,
  verification_method TEXT,
  bot_id TEXT,
  source TEXT,
  observed_at_utc TEXT NOT NULL,
  expires_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_bot_jwk_cache (
  thumbprint TEXT PRIMARY KEY,
  host TEXT NOT NULL,
  kid TEXT,
  jwk TEXT NOT NULL,
  algorithm TEXT,
  observed_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_zone_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  bot_preference_sync_enabled INTEGER NOT NULL DEFAULT 1,
  markdown_for_agents_enabled INTEGER NOT NULL DEFAULT 1,
  search_policy TEXT NOT NULL DEFAULT 'allow',
  agent_policy TEXT NOT NULL DEFAULT 'allow',
  training_policy TEXT NOT NULL DEFAULT 'disallow',
  content_use_signal TEXT NOT NULL DEFAULT 'reference',
  block_status_code INTEGER NOT NULL DEFAULT 403,
  block_response_body TEXT NOT NULL DEFAULT 'Access denied: automated crawling policy violation.',
  price_usd REAL NOT NULL DEFAULT 0.015,
  custom_robots_append TEXT NOT NULL DEFAULT '',
  updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_bot_custom_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bot_id TEXT NOT NULL UNIQUE,
  action TEXT NOT NULL,
  note TEXT,
  created_at_utc TEXT NOT NULL
);
`;

const SEED_ZONE_SQL = `
INSERT OR IGNORE INTO ai_zone_config (
  id, bot_preference_sync_enabled, markdown_for_agents_enabled, search_policy, agent_policy,
  training_policy, content_use_signal, block_status_code, block_response_body, price_usd,
  custom_robots_append, updated_at_utc
) VALUES (1, 1, 1, 'allow', 'allow', 'disallow', 'reference', 403,
  'Access denied: automated crawling policy violation.', 0.015, '', ?)
`;

type Row = Record<string, any>;
type StatementKind = 'select' | 'insert' | 'update' | 'delete' | 'noop';

const UNIQUE_KEYS: Record<string, string[][]> = {
  ai_bot_requests: [['id']],
  ai_operator_referrals: [['id']],
  ai_bot_cidr_ranges: [['id'], ['bot_id', 'cidr']],
  ai_bot_dns_cache: [['ip']],
  ai_bot_jwk_cache: [['thumbprint']],
  ai_zone_config: [['id']],
  ai_bot_custom_policies: [['id'], ['bot_id']],
};

const AUTOINCREMENT_TABLES = new Set([
  'ai_bot_requests',
  'ai_operator_referrals',
  'ai_bot_cidr_ranges',
  'ai_bot_custom_policies',
]);

function splitTopLevel(input: string, delimiter = ','): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let current = '';
  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (quote) {
      current += ch;
      if (ch === quote) {
        if (input[i + 1] === quote) {
          current += quote;
          i += 1;
        } else {
          quote = null;
        }
      }
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === '(') depth += 1;
    if (ch === ')') depth -= 1;
    if (ch === delimiter && depth === 0) {
      parts.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function stripIdentifier(token: string): string {
  return token.trim().replace(/^[`"\[]/, '').replace(/[`"\]]$/, '').split('.').pop() ?? token;
}

function parseLiteral(token: string): unknown {
  const value = token.trim();
  if (/^'(?:[^']|'')*'$/.test(value)) return value.slice(1, -1).replace(/''/g, "'");
  if (/^"(?:[^"]|"")*"$/.test(value)) return value.slice(1, -1).replace(/""/g, '"');
  if (/^`(?:[^`]|``)*`$/.test(value)) return value.slice(1, -1).replace(/``/g, '`');
  if (/^-?\d+$/.test(value)) return Number.parseInt(value, 10);
  if (/^-?\d*\.\d+$/.test(value)) return Number.parseFloat(value);
  if (/^null$/i.test(value)) return null;
  if (/^true$/i.test(value)) return 1;
  if (/^false$/i.test(value)) return 0;
  return value;
}

interface ValueCursor {
  params: unknown[];
  index: number;
}

function readValue(token: string, cursor: ValueCursor): unknown {
  if (token.trim() === '?') {
    const value = cursor.params[cursor.index];
    cursor.index += 1;
    return value === undefined ? null : value;
  }
  return parseLiteral(token);
}

function valuesEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (left === null || left === undefined || right === null || right === undefined) return false;
  return String(left) === String(right);
}

function matchesWhere(row: Row, where: string | undefined, cursor: ValueCursor): boolean {
  if (!where || !where.trim()) return true;
  const conditions = splitTopLevel(where, ',').length ? splitByAnd(where) : [where];
  for (const raw of conditions) {
    const condition = raw.trim().replace(/^\(/, '').replace(/\)$/, '').trim();
    if (!condition) continue;
    let match = /^([\w.]+)\s+IS\s+NOT\s+NULL$/i.exec(condition);
    if (match) {
      const value = row[stripIdentifier(match[1])];
      if (value === null || value === undefined) return false;
      continue;
    }
    match = /^([\w.]+)\s+IS\s+NULL$/i.exec(condition);
    if (match) {
      const value = row[stripIdentifier(match[1])];
      if (value !== null && value !== undefined) return false;
      continue;
    }
    match = /^([\w.]+)\s+LIKE\s+(\?|'(?:[^']|'')*')$/i.exec(condition);
    if (match) {
      const needle = String(readValue(match[2], cursor) ?? '');
      const pattern = `^${needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/%/g, '.*').replace(/_/g, '.')}$`;
      if (!new RegExp(pattern, 'i').test(String(row[stripIdentifier(match[1])] ?? ''))) return false;
      continue;
    }
    match = /^([\w.]+)\s*(>=|<=|!=|<>|>|<|=)\s*(\?|'(?:[^']|'')*'|"[^"]*"|\S+)$/.exec(condition);
    if (match) {
      const column = stripIdentifier(match[1]);
      const operator = match[2];
      const expected = readValue(match[3], cursor);
      const actual = row[column];
      let ok = false;
      if (operator === '=') ok = valuesEqual(actual, expected);
      else if (operator === '!=' || operator === '<>') ok = !valuesEqual(actual, expected);
      else if (expected === null || actual === null || actual === undefined) ok = false;
      else {
        const a = typeof actual === 'number' ? actual : Number.parseFloat(String(actual));
        const b = typeof expected === 'number' ? expected : Number.parseFloat(String(expected));
        ok =
          operator === '>'
            ? a > b
            : operator === '<'
              ? a < b
              : operator === '>='
                ? a >= b
                : a <= b;
      }
      if (!ok) return false;
      continue;
    }
    // Unsupported predicates are treated as non-matching rather than throwing.
    return false;
  }
  return true;
}

function splitByAnd(input: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let current = '';
  const lower = input.toLowerCase();
  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (quote) {
      current += ch;
      if (ch === quote && input[i + 1] !== quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === '(') depth += 1;
    if (ch === ')') depth -= 1;
    if (depth === 0 && lower.startsWith('and', i) && /\s/i.test(input[i + 3] ?? ' ')) {
      if (current.trim()) parts.push(current.trim());
      current = '';
      i += 2;
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function classifySql(sql: string): StatementKind {
  if (/^SELECT\b/i.test(sql)) return 'select';
  if (/^INSERT\b|^REPLACE\b/i.test(sql)) return 'insert';
  if (/^UPDATE\b/i.test(sql)) return 'update';
  if (/^DELETE\b/i.test(sql)) return 'delete';
  return 'noop';
}

class MemoryDatabase implements AIBotDatabase {
  private readonly tables = new Map<string, Row[]>();
  private readonly nextIds = new Map<string, number>();

  private table(name: string): Row[] {
    let rows = this.tables.get(name);
    if (!rows) {
      rows = [];
      this.tables.set(name, rows);
    }
    return rows;
  }

  private findConflict(table: string, row: Row): Row | undefined {
    const keys = UNIQUE_KEYS[table] ?? [['id']];
    const rows = this.table(table);
    for (const key of keys) {
      if (key.some((column) => row[column] === null || row[column] === undefined)) continue;
      const found = rows.find((candidate) => key.every((column) => valuesEqual(candidate[column], row[column])));
      if (found) return found;
    }
    return undefined;
  }

  private execute(sql: string, params: unknown[], mode: 'get' | 'all' | 'run'): any {
    const normalized = sql.replace(/;\s*$/, '').replace(/\s+/g, ' ').trim();
    const kind = classifySql(normalized);
    if (kind === 'noop') return mode === 'all' ? [] : undefined;

    if (kind === 'select') {
      const head = /^SELECT\s+([\s\S]+?)\s+FROM\s+([`"\[\]\w]+)([\s\S]*)$/i.exec(normalized);
      if (!head) return mode === 'all' ? [] : undefined;
      const projection = head[1].trim();
      const table = stripIdentifier(head[2]);
      let rest = head[3] ?? '';
      let limit: number | null = null;
      const limitMatch = /\s+LIMIT\s+(\d+)\s*$/i.exec(rest);
      if (limitMatch) {
        limit = Number.parseInt(limitMatch[1], 10);
        rest = rest.slice(0, limitMatch.index).trim();
      }
      let orderBy: string | undefined;
      const orderMatch = /\s+ORDER\s+BY\s+([\s\S]+)$/i.exec(rest);
      if (orderMatch) {
        orderBy = orderMatch[1].trim();
        rest = rest.slice(0, orderMatch.index).trim();
      }
      let where: string | undefined;
      const whereMatch = /^WHERE\s+([\s\S]+)$/i.exec(rest.trim());
      if (whereMatch) where = whereMatch[1].trim();

      const cursor: ValueCursor = { params, index: 0 };
      let rows = this.table(table).filter((row) => matchesWhere(row, where, cursor));
      if (orderBy) {
        const terms = splitTopLevel(orderBy).map((term) => {
          const parts = term.trim().split(/\s+/);
          return { column: stripIdentifier(parts[0]), desc: /^desc$/i.test(parts[1] ?? '') };
        });
        rows = [...rows].sort((a, b) => {
          for (const term of terms) {
            const av = a[term.column];
            const bv = b[term.column];
            if (valuesEqual(av, bv)) continue;
            if (av === null || av === undefined) return term.desc ? 1 : -1;
            if (bv === null || bv === undefined) return term.desc ? -1 : 1;
            const result = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv));
            return term.desc ? -result : result;
          }
          return 0;
        });
      }

      const project = (row: Row): Row => {
        if (projection === '*') return { ...row };
        const out: Row = {};
        for (const item of splitTopLevel(projection)) {
          const aliasMatch = /^(.+?)\s+AS\s+([\w]+)$/i.exec(item);
          const expression = (aliasMatch ? aliasMatch[1] : item).trim();
          const alias = aliasMatch ? aliasMatch[2] : expression;
          const countMatch = /^COUNT\s*\(\s*(\*|[`"\[\]\w]+)\s*\)$/i.exec(expression);
          if (countMatch) {
            if (countMatch[1] === '*') out[alias] = rows.length;
            else {
              const column = stripIdentifier(countMatch[1]);
              out[alias] = rows.filter((candidate) => candidate[column] !== null && candidate[column] !== undefined).length;
            }
            continue;
          }
          const sumMatch = /^SUM\s*\(\s*([`"\[\]\w]+)\s*\)$/i.exec(expression);
          if (sumMatch) {
            const column = stripIdentifier(sumMatch[1]);
            out[alias] = rows.reduce<number>((total, candidate) => total + (Number(candidate[column]) || 0), 0);
            continue;
          }
          out[alias] = row[stripIdentifier(expression)];
        }
        return out;
      };

      let projected = rows.map(project);
      // COUNT/SUM with no GROUP BY returns a single aggregate row.
      if (!limit && /^COUNT\s*\(|^SUM\s*\(/i.test(projection) && projected.length === 0) {
        projected = [project({})];
      }
      if (limit !== null) projected = projected.slice(0, limit);
      if (mode === 'get') return projected[0];
      return projected;
    }

    if (kind === 'insert') {
      const match = /^INSERT(?:\s+OR\s+(IGNORE|REPLACE))?\s+INTO\s+([`"\[\]\w]+)\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)([\s\S]*)$/i.exec(normalized)
        ?? /^REPLACE\s+INTO\s+([`"\[\]\w]+)\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)([\s\S]*)$/i.exec(normalized);
      if (!match) return { changes: 0 };
      const orClause = match[1] && /^(IGNORE|REPLACE)$/i.test(match[1]) ? match[1].toUpperCase() : undefined;
      const table = stripIdentifier(orClause ? match[2] : match[1]);
      const columnsRaw = orClause ? match[3] : match[2];
      const valuesRaw = orClause ? match[4] : match[3];
      const tail = (orClause ? match[5] : match[4]) ?? '';
      const columns = splitTopLevel(columnsRaw).map(stripIdentifier);
      const cursor: ValueCursor = { params, index: 0 };
      const values = splitTopLevel(valuesRaw).map((token) => readValue(token, cursor));
      const row: Row = {};
      columns.forEach((column, index) => {
        row[column] = values[index] ?? null;
      });

      const conflictAction = /ON\s+CONFLICT(?:[^]*?)?\s+DO\s+(NOTHING|UPDATE\s+SET\s+([\s\S]+))/i.exec(tail);
      const existing = this.findConflict(table, row);
      if (existing) {
        if (orClause === 'IGNORE' || (conflictAction && /^NOTHING$/i.test(conflictAction[1]))) {
          return { changes: 0 };
        }
        if (conflictAction && conflictAction[2]) {
          for (const assignment of splitTopLevel(conflictAction[2])) {
            const setMatch = /^([\w]+)\s*=\s*([\s\S]+)$/.exec(assignment.trim());
            if (!setMatch) continue;
            const column = stripIdentifier(setMatch[1]);
            const expression = setMatch[2].trim();
            const excluded = /^excluded\.([\w]+)$/i.exec(expression);
            existing[column] = excluded ? row[stripIdentifier(excluded[1])] : readValue(expression, cursor);
          }
          return { changes: 1, lastInsertRowid: existing.id };
        }
        Object.assign(existing, row);
        return { changes: 1, lastInsertRowid: existing.id };
      }

      if (AUTOINCREMENT_TABLES.has(table) && (row.id === null || row.id === undefined)) {
        const next = this.nextIds.get(table) ?? 1;
        row.id = next;
        this.nextIds.set(table, next + 1);
      }
      this.table(table).push(row);
      return { changes: 1, lastInsertRowid: row.id ?? this.table(table).length };
    }

    if (kind === 'update') {
      const match = /^UPDATE\s+([`"\[\]\w]+)\s+SET\s+([\s\S]+?)(?:\s+WHERE\s+([\s\S]+))?$/i.exec(normalized);
      if (!match) return { changes: 0 };
      const table = stripIdentifier(match[1]);
      const cursor: ValueCursor = { params, index: 0 };
      const assignments = splitTopLevel(match[2]).map((item) => {
        const setMatch = /^([\w]+)\s*=\s*([\s\S]+)$/.exec(item.trim());
        return setMatch ? { column: stripIdentifier(setMatch[1]), value: readValue(setMatch[2], cursor) } : null;
      }).filter((item): item is { column: string; value: unknown } => item !== null);
      const rows = this.table(table).filter((row) => matchesWhere(row, match[3], cursor));
      for (const row of rows) for (const assignment of assignments) row[assignment.column] = assignment.value;
      return { changes: rows.length };
    }

    if (kind === 'delete') {
      const match = /^DELETE\s+FROM\s+([`"\[\]\w]+)(?:\s+WHERE\s+([\s\S]+))?$/i.exec(normalized);
      if (!match) return { changes: 0 };
      const table = stripIdentifier(match[1]);
      const cursor: ValueCursor = { params, index: 0 };
      const rows = this.table(table);
      const remove = new Set(rows.filter((row) => matchesWhere(row, match[2], cursor)));
      for (let i = rows.length - 1; i >= 0; i -= 1) if (remove.has(rows[i])) rows.splice(i, 1);
      return { changes: remove.size };
    }

    return { changes: 0 };
  }

  prepare(sql: string): AIBotStatement {
    return {
      get: (...params: unknown[]) => this.execute(sql, params, 'get'),
      all: (...params: unknown[]) => this.execute(sql, params, 'all'),
      run: (...params: unknown[]) => this.execute(sql, params, 'run'),
    };
  }

  exec(sql: string): void {
    // Table creation is implicit in the row store; the DDL is still validated for syntax shape.
    void sql;
  }

  pragma(): unknown {
    return undefined;
  }

  transaction<T extends (...args: any[]) => any>(fn: T): T {
    return ((...args: any[]) => {
      const snapshot = new Map<string, Row[]>();
      for (const [name, rows] of this.tables) snapshot.set(name, rows.map((row) => ({ ...row })));
      const ids = new Map(this.nextIds);
      try {
        return fn(...args);
      } catch (error) {
        this.tables.clear();
        for (const [name, rows] of snapshot) this.tables.set(name, rows);
        this.nextIds.clear();
        for (const [name, id] of ids) this.nextIds.set(name, id);
        throw error;
      }
    }) as T;
  }

  close(): void {
    this.tables.clear();
    this.nextIds.clear();
  }
}

function createMemoryDatabase(): AIBotDatabase {
  const db = new MemoryDatabase();
  db.exec(SCHEMA_SQL);
  db.prepare(SEED_ZONE_SQL).run(new Date().toISOString());
  return db;
}

function isServerlessRuntime(): boolean {
  return Boolean(
    process.env.VERCEL ||
      process.env.VERCEL_ENV ||
      process.env.AWS_LAMBDA_FUNCTION_NAME ||
      process.env.NETLIFY
  );
}

export function defaultAIBotDatabasePath(): string {
  return isServerlessRuntime() ? '/tmp/intel-ai-bots.db' : './data/intel-ai-bots.db';
}

/**
 * Opens (or creates) the protection database. Never throws because of a missing native driver:
 * a complete in-memory adapter is used instead.
 */
export function initAIBotDatabase(customDbPath?: string): AIBotDatabase {
  const dbPath = customDbPath || defaultAIBotDatabasePath();
  try {
    const dir = path.dirname(dbPath);
    if (dir && dir !== '.' && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const requireModule = createRequire(import.meta.url);
    const BetterSqlite3 = requireModule('better-sqlite3') as new (filename: string) => NativeDatabase;
    const native = new BetterSqlite3(dbPath);
    native.pragma('journal_mode = WAL');
    native.pragma('synchronous = NORMAL');
    native.pragma('foreign_keys = ON');
    native.pragma('busy_timeout = 5000');
    native.exec(SCHEMA_SQL);
    native.prepare(SEED_ZONE_SQL).run(new Date().toISOString());

    return {
      prepare: (sql: string) => native.prepare(sql),
      exec: (sql: string) => native.exec(sql),
      pragma: (name: string, value?: string | number) =>
        value === undefined ? native.pragma(name) : native.pragma(name, value),
      transaction: <T extends (...args: any[]) => any>(fn: T): T => native.transaction(fn),
      close: () => native.close(),
    };
  } catch {
    return createMemoryDatabase();
  }
}

/** Exported mainly for tests and diagnostics. */
export { SCHEMA_SQL };

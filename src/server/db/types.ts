/**
 * Neutral SQLite adapter contract shared by the identity engine.
 *
 * The Cloudflare Worker injects a request-scoped Durable-Object SQLite adapter
 * (`{ prepare, exec }`); the standalone Node runtime injects better-sqlite3.
 * Both satisfy this interface, so no module needs to know which runtime it is in.
 */

/** A single prepared statement, compatible with better-sqlite3's positional parameter API. */
export interface SqlStatement {
  get(...params: unknown[]): any;
  all(...params: unknown[]): any[];
  run(...params: unknown[]): { changes: number; lastInsertRowid?: number | bigint };
}

/** The adapter accepted by every identity module. */
export interface SqlDatabase {
  prepare(sql: string): SqlStatement;
  exec(sql: string): void;
  pragma?(name: string, value?: string | number): unknown;
  transaction?<T extends (...args: any[]) => any>(fn: T): T;
  close?(): void;
}

/**
 * Backwards-compatible alias used by the identity resolver/index modules.
 * Kept as a distinct name so call sites stay readable.
 */
export type AIBotDatabase = SqlDatabase;

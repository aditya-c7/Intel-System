#!/usr/bin/env node
/**
 * release-manifest.mjs
 *
 * Write an immutable release record to releases/<id>.json so that rollback has
 * a concrete artifact to read. Fields that cannot be known at build time
 * (Durable Object bookmark, row counts, asset checksum) are written as
 * explicit placeholders. Nothing here invents values or touches production.
 *
 * Usage:
 *   node scripts/release-manifest.mjs [--id <id>] [--dry-run] [--force]
 *
 * Environment:
 *   RELEASE_ID                       release id (default: <timestamp>-<sha7>)
 *   RELEASE_APPROVER | APPROVER      required for a real (non dry-run) record
 *   LAST_GOOD | LAST_GOOD_VERSION    worker version id targeted by rollback
 *   FLAG_* | FEATURE_FLAG_* | ENABLE_* | ROLLBACK_FLAG_*   flag snapshot
 *   FLAG_SNAPSHOT                    optional extra flags as a JSON object
 *   RELEASE_DO_BOOKMARK              optional real DO bookmark (else placeholder)
 *   RELEASE_ROW_COUNTS               optional JSON object { table: rowCount }
 *   RELEASE_CHECKSUM                 optional sha256 of the released asset set
 *   ROLLBACK_SCENARIO                optional classification hint for rollback
 *
 * --dry-run prints the manifest and writes nothing. Writes fail if the target
 * already exists unless --force is given.
 */
import { execFileSync } from 'node:child_process';
import { access, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(SCRIPT_DIR, '..');
const RELEASES_DIR = path.join(ROOT, 'releases');
const FLAG_PREFIXES = ['FLAG_', 'FEATURE_FLAG_', 'ENABLE_', 'ROLLBACK_FLAG_'];
const SCHEMA_VERSION = 1;

const HELP = `Usage: node scripts/release-manifest.mjs [options]

Options:
  --id <id>     Release id (default: <timestamp>-<git-sha7>).
  --dry-run     Print the manifest without writing a file.
  --force       Overwrite an existing release with the same id.
  --help        Show this help.

Required for a real record: RELEASE_APPROVER (or APPROVER) and a reachable git
repository. LAST_GOOD is required for a usable rollback command.
`;

function parseArgs(argv) {
  const out = { dryRun: false, force: false, help: false, id: null, unknown: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') out.dryRun = true;
    else if (arg === '--force') out.force = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else if (arg === '--id') out.id = argv[++i] ?? null;
    else if (arg.startsWith('--id=')) out.id = arg.slice(5);
    else out.unknown.push(arg);
  }
  return out;
}

function isTruthy(value) {
  if (typeof value === 'boolean') return value;
  return ['1', 'true', 'yes', 'on', 'enabled'].includes(String(value ?? '').trim().toLowerCase());
}

function sanitizeId(raw) {
  const id = String(raw ?? '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$/.test(id) || id.includes('..')) {
    throw new Error(`Invalid release id "${id}": use letters, digits, dot, underscore or dash (no path segments).`);
  }
  return id;
}

function defaultId(timestamp, sha) {
  const stamp = timestamp.replace(/\.\d{3}Z$/, 'Z').replace(/[-:]/g, '');
  return `${stamp}-${(sha || 'nogit').slice(0, 7)}`;
}

function parseJsonObjectEnv(name, raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`${name} must be a JSON object: ${error.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${name} must be a JSON object, not an array or scalar.`);
  }
  return parsed;
}

function collectFlags() {
  const flags = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (FLAG_PREFIXES.some(prefix => key.startsWith(prefix))) flags[key] = value;
  }
  const extra = parseJsonObjectEnv('FLAG_SNAPSHOT', process.env.FLAG_SNAPSHOT);
  if (extra) Object.assign(flags, extra);
  return Object.fromEntries(Object.entries(flags).sort(([a], [b]) => a.localeCompare(b)));
}

function gitInfo() {
  const options = { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] };
  try {
    const sha = execFileSync('git', ['rev-parse', 'HEAD'], options).trim();
    let dirty = null;
    try {
      dirty = execFileSync('git', ['status', '--porcelain'], options).trim().length > 0;
    } catch {
      // Dirty state is informative only; the SHA is the critical value.
    }
    return { sha: sha || null, dirty };
  } catch {
    return { sha: null, dirty: null };
  }
}

async function exists(filename) {
  try {
    await access(filename);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(HELP);
    return;
  }
  if (args.unknown.length) throw new Error(`Unknown argument(s): ${args.unknown.join(', ')}`);

  const env = process.env;
  const git = gitInfo();
  const timestamp = new Date().toISOString();
  const id = sanitizeId(args.id || env.RELEASE_ID || defaultId(timestamp, git.sha));
  const approver = String(env.RELEASE_APPROVER || env.APPROVER || '').trim();
  const lastGood = String(env.LAST_GOOD || env.LAST_GOOD_VERSION || '').trim() || null;
  const flagSnapshot = collectFlags();
  const rowCountsInput = parseJsonObjectEnv('RELEASE_ROW_COUNTS', env.RELEASE_ROW_COUNTS);
  const bookmark = String(env.RELEASE_DO_BOOKMARK || '').trim();
  const checksum = String(env.RELEASE_CHECKSUM || '').trim();

  const pending = [];
  const doBookmark = bookmark
    ? { status: 'provided', value: bookmark }
    : { status: 'placeholder', value: null, note: 'TODO: record the Durable Object SQLite bookmark/LSN taken at release time.' };
  if (!bookmark) pending.push('doBookmark');

  const rowCounts = rowCountsInput
    ? { status: 'provided', tables: rowCountsInput }
    : {
        status: 'placeholder',
        tables: {
          visitors: null,
          visits: null,
          hardware_anchors: null,
          identity_lsh_bands: null,
          schema_migrations: null,
        },
        note: 'TODO: fill with read-only row counts from the target environment before sign-off.',
      };
  if (!rowCountsInput) pending.push('rowCounts');

  const checksumRecord = checksum
    ? { status: 'provided', algorithm: 'sha256', value: checksum }
    : { status: 'placeholder', algorithm: 'sha256', value: null, note: 'TODO: sha256 of the released static asset set.' };
  if (!checksum) pending.push('checksum');
  if (!approver) pending.push('approver');
  if (!lastGood) pending.push('lastGood');

  const rollbackCommand = 'npm run rollback:last -- --dry-run';
  const rollbackExecuteCommand = 'npm run rollback:last -- --execute';

  const manifest = {
    schemaVersion: SCHEMA_VERSION,
    kind: 'release-manifest',
    id,
    gitSha: git.sha,
    gitDirty: git.dirty,
    timestamp,
    flagSnapshot,
    doBookmark,
    rowCounts,
    checksum: checksumRecord,
    approver: approver || '<unspecified>',
    lastGood,
    rollbackCommand,
    rollbackExecuteCommand,
    rollback: {
      scenarioHint: String(env.ROLLBACK_SCENARIO || '').trim() || null,
      lastGood,
      command: rollbackCommand,
      executeCommand: rollbackExecuteCommand,
      note: 'Execution requires the explicit --execute flag; dry-run is the default.',
    },
    pending,
  };

  const serialized = `${JSON.stringify(manifest, null, 2)}\n`;

  if (args.dryRun) {
    console.log('[DRY-RUN] release manifest (nothing written):');
    console.log(serialized.trimEnd());
    if (pending.length) console.log(`\n[DRY-RUN] Placeholder/missing fields: ${pending.join(', ')}`);
    return;
  }

  if (!approver) throw new Error('RELEASE_APPROVER (or APPROVER) is required for a real release manifest.');
  if (!git.sha) throw new Error('Could not resolve git HEAD; a release manifest must reference a git SHA.');

  await mkdir(RELEASES_DIR, { recursive: true });
  const filename = path.join(RELEASES_DIR, `${id}.json`);
  if (!args.force && await exists(filename)) {
    throw new Error(`Release ${id} already exists at ${path.relative(ROOT, filename)}; use --force to overwrite.`);
  }
  await writeFile(filename, serialized, { encoding: 'utf8', flag: args.force ? 'w' : 'wx' });
  console.log(`Wrote ${path.relative(ROOT, filename).replaceAll(path.sep, '/')}`);
  if (pending.length) console.log(`Placeholder/missing fields to fill before sign-off: ${pending.join(', ')}`);
}

try {
  await main();
} catch (error) {
  console.error(`release-manifest: ${error.message}`);
  process.exitCode = 2;
}

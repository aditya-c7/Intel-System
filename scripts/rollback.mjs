#!/usr/bin/env node
/**
 * rollback.mjs
 *
 * One-command rollback planner for the last release. It NEVER executes a
 * destructive command unless --execute is passed explicitly; the default is
 * a read-only dry-run that prints the decision and the exact command.
 *
 * Usage:
 *   npm run rollback:last -- [--dry-run] [--execute] [--scenario <name>] [--manifest <path>]
 *
 * Decision tree (explicit ROLLBACK_SCENARIO / --scenario overrides classification):
 *   1. flag-gated           -> print instructions to flip flags OFF; no deploy change.
 *   2. blocked-lifecycle    -> REFUSE: a version rollback cannot undo schema/DO state.
 *   3. asset-skew           -> keep BOTH asset sets; do not prune or half-rollback.
 *   4. bad-code-no-lifecycle-> print `wrangler rollback --version-id <LAST_GOOD>`.
 *   5. unclassified         -> fail closed and print the tree.
 *
 * Classification signals (environment):
 *   ROLLBACK_SCENARIO       flag-gated | bad-code-no-lifecycle | asset-skew | blocked-lifecycle
 *   LAST_GOOD | LAST_GOOD_VERSION   target worker version id
 *   FLAG_* | FEATURE_FLAG_* | ENABLE_* | ROLLBACK_FLAG_*   enabled flags -> flag-gated
 *   LIFECYCLE_CHANGE | SCHEMA_CHANGE | DO_MIGRATION        -> blocked-lifecycle
 *   ASSET_SKEW or CURRENT_ASSET_VERSION != LAST_GOOD_ASSET_VERSION -> asset-skew
 *   RELEASE_MANIFEST        optional manifest path (default: newest releases/*.json)
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(SCRIPT_DIR, '..');
const RELEASES_DIR = path.join(ROOT, 'releases');
const WRANGLER_ARGS = ['--yes', 'wrangler@4.161.0'];
const FLAG_PREFIXES = ['FLAG_', 'FEATURE_FLAG_', 'ENABLE_', 'ROLLBACK_FLAG_'];
const VERSION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

const SCENARIOS = new Set([
  'flag-gated',
  'bad-code-no-lifecycle',
  'asset-skew',
  'blocked-lifecycle',
]);

const ALIASES = {
  flags: 'flag-gated',
  flag: 'flag-gated',
  'feature-flags': 'flag-gated',
  code: 'bad-code-no-lifecycle',
  'bad-code': 'bad-code-no-lifecycle',
  deploy: 'bad-code-no-lifecycle',
  assets: 'asset-skew',
  asset: 'asset-skew',
  skew: 'asset-skew',
  lifecycle: 'blocked-lifecycle',
  blocked: 'blocked-lifecycle',
  schema: 'blocked-lifecycle',
};

const HELP = `Usage: node scripts/rollback.mjs [options]

Options:
  --dry-run              Default. Print the plan; execute nothing.
  --execute              Opt in to running the one destructive command (bad code only).
  --scenario <name>      Override classification: flag-gated, bad-code-no-lifecycle,
                         asset-skew, blocked-lifecycle.
  --manifest <path>      Read a specific releases/<id>.json (default: newest).
  --help                 Show this help.

Safety: no command is run without --execute, and --execute is ignored for every
scenario except bad-code-no-lifecycle with a valid LAST_GOOD version id.
`;

function parseArgs(argv) {
  const out = { dryRun: false, execute: false, help: false, scenario: null, manifest: null, unknown: [] };
  let dryRunSeen = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') { out.dryRun = true; dryRunSeen = true; }
    else if (arg === '--execute') out.execute = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else if (arg === '--scenario') out.scenario = argv[++i] ?? null;
    else if (arg.startsWith('--scenario=')) out.scenario = arg.slice(11);
    else if (arg === '--manifest') out.manifest = argv[++i] ?? null;
    else if (arg.startsWith('--manifest=')) out.manifest = arg.slice(11);
    else out.unknown.push(arg);
  }
  if (out.execute && dryRunSeen) {
    throw new Error('--execute and --dry-run are mutually exclusive; choose one.');
  }
  if (!out.execute) out.dryRun = true; // explicit default
  return out;
}

function isTruthy(value) {
  if (typeof value === 'boolean') return value;
  return ['1', 'true', 'yes', 'on', 'enabled'].includes(String(value ?? '').trim().toLowerCase());
}

function normalizeScenario(raw) {
  const key = String(raw ?? '').trim().toLowerCase();
  if (!key) return null;
  if (SCENARIOS.has(key)) return key;
  return ALIASES[key] ?? null;
}

function loadManifest(explicitPath) {
  const requested = explicitPath || process.env.RELEASE_MANIFEST;
  let filename = requested ? path.resolve(ROOT, requested) : null;
  if (!filename) {
    try {
      const names = readdirSync(RELEASES_DIR)
        .filter(name => /^[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(name))
        .sort();
      if (names.length) filename = path.join(RELEASES_DIR, names[names.length - 1]);
    } catch {
      // No releases directory yet: classification falls back to environment.
    }
  }
  if (!filename) return { manifest: null, file: null };
  try {
    const manifest = JSON.parse(readFileSync(filename, 'utf8'));
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
      throw new Error('manifest root must be a JSON object');
    }
    return { manifest, file: path.relative(ROOT, filename).replaceAll(path.sep, '/') };
  } catch (error) {
    if (requested) throw new Error(`Could not read manifest ${filename}: ${error.message}`);
    console.error(`rollback: ignoring unreadable manifest ${filename}: ${error.message}`);
    return { manifest: null, file: null };
  }
}

function firstNonEmpty(...values) {
  for (const value of values) {
    if (value === null || value === undefined) continue;
    const text = String(value).trim();
    if (text) return text;
  }
  return null;
}

function collectEnabledFlags(manifest) {
  const enabled = [];
  const candidates = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (FLAG_PREFIXES.some(prefix => key.startsWith(prefix))) candidates[key] = value;
  }
  if (manifest?.flagSnapshot && typeof manifest.flagSnapshot === 'object') {
    Object.assign(candidates, manifest.flagSnapshot);
  }
  for (const [key, value] of Object.entries(candidates)) {
    if (isTruthy(value)) enabled.push(key);
  }
  return enabled.sort();
}

function classify({ scenarioArg, manifest }) {
  const env = process.env;
  const rawScenario = scenarioArg || env.ROLLBACK_SCENARIO;
  const explicit = normalizeScenario(rawScenario);
  if (rawScenario && !explicit) {
    return {
      kind: 'unknown',
      reason: `Unknown scenario "${rawScenario}". Use one of: ${[...SCENARIOS].join(', ')}.`,
      evidence: {},
    };
  }

  const lastGood = firstNonEmpty(env.LAST_GOOD, env.LAST_GOOD_VERSION, manifest?.lastGood, manifest?.rollback?.lastGood);
  const flags = collectEnabledFlags(manifest);
  const lifecycleChanged =
    isTruthy(env.LIFECYCLE_CHANGE) ||
    isTruthy(env.SCHEMA_CHANGE) ||
    isTruthy(env.DO_MIGRATION) ||
    isTruthy(env.LIFECYCLE_MIGRATION);
  const assetSkew =
    isTruthy(env.ASSET_SKEW) ||
    Boolean(
      env.CURRENT_ASSET_VERSION &&
      env.LAST_GOOD_ASSET_VERSION &&
      String(env.CURRENT_ASSET_VERSION) !== String(env.LAST_GOOD_ASSET_VERSION),
    );

  const evidence = {
    lastGood,
    enabledFlags: flags,
    lifecycleChanged,
    assetSkew,
    manifestGitSha: manifest?.gitSha ?? null,
    manifestApprover: manifest?.approver ?? null,
  };

  if (explicit) {
    return { kind: explicit, reason: 'Explicit scenario override.', evidence };
  }

  // Safety-first ordering: flipping a flag is reversible, so it is suggested
  // first. Anything that changed stored/schema state is refused before a
  // version rollback is offered.
  if (flags.length) {
    return { kind: 'flag-gated', reason: `Enabled flag(s) present: ${flags.join(', ')}`, evidence };
  }
  if (lifecycleChanged) {
    return {
      kind: 'blocked-lifecycle',
      reason: 'Lifecycle/schema/Durable Object state changed; a Worker version rollback cannot reverse it.',
      evidence,
    };
  }
  if (assetSkew) {
    return { kind: 'asset-skew', reason: 'Worker version and static asset version differ.', evidence };
  }
  if (lastGood) {
    return {
      kind: 'bad-code-no-lifecycle',
      reason: 'No enabled flags, lifecycle change or asset skew: code-only regression.',
      evidence,
    };
  }
  return {
    kind: 'unknown',
    reason: 'No classification signal found (set ROLLBACK_SCENARIO and LAST_GOOD, or write a release manifest).',
    evidence,
  };
}

function printEvidence(plan) {
  const e = plan.evidence || {};
  console.log(`Reason: ${plan.reason}`);
  console.log('Evidence:');
  console.log(`  lastGood        : ${e.lastGood || '<unset>'}`);
  console.log(`  enabledFlags    : ${e.enabledFlags?.length ? e.enabledFlags.join(', ') : '<none>'}`);
  console.log(`  lifecycleChange : ${e.lifecycleChanged ? 'yes' : 'no'}`);
  console.log(`  assetSkew       : ${e.assetSkew ? 'yes' : 'no'}`);
  if (e.manifestGitSha) console.log(`  manifest git sha: ${e.manifestGitSha}`);
  if (e.manifestApprover) console.log(`  manifest approver: ${e.manifestApprover}`);
}

function runNpx(args) {
  const npxCli = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npx-cli.js');
  const useNode = existsSync(npxCli);
  const command = useNode ? process.execPath : (process.platform === 'win32' ? 'npx.cmd' : 'npx');
  const commandArgs = useNode ? [npxCli, ...args] : args;
  const result = spawnSync(command, commandArgs, {
    cwd: ROOT,
    stdio: 'inherit',
    shell: process.platform === 'win32' && !useNode,
  });
  if (result.error) {
    console.error(`rollback: failed to launch command: ${result.error.message}`);
    return 1;
  }
  return result.status ?? 1;
}

function planAndRun(plan, options, manifestInfo) {
  const mode = options.execute ? 'EXECUTE' : 'DRY-RUN';
  console.log(`[${mode}] ROLLBACK PLAN${options.execute ? '' : ' (no commands executed)'}`);
  if (manifestInfo?.file) console.log(`Manifest: ${manifestInfo.file}`);
  console.log(`Scenario: ${plan.kind}`);
  printEvidence(plan);
  console.log('');

  switch (plan.kind) {
    case 'flag-gated': {
      const flags = plan.evidence.enabledFlags || [];
      console.log('The release is behind feature flags. Do NOT roll back the Worker version.');
      console.log('Flip these flags OFF in the flag store/configuration:');
      for (const flag of flags) console.log(`  ${flag}=false`);
      if (!flags.length) console.log('  <no enabled flags found in env or manifest; list the flags being disabled above>');
      console.log('Then confirm the flags are off and re-run: npm run rollback:last -- --dry-run');
      console.log('This script does not change flags and issues no destructive command.');
      if (options.execute) console.log('--execute is not applicable to flag-gated rollbacks; nothing was run.');
      return 0;
    }
    case 'asset-skew': {
      console.log('Worker code and static assets are skewed between versions.');
      console.log('Keep BOTH asset sets in place.');
      console.log('  - Do not delete or prune the previous asset set.');
      console.log('  - Do not roll back only assets or only the Worker.');
      console.log('  - Redeploy a matched Worker + asset pair after confirming the asset hash.');
      console.log('This script issues no destructive command.');
      if (options.execute) console.log('--execute is not applicable to asset-skew; nothing was run.');
      return 0;
    }
    case 'blocked-lifecycle': {
      console.log('REFUSING TO ROLL BACK.');
      console.log(`Reason: ${plan.reason}`);
      console.log('A Worker version rollback does not undo Durable Object storage, schema_migrations');
      console.log('or any lifecycle/data migration. Do not run wrangler rollback for this release.');
      console.log('Required next steps: run the staging restore drill (node scripts/backup-drill.mjs),');
      console.log('review the data restore plan, and obtain explicit approval before any data change.');
      if (options.execute) console.log('--execute is refused for blocked-lifecycle; nothing was run.');
      return 2;
    }
    case 'bad-code-no-lifecycle': {
      const lastGood = plan.evidence.lastGood;
      if (!lastGood) {
        console.log('Cannot produce a rollback command: LAST_GOOD (or LAST_GOOD_VERSION) is unset.');
        console.log('Template: wrangler rollback --version-id <LAST_GOOD>');
        return 2;
      }
      if (!VERSION_ID_RE.test(lastGood)) {
        console.log(`Refusing to use LAST_GOOD="${lastGood}": invalid version id characters.`);
        return 2;
      }
      console.log('Safe to revert the Worker version: no lifecycle, flag or asset change to unwind.');
      console.log('Command:');
      console.log(`  wrangler rollback --version-id ${lastGood}`);
      const args = [...WRANGLER_ARGS, 'rollback', '--version-id', lastGood];
      if (!options.execute) {
        console.log(`Executable form (only with --execute): npx ${args.join(' ')}`);
        console.log('Dry-run: no command was executed.');
        return 0;
      }
      console.log(`[EXECUTE] npx ${args.join(' ')}`);
      return runNpx(args);
    }
    case 'unknown':
    default: {
      console.log('No safe classification. Decision tree:');
      console.log('  1. flag-gated            -> flip flags OFF (no deploy change).');
      console.log('  2. blocked-lifecycle     -> refuse; schema/DO state cannot be rolled back by version.');
      console.log('  3. asset-skew            -> keep both asset sets; redeploy a matched pair.');
      console.log('  4. bad-code-no-lifecycle -> wrangler rollback --version-id <LAST_GOOD>.');
      console.log('Set ROLLBACK_SCENARIO or LAST_GOOD and re-run. Nothing was executed.');
      return 2;
    }
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(HELP);
    return 0;
  }
  if (args.unknown.length) throw new Error(`Unknown argument(s): ${args.unknown.join(', ')}`);

  const manifestInfo = loadManifest(args.manifest);
  const plan = classify({ scenarioArg: args.scenario, manifest: manifestInfo.manifest });
  return planAndRun(plan, args, manifestInfo);
}

try {
  process.exitCode = main();
} catch (error) {
  console.error(`rollback: ${error.message}`);
  process.exitCode = 2;
}

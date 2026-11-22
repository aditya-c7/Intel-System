#!/usr/bin/env node
/**
 * backup-drill.mjs
 *
 * Documents and validates the staging-only backup/restore drill. This script
 * performs NO writes of any kind: no production writes, no staging writes.
 * It prints the runbook, validates that the configured target is really
 * staging (fail closed if staging is missing or looks like production), and
 * optionally performs read-only GET checks with --verify.
 *
 * Usage:
 *   node scripts/backup-drill.mjs [--verify] [--help]
 *
 * Required environment (validation fails closed without it):
 *   STAGING=true or ENVIRONMENT=staging or CLOUDFLARE_ENV=staging
 *   STAGING_WORKER_URL (or STAGING_URL)   https staging Worker base URL
 *   DRILL_OPERATOR                       person running the drill
 * Optional:
 *   PRODUCTION_URL | PRODUCTION_HOST     explicit production host to reject
 *
 * The drill endpoints below are templates for a staging-only harness. They
 * must be disabled in production. Review each command before running it by
 * hand; this script never calls them.
 */

const HELP = `Usage: node scripts/backup-drill.mjs [options]

Options:
  --verify   Perform read-only GET checks against the staging Worker (default off).
  --help     Show this help.

This script never writes. It documents the drill and fails closed unless a
staging environment is explicitly configured.
`;

const STEPS = [
  {
    id: 1,
    name: 'Seed',
    purpose: 'Insert a small, known fixture set into the STAGING Durable Object only.',
    command: 'POST <STAGING_WORKER_URL>/__drill/seed   (fixture file, staging-only endpoint)',
    verify: 'Read back fixture rows; record baseline counts per table and the baseline checksum.',
  },
  {
    id: 2,
    name: 'Bookmark',
    purpose: 'Capture the DO SQLite bookmark/LSN immediately before the bad write.',
    command: 'POST <STAGING_WORKER_URL>/__drill/bookmark   -> save <BOOKMARK_ID>',
    verify: 'Confirm the bookmark id is non-empty and the current counts still match the baseline.',
  },
  {
    id: 3,
    name: 'Bad write',
    purpose: 'Apply a deliberate bad write after the bookmark to simulate corruption.',
    command: 'POST <STAGING_WORKER_URL>/__drill/bad-write   (staging-only endpoint)',
    verify: 'Confirm counts/checksum now DIFFER from the baseline; if not, the drill is invalid.',
  },
  {
    id: 4,
    name: 'Restore',
    purpose: 'Restore the staging DO from backup up to the saved bookmark.',
    command: 'POST <STAGING_WORKER_URL>/__drill/restore   { bookmark: <BOOKMARK_ID> }',
    verify: 'Confirm the bad write is gone and the store is back at the bookmarked state.',
  },
  {
    id: 5,
    name: 'Verify counts + checksum',
    purpose: 'Compare restored row counts and checksum against the seeded baseline.',
    command: 'GET <STAGING_WORKER_URL>/__drill/verify?bookmark=<BOOKMARK_ID>',
    verify: 'FAIL the drill on any count or checksum mismatch. Record the observed values.',
  },
  {
    id: 6,
    name: 'Restore forward',
    purpose: 'Re-apply only the good writes captured after the bookmark, then re-verify.',
    command: 'POST <STAGING_WORKER_URL>/__drill/restore-forward   { bookmark: <BOOKMARK_ID> }',
    verify: 'Re-run step 5; counts and checksum must match the expected post-forward values.',
  },
];

function parseArgs(argv) {
  const out = { verify: false, help: false, unknown: [] };
  for (const arg of argv) {
    if (arg === '--verify') out.verify = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else out.unknown.push(arg);
  }
  return out;
}

function isTruthy(value) {
  if (typeof value === 'boolean') return value;
  return ['1', 'true', 'yes', 'on', 'enabled'].includes(String(value ?? '').trim().toLowerCase());
}

function validateEnv() {
  const env = process.env;
  const errors = [];
  const checks = [];
  const envName = String(env.CLOUDFLARE_ENV || env.ENVIRONMENT || env.APP_ENV || '').trim().toLowerCase();
  const explicitStaging =
    isTruthy(env.STAGING) ||
    envName === 'staging' ||
    String(env.CLOUDFLARE_ENV || '').trim().toLowerCase() === 'staging';

  if (['production', 'prod', 'live'].includes(envName)) {
    errors.push(`Environment is "${envName}": the restore drill must never target production.`);
  } else if (!explicitStaging) {
    errors.push('Staging is not confirmed: set STAGING=true or ENVIRONMENT=staging (or CLOUDFLARE_ENV=staging).');
  } else {
    checks.push(`staging confirmed (${envName || 'STAGING=true'})`);
  }
  if (envName && envName !== 'staging' && !['production', 'prod', 'live'].includes(envName)) {
    errors.push(`Environment "${envName}" is not staging; refusing to run the drill.`);
  }

  const rawUrl = String(env.STAGING_WORKER_URL || env.STAGING_URL || '').trim();
  let url = null;
  if (!rawUrl) {
    errors.push('STAGING_WORKER_URL (or STAGING_URL) is required.');
  } else {
    try {
      url = new URL(rawUrl);
      const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname.toLowerCase());
      if (url.protocol !== 'https:' && !loopback) {
        errors.push('STAGING_WORKER_URL must use https (http is allowed only for loopback).');
      } else {
        checks.push(`target is ${loopback ? 'loopback' : 'https'} URL`);
      }
      const productionHosts = new Set(['intel.adityahq.me']);
      if (env.PRODUCTION_URL) {
        try { productionHosts.add(new URL(env.PRODUCTION_URL).hostname.toLowerCase()); } catch {}
      }
      if (env.PRODUCTION_HOST) productionHosts.add(String(env.PRODUCTION_HOST).trim().toLowerCase());
      if (productionHosts.has(url.hostname.toLowerCase())) {
        errors.push(`STAGING_WORKER_URL points at production host "${url.hostname}"; drill refused.`);
      } else {
        checks.push(`host ${url.hostname} is not a known production host`);
      }
    } catch (error) {
      errors.push(`STAGING_WORKER_URL is not a valid URL: ${error.message}`);
    }
  }

  const operator = String(env.DRILL_OPERATOR || '').trim();
  if (!operator) errors.push('DRILL_OPERATOR is required for drill accountability.');
  else checks.push(`operator: ${operator}`);

  return { errors, checks, url, operator };
}

async function verifyStaging(url) {
  const target = new URL('/api/health', url).toString();
  console.log(`\n[VERIFY] GET ${target} (read-only)`);
  try {
    const response = await fetch(target, {
      method: 'GET',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    });
    const body = await response.text();
    console.log(`[VERIFY] status: ${response.status}`);
    if (response.status !== 200) {
      console.error('[VERIFY] FAIL: staging health check did not return HTTP 200.');
      return 1;
    }
    try {
      const parsed = JSON.parse(body);
      console.log(`[VERIFY] json status field: ${parsed?.status ?? '<none>'}`);
    } catch {
      console.error('[VERIFY] FAIL: staging health response was not JSON.');
      return 1;
    }
    console.log('[VERIFY] PASS: staging reached; no data was written.');
    return 0;
  } catch (error) {
    console.error(`[VERIFY] FAIL: ${error.message}`);
    return 1;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(HELP);
    return 0;
  }
  if (args.unknown.length) throw new Error(`Unknown argument(s): ${args.unknown.join(', ')}`);

  console.log('BACKUP / RESTORE DRILL — STAGING ONLY');
  console.log('This script performs NO writes; the steps below are documentation templates.');
  console.log('Run the commands by hand against staging only, and never enable drill endpoints in production.\n');

  for (const step of STEPS) {
    console.log(`Step ${step.id}/${STEPS.length} — ${step.name}`);
    console.log(`  Purpose : ${step.purpose}`);
    console.log(`  Command : ${step.command}`);
    console.log(`  Verify  : ${step.verify}`);
    console.log('');
  }

  const result = validateEnv();
  console.log('VALIDATION');
  for (const check of result.checks) console.log(`  PASS  ${check}`);
  for (const error of result.errors) console.log(`  FAIL  ${error}`);

  if (result.errors.length) {
    console.error('\nStaging validation failed: drill not started. No commands were run.');
    return 2;
  }
  console.log('\nStaging validation passed. No commands were run by this script.');

  if (args.verify) return await verifyStaging(result.url);
  return 0;
}

try {
  process.exitCode = await main();
} catch (error) {
  console.error(`backup-drill: ${error.message}`);
  process.exitCode = 2;
}

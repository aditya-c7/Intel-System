import { build } from 'esbuild';
import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';

/**
 * Bundles the Express application (server.ts) together with the Vercel
 * entry point into a single ESM function at `api/index.js`.
 *
 * Why: the Vercel Node.js runtime executes the function as native ESM because
 * package.json has `"type": "module"`. Extensionless TypeScript imports are
 * not valid ESM specifiers at runtime, so shipping an unbundled `api/index.ts`
 * can crash with ERR_MODULE_NOT_FOUND. Pre-bundling removes the whole class of
 * failures.
 */
const root = process.cwd();
const outfile = path.join(root, 'api', 'index.js');

if (!existsSync(path.join(root, 'api'))) {
  mkdirSync(path.join(root, 'api'), { recursive: true });
}

await build({
  entryPoints: [path.join(root, 'api', '_entry.ts')],
  outfile,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  packages: 'external',
  legalComments: 'none',
  sourcemap: false,
  logLevel: 'info',
  banner: {
    js: [
      "import { createRequire as __intelCreateRequire } from 'node:module';",
      'const require = __intelCreateRequire(import.meta.url);',
    ].join('\n'),
  },
});

console.log(`[build-api] Wrote ${path.relative(root, outfile)}`);

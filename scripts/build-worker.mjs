import { build } from 'esbuild';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

// Adapt only the Worker bundle. The Node/Vercel source and build remain unchanged.
// Fail closed if server.ts changes shape rather than silently publishing a broken adapter.
function replaceOnce(source, before, after) {
  if (source.split(before).length !== 2) {
    throw new Error(`Worker adapter expected exactly one source marker: ${before.slice(0, 90)}`);
  }
  return source.replace(before, after);
}

await build({
  entryPoints: ['worker/index.js'],
  outfile: 'build/worker/index.js',
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'es2022',
  external: ['cloudflare:*'],
  define: { 'process.env.NODE_ENV': '"production"' },
  banner: {
    js: "import { createRequire as __intelCreateRequire } from 'node:module'; const require = __intelCreateRequire('/worker/index.js');",
  },
  legalComments: 'none',
  logLevel: 'info',
  plugins: [{
    name: 'intel-workers-adapter',
    setup(builder) {
      builder.onLoad({ filter: /[/\\]server\.ts$/ }, async ({ path: filename }) => {
        let source = await readFile(filename, 'utf8');
        const start = source.indexOf('function initializeDatabase(): DatabaseAdapter {');
        const schemaStart = source.indexOf('    sqliteDb.exec(`', start);
        const schemaEnd = source.indexOf('\n    return sqliteDb;', schemaStart);
        const endMarker = 'const db = initializeDatabase();';
        const end = source.indexOf(endMarker, schemaEnd);
        if ([start, schemaStart, schemaEnd, end].some(index => index < 0)) {
          throw new Error('Worker database adapter no longer matches server.ts; review the integration.');
        }
        const schema = source.slice(schemaStart, schemaEnd).replaceAll('sqliteDb.', 'database.');
        const adapter = `
export function initializeDatabaseSchema(database: DatabaseAdapter): void {
${schema}
}
const workerDatabaseContext = new AsyncLocalStorage<DatabaseAdapter>();
export function withDatabase<T>(database: DatabaseAdapter, callback: () => T): T {
  return workerDatabaseContext.run(database, callback);
}
function requestDatabase(): DatabaseAdapter {
  const database = workerDatabaseContext.getStore();
  if (!database) throw new Error('Persistent database context is required for this API route.');
  return database;
}
const db: DatabaseAdapter = {
  prepare: (sql) => requestDatabase().prepare(sql),
  exec: (sql) => requestDatabase().exec(sql),
};
`;
        source = source.slice(0, start) + adapter + source.slice(end + endMarker.length);
        source = "import { AsyncLocalStorage } from 'node:async_hooks';\n" + source;
        source = replaceOnce(source, 'dotenv.config();', '// Secrets are provided by Worker bindings.');
        source = source.replace(/const IS_SERVERLESS_RUNTIME = Boolean\([\s\S]*?\n\);/, 'const IS_SERVERLESS_RUNTIME = true;');
        if (!source.includes('const IS_SERVERLESS_RUNTIME = true;')) {
          throw new Error('Worker standalone-listener guard could not be installed.');
        }
        source = source.replaceAll("await import('vite')", "await import(String('vite'))");
        return { contents: source, loader: 'ts', resolveDir: path.dirname(filename) };
      });
    },
  }],
});

const esbuild = require("esbuild");
const production = process.argv.includes('--production');
const watch = process.argv.includes('--watch');
const options = { bundle: true, minify: production, sourcemap: !production, sourcesContent: false, logLevel: 'info' };
const targets = [
  { entryPoints: ['packages/core/src/runtime/main.ts'], platform: 'node', format: 'cjs', outfile: '.aqiron-build/node/core-runtime.js', external: ['keytar'] },
  { entryPoints: ['packages/cli/src/main.ts'], platform: 'node', format: 'cjs', outfile: '.aqiron-build/node/aqiron-cli.js', banner: { js: '#!/usr/bin/env node' }, external: ['keytar'] },
  { entryPoints: ['packages/desktop/src/main.ts'], platform: 'node', format: 'cjs', outfile: '.aqiron-build/node/aqiron-desktop-bridge.js', external: ['keytar'] },
];
async function main() {
  const contexts = await Promise.all(targets.map((target) => esbuild.context({ ...options, ...target })));
  if (watch) {
    await Promise.all(contexts.map((context) => context.watch()));
    return;
  }
  try { await Promise.all(contexts.map((context) => context.rebuild())); }
  finally { await Promise.all(contexts.map((context) => context.dispose())); }
}
main().catch((error) => { console.error(error); process.exit(1); });

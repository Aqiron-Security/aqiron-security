const esbuild = require("esbuild");

const production = process.argv.includes('--production');
const watch = process.argv.includes('--watch');

/**
 * @type {import('esbuild').Plugin}
 */
const esbuildProblemMatcherPlugin = {
	name: 'esbuild-problem-matcher',

	setup(build) {
		build.onStart(() => {
			console.log('[watch] build started');
		});
		build.onEnd((result) => {
			result.errors.forEach(({ text, location }) => {
				console.error(`✘ [ERROR] ${text}`);
				console.error(`    ${location.file}:${location.line}:${location.column}:`);
			});
			console.log('[watch] build finished');
		});
	},
};

async function main() {
	const extensionCtx = await esbuild.context({
		entryPoints: [
			'src/extension.ts'
		],
		bundle: true,
		format: 'cjs',
		minify: production,
		sourcemap: !production,
		sourcesContent: false,
		platform: 'node',
		outfile: 'dist/extension.js',
		external: ['vscode'],
		logLevel: 'silent',
		plugins: [
			/* add to the end of plugins array */
			esbuildProblemMatcherPlugin,
		],
	});
	const runtimeCtx = await esbuild.context({
		entryPoints: [
			'packages/core/src/runtime/main.ts'
		],
		bundle: true,
		format: 'cjs',
		minify: production,
		sourcemap: !production,
		sourcesContent: false,
		platform: 'node',
		outfile: 'dist/core-runtime.js',
		external: ['keytar'],
		logLevel: 'silent',
		plugins: [
			esbuildProblemMatcherPlugin,
		],
	});
	const webviewCtx = await esbuild.context({
		entryPoints: [
			'src/webview/ui/index.tsx'
		],
		bundle: true,
		format: 'iife',
		minify: production,
		sourcemap: !production,
		sourcesContent: false,
		platform: 'browser',
		outfile: 'dist/webview.js',
		logLevel: 'silent',
		loader: {
			'.css': 'css',
			'.ttf': 'file',
		},
		assetNames: '[name]-[hash]',
		plugins: [
			esbuildProblemMatcherPlugin,
		],
	});
	if (watch) {
		await Promise.all([extensionCtx.watch(), runtimeCtx.watch(), webviewCtx.watch()]);
	} else {
		await Promise.all([extensionCtx.rebuild(), runtimeCtx.rebuild(), webviewCtx.rebuild()]);
		await Promise.all([extensionCtx.dispose(), runtimeCtx.dispose(), webviewCtx.dispose()]);
	}
}

main().catch(e => {
	console.error(e);
	process.exit(1);
});

import { defineConfig } from '@vscode/test-cli';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const summaryReporter = fileURLToPath(new URL('./scripts/vscode-test-summary-reporter.cjs', import.meta.url));
const testOutDir = path.resolve(process.env.AQIRON_TEST_OUTDIR ?? 'out');
const summaryPath = path.resolve(process.env.AQIRON_VSCODE_TEST_SUMMARY
	?? path.join(testOutDir, 'vscode-test-summary.json'));

export default defineConfig({
	files: `${process.env.AQIRON_TEST_OUTDIR ?? 'out'}/src/test/**/*.test.js`,
	mocha: { ui: 'tdd', reporter: summaryReporter },
	env: {
		AQIRON_TEST_OUTDIR: testOutDir,
		AQIRON_VSCODE_TEST_SUMMARY: summaryPath,
	},
});

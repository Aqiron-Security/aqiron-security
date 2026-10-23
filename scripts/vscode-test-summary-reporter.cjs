const fs = require('node:fs');
const path = require('node:path');

module.exports = class VscodeTestSummaryReporter {
	constructor(runner) {
		const result = { tests: 0, passes: 0, failures: 0, pending: 0 };
		runner.on('pass', () => {
			result.tests += 1;
			result.passes += 1;
		});
		runner.on('fail', () => {
			result.tests += 1;
			result.failures += 1;
		});
		runner.on('pending', () => {
			result.tests += 1;
			result.pending += 1;
		});
		runner.once('end', () => {
			const output = process.env.AQIRON_VSCODE_TEST_SUMMARY
				?? path.resolve(process.env.AQIRON_TEST_OUTDIR ?? 'out', 'vscode-test-summary.json');
			fs.mkdirSync(path.dirname(output), { recursive: true });
			fs.writeFileSync(output, `${JSON.stringify(result)}\n`, 'utf8');
		});
	}
};

const fs = require('node:fs');
const path = require('node:path');

const summaryPath = process.env.AQIRON_VSCODE_TEST_SUMMARY
	?? path.resolve(process.env.AQIRON_TEST_OUTDIR ?? 'out', 'vscode-test-summary.json');

let summary;
try {
	summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
} catch {
	console.error(`VS Code test summary is missing or invalid: ${summaryPath}`);
	process.exit(1);
}

const { tests, passes, failures, pending } = summary;
if (![tests, passes, failures, pending].every(Number.isSafeInteger)
	|| tests <= 0 || tests !== passes + failures + pending) {
	console.error(`VS Code extension tests did not produce a valid non-empty summary: ${JSON.stringify(summary)}`);
	process.exit(1);
}

console.log(`VS Code extension-host tests: ${passes} passed, ${failures} failed, ${pending} skipped (${tests} total).`);
if (failures > 0) {
	process.exit(1);
}

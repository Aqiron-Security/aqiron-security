const fs = require('node:fs');
const path = require('node:path');

const summaryPath = process.env.AQIRON_VSCODE_TEST_SUMMARY
	?? path.resolve(process.env.AQIRON_TEST_OUTDIR ?? 'out', 'vscode-test-summary.json');
const runnerOutcome = process.env.AQIRON_VSCODE_TEST_OUTCOME ?? 'unknown';

function report(message) {
	console.log(message);
	const stepSummary = process.env.GITHUB_STEP_SUMMARY;
	if (stepSummary) {
		fs.appendFileSync(stepSummary, `${message}\n`);
	}
}

if (runnerOutcome === 'skipped') {
	report('VS Code extension-host tests: NOT RUN (the workflow skipped the runner step); no test counts are available.');
	process.exit(0);
}

if (!['success', 'failure', 'cancelled'].includes(runnerOutcome)) {
	console.error(`VS Code extension-host runner outcome is unavailable or invalid (${runnerOutcome}); no test result can be accepted.`);
	process.exit(1);
}

let summary;
try {
	summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
} catch {
	console.error(`VS Code extension-host runner outcome: ${runnerOutcome}; no valid test summary was produced. Execution and test counts are unverified.`);
	process.exit(1);
}

const { tests, passes, failures, pending } = summary;
if (![tests, passes, failures, pending].every(Number.isSafeInteger)
	|| tests <= 0 || tests !== passes + failures + pending) {
	console.error(`VS Code extension tests did not produce a valid non-empty summary: ${JSON.stringify(summary)}`);
	process.exit(1);
}

report(`VS Code extension-host tests: ${passes} passed, ${failures} failed, ${pending} skipped (${tests} total); runner outcome: ${runnerOutcome}.`);
if (failures > 0 || runnerOutcome !== 'success') {
	process.exit(1);
}

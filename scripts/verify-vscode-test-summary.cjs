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
if (summary.failureDetails !== undefined) {
	if (!Array.isArray(summary.failureDetails) || summary.failureDetails.length > 25
		|| summary.failureDetails.some((item) => !item || typeof item.title !== 'string' || typeof item.error !== 'string' || item.title.length > 500 || item.error.length > 500)) {
		console.error('VS Code extension-host failure details are malformed; the aggregate result remains failed.');
		process.exit(1);
	}
	for (const failure of summary.failureDetails) {
		report(`Failed test: ${sanitize(failure.title)} — ${sanitize(failure.error)}`);
	}
}
if (failures > 0 || runnerOutcome !== 'success') {
	process.exit(1);
}

function sanitize(value) {
	return String(value)
		.replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
		.replace(/[\u0000-\u001f\u007f]/g, ' ')
		.replace(/\bBearer\s+\S+/gi, 'Bearer [redacted]')
		.replace(/\b(?:sk[-_][A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{12,})\b/g, '[redacted-secret]')
		.replace(/(["']?(?:api[_-]?key|api[_-]?secret|password|passwd|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token|refresh[_-]?token|session[_-]?token|id[_-]?token|token|auth(?:orization)?|credential(?:s)?|private[_-]?key|signing[_-]?key|subscription[_-]?key)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}&]+)/gi, '$1[redacted]')
		.replace(/(https?:\/\/)[^/@\s]+@/gi, '$1[redacted]@')
		.replace(/([?&](?:token|key|secret|auth|signature|api_key)=)[^&#\s]+/gi, '$1[redacted]')
		.replace(/\b[A-Za-z]:\\Users\\[^\\\s]+/g, '[user-path]')
		.replace(/\/(?:home|Users)\/[^/\s]+/g, '[user-path]')
		.slice(0, 500);
}

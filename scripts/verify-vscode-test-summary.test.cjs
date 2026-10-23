const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { afterEach, test } = require('node:test');

const verifier = path.join(__dirname, 'verify-vscode-test-summary.cjs');
const temporaryDirectories = [];

afterEach(() => {
	for (const directory of temporaryDirectories.splice(0)) {
		fs.rmSync(directory, { recursive: true, force: true });
	}
});

function runVerifier(outcome, summary) {
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-vscode-summary-'));
	temporaryDirectories.push(directory);
	const summaryPath = path.join(directory, 'summary.json');
	if (summary !== undefined) {
		fs.writeFileSync(summaryPath, JSON.stringify(summary), 'utf8');
	}
	const environment = {
		...process.env,
		AQIRON_TEST_OUTDIR: directory,
		AQIRON_VSCODE_TEST_SUMMARY: summaryPath,
		GITHUB_STEP_SUMMARY: '',
	};
	if (outcome !== undefined) {
		environment.AQIRON_VSCODE_TEST_OUTCOME = outcome;
	} else {
		delete environment.AQIRON_VSCODE_TEST_OUTCOME;
	}
	return spawnSync(process.execPath, [verifier], {
		encoding: 'utf8',
		env: environment,
	});
}

test('reports a skipped extension-host suite as not run without calling it a pass', () => {
	const result = runVerifier('skipped', undefined);
	assert.equal(result.status, 0, result.stderr);
	assert.match(result.stdout, /NOT RUN/);
	assert.match(result.stdout, /no test counts are available/);
	assert.doesNotMatch(result.stdout, /passed/);
});

test('reports counts and preserves failure when the suite ran and tests failed', () => {
	const result = runVerifier('failure', { tests: 2, passes: 1, failures: 1, pending: 0 });
	assert.equal(result.status, 1);
	assert.match(result.stdout, /1 passed, 1 failed, 0 skipped \(2 total\)/);
	assert.match(result.stdout, /runner outcome: failure/);
});

test('keeps an executed runner failure without a summary explicitly unverified', () => {
	const result = runVerifier('failure', undefined);
	assert.equal(result.status, 1);
	assert.match(result.stderr, /runner outcome: failure/);
	assert.match(result.stderr, /Execution and test counts are unverified/);
});

test('rejects a successful runner outcome without a valid summary', () => {
	const result = runVerifier('success', { tests: 0, passes: 0, failures: 0, pending: 0 });
	assert.equal(result.status, 1);
	assert.match(result.stderr, /valid non-empty summary/);
});

test('fails closed when the workflow did not provide the runner outcome', () => {
	const result = runVerifier(undefined, { tests: 1, passes: 1, failures: 0, pending: 0 });
	assert.equal(result.status, 1);
	assert.match(result.stderr, /runner outcome is unavailable or invalid/);
});

test('accepts a non-empty successful summary only when the runner succeeded', () => {
	const result = runVerifier('success', { tests: 3, passes: 2, failures: 0, pending: 1 });
	assert.equal(result.status, 0, result.stderr);
	assert.match(result.stdout, /2 passed, 0 failed, 1 skipped \(3 total\)/);
});

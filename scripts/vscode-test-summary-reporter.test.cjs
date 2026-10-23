const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { afterEach, test } = require('node:test');

const Reporter = require('./vscode-test-summary-reporter.cjs');
const temporaryDirectories = [];

afterEach(() => {
	for (const directory of temporaryDirectories.splice(0)) {
		fs.rmSync(directory, { recursive: true, force: true });
	}
});

test('captures failed titles and bounded sanitized error messages in the test summary', () => {
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-vscode-reporter-'));
	temporaryDirectories.push(directory);
	const summaryPath = path.join(directory, 'summary.json');
	const previousPath = process.env.AQIRON_VSCODE_TEST_SUMMARY;
	process.env.AQIRON_VSCODE_TEST_SUMMARY = summaryPath;
	try {
		const runner = new EventEmitter();
		new Reporter(runner);
		runner.emit('fail', { fullTitle: () => 'Suite > apiKey: title_synthetic_secret' }, { message: 'Bearer abc123456789 at C:\\Users\\person\\secret.txt' });
		runner.emit('end');
		const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
		assert.deepEqual({ tests: summary.tests, passes: summary.passes, failures: summary.failures, pending: summary.pending }, { tests: 1, passes: 0, failures: 1, pending: 0 });
		assert.deepEqual(summary.failureDetails, [{ title: 'Suite > apiKey: [redacted]', error: 'Bearer [redacted] at [user-path]\\secret.txt' }]);
		assert.doesNotMatch(JSON.stringify(summary), /title_synthetic_secret/);
	} finally {
		if (previousPath === undefined) {delete process.env.AQIRON_VSCODE_TEST_SUMMARY;}
		else {process.env.AQIRON_VSCODE_TEST_SUMMARY = previousPath;}
	}
});

test('redacts common credential fields, quoted JSON values, Google keys, and provider tokens', () => {
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-vscode-redaction-'));
	temporaryDirectories.push(directory);
	const summaryPath = path.join(directory, 'summary.json');
	const previousPath = process.env.AQIRON_VSCODE_TEST_SUMMARY;
	process.env.AQIRON_VSCODE_TEST_SUMMARY = summaryPath;
	const secrets = [
		'synthetic_api_key_value', 'synthetic_api_dash_value', 'synthetic_api_camel_value',
		'synthetic_password_value', 'synthetic_passwd_value', 'synthetic_secret_value',
		'synthetic_client_secret_value', 'synthetic_access_token_value', 'synthetic_refresh_token_value',
		'synthetic_id_token_value', 'synthetic_secret_key_value', 'synthetic_session_token_value', 'AIzaSySyntheticGoogleKey0123456789',
		'sk-ant-api03-synthetic-provider-key', 'sk-or-v1-synthetic-provider-key',
		'ghp_syntheticGitHubTokenValue', 'xoxb-synthetic-slack-token',
	];
	try {
		const runner = new EventEmitter();
		new Reporter(runner);
		runner.emit('fail', { title: 'API-KEY: synthetic_api_dash_value' }, { message: [
			'operation failed',
			'api_key=synthetic_api_key_value',
			'api-key: "synthetic_api_dash_value"',
			'apiKey: \'synthetic_api_camel_value\'',
			'password=synthetic_password_value',
			'passwd: "synthetic_passwd_value"',
			'secret="synthetic_secret_value"',
			'{"client_secret":"synthetic_client_secret_value", "access_token": "synthetic_access_token_value"}',
			'refreshToken = synthetic_refresh_token_value',
			'ID-token:\'synthetic_id_token_value\'',
			'secret_key=synthetic_secret_key_value sessionToken: synthetic_session_token_value',
			'Google=AIzaSySyntheticGoogleKey0123456789',
			'Anthropic=sk-ant-api03-synthetic-provider-key OpenRouter=sk-or-v1-synthetic-provider-key',
			'GitHub=ghp_syntheticGitHubTokenValue Slack=xoxb-synthetic-slack-token',
		].join('; ')});
		runner.emit('end');
		const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
		const serialized = JSON.stringify(summary.failureDetails);
		for (const secret of secrets) {assert.ok(!serialized.includes(secret), `synthetic secret leaked: ${secret}`);}
		assert.match(serialized, /operation failed/);
		assert.match(serialized, /api_key=\[redacted\]/);
		assert.equal(summary.failureDetails[0].title, 'API-KEY: [redacted]');
	} finally {
		if (previousPath === undefined) {delete process.env.AQIRON_VSCODE_TEST_SUMMARY;}
		else {process.env.AQIRON_VSCODE_TEST_SUMMARY = previousPath;}
	}
});

test('caps the number of failure details while preserving aggregate counts', () => {
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-vscode-reporter-limit-'));
	temporaryDirectories.push(directory);
	const summaryPath = path.join(directory, 'summary.json');
	const previousPath = process.env.AQIRON_VSCODE_TEST_SUMMARY;
	process.env.AQIRON_VSCODE_TEST_SUMMARY = summaryPath;
	try {
		const runner = new EventEmitter();
		new Reporter(runner);
		for (let index = 0; index < 30; index += 1) {runner.emit('fail', { title: `failure ${index}` }, { message: 'failure' });}
		runner.emit('end');
		const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
		assert.equal(summary.failures, 30);
		assert.equal(summary.failureDetails.length, 25);
	} finally {
		if (previousPath === undefined) {delete process.env.AQIRON_VSCODE_TEST_SUMMARY;}
		else {process.env.AQIRON_VSCODE_TEST_SUMMARY = previousPath;}
	}
});

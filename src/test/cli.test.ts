import * as assert from 'assert';
import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CliCoreClient, CliOutput, runCli } from '../../packages/cli/src/cli';
import { CoreScanStartResult } from '../../packages/core/src/runtime/protocol';
import { createJsonReport } from '../../packages/core/src/reports/reportExporters';
import { CoreClient } from '../../packages/core/src/client';

suite('Aqiron CLI', () => {
	test('parses workspace path, starts Core through its client, scans and prints the final Core result', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const stdout = captureOutput();
		const stderr = captureOutput();
		const fake = new FakeCoreClient();
		try {
			const code = await runCli(['scan', workspace, '--trust-local-workspace'], { stdout, stderr, createClient: () => fake });
			assert.equal(code, 0);
			assert.equal(fake.request?.workspaceRoot, path.resolve(workspace));
			assert.equal(fake.request?.mode, 'deep');
			assert.equal(fake.request?.trusted, true, 'Core receives trusted=true only after the user opts in with --trust-local-workspace');
			assert.equal(fake.startCalls, 1);
			assert.equal(fake.stopCalls, 1);
			assert.match(stdout.text, /Findings: 2/);
			assert.match(stdout.text, /High:\s+1/);
			assert.match(stdout.text, /Low:\s+1/);
			assert.equal(stderr.text, '');
		} finally {
			fs.rmSync(workspace, { recursive: true, force: true });
		}
	});

	test('streams only real progress events correlated to the scan request', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const stdout = captureOutput();
		const fake = new FakeCoreClient();
		fake.onStart = async (request) => {
			fake.emit({ event: 'stage', requestId: 'unrelated', payload: { type: 'stage', stage: { name: 'Wrong', status: 'running', progress: 1 } } });
			fake.emit({ event: 'stage', requestId: request.requestId, payload: { type: 'stage', stage: { name: 'Native analysis', status: 'running', progress: 10 } } });
			fake.emit({ event: 'tool', requestId: request.requestId, payload: { type: 'tool', tool: { label: 'Semgrep', status: 'unavailable' } } });
		};
		try {
			await runCli(['scan', workspace, '--trust-local-workspace'], { stdout, stderr: captureOutput(), createClient: () => fake });
			assert.match(stdout.text, /Native analysis: running/);
			assert.doesNotMatch(stdout.text, /10%/);
			assert.match(stdout.text, /Scanner: Semgrep \(unavailable\)/);
			assert.doesNotMatch(stdout.text, /Wrong/);
		} finally {
			fs.rmSync(workspace, { recursive: true, force: true });
		}
	});

	test('writes stable JSON and Core-generated SARIF without mixing text into stdout', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const json = captureOutput();
		const sarif = captureOutput();
		try {
			assert.equal(await runCli(['scan', workspace, '--format', 'json', '--trust-local-workspace'], { stdout: json, stderr: captureOutput(), createClient: () => new FakeCoreClient() }), 0);
			assert.equal(JSON.parse(json.text).schemaVersion, 1);
			assert.equal(JSON.parse(json.text).report.summary.total, 2);
			assert.doesNotMatch(json.text, /Aqiron Security|Scanning\.\.\./);
			assert.doesNotMatch(json.text, /sk-test-secret-value-123456/);
			assert.match(json.text, /\[REDACTED\]/);
			assert.equal(await runCli(['scan', workspace, '--format', 'sarif', '--trust-local-workspace'], { stdout: sarif, stderr: captureOutput(), createClient: () => new FakeCoreClient() }), 0);
			const sarifDocument = JSON.parse(sarif.text);
			assert.equal(sarifDocument.version, '2.1.0');
			assert.equal(sarifDocument.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
			assert.doesNotMatch(sarif.text, /Aqiron Security\n|Scanning\.\.\./);
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('JSON adds scan skip diagnostics while preserving the existing scan and report fields', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const stdout = captureOutput();
		const fake = new FakeCoreClient();
		fake.skippedFiles = 2;
		fake.skipReasons = { 'line-limit': 1, 'size-limit': 1 };
		try {
			assert.equal(await runCli(['scan', workspace, '--format', 'json', '--trust-local-workspace'], { stdout, stderr: captureOutput(), createClient: () => fake }), 0);
			const result = JSON.parse(stdout.text) as { scan: Record<string, unknown>; report: { summary: { total: number } } };
			assert.equal(result.scan.filesScanned, 8);
			assert.equal(result.scan.skippedFiles, 2);
			assert.equal(result.scan.coverageDiagnosticsAvailable, true);
			assert.equal(result.scan.coverageDiagnosticsPresent, true);
			assert.equal(result.scan.coverageDiagnosticsValid, true);
			assert.equal(result.scan.coverageStatus, 'partial');
			assert.equal(result.scan.skippedFilesCountCertainty, 'exact');
			assert.deepEqual(result.scan.skipReasons, { 'line-limit': 1, 'size-limit': 1 });
			assert.equal(result.report.summary.total, 2);

			const conflictJson = captureOutput();
			const conflictFake = new FakeCoreClient();
			conflictFake.skippedFiles = 1;
			conflictFake.skipReasons = { first: 2, second: 3 };
			assert.equal(await runCli(['scan', workspace, '--format', 'json', '--trust-local-workspace'], { stdout: conflictJson, stderr: captureOutput(), createClient: () => conflictFake }), 0);
			const conflictScan = (JSON.parse(conflictJson.text) as { scan: Record<string, unknown> }).scan;
			assert.equal(conflictScan.skippedFiles, 5);
			assert.equal(conflictScan.skippedFilesIsLowerBound, true);
			assert.equal(conflictScan.skippedFilesCountCertainty, 'lower-bound');
			assert.equal(conflictScan.skipCountConflict, true);

			const legacyJson = captureOutput();
			assert.equal(await runCli(['scan', workspace, '--format', 'json', '--trust-local-workspace'], { stdout: legacyJson, stderr: captureOutput(), createClient: () => new FakeCoreClient() }), 0);
			const legacyScan = (JSON.parse(legacyJson.text) as { scan: Record<string, unknown> }).scan;
			assert.equal(legacyScan.coverageStatus, 'unavailable');
			assert.equal(legacyScan.coverageDiagnosticsPresent, false);
			assert.equal(legacyScan.skippedFilesCountCertainty, 'indeterminate');
			assert.equal('skippedFiles' in legacyScan, false);
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('text reports partial coverage and reasons, tolerating malformed optional diagnostics', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		try {
			const partial = captureOutput();
			const fake = new FakeCoreClient();
			fake.skippedFiles = 1;
			fake.skipReasons = { 'line-limit': 1 };
			assert.equal(await runCli(['scan', workspace, '--trust-local-workspace'], { stdout: partial, stderr: captureOutput(), createClient: () => fake }), 0);
			assert.match(partial.text, /Coverage: Partial \(1 file skipped\)/);
			assert.match(partial.text, /Skip reasons: line-limit \(1\)/);
			assert.match(partial.text, /Findings: 2/);

			const reasonsOnly = captureOutput();
			const reasonsOnlyFake = new FakeCoreClient();
			reasonsOnlyFake.skipReasons = { 'line-limit': 1 };
			assert.equal(await runCli(['scan', workspace, '--trust-local-workspace'], { stdout: reasonsOnly, stderr: captureOutput(), createClient: () => reasonsOnlyFake }), 0);
			assert.match(reasonsOnly.text, /Coverage: Partial \(1 file skipped\)/);

			const explicitZeroWithReasons = captureOutput();
			const explicitZeroWithReasonsFake = new FakeCoreClient();
			explicitZeroWithReasonsFake.skippedFiles = 0;
			explicitZeroWithReasonsFake.skipReasons = { 'line-limit': 2 };
			assert.equal(await runCli(['scan', workspace, '--trust-local-workspace'], { stdout: explicitZeroWithReasons, stderr: captureOutput(), createClient: () => explicitZeroWithReasonsFake }), 0);
			assert.match(explicitZeroWithReasons.text, /Coverage: Partial \(at least 2 files skipped; conflicting totals, exact count unavailable\)/);

			const explicitExceedsReasons = captureOutput();
			const explicitExceedsReasonsFake = new FakeCoreClient();
			explicitExceedsReasonsFake.skippedFiles = 8;
			explicitExceedsReasonsFake.skipReasons = { 'line-limit': 2 };
			assert.equal(await runCli(['scan', workspace, '--trust-local-workspace'], { stdout: explicitExceedsReasons, stderr: captureOutput(), createClient: () => explicitExceedsReasonsFake }), 0);
			assert.match(explicitExceedsReasons.text, /at least 8 files skipped; conflicting totals/);

			const clean = captureOutput();
			const cleanFake = new FakeCoreClient();
			cleanFake.skippedFiles = 0;
			cleanFake.skipReasons = {};
			assert.equal(await runCli(['scan', workspace, '--trust-local-workspace'], { stdout: clean, stderr: captureOutput(), createClient: () => cleanFake }), 0);
			assert.doesNotMatch(clean.text, /Coverage: Partial|Coverage: Unavailable/);

			const complete = captureOutput();
			assert.equal(await runCli(['scan', workspace, '--trust-local-workspace'], { stdout: complete, stderr: captureOutput(), createClient: () => new FakeCoreClient() }), 0);
			assert.match(complete.text, /Coverage: Unavailable/);

			const malformed = captureOutput();
			const malformedFake = new FakeCoreClient();
			malformedFake.skippedFiles = -1;
			malformedFake.skipReasons = { '<img onerror=alert(1)>': -2, 'bad\u001b[31m': 1 };
			assert.equal(await runCli(['scan', workspace, '--trust-local-workspace'], { stdout: malformed, stderr: captureOutput(), createClient: () => malformedFake }), 0);
			assert.doesNotMatch(malformed.text, /<img|bad|Coverage: Partial/);
			assert.match(malformed.text, /Coverage: Unavailable/);

			const overflowJson = captureOutput();
			const overflowFake = new FakeCoreClient();
			overflowFake.skipReasons = { first: Number.MAX_SAFE_INTEGER, second: 1 };
			assert.equal(await runCli(['scan', workspace, '--format', 'json', '--trust-local-workspace'], { stdout: overflowJson, stderr: captureOutput(), createClient: () => overflowFake }), 0);
			const overflowScan = (JSON.parse(overflowJson.text) as { scan: Record<string, unknown> }).scan;
			assert.equal(overflowScan.skippedFiles, Number.MAX_SAFE_INTEGER);
			assert.equal(overflowScan.skippedFilesIsLowerBound, true);
			assert.equal(overflowScan.skippedFilesCountCertainty, 'lower-bound');
			assert.equal(overflowScan.coverageStatus, 'partial');

			const overflowText = captureOutput();
			assert.equal(await runCli(['scan', workspace, '--trust-local-workspace'], { stdout: overflowText, stderr: captureOutput(), createClient: () => overflowFake }), 0);
			assert.match(overflowText.text, new RegExp(`at least ${Number.MAX_SAFE_INTEGER} files skipped`));

			const safeSumJson = captureOutput();
			const safeSumFake = new FakeCoreClient();
			safeSumFake.skipReasons = { first: Number.MAX_SAFE_INTEGER - 4, second: 3 };
			assert.equal(await runCli(['scan', workspace, '--format', 'json', '--trust-local-workspace'], { stdout: safeSumJson, stderr: captureOutput(), createClient: () => safeSumFake }), 0);
			const safeSumScan = (JSON.parse(safeSumJson.text) as { scan: Record<string, unknown> }).scan;
			assert.equal(safeSumScan.skippedFiles, Number.MAX_SAFE_INTEGER - 1);
			assert.equal(safeSumScan.skippedFilesIsLowerBound, undefined);

			const veryLargeExplicitJson = captureOutput();
			const veryLargeExplicitFake = new FakeCoreClient();
			veryLargeExplicitFake.skippedFiles = Number.MAX_SAFE_INTEGER;
			assert.equal(await runCli(['scan', workspace, '--format', 'json', '--trust-local-workspace'], { stdout: veryLargeExplicitJson, stderr: captureOutput(), createClient: () => veryLargeExplicitFake }), 0);
			const veryLargeExplicitScan = (JSON.parse(veryLargeExplicitJson.text) as { scan: Record<string, unknown> }).scan;
			assert.equal(veryLargeExplicitScan.skippedFiles, Number.MAX_SAFE_INTEGER);
			assert.equal(veryLargeExplicitScan.skippedFilesIsLowerBound, undefined);
			assert.equal(veryLargeExplicitScan.skippedFilesCountCertainty, 'exact');
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('writes output files exclusively and preserves an existing file', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-output-'));
		const outputPath = path.join(outputDir, 'result.json');
		try {
			const stdout = captureOutput();
			assert.equal(await runCli(['scan', workspace, '--format', 'json', '--output', outputPath, '--trust-local-workspace'], { stdout, stderr: captureOutput(), createClient: () => new FakeCoreClient() }), 0);
			assert.equal(JSON.parse(fs.readFileSync(outputPath, 'utf8')).report.summary.total, 2);
			assert.equal(stdout.text, '');
			assert.equal(await runCli(['scan', workspace, '--format', 'json', '--output', outputPath, '--trust-local-workspace'], { stderr: captureOutput(), createClient: () => new FakeCoreClient() }), 1);
			assert.equal(JSON.parse(fs.readFileSync(outputPath, 'utf8')).report.summary.total, 2);
		} finally {
			fs.rmSync(workspace, { recursive: true, force: true });
			fs.rmSync(outputDir, { recursive: true, force: true });
		}
	});

	test('requires output for PDF and preserves trust validation', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const fake = new FakeCoreClient();
		try {
			const missingOutput = captureOutput();
			assert.equal(await runCli(['scan', workspace, '--format', 'pdf', '--trust-local-workspace'], { stderr: missingOutput, createClient: () => fake }), 2);
			assert.match(missingOutput.text, /PDF output requires --output/);
			assert.equal(fake.startCalls, 0);
			const missingTrust = captureOutput();
			assert.equal(await runCli(['scan', workspace, '--format', 'pdf', '--output', 'report.pdf'], { stderr: missingTrust, createClient: () => fake }), 2);
			assert.match(missingTrust.text, /Workspace trust is required/);
			assert.equal(fake.startCalls, 0);
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('writes the PDF returned by scan.start to an exclusive output file without stdout output', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-output-'));
		const outputPath = path.join(outputDir, 'report.pdf');
		const fake = new FakeCoreClient();
		const stdout = captureOutput();
		const expectedPdf = Buffer.concat([Buffer.from('%PDF-1.4\nAqiron report '), Buffer.from([0xe9])]);
		try {
			assert.equal(await runCli(['scan', workspace, '--format', 'pdf', '--output', outputPath, '--trust-local-workspace'], { stdout, stderr: captureOutput(), createClient: () => fake }), 0);
			assert.equal(stdout.text, '');
			assert.equal(fake.startCalls, 1);
			assert.ok(fs.readFileSync(outputPath).equals(expectedPdf));
			assert.equal(await runCli(['scan', workspace, '--format', 'pdf', '--output', outputPath, '--trust-local-workspace'], { stderr: captureOutput(), createClient: () => new FakeCoreClient() }), 1);
			assert.ok(fs.readFileSync(outputPath).equals(expectedPdf));
		} finally {
			fs.rmSync(workspace, { recursive: true, force: true });
			fs.rmSync(outputDir, { recursive: true, force: true });
		}
	});

	test('reports scan failure during PDF mode without exposing errors or creating an artifact', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const outputPath = path.join(workspace, 'report.pdf');
		const stdout = captureOutput();
		const stderr = captureOutput();
		const fake = new FakeCoreClient();
		fake.onStart = async () => { throw new Error('rawEvidence=sk-private-value'); };
		try {
			assert.equal(await runCli(['scan', workspace, '--format', 'pdf', '--output', outputPath, '--trust-local-workspace'], { stdout, stderr, createClient: () => fake }), 1);
			assert.equal(stdout.text, '');
			assert.match(stderr.text, /Core scan failed/);
			assert.doesNotMatch(stderr.text, /sk-private-value/);
			assert.equal(fs.existsSync(outputPath), false);
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('PDF output still honors fail-on severity after writing the report', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const outputPath = path.join(workspace, 'report.pdf');
		const stderr = captureOutput();
		try {
			assert.equal(await runCli(['scan', workspace, '--format', 'pdf', '--output', outputPath, '--fail-on', 'high', '--trust-local-workspace'], { stderr, createClient: () => new FakeCoreClient() }), 1);
			assert.match(stderr.text, /Policy violation/);
			assert.ok(fs.readFileSync(outputPath).subarray(0, 8).equals(Buffer.from('%PDF-1.4')));
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('reports output directory failures without dumping filesystem details', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const output = captureOutput();
		const stderr = captureOutput();
		try {
			const target = path.join(workspace, 'missing-parent', 'result.json');
			assert.equal(await runCli(['scan', workspace, '--format', 'json', '--output', target, '--trust-local-workspace'], { stdout: output, stderr, createClient: () => new FakeCoreClient() }), 1);
			assert.equal(output.text, '');
			assert.match(stderr.text, /Output failed/);
			assert.doesNotMatch(stderr.text, /missing-parent/);
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('removes a newly-created partial PDF when writing fails', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const outputPath = path.join(workspace, 'partial.pdf');
		const fsRuntime = require('node:fs') as { writeFileSync: (fd: number, data: string, encoding: BufferEncoding) => void };
		const originalWriteFileSync = fsRuntime.writeFileSync;
		const stderr = captureOutput();
		fsRuntime.writeFileSync = (fd, data, encoding) => {
			if (typeof fd === 'number') { throw new Error('rawEvidence=private'); }
			originalWriteFileSync(fd, data, encoding);
		};
		try {
			assert.equal(await runCli(['scan', workspace, '--format', 'pdf', '--output', outputPath, '--trust-local-workspace'], { stderr, createClient: () => new FakeCoreClient() }), 1);
			assert.match(stderr.text, /Output failed/);
			assert.doesNotMatch(stderr.text, /private/);
			assert.equal(fs.existsSync(outputPath), false);
		} finally {
			fsRuntime.writeFileSync = originalWriteFileSync;
			fs.rmSync(workspace, { recursive: true, force: true });
		}
	});

	for (const [threshold, expected] of [['critical', false], ['high', true], ['medium', true], ['low', true]] as const) {
		test(`--fail-on ${threshold} gates against actual findings`, async () => {
			const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
			const stderr = captureOutput();
			try {
				const code = await runCli(['scan', workspace, '--fail-on', threshold, '--trust-local-workspace'], { stdout: captureOutput(), stderr, createClient: () => new FakeCoreClient() });
				assert.equal(code, expected ? 1 : 0);
				assert.equal(stderr.text.includes('Policy violation'), expected);
			} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
		});
	}

	test('all fail-on thresholds succeed when Core returns no findings', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		try {
			for (const threshold of ['critical', 'high', 'medium', 'low']) {
				const fake = new FakeCoreClient();
				fake.emptyFindings = true;
				const stderr = captureOutput();
				assert.equal(await runCli(['scan', workspace, '--fail-on', threshold, '--trust-local-workspace'], { stdout: captureOutput(), stderr, createClient: () => fake }), 0);
				assert.equal(stderr.text, '');
			}
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('reports startup and scan failures separately without exposing raw error content', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		try {
			const startup = new FakeCoreClient(); startup.onStartUp = async () => { throw new Error('credential=secret-value'); };
			const startupError = captureOutput();
			assert.equal(await runCli(['scan', workspace, '--trust-local-workspace'], { stdout: captureOutput(), stderr: startupError, createClient: () => startup }), 1);
			assert.match(startupError.text, /Core startup failed/);
			assert.doesNotMatch(startupError.text, /secret-value/);
			const scan = new FakeCoreClient(); scan.onStart = async () => { throw new Error('credential=secret-value'); };
			const scanError = captureOutput();
			assert.equal(await runCli(['scan', workspace, '--trust-local-workspace'], { stdout: captureOutput(), stderr: scanError, createClient: () => scan }), 1);
			assert.match(scanError.text, /Core scan failed/);
			assert.doesNotMatch(scanError.text, /secret-value/);
			assert.equal(scan.stopCalls, 1);
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('signal cancellation calls Core cancellation and always stops the client', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const fake = new FakeCoreClient();
		let cancelSignal!: () => void;
		fake.onStart = async () => { cancelSignal(); throw new Error('Core request cancelled.'); };
		try {
			const code = await runCli(['scan', workspace, '--trust-local-workspace'], {
				stderr: captureOutput(), createClient: () => fake,
				registerSignalHandlers: (handlers) => { cancelSignal = handlers.onInterrupt; return () => undefined; },
			});
			assert.equal(code, 1);
			assert.equal(fake.cancelCalls, 1);
			assert.equal(fake.stopCalls, 1);
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('rejects unknown format', async () => {
		const stderr = captureOutput();
		assert.equal(await runCli(['scan', '.', '--format', 'xml', '--trust-local-workspace'], { stderr }), 2);
		assert.match(stderr.text, /Invalid format/);
	});

	test('rejects invalid severity values and duplicate options as usage errors', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		try {
			for (const args of [
				['--fail-on', 'toString'],
				['--format', 'json', '--format', 'sarif'],
				['--fail-on', 'high', '--fail-on', 'low'],
				['--output', 'a.json', '--output', 'b.json'],
			]) {
				const stderr = captureOutput();
				assert.equal(await runCli(['scan', workspace, ...args, '--trust-local-workspace'], { stderr }), 2);
				assert.match(stderr.text, /Usage: aqiron scan/);
			}
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('rejects invalid command/path with nonzero status without starting Core', async () => {
		const fake = new FakeCoreClient();
		const stderr = captureOutput();
		assert.equal(await runCli(['report', '.'], { stderr, createClient: () => fake }), 2);
		assert.equal(await runCli(['scan', '.'], { stderr, createClient: () => fake }), 2, 'scan requires the explicit trust option');
		assert.equal(await runCli(['scan', path.join(os.tmpdir(), 'aqiron-cli-missing-path'), '--trust-local-workspace'], { stderr, createClient: () => fake }), 2);
		assert.equal(fake.startCalls, 0);
	});

	test('reports Core failures and always terminates the client', async () => {
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
		const stderr = captureOutput();
		const fake = new FakeCoreClient();
		fake.onStart = async () => { throw new Error('fixture Core failure'); };
		try {
			assert.equal(await runCli(['scan', workspace, '--trust-local-workspace'], { stderr, stdout: captureOutput(), createClient: () => fake }), 1);
			assert.match(stderr.text, /Core scan failed/);
			assert.doesNotMatch(stderr.text, /fixture Core failure/);
			assert.equal(fake.stopCalls, 1);
		} finally {
			fs.rmSync(workspace, { recursive: true, force: true });
		}
	});

	test('CLI adapter contains no scanner-specific implementation or VS Code dependency', () => {
		const source = fs.readFileSync(path.resolve(__dirname, '../../../packages/cli/src/cli.ts'), 'utf8');
		assert.doesNotMatch(source, /from ['"].*(?:scanner|vscode)/i);
		assert.doesNotMatch(source, /scanFileContent|scanWorkspace\s*\(/);
	});

	test('default CoreClient restart behavior for the VS Code client remains enabled', () => {
		const client = new CoreClient({ clientVersion: 'test', runtimePath: path.resolve(__dirname, '../../../dist/core-runtime.js'), restartOnCrash: true });
		const manager = (client as unknown as { manager: { options: { restartOnCrash?: boolean } } }).manager;
		assert.equal(manager.options.restartOnCrash, true);
	});

	test('built CLI scans the real Core characterization fixture end to end', function () {
		this.timeout(30_000);
		const cliPath = path.resolve(__dirname, '../../../dist/aqiron-cli.js');
		if (!fs.existsSync(cliPath)) { this.skip(); return; }
		const fixture = path.resolve(__dirname, '../../../src/test/fixtures/file-scan/flutter');
		const result = childProcess.spawnSync(process.execPath, [cliPath, 'scan', fixture, '--trust-local-workspace'], { encoding: 'utf8', timeout: 25_000, windowsHide: true });
		assert.equal(result.error, undefined, result.error?.message);
		assert.equal(result.status, 0, result.stderr);
		assert.match(result.stdout, /Findings: [1-9]\d*/);
		assert.match(result.stdout, /Critical:\s+\d+/);
		assert.doesNotMatch(result.stdout + result.stderr, /sk-test-secret-value-123456/);
	});

	test('built CLI JSON and SARIF consume the Core report bundle', function () {
		this.timeout(60_000);
		const cliPath = path.resolve(__dirname, '../../../dist/aqiron-cli.js');
		if (!fs.existsSync(cliPath)) { this.skip(); return; }
		const fixture = path.resolve(__dirname, '../../../src/test/fixtures/file-scan/flutter');
		for (const format of ['json', 'sarif'] as const) {
			const result = childProcess.spawnSync(process.execPath, [cliPath, 'scan', fixture, '--format', format, '--trust-local-workspace'], { encoding: 'utf8', timeout: 50_000, windowsHide: true });
			assert.equal(result.error, undefined, result.error?.message);
			assert.equal(result.status, 0, result.stderr);
			const document = JSON.parse(result.stdout) as { report?: { summary?: { total?: number }; findings?: Array<{ rawEvidence?: unknown }> }; version?: string; runs?: Array<{ results?: unknown[] }> };
			if (format === 'json') {
				assert.ok((document.report?.summary?.total ?? 0) > 0);
				assert.doesNotMatch(result.stdout, /sk-test-secret-value-123456/);
			} else {
				assert.equal(document.version, '2.1.0');
				assert.ok((document.runs?.[0]?.results?.length ?? 0) > 0);
				assert.doesNotMatch(result.stdout, /sk-test-secret-value-123456/);
			}
		}
	});

	test('built CLI applies Core-owned workspace custom rules without VS Code settings', function () {
		this.timeout(30_000);
		const cliPath = path.resolve(__dirname, '../../../dist/aqiron-cli.js');
		if (!fs.existsSync(cliPath)) { this.skip(); return; }
		const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-rules-'));
		try {
			fs.mkdirSync(path.join(workspace, 'lib'), { recursive: true });
			fs.writeFileSync(path.join(workspace, 'pubspec.yaml'), 'name: cli_rule_fixture\nflutter:\n');
			fs.writeFileSync(path.join(workspace, 'lib', 'sample.dart'), 'const cliRuleSentinel = "unsafe_cli_fixture_value";\n');
			const rulesDirectory = path.join(workspace, '.aqiron-security');
			fs.mkdirSync(rulesDirectory);
			fs.writeFileSync(path.join(rulesDirectory, 'custom-rules.json'), JSON.stringify({ version: 1, rules: [{ id: 'cli.test.shared-rule', title: 'CLI shared rule', message: 'Shared Core rule matched.', severity: 'High', pattern: 'unsafe_cli_fixture_value', extensions: ['.dart'] }] }));
			const result = childProcess.spawnSync(process.execPath, [cliPath, 'scan', workspace, '--format', 'json', '--trust-local-workspace'], { encoding: 'utf8', timeout: 25_000, windowsHide: true });
			assert.equal(result.error, undefined, result.error?.message);
			assert.equal(result.status, 0, result.stderr);
			const document = JSON.parse(result.stdout) as { report: { findings: Array<{ ruleId: string; rawEvidence?: unknown }> } };
			assert.ok(document.report.findings.some((finding) => finding.ruleId === 'cli.test.shared-rule'));
			assert.doesNotMatch(result.stdout + result.stderr, /unsafe_cli_fixture_value/);
		} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
	});

	test('built CLI writes the Core PDF report returned through scan.start', function () {
		this.timeout(45_000);
		const cliPath = path.resolve(__dirname, '../../../dist/aqiron-cli.js');
		if (!fs.existsSync(cliPath)) { this.skip(); return; }
		const fixture = path.resolve(__dirname, '../../../src/test/fixtures/file-scan/flutter');
		const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-pdf-'));
		const outputPath = path.join(outputDir, 'report.pdf');
		try {
			const result = childProcess.spawnSync(process.execPath, [cliPath, 'scan', fixture, '--format', 'pdf', '--output', outputPath, '--trust-local-workspace'], { encoding: 'utf8', timeout: 40_000, windowsHide: true });
			assert.equal(result.error, undefined, result.error?.message);
			assert.equal(result.status, 0, result.stderr);
			assert.equal(result.stdout, '', 'PDF bytes are written only to the artifact');
			const pdf = fs.readFileSync(outputPath).toString('latin1');
			assert.ok(pdf.startsWith('%PDF-1.4'));
			assert.ok(pdf.includes('/Type /Pages'));
			assert.match(pdf, /\/Count \d+/);
			assert.ok(pdf.includes('Security Assessment Report'));
			assert.ok(pdf.includes('/Subtype /Image'), 'the Core branding asset is rendered');
			assert.ok(pdf.includes('Executive Summary'));
			assert.doesNotMatch(pdf, /sk-test-secret-value-123456/);
		} finally { fs.rmSync(outputDir, { recursive: true, force: true }); }
	});
});

class FakeCoreClient implements CliCoreClient {
	private readonly listeners: Array<(event: { event: string; requestId?: string; payload?: unknown }) => void> = [];
	startCalls = 0;
	stopCalls = 0;
	cancelCalls = 0;
	emptyFindings = false;
	filesScanned = 8;
	skippedFiles?: number;
	skipReasons?: Partial<Record<string, number>>;
	request?: { requestId: string; workspaceRoot: string; trusted: boolean; mode: 'deep' };
	onStart?: (request: NonNullable<FakeCoreClient['request']>) => Promise<void>;
	onStartUp?: () => Promise<void>;
	async start(): Promise<void> { await this.onStartUp?.(); }
	async cancelRequest(): Promise<void> { this.cancelCalls += 1; }

	on(_event: 'event', listener: (event: { event: string; requestId?: string; payload?: unknown }) => void): this {
		this.listeners.push(listener);
		return this;
	}

	removeListener(_event: 'event', listener: (event: { event: string; requestId?: string; payload?: unknown }) => void): this {
		const index = this.listeners.indexOf(listener);
		if (index >= 0) {this.listeners.splice(index, 1);}
		return this;
	}

	async startScan(request: NonNullable<FakeCoreClient['request']>): Promise<CoreScanStartResult> {
		this.startCalls += 1;
		this.request = request;
		await this.onStart?.(request);
		const findings = this.emptyFindings ? [] : [
			{ severity: 'High', rawEvidence: { token: 'sk-test-secret-value-123456' } },
			{ severity: 'Low', rawEvidence: { line: 'safe' } },
		] as CoreScanStartResult['findings'];
		const correlation = { findings, relationships: [], summary: { deduplicated: 0, boosted: 0, attackPaths: 0 } };
		const graph = { nodes: [], edges: [] };
		const telemetry = { scanId: request.requestId, tools: [], logs: [], findings: findings.length, failures: 0, timeouts: 0, cancelled: false };
		return {
			scanId: request.requestId,
			state: { mode: 'deep' } as CoreScanStartResult['state'],
			findings,
			filesScanned: this.filesScanned,
			skippedFiles: this.skippedFiles,
			skipReasons: this.skipReasons,
			correlation,
			graph,
			telemetry,
			report: { sarif: { version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [] }, json: createJsonReport({ summary: { total: findings.length }, findings } as unknown as import('../../packages/core/src/reports/reportModels').SecurityReportModel), model: { summary: { total: findings.length }, findings }, pdf: Buffer.concat([Buffer.from('%PDF-1.4\nAqiron report '), Buffer.from([0xe9])]).toString('binary') } as unknown as CoreScanStartResult['report'],
			durationMs: 1250,
		};
	}

	async stop(): Promise<void> {
		this.stopCalls += 1;
	}

	emit(event: { event: string; requestId?: string; payload?: unknown }): void {
		for (const listener of this.listeners) {listener(event);}
	}
}

function captureOutput(): CliOutput & { text: string } {
	return {
		text: '',
		write(text: string) { this.text += text; },
	};
}

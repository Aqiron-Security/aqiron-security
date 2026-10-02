import * as assert from 'assert';
import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CliCoreClient, CliOutput, runCli } from '../../packages/cli/src/cli';
import { CoreScanStartResult } from '../../packages/core/src/runtime/protocol';
import { CoreClient } from '../core/coreClient';

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
			assert.doesNotMatch(json.text, /sk-test-secret-value-123456/);
			assert.match(json.text, /\[REDACTED\]/);
			assert.equal(await runCli(['scan', workspace, '--format', 'sarif', '--trust-local-workspace'], { stdout: sarif, stderr: captureOutput(), createClient: () => new FakeCoreClient() }), 0);
			assert.equal(JSON.parse(sarif.text).version, '2.1.0');
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
		} finally {
			fs.rmSync(workspace, { recursive: true, force: true });
			fs.rmSync(outputDir, { recursive: true, force: true });
		}
	});

	for (const [threshold, expected] of [['critical', false], ['high', true], ['medium', true], ['low', true]] as const) {
		test(`--fail-on ${threshold} gates against actual findings`, async () => {
			const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'aqiron-cli-'));
			try {
				const code = await runCli(['scan', workspace, '--fail-on', threshold, '--trust-local-workspace'], { stdout: captureOutput(), stderr: captureOutput(), createClient: () => new FakeCoreClient() });
				assert.equal(code, expected ? 1 : 0);
			} finally { fs.rmSync(workspace, { recursive: true, force: true }); }
		});
	}

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
		const client = new CoreClient({ extensionVersion: 'test' });
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
});

class FakeCoreClient implements CliCoreClient {
	private readonly listeners: Array<(event: { event: string; requestId?: string; payload?: unknown }) => void> = [];
	startCalls = 0;
	stopCalls = 0;
	cancelCalls = 0;
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
		const findings = [
			{ severity: 'High', rawEvidence: { token: 'sk-test-secret-value-123456' } },
			{ severity: 'Low', rawEvidence: { line: 'safe' } },
		] as CoreScanStartResult['findings'];
		return {
			scanId: request.requestId,
			state: { mode: 'deep' } as CoreScanStartResult['state'],
			findings,
			report: { sarif: { version: '2.1.0', runs: [] }, model: { summary: { total: 2 }, findings } } as unknown as CoreScanStartResult['report'],
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

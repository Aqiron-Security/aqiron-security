import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CliCoreClient, CliOutput, runCli } from '../../packages/cli/src/cli';
import { CoreScanStartResult } from '../../packages/core/src/runtime/protocol';
import { CoreClient } from '../core/coreClient';

suite('Aqiron CLI prototype', () => {
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
			assert.match(stdout.text, /Native analysis: running \(10%\)/);
			assert.match(stdout.text, /Scanner: Semgrep \(unavailable\)/);
			assert.doesNotMatch(stdout.text, /Wrong/);
		} finally {
			fs.rmSync(workspace, { recursive: true, force: true });
		}
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
			assert.match(stderr.text, /fixture Core failure/);
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
});

class FakeCoreClient implements CliCoreClient {
	private readonly listeners: Array<(event: { event: string; requestId?: string; payload?: unknown }) => void> = [];
	startCalls = 0;
	stopCalls = 0;
	request?: { requestId: string; workspaceRoot: string; trusted: boolean; mode: 'deep' };
	onStart?: (request: NonNullable<FakeCoreClient['request']>) => Promise<void>;

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
		return {
			scanId: request.requestId,
			state: {} as CoreScanStartResult['state'],
			findings: [
				{ severity: 'High' },
				{ severity: 'Low' },
			] as CoreScanStartResult['findings'],
			report: {} as CoreScanStartResult['report'],
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

import * as assert from 'assert';
import * as path from 'path';
import * as vscode from 'vscode';
import { AqironIssue, AqironScanResult } from '../models/issue';
import { AqironWebviewProvider } from '../webview/aqironWebviewProvider';

interface AgentResult {
	content: string;
	commands: Array<{ label: string; command: string; status: string }>;
	issues?: AqironIssue[];
	stats?: Record<string, unknown>;
}

interface AgentProviderHarness {
	agentScanner: { scanWorkspace(folder: vscode.WorkspaceFolder): Promise<AqironScanResult> };
	agentOutput: { appendLine(line: string): void };
	state: { issues: AqironIssue[] };
	runWorkspaceScan(): Promise<AgentResult>;
	runSecretsScan(): Promise<AgentResult>;
}

suite('AI agent scan characterization', () => {
	test('workspace tool returns every scanner issue with the current summary and stats shape', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const issue = makeIssue(path.join(fixtureRoot, 'lib', 'vulnerable.dart'), 'high.eval');
			let scannedRoot: string | undefined;
			const provider = harness({
				filesScanned: 17,
				durationMs: 24,
				issues: [issue],
				target: fixtureRoot,
				workspaceRoot: fixtureRoot,
			}, folder => { scannedRoot = folder.uri.fsPath; });
			const result = await provider.runWorkspaceScan();
			assert.equal(scannedRoot, fixtureRoot);
			assert.deepEqual(result.issues, [issue]);
			assert.equal(result.content, 'Workspace scan complete. Scanned 17 files and found 1 issue.');
			assert.deepEqual(result.commands, [{ label: 'Run Aqiron workspace scan', command: 'workspace.scan', status: 'complete' }]);
			assert.deepEqual({ filesScanned: result.stats?.filesScanned, indexedFiles: result.stats?.indexedFiles, scanStatus: result.stats?.scanStatus }, { filesScanned: 17, indexedFiles: 17, scanStatus: 'Complete' });
			assert.ok(typeof result.stats?.lastScanDurationMs === 'number' && result.stats.lastScanDurationMs >= 0);
		});
	});

	test('secret tool keeps secret rules, removes prior secret issues, preserves other issues, and summarizes matches', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const existingSecret = makeIssue(path.join(fixtureRoot, 'old.dart'), 'critical.secret');
			const existingNonSecret = makeIssue(path.join(fixtureRoot, 'existing.dart'), 'high.eval');
			const secretOne = makeIssue(path.join(fixtureRoot, 'lib', 'one.dart'), 'critical.api-key');
			const secretTwo = makeIssue(path.join(fixtureRoot, 'lib', 'two.dart'), 'critical.password');
			const nonSecret = makeIssue(path.join(fixtureRoot, 'lib', 'three.dart'), 'high.eval');
			const provider = harness({
				filesScanned: 9,
				durationMs: 20,
				issues: [secretOne, nonSecret, secretTwo],
				target: fixtureRoot,
				workspaceRoot: fixtureRoot,
			}, () => undefined, [existingSecret, existingNonSecret]);
			const result = await provider.runSecretsScan();
			assert.match(result.content, /Found 2 potential secret findings/);
			assert.match(result.content, /one\.dart:1/);
			assert.match(result.content, /two\.dart:1/);
			assert.deepEqual(result.issues, [existingNonSecret, secretOne, secretTwo]);
			assert.ok(!result.issues?.includes(nonSecret));
			assert.equal((result.issues?.[1] as AqironIssue).lineText, 'source line for critical.api-key');
			assert.deepEqual(result.commands, [
				{ label: 'Hunt secrets', command: 'secrets.scan', status: 'complete' },
				{ label: 'Workspace scanner', command: 'Scanned 9 files with Aqiron rules', status: 'complete' },
			]);
			assert.deepEqual({ filesScanned: result.stats?.filesScanned, indexedFiles: result.stats?.indexedFiles, scanStatus: result.stats?.scanStatus }, { filesScanned: 9, indexedFiles: 9, scanStatus: 'Complete' });
			assert.ok(typeof result.stats?.lastScanDurationMs === 'number' && result.stats.lastScanDurationMs >= 0);
		});
	});

	test('secret tool returns the no-findings message and an empty secret projection', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const nonSecret = makeIssue(path.join(fixtureRoot, 'lib', 'safe.dart'), 'high.eval');
			const provider = harness({ filesScanned: 4, durationMs: 10, issues: [nonSecret], target: fixtureRoot }, () => undefined);
			const result = await provider.runSecretsScan();
			assert.equal(result.content, 'Secret scan complete. I scanned 4 files and found no hardcoded API keys, passwords, tokens, or private key material with the current Aqiron rules.');
			assert.deepEqual(result.issues, []);
		});
	});

	test('secret tool propagates scanner errors to its caller', async () => {
		await withFlutterFixture(async () => {
			const provider = harness(undefined, () => undefined, [], new Error('fixture scan failed'));
			await assert.rejects(provider.runSecretsScan(), /fixture scan failed/);
		});
	});

	test('secret tool renders at most five issue locations while retaining all matching findings', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const issues = Array.from({ length: 7 }, (_, index) => makeIssue(path.join(fixtureRoot, 'lib', `secret-${index}.dart`), 'critical.token'));
			const result = await harness({ filesScanned: 7, durationMs: 1, issues, target: fixtureRoot }, () => undefined).runSecretsScan();
			assert.equal(result.issues?.length, 7);
			assert.equal((result.content.match(/secret-\d\.dart:1/g) ?? []).length, 5);
			assert.match(result.content, /Found 7 potential secret findings/);
		});
	});
});

function harness(
	result: AqironScanResult | undefined,
	onScan: (folder: vscode.WorkspaceFolder) => void,
	existingIssues: AqironIssue[] = [],
	error?: Error,
): AgentProviderHarness {
	const provider = Object.create(AqironWebviewProvider.prototype) as AgentProviderHarness;
	provider.agentScanner = {
		async scanWorkspace(folder) {
			onScan(folder);
			if (error) { throw error; }
			return result ?? { target: folder.uri.fsPath, filesScanned: 0, durationMs: 0, issues: [] };
		},
	};
	provider.agentOutput = { appendLine: () => undefined };
	provider.state = { issues: existingIssues };
	return provider;
}

function makeIssue(file: string, ruleId: string): AqironIssue {
	return {
		id: `${file}:${ruleId}`,
		file,
		title: ruleId,
		message: `Finding for ${ruleId}`,
		severity: ruleId.startsWith('critical') ? 'Critical' : 'High',
		ruleId,
		range: { file, startLine: 0, startColumn: 0, endLine: 0, endColumn: 5 },
		lineText: `source line for ${ruleId}`,
	};
}

async function withFlutterFixture(run: (root: string) => Promise<void>): Promise<void> {
	const root = path.resolve(__dirname, '../../../src/test/fixtures/file-scan/flutter');
	const workspace = vscode.workspace as unknown as Record<string, unknown>;
	const descriptor = Object.getOwnPropertyDescriptor(workspace, 'workspaceFolders');
	const folder: vscode.WorkspaceFolder = { uri: vscode.Uri.file(root), name: 'Flutter characterization fixture', index: 0 };
	Object.defineProperty(workspace, 'workspaceFolders', { configurable: true, value: [folder] });
	try {
		await run(root);
	} finally {
		if (descriptor) {
			Object.defineProperty(workspace, 'workspaceFolders', descriptor);
		} else {
			Reflect.deleteProperty(workspace, 'workspaceFolders');
		}
	}
}

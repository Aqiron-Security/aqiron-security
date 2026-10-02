import * as assert from 'assert';
import { EventEmitter } from 'events';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';
import { AqironIssue, AqironScanResult } from '../models/issue';
import { AqironWebviewProvider } from '../webview/aqironWebviewProvider';
import { CoreClient } from '../core/coreClient';
import { CoreScanStartRequest, CoreScanStartResult } from '../../packages/core/src/runtime';
import { createFinding, UnifiedFinding } from '../../packages/core/src/shared/finding';
import { NativeWorkspaceScanner } from '../../packages/core/src/scanners/native/nativeScanner';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';

interface AgentResult {
	content: string;
	commands: Array<{ label: string; command: string; status: string }>;
	issues?: AqironIssue[];
	stats?: Record<string, unknown>;
}

interface AgentProviderHarness {
	agentScanner: { scanWorkspace(folder: vscode.WorkspaceFolder): Promise<AqironScanResult> };
	coreClient: CoreClient;
	activeAgentScans: Map<string, string>;
	coreRequests: CoreScanStartRequest[];
	cancelRequests: string[];
	legacyCalls: number;
	agentOutput: { appendLine(line: string): void };
	state: {
		issues: AqironIssue[];
		pipeline: { logs: string[]; stages: unknown[]; tools: unknown[] };
		[key: string]: unknown;
	};
	runWorkspaceScan(sessionId?: string): Promise<AgentResult>;
	runSecretsScan(sessionId?: string): Promise<AgentResult>;
}

suite('AI agent scan characterization', () => {
	test('legacy secret contract detects the seven current patterns with their existing rule IDs', async () => {
		const cases: Array<{ file: string; line: string; ruleId: string }> = [
			{ file: 'config.js', line: 'const api_key = "0123456789abcdef";', ruleId: 'critical.api-key' },
			{ file: 'config.js', line: 'const aws = "AKIA1234567890ABCDEF";', ruleId: 'critical.api-key' },
			{ file: 'config.js', line: 'const google = "AIza12345678901234567890123456789012345";', ruleId: 'critical.api-key' },
			{ file: 'config.js', line: 'const stripe = "sk_live_12345678901234567890";', ruleId: 'critical.api-key' },
			{ file: 'config.js', line: 'const secret = "0123456789abcdef";', ruleId: 'critical.secret' },
			{ file: 'config.js', line: 'const password = "12345678";', ruleId: 'critical.password' },
			{ file: 'config.js', line: '-----BEGIN RSA PRIVATE KEY-----', ruleId: 'critical.private-key' },
		];
		assert.deepEqual(cases.map(item => item.ruleId), ['critical.api-key', 'critical.api-key', 'critical.api-key', 'critical.api-key', 'critical.secret', 'critical.password', 'critical.private-key']);
		const core = await new NativeWorkspaceScanner({} as never).scanFileContent('config.js', cases.map(item => item.line).join('\n'), 'agent-secret-classes', {
			supportedExtensions: ['.js'], excludedPaths: [], maxFileSizeBytes: null, skipGeneratedFiles: false,
			skipMinifiedFiles: false, skipCompiledFiles: false, eligible: true, customRules: [],
		});
		assert.deepEqual(core.findings.filter(finding => finding.ruleId.startsWith('critical.')).map(finding => finding.ruleId), cases.map(item => item.ruleId));
	});

	test('Core native file rules provide the deterministic legacy secret contract', async () => {
		const scanner = new NativeWorkspaceScanner({} as never);
		const javascript = await scanner.scanFileContent('src/config.js', 'const api_key = "0123456789abcdef";\nconst aws = "AKIA1234567890ABCDEF";', 'gap-test', {
			supportedExtensions: ['.js'], excludedPaths: [], maxFileSizeBytes: null, skipGeneratedFiles: false,
			skipMinifiedFiles: false, skipCompiledFiles: false, eligible: true, customRules: [],
		});
		assert.deepEqual(javascript.findings.filter(finding => finding.ruleId.startsWith('critical.')).map(finding => finding.ruleId), ['critical.api-key', 'critical.api-key']);
		const dart = await scanner.scanFileContent('lib/config.dart', 'const api_key = "0123456789abcdef";', 'gap-test-dart', {
			supportedExtensions: ['.dart'], excludedPaths: [], maxFileSizeBytes: null, skipGeneratedFiles: false,
			skipMinifiedFiles: false, skipCompiledFiles: false, eligible: true, customRules: [],
		});
		assert.ok(dart.findings.some(finding => finding.ruleId === 'critical.api-key'));
	});

	test('workspace tool returns every scanner issue with the current summary and stats shape', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const finding = makeFinding(path.join(fixtureRoot, 'lib', 'vulnerable.dart'), 'high.eval');
			let scannedRoot: string | undefined;
			const provider = harness(undefined, folder => { scannedRoot = folder.uri.fsPath; }, [], undefined, {
				findings: [finding],
				filesScanned: 17,
				durationMs: 24,
			});
			const result = await provider.runWorkspaceScan();
			assert.equal(scannedRoot, fixtureRoot);
			assert.equal(provider.coreRequests.length, 1, 'workspace.scan must invoke Core scan.start');
			assert.equal(provider.legacyCalls, 0, 'workspace.scan must not invoke WorkspaceScanner.scanWorkspace');
			assert.deepEqual(provider.coreRequests[0], {
				requestId: provider.coreRequests[0].requestId,
				workspaceRoot: fixtureRoot,
				targetPath: fixtureRoot,
				mode: 'deep',
				trusted: vscode.workspace.isTrusted,
				currentFile: fixtureRoot,
			});
			assert.deepEqual(result.issues?.map(issue => [issue.id, issue.file, issue.ruleId, issue.severity]), [[finding.id, finding.file, finding.ruleId, finding.severity]]);
			assert.equal(result.content, 'Workspace scan complete. Scanned 17 files and found 1 issue.');
			assert.deepEqual(result.commands, [{ label: 'Run Aqiron workspace scan', command: 'workspace.scan', status: 'complete' }]);
			assert.deepEqual({ filesScanned: result.stats?.filesScanned, indexedFiles: result.stats?.indexedFiles, scanStatus: result.stats?.scanStatus }, { filesScanned: 17, indexedFiles: 17, scanStatus: 'Complete' });
			assert.ok(typeof result.stats?.lastScanDurationMs === 'number' && result.stats.lastScanDurationMs >= 0);
		});
	});

	test('Agent Core request sends the actual untrusted-workspace state', async () => {
		await withFlutterFixture(async fixtureRoot => {
			await withWorkspaceTrust(false, async () => {
				const provider = harness(undefined, () => undefined, [], undefined, { findings: [], filesScanned: 0, durationMs: 1 });
				await provider.runWorkspaceScan();
				assert.equal(provider.coreRequests[0].trusted, false);
				assert.equal(provider.coreRequests[0].workspaceRoot, fixtureRoot);
			});
		});
	});

	test('Agent workspace scan preserves the legacy Flutter project gate', async () => {
		const root = path.resolve(__dirname, '../../../src/test/fixtures/file-scan');
		await withWorkspaceFolder({ uri: vscode.Uri.file(root), name: 'Non-Flutter fixture', index: 0 }, async () => {
			const provider = harness(undefined, () => undefined);
			const result = await provider.runWorkspaceScan();
			assert.equal(provider.coreRequests.length, 0);
			assert.equal(result.content, 'Workspace scan complete. Scanned 0 files and found 0 issues.');
			assert.equal(result.stats?.filesScanned, 0);
		});
	});

	test('secrets.scan invokes Core with the first folder, resolved policy, and actual trust', async () => {
		await withFlutterFixture(async firstRoot => {
			const first: vscode.WorkspaceFolder = { uri: vscode.Uri.file(firstRoot), name: 'First Flutter folder', index: 0 };
			const second: vscode.WorkspaceFolder = { uri: vscode.Uri.file(path.resolve(__dirname, '../../../src')), name: 'Second folder', index: 1 };
			await withWorkspaceFolders([first, second], async () => withWorkspaceTrust(false, async () => withSettings({
				excludeFolders: ['vendor'], scanGeneratedFiles: true, maxFileSizeKB: 64,
				customRules: [{ id: 'critical.secret.custom', title: 'Custom credential', message: 'Review credential.', severity: 'High', pattern: 'credentialValue', extensions: ['.js'] }],
			}, async () => {
				let selectedRoot: string | undefined;
				const provider = harness(undefined, folder => { selectedRoot = folder.uri.fsPath; }, [], undefined, { findings: [], filesScanned: 1, durationMs: 1 });
				const result = await provider.runSecretsScan('session-secret');
				assert.equal(selectedRoot, firstRoot);
				assert.equal(provider.legacyCalls, 0);
				assert.equal(provider.coreRequests.length, 1);
				assert.equal(provider.coreRequests[0].workspaceRoot, firstRoot);
				assert.equal(provider.coreRequests[0].trusted, false);
				assert.equal(provider.coreRequests[0].mode, 'quick');
				assert.equal(provider.coreRequests[0].includeExternalScanners, false);
				assert.equal(provider.coreRequests[0].workspacePolicy?.maxFileSizeBytes, 64 * 1024);
				assert.equal(provider.coreRequests[0].workspacePolicy?.skipGeneratedFiles, false);
				assert.ok(provider.coreRequests[0].workspacePolicy?.excludedDirectoryPaths.includes('vendor'));
				assert.ok(provider.coreRequests[0].workspacePolicy?.aqExclusionPatterns.length);
				assert.ok(provider.coreRequests[0].workspacePolicy?.supportedExtensions.includes('.dart'));
				assert.deepEqual(provider.coreRequests[0].workspacePolicy?.customRules.map(rule => rule.id), ['critical.secret.custom']);
				assert.equal(result.stats?.scanStatus, 'Complete');
			})));
		});
	});

	test('Agent secret scan keeps the Flutter host gate before invoking Core', async () => {
		const root = path.resolve(__dirname, '../../../src/test/fixtures/file-scan');
		await withWorkspaceFolder({ uri: vscode.Uri.file(root), name: 'Non-Flutter fixture', index: 0 }, async () => {
			const provider = harness(undefined, () => undefined);
			const result = await provider.runSecretsScan();
			assert.equal(provider.coreRequests.length, 0);
			assert.equal(provider.legacyCalls, 0);
			assert.match(result.content, /scanned 0 files and found no hardcoded/);
			assert.equal(result.stats?.filesScanned, 0);
		});
	});

	test('Agent workspace scan forwards request-correlated Core progress without fabricating events', async () => {
		await withFlutterFixture(async () => {
			const provider = harness(undefined, () => undefined, [], undefined, {
				findings: [], filesScanned: 1, durationMs: 8,
				onStart: (request, events) => {
					events.emit('event', { event: 'scan.event', requestId: 'unrelated', payload: { type: 'log', message: 'wrong scan', timestamp: 'now' } });
					events.emit('event', { event: 'scan.event', requestId: request.requestId, payload: { type: 'log', message: 'Core scanner started', tool: 'native', timestamp: 'now' } });
				},
			});
			await provider.runWorkspaceScan();
			assert.deepEqual(provider.state.pipeline.logs, ['[native] Core scanner started']);
		});
	});

	test('Agent workspace scan reports Core failure instead of a success result', async () => {
		await withFlutterFixture(async () => {
			const provider = harness(undefined, () => undefined, [], new Error('Core runtime failed'));
			const result = await provider.runWorkspaceScan();
			assert.match(result.content, /Workspace scan failed: Core runtime failed/);
			assert.equal(result.commands[0].status, 'unavailable');
			assert.equal(result.stats?.scanStatus, 'Failed');
			assert.equal(result.issues, undefined);
		});
	});

	test('Agent workspace cancellation uses Core request cancellation for the active session', async () => {
		await withFlutterFixture(async () => {
			let release!: (result: CoreScanStartResult) => void;
			const provider = harness(undefined, () => undefined, [], undefined, {
				findings: [], filesScanned: 0, durationMs: 0,
				defer: () => new Promise<CoreScanStartResult>(resolve => { release = resolve; }),
			});
			const scan = (provider as unknown as { runWorkspaceScan(sessionId: string): Promise<AgentResult> }).runWorkspaceScan('session-1');
			await new Promise(resolve => setTimeout(resolve, 0));
			(provider as unknown as { cancelAgentWorkspaceScan(sessionId: string): void }).cancelAgentWorkspaceScan('session-1');
			assert.deepEqual(provider.cancelRequests, [provider.coreRequests[0].requestId]);
			release(makeCoreResult([], 0, 0));
			await scan;
		});
	});

	test('secret tool filters Core findings, replaces prior secrets, preserves non-secrets, and summarizes matches', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const existingSecret = makeIssue(path.join(fixtureRoot, 'old.dart'), 'critical.secret');
			const existingNonSecret = makeIssue(path.join(fixtureRoot, 'existing.dart'), 'high.eval');
			const secretOne = makeFinding(path.join(fixtureRoot, 'lib', 'one.dart'), 'critical.api-key');
			const secretTwo = makeFinding(path.join(fixtureRoot, 'lib', 'two.dart'), 'critical.password');
			const nonSecret = makeFinding(path.join(fixtureRoot, 'lib', 'three.dart'), 'high.eval');
			const mixedCaseSecret = makeFinding(path.join(fixtureRoot, 'lib', 'four.dart'), 'critical.Secret');
			const provider = harness(undefined, () => undefined, [existingSecret, existingNonSecret], undefined, {
				findings: [secretOne, nonSecret, secretTwo, mixedCaseSecret], filesScanned: 9, durationMs: 20,
			});
			const result = await provider.runSecretsScan();
			assert.match(result.content, /Found 2 potential secret findings/);
			assert.match(result.content, /one\.dart:1/);
			assert.match(result.content, /two\.dart:1/);
			assert.deepEqual(result.issues?.map(issue => [issue.ruleId, issue.file]), [
				['high.eval', existingNonSecret.file], ['critical.api-key', secretOne.file], ['critical.password', secretTwo.file],
			]);
			assert.ok(!result.issues?.some(issue => issue.file === nonSecret.file), 'the incoming non-secret finding must not be projected');
			assert.ok(!result.issues?.some(issue => issue.file === mixedCaseSecret.file), 'secret rule-ID matching remains case-sensitive');
			assert.deepEqual(result.commands, [
				{ label: 'Hunt secrets', command: 'secrets.scan', status: 'complete' },
				{ label: 'Workspace scanner', command: 'Scanned 9 files with Aqiron rules', status: 'complete' },
			]);
			assert.equal(provider.legacyCalls, 0, 'secrets.scan does not invoke WorkspaceScanner.scanWorkspace');
			assert.equal(provider.coreRequests.length, 1);
			assert.deepEqual({ filesScanned: result.stats?.filesScanned, indexedFiles: result.stats?.indexedFiles, scanStatus: result.stats?.scanStatus }, { filesScanned: 9, indexedFiles: 9, scanStatus: 'Complete' });
			assert.ok(typeof result.stats?.lastScanDurationMs === 'number' && result.stats.lastScanDurationMs >= 0);
		});
	});

	test('secret tool returns the no-findings message and an empty secret projection', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const nonSecret = makeFinding(path.join(fixtureRoot, 'lib', 'safe.dart'), 'high.eval');
			const provider = harness(undefined, () => undefined, [], undefined, { findings: [nonSecret], filesScanned: 4, durationMs: 10 });
			const result = await provider.runSecretsScan();
			assert.equal(result.content, 'Secret scan complete. I scanned 4 files and found no hardcoded API keys, passwords, tokens, or private key material with the current Aqiron rules.');
			assert.deepEqual(result.issues, []);
		});
	});

	test('secret tool surfaces Core errors as a failed Agent result', async () => {
		await withFlutterFixture(async () => {
			const provider = harness(undefined, () => undefined, [], new Error('fixture scan failed'));
			const result = await provider.runSecretsScan();
			assert.match(result.content, /Secret scan failed: fixture scan failed/);
			assert.equal(result.stats?.scanStatus, 'Failed');
			assert.equal(result.commands?.[0].status, 'unavailable');
			assert.equal(provider.legacyCalls, 0);
		});
	});

	test('secret tool renders at most five issue locations while retaining all matching findings', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const findings = Array.from({ length: 7 }, (_, index) => makeFinding(path.join(fixtureRoot, 'lib', `secret-${index}.dart`), 'critical.token'));
			const result = await harness(undefined, () => undefined, [], undefined, { findings, filesScanned: 7, durationMs: 1 }).runSecretsScan();
			assert.equal(result.issues?.length, 7, JSON.stringify(result.issues?.map(issue => ({ id: issue.id, file: issue.file, ruleId: issue.ruleId }))));
			assert.equal((result.content.match(/secret-\d\.dart:1/g) ?? []).length, 5);
			assert.match(result.content, /Found 7 potential secret findings/);
		});
	});

	test('secret scan progress is request-correlated and cancellation cancels its Core request', async () => {
		await withFlutterFixture(async () => {
			let rejectScan!: (error: Error) => void;
			const provider = harness(undefined, () => undefined, [], undefined, {
				findings: [], filesScanned: 0, durationMs: 0,
				onStart: (request, events) => {
					events.emit('event', { event: 'scan.event', requestId: 'unrelated', payload: { type: 'log', message: 'wrong scan', tool: 'native', timestamp: 'now' } });
					events.emit('event', { event: 'scan.event', requestId: request.requestId, payload: { type: 'log', message: 'Core secret scan started', tool: 'native', timestamp: 'now' } });
				},
				defer: () => new Promise<CoreScanStartResult>((_resolve, reject) => { rejectScan = reject; }),
			});
			const scan = provider.runSecretsScan('session-cancel');
			await new Promise(resolve => setTimeout(resolve, 0));
			assert.deepEqual(provider.state.pipeline.logs, ['[native] Core secret scan started']);
			const requestId = provider.coreRequests[0].requestId!;
			(provider as unknown as { cancelAgentWorkspaceScan(sessionId: string): void }).cancelAgentWorkspaceScan('session-cancel');
			assert.deepEqual(provider.cancelRequests, [requestId]);
			rejectScan(new Error('Core request cancelled.'));
			const result = await scan;
			assert.equal(result.content, 'Secret scan cancelled.');
			assert.equal(result.stats?.scanStatus, 'Failed');
			assert.equal(provider.activeAgentScans.has('session-cancel'), false);
		});
	});

	test('real Agent secrets.scan finds the legacy fixture through Core and redacts serialized state', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-agent-secret-core-'));
		const secretValues = ['0123456789abcdef', 'AKIA1234567890ABCDEF', 'AIza12345678901234567890123456789012345', 'sk_live_12345678901234567890', '12345678', '-----BEGIN RSA PRIVATE KEY-----'];
		try {
			const source = await fs.readFile(path.resolve(__dirname, '../../../src/test/fixtures/core-secrets/legacy-patterns.txt'), 'utf8');
			await fs.writeFile(path.join(root, '.metadata'), '', 'utf8');
			await fs.writeFile(path.join(root, 'pubspec.yaml'), 'name: core_secret_fixture\ndependencies:\n  flutter:\n    sdk: flutter\n', 'utf8');
			await fs.mkdir(path.join(root, 'lib'), { recursive: true });
			await fs.writeFile(path.join(root, 'lib', 'legacy.js'), source, 'utf8');
			const folder: vscode.WorkspaceFolder = { uri: vscode.Uri.file(root), name: 'Core secret fixture', index: 0 };
			await withWorkspaceFolder(folder, async () => withWorkspaceTrust(false, async () => {
				const runtime = new CoreRuntime({ coreVersion: 'agent-secret-integration' });
				let returnedScanId: string | undefined;
				const provider = harness(undefined, () => undefined, [], undefined, {
					findings: [], filesScanned: 0, durationMs: 0,
					execute: async (request, events) => {
						const eventPayloads: unknown[] = [];
						const response = await runtime.handle({ id: request.requestId!, type: 'request', method: 'scan.start', params: request }, message => {
							if (message.type === 'event') {
								eventPayloads.push(message);
								events.emit('event', { event: message.event, requestId: message.requestId, payload: message.payload });
							}
						});
						assert.equal(response.success, true, response.error?.message);
						const eventJson = JSON.stringify(eventPayloads);
						for (const secret of secretValues) {assert.ok(!eventJson.includes(secret), `Core events must not contain ${secret}`);}
						assert.ok(eventPayloads.every(event => (event as { requestId?: string }).requestId === request.requestId), 'all emitted Core events are correlated to this request');
						const responseJson = JSON.stringify(response.result);
						for (const secret of secretValues) {assert.ok(!responseJson.includes(secret), `Core result must not contain raw evidence ${secret}`);}
						const coreResult = response.result as CoreScanStartResult;
						returnedScanId = coreResult.scanId;
						return coreResult;
					},
				});
				const result = await provider.runSecretsScan('session-real-scan');
				const secretRules = result.issues?.map(issue => issue.ruleId) ?? [];
				assert.equal(returnedScanId, provider.coreRequests[0].requestId, 'Core result retains the canonical request/scan identity');
				assert.deepEqual(secretRules, ['critical.api-key', 'critical.api-key', 'critical.api-key', 'critical.api-key', 'critical.secret', 'critical.secret', 'critical.password', 'critical.private-key'], JSON.stringify(result.stats));
				assert.equal(new Set(result.issues?.map(issue => issue.id)).size, 8, 'same-rule secret findings retain distinct location identities');
				assert.deepEqual(result.issues?.map(issue => [issue.file.toLowerCase(), issue.severity, issue.title, issue.range.startLine]), [
					[path.join(root, 'lib', 'legacy.js').toLowerCase(), 'Critical', 'Hardcoded API Key', 0],
					[path.join(root, 'lib', 'legacy.js').toLowerCase(), 'Critical', 'Hardcoded API Key', 1],
					[path.join(root, 'lib', 'legacy.js').toLowerCase(), 'Critical', 'Hardcoded API Key', 2],
					[path.join(root, 'lib', 'legacy.js').toLowerCase(), 'Critical', 'Hardcoded API Key', 3],
					[path.join(root, 'lib', 'legacy.js').toLowerCase(), 'Critical', 'Hardcoded Secret', 4],
					[path.join(root, 'lib', 'legacy.js').toLowerCase(), 'Critical', 'Hardcoded Secret', 5],
					[path.join(root, 'lib', 'legacy.js').toLowerCase(), 'Critical', 'Hardcoded Password', 6],
					[path.join(root, 'lib', 'legacy.js').toLowerCase(), 'Critical', 'Private Key Material', 7],
				]);
				assert.equal(result.stats?.filesScanned, 2, 'the resolved policy includes the supported pubspec.yaml file');
				assert.match(result.content, /Found 8 potential secret findings/);
				assert.equal((result.content.match(/legacy\.js:\d+/g) ?? []).length, 5);
				assert.equal(provider.coreRequests[0].trusted, false);
				const serialized = JSON.stringify(serializeAgentState(result.issues ?? []));
				for (const secret of secretValues) {assert.ok(!serialized.includes(secret), `serialized Agent state must not contain ${secret}`);}
				assert.ok(serialized.includes('[REDACTED]'));
			}));
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	test('serialized Agent state redacts each secret source span and preserves non-secret context', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const firstSecret = 'sk-live-secret-value-123';
			const secondSecret = 'password-value-456';
			const issues = [
				makeLineIssue(path.join(fixtureRoot, 'one.ts'), 'critical.api-key', `const OPENAI_API_KEY = "${firstSecret}";`, firstSecret),
				makeLineIssue(path.join(fixtureRoot, 'two.ts'), 'critical.password', `const password = "${secondSecret}";`, secondSecret),
				makeLineIssue(path.join(fixtureRoot, 'safe.ts'), 'high.eval', 'eval(userInput);', 'eval(userInput)'),
			];
			const serialized = JSON.stringify(serializeAgentState(issues));
			assert.ok(!serialized.includes(firstSecret), 'first secret must not appear in serialized Agent state');
			assert.ok(!serialized.includes(secondSecret), 'second secret must not appear in serialized Agent state');
			const state = JSON.parse(serialized) as { issues: Array<{ ruleId: string; lineText: string; file: string; line: number }> };
			assert.deepEqual(state.issues.map(issue => issue.ruleId), issues.map(issue => issue.ruleId));
			assert.equal(state.issues[0].lineText, 'const OPENAI_API_KEY = "[REDACTED]";');
			assert.equal(state.issues[1].lineText, 'const password = "[REDACTED]";');
			assert.equal(state.issues[2].lineText, 'eval(userInput);');
			assert.equal(state.issues[0].file, issues[0].file);
			assert.equal(state.issues[0].line, 1);
		});
	});
});

function harness(
	result: AqironScanResult | undefined,
	onScan: (folder: vscode.WorkspaceFolder) => void,
	existingIssues: AqironIssue[] = [],
	error?: Error,
	coreOptions?: {
		findings: UnifiedFinding[];
		filesScanned: number;
		durationMs: number;
		execute?: (request: CoreScanStartRequest, events: EventEmitter) => Promise<CoreScanStartResult>;
		onStart?: (request: CoreScanStartRequest, events: EventEmitter) => void;
		defer?: () => Promise<CoreScanStartResult>;
	},
): AgentProviderHarness {
	const provider = Object.create(AqironWebviewProvider.prototype) as AgentProviderHarness;
	const coreEvents = new EventEmitter();
	let legacyCalls = 0;
	provider.agentScanner = {
		async scanWorkspace(folder) {
			legacyCalls += 1;
			onScan(folder);
			if (error) { throw error; }
			return result ?? { target: folder.uri.fsPath, filesScanned: 0, durationMs: 0, issues: [] };
		},
	};
	provider.coreRequests = [];
	provider.cancelRequests = [];
	Object.defineProperty(provider, 'legacyCalls', { get: () => legacyCalls });
	provider.activeAgentScans = new Map();
	provider.coreClient = {
		async startScan(request: CoreScanStartRequest) {
			provider.coreRequests.push(request);
			onScan({ uri: vscode.Uri.file(request.workspaceRoot), name: 'Core workspace', index: 0 });
			coreOptions?.onStart?.(request, coreEvents);
			if (error) { throw error; }
			if (coreOptions?.execute) {return await coreOptions.execute(request, coreEvents);}
			if (coreOptions?.defer) { return await coreOptions.defer(); }
			return makeCoreResult(coreOptions?.findings ?? [], coreOptions?.filesScanned ?? 0, coreOptions?.durationMs ?? 0);
		},
		async cancelRequest(requestId: string) {
			provider.cancelRequests.push(requestId);
			return { cancelled: true, requestId };
		},
		on: coreEvents.on.bind(coreEvents),
		removeListener: coreEvents.removeListener.bind(coreEvents),
	} as unknown as CoreClient;
	provider.agentOutput = { appendLine: () => undefined };
	provider.state = {
		issues: existingIssues,
		stats: { filesScanned: 0, indexedFiles: 0, scanStatus: 'Idle', lastScanDurationMs: 0 },
		workspace: { root: undefined, status: 'No workspace' },
		pipeline: { logs: [], stages: [], tools: [] },
	};
	return provider;
}

function makeCoreResult(findings: UnifiedFinding[], filesScanned: number, durationMs: number): CoreScanStartResult {
	return { scanId: 'agent-scan', state: {} as CoreScanStartResult['state'], findings, report: {} as CoreScanStartResult['report'], filesScanned, durationMs };
}

function makeFinding(file: string, ruleId: string): UnifiedFinding {
	return createFinding({
		title: `Finding for ${ruleId}`,
		description: `Description for ${ruleId}`,
		severity: ruleId.startsWith('critical') ? 'Critical' : 'High',
		cwe: [],
		owasp: [],
		file,
		line: 1,
		column: 1,
			fingerprint: Buffer.from(`${file}|${ruleId}`).toString('base64url'),
		sourceTool: 'Aqiron',
		ruleId,
		confidence: 'High',
		remediation: 'Review the finding.',
		tags: [],
		rawEvidence: {},
	});
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

function makeLineIssue(file: string, ruleId: string, lineText: string, match: string): AqironIssue {
	const startColumn = lineText.indexOf(match);
	return {
		...makeIssue(file, ruleId),
		range: { file, startLine: 0, startColumn, endLine: 0, endColumn: startColumn + match.length },
		lineText,
	};
}

function serializeAgentState(issues: AqironIssue[]): unknown {
	const provider = Object.create(AqironWebviewProvider.prototype) as {
		context: { workspaceState: { get<T>(key: string, fallback?: T): T | undefined }; extensionUri: vscode.Uri };
		state: Record<string, unknown>;
		section: string;
		getMemory(): { previousScans: unknown[] };
		serializeState(sectionOverride?: string, webview?: vscode.Webview): unknown;
	};
	provider.context = {
		workspaceState: { get: (_key, fallback) => fallback },
		extensionUri: vscode.Uri.file(path.dirname(issues[0]?.file ?? __filename)),
	};
	provider.state = {
		issues,
		workspace: { apis: [] },
		branches: [], stats: {}, rag: { suggestionsGenerated: false, suggestions: [] },
		threatSnapshots: [], zoom: {}, memory: { previousScans: [] }, chatSessions: [], tokenUsage: {},
		ai: {}, mobsf: {}, customRules: [], pipeline: { stages: [], tools: [], logs: [] },
	};
	provider.section = 'aiAgent';
	provider.getMemory = () => ({ previousScans: [] });
	return provider.serializeState('aiAgent');
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

async function withWorkspaceFolders<T>(folders: vscode.WorkspaceFolder[], run: () => Promise<T>): Promise<T> {
	const workspace = vscode.workspace as unknown as Record<string, unknown>;
	const descriptor = Object.getOwnPropertyDescriptor(workspace, 'workspaceFolders');
	Object.defineProperty(workspace, 'workspaceFolders', { configurable: true, value: folders });
	try {
		return await run();
	} finally {
		if (descriptor) {Object.defineProperty(workspace, 'workspaceFolders', descriptor);}
		else {Reflect.deleteProperty(workspace, 'workspaceFolders');}
	}
}

async function withWorkspaceTrust<T>(trusted: boolean, run: () => Promise<T>): Promise<T> {
	const workspace = vscode.workspace as unknown as Record<string, unknown>;
	const descriptor = Object.getOwnPropertyDescriptor(workspace, 'isTrusted');
	Object.defineProperty(workspace, 'isTrusted', { configurable: true, value: trusted });
	try {
		return await run();
	} finally {
		if (descriptor) {
			Object.defineProperty(workspace, 'isTrusted', descriptor);
		} else {
			Reflect.deleteProperty(workspace, 'isTrusted');
		}
	}
}

async function withSettings<T>(settings: Record<string, unknown>, run: () => Promise<T>): Promise<T> {
	const workspace = vscode.workspace as unknown as Record<string, unknown>;
	const descriptor = Object.getOwnPropertyDescriptor(workspace, 'getConfiguration');
	const original = vscode.workspace.getConfiguration.bind(vscode.workspace);
	Object.defineProperty(workspace, 'getConfiguration', {
		configurable: true,
		value: (section?: string, scope?: vscode.ConfigurationScope) => section === 'aqiron-security'
			? { get: <V>(key: string, defaultValue?: V): V | unknown => Object.prototype.hasOwnProperty.call(settings, key) ? settings[key] : defaultValue }
			: original(section, scope),
	});
	try {
		return await run();
	} finally {
		if (descriptor) {Object.defineProperty(workspace, 'getConfiguration', descriptor);}
		else {Reflect.deleteProperty(workspace, 'getConfiguration');}
	}
}

async function withWorkspaceFolder<T>(folder: vscode.WorkspaceFolder, run: () => Promise<T>): Promise<T> {
	const workspace = vscode.workspace as unknown as Record<string, unknown>;
	const descriptor = Object.getOwnPropertyDescriptor(workspace, 'workspaceFolders');
	Object.defineProperty(workspace, 'workspaceFolders', { configurable: true, value: [folder] });
	try {
		return await run();
	} finally {
		if (descriptor) {
			Object.defineProperty(workspace, 'workspaceFolders', descriptor);
		} else {
			Reflect.deleteProperty(workspace, 'workspaceFolders');
		}
	}
}

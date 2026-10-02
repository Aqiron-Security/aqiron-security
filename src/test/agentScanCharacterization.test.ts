import * as assert from 'assert';
import { EventEmitter } from 'events';
import * as path from 'path';
import * as vscode from 'vscode';
import { AqironIssue, AqironScanResult } from '../models/issue';
import { AqironWebviewProvider } from '../webview/aqironWebviewProvider';
import { CoreClient } from '../core/coreClient';
import { CoreScanStartRequest, CoreScanStartResult } from '../../packages/core/src/runtime';
import { createFinding, UnifiedFinding } from '../../packages/core/src/shared/finding';
import { scanContent } from '../scanner/rules';
import { WorkspaceScanner } from '../scanner/workspaceScanner';
import { NativeWorkspaceScanner } from '../../packages/core/src/scanners/native/nativeScanner';

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
	runSecretsScan(): Promise<AgentResult>;
}

suite('AI agent scan characterization', () => {
	test('legacy secret contract detects the seven current patterns with their existing rule IDs', () => {
		const cases: Array<{ file: string; line: string; ruleId: string }> = [
			{ file: 'config.js', line: 'const api_key = "0123456789abcdef";', ruleId: 'critical.api-key' },
			{ file: 'config.js', line: 'const aws = "AKIA1234567890ABCDEF";', ruleId: 'critical.api-key' },
			{ file: 'config.js', line: 'const google = "AIza12345678901234567890123456789012345";', ruleId: 'critical.api-key' },
			{ file: 'config.js', line: 'const stripe = "sk_live_12345678901234567890";', ruleId: 'critical.api-key' },
			{ file: 'config.js', line: 'const secret = "0123456789abcdef";', ruleId: 'critical.secret' },
			{ file: 'config.js', line: 'const password = "12345678";', ruleId: 'critical.password' },
			{ file: 'config.js', line: '-----BEGIN RSA PRIVATE KEY-----', ruleId: 'critical.private-key' },
		];
		for (const item of cases) {
			assert.ok(scanContent(item.file, item.line).some(issue => issue.ruleId === item.ruleId), `${item.ruleId} should be detected for ${item.line}`);
		}
		assert.deepEqual(scanContent('config.js', 'const aws = "akia1234567890abcd";').filter(issue => issue.ruleId.startsWith('critical.')), [], 'fixed provider-token patterns remain case-sensitive');
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

	test('secrets.scan keeps first-folder selection and the existing WorkspaceScanner path', async () => {
		await withFlutterFixture(async firstRoot => {
			const first: vscode.WorkspaceFolder = { uri: vscode.Uri.file(firstRoot), name: 'First Flutter folder', index: 0 };
			const second: vscode.WorkspaceFolder = { uri: vscode.Uri.file(path.resolve(__dirname, '../../../src')), name: 'Second folder', index: 1 };
			await withWorkspaceFolders([first, second], async () => {
				let selectedRoot: string | undefined;
				const provider = harness({ filesScanned: 1, durationMs: 1, issues: [], target: firstRoot }, folder => { selectedRoot = folder.uri.fsPath; });
				await provider.runSecretsScan();
				assert.equal(selectedRoot, firstRoot);
				assert.equal(provider.legacyCalls, 1);
				assert.equal(provider.coreRequests.length, 0, 'policy preparation does not migrate secrets.scan');
			});
		});
	});

	test('legacy Agent workspace scanner retains its Flutter host gate', async () => {
		const root = path.resolve(__dirname, '../../../src/test/fixtures/file-scan');
		const folder: vscode.WorkspaceFolder = { uri: vscode.Uri.file(root), name: 'Non-Flutter fixture', index: 0 };
		const result = await new WorkspaceScanner({ appendLine: () => undefined } as unknown as vscode.OutputChannel).scanWorkspace(folder);
		assert.equal(result.filesScanned, 0);
		assert.deepEqual(result.issues, []);
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
			assert.equal(provider.legacyCalls, 1, 'secrets.scan remains on WorkspaceScanner.scanWorkspace');
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

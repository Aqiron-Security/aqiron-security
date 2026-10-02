import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';
import { ScanController } from '../commands/scanController';
import { DiagnosticManager } from '../diagnostics/diagnosticManager';
import { AqironScanResult } from '../models/issue';
import { WorkspaceScanner } from '../scanner/workspaceScanner';
import { scanContent } from '../scanner/rules';
import { getMaxFileSizeBytes, getSkipReason, isFlutterWorkspace, isSupportedFile, supportedExtensions } from '../utils/files';
import { AqironWebviewController } from '../webview/aqironWebviewProvider';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';
import { CoreFileScanRequest, CoreFileScanResult } from '../../packages/core/src/shared/fileScan';

suite('Legacy file scan characterization', () => {
	test('built-in rules detect representative Flutter issues and leave clean/comment-only inputs alone', async () => {
		const fixtureRoot = path.resolve(__dirname, '../../../src/test/fixtures/file-scan/flutter');
		const vulnerablePath = path.join(fixtureRoot, 'lib', 'vulnerable.dart');
		const vulnerable = scanContent(vulnerablePath, await fs.readFile(vulnerablePath, 'utf8'));
		assert.ok(vulnerable.some(issue => issue.ruleId === 'medium.print' && issue.severity === 'Medium'));
		assert.ok(vulnerable.some(issue => issue.ruleId === 'critical.api-key' && issue.severity === 'Critical'));
		assert.ok(vulnerable.every(issue => issue.file === vulnerablePath && issue.range.startLine >= 0 && issue.lineText.length > 0));
		assert.deepEqual(scanContent(path.join(fixtureRoot, 'lib', 'clean.dart'), await fs.readFile(path.join(fixtureRoot, 'lib', 'clean.dart'), 'utf8')), []);
		assert.deepEqual(scanContent(path.join(fixtureRoot, 'lib', 'commented.dart'), await fs.readFile(path.join(fixtureRoot, 'lib', 'commented.dart'), 'utf8')), []);
	});

	test('custom rules are read from Aqiron workspace configuration and can be extension-scoped', () => {
		withCustomRules([{ id: 'fixture.custom', title: 'Fixture policy', message: 'Remove the fixture policy violation.', severity: 'High', pattern: 'unsafeCall\\s*\\(', extensions: ['.dart'] }], () => {
			const dart = scanContent('fixture.dart', 'unsafeCall();');
			const typescript = scanContent('fixture.ts', 'unsafeCall();');
			assert.deepEqual(dart.map(issue => [issue.ruleId, issue.severity]), [['fixture.custom', 'High']]);
			assert.deepEqual(typescript, []);
		});
	});

	test('diagnostic projection maps Aqiron severity, source, rule code, and range', () => {
		const languages = vscode.languages as unknown as Record<string, unknown>;
		const descriptor = Object.getOwnPropertyDescriptor(languages, 'createDiagnosticCollection');
		const stored = new Map<string, vscode.Diagnostic[]>();
		Object.defineProperty(languages, 'createDiagnosticCollection', {
			configurable: true,
			value: () => ({
				clear: () => stored.clear(),
				set: (uri: vscode.Uri, diagnostics: vscode.Diagnostic[]) => stored.set(uri.fsPath, diagnostics),
				dispose: () => stored.clear(),
			}),
		});
		try {
			const manager = new DiagnosticManager();
			manager.setIssues([
				makeIssue('critical.api-key', 'Critical'),
				makeIssue('high.eval', 'High'),
				makeIssue('medium.print', 'Medium'),
				makeIssue('low.todo', 'Low'),
			]);
			const diagnostics = [...stored.values()].flat();
			assert.deepEqual(diagnostics.map(diagnostic => diagnostic.severity), [
				vscode.DiagnosticSeverity.Error,
				vscode.DiagnosticSeverity.Error,
				vscode.DiagnosticSeverity.Warning,
				vscode.DiagnosticSeverity.Information,
			]);
			assert.ok(diagnostics.every(diagnostic => diagnostic.source === 'Aqiron Security'));
			assert.deepEqual(diagnostics.map(diagnostic => diagnostic.code), ['critical.api-key', 'high.eval', 'medium.print', 'low.todo']);
			assert.equal(diagnostics[0].range.start.line, 0);
			manager.dispose();
		} finally {
			restoreProperty(languages, 'createDiagnosticCollection', descriptor);
		}
	});

	test('current-file scan reads unsaved document text while scanFile reads disk content', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const file = path.join(fixtureRoot, 'lib', 'clean.dart');
			const document = await vscode.workspace.openTextDocument(vscode.Uri.file(file));
			const edit = new vscode.WorkspaceEdit();
			edit.replace(document.uri, new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length)), "void main() {\n  print('unsaved');\n}\n");
			assert.equal(await vscode.workspace.applyEdit(edit), true);
			assert.equal(document.isDirty, true);

			const scanner = new WorkspaceScanner(quietOutput());
			const currentFileResult = await scanner.scanDocument(document);
			const diskResult = await new WorkspaceScanner(quietOutput()).scanFile(document.uri);
			assert.ok(currentFileResult.issues.some(issue => issue.ruleId === 'medium.print'));
			assert.deepEqual(diskResult.issues, []);
			assert.equal(currentFileResult.target, file);
			assert.equal(currentFileResult.workspaceRoot, fixtureRoot);
			assert.equal(currentFileResult.filesScanned, 1);
		});
	});

	test('current-file command scans the active unsaved buffer through Core and preserves the characterized findings', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const file = path.join(fixtureRoot, 'lib', 'clean.dart');
			const content = "void main() {\n  print('unsaved');\n  const apiKey = '12345678901234567890';\n}\n";
			const outcome = await runCurrentFileCoreScan(file, content);
			assert.equal(outcome.request.filePath, file);
			assert.equal(outcome.request.content, content);
			assert.equal(outcome.request.policy.maxFileSizeBytes, null, 'current-file scans remain uncapped');
			assert.ok(outcome.request.policy.supportedExtensions.includes('.dart'));
			assert.equal(outcome.request.policy.eligible, true);
			assert.equal(outcome.legacyCalls, 0, 'current-file command must not call WorkspaceScanner.scanDocument');
			assert.deepEqual(outcome.issues.map(issue => issue.ruleId), scanContent(file, content).map(issue => issue.ruleId));
			assert.equal(outcome.issues[0].lineText, "  print('unsaved');");
			assert.equal(outcome.issues[0].range.startLine, 1);
			assert.equal(outcome.issues[0].range.startColumn, 2);
			assert.equal(outcome.issues[0].range.endColumn, 8);
			assert.equal('workspaceRoot' in outcome.request, false, 'file scan must not request workspace traversal');
		});
	});

	test('current-file command preserves clean and comment-only fixture behavior', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const cleanPath = path.join(fixtureRoot, 'lib', 'clean.dart');
			const clean = await fs.readFile(cleanPath, 'utf8');
			assert.deepEqual((await runCurrentFileCoreScan(cleanPath, clean)).issues, []);
			const commentedPath = path.join(fixtureRoot, 'lib', 'commented.dart');
			const commented = await fs.readFile(commentedPath, 'utf8');
			assert.deepEqual((await runCurrentFileCoreScan(commentedPath, commented)).issues, []);
		});
	});

	test('current-file Core projection matches the vulnerable characterization fixture', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const file = path.join(fixtureRoot, 'lib', 'vulnerable.dart');
			const content = await fs.readFile(file, 'utf8');
			const expected = scanContent(file, content);
			const actual = await runCurrentFileCoreScan(file, content);
			assert.deepEqual(actual.issues.map(issue => [issue.file, issue.title, issue.message, issue.ruleId, issue.severity, issue.range.startLine, issue.range.startColumn, issue.range.endLine, issue.range.endColumn]), expected.map(issue => [issue.file, issue.title, issue.message, issue.ruleId, issue.severity, issue.range.startLine, issue.range.startColumn, issue.range.endLine, issue.range.endColumn]));
			assert.ok(actual.issues.every(issue => issue.lineText === content.split(/\r?\n/)[issue.range.startLine]));
			assert.equal(actual.legacyCalls, 0);
		});
	});

	test('current-file policy exposes all supported extensions and preserves the extension gate', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const outcome = await runCurrentFileCoreScan(path.join(fixtureRoot, 'lib', 'sample.rs'), '');
			assert.deepEqual(outcome.request.policy.supportedExtensions.sort(), [...supportedExtensions].sort());
			for (const extension of supportedExtensions) {
				assert.equal(isSupportedFile(vscode.Uri.file(path.join(fixtureRoot, 'lib', `sample${extension}`))), true, `${extension} should be accepted by the characterized extension gate`);
			}
			assert.equal(isSupportedFile(vscode.Uri.file(path.join(fixtureRoot, 'lib', 'sample.class'))), false, 'compiled .class files are rejected by the existing supported-file gate before Core');
			let coreCalls = 0;
			const compiledDocument = { uri: vscode.Uri.file(path.join(fixtureRoot, 'lib', 'Main.class')), getText: () => 'compiled' } as vscode.TextDocument;
			await withActiveDocument(compiledDocument, () => withCurrentFileController(controller => controller.scanCurrentFile(), async request => {
				coreCalls += 1;
				return { scanId: 'unexpected', filePath: request.filePath, state: 'completed', findings: [], filesScanned: 1, findingCount: 0, durationMs: 0 };
			}));
			assert.equal(coreCalls, 0, 'compiled extensions do not reach Core because the client supported-file gate rejects them first');
		});
	});

	test('current-file skip policy resolves .aq, generated, minified, and compiled cases', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const cases = [
				{ file: path.join(fixtureRoot, 'build', 'ignored.dart'), content: 'print("ignored");', oldReason: 'excluded by .aq' },
				{ file: path.join(fixtureRoot, 'lib', 'model.generated.dart'), content: 'print("generated");', oldReason: 'generated code' },
				{ file: path.join(fixtureRoot, 'lib', 'bundle.js'), content: `${'x'.repeat(1100)}\nshort`, oldReason: 'minified file' },
			] as const;
			for (const item of cases) {
				assert.equal(getSkipReason(item.file, item.content), item.oldReason);
				const result = await runCurrentFileCoreScan(item.file, item.content);
				assert.equal(result.request.policy.eligible, false);
				assert.deepEqual(result.request.policy.excludedPaths, [item.file]);
				assert.equal(result.result.state, 'skipped');
				assert.deepEqual(result.issues, []);
				assert.equal(result.result.filesScanned, 0, 'Core reports that the target was skipped');
				assert.equal(result.clientFilesScanned, 1, 'the VS Code command preserves its historical one-file result count even when skipped');
			}

			// Preserve the legacy current-file predicate: a long line alone is not minified.
			const longButNotMinified = `${'x'.repeat(1001)}\n${'short\n'.repeat(4)}`;
			const borderlinePath = path.join(fixtureRoot, 'lib', 'source.dart');
			assert.equal(getSkipReason(borderlinePath, longButNotMinified), undefined, 'legacy minified detection also requires a high average line length');
			const current = await runCurrentFileCoreScan(borderlinePath, longButNotMinified);
			assert.equal(current.result.state, 'completed', 'Core should scan a long line when the legacy average-line threshold is not met');

			await withExcludeFoldersAsync(['vendor'], async () => {
				const excludedPath = path.join(fixtureRoot, 'vendor', 'input.dart');
				assert.equal(getSkipReason(excludedPath, 'print("excluded");'), 'excluded folder');
				const excluded = await runCurrentFileCoreScan(excludedPath, 'print("excluded");');
				assert.equal(excluded.request.policy.eligible, false);
				assert.deepEqual(excluded.request.policy.excludedPaths, [excludedPath]);
			});
		});
	});

	test('current-file CORS rule conversion preserves legacy case-insensitive matching', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const file = path.join(fixtureRoot, 'lib', 'policy.js');
			const content = "CORS({ ORIGIN: '*' });";
			assert.ok(scanContent(file, content).some(issue => issue.ruleId === 'high.permissive-cors'));
			const current = await runCurrentFileCoreScan(file, content);
			assert.ok(current.issues.some(issue => issue.ruleId === 'high.permissive-cors'), 'converted Core rule preserves the legacy /i flag');
		});
	});

	test('current-file Python triple-quoted docstrings preserve legacy multiline stripping', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const file = path.join(fixtureRoot, 'lib', 'documented.py');
			const content = '"""\nDEBUG = True\n"""\n';
			assert.deepEqual(scanContent(file, content), [], 'legacy scanner treats this multiline string as non-executable content');
			const current = await runCurrentFileCoreScan(file, content);
			assert.deepEqual(current.issues, [], 'Core preserves triple-quoted string state across lines');
		});
	});

	test('current-file command resolves configured custom rules and explicit skip policy before Core scan', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const rule = { id: 'fixture.custom', title: 'Fixture policy', message: 'Remove this call.', severity: 'High', pattern: 'unsafeCall\\s*\\(', extensions: ['.dart'] };
			await withCustomRulesAsync([rule], async () => {
				const customPath = path.join(fixtureRoot, 'lib', 'custom.dart');
				const outcome = await runCurrentFileCoreScan(customPath, 'unsafeCall();');
				assert.deepEqual(outcome.issues.map(issue => issue.ruleId), ['fixture.custom']);
				assert.deepEqual(outcome.request.policy.customRules.find(candidate => candidate.id === rule.id), rule);
			});
			const generatedPath = path.join(fixtureRoot, 'lib', 'model.generated.dart');
			const skipped = await runCurrentFileCoreScan(generatedPath, 'print("should skip");');
			assert.equal(skipped.request.policy.eligible, false);
			assert.deepEqual(skipped.issues, []);
		});
	});

	test('current-file command retains workspace and Flutter gates without invoking Core', async () => {
		const fixtureRoot = path.resolve(__dirname, '../../../src/test/fixtures/file-scan');
		const file = path.join(fixtureRoot, 'outside.dart');
		const folder: vscode.WorkspaceFolder = { uri: vscode.Uri.file(fixtureRoot), name: 'Non-Flutter fixture', index: 0 };
		const workspace = vscode.workspace as unknown as Record<string, unknown>;
		const foldersDescriptor = Object.getOwnPropertyDescriptor(workspace, 'workspaceFolders');
		const lookupDescriptor = Object.getOwnPropertyDescriptor(workspace, 'getWorkspaceFolder');
		Object.defineProperty(workspace, 'workspaceFolders', { configurable: true, value: [folder] });
		Object.defineProperty(workspace, 'getWorkspaceFolder', { configurable: true, value: () => folder });
		let coreCalls = 0;
		try {
			const document = { uri: vscode.Uri.file(file), getText: () => 'print("x");' } as vscode.TextDocument;
			await withActiveDocument(document, () => withCurrentFileController(controller => controller.scanCurrentFile(), async request => {
				coreCalls += 1;
				return { scanId: 'unexpected', filePath: request.filePath, state: 'completed', findings: [], filesScanned: 1, findingCount: 0, durationMs: 0 };
			}));
		} finally {
			restoreProperty(workspace, 'workspaceFolders', foldersDescriptor);
			restoreProperty(workspace, 'getWorkspaceFolder', lookupDescriptor);
		}
		assert.equal(coreCalls, 0);
	});

	test('current-file command retains the active-file workspace-membership gate', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const workspace = vscode.workspace as unknown as Record<string, unknown>;
			const descriptor = Object.getOwnPropertyDescriptor(workspace, 'getWorkspaceFolder');
			Object.defineProperty(workspace, 'getWorkspaceFolder', { configurable: true, value: () => undefined });
			let coreCalls = 0;
			try {
				const document = { uri: vscode.Uri.file(path.join(fixtureRoot, 'lib', 'safe.dart')), getText: () => '' } as vscode.TextDocument;
				await withActiveDocument(document, () => withCurrentFileController(controller => controller.scanCurrentFile(), async request => {
					coreCalls += 1;
					return { scanId: 'unexpected', filePath: request.filePath, state: 'completed', findings: [], filesScanned: 1, findingCount: 0, durationMs: 0 };
				}));
			} finally {
				restoreProperty(workspace, 'getWorkspaceFolder', descriptor);
			}
			assert.equal(coreCalls, 0);
		});
	});

	test('records current supported types, Flutter gating, size policy, and skip policy', async () => {
		await withFlutterFixture(async fixtureRoot => {
			assert.equal(isFlutterWorkspace(fixtureRoot), true);
			assert.equal(isFlutterWorkspace(path.resolve(__dirname, '../../../src')), false);
			assert.equal(isSupportedFile(vscode.Uri.file(path.join(fixtureRoot, 'lib', 'test.rs'))), true);
			assert.equal(isSupportedFile(vscode.Uri.parse('untitled:test.dart')), false);
			assert.equal(getMaxFileSizeBytes(), 512 * 1024);
			assert.equal(getSkipReason(path.join(fixtureRoot, 'build', 'generated.dart')), 'excluded by .aq');
			assert.equal(getSkipReason(path.join(fixtureRoot, 'lib', 'model.generated.dart')), 'generated code');

			const oversized = path.join(fixtureRoot, 'lib', `oversized-${process.pid}.dart`);
			await fs.writeFile(oversized, ' '.repeat(getMaxFileSizeBytes() + 1), 'utf8');
			try {
				const result = await new WorkspaceScanner(quietOutput()).scanFile(vscode.Uri.file(oversized));
				assert.equal(result.filesScanned, 0);
				assert.deepEqual(result.issues, []);
			} finally {
				await fs.rm(oversized, { force: true });
			}
		});
	});

	test('scanFile cache reuses results when path, size, and mtime match', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const file = path.join(fixtureRoot, 'lib', `cache-probe-${process.pid}.dart`);
			const vulnerable = "const apiKey='12345678901234567890';\n";
			const safe = ' '.repeat(vulnerable.length);
			const equalLengthVulnerable = vulnerable;
			assert.equal(Buffer.byteLength(safe), Buffer.byteLength(equalLengthVulnerable));
			const scanner = new WorkspaceScanner(quietOutput());
			try {
				await fs.writeFile(file, safe, 'utf8');
				const fixedTime = new Date('2020-01-01T00:00:00.000Z');
				await fs.utimes(file, fixedTime, fixedTime);
				const first = await scanner.scanFile(vscode.Uri.file(file));
				assert.deepEqual(first.issues, []);
				await fs.writeFile(file, equalLengthVulnerable, 'utf8');
				await fs.utimes(file, fixedTime, fixedTime);
				const cached = await scanner.scanFile(vscode.Uri.file(file));
				assert.deepEqual(cached.issues, []);
			} finally {
				await fs.rm(file, { force: true });
			}
		});
	});

	test('save/realtime requests coalesce to the last supported document after the 800ms debounce', async function () {
		this.timeout(5000);
		await withFlutterFixture(async fixtureRoot => {
			const seen: string[] = [];
			const output = { appendLine: () => undefined } as unknown as vscode.OutputChannel;
			const scanner = new WorkspaceScanner(output);
			(scanner as unknown as { scanDocument(document: vscode.TextDocument): Promise<AqironScanResult> }).scanDocument = async document => {
				seen.push(document.uri.fsPath);
				return { workspaceRoot: fixtureRoot, target: document.uri.fsPath, filesScanned: 1, issues: [], durationMs: 1 };
			};
			const diagnostics = { setIssues: () => undefined } as unknown as DiagnosticManager;
			const sidebar = { setScanStatus: () => undefined, update: () => undefined, onPipelineEvent: () => undefined } as unknown as AqironWebviewController;
			const statusBar = { text: '', tooltip: '' } as vscode.StatusBarItem;
			const controller = new ScanController(scanner, diagnostics, sidebar, statusBar, output);
			const first = documentAt(path.join(fixtureRoot, 'lib', 'first.dart'));
			const second = documentAt(path.join(fixtureRoot, 'lib', 'second.dart'));
			const last = documentAt(path.join(fixtureRoot, 'lib', 'last.dart'));
			const unsupported = documentAt(path.join(fixtureRoot, 'lib', 'notes.txt'));
			try {
				controller.scanDocumentDebounced(unsupported);
				controller.scanDocumentDebounced(first);
				await delay(100);
				controller.scanDocumentDebounced(second);
				await delay(100);
				controller.scanDocumentDebounced(last);
				await delay(900);
				assert.deepEqual(seen, [last.uri.fsPath]);
			} finally {
				controller.dispose();
			}
		});
	});
});

async function withFlutterFixture(run: (root: string) => Promise<void>): Promise<void> {
	const root = path.resolve(__dirname, '../../../src/test/fixtures/file-scan/flutter');
	const workspace = vscode.workspace as unknown as Record<string, unknown>;
	const folderDescriptor = Object.getOwnPropertyDescriptor(workspace, 'workspaceFolders');
	const lookupDescriptor = Object.getOwnPropertyDescriptor(workspace, 'getWorkspaceFolder');
	const folder: vscode.WorkspaceFolder = { uri: vscode.Uri.file(root), name: 'Flutter characterization fixture', index: 0 };
	Object.defineProperty(workspace, 'workspaceFolders', { configurable: true, value: [folder] });
	Object.defineProperty(workspace, 'getWorkspaceFolder', {
		configurable: true,
		value: (uri: vscode.Uri) => uri.fsPath.toLowerCase().startsWith(root.toLowerCase()) ? folder : undefined,
	});
	try {
		await run(root);
	} finally {
		restoreProperty(workspace, 'workspaceFolders', folderDescriptor);
		restoreProperty(workspace, 'getWorkspaceFolder', lookupDescriptor);
	}
}

async function runCurrentFileCoreScan(filePath: string, content: string): Promise<{ request: CoreFileScanRequest; result: CoreFileScanResult; issues: import('../models/issue').AqironIssue[]; legacyCalls: number; clientFilesScanned: number }> {
	let capturedRequest: CoreFileScanRequest | undefined;
	let capturedResult: CoreFileScanResult | undefined;
	let capturedIssues: import('../models/issue').AqironIssue[] = [];
	let legacyCalls = 0;
	const client = {
		fileScan: async (request: CoreFileScanRequest) => {
			capturedRequest = request;
			const response = await new CoreRuntime({ coreVersion: 'file-scan-test' }).handle({
				id: `current-${Math.random().toString(36).slice(2, 8)}`, type: 'request', method: 'scan.file', params: request,
			}, () => undefined);
			if (!response.success) {throw new Error(response.error?.message ?? 'Core file scan failed.');}
			capturedResult = response.result as CoreFileScanResult;
			return capturedResult;
		},
	};
	const scanDocument = async (): Promise<never> => {legacyCalls += 1; throw new Error('Legacy current-file scan was invoked.');};
	const scanner = { scanDocument, scanWorkspace: async () => {throw new Error('Workspace scanner was invoked.');} } as unknown as WorkspaceScanner;
	const output = { appendLine: () => undefined } as unknown as vscode.OutputChannel;
	const sidebar = {
		setScanStatus: () => undefined,
		update: (issues: import('../models/issue').AqironIssue[]) => {capturedIssues = issues;},
		onPipelineEvent: () => undefined,
	} as unknown as AqironWebviewController;
	const controller = new ScanController(
		scanner,
		{ setIssues: () => undefined } as unknown as DiagnosticManager,
		sidebar,
		{ text: '', tooltip: '' } as vscode.StatusBarItem,
		output,
		undefined,
		undefined,
		undefined,
		client,
	);
	try {
		const document = { uri: vscode.Uri.file(filePath), getText: () => content } as vscode.TextDocument;
		await withActiveDocument(document, () => controller.scanCurrentFile());
	} finally {
		controller.dispose();
	}
	assert.ok(capturedRequest && capturedResult, 'current-file command must send a Core file-scan request');
	const clientFilesScanned = (controller as unknown as { workspaceStats: { filesScanned: number } }).workspaceStats.filesScanned;
	return { request: capturedRequest, result: capturedResult, issues: capturedIssues, legacyCalls, clientFilesScanned };
}

async function withActiveDocument<T>(document: vscode.TextDocument, run: () => Promise<T>): Promise<T> {
	const window = vscode.window as unknown as Record<string, unknown>;
	const descriptor = Object.getOwnPropertyDescriptor(window, 'activeTextEditor');
	Object.defineProperty(window, 'activeTextEditor', { configurable: true, value: { document } });
	try {
		return await run();
	} finally {
		restoreProperty(window, 'activeTextEditor', descriptor);
	}
}

async function withCurrentFileController<T>(run: (controller: ScanController) => Promise<T>, fileScan: (request: CoreFileScanRequest) => Promise<CoreFileScanResult>): Promise<T> {
	const scanner = new WorkspaceScanner(quietOutput());
	(scanner as unknown as { scanDocument: () => Promise<AqironScanResult> }).scanDocument = async () => {
		throw new Error('Legacy current-file scanner must not be called.');
	};
	const output = quietOutput();
	const sidebar = { setScanStatus: () => undefined, update: () => undefined, onPipelineEvent: () => undefined } as unknown as AqironWebviewController;
	const controller = new ScanController(
		scanner,
		{ setIssues: () => undefined } as unknown as DiagnosticManager,
		sidebar,
		{ text: '', tooltip: '' } as vscode.StatusBarItem,
		output,
		undefined,
		undefined,
		undefined,
		{ fileScan },
	);
	try {
		return await run(controller);
	} finally {
		controller.dispose();
	}
}

async function withCustomRulesAsync<T>(rules: unknown[], run: () => Promise<T>): Promise<T> {
	const workspace = vscode.workspace as unknown as Record<string, unknown>;
	const descriptor = Object.getOwnPropertyDescriptor(workspace, 'getConfiguration');
	const original = vscode.workspace.getConfiguration.bind(vscode.workspace);
	Object.defineProperty(workspace, 'getConfiguration', {
		configurable: true,
		value: (section?: string, scope?: vscode.ConfigurationScope) => section === 'aqiron-security'
			? { get: <V>(key: string, defaultValue?: V): V | unknown => key === 'customRules' ? rules : defaultValue }
			: original(section, scope),
	});
	try {
		return await run();
	} finally {
		restoreProperty(workspace, 'getConfiguration', descriptor);
	}
}

async function withExcludeFoldersAsync<T>(folders: string[], run: () => Promise<T>): Promise<T> {
	const workspace = vscode.workspace as unknown as Record<string, unknown>;
	const descriptor = Object.getOwnPropertyDescriptor(workspace, 'getConfiguration');
	const original = vscode.workspace.getConfiguration.bind(vscode.workspace);
	Object.defineProperty(workspace, 'getConfiguration', {
		configurable: true,
		value: (section?: string, scope?: vscode.ConfigurationScope) => section === 'aqiron-security'
			? { get: <V>(key: string, defaultValue?: V): V | unknown => key === 'excludeFolders' ? folders : defaultValue }
			: original(section, scope),
	});
	try {
		return await run();
	} finally {
		restoreProperty(workspace, 'getConfiguration', descriptor);
	}
}

function restoreProperty(target: Record<string, unknown>, key: string, descriptor: PropertyDescriptor | undefined): void {
	if (descriptor) {
		Object.defineProperty(target, key, descriptor);
	} else {
		Reflect.deleteProperty(target, key);
	}
}

function documentAt(file: string): vscode.TextDocument {
	return { uri: vscode.Uri.file(file) } as vscode.TextDocument;
}

function quietOutput(): vscode.OutputChannel {
	return { appendLine: () => undefined } as unknown as vscode.OutputChannel;
}

function makeIssue(ruleId: string, severity: 'Critical' | 'High' | 'Medium' | 'Low'): import('../models/issue').AqironIssue {
	return {
		id: ruleId,
		file: 'fixture.dart',
		title: ruleId,
		message: ruleId,
		severity,
		ruleId,
		range: { file: 'fixture.dart', startLine: 0, startColumn: 1, endLine: 0, endColumn: 2 },
		lineText: ruleId,
	};
}

function delay(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}

function withCustomRules<T>(rules: unknown[], run: () => T): T {
	const workspace = vscode.workspace as unknown as Record<string, unknown>;
	const descriptor = Object.getOwnPropertyDescriptor(workspace, 'getConfiguration');
	const original = vscode.workspace.getConfiguration.bind(vscode.workspace);
	Object.defineProperty(workspace, 'getConfiguration', {
		configurable: true,
		value: (section?: string, scope?: vscode.ConfigurationScope) => section === 'aqiron-security'
			? { get: <V>(key: string, defaultValue?: V): V | unknown => key === 'customRules' ? rules : defaultValue }
			: original(section, scope),
	});
	try {
		return run();
	} finally {
		if (descriptor) {
			Object.defineProperty(workspace, 'getConfiguration', descriptor);
		} else {
			Reflect.deleteProperty(workspace, 'getConfiguration');
		}
	}
}

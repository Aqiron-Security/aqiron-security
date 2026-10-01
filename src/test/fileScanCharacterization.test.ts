import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';
import { ScanController } from '../commands/scanController';
import { DiagnosticManager } from '../diagnostics/diagnosticManager';
import { AqironScanResult } from '../models/issue';
import { WorkspaceScanner } from '../scanner/workspaceScanner';
import { scanContent } from '../scanner/rules';
import { getMaxFileSizeBytes, getSkipReason, isFlutterWorkspace, isSupportedFile } from '../utils/files';
import { AqironWebviewController } from '../webview/aqironWebviewProvider';

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

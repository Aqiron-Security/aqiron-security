import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';
import { ScanController } from '../commands/scanController';
import { DiagnosticManager } from '../diagnostics/diagnosticManager';
import { defaultAqExclusions, getMaxFileSizeBytes, getSkipReason, isFlutterWorkspace, isSupportedFile, resolveWorkspaceScanPolicy, supportedExtensions } from '../utils/files';
import { AqironWebviewController } from '../webview/aqironWebviewProvider';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';
import { CoreFileScanRequest, CoreFileScanResult } from '../../packages/core/src/shared/fileScan';

suite('Core file and realtime scan characterization', () => {
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
		assert.deepEqual(outcome.issues.map(issue => issue.ruleId), ['medium.print', 'critical.api-key', 'low.unused-variable']);
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
			const actual = await runCurrentFileCoreScan(file, content);
			assert.deepEqual(actual.issues.map(issue => issue.ruleId), ['medium.print', 'critical.api-key', 'low.unused-variable']);
			assert.ok(actual.issues.every(issue => issue.lineText === content.split(/\r?\n/)[issue.range.startLine]));
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
			const current = await runCurrentFileCoreScan(file, content);
			assert.ok(current.issues.some(issue => issue.ruleId === 'high.permissive-cors'), 'converted Core rule preserves the legacy /i flag');
		});
	});

	test('current-file Python triple-quoted docstrings preserve legacy multiline stripping', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const file = path.join(fixtureRoot, 'lib', 'documented.py');
			const content = '"""\nDEBUG = True\n"""\n';
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

	test('post-fix current-document rescan uses Core file scanning and preserves the issue projection', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const filePath = path.join(fixtureRoot, 'lib', 'post-fix.dart');
			const content = "void main() {\n  print('remaining issue');\n}\n";
			let capturedRequest: CoreFileScanRequest | undefined;
			await withRealtimeController(async request => {
				capturedRequest = request;
				const response = await new CoreRuntime({ coreVersion: 'post-fix-scan-test' }).handle({
					id: `post-fix-${process.pid}`, type: 'request', method: 'scan.file', params: request,
				}, () => undefined);
				if (!response.success) {throw new Error(response.error?.message ?? 'Core post-fix scan failed.');}
				return response.result as CoreFileScanResult;
			}, async controller => {
				const document = documentAt(filePath, () => content);
				await (controller as unknown as { scanDocument(document: vscode.TextDocument, showMessage?: boolean): Promise<void> }).scanDocument(document, true);
				const actual = (controller as unknown as { diagnosticIssues: import('../models/issue').AqironIssue[] }).diagnosticIssues;
				assert.deepEqual(actual.map(issue => [issue.ruleId, issue.severity, issue.range.startLine, issue.range.startColumn, issue.lineText]), [['medium.print', 'Medium', 1, 2, "  print('remaining issue');"]]);
				assert.ok((controller as unknown as { outputLines: string[] }).outputLines.some(line => line.startsWith('Issues found: 1')));
			});
			assert.ok(capturedRequest);
			assert.equal(capturedRequest.filePath, filePath);
			assert.equal(capturedRequest.content, content, 'Core receives the current document buffer after the fix/save sequence');
			assert.equal(capturedRequest.policy.eligible, true);
			assert.ok(capturedRequest.policy.customRules.some(rule => rule.id === 'medium.print'));
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
		});
	});

	test('resolves deterministic workspace policy from effective VS Code settings and .aq rules', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-workspace-policy-'));
		const aqFile = path.join(root, '.aq');
		await fs.writeFile(aqFile, 'private/\n!private/keep.dart\n*.local\n# ignored comment\n', 'utf8');
		try {
			await withWorkspaceFolder({ uri: vscode.Uri.file(root), name: 'Resolved policy fixture', index: 0 }, async () => {
				await withSettingsAsync({ excludeFolders: ['vendor', 'ios\\Pods'], scanGeneratedFiles: true, maxFileSizeKB: 128 }, async () => {
					const first = resolveWorkspaceScanPolicy(root);
					const second = resolveWorkspaceScanPolicy(root);
					assert.deepEqual(first, second, 'same host settings and .aq input resolve deterministically');
					assert.deepEqual(first.supportedExtensions, [
						'.dart', '.ts', '.tsx', '.js', '.jsx', '.py', '.rs', '.java', '.c', '.cpp', '.h', '.json', '.xml', '.yaml', '.yml', '.gradle', '.rules',
					]);
					assert.ok(first.excludedDirectoryPaths.includes('vendor'));
					assert.ok(first.excludedDirectoryPaths.includes('ios/pods'));
					assert.ok(first.excludedDirectoryPaths.includes('node_modules'));
					assert.deepEqual(first.excludedFileNamePatterns, ['*.g.dart', '*.freezed.dart', '*.generated.*', '*.mocks.dart', '*.mock.dart', '*.config.dart']);
					assert.deepEqual(first.aqExclusionPatterns, [...defaultAqExclusions, 'private/', '!private/keep.dart', '*.local']);
					assert.equal(first.maxFileSizeBytes, 128 * 1024);
					assert.equal(first.skipGeneratedFiles, false, 'scanGeneratedFiles=true disables generated-file skipping');
					assert.equal(first.skipMinifiedFiles, true);
					assert.equal(first.skipCompiledFiles, true);
					assert.ok(!('eligible' in first), 'Flutter/project eligibility remains host-owned');
					assert.ok(!('trusted' in first), 'workspace trust remains separate from scan policy');
					assert.ok(!('content' in first), 'policy does not carry source content');
					assert.equal(getSkipReason(path.join(root, 'vendor', 'input.dart')), 'excluded folder');
					assert.equal(getSkipReason(path.join(root, 'private', 'blocked.dart')), 'excluded by .aq');
					assert.equal(getSkipReason(path.join(root, 'private', 'keep.dart')), undefined, 'ordered .aq negation preserves the existing re-include behavior');
					assert.equal(getSkipReason(path.join(root, 'lib', 'model.generated.dart')), undefined, 'scanGeneratedFiles disables heuristic generated checks');
					assert.equal(getSkipReason(path.join(root, 'lib', 'bundle.min.js')), 'minified file');
					assert.equal(getSkipReason(path.join(root, 'lib', 'Main.class')), 'compiled output');
				});
				await withSettingsAsync({}, async () => {
					const defaults = resolveWorkspaceScanPolicy(root);
					assert.equal(defaults.maxFileSizeBytes, 512 * 1024);
					assert.equal(defaults.skipGeneratedFiles, true);
					assert.equal(defaults.skipMinifiedFiles, true);
					assert.equal(defaults.skipCompiledFiles, true);
					assert.equal(getSkipReason(path.join(root, 'lib', 'model.generated.dart')), 'generated code');
				});
			});
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	test('save/realtime requests coalesce to the last supported document after the 800ms debounce and use Core', async function () {
		this.timeout(5000);
		await withFlutterFixture(async fixtureRoot => {
			const seen: CoreFileScanRequest[] = [];
			await withRealtimeController(async request => {
				seen.push(request);
				return emptyFileScanResult(request);
			}, async controller => {
				const first = documentAt(path.join(fixtureRoot, 'lib', 'first.dart'));
				const second = documentAt(path.join(fixtureRoot, 'lib', 'second.dart'));
				const last = documentAt(path.join(fixtureRoot, 'lib', 'last.dart'));
				const unsupported = documentAt(path.join(fixtureRoot, 'lib', 'notes.txt'));
				controller.scanDocumentDebounced(unsupported);
				controller.scanDocumentDebounced(first);
				await delay(100);
				controller.scanDocumentDebounced(second);
				await delay(100);
				controller.scanDocumentDebounced(last);
				await delay(900);
				assert.deepEqual(seen.map(request => request.filePath), [last.uri.fsPath]);
			});
		});
	});

	test('save/realtime reads the latest in-memory buffer after debounce and never reads stale disk content', async function () {
		this.timeout(5000);
		await withFlutterFixture(async fixtureRoot => {
			const filePath = path.join(fixtureRoot, 'lib', `realtime-buffer-${process.pid}.js`);
			const diskContent = 'function safe() { return true; }\n';
			let editorContent = 'function safe() { return true; }\n';
			await fs.writeFile(filePath, diskContent, 'utf8');
			const requestList: CoreFileScanRequest[] = [];
			try {
				await withRealtimeController(async request => {
					requestList.push(request);
					const response = await new CoreRuntime({ coreVersion: 'realtime-test' }).handle({
						id: `realtime-${process.pid}`, type: 'request', method: 'scan.file', params: request,
					}, () => undefined);
					if (!response.success) {throw new Error(response.error?.message ?? 'Core realtime scan failed.');}
					return response.result as CoreFileScanResult;
				}, async controller => {
					const document = documentAt(filePath, () => editorContent);
					controller.scanDocumentDebounced(document);
					await delay(450);
					editorContent = 'function unsafe(input) { return eval(input); }\n';
					await delay(500);
					assert.equal(requestList.length, 1);
					assert.equal(requestList[0].content, editorContent);
					assert.notEqual(requestList[0].content, diskContent);
					const observed = (controller as unknown as { diagnosticIssues: import('../models/issue').AqironIssue[] }).diagnosticIssues;
					assert.deepEqual(observed.map(issue => [issue.ruleId, issue.severity, issue.range.startLine, issue.range.startColumn, issue.lineText]), [['high.eval', 'High', 0, editorContent.indexOf('eval'), editorContent.trimEnd()]]);
				});
			} finally {
				await fs.rm(filePath, { force: true });
			}
		});
	});

	test('realtime scanning obeys the enable setting and continues to ignore unsupported extensions', async () => {
		await withFlutterFixture(async fixtureRoot => {
			await withSettingsAsync({ enableRealtimeScan: false }, async () => {
				await withRealtimeController(async () => { throw new Error('Core must not be called'); }, async controller => {
					controller.scanDocumentDebounced(documentAt(path.join(fixtureRoot, 'lib', 'eligible.dart'), () => 'print("x");'));
					assert.equal((controller as unknown as { requestCount: number }).requestCount, 0);
				});
			});
			await withSettingsAsync({ enableRealtimeScan: true }, async () => {
				await withRealtimeController(async () => { throw new Error('Core must not be called'); }, async controller => {
					controller.scanDocumentDebounced(documentAt(path.join(fixtureRoot, 'lib', 'notes.txt'), () => 'print("x");'));
					controller.scanDocumentDebounced(documentAt(path.join(fixtureRoot, 'lib', 'Main.class'), () => 'compiled'));
					assert.equal((controller as unknown as { requestCount: number }).requestCount, 0);
				});
			});
		});
	});

	test('realtime preserves Flutter gating, custom rules, skip policy, and uncapped document size', async () => {
		await withFlutterFixture(async fixtureRoot => {
			const rule = { id: 'fixture.realtime', title: 'Realtime custom', message: 'Review this call.', severity: 'High', pattern: 'unsafeRealtime\\s*\\(', extensions: ['.js'] };
			await withCustomRulesAsync([rule], async () => {
				await withRealtimeController(async request => {
					const response = await new CoreRuntime({ coreVersion: 'realtime-policy-test' }).handle({
						id: `policy-${process.pid}`, type: 'request', method: 'scan.file', params: request,
					}, () => undefined);
					if (!response.success) {throw new Error(response.error?.message ?? 'Core policy scan failed.');}
					return response.result as CoreFileScanResult;
				}, async controller => {
					const customPath = path.join(fixtureRoot, 'lib', 'realtime-custom.js');
					await invokeRealtimeNow(controller, documentAt(customPath, () => 'unsafeRealtime();'));
					assert.equal((controller as unknown as { lastRequest: CoreFileScanRequest }).lastRequest.policy.customRules.some(candidate => candidate.id === rule.id), true);
					assert.ok((controller as unknown as { diagnosticIssues: import('../models/issue').AqironIssue[] }).diagnosticIssues.some(issue => issue.ruleId === rule.id));

					const generatedPath = path.join(fixtureRoot, 'lib', 'model.generated.dart');
					await invokeRealtimeNow(controller, documentAt(generatedPath, () => 'print("generated");'));
					let request = (controller as unknown as { lastRequest: CoreFileScanRequest }).lastRequest;
					assert.equal(request.policy.eligible, false);
					assert.deepEqual(request.policy.excludedPaths, [generatedPath]);

					const minifiedPath = path.join(fixtureRoot, 'lib', 'realtime-bundle.js');
					await invokeRealtimeNow(controller, documentAt(minifiedPath, () => `${'x'.repeat(1200)}\\n${'y'.repeat(1200)}`));
					request = (controller as unknown as { lastRequest: CoreFileScanRequest }).lastRequest;
					assert.equal(request.policy.eligible, false);
					assert.equal(request.policy.maxFileSizeBytes, null);
					assert.equal(request.policy.skipCompiledFiles, true);

					await withSettingsAsync({ excludeFolders: ['vendor'] }, async () => {
						const excludedPath = path.join(fixtureRoot, 'vendor', 'realtime-excluded.js');
						await invokeRealtimeNow(controller, documentAt(excludedPath, () => 'unsafeRealtime();'));
						request = (controller as unknown as { lastRequest: CoreFileScanRequest }).lastRequest;
						assert.equal(request.policy.eligible, false);
						assert.deepEqual(request.policy.excludedPaths, [excludedPath]);
					});
				});
			});

			const nonFlutterRoot = path.resolve(__dirname, '../../../src/test/fixtures/file-scan');
			const nonFlutterFolder: vscode.WorkspaceFolder = { uri: vscode.Uri.file(nonFlutterRoot), name: 'Non-Flutter fixture', index: 0 };
			await withWorkspaceFolder(nonFlutterFolder, async () => {
				await withRealtimeController(async request => {
					const response = await new CoreRuntime({ coreVersion: 'realtime-flutter-test' }).handle({
						id: `flutter-${process.pid}`, type: 'request', method: 'scan.file', params: request,
					}, () => undefined);
					if (!response.success) {throw new Error(response.error?.message ?? 'Core Flutter gate scan failed.');}
					return response.result as CoreFileScanResult;
				}, async controller => {
					const document = documentAt(path.join(nonFlutterRoot, 'outside.js'), () => 'eval("x");');
					await invokeRealtimeNow(controller, document);
					assert.equal((controller as unknown as { lastRequest: CoreFileScanRequest }).lastRequest.policy.eligible, false);
					assert.deepEqual((controller as unknown as { diagnosticIssues: import('../models/issue').AqironIssue[] }).diagnosticIssues, []);
				});
			});
		});
	});

	test('realtime request during an active scan retains the workspace-scan fallback', async () => {
		await withFlutterFixture(async fixtureRoot => {
			await withRealtimeController(async () => { throw new Error('Core file scan must not start while controller is busy'); }, async controller => {
				const privateController = controller as unknown as { running: boolean; scanWorkspaceDebounced: () => void; fallbackCount: number; requestCount: number };
				privateController.running = true;
				privateController.fallbackCount = 0;
				privateController.scanWorkspaceDebounced = () => {privateController.fallbackCount += 1;};
				await invokeRealtimeNow(controller, documentAt(path.join(fixtureRoot, 'lib', 'active.js'), () => 'eval("x");'));
				assert.equal(privateController.fallbackCount, 1);
				assert.equal(privateController.requestCount, 0);
			});
		});
	});

	test('realtime Core errors are surfaced through the existing scan failure path', async () => {
		await withFlutterFixture(async fixtureRoot => {
			await withRealtimeController(async () => { throw new Error('Core request cancelled.'); }, async controller => {
				await invokeRealtimeNow(controller, documentAt(path.join(fixtureRoot, 'lib', 'cancelled.js'), () => 'eval("x");'));
				assert.equal((controller as unknown as { workspaceStats: { scanStatus: string } }).workspaceStats.scanStatus, 'Failed');
				assert.ok((controller as unknown as { outputLines: string[] }).outputLines.some(line => line.includes('Core request cancelled.')));
			});
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

async function withRealtimeController<T>(fileScan: (request: CoreFileScanRequest) => Promise<CoreFileScanResult>, run: (controller: ScanController) => Promise<T>): Promise<T> {
	let requestCount = 0;
	let lastRequest: CoreFileScanRequest | undefined;
	let diagnosticIssues: import('../models/issue').AqironIssue[] = [];
	const outputLines: string[] = [];
	const output = { appendLine: (line: string) => outputLines.push(line) } as unknown as vscode.OutputChannel;
	const diagnostics = { setIssues: (issues: import('../models/issue').AqironIssue[]) => {diagnosticIssues = issues;} } as unknown as DiagnosticManager;
	const sidebar = { setScanStatus: () => undefined, update: () => undefined, onPipelineEvent: () => undefined } as unknown as AqironWebviewController;
	const controller = new ScanController(diagnostics, sidebar, { text: '', tooltip: '' } as vscode.StatusBarItem, output, undefined, undefined, undefined, {
		fileScan: async request => {
			requestCount += 1;
			lastRequest = request;
			return await fileScan(request);
		},
	});
	Object.defineProperties(controller, {
		requestCount: { get: () => requestCount },
		lastRequest: { get: () => lastRequest },
		diagnosticIssues: { get: () => diagnosticIssues },
		outputLines: { get: () => outputLines },
	});
	try {
		return await run(controller);
	} finally {
		controller.dispose();
	}
}

async function invokeRealtimeNow(controller: ScanController, document: vscode.TextDocument): Promise<void> {
	await (controller as unknown as { scanRealtimeDocument(document: vscode.TextDocument): Promise<void> }).scanRealtimeDocument(document);
}

function emptyFileScanResult(request: CoreFileScanRequest): CoreFileScanResult {
	return { scanId: 'realtime-test', filePath: request.filePath, state: 'completed', findings: [], filesScanned: 1, findingCount: 0, durationMs: 1 };
}

async function withWorkspaceFolder<T>(folder: vscode.WorkspaceFolder, run: () => Promise<T>): Promise<T> {
	const workspace = vscode.workspace as unknown as Record<string, unknown>;
	const foldersDescriptor = Object.getOwnPropertyDescriptor(workspace, 'workspaceFolders');
	const lookupDescriptor = Object.getOwnPropertyDescriptor(workspace, 'getWorkspaceFolder');
	Object.defineProperty(workspace, 'workspaceFolders', { configurable: true, value: [folder] });
	Object.defineProperty(workspace, 'getWorkspaceFolder', { configurable: true, value: () => folder });
	try {
		return await run();
	} finally {
		restoreProperty(workspace, 'workspaceFolders', foldersDescriptor);
		restoreProperty(workspace, 'getWorkspaceFolder', lookupDescriptor);
	}
}

async function withSettingsAsync<T>(settings: Record<string, unknown>, run: () => Promise<T>): Promise<T> {
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
		restoreProperty(workspace, 'getConfiguration', descriptor);
	}
}

async function runCurrentFileCoreScan(filePath: string, content: string): Promise<{ request: CoreFileScanRequest; result: CoreFileScanResult; issues: import('../models/issue').AqironIssue[]; clientFilesScanned: number }> {
	let capturedRequest: CoreFileScanRequest | undefined;
	let capturedResult: CoreFileScanResult | undefined;
	let capturedIssues: import('../models/issue').AqironIssue[] = [];
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
	const output = { appendLine: () => undefined } as unknown as vscode.OutputChannel;
	const sidebar = {
		setScanStatus: () => undefined,
		update: (issues: import('../models/issue').AqironIssue[]) => {capturedIssues = issues;},
		onPipelineEvent: () => undefined,
	} as unknown as AqironWebviewController;
	const controller = new ScanController(
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
	return { request: capturedRequest, result: capturedResult, issues: capturedIssues, clientFilesScanned };
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
	const output = quietOutput();
	const sidebar = { setScanStatus: () => undefined, update: () => undefined, onPipelineEvent: () => undefined } as unknown as AqironWebviewController;
	const controller = new ScanController(
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

function documentAt(file: string, getText: () => string = () => ''): vscode.TextDocument {
	return { uri: vscode.Uri.file(file), getText } as vscode.TextDocument;
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

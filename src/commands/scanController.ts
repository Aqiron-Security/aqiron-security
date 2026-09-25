import * as vscode from 'vscode';
import { DiagnosticManager } from '../diagnostics/diagnosticManager';
import { AqironIssue, AqironScanResult, AqironWorkspaceStats } from '../models/issue';
import { WorkspaceScanner } from '../scanner/workspaceScanner';
import { SecurityOrchestrator } from '../security/orchestrator/securityOrchestrator';
import { SourceLocation } from '../shared/sourceSpan';
import { Debouncer } from '../utils/debounce';
import { getIssueSkipReason, isFlutterWorkspace, isSupportedFile } from '../utils/files';
import { getCounts } from '../views/aqironTreeProvider';
import { AqironWebviewController } from '../webview/aqironWebviewProvider';
import { ExecutiveSummaryGenerator } from '../security/reports/reportGenerator';
import { AIService } from '../ai/services/aiService';
import { RagWorkspaceService } from '../rag/ragWorkspaceService';

export class ScanController implements vscode.Disposable {
	private readonly debouncer = new Debouncer(800);
	private readonly issuesByFile = new Map<string, AqironIssue[]>();
	private workspaceStats: AqironWorkspaceStats = {
		filesScanned: 0,
		indexedFiles: 0,
		scanStatus: 'Idle',
		lastScanDurationMs: 0,
	};
	private running = false;
	private lastReport?: { directory?: string; jsonPath?: string; sarifPath?: string; pdfPath?: string; executiveSummary?: string };
	private readonly orchestrator: SecurityOrchestrator;
	private readonly pipelineSubscription: vscode.Disposable;

	constructor(
		private readonly scanner: WorkspaceScanner,
		private readonly diagnostics: DiagnosticManager,
		private readonly sidebar: AqironWebviewController,
		private readonly statusBar: vscode.StatusBarItem,
		private readonly output: vscode.OutputChannel,
		private readonly aiService?: AIService,
		private readonly rag?: RagWorkspaceService,
		private readonly reportSummaryGenerator?: ExecutiveSummaryGenerator,
	) {
		this.orchestrator = new SecurityOrchestrator(scanner, aiService, rag, reportSummaryGenerator);
		this.pipelineSubscription = this.orchestrator.events.on((event) => {
			this.sidebar.onPipelineEvent(event);
			if (event.type === 'log') {
				this.output.appendLine(`${event.tool ? `[${event.tool}] ` : ''}${event.message}`);
			}
		});
	}

	scanWorkspaceDebounced(): void {
		this.debouncer.run(() => {
			void this.scanWorkspace();
		});
	}

	scanDocumentDebounced(document: vscode.TextDocument): void {
		if (!vscode.workspace.getConfiguration('aqiron-security').get<boolean>('enableRealtimeScan', true)) {
			return;
		}

		if (!isSupportedFile(document.uri)) {
			return;
		}

		this.debouncer.run(() => {
			void this.scanDocument(document);
		});
	}

	async scanWorkspace(showMessage = false, mode: 'quick' | 'deep' | 'analysis' = 'deep'): Promise<void> {
		const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
		if (!workspaceFolder) {
			vscode.window.showWarningMessage('Open a workspace folder before running Aqiron Security.');
			return;
		}
		if (!isFlutterWorkspace(workspaceFolder.uri.fsPath)) {
			vscode.window.showInformationMessage('Aqiron Security currently supports Flutter workspaces only. Other workspace types will be supported in future.');
			return;
		}

		await this.runScan(async () => {
			const result = await this.orchestrator.scanWorkspace(workspaceFolder, mode);
			const visibleIssues = filterVisibleIssues(result.issues);
			this.replaceAll(visibleIssues);
			this.lastReport = result.report ? { ...result.report.exports, executiveSummary: result.report.executiveSummary } : undefined;
			if (showMessage) {
				const hiddenCount = result.issues.length - visibleIssues.length;
				const suffix = hiddenCount > 0 ? ` (${hiddenCount} generated/build finding${hiddenCount === 1 ? '' : 's'} hidden)` : '';
				vscode.window.showInformationMessage(`Aqiron Security scan completed: ${visibleIssues.length} actionable issue${visibleIssues.length === 1 ? '' : 's'} found${suffix}.`);
			}
			return { ...result, issues: visibleIssues };
		}, mode);
	}

	async analyzeWorkspace(showMessage = false): Promise<void> {
		await this.scanWorkspace(showMessage, 'analysis');
	}

	async scanCurrentFile(showMessage = false): Promise<void> {
		const document = vscode.window.activeTextEditor?.document;
		if (!document || !isSupportedFile(document.uri)) {
			vscode.window.showWarningMessage('Open a supported file before scanning.');
			return;
		}
		const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
		if (!workspaceFolder || !isFlutterWorkspace(workspaceFolder.uri.fsPath)) {
			vscode.window.showInformationMessage('Aqiron Security currently supports Flutter workspaces only. Other workspace types will be supported in future.');
			return;
		}

		await this.scanDocument(document, showMessage);
	}

	async fixCurrentFile(): Promise<void> {
		const editor = vscode.window.activeTextEditor;
		if (!editor || !isSupportedFile(editor.document.uri)) {
			vscode.window.showWarningMessage('Open a supported file before applying Aqiron Security fixes.');
			return;
		}

		const fileIssues = this.issuesByFile.get(editor.document.uri.fsPath) ?? [];
		const removableRules = new Set([
			'medium.console-log',
			'medium.print',
			'medium.debug',
			'medium.todo',
			'low.unused-variable',
		]);
		const lineNumbers = new Set(fileIssues.filter((issue) => removableRules.has(issue.ruleId)).map((issue) => issue.range.startLine));

		if (lineNumbers.size === 0) {
			vscode.window.showInformationMessage('No automatic fixes are available for the current file.');
			return;
		}

		const edit = new vscode.WorkspaceEdit();
		const lines = [...lineNumbers].sort((left, right) => right - left);
		for (const lineNumber of lines) {
			const line = editor.document.lineAt(lineNumber);
			const todoIssue = fileIssues.find((issue) => issue.ruleId === 'medium.todo' && issue.range.startLine === lineNumber);
			if (todoIssue) {
				edit.replace(editor.document.uri, line.range, line.text.replace(/\bTODO\b:?\s*/i, ''));
			} else {
				edit.delete(editor.document.uri, line.rangeIncludingLineBreak);
			}
		}

		await vscode.workspace.applyEdit(edit);
		await editor.document.save();
		await this.scanDocument(editor.document, true);
	}

	async openIssue(issue: AqironIssue): Promise<void> {
		const document = await vscode.workspace.openTextDocument(vscode.Uri.file(issue.file));
		const editor = await vscode.window.showTextDocument(document, { preview: false });
		const range = toVscodeRange(issue.range);
		editor.selection = new vscode.Selection(range.start, range.end);
		editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
	}

	openSidebar(): void {
		this.sidebar.open();
	}

	dispose(): void {
		this.debouncer.dispose();
		this.pipelineSubscription.dispose();
		this.orchestrator.dispose();
	}

	cancelScan(): void {
		this.orchestrator.cancel();
		this.output.appendLine('Scan cancellation requested.');
		this.sidebar.setScanStatus('Failed');
	}

	private async scanDocument(document: vscode.TextDocument, showMessage = false): Promise<void> {
		await this.runScan(async () => {
			const result = await this.scanner.scanDocument(document);
			this.replaceFile(document.uri.fsPath, filterVisibleIssues(result.issues));
			if (showMessage) {
				vscode.window.showInformationMessage(`Aqiron Security file scan completed: ${result.issues.length} issue${result.issues.length === 1 ? '' : 's'} found.`);
			}
			return result;
		});
	}

	private async runScan(task: () => Promise<AqironScanResult>, scanMode?: 'quick' | 'deep' | 'analysis'): Promise<void> {
		if (this.running) {
			this.scanWorkspaceDebounced();
			return;
		}

		this.running = true;
		this.workspaceStats.scanStatus = 'Scanning';
		this.sidebar.setScanStatus('Scanning');
		this.statusBar.text = '$(sync~spin) Aqiron Security Scanning';

		try {
			await vscode.window.withProgress(
				{
					location: vscode.ProgressLocation.Window,
					title: 'Aqiron Security workspace scan',
				},
				async () => {
					const result = await task();
					this.workspaceStats = {
						filesScanned: result.filesScanned,
						indexedFiles: result.filesScanned,
						scanStatus: 'Complete',
						lastScanDurationMs: result.durationMs,
					};
				},
			);
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			this.workspaceStats.scanStatus = 'Failed';
			this.output.appendLine(`Scan failed: ${message}`);
			vscode.window.showErrorMessage(`Aqiron Security scan failed: ${message}`);
		} finally {
			this.running = false;
			this.refreshViews(scanMode);
		}
	}

	private replaceAll(issues: readonly AqironIssue[]): void {
		this.issuesByFile.clear();
		for (const issue of issues) {
			const fileIssues = this.issuesByFile.get(issue.file) ?? [];
			fileIssues.push(issue);
			this.issuesByFile.set(issue.file, fileIssues);
		}
	}

	private replaceFile(file: string, issues: readonly AqironIssue[]): void {
		this.issuesByFile.set(file, [...issues]);
	}

	private refreshViews(scanMode?: 'quick' | 'deep' | 'analysis'): void {
		const allIssues = [...this.issuesByFile.values()].flat();
		this.diagnostics.setIssues(allIssues);
		this.sidebar.update(allIssues, this.workspaceStats, this.lastReport, scanMode);

		const counts = getCounts(allIssues);
		this.statusBar.text = `$(shield) Aqiron Security ${counts.total} Issue${counts.total === 1 ? '' : 's'}`;
		this.statusBar.tooltip = `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low across ${counts.filesAffected} file${counts.filesAffected === 1 ? '' : 's'}`;
	}
}

function filterVisibleIssues(issues: readonly AqironIssue[]): AqironIssue[] {
	return issues.filter((issue) => !getIssueSkipReason(issue));
}

function toVscodeRange(range: SourceLocation): vscode.Range {
	return new vscode.Range(range.startLine, range.startColumn, range.endLine, range.endColumn);
}

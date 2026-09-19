import * as vscode from 'vscode';
import * as path from 'path';
import { AIService } from './ai/services/aiService';
import { AIContextSnapshot } from './ai/types/ai';
import { ScanController } from './commands/scanController';
import { DiagnosticManager } from './diagnostics/diagnosticManager';
import { AqironQuickFixProvider } from './providers/quickFixProvider';
import { WorkspaceScanner } from './scanner/workspaceScanner';
import { RagWorkspaceService } from './rag/ragWorkspaceService';
import { isFlutterWorkspace } from './utils/files';
import { AqironWebviewProvider } from './webview/aqironWebviewProvider';
import { ExecutiveSummaryGenerator } from './security/reports/reportGenerator';
import { CorrelationResult } from './security/correlation/correlationEngine';
import { UnifiedFinding } from './security/findings/finding';
import { CoreClient } from './core/coreClient';
import { setCoreClient } from './core/coreClientSingleton';

export function activate(context: vscode.ExtensionContext): void {
	const coreClient = new CoreClient({ extensionVersion: String(context.extension.packageJSON.version ?? '0.0.0') });
	setCoreClient(coreClient);
	const output = vscode.window.createOutputChannel('Aqiron Security');
	const aiService = new AIService(context);
	const scanner = new WorkspaceScanner(output);
	const diagnostics = new DiagnosticManager();
	const rag = new RagWorkspaceService(context, aiService);
	const sidebar = new AqironWebviewProvider(context, 'agent', aiService, rag);
	const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
	const controller = new ScanController(scanner, diagnostics, sidebar, statusBar, output, aiService, rag, createAiSummaryGenerator(aiService));

	statusBar.text = '$(shield) Aqiron Security';
	statusBar.tooltip = 'Open Aqiron Security';
	statusBar.command = 'aqiron-security.openSidebar';
	statusBar.show();

	context.subscriptions.push(
		output,
		aiService,
		diagnostics,
		statusBar,
		controller,
		rag,
		vscode.languages.registerCodeActionsProvider(
			{ scheme: 'file' },
			new AqironQuickFixProvider(),
			{ providedCodeActionKinds: AqironQuickFixProvider.providedCodeActionKinds },
		),
		vscode.commands.registerCommand('aqiron-security.scanWorkspace', (options?: { mode?: 'quick' | 'deep' }) => controller.scanWorkspace(true, options?.mode === 'quick' ? 'quick' : 'deep')),
		vscode.commands.registerCommand('aqiron-security.analyzeWorkspace', () => controller.analyzeWorkspace(true)),
		vscode.commands.registerCommand('aqiron-security.scanCurrentFile', () => controller.scanCurrentFile(true)),
		vscode.commands.registerCommand('aqiron-security.fixCurrentFile', () => controller.fixCurrentFile()),
		vscode.commands.registerCommand('aqiron-security.refreshScan', () => controller.scanWorkspace(true)),
		vscode.commands.registerCommand('aqiron-security.cancelScan', () => controller.cancelScan()),
		vscode.commands.registerCommand('aqiron-security.fixWorkspace', () => showPlaceholder('Fix Workspace')),
		vscode.commands.registerCommand('aqiron-security.openIssue', (issue) => controller.openIssue(issue)),
		vscode.commands.registerCommand('aqiron-security.openSidebar', () => controller.openSidebar()),
		vscode.commands.registerCommand('aqiron-security.explainIssue', () => sidebar.startChat('Explain the highest-risk current security finding and recommend a safe fix.')),
		vscode.commands.registerCommand('aqiron-security.openChat', () => sidebar.openAgent()),
		vscode.commands.registerCommand('aqiron-security.startAiSecurityReview', () => sidebar.startChat('Analyze this workspace security posture and summarize the top threats, exploit paths, and remediation priorities.')),
		vscode.commands.registerCommand('aqiron-security.ragReindexWithAi', () => rag.reindex(true)),
		vscode.commands.registerCommand('aqiron-security.ragReindexWithoutAi', () => rag.reindex(false)),
		vscode.commands.registerCommand('aqiron-security.ragReindex', async () => {
			const selected = await vscode.window.showQuickPick(['Build with AI', 'Build without AI'], { title: 'Build Aqiron RAG workspace' });
			if (selected) {await rag.reindex(selected === 'Build with AI');}
		}),
		vscode.commands.registerCommand('aqiron-security.ragAddRegex', () => rag.addFromClipboardOrFile()),
		vscode.commands.registerCommand('aqiron-security.ragSyncRegexes', () => rag.sync()),
		vscode.workspace.onDidSaveTextDocument((document) => controller.scanDocumentDebounced(document)),
		vscode.workspace.onDidChangeWorkspaceFolders(() => { void notifyWorkspaceSupport(); controller.scanWorkspaceDebounced(); }),
		{ dispose: () => void coreClient.stop() },
	);

	void (async () => {
		await coreClient.start();
		await aiService.initialize();
		await aiService.ensureFirstRunConfigured();
		await sidebar.refreshAiState();
		await sidebar.refreshWorkspaceProfile();
		await notifyWorkspaceSupport();
	})();
	output.appendLine('Aqiron Security extension activated.');
}

async function notifyWorkspaceSupport(): Promise<void> {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (root && !isFlutterWorkspace(root)) {
		await vscode.window.showInformationMessage('Aqiron Security currently supports Flutter workspaces only. Other workspace types will be supported in future.');
	}
}

export function deactivate(): void {}

function showPlaceholder(feature: string): void {
	vscode.window.showInformationMessage(`${feature} is prepared in Aqiron Security.`);
}

function createAiSummaryGenerator(aiService: AIService): ExecutiveSummaryGenerator {
	return async (workspaceRoot: string, findings: readonly UnifiedFinding[], correlation: CorrelationResult): Promise<string> => {
		const aiState = await aiService.getWebviewState();
		const context: AIContextSnapshot = {
			workspaceName: path.basename(workspaceRoot),
			workspaceRoot,
			projectTypes: ['Flutter'],
			backend: 'Flutter workspace',
			currentFile: 'Security scan report',
			scanStatus: 'Complete',
			stats: { filesScanned: findings.length, indexedFiles: findings.length },
			apis: [],
			issues: findings.slice(0, 30).map((finding) => ({
				title: finding.title,
				message: finding.description,
				severity: finding.severity,
				ruleId: finding.ruleId,
				file: path.relative(workspaceRoot, finding.file),
				line: finding.line,
				lineText: '',
				remediation: finding.remediation,
			})),
		};
		let summary = '';
		for await (const chunk of aiService.chat({
			sessionId: `report-summary-${Date.now()}`,
			text: `Write an executive security summary for this completed scan. Be concise but specific: explain the overall risk, the most important attack paths, and the top remediation priorities. Mention that ${correlation.summary.deduplicated} duplicate signals were correlated. Return plain text only, with no title or preamble.`,
			history: [],
			model: aiState.selection.model,
			intelligence: 'Medium',
			context,
		})) {
			if (chunk.type === 'error') {
				throw new Error(chunk.error ?? 'AI report summary failed.');
			}
			if (chunk.type === 'token') {
				summary += chunk.content ?? '';
			}
		}
		return summary;
	};
}

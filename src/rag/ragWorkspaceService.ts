import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';
import { AIService } from '../ai/services/aiService';
import { addRegexSignals, syncRegexes } from './regexLoader';
import { RagIndexService } from './ragIndexService';
import { runRagBenchmark } from './ragBenchmark';
import { RegexSignal } from './types';
import { defaultAqExclusions, isFlutterWorkspace } from '../utils/files';

export class RagWorkspaceService implements vscode.Disposable {
	readonly index = new RagIndexService();
	private root?: string;

	constructor(private readonly context: vscode.ExtensionContext, private readonly aiService: AIService) {}

	async hasWorkspaceIndex(): Promise<boolean> {
		const root = this.workspaceRoot();
		return Boolean(root && isFlutterWorkspace(root) && await this.index.hasIndex(root));
	}

	async getSuggestions(): Promise<string[]> {
		const root = this.workspaceRoot();
		if (!root) {return [];}
		try {
			const text = await fs.readFile(path.join(root, '.aqiron-security', 'suggestions.md'), 'utf8');
			return text.split(/\r?\n/).map((line) => line.replace(/^\s*(?:[-*]|\d+[.)])\s*/, '').trim()).filter((line) => line.length > 12).slice(0, 5);
		} catch {
			return [];
		}
	}

	async reindex(withAi: boolean): Promise<void> {
		const root = this.requireRoot();
		this.requireTrustedWorkspace();
		this.requireFlutterWorkspace(root);
		await ensureAqFile(root);
		if (withAi) {await this.requireAi();}
		try {
			const data = await this.index.reindex(root, { withAi, generateSuggestions: withAi ? (signals) => this.generateSuggestions(root, signals) : undefined });
			if (withAi) {await runRagBenchmark(root, this.index);}
			vscode.window.showInformationMessage(`Aqiron RAG index rebuilt: ${data.manifest.filesIndexed} files indexed${withAi ? ' with AI suggestions enabled' : ''}.`);
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			vscode.window.showErrorMessage(`Aqiron RAG build failed: ${message}`);
			throw error;
		}
	}

	async sync(): Promise<void> {
		const root = this.requireRoot();
		this.requireTrustedWorkspace();
		try {
			await syncRegexes(root);
			vscode.window.showInformationMessage('Aqiron trusted regex sources synchronized. Rebuild the RAG index to apply changes.');
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			vscode.window.showErrorMessage(`Aqiron regex synchronization failed: ${message}`);
			throw error;
		}
	}

	async addFromClipboardOrFile(): Promise<void> {
		const root = this.requireRoot();
		this.requireTrustedWorkspace();
		const choice = await vscode.window.showQuickPick(['Clipboard JSON', 'Choose JSON file'], { title: 'Add Aqiron regex signals' });
		if (!choice) {return;}
		let content = '';
		if (choice === 'Clipboard JSON') {
			content = await vscode.env.clipboard.readText();
		} else {
			const files = await vscode.window.showOpenDialog({ canSelectMany: false, filters: { JSON: ['json'] }, openLabel: 'Import regex JSON' });
			if (!files?.[0]) {return;}
			content = await fs.readFile(files[0].fsPath, 'utf8');
		}
		const patterns = parsePatterns(content);
		const preview = patterns.map((pattern) => `${pattern.id}: ${pattern.description}`).join('\n');
		const confirm = await vscode.window.showInformationMessage(`Import ${patterns.length} regex signal${patterns.length === 1 ? '' : 's'}?\n${preview.slice(0, 1000)}`, 'Import', 'Cancel');
		if (confirm !== 'Import') {return;}
		const result = await addRegexSignals(root, { id: `user-${Date.now()}`, name: 'Workspace imported signals', type: 'vetted-json', url: 'workspace://manual', patterns });
		vscode.window.showInformationMessage(`Imported ${result.accepted.length} regexes; rejected ${result.rejected.length}.`);
	}

	async refreshSuggestions(): Promise<void> {
		const root = this.requireRoot();
		this.requireTrustedWorkspace();
		await this.requireAi();
		await this.reindex(true);
		void root;
	}

	async openSettings(): Promise<void> {
		await vscode.commands.executeCommand('aqiron-security.openSettings');
	}

	dispose(): void {}

	private workspaceRoot(): string | undefined {
		this.root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		return this.root;
	}

	private requireRoot(): string {
		const root = this.workspaceRoot();
		if (!root) {
			vscode.window.showErrorMessage('Open a workspace folder before building the Aqiron RAG index.');
			throw new Error('No workspace folder is open.');
		}
		return root;
	}

	private requireTrustedWorkspace(): void {
		if (!vscode.workspace.isTrusted) {
			vscode.window.showErrorMessage('Aqiron RAG is blocked while VS Code is in Restricted Mode. Trust this workspace before indexing it.', 'Manage Workspace Trust').then((action) => {
				if (action === 'Manage Workspace Trust') {void vscode.commands.executeCommand('workbench.action.manageTrust');}
			});
			throw new Error('Workspace is not trusted.');
		}
	}

	private requireFlutterWorkspace(root: string): void {
		if (!isFlutterWorkspace(root)) {
			vscode.window.showInformationMessage('Aqiron Security currently supports Flutter workspaces only. Other workspace types will be supported in future.');
			throw new Error('Flutter workspace required.');
		}
	}

	private async requireAi(): Promise<void> {
		const state = await this.aiService.getWebviewState();
		if (!state.status.connected || !state.selection.model) {
			const action = await vscode.window.showErrorMessage('An AI provider and model must be configured before building AI suggestions.', 'Configure AI');
			if (action === 'Configure AI') {await this.aiService.configureProvider();}
			throw new Error('AI provider is not configured or connected.');
		}
	}

	private async generateSuggestions(root: string, signals: import('./types').SecuritySignal[]): Promise<void> {
		const state = await this.aiService.getWebviewState();
		const context = this.aiService.createContextSnapshot([], { filesScanned: 0, indexedFiles: 0, scanStatus: 'Complete', lastScanDurationMs: 0 }, {
			name: path.basename(root), root, types: [], backend: 'Unknown', currentFile: 'None', apis: signals.filter((signal) => signal.category === 'endpoint').map((signal) => signal.file),
		});
		let text = '';
		for await (const chunk of this.aiService.chat({
			sessionId: `rag-suggestions-${Date.now()}`,
			text: `Generate up to five concise, actionable Aqiron security workspace suggestions from these detected signals. Do not repeat secrets: ${signals.slice(0, 40).map((signal) => `${signal.category}:${signal.provider}:${signal.file}`).join(', ')}`,
			history: [], model: state.selection.model, intelligence: 'Medium', context,
		})) {
			if (chunk.type === 'error') {throw new Error(chunk.error ?? 'AI suggestion generation failed.');}
			if (chunk.type === 'token') {text += chunk.content ?? '';}
		}
		await fs.writeFile(path.join(root, '.aqiron-security', 'suggestions.md'), text || 'No suggestions were generated.', 'utf8');
	}
}

async function ensureAqFile(root: string): Promise<void> {
	const file = path.join(root, '.aq');
	try {
		await fs.access(file);
		return;
	} catch {
		const content = [
			'# Aqiron Security exclusions. Add gitignore-style files or folders below.',
			'# Flutter build and generated artifacts are excluded by default.',
			...defaultAqExclusions,
			'',
		].join('\n');
		await fs.writeFile(file, content, 'utf8');
	}
}

function parsePatterns(content: string): RegexSignal[] {
	const parsed = JSON.parse(content) as unknown;
	const patterns = Array.isArray(parsed) ? parsed : parsed && typeof parsed === 'object' && Array.isArray((parsed as { patterns?: unknown }).patterns) ? (parsed as { patterns: RegexSignal[] }).patterns : [];
	if (patterns.length === 0) {throw new Error('The selected input contains no regex patterns.');}
	return patterns;
}

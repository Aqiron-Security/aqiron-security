import * as childProcess from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';
import { AIService } from '../ai/services/aiService';
import { AIProviderId, AISettings, AITaskDefaults, AIWebviewState as ProductionAiWebviewState, defaultAISettings, defaultModelFilter } from '../ai/types/ai';
import { normalizeProviderError } from '../ai/utils/request';
import { AqironIssue, AqironSeverity, AqironWorkspaceStats, severityOrder } from '../models/issue';
import { PipelineEvent, PipelineStageState, ToolExecutionState } from '../security/pipeline/events';
import { WorkspaceScanner } from '../scanner/workspaceScanner';
import { getIssueSkipReason, isFlutterWorkspace } from '../utils/files';
import { getCounts } from '../views/aqironTreeProvider';
import { RagWorkspaceService } from '../rag/ragWorkspaceService';
import { ThreatHistoryService, ThreatSnapshot } from '../security/threatHistoryService';

export type AqironWebviewSection = 'agent' | 'scan' | 'threats' | 'reports' | 'settings' | 'aiAgent';
export type WorkspaceScanMode = 'quick' | 'deep' | 'analysis';

interface WebviewState {
	issues: AqironIssue[];
	stats: AqironWorkspaceStats;
	workspace: WorkspaceProfile;
	branches: string[];
	selectedThreatId?: string;
	zoom: number;
	threatSnapshots: ThreatSnapshot[];
	activeThreatSnapshotId?: string;
	memory: AgentMemory;
	chatSessions: ChatSession[];
	activeChatSessionId?: string;
	tokenUsage: TokenUsage;
	ai: AiWebviewState;
	mobsf: MobSfSettingsState;
	customRules: string;
	pipeline: WebviewPipelineState;
	rag: { ready: boolean; building: boolean; withAi: boolean; suggestionsGenerated: boolean; suggestions: string[]; restricted: boolean; backend: 'faiss' | 'local' };
}

interface MobSfSettingsState {
	baseUrl: string;
	apiKeyConfigured: boolean;
}

interface WorkspaceProfile {
	name: string;
	root?: string;
	types: string[];
	status: 'Ready' | 'Indexing' | 'No workspace';
	risk: 'Secure' | 'Review' | 'Elevated' | 'Critical';
	hasGit: boolean;
	backend: string;
	apis: string[];
	currentFile: string;
}

interface AgentMemory {
	previousPrompts: string[];
	ignoredFindings: string[];
	frameworksDetected: string[];
	apisDiscovered: string[];
	previousScans: Array<{ timestamp: string; issueCount: number; risk: WorkspaceProfile['risk'] }>;
}

interface ChatMessage {
	id: string;
	role: 'user' | 'assistant';
	content: string;
	createdAt: string;
	streaming?: boolean;
	commands?: ToolCommand[];
}

interface ToolCommand {
	label: string;
	command: string;
	status: 'queued' | 'ready' | 'running' | 'complete' | 'unavailable';
}

interface AgentToolResult {
	content: string;
	commands: ToolCommand[];
	issues?: AqironIssue[];
	stats?: Partial<AqironWorkspaceStats>;
}

interface ChatSession {
	id: string;
	title: string;
	createdAt: string;
	updatedAt: string;
	model: string;
	intelligence: string;
	streaming?: boolean;
	messages: ChatMessage[];
}

interface TokenUsage {
	promptTokens: number;
	completionTokens: number;
	totalTokens: number;
	contextWindow: number;
	contextUsed: number;
}

type AiWebviewState = ProductionAiWebviewState;

interface WebviewPipelineState {
	stages: PipelineStageState[];
	tools: ToolExecutionState[];
	logs: string[];
	lastReport?: {
		jsonPath?: string;
		sarifPath?: string;
		pdfPath?: string;
		executiveSummary?: string;
	};
}

interface SerializableIssue {
	id: string;
	title: string;
	message: string;
	severity: AqironSeverity;
	ruleId: string;
	file: string;
	relativeFile: string;
	line: number;
	column: number;
	lineText: string;
	tool: string;
	cwe: string;
	owasp: string;
	status: string;
	confidence: string;
	riskScore: number;
	rawEvidence?: unknown;
}

const defaultStats: AqironWorkspaceStats = {
	filesScanned: 0,
	indexedFiles: 0,
	scanStatus: 'Idle',
	lastScanDurationMs: 0,
};

export interface AqironWebviewController {
	update(issues: readonly AqironIssue[], stats?: Partial<AqironWorkspaceStats>, report?: WebviewPipelineState['lastReport'], scanMode?: WorkspaceScanMode): void;
	setScanStatus(scanStatus: AqironWorkspaceStats['scanStatus']): void;
	onPipelineEvent(event: PipelineEvent): void;
	open(): void;
}

export class AqironWebviewProvider implements vscode.WebviewViewProvider, AqironWebviewController {
	private view?: { webview: vscode.Webview };
	private panel?: vscode.WebviewPanel;
	private agentPanel?: vscode.WebviewPanel;
	private readonly gitPromptedRoots = new Set<string>();
	private readonly threatHistory = new ThreatHistoryService();
	private readonly agentOutput = vscode.window.createOutputChannel('Aqiron Agent Tools');
	private readonly agentScanner = new WorkspaceScanner(this.agentOutput);
	private state: WebviewState = {
		issues: [],
		zoom: 1,
		threatSnapshots: [],
		stats: defaultStats,
		workspace: {
			name: 'No workspace',
			status: 'No workspace',
			types: [],
			hasGit: false,
			risk: 'Secure',
			backend: 'Unknown',
			apis: [],
			currentFile: 'No file',
		},
		branches: [],
		memory: {
			previousPrompts: [],
			ignoredFindings: [],
			frameworksDetected: [],
			apisDiscovered: [],
			previousScans: [],
		},
		chatSessions: [],
		tokenUsage: {
			promptTokens: 0,
			completionTokens: 0,
			totalTokens: 0,
			contextWindow: 128_000,
			contextUsed: 0,
		},
		ai: createDefaultAiState(),
		mobsf: getMobSfSettingsState(),
		customRules: formatCustomRules(getConfiguredCustomRules()),
		pipeline: {
			stages: [],
			tools: [],
			logs: [],
		},
		rag: { ready: false, building: false, withAi: true, suggestionsGenerated: false, suggestions: [], restricted: !vscode.workspace.isTrusted, backend: 'local' },
	};

	constructor(
		private readonly context: vscode.ExtensionContext,
		private section: AqironWebviewSection,
		private readonly aiService: AIService,
		private readonly rag: RagWorkspaceService,
	) {
		this.state = {
			...this.state,
			zoom: clamp(this.context.workspaceState.get<number>('aqiron.security.zoom', 1), 0.85, 1.3),
			chatSessions: this.context.workspaceState.get<ChatSession[]>(getChatSessionsKey(), []),
		};
		void this.refreshAiState();
	}

	open(): void {
		if (this.panel) {
			this.panel.reveal(vscode.ViewColumn.Beside);
			return;
		}

		const panel = vscode.window.createWebviewPanel(
			'aqiron-security.panel',
			'Aqiron Security',
			vscode.ViewColumn.Beside,
			{
				enableScripts: true,
				retainContextWhenHidden: true,
				localResourceRoots: [
					vscode.Uri.joinPath(this.context.extensionUri, 'assets'),
					vscode.Uri.joinPath(this.context.extensionUri, 'resources'),
					vscode.Uri.joinPath(this.context.extensionUri, 'dist'),
				],
			},
		);
		panel.iconPath = vscode.Uri.joinPath(this.context.extensionUri, 'assets', 'logos', 'aqiron-security-logo-mono.svg');
		this.panel = panel;
		this.view = panel;
		panel.webview.html = this.render(panel.webview);
		panel.webview.onDidReceiveMessage((message: { command: string; payload?: unknown }) => {
			void this.handleWebviewMessage(message.command, message.payload);
		});
		panel.onDidDispose(() => {
			this.panel = undefined;
			if (this.view === panel) {
				this.view = undefined;
			}
		});
		void this.refreshWorkspaceProfile();
	}

	openAgent(): void {
		this.openAgentPanel(this.state.activeChatSessionId);
	}

	startChat(text: string): void {
		void this.sendChat({ text });
	}

	private openAgentPanel(sessionId?: string): void {
		if (sessionId) {
			this.state = { ...this.state, activeChatSessionId: sessionId };
		}
		const title = this.getActiveSession()?.title ?? 'AI Agent';
		if (this.agentPanel) {
			this.agentPanel.title = title;
			this.agentPanel.reveal(vscode.ViewColumn.Beside);
			this.postState();
			return;
		}

		const panel = vscode.window.createWebviewPanel(
			'aqiron-security.aiAgent',
			title,
			vscode.ViewColumn.Beside,
			{
				enableScripts: true,
				retainContextWhenHidden: true,
				localResourceRoots: [
					vscode.Uri.joinPath(this.context.extensionUri, 'assets'),
					vscode.Uri.joinPath(this.context.extensionUri, 'resources'),
					vscode.Uri.joinPath(this.context.extensionUri, 'dist'),
				],
			},
		);
		panel.iconPath = vscode.Uri.joinPath(this.context.extensionUri, 'assets', 'tab', 'agents.svg');
		this.agentPanel = panel;
		panel.webview.html = this.render(panel.webview, 'aiAgent');
		panel.webview.onDidReceiveMessage((message: { command: string; payload?: unknown }) => {
			void this.handleWebviewMessage(message.command, message.payload);
		});
		panel.onDidDispose(() => {
			this.agentPanel = undefined;
		});
		this.postState();
	}

	resolveWebviewView(view: vscode.WebviewView): void {
		this.view = view;
		view.webview.options = {
			enableScripts: true,
				localResourceRoots: [
					vscode.Uri.joinPath(this.context.extensionUri, 'assets'),
					vscode.Uri.joinPath(this.context.extensionUri, 'resources'),
					vscode.Uri.joinPath(this.context.extensionUri, 'dist'),
				],
		};
		view.webview.html = this.render(view.webview);
		view.webview.onDidReceiveMessage((message: { command: string; payload?: unknown }) => {
			void this.handleWebviewMessage(message.command, message.payload);
		});
		void this.refreshWorkspaceProfile();
	}

	update(issues: readonly AqironIssue[], stats?: Partial<AqironWorkspaceStats>, report?: WebviewPipelineState['lastReport'], scanMode: WorkspaceScanMode = 'deep'): void {
		this.state = {
			...this.state,
			issues: [...issues],
			stats: { ...this.state.stats, ...stats },
			pipeline: report ? { ...this.state.pipeline, lastReport: report } : this.state.pipeline,
		};
		this.state.workspace = {
			...this.state.workspace,
			risk: getRiskStatus(this.state.issues),
			status: this.state.stats.scanStatus === 'Scanning' ? 'Indexing' : this.state.workspace.root ? 'Ready' : 'No workspace',
		};
		if (stats?.scanStatus === 'Complete') {
			const memory = this.getMemory();
			const previousScans = [{
				timestamp: new Date().toISOString(),
				issueCount: this.state.issues.length,
				risk: this.state.workspace.risk,
			}, ...memory.previousScans].slice(0, 20);
			this.state = { ...this.state, memory: { ...memory, previousScans } };
			void this.context.workspaceState.update(getMemoryKey(), this.state.memory);
			void this.persistThreatSnapshot(this.state.issues, this.state.stats.filesScanned, scanMode);
		}
		this.postState();
	}

	setScanStatus(scanStatus: AqironWorkspaceStats['scanStatus']): void {
		this.state = {
			...this.state,
			stats: { ...this.state.stats, scanStatus },
			pipeline: scanStatus === 'Scanning' ? { stages: [], tools: [], logs: [] } : this.state.pipeline,
			workspace: {
				...this.state.workspace,
				status: scanStatus === 'Scanning' ? 'Indexing' : this.state.workspace.root ? 'Ready' : 'No workspace',
			},
		};
		this.postState();
	}

	private async handleMessage(command: string, payload?: unknown): Promise<void> {
		switch (command) {
			case 'ready':
				await this.refreshAiState();
				this.postState();
				return;
			case 'focus':
				if (isAqironSection(payload)) {
					this.section = payload;
					this.postState();
				}
				return;
			case 'openChatSession':
				if (typeof payload === 'string') {
					this.openAgentView(payload);
				}
				return;
			case 'renameChatSession':
				await this.renameChatSession(payload);
				return;
			case 'deleteChatSession':
				await this.deleteChatSession(payload);
				return;
			case 'shareChatSession':
				await this.shareChatSession(payload);
				return;
			case 'selectPermissionMode':
				await this.selectPermissionMode(payload);
				return;
			case 'selectModel':
				await this.selectModel(payload);
				return;
			case 'refreshModels':
				await this.refreshModels();
				return;
			case 'switchProvider':
				await this.switchProvider(payload);
				return;
			case 'configureProvider':
				await this.configureProvider(payload);
				return;
			case 'saveProviderSettings':
				await this.saveProviderSettings(payload);
				return;
			case 'removeProviderCredentials':
				await this.removeProviderCredentials(payload);
				return;
			case 'saveApiCredential':
				await this.saveApiCredential(payload);
				return;
			case 'selectApiCredential':
				await this.selectApiCredential(payload);
				return;
			case 'deleteApiCredential':
				await this.deleteApiCredential(payload);
				return;
			case 'saveTaskDefaults':
				await this.saveTaskDefaults(payload);
				return;
			case 'saveMobSfSettings':
				await this.saveMobSfSettings(payload);
				return;
			case 'saveCustomRules':
				await this.saveCustomRules(payload);
				return;
			case 'applyModelFilter':
				await this.applyModelFilter(payload);
				return;
			case 'cancelGeneration':
				await this.cancelGeneration(payload);
				return;
			case 'selectIntelligence':
				await this.selectIntelligence(payload);
				return;
			case 'checkoutBranch':
				await this.checkoutBranch(payload);
				return;
			case 'createBranch':
				await this.createBranch();
				return;
			case 'sendChat':
			case 'sendChatToSession':
				await this.sendChat(payload);
				return;
			case 'scanWorkspace':
				await vscode.commands.executeCommand('aqiron-security.scanWorkspace', getScanModePayload(payload));
				return;
			case 'aiVulnerabilityAnalysis':
				await vscode.commands.executeCommand('aqiron-security.analyzeWorkspace');
				return;
			case 'scanCurrentFile':
				await vscode.commands.executeCommand('aqiron-security.scanCurrentFile');
				return;
			case 'cancelScan':
				await vscode.commands.executeCommand('aqiron-security.cancelScan');
				return;
			case 'ragReindexWithAi':
				await this.reindexRag(true);
				return;
			case 'ragReindexWithoutAi':
				await this.reindexRag(false);
				return;
			case 'ragSyncRegexes':
				await this.rag.sync();
				await this.refreshRagState();
				return;
			case 'ragAddRegex':
				await this.rag.addFromClipboardOrFile();
				return;
			case 'ragRefreshSuggestions':
				await this.reindexRag(true);
				return;
			case 'openRagSettings':
				this.section = 'settings';
				this.postState();
				return;
			case 'setZoom':
				if (typeof payload === 'number' && Number.isFinite(payload)) {
					const zoom = clamp(payload, 0.85, 1.3);
					this.state = { ...this.state, zoom };
					await this.context.workspaceState.update('aqiron.security.zoom', zoom);
					this.postState();
				}
				return;
			case 'clearTerminal':
				this.state = { ...this.state, pipeline: { ...this.state.pipeline, logs: [] } };
				this.postState();
				return;
			case 'exportReport':
				await this.exportReport(payload);
				return;
			case 'exportFinding':
				await this.exportFinding(payload);
				return;
			case 'ignoreIssue':
				await this.ignoreIssue(payload);
				return;
			case 'createRuleFromFinding':
				await this.createRuleFromFinding(payload);
				return;
			case 'openIssue':
				if (typeof payload === 'string') {
					const issue = this.state.issues.find((candidate) => candidate.id === payload);
					if (issue) {
						await vscode.commands.executeCommand('aqiron-security.openIssue', issue);
					}
				}
				return;
			case 'selectThreatSnapshot':
				if (typeof payload === 'string') {
					this.selectThreatSnapshot(payload);
				}
				return;
			case 'deleteThreatSnapshot':
				if (typeof payload === 'string') {
					await this.deleteThreatSnapshot(payload);
				}
				return;
			case 'openPolicy':
				await this.openPolicyFile();
				return;
			case 'agentAction':
				await this.recordPrompt(String(payload));
				vscode.window.showInformationMessage(`Aqiron agent queued: ${String(payload)}`);
				return;
			case 'setupComplete':
				await this.context.workspaceState.update(getSetupKey(), true);
				this.section = 'agent';
				this.postState();
				return;
			default:
				vscode.window.showInformationMessage('Aqiron Security is preparing this workflow.');
		}
	}

	private postState(): void {
		this.view?.webview.postMessage({
			type: 'state',
			state: this.serializeState(undefined, this.view.webview),
		});
		this.agentPanel?.webview.postMessage({
			type: 'state',
			state: this.serializeState('aiAgent', this.agentPanel.webview),
		});
	}

	private async handleWebviewMessage(command: string, payload?: unknown): Promise<void> {
		try {
			await this.handleMessage(command, payload);
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			vscode.window.showErrorMessage(`Aqiron Security could not complete ${command}: ${message}`);
		}
	}

	async refreshAiState(): Promise<void> {
		this.state = { ...this.state, ai: await this.aiService.getWebviewState(), mobsf: getMobSfSettingsState(), customRules: formatCustomRules(getConfiguredCustomRules()) };
		this.postState();
	}

	private async persistThreatSnapshot(issues: readonly AqironIssue[], filesScanned: number, mode: WorkspaceScanMode = 'deep'): Promise<void> {
		const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		if (!root || !isFlutterWorkspace(root)) {
			return;
		}
		try {
			const threatSnapshots = await this.threatHistory.record(root, issues, filesScanned, this.state.pipeline.lastReport?.executiveSummary, mode);
			this.state = {
				...this.state,
				threatSnapshots,
				activeThreatSnapshotId: threatSnapshots[0]?.id,
				selectedThreatId: issues[0]?.id,
			};
			this.postState();
		} catch (error) {
			this.agentOutput.appendLine(`Unable to persist threat history: ${error instanceof Error ? error.message : String(error)}`);
		}
	}

	private selectThreatSnapshot(id: string): void {
		const snapshot = this.state.threatSnapshots.find((entry) => entry.id === id);
		if (!snapshot) {
			return;
		}
		this.state = {
			...this.state,
			issues: snapshot.issues,
			stats: { ...this.state.stats, filesScanned: snapshot.filesScanned, indexedFiles: snapshot.filesScanned, scanStatus: 'Complete' },
			activeThreatSnapshotId: snapshot.id,
			selectedThreatId: snapshot.issues[0]?.id,
			pipeline: snapshot.executiveSummary ? { ...this.state.pipeline, lastReport: { ...this.state.pipeline.lastReport, executiveSummary: snapshot.executiveSummary } } : this.state.pipeline,
			workspace: { ...this.state.workspace, risk: getRiskStatus(snapshot.issues) },
		};
		this.postState();
	}

	private async deleteThreatSnapshot(id: string): Promise<void> {
		const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		if (!root || !isFlutterWorkspace(root)) {
			return;
		}
		const wasActive = this.state.activeThreatSnapshotId === id;
		const threatSnapshots = await this.threatHistory.delete(root, id);
		if (threatSnapshots.length === this.state.threatSnapshots.length) {
			return;
		}
		if (wasActive) {
			const next = threatSnapshots[0];
			if (next) {
				this.state = {
					...this.state,
					threatSnapshots,
					issues: next.issues,
					stats: { ...this.state.stats, filesScanned: next.filesScanned, indexedFiles: next.filesScanned, scanStatus: 'Complete' },
					activeThreatSnapshotId: next.id,
					selectedThreatId: next.issues[0]?.id,
					workspace: { ...this.state.workspace, risk: getRiskStatus(next.issues) },
					pipeline: next.executiveSummary ? { ...this.state.pipeline, lastReport: { ...this.state.pipeline.lastReport, executiveSummary: next.executiveSummary } } : this.state.pipeline,
				};
			} else {
				this.state = {
					...this.state,
					threatSnapshots,
					issues: [],
					stats: { ...this.state.stats, filesScanned: 0, indexedFiles: 0, scanStatus: 'Complete' },
					activeThreatSnapshotId: undefined,
					selectedThreatId: undefined,
					workspace: { ...this.state.workspace, risk: 'Secure' },
				};
			}
		} else {
			this.state = { ...this.state, threatSnapshots };
		}
		this.postState();
	}

	private async reindexRag(withAi: boolean): Promise<void> {
		this.state = { ...this.state, rag: { ...this.state.rag, building: true, withAi } };
		this.postState();
		try {
			await this.rag.reindex(withAi);
		} catch {
			// The service reports actionable details through VS Code notifications.
		} finally {
			await this.refreshRagState();
		}
	}

	private async refreshRagState(): Promise<void> {
		const ready = await this.rag.hasWorkspaceIndex();
		const data = this.rag.index.getData();
		const suggestions = ready ? await this.rag.getSuggestions() : [];
		this.state = { ...this.state, rag: { ...this.state.rag, ready, building: false, suggestionsGenerated: ready && data.manifest.aiSuggestionsGenerated, suggestions, restricted: !vscode.workspace.isTrusted, backend: this.rag.index.getVectorBackend() } };
		this.postState();
	}

	private async sendChat(payload: unknown): Promise<void> {
		await this.refreshAiState();
		const text = getPayloadText(payload);
		if (!text) {
			return;
		}
		if (await this.runRagSlashCommand(text)) {
			return;
		}
		await this.recordPrompt(text);
		const sessionId = getPayloadSessionId(payload);
		const selection = resolveChatSelection(this.state.ai, shouldUseTaskDefaults(payload));
		const existing = sessionId ? this.state.chatSessions.find((session) => session.id === sessionId) : undefined;
		const session = existing ?? createChatSession(text, selection);
		const now = new Date().toISOString();
		const userMessage: ChatMessage = { id: createId(), role: 'user', content: text, createdAt: now };
		const assistantMessage: ChatMessage = {
			id: createId(),
			role: 'assistant',
			content: '',
			createdAt: now,
			streaming: true,
		};
		const nextSession: ChatSession = {
			...session,
			title: session.messages.length === 0 ? createSessionTitle(text) : session.title,
			model: selection.model,
			intelligence: selection.intelligence,
			updatedAt: now,
			streaming: true,
			messages: [...session.messages, userMessage, assistantMessage],
		};
		let chatSessions = upsertSession(this.state.chatSessions, nextSession);
		this.state = {
			...this.state,
			activeChatSessionId: nextSession.id,
			chatSessions,
			tokenUsage: estimateTokenUsage(chatSessions),
		};
		this.openAgentView(nextSession.id);
		this.postState();
		const tool = selectAgentTool(text);
		if (tool) {
			const toolResult = await this.runAgentTool(text);
			await this.finishAssistantMessage(nextSession.id, assistantMessage.id, toolResult.content, toolResult.commands, toolResult);
			return;
		}
		try {
			const model = selection.model;
			if (!model) {
				throw new Error(selection.provider === 'openrouter'
					? 'Select an OpenRouter model after saving an API key.'
					: 'No models selected. Pick a recent or available model before starting chat.');
			}
			const history = session.messages.map((message) => ({ role: message.role, content: message.content }));
			const context = this.aiService.createContextSnapshot(this.state.issues, this.state.stats, this.state.workspace);
			let content = '';
			for await (const chunk of this.aiService.chat({
				sessionId: nextSession.id,
				text,
				history,
				model,
				intelligence: selection.intelligence,
				context,
			})) {
				if (chunk.type === 'token' && chunk.content) {
					content += chunk.content;
					this.updateAssistantMessage(nextSession.id, assistantMessage.id, { content, streaming: true });
				}
				if (chunk.type === 'error') {
					throw new Error(chunk.error ?? 'The provider stream returned an error.');
				}
			}
			this.updateAssistantMessage(nextSession.id, assistantMessage.id, { content: content || 'The provider returned an empty response.', streaming: false });
		} catch (error) {
			this.updateAssistantMessage(nextSession.id, assistantMessage.id, { content: normalizeProviderError(error), streaming: false });
			const cleanError = normalizeProviderError(error);
			if (cleanError !== 'Generation was cancelled.') {
				vscode.window.showErrorMessage(cleanError);
			}
		} finally {
			const latest = this.state.chatSessions;
			this.state = { ...this.state, chatSessions: markSessionStreaming(latest, nextSession.id, false), tokenUsage: estimateTokenUsage(latest) };
			await this.context.workspaceState.update(getChatSessionsKey(), serializeChatSessions(this.state.chatSessions));
			this.postState();
		}
		await this.refreshAiState();
	}

	private updateAssistantMessage(sessionId: string, messageId: string, patch: Partial<ChatMessage>): void {
		const chatSessions = this.state.chatSessions.map((session) => session.id === sessionId
			? {
				...session,
				updatedAt: new Date().toISOString(),
				messages: session.messages.map((message) => message.id === messageId ? { ...message, ...patch } : message),
			}
			: session);
		this.state = { ...this.state, chatSessions };
		this.postState();
	}

	private async finishAssistantMessage(sessionId: string, messageId: string, content: string, commands: ToolCommand[], toolResult?: AgentToolResult): Promise<void> {
		this.updateAssistantMessage(sessionId, messageId, { content, commands, streaming: false });
		const issues = toolResult?.issues ?? this.state.issues;
		const chatSessions = markSessionStreaming(this.state.chatSessions, sessionId, false);
		this.state = {
			...this.state,
			activeChatSessionId: sessionId,
			chatSessions,
			tokenUsage: estimateTokenUsage(chatSessions),
			issues,
			stats: { ...this.state.stats, ...toolResult?.stats },
			workspace: {
				...this.state.workspace,
				risk: getRiskStatus(issues),
				status: toolResult?.stats?.scanStatus === 'Scanning' ? 'Indexing' : this.state.workspace.status,
			},
		};
		await this.context.workspaceState.update(getChatSessionsKey(), serializeChatSessions(chatSessions));
		this.postState();
	}

	onPipelineEvent(event: PipelineEvent): void {
		switch (event.type) {
			case 'stage':
				this.state = {
					...this.state,
					pipeline: { ...this.state.pipeline, stages: upsertByName(this.state.pipeline.stages, event.stage) },
				};
				break;
			case 'tool':
				this.state = {
					...this.state,
					pipeline: { ...this.state.pipeline, tools: upsertById(this.state.pipeline.tools, event.tool) },
				};
				break;
			case 'log':
				this.state = {
					...this.state,
					pipeline: {
						...this.state.pipeline,
						logs: [...this.state.pipeline.logs.slice(-199), `${event.tool ? `[${event.tool}] ` : ''}${event.message}`],
					},
				};
				break;
			case 'complete':
				this.state = { ...this.state, stats: { ...this.state.stats, scanStatus: 'Complete', lastScanDurationMs: event.durationMs } };
				break;
			case 'cancelled':
				this.state = { ...this.state, stats: { ...this.state.stats, scanStatus: 'Failed' } };
				break;
			case 'error':
				this.state = {
					...this.state,
					pipeline: {
						...this.state.pipeline,
						logs: [...this.state.pipeline.logs.slice(-199), `[error] ${event.message}`],
					},
				};
				break;
			default:
				break;
		}
		this.postState();
	}

	private openAgentView(sessionId?: string): void {
		this.section = 'aiAgent';
		this.state = { ...this.state, activeChatSessionId: sessionId ?? this.state.activeChatSessionId };
		this.postState();
	}

	private async renameChatSession(payload: unknown): Promise<void> {
		if (!payload || typeof payload !== 'object') {
			return;
		}
		const { sessionId, title } = payload as { sessionId?: unknown; title?: unknown };
		const nextTitle = typeof title === 'string' ? title.trim() : '';
		if (typeof sessionId !== 'string' || !nextTitle) {
			return;
		}
		const chatSessions = this.state.chatSessions.map((session) => session.id === sessionId ? { ...session, title: nextTitle, updatedAt: new Date().toISOString() } : session).sort(sortSessions);
		this.state = { ...this.state, chatSessions };
		await this.context.workspaceState.update(getChatSessionsKey(), serializeChatSessions(chatSessions));
		this.postState();
	}

	private async deleteChatSession(payload: unknown): Promise<void> {
		const sessionId = typeof payload === 'string' ? payload : payload && typeof payload === 'object' && typeof (payload as { sessionId?: unknown }).sessionId === 'string' ? (payload as { sessionId: string }).sessionId : undefined;
		if (!sessionId) {
			return;
		}
		const chatSessions = this.state.chatSessions.filter((session) => session.id !== sessionId);
		this.state = {
			...this.state,
			chatSessions,
			activeChatSessionId: this.state.activeChatSessionId === sessionId ? chatSessions[0]?.id : this.state.activeChatSessionId,
			tokenUsage: estimateTokenUsage(chatSessions),
		};
		await this.context.workspaceState.update(getChatSessionsKey(), serializeChatSessions(chatSessions));
		this.postState();
	}

	private async shareChatSession(payload: unknown): Promise<void> {
		const sessionId = typeof payload === 'string' ? payload : payload && typeof payload === 'object' && typeof (payload as { sessionId?: unknown }).sessionId === 'string' ? (payload as { sessionId: string }).sessionId : undefined;
		const session = sessionId ? this.state.chatSessions.find((candidate) => candidate.id === sessionId) : undefined;
		if (!session) {
			return;
		}
		const fileName = `${session.title.replace(/[<>:"/\\|?*\x00-\x1F]/g, '').slice(0, 48) || 'aqiron-chat'}.txt`;
		const target = await vscode.window.showSaveDialog({
			defaultUri: vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? this.context.extensionPath, fileName)),
			filters: { 'Text file': ['txt'] },
			saveLabel: 'Export chat',
		});
		if (!target) {
			return;
		}
		const body = [
			session.title,
			`Model: ${session.model}`,
			`Intelligence: ${session.intelligence}`,
			`Created: ${new Date(session.createdAt).toLocaleString()}`,
			'',
			...session.messages.map((message) => `[${message.role.toUpperCase()}] ${new Date(message.createdAt).toLocaleString()}\n${message.content}`),
		].join('\n\n');
		await vscode.workspace.fs.writeFile(target, Buffer.from(body, 'utf8'));
		void vscode.window.showInformationMessage(`Exported chat: ${session.title}`);
	}

	private async exportReport(payload: unknown): Promise<void> {
		const format = typeof payload === 'string' ? payload : 'json';
		const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? this.context.extensionPath;
		const baseName = `aqiron-security-report-${new Date().toISOString().replace(/[:.]/g, '-')}`;
		const extension = format === 'pdf' ? 'pdf' : format === 'jira' || format === 'share' ? 'md' : 'json';
		const reportDirectory = path.join(workspaceRoot, '.aqiron-security', 'reports');
		await fs.mkdir(reportDirectory, { recursive: true });
		const target = await vscode.window.showSaveDialog({
			defaultUri: vscode.Uri.file(path.join(reportDirectory, `${baseName}.${extension}`)),
			filters: getReportFilters(format),
			saveLabel: format === 'jira' ? 'Save Jira ticket' : format === 'share' ? 'Save shareable report' : 'Export report',
		});
		if (!target) {
			return;
		}
		const content = format === 'pdf'
			? createPdfBuffer(this.state)
			: Buffer.from(format === 'json' ? JSON.stringify(createReportJson(this.state), null, 2) : createReportMarkdown(this.state, format), 'utf8');
		await vscode.workspace.fs.writeFile(target, content);
		void vscode.window.showInformationMessage(`Saved Aqiron report: ${target.fsPath}`);
	}

	private async exportFinding(payload: unknown): Promise<void> {
		const issue = this.findIssue(payload);
		if (!issue) {
			return;
		}
		const target = await vscode.window.showSaveDialog({
			defaultUri: vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? this.context.extensionPath, `${safeFileName(issue.title)}.json`)),
			filters: { 'JSON': ['json'] },
			saveLabel: 'Export finding',
		});
		if (!target) {
			return;
		}
		await vscode.workspace.fs.writeFile(target, Buffer.from(JSON.stringify(serializeIssue(issue), null, 2), 'utf8'));
	}

	private async ignoreIssue(payload: unknown): Promise<void> {
		const issue = this.findIssue(payload);
		if (!issue) {
			return;
		}
		this.state = {
			...this.state,
			issues: this.state.issues.map((candidate) => candidate.id === issue.id ? { ...candidate, status: 'Ignored' } : candidate),
		};
		this.postState();
	}

	private async createRuleFromFinding(payload: unknown): Promise<void> {
		const issue = this.findIssue(payload);
		if (!issue) {
			return;
		}
		const target = await vscode.window.showSaveDialog({
			defaultUri: vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? this.context.extensionPath, `${safeFileName(issue.title)}.aqiron-rule.json`)),
			filters: { 'Aqiron Rule': ['json'] },
			saveLabel: 'Save custom rule',
		});
		if (!target) {
			return;
		}
		const rule = {
			id: `custom.${safeFileName(issue.title)}`,
			title: issue.title,
			sourceTool: issue.sourceTool ?? getSourceTool(issue.ruleId),
			severity: issue.severity,
			cwe: issue.cwe ?? [getCwe(issue.ruleId)],
			owasp: issue.owasp ?? [getOwasp(issue.ruleId)],
			match: issue.lineText || issue.message,
			remediation: issue.remediation ?? 'Review the finding and encode a precise matcher before enabling this rule pack.',
		};
		await vscode.workspace.fs.writeFile(target, Buffer.from(JSON.stringify(rule, null, 2), 'utf8'));
	}

	private findIssue(payload: unknown): AqironIssue | undefined {
		return typeof payload === 'string' ? this.state.issues.find((candidate) => candidate.id === payload) : undefined;
	}

	private async runAgentTool(prompt: string): Promise<AgentToolResult> {
		const tool = selectAgentTool(prompt);
		if (!tool) {
			return unavailableToolResult('AI provider', 'No local Aqiron tool matched this request; route it through the selected AI provider instead.');
		}
		this.agentOutput.appendLine(`[agent] ${tool.id}: ${prompt}`);
		switch (tool.id) {
			case 'secrets.scan':
				return this.runSecretsScan();
			case 'workspace.scan':
				return this.runWorkspaceScan();
			case 'dependencies.scan':
				return this.runDependencyInventory();
			case 'workspace.graph':
				return this.runWorkspaceGraphTool();
			case 'mobsf.audit':
				return this.runMobSfAuditProbe();
			case 'api.fuzz':
				return this.runApiFuzzPlan();
		}
	}

	private async runSecretsScan(): Promise<AgentToolResult> {
		const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
		if (!workspaceFolder) {
			return unavailableToolResult('Hunt secrets', 'Open a workspace folder before running the secret scan.');
		}
		const startedAt = Date.now();
		const result = await this.agentScanner.scanWorkspace(workspaceFolder);
		const secretIssues = result.issues.filter((issue) => isSecretRule(issue.ruleId));
		const stats = {
			filesScanned: result.filesScanned,
			indexedFiles: result.filesScanned,
			scanStatus: 'Complete' as const,
			lastScanDurationMs: Date.now() - startedAt,
		};
		const commands: ToolCommand[] = [
			{ label: 'Hunt secrets', command: 'secrets.scan', status: 'complete' },
			{ label: 'Workspace scanner', command: `Scanned ${result.filesScanned} files with Aqiron rules`, status: 'complete' },
		];
		const findings = secretIssues.slice(0, 5).map((issue) => `- ${issue.title} in ${path.relative(workspaceFolder.uri.fsPath, issue.file)}:${issue.range.startLine + 1}`).join('\n');
		return {
			content: secretIssues.length > 0
				? [`Secret scan complete. Found ${secretIssues.length} potential secret finding${secretIssues.length === 1 ? '' : 's'}.`, findings].join('\n\n')
				: `Secret scan complete. I scanned ${result.filesScanned} files and found no hardcoded API keys, passwords, tokens, or private key material with the current Aqiron rules.`,
			commands,
			issues: mergeIssues(this.state.issues.filter((issue) => !isSecretRule(issue.ruleId)), secretIssues),
			stats,
		};
	}

	private async runWorkspaceScan(): Promise<AgentToolResult> {
		const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
		if (!workspaceFolder) {
			return unavailableToolResult('Run workspace scan', 'Open a workspace folder before running the workspace scan.');
		}
		const result = await this.agentScanner.scanWorkspace(workspaceFolder);
		return {
			content: `Workspace scan complete. Scanned ${result.filesScanned} files and found ${result.issues.length} issue${result.issues.length === 1 ? '' : 's'}.`,
			commands: [{ label: 'Run Aqiron workspace scan', command: 'workspace.scan', status: 'complete' }],
			issues: result.issues,
			stats: {
				filesScanned: result.filesScanned,
				indexedFiles: result.filesScanned,
				scanStatus: 'Complete',
				lastScanDurationMs: result.durationMs,
			},
		};
	}

	private async runDependencyInventory(): Promise<AgentToolResult> {
		const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		if (!root) {
			return unavailableToolResult('Check dependency manifests', 'Open a workspace folder before checking dependency manifests.');
		}
		const existing = [];
		for (const manifest of ['package.json', 'package-lock.json', 'pubspec.yaml', 'pubspec.lock', 'pom.xml', 'build.gradle', 'requirements.txt', 'pyproject.toml']) {
			if (await pathExists(path.join(root, manifest))) {
				existing.push(manifest);
			}
		}
		const list = unique(existing).slice(0, 12);
		return {
			content: list.length > 0
				? `Dependency inventory complete. Found ${list.length} manifest${list.length === 1 ? '' : 's'}:\n\n${list.map((item) => `- ${item}`).join('\n')}\n\nFor vulnerability checks, install or enable Trivy/SCA integration and run the dependency scan command.`
				: 'Dependency inventory complete. I did not find common dependency manifests in this workspace.',
			commands: [
				{ label: 'Inventory dependency manifests', command: 'dependencies.scan', status: 'complete' },
				{ label: 'Optional external SCA', command: 'trivy fs .', status: 'ready' },
			],
		};
	}

	private async runWorkspaceGraphTool(): Promise<AgentToolResult> {
		const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		if (!root) {
			return unavailableToolResult('Build workspace graph', 'Open a workspace folder before building the workspace graph.');
		}
		const graph = await buildWorkspaceGraph(root);
		return {
			content: [
				'Workspace graph refreshed.',
				`- APIs: ${graph.apis.length}`,
				`- Auth flows: ${graph.authFlows.length}`,
				`- Secret-related files: ${graph.secrets.length}`,
				`- Dependency files: ${graph.dependencies.length}`,
			].join('\n'),
			commands: [{ label: 'Build workspace graph', command: 'workspace.graph', status: 'complete' }],
		};
	}

	private async runMobSfAuditProbe(): Promise<AgentToolResult> {
		const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		if (!root) {
			return unavailableToolResult('Run MobSF audit', 'Open a workspace folder before preparing a MobSF audit.');
		}
		const hasAndroid = this.state.workspace.types.includes('Android') || this.state.workspace.types.includes('Flutter');
		return {
			content: hasAndroid
				? 'MoBSF audit workflow is prepared. Aqiron can identify Android/Flutter project artifacts, but this snapshot does not bundle a MobSF server or mobsfscan binary. Install MobSF/mobsfscan to execute the external static analysis command.'
				: 'MoBSF audit is only available for Android or Flutter workspaces. I did not detect those project types here.',
			commands: [
				{ label: 'Detect Android/Flutter project', command: `Workspace root: ${root}`, status: hasAndroid ? 'complete' : 'unavailable' },
				{ label: 'Run MobSF static analysis', command: 'mobsfscan .', status: hasAndroid ? 'ready' : 'unavailable' },
			],
		};
	}

	private async runApiFuzzPlan(): Promise<AgentToolResult> {
		const apis = this.state.workspace.apis;
		return {
			content: apis.length > 0
				? `API fuzzing plan prepared from ${apis.length} API-related file${apis.length === 1 ? '' : 's'}:\n\n${apis.slice(0, 6).map((api) => `- ${api}`).join('\n')}`
				: 'I did not find API route files in the workspace graph yet. Run a workspace scan or add route/controller files before fuzz planning.',
			commands: [{ label: 'Generate API fuzz cases', command: 'api.fuzz', status: apis.length > 0 ? 'complete' : 'unavailable' }],
		};
	}

	private async selectPermissionMode(payload: unknown): Promise<void> {
		if (typeof payload !== 'string' || !this.state.ai.permissionModes.some((mode) => mode.id === payload)) {
			return;
		}
		this.state = { ...this.state, ai: { ...this.state.ai, selection: { ...this.state.ai.selection, permissionMode: payload as AiWebviewState['selection']['permissionMode'] } } };
		this.postState();
	}

	private async selectModel(payload: unknown): Promise<void> {
		if (typeof payload !== 'string' || !this.state.ai.models.some((model) => model.id === payload)) {
			return;
		}
		await this.aiService.selectModel(payload);
		this.state = { ...this.state, ai: { ...this.state.ai, selection: { ...this.state.ai.selection, model: payload } } };
		await this.refreshAiState();
	}

	private async refreshModels(): Promise<void> {
		this.state = { ...this.state, ai: { ...this.state.ai, loadingModels: true, modelError: undefined } };
		this.postState();
		await this.aiService.refreshModels(true);
		await this.refreshAiState();
	}

	private async switchProvider(payload: unknown): Promise<void> {
		if (!isAiProviderId(payload)) {
			return;
		}
		await this.aiService.switchProvider(payload);
		await this.refreshAiState();
	}

	private async configureProvider(payload: unknown): Promise<void> {
		await this.aiService.configureProvider(isAiProviderId(payload) ? payload : undefined);
		await this.refreshAiState();
	}

	private async saveProviderSettings(payload: unknown): Promise<void> {
		if (!payload || typeof payload !== 'object') {
			return;
		}
		const patch = payload as Partial<AISettings>;
		const settings: Partial<AISettings> = {};
		if (typeof patch.temperature === 'number') {
			settings.temperature = clamp(patch.temperature, 0, 2);
		}
		if (typeof patch.maxTokens === 'number') {
			settings.maxTokens = Math.max(16, Math.floor(patch.maxTokens));
		}
		if (typeof patch.timeoutMs === 'number') {
			settings.timeoutMs = Math.max(5_000, Math.floor(patch.timeoutMs));
		}
		if (typeof patch.retries === 'number') {
			settings.retries = Math.max(0, Math.min(5, Math.floor(patch.retries)));
		}
		if (typeof patch.streaming === 'boolean') {
			settings.streaming = patch.streaming;
		}
		await this.aiService.updateSettings(settings);
		await this.refreshAiState();
	}

	private async removeProviderCredentials(payload: unknown): Promise<void> {
		if (!isAiProviderId(payload)) {
			return;
		}
		await this.aiService.removeProviderCredentials(payload);
		await this.refreshAiState();
	}

	private async saveApiCredential(payload: unknown): Promise<void> {
		if (!payload || typeof payload !== 'object') {
			return;
		}
		const value = payload as Record<string, unknown>;
		if (!isAiProviderId(value.providerId)) {
			return;
		}
		try {
			await this.aiService.saveApiCredential({
				id: typeof value.id === 'string' ? value.id : undefined,
				providerId: value.providerId,
				name: typeof value.name === 'string' ? value.name : undefined,
				key: typeof value.key === 'string' ? value.key : undefined,
			});
			await this.refreshAiState();
		} catch (error) {
			vscode.window.showErrorMessage(normalizeProviderError(error));
		}
	}

	private async selectApiCredential(payload: unknown): Promise<void> {
		if (typeof payload !== 'string') {
			return;
		}
		await this.aiService.selectApiCredential(payload);
		await this.refreshAiState();
	}

	private async deleteApiCredential(payload: unknown): Promise<void> {
		if (typeof payload !== 'string') {
			return;
		}
		await this.aiService.deleteApiCredential(payload);
		await this.refreshAiState();
	}

	private async saveTaskDefaults(payload: unknown): Promise<void> {
		if (!payload || typeof payload !== 'object') {
			return;
		}
		const value = payload as Record<string, unknown>;
		const defaults: AITaskDefaults = {
			useChatDefaults: typeof value.useChatDefaults === 'boolean' ? value.useChatDefaults : true,
			provider: isAiProviderId(value.provider) ? value.provider : undefined,
			model: typeof value.model === 'string' ? value.model : undefined,
			intelligence: typeof value.intelligence === 'string' ? value.intelligence : undefined,
			permissionMode: value.permissionMode === 'read-only' || value.permissionMode === 'ask-before-action' || value.permissionMode === 'workspace-trusted' ? value.permissionMode : undefined,
		};
		await this.aiService.saveTaskDefaults(defaults);
		await this.refreshAiState();
	}

	private async saveMobSfSettings(payload: unknown): Promise<void> {
		if (!payload || typeof payload !== 'object') {
			return;
		}
		const value = payload as Record<string, unknown>;
		const baseUrl = typeof value.baseUrl === 'string' ? value.baseUrl.trim() : '';
		const apiKey = typeof value.apiKey === 'string' ? value.apiKey.trim() : undefined;
		const config = vscode.workspace.getConfiguration('aqiron-security');
		await config.update('mobsfBaseUrl', baseUrl, vscode.ConfigurationTarget.Workspace);
		if (apiKey !== undefined) {
			await config.update('mobsfApiKey', apiKey, vscode.ConfigurationTarget.Workspace);
		}
		this.state = { ...this.state, mobsf: getMobSfSettingsState() };
		this.postState();
		vscode.window.showInformationMessage('MobSF settings saved.');
	}

	private async saveCustomRules(payload: unknown): Promise<void> {
		if (typeof payload !== 'string') {
			return;
		}
		try {
			const parsed = JSON.parse(payload) as unknown;
			if (!Array.isArray(parsed)) {
				throw new Error('Custom rules must be a JSON array.');
			}
			const rules = parsed.map(normalizeCustomRuleForSettings);
			await vscode.workspace.getConfiguration('aqiron-security').update('customRules', rules, vscode.ConfigurationTarget.Workspace);
			this.state = { ...this.state, customRules: formatCustomRules(rules) };
			this.postState();
			vscode.window.showInformationMessage('Aqiron custom rules saved.');
		} catch (error) {
			vscode.window.showErrorMessage(`Could not save custom rules: ${error instanceof Error ? error.message : String(error)}`);
		}
	}

	private async applyModelFilter(payload: unknown): Promise<void> {
		if (!payload || typeof payload !== 'object') {
			return;
		}
		const value = payload as Record<string, unknown>;
		this.aiService.applyModelFilter({
			query: typeof value.query === 'string' ? value.query : undefined,
			freeOnly: typeof value.freeOnly === 'boolean' ? value.freeOnly : undefined,
			codingOnly: typeof value.codingOnly === 'boolean' ? value.codingOnly : undefined,
			reasoningOnly: typeof value.reasoningOnly === 'boolean' ? value.reasoningOnly : undefined,
			visionOnly: typeof value.visionOnly === 'boolean' ? value.visionOnly : undefined,
		});
		await this.refreshAiState();
	}

	private async cancelGeneration(payload: unknown): Promise<void> {
		const sessionId = typeof payload === 'string' ? payload : this.state.activeChatSessionId;
		if (!sessionId) {
			return;
		}
		this.aiService.cancelGeneration(sessionId);
		const chatSessions = markSessionStreaming(this.state.chatSessions.map((session) => session.id === sessionId
			? { ...session, messages: session.messages.map((message) => message.streaming ? { ...message, streaming: false, content: message.content || 'Generation cancelled.' } : message) }
			: session), sessionId, false);
		this.state = { ...this.state, chatSessions };
		await this.context.workspaceState.update(getChatSessionsKey(), serializeChatSessions(chatSessions));
		this.postState();
	}

	private async selectIntelligence(payload: unknown): Promise<void> {
		if (typeof payload !== 'string' || !this.state.ai.intelligenceProfiles.some((profile) => profile.level === payload)) {
			return;
		}
		this.state = { ...this.state, ai: { ...this.state.ai, selection: { ...this.state.ai.selection, intelligence: payload } } };
		this.postState();
	}

	private async checkoutBranch(payload: unknown): Promise<void> {
		if (typeof payload !== 'string') {
			return;
		}
		const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		if (!root) {
			vscode.window.showInformationMessage('Open a workspace folder to switch branches.');
			return;
		}
		const ok = await execGit(root, ['checkout', payload]);
		if (!ok) {
			vscode.window.showErrorMessage(`Could not switch to branch: ${payload}`);
			return;
		}
		const branches = await getGitBranches(root);
		this.state = { ...this.state, branches: [payload, ...branches.filter((branch) => branch !== payload)] };
		this.postState();
	}

	private async createBranch(): Promise<void> {
		const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		if (!root) {
			vscode.window.showInformationMessage('Open a workspace folder to create a branch.');
			return;
		}
		const branchName = await vscode.window.showInputBox({
			title: 'Create and checkout new branch',
			prompt: 'Enter the new branch name',
			placeHolder: 'feature/security-audit',
			validateInput: (value) => /^[A-Za-z0-9._/-]+$/.test(value.trim()) ? undefined : 'Use letters, numbers, slash, dot, underscore, or dash.',
		});
		const nextBranch = branchName?.trim();
		if (!nextBranch) {
			return;
		}
		const ok = await execGit(root, ['checkout', '-b', nextBranch]);
		if (!ok) {
			vscode.window.showErrorMessage(`Could not create branch: ${nextBranch}`);
			return;
		}
		const branches = await getGitBranches(root);
		this.state = { ...this.state, branches: [nextBranch, ...branches.filter((branch) => branch !== nextBranch)] };
		this.postState();
	}

	private async recordPrompt(prompt: string): Promise<void> {
		const memory = this.getMemory();
		const nextPrompts = [prompt, ...memory.previousPrompts.filter((item) => item !== prompt)].slice(0, 12);
		await this.context.workspaceState.update(getMemoryKey(), { ...memory, previousPrompts: nextPrompts });
		this.state = { ...this.state, memory: { ...memory, previousPrompts: nextPrompts } };
		this.postState();
	}

	private async openPolicyFile(): Promise<void> {
		const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
		if (!workspaceFolder) {
			vscode.window.showInformationMessage('Open a workspace folder to view policy.json.');
			return;
		}

		const policyUri = vscode.Uri.joinPath(workspaceFolder.uri, 'policy.json');
		try {
			const document = await vscode.workspace.openTextDocument(policyUri);
			await vscode.window.showTextDocument(document, { preview: false });
		} catch {
			vscode.window.showInformationMessage('policy.json was not found in this workspace.');
		}
	}

	async refreshWorkspaceProfile(): Promise<void> {
		const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
		if (!workspaceFolder) {
			await this.refreshRagState();
			this.postState();
			return;
		}

		const root = workspaceFolder.uri.fsPath;
		if (!isFlutterWorkspace(root)) {
			this.state = {
				...this.state,
				workspace: {
					name: workspaceFolder.name,
					root,
					types: ['Unsupported workspace'],
					status: 'No workspace',
					risk: 'Secure',
					hasGit: false,
					backend: 'Flutter required',
					apis: [],
					currentFile: 'No file',
				},
				branches: [],
			};
			await this.refreshRagState();
			return;
		}
		const [types, branches, hasGit, graph, threatSnapshots] = await Promise.all([
			detectProjectTypes(root),
			getGitBranches(root),
			pathExists(path.join(root, '.git')),
			buildWorkspaceGraph(root),
			this.threatHistory.load(root),
		]);
		const memory = this.getMemory();
		const frameworksDetected = [...new Set([...memory.frameworksDetected, ...types])].slice(0, 16);
		const apisDiscovered = [...new Set([...memory.apisDiscovered, ...graph.apis])].slice(0, 24);
		const nextMemory = { ...memory, frameworksDetected, apisDiscovered };
		const activeThreatSnapshotId = this.state.activeThreatSnapshotId && threatSnapshots.some((snapshot) => snapshot.id === this.state.activeThreatSnapshotId) ? this.state.activeThreatSnapshotId : threatSnapshots[0]?.id;
		const activeThreatSnapshot = threatSnapshots.find((snapshot) => snapshot.id === activeThreatSnapshotId);
		const issues = this.state.issues.length ? this.state.issues : activeThreatSnapshot?.issues ?? [];
		await this.context.workspaceState.update(getMemoryKey(), nextMemory);

		this.state = {
			...this.state,
			workspace: {
				name: workspaceFolder.name,
				root,
				types,
				hasGit,
				status: this.state.stats.scanStatus === 'Scanning' ? 'Indexing' : 'Ready',
				risk: getRiskStatus(issues),
				backend: detectBackend(types),
				apis: graph.apis,
				currentFile: getCurrentFileName(),
			},
			branches,
			issues,
			stats: activeThreatSnapshot && this.state.issues.length === 0 ? { ...this.state.stats, filesScanned: activeThreatSnapshot.filesScanned, indexedFiles: activeThreatSnapshot.filesScanned, scanStatus: 'Complete' } : this.state.stats,
			threatSnapshots,
			activeThreatSnapshotId,
			selectedThreatId: this.state.selectedThreatId ?? issues[0]?.id,
			zoom: this.state.zoom,
			memory: nextMemory,
		};
		this.postState();
		await this.refreshRagState();
		if (!hasGit) {
			void this.showGitRecommendedPrompt(root);
		}
	}

	private async runRagSlashCommand(text: string): Promise<boolean> {
		const command = text.trim().toLowerCase();
		const commandMap: Record<string, string> = {
			'/rag-reindex-with-ai': 'aqiron-security.ragReindexWithAi',
			'/rag-reindex-without-ai': 'aqiron-security.ragReindexWithoutAi',
			'/rag-reindex': 'aqiron-security.ragReindex',
			'/rag-add-regex': 'aqiron-security.ragAddRegex',
			'/rag-sync-regexes': 'aqiron-security.ragSyncRegexes',
		};
		const target = commandMap[command];
		if (!target) {
			return false;
		}
		await vscode.commands.executeCommand(target);
		await this.refreshRagState();
		return true;
	}

	private async showGitRecommendedPrompt(root: string): Promise<void> {
		if (this.gitPromptedRoots.has(root) || this.context.workspaceState.get<boolean>(getGitPromptDisabledKey(root), false)) {
			return;
		}
		this.gitPromptedRoots.add(root);
		const action = await vscode.window.showInformationMessage(
			'Git is recommended in this workspace, initialize git',
			'Initialize',
			'Do it later',
			"Don't Show Again",
		);
		if (action === "Don't Show Again") {
			await this.context.workspaceState.update(getGitPromptDisabledKey(root), true);
			return;
		}
		if (action !== 'Initialize') {
			return;
		}
		const ok = await execGit(root, ['init']);
		if (!ok) {
			vscode.window.showErrorMessage('Could not initialize Git in this workspace.');
			return;
		}
		vscode.window.showInformationMessage('Git initialized for this workspace.');
		await this.refreshWorkspaceProfile();
	}

	private serializeState(sectionOverride?: AqironWebviewSection, webview = this.view?.webview): unknown {
		const setupDone = this.context.workspaceState.get<boolean>(getSetupKey(), false);
		const visibleIssues = this.state.issues.filter((issue) => !getIssueSkipReason(issue));
		const issues = visibleIssues.map(serializeIssue);
		const counts = getCounts(visibleIssues);
		const graph = buildSerializableGraph(issues, this.state.workspace);
		return {
			section: sectionOverride ?? this.section,
			setupDone,
			workspace: this.state.workspace,
			branches: this.state.branches,
			stats: this.state.stats,
			counts,
			issues,
			suggestions: this.state.rag.suggestionsGenerated ? buildSuggestions(issues, this.state.workspace.types, this.state.rag.suggestions) : [],
			rag: this.state.rag,
			selectedThreatId: this.state.selectedThreatId ?? issues[0]?.id,
			threatSnapshots: this.state.threatSnapshots.map((snapshot) => ({ ...snapshot, issues: snapshot.issues.map(serializeIssue) })),
			activeThreatSnapshotId: this.state.activeThreatSnapshotId,
			zoom: this.state.zoom,
			memory: this.getMemory(),
			graph,
			compliance: buildCompliance(counts),
			timeline: buildTimeline(this.getMemory(), counts, this.state.threatSnapshots),
			chatSessions: serializeChatSessions(this.state.chatSessions),
			activeChatSessionId: this.state.activeChatSessionId,
			tokenUsage: this.state.tokenUsage,
			ai: this.state.ai,
			mobsf: this.state.mobsf,
			customRules: this.state.customRules,
			pipeline: this.state.pipeline,
			assets: {
				logo: asWebviewUri(webview, this.context.extensionUri, 'assets/logos/aqiron-security-logo.svg'),
				logoMono: asWebviewUri(webview, this.context.extensionUri, 'assets/logos/aqiron-security-logo-mono.svg'),
				scanIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/others/scan.svg'),
				threatIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/others/threat.svg'),
				agentIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/tab/agents.svg'),
				reportsIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/tab/reports.svg'),
				addIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/chat/add.svg'),
				branchesIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/chat/branches.svg'),
				searchIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/chat/Search.svg'),
				chevronDownIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/chat/chevron-down.svg'),
				infoIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/chat/info.svg'),
				upArrowIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/chat/up_arrow.svg'),
				sessionOptionIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/ai_session_card/Option.svg'),
				sessionShareIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/ai_session_card/Share.svg'),
				sessionRenameIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/ai_session_card/Rename.svg'),
				sessionDeleteIcon: asWebviewUri(webview, this.context.extensionUri, 'assets/ai_session_card/Delete.svg'),
				glowOverlay: asWebviewUri(webview, this.context.extensionUri, 'assets/generated/glow-overlay.png'),
				aqironLogo: asWebviewUri(webview, this.context.extensionUri, 'assets/generated/aqiron-logo.svg'),
				critical: asWebviewUri(webview, this.context.extensionUri, 'assets/generated/critical.png'),
				high: asWebviewUri(webview, this.context.extensionUri, 'assets/generated/high.png'),
				medium: asWebviewUri(webview, this.context.extensionUri, 'assets/generated/medium.png'),
				low: asWebviewUri(webview, this.context.extensionUri, 'assets/generated/low.png'),
				scanLive: asWebviewUri(webview, this.context.extensionUri, 'assets/generated/scan-live.gif'),
				secureOrb: asWebviewUri(webview, this.context.extensionUri, 'assets/generated/secure-orb.svg'),
				initializationGrid: asWebviewUri(webview, this.context.extensionUri, 'assets/generated/cyber-grid.svg'),
				bg: asWebviewUri(webview, this.context.extensionUri, 'assets/backgrounds/ChatGPT Image May 9, 2026, 08_24_25 AM.png'),
			},
		};
	}

	private getMemory(): AgentMemory {
		return this.context.workspaceState.get<AgentMemory>(getMemoryKey(), this.state.memory);
	}

	private getActiveSession(): ChatSession | undefined {
		return this.state.chatSessions.find((session) => session.id === this.state.activeChatSessionId);
	}


	private render(webview: vscode.Webview, sectionOverride?: AqironWebviewSection): string {
		const nonce = getNonce();
		const state = JSON.stringify(this.serializeState(sectionOverride, webview)).replace(/</g, '\\u003c');
		const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'dist', 'webview.js'));
		const styleUri = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'dist', 'webview.css'));
		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${webview.cspSource} data:; font-src ${webview.cspSource}; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Aqiron Security</title>
	<link rel="stylesheet" href="${styleUri}">
</head>
<body>
	<div id="app"></div>
	<script nonce="${nonce}">window.__AQIRON_STATE__ = ${state};</script>
	<script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
	}
}

function getScanModePayload(payload: unknown): { mode: 'quick' | 'deep' } {
	if (payload && typeof payload === 'object' && (payload as { mode?: unknown }).mode === 'quick') {
		return { mode: 'quick' };
	}
	return { mode: 'deep' };
}
function isAqironSection(value: unknown): value is AqironWebviewSection {
	return value === 'agent' || value === 'scan' || value === 'threats' || value === 'reports' || value === 'settings' || value === 'aiAgent';
}

function asWebviewUri(webview: vscode.Webview | undefined, extensionUri: vscode.Uri, relativePath: string): string {
	if (!webview) {
		return '';
	}

	return webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, ...relativePath.split('/'))).toString();
}

function getConfiguredCustomRules(): unknown[] {
	return vscode.workspace.getConfiguration('aqiron-security').get<unknown[]>('customRules', defaultCustomRulesForSettings);
}

function getMobSfSettingsState(): MobSfSettingsState {
	const config = vscode.workspace.getConfiguration('aqiron-security');
	return {
		baseUrl: config.get<string>('mobsfBaseUrl', ''),
		apiKeyConfigured: Boolean(config.get<string>('mobsfApiKey', '').trim()),
	};
}

function formatCustomRules(rules: unknown[]): string {
	return JSON.stringify(rules, null, 2);
}

function normalizeCustomRuleForSettings(rule: unknown): Record<string, unknown> {
	if (!rule || typeof rule !== 'object') {
		throw new Error('Each rule must be an object.');
	}
	const value = rule as Record<string, unknown>;
	const id = requireString(value.id, 'id');
	const title = requireString(value.title, 'title');
	const message = requireString(value.message, 'message');
	const pattern = requireString(value.pattern, 'pattern');
	const severity = requireSeverity(value.severity);
	try {
		new RegExp(pattern);
	} catch (error) {
		throw new Error(`Rule ${id} has an invalid pattern: ${error instanceof Error ? error.message : String(error)}`);
	}
	const extensions = Array.isArray(value.extensions)
		? value.extensions.filter((extension): extension is string => typeof extension === 'string' && extension.trim().length > 0).map((extension) => extension.trim())
		: undefined;
	return { id, title, message, severity, pattern, ...(extensions?.length ? { extensions } : {}) };
}

function requireString(value: unknown, field: string): string {
	if (typeof value !== 'string' || !value.trim()) {
		throw new Error(`Rule ${field} must be a non-empty string.`);
	}
	return value.trim();
}

function requireSeverity(value: unknown): AqironSeverity {
	if (value === 'Critical' || value === 'High' || value === 'Medium' || value === 'Low') {
		return value;
	}
	throw new Error('Rule severity must be Critical, High, Medium, or Low.');
}

const defaultCustomRulesForSettings = [
	{
		id: 'high.firebase-open-rules',
		title: 'Open Firebase Rules',
		message: 'Firebase rules allow broad read/write access. Require authenticated users and resource-level authorization.',
		severity: 'High',
		pattern: 'allow\\s+(?:read|write|read,\\s*write)\\s*:\\s*if\\s+true',
		extensions: ['.rules', '.json'],
	},
	{
		id: 'high.android-exported-component',
		title: 'Exported Android Component',
		message: 'Exported Android components can expose app entry points. Add permissions or set exported=false unless intentionally public.',
		severity: 'High',
		pattern: 'android:exported\\s*=\\s*["\']true["\']',
		extensions: ['.xml'],
	},
	{
		id: 'medium.gradle-dynamic-version',
		title: 'Dynamic Dependency Version',
		message: 'Dynamic dependency versions reduce build reproducibility and can pull unexpected vulnerable releases.',
		severity: 'Medium',
		pattern: '(implementation|api|compileOnly|runtimeOnly)\\s*\\(?\\s*["\'][^"\']+:(?:\\+|latest\\.)',
		extensions: ['.gradle'],
	},
];

function createDefaultAiState(): AiWebviewState {
	return {
		providers: [
			{ id: 'openrouter', name: 'OpenRouter', connected: false, message: 'Not connected', hasCredential: false },
			{ id: 'openai', name: 'OpenAI', connected: false, message: 'Not connected', hasCredential: false },
			{ id: 'claude', name: 'Claude', connected: false, message: 'Not connected', hasCredential: false },
			{ id: 'gemini', name: 'Gemini', connected: false, message: 'Not connected', hasCredential: false },
		],
		models: [],
		filteredModels: [],
		modelFilter: defaultModelFilter,
		loadingModels: false,
		status: {
			providerId: defaultAISettings.selectedProvider,
			connected: false,
			message: 'Not connected',
		},
		settings: {
			selectedProvider: defaultAISettings.selectedProvider,
			selectedModel: defaultAISettings.selectedModel,
			recentModelIds: defaultAISettings.recentModelIds,
			activeApiCredentialId: defaultAISettings.activeApiCredentialId,
			apiCredentials: defaultAISettings.apiCredentials,
			taskDefaults: defaultAISettings.taskDefaults,
			temperature: defaultAISettings.temperature,
			maxTokens: defaultAISettings.maxTokens,
			timeoutMs: defaultAISettings.timeoutMs,
			retries: defaultAISettings.retries,
			streaming: defaultAISettings.streaming,
		},
		apiCredentials: [],
		taskDefaults: {
			useChatDefaults: true,
			provider: defaultAISettings.selectedProvider,
			model: defaultAISettings.selectedModel,
			intelligence: 'Medium',
			permissionMode: 'ask-before-action',
		},
		permissionModes: [
			{ id: 'read-only', label: 'Read Only Mode', description: 'Read workspace context without taking actions.' },
			{ id: 'ask-before-action', label: 'Ask Before Action', description: 'Confirm workspace actions first.' },
			{ id: 'workspace-trusted', label: 'Workspace Trusted', description: 'Allow trusted workspace actions.' },
		],
		intelligenceProfiles: [
			{ level: 'Low', label: 'Low', description: 'Short answers.' },
			{ level: 'Medium', label: 'Medium', description: 'Balanced reasoning.' },
			{ level: 'High', label: 'High', description: 'Deeper analysis.' },
			{ level: 'Extra High', label: 'Extra High', description: 'Maximum context and reasoning.' },
		],
		selection: {
			provider: defaultAISettings.selectedProvider,
			model: '',
			permissionMode: 'ask-before-action',
			intelligence: 'Medium',
		},
	};
}

function serializeIssue(issue: AqironIssue): SerializableIssue {
	const relativeFile = vscode.workspace.asRelativePath(issue.file);
	const range = issue.range as unknown as { startLine?: number; startColumn?: number; start?: { line?: number; character?: number } } | undefined;
	const line = range?.startLine ?? range?.start?.line ?? 0;
	const column = range?.startColumn ?? range?.start?.character ?? 0;
	return {
		id: issue.id,
		title: issue.title,
		message: issue.message,
		severity: issue.severity,
		ruleId: issue.ruleId,
		file: issue.file,
		relativeFile,
		line: line + 1,
		column: column + 1,
		lineText: issue.lineText.trim(),
		tool: issue.sourceTool && issue.sourceTool !== 'Aqiron' ? issue.sourceTool : getSourceTool(issue.ruleId),
		cwe: issue.cwe?.[0] ?? getCwe(issue.ruleId),
		owasp: issue.owasp?.[0] ?? getOwasp(issue.ruleId),
		status: issue.status ?? 'Open',
		confidence: issue.confidence ?? defaultConfidence(issue.severity),
		riskScore: issue.riskScore ?? getRiskScore(issue.severity),
		rawEvidence: redactWebviewEvidence(issue.rawEvidence),
	};
}

function isAiProviderId(value: unknown): value is AIProviderId {
	return value === 'openrouter' || value === 'openai' || value === 'claude' || value === 'gemini';
}

function clamp(value: number, min: number, max: number): number {
	return Math.max(min, Math.min(max, value));
}

function buildSuggestions(issues: readonly SerializableIssue[], projectTypes: readonly string[], aiSuggestions: readonly string[] = []): unknown[] {
	const suggestions: Array<{ title: string; detail: string; severity: AqironSeverity; recommended: boolean; command: string }> = aiSuggestions.map((detail, index) => ({
		title: `AI workspace suggestion ${index + 1}`,
		detail,
		severity: 'Medium' as const,
		recommended: index === 0,
		command: `Investigate: ${detail}`,
	}));
	suggestions.push(...issues.slice(0, 4).map((issue) => ({
		title: issue.title,
		detail: issue.message,
		severity: issue.severity,
		recommended: issue.severity === 'Critical' || issue.severity === 'High',
		command: `Investigate ${issue.relativeFile}:${issue.line}`,
	})));

	if (projectTypes.includes('Flutter')) {
		suggestions.push({
			title: 'Run Flutter APK security audit',
			detail: 'Build release APK, upload to MobSF, correlate manifest and Dart findings.',
			severity: 'High',
			recommended: true,
			command: 'Flutter MobSF audit',
		});
	}

	if (projectTypes.includes('Node.js') || projectTypes.includes('React')) {
		suggestions.push({
			title: 'Do fuzzing on API endpoints',
			detail: 'Discover route handlers and generate boundary-case payloads for local endpoints.',
			severity: 'Medium',
			recommended: issues.length > 0,
			command: 'Fuzz APIs',
		});
	}

	return suggestions.length > 0 ? suggestions : [{
		title: 'Run a deep baseline audit',
		detail: 'No immediate critical patterns are indexed yet. Start a deep scan to build project intelligence.',
		severity: 'Low',
		recommended: true,
		command: 'Deep scan',
	}];
}

async function detectProjectTypes(root: string): Promise<string[]> {
	const checks: Array<[string, string[]]> = [
		['Flutter', ['pubspec.yaml', 'lib/main.dart']],
		['React', ['package.json', 'src/App.tsx', 'src/App.jsx']],
		['Next.js', ['next.config.js', 'next.config.mjs', 'app/page.tsx', 'pages/index.tsx']],
		['Node.js', ['package.json']],
		['Python', ['requirements.txt', 'pyproject.toml']],
		['Java', ['pom.xml', 'build.gradle', 'settings.gradle']],
		['Android', ['AndroidManifest.xml', 'app/build.gradle']],
		['Firebase', ['firebase.json', '.firebaserc', 'firestore.rules']],
		['SQLite', ['database.sqlite', 'db.sqlite', 'app.db']],
		['Docker', ['Dockerfile', 'docker-compose.yml']],
	];
	const detected: string[] = [];
	for (const [type, files] of checks) {
		if (await anyPathExists(root, files)) {
			detected.push(type);
		}
	}
	if (await pathExists(path.join(root, '.git'))) {
		detected.push('Git repository');
	}
	return detected.length > 0 ? detected : ['Source workspace'];
}

async function anyPathExists(root: string, files: readonly string[]): Promise<boolean> {
	for (const file of files) {
		if (await pathExists(path.join(root, file))) {
			return true;
		}
	}
	return false;
}

async function pathExists(candidate: string): Promise<boolean> {
	try {
		await fs.stat(candidate);
		return true;
	} catch {
		return false;
	}
}

async function getGitBranches(root: string): Promise<string[]> {
	if (!(await pathExists(path.join(root, '.git')))) {
		return [];
	}

	return new Promise((resolve) => {
		childProcess.execFile('git', ['branch', '--format=%(refname:short)'], { cwd: root }, (error, stdout) => {
			if (error) {
				resolve([]);
				return;
			}
			resolve(stdout.split(/\r?\n/).map((branch) => branch.trim()).filter(Boolean).slice(0, 12));
		});
	});
}

async function execGit(root: string, args: readonly string[]): Promise<boolean> {
	return new Promise((resolve) => {
		childProcess.execFile('git', [...args], { cwd: root }, (error) => resolve(!error));
	});
}

function getSetupKey(): string {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? 'global';
	return `aqiron.setup.${root}`;
}

function getMemoryKey(): string {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? 'global';
	return `aqiron.memory.${root}`;
}

function getGitPromptDisabledKey(root: string): string {
	return `aqiron.gitPromptDisabled.${root}`;
}

function getChatSessionsKey(): string {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? 'global';
	return `aqiron.chat.sessions.${root}`;
}

function getCurrentFileName(): string {
	const document = vscode.window.activeTextEditor?.document;
	return document ? vscode.workspace.asRelativePath(document.uri) : 'No file';
}

function detectBackend(types: readonly string[]): string {
	if (types.includes('Firebase')) {
		return 'Firebase';
	}
	if (types.includes('SQLite')) {
		return 'SQLite';
	}
	if (types.includes('Node.js') || types.includes('Next.js')) {
		return 'Node API';
	}
	if (types.includes('Python')) {
		return 'Python service';
	}
	return types.includes('Flutter') ? 'Mobile client' : 'Source workspace';
}

interface WorkspaceGraph {
	files: string[];
	apis: string[];
	dependencies: string[];
	authFlows: string[];
	secrets: string[];
	dbAccess: string[];
	permissions: string[];
}

async function buildWorkspaceGraph(root: string): Promise<WorkspaceGraph> {
	const graph: WorkspaceGraph = {
		files: [],
		apis: [],
		dependencies: [],
		authFlows: [],
		secrets: [],
		dbAccess: [],
		permissions: [],
	};
	await collectGraphFiles(root, root, graph, 0);
	graph.apis = unique(graph.apis).slice(0, 16);
	graph.dependencies = unique(graph.dependencies).slice(0, 16);
	graph.authFlows = unique(graph.authFlows).slice(0, 12);
	graph.secrets = unique(graph.secrets).slice(0, 12);
	graph.dbAccess = unique(graph.dbAccess).slice(0, 12);
	graph.permissions = unique(graph.permissions).slice(0, 12);
	return graph;
}

async function collectGraphFiles(root: string, current: string, graph: WorkspaceGraph, depth: number): Promise<void> {
	if (depth > 4 || graph.files.length > 180) {
		return;
	}
	let entries: Array<import('fs').Dirent>;
	try {
		entries = await fs.readdir(current, { withFileTypes: true });
	} catch {
		return;
	}
	for (const entry of entries) {
		if (graph.files.length > 180) {
			return;
		}
		if (entry.name.startsWith('.') || ['node_modules', 'dist', 'build', 'out', 'coverage'].includes(entry.name)) {
			continue;
		}
		const fullPath = path.join(current, entry.name);
		if (entry.isDirectory()) {
			await collectGraphFiles(root, fullPath, graph, depth + 1);
			continue;
		}
		const relative = path.relative(root, fullPath).replace(/\\/g, '/');
		graph.files.push(relative);
		indexGraphSignals(relative, graph);
	}
}

function indexGraphSignals(file: string, graph: WorkspaceGraph): void {
	const lower = file.toLowerCase();
	if (/api|route|controller|endpoint/.test(lower)) {
		graph.apis.push(file);
	}
	if (/auth|login|session|token|guard/.test(lower)) {
		graph.authFlows.push(file);
	}
	if (/env|secret|key|credential/.test(lower)) {
		graph.secrets.push(file);
	}
	if (/sqlite|database|db|repo|model|schema/.test(lower)) {
		graph.dbAccess.push(file);
	}
	if (/androidmanifest|permissions|firebase|rules/.test(lower)) {
		graph.permissions.push(file);
	}
	if (/package\.json|pubspec\.yaml|pom\.xml|build\.gradle|requirements\.txt/.test(lower)) {
		graph.dependencies.push(file);
	}
}

function buildSerializableGraph(issues: readonly SerializableIssue[], workspace: WorkspaceProfile): unknown {
	const apiNodes = workspace.apis.slice(0, 5).map((api, index) => ({ id: `api-${index}`, label: path.basename(api), type: 'API' }));
	const graphIssues = selectSerializableGraphIssues(issues);
	const preferredTools = ['Betterleaks', 'OSV-Scanner', 'Semgrep', 'Trivy', 'MobSF', 'AI Analysis', 'AI Security Review', 'Custom Rules'];
	const toolNames = [...new Set([...preferredTools, ...graphIssues.map((issue) => issue.tool)])];
	const fileNames = [...new Set(graphIssues.map((issue) => issue.relativeFile))];
	const toolNodes = toolNames.map((tool, index) => ({ id: `tool-${index}`, label: tool, type: 'Tool' }));
	const findingNodes = graphIssues.map((issue) => ({ id: issue.id, label: issue.title, type: issue.severity }));
	const fileNodes = fileNames.map((file, index) => ({ id: `file-${index}`, label: path.basename(file), type: 'File' }));
	const nodes = [...toolNodes, ...findingNodes, ...fileNodes, ...apiNodes];
	const edges = graphIssues.flatMap((issue) => {
		const toolIndex = toolNames.indexOf(issue.tool);
		const fileIndex = fileNames.indexOf(issue.relativeFile);
		return [
			{ id: `detected-by-${issue.id}`, source: toolNodes[toolIndex]?.id, target: issue.id, type: 'detected-by' },
			{ id: `evidence-${issue.id}`, source: issue.id, target: fileNodes[fileIndex]?.id, type: 'evidence-in' },
		].filter((edge) => edge.source && edge.target);
	});
	return { nodes, edges };
}

function redactWebviewEvidence(value: unknown): unknown {
	if (typeof value === 'string') {
		return value
			.replace(/\b(?:sk|pk|ghp|glpat|xox[baprs]?)-[A-Za-z0-9_-]{12,}\b/g, '[REDACTED]')
			.replace(/\b[A-Za-z0-9_\/+=-]{32,}\b/g, '[REDACTED]')
			.replace(/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED]');
	}
	if (Array.isArray(value)) {
		return value.map((item) => redactWebviewEvidence(item));
	}
	if (value && typeof value === 'object') {
		return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redactWebviewEvidence(item)]));
	}
	return value;
}

function selectSerializableGraphIssues(issues: readonly SerializableIssue[]): SerializableIssue[] {
	const selected: SerializableIssue[] = [];
	const seenTools = new Set<string>();
	for (const issue of issues) {
		if (!seenTools.has(issue.tool)) {
			selected.push(issue);
			seenTools.add(issue.tool);
		}
	}
	for (const issue of issues) {
		if (selected.length >= 12) break;
		if (!selected.some((candidate) => candidate.id === issue.id)) {
			selected.push(issue);
		}
	}
	return selected;
}

function buildCompliance(counts: ReturnType<typeof getCounts>): unknown[] {
	const score = Math.max(42, 98 - counts.critical * 12 - counts.high * 7 - counts.medium * 3);
	return [
		{ name: 'OWASP', score, status: counts.critical ? 'Critical gaps' : 'Tracked' },
		{ name: 'CWE', score: Math.max(40, score - counts.high * 2), status: 'Mapped findings' },
		{ name: 'CIS', score: Math.max(45, score - counts.medium * 2), status: 'Baseline controls' },
		{ name: 'Mobile Security Checklist', score: Math.max(50, score - counts.low), status: 'Release gate ready' },
	];
}


function buildTimeline(memory: AgentMemory, counts: ReturnType<typeof getCounts>, snapshots: readonly ThreatSnapshot[] = []): unknown[] {
	if (snapshots.length > 0) {
		return snapshots.slice(0, 8).map((snapshot, index) => {
			const snapshotCounts = getCounts(snapshot.issues);
			return {
				id: snapshot.id,
				title: index === 0 ? 'Latest security scan' : `Security scan ${snapshots.length - index}`,
				detail: `${snapshotCounts.total} findings · ${snapshot.filesScanned} files · ${snapshotCounts.critical + snapshotCounts.high > 0 ? 'Action required' : 'No high-risk findings'}`,
				timestamp: snapshot.createdAt,
			};
		});
	}
	const scans = memory.previousScans.slice(0, 4);
	const base = scans.length > 0 ? scans : [{ timestamp: new Date().toISOString(), issueCount: counts.total, risk: counts.critical ? 'Critical' : counts.high ? 'Elevated' : 'Secure' }];
	return base.map((scan, index) => ({
		id: `${scan.timestamp}-${index}`,
		title: index === 0 ? 'Latest scan' : 'Historical scan',
		detail: `${scan.issueCount} open findings · ${scan.risk}`,
		timestamp: scan.timestamp,
	}));
}

function unique(values: readonly string[]): string[] {
	return [...new Set(values)];
}

function safeFileName(value: string): string {
	return value.replace(/[<>:"/\\|?*\x00-\x1F]/g, '-').replace(/\s+/g, '-').toLowerCase().slice(0, 80) || 'aqiron-artifact';
}

function getReportFilters(format: string): Record<string, string[]> {
	if (format === 'pdf') {
		return { 'PDF': ['pdf'] };
	}
	if (format === 'jira' || format === 'share') {
		return { 'Markdown': ['md'] };
	}
	return { 'JSON': ['json'] };
}

function createReportJson(state: WebviewState): unknown {
	const serializedIssues = state.issues.map(serializeIssue);
	const counts = getCounts(state.issues);
	const scoreEvolution = buildScoreEvolution(state);
	const graph = buildSerializableGraph(serializedIssues, state.workspace) as { nodes: unknown[]; edges: unknown[] };
	return {
		report: { product: 'Aqiron Security', formatVersion: '1.0', watermark: 'AQIRON SECURITY' },
		generatedAt: new Date().toISOString(),
		workspace: state.workspace,
		stats: state.stats,
		counts,
		securityScore: scoreEvolution[scoreEvolution.length - 1],
		scoreEvolution,
		scanTimeline: buildReportTimeline(state),
		threatGraph: graph,
		findings: serializedIssues,
		compliance: buildCompliance(counts),
		executiveSummary: state.pipeline.lastReport?.executiveSummary ?? createReportFallbackSummary(state, counts),
		remediationPlan: serializedIssues.slice(0, 25).map((issue) => ({
			id: issue.id,
			severity: issue.severity,
			sourceTool: issue.tool,
			file: issue.relativeFile,
			line: issue.line,
			action: issue.message,
		})),
	};
}

function createReportMarkdown(state: WebviewState, format = 'share'): string {
	const issues = state.issues.map(serializeIssue);
	const counts = getCounts(state.issues);
	const scoreEvolution = buildScoreEvolution(state);
	const graph = buildSerializableGraph(issues, state.workspace) as { nodes: unknown[]; edges: unknown[] };
	const title = format === 'jira' ? 'Aqiron Security Jira Ticket' : 'Aqiron Security Share Report';
	const topIssues = issues.slice(0, 25).map((issue, index) => `${index + 1}. **${issue.severity}: ${issue.title}**  \n   - File: \`${issue.relativeFile}:${issue.line}\`  \n   - Tool: ${issue.tool} | CWE: ${issue.cwe || 'Unmapped'} | OWASP: ${issue.owasp || 'Unmapped'}  \n   - Remediation: ${issue.message}`);
	const timeline = buildReportTimeline(state).map((item) => `- **${item.title}** - ${item.timestamp} - ${item.detail}`);
	return [
		`# ${title}`,
		'',
		'> Aqiron Security | Confidential security assessment',
		'> AQIRON SECURITY watermark applies to this report.',
		'',
		`Workspace: ${state.workspace.name}`,
		`Risk: ${state.workspace.risk}`,
		`Findings: ${counts.total} total, ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low`,
		`Files scanned: ${state.stats.filesScanned}`,
		`Security score: ${scoreEvolution.at(-1)}/100`,
		'',
		'## Executive Summary',
		state.pipeline.lastReport?.executiveSummary ?? createReportFallbackSummary(state, counts),
		'',
		'## Security Score Evolution',
		`Recent scores: ${scoreEvolution.join(' -> ')} / 100`,
		'Use this trend to verify that remediation is improving posture across scans.',
		'',
		'## Priority Findings',
		...(topIssues.length ? topIssues : ['- No open findings indexed.']),
		'',
		'## Scan Timeline',
		...(timeline.length ? timeline : ['- No completed scans recorded.']),
		'',
		'## Threat Graph',
		`- ${graph.nodes.length} graph nodes`,
		`- ${graph.edges.length} graph relationships`,
		'',
		'## Remediation Plan',
		'1. Fix critical secrets, injection paths, and malware indicators first.',
		'2. Upgrade vulnerable dependencies and regenerate lockfiles.',
		'3. Re-run Aqiron Security and attach the JSON or SARIF report to the release gate.',
		'',
		'---',
		'Generated by Aqiron Security. Keep this report with the release evidence and do not expose credentials or secret values.',
	].join('\n');
}

function createPdfBuffer(state: WebviewState): Buffer {
	const pages: string[] = [];
	const counts = getCounts(state.issues);
	const scores = buildScoreEvolution(state);
	const summary = state.pipeline.lastReport?.executiveSummary ?? createReportFallbackSummary(state, counts);
	const pageOne: string[] = [pdfWatermark(), pdfHeader('Aqiron Security', 'Security Assessment Report'), pdfText('Confidential workspace security report', 40, 700, 12, [0.55, 0.68, 0.86]), pdfText(sanitizePdfText(state.workspace.name), 40, 650, 25, [0.92, 0.96, 1]), pdfText(`Generated ${new Date().toLocaleString()}`, 40, 628, 10, [0.55, 0.68, 0.86]), pdfText('EXECUTIVE SUMMARY', 40, 575, 12, [0.22, 0.74, 0.98]), ...pdfWrap(summary, 40, 550, 532, 11, [0.82, 0.88, 0.96]), pdfText('POSTURE OVERVIEW', 40, 420, 12, [0.22, 0.74, 0.98])];
	pageOne.push(...pdfMetric('Open findings', `${counts.total}`, 40, 380, [0.1, 0.22, 0.4]));
	pageOne.push(...pdfMetric('Critical / High', `${counts.critical} / ${counts.high}`, 185, 380, [0.28, 0.12, 0.24]));
	pageOne.push(...pdfMetric('Files scanned', `${state.stats.filesScanned}`, 330, 380, [0.08, 0.27, 0.31]));
	pageOne.push(...pdfMetric('Security score', `${scores.at(-1)}/100`, 475, 380, [0.2, 0.16, 0.4]));
	pageOne.push(pdfText('SECURITY SCORE EVOLUTION', 40, 300, 12, [0.22, 0.74, 0.98]), pdfText('Higher bars indicate a stronger calculated release posture.', 40, 282, 9, [0.55, 0.68, 0.86]));
	pageOne.push(...pdfScoreBars(scores, 55, 160, 500, 100));
	pageOne.push(pdfFooter(1));
	pages.push(pageOne.join('\n'));

	const findings = state.issues.map(serializeIssue);
	for (let offset = 0, page = 2; offset < findings.length || page === 2; offset += 9, page++) {
		const slice = findings.slice(offset, offset + 9);
		const content: string[] = [pdfWatermark(), pdfHeader('Aqiron Security', `Threat Findings ${findings.length ? `${offset + 1}-${Math.min(offset + 9, findings.length)} of ${findings.length}` : '0'}`), pdfText('SEVERITY', 40, 690, 10, [0.22, 0.74, 0.98])];
		let y = 665;
		for (const issue of slice) {
			content.push(pdfRect(36, y - 54, 540, 64, issue.severity === 'Critical' ? [0.25, 0.08, 0.14] : issue.severity === 'High' ? [0.24, 0.13, 0.08] : [0.07, 0.13, 0.24], 0.85));
			content.push(pdfText(sanitizePdfText(`${issue.severity}  ${issue.title}`), 48, y - 8, 11, [0.94, 0.97, 1]));
			content.push(pdfText(sanitizePdfText(`${issue.relativeFile}:${issue.line} | ${issue.tool} | ${issue.cwe || 'CWE unmapped'}`), 48, y - 25, 9, [0.62, 0.78, 0.92]));
			content.push(...pdfWrap(issue.message, 48, y - 40, 510, 8.5, [0.82, 0.88, 0.96], 1));
			y -= 76;
		}
		if (!slice.length) {
			content.push(pdfText('No open findings indexed.', 48, 630, 12, [0.82, 0.88, 0.96]));
		}
		content.push(pdfFooter(page));
		pages.push(content.join('\n'));
		if (!findings.length) {
			break;
		}
	}

	const timeline: string[] = [pdfWatermark(), pdfHeader('Aqiron Security', 'Evidence, Timeline & Remediation'), pdfText('SCAN TIMELINE', 40, 690, 12, [0.22, 0.74, 0.98])];
	let y = 660;
	for (const item of buildReportTimeline(state).slice(0, 12)) {
		timeline.push(pdfText(sanitizePdfText(item.title), 48, y, 10, [0.94, 0.97, 1]), pdfText(sanitizePdfText(`${item.timestamp} | ${item.detail}`), 48, y - 16, 8.5, [0.62, 0.78, 0.92]));
		y -= 38;
	}
	timeline.push(pdfText('THREAT GRAPH', 40, Math.max(280, y - 12), 12, [0.22, 0.74, 0.98]));
	const graph = buildSerializableGraph(findings, state.workspace) as { nodes: unknown[]; edges: unknown[] };
	timeline.push(pdfText(`${graph.nodes.length} nodes connected by ${graph.edges.length} relationships`, 48, Math.max(255, y - 34), 10, [0.82, 0.88, 0.96]));
	timeline.push(...pdfGraph(graph, 48, Math.max(300, y - 150), 500, 88));
	timeline.push(pdfText('REMEDIATION PLAN', 40, Math.max(210, y - 72), 12, [0.22, 0.74, 0.98]), ...pdfWrap('Fix critical secrets and exposed components first. Upgrade vulnerable dependencies, review authentication boundaries, then rerun the scan and attach the JSON and PDF artifacts to the release gate.', 48, Math.max(185, y - 96), 510, 10, [0.82, 0.88, 0.96]));
	timeline.push(pdfFooter(pages.length + 1));
	pages.push(timeline.join('\n'));
	return buildPdfDocument(pages);
}

interface ReportTimelineItem {
	id: string;
	title: string;
	detail: string;
	timestamp: string;
}

function buildReportTimeline(state: WebviewState): ReportTimelineItem[] {
	return buildTimeline(state.memory, getCounts(state.issues), state.threatSnapshots) as ReportTimelineItem[];
}

function buildScoreEvolution(state: WebviewState): number[] {
	const current = Math.max(0, Math.min(100, 96 - getCounts(state.issues).critical * 12 - getCounts(state.issues).high * 6 - getCounts(state.issues).medium * 2));
	const history = state.threatSnapshots.slice(0, 6).reverse().map((snapshot) => {
		const counts = getCounts(snapshot.issues);
		return Math.max(0, Math.min(100, 96 - counts.critical * 12 - counts.high * 6 - counts.medium * 2));
	});
	return [...(history.length ? history : [78, 82, 76, 86, 89, 84]), current].slice(-7);
}

function createReportFallbackSummary(state: WebviewState, counts: ReturnType<typeof getCounts>): string {
	if (!counts.total) {
		return 'No open findings are currently indexed. Continue scheduled scans and dependency monitoring before release.';
	}
	return `Aqiron Security found ${counts.total} findings across ${counts.filesAffected} files. Prioritize ${counts.critical} critical and ${counts.high} high-severity findings, then rerun the scan to verify the release posture improves.`;
}

function sanitizePdfText(value: string): string {
	return value.replace(/[^\x20-\x7E]/g, ' ').replace(/[()\\]/g, '\\$&').replace(/\s+/g, ' ').trim();
}

function pdfText(value: string, x: number, y: number, size: number, color: [number, number, number], bold = false): string {
	const font = bold ? 'F2' : 'F1';
	return `${color[0]} ${color[1]} ${color[2]} rg BT /${font} ${size} Tf ${x} ${y} Td (${sanitizePdfText(value)}) Tj ET`;
}

function pdfRect(x: number, y: number, width: number, height: number, color: [number, number, number], opacity = 1): string {
	return `${color[0]} ${color[1]} ${color[2]} rg ${x} ${y} ${width} ${height} re f`;
}

function pdfWrap(value: string, x: number, y: number, width: number, size: number, color: [number, number, number], maxLines = 4): string[] {
	const maxChars = Math.max(24, Math.floor(width / (size * 0.55)));
	const words = sanitizePdfText(value).split(' ');
	const lines: string[] = [];
	let line = '';
	for (const word of words) {
		const next = line ? `${line} ${word}` : word;
		if (next.length > maxChars && line) {
			lines.push(line);
			line = word;
		} else {
			line = next;
		}
		if (lines.length === maxLines) {
			break;
		}
	}
	if (lines.length < maxLines && line) {
		lines.push(line);
	}
	return lines.slice(0, maxLines).map((lineValue, index) => pdfText(lineValue, x, y - index * (size + 4), size, color));
}

function pdfMetric(label: string, value: string, x: number, y: number, color: [number, number, number]): string[] {
	return [pdfRect(x, y, 132, 74, color), pdfText(label, x + 10, y + 48, 8.5, [0.68, 0.8, 0.94]), pdfText(value, x + 10, y + 22, 17, [0.95, 0.98, 1], true)];
}

function pdfScoreBars(scores: readonly number[], x: number, y: number, width: number, height: number): string[] {
	const gap = 10;
	const barWidth = (width - gap * (scores.length - 1)) / scores.length;
	return scores.flatMap((score, index) => {
		const barHeight = Math.max(8, height * score / 100);
		const barX = x + index * (barWidth + gap);
		return [pdfRect(barX, y, barWidth, height, [0.04, 0.1, 0.2]), pdfRect(barX, y, barWidth, barHeight, [0.12, 0.62, 0.86]), pdfText(`${score}`, barX + 8, y - 16, 8, [0.62, 0.78, 0.92])];
	});
}

function pdfGraph(graph: { nodes: unknown[]; edges: unknown[] }, x: number, y: number, width: number, height: number): string[] {
	const nodes = graph.nodes.slice(0, 8) as Array<{ id?: string; label?: string; type?: string }>;
	if (!nodes.length) {
		return [pdfText('No relationship graph data available.', x, y + 40, 9, [0.62, 0.78, 0.92])];
	}
	const output: string[] = [pdfRect(x, y, width, height, [0.04, 0.1, 0.2])];
	const centerX = x + width / 2;
	const centerY = y + height / 2;
	for (let index = 1; index < nodes.length; index++) {
		const nodeX = x + 42 + ((index - 1) % 4) * ((width - 84) / 3);
		const nodeY = index < 5 ? y + height - 30 : y + 18;
		output.push(`${0.18} ${0.48} ${0.7} RG 1 w ${centerX} ${centerY} m ${nodeX + 24} ${nodeY + 8} l S`);
	}
	output.push(pdfRect(centerX - 28, centerY - 12, 56, 24, [0.12, 0.62, 0.86]), pdfText('Aqiron', centerX - 20, centerY - 3, 8, [0.98, 1, 1], true));
	for (let index = 1; index < nodes.length; index++) {
		const nodeX = x + 42 + ((index - 1) % 4) * ((width - 84) / 3);
		const nodeY = index < 5 ? y + height - 30 : y + 18;
		output.push(pdfRect(nodeX, nodeY, 48, 16, [0.09, 0.19, 0.34]), pdfText(sanitizePdfText((nodes[index].label ?? nodes[index].type ?? 'Node').slice(0, 16)), nodeX + 4, nodeY + 5, 6.5, [0.78, 0.88, 0.98]));
	}
	return output;
}

function pdfWatermark(): string {
	return 'q 0.15 0.24 0.38 rg 0.707 0.707 -0.707 0.707 180 240 cm BT /F2 46 Tf (AQIRON SECURITY) Tj ET Q';
}

function pdfHeader(product: string, title: string): string {
	return `${pdfRect(0, 744, 612, 48, [0.03, 0.08, 0.16])}\n${pdfText(product, 36, 768, 15, [0.35, 0.82, 1], true)}\n${pdfText(title, 382, 768, 9, [0.68, 0.8, 0.94])}`;
}

function pdfFooter(page: number): string {
	return `${pdfText('AQIRON SECURITY  |  CONFIDENTIAL', 36, 24, 8, [0.4, 0.55, 0.72])}\n${pdfText(`Page ${page}`, 540, 24, 8, [0.4, 0.55, 0.72])}`;
}

function buildPdfDocument(pages: readonly string[]): Buffer {
	const pageCount = pages.length;
	const pageRefs = pages.map((_, index) => 5 + index * 2);
	const objects: string[] = [];
	objects[1] = `<< /Type /Catalog /Pages 2 0 R >>`;
	objects[2] = `<< /Type /Pages /Kids [${pageRefs.map((ref) => `${ref} 0 R`).join(' ')}] /Count ${pageCount} >>`;
	objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
	objects[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>';
	for (let index = 0; index < pageCount; index++) {
		const pageRef = 5 + index * 2;
		const contentRef = pageRef + 1;
		objects[pageRef] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentRef} 0 R >>`;
		objects[contentRef] = `<< /Length ${Buffer.byteLength(pages[index], 'ascii')} >>\nstream\n${pages[index]}\nendstream`;
	}
	let output = '%PDF-1.4\n';
	const offsets = [0];
	for (let index = 1; index < objects.length; index++) {
		offsets[index] = Buffer.byteLength(output, 'ascii');
		output += `${index} 0 obj\n${objects[index]}\nendobj\n`;
	}
	const xrefOffset = Buffer.byteLength(output, 'ascii');
	output += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
	for (let index = 1; index < objects.length; index++) {
		output += `${String(offsets[index]).padStart(10, '0')} 00000 n \n`;
	}
	output += `trailer << /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
	return Buffer.from(output, 'ascii');
}

function upsertByName(items: readonly PipelineStageState[], next: PipelineStageState): PipelineStageState[] {
	const existing = items.findIndex((item) => item.name === next.name);
	if (existing === -1) {
		return [...items, next];
	}
	return items.map((item, index) => index === existing ? { ...item, ...next } : item);
}

function upsertById(items: readonly ToolExecutionState[], next: ToolExecutionState): ToolExecutionState[] {
	const existing = items.findIndex((item) => item.id === next.id);
	if (existing === -1) {
		return [...items, next];
	}
	return items.map((item, index) => index === existing ? { ...item, ...next } : item);
}

function getPayloadText(payload: unknown): string {
	if (typeof payload === 'string') {
		return payload.trim();
	}
	if (payload && typeof payload === 'object' && typeof (payload as { text?: unknown }).text === 'string') {
		return (payload as { text: string }).text.trim();
	}
	return '';
}

function getPayloadSessionId(payload: unknown): string | undefined {
	if (payload && typeof payload === 'object' && typeof (payload as { sessionId?: unknown }).sessionId === 'string') {
		return (payload as { sessionId: string }).sessionId;
	}
	return undefined;
}

function shouldUseTaskDefaults(payload: unknown): boolean {
	return Boolean(payload && typeof payload === 'object' && (payload as { useTaskDefaults?: unknown }).useTaskDefaults === true);
}

function resolveChatSelection(ai: AiWebviewState, useTaskDefaults: boolean): AiWebviewState['selection'] {
	const defaults = ai.taskDefaults;
	if (!useTaskDefaults || defaults.useChatDefaults) {
		return ai.selection;
	}
	return {
		provider: defaults.provider ?? ai.selection.provider,
		model: defaults.model ?? ai.selection.model,
		intelligence: defaults.intelligence ?? ai.selection.intelligence,
		permissionMode: defaults.permissionMode ?? ai.selection.permissionMode,
	};
}

function createChatSession(prompt: string, selection: AiWebviewState['selection']): ChatSession {
	const now = new Date().toISOString();
	return {
		id: createId(),
		title: createSessionTitle(prompt),
		createdAt: now,
		updatedAt: now,
		model: selection.model,
		intelligence: selection.intelligence,
		streaming: false,
		messages: [],
	};
}

export function createSessionTitle(prompt: string): string {
	const normalized = prompt
		.replace(/[`*_#>[\](){}]/g, ' ')
		.replace(/\s+/g, ' ')
		.trim();
	const lower = normalized.toLowerCase();
	if (/^(hi|hello|hey|yo|sup|namaste|hola|good morning|good afternoon|good evening)[!.\s]*$/.test(lower)) {
		return 'Greetings';
	}
	if (/^(thanks|thank you|thx)[!.\s]*$/.test(lower)) {
		return 'Thanks';
	}
	const intent = lower.includes('rename') ? 'Rename'
		: lower.includes('delete') || lower.includes('remove') ? 'Delete'
			: lower.includes('share') || lower.includes('export') ? 'Export'
				: lower.includes('fix') || lower.includes('patch') ? 'Fix'
					: lower.includes('review') ? 'Review'
						: lower.includes('audit') ? 'Audit'
							: lower.includes('scan') ? 'Scan'
								: lower.includes('analyze') || lower.includes('analyse') ? 'Analyze'
									: lower.includes('explain') ? 'Explain'
										: lower.includes('generate') || lower.includes('create') ? 'Create'
											: '';
	const topicMatch = normalized.match(/\b(?:for|of|on|in|with|about)\s+(.+)$/i);
	let topic = topicMatch?.[1] ?? normalized.replace(/^(please\s+)?(can you\s+|could you\s+|help me\s+)?(run|create|generate|analyze|analyse|review|explain|scan|audit|fix|patch|share|export|rename|delete|remove)\s+/i, '');
	topic = topic
		.replace(/\b(the|this|that|a|an|my|our|please)\b/gi, ' ')
		.replace(/\s+/g, ' ')
		.trim();
	if (/\bmobsf\b/i.test(normalized)) {
		topic = topic ? topic.replace(/\bmobsf\b/ig, 'MoBSF') : 'MoBSF Audit';
	}
	if (/\bflutter\b/i.test(normalized) && !/\bflutter\b/i.test(topic)) {
		topic = `${topic} Flutter`.trim();
	}
	const words = topic.split(/\s+/).filter(Boolean).slice(0, 6).join(' ');
	const title = [intent, toTitleCase(words)].filter(Boolean).join(' ').trim();
	return title.slice(0, 64) || 'New chat';
}

function toTitleCase(value: string): string {
	return value
		.split(/\s+/)
		.filter(Boolean)
		.map((word) => /^[A-Z0-9:_-]+$/.test(word) ? word : word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
		.join(' ');
}

function selectAgentTool(prompt: string): { id: 'secrets.scan' | 'workspace.scan' | 'dependencies.scan' | 'workspace.graph' | 'mobsf.audit' | 'api.fuzz' } | undefined {
	const text = prompt.toLowerCase();
	if (/\b(secret|secrets|token|tokens|key|keys|credential|credentials|password|private key)\b/.test(text)) {
		return { id: 'secrets.scan' };
	}
	if (/\b(mobsf|apk|android|reverse engineer)\b/.test(text)) {
		return { id: 'mobsf.audit' };
	}
	if (/\b(dependency|dependencies|trivy|sca|packages|package audit)\b/.test(text)) {
		return { id: 'dependencies.scan' };
	}
	if (/\b(fuzz|api|endpoint|endpoints)\b/.test(text)) {
		return { id: 'api.fuzz' };
	}
	if (/\b(graph|workspace context|code map)\b/.test(text)) {
		return { id: 'workspace.graph' };
	}
	if (/\b(scan|audit|review)\b/.test(text)) {
		return { id: 'workspace.scan' };
	}
	return undefined;
}

function createToolCommands(prompt: string, workspace: WorkspaceProfile): ToolCommand[] {
	const text = prompt.toLowerCase();
	const commands: ToolCommand[] = [];
	if (/\b(mobsf|apk|android|reverse engineer)\b/.test(text)) {
		commands.push({ label: 'Build Android artifact', command: 'flutter build apk --debug', status: workspace.types.includes('Flutter') ? 'queued' : 'ready' });
		commands.push({ label: 'Run MobSF static analysis', command: 'mobsfscan .', status: 'ready' });
	}
	if (/\b(scan|dependency|dependencies|trivy|audit)\b/.test(text)) {
		commands.push({ label: 'Run Aqiron workspace scan', command: 'Aqiron Security: Scan Workspace', status: 'queued' });
		commands.push({ label: 'Check dependency manifests', command: 'trivy fs .', status: 'ready' });
		commands.push({ label: 'Check Dart dependencies', command: 'osv-scanner scan source --format json -r .', status: 'ready' });
	}
	if (/\b(secret|secrets|token|tokens|key|keys|credential|credentials|password)\b/.test(text)) {
		commands.push({ label: 'Scan project secrets', command: 'betterleaks dir . --report-path - --report-format json --exit-code 0 --redact --no-banner', status: 'ready' });
	}
	if (/\b(fuzz|api|endpoint)\b/.test(text)) {
		commands.push({ label: 'Generate API fuzz cases', command: 'Aqiron API Fuzzer', status: workspace.apis.length > 0 ? 'queued' : 'ready' });
	}
	if (/\b(explain|code|auth|login|network)\b/.test(text) && commands.length === 0) {
		commands.push({ label: 'Build workspace context', command: 'Aqiron workspace graph', status: 'queued' });
	}
	return commands;
}

function unavailableToolResult(label: string, message: string): AgentToolResult {
	return {
		content: message,
		commands: [{ label, command: label, status: 'unavailable' }],
	};
}

function isSecretRule(ruleId: string): boolean {
	return ruleId.includes('secret') || ruleId.includes('api-key') || ruleId.includes('password') || ruleId.includes('private-key') || ruleId.includes('token');
}

function mergeIssues(base: readonly AqironIssue[], additions: readonly AqironIssue[]): AqironIssue[] {
	const byId = new Map<string, AqironIssue>();
	for (const issue of [...base, ...additions]) {
		byId.set(issue.id, issue);
	}
	return [...byId.values()];
}

function upsertSession(sessions: readonly ChatSession[], session: ChatSession): ChatSession[] {
	const exists = sessions.some((candidate) => candidate.id === session.id);
	return exists
		? sessions.map((candidate) => candidate.id === session.id ? session : candidate).sort(sortSessions)
		: [session, ...sessions].sort(sortSessions);
}

function markSessionStreaming(sessions: readonly ChatSession[], sessionId: string, streaming: boolean): ChatSession[] {
	return sessions.map((session) => session.id === sessionId ? { ...session, streaming } : session).sort(sortSessions);
}

function sortSessions(left: ChatSession, right: ChatSession): number {
	return right.updatedAt.localeCompare(left.updatedAt);
}

function serializeChatSessions(sessions: readonly ChatSession[]): ChatSession[] {
	return sessions.map((session) => ({
		...session,
		title: redactLooseSecrets(session.title),
		messages: session.messages.map((message) => ({ ...message, content: redactLooseSecrets(message.content) })),
	})).sort(sortSessions);
}

function redactLooseSecrets(value: string): string {
	return value
		.replace(/\b(?:sk|pk|ghp|glpat|xox[baprs]?)-[A-Za-z0-9_-]{12,}\b/g, '[REDACTED]')
		.replace(/\b[A-Za-z0-9_\/+=-]{32,}\b/g, '[REDACTED]');
}

function estimateTokenUsage(sessions: readonly ChatSession[]): TokenUsage {
	const text = sessions.flatMap((session) => session.messages.map((message) => message.content)).join('\n');
	const totalTokens = Math.ceil(text.length / 4);
	const contextWindow = 128_000;
	return {
		promptTokens: Math.ceil(totalTokens * 0.55),
		completionTokens: Math.floor(totalTokens * 0.45),
		totalTokens,
		contextWindow,
		contextUsed: Math.min(100, Math.round((totalTokens / contextWindow) * 100)),
	};
}

function createId(): string {
	return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function getRiskStatus(issues: readonly AqironIssue[]): WorkspaceProfile['risk'] {
	if (issues.some((issue) => issue.severity === 'Critical')) {
		return 'Critical';
	}
	if (issues.some((issue) => issue.severity === 'High')) {
		return 'Elevated';
	}
	if (issues.length > 0) {
		return 'Review';
	}
	return 'Secure';
}

function defaultConfidence(severity: AqironSeverity): string {
	return severity === 'Low' ? 'Medium' : 'High';
}
function getRiskScore(severity: AqironSeverity): number {
	switch (severity) {
		case 'Critical':
			return 96;
		case 'High':
			return 82;
		case 'Medium':
			return 58;
		case 'Low':
			return 28;
	}
}

function getSourceTool(ruleId: string): string {
	if (ruleId.includes('secret') || ruleId.includes('api-key') || ruleId.includes('password')) {
		return 'Betterleaks';
	}
	if (ruleId.includes('insecure') || ruleId.includes('sql')) {
		return 'Semgrep';
	}
	return ruleId.startsWith('critical') ? 'AI Analyzer' : 'Custom Rules';
}

function getCwe(ruleId: string): string {
	if (ruleId.includes('secret') || ruleId.includes('api-key') || ruleId.includes('password')) {
		return 'CWE-798';
	}
	if (ruleId.includes('eval')) {
		return 'CWE-95';
	}
	if (ruleId.includes('shell') || ruleId.includes('subprocess')) {
		return 'CWE-78';
	}
	if (ruleId.includes('deserialization')) {
		return 'CWE-502';
	}
	return 'CWE-693';
}

function getOwasp(ruleId: string): string {
	if (ruleId.includes('secret') || ruleId.includes('api-key') || ruleId.includes('password')) {
		return 'A02 Cryptographic Failures';
	}
	if (ruleId.includes('eval') || ruleId.includes('shell') || ruleId.includes('sql')) {
		return 'A03 Injection';
	}
	return 'A05 Security Misconfiguration';
}

function getNonce(): string {
	const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	let text = '';
	for (let index = 0; index < 32; index++) {
		text += possible.charAt(Math.floor(Math.random() * possible.length));
	}
	return text;
}

function getStyles(): string {
	return `
:root {
	--bg: #05070d;
	--panel: rgba(8, 14, 28, .72);
	--panel-strong: rgba(12, 20, 40, .9);
	--line: rgba(130, 180, 255, .18);
	--line-strong: rgba(125, 210, 255, .32);
	--text: #eaf2ff;
	--muted: #8ea2bf;
	--blue: #38bdf8;
	--purple: #a78bfa;
	--green: #43d39e;
	--yellow: #f8c555;
	--orange: #ff8a4c;
	--red: #ff5370;
	font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI Variable", "Segoe UI", system-ui, sans-serif;
}
* { box-sizing: border-box; }
html, body, #app { min-height: 100%; margin: 0; }
body {
	color: var(--text);
	background:
		radial-gradient(circle at 14% 4%, rgba(56,189,248,.18), transparent 26%),
		radial-gradient(circle at 90% 8%, rgba(167,139,250,.14), transparent 28%),
		linear-gradient(180deg, #070a12, #05070d 45%, #04060b);
}
button, input, select { font: inherit; }
button { cursor: pointer; }
.shell { position: relative; min-height: 100vh; overflow: hidden; }
.shell:before {
	content: "";
	position: fixed;
	inset: 0;
	pointer-events: none;
	background-image:
		linear-gradient(rgba(72, 167, 255, .055) 1px, transparent 1px),
		linear-gradient(90deg, rgba(72, 167, 255, .055) 1px, transparent 1px);
	background-size: 28px 28px;
	mask-image: linear-gradient(to bottom, rgba(0,0,0,.82), transparent);
}
.bg-media {
	position: fixed;
	inset: 0;
	opacity: .1;
	background-size: cover;
	background-position: center;
	filter: saturate(1.15);
	pointer-events: none;
}
.content { position: relative; padding: 14px; display: flex; flex-direction: column; gap: 14px; }
.content.agent-content { padding-bottom: 236px; }
.top-nav { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; padding: 4px; border: 1px solid var(--line); border-radius: 10px; background: rgba(255,255,255,.035); backdrop-filter: blur(18px); }
.nav-btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; border: 0; color: #898989; border-radius: 7px; padding: 8px 4px; background: transparent; transition: .18s ease; font-size: 12px; }
.nav-btn.active { color: var(--text); background: linear-gradient(135deg, rgba(56,189,248,.2), rgba(167,139,250,.16)); box-shadow: inset 0 0 0 1px rgba(165,213,255,.18), 0 0 24px rgba(56,189,248,.08); }
.tab-icon { width: 14px; height: 14px; color: #898989; background-color: #898989; flex: 0 0 auto; }
.nav-btn.active .tab-icon { color: #fff; background-color: #fff; }
.codicon { display: inline-grid; place-items: center; background: transparent; color: currentColor; font-size: 13px; line-height: 1; }
.codicon-tab { background-color: transparent; }
.nav-btn.active .codicon-tab { background-color: transparent; }
.asset-icon { display: inline-block; mask: var(--icon) center / contain no-repeat; -webkit-mask: var(--icon) center / contain no-repeat; }
.svg-icon { width: 14px; height: 14px; display: inline-block; background-color: currentColor; mask: var(--icon) center / contain no-repeat; -webkit-mask: var(--icon) center / contain no-repeat; flex: 0 0 auto; }
.hero { border: 1px solid var(--line); border-radius: 14px; padding: 14px; background: linear-gradient(140deg, rgba(12,20,40,.86), rgba(6,10,20,.68)); box-shadow: 0 16px 60px rgba(0,0,0,.28); backdrop-filter: blur(20px); }
.hero-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
.brand img { width: 34px; height: 34px; object-fit: contain; filter: drop-shadow(0 0 16px rgba(56,189,248,.35)); }
.eyebrow { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }
h1, h2, h3, p { margin: 0; }
h1 { font-size: 18px; line-height: 1.2; letter-spacing: 0; }
h2 { font-size: 13px; color: #dbeafe; font-weight: 650; }
h3 { font-size: 12px; color: #e8f0ff; font-weight: 650; }
.badges { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }
.badge { border: 1px solid var(--line); border-radius: 999px; padding: 4px 8px; color: #cfe3ff; background: rgba(255,255,255,.045); font-size: 11px; white-space: nowrap; }
.badge.risk-Critical, .sev-Critical { color: #ffd7df; border-color: rgba(255,83,112,.45); background: rgba(255,83,112,.12); }
.badge.risk-Elevated, .sev-High { color: #ffe4c7; border-color: rgba(255,138,76,.46); background: rgba(255,138,76,.12); }
.badge.risk-Review, .sev-Medium { color: #fff2c7; border-color: rgba(248,197,85,.46); background: rgba(248,197,85,.12); }
.badge.risk-Secure, .sev-Low { color: #d8ffef; border-color: rgba(67,211,158,.42); background: rgba(67,211,158,.11); }
.section { display: flex; flex-direction: column; gap: 10px; animation: rise .32s ease both; }
.section-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.muted { color: var(--muted); font-size: 12px; }
.grid { display: grid; gap: 10px; }
.actions { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.card { position: relative; border: 1px solid var(--line); border-radius: 10px; padding: 12px; background: linear-gradient(150deg, rgba(15,25,48,.76), rgba(8,12,24,.72)); overflow: hidden; transition: transform .18s ease, border-color .18s ease, box-shadow .18s ease; }
.card:before { content: ""; position: absolute; inset: 0; background: radial-gradient(circle at 18% 0%, rgba(56,189,248,.16), transparent 38%); opacity: 0; transition: opacity .18s ease; pointer-events: none; }
.card:hover { transform: translateY(-1px); border-color: var(--line-strong); box-shadow: 0 18px 42px rgba(0,0,0,.24), 0 0 28px rgba(56,189,248,.08); }
.card:hover:before { opacity: 1; }
.icon { width: 28px; height: 28px; display: grid; place-items: center; border-radius: 8px; background: linear-gradient(135deg, rgba(56,189,248,.2), rgba(167,139,250,.18)); color: #dff6ff; margin-bottom: 9px; }
.icon .card-icon { width: 15px; height: 15px; display: inline-grid; place-items: center; color: #dff6ff; font-size: 14px; line-height: 1; }
.icon .card-icon.asset-icon { background-color: currentColor; }
.card p, .suggestion p { color: var(--muted); font-size: 11px; line-height: 1.45; margin-top: 5px; }
.suggestion { border: 1px solid var(--line); border-radius: 10px; padding: 10px; background: rgba(255,255,255,.038); }
.suggestion-top, .tool-top, .threat-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.inline-actions { display: flex; gap: 6px; margin-top: 10px; }
.btn { border: 1px solid var(--line); border-radius: 8px; background: rgba(255,255,255,.055); color: var(--text); padding: 7px 9px; font-size: 11px; transition: .16s ease; }
.btn.primary { background: linear-gradient(135deg, rgba(56,189,248,.32), rgba(167,139,250,.22)); border-color: rgba(135,206,255,.38); }
.btn.danger { border-color: rgba(255,83,112,.42); color: #ffd7df; }
.btn:hover { border-color: var(--line-strong); transform: translateY(-1px); }
.chatbar { position: fixed; left: 14px; right: 14px; bottom: 12px; z-index: 12; border: 1px solid var(--line-strong); border-radius: 13px; padding: 8px; background: rgba(8,14,28,.94); backdrop-filter: blur(22px); box-shadow: 0 18px 58px rgba(0,0,0,.46), 0 0 28px rgba(56,189,248,.08); }
.chat-input { width: 100%; min-height: 82px; max-height: 136px; resize: none; overflow: auto; color: var(--text); border: 0; border-radius: 8px; background: rgba(2,6,14,.62); padding: 9px 10px; font-size: 13px; line-height: 1.45; outline: 0; font-family: inherit; }
.chat-input::placeholder { color: #6f819d; }
.chat-controls { display: flex; align-items: center; gap: 5px; margin-top: 7px; min-width: 0; }
.composer-spacer { flex: 1 1 auto; min-width: 8px; }
.hover-control { position: relative; flex: 0 0 auto; }
.control-btn { min-height: 30px; border: 1px solid transparent; border-radius: 9px; background: transparent; color: var(--text); padding: 5px 7px; display: inline-flex; align-items: center; gap: 6px; font-size: 11px; line-height: 1; transition: .16s ease; white-space: nowrap; }
.control-btn:hover, .hover-control:hover > .control-btn, .hover-control:focus-within > .control-btn { border-color: var(--line-strong); background: rgba(255,255,255,.045); }
.icon-btn { width: 30px; justify-content: center; padding: 5px; border-radius: 999px; border-color: transparent; background: transparent; }
.icon-btn:hover, .hover-control:hover > .icon-btn { border-color: transparent; background: rgba(255,255,255,.07); }
.send-btn { width: 30px; height: 30px; border: 0; border-radius: 999px; display: grid; place-items: center; color: #fff; background: linear-gradient(135deg, #38bdf8, #7c3aed); box-shadow: 0 0 20px rgba(56,189,248,.24); }
.menu { position: absolute; right: 0; bottom: calc(100% + 8px); display: none; min-width: 210px; border: 1px solid var(--line-strong); border-radius: 10px; padding: 7px; background: rgba(7,11,22,.98); box-shadow: 0 18px 52px rgba(0,0,0,.46); z-index: 20; }
.menu.edge-left { left: 0; right: auto; }
.hover-control.open > .menu { display: block; }
.tip { position: absolute; left: 50%; bottom: calc(100% + 8px); transform: translateX(-50%); display: none; align-items: center; gap: 8px; width: max-content; max-width: 260px; border: 1px solid rgba(125,210,255,.22); border-radius: 8px; padding: 6px 8px; background: linear-gradient(135deg, rgba(16,38,68,.98), rgba(28,24,58,.98)); color: #f4f8ff; font-size: 12px; line-height: 1.2; box-shadow: 0 8px 28px rgba(0,0,0,.42), 0 0 18px rgba(56,189,248,.1); z-index: 30; }
.tip.edge-left { left: 0; transform: none; }
.hover-control:not(.open):hover > .tip, .token-wrap:hover > .tip, .send-wrap:hover > .tip { display: inline-flex; }
.tip kbd { border: 1px solid rgba(255,255,255,.08); border-radius: 999px; padding: 3px 8px; background: rgba(255,255,255,.12); color: #f4f4f4; font: inherit; white-space: nowrap; }
.menu-title { color: #dceaff; font-size: 11px; font-weight: 700; margin: 4px 6px 7px; }
.menu-separator { height: 1px; background: rgba(130,180,255,.22); margin: 7px 0; }
.menu-option { width: 100%; min-height: 28px; border: 0; border-radius: 7px; background: transparent; color: #dbe8fb; padding: 6px 7px; display: flex; align-items: center; gap: 7px; text-align: left; font-size: 11px; }
.menu-option:hover { background: rgba(255,255,255,.055); }
.option-spacer { flex: 1 1 auto; }
.hint { color: #8ea2bf; font-size: 10px; }
.info-dot { width: 17px; height: 17px; display: inline-grid; place-items: center; color: #aebbd1; position: relative; }
.info-dot .info-pop { position: absolute; left: 50%; bottom: calc(100% + 8px); transform: translateX(-50%); display: none; width: 274px; border: 1px solid rgba(255,255,255,.12); border-radius: 9px; padding: 10px 11px; background: #2d2d2d; color: #f4f4f4; line-height: 1.45; box-shadow: 0 12px 34px rgba(0,0,0,.44); z-index: 32; }
.info-dot:after { content: ""; position: absolute; left: -18px; right: -18px; bottom: 100%; height: 10px; }
.info-dot:hover .info-pop { display: block; }
.policy-link { color: #56b8ff; background: transparent; border: 0; padding: 0; font-size: inherit; cursor: pointer; }
.policy-link:hover { text-decoration: underline; }
.branch-menu { min-width: 242px; }
.branch-search { height: 31px; border-radius: 8px; background: rgba(2,6,14,.72); display: flex; align-items: center; gap: 7px; padding: 0 8px; color: #8ea2bf; }
.branch-search input { width: 100%; min-width: 0; border: 0; outline: 0; background: transparent; color: var(--text); font-size: 11px; }
.branch-box { height: 108px; overflow: auto; }
.token-wrap { position: relative; }
.token-ring { width: 26px; height: 26px; border-radius: 50%; background: conic-gradient(#56b8ff 0 50%, rgba(255,255,255,.12) 50% 100%); display: grid; place-items: center; }
.token-ring:after { content: ""; width: 18px; height: 18px; border-radius: inherit; background: rgba(8,14,28,.96); }
.token-tip { position: absolute; right: 0; bottom: calc(100% + 8px); display: none; width: 238px; border: 1px solid var(--line-strong); border-radius: 10px; padding: 10px; background: rgba(7,11,22,.98); color: #dbe8fb; box-shadow: 0 18px 52px rgba(0,0,0,.46); }
.token-wrap:hover .token-tip { display: block; }
.token-tip strong { display: block; margin-bottom: 6px; }
.token-compact { margin-top: 12px; font-weight: 700; line-height: 1.35; }
.model-btn { min-width: 104px; justify-content: space-between; }
.model-main { display: grid; gap: 2px; text-align: left; }
.model-reasoning { color: #8ea2bf; font-size: 10px; }
.shortcut { border: 1px solid rgba(142,162,191,.38); border-radius: 5px; padding: 2px 5px; margin-left: 5px; color: #dbe8fb; }
.submenu-wrap { position: relative; }
.submenu-wrap:after { content: ""; position: absolute; top: 0; bottom: 0; right: 100%; width: 10px; }
.submenu-wrap:hover > .side-menu { display: block; }
.side-menu { position: absolute; right: calc(100% + 8px); bottom: 0; display: none; min-width: 168px; border: 1px solid var(--line-strong); border-radius: 10px; padding: 7px; background: rgba(7,11,22,.98); box-shadow: 0 18px 52px rgba(0,0,0,.46); }
.filterbar input, .filterbar select { min-width: 0; color: var(--text); border: 1px solid var(--line); border-radius: 8px; background: rgba(2,6,14,.7); padding: 8px; font-size: 11px; outline: 0; }
.filterbar input:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(56,189,248,.12); }
.pipeline { display: grid; gap: 8px; }
.stage { display: grid; grid-template-columns: 34px 1fr auto; align-items: center; gap: 9px; border: 1px solid var(--line); border-radius: 10px; padding: 9px; background: rgba(255,255,255,.035); }
.ring { width: 30px; height: 30px; border-radius: 50%; border: 2px solid rgba(56,189,248,.25); border-top-color: var(--blue); animation: spin 1.2s linear infinite; }
.stage.done .ring { animation: none; border-color: rgba(67,211,158,.45); background: radial-gradient(circle, rgba(67,211,158,.3), transparent 58%); }
.tools { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.terminal { min-height: 160px; border: 1px solid var(--line); border-radius: 10px; padding: 10px; background: rgba(0,0,0,.32); color: #b7ffdf; font: 11px/1.7 ui-monospace, SFMono-Regular, Consolas, monospace; overflow: hidden; }
.summary { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.metric { padding: 10px; border-radius: 10px; border: 1px solid var(--line); background: rgba(255,255,255,.04); }
.metric strong { display: block; font-size: 20px; line-height: 1; margin-bottom: 6px; }
.filterbar { display: grid; grid-template-columns: minmax(0, 1fr) 118px 118px; gap: 8px; }
.threat-table { border: 1px solid var(--line); border-radius: 10px; overflow: hidden; background: rgba(255,255,255,.035); }
.threat-row { width: 100%; border: 0; border-bottom: 1px solid rgba(130,180,255,.12); color: var(--text); background: transparent; padding: 7px 10px; text-align: left; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 10px; align-items: start; }
.threat-row.active { background: rgba(56,189,248,.1); }
.threat-main { min-width: 0; display: grid; gap: 4px; }
.truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.threat-main p { color: var(--muted); font-size: 12px; line-height: 1.42; }
.threat-message { color: #d4e4f8; font-size: 12px; font-weight: 500; }
.threat-meta { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; color: var(--muted); font-size: 10px; line-height: 1.35; }
.threat-tool { color: #aee0ff; font-weight: 700; }
.threat-severity { align-self: center; }
.details { display: grid; gap: 10px; }
.detail-summary { color: #d4e4f8; font-size: 12px; line-height: 1.5; }
.detail-meta-row { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
.detail-meta-row span { border: 1px solid rgba(130,180,255,.12); border-radius: 8px; padding: 8px; background: rgba(255,255,255,.028); color: var(--muted); font-size: 11px; line-height: 1.35; }
.detail-meta-row strong { display: block; color: #dbeafe; margin-bottom: 3px; }
.details pre, .detail-snippet-empty { white-space: pre-wrap; margin: 0; padding: 10px; border-radius: 8px; border: 1px solid var(--line); background: rgba(0,0,0,.28); color: #cfe5ff; font-size: 12px; line-height: 1.5; }
.detail-snippet { max-height: 110px; overflow: auto; }
.detail-snippet-empty { color: var(--muted); }
.graph-panel { display: grid; gap: 8px; }
.graph { width: 100%; min-height: 280px; border: 1px solid var(--line); border-radius: 10px; background: linear-gradient(180deg, rgba(255,255,255,.028), rgba(255,255,255,.012)); overflow: hidden; }
.graph line { stroke: rgba(125,210,255,.3); stroke-width: 1.4; }
.graph .edge-tool { stroke-dasharray: 4 4; }
.graph circle { fill: rgba(8,14,28,.94); stroke: rgba(125,210,255,.42); stroke-width: 1.4; }
.graph text { fill: #cfe3ff; font-size: 9px; text-anchor: middle; paint-order: stroke; stroke: rgba(5,7,13,.9); stroke-width: 3px; }
.graph-finding.severity-critical circle { stroke: rgba(255,83,112,.78); fill: rgba(255,83,112,.18); }
.graph-finding.severity-high circle { stroke: rgba(255,138,76,.72); fill: rgba(255,138,76,.14); }
.graph-finding.severity-medium circle { stroke: rgba(248,197,85,.68); fill: rgba(248,197,85,.13); }
.graph-file circle { stroke: rgba(67,211,158,.55); }
.graph-tool circle { stroke: rgba(167,139,250,.58); }
.graph-empty { min-height: 160px; display: grid; place-content: center; gap: 5px; border: 1px dashed var(--line); border-radius: 10px; color: var(--muted); text-align: center; }
.graph-empty strong { color: #dbeafe; }
.chart { height: 86px; display: flex; align-items: end; gap: 7px; padding: 10px; border: 1px solid var(--line); border-radius: 10px; background: rgba(255,255,255,.035); }
.bar { flex: 1; min-height: 14px; border-radius: 6px 6px 2px 2px; background: linear-gradient(180deg, var(--blue), rgba(56,189,248,.28)); box-shadow: 0 0 18px rgba(56,189,248,.18); }
.overlay { position: fixed; inset: 0; z-index: 20; display: grid; place-items: center; padding: 20px; background: radial-gradient(circle at center, rgba(18,35,70,.95), rgba(3,5,10,.98)); animation: fade .24s ease both; }
.setup { width: min(420px, 100%); text-align: center; border: 1px solid var(--line-strong); border-radius: 18px; padding: 24px; background: rgba(8,14,28,.7); box-shadow: 0 0 70px rgba(56,189,248,.12); }
.pulse-logo { width: 74px; height: 74px; margin: 0 auto 16px; object-fit: contain; filter: drop-shadow(0 0 28px rgba(56,189,248,.58)); animation: pulse 1.8s ease-in-out infinite; }
.progress { height: 7px; border-radius: 999px; background: rgba(255,255,255,.08); overflow: hidden; margin: 18px 0; }
.progress span { display: block; height: 100%; width: var(--progress, 0%); border-radius: inherit; background: linear-gradient(90deg, var(--blue), var(--purple)); box-shadow: 0 0 22px rgba(56,189,248,.45); transition: width .35s ease; }
.steps { text-align: left; display: grid; gap: 8px; color: var(--muted); font-size: 12px; }
.step.done { color: #d8ffef; }
.empty { text-align: center; padding: 18px; color: var(--muted); border: 1px dashed var(--line); border-radius: 10px; background: rgba(255,255,255,.025); }
@keyframes rise { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes pulse { 0%, 100% { transform: scale(1); opacity: .88; } 50% { transform: scale(1.06); opacity: 1; } }
@keyframes fade { from { opacity: 0; } to { opacity: 1; } }
@media (max-width: 320px) {
	.actions, .tools, .summary { grid-template-columns: 1fr; }
	.chatbar { left: 8px; right: 8px; bottom: 8px; }
	.chat-controls { flex-wrap: wrap; }
	.filterbar { grid-template-columns: 1fr; }
}
`;
}

function getScript(): string {
	return `
const vscode = acquireVsCodeApi();
let state = window.__AQIRON_STATE__;
let selectedThreatId = state.selectedThreatId;
const tabs = ['agent', 'scan', 'threats', 'reports'];
const actionCards = [
	['Explain this code', 'Trace intent, data flow, and security assumptions.', 'code'],
	['Scan this project', 'Run a fast static scan across indexed files.', 'shield'],
	['Do fuzzing', 'Generate and execute endpoint fuzz plans.', 'spark'],
	['Check dependencies', 'Audit manifests, lockfiles, and vulnerable packages.', 'pkg'],
	['Analyze network security', 'Review TLS, endpoints, and traffic assumptions.', 'net'],
	['Hunt secrets', 'Find keys, tokens, certs, and leaked credentials.', 'key'],
	['Reverse engineer APK', 'Build and analyze Android release artifacts.', 'apk'],
	['Generate exploit simulation', 'Create contained proof-of-risk scenarios.', 'sim'],
	['Review auth flow', 'Map auth boundaries and session risks.', 'auth'],
	['Analyze APIs', 'Discover routes, schemas, and abuse cases.', 'api']
];
const scanStages = ['Preparing', 'Building APK', 'Uploading', 'Scanning', 'AI Analysis', 'Correlation', 'Generating report'];
	const tools = ['Semgrep', 'Trivy', 'Betterleaks', 'OSV-Scanner', 'MobSF', 'AI Analysis', 'AI Security Review', 'Custom Rules'];
const setupSteps = ['Detecting project type', 'Building project graph', 'Detecting framework', 'Indexing source files', 'Preparing security agents', 'Loading scan engines', 'Connecting local AI', 'Workspace ready'];

window.addEventListener('message', event => {
	if (event.data.type === 'state') {
		state = event.data.state;
		selectedThreatId = selectedThreatId || state.selectedThreatId;
		render();
	}
});
function post(command, payload) { vscode.postMessage({ command, payload }); }
function esc(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function severityClass(sev) { return 'badge sev-' + esc(sev); }
function currentSection() { return state.section; }

function render() {
	document.getElementById('app').innerHTML = '<div class="shell"><div class="bg-media" style="background-image:url(' + esc(state.assets.bg) + ')"></div><div class="content ' + (currentSection() === 'agent' ? 'agent-content' : '') + '">' + nav() + page() + '</div>' + setupOverlay() + '</div>';
	bind();
}

function nav() {
	return '<div class="top-nav">' + tabs.map(tab => '<button class="nav-btn ' + (tab === currentSection() ? 'active' : '') + '" data-focus="' + tab + '">' + tabIcon(tab) + '<span>' + label(tab) + '</span></button>').join('') + '</div>';
}

function hero(title, subtitle) {
	const types = state.workspace.types || [];
	return '<header class="hero"><div class="hero-row"><div class="brand"><img src="' + esc(state.assets.logo) + '" /><div><div class="eyebrow">' + esc(subtitle) + '</div><h1>' + esc(title) + '</h1></div></div><span class="badge risk-' + esc(state.workspace.risk) + '">' + esc(state.workspace.risk) + '</span></div><div class="badges"><span class="badge">' + esc(types[0] || 'Workspace') + '</span><span class="badge">' + esc(state.workspace.status) + '</span><span class="badge">' + esc(state.stats.scanStatus) + '</span></div></header>';
}

function page() {
	if (currentSection() === 'agent') return agentPage();
	if (currentSection() === 'scan') return scanPage();
	if (currentSection() === 'threats') return threatsPage();
	return reportsPage();
}

function agentPage() {
	return hero('Aqiron Security Agent', state.workspace.name) +
	section('Smart Actions', '<div class="grid actions">' + actionCards.map(card => '<button class="card" data-agent="' + esc(card[0]) + '"><div class="icon">' + icon(card[2]) + '</div><h3>' + esc(card[0]) + '</h3><p>' + esc(card[1]) + '</p></button>').join('') + '</div>') +
	section('Smart Suggestions', suggestions()) +
	chatbar();
}

function suggestions() {
	return '<div class="grid">' + state.suggestions.map(s => '<div class="suggestion"><div class="suggestion-top"><h3>' + esc(s.title) + '</h3><span class="' + severityClass(s.severity) + '">' + esc(s.severity) + '</span></div><p>' + esc(s.detail) + '</p><div class="inline-actions"><button class="btn primary" data-agent="' + esc(s.command) + '">Run</button><button class="btn" data-agent="Explain ' + esc(s.title) + '">Explain</button>' + (s.recommended ? '<span class="badge">Recommended</span>' : '') + '</div></div>').join('') + '</div>';
}

function chatbar() {
	return '<div class="chatbar">' +
		'<textarea class="chat-input" rows="2" placeholder="Ask Aqiron to analyze, explain, fuzz, patch, or report..."></textarea>' +
		'<div class="chat-controls">' +
			'<div class="hover-control"><button class="control-btn icon-btn"><span class="svg-icon" style="--icon:url(' + esc(state.assets.addIcon) + ')"></span></button><span class="tip edge-left">Add files and more</span></div>' +
			providerDropdown() +
			branchDropdown() +
			'<div class="composer-spacer"></div>' +
			tokenWidget() +
			modelDropdown() +
			'<div class="send-wrap hover-control"><button class="send-btn" data-agent="Send chat"><span class="svg-icon" style="--icon:url(' + esc(state.assets.upArrowIcon) + ')"></span></button><span class="tip">Send</span></div>' +
		'</div>' +
	'</div>';
}

function providerDropdown() {
	return '<div class="hover-control">' +
		'<button class="control-btn" data-menu-toggle>OpenRouter<span class="svg-icon" style="--icon:url(' + esc(state.assets.chevronDownIcon) + ')"></span></button><span class="tip edge-left">Provider</span>' +
		'<div class="menu edge-left">' +
			'<div class="menu-option">OpenRouter<span class="option-spacer"></span><span class="hint">Active</span></div>' +
			'<button class="menu-option" data-command="refreshModels">Refresh models</button>' +
			'<button class="menu-option" data-command="configureProvider">Add Provider</button>' +
		'</div>' +
	'</div>';
}

function branchDropdown() {
	return '<div class="hover-control">' +
		'<button class="control-btn" data-menu-toggle><span class="svg-icon" style="--icon:url(' + esc(state.assets.branchesIcon) + ')"></span><span>master</span><span class="svg-icon" style="--icon:url(' + esc(state.assets.chevronDownIcon) + ')"></span></button><span class="tip edge-left">Switch branch</span>' +
		'<div class="menu branch-menu edge-left">' +
			'<div class="branch-search"><span class="codicon codicon-search">⌕</span><input placeholder="Search branches" /></div>' +
			'<div class="menu-title">Branches</div>' +
			'<div class="branch-box"><button class="menu-option"><span class="svg-icon" style="--icon:url(' + esc(state.assets.branchesIcon) + ')"></span><span>master</span></button></div>' +
			'<div class="menu-separator"></div>' +
			'<button class="menu-option"><span class="svg-icon" style="--icon:url(' + esc(state.assets.addIcon) + ')"></span><span>Create and checkout new branch...</span></button>' +
		'</div>' +
	'</div>';
}

function tokenWidget() {
	return '<div class="token-wrap">' +
		'<div class="token-ring"></div>' +
		'<div class="token-tip"><strong>Context window:</strong><div>32% used (68% left)</div><div class="muted">83k / 258k tokens used</div><div class="token-compact">Aqiron Security automatically<br />compacts its context</div></div>' +
	'</div>';
}

function modelDropdown() {
	return '<div class="hover-control">' +
		'<button class="control-btn model-btn" data-menu-toggle><span class="model-main"><span>qwen-coder</span><span class="model-reasoning">Medium</span></span><span class="svg-icon" style="--icon:url(' + esc(state.assets.chevronDownIcon) + ')"></span></button><span class="tip">Select model <kbd>Ctrl+Shift+M</kbd></span>' +
		'<div class="menu">' +
			'<div class="menu-title">Intelligence</div>' +
			'<button class="menu-option">Low</button>' +
			'<button class="menu-option">Medium<span class="option-spacer"></span><span class="codicon codicon-check">✓</span></button>' +
			'<button class="menu-option">High</button>' +
			'<button class="menu-option">Extra High</button>' +
			'<div class="menu-separator"></div>' +
			'<div class="submenu-wrap"><button class="menu-option">qwen coder<span class="option-spacer"></span><span>›</span></button>' +
				'<div class="side-menu"><div class="menu-title">Model</div><button class="menu-option">gpt-oss<span class="option-spacer"></span><span class="codicon codicon-check">✓</span></button><button class="menu-option">xiaomi-ai</button><div class="submenu-wrap"><button class="menu-option">Other models<span class="option-spacer"></span><span>›</span></button><div class="side-menu"><button class="menu-option">gpt-3</button><button class="menu-option">sonnet-4</button></div></div></div>' +
			'</div>' +
		'</div>' +
	'</div>';
}

function scanPage() {
	return hero('Live Scan Pipeline', 'Agentic scan workflow') +
	section('Pipeline', '<div class="pipeline">' + scanStages.map((name, i) => '<div class="stage ' + (state.stats.scanStatus === 'Complete' || i < activeStage() ? 'done' : '') + '"><div class="ring"></div><div><h3>' + esc(name) + '</h3><p class="muted">' + stageText(i) + '</p></div><span class="badge">' + (i <= activeStage() ? 'Live' : 'Queued') + '</span></div>').join('') + '</div>') +
	section('Tool Execution', '<div class="grid tools">' + tools.map((tool, i) => '<div class="card"><div class="tool-top"><h3>' + esc(tool) + '</h3><span class="badge">' + (state.stats.scanStatus === 'Scanning' ? 'Running' : i < 2 ? 'Ready' : 'Idle') + '</span></div><p>Runtime ' + (12 + i * 7) + 's | CPU ' + (8 + i * 3) + '% | Memory ' + (90 + i * 21) + 'MB</p></div>').join('') + '</div>') +
	section('Terminal Stream', '<div class="terminal">' + terminalLines().join('<br>') + '</div>') +
	section('Controls', '<div class="inline-actions"><button class="btn primary" data-command="scanWorkspace" data-scan-mode="quick">Quick Scan</button><button class="btn" data-command="scanWorkspace" data-scan-mode="deep">Deep Scan</button><button class="btn" data-agent="Analyze this workspace security posture and prioritize risk using the current scan context.">AI Audit</button><button class="btn" data-agent="Assess runtime security behavior and execution risks from the current workspace context.">Dynamic Analysis</button><button class="btn danger">Cancel Scan</button></div>');
}

function threatsPage() {
	const selected = state.issues.find(i => i.id === selectedThreatId) || state.issues[0];
	return hero('Threat Management', 'Vulnerability dashboard') +
	'<div class="grid summary">' + ['Critical','High','Medium','Low'].map(sev => '<div class="metric"><strong>' + esc(state.counts[sev.toLowerCase()]) + '</strong><span class="' + severityClass(sev) + '">' + sev + '</span></div>').join('') + '</div>' +
	'<div class="filterbar"><input placeholder="Search threats, files, CWE, OWASP..." /><select><option>Severity</option>' + severityOrderOptions() + '</select><select><option>Tool</option><option>Semgrep</option><option>Trivy</option><option>Betterleaks</option><option>OSV-Scanner</option><option>MobSF</option><option>AI Analysis</option><option>AI Security Review</option><option>Custom Rules</option></select></div>' +
	section('Threats', threatRows()) +
	section('Threat Graph', threatGraph()) +
	section('Details', selected ? threatDetails(selected) : '<div class="empty">No vulnerabilities indexed yet. Run a scan to populate this dashboard.</div>');
}

function reportsPage() {
	return hero('Enterprise Reports', 'Risk intelligence') +
	'<div class="grid summary"><div class="metric"><strong>' + riskScore() + '</strong><span class="muted">Risk score</span></div><div class="metric"><strong>' + esc(state.counts.total) + '</strong><span class="muted">Open findings</span></div><div class="metric"><strong>92%</strong><span class="muted">OWASP coverage</span></div><div class="metric"><strong>' + esc(state.stats.filesScanned) + '</strong><span class="muted">Files scanned</span></div></div>' +
	section('Risk Trend', '<div class="chart">' + [38,52,44,61,48,35,28].map(h => '<div class="bar" style="height:' + h + 'px"></div>').join('') + '</div>') +
	section('AI Summary', '<div class="card"><h3>Executive security posture</h3><p>' + reportSummary() + '</p></div>') +
	section('Tool Summaries', '<div class="grid tools">' + tools.slice(0,6).map(t => '<div class="card"><h3>' + esc(t) + '</h3><p>Completed baseline analysis with correlated findings and traceable evidence.</p></div>').join('') + '</div>') +
	section('Actions', '<div class="inline-actions"><button class="btn primary">Export PDF</button><button class="btn">Export JSON</button><button class="btn">Share report</button><button class="btn">Create Jira issue</button></div>');
}

function section(title, body) { return '<section class="section"><div class="section-head"><h2>' + esc(title) + '</h2></div>' + body + '</section>'; }
function label(tab) { return ({agent:'Agent', scan:'Scan', threats:'Threat', reports:'Reports'}[tab] || tab); }
function tabIcon(tab) {
	if (tab === 'scan') return '<span class="tab-icon asset-icon" style="--icon:url(' + esc(state.assets.scanIcon) + ')"></span>';
	if (tab === 'threats') return '<span class="tab-icon asset-icon" style="--icon:url(' + esc(state.assets.threatIcon) + ')"></span>';
	if (tab === 'reports') return '<span class="tab-icon asset-icon" style="--icon:url(' + esc(state.assets.reportsIcon) + ')"></span>';
	return '<span class="tab-icon asset-icon" style="--icon:url(' + esc(state.assets.agentIcon) + ')"></span>';
}
function activeStage() { return state.stats.scanStatus === 'Scanning' ? 3 : state.stats.scanStatus === 'Complete' ? 6 : 0; }
function stageText(i) { return i <= activeStage() ? 'Telemetry streaming into Aqiron correlation graph.' : 'Waiting for upstream stage.'; }
function terminalLines() { return ['[Aqiron] Preparing workspace graph', '[Semgrep] Analyzing source files', '[MobSF] Awaiting Android artifact', '[Trivy] Checking dependency manifests', '[AI] Correlating vulnerabilities with project context']; }
function threatRows() {
	return state.issues.length ? '<div class="threat-table">' + state.issues.map(i => '<button class="threat-row ' + (i.id === selectedThreatId ? 'active' : '') + '" data-threat="' + esc(i.id) + '"><div class="threat-main"><h3 class="truncate">' + esc(i.title) + '</h3><p class="threat-message truncate">' + esc(threatSummary(i)) + '</p><div class="threat-meta"><span>' + esc(i.relativeFile) + ':' + esc(i.line) + '</span><span class="threat-tool">' + esc(displayToolName(i.tool)) + '</span><span>' + esc(i.cwe) + '</span></div></div><span class="threat-severity ' + severityClass(i.severity) + '">' + esc(i.severity) + '</span></button>').join('') + '</div>' : '<div class="empty">No threats yet. Start a scan to build the vulnerability inventory.</div>';
}
function threatDetails(i) {
	const snippet = formatEvidenceSnippet(i.lineText);
	return '<div class="card details"><div class="suggestion-top"><h3>' + esc(i.title) + '</h3><span class="' + severityClass(i.severity) + '">' + esc(i.severity) + '</span></div><p class="detail-summary">' + esc(threatSummary(i)) + '</p><div class="badges"><span class="badge">Source: ' + esc(displayToolName(i.tool)) + '</span><span class="badge">' + esc(i.owasp) + '</span><span class="badge">' + esc(i.cwe) + '</span><span class="badge">Risk ' + esc(i.riskScore) + '</span><span class="badge">' + esc(i.status) + '</span></div><div class="detail-meta-row"><span><strong>Confidence</strong>' + esc(i.confidence) + '</span><span><strong>Location</strong>' + esc(i.relativeFile) + ':' + esc(i.line) + '</span><span><strong>Source tool</strong>' + esc(displayToolName(i.tool)) + '</span></div>' + (snippet ? '<pre class="detail-snippet">' + esc(snippet) + '</pre>' : '<div class="detail-snippet-empty">Evidence captured in the file. Use Open File to inspect the exact line.</div>') + '<div class="inline-actions"><button class="btn primary" data-agent="Explain ' + esc(i.title) + '">Explain</button><button class="btn" data-agent="Fix ' + esc(i.title) + '">Fix with AI</button><button class="btn" data-open="' + esc(i.id) + '">Open in editor</button><button class="btn">Ignore</button><button class="btn" data-agent="Create patch">Create patch</button></div></div>';
}
function threatGraph() {
	const issues = selectSerializableGraphIssues(state.issues.map(serializeIssue));
	if (!issues.length) {
		return '<div class="graph-empty"><strong>No relationships yet</strong><span>Run a scan with actionable findings to build file, tool, and risk links.</span></div>';
	}
	const tools = [...new Set(issues.map(issue => issue.tool))].slice(0, 6);
	const files = [...new Set(issues.map(issue => issue.relativeFile))].slice(0, 6);
	const width = 660;
	const height = Math.max(280, 150 + Math.max(tools.length, files.length, issues.length) * 32);
	const centerX = 330;
	const toolX = 86;
	const findingX = centerX;
	const fileX = 574;
	const toolNodes = tools.map((tool, index) => ({ id: 'tool-' + index, label: displayToolName(tool), x: toolX, y: 52 + index * 38, className: 'graph-tool' }));
	const fileNodes = files.map((file, index) => ({ id: 'file-' + index, label: file.split(/[\\/]/).pop() || file, x: fileX, y: 52 + index * 38, className: 'graph-file' }));
	const nodeLookup = new Map(toolNodes.map(node => [node.label, node]));
	const fileLookup = new Map(files.map((file, index) => [file, fileNodes[index]]));
	const findingNodes = issues.map((issue, index) => ({
		id: issue.id,
		label: issue.title,
		secondary: issue.severity + ' · ' + issue.confidence,
		x: findingX,
		y: 52 + index * 32,
		className: 'graph-finding severity-' + issue.severity.toLowerCase(),
		tool: nodeLookup.get(displayToolName(issue.tool)) || toolNodes[0],
		file: fileLookup.get(issue.relativeFile) || fileNodes[0],
	}));
	const edges = findingNodes.flatMap((node, index) => [
		'<line class="edge-tool" x1="' + node.tool.x + '" y1="' + node.tool.y + '" x2="' + node.x + '" y2="' + node.y + '"></line>',
		'<line x1="' + node.x + '" y1="' + node.y + '" x2="' + node.file.x + '" y2="' + node.file.y + '"></line>',
		'<circle class="' + node.tool.className + '" cx="' + node.tool.x + '" cy="' + node.tool.y + '" r="14"></circle>',
		'<text x="' + node.tool.x + '" y="' + (node.tool.y + 4) + '">' + esc(node.tool.label) + '</text>',
		'<circle class="' + node.className + '" cx="' + node.x + '" cy="' + node.y + '" r="17"></circle>',
		'<text x="' + node.x + '" y="' + (node.y + 4) + '">' + esc(shortLabel(node.label, 18)) + '</text>',
		'<text x="' + node.x + '" y="' + (node.y + 18) + '">' + esc(node.secondary) + '</text>',
		'<circle class="' + node.file.className + '" cx="' + node.file.x + '" cy="' + node.file.y + '" r="14"></circle>',
		'<text x="' + node.file.x + '" y="' + (node.file.y + 4) + '">' + esc(node.file.label) + '</text>',
	]);
	return '<div class="graph-panel"><svg class="graph" viewBox="0 0 ' + width + ' ' + height + '" role="img" aria-label="Threat relationship graph" preserveAspectRatio="none">' + edges.join('') + '</svg><div class="graph-legend graph-legend-horizontal"><span>Scanner</span><span>Finding</span><span>Evidence file</span></div></div>';
}
function displayToolName(tool) {
	if (tool === 'AI Analysis' || tool === 'AI Analyzer') {
		return 'AI Analyzer';
	}
	if (tool === 'AI Security Review') {
		return 'AI Security Review';
	}
	return tool || 'Aqiron';
}
function threatSummary(issue) {
	const summary = (issue.message || '').replace(/\s+/g, ' ').trim();
	if (!summary) {
		return 'Finding detected in the workspace.';
	}
	if (/secret-like material was detected/i.test(summary) || /api key detected/i.test(summary)) {
		return issue.remediation || 'Secret material detected. Rotate the credential and move it to a managed secret store.';
	}
	return summary;
}
function formatEvidenceSnippet(lineText) {
	const text = String(lineText || '').trim();
	if (!text) {
		return '';
	}
	if (/^\{[\s\S]*\}$/.test(text) && /executionSuccessful|toolExecutionNotifications|Syntax error at line/i.test(text)) {
		return '';
	}
	if (/executionSuccessful|toolExecutionNotifications|Syntax error at line/i.test(text)) {
		return '';
	}
	return text.length > 260 ? text.slice(0, 257).trimEnd() + '...' : text;
}
function shortLabel(value, max) {
	const text = String(value || '').replace(/\s+/g, ' ').trim();
	return text.length > max ? text.slice(0, Math.max(0, max - 1)).trimEnd() + '…' : text;
}
function severityOrderOptions() { return ['Critical','High','Medium','Low'].map(s => '<option>' + s + '</option>').join(''); }
function riskScore() { return Math.max(0, 100 - state.counts.critical * 18 - state.counts.high * 10 - state.counts.medium * 4 - state.counts.low); }
function reportSummary() { return state.counts.total ? 'Aqiron found ' + state.counts.total + ' issues across ' + state.counts.filesAffected + ' files. Prioritize critical secrets, injection paths, and exposed runtime controls before release.' : 'No open findings are currently indexed. Maintain scheduled scans and dependency monitoring before release gates.'; }
function setupOverlay() {
	if (state.setupDone || currentSection() !== 'agent') return '';
	return '<div class="overlay"><div class="setup"><img class="pulse-logo" src="' + esc(state.assets.logo) + '" /><h1>Setting up Aqiron Workspace...</h1><div class="progress"><span id="setup-progress"></span></div><div class="steps">' + setupSteps.map((s, i) => '<div class="step" data-step="' + i + '">○ ' + esc(s) + '</div>').join('') + '</div></div></div>';
}
function icon(name) {
	const icons = {
		code: '<span class="card-icon codicon codicon-agent">◇</span>',
		shield: '<span class="card-icon asset-icon" style="--icon:url(' + esc(state.assets.scanIcon) + ')"></span>',
		spark: '<span class="card-icon">+</span>',
		pkg: '<span class="card-icon">□</span>',
		net: '<span class="card-icon">⌁</span>',
		key: '<span class="card-icon">⌘</span>',
		apk: '<span class="card-icon">▤</span>',
		sim: '<span class="card-icon">△</span>',
		auth: '<span class="card-icon">◎</span>',
		api: '<span class="card-icon">{}</span>'
	};
	return icons[name] || '<span class="card-icon">+</span>';
}
function bind() {
	document.querySelectorAll('[data-menu-toggle]').forEach(el => el.addEventListener('click', event => {
		event.stopPropagation();
		const control = el.closest('.hover-control');
		const wasOpen = control.classList.contains('open');
		closeMenus();
		if (!wasOpen) control.classList.add('open');
	}));
	document.querySelectorAll('.menu').forEach(el => el.addEventListener('click', event => event.stopPropagation()));
	document.onclick = closeMenus;
	document.querySelectorAll('[data-focus]').forEach(el => el.addEventListener('click', () => post('focus', el.dataset.focus)));
	document.querySelectorAll('[data-command]').forEach(el => el.addEventListener('click', () => post(el.dataset.command, el.dataset.scanMode ? { mode: el.dataset.scanMode } : undefined)));
	document.querySelectorAll('[data-agent]').forEach(el => el.addEventListener('click', () => post('agentAction', el.dataset.agent)));
	document.querySelectorAll('[data-threat]').forEach(el => el.addEventListener('click', () => { selectedThreatId = el.dataset.threat; render(); }));
	document.querySelectorAll('[data-open]').forEach(el => el.addEventListener('click', () => post('openIssue', el.dataset.open)));
	startSetup();
}
function closeMenus() {
	document.querySelectorAll('.hover-control.open').forEach(el => el.classList.remove('open'));
}
function startSetup() {
	const progress = document.getElementById('setup-progress');
	if (!progress) return;
	let index = 0;
	const tick = () => {
		document.querySelectorAll('.step').forEach((step, i) => {
			if (i <= index) { step.classList.add('done'); step.textContent = '✓ ' + setupSteps[i]; }
		});
		progress.style.setProperty('--progress', Math.round(((index + 1) / setupSteps.length) * 100) + '%');
		index++;
		if (index < setupSteps.length) setTimeout(tick, 420);
		else setTimeout(() => { state.setupDone = true; post('setupComplete'); render(); }, 520);
	};
	setTimeout(tick, 260);
}
post('ready');
render();
`;
}

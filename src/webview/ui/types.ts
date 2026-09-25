import { AIModel, AIModelFilter, AIProviderCredential, AIProviderId, AITaskDefaults, ProviderConnectionStatus } from '../../ai/types/ai.js';

export type Section = 'agent' | 'scan' | 'threats' | 'reports' | 'settings' | 'aiAgent';
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
export type PermissionModeId = 'read-only' | 'ask-before-action' | 'workspace-trusted';

export interface WebviewIssue {
	id: string;
	title: string;
	message: string;
	severity: Severity;
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

export interface Counts {
	total: number;
	critical: number;
	high: number;
	medium: number;
	low: number;
	filesAffected: number;
}

export interface WorkspaceProfile {
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

export interface WorkspaceStats {
	filesScanned: number;
	indexedFiles: number;
	scanStatus: 'Idle' | 'Scanning' | 'Complete' | 'Failed';
	lastScanDurationMs: number;
}

export interface Suggestion {
	title: string;
	detail: string;
	severity: Severity;
	recommended: boolean;
	command: string;
}

export interface AgentMemory {
	previousPrompts: string[];
	ignoredFindings: string[];
	frameworksDetected: string[];
	apisDiscovered: string[];
	previousScans: Array<{ timestamp: string; issueCount: number; risk: WorkspaceProfile['risk'] }>;
}

export interface GraphNode {
	id: string;
	label: string;
	type: string;
}

export interface GraphEdge {
	id: string;
	source: string;
	target: string;
}

export interface TokenUsage {
	promptTokens: number;
	completionTokens: number;
	totalTokens: number;
	contextWindow: number;
	contextUsed: number;
}

export interface ChatMessage {
	id: string;
	role: 'user' | 'assistant';
	content: string;
	createdAt: string;
	streaming?: boolean;
	commands?: Array<{ label: string; command: string; status: 'queued' | 'ready' | 'running' | 'complete' | 'unavailable' }>;
}

export interface ChatSession {
	id: string;
	title: string;
	createdAt: string;
	updatedAt: string;
	model: string;
	intelligence: string;
	streaming?: boolean;
	messages: ChatMessage[];
}

export interface AiState {
	providers: Array<{
		id: AIProviderId;
		name: string;
		connected: boolean;
		message: string;
		hasCredential: boolean;
		endpoint?: string;
	}>;
	models: AIModel[];
	filteredModels: AIModel[];
	modelFilter: AIModelFilter;
	loadingModels: boolean;
	modelError?: string;
	status: ProviderConnectionStatus;
	settings: {
		selectedProvider: AIProviderId;
		selectedModel?: string;
		recentModelIds?: string[];
		activeApiCredentialId?: string;
		apiCredentials?: AIProviderCredential[];
		taskDefaults?: AITaskDefaults;
		temperature: number;
		maxTokens: number;
		timeoutMs: number;
		retries: number;
		streaming: boolean;
		openRouterEndpoint?: string;
	};
	apiCredentials: AIProviderCredential[];
	taskDefaults: AITaskDefaults;
	permissionModes: Array<{ id: PermissionModeId; label: string; description: string }>;
	intelligenceProfiles: Array<{ level: string; label: string; description: string }>;
	selection: {
		provider: AIProviderId;
		model: string;
		permissionMode: PermissionModeId;
		intelligence: string;
	};
}

export type PipelineToolStatus = 'queued' | 'running' | 'completed' | 'failed' | 'timeout' | 'unavailable' | 'cancelled';

export interface PipelineStage {
	name: string;
	status: PipelineToolStatus;
	progress: number;
	durationMs?: number;
}

export interface PipelineTool {
	id: string;
	label: string;
	command: string;
	status: PipelineToolStatus;
	durationMs?: number;
	exitCode?: number;
	message?: string;
	findingsCount?: number;
}

export interface WebviewState {
	section: Section;
	setupDone: boolean;
	workspace: WorkspaceProfile;
	branches: string[];
	stats: WorkspaceStats;
	counts: Counts;
	issues: WebviewIssue[];
	suggestions: Suggestion[];
	selectedThreatId?: string;
	zoom: number;
	threatSnapshots: ThreatSnapshot[];
	activeThreatSnapshotId?: string;
	memory: AgentMemory;
	graph: { nodes: GraphNode[]; edges: GraphEdge[] };
	compliance: Array<{ name: string; score: number; status: string }>;
	timeline: Array<{ id: string; title: string; detail: string; timestamp: string }>;
	chatSessions: ChatSession[];
	activeChatSessionId?: string;
	tokenUsage: TokenUsage;
	ai: AiState;
	mobsf: {
		baseUrl: string;
		apiKeyConfigured: boolean;
	};
	customRules: string;
	pipeline: {
		stages: PipelineStage[];
		tools: PipelineTool[];
		logs: string[];
		lastReport?: {
			directory?: string;
			jsonPath?: string;
			sarifPath?: string;
			pdfPath?: string;
			executiveSummary?: string;
		};
	};
	assets: Record<string, string>;
	rag: {
		ready: boolean;
		building: boolean;
		withAi: boolean;
		suggestionsGenerated: boolean;
		suggestions: string[];
		restricted: boolean;
		backend: 'faiss' | 'local';
	};
}

export interface ThreatSnapshot {
	id: string;
	title: string;
	createdAt: string;
	filesScanned: number;
	executiveSummary?: string;
	issues: WebviewIssue[];
}

export interface VsCodeApi {
	postMessage(message: { command: string; payload?: unknown }): void;
}


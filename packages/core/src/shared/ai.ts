export type AIProviderId = 'ollama' | 'openrouter';

export type AIMessageRole = 'system' | 'user' | 'assistant';

export interface AIProvider {
	id: string;
	name: string;
	initialize(): Promise<void>;
	getModels(): Promise<AIModel[]>;
	chat(req: ChatRequest): AsyncGenerator<StreamChunk>;
	validateConnection(): Promise<boolean>;
}

export interface AIModel {
	id: string;
	label: string;
	providerId: AIProviderId;
	contextWindow?: number;
	description?: string;
	family?: string;
	parameterSize?: string;
	quantization?: string;
	pricing?: {
		prompt: number;
		completion: number;
		request?: number;
	};
	badges: AIModelBadge[];
	capabilities: AIModelCapability[];
}

export type AIModelBadge = 'free' | 'paid' | 'coding' | 'reasoning' | 'vision' | 'local' | 'cloud' | 'custom';
export type AIModelCapability = 'chat' | 'code' | 'reasoning' | 'vision';

export interface ChatMessage {
	role: AIMessageRole;
	content: string;
}

export interface ChatRequest {
	model: string;
	messages: ChatMessage[];
	temperature: number;
	maxTokens: number;
	stream: boolean;
	timeoutMs: number;
	retries: number;
	abortSignal?: AbortSignal;
}

export interface StreamChunk {
	type: 'token' | 'done' | 'error';
	content?: string;
	finishReason?: string;
	usage?: TokenUsage;
	error?: string;
}

export interface TokenUsage {
	promptTokens: number;
	completionTokens: number;
	totalTokens: number;
}

export interface ProviderConnectionStatus {
	providerId: AIProviderId;
	connected: boolean;
	message: string;
	checkedAt?: string;
}

export interface ProviderConfig {
	providerId: AIProviderId;
	endpoint?: string;
	hasApiKey?: boolean;
	hasAuthToken?: boolean;
}

export interface AISettings {
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
	ollamaEndpoint: string;
	openRouterEndpoint: string;
}

export interface AIProviderCredential {
	id: string;
	name: string;
	providerId: AIProviderId;
	last4: string;
	createdAt: string;
	updatedAt: string;
}

export interface AITaskDefaults {
	useChatDefaults: boolean;
	provider?: AIProviderId;
	model?: string;
	intelligence?: string;
	permissionMode?: 'read-only' | 'ask-before-action' | 'workspace-trusted';
}

export interface AIModelFilter {
	query: string;
	freeOnly: boolean;
	codingOnly: boolean;
	reasoningOnly: boolean;
	visionOnly: boolean;
}

export interface AIWebviewState {
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
	settings: Omit<AISettings, 'ollamaEndpoint' | 'openRouterEndpoint'> & {
		ollamaEndpoint?: string;
		openRouterEndpoint?: string;
	};
	apiCredentials: AIProviderCredential[];
	taskDefaults: AITaskDefaults;
	permissionModes: Array<{ id: 'read-only' | 'ask-before-action' | 'workspace-trusted'; label: string; description: string }>;
	intelligenceProfiles: Array<{ level: string; label: string; description: string }>;
	selection: {
		provider: AIProviderId;
		model: string;
		permissionMode: 'read-only' | 'ask-before-action' | 'workspace-trusted';
		intelligence: string;
	};
}

export interface AIContextSnapshot {
	workspaceName: string;
	workspaceRoot?: string;
	projectTypes: string[];
	backend: string;
	currentFile: string;
	selectedCode?: string;
	scanStatus: string;
	issues: Array<{
		title: string;
		message: string;
		severity: string;
		ruleId: string;
		file: string;
		line: number;
		lineText: string;
		remediation?: string;
	}>;
	stats: {
		filesScanned: number;
		indexedFiles: number;
	};
	apis: string[];
}

export interface AIAnalysisContext {
	workspaceName: string;
	workspaceRoot?: string;
	projectTypes: string[];
	profile: {
		languages: string[];
		frameworks: string[];
		platforms: string[];
		services: string[];
		authentication: string[];
		databases: string[];
		storage: string[];
		dependencyManagers: string[];
		nativeCode: string[];
		ciCd: string[];
		sensitiveFiles: string[];
	};
	analysisGoals: string[];
	retrievalQueries: string[];
	candidateFiles: Array<{
		path: string;
		reason: string;
		language?: string;
		excerpt: string;
	}>;
	deterministicFindings: Array<{
		title: string;
		description: string;
		severity: string;
		sourceTool: string;
		ruleId: string;
		file: string;
		line: number;
		tags: string[];
		remediation?: string;
	}>;
	ragEvidence: Array<{
		query: string;
		file: string;
		startLine: number;
		endLine: number;
		score: number;
		excerpt: string;
		signalIds: string[];
	}>;
}

export interface AIAnalysisRequest {
	sessionId: string;
	model: string;
	intelligence: string;
	history: ChatMessage[];
	context: AIAnalysisContext;
}

export const defaultAISettings: AISettings = {
	selectedProvider: 'openrouter',
	temperature: 0.2,
	maxTokens: 2048,
	timeoutMs: 120_000,
	retries: 2,
	streaming: true,
	ollamaEndpoint: 'http://localhost:11434',
	openRouterEndpoint: 'https://openrouter.ai/api/v1',
};

export const defaultModelFilter: AIModelFilter = {
	query: '',
	freeOnly: false,
	codingOnly: false,
	reasoningOnly: false,
	visionOnly: false,
};

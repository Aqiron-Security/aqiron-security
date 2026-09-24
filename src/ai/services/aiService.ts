import * as path from 'path';
import * as vscode from 'vscode';
import { AIAnalysisContext, AIAnalysisRequest, AIContextSnapshot, AIModel, AIModelFilter, AIProviderCredential, AIProviderId, AISettings, AITaskDefaults, AIWebviewState, ChatMessage, ChatRequest, ProviderConnectionStatus, StreamChunk, defaultAISettings, defaultModelFilter } from '../types/ai';
import { normalizeProviderError } from '../utils/request';
import { aiSecretKeys } from './credentialService';
import { getCoreClient } from '../../core/coreClientSingleton';
import { AqironIssue, AqironWorkspaceStats } from '../../models/issue';
import { providerCredentialFallbackName, providerLabel } from './providerCredentialName';

export interface ChatHistoryItem {
	role: 'user' | 'assistant';
	content: string;
}

export interface AIChatInput {
	sessionId: string;
	text: string;
	history: ChatHistoryItem[];
	model: string;
	intelligence: string;
	context: AIContextSnapshot;
}

const SETTINGS_KEY = 'aqiron.ai.settings';

export class AIService implements vscode.Disposable {
	private settings: AISettings = defaultAISettings;
	private models: AIModel[] = [];
	private loadingModels = false;
	private modelError: string | undefined;
	private status: ProviderConnectionStatus = {
		providerId: defaultAISettings.selectedProvider,
		connected: false,
		message: 'Not connected',
	};
	private modelFilter: AIModelFilter = defaultModelFilter;

	constructor(private readonly context: vscode.ExtensionContext) {}

	async initialize(): Promise<void> {
		this.settings = normalizeSettings(this.context.globalState.get<AISettings>(SETTINGS_KEY));
		if ((this.settings as unknown as { selectedProvider?: string }).selectedProvider === 'ollama') {
			const { ollamaEndpoint: _ollamaEndpoint, ...migrated } = this.settings as AISettings & { ollamaEndpoint?: string };
			await getCoreClient().credentialsDelete({ key: 'aqiron.ai.ollama.authToken' });
			await this.saveSettings({ ...migrated, selectedProvider: 'openrouter' });
		}
		await this.migrateLegacyCredentials();
		await this.refreshModels(false);
	}

	dispose(): void {}

	async ensureFirstRunConfigured(): Promise<void> {
		if (this.context.globalState.get<AISettings | undefined>(SETTINGS_KEY)) {
			return;
		}
		const picked = await vscode.window.showQuickPick([
			{ label: 'OpenRouter', providerId: 'openrouter' as const, description: 'Cloud models through OpenRouter' },
			{ label: 'OpenAI', providerId: 'openai' as const, description: 'Direct OpenAI models' },
			{ label: 'Claude', providerId: 'claude' as const, description: 'Direct Anthropic Claude models' },
			{ label: 'Gemini', providerId: 'gemini' as const, description: 'Direct Google Gemini models' },
		], { title: 'Choose Aqiron AI provider', placeHolder: 'Select the provider Aqiron should use first' });
		if (!picked) {
			await this.saveSettings(defaultAISettings);
			return;
		}
		await this.configureProvider(picked.providerId);
	}

	async configureProvider(providerId?: AIProviderId): Promise<void> {
		const target = providerId ?? this.settings.selectedProvider;
		const apiKey = await vscode.window.showInputBox({ title: `${providerLabel(target)} API key`, prompt: `Enter your ${providerLabel(target)} API key.`, password: true, ignoreFocusOut: true });
		if (!apiKey) return;
		await this.saveApiCredential({ providerId: target, name: providerLabel(target), key: apiKey.trim() }, false);
		await this.saveSettings({ ...this.settings, selectedProvider: target });
		await this.refreshModels(true);
	}

	async configureOpenRouter(): Promise<void> {
		const apiKey = await vscode.window.showInputBox({
			title: 'OpenRouter API key',
			prompt: 'Enter your OpenRouter API key.',
			password: true,
			ignoreFocusOut: true,
		});
		if (!apiKey) {
			return;
		}
		await this.saveApiCredential({ providerId: 'openrouter', name: 'OpenRouter', key: apiKey.trim() }, false);
		await this.saveSettings({ ...this.settings, selectedProvider: 'openrouter' });
		const result = await getCoreClient().models('openrouter');
		this.status = result.status;
	}

	async updateSettings(patch: Partial<AISettings>): Promise<void> {
		await this.saveSettings({ ...this.settings, ...patch });
		await this.refreshModels(true);
	}

	async switchProvider(providerId: AIProviderId): Promise<void> {
		const credential = this.settings.apiCredentials?.find((api) => api.providerId === providerId);
		await this.saveSettings({ ...this.settings, selectedProvider: providerId, activeApiCredentialId: credential?.id });
		await this.refreshModels(true);
	}

	async selectModel(modelId: string): Promise<void> {
		const recentModelIds = [modelId, ...(this.settings.recentModelIds ?? []).filter((id) => id !== modelId)].slice(0, 8);
		await this.saveSettings({ ...this.settings, selectedModel: modelId, recentModelIds });
	}

	async saveApiCredential(input: { id?: string; providerId: AIProviderId; name?: string; key?: string }, refresh = true): Promise<AIProviderCredential> {
		const now = new Date().toISOString();
		const existing = input.id ? this.settings.apiCredentials?.find((api) => api.id === input.id) : undefined;
		const key = input.key?.trim();
		if (!key) {
			throw new Error(`Paste a ${providerLabel(input.providerId)} API key before saving.`);
		}
		const providerName = await this.getProviderCredentialName(input.providerId, key);
		const last4 = key.slice(-4);
		const next: AIProviderCredential = {
			id: existing?.id ?? createId(),
			name: providerName ?? existing?.name ?? providerCredentialFallbackName(input.providerId, last4),
			providerId: input.providerId,
			last4,
			createdAt: existing?.createdAt ?? now,
			updatedAt: now,
		};
		await getCoreClient().credentialsSet({ key: aiSecretKeys.apiCredential(next.id), value: key });
		if (next.providerId === 'openrouter') {
			await getCoreClient().credentialsSet({ key: aiSecretKeys.openRouterApiKey, value: key });
		}
		const apiCredentials = [next, ...(this.settings.apiCredentials ?? []).filter((api) => api.id !== next.id)];
		await this.saveSettings({ ...this.settings, apiCredentials, activeApiCredentialId: next.id, selectedProvider: next.providerId });
		if (refresh) {
			await this.refreshModels(true);
		}
		return next;
	}

	async selectApiCredential(id: string): Promise<void> {
		const api = this.settings.apiCredentials?.find((candidate) => candidate.id === id);
		if (!api) {
			return;
		}
		await this.saveSettings({ ...this.settings, activeApiCredentialId: id, selectedProvider: api.providerId });
		await this.refreshModels(true);
	}

	async deleteApiCredential(id: string): Promise<void> {
		await getCoreClient().credentialsDelete({ key: aiSecretKeys.apiCredential(id) });
		const apiCredentials = (this.settings.apiCredentials ?? []).filter((api) => api.id !== id);
		const activeApiCredentialId = this.settings.activeApiCredentialId === id ? apiCredentials[0]?.id : this.settings.activeApiCredentialId;
		const selectedProvider = apiCredentials.find((api) => api.id === activeApiCredentialId)?.providerId ?? this.settings.selectedProvider;
		await this.saveSettings({ ...this.settings, apiCredentials, activeApiCredentialId, selectedProvider });
		await this.refreshModels(true);
	}

	async saveTaskDefaults(defaults: AITaskDefaults): Promise<void> {
		await this.saveSettings({ ...this.settings, taskDefaults: defaults });
	}

	async removeProviderCredentials(providerId: AIProviderId): Promise<void> {
		const providerCredentials = (this.settings.apiCredentials ?? []).filter((api) => api.providerId === providerId);
		await Promise.all(providerCredentials.map((api) => getCoreClient().credentialsDelete({ key: aiSecretKeys.apiCredential(api.id) })));
		if (providerId === 'openrouter') await getCoreClient().credentialsDelete({ key: aiSecretKeys.openRouterApiKey });
		const apiCredentials = (this.settings.apiCredentials ?? []).filter((api) => api.providerId !== providerId);
		await this.saveSettings({ ...this.settings, apiCredentials, activeApiCredentialId: apiCredentials[0]?.id });
		await this.refreshModels(true);
	}

	async refreshModels(force: boolean): Promise<void> {
		this.loadingModels = true;
		this.modelError = undefined;
		try {
			const result = await getCoreClient().models(this.settings.selectedProvider);
			this.models = result.models ?? [];
			this.status = result.status ?? this.status;
			if (force) {
				const selectedExists = Boolean(this.settings.selectedModel && this.models.some((model) => model.id === this.settings.selectedModel));
				if (!selectedExists) {
					const recentModel = this.settings.recentModelIds?.find((modelId) => this.models.some((model) => model.id === modelId));
					if (recentModel) {
						await this.selectModel(recentModel);
					}
				}
			}
		} catch (error) {
			this.models = [];
			this.modelError = normalizeProviderError(error);
			this.status = { providerId: this.settings.selectedProvider, connected: false, message: this.modelError, checkedAt: new Date().toISOString() };
		} finally {
			this.loadingModels = false;
		}
	}

	applyModelFilter(filter: Partial<AIModelFilter>): void {
		this.modelFilter = { ...this.modelFilter, ...filter };
	}

	async getWebviewState(): Promise<AIWebviewState> {
		const providerIds = (await getCoreClient().providers()).providers as AIProviderId[];
		const filteredModels = applyModelFilter(this.models, this.modelFilter);
		const openRouterHasCredential = await getCoreClient().credentialsExists(aiSecretKeys.openRouterApiKey);
		return {
			providers: providerIds.map((id) => ({
				id,
				name: providerLabel(id),
				connected: this.status.providerId === id ? this.status.connected : false,
				message: this.status.providerId === id ? this.status.message : 'Not selected',
				hasCredential: this.settings.apiCredentials?.some((api) => api.providerId === id) ?? (id === 'openrouter' && openRouterHasCredential.exists),
			})),
			models: this.models,
			filteredModels,
			modelFilter: this.modelFilter,
			loadingModels: this.loadingModels,
			modelError: this.modelError,
			status: this.status,
			settings: {
				selectedProvider: this.settings.selectedProvider,
				selectedModel: this.settings.selectedModel,
				recentModelIds: this.settings.recentModelIds,
				activeApiCredentialId: this.settings.activeApiCredentialId,
				apiCredentials: this.settings.apiCredentials,
				taskDefaults: this.settings.taskDefaults,
				temperature: this.settings.temperature,
				maxTokens: this.settings.maxTokens,
				timeoutMs: this.settings.timeoutMs,
				retries: this.settings.retries,
				streaming: this.settings.streaming,
				openRouterEndpoint: this.settings.selectedProvider === 'openrouter' ? this.settings.openRouterEndpoint : undefined,
			},
			apiCredentials: this.settings.apiCredentials ?? [],
			taskDefaults: this.settings.taskDefaults ?? {
				useChatDefaults: true,
				provider: this.settings.selectedProvider,
				model: this.settings.selectedModel,
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
				provider: this.settings.selectedProvider,
				model: this.settings.selectedModel && this.models.some((model) => model.id === this.settings.selectedModel) ? this.settings.selectedModel : '',
				permissionMode: this.settings.taskDefaults?.permissionMode ?? 'ask-before-action',
				intelligence: this.settings.taskDefaults?.intelligence ?? 'Medium',
			},
		};
	}

	async *chat(input: AIChatInput): AsyncGenerator<StreamChunk> {
		const selectedModel = input.model || this.settings.selectedModel;
		if (!selectedModel) {
			throw new Error('Select a model before starting chat.');
		}
		yield* getCoreClient().chat({
			sessionId: input.sessionId,
			text: input.text,
			history: this.buildMessages(input),
			model: selectedModel,
			intelligence: input.intelligence,
			context: input.context as never,
		});
	}

	async *analyzeVulnerabilities(input: AIAnalysisRequest): AsyncGenerator<StreamChunk> {
		try {
			const result = await getCoreClient().vulnerabilityAnalysis({
				sessionId: input.sessionId,
				workspaceRoot: input.context.workspaceRoot,
				model: input.model || this.settings.selectedModel,
				history: input.history,
				context: input.context as never,
			} as never);
			const summary = typeof result === 'object' && result && 'summary' in result ? String((result as { summary?: string }).summary ?? '') : '';
			yield { type: 'token', content: summary || JSON.stringify(result) };
			yield { type: 'done' };
		} catch (error) {
			yield { type: 'error', error: error instanceof Error ? error.message : String(error) };
		}
	}

	cancelGeneration(sessionId: string): void {
		void getCoreClient().cancelRequest(`ai-chat-${sessionId}`).catch(() => undefined);
	}

	createContextSnapshot(issues: readonly AqironIssue[], stats: AqironWorkspaceStats, workspace: { name: string; root?: string; types: string[]; backend: string; currentFile: string; apis: string[] }): AIContextSnapshot {
		const editor = vscode.window.activeTextEditor;
		const selectedCode = editor && !editor.selection.isEmpty ? editor.document.getText(editor.selection).slice(0, 12_000) : undefined;
		return {
			workspaceName: workspace.name,
			workspaceRoot: workspace.root,
			projectTypes: workspace.types,
			backend: workspace.backend,
			currentFile: workspace.currentFile,
			selectedCode,
			scanStatus: stats.scanStatus,
			stats: {
				filesScanned: stats.filesScanned,
				indexedFiles: stats.indexedFiles,
			},
			apis: workspace.apis.slice(0, 24),
			issues: issues.slice(0, 20).map((issue) => ({
				title: issue.title,
				message: issue.message,
				severity: issue.severity,
				ruleId: issue.ruleId,
				file: workspace.root ? path.relative(workspace.root, issue.file) : issue.file,
				line: issue.range.startLine + 1,
				lineText: issue.lineText.slice(0, 500),
				remediation: issue.remediation,
			})),
		};
	}

	private buildMessages(input: AIChatInput): ChatMessage[] {
		const system = [
			'You are Aqiron Security, a production DevSecOps assistant inside VS Code.',
			'Give concrete security analysis, remediation, secure code, exploit explanations, scan summaries, and threat analysis using the supplied workspace context.',
			'Do not claim to have run tools unless the context says they ran. Prefer actionable fixes and clearly name risk.',
			`Reasoning depth: ${input.intelligence}.`,
		].join('\n');
		const context = truncate(JSON.stringify(input.context, null, 2), 18_000);
		const history = input.history.slice(-12).map((message): ChatMessage => ({
			role: message.role,
			content: truncate(message.content, 6_000),
		}));
		return [
			{ role: 'system', content: system },
			{ role: 'user', content: `Workspace security context:\n${context}` },
			...history,
			{ role: 'user', content: input.text },
		];
	}

	private async saveSettings(settings: AISettings): Promise<void> {
		this.settings = normalizeSettings(settings);
		await this.context.globalState.update(SETTINGS_KEY, this.settings);
		await getCoreClient().credentialsSet({ key: aiSecretKeys.settings, value: JSON.stringify(this.settings) });
	}

	private async getProviderCredentialName(providerId: AIProviderId, apiKey: string): Promise<string | undefined> {
		// Regular model API keys do not expose key-name metadata. Keep this hook
		// provider-aware so supported metadata can be added without exposing keys
		// or introducing a new IPC method.
		void providerId;
		void apiKey;
		return undefined;
	}

	private async migrateLegacyCredentials(): Promise<void> {
		const openRouterKeyExists = await getCoreClient().credentialsExists(aiSecretKeys.openRouterApiKey);
		const hasOpenRouterApi = this.settings.apiCredentials?.some((api) => api.providerId === 'openrouter');
		if (!openRouterKeyExists.exists || hasOpenRouterApi) {
			return;
		}
		const now = new Date().toISOString();
		const api: AIProviderCredential = {
			id: createId(),
			name: 'OpenRouter',
			providerId: 'openrouter',
			last4: '****',
			createdAt: now,
			updatedAt: now,
		};
		await this.saveSettings({
			...this.settings,
			apiCredentials: [api, ...(this.settings.apiCredentials ?? [])],
			activeApiCredentialId: this.settings.activeApiCredentialId ?? api.id,
		});
	}
}


function normalizeSettings(settings?: Partial<AISettings> & { ollamaEndpoint?: string }): AISettings {
	const { ollamaEndpoint: _legacyOllamaEndpoint, ...withoutLegacyOllama } = settings ?? {};
	return {
		...defaultAISettings,
		...withoutLegacyOllama,
		selectedProvider: settings?.selectedProvider ?? defaultAISettings.selectedProvider,
		openRouterEndpoint: settings?.openRouterEndpoint ?? defaultAISettings.openRouterEndpoint,
		apiCredentials: settings?.apiCredentials ?? [],
		recentModelIds: settings?.recentModelIds ?? [],
	};
}

function applyModelFilter(models: readonly AIModel[], filter: AIModelFilter): AIModel[] {
	return models.filter((model) => {
		if (filter.freeOnly && !model.badges.includes('free')) {
			return false;
		}
		if (filter.codingOnly && !model.capabilities.includes('code')) {
			return false;
		}
		if (filter.reasoningOnly && !model.capabilities.includes('reasoning')) {
			return false;
		}
		if (filter.visionOnly && !model.capabilities.includes('vision')) {
			return false;
		}
		const q = filter.query.trim().toLowerCase();
		if (!q) {
			return true;
		}
		return [model.id, model.label, model.description ?? '', ...(model.badges ?? []), ...(model.capabilities ?? [])].some((part) => part.toLowerCase().includes(q));
	});
}

function createId(): string {
	return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
}

function truncate(value: string, max: number): string {
	if (value.length <= max) {
		return value;
	}
	return `${value.slice(0, max)}\n[truncated ${value.length - max} chars]`;
}

import { AIModel, AIProvider, ChatRequest, ProviderCompletionMetadata, StreamChunk } from '../../shared/ai';
import { CredentialService } from '../services/credentialService';
import { BaseProvider } from './baseProvider';
import { AIHttpError, AITransport, OpenRouterRejectedRequest, normalizeProviderError, parseSseStream } from '../utils/request';
import { withRetry, isTransientError } from '../utils/retry';

interface OpenRouterModelsResponse {
	data?: Array<{
		id: string;
		name?: string;
		description?: string;
		context_length?: number;
		pricing?: {
			prompt?: string;
			completion?: string;
			request?: string;
			image?: string;
		};
		architecture?: {
			input_modalities?: string[];
			output_modalities?: string[];
			modality?: string;
		};
		supported_parameters?: string[];
	}>;
}

interface OpenRouterChunk {
	choices?: Array<{
		delta?: Record<string, unknown> & { content?: unknown };
		message?: Record<string, unknown> & { content?: unknown };
		finish_reason?: string | null;
	}>;
	usage?: {
		prompt_tokens?: number;
		completion_tokens?: number;
		total_tokens?: number;
		completion_tokens_details?: { reasoning_tokens?: number };
	};
	error?: {
		message?: string;
		code?: string;
	};
}

export interface OpenRouterResponseDiagnostics {
	status: number;
	contentType: string | undefined;
	streamed: boolean;
	eventCount: number;
	contentBearingEvents: number;
	textCharacters: number;
	finalEventReceived: boolean;
	choiceCount: number;
	responseKeys: string[];
	deltaKeys: string[];
	messageKeys: string[];
	contentPresent: boolean;
	contentTypeCounts: Record<string, number>;
	contentPartArray: boolean;
	deltaContentPresent: boolean;
	deltaContentType?: string;
	messageContentPresent: boolean;
	messageContentType?: string;
	reasoningPresent: boolean;
	reasoningNonEmpty: boolean;
	toolCallsPresent: boolean;
	refusalPresent: boolean;
	finishReasons: string[];
	requestedMaxTokens: number;
	reasoningControlApplied: boolean;
	usageRequested: boolean;
	reasoningCharacters: number;
	completionTokens: number;
	reasoningTokens: number;
	result: 'accepted' | 'empty' | 'decode-error';
}

export class OpenRouterProvider extends BaseProvider implements AIProvider {
	readonly id = 'openrouter' as const;
	readonly name = 'OpenRouter';

	constructor(
		credentials: CredentialService,
		transport: AITransport,
		private readonly onDiagnostics?: (diagnostics: OpenRouterResponseDiagnostics) => void,
		private readonly onRequestRejected?: (diagnostics: OpenRouterRejectedRequest) => void,
	) {
		super(credentials, transport);
	}

	async getModels(): Promise<AIModel[]> {
		const settings = await this.getSettings();
		const auth = await this.getAuthHeader();
		const response = await this.transport.request(`${this.normalizeBaseUrl(settings.openRouterEndpoint)}/models`, {
			timeoutMs: settings.timeoutMs,
			headers: { Authorization: auth },
		});
		const data = await response.json<OpenRouterModelsResponse>();
		return (data.data ?? []).map((model) => {
			const promptPrice = parsePrice(model.pricing?.prompt);
			const completionPrice = parsePrice(model.pricing?.completion);
			const requestPrice = parsePrice(model.pricing?.request);
			const free = promptPrice === 0 && completionPrice === 0 && requestPrice === 0;
			const vision = Boolean(model.architecture?.input_modalities?.includes('image') || model.architecture?.output_modalities?.includes('image') || /vision|vl|image/i.test(model.id));
			const coding = /code|coder|coding|deepseek|qwen|claude|gpt|devstral/i.test(`${model.id} ${model.name ?? ''} ${model.description ?? ''}`);
			const reasoning = /reason|thinking|r1|o\d|deepseek|qwen/i.test(`${model.id} ${model.name ?? ''} ${model.description ?? ''}`);
			return {
				id: model.id,
				label: model.name ?? model.id,
				providerId: this.id,
				contextWindow: model.context_length,
				description: model.description,
				pricing: { prompt: promptPrice, completion: completionPrice, request: requestPrice },
				supportedParameters: model.supported_parameters,
				badges: [free ? 'free' : 'paid', 'cloud', ...(coding ? ['coding' as const] : []), ...(reasoning ? ['reasoning' as const] : []), ...(vision ? ['vision' as const] : [])],
				capabilities: ['chat', ...(coding ? ['code' as const] : []), ...(reasoning ? ['reasoning' as const] : []), ...(vision ? ['vision' as const] : [])],
			};
		});
	}

	async validateConnection(): Promise<boolean> {
		const auth = await this.getAuthHeader();
		if (!auth) {
			return false;
		}
		try {
			await this.getModels();
			return true;
		} catch {
			return false;
		}
	}

	async *chat(req: ChatRequest): AsyncGenerator<StreamChunk> {
		const settings = await this.getSettings();
		const auth = await this.getAuthHeader();
		let response;
		try {
			response = await withRetry(
				async () => await this.transport.request(`${this.normalizeBaseUrl(settings.openRouterEndpoint)}/chat/completions`, {
					method: 'POST',
					timeoutMs: req.timeoutMs,
					abortSignal: req.abortSignal,
					maxRequestBodyBytes: req.transportLimits?.maxRequestBodyBytes,
					maxResponseBodyBytes: req.transportLimits?.maxResponseBodyBytes,
					maxSseEventBytes: req.transportLimits?.maxSseEventBytes,
					headers: {
						Authorization: auth,
						'HTTP-Referer': 'https://aqiron-security.local',
						'X-Title': 'Aqiron Security',
					},
					body: {
						model: req.model,
						messages: req.messages,
						stream: true,
						temperature: req.temperature,
						max_tokens: req.maxTokens,
						...(req.openRouterReasoning ? { reasoning: req.openRouterReasoning } : {}),
						...(req.includeUsage ? { stream_options: { include_usage: true } } : {}),
					},
				}),
				{ retries: req.retries, shouldRetry: isTransientError },
			);
		} catch (error) {
			const safeError = error instanceof AIHttpError
				? new AIHttpError(error.status)
				: new AIHttpError(req.abortSignal?.aborted ? 408 : 502);
			try { this.onRequestRejected?.({ status: safeError.status, category: safeError.category }); }
			catch { /* Diagnostics callbacks must not replace the safe provider error. */ }
			throw safeError;
		}
		const diagnostics: OpenRouterResponseDiagnostics = {
			status: response.status,
			contentType: header(response.headers, 'content-type'),
			streamed: Boolean(response.body),
			eventCount: 0,
			contentBearingEvents: 0,
			textCharacters: 0,
			finalEventReceived: false,
			choiceCount: 0,
			responseKeys: [],
			deltaKeys: [],
			messageKeys: [],
			contentPresent: false,
			contentTypeCounts: {},
			contentPartArray: false,
			deltaContentPresent: false,
			messageContentPresent: false,
			reasoningPresent: false,
			reasoningNonEmpty: false,
			toolCallsPresent: false,
			refusalPresent: false,
			finishReasons: [],
			requestedMaxTokens: req.maxTokens,
			reasoningControlApplied: Boolean(req.openRouterReasoning),
			usageRequested: Boolean(req.includeUsage),
			reasoningCharacters: 0,
			completionTokens: 0,
			reasoningTokens: 0,
			result: 'empty',
		};
		let completionFinishReason: string | undefined;
		let completionUsage: OpenRouterChunk['usage'];
		try {
			for await (const item of parseSseStream(response, (event) => {
				if (event.done) {
					diagnostics.finalEventReceived = true;
					return;
				}
				diagnostics.eventCount++;
				const chunk = asRecord(event.data);
				if (chunk) {
					diagnostics.responseKeys = [...new Set([...diagnostics.responseKeys, ...Object.keys(chunk)])];
					completionUsage = chunk.usage as OpenRouterChunk['usage'];
					diagnostics.reasoningTokens = completionUsage?.completion_tokens_details?.reasoning_tokens ?? diagnostics.reasoningTokens;
				}
				const choices = Array.isArray(chunk?.choices) ? chunk.choices : [];
				diagnostics.choiceCount = Math.max(diagnostics.choiceCount, choices.length);
				for (const rawChoice of choices) {
					const choice = asRecord(rawChoice);
					const delta = asRecord(choice?.delta);
					const message = asRecord(choice?.message);
					if (delta) {
						diagnostics.deltaKeys = [...new Set([...diagnostics.deltaKeys, ...Object.keys(delta)])];
					}
					if (message) {
						diagnostics.messageKeys = [...new Set([...diagnostics.messageKeys, ...Object.keys(message)])];
					}
					if (delta?.content !== undefined && delta.content !== null) {
						diagnostics.deltaContentPresent = true;
						diagnostics.deltaContentType = valueType(delta.content);
					}
					if (message?.content !== undefined && message.content !== null) {
						diagnostics.messageContentPresent = true;
						diagnostics.messageContentType = valueType(message.content);
					}
					const content = delta?.content ?? message?.content;
					const extracted = extractOpenRouterContent(content);
					if (content !== undefined && content !== null) {
						diagnostics.contentPresent = true;
						const type = valueType(content);
						diagnostics.contentTypeCounts[type] = (diagnostics.contentTypeCounts[type] ?? 0) + 1;
						diagnostics.contentPartArray ||= Array.isArray(content);
					}
					if (extracted.length > 0) {
						diagnostics.contentBearingEvents++;
						diagnostics.textCharacters += extracted.length;
					}
					const reasoning = delta?.reasoning ?? delta?.reasoning_content ?? message?.reasoning ?? message?.reasoning_content;
					diagnostics.reasoningPresent ||= reasoning !== undefined && reasoning !== null;
					diagnostics.reasoningNonEmpty ||= hasText(reasoning);
					if (hasText(reasoning)) {
						diagnostics.reasoningCharacters += typeof reasoning === 'string' ? reasoning.length : textArrayLength(reasoning);
					}
					diagnostics.toolCallsPresent ||= Boolean(delta?.tool_calls ?? message?.tool_calls);
					diagnostics.refusalPresent ||= Boolean(delta?.refusal ?? message?.refusal);
					const finishReason = choice?.finish_reason;
					if (typeof finishReason === 'string' && finishReason && !diagnostics.finishReasons.includes(finishReason)) {
						diagnostics.finishReasons.push(finishReason);
					}
					if (typeof finishReason === 'string' && finishReason) {
						completionFinishReason = finishReason;
					}
				}
			}, req.transportLimits?.maxResponseBodyBytes, req.transportLimits?.maxSseEventBytes)) {
				const chunk = item as OpenRouterChunk;
				if (chunk.error?.message) {
					yield { type: 'error', error: 'The provider returned an error response.' };
					continue;
				}
				const choice = chunk.choices?.[0];
				// OpenRouter-compatible providers normally stream delta.content. Some
				// return the completed message on the terminal chunk instead; use it
				// only when that chunk has no delta so content is never duplicated.
				const content = extractOpenRouterContent(choice?.delta?.content ?? choice?.message?.content);
				if (content) {
					yield { type: 'token', content };
				}
			}
			diagnostics.completionTokens = completionUsage?.completion_tokens ?? 0;
			diagnostics.result = diagnostics.textCharacters > 0 ? 'accepted' : 'empty';
			const providerCompletion: ProviderCompletionMetadata = {
				reasoningPresent: diagnostics.reasoningNonEmpty,
				reasoningCharacters: diagnostics.reasoningCharacters,
				completionTokens: diagnostics.completionTokens,
			};
			yield {
				type: 'done',
				finishReason: completionFinishReason,
				usage: {
					promptTokens: completionUsage?.prompt_tokens ?? 0,
					completionTokens: completionUsage?.completion_tokens ?? 0,
					totalTokens: completionUsage?.total_tokens ?? 0,
				},
				providerCompletion,
			};
		} catch (error) {
			diagnostics.result = 'decode-error';
			throw error;
		} finally {
			this.onDiagnostics?.(diagnostics);
		}
	}
}

function extractOpenRouterContent(content: unknown): string {
	if (typeof content === 'string') {
		return content;
	}
	if (!Array.isArray(content)) {
		return '';
	}
	return content.map((part) => {
		const record = asRecord(part);
		return record?.type === 'text' && typeof record.text === 'string' ? record.text : '';
	}).join('');
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
	return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function valueType(value: unknown): string {
	return Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;
}

function hasText(value: unknown): boolean {
	return typeof value === 'string' ? value.length > 0 : Array.isArray(value) && value.some((part) => hasText(asRecord(part)?.text));
}

function textArrayLength(value: unknown): number {
	return Array.isArray(value) ? value.reduce((total, part) => {
		const text = asRecord(part)?.text;
		return total + (typeof text === 'string' ? text.length : 0);
	}, 0) : 0;
}

function header(headers: Record<string, string>, key: string): string | undefined {
	return Object.entries(headers).find(([name]) => name.toLowerCase() === key)?.[1];
}

function parsePrice(value: string | undefined): number {
	const parsed = Number(value ?? 0);
	return Number.isFinite(parsed) ? parsed : 0;
}

import { AIModel, AIProvider, ChatRequest, StreamChunk } from '../../shared/ai';
import { CredentialService } from '../services/credentialService';
import { BaseProvider } from './baseProvider';
import { AITransport, normalizeProviderError, parseSseStream } from '../utils/request';
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
		delta?: { content?: string };
		finish_reason?: string | null;
	}>;
	usage?: {
		prompt_tokens?: number;
		completion_tokens?: number;
		total_tokens?: number;
	};
	error?: {
		message?: string;
		code?: string;
	};
}

export class OpenRouterProvider extends BaseProvider implements AIProvider {
	readonly id = 'openrouter' as const;
	readonly name = 'OpenRouter';

	constructor(credentials: CredentialService, transport: AITransport) {
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
		const response = await withRetry(
			async () => await this.transport.request(`${this.normalizeBaseUrl(settings.openRouterEndpoint)}/chat/completions`, {
				method: 'POST',
				timeoutMs: req.timeoutMs,
				abortSignal: req.abortSignal,
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
				},
			}),
			{ retries: req.retries, shouldRetry: isTransientError },
		);
		for await (const item of parseSseStream(response)) {
			const chunk = item as OpenRouterChunk;
			if (chunk.error?.message) {
				yield { type: 'error', error: chunk.error.message };
				continue;
			}
			const choice = chunk.choices?.[0];
			const content = choice?.delta?.content ?? '';
			if (content) {
				yield { type: 'token', content };
			}
			if (choice?.finish_reason) {
				yield {
					type: 'done',
					finishReason: choice.finish_reason,
					usage: {
						promptTokens: chunk.usage?.prompt_tokens ?? 0,
						completionTokens: chunk.usage?.completion_tokens ?? 0,
						totalTokens: chunk.usage?.total_tokens ?? 0,
					},
				};
			}
		}
	}
}

function parsePrice(value: string | undefined): number {
	const parsed = Number(value ?? 0);
	return Number.isFinite(parsed) ? parsed : 0;
}

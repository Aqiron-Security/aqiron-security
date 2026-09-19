import { AIModel, AIProvider, ChatRequest, StreamChunk } from '../../shared/ai';
import { CredentialService } from '../services/credentialService';
import { BaseProvider } from './baseProvider';
import { AIHttpResponse, AITransport, parseNdjsonStream, normalizeProviderError } from '../utils/request';
import { withRetry, isTransientError } from '../utils/retry';

interface OllamaTagsResponse {
	models?: Array<{
		name?: string;
		model?: string;
		size?: number;
		modified_at?: string;
		details?: {
			family?: string;
			families?: string[];
			parameter_size?: string;
			quantization_level?: string;
		};
	}>;
}

interface OllamaChatChunk {
	message?: { content?: string; thinking?: string };
	done?: boolean;
	done_reason?: string;
	prompt_eval_count?: number;
	eval_count?: number;
}

export class OllamaProvider extends BaseProvider implements AIProvider {
	readonly id = 'ollama' as const;
	readonly name = 'Ollama';

	constructor(credentials: CredentialService, transport: AITransport) {
		super(credentials, transport);
	}

	async getModels(): Promise<AIModel[]> {
		const settings = await this.getSettings();
		const baseUrl = this.normalizeBaseUrl(settings.ollamaEndpoint);
		const auth = await this.getAuthHeader();
		const response = await this.transport.request(`${baseUrl}/api/tags`, {
			timeoutMs: settings.timeoutMs,
			headers: { Authorization: auth },
		});
		const data = await response.json<OllamaTagsResponse>();
		const models = data.models ?? [];
		return models.map((model) => {
			const id = model.model ?? model.name ?? 'custom';
			const family = model.details?.family ?? model.details?.families?.[0] ?? inferFamily(id);
			return {
				id,
				label: id,
				providerId: this.id,
				family,
				parameterSize: model.details?.parameter_size,
				quantization: model.details?.quantization_level,
				description: `Local Ollama model${model.size ? ` (${formatBytes(model.size)})` : ''}.`,
				badges: ['local', 'free', ...(isCodingModel(id) ? ['coding' as const] : []), ...(isReasoningModel(id) ? ['reasoning' as const] : [])],
				capabilities: ['chat', ...(isCodingModel(id) ? ['code' as const] : []), ...(isReasoningModel(id) ? ['reasoning' as const] : [])],
			};
		});
	}

	async validateConnection(): Promise<boolean> {
		try {
			await this.getModels();
			return true;
		} catch {
			return false;
		}
	}

	async *chat(req: ChatRequest): AsyncGenerator<StreamChunk> {
		const settings = await this.getSettings();
		const baseUrl = this.normalizeBaseUrl(settings.ollamaEndpoint);
		const auth = await this.getAuthHeader();
		const response = await withRetry(
			async () => await this.transport.request(`${baseUrl}/api/chat`, {
				method: 'POST',
				timeoutMs: req.timeoutMs,
				abortSignal: req.abortSignal,
				headers: { Authorization: auth },
				body: {
					model: req.model,
					messages: req.messages,
					stream: true,
					options: {
						temperature: req.temperature,
						num_predict: req.maxTokens,
					},
				},
			}),
			{ retries: req.retries, shouldRetry: isTransientError },
		);
		for await (const item of parseNdjsonStream(response)) {
			const chunk = item as OllamaChatChunk;
			const content = chunk.message?.content ?? '';
			if (content) {
				yield { type: 'token', content };
			}
			if (chunk.done) {
				yield {
					type: 'done',
					finishReason: chunk.done_reason,
					usage: {
						promptTokens: chunk.prompt_eval_count ?? 0,
						completionTokens: chunk.eval_count ?? 0,
						totalTokens: (chunk.prompt_eval_count ?? 0) + (chunk.eval_count ?? 0),
					},
				};
			}
		}
	}
}

function inferFamily(model: string): string {
	const lower = model.toLowerCase();
	for (const family of ['llama', 'qwen', 'mistral', 'deepseek', 'codellama', 'gpt-oss']) {
		if (lower.includes(family)) {
			return family;
		}
	}
	return 'custom';
}

function isCodingModel(model: string): boolean {
	return /code|coder|codellama|deepseek|qwen/i.test(model);
}

function isReasoningModel(model: string): boolean {
	return /reason|r1|deepseek|qwen|gpt-oss/i.test(model);
}

function formatBytes(bytes: number): string {
	const gb = bytes / 1024 / 1024 / 1024;
	return `${gb.toFixed(gb >= 10 ? 0 : 1)}GB`;
}

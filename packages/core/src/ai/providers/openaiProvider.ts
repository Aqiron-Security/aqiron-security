import { AIModel, AIProvider, ChatRequest, StreamChunk } from '../../shared/ai';
import { BaseProvider } from './baseProvider';
import { AITransport, parseSseStream } from '../utils/request';
import { CredentialService } from '../services/credentialService';
import { withRetry, isTransientError } from '../utils/retry';

interface OpenAIModelsResponse { data?: Array<{ id: string; owned_by?: string }> }
interface OpenAIChunk { choices?: Array<{ delta?: { content?: string }; finish_reason?: string | null }> }

export class OpenAIProvider extends BaseProvider implements AIProvider {
	readonly id = 'openai' as const;
	readonly name = 'OpenAI';
	private readonly endpoint = 'https://api.openai.com/v1';

	constructor(credentials: CredentialService, transport: AITransport) { super(credentials, transport); }

	async getModels(): Promise<AIModel[]> {
		const settings = await this.getSettings();
		const response = await this.transport.request(`${this.endpoint}/models`, { timeoutMs: settings.timeoutMs, headers: { Authorization: await this.getAuthHeader() } });
		const data = await response.json<OpenAIModelsResponse>();
		return (data.data ?? []).filter((model) => isChatModel(model.id)).map((model) => modelInfo(model.id, model.owned_by));
	}

	async validateConnection(): Promise<boolean> {
		try { await this.getModels(); return true; } catch { return false; }
	}

	async *chat(req: ChatRequest): AsyncGenerator<StreamChunk> {
		const response = await withRetry(async () => {
			const settings = await this.getSettings();
			return await this.transport.request(`${this.endpoint}/chat/completions`, {
				method: 'POST', timeoutMs: req.timeoutMs, abortSignal: req.abortSignal,
				headers: { Authorization: await this.getAuthHeader() },
				body: { model: req.model, messages: req.messages, stream: true, temperature: req.temperature, max_tokens: req.maxTokens },
			});
		}, { retries: req.retries, shouldRetry: isTransientError });
		for await (const item of parseSseStream(response)) {
			const chunk = item as OpenAIChunk;
			const choice = chunk.choices?.[0];
			if (choice?.delta?.content) yield { type: 'token', content: choice.delta.content };
			if (choice?.finish_reason) yield { type: 'done', finishReason: choice.finish_reason };
		}
	}
}

function isChatModel(id: string): boolean {
	return !/(embedding|moderation|whisper|tts|dall-e|realtime|transcribe|audio)/i.test(id);
}

function modelInfo(id: string, owner?: string): AIModel {
	const reasoning = /reason|o[134]|gpt-5/i.test(id);
	const coding = /code|coder|gpt/i.test(id);
	return { id, label: id, providerId: 'openai', description: owner ? `OpenAI model owned by ${owner}.` : 'OpenAI model.', badges: ['paid', 'cloud', ...(coding ? ['coding' as const] : []), ...(reasoning ? ['reasoning' as const] : [])], capabilities: ['chat', ...(coding ? ['code' as const] : []), ...(reasoning ? ['reasoning' as const] : [])] };
}

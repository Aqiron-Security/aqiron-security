import { AIModel, AIProvider, ChatRequest, StreamChunk } from '../../shared/ai';
import { BaseProvider } from './baseProvider';
import { AITransport, parseSseStream } from '../utils/request';
import { CredentialService } from '../services/credentialService';
import { withRetry, isTransientError } from '../utils/retry';

interface ClaudeModelsResponse { data?: Array<{ id: string; display_name?: string; max_input_tokens?: number }> }

export class ClaudeProvider extends BaseProvider implements AIProvider {
	readonly id = 'claude' as const;
	readonly name = 'Claude';
	private readonly endpoint = 'https://api.anthropic.com/v1';

	constructor(credentials: CredentialService, transport: AITransport) { super(credentials, transport); }

	async getModels(): Promise<AIModel[]> {
		const settings = await this.getSettings();
		const response = await this.transport.request(`${this.endpoint}/models`, { timeoutMs: settings.timeoutMs, headers: await this.getApiHeaders() });
		const data = await response.json<ClaudeModelsResponse>();
		return (data.data ?? []).map((model) => ({ id: model.id, label: model.display_name ?? model.id, providerId: 'claude' as const, contextWindow: model.max_input_tokens, badges: ['paid', 'cloud', ...(model.id.includes('opus') || model.id.includes('sonnet') ? ['reasoning' as const] : [])], capabilities: ['chat', 'code'] }));
	}

	async validateConnection(): Promise<boolean> {
		try { await this.getModels(); return true; } catch { return false; }
	}

	async *chat(req: ChatRequest): AsyncGenerator<StreamChunk> {
		const messages = req.messages.filter((message) => message.role !== 'system');
		const system = req.messages.filter((message) => message.role === 'system').map((message) => message.content).join('\n\n');
		const response = await withRetry(async () => {
			return await this.transport.request(`${this.endpoint}/messages`, {
				method: 'POST', timeoutMs: req.timeoutMs, abortSignal: req.abortSignal, headers: await this.getApiHeaders(),
				body: { model: req.model, max_tokens: req.maxTokens, ...(system ? { system } : {}), messages, stream: true },
			});
		}, { retries: req.retries, shouldRetry: isTransientError });
		for await (const item of parseSseStream(response)) {
			const event = item as { type?: string; delta?: { type?: string; text?: string }; error?: { message?: string } };
			if (event.type === 'content_block_delta' && event.delta?.type === 'text_delta' && event.delta.text) yield { type: 'token', content: event.delta.text };
			if (event.type === 'message_stop') yield { type: 'done' };
			if (event.type === 'error') yield { type: 'error', error: event.error?.message ?? 'Claude returned an error.' };
		}
	}

	private async getApiHeaders(): Promise<Record<string, string | undefined>> {
		return { 'x-api-key': await this.getApiKey(), 'anthropic-version': '2023-06-01' };
	}
}

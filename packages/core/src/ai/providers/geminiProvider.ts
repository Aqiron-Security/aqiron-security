import { AIModel, AIProvider, ChatRequest, StreamChunk } from '../../shared/ai';
import { BaseProvider } from './baseProvider';
import { AITransport, parseSseStream } from '../utils/request';
import { CredentialService } from '../services/credentialService';
import { withRetry, isTransientError } from '../utils/retry';

interface GeminiModelsResponse { models?: Array<{ name: string; displayName?: string; description?: string; inputTokenLimit?: number; supportedGenerationMethods?: string[] }> }
interface GeminiChunk { candidates?: Array<{ content?: { parts?: Array<{ text?: string }> }; finishReason?: string }> }

export class GeminiProvider extends BaseProvider implements AIProvider {
	readonly id = 'gemini' as const;
	readonly name = 'Gemini';
	private readonly endpoint = 'https://generativelanguage.googleapis.com/v1beta';

	constructor(credentials: CredentialService, transport: AITransport) { super(credentials, transport); }

	async getModels(): Promise<AIModel[]> {
		const settings = await this.getSettings();
		const response = await this.transport.request(`${this.endpoint}/models`, { timeoutMs: settings.timeoutMs, headers: { 'x-goog-api-key': await this.getApiKey() } });
		const data = await response.json<GeminiModelsResponse>();
		return (data.models ?? []).filter((model) => model.supportedGenerationMethods?.includes('generateContent')).map((model) => {
			const id = model.name.replace(/^models\//, '');
			return { id, label: model.displayName ?? id, providerId: 'gemini' as const, contextWindow: model.inputTokenLimit, description: model.description, badges: ['paid', 'cloud', ...(id.includes('pro') || id.includes('thinking') ? ['reasoning' as const] : [])], capabilities: ['chat', 'vision', ...(id.includes('code') ? ['code' as const] : [])] };
		});
	}

	async validateConnection(): Promise<boolean> {
		try { await this.getModels(); return true; } catch { return false; }
	}

	async *chat(req: ChatRequest): AsyncGenerator<StreamChunk> {
		const system = req.messages.filter((message) => message.role === 'system').map((message) => message.content).join('\n\n');
		const contents = req.messages.filter((message) => message.role !== 'system').map((message) => ({ role: message.role === 'assistant' ? 'model' : 'user', parts: [{ text: message.content }] }));
		const response = await withRetry(async () => await this.transport.request(`${this.endpoint}/models/${encodeURIComponent(req.model)}:streamGenerateContent?alt=sse`, {
			method: 'POST', timeoutMs: req.timeoutMs, abortSignal: req.abortSignal, headers: { 'x-goog-api-key': await this.getApiKey() },
			body: { ...(system ? { systemInstruction: { parts: [{ text: system }] } } : {}), contents, generationConfig: { temperature: req.temperature, maxOutputTokens: req.maxTokens } },
		}), { retries: req.retries, shouldRetry: isTransientError });
		for await (const item of parseSseStream(response)) {
			const chunk = item as GeminiChunk;
			const text = chunk.candidates?.[0]?.content?.parts?.map((part) => part.text ?? '').join('') ?? '';
			if (text) yield { type: 'token', content: text };
			if (chunk.candidates?.[0]?.finishReason) yield { type: 'done', finishReason: chunk.candidates[0].finishReason };
		}
	}
}

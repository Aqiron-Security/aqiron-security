import { ChatRequest, StreamChunk } from '../../shared/ai';
import { ProviderRegistry } from './providerRegistry';

export class StreamingService {
	private readonly active = new Map<string, AbortController>();

	constructor(private readonly registry: ProviderRegistry) {}

	cancel(sessionId: string): void {
		this.active.get(sessionId)?.abort();
		this.active.delete(sessionId);
	}

	cancelAll(): void {
		for (const controller of this.active.values()) {
			controller.abort();
		}
		this.active.clear();
	}

	async *stream(sessionId: string, req: Omit<ChatRequest, 'abortSignal'>): AsyncGenerator<StreamChunk> {
		this.cancel(sessionId);
		const controller = new AbortController();
		this.active.set(sessionId, controller);
		try {
			const provider = this.registry.getCurrentProvider();
			for await (const chunk of provider.chat({ ...req, abortSignal: controller.signal })) {
				yield chunk;
			}
		} finally {
			if (this.active.get(sessionId) === controller) {
				this.active.delete(sessionId);
			}
		}
	}
}

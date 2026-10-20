import { AIModel, AIProviderId, OpenRouterReasoningOptions } from '../../shared/ai';

export interface ChatGenerationPolicy {
	maxTokens?: number;
	openRouterReasoning?: OpenRouterReasoningOptions;
}

/**
 * OpenRouter declares request controls per model. Apply an output-oriented policy
 * only when the selected route advertises the parameter it will receive.
 */
export function resolveChatGenerationPolicy(providerId: AIProviderId, model: AIModel | undefined, configuredMaxTokens: number): ChatGenerationPolicy {
	if (providerId !== 'openrouter' || !model) {
		return {};
	}
	const supported = new Set(model.supportedParameters ?? []);
	const policy: ChatGenerationPolicy = {};
	if (supported.has('reasoning')) {
		// OpenRouter's MiniMax M3.1 Flash route rejects a disabled reasoning
		// setting (the endpoint requires adaptive thinking). Keep reasoning on,
		// but cap its share of the completion budget so visible answer tokens remain.
		policy.openRouterReasoning = /^minimax\/minimax-m3\.1-flash(?::|$)/i.test(model.id)
			? { enabled: true, max_tokens: 1024 }
			: { enabled: false };
	}
	if (supported.has('max_tokens')) {
		policy.maxTokens = Math.max(configuredMaxTokens, 4096);
	}
	return policy;
}

import { AIProviderId } from '../types/ai';

export function providerLabel(providerId: AIProviderId, last4 = ''): string {
	const label = providerId === 'openrouter' ? 'OpenRouter' : providerId === 'openai' ? 'OpenAI' : providerId === 'claude' ? 'Claude' : 'Gemini';
	return last4 ? `${label} ${'*'.repeat(4)}${last4}` : label;
}

export function providerCredentialFallbackName(providerId: AIProviderId, last4: string): string {
	return `${providerLabel(providerId)} API key ••••${last4}`;
}

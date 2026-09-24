import { AIProviderCredential, AIProviderId } from '../../ai/types/ai';

export const providerOptions: Array<{ id: AIProviderId; name: string }> = [
	{ id: 'openrouter', name: 'OpenRouter' },
	{ id: 'openai', name: 'OpenAI' },
	{ id: 'claude', name: 'Claude' },
	{ id: 'gemini', name: 'Gemini' },
];

export function configuredProviderOptions(credentials: readonly AIProviderCredential[]): Array<{ id: AIProviderId; name: string }> {
	return providerOptions.filter((provider) => credentials.some((credential) => credential.providerId === provider.id));
}

export function providerName(providerId: AIProviderId): string {
	return providerOptions.find((provider) => provider.id === providerId)?.name ?? 'Provider';
}

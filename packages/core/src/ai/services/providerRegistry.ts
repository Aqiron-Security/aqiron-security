import { AIProvider, AIProviderId, AISettings, defaultAISettings } from '../../shared/ai';
import { CredentialService, aiSecretKeys } from './credentialService';

export class ProviderRegistry {
	private readonly providers = new Map<AIProviderId, AIProvider>();
	private currentProviderId: AIProviderId = defaultAISettings.selectedProvider;

	constructor(private readonly credentials: CredentialService) {}

	async initialize(): Promise<void> {
		const settings = await this.credentials.getJson<AISettings>(aiSecretKeys.settings, defaultAISettings);
		this.currentProviderId = settings.selectedProvider;
		await Promise.all([...this.providers.values()].map((provider) => provider.initialize()));
	}

	register(provider: AIProvider): void {
		this.providers.set(provider.id as AIProviderId, provider);
	}

	getProvider(id: AIProviderId): AIProvider {
		const provider = this.providers.get(id);
		if (!provider) {
			throw new Error(`AI provider is not registered: ${id}`);
		}
		return provider;
	}

	async switchProvider(id: AIProviderId): Promise<AIProvider> {
		const provider = this.getProvider(id);
		const settings = await this.credentials.getJson<AISettings>(aiSecretKeys.settings, defaultAISettings);
		await this.credentials.saveJson(aiSecretKeys.settings, { ...settings, selectedProvider: id });
		this.currentProviderId = id;
		await provider.initialize();
		return provider;
	}

	getCurrentProvider(): AIProvider {
		return this.getProvider(this.currentProviderId);
	}

	getProviders(): AIProvider[] {
		return [...this.providers.values()];
	}
}

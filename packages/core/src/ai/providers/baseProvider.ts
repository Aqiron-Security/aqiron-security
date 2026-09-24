import { AIProviderId } from '../../shared/ai';
import { AISettings, defaultAISettings } from '../../shared/ai';
import { CredentialService, aiSecretKeys } from '../services/credentialService';
import { AITransport } from '../utils/request';

export abstract class BaseProvider {
	abstract readonly id: AIProviderId;
	abstract readonly name: string;
	protected settings: AISettings = defaultAISettings;

	constructor(
		protected readonly credentials: CredentialService,
		protected readonly transport: AITransport,
	) {}

	async initialize(): Promise<void> {
		this.settings = await this.credentials.getJson(aiSecretKeys.settings, defaultAISettings);
	}

	protected async getSettings(): Promise<AISettings> {
		this.settings = await this.credentials.getJson(aiSecretKeys.settings, defaultAISettings);
		return this.settings;
	}

	protected normalizeBaseUrl(url: string): string {
		return url.trim().replace(/\/+$/, '');
	}

	protected async getAuthHeader(): Promise<string | undefined> {
		const key = await this.getApiKey();
		return key ? `Bearer ${key}` : undefined;
	}

	protected async getApiKey(): Promise<string | undefined> {
		const settings = await this.getSettings();
		const providerApis = settings.apiCredentials?.filter((api) => api.providerId === this.id) ?? [];
		const activeApi = providerApis.find((api) => api.id === settings.activeApiCredentialId) ?? providerApis[0];
		const key = activeApi
			? await this.credentials.getSecret(aiSecretKeys.apiCredential(activeApi.id))
			: this.id === 'openrouter'
				? await this.credentials.getSecret(aiSecretKeys.openRouterApiKey)
				: undefined;
		return key;
	}
}

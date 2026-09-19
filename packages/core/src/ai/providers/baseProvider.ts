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
		if (this.id === 'openrouter') {
			const settings = await this.getSettings();
			const activeApi = settings.apiCredentials?.find((api) => api.id === settings.activeApiCredentialId && api.providerId === 'openrouter');
			const key = activeApi ? await this.credentials.getSecret(aiSecretKeys.apiCredential(activeApi.id)) : await this.credentials.getSecret(aiSecretKeys.openRouterApiKey);
			return key ? `Bearer ${key}` : undefined;
		}
		const token = await this.credentials.getSecret(aiSecretKeys.ollamaAuthToken);
		return token ? `Bearer ${token}` : undefined;
	}
}

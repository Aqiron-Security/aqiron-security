import { CredentialStore } from '../../shared/platform';

export class CredentialService {
	constructor(private readonly store: CredentialStore) {}

	async saveSecret(key: string, value: string): Promise<void> {
		await this.store.set(key, value);
	}

	async getSecret(key: string): Promise<string | undefined> {
		return this.store.get(key);
	}

	async deleteSecret(key: string): Promise<void> {
		await this.store.delete(key);
	}

	async saveJson<T>(key: string, value: T): Promise<void> {
		await this.saveSecret(key, JSON.stringify(value));
	}

	async getJson<T>(key: string, fallback: T): Promise<T> {
		const raw = await this.getSecret(key);
		if (!raw) {
			return fallback;
		}
		try {
			return { ...fallback, ...JSON.parse(raw) as Partial<T> };
		} catch {
			return fallback;
		}
	}
}

export const aiSecretKeys = {
	settings: 'aqiron.ai.settings',
	openRouterApiKey: 'aqiron.ai.openrouter.apiKey',
	ollamaAuthToken: 'aqiron.ai.ollama.authToken',
	apiCredential: (id: string) => `aqiron.ai.api.${id}`,
};

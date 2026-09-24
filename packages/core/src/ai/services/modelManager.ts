import { AIModel, AIModelFilter, AIProviderId, AISettings, defaultAISettings, defaultModelFilter } from '../../shared/ai';
import { CredentialService, aiSecretKeys } from './credentialService';
import { ProviderRegistry } from './providerRegistry';
interface ModelCacheEntry {
	models: AIModel[];
	loadedAt: number;
}

export class ModelManager {
	private readonly cache = new Map<AIProviderId, ModelCacheEntry>();
	private filter: AIModelFilter = defaultModelFilter;
	private readonly cacheMs = 5 * 60 * 1000;

	constructor(
		private readonly registry: ProviderRegistry,
		private readonly credentials: CredentialService,
	) {}

	async getModels(providerId: AIProviderId, force = false): Promise<AIModel[]> {
		const cached = this.cache.get(providerId);
		if (!force && cached && Date.now() - cached.loadedAt < this.cacheMs) {
			return cached.models;
		}
		const provider = this.registry.getProvider(providerId);
		const models = await provider.getModels();
		this.cache.set(providerId, { models, loadedAt: Date.now() });
		return models;
	}

	clear(providerId?: AIProviderId): void {
		if (providerId) {
			this.cache.delete(providerId);
		} else {
			this.cache.clear();
		}
	}

	applyFilter(models: readonly AIModel[], filter = this.filter): AIModel[] {
		const query = filter.query.trim().toLowerCase();
		return models.filter((model) => {
			const haystack = `${model.id} ${model.label} ${model.description ?? ''} ${model.family ?? ''}`.toLowerCase();
			return (!query || haystack.includes(query))
				&& (!filter.freeOnly || model.badges.includes('free'))
				&& (!filter.codingOnly || model.badges.includes('coding'))
				&& (!filter.reasoningOnly || model.badges.includes('reasoning'))
				&& (!filter.visionOnly || model.badges.includes('vision'));
		});
	}

	setFilter(filter: Partial<AIModelFilter>): AIModelFilter {
		this.filter = { ...this.filter, ...filter };
		return this.filter;
	}

	getFilter(): AIModelFilter {
		return this.filter;
	}

	async selectModel(modelId: string): Promise<void> {
		const settings = await this.credentials.getJson<AISettings>(aiSecretKeys.settings, defaultAISettings);
		const recentModelIds = [modelId, ...(settings.recentModelIds ?? []).filter((id) => id !== modelId)].slice(0, 8);
		await this.credentials.saveJson(aiSecretKeys.settings, { ...settings, selectedModel: modelId, recentModelIds });
	}
}

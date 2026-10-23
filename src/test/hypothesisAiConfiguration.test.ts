import * as assert from 'node:assert/strict';
import { aiSecretKeys } from '../../packages/core/src/ai/services/credentialService';
import { hypothesisAiModelCapability, resolveHypothesisAiProviderConfiguration, sameHypothesisAiProviderConfiguration } from '../../packages/core/src/hypotheses/hypothesisAiConfiguration';
import { CredentialStore } from '../../packages/core/src/shared/platform';
import { defaultAISettings } from '../../packages/core/src/shared/ai';

suite('Hypothesis AI provider configuration binding', () => {
	test('model capability policy permits reviewed native formats and requires OpenRouter route enforcement', () => {
		assert.deepEqual(hypothesisAiModelCapability('openai', 'gpt-4o-mini'), { supported: true, responseMode: 'openai-json-object' });
		assert.equal(hypothesisAiModelCapability('openai', 'gpt-4o-mini-preview').supported, false);
		assert.equal(hypothesisAiModelCapability('claude', 'claude-opus-5-5').responseMode, 'anthropic-json-schema');
		assert.equal(hypothesisAiModelCapability('claude', 'claude-unknown').supported, false);
		assert.equal(hypothesisAiModelCapability('gemini', 'gemini-4-argon').supported, true);
		assert.equal(hypothesisAiModelCapability('gemini', 'gemini-unknown').supported, false);
		assert.deepEqual(hypothesisAiModelCapability('openrouter', 'vendor/model'), { supported: true, responseMode: 'openrouter-required-json-object' });
		assert.equal(hypothesisAiModelCapability('openrouter', '').supported, false);
	});
	test('unchanged configuration stays eligible; provider, model, endpoint, selection and credential rotation change identity', async () => {
		const state = configuredStore();
		const key = new Uint8Array(32).fill(7);
		const first = await resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openrouter', modelId: 'vendor/model-a', credentialVersionKey: key });
		const same = await resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openrouter', modelId: 'vendor/model-a', credentialVersionKey: key });
		assert.equal(sameHypothesisAiProviderConfiguration(same, first), true);
		state.values.set(aiSecretKeys.settings, JSON.stringify({ ...JSON.parse(state.values.get(aiSecretKeys.settings)!), selectedProvider: 'openai' }));
		assert.equal(sameHypothesisAiProviderConfiguration(await resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openrouter', modelId: 'vendor/model-a', credentialVersionKey: key }), first), false, 'global provider selection invalidates but never redirects the bound provider');
		state.values.set(aiSecretKeys.settings, JSON.stringify({ ...JSON.parse(state.values.get(aiSecretKeys.settings)!), selectedProvider: 'openrouter', selectedModel: 'vendor/model-b' }));
		assert.equal(sameHypothesisAiProviderConfiguration(await resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openrouter', modelId: 'vendor/model-a', credentialVersionKey: key }), first), false, 'global model selection invalidates but never redirects the bound model');
		state.values.set(aiSecretKeys.settings, JSON.stringify({ ...JSON.parse(state.values.get(aiSecretKeys.settings)!), selectedModel: 'vendor/model-a' }));
		assert.equal(sameHypothesisAiProviderConfiguration(await resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openai', modelId: 'vendor/model-a', credentialVersionKey: key }), first), false);
		assert.equal(sameHypothesisAiProviderConfiguration(await resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openrouter', modelId: 'vendor/model-b', credentialVersionKey: key }), first), false);
		state.values.set(aiSecretKeys.settings, JSON.stringify({ ...defaultAISettings, selectedProvider: 'openrouter', selectedModel: 'vendor/model-a', openRouterEndpoint: 'https://openrouter.ai/custom/v1', activeApiCredentialId: 'router-1', apiCredentials: [{ id: 'router-1', providerId: 'openrouter', name: 'Router', last4: '9876', createdAt: 'created', updatedAt: 'updated' }] }));
		assert.equal(sameHypothesisAiProviderConfiguration(await resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openrouter', modelId: 'vendor/model-a', credentialVersionKey: key }), first), false, 'endpoint changes invalidate');
		state.values.set(aiSecretKeys.settings, JSON.stringify({ ...defaultAISettings, selectedProvider: 'openrouter', selectedModel: 'vendor/model-a', openRouterEndpoint: 'https://openrouter.ai/api/v1', activeApiCredentialId: 'router-1', apiCredentials: [{ id: 'router-1', providerId: 'openrouter', name: 'Router', last4: '9876', createdAt: 'created', updatedAt: 'updated' }] }));
		state.values.set(aiSecretKeys.apiCredential('router-1'), 'rotated-fake-secret');
		assert.equal(sameHypothesisAiProviderConfiguration(await resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openrouter', modelId: 'vendor/model-a', credentialVersionKey: key }), first), false, 'credential rotation invalidates even if metadata is unchanged');
		const alteredOptions = { ...first, requestOptions: { ...first.requestOptions, timeoutMs: first.requestOptions.timeoutMs + 1 } };
		assert.equal(sameHypothesisAiProviderConfiguration(alteredOptions, first), false, 'request option changes invalidate');
	});

	test('missing credentials and unsafe endpoint config fail closed without leaking secrets', async () => {
		const state = configuredStore();
		const key = new Uint8Array(32).fill(3);
		state.values.set(aiSecretKeys.settings, JSON.stringify({ ...defaultAISettings, selectedProvider: 'openrouter', openRouterEndpoint: 'https://openrouter.ai/api/v1?access_token=do-not-leak', activeApiCredentialId: 'router-1', apiCredentials: [{ id: 'router-1', providerId: 'openrouter', name: 'Router', last4: '9876', createdAt: 'created', updatedAt: 'updated' }] }));
		let error: unknown;
		try {await resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openrouter', modelId: 'model', credentialVersionKey: key });} catch (caught) {error = caught;}
		assert.ok(error instanceof Error);
		assert.equal(error.message.includes('do-not-leak'), false);
		assert.equal(JSON.stringify(error).includes('fake-secret'), false);
		state.values.set(aiSecretKeys.settings, JSON.stringify({ ...defaultAISettings, selectedProvider: 'openrouter', openRouterEndpoint: 'https://attacker.example/v1', activeApiCredentialId: 'router-1', apiCredentials: [{ id: 'router-1', providerId: 'openrouter', name: 'Router', last4: '9876', createdAt: 'created', updatedAt: 'updated' }] }));
		await assert.rejects(resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openrouter', modelId: 'model', credentialVersionKey: key }), /endpoint configuration is invalid/);
		state.values.set(aiSecretKeys.settings, JSON.stringify({ ...defaultAISettings, selectedProvider: 'openrouter', openRouterEndpoint: 'https://openrouter.ai/api/v1', activeApiCredentialId: 'router-1', apiCredentials: [{ id: 'router-1', providerId: 'openrouter', name: 'Router', last4: '9876', createdAt: 'created', updatedAt: 'updated' }] }));
		state.values.delete(aiSecretKeys.apiCredential('router-1'));
		await assert.rejects(resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openrouter', modelId: 'model', credentialVersionKey: key }), /credential configuration is unavailable/);
	});

	test('snapshot and public disclosure fields contain destination details but no raw credential or HMAC', async () => {
		const state = configuredStore();
		const snapshot = await resolveHypothesisAiProviderConfiguration({ store: state.store, providerId: 'openrouter', modelId: 'vendor/model-a', credentialVersionKey: new Uint8Array(32).fill(1) });
		const serialized = JSON.stringify(snapshot);
		assert.match(snapshot.destination, /^https:\/\/openrouter\.ai\/api\/v1\/chat\/completions$/);
		assert.equal(serialized.includes('fake-provider-secret'), false);
		assert.equal(snapshot.credentialVersionTag.length, 64);
		assert.equal(serialized.includes(snapshot.credentialVersionTag), false, 'ephemeral credential HMAC is not serialized');
		assert.equal(snapshot.credentialLast4, '9876');
		assert.match(snapshot.destination, /openrouter\.ai/);
	});
});

function configuredStore(): { store: CredentialStore; values: Map<string, string> } {
	const values = new Map<string, string>([
		[aiSecretKeys.settings, JSON.stringify({ ...defaultAISettings, selectedProvider: 'openrouter', selectedModel: 'vendor/model-a', openRouterEndpoint: 'https://openrouter.ai/api/v1', activeApiCredentialId: 'router-1', apiCredentials: [{ id: 'router-1', providerId: 'openrouter', name: 'Router', last4: '9876', createdAt: 'created', updatedAt: 'updated' }] })],
		[aiSecretKeys.apiCredential('router-1'), 'fake-provider-secret'],
		[aiSecretKeys.apiCredential('openai-1'), 'fake-openai-secret'],
	]);
	const parsed = JSON.parse(values.get(aiSecretKeys.settings)!) as Record<string, unknown>;
	parsed.apiCredentials = [...parsed.apiCredentials as unknown[], { id: 'openai-1', providerId: 'openai', name: 'OpenAI', last4: '4321', createdAt: 'created', updatedAt: 'updated' }];
	values.set(aiSecretKeys.settings, JSON.stringify(parsed));
	return { values, store: { get: async key => values.get(key), set: async (key, value) => {values.set(key, value);}, delete: async key => {values.delete(key);} } };
}

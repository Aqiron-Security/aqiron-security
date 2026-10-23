import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { aiSecretKeys } from '../../packages/core/src/ai/services/credentialService';
import { AITransport } from '../../packages/core/src/ai/utils/request';
import { buildHypothesisAiBoundRequest, resolveHypothesisAiProviderConfiguration, sendHypothesisAiBoundRequest } from '../../packages/core/src/hypotheses/hypothesisAiConfiguration';
import { CredentialStore } from '../../packages/core/src/shared/platform';
import { AIProviderId, defaultAISettings } from '../../packages/core/src/shared/ai';

suite('Hypothesis AI immutable request plan', () => {
	test('provider-specific request plans preserve the prepared model, destination, content and bounded options', async () => {
		for (const providerId of ['openai', 'claude', 'gemini', 'openrouter'] as AIProviderId[]) {
			const fixture = storeFor(providerId);
			const key = new Uint8Array(32).fill(9);
			const modelId = 'selected-model';
			const canonicalEnvelope = JSON.stringify({ providerId, modelId, content: { purpose: 'purpose', instructions: 'instructions', evidence: [{ alias: 'e1', kind: 'finding', summary: 'exact selected evidence' }] } });
			const initial = await resolveHypothesisAiProviderConfiguration({ store: fixture.store, providerId, modelId, credentialVersionKey: key });
			const expiresAt = new Date(Date.now() + 30_000).toISOString();
			const captured = { ...initial, preparationId: 'preparation-1', expiresAt, outboundContentFingerprint: crypto.createHash('sha256').update(canonicalEnvelope).digest('hex') };
			Object.defineProperty(captured, 'credentialVersionTag', { value: initial.credentialVersionTag, enumerable: false });
			const secretReadsBeforePlan = fixture.secretReads;
			const execution = await buildHypothesisAiBoundRequest({ store: fixture.store, providerConfiguration: captured, preparationId: 'preparation-1', expiresAt, canonicalEnvelope, credentialVersionKey: key });
			assert.equal(fixture.secretReads - secretReadsBeforePlan, 1, 'plan resolution reads one credential and uses that same value for verification and auth construction');
			assert.equal(execution.plan.destination, captured.destination);
			assert.equal(execution.plan.modelId, modelId);
			assert.equal(execution.plan.preparationId, 'preparation-1');
			assert.equal(execution.plan.contentFingerprint, captured.outboundContentFingerprint);
			assert.equal(initial.responseMode, providerId === 'openai' ? 'openai-json-object' : providerId === 'openrouter' ? 'openrouter-required-json-object' : providerId === 'claude' ? 'anthropic-json-schema' : 'gemini-json-mime');
			assert.equal(execution.plan.requestBodyFingerprint, crypto.createHash('sha256').update(execution.plan.body, 'utf8').digest('hex'));
			assert.equal(Object.isFrozen(execution.plan), true);
			assert.equal(JSON.stringify(execution).includes('fake-secret-value'), false);
			assert.equal(JSON.stringify(execution.plan).includes(execution.authentication.headerValue), false);
			const body = JSON.parse(execution.plan.body) as Record<string, unknown>;
			assert.equal(JSON.stringify(body).includes('exact selected evidence'), true);
			assert.equal(JSON.stringify(body).includes('fake-secret-value'), false);
			if (providerId === 'openai' || providerId === 'openrouter' || providerId === 'claude') {
				assert.equal(body.model, modelId);
				assert.equal(body.stream, false);
				if (providerId === 'openrouter') { assert.deepEqual(body.response_format, { type: 'json_object' }); assert.deepEqual(body.provider, { require_parameters: true }); }
				if (providerId === 'openai') { assert.deepEqual(body.response_format, { type: 'json_object' }); }
				if (providerId === 'claude') { assert.deepEqual((body.output_config as Record<string, any>).format.type, 'json_schema'); assert.equal((body.output_config as Record<string, any>).format.schema.additionalProperties, false); }
			} else {
				assert.equal(execution.plan.destination, `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(modelId)}:generateContent`);
				assert.equal((body.generationConfig as Record<string, unknown>).responseMimeType, 'application/json');
			}
		}
	});

	test('transport receives the exact plan URL, method, headers, body bytes and limits', async () => {
		const fixture = storeFor('openrouter');
		const key = new Uint8Array(32).fill(2);
		const providerId = 'openrouter';
		const modelId = 'vendor/model';
		const canonicalEnvelope = JSON.stringify({ providerId, modelId, content: { purpose: 'p', instructions: 'i', evidence: [] } });
		const initial = await resolveHypothesisAiProviderConfiguration({ store: fixture.store, providerId, modelId, credentialVersionKey: key });
		const expiresAt = new Date(Date.now() + 30_000).toISOString();
		const captured = { ...initial, preparationId: 'prep', expiresAt, outboundContentFingerprint: crypto.createHash('sha256').update(canonicalEnvelope).digest('hex') };
		Object.defineProperty(captured, 'credentialVersionTag', { value: initial.credentialVersionTag, enumerable: false });
		const execution = await buildHypothesisAiBoundRequest({ store: fixture.store, providerConfiguration: captured, preparationId: 'prep', expiresAt, canonicalEnvelope, credentialVersionKey: key });
		let observed: { url: string; options: Parameters<AITransport['request']>[1] } | undefined;
		const transport: AITransport = { request: async (url, options) => {
			observed = { url, options };
			return { ok: true, status: 200, headers: {}, text: async () => '', json: async <T>() => ({} as T), body: null };
		} };
		await sendHypothesisAiBoundRequest(transport, execution);
		assert.equal(observed?.url, execution.plan.destination);
		assert.equal(observed?.options.method, execution.plan.method);
		assert.equal(observed?.options.serializedBody, execution.plan.body);
		assert.equal(crypto.createHash('sha256').update(observed?.options.serializedBody ?? '', 'utf8').digest('hex'), execution.plan.requestBodyFingerprint);
		assert.equal(observed?.options.headers?.Authorization, `Bearer ${fixture.secret}`);
		assert.equal(observed?.options.timeoutMs, execution.plan.requestOptions.timeoutMs);
		assert.equal(observed?.options.maxRequestBodyBytes, execution.plan.requestOptions.maxRequestBodyBytes);
		assert.equal(observed?.options.maxResponseBodyBytes, execution.plan.requestOptions.maxResponseBodyBytes);
	});

	test('stale credentials/config, malformed envelope and expired plans reject before transport', async () => {
		const fixture = storeFor('openrouter');
		const key = new Uint8Array(32).fill(4);
		const providerId = 'openrouter';
		const modelId = 'model';
		const canonicalEnvelope = JSON.stringify({ providerId, modelId, content: { purpose: 'p', instructions: 'i', evidence: [] } });
		const initial = await resolveHypothesisAiProviderConfiguration({ store: fixture.store, providerId, modelId, credentialVersionKey: key });
		const expiresAt = new Date(Date.now() + 30_000).toISOString();
		const captured = { ...initial, preparationId: 'prep', expiresAt, outboundContentFingerprint: crypto.createHash('sha256').update(canonicalEnvelope).digest('hex') };
		Object.defineProperty(captured, 'credentialVersionTag', { value: initial.credentialVersionTag, enumerable: false });
		fixture.values.set(aiSecretKeys.settings, JSON.stringify({ ...JSON.parse(fixture.values.get(aiSecretKeys.settings)!), openRouterEndpoint: 'https://openrouter.ai/changed/v1' }));
		await assert.rejects(buildHypothesisAiBoundRequest({ store: fixture.store, providerConfiguration: captured, preparationId: 'prep', expiresAt, canonicalEnvelope, credentialVersionKey: key }), /stale/);
		await assert.rejects(buildHypothesisAiBoundRequest({ store: fixture.store, providerConfiguration: captured, preparationId: 'prep', expiresAt: new Date(Date.now() - 1).toISOString(), canonicalEnvelope, credentialVersionKey: key }), /unavailable/);
	});

	test('ambiguous credentials fail closed before plan construction', async () => {
		const fixture = storeFor('openai');
		const settings = JSON.parse(fixture.values.get(aiSecretKeys.settings)!) as Record<string, any>;
		settings.activeApiCredentialId = undefined;
		settings.apiCredentials.push({ id: 'second', providerId: 'openai', name: 'Second', last4: '2222', createdAt: 'created', updatedAt: 'updated' });
		fixture.values.set(aiSecretKeys.settings, JSON.stringify(settings));
		await assert.rejects(resolveHypothesisAiProviderConfiguration({ store: fixture.store, providerId: 'openai', modelId: 'model', credentialVersionKey: new Uint8Array(32).fill(5) }), /ambiguous/);
	});
});

function storeFor(providerId: AIProviderId): { store: CredentialStore; values: Map<string, string>; secret: string; secretReads: number } {
	const secret = 'fake-secret-value';
	const id = `credential-${providerId}`;
	const values = new Map<string, string>([
		[aiSecretKeys.settings, JSON.stringify({ ...defaultAISettings, selectedProvider: providerId, selectedModel: 'selected-model', openRouterEndpoint: 'https://openrouter.ai/api/v1', activeApiCredentialId: id, apiCredentials: [{ id, providerId, name: 'Fake credential', last4: '4321', createdAt: 'created', updatedAt: 'updated' }] })],
		[aiSecretKeys.apiCredential(id), secret],
	]);
	const fixture = { values, secret, secretReads: 0, store: undefined as unknown as CredentialStore };
	fixture.store = { get: async key => {if (key === aiSecretKeys.apiCredential(id)) {fixture.secretReads += 1;} return values.get(key);}, set: async (key, value) => {values.set(key, value);}, delete: async key => {values.delete(key);} };
	return fixture;
}

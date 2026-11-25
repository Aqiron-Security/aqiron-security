import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { aiSecretKeys } from '../../packages/core/src/ai/services/credentialService';
import { AITransport } from '../../packages/core/src/ai/utils/request';
import { buildHypothesisAiBoundRequest, createHypothesisAiBoundRequestPlan, hypothesisAiRequestSemanticsFingerprint, HypothesisAiProviderConfigurationSnapshot, resolveHypothesisAiProviderConfiguration, sendHypothesisAiBoundRequest } from '../../packages/core/src/hypotheses/hypothesisAiConfiguration';
import { CredentialStore } from '../../packages/core/src/shared/platform';
import { AIProviderId, defaultAISettings } from '../../packages/core/src/shared/ai';
import { createHypothesisAiExecutor } from '../../packages/core/src/hypotheses/hypothesisAiExecutor';
import { createHypothesisAiRequestContext } from '../../packages/core/src/hypotheses/aiProposalValidation';
import { HypothesisEvidenceRef, HypothesisSnapshot } from '../../packages/core/src/hypotheses/contracts';
import { HypothesisStoreService } from '../../packages/core/src/hypotheses/hypothesisStore';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';

suite('Hypothesis AI immutable request plan', () => {
	test('provider-specific request plans preserve the prepared model, destination, content and bounded options', async () => {
		for (const providerId of ['openai', 'claude', 'gemini', 'openrouter'] as AIProviderId[]) {
			const fixture = storeFor(providerId);
			const key = new Uint8Array(32).fill(9);
			const modelId = providerId === 'openai' ? 'gpt-4o-mini' : providerId === 'claude' ? 'claude-opus-5-5' : providerId === 'gemini' ? 'gemini-4-argon' : 'vendor/model';
			const canonicalEnvelope = JSON.stringify({ providerId, modelId, content: { purpose: 'purpose', instructions: 'instructions', evidence: [{ alias: 'e1', kind: 'finding', summary: 'exact selected evidence' }] } });
			const initial = await resolveHypothesisAiProviderConfiguration({ store: fixture.store, providerId, modelId, credentialVersionKey: key });
			const expiresAt = new Date(Date.now() + 30_000).toISOString();
			const captured = captureRequest(initial, 'preparation-1', expiresAt, canonicalEnvelope);
			const secretReadsBeforePlan = fixture.secretReads;
			const execution = await buildHypothesisAiBoundRequest({ store: fixture.store, providerConfiguration: captured, preparationId: 'preparation-1', expiresAt, canonicalEnvelope, credentialVersionKey: key });
			assert.equal(fixture.secretReads - secretReadsBeforePlan, 1, 'plan resolution reads one credential and uses that same value for verification and auth construction');
			assert.equal(execution.plan.destination, captured.destination);
			assert.equal(execution.plan.modelId, modelId);
			assert.equal(execution.plan.preparationId, 'preparation-1');
			assert.equal(execution.plan.contentFingerprint, captured.outboundContentFingerprint);
			assert.equal(initial.responseMode, providerId === 'openai' ? 'openai-json-object' : providerId === 'openrouter' ? 'openrouter-required-json-object' : providerId === 'claude' ? 'anthropic-json-schema' : 'gemini-json-mime');
			assert.equal(execution.plan.requestBodyFingerprint, crypto.createHash('sha256').update(execution.plan.body, 'utf8').digest('hex'));
			assert.equal(execution.plan.requestSemanticsFingerprint, hypothesisAiRequestSemanticsFingerprint(execution.plan));
			assert.equal(execution.plan.authenticationHeaderName, execution.authentication.headerName);
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

	test('approved request digest covers routing, provider response schema, exact content and generation semantics', async () => {
		const fixture = storeFor('claude');
		const key = new Uint8Array(32).fill(6);
		const providerId = 'claude';
		const modelId = 'claude-opus-5-5';
		const canonicalEnvelope = JSON.stringify({ providerId, modelId, content: { purpose: 'p', instructions: 'i', evidence: [{ alias: 'e1', kind: 'finding', summary: 'synthetic evidence' }] } });
		const initial = await resolveHypothesisAiProviderConfiguration({ store: fixture.store, providerId, modelId, credentialVersionKey: key });
		const expiresAt = new Date(Date.now() + 30_000).toISOString();
		const captured = captureRequest(initial, 'prep-digest', expiresAt, canonicalEnvelope);
		const execution = await buildHypothesisAiBoundRequest({ store: fixture.store, providerConfiguration: captured, preparationId: 'prep-digest', expiresAt, canonicalEnvelope, credentialVersionKey: key });
		assert.equal(execution.plan.responseMode, 'anthropic-json-schema');
		assert.equal(execution.plan.body.includes('falsificationCriteria'), true, 'the concrete structured response schema is included in the request body digest');
		assert.equal(JSON.stringify(execution.plan).includes(fixture.secret), false);
		const altered = { ...execution.plan, modelId: 'changed-model' };
		assert.notEqual(hypothesisAiRequestSemanticsFingerprint(altered), execution.plan.requestSemanticsFingerprint);
		const schemaAltered = { ...execution.plan, body: execution.plan.body.replace('"additionalProperties":false', '"additionalProperties":true') };
		assert.notEqual(hypothesisAiRequestSemanticsFingerprint(schemaAltered), execution.plan.requestSemanticsFingerprint, 'response-schema changes alter the approved digest');
		const optionsAltered = { ...execution.plan, requestOptions: { ...execution.plan.requestOptions, timeoutMs: execution.plan.requestOptions.timeoutMs + 1 } };
		assert.notEqual(hypothesisAiRequestSemanticsFingerprint(optionsAltered), execution.plan.requestSemanticsFingerprint, 'generation/transport option changes alter the approved digest');
		let transportCalls = 0;
		const transport: AITransport = { request: async () => {transportCalls += 1; return { ok: true, status: 200, headers: {}, text: async () => '', json: async <T>() => ({} as T), body: null };} };
		await assert.rejects(sendHypothesisAiBoundRequest(transport, { plan: altered, authentication: execution.authentication }), /plan is invalid/);
		assert.equal(transportCalls, 0, 'tampered approved request semantics fail before transport');
	});

	test('missing request digest or changed credential reference fails closed before transport planning', async () => {
		const fixture = storeFor('openrouter');
		const key = new Uint8Array(32).fill(8);
		const canonicalEnvelope = JSON.stringify({ providerId: 'openrouter', modelId: 'model', content: { purpose: 'p', instructions: 'i', evidence: [] } });
		const initial = await resolveHypothesisAiProviderConfiguration({ store: fixture.store, providerId: 'openrouter', modelId: 'model', credentialVersionKey: key });
		const expiresAt = new Date(Date.now() + 30_000).toISOString();
		const captured = captureRequest(initial, 'prep-reference', expiresAt, canonicalEnvelope);
		const unbound = { ...captured, requestSemanticsFingerprint: undefined };
		await assert.rejects(buildHypothesisAiBoundRequest({ store: fixture.store, providerConfiguration: unbound, preparationId: 'prep-reference', expiresAt, canonicalEnvelope, credentialVersionKey: key }), /unavailable/);
		const settings = JSON.parse(fixture.values.get(aiSecretKeys.settings)!) as Record<string, any>;
		settings.apiCredentials.push({ id: 'replacement', providerId: 'openrouter', name: 'Replacement', last4: '1111', createdAt: 'created', updatedAt: 'updated' });
		settings.activeApiCredentialId = 'replacement';
		fixture.values.set(aiSecretKeys.settings, JSON.stringify(settings));
		fixture.values.set(aiSecretKeys.apiCredential('replacement'), 'replacement-secret');
		await assert.rejects(buildHypothesisAiBoundRequest({ store: fixture.store, providerConfiguration: captured, preparationId: 'prep-reference', expiresAt, canonicalEnvelope, credentialVersionKey: key }), /stale/);
	});

	test('transport receives the exact plan URL, method, headers, body bytes and limits', async () => {
		const fixture = storeFor('openrouter');
		const key = new Uint8Array(32).fill(2);
		const providerId = 'openrouter';
		const modelId = 'vendor/model';
		const canonicalEnvelope = JSON.stringify({ providerId, modelId, content: { purpose: 'p', instructions: 'i', evidence: [] } });
		const initial = await resolveHypothesisAiProviderConfiguration({ store: fixture.store, providerId, modelId, credentialVersionKey: key });
		const expiresAt = new Date(Date.now() + 30_000).toISOString();
		const captured = captureRequest(initial, 'prep', expiresAt, canonicalEnvelope);
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
		const captured = captureRequest(initial, 'prep', expiresAt, canonicalEnvelope);
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

	test('executor diagnostics distinguish preflight, request construction, transport, validation, and unexpected failures without error text', async () => {
		const fixture = storeFor('openrouter');
		const key = new Uint8Array(32).fill(7);
		const providerId = 'openrouter';
		const modelId = 'vendor/model';
		const preparationId = 'diagnostic-preparation';
		const expiresAt = new Date(Date.now() + 30_000).toISOString();
		const evidence: HypothesisEvidenceRef = { id: 'finding:diagnostic', kind: 'finding', source: 'synthetic rule', findingId: 'diagnostic', ruleId: 'rule.diagnostic', observedAt: new Date().toISOString(), freshness: 'current' };
		const snapshot = { id: 'snapshot:diagnostic', workspaceRoot: 'C:/synthetic', scanId: 'scan:diagnostic', capturedAt: evidence.observedAt, fingerprint: 'a'.repeat(64), profile: {}, evidence: [evidence], findings: [{ id: 'diagnostic', ruleId: 'rule.diagnostic' }], relationships: [] } as unknown as HypothesisSnapshot;
		const context = createHypothesisAiRequestContext(snapshot, undefined, { providerId, preparationId, expiresAt });
		const envelope = JSON.stringify({ providerId, modelId, content: { purpose: 'test', instructions: 'test', evidence: [{ alias: 'e1', kind: 'finding', summary: 'synthetic evidence' }] } });
		const initial = await resolveHypothesisAiProviderConfiguration({ store: fixture.store, providerId, modelId, credentialVersionKey: key });
		const captured = captureRequest(initial, preparationId, expiresAt, envelope);
		const executionRequest = await buildHypothesisAiBoundRequest({ store: fixture.store, providerConfiguration: captured, preparationId, expiresAt, canonicalEnvelope: envelope, credentialVersionKey: key });
		const store = new HypothesisStoreService(createNodeFileSystem());
		const validModelJson = JSON.stringify({ schemaVersion: 1, proposals: [{ title: 'Review access control', claim: 'Could this route lack authorization?', evidenceRationale: 'The synthetic finding identifies a route.', supportingEvidenceAliases: ['e1'], contradictoryEvidenceAliases: [], verificationCriteria: ['Inspect the route guard.'], falsificationCriteria: ['Confirm the route rejects unauthenticated access.'], uncertainties: ['Runtime configuration is unknown.'] }] });
		const responseFor = (text: string) => ({ ok: true, status: 200, headers: { 'content-type': 'application/json' }, text: async () => text, json: async <T>() => JSON.parse(text) as T, body: null });
		const run = async (transport: AITransport, request = executionRequest) => {
			const diagnostics: Array<Record<string, unknown>> = [];
			const executor = createHypothesisAiExecutor(transport, store, (event) => diagnostics.push(event as unknown as Record<string, unknown>));
			let error: unknown;
			try {await executor(envelope, new AbortController().signal, request, undefined, context);} catch (caught) {error = caught;}
			return { diagnostics, error };
		};

		const preflightEvents: Array<Record<string, unknown>> = [];
		const preflight = createHypothesisAiExecutor({ request: async () => {throw new Error('must not reach transport');} }, store, (event) => preflightEvents.push(event as unknown as Record<string, unknown>));
		await assert.rejects(preflight(envelope, new AbortController().signal, undefined, undefined, context));
		assert.deepEqual(preflightEvents[0], { stage: 'executor-preflight', outcome: 'failed', failureCategory: 'executor-preflight-failed', transportInvoked: false, transportResponseReceived: false, providerResponseValidated: false, persistenceAttempted: false });

		let constructionTransportCalls = 0;
		const tampered = { ...executionRequest, plan: { ...executionRequest.plan, body: `${executionRequest.plan.body} ` } };
		const construction = await run({ request: async () => {constructionTransportCalls += 1; return responseFor(validModelJson);} }, tampered);
		assert.equal(constructionTransportCalls, 0);
		assert.equal(construction.diagnostics[0]?.stage, 'request-construction');
		assert.equal(construction.diagnostics[0]?.failureCategory, 'request-construction-failed');
		assert.equal(construction.diagnostics[0]?.transportInvoked, false);

		const marker = 'private transport exception marker';
		const transportFailure = await run({ request: async () => {throw new Error(marker);} });
		assert.equal(transportFailure.diagnostics[0]?.stage, 'transport');
		assert.equal(transportFailure.diagnostics[0]?.failureCategory, 'transport-failed');
		assert.equal(transportFailure.diagnostics[0]?.transportInvoked, true, 'adapter invocation does not assert server receipt');
		assert.equal(transportFailure.diagnostics[0]?.transportResponseReceived, false);
		assert.equal(JSON.stringify(transportFailure.diagnostics).includes(marker), false);
		assert.equal(JSON.stringify(transportFailure.error).includes(marker), false);

		const invalidResponse = await run({ request: async () => responseFor('{ malformed response text') });
		assert.equal(invalidResponse.diagnostics[0]?.stage, 'response-validation');
		assert.equal(invalidResponse.diagnostics[0]?.failureCategory, 'response-validation-failed');
		assert.equal(invalidResponse.diagnostics[0]?.transportInvoked, true);
		assert.equal(invalidResponse.diagnostics[0]?.transportResponseReceived, true);
		assert.equal(invalidResponse.diagnostics[0]?.providerResponseValidated, false);

		const hostileRequest = Object.defineProperty({}, 'plan', { get() {throw new Error(marker);} }) as typeof executionRequest;
		const unexpectedEvents: Array<Record<string, unknown>> = [];
		const unexpectedExecutor = createHypothesisAiExecutor({ request: async () => {throw new Error('must not reach transport');} }, store, (event) => unexpectedEvents.push(event as unknown as Record<string, unknown>));
		await assert.rejects(unexpectedExecutor(envelope, new AbortController().signal, hostileRequest, undefined, context));
		assert.equal(unexpectedEvents[0]?.stage, 'unknown');
		assert.equal(unexpectedEvents[0]?.failureCategory, 'unexpected-executor-failure');
		assert.equal(JSON.stringify(unexpectedEvents).includes(marker), false);
	});
});

function captureRequest(initial: HypothesisAiProviderConfigurationSnapshot, preparationId: string, expiresAt: string, canonicalEnvelope: string): HypothesisAiProviderConfigurationSnapshot {
	const captured: HypothesisAiProviderConfigurationSnapshot = {
		...initial, preparationId, expiresAt,
		outboundContentFingerprint: crypto.createHash('sha256').update(canonicalEnvelope).digest('hex'),
	};
	Object.defineProperty(captured, 'credentialVersionTag', { value: initial.credentialVersionTag, enumerable: false });
	captured.requestSemanticsFingerprint = createHypothesisAiBoundRequestPlan({ providerConfiguration: captured, preparationId, expiresAt, canonicalEnvelope }).requestSemanticsFingerprint;
	return captured;
}

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

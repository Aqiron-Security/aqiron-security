import * as crypto from 'node:crypto';
import { AIProviderId, AISettings, defaultAISettings } from '../shared/ai';
import { CredentialStore } from '../shared/platform';
import { aiSecretKeys } from '../ai/services/credentialService';
import { HYPOTHESIS_AI_ADAPTER_LIMITS } from './hypothesisAiAdapter';
import { AITransport } from '../ai/utils/request';

export interface HypothesisAiRequestOptionsSnapshot {
	temperature: 0;
	maxTokens: 2048;
	timeoutMs: number;
	retries: 0;
	streaming: false;
	maxRequestBodyBytes: number;
	maxResponseBodyBytes: number;
}

/** The response-format capability is retained and never degrades to prompt-only JSON. */
export type HypothesisAiResponseMode = 'openai-json-object' | 'openrouter-required-json-object' | 'anthropic-json-schema' | 'gemini-json-mime';

/** Bump whenever the offline model/response-mode acceptance policy changes. */
export const HYPOTHESIS_AI_CAPABILITY_POLICY_VERSION = 'hypothesis-ai-capabilities-v1';

/** Offline preparation allowlist. Unknown native model IDs are rejected; OpenRouter requires router-enforced parameter support in its frozen body. */
export function hypothesisAiModelCapability(providerId: AIProviderId, modelId: string): { supported: boolean; responseMode: HypothesisAiResponseMode; reason?: string } {
	const exactModels: Partial<Record<AIProviderId, readonly string[]>> = {
		openai: ['gpt-4o', 'gpt-4o-mini', 'gpt-4o-2024-08-06', 'gpt-4o-mini-2024-07-18'],
		claude: ['claude-opus-5-5'],
		gemini: ['gemini-4-argon', 'gemini-3.8-flash'],
	};
	const responseMode = responseModeFor(providerId);
	if (providerId === 'openrouter') {
		return modelId.trim() ? { supported: true, responseMode } : { supported: false, responseMode, reason: 'A concrete routed model ID is required.' };
	}
	const supported = (exactModels[providerId] ?? []).includes(modelId);
	return supported ? { supported, responseMode } : { supported, responseMode, reason: 'This model is not in the reviewed structured-response allowlist.' };
}

/** Core-private plan. `credentialVersionTag` is an ephemeral keyed HMAC and must never be serialized or disclosed. */
export interface HypothesisAiProviderConfigurationSnapshot {
	providerId: AIProviderId;
	modelId: string;
	requestPlanVersion: 1;
	capabilityPolicyVersion: string;
	destination: string;
	credentialIdentity: string;
	credentialName: string;
	credentialLast4: string;
	credentialUpdatedAt: string;
	credentialVersionTag: string;
	configuredSelection: { providerId: AIProviderId; modelId: string };
	requestOptions: HypothesisAiRequestOptionsSnapshot;
	responseMode: HypothesisAiResponseMode;
	configurationFingerprint: string;
	preparationId?: string;
	expiresAt?: string;
	outboundContentFingerprint?: string;
}

/** Public request metadata. Authentication is deliberately a separate, short-lived value. */
export interface HypothesisAiBoundRequestPlan {
	readonly planVersion: 1;
	readonly preparationId: string;
	readonly expiresAt: string;
	readonly providerId: AIProviderId;
	readonly modelId: string;
	readonly destination: string;
	readonly method: 'POST';
	readonly headers: Readonly<Record<string, string>>;
	readonly body: string;
	readonly contentFingerprint: string;
	readonly requestBodyFingerprint: string;
	readonly configurationFingerprint: string;
	readonly requestOptions: Readonly<HypothesisAiRequestOptionsSnapshot>;
}

export interface HypothesisAiBoundExecutionRequest {
	readonly plan: HypothesisAiBoundRequestPlan;
	/** Secret auth value is not part of plan, JSON serialization, or diagnostics. */
	authentication: { headerName: string; headerValue: string };
}

const PROVIDER_DESTINATIONS: Record<Exclude<AIProviderId, 'openrouter'>, string> = {
	openai: 'https://api.openai.com/v1/chat/completions',
	claude: 'https://api.anthropic.com/v1/messages',
	gemini: 'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent',
};

export async function resolveHypothesisAiProviderConfiguration(input: {
	store: CredentialStore;
	providerId: AIProviderId;
	modelId: string;
	credentialVersionKey: Uint8Array;
}): Promise<HypothesisAiProviderConfigurationSnapshot> {
	return (await resolveConfigurationAndCredential(input)).snapshot;
}

async function resolveConfigurationAndCredential(input: {
	store: CredentialStore;
	providerId: AIProviderId;
	modelId: string;
	credentialVersionKey: Uint8Array;
}): Promise<{ snapshot: HypothesisAiProviderConfigurationSnapshot; secret: string }> {
	let settings: AISettings;
	try {
		const raw = await input.store.get(aiSecretKeys.settings);
		if (!raw) {throw new Error('missing-settings');}
		const parsed: unknown = JSON.parse(raw);
		if (!isRecord(parsed)) {throw new Error('invalid-settings');}
		settings = { ...defaultAISettings, ...parsed } as AISettings;
	} catch {
		throw new Error('Hypothesis synthesis provider configuration is unavailable.');
	}
	const providerAccounts = (Array.isArray(settings.apiCredentials) ? settings.apiCredentials : []).filter(account => isRecord(account) && account.providerId === input.providerId);
	if (new Set(providerAccounts.map(account => account.id).filter(id => typeof id === 'string')).size !== providerAccounts.length) {throw new Error('Hypothesis synthesis credential configuration is ambiguous.');}
	const explicitlySelectedAccount = providerAccounts.find(account => account.id === settings.activeApiCredentialId);
	if (providerAccounts.length > 1 && !explicitlySelectedAccount) {throw new Error('Hypothesis synthesis credential configuration is ambiguous.');}
	const selectedAccount = explicitlySelectedAccount ?? providerAccounts[0];
	let secret: string | undefined;
	let credentialIdentity: string;
	let credentialName: string;
	let credentialLast4: string;
	let credentialUpdatedAt: string;
	try {
		if (selectedAccount && typeof selectedAccount.id === 'string' && selectedAccount.id.length > 0) {
			credentialIdentity = `api-credential:${selectedAccount.id}`;
			credentialName = safeLabel(selectedAccount.name, input.providerId);
			credentialLast4 = typeof selectedAccount.last4 === 'string' ? selectedAccount.last4.slice(-4) : '';
			credentialUpdatedAt = typeof selectedAccount.updatedAt === 'string' ? selectedAccount.updatedAt : '';
			secret = await input.store.get(aiSecretKeys.apiCredential(selectedAccount.id));
		} else if (input.providerId === 'openrouter') {
			credentialIdentity = 'legacy-openrouter-credential';
			credentialName = 'OpenRouter API key';
			credentialUpdatedAt = '';
			secret = await input.store.get(aiSecretKeys.openRouterApiKey);
			credentialLast4 = secret ? secret.slice(-4) : '';
		} else {
			throw new Error('missing-credential-identity');
		}
	} catch {
		throw new Error('Hypothesis synthesis credential configuration is unavailable.');
	}
	if (typeof secret !== 'string' || secret.length === 0) {throw new Error('Hypothesis synthesis credential configuration is unavailable.');}
	const destination = resolveDestination(input.providerId, settings.openRouterEndpoint, input.modelId);
	const requestOptions: HypothesisAiRequestOptionsSnapshot = {
		temperature: 0, maxTokens: 2048,
		timeoutMs: HYPOTHESIS_AI_ADAPTER_LIMITS.defaultTimeoutMs,
		retries: 0, streaming: false,
		maxRequestBodyBytes: HYPOTHESIS_AI_ADAPTER_LIMITS.maxRequestBytes,
		maxResponseBodyBytes: HYPOTHESIS_AI_ADAPTER_LIMITS.maxResponseBytes,
	};
	const nonSecret = {
		version: 1, requestPlanVersion: 1 as const, capabilityPolicyVersion: HYPOTHESIS_AI_CAPABILITY_POLICY_VERSION, providerId: input.providerId, modelId: input.modelId, destination,
		// Selection is an invalidation marker only. The request remains pinned to
		// the explicit provider/model above and is never rerouted by this setting.
		configuredSelection: { providerId: settings.selectedProvider, modelId: settings.selectedModel ?? '' },
		credentialIdentity, credentialName, credentialLast4, credentialUpdatedAt,
		requestOptions,
		responseMode: responseModeFor(input.providerId),
	};
	const snapshot: HypothesisAiProviderConfigurationSnapshot = {
		...nonSecret,
		configuredSelection: nonSecret.configuredSelection,
		configurationFingerprint: crypto.createHash('sha256').update(JSON.stringify(nonSecret), 'utf8').digest('hex'),
		credentialVersionTag: '',
	};
	Object.defineProperty(snapshot, 'credentialVersionTag', { value: crypto.createHmac('sha256', input.credentialVersionKey).update(secret, 'utf8').digest('hex'), enumerable: false, writable: false });
	return { snapshot, secret };
}

/** Resolve once, compare that exact credential/configuration, and bind its same credential value to the request. */
export async function buildHypothesisAiBoundRequest(input: {
	store: CredentialStore;
	providerConfiguration: HypothesisAiProviderConfigurationSnapshot;
	preparationId: string;
	expiresAt: string;
	canonicalEnvelope: string;
	credentialVersionKey: Uint8Array;
}): Promise<HypothesisAiBoundExecutionRequest> {
	if (!input.preparationId || !Number.isFinite(Date.parse(input.expiresAt)) || Date.parse(input.expiresAt) <= Date.now()
		|| input.providerConfiguration.preparationId !== input.preparationId
		|| input.providerConfiguration.expiresAt !== input.expiresAt
		|| input.providerConfiguration.outboundContentFingerprint !== crypto.createHash('sha256').update(input.canonicalEnvelope, 'utf8').digest('hex')) {
		throw new Error('Hypothesis request plan is unavailable.');
	}
	const { snapshot, secret } = await resolveConfigurationAndCredential({ store: input.store, providerId: input.providerConfiguration.providerId, modelId: input.providerConfiguration.modelId, credentialVersionKey: input.credentialVersionKey });
	if (!sameHypothesisAiProviderConfiguration(snapshot, input.providerConfiguration)) {throw new Error('Hypothesis request plan is stale.');}
	let envelope: unknown;
	try {envelope = JSON.parse(input.canonicalEnvelope);} catch {throw new Error('Hypothesis request plan is invalid.');}
	if (!isRecord(envelope) || envelope.providerId !== snapshot.providerId || envelope.modelId !== snapshot.modelId || !isRecord(envelope.content)) {throw new Error('Hypothesis request plan is inconsistent.');}
	const contentText = JSON.stringify(envelope.content);
	const bodyValue = providerBody(snapshot.providerId, snapshot.modelId, contentText, snapshot.requestOptions);
	const body = JSON.stringify(bodyValue);
	if (Buffer.byteLength(body, 'utf8') > snapshot.requestOptions.maxRequestBodyBytes) {throw new Error('Hypothesis request plan exceeds its size limit.');}
	const headers: Record<string, string> = { Accept: 'application/json', 'Content-Type': 'application/json' };
	let headerName: string;
	let headerValue: string;
	switch (snapshot.providerId) {
		case 'openai': headerName = 'Authorization'; headerValue = `Bearer ${secret}`; break;
		case 'openrouter': headerName = 'Authorization'; headerValue = `Bearer ${secret}`; headers['HTTP-Referer'] = 'https://aqiron-security.local'; headers['X-Title'] = 'Aqiron Security'; break;
		case 'claude': headerName = 'x-api-key'; headerValue = secret; headers['anthropic-version'] = '2023-06-01'; break;
		case 'gemini': headerName = 'x-goog-api-key'; headerValue = secret; break;
	}
	const plan: HypothesisAiBoundRequestPlan = {
		planVersion: 1, preparationId: input.preparationId, expiresAt: input.expiresAt, providerId: snapshot.providerId, modelId: snapshot.modelId,
		destination: snapshot.destination, method: 'POST', headers, body,
		contentFingerprint: input.providerConfiguration.outboundContentFingerprint!, configurationFingerprint: snapshot.configurationFingerprint,
		requestBodyFingerprint: crypto.createHash('sha256').update(body, 'utf8').digest('hex'),
		requestOptions: { ...snapshot.requestOptions },
	};
	Object.freeze(plan.headers);
	Object.freeze(plan.requestOptions);
	Object.freeze(plan);
	const executionRequest = { plan, authentication: { headerName, headerValue } };
	Object.defineProperty(executionRequest, 'authentication', { value: executionRequest.authentication, enumerable: false, writable: false });
	Object.freeze(executionRequest.authentication);
	Object.freeze(executionRequest);
	return executionRequest;
}

/** Apply a plan verbatim; callers provide only the once-verified, short-lived auth value. */
export async function sendHypothesisAiBoundRequest(transport: AITransport, request: HypothesisAiBoundExecutionRequest, signal?: AbortSignal): Promise<Awaited<ReturnType<AITransport['request']>>> {
	const { plan, authentication } = request;
	if (!Number.isFinite(Date.parse(plan.expiresAt)) || Date.parse(plan.expiresAt) <= Date.now()) {throw new Error('Hypothesis request plan expired.');}
	if (signal?.aborted) {throw new Error('Hypothesis request cancelled.');}
	if (plan.method !== 'POST' || crypto.createHash('sha256').update(plan.body, 'utf8').digest('hex') !== plan.requestBodyFingerprint) {throw new Error('Hypothesis request plan is invalid.');}
	return await transport.request(plan.destination, {
		method: plan.method, headers: { ...plan.headers, [authentication.headerName]: authentication.headerValue },
		serializedBody: plan.body, timeoutMs: plan.requestOptions.timeoutMs, abortSignal: signal,
		maxRequestBodyBytes: plan.requestOptions.maxRequestBodyBytes,
		maxResponseBodyBytes: plan.requestOptions.maxResponseBodyBytes,
	});
}

function providerBody(providerId: AIProviderId, modelId: string, contentText: string, options: HypothesisAiRequestOptionsSnapshot): Record<string, unknown> {
	const messages = [{ role: 'user', content: contentText }];
	switch (providerId) {
		case 'openai': return { model: modelId, messages, stream: false, temperature: options.temperature, max_tokens: options.maxTokens, response_format: { type: 'json_object' } };
		case 'openrouter': return { model: modelId, messages, stream: false, temperature: options.temperature, max_tokens: options.maxTokens, response_format: { type: 'json_object' }, provider: { require_parameters: true } };
		case 'claude': return { model: modelId, max_tokens: options.maxTokens, messages, stream: false, output_config: { format: { type: 'json_schema', schema: hypothesisProposalJsonSchema } } };
		case 'gemini': return { contents: [{ role: 'user', parts: [{ text: contentText }] }], generationConfig: { temperature: options.temperature, maxOutputTokens: options.maxTokens, responseMimeType: 'application/json' } };
	}
}

function responseModeFor(providerId: AIProviderId): HypothesisAiResponseMode {
	switch (providerId) {
		case 'openai': return 'openai-json-object';
		case 'openrouter': return 'openrouter-required-json-object';
		case 'claude': return 'anthropic-json-schema';
		case 'gemini': return 'gemini-json-mime';
	}
}

// Provider-compatible structural shape only. Core's strict validator remains
// authoritative for limits, aliases, and semantic rules after parsing.
const proposalProperties = {
	title: { type: 'string' }, claim: { type: 'string' }, evidenceRationale: { type: 'string' },
	supportingEvidenceAliases: { type: 'array', items: { type: 'string' } },
	contradictoryEvidenceAliases: { type: 'array', items: { type: 'string' } },
	verificationCriteria: { type: 'array', items: { type: 'string' } },
	falsificationCriteria: { type: 'array', items: { type: 'string' } },
	uncertainties: { type: 'array', items: { type: 'string' } },
};
const hypothesisProposalJsonSchema = {
	type: 'object',
	properties: {
		schemaVersion: { type: 'integer' },
		proposals: { type: 'array', items: { type: 'object', properties: proposalProperties, required: Object.keys(proposalProperties), additionalProperties: false } },
	},
	required: ['schemaVersion', 'proposals'], additionalProperties: false,
};

export function sameHypothesisAiProviderConfiguration(current: HypothesisAiProviderConfigurationSnapshot, captured: HypothesisAiProviderConfigurationSnapshot): boolean {
	return current.providerId === captured.providerId && current.modelId === captured.modelId && current.destination === captured.destination
		&& current.credentialIdentity === captured.credentialIdentity && current.credentialName === captured.credentialName
		&& current.credentialLast4 === captured.credentialLast4 && current.credentialUpdatedAt === captured.credentialUpdatedAt
		&& current.credentialVersionTag === captured.credentialVersionTag
		&& current.capabilityPolicyVersion === captured.capabilityPolicyVersion
		&& current.configurationFingerprint === captured.configurationFingerprint
		&& JSON.stringify(current.requestOptions) === JSON.stringify(captured.requestOptions);
}

function resolveDestination(providerId: AIProviderId, openRouterEndpoint: string, modelId: string): string {
	let target: URL;
	try {
		if (providerId === 'openrouter') {
			target = new URL(openRouterEndpoint.trim());
			target.pathname = `${target.pathname.replace(/\/+$/, '')}/chat/completions`;
		} else {
			const value = PROVIDER_DESTINATIONS[providerId as Exclude<AIProviderId, 'openrouter'>];
			target = new URL(value.replace('{model}', encodeURIComponent(modelId)));
		}
	} catch {throw new Error('Hypothesis synthesis endpoint configuration is invalid.');}
	if (target.protocol !== 'https:' || target.username || target.password || target.hash) {throw new Error('Hypothesis synthesis endpoint configuration is invalid.');}
	if (providerId === 'openrouter' && target.origin !== 'https://openrouter.ai') {throw new Error('Hypothesis synthesis endpoint configuration is invalid.');}
	for (const [key] of target.searchParams) {
		if (/(?:key|token|auth|secret|credential|password)/i.test(key)) {throw new Error('Hypothesis synthesis endpoint configuration is invalid.');}
	}
	return `${target.origin}${target.pathname}${target.search}`;
}

function safeLabel(value: unknown, fallback: string): string {
	if (typeof value !== 'string') {return fallback;}
	return value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 80) || fallback;
}

function isRecord(value: unknown): value is Record<string, any> {return Boolean(value && typeof value === 'object' && !Array.isArray(value));}

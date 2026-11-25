import { strict as assert } from 'assert';
import { AIModel, AIProvider, ChatRequest, StreamChunk } from '../../packages/core/src/shared/ai';
import {
	HYPOTHESIS_AI_ADAPTER_LIMITS,
	HypothesisAiInvocationResult,
	invokeHypothesisAi,
} from '../../packages/core/src/hypotheses/hypothesisAiAdapter';
import { createHypothesisAiRequestContext, validateHypothesisAiResponse } from '../../packages/core/src/hypotheses/aiProposalValidation';
import { HypothesisSnapshot } from '../../packages/core/src/hypotheses/contracts';

suite('Hypothesis AI provider-bound adapter', () => {
	test('invokes only the explicitly injected provider when shared selection changes', async () => {
		let selectedProvider = 'openai';
		let firstCalls = 0;
		let secondCalls = 0;
		const first = fakeProvider('openai', async function* () {
			firstCalls++;
			selectedProvider = 'claude';
			yield { type: 'token', content: 'bounded response' };
		});
		const second = fakeProvider('claude', async function* () { secondCalls++; yield { type: 'token', content: 'wrong provider' }; });
		const result = await invokeHypothesisAi({ provider: first, providerId: 'openai', model: model('openai'), prompt: 'minimal prompt' });
		assert.equal(selectedProvider, 'claude');
		assert.equal(firstCalls, 1);
		assert.equal(secondCalls, 0);
		assert.deepEqual(result, { ok: true, providerId: 'openai', modelId: 'model-openai', text: 'bounded response' });
	});

	test('completes a bounded stream with the explicit model and zero retries', async () => {
		let request: ChatRequest | undefined;
		const provider = fakeProvider('openai', async function* (input) {
			request = input;
			yield { type: 'token', content: 'part one ' };
			yield { type: 'token', content: 'part two' };
			yield { type: 'done' };
		});
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'bounded prompt' });
		assert.equal(result.ok, true);
		if (!result.ok) {return;}
		assert.equal(result.text, 'part one part two');
		assert.deepEqual(Object.keys(result).sort(), ['modelId', 'ok', 'providerId', 'text']);
		assert.equal(request?.retries, 0);
		assert.equal(request?.abortSignal instanceof AbortSignal, true);
	});

	test('rejects response bytes beyond the UTF-8 budget, including multibyte chunks', async () => {
		let observedSignal: AbortSignal | undefined;
		const provider = fakeProvider('openai', async function* (request) {
			observedSignal = request.abortSignal;
			yield { type: 'token', content: 'é'.repeat(HYPOTHESIS_AI_ADAPTER_LIMITS.maxResponseBytes / 2) };
			yield { type: 'token', content: 'é' };
		});
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p' });
		assert.deepEqual(result, { ok: false, error: 'response-too-large' });
		assert.equal(observedSignal?.aborted, true);
	});

	test('rejects oversized UTF-8 request payloads before invoking a provider', async () => {
		let calls = 0;
		const provider = fakeProvider('openai', async function* () { calls++; });
		// The prompt itself is below the cap, but JSON framing and request fields push
		// the complete serialized envelope over the limit.
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'x'.repeat(HYPOTHESIS_AI_ADAPTER_LIMITS.maxRequestBytes - 1) });
		assert.deepEqual(result, { ok: false, error: 'invalid-request' });
		assert.equal(calls, 0);
	});

	test('counts a supplementary character split across chunks using concatenated UTF-8 semantics', async () => {
		const provider = fakeProvider('openai', async function* () {
			yield { type: 'token', content: '\ud83d' };
			yield { type: 'token', content: '\ude80' };
		});
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p' });
		assert.equal(result.ok, true);
		if (result.ok) {assert.equal(Buffer.byteLength(result.text, 'utf8'), 4); assert.equal(result.text, '🚀');}
	});

	test('accepts a split supplementary character at the exact UTF-8 response limit', async () => {
		const provider = fakeProvider('openai', async function* () {
			yield { type: 'token', content: 'a'.repeat(HYPOTHESIS_AI_ADAPTER_LIMITS.maxResponseBytes - 4) + '\ud83d' };
			yield { type: 'token', content: '\ude80' };
		});
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p' });
		assert.equal(result.ok, true);
		if (result.ok) {assert.equal(Buffer.byteLength(result.text, 'utf8'), HYPOTHESIS_AI_ADAPTER_LIMITS.maxResponseBytes);}
	});

	test('rejects one byte above the UTF-8 limit and terminates the iterator', async () => {
		let aborted = false;
		let detached = false;
		const provider = customIteratorProvider('openai', (request) => {
			request.abortSignal?.addEventListener('abort', () => {aborted = true;});
			let index = 0;
			return {
				next: async () => index++ === 0
					? { done: false, value: { type: 'token', content: 'a'.repeat(HYPOTHESIS_AI_ADAPTER_LIMITS.maxResponseBytes - 3) + '🚀' } as StreamChunk }
					: { done: true, value: undefined as never },
				return: async () => {detached = true; return { done: true, value: undefined as never };},
			};
		});
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p' });
		assert.deepEqual(result, { ok: false, error: 'response-too-large' });
		assert.equal(aborted, true);
		assert.equal(detached, true);
	});

	test('counts an unmatched trailing high surrogate as Node UTF-8 replacement bytes', async () => {
		const provider = fakeProvider('openai', async function* () {
			yield { type: 'token', content: 'a'.repeat(HYPOTHESIS_AI_ADAPTER_LIMITS.maxResponseBytes - 3) + '\ud83d' };
		});
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p' });
		assert.equal(result.ok, true);
		if (result.ok) {assert.equal(Buffer.byteLength(result.text, 'utf8'), HYPOTHESIS_AI_ADAPTER_LIMITS.maxResponseBytes);}
	});

	test('counts a pending high surrogate followed by a non-low surrogate consistently', async () => {
		const provider = fakeProvider('openai', async function* () {
			yield { type: 'token', content: '\ud83d' };
		yield { type: 'token', content: 'x' };
	});
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p' });
		assert.equal(result.ok, true);
		if (result.ok) { assert.equal(Buffer.byteLength(result.text, 'utf8'), 4); assert.equal(result.text, '\ud83dx'); }
	});

	test('allows an empty chunk between the halves of a supplementary character', async () => {
		const provider = fakeProvider('openai', async function* () {
			yield { type: 'token', content: '\ud83d' };
			yield { type: 'token', content: '' };
			yield { type: 'token', content: '\ude80' };
		});
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p' });
		assert.equal(result.ok, true);
		if (result.ok) { assert.equal(result.text, '🚀'); assert.equal(Buffer.byteLength(result.text, 'utf8'), 4); }
	});

	test('accepts the exact serialized adapter-envelope request boundary', async () => {
		let calls = 0;
		const provider = fakeProvider('openai', async function* () { calls++; yield { type: 'token', content: 'ok' }; });
		const base = { model: model('openai').id, messages: [{ role: 'user', content: '' }], temperature: 0, maxTokens: 2048, stream: true, timeoutMs: 30_000, retries: 0 };
		const overhead = Buffer.byteLength(JSON.stringify(base), 'utf8');
		const prompt = 'x'.repeat(HYPOTHESIS_AI_ADAPTER_LIMITS.maxRequestBytes - overhead);
		assert.equal(Buffer.byteLength(JSON.stringify({ ...base, messages: [{ role: 'user', content: prompt }] }), 'utf8'), HYPOTHESIS_AI_ADAPTER_LIMITS.maxRequestBytes);
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt });
		assert.equal(result.ok, true);
		assert.equal(calls, 1);
	});

	test('a throwing iterator return accessor cannot escape cancellation cleanup', async () => {
		let started!: () => void;
		const entered = new Promise<void>((resolve) => { started = resolve; });
		const provider = customIteratorProvider('openai', (request) => {
			started();
			return {
				next: () => new Promise<IteratorResult<StreamChunk>>(() => undefined),
				get return(): (value?: unknown) => Promise<IteratorResult<StreamChunk>> { throw new Error('untrusted return getter'); },
			};
		});
		const controller = new AbortController();
		const pending = invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p', signal: controller.signal });
		await entered;
		controller.abort();
		assert.deepEqual(await pending, { ok: false, error: 'cancelled' });
	});

	test('a throwing iterator return accessor cannot escape timeout cleanup', async () => {
		const provider = customIteratorProvider('openai', () => ({
			next: () => new Promise<IteratorResult<StreamChunk>>(() => undefined),
			get return(): (value?: unknown) => Promise<IteratorResult<StreamChunk>> { throw new Error('untrusted return getter'); },
		}));
		assert.deepEqual(await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p', timeoutMs: 10 }), { ok: false, error: 'timed-out' });
	});

	test('pending surrogate text is not accepted on cancellation or provider error', async () => {
		const controller = new AbortController();
		const cancelledProvider = fakeProvider('openai', async function* (request) {
			yield { type: 'token', content: '\ud83d' };
			await new Promise<void>((resolve) => request.abortSignal?.addEventListener('abort', () => resolve(), { once: true }));
			yield { type: 'token', content: '\ude80' };
		});
		const pending = invokeHypothesisAi({ provider: cancelledProvider, providerId: 'openai', model: model('openai'), prompt: 'p', signal: controller.signal });
		await new Promise((resolve) => setImmediate(resolve));
		controller.abort();
		assert.deepEqual(await pending, { ok: false, error: 'cancelled' });
		const errorProvider = fakeProvider('openai', async function* () {
			yield { type: 'token', content: '\ud83d' };
			yield { type: 'error', error: 'private' };
		});
		assert.deepEqual(await invokeHypothesisAi({ provider: errorProvider, providerId: 'openai', model: model('openai'), prompt: 'p' }), { ok: false, error: 'provider-failure' });
	});

	test('removes caller abort listener after successful completion', async () => {
		const controller = new AbortController();
		const signal = controller.signal;
		const add = signal.addEventListener.bind(signal);
		const remove = signal.removeEventListener.bind(signal);
		let added = 0;
		let removed = 0;
		let timeoutScheduled = false;
		let timeoutCleared = false;
		const originalSetTimeout = globalThis.setTimeout;
		const originalClearTimeout = globalThis.clearTimeout;
		globalThis.setTimeout = ((...args: Parameters<typeof setTimeout>) => { timeoutScheduled = true; return originalSetTimeout(...args); }) as typeof setTimeout;
		globalThis.clearTimeout = ((handle: ReturnType<typeof setTimeout>) => { timeoutCleared = true; return originalClearTimeout(handle); }) as typeof clearTimeout;
		signal.addEventListener = ((...args: Parameters<AbortSignal['addEventListener']>) => { added++; return add(...args); }) as AbortSignal['addEventListener'];
		signal.removeEventListener = ((...args: Parameters<AbortSignal['removeEventListener']>) => { removed++; return remove(...args); }) as AbortSignal['removeEventListener'];
		const provider = fakeProvider('openai', async function* () { yield { type: 'token', content: 'ok' }; });
		try {
			assert.equal((await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p', signal })).ok, true);
			assert.equal(added, 1);
			assert.equal(removed, 1);
			assert.equal(timeoutScheduled, true);
			assert.equal(timeoutCleared, true);
		} finally {
			globalThis.setTimeout = originalSetTimeout;
			globalThis.clearTimeout = originalClearTimeout;
		}
	});

	test('rejected iterator next aborts provider work and detaches without accepting late output', async () => {
		let signalAborted = false;
		let detachCalls = 0;
		let nextCalls = 0;
		const provider = customIteratorProvider('openai', (request) => {
			request.abortSignal?.addEventListener('abort', () => {signalAborted = true;});
			return {
				next: async () => {nextCalls++; if (nextCalls === 1) {throw new Error('private provider error');} return { done: false, value: { type: 'token', content: 'late' } as StreamChunk };},
				return: async () => {detachCalls++; return { done: true, value: undefined as never };},
			};
		});
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p' });
		assert.deepEqual(result, { ok: false, error: 'provider-failure' });
		assert.equal(signalAborted, true);
		assert.equal(detachCalls, 1);
		assert.equal(nextCalls, 1);
	});

	test('error chunks abort provider work and detach the stream', async () => {
		const { result, aborted, detached } = await invokeMalformedStream({ type: 'error', error: 'sensitive' });
		assert.deepEqual(result, { ok: false, error: 'provider-failure' });
		assert.equal(aborted(), true);
		assert.equal(detached(), true);
	});

	test('non-string token content aborts provider work and detaches the stream', async () => {
		const { result, aborted, detached } = await invokeMalformedStream({ type: 'token', content: 42 } as unknown as StreamChunk);
		assert.deepEqual(result, { ok: false, error: 'invalid-provider-output' });
		assert.equal(aborted(), true);
		assert.equal(detached(), true);
	});

	test('never-resolving iterator cleanup does not delay a terminal rejection', async () => {
		let aborted = false;
		let detached = false;
		const provider = customIteratorProvider('openai', (request) => {
			request.abortSignal?.addEventListener('abort', () => {aborted = true;});
			return {
				next: async () => ({ done: false, value: { type: 'error' } as StreamChunk }),
				return: () => {detached = true; return new Promise<IteratorResult<StreamChunk>>(() => undefined);},
			};
		});
		const result = await Promise.race([
			invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p' }),
			new Promise<HypothesisAiInvocationResult>((resolve) => setTimeout(() => resolve({ ok: true, providerId: 'timeout', modelId: 'timeout', text: '' }), 100)),
		]);
		assert.deepEqual(result, { ok: false, error: 'provider-failure' });
		assert.equal(aborted, true);
		assert.equal(detached, true);
	});

	test('cancellation before invocation does not call the provider', async () => {
		let calls = 0;
		const controller = new AbortController();
		controller.abort();
		const provider = fakeProvider('openai', async function* () { calls++; });
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p', signal: controller.signal });
		assert.deepEqual(result, { ok: false, error: 'cancelled' });
		assert.equal(calls, 0);
	});

	test('cancellation during streaming stops accepting chunks and aborts the provider signal', async () => {
		let started!: () => void;
		const entered = new Promise<void>((resolve) => { started = resolve; });
		let providerSignal: AbortSignal | undefined;
		const provider = fakeProvider('openai', async function* (request) {
			providerSignal = request.abortSignal;
			started();
			yield { type: 'token', content: 'partial' };
			await new Promise<void>((resolve) => request.abortSignal?.addEventListener('abort', () => resolve(), { once: true }));
			yield { type: 'token', content: 'late' };
		});
		const controller = new AbortController();
		const pending = invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p', signal: controller.signal });
		await entered;
		controller.abort();
		assert.deepEqual(await pending, { ok: false, error: 'cancelled' });
		assert.equal(providerSignal?.aborted, true);
	});

	test('times out an uncooperative provider and ignores its late result', async () => {
		let release!: () => void;
		let started!: () => void;
		const late = new Promise<void>((resolve) => { release = resolve; });
		const entered = new Promise<void>((resolve) => { started = resolve; });
		let providerSignal: AbortSignal | undefined;
		const provider = fakeProvider('openai', async function* (request) {
			providerSignal = request.abortSignal;
			started();
			await late; // Deliberately ignores AbortSignal.
			yield { type: 'token', content: 'late result' };
		});
		const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p', timeoutMs: 20 });
		assert.deepEqual(result, { ok: false, error: 'timed-out' });
		await entered;
		assert.equal(providerSignal?.aborted, true);
		release();
		await new Promise((resolve) => setTimeout(resolve, 0));
		assert.deepEqual(result, { ok: false, error: 'timed-out' });
	});

	test('categorizes provider failure and empty output without retry or fallback', async () => {
		let primaryCalls = 0;
		let fallbackCalls = 0;
		const primary = fakeProvider('openai', async function* () { primaryCalls++; throw new Error('sensitive provider detail'); });
		const fallback = fakeProvider('claude', async function* () { fallbackCalls++; yield { type: 'token', content: 'fallback' }; });
		const failed = await invokeHypothesisAi({ provider: primary, providerId: 'openai', model: model('openai'), prompt: 'secret prompt' });
		const empty = await invokeHypothesisAi({ provider: fakeProvider('openai', async function* () {}), providerId: 'openai', model: model('openai'), prompt: 'p' });
		assert.deepEqual(failed, { ok: false, error: 'provider-failure' });
		assert.deepEqual(empty, { ok: false, error: 'empty-response' });
		assert.equal(primaryCalls, 1);
		assert.equal(fallbackCalls, 0);
		assert.ok(!JSON.stringify(failed).includes('sensitive provider detail'));
		assert.ok(!JSON.stringify(failed).includes('secret prompt'));
		assert.deepEqual(await invokeHypothesisAi({ provider: primary, providerId: 'claude', model: model('claude'), prompt: 'p' }), { ok: false, error: 'invalid-request' });
	});

	test('emits no logs or token events and leaves proposal validation separate', async () => {
		const raw = 'model supplied unstructured text';
		const provider = fakeProvider('openai', async function* () { yield { type: 'token', content: raw }; });
		const logs: unknown[][] = [];
		const oldLog = console.log;
		const oldWarn = console.warn;
		const oldError = console.error;
		console.log = (...args: unknown[]) => { logs.push(args); };
		console.warn = (...args: unknown[]) => { logs.push(args); };
		console.error = (...args: unknown[]) => { logs.push(args); };
		try {
			const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'source excerpt must stay private' });
			assert.deepEqual(result, { ok: true, providerId: 'openai', modelId: 'model-openai', text: raw });
			assert.deepEqual(logs, []);
			assert.ok(!('proposals' in result));
			const context = testContext();
			assert.deepEqual(validateHypothesisAiResponse(result.text, context), { valid: false, error: 'malformed-response' });
		} finally {
			console.log = oldLog;
			console.warn = oldWarn;
			console.error = oldError;
		}
	});

	test('rejects timeout values beyond the hard cap and provider/model mismatches', async () => {
		let calls = 0;
		const provider = fakeProvider('openai', async function* () { calls++; });
		assert.deepEqual(await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p', timeoutMs: HYPOTHESIS_AI_ADAPTER_LIMITS.maxTimeoutMs + 1 }), { ok: false, error: 'invalid-request' });
		assert.deepEqual(await invokeHypothesisAi({ provider, providerId: 'claude', model: model('claude'), prompt: 'p' }), { ok: false, error: 'invalid-request' });
		assert.equal(calls, 0);
	});
});

function model(providerId: AIModel['providerId']): Pick<AIModel, 'id' | 'providerId'> {
	return { id: `model-${providerId}`, providerId };
}

function fakeProvider(id: string, chat: (request: ChatRequest) => AsyncGenerator<StreamChunk>): AIProvider {
	return {
		id,
		name: `Fake ${id}`,
		initialize: async () => undefined,
		getModels: async () => [],
		chat,
		validateConnection: async () => true,
	};
}

function customIteratorProvider(id: string, create: (request: ChatRequest) => AsyncIterator<StreamChunk>): AIProvider {
	return {
		id,
		name: `Fake ${id}`,
		initialize: async () => undefined,
		getModels: async () => [],
		chat: ((request: ChatRequest) => create(request)) as AIProvider['chat'],
		validateConnection: async () => true,
	};
}

async function invokeMalformedStream(chunk: StreamChunk): Promise<{ result: HypothesisAiInvocationResult; aborted: () => boolean; detached: () => boolean }> {
	let wasAborted = false;
	let wasDetached = false;
	const provider = customIteratorProvider('openai', (request) => {
		request.abortSignal?.addEventListener('abort', () => {wasAborted = true;});
		return {
			next: async () => ({ done: false, value: chunk }),
			return: async () => {wasDetached = true; return { done: true, value: undefined as never };},
		};
	});
	const result = await invokeHypothesisAi({ provider, providerId: 'openai', model: model('openai'), prompt: 'p' });
	return { result, aborted: () => wasAborted, detached: () => wasDetached };
}

function testContext() {
	const finding = {
		id: 'finding:adapter-test', kind: 'finding' as const, source: 'test scanner', findingId: 'adapter-test', ruleId: 'rule.adapter-test',
		observedAt: '2026-10-21T00:00:00.000Z', freshness: 'current' as const,
	};
	return createHypothesisAiRequestContext({
		id: 'snapshot:adapter-test', workspaceRoot: 'C:/workspace', scanId: 'scan:adapter-test', capturedAt: '2026-10-21T00:00:00.000Z',
		fingerprint: 'a'.repeat(64), profile: {} as never, evidence: [finding], findings: [{ id: 'adapter-test', ruleId: 'rule.adapter-test' } as never], relationships: [],
	} as HypothesisSnapshot);
}

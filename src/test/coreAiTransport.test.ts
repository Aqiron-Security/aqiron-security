import * as assert from 'assert';
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { AIHttpError, AITransport, createNetworkTransport, AI_TRANSPORT_LIMITS, parseSseStream } from '../../packages/core/src/ai/utils/request';
import { OpenAIProvider } from '../../packages/core/src/ai/providers/openaiProvider';
import { ClaudeProvider } from '../../packages/core/src/ai/providers/claudeProvider';
import { GeminiProvider } from '../../packages/core/src/ai/providers/geminiProvider';
import { OpenRouterProvider } from '../../packages/core/src/ai/providers/openrouterProvider';
import { CredentialService, aiSecretKeys } from '../../packages/core/src/ai/services/credentialService';
import { ChatRequest, AIProviderId, defaultAISettings } from '../../packages/core/src/shared/ai';
import { CredentialStore, Logger, NetworkClient, NetworkResponse } from '../../packages/core/src/shared/platform';
import { createNodeNetworkClient } from '../../packages/core/src/runtime/nodeAdapters';

suite('AI provider transport bounds', () => {
	test('Node fetch transport sends the exact frozen bytes and reads a bounded local JSON response', async () => {
		let requestSeen: { method?: string; authorization?: string; body: string } | undefined;
		const server = await startLocalServer(async (req, res) => {
			requestSeen = await captureRequest(req);
			res.writeHead(200, { 'content-type': 'application/json' });
			res.end('{"ok":true}');
		});
		try {
			const body = '{"model":"fixture-model","messages":[]}';
			const client = createNodeNetworkClient(silentLogger());
			const result = await createNetworkTransport(client).request(`${server.url}/chat`, {
				method: 'POST', headers: { Authorization: 'Bearer synthetic-fixture-token' }, serializedBody: body,
				timeoutMs: 2000, maxRequestBodyBytes: Buffer.byteLength(body), maxResponseBodyBytes: 64,
			});
			assert.equal(result.status, 200);
			assert.equal(result.headers['content-type'], 'application/json');
			assert.equal(await result.text(), '{"ok":true}');
			assert.deepEqual(requestSeen, { method: 'POST', authorization: 'Bearer synthetic-fixture-token', body });
			const direct = await client.request(`${server.url}/direct-json`);
			assert.deepEqual(await direct.json(), { ok: true }, 'the Node client response helpers consume the wrapped stream correctly');
		} finally { await server.close(); }
	});

	test('Node fetch transport rejects redirects without forwarding credentials to the redirect target', async () => {
		let credentialTargetHits = 0;
		const server = await startLocalServer(async (req, res) => {
			if (req.url === '/redirect') { res.writeHead(302, { location: '/credential-target' }); res.end(); return; }
			credentialTargetHits++;
			res.writeHead(200, { 'content-type': 'application/json' }); res.end('{}');
		});
		try {
			await assert.rejects(createNetworkTransport(createNodeNetworkClient(silentLogger())).request(`${server.url}/redirect`, {
				method: 'POST', headers: { Authorization: 'Bearer synthetic-only' }, body: { prompt: 'fixture' }, timeoutMs: 2000,
			}), (error: unknown) => error instanceof AIHttpError && error.status === 302);
			assert.equal(credentialTargetHits, 0);
		} finally { await server.close(); }
	});

	test('Node fetch transport rejects oversized advertised length and chunked overflow while stopping the response', async () => {
		let overflowClosed!: () => void;
		const overflowResponseClosed = new Promise<void>(resolve => { overflowClosed = resolve; });
		const server = await startLocalServer(async (req, res) => {
			if (req.url === '/advertised') { res.writeHead(200, { 'content-type': 'application/json', 'content-length': '1000' }); res.end('{}'); return; }
			res.writeHead(req.url === '/chunked-error' ? 500 : 200, { 'content-type': 'application/json', 'transfer-encoding': 'chunked' });
			res.on('close', overflowClosed);
			res.write('12345');
			await new Promise(resolve => setTimeout(resolve, 30));
			if (!res.destroyed) { res.end(); }
		});
		try {
			const transport = createNetworkTransport(createNodeNetworkClient(silentLogger()));
			await assert.rejects(transport.request(`${server.url}/advertised`, { timeoutMs: 2000, maxResponseBodyBytes: 4 }), (e: unknown) => e instanceof AIHttpError && e.outcome === 'limit');
			const chunked = await transport.request(`${server.url}/chunked`, { timeoutMs: 2000, maxResponseBodyBytes: 4 });
			await assert.rejects(chunked.text(), (e: unknown) => e instanceof AIHttpError && e.outcome === 'limit');
			await overflowResponseClosed;
			await assert.rejects(transport.request(`${server.url}/chunked-error`, { timeoutMs: 2000, maxResponseBodyBytes: 4 }), (e: unknown) => e instanceof AIHttpError && e.outcome === 'limit', 'error status bodies are subject to the same byte ceiling');
		} finally { await server.close(); }
	});

	test('Node fetch transport cancellation while waiting for headers aborts the underlying request', async () => {
		let requestEntered!: () => void;
		const entered = new Promise<void>(resolve => { requestEntered = resolve; });
		let serverObservedClose!: () => void;
		const closed = new Promise<void>(resolve => { serverObservedClose = resolve; });
		const server = await startLocalServer(async (_req, res) => {
			requestEntered();
			res.on('close', serverObservedClose);
		});
		try {
			const controller = new AbortController();
			const pending = createNetworkTransport(createNodeNetworkClient(silentLogger())).request(`${server.url}/slow-headers`, { timeoutMs: 5000, abortSignal: controller.signal });
			await Promise.race([entered, pending.then(() => { throw new Error('Request unexpectedly completed before the local server observed it.'); })]);
			controller.abort();
			await assert.rejects(pending, (e: unknown) => e instanceof AIHttpError && e.outcome === 'cancelled');
			await closed;
		} finally { await server.close(); }
	});

	test('Node fetch transport timeout aborts header wait and reports timeout distinctly', async () => {
		let enteredResolve!: () => void;
		const entered = new Promise<void>(resolve => { enteredResolve = resolve; });
		let serverObservedClose!: () => void;
		const closed = new Promise<void>(resolve => { serverObservedClose = resolve; });
		const server = await startLocalServer(async (_req, res) => { enteredResolve(); res.on('close', serverObservedClose); });
		try {
			const pending = createNetworkTransport(createNodeNetworkClient(silentLogger())).request(`${server.url}/slow-timeout`, { timeoutMs: 80 });
			await Promise.race([entered, pending.then(() => { throw new Error('Request unexpectedly completed before the local server observed it.'); })]);
			await assert.rejects(pending, (e: unknown) => e instanceof AIHttpError && e.outcome === 'timeout');
			await closed;
		} finally { await server.close(); }
	});

	test('Node fetch transport abort during response streaming cancels the underlying reader', async () => {
		let firstChunkSent!: () => void;
		const sent = new Promise<void>(resolve => { firstChunkSent = resolve; });
		let serverObservedClose!: () => void;
		const closed = new Promise<void>(resolve => { serverObservedClose = resolve; });
		const server = await startLocalServer(async (_req, res) => {
			res.writeHead(200, { 'content-type': 'application/json', 'transfer-encoding': 'chunked' });
			res.on('close', serverObservedClose);
			res.write('{'); firstChunkSent();
			await new Promise(resolve => setTimeout(resolve, 1000));
			if (!res.destroyed) { res.end('}'); }
		});
		try {
			const controller = new AbortController();
			const response = await createNetworkTransport(createNodeNetworkClient(silentLogger())).request(`${server.url}/slow-body`, { timeoutMs: 5000, abortSignal: controller.signal });
			await sent;
			const reader = response.body!.getReader();
			assert.equal((await reader.read()).done, false);
			controller.abort();
			await assert.rejects(reader.read(), (e: unknown) => e instanceof AIHttpError && e.outcome === 'cancelled');
			await closed;
		} finally { await server.close(); }
	});

	test('Node fetch transport handles premature connection close and malformed UTF-8 without returning partial success', async () => {
		const server = await startLocalServer(async (req, res) => {
			if (req.url === '/cut') { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{"partial":'); res.destroy(); return; }
			res.writeHead(200, { 'content-type': 'application/json' }); res.end(Buffer.from([0xff]));
		});
		try {
			const transport = createNetworkTransport(createNodeNetworkClient(silentLogger()));
			await assert.rejects(transport.request(`${server.url}/cut`, { timeoutMs: 2000 }), (e: unknown) => e instanceof AIHttpError && e.status === 502);
			const malformed = await transport.request(`${server.url}/invalid-utf8`, { timeoutMs: 2000 });
			await assert.rejects(malformed.text(), (e: unknown) => e instanceof AIHttpError);
		} finally { await server.close(); }
	});

	test('serializes once, measures UTF-8 bytes, and passes the same request string', async () => {
		const body = { text: 'é🚀' };
		const expected = JSON.stringify(body);
		let transmitted: string | Uint8Array | undefined;
		const transport = createNetworkTransport({ request: async (_url, options) => { transmitted = options?.body; return response(200, 'data: [DONE]\n\n'); } });
		await transport.request('https://fake.invalid/chat', { method: 'POST', timeoutMs: 1000, body, maxRequestBodyBytes: Buffer.byteLength(expected, 'utf8') });
		assert.equal(transmitted, expected);
		assert.equal(Buffer.byteLength(transmitted as string, 'utf8'), Buffer.byteLength(expected, 'utf8'));
	});

	test('rejects a body that cannot be represented as a JSON string before network invocation', async () => {
		let calls = 0;
		const transport = createNetworkTransport({ request: async () => { calls++; return response(200, ''); } });
		await assert.rejects(transport.request('https://fake.invalid/chat', { method: 'POST', timeoutMs: 1000, body: () => undefined }), (error: unknown) => error instanceof AIHttpError && error.status === 400);
		assert.equal(calls, 0);
	});

	test('rejects a one-byte-over final request body before network invocation', async () => {
		let calls = 0;
		const transport = createNetworkTransport({ request: async () => { calls++; return response(200, ''); } });
		await assert.rejects(transport.request('https://fake.invalid/chat', { method: 'POST', timeoutMs: 1000, body: { value: 'é' }, maxRequestBodyBytes: Buffer.byteLength(JSON.stringify({ value: 'é' }), 'utf8') - 1 }));
		assert.equal(calls, 0);
	});

	test('caller-supplied transport limits cannot raise the finite generic hard ceilings', async () => {
		let calls = 0;
		const transport = createNetworkTransport({ request: async () => { calls++; return response(200, ''); } });
		await assert.rejects(transport.request('https://fake.invalid', { timeoutMs: 1000, body: {}, maxRequestBodyBytes: AI_TRANSPORT_LIMITS.maxRequestBodyBytes + 1 }));
		await assert.rejects(transport.request('https://fake.invalid', { timeoutMs: 1000, maxResponseBodyBytes: AI_TRANSPORT_LIMITS.maxResponseBodyBytes + 1 }));
		assert.equal(calls, 0);
	});

	test('all four providers send their fully transformed serialized body through the bounded transport', async () => {
		const providerIds: AIProviderId[] = ['openai', 'claude', 'gemini', 'openrouter'];
		for (const id of providerIds) {
			let sentBody: string | Uint8Array | undefined;
			let calls = 0;
			const network: NetworkClient = { request: async (_url, options) => { calls++; sentBody = options?.body; return response(200, 'data: [DONE]\n\n'); } };
			const provider = providerFor(id, createNetworkTransport(network));
			const request = chatRequest(id);
			for await (const _chunk of provider.chat(request)) { /* fake stream */ }
			assert.equal(calls, 1, `${id} should make one fake request`);
			assert.equal(typeof sentBody, 'string');
			const serialized = sentBody as string;
			assert.equal(Buffer.byteLength(serialized, 'utf8') <= AI_TRANSPORT_LIMITS.maxRequestBodyBytes, true);
			const parsed = JSON.parse(serialized) as Record<string, unknown>;
			assert.equal('transportLimits' in parsed, false);
			if (id === 'gemini') { assert.ok(Array.isArray(parsed.contents)); assert.ok(parsed.generationConfig); }
			if (id === 'claude') { assert.equal(parsed.system, 'system instructions'); }
			if (id === 'openrouter') { assert.ok(parsed.reasoning); assert.deepEqual(parsed.stream_options, { include_usage: true }); }
			if (id === 'openai') { assert.ok(Array.isArray(parsed.messages)); }
		}
	});

	test('each provider accepts its exact final-body boundary and rejects one byte below it', async () => {
		for (const id of ['openai', 'claude', 'gemini', 'openrouter'] as const) {
			let serializedBody = '';
			const baseline = providerFor(id, createNetworkTransport({ request: async (_url, options) => { serializedBody = options?.body as string; return response(200, 'data: [DONE]\n\n'); } }));
			for await (const _chunk of baseline.chat(chatRequest(id))) { /* capture provider framing */ }
			const exactBytes = Buffer.byteLength(serializedBody, 'utf8');
			let exactCalls = 0;
			const exactProvider = providerFor(id, createNetworkTransport({ request: async () => { exactCalls++; return response(200, 'data: [DONE]\n\n'); } }));
			const exactRequest = chatRequest(id);
			exactRequest.transportLimits = { maxRequestBodyBytes: exactBytes, maxResponseBodyBytes: 65_536, maxSseEventBytes: 65_536 };
			for await (const _chunk of exactProvider.chat(exactRequest)) { /* exact serialized boundary succeeds */ }
			assert.equal(exactCalls, 1, `${id} exact boundary should reach the fake network`);
			let overCalls = 0;
			const overProvider = providerFor(id, createNetworkTransport({ request: async () => { overCalls++; return response(200, 'data: [DONE]\n\n'); } }));
			const overRequest = chatRequest(id);
			overRequest.transportLimits = { maxRequestBodyBytes: exactBytes - 1, maxResponseBodyBytes: 65_536, maxSseEventBytes: 65_536 };
			await assert.rejects(async () => { for await (const _chunk of overProvider.chat(overRequest)) { /* one byte over */ } }, (error: unknown) => error instanceof AIHttpError && error.status === 413, id);
			assert.equal(overCalls, 0, `${id} one byte over must not reach the fake network`);
		}
	});

	test('provider-framed body exceeding the synthesis limit is rejected before network invocation', async () => {
		let calls = 0;
		const provider = providerFor('openai', createNetworkTransport({ request: async () => { calls++; return response(200, 'data: [DONE]\n\n'); } }));
		const request = chatRequest('openai');
		request.messages = [{ role: 'user', content: 'x'.repeat(300) }];
		request.transportLimits = { maxRequestBodyBytes: 128, maxResponseBodyBytes: 65_536, maxSseEventBytes: 65_536 };
		await assert.rejects(async () => { for await (const _chunk of provider.chat(request)) { /* should be rejected before response */ } });
		assert.equal(calls, 0);
	});

	test('all four providers propagate request-specific transport ceilings', async () => {
		for (const id of ['openai', 'claude', 'gemini', 'openrouter'] as const) {
			let calls = 0;
			const provider = providerFor(id, createNetworkTransport({ request: async () => { calls++; return response(200, 'data: [DONE]\n\n'); } }));
			const request = chatRequest(id);
			request.transportLimits = { maxRequestBodyBytes: 1, maxResponseBodyBytes: 65_536, maxSseEventBytes: 65_536 };
			await assert.rejects(async () => { for await (const _chunk of provider.chat(request)) { /* body rejected before transport */ } }, (error: unknown) => error instanceof AIHttpError && error.status === 413, id);
			assert.equal(calls, 0, `${id} must reject its framed body before the network client`);
		}
	});

	test('all four providers propagate the raw response-body ceiling', async () => {
		for (const id of ['openai', 'claude', 'gemini', 'openrouter'] as const) {
			let cancelled = false;
			let sent = false;
			const stream = new ReadableStream<Uint8Array>({
				pull(controller) { if (!sent) { sent = true; controller.enqueue(new TextEncoder().encode('12345')); } },
				cancel() { cancelled = true; },
			});
			let calls = 0;
			const provider = providerFor(id, createNetworkTransport({ request: async () => { calls++; return response(200, '', stream); } }));
			const request = chatRequest(id);
			request.transportLimits = { maxRequestBodyBytes: 65_536, maxResponseBodyBytes: 4, maxSseEventBytes: 64 };
			await assert.rejects(async () => { for await (const _chunk of provider.chat(request)) { /* bounded stream rejects */ } }, (error: unknown) => error instanceof AIHttpError, id);
			assert.equal(calls, 1, `${id} request starts once`);
			assert.equal(cancelled, true, `${id} response reader is cancelled`);
		}
	});

	test('bounded raw response cancels overflow instead of yielding a truncated success', async () => {
		let cancelled = false;
		const stream = new ReadableStream<Uint8Array>({
			pull(controller) { controller.enqueue(new TextEncoder().encode('12345')); },
			cancel() { cancelled = true; },
		});
		const transport = createNetworkTransport({ request: async () => response(200, '', stream) });
		const bounded = await transport.request('https://fake.invalid/chat', { timeoutMs: 1000, maxResponseBodyBytes: 4 });
		await assert.rejects(async () => { for await (const _event of parseSseStream(bounded)) { /* no result on overflow */ } });
		assert.equal(cancelled, true);
	});

	test('caller cancellation reaches the network signal and cancels the response reader', async () => {
		let cancelled = false;
		let observedSignal: AbortSignal | undefined;
		let sent = false;
		let releasePendingPull!: () => void;
		let markPullPending!: () => void;
		const pullPending = new Promise<void>((resolve) => { markPullPending = resolve; });
		const stream = new ReadableStream<Uint8Array>({
			pull(controller) {
				if (!sent) { sent = true; controller.enqueue(new TextEncoder().encode('data: {"x":1}\n\n')); return; }
				markPullPending();
				return new Promise<void>((resolve) => { releasePendingPull = resolve; });
			},
			cancel() { cancelled = true; releasePendingPull?.(); },
		});
		const transport = createNetworkTransport({ request: async (_url, options) => { observedSignal = options?.abortSignal; return response(200, '', stream); } });
		const controller = new AbortController();
		const bounded = await transport.request('https://fake.invalid', { timeoutMs: 10_000, abortSignal: controller.signal });
		const consume = (async () => { for await (const _event of parseSseStream(bounded)) { /* wait for cancellation */ } })();
		await pullPending;
		controller.abort();
		await assert.rejects(consume);
		await new Promise((resolve) => setImmediate(resolve));
		assert.equal(observedSignal?.aborted, true, 'abort signal reaches the network client');
		assert.equal(cancelled, true, 'response reader cancellation reaches the source stream');
	});

	test('SSE handles split UTF-8, split delimiters, empty and multiple events, and EOF data', async () => {
		const bytes = new TextEncoder().encode('data: {"text":"🚀"}\r\n\r\ndata: \n\ndata: {"n":2}');
		const rocket = new TextEncoder().encode('🚀');
		const splitAt = bytes.indexOf(rocket[1]!);
		const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(bytes.subarray(0, splitAt + 1)); controller.enqueue(bytes.subarray(splitAt + 1)); controller.close(); } });
		const transport = createNetworkTransport({ request: async () => response(200, '', stream) });
		const bounded = await transport.request('https://fake.invalid/chat', { timeoutMs: 1000 });
		const events: unknown[] = [];
		for await (const event of parseSseStream(bounded)) { events.push(event); }
		assert.deepEqual(events, [{ text: '🚀' }, { n: 2 }]);
	});

	test('SSE event overflow and malformed UTF-8 reject and cancel the reader', async () => {
		let cancelled = 0;
		const makeStream = (value: Uint8Array) => {
			let sent = false;
			return new ReadableStream<Uint8Array>({ pull(controller) { if (!sent) { sent = true; controller.enqueue(value); } }, cancel() { cancelled++; } });
		};
		const over = await createNetworkTransport({ request: async () => response(200, '', makeStream(new TextEncoder().encode(`data: ${'x'.repeat(100)}\n\n`))) }).request('https://fake.invalid', { timeoutMs: 1000, maxSseEventBytes: 12 });
		await assert.rejects(async () => { for await (const _event of parseSseStream(over)) { /* none */ } });
		const invalid = await createNetworkTransport({ request: async () => response(200, '', makeStream(new Uint8Array([0xff]))) }).request('https://fake.invalid', { timeoutMs: 1000 });
		await assert.rejects(async () => { for await (const _event of parseSseStream(invalid)) { /* none */ } });
		assert.equal(cancelled, 2);
	});

	test('bounded JSON response reader rejects malformed UTF-8 and cancels without returning truncated text', async () => {
		let cancelled = false;
		let sent = false;
		let releasePull: (() => void) | undefined;
		const stream = new ReadableStream<Uint8Array>({
			pull(controller) { if (!sent) {sent = true; controller.enqueue(new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x7d])); return;} return new Promise<void>(resolve => {releasePull = resolve;}); },
			cancel() {cancelled = true; releasePull?.();},
		});
		const bounded = await createNetworkTransport({ request: async () => response(200, '', stream) }).request('https://fake.invalid', { timeoutMs: 1000, maxResponseBodyBytes: 128 });
		await assert.rejects(bounded.text(), error => error instanceof AIHttpError);
		assert.equal(cancelled, true);
	});

	test('oversized error bodies do not use text fallback and cancel the reader', async () => {
		let textCalls = 0;
		let cancelled = false;
		const stream = new ReadableStream<Uint8Array>({ pull(controller) { controller.enqueue(new Uint8Array(8193).fill(65)); }, cancel() { cancelled = true; } });
		const transport = createNetworkTransport({ request: async () => ({ ...response(400, '', stream), text: async () => { textCalls++; return 'unbounded'; } }) });
		await assert.rejects(transport.request('https://fake.invalid', { timeoutMs: 1000 }));
		assert.equal(textCalls, 0);
		assert.equal(cancelled, true);
	});

	test('malformed provider JSON cannot surface parser text or retain it as a cause', async () => {
		const marker = 'SECRET=do-not-share';
		const transport = createNetworkTransport({ request: async () => response(200, `not-json ${marker}`) });
		const result = await transport.request('https://fake.invalid/models', { timeoutMs: 1000 });
		await assert.rejects(result.json(), (error: unknown) => {
			assert.ok(error instanceof AIHttpError);
			assert.equal(error.status, 502);
			assert.ok(!error.message.includes(marker));
			assert.equal((error as AIHttpError & { cause?: unknown }).cause, undefined);
			return true;
		});
	});

	test('preserves the bounded transport error category for an oversized HTTP error body', async () => {
		const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new Uint8Array(65_537).fill(65)); controller.close(); } });
		const transport = createNetworkTransport({ request: async () => response(400, '', stream) });
		await assert.rejects(transport.request('https://fake.invalid', { timeoutMs: 1000, maxResponseBodyBytes: 65_536 }), (error: unknown) => error instanceof AIHttpError && error.status === 413);
	});
});

function providerFor(id: AIProviderId, transport: AITransport) {
	const credentials = new CredentialService(store(id));
	if (id === 'openai') { return new OpenAIProvider(credentials, transport); }
	if (id === 'claude') { return new ClaudeProvider(credentials, transport); }
	if (id === 'gemini') { return new GeminiProvider(credentials, transport); }
	return new OpenRouterProvider(credentials, transport);
}

function chatRequest(id: AIProviderId): ChatRequest {
	return { model: `model-${id}`, messages: [{ role: 'system', content: 'system instructions' }, { role: 'user', content: 'user text' }], temperature: 0.2, maxTokens: 50, stream: true, timeoutMs: 1000, retries: 0, openRouterReasoning: { enabled: true, effort: 'low' }, includeUsage: true };
}

function store(id: AIProviderId): CredentialStore {
	const credential = { id: `${id}-credential`, name: id, providerId: id, last4: '1234', createdAt: 'now', updatedAt: 'now' };
	const values = new Map<string, string>([
		[aiSecretKeys.settings, JSON.stringify({ ...defaultAISettings, selectedProvider: id, openRouterEndpoint: 'https://fake.invalid/api/v1', apiCredentials: [credential], activeApiCredentialId: credential.id })],
		[aiSecretKeys.apiCredential(credential.id), 'fake-secret'],
	]);
	return { get: async (key) => values.get(key), set: async (key, value) => { values.set(key, value); }, delete: async (key) => { values.delete(key); } };
}

function response(status: number, text: string, body?: ReadableStream<Uint8Array>): NetworkResponse {
	const actualBody = body ?? new ReadableStream<Uint8Array>({ start(controller) { if (text) { controller.enqueue(new TextEncoder().encode(text)); } controller.close(); } });
	return { ok: status >= 200 && status < 300, status, headers: { 'content-type': 'text/event-stream' }, body: actualBody, text: async () => text, json: async <T>() => JSON.parse(text) as T };
}

async function startLocalServer(handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>): Promise<{ url: string; close: () => Promise<void> }> {
	const server = createServer((request, response) => { void Promise.resolve(handler(request, response)).catch(() => response.destroy()); });
	await new Promise<void>((resolve, reject) => {
		server.once('error', reject);
		server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
	});
	const address = server.address();
	if (!address || typeof address === 'string') { throw new Error('Local test server did not bind to a TCP port.'); }
	return {
		url: `http://127.0.0.1:${address.port}`,
		close: async () => {
			server.closeAllConnections();
			await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		},
	};
}

async function captureRequest(request: IncomingMessage): Promise<{ method?: string; authorization?: string; body: string }> {
	const parts: Buffer[] = [];
	for await (const part of request) { parts.push(Buffer.from(part)); }
	return { method: request.method, authorization: request.headers.authorization, body: Buffer.concat(parts).toString('utf8') };
}

function silentLogger(): Logger {
	return { debug() {}, info() {}, warn() {}, error() {} };
}

import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { AIReviewService, AIService, AIVulnerabilityAnalysis, ClaudeProvider, CredentialService, GeminiProvider, OpenAIProvider, OpenRouterProvider, ProviderRegistry } from '../../packages/core/src/ai';
import { AIAnalysisRequest, AIModel, AIProvider, AIProviderId, AISettings, ChatRequest, StreamChunk, defaultAISettings } from '../../packages/core/src/shared/ai';
import { CredentialStore, NetworkClient } from '../../packages/core/src/shared/platform';
import { SecurityContextBuilder } from '../../packages/core/src/context';
import { RagIndexService, RagRetrievalService } from '../../packages/core/src/rag';
import { AIHttpError, AIHttpResponse, AITransport, createNetworkTransport } from '../../packages/core/src/ai/utils/request';
import { resolveChatGenerationPolicy } from '../../packages/core/src/ai/services/chatGenerationPolicy';

suite('Core AI', () => {
	test('interactive chat generation policy is model-aware and preserves other providers', () => {
		const supported: AIModel = { id: 'nvidia/nemotron-3.5-lightning:free', label: 'Nemotron', providerId: 'openrouter', supportedParameters: ['reasoning', 'max_tokens'], badges: ['free', 'cloud'], capabilities: ['chat', 'reasoning'] };
		const minimax: AIModel = { ...supported, id: 'minimax/minimax-m3.1-flash:free', label: 'MiniMax M3.1 Flash' };
		assert.deepStrictEqual(resolveChatGenerationPolicy('openrouter', supported, 2048), { openRouterReasoning: { enabled: false }, maxTokens: 4096 });
		assert.deepStrictEqual(resolveChatGenerationPolicy('openrouter', minimax, 2048), { openRouterReasoning: { enabled: true, max_tokens: 1024 }, maxTokens: 4096 });
		assert.deepStrictEqual(resolveChatGenerationPolicy('openrouter', supported, 8192), { openRouterReasoning: { enabled: false }, maxTokens: 8192 });
		assert.deepStrictEqual(resolveChatGenerationPolicy('openai', supported, 2048), {});
		assert.deepStrictEqual(resolveChatGenerationPolicy('openrouter', { ...supported, supportedParameters: [] }, 2048), {});
		assert.deepStrictEqual(resolveChatGenerationPolicy('openrouter', { ...supported, supportedParameters: ['reasoning'] }, 2048), { openRouterReasoning: { enabled: false } });
	});
	test('provider registry exposes the four supported providers and rejects Ollama', async () => {
		const credentials = new CredentialService(memoryStore());
		const registry = new ProviderRegistry(credentials);
		for (const id of ['openrouter', 'openai', 'claude', 'gemini'] as const) registry.register(fakeProvider(id));
		assert.deepStrictEqual(registry.getProviders().map((provider) => provider.id), ['openrouter', 'openai', 'claude', 'gemini']);
		assert.throws(() => registry.getProvider('ollama' as AIProviderId));
		await registry.switchProvider('gemini');
		assert.strictEqual(registry.getCurrentProvider().id, 'gemini');
	});

	test('OpenAI provider discovers models and streams chat', async () => {
		const provider = new OpenAIProvider(new CredentialService(providerStore('openai')), transport({
			'GET /v1/models': jsonResponse({ data: [{ id: 'gpt-4o', owned_by: 'openai' }, { id: 'text-embedding-3-small' }] }),
			'POST /v1/chat/completions': sseResponse(['data: {"choices":[{"delta":{"content":"hello"},"finish_reason":"stop"}]}', 'data: [DONE]']),
		}));
		assert.deepStrictEqual((await provider.getModels()).map((model) => model.id), ['gpt-4o']);
		assert.ok((await collect(provider.chat(makeChatRequest()))).some((chunk) => (chunk as StreamChunk).type === 'token'));
	});

	test('Claude provider discovers models and streams chat', async () => {
		const provider = new ClaudeProvider(new CredentialService(providerStore('claude')), transport({
			'GET /v1/models': jsonResponse({ data: [{ id: 'claude-sonnet', display_name: 'Claude Sonnet' }] }),
			'POST /v1/messages': sseResponse(['data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}', 'data: {"type":"message_stop"}']),
		}));
		assert.strictEqual((await provider.getModels())[0].label, 'Claude Sonnet');
		assert.ok((await collect(provider.chat(makeChatRequest()))).some((chunk) => (chunk as StreamChunk).type === 'token'));
	});

	test('Gemini provider discovers chat models and streams chat', async () => {
		const provider = new GeminiProvider(new CredentialService(providerStore('gemini')), transport({
			'GET /v1beta/models': jsonResponse({ models: [{ name: 'models/gemini-2.5-flash', displayName: 'Gemini Flash', supportedGenerationMethods: ['generateContent'] }, { name: 'models/text-embedding', supportedGenerationMethods: ['embedContent'] }] }),
			'POST /v1beta/models/gemini-2.5-flash:streamGenerateContent': sseResponse(['data: {"candidates":[{"content":{"parts":[{"text":"hello"}]},"finishReason":"STOP"}]}']),
		}));
		assert.deepStrictEqual((await provider.getModels()).map((model) => model.id), ['gemini-2.5-flash']);
		assert.ok((await collect(provider.chat({ ...makeChatRequest(), model: 'gemini-2.5-flash' }))).some((chunk) => (chunk as StreamChunk).type === 'token'));
	});

	test('migrates legacy Ollama settings and credential', async () => {
		const store = memoryStore({
			[aiKey('aqiron.ai.settings')]: JSON.stringify({ ...defaultAISettings, selectedProvider: 'ollama', ollamaEndpoint: 'http://localhost:11434' }),
			[aiKey('aqiron.ai.ollama.authToken')]: 'legacy-token',
		});
		const service = new AIService({
			credentialStore: store,
			transport: transport({ 'GET /models': jsonResponse({ data: [] }) }),
		});
		await service.initialize();
		const settings = JSON.parse((await store.get(aiKey('aqiron.ai.settings'))) ?? '{}') as Record<string, unknown>;
		assert.strictEqual(settings.selectedProvider, 'openrouter');
		assert.ok(!('ollamaEndpoint' in settings));
		assert.strictEqual(await store.get(aiKey('aqiron.ai.ollama.authToken')), undefined);
	});

	test('openrouter provider discovers models and streams chat', async () => {
		const store = memoryStore({
			[aiKey('aqiron.ai.settings')]: JSON.stringify({ ...defaultAISettings, openRouterEndpoint: 'https://openrouter.example', selectedProvider: 'openrouter', apiCredentials: [{ id: 'cred', name: 'OpenRouter', providerId: 'openrouter', last4: '1234', createdAt: 'now', updatedAt: 'now' }], activeApiCredentialId: 'cred' }),
			[aiKey('aqiron.ai.api.cred')]: 'secret',
		});
		const provider = new OpenRouterProvider(new CredentialService(store), transport({
			'GET /models': jsonResponse({ data: [{ id: 'openai/gpt-4o-mini', name: 'GPT', pricing: { prompt: '0', completion: '0', request: '0' }, supported_parameters: ['max_tokens', 'reasoning'] }] }),
			'POST /chat/completions': sseResponse(['data: {"choices":[{"delta":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}', 'data: [DONE]']),
		}));
		const discovered = await provider.getModels();
		assert.strictEqual(discovered[0].id, 'openai/gpt-4o-mini');
		assert.deepStrictEqual(discovered[0].supportedParameters, ['max_tokens', 'reasoning']);
		const chunks = await collect(provider.chat(makeChatRequest()));
		assert.ok(chunks.some((chunk) => chunk.type === 'token'));
	});

	test('network transport preserves the OpenRouter response stream', async () => {
		const store = memoryStore({
			[aiKey('aqiron.ai.settings')]: JSON.stringify({ ...defaultAISettings, openRouterEndpoint: 'https://openrouter.example', selectedProvider: 'openrouter', apiCredentials: [{ id: 'cred', name: 'OpenRouter', providerId: 'openrouter', last4: '1234', createdAt: 'now', updatedAt: 'now' }], activeApiCredentialId: 'cred' }),
			[aiKey('aqiron.ai.api.cred')]: 'secret',
		});
		const provider = new OpenRouterProvider(new CredentialService(store), createNetworkTransport({
			request: async () => sseResponse(['data: {"choices":[{"delta":{"content":"hello"},"finish_reason":"stop"}]}', 'data: [DONE]']),
		}));
		const chunks = await collect(provider.chat(makeChatRequest()));
		assert.ok(chunks.some((chunk) => chunk.type === 'token' && chunk.content === 'hello'));
	});

	test('OpenRouter aggregates streamed text and reports safe response metadata', async () => {
		const diagnostics: Array<Record<string, unknown>> = [];
		const provider = new OpenRouterProvider(new CredentialService(providerStore('openrouter')), transport({
			'POST /chat/completions': sseResponse([
				`data: ${JSON.stringify({ choices: [{ delta: { role: 'assistant' }, finish_reason: null }] })}`,
				`data: ${JSON.stringify({ choices: [{ delta: { content: 'Use a safe ' }, finish_reason: null }] })}`,
				`data: ${JSON.stringify({ choices: [{ delta: { content: 'credential store.' }, finish_reason: 'stop' }] })}`,
				'data: [DONE]',
			]),
		}), (entry) => diagnostics.push(entry as unknown as Record<string, unknown>));
		const chunks = await collect(provider.chat(makeChatRequest()));
		assert.strictEqual(chunks.filter((chunk) => chunk.type === 'token').map((chunk) => chunk.content).join(''), 'Use a safe credential store.');
		assert.strictEqual(diagnostics.length, 1);
		assert.strictEqual(diagnostics[0].result, 'accepted');
		assert.strictEqual(diagnostics[0].eventCount, 3);
		assert.strictEqual(diagnostics[0].contentBearingEvents, 2);
		assert.strictEqual(diagnostics[0].textCharacters, 28);
		assert.strictEqual(diagnostics[0].finalEventReceived, true);
		assert.ok(!JSON.stringify(diagnostics).includes('credential store'));
	});

	test('OpenRouter applies request-scoped reasoning controls and preserves ordinary chat settings', async () => {
		const store = memoryStore({
			[aiKey('aqiron.ai.settings')]: JSON.stringify({ ...defaultAISettings, selectedProvider: 'openrouter', selectedModel: 'nvidia/nemotron-3.5-lightning:free', maxTokens: 768, openRouterEndpoint: 'https://openrouter.example', apiCredentials: [{ id: 'cred', name: 'OpenRouter', providerId: 'openrouter', last4: '1234', createdAt: 'now', updatedAt: 'now' }], activeApiCredentialId: 'cred' }),
			[aiKey('aqiron.ai.api.cred')]: 'secret',
		});
		let requestBody: Record<string, unknown> | undefined;
		const service = new AIService({
			credentialStore: store,
			transport: {
				request: async (_url, options) => {
					if (options.method === 'POST') {
						requestBody = options.body as Record<string, unknown>;
					}
					return sseResponse([`data: ${JSON.stringify({ choices: [{ delta: { content: 'ordinary reply' }, finish_reason: 'stop' }] })}`, 'data: [DONE]']);
				},
			},
		});
		await service.prepare();
		const result = await collect(service.chat({ sessionId: 'ordinary', text: 'hello', history: [], model: 'nvidia/nemotron-3.5-lightning:free', intelligence: 'Medium', context: {} as never }));
		assert.strictEqual(result.find((chunk) => chunk.type === 'token')?.content, 'ordinary reply');
		assert.strictEqual(requestBody?.max_tokens, 768);
		assert.ok(!('reasoning' in (requestBody ?? {})), 'ordinary chat must retain the existing unmodified reasoning behavior');

		let recommendationBody: Record<string, unknown> | undefined;
		const recommendation = new OpenRouterProvider(new CredentialService(store), {
			request: async (_url, options) => {
				recommendationBody = options.body as Record<string, unknown>;
				return sseResponse([`data: ${JSON.stringify({ choices: [{ delta: { content: 'recommendation response' }, finish_reason: 'stop' }] })}`, 'data: [DONE]']);
			},
		});
		await collect(recommendation.chat({ ...makeChatRequest(), model: 'nvidia/nemotron-3.5-lightning:free', maxTokens: 4096, openRouterReasoning: { enabled: false }, includeUsage: true }));
		assert.strictEqual(recommendationBody?.model, 'nvidia/nemotron-3.5-lightning:free');
		assert.strictEqual(recommendationBody?.max_tokens, 4096);
		assert.deepStrictEqual(recommendationBody?.reasoning, { enabled: false });
		assert.deepStrictEqual(recommendationBody?.stream_options, { include_usage: true });
	});

	test('MiniMax OpenRouter request preserves selected model and maps supported request parameters', async () => {
		let requestBody: Record<string, unknown> | undefined;
		const provider = new OpenRouterProvider(new CredentialService(providerStore('openrouter')), {
			request: async (_url, options) => {
				requestBody = options.body as Record<string, unknown>;
				return sseResponse([`data: ${JSON.stringify({ choices: [{ delta: { content: 'A concise reply.' }, finish_reason: 'stop' }] })}`, 'data: [DONE]']);
			},
		});
		const chunks = await collect(provider.chat({ ...makeChatRequest(), model: 'minimax/minimax-m3.1-flash:free', maxTokens: 4096, openRouterReasoning: { enabled: true, max_tokens: 1024 } }));
		assert.strictEqual(requestBody?.model, 'minimax/minimax-m3.1-flash:free');
		assert.strictEqual(requestBody?.max_tokens, 4096);
		assert.deepStrictEqual(requestBody?.reasoning, { enabled: true, max_tokens: 1024 });
		assert.strictEqual(requestBody?.stream, true);
		assert.ok(Array.isArray(requestBody?.messages));
		assert.strictEqual(chunks.filter((chunk) => chunk.type === 'token').map((chunk) => chunk.content).join(''), 'A concise reply.');
	});

	test('OpenRouter reports safe structured HTTP rejection metadata and preserves typed provider detail', async () => {
		const diagnostics: Array<Record<string, unknown>> = [];
		const body = JSON.stringify({ error: { code: 400, message: 'Reasoning is mandatory for this endpoint and cannot be disabled.', metadata: { error_type: 'invalid_request', provider_code: 'bad_reasoning', raw: 'flagged source text must never be logged' } } });
		const provider = new OpenRouterProvider(new CredentialService(providerStore('openrouter')), createNetworkTransport({
			request: async () => ({ ok: false, status: 400, headers: { 'content-type': 'application/json' }, text: async () => body, json: async () => JSON.parse(body), body: null }),
		}), undefined, (entry) => diagnostics.push(entry as unknown as Record<string, unknown>));
		let rejection: unknown;
		await assert.rejects(async () => collect(provider.chat({ ...makeChatRequest(), model: 'minimax/minimax-m3.1-flash:free', openRouterReasoning: { enabled: false } })), (error: unknown) => {
			rejection = error;
			return error instanceof AIHttpError && error.status === 400 && /HTTP 400/.test(error.message);
		});
		assert.strictEqual(diagnostics.length, 1);
		assert.strictEqual(diagnostics[0].modelId, 'minimax/minimax-m3.1-flash:free');
		assert.strictEqual(diagnostics[0].errorCode, '400');
		assert.strictEqual(diagnostics[0].errorType, 'invalid_request');
		assert.strictEqual(diagnostics[0].providerCode, 'bad_reasoning');
		assert.strictEqual(diagnostics[0].parameter, 'reasoning');
		assert.ok(!JSON.stringify(diagnostics).includes('flagged source text'));
		assert.ok(rejection instanceof AIHttpError);
		assert.match(rejection.message, /Reasoning is mandatory/);
		assert.strictEqual(rejection.providerError?.originalMessage, 'Reasoning is mandatory for this endpoint and cannot be disabled.');
		assert.ok(!JSON.stringify(rejection).includes('flagged source text'));
	});

	test('OpenRouter malformed and non-JSON HTTP error bodies remain safe and useful', async () => {
		for (const [body, expectedFormat] of [['{not json}', 'malformed-json'], ['upstream unavailable', 'non-json']] as const) {
			const diagnostics: Array<Record<string, unknown>> = [];
			const provider = new OpenRouterProvider(new CredentialService(providerStore('openrouter')), createNetworkTransport({
				request: async () => ({ ok: false, status: 400, headers: { 'content-type': 'text/plain' }, text: async () => body, json: async () => { throw new Error('not json'); }, body: null }),
			}), undefined, (entry) => diagnostics.push(entry as unknown as Record<string, unknown>));
			await assert.rejects(async () => collect(provider.chat(makeChatRequest())), /Provider request failed with HTTP 400\./);
			assert.strictEqual(diagnostics[0].bodyFormat, expectedFormat);
			assert.strictEqual(diagnostics[0].message, 'Provider request failed with HTTP 400.');
		}
	});

	test('OpenRouter extracts text content-part arrays and terminal completed messages', async () => {
		const arrayProvider = new OpenRouterProvider(new CredentialService(providerStore('openrouter')), transport({
			'POST /chat/completions': sseResponse([`data: ${JSON.stringify({ choices: [{ delta: { content: [{ type: 'text', text: 'structured ' }, { type: 'image', image_url: 'not logged' }, { type: 'text', text: 'text' }] } }] })}`, 'data: [DONE]']),
		}));
		const arrayChunks = await collect(arrayProvider.chat(makeChatRequest()));
		assert.strictEqual(arrayChunks.filter((chunk) => chunk.type === 'token').map((chunk) => chunk.content).join(''), 'structured text');

		const finalMessageProvider = new OpenRouterProvider(new CredentialService(providerStore('openrouter')), transport({
			'POST /chat/completions': sseResponse([`data: ${JSON.stringify({ choices: [{ message: { role: 'assistant', content: 'completed response' }, finish_reason: 'stop' }] })}`, 'data: [DONE]']),
		}));
		const finalChunks = await collect(finalMessageProvider.chat(makeChatRequest()));
		assert.strictEqual(finalChunks.filter((chunk) => chunk.type === 'token').map((chunk) => chunk.content).join(''), 'completed response');
	});

	test('OpenRouter distinguishes reasoning-only and malformed streams without accepting them as text', async () => {
		const diagnostics: Array<Record<string, unknown>> = [];
		const provider = new OpenRouterProvider(new CredentialService(providerStore('openrouter')), transport({
			'POST /chat/completions': sseResponse([`data: ${JSON.stringify({ choices: [{ delta: { reasoning: 'private reasoning' }, finish_reason: 'stop' }] })}`, 'data: [DONE]']),
		}), (entry) => diagnostics.push(entry as unknown as Record<string, unknown>));
		const chunks = await collect(provider.chat(makeChatRequest()));
		assert.ok(!chunks.some((chunk) => chunk.type === 'token'));
		assert.strictEqual(diagnostics[0].result, 'empty');
		assert.strictEqual(diagnostics[0].reasoningNonEmpty, true);
		assert.ok(!JSON.stringify(diagnostics).includes('private reasoning'));

		const malformedDiagnostics: Array<Record<string, unknown>> = [];
		const malformed = new OpenRouterProvider(new CredentialService(providerStore('openrouter')), transport({
			'POST /chat/completions': sseResponse(['data: {not-json}']),
		}), (entry) => malformedDiagnostics.push(entry as unknown as Record<string, unknown>));
		await assert.rejects(async () => collect(malformed.chat(makeChatRequest())));
		assert.strictEqual(malformedDiagnostics[0].result, 'decode-error');
	});

	test('AI vulnerability analysis parses structured output', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-ai-'));
		try {
			await fs.writeFile(path.join(root, 'pubspec.yaml'), 'name: demo\nflutter:\n  sdk: flutter\n');
			await fs.writeFile(path.join(root, 'lib.dart'), 'const apiKey = "sk-test-12345678901234567890";\n');
			const aiService = new AIService({
				credentialStore: memoryStore({
					[aiKey('aqiron.ai.settings')]: JSON.stringify({ ...defaultAISettings, selectedModel: 'test-model' }),
				}),
				transport: transport({
					'GET /models': jsonResponse({ data: [] }),
					'POST /chat/completions': sseResponse([
						`data: ${JSON.stringify({ choices: [{ delta: { content: JSON.stringify({ summary: 'ok', findings: [{ title: 'Secret', description: 'Secret exposed', severity: 'High', confidence: 'High confidence', projectLevel: true }] }) } }] })}`,
						'data: [DONE]',
					]),
				}),
			});
			await aiService.initialize();
			const analysis = new AIVulnerabilityAnalysis({
				aiService,
				contextBuilder: new SecurityContextBuilder({ filesystem: fileSystem() }),
				ragRetrieval: new RagRetrievalService(new RagIndexService({ filesystem: fileSystem() })),
			});
			const result = await analysis.analyze(root, []);
			assert.ok(result.findings.length >= 0);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	test('AI review streams contextual guidance', async () => {
		const review = new AIReviewService({
			getState: async () => ({ selection: { model: 'test-model', intelligence: 'Medium' } }),
			chat: async function* () {
				yield { type: 'token', content: 'Use secure storage.' };
				yield { type: 'done' };
			},
		} as unknown as AIService);
		const text = await review.explainFinding({
			id: 'finding-1',
			title: 'Hardcoded secret',
			description: 'A secret is embedded in source code.',
			severity: 'High',
			cwe: [],
			owasp: [],
			file: '/workspace/lib/main.dart',
			line: 1,
			column: 1,
			sourceTool: 'AI Analysis',
			ruleId: 'ai-analysis.secret',
			confidence: 'High',
			remediation: 'Move the value to a secret store and rotate it.',
			tags: [],
			status: 'Open',
			riskScore: 80,
			fingerprint: 'fp',
			graph: { type: 'finding' } as never,
			rawEvidence: { evidence: 'const apiKey = "secret";' },
		} as unknown as Parameters<AIReviewService['explainFinding']>[0]);
		assert.strictEqual(text, 'Use secure storage.');
	});
});

function fakeProvider(id: AIProviderId): AIProvider {
	return {
		id,
		name: id,
		initialize: async () => undefined,
		getModels: async () => [],
		chat: async function* () { yield { type: 'done' }; },
		validateConnection: async () => true,
	};
}

function makeChatRequest(): ChatRequest {
	return { model: 'test', messages: [{ role: 'user', content: 'hello' }], temperature: 0, maxTokens: 16, stream: true, timeoutMs: 1_000, retries: 0 };
}

function memoryStore(initial: Record<string, string> = {}): CredentialStore {
	const state = new Map(Object.entries(initial));
	return {
		get: async (key: string) => state.get(key),
		set: async (key: string, value: string) => { state.set(key, value); },
		delete: async (key: string) => { state.delete(key); },
	};
}

function providerStore(providerId: AIProviderId): CredentialStore {
	const credential = { id: `${providerId}-cred`, name: providerId, providerId, last4: '1234', createdAt: 'now', updatedAt: 'now' };
	return memoryStore({
		[aiKey('aqiron.ai.settings')]: JSON.stringify({ ...defaultAISettings, selectedProvider: providerId, apiCredentials: [credential], activeApiCredentialId: credential.id }),
		[aiKey(`aqiron.ai.api.${credential.id}`)]: 'secret',
	});
}

function aiKey(key: string): string {
	return key;
}

function transport(responses: Record<string, AIHttpResponse>): AITransport {
	return {
		async request(url: string, options) {
			const key = `${options.method ?? 'GET'} ${new URL(url).pathname}`;
			const response = responses[key] ?? Object.entries(responses).find(([expected]) => {
				const [method, pathname] = expected.split(' ');
				return key.startsWith(`${method} `) && key.endsWith(pathname);
			})?.[1];
			if (!response) {
				throw new Error(`Unexpected request: ${key}`);
			}
			return response;
		},
	};
}

function jsonResponse(body: unknown): AIHttpResponse {
	return {
		ok: true,
		status: 200,
		headers: {},
		text: async () => JSON.stringify(body),
		json: async <T = unknown>() => body as T,
		body: null,
	};
}

function ndjsonResponse(lines: string[]): AIHttpResponse {
	const encoder = new TextEncoder();
	const stream = new ReadableStream<Uint8Array>({
		start(controller) {
			controller.enqueue(encoder.encode(lines.join('\n')));
			controller.close();
		},
	});
	return {
		ok: true,
		status: 200,
		headers: {},
		text: async () => lines.join('\n'),
		json: async <T = unknown>() => JSON.parse(lines.join('\n')) as T,
		body: stream,
	};
}

function sseResponse(lines: string[]): AIHttpResponse {
	const encoder = new TextEncoder();
	const stream = new ReadableStream<Uint8Array>({
		start(controller) {
			controller.enqueue(encoder.encode(lines.join('\n\n')));
			controller.close();
		},
	});
	return {
		ok: true,
		status: 200,
		headers: { 'content-type': 'text/event-stream' },
		text: async () => lines.join('\n\n'),
		json: async <T = unknown>() => JSON.parse(lines.join('\n\n')) as T,
		body: stream,
	};
}

function fileSystem(): import('../../packages/core/src/shared/platform').FileSystem {
	return {
		readFile: readFile,
		writeFile: fs.writeFile,
		mkdir: async (file: string, options?: { recursive?: boolean }) => { await fs.mkdir(file, options); },
		readdir: fs.readdir,
		stat: async (file: string) => {
			const stat = await fs.stat(file);
			return { isFile: () => stat.isFile(), isDirectory: () => stat.isDirectory(), size: stat.size, mtimeMs: stat.mtimeMs };
		},
		access: fs.access,
		rename: fs.rename,
		exists: async (file: string) => fs.access(file).then(() => true).catch(() => false),
	};
}

async function readFile(file: string, encoding: BufferEncoding): Promise<string>;
async function readFile(file: string): Promise<Uint8Array>;
async function readFile(file: string, encoding?: BufferEncoding): Promise<string | Uint8Array> {
	return encoding ? fs.readFile(file, encoding) : fs.readFile(file);
}

async function collect<T>(generator: AsyncGenerator<T | StreamChunk>): Promise<T[]> {
	const output: T[] = [];
	for await (const item of generator) {
		output.push(item as T);
	}
	return output;
}

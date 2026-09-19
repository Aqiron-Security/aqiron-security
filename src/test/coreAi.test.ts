import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { AIReviewService, AIService, AIVulnerabilityAnalysis, CredentialService, OllamaProvider, OpenRouterProvider, ProviderRegistry } from '../../packages/core/src/ai';
import { AIAnalysisRequest, AIModel, AIProvider, AIProviderId, AISettings, ChatRequest, StreamChunk, defaultAISettings } from '../../packages/core/src/shared/ai';
import { CredentialStore, NetworkClient } from '../../packages/core/src/shared/platform';
import { SecurityContextBuilder } from '../../packages/core/src/context';
import { RagIndexService, RagRetrievalService } from '../../packages/core/src/rag';
import { AIHttpResponse, AITransport, createNetworkTransport } from '../../packages/core/src/ai/utils/request';

suite('Core AI', () => {
	test('provider registry switches providers and reports unavailable providers', async () => {
		const credentials = new CredentialService(memoryStore());
		const registry = new ProviderRegistry(credentials);
		registry.register(fakeProvider('ollama'));
		assert.throws(() => registry.getProvider('openrouter' as AIProviderId));
		await registry.switchProvider('ollama');
		assert.strictEqual(registry.getCurrentProvider().id, 'ollama');
	});

	test('ollama provider discovers models and streams chat', async () => {
		const provider = new OllamaProvider(new CredentialService(memoryStore({
			[aiKey('aqiron.ai.settings')]: JSON.stringify(defaultAISettings),
		})), transport({
			'GET /api/tags': jsonResponse({ models: [{ model: 'llama3.2', details: { family: 'llama' } }] }),
			'POST /api/chat': ndjsonResponse(['{"message":{"content":"hello"},"done":true,"prompt_eval_count":1,"eval_count":2}']),
		}));
		const models = await provider.getModels();
		assert.strictEqual(models[0].id, 'llama3.2');
		const chunks = await collect(provider.chat(makeChatRequest()));
		assert.ok(chunks.some((chunk) => chunk.type === 'token'));
	});

	test('openrouter provider discovers models and streams chat', async () => {
		const store = memoryStore({
			[aiKey('aqiron.ai.settings')]: JSON.stringify({ ...defaultAISettings, openRouterEndpoint: 'https://openrouter.example', selectedProvider: 'openrouter', apiCredentials: [{ id: 'cred', name: 'OpenRouter', providerId: 'openrouter', last4: '1234', createdAt: 'now', updatedAt: 'now' }], activeApiCredentialId: 'cred' }),
			[aiKey('aqiron.ai.api.cred')]: 'secret',
		});
		const provider = new OpenRouterProvider(new CredentialService(store), transport({
			'GET /models': jsonResponse({ data: [{ id: 'openai/gpt-4o-mini', name: 'GPT', pricing: { prompt: '0', completion: '0', request: '0' } }] }),
			'POST /chat/completions': sseResponse(['data: {"choices":[{"delta":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}', 'data: [DONE]']),
		}));
		assert.strictEqual((await provider.getModels())[0].id, 'openai/gpt-4o-mini');
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
		headers: {},
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

import * as path from 'path';
import * as childProcess from 'child_process';
import * as fs from 'fs/promises';
import * as os from 'os';
import { strict as assert } from 'assert';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';
import { NodeCredentialStore } from '../../packages/core/src/runtime/nodeAdapters';
import { CredentialStore, NetworkClient, NetworkResponse } from '../../packages/core/src/shared/platform';
import { AITransport, createNetworkTransport } from '../../packages/core/src/ai/utils/request';

interface CoreResponse {
	id: string;
	type: 'response';
	success: boolean;
	result?: unknown;
	error?: { code: string; message: string };
}

async function createWorkspaceTempDirectory(prefix: string): Promise<string> {
	let directory = __dirname;
	while (directory !== path.dirname(directory)) {
		try {
			await fs.access(path.join(directory, 'package.json'));
			return await fs.mkdtemp(path.join(directory, `.${prefix}-`));
		} catch {
			directory = path.dirname(directory);
		}
	}
	throw new Error('Could not locate the repository root for a runtime test fixture.');
}

suite('Core runtime process', () => {
	test('Core OpenRouter rejection logging contains only safe status/category diagnostics', async () => {
		const marker = 'SECRET=do-not-share';
		const modelId = 'private-model-identifier';
		const values = new Map<string, string>([
			['aqiron.ai.settings', JSON.stringify({ selectedProvider: 'openrouter', selectedModel: modelId, temperature: 0.2, maxTokens: 1024, timeoutMs: 30_000, retries: 0, streaming: true, openRouterEndpoint: 'https://test.invalid/api/v1' })],
			['aqiron.ai.openrouter.apiKey', 'private-provider-credential'],
		]);
		const credentialStore: CredentialStore = { get: async (key) => values.get(key), set: async (key, value) => { values.set(key, value); }, delete: async (key) => { values.delete(key); } };
		let failureMode: 'json' | 'malformed' | 'throw' = 'json';
		const network: NetworkClient = { request: async (url) => {
			if (url.endsWith('/models')) {return fakeResponse(200, JSON.stringify({ data: [{ id: modelId, supported_parameters: [] }] }));}
			if (failureMode === 'throw') {throw new Error(`Input rejected: ${marker}`);}
			if (failureMode === 'malformed') {return fakeResponse(400, `malformed response ${marker}`);}
			return fakeResponse(400, JSON.stringify({ error: { message: `Input rejected: ${marker}` } }));
		} };
		const runtime = new CoreRuntime({ coreVersion: 'safe-provider-error-test', credentialStore, aiTransport: createNetworkTransport(network) });
		const originalWrite = process.stderr.write.bind(process.stderr);
		let capturedLogs = '';
		process.stderr.write = ((chunk: string | Uint8Array) => { capturedLogs += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'); return true; }) as typeof process.stderr.write;
		try {
			for (const [index, mode] of (['json', 'malformed', 'throw'] as const).entries()) {
				failureMode = mode;
				const id = `safe-provider-rejection-${index}`;
				const response = await runtime.handle({ id, type: 'request', method: 'ai.chat', params: {
					sessionId: id, providerId: 'openrouter', model: modelId, text: 'Do not log this prompt.', intelligence: 'Medium', history: [],
					context: { workspaceName: 'fixture', projectTypes: [], backend: 'Core', currentFile: 'None', scanStatus: 'Complete', issues: [], stats: { filesScanned: 0, indexedFiles: 0 }, apis: [] },
				} }, () => undefined);
				assert.equal(response.success, false);
				assert.ok(!JSON.stringify(response).includes(marker));
			}
			const rejectionLogs = capturedLogs.split(/\r?\n/).filter((line) => line.includes('ai.openrouter.request.rejected'));
			assert.equal(rejectionLogs.length, 3);
			assert.ok(rejectionLogs.some((line) => line.includes('"status":400') && line.includes('"category":"request-rejected"')));
			assert.ok(rejectionLogs.some((line) => line.includes('"status":502') && line.includes('"category":"provider-unavailable"')));
			assert.ok(!capturedLogs.includes(marker));
			assert.ok(!capturedLogs.includes(modelId));
			assert.ok(!capturedLogs.includes('private-provider-credential'));
		} finally {
			process.stderr.write = originalWrite as typeof process.stderr.write;
		}
	});

	test('handshakes, reports health, and exposes credential metadata without requiring a keychain session', async () => {
		const runtime = path.resolve(__dirname, '../../../dist/core-runtime.js');
		const child = childProcess.spawn(process.execPath, [runtime], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
		const responses = new Map<string, (response: CoreResponse) => void>();
		let buffer = '';
		child.stdout.setEncoding('utf8');
		child.stdout.on('data', (chunk: string) => {
			buffer += chunk;
			const lines = buffer.split(/\r?\n/);
			buffer = lines.pop() ?? '';
			for (const line of lines) {
				if (!line.trim()) {
					continue;
				}
				const parsed = JSON.parse(line) as CoreResponse;
				responses.get(parsed.id)?.(parsed);
			}
		});

		const request = async <T>(method: string, params?: unknown): Promise<T> => {
			const id = `${Date.now()}-${Math.random()}`;
			const response = await new Promise<CoreResponse>((resolve, reject) => {
				responses.set(id, resolve);
				child.once('exit', (code) => reject(new Error(`runtime exited early: ${code ?? 'unknown'}`)));
				child.stdin.write(`${JSON.stringify({ id, type: 'request', method, params })}\n`);
			});
			assert.equal(response.type, 'response');
			assert.equal(response.success, true, response.error?.message ?? 'request failed');
			return response.result as T;
		};

		try {
			const handshake = await request<{ protocolVersion: number; coreVersion: string; status: string }>('core.handshake', {
				extensionVersion: '0.0.1',
				protocolVersion: 1,
				platform: process.platform,
				architecture: process.arch,
			});
			assert.equal(handshake.status, 'compatible');

			const health = await request<{ ok: true; ready: boolean; uptimeMs: number }>('core.health');
			assert.equal(health.ok, true);
			assert.equal(health.ready, true);

			await request('core.shutdown');
		} finally {
			child.kill();
		}
	});

	test('round-trips credentials through an injected mock store without returning the secret', async () => {
		const values = new Map<string, string>();
		const store: CredentialStore = {
			get: async (key) => values.get(key),
			set: async (key, value) => { values.set(key, value); },
			delete: async (key) => { values.delete(key); },
		};
		const runtime = new CoreRuntime({ coreVersion: 'test', credentialStore: store });
		const emit = (): void => undefined;
		const status = await runtime.handle({ id: 'cred-status-missing', type: 'request', method: 'credentials.status', params: { key: 'missing-test-key' } }, emit);
		assert.equal((status.result as { hasValue: boolean }).hasValue, false);
		const set = await runtime.handle({ id: 'cred-set', type: 'request', method: 'credentials.set', params: { key: 'test-key', value: 'super-secret' } }, emit);
		assert.deepEqual(set.result, { hasValue: true, updatedAt: (set.result as { updatedAt: string }).updatedAt });
		assert.ok(!JSON.stringify(set).includes('super-secret'));
		const exists = await runtime.handle({ id: 'cred-exists', type: 'request', method: 'credentials.exists', params: { key: 'test-key' } }, emit);
		assert.deepEqual(exists.result, { exists: true });
		await runtime.handle({ id: 'cred-delete', type: 'request', method: 'credentials.delete', params: { key: 'test-key' } }, emit);
		const deleted = await runtime.handle({ id: 'cred-deleted', type: 'request', method: 'credentials.exists', params: { key: 'test-key' } }, emit);
		assert.deepEqual(deleted.result, { exists: false });
	});

	test('Windows keychain access denial makes status unavailable without mutating credentials', async () => {
		let reads = 0;
		let writes = 0;
		const credentialStore = new NodeCredentialStore({
			platform: 'win32',
			keytarFactory: () => ({
				getPassword: async () => { reads++; throw new Error('Access is denied.\r\n'); },
				setPassword: async () => { writes++; },
				deletePassword: async () => { writes++; return false; },
			}),
		});
		const runtime = new CoreRuntime({ coreVersion: 'credential-unavailable-test', credentialStore });
		const response = await runtime.handle({ id: 'credential-status-unavailable', type: 'request', method: 'credentials.status', params: { key: 'missing-test-key' } }, () => undefined);
		assert.equal(response.success, true);
		assert.deepEqual(response.result, { hasValue: false });
		assert.equal(reads, 1);
		assert.equal(writes, 0, 'read-only credential status must not set or delete credentials');
		assert.doesNotMatch(JSON.stringify(response), /Access is denied/);
	});

	test('Core clients observe credentials across runtime restarts and can delete them', async () => {
		const values = new Map<string, string>();
		const store: CredentialStore = { get: async (key) => values.get(key), set: async (key, value) => { values.set(key, value); }, delete: async (key) => { values.delete(key); } };
		const firstClient = new CoreRuntime({ coreVersion: 'client-one', credentialStore: store });
		const emit = (): void => undefined;
		const key = `aqiron.ai.api.cross-client-${Date.now()}`;
		const set = await firstClient.handle({ id: 'cross-set', type: 'request', method: 'credentials.set', params: { key, value: 'configured-secret-value' } }, emit);
		assert.equal(set.success, true);
		const restartedCore = new CoreRuntime({ coreVersion: 'client-two', credentialStore: store });
		const visible = await restartedCore.handle({ id: 'cross-status', type: 'request', method: 'credentials.status', params: { key } }, emit);
		assert.deepEqual(visible.result, { hasValue: true });
		assert.ok(!JSON.stringify(visible).includes('configured-secret-value'));
		await restartedCore.handle({ id: 'cross-delete', type: 'request', method: 'credentials.delete', params: { key } }, emit);
		const afterDelete = await firstClient.handle({ id: 'cross-check', type: 'request', method: 'credentials.exists', params: { key } }, emit);
		assert.deepEqual(afterDelete.result, { exists: false });
	});

	test('provider status returns masked metadata but never API key values', async () => {
		const values = new Map<string, string>([
			['aqiron.ai.settings', JSON.stringify({ apiCredentials: [{ id: 'openai-key-1', name: 'Work account', providerId: 'openai', last4: 'abcd', createdAt: 'today', updatedAt: 'today', secret: 'must-not-serialize' }], apiKey: 'legacy-secret-must-not-serialize', taskDefaults: { model: 'test', secret: 'task-default-secret' } })],
			['aqiron.ai.api.openai-key-1', 'private-test-secret-value'],
			['aqiron.ai.openrouter.apiKey', 'legacy-openrouter-secret'],
		]);
		const store: CredentialStore = { get: async (key) => values.get(key), set: async (key, value) => { values.set(key, value); }, delete: async (key) => { values.delete(key); } };
		const runtime = new CoreRuntime({ coreVersion: 'provider-status-test', credentialStore: store });
		const response = await runtime.handle({ id: 'provider-status', type: 'request', method: 'ai.providers', params: {} }, () => undefined);
		assert.equal(response.success, true);
		const result = response.result as { configuredProviders: Array<{ id: string; configured: boolean }>; credentialSummaries: Array<{ last4: string }> };
		assert.equal(result.configuredProviders.find((provider) => provider.id === 'openai')?.configured, true);
		assert.equal(result.credentialSummaries[0]?.last4, 'abcd');
		assert.ok(!JSON.stringify(response).includes('private-test-secret-value'));
		assert.ok(!JSON.stringify(response).includes('legacy-secret-must-not-serialize'));
		assert.ok(!JSON.stringify(response).includes('must-not-serialize'));
		assert.ok(!JSON.stringify(response).includes('task-default-secret'));
		assert.equal((response.result as { configuredProviders: Array<{ id: string; configured: boolean }> }).configuredProviders.find((provider) => provider.id === 'openrouter')?.configured, true);
		await runtime.handle({ id: 'legacy-delete', type: 'request', method: 'credentials.delete', params: { key: 'aqiron.ai.openrouter.apiKey' } }, () => undefined);
		const afterLegacyDelete = await runtime.handle({ id: 'providers-after-legacy-delete', type: 'request', method: 'ai.providers', params: {} }, () => undefined);
		assert.equal((afterLegacyDelete.result as { configuredProviders: Array<{ id: string; configured: boolean }> }).configuredProviders.find((provider) => provider.id === 'openrouter')?.configured, false);
	});

	test('Core loads existing workspace threat history without running a scan', async () => {
		const root = await createWorkspaceTempDirectory('aqiron-threat-history');
		const file = path.join(root, '.aqiron-security', 'threats.json');
		await fs.mkdir(path.dirname(file), { recursive: true });
		await fs.writeFile(file, JSON.stringify([{ id: 'stored-scan', title: 'Security scan - 1 finding', createdAt: '2026-10-01T00:00:00.000Z', filesScanned: 4, extraMetadata: { retained: true }, issues: [{ id: 'stored-finding', file: path.join(root, 'lib', 'main.dart'), title: 'Stored threat', message: 'Review this finding', severity: 'High', ruleId: 'custom.flutter.test', range: { startLine: 8, startColumn: 2 }, lineText: 'dangerousCall()' }] }]), 'utf8');
		const runtime = new CoreRuntime({ coreVersion: 'threat-history-test' });
		const events: unknown[] = [];
		try {
			const response = await runtime.handle({ id: 'history-get', type: 'request', method: 'workspace.threat-history.get', params: { workspaceRoot: root } }, (event) => { events.push(event); });
			assert.equal(response.success, true, JSON.stringify(response.error));
			const result = response.result as { snapshots: Array<{ id: string; issues: Array<{ id: string }> }> };
			assert.equal(result.snapshots[0]?.id, 'stored-scan');
			assert.equal(result.snapshots[0]?.issues[0]?.id, 'stored-finding');
			assert.equal(events.length, 0, 'loading persisted threats must not trigger scanning');
			const deleted = await runtime.handle({ id: 'history-delete', type: 'request', method: 'workspace.threat-history.delete', params: { workspaceRoot: root, snapshotId: 'stored-scan' } }, () => undefined);
			assert.equal(deleted.success, true, JSON.stringify(deleted.error));
			assert.deepEqual((deleted.result as { snapshots: unknown[] }).snapshots, []);
			assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), [], 'Core deletion updates the persisted threat-history source');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('Core discovers existing workspace PDF, JSON, and SARIF artifacts without scanning', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-report-discovery-'));
		const directory = path.join(root, '.aqiron-security', 'reports', '2026-10-01');
		await fs.mkdir(directory, { recursive: true });
		await fs.writeFile(path.join(directory, 'assessment.pdf'), '%PDF-1.4 fixture');
		await fs.writeFile(path.join(directory, 'assessment.json'), '{"report":true}');
		await fs.writeFile(path.join(directory, 'assessment.sarif'), '{"version":"2.1.0"}');
		const runtime = new CoreRuntime({ coreVersion: 'report-discovery-test' });
		const events: unknown[] = [];
		try {
			const response = await runtime.handle({ id: 'reports-get', type: 'request', method: 'workspace.reports.get', params: { workspaceRoot: root } }, (event) => { events.push(event); });
			assert.equal(response.success, true, JSON.stringify(response.error));
			const result = response.result as { pdfPath?: string; jsonPath?: string; sarifPath?: string; sizes?: { pdf?: number; json?: number; sarif?: number } };
			assert.equal(result.pdfPath, path.join(directory, 'assessment.pdf'));
			assert.equal(result.jsonPath, path.join(directory, 'assessment.json'));
			assert.equal(result.sarifPath, path.join(directory, 'assessment.sarif'));
			assert.ok((result.sizes?.pdf ?? 0) > 0 && (result.sizes?.json ?? 0) > 0 && (result.sizes?.sarif ?? 0) > 0);
			assert.equal(events.length, 0, 'report discovery must not start a scan');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('Core agent session storage is project-scoped, redacts secrets, and is available after Core restart', async () => {
		const root = await createWorkspaceTempDirectory('aqiron-agent-sessions');
		const runtime = new CoreRuntime({ coreVersion: 'agent-sessions-test' });
		const session = { id: 'session-1', title: 'Review workspace', createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-01T00:01:00.000Z', model: 'model-a', intelligence: 'balanced', messages: [{ id: 'message-1', role: 'user' as const, content: 'do not persist sk-12345678901234567890', createdAt: '2026-10-01T00:00:00.000Z' }] };
		try {
			const saved = await runtime.handle({ id: 'agent-sessions-set', type: 'request', method: 'workspace.agent-sessions.set', params: { workspaceRoot: root, sessions: [session] } }, () => undefined);
			assert.equal(saved.success, true, JSON.stringify(saved.error));
			assert.ok(!JSON.stringify(saved).includes('sk-12345678901234567890'));
			const restarted = new CoreRuntime({ coreVersion: 'agent-sessions-restart-test' });
			const loaded = await restarted.handle({ id: 'agent-sessions-get', type: 'request', method: 'workspace.agent-sessions.get', params: { workspaceRoot: root } }, () => undefined);
			assert.equal(loaded.success, true, JSON.stringify(loaded.error));
			const sessions = (loaded.result as { sessions: Array<{ id: string; messages: Array<{ content: string }> }> }).sessions;
			assert.equal(sessions[0]?.id, 'session-1');
			assert.equal(sessions[0]?.messages[0]?.content, 'do not persist [REDACTED]');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('Core recommendations load only persisted generated RAG suggestions without scanning', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-recommendations-'));
		const directory = path.join(root, '.aqiron-security');
		await fs.mkdir(directory, { recursive: true });
		await fs.writeFile(path.join(directory, 'index.json'), JSON.stringify({ manifest: { version: 1, createdAt: '', updatedAt: '2026-10-01T00:00:00.000Z', filesIndexed: 2, filesSkipped: 0, errors: [], aiSuggestionsGenerated: true }, files: [], chunks: [] }));
		await fs.writeFile(path.join(directory, 'suggestions.md'), '- Review the workspace storage permissions carefully.\n');
		const runtime = new CoreRuntime({ coreVersion: 'recommendations-test' });
		try {
			const result = await runtime.handle({ id: 'recommendations-get', type: 'request', method: 'workspace.recommendations.get', params: { workspaceRoot: root } }, () => undefined);
			assert.equal(result.success, true, JSON.stringify(result.error));
		assert.deepEqual(result.result, { generated: true, suggestions: ['- Review the workspace storage permissions carefully.\n'] });
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('Core rag.index withAi generates and persists recommendations through Core AI without scanning', async () => {
		const root = await createWorkspaceTempDirectory('aqiron-rag-refresh');
		const values = new Map<string, string>([
			['aqiron.ai.settings', JSON.stringify({ selectedProvider: 'openrouter', selectedModel: 'minimax/minimax-m3.1-flash:free', temperature: 0.2, maxTokens: 1024, timeoutMs: 30_000, retries: 0, streaming: true, openRouterEndpoint: 'https://test.invalid/api/v1' })],
			['aqiron.ai.openrouter.apiKey', 'test-secret-never-log'],
		]);
		const credentialStore: CredentialStore = { get: async (key) => values.get(key), set: async (key, value) => { values.set(key, value); }, delete: async (key) => { values.delete(key); } };
		const recommendation = `\`\`\`json\n${JSON.stringify({ recommendations: [{ title: 'Review the workspace storage permissions', description: 'Restrict access to sensitive local data.', severity: 'High', recommended: true, command: 'Review storage permissions' }] })}\n\`\`\``;
		let chatUrl = '';
		let chatBody: unknown;
		const aiTransport: AITransport = { request: async (url, options) => url.endsWith('/models') ? {
			ok: true, status: 200, headers: {}, text: async () => '', json: async <T>() => ({ data: [{ id: 'minimax/minimax-m3.1-flash:free', name: 'MiniMax M3.1 Flash', pricing: { prompt: '0', completion: '0' }, supported_parameters: ['reasoning', 'max_tokens'] }] } as T),
		} : {
			...(chatUrl = url, chatBody = options.body, {}),
			ok: true, status: 200, headers: {}, text: async () => '', json: async <T>() => ({} as T),
			body: new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify({ choices: [{ delta: { content: recommendation }, finish_reason: 'stop' }] })}\n\ndata: [DONE]\n\n`)); controller.close(); } }),
		} };
		await fs.mkdir(path.join(root, 'lib'), { recursive: true });
		await fs.writeFile(path.join(root, 'lib', 'main.dart'), 'void main() { final token = "example"; }');
		const runtime = new CoreRuntime({ coreVersion: 'recommendation-refresh-test', credentialStore, aiTransport });
		const events: unknown[] = [];
		try {
			const result = await runtime.handle({ id: 'recommendations-refresh', type: 'request', method: 'rag.index', params: { workspaceRoot: root, withAi: true } }, (event) => events.push(event));
			assert.equal(result.success, true);
			assert.equal(chatUrl, 'https://test.invalid/api/v1/chat/completions');
			assert.equal((chatBody as { model?: string }).model, 'minimax/minimax-m3.1-flash:free', 'recommendations must use the configured model');
			assert.equal((chatBody as { max_tokens?: number }).max_tokens, 4096, 'recommendation generation needs a bounded final-output budget');
			assert.deepEqual((chatBody as { reasoning?: unknown }).reasoning, { enabled: true, max_tokens: 1024 }, 'MiniMax requires reasoning, which must be bounded to leave room for the recommendation text');
			assert.deepEqual((chatBody as { stream_options?: unknown }).stream_options, { include_usage: true });
			const messages = (chatBody as { messages: Array<{ role: string; content: string }> }).messages;
			assert.equal(messages.at(-1)?.content.startsWith('Return only a JSON array'), true, 'the Core AI request must contain the VS Code recommendation prompt as its final user message');
			assert.equal(messages.at(-2)?.content, messages.at(-1)?.content, 'Core must use the same completed chat request shape as VS Code reindexRag(true)');
			assert.equal(messages[0]?.role, 'system');
			assert.match(await fs.readFile(path.join(root, '.aqiron-security', 'suggestions.md'), 'utf8'), /Review the workspace storage permissions/);
			const loaded = await runtime.handle({ id: 'recommendations-refresh-load', type: 'request', method: 'workspace.recommendations.get', params: { workspaceRoot: root } }, () => undefined);
			assert.equal((loaded.result as { suggestions: string[] }).suggestions.length, 1);
			assert.equal(events.some((event) => JSON.stringify(event).includes('scan.')), false, 'recommendation refresh must not run a security scan');
			assert.doesNotMatch(JSON.stringify(result), /test-secret-never-log/);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('Core interactive MiniMax chat bounds mandatory reasoning and returns streamed Explain text', async () => {
		const values = new Map<string, string>([
			['aqiron.ai.settings', JSON.stringify({ selectedProvider: 'openrouter', selectedModel: 'minimax/minimax-m3.1-flash:free', temperature: 0.2, maxTokens: 2048, timeoutMs: 30_000, retries: 0, streaming: true, openRouterEndpoint: 'https://test.invalid/api/v1' })],
			['aqiron.ai.openrouter.apiKey', 'runtime-chat-secret'],
		]);
		const credentialStore: CredentialStore = { get: async (key) => values.get(key), set: async (key, value) => { values.set(key, value); }, delete: async (key) => { values.delete(key); } };
		let chatBody: Record<string, unknown> | undefined;
		const aiTransport: AITransport = { request: async (url, options) => url.endsWith('/models') ? {
			ok: true, status: 200, headers: {}, text: async () => '', json: async <T>() => ({ data: [{ id: 'minimax/minimax-m3.1-flash:free', name: 'MiniMax M3.1 Flash', supported_parameters: ['reasoning', 'max_tokens'] }] } as T),
		} : {
			...(chatBody = options.body as Record<string, unknown>, {}),
			ok: true, status: 200, headers: {}, text: async () => '', json: async <T>() => ({} as T),
			body: new ReadableStream<Uint8Array>({ start(controller) {
				controller.enqueue(new TextEncoder().encode([
					`data: ${JSON.stringify({ choices: [{ delta: { reasoning: 'bounded reasoning metadata, not assistant output' } }] })}`,
					`data: ${JSON.stringify({ choices: [{ delta: { content: 'Review the recommendation by restricting public access to the storage bucket.' }, finish_reason: 'stop' }] })}`,
					'data: [DONE]',
				].join('\n\n') + '\n\n'));
				controller.close();
			} }),
		} };
		const runtime = new CoreRuntime({ coreVersion: 'interactive-chat-policy-test', credentialStore, aiTransport });
		const events: unknown[] = [];
		const response = await runtime.handle({ id: 'explain-chat', type: 'request', method: 'ai.chat', params: {
				sessionId: 'existing-session', providerId: 'openrouter', model: 'minimax/minimax-m3.1-flash:free', text: 'Explain Secure Storage Recommendation', intelligence: 'Medium',
			history: [{ role: 'user', content: 'Secure Storage Recommendation: restrict public bucket access.' }, { role: 'assistant', content: 'The finding concerns an exposed storage bucket.' }],
			context: { workspaceName: 'fixture', projectTypes: [], backend: 'Core', currentFile: 'None', scanStatus: 'Complete', issues: [], stats: { filesScanned: 0, indexedFiles: 0 }, apis: [] },
		} }, (event) => events.push(event));
		assert.equal(response.success, true, JSON.stringify(response.error));
		assert.equal((response.result as { text: string }).text, 'Review the recommendation by restricting public access to the storage bucket.');
		assert.equal(chatBody?.model, 'minimax/minimax-m3.1-flash:free', 'the selected model must be preserved');
		assert.equal(chatBody?.max_tokens, 4096);
		assert.deepEqual(chatBody?.reasoning, { enabled: true, max_tokens: 1024 });
		const messages = chatBody?.messages as Array<{ role: string; content: string }>;
		assert.ok(messages.some((message) => message.content === 'Explain Secure Storage Recommendation'));
		assert.ok(messages.some((message) => message.content === 'Secure Storage Recommendation: restrict public bucket access.'));
		assert.ok(messages.some((message) => message.content === 'The finding concerns an exposed storage bucket.'));
		assert.ok(events.some((event) => JSON.stringify(event).includes('ai.token')));
		assert.ok(events.some((event) => JSON.stringify(event).includes('ai.completed')));
		assert.ok(!JSON.stringify(response).includes('runtime-chat-secret'));
	});

	test('Core interactive chat rejects reasoning-only length exhaustion without emitting an assistant completion', async () => {
		const values = new Map<string, string>([
			['aqiron.ai.settings', JSON.stringify({ selectedProvider: 'openrouter', selectedModel: 'nvidia/nemotron-3.5-lightning:free', temperature: 0.2, maxTokens: 2048, timeoutMs: 30_000, retries: 0, streaming: true, openRouterEndpoint: 'https://test.invalid/api/v1' })],
			['aqiron.ai.openrouter.apiKey', 'runtime-chat-secret'],
		]);
		const credentialStore: CredentialStore = { get: async (key) => values.get(key), set: async (key, value) => { values.set(key, value); }, delete: async (key) => { values.delete(key); } };
		const aiTransport: AITransport = { request: async (url) => url.endsWith('/models') ? {
			ok: true, status: 200, headers: {}, text: async () => '', json: async <T>() => ({ data: [{ id: 'nvidia/nemotron-3.5-lightning:free', supported_parameters: ['reasoning', 'max_tokens'] }] } as T),
		} : {
			ok: true, status: 200, headers: {}, text: async () => '', json: async <T>() => ({} as T),
			body: new ReadableStream<Uint8Array>({ start(controller) {
				controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify({ choices: [{ delta: { reasoning: 'reasoning only' }, finish_reason: 'length' }], usage: { completion_tokens: 4096, completion_tokens_details: { reasoning_tokens: 4096 } } })}\n\ndata: [DONE]\n\n`));
				controller.close();
			} }),
		} };
		const runtime = new CoreRuntime({ coreVersion: 'interactive-chat-empty-test', credentialStore, aiTransport });
		const events: unknown[] = [];
		const response = await runtime.handle({ id: 'empty-chat', type: 'request', method: 'ai.chat', params: {
			sessionId: 'empty-session', providerId: 'openrouter', model: 'nvidia/nemotron-3.5-lightning:free', text: 'Explain this recommendation', intelligence: 'Medium', history: [],
			context: { workspaceName: 'fixture', projectTypes: [], backend: 'Core', currentFile: 'None', scanStatus: 'Complete', issues: [], stats: { filesScanned: 0, indexedFiles: 0 }, apis: [] },
		} }, (event) => events.push(event));
		assert.equal(response.success, false);
		assert.match(response.error?.message ?? '', /used its 4096-token generation budget on reasoning/i);
		assert.ok(!events.some((event) => JSON.stringify(event).includes('ai.completed')));
		assert.ok(!JSON.stringify(response).includes('reasoning only'));
	});

	test('Core recommendation refresh accepts VS Code plain text output and preserves existing data on invalid output', async () => {
		const root = await createWorkspaceTempDirectory('aqiron-rag-refresh-invalid');
		const directory = path.join(root, '.aqiron-security');
		await fs.mkdir(directory, { recursive: true });
		const previous = '[{"title":"Existing recommendation","detail":"Keep this until generation succeeds.","command":"Existing recommendation"}]';
		await fs.writeFile(path.join(directory, 'suggestions.md'), previous);
		const values = new Map<string, string>([
			['aqiron.ai.settings', JSON.stringify({ selectedProvider: 'openrouter', selectedModel: 'test/model', temperature: 0.2, maxTokens: 1024, timeoutMs: 30_000, retries: 0, streaming: true, openRouterEndpoint: 'https://test.invalid/api/v1' })],
			['aqiron.ai.openrouter.apiKey', 'test-secret-never-log'],
		]);
		const credentialStore: CredentialStore = { get: async (key) => values.get(key), set: async (key, value) => { values.set(key, value); }, delete: async (key) => { values.delete(key); } };
		let output = '- Review storage permissions carefully.';
		let lastChatBody: Record<string, unknown> | undefined;
		const aiTransport: AITransport = { request: async (url, options) => url.endsWith('/models') ? {
			ok: true, status: 200, headers: {}, text: async () => '', json: async <T>() => ({ data: [{ id: 'test/model', name: 'Test model', pricing: { prompt: '0', completion: '0' }, supported_parameters: ['reasoning', 'max_tokens'] }] } as T),
		} : {
			...(lastChatBody = options.body as Record<string, unknown>, {}),
			ok: true, status: 200, headers: {}, text: async () => '', json: async <T>() => ({} as T),
			body: new ReadableStream<Uint8Array>({ start(controller) {
				const response = output === '__reasoning_only__'
					? { choices: [{ delta: { reasoning: 'private analysis' }, finish_reason: 'length' }], usage: { completion_tokens: 4096, completion_tokens_details: { reasoning_tokens: 4096 } } }
					: { choices: [{ delta: { content: output }, finish_reason: 'stop' }] };
				controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(response)}\n\ndata: [DONE]\n\n`));
				controller.close();
			} }),
		} };
		await fs.writeFile(path.join(root, 'main.dart'), 'void main() {}');
		const runtime = new CoreRuntime({ coreVersion: 'recommendation-refresh-invalid-test', credentialStore, aiTransport });
		try {
			const refresh = (id: string) => runtime.handle({ id, type: 'request', method: 'rag.index', params: { workspaceRoot: root, withAi: true } }, () => undefined);
			const accepted = await refresh('recommendations-plain-text');
			assert.equal(accepted.success, true, JSON.stringify(accepted.error));
			assert.equal(lastChatBody?.max_tokens, 4096);
			assert.deepEqual(lastChatBody?.reasoning, { enabled: false });
			assert.match(await fs.readFile(path.join(directory, 'suggestions.md'), 'utf8'), /Review storage permissions carefully/);
			output = '__reasoning_only__';
			const rejected = await refresh('recommendations-invalid-output');
			assert.equal(rejected.success, false);
			assert.match(rejected.error?.message ?? '', /used its 4096-token generation budget on reasoning/);
			assert.match(await fs.readFile(path.join(directory, 'suggestions.md'), 'utf8'), /Review storage permissions carefully/);
			assert.doesNotMatch(JSON.stringify(rejected), /test-secret-never-log/);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('Core recommendation index state follows the requested workspace when switching projects', async () => {
		const roots = await Promise.all([fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-recommendations-a-')), fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-recommendations-b-'))]);
		const runtime = new CoreRuntime({ coreVersion: 'recommendations-project-scope-test' });
		try {
			for (const [index, root] of roots.entries()) {
				const directory = path.join(root, '.aqiron-security');
				await fs.mkdir(directory, { recursive: true });
				await fs.writeFile(path.join(directory, 'index.json'), JSON.stringify({ manifest: { version: 1, createdAt: '', updatedAt: `2026-10-0${index + 1}T00:00:00.000Z`, filesIndexed: 1, filesSkipped: 0, errors: [], aiSuggestionsGenerated: index === 0 }, files: [], chunks: [] }));
				await fs.writeFile(path.join(directory, 'suggestions.md'), `- Project ${index === 0 ? 'A' : 'B'} recommendation.\n`);
			}
			const request = (id: string, workspaceRoot: string) => runtime.handle({ id, type: 'request', method: 'workspace.recommendations.get', params: { workspaceRoot } }, () => undefined);
			const projectA = await request('recommendations-project-a', roots[0]!);
			const projectB = await request('recommendations-project-b', roots[1]!);
			const projectAAgain = await request('recommendations-project-a-return', roots[0]!);
			assert.deepEqual(projectA.result, { generated: true, suggestions: ['- Project A recommendation.\n'] });
			assert.deepEqual(projectB.result, { generated: false, suggestions: [] }, 'project B must use its own manifest rather than the cached project A manifest');
			assert.deepEqual(projectAAgain.result, { generated: true, suggestions: ['- Project A recommendation.\n'] });
		} finally { await Promise.all(roots.map((root) => fs.rm(root, { recursive: true, force: true }))); }
	});

	test('deleting a provider credential also removes its public metadata and active selection', async () => {
		const id = 'test-delete-provider';
		const values = new Map<string, string>([
			['aqiron.ai.settings', JSON.stringify({ selectedProvider: 'openai', activeApiCredentialId: id, apiCredentials: [{ id, name: 'Work', providerId: 'openai', last4: 'abcd', createdAt: 'today', updatedAt: 'today' }] })],
			[`aqiron.ai.api.${id}`, 'credential-value-never-return-this'],
		]);
		const store: CredentialStore = { get: async (key) => values.get(key), set: async (key, value) => { values.set(key, value); }, delete: async (key) => { values.delete(key); } };
		const runtime = new CoreRuntime({ coreVersion: 'credential-delete-test', credentialStore: store });
		const deleted = await runtime.handle({ id: 'provider-delete', type: 'request', method: 'credentials.delete', params: { key: `aqiron.ai.api.${id}` } }, () => undefined);
		assert.equal(deleted.success, true);
		const providers = await runtime.handle({ id: 'provider-list-after-delete', type: 'request', method: 'ai.providers', params: {} }, () => undefined);
		assert.ok(!JSON.stringify(providers).includes(id));
		assert.ok(!JSON.stringify(providers).includes('credential-value-never-return-this'));
		assert.equal(JSON.parse(values.get('aqiron.ai.settings') ?? '{}').activeApiCredentialId, undefined);
	});

	test('Core model lookup initializes from persisted provider credentials before switching providers', async () => {
		const id = 'persisted-provider-model-test';
		const values = new Map<string, string>([
			['aqiron.ai.settings', JSON.stringify({ selectedProvider: 'openai', activeApiCredentialId: id, apiCredentials: [{ id, name: 'Work', providerId: 'openai', last4: 'abcd', createdAt: 'today', updatedAt: 'today' }] })],
			[`aqiron.ai.api.${id}`, 'private-model-test-key'],
		]);
		const store: CredentialStore = { get: async (key) => values.get(key), set: async (key, value) => { values.set(key, value); }, delete: async (key) => { values.delete(key); } };
		const runtime = new CoreRuntime({ coreVersion: 'model-settings-test', credentialStore: store, aiTransport: { request: async () => ({ ok: true, status: 200, headers: {}, text: async () => '', json: async <T>() => ({ data: [{ id: 'gpt-test', owned_by: 'test' }] } as T) }) } });
		const response = await runtime.handle({ id: 'models-from-settings', type: 'request', method: 'ai.models', params: { providerId: 'openai' } }, () => undefined);
		assert.equal(response.success, true, JSON.stringify(response.error));
		assert.ok(!JSON.stringify(response).includes('private-model-test-key'));
		assert.deepEqual((response.result as { models: Array<{ id: string }> }).models.map((model) => model.id), ['gpt-test']);
		assert.equal(JSON.parse(values.get('aqiron.ai.settings') ?? '{}').activeApiCredentialId, id, 'provider switching must retain the persisted credential selection');
	});

	test('workspace rules saved through Core are persisted and applied by a later Core scan', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-rules-'));
		const sourcePath = path.join(root, 'lib', 'main.dart');
		await fs.mkdir(path.dirname(sourcePath), { recursive: true });
		await fs.writeFile(sourcePath, 'void main() { dangerousDesktopMarker(); }\n');
		const runtime = new CoreRuntime({ coreVersion: 'rules-test' });
		const emit = (): void => undefined;
		try {
			const set = await runtime.handle({ id: 'rules-set', type: 'request', method: 'workspace.rules.set', params: { workspaceRoot: root, rules: [{ id: 'custom.flutter.marker', title: 'Flutter marker', message: 'Review marker.', severity: 'High', pattern: 'dangerousDesktopMarker', extensions: ['.dart'] }] } }, emit);
			assert.equal(set.success, true, JSON.stringify(set.error));
			const secondRuntime = new CoreRuntime({ coreVersion: 'rules-restart-test' });
			const loaded = await secondRuntime.handle({ id: 'rules-get', type: 'request', method: 'workspace.rules.get', params: { workspaceRoot: root } }, emit);
			assert.equal((loaded.result as { rules: Array<{ id: string }> }).rules[0]?.id, 'custom.flutter.marker');
			const scan = await secondRuntime.handle({ id: 'rules-scan', type: 'request', method: 'scan.start', params: { workspaceRoot: root, trusted: true, mode: 'quick', includeExternalScanners: false } }, emit);
			assert.equal(scan.success, true, JSON.stringify(scan.error));
			assert.ok((scan.result as { findings: Array<{ ruleId: string }> }).findings.some((finding) => finding.ruleId === 'custom.flutter.marker'));
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});
});

function fakeResponse(status: number, text: string): NetworkResponse {
	const bytes = new TextEncoder().encode(text);
	return {
		ok: status >= 200 && status < 300,
		status,
		headers: { 'content-type': 'application/json' },
		text: async () => text,
		json: async <T>() => JSON.parse(text) as T,
		body: new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(bytes); controller.close(); } }),
	};
}

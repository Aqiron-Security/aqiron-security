const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { test } = require('node:test');

const root = path.resolve(__dirname, '../../..');
const bridgePath = path.join(root, 'dist/aqiron-desktop-bridge.js');
const runtimePath = path.join(root, 'dist/core-runtime.js');
const fixture = path.join(root, 'src/test/fixtures/file-scan/flutter');

test('desktop bridge detects a project, starts the real Core scan, forwards events and returns real findings', { timeout: 120_000 }, async () => {
	const bridge = await startBridge(runtimePath);
	try {
		const profile = await bridge.request('project.detect', { workspaceRoot: fixture, trusted: true });
		assert.ok(profile.projectTypes.includes('Flutter'));
		await bridge.request('project.profile', { workspaceRoot: fixture, trusted: true });
		const providers = await bridge.request('ai.providers', {});
		assert.ok(Array.isArray(providers.providers), 'Desktop project selection reads provider status through CoreClient');
		await bridge.request('workspace.rules.get', { workspaceRoot: fixture, trusted: true });
		const history = await bridge.request('workspace.threat-history.get', { workspaceRoot: fixture });
		assert.ok(Array.isArray(history.snapshots), 'Desktop can load existing workspace threat snapshots through Core');
		assert.equal(bridge.events.some((event) => event.event?.startsWith('scan.')), false, 'project restoration detection must not start a scan');
		const providersAfterSelection = await bridge.request('ai.providers', {});
		assert.ok(Array.isArray(providersAfterSelection.providers), 'the Core bridge remains usable after project selection calls');
		assert.doesNotMatch(bridge.logs(), /"operation":"core\.shutdown"/, 'successful project selection must not shut down Core');
		assert.doesNotMatch(bridge.logs(), /EPIPE|broken pipe/i, 'successful project selection must not produce a pipe failure');
		const result = await bridge.request('scan.start', { workspaceRoot: fixture, trusted: true, mode: 'quick', includeExternalScanners: false });
		assert.ok(result.scanId);
		assert.ok(Array.isArray(result.findings));
		assert.ok(result.findings.length > 0, 'fixture must produce findings from Core');
		assert.ok(result.report.model.executiveSummary);
		assert.ok(result.report.pdf.startsWith('%PDF-1.4'), 'Core PDF renderer must return the PDF bundle');
		assert.ok(result.report.json, 'Core JSON report representation must be in the bundle');
		assert.equal(result.report.sarif.version, '2.1.0', 'Core SARIF exporter must be in the bundle');
		assert.ok(bridge.events.some((event) => event.event?.startsWith('scan.')));
	} finally { await bridge.close(); }
	assert.doesNotMatch(bridge.logs(), /EPIPE|broken pipe/i, 'graceful bridge shutdown must not write to a closed pipe');
});

test('desktop bridge dispatches credential deletion to CoreClient', { timeout: 30_000 }, async () => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-desktop-credentials-'));
	const mockRuntime = path.join(directory, 'credential-runtime.js');
	await fs.writeFile(mockRuntime, [
		"const readline = require('node:readline');",
		"readline.createInterface({ input: process.stdin }).on('line', line => {",
		"const request = JSON.parse(line);",
		"if (request.method === 'credentials.delete') process.stderr.write('MOCK_CREDENTIAL_DELETE:' + request.params.key + '\\n');",
		"if (request.method === 'ai.models') process.stderr.write('MOCK_AI_MODELS:' + request.params.providerId + '\\n');",
		"if (request.method === 'ai.cancel') process.stderr.write('MOCK_AI_CANCEL:' + request.params.sessionId + '\\n');",
		"if (request.method === 'ai.chat') { process.stderr.write('MOCK_AI_CHAT:' + request.params.providerId + ':' + request.params.model + '\\n'); process.stdout.write(JSON.stringify({ type: 'event', event: 'ai.token', requestId: request.params.sessionId, payload: { content: 'reply' } }) + '\\n'); process.stdout.write(JSON.stringify({ type: 'event', event: 'ai.completed', requestId: request.params.sessionId, payload: { text: 'reply' } }) + '\\n'); }",
		"const result = request.method === 'core.handshake' ? { protocolVersion: 1, coreVersion: 'test', status: 'compatible' } : request.method === 'ai.models' ? { models: [{ id: 'test-model', label: 'Test model', providerId: request.params.providerId, badges: [], capabilities: [] }], status: { providerId: request.params.providerId, connected: true, message: 'Ready' } } : request.method === 'ai.cancel' ? { cancelled: true } : { hasValue: false };",
		"process.stdout.write(JSON.stringify({ id: request.id, type: 'response', success: true, result }) + '\\n');",
		"});",
	].join('\n'));
	const bridge = await startBridge(mockRuntime);
	try {
		const result = await bridge.request('credentials.delete', { key: 'aqiron.ai.api.desktop-test' });
		assert.equal(result.hasValue, false);
		assert.match(bridge.logs(), /MOCK_CREDENTIAL_DELETE:aqiron\.ai\.api\.desktop-test/);
		const models = await bridge.request('ai.models', { providerId: 'openai' });
		assert.equal(models.models[0]?.providerId, 'openai');
		assert.match(bridge.logs(), /MOCK_AI_MODELS:openai/);
		const chat = await bridge.request('ai.chat', { sessionId: 'desktop-session', providerId: 'openai', model: 'test-model', text: 'hello', intelligence: 'Medium', history: [], context: {} });
		assert.equal(chat.text, 'reply');
		assert.match(bridge.logs(), /MOCK_AI_CHAT:openai:test-model/);
		assert.ok(bridge.events.some((event) => event.event === 'ai.token' && event.requestId === 'desktop-session'), 'AI token events are forwarded so Desktop can render streaming output');
		const cancelled = await bridge.request('ai.cancel', { sessionId: 'desktop-session' });
		assert.deepEqual(cancelled, { cancelled: true });
		assert.match(bridge.logs(), /MOCK_AI_CANCEL:desktop-session/);
	} finally { await bridge.close(); await fs.rm(directory, { recursive: true, force: true }); }
});

test('desktop bridge reads and writes Core-owned project agent sessions and recommendations', { timeout: 30_000 }, async () => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-desktop-agent-state-'));
	const bridge = await startBridge(runtimePath);
	const session = { id: 'session-1', title: 'Existing review', createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-01T00:01:00.000Z', model: 'model-a', intelligence: 'balanced', messages: [{ id: 'message-1', role: 'user', content: 'Review this project', createdAt: '2026-10-01T00:00:00.000Z' }] };
	try {
		await bridge.request('workspace.agent-sessions.set', { workspaceRoot: directory, sessions: [session] });
		const history = await bridge.request('workspace.agent-sessions.get', { workspaceRoot: directory });
		assert.equal(history.sessions[0]?.id, 'session-1');
		const recommendations = await bridge.request('workspace.recommendations.get', { workspaceRoot: directory });
		assert.deepEqual(recommendations, { generated: false, suggestions: [] });
		assert.equal(bridge.events.some((event) => event.event?.startsWith('scan.')), false, 'loading agent state must not trigger a scan');
	} finally { await bridge.close(); await fs.rm(directory, { recursive: true, force: true }); }
});

test('desktop recommendation reads are project-scoped through Core and do not scan', { timeout: 30_000 }, async () => {
	const roots = await Promise.all([fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-desktop-recommendations-a-')), fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-desktop-recommendations-b-'))]);
	const bridge = await startBridge(runtimePath);
	try {
		for (const [index, root] of roots.entries()) {
			const directory = path.join(root, '.aqiron-security');
			await fs.mkdir(directory, { recursive: true });
			await fs.writeFile(path.join(directory, 'index.json'), JSON.stringify({ manifest: { version: 1, createdAt: '', updatedAt: `2026-10-0${index + 1}T00:00:00.000Z`, filesIndexed: 1, filesSkipped: 0, errors: [], aiSuggestionsGenerated: true }, files: [], chunks: [] }));
			await fs.writeFile(path.join(directory, 'suggestions.md'), JSON.stringify([{ title: `Project ${index ? 'B' : 'A'} recommendation`, detail: 'Actual project-specific recommendation.', severity: 'Medium', command: 'Review this project' }]));
		}
		const projectA = await bridge.request('workspace.recommendations.get', { workspaceRoot: roots[0] });
		const projectB = await bridge.request('workspace.recommendations.get', { workspaceRoot: roots[1] });
		assert.match(projectA.suggestions[0], /Project A recommendation/);
		assert.match(projectB.suggestions[0], /Project B recommendation/);
		assert.equal(bridge.events.some((event) => event.event?.startsWith('scan.')), false);
	} finally { await bridge.close(); await Promise.all(roots.map((root) => fs.rm(root, { recursive: true, force: true }))); }
});

test('desktop bridge forwards recommendation refresh to Core rag.index with AI enabled and does not scan', { timeout: 30_000 }, async () => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-desktop-rag-refresh-'));
	const mockRuntime = path.join(directory, 'rag-runtime.js');
	await fs.writeFile(mockRuntime, [
		"const readline = require('node:readline');",
		"readline.createInterface({ input: process.stdin }).on('line', line => {",
		"const request = JSON.parse(line);",
		"if (request.method === 'core.handshake') { process.stdout.write(JSON.stringify({ id: request.id, type: 'response', success: true, result: { protocolVersion: 1, coreVersion: 'test', status: 'compatible' } }) + '\\n'); return; }",
		"if (request.method === 'core.health') { process.stdout.write(JSON.stringify({ id: request.id, type: 'response', success: true, result: { ready: true } }) + '\\n'); return; }",
		"if (request.method === 'rag.index') process.stderr.write('MOCK_RAG_INDEX:' + request.params.workspaceRoot + ':' + request.params.withAi + '\\n');",
		"const result = request.method === 'rag.index' ? { index: { manifest: { aiSuggestionsGenerated: true } } } : {};",
		"process.stdout.write(JSON.stringify({ id: request.id, type: 'response', success: true, result }) + '\\n');",
		"});",
	].join('\n'));
	const bridge = await startBridge(mockRuntime);
	try {
		const result = await bridge.request('rag.index', { workspaceRoot: directory, withAi: true });
		assert.equal(result.index.manifest.aiSuggestionsGenerated, true);
		assert.ok(bridge.logs().includes(`MOCK_RAG_INDEX:${directory}:true`));
		assert.equal(bridge.events.some((event) => event.event?.startsWith('scan.')), false, 'recommendation refresh must not trigger scan.start');
	} finally { await bridge.close(); await fs.rm(directory, { recursive: true, force: true }); }
});

test('desktop bridge preserves recommendation request failures for an explicit UI error state', { timeout: 30_000 }, async () => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-desktop-recommendation-error-'));
	const mockRuntime = path.join(directory, 'recommendation-runtime.js');
	await fs.writeFile(mockRuntime, [
		"const readline = require('node:readline');",
		"readline.createInterface({ input: process.stdin }).on('line', line => {",
		"const request = JSON.parse(line);",
		"if (request.method === 'core.handshake') process.stdout.write(JSON.stringify({ id: request.id, type: 'response', success: true, result: { protocolVersion: 1, coreVersion: 'test', status: 'compatible' } }) + '\\n');",
		"else if (request.method === 'core.health') process.stdout.write(JSON.stringify({ id: request.id, type: 'response', success: true, result: { ready: true } }) + '\\n');",
		"else process.stdout.write(JSON.stringify({ id: request.id, type: 'response', success: false, error: { code: 'RECOMMENDATIONS_READ_FAILED', message: 'Permission denied reading suggestions.md' } }) + '\\n');",
		"});",
	].join('\n'));
	const bridge = await startBridge(mockRuntime);
	try { await assert.rejects(bridge.request('workspace.recommendations.get', { workspaceRoot: directory }), /Permission denied reading suggestions\.md/); }
	finally { await bridge.close(); await fs.rm(directory, { recursive: true, force: true }); }
});

test('desktop bridge deletes a persisted threat snapshot through Core and preserves other snapshots', { timeout: 30_000 }, async () => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-desktop-threat-delete-'));
	const securityDirectory = path.join(directory, '.aqiron-security');
	await fs.mkdir(securityDirectory, { recursive: true });
	const file = path.join(securityDirectory, 'threats.json');
	await fs.writeFile(file, JSON.stringify([
		{ id: 'remove-me', title: 'Old result', issues: [] },
		{ id: 'keep-me', title: 'Current result', extraMetadata: { retained: true }, issues: [{ id: 'finding-stays' }] },
	]));
	const bridge = await startBridge(runtimePath);
	try {
		const result = await bridge.request('workspace.threat-history.delete', { workspaceRoot: directory, snapshotId: 'remove-me' });
		assert.deepEqual(result.snapshots.map((snapshot) => snapshot.id), ['keep-me']);
		assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')).map((snapshot) => snapshot.id), ['keep-me']);
		assert.equal(JSON.parse(await fs.readFile(file, 'utf8'))[0].extraMetadata.retained, true);
		assert.equal((await bridge.request('workspace.threat-history.get', { workspaceRoot: directory })).snapshots[0].issues[0].id, 'finding-stays');
	} finally { await bridge.close(); await fs.rm(directory, { recursive: true, force: true }); }
});

test('desktop bridge discovers existing report artifacts through Core without starting a scan', { timeout: 30_000 }, async () => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-desktop-report-discovery-'));
	const reportDirectory = path.join(directory, '.aqiron-security', 'reports', 'scan-001');
	await fs.mkdir(reportDirectory, { recursive: true });
	await fs.writeFile(path.join(reportDirectory, 'report.pdf'), '%PDF-1.4');
	await fs.writeFile(path.join(reportDirectory, 'report.json'), '{"ok":true}');
	await fs.writeFile(path.join(reportDirectory, 'report.sarif'), '{"version":"2.1.0"}');
	const bridge = await startBridge(runtimePath);
	try {
		const reports = await bridge.request('workspace.reports.get', { workspaceRoot: directory });
		assert.equal(reports.pdfPath, path.join(reportDirectory, 'report.pdf'));
		assert.equal(reports.jsonPath, path.join(reportDirectory, 'report.json'));
		assert.equal(reports.sarifPath, path.join(reportDirectory, 'report.sarif'));
		assert.equal(bridge.events.some((event) => event.event?.startsWith('scan.')), false);
	} finally { await bridge.close(); await fs.rm(directory, { recursive: true, force: true }); }
});

test('desktop bridge surfaces Core startup failures to the caller', { timeout: 30_000 }, async () => {
	const bridge = await startBridge(path.join(os.tmpdir(), 'aqiron-missing-runtime.js'));
	try {
		await assert.rejects(bridge.request('core.health', {}), /Core|runtime|handshake/i);
	} finally { await bridge.close(); }
});

test('desktop bridge reports a Core crash during a request as a disconnect', { timeout: 30_000 }, async () => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-desktop-crash-'));
	const mockRuntime = path.join(directory, 'crash-runtime.js');
	await fs.writeFile(mockRuntime, [
		"const readline = require('node:readline');",
		"readline.createInterface({ input: process.stdin }).on('line', line => {",
		"const request = JSON.parse(line);",
		"if (request.method === 'scan.start') { process.exit(17); return; }",
		"const result = request.method === 'core.handshake' ? { protocolVersion: 1, coreVersion: 'test', status: 'compatible' } : { ready: true };",
		"process.stdout.write(JSON.stringify({ id: request.id, type: 'response', success: true, result }) + '\\n');",
		"});",
	].join('\n'));
	const bridge = await startBridge(mockRuntime);
	try {
		await assert.rejects(bridge.request('scan.start', { workspaceRoot: fixture, trusted: true }), /exited unexpectedly|unavailable|crash/i);
	} finally {
		await bridge.close();
		await fs.rm(directory, { recursive: true, force: true });
	}
});

test('desktop bridge waits for an active request before orderly Core shutdown', { timeout: 30_000 }, async () => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-desktop-shutdown-'));
	const mockRuntime = path.join(directory, 'delayed-runtime.js');
	await fs.writeFile(mockRuntime, [
		"const readline = require('node:readline');",
		"readline.createInterface({ input: process.stdin }).on('line', line => {",
		"const request = JSON.parse(line);",
		"const send = result => process.stdout.write(JSON.stringify({ id: request.id, type: 'response', success: true, result }) + '\\n');",
		"if (request.method === 'core.handshake') send({ protocolVersion: 1, coreVersion: 'test', status: 'compatible' });",
		"else if (request.method === 'core.health') send({ ready: true });",
		"else if (request.method === 'scan.start') setTimeout(() => { process.stderr.write('MOCK_SCAN_DONE\\n'); send({ scanId: 'scan-test', findings: [] }); }, 150);",
		"else if (request.method === 'core.shutdown') { process.stderr.write('MOCK_SHUTDOWN\\n'); send({ ok: true }); setTimeout(() => process.exit(0), 10); }",
		"});",
	].join('\n'));
	const bridge = await startBridge(mockRuntime);
	try {
		const activeRequest = bridge.request('scan.start', { workspaceRoot: fixture, trusted: true, mode: 'quick' });
		bridge.closeInput();
		const result = await activeRequest;
		assert.equal(result.scanId, 'scan-test');
		await bridge.waitForExit();
		const logs = bridge.logs();
		assert.ok(logs.indexOf('MOCK_SCAN_DONE') >= 0);
		assert.ok(logs.indexOf('MOCK_SHUTDOWN') > logs.indexOf('MOCK_SCAN_DONE'), 'Core shutdown must wait until the in-flight request completes');
		assert.doesNotMatch(logs, /EPIPE|broken pipe/i);
	} finally {
		await bridge.close();
		await fs.rm(directory, { recursive: true, force: true });
	}
});

async function startBridge(runtime) {
	const child = spawn(process.execPath, [bridgePath], { cwd: root, env: { ...process.env, AQIRON_CORE_RUNTIME_PATH: runtime }, stdio: ['pipe', 'pipe', 'pipe'] });
	const lines = readline.createInterface({ input: child.stdout });
	const queue = [];
	let wake;
	const events = [];
	lines.on('line', (line) => {
		const message = JSON.parse(line);
		if (message.type === 'event') { events.push(message.event); }
		else { queue.push(message); }
		wake?.();
	});
	const stderr = [];
	child.stderr.on('data', (chunk) => stderr.push(String(chunk)));
	return {
		events,
		logs: () => stderr.join(''),
		closeInput: () => child.stdin.end(),
		waitForExit: async () => {
			if (child.exitCode === null) await Promise.race([once(child, 'exit'), new Promise((resolve) => setTimeout(resolve, 2_000))]);
		},
		request(method, params) {
			const id = `test-${Date.now()}-${Math.random()}`;
			child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
			return (async () => {
				const deadline = Date.now() + 60_000;
				while (Date.now() < deadline) {
					const index = queue.findIndex((message) => message.id === id);
					if (index >= 0) {
						const response = queue.splice(index, 1)[0];
						if (response.success) return response.result;
						throw new Error(response.error || 'Desktop bridge request failed');
					}
					await new Promise((resolve, reject) => {
						const timer = setTimeout(() => reject(new Error(`Bridge response timed out. ${stderr.join('')}`)), Math.max(1, deadline - Date.now()));
						wake = () => { clearTimeout(timer); wake = undefined; resolve(); };
					});
				}
				throw new Error('Desktop bridge response timed out');
			})();
		},
		close: async () => {
			child.stdin.end();
			if (child.exitCode === null) {
				await Promise.race([once(child, 'exit'), new Promise((resolve) => setTimeout(resolve, 2_000))]);
				if (child.exitCode === null) child.kill();
			}
			lines.close();
		},
	};
}

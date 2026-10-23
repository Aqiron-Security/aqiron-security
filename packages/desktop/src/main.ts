import * as readline from 'node:readline';
import { CoreClient } from '../../core/src/client';

const runtimePath = process.env.AQIRON_CORE_RUNTIME_PATH;
if (!runtimePath) {
	process.stderr.write('AQIRON_CORE_RUNTIME_PATH is required.\n');
	process.exit(1);
}

const client = new CoreClient({ clientVersion: '0.1.0', runtimePath, restartOnCrash: true });
client.on('event', (event) => write({ type: 'event', event }));
client.on('exit', (event) => write({ type: 'event', event: { type: 'desktop', event: 'core.disconnected', payload: event } }));
client.on('log', (message) => process.stderr.write(`${message}\n`));

type DesktopMethod = 'project.detect' | 'project.profile' | 'scan.start' | 'rag.index' | 'ai.providers' | 'ai.models' | 'ai.chat' | 'ai.cancel' | 'core.cancel' | 'credentials.status' | 'credentials.set' | 'credentials.delete' | 'workspace.rules.get' | 'workspace.rules.set' | 'workspace.threat-history.get' | 'workspace.threat-history.delete' | 'workspace.reports.get' | 'workspace.agent-sessions.get' | 'workspace.agent-sessions.set' | 'workspace.recommendations.get' | 'hypotheses.ai.prepare' | 'hypotheses.ai.approve' | 'hypotheses.ai.deny' | 'hypotheses.ai.execute';
interface DesktopRequest { id: string; method: DesktopMethod; params: unknown; }

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
const inFlight = new Set<Promise<void>>();
input.on('line', (line) => {
	const task = handle(line);
	inFlight.add(task);
	void task.then(() => inFlight.delete(task), () => inFlight.delete(task));
});
input.on('close', () => {
	void (async () => {
		await Promise.allSettled([...inFlight]);
		await client.stop();
	})();
});

async function handle(line: string): Promise<void> {
	let request: DesktopRequest;
	try { request = JSON.parse(line) as DesktopRequest; }
	catch { return; }
	try {
		await client.start();
		const result = await callCore(request.method, request.params, request.id);
		write({ type: 'response', id: request.id, success: true, result });
	} catch (error) {
		write({ type: 'response', id: request.id, success: false, error: error instanceof Error ? error.message : String(error) });
	}
}

function callCore(method: DesktopMethod, params: unknown, requestId: string): Promise<unknown> {
	const request = params as never;
	switch (method) {
		case 'project.detect': return client.detectProject(request);
		case 'project.profile': return client.profileProject(request);
		case 'scan.start': return client.startScan(request);
		case 'rag.index': return client.indexRag(request);
		case 'ai.providers': return client.providers();
		case 'ai.models': return client.models((request as { providerId?: string }).providerId);
		case 'ai.chat': return collectChat(request);
		case 'ai.cancel': return client.cancelAi((request as { sessionId: string }).sessionId);
		case 'core.cancel': return client.cancelRequest((request as { requestId: string }).requestId);
		case 'credentials.status': return client.credentialsStatus((request as { key: string }).key);
		case 'credentials.set': return client.credentialsSet(request);
		case 'credentials.delete': return client.credentialsDelete(request);
		case 'workspace.rules.get': return client.getWorkspaceRules((request as { workspaceRoot: string }).workspaceRoot);
		case 'workspace.rules.set': return client.setWorkspaceRules((request as { workspaceRoot: string; rules: import('../../core/src/shared/workspaceRules').WorkspaceCustomRule[] }).workspaceRoot, (request as { rules: import('../../core/src/shared/workspaceRules').WorkspaceCustomRule[] }).rules);
		case 'workspace.threat-history.get': return client.getThreatHistory((request as { workspaceRoot: string }).workspaceRoot);
		case 'workspace.threat-history.delete': return client.deleteThreatSnapshot((request as { workspaceRoot: string }).workspaceRoot, (request as { snapshotId: string }).snapshotId);
		case 'workspace.reports.get': return client.getWorkspaceReports((request as { workspaceRoot: string }).workspaceRoot);
		case 'workspace.agent-sessions.get': return client.getAgentSessions((request as { workspaceRoot: string }).workspaceRoot).then((sessions) => ({ sessions }));
		case 'workspace.agent-sessions.set': return client.setAgentSessions((request as { workspaceRoot: string; sessions: import('../../core/src/runtime/protocol').CoreAgentSession[] }).workspaceRoot, (request as { sessions: import('../../core/src/runtime/protocol').CoreAgentSession[] }).sessions).then((sessions) => ({ sessions }));
		case 'workspace.recommendations.get': return client.getWorkspaceRecommendations((request as { workspaceRoot: string }).workspaceRoot);
		case 'hypotheses.ai.prepare': return client.prepareHypothesisAiDisclosure(request as import('../../core/src/hypotheses/contracts').HypothesisAiPrepareRequest);
		case 'hypotheses.ai.approve': { const input = request as { preparationId: string; contentFingerprint: string }; return client.approveHypothesisAiPreparation(input.preparationId, input.contentFingerprint); }
		case 'hypotheses.ai.deny': { const input = request as { preparationId: string; contentFingerprint: string }; return client.denyHypothesisAiPreparation(input.preparationId, input.contentFingerprint); }
		case 'hypotheses.ai.execute': { const input = request as { preparationId: string; contentFingerprint: string }; return client.executeHypothesisAiPreparation(input.preparationId, input.contentFingerprint, requestId); }
		default: return Promise.reject(new Error('Unsupported desktop Core method'));
	}
}

async function collectChat(request: unknown): Promise<{ text: string }> {
	let text = '';
	const chatRequest = request as import('../../core/src/runtime/protocol').CoreAiChatRequest;
	for await (const chunk of client.chat(chatRequest)) {
		if (chunk.type === 'token') {
			const content = chunk.content ?? '';
			text += content;
			write({ type: 'event', event: { event: 'ai.token', requestId: chatRequest.sessionId, payload: { content } } });
		}
		if (chunk.type === 'error') throw new Error(chunk.error ?? 'Core AI request failed.');
	}
	return { text };
}

function write(message: unknown): void {
	process.stdout.write(`${JSON.stringify(message)}\n`);
}

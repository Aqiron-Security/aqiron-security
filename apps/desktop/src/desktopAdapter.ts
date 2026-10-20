import type { WebviewState } from '../../../src/webview/ui/types.js';
import type { UnifiedFinding } from '../../../packages/core/src/shared/finding.js';
import { countFindings, mapFinding } from '../../../packages/desktop/src/findings.js';
import { providerName } from '../../../src/webview/ui/providerOptions.js';
import { buildWorkspaceRecommendations } from '../../../src/agents/recommendations.js';
import aqironLogo from '../src-tauri/icons/aqiron-security-logo.png';
type DesktopCoreEvent = { event?: string; requestId?: string; payload?: Record<string, unknown> };
type DesktopCommand = 'project.detect' | 'project.profile' | 'scan.start' | 'rag.index' | 'ai.providers' | 'ai.models' | 'ai.chat' | 'ai.cancel' | 'credentials.status' | 'credentials.set' | 'credentials.delete' | 'workspace.rules.get' | 'workspace.rules.set' | 'workspace.threat-history.get' | 'workspace.threat-history.delete' | 'workspace.reports.get' | 'workspace.agent-sessions.get' | 'workspace.agent-sessions.set' | 'workspace.recommendations.get';

const EMPTY = makeInitialState();

export function createDesktopAdapter(): { state: WebviewState; postMessage(message: { command: string; payload?: unknown }): void } {
	let state = EMPTY;
	let workspaceRoot: string | undefined;
	let scanning = false;
	let selectionVersion = 0;
	let pickerRequest = 0;
	let reportBundle: { json: unknown; sarif: unknown; pdf: string } | undefined;
	let refreshingRecommendations = false;
	let coreAiSettings: Record<string, unknown> = {};
	const credentialKey = (id: string) => `aqiron.ai.api.${id}`;
	const refreshProviders = async () => {
		const providers = await core('ai.providers') as { providers: string[]; configuredProviders?: Array<{ id: string; configured: boolean }>; credentialSummaries?: WebviewState['ai']['apiCredentials']; settings?: Record<string, unknown> & { selectedProvider?: string; selectedModel?: string; activeApiCredentialId?: string } };
		coreAiSettings = providers.settings ?? coreAiSettings;
		const providerId = providers.settings?.selectedProvider ?? state.ai.selection.provider;
		const modelResult = await core('ai.models') as { models: WebviewState['ai']['models']; status: WebviewState['ai']['status'] };
		const configured = new Map((providers.configuredProviders ?? []).map((item) => [item.id, item.configured]));
		const selectedProvider = providerId as WebviewState['ai']['selection']['provider'];
		const selectedModel = providers.settings?.selectedModel;
		update({ ai: { ...state.ai, providers: providers.providers.map((id) => ({ id: id as WebviewState['ai']['selection']['provider'], name: providerName(id as WebviewState['ai']['selection']['provider']), connected: id === providerId ? modelResult.status.connected : false, message: id === providerId ? modelResult.status.message : 'Not selected', hasCredential: configured.get(id) ?? false })), apiCredentials: providers.credentialSummaries ?? [], models: modelResult.models, filteredModels: filterDesktopModels(modelResult.models, state.ai.modelFilter), status: modelResult.status, taskDefaults: (providers.settings?.taskDefaults as WebviewState['ai']['taskDefaults'] | undefined) ?? state.ai.taskDefaults, settings: { ...state.ai.settings, ...providers.settings, activeApiCredentialId: providers.settings?.activeApiCredentialId, selectedProvider }, selection: { ...state.ai.selection, provider: selectedProvider, model: selectedModel && modelResult.models.some((model) => model.id === selectedModel) ? selectedModel : state.ai.selection.model && modelResult.models.some((model) => model.id === state.ai.selection.model) ? state.ai.selection.model : modelResult.models[0]?.id ?? '' } } });
	};
	const persistAiSettings = async (patch: Record<string, unknown>) => {
		coreAiSettings = { ...coreAiSettings, ...patch, apiCredentials: state.ai.apiCredentials };
		await core('credentials.set', { key: 'aqiron.ai.settings', value: JSON.stringify(coreAiSettings) });
		await refreshProviders();
	};
	const deleteCredential = async (id: string) => {
		try {
			await core('credentials.delete', { key: credentialKey(id) });
			await refreshProviders();
		} catch (error) { window.alert(`Could not delete credential: ${error instanceof Error ? error.message : String(error)}`); }
	};
	const deleteLegacyProviderCredential = async (providerId: string) => {
		if (providerId !== 'openrouter') return;
		try {
			await core('credentials.delete', { key: 'aqiron.ai.openrouter.apiKey' });
			await refreshProviders();
		} catch (error) { window.alert(`Could not delete credential: ${error instanceof Error ? error.message : String(error)}`); }
	};
	const deleteThreatSnapshot = async (snapshotId: string) => {
		if (!workspaceRoot || !state.threatSnapshots.some((snapshot) => snapshot.id === snapshotId)) return;
		try {
			const result = await core('workspace.threat-history.delete', { snapshotId }) as { snapshots: StoredThreatSnapshot[] };
			const snapshots = result.snapshots.map((snapshot) => ({ ...snapshot, issues: snapshot.issues.map((issue) => mapStoredIssue(issue, workspaceRoot!)) }));
			const activeId = state.activeThreatSnapshotId === snapshotId ? snapshots[0]?.id : state.activeThreatSnapshotId;
			const active = snapshots.find((snapshot) => snapshot.id === activeId);
			const issues = active?.issues ?? (state.activeThreatSnapshotId === snapshotId ? [] : state.issues);
			const counts = countFindings(issues);
			update({ threatSnapshots: snapshots, activeThreatSnapshotId: activeId, issues, counts, selectedThreatId: issues[0]?.id, suggestions: rebuildRecommendations(issues), stats: active ? { ...state.stats, filesScanned: active.filesScanned, indexedFiles: active.filesScanned, scanStatus: 'Complete' } : state.activeThreatSnapshotId === snapshotId ? { ...state.stats, filesScanned: 0, indexedFiles: 0, scanStatus: 'Complete' } : state.stats, workspace: { ...state.workspace, risk: counts.critical ? 'Critical' : counts.high ? 'Elevated' : counts.medium ? 'Review' : 'Secure' } });
		} catch (error) { window.alert(`Could not delete threat report: ${error instanceof Error ? error.message : String(error)}`); }
	};
	const removeProviderCredentials = async (providerId: string) => {
		try {
			for (const credential of state.ai.apiCredentials.filter((item) => item.providerId === providerId)) await core('credentials.delete', { key: credentialKey(credential.id) });
			if (providerId === 'openrouter') await core('credentials.delete', { key: 'aqiron.ai.openrouter.apiKey' });
			await refreshProviders();
		} catch (error) { window.alert(`Could not remove provider credentials: ${error instanceof Error ? error.message : String(error)}`); }
	};
	const saveCredential = async (input: Record<string, unknown>) => {
		const providerId = input.providerId;
		const key = typeof input.key === 'string' ? input.key.trim() : '';
		if (typeof providerId !== 'string' || !state.ai.providers.some((provider) => provider.id === providerId) || !key) { window.alert('Choose a provider and enter an API key.'); return; }
		try {
			const id = typeof input.id === 'string' ? input.id : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
			const now = new Date().toISOString();
			const existing = state.ai.apiCredentials.find((credential) => credential.id === id);
			const summary = { id, name: typeof input.name === 'string' && input.name.trim() ? input.name.trim() : existing?.name ?? `${providerId} ${key.slice(-4)}`, providerId: providerId as WebviewState['ai']['selection']['provider'], last4: key.slice(-4), createdAt: existing?.createdAt ?? now, updatedAt: now };
			await core('credentials.set', { key: credentialKey(id), value: key });
			if (providerId === 'openrouter') await core('credentials.set', { key: 'aqiron.ai.openrouter.apiKey', value: key });
			const summaries = [summary, ...state.ai.apiCredentials.filter((credential) => credential.id !== id)];
			await core('credentials.set', { key: 'aqiron.ai.settings', value: JSON.stringify({ ...coreAiSettings, apiCredentials: summaries, activeApiCredentialId: id, selectedProvider: providerId }) });
			await refreshProviders();
		} catch (error) { window.alert(`Could not save credential: ${error instanceof Error ? error.message : String(error)}`); }
	};
	const sendChat = async (payload: unknown) => {
		const input = payload && typeof payload === 'object' ? payload as { text?: unknown; sessionId?: unknown; useTaskDefaults?: unknown } : {};
		const text = typeof input.text === 'string' ? input.text.trim() : '';
		const defaults = state.ai.taskDefaults;
		const useDefaults = input.useTaskDefaults === true && defaults.useChatDefaults === false;
		const providerId = useDefaults && defaults.provider ? defaults.provider : state.ai.selection.provider;
		const model = useDefaults && defaults.model ? defaults.model : state.ai.selection.model;
		const intelligence = useDefaults && defaults.intelligence ? defaults.intelligence : state.ai.selection.intelligence;
		if (!text || !model) { if (text) window.alert('Select an available model before sending.'); return; }
		const now = new Date().toISOString();
		const sessionId = typeof input.sessionId === 'string' ? input.sessionId : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
		const existing = state.chatSessions.find((session) => session.id === sessionId);
		const userMessage = { id: `${sessionId}-u-${Date.now()}`, role: 'user' as const, content: text, createdAt: now };
		const assistantMessage = { id: `${sessionId}-a-${Date.now()}`, role: 'assistant' as const, content: '', createdAt: now, streaming: true };
		const session = existing ?? { id: sessionId, title: text.slice(0, 60), createdAt: now, updatedAt: now, model, intelligence, messages: [] };
		const next = { ...session, model, intelligence, updatedAt: now, streaming: true, messages: [...session.messages, userMessage, assistantMessage] };
		update({ section: 'aiAgent', activeChatSessionId: sessionId, chatSessions: [...state.chatSessions.filter((item) => item.id !== sessionId), next] });
		try {
			const result = await core('ai.chat', { sessionId, providerId, model, text, intelligence, history: session.messages.map((message) => ({ role: message.role, content: message.content })), context: { workspaceName: state.workspace.name, workspaceRoot, projectTypes: state.workspace.types, backend: state.workspace.backend, currentFile: 'No file', stats: { filesScanned: state.stats.filesScanned, indexedFiles: state.stats.indexedFiles }, apis: state.workspace.apis, issues: state.issues.slice(0, 20).map((issue) => ({ title: issue.title, message: issue.message, severity: issue.severity, ruleId: issue.ruleId, file: issue.relativeFile, line: issue.line, remediation: '' })) } }) as { text: string };
			finishChat(sessionId, assistantMessage.id, result.text || 'The provider returned an empty response.');
		} catch (error) { finishChat(sessionId, assistantMessage.id, `Chat failed: ${error instanceof Error ? error.message : String(error)}`); }
	};
	const saveSessions = async (chatSessions: WebviewState['chatSessions'], activeChatSessionId = state.activeChatSessionId) => {
		if (!workspaceRoot) { window.alert('Select a project before saving conversation history.'); return; }
		try {
			const result = await core('workspace.agent-sessions.set', { sessions: chatSessions }) as { sessions: WebviewState['chatSessions'] };
			update({ chatSessions: result.sessions, activeChatSessionId: activeChatSessionId && result.sessions.some((session) => session.id === activeChatSessionId) ? activeChatSessionId : result.sessions[0]?.id });
		} catch (error) { window.alert(`Could not save conversation history: ${error instanceof Error ? error.message : String(error)}`); }
	};
	const loadProviderModels = async (providerId: string, activeApiCredentialId?: string) => {
		const selectedProvider = providerId as WebviewState['ai']['selection']['provider'];
		const settings = { ...coreAiSettings, ...(activeApiCredentialId ? { activeApiCredentialId } : {}), selectedProvider };
		if (activeApiCredentialId) {
			await core('credentials.set', { key: 'aqiron.ai.settings', value: JSON.stringify({ ...settings, apiCredentials: state.ai.apiCredentials }) });
			coreAiSettings = { ...settings, apiCredentials: state.ai.apiCredentials };
		}
		update({ ai: { ...state.ai, loadingModels: true, modelError: undefined, models: [], filteredModels: [], status: { ...state.ai.status, connected: false, message: 'Loading models…' }, settings: { ...state.ai.settings, selectedProvider, activeApiCredentialId: activeApiCredentialId ?? state.ai.settings.activeApiCredentialId }, selection: { ...state.ai.selection, provider: selectedProvider, model: '' } } });
		try {
			const result = await core('ai.models', activeApiCredentialId ? {} : { providerId }) as { models: WebviewState['ai']['models']; status: WebviewState['ai']['status'] };
			const providers = await core('ai.providers') as { settings?: Record<string, unknown> & { activeApiCredentialId?: string; selectedModel?: string; selectedProvider?: string } };
			coreAiSettings = providers.settings ?? coreAiSettings;
			const model = typeof coreAiSettings.selectedModel === 'string' && result.models.some((item) => item.id === coreAiSettings.selectedModel) ? coreAiSettings.selectedModel : result.models[0]?.id ?? '';
			update({ ai: { ...state.ai, loadingModels: false, modelError: result.status.connected ? undefined : result.status.message, providers: state.ai.providers.map((provider) => ({ ...provider, connected: provider.id === selectedProvider ? result.status.connected : false, message: provider.id === selectedProvider ? result.status.message : 'Not selected' })), models: result.models, filteredModels: filterDesktopModels(result.models, state.ai.modelFilter), status: result.status, settings: { ...state.ai.settings, activeApiCredentialId: providers.settings?.activeApiCredentialId, selectedProvider }, selection: { ...state.ai.selection, model } } });
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			update({ ai: { ...state.ai, loadingModels: false, modelError: message, models: [], filteredModels: [], status: { ...state.ai.status, connected: false, message } } });
			throw error;
		}
	};
	const finishChat = async (sessionId: string, messageId: string, content: string) => {
		const chatSessions = state.chatSessions.map((session) => session.id === sessionId ? { ...session, streaming: false, updatedAt: new Date().toISOString(), messages: session.messages.map((message) => message.id === messageId ? { ...message, content, streaming: false } : message) } : session);
		await saveSessions(chatSessions, sessionId);
	};
	const rebuildRecommendations = (issues: WebviewState['issues']) => state.rag.suggestionsGenerated ? buildWorkspaceRecommendations(issues, state.rag.suggestions) : [];
	const refreshRecommendations = async () => {
		if (!workspaceRoot || refreshingRecommendations) { return; }
		const root = workspaceRoot;
		const version = selectionVersion;
		refreshingRecommendations = true;
		update({ rag: { ...state.rag, building: true, withAi: true, suggestionError: undefined } });
		try {
			await core('rag.index', { withAi: true });
			if (version !== selectionVersion || root !== workspaceRoot) { return; }
			const result = await core('workspace.recommendations.get') as { generated: boolean; suggestions: string[] };
			if (version !== selectionVersion || root !== workspaceRoot) { return; }
			const suggestions = result.generated ? buildWorkspaceRecommendations(state.issues, result.suggestions) : [];
			update({ suggestions, rag: { ...state.rag, ready: true, building: false, withAi: true, suggestionsGenerated: result.generated, suggestions: result.suggestions, suggestionError: undefined } });
		} catch (error) {
			if (version === selectionVersion && root === workspaceRoot) {
				update({ rag: { ...state.rag, building: false, suggestionError: error instanceof Error ? error.message : String(error) } });
			}
		} finally {
			refreshingRecommendations = false;
		}
	};
	const update = (next: Partial<WebviewState>) => {
		state = { ...state, ...next };
		window.dispatchEvent(new MessageEvent('message', { data: { type: 'state', state } }));
	};
	const core = (method: DesktopCommand, params: unknown = {}) => import('@tauri-apps/api/core').then(({ invoke }) => invoke<unknown>('core_request', { method, params }));
	void import('@tauri-apps/api/event').then(({ listen }) => listen<DesktopCoreEvent>('desktop-core-event', ({ payload }) => {
		const event = payload.event ?? '';
		if (event === 'ai.token' && typeof payload.requestId === 'string' && typeof payload.payload?.content === 'string') {
			const sessionId = payload.requestId;
			update({ chatSessions: state.chatSessions.map((session) => session.id === sessionId ? { ...session, messages: session.messages.map((message, index) => index === session.messages.length - 1 && message.role === 'assistant' && message.streaming ? { ...message, content: message.content + String(payload.payload?.content) } : message) } : session) });
			return;
		}
		if (event === 'core.disconnected') {
			update({ stats: { ...state.stats, scanStatus: scanning ? 'Failed' : state.stats.scanStatus }, pipeline: { ...state.pipeline, logs: [...state.pipeline.logs, 'Aqiron Core disconnected. Run the scan again to reconnect.'] } });
			return;
		}
		if (event.startsWith('scan.')) {
			const detail = payload.payload ?? {};
			const stage = String(detail.stage ?? detail.name ?? event);
			const progressValue = Number(detail.progress ?? detail.percent ?? 0);
			const previous = state.pipeline.stages.filter((item) => item.name !== stage);
			const complete = event.endsWith('.completed') || event === 'scan.completed';
			update({ pipeline: { ...state.pipeline, stages: [...previous, { name: stage, status: complete ? 'completed' : 'running', progress: complete ? 100 : Number.isFinite(progressValue) ? progressValue : 0 }], logs: [...state.pipeline.logs, `${event}: ${stage}`].slice(-250) } });
		}
	}));
	const scan = async (mode: 'quick' | 'deep' | 'analysis' = 'deep') => {
		if (!workspaceRoot || scanning) { return; }
		const scanRoot = workspaceRoot;
		const scanVersion = selectionVersion;
		scanning = true;
		update({ section: 'scan', stats: { ...state.stats, scanStatus: 'Scanning' }, pipeline: { stages: [], tools: [], logs: ['Starting Aqiron Core scan…'] } });
		try {
			const result = await core('scan.start', { workspaceRoot, trusted: true, mode }) as { findings: UnifiedFinding[]; filesScanned?: number; durationMs?: number; report?: { model: { generatedAt: string; executiveSummary: string; summary: WebviewState['counts'] }; json: unknown; text: string; sarif: unknown; pdf: string }; scanId?: string };
			if (scanVersion !== selectionVersion) { return; }
			reportBundle = result.report;
			const issues = (result.findings ?? []).map((finding) => mapFinding(finding, scanRoot));
			const counts = countFindings(issues);
			const risk = counts.critical ? 'Critical' : counts.high ? 'Elevated' : counts.medium ? 'Review' : 'Secure';
			const filesScanned = result.filesScanned ?? 0;
			update({ section: 'threats', issues, counts, suggestions: rebuildRecommendations(issues), selectedThreatId: issues[0]?.id,
				stats: { filesScanned, indexedFiles: filesScanned, scanStatus: 'Complete', lastScanDurationMs: result.durationMs ?? 0 },
				workspace: { ...state.workspace, risk },
				pipeline: { ...state.pipeline, stages: state.pipeline.stages.map((stage) => ({ ...stage, status: 'completed', progress: 100 })), lastReport: { executiveSummary: result.report?.model?.executiveSummary, reportData: result.report ? { model: { generatedAt: result.report.model.generatedAt, executiveSummary: result.report.model.executiveSummary, summary: result.report.model.summary }, text: result.report.text } : undefined, artifactsAvailable: { pdf: Boolean(result.report?.pdf), json: Boolean(result.report?.json), sarif: Boolean(result.report?.sarif) } } },
				threatSnapshots: [{ id: result.scanId ?? String(Date.now()), title: 'Latest scan', createdAt: new Date().toISOString(), filesScanned, executiveSummary: result.report?.model?.executiveSummary, issues }],
				activeThreatSnapshotId: result.scanId,
			});
		} catch (error) {
			if (scanVersion !== selectionVersion) { return; }
			update({ stats: { ...state.stats, scanStatus: 'Failed' }, pipeline: { ...state.pipeline, stages: state.pipeline.stages.map((stage) => ({ ...stage, status: 'failed' })), logs: [...state.pipeline.logs, `Scan failed: ${error instanceof Error ? error.message : String(error)}`] } });
		} finally { scanning = false; }
	};
	const loadWorkspace = async (selection: string, request: number) => {
		const selectedVersion = ++selectionVersion;
		workspaceRoot = selection;
		reportBundle = undefined;
		update({ desktopProjectError: undefined, desktopProjectLoading: true,
			workspace: { ...state.workspace, name: folderName(selection), root: undefined, types: [], status: 'Indexing', risk: 'Secure', backend: 'Aqiron Core' },
			issues: [], selectedThreatId: undefined, counts: emptyCounts(), threatSnapshots: [], activeThreatSnapshotId: undefined,
			stats: { filesScanned: 0, indexedFiles: 0, scanStatus: 'Idle', lastScanDurationMs: 0 },
			pipeline: { stages: [], tools: [], logs: [] },
			ai: { ...state.ai, providers: [], models: [], filteredModels: [], apiCredentials: [], selection: { ...state.ai.selection, model: '' } }, customRules: '[]', chatSessions: [], activeChatSessionId: undefined, suggestions: [], rag: { ...state.rag, ready: false, suggestionsGenerated: false, suggestions: [], suggestionError: undefined },
		});
		try {
			const detected = await core('project.detect') as { projectTypes?: string[]; frameworks?: string[]; languages?: string[] };
			const profile = await core('project.profile') as { projectProfile?: { projectTypes?: string[]; frameworks?: string[]; languages?: string[] } };
			const providers = await core('ai.providers') as { providers: string[]; configuredProviders?: Array<{ id: string; configured: boolean }>; credentialSummaries?: WebviewState['ai']['apiCredentials']; settings?: Record<string, unknown> & { selectedProvider?: string; selectedModel?: string; activeApiCredentialId?: string } };
			coreAiSettings = providers.settings ?? {};
			const providerId = providers.settings?.selectedProvider ?? state.ai.selection.provider ?? 'openrouter';
			const modelResult = await core('ai.models') as { models: WebviewState['ai']['models']; status: WebviewState['ai']['status'] };
			const [ruleResult, historyResult, sessionResult, recommendationResult, reportResult] = await Promise.all([
				core('workspace.rules.get') as Promise<{ rules: unknown[] }>,
				core('workspace.threat-history.get') as Promise<{ snapshots: StoredThreatSnapshot[] }>,
				core('workspace.agent-sessions.get') as Promise<{ sessions: WebviewState['chatSessions'] }>,
				core('workspace.recommendations.get').then((result) => ({ ...(result as { generated: boolean; suggestions: string[] }), error: undefined as string | undefined }), (error: unknown) => ({ generated: false, suggestions: [], error: error instanceof Error ? error.message : String(error) })),
				core('workspace.reports.get') as Promise<{ directory?: string; jsonPath?: string; sarifPath?: string; pdfPath?: string; sizes?: { json?: number; sarif?: number; pdf?: number }; modifiedAt?: string }>,
			]);
			if (request !== pickerRequest || selectedVersion !== selectionVersion) { return; }
			const { invoke } = await import('@tauri-apps/api/core');
			let persistenceError: string | undefined;
			try { await invoke('remember_project', { workspaceRoot: selection }); }
			catch (error) { persistenceError = error instanceof Error ? error.message : String(error); }
			if (request !== pickerRequest || selectedVersion !== selectionVersion) { return; }
			const project = profile.projectProfile ?? detected;
			const configured = new Map((providers.configuredProviders ?? []).map((item) => [item.id, item.configured]));
			const issues = (historyResult.snapshots[0]?.issues ?? []).map((issue) => mapStoredIssue(issue, selection));
			const counts = countFindings(issues);
			const suggestions = recommendationResult.generated ? buildWorkspaceRecommendations(issues, recommendationResult.suggestions) : [];
			const selectedProvider = providerId as WebviewState['ai']['selection']['provider'];
			update({ desktopProjectError: undefined, desktopProjectLoading: false, workspace: { ...state.workspace, name: folderName(selection), root: selection, types: project.projectTypes ?? project.frameworks ?? project.languages ?? [], status: 'Ready', backend: 'Aqiron Core', risk: counts.critical ? 'Critical' : counts.high ? 'Elevated' : counts.medium ? 'Review' : 'Secure' }, issues, counts, selectedThreatId: issues[0]?.id, threatSnapshots: historyResult.snapshots.map((snapshot) => ({ ...snapshot, issues: snapshot.issues.map((issue) => mapStoredIssue(issue, selection)) })), activeThreatSnapshotId: historyResult.snapshots[0]?.id, stats: historyResult.snapshots[0] ? { ...state.stats, filesScanned: historyResult.snapshots[0].filesScanned, indexedFiles: historyResult.snapshots[0].filesScanned, scanStatus: 'Complete' } : state.stats, suggestions, chatSessions: sessionResult.sessions, activeChatSessionId: sessionResult.sessions[0]?.id, ai: { ...state.ai, providers: providers.providers.map((id) => ({ id: id as WebviewState['ai']['selection']['provider'], name: providerName(id as WebviewState['ai']['selection']['provider']), connected: id === providerId ? modelResult.status.connected : false, message: id === providerId ? modelResult.status.message : 'Not selected', hasCredential: configured.get(id) ?? false })), models: modelResult.models, filteredModels: filterDesktopModels(modelResult.models, state.ai.modelFilter), status: modelResult.status, apiCredentials: providers.credentialSummaries ?? [], selection: { ...state.ai.selection, provider: selectedProvider, model: state.ai.selection.model && modelResult.models.some((item) => item.id === state.ai.selection.model) ? state.ai.selection.model : modelResult.models[0]?.id ?? '' } }, customRules: JSON.stringify(ruleResult.rules, null, 2), rag: { ...state.rag, ready: recommendationResult.generated, suggestionsGenerated: recommendationResult.generated, suggestions: recommendationResult.suggestions, suggestionError: recommendationResult.error }, pipeline: { ...state.pipeline, lastReport: reportResult.directory ? { directory: reportResult.directory, pdfPath: reportResult.pdfPath, jsonPath: reportResult.jsonPath, sarifPath: reportResult.sarifPath, sizes: reportResult.sizes, modifiedAt: reportResult.modifiedAt, artifactsAvailable: { pdf: Boolean(reportResult.pdfPath), json: Boolean(reportResult.jsonPath), sarif: Boolean(reportResult.sarifPath) } } : undefined } });
			if (persistenceError) { window.alert(`Project selected, but could not remember it for the next launch: ${persistenceError}`); }
		} catch (error) {
			if (request !== pickerRequest || selectedVersion !== selectionVersion) { return; }
			selectionVersion++;
			workspaceRoot = undefined;
			try { const { invoke } = await import('@tauri-apps/api/core'); await invoke('forget_project'); } catch { /* A fresh launch remains in the no-project state if clearing fails. */ }
			const message = `Project detection failed: ${error instanceof Error ? error.message : String(error)}`;
			update({ desktopProjectError: message, desktopProjectLoading: false, workspace: { ...state.workspace, name: 'No project selected', root: undefined, types: [], status: 'No workspace' }, pipeline: { ...state.pipeline, logs: [...state.pipeline.logs, message] } });
		}
	};
	const restoreWorkspace = async () => {
		const request = ++pickerRequest;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const selection = await invoke<string | null>('restore_last_project');
			if (request !== pickerRequest || typeof selection !== 'string') { return; }
			await loadWorkspace(selection, request);
		} catch (error) {
			if (request !== pickerRequest) { return; }
			selectionVersion++;
			workspaceRoot = undefined;
			try { const { invoke } = await import('@tauri-apps/api/core'); await invoke('forget_project'); } catch { /* Restoration failures fall back to manual selection. */ }
			const message = `Project detection failed: ${error instanceof Error ? error.message : String(error)}`;
			update({ desktopProjectError: message, desktopProjectLoading: false, workspace: { ...state.workspace, name: 'No project selected', root: undefined, types: [], status: 'No workspace' }, pipeline: { ...state.pipeline, logs: [...state.pipeline.logs, message] } });
		}
	};
	const selectWorkspace = async () => {
		const request = ++pickerRequest;
		try {
			const { invoke } = await import('@tauri-apps/api/core');
			const selection = await invoke<string | null>('select_workspace');
			if (request !== pickerRequest || typeof selection !== 'string') { return; }
			await loadWorkspace(selection, request);
		} catch (error) {
			if (request !== pickerRequest) { return; }
			selectionVersion++;
			workspaceRoot = undefined;
			const message = `Project detection failed: ${error instanceof Error ? error.message : String(error)}`;
			update({ desktopProjectError: message, desktopProjectLoading: false, workspace: { ...state.workspace, name: 'No project selected', root: undefined, types: [], status: 'No workspace' }, pipeline: { ...state.pipeline, logs: [...state.pipeline.logs, message] } });
		}
	};
	return {
		state,
		postMessage: ({ command, payload }) => {
			if (command === 'focus' && typeof payload === 'string') { update({ section: payload as WebviewState['section'] }); }
			else if (command === 'selectWorkspace') { void selectWorkspace(); }
			else if (command === 'scanWorkspace') { void scan(); }
			else if (command === 'ragRefreshSuggestions') { void refreshRecommendations(); }
			else if (command === 'aiVulnerabilityAnalysis') { void scan('analysis'); }
			else if (command === 'sendChat') { void sendChat(payload); }
			else if (command === 'configureProvider' && typeof payload === 'string' && state.ai.providers.some((provider) => provider.id === payload)) { update({ section: 'settings', ai: { ...state.ai, selection: { ...state.ai.selection, provider: payload as WebviewState['ai']['selection']['provider'] } } }); }
			else if (command === 'selectThreatSnapshot' && typeof payload === 'string') {
				const snapshot = state.threatSnapshots.find((item) => item.id === payload);
				if (snapshot) {
					const counts = countFindings(snapshot.issues);
				update({ activeThreatSnapshotId: snapshot.id, issues: snapshot.issues, counts, suggestions: rebuildRecommendations(snapshot.issues), selectedThreatId: snapshot.issues[0]?.id, stats: { ...state.stats, filesScanned: snapshot.filesScanned, indexedFiles: snapshot.filesScanned, scanStatus: 'Complete' }, workspace: { ...state.workspace, risk: counts.critical ? 'Critical' : counts.high ? 'Elevated' : counts.medium ? 'Review' : 'Secure' } });
				}
			}
			else if (command === 'deleteThreatSnapshot' && typeof payload === 'string') { void deleteThreatSnapshot(payload); }
			else if (command === 'openChatSession' && typeof payload === 'string' && state.chatSessions.some((session) => session.id === payload)) { update({ section: 'aiAgent', activeChatSessionId: payload }); }
			else if (command === 'renameChatSession' && payload && typeof payload === 'object') {
				const input = payload as { sessionId?: unknown; title?: unknown };
				const title = typeof input.title === 'string' ? input.title.trim() : '';
				if (typeof input.sessionId === 'string' && title) { void saveSessions(state.chatSessions.map((session) => session.id === input.sessionId ? { ...session, title, updatedAt: new Date().toISOString() } : session)); }
			}
			else if (command === 'deleteChatSession' && typeof payload === 'string') { void saveSessions(state.chatSessions.filter((session) => session.id !== payload), state.activeChatSessionId === payload ? undefined : state.activeChatSessionId); }
			else if (command === 'switchProvider' && typeof payload === 'string') { void loadProviderModels(payload).catch((error) => window.alert(`Could not load provider models: ${error instanceof Error ? error.message : String(error)}`)); }
			else if (command === 'selectModel' && typeof payload === 'string' && state.ai.models.some((model) => model.id === payload)) { update({ ai: { ...state.ai, selection: { ...state.ai.selection, model: payload } } }); void persistAiSettings({ selectedModel: payload }).catch((error) => window.alert(`Could not save selected model: ${error instanceof Error ? error.message : String(error)}`)); }
			else if (command === 'refreshModels') { void refreshProviders().catch((error) => window.alert(`Could not refresh provider models: ${error instanceof Error ? error.message : String(error)}`)); }
			else if (command === 'applyModelFilter' && payload && typeof payload === 'object') { const filter = { ...state.ai.modelFilter, ...(payload as Partial<WebviewState['ai']['modelFilter']>) }; const query = filter.query.trim().toLowerCase(); const models = state.ai.models.filter((model) => (!filter.freeOnly || model.badges.includes('free')) && (!filter.codingOnly || model.capabilities.includes('code')) && (!filter.reasoningOnly || model.capabilities.includes('reasoning')) && (!filter.visionOnly || model.capabilities.includes('vision')) && (!query || [model.id, model.label, model.description ?? '', ...model.badges, ...model.capabilities].some((part) => part.toLowerCase().includes(query)))); update({ ai: { ...state.ai, modelFilter: filter, filteredModels: models } }); }
			else if (command === 'deleteApiCredential' && typeof payload === 'string') { void deleteCredential(payload); }
			else if (command === 'deleteLegacyProviderCredential' && typeof payload === 'string') { void deleteLegacyProviderCredential(payload); }
			else if (command === 'removeProviderCredentials' && typeof payload === 'string') { void removeProviderCredentials(payload); }
			else if (command === 'saveApiCredential' && payload && typeof payload === 'object') { void saveCredential(payload as Record<string, unknown>); }
			else if (command === 'selectApiCredential' && typeof payload === 'string') { const selected = state.ai.apiCredentials.find((api) => api.id === payload); if (selected) { void loadProviderModels(selected.providerId, selected.id).catch((error) => window.alert(`Could not select provider: ${error instanceof Error ? error.message : String(error)}`)); } }
			else if (command === 'selectIntelligence' && typeof payload === 'string' && state.ai.intelligenceProfiles.some((profile) => profile.level === payload)) { update({ ai: { ...state.ai, selection: { ...state.ai.selection, intelligence: payload } } }); }
			else if (command === 'cancelGeneration') { const sessionId = typeof payload === 'string' ? payload : state.activeChatSessionId; if (sessionId) { void core('ai.cancel', { sessionId }).catch((error) => window.alert(`Could not cancel generation: ${error instanceof Error ? error.message : String(error)}`)); } }
			else if (command === 'saveProviderSettings' && payload && typeof payload === 'object') { const input = payload as Record<string, unknown>; void persistAiSettings({ temperature: clampFloat(input.temperature, 0, 2), maxTokens: clampNumber(input.maxTokens, 16, 1_000_000), timeoutMs: clampNumber(input.timeoutMs, 5_000, 600_000), retries: clampNumber(input.retries, 0, 5), ...(typeof input.streaming === 'boolean' ? { streaming: input.streaming } : {}) }).catch((error) => window.alert(`Could not save AI settings: ${error instanceof Error ? error.message : String(error)}`)); }
			else if (command === 'saveTaskDefaults' && payload && typeof payload === 'object') { void persistAiSettings({ taskDefaults: { ...(coreAiSettings.taskDefaults as Record<string, unknown> ?? {}), ...(payload as Record<string, unknown>) } }).catch((error) => window.alert(`Could not save AI defaults: ${error instanceof Error ? error.message : String(error)}`)); }
			else if (command === 'exportReport' && (payload === 'pdf' || payload === 'json' || payload === 'sarif')) { const exportPromise = reportBundle ? import('@tauri-apps/api/core').then(({ invoke }) => invoke('save_report_artifact', { format: payload, report: reportBundle })) : state.pipeline.lastReport?.[`${payload}Path` as 'pdfPath' | 'jsonPath' | 'sarifPath'] ? import('@tauri-apps/api/core').then(({ invoke }) => invoke('save_existing_report_artifact', { format: payload })) : Promise.reject(new Error('That report artifact is unavailable for the active project.')); void exportPromise.catch((error) => window.alert(`Report export failed: ${error instanceof Error ? error.message : String(error)}`)); }
			else if (command === 'exportFinding' && typeof payload === 'string') { void import('@tauri-apps/api/core').then(({ invoke }) => invoke('export_finding', { findingId: payload })).catch((error) => window.alert(`Finding export failed: ${error instanceof Error ? error.message : String(error)}`)); }
			else if (command === 'openIssue' && typeof payload === 'string') { void import('@tauri-apps/api/core').then(({ invoke }) => invoke('open_finding_file', { findingId: payload })).catch((error) => window.alert(`Unable to open finding: ${error instanceof Error ? error.message : String(error)}`)); }
			else if (command === 'saveCustomRules' && typeof payload === 'string') {
				try {
					const rules: unknown = JSON.parse(payload);
					if (!Array.isArray(rules)) throw new Error('Custom rules must be a JSON array.');
					void core('workspace.rules.set', { rules }).then((result) => update({ customRules: JSON.stringify((result as { rules: unknown[] }).rules, null, 2) })).catch((error) => window.alert(`Could not save custom rules: ${error instanceof Error ? error.message : String(error)}`));
				} catch (error) { window.alert(`Could not save custom rules: ${error instanceof Error ? error.message : String(error)}`); }
			}
			else if (command === 'ready') { void restoreWorkspace(); }
			else if (command === 'clearTerminal') { update({ pipeline: { ...state.pipeline, logs: [] } }); }
		},
	};
}

function folderName(path: string): string { return path.split(/[\\/]/).filter(Boolean).at(-1) ?? path; }
function clampNumber(value: unknown, minimum: number, maximum: number): number { const numeric = typeof value === 'number' && Number.isFinite(value) ? value : minimum; return Math.max(minimum, Math.min(maximum, Math.floor(numeric))); }
function clampFloat(value: unknown, minimum: number, maximum: number): number { const numeric = typeof value === 'number' && Number.isFinite(value) ? value : minimum; return Math.max(minimum, Math.min(maximum, numeric)); }

function filterDesktopModels(models: WebviewState['ai']['models'], filter: WebviewState['ai']['modelFilter']): WebviewState['ai']['models'] {
	const query = filter.query.trim().toLowerCase();
	return models.filter((model) => (!filter.freeOnly || model.badges.includes('free')) && (!filter.codingOnly || model.capabilities.includes('code')) && (!filter.reasoningOnly || model.capabilities.includes('reasoning')) && (!filter.visionOnly || model.capabilities.includes('vision')) && (!query || [model.id, model.label, model.description ?? '', ...model.badges, ...model.capabilities].some((part) => part.toLowerCase().includes(query))));
}

interface StoredThreatSnapshot { id: string; title: string; createdAt: string; filesScanned: number; executiveSummary?: string; issues: Array<Record<string, unknown>>; }

function mapStoredIssue(issue: Record<string, unknown>, root: string): WebviewState['issues'][number] {
	const file = typeof issue.file === 'string' ? issue.file : '';
	const range = issue.range && typeof issue.range === 'object' ? issue.range as Record<string, unknown> : {};
	const start = typeof range.startLine === 'number' ? range.startLine : (range.start && typeof range.start === 'object' && typeof (range.start as Record<string, unknown>).line === 'number' ? (range.start as Record<string, unknown>).line as number : 0);
	const normalizedRoot = root.replace(/[\\/]+$/, '');
	const relativeFile = file.toLowerCase().startsWith(`${normalizedRoot.toLowerCase()}${file.includes('\\') ? '\\' : '/'}`) ? file.slice(normalizedRoot.length).replace(/^[\\/]+/, '') : file;
	const severity = ['Critical', 'High', 'Medium', 'Low'].includes(String(issue.severity)) ? issue.severity as WebviewState['issues'][number]['severity'] : 'Medium';
	return { id: String(issue.id), title: String(issue.title ?? issue.ruleId ?? 'Security finding'), message: String(issue.message ?? ''), severity, ruleId: String(issue.ruleId ?? ''), file, relativeFile, line: start + 1, column: typeof range.startColumn === 'number' ? range.startColumn + 1 : 1, lineText: String(issue.lineText ?? ''), tool: String(issue.sourceTool ?? 'Aqiron'), cwe: Array.isArray(issue.cwe) ? issue.cwe.join(', ') : '', owasp: Array.isArray(issue.owasp) ? issue.owasp.join(', ') : '', status: String(issue.status ?? 'Open'), confidence: String(issue.confidence ?? 'Medium'), riskScore: typeof issue.riskScore === 'number' ? issue.riskScore : 0, rawEvidence: issue.rawEvidence };
}

function emptyCounts(): WebviewState['counts'] { return { total: 0, critical: 0, high: 0, medium: 0, low: 0, filesAffected: 0 }; }

function makeInitialState(): WebviewState {
	return {
		section: 'scan', setupDone: true,
		workspace: { name: 'No project selected', types: [], status: 'No workspace', risk: 'Secure', hasGit: false, backend: 'Aqiron Core', apis: [], currentFile: 'No file' },
		branches: [], stats: { filesScanned: 0, indexedFiles: 0, scanStatus: 'Idle', lastScanDurationMs: 0 },
		counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0, filesAffected: 0 }, issues: [], suggestions: [], zoom: 1,
		threatSnapshots: [], memory: { previousPrompts: [], ignoredFindings: [], frameworksDetected: [], apisDiscovered: [], previousScans: [] },
		graph: { nodes: [], edges: [] }, compliance: [], timeline: [], chatSessions: [], tokenUsage: { promptTokens: 0, completionTokens: 0, totalTokens: 0, contextWindow: 128000, contextUsed: 0 },
		ai: { providers: [], models: [], filteredModels: [], modelFilter: { query: '', freeOnly: false, codingOnly: false, reasoningOnly: false, visionOnly: false }, loadingModels: false, status: { connected: false, message: 'Configure an AI provider in Aqiron Security for agent features.' }, settings: { selectedProvider: 'openrouter', temperature: 0.2, maxTokens: 4096, timeoutMs: 60000, retries: 2, streaming: true }, apiCredentials: [], taskDefaults: {} as WebviewState['ai']['taskDefaults'], permissionModes: [], intelligenceProfiles: [], selection: { provider: 'openrouter', model: '', permissionMode: 'read-only', intelligence: 'balanced' } },
		mobsf: { baseUrl: '', apiKeyConfigured: false }, customRules: '[]', pipeline: { stages: [], tools: [], logs: [] }, assets: {
			logo: aqironLogo, scanIcon: '/assets/others/scan.svg', threatIcon: '/assets/others/threat.svg', agentIcon: '/assets/tab/agents.svg', reportsIcon: '/assets/tab/reports.svg', infoIcon: '/assets/chat/info.svg', initializationGrid: '/assets/generated/cyber-grid.svg',
		}, rag: { ready: true, building: false, withAi: false, suggestionsGenerated: false, suggestions: [], restricted: false, backend: 'local' },
	} as unknown as WebviewState;
}

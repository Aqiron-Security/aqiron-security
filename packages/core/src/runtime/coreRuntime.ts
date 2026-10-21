import * as path from 'node:path';
import { AIService } from '../ai/services/aiService';
import { resolveChatGenerationPolicy } from '../ai/services/chatGenerationPolicy';
import { AIVulnerabilityAnalysis, AIAnalysisResult } from '../ai/analysis/aiVulnerabilityAnalysis';
import { AIReviewService } from '../ai/analysis/aiReview';
import { createNetworkTransport } from '../ai/utils/request';
import { createNodeFileSystem, createNodeLogger, createNodeNetworkClient, createNodeProcessRunner, NodeCredentialStore } from './nodeAdapters';
import { CORE_PROTOCOL_VERSION, CoreAgentSession, CoreAiChatRequest, CoreAiModelsRequest, CoreAiModelsResult, CoreAiProvidersResult, CoreAiReviewRequest, CoreAiVulnerabilityAnalysisRequest, CoreCredentialsDeleteRequest, CoreCredentialsSetRequest, CoreCredentialsStatusResult, CoreEventMessage, CoreHandshakeRequest, CoreHandshakeResponse, CoreHealthResult, CoreInfoResult, CoreMessage, CoreMethod, CoreMethodResults, CoreProjectDetectRequest, CoreProjectProfileResult, CoreRagIndexRequest, CoreRagIndexResult, CoreRagQueryRequest, CoreRagQueryResult, CoreRagStatusResult, CoreRequestMessage, CoreResponseMessage, CoreScanStartRequest, CoreScanStartResult, CoreScanStatusResult, CoreRuntimeServicesState, CoreReportGenerateRequest } from './protocol';
import { ProjectDetectorOptions, detectProjectProfile } from '../project/projectDetector';
import { SecurityContextBuilder } from '../context';
import { RagIndexService, RagRetrievalService } from '../rag';
import { ScannerManager } from '../scanners';
import { BetterleaksScanner, MobSfScanner, NativeWorkspaceScanner, OsvScanner, SemgrepScanner, TrivyScanner } from '../scanners';
import { CoreScanService } from '../orchestration';
import { ReportGenerator } from '../reports';
import { PipelineEventBus, ScanState } from '../shared/pipeline';
import { CancellationSource, createCancellationSource, CancellationTokenLike } from '../shared/cancellation';
import { UnifiedFinding } from '../shared/finding';
import { SecurityGraph } from '../correlation/relationshipGraph';
import { CorrelationResult } from '../correlation/correlationEngine';
import { AITransport } from '../ai/utils/request';
import { AIContextSnapshot, AIProviderId, OpenRouterReasoningOptions, ProviderCompletionMetadata } from '../shared/ai';
import { ProjectProfile } from '../project/projectProfile';
import { SecurityReportContent } from '../reports/reportModels';
import { CredentialStore } from '../shared/platform';
import { WorkspaceRuleStore } from '../shared/workspaceRules';
import { aiSecretKeys } from '../ai/services/credentialService';
import { parseRecommendationSourceDetailed } from '../shared/recommendations';
import { HypothesisStoreService } from '../hypotheses/hypothesisStore';
import { buildHypothesisSnapshot, generateDeterministicHypotheses } from '../hypotheses/hypothesisEngine';
import { HypothesisGenerationDiagnostics, HypothesisGenerationResult, HypothesisReviewInput, HypothesisReviewResult, SecurityHypothesis } from '../hypotheses/contracts';
import { FindingSourceProvenance } from '../shared/sourceProvenance';

interface CoreRuntimeOptions {
	coreVersion: string;
	protocolVersion?: number;
	credentialStore?: CredentialStore;
	aiTransport?: AITransport;
}

interface ScanStateRecord {
	state: ScanState;
	result?: CoreScanStartResult;
	sourceProvenance?: FindingSourceProvenance[];
	excludedProvenanceCount?: number;
}

interface ActiveRequest {
	source: CancellationSource;
	onCancel?: () => void;
}

interface InternalAiChatOptions {
	maxTokens?: number;
	openRouterReasoning?: OpenRouterReasoningOptions;
	includeUsage?: boolean;
	completion?: { finishReason?: string; providerCompletion?: ProviderCompletionMetadata };
}

export class CoreRuntime {
	private readonly startedAt = new Date().toISOString();
	private readonly logger = createNodeLogger('aqiron-core-runtime');
	private readonly filesystem = createNodeFileSystem();
	private readonly networkClient = createNodeNetworkClient(this.logger);
	private readonly processRunner = createNodeProcessRunner();
	private readonly credentialStore: CredentialStore;
	private readonly transport: AITransport;
	private readonly aiService: AIService;
	private aiReady?: Promise<void>;
	private readonly aiReview: AIReviewService;
	private readonly ragIndex = new RagIndexService({ filesystem: this.filesystem, networkClient: this.networkClient });
	private readonly ragRetrieval = new RagRetrievalService(this.ragIndex);
	private readonly contextBuilder = new SecurityContextBuilder({ filesystem: this.filesystem });
	private readonly scannerManager = new ScannerManager();
	private readonly nativeScanner: NativeWorkspaceScanner;
	private readonly workspaceRules = new WorkspaceRuleStore(this.filesystem);
	private readonly hypotheses = new HypothesisStoreService(this.filesystem);
	private readonly reportGenerator = new ReportGenerator();
	private readonly pipeline = new CoreScanService();
	private readonly events = new PipelineEventBus();
	private readonly scans = new Map<string, ScanStateRecord>();
	private readonly activeRequests = new Map<string, ActiveRequest>();
	private readonly runtimeState: CoreRuntimeServicesState;
	private shutdownRequested = false;

	constructor(private readonly options: CoreRuntimeOptions) {
		this.credentialStore = options.credentialStore ?? new NodeCredentialStore();
		this.transport = options.aiTransport ?? createNetworkTransport(this.networkClient);
		this.nativeScanner = new NativeWorkspaceScanner(this.filesystem);
		this.aiService = new AIService({
			credentialStore: this.credentialStore,
			transport: this.transport,
			onOpenRouterDiagnostics: (diagnostics) => this.logger.info('ai.openrouter.response.diagnostics', diagnostics),
			onOpenRouterRequestRejected: (diagnostics) => this.logger.warn('ai.openrouter.request.rejected', diagnostics),
		});
		this.aiReview = new AIReviewService(this.aiService);
		this.runtimeState = {
			startedAt: this.startedAt,
			coreVersion: options.coreVersion,
			protocolVersion: options.protocolVersion ?? CORE_PROTOCOL_VERSION,
		};
		this.scannerManager.register(new BetterleaksScanner());
		this.scannerManager.register(new MobSfScanner());
		this.scannerManager.register(new OsvScanner());
		this.scannerManager.register(new SemgrepScanner());
		this.scannerManager.register(new TrivyScanner());
	}

	async handle(input: unknown, emit: (event: CoreEventMessage) => void): Promise<CoreResponseMessage> {
		const requestId = isRecord(input) && typeof input.id === 'string' ? input.id : 'unknown';
		if (!validateRequest(input)) {
			return this.fail(requestId, 'CORE_INVALID_REQUEST', 'Malformed Core request or params.');
		}
		const message = input;
		const startedAt = Date.now();
		this.logger.debug('request.started', { requestId: message.id, operation: message.method });
		if (message.method === 'core.cancel') {
			return this.ok(message.id, 'core.cancel', this.cancelRequest(message.params));
		}
		if (this.activeRequests.has(message.id)) {
			return this.fail(message.id, 'CORE_INVALID_REQUEST', 'A request with this id is already active.');
		}
		const source = createCancellationSource();
		const active: ActiveRequest = { source };
		this.activeRequests.set(message.id, active);
		try {
			switch (message.method) {
				case 'core.handshake':
					return this.ok(message.id, 'core.handshake', await this.handshake(message.params));
				case 'core.health':
					return this.ok(message.id, 'core.health', this.health());
				case 'core.info':
					return this.ok(message.id, 'core.info', this.info());
				case 'core.shutdown':
					return this.ok(message.id, 'core.shutdown', await this.shutdown());
				case 'project.detect':
					return this.ok(message.id, 'project.detect', await this.detectProject(message.params));
				case 'project.profile':
					return this.ok(message.id, 'project.profile', await this.profileProject(message.params));
				case 'workspace.rules.get':
					return this.ok(message.id, 'workspace.rules.get', { rules: await this.workspaceRules.get(message.params.workspaceRoot), configured: await this.workspaceRules.has(message.params.workspaceRoot) });
				case 'workspace.rules.set':
					return this.ok(message.id, 'workspace.rules.set', { rules: await this.workspaceRules.set(message.params.workspaceRoot, message.params.rules) });
				case 'workspace.threat-history.get':
					return this.ok(message.id, 'workspace.threat-history.get', await this.workspaceThreatHistory(message.params.workspaceRoot));
				case 'workspace.threat-history.delete':
					return this.ok(message.id, 'workspace.threat-history.delete', await this.deleteWorkspaceThreatSnapshot(message.params.workspaceRoot, message.params.snapshotId));
				case 'workspace.reports.get':
					return this.ok(message.id, 'workspace.reports.get', await this.workspaceReports(message.params.workspaceRoot));
				case 'workspace.agent-sessions.get':
					return this.ok(message.id, 'workspace.agent-sessions.get', await this.workspaceAgentSessions(message.params.workspaceRoot));
				case 'workspace.agent-sessions.set':
					return this.ok(message.id, 'workspace.agent-sessions.set', await this.saveWorkspaceAgentSessions(message.params.workspaceRoot, message.params.sessions));
				case 'workspace.recommendations.get':
					return this.ok(message.id, 'workspace.recommendations.get', await this.workspaceRecommendations(message.params.workspaceRoot));
				case 'hypotheses.generate':
					return this.ok(message.id, 'hypotheses.generate', await this.generateHypotheses(message.params.workspaceRoot, message.params.scanId, source.token));
				case 'hypotheses.list': {
					const store = await this.hypotheses.list(this.resolveHypothesisRoot(message.params.workspaceRoot));
					const selected = store.hypotheses.filter((item) => (!message.params.status || item.status === message.params.status) && (message.params.includeStale || message.params.status === 'stale' || item.status !== 'stale'));
					return this.ok(message.id, 'hypotheses.list', { hypotheses: selected, storeVersion: store.version });
				}
				case 'hypotheses.get': {
					const store = await this.hypotheses.list(this.resolveHypothesisRoot(message.params.workspaceRoot));
					return this.ok(message.id, 'hypotheses.get', { hypothesis: store.hypotheses.find((item) => item.id === message.params.hypothesisId) });
				}
				case 'hypotheses.review':
					return this.ok(message.id, 'hypotheses.review', await this.reviewHypothesis(message.params));
				case 'rag.index':
					return this.ok(message.id, 'rag.index', await this.indexRag(message.params, source.token));
				case 'rag.status':
					return this.ok(message.id, 'rag.status', await this.ragStatus(message.params));
				case 'rag.query':
					return this.ok(message.id, 'rag.query', await this.ragQuery(message.params));
				case 'scan.start':
					return this.ok(message.id, 'scan.start', await this.startScan(message.params, emit, source.token));
				case 'scan.file':
					return this.ok(message.id, 'scan.file', await this.scanFile(message.id, message.params, emit, source.token));
				case 'scan.cancel':
					return this.ok(message.id, 'scan.cancel', this.cancelScan(message.params.scanId));
				case 'scan.status':
					return this.ok(message.id, 'scan.status', this.scanStatus(message.params.scanId));
				case 'ai.providers':
					return this.ok(message.id, 'ai.providers', await this.aiProviders());
				case 'ai.models':
					return this.ok(message.id, 'ai.models', await this.aiModels(message.params));
				case 'ai.cancel':
					this.aiService.cancel(message.params.sessionId ?? '');
					return this.ok(message.id, 'ai.cancel', { cancelled: true });
				case 'ai.chat':
					active.onCancel = () => this.aiService.cancel(message.params.sessionId);
					return this.ok(message.id, 'ai.chat', await this.aiChat(message.params, emit, source.token));
				case 'ai.review':
					return this.ok(message.id, 'ai.review', await this.aiReviewFindings(message.params, emit));
				case 'ai.vulnerabilityAnalysis':
					active.onCancel = () => this.aiService.cancel(message.params.sessionId);
					return this.ok(message.id, 'ai.vulnerabilityAnalysis', await this.aiVulnerabilityAnalysis(message.params, emit, source.token));
				case 'credentials.status':
					return this.ok(message.id, 'credentials.status', await this.credentialsStatus(message.params.key));
				case 'credentials.set':
					return this.ok(message.id, 'credentials.set', await this.credentialsSet(message.params));
				case 'credentials.delete':
					return this.ok(message.id, 'credentials.delete', await this.credentialsDelete(message.params));
				case 'credentials.exists':
					return this.ok(message.id, 'credentials.exists', await this.credentialsExists(message.params.key));
				case 'report.generate':
					return this.ok(message.id, 'report.generate', await this.reportGenerate(message.params));
				default:
					return this.fail('unknown', 'INVALID_REQUEST', 'Unknown Core method.');
			}
		} catch (error) {
			const code = source.token.isCancellationRequested ? 'CORE_REQUEST_CANCELLED' : this.mapErrorCode(error);
			return this.fail(message.id, code, source.token.isCancellationRequested ? 'Core request cancelled.' : error instanceof Error ? error.message : String(error));
		} finally {
			this.activeRequests.delete(message.id);
			this.logger.debug('request.finished', { requestId: message.id, operation: message.method, durationMs: Date.now() - startedAt, success: !source.token.isCancellationRequested });
		}
	}

	cancelRequest(request: { requestId?: string }): { cancelled: boolean; requestId?: string } {
		if (!request.requestId) {
			return { cancelled: false };
		}
		const active = this.activeRequests.get(request.requestId);
		if (!active) {
			return { cancelled: false, requestId: request.requestId };
		}
		active.source.cancel();
		active.onCancel?.();
		return { cancelled: true, requestId: request.requestId };
	}

	private async handshake(request: CoreHandshakeRequest): Promise<CoreHandshakeResponse> {
		if (request.protocolVersion !== CORE_PROTOCOL_VERSION) {
			return {
				protocolVersion: CORE_PROTOCOL_VERSION,
				coreVersion: this.options.coreVersion,
				status: request.protocolVersion < CORE_PROTOCOL_VERSION ? 'extension-too-old' : 'protocol-mismatch',
				reason: `Protocol version ${request.protocolVersion} is not compatible with core protocol ${CORE_PROTOCOL_VERSION}.`,
			};
		}
		return {
			protocolVersion: CORE_PROTOCOL_VERSION,
			coreVersion: this.options.coreVersion,
			status: 'compatible',
		};
	}

	private health(): CoreHealthResult {
		return { ok: true, ready: true, uptimeMs: Date.now() - new Date(this.startedAt).getTime() };
	}

	private info(): CoreInfoResult {
		return { ...this.runtimeState, runtime: 'node' };
	}

	private async shutdown(): Promise<{ ok: true }> {
		this.shutdownRequested = true;
		return { ok: true };
	}

	private async detectProject(request: CoreProjectDetectRequest): Promise<ProjectProfile> {
		return await detectProjectProfile(request.workspaceRoot, this.filesystem, this.projectOptions(request.workspaceRoot));
	}

	private resolveHypothesisRoot(workspaceRoot: string): string {
		if (!path.isAbsolute(workspaceRoot) || workspaceRoot.includes('\0')) throw Object.assign(new Error('A canonical absolute workspace root is required.'), { code: 'HYPOTHESIS_INVALID_WORKSPACE' });
		return path.resolve(workspaceRoot);
	}

	private async generateHypotheses(workspaceRoot: string, scanId: string, cancellationToken?: CancellationTokenLike): Promise<HypothesisGenerationResult> {
		const root = this.resolveHypothesisRoot(workspaceRoot);
		const scanRecord = this.scans.get(scanId);
		const scan = scanRecord?.result;
		if (!scan || scan.state.finalState !== 'completed' || normalizeWorkspaceIdentity(scan.state.workspaceRoot) !== normalizeWorkspaceIdentity(root)) {
			return { status: 'no-evidence', scanId, hypotheses: [], diagnostics: [{ code: 'no-evidence', count: 1, message: 'No completed Core scan evidence is available for this workspace and scan ID.' }] };
		}
		if (cancellationToken?.isCancellationRequested) throw new Error('Core request cancelled.');
		const profile = await detectProjectProfile(root, this.filesystem, this.projectOptions(root));
		const snapshot = await buildHypothesisSnapshot({
			workspaceRoot: root, scanId, findings: scan.findings, relationships: scan.correlation?.relationships ?? [],
			profile, filesystem: this.filesystem, scanProvenance: scanRecord?.sourceProvenance, capturedAt: scan.state.completedAt, cancelled: () => Boolean(cancellationToken?.isCancellationRequested),
		});
		if (cancellationToken?.isCancellationRequested) throw new Error('Core request cancelled.');
		if (snapshot.findings.length === 0) {
			await this.hypotheses.mergeGeneration(root, snapshot, [], () => Boolean(cancellationToken?.isCancellationRequested));
			const unavailable = (snapshot.excludedUnprovenancedFindings ?? 0) + (scanRecord?.excludedProvenanceCount ?? 0);
			return { status: 'no-evidence', scanId, snapshotId: snapshot.id, hypotheses: [], diagnostics: [{ code: 'no-evidence', count: Math.max(1, unavailable), message: unavailable ? 'Findings were excluded because scan-time provenance was missing, source changed or disappeared, reads failed or exceeded per-file/aggregate byte limits, or path/span validation failed.' : 'The completed scan has no findings with verified in-workspace source spans.' }] };
		}
		const candidates = generateDeterministicHypotheses(snapshot);
		const store = await this.hypotheses.mergeGeneration(root, snapshot, candidates, () => Boolean(cancellationToken?.isCancellationRequested));
		const generated = candidates.map((candidate) => store.hypotheses.find((item) => item.id === candidate.id) ?? candidate);
		const diagnostics: HypothesisGenerationDiagnostics[] = candidates.length ? [] : [{ code: 'no-supported-rule', count: 1, message: 'Current verified evidence did not satisfy an allowlisted deterministic hypothesis rule.' }];
		if ((snapshot.excludedUnprovenancedFindings ?? 0) + (scanRecord?.excludedProvenanceCount ?? 0) > 0) diagnostics.push({ code: 'invalid-evidence', count: (snapshot.excludedUnprovenancedFindings ?? 0) + (scanRecord?.excludedProvenanceCount ?? 0), message: 'Some findings were excluded because provenance was unavailable, source changed or could not be read within the per-file/aggregate raw-byte budgets, or path/span validation failed.' });
		return { status: 'generated', scanId, snapshotId: snapshot.id, hypotheses: generated, diagnostics };
	}

	private async reviewHypothesis(input: HypothesisReviewInput): Promise<HypothesisReviewResult> {
		const root = this.resolveHypothesisRoot(input.workspaceRoot);
		return await this.hypotheses.review(root, input);
	}

	private async workspaceThreatHistory(workspaceRoot: string): Promise<CoreMethodResults['workspace.threat-history.get']> {
		try {
			const raw = await this.filesystem.readFile(path.join(workspaceRoot, '.aqiron-security', 'threats.json'), 'utf8');
			const parsed = JSON.parse(raw) as unknown;
			if (!Array.isArray(parsed)) return { snapshots: [] };
			const snapshots = parsed.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object' && !Array.isArray(item)
				&& typeof (item as Record<string, unknown>).id === 'string' && Array.isArray((item as Record<string, unknown>).issues))
				.slice(0, 50).map((item) => ({
					id: String(item.id), title: typeof item.title === 'string' ? item.title : 'Security scan',
					createdAt: typeof item.createdAt === 'string' ? item.createdAt : '',
					filesScanned: typeof item.filesScanned === 'number' ? item.filesScanned : 0,
					executiveSummary: typeof item.executiveSummary === 'string' ? item.executiveSummary : undefined,
					issues: (Array.isArray(item.issues) ? item.issues : []).filter((issue: unknown): issue is Record<string, unknown> => Boolean(issue) && typeof issue === 'object' && !Array.isArray(issue) && typeof (issue as Record<string, unknown>).id === 'string'),
				}));
			return { snapshots };
		} catch (error) {
			if (error && typeof error === 'object' && 'code' in error && (error as { code?: unknown }).code === 'ENOENT') return { snapshots: [] };
			throw error;
		}
	}

	private async deleteWorkspaceThreatSnapshot(workspaceRoot: string, snapshotId: string): Promise<CoreMethodResults['workspace.threat-history.delete']> {
		let stored: unknown;
		try { stored = JSON.parse(await this.filesystem.readFile(path.join(workspaceRoot, '.aqiron-security', 'threats.json'), 'utf8')); }
		catch (error) { if (isMissingFile(error)) return { snapshots: [] }; throw error; }
		if (!Array.isArray(stored)) return { snapshots: [] };
		const remaining = stored.filter((snapshot) => !isRecord(snapshot) || snapshot.id !== snapshotId);
		if (remaining.length !== stored.length) {
			const target = path.join(workspaceRoot, '.aqiron-security', 'threats.json');
			const temporary = `${target}.${Date.now()}.tmp`;
			await this.filesystem.writeFile(temporary, JSON.stringify(remaining, null, 2), 'utf8');
			await this.filesystem.rename(temporary, target);
		}
		return await this.workspaceThreatHistory(workspaceRoot);
	}

	private async workspaceReports(workspaceRoot: string): Promise<CoreMethodResults['workspace.reports.get']> {
		const reportsRoot = path.join(workspaceRoot, '.aqiron-security', 'reports');
		try {
			const folders = (await this.filesystem.readdir(reportsRoot, { withFileTypes: true }))
				.filter((entry): entry is { name: string; isDirectory(): boolean; isFile(): boolean } => typeof entry !== 'string' && entry.isDirectory())
				.map((entry) => entry.name).sort((left, right) => right.localeCompare(left));
			for (const folder of folders) {
				const directory = path.join(reportsRoot, folder);
				const entries = (await this.filesystem.readdir(directory, { withFileTypes: true })).filter((entry): entry is { name: string; isDirectory(): boolean; isFile(): boolean } => typeof entry !== 'string' && entry.isFile());
				const find = (extension: string) => entries.find((entry) => path.extname(entry.name).toLowerCase() === extension)?.name;
				const names = { json: find('.json'), sarif: find('.sarif'), pdf: find('.pdf') };
				if (!names.json && !names.sarif && !names.pdf) continue;
				const files = await Promise.all(Object.entries(names).map(async ([format, name]) => name ? [format, await this.filesystem.stat(path.join(directory, name))] as const : undefined));
				const sizes: { json?: number; sarif?: number; pdf?: number } = {};
				let modifiedAt = '';
				for (const item of files) if (item) { sizes[item[0] as keyof typeof sizes] = item[1].size; if (item[1].mtimeMs > Date.parse(modifiedAt || '1970-01-01')) modifiedAt = new Date(item[1].mtimeMs).toISOString(); }
				return { directory, jsonPath: names.json ? path.join(directory, names.json) : undefined, sarifPath: names.sarif ? path.join(directory, names.sarif) : undefined, pdfPath: names.pdf ? path.join(directory, names.pdf) : undefined, sizes, modifiedAt: modifiedAt || undefined };
			}
			return {};
		} catch (error) { if (isMissingFile(error)) return {}; throw error; }
	}

	private async workspaceAgentSessions(workspaceRoot: string): Promise<CoreMethodResults['workspace.agent-sessions.get']> {
		try {
			const parsed = JSON.parse(await this.filesystem.readFile(path.join(workspaceRoot, '.aqiron-security', 'agent-sessions.json'), 'utf8')) as unknown;
			if (!isRecord(parsed) || parsed.version !== 1 || !Array.isArray(parsed.sessions)) return { sessions: [] };
			return { sessions: parsed.sessions.filter(isAgentSession).map(sanitizeAgentSession).sort((left, right) => right.updatedAt.localeCompare(left.updatedAt)) };
		} catch (error) {
			if (isMissingFile(error)) return { sessions: [] };
			throw error;
		}
	}

	private async saveWorkspaceAgentSessions(workspaceRoot: string, sessions: CoreAgentSession[]): Promise<CoreMethodResults['workspace.agent-sessions.set']> {
		const directory = path.join(workspaceRoot, '.aqiron-security');
		await this.filesystem.mkdir(directory, { recursive: true });
		const safe = sessions.filter(isAgentSession).map(sanitizeAgentSession).sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
		const target = path.join(directory, 'agent-sessions.json');
		const temporary = `${target}.${Date.now()}.tmp`;
		await this.filesystem.writeFile(temporary, JSON.stringify({ version: 1, sessions: safe }), 'utf8');
		await this.filesystem.rename(temporary, target);
		return { sessions: safe };
	}

	private async workspaceRecommendations(workspaceRoot: string): Promise<CoreMethodResults['workspace.recommendations.get']> {
		const hasIndex = await this.ragIndex.hasIndex(workspaceRoot);
		const data = hasIndex ? this.ragIndex.getData() : undefined;
		if (!data?.manifest.aiSuggestionsGenerated) return { generated: false, suggestions: [] };
		try {
			const content = await this.filesystem.readFile(path.join(workspaceRoot, '.aqiron-security', 'suggestions.md'), 'utf8');
			return { generated: true, suggestions: content.trim() ? [content] : [] };
		} catch (error) {
			if (isMissingFile(error)) return { generated: false, suggestions: [] };
			throw error;
		}
	}

	private async profileProject(request: CoreProjectDetectRequest): Promise<CoreProjectProfileResult> {
		const projectProfile = await detectProjectProfile(request.workspaceRoot, this.filesystem, this.projectOptions(request.workspaceRoot));
		return { projectProfile, securities: projectProfile.securitySignals };
	}

	private async indexRag(request: CoreRagIndexRequest, cancellationToken?: CancellationTokenLike): Promise<CoreRagIndexResult> {
		if (cancellationToken?.isCancellationRequested) {
			throw new Error('Core request cancelled.');
		}
		const index = await this.ragIndex.reindex(request.workspaceRoot, {
			withAi: Boolean(request.withAi),
			generateSuggestions: request.withAi ? async (signals) => {
				this.logger.info('recommendations.generation.started', { workspaceScoped: true, signals: signals.length });
				await this.ensureAiReady();
				await this.aiService.refreshModels(true);
				const ai = await this.aiService.getState();
				if (!ai.status.connected || !ai.selection.model) {
					this.logger.warn('recommendations.provider.unavailable', { providerResolved: Boolean(ai.status.providerId), modelResolved: Boolean(ai.selection.model), connected: ai.status.connected });
					throw new Error(ai.status.message || 'Configure and connect an AI provider and model before refreshing recommendations.');
				}
				this.logger.debug('recommendations.provider.resolved', { providerId: ai.selection.provider, modelId: ai.selection.model, connected: ai.status.connected });
				const modelMetadata = ai.models.find((model) => model.id === ai.selection.model);
				const generationPolicy = resolveChatGenerationPolicy(ai.selection.provider, modelMetadata, ai.settings.maxTokens);
				const recommendationMaxTokens = generationPolicy.maxTokens ?? ai.settings.maxTokens;
				const recommendationReasoning = generationPolicy.openRouterReasoning;
				this.logger.info('recommendations.request.configured', {
					providerId: ai.selection.provider,
					modelId: ai.selection.model,
					maxTokens: recommendationMaxTokens,
					reasoningControlApplied: Boolean(recommendationReasoning),
					usageRequested: ai.selection.provider === 'openrouter',
					reasoningControl: recommendationReasoning?.enabled === false ? 'disabled' : recommendationReasoning ? 'enabled-bounded' : 'unsupported-or-not-openrouter',
				});
				const context: AIContextSnapshot = {
					workspaceName: path.basename(request.workspaceRoot), workspaceRoot: request.workspaceRoot,
					projectTypes: [], backend: 'Unknown', currentFile: 'None', scanStatus: 'Complete',
					issues: [], stats: { filesScanned: 0, indexedFiles: 0 },
					apis: signals.filter((signal) => signal.category === 'endpoint').map((signal) => signal.file),
				};
				const prompt = `Return only a JSON array of up to five actionable Aqiron security recommendations. Each item must have title and detail; include severity (Critical, High, Medium, or Low), recommended (boolean), command, and metadata fields ruleId/file/line/category only when known. Do not include analysis, reasoning, or introductory text. Do not repeat secrets. Signals: ${signals.slice(0, 40).map((signal) => `${signal.category}:${signal.provider}:${signal.file}`).join(', ')}`;
				const system = [
					'You are Aqiron Security, a production DevSecOps assistant inside VS Code.',
					'Give concrete security analysis, remediation, secure code, exploit explanations, scan summaries, and threat analysis using the supplied workspace context.',
					'Do not claim to have run tools unless the context says they ran. Prefer actionable fixes and clearly name risk.',
					'Reasoning depth: Medium.',
				].join('\n');
				const completion: NonNullable<InternalAiChatOptions['completion']> = {};
				const chat = await this.aiChat({
					sessionId: `rag-suggestions-${Date.now()}`,
					providerId: ai.selection.provider,
					text: prompt,
					history: [
						{ role: 'system', content: system },
						{ role: 'user', content: `Workspace security context:\n${JSON.stringify(context, null, 2)}` },
						{ role: 'user', content: prompt },
					],
					model: ai.selection.model,
					intelligence: 'Medium',
					context: context as never,
				}, () => undefined, cancellationToken, {
					maxTokens: recommendationMaxTokens,
					openRouterReasoning: recommendationReasoning,
					includeUsage: ai.selection.provider === 'openrouter',
					completion,
				});
				const text = chat.text;
				this.logger.info('recommendations.response.received', { providerId: ai.selection.provider, modelId: ai.selection.model, responseReceived: text.length > 0, valueType: 'completed-chat-result', responseKeys: ['text'], textType: typeof text, responseLength: text.length, completionReceived: true });
				const parsed = parseRecommendationSourceDetailed(text);
				this.logger.info('recommendations.response.parsed', parsed.diagnostics);
				const recommendations = parsed.recommendations;
				if (recommendations.length === 0) {
					const reason = text.length === 0 && completion.finishReason === 'length' && completion.providerCompletion?.reasoningPresent
						? `The AI provider used its ${recommendationMaxTokens}-token generation budget on reasoning before returning recommendation text.`
						: text.length === 0 ? 'The AI provider completed without returning recommendation text.' : `The AI provider returned ${parsed.diagnostics.format} content that did not contain a valid recommendation (${parsed.diagnostics.rejected} rejected candidate(s)).`;
					throw new Error(`${reason} Existing recommendations were preserved.`);
				}
				this.logger.info('recommendations.persistence.started', { accepted: recommendations.length, destination: 'workspace-suggestions' });
				await this.filesystem.writeFile(path.join(request.workspaceRoot, '.aqiron-security', 'suggestions.md'), JSON.stringify(recommendations, null, 2), 'utf8');
				this.logger.info('recommendations.persistence.completed', { accepted: recommendations.length });
			} : undefined,
		});
		if (cancellationToken?.isCancellationRequested) {
			throw new Error('Core request cancelled.');
		}
		return { index };
	}

	private async ragStatus(request: CoreProjectDetectRequest): Promise<CoreRagStatusResult> {
		const hasIndex = await this.ragIndex.hasIndex(request.workspaceRoot);
		const data = hasIndex ? this.ragIndex.getData() : undefined;
		return { hasIndex, updatedAt: data?.manifest.updatedAt, fileCount: data?.files.length ?? 0, chunkCount: data?.chunks.length ?? 0, aiSuggestionsGenerated: data?.manifest.aiSuggestionsGenerated ?? false };
	}

	private async ragQuery(request: CoreRagQueryRequest): Promise<CoreRagQueryResult> {
		const results = await this.ragRetrieval.retrieve({
			workspaceName: path.basename(request.workspaceRoot),
			workspaceRoot: request.workspaceRoot,
			projectTypes: [],
			profile: {
				languages: [],
				frameworks: [],
				platforms: [],
				services: [],
				authentication: [],
				databases: [],
				storage: [],
				dependencyManagers: [],
				nativeCode: [],
				ciCd: [],
				sensitiveFiles: [],
			},
			analysisGoals: [request.query],
			retrievalQueries: [request.query],
			candidateFiles: [],
			deterministicFindings: [],
			ragEvidence: [],
		});
		return { results };
	}

	private async startScan(request: CoreScanStartRequest, emit: (event: CoreEventMessage) => void, cancellationToken?: CancellationTokenLike): Promise<CoreScanStartResult> {
		const scanId = request.requestId ?? `scan-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
		if (cancellationToken?.isCancellationRequested) {
			throw new Error('Core request cancelled.');
		}
		const eventBus = new PipelineEventBus();
		eventBus.on((event) => emit({ type: 'event', event: event.type, requestId: scanId, payload: event }));
		const hasStoredRules = await this.workspaceRules.has(request.workspaceRoot);
		const customRules = hasStoredRules ? await this.workspaceRules.get(request.workspaceRoot) : request.workspacePolicy?.customRules ?? request.customRules ?? [];
		if (!hasStoredRules && request.workspacePolicy) await this.workspaceRules.set(request.workspaceRoot, customRules);
		const workspacePolicy = request.workspacePolicy ? { ...request.workspacePolicy, customRules } : undefined;
		const scannerContext = {
			workspaceRoot: request.workspaceRoot,
			targetPath: request.targetPath ?? request.workspaceRoot,
			mode: request.mode ?? 'deep',
			exclusions: workspacePolicy
				? [...new Set([...workspacePolicy.excludedDirectoryPaths, ...workspacePolicy.aqExclusionPatterns])]
				: ['node_modules/', 'dist/', 'build/', 'coverage/', '.git/', '.dart_tool/', '.aqiron-security/', 'generated/', 'gen/', 'target/', 'bin/', 'obj/'],
			cancellationToken,
			configuration: {
				get: <T>(key: string, defaultValue?: T): T | undefined => {
					if (workspacePolicy && key === 'scanGeneratedFiles') {return (!workspacePolicy.skipGeneratedFiles) as T;}
					if (workspacePolicy && key === 'maxFileSizeKB') {return (workspacePolicy.maxFileSizeBytes / 1024) as T;}
					const value = this.projectConfiguration(request.workspaceRoot, key);
					return (value === undefined ? defaultValue : value) as T | undefined;
				},
			},
			filesystem: this.filesystem,
			processRunner: this.processRunner,
			networkClient: this.networkClient,
			credentialStore: this.credentialStore,
			logger: this.logger,
			environment: { platform: process.platform, arch: process.arch, os: process.platform },
		} as const;
		const result = await this.pipeline.run({
			scanId,
			workspaceRoot: request.workspaceRoot,
			targetPath: request.targetPath,
			mode: request.mode,
			workspacePolicy,
			customRules,
			includeExternalScanners: request.includeExternalScanners,
			cancellationToken,
			emitter: eventBus,
			scannerContext: scannerContext as never,
			 scannerManager: this.scannerManager,
			nativeScanner: this.nativeScanner,
			aiAnalysis: undefined,
			reportGenerator: this.reportGenerator,
		});
		const state: ScanState = { scanId, workspaceRoot: request.workspaceRoot, targetPath: request.targetPath ?? request.workspaceRoot, mode: request.mode ?? 'deep', stage: 'Idle', stageProgress: 100, scanners: [], findingsCount: result.findings.length, riskScore: result.findings.length ? Math.min(100, result.findings.length * 15) : 0, cancelled: false, startedAt: new Date().toISOString(), updatedAt: new Date().toISOString(), completedAt: new Date().toISOString(), reportStatus: 'completed', finalState: 'completed' };
		const response: CoreScanStartResult = { scanId: result.scanId, state, findings: result.findings, report: result.report, filesScanned: result.filesScanned, durationMs: result.durationMs, toolResults: result.toolResults, correlation: result.correlation, graph: result.graph, telemetry: result.telemetry };
		this.scans.set(scanId, { state, result: response, sourceProvenance: result.sourceProvenance, excludedProvenanceCount: result.excludedProvenanceCount });
		return response;
	}

	private async scanFile(scanId: string, request: import('../shared/fileScan').CoreFileScanRequest, emit: (event: CoreEventMessage) => void, cancellationToken?: CancellationTokenLike): Promise<import('../shared/fileScan').CoreFileScanResult> {
		emit({ type: 'event', event: 'scan.file.started', requestId: scanId, payload: { scanId, filePath: request.filePath } });
		let policy = request.policy;
		if (request.workspaceRoot && await this.workspaceRules.has(request.workspaceRoot)) {
			policy = { ...policy, customRules: await this.workspaceRules.get(request.workspaceRoot) };
		}
		const result = await this.nativeScanner.scanFileContent(request.filePath, request.content, scanId, policy, cancellationToken);
		emit({ type: 'event', event: 'scan.file.completed', requestId: scanId, payload: { scanId, filePath: request.filePath, state: result.state, findingCount: result.findingCount, filesScanned: result.filesScanned } });
		return result;
	}

	private cancelScan(scanId?: string): { cancelled: boolean } {
		return this.cancelRequest({ requestId: scanId }).cancelled ? { cancelled: true } : { cancelled: false };
	}

	private scanStatus(scanId?: string): CoreScanStatusResult {
		const record = scanId ? this.scans.get(scanId) : undefined;
		return { scanId, state: record?.state, running: Boolean(record && record.state.finalState === 'running') };
	}

	private async aiProviders(): Promise<CoreAiProvidersResult> {
		const providers = this.aiService['registry'].getProviders().map((provider) => provider.id);
		let summaries: Array<{ id: string; name: string; providerId: string; last4: string; createdAt: string; updatedAt: string }> = [];
		try {
			const rawSettings = await this.credentialStore.get(aiSecretKeys.settings);
			const settings = rawSettings ? JSON.parse(rawSettings) as { apiCredentials?: unknown[] } : {};
			summaries = Array.isArray(settings.apiCredentials) ? settings.apiCredentials.flatMap((entry) => {
				if (!isRecord(entry) || typeof entry.id !== 'string' || typeof entry.providerId !== 'string') {
					return [];
				}
				return [{ id: entry.id, providerId: entry.providerId, name: typeof entry.name === 'string' ? entry.name : entry.providerId, last4: typeof entry.last4 === 'string' ? entry.last4.slice(-4) : '', createdAt: typeof entry.createdAt === 'string' ? entry.createdAt : '', updatedAt: typeof entry.updatedAt === 'string' ? entry.updatedAt : '' }];
			}) : [];
		} catch (error) {
			if (!isCredentialStoreUnavailable(error) && !(error instanceof SyntaxError)) {
				throw error;
			}
		}
		const activeSummaries = [] as typeof summaries;
		for (const summary of summaries) {
			try {
				if (await this.credentialStore.get(aiSecretKeys.apiCredential(summary.id))) {
					activeSummaries.push(summary);
				}
			} catch (error) {
				if (!isCredentialStoreUnavailable(error)) {
					throw error;
				}
			}
		}
		const configuredProviders = await Promise.all(providers.map(async (id) => {
			try {
				const saved = activeSummaries.filter((entry) => entry.providerId === id);
				const hasCredential = id === 'openrouter' && Boolean(await this.credentialStore.get(aiSecretKeys.openRouterApiKey))
					|| (await Promise.all(saved.map((entry) => this.credentialStore.get(aiSecretKeys.apiCredential(entry.id))))).some(Boolean);
				return { id, configured: hasCredential };
			} catch (error) {
				if (!isCredentialStoreUnavailable(error)) {
					throw error;
				}
				return { id, configured: false };
			}
		}));
		let settings: import('../shared/ai').AISettings | undefined;
		try { const raw = await this.credentialStore.get(aiSecretKeys.settings); if (raw) settings = publicAiSettings(JSON.parse(raw)); }
		catch (error) { if (!isCredentialStoreUnavailable(error) && !(error instanceof SyntaxError)) throw error; }
		return { providers, configuredProviders, credentialSummaries: activeSummaries, settings };
	}

	private async aiModels(request: CoreAiModelsRequest): Promise<CoreAiModelsResult> {
		await this.ensureAiReady();
		if (request.providerId) {
			await this.aiService.switchProvider(request.providerId as AIProviderId);
		} else await this.aiService.refreshModels(true);
		const state = await this.aiService.getState();
		return { models: state.models, status: state.status };
	}

	private async aiChat(request: CoreAiChatRequest, emit: (event: CoreEventMessage) => void, cancellationToken?: CancellationTokenLike, options?: InternalAiChatOptions): Promise<{ text: string }> {
		await this.ensureAiReady();
		if (request.providerId) await this.aiService.switchProvider(request.providerId as AIProviderId);
		const ai = await this.aiService.getState();
		const providerId: AIProviderId = request.providerId ? request.providerId as AIProviderId : ai.selection.provider;
		const model = request.model || ai.selection.model;
		const generationPolicy = resolveChatGenerationPolicy(providerId, ai.models.find((entry) => entry.id === model), ai.settings.maxTokens);
		this.logger.debug('ai.chat.request.configured', {
			providerId,
			modelId: model,
			maxTokens: options?.maxTokens ?? generationPolicy.maxTokens ?? ai.settings.maxTokens,
			reasoningControlApplied: Boolean(options?.openRouterReasoning ?? generationPolicy.openRouterReasoning),
			reasoningControl: (options?.openRouterReasoning ?? generationPolicy.openRouterReasoning)?.enabled === false ? 'disabled' : (options?.openRouterReasoning ?? generationPolicy.openRouterReasoning) ? 'enabled-bounded' : 'unsupported-or-unneeded',
			messageCount: request.history.length + 3,
		});
		const completion = options?.completion ?? {};
		let text = '';
		for await (const chunk of this.aiService.chat({
			sessionId: request.sessionId,
			text: request.text,
			history: request.history.filter((message) => message.role !== 'system').map((message) => ({ role: message.role as 'user' | 'assistant', content: message.content })),
			model,
			intelligence: request.intelligence,
			context: request.context as never,
			maxTokens: options?.maxTokens ?? generationPolicy.maxTokens,
			openRouterReasoning: options?.openRouterReasoning ?? generationPolicy.openRouterReasoning,
			includeUsage: options?.includeUsage,
		})) {
			if (cancellationToken?.isCancellationRequested) {
				throw new Error('Core request cancelled.');
			}
			if (chunk.type === 'token') {
				text += chunk.content ?? '';
				emit({ type: 'event', event: 'ai.token', requestId: request.sessionId, payload: chunk });
			}
			if (chunk.type === 'error') {
				emit({ type: 'event', event: 'ai.error', requestId: request.sessionId, payload: chunk });
			}
			if (chunk.type === 'done') {
				completion.finishReason = chunk.finishReason;
				completion.providerCompletion = chunk.providerCompletion;
			}
		}
		if (!text.trim()) {
			const budgetExhausted = completion.finishReason === 'length' && completion.providerCompletion?.reasoningPresent;
			throw new Error(budgetExhausted
				? `The selected AI model used its ${options?.maxTokens ?? generationPolicy.maxTokens ?? ai.settings.maxTokens}-token generation budget on reasoning before returning an assistant response.`
				: 'The selected AI provider completed without returning assistant text.');
		}
		emit({ type: 'event', event: 'ai.completed', requestId: request.sessionId, payload: { text } });
		return { text };
	}

	private async aiReviewFindings(request: CoreAiReviewRequest, emit: (event: CoreEventMessage) => void): Promise<{ text: string }> {
		const text = await this.aiReview.summarizeFindings(request.findings);
		emit({ type: 'event', event: 'ai.completed', requestId: request.sessionId, payload: { text } });
		return { text };
	}

	private async aiVulnerabilityAnalysis(request: CoreAiVulnerabilityAnalysisRequest, emit: (event: CoreEventMessage) => void, cancellationToken?: CancellationTokenLike): Promise<AIAnalysisResult> {
		const analysis = new AIVulnerabilityAnalysis({
			aiService: this.aiService,
			contextBuilder: this.contextBuilder,
			ragRetrieval: this.ragRetrieval,
		});
		const result = await analysis.analyze(request.workspaceRoot, request.baselineFindings, cancellationToken);
		emit({ type: 'event', event: 'ai.completed', requestId: request.sessionId, payload: { findings: result.findings.length } });
		return result;
	}

private async credentialsStatus(key: string): Promise<CoreCredentialsStatusResult> {
	try {
		const hasValue = Boolean(await this.credentialStore.get(key));
		return { hasValue };
	} catch (error) {
		if (
			typeof error === 'object' &&
			error !== null &&
			'code' in error &&
			(error as { code?: unknown }).code === 'CREDENTIAL_STORE_UNAVAILABLE'
		) {
			// Status checks must work when no desktop keychain session exists.
			return { hasValue: false };
		}

		throw error;
	}
}

	private async credentialsSet(request: CoreCredentialsSetRequest): Promise<CoreCredentialsStatusResult> {
		await this.credentialStore.set(request.key, request.value);
		if (request.key === aiSecretKeys.settings) await this.aiService.reloadSettings();
		return { hasValue: true, updatedAt: new Date().toISOString() };
	}

	private async credentialsDelete(request: CoreCredentialsDeleteRequest): Promise<CoreCredentialsStatusResult> {
		await this.credentialStore.delete(request.key);
		const match = /^aqiron\.ai\.api\.(.+)$/.exec(request.key);
		if (match) {
			const raw = await this.credentialStore.get(aiSecretKeys.settings);
			if (raw) {
				let settings: { apiCredentials?: Array<{ id?: string; providerId?: string }>; activeApiCredentialId?: string; selectedProvider?: string } | undefined;
				try { settings = JSON.parse(raw) as typeof settings; }
				catch (error) { if (!(error instanceof SyntaxError)) throw error; }
				if (settings) {
					const credentials = (settings.apiCredentials ?? []).filter((entry) => entry.id !== match[1]);
					if (settings.apiCredentials?.some((entry) => entry.id === match[1])) {
						const active = settings.activeApiCredentialId === match[1] ? credentials[0]?.id : settings.activeApiCredentialId;
						const activeCredential = credentials.find((entry) => entry.id === active);
						await this.credentialStore.set(aiSecretKeys.settings, JSON.stringify({ ...settings, apiCredentials: credentials, activeApiCredentialId: active, selectedProvider: activeCredential?.providerId ?? settings.selectedProvider }));
						const removed = settings.apiCredentials!.find((entry) => entry.id === match[1]);
						if (removed?.providerId === 'openrouter' && !credentials.some((entry) => entry.providerId === 'openrouter')) await this.credentialStore.delete(aiSecretKeys.openRouterApiKey);
					}
				}
			}
			await this.aiService.reloadSettings();
		}
		return { hasValue: false, updatedAt: new Date().toISOString() };
	}

	private async ensureAiReady(): Promise<void> {
		if (!this.aiReady) {
			this.aiReady = this.aiService.prepare().catch((error) => {
				this.aiReady = undefined;
				throw error;
			});
		}
		await this.aiReady;
	}

	private async credentialsExists(key: string): Promise<{ exists: boolean }> {
		return { exists: Boolean(await this.credentialStore.get(key)) };
	}

	private async reportGenerate(request: { workspaceRoot?: string; scanId?: string; mode?: 'quick' | 'deep' | 'analysis' | 'custom'; findings?: UnifiedFinding[]; correlation?: CorrelationResult; graph?: SecurityGraph; telemetry?: unknown }): Promise<SecurityReportContent> {
		const findings = request.findings ?? [];
		const correlation = request.correlation ?? ({ findings, relationships: [], summary: { deduplicated: 0, boosted: 0, attackPaths: 0 } } as CorrelationResult);
		const graph = request.graph ?? ({ nodes: [], edges: [] } as unknown as SecurityGraph);
		const workspaceRoot = request.workspaceRoot ?? (findings[0]?.file ? path.dirname(findings[0].file) : process.cwd());
		return await this.reportGenerator.generate(workspaceRoot, findings, correlation, graph, request.telemetry as never, { scanMode: request.mode, scanId: request.scanId });
	}

	private projectOptions(root: string): ProjectDetectorOptions {
		return {
			isExcludedPath: (file, workspaceRoot) => this.isExcludedPath(file, workspaceRoot ?? root),
		};
	}

	private projectConfiguration(root: string, key: string): unknown {
		if (key === 'scanGeneratedFiles') {
			return false;
		}
		if (key === 'maxFileSizeKB') {
			return 512;
		}
		if (key === 'excludeFolders') {
			return ['node_modules', 'dist', 'build', 'coverage', '.git', '.dart_tool', '.aqiron-security'];
		}
		return undefined;
	}

	private isExcludedPath(file: string, root: string): boolean {
		const relative = path.relative(root, file).replace(/\\/g, '/');
		return /(^|\/)(node_modules|dist|build|coverage|\.git|\.dart_tool|out|target|bin|obj)(\/|$)/i.test(relative);
	}

	private ok<K extends CoreMethod>(id: string, _method: K, result: CoreMethodResults[K]): CoreResponseMessage {
		return { id, type: 'response', success: true, result };
	}

	private fail(id: string, code: string, message: string, details?: unknown): CoreResponseMessage {
		return { id, type: 'response', success: false, error: { code, message, details } };
	}

	private mapErrorCode(error: unknown): string {
		if (typeof error === 'object' && error && 'code' in error && typeof (error as { code?: unknown }).code === 'string') {
			const code = (error as { code: string }).code;
			if (code.startsWith('HYPOTHESIS_') || code === 'CREDENTIAL_STORE_UNAVAILABLE') {
				return code;
			}
		}
		const message = error instanceof Error ? error.message : String(error);
		if (/cancel/i.test(message)) {
			return 'CANCELLED_ERROR';
		}
		if (/timeout/i.test(message)) {
			return 'TIMEOUT_ERROR';
		}
		if (/authentication|credential/i.test(message)) {
			return 'AUTHENTICATION_ERROR';
		}
		if (/rate limit/i.test(message)) {
			return 'RATE_LIMIT_ERROR';
		}
		return 'PROVIDER_UNAVAILABLE';
	}
}

function isCredentialStoreUnavailable(error: unknown): boolean {
	return isRecord(error) && error.code === 'CREDENTIAL_STORE_UNAVAILABLE';
}

export async function runCoreRuntime(input: AsyncIterable<string>, output: (message: CoreMessage) => void, options: CoreRuntimeOptions): Promise<void> {
	const runtime = new CoreRuntime(options);
	const active = new Set<Promise<void>>();
	for await (const line of input) {
		const trimmed = line.trim();
		if (!trimmed) {
			continue;
		}
		let parsed: unknown;
		try {
			parsed = JSON.parse(trimmed) as unknown;
		} catch (error) {
			output({ type: 'response', id: 'unknown', success: false, error: { code: 'CORE_PROTOCOL_ERROR', message: 'Malformed JSON request.' } });
			continue;
		}
		if (!validateRequest(parsed)) {
			const requestId = isRecord(parsed) && typeof parsed.id === 'string' ? parsed.id : 'unknown';
			output({ type: 'response', id: requestId, success: false, error: { code: 'CORE_INVALID_REQUEST', message: 'Invalid request envelope, method, or params.' } });
			continue;
		}
		const task = runtime.handle(parsed, (event) => output(event)).then((response) => output(response)).catch((error) => {
			output({ type: 'response', id: parsed.id, success: false, error: { code: 'CORE_OPERATION_FAILED', message: error instanceof Error ? error.message : String(error) } });
		});
		active.add(task);
		task.finally(() => active.delete(task)).catch(() => undefined);
		if (parsed.method === 'core.shutdown') {
			break;
		}
	}
	await Promise.all(active);
}

const CORE_METHODS = new Set<string>([
	'core.handshake', 'core.health', 'core.info', 'core.shutdown', 'core.cancel',
	'project.detect', 'project.profile', 'rag.index', 'rag.status', 'rag.query',
	'workspace.rules.get', 'workspace.rules.set',
	'workspace.threat-history.get', 'workspace.threat-history.delete',
	'workspace.agent-sessions.get', 'workspace.agent-sessions.set', 'workspace.recommendations.get', 'workspace.reports.get',
	'hypotheses.generate', 'hypotheses.list', 'hypotheses.get', 'hypotheses.review',
	'scan.start', 'scan.file', 'scan.cancel', 'scan.status', 'ai.providers', 'ai.models', 'ai.chat',
	'ai.cancel', 'ai.review', 'ai.vulnerabilityAnalysis', 'report.generate',
	'credentials.status', 'credentials.set', 'credentials.delete', 'credentials.exists',
]);

function validateRequest(value: unknown): value is CoreRequestMessage {
	if (!isRecord(value) || value.type !== 'request' || typeof value.id !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(value.id)) {
		return false;
	}
	if (typeof value.method !== 'string' || !CORE_METHODS.has(value.method)) {
		return false;
	}
	const params = value.params;
	if (params !== undefined && !isRecord(params)) {
		return false;
	}
	const input = (params ?? {}) as Record<string, unknown>;
	const string = (key: string): boolean => typeof input[key] === 'string' && (input[key] as string).length > 0;
	const hypothesisWorkspace = (): boolean => string('workspaceRoot') && String(input.workspaceRoot).length <= 4096 && !String(input.workspaceRoot).includes('\0') && String(input.workspaceRoot).trim() === String(input.workspaceRoot) && path.isAbsolute(String(input.workspaceRoot));
	const hypothesisScanId = (): boolean => string('scanId') && /^[A-Za-z0-9._:-]{1,128}$/.test(String(input.scanId));
	const optionalString = (key: string): boolean => input[key] === undefined || typeof input[key] === 'string';
	switch (value.method) {
		case 'core.health': case 'core.info': case 'core.shutdown': case 'ai.providers':
			return params === undefined || Object.keys(input).length === 0;
		case 'core.handshake': return string('extensionVersion') && typeof input.protocolVersion === 'number' && string('platform') && string('architecture');
		case 'core.cancel': return optionalString('requestId');
		case 'project.detect': case 'project.profile': case 'rag.status': return string('workspaceRoot') && typeof input.trusted === 'boolean' && optionalString('currentFile');
		case 'workspace.rules.get': case 'workspace.threat-history.get': case 'workspace.agent-sessions.get': case 'workspace.recommendations.get': case 'workspace.reports.get': return string('workspaceRoot');
		case 'hypotheses.generate': return hypothesisWorkspace() && hypothesisScanId();
		case 'hypotheses.list': return hypothesisWorkspace() && (input.status === undefined || ['proposed', 'investigating', 'validated', 'rejected', 'dismissed', 'stale', 'unsubstantiated'].includes(String(input.status))) && (input.includeStale === undefined || typeof input.includeStale === 'boolean');
		case 'hypotheses.get': return hypothesisWorkspace() && string('hypothesisId') && String(input.hypothesisId).length <= 80;
		case 'hypotheses.review': return hypothesisWorkspace() && string('hypothesisId') && String(input.hypothesisId).length <= 80 && ['investigate', 'validate', 'reject', 'dismiss', 'reopen'].includes(String(input.action)) && (input.note === undefined || typeof input.note === 'string' && input.note.length <= 500) && (input.evidenceRefs === undefined || Array.isArray(input.evidenceRefs) && input.evidenceRefs.length <= 20 && input.evidenceRefs.every((item) => typeof item === 'string' && item.length <= 200));
		case 'workspace.threat-history.delete': return string('workspaceRoot') && string('snapshotId');
		case 'workspace.agent-sessions.set': return string('workspaceRoot') && Array.isArray(input.sessions) && input.sessions.every(isAgentSession);
		case 'workspace.rules.set': return string('workspaceRoot') && Array.isArray(input.rules) && validateRuleList(input.rules);
		case 'rag.index': return string('workspaceRoot') && (input.withAi === undefined || typeof input.withAi === 'boolean');
		case 'rag.query': return string('workspaceRoot') && string('query') && (input.limit === undefined || typeof input.limit === 'number');
		case 'scan.start': return string('workspaceRoot') && typeof input.trusted === 'boolean' && optionalString('requestId') && optionalString('targetPath') && optionalString('currentFile') && (input.mode === undefined || ['quick', 'deep', 'analysis'].includes(String(input.mode))) && (input.includeExternalScanners === undefined || typeof input.includeExternalScanners === 'boolean') && (input.workspacePolicy === undefined || validateWorkspaceScanPolicy(input.workspacePolicy)) && (input.customRules === undefined || validateRuleList(input.customRules));
		case 'scan.file': return validateFileScanRequest(input);
		case 'scan.cancel': case 'scan.status': return optionalString('scanId');
		case 'ai.models': return optionalString('providerId');
		case 'ai.cancel': return optionalString('sessionId');
		case 'ai.chat': return string('sessionId') && optionalString('providerId') && typeof input.text === 'string' && Array.isArray(input.history) && string('model') && typeof input.intelligence === 'string' && isRecord(input.context);
		case 'ai.review': return string('sessionId') && Array.isArray(input.findings);
		case 'ai.vulnerabilityAnalysis': return string('sessionId') && string('workspaceRoot') && Array.isArray(input.baselineFindings);
		case 'credentials.status': case 'credentials.exists': case 'credentials.delete': return string('key');
		case 'credentials.set': return string('key') && typeof input.value === 'string';
		case 'report.generate': return optionalString('workspaceRoot') && optionalString('scanId') && (input.mode === undefined || ['quick', 'deep', 'analysis', 'custom'].includes(String(input.mode))) && (input.findings === undefined || Array.isArray(input.findings));
		default: return false;
	}
}

function publicAiSettings(value: unknown): import('../shared/ai').AISettings {
	if (!isRecord(value)) return {} as import('../shared/ai').AISettings;
	const safe: Record<string, unknown> = {};
	for (const key of ['selectedProvider', 'selectedModel', 'recentModelIds', 'activeApiCredentialId', 'temperature', 'maxTokens', 'timeoutMs', 'retries', 'streaming']) {
		if (key in value) safe[key] = value[key];
	}
	const taskDefaults = value.taskDefaults;
	if (isRecord(taskDefaults)) {
		safe.taskDefaults = Object.fromEntries(['useChatDefaults', 'provider', 'model', 'intelligence', 'permissionMode'].filter((key) => key in taskDefaults).map((key) => [key, taskDefaults[key]]));
	}
	safe.apiCredentials = Array.isArray(value.apiCredentials) ? value.apiCredentials.flatMap((entry) => {
		if (!isRecord(entry) || typeof entry.id !== 'string' || typeof entry.providerId !== 'string') return [];
		return [{ id: entry.id, providerId: entry.providerId, name: typeof entry.name === 'string' ? entry.name : entry.providerId, last4: typeof entry.last4 === 'string' ? entry.last4.slice(-4) : '', createdAt: typeof entry.createdAt === 'string' ? entry.createdAt : '', updatedAt: typeof entry.updatedAt === 'string' ? entry.updatedAt : '' }];
	}) : [];
	return safe as unknown as import('../shared/ai').AISettings;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isMissingFile(error: unknown): boolean {
	return isRecord(error) && error.code === 'ENOENT';
}

function normalizeWorkspaceIdentity(root: string): string {
	const resolved = path.resolve(root);
	return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function isAgentSession(value: unknown): value is CoreAgentSession {
	if (!isRecord(value) || typeof value.id !== 'string' || typeof value.title !== 'string' || typeof value.createdAt !== 'string' || typeof value.updatedAt !== 'string' || typeof value.model !== 'string' || typeof value.intelligence !== 'string' || !Array.isArray(value.messages)) return false;
	return value.messages.every((message) => isRecord(message) && typeof message.id === 'string' && (message.role === 'user' || message.role === 'assistant') && typeof message.content === 'string' && typeof message.createdAt === 'string');
}

function sanitizeAgentSession(session: CoreAgentSession): CoreAgentSession {
	const redact = (text: string) => text.replace(/\b(?:sk|pk|ghp|glpat|xox[baprs]?)-[A-Za-z0-9_-]{12,}\b/g, '[REDACTED]').replace(/\b[A-Za-z0-9_\/=+-]{32,}\b/g, '[REDACTED]');
	const sanitize = (value: unknown): unknown => typeof value === 'string' ? redact(value) : Array.isArray(value) ? value.map(sanitize) : isRecord(value) ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitize(item)])) : value;
	return {
		id: session.id, title: redact(session.title), createdAt: session.createdAt, updatedAt: session.updatedAt,
		model: session.model, intelligence: session.intelligence, streaming: false,
		messages: session.messages.map((message) => ({ id: message.id, role: message.role, content: redact(message.content), createdAt: message.createdAt, streaming: false, ...(Array.isArray(message.commands) ? { commands: sanitize(message.commands) as unknown[] } : {}) })),
	};
}

function validateFileScanRequest(input: Record<string, unknown>): boolean {
	if (typeof input.filePath !== 'string' || input.filePath.trim().length === 0 || typeof input.content !== 'string' || !isRecord(input.policy) || (input.workspaceRoot !== undefined && typeof input.workspaceRoot !== 'string')) {return false;}
	const policy = input.policy;
	if (!Array.isArray(policy.supportedExtensions) || !policy.supportedExtensions.every((value) => typeof value === 'string' && value.length > 0)) {return false;}
	if (!Array.isArray(policy.excludedPaths) || !policy.excludedPaths.every((value) => typeof value === 'string')) {return false;}
	if (!(policy.maxFileSizeBytes === null || (typeof policy.maxFileSizeBytes === 'number' && Number.isSafeInteger(policy.maxFileSizeBytes) && policy.maxFileSizeBytes >= 0))) {return false;}
	if (!['skipGeneratedFiles', 'skipMinifiedFiles', 'skipCompiledFiles', 'eligible'].every((key) => typeof policy[key] === 'boolean')) {return false;}
	return Array.isArray(policy.customRules) && policy.customRules.every((rule) => isRecord(rule)
		&& typeof rule.id === 'string' && rule.id.length > 0
		&& typeof rule.title === 'string' && typeof rule.message === 'string' && typeof rule.pattern === 'string'
		&& ['Critical', 'High', 'Medium', 'Low'].includes(String(rule.severity))
		&& (rule.caseSensitive === undefined || typeof rule.caseSensitive === 'boolean')
		&& (rule.extensions === undefined || (Array.isArray(rule.extensions) && rule.extensions.every((value) => typeof value === 'string'))));
}

function validateWorkspaceScanPolicy(value: unknown): boolean {
	if (!isRecord(value)) {return false;}
	const stringArray = (candidate: unknown): candidate is string[] => Array.isArray(candidate) && candidate.every((item) => typeof item === 'string');
	if (!stringArray(value.supportedExtensions) || !stringArray(value.excludedDirectoryPaths) || !stringArray(value.excludedFileNamePatterns) || !stringArray(value.aqExclusionPatterns)) {return false;}
	if (typeof value.maxFileSizeBytes !== 'number' || !Number.isSafeInteger(value.maxFileSizeBytes) || value.maxFileSizeBytes < 0) {return false;}
	if (!['skipGeneratedFiles', 'skipMinifiedFiles', 'skipCompiledFiles'].every((key) => typeof value[key] === 'boolean')) {return false;}
	return validateRuleList(value.customRules);
}

function validateRuleList(candidate: unknown): boolean {
	return Array.isArray(candidate) && candidate.every((rule) => isRecord(rule)
		&& typeof rule.id === 'string' && rule.id.trim().length > 0
		&& typeof rule.title === 'string' && rule.title.trim().length > 0
		&& typeof rule.message === 'string' && typeof rule.pattern === 'string' && rule.pattern.length > 0
		&& ['Critical', 'High', 'Medium', 'Low'].includes(String(rule.severity))
		&& (rule.extensions === undefined || (Array.isArray(rule.extensions) && rule.extensions.every((value) => typeof value === 'string')))
		&& (rule.caseSensitive === undefined || typeof rule.caseSensitive === 'boolean'));
}

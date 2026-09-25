import * as path from 'node:path';
import { AIService } from '../ai/services/aiService';
import { AIVulnerabilityAnalysis, AIAnalysisResult } from '../ai/analysis/aiVulnerabilityAnalysis';
import { AIReviewService } from '../ai/analysis/aiReview';
import { createNetworkTransport } from '../ai/utils/request';
import { createNodeFileSystem, createNodeLogger, createNodeNetworkClient, createNodeProcessRunner, NodeCredentialStore } from './nodeAdapters';
import { CORE_PROTOCOL_VERSION, CoreAiChatRequest, CoreAiModelsRequest, CoreAiModelsResult, CoreAiProvidersResult, CoreAiReviewRequest, CoreAiVulnerabilityAnalysisRequest, CoreCredentialsDeleteRequest, CoreCredentialsSetRequest, CoreCredentialsStatusResult, CoreEventMessage, CoreHandshakeRequest, CoreHandshakeResponse, CoreHealthResult, CoreInfoResult, CoreMessage, CoreProjectDetectRequest, CoreProjectProfileResult, CoreRagIndexRequest, CoreRagIndexResult, CoreRagQueryRequest, CoreRagQueryResult, CoreRagStatusResult, CoreRequestMessage, CoreResponseMessage, CoreScanStartRequest, CoreScanStartResult, CoreScanStatusResult, CoreRuntimeServicesState } from './protocol';
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
import { AIProviderId } from '../shared/ai';
import { ProjectProfile } from '../project/projectProfile';
import { SecurityReportContent } from '../reports/reportModels';
import { CredentialStore } from '../shared/platform';

interface CoreRuntimeOptions {
	coreVersion: string;
	protocolVersion?: number;
	credentialStore?: CredentialStore;
}

interface ScanStateRecord {
	state: ScanState;
	result?: CoreScanStartResult;
}

interface ActiveRequest {
	source: CancellationSource;
	onCancel?: () => void;
}

export class CoreRuntime {
	private readonly startedAt = new Date().toISOString();
	private readonly logger = createNodeLogger('aqiron-core-runtime');
	private readonly filesystem = createNodeFileSystem();
	private readonly networkClient = createNodeNetworkClient(this.logger);
	private readonly processRunner = createNodeProcessRunner();
	private readonly credentialStore: CredentialStore;
	private readonly transport: AITransport = createNetworkTransport(this.networkClient);
	private readonly aiService: AIService;
	private readonly aiReview: AIReviewService;
	private readonly ragIndex = new RagIndexService({ filesystem: this.filesystem, networkClient: this.networkClient });
	private readonly ragRetrieval = new RagRetrievalService(this.ragIndex);
	private readonly contextBuilder = new SecurityContextBuilder({ filesystem: this.filesystem });
	private readonly scannerManager = new ScannerManager();
	private readonly nativeScanner: NativeWorkspaceScanner;
	private readonly reportGenerator = new ReportGenerator();
	private readonly pipeline = new CoreScanService();
	private readonly events = new PipelineEventBus();
	private readonly scans = new Map<string, ScanStateRecord>();
	private readonly activeRequests = new Map<string, ActiveRequest>();
	private readonly runtimeState: CoreRuntimeServicesState;
	private shutdownRequested = false;

	constructor(private readonly options: CoreRuntimeOptions) {
		this.credentialStore = options.credentialStore ?? new NodeCredentialStore();
		this.nativeScanner = new NativeWorkspaceScanner(this.filesystem);
		this.aiService = new AIService({ credentialStore: this.credentialStore, transport: this.transport });
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

	async handle(message: CoreRequestMessage, emit: (event: CoreEventMessage) => void): Promise<CoreResponseMessage> {
		const startedAt = Date.now();
		this.logger.debug('request.started', { requestId: message.id, operation: message.method });
		if (message.method === 'core.cancel') {
			return this.ok(message.id, this.cancelRequest(message.params as { requestId?: string }));
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
					return this.ok(message.id, await this.handshake(message.params as CoreHandshakeRequest));
				case 'core.health':
					return this.ok(message.id, this.health());
				case 'core.info':
					return this.ok(message.id, this.info());
				case 'core.shutdown':
					return this.ok(message.id, await this.shutdown());
				case 'project.detect':
					return this.ok(message.id, await this.detectProject(message.params as CoreProjectDetectRequest));
				case 'project.profile':
					return this.ok(message.id, await this.profileProject(message.params as CoreProjectDetectRequest));
				case 'rag.index':
					return this.ok(message.id, await this.indexRag(message.params as CoreRagIndexRequest, source.token));
				case 'rag.status':
					return this.ok(message.id, await this.ragStatus(message.params as CoreProjectDetectRequest));
				case 'rag.query':
					return this.ok(message.id, await this.ragQuery(message.params as CoreRagQueryRequest));
				case 'scan.start':
					return this.ok(message.id, await this.startScan(message.params as CoreScanStartRequest, emit, source.token));
				case 'scan.cancel':
					return this.ok(message.id, this.cancelScan((message.params as { scanId?: string }).scanId));
				case 'scan.status':
					return this.ok(message.id, this.scanStatus((message.params as { scanId?: string }).scanId));
				case 'ai.providers':
					return this.ok(message.id, this.aiProviders());
				case 'ai.models':
					return this.ok(message.id, await this.aiModels(message.params as CoreAiModelsRequest));
				case 'ai.cancel':
					this.aiService.cancel(String((message.params as { sessionId?: string })?.sessionId ?? ''));
					return this.ok(message.id, { cancelled: true });
				case 'ai.chat':
					active.onCancel = () => this.aiService.cancel((message.params as CoreAiChatRequest).sessionId);
					return this.ok(message.id, await this.aiChat(message.params as CoreAiChatRequest, emit, source.token));
				case 'ai.review':
					return this.ok(message.id, await this.aiReviewFindings(message.params as CoreAiReviewRequest, emit));
				case 'ai.vulnerabilityAnalysis':
					active.onCancel = () => this.aiService.cancel((message.params as CoreAiVulnerabilityAnalysisRequest).sessionId);
					return this.ok(message.id, await this.aiVulnerabilityAnalysis(message.params as CoreAiVulnerabilityAnalysisRequest, emit, source.token));
				case 'credentials.status':
					return this.ok(message.id, await this.credentialsStatus((message.params as { key: string }).key));
				case 'credentials.set':
					return this.ok(message.id, await this.credentialsSet(message.params as CoreCredentialsSetRequest));
				case 'credentials.delete':
					return this.ok(message.id, await this.credentialsDelete(message.params as CoreCredentialsDeleteRequest));
				case 'credentials.exists':
					return this.ok(message.id, await this.credentialsExists((message.params as { key: string }).key));
				case 'report.generate':
					return this.ok(message.id, await this.reportGenerate(message.params as { scanId?: string; mode?: 'quick' | 'deep' | 'analysis' | 'custom'; findings?: UnifiedFinding[]; correlation?: CorrelationResult; graph?: SecurityGraph; telemetry?: unknown }));
				default:
					return this.fail(message.id, 'INVALID_REQUEST', `Unknown method: ${message.method}`);
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

	private async profileProject(request: CoreProjectDetectRequest): Promise<CoreProjectProfileResult> {
		const projectProfile = await detectProjectProfile(request.workspaceRoot, this.filesystem, this.projectOptions(request.workspaceRoot));
		return { projectProfile, securities: projectProfile.securitySignals };
	}

	private async indexRag(request: CoreRagIndexRequest, cancellationToken?: CancellationTokenLike): Promise<CoreRagIndexResult> {
		if (cancellationToken?.isCancellationRequested) {
			throw new Error('Core request cancelled.');
		}
		const index = await this.ragIndex.reindex(request.workspaceRoot, { withAi: Boolean(request.withAi), generateSuggestions: request.withAi ? async () => undefined : undefined });
		if (cancellationToken?.isCancellationRequested) {
			throw new Error('Core request cancelled.');
		}
		return { index };
	}

	private async ragStatus(request: CoreProjectDetectRequest): Promise<CoreRagStatusResult> {
		const hasIndex = await this.ragIndex.hasIndex(request.workspaceRoot);
		const data = hasIndex ? this.ragIndex.getData() : undefined;
		return { hasIndex, updatedAt: data?.manifest.updatedAt, fileCount: data?.files.length ?? 0, chunkCount: data?.chunks.length ?? 0 };
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
		const scannerContext = {
			workspaceRoot: request.workspaceRoot,
			targetPath: request.targetPath ?? request.workspaceRoot,
			mode: request.mode ?? 'deep',
			exclusions: ['node_modules/', 'dist/', 'build/', 'coverage/', '.git/', '.dart_tool/', '.aqiron-security/', 'generated/', 'gen/', 'target/', 'bin/', 'obj/'],
			cancellationToken,
			configuration: {
				get: <T>(key: string, defaultValue?: T): T | undefined => {
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
			workspaceRoot: request.workspaceRoot,
			targetPath: request.targetPath,
			mode: request.mode,
			cancellationToken,
			emitter: eventBus,
			scannerContext: scannerContext as never,
			 scannerManager: this.scannerManager,
			nativeScanner: this.nativeScanner,
			aiAnalysis: undefined,
			reportGenerator: this.reportGenerator,
		});
		const state: ScanState = { scanId, workspaceRoot: request.workspaceRoot, targetPath: request.targetPath ?? request.workspaceRoot, mode: request.mode ?? 'deep', stage: 'Idle', stageProgress: 100, scanners: [], findingsCount: result.findings.length, riskScore: result.findings.length ? Math.min(100, result.findings.length * 15) : 0, cancelled: false, startedAt: new Date().toISOString(), updatedAt: new Date().toISOString(), completedAt: new Date().toISOString(), reportStatus: 'completed', finalState: 'completed' };
		const response: CoreScanStartResult = { scanId, state, findings: result.findings, report: result.report, filesScanned: result.filesScanned, durationMs: result.durationMs, toolResults: result.toolResults, correlation: result.correlation, graph: result.graph, telemetry: result.telemetry };
		this.scans.set(scanId, { state, result: response });
		return response;
	}

	private cancelScan(scanId?: string): { cancelled: boolean } {
		return this.cancelRequest({ requestId: scanId }).cancelled ? { cancelled: true } : { cancelled: false };
	}

	private scanStatus(scanId?: string): CoreScanStatusResult {
		const record = scanId ? this.scans.get(scanId) : undefined;
		return { scanId, state: record?.state, running: Boolean(record && record.state.finalState === 'running') };
	}

	private aiProviders(): CoreAiProvidersResult {
		return { providers: this.aiService['registry'].getProviders().map((provider) => provider.id) };
	}

	private async aiModels(request: CoreAiModelsRequest): Promise<CoreAiModelsResult> {
		if (request.providerId) {
			await this.aiService.switchProvider(request.providerId as AIProviderId);
		}
		const state = await this.aiService.getState();
		return { models: state.models, status: state.status };
	}

	private async aiChat(request: CoreAiChatRequest, emit: (event: CoreEventMessage) => void, cancellationToken?: CancellationTokenLike): Promise<{ text: string }> {
		const model = request.model || (await this.aiService.getState()).selection.model;
		let text = '';
		for await (const chunk of this.aiService.chat({
			sessionId: request.sessionId,
			text: request.text,
			history: request.history.filter((message) => message.role !== 'system').map((message) => ({ role: message.role as 'user' | 'assistant', content: message.content })),
			model,
			intelligence: request.intelligence,
			context: request.context as never,
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
		return { hasValue: true, updatedAt: new Date().toISOString() };
	}

	private async credentialsDelete(request: CoreCredentialsDeleteRequest): Promise<CoreCredentialsStatusResult> {
		await this.credentialStore.delete(request.key);
		return { hasValue: false, updatedAt: new Date().toISOString() };
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

	private ok<T>(id: string, result: T): CoreResponseMessage {
		return { id, type: 'response', success: true, result };
	}

	private fail(id: string, code: string, message: string, details?: unknown): CoreResponseMessage {
		return { id, type: 'response', success: false, error: { code, message, details } };
	}

	private mapErrorCode(error: unknown): string {
		if (typeof error === 'object' && error && 'code' in error && typeof (error as { code?: unknown }).code === 'string') {
			const code = (error as { code: string }).code;
			if (code === 'CREDENTIAL_STORE_UNAVAILABLE') {
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

export async function runCoreRuntime(input: AsyncIterable<string>, output: (message: CoreMessage) => void, options: CoreRuntimeOptions): Promise<void> {
	const runtime = new CoreRuntime(options);
	const active = new Set<Promise<void>>();
	for await (const line of input) {
		const trimmed = line.trim();
		if (!trimmed) {
			continue;
		}
		let parsed: CoreRequestMessage;
		try {
			parsed = JSON.parse(trimmed) as CoreRequestMessage;
		} catch (error) {
			output({ type: 'response', id: 'unknown', success: false, error: { code: 'CORE_PROTOCOL_ERROR', message: 'Malformed JSON request.' } });
			continue;
		}
		const validationError = validateRequest(parsed);
		if (validationError) {
			output({ type: 'response', id: typeof parsed.id === 'string' ? parsed.id : 'unknown', success: false, error: validationError });
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

const CORE_METHODS = new Set([
	'core.handshake', 'core.health', 'core.info', 'core.shutdown', 'core.cancel',
	'project.detect', 'project.profile', 'rag.index', 'rag.status', 'rag.query',
	'scan.start', 'scan.cancel', 'scan.status', 'ai.providers', 'ai.models', 'ai.chat',
	'ai.cancel', 'ai.review', 'ai.vulnerabilityAnalysis', 'report.generate',
	'credentials.status', 'credentials.set', 'credentials.delete', 'credentials.exists',
]);

function validateRequest(value: unknown): { code: string; message: string } | undefined {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		return { code: 'CORE_INVALID_REQUEST', message: 'Request must be a JSON object.' };
	}
	const request = value as Record<string, unknown>;
	if (request.type !== 'request' || typeof request.id !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(request.id)) {
		return { code: 'CORE_INVALID_REQUEST', message: 'Invalid request envelope or request id.' };
	}
	if (typeof request.method !== 'string' || !CORE_METHODS.has(request.method)) {
		return { code: 'CORE_INVALID_REQUEST', message: 'Unsupported Core method.' };
	}
	if (request.params !== undefined && (!request.params || typeof request.params !== 'object' || Array.isArray(request.params))) {
		return { code: 'CORE_INVALID_REQUEST', message: 'Request params must be a JSON object.' };
	}
	return undefined;
}

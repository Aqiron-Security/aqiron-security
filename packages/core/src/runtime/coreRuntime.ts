import * as path from 'node:path';
import { AIService } from '../ai/services/aiService';
import { AIVulnerabilityAnalysis, AIAnalysisResult } from '../ai/analysis/aiVulnerabilityAnalysis';
import { AIReviewService } from '../ai/analysis/aiReview';
import { createNetworkTransport } from '../ai/utils/request';
import { createNodeFileSystem, createNodeLogger, createNodeNetworkClient, createNodeProcessRunner, NodeCredentialStore } from './nodeAdapters';
import { CORE_PROTOCOL_VERSION, CoreAiChatRequest, CoreAiModelsRequest, CoreAiModelsResult, CoreAiProvidersResult, CoreAiReviewRequest, CoreAiVulnerabilityAnalysisRequest, CoreCredentialsDeleteRequest, CoreCredentialsSetRequest, CoreHandshakeRequest, CoreHandshakeResponse, CoreHealthResult, CoreInfoResult, CoreMessage, CoreProjectDetectRequest, CoreProjectProfileResult, CoreRagIndexRequest, CoreRagIndexResult, CoreRagQueryRequest, CoreRagQueryResult, CoreRagStatusResult, CoreRequestMessage, CoreResponseMessage, CoreRuntimeServicesState, CoreScanStartRequest, CoreScanStartResult, CoreScanStatusResult, CoreEventMessage, CoreProgressEnvelope } from './protocol';
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
					return this.ok(message.id, await this.reportGenerate(message.params as { scanId?: string; findings?: UnifiedFinding[]; correlation?: CorrelationResult; graph?: SecurityGraph; telemetry?: unknown; workspaceRoot?: string }));
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

	// ... unchanged implementation omitted

	private async credentialsStatus(key: string): Promise<CoreCredentialsStatusResult> {
		this.validateCredentialKey(key);
		const value = await this.credentialStore.get(key);
		return { hasValue: value !== undefined };
	}

	private async credentialsSet(request: CoreCredentialsSetRequest): Promise<CoreCredentialsStatusResult> {
		this.validateCredentialKey(request.key);
		await this.credentialStore.set(request.key, request.value);
		return { hasValue: true, updatedAt: new Date().toISOString() };
	}

	private async credentialsDelete(request: CoreCredentialsDeleteRequest): Promise<CoreCredentialsStatusResult> {
		this.validateCredentialKey(request.key);
		await this.credentialStore.delete(request.key);
		return { hasValue: false, updatedAt: new Date().toISOString() };
	}

	private async credentialsExists(key: string): Promise<{ exists: boolean }> {
		this.validateCredentialKey(key);
		const value = await this.credentialStore.get(key);
		return { exists: value !== undefined };
	}

	private validateCredentialKey(key: unknown): asserts key is string {
		if (typeof key !== 'string' || key.length === 0) {
			throw new Error('Credential key is required');
		}
	}

	// ... unchanged implementation omitted
}

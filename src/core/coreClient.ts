import { EventEmitter } from 'events';
import { AIAnalysisContext, AIModel, ChatMessage, StreamChunk } from '../../packages/core/src/shared/ai';
import { UnifiedFinding } from '../../packages/core/src/shared/finding';
import { ProjectProfile } from '../../packages/core/src/project/projectProfile';
import { SecurityContext } from '../../packages/core/src/context/contextTypes';
import { RagIndexData, RagSearchResult } from '../../packages/core/src/shared/rag';
import { ScanState, PipelineEvent } from '../../packages/core/src/pipeline/events';
import { SecurityReportContent } from '../../packages/core/src/reports';
import { CoreProcessEvent, CoreProcessManager } from './coreProcessManager';
import { CoreAiChatRequest, CoreAiModelsRequest, CoreAiModelsResult, CoreAiProvidersResult, CoreAiReviewRequest, CoreAiVulnerabilityAnalysisRequest, CoreCredentialsDeleteRequest, CoreCredentialsSetRequest, CoreCredentialsStatusResult, CoreHandshakeResponse, CoreHealthResult, CoreInfoResult, CoreProjectDetectRequest, CoreProjectProfileResult, CoreRagIndexRequest, CoreRagIndexResult, CoreRagQueryRequest, CoreRagQueryResult, CoreRagStatusResult, CoreScanStartRequest, CoreScanStartResult, CoreScanStatusResult } from '../../packages/core/src/runtime';

export interface CoreClientOptions {
	extensionVersion: string;
}

function createId(): string {
	return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export class CoreClient extends EventEmitter {
	private readonly manager: CoreProcessManager;
	private ready?: Promise<CoreHandshakeResponse>;

	constructor(options: CoreClientOptions) {
		super();
		this.manager = new CoreProcessManager({ extensionVersion: options.extensionVersion, restartOnCrash: true });
		this.manager.on('log', (message) => this.emit('log', message));
		this.manager.on('exit', (event) => {
			this.ready = undefined;
			this.emit('exit', event);
		});
		this.manager.onCoreEvent((event) => this.emit('event', event));
	}

	async start(): Promise<CoreHandshakeResponse> {
		this.ready ??= this.manager.start();
		return await this.ready;
	}

	async stop(): Promise<void> {
		await this.manager.stop();
	}

	async health(): Promise<CoreHealthResult> {
		await this.start();
		return await this.manager.request<CoreHealthResult>('core.health');
	}

	async info(): Promise<CoreInfoResult> {
		await this.start();
		return await this.manager.request<CoreInfoResult>('core.info');
	}

	async detectProject(request: CoreProjectDetectRequest): Promise<ProjectProfile> {
		await this.start();
		return await this.manager.request<ProjectProfile>('project.detect', request);
	}

	async profileProject(request: CoreProjectDetectRequest): Promise<CoreProjectProfileResult> {
		await this.start();
		return await this.manager.request<CoreProjectProfileResult>('project.profile', request);
	}

	async indexRag(request: CoreRagIndexRequest): Promise<CoreRagIndexResult> {
		await this.start();
		return await this.manager.request<CoreRagIndexResult>('rag.index', request);
	}

	async ragStatus(workspaceRoot: string): Promise<CoreRagStatusResult> {
		await this.start();
		return await this.manager.request<CoreRagStatusResult>('rag.status', { workspaceRoot, trusted: true });
	}

	async queryRag(request: CoreRagQueryRequest): Promise<CoreRagQueryResult> {
		await this.start();
		return await this.manager.request<CoreRagQueryResult>('rag.query', request);
	}

	async startScan(request: CoreScanStartRequest): Promise<CoreScanStartResult> {
		await this.start();
		const requestId = request.requestId ?? createId();
		// A deep scan can run several bounded scanner operations sequentially.
		// The individual scanner timeouts remain strict; this covers the aggregate operation.
		return await this.manager.request<CoreScanStartResult>('scan.start', { ...request, requestId }, 10 * 60_000, requestId);
	}

	async cancelScan(scanId: string): Promise<{ cancelled: boolean }> {
		await this.start();
		return await this.manager.request<{ cancelled: boolean }>('core.cancel', { requestId: scanId });
	}

	async cancelRequest(requestId: string): Promise<{ cancelled: boolean; requestId?: string }> {
		await this.start();
		return await this.manager.cancel(requestId);
	}

	async scanStatus(scanId: string): Promise<CoreScanStatusResult> {
		await this.start();
		return await this.manager.request<CoreScanStatusResult>('scan.status', { scanId });
	}

	async providers(): Promise<CoreAiProvidersResult> {
		await this.start();
		return await this.manager.request<CoreAiProvidersResult>('ai.providers');
	}

	async models(providerId?: string): Promise<CoreAiModelsResult> {
		await this.start();
		return await this.manager.request<CoreAiModelsResult>('ai.models', { providerId } satisfies CoreAiModelsRequest);
	}

	async *chat(request: CoreAiChatRequest): AsyncGenerator<StreamChunk> {
		const pending = this.createEventStream(`ai.completed`, request.sessionId);
		const task = this.manager.request<{ text: string }>('ai.chat', request, undefined, `ai-chat-${request.sessionId}`);
		yield* pending.stream(task);
	}

	async *review(request: CoreAiReviewRequest): AsyncGenerator<StreamChunk> {
		const pending = this.createEventStream('ai.completed', request.sessionId);
		const task = this.manager.request<{ text: string }>('ai.review', request, undefined, `ai-review-${request.sessionId}`);
		yield* pending.stream(task);
	}

	async vulnerabilityAnalysis(request: CoreAiVulnerabilityAnalysisRequest): Promise<unknown> {
		await this.start();
		return await this.manager.request('ai.vulnerabilityAnalysis', request);
	}

	async reportGenerate(request: { workspaceRoot?: string; scanId?: string; findings?: UnifiedFinding[]; correlation?: unknown; graph?: unknown; telemetry?: unknown }): Promise<SecurityReportContent> {
		await this.start();
		return await this.manager.request<SecurityReportContent>('report.generate', request);
	}

	async credentialsStatus(key: string): Promise<CoreCredentialsStatusResult> {
		await this.start();
		return await this.manager.request<CoreCredentialsStatusResult>('credentials.status', { key });
	}

	async credentialsSet(request: CoreCredentialsSetRequest): Promise<CoreCredentialsStatusResult> {
		await this.start();
		return await this.manager.request<CoreCredentialsStatusResult>('credentials.set', request);
	}

	async credentialsDelete(request: CoreCredentialsDeleteRequest): Promise<CoreCredentialsStatusResult> {
		await this.start();
		return await this.manager.request<CoreCredentialsStatusResult>('credentials.delete', request);
	}

	async credentialsExists(key: string): Promise<{ exists: boolean }> {
		await this.start();
		return await this.manager.request<{ exists: boolean }>('credentials.exists', { key });
	}

	private createEventStream(eventName: string, requestId: string): { stream(task: Promise<unknown>): AsyncGenerator<StreamChunk> } {
		const client = this;
		const queue: Array<StreamChunk | { type: 'done' }> = [];
		let wake: (() => void) | undefined;
		const listener = (event: CoreProcessEvent) => {
			if (event.requestId !== requestId) {
				return;
			}
			if (event.event === 'ai.token' && typeof (event.payload as { content?: string })?.content === 'string') {
				queue.push({ type: 'token', content: (event.payload as { content?: string }).content });
			}
			if (event.event === eventName) {
				queue.push({ type: 'done' });
			}
			wake?.();
		};
		client.on('event', listener);
		return {
			async *stream(task: Promise<unknown>): AsyncGenerator<StreamChunk> {
				try {
					void task.catch((error) => {
						queue.push({ type: 'error', error: error instanceof Error ? error.message : String(error) });
						wake?.();
					});
					while (true) {
						if (queue.length === 0) {
							await new Promise<void>((resolve) => { wake = resolve; });
							continue;
						}
						const next = queue.shift();
						if (!next) {
							continue;
						}
						if (next.type === 'done') {
							break;
						}
						if (next.type === 'error') {
							yield next;
							break;
						}
						yield next;
					}
				} finally {
					client.removeListener('event', listener);
				}
			},
		};
	}
}

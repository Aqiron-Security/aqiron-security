import { AIAnalysisContext, AIModel, ChatMessage, ProviderConnectionStatus } from '../shared/ai';
import { CancellationTokenLike } from '../shared/cancellation';
import { ProjectProfile } from '../project/projectProfile';
import { SecurityContext } from '../context/contextTypes';
import { RagIndexData } from '../shared/rag';
import { ScanState, PipelineEvent } from '../shared/pipeline';
import { UnifiedFinding } from '../shared/finding';
import { SecurityReportContent } from '../reports/reportModels';
import { RagRetrievalResult } from '../rag/ragRetrievalService';
import { CorrelationResult } from '../correlation/correlationEngine';
import { SecurityGraph } from '../correlation/relationshipGraph';
import { ScannerResult } from '../shared/scanner';

export const CORE_PROTOCOL_VERSION = 1;

export type CoreMessage =
	| CoreRequestMessage
	| CoreResponseMessage
	| CoreEventMessage;

export interface CoreHandshakeRequest {
	extensionVersion: string;
	protocolVersion: number;
	platform: string;
	architecture: string;
}

export interface CoreHandshakeResponse {
	protocolVersion: number;
	coreVersion: string;
	status: 'compatible' | 'protocol-mismatch' | 'extension-too-old' | 'core-too-old' | 'unsupported';
	reason?: string;
}

export interface CoreRequestMessage {
	id: string;
	type: 'request';
	method: string;
	params?: unknown;
}

export interface CoreCancelRequest {
	requestId: string;
}

export interface CoreResponseMessage {
	id: string;
	type: 'response';
	success: boolean;
	result?: unknown;
	error?: CoreProtocolError;
}

export interface CoreEventMessage {
	type: 'event';
	event: string;
	requestId?: string;
	payload?: unknown;
}

export interface CoreProtocolError {
	code: string;
	message: string;
	details?: unknown;
}

export interface CoreHealthResult {
	ok: true;
	ready: boolean;
	uptimeMs: number;
}

export interface CoreInfoResult {
	coreVersion: string;
	protocolVersion: number;
	runtime: 'node';
	startedAt: string;
}

export interface CoreProjectDetectRequest {
	workspaceRoot: string;
	trusted: boolean;
	currentFile?: string;
}

export interface CoreProjectProfileRequest extends CoreProjectDetectRequest {
}

export interface CoreProjectProfileResult {
	projectProfile: ProjectProfile;
	securities: string[];
}

export interface CoreRagIndexRequest {
	workspaceRoot: string;
	withAi?: boolean;
}

export interface CoreRagIndexResult {
	index: RagIndexData;
}

export interface CoreRagStatusResult {
	hasIndex: boolean;
	updatedAt?: string;
	fileCount: number;
	chunkCount: number;
}

export interface CoreRagQueryRequest {
	workspaceRoot: string;
	query: string;
	limit?: number;
}

export interface CoreRagQueryResult {
	results: RagRetrievalResult[];
}

export interface CoreScanStartRequest {
	requestId?: string;
	workspaceRoot: string;
	targetPath?: string;
	mode?: 'quick' | 'deep' | 'analysis';
	trusted: boolean;
	currentFile?: string;
}

export interface CoreScanStartResult {
	scanId: string;
	state: ScanState;
	findings: UnifiedFinding[];
	report: SecurityReportContent;
	filesScanned?: number;
	durationMs?: number;
	toolResults?: ScannerResult[];
	correlation?: CorrelationResult;
	graph?: SecurityGraph;
	telemetry?: unknown;
}

export interface CoreScanStatusResult {
	scanId?: string;
	state?: ScanState;
	running: boolean;
}

export interface CoreAiProvidersResult {
	providers: string[];
}

export interface CoreAiModelsRequest {
	providerId?: string;
}

export interface CoreAiModelsResult {
	models: AIModel[];
	status: ProviderConnectionStatus;
}

export interface CoreAiChatRequest {
	sessionId: string;
	text: string;
	history: ChatMessage[];
	model: string;
	intelligence: string;
	context: AIAnalysisContext | SecurityContext;
}

export interface CoreAiReviewRequest {
	sessionId: string;
	findings: UnifiedFinding[];
}

export interface CoreAiVulnerabilityAnalysisRequest {
	sessionId: string;
	workspaceRoot: string;
	baselineFindings: UnifiedFinding[];
}

export interface CoreCredentialsStatusResult {
	hasValue: boolean;
	updatedAt?: string;
}

export interface CoreCredentialsSetRequest {
	key: string;
	value: string;
}

export interface CoreCredentialsDeleteRequest {
	key: string;
}

export interface CoreRuntimeServicesState {
	startedAt: string;
	coreVersion: string;
	protocolVersion: number;
}

export interface CoreProgressEnvelope {
	event: PipelineEvent['type'] | 'ai.token' | 'ai.completed' | 'ai.error' | 'rag.index.progress' | 'credentials.changed';
	payload: unknown;
}

export interface CancellationRegistry {
	cancel(requestId: string): void;
	register(requestId: string, token: CancellationTokenLike): void;
}

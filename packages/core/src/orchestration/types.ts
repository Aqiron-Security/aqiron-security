import { CancellationTokenLike } from '../shared/cancellation';
import { Configuration, CredentialStore, FileSystem, Logger, NetworkClient, ProcessRunner } from '../shared/platform';
import { UnifiedFinding } from '../shared/finding';
import { PipelineEmitter } from '../shared/pipeline';
import { SecurityReportContent } from '../reports';
import { RagRetrievalService } from '../rag';
import { SecurityContextBuilder } from '../context';
import { ScannerManager, ScannerResult, ScannerContext, ScannerMode } from '../scanners';
import { CorrelationResult } from '../correlation/correlationEngine';
import { SecurityGraph } from '../correlation/relationshipGraph';
import { ScanTelemetrySnapshot } from '../telemetry';
import { ResolvedWorkspaceScanPolicy } from '../shared/workspaceScanPolicy';
import { WorkspaceCustomRule } from '../shared/workspaceRules';
import { FindingSourceProvenance } from '../shared/sourceProvenance';

export interface NativeScanResult {
	findings: UnifiedFinding[];
	/** Optional for adapters; only Core-native scanner provenance is currently trusted. */
	sourceProvenance?: FindingSourceProvenance[];
	excludedProvenanceCount?: number;
	filesScanned: number;
	durationMs: number;
}

export interface NativeScanAdapter {
	scanWorkspace(workspaceRoot: string, cancellationToken?: CancellationTokenLike, policy?: ResolvedWorkspaceScanPolicy, customRules?: WorkspaceCustomRule[]): Promise<NativeScanResult>;
}

export interface AIAnalysisAdapter {
	analyze(workspaceRoot: string, baselineFindings: readonly UnifiedFinding[], emitter?: PipelineEmitter, cancellationToken?: CancellationTokenLike): Promise<{
		findings: UnifiedFinding[];
		summary: string;
		retrievalCount: number;
		filesAnalyzed: number;
		durationMs: number;
	}>;
}

export interface CoreScanRequest {
	scanId: string;
	workspaceRoot: string;
	targetPath?: string;
	mode?: ScannerMode;
	workspacePolicy?: ResolvedWorkspaceScanPolicy;
	customRules?: WorkspaceCustomRule[];
	includeExternalScanners?: boolean;
	emitter: PipelineEmitter;
	scannerContext: ScannerContext;
	cancellationToken?: CancellationTokenLike;
	nativeScanner?: NativeScanAdapter;
	scannerManager: ScannerManager;
	contextBuilder?: SecurityContextBuilder;
	ragRetrieval?: RagRetrievalService;
	aiAnalysis?: AIAnalysisAdapter;
	reportGenerator: import('../reports').ReportGenerator;
}

export interface CoreScanResult {
	scanId: string;
	workspaceRoot: string;
	targetPath: string;
	filesScanned: number;
	durationMs: number;
	findings: UnifiedFinding[];
	toolResults: ScannerResult[];
	correlation: CorrelationResult;
	graph: SecurityGraph;
	telemetry: ScanTelemetrySnapshot;
	report: SecurityReportContent;
	/** Internal scan-time provenance. Runtime retains it separately from public scan results. */
	sourceProvenance?: FindingSourceProvenance[];
	excludedProvenanceCount?: number;
}

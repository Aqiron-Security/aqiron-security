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

export interface NativeScanResult {
	findings: UnifiedFinding[];
	filesScanned: number;
	durationMs: number;
}

export interface NativeScanAdapter {
	scanWorkspace(workspaceRoot: string, cancellationToken?: CancellationTokenLike): Promise<NativeScanResult>;
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
	workspaceRoot: string;
	targetPath?: string;
	mode?: ScannerMode;
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
}

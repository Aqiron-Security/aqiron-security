import { UnifiedFinding } from './finding';

export type PipelineStageName =
	| 'Preparing'
	| 'Project Discovery'
	| 'Indexing'
	| 'Scanner Execution'
	| 'Dependency Analysis'
	| 'SAST'
	| 'Secret Scanning'
	| 'RAG Retrieval'
	| 'Validation'
	| 'AI Vulnerability Analysis'
	| 'AI Correlation'
	| 'Report Generation';

export type ToolStatus = 'queued' | 'running' | 'completed' | 'failed' | 'timeout' | 'unavailable' | 'cancelled';

export interface ToolExecutionState {
	id: string;
	label: string;
	command: string;
	status: ToolStatus;
	startedAt?: string;
	completedAt?: string;
	durationMs?: number;
	exitCode?: number;
	message?: string;
	findingsCount?: number;
}

export interface ScanState {
	scanId: string;
	workspaceRoot: string;
	targetPath: string;
	mode: string;
	stage: PipelineStageName | 'Initialising' | 'Idle';
	stageProgress: number;
	scanners: ToolExecutionState[];
	findingsCount: number;
	riskScore: number;
	cancelled: boolean;
	startedAt: string;
	updatedAt: string;
	completedAt?: string;
	reportStatus: 'idle' | 'running' | 'completed' | 'failed';
	finalState: 'idle' | 'running' | 'completed' | 'failed' | 'cancelled';
}

export interface PipelineStageState {
	name: PipelineStageName;
	status: ToolStatus;
	progress: number;
	startedAt?: string;
	completedAt?: string;
	durationMs?: number;
}

export type PipelineEvent =
	| { type: 'scan.started'; scan: ScanState }
	| { type: 'scan.stage.started'; scanId: string; stage: PipelineStageState }
	| { type: 'scan.stage.progress'; scanId: string; stage: PipelineStageState }
	| { type: 'scan.stage.completed'; scanId: string; stage: PipelineStageState }
	| { type: 'scanner.started'; scanId: string; scanner: ToolExecutionState }
	| { type: 'scanner.output'; scanId: string; scannerId: string; message: string; timestamp: string }
	| { type: 'scanner.completed'; scanId: string; scanner: ToolExecutionState }
	| { type: 'findings.updated'; scanId: string; findingsCount: number; riskScore: number; timestamps: string[] }
	| { type: 'correlation.completed'; scanId: string; findingsCount: number; relationships: number; duplicates: number }
	| { type: 'ai.analysis.started'; scanId: string; workspaceRoot: string }
	| { type: 'ai.analysis.completed'; scanId: string; findingsCount: number; durationMs: number }
	| { type: 'report.started'; scanId: string }
	| { type: 'report.completed'; scanId: string }
	| { type: 'scan.completed'; scan: ScanState }
	| { type: 'scan.failed'; scan: ScanState; message: string; tool?: string }
	| { type: 'scan.cancelled'; scan: ScanState; reason: string }
	| { type: 'stage'; stage: PipelineStageState }
	| { type: 'tool'; tool: ToolExecutionState }
	| { type: 'log'; tool?: string; message: string; timestamp: string }
	| { type: 'finding'; finding: UnifiedFinding }
	| { type: 'complete'; durationMs: number; findingsCount: number }
	| { type: 'cancelled'; reason: string }
	| { type: 'error'; message: string; tool?: string };

export interface PipelineEmitter {
	emit(event: PipelineEvent): void;
}

export class PipelineEventBus implements PipelineEmitter {
	private readonly listeners = new Set<(event: PipelineEvent) => void>();

	on(listener: (event: PipelineEvent) => void): { dispose(): void } {
		this.listeners.add(listener);
		return { dispose: () => this.listeners.delete(listener) };
	}

	emit(event: PipelineEvent): void {
		for (const listener of this.listeners) {
			listener(event);
		}
	}
}

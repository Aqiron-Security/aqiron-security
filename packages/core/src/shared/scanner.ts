import { UnifiedFinding } from './finding';
import { CancellationTokenLike } from './cancellation';

export interface ScanTarget {
	workspaceRoot: string;
	targetPath: string;
	containerImage?: string;
	exclusions: string[];
	policyPath?: string;
}

export interface ScannerInputFile {
	path: string;
	relativePath: string;
}

export interface ScannerRunContext {
	emitter: import('./pipeline').PipelineEmitter;
	cancellationToken?: CancellationTokenLike;
	timeoutMs: number;
}

export interface ScannerResult {
	toolId: string;
	label: string;
	findings: UnifiedFinding[];
	filesScanned?: number;
	durationMs: number;
	unavailable?: boolean;
	error?: string;
}

export interface SecurityScanner {
	readonly id: string;
	readonly label: string;
	scan(target: ScanTarget, context: ScannerRunContext): Promise<ScannerResult>;
}

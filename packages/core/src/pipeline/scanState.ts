import { PipelineStageName, ScanState, ToolExecutionState } from '../shared/pipeline';

export type ScanFinalState = ScanState['finalState'];

export function createScanState(input: {
	scanId: string;
	workspaceRoot: string;
	targetPath: string;
	mode: string;
	startedAt?: string;
}): ScanState {
	const startedAt = input.startedAt ?? new Date().toISOString();
	return {
		scanId: input.scanId,
		workspaceRoot: input.workspaceRoot,
		targetPath: input.targetPath,
		mode: input.mode,
		stage: 'Idle',
		stageProgress: 0,
		scanners: [],
		findingsCount: 0,
		riskScore: 0,
		cancelled: false,
		startedAt,
		updatedAt: startedAt,
		reportStatus: 'idle',
		finalState: 'running',
	};
}

export function updateStageState(state: ScanState, stage: PipelineStageName | 'Initialising' | 'Idle', progress: number, status: ToolExecutionState['status'] = 'running'): ScanState {
	const updatedAt = new Date().toISOString();
	return {
		...state,
		stage,
		stageProgress: clamp(progress, 0, 100),
		updatedAt,
		finalState: status === 'failed' ? 'failed' : state.finalState,
	};
}

export function updateScannerState(state: ScanState, scanner: ToolExecutionState): ScanState {
	const scanners = [...state.scanners];
	const index = scanners.findIndex((entry) => entry.id === scanner.id);
	if (index === -1) {
		scanners.push(scanner);
	} else {
		scanners[index] = { ...scanners[index], ...scanner };
	}
	return {
		...state,
		scanners,
		updatedAt: scanner.completedAt ?? scanner.startedAt ?? new Date().toISOString(),
	};
}

export function updateFindingState(state: ScanState, findingsCount: number, riskScore: number): ScanState {
	return {
		...state,
		findingsCount,
		riskScore: clamp(riskScore, 0, 100),
		updatedAt: new Date().toISOString(),
	};
}

export function markCompleted(state: ScanState, finalState: ScanFinalState = 'completed'): ScanState {
	const updatedAt = new Date().toISOString();
	return {
		...state,
		reportStatus: finalState === 'completed' ? 'completed' : state.reportStatus,
		finalState,
		completedAt: updatedAt,
		updatedAt,
	};
}

export function markReportState(state: ScanState, reportStatus: ScanState['reportStatus']): ScanState {
	return {
		...state,
		reportStatus,
		updatedAt: new Date().toISOString(),
	};
}

function clamp(value: number, min: number, max: number): number {
	return Math.max(min, Math.min(max, value));
}

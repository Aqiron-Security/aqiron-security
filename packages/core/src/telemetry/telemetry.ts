import { PipelineEvent, ToolExecutionState } from '../pipeline/events';

export interface ScanTelemetrySnapshot {
	scanId: string;
	startedAt: string;
	completedAt?: string;
	durationMs?: number;
	tools: ToolExecutionState[];
	logs: string[];
	findings: number;
	failures: number;
	timeouts: number;
	cancelled: boolean;
}

export class TelemetryEngine {
	private snapshot: ScanTelemetrySnapshot;

	constructor(scanId: string) {
		this.snapshot = {
			scanId,
			startedAt: new Date().toISOString(),
			tools: [],
			logs: [],
			findings: 0,
			failures: 0,
			timeouts: 0,
			cancelled: false,
		};
	}

	record(event: PipelineEvent): void {
		switch (event.type) {
			case 'tool':
				this.upsertTool(event.tool);
				if (event.tool.status === 'failed') {
					this.snapshot.failures += 1;
				}
				if (event.tool.status === 'timeout') {
					this.snapshot.timeouts += 1;
				}
				break;
			case 'log':
				this.snapshot.logs = [...this.snapshot.logs.slice(-199), `[${event.timestamp}]${event.tool ? ` [${event.tool}]` : ''} ${event.message}`];
				break;
			case 'finding':
				this.snapshot.findings += 1;
				break;
			case 'complete':
				this.snapshot.completedAt = new Date().toISOString();
				this.snapshot.durationMs = event.durationMs;
				this.snapshot.findings = event.findingsCount;
				break;
			case 'cancelled':
				this.snapshot.cancelled = true;
				this.snapshot.completedAt = new Date().toISOString();
				break;
			default:
				break;
		}
	}

	getSnapshot(): ScanTelemetrySnapshot {
		return {
			...this.snapshot,
			tools: [...this.snapshot.tools],
			logs: [...this.snapshot.logs],
		};
	}

	private upsertTool(tool: ToolExecutionState): void {
		const index = this.snapshot.tools.findIndex((candidate) => candidate.id === tool.id);
		if (index === -1) {
			this.snapshot.tools.push(tool);
			return;
		}
		this.snapshot.tools[index] = { ...this.snapshot.tools[index], ...tool };
	}
}

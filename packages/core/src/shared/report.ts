import { CorrelationResult } from '../correlation/correlationEngine';
import { SecurityGraph } from '../correlation/relationshipGraph';
import { UnifiedFinding } from './finding';
import { ScanTelemetrySnapshot } from '../telemetry/telemetry';

export type ExecutiveSummaryGenerator = (workspaceRoot: string, findings: readonly UnifiedFinding[], correlation: CorrelationResult) => Promise<string>;

export interface SecurityReportBundle {
	json: unknown;
	sarif: unknown;
	executiveSummary: string;
	exports: {
		directory?: string;
		jsonPath?: string;
		sarifPath?: string;
		pdfPath?: string;
	};
}

export interface SecurityReportInput {
	workspaceRoot: string;
	findings: readonly UnifiedFinding[];
	correlation: CorrelationResult;
	graph: SecurityGraph;
	telemetry: ScanTelemetrySnapshot;
}

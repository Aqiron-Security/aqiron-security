import { CorrelationResult } from '../correlation/correlationEngine';
import { SecurityGraph } from '../correlation/relationshipGraph';
import { UnifiedFinding } from '../shared/finding';
import { ScanTelemetrySnapshot } from '../telemetry/telemetry';

export interface SecurityReportSummary {
	total: number;
	critical: number;
	high: number;
	medium: number;
	low: number;
}

export interface SecurityReportCompliancePosture {
	owaspCoverage: 'Mapped' | 'Partial';
	cweCoverage: 'Mapped' | 'Partial';
	releaseGate: 'Pass' | 'Review' | 'Block';
}

export interface SecurityReportRemediationItem {
	id: string;
	severity: string;
	file: string;
	line: number;
	action: string;
}

export interface SecurityReportPdfContext {
	scanMode?: 'quick' | 'deep' | 'analysis' | 'custom';
	scanId?: string;
	reportVersion?: string;
}

export interface SecurityReportModel {
	generatedAt: string;
	executiveSummary: string;
	summary: SecurityReportSummary;
	owasp: Record<string, number>;
	cwe: Record<string, number>;
	compliancePosture: SecurityReportCompliancePosture;
	remediationPlan: SecurityReportRemediationItem[];
	findings: readonly UnifiedFinding[];
	correlation: CorrelationResult['summary'];
	graph: SecurityGraph;
	telemetry: ScanTelemetrySnapshot;
}

export interface SecurityReportContent {
	model: SecurityReportModel;
	text: string;
	sarif: unknown;
	pdf: string;
}

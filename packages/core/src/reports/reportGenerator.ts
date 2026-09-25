import { CorrelationResult } from '../correlation/correlationEngine';
import { SecurityGraph } from '../correlation/relationshipGraph';
import { UnifiedFinding } from '../shared/finding';
import { ScanTelemetrySnapshot } from '../telemetry/telemetry';
import { ExecutiveSummaryGenerator, createExecutiveSummary } from './executiveSummary';
import { createJsonReport, createPdfReport, createSarifReport, createTextReport } from './reportExporters';
import { SecurityReportContent, SecurityReportModel, SecurityReportPdfContext } from './reportModels';

export class ReportGenerator {
	constructor(private readonly executiveSummaryGenerator?: ExecutiveSummaryGenerator) {}

	async generate(workspaceRoot: string, findings: readonly UnifiedFinding[], correlation: CorrelationResult, graph: SecurityGraph, telemetry: ScanTelemetrySnapshot, reportContext?: SecurityReportPdfContext): Promise<SecurityReportContent> {
		const generatedAt = new Date().toISOString();
		const executiveSummary = await createExecutiveSummary(workspaceRoot, findings, correlation, this.executiveSummaryGenerator);
		const model: SecurityReportModel = {
			generatedAt,
			executiveSummary,
			summary: summarize(findings),
			owasp: countMapped(findings, 'owasp'),
			cwe: countMapped(findings, 'cwe'),
			compliancePosture: createCompliancePosture(findings),
			remediationPlan: findings.slice(0, 25).map((finding) => ({
				id: finding.id,
				severity: finding.severity,
				file: finding.file,
				line: finding.line,
				action: finding.remediation,
			})),
			findings,
			correlation: correlation.summary,
			graph,
			telemetry,
		};
		void createJsonReport(model);
		const sarif = createSarifReport(findings);
		const pdf = createPdfReport(model, workspaceRoot, reportContext);
		const text = createTextReport({ model, text: executiveSummary, sarif, pdf });
		return { model, text, sarif, pdf };
	}
}

function summarize(findings: readonly UnifiedFinding[]): { total: number; critical: number; high: number; medium: number; low: number } {
	return {
		total: findings.length,
		critical: findings.filter((finding) => finding.severity === 'Critical').length,
		high: findings.filter((finding) => finding.severity === 'High').length,
		medium: findings.filter((finding) => finding.severity === 'Medium').length,
		low: findings.filter((finding) => finding.severity === 'Low').length,
	};
}

function countMapped(findings: readonly UnifiedFinding[], key: 'owasp' | 'cwe'): Record<string, number> {
	const counts: Record<string, number> = {};
	for (const finding of findings) {
		for (const value of finding[key]) {
			counts[value] = (counts[value] ?? 0) + 1;
		}
	}
	return counts;
}

function createCompliancePosture(findings: readonly UnifiedFinding[]): { owaspCoverage: 'Mapped' | 'Partial'; cweCoverage: 'Mapped' | 'Partial'; releaseGate: 'Pass' | 'Review' | 'Block' } {
	const summary = summarize(findings);
	return {
		owaspCoverage: findings.some((finding) => finding.owasp.length > 0) ? 'Mapped' : 'Partial',
		cweCoverage: findings.some((finding) => finding.cwe.length > 0) ? 'Mapped' : 'Partial',
		releaseGate: summary.critical > 0 || summary.high > 3 ? 'Block' : summary.high > 0 ? 'Review' : 'Pass',
	};
}

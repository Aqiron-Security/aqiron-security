import * as fs from 'fs/promises';
import * as path from 'path';
import { ExecutiveSummaryGenerator, SecurityReportContent, SecurityReportBundle, CorrelationResult, SecurityGraph, ScanTelemetrySnapshot, UnifiedFinding } from '../../../packages/core/src';
import { getCoreClient } from '../../core/coreClientSingleton';

export type { ExecutiveSummaryGenerator, SecurityReportBundle };

export class ReportGenerator {
	constructor(_generateAiSummary?: ExecutiveSummaryGenerator) {}

	async generate(workspaceRoot: string, findings: readonly UnifiedFinding[], correlation: CorrelationResult, graph: SecurityGraph, telemetry: ScanTelemetrySnapshot): Promise<SecurityReportBundle> {
		const reportDirectory = path.join(workspaceRoot, '.aqiron-security', 'reports');
		await fs.mkdir(reportDirectory, { recursive: true });
		const stamp = new Date().toISOString().replace(/[:.]/g, '-');
		const content = await getCoreClient().reportGenerate({ workspaceRoot, findings: [...findings], correlation, graph, telemetry });
		const jsonPath = path.join(reportDirectory, `aqiron-security-${stamp}.json`);
		const sarifPath = path.join(reportDirectory, `aqiron-security-${stamp}.sarif`);
		const pdfPath = path.join(reportDirectory, `aqiron-security-${stamp}.pdf`);
		await fs.writeFile(jsonPath, JSON.stringify(content.model, null, 2), 'utf8');
		await fs.writeFile(sarifPath, JSON.stringify(content.sarif, null, 2), 'utf8');
		await fs.writeFile(pdfPath, content.pdf, 'binary');
		return { json: content.model, sarif: content.sarif, executiveSummary: content.model.executiveSummary, exports: { jsonPath, sarifPath, pdfPath } };
	}
}

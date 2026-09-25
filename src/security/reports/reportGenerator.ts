import * as fs from 'fs/promises';
import { ExecutiveSummaryGenerator, SecurityReportContent, SecurityReportBundle, CorrelationResult, SecurityGraph, ScanTelemetrySnapshot, UnifiedFinding } from '../../../packages/core/src';
import { getCoreClient } from '../../core/coreClientSingleton';
import { createReportBundlePaths } from './reportStorage';

export type { ExecutiveSummaryGenerator, SecurityReportBundle };

export class ReportGenerator {
	constructor(_generateAiSummary?: ExecutiveSummaryGenerator) {}

	async generate(workspaceRoot: string, findings: readonly UnifiedFinding[], correlation: CorrelationResult, graph: SecurityGraph, telemetry: ScanTelemetrySnapshot): Promise<SecurityReportBundle> {
		const content = await getCoreClient().reportGenerate({ workspaceRoot, findings: [...findings], correlation, graph, telemetry });
		const paths = await createReportBundlePaths(workspaceRoot, content.model.generatedAt);
		await fs.writeFile(paths.jsonPath, JSON.stringify(content.model, null, 2), 'utf8');
		await fs.writeFile(paths.sarifPath, JSON.stringify(content.sarif, null, 2), 'utf8');
		await fs.writeFile(paths.pdfPath, content.pdf, 'binary');
		return { json: content.model, sarif: content.sarif, executiveSummary: content.model.executiveSummary, exports: paths };
	}
}

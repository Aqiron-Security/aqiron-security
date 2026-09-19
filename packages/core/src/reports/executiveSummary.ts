import * as path from 'path';
import { CorrelationResult } from '../correlation/correlationEngine';
import { UnifiedFinding } from '../shared/finding';
export type ExecutiveSummaryGenerator = import('../shared/report').ExecutiveSummaryGenerator;

export async function createExecutiveSummary(workspaceRoot: string, findings: readonly UnifiedFinding[], correlation: CorrelationResult, generator?: ExecutiveSummaryGenerator): Promise<string> {
	if (generator) {
		try {
			const generated = (await generator(workspaceRoot, findings, correlation)).trim();
			if (generated) {
				return generated;
			}
		} catch {
			// Fall back to deterministic output if AI summary generation fails.
		}
	}
	return createDeterministicExecutiveSummary(findings, correlation);
}

export function createDeterministicExecutiveSummary(findings: readonly UnifiedFinding[], correlation: CorrelationResult): string {
	const summary = summarize(findings);
	const top = findings.slice(0, 5).map((finding) => `${finding.severity}: ${finding.title} (${path.basename(finding.file)}:${finding.line})`);
	return [
		'Aqiron Security Executive Summary',
		`Open findings: ${summary.total} (${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low).`,
		`Correlation deduplicated ${correlation.summary.deduplicated} duplicate signals and inferred ${correlation.summary.attackPaths} attack path(s).`,
		'Priority remediation:',
		...top.map((line) => `- ${line}`),
	].join('\n');
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

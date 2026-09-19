import { SecurityReportContent, SecurityReportModel } from './reportModels';
import { UnifiedFinding } from '../shared/finding';

export function createJsonReport(model: SecurityReportModel): unknown {
	return model;
}

export function createTextReport(content: SecurityReportContent): string {
	return [
		'Aqiron Security Report',
		`Generated at: ${content.model.generatedAt}`,
		'',
		content.model.executiveSummary,
		'',
		`Findings: ${content.model.summary.total} total (${content.model.summary.critical} critical, ${content.model.summary.high} high, ${content.model.summary.medium} medium, ${content.model.summary.low} low)`,
		`OWASP mappings: ${Object.keys(content.model.owasp).length}`,
		`CWE mappings: ${Object.keys(content.model.cwe).length}`,
	].join('\n');
}

export function createSarifReport(findings: readonly UnifiedFinding[]): unknown {
	return {
		version: '2.1.0',
		$schema: 'https://json.schemastore.org/sarif-2.1.0.json',
		runs: [{
			tool: { driver: { name: 'Aqiron Security', informationUri: 'https://aqiron.security' } },
			results: findings.map((finding) => ({
				ruleId: finding.ruleId,
				level: toSarifLevel(finding.severity),
				message: { text: finding.description },
				locations: [{
					physicalLocation: {
						artifactLocation: { uri: finding.file },
						region: { startLine: finding.line, startColumn: finding.column },
					},
				}],
				properties: {
					sourceTool: finding.sourceTool,
					cwe: finding.cwe,
					owasp: finding.owasp,
					confidence: finding.confidence,
					remediation: finding.remediation,
				},
			})),
		}],
	};
}

export function createPdfReport(text: string): string {
	const escaped = text.replace(/[()\\]/g, '\\$&').split(/\r?\n/).slice(0, 35);
	const content = escaped.map((line, index) => `BT /F1 10 Tf 36 ${760 - index * 16} Td (${line}) Tj ET`).join('\n');
	const objects = [
		'1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj',
		'2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj',
		'3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj',
		'4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj',
		`5 0 obj << /Length ${Buffer.byteLength(content)} >> stream\n${content}\nendstream endobj`,
	];
	const body = objects.join('\n');
	return `%PDF-1.4\n${body}\ntrailer << /Root 1 0 R >>\n%%EOF`;
}

function toSarifLevel(severity: string): 'error' | 'warning' | 'note' {
	if (severity === 'Critical' || severity === 'High') {
		return 'error';
	}
	if (severity === 'Medium') {
		return 'warning';
	}
	return 'note';
}

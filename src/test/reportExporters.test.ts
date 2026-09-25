import { strict as assert } from 'assert';
import { createJsonReport, createPdfReport, createSarifReport } from '../../packages/core/src/reports/reportExporters';
import { SecurityReportModel } from '../../packages/core/src/reports/reportModels';
import { createFinding } from '../../packages/core/src/shared/finding';

function makeModel(findings = [makeFinding('Critical'), makeFinding('High'), makeFinding('Medium'), makeFinding('Low')]): SecurityReportModel {
	return {
		generatedAt: '2026-09-25T10:00:00.000Z',
		executiveSummary: 'A deterministic summary based on the supplied findings.',
		summary: {
			total: findings.length,
			critical: findings.filter((finding) => finding.severity === 'Critical').length,
			high: findings.filter((finding) => finding.severity === 'High').length,
			medium: findings.filter((finding) => finding.severity === 'Medium').length,
			low: findings.filter((finding) => finding.severity === 'Low').length,
		},
		owasp: { 'A01:2021': 1 },
		cwe: { 'CWE-798': 1 },
		compliancePosture: { owaspCoverage: 'Mapped', cweCoverage: 'Mapped', releaseGate: 'Block' },
		remediationPlan: findings.map((finding) => ({ id: finding.id, severity: finding.severity, file: finding.file, line: finding.line, action: finding.remediation })),
		findings,
		correlation: { deduplicated: 1, boosted: 1, attackPaths: 1 },
		graph: { nodes: [], edges: [] },
		telemetry: {
			scanId: 'scan-test',
			startedAt: '2026-09-25T09:59:00.000Z',
			completedAt: '2026-09-25T10:00:00.000Z',
			durationMs: 60000,
			tools: [{ id: 'semgrep', label: 'Semgrep', command: 'semgrep', status: 'completed', findingsCount: 4 }],
			logs: [],
			findings: findings.length,
			failures: 0,
			timeouts: 0,
			cancelled: false,
		},
	};
}

function makeFinding(severity: 'Critical' | 'High' | 'Medium' | 'Low', index = 0) {
	return createFinding({
		title: `${severity} finding ${index}`,
		description: 'A finding description supplied by the scanner.',
		severity,
		cwe: ['798'],
		owasp: ['A01:2021'],
		file: `D:/workspace/${'very/'.repeat(index + 1)}long-file-name-${index}.dart`,
		line: index + 1,
		column: 1,
		sourceTool: 'Aqiron',
		ruleId: `test.${severity.toLowerCase()}`,
		confidence: 'High',
		remediation: 'Apply the supplied remediation guidance.',
		tags: ['sast'],
		rawEvidence: { line: 'safe evidence', token: 'sk-test-12345678901234567890' },
	});
}

suite('Report exporters', () => {
	test('generates a multi-page PDF with data-backed severity and sections', () => {
		const model = makeModel();
		const pdf = createPdfReport(model, 'D:/workspace/example-app');
		assert.ok(pdf.startsWith('%PDF-1.4'));
		assert.ok(pdf.includes('/Type /Pages'));
		assert.match(pdf, /\/Count \d+/);
		assert.ok(pdf.includes('Security Assessment Report'));
		assert.ok(pdf.includes('/Subtype /Image'));
		assert.ok(pdf.includes('/Filter /DCTDecode'));
		assert.ok(pdf.includes('CRITICAL'));
		assert.ok(pdf.includes('Scanner / Coverage Summary'));
		assert.ok(pdf.includes('/Subtype /Link'));
		assert.ok(!pdf.includes('{PAGE:'));
		assert.ok(!pdf.includes('(Report) Tj ET'));
		assert.ok(!pdf.includes('Aqiron Risk Score'));
		assert.ok(!pdf.includes('sk-test-12345678901234567890'));
	});

	test('omits optional correlation and stray report pages when relationship data is empty', () => {
		const model = makeModel([]);
		model.correlation = { deduplicated: 0, boosted: 0, attackPaths: 0 };
		model.graph = { nodes: [], edges: [] };
		const pdf = createPdfReport(model);
		assert.ok(!pdf.includes('05  Correlation / Relationships'));
		assert.ok(!pdf.includes('(Report) Tj ET'));
	});

	test('adds contents and report identity only when the report is large enough', () => {
		const findings = Array.from({ length: 8 }, (_, index) => makeFinding(index % 2 ? 'High' : 'Medium', index));
		const model = makeModel(findings);
		const pdf = createPdfReport(model, 'D:/workspace/example-app', { scanMode: 'deep', scanId: 'scan-large' });
		assert.ok(pdf.includes('00  Contents'));
		assert.ok(pdf.includes('Scan mode'));
		assert.ok(pdf.includes('deep'));
		assert.ok(pdf.includes('scan-large'));
	});

	test('handles empty findings and missing optional telemetry', () => {
		const model = makeModel([]);
		(model as { telemetry?: unknown }).telemetry = undefined;
		const pdf = createPdfReport(model);
		assert.ok(pdf.startsWith('%PDF-1.4'));
		assert.ok(pdf.includes('No findings were returned by the assessment.'));
		assert.ok(pdf.includes('Scan telemetry was not supplied with this report.'));
	});

	test('handles long descriptions, paths, and evidence without rendering failure', () => {
		const finding = makeFinding('High', 2);
		finding.description = 'long description '.repeat(500);
		finding.file = `D:/workspace/${'nested/'.repeat(100)}file-with-a-very-long-name.dart`;
		finding.rawEvidence = { evidence: 'evidence '.repeat(1000) };
		const model = makeModel([finding]);
		const pdf = createPdfReport(model, 'D:/workspace/example-app');
		assert.ok(pdf.startsWith('%PDF-1.4'));
		assert.ok(pdf.includes('/Count'));
	});

	test('keeps JSON and SARIF exporters independent of PDF presentation', () => {
		const model = makeModel();
		assert.deepEqual(createJsonReport(model), model);
		const sarif = createSarifReport(model.findings) as { runs: Array<{ results: unknown[] }> };
		assert.equal(sarif.runs[0].results.length, model.findings.length);
	});
});

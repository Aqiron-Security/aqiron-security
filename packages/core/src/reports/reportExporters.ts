import * as fs from 'fs';
import * as path from 'path';
import { SecurityReportContent, SecurityReportModel, SecurityReportPdfContext } from './reportModels';
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

/**
 * Render the report model directly into a small, dependency-free PDF.
 *
 * This intentionally lives beside the JSON/SARIF exporters: it is a
 * presentation layer and does not change finding normalization or report IPC.
 */
export function createPdfReport(model: SecurityReportModel, workspaceRoot = '', pdfContext?: SecurityReportPdfContext): string {
	const document = new PdfDocument(loadReportLogo(workspaceRoot));
	const report = new ReportLayout(document, model, workspaceRoot, pdfContext);
	report.render();
	return document.serialize();
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

const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;
const MARGIN = 48;
const CONTENT_WIDTH = PAGE_WIDTH - (MARGIN * 2);
const COLORS = {
	ink: [25, 35, 50],
	muted: [91, 105, 122],
	line: [218, 224, 231],
	panel: [246, 248, 250],
	brand: [20, 91, 105],
	brandLight: [226, 241, 242],
	findingsPanel: [231, 240, 246],
	criticalPanel: [250, 233, 236],
	highPanel: [252, 240, 230],
	mediumPanel: [252, 247, 228],
	lowPanel: [231, 243, 243],
	critical: [150, 48, 59],
	high: [194, 99, 34],
	medium: [170, 122, 27],
	low: [48, 111, 119],
} as const;
type Color = readonly [number, number, number];

class PdfDocument {
	private readonly pages: string[][] = [];
	private readonly links = new Map<number, Array<{ x: number; y: number; width: number; height: number; uri: string }>>();
	private readonly tokens = new Map<string, string>();

	constructor(private readonly logoJpeg?: Buffer) {}

	addPage(): string[] {
		const page: string[] = [];
		this.pages.push(page);
		return page;
	}

	addLink(page: string[], x: number, y: number, width: number, height: number, uri: string): void {
		const pageIndex = this.pages.indexOf(page);
		if (pageIndex >= 0) {
			const pageLinks = this.links.get(pageIndex) ?? [];
			pageLinks.push({ x, y, width, height, uri });
			this.links.set(pageIndex, pageLinks);
		}
	}

	setToken(token: string, value: string): void {
		this.tokens.set(token, value);
	}

	serialize(): string {
		const objects: string[] = [];
		const pageObjectIds: number[] = [];
		const pageTreeId = 2;
		objects[0] = '<< /Type /Catalog /Pages 2 0 R >>';
		objects[1] = '';
		objects[2] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
		objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>';
		objects[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>';
		const logoImageId = this.logoJpeg ? 6 : undefined;
		if (this.logoJpeg) {
			objects[5] = `<< /Type /XObject /Subtype /Image /Width 128 /Height 154 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${this.logoJpeg.length} >> stream\n${this.logoJpeg.toString('latin1')}\nendstream`;
		}
		let nextId = this.logoJpeg ? 7 : 6;
		const pageInfos: Array<{ page: string[]; contentId: number; pageId: number; annotationIds: number[] }> = [];
		for (const page of this.pages) {
			const contentId = nextId++;
			const pageId = nextId++;
			const content = this.replaceTokens(page.join('\n'));
			objects[contentId - 1] = `<< /Length ${Buffer.byteLength(content, 'ascii')} >> stream\n${content}\nendstream`;
			pageObjectIds.push(pageId);
			const annotationIds = (this.links.get(pageInfos.length) ?? []).map(() => nextId++);
			pageInfos.push({ page, contentId, pageId, annotationIds });
		}
		for (let index = 0; index < pageInfos.length; index++) {
			const info = pageInfos[index];
			const annots = info.annotationIds.length ? ` /Annots [${info.annotationIds.map((id) => `${id} 0 R`).join(' ')}]` : '';
			const imageResource = logoImageId ? ` /XObject << /Im1 ${logoImageId} 0 R >>` : '';
			objects[info.pageId - 1] = `<< /Type /Page /Parent ${pageTreeId} 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >>${imageResource} >> /Contents ${info.contentId} 0 R${annots} >>`;
			const pageLinks = this.links.get(index) ?? [];
			for (let linkIndex = 0; linkIndex < pageLinks.length; linkIndex++) {
				const link = pageLinks[linkIndex];
				objects[info.annotationIds[linkIndex] - 1] = `<< /Type /Annot /Subtype /Link /Rect [${round(link.x)} ${round(link.y)} ${round(link.x + link.width)} ${round(link.y + link.height)}] /Border [0 0 0] /A << /S /URI /URI (${pdfEscape(link.uri)}) >> >>`;
			}
		}
		objects[1] = `<< /Type /Pages /Kids [${pageObjectIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageObjectIds.length} >>`;
		const output = ['%PDF-1.4'];
		const offsets: number[] = [0];
		for (let index = 0; index < objects.length; index++) {
			if (!objects[index]) {
				continue;
			}
			offsets[index + 1] = Buffer.byteLength(output.join('\n') + '\n', 'ascii');
			output.push(`${index + 1} 0 obj`, objects[index], 'endobj');
		}
		const xrefOffset = Buffer.byteLength(output.join('\n') + '\n', 'ascii');
		output.push(`xref\n0 ${objects.length + 1}`, '0000000000 65535 f ');
		for (let index = 1; index <= objects.length; index++) {
			output.push(`${String(offsets[index] ?? 0).padStart(10, '0')} 00000 n `);
		}
		output.push(`trailer << /Size ${objects.length + 1} /Root 1 0 R >>`, `startxref\n${xrefOffset}`, '%%EOF');
		return output.join('\n');
	}

	private replaceTokens(value: string): string {
		let result = value;
		for (const [token, replacement] of this.tokens) result = result.replaceAll(token, replacement);
		return result;
	}

	hasLogo(): boolean {
		return Boolean(this.logoJpeg);
	}
}

class ReportLayout {
	private page: string[];
	private y = PAGE_HEIGHT - MARGIN;
	private pageNumber = 0;
	private activeSection = 'Report';
	private readonly sectionPages = new Map<string, number>();
	private readonly includeContents: boolean;

	constructor(private readonly document: PdfDocument, private readonly model: SecurityReportModel, private readonly workspaceRoot: string, private readonly pdfContext?: SecurityReportPdfContext) {
		this.page = document.addPage();
		this.includeContents = model.findings.length >= 8;
	}

	render(): void {
		this.renderCover();
		if (this.includeContents) {
			this.newPage('Contents');
			this.renderContents();
		}
		this.newPage('Executive Summary');
		this.renderExecutiveSummary();
		this.newPage('Security Overview');
		this.renderOverview();
		this.newPage('Key Findings');
		this.renderKeyFindings();
		this.renderDetailedFindings();
		if (this.hasCorrelationData()) {
			this.newPage('Correlation / Relationships');
			this.renderCorrelation();
		}
		if (this.model.telemetry?.tools?.length) {
			this.newPage('Scanner / Coverage Summary');
			this.renderScannerSummary();
		}
		this.renderRemediation();
		this.newPage('Appendix');
		this.renderAppendix();
		this.addFooter();
		for (const [title, page] of this.sectionPages) this.document.setToken(`{PAGE:${title}}`, String(page));
	}

	private renderCover(): void {
		this.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, COLORS.ink, true);
		this.rect(0, PAGE_HEIGHT - 14, PAGE_WIDTH, 14, COLORS.brand, true);
		if (this.document.hasLogo()) this.image('Im1', MARGIN, 605, 48, 58); else this.logo(MARGIN, 605, 48, COLORS.brandLight);
		this.text('AQIRON SECURITY', MARGIN + 64, 626, 12, [174, 205, 208], 'F2');
		this.text('Security Assessment Report', MARGIN, 510, 28, [255, 255, 255], 'F2');
		this.text(workspaceName(this.workspaceRoot), MARGIN, 470, 17, [218, 232, 234], 'F1');
		this.line(MARGIN, 438, PAGE_WIDTH - MARGIN, 438, COLORS.brand, 2);
		this.text('Generated', MARGIN, 405, 9, [174, 205, 208], 'F2');
		this.text(formatDate(this.model.generatedAt), MARGIN, 386, 12, [255, 255, 255]);
		this.renderIdentityBlock(MARGIN, 335, CONTENT_WIDTH, true);
		this.renderSeverityStrip(MARGIN, 245, CONTENT_WIDTH, this.model.summary);
		this.text('Assessment status', MARGIN, 185, 8, [174, 205, 208], 'F2');
		this.renderSeverityLegend(MARGIN, 164, true);
		const status = scanStatus(this.model.telemetry);
		this.badge(status.label, MARGIN, 124, status.color);
		this.text(status.detail, MARGIN + 92, 127, 8.5, [218, 232, 234]);
		this.text('Aqiron Security', MARGIN, 82, 10, [174, 205, 208], 'F2');
		this.text('Local-first application security assessment', MARGIN, 64, 9, [140, 164, 170]);
	}

	private renderExecutiveSummary(): void {
		this.renderIdentityBlock(MARGIN, this.y, CONTENT_WIDTH, false);
		this.y -= 68;
		this.sectionIntro('A concise reading of the assessment based on the findings and scan telemetry supplied to the report.');
		this.metricRow([
			['Findings', String(this.model.summary.total)],
			['Critical', String(this.model.summary.critical)],
			['High', String(this.model.summary.high)],
			['Medium', String(this.model.summary.medium)],
			['Low', String(this.model.summary.low)],
		]);
		this.y -= 22;
		this.heading('Assessment result');
		const status = scanStatus(this.model.telemetry);
		this.badge(status.label, MARGIN, this.y - 3, status.color);
		this.paragraph(status.detail, MARGIN + 92, this.y + 1, CONTENT_WIDTH - 92, 10, COLORS.ink);
		this.y -= 30;
		this.heading('Executive summary');
		this.flowParagraph(this.model.executiveSummary, MARGIN, CONTENT_WIDTH, 10.5, COLORS.ink);
		this.heading('Key observations');
		const observations = this.observations();
		for (const observation of observations) {
			this.bullet(observation);
		}
		this.renderNextActions();
	}

	private renderContents(): void {
		this.sectionIntro('A quick guide to the sections in this assessment.');
		for (const title of ['Executive Summary', 'Security Overview', 'Key Findings', 'Detailed Findings', 'Correlation / Relationships', 'Scanner / Coverage Summary', 'Remediation Summary', 'Appendix']) {
			if (title === 'Correlation / Relationships' && !this.hasCorrelationData()) continue;
			if (title === 'Scanner / Coverage Summary' && !this.model.telemetry?.tools?.length) continue;
			if (title === 'Remediation Summary' && !this.hasStatuses() && this.model.remediationPlan.length === 0) continue;
			this.text(`${sectionNumber(title)}  ${title}`, MARGIN, this.y, 10.5, COLORS.ink, 'F2');
			this.text(`{PAGE:${title}}`, PAGE_WIDTH - MARGIN - 26, this.y, 10, COLORS.muted, 'F3');
			this.line(MARGIN + 168, this.y - 2, PAGE_WIDTH - MARGIN - 36, this.y - 2, COLORS.line, 0.5);
			this.y -= 27;
		}
	}

	private renderOverview(): void {
		this.sectionIntro('Counts below are derived directly from the report findings and mappings.');
		this.heading('Severity distribution');
		const severityRows: Array<[string, number, Color]> = [
			['Critical', this.model.summary.critical, COLORS.critical],
			['High', this.model.summary.high, COLORS.high],
			['Medium', this.model.summary.medium, COLORS.medium],
			['Low', this.model.summary.low, COLORS.low],
		];
		const max = Math.max(1, ...severityRows.map((row) => row[1]));
		for (const [label, count, color] of severityRows) {
			this.text(label, MARGIN, this.y, 9.5, COLORS.ink, 'F2');
			this.text(String(count), MARGIN + 80, this.y, 9.5, COLORS.muted, 'F1');
			this.rect(MARGIN + 112, this.y - 4, 300, 10, COLORS.panel, true);
			if (count > 0) {
				this.rect(MARGIN + 112, this.y - 4, Math.max(7, 300 * count / max), 10, color, true);
			}
			this.y -= 25;
		}
		this.y -= 10;
		this.heading('Finding inventory');
		this.renderOverviewColumns();
		this.y -= 8;
		this.heading('Finding mappings');
		this.keyValue('OWASP references', String(Object.keys(this.model.owasp ?? {}).length));
		this.keyValue('CWE references', String(Object.keys(this.model.cwe ?? {}).length));
		if (this.hasCorrelationData()) {
			this.keyValue('Correlation relationships', String(this.model.graph?.edges?.length ?? 0));
			this.keyValue('Graph nodes', String(this.model.graph?.nodes?.length ?? 0));
		}
		if (this.hasStatuses()) {
			this.y -= 12;
			this.heading('Finding status');
			for (const [status, count] of statusCounts(this.model.findings)) {
				this.keyValue(status, String(count));
			}
		}
	}

	private renderKeyFindings(): void {
		this.sectionIntro('The prioritized list is ordered by the existing finding risk score, without creating a new aggregate score.');
		// Keep the prioritized section to one dense page. The complete set remains in Detailed Findings.
		const findings = [...this.model.findings].sort((left, right) => right.riskScore - left.riskScore).slice(0, 4);
		if (findings.length === 0) {
			this.emptyState('No findings were returned by the assessment.');
			return;
		}
		for (const finding of findings) {
			this.findingCard(finding, false);
		}
	}

	private renderDetailedFindings(): void {
		if (this.model.findings.length === 0) {
			return;
		}
		this.newPage('Detailed Findings');
		for (const finding of this.model.findings) {
			this.findingCard(finding, true);
		}
	}

	private findingCard(finding: UnifiedFinding, detailed: boolean): void {
		const titleLines = wrap(finding.title, detailed ? 72 : 66);
		const estimated = detailed ? 100 + titleLines.length * 16 : 125 + titleLines.length * 16 + wrap(compactPath(finding.file), 55).length * 12;
		if (detailed && this.y < 330) {
			this.newPage('Detailed Findings');
		}
		this.ensure(estimated, detailed ? 'Detailed Findings' : 'Key Findings');
		this.rect(MARGIN, this.y - 8, CONTENT_WIDTH, 3, severityColor(finding.severity), true);
		this.text(finding.severity.toUpperCase(), MARGIN, this.y - 28, 8.5, severityColor(finding.severity), 'F2');
		this.text(finding.id, MARGIN + 92, this.y - 28, 8.5, COLORS.muted, 'F3');
		this.y -= 45;
		for (const line of titleLines) {
			this.text(line, MARGIN, this.y, 13, COLORS.ink, 'F2');
			this.y -= 16;
		}
		this.renderFindingMetadata(finding);
		if (detailed) {
			this.optionalBlock('Description', finding.description);
			this.optionalBlock('Evidence', formatEvidence(finding.rawEvidence));
			this.optionalBlock('Remediation', finding.remediation);
			const related = finding.graph?.edges?.filter((edge) => edge.type === 'correlates-with').map((edge) => edge.targetId) ?? [];
			if (related.length) {
				this.optionalBlock('Related findings', related.join(', '));
			}
			const mappings = [...finding.cwe.map((value) => `CWE-${value.replace(/^CWE-/, '')}`), ...finding.owasp].join(', ');
			if (mappings) {
				this.optionalBlock('Mappings', mappings);
			}
		}
		this.y -= 14;
	}

	private renderCorrelation(): void {
		this.sectionIntro('Only relationships and graph metadata present in this report are shown.');
		this.heading('Correlation summary');
		this.keyValue('Duplicate signals removed', String(this.model.correlation?.deduplicated ?? 0));
		this.keyValue('Findings severity-boosted', String(this.model.correlation?.boosted ?? 0));
		this.keyValue('Attack paths inferred', String(this.model.correlation?.attackPaths ?? 0));
		this.keyValue('Relationship edges', String(this.model.graph?.edges?.length ?? 0));
		this.y -= 12;
		this.heading('Relationship map');
		this.renderRelationshipMap();
	}

	private renderScannerSummary(): void {
		this.sectionIntro('Scanner state is taken from scan telemetry. Unavailable tools are not presented as successful zero-finding scans.');
		this.heading('Scanner execution');
		for (const tool of this.model.telemetry.tools) {
			this.ensure(36, 'Scanner / Coverage Summary');
			const color = tool.status === 'completed' ? COLORS.low : tool.status === 'unavailable' ? COLORS.medium : COLORS.critical;
			this.badge(tool.status.toUpperCase(), MARGIN, this.y - 3, color);
			this.text(tool.label, MARGIN + 86, this.y, 10, COLORS.ink, 'F2');
			this.text(tool.findingsCount === undefined ? 'Finding count unavailable' : `${tool.findingsCount} finding${tool.findingsCount === 1 ? '' : 's'}`, MARGIN + 310, this.y, 9, COLORS.muted);
			if (tool.message) {
				this.paragraph(tool.message, MARGIN + 86, this.y - 14, CONTENT_WIDTH - 86, 8.5, COLORS.muted);
			}
			this.y -= tool.message ? 30 : 22;
		}
	}

	private renderRemediation(): void {
		if (!this.hasStatuses() && this.model.remediationPlan.length === 0) {
			return;
		}
		this.newPage('Remediation Summary');
		this.sectionIntro('Remediation information is limited to the finding statuses and guidance supplied by Aqiron.');
		if (this.hasStatuses()) {
			for (const [status, count] of statusCounts(this.model.findings)) {
				this.keyValue(status, String(count));
			}
		}
		if (this.model.remediationPlan.length) {
			this.y -= 14;
			this.heading('Prioritized actions');
			for (const item of this.model.remediationPlan.slice(0, 25)) {
				this.ensure(28, 'Remediation Summary');
				this.text(item.severity, MARGIN, this.y, 8.5, severityColor(item.severity), 'F2');
				this.text(item.id, MARGIN + 54, this.y, 7.5, severityColor(item.severity), 'F3');
				const action = `${compactPath(item.file)}:${item.line} - ${item.action}`;
				const actionLines = wrap(action, 50);
				for (let lineIndex = 0; lineIndex < actionLines.length; lineIndex++) {
					this.text(actionLines[lineIndex], MARGIN + 220, this.y - lineIndex * 12, 8.5, COLORS.ink);
				}
				this.y -= Math.max(20, actionLines.length * 12 + 5);
			}
		}
	}

	private renderAppendix(): void {
		this.sectionIntro('Technical metadata retained for traceability and review.');
		this.heading('Report metadata');
		this.keyValue('Generated at', formatDate(this.model.generatedAt));
		if (this.model.telemetry) {
			this.keyValue('Scan identifier', this.model.telemetry.scanId);
			this.keyValue('Started at', formatDate(this.model.telemetry.startedAt));
			if (this.model.telemetry.completedAt) {
				this.keyValue('Completed at', formatDate(this.model.telemetry.completedAt));
			}
			if (this.model.telemetry.durationMs !== undefined) {
				this.keyValue('Duration', `${this.model.telemetry.durationMs} ms`);
			}
		}
		this.keyValue('Workspace', workspaceName(this.workspaceRoot));
		if (this.pdfContext?.scanMode) this.keyValue('Scan mode', this.pdfContext.scanMode);
		if (this.pdfContext?.reportVersion) this.keyValue('Report version', this.pdfContext.reportVersion);
		this.y -= 14;
		this.heading('Technical inventory');
		this.renderAppendixColumns();
		this.y -= 14;
		this.heading('Finding identifiers');
		this.renderFindingIdentifierTable();
	}

	private observations(): string[] {
		const observations: string[] = [];
		if (this.model.summary.critical > 0) observations.push(`${this.model.summary.critical} critical finding${this.model.summary.critical === 1 ? '' : 's'} require immediate review.`);
		if (this.model.summary.high > 0) observations.push(`${this.model.summary.high} high-severity finding${this.model.summary.high === 1 ? '' : 's'} are present in the assessed result.`);
		if (this.model.correlation?.attackPaths > 0) observations.push(`${this.model.correlation.attackPaths} inferred attack path${this.model.correlation.attackPaths === 1 ? '' : 's'} are recorded in the correlation summary.`);
		if (observations.length === 0) observations.push('No critical or high-severity findings were returned by the assessed scan result.');
		return observations;
	}

	private sectionIntro(value: string): void {
		this.paragraph(value, MARGIN, this.y, CONTENT_WIDTH, 9, COLORS.muted);
		this.y -= 22;
	}

	private heading(value: string): void {
		this.ensure(30, value);
		this.icon(value, MARGIN, this.y - 10);
		this.text(value, MARGIN + 22, this.y, 15, COLORS.ink, 'F2');
		this.line(MARGIN + 22, this.y - 8, MARGIN + 56, this.y - 8, COLORS.brand, 2);
		this.y -= 25;
	}

	private keyValue(label: string, value: string): void {
		this.ensure(17);
		this.text(label, MARGIN, this.y, 9, COLORS.muted, 'F2');
		const lines = wrap(value, 55);
		for (let index = 0; index < lines.length; index++) {
			this.text(lines[index], MARGIN + 142, this.y - index * 12, 9, COLORS.ink);
		}
		this.y -= Math.max(16, lines.length * 12 + 2);
	}

	private optionalBlock(label: string, value: string): void {
		if (!value.trim()) return;
		this.ensure(28, 'Detailed Findings');
		this.text(label, MARGIN, this.y, 8.5, COLORS.muted, 'F2');
		this.y -= 14;
		const lines = wrap(value, 92);
		for (const line of lines) {
			this.ensure(14, 'Detailed Findings');
			this.text(line, MARGIN, this.y, 9, COLORS.ink, 'F1');
			this.y -= 13;
		}
		this.y -= 5;
	}

	private paragraph(value: string, x: number, y: number, width: number, size: number, color: Color): void {
		const maxChars = Math.max(12, Math.floor(width / (size * 0.52)));
		const lines = wrap(value, maxChars);
		for (let index = 0; index < lines.length; index++) {
			this.text(lines[index], x, y - index * (size + 3), size, color);
		}
	}

	private flowParagraph(value: string, x: number, width: number, size: number, color: Color): void {
		const maxChars = Math.max(12, Math.floor(width / (size * 0.52)));
		const lines = wrap(value, maxChars);
		for (const line of lines) {
			this.ensure(size + 5, 'Executive Summary');
			this.text(line, x, this.y, size, color);
			this.y -= size + 3;
		}
		this.y -= 5;
	}

	private bullet(value: string): void {
		const lines = wrap(value, Math.max(12, Math.floor((CONTENT_WIDTH - 14) / (9.5 * 0.52))));
		this.ensure(Math.max(18, lines.length * 13 + 5));
		this.text('-', MARGIN, this.y, 10, COLORS.brand, 'F2');
		for (let index = 0; index < lines.length; index++) {
			this.text(lines[index], MARGIN + 14, this.y - index * 13, 9.5, COLORS.ink);
		}
		this.y -= Math.max(17, lines.length * 13 + 4);
	}

	private metricRow(metrics: Array<[string, string]>): void {
		const width = CONTENT_WIDTH / metrics.length;
		const metricStyles: Array<{ panel: Color; accent: Color }> = [
			{ panel: COLORS.findingsPanel, accent: COLORS.brand },
			{ panel: COLORS.criticalPanel, accent: COLORS.critical },
			{ panel: COLORS.highPanel, accent: COLORS.high },
			{ panel: COLORS.mediumPanel, accent: COLORS.medium },
			{ panel: COLORS.lowPanel, accent: COLORS.low },
		];
		for (let index = 0; index < metrics.length; index++) {
			const x = MARGIN + index * width;
			const style = metricStyles[index] ?? metricStyles[0];
			this.rect(x, this.y - 44, width - 6, 42, style.panel, true);
			this.rect(x, this.y - 6, width - 6, 4, style.accent, true);
			this.text(metrics[index][1], x + 10, this.y - 22, 17, COLORS.ink, 'F2');
			this.text(metrics[index][0], x + 10, this.y - 37, 7.5, style.accent, 'F2');
		}
		this.y -= 62;
	}

	private renderSeverityStrip(x: number, y: number, width: number, summary: SecurityReportModel['summary']): void {
		const entries: Array<[number, Color]> = [[summary.critical, COLORS.critical], [summary.high, COLORS.high], [summary.medium, COLORS.medium], [summary.low, COLORS.low]];
		const total = Math.max(1, summary.total);
		let offset = x;
		for (const [count, color] of entries) {
			const segment = width * count / total;
			if (segment > 0) this.rect(offset, y, Math.max(3, segment), 12, color, true);
			offset += segment;
		}
		this.text(`${summary.total} total findings`, x, y - 28, 10, [218, 232, 234], 'F2');
	}

	private renderSeverityLegend(x: number, y: number, onDark = false): void {
		const labels: Array<[string, Color]> = [['Critical', COLORS.critical], ['High', COLORS.high], ['Medium', COLORS.medium], ['Low', COLORS.low]];
		let offset = x;
		for (const [label, color] of labels) {
			this.rect(offset, y, 8, 8, color, true);
			this.text(label, offset + 13, y + 1, 7.5, onDark ? [218, 232, 234] : COLORS.muted, 'F2');
			offset += 72;
		}
	}

	private renderIdentityBlock(x: number, y: number, width: number, onDark: boolean): void {
		const panel = onDark ? [35, 51, 62] as Color : COLORS.panel;
		const textColor = onDark ? [218, 232, 234] as Color : COLORS.ink;
		this.rect(x, y - 52, width, 46, panel, true);
		const values: Array<[string, string]> = [
			['Workspace', workspaceName(this.workspaceRoot)],
			['Scan date', formatDate(this.model.generatedAt)],
			['Scan mode', this.pdfContext?.scanMode ?? 'Not supplied'],
		];
		const columnWidth = width / values.length;
		for (let index = 0; index < values.length; index++) {
			const [label, value] = values[index];
			const cellX = x + index * columnWidth + 10;
			this.text(label, cellX, y - 21, 7, onDark ? [174, 205, 208] : COLORS.muted, 'F2');
			this.text(wrap(value, 23)[0], cellX, y - 37, 8.5, textColor, 'F2');
		}
	}

	private renderNextActions(): void {
		const actions = this.model.remediationPlan.filter((item) => item.action.trim()).slice(0, 3);
		if (!actions.length) return;
		this.heading('Next recommended actions');
		for (const item of actions) this.bullet(`${item.severity}: ${item.action}`);
	}

	private renderFindingMetadata(finding: UnifiedFinding): void {
		const location = `${compactPath(finding.file)}:${finding.line}`;
		const locationLines = wrap(location, 62);
		const height = 28 + locationLines.length * 12;
		this.ensure(height, this.activeSection);
		this.rect(MARGIN, this.y - height + 5, CONTENT_WIDTH, height, COLORS.panel, true);
		this.text('Location', MARGIN + 10, this.y - 14, 8, COLORS.muted, 'F2');
		for (let index = 0; index < locationLines.length; index++) {
			this.text(locationLines[index], MARGIN + 92, this.y - 14 - index * 12, 8.5, COLORS.ink, 'F3');
		}
		if (isAbsolutePath(finding.file)) {
			this.document.addLink(this.page, MARGIN + 92, this.y - 18 - (locationLines.length - 1) * 12, CONTENT_WIDTH - 102, 11, fileUri(finding.file, finding.line));
		}
		const metadataY = this.y - 14 - locationLines.length * 12;
		this.text('Source', MARGIN + 10, metadataY, 8, COLORS.muted, 'F2');
		this.text(finding.sourceTool, MARGIN + 92, metadataY, 8.5, COLORS.ink, 'F2');
		this.text('Status', MARGIN + 270, metadataY, 8, COLORS.muted, 'F2');
		this.text(finding.status, MARGIN + 320, metadataY, 8.5, COLORS.ink, 'F2');
		if (finding.cvss !== undefined) {
			this.text('CVSS', MARGIN + 410, metadataY, 8, COLORS.muted, 'F2');
			this.text(String(finding.cvss), MARGIN + 450, metadataY, 8.5, COLORS.ink, 'F2');
		}
		this.y -= height + 9;
	}

	private renderOverviewColumns(): void {
		const sourceCounts = countValues(this.model.findings.map((finding) => String(finding.sourceTool)));
		const fileCounts = countValues(this.model.findings.map((finding) => compactPath(finding.file)));
		const left = sourceCounts.slice(0, 4);
		const right = fileCounts.slice(0, 4);
		const startY = this.y;
		this.text('By source', MARGIN, startY, 8.5, COLORS.muted, 'F2');
		for (let index = 0; index < left.length; index++) {
			const [label, count] = left[index];
			this.text(truncate(label, 25), MARGIN, startY - 16 - index * 14, 8.5, COLORS.ink);
			this.text(String(count), MARGIN + 150, startY - 16 - index * 14, 8.5, COLORS.ink, 'F2');
		}
		this.text('Most affected paths', MARGIN + 270, startY, 8.5, COLORS.muted, 'F2');
		for (let index = 0; index < right.length; index++) {
			const [label, count] = right[index];
			this.text(truncate(label, 34), MARGIN + 270, startY - 16 - index * 14, 8.5, COLORS.ink);
			this.text(String(count), PAGE_WIDTH - MARGIN - 16, startY - 16 - index * 14, 8.5, COLORS.ink, 'F2');
		}
		this.y -= 20 + Math.max(left.length, right.length) * 14;
	}

	private renderRelationshipMap(): void {
		const nodes = new Map((this.model.graph?.nodes ?? []).map((node) => [node.id, node]));
		const edges = (this.model.graph?.edges ?? []).slice(0, 12);
		if (!edges.length) {
			this.emptyState('No relationship edges were returned by the assessment.');
			return;
		}
		for (const edge of edges) {
			this.ensure(30, 'Correlation / Relationships');
			const source = nodes.get(edge.source)?.label ?? edge.source;
			const target = nodes.get(edge.target)?.label ?? edge.target;
			const rowY = this.y;
			this.rect(MARGIN, rowY - 16, 172, 22, COLORS.panel, true);
			this.rect(MARGIN + 298, rowY - 16, 172, 22, COLORS.panel, true);
			this.text(truncate(source, 28), MARGIN + 8, rowY - 8, 8, COLORS.ink, 'F2');
			this.text(truncate(target, 28), MARGIN + 306, rowY - 8, 8, COLORS.ink, 'F2');
			this.line(MARGIN + 178, rowY - 5, MARGIN + 292, rowY - 5, COLORS.brand, 1.2);
			this.line(MARGIN + 284, rowY - 9, MARGIN + 292, rowY - 5, COLORS.brand, 1.2);
			this.line(MARGIN + 284, rowY - 1, MARGIN + 292, rowY - 5, COLORS.brand, 1.2);
			this.text(edge.type, MARGIN + 190, rowY - 2, 7, COLORS.muted, 'F3');
			this.y -= 31;
		}
		if (this.model.graph && this.model.graph.edges.length > edges.length) {
			this.text(`+ ${this.model.graph.edges.length - edges.length} additional relationships in the report graph.`, MARGIN, this.y, 8.5, COLORS.muted);
			this.y -= 16;
		}
	}

	private renderAppendixColumns(): void {
		const sourceCount = new Set(this.model.findings.map((finding) => finding.sourceTool)).size;
		const fileCount = new Set(this.model.findings.map((finding) => finding.file)).size;
		const ruleCount = new Set(this.model.findings.map((finding) => finding.ruleId)).size;
		const rows: Array<[string, string]> = [
			['Findings', String(this.model.findings.length)],
			['Source tools', String(sourceCount)],
			['Affected paths', String(fileCount)],
			['Distinct rules', String(ruleCount)],
			['OWASP references', String(Object.keys(this.model.owasp ?? {}).length)],
			['CWE references', String(Object.keys(this.model.cwe ?? {}).length)],
			['Graph nodes', String(this.model.graph?.nodes?.length ?? 0)],
			['Graph edges', String(this.model.graph?.edges?.length ?? 0)],
		];
		for (let index = 0; index < rows.length; index++) {
			const column = index % 2;
			const row = Math.floor(index / 2);
			const x = MARGIN + column * 258;
			const y = this.y - row * 18;
			this.text(rows[index][0], x, y, 8.5, COLORS.muted, 'F2');
			this.text(rows[index][1], x + 142, y, 8.5, COLORS.ink, 'F2');
		}
		this.y -= Math.ceil(rows.length / 2) * 18 + 4;
	}

	private renderFindingIdentifierTable(): void {
		for (const finding of this.model.findings) {
			this.ensure(18, 'Appendix');
			this.text(finding.id, MARGIN, this.y, 8, COLORS.ink, 'F3');
			this.text(finding.severity, MARGIN + 190, this.y, 8, severityColor(finding.severity), 'F2');
			this.text(truncate(finding.ruleId, 32), MARGIN + 260, this.y, 8, COLORS.muted, 'F3');
			this.y -= 14;
		}
	}

	private emptyState(value: string): void {
		this.rect(MARGIN, this.y - 40, CONTENT_WIDTH, 38, COLORS.panel, true);
		this.text(value, MARGIN + 14, this.y - 24, 10, COLORS.muted);
		this.y -= 58;
	}

	private hasStatuses(): boolean {
		return this.model.findings.some((finding) => finding.status !== undefined);
	}

	private hasCorrelationData(): boolean {
		return Boolean(this.model.correlation && (this.model.correlation.deduplicated > 0 || this.model.correlation.boosted > 0 || this.model.correlation.attackPaths > 0)) || Boolean(this.model.graph?.nodes?.length || this.model.graph?.edges?.length);
	}

	private newPage(title: string): void {
		if (this.pageNumber > 0) {
			this.addFooter();
		}
		this.page = this.document.addPage();
		this.pageNumber += 1;
		this.activeSection = title;
		if (!this.sectionPages.has(title)) this.sectionPages.set(title, this.pageNumber);
		this.y = PAGE_HEIGHT - MARGIN;
		this.text('AQIRON SECURITY  |  SECURITY ASSESSMENT REPORT', MARGIN, this.y, 7.5, COLORS.muted, 'F2');
		this.line(MARGIN, this.y - 9, PAGE_WIDTH - MARGIN, this.y - 9, COLORS.line, 0.7);
		this.y -= 32;
		this.text(`${sectionNumber(title)}  ${title}`, MARGIN, this.y, 22, COLORS.ink, 'F2');
		this.y -= 30;
	}

	private addFooter(): void {
		this.line(MARGIN, 42, PAGE_WIDTH - MARGIN, 42, COLORS.line, 0.7);
		const reportId = this.pdfContext?.scanId ?? this.model.telemetry?.scanId;
		this.text(reportId ? `Aqiron Security  |  ${reportId}` : 'Aqiron Security', MARGIN, 28, 7.5, COLORS.muted, 'F2');
		this.text(`Page ${this.pageNumber}`, PAGE_WIDTH - MARGIN - 40, 28, 7.5, COLORS.muted);
	}

	private ensure(height: number, title = this.activeSection): void {
		if (this.y - height >= 52) return;
		this.newPage(title);
	}

	private text(value: string, x: number, y: number, size: number, color: Color, font = 'F1'): void {
		this.page.push(`${rgb(color)} rg BT /${font} ${size} Tf 1 0 0 1 ${round(x)} ${round(y)} Tm (${pdfEscape(value)}) Tj ET`);
	}

	private logo(x: number, y: number, size: number, color: Color): void {
		const scale = size / 24;
		this.page.push(`q ${round(scale)} 0 0 ${round(scale)} ${round(x)} ${round(y)} cm ${rgb(color)} rg 12 2.5 m 20 5.5 l 20 11.4 l 18.5 16 l 15.5 20 l 12 21.5 l 8.5 20 l 5.5 16 l 4 11.4 l 4 5.5 l 12 2.5 l h f`);
		this.page.push(`${rgb(COLORS.ink)} rg 12 5.2 m 17.5 7.25 l 17.5 11.45 l 16 15 l 12 18.65 l 8 15 l 6.5 11.45 l 6.5 7.25 l 12 5.2 l h f`);
		this.page.push(`${rgb(color)} rg 8.25 15.75 m 11.5 7.75 l 12.5 7.75 l 15.75 15.75 l 14.15 15.75 l 13.5 14.05 l 10.5 14.05 l 9.85 15.75 l h f`);
		this.page.push('Q');
	}

	private image(name: string, x: number, y: number, width: number, height: number): void {
		this.page.push(`q ${round(width)} 0 0 ${round(height)} ${round(x)} ${round(y)} cm /${name} Do Q`);
	}

	private icon(value: string, x: number, y: number): void {
		const color = value.toLowerCase().includes('finding') ? COLORS.critical : value.toLowerCase().includes('scanner') ? COLORS.low : value.toLowerCase().includes('remediation') ? COLORS.high : COLORS.brand;
		this.rect(x, y, 12, 12, color, true);
		this.line(x + 3, y + 6, x + 9, y + 6, [255, 255, 255], 1);
	}

	private rect(x: number, y: number, width: number, height: number, color: Color, fill: boolean): void {
		this.page.push(`${rgb(color)} ${fill ? 'rg' : 'RG'} ${round(x)} ${round(y)} ${round(width)} ${round(height)} re ${fill ? 'f' : 'S'}`);
	}

	private line(x1: number, y1: number, x2: number, y2: number, color: Color, width: number): void {
		this.page.push(`${rgb(color)} RG ${round(width)} w ${round(x1)} ${round(y1)} m ${round(x2)} ${round(y2)} l S`);
	}

	private badge(value: string, x: number, y: number, color: Color): void {
		this.rect(x, y - 5, 78, 16, color, true);
		this.text(value, x + 7, y + 1, 7, [255, 255, 255], 'F2');
	}
}

function wrap(value: string, maxChars: number): string[] {
	const words = String(value || '').replace(/\s+/g, ' ').trim().split(' ').filter(Boolean);
	if (!words.length) return [''];
	const lines: string[] = [];
	let current = '';
	for (const word of words) {
		if (word.length > maxChars) {
			if (current) lines.push(current);
			for (let index = 0; index < word.length; index += maxChars) lines.push(word.slice(index, index + maxChars));
			current = '';
			continue;
		}
		const candidate = current ? `${current} ${word}` : word;
		if (candidate.length > maxChars) {
			lines.push(current);
			current = word;
		} else {
			current = candidate;
		}
	}
	if (current) lines.push(current);
	return lines;
}

function pdfEscape(value: string): string {
	return ascii(String(value)).replace(/[()\\]/g, '\\$&');
}

function ascii(value: string): string {
	return value.replace(/[^\x20-\x7E]/g, '?');
}

function rgb(color: Color): string {
	return `${(color[0] / 255).toFixed(3)} ${(color[1] / 255).toFixed(3)} ${(color[2] / 255).toFixed(3)}`;
}

function round(value: number): string {
	return value.toFixed(2).replace(/\.00$/, '');
}

function severityColor(severity: string): Color {
	return severity === 'Critical' ? COLORS.critical : severity === 'High' ? COLORS.high : severity === 'Medium' ? COLORS.medium : COLORS.low;
}

function workspaceName(root: string): string {
	const normalized = root.replace(/[\\/]+$/, '');
	return normalized.split(/[\\/]/).pop() || 'Workspace assessment';
}

function sectionNumber(title: string): string {
	const numbers: Record<string, string> = {
		'Executive Summary': '01',
		'Security Overview': '02',
		'Key Findings': '03',
		'Detailed Findings': '04',
		'Correlation / Relationships': '05',
		'Scanner / Coverage Summary': '06',
		'Remediation Summary': '07',
		'Appendix': '08',
		Contents: '00',
	};
	return numbers[title] ?? '';
}

function compactPath(file: string): string {
	return file.replace(/^[A-Za-z]:[\\/]/, '').replace(/\\/g, '/');
}

function isAbsolutePath(file: string): boolean {
	return /^[A-Za-z]:[\\/]/.test(file) || file.startsWith('/');
}

function fileUri(file: string, line: number): string {
	const normalized = file.replace(/\\/g, '/');
	const uri = normalized.startsWith('/') ? `file://${normalized}` : `file:///${normalized}`;
	return `${encodeURI(uri)}#L${Math.max(1, line)}`;
}

function formatDate(value: string): string {
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? value : date.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
}

function statusCounts(findings: readonly UnifiedFinding[]): Array<[string, number]> {
	const counts = new Map<string, number>();
	for (const finding of findings) counts.set(finding.status, (counts.get(finding.status) ?? 0) + 1);
	return [...counts.entries()];
}

function countValues(values: readonly string[]): Array<[string, number]> {
	const counts = new Map<string, number>();
	for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
	return [...counts.entries()].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
}

function truncate(value: string, maxChars: number): string {
	return value.length > maxChars ? `${value.slice(0, Math.max(1, maxChars - 3))}...` : value;
}

function formatEvidence(evidence: unknown): string {
	if (evidence === undefined || evidence === null) return '';
	const safe = redactEvidence(evidence);
	const value = typeof safe === 'string' ? safe : JSON.stringify(safe);
	return value.length > 2400 ? `${value.slice(0, 2400)} ...` : value;
}

function loadReportLogo(workspaceRoot: string): Buffer | undefined {
	const candidates = [
		path.join(workspaceRoot, 'assets', 'logos', 'aqiron-security-logo-pdf.jpg'),
		path.resolve(__dirname, '..', '..', '..', '..', 'assets', 'logos', 'aqiron-security-logo-pdf.jpg'),
		path.resolve(__dirname, '..', 'assets', 'logos', 'aqiron-security-logo-pdf.jpg'),
		path.resolve(process.cwd(), 'assets', 'logos', 'aqiron-security-logo-pdf.jpg'),
	];
	for (const candidate of candidates) {
		try {
			if (fs.existsSync(candidate)) return fs.readFileSync(candidate);
		} catch {
			// A report must remain usable if the optional packaged branding asset is unavailable.
		}
	}
	return undefined;
}

function redactEvidence(value: unknown, key = ''): unknown {
	if (/(secret|token|password|credential|private.?key|api.?key|match)/i.test(key)) return '[REDACTED]';
	if (Array.isArray(value)) return value.map((item) => redactEvidence(item));
	if (typeof value === 'object' && value !== null) {
		return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [childKey, redactEvidence(childValue, childKey)]));
	}
	if (typeof value === 'string' && /(sk-[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_-]{20,}|ghp_[A-Za-z0-9]{20,})/.test(value)) return '[REDACTED]';
	return value;
}

function scanStatus(telemetry: SecurityReportModel['telemetry']): { label: string; detail: string; color: Color } {
	if (!telemetry) return { label: 'UNKNOWN', detail: 'Scan telemetry was not supplied with this report.', color: COLORS.medium };
	if (telemetry.cancelled) return { label: 'CANCELLED', detail: 'The scan was cancelled before completion.', color: COLORS.medium };
	if (telemetry.failures > 0 || telemetry.timeouts > 0) return { label: 'REVIEW', detail: `${telemetry.failures} scanner failure${telemetry.failures === 1 ? '' : 's'} and ${telemetry.timeouts} timeout${telemetry.timeouts === 1 ? '' : 's'} were recorded.`, color: COLORS.high };
	return { label: 'COMPLETED', detail: 'The scan completed with the available telemetry.', color: COLORS.low };
}

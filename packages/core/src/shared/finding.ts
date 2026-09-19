import * as path from 'path';
import { createSourceLocation } from './sourceSpan';
import { AqironConfidence, AqironFindingGraphMetadata, AqironIssue, AqironSeverity, AqironSourceTool } from './issue';

export interface UnifiedFinding {
	id: string;
	title: string;
	description: string;
	severity: AqironSeverity;
	cwe: string[];
	owasp: string[];
	cvss?: number;
	file: string;
	line: number;
	column: number;
	endLine?: number;
	endColumn?: number;
	sourceTool: AqironSourceTool;
	ruleId: string;
	confidence: AqironConfidence;
	remediation: string;
	tags: string[];
	rawEvidence: unknown;
	graph: AqironFindingGraphMetadata;
	fingerprint: string;
	status: 'Open' | 'Triaged' | 'Ignored' | 'Fixed';
	riskScore: number;
}

export interface FindingLocation {
	file?: string;
	line?: number;
	column?: number;
	endLine?: number;
	endColumn?: number;
}

export function createFinding(input: Omit<UnifiedFinding, 'id' | 'fingerprint' | 'status' | 'riskScore' | 'graph'> & {
	graph?: Partial<AqironFindingGraphMetadata>;
	fingerprint?: string;
	status?: UnifiedFinding['status'];
	riskScore?: number;
}): UnifiedFinding {
	const fingerprint = input.fingerprint ?? createFingerprint(input.sourceTool, input.ruleId, input.file, input.line, input.title);
	return {
		...input,
		id: `${input.sourceTool.toLowerCase()}:${fingerprint}`,
		fingerprint,
		status: input.status ?? 'Open',
		riskScore: input.riskScore ?? calculateRiskScore(input.severity, input.confidence, input.cvss),
		graph: {
			nodeId: `finding:${fingerprint}`,
			nodeType: inferGraphNodeType(input.tags),
			edges: [{ targetId: `file:${normalizePath(input.file)}`, type: 'evidence-of' }],
			...input.graph,
		},
	};
}

export function findingToIssue(finding: UnifiedFinding, lineText = ''): AqironIssue {
	const startLine = Math.max(0, finding.line - 1);
	const startColumn = Math.max(0, finding.column - 1);
	const endLine = Math.max(startLine, (finding.endLine ?? finding.line) - 1);
	const endColumn = Math.max(startColumn + 1, (finding.endColumn ?? finding.column + 1) - 1);
	return {
		id: finding.id,
		file: finding.file,
		title: finding.title,
		message: finding.description,
		severity: finding.severity,
		ruleId: finding.ruleId,
		range: createSourceLocation(finding.file, startLine, startColumn, endLine, endColumn),
		lineText,
		sourceTool: finding.sourceTool,
		confidence: finding.confidence,
		cwe: finding.cwe,
		owasp: finding.owasp,
		cvss: finding.cvss,
		remediation: finding.remediation,
		tags: finding.tags,
		rawEvidence: finding.rawEvidence,
		graph: finding.graph,
		fingerprint: finding.fingerprint,
		status: finding.status,
		riskScore: finding.riskScore,
	};
}

export function issueToFinding(issue: AqironIssue): UnifiedFinding {
	return createFinding({
		title: issue.title,
		description: issue.message,
		severity: issue.severity,
		cwe: issue.cwe ?? [],
		owasp: issue.owasp ?? [],
		cvss: issue.cvss,
		file: issue.file,
		line: issue.range.startLine + 1,
		column: issue.range.startColumn + 1,
		sourceTool: issue.sourceTool ?? 'Aqiron',
		ruleId: issue.ruleId,
		confidence: issue.confidence ?? 'Medium',
		remediation: issue.remediation ?? defaultRemediation(issue.ruleId),
		tags: issue.tags ?? ['aqiron-native'],
		rawEvidence: issue.rawEvidence ?? { lineText: issue.lineText },
		graph: issue.graph,
		fingerprint: issue.fingerprint,
		status: issue.status,
		riskScore: issue.riskScore,
	});
}

export function normalizeSeverity(value: unknown): AqironSeverity {
	const normalized = String(value ?? '').toLowerCase();
	if (normalized === 'critical') {
		return 'Critical';
	}
	if (normalized === 'high') {
		return 'High';
	}
	if (normalized === 'medium' || normalized === 'moderate') {
		return 'Medium';
	}
	return 'Low';
}

export function calculateRiskScore(severity: AqironSeverity, confidence: AqironConfidence, cvss?: number): number {
	const severityBase = { Critical: 95, High: 80, Medium: 55, Low: 25 }[severity];
	const confidenceDelta = { High: 5, Medium: 0, Low: -10 }[confidence];
	const cvssDelta = cvss === undefined ? 0 : Math.round((cvss - 5) * 3);
	return Math.max(1, Math.min(100, severityBase + confidenceDelta + cvssDelta));
}

export function createFingerprint(sourceTool: string, ruleId: string, file: string, line: number, title: string): string {
	return Buffer.from([sourceTool, ruleId, normalizePath(file), String(line), title].join('|')).toString('base64url').slice(0, 24);
}

export function normalizePath(file: string): string {
	return file.split(path.sep).join('/');
}

function inferGraphNodeType(tags: readonly string[]): AqironFindingGraphMetadata['nodeType'] {
	if (tags.includes('secret')) {
		return 'secret';
	}
	if (tags.includes('malware')) {
		return 'malware-indicator';
	}
	if (tags.includes('dependency') || tags.includes('container')) {
		return 'dependency';
	}
	return 'vulnerability';
}

function defaultRemediation(ruleId: string): string {
	if (ruleId.includes('secret')) {
		return 'Rotate the exposed credential and move the value into a managed secret store.';
	}
	if (ruleId.includes('dependency') || ruleId.includes('cve')) {
		return 'Upgrade the affected package or apply the vendor-recommended mitigation.';
	}
	return 'Review the finding, validate exploitability, and apply the safest code or configuration fix.';
}

import { SourceLocation } from './sourceSpan';

export type AqironSeverity = 'Critical' | 'High' | 'Medium' | 'Low';

export type AqironRuleId =
	| 'critical.api-key'
	| 'critical.secret'
	| 'critical.token'
	| 'critical.private-key'
	| 'critical.password'
	| 'high.eval'
	| 'high.shell-execution'
	| 'high.subprocess'
	| 'high.sql-injection'
	| 'high.unsafe-deserialization'
	| 'high.unsafe-c-api'
	| 'medium.todo'
	| 'medium.console-log'
	| 'medium.print'
	| 'medium.debug'
	| 'medium.insecure-http'
	| 'low.unused-variable'
	| 'low.empty-catch'
	| 'low.long-function';

export type AqironSourceTool = 'Aqiron' | 'Trivy' | 'Semgrep' | 'Betterleaks' | 'OSV-Scanner' | 'MobSF' | 'AI Analysis' | 'Correlation';
export type AqironConfidence = 'Low' | 'Medium' | 'High';

export interface AqironFindingGraphMetadata {
	nodeId: string;
	nodeType: 'api' | 'auth' | 'dependency' | 'secret' | 'vulnerability' | 'file' | 'mobile-artifact' | 'malware-indicator';
	edges: Array<{
		targetId: string;
		type: 'imports' | 'api-calls' | 'auth-relationship' | 'vulnerable-dependency-usage' | 'data-flow' | 'evidence-of' | 'correlates-with';
	}>;
}

export interface AqironIssue {
	id: string;
	file: string;
	title: string;
	message: string;
	severity: AqironSeverity;
	ruleId: AqironRuleId | string;
	range: SourceLocation;
	lineText: string;
	sourceTool?: AqironSourceTool;
	confidence?: AqironConfidence;
	cwe?: string[];
	owasp?: string[];
	cvss?: number;
	remediation?: string;
	tags?: string[];
	rawEvidence?: unknown;
	graph?: AqironFindingGraphMetadata;
	fingerprint?: string;
	status?: 'Open' | 'Triaged' | 'Ignored' | 'Fixed';
	riskScore?: number;
}

export interface AqironScanResult {
	scanId?: string;
	workspaceRoot?: string;
	target: string;
	filesScanned: number;
	coverageDiagnosticsAvailable?: boolean;
	coverageDiagnosticsPresent?: boolean;
	coverageDiagnosticsValid?: boolean;
	coverageStatus?: 'complete' | 'partial' | 'unavailable';
	skippedFiles?: number;
	skippedFilesIsLowerBound?: boolean;
	skippedFilesCountCertainty?: 'exact' | 'lower-bound' | 'indeterminate';
	skipCountConflict?: boolean;
	skipReasonsTruncated?: boolean;
	skipReasons?: Partial<Record<string, number>>;
	issues: AqironIssue[];
	durationMs: number;
}

export interface AqironWorkspaceStats {
	filesScanned: number;
	indexedFiles: number;
	coverageDiagnosticsAvailable?: boolean;
	coverageDiagnosticsPresent?: boolean;
	coverageDiagnosticsValid?: boolean;
	coverageStatus?: 'complete' | 'partial' | 'unavailable';
	skippedFiles?: number;
	skippedFilesIsLowerBound?: boolean;
	skippedFilesCountCertainty?: 'exact' | 'lower-bound' | 'indeterminate';
	skipCountConflict?: boolean;
	skipReasonsTruncated?: boolean;
	skipReasons?: Partial<Record<string, number>>;
	scanStatus: 'Idle' | 'Scanning' | 'Complete' | 'Failed';
	lastScanDurationMs: number;
}

export interface AqironSeverityCounts {
	total: number;
	critical: number;
	high: number;
	medium: number;
	low: number;
	filesAffected: number;
}

export const severityOrder: AqironSeverity[] = ['Critical', 'High', 'Medium', 'Low'];

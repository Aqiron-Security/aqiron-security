export interface SecurityProjectProfile {
	languages: string[];
	frameworks: string[];
	platforms: string[];
	services: string[];
	authentication: string[];
	databases: string[];
	storage: string[];
	dependencyManagers: string[];
	nativeCode: string[];
	ciCd: string[];
	sensitiveFiles: string[];
}

export interface SecurityContextFile {
	path: string;
	reason: string;
	language?: string;
	excerpt: string;
}

export interface SecurityDeterministicFindingSummary {
	title: string;
	description: string;
	severity: string;
	sourceTool: string;
	ruleId: string;
	file: string;
	line: number;
	tags: string[];
	remediation?: string;
}

export interface SecurityRagEvidence {
	query: string;
	file: string;
	startLine: number;
	endLine: number;
	score: number;
	excerpt: string;
	signalIds: string[];
}

export interface SecurityAnalysisContext {
	workspaceName: string;
	workspaceRoot?: string;
	projectTypes: string[];
	profile: SecurityProjectProfile;
	analysisGoals: string[];
	retrievalQueries: string[];
	candidateFiles: SecurityContextFile[];
	deterministicFindings: SecurityDeterministicFindingSummary[];
	ragEvidence: SecurityRagEvidence[];
}

export type AiAnalysisConfidence = 'Confirmed' | 'High confidence' | 'Medium confidence' | 'Low confidence' | 'Needs verification';

export interface AiAnalysisFindingDraft {
	title: string;
	description: string;
	severity: 'Critical' | 'High' | 'Medium' | 'Low';
	confidence: AiAnalysisConfidence;
	cwe?: string[];
	owasp?: string[];
	file?: string;
	line?: number;
	column?: number;
	endLine?: number;
	endColumn?: number;
	evidence?: string;
	reasoning?: string;
	remediation?: string;
	category?: string;
	ruleId?: string;
	tags?: string[];
	projectLevel?: boolean;
	sources?: Array<{
		type: 'scanner' | 'rag' | 'code' | 'config';
		label: string;
		file?: string;
		line?: number;
		excerpt?: string;
	}>;
}

export interface AiAnalysisResponse {
	summary?: string;
	findings?: AiAnalysisFindingDraft[];
}

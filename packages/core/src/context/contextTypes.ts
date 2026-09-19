import { SecurityAnalysisContext, SecurityContextFile, SecurityDeterministicFindingSummary, SecurityRagEvidence, SecurityProjectProfile } from '../shared/analysis';
import { ProjectProfile } from '../project/projectProfile';
import { RagRetrievalResult } from '../rag/ragRetrievalService';

export type { SecurityAnalysisContext, SecurityContextFile, SecurityDeterministicFindingSummary, SecurityRagEvidence, SecurityProjectProfile };

export interface SecurityContext extends SecurityAnalysisContext {
	projectProfile: ProjectProfile;
	projectTypes: string[];
	securitySignals: string[];
	retrievedKnowledge: RagRetrievalResult[];
}

export interface SecurityContextBuilderOptions {
	filesystem: import('../shared/platform').FileSystem;
	isExcludedPath?: (file: string, root: string) => boolean;
	maxFileSizeBytes?: number;
}

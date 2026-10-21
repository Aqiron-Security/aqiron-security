import { ProjectProfile } from '../project/projectProfile';
import { UnifiedFinding } from '../shared/finding';
import { CorrelatedRelationship } from '../correlation/correlationEngine';

export type HypothesisStatus = 'proposed' | 'investigating' | 'validated' | 'rejected' | 'dismissed' | 'stale' | 'unsubstantiated';
export type HypothesisConfidenceBand = 'low' | 'moderate' | 'high';
export type HypothesisEvidenceKind = 'finding' | 'relationship' | 'source-span';

/** Source coordinates are one-based inclusive, matching UnifiedFinding. */
export interface HypothesisEvidenceRef {
	id: string;
	kind: HypothesisEvidenceKind;
	source: string;
	file?: string;
	startLine?: number;
	endLine?: number;
	contentHash?: string;
	fileContentHash?: string;
	findingId?: string;
	ruleId?: string;
	relationshipId?: string;
	observedAt: string;
	freshness: 'current' | 'stale';
}

export type ConfidenceFactor =
	| { kind: 'direct-evidence'; value: 'verified-source-span' | 'scanner-finding'; detail: string }
	| { kind: 'corroboration'; value: 'single-source-family' | 'multiple-source-families'; detail: string }
	| { kind: 'relationship'; value: 'heuristic' | 'explicit'; detail: string }
	| { kind: 'freshness'; value: 'current' | 'stale'; detail: string }
	| { kind: 'contradiction'; value: 'present' | 'none-observed'; detail: string }
	| { kind: 'preconditions'; value: 'known' | 'unknown'; detail: string };

export interface SecurityHypothesis {
	id: string;
	title: string;
	description: string;
	weakness?: string;
	attackPath?: string;
	asset: { kind: 'file' | 'dependency' | 'service' | 'project'; id: string; label?: string };
	evidence: HypothesisEvidenceRef[];
	rationale: string;
	confidence: { band: HypothesisConfidenceBand; factors: ConfidenceFactor[]; policyVersion: 1 };
	assumptions: string[];
	contradictions: HypothesisEvidenceRef[];
	impact?: string;
	verificationSteps: string[];
	status: HypothesisStatus;
	/** Current evidence state. A validated status records reviewer history and can coexist with stale evidence. */
	evidenceFreshness?: 'current' | 'stale' | 'provenance-unavailable';
	createdAt: string;
	updatedAt: string;
	snapshotId: string;
	relatedFindingIds: string[];
	relatedRuleIds: string[];
	relatedHypothesisIds: string[];
	review?: { at: string; action: 'investigate' | 'validate' | 'reject' | 'dismiss' | 'reopen'; note?: string; evidenceRefs?: string[] };
}

export interface HypothesisSnapshot {
	id: string;
	workspaceRoot: string;
	scanId: string;
	capturedAt: string;
	fingerprint: string;
	profile: ProjectProfile;
	evidence: HypothesisEvidenceRef[];
	findings: UnifiedFinding[];
	relationships: CorrelatedRelationship[];
	excludedUnprovenancedFindings?: number;
}

export type HypothesisDiagnosticCode = 'no-evidence' | 'invalid-evidence' | 'candidate-rejected' | 'candidate-deduplicated' | 'no-supported-rule';
export interface HypothesisGenerationDiagnostics {
	code: HypothesisDiagnosticCode;
	count: number;
	message: string;
}
export interface HypothesisGenerationResult {
	status: 'generated' | 'no-evidence';
	scanId: string;
	snapshotId?: string;
	hypotheses: SecurityHypothesis[];
	diagnostics: HypothesisGenerationDiagnostics[];
}

export type HypothesisTriageAction = 'investigate' | 'validate' | 'reject' | 'dismiss' | 'reopen';
export interface HypothesisReviewInput {
	workspaceRoot: string;
	hypothesisId: string;
	action: HypothesisTriageAction;
	note?: string;
	evidenceRefs?: string[];
}

export interface HypothesisReviewResult {
	hypothesis: SecurityHypothesis;
	applied: boolean;
	diagnostic?: 'stale-evidence' | 'provenance-unavailable';
}

export interface HypothesisStore {
	version: 1;
	scoringPolicyVersion: 1;
	/** Monotonic committed store generation; absent legacy v1 stores are generation zero. */
	generation?: number;
	updatedAt: string;
	hypotheses: SecurityHypothesis[];
	snapshots: Array<Pick<HypothesisSnapshot, 'id' | 'scanId' | 'capturedAt' | 'fingerprint'>>;
}

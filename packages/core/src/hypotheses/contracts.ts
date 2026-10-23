import { ProjectProfile } from '../project/projectProfile';
import { UnifiedFinding } from '../shared/finding';
import { CorrelatedRelationship } from '../correlation/correlationEngine';
import { AIProviderId } from '../shared/ai';

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

/**
 * Versioned untrusted provider response shape. Aliases are request-local Core values,
 * never persisted evidence identifiers or caller-selected paths/locations.
 */
export interface HypothesisAiResponseV1 {
	schemaVersion: 1;
	proposals: HypothesisAiProposalV1[];
}

export interface HypothesisAiProposalV1 {
	title: string;
	claim: string;
	evidenceRationale: string;
	supportingEvidenceAliases: string[];
	contradictoryEvidenceAliases: string[];
	verificationCriteria: string[];
	falsificationCriteria: string[];
	uncertainties: string[];
}

/** Opaque handle issued by Core for one proposal-synthesis request. */
export interface HypothesisAiRequestContext {
	/** Opaque local correlation value. It is never requested from or trusted in model output. */
	readonly correlationToken: string;
}

/** Private Core commit handshake; cancellation is honored until beginCommit wins. */
export interface HypothesisAiCommitControl {
	beginCommit(): boolean;
	markCommitted(): void;
}

/** Normalized result after every alias has been resolved to verified Core evidence. */
export interface ValidatedHypothesisAiProposal {
	title: string;
	claim: string;
	evidenceRationale: string;
	supportingEvidence: HypothesisEvidenceRef[];
	contradictoryEvidence: HypothesisEvidenceRef[];
	verificationCriteria: string[];
	falsificationCriteria: string[];
	uncertainties: string[];
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
	/** Optional provenance marker; absent on legacy deterministic records. */
	origin?: { kind: 'ai-proposal'; preparationId: string; providerId: AIProviderId; modelId: string };
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
	/** Evidence IDs whose scanner-recorded source hashes were verified to have changed. */
	staleEvidenceIds?: string[];
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

/** Bounded, operation-local request for a disclosure preview. It does not authorize execution. */
export interface HypothesisAiPrepareRequest {
	workspaceRoot: string;
	scanId: string;
	providerId: AIProviderId;
	modelId: string;
	/** Exact Core-issued evidence IDs selected from the current scan snapshot. */
	evidenceIds: string[];
	/** Defaults to false. Excerpts are disclosed only in the returned local preview. */
	includeSourceExcerpts?: boolean;
}

export type HypothesisAiDisclosureCategory = 'finding-summary' | 'relationship-summary' | 'source-excerpt';

export interface HypothesisAiPreparedEvidencePreview {
	alias: string;
	evidenceId: string;
	kind: HypothesisEvidenceKind;
	summary: string;
	/** Display-only local evidence location; omitted from proposedContent sent to a future provider. */
	sourcePath?: string;
	startLine?: number;
	endLine?: number;
	/** Exact bounded source-span text proposed for disclosure when explicitly opted in. */
	excerptText?: string;
	excerptUtf8Bytes?: number;
}

export interface HypothesisAiProposedContent {
	purpose: string;
	instructions: string;
	evidence: Array<{
		alias: string;
		kind: HypothesisEvidenceKind;
		summary: string;
		excerpt?: string;
	}>;
}

export interface HypothesisAiPreparedDisclosureManifest {
	preparationId: string;
	expiresAt: string;
	workspaceIdentity: string;
	scanId: string;
	snapshotId: string;
	snapshotFingerprint: string;
	provider: {
		id: AIProviderId;
		modelId: string;
		external: true;
		endpoint: string;
		endpointClassification: 'known' | 'unknown';
		credential: { identity: string; name: string; last4: string; updatedAt: string };
		configurationFingerprint: string;
		capabilityPolicyVersion?: string;
		responseMode?: 'openai-json-object' | 'openrouter-required-json-object' | 'anthropic-json-schema' | 'gemini-json-mime';
		requestOptions: { temperature: 0; maxTokens: 2048; timeoutMs: number; retries: 0; streaming: false; maxRequestBodyBytes: number; maxResponseBodyBytes: number };
		retentionPolicy: 'unknown';
	};
	dataCategories: HypothesisAiDisclosureCategory[];
	evidenceCount: number;
	findingCount: number;
	relationshipCount: number;
	excerptCount: number;
	includeSourceExcerpts: boolean;
	evidence: HypothesisAiPreparedEvidencePreview[];
	/** Exact bounded Core-side content object proposed for a future invocation. */
	proposedContent: HypothesisAiProposedContent;
	proposedContentUtf8Bytes: number;
	coreEnvelopeUtf8Bytes: number;
	previewUtf8Bytes: number;
	previewOnly: true;
	executionAvailable: false;
	providerCallMade: false;
	disclosure: string;
}

export type HypothesisAiPreparationDiagnosticCode = 'scan-unavailable' | 'evidence-unavailable' | 'evidence-stale' | 'excerpt-unavailable' | 'limits-exceeded' | 'registry-full' | 'busy' | 'provider-configuration-unavailable' | 'provider-capability-unsupported';
export type HypothesisAiPrepareResult =
	| { status: 'prepared'; manifest: HypothesisAiPreparedDisclosureManifest; contentFingerprint: string }
	| { status: 'rejected'; scanId: string; diagnostic: { code: HypothesisAiPreparationDiagnosticCode; message: string } };

/** Hard bounds for the preview-only preparation path. */
export const HYPOTHESIS_AI_PREPARATION_LIMITS = Object.freeze({
	maxWorkspaceRootChars: 4096,
	maxScanIdChars: 128,
	maxProviderIdChars: 32,
	maxModelIdChars: 128,
	maxEvidenceSelectors: 40,
	maxEvidenceIdChars: 256,
	maxEvidencePathChars: 512,
	maxSerializedPrepareRequestBytes: 16384,
	maxExcerptBytes: 2048,
	maxAggregateExcerptBytes: 8192,
	maxContentEnvelopeBytes: 16384,
	maxSerializedPreviewBytes: 32768,
	maxLivePreparations: 16,
	maxRegistryBytes: 1_048_576,
	preparationLifetimeMs: 300_000,
	maxSourceFileBytes: 10_000_000,
	maxAggregateSourceBytes: 50_000_000,
});

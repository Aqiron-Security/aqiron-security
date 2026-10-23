import * as crypto from 'node:crypto';
import {
	HypothesisAiProposalV1,
	HypothesisAiRequestContext,
	HypothesisEvidenceRef,
	HypothesisSnapshot,
	HypothesisAiCommitControl,
	ValidatedHypothesisAiProposal,
} from './contracts';
import { validateEvidenceReference } from './hypothesisEngine';
import { HypothesisStoreService } from './hypothesisStore';
import { AIProviderId } from '../shared/ai';

export const HYPOTHESIS_AI_RESPONSE_LIMITS = Object.freeze({
	maxResponseBytes: 16_384,
	maxValidatedProposalBytes: 12_288,
	maxProposals: 5,
	maxEvidenceAliases: 40,
	maxEvidencePerProposal: 8,
	maxTitleLength: 160,
	maxClaimLength: 500,
	maxRationaleLength: 1_200,
	maxCriteriaCount: 5,
	maxCriterionLength: 300,
	maxUncertaintyCount: 5,
	maxUncertaintyLength: 240,
});

export type HypothesisAiValidationError =
	| 'empty-response'
	| 'response-too-large'
	| 'malformed-response'
	| 'unsupported-schema-version'
	| 'invalid-shape'
	| 'unknown-field'
	| 'invalid-alias'
	| 'invalid-context'
	| 'invalid-correlation'
	| 'invalid-content'
	| 'response-empty-or-reasoning-only';

export type HypothesisAiValidationResult =
	| { valid: true; proposals: ValidatedHypothesisAiProposal[] }
	| { valid: false; error: HypothesisAiValidationError };

interface RequestState {
	snapshot: HypothesisSnapshot;
	aliases: ReadonlyMap<string, HypothesisEvidenceRef>;
	providerId: AIProviderId;
	preparationId?: string;
	expiresAt?: string;
}

// Context authenticity and aliases are held only here. A structurally compatible
// object or caller-created Map cannot manufacture an issued request context.
const requestStates = new WeakMap<object, RequestState>();
const validatedStates = new WeakMap<object, { state: RequestState; proposals: ValidatedHypothesisAiProposal[] }>();

/** Issues a fresh request context with aliases for verified current snapshot evidence. */
export function createHypothesisAiRequestContext(snapshot: HypothesisSnapshot, evidence?: readonly HypothesisEvidenceRef[], binding: { providerId?: AIProviderId; preparationId?: string; expiresAt?: string } = {}): HypothesisAiRequestContext {
	if (!snapshot || !Array.isArray(snapshot.evidence)) {
		throw new TypeError('Hypothesis synthesis requires a Core evidence snapshot.');
	}
	const references = evidence ?? snapshot.evidence;
	if (!Array.isArray(references)) {
		throw new TypeError('Hypothesis synthesis requires a Core evidence snapshot.');
	}
	if (references.length > HYPOTHESIS_AI_RESPONSE_LIMITS.maxEvidenceAliases) {
		throw new RangeError('Hypothesis synthesis evidence exceeds the alias limit.');
	}
	const sorted = [...references].sort((left, right) => left?.id?.localeCompare?.(right.id) ?? 0);
	const ids = new Set<string>();
	const aliases = new Map<string, HypothesisEvidenceRef>();
	for (const ref of sorted) {
		if (!ref || typeof ref.id !== 'string' || !ref.id || ids.has(ref.id) || ref.freshness !== 'current' || !validateEvidenceReference(snapshot, ref)) {
			throw new TypeError('Hypothesis synthesis aliases require unique, current references verified by the Core snapshot.');
		}
		ids.add(ref.id);
		const canonical = snapshot.evidence.find((candidate) => candidate.id === ref.id && candidate.kind === ref.kind);
		if (!canonical) {
			throw new TypeError('Hypothesis synthesis evidence is not present in the Core snapshot.');
		}
		aliases.set(`e${aliases.size + 1}`, Object.freeze({ ...canonical }));
	}
	const correlationToken = crypto.randomBytes(32).toString('hex');
	const context = Object.freeze({ correlationToken });
	requestStates.set(context, { snapshot, aliases, providerId: binding.providerId ?? 'openai', preparationId: binding.preparationId, expiresAt: binding.expiresAt });
	return context;
}

/** Provider and preparation associations stay in Core memory and never enter model JSON. */
export function hypothesisAiRequestContextProvider(context: HypothesisAiRequestContext): AIProviderId | undefined {
	return isRequestContext(context) ? requestStates.get(context)!.providerId : undefined;
}

/**
 * Parses, strictly validates, and maps untrusted JSON into verified Core evidence.
 * Invalid response content is returned only as a stable diagnostic code; raw
 * provider payloads and excerpts are never included in errors or diagnostics.
 */
export function validateHypothesisAiResponse(raw: unknown, context: HypothesisAiRequestContext): HypothesisAiValidationResult {
	if (!isRequestContext(context)) {return { valid: false, error: 'invalid-context' };}
	if (typeof raw !== 'string' || raw.trim().length === 0) {return { valid: false, error: 'empty-response' };}
	if (Buffer.byteLength(raw, 'utf8') > HYPOTHESIS_AI_RESPONSE_LIMITS.maxResponseBytes) {return { valid: false, error: 'response-too-large' };}
	let parsed: unknown;
	try { parsed = JSON.parse(raw) as unknown; }
	catch { return { valid: false, error: 'malformed-response' }; }
	if (!isRecord(parsed)) {return { valid: false, error: 'invalid-shape' };}
	if (parsed.schemaVersion !== 1) {return { valid: false, error: 'unsupported-schema-version' };}
	if (hasUnknownKeys(parsed, ['schemaVersion', 'proposals'])) {return { valid: false, error: 'unknown-field' };}
	if (!Array.isArray(parsed.proposals)) {return { valid: false, error: 'invalid-shape' };}
	if (parsed.proposals.length === 0) {return { valid: false, error: 'response-empty-or-reasoning-only' };}
	if (parsed.proposals.length > HYPOTHESIS_AI_RESPONSE_LIMITS.maxProposals) {return { valid: false, error: 'invalid-content' };}
	const state = requestStates.get(context)!;
	const proposals: ValidatedHypothesisAiProposal[] = [];
	const proposalFingerprints = new Set<string>();
	for (const candidate of parsed.proposals) {
		if (!isRecord(candidate)) {return { valid: false, error: 'invalid-shape' };}
		if (hasUnknownKeys(candidate, proposalKeys)) {return { valid: false, error: 'unknown-field' };}
		const normalized = normalizeProposal(candidate as unknown as HypothesisAiProposalV1, state.aliases);
		if (!normalized) {return { valid: false, error: 'invalid-content' };}
		if (normalized === 'invalid-alias') {return { valid: false, error: 'invalid-alias' };}
		if (normalized === 'reasoning-only') {return { valid: false, error: 'response-empty-or-reasoning-only' };}
		const serialized = JSON.stringify(normalized);
		if (Buffer.byteLength(serialized, 'utf8') > HYPOTHESIS_AI_RESPONSE_LIMITS.maxValidatedProposalBytes) {return { valid: false, error: 'invalid-content' };}
		const fingerprint = crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');
		if (proposalFingerprints.has(fingerprint)) {return { valid: false, error: 'invalid-content' };}
		proposalFingerprints.add(fingerprint);
		proposals.push(normalized);
	}
	const result: HypothesisAiValidationResult = { valid: true, proposals };
	validatedStates.set(result, { state, proposals: cloneValidatedProposals(proposals) });
	return result;
}

/** Core-only parse, validate, then persist boundary. No store write occurs on any invalid response. */

export async function validateAndPersistHypothesisAiResponse(raw: unknown, context: HypothesisAiRequestContext, store: HypothesisStoreService, preparation: { id: string; providerId: AIProviderId; modelId: string }, signal?: AbortSignal, commitControl?: HypothesisAiCommitControl): Promise<HypothesisAiValidationResult> {
	throwIfCancelled(signal);
	const validation = validateHypothesisAiResponse(raw, context);
	if (!validation.valid) {return validation;}
	const persisted = await persistHypothesisAiValidationResult(validation, store, preparation, signal, commitControl);
	if (!persisted) {return { valid: false, error: 'invalid-correlation' };}
	return validation;
}

/** Persists the exact Core-validated result object and its retained, unmutated proposal copy. */
export async function persistHypothesisAiValidationResult(validation: HypothesisAiValidationResult, store: HypothesisStoreService, preparation: { id: string; providerId: AIProviderId; modelId: string }, signal?: AbortSignal, commitControl?: HypothesisAiCommitControl): Promise<boolean> {
	if (!validation?.valid) {return false;}
	const retained = validatedStates.get(validation as object);
	if (!retained) {return false;}
	if (!retained.state.preparationId || retained.state.preparationId !== preparation.id || !retained.state.expiresAt || !Number.isFinite(Date.parse(retained.state.expiresAt)) || Date.parse(retained.state.expiresAt) <= Date.now()) {return false;}
	throwIfCancelled(signal);
	await store.persistValidatedAiProposals(retained.state.snapshot.workspaceRoot, retained.state.snapshot, cloneValidatedProposals(retained.proposals), preparation.id, preparation.providerId, preparation.modelId, signal, commitControl);
	return true;
}

function cloneValidatedProposals(proposals: readonly ValidatedHypothesisAiProposal[]): ValidatedHypothesisAiProposal[] {
	return proposals.map(proposal => ({ ...proposal, supportingEvidence: proposal.supportingEvidence.map(ref => ({ ...ref })), contradictoryEvidence: proposal.contradictoryEvidence.map(ref => ({ ...ref })), verificationCriteria: [...proposal.verificationCriteria], falsificationCriteria: [...proposal.falsificationCriteria], uncertainties: [...proposal.uncertainties] }));
}

function throwIfCancelled(signal?: AbortSignal): void {if (signal?.aborted) {throw Object.assign(new Error('Core request cancelled.'), { code: 'CORE_REQUEST_CANCELLED' });}}

function isRequestContext(value: unknown): value is HypothesisAiRequestContext {
	return Boolean(value && typeof value === 'object' && requestStates.has(value));
}

const proposalKeys = [
	'title', 'claim', 'evidenceRationale', 'supportingEvidenceAliases', 'contradictoryEvidenceAliases',
	'verificationCriteria', 'falsificationCriteria', 'uncertainties',
] as const;

function normalizeProposal(value: HypothesisAiProposalV1, aliases: ReadonlyMap<string, HypothesisEvidenceRef>): ValidatedHypothesisAiProposal | 'invalid-alias' | 'reasoning-only' | undefined {
	const title = normalizeText(value.title, HYPOTHESIS_AI_RESPONSE_LIMITS.maxTitleLength);
	const claim = normalizeText(value.claim, HYPOTHESIS_AI_RESPONSE_LIMITS.maxClaimLength);
	const evidenceRationale = normalizeText(value.evidenceRationale, HYPOTHESIS_AI_RESPONSE_LIMITS.maxRationaleLength);
	if (!title || !claim || !evidenceRationale) {return undefined;}
	if (isReasoningOnly(title) || isReasoningOnly(claim) || isReasoningOnly(evidenceRationale)) {return 'reasoning-only';}
	if (!Array.isArray(value.supportingEvidenceAliases) || !Array.isArray(value.contradictoryEvidenceAliases)
		|| value.supportingEvidenceAliases.length + value.contradictoryEvidenceAliases.length > HYPOTHESIS_AI_RESPONSE_LIMITS.maxEvidencePerProposal) {return undefined;}
	const supportingEvidence = resolveAliases(value.supportingEvidenceAliases, aliases);
	const contradictoryEvidence = resolveAliases(value.contradictoryEvidenceAliases, aliases);
	if (!supportingEvidence || !contradictoryEvidence) {return 'invalid-alias';}
	if (supportingEvidence.length === 0 || supportingEvidence.length + contradictoryEvidence.length > HYPOTHESIS_AI_RESPONSE_LIMITS.maxEvidencePerProposal) {return undefined;}
	if (supportingEvidence.some((ref) => ref.freshness !== 'current') || contradictoryEvidence.some((ref) => ref.freshness !== 'current')) {return 'invalid-alias';}
	if (!supportingEvidence.some((ref) => ref.kind === 'finding' || ref.kind === 'source-span')) {return undefined;}
	if (supportingEvidence.some((support) => contradictoryEvidence.some((contradiction) => contradiction.id === support.id))) {return undefined;}
	const verificationCriteria = normalizeList(value.verificationCriteria, HYPOTHESIS_AI_RESPONSE_LIMITS.maxCriteriaCount, HYPOTHESIS_AI_RESPONSE_LIMITS.maxCriterionLength);
	const falsificationCriteria = normalizeList(value.falsificationCriteria, HYPOTHESIS_AI_RESPONSE_LIMITS.maxCriteriaCount, HYPOTHESIS_AI_RESPONSE_LIMITS.maxCriterionLength);
	const uncertainties = normalizeList(value.uncertainties, HYPOTHESIS_AI_RESPONSE_LIMITS.maxUncertaintyCount, HYPOTHESIS_AI_RESPONSE_LIMITS.maxUncertaintyLength);
	if (!verificationCriteria || !falsificationCriteria || !uncertainties || verificationCriteria.length === 0 || falsificationCriteria.length === 0 || uncertainties.length === 0) {return undefined;}
	if ([...verificationCriteria, ...falsificationCriteria, ...uncertainties].some(isReasoningOnly)) {return 'reasoning-only';}
	return { title, claim, evidenceRationale, supportingEvidence, contradictoryEvidence, verificationCriteria, falsificationCriteria, uncertainties };
}

function resolveAliases(value: unknown, aliases: ReadonlyMap<string, HypothesisEvidenceRef>): HypothesisEvidenceRef[] | undefined {
	if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || !/^e[1-9]\d{0,2}$/.test(item))) {return undefined;}
	if (new Set(value).size !== value.length) {return undefined;}
	const resolved: HypothesisEvidenceRef[] = [];
	for (const alias of value) {
		const ref = aliases.get(alias);
		if (!ref) {return undefined;}
		resolved.push({ ...ref });
	}
	return resolved;
}

function normalizeList(value: unknown, maxCount: number, maxLength: number): string[] | undefined {
	if (!Array.isArray(value) || value.length > maxCount) {return undefined;}
	const output: string[] = [];
	for (const item of value) {
		const normalized = normalizeText(item, maxLength);
		if (!normalized || isReasoningOnly(normalized)) {return undefined;}
		output.push(normalized);
	}
	return output;
}

function normalizeText(value: unknown, maxLength: number): string | undefined {
	if (typeof value !== 'string') {return undefined;}
	if (!hasWellFormedUtf16(value)) {return undefined;}
	const normalized = value.replace(/\r\n?/g, '\n').trim();
	if (!normalized || normalized.length > maxLength || /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(normalized)) {return undefined;}
	return normalized;
}

function hasWellFormedUtf16(value: string): boolean {
	for (let index = 0; index < value.length; index++) {
		const code = value.charCodeAt(index);
		if (code >= 0xD800 && code <= 0xDBFF) {
			const next = value.charCodeAt(index + 1);
			if (!(next >= 0xDC00 && next <= 0xDFFF)) {return false;}
			index++;
		} else if (code >= 0xDC00 && code <= 0xDFFF) {
			return false;
		}
	}
	return true;
}

function isReasoningOnly(value: string): boolean {
	return /^(?:here(?:['’]s| is) (?:a )?(?:my )?(?:thinking|reasoning)(?: process)?\b|let me (?:think|reason|analy[sz]e)\b|i (?:will|should|need to) (?:think|reason|analy[sz]e)\b|step\s*\d+\s*:\s*(?:thinking|analysis)\b)/i.test(value.trim());
}

function hasUnknownKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
	return Object.keys(value).some((key) => !allowed.includes(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

import * as crypto from 'node:crypto';
import * as path from 'node:path';
import { CorrelatedRelationship } from '../correlation/correlationEngine';
import { UnifiedFinding } from '../shared/finding';
import { FileSystem } from '../shared/platform';
import { ProjectProfile } from '../project/projectProfile';
import { ConfidenceFactor, HypothesisEvidenceRef, HypothesisSnapshot, SecurityHypothesis } from './contracts';

const MAX_FINDINGS = 500;
const MAX_RELATIONSHIPS = 1000;
const MAX_LINE_BYTES = 2_000;

export async function buildHypothesisSnapshot(input: {
	workspaceRoot: string;
	scanId: string;
	findings: readonly UnifiedFinding[];
	relationships: readonly CorrelatedRelationship[];
	profile: ProjectProfile;
	filesystem: FileSystem;
	capturedAt?: string;
	cancelled?: () => boolean;
}): Promise<HypothesisSnapshot> {
	const root = path.resolve(input.workspaceRoot);
	const findings: UnifiedFinding[] = [];
	const refs: HypothesisEvidenceRef[] = [];
	const findingIds = new Set<string>();
	for (const finding of input.findings.slice(0, MAX_FINDINGS)) {
		if (input.cancelled?.()) {throw new Error('Core request cancelled.');}
		if (!finding || typeof finding.id !== 'string' || !finding.id || findingIds.has(finding.id)) {continue;}
		const relative = findingPath(root, finding.file);
		if (!relative || !Number.isInteger(finding.line) || finding.line < 1) {continue;}
		const abs = path.resolve(root, relative);
		let content: string;
		try { content = await input.filesystem.readFile(abs, 'utf8'); } catch { continue; }
		const lines = content.split(/\r?\n/);
		if (finding.line > lines.length) {continue;}
		const endLine = finding.endLine ?? finding.line;
		if (!Number.isInteger(endLine) || endLine < finding.line || endLine > lines.length) {continue;}
		const excerpt = lines.slice(finding.line - 1, Math.min(endLine, finding.line + 2)).join('\n').slice(0, MAX_LINE_BYTES);
		const hash = sha256(excerpt);
		const sourceRef: HypothesisEvidenceRef = {
			id: `span:${relative}:${finding.line}-${endLine}:${hash.slice(0, 16)}`,
			kind: 'source-span', source: 'Core filesystem snapshot', file: relative,
			startLine: finding.line, endLine, contentHash: hash, findingId: finding.id, observedAt: new Date().toISOString(), freshness: 'current',
		};
		const findingRef: HypothesisEvidenceRef = {
			id: `finding:${finding.id}`, kind: 'finding', source: finding.sourceTool, file: relative,
			startLine: finding.line, endLine, contentHash: hash, findingId: finding.id, ruleId: finding.ruleId,
			observedAt: new Date().toISOString(), freshness: 'current',
		};
		findingIds.add(finding.id);
		findings.push(stripSensitiveEvidence(finding));
		refs.push(sourceRef, findingRef);
	}
	const relationships = input.relationships.slice(0, MAX_RELATIONSHIPS).filter((relationship) => {
		if (!findingIds.has(relationship.sourceId) || !findingIds.has(relationship.targetId)) {return false;}
		if (!['duplicate-of', 'same-file', 'secret-to-dependency', 'dependency-to-source', 'malware-to-artifact', 'attack-path'].includes(relationship.type)) {return false;}
		return Number.isFinite(relationship.weight) && typeof relationship.reason === 'string' && relationship.reason.length <= 500;
	}).map((relationship) => ({ ...relationship, weight: 0 }));
	for (const relationship of relationships) {
		const id = relationshipKey(relationship);
		refs.push({ id: `relationship:${id}`, kind: 'relationship', source: 'ThreatCorrelationEngine', relationshipId: id, observedAt: new Date().toISOString(), freshness: 'current' });
	}
	const capturedAt = input.capturedAt ?? new Date().toISOString();
	const fingerprint = sha256(JSON.stringify({
		scanId: input.scanId,
		findings: findings.map((finding) => [finding.id, finding.ruleId, safeRelativePath(root, finding.file), finding.line, refs.find((ref) => ref.findingId === finding.id)?.contentHash]).sort((a, b) => String(a[0]).localeCompare(String(b[0]))),
		relationships: relationships.map(relationshipKey).sort(),
	}));
	const id = `snapshot:${fingerprint.slice(0, 32)}`;
	return { id, workspaceRoot: root, scanId: input.scanId, capturedAt, fingerprint, profile: input.profile, evidence: refs, findings, relationships };
}

export function safeRelativePath(root: string, input: string): string | undefined {
	if (typeof input !== 'string' || !input.trim() || path.isAbsolute(input) || /^[a-z]:/i.test(input) || input.startsWith('\\\\')) {return undefined;}
	const normalized = input.replace(/\\/g, '/');
	if (normalized.split('/').some((part) => part === '..' || part === '')) {return undefined;}
	const absolute = path.resolve(root, normalized);
	const relative = path.relative(root, absolute);
	if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {return undefined;}
	return relative.split(path.sep).join('/');
}

function findingPath(root: string, input: string): string | undefined {
	if (path.isAbsolute(input)) {
		const relative = path.relative(root, path.resolve(input));
		if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {return undefined;}
		return safeRelativePath(root, relative);
	}
	return safeRelativePath(root, input);
}

export function relationshipKey(relationship: CorrelatedRelationship): string {
	return sha256([relationship.type, relationship.sourceId, relationship.targetId].join('|')).slice(0, 24);
}

export function validateEvidenceReference(snapshot: HypothesisSnapshot, ref: HypothesisEvidenceRef): boolean {
	if (!ref || ref.freshness !== 'current') {return false;}
	const recorded = snapshot.evidence.find((candidate) => candidate.id === ref.id && candidate.kind === ref.kind);
	if (!recorded || ['source', 'file', 'startLine', 'endLine', 'contentHash', 'findingId', 'ruleId', 'relationshipId', 'observedAt', 'freshness'].some((key) => (recorded as unknown as Record<string, unknown>)[key] !== (ref as unknown as Record<string, unknown>)[key])) {return false;}
	if (ref.file !== undefined && !safeRelativePath(snapshot.workspaceRoot, ref.file)) {return false;}
	if ((ref.startLine !== undefined && (!Number.isInteger(ref.startLine) || ref.startLine < 1)) || (ref.endLine !== undefined && (!Number.isInteger(ref.endLine) || ref.endLine < (ref.startLine ?? 1)))) {return false;}
	if (ref.kind === 'finding') {return Boolean(ref.findingId && snapshot.findings.some((finding) => finding.id === ref.findingId && finding.ruleId === ref.ruleId));}
	if (ref.kind === 'relationship') {return Boolean(ref.relationshipId && snapshot.relationships.some((relationship) => relationshipKey(relationship) === ref.relationshipId));}
	if (ref.kind === 'source-span') {return Boolean(ref.file && ref.contentHash && /^[a-f0-9]{64}$/.test(ref.contentHash));}
	return false;
}

/** V1 allows only an explicit malware-to-artifact relation, and phrases it as an attribution question, not a vulnerability claim. */
export function generateDeterministicHypotheses(snapshot: HypothesisSnapshot): SecurityHypothesis[] {
	const byId = new Map(snapshot.findings.map((finding) => [finding.id, finding]));
	const byEvidence = new Map(snapshot.evidence.map((ref) => [ref.id, ref]));
	const candidates: SecurityHypothesis[] = [];
	for (const relation of snapshot.relationships) {
		if (relation.type !== 'malware-to-artifact') {continue;}
		const source = byId.get(relation.sourceId);
		const target = byId.get(relation.targetId);
		if (!source || !target || source.sourceTool === 'AI Analysis' || target.sourceTool === 'AI Analysis') {continue;}
		const sourceEvidence = byEvidence.get(`finding:${source.id}`);
		const sourceSpan = snapshot.evidence.find((ref) => ref.kind === 'source-span' && ref.findingId === source.id);
		const targetEvidence = byEvidence.get(`finding:${target.id}`);
		const targetSpan = snapshot.evidence.find((ref) => ref.kind === 'source-span' && ref.findingId === target.id);
		const relationRef = byEvidence.get(`relationship:${relationshipKey(relation)}`);
		if (!sourceEvidence || !sourceSpan || !targetEvidence || !targetSpan || !relationRef) {continue;}
		if (![sourceEvidence, sourceSpan, targetEvidence, targetSpan, relationRef].every((ref) => validateEvidenceReference(snapshot, ref))) {continue;}
		const evidence = [sourceEvidence, sourceSpan, targetEvidence, targetSpan, relationRef];
		const sources = new Set([source.sourceTool, target.sourceTool]);
		const factors: ConfidenceFactor[] = [
			{ kind: 'direct-evidence', value: 'verified-source-span', detail: 'Both scanner finding locations resolve to current source spans with content hashes.' },
			{ kind: 'corroboration', value: sources.size > 1 ? 'multiple-source-families' : 'single-source-family', detail: sources.size > 1 ? 'The two findings have different source tool identifiers; relation derivation is not counted as an independent source.' : 'Only one scanner source family is represented.' },
			{ kind: 'relationship', value: 'heuristic', detail: 'malware-to-artifact is a filename/tag correlation heuristic, not proof of attribution.' },
			{ kind: 'freshness', value: 'current', detail: 'All cited finding and span references belong to the current completed scan snapshot.' },
			{ kind: 'contradiction', value: 'none-observed', detail: 'The snapshot provides no explicit contradictory reference; absence is not proof.' },
			{ kind: 'preconditions', value: 'unknown', detail: 'Exploit or execution preconditions are not represented by this correlation.' },
		];
		const claim = `Does the malware indicator reported by ${source.sourceTool} belong to the mobile artifact associated with ${target.sourceTool}?`;
		const stableKey = sha256(JSON.stringify({ workspace: snapshot.workspaceRoot, claim: normalizeClaim(claim), asset: targetEvidence.file, evidence: evidence.map((ref) => ref.id).sort() }));
		candidates.push({
			id: `hyp:${stableKey.slice(0, 32)}`,
			title: 'Verify malware indicator attribution to mobile artifact',
			description: claim,
			attackPath: 'Potential indicator-to-artifact association reported by correlation; execution or reachability is not established.',
			asset: { kind: 'file', id: targetEvidence.file!, label: path.basename(targetEvidence.file!) },
			evidence,
			rationale: 'The snapshot contains two current scanner finding references and a malware-to-artifact correlation. The correlation is heuristic and does not establish that the indicator is present in or executes from the artifact.',
			confidence: { band: confidenceBand(factors), factors, policyVersion: 1 },
			assumptions: ['The correlation engine matched the intended mobile artifact.'],
			contradictions: [], impact: 'If attribution is confirmed, the artifact may require malware triage.',
			verificationSteps: ['Review the cited scanner evidence and inspect the artifact with an approved malware analysis workflow.'],
			status: 'proposed', createdAt: snapshot.capturedAt, updatedAt: snapshot.capturedAt, snapshotId: snapshot.id,
			relatedFindingIds: [source.id, target.id].sort(), relatedRuleIds: [...new Set([source.ruleId, target.ruleId])].sort(), relatedHypothesisIds: [],
		});
	}
	return [...new Map(candidates.sort((a, b) => a.id.localeCompare(b.id)).map((candidate) => [candidate.id, candidate])).values()];
}

export function confidenceBand(factors: readonly ConfidenceFactor[]): 'low' | 'moderate' | 'high' {
	const direct = factors.some((factor) => factor.kind === 'direct-evidence' && factor.value === 'verified-source-span');
	const corroborated = factors.some((factor) => factor.kind === 'corroboration' && factor.value === 'multiple-source-families');
	const explicitRelation = factors.some((factor) => factor.kind === 'relationship' && factor.value === 'explicit');
	const stale = factors.some((factor) => factor.kind === 'freshness' && factor.value === 'stale');
	const contradiction = factors.some((factor) => factor.kind === 'contradiction' && factor.value === 'present');
	if (stale || contradiction || !direct) {return 'low';}
	if (corroborated && explicitRelation) {return 'moderate';}
	return 'low'; // V1 has no supported relationship that warrants high confidence.
}

function stripSensitiveEvidence(finding: UnifiedFinding): UnifiedFinding {
	return { ...finding, rawEvidence: undefined };
}
function normalizeClaim(value: string): string { return value.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(); }
function sha256(value: string): string { return crypto.createHash('sha256').update(value).digest('hex'); }

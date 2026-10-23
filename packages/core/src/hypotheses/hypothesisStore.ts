import * as crypto from 'node:crypto';
import * as path from 'node:path';
import { FileSystem } from '../shared/platform';
import { AIProviderId } from '../shared/ai';
import { HypothesisAiCommitControl } from './contracts';
import { HypothesisReviewInput, HypothesisReviewResult, HypothesisSnapshot, HypothesisStatus, HypothesisStore, SecurityHypothesis, ValidatedHypothesisAiProposal } from './contracts';
import { hashSourceContent, hashSourceSpan } from '../shared/sourceProvenance';
import { validateEvidenceReference } from './hypothesisEngine';

const MAX_HYPOTHESES = 500;
const MAX_SNAPSHOTS = 20;
const MAX_STORE_CHARS = 5_000_000;
const MAX_FRESHNESS_BYTES = 50_000_000;
const MAX_SOURCE_FILE_BYTES = 10_000_000;
const locks = new Map<string, Promise<void>>();

export class HypothesisStoreError extends Error {
	readonly code = 'HYPOTHESIS_STORE_INVALID';
	constructor(message: string) { super(message); this.name = 'HypothesisStoreError'; }
}

export class HypothesisStoreService {
	constructor(private readonly filesystem: FileSystem) {}

	async list(root: string): Promise<HypothesisStore> {
		return await withWorkspaceLock(root, this.filesystem, async (safeRoot) => {
			const store = await this.read(safeRoot);
			const refreshed = await this.markChangedEvidenceStale(safeRoot, store);
			if (refreshed !== store) {await this.write(safeRoot, refreshed);}
			return refreshed;
		});
	}

	async mergeGeneration(root: string, snapshot: HypothesisSnapshot, candidates: SecurityHypothesis[], cancelled: () => boolean): Promise<HypothesisStore> {
		return await withWorkspaceLock(root, this.filesystem, async (safeRoot) => {
			if (cancelled()) {throw new Error('Core request cancelled.');}
			const current = await this.read(safeRoot);
			const latestSnapshot = current.snapshots[0];
			if (latestSnapshot && Date.parse(snapshot.capturedAt) < Date.parse(latestSnapshot.capturedAt)) {
				throw Object.assign(new Error('This completed scan is older than the latest hypothesis snapshot. Refresh from the current scan before generating again.'), { code: 'HYPOTHESIS_STALE_GENERATION' });
			}
			const byId = new Map(current.hypotheses.map((hypothesis) => [hypothesis.id, hypothesis]));
			const regeneratedIds = new Set(candidates.map((candidate) => candidate.id));
			for (const [id, previous] of byId) {
				if (previous.snapshotId !== snapshot.id && !regeneratedIds.has(id) && ['proposed', 'investigating', 'dismissed'].includes(previous.status)) {
					byId.set(id, { ...previous, status: 'stale', updatedAt: snapshot.capturedAt });
				}
			}
			for (const candidate of candidates) {
				if (cancelled()) {throw new Error('Core request cancelled.');}
				const previous = byId.get(candidate.id);
				byId.set(candidate.id, previous ? preserveReview(previous, candidate) : candidate);
			}
			const hypotheses = [...byId.values()].sort((a, b) => a.id.localeCompare(b.id)).slice(0, MAX_HYPOTHESES);
			const snapshots = [{ id: snapshot.id, scanId: snapshot.scanId, capturedAt: snapshot.capturedAt, fingerprint: snapshot.fingerprint }, ...current.snapshots.filter((item) => item.id !== snapshot.id)].slice(0, MAX_SNAPSHOTS);
			const next: HypothesisStore = { version: 1, scoringPolicyVersion: 1, generation: (current.generation ?? 0) + 1, updatedAt: new Date().toISOString(), hypotheses, snapshots };
			validateStore(next);
			if (cancelled()) {throw new Error('Core request cancelled.');}
			await this.write(safeRoot, next);
			return next;
		});
	}

	async review(root: string, input: HypothesisReviewInput, now = new Date().toISOString()): Promise<HypothesisReviewResult> {
		return await withWorkspaceLock(root, this.filesystem, async (safeRoot) => {
			const original = await this.read(safeRoot);
			const store = await this.markChangedEvidenceStale(safeRoot, original);
			if (store !== original) {await this.write(safeRoot, store);}
			const index = store.hypotheses.findIndex((hypothesis) => hypothesis.id === input.hypothesisId);
			if (index < 0) {throw Object.assign(new Error('Hypothesis was not found in this workspace.'), { code: 'HYPOTHESIS_NOT_FOUND' });}
			const hypothesis = store.hypotheses[index];
			if (hypothesis.evidenceFreshness === 'provenance-unavailable') {return { hypothesis, applied: false, diagnostic: 'provenance-unavailable' };}
			if (hypothesis.evidenceFreshness === 'stale' || hypothesis.status === 'stale') {return { hypothesis, applied: false, diagnostic: 'stale-evidence' };}
			if ((input.action === 'validate' || input.action === 'reject') && !hasCurrentSourceProvenance(hypothesis)) {
				return { hypothesis: staleEvidence(hypothesis, 'provenance-unavailable'), applied: false, diagnostic: 'provenance-unavailable' };
			}
			const nextStatus = transition(hypothesis.status, input.action);
			if (input.action === 'validate' && (!Array.isArray(input.evidenceRefs) || input.evidenceRefs.length === 0 || !input.evidenceRefs.some((id) => hypothesis.evidence.some((ref) => ref.id === id && ref.freshness === 'current')))) {
				throw Object.assign(new Error('Validation requires at least one current supporting evidence reference.'), { code: 'HYPOTHESIS_EVIDENCE_REQUIRED' });
			}
			if (input.evidenceRefs?.some((id) => ![...hypothesis.evidence, ...hypothesis.contradictions].some((ref) => ref.id === id && ref.freshness === 'current'))) {
				throw Object.assign(new Error('Review references evidence that is not current for this hypothesis.'), { code: 'HYPOTHESIS_INVALID_EVIDENCE' });
			}
			const updated: SecurityHypothesis = { ...hypothesis, status: nextStatus, updatedAt: now, review: { at: now, action: input.action, ...(input.note ? { note: input.note.slice(0, 500) } : {}), ...(input.evidenceRefs?.length ? { evidenceRefs: [...new Set(input.evidenceRefs)].slice(0, 20) } : {}) } };
			const hypotheses = [...store.hypotheses]; hypotheses[index] = updated;
			await this.write(safeRoot, { ...store, generation: (store.generation ?? 0) + 1, updatedAt: now, hypotheses });
			return { hypothesis: updated, applied: true };
		});
	}

	/** Appends only freshly validated AI proposals. Existing records are never replaced. */
	async persistValidatedAiProposals(root: string, snapshot: HypothesisSnapshot, proposals: readonly ValidatedHypothesisAiProposal[], preparationId: string, providerId: AIProviderId, modelId: string, signal?: AbortSignal, commitControl?: HypothesisAiCommitControl): Promise<HypothesisStore> {
		return await withWorkspaceLock(root, this.filesystem, async (safeRoot) => {
			throwIfCancelled(signal);
			if (!proposals.length || proposals.length > 5 || !/^[a-f0-9-]{1,80}$/i.test(preparationId) || providerId.length > 32 || modelId.length > 128
				|| proposals.some((proposal) => !isBoundedString(proposal.title, 160, 1) || !isBoundedString(proposal.claim, 500, 1) || !isBoundedString(proposal.evidenceRationale, 1200, 1)
					|| !Array.isArray(proposal.supportingEvidence) || proposal.supportingEvidence.length === 0 || proposal.supportingEvidence.length > 8
					|| !Array.isArray(proposal.contradictoryEvidence) || proposal.contradictoryEvidence.length > 8
					|| [...proposal.supportingEvidence, ...proposal.contradictoryEvidence].some((ref) => !validateEvidenceReference(snapshot, ref))
					|| !isStringList(proposal.verificationCriteria, 5, 300) || !isStringList(proposal.falsificationCriteria, 5, 300) || !isStringList(proposal.uncertainties, 5, 240))) {
				throw new HypothesisStoreError('Validated proposal persistence request is invalid; existing data was preserved.');
			}
			const current = await this.read(safeRoot);
			throwIfCancelled(signal);
			if (current.snapshots[0] && current.snapshots[0].id !== snapshot.id) {throw Object.assign(new Error('AI proposals belong to a scan snapshot that is no longer current.'), { code: 'HYPOTHESIS_STALE_GENERATION' });}
			await this.assertAiProposalEvidenceFresh(safeRoot, snapshot, proposals);
			throwIfCancelled(signal);
			const timestamp = new Date().toISOString();
			const additions = proposals.map((proposal, index): SecurityHypothesis => {
				const evidence = [...proposal.supportingEvidence, ...proposal.contradictoryEvidence].map((ref) => ({ ...ref }));
				const id = `hyp:ai:${crypto.createHash('sha256').update(`${preparationId}:${index}:${JSON.stringify(proposal)}`).digest('hex').slice(0, 32)}`;
				const file = proposal.supportingEvidence.find((ref) => ref.file)?.file;
				const firstFinding = proposal.supportingEvidence.find((ref) => ref.findingId);
				return {
					id, title: proposal.title, description: proposal.claim, asset: file ? { kind: 'file', id: file } : { kind: 'project', id: snapshot.workspaceRoot }, evidence,
					rationale: proposal.evidenceRationale, confidence: { band: 'low', factors: [
						{ kind: 'freshness', value: 'current', detail: 'Evidence was current in the bound Core snapshot at validation.' },
						{ kind: 'preconditions', value: 'unknown', detail: 'AI-generated claims require independent reviewer verification.' },
					], policyVersion: 1 }, assumptions: proposal.uncertainties.slice(0, 10), contradictions: proposal.contradictoryEvidence.map((ref) => ({ ...ref })),
					verificationSteps: [...proposal.verificationCriteria, ...proposal.falsificationCriteria].slice(0, 10), status: 'proposed', evidenceFreshness: 'current',
					createdAt: timestamp, updatedAt: timestamp, snapshotId: snapshot.id, relatedFindingIds: firstFinding ? [firstFinding.findingId!] : [],
					relatedRuleIds: proposal.supportingEvidence.flatMap((ref) => ref.ruleId ? [ref.ruleId] : []).slice(0, 100), relatedHypothesisIds: [],
					origin: { kind: 'ai-proposal', preparationId, providerId, modelId },
				};
			});
			const existingIds = new Set(current.hypotheses.map((item) => item.id));
			if (additions.some((item) => existingIds.has(item.id)) || current.hypotheses.length + additions.length > MAX_HYPOTHESES) {throw new HypothesisStoreError('AI proposals conflict with existing records or exceed store capacity; existing data was preserved.');}
			const snapshots = current.snapshots.length ? current.snapshots : [{ id: snapshot.id, scanId: snapshot.scanId, capturedAt: snapshot.capturedAt, fingerprint: snapshot.fingerprint }];
			const next: HypothesisStore = { ...current, generation: (current.generation ?? 0) + 1, updatedAt: timestamp, hypotheses: [...current.hypotheses, ...additions].sort((a, b) => a.id.localeCompare(b.id)), snapshots };
			validateStore(next);
			// Cancellation is checked at the last boundary before the atomic write.
			throwIfCancelled(signal);
			await this.write(safeRoot, next, signal, commitControl);
			return next;
		});
	}

	private async markChangedEvidenceStale(root: string, store: HypothesisStore): Promise<HypothesisStore> {
		let changed = false;
		const active = store.hypotheses.filter((hypothesis) => hypothesis.evidenceFreshness !== 'stale' && hypothesis.evidenceFreshness !== 'provenance-unavailable');
		const refsByFile = new Map<string, { file: string; references: Array<{ hypothesisId: string; ref: SecurityHypothesis['evidence'][number] }> }>();
		const invalidHypotheses = new Set<string>();
		const provenanceUnavailableHypotheses = new Set<string>();
		for (const hypothesis of active) {
			const sourceSpans = hypothesis.evidence.filter((item) => item.kind === 'source-span');
			if (sourceSpans.length === 0) {provenanceUnavailableHypotheses.add(hypothesis.id); continue;}
			const currentSourceSpans = sourceSpans.filter((item) => item.freshness === 'current');
			if (currentSourceSpans.length === 0) {invalidHypotheses.add(hypothesis.id); continue;}
			for (const ref of currentSourceSpans) {
				if (!ref.file || !ref.contentHash || !ref.fileContentHash || !Number.isInteger(ref.startLine) || !Number.isInteger(ref.endLine) || ref.startLine! < 1 || ref.endLine! < ref.startLine!) {invalidHypotheses.add(hypothesis.id); continue;}
				const file = path.resolve(root, ref.file);
				const key = process.platform === 'win32' ? file.toLowerCase() : file;
				const entry = refsByFile.get(key) ?? { file, references: [] };
				entry.references.push({ hypothesisId: hypothesis.id, ref });
				refsByFile.set(key, entry);
			}
		}
		const staleHypotheses = new Set(invalidHypotheses);
		let freshnessBytes = 0;
		for (const { file, references } of refsByFile.values()) {
			if (!await isSafeStoreRelativeFile(root, path.relative(root, file).split(path.sep).join('/'), this.filesystem)) { for (const item of references) staleHypotheses.add(item.hypothesisId); continue; }
			if (!this.filesystem.readFileBoundedBytes) {throw new HypothesisStoreError('Hypothesis freshness checks require bounded raw-byte filesystem reads; existing data was preserved.');}
			let content: string;
			let readAttempted = false;
			try {
				const stat = await this.filesystem.stat(file);
				if (!stat.isFile() || stat.size > MAX_SOURCE_FILE_BYTES || freshnessBytes + stat.size > MAX_FRESHNESS_BYTES) {for (const item of references) staleHypotheses.add(item.hypothesisId); continue;}
				const readLimit = Math.min(MAX_SOURCE_FILE_BYTES, MAX_FRESHNESS_BYTES - freshnessBytes);
				readAttempted = true;
				const bytes = await this.filesystem.readFileBoundedBytes(file, readLimit);
				if (bytes.byteLength > readLimit) {freshnessBytes = MAX_FRESHNESS_BYTES; for (const item of references) {staleHypotheses.add(item.hypothesisId);} continue;}
				freshnessBytes += bytes.byteLength;
				content = Buffer.from(bytes).toString('utf8');
			} catch (error) {
				if (readAttempted) {
					if (error && typeof error === 'object' && 'bytesRead' in error && Number.isSafeInteger((error as { bytesRead?: unknown }).bytesRead)) {freshnessBytes += Math.min(MAX_FRESHNESS_BYTES - freshnessBytes, Number((error as { bytesRead: number }).bytesRead));}
					else {freshnessBytes = MAX_FRESHNESS_BYTES;}
				}
				for (const item of references) staleHypotheses.add(item.hypothesisId); continue;
			}
			const lines = content.split(/\r?\n/);
			const spanHashes = new Map<string, string | undefined>();
			const fileHash = hashSourceContent(content);
			for (const { hypothesisId, ref } of references) {
				const key = `${ref.startLine}-${ref.endLine}`;
				if (!spanHashes.has(key)) {spanHashes.set(key, hashSpanFromLines(lines, ref.startLine!, ref.endLine!));}
				if (spanHashes.get(key) !== ref.contentHash || fileHash !== ref.fileContentHash) {staleHypotheses.add(hypothesisId);}
			}
		}
		const hypotheses = store.hypotheses.map((hypothesis) => {
			if (provenanceUnavailableHypotheses.has(hypothesis.id)) {changed = true; return staleEvidence(hypothesis, 'provenance-unavailable');}
			if (!staleHypotheses.has(hypothesis.id)) {return hypothesis;}
			changed = true;
			return staleEvidence(hypothesis);
		});
		return changed ? { ...store, generation: (store.generation ?? 0) + 1, updatedAt: new Date().toISOString(), hypotheses } : store;
	}

	private async assertAiProposalEvidenceFresh(root: string, snapshot: HypothesisSnapshot, proposals: readonly ValidatedHypothesisAiProposal[]): Promise<void> {
		const references = [...new Map(proposals.flatMap((proposal) => [...proposal.supportingEvidence, ...proposal.contradictoryEvidence]).filter((ref) => ref.kind === 'source-span').map((ref) => [ref.id, ref])).values()];
		if (!references.length) {throw new HypothesisStoreError('AI proposals require verified source-span evidence; existing data was preserved.');}
		if (!this.filesystem.readFileBoundedBytes) {throw new HypothesisStoreError('AI proposal persistence requires bounded evidence reads; existing data was preserved.');}
		let totalBytes = 0;
		const files = new Map<string, Uint8Array>();
		for (const ref of references) {
			if (!ref.file || !ref.contentHash || !ref.fileContentHash || ref.startLine === undefined || ref.endLine === undefined || !await isSafeStoreRelativeFile(root, ref.file, this.filesystem)) {throw new HypothesisStoreError('AI proposal evidence path or provenance is invalid; existing data was preserved.');}
			let bytes = files.get(ref.file);
			if (!bytes) {
				const absolute = path.resolve(root, ref.file);
				const stat = await this.filesystem.stat(absolute);
				if (!stat.isFile() || stat.size > MAX_SOURCE_FILE_BYTES || totalBytes + stat.size > MAX_FRESHNESS_BYTES) {throw new HypothesisStoreError('AI proposal source evidence exceeds freshness limits; existing data was preserved.');}
				bytes = await this.filesystem.readFileBoundedBytes(absolute, Math.min(MAX_SOURCE_FILE_BYTES, MAX_FRESHNESS_BYTES - totalBytes));
				if (bytes.byteLength > MAX_SOURCE_FILE_BYTES || totalBytes + bytes.byteLength > MAX_FRESHNESS_BYTES) {throw new HypothesisStoreError('AI proposal source evidence exceeds freshness limits; existing data was preserved.');}
				totalBytes += bytes.byteLength;
				files.set(ref.file, bytes);
			}
			let content: string;
			try { content = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch {throw new HypothesisStoreError('AI proposal source evidence is no longer valid UTF-8; existing data was preserved.');}
			if (hashSourceContent(content) !== ref.fileContentHash || hashSourceSpan(content, ref.startLine, ref.endLine) !== ref.contentHash) {throw Object.assign(new Error('AI proposal evidence changed after preparation; create a fresh preparation.'), { code: 'HYPOTHESIS_STALE_GENERATION' });}
		}
	}

	private async read(root: string): Promise<HypothesisStore> {
		const file = storePath(root);
		await assertSafeStoreTarget(root, file, this.filesystem, true);
		await this.recoverBackup(file);
		await assertSafeStoreTarget(root, file, this.filesystem, true);
		let raw: string;
		if (!this.filesystem.readFileBounded) {throw new HypothesisStoreError('Hypothesis storage requires bounded filesystem reads; existing data was preserved.');}
		try { raw = await this.filesystem.readFileBounded(file, MAX_STORE_CHARS, 'utf8'); }
		catch (error) {
			if (isMissing(error)) {return emptyStore();}
			if (hasErrorCode(error, 'FILE_TOO_LARGE')) {throw new HypothesisStoreError(`Hypothesis store at ${file} exceeds the 5 MB safety limit. Preserve the file and recover it before writing.`);}
			throw error;
		}
		if (Buffer.byteLength(raw, 'utf8') > MAX_STORE_CHARS) {throw new HypothesisStoreError(`Hypothesis store at ${file} exceeds the 5 MB safety limit. Preserve the file and recover it before writing.`);}
		let parsed: unknown;
		try { parsed = JSON.parse(raw) as unknown; } catch { throw new HypothesisStoreError(`Hypothesis store at ${file} contains invalid JSON. Preserve the file and recover it before writing.`); }
		if (!isStore(parsed)) {throw new HypothesisStoreError(`Hypothesis store at ${file} has an invalid or unsupported schema. Preserve the file and recover it before writing.`);}
		return { ...parsed, generation: parsed.generation ?? 0 };
	}

	private async write(root: string, store: HypothesisStore, signal?: AbortSignal, commitControl?: HypothesisAiCommitControl): Promise<void> {
		const directory = path.dirname(storePath(root));
		await assertSafeStoreDirectory(root, directory, this.filesystem, true);
		const target = storePath(root);
		await assertSafeStoreTarget(root, target, this.filesystem, true);
		const temporary = `${target}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
		const serialized = JSON.stringify(store, null, 2);
		if (!Number.isSafeInteger(store.generation) || (store.generation ?? -1) < 0) {throw new HypothesisStoreError('Hypothesis store generation is invalid; existing data was preserved.');}
		if (Buffer.byteLength(serialized, 'utf8') > MAX_STORE_CHARS) {throw new HypothesisStoreError('Hypothesis store exceeds the 5 MB safety limit; existing data was preserved.');}
		if (!this.filesystem.writeFileExclusive) {throw new HypothesisStoreError('Filesystem exclusive-create support is required for safe hypothesis persistence.');}
		let createdTemporary = false;
		try {
			await this.filesystem.writeFileExclusive(temporary, serialized, 'utf8');
			createdTemporary = true;
			await assertSafeStoreTarget(root, temporary, this.filesystem, false);
			if (!(await this.filesystem.exists(target))) {
				throwIfCancelled(signal);
				if (commitControl && !commitControl.beginCommit()) {throwIfCancelled(signal); throw Object.assign(new Error('Core request cancelled before persistence commit.'), { code: 'CORE_REQUEST_CANCELLED' });}
				await this.filesystem.rename(temporary, target);
				commitControl?.markCommitted();
				return;
			}
			const backup = `${target}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.bak`;
			await this.filesystem.rename(target, backup);
			try {
				throwIfCancelled(signal);
				if (commitControl && !commitControl.beginCommit()) {throwIfCancelled(signal); throw Object.assign(new Error('Core request cancelled before persistence commit.'), { code: 'CORE_REQUEST_CANCELLED' });}
				await this.filesystem.rename(temporary, target);
				commitControl?.markCommitted();
			} catch (error) {
				try { await this.filesystem.rename(backup, target); }
				catch { throw Object.assign(new Error(`Could not replace hypothesis store. The previous store is preserved at ${backup}; recover it before continuing.`), { code: 'HYPOTHESIS_STORE_RECOVERY_REQUIRED' }); }
				throw error;
			}
			try { await this.filesystem.unlink?.(backup); } catch { /* committed replacement is valid; orphan backup remains recoverable */ }
		} finally {
			if (createdTemporary && this.filesystem.unlink) {
				try { await assertSafeStoreTarget(root, temporary, this.filesystem, false); await this.filesystem.unlink(temporary); } catch { /* absent or unsafe temporary files are preserved for recovery */ }
			}
		}
	}

	private async recoverBackup(target: string): Promise<void> {
		if (await this.filesystem.exists(target)) {return;}
		let entries: Array<string | { name: string }>;
		try { entries = await this.filesystem.readdir(path.dirname(target)); }
		catch (error) {if (isMissing(error)) {return;} throw Object.assign(new HypothesisStoreError(`Could not inspect hypothesis backups beside ${target}; preserve store artifacts and retry recovery.`), { code: 'HYPOTHESIS_STORE_RECOVERY_REQUIRED' });}
		const prefix = `${path.basename(target)}.`;
		const backups = entries.map((entry) => typeof entry === 'string' ? entry : entry.name).filter((name) => name.startsWith(prefix) && name.endsWith('.bak'));
		if (backups.length === 0) {return;}
		const valid: Array<{ name: string; generation: number; raw: string }> = [];
		for (const backupName of backups) {
			const backup = path.join(path.dirname(target), backupName);
			try {
				await assertSafeStoreTarget(path.dirname(path.dirname(target)), backup, this.filesystem, false);
				if (!this.filesystem.readFileBounded) {throw new HypothesisStoreError('Backup recovery requires bounded reads; preserve all backup files and recover manually.');}
				const raw = await this.filesystem.readFileBounded(backup, MAX_STORE_CHARS, 'utf8');
				if (Buffer.byteLength(raw, 'utf8') > MAX_STORE_CHARS) {throw new Error('backup exceeds byte limit');}
				const parsed = JSON.parse(raw) as unknown;
				if (!isStore(parsed)) {throw new Error('unsupported or invalid backup schema');}
				valid.push({ name: backupName, generation: parsed.generation ?? 0, raw });
			} catch {
				throw Object.assign(new HypothesisStoreError(`Hypothesis backup ${backup} is corrupt, unsupported, or unreadable. No backup was selected; preserve all store artifacts for manual recovery.`), { code: 'HYPOTHESIS_STORE_RECOVERY_REQUIRED' });
			}
		}
		valid.sort((left, right) => right.generation - left.generation);
		if (valid.length > 1 && valid[0].generation === valid[1].generation && valid[0].raw !== valid[1].raw) {
			throw Object.assign(new HypothesisStoreError('Hypothesis backups have conflicting contents at the same committed generation. Preserve all artifacts for manual recovery.'), { code: 'HYPOTHESIS_STORE_RECOVERY_REQUIRED' });
		}
		await this.filesystem.rename(path.join(path.dirname(target), valid[0].name), target);
	}
}

export function transition(status: HypothesisStatus, action: HypothesisReviewInput['action']): HypothesisStatus {
	const allowed: Record<HypothesisStatus, Partial<Record<HypothesisReviewInput['action'], HypothesisStatus>>> = {
		proposed: { investigate: 'investigating', validate: 'validated', reject: 'rejected', dismiss: 'dismissed' },
		investigating: { validate: 'validated', reject: 'rejected', dismiss: 'dismissed' },
		validated: {}, rejected: {}, dismissed: { reopen: 'proposed' }, stale: {}, unsubstantiated: {},
	};
	const next = allowed[status]?.[action];
	if (!next) {throw Object.assign(new Error(`Cannot ${action} a hypothesis in ${status} status.`), { code: 'HYPOTHESIS_INVALID_TRANSITION' });}
	return next;
}

function preserveReview(previous: SecurityHypothesis, candidate: SecurityHypothesis): SecurityHypothesis {
	if (previous.status === 'validated' || previous.status === 'rejected') {return { ...candidate, status: previous.status, createdAt: previous.createdAt, review: previous.review, evidenceFreshness: 'current' };}
	if (previous.status === 'dismissed' || previous.status === 'investigating') {return { ...candidate, status: previous.status, createdAt: previous.createdAt, review: previous.review };}
	if (previous.status === 'stale') {
		const restoredStatus = previous.review?.action === 'dismiss' ? 'dismissed' : previous.review?.action === 'investigate' ? 'investigating' : candidate.status;
		return { ...candidate, status: restoredStatus, createdAt: previous.createdAt, review: previous.review };
	}
	return { ...candidate, createdAt: previous.createdAt };
}

function emptyStore(): HypothesisStore { return { version: 1, scoringPolicyVersion: 1, generation: 0, updatedAt: '', hypotheses: [], snapshots: [] }; }
function storePath(root: string): string { return path.join(path.resolve(root), '.aqiron-security', 'hypotheses.json'); }
function staleEvidence(hypothesis: SecurityHypothesis, freshness: 'stale' | 'provenance-unavailable' = 'stale'): SecurityHypothesis {
	const historical = hypothesis.status === 'validated' || hypothesis.status === 'rejected';
	return { ...hypothesis, evidenceFreshness: freshness, evidence: hypothesis.evidence.map((ref) => ({ ...ref, freshness: 'stale' })), updatedAt: new Date().toISOString(), ...(!historical ? { status: 'stale' as const } : {}) };
}
function hasCurrentSourceProvenance(hypothesis: SecurityHypothesis): boolean {
	return hypothesis.evidence.some((ref) => ref.kind === 'source-span' && ref.freshness === 'current' && Boolean(ref.file && ref.contentHash && ref.fileContentHash && ref.findingId) && Number.isInteger(ref.startLine) && Number.isInteger(ref.endLine) && ref.startLine! >= 1 && ref.endLine! >= ref.startLine!);
}
function hashSpanFromLines(lines: readonly string[], startLine: number, endLine: number): string | undefined {
	if (!Number.isInteger(startLine) || !Number.isInteger(endLine) || startLine < 1 || endLine < startLine || endLine > lines.length || endLine - startLine + 1 > 20) {return undefined;}
	const span = lines.slice(startLine - 1, endLine).join('\n');
	if (Buffer.byteLength(span, 'utf8') > 64_000) {return undefined;}
	return crypto.createHash('sha256').update(span, 'utf8').digest('hex');
}
async function withWorkspaceLock<T>(root: string, filesystem: FileSystem, task: (safeRoot: string) => Promise<T>): Promise<T> {
	const safeRoot = await physicalWorkspaceRoot(root, filesystem);
	const directory = path.join(safeRoot, '.aqiron-security');
	await assertSafeStoreDirectory(safeRoot, directory, filesystem, true);
	const resolvedRoot = safeRoot;
	const key = process.platform === 'win32' ? resolvedRoot.toLowerCase() : resolvedRoot;
	const previous = locks.get(key) ?? Promise.resolve();
	let release!: () => void;
	const current = new Promise<void>((resolve) => { release = resolve; });
	const queued = previous.then(() => current);
	locks.set(key, queued);
	await previous;
	let releaseFileLock: (() => Promise<void>) | undefined;
	try {
		await assertSafeStoreDirectory(safeRoot, directory, filesystem, false);
		releaseFileLock = await acquireWorkspaceLock(safeRoot, filesystem);
		return await task(safeRoot);
	}
	finally {
		try { await releaseFileLock?.(); }
		finally { release(); if (locks.get(key) === queued) {locks.delete(key);} }
	}
}
async function acquireWorkspaceLock(root: string, filesystem: FileSystem): Promise<() => Promise<void>> {
	const lockPath = `${storePath(root)}.lock`;
	const gatePath = `${lockPath}.gate`;
	const deadline = Date.now() + 15_000;
	const token = crypto.randomBytes(16).toString('hex');
	if (!filesystem.writeFileExclusive || !filesystem.unlink || !filesystem.rmdir || !filesystem.lstat || !filesystem.realpath) {throw new HypothesisStoreError('Hypothesis locks require exclusive create, lstat, realpath, unlink and rmdir filesystem support.');}
	while (Date.now() < deadline) {
		let ownsGate = false;
		let createdLockDirectory = false;
		const ownerPath = path.join(lockPath, 'owner.json');
		try {
			await assertSafeStoreTarget(root, storePath(root), filesystem, true);
			await filesystem.mkdir(gatePath);
			ownsGate = true;
			try { await filesystem.mkdir(lockPath); createdLockDirectory = true; }
			catch (error) { if (!isAlreadyExists(error)) {throw error;} await assertSafeLockDirectory(lockPath, filesystem, false); }
			const owner = await readLockOwner(ownerPath, filesystem);
			if (!owner && !createdLockDirectory) {
				throw Object.assign(new HypothesisStoreError(`Hypothesis lock at ${lockPath} exists without an owner record. Ownership is ambiguous; stop all Core processes and recover the lock manually.`), { code: 'HYPOTHESIS_STORE_LOCKED' });
			}
			if (owner && (!Number.isSafeInteger(owner.pid) || Number(owner.pid) <= 0 || typeof owner.token !== 'string' || owner.token.length < 1 || owner.token.length > 128)) {
				throw Object.assign(new HypothesisStoreError(`Hypothesis lock owner at ${ownerPath} is malformed; ownership is ambiguous and manual recovery is required after stopping all Core processes.`), { code: 'HYPOTHESIS_STORE_LOCKED' });
			}
			if (owner && isProcessAlive(owner.pid)) {
				await releaseGate(gatePath, filesystem);
				ownsGate = false;
				await new Promise((resolve) => setTimeout(resolve, 25));
				continue;
			}
			if (owner) {
				const lockIdentity = await filesystem.realpath!(lockPath);
				const inspectedAgain = await readLockOwner(ownerPath, filesystem);
				if (!inspectedAgain || inspectedAgain.pid !== owner.pid || inspectedAgain.token !== owner.token || !samePhysicalPath(await filesystem.realpath!(lockPath), lockIdentity)) {
					throw Object.assign(new HypothesisStoreError(`Hypothesis lock ownership at ${lockPath} changed during stale-owner recovery; no owner record was removed.`), { code: 'HYPOTHESIS_STORE_LOCKED' });
				}
				await filesystem.unlink!(ownerPath);
			}
			await filesystem.writeFileExclusive(ownerPath, JSON.stringify({ pid: process.pid, token }), 'utf8');
			await assertRegularLockOwner(ownerPath, filesystem);
			await releaseGate(gatePath, filesystem);
			ownsGate = false;
			return async () => {
				let releaseGateLock: (() => Promise<void>) | undefined;
				try {
					releaseGateLock = await acquireGate(gatePath, deadlineAfterLock(), filesystem);
					await assertSafeLockDirectory(lockPath, filesystem, false);
					const current = await readLockOwner(ownerPath, filesystem);
					if (current?.token === token) {
						await filesystem.unlink!(ownerPath);
						await assertSafeLockDirectory(lockPath, filesystem, false);
						await filesystem.rmdir!(lockPath);
					}
				} finally { await releaseGateLock?.(); }
			};
		} catch (error) {
			if (ownsGate) {
				if (createdLockDirectory) {
					try { if (!await filesystem.exists(ownerPath)) {await assertSafeLockDirectory(lockPath, filesystem, false); await filesystem.rmdir!(lockPath);} } catch { /* preserve ambiguous lock state for manual recovery */ }
				}
				await releaseGate(gatePath, filesystem);
			}
			if (!isAlreadyExists(error)) {throw error;}
			await new Promise((resolve) => setTimeout(resolve, 25));
		}
	}
	throw Object.assign(new Error(`Hypothesis store lock or recovery gate is held by another or interrupted Core process: ${lockPath}. Do not remove lock artifacts unless all Core processes for this workspace have stopped.`), { code: 'HYPOTHESIS_STORE_LOCKED' });
}
async function acquireGate(gatePath: string, deadline: number, filesystem: FileSystem): Promise<() => Promise<void>> {
	while (Date.now() < deadline) {
		try { await filesystem.mkdir(gatePath); return async () => { try { await releaseGate(gatePath, filesystem); } catch { /* a missing or replaced gate is never removed */ } }; }
		catch (error) { if (!isAlreadyExists(error)) {throw error;} await new Promise((resolve) => setTimeout(resolve, 25)); }
	}
	throw Object.assign(new Error(`Hypothesis lock recovery gate is held or was left by an interrupted Core process: ${gatePath}. Manual recovery is required after stopping all Core processes for this workspace.`), { code: 'HYPOTHESIS_STORE_LOCKED' });
}
async function releaseGate(gatePath: string, filesystem: FileSystem): Promise<void> {
	const stat = await filesystem.lstat!(gatePath);
	if (stat.isSymbolicLink() || !stat.isDirectory() || !samePhysicalPath(await filesystem.realpath!(gatePath), gatePath)) {throw new HypothesisStoreError('Hypothesis lock gate is not a safe workspace directory.');}
	await filesystem.rmdir!(gatePath);
}
function deadlineAfterLock(): number { return Date.now() + 15_000; }
async function readLockOwner(ownerPath: string, filesystem: FileSystem): Promise<{ pid?: unknown; token?: unknown } | undefined> {
	try {
		await assertRegularLockOwner(ownerPath, filesystem);
		if (!filesystem.readFileBounded) {throw new HypothesisStoreError('Hypothesis locks require bounded owner-file reads.');}
		let parsed: unknown;
		try { parsed = JSON.parse(await filesystem.readFileBounded(ownerPath, 2048, 'utf8')) as unknown; }
		catch (error) { if (isMissing(error)) {return undefined;} throw Object.assign(new HypothesisStoreError(`Hypothesis lock owner at ${ownerPath} is unreadable or malformed; ownership is ambiguous and manual recovery is required after stopping all Core processes.`), { code: 'HYPOTHESIS_STORE_LOCKED' }); }
		if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {return { token: null };}
		return parsed as { pid?: unknown; token?: unknown };
	} catch (error) {if (isMissing(error)) {return undefined;} throw error;}
}
async function assertSafeLockDirectory(lockPath: string, filesystem: FileSystem, create: boolean): Promise<void> {
	try {
		const stat = await filesystem.lstat!(lockPath);
		if (stat.isSymbolicLink() || !stat.isDirectory() || !samePhysicalPath(await filesystem.realpath!(lockPath), lockPath)) {throw new HypothesisStoreError('Hypothesis lock path is not a safe workspace directory.');}
	} catch (error) {
		if (!isMissing(error) || !create) {throw error;}
		try {await filesystem.mkdir(lockPath);} catch (createError) {if (!isAlreadyExists(createError)) {throw createError;}}
		const stat = await filesystem.lstat!(lockPath);
		if (stat.isSymbolicLink() || !stat.isDirectory() || !samePhysicalPath(await filesystem.realpath!(lockPath), lockPath)) {throw new HypothesisStoreError('Hypothesis lock path changed during creation.');}
	}
}
async function assertRegularLockOwner(ownerPath: string, filesystem: FileSystem): Promise<void> {
	if (!filesystem.lstat || !filesystem.realpath) {throw new Error('Filesystem lstat/realpath support is required for hypothesis lock ownership.');}
	const stat = await filesystem.lstat(ownerPath);
	if (stat.isSymbolicLink() || !stat.isFile() || !samePhysicalPath(await filesystem.realpath(ownerPath), ownerPath)) {throw new Error('Hypothesis lock owner must be a regular file.');}
}
function samePhysicalPath(left: string, right: string): boolean {
	const a = path.resolve(left), b = path.resolve(right);
	return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}
function isProcessAlive(pid: unknown): boolean {
	if (!Number.isInteger(pid) || Number(pid) <= 0) {return false;}
	try { process.kill(Number(pid), 0); return true; }
	catch (error) { return Boolean(error && typeof error === 'object' && 'code' in error && (error as { code?: unknown }).code !== 'ESRCH'); }
}
function isMissing(error: unknown): boolean { return Boolean(error && typeof error === 'object' && 'code' in error && (error as { code?: unknown }).code === 'ENOENT'); }
function isAlreadyExists(error: unknown): boolean { return Boolean(error && typeof error === 'object' && 'code' in error && (error as { code?: unknown }).code === 'EEXIST'); }
function hasErrorCode(error: unknown, code: string): boolean { return Boolean(error && typeof error === 'object' && 'code' in error && (error as { code?: unknown }).code === code); }
async function physicalWorkspaceRoot(root: string, filesystem: FileSystem): Promise<string> {
	if (!path.isAbsolute(root) || !filesystem.realpath || !filesystem.lstat) {throw new HypothesisStoreError('Hypothesis storage requires an absolute workspace and filesystem realpath/lstat support.');}
	const actual = await filesystem.realpath(path.resolve(root));
	const stat = await filesystem.lstat(actual);
	if (!stat.isDirectory() || stat.isSymbolicLink()) {throw new HypothesisStoreError('Hypothesis workspace root must resolve to a physical directory.');}
	return actual;
}
async function assertSafeStoreDirectory(root: string, directory: string, filesystem: FileSystem, create: boolean): Promise<void> {
	if (!filesystem.lstat || !filesystem.realpath) {throw new HypothesisStoreError('Hypothesis storage requires filesystem realpath/lstat support; refusing unsafe access.');}
	if (path.dirname(directory) !== root || path.basename(directory) !== '.aqiron-security') {throw new HypothesisStoreError('Hypothesis store directory escapes the workspace.');}
	try {
		let stat = await filesystem.lstat(directory);
		if (stat.isSymbolicLink() || !stat.isDirectory()) {throw new HypothesisStoreError('The .aqiron-security path must be a real directory, not a symlink.');}
	} catch (error) {
		if (!isMissing(error) || !create) {throw error;}
		await filesystem.mkdir(directory);
		const stat = await filesystem.lstat(directory);
		if (stat.isSymbolicLink() || !stat.isDirectory()) {throw new HypothesisStoreError('The .aqiron-security path changed during creation.');}
	}
	const actual = await filesystem.realpath(directory);
	if (!samePhysicalPath(path.dirname(actual), root) || path.basename(actual).toLowerCase() !== '.aqiron-security') {throw new HypothesisStoreError('The .aqiron-security directory resolves outside the workspace.');}
}
async function assertSafeStoreTarget(root: string, target: string, filesystem: FileSystem, allowMissing: boolean): Promise<void> {
	await assertSafeStoreDirectory(root, path.dirname(target), filesystem, false);
	if (!filesystem.lstat || !filesystem.realpath) {throw new HypothesisStoreError('Hypothesis storage requires filesystem realpath/lstat support.');}
	try {
		const stat = await filesystem.lstat(target);
		if (stat.isSymbolicLink() || !stat.isFile()) {throw new HypothesisStoreError('Hypothesis store artifacts must be regular files, not symlinks.');}
		if (!samePhysicalPath(await filesystem.realpath(target), target)) {throw new HypothesisStoreError('Hypothesis store artifact resolves outside its expected workspace path.');}
	} catch (error) { if (!allowMissing || !isMissing(error)) {throw error;} }
}
async function isSafeStoreRelativeFile(root: string, relative: string, filesystem: FileSystem): Promise<boolean> {
	if (!filesystem.lstat || !filesystem.realpath || !relative || path.isAbsolute(relative) || relative.includes('\\') || relative.split('/').some((part) => !part || part === '..')) {return false;}
	let current = root;
	for (const part of relative.split('/')) {
		current = path.join(current, part);
		try { const stat = await filesystem.lstat(current); if (stat.isSymbolicLink()) {return false;} }
		catch { return false; }
	}
	try {
		const actual = await filesystem.realpath(current);
		const rel = path.relative(root, actual);
		const stat = await filesystem.lstat(actual);
		return stat.isFile() && Boolean(rel) && rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
	} catch { return false; }
}
function isStore(value: unknown): value is HypothesisStore {
	if (!isRecord(value) || value.version !== 1 || value.scoringPolicyVersion !== 1 || (value.generation !== undefined && (!Number.isSafeInteger(value.generation) || Number(value.generation) < 0)) || (value.updatedAt !== '' && !isTimestamp(value.updatedAt)) || !Array.isArray(value.hypotheses) || !Array.isArray(value.snapshots) || value.hypotheses.length > MAX_HYPOTHESES || value.snapshots.length > MAX_SNAPSHOTS) {return false;}
	if (Object.keys(value).some((key) => !['version','scoringPolicyVersion','generation','updatedAt','hypotheses','snapshots'].includes(key))) {return false;}
	return value.hypotheses.every(isHypothesis) && value.snapshots.every((item) => isRecord(item) && Object.keys(item).every((key) => ['id','scanId','capturedAt','fingerprint'].includes(key)) && typeof item.id === 'string' && item.id.length <= 80 && typeof item.scanId === 'string' && item.scanId.length <= 128 && isTimestamp(item.capturedAt) && typeof item.fingerprint === 'string' && /^[a-f0-9]{64}$/.test(item.fingerprint));
}
function validateStore(store: HypothesisStore): void { if (!isStore(store)) {throw new HypothesisStoreError('Hypothesis store exceeds bounds or contains invalid data; existing data was preserved.');} }
function isHypothesis(value: unknown): value is SecurityHypothesis {
	if (!isRecord(value)) {return false;}
	if (typeof value.id !== 'string' || value.id.length > 80 || !isBoundedString(value.title, 160, 1)
		|| !isBoundedString(value.description, 1000, 1) || !isBoundedString(value.rationale, 1200, 1)
		|| !['proposed','investigating','validated','rejected','dismissed','stale','unsubstantiated'].includes(String(value.status))
		|| !isBoundedString(value.snapshotId, 80, 1) || !isTimestamp(value.createdAt) || !isTimestamp(value.updatedAt)
		|| !Array.isArray(value.evidence) || value.evidence.length === 0 || value.evidence.length > 20
		|| !Array.isArray(value.contradictions) || value.contradictions.length > 20
		|| !isStringList(value.assumptions, 10, 500) || !isStringList(value.verificationSteps, 10, 500)
		|| !isAsset(value.asset) || !isConfidence(value.confidence)) {return false;}
	const allowedKeys = new Set(['id','title','description','weakness','attackPath','asset','evidence','rationale','confidence','assumptions','contradictions','impact','verificationSteps','status','evidenceFreshness','createdAt','updatedAt','snapshotId','relatedFindingIds','relatedRuleIds','relatedHypothesisIds','origin','review']);
	if (Object.keys(value).some((key) => !allowedKeys.has(key))) {return false;}
	if (value.evidenceFreshness !== undefined && !['current','stale','provenance-unavailable'].includes(String(value.evidenceFreshness))) {return false;}
	if (![...value.evidence, ...value.contradictions].every(isEvidenceRef)) {return false;}
	if (value.review !== undefined && !isReview(value.review)) {return false;}
	if (value.origin !== undefined && (!isRecord(value.origin) || Object.keys(value.origin).some((key) => !['kind','preparationId','providerId','modelId'].includes(key)) || value.origin.kind !== 'ai-proposal' || !isBoundedString(value.origin.preparationId, 80, 1) || !isBoundedString(value.origin.providerId, 32, 1) || !isBoundedString(value.origin.modelId, 128, 1))) {return false;}
	const idLists = [value.relatedFindingIds, value.relatedRuleIds, value.relatedHypothesisIds];
	return idLists.every((items) => Array.isArray(items) && items.length <= 100 && items.every((item: unknown) => typeof item === 'string' && item.length <= 200))
		&& (value.weakness === undefined || isBoundedString(value.weakness, 120))
		&& (value.attackPath === undefined || isBoundedString(value.attackPath, 500))
		&& (value.impact === undefined || isBoundedString(value.impact, 500));
}
function isRecord(value: unknown): value is Record<string, any> { return Boolean(value && typeof value === 'object' && !Array.isArray(value)); }
function isTimestamp(value: unknown): value is string { return typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value)); }
function isBoundedString(value: unknown, max: number, min = 0): value is string { return typeof value === 'string' && value.length >= min && value.length <= max; }
function isStringList(value: unknown, maxItems: number, maxLength: number): value is string[] { return Array.isArray(value) && value.length <= maxItems && value.every((item) => isBoundedString(item, maxLength)); }
function throwIfCancelled(signal?: AbortSignal): void {if (signal?.aborted) {throw Object.assign(new Error('Core request cancelled.'), { code: 'CORE_REQUEST_CANCELLED' });}}
function isAsset(value: unknown): boolean {
	return isRecord(value) && Object.keys(value).every((key) => ['kind','id','label'].includes(key))
		&& ['file','dependency','service','project'].includes(String(value.kind))
		&& isBoundedString(value.id, 300, 1) && (value.label === undefined || isBoundedString(value.label, 160));
}
function isConfidence(value: unknown): boolean {
	return isRecord(value) && Object.keys(value).every((key) => ['band','factors','policyVersion'].includes(key))
		&& ['low','moderate','high'].includes(String(value.band)) && value.policyVersion === 1
		&& Array.isArray(value.factors) && value.factors.length <= 12 && value.factors.every(isConfidenceFactor);
}
function isEvidenceRef(value: unknown): boolean {
	if (!isRecord(value) || Object.keys(value).some((key) => !['id','kind','source','file','startLine','endLine','contentHash','fileContentHash','findingId','ruleId','relationshipId','observedAt','freshness'].includes(key))) {return false;}
	if (!isBoundedString(value.id, 500, 1) || !['finding','relationship','source-span'].includes(String(value.kind)) || !isBoundedString(value.source, 100, 1) || !isTimestamp(value.observedAt) || !['current','stale'].includes(String(value.freshness))) {return false;}
	if (value.file !== undefined && (!isBoundedString(value.file, 300, 1) || path.isAbsolute(value.file) || /^[a-z]:/i.test(value.file) || value.file.startsWith('/') || value.file.includes('\\') || value.file.split('/').some((part: string) => part === '..' || part === ''))) {return false;}
	if (value.startLine !== undefined && (!Number.isInteger(value.startLine) || value.startLine < 1 || value.startLine > 10_000_000)) {return false;}
	if (value.endLine !== undefined && (!Number.isInteger(value.endLine) || value.endLine < (value.startLine ?? 1) || value.endLine > 10_000_000)) {return false;}
	if (value.contentHash !== undefined && (!isBoundedString(value.contentHash, 64, 64) || !/^[a-f0-9]{64}$/.test(value.contentHash))) {return false;}
	if (value.fileContentHash !== undefined && (!isBoundedString(value.fileContentHash, 64, 64) || !/^[a-f0-9]{64}$/.test(value.fileContentHash))) {return false;}
	for (const key of ['findingId','ruleId','relationshipId']) {if (value[key] !== undefined && !isBoundedString(value[key], 200, 1)) {return false;}}
	if (value.kind === 'finding') {return isBoundedString(value.findingId, 200, 1) && isBoundedString(value.ruleId, 200, 1);}
	if (value.kind === 'relationship') {return isBoundedString(value.relationshipId, 200, 1);}
	return isBoundedString(value.file, 300, 1) && Number.isInteger(value.startLine) && Number.isInteger(value.endLine) && isBoundedString(value.contentHash, 64, 64) && isBoundedString(value.findingId, 200, 1);
}
function isReview(value: unknown): boolean {
	return isRecord(value) && Object.keys(value).every((key) => ['at','action','note','evidenceRefs'].includes(key))
		&& isTimestamp(value.at) && ['investigate','validate','reject','dismiss','reopen'].includes(String(value.action))
		&& (value.note === undefined || isBoundedString(value.note, 500))
		&& (value.evidenceRefs === undefined || isStringList(value.evidenceRefs, 20, 200));
}
function isConfidenceFactor(value: unknown): boolean {
	if (!isRecord(value) || Object.keys(value).some((key) => !['kind','value','detail'].includes(key)) || typeof value.kind !== 'string' || typeof value.value !== 'string' || typeof value.detail !== 'string' || value.detail.length > 300) {return false;}
	const values: Record<string, string[]> = { 'direct-evidence': ['verified-source-span','scanner-finding'], corroboration: ['single-source-family','multiple-source-families'], relationship: ['heuristic','explicit'], freshness: ['current','stale'], contradiction: ['present','none-observed'], preconditions: ['known','unknown'] };
	return Boolean(values[value.kind]?.includes(value.value));
}

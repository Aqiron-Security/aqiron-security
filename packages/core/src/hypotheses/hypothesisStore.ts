import * as crypto from 'node:crypto';
import * as path from 'node:path';
import { FileSystem } from '../shared/platform';
import { HypothesisReviewInput, HypothesisSnapshot, HypothesisStatus, HypothesisStore, SecurityHypothesis } from './contracts';

const MAX_HYPOTHESES = 500;
const MAX_SNAPSHOTS = 20;
const MAX_STORE_CHARS = 5_000_000;
const locks = new Map<string, Promise<void>>();

export class HypothesisStoreError extends Error {
	readonly code = 'HYPOTHESIS_STORE_INVALID';
	constructor(message: string) { super(message); this.name = 'HypothesisStoreError'; }
}

export class HypothesisStoreService {
	constructor(private readonly filesystem: FileSystem) {}

	async list(root: string): Promise<HypothesisStore> {
		return await withWorkspaceLock(root, this.filesystem, async () => {
			const store = await this.read(root);
			const refreshed = await this.markChangedEvidenceStale(root, store);
			if (refreshed !== store) {await this.write(root, refreshed);}
			return refreshed;
		});
	}

	async mergeGeneration(root: string, snapshot: HypothesisSnapshot, candidates: SecurityHypothesis[], cancelled: () => boolean): Promise<HypothesisStore> {
		return await withWorkspaceLock(root, this.filesystem, async () => {
			if (cancelled()) {throw new Error('Core request cancelled.');}
			const current = await this.read(root);
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
			const next: HypothesisStore = { version: 1, scoringPolicyVersion: 1, updatedAt: new Date().toISOString(), hypotheses, snapshots };
			validateStore(next);
			if (cancelled()) {throw new Error('Core request cancelled.');}
			await this.write(root, next);
			return next;
		});
	}

	async review(root: string, input: HypothesisReviewInput, now = new Date().toISOString()): Promise<SecurityHypothesis> {
		return await withWorkspaceLock(root, this.filesystem, async () => {
			const original = await this.read(root);
			const store = await this.markChangedEvidenceStale(root, original);
			if (store !== original) {await this.write(root, store);}
			const index = store.hypotheses.findIndex((hypothesis) => hypothesis.id === input.hypothesisId);
			if (index < 0) {throw Object.assign(new Error('Hypothesis was not found in this workspace.'), { code: 'HYPOTHESIS_NOT_FOUND' });}
			const hypothesis = store.hypotheses[index];
			const nextStatus = transition(hypothesis.status, input.action);
			if (input.action === 'validate' && (!Array.isArray(input.evidenceRefs) || input.evidenceRefs.length === 0 || !input.evidenceRefs.some((id) => hypothesis.evidence.some((ref) => ref.id === id && ref.freshness === 'current')))) {
				throw Object.assign(new Error('Validation requires at least one current supporting evidence reference.'), { code: 'HYPOTHESIS_EVIDENCE_REQUIRED' });
			}
			if (input.evidenceRefs?.some((id) => ![...hypothesis.evidence, ...hypothesis.contradictions].some((ref) => ref.id === id && ref.freshness === 'current'))) {
				throw Object.assign(new Error('Review references evidence that is not current for this hypothesis.'), { code: 'HYPOTHESIS_INVALID_EVIDENCE' });
			}
			const updated: SecurityHypothesis = { ...hypothesis, status: nextStatus, updatedAt: now, review: { at: now, action: input.action, ...(input.note ? { note: input.note.slice(0, 500) } : {}), ...(input.evidenceRefs?.length ? { evidenceRefs: [...new Set(input.evidenceRefs)].slice(0, 20) } : {}) } };
			const hypotheses = [...store.hypotheses]; hypotheses[index] = updated;
			await this.write(root, { ...store, updatedAt: now, hypotheses });
			return updated;
		});
	}

	private async markChangedEvidenceStale(root: string, store: HypothesisStore): Promise<HypothesisStore> {
		let changed = false;
		const hypotheses = await Promise.all(store.hypotheses.map(async (hypothesis) => {
			if (!['proposed', 'investigating', 'dismissed'].includes(hypothesis.status)) {return hypothesis;}
			for (const ref of hypothesis.evidence.filter((item) => item.kind === 'source-span')) {
				if (!ref.file || !ref.contentHash || !Number.isInteger(ref.startLine) || !Number.isInteger(ref.endLine) || ref.startLine! < 1) { changed = true; return { ...hypothesis, status: 'stale' as const, updatedAt: new Date().toISOString() }; }
				let content: string;
				try { content = await this.filesystem.readFile(path.resolve(root, ref.file), 'utf8'); }
				catch { changed = true; return { ...hypothesis, status: 'stale' as const, updatedAt: new Date().toISOString() }; }
				const lines = content.split(/\r?\n/);
				if (ref.endLine! > lines.length) { changed = true; return { ...hypothesis, status: 'stale' as const, updatedAt: new Date().toISOString() }; }
				const excerpt = lines.slice(ref.startLine! - 1, Math.min(ref.endLine!, ref.startLine! + 2)).join('\n').slice(0, 2_000);
				if (crypto.createHash('sha256').update(excerpt).digest('hex') !== ref.contentHash) { changed = true; return { ...hypothesis, status: 'stale' as const, updatedAt: new Date().toISOString() }; }
			}
			return hypothesis;
		}));
		return changed ? { ...store, updatedAt: new Date().toISOString(), hypotheses } : store;
	}

	private async read(root: string): Promise<HypothesisStore> {
		const file = storePath(root);
		await this.recoverBackup(file);
		let raw: string;
		try { raw = await this.filesystem.readFile(file, 'utf8'); }
		catch (error) { if (isMissing(error)) {return emptyStore();} throw error; }
		if (Buffer.byteLength(raw, 'utf8') > MAX_STORE_CHARS) {throw new HypothesisStoreError(`Hypothesis store at ${file} exceeds the 5 MB safety limit. Preserve the file and recover it before writing.`);}
		let parsed: unknown;
		try { parsed = JSON.parse(raw) as unknown; } catch { throw new HypothesisStoreError(`Hypothesis store at ${file} contains invalid JSON. Preserve the file and recover it before writing.`); }
		if (!isStore(parsed)) {throw new HypothesisStoreError(`Hypothesis store at ${file} has an invalid or unsupported schema. Preserve the file and recover it before writing.`);}
		return parsed;
	}

	private async write(root: string, store: HypothesisStore): Promise<void> {
		const directory = path.dirname(storePath(root));
		await this.filesystem.mkdir(directory, { recursive: true });
		const target = storePath(root);
		const temporary = `${target}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
		const serialized = JSON.stringify(store, null, 2);
		if (Buffer.byteLength(serialized, 'utf8') > MAX_STORE_CHARS) {throw new HypothesisStoreError('Hypothesis store exceeds the 5 MB safety limit; existing data was preserved.');}
		await this.filesystem.writeFile(temporary, serialized, 'utf8');
		if (!(await this.filesystem.exists(target))) {
			await this.filesystem.rename(temporary, target);
			return;
		}
		const backup = `${target}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.bak`;
		await this.filesystem.rename(target, backup);
		try {
			await this.filesystem.rename(temporary, target);
		} catch (error) {
			try { await this.filesystem.rename(backup, target); }
			catch { throw Object.assign(new Error(`Could not replace hypothesis store. The previous store is preserved at ${backup}; recover it before continuing.`), { code: 'HYPOTHESIS_STORE_RECOVERY_REQUIRED' }); }
			throw error;
		}
		try { await this.filesystem.unlink?.(backup); } catch { /* committed replacement is valid; orphan backup remains recoverable */ }
	}

	private async recoverBackup(target: string): Promise<void> {
		if (await this.filesystem.exists(target)) {return;}
		let entries: Array<string | { name: string }>;
		try { entries = await this.filesystem.readdir(path.dirname(target)); } catch { return; }
		const prefix = `${path.basename(target)}.`;
		const backups = entries.map((entry) => typeof entry === 'string' ? entry : entry.name).filter((name) => name.startsWith(prefix) && name.endsWith('.bak')).sort();
		if (backups.length > 0) {await this.filesystem.rename(path.join(path.dirname(target), backups[backups.length - 1]), target);}
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
	if (previous.status === 'validated' || previous.status === 'rejected') {return previous;}
	if (previous.status === 'dismissed' || previous.status === 'investigating') {return { ...candidate, status: previous.status, createdAt: previous.createdAt, review: previous.review };}
	if (previous.status === 'stale') {
		const restoredStatus = previous.review?.action === 'dismiss' ? 'dismissed' : previous.review?.action === 'investigate' ? 'investigating' : candidate.status;
		return { ...candidate, status: restoredStatus, createdAt: previous.createdAt, review: previous.review };
	}
	return { ...candidate, createdAt: previous.createdAt };
}

function emptyStore(): HypothesisStore { return { version: 1, scoringPolicyVersion: 1, updatedAt: '', hypotheses: [], snapshots: [] }; }
function storePath(root: string): string { return path.join(path.resolve(root), '.aqiron-security', 'hypotheses.json'); }
async function withWorkspaceLock<T>(root: string, filesystem: FileSystem, task: () => Promise<T>): Promise<T> {
	const resolvedRoot = path.resolve(root);
	const key = process.platform === 'win32' ? resolvedRoot.toLowerCase() : resolvedRoot;
	const previous = locks.get(key) ?? Promise.resolve();
	let release!: () => void;
	const current = new Promise<void>((resolve) => { release = resolve; });
	const queued = previous.then(() => current);
	locks.set(key, queued);
	await previous;
	let releaseFileLock: (() => Promise<void>) | undefined;
	try {
		await filesystem.mkdir(path.dirname(storePath(root)), { recursive: true });
		releaseFileLock = await acquireWorkspaceLock(path.resolve(root), filesystem);
		return await task();
	}
	finally { await releaseFileLock?.(); release(); if (locks.get(key) === queued) {locks.delete(key);} }
}
async function acquireWorkspaceLock(root: string, filesystem: FileSystem): Promise<() => Promise<void>> {
	const lockPath = `${storePath(root)}.lock`;
	const deadline = Date.now() + 15_000;
	while (Date.now() < deadline) {
		try {
			await filesystem.mkdir(lockPath);
			return async () => { try { await filesystem.rmdir?.(lockPath); } catch { /* stale-lock recovery handles interrupted releases */ } };
		} catch (error) {
			if (!isAlreadyExists(error)) {throw error;}
			try {
				const stat = await filesystem.stat(lockPath);
				if (Date.now() - stat.mtimeMs > 120_000) {
					const stale = `${lockPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.stale`;
					await filesystem.rename(lockPath, stale);
					try { await filesystem.rmdir?.(stale); } catch { /* an empty stale lock may be cleaned on a later pass */ }
					continue;
				}
			} catch (inspectError) {
				if (!isMissing(inspectError) && !isAlreadyExists(inspectError)) {throw inspectError;}
			}
			await new Promise((resolve) => setTimeout(resolve, 25));
		}
	}
	throw Object.assign(new Error(`Hypothesis store is locked by another Core process: ${lockPath}`), { code: 'HYPOTHESIS_STORE_LOCKED' });
}
function isMissing(error: unknown): boolean { return Boolean(error && typeof error === 'object' && 'code' in error && (error as { code?: unknown }).code === 'ENOENT'); }
function isAlreadyExists(error: unknown): boolean { return Boolean(error && typeof error === 'object' && 'code' in error && (error as { code?: unknown }).code === 'EEXIST'); }
function isStore(value: unknown): value is HypothesisStore {
	if (!isRecord(value) || value.version !== 1 || value.scoringPolicyVersion !== 1 || (value.updatedAt !== '' && !isTimestamp(value.updatedAt)) || !Array.isArray(value.hypotheses) || !Array.isArray(value.snapshots) || value.hypotheses.length > MAX_HYPOTHESES || value.snapshots.length > MAX_SNAPSHOTS) {return false;}
	if (Object.keys(value).some((key) => !['version','scoringPolicyVersion','updatedAt','hypotheses','snapshots'].includes(key))) {return false;}
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
	const allowedKeys = new Set(['id','title','description','weakness','attackPath','asset','evidence','rationale','confidence','assumptions','contradictions','impact','verificationSteps','status','createdAt','updatedAt','snapshotId','relatedFindingIds','relatedRuleIds','relatedHypothesisIds','review']);
	if (Object.keys(value).some((key) => !allowedKeys.has(key))) {return false;}
	if (![...value.evidence, ...value.contradictions].every(isEvidenceRef)) {return false;}
	if (value.review !== undefined && !isReview(value.review)) {return false;}
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
	if (!isRecord(value) || Object.keys(value).some((key) => !['id','kind','source','file','startLine','endLine','contentHash','findingId','ruleId','relationshipId','observedAt','freshness'].includes(key))) {return false;}
	if (!isBoundedString(value.id, 500, 1) || !['finding','relationship','source-span'].includes(String(value.kind)) || !isBoundedString(value.source, 100, 1) || !isTimestamp(value.observedAt) || !['current','stale'].includes(String(value.freshness))) {return false;}
	if (value.file !== undefined && (!isBoundedString(value.file, 300, 1) || path.isAbsolute(value.file) || /^[a-z]:/i.test(value.file) || value.file.startsWith('/') || value.file.includes('\\') || value.file.split('/').some((part: string) => part === '..' || part === ''))) {return false;}
	if (value.startLine !== undefined && (!Number.isInteger(value.startLine) || value.startLine < 1 || value.startLine > 10_000_000)) {return false;}
	if (value.endLine !== undefined && (!Number.isInteger(value.endLine) || value.endLine < (value.startLine ?? 1) || value.endLine > 10_000_000)) {return false;}
	if (value.contentHash !== undefined && (!isBoundedString(value.contentHash, 64, 64) || !/^[a-f0-9]{64}$/.test(value.contentHash))) {return false;}
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

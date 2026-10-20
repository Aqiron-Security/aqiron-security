import * as crypto from 'node:crypto';
import * as path from 'node:path';
import { FileSystem } from '../shared/platform';
import { HypothesisReviewInput, HypothesisReviewResult, HypothesisSnapshot, HypothesisStatus, HypothesisStore, SecurityHypothesis } from './contracts';
import { hashSourceSpan } from './hypothesisEngine';

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
			const next: HypothesisStore = { version: 1, scoringPolicyVersion: 1, updatedAt: new Date().toISOString(), hypotheses, snapshots };
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
			if (hypothesis.evidenceFreshness === 'stale' || hypothesis.status === 'stale') {return { hypothesis, applied: false, diagnostic: 'stale-evidence' };}
			const nextStatus = transition(hypothesis.status, input.action);
			if (input.action === 'validate' && (!Array.isArray(input.evidenceRefs) || input.evidenceRefs.length === 0 || !input.evidenceRefs.some((id) => hypothesis.evidence.some((ref) => ref.id === id && ref.freshness === 'current')))) {
				throw Object.assign(new Error('Validation requires at least one current supporting evidence reference.'), { code: 'HYPOTHESIS_EVIDENCE_REQUIRED' });
			}
			if (input.evidenceRefs?.some((id) => ![...hypothesis.evidence, ...hypothesis.contradictions].some((ref) => ref.id === id && ref.freshness === 'current'))) {
				throw Object.assign(new Error('Review references evidence that is not current for this hypothesis.'), { code: 'HYPOTHESIS_INVALID_EVIDENCE' });
			}
			const updated: SecurityHypothesis = { ...hypothesis, status: nextStatus, updatedAt: now, review: { at: now, action: input.action, ...(input.note ? { note: input.note.slice(0, 500) } : {}), ...(input.evidenceRefs?.length ? { evidenceRefs: [...new Set(input.evidenceRefs)].slice(0, 20) } : {}) } };
			const hypotheses = [...store.hypotheses]; hypotheses[index] = updated;
			await this.write(safeRoot, { ...store, updatedAt: now, hypotheses });
			return { hypothesis: updated, applied: true };
		});
	}

	private async markChangedEvidenceStale(root: string, store: HypothesisStore): Promise<HypothesisStore> {
		let changed = false;
		const hypotheses = await Promise.all(store.hypotheses.map(async (hypothesis) => {
			if (!['proposed', 'investigating', 'dismissed', 'validated', 'rejected'].includes(hypothesis.status) || hypothesis.evidenceFreshness === 'stale') {return hypothesis;}
			for (const ref of hypothesis.evidence.filter((item) => item.kind === 'source-span' && item.freshness === 'current')) {
				if (!ref.file || !ref.contentHash || !Number.isInteger(ref.startLine) || !Number.isInteger(ref.endLine) || ref.startLine! < 1) { changed = true; return staleEvidence(hypothesis); }
				let content: string;
				if (!await isSafeStoreRelativeFile(root, ref.file, this.filesystem)) { changed = true; return staleEvidence(hypothesis); }
				try { const stat = await this.filesystem.stat(path.resolve(root, ref.file)); if (!stat.isFile() || stat.size > 10_000_000) { changed = true; return staleEvidence(hypothesis); } } catch { changed = true; return staleEvidence(hypothesis); }
				try { content = await this.filesystem.readFile(path.resolve(root, ref.file), 'utf8'); }
				catch { changed = true; return staleEvidence(hypothesis); }
				let currentHash: string;
				try { currentHash = hashSourceSpan(content, ref.startLine!, ref.endLine!); } catch { changed = true; return staleEvidence(hypothesis); }
				if (currentHash !== ref.contentHash) { changed = true; return staleEvidence(hypothesis); }
			}
			return hypothesis;
		}));
		return changed ? { ...store, updatedAt: new Date().toISOString(), hypotheses } : store;
	}

	private async read(root: string): Promise<HypothesisStore> {
		const file = storePath(root);
		await assertSafeStoreTarget(root, file, this.filesystem, true);
		await this.recoverBackup(file);
		await assertSafeStoreTarget(root, file, this.filesystem, true);
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
		await assertSafeStoreDirectory(root, directory, this.filesystem, true);
		const target = storePath(root);
		await assertSafeStoreTarget(root, target, this.filesystem, true);
		const temporary = `${target}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
		const serialized = JSON.stringify(store, null, 2);
		if (Buffer.byteLength(serialized, 'utf8') > MAX_STORE_CHARS) {throw new HypothesisStoreError('Hypothesis store exceeds the 5 MB safety limit; existing data was preserved.');}
		if (!this.filesystem.writeFileExclusive) {throw new HypothesisStoreError('Filesystem exclusive-create support is required for safe hypothesis persistence.');}
		await this.filesystem.writeFileExclusive(temporary, serialized, 'utf8');
		await assertSafeStoreTarget(root, temporary, this.filesystem, false);
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
		const backups = entries.map((entry) => typeof entry === 'string' ? entry : entry.name).filter((name) => name.startsWith(prefix) && name.endsWith('.bak')).sort().reverse();
		for (const backupName of backups) {
			const backup = path.join(path.dirname(target), backupName);
			try { await assertSafeStoreTarget(path.dirname(path.dirname(target)), backup, this.filesystem, false); }
			catch { continue; }
			await this.filesystem.rename(backup, target);
			return;
		}
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

function emptyStore(): HypothesisStore { return { version: 1, scoringPolicyVersion: 1, updatedAt: '', hypotheses: [], snapshots: [] }; }
function storePath(root: string): string { return path.join(path.resolve(root), '.aqiron-security', 'hypotheses.json'); }
function staleEvidence(hypothesis: SecurityHypothesis): SecurityHypothesis {
	const historical = hypothesis.status === 'validated' || hypothesis.status === 'rejected';
	return { ...hypothesis, evidenceFreshness: 'stale', evidence: hypothesis.evidence.map((ref) => ({ ...ref, freshness: 'stale' })), updatedAt: new Date().toISOString(), ...(!historical ? { status: 'stale' as const } : {}) };
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
	finally { await releaseFileLock?.(); release(); if (locks.get(key) === queued) {locks.delete(key);} }
}
async function acquireWorkspaceLock(root: string, filesystem: FileSystem): Promise<() => Promise<void>> {
	const lockPath = `${storePath(root)}.lock`;
	const deadline = Date.now() + 15_000;
	const token = crypto.randomBytes(16).toString('hex');
	if (!filesystem.writeFileExclusive || !filesystem.unlink || !filesystem.rmdir || !filesystem.lstat || !filesystem.realpath) {throw new HypothesisStoreError('Hypothesis locks require exclusive create, lstat, realpath, unlink and rmdir filesystem support.');}
	while (Date.now() < deadline) {
		let createdLock = false;
		try {
			await assertSafeStoreTarget(root, storePath(root), filesystem, true);
			await filesystem.mkdir(lockPath);
			createdLock = true;
			const lockStat = await filesystem.lstat!(lockPath);
			if (lockStat.isSymbolicLink() || !lockStat.isDirectory() || !samePhysicalPath(await filesystem.realpath!(lockPath), lockPath)) {throw new HypothesisStoreError('Hypothesis lock path is not a safe workspace directory.');}
			const ownerPath = path.join(lockPath, 'owner.json');
			if (!filesystem.writeFileExclusive) {throw new Error('Filesystem exclusive-create support is required for lock ownership.');}
			await filesystem.writeFileExclusive(ownerPath, JSON.stringify({ pid: process.pid, token }), 'utf8');
			await assertRegularLockOwner(ownerPath, filesystem);
			return async () => {
				try {
				const lockStat = await filesystem.lstat!(lockPath);
				if (lockStat.isSymbolicLink() || !lockStat.isDirectory() || !samePhysicalPath(await filesystem.realpath!(lockPath), lockPath)) {return;}
				await assertRegularLockOwner(ownerPath, filesystem);
					const owner = JSON.parse(await filesystem.readFile(ownerPath, 'utf8')) as { token?: unknown };
					if (owner.token === token) { await filesystem.unlink!(ownerPath); await filesystem.rmdir!(lockPath); }
				} catch { /* ownership changed or storage is unavailable; never remove another owner's lock */ }
			};
		} catch (error) {
			if (createdLock) {
				try {
					const lockStat = await filesystem.lstat!(lockPath);
					if (lockStat.isSymbolicLink() || !lockStat.isDirectory() || !samePhysicalPath(await filesystem.realpath!(lockPath), lockPath)) {throw new Error('Lock path changed during acquisition.');}
					const ownerPath = path.join(lockPath, 'owner.json');
					try { await assertRegularLockOwner(ownerPath, filesystem); const owner = JSON.parse(await filesystem.readFile(ownerPath, 'utf8')) as { token?: unknown }; if (owner.token === token) { await filesystem.unlink!(ownerPath); } } catch (cleanupError) { if (!isMissing(cleanupError)) { throw cleanupError; } }
					await filesystem.rmdir!(lockPath);
				} catch { /* leave uncertain ownership untouched */ }
			}
			if (!isAlreadyExists(error)) {throw error;}
			try {
				if (!filesystem.lstat) {throw new Error('Filesystem lstat support is required for lock ownership.');}
				const lockStat = await filesystem.lstat(lockPath);
			if (lockStat.isSymbolicLink() || !lockStat.isDirectory() || !samePhysicalPath(await filesystem.realpath!(lockPath), lockPath)) {throw new Error('Hypothesis lock path is not a real directory.');}
				const ownerPath = path.join(lockPath, 'owner.json');
				let owner: { pid?: unknown; token?: unknown } | undefined;
				try { await assertRegularLockOwner(ownerPath, filesystem); }
				catch (ownerStatError) { if (!isMissing(ownerStatError)) { throw ownerStatError; } }
				try { owner = JSON.parse(await filesystem.readFile(ownerPath, 'utf8')) as { pid?: unknown; token?: unknown }; } catch (ownerError) { if (!isMissing(ownerError)) { throw ownerError; } }
				const staleOwner = Boolean(owner && Number.isInteger(owner.pid) && Number(owner.pid) > 0 && !isProcessAlive(owner.pid));
				if (staleOwner) {
					const stale = `${lockPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.stale`;
					await filesystem.rename(lockPath, stale);
					try { await filesystem.unlink!(path.join(stale, 'owner.json')); await filesystem.rmdir!(stale); } catch { /* recovery cleanup is retried on the next pass */ }
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
	const allowedKeys = new Set(['id','title','description','weakness','attackPath','asset','evidence','rationale','confidence','assumptions','contradictions','impact','verificationSteps','status','evidenceFreshness','createdAt','updatedAt','snapshotId','relatedFindingIds','relatedRuleIds','relatedHypothesisIds','review']);
	if (Object.keys(value).some((key) => !allowedKeys.has(key))) {return false;}
	if (value.evidenceFreshness !== undefined && !['current','stale'].includes(String(value.evidenceFreshness))) {return false;}
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

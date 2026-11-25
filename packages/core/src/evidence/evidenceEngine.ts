import * as crypto from 'node:crypto';
import * as path from 'node:path';
import type { FileSystem } from '../shared/platform';
import { createSourceLineIndex, hashSourceContent } from '../shared/sourceProvenance';
import type { FindingSourceProvenance } from '../shared/sourceProvenance';
import { withWorkspaceLock } from '../hypotheses/hypothesisStore';

export const EVIDENCE_SCHEMA_VERSION = 1;
export const EVIDENCE_COLLECTOR_ID = 'aqiron.native-scanner';
export const EVIDENCE_COLLECTOR_VERSION = '1';
export const MAX_EVIDENCE_RECORDS = 20_000;
export const MAX_EVIDENCE_STORE_BYTES = 5_000_000;
const MAX_SOURCE_FILE_BYTES = 10_000_000;
const MAX_FRESHNESS_BYTES = 50_000_000;

export interface SourceSpanObservation {
	readonly id: string;
	readonly schemaVersion: 1;
	readonly kind: 'source_span';
	readonly workspaceIdentity: string;
	readonly scanId: string;
	/** Finding identity supplied only by Core's native scanner provenance. Absent on legacy observations. */
	readonly originatingFindingId?: string;
	readonly collector: { readonly id: string; readonly version: string };
	readonly observedAt: string;
	readonly source: { readonly path: string; readonly startLine: number; readonly endLine: number; readonly fileContentHash: string; readonly spanContentHash: string };
}

export type EvidenceFreshness =
	| { status: 'current'; reason?: undefined }
	| { status: 'stale'; reason: 'content-changed' | 'span-changed' }
	| { status: 'unavailable'; reason: 'missing' | 'unsafe-path' | 'read-failed' | 'limit-exceeded' | 'invalid-encoding' }
	| { status: 'not-rechecked'; reason?: undefined };

interface EvidenceStore { version: 1; observations: SourceSpanObservation[] }

/** Core-owned first-stage source evidence persistence and on-demand freshness. */
export class EvidenceEngine {
	constructor(private readonly filesystem: FileSystem) {}

	async captureScan(root: string, scanId: string, provenance: readonly FindingSourceProvenance[]): Promise<SourceSpanObservation[]> {
		if (!/^[A-Za-z0-9._:-]{1,128}$/.test(scanId) || provenance.length > 10_000) { throw new Error('Evidence scan context is invalid.'); }
		try { return await withWorkspaceLock(root, this.filesystem, async (safeRoot) => {
			const existing = await this.read(safeRoot);
			const additions: SourceSpanObservation[] = [];
			let bytesRead = 0;
			for (const item of provenance) {
				if (additions.length + existing.observations.length >= MAX_EVIDENCE_RECORDS || !validProvenance(item)) { continue; }
				const relative = normalizeRelative(item.file);
				if (!relative) { continue; }
				const absolute = path.resolve(safeRoot, relative);
				if (!await safeFile(safeRoot, relative, this.filesystem)) { continue; }
				try {
					const stat = await this.filesystem.stat(absolute);
					if (!stat.isFile() || stat.size > MAX_SOURCE_FILE_BYTES || bytesRead + stat.size > MAX_FRESHNESS_BYTES || !this.filesystem.readFileBoundedBytes) { continue; }
					const bytes = await this.filesystem.readFileBoundedBytes(absolute, Math.min(MAX_SOURCE_FILE_BYTES, MAX_FRESHNESS_BYTES - bytesRead));
					bytesRead += bytes.byteLength;
					if (bytes.byteLength > MAX_SOURCE_FILE_BYTES || bytesRead > MAX_FRESHNESS_BYTES) { continue; }
					let content: string;
					try { content = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { continue; }
					const lineIndex = createSourceLineIndex(content);
					const spanContentHash = lineIndex.hashSpan(item.startLine, item.endLine);
					const fileContentHash = hashSourceContent(content);
					if (spanContentHash !== item.contentHash || fileContentHash !== item.sourceContentHash) { continue; }
					additions.push(Object.freeze({ id: `ev1_${crypto.randomUUID()}`, schemaVersion: 1, kind: 'source_span', workspaceIdentity: safeRoot,
						scanId, originatingFindingId: item.findingId, collector: Object.freeze({ id: EVIDENCE_COLLECTOR_ID, version: EVIDENCE_COLLECTOR_VERSION }), observedAt: item.observedAt,
						source: Object.freeze({ path: relative, startLine: item.startLine, endLine: item.endLine, fileContentHash, spanContentHash }) }));
				} catch { /* unsafe, missing, oversized, or malformed scanner provenance is not evidence */ }
			}
			if (additions.length) { await this.write(safeRoot, { version: 1, observations: [...existing.observations, ...additions] }); }
			return additions;
		}); }
		catch (cause) { throw Object.assign(new Error('Core could not safely persist source evidence.', { cause }), { code: 'EVIDENCE_PERSISTENCE_FAILED' }); }
	}

	async get(root: string, evidenceId: string): Promise<SourceSpanObservation | undefined> {
		return await withWorkspaceLock(root, this.filesystem, async (safeRoot) => (await this.read(safeRoot)).observations.find((item) => item.id === evidenceId));
	}

	/** Resolve only observations carrying Core-captured finding association metadata. */
	async findForFinding(root: string, scanId: string, findingId: string): Promise<SourceSpanObservation[]> {
		return await withWorkspaceLock(root, this.filesystem, async (safeRoot) => (await this.read(safeRoot)).observations
			.filter((item) => item.workspaceIdentity === safeRoot && item.scanId === scanId && item.originatingFindingId === findingId));
	}

	async list(root: string, options: { scanId?: string; limit?: number; beforeId?: string } = {}): Promise<SourceSpanObservation[]> {
		const limit = Math.max(1, Math.min(500, Math.trunc(options.limit ?? 100)));
		return await withWorkspaceLock(root, this.filesystem, async (safeRoot) => (await this.read(safeRoot)).observations
			.filter((item) => !options.scanId || item.scanId === options.scanId)
			.filter((item) => !options.beforeId || item.id < options.beforeId)
			.sort((a, b) => a.id.localeCompare(b.id)).slice(0, limit));
	}

	async recheck(root: string, observation: SourceSpanObservation): Promise<EvidenceFreshness> {
		return await withWorkspaceLock(root, this.filesystem, async (safeRoot) => {
			const persisted = (await this.read(safeRoot)).observations.find((item) => item.id === observation?.id);
			if (!persisted || JSON.stringify(persisted) !== JSON.stringify(observation) || !validObservation(persisted) || persisted.workspaceIdentity !== safeRoot) { return { status: 'unavailable', reason: 'unsafe-path' }; }
			observation = persisted;
			const relative = normalizeRelative(observation.source.path);
			if (!relative) { return { status: 'unavailable', reason: 'unsafe-path' }; }
			const absolute = path.resolve(safeRoot, relative);
			try { await this.filesystem.lstat!(absolute); }
			catch (error) { return { status: 'unavailable', reason: error && typeof error === 'object' && 'code' in error && (error as {code?: string}).code === 'ENOENT' ? 'missing' : 'read-failed' }; }
			if (!await safeFile(safeRoot, relative, this.filesystem)) { return { status: 'unavailable', reason: 'unsafe-path' }; }
			if (!this.filesystem.readFileBoundedBytes) { return { status: 'unavailable', reason: 'read-failed' }; }
			try {
				const stat = await this.filesystem.stat(absolute);
				if (!stat.isFile() || stat.size > MAX_SOURCE_FILE_BYTES) { return { status: 'unavailable', reason: 'limit-exceeded' }; }
				const bytes = await this.filesystem.readFileBoundedBytes(absolute, MAX_SOURCE_FILE_BYTES);
				if (bytes.byteLength > MAX_SOURCE_FILE_BYTES) { return { status: 'unavailable', reason: 'limit-exceeded' }; }
				let content: string;
				try { content = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return { status: 'unavailable', reason: 'invalid-encoding' }; }
				const fileHash = hashSourceContent(content);
				if (fileHash !== observation.source.fileContentHash) { return { status: 'stale', reason: 'content-changed' }; }
				const spanHash = createSourceLineIndex(content).hashSpan(observation.source.startLine, observation.source.endLine);
				return spanHash === observation.source.spanContentHash ? { status: 'current' } : { status: 'stale', reason: 'span-changed' };
			} catch (error) {
				return { status: 'unavailable', reason: error && typeof error === 'object' && 'code' in error && (error as {code?: string}).code === 'ENOENT' ? 'missing' : 'read-failed' };
			}
		});
	}

	private async read(root: string): Promise<EvidenceStore> {
		const file = storePath(root);
		if (!this.filesystem.readFileBounded || !this.filesystem.lstat || !this.filesystem.realpath) { throw new Error('Evidence storage requires bounded reads and physical path checks.'); }
		await this.recoverBackup(file);
		try {
			const stat = await this.filesystem.lstat(file);
			if (stat.isSymbolicLink() || !stat.isFile() || !samePath(await this.filesystem.realpath(file), file)) { throw new Error('Evidence store is unsafe.'); }
			const raw = await this.filesystem.readFileBounded(file, MAX_EVIDENCE_STORE_BYTES, 'utf8');
			if (Buffer.byteLength(raw, 'utf8') > MAX_EVIDENCE_STORE_BYTES) { throw new Error('Evidence store exceeds its safety limit.'); }
			const parsed: unknown = JSON.parse(raw);
			if (!isEvidenceStore(parsed) || parsed.observations.some((item) => item.workspaceIdentity !== root)) { throw new Error('Evidence store schema is invalid or unsupported.'); }
			return parsed;
		} catch (error) {
			if (error && typeof error === 'object' && 'code' in error && (error as { code?: string }).code === 'ENOENT') { return { version: 1, observations: [] }; }
			throw error;
		}
	}

	private async recoverBackup(target: string): Promise<void> {
		if (await this.filesystem.exists(target)) { return; }
		let entries: Array<string | { name: string }>;
		try { entries = await this.filesystem.readdir(path.dirname(target)); }
		catch (error) { if (error && typeof error === 'object' && 'code' in error && (error as { code?: string }).code === 'ENOENT') { return; } throw new Error('Evidence recovery could not inspect workspace records.'); }
		const names = entries.map((entry) => typeof entry === 'string' ? entry : entry.name)
			.filter((name) => name.startsWith(`${path.basename(target)}.`) && name.endsWith('.bak')).sort();
		if (!names.length) { return; }
		if (names.length > 32) { throw new Error('Evidence recovery has too many backup candidates; history was preserved.'); }
		const valid: Array<{ name: string; raw: string }> = [];
		for (const name of names) {
			const candidate = path.join(path.dirname(target), name);
			try {
				const stat = await this.filesystem.lstat!(candidate);
				if (stat.isSymbolicLink() || !stat.isFile() || !samePath(await this.filesystem.realpath!(candidate), candidate)) { throw new Error(); }
				const raw = await this.filesystem.readFileBounded!(candidate, MAX_EVIDENCE_STORE_BYTES, 'utf8');
				const backupStore: unknown = JSON.parse(raw);
				if (Buffer.byteLength(raw, 'utf8') > MAX_EVIDENCE_STORE_BYTES || !isEvidenceStore(backupStore)
					|| backupStore.observations.some((item) => item.workspaceIdentity !== path.dirname(path.dirname(target)))) { throw new Error(); }
				valid.push({ name, raw });
			} catch { throw new Error('An evidence backup is malformed or unsafe; all recovery files were preserved.'); }
		}
		if (valid.some((item) => item.raw !== valid[0].raw)) { throw new Error('Evidence backups conflict; all recovery files were preserved.'); }
		await this.filesystem.rename(path.join(path.dirname(target), valid[0].name), target);
	}

	private async write(root: string, store: EvidenceStore): Promise<void> {
		const target = storePath(root), serialized = JSON.stringify(store);
		if (store.observations.length > MAX_EVIDENCE_RECORDS || Buffer.byteLength(serialized, 'utf8') > MAX_EVIDENCE_STORE_BYTES) { throw new Error('Evidence store capacity exceeded; prior history was preserved.'); }
		if (!this.filesystem.writeFileExclusive || !this.filesystem.rename || !this.filesystem.unlink) { throw new Error('Evidence persistence requires exclusive creation, atomic rename, and cleanup support.'); }
		const temporary = `${target}.${crypto.randomBytes(12).toString('hex')}.tmp`;
		await this.filesystem.writeFileExclusive(temporary, serialized, 'utf8');
		if (!this.filesystem.lstat || !this.filesystem.realpath) { throw new Error('Evidence persistence requires physical path checks.'); }
		const tempStat = await this.filesystem.lstat(temporary);
		if (tempStat.isSymbolicLink() || !tempStat.isFile() || !samePath(await this.filesystem.realpath(temporary), temporary)) { throw new Error('Evidence temporary file is unsafe.'); }
		if (!(await this.filesystem.exists(target))) { await this.filesystem.rename(temporary, target); return; }
		const backup = `${target}.${crypto.randomBytes(12).toString('hex')}.bak`;
		await this.filesystem.rename(target, backup);
		try { await this.filesystem.rename(temporary, target); }
		catch (error) { try { await this.filesystem.rename(backup, target); } catch { throw new Error('Evidence history is preserved in its recovery backup.'); } throw error; }
		try { await this.filesystem.unlink(backup); } catch { /* committed store remains valid; backup is recoverable */ }
	}
}

function storePath(root: string): string { return path.join(root, '.aqiron-security', 'evidence.json'); }
function validProvenance(value: FindingSourceProvenance): boolean {
	return Boolean(value && typeof value.file === 'string' && typeof value.findingId === 'string' && value.findingId.length <= 256
		&& typeof value.sourceTool === 'string' && value.sourceTool === 'Aqiron' && typeof value.ruleId === 'string' && value.ruleId.length <= 256
		&& Number.isInteger(value.startLine) && value.startLine >= 1 && Number.isInteger(value.endLine) && value.endLine >= value.startLine && value.endLine - value.startLine < 20
		&& /^[a-f0-9]{64}$/.test(value.contentHash) && /^[a-f0-9]{64}$/.test(value.sourceContentHash)
		&& typeof value.observedAt === 'string' && Number.isFinite(Date.parse(value.observedAt)));
}
function normalizeRelative(value: string): string | undefined {
	if (!value || value.includes('\0') || value.startsWith('/') || /^[a-z]:/i.test(value) || value.startsWith('\\')) { return undefined; }
	const parts = value.replace(/\\/g, '/').split('/');
	if (parts.some((part) => !part || part === '.' || part === '..')) { return undefined; }
	return parts.join('/');
}
async function safeFile(root: string, relative: string, filesystem: FileSystem): Promise<boolean> {
	if (!filesystem.lstat || !filesystem.realpath) { return false; }
	let current = root;
	for (const part of relative.split('/')) {
		current = path.join(current, part);
		try { const stat = await filesystem.lstat(current); if (stat.isSymbolicLink()) { return false; } } catch { return false; }
	}
	try {
		const actual = await filesystem.realpath(current), rel = path.relative(root, actual), stat = await filesystem.lstat(actual);
		return stat.isFile() && Boolean(rel) && rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
	} catch { return false; }
}
function validObservation(value: SourceSpanObservation): boolean {
	return Boolean(value && value.schemaVersion === 1 && value.kind === 'source_span' && /^ev1_[0-9a-f-]{36}$/.test(value.id)
		&& typeof value.workspaceIdentity === 'string' && typeof value.scanId === 'string' && (value.originatingFindingId === undefined || (typeof value.originatingFindingId === 'string' && value.originatingFindingId.length > 0 && value.originatingFindingId.length <= 256)) && value.collector?.id === EVIDENCE_COLLECTOR_ID && value.collector.version === EVIDENCE_COLLECTOR_VERSION
		&& Number.isFinite(Date.parse(value.observedAt)) && normalizeRelative(value.source?.path) === value.source?.path
		&& Number.isInteger(value.source.startLine) && value.source.startLine >= 1 && Number.isInteger(value.source.endLine) && value.source.endLine >= value.source.startLine && value.source.endLine - value.source.startLine < 20
		&& /^[a-f0-9]{64}$/.test(value.source.fileContentHash) && /^[a-f0-9]{64}$/.test(value.source.spanContentHash));
}
function isEvidenceStore(value: unknown): value is EvidenceStore {
	return Boolean(value && typeof value === 'object' && !Array.isArray(value) && (value as EvidenceStore).version === 1 && Array.isArray((value as EvidenceStore).observations)
		&& (value as EvidenceStore).observations.length <= MAX_EVIDENCE_RECORDS && (value as EvidenceStore).observations.every(validObservation)
		&& new Set((value as EvidenceStore).observations.map((item) => item.id)).size === (value as EvidenceStore).observations.length);
}
function samePath(left: string, right: string): boolean { const a = path.resolve(left), b = path.resolve(right); return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b; }

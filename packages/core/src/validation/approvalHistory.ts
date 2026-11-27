import { createHash, randomUUID } from 'node:crypto';
import * as path from 'node:path';
import type { FileSystem } from '../shared/platform';
import { withWorkspaceLock } from '../hypotheses/hypothesisStore';
import { canonicalize } from './contracts';

export const APPROVAL_HISTORY_SCHEMA_VERSION = 1 as const;
export const APPROVAL_HISTORY_MAX_BYTES = 4 * 1024 * 1024;
export const APPROVAL_HISTORY_MAX_EVENTS = 20_000;
export const APPROVAL_HISTORY_MAX_EVENT_BYTES = 8 * 1024;

export type ApprovalHistoryEventTypeV1 = 'approval-issued' | 'approval-revoked' | 'approval-expired' | 'approval-invalidated';
export type HistoricalApprovalStatusV1 = 'historical-only' | 'revoked' | 'expired' | 'invalidated';

export interface ApprovalIssuedAuditInputV1 {
	approvalId: string;
	requestId: string;
	requestDigest: string;
	createdAt: string;
	expiresAt: string;
	projectIdentity: string;
	permittedScopeDigest: string;
	procedureId: string;
	procedureVersion: string;
	artifactDigest: string;
	argumentDigest: string;
	evidenceSnapshotId: string;
	evidenceDigest: string;
	capabilities: { filesystem: 'none' | 'read-only'; network: 'none'; projectWrites: false; inheritedCredentials: false };
	resourceLimits: { timeoutMs: number; memoryBytes: number; outputBytes: number; processCount: number };
}

export interface ApprovalHistoryEventV1 {
	schemaVersion: 1;
	eventId: string;
	sequence: number;
	eventType: ApprovalHistoryEventTypeV1;
	timestamp: string;
	approvalId: string;
	issued?: ApprovalIssuedAuditInputV1;
	decision?: 'revoked' | 'expired' | 'invalidated-by-restart' | 'shutdown';
	previousEventHash: string;
	eventHash: string;
}

export interface ApprovalHistoryEventReferenceV1 { eventId: string; eventHash: string; }

/** Historical audit data has no nonce, monotonic deadline, active flag, or execution authority. */
export interface HistoricalApprovalRecordV1 extends ApprovalIssuedAuditInputV1 {
	schemaVersion: 1;
	status: HistoricalApprovalStatusV1;
	historicalOnly: true;
	canAuthorizeExecution: false;
	lastEventAt: string;
}

export interface ApprovalHistoryOptions { maxBytes?: number; maxEvents?: number; eventId?: () => string; }
export interface ApprovalHistoryPersistence {
	recordIssued(input: ApprovalIssuedAuditInputV1): Promise<ApprovalHistoryEventReferenceV1>;
	recordStatus(approvalId: string, decision: 'revoked' | 'expired' | 'invalidated-by-restart' | 'shutdown', timestamp: string): Promise<void>;
	query(): Promise<HistoricalApprovalRecordV1[]>;
}

export class ApprovalHistoryError extends Error {
	readonly code = 'APPROVAL_HISTORY_UNAVAILABLE';
	constructor(message: string, cause?: unknown) { super(message, { cause }); this.name = 'ApprovalHistoryError'; }
}

const ambiguousRoots = new Set<string>();

/** A distinct append-only audit log. It never stores or reconstructs active grants. */
export class ApprovalHistoryStore implements ApprovalHistoryPersistence {
	private readonly maxBytes: number;
	private readonly maxEvents: number;
	private readonly eventId: () => string;

	constructor(private readonly filesystem: FileSystem, private readonly coreDataDirectory: string, options: ApprovalHistoryOptions = {}) {
		this.maxBytes = options.maxBytes ?? APPROVAL_HISTORY_MAX_BYTES;
		this.maxEvents = options.maxEvents ?? APPROVAL_HISTORY_MAX_EVENTS;
		this.eventId = options.eventId ?? randomUUID;
		if (!Number.isSafeInteger(this.maxBytes) || this.maxBytes < 1024 || this.maxBytes > APPROVAL_HISTORY_MAX_BYTES
			|| !Number.isSafeInteger(this.maxEvents) || this.maxEvents < 1 || this.maxEvents > APPROVAL_HISTORY_MAX_EVENTS) {
			throw new RangeError('Approval history limits are invalid.');
		}
	}

	async recordIssued(input: ApprovalIssuedAuditInputV1): Promise<ApprovalHistoryEventReferenceV1> {
		const issued = validateIssued(input);
		const reference = await this.append('approval-issued', issued.approvalId, issued.createdAt, issued);
		if (!reference) { throw new ApprovalHistoryError('Approval issue event reference was not produced.'); }
		return reference;
	}

	async recordStatus(approvalId: string, decision: 'revoked' | 'expired' | 'invalidated-by-restart' | 'shutdown', timestamp: string): Promise<void> {
		if (!isUuid(approvalId) || !validTimestamp(timestamp)) { throw new TypeError('Invalid approval history status event.'); }
		const eventType = decision === 'revoked' ? 'approval-revoked' : decision === 'expired' ? 'approval-expired' : 'approval-invalidated';
		await this.append(eventType, approvalId, timestamp, undefined, decision);
	}

	async query(): Promise<HistoricalApprovalRecordV1[]> {
		return await this.withLock(async (root) => {
			const events = await this.load(root);
			return buildHistoricalRecords(events);
		});
	}

	private async append(eventType: ApprovalHistoryEventTypeV1, approvalId: string, timestamp: string, issued?: ApprovalIssuedAuditInputV1, decision?: ApprovalHistoryEventV1['decision']): Promise<ApprovalHistoryEventReferenceV1 | void> {
		return await this.withLock(async (root) => {
			const key = historyKey(root);
			if (ambiguousRoots.has(key)) { throw new ApprovalHistoryError('Approval history is unavailable after an ambiguous append.'); }
			const events = await this.load(root);
			if (events.length && Date.parse(timestamp) < Date.parse(events.at(-1)!.timestamp)) { throw new ApprovalHistoryError('Approval history clock moved backward; no event was appended.'); }
			const priorApproval = events.find(event => event.approvalId === approvalId);
			if (eventType === 'approval-issued') {
				if (priorApproval) { throw new ApprovalHistoryError('Approval identifier already exists in historical records.'); }
				if (events.some(event => event.eventType === 'approval-issued' && event.issued?.requestId === issued?.requestId)) {
					throw new ApprovalHistoryError('Approval request ID was already recorded.');
				}
			} else if (!priorApproval || priorApproval.eventType !== 'approval-issued') {
				throw new ApprovalHistoryError('Approval status event has no prior issued record.');
			} else if (events.some(event => event.approvalId === approvalId && event.eventType !== 'approval-issued')) {
				throw new ApprovalHistoryError('Approval already has a terminal historical status.');
			}
			if (events.length >= this.maxEvents) { throw new ApprovalHistoryError('Approval history event limit reached; no history was removed.'); }
			const unsigned = {
				schemaVersion: APPROVAL_HISTORY_SCHEMA_VERSION, eventId: this.eventId(), sequence: events.length + 1,
				eventType, timestamp, approvalId, ...(issued ? { issued } : {}), ...(decision ? { decision } : {}),
				previousEventHash: events.at(-1)?.eventHash ?? '0'.repeat(64),
			};
			const event = validateEvent({ ...unsigned, eventHash: hash(unsigned) });
			if (events.some(item => item.eventId === event.eventId)) { throw new ApprovalHistoryError('Approval history event ID was reused.'); }
			const line = Buffer.from(`${canonicalize(event)}\n`, 'utf8');
			const currentBytes = await this.readBytes(root);
			if (currentBytes.byteLength + line.byteLength > this.maxBytes) { throw new ApprovalHistoryError('Approval history byte limit reached; no history was removed.'); }
			const append = this.filesystem.appendFileDurable;
			const createMarker = this.filesystem.writeFileDurableExclusive;
			const removeMarker = this.filesystem.unlinkDurable;
			if (!append || !createMarker || !removeMarker) { throw new ApprovalHistoryError('Durable safe approval-history filesystem capabilities are unavailable.'); }
			try {
				await createMarker(markerPath(root), Buffer.from(canonicalize({ eventId: event.eventId, sequence: event.sequence, eventHash: event.eventHash }), 'utf8'));
				await append(historyPath(root), line);
				await removeMarker(markerPath(root));
			} catch (error) {
				ambiguousRoots.add(key);
				throw new ApprovalHistoryError('Approval history append is ambiguous; history is unavailable and prior bytes were preserved.', error);
			}
			return eventType === 'approval-issued' ? { eventId: event.eventId, eventHash: event.eventHash } : undefined;
		});
	}

	private async withLock<T>(task: (safeRoot: string) => Promise<T>): Promise<T> {
		try {
			const root = await this.ensureCoreDataDirectory();
			return await withWorkspaceLock(root, this.filesystem, async safeRoot => {
				if (ambiguousRoots.has(historyKey(safeRoot))) { throw new ApprovalHistoryError('Approval history is unavailable after an ambiguous append.'); }
				await ensureHistoryDirectory(safeRoot, this.filesystem);
				return await task(safeRoot);
			});
		} catch (error) {
			if (error instanceof ApprovalHistoryError) { throw error; }
			throw new ApprovalHistoryError('Approval history storage is unavailable.', error);
		}
	}

	private async ensureCoreDataDirectory(): Promise<string> {
		if (!path.isAbsolute(this.coreDataDirectory) || !this.filesystem.mkdir || !this.filesystem.lstat || !this.filesystem.realpath) { throw new ApprovalHistoryError('Core data directory cannot be safely established.'); }
		await this.filesystem.mkdir(this.coreDataDirectory, { recursive: true });
		const stat = await this.filesystem.lstat(this.coreDataDirectory);
		if (!stat.isDirectory() || stat.isSymbolicLink()) { throw new ApprovalHistoryError('Core data directory is not a physical directory.'); }
		const real = await this.filesystem.realpath(this.coreDataDirectory);
		if (normalizePhysicalPath(real) !== normalizePhysicalPath(this.coreDataDirectory)) { throw new ApprovalHistoryError('Core data directory resolves unexpectedly.'); }
		return real;
	}

	private async load(root: string): Promise<ApprovalHistoryEventV1[]> {
		if (!this.filesystem.lstat || !this.filesystem.readFileSafeBoundedBytes || !this.filesystem.readdir) { throw new ApprovalHistoryError('Safe bounded approval-history reads are unavailable.'); }
		const marker = markerPath(root);
		try { await this.filesystem.lstat(marker); throw new ApprovalHistoryError('A pending approval-history append marker requires manual recovery.'); }
		catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') { throw error; } }
		let bytes: Uint8Array;
		try { bytes = await this.filesystem.readFileSafeBoundedBytes(historyPath(root), this.maxBytes); }
		catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') { return []; }
			if ((error as NodeJS.ErrnoException).code === 'FILE_TOO_LARGE') { throw new ApprovalHistoryError('Approval history exceeds its hard byte limit.', error); }
			throw error;
		}
		if (!bytes.byteLength) { return []; }
		let text: string;
		try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
		catch (error) { throw new ApprovalHistoryError('Approval history contains invalid UTF-8.', error); }
		if (!text.endsWith('\n')) { throw new ApprovalHistoryError('Approval history has a truncated final record.'); }
		const events: ApprovalHistoryEventV1[] = [];
		const ids = new Set<string>();
		let priorHash = '0'.repeat(64);
		for (const line of text.slice(0, -1).split('\n')) {
			let event: ApprovalHistoryEventV1;
			try { event = validateEvent(JSON.parse(line)); }
			catch (error) { throw new ApprovalHistoryError('Approval history contains a malformed event.', error); }
			if (ids.has(event.eventId) || event.sequence !== events.length + 1 || event.previousEventHash !== priorHash || (events.length > 0 && Date.parse(event.timestamp) < Date.parse(events.at(-1)!.timestamp))) { throw new ApprovalHistoryError('Approval history sequence, event ID, timestamp order, or hash chain is invalid.'); }
			if (event.eventHash !== hash(eventHashInput(event))) { throw new ApprovalHistoryError('Approval history event digest is invalid.'); }
			if (event.eventType === 'approval-issued' && events.some(item => item.eventType === 'approval-issued' && (item.approvalId === event.approvalId || item.issued?.requestId === event.issued?.requestId))) { throw new ApprovalHistoryError('Approval ID or request ID is duplicated in history.'); }
			if (event.eventType !== 'approval-issued') {
				const prior = [...events].reverse().find(item => item.approvalId === event.approvalId);
				if (!prior || prior.eventType !== 'approval-issued') { throw new ApprovalHistoryError('Approval status event has no issued event.'); }
				if (events.some(item => item.approvalId === event.approvalId && item.eventType !== 'approval-issued')) { throw new ApprovalHistoryError('Approval has multiple terminal status events.'); }
			}
			ids.add(event.eventId); priorHash = event.eventHash; events.push(event);
			if (events.length > this.maxEvents) { throw new ApprovalHistoryError('Approval history exceeds its event-count limit.'); }
		}
		return events;
	}

	private async readBytes(root: string): Promise<Uint8Array> {
		if (!this.filesystem.lstat || !this.filesystem.readFileSafeBoundedBytes) { throw new ApprovalHistoryError('Safe bounded approval-history reads are unavailable.'); }
		try {
			const stat = await this.filesystem.lstat(historyPath(root));
			if (!stat.isFile() || stat.isSymbolicLink()) { throw new ApprovalHistoryError('Approval history target is not a regular file.'); }
			return await this.filesystem.readFileSafeBoundedBytes(historyPath(root), this.maxBytes);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') { return new Uint8Array(); }
			throw error;
		}
	}
}

export function validateApprovalHistoryEvent(value: unknown): ApprovalHistoryEventV1 { return validateEvent(value); }

function validateEvent(value: unknown): ApprovalHistoryEventV1 {
	canonicalize(value);
	const record = exactRecord(value, ['schemaVersion','eventId','sequence','eventType','timestamp','approvalId','previousEventHash','eventHash'], ['issued','decision']);
	if (record.schemaVersion !== 1 || !isUuid(record.eventId) || !Number.isSafeInteger(record.sequence) || record.sequence < 1 || !isUuid(record.approvalId)
		|| !validTimestamp(record.timestamp) || !isHash(record.previousEventHash) || !isHash(record.eventHash)) { throw new TypeError('Invalid approval history event envelope.'); }
	if (record.eventType === 'approval-issued') {
		if (!record.issued || record.decision !== undefined) { throw new TypeError('Approval-issued event payload is invalid.'); }
		record.issued = validateIssued(record.issued);
		if (record.issued.approvalId !== record.approvalId || record.issued.createdAt !== record.timestamp) { throw new TypeError('Approval issue event fields disagree.'); }
	} else if (['approval-revoked','approval-expired','approval-invalidated'].includes(record.eventType)) {
		if (record.issued !== undefined || !['revoked','expired','invalidated-by-restart','shutdown'].includes(record.decision)) { throw new TypeError('Approval status event payload is invalid.'); }
		if (record.eventType === 'approval-revoked' && record.decision !== 'revoked' || record.eventType === 'approval-expired' && record.decision !== 'expired' || record.eventType === 'approval-invalidated' && !['invalidated-by-restart','shutdown'].includes(record.decision)) { throw new TypeError('Approval status and decision disagree.'); }
	} else { throw new TypeError('Unknown approval history event type.'); }
	if (Buffer.byteLength(canonicalize(record), 'utf8') > APPROVAL_HISTORY_MAX_EVENT_BYTES) { throw new RangeError('Approval history event exceeds the byte limit.'); }
	return JSON.parse(JSON.stringify(record)) as ApprovalHistoryEventV1;
}

function validateIssued(value: unknown): ApprovalIssuedAuditInputV1 {
	const item = exactRecord(value, ['approvalId','requestId','requestDigest','createdAt','expiresAt','projectIdentity','permittedScopeDigest','procedureId','procedureVersion','artifactDigest','argumentDigest','evidenceSnapshotId','evidenceDigest','capabilities','resourceLimits']);
	const caps = exactRecord(item.capabilities, ['filesystem','network','projectWrites','inheritedCredentials']);
	const limits = exactRecord(item.resourceLimits, ['timeoutMs','memoryBytes','outputBytes','processCount']);
	if (!isUuid(item.approvalId) || !isSafeId(item.requestId) || !isHash(item.requestDigest) || !validTimestamp(item.createdAt) || !validTimestamp(item.expiresAt) || Date.parse(item.expiresAt) <= Date.parse(item.createdAt)
		|| !isDigest(item.projectIdentity) || !isDigest(item.permittedScopeDigest) || typeof item.procedureId !== 'string' || !/^[a-z][a-z0-9.-]*:[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/.test(item.procedureId)
		|| typeof item.procedureVersion !== 'string' || !isSemVer(item.procedureVersion) || !isDigest(item.artifactDigest) || !isDigest(item.argumentDigest)
		|| !isSafeId(item.evidenceSnapshotId) || !isDigest(item.evidenceDigest)
		|| !['none','read-only'].includes(String(caps.filesystem)) || caps.network !== 'none' || caps.projectWrites !== false || caps.inheritedCredentials !== false
		|| ['timeoutMs','memoryBytes','outputBytes','processCount'].some(key => !Number.isSafeInteger(limits[key]) || Number(limits[key]) < 1)) { throw new TypeError('Invalid approval-issued audit facts.'); }
	return JSON.parse(JSON.stringify({
		approvalId: item.approvalId, requestId: item.requestId, requestDigest: item.requestDigest, createdAt: item.createdAt, expiresAt: item.expiresAt,
		projectIdentity: item.projectIdentity, permittedScopeDigest: item.permittedScopeDigest, procedureId: item.procedureId, procedureVersion: item.procedureVersion,
		artifactDigest: item.artifactDigest, argumentDigest: item.argumentDigest, evidenceSnapshotId: item.evidenceSnapshotId, evidenceDigest: item.evidenceDigest,
		capabilities: { filesystem: caps.filesystem, network: 'none', projectWrites: false, inheritedCredentials: false },
		resourceLimits: { timeoutMs: limits.timeoutMs, memoryBytes: limits.memoryBytes, outputBytes: limits.outputBytes, processCount: limits.processCount },
	})) as ApprovalIssuedAuditInputV1;
}

function buildHistoricalRecords(events: ApprovalHistoryEventV1[]): HistoricalApprovalRecordV1[] {
	const records = new Map<string, HistoricalApprovalRecordV1>();
	for (const event of events) {
		if (event.eventType === 'approval-issued') {
			records.set(event.approvalId, { schemaVersion: 1, ...event.issued!, status: 'historical-only', historicalOnly: true, canAuthorizeExecution: false, lastEventAt: event.timestamp });
		} else {
			const prior = records.get(event.approvalId)!;
			records.set(event.approvalId, { ...prior, status: event.decision === 'revoked' ? 'revoked' : event.decision === 'expired' ? 'expired' : 'invalidated', lastEventAt: event.timestamp });
		}
	}
	return [...records.values()];
}

function exactRecord(value: unknown, required: string[], optional: string[] = []): Record<string, any> {
	if (!value || typeof value !== 'object' || Array.isArray(value) || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) { throw new TypeError('Expected a plain approval history object.'); }
	const item = value as Record<string, unknown>;
	if (Object.keys(item).some(key => !required.includes(key) && !optional.includes(key)) || required.some(key => !Object.prototype.hasOwnProperty.call(item, key))) { throw new TypeError('Unknown or missing approval history field.'); }
	return item;
}
function eventHashInput(event: ApprovalHistoryEventV1): unknown { const { eventHash: _hash, ...input } = event; return input; }
function hash(value: unknown): string { return createHash('sha256').update(canonicalize(value)).digest('hex'); }
function historyPath(root: string): string { return path.join(root, '.aqiron-security', 'controlled-validation-approvals.log'); }
function markerPath(root: string): string { return path.join(root, '.aqiron-security', '.controlled-validation-approvals.pending'); }
function historyKey(root: string): string { const resolved = path.resolve(root); return process.platform === 'win32' ? resolved.toLowerCase() : resolved; }
async function ensureHistoryDirectory(root: string, filesystem: FileSystem): Promise<void> {
	const directory = path.join(root, '.aqiron-security');
	if (!filesystem.lstat || !filesystem.realpath || !filesystem.mkdir || !filesystem.syncDirectoryDurable) { throw new ApprovalHistoryError('Safe durable history directory capabilities are unavailable.'); }
	try { await filesystem.lstat(directory); }
	catch (error) {
		if ((error as NodeJS.ErrnoException).code !== 'ENOENT') { throw error; }
		await filesystem.mkdir(directory);
		await filesystem.syncDirectoryDurable(root);
	}
	const stat = await filesystem.lstat(directory);
	if (!stat.isDirectory() || stat.isSymbolicLink() || normalizePhysicalPath(await filesystem.realpath(directory)) !== normalizePhysicalPath(directory)) { throw new ApprovalHistoryError('Approval history directory is unsafe.'); }
}
function normalizePhysicalPath(value: string): string {
	let normalized = path.resolve(value);
	if (normalized.startsWith('\\\\?\\')) { normalized = normalized.slice(4); }
	normalized = normalized.replace(/\\/g, '/');
	if (process.platform === 'win32') { normalized = normalized.toLowerCase(); }
	return normalized;
}
function validTimestamp(value: unknown): value is string { return typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value; }
function isUuid(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value); }
function isSafeId(value: unknown): value is string { return typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(value); }
function isDigest(value: unknown): value is string { return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value); }
function isHash(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
function isSemVer(value: unknown): value is string { return typeof value === 'string' && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value); }

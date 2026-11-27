import { createHash, randomUUID } from 'node:crypto';
import * as path from 'node:path';
import type { FileSystem } from '../shared/platform';
import { withWorkspaceLock } from '../hypotheses/hypothesisStore';
import { canonicalize } from './contracts';
import { ApprovalHistoryEventReferenceV1 } from './approvalHistory';

export const VALIDATION_LIFECYCLE_SCHEMA_VERSION = 1 as const;
export const VALIDATION_LIFECYCLE_BUCKETS = 256;
export const VALIDATION_LIFECYCLE_MAX_BUCKET_BYTES = 4 * 1024 * 1024;
export const VALIDATION_LIFECYCLE_MAX_BUCKET_APPROVALS = 20_000;
export const VALIDATION_LIFECYCLE_MAX_APPROVAL_BYTES = 64 * 1024;
export const VALIDATION_LIFECYCLE_MAX_APPROVAL_EVENTS = 128;

export type ValidationLifecycleTerminalTypeV1 = 'execution-completed' | 'execution-failed' | 'execution-cancelled' | 'execution-expired' | 'execution-blocked' | 'execution-interrupted';
export interface ExecutionStartCommittedEventV1 {
	schemaVersion: 1; eventId: string; executionId: string; approvalId: string; sequence: number;
	eventType: 'execution-start-committed'; timestamp: string; approvalHistory: ApprovalHistoryEventReferenceV1;
	authorizationBindingDigest: string; projectRoot: string; projectIdentity: string; permittedTargets: string[];
	procedureId: string; procedureVersion: string; artifactDigest: string; argumentDigest: string;
	evidenceSnapshotId: string; evidenceDigest: string; capabilities: { filesystem: 'none' | 'read-only'; network: 'none'; projectWrites: false; inheritedCredentials: false };
	resourceLimits: { timeoutMs: number; memoryBytes: number; outputBytes: number; processCount: number };
	previousEventHash: string; eventHash: string;
}
export interface ValidationLifecycleTerminalEventV1 {
	schemaVersion: 1; eventId: string; executionId: string; approvalId: string; sequence: number;
	eventType: ValidationLifecycleTerminalTypeV1; timestamp: string; category: string;
	previousEventHash: string; eventHash: string;
}
export type ValidationLifecycleEventV1 = ExecutionStartCommittedEventV1 | ValidationLifecycleTerminalEventV1;
export type FutureValidationExecutionStateV1 = 'start-committed' | 'completed' | 'failed' | 'cancelled' | 'expired' | 'blocked' | 'interrupted';
export interface HistoricalStartCommitmentV1 extends ExecutionStartCommittedEventV1 { historicalOnly: true; canAuthorizeExecution: false; approvalStatus: 'consumed'; }
export interface StartCommitInputV1 {
	approvalId: string; executionId?: string; timestamp: string; approvalHistory: ApprovalHistoryEventReferenceV1;
	authorizationBindingDigest: string; projectRoot: string; projectIdentity: string; permittedTargets: string[];
	procedureId: string; procedureVersion: string; artifactDigest: string; argumentDigest: string;
	evidenceSnapshotId: string; evidenceDigest: string;
	capabilities: ExecutionStartCommittedEventV1['capabilities']; resourceLimits: ExecutionStartCommittedEventV1['resourceLimits'];
}
export type StartCommitStoreResultV1 = { committed: true; duplicate: false; event: HistoricalStartCommitmentV1 } | { committed: false; duplicate: true; event: HistoricalStartCommitmentV1 };

export class ValidationLifecycleError extends Error {
	readonly code = 'VALIDATION_LIFECYCLE_UNAVAILABLE';
	constructor(message: string, cause?: unknown) { super(message, { cause }); this.name = 'ValidationLifecycleError'; }
}

const ambiguousBuckets = new Set<string>();

/** Separate durable lifecycle journal. Per-approval hash buckets avoid a process-wide append lock. */
export class ValidationLifecycleStore {
	private readonly executionId: () => string;
	private readonly maxBucketBytes: number;
	private readonly maxBucketApprovals: number;
	private readonly maxApprovalBytes: number;
	private readonly maxApprovalEvents: number;
	constructor(private readonly filesystem: FileSystem, private readonly coreDataDirectory: string, options: { executionId?: () => string; maxBucketBytes?: number; maxBucketApprovals?: number; maxApprovalBytes?: number; maxApprovalEvents?: number } = {}) {
		this.executionId = options.executionId ?? randomUUID;
		this.maxBucketBytes = options.maxBucketBytes ?? VALIDATION_LIFECYCLE_MAX_BUCKET_BYTES;
		this.maxBucketApprovals = options.maxBucketApprovals ?? VALIDATION_LIFECYCLE_MAX_BUCKET_APPROVALS;
		this.maxApprovalBytes = options.maxApprovalBytes ?? VALIDATION_LIFECYCLE_MAX_APPROVAL_BYTES;
		this.maxApprovalEvents = options.maxApprovalEvents ?? VALIDATION_LIFECYCLE_MAX_APPROVAL_EVENTS;
		if (!Number.isSafeInteger(this.maxBucketBytes) || this.maxBucketBytes < 1 || this.maxBucketBytes > VALIDATION_LIFECYCLE_MAX_BUCKET_BYTES || !Number.isSafeInteger(this.maxBucketApprovals) || this.maxBucketApprovals < 1 || this.maxBucketApprovals > VALIDATION_LIFECYCLE_MAX_BUCKET_APPROVALS || !Number.isSafeInteger(this.maxApprovalBytes) || this.maxApprovalBytes < 1 || this.maxApprovalBytes > VALIDATION_LIFECYCLE_MAX_APPROVAL_BYTES || !Number.isSafeInteger(this.maxApprovalEvents) || this.maxApprovalEvents < 1 || this.maxApprovalEvents > VALIDATION_LIFECYCLE_MAX_APPROVAL_EVENTS) { throw new RangeError('Lifecycle limits are invalid.'); }
	}

	async commitStart(input: StartCommitInputV1): Promise<StartCommitStoreResultV1> {
		const safe = validateStartInput(input);
		const executionId = safe.executionId ?? this.executionId();
		if (!isUuid(executionId)) { throw new TypeError('Invalid execution ID.'); }
		const bucket = bucketFor(safe.approvalId);
		const bucketRoot = path.join(this.coreDataDirectory, '.aqiron-security', 'validation-lifecycle', bucket);
		try {
			await this.filesystem.mkdir(bucketRoot, { recursive: true });
			const physical = await this.filesystem.realpath?.(bucketRoot);
			const stat = await this.filesystem.lstat?.(bucketRoot);
			if (!physical || !stat?.isDirectory() || stat.isSymbolicLink() || normalizePath(physical) !== normalizePath(bucketRoot)) { throw new ValidationLifecycleError('Lifecycle bucket is not a canonical physical directory.'); }
			return await withWorkspaceLock(bucketRoot, this.filesystem, async root => {
				const key = normalizePath(root);
				if (ambiguousBuckets.has(key)) { throw new ValidationLifecycleError('Lifecycle bucket is unavailable after an ambiguous append.'); }
				const directory = path.join(root, '.aqiron-security', 'lifecycle');
				await this.ensureDirectory(root, directory);
				const entries = await this.readBucket(directory);
				const prior = entries.get(safe.approvalId);
				if (prior) {
					if (prior.eventType !== 'execution-start-committed' || prior.authorizationBindingDigest !== safe.authorizationBindingDigest) { throw new ValidationLifecycleError('Approval already has a conflicting lifecycle commitment.'); }
					return { committed: false, duplicate: true, event: historical(prior) };
				}
			if (entries.size >= this.maxBucketApprovals) { throw new ValidationLifecycleError('Lifecycle bucket approval limit reached; history was preserved.'); }
			const unsigned = {
				// One start per approval makes the approval UUID a globally unique stable event identity.
				schemaVersion: 1, eventId: safe.approvalId, executionId, approvalId: safe.approvalId, sequence: 1,
				eventType: 'execution-start-committed', timestamp: safe.timestamp, approvalHistory: safe.approvalHistory,
				authorizationBindingDigest: safe.authorizationBindingDigest, projectRoot: safe.projectRoot, projectIdentity: safe.projectIdentity,
				permittedTargets: safe.permittedTargets, procedureId: safe.procedureId, procedureVersion: safe.procedureVersion,
				artifactDigest: safe.artifactDigest, argumentDigest: safe.argumentDigest, evidenceSnapshotId: safe.evidenceSnapshotId,
				evidenceDigest: safe.evidenceDigest, capabilities: safe.capabilities, resourceLimits: safe.resourceLimits,
				previousEventHash: '0'.repeat(64),
			};
			const validated = validateLifecycleEvent({ ...unsigned, eventHash: hash(unsigned) }) as ExecutionStartCommittedEventV1;
			if (Buffer.byteLength(`${canonicalize(validated)}\n`, 'utf8') > this.maxApprovalBytes) { throw new ValidationLifecycleError('Lifecycle approval event/byte limit reached; history was preserved.'); }
			if (entries.bytes + Buffer.byteLength(`${canonicalize(validated)}\n`, 'utf8') > this.maxBucketBytes) { throw new ValidationLifecycleError('Lifecycle bucket byte limit reached; history was preserved.'); }
			const file = path.join(directory, `${safe.approvalId}.log`); const marker = `${file}.pending`;
			if (!this.filesystem.appendFileDurable || !this.filesystem.writeFileDurableExclusive || !this.filesystem.unlinkDurable) { throw new ValidationLifecycleError('Durable lifecycle filesystem capabilities are unavailable.'); }
			try {
				await this.filesystem.writeFileDurableExclusive(marker, Buffer.from(canonicalize({ eventId: validated.eventId, eventHash: validated.eventHash }), 'utf8'));
				await this.filesystem.appendFileDurable(file, Buffer.from(`${canonicalize(validated)}\n`, 'utf8'));
				await this.filesystem.unlinkDurable(marker);
			} catch (error) { ambiguousBuckets.add(key); throw new ValidationLifecycleError('Lifecycle start append is ambiguous; no receipt was issued.', error); }
			return { committed: true, duplicate: false, event: historical(validated) };
			});
		} catch (error) {
			if (error instanceof ValidationLifecycleError) { throw error; }
			throw new ValidationLifecycleError('Lifecycle commitment could not be durably recorded.', error);
		}
	}

	async queryStart(approvalId: string): Promise<HistoricalStartCommitmentV1 | undefined> {
		if (!isUuid(approvalId)) { throw new TypeError('Invalid approval ID.'); }
		const bucketRoot = path.join(this.coreDataDirectory, '.aqiron-security', 'validation-lifecycle', bucketFor(approvalId));
		try {
			if (!this.filesystem.lstat || !this.filesystem.realpath) { throw new ValidationLifecycleError('Lifecycle bucket cannot be inspected safely.'); }
			let stat;
			try { stat = await this.filesystem.lstat(bucketRoot); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') { return undefined; } throw error; }
			if (!stat.isDirectory() || stat.isSymbolicLink()) { throw new ValidationLifecycleError('Lifecycle bucket is not a physical directory.'); }
			const physical = await this.filesystem.realpath(bucketRoot);
			if (normalizePath(physical) !== normalizePath(bucketRoot)) { throw new ValidationLifecycleError('Lifecycle bucket path resolves unexpectedly.'); }
			return await withWorkspaceLock(bucketRoot, this.filesystem, async root => {
				const directory = path.join(root, '.aqiron-security', 'lifecycle');
				const entries = await this.readBucket(directory);
				const event = entries.get(approvalId);
				return event?.eventType === 'execution-start-committed' ? historical(event) : undefined;
			});
		} catch (error) { if (error instanceof ValidationLifecycleError) { throw error; } throw new ValidationLifecycleError('Lifecycle history is unavailable.', error); }
	}

	private async ensureDirectory(root: string, directory: string): Promise<void> {
		if (!this.filesystem.mkdir || !this.filesystem.lstat || !this.filesystem.realpath || !this.filesystem.syncDirectoryDurable) { throw new ValidationLifecycleError('Lifecycle directory durability capabilities are unavailable.'); }
		try { await this.filesystem.mkdir(directory); await this.filesystem.syncDirectoryDurable(path.dirname(directory)); }
		catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') { throw error; } }
		const stat = await this.filesystem.lstat(directory);
		if (!stat.isDirectory() || stat.isSymbolicLink() || normalizePath(await this.filesystem.realpath(directory)) !== normalizePath(directory)) { throw new ValidationLifecycleError('Lifecycle event directory is unsafe.'); }
		if (normalizePath(path.dirname(directory)) !== normalizePath(path.join(root, '.aqiron-security'))) { throw new ValidationLifecycleError('Lifecycle path escapes its bucket.'); }
	}

	private async readBucket(directory: string): Promise<Map<string, ExecutionStartCommittedEventV1> & { bytes: number }> {
		if (!this.filesystem.readdir || !this.filesystem.lstat || !this.filesystem.readFileSafeBoundedBytes) { throw new ValidationLifecycleError('Safe bounded lifecycle reads are unavailable.'); }
		const result = new Map<string, ExecutionStartCommittedEventV1>() as Map<string, ExecutionStartCommittedEventV1> & { bytes: number };
		result.bytes = 0;
		let files: Array<string | { name: string; isDirectory(): boolean; isFile(): boolean }>;
		try { files = await this.filesystem.readdir(directory); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') { return result; } throw error; }
		if (files.length > this.maxBucketApprovals) { throw new ValidationLifecycleError('Lifecycle bucket exceeds its approval limit.'); }
		const eventIds = new Set<string>();
		for (const entry of files) {
			const name = typeof entry === 'string' ? entry : entry.name;
			if (!/^[a-f0-9-]{36}\.log(?:\.pending)?$/.test(name)) { throw new ValidationLifecycleError('Unexpected lifecycle recovery artifact requires manual recovery.'); }
			const file = path.join(directory, name);
			const stat = await this.filesystem.lstat(file);
			if (!stat.isFile() || stat.isSymbolicLink()) { throw new ValidationLifecycleError('Lifecycle artifact is not a regular file.'); }
			if (name.endsWith('.pending')) { throw new ValidationLifecycleError('A pending lifecycle append requires manual recovery.'); }
			const bytes = await this.filesystem.readFileSafeBoundedBytes(file, this.maxApprovalBytes);
			result.bytes += bytes.byteLength;
			if (result.bytes > this.maxBucketBytes) { throw new ValidationLifecycleError('Lifecycle bucket exceeds its byte limit.'); }
			const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
			if (!text.endsWith('\n')) { throw new ValidationLifecycleError('Lifecycle log is truncated.'); }
			const events = text.slice(0, -1).split('\n').map(line => validateLifecycleEvent(JSON.parse(line)));
			if (events.length < 1 || events.length > this.maxApprovalEvents) { throw new ValidationLifecycleError('Lifecycle approval event count is invalid.'); }
			let previous = '0'.repeat(64);
			for (let index = 0; index < events.length; index++) {
				const event = events[index]!;
				if (eventIds.has(event.eventId) || event.approvalId !== name.slice(0, 36) || event.sequence !== index + 1 || event.previousEventHash !== previous || event.eventHash !== hash(eventHashInput(event)) || index > 0 && (event.executionId !== events[0]!.executionId || Date.parse(event.timestamp) < Date.parse(events[index - 1]!.timestamp))) { throw new ValidationLifecycleError('Lifecycle sequence, identity, timestamp order, or hash chain is invalid.'); }
				eventIds.add(event.eventId);
				if (index === 0 && event.eventType !== 'execution-start-committed') { throw new ValidationLifecycleError('Lifecycle history does not begin with a start commitment.'); }
				if (index > 0 && (event.eventType === 'execution-start-committed' || events.slice(1, index).some(prior => prior.eventType !== 'execution-start-committed'))) { throw new ValidationLifecycleError('Lifecycle terminal event ordering is invalid.'); }
				previous = event.eventHash;
			}
			if (result.has(events[0]!.approvalId)) { throw new ValidationLifecycleError('Duplicate lifecycle approval identity.'); }
			result.set(events[0]!.approvalId, events[0] as ExecutionStartCommittedEventV1);
		}
		return result;
	}
}

export function validateValidationLifecycleEvent(value: unknown): ValidationLifecycleEventV1 { return validateLifecycleEvent(value); }
function validateLifecycleEvent(value: unknown): ValidationLifecycleEventV1 {
	canonicalize(value);
	const event = plain(value);
	const startKeys = ['schemaVersion','eventId','executionId','approvalId','sequence','eventType','timestamp','approvalHistory','authorizationBindingDigest','projectRoot','projectIdentity','permittedTargets','procedureId','procedureVersion','artifactDigest','argumentDigest','evidenceSnapshotId','evidenceDigest','capabilities','resourceLimits','previousEventHash','eventHash'];
	if (event.eventType === 'execution-start-committed') {
		exact(event, startKeys);
		if (event.schemaVersion !== 1 || !isUuid(event.eventId) || !isUuid(event.executionId) || !isUuid(event.approvalId) || event.sequence !== 1 || !iso(event.timestamp)
			|| !isHash(event.authorizationBindingDigest) || typeof event.projectRoot !== 'string' || event.projectRoot.length > 2048 || !path.isAbsolute(event.projectRoot)
			|| !isDigest(event.projectIdentity) || !Array.isArray(event.permittedTargets) || event.permittedTargets.length < 1 || event.permittedTargets.length > 256
			|| event.permittedTargets.some((item: unknown) => typeof item !== 'string' || !item || item.length > 1024 || item.includes('..') || item.startsWith('/') || item.includes('\\'))
			|| !isProcedureId(event.procedureId) || !isSemVer(event.procedureVersion) || !isDigest(event.artifactDigest) || !isDigest(event.argumentDigest)
			|| !isSafeId(event.evidenceSnapshotId) || !isDigest(event.evidenceDigest) || !isHash(event.previousEventHash) || !isHash(event.eventHash)) { throw new TypeError('Invalid lifecycle start event.'); }
		const history = plain(event.approvalHistory); exact(history, ['eventId','eventHash']);
		if (!isUuid(history.eventId) || !isHash(history.eventHash)) { throw new TypeError('Invalid approval history reference.'); }
		const caps = plain(event.capabilities); exact(caps, ['filesystem','network','projectWrites','inheritedCredentials']);
		if (!['none','read-only'].includes(caps.filesystem) || caps.network !== 'none' || caps.projectWrites !== false || caps.inheritedCredentials !== false) { throw new TypeError('Unsupported lifecycle capabilities.'); }
		const limits = plain(event.resourceLimits); exact(limits, ['timeoutMs','memoryBytes','outputBytes','processCount']);
		if (Object.values(limits).some(value => !Number.isSafeInteger(value) || Number(value) < 1)) { throw new TypeError('Invalid lifecycle resource limits.'); }
	} else if (['execution-completed','execution-failed','execution-cancelled','execution-expired','execution-blocked','execution-interrupted'].includes(String(event.eventType))) {
		exact(event, ['schemaVersion','eventId','executionId','approvalId','sequence','eventType','timestamp','category','previousEventHash','eventHash']);
		if (event.schemaVersion !== 1 || !isUuid(event.eventId) || !isUuid(event.executionId) || !isUuid(event.approvalId) || !Number.isSafeInteger(event.sequence) || Number(event.sequence) < 2 || !iso(event.timestamp) || typeof event.category !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(event.category) || !isHash(event.previousEventHash) || !isHash(event.eventHash)) { throw new TypeError('Invalid lifecycle terminal event.'); }
	} else { throw new TypeError('Unknown lifecycle event type.'); }
	if (Buffer.byteLength(canonicalize(event), 'utf8') > VALIDATION_LIFECYCLE_MAX_APPROVAL_BYTES) { throw new RangeError('Lifecycle event exceeds its size limit.'); }
	return JSON.parse(JSON.stringify(event)) as ValidationLifecycleEventV1;
}
function validateStartInput(value: StartCommitInputV1): StartCommitInputV1 {
	const item = plain(value); exact(item, ['approvalId','timestamp','approvalHistory','authorizationBindingDigest','projectRoot','projectIdentity','permittedTargets','procedureId','procedureVersion','artifactDigest','argumentDigest','evidenceSnapshotId','evidenceDigest','capabilities','resourceLimits'], ['executionId']);
	const event = validateLifecycleEvent({ ...item, schemaVersion: 1, eventId: randomUUID(), executionId: item.executionId ?? randomUUID(), sequence: 1, eventType: 'execution-start-committed', previousEventHash: '0'.repeat(64), eventHash: '0'.repeat(64) });
	const { schemaVersion: _v, eventId: _e, executionId: _x, sequence: _s, eventType: _t, previousEventHash: _p, eventHash: _h, ...input } = event as ExecutionStartCommittedEventV1;
	return input;
}
function historical(event: ExecutionStartCommittedEventV1): HistoricalStartCommitmentV1 { return { ...event, historicalOnly: true, canAuthorizeExecution: false, approvalStatus: 'consumed' }; }
function eventHashInput(event: ValidationLifecycleEventV1): unknown { const { eventHash: _hash, ...input } = event; return input; }
function hash(value: unknown): string { return createHash('sha256').update(canonicalize(value)).digest('hex'); }
function bucketFor(approvalId: string): string { return createHash('sha256').update(approvalId).digest('hex').slice(0, 2); }
function normalizePath(value: string): string { let result = path.resolve(value); if (result.startsWith('\\\\?\\')) { result = result.slice(4); } result = result.replace(/\\/g, '/'); return process.platform === 'win32' ? result.toLowerCase() : result; }
function plain(value: unknown): Record<string, any> { if (!value || typeof value !== 'object' || Array.isArray(value) || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) { throw new TypeError('Expected a plain lifecycle record.'); } return value as Record<string, any>; }
function exact(value: Record<string, unknown>, required: string[], optional: string[] = []): void { if (Object.keys(value).some(key => !required.includes(key) && !optional.includes(key)) || required.some(key => !Object.prototype.hasOwnProperty.call(value, key))) { throw new TypeError('Unknown or missing lifecycle record field.'); } }
function isUuid(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value); }
function isHash(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
function isDigest(value: unknown): value is string { return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value); }
function isSafeId(value: unknown): value is string { return typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(value); }
function isProcedureId(value: unknown): value is string { return typeof value === 'string' && /^[a-z][a-z0-9.-]*:[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/.test(value); }
function isSemVer(value: unknown): value is string { return typeof value === 'string' && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value); }
function iso(value: unknown): value is string { return typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value; }

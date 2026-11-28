import * as assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { suite, test } from 'mocha';
import { ApprovalHistoryStore } from '../../packages/core/src/validation/approvalHistory';
import { authorizationBindingDigest } from '../../packages/core/src/validation/authorization';
import { ValidationLifecycleStore, validateValidationLifecycleEvent } from '../../packages/core/src/validation/validationLifecycle';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';
import type { FileSystem } from '../../packages/core/src/shared/platform';
import { CONTROLLED_VALIDATION_CONSENT_DISCLOSURE_VERSION, ControlledValidationAuthorizationService, ControlledValidationAuthorizationClock, ControlledValidationAuthorizationDependencies, ControlledValidationAuthorizationIdSource, ControlledValidationAuthorizationRequestV1, VerifiedControlledValidationProcedure } from '../../packages/core/src/validation/authorization';
import { digestCanonical, ProcedureMetadataV1 } from '../../packages/core/src/validation/contracts';

const digest = `sha256:${'c'.repeat(64)}`;
const execFile = promisify(execFileCallback);
const procedureMetadata: ProcedureMetadataV1 = {
	schemaVersion: 1, id: 'aqiron:integrity:source-span', version: '1.0.0', packageDigest: digest,
	publisherId: 'aqiron-release', signature: { identity: 'release', state: 'unverified' },
	supportedHypothesisTypes: ['source-integrity'], supportedAssetTypes: ['file'], requiredEvidenceTypes: ['source-span'],
	parameterSchemaId: 'source-span-input-v1', targetPolicyId: 'project-file-v1', scopePolicyId: 'selected-targets-v1', environmentRequirements: ['offline'],
	capabilities: { filesystem: 'read-only', network: 'none' }, resourceCeilings: { timeoutMs: 2000, memoryBytes: 64 * 1024 * 1024, outputBytes: 8192, processCount: 1 },
	resultSchemaId: 'source-span-result-v1', retirement: 'active',
};

function request(id: string): ControlledValidationAuthorizationRequestV1 {
	return { schemaVersion: 1, requestId: id, consent: { disclosureVersion: CONTROLLED_VALIDATION_CONSENT_DISCLOSURE_VERSION, confirmed: true },
		project: { root: path.resolve(os.tmpdir()).replace(/\\/g, '/'), identity: digest, permittedTargets: ['src/a.ts'] },
		procedure: { id: procedureMetadata.id, version: procedureMetadata.version, artifactDigest: digest },
		arguments: { path: 'src/a.ts' }, argumentDigest: `sha256:${digestCanonical({ path: 'src/a.ts' })}`,
		evidence: { snapshotId: 'snapshot-1', digest }, capabilities: { filesystem: 'read-only', network: 'none', projectWrites: false, inheritedCredentials: false },
		resourceLimits: { timeoutMs: 1000, memoryBytes: 32 * 1024 * 1024, outputBytes: 4096, processCount: 1 } };
}

function durableTestFileSystem(options: { failAppend?: boolean } = {}): FileSystem {
	const base = createNodeFileSystem();
	return { ...base,
		readFileSafeBoundedBytes: async (file, max) => { const bytes = await fs.readFile(file); if (bytes.byteLength > max) { throw Object.assign(new Error('too large'), { code: 'FILE_TOO_LARGE' }); } return new Uint8Array(bytes); },
		syncDirectoryDurable: async () => undefined,
		writeFileDurableExclusive: async (file, bytes) => { const handle = await fs.open(file, 'wx'); try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); } },
		appendFileDurable: async (file, bytes) => { if (options.failAppend && file.includes(`${path.sep}lifecycle${path.sep}`)) { throw Object.assign(new Error('injected append fault'), { code: 'EIO' }); } const handle = await fs.open(file, 'a'); try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); } },
		unlinkDurable: async file => { await fs.unlink(file); },
	} as FileSystem;
}
function bucket(approvalId: string): string { return createHash('sha256').update(approvalId).digest('hex').slice(0, 2); }

async function canonicalTempRoot(prefix: string): Promise<string> {
	const supplied = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
	return await fs.realpath(supplied);
}

async function lifecyclePathDiagnostics(suppliedRoot: string, bucketRoot: string): Promise<string> {
	const [physical, stat] = await Promise.all([fs.realpath(bucketRoot), fs.lstat(bucketRoot)]);
	const normalized = (value: string) => path.resolve(value).replace(/\\/g, '/').replace(/^\\\\\?\\/, '').toLowerCase();
	return JSON.stringify({ suppliedLifecycleRoot: suppliedRoot, bucketRoot, realpathBucketRoot: physical,
		lstat: { directory: stat.isDirectory(), symlink: stat.isSymbolicLink() },
		normalized: { bucketRoot: normalized(bucketRoot), realpathBucketRoot: normalized(physical) } });
}

function serviceFor(history: ApprovalHistoryStore, lifecycle: ValidationLifecycleStore) {
	let next = 1;
	const dependencies: ControlledValidationAuthorizationDependencies = {
		resolveProject: async root => ({ canonicalRoot: root, identity: digest }), validateProjectTargets: async () => true,
		resolveVerifiedProcedure: async () => ({ metadata: procedureMetadata, artifactDigest: digest, inputSchemaDigest: digest, policyDigest: digest, verified: true, validateArguments: value => typeof value === 'object' && value !== null }),
		resolveCurrentEvidence: async () => ({ digest, current: true }), validatePolicy: () => true,
	};
	const clock: ControlledValidationAuthorizationClock = { wallNow: () => Date.parse('2026-11-27T12:00:00.000Z'), monotonicNow: () => 1000 };
	const ids: ControlledValidationAuthorizationIdSource = { approvalId: () => `00000000-0000-4000-8000-${String(next++).padStart(12, '0')}`, nonce: () => String(next).padStart(64, '0'), epoch: () => '00000000-0000-4000-8000-000000000099' };
	return new ControlledValidationAuthorizationService(dependencies, history, lifecycle, clock, ids);
}

suite('Controlled Validation atomic lifecycle commitment', function () {
	this.timeout(20_000);
	test('commits one durable non-executable start and rejects reuse', async () => {
		const root = await canonicalTempRoot('aqiron-lifecycle-once-');
		try {
			const fileSystem = durableTestFileSystem(); const history = new ApprovalHistoryStore(fileSystem, root); const lifecycle = new ValidationLifecycleStore(fileSystem, root);
			const service = serviceFor(history, lifecycle); const candidate = request('once'); const approval = await service.approve(candidate); assert.equal(approval.ok, true); if (!approval.ok) { return; }
			const binding = authorizationBindingDigest(approval.approval.approvalId, approval.approval.requestDigest);
			const committed = await service.commitStart(approval.approval.approvalId, binding, candidate);
			assert.equal(committed.ok, true); if (!committed.ok) { return; } assert.equal(committed.duplicate, false); assert.equal(committed.receipt.nonExecutable, true);
			assert.equal((await lifecycle.queryStart(approval.approval.approvalId))?.canAuthorizeExecution, false);
			const retry = await service.commitStart(approval.approval.approvalId, binding, candidate); assert.equal(retry.ok, false); if (!retry.ok) { assert.equal(retry.code, 'APPROVAL_ALREADY_CONSUMED'); }
			const restarted = serviceFor(history, lifecycle); const restored = await restarted.validate(approval.approval.approvalId, candidate); assert.equal(restored.ok, false); if (!restored.ok) { assert.equal(restored.code, 'APPROVAL_NOT_FOUND'); }
			assert.equal(await fs.readdir(path.join(root, '.aqiron-security', 'validation-lifecycle', bucket(approval.approval.approvalId), '.aqiron-security', 'lifecycle')).then(entries => entries.length), 1);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('simultaneous starts for one approval have a single durable winner', async () => {
		const root = await canonicalTempRoot('aqiron-lifecycle-race-');
		try {
			const fileSystem = durableTestFileSystem(); const history = new ApprovalHistoryStore(fileSystem, root); const lifecycle = new ValidationLifecycleStore(fileSystem, root); const service = serviceFor(history, lifecycle);
			const candidate = request('race'); const approval = await service.approve(candidate); assert.equal(approval.ok, true); if (!approval.ok) { return; }
			const binding = authorizationBindingDigest(approval.approval.approvalId, approval.approval.requestDigest);
			const results = await Promise.all([service.commitStart(approval.approval.approvalId, binding, candidate), service.commitStart(approval.approval.approvalId, binding, candidate)]);
			assert.equal(results.filter(result => result.ok).length, 1); assert.equal(results.filter(result => !result.ok && result.code === 'APPROVAL_ALREADY_CONSUMED').length, 1);
			assert.ok(await lifecycle.queryStart(approval.approval.approvalId));
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('different approvals commit independently and bind all authorization facts', async () => {
		const root = await canonicalTempRoot('aqiron-lifecycle-distinct-');
		try {
			const fileSystem = durableTestFileSystem(); const history = new ApprovalHistoryStore(fileSystem, root); const lifecycle = new ValidationLifecycleStore(fileSystem, root); const service = serviceFor(history, lifecycle);
			const a = request('different-a'); const b = request('different-b'); const [issuedA, issuedB] = await Promise.all([service.approve(a), service.approve(b)]); assert.equal(issuedA.ok && issuedB.ok, true); if (!issuedA.ok || !issuedB.ok) { return; }
			const [one, two] = await Promise.all([service.commitStart(issuedA.approval.approvalId, authorizationBindingDigest(issuedA.approval.approvalId, issuedA.approval.requestDigest), a), service.commitStart(issuedB.approval.approvalId, authorizationBindingDigest(issuedB.approval.approvalId, issuedB.approval.requestDigest), b)]);
			assert.equal(one.ok && two.ok, true); const record = await lifecycle.queryStart(issuedA.approval.approvalId); assert.equal(record?.argumentDigest, issuedA.approval.argumentDigest); assert.equal(record?.approvalHistory.eventHash.length, 64);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('binding tampering, revocation, and expiry never commit a start', async () => {
		for (const scenario of ['binding', 'revoked', 'expired'] as const) {
			const root = await canonicalTempRoot(`aqiron-lifecycle-${scenario}-`);
			try {
				const fileSystem = durableTestFileSystem(); const history = new ApprovalHistoryStore(fileSystem, root); const lifecycle = new ValidationLifecycleStore(fileSystem, root); const service = serviceFor(history, lifecycle); const candidate = request(scenario); const issued = await service.approve(candidate); assert.equal(issued.ok, true); if (!issued.ok) { continue; }
				const binding = authorizationBindingDigest(issued.approval.approvalId, issued.approval.requestDigest);
				if (scenario === 'revoked') { await service.revoke(issued.approval.approvalId); }
				if (scenario === 'expired') { (service as unknown as { clock: { monotonicNow(): number } }).clock.monotonicNow = () => 1e9; }
				const result = await service.commitStart(issued.approval.approvalId, scenario === 'binding' ? '0'.repeat(64) : binding, candidate);
				assert.equal(result.ok, false); assert.equal(await lifecycle.queryStart(issued.approval.approvalId), undefined);
			} finally { await fs.rm(root, { recursive: true, force: true }); }
		}
	});

	test('revocation ordered before start commitment prevents the write', async () => {
		const root = await canonicalTempRoot('aqiron-lifecycle-revoke-race-');
		try {
			const fileSystem = durableTestFileSystem(); const history = new ApprovalHistoryStore(fileSystem, root); const lifecycle = new ValidationLifecycleStore(fileSystem, root); const service = serviceFor(history, lifecycle); const candidate = request('revoke-race'); const issued = await service.approve(candidate); assert.equal(issued.ok, true); if (!issued.ok) { return; }
			const binding = authorizationBindingDigest(issued.approval.approvalId, issued.approval.requestDigest);
			const [revoked, committed] = await Promise.all([service.revoke(issued.approval.approvalId), service.commitStart(issued.approval.approvalId, binding, candidate)]);
			assert.equal(revoked.ok, true); assert.equal(committed.ok, false); assert.equal(await lifecycle.queryStart(issued.approval.approvalId), undefined);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('event-size and bucket capacity reject new records without deleting history', async () => {
		const root = await canonicalTempRoot('aqiron-lifecycle-limits-');
		try {
			const fileSystem = durableTestFileSystem(); const tooSmall = new ValidationLifecycleStore(fileSystem, root, { maxApprovalBytes: 512 });
			const input = { approvalId: '00000000-0000-4000-8000-000000000041', timestamp: '2026-11-27T12:00:00.000Z', approvalHistory: { eventId: '00000000-0000-4000-8000-000000000042', eventHash: 'a'.repeat(64) }, authorizationBindingDigest: 'b'.repeat(64), projectRoot: path.resolve(os.tmpdir()).replace(/\\/g, '/'), projectIdentity: digest, permittedTargets: ['src/a.ts'], procedureId: procedureMetadata.id, procedureVersion: procedureMetadata.version, artifactDigest: digest, argumentDigest: digest, evidenceSnapshotId: 'snapshot-1', evidenceDigest: digest, capabilities: { filesystem: 'read-only' as const, network: 'none' as const, projectWrites: false as const, inheritedCredentials: false as const }, resourceLimits: { timeoutMs: 1000, memoryBytes: 1024, outputBytes: 1024, processCount: 1 } };
			await assert.rejects(() => tooSmall.commitStart(input), /byte limit/);
			const bounded = new ValidationLifecycleStore(fileSystem, root, { maxBucketBytes: 1 }); await assert.rejects(() => bounded.commitStart(input), /byte limit/); assert.equal(await bounded.queryStart(input.approvalId), undefined);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('stale lock recovery is safe and a live lock timeout fails closed', async function () {
		this.timeout(20_000);
		const root = await canonicalTempRoot('aqiron-lifecycle-locks-');
		try {
			const fileSystem = durableTestFileSystem(); const input = { approvalId: '00000000-0000-4000-8000-000000000051', timestamp: '2026-11-27T12:00:00.000Z', approvalHistory: { eventId: '00000000-0000-4000-8000-000000000052', eventHash: 'a'.repeat(64) }, authorizationBindingDigest: 'b'.repeat(64), projectRoot: path.resolve(os.tmpdir()).replace(/\\/g, '/'), projectIdentity: digest, permittedTargets: ['src/a.ts'], procedureId: procedureMetadata.id, procedureVersion: procedureMetadata.version, artifactDigest: digest, argumentDigest: digest, evidenceSnapshotId: 'snapshot-1', evidenceDigest: digest, capabilities: { filesystem: 'read-only' as const, network: 'none' as const, projectWrites: false as const, inheritedCredentials: false as const }, resourceLimits: { timeoutMs: 1000, memoryBytes: 1024, outputBytes: 1024, processCount: 1 } };
			const deadPid = Number((await execFile(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'])).stdout); const bucketRoot = path.join(root, '.aqiron-security', 'validation-lifecycle', bucket(input.approvalId)); const lockPath = path.join(bucketRoot, '.aqiron-security', 'hypotheses.json.lock'); await fs.mkdir(lockPath, { recursive: true }); await fs.writeFile(path.join(lockPath, 'owner.json'), JSON.stringify({ pid: deadPid, token: 'stale-lock-owner' }));
			const recovered = await new ValidationLifecycleStore(fileSystem, root).commitStart(input); assert.equal(recovered.committed, true);
			const timeoutRoot = await canonicalTempRoot('aqiron-lifecycle-lock-timeout-');
			try {
				const timeoutBucket = path.join(timeoutRoot, '.aqiron-security', 'validation-lifecycle', bucket(input.approvalId)); const liveLock = path.join(timeoutBucket, '.aqiron-security', 'hypotheses.json.lock'); await fs.mkdir(liveLock, { recursive: true }); await fs.writeFile(path.join(liveLock, 'owner.json'), JSON.stringify({ pid: process.pid, token: 'live-lock-owner' }));
				await assert.rejects(() => new ValidationLifecycleStore(fileSystem, timeoutRoot).commitStart(input), /Lifecycle commitment/);
				assert.equal(await fs.readdir(path.join(timeoutBucket, '.aqiron-security')).then(entries => entries.some(name => String(name).endsWith('.log'))), false);
			} finally { await fs.rm(timeoutRoot, { recursive: true, force: true }); }
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('failed durable append returns no receipt and leaves a manual-recovery marker', async () => {
		const root = await canonicalTempRoot('aqiron-lifecycle-fault-');
		try {
			const fileSystem = durableTestFileSystem({ failAppend: true }); const history = new ApprovalHistoryStore(fileSystem, root); const lifecycle = new ValidationLifecycleStore(fileSystem, root); const service = serviceFor(history, lifecycle); const candidate = request('fault'); const issued = await service.approve(candidate); assert.equal(issued.ok, true); if (!issued.ok) { return; }
			const binding = authorizationBindingDigest(issued.approval.approvalId, issued.approval.requestDigest); const result = await service.commitStart(issued.approval.approvalId, binding, candidate); assert.equal(result.ok, false);
			const directory = path.join(root, '.aqiron-security', 'validation-lifecycle', bucket(issued.approval.approvalId), '.aqiron-security', 'lifecycle');
			const markers = await fs.readdir(directory).catch(() => []); assert.ok(markers.some(name => String(name).endsWith('.pending')));
			const active = await service.validate(issued.approval.approvalId, candidate); assert.equal(active.ok, true);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('corrupt, truncated, duplicate, and reordered lifecycle records fail closed', async () => {
		const root = await canonicalTempRoot('aqiron-lifecycle-corrupt-');
		try {
			const store = new ValidationLifecycleStore(durableTestFileSystem(), root); const input = { approvalId: '00000000-0000-4000-8000-000000000011', timestamp: '2026-11-27T12:00:00.000Z', approvalHistory: { eventId: '00000000-0000-4000-8000-000000000012', eventHash: 'a'.repeat(64) }, authorizationBindingDigest: 'b'.repeat(64), projectRoot: path.resolve(os.tmpdir()).replace(/\\/g, '/'), projectIdentity: digest, permittedTargets: ['src/a.ts'], procedureId: procedureMetadata.id, procedureVersion: procedureMetadata.version, artifactDigest: digest, argumentDigest: digest, evidenceSnapshotId: 'snapshot-1', evidenceDigest: digest, capabilities: { filesystem: 'read-only' as const, network: 'none' as const, projectWrites: false as const, inheritedCredentials: false as const }, resourceLimits: { timeoutMs: 1000, memoryBytes: 1024, outputBytes: 1024, processCount: 1 } };
			await store.commitStart(input); const good = await store.queryStart(input.approvalId); assert.ok(good); assert.equal(good?.historicalOnly, true); assert.equal(good?.canAuthorizeExecution, false);
			const logPath = path.join(root, '.aqiron-security', 'validation-lifecycle', bucket(input.approvalId), '.aqiron-security', 'lifecycle', `${input.approvalId}.log`);
			const raw = await fs.readFile(logPath, 'utf8');
			await fs.writeFile(logPath, `${raw.slice(0, -2)}\n`);
			await assert.rejects(() => store.queryStart(input.approvalId), /Lifecycle/);
			const malformed = { ...JSON.parse(raw.trim()), sequence: 2 };
			assert.throws(() => validateValidationLifecycleEvent(malformed), /lifecycle/i);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('real Node filesystem integration fails closed when durable directory sync is unavailable', async () => {
		const root = await canonicalTempRoot('aqiron-lifecycle-nodefs-');
		try {
			const store = new ValidationLifecycleStore(createNodeFileSystem(), root);
			const input = { approvalId: '00000000-0000-4000-8000-000000000021', timestamp: '2026-11-27T12:00:00.000Z', approvalHistory: { eventId: '00000000-0000-4000-8000-000000000022', eventHash: 'a'.repeat(64) }, authorizationBindingDigest: 'b'.repeat(64), projectRoot: path.resolve(os.tmpdir()).replace(/\\/g, '/'), projectIdentity: digest, permittedTargets: ['src/a.ts'], procedureId: procedureMetadata.id, procedureVersion: procedureMetadata.version, artifactDigest: digest, argumentDigest: digest, evidenceSnapshotId: 'snapshot-1', evidenceDigest: digest, capabilities: { filesystem: 'read-only' as const, network: 'none' as const, projectWrites: false as const, inheritedCredentials: false as const }, resourceLimits: { timeoutMs: 1000, memoryBytes: 1024, outputBytes: 1024, processCount: 1 } };
			if (process.platform === 'win32') { await assert.rejects(() => store.commitStart(input), /durability|Lifecycle/i); assert.equal(await store.queryStart(input.approvalId), undefined); }
			else { const result = await store.commitStart(input); assert.equal(result.committed, true); assert.ok(await store.queryStart(input.approvalId)); }
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('real Node filesystem durably commits and reopens a complete POSIX start lifecycle', async function () {
		if (process.platform !== 'linux' && process.platform !== 'darwin') { this.skip(); return; }
		const root = await canonicalTempRoot('aqiron-lifecycle-posix-integration-');
		try {
			const stats = await fs.statfs(root);
			process.stdout.write(`POSIX lifecycle durability environment: os=${process.platform} ${os.release()} node=${process.version} statfs.type=0x${stats.type.toString(16)} root=${root}\n`);
			const adapter = createNodeFileSystem();
			const history = new ApprovalHistoryStore(adapter, root);
			const lifecycle = new ValidationLifecycleStore(adapter, root);
			const service = serviceFor(history, lifecycle); const candidate = request('posix-real-node-adapter');
			const approved = await service.approve(candidate); assert.equal(approved.ok, true); if (!approved.ok) { return; }
			const binding = authorizationBindingDigest(approved.approval.approvalId, approved.approval.requestDigest);
			let committed;
			try { committed = await service.commitStart(approved.approval.approvalId, binding, candidate); }
			catch (error) {
				const bucketRoot = path.join(root, '.aqiron-security', 'validation-lifecycle', bucket(approved.approval.approvalId));
				process.stderr.write(`Lifecycle path diagnostics: ${await lifecyclePathDiagnostics(root, bucketRoot)}\n`);
				throw error;
			}
			assert.equal(committed.ok, true); if (!committed.ok) { return; }
			assert.equal(committed.receipt.nonExecutable, true); assert.equal(committed.receipt.status, 'consumed');
			const reopened = await new ValidationLifecycleStore(createNodeFileSystem(), root).queryStart(approved.approval.approvalId);
			assert.ok(reopened); assert.equal(reopened?.eventType, 'execution-start-committed'); assert.equal(reopened?.sequence, 1); assert.equal(reopened?.executionId, committed.receipt.executionId);
			assert.equal(reopened?.historicalOnly, true); assert.equal(reopened?.canAuthorizeExecution, false); assert.equal(reopened?.eventHash.length, 64);
			const logPath = path.join(root, '.aqiron-security', 'validation-lifecycle', bucket(approved.approval.approvalId), '.aqiron-security', 'lifecycle', `${approved.approval.approvalId}.log`);
			const lines = (await fs.readFile(logPath, 'utf8')).trimEnd().split('\n'); assert.equal(lines.length, 1);
			const validated = validateValidationLifecycleEvent(JSON.parse(lines[0]!));
			assert.equal(validated.eventType, 'execution-start-committed'); assert.equal(validated.sequence, 1); assert.equal(validated.eventHash, reopened?.eventHash);
			assert.equal(validated.previousEventHash, '0'.repeat(64));
			const approvalHistory = await new ApprovalHistoryStore(createNodeFileSystem(), root).query();
			assert.equal(approvalHistory.length, 1); assert.equal(approvalHistory[0]?.approvalId, approved.approval.approvalId); assert.equal(approvalHistory[0]?.historicalOnly, true);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('independent processes serialize duplicate commitments with the filesystem lock', async () => {
		const root = await canonicalTempRoot('aqiron-lifecycle-process-race-');
		try {
			const approvalId = '00000000-0000-4000-8000-000000000031';
			const input = { approvalId, timestamp: '2026-11-27T12:00:00.000Z', approvalHistory: { eventId: '00000000-0000-4000-8000-000000000032', eventHash: 'a'.repeat(64) }, authorizationBindingDigest: 'b'.repeat(64), projectRoot: path.resolve(os.tmpdir()).replace(/\\/g, '/'), projectIdentity: digest, permittedTargets: ['src/a.ts'], procedureId: procedureMetadata.id, procedureVersion: procedureMetadata.version, artifactDigest: digest, argumentDigest: digest, evidenceSnapshotId: 'snapshot-1', evidenceDigest: digest, capabilities: { filesystem: 'read-only', network: 'none', projectWrites: false, inheritedCredentials: false }, resourceLimits: { timeoutMs: 1000, memoryBytes: 1024, outputBytes: 1024, processCount: 1 } };
			const worker = path.join(__dirname, 'controlledValidationLifecycleWorker.js');
			const invoke = async () => JSON.parse((await execFile(process.execPath, [worker, root, JSON.stringify(input)], { timeout: 30_000 })).stdout.trim()) as { committed: boolean; duplicate: boolean; executionId: string };
			const results = await Promise.all([invoke(), invoke()]);
			assert.equal(results.filter(item => item.committed).length, 1); assert.equal(results.filter(item => item.duplicate).length, 1); assert.equal(results[0]?.executionId, results[1]?.executionId);
			const persisted = await new ValidationLifecycleStore(durableTestFileSystem(), root).queryStart(approvalId); assert.ok(persisted);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});
});

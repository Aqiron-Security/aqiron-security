import * as assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { suite, test } from 'mocha';
import {
	CONTROLLED_VALIDATION_APPROVAL_TTL_MS,
	CONTROLLED_VALIDATION_CONSENT_DISCLOSURE_VERSION,
	ControlledValidationAuthorizationClock,
	ControlledValidationAuthorizationDependencies,
	ControlledValidationAuthorizationIdSource,
	ControlledValidationAuthorizationRequestV1,
	ControlledValidationAuthorizationService,
	VerifiedControlledValidationProcedure,
} from '../../packages/core/src/validation/authorization';
import { digestCanonical, ProcedureMetadataV1 } from '../../packages/core/src/validation/contracts';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';
import { ApprovalHistoryPersistence, ApprovalHistoryStore, HistoricalApprovalRecordV1 } from '../../packages/core/src/validation/approvalHistory';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';
import type { FileSystem } from '../../packages/core/src/shared/platform';
import { ValidationLifecycleStore } from '../../packages/core/src/validation/validationLifecycle';

const digest = `sha256:${'a'.repeat(64)}`;
const differentDigest = `sha256:${'b'.repeat(64)}`;
const metadata: ProcedureMetadataV1 = {
	schemaVersion: 1, id: 'aqiron:integrity:source-span', version: '1.0.0', packageDigest: digest,
	publisherId: 'aqiron-release', signature: { identity: 'aqiron-release-key', state: 'unverified' },
	supportedHypothesisTypes: ['source-integrity'], supportedAssetTypes: ['file'], requiredEvidenceTypes: ['source-span'],
	parameterSchemaId: 'source-span-input-v1', targetPolicyId: 'project-file-v1', scopePolicyId: 'selected-targets-v1',
	environmentRequirements: ['offline'], capabilities: { filesystem: 'read-only', network: 'none' },
	resourceCeilings: { timeoutMs: 2_000, memoryBytes: 64 * 1024 * 1024, outputBytes: 8_192, processCount: 1 },
	resultSchemaId: 'source-span-result-v1', retirement: 'active',
};

class TestApprovalHistory implements ApprovalHistoryPersistence {
	readonly records = new Map<string, HistoricalApprovalRecordV1>();
	failIssued = false;
	failStatus = false;
	async recordIssued(input: import('../../packages/core/src/validation/approvalHistory').ApprovalIssuedAuditInputV1): Promise<{ eventId: string; eventHash: string }> {
		if (this.failIssued) { throw new Error('injected issued-history failure'); }
		if ([...this.records.values()].some(item => item.requestId === input.requestId) || this.records.has(input.approvalId)) { throw new Error('duplicate history identity'); }
		this.records.set(input.approvalId, { schemaVersion: 1, ...JSON.parse(JSON.stringify(input)), status: 'historical-only', historicalOnly: true, canAuthorizeExecution: false, lastEventAt: input.createdAt });
		return { eventId: '00000000-0000-4000-8000-000000000001', eventHash: 'a'.repeat(64) };
	}
	async recordStatus(approvalId: string, decision: 'revoked' | 'expired' | 'invalidated-by-restart' | 'shutdown', timestamp: string): Promise<void> {
		if (this.failStatus) { throw new Error('injected status-history failure'); }
		const prior = this.records.get(approvalId);
		if (!prior) { throw new Error('missing record'); }
		this.records.set(approvalId, { ...prior, status: decision === 'revoked' ? 'revoked' : decision === 'expired' ? 'expired' : 'invalidated', lastEventAt: timestamp });
	}
	async query(): Promise<HistoricalApprovalRecordV1[]> { return [...this.records.values()].map(record => JSON.parse(JSON.stringify(record)) as HistoricalApprovalRecordV1); }
}

function request(id = 'request-1'): ControlledValidationAuthorizationRequestV1 {
	return {
		schemaVersion: 1, requestId: id,
		consent: { disclosureVersion: CONTROLLED_VALIDATION_CONSENT_DISCLOSURE_VERSION, confirmed: true },
		project: { root: 'C:/repo', identity: digest, permittedTargets: ['src/a.ts'] },
		procedure: { id: metadata.id, version: metadata.version, artifactDigest: metadata.packageDigest },
		arguments: { path: 'src/a.ts', expectedDigest: digest }, argumentDigest: `sha256:${digestCanonical({ path: 'src/a.ts', expectedDigest: digest })}`,
		evidence: { snapshotId: 'snapshot-1', digest },
		capabilities: { filesystem: 'read-only', network: 'none', projectWrites: false, inheritedCredentials: false },
		resourceLimits: { timeoutMs: 1_000, memoryBytes: 32 * 1024 * 1024, outputBytes: 4_096, processCount: 1 },
	};
}

function fixture(history: ApprovalHistoryPersistence = new TestApprovalHistory(), lifecycle?: ValidationLifecycleStore) {
	let wall = Date.parse('2026-11-27T12:00:00.000Z');
	let mono = 10_000;
	let evidenceCurrent = true;
	let procedure: VerifiedControlledValidationProcedure | undefined = {
		metadata, artifactDigest: digest, inputSchemaDigest: digest, policyDigest: digest, verified: true,
		validateArguments: value => typeof value === 'object' && value !== null && !Array.isArray(value)
			&& typeof (value as Record<string, unknown>).path === 'string'
			&& typeof (value as Record<string, unknown>).expectedDigest === 'string',
	};
	let nextId = 1;
	let nextNonce = 1;
	const dependencies: ControlledValidationAuthorizationDependencies = {
		resolveProject: async root => ({ canonicalRoot: root, identity: digest }),
		validateProjectTargets: async (_project, targets) => targets.every(target => target === 'src/a.ts'),
		resolveVerifiedProcedure: async () => procedure,
		resolveCurrentEvidence: async () => ({ digest, current: evidenceCurrent }),
		validatePolicy: () => true,
	};
	const clock: ControlledValidationAuthorizationClock = { wallNow: () => wall, monotonicNow: () => mono };
	const ids: ControlledValidationAuthorizationIdSource = {
		approvalId: () => `00000000-0000-4000-8000-${String(nextId++).padStart(12, '0')}`,
		nonce: () => String(nextNonce++).padStart(64, '0'),
		epoch: () => '00000000-0000-4000-8000-000000000000',
	};
	return {
		service: new ControlledValidationAuthorizationService(dependencies, history, lifecycle, clock, ids),
		setMono(value: number) { mono = value; },
		setEvidenceCurrent(value: boolean) { evidenceCurrent = value; },
		setProcedure(value: VerifiedControlledValidationProcedure | undefined) { procedure = value; },
		dependencies, clock, ids, history,
	};
}

function reliableHistoryFileSystem(options: { failAppend?: boolean } = {}): FileSystem {
	const base = createNodeFileSystem();
	return {
		...base,
		readFileSafeBoundedBytes: async (file, maxBytes) => {
			const bytes = await fs.readFile(file);
			if (bytes.byteLength > maxBytes) { throw Object.assign(new Error('bounded test read exceeded'), { code: 'FILE_TOO_LARGE' }); }
			return new Uint8Array(bytes);
		},
		syncDirectoryDurable: async () => undefined,
		writeFileDurableExclusive: async (file, bytes) => {
			const handle = await fs.open(file, 'wx');
			try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
		},
		unlinkDurable: async file => { await fs.unlink(file); },
		appendFileDurable: async (file, bytes) => {
			if (options.failAppend) { throw Object.assign(new Error('injected durable append failure'), { code: 'EIO' }); }
			const handle = await fs.open(file, 'a');
			try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
		},
	} as FileSystem;
}

function issuedAuditInput(approvalId = '00000000-0000-4000-8000-000000000091') {
	const value = request(`audit-${approvalId.slice(-4)}`);
	return {
		approvalId, requestId: value.requestId, requestDigest: digestCanonical(value),
		createdAt: '2026-11-27T12:00:00.000Z', expiresAt: '2026-11-27T12:05:00.000Z',
		projectIdentity: value.project.identity, permittedScopeDigest: `sha256:${digestCanonical(value.project.permittedTargets)}`,
		procedureId: value.procedure.id, procedureVersion: value.procedure.version, artifactDigest: value.procedure.artifactDigest,
		argumentDigest: value.argumentDigest, evidenceSnapshotId: value.evidence.snapshotId, evidenceDigest: value.evidence.digest,
		capabilities: { filesystem: 'read-only' as const, network: 'none' as const, projectWrites: false as const, inheritedCredentials: false as const },
		resourceLimits: value.resourceLimits,
	};
}

suite('Controlled Validation Core authorization', () => {
	test('records a valid restricted approval without making it executable', async () => {
		const f = fixture();
		const result = await f.service.approve(request());
		assert.equal(result.ok, true, result.ok ? undefined : result.message);
		if (!result.ok) { return; }
		assert.equal(result.approval.status, 'approved');
		assert.equal(result.approval.nonExecutable, true);
		assert.match(result.approval.nonce, /^[a-f0-9]{64}$/);
		assert.equal(Date.parse(result.approval.expiresAt) - Date.parse(result.approval.createdAt), CONTROLLED_VALIDATION_APPROVAL_TTL_MS);
		assert.throws(() => f.service.assertExecutable(result.approval.approvalId), { code: 'APPROVAL_NON_EXECUTABLE' });
	});

	test('rejects noncanonical project roots and project scope substitution', async () => {
		const f = fixture();
		const invalidRoot = { ...request(), project: { ...request().project, root: 'C:/repo/../other' } };
		const rootResult = await f.service.approve(invalidRoot);
		assert.equal(rootResult.ok, false);
		if (!rootResult.ok) { assert.equal(rootResult.code, 'INVALID_REQUEST'); }
		const substitutedProject = { ...request(), project: { ...request().project, identity: differentDigest } };
		const projectResult = await f.service.approve(substitutedProject);
		assert.equal(projectResult.ok, false);
		if (!projectResult.ok) { assert.equal(projectResult.code, 'INVALID_PROJECT_SCOPE'); }
		const substituted = { ...request(), project: { ...request().project, permittedTargets: ['src/b.ts'] } };
		const targetResult = await f.service.approve(substituted);
		assert.equal(targetResult.ok, false);
		if (!targetResult.ok) { assert.equal(targetResult.code, 'TARGET_OUT_OF_SCOPE'); }
	});

	test('rejects altered arguments and mismatched argument digests', async () => {
		const f = fixture();
		const tampered = { ...request(), arguments: { path: 'src/b.ts', expectedDigest: digest } };
		const result = await f.service.approve(tampered);
		assert.equal(result.ok, false);
		if (!result.ok) { assert.equal(result.code, 'ARGUMENT_DIGEST_MISMATCH'); }
	});

	test('rejects stale or changed evidence snapshots', async () => {
		const f = fixture(); f.setEvidenceCurrent(false);
		const result = await f.service.approve(request());
		assert.equal(result.ok, false);
		if (!result.ok) { assert.equal(result.code, 'EVIDENCE_STALE'); }
	});

	test('rejects procedure identity and verified artifact digest mismatches', async () => {
		const f = fixture();
		const wrongIdentity = { ...request(), procedure: { ...request().procedure, id: 'aqiron:integrity:other' } };
		const identityResult = await f.service.approve(wrongIdentity);
		assert.equal(identityResult.ok, false);
		if (!identityResult.ok) { assert.equal(identityResult.code, 'PROCEDURE_IDENTITY_MISMATCH'); }
		const wrongArtifact = { ...request(), procedure: { ...request().procedure, artifactDigest: differentDigest } };
		const digestResult = await f.service.approve(wrongArtifact);
		assert.equal(digestResult.ok, false);
		if (!digestResult.ok) { assert.equal(digestResult.code, 'PROCEDURE_IDENTITY_MISMATCH'); }
	});

	test('expires approvals at the monotonic deadline and preserves an expired history record', async () => {
		const f = fixture();
		const approved = await f.service.approve(request());
		assert.equal(approved.ok, true);
		if (!approved.ok) { return; }
		f.setMono(10_000 + CONTROLLED_VALIDATION_APPROVAL_TTL_MS);
		const result = await f.service.validate(approved.approval.approvalId, request());
		assert.equal(result.ok, false);
		if (!result.ok) { assert.equal(result.code, 'APPROVAL_EXPIRED'); }
		assert.equal((await f.service.inspectHistory())[0]?.status, 'expired');
	});

	test('revokes approval and rejects later validation', async () => {
		const f = fixture();
		const approved = await f.service.approve(request());
		assert.equal(approved.ok, true);
		if (!approved.ok) { return; }
		assert.equal((await f.service.revoke(approved.approval.approvalId)).ok, true);
		const checked = await f.service.validate(approved.approval.approvalId, request());
		assert.equal(checked.ok, false);
		if (!checked.ok) { assert.equal(checked.code, 'APPROVAL_REVOKED'); }
	});

	test('rejects duplicate approval IDs and nonce reuse', async () => {
		const f = fixture();
		const sameIdSource: ControlledValidationAuthorizationIdSource = { ...f.ids, approvalId: () => '00000000-0000-4000-8000-000000000111' };
		const idService = new ControlledValidationAuthorizationService(f.dependencies, new TestApprovalHistory(), undefined, f.clock, sameIdSource);
		assert.equal((await idService.approve(request('first'))).ok, true);
		const duplicateId = await idService.approve(request('second'));
		assert.equal(duplicateId.ok, false);
		if (!duplicateId.ok) { assert.equal(duplicateId.code, 'DUPLICATE_APPROVAL_ID'); }

		let generatedNonce = 0;
		const sameNonceSource: ControlledValidationAuthorizationIdSource = {
			...f.ids, approvalId: (() => { let id = 200; return () => `00000000-0000-4000-8000-${String(id++).padStart(12, '0')}`; })(),
			nonce: () => { generatedNonce++; return 'f'.repeat(64); },
		};
		const nonceService = new ControlledValidationAuthorizationService(f.dependencies, new TestApprovalHistory(), undefined, f.clock, sameNonceSource);
		assert.equal((await nonceService.approve(request('nonce-first'))).ok, true);
		const reusedNonce = await nonceService.approve(request('nonce-second'));
		assert.equal(reusedNonce.ok, false);
		if (!reusedNonce.ok) { assert.equal(reusedNonce.code, 'NONCE_REUSE'); }
		assert.equal(generatedNonce, 2);
	});

	test('fails closed when the verified procedure catalog is unavailable', async () => {
		const f = fixture(); f.setProcedure(undefined);
		const result = await f.service.approve(request());
		assert.equal(result.ok, false);
		if (!result.ok) { assert.equal(result.code, 'PROCEDURE_VERIFICATION_UNAVAILABLE'); }
	});

	test('rejects unsupported capabilities and limits above the catalog ceiling', async () => {
		const f = fixture();
		const network = { ...request(), capabilities: { ...request().capabilities, network: 'unrestricted' } };
		const networkResult = await f.service.approve(network);
		assert.equal(networkResult.ok, false);
		if (!networkResult.ok) { assert.equal(networkResult.code, 'CAPABILITY_UNSUPPORTED'); }
		const overLimit = { ...request(), resourceLimits: { ...request().resourceLimits, timeoutMs: 9_000 } };
		const limitResult = await f.service.approve(overLimit);
		assert.equal(limitResult.ok, false);
		if (!limitResult.ok) { assert.equal(limitResult.code, 'RESOURCE_LIMIT_EXCEEDED'); }
	});

	test('rejects oversized and deeply nested canonical inputs', async () => {
		const f = fixture();
		const oversized = { ...request(), arguments: { blob: 'x'.repeat(1_100_000) } };
		const oversizedResult = await f.service.approve(oversized);
		assert.equal(oversizedResult.ok, false);
		if (!oversizedResult.ok) { assert.equal(oversizedResult.code, 'INVALID_REQUEST'); }
		let nested: unknown = 'leaf';
		for (let i = 0; i < 70; i++) { nested = [nested]; }
		const nestedResult = await f.service.approve({ ...request(), arguments: nested });
		assert.equal(nestedResult.ok, false);
		if (!nestedResult.ok) { assert.equal(nestedResult.code, 'INVALID_REQUEST'); }
	});

	test('requires explicit consent acknowledgement and rejects altered approval bindings', async () => {
		const f = fixture();
		const missingConsent = { ...request(), consent: { disclosureVersion: 'old', confirmed: false } };
		const consentResult = await f.service.approve(missingConsent);
		assert.equal(consentResult.ok, false);
		if (!consentResult.ok) { assert.equal(consentResult.code, 'INVALID_REQUEST'); }
		const approved = await f.service.approve(request());
		assert.equal(approved.ok, true);
		if (!approved.ok) { return; }
		const altered = { ...request(), project: { ...request().project, permittedTargets: ['src/b.ts'] } };
		const changed = await f.service.validate(approved.approval.approvalId, altered);
		assert.equal(changed.ok, false);
		if (!changed.ok) { assert.equal(changed.code, 'APPROVAL_BINDING_MISMATCH'); }
		const changedArguments = { ...request(), arguments: { path: 'src/b.ts', expectedDigest: digest }, argumentDigest: `sha256:${digestCanonical({ path: 'src/b.ts', expectedDigest: digest })}` };
		const changedArgsResult = await f.service.validate(approved.approval.approvalId, changedArguments);
		assert.equal(changedArgsResult.ok, false);
		if (!changedArgsResult.ok) { assert.equal(changedArgsResult.code, 'APPROVAL_BINDING_MISMATCH'); }
	});

	test('a new Core authorization service cannot restore an approval after restart', async () => {
		const first = fixture();
		const approved = await first.service.approve(request());
		assert.equal(approved.ok, true);
		if (!approved.ok) { return; }
		const restarted = fixture();
		const result = await restarted.service.validate(approved.approval.approvalId, request());
		assert.equal(result.ok, false);
		if (!result.ok) { assert.equal(result.code, 'APPROVAL_NOT_FOUND'); }
	});

	test('the production Core runtime has no verified catalog providers and therefore fails closed', async () => {
		const core = new CoreRuntime({ coreVersion: 'authorization-foundation-test' });
		const result = await core.authorizeControlledValidation(request());
		assert.equal(result.ok, false);
		if (!result.ok) { assert.ok(['DEPENDENCY_UNAVAILABLE','HISTORY_STORAGE_UNAVAILABLE'].includes(result.code)); }
	});
});

suite('Controlled Validation durable approval history', function () {
	this.timeout(15_000);
	test('Core restart preserves audit inspection but leaves active authorization empty', async () => {
		const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-approval-history-'));
		const projectDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-selected-project-'));
		const filesystem = reliableHistoryFileSystem();
		try {
			const firstHistory = new ApprovalHistoryStore(filesystem, dataDirectory);
			const f = fixture(firstHistory);
			const firstCore = new CoreRuntime({ coreVersion: 'approval-history-first', controlledValidationAuthorizationDependencies: f.dependencies, controlledValidationHistory: firstHistory });
			const issued = await firstCore.authorizeControlledValidation(request());
			assert.equal(issued.ok, true, issued.ok ? undefined : issued.message);
			if (!issued.ok) { return; }
			const logPath = path.join(dataDirectory, '.aqiron-security', 'controlled-validation-approvals.log');
			const persisted = await fs.readFile(logPath, 'utf8');
			assert.ok(!persisted.includes(issued.approval.nonce));
			assert.ok(!persisted.includes('monotonicDeadline'));
			assert.ok(!persisted.includes('"arguments"'));
			assert.equal(path.resolve(logPath).startsWith(path.resolve(projectDirectory)), false);
			await firstCore.handle({ id: 'shutdown-first', type: 'request', method: 'core.shutdown', params: undefined }, () => undefined);

			const secondHistory = new ApprovalHistoryStore(filesystem, dataDirectory);
			const secondCore = new CoreRuntime({ coreVersion: 'approval-history-restarted', controlledValidationAuthorizationDependencies: f.dependencies, controlledValidationHistory: secondHistory });
			const inspected = await secondHistory.query();
			assert.equal(inspected.length, 1);
			assert.equal(inspected[0]?.approvalId, issued.approval.approvalId);
			assert.equal(inspected[0]?.status, 'invalidated');
			assert.equal(inspected[0]?.historicalOnly, true);
			assert.equal(inspected[0]?.canAuthorizeExecution, false);
			assert.ok(!Object.hasOwn(inspected[0]!, 'nonce'));
			assert.ok(!Object.hasOwn(inspected[0]!, 'monotonicDeadline'));
			const oldGrant = await secondCore.validateControlledValidationAuthorization(issued.approval.approvalId, request());
			assert.deepEqual(oldGrant.ok ? { ok: true } : { ok: false, code: oldGrant.code }, { ok: false, code: 'APPROVAL_NOT_FOUND' });
			const replay = await secondCore.authorizeControlledValidation(request());
			assert.equal(replay.ok, false);
			if (!replay.ok) { assert.equal(replay.code, 'APPROVAL_REPLAY'); }
			await secondCore.handle({ id: 'shutdown-second', type: 'request', method: 'core.shutdown', params: undefined }, () => undefined);
		} finally {
			await fs.rm(dataDirectory, { recursive: true, force: true });
			await fs.rm(projectDirectory, { recursive: true, force: true });
		}
	});

	test('approval creation fails closed if its issued event cannot be durably recorded', async () => {
		const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-approval-write-fail-'));
		try {
			const history = new ApprovalHistoryStore(reliableHistoryFileSystem({ failAppend: true }), dataDirectory);
			const f = fixture(history);
			const result = await f.service.approve(request());
			assert.equal(result.ok, false);
			if (!result.ok) { assert.equal(result.code, 'HISTORY_STORAGE_UNAVAILABLE'); }
			const active = await f.service.validate('00000000-0000-4000-8000-000000000001', request());
			assert.equal(active.ok, false);
			if (!active.ok) { assert.equal(active.code, 'APPROVAL_NOT_FOUND'); }
		} finally { await fs.rm(dataDirectory, { recursive: true, force: true }); }
	});

	test('crash recovery exposes an issued event as historical-only without reconstructing a grant', async () => {
		const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-approval-crash-'));
		try {
			const filesystem = reliableHistoryFileSystem();
			const firstHistory = new ApprovalHistoryStore(filesystem, dataDirectory);
			const f = fixture(firstHistory);
			let original: CoreRuntime | undefined = new CoreRuntime({ coreVersion: 'approval-history-crash-before', controlledValidationAuthorizationDependencies: f.dependencies, controlledValidationHistory: firstHistory });
			const oldRequest = request('crash-request');
			const issued = await original.authorizeControlledValidation(oldRequest);
			assert.equal(issued.ok, true);
			if (!issued.ok) { return; }
			original = undefined; // Simulate process loss: no shutdown invalidation event runs.
			const restartedHistory = new ApprovalHistoryStore(filesystem, dataDirectory);
			const restarted = new CoreRuntime({ coreVersion: 'approval-history-crash-after', controlledValidationAuthorizationDependencies: f.dependencies, controlledValidationHistory: restartedHistory });
			const [record] = await restartedHistory.query();
			assert.equal(record?.status, 'historical-only');
			assert.equal(record?.canAuthorizeExecution, false);
			const result = await restarted.validateControlledValidationAuthorization(issued.approval.approvalId, oldRequest);
			assert.equal(result.ok, false);
			if (!result.ok) { assert.equal(result.code, 'APPROVAL_NOT_FOUND'); }
			await restarted.handle({ id: 'shutdown-crash-recovery', type: 'request', method: 'core.shutdown', params: undefined }, () => undefined);
		} finally { await fs.rm(dataDirectory, { recursive: true, force: true }); }
	});

	test('expiry is durably recorded after the monotonic lifetime ends', async () => {
		const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-approval-expiry-'));
		try {
			const history = new ApprovalHistoryStore(reliableHistoryFileSystem(), dataDirectory);
			const f = fixture(history);
			const issued = await f.service.approve(request());
			assert.equal(issued.ok, true);
			if (!issued.ok) { return; }
			f.setMono(10_000 + CONTROLLED_VALIDATION_APPROVAL_TTL_MS);
			const expired = await f.service.validate(issued.approval.approvalId, request());
			assert.equal(expired.ok, false);
			if (!expired.ok) { assert.equal(expired.code, 'APPROVAL_EXPIRED'); }
			assert.equal((await history.query())[0]?.status, 'expired');
		} finally { await fs.rm(dataDirectory, { recursive: true, force: true }); }
	});

	test('revocation invalidates memory before a failed history append', async () => {
		const history = new TestApprovalHistory();
		const f = fixture(history);
		const issued = await f.service.approve(request());
		assert.equal(issued.ok, true);
		if (!issued.ok) { return; }
		history.failStatus = true;
		const revoked = await f.service.revoke(issued.approval.approvalId);
		assert.equal(revoked.ok, false);
		if (!revoked.ok) { assert.equal(revoked.code, 'HISTORY_STORAGE_UNAVAILABLE'); }
		const checked = await f.service.validate(issued.approval.approvalId, request());
		assert.equal(checked.ok, false);
		if (!checked.ok) { assert.equal(checked.code, 'APPROVAL_REVOKED'); }
	});

	test('corrupt, malformed and truncated history is rejected without repair', async () => {
		for (const content of ['{invalid}\n', '{"schemaVersion":1', `${' '.repeat(50)}\n`]) {
			const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-approval-corrupt-'));
			try {
				const history = new ApprovalHistoryStore(reliableHistoryFileSystem(), dataDirectory);
				await history.recordIssued(issuedAuditInput());
				const logPath = path.join(dataDirectory, '.aqiron-security', 'controlled-validation-approvals.log');
				await fs.writeFile(logPath, content, 'utf8');
				await assert.rejects(() => history.query(), /Approval history/);
				assert.equal(await fs.readFile(logPath, 'utf8'), content);
			} finally { await fs.rm(dataDirectory, { recursive: true, force: true }); }
		}
	});

	test('rejects duplicate event IDs and enforces hard event capacity without deleting history', async () => {
		const duplicateRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-approval-duplicate-event-'));
		const limitedRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-approval-capacity-'));
		const byteLimitedRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-approval-byte-capacity-'));
		try {
			const duplicate = new ApprovalHistoryStore(reliableHistoryFileSystem(), duplicateRoot, { eventId: () => '00000000-0000-4000-8000-000000000099' });
			await duplicate.recordIssued(issuedAuditInput('00000000-0000-4000-8000-000000000091'));
			await assert.rejects(() => duplicate.recordIssued(issuedAuditInput('00000000-0000-4000-8000-000000000092')), /event ID was reused/);
			const bounded = new ApprovalHistoryStore(reliableHistoryFileSystem(), limitedRoot, { maxEvents: 1 });
			await bounded.recordIssued(issuedAuditInput('00000000-0000-4000-8000-000000000093'));
			const logPath = path.join(limitedRoot, '.aqiron-security', 'controlled-validation-approvals.log');
			const prior = await fs.readFile(logPath);
			await assert.rejects(() => bounded.recordIssued(issuedAuditInput('00000000-0000-4000-8000-000000000094')), /event limit reached/);
			assert.deepEqual(await fs.readFile(logPath), prior);
			const byteBounded = new ApprovalHistoryStore(reliableHistoryFileSystem(), byteLimitedRoot, { maxBytes: 2048 });
			await byteBounded.recordIssued(issuedAuditInput('00000000-0000-4000-8000-000000000095'));
			const bytePath = path.join(byteLimitedRoot, '.aqiron-security', 'controlled-validation-approvals.log');
			const bytePrior = await fs.readFile(bytePath);
			await assert.rejects(() => byteBounded.recordIssued(issuedAuditInput('00000000-0000-4000-8000-000000000096')), /byte limit reached/);
			assert.deepEqual(await fs.readFile(bytePath), bytePrior);
		} finally {
			await fs.rm(duplicateRoot, { recursive: true, force: true });
			await fs.rm(limitedRoot, { recursive: true, force: true });
			await fs.rm(byteLimitedRoot, { recursive: true, force: true });
		}
	});
});

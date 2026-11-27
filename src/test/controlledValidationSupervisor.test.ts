import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { IsolationCapabilityReport, IsolationQualification } from '../../packages/core/src/validation/isolation/contracts';
import { validateIsolationProfile } from '../../packages/core/src/validation/isolation/profile';
import { acceptCommittedStartReceipt } from '../../packages/core/src/validation/isolation/receipt';
import { IsolationProvider, IsolatedWorkerRequest, IsolatedWorkerResult, ValidatedTargetProjectScope, VerifiedProcedureDescriptor } from '../../packages/core/src/validation/isolation/providers';
import { CONTROLLED_VALIDATION_PRODUCTION_EXECUTION_ENABLED, createContractTestSupervisor, createExecutionSupervisor } from '../../packages/core/src/validation/executionSupervisor';
import { CancellationClock } from '../../packages/core/src/validation/cancellation';

const caps = Object.fromEntries(['filesystemAllowlist','readOnlyInputs','projectRootContainment','symlinkRaceResistance','networkDeniedByOs','descendantContainment','cpuCeiling','memoryCeiling','executionDeadline','outputBound','processCountCeiling','forcedTermination','cleanup'].map(k => [k, true])) as unknown as IsolationCapabilityReport;
const qualification: IsolationQualification = { platform: 'linux', state: 'qualified', evidenceId: 'fake-only', capabilities: caps, reason: 'contract fake; not production evidence' };
const root = path.join(tmpdir(), 'controlled-validation-project');
const profile = validateIsolationProfile({ projectRoot: root, inputPaths: [path.join(root, 'input.json')], network: 'denied', projectWrites: false, inheritedCredentials: false, timeoutMs: 1000, memoryBytes: 1024 * 1024, cpuMillis: 1000, outputBytes: 1024, processCount: 1 });
const descriptor: VerifiedProcedureDescriptor = { id: 'aqiron:test', version: '1.0.0', artifactDigest: `sha256:${'a'.repeat(64)}`, workerPayload: new Uint8Array([1]), verified: true };
const scope: ValidatedTargetProjectScope = { projectRoot: root, projectIdentityDigest: `sha256:${'b'.repeat(64)}`, targetIds: ['target-1'], inputPaths: profile.inputPaths };
const receipt = () => acceptCommittedStartReceipt({ schemaVersion: 1, executionId: '00000000-0000-4000-8000-000000000001', approvalId: '00000000-0000-4000-8000-000000000002', commitmentEventId: '00000000-0000-4000-8000-000000000003', authorizationBindingDigest: `sha256:${'c'.repeat(64)}`, consumedAt: '2026-11-27T00:00:00.000Z', status: 'consumed', nonExecutable: true });

function providerFor(launch: (request: IsolatedWorkerRequest) => Promise<IsolatedWorkerResult>, qualificationOverride = qualification): IsolationProvider {
	return {
		platform: 'linux',
		getQualification: () => qualificationOverride,
		async launch(request) {
			return {
				wait: () => launch(request),
				async terminate() { return { confirmed: true }; },
				async cleanup() {},
			};
		},
	};
}

function deferred<T>() { let resolve!: (value: T) => void; let reject!: (reason?: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
class ManualClock implements CancellationClock {
	private time = 0; private nextId = 0; private readonly timers = new Map<number, { at: number; callback: () => void }>();
	now(): number { return this.time; }
	setTimeout(callback: () => void, ms: number): unknown { const id = ++this.nextId; this.timers.set(id, { at: this.time + ms, callback }); return id; }
	clearTimeout(handle: unknown): void { this.timers.delete(handle as number); }
	advance(ms: number): void { this.time += ms; for (const [id, timer] of [...this.timers]) { if (timer.at <= this.time) { this.timers.delete(id); timer.callback(); } } }
}
const executionId = '00000000-0000-4000-8000-000000000001';
const terminatedResult: IsolatedWorkerResult = { exitCategory: 'terminated', output: new Uint8Array(), truncated: false };
async function flushMicrotasks(): Promise<void> { for (let i = 0; i < 8; i++) { await Promise.resolve(); } }

suite('controlled validation supervisor contract', () => {
	test('production supervisor rejects and default remains disabled', async () => {
		assert.equal(CONTROLLED_VALIDATION_PRODUCTION_EXECUTION_ENABLED, false);
		const result = await createExecutionSupervisor().launch({ receipt: receipt(), descriptor, scope, profile, input: new Uint8Array() });
		assert.equal(result.status, 'blocked');
	});
	test('no public Core or client route references the supervisor', () => {
		for (const file of ['packages/core/src/runtime/coreRuntime.ts', 'packages/core/src/runtime/protocol.ts', 'packages/desktop/src/main.ts', 'packages/cli/src/cli.ts']) {
			const source = readFileSync(path.join(process.cwd(), file), 'utf8');
			assert.equal(source.includes('executionSupervisor'), false, `${file} must not route to the supervisor`);
		}
	});
	test('missing and invalid receipt or descriptor are rejected before provider launch', async () => {
		let launches = 0; const provider = providerFor(async () => { launches++; return { exitCategory: 'success', output: new Uint8Array(), truncated: false }; });
		const supervisor = createContractTestSupervisor({ providers: [provider], qualification });
		const validReceipt = receipt();
		assert.equal((await supervisor.launch({ receipt: {} as never, descriptor, scope, profile, input: new Uint8Array() })).status, 'blocked');
		const malformedDescriptor = { ...descriptor, verified: false } as unknown as VerifiedProcedureDescriptor;
		assert.equal((await supervisor.launch({ receipt: validReceipt, descriptor: malformedDescriptor, scope, profile, input: new Uint8Array() })).status, 'blocked');
		assert.equal(launches, 0);
	});
	test('unqualified provider, oversized input, and malformed scope are rejected', async () => {
		let launches = 0; const provider = providerFor(async () => { launches++; return { exitCategory: 'success', output: new Uint8Array(), truncated: false }; }, { ...qualification, state: 'qualification-pending' });
		const supervisor = createContractTestSupervisor({ providers: [provider], qualification: { ...qualification, state: 'qualification-pending' } });
		assert.equal((await supervisor.launch({ receipt: receipt(), descriptor, scope, profile, input: new Uint8Array() })).status, 'blocked');
		const accepted = createContractTestSupervisor({ providers: [providerFor(async () => { launches++; return { exitCategory: 'success', output: new Uint8Array(), truncated: false }; })], qualification });
		assert.equal((await accepted.launch({ receipt: receipt(), descriptor, scope: { ...scope, projectRoot: '/elsewhere' }, profile, input: new Uint8Array() })).status, 'blocked');
		assert.equal(launches, 0);
	});
	test('provider receives fixed worker entry and allowlisted environment only', async () => {
		let seen: IsolatedWorkerRequest | undefined;
		const supervisor = createContractTestSupervisor({ providers: [providerFor(async request => { seen = request; return { exitCategory: 'success', output: new Uint8Array([7]), truncated: false }; })], qualification });
		const result = await supervisor.launch({ receipt: receipt(), descriptor, scope, profile, input: new Uint8Array([1]) });
		assert.equal(result.status, 'completed'); assert.equal(result.outputDigest?.length, 64);
		assert.equal(seen?.workerEntry, 'aqiron-controlled-validation-worker-v1');
		assert.deepEqual(Object.keys(seen!.environment).sort(), ['LANG', 'LC_ALL', 'TZ']);
		assert.equal('command' in (seen as object), false);
	});
	test('successful natural completion is owned and cleaned exactly once', async () => {
		let waits = 0; let terminated = 0; let cleaned = 0;
		const provider: IsolationProvider = { platform: 'linux', getQualification: () => qualification, async launch() { return { async wait() { waits++; return { exitCategory: 'success', output: new Uint8Array([9]), truncated: false }; }, async terminate() { terminated++; return { confirmed: true }; }, async cleanup() { cleaned++; } }; } };
		const result = await createContractTestSupervisor({ providers: [provider], qualification }).launch({ receipt: receipt(), descriptor, scope, profile, input: new Uint8Array() });
		assert.equal(result.status, 'completed'); assert.equal(result.cleanupOutcome, 'completed'); assert.deepEqual({ waits, terminated, cleaned }, { waits: 1, terminated: 0, cleaned: 1 });
	});
	test('explicit cancellation and supervisor timeout converge on one operation', async () => {
		const wait = deferred<IsolatedWorkerResult>(); const clock = new ManualClock(); let terminated = 0; let cleaned = 0; let reason = '';
		const provider: IsolationProvider = { platform: 'linux', getQualification: () => qualification, async launch() { return { wait: () => wait.promise, async terminate(value) { terminated++; reason = value; wait.resolve(terminatedResult); return { confirmed: true }; }, async cleanup() { cleaned++; } }; } };
		const short = validateIsolationProfile({ projectRoot: root, inputPaths: [path.join(root, 'input.json')], network: 'denied', projectWrites: false, inheritedCredentials: false, timeoutMs: 100, memoryBytes: 1024 * 1024, cpuMillis: 1000, outputBytes: 1024, processCount: 1 });
		const supervisor = createContractTestSupervisor({ providers: [provider], qualification, cancellationClock: clock });
		const launch = supervisor.launch({ receipt: receipt(), descriptor, scope, profile: short, input: new Uint8Array() }); await flushMicrotasks();
		const explicit = supervisor.cancel(executionId); const repeated = supervisor.cancel(executionId); clock.advance(100); const [cancelResult, repeatedResult, result] = await Promise.all([explicit, repeated, launch]);
		assert.equal(cancelResult, repeatedResult); assert.equal(cancelResult?.outcome, 'cancelled'); assert.equal(result.status, 'cancelled'); assert.equal(result.cancellationRequested, true); assert.equal(reason, 'cancel'); assert.deepEqual({ terminated, cleaned }, { terminated: 1, cleaned: 1 });
		assert.equal(await supervisor.cancel(executionId), undefined);
	});
	test('timeout with confirmed termination is timed-out and cleans exactly once', async () => {
		const wait = deferred<IsolatedWorkerResult>(); const clock = new ManualClock(); let terminated = 0; let cleaned = 0;
		const provider: IsolationProvider = { platform: 'linux', getQualification: () => qualification, async launch() { return { wait: () => wait.promise, async terminate() { terminated++; wait.resolve(terminatedResult); return { confirmed: true }; }, async cleanup() { cleaned++; } }; } };
		const short = validateIsolationProfile({ projectRoot: root, inputPaths: [path.join(root, 'input.json')], network: 'denied', projectWrites: false, inheritedCredentials: false, timeoutMs: 100, memoryBytes: 1024 * 1024, cpuMillis: 1000, outputBytes: 1024, processCount: 1 });
		const supervisor = createContractTestSupervisor({ providers: [provider], qualification, cancellationClock: clock }); const launch = supervisor.launch({ receipt: receipt(), descriptor, scope, profile: short, input: new Uint8Array() }); await flushMicrotasks(); clock.advance(100); const result = await launch;
		assert.equal(result.status, 'timed-out'); assert.equal(result.teardownConfirmed, true); assert.equal(result.cleanupOutcome, 'completed'); assert.deepEqual({ terminated, cleaned }, { terminated: 1, cleaned: 1 });
	});
	test('supervisor timeout alone uses coordinator termination and reports uncertainty honestly', async () => {
		const wait = deferred<IsolatedWorkerResult>(); const clock = new ManualClock(); let terminated = 0; let cleaned = 0;
		const provider: IsolationProvider = { platform: 'linux', getQualification: () => qualification, async launch() { return { wait: () => wait.promise, async terminate() { terminated++; return { confirmed: false }; }, async cleanup() { cleaned++; } }; } };
		const short = validateIsolationProfile({ projectRoot: root, inputPaths: [path.join(root, 'input.json')], network: 'denied', projectWrites: false, inheritedCredentials: false, timeoutMs: 100, memoryBytes: 1024 * 1024, cpuMillis: 1000, outputBytes: 1024, processCount: 1 });
		const supervisor = createContractTestSupervisor({ providers: [provider], qualification, cancellationClock: clock }); const launch = supervisor.launch({ receipt: receipt(), descriptor, scope, profile: short, input: new Uint8Array() }); await flushMicrotasks(); clock.advance(100); await flushMicrotasks();
		const result = await launch; assert.equal(result.status, 'interrupted'); assert.equal(result.teardownConfirmed, false); assert.equal(result.executionUncertain, true); assert.equal(result.cleanupOutcome, 'skipped-termination-unconfirmed'); assert.deepEqual({ terminated, cleaned }, { terminated: 1, cleaned: 0 });
	});
	test('provider launch failure has no worker lifecycle to terminate or clean', async () => {
		let terminated = 0; let cleaned = 0;
		const provider: IsolationProvider = { platform: 'linux', getQualification: () => qualification, async launch() { throw new Error('provider launch failed'); } };
		const result = await createContractTestSupervisor({ providers: [provider], qualification }).launch({ receipt: receipt(), descriptor, scope, profile, input: new Uint8Array() });
		assert.equal(result.status, 'failed'); assert.equal(result.teardownConfirmed, undefined); assert.deepEqual({ terminated, cleaned }, { terminated: 0, cleaned: 0 });
	});
	test('failed launch is contained as failure and cleanup is attempted', async () => {
		let cleaned = 0;
		const broken: IsolationProvider = { platform: 'linux', getQualification: () => qualification, async launch() { return { wait: async () => { throw new Error('worker failure'); }, async terminate() { return { confirmed: true }; }, async cleanup() { cleaned++; } }; } };
		const result = await createContractTestSupervisor({ providers: [broken], qualification }).launch({ receipt: receipt(), descriptor, scope, profile, input: new Uint8Array() });
		assert.equal(result.status, 'failed'); assert.equal(result.teardownConfirmed, true); assert.equal(result.cleanupOutcome, 'completed'); assert.equal(cleaned, 1);
	});
});

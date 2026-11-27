import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { IsolationCapabilityReport, IsolationQualification } from '../../packages/core/src/validation/isolation/contracts';
import { validateIsolationProfile } from '../../packages/core/src/validation/isolation/profile';
import { acceptCommittedStartReceipt } from '../../packages/core/src/validation/isolation/receipt';
import { IsolationProvider, IsolatedWorkerRequest, IsolatedWorkerResult, ValidatedTargetProjectScope, VerifiedProcedureDescriptor } from '../../packages/core/src/validation/isolation/providers';
import { CONTROLLED_VALIDATION_PRODUCTION_EXECUTION_ENABLED, createContractTestSupervisor, createExecutionSupervisor } from '../../packages/core/src/validation/executionSupervisor';

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
	test('timeout requests termination, reports confirmation, and cleans resources', async () => {
		let terminated = 0; let cleaned = 0;
		const provider: IsolationProvider = { platform: 'linux', getQualification: () => qualification, async launch() { return { wait: () => new Promise<never>(() => {}), async terminate() { terminated++; return { confirmed: true }; }, async cleanup() { cleaned++; } }; } };
		const short = validateIsolationProfile({ projectRoot: root, inputPaths: [path.join(root, 'input.json')], network: 'denied', projectWrites: false, inheritedCredentials: false, timeoutMs: 5, memoryBytes: 1024 * 1024, cpuMillis: 1000, outputBytes: 1024, processCount: 1 });
		const result = await createContractTestSupervisor({ providers: [provider], qualification }).launch({ receipt: receipt(), descriptor, scope, profile: short, input: new Uint8Array() });
		assert.equal(result.status, 'timed-out'); assert.equal(result.teardownConfirmed, true); assert.equal(terminated, 1); assert.equal(cleaned, 1);
	});
	test('failed launch is contained as failure and cleanup is attempted', async () => {
		let cleaned = 0;
		const broken: IsolationProvider = { platform: 'linux', getQualification: () => qualification, async launch() { return { wait: async () => { throw new Error('worker failure'); }, async terminate() { return { confirmed: true }; }, async cleanup() { cleaned++; } }; } };
		const result = await createContractTestSupervisor({ providers: [broken], qualification }).launch({ receipt: receipt(), descriptor, scope, profile, input: new Uint8Array() });
		assert.equal(result.status, 'failed'); assert.equal(result.teardownConfirmed, true); assert.equal(cleaned, 1);
	});
});

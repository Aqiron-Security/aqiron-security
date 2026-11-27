import { strict as assert } from 'node:assert';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { IsolationCapabilityReport, IsolationQualification, qualificationAllowsExecution } from '../../packages/core/src/validation/isolation/contracts';
import { DEFAULT_ISOLATION_QUALIFICATIONS } from '../../packages/core/src/validation/isolation/providers';
import { validateIsolationProfile } from '../../packages/core/src/validation/isolation/profile';

suite('controlled validation isolation contracts', () => {
	test('no platform is enabled by default', () => {
		for (const platform of ['windows', 'linux', 'macos'] as const) {
			const item = DEFAULT_ISOLATION_QUALIFICATIONS[platform];
			assert.equal(item.platform, platform);
			assert.notEqual(item.state, 'qualified');
			assert.equal(qualificationAllowsExecution(item), false);
		}
	});
	test('unsupported, unqualified, and incomplete capability reports fail closed', () => {
		const all = Object.fromEntries(['filesystemAllowlist','readOnlyInputs','projectRootContainment','symlinkRaceResistance','networkDeniedByOs','descendantContainment','cpuCeiling','memoryCeiling','executionDeadline','outputBound','processCountCeiling','forcedTermination','cleanup'].map(k => [k, true])) as unknown as IsolationCapabilityReport;
		const base: IsolationQualification = { platform: 'linux', state: 'qualified', evidenceId: 'acceptance-1', capabilities: all, reason: 'test fake only' };
		assert.equal(qualificationAllowsExecution({ ...base, state: 'unsupported' }), false);
		assert.equal(qualificationAllowsExecution({ ...base, state: 'qualification-pending' }), false);
		assert.equal(qualificationAllowsExecution({ ...base, capabilities: { ...all, networkDeniedByOs: false } }), false);
		assert.equal(qualificationAllowsExecution({ ...base, capabilities: { ...all, symlinkRaceResistance: false } }), false);
		assert.equal(qualificationAllowsExecution({ ...base, capabilities: { ...all, descendantContainment: false } }), false);
		assert.equal(qualificationAllowsExecution({ ...base, evidenceId: undefined }), false);
	});
	test('read-only input paths must be contained under project root', () => {
		const root = path.join(tmpdir(), 'cv-project');
		const valid = validateIsolationProfile({ projectRoot: root, inputPaths: [path.join(root, 'snapshot.json')], network: 'denied', projectWrites: false, inheritedCredentials: false, timeoutMs: 1000, memoryBytes: 1024 * 1024, cpuMillis: 1000, outputBytes: 1024, processCount: 1 });
		assert.equal(valid.network, 'denied'); assert.equal(valid.projectWrites, false);
		assert.throws(() => validateIsolationProfile({ projectRoot: root, inputPaths: [path.join(root, '..', 'outside.json')], network: 'denied', projectWrites: false, inheritedCredentials: false, timeoutMs: 1000, memoryBytes: 1024 * 1024, cpuMillis: 1000, outputBytes: 1024, processCount: 1 }));
	});
	test('network, writable project, credentials, and invalid resource limits are rejected', () => {
		const root = path.join(tmpdir(), 'cv-project'); const base = { projectRoot: root, inputPaths: [path.join(root, 'input')], network: 'denied', projectWrites: false, inheritedCredentials: false, timeoutMs: 1000, memoryBytes: 1024 * 1024, cpuMillis: 1000, outputBytes: 1024, processCount: 1 };
		assert.throws(() => validateIsolationProfile({ ...base, network: 'allowed' }));
		assert.throws(() => validateIsolationProfile({ ...base, projectWrites: true }));
		assert.throws(() => validateIsolationProfile({ ...base, inheritedCredentials: true }));
		assert.throws(() => validateIsolationProfile({ ...base, processCount: 0 }));
		assert.throws(() => validateIsolationProfile({ ...base, memoryBytes: Number.MAX_SAFE_INTEGER }));
	});
});

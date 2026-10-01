import { strict as assert } from 'assert';
import { CoreMethodParams, CoreRequestMessage, CoreResultFor } from '../../packages/core/src/runtime/protocol';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';

suite('Core protocol contracts', () => {
	test('maps current methods to their params and result types', () => {
		const request: CoreRequestMessage = {
			id: 'health-1',
			type: 'request',
			method: 'core.health',
			params: undefined,
		};
		const params: CoreMethodParams['credentials.set'] = { key: 'token', value: 'secret' };
		const result: CoreResultFor<'core.health'> = { ok: true, ready: true, uptimeMs: 1 };
		assert.equal(request.method, 'core.health');
		assert.equal(params.key, 'token');
		assert.equal(result.ready, true);
		// @ts-expect-error Method and params must stay paired.
		const invalid: CoreRequestMessage = { id: 'bad', type: 'request', method: 'credentials.set', params: { key: 'token' } };
		void invalid;
	});

	test('keeps the existing JSON-line request envelope serialization', () => {
		const request: CoreRequestMessage = {
			id: 'scan-42',
			type: 'request',
			method: 'scan.start',
			params: { workspaceRoot: '/repo', trusted: true, mode: 'deep' },
		};
		assert.equal(JSON.stringify(request), '{"id":"scan-42","type":"request","method":"scan.start","params":{"workspaceRoot":"/repo","trusted":true,"mode":"deep"}}');
	});

	test('rejects malformed method params before dispatch', async () => {
		const runtime = new CoreRuntime({ coreVersion: 'test' });
		const response = await runtime.handle({ id: 'bad-params', type: 'request', method: 'credentials.set', params: { key: 'missing-value' } }, () => undefined);
		assert.equal(response.success, false);
		assert.equal(response.error?.code, 'CORE_INVALID_REQUEST');
	});

	test('rejects unknown methods with the existing invalid-request response', async () => {
		const runtime = new CoreRuntime({ coreVersion: 'test' });
		const response = await runtime.handle({ id: 'unknown-method', type: 'request', method: 'test.unknown', params: {} }, () => undefined);
		assert.equal(response.success, false);
		assert.equal(response.error?.code, 'CORE_INVALID_REQUEST');
	});
});

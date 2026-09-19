import * as path from 'path';
import * as childProcess from 'child_process';
import { strict as assert } from 'assert';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';
import { CredentialStore } from '../../packages/core/src/shared/platform';

interface CoreResponse {
	id: string;
	type: 'response';
	success: boolean;
	result?: unknown;
	error?: { code: string; message: string };
}

suite('Core runtime process', () => {
	test('handshakes, reports health, and exposes credential metadata without requiring a keychain session', async () => {
		const runtime = path.resolve(__dirname, '../../../dist/core-runtime.js');
		const child = childProcess.spawn(process.execPath, [runtime], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
		const responses = new Map<string, (response: CoreResponse) => void>();
		let buffer = '';
		child.stdout.setEncoding('utf8');
		child.stdout.on('data', (chunk: string) => {
			buffer += chunk;
			const lines = buffer.split(/\r?\n/);
			buffer = lines.pop() ?? '';
			for (const line of lines) {
				if (!line.trim()) {
					continue;
				}
				const parsed = JSON.parse(line) as CoreResponse;
				responses.get(parsed.id)?.(parsed);
			}
		});

		const request = async <T>(method: string, params?: unknown): Promise<T> => {
			const id = `${Date.now()}-${Math.random()}`;
			const response = await new Promise<CoreResponse>((resolve, reject) => {
				responses.set(id, resolve);
				child.once('exit', (code) => reject(new Error(`runtime exited early: ${code ?? 'unknown'}`)));
				child.stdin.write(`${JSON.stringify({ id, type: 'request', method, params })}\n`);
			});
			assert.equal(response.type, 'response');
			assert.equal(response.success, true, response.error?.message ?? 'request failed');
			return response.result as T;
		};

		try {
			const handshake = await request<{ protocolVersion: number; coreVersion: string; status: string }>('core.handshake', {
				extensionVersion: '0.0.1',
				protocolVersion: 1,
				platform: process.platform,
				architecture: process.arch,
			});
			assert.equal(handshake.status, 'compatible');

			const health = await request<{ ok: true; ready: boolean; uptimeMs: number }>('core.health');
			assert.equal(health.ok, true);
			assert.equal(health.ready, true);

			const status = await request<{ hasValue: boolean }>('credentials.status', { key: `aqiron.missing.${Date.now()}` });
			assert.equal(status.hasValue, false);

			await request('core.shutdown');
		} finally {
			child.kill();
		}
	});

	test('round-trips credentials through an injected mock store without returning the secret', async () => {
		const values = new Map<string, string>();
		const store: CredentialStore = {
			get: async (key) => values.get(key),
			set: async (key, value) => { values.set(key, value); },
			delete: async (key) => { values.delete(key); },
		};
		const runtime = new CoreRuntime({ coreVersion: 'test', credentialStore: store });
		const emit = (): void => undefined;
		const set = await runtime.handle({ id: 'cred-set', type: 'request', method: 'credentials.set', params: { key: 'test-key', value: 'super-secret' } }, emit);
		assert.deepEqual(set.result, { hasValue: true, updatedAt: (set.result as { updatedAt: string }).updatedAt });
		assert.ok(!JSON.stringify(set).includes('super-secret'));
		const exists = await runtime.handle({ id: 'cred-exists', type: 'request', method: 'credentials.exists', params: { key: 'test-key' } }, emit);
		assert.deepEqual(exists.result, { exists: true });
		await runtime.handle({ id: 'cred-delete', type: 'request', method: 'credentials.delete', params: { key: 'test-key' } }, emit);
		const deleted = await runtime.handle({ id: 'cred-deleted', type: 'request', method: 'credentials.exists', params: { key: 'test-key' } }, emit);
		assert.deepEqual(deleted.result, { exists: false });
	});
});

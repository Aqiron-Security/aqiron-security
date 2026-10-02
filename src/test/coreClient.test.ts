import * as assert from 'assert';
import * as fsSync from 'node:fs';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { CoreClient } from '../../packages/core/src/client';
import { CoreClientTransport } from '../../packages/core/src/client/coreProcessManager';
import { CoreEventMessage, CoreMethod, CoreMethodParams, CoreResultFor } from '../../packages/core/src/runtime';

const runtimePath = path.resolve(__dirname, '../../../dist/core-runtime.js');

suite('Host-neutral Core client', () => {
	test('starts Core, completes handshake, makes typed requests and forwards protocol events with the supplied request ID', async function () {
		this.timeout(30_000);
		const workspaceRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-client-test-'));
		const client = new CoreClient({ clientVersion: 'test-client', runtimePath, restartOnCrash: false });
		const events: CoreEventMessage[] = [];
		const listener = (event: CoreEventMessage) => events.push(event);
		client.on('event', listener);
		try {
			const handshake = await client.start();
			assert.equal(handshake.status, 'compatible');
			assert.equal(handshake.protocolVersion, 1);
			assert.equal((await client.health()).ready, true);
			assert.equal((await client.info()).runtime, 'node');
			const requestId = 'host-neutral-client-scan-id';
			const result = await client.startScan({ requestId, workspaceRoot, trusted: true, mode: 'quick' });
			assert.equal(result.scanId, requestId);
			assert.ok(events.length > 0);
			assert.ok(events.every((event) => event.type === 'event' && event.requestId === requestId));
		} finally {
			client.removeListener('event', listener);
			await client.stop();
			await fs.rm(workspaceRoot, { recursive: true, force: true });
		}
	});

	test('maps request cancellation through the configured transport with the same request ID', async () => {
		const transport = new RecordingTransport();
		const client = new CoreClient({ clientVersion: 'test-client', runtimePath, restartOnCrash: false }, transport);
		const result = await client.cancelRequest('cancel-this-request');
		assert.deepEqual(result, { cancelled: true, requestId: 'cancel-this-request' });
		assert.deepEqual(transport.cancelledIds, ['cancel-this-request']);
	});

	test('the host-neutral client has no VS Code or scanner implementation dependencies', () => {
		const clientRoot = path.resolve(__dirname, '../../../packages/core/src/client');
		const sources = ['coreClient.ts', 'coreProcessManager.ts', 'index.ts'].map((file) => fsSyncRead(path.join(clientRoot, file))).join('\n');
		assert.doesNotMatch(sources, /from\s+['"]vscode['"]/i);
		assert.doesNotMatch(sources, /(?:scannerManager|NativeWorkspaceScanner|from\s+['"].*\/scanners)/i);
		const extensionSource = fsSyncRead(path.resolve(__dirname, '../../../src/extension.ts'));
		assert.match(extensionSource, /CoreClient.*from ['"]\.\.\/packages\/core\/src\/client['"]/);
	});
});

class RecordingTransport implements CoreClientTransport {
	readonly cancelledIds: string[] = [];
	async start() { return { protocolVersion: 1, coreVersion: 'test', status: 'compatible' as const }; }
	async stop(): Promise<void> {}
	async request<K extends CoreMethod>(_method: K, _params: CoreMethodParams[K], _timeoutMs?: number, _requestId?: string): Promise<CoreResultFor<K>> {
		return { cancelled: true } as CoreResultFor<K>;
	}
	async cancel(requestId: string) { this.cancelledIds.push(requestId); return { cancelled: true, requestId }; }
	onCoreEvent(_listener: (event: CoreEventMessage) => void): () => void { return () => undefined; }
	on(_event: 'log' | 'exit', _listener: ((message: string) => void) | ((event: { code: number | null; signal: NodeJS.Signals | null }) => void)): this { return this; }
}

function fsSyncRead(filePath: string): string {
	return fsSync.readFileSync(filePath, 'utf8');
}

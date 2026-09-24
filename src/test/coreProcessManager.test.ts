import * as assert from 'assert';
import * as childProcess from 'child_process';
import { EventEmitter } from 'events';
import { createRequire } from 'module';
import { CoreProcessManager } from '../core/coreProcessManager';

const loadModule = createRequire(__filename);

interface TestStream extends EventEmitter {
	setEncoding(encoding: string): void;
}

class FakeCoreChild extends EventEmitter {
	readonly stdout = createStream();
	readonly stderr = createStream();
	readonly stdin = { write: (payload: string): boolean => {
			const request = JSON.parse(payload) as { id: string; method: string };
			if (request.method === 'slow') {
				return true;
			}
			const result = request.method === 'core.handshake'
				? { protocolVersion: 1, coreVersion: 'test', status: 'compatible' }
				: request.method === 'core.health' ? { ok: true, ready: true } : { ok: true };
			const response = `${JSON.stringify({ id: request.id, type: 'response', success: true, result })}\n`;
			if (this.splitResponses) {
				const midpoint = Math.max(1, Math.floor(response.length / 2));
				this.stdout.emit('data', response.slice(0, midpoint));
				this.stdout.emit('data', response.slice(midpoint));
			} else {
				this.stdout.emit('data', response);
			}
			return true;
		}};
	private killed = false;

	constructor(private readonly splitResponses = false) {
		super();
	}

	kill(): boolean {
		if (!this.killed) {
			this.killed = true;
			this.emit('exit', null, 'SIGTERM');
		}
		return true;
	}

	crash(): void {
		this.emit('exit', 1, null);
	}
}

function createStream(): TestStream {
	const stream = new EventEmitter() as TestStream;
	stream.setEncoding = (): void => undefined;
	return stream;
}

function installSpawn(factory: () => FakeCoreChild): () => void {
	const module = loadModule('child_process') as typeof childProcess;
	const original = module.spawn;
	module.spawn = (() => factory()) as unknown as typeof childProcess.spawn;
	return () => { module.spawn = original; };
}

function handleStdout(manager: CoreProcessManager, chunk: string): void {
	(manager as unknown as { handleStdout(value: string): void }).handleStdout(chunk);
}

async function waitFor(condition: () => boolean, timeoutMs = 1_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!condition()) {
		if (Date.now() >= deadline) {
			throw new Error('Timed out waiting for test condition.');
		}
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

suite('Core process manager', () => {
	test('reconstructs a response split across stdout chunks in one process', async () => {
		const child = new FakeCoreChild(true);
		const restore = installSpawn(() => child);
		const manager = new CoreProcessManager({ extensionVersion: 'test', restartOnCrash: false });
		try {
			await manager.start();
			const result = await manager.request<{ ok: boolean }>('example');
			assert.deepStrictEqual(result, { ok: true });
		} finally {
			restore();
			await manager.stop();
		}
	});

	test('clears stale partial stdout before launching the next process', async () => {
		const children: FakeCoreChild[] = [];
		const restore = installSpawn(() => {
			const child = new FakeCoreChild();
			children.push(child);
			return child;
		});
		const manager = new CoreProcessManager({ extensionVersion: 'test', restartOnCrash: false });
		try {
			await manager.start();
			handleStdout(manager, '{"id":"old-request","type":"response"');
			children[0].crash();
			assert.strictEqual(manager.getState(), 'crashed');
			await manager.start();
			assert.strictEqual(children.length, 2);
			assert.strictEqual(manager.getState(), 'ready');
		} finally {
			restore();
			await manager.stop();
		}
	});

	test('logs malformed JSON without breaking subsequent messages', () => {
		const manager = new CoreProcessManager({ extensionVersion: 'test', restartOnCrash: false });
		const logs: string[] = [];
		manager.on('log', (message: string) => logs.push(message));
		handleStdout(manager, 'not-json\n');
		assert.deepStrictEqual(logs, ['Malformed message from core: not-json']);
	});

	test('rejects pending requests and automatically restarts after a crash', async () => {
		const children: FakeCoreChild[] = [];
		const restore = installSpawn(() => {
			const child = new FakeCoreChild();
			children.push(child);
			return child;
		});
		const manager = new CoreProcessManager({ extensionVersion: 'test', restartOnCrash: true });
		try {
			await manager.start();
			const pending = manager.request('slow', undefined, 0).then(() => undefined, (error: { code?: string }) => error);
			await Promise.resolve();
			children[0].crash();
			const error = await pending;
			assert.strictEqual(error?.code, 'CORE_PROCESS_CRASHED');
			assert.strictEqual(manager.getState(), 'restarting');
			await waitFor(() => children.length === 2 && manager.getState() === 'ready');
		} finally {
			restore();
			await manager.stop();
		}
	});
});

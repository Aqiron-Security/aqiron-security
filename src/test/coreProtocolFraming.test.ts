import { strict as assert } from 'node:assert';
import { frameCoreProtocolBytes } from '../../packages/core/src/runtime/protocolFraming';
import { runCoreRuntime } from '../../packages/core/src/runtime/coreRuntime';
import { CoreMessage } from '../../packages/core/src/runtime/protocol';

suite('Core protocol byte framing', () => {
	test('rejects a frame above the cap without retaining it and continues at the next delimiter', async () => {
		const frames = await collect(frameCoreProtocolBytes(chunks([Buffer.from('1234567890123456789012345\n{"type":"request"}\n')]), 24));
		assert.deepEqual(frames.map((frame) => 'error' in frame ? frame : frame.raw.toString('utf8')), [
			{ error: 'frame-too-large' },
			'{"type":"request"}',
		]);
	});

	test('uses process-failure framing for an oversized request instead of dispatching later data', async () => {
		const output: CoreMessage[] = [];
		const health = Buffer.from(JSON.stringify({ id: 'after-overflow', type: 'request', method: 'core.health', params: {} }) + '\n');
		await runCoreRuntime(frameCoreProtocolBytes(chunks([Buffer.from('x'.repeat(17) + '\n'), health]), 16), (message) => output.push(message), { coreVersion: 'framing-test' });
		assert.equal(output.length, 1);
		assert.equal(output[0]?.type, 'response');
		if (output[0]?.type === 'response') {assert.equal(output[0].error?.code, 'CORE_FRAME_TOO_LARGE');}
	});

	test('handles split LF, CRLF, multiple frames, and a final incomplete frame', async () => {
		const frames = await collect(frameCoreProtocolBytes(chunks([
			Buffer.from('{"a":"雪"}\r'), Buffer.from('\n{"b":2}\n{"c":3}'),
		])));
		assert.deepEqual(frames.map((frame) => 'error' in frame ? frame : frame.raw.toString('utf8')), ['{"a":"雪"}', '{"b":2}', '{"c":3}']);
		assert.equal(frames[0] && !('error' in frames[0]) && frames[0].byteLength, Buffer.byteLength('{"a":"雪"}', 'utf8'));
	});

	test('uses raw UTF-8 bytes for multibyte input and rejects invalid UTF-8 before dispatch', async () => {
		const oversized = await collect(frameCoreProtocolBytes(chunks([Buffer.from('雪雪雪\n')]), 8));
		assert.deepEqual(oversized, [{ error: 'frame-too-large' }]);
		const output: CoreMessage[] = [];
		await runCoreRuntime(frameCoreProtocolBytes(chunks([Buffer.from([0xc3, 0x28, 0x0a])])), (message) => output.push(message), { coreVersion: 'framing-test' });
		assert.equal(output.length, 1);
		assert.equal(output[0]?.type, 'response');
		if (output[0]?.type === 'response') {assert.equal(output[0].error?.code, 'CORE_PROTOCOL_ERROR');}
	});

	test('accepts a legitimate Core request below the global framing cap', async () => {
		const request = Buffer.from(JSON.stringify({ id: 'frame-health', type: 'request', method: 'core.health', params: {} }) + '\n');
		const output: CoreMessage[] = [];
		await runCoreRuntime(frameCoreProtocolBytes(chunks([request])), (message) => output.push(message), { coreVersion: 'framing-test' });
		assert.equal(output.length, 1);
		assert.equal(output[0]?.type, 'response');
		if (output[0]?.type === 'response') {assert.equal(output[0].success, true);}
	});
});

async function* chunks(items: Buffer[]): AsyncGenerator<Uint8Array> { for (const item of items) { yield item; } }
async function collect<T>(items: AsyncIterable<T>): Promise<T[]> { const output: T[] = []; for await (const item of items) {output.push(item);} return output; }

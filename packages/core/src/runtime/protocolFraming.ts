/** Global raw-byte ceiling for one newline-delimited Core JSON frame (16 MiB). */
export const MAX_CORE_PROTOCOL_FRAME_BYTES = 16 * 1024 * 1024;

export type CoreProtocolFrame = { raw: Buffer; byteLength: number } | { error: 'frame-too-large' };

/**
 * Frames raw stdin chunks without first materializing unbounded lines. Once a frame
 * crosses its cap, its bytes are discarded through the next LF delimiter.
 */
export async function* frameCoreProtocolBytes(
	input: AsyncIterable<Uint8Array>,
	maxFrameBytes = MAX_CORE_PROTOCOL_FRAME_BYTES,
): AsyncGenerator<CoreProtocolFrame> {
	let parts: Buffer[] = [];
	let retained = 0;
	let oversized = false;
	const append = (chunk: Buffer): void => {
		if (!chunk.length || oversized) { return; }
		if (retained + chunk.length > maxFrameBytes) { parts = []; retained = 0; oversized = true; return; }
		parts.push(chunk); retained += chunk.length;
	};
	const finish = (): CoreProtocolFrame | undefined => {
		if (oversized) { parts = []; retained = 0; oversized = false; return { error: 'frame-too-large' }; }
		if (!retained) { parts = []; return undefined; }
		let raw = Buffer.concat(parts, retained);
		parts = []; retained = 0;
		if (raw.length && raw[raw.length - 1] === 13) { raw = raw.subarray(0, raw.length - 1); }
		if (!raw.length) { return undefined; }
		return { raw, byteLength: raw.length };
	};
	for await (const inputChunk of input) {
		const chunk = Buffer.from(inputChunk.buffer, inputChunk.byteOffset, inputChunk.byteLength);
		let start = 0;
		for (let index = 0; index < chunk.length; index += 1) {
			if (chunk[index] !== 10) { continue; }
			append(chunk.subarray(start, index));
			const frame = finish();
			if (frame) { yield frame; }
			start = index + 1;
		}
		append(chunk.subarray(start));
	}
	const final = finish();
	if (final) { yield final; }
}

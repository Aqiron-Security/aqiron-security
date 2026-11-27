import * as fs from 'node:fs/promises';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';
import { StartCommitInputV1, ValidationLifecycleStore } from '../../packages/core/src/validation/validationLifecycle';
import type { FileSystem } from '../../packages/core/src/shared/platform';

function testFileSystem(): FileSystem {
	const base = createNodeFileSystem();
	return { ...base,
		readFileSafeBoundedBytes: async (file, max) => { const bytes = await fs.readFile(file); if (bytes.byteLength > max) { throw Object.assign(new Error('too large'), { code: 'FILE_TOO_LARGE' }); } return new Uint8Array(bytes); },
		syncDirectoryDurable: async () => undefined,
		writeFileDurableExclusive: async (file, bytes) => { const handle = await fs.open(file, 'wx'); try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); } },
		appendFileDurable: async (file, bytes) => { const handle = await fs.open(file, 'a'); try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); } },
		unlinkDurable: async file => { await fs.unlink(file); },
	} as FileSystem;
}

async function main(): Promise<void> {
	const root = process.argv[2]; const raw = process.argv[3];
	if (!root || !raw || raw.length > 16_384) { throw new TypeError('Worker input is missing or oversized.'); }
	const input = JSON.parse(raw) as StartCommitInputV1;
	const result = await new ValidationLifecycleStore(testFileSystem(), root).commitStart(input);
	process.stdout.write(JSON.stringify({ committed: result.committed, duplicate: result.duplicate, executionId: result.event.executionId }));
}

void main().catch(error => { process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`); process.exitCode = 1; });

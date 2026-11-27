import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';

async function main(): Promise<void> {
	const [operation, target] = process.argv.slice(2);
	if (!target || !['safe-read', 'append'].includes(operation ?? '')) { throw new Error('Invalid durable filesystem worker arguments.'); }
	const filesystem = createNodeFileSystem();
	try {
		if (operation === 'safe-read') { await filesystem.readFileSafeBoundedBytes!(target, 128); }
		else { await filesystem.appendFileDurable!(target, Buffer.from('fifo-test')); }
		process.stdout.write('unexpected-success\n');
	} catch {
		process.stdout.write('rejected\n');
	}
}

void main().catch(error => { process.stderr.write(`${error instanceof Error ? error.message : 'worker-failed'}\n`); process.exitCode = 1; });

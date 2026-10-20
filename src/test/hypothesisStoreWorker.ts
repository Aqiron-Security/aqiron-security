import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { HypothesisStoreService } from '../../packages/core/src/hypotheses/hypothesisStore';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';
import { HypothesisReviewInput } from '../../packages/core/src/hypotheses/contracts';

async function main(): Promise<void> {
	const [mode, root, id, action] = process.argv.slice(2);
	if (mode === 'review') {
		const input: HypothesisReviewInput = { workspaceRoot: root, hypothesisId: id, action: action as HypothesisReviewInput['action'] };
		await new HypothesisStoreService(createNodeFileSystem()).review(root, input);
		return;
	}
	if (mode === 'hold-lock') {
		const lockPath = `${path.join(root, '.aqiron-security', 'hypotheses.json')}.lock`;
		await fs.mkdir(lockPath);
		await fs.writeFile(path.join(lockPath, 'owner.json'), JSON.stringify({ pid: process.pid, token: 'worker-owner' }));
		const old = new Date(Date.now() - 180_000);
		await fs.utimes(lockPath, old, old);
		process.stdout.write('ready\n');
		await new Promise<void>((resolve) => process.stdin.once('data', () => resolve()));
		await fs.unlink(path.join(lockPath, 'owner.json'));
		await fs.rmdir(lockPath);
	}
}

void main().catch((error) => { process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`); process.exitCode = 1; });

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { HypothesisStoreService } from '../../packages/core/src/hypotheses/hypothesisStore';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';
import { HypothesisReviewInput } from '../../packages/core/src/hypotheses/contracts';

async function main(): Promise<void> {
	const [mode, root, id, action] = process.argv.slice(2);
	if (mode === 'hold-review') {
		process.stdout.write('worker-ready\n');
		const filesystem = createNodeFileSystem();
		const originalRead = filesystem.readFileBounded!;
		const storePath = path.join(root, '.aqiron-security', 'hypotheses.json');
		filesystem.readFileBounded = async (file, maxBytes, encoding) => {
			if (path.resolve(file) === path.resolve(storePath)) {
				process.stdout.write('critical-section\n');
				await new Promise<void>((resolve) => process.stdin.once('data', () => resolve()));
			}
			return await originalRead(file, maxBytes, encoding);
		};
		await new HypothesisStoreService(filesystem).review(root, { workspaceRoot: root, hypothesisId: id, action: action as HypothesisReviewInput['action'] });
		process.stdout.write('review-complete\n');
		return;
	}
	if (mode === 'review') {
		const input: HypothesisReviewInput = { workspaceRoot: root, hypothesisId: id, action: action as HypothesisReviewInput['action'] };
		await new HypothesisStoreService(createNodeFileSystem()).review(root, input);
		return;
	}
	if (mode === 'race-review' || mode === 'race-list') {
		const [barrier, id, action, index] = process.argv.slice(4);
		await fs.writeFile(path.join(barrier, `ready-${index}`), 'ready');
		process.stdout.write('ready\n');
		while (!await fs.access(path.join(barrier, 'go')).then(() => true).catch(() => false)) {await new Promise((resolve) => setTimeout(resolve, 5));}
		const filesystem = createNodeFileSystem();
		const originalRead = filesystem.readFileBounded!;
		const storePath = path.join(root, '.aqiron-security', 'hypotheses.json');
		const overlapPath = path.join(barrier, 'overlap');
		filesystem.readFileBounded = async (file, maxBytes, encoding) => {
			const normalized = path.resolve(file);
			const isCritical = normalized === path.resolve(storePath) || normalized.endsWith(`${path.sep}hypotheses.json.lock${path.sep}owner.json`);
			const marker = path.join(barrier, `${normalized === path.resolve(storePath) ? 'store' : 'owner'}-${process.pid}`);
			if (isCritical) {
				await fs.writeFile(marker, 'active');
				await new Promise((resolve) => setTimeout(resolve, 100));
				const names = await fs.readdir(barrier);
				if (names.filter((name) => name.startsWith(normalized === path.resolve(storePath) ? 'store-' : 'owner-')).length > 1) {await fs.writeFile(overlapPath, 'overlap');}
				await fs.unlink(marker).catch(() => undefined);
			}
			return await originalRead(file, maxBytes, encoding);
		};
		const service = new HypothesisStoreService(filesystem);
		if (mode === 'race-review') {
			const input: HypothesisReviewInput = { workspaceRoot: root, hypothesisId: id, action: action as HypothesisReviewInput['action'] };
			await service.review(root, input);
		} else {await service.list(root);}
		if (await fs.access(overlapPath).then(() => true).catch(() => false)) {process.stdout.write('overlap\n');}
		return;
	}
	if (mode === 'hold-lock') {
		const lockPath = `${path.join(root, '.aqiron-security', 'hypotheses.json')}.lock`;
		const gatePath = `${lockPath}.gate`;
		await fs.mkdir(gatePath);
		await fs.mkdir(lockPath);
		await fs.writeFile(path.join(lockPath, 'owner.json'), JSON.stringify({ pid: process.pid, token: 'worker-owner' }));
		const old = new Date(Date.now() - 180_000);
		await fs.utimes(lockPath, old, old);
		await fs.rmdir(gatePath);
		process.stdout.write('ready\n');
		await new Promise<void>((resolve) => process.stdin.once('data', () => resolve()));
		while (true) {
			try { await fs.mkdir(gatePath); break; }
			catch (error) { if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'EEXIST') {throw error;} await new Promise((resolve) => setTimeout(resolve, 5)); }
		}
		await fs.unlink(path.join(lockPath, 'owner.json'));
		await fs.rmdir(lockPath);
		await fs.rmdir(gatePath);
	}
}


void main().catch((error) => { process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`); process.exitCode = 1; });

import * as assert from 'node:assert/strict';
import * as nodeFs from 'node:fs';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { suite, test } from 'mocha';
import { EvidenceEngine } from '../../packages/core/src/evidence/evidenceEngine';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';
import { hashSourceContent, hashSourceSpan } from '../../packages/core/src/shared/sourceProvenance';
import type { FileSystem } from '../../packages/core/src/shared/platform';

suite('Core Evidence Engine', function () {
	this.timeout(15_000);
	function fixture(root: string) {
		const content = 'const value = 1;\n';
		return { content, provenance: { findingId: 'f', file: 'src/sample.ts', startLine: 1, endLine: 1, contentHash: hashSourceSpan(content, 1, 1), sourceContentHash: hashSourceContent(content), sourceTool: 'Aqiron', ruleId: 'native.test', observedAt: '2026-11-25T00:00:00.000Z' } };
	}
	async function setup(root: string) {
		const file = path.join(root, 'src', 'sample.ts'); await fs.mkdir(path.dirname(file), { recursive: true });
		const { content, provenance } = fixture(root); await fs.writeFile(file, content, 'utf8');
		return { engine: new EvidenceEngine(createNodeFileSystem()), provenance };
	}
	function failingFilesystem(fail: (operation: string, file: string) => boolean): FileSystem {
		const base = createNodeFileSystem();
		return new Proxy(base, { get(target, key, receiver) {
			const value = Reflect.get(target, key, receiver);
			if (typeof value !== 'function') { return value; }
			return (...args: unknown[]) => {
				const file = String(args[0] ?? '');
				if (fail(String(key), file)) { return Promise.reject(Object.assign(new Error('injected filesystem failure'), { code: 'EIO' })); }
				return (value as (...values: unknown[]) => unknown).apply(target, args);
			};
		} });
	}
	test('captures distinct immutable observations and rechecks without changing history', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-evidence-test-'));
		try {
			const file = path.join(root, 'src', 'sample.ts');
			await fs.mkdir(path.dirname(file), { recursive: true });
			const content = 'const token = "example-secret";\n';
			await fs.writeFile(file, content, 'utf8');
			const engine = new EvidenceEngine(createNodeFileSystem());
			const provenance = { findingId: 'finding-1', file: 'src/sample.ts', startLine: 1, endLine: 1, contentHash: hashSourceSpan(content, 1, 1), sourceContentHash: hashSourceContent(content), sourceTool: 'Aqiron', ruleId: 'critical.secret', observedAt: '2026-11-25T00:00:00.000Z' };
			const first = await engine.captureScan(root, 'scan-1', [provenance]);
			const second = await engine.captureScan(root, 'scan-2', [provenance]);
			assert.equal(first.length, 1);
			assert.equal(second.length, 1);
			assert.notEqual(first[0].id, second[0].id);
			assert.equal(first[0].kind, 'source_span');
			assert.equal(first[0].originatingFindingId, 'finding-1');
			assert.equal(first[0].workspaceIdentity, await fs.realpath(root));
			assert.deepEqual(await engine.recheck(root, first[0]), { status: 'current' });
			await fs.writeFile(file, 'const token = "changed-secret";\n', 'utf8');
			assert.deepEqual(await engine.recheck(root, first[0]), { status: 'stale', reason: 'content-changed' });
			assert.deepEqual(await engine.get(root, first[0].id), first[0]);
			assert.equal((await engine.list(root, { scanId: 'scan-2' })).length, 1);
			await fs.unlink(file);
			assert.deepEqual(await engine.recheck(root, first[0]), { status: 'unavailable', reason: 'missing' });
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('rejects forged scanner provenance and unsafe relative paths', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-evidence-test-'));
		try {
			const engine = new EvidenceEngine(createNodeFileSystem());
			const forged = { findingId: 'f', file: '../outside.ts', startLine: 1, endLine: 1, contentHash: 'a'.repeat(64), sourceContentHash: 'b'.repeat(64), sourceTool: 'forged', ruleId: 'r', observedAt: '2026-11-25T00:00:00.000Z' };
			assert.deepEqual(await engine.captureScan(root, 'scan-1', [forged]), []);
			await assert.rejects(() => engine.captureScan(root, '../bad', []));
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('serializes concurrent appends and preserves corrupt history for recovery', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-evidence-test-'));
		try {
			const file = path.join(root, 'src', 'sample.ts');
			await fs.mkdir(path.dirname(file), { recursive: true });
			const content = 'const value = 1;\n';
			await fs.writeFile(file, content, 'utf8');
			const engine = new EvidenceEngine(createNodeFileSystem());
			const provenance = { findingId: 'f', file: 'src/sample.ts', startLine: 1, endLine: 1, contentHash: hashSourceSpan(content, 1, 1), sourceContentHash: hashSourceContent(content), sourceTool: 'Aqiron', ruleId: 'native.test', observedAt: '2026-11-25T00:00:00.000Z' };
			const writes = await Promise.all(Array.from({ length: 6 }, (_, index) => engine.captureScan(root, `scan-${index}`, [provenance])));
			assert.equal(writes.flat().length, 6);
			assert.equal((await engine.list(root, { limit: 20 })).length, 6);
			const storePath = path.join(root, '.aqiron-security', 'evidence.json');
			const committed = await fs.readFile(storePath, 'utf8');
			await fs.writeFile(storePath, '{broken', 'utf8');
			await assert.rejects(() => engine.captureScan(root, 'scan-next', [provenance]), /could not safely persist/i);
			assert.equal(await fs.readFile(storePath, 'utf8'), '{broken');
			const backup = `${storePath}.recover.bak`;
			await fs.writeFile(backup, committed, 'utf8');
			await fs.unlink(storePath);
			assert.equal((await engine.list(root, { limit: 20 })).length, 6);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('failed atomic replacement preserves committed history and releases the workspace lock', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-evidence-failure-'));
		try {
			const { engine, provenance } = await setup(root);
			const accepted = (await engine.captureScan(root, 'accepted', [provenance]))[0];
			const target = path.join(root, '.aqiron-security', 'evidence.json');
			let failed = false;
			const failing = new EvidenceEngine(failingFilesystem((op, file) => {
				if (!failed && op === 'rename' && file.includes('.tmp') && file !== target) { failed = true; return true; }
				return false;
			}));
			await assert.rejects(() => failing.captureScan(root, 'rejected', [provenance]), /could not safely persist/i);
			assert.deepEqual(await engine.get(root, accepted.id), accepted);
			assert.equal((await engine.list(root)).length, 1);
			const recovered = await engine.captureScan(root, 'after-failure', [provenance]);
			assert.equal(recovered.length, 1);
			assert.equal((await engine.list(root)).length, 2);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('exclusive temporary creation and lock acquisition failures are reported without changing history', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-evidence-boundary-'));
		try {
			const { engine, provenance } = await setup(root);
			const accepted = (await engine.captureScan(root, 'accepted', [provenance]))[0];
			const storePath = path.join(root, '.aqiron-security', 'evidence.json');
			const tempFailure = new EvidenceEngine(failingFilesystem((op, file) => op === 'writeFileExclusive' && file.startsWith(`${storePath}.`) && file.endsWith('.tmp')));
			await assert.rejects(() => tempFailure.captureScan(root, 'no-temp', [provenance]), /could not safely persist/i);
			const lockFailure = new EvidenceEngine(failingFilesystem((op, file) => op === 'writeFileExclusive' && file.endsWith('owner.json')));
			await assert.rejects(() => lockFailure.captureScan(root, 'no-lock', [provenance]));
			assert.deepEqual(await engine.get(root, accepted.id), accepted);
			assert.equal((await engine.list(root)).length, 1);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('ignores orphan temporary files, restores only validated backups, and rejects malformed stores', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-evidence-recovery-'));
		try {
			const { engine, provenance } = await setup(root);
			const accepted = (await engine.captureScan(root, 'accepted', [provenance]))[0];
			const target = path.join(root, '.aqiron-security', 'evidence.json');
			const committed = await fs.readFile(target, 'utf8');
			await fs.writeFile(`${target}.orphan.tmp`, '{partial', 'utf8');
			await fs.writeFile(`${target}.recovery.bak`, committed, 'utf8');
			await fs.unlink(target);
			assert.deepEqual(await engine.get(root, accepted.id), accepted);
			assert.equal(await fs.readFile(target, 'utf8'), committed);
			await fs.writeFile(target, '{corrupt', 'utf8');
			await assert.rejects(() => engine.list(root));
			assert.equal(await fs.readFile(target, 'utf8'), '{corrupt');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('rejects foreign-workspace and malformed backups without moving artifacts', async () => {
		for (const kind of ['foreign', 'malformed'] as const) {
			const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-evidence-bad-backup-'));
			try {
				const { engine, provenance } = await setup(root);
				await engine.captureScan(root, 'accepted', [provenance]);
				const target = path.join(root, '.aqiron-security', 'evidence.json');
				const committed = JSON.parse(await fs.readFile(target, 'utf8')) as { observations: Array<Record<string, unknown>> };
				const backupPath = `${target}.candidate.bak`;
				if (kind === 'foreign') { committed.observations[0].workspaceIdentity = `${root}-foreign`; await fs.writeFile(backupPath, JSON.stringify(committed), 'utf8'); }
				else { await fs.writeFile(backupPath, '{broken', 'utf8'); }
				await fs.unlink(target);
				const backupBefore = await fs.readFile(backupPath, 'utf8');
				await assert.rejects(() => engine.list(root));
				await assert.rejects(() => fs.stat(target), { code: 'ENOENT' });
				assert.equal(await fs.readFile(backupPath, 'utf8'), backupBefore);
			} finally { await fs.rm(root, { recursive: true, force: true }); }
		}
	});

	test('exclusive creation collision preserves the pre-existing file', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-evidence-partial-write-'));
		try {
			const target = path.join(root, 'existing.tmp');
			await fs.writeFile(target, 'other-writers-file', 'utf8');
			const filesystem = createNodeFileSystem();
			await assert.rejects(() => filesystem.writeFileExclusive!(target, 'replacement', 'utf8'));
			assert.equal(await fs.readFile(target, 'utf8'), 'other-writers-file');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('actual Node adapter leaves a partial orphan and never deletes a replacement pathname', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-evidence-partial-write-'));
		const target = path.join(root, 'owned.tmp'), owned = `${target}.owned`;
		const filesystem = createNodeFileSystem();
		const promises = nodeFs.promises as unknown as { open: (...args: any[]) => Promise<any> };
		const originalOpen = promises.open;
		try {
			promises.open = async (file: string, ...args: any[]) => {
				const handle = await originalOpen.call(nodeFs.promises, file, ...args);
				if (file !== target) { return handle; }
				return new Proxy(handle, { get(nativeHandle, key, receiver) {
					if (key === 'writeFile') { return async () => {
						await nativeHandle.writeFile('partial-bytes');
						await nativeHandle.close();
						await fs.rename(target, owned);
						await fs.writeFile(target, 'replacement-writer-data', 'utf8');
						throw new Error('injected failure after partial bytes and path replacement');
					}; }
					const value = Reflect.get(nativeHandle, key, receiver);
					return typeof value === 'function' ? value.bind(nativeHandle) : value;
				} });
			};
			await assert.rejects(() => filesystem.writeFileExclusive!(target, 'full-payload', 'utf8'), /injected failure/);
			assert.equal(await fs.readFile(owned, 'utf8'), 'partial-bytes', 'the actual exclusive-created file received bytes before failure');
			assert.equal(await fs.readFile(target, 'utf8'), 'replacement-writer-data', 'failure cleanup must not unlink a replacement path');
		} finally { promises.open = originalOpen; await fs.rm(root, { recursive: true, force: true }); }
	});

	test('partial write failure leaves an ignored orphan and preserves committed evidence and lock usability', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-evidence-partial-store-'));
		const promises = nodeFs.promises as unknown as { open: (...args: any[]) => Promise<any> };
		const originalOpen = promises.open;
		try {
			const { engine, provenance } = await setup(root);
			const accepted = (await engine.captureScan(root, 'accepted', [provenance]))[0];
			const target = path.join(root, '.aqiron-security', 'evidence.json');
			const committed = await fs.readFile(target, 'utf8');
			let partialPath = '';
			promises.open = async (file: string, ...args: any[]) => {
				const handle = await originalOpen.call(nodeFs.promises, file, ...args);
				if (typeof file !== 'string' || !file.startsWith(`${target}.`) || !file.endsWith('.tmp')) { return handle; }
				partialPath = file;
				return new Proxy(handle, { get(nativeHandle, key, receiver) {
					if (key === 'writeFile') { return async () => { await nativeHandle.writeFile('partial-store-bytes'); throw new Error('injected partial store write'); }; }
					const value = Reflect.get(nativeHandle, key, receiver);
					return typeof value === 'function' ? value.bind(nativeHandle) : value;
				} });
			};
			await assert.rejects(() => engine.captureScan(root, 'failed-partial', [provenance]), /could not safely persist/i);
			promises.open = originalOpen;
			assert.ok(partialPath);
			assert.equal(await fs.readFile(partialPath, 'utf8'), 'partial-store-bytes');
			assert.equal(await fs.readFile(target, 'utf8'), committed);
			assert.deepEqual(await engine.get(root, accepted.id), accepted);
			assert.equal((await engine.list(root)).length, 1, 'reader ignores the orphan partial temporary file');
			assert.equal((await engine.captureScan(root, 'after-partial-failure', [provenance])).length, 1, 'workspace lock was released after failure');
			assert.equal((await engine.list(root)).length, 2);
		} finally { promises.open = originalOpen; await fs.rm(root, { recursive: true, force: true }); }
	});

	test('concurrent appends retain all accepted immutable observations and list bounds', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-evidence-race-'));
		try {
			const { engine, provenance } = await setup(root);
			const results = await Promise.all(Array.from({ length: 12 }, (_, i) => engine.captureScan(root, `parallel-${i}`, [provenance])));
			const observations = results.flat();
			assert.equal(observations.length, 12);
			assert.equal(new Set(observations.map((item) => item.id)).size, 12);
			assert.equal((await engine.list(root, { limit: 3 })).length, 3);
			for (const item of observations) { assert.deepEqual(await engine.get(root, item.id), item); }
			const store = JSON.parse(await fs.readFile(path.join(root, '.aqiron-security', 'evidence.json'), 'utf8')) as { observations: unknown[] };
			assert.equal(store.observations.length, 12);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});
});

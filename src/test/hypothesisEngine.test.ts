import { strict as assert } from 'assert';
import * as fs from 'fs/promises';
import * as path from 'path';
import { spawn } from 'node:child_process';
import * as crypto from 'node:crypto';
import { CorrelatedRelationship } from '../../packages/core/src/correlation/correlationEngine';
import { createFinding } from '../../packages/core/src/findings/finding';
import { UnifiedFinding } from '../../packages/core/src/shared/finding';
import { createEmptyProjectProfile } from '../../packages/core/src/project/projectProfile';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';
import { buildHypothesisSnapshot, generateDeterministicHypotheses, hashSourceSpan, safeRelativePath, validateEvidenceReference } from '../../packages/core/src/hypotheses/hypothesisEngine';
import { HypothesisStoreError, HypothesisStoreService, transition } from '../../packages/core/src/hypotheses/hypothesisStore';
import { FileSystem } from '../../packages/core/src/shared/platform';
import { AITransport } from '../../packages/core/src/ai/utils/request';
import * as sourceProvenance from '../../packages/core/src/shared/sourceProvenance';
import { createSourceLineIndex, FindingSourceProvenance, hashSourceContent } from '../../packages/core/src/shared/sourceProvenance';
import { NativeWorkspaceScanner } from '../../packages/core/src/scanners/native/nativeScanner';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';

suite('Core deterministic hypothesis engine', () => {
	test('builds a stable snapshot from verified findings and emits only the allowlisted malware attribution hypothesis', async () => {
		const root = await testRoot('snapshot');
		try {
			await fs.mkdir(path.join(root, 'src'), { recursive: true });
			await fs.writeFile(path.join(root, 'src', 'indicator.txt'), 'malware-indicator\n');
			await fs.writeFile(path.join(root, 'src', 'mobile.apk'), 'artifact-signature\n');
			const findings = [
				createFinding({ title: 'Malware indicator', description: 'Indicator matched', severity: 'High', cwe: [], owasp: [], file: path.join(root, 'src', 'indicator.txt'), line: 1, column: 1, sourceTool: 'MobSF', ruleId: 'mobsf.indicator', confidence: 'Medium', remediation: 'Review', tags: ['malware'], rawEvidence: { secret: 'do-not-persist' } }),
				createFinding({ title: 'Mobile artifact signal', description: 'Artifact flagged', severity: 'Low', cwe: [], owasp: [], file: path.join(root, 'src', 'mobile.apk'), line: 1, column: 1, sourceTool: 'Trivy', ruleId: 'trivy.artifact', confidence: 'Low', remediation: 'Review', tags: ['artifact'], rawEvidence: { secret: 'do-not-persist' } }),
			];
			const relation: CorrelatedRelationship = { sourceId: findings[0].id, targetId: findings[1].id, type: 'malware-to-artifact', weight: 0.75, reason: 'filename/tag heuristic' };
			const input = { workspaceRoot: root, scanId: 'scan-a', findings, relationships: [relation], profile: createEmptyProjectProfile(root), filesystem: createFileSystem(), scanProvenance: [...makeProvenance(findings[0], root, 'malware-indicator\n'), ...makeProvenance(findings[1], root, 'artifact-signature\n')] };
			const first = await buildHypothesisSnapshot(input);
			const second = await buildHypothesisSnapshot(input);
			assert.equal(first.id, second.id);
			assert.ok(first.evidence.every((ref) => !ref.file || !path.isAbsolute(ref.file)));
			assert.ok(first.evidence.every((ref) => validateEvidenceReference(first, ref)));
			const hypotheses = generateDeterministicHypotheses(first);
			assert.equal(hypotheses.length, 1);
			assert.equal(hypotheses[0].status, 'proposed');
			assert.equal(hypotheses[0].confidence.band, 'low');
			assert.match(hypotheses[0].description, /^Does the malware indicator/);
			assert.ok(hypotheses[0].evidence.length >= 5);
			assert.ok(!JSON.stringify(hypotheses).includes('do-not-persist'));
			assert.equal(generateDeterministicHypotheses({ ...first, relationships: [] }).length, 0);
			assert.equal(generateDeterministicHypotheses({ ...first, relationships: [relation, relation] }).length, 1);
			const stored = new HypothesisStoreService(createFileSystem());
			await stored.mergeGeneration(root, first, hypotheses, () => false);
			const persisted = await fs.readFile(path.join(root, '.aqiron-security', 'hypotheses.json'), 'utf8');
			assert.ok(!persisted.includes('do-not-persist'));
			assert.ok(!persisted.includes('excerpt'));
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('rejects fabricated references, absolute/traversal paths, and stale references', async () => {
		const root = await testRoot('evidence');
		try {
			await fs.writeFile(path.join(root, 'file.ts'), 'const safe = true;\n');
			const finding = createFinding({ title: 'Observed', description: 'Observed issue', severity: 'Low', cwe: [], owasp: [], file: path.join(root, 'file.ts'), line: 1, column: 1, sourceTool: 'Aqiron', ruleId: 'test.rule', confidence: 'Low', remediation: 'Review', tags: [], rawEvidence: {} });
			const source = 'const safe = true;\n';
			const snapshot = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'scan', findings: [finding], relationships: [], profile: createEmptyProjectProfile(root), filesystem: createFileSystem(), scanProvenance: makeProvenance(finding, root, source) });
			const reference = snapshot.evidence.find((item) => item.kind === 'finding')!;
			assert.equal(validateEvidenceReference(snapshot, { ...reference, id: 'finding:fabricated' }), false);
			assert.equal(safeRelativePath(root, '../outside.ts'), undefined);
			assert.equal(safeRelativePath(root, path.join(root, 'file.ts')), undefined);
			assert.equal(safeRelativePath(root, 'src\\file.ts'), 'src/file.ts');
			assert.equal(validateEvidenceReference(snapshot, { ...reference, file: '../outside.ts' }), false);
			assert.equal(validateEvidenceReference(snapshot, { ...reference, startLine: 0 }), false);
			assert.equal(validateEvidenceReference(snapshot, { ...reference, freshness: 'stale' }), false);
			const store = new HypothesisStoreService(createFileSystem());
			const span = snapshot.evidence.find((item) => item.kind === 'source-span')!;
			const hypothesis = { ...testHypothesis(), evidence: [span], snapshotId: snapshot.id };
			await store.mergeGeneration(root, snapshot, [hypothesis], () => false);
			await fs.writeFile(path.join(root, 'file.ts'), 'const changed = false;\n');
			assert.equal((await store.list(root)).hypotheses[0].status, 'stale');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('uses hashes captured from the native scanner and excludes changed, deleted, or unreadable sources', async () => {
		for (const outcome of ['unchanged', 'modified', 'deleted', 'unreadable'] as const) {
			const root = await testRoot(`scan-provenance-${outcome}`);
			try {
				const file = path.join(root, 'src.ts');
				const observed = 'OBSERVED_MARKER\n';
				await fs.writeFile(file, observed);
				const scan = await new NativeWorkspaceScanner(createFileSystem()).scanWorkspace(root, undefined, undefined, [testRule()]);
				const finding = scan.findings[0];
				assert.ok(finding, 'fixture must produce a native finding');
				const provenance = scan.sourceProvenance?.find((item) => item.findingId === finding.id);
				assert.ok(provenance, 'native scan must retain scan-time provenance');
				assert.equal(provenance.contentHash, hashSourceSpan(observed, finding.line, finding.endLine ?? finding.line));
				if (outcome === 'modified') { await fs.writeFile(file, 'OBSERVED_MARKER\nconst unrelated = true;\n'); }
				if (outcome === 'deleted') { await fs.unlink(file); }
				const filesystem = outcome === 'unreadable' ? createFileSystem({ unreadablePaths: [file] }) : createFileSystem();
				const snapshot = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'native-scan', findings: [finding], relationships: [], profile: createEmptyProjectProfile(root), filesystem, scanProvenance: [provenance] });
				assert.equal(snapshot.findings.length, outcome === 'unchanged' ? 1 : 0);
				assert.equal(snapshot.excludedUnprovenancedFindings, outcome === 'unchanged' ? 0 : 1);
			} finally { await fs.rm(root, { recursive: true, force: true }); }
		}
	});

	test('bounds unique snapshot reads, aggregate source bytes, growth, per-file size and read failures', async () => {
		const root = await testRoot('snapshot-read-bounds');
		try {
			const content = 'observed\n';
			const sharedFile = path.join(root, 'shared.ts');
			await fs.writeFile(sharedFile, content);
			const sharedFindings = Array.from({ length: 12 }, (_, index) => createFinding({ title: `Observed ${index}`, description: 'Observed', severity: 'Low', cwe: [], owasp: [], file: sharedFile, line: 1, column: 1, sourceTool: 'Aqiron', ruleId: `rule.${index}`, confidence: 'Low', remediation: 'Review', tags: [], rawEvidence: {} }));
			const sharedProvenance = sharedFindings.map((finding) => makeProvenance(finding, root, content)[0]);
			let sharedReads = 0;
			const countFs = createFileSystem();
			const baseRead = countFs.readFileBoundedBytes!;
			countFs.readFileBoundedBytes = async (file, maxBytes) => { if (path.resolve(file) === path.resolve(sharedFile)) {sharedReads += 1;} return await baseRead(file, maxBytes); };
			const sharedSnapshot = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'shared-source', findings: sharedFindings, relationships: [], profile: createEmptyProjectProfile(root), filesystem: countFs, scanProvenance: sharedProvenance });
			assert.equal(sharedReads, 1);
			assert.equal(sharedSnapshot.findings.length, sharedFindings.length);

			const growingFile = path.join(root, 'growing.ts');
			await fs.writeFile(growingFile, content);
			const growingFinding = createFinding({ title: 'Growing', description: 'Observed', severity: 'Low', cwe: [], owasp: [], file: growingFile, line: 1, column: 1, sourceTool: 'Aqiron', ruleId: 'growth', confidence: 'Low', remediation: 'Review', tags: [], rawEvidence: {} });
			const growFs = createFileSystem({ beforeBoundedRead: async (file) => {if (path.resolve(file) === path.resolve(growingFile)) {await fs.writeFile(growingFile, 'x'.repeat(10_000_001));}} });
			const grown = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'growth', findings: [growingFinding], relationships: [], profile: createEmptyProjectProfile(root), filesystem: growFs, scanProvenance: makeProvenance(growingFinding, root, content) });
			assert.equal(grown.findings.length, 0, 'growth after the metadata check fails closed at the bounded handle read');
			assert.equal(grown.excludedUnprovenancedFindings, 1);

			const unreadable = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'unreadable', findings: [growingFinding], relationships: [], profile: createEmptyProjectProfile(root), filesystem: createFileSystem({ unreadablePaths: [growingFile] }), scanProvenance: makeProvenance(growingFinding, root, content) });
			assert.equal(unreadable.findings.length, 0);

			const aggregateFindings: UnifiedFinding[] = [];
			const aggregateProvenance: FindingSourceProvenance[] = [];
			const largeText = `x\n${'z'.repeat(9_999_998)}`;
			const largeHash = hashSourceContent(largeText);
			const largeSpan = hashSourceSpan(largeText, 1, 1);
			const aggregateFiles: string[] = [];
			for (let index = 0; index < 6; index += 1) {
				const file = path.join(root, `aggregate-${index}.ts`);
				await fs.writeFile(file, 'x');
				aggregateFiles.push(path.resolve(file));
				const finding = createFinding({ title: `Aggregate ${index}`, description: 'Observed', severity: 'Low', cwe: [], owasp: [], file, line: 1, column: 1, sourceTool: 'Aqiron', ruleId: `aggregate.${index}`, confidence: 'Low', remediation: 'Review', tags: [], rawEvidence: {} });
				aggregateFindings.push(finding);
				aggregateProvenance.push({ ...makeProvenance(finding, root, largeText)[0], contentHash: largeSpan, sourceContentHash: largeHash });
			}
			let rawConsumed = 0;
			const aggregateFs = createFileSystem();
			const aggregateStat = aggregateFs.stat;
			aggregateFs.stat = async (file) => aggregateFiles.includes(path.resolve(file)) ? { isFile: () => true, isDirectory: () => false, size: 10_000_000, mtimeMs: 0 } : await aggregateStat(file);
			aggregateFs.readFileBoundedBytes = async (file, maxBytes) => {
				if (!aggregateFiles.includes(path.resolve(file))) {return await createFileSystem().readFileBoundedBytes!(file, maxBytes);}
				if (maxBytes < 10_000_000) {throw Object.assign(new Error('FILE_TOO_LARGE'), { code: 'FILE_TOO_LARGE', bytesRead: maxBytes + 1 });}
				rawConsumed += 10_000_000;
				return Buffer.from(largeText, 'utf8');
			};
			const aggregate = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'aggregate', findings: aggregateFindings, relationships: [], profile: createEmptyProjectProfile(root), filesystem: aggregateFs, scanProvenance: aggregateProvenance });
			assert.equal(rawConsumed, 50_000_000);
			assert.equal(aggregate.findings.length, 5);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('fails closed for existing lock directories with missing, malformed, or unreadable owners', async () => {
		for (const state of ['missing', 'malformed', 'unreadable'] as const) {
			const root = await testRoot(`owner-${state}`);
			try {
				const lock = `${path.join(root, '.aqiron-security', 'hypotheses.json')}.lock`;
				await fs.mkdir(lock, { recursive: true });
				const owner = path.join(lock, 'owner.json');
				if (state !== 'missing') {await fs.writeFile(owner, state === 'malformed' ? '{' : JSON.stringify({ pid: process.pid, token: 'unreadable-owner' }));}
				const service = new HypothesisStoreService(createFileSystem({ unreadablePaths: state === 'unreadable' ? [owner] : [] }));
				await assert.rejects(service.list(root), (error: unknown) => error instanceof Error && ['HYPOTHESIS_STORE_LOCKED', 'HYPOTHESIS_STORE_INVALID'].includes(String((error as NodeJS.ErrnoException).code)));
				assert.equal(await fs.access(lock).then(() => true).catch(() => false), true, 'ambiguous lock artifact is preserved');
			} finally {await fs.rm(root, { recursive: true, force: true });}
		}
	});

	test('does not admit a second reviewer after an active lock owner record disappears', async () => {
		const root = await testRoot('owner-disappears');
		let worker: ReturnType<typeof spawn> | undefined;
		try {
			const hypothesis = await addCurrentTestProvenance(root, testHypothesis());
			const storeFile = path.join(root, '.aqiron-security', 'hypotheses.json');
			await fs.mkdir(path.dirname(storeFile), { recursive: true });
			await fs.writeFile(storeFile, JSON.stringify({ version: 1, scoringPolicyVersion: 1, generation: 1, updatedAt: '', hypotheses: [hypothesis], snapshots: [] }));
			worker = spawn(process.execPath, [path.join(__dirname, 'hypothesisStoreWorker.js'), 'hold-review', root, hypothesis.id, 'dismiss'], { stdio: ['pipe', 'pipe', 'pipe'] });
			let workerOutput = '';
			await new Promise<void>((resolve, reject) => {
				const timer = setTimeout(() => reject(new Error(`review worker did not enter its protected store read; output: ${workerOutput}`)), 8_000);
				worker!.stdout!.on('data', (chunk) => {workerOutput += String(chunk); if (workerOutput.includes('critical-section')) {clearTimeout(timer); resolve();}});
				worker!.stderr!.on('data', (chunk) => reject(new Error(String(chunk)))); worker!.once('error', reject); worker!.once('exit', (code) => reject(new Error(`review worker exited before entering critical section: ${code}`)));
			});
			const owner = path.join(root, '.aqiron-security', 'hypotheses.json.lock', 'owner.json');
			await fs.unlink(owner);
			const second = spawn(process.execPath, [path.join(__dirname, 'hypothesisStoreWorker.js'), 'review', root, hypothesis.id, 'reject'], { stdio: ['ignore', 'pipe', 'pipe'] });
			const gatePresent = await fs.access(`${path.dirname(owner)}.gate`).then(() => true).catch(() => false);
			const secondError = await new Promise<string>((resolve, reject) => {let stderr = ''; const timer = setTimeout(() => reject(new Error(`second reviewer did not fail closed; gate present=${gatePresent}; stderr=${stderr}`)), 8_000); second.stderr!.on('data', (chunk) => {stderr += String(chunk);}); second.once('error', reject); second.once('exit', (code) => {clearTimeout(timer); code === 0 ? reject(new Error('second reviewer unexpectedly acquired the ownerless lock')) : resolve(stderr);});});
			assert.match(secondError, /owner record|ownership is ambiguous/i);
			worker.stdin!.end('continue\n');
			await new Promise<void>((resolve, reject) => {worker!.once('error', reject); worker!.once('exit', (code) => code === 0 ? resolve() : reject(new Error(`first reviewer exited ${code}`))); worker!.stderr!.on('data', (chunk) => reject(new Error(String(chunk))));});
			const persisted = JSON.parse(await fs.readFile(path.join(root, '.aqiron-security', 'hypotheses.json'), 'utf8')) as { hypotheses: SecurityHypothesis[] };
			const saved = persisted.hypotheses[0];
			assert.equal(saved.status, 'dismissed');
			assert.equal(saved.review?.action, 'dismiss');
		} finally {worker?.kill(); await fs.rm(root, { recursive: true, force: true });}
	});

	test('accounts freshness budgets in raw bytes even when invalid UTF-8 expands during decoding', async () => {
		const root = await testRoot('raw-freshness-budget');
		try {
			const paths = Array.from({ length: 7 }, (_, index) => path.join(root, `raw-${index}.ts`));
			for (const file of paths) {await fs.writeFile(file, 'x');}
			const sizes = new Map(paths.map((file, index) => [path.resolve(file), index < 5 ? 9_800_000 : index === 5 ? 1_000_000 : 1]));
			const hypotheses = paths.map((file, index) => {
				const base = testHypothesis();
				return { ...base, id: `hyp:raw-${index}`, evidence: [{ id: `span-raw-${index}`, kind: 'source-span' as const, source: 'Core', file: path.basename(file), startLine: 1, endLine: 1, contentHash: '0'.repeat(64), fileContentHash: '1'.repeat(64), findingId: `finding-raw-${index}`, observedAt: base.createdAt, freshness: 'current' as const }] };
			});
			const storeFile = path.join(root, '.aqiron-security', 'hypotheses.json');
			await fs.mkdir(path.dirname(storeFile), { recursive: true });
			await fs.writeFile(storeFile, JSON.stringify({ version: 1, scoringPolicyVersion: 1, updatedAt: '', hypotheses, snapshots: [] }));
			let rawConsumed = 0;
			const filesystem = createFileSystem();
			const baseStat = filesystem.stat;
			filesystem.stat = async (file) => sizes.has(path.resolve(file)) ? { isFile: () => true, isDirectory: () => false, size: sizes.get(path.resolve(file))!, mtimeMs: 0 } : await baseStat(file);
			filesystem.readFileBoundedBytes = async (file, maxBytes) => {
				const size = sizes.get(path.resolve(file));
				if (size === undefined) {return await createFileSystem().readFileBoundedBytes!(file, maxBytes);}
				if (size > maxBytes) {rawConsumed += maxBytes + 1; throw Object.assign(new Error('FILE_TOO_LARGE'), { code: 'FILE_TOO_LARGE', bytesRead: maxBytes + 1 });}
				rawConsumed += size;
				return Buffer.alloc(size, path.resolve(file) === path.resolve(paths[5]) ? 0xff : 0x61);
			};
			const refreshed = await new HypothesisStoreService(filesystem).list(root);
			assert.equal(rawConsumed, 50_000_000, 'five 9.8 MB reads plus the invalid 1 MB read exhaust the raw-byte budget');
			assert.equal(refreshed.hypotheses[6].evidenceFreshness, 'stale', 'later references fail closed after raw bytes are exhausted');
		} finally {await fs.rm(root, { recursive: true, force: true });}
	});

	test('recovers the highest committed generation regardless of backup filename order and preserves ambiguous generations', async () => {
		for (const scenario of ['ordered', 'conflict', 'corrupt'] as const) {
			const root = await testRoot(`backup-generation-${scenario}`);
			try {
				const directory = path.join(root, '.aqiron-security');
				await fs.mkdir(directory, { recursive: true });
				const target = path.join(directory, 'hypotheses.json');
				const older = { version: 1, scoringPolicyVersion: 1, generation: 2, updatedAt: '', hypotheses: [], snapshots: [] };
				const newer = { version: 1, scoringPolicyVersion: 1, generation: 7, updatedAt: '', hypotheses: [], snapshots: [] };
				await fs.writeFile(`${target}.999999.ff.bak`, JSON.stringify(older));
				await fs.writeFile(`${target}.000001.aa.bak`, JSON.stringify(newer));
				if (scenario === 'conflict') {await fs.writeFile(`${target}.000002.bb.bak`, JSON.stringify({ ...newer, updatedAt: '2026-10-20T00:00:00.000Z' }));}
				if (scenario === 'corrupt') {await fs.writeFile(`${target}.000002.bb.bak`, '{corrupt');}
				await fs.writeFile(`${target}.999999.zz.tmp`, JSON.stringify({ ...newer, generation: 99 }));
				const store = new HypothesisStoreService(createFileSystem());
				if (scenario === 'ordered') {assert.equal((await store.list(root)).generation, 7);}
				else {
					await assert.rejects(store.list(root), (error: unknown) => error instanceof Error && (error as NodeJS.ErrnoException).code === 'HYPOTHESIS_STORE_RECOVERY_REQUIRED');
					assert.equal(await fs.access(target).then(() => true).catch(() => false), false, 'ambiguous backups are not installed or discarded');
					assert.equal(await fs.access(`${target}.000002.bb.bak`).then(() => true).catch(() => false), true, 'corrupt or conflicting backups are preserved');
				}
			} finally {await fs.rm(root, { recursive: true, force: true });}
		}
	});

	test('recovers the newest committed generation after backup cleanup failures and ignores interrupted temporary generations', async () => {
		const root = await testRoot('backup-cleanup-failure');
		try {
			const filesystem = createFileSystem({ failBackupCleanup: true });
			const store = new HypothesisStoreService(filesystem);
			const hypothesis = await addCurrentTestProvenance(root, testHypothesis());
			await store.mergeGeneration(root, testSnapshot(root), [hypothesis], () => false);
			await store.review(root, { workspaceRoot: root, hypothesisId: hypothesis.id, action: 'investigate' });
			await store.review(root, { workspaceRoot: root, hypothesisId: hypothesis.id, action: 'dismiss' });
			const target = path.join(root, '.aqiron-security', 'hypotheses.json');
			const committed = await fs.readFile(target, 'utf8');
			const committedStore = JSON.parse(committed) as { generation: number; hypotheses: SecurityHypothesis[] };
			assert.equal(committedStore.generation, 3);
			await fs.writeFile(`${target}.000000.zz.tmp`, JSON.stringify({ ...committedStore, generation: 99 }));
			await fs.writeFile(`${target}.interrupted.aa.bak`, committed);
			await fs.unlink(target);
			const recovered = await store.list(root);
			assert.equal(recovered.generation, 3);
			assert.equal(recovered.hypotheses[0].status, 'dismissed');
			assert.ok(await fs.access(`${target}.000000.zz.tmp`).then(() => true).catch(() => false), 'uncommitted temporary data remains untouched');
		} finally {await fs.rm(root, { recursive: true, force: true });}
	});

	test('closes bounded raw-read handles after size rejection', async () => {
		const root = await testRoot('bounded-read-cleanup');
		try {
			const file = path.join(root, 'bounded.bin');
			await fs.writeFile(file, Buffer.from([0xff, 0xff]));
			const filesystem = createNodeFileSystem();
			await assert.rejects(filesystem.readFileBoundedBytes!(file, 1), (error: unknown) => (error as NodeJS.ErrnoException).code === 'FILE_TOO_LARGE');
			await fs.rename(file, `${file}.moved`);
			assert.equal((await fs.readFile(`${file}.moved`)).byteLength, 2);
		} finally {await fs.rm(root, { recursive: true, force: true });}
	});

	test('requires exact scan provenance, rejects missing spans, and bounds large files and line ranges', async () => {
		const root = await testRoot('scan-provenance-bounds');
		try {
			const file = path.join(root, 'large.ts');
			const observed = `OBSERVED_MARKER${'x'.repeat(10_000_001)}\n`;
			await fs.writeFile(file, observed);
			const finding = createFinding({ title: 'Observed', description: 'Observed issue', severity: 'Low', cwe: [], owasp: [], file, line: 1, column: 1, sourceTool: 'Aqiron', ruleId: 'test.rule', confidence: 'Low', remediation: 'Review', tags: [], rawEvidence: {} });
			const scan = await new NativeWorkspaceScanner(createFileSystem()).scanWorkspace(root, undefined, undefined, [testRule()]);
			assert.equal(scan.sourceProvenance?.length ?? 0, 0);
			assert.ok((scan.excludedProvenanceCount ?? 0) > 0);
			const missing = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'scan', findings: [finding], relationships: [], profile: createEmptyProjectProfile(root), filesystem: createFileSystem() });
			assert.equal(missing.findings.length, 0);
			assert.equal(missing.excludedUnprovenancedFindings, 1);
			assert.throws(() => hashSourceSpan('one line', 2, 2));
			assert.throws(() => hashSourceSpan(Array.from({ length: 21 }, () => 'x').join('\n'), 1, 21));
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('uses conservative, explainable confidence bands and monotonic contradiction handling', () => {
		const low = [{ kind: 'direct-evidence', value: 'verified-source-span', detail: 'direct' }, { kind: 'corroboration', value: 'multiple-source-families', detail: 'two' }, { kind: 'relationship', value: 'heuristic', detail: 'heuristic' }] as const;
		assert.equal(confidenceBand(low), 'low');
		assert.equal(confidenceBand([...low, { kind: 'relationship', value: 'explicit', detail: 'verified edge' }]), 'moderate');
		assert.equal(confidenceBand([...low, { kind: 'relationship', value: 'explicit', detail: 'verified edge' }, { kind: 'contradiction', value: 'present', detail: 'conflict' }]), 'low');
	});

	test('enforces lifecycle transitions and requires current supporting evidence to validate', async () => {
		assert.equal(transition('proposed', 'investigate'), 'investigating');
		assert.equal(transition('proposed', 'dismiss'), 'dismissed');
		assert.equal(transition('investigating', 'reject'), 'rejected');
		assert.throws(() => transition('validated', 'reopen'), /Cannot reopen/);
		const root = await testRoot('review');
		try {
			const source = 'const reviewed = true;\n';
			await fs.writeFile(path.join(root, 'reviewed.ts'), source);
			const service = new HypothesisStoreService(createFileSystem());
			const sourceSpan = { id: 'span:current', kind: 'source-span' as const, source: 'Core', file: 'reviewed.ts', startLine: 1, endLine: 1, contentHash: hashSourceSpan(source, 1, 1), fileContentHash: hashSourceContent(source), findingId: 'test', observedAt: '2026-01-01T00:00:00.000Z', freshness: 'current' as const };
			const hypothesis = { ...testHypothesis(), evidence: [sourceSpan] };
			await service.mergeGeneration(root, testSnapshot(root), [hypothesis], () => false);
			await assert.rejects(service.review(root, { workspaceRoot: root, hypothesisId: hypothesis.id, action: 'validate' }), /requires at least one current/);
			const validated = await service.review(root, { workspaceRoot: root, hypothesisId: hypothesis.id, action: 'validate', evidenceRefs: [hypothesis.evidence[0].id] });
			assert.equal(validated.applied, true);
			assert.equal(validated.hypothesis.status, 'validated');
			assert.equal(validated.hypothesis.review?.action, 'validate');
			assert.deepEqual(validated.hypothesis.review?.evidenceRefs, [sourceSpan.id]);
			assert.equal('finding' in validated.hypothesis, false);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('rejects an oversized hypotheses store using a bounded read and preserves it', async () => {
		const root = await testRoot('oversized-store');
		try {
			const file = path.join(root, '.aqiron-security', 'hypotheses.json');
			await fs.mkdir(path.dirname(file), { recursive: true });
			await fs.writeFile(file, 'x'.repeat(5_000_001));
			const store = new HypothesisStoreService(createFileSystem());
			await assert.rejects(store.list(root), (error: unknown) => error instanceof HypothesisStoreError && /5 MB safety limit/.test(error.message));
			assert.equal((await fs.stat(file)).size, 5_000_001);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('bounds freshness reads and deduplicates repeated source paths', async () => {
		const root = await testRoot('freshness-bounds');
		try {
			const file = path.join(root, 'source.ts');
			const content = 'same source\n';
			await fs.writeFile(file, content);
			const sourceHash = hashSourceContent(content);
			const spanHash = hashSourceSpan(content, 1, 1);
			const storeFile = path.join(root, '.aqiron-security', 'hypotheses.json');
			await fs.mkdir(path.dirname(storeFile), { recursive: true });
			const hypotheses = Array.from({ length: 8 }, (_, index) => {
				const hypothesis = testHypothesis();
				const evidence = { id: `span:${index}`, kind: 'source-span' as const, source: 'Core', file: 'source.ts', startLine: 1, endLine: 1, contentHash: spanHash, fileContentHash: sourceHash, findingId: `finding-${index}`, observedAt: hypothesis.createdAt, freshness: 'current' as const };
				return { ...hypothesis, id: `hyp:fresh-${index}`, evidence: [evidence] };
			});
			await fs.writeFile(storeFile, JSON.stringify({ version: 1, scoringPolicyVersion: 1, updatedAt: '', hypotheses, snapshots: [] }));
			let boundedReads = 0;
			const filesystem = createFileSystem({ beforeBoundedRead: async (readPath) => { if (path.resolve(readPath) === path.resolve(file)) {boundedReads += 1;} } });
			const refreshed = await new HypothesisStoreService(filesystem).list(root);
			assert.equal(boundedReads, 1, 'same source path is read once for all source-span references');
			assert.ok(refreshed.hypotheses.every((hypothesis) => hypothesis.evidenceFreshness !== 'stale'));
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('deduplicates freshness reads for Windows paths that differ only by casing', async function () {
		if (process.platform !== 'win32') { this.skip(); }
		const root = await testRoot('freshness-windows-case');
		try {
			const file = path.join(root, 'src', 'File.ts');
			const content = 'same source\n';
			await fs.mkdir(path.dirname(file), { recursive: true });
			await fs.writeFile(file, content);
			const sourceHash = hashSourceContent(content);
			const spanHash = hashSourceSpan(content, 1, 1);
			const base = testHypothesis();
			const hypothesis = {
				...base,
				evidence: [
					{ id: 'span:lower', kind: 'source-span' as const, source: 'Core', file: 'src/File.ts', startLine: 1, endLine: 1, contentHash: spanHash, fileContentHash: sourceHash, findingId: 'finding-lower', observedAt: base.createdAt, freshness: 'current' as const },
					{ id: 'span:upper', kind: 'source-span' as const, source: 'Core', file: 'SRC/FILE.TS', startLine: 1, endLine: 1, contentHash: spanHash, fileContentHash: sourceHash, findingId: 'finding-upper', observedAt: base.createdAt, freshness: 'current' as const },
				],
			};
			const storeFile = path.join(root, '.aqiron-security', 'hypotheses.json');
			await fs.mkdir(path.dirname(storeFile), { recursive: true });
			await fs.writeFile(storeFile, JSON.stringify({ version: 1, scoringPolicyVersion: 1, updatedAt: '', hypotheses: [hypothesis], snapshots: [] }));
			let reads = 0;
			const filesystem = createFileSystem({ beforeBoundedRead: async (readPath) => {
				if (path.resolve(readPath).toLowerCase() === path.resolve(file).toLowerCase()) { reads += 1; }
			} });
			const refreshed = await new HypothesisStoreService(filesystem).list(root);
			assert.equal(reads, 1, 'case variants resolve to one bounded freshness read');
			assert.deepEqual(refreshed.hypotheses[0]?.evidence.map((ref) => ref.freshness), ['current', 'current']);
			assert.notEqual(refreshed.hypotheses[0]?.evidenceFreshness, 'stale');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('serializes large freshness reads and enforces the aggregate byte budget', async () => {
		const root = await testRoot('freshness-aggregate-budget');
		try {
			const content = `${'A'.repeat(100)}\n`.repeat(90_000);
			const sourceHash = hashSourceContent(content);
			const spanHash = hashSourceSpan(content, 1, 1);
			const hypotheses: SecurityHypothesis[] = [];
			const sourceFiles: string[] = [];
			for (let index = 0; index < 6; index += 1) {
				const relative = `large-${index}.ts`;
				const file = path.join(root, relative);
				sourceFiles.push(path.resolve(file));
				await fs.writeFile(file, content);
				const base = testHypothesis();
				const ref = { id: `span-large-${index}`, kind: 'source-span' as const, source: 'Core', file: relative, startLine: 1, endLine: 1, contentHash: spanHash, fileContentHash: sourceHash, findingId: `finding-large-${index}`, observedAt: base.createdAt, freshness: 'current' as const };
				hypotheses.push({ ...base, id: `hyp:large-${index}`, evidence: [ref] });
			}
			const storeFile = path.join(root, '.aqiron-security', 'hypotheses.json');
			await fs.mkdir(path.dirname(storeFile), { recursive: true });
			await fs.writeFile(storeFile, JSON.stringify({ version: 1, scoringPolicyVersion: 1, updatedAt: '', hypotheses, snapshots: [] }));
			let activeReads = 0, maxActiveReads = 0;
			const filesystem = createFileSystem({ beforeBoundedRead: async (file) => {
				if (!sourceFiles.includes(path.resolve(file))) {return;}
				activeReads += 1; maxActiveReads = Math.max(maxActiveReads, activeReads);
				await new Promise((resolve) => setTimeout(resolve, 10));
				activeReads -= 1;
			} });
			const refreshed = await new HypothesisStoreService(filesystem).list(root);
			assert.equal(maxActiveReads, 1, 'freshness reads are sequential across hypotheses');
			assert.equal(refreshed.hypotheses.filter((item) => item.evidenceFreshness === 'stale').length, 1, 'the final file exceeds the 50 MB aggregate freshness budget and fails closed');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('retains validation history while exposing changed and deleted evidence as stale', async () => {
		for (const remove of [false, true]) {
			const root = await testRoot(remove ? 'validated-deleted' : 'validated-changed');
			try {
				const source = 'const observed = true;\nconst unrelated = true;\n';
				const file = path.join(root, 'src.ts');
				await fs.writeFile(file, source);
				const finding = createFinding({ title: 'Observed', description: 'Observed issue', severity: 'Low', cwe: [], owasp: [], file, line: 1, column: 1, sourceTool: 'Aqiron', ruleId: 'test.rule', confidence: 'Low', remediation: 'Review', tags: [], rawEvidence: {} });
				const snapshot = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'scan', findings: [finding], relationships: [], profile: createEmptyProjectProfile(root), filesystem: createFileSystem(), scanProvenance: makeProvenance(finding, root, source) });
				const span = snapshot.evidence.find((ref) => ref.kind === 'source-span')!;
				const hypothesis = { ...testHypothesis(), evidence: [span], snapshotId: snapshot.id };
				const store = new HypothesisStoreService(createFileSystem());
				await store.mergeGeneration(root, snapshot, [hypothesis], () => false);
				await store.review(root, { workspaceRoot: root, hypothesisId: hypothesis.id, action: 'validate', evidenceRefs: [span.id] });
				if (remove) { await fs.unlink(file); } else { await fs.writeFile(file, 'const observed = true;\nconst unrelated = false;\n'); }
				const listed = (await store.list(root)).hypotheses[0];
				assert.equal(listed.status, 'validated');
				assert.equal(listed.evidenceFreshness, 'stale');
				assert.equal(listed.evidence[0].freshness, 'stale');
				assert.equal(listed.review?.action, 'validate');
				const reviewed = await store.review(root, { workspaceRoot: root, hypothesisId: hypothesis.id, action: 'validate', evidenceRefs: [span.id] });
				assert.equal(reviewed.applied, false);
				assert.equal(reviewed.diagnostic, 'stale-evidence');
				assert.equal(reviewed.hypothesis.evidenceFreshness, 'stale');
				const runtime = new CoreRuntime({ coreVersion: 'test' });
				const listedResponse = await runtime.handle({ id: 'hyp-stale-list', type: 'request', method: 'hypotheses.list', params: { workspaceRoot: root, status: 'validated' } }, () => undefined);
				assert.equal(((listedResponse.result as { hypotheses: SecurityHypothesis[] }).hypotheses[0]).evidenceFreshness, 'stale');
				const fetchedResponse = await runtime.handle({ id: 'hyp-stale-get', type: 'request', method: 'hypotheses.get', params: { workspaceRoot: root, hypothesisId: hypothesis.id } }, () => undefined);
				assert.equal((fetchedResponse.result as { hypothesis: SecurityHypothesis }).hypothesis.evidenceFreshness, 'stale');
				const reviewResponse = await runtime.handle({ id: 'hyp-stale-review', type: 'request', method: 'hypotheses.review', params: { workspaceRoot: root, hypothesisId: hypothesis.id, action: 'validate', evidenceRefs: [span.id] } }, () => undefined);
				assert.equal((reviewResponse.result as { applied: boolean; diagnostic: string; hypothesis: SecurityHypothesis }).applied, false);
				assert.equal((reviewResponse.result as { applied: boolean; diagnostic: string; hypothesis: SecurityHypothesis }).diagnostic, 'stale-evidence');
			} finally { await fs.rm(root, { recursive: true, force: true }); }
		}
	});

	test('legacy finding-only hypotheses remain readable but cannot be reviewed without source provenance', async () => {
		for (const outcome of ['changed', 'missing'] as const) {
			const root = await testRoot(`legacy-provenance-${outcome}`);
			try {
				const sourcePath = path.join(root, 'legacy.ts');
				await fs.writeFile(sourcePath, 'const oldValue = true;\n');
				const legacy = {
					...testHypothesis(),
					evidence: [{ ...testHypothesis().evidence[0]!, file: 'legacy.ts', startLine: 1, endLine: 1 }],
				};
				const directory = path.join(root, '.aqiron-security');
				await fs.mkdir(directory, { recursive: true });
				const storePath = path.join(directory, 'hypotheses.json');
				await fs.writeFile(storePath, JSON.stringify({ version: 1, scoringPolicyVersion: 1, updatedAt: '', hypotheses: [legacy], snapshots: [] }));
				if (outcome === 'changed') {await fs.writeFile(sourcePath, 'const newValue = false;\n');} else {await fs.unlink(sourcePath);}
				const service = new HypothesisStoreService(createFileSystem());
				const listed = (await service.list(root)).hypotheses[0]!;
				assert.equal(listed.evidenceFreshness, 'provenance-unavailable');
				assert.equal(listed.status, 'stale');
				assert.equal(listed.evidence[0]?.freshness, 'stale');
				const runtime = new CoreRuntime({ coreVersion: 'legacy-provenance-test' });
				const fetched = await runtime.handle({ id: 'legacy-get', type: 'request', method: 'hypotheses.get', params: { workspaceRoot: root, hypothesisId: legacy.id } }, () => undefined);
				const fetchedHypothesis = (fetched.result as { hypothesis: SecurityHypothesis }).hypothesis;
				assert.equal(fetchedHypothesis.evidenceFreshness, 'provenance-unavailable');
				for (const action of ['validate', 'reject'] as const) {
					const reviewed = await service.review(root, { workspaceRoot: root, hypothesisId: legacy.id, action, evidenceRefs: [legacy.evidence[0]!.id] });
					assert.equal(reviewed.applied, false);
					assert.equal(reviewed.diagnostic, 'provenance-unavailable');
					assert.equal(reviewed.hypothesis.status, 'stale');
				}
			} finally {await fs.rm(root, { recursive: true, force: true });}
		}
	});

	test('legacy validated hypotheses keep their review history while exposing unavailable provenance', async () => {
		const root = await testRoot('legacy-validated-provenance');
		try {
			const legacy = { ...testHypothesis(), status: 'validated' as const, evidence: [{ ...testHypothesis().evidence[0]!, file: 'missing.ts', startLine: 1, endLine: 1 }], review: { at: '2026-01-01T00:00:00.000Z', action: 'validate' as const, evidenceRefs: ['finding:test'] } };
			const directory = path.join(root, '.aqiron-security');
			await fs.mkdir(directory, { recursive: true });
			await fs.writeFile(path.join(directory, 'hypotheses.json'), JSON.stringify({ version: 1, scoringPolicyVersion: 1, updatedAt: '', hypotheses: [legacy], snapshots: [] }));
			const hypothesis = (await new HypothesisStoreService(createFileSystem()).list(root)).hypotheses[0]!;
			assert.equal(hypothesis.status, 'validated');
			assert.equal(hypothesis.evidenceFreshness, 'provenance-unavailable');
			assert.equal(hypothesis.evidence[0]?.freshness, 'stale');
			assert.equal(hypothesis.review?.action, 'validate');
		} finally {await fs.rm(root, { recursive: true, force: true });}
	});

	test('source-span evidence without a full-file hash stays stale and cannot be reviewed', async () => {
		const root = await testRoot('missing-file-hash');
		try {
			const source = 'const observed = true;\n';
			await fs.writeFile(path.join(root, 'source.ts'), source);
			const makeIncomplete = (id: string, status: SecurityHypothesis['status']) => {
				const base = testHypothesis();
				return {
					...base,
					id,
					status,
					evidence: [{ id: `span:${id}`, kind: 'source-span' as const, source: 'Core', file: 'source.ts', startLine: 1, endLine: 1, contentHash: hashSourceSpan(source, 1, 1), findingId: `finding:${id}`, observedAt: base.createdAt, freshness: 'current' as const }],
					...(status === 'validated' ? { review: { at: base.updatedAt, action: 'validate' as const, evidenceRefs: [`span:${id}`] } } : {}),
				};
			};
			const proposed = makeIncomplete('hyp:missing-file-hash-proposed', 'proposed');
			const historical = makeIncomplete('hyp:missing-file-hash-validated', 'validated');
			const storeFile = path.join(root, '.aqiron-security', 'hypotheses.json');
			await fs.mkdir(path.dirname(storeFile), { recursive: true });
			await fs.writeFile(storeFile, JSON.stringify({ version: 1, scoringPolicyVersion: 1, updatedAt: '', hypotheses: [proposed, historical], snapshots: [] }));

			const service = new HypothesisStoreService(createFileSystem());
			const listed = await service.list(root);
			const staleProposed = listed.hypotheses.find((item) => item.id === proposed.id)!;
			const staleHistorical = listed.hypotheses.find((item) => item.id === historical.id)!;
			assert.equal(staleProposed.status, 'stale');
			assert.equal(staleProposed.evidenceFreshness, 'stale');
			assert.equal(staleProposed.evidence[0]?.freshness, 'stale');
			assert.equal(staleHistorical.status, 'validated', 'historical lifecycle state is retained');
			assert.equal(staleHistorical.evidenceFreshness, 'stale');
			assert.equal(staleHistorical.review?.action, 'validate');

			const runtime = new CoreRuntime({ coreVersion: 'missing-file-hash-test' });
			const listResponse = await runtime.handle({ id: 'missing-hash-list', type: 'request', method: 'hypotheses.list', params: { workspaceRoot: root, includeStale: true } }, () => undefined);
			const runtimeList = (listResponse.result as { hypotheses: SecurityHypothesis[] }).hypotheses;
			assert.equal(runtimeList.find((item) => item.id === proposed.id)?.evidenceFreshness, 'stale');
			const getResponse = await runtime.handle({ id: 'missing-hash-get', type: 'request', method: 'hypotheses.get', params: { workspaceRoot: root, hypothesisId: historical.id } }, () => undefined);
			const fetched = (getResponse.result as { hypothesis: SecurityHypothesis }).hypothesis;
			assert.equal(fetched.status, 'validated');
			assert.equal(fetched.evidenceFreshness, 'stale');
			assert.equal(fetched.review?.action, 'validate');
			for (const action of ['validate', 'reject'] as const) {
				const result = await service.review(root, { workspaceRoot: root, hypothesisId: proposed.id, action, evidenceRefs: [proposed.evidence[0]!.id] });
				assert.equal(result.applied, false);
				assert.equal(result.diagnostic, 'stale-evidence');
			}
			const stillHistorical = (await service.list(root)).hypotheses.find((item) => item.id === historical.id)!;
			assert.equal(stillHistorical.status, 'validated');
			assert.equal(stillHistorical.review?.action, 'validate');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('indexes source lines once and preserves span hashes for line endings, Unicode, and large distinct spans', () => {
		for (const [content, start, end, expected] of [
			['alpha\r\nbeta\n\nend', 1, 2, 'alpha\nbeta'],
			['alpha\nbeta', 2, 2, 'beta'],
			['a\rb', 1, 1, 'a\rb'],
			['\n雪\n', 2, 2, '雪'],
			['tail-without-newline', 1, 1, 'tail-without-newline'],
		] as const) {
			const expectedHash = crypto.createHash('sha256').update(expected, 'utf8').digest('hex');
			assert.equal(createSourceLineIndex(content).hashSpan(start, end), expectedHash);
		}
		assert.equal(hashSourceContent('alpha\r\nbeta'), crypto.createHash('sha256').update('alpha\r\nbeta', 'utf8').digest('hex'), 'full-file hashing retains original CRLF');
		assert.throws(() => createSourceLineIndex('one').hashSpan(2, 2));
		assert.throws(() => createSourceLineIndex('one').hashSpan(0, 1));

		const content = Array.from({ length: 12_000 }, (_, index) => 'line-' + index + '-' + 'x'.repeat(680)).join('\n');
		const referenceLines = content.split(/\r?\n/);
		const originalSplit = String.prototype.split;
		let wholeFileIndexBuilds = 0;
		const instrumented = String.prototype as unknown as { split: (this: string, separator?: string | RegExp, limit?: number) => string[] };
		instrumented.split = function (this: string, separator?: string | RegExp, limit?: number): string[] {
			if (this === content && separator instanceof RegExp && separator.source === '\\r?\\n') {wholeFileIndexBuilds += 1;}
			return Reflect.apply(originalSplit, this, [separator, limit]) as string[];
		};
		try {
			const index = createSourceLineIndex(content);
			assert.equal(index.lineCount, 12_000);
			for (let line = 1; line <= 2_000; line += 1) {
				const expected = referenceLines[line - 1]!;
				assert.equal(index.hashSpan(line, line), crypto.createHash('sha256').update(expected, 'utf8').digest('hex'));
			}
			assert.equal(wholeFileIndexBuilds, 1, 'one reusable line index serves every distinct span');
		} finally {instrumented.split = originalSplit as typeof instrumented.split;}
	});

	test('builds one source line index per file during snapshot construction with many distinct spans', async () => {
		const root = await testRoot('snapshot-line-index-once');
		const sourcePath = path.join(root, 'many-spans.ts');
		const lines = Array.from({ length: 128 }, (_, index) => `const observed${index} = ${index};`);
		const content = `${lines.join('\n')}\n`;
		try {
			await fs.writeFile(sourcePath, content);
			const findings = lines.map((_, index) => createFinding({ title: `Observed ${index}`, description: 'Observed test evidence', severity: 'Low', cwe: [], owasp: [], file: sourcePath, line: index + 1, column: 1, sourceTool: 'Aqiron', ruleId: `test.observed.${index}`, confidence: 'Low', remediation: 'Review', tags: [], rawEvidence: {}, fingerprint: `snapshot-test-${index}` }));
			const scanProvenance = findings.flatMap((finding) => makeProvenance(finding, root, content));
			const mutableProvenance = sourceProvenance as unknown as { createSourceLineIndex: typeof createSourceLineIndex };
			const originalCreateIndex = mutableProvenance.createSourceLineIndex;
			let indexBuilds = 0;
			mutableProvenance.createSourceLineIndex = (source: string) => { indexBuilds += 1; return originalCreateIndex(source); };
			try {
				const snapshot = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'many-spans', findings, relationships: [], profile: createEmptyProjectProfile(root), filesystem: createFileSystem(), scanProvenance });
				assert.equal(indexBuilds, 1, 'snapshot construction indexes the source file once, not once per distinct span');
				const sourceSpans = snapshot.evidence.filter((ref) => ref.kind === 'source-span');
				assert.equal(sourceSpans.length, lines.length);
				assert.ok(sourceSpans.every((ref) => ref.freshness === 'current' && ref.fileContentHash === hashSourceContent(content)));
				for (const ref of sourceSpans) {
					const expected = crypto.createHash('sha256').update(lines[ref.startLine! - 1]!, 'utf8').digest('hex');
					assert.equal(ref.contentHash, expected, `span ${ref.startLine} retains the inclusive line hash`);
				}

				await fs.writeFile(sourcePath, `${lines.join('\n')}\n// changed after scan\n`);
				const changedSnapshot = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'many-spans-changed', findings, relationships: [], profile: createEmptyProjectProfile(root), filesystem: createFileSystem(), scanProvenance });
				assert.equal(indexBuilds, 2, 'the changed-source snapshot also builds exactly one index for its file');
				assert.equal(changedSnapshot.evidence.filter((ref) => ref.kind === 'source-span').length, 0, 'changed full-file content fails freshness validation');
				assert.equal(changedSnapshot.excludedUnprovenancedFindings, findings.length);
			} finally { mutableProvenance.createSourceLineIndex = originalCreateIndex; }
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('caps native scan provenance at the configured record count', async () => {
		const root = await testRoot('provenance-record-cap');
		try {
			await fs.writeFile(path.join(root, 'many.ts'), 'OBSERVED_MARKER\n');
			const rules = Array.from({ length: 10_001 }, (_, index) => ({ ...testRule(), id: `test.observed.${index}` }));
			const scan = await new NativeWorkspaceScanner(createFileSystem()).scanWorkspace(root, undefined, undefined, rules);
			assert.equal(scan.sourceProvenance?.length, 10_000);
			assert.equal(scan.excludedProvenanceCount, 1);
		} finally {await fs.rm(root, { recursive: true, force: true });}
	});

	test('persists atomically, preserves triage on regeneration, serializes concurrent updates, and protects corrupt stores', async () => {
		const root = await testRoot('store');
		try {
			const service = new HypothesisStoreService(createFileSystem());
			assert.equal((await service.list(root)).hypotheses.length, 0);
			const hypothesis = await addCurrentTestProvenance(root, testHypothesis());
			const snapshot = testSnapshot(root);
			await service.mergeGeneration(root, snapshot, [hypothesis], () => false);
			await service.review(root, { workspaceRoot: root, hypothesisId: hypothesis.id, action: 'investigate' });
			await Promise.all([
				service.review(root, { workspaceRoot: root, hypothesisId: hypothesis.id, action: 'dismiss' }).catch(() => undefined),
				service.mergeGeneration(root, { ...snapshot, id: 'snapshot:next', fingerprint: 'b'.repeat(64) }, [hypothesis], () => false),
			]);
			const reloaded = await service.list(root);
			assert.equal(reloaded.hypotheses[0].status, 'dismissed');
			assert.ok(reloaded.snapshots.length <= 20);
			const file = path.join(root, '.aqiron-security', 'hypotheses.json');
			assert.ok(!(await fs.readFile(file, 'utf8')).includes('excerpt'));
			const crashBackup = `${file}.simulated-crash.bak`;
			await fs.rename(file, crashBackup);
			assert.equal((await service.list(root)).hypotheses[0].status, 'dismissed');
			assert.equal(await fs.access(file).then(() => true).catch(() => false), true);
			const beforeFailedWrite = await fs.readFile(file, 'utf8');
			const failedService = new HypothesisStoreService(createFileSystem({ failRenameAt: 2 }));
			await assert.rejects(failedService.mergeGeneration(root, { ...snapshot, id: 'snapshot:failed' }, [], () => false));
			assert.equal(await fs.readFile(file, 'utf8'), beforeFailedWrite);
			assert.equal((await fs.readdir(path.dirname(file))).some((name) => String(name).endsWith('.tmp')), false, 'failed replacement removes only its own temporary file');
			assert.equal((await service.list(root)).hypotheses[0].status, 'dismissed', 'a failed write releases both process-local and cross-process locks');
			const otherRoot = await testRoot('isolated');
			try { assert.equal((await service.list(otherRoot)).hypotheses.length, 0); } finally { await fs.rm(otherRoot, { recursive: true, force: true }); }
			await fs.writeFile(file, '{broken');
			await assert.rejects(service.mergeGeneration(root, snapshot, [], () => false), (error: unknown) => error instanceof HypothesisStoreError);
			assert.equal(await fs.readFile(file, 'utf8'), '{broken');
			await fs.writeFile(file, JSON.stringify({ version: 99, hypotheses: [], snapshots: [] }));
			await assert.rejects(service.list(root), (error: unknown) => error instanceof HypothesisStoreError);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('runtime rejects generation without a completed same-project Core scan and validates request arguments', async () => {
		const root = await testRoot('runtime');
		try {
			const runtime = new CoreRuntime({ coreVersion: 'test' });
			const response = await runtime.handle({ id: 'hyp-no-evidence', type: 'request', method: 'hypotheses.generate', params: { workspaceRoot: root, scanId: 'missing-scan' } }, () => undefined);
			assert.equal(response.success, true);
			assert.equal((response.result as { status: string }).status, 'no-evidence');
			const invalid = await runtime.handle({ id: 'hyp-invalid', type: 'request', method: 'hypotheses.review', params: { workspaceRoot: root, hypothesisId: 'hyp:x', action: 'set-status', status: 'validated' } }, () => undefined);
			assert.equal(invalid.success, false);
			assert.equal(invalid.error?.code, 'CORE_INVALID_REQUEST');
			for (const params of [
				{ workspaceRoot: ' ', scanId: 'scan' },
				{ workspaceRoot: root, scanId: 's'.repeat(129) },
				{ workspaceRoot: `${root}${'x'.repeat(4097)}`, scanId: 'scan' },
				{ workspaceRoot: `${root}\0suffix`, scanId: 'scan' },
			]) {
				const bounded = await runtime.handle({ id: 'hyp-bounds', type: 'request', method: 'hypotheses.generate', params }, () => undefined);
				assert.equal(bounded.success, false);
				assert.equal(bounded.error?.code, 'CORE_INVALID_REQUEST');
			}
			for (const scanId of ['scan.v1-abc_123:xyz', 's'.repeat(128)]) {
				const accepted = await runtime.handle({ id: 'hyp-bounds-ok', type: 'request', method: 'hypotheses.generate', params: { workspaceRoot: root, scanId } }, () => undefined);
				assert.equal(accepted.success, true);
			}
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('generation consumes an existing scan without invoking AI or launching another scan', async () => {
		const root = await testRoot('existing-scan');
		let aiCalls = 0;
		try {
			await fs.writeFile(path.join(root, 'sample.ts'), 'const API_KEY = "AKIA1234567890ABCDEF";\n');
			const aiTransport: AITransport = { request: async () => { aiCalls += 1; throw new Error('AI must not be called.'); } };
			const runtime = new CoreRuntime({ coreVersion: 'test', aiTransport });
			const scan = await runtime.handle({ id: 'hyp-phase1-scan', type: 'request', method: 'scan.start', params: { workspaceRoot: root, trusted: true, mode: 'quick', includeExternalScanners: false } }, () => undefined);
			assert.equal(scan.success, true, scan.error?.message);
			const scanResult = scan.result as { scanId: string; findings: unknown[] };
			assert.equal('sourceProvenance' in scanResult, false, 'scan protocol response remains unchanged');
			const generationEvents: unknown[] = [];
			const generation = await runtime.handle({ id: 'hyp-phase1-generation', type: 'request', method: 'hypotheses.generate', params: { workspaceRoot: root, scanId: scanResult.scanId } }, (event) => generationEvents.push(event));
			assert.equal(generation.success, true, generation.error?.message);
			const result = generation.result as { status: string; scanId: string };
			assert.equal(result.scanId, scanResult.scanId);
			assert.ok(['generated', 'no-evidence'].includes(result.status));
			assert.equal(aiCalls, 0);
			assert.equal(generationEvents.length, 0);
			assert.equal((await fs.stat(path.join(root, '.aqiron-security', 'hypotheses.json'))).isFile(), true);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('runtime dispatch builds and persists an evidence-backed candidate from retained Core scan data', async () => {
		const root = await testRoot('runtime-candidate');
		let aiCalls = 0;
		try {
			await fs.mkdir(path.join(root, 'src'), { recursive: true });
			await fs.writeFile(path.join(root, 'src', 'indicator.txt'), 'malware-indicator\n');
			await fs.writeFile(path.join(root, 'src', 'mobile.apk'), 'artifact-signature\n');
			const findings = [
				createFinding({ title: 'Malware indicator', description: 'Indicator matched', severity: 'High', cwe: [], owasp: [], file: path.join(root, 'src', 'indicator.txt'), line: 1, column: 1, sourceTool: 'MobSF', ruleId: 'mobsf.indicator', confidence: 'Medium', remediation: 'Review', tags: ['malware'], rawEvidence: { secret: 'never-store' } }),
				createFinding({ title: 'Mobile artifact signal', description: 'Artifact flagged', severity: 'Low', cwe: [], owasp: [], file: path.join(root, 'src', 'mobile.apk'), line: 1, column: 1, sourceTool: 'Trivy', ruleId: 'trivy.artifact', confidence: 'Low', remediation: 'Review', tags: ['artifact'], rawEvidence: { secret: 'never-store' } }),
			];
			const relationship: CorrelatedRelationship = { sourceId: findings[0].id, targetId: findings[1].id, type: 'malware-to-artifact', weight: 0.75, reason: 'correlation heuristic' };
			const aiTransport: AITransport = { request: async () => { aiCalls += 1; throw new Error('AI must not be called.'); } };
			const runtime = new CoreRuntime({ coreVersion: 'test', aiTransport });
			const scanId = 'retained-core-scan';
			const internal = runtime as unknown as { scans: Map<string, { result: { state: { finalState: string; workspaceRoot: string; completedAt: string }; findings: typeof findings; correlation: { relationships: CorrelatedRelationship[] } }; sourceProvenance: FindingSourceProvenance[] }> };
			internal.scans.set(scanId, { result: { state: { finalState: 'completed', workspaceRoot: root, completedAt: '2026-10-20T00:00:00.000Z' }, findings, correlation: { relationships: [relationship] } }, sourceProvenance: [...makeProvenance(findings[0], root, 'malware-indicator\n'), ...makeProvenance(findings[1], root, 'artifact-signature\n')] });
			const response = await runtime.handle({ id: 'hyp-runtime-candidate', type: 'request', method: 'hypotheses.generate', params: { workspaceRoot: root, scanId } }, () => undefined);
			assert.equal(response.success, true, response.error?.message);
			const result = response.result as { status: string; hypotheses: Array<{ status: string; confidence: { band: string } }> };
			assert.equal(result.status, 'generated');
			assert.equal(result.hypotheses.length, 1);
			const persisted = await fs.readFile(path.join(root, '.aqiron-security', 'hypotheses.json'), 'utf8');
			assert.ok(!persisted.includes('never-store'));
			assert.equal(aiCalls, 0);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('fails closed when the retained scan record has no source provenance', async () => {
		const root = await testRoot('scan-source-change');
		try {
			const file = path.join(root, 'src', 'indicator.txt');
			await fs.mkdir(path.dirname(file), { recursive: true });
			await fs.writeFile(file, 'before scan evidence\n');
			const finding = createFinding({ title: 'Malware indicator', description: 'Indicator matched', severity: 'High', cwe: [], owasp: [], file, line: 1, column: 1, sourceTool: 'MobSF', ruleId: 'mobsf.indicator', confidence: 'Medium', remediation: 'Review', tags: ['malware'], rawEvidence: {} });
			const runtime = new CoreRuntime({ coreVersion: 'test' });
			const scanId = 'scan-source-change';
			const internal = runtime as unknown as { scans: Map<string, { result: { state: { finalState: string; workspaceRoot: string; completedAt: string }; findings: typeof finding[]; correlation: { relationships: CorrelatedRelationship[] } } }> };
			internal.scans.set(scanId, { result: { state: { finalState: 'completed', workspaceRoot: root, completedAt: '2026-10-20T00:00:00.000Z' }, findings: [finding], correlation: { relationships: [] } } });
			await fs.writeFile(file, 'after scan evidence\n');
			const response = await runtime.handle({ id: 'hyp-scan-source-change', type: 'request', method: 'hypotheses.generate', params: { workspaceRoot: root, scanId } }, () => undefined);
			assert.equal(response.success, true);
			assert.equal((response.result as { status: string }).status, 'no-evidence');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('rejects symlinked store, backup, lock, and source paths', async () => {
		const root = await testRoot('symlink');
		const outside = await testRoot('symlink-outside');
		try {
			if (process.platform === 'win32') {
				const outsideStore = path.join(outside, 'hypotheses.json');
				await fs.writeFile(outsideStore, '{"external":true}');
				const storeDirectory = path.join(root, '.aqiron-security');
				await fs.mkdir(storeDirectory);
				await assert.rejects(new HypothesisStoreService(createFileSystem({ symlinkPaths: [storeDirectory] })).list(root));
				const backupPath = path.join(storeDirectory, 'hypotheses.json.1.abc.bak');
				await assert.rejects(fs.lstat(backupPath));
				await assert.doesNotReject(new HypothesisStoreService(createFileSystem({ symlinkPaths: [backupPath] })).list(root));
				const lockPath = `${path.join(storeDirectory, 'hypotheses.json')}.lock`;
				await fs.rm(lockPath, { recursive: true, force: true });
				await fs.mkdir(lockPath);
				await assert.rejects(new HypothesisStoreService(createFileSystem({ symlinkPaths: [lockPath] })).list(root));
				await fs.rm(lockPath, { recursive: true, force: true });
				await fs.mkdir(path.join(root, 'linked-source'));
				const source = path.join(root, 'linked-source', 'external.ts');
				await fs.writeFile(source, 'const outside = true;\n');
				const finding = createFinding({ title: 'Observed', description: 'Observed issue', severity: 'Low', cwe: [], owasp: [], file: source, line: 1, column: 1, sourceTool: 'Aqiron', ruleId: 'test.rule', confidence: 'Low', remediation: 'Review', tags: [], rawEvidence: {} });
				const snapshot = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'scan', findings: [finding], relationships: [], profile: createEmptyProjectProfile(root), filesystem: createFileSystem({ symlinkPaths: [path.join(root, 'linked-source')] }), scanProvenance: makeProvenance(finding, root, 'const outside = true;\n') });
				assert.equal(snapshot.findings.length, 0);
				assert.equal(await fs.readFile(outsideStore, 'utf8'), '{"external":true}');
				return;
			}
			const service = new HypothesisStoreService(createFileSystem());
			const outsideStore = path.join(outside, 'hypotheses.json');
			await fs.writeFile(outsideStore, '{"external":true}');
			await fs.symlink(outside, path.join(root, '.aqiron-security'), 'dir');
			await assert.rejects(service.list(root));
			assert.equal(await fs.readFile(outsideStore, 'utf8'), '{"external":true}');
			await fs.unlink(path.join(root, '.aqiron-security'));
			await fs.mkdir(path.join(root, '.aqiron-security'));
			const tempSymlink = path.join(root, '.aqiron-security', 'hypotheses.json.attack.tmp');
			await fs.symlink(outsideStore, tempSymlink);
			await assert.rejects(createFileSystem().writeFileExclusive!(tempSymlink, 'overwrite', 'utf8'));
			assert.equal(await fs.readFile(outsideStore, 'utf8'), '{"external":true}');
			await fs.symlink(outside, path.join(root, '.aqiron-security', 'hypotheses.json.1.abc.bak'), 'dir');
			assert.equal((await service.list(root)).hypotheses.length, 0);
			await fs.symlink(outside, `${path.join(root, '.aqiron-security', 'hypotheses.json')}.lock`, 'dir');
			await assert.rejects(service.list(root));
			await fs.writeFile(path.join(outside, 'external.ts'), 'const outside = true;\n');
			const linkedDir = path.join(root, 'linked-source');
			await fs.symlink(outside, linkedDir, 'dir');
			const source = path.join(linkedDir, 'external.ts');
			const finding = createFinding({ title: 'Observed', description: 'Observed issue', severity: 'Low', cwe: [], owasp: [], file: source, line: 1, column: 1, sourceTool: 'Aqiron', ruleId: 'test.rule', confidence: 'Low', remediation: 'Review', tags: [], rawEvidence: {} });
			const snapshot = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'scan', findings: [finding], relationships: [], profile: createEmptyProjectProfile(root), filesystem: createFileSystem(), scanProvenance: makeProvenance(finding, root, 'const outside = true;\n') });
			assert.equal(snapshot.findings.length, 0);
		} finally { await fs.rm(root, { recursive: true, force: true }); await fs.rm(outside, { recursive: true, force: true }); }
	});

	test('rehashes the complete canonical span, including content beyond 2,000 characters', async () => {
		const root = await testRoot('full-span');
		try {
			const initial = `${'A'.repeat(2500)}\n`;
			const file = path.join(root, 'long.txt');
			await fs.writeFile(file, initial);
			const finding = createFinding({ title: 'Observed', description: 'Observed issue', severity: 'Low', cwe: [], owasp: [], file, line: 1, column: 1, endLine: 1, sourceTool: 'Aqiron', ruleId: 'test.rule', confidence: 'Low', remediation: 'Review', tags: [], rawEvidence: {} });
			const snapshot = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'scan', findings: [finding], relationships: [], profile: createEmptyProjectProfile(root), filesystem: createFileSystem(), scanProvenance: makeProvenance(finding, root, initial) });
			const hypothesis = { ...testHypothesis(), evidence: [snapshot.evidence.find((ref) => ref.kind === 'source-span')!], snapshotId: snapshot.id };
			const store = new HypothesisStoreService(createFileSystem());
			await store.mergeGeneration(root, snapshot, [hypothesis], () => false);
			await fs.writeFile(file, `${'A'.repeat(2200)}B${'A'.repeat(299)}\n`);
			assert.equal((await store.list(root)).hypotheses[0].status, 'stale');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('protects a live cross-process lock even when its directory timestamp is older than two minutes', async () => {
		const root = await testRoot('live-cross-process-lock');
		await fs.mkdir(path.join(root, '.aqiron-security'), { recursive: true });
		const worker = spawn(process.execPath, [path.join(__dirname, 'hypothesisStoreWorker.js'), 'hold-lock', root], { stdio: ['pipe', 'pipe', 'pipe'] });
		try {
			await new Promise<void>((resolve, reject) => {
				worker.stdout.setEncoding('utf8');
				worker.stdout.on('data', (chunk: string) => { if (chunk.includes('ready')) { resolve(); } });
				worker.once('error', reject);
				worker.stderr.on('data', (chunk) => reject(new Error(String(chunk))));
			});
			let completed = false;
			const operation = new HypothesisStoreService(createFileSystem()).list(root).then(() => { completed = true; });
			await new Promise((resolve) => setTimeout(resolve, 250));
			assert.equal(completed, false);
			worker.stdin.write('\n');
			await operation;
			assert.equal(completed, true);
		} finally { worker.kill(); await fs.rm(root, { recursive: true, force: true }); }
	});

	test('recovers a genuinely dead cross-process lock and preserves concurrent triage updates', async () => {
		const root = await testRoot('dead-cross-process-lock');
		try {
			await fs.mkdir(path.join(root, '.aqiron-security'), { recursive: true });
			const lockPath = `${path.join(root, '.aqiron-security', 'hypotheses.json')}.lock`;
			await fs.mkdir(lockPath);
			await fs.writeFile(path.join(lockPath, 'owner.json'), JSON.stringify({ pid: 2_147_483_647, token: 'dead-owner' }));
			const old = new Date(Date.now() - 180_000);
			await fs.utimes(lockPath, old, old);
			const service = new HypothesisStoreService(createFileSystem());
			assert.equal((await service.list(root)).hypotheses.length, 0);
			const first = await addCurrentTestProvenance(root, { ...testHypothesis(), id: 'hyp:process-a' });
			const second = await addCurrentTestProvenance(root, { ...testHypothesis(), id: 'hyp:process-b' });
			await service.mergeGeneration(root, testSnapshot(root), [first, second], () => false);
			const worker = spawn(process.execPath, [path.join(__dirname, 'hypothesisStoreWorker.js'), 'review', root, first.id, 'dismiss'], { stdio: ['ignore', 'pipe', 'pipe'] });
			await Promise.all([
				new Promise<void>((resolve, reject) => { worker.once('exit', (code) => code === 0 ? resolve() : reject(new Error(`worker exited ${code}`))); worker.stderr.on('data', (chunk) => reject(new Error(String(chunk)))); }),
				service.review(root, { workspaceRoot: root, hypothesisId: second.id, action: 'dismiss' }),
			]);
			const reloaded = await service.list(root);
			assert.equal(reloaded.hypotheses.find((item) => item.id === first.id)?.status, 'dismissed');
			assert.equal(reloaded.hypotheses.find((item) => item.id === second.id)?.status, 'dismissed');
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('serializes simultaneous dead-lock reclaimers and a new owner without overlapping critical sections', async () => {
		const root = await testRoot('stale-lock-reclaim-race');
		try {
			await fs.mkdir(path.join(root, '.aqiron-security'), { recursive: true });
			const lockPath = `${path.join(root, '.aqiron-security', 'hypotheses.json')}.lock`;
			await fs.mkdir(lockPath);
			await fs.writeFile(path.join(lockPath, 'owner.json'), JSON.stringify({ pid: 2_147_483_647, token: 'dead-race-owner' }));
			const first = await addCurrentTestProvenance(root, { ...testHypothesis(), id: 'hyp:race-a' });
			const second = await addCurrentTestProvenance(root, { ...testHypothesis(), id: 'hyp:race-b' });
			const seed = new HypothesisStoreService(createFileSystem());
			await seed.mergeGeneration(root, testSnapshot(root), [first, second], () => false);
			await fs.mkdir(lockPath);
			await fs.writeFile(path.join(lockPath, 'owner.json'), JSON.stringify({ pid: 2_147_483_647, token: 'dead-race-owner' }));
			const barrier = path.join(root, 'race-barrier');
			await fs.mkdir(barrier);
			const modes: Array<[string, string, string]> = [['race-review', first.id, 'dismiss'], ['race-review', second.id, 'dismiss'], ['race-list', '', '']];
			const workers = modes.map(([mode, id, action], index) => spawn(process.execPath, [path.join(__dirname, 'hypothesisStoreWorker.js'), mode, root, barrier, id, action, String(index)], { stdio: ['pipe', 'pipe', 'pipe'] }));
			try {
				await Promise.all(workers.map((worker) => new Promise<void>((resolve, reject) => {
					worker.once('error', reject);
					worker.stdout.once('data', (chunk: Buffer) => { if (String(chunk).includes('ready')) {resolve();} });
					worker.stderr.on('data', (chunk) => reject(new Error(String(chunk))));
				})));
				await fs.writeFile(path.join(barrier, 'go'), 'go');
				const results = await Promise.all(workers.map((worker) => new Promise<string>((resolve, reject) => {
					let output = '';
					worker.stdout.on('data', (chunk) => { output += String(chunk); });
					worker.once('exit', (code) => code === 0 ? resolve(output) : reject(new Error(`race worker exited ${code}: ${output}`)));
					worker.stderr.on('data', (chunk) => reject(new Error(String(chunk))));
				})));
				assert.ok(results.every((result) => !result.includes('overlap')) && !await fs.access(path.join(barrier, 'overlap')).then(() => true).catch(() => false), 'no two processes observed simultaneous entry to a protected owner/store read');
				const final = await seed.list(root);
				assert.equal(final.hypotheses.find((item) => item.id === first.id)?.status, 'dismissed');
				assert.equal(final.hypotheses.find((item) => item.id === second.id)?.status, 'dismissed');
			} finally { for (const worker of workers) {worker.kill();} }
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});
});

import { confidenceBand } from '../../packages/core/src/hypotheses/hypothesisEngine';
import { HypothesisSnapshot, SecurityHypothesis } from '../../packages/core/src/hypotheses/contracts';

function testHypothesis(): SecurityHypothesis {
	const ref = { id: 'finding:test', kind: 'finding' as const, source: 'Aqiron', findingId: 'test', ruleId: 'rule.test', observedAt: '2026-01-01T00:00:00.000Z', freshness: 'current' as const };
	return { id: 'hyp:test', title: 'Test hypothesis', description: 'Does the observed indicator belong to the artifact?', asset: { kind: 'project', id: 'src' }, evidence: [ref], rationale: 'Evidence summary.', confidence: { band: 'low', factors: [], policyVersion: 1 }, assumptions: [], contradictions: [], verificationSteps: ['Review the evidence manually.'], status: 'proposed', createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', snapshotId: 'snapshot:test', relatedFindingIds: ['test'], relatedRuleIds: ['rule.test'], relatedHypothesisIds: [] };
}
function makeProvenance(finding: ReturnType<typeof createFinding>, root: string, content: string): FindingSourceProvenance[] {
	return [{ findingId: finding.id, file: path.relative(root, finding.file).split(path.sep).join('/'), startLine: finding.line, endLine: finding.endLine ?? finding.line, contentHash: hashSourceSpan(content, finding.line, finding.endLine ?? finding.line), sourceContentHash: hashSourceContent(content), sourceTool: finding.sourceTool, ruleId: finding.ruleId, observedAt: '2026-01-01T00:00:00.000Z' }];
}
async function addCurrentTestProvenance(root: string, hypothesis: SecurityHypothesis): Promise<SecurityHypothesis> {
	const content = 'const reviewed = true;\n';
	await fs.writeFile(path.join(root, 'test-source.ts'), content);
	const evidence = { id: `span:${hypothesis.id}`, kind: 'source-span' as const, source: 'Core', file: 'test-source.ts', startLine: 1, endLine: 1, contentHash: hashSourceSpan(content, 1, 1), fileContentHash: hashSourceContent(content), findingId: hypothesis.relatedFindingIds[0] ?? hypothesis.id, observedAt: hypothesis.createdAt, freshness: 'current' as const };
	return { ...hypothesis, evidence: [evidence], evidenceFreshness: 'current' };
}
function testRule() { return { id: 'test.observed', title: 'Observed marker', message: 'Review marker', severity: 'Low' as const, pattern: 'OBSERVED_MARKER', extensions: ['.ts'] }; }
function testSnapshot(root: string): HypothesisSnapshot { return { id: 'snapshot:test', workspaceRoot: root, scanId: 'scan:test', capturedAt: '2026-01-01T00:00:00.000Z', fingerprint: 'a'.repeat(64), profile: createEmptyProjectProfile(root), evidence: [], findings: [], relationships: [] }; }
function createFileSystem(options: { failRenameAt?: number; failBackupCleanup?: boolean; symlinkPaths?: string[]; unreadablePaths?: string[]; beforeBoundedRead?: (file: string) => Promise<void> | void } = {}): FileSystem {
	let renameCount = 0;
	return {
		readFile: (async (file: string, encoding?: BufferEncoding) => { if (options.unreadablePaths?.some((item) => path.resolve(item) === path.resolve(file))) { throw Object.assign(new Error('simulated unreadable source'), { code: 'EACCES' }); } return encoding ? fs.readFile(file, encoding) : fs.readFile(file); }) as FileSystem['readFile'],
		readFileBounded: async (file, maxBytes, encoding) => {
			if (options.unreadablePaths?.some((item) => path.resolve(item) === path.resolve(file))) {throw Object.assign(new Error('simulated unreadable source'), { code: 'EACCES' });}
			await options.beforeBoundedRead?.(file);
			const handle = await fs.open(file, 'r');
			try {
				const stat = await handle.stat();
				if (stat.size > maxBytes) {throw Object.assign(new Error('FILE_TOO_LARGE'), { code: 'FILE_TOO_LARGE' });}
				const chunks: Buffer[] = [];
				let total = 0;
				while (total <= maxBytes) {
					const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1 - total));
					const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
					if (!bytesRead) {break;}
					total += bytesRead;
					if (total > maxBytes) {throw Object.assign(new Error('FILE_TOO_LARGE'), { code: 'FILE_TOO_LARGE' });}
					chunks.push(chunk.subarray(0, bytesRead));
				}
				return Buffer.concat(chunks, total).toString(encoding);
			} finally {await handle.close();}
		},
		readFileBoundedBytes: async (file, maxBytes) => {
			if (options.unreadablePaths?.some((item) => path.resolve(item) === path.resolve(file))) {throw Object.assign(new Error('simulated unreadable source'), { code: 'EACCES', bytesRead: 0 });}
			await options.beforeBoundedRead?.(file);
			const handle = await fs.open(file, 'r');
			let total = 0;
			try {
				const stat = await handle.stat();
				if (stat.size > maxBytes) {throw Object.assign(new Error('FILE_TOO_LARGE'), { code: 'FILE_TOO_LARGE', bytesRead: 0 });}
				const chunks: Buffer[] = [];
				while (total <= maxBytes) {
					const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1 - total));
					const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
					if (!bytesRead) {break;}
					total += bytesRead;
					if (total > maxBytes) {throw Object.assign(new Error('FILE_TOO_LARGE'), { code: 'FILE_TOO_LARGE', bytesRead: total });}
					chunks.push(chunk.subarray(0, bytesRead));
				}
				return Buffer.concat(chunks, total);
			} catch (error) {if (error && typeof error === 'object') {Object.assign(error, { bytesRead: total });} throw error;}
			finally {await handle.close();}
		},
		writeFile: async (file, contents, encoding) => { await fs.mkdir(path.dirname(file), { recursive: true }); await fs.writeFile(file, contents, encoding); },
		writeFileExclusive: async (file, contents, encoding) => { await fs.writeFile(file, contents, { encoding, flag: 'wx' }); },
		mkdir: async (directory, options) => { await fs.mkdir(directory, options); },
		readdir: async (directory, options) => await fs.readdir(directory, options as any) as any,
		stat: async (file) => { const stat = await fs.stat(file); return { isFile: () => stat.isFile(), isDirectory: () => stat.isDirectory(), size: stat.size, mtimeMs: stat.mtimeMs }; },
		lstat: async (file) => { if (options.symlinkPaths?.some((item) => path.resolve(item).toLowerCase() === path.resolve(file).toLowerCase())) {return { isFile: () => false, isDirectory: () => false, isSymbolicLink: () => true, size: 0, mtimeMs: 0 };} const stat = await fs.lstat(file); return { isFile: () => stat.isFile(), isDirectory: () => stat.isDirectory(), isSymbolicLink: () => stat.isSymbolicLink(), size: stat.size, mtimeMs: stat.mtimeMs }; },
		realpath: async (file) => await fs.realpath(file),
		access: async (file) => { await fs.access(file); },
		rename: async (oldPath, newPath) => { renameCount += 1; if (options.failRenameAt === renameCount) {throw new Error('simulated replacement failure');} await fs.rename(oldPath, newPath); },
		unlink: async (file) => { if (options.failBackupCleanup && file.endsWith('.bak')) {throw Object.assign(new Error('simulated backup cleanup failure'), { code: 'EPERM' });} await fs.unlink(file); },
		rmdir: async (directory) => { await fs.rmdir(directory); },
		exists: async (file) => await fs.access(file).then(() => true).catch(() => false),
	};
}
async function nodeReadFile(file: string, encoding: BufferEncoding): Promise<string>;
async function nodeReadFile(file: string): Promise<Uint8Array>;
async function nodeReadFile(file: string, encoding?: BufferEncoding): Promise<string | Uint8Array> { return encoding ? fs.readFile(file, encoding) : fs.readFile(file); }
async function testRoot(name: string): Promise<string> { return await fs.mkdtemp(path.join(process.cwd(), `.tmp-aqiron-hypothesis-${name}-`)); }

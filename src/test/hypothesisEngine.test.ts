import { strict as assert } from 'assert';
import * as fs from 'fs/promises';
import * as path from 'path';
import { CorrelatedRelationship } from '../../packages/core/src/correlation/correlationEngine';
import { createFinding } from '../../packages/core/src/findings/finding';
import { createEmptyProjectProfile } from '../../packages/core/src/project/projectProfile';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';
import { buildHypothesisSnapshot, generateDeterministicHypotheses, safeRelativePath, validateEvidenceReference } from '../../packages/core/src/hypotheses/hypothesisEngine';
import { HypothesisStoreError, HypothesisStoreService, transition } from '../../packages/core/src/hypotheses/hypothesisStore';
import { FileSystem } from '../../packages/core/src/shared/platform';
import { AITransport } from '../../packages/core/src/ai/utils/request';

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
			const input = { workspaceRoot: root, scanId: 'scan-a', findings, relationships: [relation], profile: createEmptyProjectProfile(root), filesystem: createFileSystem() };
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
			const snapshot = await buildHypothesisSnapshot({ workspaceRoot: root, scanId: 'scan', findings: [finding], relationships: [], profile: createEmptyProjectProfile(root), filesystem: createFileSystem() });
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
			const service = new HypothesisStoreService(createFileSystem());
			const hypothesis = testHypothesis();
			await service.mergeGeneration(root, testSnapshot(root), [hypothesis], () => false);
			await assert.rejects(service.review(root, { workspaceRoot: root, hypothesisId: hypothesis.id, action: 'validate' }), /requires at least one current/);
			const validated = await service.review(root, { workspaceRoot: root, hypothesisId: hypothesis.id, action: 'validate', evidenceRefs: [hypothesis.evidence[0].id] });
			assert.equal(validated.status, 'validated');
			assert.equal(validated.review?.action, 'validate');
			assert.deepEqual(validated.review?.evidenceRefs, [hypothesis.evidence[0].id]);
			assert.equal('finding' in validated, false);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('persists atomically, preserves triage on regeneration, serializes concurrent updates, and protects corrupt stores', async () => {
		const root = await testRoot('store');
		try {
			const service = new HypothesisStoreService(createFileSystem());
			assert.equal((await service.list(root)).hypotheses.length, 0);
			const hypothesis = testHypothesis();
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
			const internal = runtime as unknown as { scans: Map<string, { result: { state: { finalState: string; workspaceRoot: string; completedAt: string }; findings: typeof findings; correlation: { relationships: CorrelatedRelationship[] } } }> };
			internal.scans.set(scanId, { result: { state: { finalState: 'completed', workspaceRoot: root, completedAt: '2026-10-20T00:00:00.000Z' }, findings, correlation: { relationships: [relationship] } } });
			const response = await runtime.handle({ id: 'hyp-runtime-candidate', type: 'request', method: 'hypotheses.generate', params: { workspaceRoot: root, scanId } }, () => undefined);
			assert.equal(response.success, true, response.error?.message);
			const result = response.result as { status: string; hypotheses: Array<{ status: string; confidence: { band: string } }> };
			assert.equal(result.status, 'generated');
			assert.equal(result.hypotheses.length, 1);
			assert.equal(result.hypotheses[0].status, 'proposed');
			assert.equal(result.hypotheses[0].confidence.band, 'low');
			const persisted = await fs.readFile(path.join(root, '.aqiron-security', 'hypotheses.json'), 'utf8');
			assert.ok(!persisted.includes('never-store'));
			assert.equal(aiCalls, 0);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});
});

import { confidenceBand } from '../../packages/core/src/hypotheses/hypothesisEngine';
import { HypothesisSnapshot, SecurityHypothesis } from '../../packages/core/src/hypotheses/contracts';

function testHypothesis(): SecurityHypothesis {
	const ref = { id: 'finding:test', kind: 'finding' as const, source: 'Aqiron', findingId: 'test', ruleId: 'rule.test', observedAt: '2026-01-01T00:00:00.000Z', freshness: 'current' as const };
	return { id: 'hyp:test', title: 'Test hypothesis', description: 'Does the observed indicator belong to the artifact?', asset: { kind: 'project', id: 'src' }, evidence: [ref], rationale: 'Evidence summary.', confidence: { band: 'low', factors: [], policyVersion: 1 }, assumptions: [], contradictions: [], verificationSteps: ['Review the evidence manually.'], status: 'proposed', createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', snapshotId: 'snapshot:test', relatedFindingIds: ['test'], relatedRuleIds: ['rule.test'], relatedHypothesisIds: [] };
}
function testSnapshot(root: string): HypothesisSnapshot { return { id: 'snapshot:test', workspaceRoot: root, scanId: 'scan:test', capturedAt: '2026-01-01T00:00:00.000Z', fingerprint: 'a'.repeat(64), profile: createEmptyProjectProfile(root), evidence: [], findings: [], relationships: [] }; }
function createFileSystem(options: { failRenameAt?: number } = {}): FileSystem {
	let renameCount = 0;
	return {
		readFile: nodeReadFile,
		writeFile: async (file, contents, encoding) => { await fs.mkdir(path.dirname(file), { recursive: true }); await fs.writeFile(file, contents, encoding); },
		mkdir: async (directory, options) => { await fs.mkdir(directory, options); },
		readdir: async (directory, options) => await fs.readdir(directory, options as any) as any,
		stat: async (file) => { const stat = await fs.stat(file); return { isFile: () => stat.isFile(), isDirectory: () => stat.isDirectory(), size: stat.size, mtimeMs: stat.mtimeMs }; },
		access: async (file) => { await fs.access(file); },
		rename: async (oldPath, newPath) => { renameCount += 1; if (options.failRenameAt === renameCount) {throw new Error('simulated replacement failure');} await fs.rename(oldPath, newPath); },
		unlink: async (file) => { await fs.unlink(file); },
		rmdir: async (directory) => { await fs.rmdir(directory); },
		exists: async (file) => await fs.access(file).then(() => true).catch(() => false),
	};
}
async function nodeReadFile(file: string, encoding: BufferEncoding): Promise<string>;
async function nodeReadFile(file: string): Promise<Uint8Array>;
async function nodeReadFile(file: string, encoding?: BufferEncoding): Promise<string | Uint8Array> { return encoding ? fs.readFile(file, encoding) : fs.readFile(file); }
async function testRoot(name: string): Promise<string> { return await fs.mkdtemp(path.join(process.cwd(), `.tmp-aqiron-hypothesis-${name}-`)); }

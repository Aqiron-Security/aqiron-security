import { strict as assert } from 'assert';
import * as fs from 'fs/promises';
import * as path from 'path';
import { relationshipKey } from '../../packages/core/src/hypotheses/hypothesisEngine';
import {
	createHypothesisAiRequestContext,
	HYPOTHESIS_AI_RESPONSE_LIMITS,
	validateHypothesisAiResponse,
	validateAndPersistHypothesisAiResponse,
	persistHypothesisAiValidationResult,
} from '../../packages/core/src/hypotheses/aiProposalValidation';
import { HypothesisAiProposalV1, HypothesisAiRequestContext, HypothesisEvidenceRef, HypothesisSnapshot } from '../../packages/core/src/hypotheses/contracts';
import { HypothesisStoreService } from '../../packages/core/src/hypotheses/hypothesisStore';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';
import { readAndValidateHypothesisAiResponse } from '../../packages/core/src/hypotheses/hypothesisAiResponse';
import { hashSourceContent, hashSourceSpan } from '../../packages/core/src/shared/sourceProvenance';

suite('Hypothesis AI proposal contract validation', () => {
	test('normalizes a valid versioned proposal and resolves only context-owned evidence', () => {
		const refs = evidenceRefs(3);
		const context = createHypothesisAiRequestContext(snapshotFor(refs));
		const valid = validateHypothesisAiResponse(response(context, proposal({
			supportingEvidenceAliases: ['e1', 'e3'],
			contradictoryEvidenceAliases: ['e2'],
			evidenceRationale: '  The scanner signals are related.\r\nReview the source span.  ',
		})), context);
		assert.equal(valid.valid, true);
		if (!valid.valid) {return;}
		assert.equal(valid.proposals.length, 1);
		assert.equal(valid.proposals[0].evidenceRationale, 'The scanner signals are related.\nReview the source span.');
		assert.deepEqual(valid.proposals[0].supportingEvidence.map((ref) => ref.id), [refs[0].id, refs[1].id]);
		assert.deepEqual(valid.proposals[0].contradictoryEvidence.map((ref) => ref.id), [refs[2].id]);
		assert.deepEqual(valid.proposals[0].supportingEvidence[0], refs[0]);
		assert.ok(!('file' in valid.proposals[0]));
	});

	test('model output is not trusted to correlate contexts; aliases resolve only through the retained Core context', () => {
		const refsA = evidenceRefs(2);
		const refsB = evidenceRefs(2).map((ref) => ({ ...ref, id: `${ref.kind}:other-${ref.id}`,
			...(ref.kind === 'finding' ? { findingId: `other-${ref.findingId}` } : {}),
			...(ref.kind === 'source-span' ? { findingId: `other-${ref.findingId}` } : {}),
		}));
		const contextA = createHypothesisAiRequestContext(snapshotFor(refsA));
		const contextB = createHypothesisAiRequestContext(snapshotFor(refsB));
		assert.equal(contextA.correlationToken === contextB.correlationToken, false);
		const rawFromA = response(contextA, proposal({ supportingEvidenceAliases: ['e1'] }));
		const resolvedInB = validateHypothesisAiResponse(rawFromA, contextB);
		assert.equal(resolvedInB.valid, true);
		if (resolvedInB.valid) { assert.equal(resolvedInB.proposals[0]?.supportingEvidence[0]?.id, refsB[0]?.id); }
		assert.equal(validateHypothesisAiResponse(rawFromA, contextA).valid, true);
	});

	test('rejects model-supplied correlation fields instead of treating them as authorization', () => {
		const context = createHypothesisAiRequestContext(snapshotFor(evidenceRefs(2)));
		const valid = JSON.parse(response(context, proposal())) as Record<string, unknown>;
		assert.deepEqual(validateHypothesisAiResponse(JSON.stringify({ ...valid, correlationToken: 'arbitrary' }), context), { valid: false, error: 'unknown-field' });
	});

	test('a retained response context cannot be persisted under another preparation identity', async () => {
		const context = createHypothesisAiRequestContext(snapshotFor(evidenceRefs(2)), undefined, { preparationId: 'preparation-a' });
		let persistenceCalls = 0;
		const store = { persistValidatedAiProposals: async () => { persistenceCalls++; } } as unknown as HypothesisStoreService;
		const result = await validateAndPersistHypothesisAiResponse(response(context, proposal()), context, store, { id: 'preparation-b', providerId: 'openai', modelId: 'model' });
		assert.deepEqual(result, { valid: false, error: 'invalid-correlation' });
		assert.equal(persistenceCalls, 0, 'stale/cross-preparation output never reaches persistence');
		const expiredContext = createHypothesisAiRequestContext(snapshotFor(evidenceRefs(2)), undefined, { preparationId: 'expired-preparation', expiresAt: new Date(Date.now() - 1).toISOString() });
		const expiredResult = validateHypothesisAiResponse(response(expiredContext, proposal()), expiredContext);
		assert.equal(await persistHypothesisAiValidationResult(expiredResult, store, { id: 'expired-preparation', providerId: 'openai', modelId: 'model' }), false);
		assert.equal(persistenceCalls, 0, 'expired response context cannot be attached after its preparation expires');
	});

	test('rejects caller-constructed contexts and maps at runtime', () => {
		const context = createHypothesisAiRequestContext(snapshotFor(evidenceRefs(2)));
		const raw = response(context, proposal());
		assert.deepEqual(validateHypothesisAiResponse(raw, { correlationToken: context.correlationToken } as HypothesisAiRequestContext), { valid: false, error: 'invalid-context' });
		assert.deepEqual(validateHypothesisAiResponse(raw, new Map([['e1', evidenceRefs(2)[0]]]) as unknown as HypothesisAiRequestContext), { valid: false, error: 'invalid-context' });
	});

	test('keeps issued evidence copies stable when the original snapshot is mutated', () => {
		const refs = evidenceRefs(2);
		const expectedFindingId = refs[0].id;
		const snapshot = snapshotFor(refs) as HypothesisSnapshot;
		const context = createHypothesisAiRequestContext(snapshot);
		snapshot.evidence[0].id = 'finding:mutated';
		snapshot.evidence[0].findingId = 'finding:mutated';
		snapshot.evidence = [];
		const raw = response(context, proposal({ supportingEvidenceAliases: ['e1'] }));
		const first = validateHypothesisAiResponse(raw, context);
		assert.equal(first.valid, true);
		if (!first.valid) {return;}
		assert.equal(first.proposals[0].supportingEvidence[0].id, expectedFindingId);
		first.proposals[0].supportingEvidence[0].id = 'caller-mutated-result';
		const second = validateHypothesisAiResponse(raw, context);
		assert.equal(second.valid, true);
		if (!second.valid) {return;}
		assert.equal(second.proposals[0].supportingEvidence[0].id, expectedFindingId);
	});

	test('rejects empty, malformed, unsupported, unknown, and oversized responses', () => {
		const context = createHypothesisAiRequestContext(snapshotFor(evidenceRefs(2)));
		assert.deepEqual(validateHypothesisAiResponse('  ', context), { valid: false, error: 'empty-response' });
		assert.deepEqual(validateHypothesisAiResponse('{not json}', context), { valid: false, error: 'malformed-response' });
		assert.deepEqual(validateHypothesisAiResponse(JSON.stringify({ schemaVersion: 2, proposals: [] }), context), { valid: false, error: 'unsupported-schema-version' });
		assert.deepEqual(validateHypothesisAiResponse(response(context, proposal(), { debug: true }), context), { valid: false, error: 'unknown-field' });
		assert.deepEqual(validateHypothesisAiResponse(response(context, proposal({ file: 'src/fake.ts', line: 900, confidence: 'high', status: 'validated' })), context), { valid: false, error: 'unknown-field' });
		assert.deepEqual(validateHypothesisAiResponse('x'.repeat(HYPOTHESIS_AI_RESPONSE_LIMITS.maxResponseBytes + 1), context), { valid: false, error: 'response-too-large' });
	});

	test('enforces the response limit using UTF-8 bytes for multibyte text', () => {
		const context = createHypothesisAiRequestContext(snapshotFor(evidenceRefs(2)));
		const long = proposal({
			title: 'é'.repeat(HYPOTHESIS_AI_RESPONSE_LIMITS.maxTitleLength),
			claim: 'é'.repeat(HYPOTHESIS_AI_RESPONSE_LIMITS.maxClaimLength),
			evidenceRationale: 'é'.repeat(HYPOTHESIS_AI_RESPONSE_LIMITS.maxRationaleLength),
			verificationCriteria: Array(HYPOTHESIS_AI_RESPONSE_LIMITS.maxCriteriaCount).fill('é'.repeat(HYPOTHESIS_AI_RESPONSE_LIMITS.maxCriterionLength)),
			falsificationCriteria: Array(HYPOTHESIS_AI_RESPONSE_LIMITS.maxCriteriaCount).fill('é'.repeat(HYPOTHESIS_AI_RESPONSE_LIMITS.maxCriterionLength)),
			uncertainties: Array(HYPOTHESIS_AI_RESPONSE_LIMITS.maxUncertaintyCount).fill('é'.repeat(HYPOTHESIS_AI_RESPONSE_LIMITS.maxUncertaintyLength)),
		});
		const raw = response(context, [long, long]);
		assert.ok(raw.length < HYPOTHESIS_AI_RESPONSE_LIMITS.maxResponseBytes);
		assert.ok(Buffer.byteLength(raw, 'utf8') > HYPOTHESIS_AI_RESPONSE_LIMITS.maxResponseBytes);
		assert.deepEqual(validateHypothesisAiResponse(raw, context), { valid: false, error: 'response-too-large' });
	});

	test('rejects fabricated or duplicate aliases and insufficient direct support', () => {
		const refs = evidenceRefs(3);
		const context = createHypothesisAiRequestContext(snapshotFor(refs));
		const validate = (item: HypothesisAiProposalV1) => validateHypothesisAiResponse(response(context, item), context);
		assert.deepEqual(validate(proposal({ supportingEvidenceAliases: ['e999'] })), { valid: false, error: 'invalid-alias' });
		assert.deepEqual(validate(proposal({ supportingEvidenceAliases: ['e1', 'e1'] })), { valid: false, error: 'invalid-alias' });
		assert.deepEqual(validate(proposal({ supportingEvidenceAliases: ['e1'], contradictoryEvidenceAliases: ['e1'] })), { valid: false, error: 'invalid-content' });
		assert.deepEqual(validate(proposal({ supportingEvidenceAliases: ['e2'] })), { valid: false, error: 'invalid-content' });
		assert.throws(() => createHypothesisAiRequestContext(snapshotFor(refs), [refs[0], { ...refs[1], freshness: 'stale' }]), /verified by the Core snapshot/);
		assert.throws(() => createHypothesisAiRequestContext(snapshotFor(refs), [{ ...refs[0], id: 'finding:fabricated' }]), /verified by the Core snapshot/);
	});

	test('rejects malformed UTF-16 in every text field and accepts valid surrogate pairs', () => {
		const context = createHypothesisAiRequestContext(snapshotFor(evidenceRefs(2)));
		const malformed = ['\\ud800', '\\udc00'];
		const cases: Array<(value: string) => HypothesisAiProposalV1> = [
			(value) => proposal({ title: value }),
			(value) => proposal({ claim: value }),
			(value) => proposal({ evidenceRationale: value }),
			(value) => proposal({ verificationCriteria: [value] }),
			(value) => proposal({ falsificationCriteria: [value] }),
			(value) => proposal({ uncertainties: [value] }),
		];
		for (const invalid of malformed) {
			for (const makeProposal of cases) {
				assert.deepEqual(validateHypothesisAiResponse(response(context, makeProposal(JSON.parse(`"${invalid}"`) as string)), context), { valid: false, error: 'invalid-content' });
			}
		}
		const validPair = JSON.parse('"\\ud83d\\udd12"') as string;
		const valid = validateHypothesisAiResponse(response(context, proposal({ claim: validPair })), context);
		assert.equal(valid.valid, true);
	});

	test('rejects reasoning-only, empty, and non-falsifiable proposals', () => {
		const context = createHypothesisAiRequestContext(snapshotFor(evidenceRefs(3)));
		assert.deepEqual(validateHypothesisAiResponse(JSON.stringify({ schemaVersion: 1, proposals: [] }), context), { valid: false, error: 'response-empty-or-reasoning-only' });
		assert.deepEqual(validateHypothesisAiResponse(response(context, proposal({ evidenceRationale: 'Let me think through this step by step.' })), context), { valid: false, error: 'response-empty-or-reasoning-only' });
		assert.deepEqual(validateHypothesisAiResponse(response(context, proposal({ verificationCriteria: [] })), context), { valid: false, error: 'invalid-content' });
		assert.deepEqual(validateHypothesisAiResponse(response(context, proposal({ falsificationCriteria: [] })), context), { valid: false, error: 'invalid-content' });
		assert.deepEqual(validateHypothesisAiResponse(response(context, proposal({ uncertainties: [] })), context), { valid: false, error: 'invalid-content' });
	});

	test('bounds proposal, reference, field, and criteria counts', () => {
		const context = createHypothesisAiRequestContext(snapshotFor(evidenceRefs(HYPOTHESIS_AI_RESPONSE_LIMITS.maxEvidenceAliases)));
		const valid = proposal({ supportingEvidenceAliases: ['e1'], contradictoryEvidenceAliases: [] });
		const validate = (proposals: unknown[]) => validateHypothesisAiResponse(response(context, proposals), context);
		assert.deepEqual(validate(Array.from({ length: HYPOTHESIS_AI_RESPONSE_LIMITS.maxProposals + 1 }, () => valid)), { valid: false, error: 'invalid-content' });
		assert.deepEqual(validate([proposal({ supportingEvidenceAliases: Array(HYPOTHESIS_AI_RESPONSE_LIMITS.maxEvidencePerProposal + 1).fill('e1') })]), { valid: false, error: 'invalid-content' });
		assert.deepEqual(validate([proposal({ title: 't'.repeat(HYPOTHESIS_AI_RESPONSE_LIMITS.maxTitleLength + 1) })]), { valid: false, error: 'invalid-content' });
		assert.deepEqual(validate([proposal({ claim: 'c'.repeat(HYPOTHESIS_AI_RESPONSE_LIMITS.maxClaimLength + 1) })]), { valid: false, error: 'invalid-content' });
		assert.deepEqual(validate([proposal({ evidenceRationale: 'r'.repeat(HYPOTHESIS_AI_RESPONSE_LIMITS.maxRationaleLength + 1) })]), { valid: false, error: 'invalid-content' });
		assert.deepEqual(validate([proposal({ verificationCriteria: Array(HYPOTHESIS_AI_RESPONSE_LIMITS.maxCriteriaCount + 1).fill('Verify manually.') })]), { valid: false, error: 'invalid-content' });
		assert.deepEqual(validate([proposal({ falsificationCriteria: Array(HYPOTHESIS_AI_RESPONSE_LIMITS.maxCriteriaCount + 1).fill('Falsify manually.') })]), { valid: false, error: 'invalid-content' });
		assert.deepEqual(validate([proposal({ uncertainties: Array(HYPOTHESIS_AI_RESPONSE_LIMITS.maxUncertaintyCount + 1).fill('Unknown.') })]), { valid: false, error: 'invalid-content' });
		assert.throws(() => createHypothesisAiRequestContext(snapshotFor(evidenceRefs(HYPOTHESIS_AI_RESPONSE_LIMITS.maxEvidenceAliases + 1))), /alias limit/);
	});

	test('rejects duplicate normalized proposals and enforces exact response-byte boundary', () => {
		const context = createHypothesisAiRequestContext(snapshotFor(evidenceRefs(2)));
		const item = proposal();
		assert.deepEqual(validateHypothesisAiResponse(response(context, [item, item]), context), { valid: false, error: 'invalid-content' });
		const valid = response(context, proposal());
		const exact = `${valid}${' '.repeat(HYPOTHESIS_AI_RESPONSE_LIMITS.maxResponseBytes - Buffer.byteLength(valid, 'utf8'))}`;
		assert.equal(Buffer.byteLength(exact, 'utf8'), HYPOTHESIS_AI_RESPONSE_LIMITS.maxResponseBytes);
		assert.equal(validateHypothesisAiResponse(exact, context).valid, true);
		assert.deepEqual(validateHypothesisAiResponse(`${exact} `, context), { valid: false, error: 'response-too-large' });
	});

	test('persists only after validation, appends AI-origin proposals, and preserves legacy records', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-aqiron-ai-persistence-'));
		try {
			await fs.mkdir(path.join(root, 'src'), { recursive: true });
			const source = 'verified persistence evidence\n';
			await fs.writeFile(path.join(root, 'src', 'test.ts'), source);
			const contentHash = hashSourceSpan(source, 1, 1)!;
			const fileContentHash = hashSourceContent(source);
			const observedAt = '2026-10-21T00:00:00.000Z';
			const refs: HypothesisEvidenceRef[] = [
				{ id: 'finding:finding-1', kind: 'finding', source: 'test', findingId: 'finding-1', ruleId: 'rule.test', file: 'src/test.ts', startLine: 1, endLine: 1, contentHash, observedAt, freshness: 'current' },
				{ id: `span:src/test.ts:1-1:${contentHash.slice(0, 16)}`, kind: 'source-span', source: 'Core filesystem snapshot', file: 'src/test.ts', startLine: 1, endLine: 1, contentHash, fileContentHash, findingId: 'finding-1', observedAt, freshness: 'current' },
			];
			const snapshot = { id: 'snapshot:persist', workspaceRoot: root, scanId: 'scan:persist', capturedAt: observedAt, fingerprint: 'a'.repeat(64), profile: {} as never, evidence: refs, findings: [{ id: 'finding-1', ruleId: 'rule.test' } as never], relationships: [] } as HypothesisSnapshot;
			const preparationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
			const context = createHypothesisAiRequestContext(snapshot, undefined, { providerId: 'openai', preparationId, expiresAt: new Date(Date.now() + 60_000).toISOString() });
			const store = new HypothesisStoreService(createNodeFileSystem());
			const invalid = await validateAndPersistHypothesisAiResponse('{bad json}', context, store, { id: preparationId, providerId: 'openai', modelId: 'fake-model' });
			assert.equal(invalid.valid, false);
			assert.equal(await fs.access(path.join(root, '.aqiron-security', 'hypotheses.json')).then(() => true, () => false), false);
			const persistenceResponse = response(context, proposal({ supportingEvidenceAliases: ['e1', 'e2'] }));
			const cancellation = new AbortController();
			const cancellableFilesystem = createNodeFileSystem();
			const readBoundedBytes = cancellableFilesystem.readFileBoundedBytes!.bind(cancellableFilesystem);
			cancellableFilesystem.readFileBoundedBytes = async (file, limit) => {
				const bytes = await readBoundedBytes(file, limit);
				if (path.resolve(file) === path.resolve(root, 'src/test.ts')) {cancellation.abort();}
				return bytes;
			};
			await assert.rejects(validateAndPersistHypothesisAiResponse(persistenceResponse, context, new HypothesisStoreService(cancellableFilesystem), { id: preparationId, providerId: 'openai', modelId: 'fake-model' }, cancellation.signal), /Core request cancelled/);
			assert.equal(await fs.access(path.join(root, '.aqiron-security', 'hypotheses.json')).then(() => true, () => false), false, 'cancellation immediately before persistence leaves no store file');
			const result = await validateAndPersistHypothesisAiResponse(persistenceResponse, context, store, { id: preparationId, providerId: 'openai', modelId: 'fake-model' });
			assert.equal(result.valid, true);
			const persisted = JSON.parse(await fs.readFile(path.join(root, '.aqiron-security', 'hypotheses.json'), 'utf8')) as { hypotheses: Array<Record<string, unknown>> };
			assert.equal(persisted.hypotheses.length, 1);
			assert.equal(persisted.hypotheses[0].status, 'proposed');
			assert.deepEqual(persisted.hypotheses[0].origin, { kind: 'ai-proposal', preparationId, providerId: 'openai', modelId: 'fake-model' });
			assert.equal(persisted.hypotheses[0].review, undefined);
			// A second attempt with the same deterministic identity fails closed instead of overwriting.
			await assert.rejects(validateAndPersistHypothesisAiResponse(persistenceResponse, context, store, { id: preparationId, providerId: 'openai', modelId: 'fake-model' }));
			const afterReplay = JSON.parse(await fs.readFile(path.join(root, '.aqiron-security', 'hypotheses.json'), 'utf8')) as { hypotheses: unknown[] };
			assert.equal(afterReplay.hypotheses.length, 1);
		} finally { await fs.rm(root, { recursive: true, force: true }); }
	});

	test('response boundary rejects provider errors, cancellation, and malformed envelopes without exposing body text', async () => {
		const context = createHypothesisAiRequestContext(snapshotFor(evidenceRefs(2)));
		const marker = 'provider-secret-response-marker';
		await assert.rejects(readAndValidateHypothesisAiResponse({ ok: false, status: 500, headers: {}, text: async () => marker, json: async <T>() => marker as T }, context), (error: unknown) => {
			assert.ok(error instanceof Error);
			assert.ok(!error.message.includes(marker));
			return true;
		});
		const cancelled = new AbortController(); cancelled.abort();
		await assert.rejects(readAndValidateHypothesisAiResponse({ ok: true, status: 200, headers: {}, text: async () => response(context, proposal()), json: async <T>() => ({} as T) }, context, cancelled.signal));
		const invalid = await readAndValidateHypothesisAiResponse({ ok: true, status: 200, headers: { 'content-type': 'application/json' }, text: async () => `{"error":"${marker}"}`, json: async <T>() => ({} as T) }, context);
		assert.equal(invalid.valid, false);
		if (!invalid.valid) {assert.equal(invalid.error, 'invalid-shape');}
	});

	test('cancellation at the atomic rename boundary reports committed state and leaves the file present', async () => {
		const root = await fs.mkdtemp(path.join(process.cwd(), '.tmp-aqiron-ai-commit-race-'));
		try {
			await fs.mkdir(path.join(root, 'src'), { recursive: true });
			const source = 'commit boundary evidence\n'; await fs.writeFile(path.join(root, 'src/test.ts'), source);
			const observedAt = '2026-10-21T00:00:00.000Z'; const contentHash = hashSourceSpan(source, 1, 1)!; const fileContentHash = hashSourceContent(source);
			const refs = [
				{ id: 'finding:commit', kind: 'finding' as const, source: 'test', findingId: 'commit', ruleId: 'rule.commit', file: 'src/test.ts', startLine: 1, endLine: 1, contentHash, observedAt, freshness: 'current' as const },
				{ id: `span:src/test.ts:1-1:${contentHash.slice(0, 16)}`, kind: 'source-span' as const, source: 'Core filesystem snapshot', file: 'src/test.ts', startLine: 1, endLine: 1, contentHash, fileContentHash, findingId: 'commit', observedAt, freshness: 'current' as const },
			];
			const snapshot = { id: 'snapshot:commit', workspaceRoot: root, scanId: 'scan:commit', capturedAt: observedAt, fingerprint: 'b'.repeat(64), profile: {} as never, evidence: refs, findings: [{ id: 'commit', ruleId: 'rule.commit' } as never], relationships: [] } as HypothesisSnapshot;
			const context = createHypothesisAiRequestContext(snapshot);
			const valid = validateHypothesisAiResponse(response(context, proposal({ supportingEvidenceAliases: ['e1', 'e2'] })), context);
			assert.equal(valid.valid, true); if (!valid.valid) {return;}
			const abort = new AbortController(); let commitStarted = false; let committed = false;
			const filesystem = createNodeFileSystem(); const rename = filesystem.rename.bind(filesystem);
			filesystem.rename = async (oldPath, newPath) => {
				if (newPath === path.join(root, '.aqiron-security', 'hypotheses.json') && oldPath.endsWith('.tmp')) { assert.equal(commitStarted, true); abort.abort(); }
				await rename(oldPath, newPath);
			};
			const store = new HypothesisStoreService(filesystem);
			await store.persistValidatedAiProposals(root, snapshot, valid.proposals, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'openai', 'fake', abort.signal, {
				beginCommit: () => {commitStarted = true; return true;}, markCommitted: () => {committed = true;},
			});
			assert.equal(abort.signal.aborted, true); assert.equal(committed, true);
			assert.equal(JSON.parse(await fs.readFile(path.join(root, '.aqiron-security', 'hypotheses.json'), 'utf8')).hypotheses.length, 1);
		} finally {await fs.rm(root, { recursive: true, force: true });}
	});
});

function proposal(overrides: Record<string, unknown> = {}): HypothesisAiProposalV1 {
	return {
		title: 'Check the authentication boundary',
		claim: 'Could this route accept an unauthenticated request?',
		evidenceRationale: 'A scanner finding and a verified source span refer to the same route.',
		supportingEvidenceAliases: ['e1'],
		contradictoryEvidenceAliases: [],
		verificationCriteria: ['Review the route guard and its caller.'],
		falsificationCriteria: ['Confirm the route rejects unauthenticated requests.'],
		uncertainties: ['Runtime configuration was not observed.'],
		...overrides,
	} as HypothesisAiProposalV1;
}

function response(_context: HypothesisAiRequestContext, proposals: unknown, extra: Record<string, unknown> = {}): string {
	return JSON.stringify({ schemaVersion: 1, proposals: Array.isArray(proposals) ? proposals : [proposals], ...extra });
}

function evidenceRefs(count: number): HypothesisEvidenceRef[] {
	return Array.from({ length: count }, (_, index) => {
		const kind = index === 0 ? 'finding' : index === 1 ? 'source-span' : index === 2 ? 'relationship' : 'finding';
		const relationship = { type: 'same-file' as const, sourceId: 'finding-1', targetId: 'finding-2', weight: 0.5, reason: 'verified test relation' };
		return {
			id: kind === 'relationship' ? `relationship:${relationshipKey(relationship)}` : `${kind}:${String(index + 1).padStart(3, '0')}`,
			kind,
			source: 'Core test fixture',
			...(kind === 'finding' ? { findingId: `finding-${index + 1}`, ruleId: `rule.test.${index + 1}` } : {}),
			...(kind === 'source-span' ? { file: 'src/test.ts', startLine: 1, endLine: 1, contentHash: 'a'.repeat(64), fileContentHash: 'b'.repeat(64), findingId: 'finding-1' } : {}),
			...(kind === 'relationship' ? { relationshipId: relationshipKey(relationship) } : {}),
			observedAt: '2026-10-21T00:00:00.000Z',
			freshness: 'current' as const,
		};
	});
}

function snapshotFor(evidence: HypothesisEvidenceRef[]) {
	const relationship = { type: 'same-file' as const, sourceId: 'finding-1', targetId: 'finding-2', weight: 0.5, reason: 'verified test relation' };
	return {
		id: 'snapshot:test', workspaceRoot: 'C:/workspace', scanId: 'scan:test', capturedAt: '2026-10-21T00:00:00.000Z', fingerprint: 'a'.repeat(64),
		profile: {} as never,
		evidence,
		findings: evidence.filter((ref) => ref.kind === 'finding').map((ref) => ({ id: ref.findingId!, ruleId: ref.ruleId! } as never)),
		relationships: evidence.some((ref) => ref.kind === 'relationship') ? [relationship] : [],
	} as never;
}

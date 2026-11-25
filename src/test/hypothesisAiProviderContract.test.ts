import { strict as assert } from 'assert';
import { HypothesisAiRequestContext, HypothesisEvidenceRef, HypothesisSnapshot } from '../../packages/core/src/hypotheses/contracts';
import { createHypothesisAiRequestContext } from '../../packages/core/src/hypotheses/aiProposalValidation';
import { readAndValidateHypothesisAiResponse } from '../../packages/core/src/hypotheses/hypothesisAiResponse';
import { AIHttpResponse } from '../../packages/core/src/ai/utils/request';

// Provider-shaped offline contract fixtures. These establish parser behavior,
// not live-provider compatibility or support for every model behind a router.
suite('Hypothesis AI provider envelope contract fixtures (offline)', () => {
	const modelJson = JSON.stringify({ schemaVersion: 1, proposals: [{
		title: 'Review route authorization', claim: 'Could this route accept an unauthenticated request?', evidenceRationale: 'The scan finding identifies a route requiring review.',
		supportingEvidenceAliases: ['e1'], contradictoryEvidenceAliases: [], verificationCriteria: ['Inspect the route guard.'],
		falsificationCriteria: ['Confirm unauthenticated requests are rejected.'], uncertainties: ['Runtime configuration was not observed.'],
	}] });
	const fixtures: Array<{ provider: 'openai' | 'openrouter' | 'claude' | 'gemini'; body: unknown }> = [
		{ provider: 'openai', body: { choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: modelJson } }] } },
		{ provider: 'openrouter', body: { choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: modelJson } }] } },
		{ provider: 'claude', body: { type: 'message', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'text', text: modelJson }] } },
		{ provider: 'gemini', body: { candidates: [{ finishReason: 'STOP', content: { parts: [{ text: modelJson }] } }] } },
	];

	for (const fixture of fixtures) {
		test(`${fixture.provider} documented JSON envelope extracts text and validates proposals`, async () => {
			const context = contextFor(fixture.provider);
			const result = await readAndValidateHypothesisAiResponse(response(JSON.stringify(fixture.body)), context);
			assert.equal(result.valid, true);
			if (result.valid) { assert.equal(result.proposals[0]?.supportingEvidence[0]?.id, 'finding:fixture'); }
		});
	}

	test('rejects wrong content type, malformed/truncated JSON and malformed envelopes', async () => {
		const context = contextFor('openai');
		for (const [body, headers] of [['{', { 'content-type': 'application/json' }], ['{}', { 'content-type': 'text/event-stream' }], ['{}', { 'content-type': 'application/json' }]] as Array<[string, Record<string, string>]>) {
			const result = await readAndValidateHypothesisAiResponse(response(body, headers), context);
			assert.equal(result.valid, false);
		}
	});

	test('rejects missing text, unexpected blocks, refusal, and incomplete provider results', async () => {
		const cases = [
			['openai', { choices: [{ finish_reason: 'length', message: { content: modelJson } }] }],
			['openai', { choices: [{ finish_reason: 'stop', message: { refusal: 'cannot comply', content: modelJson } }] }],
			['openrouter', { choices: [{ finish_reason: 'tool_calls', message: { content: modelJson } }] }],
			['claude', { type: 'message', role: 'assistant', stop_reason: 'max_tokens', content: [{ type: 'text', text: modelJson }] }],
			['claude', { type: 'message', role: 'assistant', stop_reason: 'end_turn', content: [{ type: 'tool_use', id: 'x' }] }],
			['gemini', { candidates: [{ finishReason: 'MAX_TOKENS', content: { parts: [{ text: modelJson }] } }] }],
			['gemini', { promptFeedback: { blockReason: 'SAFETY' }, candidates: [] }],
		] as const;
		for (const [provider, body] of cases) {
			const result = await readAndValidateHypothesisAiResponse(response(JSON.stringify(body)), contextFor(provider));
			assert.equal(result.valid, false, `${provider} malformed/refusal fixture rejected`);
		}
	});

	test('rejects HTTP-success provider error envelopes and tool-bearing completion envelopes', async () => {
		const context = contextFor('openrouter');
		for (const body of [{ error: { message: 'private provider error' }, choices: [] }, { choices: [{ finish_reason: 'stop', message: { content: modelJson, tool_calls: [] } }] }]) {
			const result = await readAndValidateHypothesisAiResponse(response(JSON.stringify(body)), context);
			assert.equal(result.valid, false);
		}
	});

	test('rejects syntactically valid envelope with invalid proposal payload and over-limit body', async () => {
		const context = contextFor('openai');
		const invalidProposal = JSON.stringify({ schemaVersion: 1, proposals: [{ title: 'bad' }] });
		const parsed = await readAndValidateHypothesisAiResponse(response(JSON.stringify({ choices: [{ finish_reason: 'stop', message: { content: invalidProposal } }] })), context);
		assert.equal(parsed.valid, false);
		const oversized = JSON.stringify({ choices: [{ finish_reason: 'stop', message: { content: `${modelJson}${' '.repeat(16_384)}` } }] });
		const overLimit = await readAndValidateHypothesisAiResponse(response(oversized), context);
		assert.deepEqual(overLimit, { valid: false, error: 'response-too-large' });
	});

	test('transport error and cancellation remain failures without parsing a late body', async () => {
		const context = contextFor('openai');
		await assert.rejects(readAndValidateHypothesisAiResponse({ ok: false, status: 503, headers: {}, text: async () => 'secret body', json: async <T>() => ({} as T) }, context));
		const abort = new AbortController(); abort.abort();
		await assert.rejects(readAndValidateHypothesisAiResponse(response(JSON.stringify(fixtures[0]!.body)), context, abort.signal));
	});
});

function contextFor(provider: 'openai' | 'openrouter' | 'claude' | 'gemini'): HypothesisAiRequestContext {
	const evidence: HypothesisEvidenceRef = { id: 'finding:fixture', kind: 'finding', source: 'fixture scanner', findingId: 'fixture', ruleId: 'rule.fixture', observedAt: '2026-10-21T00:00:00.000Z', freshness: 'current' };
	const snapshot = { id: 'snapshot:fixture', workspaceRoot: 'C:/fixture', scanId: 'scan:fixture', capturedAt: evidence.observedAt, fingerprint: 'a'.repeat(64), profile: {}, evidence: [evidence], findings: [{ id: 'fixture', ruleId: 'rule.fixture' }], relationships: [] } as unknown as HypothesisSnapshot;
	return createHypothesisAiRequestContext(snapshot, undefined, { providerId: provider });
}

function response(body: string, headers: Record<string, string> = { 'content-type': 'application/json; charset=utf-8' }): AIHttpResponse {
	return { ok: true, status: 200, headers, text: async () => body, json: async <T>() => JSON.parse(body) as T, body: null };
}

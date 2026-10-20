import * as assert from 'assert';
import { buildWorkspaceRecommendations, parseRecommendationSource, recommendationChatPayload } from '../agents/recommendations';
import { parseRecommendationSourceDetailed } from '../../packages/core/src/shared/recommendations';

suite('Shared workspace recommendations', () => {
	test('preserves real structured recommendation fields and metadata', () => {
		const source = JSON.stringify([{ title: 'Review token handling', detail: 'Rotate exposed tokens and move them to a secret store.', severity: 'High', recommended: true, command: 'Review token handling', metadata: { ruleId: 'secret.token', file: 'lib/auth.dart', line: 18, category: 'Secrets' } }]);
		assert.deepEqual(parseRecommendationSource(source), [{ title: 'Review token handling', detail: 'Rotate exposed tokens and move them to a secret store.', severity: 'High', recommended: true, command: 'Review token handling', metadata: { ruleId: 'secret.token', file: 'lib/auth.dart', line: 18, category: 'Secrets' } }]);
	});

	test('uses legacy recommendation content without generic titles or reasoning artifacts', () => {
		const projected = buildWorkspaceRecommendations([], ['- Review storage permissions carefully.\n- Here’s a thinking process.\n- Let me think through this.']);
		assert.equal(projected.length, 1);
		assert.equal(projected[0]?.title, 'Review storage permissions carefully.');
		assert.equal(projected[0]?.command, 'Review storage permissions carefully.');
		assert.equal(projected[0]?.severity, undefined);
		assert.doesNotMatch(projected[0]?.title ?? '', /AI workspace suggestion/i);
	});

	test('returns an actual empty result when the source contains no valid recommendations', () => {
		assert.deepEqual(buildWorkspaceRecommendations([], []), []);
		assert.deepEqual(parseRecommendationSource('Here’s a thinking process.'), []);
	});

	test('reports safe format and validation diagnostics without returning source content', () => {
		const parsed = parseRecommendationSourceDetailed('```json\n{"recommendations":[{"title":"Review auth","description":"Restrict token access."},{"title":"","detail":"Missing title."}]}\n```');
		assert.equal(parsed.diagnostics.format, 'fenced-json');
		assert.equal(parsed.diagnostics.branch, 'json-recommendations');
		assert.deepEqual({ candidates: parsed.diagnostics.candidates, accepted: parsed.diagnostics.accepted, rejected: parsed.diagnostics.rejected }, { candidates: 2, accepted: 1, rejected: 1 });
		assert.deepEqual(parsed.diagnostics.rejectionReasons, { 'missing-title-or-detail': 1 });
		assert.equal(JSON.stringify(parsed.diagnostics).includes('Restrict token access'), false);
		assert.equal(parseRecommendationSourceDetailed('   ').diagnostics.format, 'empty');
		assert.equal(parseRecommendationSourceDetailed('{bad json').diagnostics.format, 'malformed-json');
	});

	test('Run and Explain retain the shared chat payload semantics', () => {
		const recommendation = { title: 'Review token handling', detail: 'Rotate exposed tokens.', command: 'Review token handling' };
		assert.deepEqual(recommendationChatPayload(recommendation, 'run'), { text: 'Review token handling', useTaskDefaults: true });
		assert.deepEqual(recommendationChatPayload(recommendation, 'explain'), { text: 'Explain Review token handling', useTaskDefaults: true });
	});
});

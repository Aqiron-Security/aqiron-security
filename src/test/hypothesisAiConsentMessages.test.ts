import { strict as assert } from 'assert';
import { isHypothesisAiPrepareMessage, isHypothesisAiResponseMessage, isWebviewMessage } from '../webview/hypothesisAiConsentMessages';

suite('VS Code hypothesis consent message validation', () => {
	test('accepts only bounded known webview envelopes', () => {
		assert.equal(isWebviewMessage({ command: 'prepareHypothesisAi', payload: { providerId: 'openai' } }), true);
		assert.equal(isWebviewMessage({ command: 'prepareHypothesisAi', payload: {}, injected: true }), false);
		assert.equal(isWebviewMessage({ command: 'unknownCommand' }), false);
		assert.equal(isWebviewMessage({ command: 'focus'.repeat(20) }), false);
		assert.equal(isWebviewMessage({ command: 'ready', payload: 'x'.repeat(1_048_577) }), false);
		assert.equal(isWebviewMessage(null), false);
	});

	test('rejects forged preparation payload fields and malformed evidence selectors', () => {
		const valid = { providerId: 'openai', modelId: 'gpt-test', evidenceIds: ['finding:one'], includeSourceExcerpts: false };
		assert.equal(isHypothesisAiPrepareMessage(valid), true);
		assert.equal(isHypothesisAiPrepareMessage({ ...valid, manifest: {} }), false);
		assert.equal(isHypothesisAiPrepareMessage({ ...valid, evidenceIds: ['finding:one', 'finding:one'] }), false);
		assert.equal(isHypothesisAiPrepareMessage({ ...valid, includeSourceExcerpts: 'yes' }), false);
		assert.equal(isHypothesisAiPrepareMessage({ ...valid, evidenceIds: [' x'] }), false);
	});

	test('approval and execute messages permit only Core preparation identity and fingerprint', () => {
		const valid = { preparationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', contentFingerprint: 'a'.repeat(64) };
		assert.equal(isHypothesisAiResponseMessage(valid), true);
		assert.equal(isWebviewMessage({ command: 'executeHypothesisAi', payload: valid }), true);
		assert.equal(isWebviewMessage({ command: 'cancelHypothesisAiExecution' }), true);
		assert.equal(isHypothesisAiResponseMessage({ ...valid, disclosure: 'forged' }), false);
		assert.equal(isHypothesisAiResponseMessage({ ...valid, body: '{}' }), false);
		assert.equal(isHypothesisAiResponseMessage({ ...valid, contentFingerprint: 'short' }), false);
		assert.equal(isHypothesisAiResponseMessage({ preparationId: 'unknown', contentFingerprint: 'a'.repeat(64) }), false);
	});
});

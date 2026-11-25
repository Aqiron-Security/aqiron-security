import { strict as assert } from 'assert';
import { dispatchApprovedHypothesisAiExecution, hypothesisAiExecutionPresentation, hypothesisAiProposalSavedMessage, isHypothesisAiPrepareMessage, isHypothesisAiResponseMessage, isWebviewMessage } from '../webview/hypothesisAiConsentMessages';

suite('VS Code hypothesis consent message validation', () => {
	test('labels AI synthesis output as proposed pending reviewer assessment', () => {
		assert.equal(hypothesisAiProposalSavedMessage(1), 'Core saved 1 AI-proposed hypothesis as proposed. Reviewer assessment is still required.');
		assert.equal(hypothesisAiProposalSavedMessage(2), 'Core saved 2 AI-proposed hypotheses as proposed. Reviewer assessment is still required.');
		assert.doesNotMatch(hypothesisAiProposalSavedMessage(1), /validated/i);
	});

	test('execution affordance copy distinguishes disabled gate reporting from deliberate synthesis execution', () => {
		assert.deepEqual(hypothesisAiExecutionPresentation(false), { statusText: 'Core reports that provider execution is disabled. Approval did not contact the provider; no execution action is available.' });
		assert.deepEqual(hypothesisAiExecutionPresentation(true), { actionLabel: 'Execute approved synthesis' });
	});

	test('only an enabled, explicitly approved preparation dispatches exactly one synthesis action', () => {
		const messages: Array<{ command: string; payload: unknown }> = [];
		const post = (command: 'executeHypothesisAi', payload: { preparationId: string; contentFingerprint: string }) => { messages.push({ command, payload }); };
		assert.equal(dispatchApprovedHypothesisAiExecution(false, true, 'prep', 'a'.repeat(64), post), false);
		assert.equal(dispatchApprovedHypothesisAiExecution(true, false, 'prep', 'a'.repeat(64), post), false);
		assert.equal(messages.length, 0);
		assert.equal(dispatchApprovedHypothesisAiExecution(true, true, 'prep', 'a'.repeat(64), post), true);
		assert.deepEqual(messages, [{ command: 'executeHypothesisAi', payload: { preparationId: 'prep', contentFingerprint: 'a'.repeat(64) } }]);
	});

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

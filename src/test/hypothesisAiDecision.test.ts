import * as assert from 'assert';
import type { HypothesisAiLifecycleResult } from '../../packages/core/src/hypotheses/hypothesisAiPreparation';
import { HypothesisAiDecisionConsent, HypothesisAiDecisionCoordinator, HypothesisAiDecisionRequest } from '../webview/hypothesisAiDecision';

const fingerprint = 'a'.repeat(64);

suite('VS Code hypothesis AI decision coordination', () => {
	test('records approval success and clears provider-owned pending state', async () => {
		const harness = createHarness();
		const result: HypothesisAiLifecycleResult = { ok: true, state: 'approved' };
		assert.equal(await harness.coordinator.submit(harness.input('approve', async () => result)), true);
		assert.deepEqual(harness.consent.result, result);
		assert.equal(harness.consent.decisionPending, false);
		assert.deepEqual(harness.publishedStates.map((state) => state?.decisionPending), [true, false]);
	});

	test('records denial success and does not invoke an execution request', async () => {
		const harness = createHarness();
		const result: HypothesisAiLifecycleResult = { ok: true, state: 'denied' };
		assert.equal(await harness.coordinator.submit(harness.input('deny', async () => result)), true);
		assert.deepEqual(harness.consent.result, result);
		assert.equal(harness.consent.decisionPending, false);
	});

	test('shows Core lifecycle failures and clears pending state', async () => {
		const harness = createHarness();
		const result: HypothesisAiLifecycleResult = { ok: false, state: 'invalidated', reason: 'revalidation-failed' };
		await harness.coordinator.submit(harness.input('approve', async () => result));
		assert.deepEqual(harness.consent.result, result);
		assert.equal(harness.consent.message, 'The scan evidence or provider configuration changed. Prepare a fresh disclosure.');
		assert.equal(harness.consent.decisionPending, false);
	});

	test('shows a rejected Core request and clears pending state', async () => {
		const harness = createHarness();
		await harness.coordinator.submit(harness.input('deny', async () => {throw new Error('Core rejected request');}));
		assert.match(harness.consent.message ?? '', /Core rejected the decision request/);
		assert.equal(harness.consent.result, undefined);
		assert.equal(harness.consent.decisionPending, false);
		assert.equal(harness.consent.decisionOutcomeUnconfirmed, false);
	});

	for (const [label, code] of [['timeout', 'CORE_REQUEST_TIMEOUT'], ['Core process exit', 'CORE_PROCESS_CRASHED']] as const) {
		test(`marks ${label} as unconfirmed and blocks resubmission`, async () => {
			const harness = createHarness();
			let calls = 0;
			const input = harness.input('approve', async () => {calls += 1; throw Object.assign(new Error(label), { code });});
			await harness.coordinator.submit(input);
			assert.equal(harness.consent.decisionPending, false);
			assert.equal(harness.consent.decisionOutcomeUnconfirmed, true);
			assert.match(harness.consent.message ?? '', /Core did not return a decision response/);
			assert.equal(await harness.coordinator.submit(input), false);
			assert.equal(calls, 1);
		});
	}

	test('blocks duplicate clicks while the same preparation decision is pending', async () => {
		const harness = createHarness();
		let resolveRequest!: (value: HypothesisAiLifecycleResult) => void;
		let calls = 0;
		const input = harness.input('approve', () => {calls += 1; return new Promise<HypothesisAiLifecycleResult>((resolve) => {resolveRequest = resolve;});});
		const first = harness.coordinator.submit(input);
		assert.equal(harness.consent.decisionPending, true);
		assert.equal(await harness.coordinator.submit(input), false);
		assert.equal(calls, 1);
		resolveRequest({ ok: true, state: 'approved' });
		await first;
		assert.equal(harness.consent.decisionPending, false);
	});

	test('ignores a late response after the UI has switched to a newer preparation', async () => {
		const harness = createHarness();
		let resolveRequest!: (value: HypothesisAiLifecycleResult) => void;
		const first = harness.coordinator.submit(harness.input('approve', () => new Promise<HypothesisAiLifecycleResult>((resolve) => {resolveRequest = resolve;})));
		harness.consent = makeConsent('new-preparation', 'b'.repeat(64));
		resolveRequest({ ok: true, state: 'approved' });
		await first;
		assert.equal(harness.consent.manifest?.preparationId, 'new-preparation');
		assert.equal(harness.consent.result, undefined);
		assert.equal(harness.consent.decisionPending, undefined);
	});
});

function createHarness() {
	const coordinator = new HypothesisAiDecisionCoordinator();
	let consent = makeConsent('preparation-one', fingerprint);
	const publishedStates: Array<HypothesisAiDecisionConsent | undefined> = [];
	return {
		coordinator,
		get consent() {return consent;},
		set consent(value: HypothesisAiDecisionConsent) {consent = value;},
		publishedStates,
		input(action: 'approve' | 'deny', request: HypothesisAiDecisionRequest['request']): HypothesisAiDecisionRequest {
			return { action, preparationId: 'preparation-one', contentFingerprint: fingerprint, getConsent: () => consent, setConsent: (next) => {consent = next;}, request, publish: () => publishedStates.push(consent) };
		},
	};
}

function makeConsent(preparationId: string, contentFingerprint: string): HypothesisAiDecisionConsent {
	return { manifest: { preparationId } as HypothesisAiDecisionConsent['manifest'], contentFingerprint };
}

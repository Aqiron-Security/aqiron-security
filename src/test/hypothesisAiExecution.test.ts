import * as assert from 'assert';
import { HypothesisAiLifecycleResult } from '../../packages/core/src/hypotheses/hypothesisAiPreparation';
import { HypothesisAiExecutionConsent, HypothesisAiExecutionCoordinator } from '../webview/hypothesisAiExecution';

suite('Hypothesis AI execution outcome coordination', () => {
	test('records a successful terminal result and clears pending state', async () => {
		const state = harness();
		await state.coordinator.submit(state.input(async () => ({ ok: true, state: 'succeeded', value: { proposalCount: 1 } })));
		assert.equal(state.consent.executionPending, false);
		assert.deepEqual(state.consent.executionResult, { ok: true, state: 'succeeded', value: { proposalCount: 1 } });
		assert.equal(state.consent.executionOutcomeUnconfirmed, false);
	});

	test('marks a Core timeout result unconfirmed and blocks resubmission', async () => {
		const state = harness();
		await state.coordinator.submit(state.input(async () => ({ ok: false, state: 'failed', reason: 'timed-out' })));
		assert.equal(state.consent.executionPending, false);
		assert.equal(state.consent.executionOutcomeUnconfirmed, true);
		assert.match(state.consent.message ?? '', /Execution outcome unconfirmed.*provider may have received/s);
		assert.equal(await state.coordinator.submit(state.input(async () => { throw new Error('must not retry'); })), false);
	});

	test('preserves an authoritative disabled-gate result without labeling it unconfirmed', async () => {
		const state = harness();
		await state.coordinator.submit(state.input(async () => ({ ok: false, state: 'approved', reason: 'executor-disabled' })));
		assert.equal(state.consent.executionPending, false);
		assert.equal(state.consent.executionOutcomeUnconfirmed, false);
		assert.match(state.consent.message ?? '', /disabled by this release gate.*No provider request was made/);
	});

	test('marks a rejected Core request unconfirmed, clears pending, and blocks resubmission', async () => {
		const state = harness();
		await state.coordinator.submit(state.input(async () => { throw Object.assign(new Error('Core exited'), { code: 'CORE_PROCESS_CRASHED' }); }));
		assert.equal(state.consent.executionPending, false);
		assert.equal(state.consent.executionOutcomeUnconfirmed, true);
		assert.match(state.consent.message ?? '', /may continue processing/);
		assert.equal(await state.coordinator.submit(state.input(async () => ({ ok: true, state: 'succeeded', value: { proposalCount: 1 } }))), false);
	});

	test('a locally cancelled Core execution is unconfirmed because the remote provider may continue', async () => {
		const state = harness();
		await state.coordinator.submit(state.input(async () => ({ ok: false, state: 'cancelled', reason: 'cancelled' })));
		assert.equal(state.consent.executionPending, false);
		assert.equal(state.consent.executionOutcomeUnconfirmed, true);
		assert.match(state.consent.message ?? '', /may continue processing/);
	});

	test('prevents duplicate requests while the preparation is pending', async () => {
		const state = harness();
		let finish!: (result: HypothesisAiLifecycleResult<{ proposalCount: number }>) => void;
		const first = state.coordinator.submit(state.input(() => new Promise((resolve) => {finish = resolve;})));
		assert.equal(state.consent.executionPending, true);
		assert.equal(await state.coordinator.submit(state.input(async () => { throw new Error('duplicate request'); })), false);
		finish({ ok: true, state: 'succeeded', value: { proposalCount: 2 } });
		await first;
		assert.equal(state.consent.executionPending, false);
	});

	test('late responses cannot overwrite a newer preparation', async () => {
		const state = harness();
		let finish!: (result: HypothesisAiLifecycleResult<{ proposalCount: number }>) => void;
		const request = state.coordinator.submit(state.input(() => new Promise((resolve) => {finish = resolve;})));
		state.consent = approvedConsent('prep-new');
		finish({ ok: true, state: 'succeeded', value: { proposalCount: 1 } });
		await request;
		assert.equal(state.consent.manifest?.preparationId, 'prep-new');
		assert.equal(state.consent.executionResult, undefined);
	});
});

function harness() {
	const coordinator = new HypothesisAiExecutionCoordinator();
	let consent = approvedConsent();
	let publications = 0;
	return {
		coordinator,
		get consent() {return consent;},
		set consent(value: HypothesisAiExecutionConsent) {consent = value;},
		input: (request: () => Promise<HypothesisAiLifecycleResult<{ proposalCount: number }>>) => ({
			preparationId: 'prep-current', contentFingerprint: 'a'.repeat(64),
			getConsent: () => consent,
			setConsent: (value: HypothesisAiExecutionConsent) => {consent = value;},
			request,
			publish: () => {publications++;},
		}),
		get publications() {return publications;},
	};
}

function approvedConsent(preparationId = 'prep-current'): HypothesisAiExecutionConsent {
	return {
		manifest: { preparationId } as HypothesisAiExecutionConsent['manifest'],
		contentFingerprint: 'a'.repeat(64),
		result: { ok: true, state: 'approved' },
	};
}

import * as assert from 'node:assert/strict';
import { HypothesisAiPreparationRegistry } from '../../packages/core/src/hypotheses/hypothesisAiPreparation';
import { HypothesisAiPreparedDisclosureManifest } from '../../packages/core/src/hypotheses/contracts';

suite('Core hypothesis AI approval lifecycle', () => {
	test('preparation alone is not consent and forged, missing, and mismatched identities are rejected', async () => {
		const registry = new HypothesisAiPreparationRegistry();
		const { manifest, fingerprint } = issue(registry, 'prepared-only');
		let invoked = 0;
		const revalidate = async () => true;
		assert.deepEqual(await registry.execute(manifest.preparationId, fingerprint, revalidate, async () => {invoked++;}), { ok: false, state: 'prepared', reason: 'invalid-state' });
		assert.equal((await registry.approve('forged-id', fingerprint, revalidate)).ok, false);
		assert.equal(failureReason(await registry.approve(manifest.preparationId, 'f'.repeat(64), revalidate)), 'fingerprint-mismatch');
		assert.equal((await registry.approve(manifest.preparationId, fingerprint, revalidate)).ok, true);
		assert.equal(invoked, 0);
		registry.dispose();
	});

	test('revalidation failure invalidates a preparation before approval or execution', async () => {
		const registry = new HypothesisAiPreparationRegistry();
		const { manifest, fingerprint } = issue(registry);
		let invoked = 0;
		assert.deepEqual(await registry.approve(manifest.preparationId, fingerprint, () => false), { ok: false, state: 'invalidated', reason: 'revalidation-failed' });
		assert.equal((await registry.execute(manifest.preparationId, fingerprint, () => true, async () => {invoked++;})).ok, false);
		assert.equal(invoked, 0);
		registry.dispose();
	});

	test('approval and execution are bound to the exact retained content and configuration fingerprint', async () => {
		const registry = new HypothesisAiPreparationRegistry();
		const { manifest, fingerprint } = issue(registry, 'immutable', JSON.stringify({ providerId: 'openai', modelId: 'model-a', endpoint: 'https://unknown.invalid', content: 'bounded' }));
		assert.equal(fingerprint, registry.fingerprint(manifest.preparationId));
		assert.equal((await registry.approve(manifest.preparationId, fingerprint, async retained => retained.provider.id === 'openai' && retained.provider.modelId === 'model-a')).ok, true);
		const alteredFingerprint = '0'.repeat(64);
		assert.equal(failureReason(await registry.execute(manifest.preparationId, alteredFingerprint, () => true, async () => 'should-not-run')), 'fingerprint-mismatch');
		registry.dispose();
	});

	test('approved preparation can be claimed once; deterministic concurrent attempts invoke only one executor', async () => {
		const registry = new HypothesisAiPreparationRegistry();
		const { manifest, fingerprint } = issue(registry);
		assert.equal((await registry.approve(manifest.preparationId, fingerprint, () => true)).ok, true);
		const validationStarted = deferred<void>();
		const releaseValidation = deferred<void>();
		let validations = 0;
		const revalidate = async () => {validations++; validationStarted.resolve(); await releaseValidation.promise; return true;};
		const executorStarted = deferred<void>();
		const releaseExecutor = deferred<string>();
		let invocations = 0;
		const executor = async () => {invocations++; executorStarted.resolve(); return await releaseExecutor.promise;};
		const first = registry.execute(manifest.preparationId, fingerprint, revalidate, executor);
		await validationStarted.promise;
		const second = registry.execute(manifest.preparationId, fingerprint, revalidate, executor);
		assert.equal(failureReason(await second), 'invalid-state', 'the first caller claims before asynchronous revalidation');
		releaseValidation.resolve();
		await executorStarted.promise;
		releaseExecutor.resolve('fake-result');
		const results = await Promise.all([first, second]);
		assert.equal(invocations, 1);
		assert.equal(validations, 1, 'only the execution claimant revalidates');
		assert.equal(results.filter(result => result.ok).length, 1);
		assert.equal((await registry.execute(manifest.preparationId, fingerprint, () => true, executor)).ok, false, 'replay after claim is rejected');
		registry.dispose();
	});

	test('expired preparations and invalidated approvals cannot execute', async () => {
		let now = 1_800_000_000_000;
		const registry = new HypothesisAiPreparationRegistry(undefined, () => now);
		const expiring = createManifest('expires', now + 50);
		assert.equal(registry.issue(expiring, 'payload', now), true);
		const expiredFp = registry.fingerprint(expiring.preparationId)!;
		await registry.approve(expiring.preparationId, expiredFp, () => true);
		now += 51;
		let calls = 0;
		assert.equal(failureReason(await registry.execute(expiring.preparationId, expiredFp, () => true, async () => {calls++;})), 'unknown-preparation');
		assert.equal(calls, 0);
		const invalidManifest = createManifest('config-change', now + 300_000);
		assert.equal(registry.issue(invalidManifest, JSON.stringify({ providerId: 'openai', modelId: 'model-a', endpoint: 'https://first.invalid' }), now), true);
		const invalid = { manifest: invalidManifest, fingerprint: registry.fingerprint('config-change')! };
		assert.equal((await registry.approve(invalid.manifest.preparationId, invalid.fingerprint, () => true)).ok, true);
		assert.equal(failureReason(await registry.execute(invalid.manifest.preparationId, invalid.fingerprint, retained => retained.provider.modelId === 'new-config-model', async () => {calls++;})), 'revalidation-failed', 'changed provider configuration invalidates the approval');
		assert.equal(calls, 0);
		registry.dispose();
	});

	test('denial, cancellation, executor failure and timeout are terminal one-use outcomes', async () => {
		const registry = new HypothesisAiPreparationRegistry();
		const denied = issue(registry, 'denied');
		assert.equal(registry.deny(denied.manifest.preparationId, denied.fingerprint).state, 'denied');
		let calls = 0;
		assert.equal((await registry.execute(denied.manifest.preparationId, denied.fingerprint, () => true, async () => {calls++;})).ok, false);
		const cancelled = issue(registry, 'cancel');
		await registry.approve(cancelled.manifest.preparationId, cancelled.fingerprint, () => true);
		const controller = new AbortController();
		const started = deferred<void>();
		const running = registry.execute(cancelled.manifest.preparationId, cancelled.fingerprint, () => true, async (_payload, signal) => {calls++; started.resolve(); await new Promise<void>(resolve => signal.addEventListener('abort', () => resolve(), { once: true })); return 'late';}, { signal: controller.signal });
		await started.promise;
		controller.abort();
		assert.equal(failureReason(await running), 'cancelled');
		const failed = issue(registry, 'failure');
		await registry.approve(failed.manifest.preparationId, failed.fingerprint, () => true);
		assert.equal(failureReason(await registry.execute(failed.manifest.preparationId, failed.fingerprint, () => true, async () => {calls++; throw new Error('fake');})), 'execution-failed');
		const timeout = issue(registry, 'timeout');
		await registry.approve(timeout.manifest.preparationId, timeout.fingerprint, () => true);
		assert.equal(failureReason(await registry.execute(timeout.manifest.preparationId, timeout.fingerprint, () => true, async (_payload, signal) => {calls++; await new Promise<void>(resolve => signal.addEventListener('abort', () => resolve(), { once: true })); return 'late';}, { timeoutMs: 0 })), 'timed-out');
		assert.equal(calls, 3);
		registry.dispose();
	});

	test('cancellation before commit aborts, while cancellation after commit reservation cannot misreport a committed result', async () => {
		const registry = new HypothesisAiPreparationRegistry();
		const { manifest, fingerprint } = issue(registry, 'commit-race');
		await registry.approve(manifest.preparationId, fingerprint, () => true);
		const commitEntered = deferred<void>();
		const releaseCommit = deferred<void>();
		const abort = new AbortController();
		const running = registry.execute(manifest.preparationId, fingerprint, () => true, async (_payload, _signal, _request, commit) => {
			assert.equal(commit!.beginCommit(), true);
			commitEntered.resolve();
			await releaseCommit.promise;
			commit!.markCommitted();
			return 'committed';
		}, { signal: abort.signal });
		await commitEntered.promise;
		abort.abort();
		releaseCommit.resolve();
		assert.deepEqual(await running, { ok: true, state: 'succeeded', value: 'committed' });
		assert.equal((await registry.execute(manifest.preparationId, fingerprint, () => true, async () => 'replay')).ok, false);
		registry.dispose();
	});

	test('a late executor continuation after cancellation cannot cross the removed preparation commit guard', async () => {
		const registry = new HypothesisAiPreparationRegistry();
		const { manifest, fingerprint } = issue(registry, 'late-cancel-continuation');
		await registry.approve(manifest.preparationId, fingerprint, () => true);
		const started = deferred<void>(); const release = deferred<void>(); const continued = deferred<void>();
		let commitControl: import('../../packages/core/src/hypotheses/contracts').HypothesisAiCommitControl | undefined;
		let committed = false;
		const abort = new AbortController();
		const running = registry.execute(manifest.preparationId, fingerprint, () => true, async (_payload, _signal, _request, control) => {
			commitControl = control; started.resolve(); await release.promise;
			committed = control!.beginCommit();
			if (committed) {control!.markCommitted();}
			continued.resolve();
		}, { signal: abort.signal });
		await started.promise; abort.abort();
		assert.equal(failureReason(await running), 'cancelled');
		release.resolve();
		await continued.promise;
		assert.equal(commitControl!.beginCommit(), false);
		assert.equal(committed, false, 'late work cannot reserve or report a persistence commit');
		registry.dispose();
	});

	test('expiry during asynchronous revalidation or execution aborts work and cannot report late success', async () => {
		let now = 1_800_000_000_000;
		const scheduled: Array<{ callback: () => void; dueAt: number; cancelled: boolean }> = [];
		const timers = {
			setTimeout(callback: () => void, delayMs: number): ReturnType<typeof setTimeout> {
				const record = { callback, dueAt: now + delayMs, cancelled: false };
				scheduled.push(record);
				return Object.assign({ unref: () => undefined, __record: record }) as unknown as ReturnType<typeof setTimeout>;
			},
			clearTimeout(timer: ReturnType<typeof setTimeout>): void { (timer as unknown as { __record: typeof scheduled[number] }).__record.cancelled = true; },
		};
		const advance = (milliseconds: number) => {
			now += milliseconds;
			let next: typeof scheduled[number] | undefined;
			while ((next = scheduled.filter(item => !item.cancelled && item.dueAt <= now).sort((a, b) => a.dueAt - b.dueAt)[0])) {next.cancelled = true; next.callback();}
		};
		const registry = new HypothesisAiPreparationRegistry(timers, () => now);
		const manifest = createManifest('expires-in-flight', now + 100);
		assert.equal(registry.issue(manifest, 'bounded payload', now), true);
		const fingerprint = registry.fingerprint(manifest.preparationId)!;
		assert.equal((await registry.approve(manifest.preparationId, fingerprint, () => true)).ok, true);
		const revalidationStarted = deferred<void>();
		const releaseRevalidation = deferred<void>();
		let executorCalls = 0;
		const blockedRevalidation = registry.execute(manifest.preparationId, fingerprint, async () => {revalidationStarted.resolve(); await releaseRevalidation.promise; return true;}, async () => {executorCalls++; return 'must not run';});
		await revalidationStarted.promise;
		advance(100);
		assert.equal(failureReason(await blockedRevalidation), 'unknown-preparation');
		assert.equal(executorCalls, 0, 'expiry while revalidating prevents transport dispatch');
		releaseRevalidation.resolve();

		const inFlight = createManifest('expires-during-executor', now + 100);
		assert.equal(registry.issue(inFlight, 'bounded payload', now), true);
		const inFlightFingerprint = registry.fingerprint(inFlight.preparationId)!;
		assert.equal((await registry.approve(inFlight.preparationId, inFlightFingerprint, () => true)).ok, true);
		const executorStarted = deferred<void>();
		let observedAbort = false;
		const running = registry.execute(inFlight.preparationId, inFlightFingerprint, () => true, async (_payload, signal) => {
			executorCalls++;
			if (signal.aborted) {observedAbort = true;} else {signal.addEventListener('abort', () => {observedAbort = true;}, { once: true });}
			executorStarted.resolve();
			await new Promise<void>(resolve => signal.addEventListener('abort', () => resolve(), { once: true }));
			return 'late-result';
		});
		await executorStarted.promise;
		advance(100);
		const expiredResult = await running;
		assert.equal(expiredResult.ok, false);
		assert.equal(expiredResult.reason, 'unknown-preparation');
		assert.equal(observedAbort, true, 'expiry aborts the active executor signal');
		assert.equal((await registry.execute(inFlight.preparationId, inFlightFingerprint, () => true, async () => 'replay')).ok, false);
		registry.dispose();

		const restarted = new HypothesisAiPreparationRegistry();
		const beforeRestart = issue(restarted, 'dispose-in-flight');
		assert.equal((await restarted.approve(beforeRestart.manifest.preparationId, beforeRestart.fingerprint, () => true)).ok, true);
		const active = deferred<void>();
		let restartAbortObserved = false;
		const executing = restarted.execute(beforeRestart.manifest.preparationId, beforeRestart.fingerprint, () => true, async (_payload, signal) => {
			if (!signal.aborted) {signal.addEventListener('abort', () => {restartAbortObserved = true;}, { once: true });}
			active.resolve();
			await new Promise<void>(resolve => signal.addEventListener('abort', () => resolve(), { once: true }));
			return 'late-after-dispose';
		});
		await active.promise;
		restarted.dispose();
		const invalidated = await executing;
		assert.equal(invalidated.ok, false);
		assert.equal(invalidated.state, 'invalidated');
		assert.equal(restartAbortObserved, true, 'registry disposal aborts any in-flight execution during Core shutdown/restart');
	});

	test('restart loses approvals and capacity rejection preserves existing preparations', async () => {
		const firstRuntime = new HypothesisAiPreparationRegistry();
		const retained = issue(firstRuntime, 'restart');
		await firstRuntime.approve(retained.manifest.preparationId, retained.fingerprint, () => true);
		firstRuntime.dispose();
		const restartedRuntime = new HypothesisAiPreparationRegistry();
		assert.equal((await restartedRuntime.execute(retained.manifest.preparationId, retained.fingerprint, () => true, async () => 'never')).ok, false);
		const full = new HypothesisAiPreparationRegistry();
		const accepted = Array.from({ length: 16 }, (_, index) => issue(full, `capacity-${index}`));
		const overflow = createManifest('overflow', Date.now() + 300_000);
		assert.equal(full.issue(overflow, 'payload'), false);
		assert.equal(full.activeCount(), 16);
		assert.ok(full.fingerprint(accepted[0]!.manifest.preparationId));
		full.dispose(); restartedRuntime.dispose();
	});
});

function issue(registry: HypothesisAiPreparationRegistry, id = 'preparation', envelope = 'exact-canonical-content') {
	const manifest = createManifest(id, Date.now() + 300_000);
	assert.equal(registry.issue(manifest, envelope), true);
	return { manifest, fingerprint: registry.fingerprint(id)! };
}

function createManifest(id: string, expires: number): HypothesisAiPreparedDisclosureManifest {
	return {
		preparationId: id, expiresAt: new Date(expires).toISOString(), workspaceIdentity: 'C:/workspace', scanId: 'scan-1', snapshotId: 'snapshot-1', snapshotFingerprint: 'a'.repeat(64),
		provider: { id: 'openai', modelId: 'model-a', external: true, endpoint: 'https://api.openai.com/v1/chat/completions', endpointClassification: 'known', credential: { identity: 'test', name: 'Test', last4: '1234', updatedAt: 'now' }, configurationFingerprint: 'a'.repeat(64), requestOptions: { temperature: 0, maxTokens: 2048, timeoutMs: 30_000, retries: 0, streaming: false, maxRequestBodyBytes: 16_384, maxResponseBodyBytes: 16_384 }, retentionPolicy: 'unknown' },
		dataCategories: ['finding-summary'], evidenceCount: 1, findingCount: 1, relationshipCount: 0, excerptCount: 0, includeSourceExcerpts: false,
		evidence: [], proposedContent: { purpose: 'test synthesis', instructions: 'test', evidence: [] }, proposedContentUtf8Bytes: 1, coreEnvelopeUtf8Bytes: 1,
		previewUtf8Bytes: 1, previewOnly: true, executionAvailable: false, providerCallMade: false, disclosure: 'test',
	};
}

function deferred<T>() {
	let resolve!: (value: T | PromiseLike<T>) => void;
	const promise = new Promise<T>(done => {resolve = done;});
	return { promise, resolve };
}

function failureReason(result: { ok: boolean; reason?: string }): string | undefined { return result.ok ? undefined : result.reason; }

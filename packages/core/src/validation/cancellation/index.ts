import type { IsolatedWorkerHandle, IsolatedWorkerResult } from '../isolation/providers';

export type CancellationState = 'registered' | 'running' | 'cancellation-requested' | 'termination-requested' | 'termination-confirmed' | 'completed' | 'failed' | 'timed-out' | 'cancelled' | 'interrupted' | 'cleanup-completed' | 'cleanup-failed';
export type CancellationOutcome = 'completed' | 'failed' | 'cancelled' | 'interrupted' | 'timed-out';
export interface ShutdownBounds { readonly waitMs: number; readonly terminateMs: number; readonly confirmationMs: number; readonly cleanupMs: number; readonly totalMs: number; }
export interface CancellationResult {
	readonly cancellationRequested: boolean;
	readonly terminationConfirmed: boolean;
	readonly outcome: CancellationOutcome;
	readonly cleanup: 'completed' | 'failed' | 'skipped-termination-unconfirmed' | 'not-needed';
	readonly executionUncertain: boolean;
	readonly workerResult?: IsolatedWorkerResult;
}
export interface CancellationClock { now(): number; setTimeout(callback: () => void, ms: number): unknown; clearTimeout(handle: unknown): void; }
export const DEFAULT_SHUTDOWN_BOUNDS: ShutdownBounds = Object.freeze({ waitMs: 120_000, terminateMs: 2_000, confirmationMs: 5_000, cleanupMs: 2_000, totalMs: 10_000 });
const MAX_BOUND = 120_000;
const systemClock: CancellationClock = { now: () => Number(process.hrtime.bigint()) / 1e6, setTimeout: (callback, ms) => setTimeout(callback, ms), clearTimeout: handle => clearTimeout(handle as ReturnType<typeof setTimeout>) };

/** Core-owned coordination around the existing provider handle. It never launches workers. */
export class WorkerCancellationCoordinator {
	private stateValue: CancellationState = 'registered';
	private outcome?: CancellationResult;
	private cancelOperation?: Promise<CancellationResult>;
	private readonly completion: Promise<IsolatedWorkerResult>;
	private workerSettled = false;
	private workerValue?: IsolatedWorkerResult;
	private workerFailed = false;
	private explicitCancellationRequested = false;
	private cleanupOperation?: Promise<CancellationResult['cleanup']>;
	private readonly clock: CancellationClock;
	private cancellationStartedAt = 0;
	constructor(private readonly handle: IsolatedWorkerHandle, private readonly bounds: ShutdownBounds = DEFAULT_SHUTDOWN_BOUNDS, clock: CancellationClock = systemClock) {
		validateBounds(bounds); this.clock = clock;
		this.transition('running');
		// Attach rejection handling immediately so a late worker rejection cannot become unhandled.
		this.completion = Promise.resolve().then(() => handle.wait());
		void this.completion.then(result => { this.workerSettled = true; this.workerValue = result; }, () => { this.workerSettled = true; this.workerFailed = true; });
	}
	get state(): CancellationState { return this.stateValue; }
	get terminalResult(): CancellationResult | undefined { return this.outcome; }
	waitForCompletion(): Promise<CancellationResult> {
		if (this.outcome) { return Promise.resolve(this.outcome); }
		return this.raceBounded(this.completion, this.bounds.waitMs).then(async result => {
			if ('rejected' in result) { return this.cancel('failure'); }
			if (!result.timedOut) { return this.finishNaturally(result.value.exitCategory === 'success' ? 'completed' : 'failed', result.value); }
			return this.cancel('timeout');
		}, () => this.cancel('failure'));
	}
	cancel(reason: 'cancel' | 'timeout' | 'failure' = 'cancel'): Promise<CancellationResult> {
		if (this.outcome) { return Promise.resolve(this.outcome); }
		if (this.cancelOperation) { if (reason === 'cancel') { this.explicitCancellationRequested = true; } return this.cancelOperation; }
		if (this.workerSettled && !this.workerFailed) { return this.finishNaturally(this.workerValue?.exitCategory === 'success' ? 'completed' : 'failed', this.workerValue); }
		if (reason === 'cancel') { this.explicitCancellationRequested = true; }
		// This synchronous state change is the cancellation linearization point.
		this.cancellationStartedAt = this.clock.now();
		this.transition('cancellation-requested');
		this.cancelOperation = this.performCancellation(reason);
		return this.cancelOperation;
	}
	shutdown(): Promise<CancellationResult> { return this.cancel('cancel'); }
	private async performCancellation(reason: 'cancel' | 'timeout' | 'failure'): Promise<CancellationResult> {
		const remaining = () => Math.max(0, this.bounds.totalMs - (this.clock.now() - this.cancellationStartedAt));
		if (remaining() <= 0) { return this.commit('interrupted', false, 'skipped-termination-unconfirmed', true); }
		this.transition('termination-requested');
		const terminate = this.raceBounded(Promise.resolve().then(() => this.handle.terminate(reason)), Math.min(this.bounds.terminateMs, remaining()));
		const requested = await terminate;
		if (!('value' in requested) || !requested.value.confirmed) { return this.commit('interrupted', false, 'skipped-termination-unconfirmed', true); }
		this.transition('termination-confirmed');
		// A completed wait during termination is a completion outcome, but termination remains confirmed.
		const completed = await this.raceBounded(this.completion, Math.min(this.bounds.confirmationMs, remaining()));
		if ('value' in completed) {
			const cleanup = await this.cleanupOnce(Math.min(this.bounds.cleanupMs, remaining()));
			const outcome = this.workerFailed || completed.value.exitCategory === 'worker-error' ? 'failed' : completed.value.exitCategory === 'terminated' ? reason === 'timeout' ? 'timed-out' : reason === 'failure' ? 'failed' : 'cancelled' : 'completed';
			return this.commit(outcome, true, cleanup, false, completed.value);
		}
		const cleanup = await this.cleanupOnce(Math.min(this.bounds.cleanupMs, remaining()));
		const outcome = reason === 'timeout' ? 'timed-out' : reason === 'failure' ? 'failed' : 'cancelled';
		return this.commit(outcome, true, cleanup, false);
	}
	private async finishNaturally(outcome: 'completed' | 'failed', workerResult?: IsolatedWorkerResult): Promise<CancellationResult> {
		if (this.outcome) { return this.outcome; }
		const cleanup = await this.cleanupOnce(this.bounds.cleanupMs);
		return this.commit(outcome, false, cleanup, false, workerResult);
	}
	private async cleanupOnce(budget: number): Promise<CancellationResult['cleanup']> {
		if (this.cleanupOperation) { return this.cleanupOperation; }
		this.cleanupOperation = this.raceBounded(Promise.resolve().then(() => this.handle.cleanup()), budget).then(result => {
			if (!('value' in result)) { this.transition('cleanup-failed'); return 'failed'; }
			this.transition('cleanup-completed'); return 'completed';
		}, () => { this.transition('cleanup-failed'); return 'failed'; });
		return this.cleanupOperation;
	}
	private commit(outcome: CancellationOutcome, terminationConfirmed: boolean, cleanup: CancellationResult['cleanup'], uncertain: boolean, workerResult?: IsolatedWorkerResult): CancellationResult {
		if (this.outcome) { return this.outcome; }
		const terminalState: CancellationState = outcome === 'completed' ? 'completed' : outcome === 'failed' ? 'failed' : outcome === 'cancelled' ? 'cancelled' : outcome === 'timed-out' ? 'timed-out' : 'interrupted';
		const result = Object.freeze({ cancellationRequested: this.explicitCancellationRequested, terminationConfirmed, outcome, cleanup, executionUncertain: uncertain, ...(workerResult ? { workerResult } : {}) });
		this.transition(terminalState); this.outcome = result; return result;
	}
	private transition(next: CancellationState): void {
		if (this.outcome) { throw new Error('Terminal cancellation outcome is immutable.'); }
		const allowed: Readonly<Record<CancellationState, readonly CancellationState[]>> = {
			registered: ['running'], running: ['cancellation-requested', 'cleanup-completed', 'cleanup-failed', 'completed', 'failed'],
			'cancellation-requested': ['termination-requested', 'interrupted'], 'termination-requested': ['termination-confirmed', 'interrupted'],
			'termination-confirmed': ['cleanup-completed', 'cleanup-failed', 'completed', 'failed', 'cancelled', 'timed-out'],
			'cleanup-completed': ['completed', 'failed', 'cancelled', 'timed-out'], 'cleanup-failed': ['completed', 'failed', 'cancelled', 'timed-out'],
			completed: [], failed: [], 'timed-out': [], cancelled: [], interrupted: [],
		};
		if (!allowed[this.stateValue].includes(next)) { throw new Error(`Invalid cancellation transition ${this.stateValue} -> ${next}.`); }
		this.stateValue = next;
	}
	private async raceBounded<T>(operation: Promise<T>, budget: number): Promise<{ timedOut: true } | { rejected: true } | { timedOut: false; value: T }> {
		const allowed = budget;
		let timer: unknown;
		const timeout = new Promise<{ timedOut: true }>(resolve => { timer = this.clock.setTimeout(() => resolve({ timedOut: true }), allowed); });
		const settled = operation.then(value => ({ timedOut: false as const, value }), () => ({ rejected: true as const }));
		const result = await Promise.race([settled, timeout]);
		if (timer !== undefined) { this.clock.clearTimeout(timer); }
		return result;
	}
}

function validateBounds(bounds: ShutdownBounds): void {
	if (!bounds || typeof bounds !== 'object' || Object.values(bounds).some(value => !Number.isSafeInteger(value) || value < 1 || value > MAX_BOUND) || bounds.totalMs < Math.max(bounds.terminateMs, bounds.cleanupMs) || bounds.totalMs > bounds.waitMs + bounds.terminateMs + bounds.confirmationMs + bounds.cleanupMs) { throw new RangeError('Shutdown bounds are invalid or inconsistent.'); }
}

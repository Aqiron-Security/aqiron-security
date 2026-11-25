import type { HypothesisAiPreparedDisclosureManifest } from '../../packages/core/src/hypotheses/contracts';
import type { HypothesisAiLifecycleResult } from '../../packages/core/src/hypotheses/hypothesisAiPreparation';

export interface HypothesisAiExecutionConsent {
	manifest?: HypothesisAiPreparedDisclosureManifest;
	contentFingerprint?: string;
	result?: HypothesisAiLifecycleResult;
	executionResult?: HypothesisAiLifecycleResult<{ proposalCount: number }>;
	executionPending?: boolean;
	executionOutcomeUnconfirmed?: boolean;
	message?: string;
}

export interface HypothesisAiExecutionRequest {
	preparationId: string;
	contentFingerprint: string;
	getConsent(): HypothesisAiExecutionConsent | undefined;
	setConsent(consent: HypothesisAiExecutionConsent): void;
	request(): Promise<HypothesisAiLifecycleResult<{ proposalCount: number }>>;
	publish(): void;
}

/** Keeps execution state preparation-specific and prevents retries after an unknown outcome. */
export class HypothesisAiExecutionCoordinator {
	private readonly pending = new Set<string>();
	private readonly unconfirmed = new Set<string>();

	async submit(input: HypothesisAiExecutionRequest): Promise<boolean> {
		const key = executionKey(input.preparationId, input.contentFingerprint);
		const current = input.getConsent();
		if (!isCurrentPreparation(current, input.preparationId, input.contentFingerprint)
			|| current.result?.state !== 'approved' || current.executionResult || current.executionPending
			|| current.executionOutcomeUnconfirmed || this.pending.has(key) || this.unconfirmed.has(key)) {return false;}

		this.pending.add(key);
		this.updateCurrent(input, (consent) => ({ ...consent, executionPending: true, message: 'Execution is running through Core.' }));
		input.publish();
		try {
			const result = await input.request();
			const outcomeUnconfirmed = isUnconfirmedResult(result);
			if (outcomeUnconfirmed) {this.unconfirmed.add(key);}
			this.updateCurrent(input, (consent) => ({
				...consent,
				executionResult: result,
				executionOutcomeUnconfirmed: outcomeUnconfirmed,
				message: executionMessage(result),
			}));
		} catch {
			this.unconfirmed.add(key);
			this.updateCurrent(input, (consent) => ({
				...consent,
				executionOutcomeUnconfirmed: true,
				message: unconfirmedMessage(),
			}));
		} finally {
			this.pending.delete(key);
			this.updateCurrent(input, (consent) => ({ ...consent, executionPending: false }));
			input.publish();
		}
		return true;
	}

	private updateCurrent(input: HypothesisAiExecutionRequest, update: (consent: HypothesisAiExecutionConsent) => HypothesisAiExecutionConsent): void {
		const current = input.getConsent();
		if (!isCurrentPreparation(current, input.preparationId, input.contentFingerprint)) {return;}
		input.setConsent(update(current));
	}
}

export function isUnconfirmedResult(result: HypothesisAiLifecycleResult<{ proposalCount: number }>): boolean {
	return !result.ok && (result.reason === 'cancelled' || result.reason === 'timed-out' || result.reason === 'execution-failed');
}

export function unconfirmedMessage(): string {
	return 'Execution outcome unconfirmed. Core did not return an authoritative result. A provider may have received the request and may continue processing; this preparation cannot be submitted again.';
}

function executionMessage(result: HypothesisAiLifecycleResult<{ proposalCount: number }>): string | undefined {
	if (isUnconfirmedResult(result)) {return unconfirmedMessage();}
	if (result.ok && result.state === 'succeeded') {return undefined;}
	if (!result.ok && result.reason === 'executor-disabled') {return 'Execution is disabled by this release gate. No provider request was made.';}
	return !result.ok ? `Core did not complete this execution (${result.reason}). This preparation cannot be replayed.` : undefined;
}

function isCurrentPreparation(consent: HypothesisAiExecutionConsent | undefined, preparationId: string, contentFingerprint: string): consent is HypothesisAiExecutionConsent {
	return consent?.manifest?.preparationId === preparationId && consent.contentFingerprint === contentFingerprint;
}

function executionKey(preparationId: string, contentFingerprint: string): string {
	return `${preparationId}:${contentFingerprint}`;
}

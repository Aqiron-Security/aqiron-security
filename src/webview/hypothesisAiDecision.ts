import type { HypothesisAiPreparedDisclosureManifest } from '../../packages/core/src/hypotheses/contracts';
import type { HypothesisAiLifecycleResult } from '../../packages/core/src/hypotheses/hypothesisAiPreparation';

export interface HypothesisAiDecisionConsent {
	manifest?: HypothesisAiPreparedDisclosureManifest;
	contentFingerprint?: string;
	result?: HypothesisAiLifecycleResult;
	decisionPending?: boolean;
	decisionOutcomeUnconfirmed?: boolean;
	message?: string;
}

export interface HypothesisAiDecisionRequest {
	action: 'approve' | 'deny';
	preparationId: string;
	contentFingerprint: string;
	getConsent(): HypothesisAiDecisionConsent | undefined;
	setConsent(consent: HypothesisAiDecisionConsent): void;
	request(): Promise<HypothesisAiLifecycleResult>;
	publish(): void;
}

/** Provider-owned decision coordination prevents duplicate submissions and stale state writes. */
export class HypothesisAiDecisionCoordinator {
	private readonly pending = new Set<string>();
	private readonly unconfirmed = new Set<string>();

	async submit(input: HypothesisAiDecisionRequest): Promise<boolean> {
		const key = decisionKey(input.preparationId, input.contentFingerprint);
		const current = input.getConsent();
		if (!isCurrentPreparation(current, input.preparationId, input.contentFingerprint)
			|| current.result || current.decisionPending || this.pending.has(key) || this.unconfirmed.has(key)) {return false;}

		this.pending.add(key);
		this.updateCurrent(input, (consent) => ({ ...consent, decisionPending: true, message: 'Recording decision…' }));
		input.publish();
		try {
			const result = await input.request();
			this.updateCurrent(input, (consent) => ({
				...consent,
				result,
				message: result.ok ? undefined : lifecycleFailureMessage(result.state, result.reason),
			}));
		} catch (error) {
			const code = getErrorCode(error);
			const outcomeUnconfirmed = code === 'CORE_REQUEST_TIMEOUT' || code === 'CORE_PROCESS_CRASHED';
			if (outcomeUnconfirmed) {this.unconfirmed.add(key);}
			this.updateCurrent(input, (consent) => ({
				...consent,
				decisionOutcomeUnconfirmed: outcomeUnconfirmed,
				message: outcomeUnconfirmed
					? `Core did not return a decision response${code === 'CORE_REQUEST_TIMEOUT' ? ' before the request timed out' : ' before the process exited'}. This preparation cannot be submitted again.`
					: 'Core rejected the decision request. No decision was confirmed.',
			}));
		} finally {
			this.pending.delete(key);
			this.updateCurrent(input, (consent) => ({ ...consent, decisionPending: false }));
			input.publish();
		}
		return true;
	}

	private updateCurrent(input: HypothesisAiDecisionRequest, update: (consent: HypothesisAiDecisionConsent) => HypothesisAiDecisionConsent): void {
		const current = input.getConsent();
		if (!isCurrentPreparation(current, input.preparationId, input.contentFingerprint)) {return;}
		input.setConsent(update(current));
	}
}

export function lifecycleFailureMessage(state: string, reason: string): string {
	if (state === 'expired') {return 'This disclosure expired. Prepare a fresh disclosure before deciding.';}
	if (state === 'invalidated') {return 'The scan evidence or provider configuration changed. Prepare a fresh disclosure.';}
	if (state === 'denied') {return 'This preparation was denied.';}
	return `Core did not record this decision (${reason}). Current state: ${state}.`;
}

function isCurrentPreparation(consent: HypothesisAiDecisionConsent | undefined, preparationId: string, contentFingerprint: string): consent is HypothesisAiDecisionConsent {
	return consent?.manifest?.preparationId === preparationId && consent.contentFingerprint === contentFingerprint;
}

function decisionKey(preparationId: string, contentFingerprint: string): string {
	return `${preparationId}:${contentFingerprint}`;
}

function getErrorCode(error: unknown): string | undefined {
	return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' ? error.code : undefined;
}

import { AITransport } from '../ai/utils/request';
import { HypothesisAiCommitControl, HypothesisAiRequestContext } from './contracts';
import { HypothesisAiBoundExecutionRequest } from './hypothesisAiConfiguration';
import { persistHypothesisAiValidationResult } from './aiProposalValidation';
import { sendHypothesisAiBoundRequest } from './hypothesisAiConfiguration';
import { HypothesisAiExecutor } from './hypothesisAiPreparation';
import { readAndValidateHypothesisAiResponse } from './hypothesisAiResponse';
import { HypothesisStoreService } from './hypothesisStore';
import * as crypto from 'node:crypto';

/**
 * Core-owned execution pipeline. Its transport is injected by composition, while
 * request construction, response validation, preparation association and commit
 * remain fixed here. Tests inject a fake AITransport; CoreRuntime constructs
 * this production-intended pipeline but keeps it unreachable behind its closed
 * source-controlled activation gate until a separate review.
 */
export function createHypothesisAiExecutor(transport: AITransport, store: HypothesisStoreService): HypothesisAiExecutor {
	return async (contentEnvelope: string, signal: AbortSignal, request?: HypothesisAiBoundExecutionRequest, commitControl?: HypothesisAiCommitControl, context?: HypothesisAiRequestContext): Promise<{ proposalCount: number }> => {
		if (!request || !context || request.plan.contentFingerprint.length !== 64
			|| request.plan.contentFingerprint !== crypto.createHash('sha256').update(contentEnvelope, 'utf8').digest('hex')
			|| signal.aborted) {
			throw new Error('Hypothesis synthesis execution is unavailable.');
		}
		const response = await sendHypothesisAiBoundRequest(transport, request, signal);
		if (signal.aborted) {throw new Error('Hypothesis synthesis was cancelled.');}
		const validation = await readAndValidateHypothesisAiResponse(response, context, signal);
		if (signal.aborted || !validation.valid) {throw new Error('Hypothesis provider response was not accepted.');}
		const persisted = await persistHypothesisAiValidationResult(validation, store, { id: request.plan.preparationId, providerId: request.plan.providerId, modelId: request.plan.modelId }, signal, commitControl);
		if (!persisted) {throw new Error('Hypothesis proposal persistence was rejected.');}
		return { proposalCount: validation.proposals.length };
	};
}

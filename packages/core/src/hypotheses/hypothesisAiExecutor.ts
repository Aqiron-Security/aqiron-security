import { AITransport } from '../ai/utils/request';
import { HypothesisAiCommitControl, HypothesisAiRequestContext } from './contracts';
import { HypothesisAiBoundExecutionRequest } from './hypothesisAiConfiguration';
import { persistHypothesisAiValidationResult } from './aiProposalValidation';
import { sendHypothesisAiBoundRequest } from './hypothesisAiConfiguration';
import { HypothesisAiExecutor } from './hypothesisAiPreparation';
import { readAndValidateHypothesisAiResponse } from './hypothesisAiResponse';
import { HypothesisStoreService } from './hypothesisStore';
import * as crypto from 'node:crypto';

export interface HypothesisAiExecutionDiagnostic {
	stage: 'executor-preflight' | 'request-construction' | 'transport' | 'response-validation' | 'persistence' | 'complete' | 'unknown';
	outcome: 'failed' | 'succeeded';
	failureCategory?: 'executor-preflight-failed' | 'request-construction-failed' | 'transport-failed' | 'response-validation-failed' | 'persistence-failed' | 'unexpected-executor-failure';
	/** Adapter invocation is not proof of network delivery or remote processing. */
	transportInvoked: boolean;
	transportResponseReceived: boolean;
	providerResponseValidated: boolean;
	persistenceAttempted: boolean;
}

/**
 * Core-owned execution pipeline. Its transport is injected by composition, while
 * request construction, response validation, preparation association and commit
 * remain fixed here. Tests inject a fake AITransport; CoreRuntime constructs
 * this production-intended pipeline but keeps it unreachable behind its closed
 * source-controlled activation gate until a separate review.
 */
export function createHypothesisAiExecutor(transport: AITransport, store: HypothesisStoreService, onDiagnostic?: (diagnostic: HypothesisAiExecutionDiagnostic) => void): HypothesisAiExecutor {
	return async (contentEnvelope: string, signal: AbortSignal, request?: HypothesisAiBoundExecutionRequest, commitControl?: HypothesisAiCommitControl, context?: HypothesisAiRequestContext): Promise<{ proposalCount: number }> => {
		let stage: HypothesisAiExecutionDiagnostic['stage'] = 'executor-preflight';
		let transportInvoked = false;
		let transportResponseReceived = false;
		let providerResponseValidated = false;
		let persistenceAttempted = false;
		let diagnosticReported = false;
		const report = (outcome: HypothesisAiExecutionDiagnostic['outcome'], failureCategory?: HypothesisAiExecutionDiagnostic['failureCategory']): void => {
			diagnosticReported = true;
			try {onDiagnostic?.({ stage, outcome, ...(failureCategory ? { failureCategory } : {}), transportInvoked, transportResponseReceived, providerResponseValidated, persistenceAttempted });} catch { /* diagnostics must never affect execution */ }
		};
		const fail = (failureCategory: NonNullable<HypothesisAiExecutionDiagnostic['failureCategory']>): never => {
			report('failed', failureCategory);
			throw new Error('Hypothesis synthesis execution failed.');
		};
		try {
			if (!request || !context || request.plan.contentFingerprint.length !== 64
				|| request.plan.contentFingerprint !== crypto.createHash('sha256').update(contentEnvelope, 'utf8').digest('hex')
				|| signal.aborted) {return fail('executor-preflight-failed');}

			stage = 'request-construction';
			let response: Awaited<ReturnType<AITransport['request']>>;
			try {
				response = await sendHypothesisAiBoundRequest(transport, request, signal, () => {transportInvoked = true; stage = 'transport';});
			} catch {
				stage = transportInvoked ? 'transport' : 'request-construction';
				return fail(transportInvoked ? 'transport-failed' : 'request-construction-failed');
			}
			transportResponseReceived = true;
			stage = 'response-validation';
			let validation: Awaited<ReturnType<typeof readAndValidateHypothesisAiResponse>>;
			try {validation = await readAndValidateHypothesisAiResponse(response, context, signal);}
			catch {return fail('response-validation-failed');}
			if (signal.aborted || !validation.valid) {return fail('response-validation-failed');}
			providerResponseValidated = true;

			stage = 'persistence';
			if (commitControl?.beforeCommit && !(await commitControl.beforeCommit())) {return fail('persistence-failed');}
			if (signal.aborted || (commitControl?.canCommit && !commitControl.canCommit())) {return fail('persistence-failed');}
			persistenceAttempted = true;
			let persisted: boolean;
			try {persisted = await persistHypothesisAiValidationResult(validation, store, { id: request.plan.preparationId, providerId: request.plan.providerId, modelId: request.plan.modelId }, signal, commitControl);}
			catch {return fail('persistence-failed');}
			if (!persisted) {return fail('persistence-failed');}
			stage = 'complete';
			report('succeeded');
			return { proposalCount: validation.proposals.length };
		} catch {
			if (!diagnosticReported) {
				stage = 'unknown';
				report('failed', 'unexpected-executor-failure');
			}
			throw new Error('Hypothesis synthesis execution failed.');
		}
	};
}

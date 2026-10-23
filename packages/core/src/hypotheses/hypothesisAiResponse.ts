import { AIHttpError, AIHttpResponse } from '../ai/utils/request';
import { HypothesisAiRequestContext } from './contracts';
import { HYPOTHESIS_AI_RESPONSE_LIMITS, validateHypothesisAiResponse, HypothesisAiValidationResult, hypothesisAiRequestContextProvider } from './aiProposalValidation';

/**
 * Parses provider-specific, non-streaming HTTP JSON envelopes. These are API
 * contract fixtures and strict adapters; they do not assert live compatibility.
 */
export async function readAndValidateHypothesisAiResponse(response: AIHttpResponse, context: HypothesisAiRequestContext, signal?: AbortSignal): Promise<HypothesisAiValidationResult> {
	if (!response || response.ok !== true || !Number.isInteger(response.status) || response.status < 200 || response.status >= 300) {throw new AIHttpError(response?.status ?? 502);}
	if (signal?.aborted) {throw new AIHttpError(408);}
	const contentType = Object.entries(response.headers ?? {}).find(([key]) => key.toLowerCase() === 'content-type')?.[1]?.split(';', 1)[0].trim().toLowerCase();
	if (contentType !== 'application/json') {return { valid: false, error: 'malformed-response' };}
	try {
		// Production AITransport exposes a byte-limited stream reader and the
		// synthesis plan sets its transport cap to the same maximum.
		const raw = await response.text();
		if (signal?.aborted) {throw new AIHttpError(408);}
		if (Buffer.byteLength(raw, 'utf8') > HYPOTHESIS_AI_RESPONSE_LIMITS.maxResponseBytes) {return { valid: false, error: 'response-too-large' };}
		let envelope: unknown;
		try { envelope = JSON.parse(raw) as unknown; } catch {return { valid: false, error: 'malformed-response' };}
		if (!isRecord(envelope) || envelope.error !== undefined) {return { valid: false, error: 'invalid-shape' };}
		const modelText = extractModelText(hypothesisAiRequestContextProvider(context), envelope);
		if (modelText === undefined) {return { valid: false, error: 'invalid-shape' };}
		if (Buffer.byteLength(modelText, 'utf8') > HYPOTHESIS_AI_RESPONSE_LIMITS.maxResponseBytes) {return { valid: false, error: 'response-too-large' };}
		return validateHypothesisAiResponse(modelText, context);
	} catch (error) {
		if (error instanceof AIHttpError) {throw error;}
		throw new AIHttpError(signal?.aborted ? 408 : 502);
	}
}

function extractModelText(provider: string | undefined, value: unknown): string | undefined {
	if (!provider || !isRecord(value)) {return undefined;}
	switch (provider) {
		case 'openai': case 'openrouter': {
			if (!Array.isArray(value.choices) || value.choices.length !== 1) {return undefined;}
			const choice = value.choices[0];
			if (!isRecord(choice) || choice.finish_reason !== 'stop' || !isRecord(choice.message) || (choice.message.refusal !== undefined && choice.message.refusal !== null) || choice.message.tool_calls !== undefined || choice.message.function_call !== undefined || typeof choice.message.content !== 'string') {return undefined;}
			return choice.message.content;
		}
		case 'claude': {
			if (value.type !== 'message' || value.role !== 'assistant' || value.stop_reason !== 'end_turn' || !Array.isArray(value.content) || value.content.length === 0) {return undefined;}
			const text: string[] = [];
			for (const block of value.content) {
				if (!isRecord(block) || block.type !== 'text' || typeof block.text !== 'string') {return undefined;}
				text.push(block.text);
			}
			return text.join('');
		}
		case 'gemini': {
			if (isRecord(value.promptFeedback) && value.promptFeedback.blockReason !== undefined && value.promptFeedback.blockReason !== null) {return undefined;}
			if (!Array.isArray(value.candidates) || value.candidates.length !== 1) {return undefined;}
			const candidate = value.candidates[0];
			if (!isRecord(candidate) || candidate.finishReason !== 'STOP' || !isRecord(candidate.content) || !Array.isArray(candidate.content.parts) || candidate.content.parts.length === 0) {return undefined;}
			const text: string[] = [];
			for (const part of candidate.content.parts) {
				if (!isRecord(part) || typeof part.text !== 'string' || part.thought === true) {return undefined;}
				text.push(part.text);
			}
			return text.join('');
		}
	}
	return undefined;
}

function isRecord(value: unknown): value is Record<string, any> {return Boolean(value && typeof value === 'object' && !Array.isArray(value));}

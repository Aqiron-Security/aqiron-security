import { AIModel, AIProvider, ChatRequest, StreamChunk } from '../shared/ai';

export const HYPOTHESIS_AI_ADAPTER_LIMITS = Object.freeze({
	// UTF-8 bytes in the complete serialized request envelope, not model tokens or billing units.
	maxRequestBytes: 16_384,
	maxResponseBytes: 16_384,
	maxResponseBodyBytes: 65_536,
	maxSseEventBytes: 65_536,
	defaultTimeoutMs: 30_000,
	maxTimeoutMs: 60_000,
	maxProviderIdLength: 64,
	maxModelIdLength: 256,
});

export type HypothesisAiInvocationError =
	| 'invalid-request'
	| 'cancelled'
	| 'timed-out'
	| 'provider-failure'
	| 'invalid-provider-output'
	| 'response-too-large'
	| 'empty-response';

export type HypothesisAiInvocationResult =
	| { ok: true; providerId: string; modelId: string; text: string }
	| { ok: false; error: HypothesisAiInvocationError };

export interface HypothesisAiInvocationOptions {
	/** Provider instance selected by Core for this operation; no registry lookup occurs. */
	provider: AIProvider;
	providerId: string;
	model: Pick<AIModel, 'id' | 'providerId'>;
	prompt: string;
	signal?: AbortSignal;
	timeoutMs?: number;
}

const ABORTED = Symbol('hypothesis-ai-aborted');

interface Utf8Counter { bytes: number; pendingHighSurrogate: boolean }

/**
 * Internal, provider-bound invocation seam. It returns untrusted text only;
 * callers must pass the text through the Slice 1 validator. It never logs,
 * emits stream events, retries, selects providers, or persists results.
 */
export async function invokeHypothesisAi(options: HypothesisAiInvocationOptions): Promise<HypothesisAiInvocationResult> {
	if (!options || typeof options !== 'object') {return { ok: false, error: 'invalid-request' };}
	const { provider, providerId, model, prompt, signal } = options;
	const timeoutMs = options.timeoutMs ?? HYPOTHESIS_AI_ADAPTER_LIMITS.defaultTimeoutMs;
	if (!provider || typeof provider.chat !== 'function' || typeof provider.id !== 'string'
		|| !providerId || providerId.length > HYPOTHESIS_AI_ADAPTER_LIMITS.maxProviderIdLength || provider.id !== providerId
		|| !model || typeof model.id !== 'string' || !model.id || model.id.length > HYPOTHESIS_AI_ADAPTER_LIMITS.maxModelIdLength
		|| model.providerId !== providerId || typeof prompt !== 'string'
		|| !Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > HYPOTHESIS_AI_ADAPTER_LIMITS.maxTimeoutMs) {
		return { ok: false, error: 'invalid-request' };
	}
	if (signal?.aborted) {return { ok: false, error: 'cancelled' };}
	if (Buffer.byteLength(prompt, 'utf8') > HYPOTHESIS_AI_ADAPTER_LIMITS.maxRequestBytes) {return { ok: false, error: 'invalid-request' };}
	const serializedRequest = JSON.stringify({
		model: model.id,
		messages: [{ role: 'user', content: prompt }],
		temperature: 0,
		maxTokens: 2048,
		stream: true,
		timeoutMs,
		retries: 0,
	});
	if (Buffer.byteLength(serializedRequest, 'utf8') > HYPOTHESIS_AI_ADAPTER_LIMITS.maxRequestBytes) {return { ok: false, error: 'invalid-request' };}

	const controller = new AbortController();
	let abortKind: 'cancelled' | 'timed-out' | undefined;
	let terminalError: HypothesisAiInvocationError | undefined;
	let acceptingOutput = true;
	let iterator: AsyncGenerator<StreamChunk> | undefined;
	let detached = false;
	let resolveAborted!: (value: typeof ABORTED) => void;
	const aborted = new Promise<typeof ABORTED>((resolve) => { resolveAborted = resolve; });
	const detach = () => {
		if (detached || !iterator) {return;}
		detached = true;
		try {
			// Do not wait for provider-controlled iterator cleanup: a pending next() may
			// prevent finalization, and return() itself may never settle.
			const activeIterator = iterator;
			const returnMethod = activeIterator.return;
			if (typeof returnMethod === 'function') { void Promise.resolve().then(() => returnMethod.call(activeIterator, undefined)).catch(() => undefined); }
		} catch { /* best-effort detachment; preserve the original safe error */ }
	};
	const terminate = (error: HypothesisAiInvocationError, kind?: 'cancelled' | 'timed-out') => {
		if (!acceptingOutput) {return;}
		acceptingOutput = false;
		terminalError = error;
		if (kind) {abortKind = kind;}
		if (!controller.signal.aborted) {controller.abort();}
		resolveAborted(ABORTED);
		detach();
	};
	let signalAbortListener: (() => void) | undefined;
	if (signal) {
		signalAbortListener = () => terminate('cancelled', 'cancelled');
		signal.addEventListener('abort', signalAbortListener, { once: true });
	}
	const deadline = Date.now() + timeoutMs;
	const timer = setTimeout(() => terminate('timed-out', 'timed-out'), timeoutMs);
	const request: ChatRequest = {
		model: model.id,
		messages: [{ role: 'user', content: prompt }],
		temperature: 0,
		maxTokens: 2048,
		stream: true,
		timeoutMs,
		retries: 0,
		abortSignal: controller.signal,
		transportLimits: {
			maxRequestBodyBytes: HYPOTHESIS_AI_ADAPTER_LIMITS.maxRequestBytes,
			maxResponseBodyBytes: HYPOTHESIS_AI_ADAPTER_LIMITS.maxResponseBodyBytes,
			maxSseEventBytes: HYPOTHESIS_AI_ADAPTER_LIMITS.maxSseEventBytes,
		},
	};
	const chunks: string[] = [];
	const byteCounter: Utf8Counter = { bytes: 0, pendingHighSurrogate: false };
	try {
		if (signal?.aborted) {terminate('cancelled', 'cancelled'); return { ok: false, error: 'cancelled' };}
		iterator = provider.chat(request);
		if (!acceptingOutput) {detach(); return { ok: false, error: terminalError ?? 'cancelled' };}
		while (true) {
			const next = Promise.resolve().then(() => iterator!.next()).then(
				(value) => ({ type: 'next' as const, value }),
				() => ({ type: 'failure' as const }),
			);
			const outcome = await Promise.race([next, aborted.then(() => ({ type: 'aborted' as const }))]);
			if (!acceptingOutput || outcome.type === 'aborted') {return { ok: false, error: terminalError ?? 'cancelled' };}
			if (Date.now() >= deadline) {terminate('timed-out', 'timed-out'); return { ok: false, error: 'timed-out' };}
			if (outcome.type === 'failure') {terminate('provider-failure'); return { ok: false, error: 'provider-failure' };}
			if (outcome.value.done) {break;}
			const chunk = outcome.value.value;
			if (!chunk || (chunk.type !== 'token' && chunk.type !== 'done' && chunk.type !== 'error')) {
				terminate('invalid-provider-output'); return { ok: false, error: 'invalid-provider-output' };
			}
			if (chunk.type === 'error') {terminate('provider-failure'); return { ok: false, error: 'provider-failure' };}
			if (chunk.type === 'done') {break;}
			if (chunk.content === undefined) {continue;}
			if (typeof chunk.content !== 'string') {
				terminate('invalid-provider-output'); return { ok: false, error: 'invalid-provider-output' };
			}
			if (!addUtf8Bytes(byteCounter, chunk.content, HYPOTHESIS_AI_ADAPTER_LIMITS.maxResponseBytes)) {
				terminate('response-too-large'); return { ok: false, error: 'response-too-large' };
			}
			chunks.push(chunk.content);
		}
		if (!acceptingOutput) {return { ok: false, error: terminalError ?? 'cancelled' };}
		if (Date.now() >= deadline) {terminate('timed-out', 'timed-out'); return { ok: false, error: 'timed-out' };}
		if (byteCounter.pendingHighSurrogate) {
			byteCounter.pendingHighSurrogate = false;
			byteCounter.bytes += 3; // Node encodes an unmatched UTF-16 surrogate as U+FFFD.
			if (byteCounter.bytes > HYPOTHESIS_AI_ADAPTER_LIMITS.maxResponseBytes) {
				terminate('response-too-large'); return { ok: false, error: 'response-too-large' };
			}
		}
		const text = chunks.join('');
		if (text.length === 0) {terminate('empty-response'); return { ok: false, error: 'empty-response' };}
		return { ok: true, providerId, modelId: model.id, text };
	} catch {
		terminate(controller.signal.aborted ? abortKind ?? 'cancelled' : 'provider-failure', abortKind);
		return { ok: false, error: terminalError ?? 'provider-failure' };
	} finally {
		acceptingOutput = false;
		clearTimeout(timer);
		if (signal && signalAbortListener) {signal.removeEventListener('abort', signalAbortListener);}
	}
}

/** Incrementally mirrors Buffer.byteLength(concatenated, 'utf8') without re-encoding prior chunks. */
function addUtf8Bytes(counter: Utf8Counter, text: string, limit: number): boolean {
	if (text.length === 0) {return true;}
	let offset = 0;
	if (counter.pendingHighSurrogate) {
		counter.pendingHighSurrogate = false;
		if (text.length > 0 && isLowSurrogate(text.charCodeAt(0))) {
			counter.bytes += 4;
			offset = 1;
		} else {
			counter.bytes += 3;
		}
		if (counter.bytes > limit) {return false;}
	}
	for (let i = offset; i < text.length; i++) {
		const code = text.charCodeAt(i);
		if (code <= 0x7f) {counter.bytes += 1;}
		else if (code <= 0x7ff) {counter.bytes += 2;}
		else if (isHighSurrogate(code)) {
			if (i + 1 < text.length && isLowSurrogate(text.charCodeAt(i + 1))) {counter.bytes += 4; i++;}
			else if (i === text.length - 1) {counter.pendingHighSurrogate = true;}
			else {counter.bytes += 3;}
		} else if (isLowSurrogate(code)) {counter.bytes += 3;}
		else {counter.bytes += 3;}
		if (counter.bytes > limit) {return false;}
	}
	return true;
}

function isHighSurrogate(code: number): boolean {return code >= 0xd800 && code <= 0xdbff;}
function isLowSurrogate(code: number): boolean {return code >= 0xdc00 && code <= 0xdfff;}

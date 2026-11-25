import { NetworkClient, NetworkResponse } from '../../shared/platform';
import { createTimeoutSignal, TimeoutError } from './timeout';

export class AIHttpError extends Error {
	public readonly status: number;
	public readonly category: ProviderErrorCategory;
	public readonly outcome: 'http' | 'timeout' | 'cancelled' | 'transport' | 'limit' | 'invalid-request';

	constructor(
		status: number,
		_untrustedMessage?: string,
		_untrustedDetails?: unknown,
		outcome?: AIHttpError['outcome'],
	) {
		// The legacy optional arguments remain accepted for source compatibility,
		// but are intentionally neither retained nor reflected in the Error.
		const safeStatus = Number.isSafeInteger(status) && status >= 0 && status <= 599 ? status : 502;
		const category = classifyProviderError(safeStatus);
		super(`Provider request failed (${category}, HTTP ${safeStatus}).`);
		this.name = 'AIHttpError';
		this.status = safeStatus;
		this.category = category;
		this.outcome = outcome ?? (safeStatus === 413 ? 'limit' : safeStatus === 400 ? 'invalid-request' : safeStatus === 408 ? 'timeout' : safeStatus >= 400 ? 'http' : 'transport');
	}
}

export type ProviderErrorCategory = 'authentication' | 'rate-limited' | 'request-rejected' | 'provider-unavailable' | 'transport-failure';

export interface OpenRouterRejectedRequest {
	status: number;
	category: ProviderErrorCategory;
}

function classifyProviderError(status: number): ProviderErrorCategory {
	if (status === 0 || status === 408) {return 'transport-failure';}
	if (status === 401 || status === 403) {return 'authentication';}
	if (status === 429) {return 'rate-limited';}
	if (status >= 500) {return 'provider-unavailable';}
	return 'request-rejected';
}

export interface AIRequestOptions {
	method?: 'GET' | 'POST' | 'DELETE';
	headers?: Record<string, string | undefined>;
	body?: unknown;
	/** Internal bound-request seam: forward this exact JSON byte string without another serialization pass. */
	serializedBody?: string;
	/** Serialized exactly once after provider framing and passed unchanged to NetworkClient. */
	maxRequestBodyBytes?: number;
	maxResponseBodyBytes?: number;
	maxSseEventBytes?: number;
	timeoutMs: number;
	abortSignal?: AbortSignal;
}

export interface AIHttpResponse {
	ok: boolean;
	status: number;
	headers: Record<string, string>;
	text(): Promise<string>;
	json<T = unknown>(): Promise<T>;
	body?: ReadableStream<Uint8Array> | null;
	maxResponseBodyBytes?: number;
	maxSseEventBytes?: number;
}

export interface AITransport {
	request(url: string, options: AIRequestOptions): Promise<AIHttpResponse>;
}

export const AI_TRANSPORT_LIMITS = Object.freeze({
	maxRequestBodyBytes: 1_048_576,
	maxResponseBodyBytes: 4_194_304,
	maxErrorBodyBytes: 8_192,
	maxSseEventBytes: 65_536,
	maxResponseChunks: 65_536,
});

export function createNetworkTransport(client: NetworkClient): AITransport {
	return {
		async request(url: string, options: AIRequestOptions): Promise<AIHttpResponse> {
			let serializedBody: string | undefined;
			try {
				if (options.serializedBody !== undefined && options.body !== undefined) {throw new Error('ambiguous-body');}
				serializedBody = options.serializedBody ?? (options.body === undefined ? undefined : JSON.stringify(options.body));
				if (options.body !== undefined && typeof serializedBody !== 'string') {
					throw new Error('Provider request is not JSON serializable.');
				}
			}
			catch { throw new AIHttpError(400, 'Provider request could not be serialized.'); }
			const requestLimit = options.maxRequestBodyBytes ?? AI_TRANSPORT_LIMITS.maxRequestBodyBytes;
			if (!Number.isSafeInteger(requestLimit) || requestLimit < 1 || requestLimit > AI_TRANSPORT_LIMITS.maxRequestBodyBytes || (serializedBody !== undefined && Buffer.byteLength(serializedBody, 'utf8') > requestLimit)) {
				throw new AIHttpError(413, 'Provider request exceeded the configured size limit.');
			}
			const maxResponseBytes = options.maxResponseBodyBytes ?? AI_TRANSPORT_LIMITS.maxResponseBodyBytes;
			const maxSseEventBytes = options.maxSseEventBytes ?? AI_TRANSPORT_LIMITS.maxSseEventBytes;
			if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > AI_TRANSPORT_LIMITS.maxResponseBodyBytes || !Number.isSafeInteger(maxSseEventBytes) || maxSseEventBytes < 1 || maxSseEventBytes > AI_TRANSPORT_LIMITS.maxSseEventBytes) { throw new AIHttpError(413, 'Provider response limit is invalid.'); }
			const timeout = createTimeoutSignal(options.timeoutMs, options.abortSignal);
			let disposeResponse = () => timeout.dispose();
			let responseReturned = false;
			try {
				let response: NetworkResponse;
				try {
					response = await client.request(url, {
						method: options.method ?? 'GET',
						headers: cleanHeaders({
							Accept: 'application/json',
							'Content-Type': options.body === undefined ? undefined : 'application/json',
							...options.headers,
						}),
						body: serializedBody,
						timeoutMs: options.timeoutMs,
						abortSignal: timeout.signal,
						redirect: 'manual',
					});
				} catch (error) {
					// Network client exceptions can contain request or response data.
					// Keep only a safe status/category and never retain the exception or cause.
					throw new AIHttpError(error instanceof AIHttpError ? error.status : timeout.signal.aborted ? 408 : 502, undefined, undefined, timeout.signal.aborted ? (timeout.signal.reason instanceof TimeoutError ? 'timeout' : 'cancelled') : 'transport');
				}
				const advertisedBytes = responseHeader(response.headers, 'content-length');
				if (advertisedBytes !== undefined && /^\d+$/.test(advertisedBytes) && Number(advertisedBytes) > maxResponseBytes) {
					try { await response.body?.cancel(); } catch { /* stop an oversized response best-effort */ }
					throw new AIHttpError(413, undefined, undefined, 'limit');
				}
				const bounded = createBoundedResponseBody(response.body, maxResponseBytes, timeout.dispose, timeout.signal);
				disposeResponse = bounded.dispose;
				const boundedResponse: NetworkResponse = { ...response, body: bounded.stream };
				if (!response.ok) {
					await discardErrorBody(boundedResponse, Math.min(maxResponseBytes, AI_TRANSPORT_LIMITS.maxErrorBodyBytes));
					// Provider body bytes are deliberately discarded without decoding.
					throw new AIHttpError(response.status);
				}
				const result: AIHttpResponse = {
					ok: response.ok,
					status: response.status,
					headers: response.headers,
					text: async () => readBoundedText(boundedResponse),
					json: async <T = unknown>() => {
						const text = await readBoundedText(boundedResponse);
						try {return JSON.parse(text) as T;}
						catch {throw new AIHttpError(502);}
					},
					body: bounded.stream,
					maxResponseBodyBytes: maxResponseBytes,
					maxSseEventBytes,
				};
				responseReturned = true;
				return result;
			} finally {
				// For streaming responses, the wrapper owns timeout disposal through EOF/cancel.
				if (!responseReturned) { disposeResponse(); }
			}
		},
	};
}

/** Consume only a bounded number of raw error bytes and never decode provider text. */
async function discardErrorBody(response: NetworkResponse, maxBytes = 8192): Promise<void> {
	if (!response.body) {return;}
	const reader = response.body.getReader();
	let byteCount = 0;
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) {return;}
			if (value.byteLength > maxBytes - byteCount) {
				cancelReader(reader);
				return;
			}
			byteCount += value.byteLength;
		}
	} catch (error) {
		cancelReader(reader);
		if (error instanceof AIHttpError) {throw error;}
	} finally {
		try { reader.releaseLock(); } catch { /* already released by a cancelled stream */ }
	}
}

function createBoundedResponseBody(body: ReadableStream<Uint8Array> | null | undefined, maxBytes: number, dispose: () => void, signal: AbortSignal): { stream: ReadableStream<Uint8Array>; dispose: () => void } {
	let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
	let streamController: ReadableStreamDefaultController<Uint8Array> | undefined;
	let bytesRead = 0;
	let chunksRead = 0;
	let finished = false;
	const finish = () => {
		if (finished) { return; }
		finished = true;
		signal.removeEventListener('abort', abort);
		try { reader?.releaseLock(); } catch { /* best effort after cancellation */ }
		dispose();
	};
	const abort = () => {
		cancelReader(reader);
		try { streamController?.error(abortError(signal)); } catch { /* stream may already be terminal */ }
		finish();
	};
	const stream = new ReadableStream<Uint8Array>({
		start(controller) {
			streamController = controller;
			if (!body) {
				controller.error(new AIHttpError(502, 'Provider response stream is unavailable.'));
				finish();
				return;
			}
			reader = body.getReader();
			signal.addEventListener('abort', abort, { once: true });
			if (signal.aborted) { abort(); controller.error(new AIHttpError(408, 'Provider request was cancelled or timed out.')); }
		},
		async pull(controller) {
			if (finished) { return; }
			try {
				const { value, done } = await reader!.read();
				if (done) { controller.close(); finish(); return; }
				if (++chunksRead > AI_TRANSPORT_LIMITS.maxResponseChunks) {
					cancelReader(reader);
					controller.error(new AIHttpError(413, 'Provider response exceeded the configured chunk limit.'));
					finish();
					return;
				}
				if (value.byteLength > maxBytes - bytesRead) {
					cancelReader(reader);
					controller.error(new AIHttpError(413, 'Provider response exceeded the configured size limit.'));
					finish();
					return;
				}
				bytesRead += value.byteLength;
				controller.enqueue(value);
			} catch {
				controller.error(signal.aborted ? abortError(signal) : new AIHttpError(502, undefined, undefined, 'transport'));
				finish();
			}
		},
		cancel() { cancelReader(reader); finish(); },
	});
	return { stream, dispose: finish };
}

function abortError(signal: AbortSignal): AIHttpError {
	return signal.reason instanceof TimeoutError
		? new AIHttpError(408, undefined, undefined, 'timeout')
		: new AIHttpError(408, undefined, undefined, 'cancelled');
}

function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array> | undefined): void {
	if (!reader) { return; }
	try { void reader.cancel().catch(() => undefined); } catch { /* best effort */ }
}

function responseHeader(headers: Record<string, string>, name: string): string | undefined {
	const key = Object.keys(headers).find(value => value.toLowerCase() === name);
	return key === undefined ? undefined : headers[key];
}

async function readBoundedText(response: NetworkResponse): Promise<string> {
	if (!response.body) { throw new AIHttpError(502, 'Provider response stream is unavailable.'); }
	const reader = response.body.getReader();
	const decoder = new TextDecoder('utf-8', { fatal: true });
	const textParts: string[] = [];
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) { textParts.push(decoder.decode()); return textParts.join(''); }
			textParts.push(decoder.decode(value, { stream: true }));
		}
	} catch (error) {
		cancelReader(reader);
		if (error instanceof AIHttpError) { throw error; }
		throw new AIHttpError(502, 'Provider response exceeded a transport limit or contained invalid UTF-8.');
	} finally {
		try { reader.releaseLock(); } catch { /* stream cleanup may already release it */ }
	}
}

export async function* parseNdjsonStream(response: AIHttpResponse): AsyncGenerator<unknown> {
	const reader = await toReader(response);
	const decoder = new TextDecoder();
	let buffer = '';
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) {
				break;
			}
			buffer += decoder.decode(value, { stream: true });
			const lines = buffer.split(/\r?\n/);
			buffer = lines.pop() ?? '';
			for (const line of lines) {
				const trimmed = line.trim();
				if (trimmed) {
					yield JSON.parse(trimmed);
				}
			}
		}
		buffer += decoder.decode();
		if (buffer.trim()) {
			yield JSON.parse(buffer.trim());
		}
	} finally {
		reader.releaseLock();
	}
}

export interface SseStreamEvent {
	data?: unknown;
	done: boolean;
}

export async function* parseSseStream(response: AIHttpResponse, onEvent?: (event: SseStreamEvent) => void, responseLimit?: number, eventLimit?: number): AsyncGenerator<unknown> {
	const maxResponseBytes = responseLimit ?? response.maxResponseBodyBytes ?? AI_TRANSPORT_LIMITS.maxResponseBodyBytes;
	const maxEventBytes = eventLimit ?? response.maxSseEventBytes ?? AI_TRANSPORT_LIMITS.maxSseEventBytes;
	if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > AI_TRANSPORT_LIMITS.maxResponseBodyBytes || !Number.isSafeInteger(maxEventBytes) || maxEventBytes < 1 || maxEventBytes > AI_TRANSPORT_LIMITS.maxSseEventBytes) { throw new AIHttpError(413, 'Provider response limit is invalid.'); }
	const reader = await toReader(response);
	const decoder = new TextDecoder('utf-8', { fatal: true });
	let lineParts: string[] = [];
	let eventLines: string[] = [];
	let lineBytes = 0;
	let eventBytes = 0;
	let responseBytes = 0;
	let responseChunks = 0;
	let afterCarriageReturn = false;
	let completedNormally = false;
	const appendLineText = (controllerText: string, byteLength: number) => {
		if (byteLength > maxEventBytes - eventBytes || byteLength > maxEventBytes - lineBytes) {
			throw new AIHttpError(413, 'Provider response event exceeded the configured size limit.');
		}
		lineBytes += byteLength;
		eventBytes += byteLength;
		lineParts.push(controllerText);
	};
	const finishLine = () => {
		const line = lineParts.join('');
		lineParts = [];
		lineBytes = 0;
		if (line.length === 0) { return true; }
		eventLines.push(line);
		return false;
	};
	const decodeEvent = (lines: string[]) => {
		const data: string[] = [];
		for (const line of lines) {
			if (!line.startsWith('data:')) { continue; }
			let value = line.slice(5);
			if (value.startsWith(' ')) { value = value.slice(1); }
			data.push(value);
		}
		return data.join('\n');
	};
	const processText = function* (text: string): Generator<unknown> {
		for (let i = 0; i < text.length; i++) {
			const code = text.charCodeAt(i);
			if (code === 13) {
				const wasBlank = finishLine();
				eventBytes++;
				if (eventBytes > maxEventBytes) { throw new AIHttpError(413, 'Provider response event exceeded the configured size limit.'); }
				afterCarriageReturn = true;
				if (wasBlank) {
					const eventText = decodeEvent(eventLines);
					eventLines = [];
					eventBytes = 0;
					const parsed = dispatchSseData(eventText, onEvent);
					if (parsed !== undefined) { yield parsed; }
				}
				continue;
			}
			if (code === 10) {
				if (afterCarriageReturn) { afterCarriageReturn = false; continue; }
				const wasBlank = finishLine();
				eventBytes++;
				if (eventBytes > maxEventBytes) { throw new AIHttpError(413, 'Provider response event exceeded the configured size limit.'); }
				if (wasBlank) {
					const eventText = decodeEvent(eventLines);
					eventLines = [];
					eventBytes = 0;
					const parsed = dispatchSseData(eventText, onEvent);
					if (parsed !== undefined) { yield parsed; }
				}
				continue;
			}
			afterCarriageReturn = false;
			let value = text[i]!;
			if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) { value += text[++i]!; }
			appendLineText(value, Buffer.byteLength(value, 'utf8'));
		}
	};
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) {
				break;
			}
			if (++responseChunks > AI_TRANSPORT_LIMITS.maxResponseChunks) { throw new AIHttpError(413, 'Provider response exceeded the configured chunk limit.'); }
			if (value.byteLength > maxResponseBytes - responseBytes) { throw new AIHttpError(413, 'Provider response exceeded the configured size limit.'); }
			responseBytes += value.byteLength;
			const decoded = decoder.decode(value, { stream: true });
			for (const item of processText(decoded)) { yield item; }
		}
		const trailing = decoder.decode();
		for (const item of processText(trailing)) { yield item; }
		if (lineParts.length || eventLines.length) {
			if (lineParts.length) { eventLines.push(lineParts.join('')); lineParts = []; }
			const parsed = dispatchSseData(decodeEvent(eventLines), onEvent);
			if (parsed !== undefined) { yield parsed; }
		}
		completedNormally = true;
	} catch (error) {
		cancelReader(reader);
		if (error instanceof AIHttpError) { throw error; }
		throw new AIHttpError(502, 'Provider response contained malformed UTF-8 or invalid stream data.');
	} finally {
		if (!completedNormally) { cancelReader(reader); }
		try { reader.releaseLock(); } catch { /* cancellation may release the lock */ }
	}
}

function dispatchSseData(data: string, onEvent?: (event: SseStreamEvent) => void): unknown | undefined {
	if (!data) { return undefined; }
	if (data === '[DONE]') { onEvent?.({ done: true }); return undefined; }
	const parsed = JSON.parse(data);
	onEvent?.({ data: parsed, done: false });
	return parsed;
}

export function redactSecret(value: string): string {
	return value
		.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/g, 'Bearer [redacted]')
		.replace(/(api[_-]?key=)[^&\s]+/gi, '$1[redacted]')
		.replace(/(authorization["']?\s*:\s*["']?)[^"',\s]+/gi, '$1[redacted]');
}

export function normalizeProviderError(error: unknown): string {
	if (error instanceof AIHttpError) {
		if (error.category === 'authentication') {
			return 'Authentication failed. Check the saved provider credentials.';
		}
		if (error.category === 'rate-limited') {
			return 'The provider rate limit was reached (429). Wait a moment, switch API key/model, or use a provider account with more quota.';
		}
		if (error.status === 402) {
			return 'The provider rejected the request because the account may have no available credits.';
		}
		if (error.status === 404) {
			return 'The selected model or endpoint was not found (HTTP 404).';
		}
		if (error.category === 'provider-unavailable' || error.category === 'transport-failure') {
			return `The provider is temporarily unavailable (${error.status}). Try again shortly.`;
		}
		return `The provider rejected the request (HTTP ${error.status}).`;
	}
	if (error instanceof Error) {
		if (error.name === 'AbortError') {
			return 'Generation was cancelled.';
		}
		if (error.name === 'TimeoutError') {
			return 'The provider request timed out.';
		}
		return 'The provider transport failed. Review the safe status and category for troubleshooting.';
	}
	return 'The provider request failed.';
}

function cleanHeaders(headers: Record<string, string | undefined>): Record<string, string> {
	return Object.fromEntries(Object.entries(headers).filter((entry): entry is [string, string] => typeof entry[1] === 'string' && entry[1].length > 0));
}

async function toReader(response: AIHttpResponse): Promise<ReadableStreamDefaultReader<Uint8Array>> {
	if (!response.body) {
		throw new AIHttpError(0, 'The provider returned an empty response stream.');
	}
	return response.body.getReader();
}

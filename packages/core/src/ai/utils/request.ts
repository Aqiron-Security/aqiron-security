import { NetworkClient, NetworkResponse } from '../../shared/platform';
import { createTimeoutSignal } from './timeout';

export class AIHttpError extends Error {
	public readonly providerError?: OpenRouterProviderError;

	constructor(
		public readonly status: number,
		message: string,
		providerError?: OpenRouterProviderError | string,
	) {
		super(message);
		this.name = 'AIHttpError';
		if (typeof providerError === 'string') {
			this.body = providerError;
		} else if (providerError) {
			// Keep the provider's original response available to typed internal
			// handling without making it enumerable/loggable by default.
			Object.defineProperty(this, 'providerError', { value: providerError, enumerable: false });
		}
	}

	public readonly body?: string;
}

export interface OpenRouterProviderError {
	code?: string;
	errorType?: string;
	providerCode?: string;
	parameter?: string;
	/** Original provider message; do not log or serialize this value. */
	originalMessage?: string;
	bodyFormat: 'json' | 'malformed-json' | 'non-json' | 'empty';
}

export interface OpenRouterRejectedRequest {
	status: number;
	providerId: 'openrouter';
	modelId: string;
	errorCode?: string;
	message: string;
	errorType?: string;
	providerCode?: string;
	parameter?: string;
	bodyFormat: OpenRouterProviderError['bodyFormat'];
}

export interface AIRequestOptions {
	method?: 'GET' | 'POST' | 'DELETE';
	headers?: Record<string, string | undefined>;
	body?: unknown;
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
}

export interface AITransport {
	request(url: string, options: AIRequestOptions): Promise<AIHttpResponse>;
}

export function createNetworkTransport(client: NetworkClient): AITransport {
	return {
		async request(url: string, options: AIRequestOptions): Promise<AIHttpResponse> {
			const timeout = createTimeoutSignal(options.timeoutMs, options.abortSignal);
			try {
				const response = await client.request(url, {
					method: options.method ?? 'GET',
					headers: cleanHeaders({
						Accept: 'application/json',
						'Content-Type': options.body === undefined ? undefined : 'application/json',
						...options.headers,
					}),
					body: options.body === undefined ? undefined : JSON.stringify(options.body),
					timeoutMs: options.timeoutMs,
					cancellationToken: undefined,
				});
				if (!response.ok) {
					const errorBody = await readErrorBody(response);
					const parsed = parseProviderError(errorBody, response.status);
					throw new AIHttpError(response.status, parsed.safeMessage, parsed.details);
				}
				return {
					ok: response.ok,
					status: response.status,
					headers: response.headers,
					text: async () => response.text(),
					json: async <T = unknown>() => response.json<T>(),
					body: response.body,
				};
			} finally {
				timeout.dispose();
			}
		},
	};
}

/** Read a bounded provider error response so malformed/large bodies cannot be retained. */
async function readErrorBody(response: NetworkResponse, maxBytes = 8192): Promise<{ text: string; format: 'json' | 'malformed-json' | 'non-json' | 'empty' }> {
	let text = '';
	if (response.body) {
		const reader = response.body.getReader();
		const decoder = new TextDecoder();
		let byteCount = 0;
		try {
			while (byteCount < maxBytes) {
				const { value, done } = await reader.read();
				if (done) {
					break;
				}
				const remaining = maxBytes - byteCount;
				const bounded = value.subarray(0, remaining);
				byteCount += bounded.byteLength;
				text += decoder.decode(bounded, { stream: true });
				if (bounded.byteLength !== value.byteLength) {
					await reader.cancel();
					break;
				}
			}
			text += decoder.decode();
		} finally {
			reader.releaseLock();
		}
	} else {
		text = (await response.text()).slice(0, maxBytes);
	}
	if (!text.trim()) {
		return { text: '', format: 'empty' };
	}
	try {
		JSON.parse(text);
		return { text, format: 'json' };
	} catch {
		return { text: '', format: /^[\s]*[<{]/.test(text) ? 'malformed-json' : 'non-json' };
	}
}

function parseProviderError(body: Awaited<ReturnType<typeof readErrorBody>>, status: number): { safeMessage: string; details: OpenRouterProviderError } {
	let root: Record<string, unknown> | undefined;
	if (body.format === 'json') {
		try { root = asRecord(JSON.parse(body.text)); } catch { /* validated above */ }
	}
	const error = asRecord(root?.error) ?? root;
	const metadata = asRecord(error?.metadata);
	const originalMessage = typeof error?.message === 'string' ? error.message : undefined;
	const code = safeIdentifier(error?.code);
	const errorType = safeIdentifier(metadata?.error_type);
	const providerCode = safeIdentifier(metadata?.provider_code);
	const parameter = identifyInvalidParameter(error, metadata, originalMessage);
	const details: OpenRouterProviderError = {
		...(code ? { code } : {}),
		...(errorType ? { errorType } : {}),
		...(providerCode ? { providerCode } : {}),
		...(parameter ? { parameter } : {}),
		...(originalMessage ? { originalMessage } : {}),
		bodyFormat: body.format,
	};
	const safeText = sanitizeProviderErrorMessage(originalMessage);
	return { safeMessage: safeText ? `Provider request failed with HTTP ${status}: ${safeText}` : `Provider request failed with HTTP ${status}.`, details };
}

function identifyInvalidParameter(error: Record<string, unknown> | undefined, metadata: Record<string, unknown> | undefined, message: string | undefined): string | undefined {
	for (const value of [metadata?.invalid_parameter, metadata?.parameter, error?.param, error?.parameter]) {
		const parameter = safeParameter(value);
		if (parameter) {
			return parameter;
		}
	}
	const matches = [
		message?.match(/\b(reasoning)\b(?=.*\b(?:mandatory|required|disabled|cannot be disabled)\b)/i),
		message?.match(/(?:invalid|unsupported|unknown|missing|required)\s+(?:request\s+)?(?:parameter|field)\s+[`"']?([A-Za-z][A-Za-z0-9_.\[\]-]{0,63})/i),
		message?.match(/\b([A-Za-z][A-Za-z0-9_.\[\]-]{0,63})\s+(?:parameter|field)\s+(?:is\s+)?(?:invalid|unsupported|required)/i),
		message?.match(/(?:parameter|field)\s+[`"']?([A-Za-z][A-Za-z0-9_.\[\]-]{0,63})[`"']?\s+(?:is\s+)?(?:invalid|unsupported|not supported|required)/i),
	];
	return matches.map((match) => match ? safeParameter(match[1]) : undefined).find(Boolean);
}

function sanitizeProviderErrorMessage(value: string | undefined): string | undefined {
	if (!value || value.length > 1000 || /(?:prompt|input|source|snippet|content)\s+(?:was|is|contains|included|provided)/i.test(value)) {
		return undefined;
	}
	const safe = redactSecret(value)
		.replace(/https?:\/\/\S+/gi, '[url]')
		.replace(/[`"'][^`"']*[`"']/g, '[redacted]')
		.replace(/[\r\n\t]+/g, ' ')
		.replace(/\b[A-Za-z0-9_\/-]{40,}\b/g, '[redacted]')
		.trim()
		.slice(0, 240);
	return safe && /^[\w .,:;()\[\]{}+\-/=]+$/.test(safe) ? safe : undefined;
}

function safeIdentifier(value: unknown): string | undefined {
	if (typeof value === 'number' && Number.isFinite(value)) {
		return String(value);
	}
	if (typeof value !== 'string') {
		return undefined;
	}
	const normalized = value.trim();
	return normalized.length > 0 && normalized.length <= 80 && /^[A-Za-z0-9_.:-]+$/.test(normalized) ? normalized : undefined;
}

function safeParameter(value: unknown): string | undefined {
	if (typeof value !== 'string') {
		return undefined;
	}
	const normalized = value.trim();
	return normalized.length > 0 && normalized.length <= 64 && /^[A-Za-z][A-Za-z0-9_.\[\]-]*$/.test(normalized) ? normalized.toLowerCase() : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
	return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
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

export async function* parseSseStream(response: AIHttpResponse, onEvent?: (event: SseStreamEvent) => void): AsyncGenerator<unknown> {
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
			const events = buffer.split(/\r?\n\r?\n/);
			buffer = events.pop() ?? '';
			for (const event of events) {
				for (const line of event.split(/\r?\n/)) {
					if (!line.startsWith('data:')) {
						continue;
					}
					const data = line.slice(5).trim();
					if (!data) {
						continue;
					}
					if (data === '[DONE]') {
						onEvent?.({ done: true });
						continue;
					}
					const parsed = JSON.parse(data);
					onEvent?.({ data: parsed, done: false });
					yield parsed;
				}
			}
		}
		if (buffer.trim()) {
			for (const line of buffer.split(/\r?\n/)) {
				if (!line.startsWith('data:')) {
					continue;
				}
				const data = line.slice(5).trim();
				if (data === '[DONE]') {
					onEvent?.({ done: true });
				} else if (data) {
					const parsed = JSON.parse(data);
					onEvent?.({ data: parsed, done: false });
					yield parsed;
				}
			}
		}
	} finally {
		reader.releaseLock();
	}
}

export function redactSecret(value: string): string {
	return value
		.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/g, 'Bearer [redacted]')
		.replace(/(api[_-]?key=)[^&\s]+/gi, '$1[redacted]')
		.replace(/(authorization["']?\s*:\s*["']?)[^"',\s]+/gi, '$1[redacted]');
}

export function normalizeProviderError(error: unknown): string {
	if (error instanceof AIHttpError) {
		if (error.status === 401 || error.status === 403) {
			return 'Authentication failed. Check the saved provider credentials.';
		}
		if (error.status === 402) {
			return 'The provider rejected the request because the account has no available credits.';
		}
		if (error.status === 404) {
			return 'The selected model or endpoint was not found.';
		}
		if (error.status === 429) {
			return 'The provider rate limit was reached (429). Wait a moment, switch API key/model, or use a provider account with more quota.';
		}
		if (error.status === 408 || error.status >= 500) {
			return `The provider is temporarily unavailable (${error.status}). Try again shortly.`;
		}
		return error.message;
	}
	if (error instanceof Error) {
		if (error.name === 'AbortError') {
			return 'Generation was cancelled.';
		}
		if (error.name === 'TimeoutError') {
			return error.message;
		}
		if (/fetch failed|ECONNREFUSED|ENOTFOUND|network/i.test(error.message)) {
			return 'Network connection failed. Check the provider endpoint and internet/local server status.';
		}
		return redactSecret(error.message);
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

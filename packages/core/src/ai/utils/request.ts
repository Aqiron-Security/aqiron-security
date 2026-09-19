import { NetworkClient } from '../../shared/platform';
import { createTimeoutSignal } from './timeout';

export class AIHttpError extends Error {
	constructor(
		public readonly status: number,
		message: string,
		public readonly body?: string,
	) {
		super(message);
		this.name = 'AIHttpError';
	}
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
					throw new AIHttpError(response.status, `Provider request failed with HTTP ${response.status}.`);
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

export async function* parseSseStream(response: AIHttpResponse): AsyncGenerator<unknown> {
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
					if (!data || data === '[DONE]') {
						continue;
					}
					yield JSON.parse(data);
				}
			}
		}
		if (buffer.trim()) {
			for (const line of buffer.split(/\r?\n/)) {
				if (!line.startsWith('data:')) {
					continue;
				}
				const data = line.slice(5).trim();
				if (data && data !== '[DONE]') {
					yield JSON.parse(data);
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

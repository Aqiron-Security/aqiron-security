import { AIHttpError, AIHttpResponse, AITransport, normalizeProviderError, parseNdjsonStream, parseSseStream, redactSecret } from '../../../packages/core/src/ai';
import { createTimeoutSignal } from './timeout';

export { AIHttpError, normalizeProviderError, parseNdjsonStream, parseSseStream, redactSecret };
export type { AIHttpResponse, AITransport };

export interface RequestOptions {
	method?: 'GET' | 'POST' | 'DELETE';
	headers?: Record<string, string | undefined>;
	body?: unknown;
	timeoutMs: number;
	abortSignal?: AbortSignal;
}

export async function requestJson<T>(url: string, options: RequestOptions): Promise<T> {
	const response = await request(url, options);
	return await response.json() as T;
}

export async function request(url: string, options: RequestOptions): Promise<Response> {
	const timeout = createTimeoutSignal(options.timeoutMs, options.abortSignal);
	try {
		const headers = cleanHeaders({
			Accept: 'application/json',
			'Content-Type': options.body === undefined ? undefined : 'application/json',
			...options.headers,
		});
		const response = await fetch(url, {
			method: options.method ?? 'GET',
			headers,
			body: options.body === undefined ? undefined : JSON.stringify(options.body),
			signal: timeout.signal,
		});
		if (!response.ok) {
			const body = await response.text().catch(() => '');
			throw new AIHttpError(response.status, createHttpMessage(response.status, body), body.slice(0, 1000));
		}
		return response;
	} finally {
		timeout.dispose();
	}
}

function cleanHeaders(headers: Record<string, string | undefined>): Record<string, string> {
	return Object.fromEntries(Object.entries(headers).filter((entry): entry is [string, string] => typeof entry[1] === 'string' && entry[1].length > 0));
}

function createHttpMessage(status: number, body: string): string {
	const cleanBody = redactSecret(body).trim();
	return cleanBody ? `Provider request failed with HTTP ${status}: ${cleanBody.slice(0, 240)}` : `Provider request failed with HTTP ${status}.`;
}

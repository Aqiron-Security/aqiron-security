import { AIHttpError, AIHttpResponse, AITransport, normalizeProviderError, parseNdjsonStream, parseSseStream } from '../../../packages/core/src/ai';
import { createTimeoutSignal } from './timeout';

export { AIHttpError, normalizeProviderError, parseNdjsonStream, parseSseStream };
export { redactSecret } from '../../../packages/core/src/ai';
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
	try {return await response.json() as T;}
	catch {throw new AIHttpError(502);}
}

export async function request(url: string, options: RequestOptions): Promise<Response> {
	const timeout = createTimeoutSignal(options.timeoutMs, options.abortSignal);
	try {
		const headers = cleanHeaders({
			Accept: 'application/json',
			'Content-Type': options.body === undefined ? undefined : 'application/json',
			...options.headers,
		});
		let response: Response;
		try {
			response = await fetch(url, {
				method: options.method ?? 'GET',
				headers,
				body: options.body === undefined ? undefined : JSON.stringify(options.body),
				signal: timeout.signal,
			});
		} catch {
			throw new AIHttpError(timeout.signal.aborted ? 408 : 502);
		}
		if (!response.ok) {
			throw new AIHttpError(response.status);
		}
		return response;
	} finally {
		timeout.dispose();
	}
}

function cleanHeaders(headers: Record<string, string | undefined>): Record<string, string> {
	return Object.fromEntries(Object.entries(headers).filter((entry): entry is [string, string] => typeof entry[1] === 'string' && entry[1].length > 0));
}

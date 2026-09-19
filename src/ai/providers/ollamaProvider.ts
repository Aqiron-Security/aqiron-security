import { AIHttpError, AITransport } from '../../../packages/core/src/ai';
import { OllamaProvider as CoreOllamaProvider } from '../../../packages/core/src/ai';
import { CredentialService } from '../services/credentialService';

export class OllamaProvider extends CoreOllamaProvider {
	constructor(credentials: CredentialService) {
		super(credentials as never, createFetchTransport());
	}
}

function createFetchTransport(): AITransport {
	return {
		async request(url, options) {
			const response = await fetch(url, {
				method: options.method ?? 'GET',
				headers: cleanHeaders({
					Accept: 'application/json',
					'Content-Type': options.body === undefined ? undefined : 'application/json',
					...options.headers,
				}),
				body: options.body === undefined ? undefined : JSON.stringify(options.body),
				signal: options.abortSignal,
			});
			if (!response.ok) {
				const body = await response.text().catch(() => '');
				throw new AIHttpError(response.status, body ? `Provider request failed with HTTP ${response.status}: ${body.slice(0, 240)}` : `Provider request failed with HTTP ${response.status}.`, body.slice(0, 1000));
			}
			return {
				ok: response.ok,
				status: response.status,
				headers: Object.fromEntries(Array.from((response.headers as unknown as Iterable<[string, string]>))),
				text: async () => response.text(),
				json: async <T = unknown>() => (await response.json()) as T,
				body: response.body,
			};
		},
	};
}

function cleanHeaders(headers: Record<string, string | undefined>): Record<string, string> {
	return Object.fromEntries(Object.entries(headers).filter((entry): entry is [string, string] => typeof entry[1] === 'string' && entry[1].length > 0));
}

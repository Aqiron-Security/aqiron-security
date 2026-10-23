import { AIHttpError, AITransport } from '../../../packages/core/src/ai';
import { OpenRouterProvider as CoreOpenRouterProvider } from '../../../packages/core/src/ai';
import { CredentialService } from '../services/credentialService';

export class OpenRouterProvider extends CoreOpenRouterProvider {
	constructor(credentials: CredentialService) {
		super(credentials as never, createFetchTransport());
	}
}

function createFetchTransport(): AITransport {
	return {
		async request(url, options) {
			let response: Response;
			try {
				response = await fetch(url, {
					method: options.method ?? 'GET',
					headers: cleanHeaders({
						Accept: 'application/json',
						'Content-Type': options.body === undefined ? undefined : 'application/json',
						...options.headers,
					}),
					body: options.body === undefined ? undefined : JSON.stringify(options.body),
					signal: options.abortSignal,
				});
			} catch {
				throw new AIHttpError(options.abortSignal?.aborted ? 408 : 502);
			}
			if (!response.ok) {
				throw new AIHttpError(response.status);
			}
			return {
				ok: response.ok,
				status: response.status,
				headers: Object.fromEntries(Array.from((response.headers as unknown as Iterable<[string, string]>))),
				text: async () => response.text(),
				json: async <T = unknown>() => {
					try {return await response.json() as T;}
					catch {throw new AIHttpError(502);}
				},
				body: response.body,
			};
		},
	};
}

function cleanHeaders(headers: Record<string, string | undefined>): Record<string, string> {
	return Object.fromEntries(Object.entries(headers).filter((entry): entry is [string, string] => typeof entry[1] === 'string' && entry[1].length > 0));
}

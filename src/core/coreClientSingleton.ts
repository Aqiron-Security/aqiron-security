import { CoreClient } from './coreClient';

let sharedCoreClient: CoreClient | undefined;

export function setCoreClient(client: CoreClient): void {
	sharedCoreClient = client;
}

export function clearCoreClient(): void {
	sharedCoreClient = undefined;
}

export function getCoreClient(): CoreClient {
	if (!sharedCoreClient) {
		throw new Error('Core client has not been initialized.');
	}
	return sharedCoreClient;
}

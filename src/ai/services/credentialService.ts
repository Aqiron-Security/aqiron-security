import { aiSecretKeys } from '../../../packages/core/src/ai';
import { getCoreClient } from '../../core/coreClientSingleton';

export { aiSecretKeys };

export class CredentialService {
	async status(key: string): Promise<{ hasValue: boolean }> {
		return await getCoreClient().credentialsStatus(key);
	}

	async saveSecret(key: string, value: string): Promise<void> {
		await getCoreClient().credentialsSet({ key, value });
	}

	async deleteSecret(key: string): Promise<void> {
		await getCoreClient().credentialsDelete({ key });
	}

	async exists(key: string): Promise<boolean> {
		return (await getCoreClient().credentialsExists(key)).exists;
	}
}

import { IsolationPlatform, IsolationQualification, ValidatedIsolationProfile, unavailableQualification } from './contracts';

export interface IsolationProvider {
	readonly platform: IsolationPlatform;
	getQualification(): IsolationQualification;
	launch(request: IsolatedWorkerRequest): Promise<IsolatedWorkerHandle>;
}

/** Private supervisor-to-provider contract. A provider must not accept commands or scripts. */
export interface IsolatedWorkerRequest {
	readonly workerEntry: 'aqiron-controlled-validation-worker-v1';
	readonly descriptor: VerifiedProcedureDescriptor;
	readonly scope: ValidatedTargetProjectScope;
	readonly profile: ValidatedIsolationProfile;
	readonly environment: Readonly<Record<string, string>>;
	readonly input: Uint8Array;
}

export interface IsolatedWorkerHandle {
	wait(): Promise<IsolatedWorkerResult>;
	terminate(reason: 'timeout' | 'cancel' | 'failure'): Promise<{ confirmed: boolean }>;
	cleanup(): Promise<void>;
}

export interface IsolatedWorkerResult {
	readonly exitCategory: 'success' | 'worker-error' | 'terminated';
	readonly output: Uint8Array;
	readonly truncated: boolean;
}

/** Adapter boundary for the later verified registry integration. */
export interface VerifiedProcedureDescriptor {
	readonly id: string;
	readonly version: string;
	readonly artifactDigest: string;
	readonly workerPayload: Uint8Array;
	readonly verified: true;
}

/** Adapter boundary for Core-derived project and target scope. */
export interface ValidatedTargetProjectScope {
	readonly projectRoot: string;
	readonly projectIdentityDigest: string;
	readonly targetIds: readonly string[];
	readonly inputPaths: readonly string[];
}

/** Production providers remain unavailable until OS-specific adversarial acceptance. */
export const DEFAULT_ISOLATION_QUALIFICATIONS = Object.freeze({
	windows: unavailableQualification('windows'),
	linux: unavailableQualification('linux'),
	macos: unavailableQualification('macos'),
});

export function currentIsolationPlatform(): IsolationPlatform | undefined {
	if (process.platform === 'win32') { return 'windows'; }
	if (process.platform === 'linux') { return 'linux'; }
	if (process.platform === 'darwin') { return 'macos'; }
	return undefined;
}

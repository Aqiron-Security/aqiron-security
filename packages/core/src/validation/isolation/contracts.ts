/** OS-enforced isolation contracts. API presence alone never qualifies a provider. */
export type IsolationQualificationState = 'unsupported' | 'capability-unavailable' | 'configuration-invalid' | 'qualification-pending' | 'qualified' | 'revoked';
export type IsolationPlatform = 'windows' | 'linux' | 'macos';

export interface IsolationCapabilityReport {
	readonly filesystemAllowlist: boolean;
	readonly readOnlyInputs: boolean;
	readonly projectRootContainment: boolean;
	readonly symlinkRaceResistance: boolean;
	readonly networkDeniedByOs: boolean;
	readonly descendantContainment: boolean;
	readonly cpuCeiling: boolean;
	readonly memoryCeiling: boolean;
	readonly executionDeadline: boolean;
	readonly outputBound: boolean;
	readonly processCountCeiling: boolean;
	readonly forcedTermination: boolean;
	readonly cleanup: boolean;
}

export interface IsolationQualification {
	readonly platform: IsolationPlatform;
	readonly state: IsolationQualificationState;
	readonly capabilities: IsolationCapabilityReport;
	readonly evidenceId?: string;
	readonly reason: string;
}

export interface ValidatedIsolationProfile {
	readonly projectRoot: string;
	readonly inputPaths: readonly string[];
	readonly network: 'denied';
	readonly projectWrites: false;
	readonly inheritedCredentials: false;
	readonly timeoutMs: number;
	readonly memoryBytes: number;
	readonly cpuMillis: number;
	readonly outputBytes: number;
	readonly processCount: number;
}

export const REQUIRED_ISOLATION_CAPABILITIES: readonly (keyof IsolationCapabilityReport)[] = [
	'filesystemAllowlist', 'readOnlyInputs', 'projectRootContainment', 'symlinkRaceResistance',
	'networkDeniedByOs', 'descendantContainment', 'cpuCeiling', 'memoryCeiling',
	'executionDeadline', 'outputBound', 'processCountCeiling', 'forcedTermination', 'cleanup',
];

export function qualificationAllowsExecution(value: IsolationQualification): boolean {
	return value.state === 'qualified' && Boolean(value.evidenceId) && REQUIRED_ISOLATION_CAPABILITIES.every(key => value.capabilities[key] === true);
}

export function unavailableQualification(platform: IsolationPlatform, state: Exclude<IsolationQualificationState, 'qualified'> = 'qualification-pending'): IsolationQualification {
	return Object.freeze({ platform, state, capabilities: Object.freeze({
		filesystemAllowlist: false, readOnlyInputs: false, projectRootContainment: false, symlinkRaceResistance: false,
		networkDeniedByOs: false, descendantContainment: false, cpuCeiling: false, memoryCeiling: false,
		executionDeadline: false, outputBound: false, processCountCeiling: false, forcedTermination: false, cleanup: false,
	}), reason: 'No platform has completed adversarial isolation qualification.' });
}

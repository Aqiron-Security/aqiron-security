import { createHash } from 'node:crypto';
import { IsolationQualification, qualificationAllowsExecution } from './isolation/contracts';
import { IsolationProvider, IsolatedWorkerResult, ValidatedTargetProjectScope, VerifiedProcedureDescriptor, DEFAULT_ISOLATION_QUALIFICATIONS, currentIsolationPlatform } from './isolation/providers';
import { ValidatedIsolationProfile } from './isolation/contracts';
import { CommittedStartReceipt, isAcceptedCommittedStartReceipt } from './isolation/receipt';

/** Kept source-controlled and closed. No runtime/client option can enable production launch. */
export const CONTROLLED_VALIDATION_PRODUCTION_EXECUTION_ENABLED = false;
const WORKER_ENTRY = 'aqiron-controlled-validation-worker-v1' as const;
const MAX_INPUT_BYTES = 1024 * 1024;

export interface SupervisorLaunchInput {
	readonly receipt: CommittedStartReceipt;
	readonly descriptor: VerifiedProcedureDescriptor;
	readonly scope: ValidatedTargetProjectScope;
	readonly profile: ValidatedIsolationProfile;
	readonly input: Uint8Array;
}

export interface SupervisorResult {
	readonly executionId: string;
	readonly status: 'completed' | 'failed' | 'timed-out' | 'blocked';
	readonly output?: Uint8Array;
	readonly outputDigest?: string;
	readonly teardownConfirmed?: boolean;
}

export interface SupervisorDependencies {
	readonly providers?: readonly IsolationProvider[];
	readonly qualification?: IsolationQualification;
	/** Explicit contract-test seam. It cannot change the production factory. */
	readonly contractTestOnly?: true;
}

export interface ExecutionSupervisor {
	launch(input: SupervisorLaunchInput): Promise<SupervisorResult>;
	qualification(): IsolationQualification | undefined;
}

const EMPTY_ENVIRONMENT = Object.freeze({ LANG: 'C', LC_ALL: 'C', TZ: 'UTC' });

/** Production factory is permanently fail closed until a reviewed source change. */
export function createExecutionSupervisor(): ExecutionSupervisor {
	return createSupervisor({ providers: [], qualification: currentIsolationPlatform() ? DEFAULT_ISOLATION_QUALIFICATIONS[currentIsolationPlatform()!] : undefined });
}

/** Unit/contract-test seam only; an injected fake never changes platform qualification. */
export function createContractTestSupervisor(dependencies: Omit<SupervisorDependencies, 'contractTestOnly'>): ExecutionSupervisor {
	return createSupervisor({ ...dependencies, contractTestOnly: true });
}

function createSupervisor(dependencies: SupervisorDependencies): ExecutionSupervisor {
	const provider = dependencies.providers?.find(item => item.platform === dependencies.qualification?.platform);
	const qualification = dependencies.qualification ?? provider?.getQualification();
	return {
		qualification: () => qualification,
		async launch(input): Promise<SupervisorResult> {
			const id = input?.receipt?.executionId ?? 'unknown';
			if (!dependencies.contractTestOnly || CONTROLLED_VALIDATION_PRODUCTION_EXECUTION_ENABLED) { return { executionId: id, status: 'blocked' }; }
			if (!isAcceptedCommittedStartReceipt(input.receipt) || !validDescriptor(input.descriptor) || !validScope(input.scope, input.profile) || !(input.input instanceof Uint8Array) || input.input.byteLength > MAX_INPUT_BYTES) { return { executionId: id, status: 'blocked' }; }
			if (!provider || !qualification || provider.platform !== qualification.platform || !qualificationAllowsExecution(qualification) || !qualificationAllowsExecution(provider.getQualification())) { return { executionId: id, status: 'blocked' }; }
			const profile = input.profile;
			const boundedInput = new Uint8Array(input.input);
			let handle;
			try {
				handle = await provider.launch({ workerEntry: WORKER_ENTRY, descriptor: input.descriptor, scope: input.scope, profile, environment: EMPTY_ENVIRONMENT, input: boundedInput });
				let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
				const timeout = new Promise<never>((_, reject) => { timeoutHandle = setTimeout(() => reject(Object.assign(new Error('Worker execution deadline exceeded.'), { code: 'WORKER_TIMEOUT' })), profile.timeoutMs); });
				let result: IsolatedWorkerResult;
				try { result = await Promise.race([handle.wait(), timeout]); }
				catch (error) {
					const timedOut = (error as { code?: string })?.code === 'WORKER_TIMEOUT';
					const stopped = await handle.terminate(timedOut ? 'timeout' : 'failure');
					return { executionId: id, status: timedOut ? 'timed-out' : 'failed', teardownConfirmed: stopped.confirmed };
				} finally { if (timeoutHandle) { clearTimeout(timeoutHandle); } }
				if (!(result.output instanceof Uint8Array) || result.output.byteLength > profile.outputBytes || result.truncated) { return { executionId: id, status: 'failed' }; }
				return { executionId: id, status: result.exitCategory === 'success' ? 'completed' : 'failed', output: new Uint8Array(result.output), outputDigest: createHash('sha256').update(result.output).digest('hex') };
			} catch { return { executionId: id, status: 'failed' }; }
			finally { if (handle) { try { await handle.cleanup(); } catch { /* retain failure-closed result */ } } }
		},
	};
}

function validDescriptor(value: VerifiedProcedureDescriptor): boolean {
	return Boolean(value && value.verified === true && /^[a-z][a-z0-9.-]*:[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/.test(value.id)
		&& /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value.version)
		&& /^sha256:[a-f0-9]{64}$/.test(value.artifactDigest) && value.workerPayload instanceof Uint8Array && value.workerPayload.byteLength > 0 && value.workerPayload.byteLength <= MAX_INPUT_BYTES);
}
function validScope(value: ValidatedTargetProjectScope, profile: ValidatedIsolationProfile): boolean {
	return Boolean(value && value.projectRoot === profile.projectRoot && /^sha256:[a-f0-9]{64}$/.test(value.projectIdentityDigest)
		&& Array.isArray(value.targetIds) && value.targetIds.length > 0 && value.targetIds.length <= 256 && value.targetIds.every(id => typeof id === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(id))
		&& Array.isArray(value.inputPaths) && value.inputPaths.length === profile.inputPaths.length && value.inputPaths.every((p, i) => p === profile.inputPaths[i]));
}

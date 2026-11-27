import path from 'node:path';
import { ValidatedIsolationProfile } from './contracts';

export interface RequestedIsolationProfile {
	readonly projectRoot: string;
	readonly inputPaths: readonly string[];
	readonly network: string;
	readonly projectWrites: boolean;
	readonly inheritedCredentials: boolean;
	readonly timeoutMs: number;
	readonly memoryBytes: number;
	readonly cpuMillis: number;
	readonly outputBytes: number;
	readonly processCount: number;
}

export interface IsolationResourceCeilings {
	readonly maxTimeoutMs: number;
	readonly maxMemoryBytes: number;
	readonly maxCpuMillis: number;
	readonly maxOutputBytes: number;
	readonly maxProcessCount: number;
}

const DEFAULT_CEILINGS: IsolationResourceCeilings = Object.freeze({ maxTimeoutMs: 120_000, maxMemoryBytes: 512 * 1024 * 1024, maxCpuMillis: 60_000, maxOutputBytes: 1024 * 1024, maxProcessCount: 16 });

export function validateIsolationProfile(request: RequestedIsolationProfile, ceilings: IsolationResourceCeilings = DEFAULT_CEILINGS): ValidatedIsolationProfile {
	if (!request || typeof request !== 'object' || request.network !== 'denied' || request.projectWrites !== false || request.inheritedCredentials !== false) { throw new TypeError('Isolation profile must deny network, project writes, and inherited credentials.'); }
	if (!path.isAbsolute(request.projectRoot) || !Array.isArray(request.inputPaths) || request.inputPaths.length < 1 || request.inputPaths.length > 256) { throw new TypeError('Isolation project scope is invalid.'); }
	const root = path.resolve(request.projectRoot);
	const inputs = request.inputPaths.map(item => {
		if (typeof item !== 'string' || !path.isAbsolute(item)) { throw new TypeError('Isolation input path must be absolute.'); }
		const resolved = path.resolve(item);
		const relative = path.relative(root, resolved);
		if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) { throw new TypeError('Isolation input must be a file contained within the project root.'); }
		return resolved;
	});
	if (new Set(inputs).size !== inputs.length) { throw new TypeError('Isolation input paths must be unique.'); }
	const values: Array<[number, number, string]> = [
		[request.timeoutMs, ceilings.maxTimeoutMs, 'timeout'], [request.memoryBytes, ceilings.maxMemoryBytes, 'memory'],
		[request.cpuMillis, ceilings.maxCpuMillis, 'CPU'], [request.outputBytes, ceilings.maxOutputBytes, 'output'], [request.processCount, ceilings.maxProcessCount, 'process count'],
	];
	for (const [value, max, label] of values) { if (!Number.isSafeInteger(value) || value < 1 || value > max) { throw new RangeError(`Isolation ${label} limit is invalid.`); } }
	return Object.freeze({ projectRoot: root, inputPaths: Object.freeze(inputs), network: 'denied', projectWrites: false, inheritedCredentials: false, timeoutMs: request.timeoutMs, memoryBytes: request.memoryBytes, cpuMillis: request.cpuMillis, outputBytes: request.outputBytes, processCount: request.processCount });
}

export const isolationResourceCeilings = DEFAULT_CEILINGS;

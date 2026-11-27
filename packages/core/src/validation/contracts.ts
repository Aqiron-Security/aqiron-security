import { createHash } from 'node:crypto';
import * as path from 'node:path';
import type { FileSystem } from '../shared/platform';

export type SignatureState = 'unverified' | 'verified' | 'invalid' | 'revoked';
export interface ProcedureMetadataV1 {
	schemaVersion: 1;
	id: string;
	version: string;
	packageDigest: string;
	publisherId: string;
	signature: { identity: string; state: SignatureState };
	supportedHypothesisTypes: string[];
	supportedAssetTypes: string[];
	requiredEvidenceTypes: string[];
	parameterSchemaId: string;
	targetPolicyId: string;
	scopePolicyId: string;
	environmentRequirements: string[];
	capabilities: { filesystem: 'none' | 'read-only'; network: 'none' };
	resourceCeilings: { timeoutMs: number; memoryBytes: number; outputBytes: number; processCount: number };
	resultSchemaId: string;
	retirement: 'active' | 'retired' | 'revoked';
}

export function validateProcedureMetadata(value: unknown): ProcedureMetadataV1 {
	canonicalize(value);
	const x = record(value, ['schemaVersion','id','version','packageDigest','publisherId','signature','supportedHypothesisTypes','supportedAssetTypes','requiredEvidenceTypes','parameterSchemaId','targetPolicyId','scopePolicyId','environmentRequirements','capabilities','resourceCeilings','resultSchemaId','retirement']);
	if (x.schemaVersion !== 1 || !isNamespacedId(x.id) || !isSemVer(x.version) || !isDigest(x.packageDigest) || !isId(x.publisherId)) { throw new Error('Invalid procedure identity or version.'); }
	const sig = record(x.signature, ['identity','state']);
	if (!isId(sig.identity) || !['unverified','verified','invalid','revoked'].includes(String(sig.state)) || sig.state === 'verified') { throw new Error('Signature verification is unavailable; registry metadata cannot claim verified signatures.'); }
	const caps = record(x.capabilities, ['filesystem','network']);
	if (!['none','read-only'].includes(String(caps.filesystem)) || caps.network !== 'none') { throw new Error('Contradictory or unsupported procedure capabilities.'); }
	const limits = record(x.resourceCeilings, ['timeoutMs','memoryBytes','outputBytes','processCount']);
	for (const key of ['timeoutMs','memoryBytes','outputBytes','processCount']) {if (!Number.isSafeInteger(limits[key]) || Number(limits[key]) <= 0) { throw new Error('Invalid procedure resource ceiling.'); }}
	for (const key of ['supportedHypothesisTypes','supportedAssetTypes','requiredEvidenceTypes','environmentRequirements']) {if (!Array.isArray(x[key]) || (x[key] as unknown[]).length > 64 || !(x[key] as unknown[]).every(item => isId(item))) { throw new Error(`Invalid ${key}.`); }}
	for (const key of ['parameterSchemaId','targetPolicyId','scopePolicyId','resultSchemaId']) {if (!isId(x[key])) { throw new Error(`Invalid ${key}.`); }}
	if (!['active','retired','revoked'].includes(String(x.retirement))) {throw new Error('Invalid retirement state.');}
	return deepFreeze(cloneJson(value)) as unknown as ProcedureMetadataV1;
}

export class ProcedureRegistry {
	private readonly versions = new Map<string, ProcedureMetadataV1>();
	register(value: unknown): ProcedureMetadataV1 {
		const item = validateProcedureMetadata(value); const key = `${item.id}@${item.version}`; const previous = this.versions.get(key);
		if (previous && canonicalize(previous) !== canonicalize(item)) {throw new Error('Procedure version is already bound to different content.');}
		this.versions.set(key, previous ?? item); return this.versions.get(key)!;
	}
	get(id: string, version: string): ProcedureMetadataV1 | undefined { return this.versions.get(`${id}@${version}`); }
}

export interface PreparationManifestV1 {
	schemaVersion: 1;
	hypothesis: { id: string; contentDigest: string };
	snapshot: { id: string; fingerprint: string };
	workspaceIdentity: string;
	evidence: Array<{ id: string; kind: string; digest: string }>;
	procedure: { id: string; version: string; packageDigest: string; signatureIdentity: string };
	target: { identity: string; allowedScope: unknown };
	environment: { runtimeIdentity: string; policyDigest: string };
	parameters: JsonValue;
	requestedOperations: string[];
	resourceLimits: Record<string, number>;
}
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

/** Derive a non-path workspace identity from Core-inspected physical workspace location. */
export async function derivePhysicalWorkspaceIdentity(workspaceRoot:string,filesystem:Pick<FileSystem,'lstat'|'realpath'>):Promise<string>{
	if(typeof workspaceRoot!=='string'||workspaceRoot.length<1||workspaceRoot.length>4096||!filesystem.lstat||!filesystem.realpath){throw new Error('Physical workspace identity requires bounded path inspection.');}
	const stat=await filesystem.lstat(workspaceRoot);if(!stat.isDirectory()||stat.isSymbolicLink()){throw new Error('Workspace root must be a physical directory.');}
	const physical=await filesystem.realpath(workspaceRoot);const normalized=path.resolve(physical).replace(/\\/g,'/');const identityPath=process.platform==='win32'?normalized.toLowerCase():normalized;
	return `sha256:${createHash('sha256').update(`aqiron-workspace-v1\0${identityPath}`,'utf8').digest('hex')}`;
}

export const CANONICALIZATION_LIMITS = Object.freeze({ maxDepth: 64, maxNodes: 20_000, maxStringBytes: 65_536, maxContainerEntries: 4_096, maxSerializedBytes: 1_048_576 });
export function canonicalize(value: unknown): string { const writer = new BoundedCanonicalWriter(); writer.write(value); return writer.finish(); }
export function digestCanonical(value: unknown): string { return createHash('sha256').update(canonicalize(value), 'utf8').digest('hex'); }
export function validatePreparationManifest(value: unknown): PreparationManifestV1 {
	canonicalize(value);
	const x = record(value, ['schemaVersion','hypothesis','snapshot','workspaceIdentity','evidence','procedure','target','environment','parameters','requestedOperations','resourceLimits']);
	if (x.schemaVersion !== 1) {throw new Error('Unsupported preparation manifest version.');}
	const h=record(x.hypothesis,['id','contentDigest']); const s=record(x.snapshot,['id','fingerprint']); const p=record(x.procedure,['id','version','packageDigest','signatureIdentity']); const t=record(x.target,['identity','allowedScope']); const e=record(x.environment,['runtimeIdentity','policyDigest']);
	if (!isId(h.id)||!isDigest(h.contentDigest)||!isId(s.id)||!isDigest(s.fingerprint)||!isDigest(x.workspaceIdentity)||!Array.isArray(x.evidence)||x.evidence.length>128||!isNamespacedId(p.id)||!isSemVer(p.version)||!isDigest(p.packageDigest)||!isId(p.signatureIdentity)||!isId(t.identity)||!isId(e.runtimeIdentity)||!isDigest(e.policyDigest)) {throw new Error('Invalid preparation manifest identity.');}
	for(const item of x.evidence) {const r=record(item,['id','kind','digest']); if(!isId(r.id)||!isId(r.kind)||!isDigest(r.digest)) {throw new Error('Invalid manifest evidence.');}}
	if(!Array.isArray(x.requestedOperations)||x.requestedOperations.length>64||!x.requestedOperations.every(isId)) {throw new Error('Invalid requested operations.');}
	const limits=record(x.resourceLimits,Object.keys(x.resourceLimits as object)); if(Object.keys(limits).length>32||Object.values(limits).some(n=>!Number.isSafeInteger(n)||Number(n)<0)) {throw new Error('Invalid manifest resource limits.');}
	canonicalize(x.parameters); canonicalize(t.allowedScope);
	return deepFreeze(cloneJson(value)) as unknown as PreparationManifestV1;
}
export function preparationManifestDigest(value: unknown): string { return digestCanonical(validatePreparationManifest(value)); }

class BoundedCanonicalWriter {
	private readonly chunks: string[] = [];
	private readonly ancestors = new Set<object>();
	private nodes = 0;
	private bytes = 0;
	write(value: unknown): void { this.visit(value, 0); }
	finish(): string { return this.chunks.join(''); }
	private emit(fragment: string): void {
		this.bytes += Buffer.byteLength(fragment, 'utf8');
		if (this.bytes > CANONICALIZATION_LIMITS.maxSerializedBytes) { throw new RangeError('Canonical JSON exceeds the serialized byte limit.'); }
		this.chunks.push(fragment);
	}
	private visit(value: unknown, depth: number): void {
		if (depth > CANONICALIZATION_LIMITS.maxDepth) { throw new RangeError('Canonical JSON exceeds the maximum depth.'); }
		if (++this.nodes > CANONICALIZATION_LIMITS.maxNodes) { throw new RangeError('Canonical JSON exceeds the node limit.'); }
		if (value === null) { this.emit('null'); return; }
		if (typeof value === 'string') {
			if (Buffer.byteLength(value, 'utf8') > CANONICALIZATION_LIMITS.maxStringBytes) { throw new RangeError('Canonical string exceeds the per-string byte limit.'); }
			this.emit(JSON.stringify(value)); return;
		}
		if (typeof value === 'boolean') { this.emit(value ? 'true' : 'false'); return; }
		if (typeof value === 'number') {
			if (!Number.isFinite(value)) { throw new TypeError('Non-finite numbers are not canonical JSON.'); }
			this.emit(Object.is(value, -0) ? '0' : JSON.stringify(value)); return;
		}
		if (typeof value !== 'object' || value === undefined) { throw new TypeError('Unsupported canonical value.'); }
		if (this.ancestors.has(value)) { throw new TypeError('Canonical values cannot contain cycles.'); }
		this.ancestors.add(value);
		try {
			if (Array.isArray(value)) {
				if (Object.getPrototypeOf(value) !== Array.prototype) { throw new TypeError('Canonical arrays must have the standard prototype.'); }
				if (value.length > CANONICALIZATION_LIMITS.maxContainerEntries) { throw new RangeError('Canonical array exceeds the container-entry limit.'); }
				const keys = Reflect.ownKeys(value);
				if (keys.some(key => typeof key === 'symbol' || (key !== 'length' && !(typeof key === 'string' && /^(0|[1-9]\d*)$/.test(key) && Number(key) < value.length)))) { throw new TypeError('Canonical arrays may contain only indexed items.'); }
				this.emit('[');
				for (let i = 0; i < value.length; i++) {
					if (i) { this.emit(','); }
					if (!Object.prototype.hasOwnProperty.call(value, i)) { throw new TypeError('Sparse arrays are unsupported.'); }
					const descriptor = Object.getOwnPropertyDescriptor(value, String(i))!;
					if (!('value' in descriptor)) { throw new TypeError('Canonical array items must be data properties.'); }
					this.visit(descriptor.value, depth + 1);
				}
				this.emit(']'); return;
			}
			const proto = Object.getPrototypeOf(value);
			if (proto !== Object.prototype && proto !== null) { throw new TypeError('Canonical objects must be plain objects.'); }
			const keys = Reflect.ownKeys(value);
			if (keys.length > CANONICALIZATION_LIMITS.maxContainerEntries) { throw new RangeError('Canonical object exceeds the container-entry limit.'); }
			if (keys.some(key => typeof key === 'symbol')) { throw new TypeError('Symbol keys are unsupported.'); }
			const stringKeys = keys as string[];
			for (const key of stringKeys) { if (Buffer.byteLength(key, 'utf8') > CANONICALIZATION_LIMITS.maxStringBytes) { throw new RangeError('Canonical property name exceeds the per-string byte limit.'); } }
			const sorted = stringKeys.sort();
			this.emit('{');
			for (let i = 0; i < sorted.length; i++) {
				if (i) { this.emit(','); }
				const key = sorted[i]!;
				const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
				if (!descriptor.enumerable || !('value' in descriptor)) { throw new TypeError('Canonical properties must be enumerable data properties.'); }
				this.emit(JSON.stringify(key)); this.emit(':'); this.visit(descriptor.value, depth + 1);
			}
			this.emit('}');
		} finally { this.ancestors.delete(value); }
	}
}
function record(value: unknown, keys: string[]): Record<string, any> { if(!value||typeof value!=='object'||Array.isArray(value)||(Object.getPrototypeOf(value)!==Object.prototype&&Object.getPrototypeOf(value)!==null)) {throw new TypeError('Expected a plain object.');} const x=value as Record<string,unknown>; if(Object.keys(x).some(k=>!keys.includes(k))||keys.some(k=>!Object.prototype.hasOwnProperty.call(x,k))) {throw new TypeError('Unknown or missing contract field.');} return x; }
function isId(v: unknown): v is string { return typeof v==='string'&&v.length<=160&&/^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$/.test(v); }
function isNamespacedId(v: unknown): v is string { return typeof v==='string'&&v.length<=160&&/^[a-z][a-z0-9.-]*:[a-zA-Z0-9][a-zA-Z0-9._:/-]*$/.test(v); }
function isDigest(v: unknown): v is string { return typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v); }
function isSemVer(value:unknown):value is string{
	if(typeof value!=='string'||value.length>128){return false;}
	const plus=value.indexOf('+');const coreAndPre=plus<0?value:value.slice(0,plus);const build=plus<0?undefined:value.slice(plus+1);
	if(build!==undefined&&(!build||!build.split('.').every(part=>/^[0-9A-Za-z-]+$/.test(part)))){return false;}
	const hyphen=coreAndPre.indexOf('-');const core=hyphen<0?coreAndPre:coreAndPre.slice(0,hyphen);const pre=hyphen<0?undefined:coreAndPre.slice(hyphen+1);
	if(!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(core)){return false;}
	if(pre===undefined){return true;}
	return Boolean(pre)&&pre.split('.').every(part=>/^[0-9A-Za-z-]+$/.test(part)&&(!/^\d+$/.test(part)||part==='0'||!part.startsWith('0')));
}
function cloneJson<T>(v:T):T { return JSON.parse(JSON.stringify(v)) as T; }
function deepFreeze<T>(v:T):T { if(v&&typeof v==='object'&&!Object.isFrozen(v)){Object.freeze(v);for(const child of Object.values(v as object)){deepFreeze(child);}} return v; }

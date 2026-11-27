import { createHash } from 'node:crypto';
import { canonicalize, digestCanonical, JsonValue } from '../contracts';

export type ProcedureSchema =
	| { type: 'string'; minLength: number; maxLength: number; pattern?: string }
	| { type: 'integer'; minimum: number; maximum: number }
	| { type: 'boolean' }
	| { type: 'enum'; values: readonly string[] }
	| { type: 'array'; items: ProcedureSchema; minItems: number; maxItems: number }
	| { type: 'object'; properties: Readonly<Record<string, ProcedureSchema>>; required: readonly string[]; additionalProperties: false };

export interface ProcedureDescriptorV1 {
	readonly schemaVersion: 1;
	readonly id: string;
	readonly version: string;
	readonly artifact: Readonly<{ identity: string; digest: string; kind: 'descriptor-package' }>;
	readonly input: ProcedureSchema;
	readonly result: ProcedureSchema;
	readonly targetPolicy: Readonly<{ id: string; targetKind: 'source-span'; maxTargets: 1; projectOnly: true }>;
	readonly projectScopePolicy: Readonly<{ id: string; binding: 'exact-project-identity'; targetMustBeInProject: true }>;
	readonly capabilities: readonly ('captured-source-read' | 'network' | 'project-write' | 'credentials' | 'child-process')[];
	readonly resources: Readonly<{ maxInputBytes: number; maxReadBytes: number; maxOutputBytes: number; maxDepth: number; maxNodes: number; timeoutMs: number; memoryBytes: number; processCount: number }>;
	readonly requirements: Readonly<{ offline: true; readOnly: true; noProjectModification: true; noCredentialInheritance: true; cli: false; desktopEndpoint: false }>;
	readonly failureCategories: readonly string[];
	readonly audit: Readonly<{ owner: 'core'; classification: 'integrity-check'; recordsDigests: true; recordsSourceText: false }>;
	readonly compatibility: Readonly<{ contractMajor: 1; compatibleWith: readonly string[]; breakingChangesRequireNewMajor: true }>;
}

export type ProcedureVerificationFailureCode = 'ARTIFACT_DIGEST_MISMATCH' | 'PROCEDURE_IDENTITY_MISMATCH' | 'SIGNATURE_VERIFIER_UNAVAILABLE' | 'SIGNATURE_INVALID' | 'CATALOG_PROVIDER_UNAVAILABLE' | 'CATALOG_UNTRUSTED' | 'SIGNING_IDENTITY_INVALID' | 'SIGNING_IDENTITY_REVOKED' | 'REVOCATION_PROVIDER_UNAVAILABLE' | 'ARTIFACT_REVOKED';
export class ProcedureVerificationError extends Error {
	constructor(readonly code: ProcedureVerificationFailureCode, message: string) { super(message); this.name = 'ProcedureVerificationError'; }
}
export interface ProcedureSignature { readonly catalogIdentity: string; readonly signingKeyIdentity: string; readonly signature: Uint8Array }
export interface VerifiedProcedureDescriptor { readonly descriptor: ProcedureDescriptorV1; readonly verified: true; readonly artifactDigest: string; readonly catalogIdentity: string; readonly signingKeyIdentity: string }
export interface ProcedureArtifactTrustProviders {
	verifySignature(input: { readonly artifactDigest: string; readonly procedureId: string; readonly version: string; readonly signature: Uint8Array; readonly signingKeyIdentity: string }): Promise<boolean>;
	verifyTrustedCatalog(input: { readonly catalogIdentity: string; readonly procedureId: string; readonly version: string; readonly artifactDigest: string }): Promise<boolean>;
	getSigningKeyStatus(input: { readonly catalogIdentity: string; readonly signingKeyIdentity: string }): Promise<'active' | 'invalid' | 'revoked'>;
	getRevocationStatus(input: { readonly catalogIdentity: string; readonly artifactDigest: string; readonly procedureId: string; readonly version: string }): Promise<'active' | 'revoked'>;
}

/** Verification boundary only. Providers own trust roots, catalog authenticity, key lifecycle and revocation freshness. */
export class ProcedureArtifactVerifier {
	constructor(private readonly providers?: Partial<ProcedureArtifactTrustProviders>) {}
	async verify(descriptor: ProcedureDescriptorV1, artifact: Uint8Array, signature: ProcedureSignature): Promise<VerifiedProcedureDescriptor> {
		if (!(artifact instanceof Uint8Array) || artifact.byteLength > 64 * 1024 * 1024) { throw new ProcedureVerificationError('ARTIFACT_DIGEST_MISMATCH', 'Procedure artifact is not a bounded byte array.'); }
		const artifactSnapshot = new Uint8Array(artifact);
		const signatureSnapshot = signature?.signature instanceof Uint8Array ? new Uint8Array(signature.signature) : undefined;
		const digest = 'sha256:' + createHash('sha256').update(artifactSnapshot).digest('hex');
		if (digest !== descriptor.artifact.digest) { throw new ProcedureVerificationError('ARTIFACT_DIGEST_MISMATCH', 'Procedure artifact digest does not match the immutable descriptor.'); }
		if (!signature || signature.catalogIdentity !== descriptor.artifact.identity || !safeId(signature.signingKeyIdentity) || !(signature.signature instanceof Uint8Array) || signature.signature.length < 1 || signature.signature.length > 16_384) { throw new ProcedureVerificationError('PROCEDURE_IDENTITY_MISMATCH', 'Signature identity is not bound to this procedure descriptor.'); }
		const providers = this.providers;
		if (!providers?.verifyTrustedCatalog) { throw new ProcedureVerificationError('CATALOG_PROVIDER_UNAVAILABLE', 'Trusted procedure catalog provider is unavailable.'); }
		let catalogTrusted: boolean;
		try { catalogTrusted = await providers.verifyTrustedCatalog({ catalogIdentity: signature.catalogIdentity, procedureId: descriptor.id, version: descriptor.version, artifactDigest: digest }); } catch { throw new ProcedureVerificationError('CATALOG_PROVIDER_UNAVAILABLE', 'Trusted procedure catalog provider failed.'); }
		if (!catalogTrusted) { throw new ProcedureVerificationError('CATALOG_UNTRUSTED', 'Procedure catalog identity is not trusted.'); }
		if (!providers.getSigningKeyStatus) { throw new ProcedureVerificationError('SIGNATURE_VERIFIER_UNAVAILABLE', 'Signing-key status provider is unavailable.'); }
		let keyStatus: 'active' | 'invalid' | 'revoked';
		try { keyStatus = await providers.getSigningKeyStatus({ catalogIdentity: signature.catalogIdentity, signingKeyIdentity: signature.signingKeyIdentity }); } catch { throw new ProcedureVerificationError('SIGNATURE_VERIFIER_UNAVAILABLE', 'Signing-key status provider failed.'); }
		if (keyStatus === 'revoked') { throw new ProcedureVerificationError('SIGNING_IDENTITY_REVOKED', 'Procedure signing identity is revoked.'); }
		if (keyStatus !== 'active') { throw new ProcedureVerificationError('SIGNING_IDENTITY_INVALID', 'Procedure signing identity is invalid or unavailable.'); }
		if (!providers.verifySignature) { throw new ProcedureVerificationError('SIGNATURE_VERIFIER_UNAVAILABLE', 'Procedure signature verifier is unavailable.'); }
		let signatureValid: boolean;
		try { signatureValid = await providers.verifySignature({ artifactDigest: digest, procedureId: descriptor.id, version: descriptor.version, signature: signatureSnapshot!, signingKeyIdentity: signature.signingKeyIdentity }); } catch { throw new ProcedureVerificationError('SIGNATURE_VERIFIER_UNAVAILABLE', 'Procedure signature verifier failed.'); }
		if (!signatureValid) { throw new ProcedureVerificationError('SIGNATURE_INVALID', 'Procedure artifact signature is invalid.'); }
		if (!providers.getRevocationStatus) { throw new ProcedureVerificationError('REVOCATION_PROVIDER_UNAVAILABLE', 'Procedure revocation provider is unavailable.'); }
		let revocation: 'active' | 'revoked';
		try { revocation = await providers.getRevocationStatus({ catalogIdentity: signature.catalogIdentity, artifactDigest: digest, procedureId: descriptor.id, version: descriptor.version }); } catch { throw new ProcedureVerificationError('REVOCATION_PROVIDER_UNAVAILABLE', 'Procedure revocation provider failed.'); }
		if (revocation === 'revoked') { throw new ProcedureVerificationError('ARTIFACT_REVOKED', 'Procedure artifact is revoked.'); }
		if (revocation !== 'active') { throw new ProcedureVerificationError('REVOCATION_PROVIDER_UNAVAILABLE', 'Procedure revocation status is unavailable.'); }
		return deepFreeze({ descriptor, verified: true as const, artifactDigest: digest, catalogIdentity: signature.catalogIdentity, signingKeyIdentity: signature.signingKeyIdentity });
	}
}

export class ProcedureRegistryError extends Error {
	constructor(readonly code: 'INVALID_DESCRIPTOR' | 'DUPLICATE_ID' | 'DUPLICATE_VERSION' | 'NOT_FOUND' | 'UNSUPPORTED_CAPABILITY' | 'OUTSIDE_V1_POLICY' | 'INVALID_ARGUMENTS' | 'SCOPE_MISMATCH', message: string) { super(message); this.name = 'ProcedureRegistryError'; }
}

/** Metadata-only catalog. It returns verified immutable metadata; it has no launch or execution method. */
export class ProcedureRegistry {
	private readonly byId = new Map<string, ProcedureDescriptorV1>();
	private readonly versions = new Set<string>();
	register(value: unknown): ProcedureDescriptorV1 {
		const descriptor = validateProcedureDescriptor(value);
		if (this.byId.has(descriptor.id)) { throw new ProcedureRegistryError('DUPLICATE_ID', 'Procedure IDs are unique within this immutable v1 catalog.'); }
		if (this.versions.has(descriptor.version)) { throw new ProcedureRegistryError('DUPLICATE_VERSION', 'Procedure versions are unique within this immutable v1 catalog.'); }
		this.enforceV1(descriptor);
		this.byId.set(descriptor.id, descriptor); this.versions.add(descriptor.version);
		return descriptor;
	}
	get(id: string, version: string): ProcedureDescriptorV1 {
		const item = this.byId.get(id);
		if (!item || item.version !== version) { throw new ProcedureRegistryError('NOT_FOUND', 'Registered procedure identity and version were not found.'); }
		return item;
	}
	async verifyRegistered(id: string, version: string, artifact: Uint8Array, signature: ProcedureSignature, verifier: ProcedureArtifactVerifier): Promise<VerifiedProcedureDescriptor> {
		return verifier.verify(this.get(id, version), artifact, signature);
	}
	validateArguments(id: string, version: string, value: unknown, scope: { projectIdentity: string; targetProjectIdentity: string; targetCount: number; target: Readonly<Record<string, string | number>> }): JsonValue {
		const item = this.get(id, version);
		if (scope.projectIdentity !== scope.targetProjectIdentity || scope.targetCount !== item.targetPolicy.maxTargets) { throw new ProcedureRegistryError('SCOPE_MISMATCH', 'Procedure target is outside the exact project or target-count policy.'); }
		try {
			validateAgainstSchema(value, item.input, item.resources);
			const args = plain(value);
			for (const [key, expected] of Object.entries(scope.target)) { if (args[key] !== expected) { throw new ProcedureRegistryError('SCOPE_MISMATCH', 'Arguments do not match the Core-selected target.'); } }
			if (typeof args.relativePath !== 'string' || args.relativePath.startsWith('/') || args.relativePath.includes(':') || args.relativePath.includes('\\\\') || /[\\u0000-\\u001f]/.test(args.relativePath) || args.relativePath.split('/').some((part: string) => part === '..' || part === '.' || part.length === 0) || typeof args.startLine !== 'number' || typeof args.endLine !== 'number' || args.endLine < args.startLine || args.endLine - args.startLine > 4095) { throw new ProcedureRegistryError('SCOPE_MISMATCH', 'Source span is not a normalized bounded in-project range.'); }
			return freezeJson(value) as JsonValue;
		}
		catch (error) { if (error instanceof ProcedureRegistryError) { throw error; } throw new ProcedureRegistryError('INVALID_ARGUMENTS', error instanceof Error ? error.message : 'Procedure arguments are invalid.'); }
	}
	private enforceV1(item: ProcedureDescriptorV1): void {
		if (item.capabilities.some(capability => capability !== 'captured-source-read')) { throw new ProcedureRegistryError('UNSUPPORTED_CAPABILITY', 'Procedure declares a capability outside the approved v1 set.'); }
		if (item.requirements.offline !== true || item.requirements.readOnly !== true || item.requirements.noProjectModification !== true || item.requirements.noCredentialInheritance !== true || item.requirements.cli !== false || item.requirements.desktopEndpoint !== false || item.resources.processCount !== 1 || item.resources.maxInputBytes > 32 * 1024 || item.resources.maxReadBytes > 10 * 1024 * 1024 || item.resources.maxOutputBytes > 8192 || item.resources.maxDepth > 8 || item.resources.maxNodes > 256 || item.resources.timeoutMs > 10_000 || item.resources.memoryBytes > 64 * 1024 * 1024) { throw new ProcedureRegistryError('OUTSIDE_V1_POLICY', 'Procedure exceeds the approved offline, read-only, bounded v1 policy.'); }
	}
}

export function validateProcedureDescriptor(value: unknown): ProcedureDescriptorV1 {
	try {
		canonicalize(value);
		const x = plain(value);
		exactKeys(x, ['schemaVersion','id','version','artifact','input','result','targetPolicy','projectScopePolicy','capabilities','resources','requirements','failureCategories','audit','compatibility']);
		if (x.schemaVersion !== 1 || !/^aqiron\.core:[a-z0-9][a-z0-9.-]{0,127}$/.test(x.id) || !semver(x.version)) { throw new Error('Invalid procedure identity, version, or schema version.'); }
		const artifact = plain(x.artifact); exactKeys(artifact, ['identity','digest','kind']); if (!safeId(artifact.identity) || !digest(artifact.digest) || artifact.kind !== 'descriptor-package') { throw new Error('Invalid artifact identity or digest.'); }
		validateSchemaDefinition(x.input, 0); validateSchemaDefinition(x.result, 0);
		const target = plain(x.targetPolicy); exactKeys(target, ['id','targetKind','maxTargets','projectOnly']); if (!safeId(target.id) || target.targetKind !== 'source-span' || target.maxTargets !== 1 || target.projectOnly !== true) { throw new Error('Target policy is outside v1.'); }
		const project = plain(x.projectScopePolicy); exactKeys(project, ['id','binding','targetMustBeInProject']); if (!safeId(project.id) || project.binding !== 'exact-project-identity' || project.targetMustBeInProject !== true) { throw new Error('Project scope policy is outside v1.'); }
		if (!Array.isArray(x.capabilities) || x.capabilities.length > 8 || !x.capabilities.every(safeId) || new Set(x.capabilities).size !== x.capabilities.length) { throw new Error('Invalid capability declaration.'); }
		const r = plain(x.resources); exactKeys(r, ['maxInputBytes','maxReadBytes','maxOutputBytes','maxDepth','maxNodes','timeoutMs','memoryBytes','processCount']); for (const [key, n] of Object.entries(r)) { if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 1 || n > 64 * 1024 * 1024) { throw new Error(`Invalid resource ceiling: ${key}.`); } }
		const req = plain(x.requirements); exactKeys(req, ['offline','readOnly','noProjectModification','noCredentialInheritance','cli','desktopEndpoint']);
		if (req.offline !== true || req.readOnly !== true || req.noProjectModification !== true || req.noCredentialInheritance !== true || req.cli !== false || req.desktopEndpoint !== false) { throw new Error('Procedure requirements violate v1.'); }
		if (!Array.isArray(x.failureCategories) || x.failureCategories.length < 1 || x.failureCategories.length > 32 || !x.failureCategories.every(safeId) || new Set(x.failureCategories).size !== x.failureCategories.length) { throw new Error('Invalid failure categories.'); }
		const audit = plain(x.audit); exactKeys(audit, ['owner','classification','recordsDigests','recordsSourceText']); if (audit.owner !== 'core' || audit.classification !== 'integrity-check' || audit.recordsDigests !== true || audit.recordsSourceText !== false) { throw new Error('Invalid audit metadata.'); }
		const compatibility = plain(x.compatibility); exactKeys(compatibility, ['contractMajor','compatibleWith','breakingChangesRequireNewMajor']); if (compatibility.contractMajor !== 1 || compatibility.breakingChangesRequireNewMajor !== true || !Array.isArray(compatibility.compatibleWith) || compatibility.compatibleWith.length > 16 || !compatibility.compatibleWith.every(safeId)) { throw new Error('Invalid compatibility metadata.'); }
		return deepFreeze(JSON.parse(JSON.stringify(value))) as ProcedureDescriptorV1;
	} catch (error) { if (error instanceof ProcedureRegistryError) { throw error; } throw new ProcedureRegistryError('INVALID_DESCRIPTOR', error instanceof Error ? error.message : 'Invalid procedure descriptor.'); }
}

function validateSchemaDefinition(schema: unknown, depth: number): void {
	if (depth > 8) { throw new Error('Schema nesting exceeds its limit.'); }
	const x = plain(schema);
	switch (x.type) {
		case 'string': exactKeys(x, ['type','minLength','maxLength'], ['pattern']); if (!bound(x.minLength, 0, 4096) || !bound(x.maxLength, x.minLength, 16_384) || x.pattern !== undefined && (typeof x.pattern !== 'string' || x.pattern !== '^sha256:[a-f0-9]{64}$')) { throw new Error('Invalid string schema bounds.'); } break;
		case 'integer': exactKeys(x, ['type','minimum','maximum']); if (!Number.isSafeInteger(x.minimum) || !Number.isSafeInteger(x.maximum) || x.minimum > x.maximum || x.minimum < -1_000_000_000 || x.maximum > 1_000_000_000) { throw new Error('Invalid integer schema bounds.'); } break;
		case 'boolean': exactKeys(x, ['type']); break;
		case 'enum': exactKeys(x, ['type','values']); if (!Array.isArray(x.values) || !x.values.length || x.values.length > 64 || !x.values.every(v => typeof v === 'string' && v.length <= 128) || new Set(x.values).size !== x.values.length) { throw new Error('Invalid enum schema.'); } break;
		case 'array': exactKeys(x, ['type','items','minItems','maxItems']); if (!bound(x.minItems, 0, 1024) || !bound(x.maxItems, x.minItems, 4096)) { throw new Error('Invalid array schema bounds.'); } validateSchemaDefinition(x.items, depth + 1); break;
		case 'object': exactKeys(x, ['type','properties','required','additionalProperties']); if (x.additionalProperties !== false) { throw new Error('Additional schema properties must be prohibited.'); } { const props = plain(x.properties); if (Object.keys(props).length > 64 || !Array.isArray(x.required) || !x.required.every((k: unknown) => typeof k === 'string' && Object.hasOwn(props, k)) || new Set(x.required).size !== x.required.length) { throw new Error('Invalid object schema.'); } for (const child of Object.values(props)) { validateSchemaDefinition(child, depth + 1); } } break;
		default: throw new Error('Unsupported schema type.');
	}
}
function validateAgainstSchema(value: unknown, schema: ProcedureSchema, limits: ProcedureDescriptorV1['resources']): void {
	const text = canonicalize(value); if (Buffer.byteLength(text, 'utf8') > limits.maxInputBytes) { throw new Error('Arguments exceed the input byte limit.'); }
	let nodes = 0;
	const visit = (v: unknown, s: ProcedureSchema, depth: number): void => {
		if (depth > limits.maxDepth || ++nodes > limits.maxNodes) { throw new Error('Arguments exceed depth or node limits.'); }
		switch (s.type) {
			case 'string': if (typeof v !== 'string' || [...v].length < s.minLength || [...v].length > s.maxLength || s.pattern && !(new RegExp(s.pattern).test(v))) { throw new Error('String argument violates its registered schema.'); } return;
			case 'integer': if (!Number.isSafeInteger(v) || Number(v) < s.minimum || Number(v) > s.maximum) { throw new Error('Integer argument violates its registered schema.'); } return;
			case 'boolean': if (typeof v !== 'boolean') { throw new Error('Boolean argument violates its registered schema.'); } return;
			case 'enum': if (typeof v !== 'string' || !s.values.includes(v)) { throw new Error('Enum argument violates its registered schema.'); } return;
			case 'array': if (!Array.isArray(v) || v.length < s.minItems || v.length > s.maxItems) { throw new Error('Array argument violates its registered schema.'); } v.forEach(item => visit(item, s.items, depth + 1)); return;
			case 'object': if (!v || typeof v !== 'object' || Array.isArray(v)) { throw new Error('Object argument violates its registered schema.'); } { const o = v as Record<string, unknown>; if (Object.keys(o).some(k => !Object.hasOwn(s.properties, k)) || s.required.some(k => !Object.hasOwn(o, k))) { throw new Error('Object argument has unknown or missing fields.'); } for (const [key, child] of Object.entries(o)) { visit(child, s.properties[key]!, depth + 1); } } return;
		}
	}; visit(value, schema, 0);
}
function plain(v: unknown): Record<string, any> { if (!v || typeof v !== 'object' || Array.isArray(v) || (Object.getPrototypeOf(v) !== Object.prototype && Object.getPrototypeOf(v) !== null)) { throw new Error('Expected a plain object.'); } return v as Record<string, any>; }
function exactKeys(v: Record<string, unknown>, required: string[], optional: string[] = []): void { const keys = Object.keys(v); if (keys.some(k => !required.includes(k) && !optional.includes(k)) || required.some(k => !Object.hasOwn(v, k))) { throw new Error('Unknown or missing contract field.'); } }
function bound(v: unknown, min: number, max: number): boolean { return typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= max; }
function safeId(v: unknown): v is string { return typeof v === 'string' && v.length > 0 && v.length <= 160 && /^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$/.test(v); }
function digest(v: unknown): v is string { return typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v); }
function semver(v: unknown): boolean { return typeof v === 'string' && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(v); }
function freezeJson<T>(v: T): T { return deepFreeze(JSON.parse(canonicalize(v)) as T); }
function deepFreeze<T>(v: T): T { if (v && typeof v === 'object' && !Object.isFrozen(v)) { Object.freeze(v); for (const child of Object.values(v as object)) { deepFreeze(child); } } return v; }

const sourceInput: ProcedureSchema = { type: 'object', additionalProperties: false, required: ['observationId','snapshotId','snapshotFingerprint','scanId','findingId','relativePath','startLine','endLine','expectedFileDigest','expectedSpanDigest'], properties: {
	observationId: { type: 'string', minLength: 1, maxLength: 128 }, snapshotId: { type: 'string', minLength: 1, maxLength: 128 }, snapshotFingerprint: { type: 'string', minLength: 71, maxLength: 71, pattern: '^sha256:[a-f0-9]{64}$' }, scanId: { type: 'string', minLength: 1, maxLength: 128 }, findingId: { type: 'string', minLength: 1, maxLength: 128 }, relativePath: { type: 'string', minLength: 1, maxLength: 1024 }, startLine: { type: 'integer', minimum: 1, maximum: 1_000_000 }, endLine: { type: 'integer', minimum: 1, maximum: 1_000_000 }, expectedFileDigest: { type: 'string', minLength: 71, maxLength: 71, pattern: '^sha256:[a-f0-9]{64}$' }, expectedSpanDigest: { type: 'string', minLength: 71, maxLength: 71, pattern: '^sha256:[a-f0-9]{64}$' },
} };
const sourceResult: ProcedureSchema = { type: 'object', additionalProperties: false, required: ['status','observationId','snapshotId','actualFileDigest','actualSpanDigest','bytesRead','linesRead'], properties: {
	status: { type: 'enum', values: ['match','changed','unavailable','unsafe-target','invalid-encoding','limit-exceeded'] }, observationId: { type: 'string', minLength: 1, maxLength: 128 }, snapshotId: { type: 'string', minLength: 1, maxLength: 128 }, actualFileDigest: { type: 'string', minLength: 0, maxLength: 71 }, actualSpanDigest: { type: 'string', minLength: 0, maxLength: 71 }, bytesRead: { type: 'integer', minimum: 0, maximum: 10 * 1024 * 1024 }, linesRead: { type: 'integer', minimum: 0, maximum: 4096 },
} };
const sourceDescriptorWithoutDigest = { schemaVersion: 1 as const, id: 'aqiron.core:source-span-integrity-check-v1', version: '1.0.0', artifact: { identity: 'aqiron-core-catalog-v1', digest: 'sha256:' + '0'.repeat(64), kind: 'descriptor-package' as const }, input: sourceInput, result: sourceResult, targetPolicy: { id: 'single-core-captured-source-span-v1', targetKind: 'source-span' as const, maxTargets: 1 as const, projectOnly: true as const }, projectScopePolicy: { id: 'exact-project-identity-v1', binding: 'exact-project-identity' as const, targetMustBeInProject: true as const }, capabilities: ['captured-source-read'] as const, resources: { maxInputBytes: 32 * 1024, maxReadBytes: 10 * 1024 * 1024, maxOutputBytes: 8 * 1024, maxDepth: 8, maxNodes: 256, timeoutMs: 2000, memoryBytes: 64 * 1024 * 1024, processCount: 1 }, requirements: { offline: true as const, readOnly: true as const, noProjectModification: true as const, noCredentialInheritance: true as const, cli: false as const, desktopEndpoint: false as const }, failureCategories: ['unavailable','unsafe-target','invalid-encoding','limit-exceeded'], audit: { owner: 'core' as const, classification: 'integrity-check' as const, recordsDigests: true as const, recordsSourceText: false as const }, compatibility: { contractMajor: 1 as const, compatibleWith: ['controlled-validation-v1'], breakingChangesRequireNewMajor: true as const } };
/** Descriptor-only catalog identity digest; it identifies immutable metadata, not executable code or trusted authorship. */
export const SOURCE_SPAN_INTEGRITY_CHECK_V1 = deepFreeze({ ...sourceDescriptorWithoutDigest, artifact: { ...sourceDescriptorWithoutDigest.artifact, digest: `sha256:${createHash('sha256').update(canonicalize(sourceDescriptorWithoutDigest)).digest('hex')}` } }) as ProcedureDescriptorV1;
export function createCoreProcedureRegistry(): ProcedureRegistry { const registry = new ProcedureRegistry(); registry.register(SOURCE_SPAN_INTEGRITY_CHECK_V1); return registry; }
export function procedureDescriptorDigest(descriptor: ProcedureDescriptorV1): string { return digestCanonical(descriptor); }





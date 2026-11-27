import * as assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { suite, test } from 'mocha';
import { ProcedureArtifactVerifier, ProcedureRegistry, ProcedureRegistryError, ProcedureVerificationError, SOURCE_SPAN_INTEGRITY_CHECK_V1, createCoreProcedureRegistry, ProcedureDescriptorV1, ProcedureArtifactTrustProviders, validateProcedureDescriptor } from '../../packages/core/src/validation/procedures/registry';

const goodArgs = { observationId:'obs-1', snapshotId:'snap-1', snapshotFingerprint:`sha256:${'a'.repeat(64)}`, scanId:'scan-1', findingId:'finding-1', relativePath:'src/a.ts', startLine:1, endLine:2, expectedFileDigest:`sha256:${'b'.repeat(64)}`, expectedSpanDigest:`sha256:${'c'.repeat(64)}` };
const scopeFor = (args: Record<string, string | number>) => ({ projectIdentity:'project-1', targetProjectIdentity:'project-1', targetCount:1, target:Object.fromEntries(['observationId','snapshotId','snapshotFingerprint','scanId','findingId','relativePath','startLine','endLine'].map(k=>[k,args[k]])) as Record<string,string|number> });
const scope = scopeFor(goodArgs);
function descriptor(id = 'aqiron.core:test-procedure', version = '1.0.0', digest = `sha256:${'1'.repeat(64)}`): ProcedureDescriptorV1 {
	return validateProcedureDescriptor({ ...SOURCE_SPAN_INTEGRITY_CHECK_V1, id, version, artifact:{...SOURCE_SPAN_INTEGRITY_CHECK_V1.artifact, identity:'test-catalog',digest} });
}
function providers(overrides: Partial<ProcedureArtifactTrustProviders> = {}): ProcedureArtifactTrustProviders {
	return {
		verifySignature: async () => true,
		verifyTrustedCatalog: async () => true,
		getSigningKeyStatus: async () => 'active',
		getRevocationStatus: async () => 'active',
		...overrides,
	};
}
const bytes = Buffer.from('deterministic test artifact');
const sha = (value: Uint8Array) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const signature = { catalogIdentity:'test-catalog', signingKeyIdentity:'test-key', signature:new Uint8Array([1,2,3]) };

suite('Controlled Validation procedure registry', () => {
	test('registers unique immutable descriptors and resolves exact identity/version', () => {
		const registry = new ProcedureRegistry();
		const first = registry.register(descriptor());
		assert.equal(registry.get(first.id, first.version), first);
		assert.ok(Object.isFrozen(first)); assert.ok(Object.isFrozen(first.input)); assert.ok(Object.isFrozen(first.resources));
		assert.throws(() => (first as any).id = 'changed');
		assert.throws(() => registry.register(descriptor()), (e: unknown) => e instanceof ProcedureRegistryError && e.code === 'DUPLICATE_ID');
		assert.throws(() => registry.register(descriptor('aqiron.core:different-procedure', '1.0.0')), (e: unknown) => e instanceof ProcedureRegistryError && e.code === 'DUPLICATE_VERSION');
	});
	test('rejects ambiguous definitions, mutable schema fields, and malformed descriptors', () => {
		const registry = new ProcedureRegistry(); registry.register(descriptor());
		assert.throws(() => registry.register({...descriptor('aqiron.core:other-procedure', '2.0.0'), capabilities:['network'] as any}), (e: unknown) => e instanceof ProcedureRegistryError && e.code === 'UNSUPPORTED_CAPABILITY');
		assert.throws(() => validateProcedureDescriptor({...descriptor(), unexpected:'value'}), (e: unknown) => e instanceof ProcedureRegistryError && e.code === 'INVALID_DESCRIPTOR');
		const mutableSchema = {...descriptor(), input:{...(descriptor().input as any), additionalProperties:true}};
		assert.throws(() => validateProcedureDescriptor(mutableSchema));
		const unsafePattern = {...descriptor(), input:{...(descriptor().input as any), properties:{...(descriptor().input as any).properties, observationId:{type:'string',minLength:1,maxLength:32,pattern:'(a+)+'}}}};
		assert.throws(() => validateProcedureDescriptor(unsafePattern));
	});
	test('fails artifact digest mismatch before accepting signature metadata', async () => {
		const d = descriptor('aqiron.core:test-digest', '1.0.0', `sha256:${'0'.repeat(64)}`);
		await assert.rejects(new ProcedureArtifactVerifier(providers()).verify(d, bytes, signature), (e: unknown) => e instanceof ProcedureVerificationError && e.code === 'ARTIFACT_DIGEST_MISMATCH');
	});
	test('fails closed for unavailable signature, catalog, key status, and revocation providers', async () => {
		const d = descriptor('aqiron.core:test-verify', '1.0.0', sha(bytes));
		await assert.rejects(new ProcedureArtifactVerifier().verify(d, bytes, signature), (e: unknown) => e instanceof ProcedureVerificationError && e.code === 'CATALOG_PROVIDER_UNAVAILABLE');
		await assert.rejects(new ProcedureArtifactVerifier({verifyTrustedCatalog:async()=>true}).verify(d,bytes,signature), (e: unknown) => e instanceof ProcedureVerificationError && e.code === 'SIGNATURE_VERIFIER_UNAVAILABLE');
		await assert.rejects(new ProcedureArtifactVerifier(providers({getSigningKeyStatus:undefined})).verify(d,bytes,signature), (e: unknown) => e instanceof ProcedureVerificationError && e.code === 'SIGNATURE_VERIFIER_UNAVAILABLE');
		await assert.rejects(new ProcedureArtifactVerifier(providers({getRevocationStatus:undefined})).verify(d,bytes,signature), (e: unknown) => e instanceof ProcedureVerificationError && e.code === 'REVOCATION_PROVIDER_UNAVAILABLE');
	});
	test('rejects invalid or revoked signing identities, untrusted catalogs, bad signatures, and revoked artifacts', async () => {
		const d = descriptor('aqiron.core:test-identities', '1.0.0', sha(bytes));
		for (const [provider, code] of [
			[providers({getSigningKeyStatus:async()=> 'invalid'}), 'SIGNING_IDENTITY_INVALID'],
			[providers({getSigningKeyStatus:async()=> 'revoked'}), 'SIGNING_IDENTITY_REVOKED'],
			[providers({verifyTrustedCatalog:async()=>false}), 'CATALOG_UNTRUSTED'],
			[providers({verifySignature:async()=>false}), 'SIGNATURE_INVALID'],
			[providers({getRevocationStatus:async()=> 'revoked'}), 'ARTIFACT_REVOKED'],
		] as const) { await assert.rejects(new ProcedureArtifactVerifier(provider).verify(d,bytes,signature), (e: unknown) => e instanceof ProcedureVerificationError && e.code === code); }
	});
	test('validates argument types, inclusive boundaries, exact project, and exact selected target', () => {
		const registry = createCoreProcedureRegistry();
		assert.deepEqual(registry.validateArguments(SOURCE_SPAN_INTEGRITY_CHECK_V1.id, '1.0.0', goodArgs, scope), goodArgs);
		for (const value of [ {...goodArgs,startLine:0}, {...goodArgs,endLine:4_097}, {...goodArgs,startLine:'1'}, {...goodArgs,extra:'field'}, {...goodArgs,relativePath:'../secret'} ]) {
			assert.throws(() => registry.validateArguments(SOURCE_SPAN_INTEGRITY_CHECK_V1.id,'1.0.0',value,scopeFor(value)));
		}
		assert.throws(() => registry.validateArguments(SOURCE_SPAN_INTEGRITY_CHECK_V1.id,'1.0.0',{...goodArgs,relativePath:'other.ts'},scope), (e: unknown) => e instanceof ProcedureRegistryError && e.code === 'SCOPE_MISMATCH');
		assert.throws(() => registry.validateArguments(SOURCE_SPAN_INTEGRITY_CHECK_V1.id,'1.0.0',goodArgs,{...scope,targetCount:2}));
	});
	test('rejects deeply nested and oversized inputs within canonical and schema bounds', () => {
		const registry = createCoreProcedureRegistry();
		const oversized = {...goodArgs, relativePath:'x'.repeat(40_000)};
		assert.throws(() => registry.validateArguments(SOURCE_SPAN_INTEGRITY_CHECK_V1.id,'1.0.0',oversized,{...scope,target:{...scope.target,relativePath:oversized.relativePath}}));
		let nested: any = goodArgs; for (let i=0;i<80;i++) { nested={...nested, observationId:nested}; }
		assert.throws(() => registry.validateArguments(SOURCE_SPAN_INTEGRITY_CHECK_V1.id,'1.0.0',nested,scope));
	});
	test('rejects non-v1 capabilities, policies, and project scope mismatches', () => {
		assert.throws(() => new ProcedureRegistry().register({...descriptor(),capabilities:['network'] as any}), (e: unknown) => e instanceof ProcedureRegistryError && e.code === 'UNSUPPORTED_CAPABILITY');
		assert.throws(() => new ProcedureRegistry().register({...descriptor(),requirements:{...descriptor().requirements,offline:false}}), (e: unknown) => e instanceof ProcedureRegistryError && e.code === 'INVALID_DESCRIPTOR');
	});
	test('initial descriptor is metadata only and registry has no execution path', () => {
		const initial = createCoreProcedureRegistry().get('aqiron.core:source-span-integrity-check-v1','1.0.0');
		assert.equal(initial.audit.recordsSourceText, false);
		assert.deepEqual(initial.capabilities,['captured-source-read']);
		assert.equal(initial.requirements.offline,true); assert.equal(initial.requirements.readOnly,true);
		assert.ok(!Object.keys(initial).some(k => /body|script|command|executable/i.test(k)));
		assert.equal('execute' in ProcedureRegistry.prototype,false); assert.equal('launch' in ProcedureRegistry.prototype,false);
		assert.throws(() => new ProcedureRegistry().get(initial.id,'1.0.0'));
	});
	test('verified handoff is immutable and carries catalog, signing, and revocation checked identity', async () => {
		const d = descriptor('aqiron.core:test-handoff','1.0.0',sha(bytes));
		const result = await new ProcedureArtifactVerifier(providers()).verify(d,bytes,signature);
		assert.equal(result.verified,true); assert.equal(result.descriptor,d); assert.equal(result.artifactDigest,sha(bytes));
		assert.equal(result.catalogIdentity,'test-catalog'); assert.equal(result.signingKeyIdentity,'test-key');
		assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.descriptor));
	});
});




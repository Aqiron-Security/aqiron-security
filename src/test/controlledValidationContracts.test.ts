import * as assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { suite, test } from 'mocha';
import { CANONICALIZATION_LIMITS, canonicalize, derivePhysicalWorkspaceIdentity, digestCanonical, preparationManifestDigest, ProcedureRegistry, validatePreparationManifest, validateProcedureMetadata } from '../../packages/core/src/validation/contracts';

const digest=`sha256:${'a'.repeat(64)}`;
const procedure={schemaVersion:1,id:'aqiron:http:header-check',version:'1.2.3',packageDigest:digest,publisherId:'aqiron-core',signature:{identity:'aqiron-release',state:'unverified'},supportedHypothesisTypes:['web-header'],supportedAssetTypes:['service'],requiredEvidenceTypes:['finding'],parameterSchemaId:'schema-v1',targetPolicyId:'offline-target-v1',scopePolicyId:'local-only-v1',environmentRequirements:['node-22'],capabilities:{filesystem:'none',network:'none'},resourceCeilings:{timeoutMs:1000,memoryBytes:1048576,outputBytes:4096,processCount:1},resultSchemaId:'result-v1',retirement:'active'};
const manifest={schemaVersion:1,hypothesis:{id:'hyp-1',contentDigest:digest},snapshot:{id:'snap-1',fingerprint:digest},workspaceIdentity:digest,evidence:[{id:'ev-1',kind:'finding',digest}],procedure:{id:procedure.id,version:procedure.version,packageDigest:digest,signatureIdentity:'aqiron-release'},target:{identity:'local-target',allowedScope:{kind:'workspace'}},environment:{runtimeIdentity:'node-22',policyDigest:digest},parameters:{z:2,a:['x',true]},requestedOperations:['inspect'],resourceLimits:{timeoutMs:1000}};

suite('Controlled Validation contracts',()=>{
	test('canonical vectors and insertion-order independence',()=>{
		assert.equal(canonicalize({z:1,a:'x',b:[true,null]}),'{"a":"x","b":[true,null],"z":1}');
		assert.equal(canonicalize({b:[true,null],a:'x',z:1}),canonicalize({z:1,a:'x',b:[true,null]}));
		assert.equal(digestCanonical({a:1}), '015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862');
	});
	test('derives a stable non-path physical workspace identity',async()=>{const root=await fs.mkdtemp(path.join(os.tmpdir(),'aqiron-workspace-id-'));try{const filesystem={lstat:async(p:string)=>{const s=await fs.lstat(p);return {isFile:()=>s.isFile(),isDirectory:()=>s.isDirectory(),isSymbolicLink:()=>s.isSymbolicLink(),size:s.size,mtimeMs:s.mtimeMs};},realpath:async(p:string)=>await fs.realpath(p)};const a=await derivePhysicalWorkspaceIdentity(root,filesystem as any);const b=await derivePhysicalWorkspaceIdentity(root,filesystem as any);assert.equal(a,b);assert.match(a,/^sha256:[a-f0-9]{64}$/);assert.ok(!a.includes(root));}finally{await fs.rm(root,{recursive:true,force:true});}});
	test('rejects unsupported canonical values',()=>{
		const cycle:any={};cycle.self=cycle;
		for(const v of [undefined,NaN,Infinity,cycle,new Date(),Object.assign(Object.create({x:1}),{a:1}),Array(1)]) {assert.throws(()=>canonicalize(v));}
		assert.throws(()=>canonicalize({value:undefined}));
		const hidden={a:1};Object.defineProperty(hidden,'secret',{value:2});assert.throws(()=>canonicalize(hidden));
	});
	test('bounds canonical traversal depth, nodes, strings, containers, and aggregate bytes',()=>{
		let nested:unknown=null;for(let i=0;i<=CANONICALIZATION_LIMITS.maxDepth;i++){nested=[nested];}assert.throws(()=>canonicalize(nested),/maximum depth/);
		const manyNodes=Array.from({length:101},()=>Array.from({length:200},()=>null));assert.throws(()=>canonicalize(manyNodes),/node limit/);
		assert.throws(()=>canonicalize('x'.repeat(CANONICALIZATION_LIMITS.maxStringBytes+1)),/per-string byte limit/);
		assert.throws(()=>canonicalize(Array.from({length:CANONICALIZATION_LIMITS.maxContainerEntries+1},()=>null)),/container-entry limit/);
		const tooManyProperties=Object.fromEntries(Array.from({length:CANONICALIZATION_LIMITS.maxContainerEntries+1},(_,i)=>[`p${i}`,null]));assert.throws(()=>canonicalize(tooManyProperties),/container-entry limit/);
		const tooManyBytes=Object.fromEntries(Array.from({length:18},(_,i)=>[`key-${i}`, 'x'.repeat(60_000)]));assert.throws(()=>canonicalize(tooManyBytes),/serialized byte limit/);
		assert.throws(()=>canonicalize({['k'.repeat(CANONICALIZATION_LIMITS.maxStringBytes+1)]:true}),/property name exceeds/);
	});
	test('bounded canonicalization preserves valid nested manifest output and stable vectors',()=>{
		const valid=validatePreparationManifest(manifest);assert.equal(canonicalize(valid),canonicalize(manifest));assert.equal(digestCanonical({a:1}), '015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862');
		const invalid={...manifest,parameters:Object.fromEntries(Array.from({length:18},(_,i)=>[`parameter-${i}`,'x'.repeat(60_000)]))};assert.throws(()=>validatePreparationManifest(invalid),/serialized byte limit/);
	});
	test('validates immutable metadata and rejects unknown, invalid, mutable-version content',()=>{
		const frozen=validateProcedureMetadata(procedure); assert.equal(Object.isFrozen(frozen),true); assert.equal(Object.isFrozen(frozen.capabilities),true);
		assert.throws(()=>validateProcedureMetadata({...procedure,unexpected:true}));
		assert.throws(()=>validateProcedureMetadata({...procedure,version:'v1'}));assert.throws(()=>validateProcedureMetadata({...procedure,version:'1.2.3-01'}));
		assert.throws(()=>validateProcedureMetadata({...procedure,packageDigest:'sha256:bad'}));
		assert.throws(()=>validateProcedureMetadata({...procedure,signature:{identity:'release',state:'verified'}}));
		const registry=new ProcedureRegistry();registry.register(procedure);assert.throws(()=>registry.register({...procedure,packageDigest:`sha256:${'b'.repeat(64)}`}));
	});
	test('manifest digest binds every security relevant field and excludes authorization facts',()=>{
		validatePreparationManifest(manifest); const base=preparationManifestDigest(manifest);
		const changed=[
			{...manifest,hypothesis:{...manifest.hypothesis,id:'hyp-2'}},{...manifest,hypothesis:{...manifest.hypothesis,contentDigest:`sha256:${'b'.repeat(64)}`}},
			{...manifest,snapshot:{...manifest.snapshot,id:'snap-2'}},{...manifest,snapshot:{...manifest.snapshot,fingerprint:`sha256:${'b'.repeat(64)}`}},{...manifest,workspaceIdentity:`sha256:${'b'.repeat(64)}`},
			{...manifest,evidence:[{...manifest.evidence[0],id:'ev-2'}]},{...manifest,evidence:[{...manifest.evidence[0],kind:'relationship'}]},{...manifest,evidence:[{...manifest.evidence[0],digest:`sha256:${'b'.repeat(64)}`} ]},
			{...manifest,procedure:{...manifest.procedure,id:'aqiron:http:other'}},{...manifest,procedure:{...manifest.procedure,version:'1.2.4'}},{...manifest,procedure:{...manifest.procedure,packageDigest:`sha256:${'b'.repeat(64)}`}},{...manifest,procedure:{...manifest.procedure,signatureIdentity:'other-release'}},
			{...manifest,target:{...manifest.target,identity:'other'}},{...manifest,target:{...manifest.target,allowedScope:{kind:'different'}}},
			{...manifest,environment:{...manifest.environment,runtimeIdentity:'node-23'}},{...manifest,environment:{...manifest.environment,policyDigest:`sha256:${'b'.repeat(64)}`}},
			{...manifest,parameters:{z:3,a:['x',true]}},{...manifest,requestedOperations:['inspect','read']},{...manifest,resourceLimits:{timeoutMs:999}}
		];
		for(const item of changed) {assert.notEqual(preparationManifestDigest(item),base);}
		assert.throws(()=>validatePreparationManifest({...manifest,principal:'alice'}));
		assert.throws(()=>validatePreparationManifest({...manifest,unexpected:true}));
	});
});

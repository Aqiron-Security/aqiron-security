import { createHash, randomUUID } from 'node:crypto';
import * as path from 'node:path';
import type { FileSystem } from '../shared/platform';
import { withWorkspaceLock } from '../hypotheses/hypothesisStore';
import { canonicalize } from './contracts';

export type ExecutionLifecycle = 'prepared'|'awaiting-authorization'|'authorized'|'queued'|'starting'|'running'|'cancel-requested'|'cancelled-local'|'remote-stop-unconfirmed'|'completed'|'failed'|'expired'|'interrupted';
export type ResultOutcome = 'reproduced'|'not-reproduced'|'inconclusive'|'blocked'|'environment-error';
export type AuthorizationState = 'not-applicable'|'awaiting'|'authorized'|'consumed'|'denied'|'blocked'|'expired'|'revoked';
export type ReviewerInterpretation = 'supports'|'contradicts'|'inconclusive'|'informational';
export type HypothesisReviewStatus = 'proposed'|'investigating'|'validated'|'rejected'|'dismissed'|'stale'|'unsubstantiated';
export type ConfirmedScannerFindingStatus = 'unconfirmed'|'confirmed'|'not-confirmed';

export interface AttemptEventV1 {
	schemaVersion: 1; eventId: string; attemptId: string; sequence: number;
	eventType: 'lifecycle'|'outcome'|'authorization'|'reviewer-interpretation'|'hypothesis-review'|'scanner-finding';
	timestamp: string; previousEventHash: string; eventHash: string;
	payload: { lifecycle?: ExecutionLifecycle; outcome?: ResultOutcome; authorization?: AuthorizationState; receiptDigest?: string|null; manifestDigest?: string|null; principal?: string|null; authenticationAssurance?: string|null; authenticationMethod?: string|null; consentTimestamp?: string|null; expiresAt?: string|null; authorizationId?: string|null; nonce?: string|null; consumedAt?: string|null; reviewerInterpretation?: ReviewerInterpretation; hypothesisReviewStatus?: HypothesisReviewStatus; confirmedFindingStatus?: ConfirmedScannerFindingStatus; details?: Record<string, unknown> };
}
export const EMPTY_EVENT_HASH = '0'.repeat(64);
export const MAX_ATTEMPT_EVENT_BYTES = 32_768;
export const MAX_ATTEMPT_LEDGER_BYTES = 8 * 1024 * 1024;
export const MAX_ATTEMPT_QUERY_EVENTS = 500;
const fields=['schemaVersion','eventId','attemptId','sequence','eventType','timestamp','previousEventHash','eventHash','payload'];
const lifecycle=new Set(['prepared','awaiting-authorization','authorized','queued','starting','running','cancel-requested','cancelled-local','remote-stop-unconfirmed','completed','failed','expired','interrupted']);
const outcome=new Set(['reproduced','not-reproduced','inconclusive','blocked','environment-error']);
const auth=new Set(['not-applicable','awaiting','authorized','consumed','denied','blocked','expired','revoked']);
const interpretations=new Set(['supports','contradicts','inconclusive','informational']);
const reviews=new Set(['proposed','investigating','validated','rejected','dismissed','stale','unsubstantiated']);
const findings=new Set(['unconfirmed','confirmed','not-confirmed']);

export function validateAttemptEvent(value: unknown): AttemptEventV1 {
	canonicalize(value);
	const x=plain(value); exact(x,fields); if(x.schemaVersion!==1||!eventId(x.eventId)||!eventId(x.attemptId)||!Number.isSafeInteger(x.sequence)||x.sequence<1||!['lifecycle','outcome','authorization','reviewer-interpretation','hypothesis-review','scanner-finding'].includes(x.eventType)||typeof x.timestamp!=='string'||!validIso(x.timestamp)||!hash(x.previousEventHash)||!hash(x.eventHash)) {throw new Error('Invalid attempt event envelope.');}
	const p=plain(x.payload); const receiptFields=['receiptDigest','manifestDigest','principal','authenticationAssurance','authenticationMethod','consentTimestamp','expiresAt','authorizationId','nonce']; const allowed=['lifecycle','outcome','authorization',...receiptFields,'consumedAt','reviewerInterpretation','hypothesisReviewStatus','confirmedFindingStatus','details']; if(Object.keys(p).some(k=>!allowed.includes(k))||Object.keys(p).length===0){throw new Error('Invalid attempt event payload.');}
	if(p.lifecycle!==undefined&&!lifecycle.has(p.lifecycle as string)||p.outcome!==undefined&&!outcome.has(p.outcome as string)||p.authorization!==undefined&&!auth.has(p.authorization as string)||p.reviewerInterpretation!==undefined&&!interpretations.has(p.reviewerInterpretation as string)||p.hypothesisReviewStatus!==undefined&&!reviews.has(p.hypothesisReviewStatus as string)||p.confirmedFindingStatus!==undefined&&!findings.has(p.confirmedFindingStatus as string)){throw new Error('Invalid attempt event state.');}
	const stateField:Record<string,string>={'lifecycle':'lifecycle','outcome':'outcome','authorization':'authorization','reviewer-interpretation':'reviewerInterpretation','hypothesis-review':'hypothesisReviewStatus','scanner-finding':'confirmedFindingStatus'};
	const matching=stateField[x.eventType as string]; if(typeof p[matching]!=='string'||Object.keys(p).some(k=>k!=='details'&&k!=='consumedAt'&&!receiptFields.includes(k)&&k!==matching)){throw new Error('Attempt event type and payload state do not match.');}
	if(x.eventType!=='authorization'&&Object.keys(p).some(k=>[...receiptFields,'consumedAt'].includes(k))){throw new Error('Authorization facts belong only to authorization events.');}
	for(const k of [...receiptFields,'consumedAt']) {if(p[k]!==undefined&&p[k]!==null&&typeof p[k]!=='string'){throw new Error('Invalid nullable authorization fact.');}}
	if(p.receiptDigest!==undefined&&p.receiptDigest!==null&&!/^sha256:[a-f0-9]{64}$/.test(p.receiptDigest as string)||p.manifestDigest!==undefined&&p.manifestDigest!==null&&!/^sha256:[a-f0-9]{64}$/.test(p.manifestDigest as string)){throw new Error('Invalid receipt or manifest digest.');}
	const hasReceipt=typeof p.receiptDigest==='string'; const hasAnyReceiptFact=receiptFields.some(k=>p[k]!==undefined&&p[k]!==null);
	if(!hasReceipt&&hasAnyReceiptFact||!hasReceipt&&typeof p.consumedAt==='string'){throw new Error('Authorization facts require a receipt digest.');}
	if((p.authorization==='authorized'||p.authorization==='consumed')&&!hasReceipt){throw new Error('Authorized or consumed state requires a receipt digest.');}
	if(['not-applicable','awaiting','denied','blocked'].includes(String(p.authorization))&&(hasReceipt||hasAnyReceiptFact||p.consumedAt!==undefined&&p.consumedAt!==null)){throw new Error('This authorization state cannot contain receipt facts.');}
	if(hasReceipt&&receiptFields.some(k=>typeof p[k]!=='string'||(p[k] as string).length<1||(p[k] as string).length>256)){throw new Error('A receipt requires all bounded receipt facts.');}
	if(p.authorization==='consumed'&&(typeof p.consumedAt!=='string'||p.consumedAt!==x.timestamp)){throw new Error('Consumed authorization time must equal the event timestamp.');}
	if(p.authorization!=='consumed'&&p.consumedAt!==undefined&&p.consumedAt!==null){throw new Error('Only grant consumption events may record a consumed time.');}
	if(p.consentTimestamp!==undefined&&p.consentTimestamp!==null&&!validIso(p.consentTimestamp as string)||p.expiresAt!==undefined&&p.expiresAt!==null&&!validIso(p.expiresAt as string)||p.consumedAt!==undefined&&p.consumedAt!==null&&!validIso(p.consumedAt as string)){throw new Error('Invalid authorization timestamp.');}
	if(hasReceipt&&(!validIso(p.consentTimestamp as string)||!validIso(p.expiresAt as string)||Date.parse(p.consentTimestamp as string)>=Date.parse(p.expiresAt as string)||Date.parse(x.timestamp as string)<Date.parse(p.consentTimestamp as string)||((p.authorization==='authorized'||p.authorization==='consumed')&&Date.parse(x.timestamp as string)>=Date.parse(p.expiresAt as string))||(p.authorization==='expired'&&Date.parse(x.timestamp as string)<Date.parse(p.expiresAt as string)))){throw new Error('Receipt timestamps are inconsistent with the authorization event.');}
	if(p.details!==undefined) { const details=plain(p.details); if(Buffer.byteLength(canonicalize(details),'utf8')>MAX_ATTEMPT_EVENT_BYTES/2){throw new Error('Attempt details are oversized.');} }
	if(Buffer.byteLength(canonicalize(eventHashInput(x as unknown as AttemptEventV1)),'utf8')>MAX_ATTEMPT_EVENT_BYTES){throw new Error('Attempt event is oversized.');}
	return JSON.parse(JSON.stringify(x)) as AttemptEventV1;
}
export function eventHashInput(event: Omit<AttemptEventV1,'eventHash'>|AttemptEventV1): unknown { const {eventHash: _omitted,...included}=event as AttemptEventV1; return included; }

export interface AppendAttemptEventInput { attemptId: string; eventType: AttemptEventV1['eventType']; timestamp: string; payload: AttemptEventV1['payload']; eventId?: string; }
export type AttemptLedgerState = {available:true;events:AttemptEventV1[]}|{available:false;reason:'integrity-unavailable'|'durability-unavailable'|'storage-unavailable'};
const ambiguousWorkspaces=new Set<string>();
export class AttemptLedgerIntegrityError extends Error { readonly code='ATTEMPT_LEDGER_INTEGRITY'; constructor(message:string,cause?:unknown){super(message,{cause});this.name='AttemptLedgerIntegrityError';} }
function integrity(message:string,cause?:unknown):AttemptLedgerIntegrityError{return new AttemptLedgerIntegrityError(message,cause);}
export class AttemptLedger {
	private readonly maxBytes:number;
	constructor(private readonly filesystem:FileSystem, private readonly options:{maxBytes?:number; eventId?:()=>string}={}){
		const limit=options.maxBytes===undefined?MAX_ATTEMPT_LEDGER_BYTES:options.maxBytes;
		if(!Number.isSafeInteger(limit)||limit<1||limit>MAX_ATTEMPT_LEDGER_BYTES){throw new RangeError(`Attempt ledger capacity must be an integer from 1 to ${MAX_ATTEMPT_LEDGER_BYTES} bytes.`);}
		this.maxBytes=limit;
	}
	async query(workspaceRoot:string,limit=MAX_ATTEMPT_QUERY_EVENTS):Promise<AttemptLedgerState>{
		if(!Number.isSafeInteger(limit)||limit<1||limit>MAX_ATTEMPT_QUERY_EVENTS){throw new RangeError('Invalid bounded ledger query limit.');}
		try { const loaded=await withWorkspaceLock(workspaceRoot,this.filesystem,async root=>{if(ambiguousWorkspaces.has(path.resolve(root))){throw integrity('Attempt history unavailable after ambiguous persistence.');}return await this.load(root);}); return {available:true,events:loaded.slice(-limit)}; }
		catch(e){if(isDurabilityFailure(e)){return {available:false,reason:'durability-unavailable'};}if(e instanceof AttemptLedgerIntegrityError){return {available:false,reason:'integrity-unavailable'};}return {available:false,reason:'storage-unavailable'};}
	}
	async append(workspaceRoot:string,input:AppendAttemptEventInput):Promise<AttemptEventV1>{
		const snapshot=snapshotAppendInput(input);
		const eventId=snapshot.eventId??(this.options.eventId??randomUUID)();
		if(!validEventId(eventId)){throw new TypeError('Invalid generated attempt event ID.');}
		return await withWorkspaceLock(workspaceRoot,this.filesystem,async root=>{
			const key=path.resolve(root); if(ambiguousWorkspaces.has(key)){throw integrity('Attempt history is unavailable after an ambiguous append.');}
			const events=await this.load(root);
			const priorEvent=events.find(e=>e.eventId===eventId);
			if(priorEvent){if(sameIntent(priorEvent,snapshot)){return detachedEvent(priorEvent);}throw new Error('Attempt event ID was reused for a different operation.');}
			const previous=events.at(-1); const unsigned={schemaVersion:1 as const,eventId,attemptId:snapshot.attemptId,sequence:(previous?.sequence??0)+1,eventType:snapshot.eventType,timestamp:snapshot.timestamp,previousEventHash:previous?.eventHash??EMPTY_EVENT_HASH,payload:snapshot.payload};
			const candidate={...unsigned,eventHash:createHash('sha256').update(canonicalize(unsigned)).digest('hex')} as AttemptEventV1;
			const event=validateAttemptEvent(candidate);
			validateAttemptHistory([...events,event]);
			const line=Buffer.from(`${canonicalize(event)}\n`,'utf8'); if((await this.readLedgerBytes(root,this.maxBytes)).byteLength+line.byteLength>this.maxBytes){throw new Error('Attempt ledger capacity exceeded.');}
			const append=this.filesystem.appendFileDurable; const createMarker=this.filesystem.writeFileDurableExclusive; const removeMarker=this.filesystem.unlinkDurable;
			if(!append||!createMarker||!removeMarker){throw Object.assign(new Error('Durable append and recovery-marker capabilities are required.'),{code:'DURABILITY_UNAVAILABLE'});}
			const marker=markerPath(root); const markerBytes=Buffer.from(canonicalize({eventId,attemptId:snapshot.attemptId,sequence:event.sequence,eventHash:event.eventHash}),'utf8');
			try { await createMarker(marker,markerBytes); await append(ledgerPath(root),line); await removeMarker(marker); }
			catch(error){ambiguousWorkspaces.add(key);throw Object.assign(new Error('Attempt append failed; commit state is ambiguous and history is unavailable.'),{code:'ATTEMPT_APPEND_AMBIGUOUS',cause:error});}
			return detachedEvent(event);
		});
	}
	private async load(root:string):Promise<AttemptEventV1[]>{
		const file=ledgerPath(root); const dir=path.dirname(file); await this.ensureSafeDirectory(root,dir);
		if(!this.filesystem.readdir){throw new Error('Recovery-artifact inspection is required.');}
		const entries=await this.filesystem.readdir(dir); if(entries.some(entry=>(typeof entry==='string'?entry:entry.name)!=='attempts.log')){throw integrity('Conflicting validation recovery artifact; history is unavailable.');}
		let bytes:Uint8Array;try{bytes=await this.readLedgerBytes(root,this.maxBytes);}catch(error){if((error as NodeJS.ErrnoException).code==='FILE_TOO_LARGE'){throw integrity('Attempt ledger exceeds the configured hard capacity.',error);}throw error;}
		if(bytes.byteLength===0){return [];} let text:string;
		try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch(error){throw integrity('Malformed UTF-8 in attempt history.',error);}
		if(!text.endsWith('\n')){throw integrity('Torn attempt ledger record.');}
		const events:AttemptEventV1[]=[];const ids=new Set<string>();let prior=EMPTY_EVENT_HASH;let seq=0;
		for(const line of text.slice(0,-1).split('\n')){
			if(!line){throw integrity('Empty committed event record.');}
			let event:AttemptEventV1;
			try{event=validateAttemptEvent(JSON.parse(line));}catch(error){throw integrity('Malformed committed attempt event.',error);}
			if(event.sequence!==++seq||event.previousEventHash!==prior||ids.has(event.eventId)){throw integrity('Attempt sequence, event ID, or hash-chain link is invalid.');}
			const expected=createHash('sha256').update(canonicalize(eventHashInput(event))).digest('hex');if(event.eventHash!==expected){throw integrity('Attempt event digest mismatch.');}
			ids.add(event.eventId);prior=event.eventHash;events.push(event);
		}
		validateAttemptHistory(events);
		return events;
	}
	private async readLedgerBytes(root:string,max:number):Promise<Uint8Array>{const file=ledgerPath(root);if(!this.filesystem.readFileSafeBoundedBytes||!this.filesystem.lstat){throw new Error('Safe bounded byte reads and path inspection are required.');}let stat;try{stat=await this.filesystem.lstat(file);}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT'){throw e;}const parent=await this.filesystem.lstat(path.dirname(file));if(!parent.isDirectory()||parent.isSymbolicLink()){throw new Error('Validation storage directory is unavailable.');}return new Uint8Array();}if(!stat.isFile()||stat.isSymbolicLink()){throw new Error('Unsafe ledger target.');}return await this.filesystem.readFileSafeBoundedBytes(file,max);}
	private async ensureSafeDirectory(root:string,dir:string):Promise<void>{if(!this.filesystem.lstat||!this.filesystem.realpath||!this.filesystem.syncDirectoryDurable){throw Object.assign(new Error('Safe path inspection and durable directory sync are required.'),{code:'DURABILITY_UNAVAILABLE'});}const parent=path.dirname(dir);try{await this.filesystem.syncDirectoryDurable(root);await this.filesystem.mkdir(dir);}catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST'&&(e as {code?:string}).code!=='EISDIR'){throw e;}}await this.filesystem.syncDirectoryDurable(parent);const s=await this.filesystem.lstat(dir);if(!s.isDirectory()||s.isSymbolicLink()){throw new Error('Unsafe validation storage directory.');}const actual=await this.filesystem.realpath(dir);if(path.resolve(actual)!==path.resolve(dir)){throw new Error('Validation storage path resolves unexpectedly.');}}
}
function ledgerPath(root:string):string{return path.join(root,'.aqiron-security','validation','attempts.log');}
function markerPath(root:string):string{return path.join(root,'.aqiron-security','validation','.append-pending');}
interface AttemptHistoryState { lifecycle?:ExecutionLifecycle; authorization?:AuthorizationState; receiptDigest?:string; authorizationFacts:Map<string,unknown>; grantConsumed:boolean; outcomeRecorded:boolean; }
const lifecycleEdges:Record<ExecutionLifecycle,ReadonlySet<ExecutionLifecycle>>={
	'prepared':new Set(['awaiting-authorization','failed','expired']),
	'awaiting-authorization':new Set(['authorized','failed','expired','interrupted']),
	'authorized':new Set(['queued','failed','expired','interrupted']),
	'queued':new Set(['starting','failed','expired','interrupted']),
	'starting':new Set(['running','cancel-requested','failed','interrupted']),
	'running':new Set(['cancel-requested','completed','failed','interrupted']),
	'cancel-requested':new Set(['cancelled-local','remote-stop-unconfirmed','completed','failed','interrupted']),
	'cancelled-local':new Set(), 'remote-stop-unconfirmed':new Set(), 'completed':new Set(), 'failed':new Set(), 'expired':new Set(), 'interrupted':new Set()
};
function validateAttemptHistory(events:AttemptEventV1[]):Map<string,AttemptHistoryState>{
	const states=new Map<string,AttemptHistoryState>();
	const receiptOwners=new Map<string,{attemptId:string;manifestDigest:string}>();
	const consumedNonces=new Map<string,string>();
	for(const event of events){
		let state=states.get(event.attemptId);
		if(!state){if(event.eventType!=='lifecycle'||event.payload.lifecycle!=='prepared'){throw integrity('Each attempt history must begin with lifecycle prepared.');}state={lifecycle:'prepared',authorizationFacts:new Map(),grantConsumed:false,outcomeRecorded:false};states.set(event.attemptId,state);continue;}
		if(state.outcomeRecorded&&['lifecycle','authorization','outcome'].includes(event.eventType)){throw integrity('Execution and authorization history cannot change after a terminal outcome.');}
		if(event.eventType==='lifecycle'){
			const next=event.payload.lifecycle!;const current=state.lifecycle!;
			if(!lifecycleEdges[current].has(next)){throw integrity(`Impossible lifecycle transition ${current} -> ${next}.`);}
			if(next==='authorized'&&state.authorization!=='authorized'){throw integrity('Lifecycle authorization requires an authorized receipt state.');}
			if(next==='queued'&&state.authorization!=='authorized'){throw integrity('Queueing requires a current authorized receipt state.');}
			if(next==='starting'&&(!state.grantConsumed||state.authorization!=='consumed')){throw integrity('Starting requires a single-use consumed grant.');}
			if(next==='running'&&!state.grantConsumed){throw integrity('Running requires a historically consumed grant.');}
			state.lifecycle=next;continue;
		}
		if(event.eventType==='authorization'){
			const next=event.payload.authorization!;const current=state.authorization;
			if(!current){
				if(!['not-applicable','awaiting','denied','blocked','expired'].includes(next)){throw integrity('Authorization cannot begin in a receipt-dependent state.');}
			}else{
				const allowed:Record<AuthorizationState,ReadonlySet<AuthorizationState>>={
					'not-applicable':new Set(), 'awaiting':new Set(['authorized','denied','blocked','expired']),
					'authorized':new Set(['consumed','expired','revoked']), 'consumed':new Set(['expired','revoked']),
					'denied':new Set(), 'blocked':new Set(), 'expired':new Set(), 'revoked':new Set()
				};
				if(!allowed[current].has(next)){throw integrity(`Impossible authorization transition ${current} -> ${next}.`);}
			}
			if(next==='authorized'&&state.lifecycle!=='awaiting-authorization'){throw integrity('Receipt authorization must follow awaiting-authorization.');}
			if(next==='awaiting'&&state.lifecycle!=='awaiting-authorization'){throw integrity('Awaiting authorization must follow the lifecycle awaiting-authorization state.');}
			if(next==='denied'&&state.lifecycle!=='awaiting-authorization'){throw integrity('Denial must be recorded while awaiting authorization.');}
			if(next==='not-applicable'&&state.lifecycle!=='prepared'){throw integrity('Not-applicable authorization must be recorded before authorization begins.');}
			if(next==='blocked'&&state.lifecycle!=='prepared'&&state.lifecycle!=='awaiting-authorization'){throw integrity('Authorization blocking must occur before a grant is accepted.');}
			if(next==='consumed'&&state.lifecycle!=='queued'){throw integrity('Grant consumption must bind to a queued attempt.');}
			if((next==='authorized'||next==='consumed')&&state.receiptDigest&&event.payload.receiptDigest!==state.receiptDigest){throw integrity('Authorization receipt identity changed within an attempt.');}
			if(state.receiptDigest&&event.payload.receiptDigest===null){throw integrity('A recorded authorization receipt cannot be cleared.');}
			for(const [key,value] of Object.entries(event.payload)){if(['receiptDigest','manifestDigest','principal','authenticationAssurance','authenticationMethod','consentTimestamp','expiresAt','authorizationId','nonce','consumedAt'].includes(key)&&value!==null){if(state.authorizationFacts.has(key)&&state.authorizationFacts.get(key)!==value){throw integrity(`Authorization fact ${key} changed within an attempt.`);}state.authorizationFacts.set(key,value);}}
			if(next==='expired'){
				const recordedExpiry=state.authorizationFacts.get('expiresAt');
				if(typeof recordedExpiry==='string'&&Date.parse(event.timestamp)<Date.parse(recordedExpiry)){throw integrity('Authorization cannot expire before its recorded receipt expiry.');}
			}
			if(next==='authorized'||next==='consumed'){
				const manifestDigest=event.payload.manifestDigest!;const identities=[`id:${event.payload.authorizationId!}`,`digest:${event.payload.receiptDigest!}`];
				for(const identity of identities){const owner=receiptOwners.get(identity);if(owner&&(owner.attemptId!==event.attemptId||owner.manifestDigest!==manifestDigest)){throw integrity('Authorization receipt identity is already bound to another attempt or manifest.');}receiptOwners.set(identity,{attemptId:event.attemptId,manifestDigest});}
			}
			if(event.payload.receiptDigest){state.receiptDigest=event.payload.receiptDigest;}
			if(next==='consumed'){if(state.grantConsumed){throw integrity('Authorization grant was consumed more than once.');}const nonce=event.payload.nonce!;const priorAttempt=consumedNonces.get(nonce);if(priorAttempt&&priorAttempt!==event.attemptId){throw integrity('Authorization nonce was already consumed by another attempt.');}consumedNonces.set(nonce,event.attemptId);state.grantConsumed=true;}
			state.authorization=next;continue;
		}
		if(event.eventType==='outcome'){
			if(state.outcomeRecorded){throw integrity('An attempt cannot record multiple terminal outcomes.');}
			const terminal=new Set<ExecutionLifecycle>(['completed','failed','expired','interrupted','cancelled-local','remote-stop-unconfirmed']);
			const result=event.payload.outcome!;
			if((result==='reproduced'||result==='not-reproduced')&&(state.lifecycle!=='completed'||!state.grantConsumed)){throw integrity('Positive or negative reproduction outcomes require completed execution with a historically consumed grant.');}
			if(result==='blocked'&&(!(['prepared','awaiting-authorization','authorized','queued','expired'] as ExecutionLifecycle[]).includes(state.lifecycle!)||!(state.authorization==='blocked'||state.authorization==='denied'||state.authorization==='expired'||state.authorization==='revoked'))){throw integrity('Blocked outcome requires a recorded pre-start authorization block, denial, expiry, or revocation.');}
			if(result==='environment-error'&&state.lifecycle!=='failed'&&state.lifecycle!=='interrupted'){throw integrity('Environment error requires a failed or interrupted attempt.');}
			if(result==='inconclusive'&&!terminal.has(state.lifecycle!)){throw integrity('Inconclusive outcome requires a terminal lifecycle state.');}
			state.outcomeRecorded=true;
		}
	}
	return states;
}
function snapshotAppendInput(value:unknown):AppendAttemptEventInput{
	canonicalize(value);
	const x=plain(value);const allowed=['attemptId','eventType','timestamp','payload','eventId'];
	if(Object.keys(x).some(k=>!allowed.includes(k))||['attemptId','eventType','timestamp','payload'].some(k=>!Object.prototype.hasOwnProperty.call(x,k))){throw new TypeError('Unknown or missing append request field.');}
	const candidate={schemaVersion:1 as const,eventId:x.eventId===undefined?'snapshot':x.eventId,attemptId:x.attemptId,sequence:1,eventType:x.eventType,timestamp:x.timestamp,previousEventHash:EMPTY_EVENT_HASH,eventHash:'0'.repeat(64),payload:x.payload};
	const detached=validateAttemptEvent(candidate);
	return {attemptId:detached.attemptId,eventType:detached.eventType,timestamp:detached.timestamp,payload:detached.payload,...(x.eventId!==undefined?{eventId:detached.eventId}:{})};
}
function sameIntent(event:AttemptEventV1,input:AppendAttemptEventInput):boolean{return event.attemptId===input.attemptId&&event.eventType===input.eventType&&event.timestamp===input.timestamp&&canonicalize(event.payload)===canonicalize(input.payload);}
function detachedEvent(event:AttemptEventV1):AttemptEventV1{return JSON.parse(JSON.stringify(event)) as AttemptEventV1;}
function validEventId(value:unknown):value is string{return typeof value==='string'&&value.length<=128&&/^[a-zA-Z0-9][a-zA-Z0-9._:-]*$/.test(value);}
function plain(v:unknown):Record<string,any>{if(!v||typeof v!=='object'||Array.isArray(v)||(Object.getPrototypeOf(v)!==Object.prototype&&Object.getPrototypeOf(v)!==null)){throw new TypeError('Expected plain event object.');}return v as Record<string,any>;}
function exact(x:Record<string,unknown>,keys:string[]):void{if(Object.keys(x).length!==keys.length||Object.keys(x).some(k=>!keys.includes(k))){throw new Error('Unknown or missing attempt event field.');}}
function eventId(v:unknown):v is string{return typeof v==='string'&&v.length<=128&&/^[a-zA-Z0-9][a-zA-Z0-9._:-]*$/.test(v);}
function hash(v:unknown):v is string{return typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);}
function validIso(v:string):boolean{return /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;}
function isDurabilityFailure(e:unknown):boolean{return !!e&&typeof e==='object'&&((e as {code?:string}).code==='DURABILITY_UNAVAILABLE');}

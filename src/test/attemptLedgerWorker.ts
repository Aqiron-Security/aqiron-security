import { AttemptLedger } from '../../packages/core/src/validation/attemptLedger';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';
import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';

async function main():Promise<void>{
	const [workspaceRoot,workerId,countText]=process.argv.slice(2);
	if(process.argv[2]==='hold-gate'){
		const root=process.argv[3];const securityDir=path.join(root,'.aqiron-security');const gate=`${path.join(securityDir,'hypotheses.json')}.lock.gate`;await fs.mkdir(securityDir);await fs.mkdir(gate);process.stdout.write('gate-held\n');await new Promise<void>(()=>{});return;
	}
	if(process.argv[2]==='query-ledger'){
		const root=process.argv[3];process.stdout.write('query-started\n');const state=await new AttemptLedger(createNodeFileSystem()).query(root);process.stdout.write(`${JSON.stringify(state)}\n`);return;
	}
	if(process.argv[2]==='consume-race'){
		const [,root,attemptId,barrier]=process.argv.slice(2);const ledger=new AttemptLedger(createNodeFileSystem());const timestamp=new Date().toISOString();const digest=(v:string)=>`sha256:${createHash('sha256').update(v).digest('hex')}`;const facts={receiptDigest:digest(`receipt-${attemptId}`),manifestDigest:digest(`manifest-${attemptId}`),principal:'principal-recorded',authenticationAssurance:'aal2-recorded',consentTimestamp:timestamp,expiresAt:new Date(Date.now()+3_600_000).toISOString(),authorizationId:`authorization-${attemptId}`,nonce:'workspace-race-nonce'};const append=(eventId:string,eventType:any,payload:any)=>ledger.append(root,{attemptId,eventId,eventType,timestamp,payload});
		await append('prepared','lifecycle',{lifecycle:'prepared'});await append('awaiting-life','lifecycle',{lifecycle:'awaiting-authorization'});await append('awaiting-auth','authorization',{authorization:'awaiting'});await append('authorized','authorization',{authorization:'authorized',...facts});await append('authorized-life','lifecycle',{lifecycle:'authorized'});await append('queued','lifecycle',{lifecycle:'queued'});process.stdout.write(`${attemptId}:ready\n`);while(!await fs.access(path.join(barrier,'go')).then(()=>true).catch(()=>false)){await new Promise(resolve=>setTimeout(resolve,5));}try{await append('consumed','authorization',{authorization:'consumed',...facts,consumedAt:timestamp});process.stdout.write(`${attemptId}:consumed\n`);}catch{process.stdout.write(`${attemptId}:rejected\n`);}return;
	}
	if(!workspaceRoot||!workerId||!/^\d+$/.test(countText??'')){throw new Error('Invalid ledger worker arguments.');}
	const count=Number(countText);if(!Number.isSafeInteger(count)||count<1||count>100){throw new Error('Invalid ledger worker event count.');}
	const ledger=new AttemptLedger(createNodeFileSystem());const acknowledged=[];
	for(let i=0;i<count;i++){
		const attemptId=`${workerId}-${i}`;const timestamp='2026-11-26T00:00:00.000Z';
		acknowledged.push(await ledger.append(workspaceRoot,{attemptId,eventId:`${attemptId}-prepared`,eventType:'lifecycle',timestamp,payload:{lifecycle:'prepared'}}));
		acknowledged.push(await ledger.append(workspaceRoot,{attemptId,eventId:`${attemptId}-failed`,eventType:'lifecycle',timestamp,payload:{lifecycle:'failed'}}));
	}
	process.stdout.write(`${JSON.stringify(acknowledged)}\n`);
}

void main().catch(error=>{process.stderr.write(`${error instanceof Error?error.stack:String(error)}\n`);process.exitCode=1;});

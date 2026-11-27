import * as assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { suite, test } from 'mocha';
import { appendFileDurableWithRetry, createNodeFileSystem, requireSafeOpenCapabilities } from '../../packages/core/src/runtime/nodeAdapters';

suite('Node durable filesystem adapter',function(){
	this.timeout(10000);
	test('real durability operations either synchronize or report platform limitation',async()=>{
		const root=await fs.mkdtemp(path.join(os.tmpdir(),'aqiron-node-durable-'));const adapter=createNodeFileSystem();
		try{
			const file=path.join(root,'attempts.log');const bytes=Buffer.from('first\n');
			if(process.platform==='win32'){
				for(const operation of [()=>adapter.syncDirectoryDurable!(root),()=>adapter.writeFileDurableExclusive!(path.join(root,'new.log'),bytes),()=>adapter.appendFileDurable!(file,bytes),()=>adapter.unlinkDurable!(file)]){
					await assert.rejects(operation,error=>(error as NodeJS.ErrnoException).code==='DURABILITY_UNAVAILABLE');
				}
				return;
			}
			await adapter.syncDirectoryDurable!(root);
			await adapter.writeFileDurableExclusive!(file,bytes);
			await assert.rejects(()=>adapter.writeFileDurableExclusive!(file,bytes));
			await adapter.appendFileDurable!(file,Buffer.from('second\n'));
			assert.equal(await fs.readFile(file,'utf8'),'first\nsecond\n');
			await assert.rejects(()=>adapter.appendFileDurable!(root,Buffer.from('not a file')));
			const target=path.join(root,'target');await fs.writeFile(target,'untouched');const link=path.join(root,'link');let symlinkAvailable=true;
			try{await fs.symlink(target,link);}catch(error){if((error as NodeJS.ErrnoException).code==='EPERM'||(error as NodeJS.ErrnoException).code==='EACCES'){symlinkAvailable=false;}else{throw error;}}
			if(symlinkAvailable){await assert.rejects(()=>adapter.appendFileDurable!(link,Buffer.from('bad')));await assert.rejects(()=>adapter.unlinkDurable!(link));assert.equal(await fs.readFile(target,'utf8'),'untouched');}
			await adapter.unlinkDurable!(file);await assert.rejects(()=>fs.stat(file));
		}finally{await fs.rm(root,{recursive:true,force:true});}
	});
	test('durable append exclusively creates, opens existing files without create, retries disappearance, and syncs new entries',async()=>{
		const flags={readWrite:1,append:2,create:4,exclusive:8,noFollow:16,nonBlock:32};const calls:Array<{flags:number;mode?:number}>=[];let directories=0;let writes=0;
		const handle={stat:async()=>({isFile:()=>true,nlink:1}),write:async(_b:Uint8Array,_o:number,n:number)=>{writes++;return {bytesWritten:n};},sync:async()=>{},close:async()=>{}};
		let attempt=0;
		await appendFileDurableWithRetry('C:/workspace/attempts.log',Buffer.from('record\n'),{open:async(_file,openFlags,mode)=>{calls.push({flags:openFlags,mode});attempt++;if(attempt===1){throw Object.assign(new Error('exists'),{code:'EEXIST'});}if(attempt===2){throw Object.assign(new Error('disappeared'),{code:'ENOENT'});}return handle;},syncDirectory:async()=>{directories++;}},flags);
		assert.equal(calls.length,3);assert.equal(calls[0]!.flags,(1|2|4|8|16|32));assert.equal(calls[0]!.mode,0o600);assert.equal(calls[1]!.flags,(1|2|16|32));assert.equal(calls[1]!.flags&flags.create,0,'existing-file fallback never uses O_CREAT');assert.equal(calls[2]!.flags,(1|2|4|8|16|32));for(const call of calls){assert.ok(call.flags&flags.noFollow);assert.ok(call.flags&flags.nonBlock);}assert.equal(writes,1);assert.equal(directories,1,'directory entry is synchronized after the successful exclusive create');
	});
	test('durable append bounds repeated EEXIST/ENOENT races and never recreates through fallback',async()=>{
		const flags={readWrite:1,append:2,create:4,exclusive:8,noFollow:16,nonBlock:32};let exclusiveCalls=0;let fallbackCalls=0;let directorySyncs=0;
		await assert.rejects(()=>appendFileDurableWithRetry('C:/workspace/attempts.log',Buffer.from('record\n'),{open:async(_file,openFlags)=>{if(openFlags&flags.create){exclusiveCalls++;throw Object.assign(new Error('exists'),{code:'EEXIST'});}fallbackCalls++;assert.equal(openFlags&flags.create,0);throw Object.assign(new Error('disappeared'),{code:'ENOENT'});},syncDirectory:async()=>{directorySyncs++;}},flags,3),error=>(error as NodeJS.ErrnoException).code==='ENOENT');
		assert.equal(exclusiveCalls,3);assert.equal(fallbackCalls,3);assert.equal(directorySyncs,0);
	});
	test('safe-open operations fail closed when O_NOFOLLOW or O_NONBLOCK is unavailable',()=>{
		assert.throws(()=>requireSafeOpenCapabilities(undefined,32),error=>(error as NodeJS.ErrnoException).code==='SAFE_OPEN_UNAVAILABLE');
		assert.throws(()=>requireSafeOpenCapabilities(16,undefined),error=>(error as NodeJS.ErrnoException).code==='SAFE_OPEN_UNAVAILABLE');
		assert.throws(()=>requireSafeOpenCapabilities(0,32),error=>(error as NodeJS.ErrnoException).code==='SAFE_OPEN_UNAVAILABLE');
		assert.equal(requireSafeOpenCapabilities(16,32),48);
	});
	test('bounded reads preserve ordinary reads and require real no-follow support for safe reads',async()=>{
		const root=await fs.mkdtemp(path.join(os.tmpdir(),'aqiron-safe-read-'));const adapter=createNodeFileSystem();
		try{
			const file=path.join(root,'record');await fs.writeFile(file,'safe bytes');assert.equal(Buffer.from(await adapter.readFileBoundedBytes!(file,32)).toString(),'safe bytes');
			if(process.platform==='win32'){await assert.rejects(()=>adapter.readFileSafeBoundedBytes!(file,32),error=>(error as NodeJS.ErrnoException).code==='SAFE_OPEN_UNAVAILABLE');return;}
			assert.equal(Buffer.from(await adapter.readFileSafeBoundedBytes!(file,32)).toString(),'safe bytes');
			const symlink=path.join(root,'link');await fs.symlink(file,symlink);await assert.rejects(()=>adapter.readFileSafeBoundedBytes!(symlink,32));assert.equal(await fs.readFile(file,'utf8'),'safe bytes');
		}finally{await fs.rm(root,{recursive:true,force:true});}
	});
	test('POSIX safe opens reject FIFO targets without hanging and regular files still work',async function(){
		if(process.platform==='win32'){this.skip();return;}
		const root=await fs.mkdtemp(path.join(os.tmpdir(),'aqiron-fifo-open-'));const fifo=path.join(root,'pipe');const regular=path.join(root,'regular');const mkfifo=spawnSync('mkfifo',[fifo],{encoding:'utf8',timeout:3000,windowsHide:true});
		if(mkfifo.error){await fs.rm(root,{recursive:true,force:true});throw mkfifo.error;}if(mkfifo.status!==0){await fs.rm(root,{recursive:true,force:true});throw new Error(`mkfifo failed: ${mkfifo.stderr}`);}
		const worker=path.join(__dirname,'nodeDurableFileSystemWorker.js');const children:ChildProcess[]=[];
		try{
			await fs.writeFile(regular,'regular-data');
			const safeRead=await runBoundedWorker(worker,['safe-read',fifo],children);assert.match(safeRead,/rejected/);
			const fifoAppend=await runBoundedWorker(worker,['append',fifo],children);assert.match(fifoAppend,/rejected/);
			assert.equal(Buffer.from(await createNodeFileSystem().readFileSafeBoundedBytes!(regular,128)).toString(),'regular-data');
			await createNodeFileSystem().appendFileDurable!(regular,Buffer.from('-append'));assert.equal(await fs.readFile(regular,'utf8'),'regular-data-append');
		}finally{for(const child of children){if(child.exitCode===null&&child.signalCode===null){child.kill();}}await Promise.all(children.map(child=>child.exitCode!==null||child.signalCode!==null?Promise.resolve():new Promise<void>(resolve=>child.once('close',()=>resolve()))));await fs.rm(root,{recursive:true,force:true});}
	});
});

async function runBoundedWorker(worker:string,args:string[],children:ChildProcess[]):Promise<string>{
	const child=spawn(process.execPath,[worker,...args],{stdio:['ignore','pipe','pipe'],windowsHide:true});children.push(child);let stdout='';let stderr='';child.stdout?.setEncoding('utf8').on('data',chunk=>stdout+=chunk);child.stderr?.setEncoding('utf8').on('data',chunk=>stderr+=chunk);
	return await new Promise<string>((resolve,reject)=>{const timer=setTimeout(()=>{child.kill();reject(new Error(`Safe-open worker timed out for ${args[0]}; possible blocking FIFO open.`));},2000);child.once('error',error=>{clearTimeout(timer);reject(error);});child.once('close',code=>{clearTimeout(timer);if(code===0){resolve(stdout);}else{reject(new Error(`Safe-open worker exited ${code}: ${stderr}`));}});});
}

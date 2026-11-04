import { afterEach, expect, test } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
const roots: string[] = [];
async function call(root: string, action: string, args: object) {
  const r = await exec(process.execPath, [resolve('worker/remote-executor.mjs'), root, action, Buffer.from(JSON.stringify(args)).toString('base64')]);
  return JSON.parse(r.stdout || '{}');
}
async function fixture() { const r = await mkdtemp(join(tmpdir(), 'ch-remote-')); roots.push(r); return r; }
afterEach(async () => { for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });
test('claims before launch, rejects changed fingerprint and bounds disconnected output', async () => {
  const root = await fixture();
  const spec = { id: 'job-1', kind: 'task', command: 'printf once >> count; head -c 100000 /dev/zero', cwd: root, fingerprint: 'abc', timeoutMs: 5000, maxBytes: 32 };
  await Promise.all([call(root, 'start', spec), call(root, 'start', spec)]);
  await expect(call(root, 'start', { ...spec, fingerprint: 'other' })).rejects.toThrow();
  let r;
  for (let i = 0; i < 60; i++) { r = await call(root, 'read', { id: spec.id, offset: 0, maxBytes: 20 }); if (r.status === 'exited') break; await new Promise(resolve => setTimeout(resolve, 30)); }
  expect(r.status).toBe('exited'); expect(r.outputBytes).toBe(32); expect(r.truncated).toBe(true);
  expect(Buffer.from(r.output, 'base64')).toHaveLength(20);
  expect(await readFile(join(root, 'count'), 'utf8')).toBe('once');
});
test('pre-start cancellation prevents execution', async () => {
  const root = await fixture(); await call(root, 'cancel', { id: 'never' });
  await call(root, 'start', { id: 'never', kind: 'task', command: 'touch bad', cwd: root, fingerprint: 'a', timeoutMs: 5000, maxBytes: 100 });
  expect((await call(root, 'read', { id: 'never', offset: 0, maxBytes: 100 })).exitCode).toBe(143);
});
test('shell input reaches the same persistent shell', async () => {
  const root = await fixture(); await call(root, 'start', { id: 'shell', kind: 'shell', cwd: root, fingerprint: 'a', timeoutMs: 5000, maxBytes: 100 });
  for(let i=0;i<60;i++){ if ((await call(root,'read',{id:'shell',offset:0,maxBytes:100})).status==='running') break; await new Promise(r=>setTimeout(r,20)); }
  await call(root, 'write', { id: 'shell', input: 'export CHECK=retained\n' });
  await call(root, 'write', { id: 'shell', input: 'printf "$CHECK"; exit\n' });
  let r; for(let i=0;i<60;i++){ r=await call(root,'read',{id:'shell',offset:0,maxBytes:100}); if(r.status==='exited')break;await new Promise(r=>setTimeout(r,20)); }
  expect(Buffer.from(r.output,'base64').toString()).toBe('retained');
});
test('cancels detached descendants and never writes completion marker', async () => {
  const root = await fixture();
  await call(root, 'start', { id:'cancel',kind:'task',command:'setsid bash -c "sleep 10; touch unexpected" & echo $! > child; wait',cwd:root,fingerprint:'c',timeoutMs:15000,maxBytes:100 });
  const pid = Number(await readFile(join(root,'child'),'utf8'));
  await call(root,'cancel',{id:'cancel'});
  let live = false; try { live = !['Z','X'].includes((await readFile(`/proc/${pid}/stat`,'utf8')).split(') ')[1]!.split(' ')[0]!); } catch { /* exited */ }
  expect(live).toBe(false);
  await expect(readFile(join(root,'unexpected'))).rejects.toThrow();
});
test('records timeout and recovers bounded output from a later reader',async()=>{
 const root=await fixture();await call(root,'start',{id:'timeout',kind:'task',command:'printf begin; sleep 30',cwd:root,fingerprint:'t',timeoutMs:150,maxBytes:100});
 let result;for(let i=0;i<40;i++){result=await call(root,'read',{id:'timeout',offset:2,maxBytes:100});if(result.status==='exited')break;await new Promise(r=>setTimeout(r,20));}
 expect(result.exitCode).toBe(124);expect(Buffer.from(result.output,'base64').toString()).toBe('gin');expect(result.nextOffset).toBe(5);
});
test('durable child receives runtime environment and authoritative workspace roots',async()=>{
 const root=await fixture();const {mkdir,writeFile}=await import('node:fs/promises');await mkdir(join(root,'runtime'));await writeFile(join(root,'runtime','environment.json'),JSON.stringify({CANARY_VALUE:'present',HARNESS_WORKSPACE_ROOT:'/incorrect'}));
 await call(root,'start',{id:'env',kind:'task',command:'printf "%s|%s" "$CANARY_VALUE" "$HARNESS_WORKSPACE_ROOT"',cwd:root,fingerprint:'env',timeoutMs:1000,maxBytes:1000});
 let result;for(let i=0;i<40;i++){result=await call(root,'read',{id:'env',offset:0,maxBytes:1000});if(result.status==='exited')break;await new Promise(r=>setTimeout(r,20));}
 expect(Buffer.from(result.output,'base64').toString()).toBe(`present|${root}/repo`);
});
async function orphanFixture(root: string) {
 const script = `const {spawn}=require('child_process');const f=require('fs');const child=spawn('sh',['-c',${JSON.stringify(`while test ! -e '${root}/release-daemon'; do sleep 0.02; done; touch '${root}/daemon-leak'; sleep 30`)}],{detached:true,stdio:'ignore'});f.writeFileSync(${JSON.stringify(join(root,'daemon.pid'))},String(child.pid));child.unref();`;
 const command = `node -e '${script.replaceAll("'", "'\\''")}'`;
 return command;
}
async function daemonPid(root: string): Promise<number> {
 for(let i=0;i<100;i++){try{return Number(await readFile(join(root,'daemon.pid'),'utf8'));}catch{await new Promise(r=>setTimeout(r,10));}}
 throw Error('daemon PID was not published');
}
test.each(['cancel','timeout','complete'])('contains reparented detached descendants on %s',async mode=>{
 const root=await fixture();const command=await orphanFixture(root);
 await call(root,'start',{id:'orphan',kind:'task',command:command+(mode==='complete'?'':' ; sleep 30'),cwd:root,fingerprint:mode,timeoutMs:mode==='timeout'?350:10000,maxBytes:100});
 const pid=await daemonPid(root);
 if(mode==='cancel'){
  // The intermediary Node has exited; this is no longer ordinary current-parent ancestry.
  await new Promise(r=>setTimeout(r,100));
  await call(root,'cancel',{id:'orphan'});
 }
 let observation;for(let i=0;i<100;i++){observation=await call(root,'read',{id:'orphan',offset:0,maxBytes:100});if(observation.status==='exited')break;await new Promise(r=>setTimeout(r,20));}
 expect(observation.status).toBe('exited');
 let live=false;try{live=!['Z','X'].includes((await readFile(`/proc/${pid}/stat`,'utf8')).split(') ')[1]!.split(' ')[0]!);}catch{/* gone */}
 // Always clean the failing baseline's own daemon so a red TDD run cannot leave a process behind.
 if(live){try{process.kill(-pid,'SIGKILL');}catch{/* already exited */}}
 expect(live).toBe(false);
 await (await import('node:fs/promises')).writeFile(join(root,'release-daemon'),'go');await new Promise(r=>setTimeout(r,150));await expect(readFile(join(root,'daemon-leak'))).rejects.toThrow();
});
test.each(['shell','terminal'])('closes a %s only after adopted detached descendants are gone',async kind=>{
 const root=await fixture();const spec={id:kind,kind:'shell',cwd:root,fingerprint:kind,timeoutMs:10000,maxBytes:1000};
 const {spawn}=await import('node:child_process');
 const terminal=kind==='terminal'?spawn(process.execPath,[resolve('worker/remote-executor.mjs'),root,'terminal',Buffer.from(JSON.stringify(spec)).toString('base64')],{stdio:['pipe','ignore','ignore']}):undefined;
 try{
  if(kind==='shell')await call(root,'start',spec);
  else for(let n=0;n<100;n++){if((await call(root,'read',{id:kind,offset:0,maxBytes:0})).status==='running')break;await new Promise(r=>setTimeout(r,10));}
  const command=(await orphanFixture(root))+'\n';
  if(terminal)terminal.stdin!.write(command);else await call(root,'write',{id:kind,input:command});
  const pid=await daemonPid(root);await new Promise(r=>setTimeout(r,100));
  const receipt=JSON.parse(await readFile(join(root,'.ch-jobs',kind,'process'),'utf8'));
  const parent=Number((await readFile(`/proc/${pid}/stat`,'utf8')).split(') ')[1]!.split(' ')[1]);
  await call(root,'cancel',{id:kind});
  let live=false;try{live=!['Z','X'].includes((await readFile(`/proc/${pid}/stat`,'utf8')).split(') ')[1]!.split(' ')[0]!);}catch{/* gone */}
  if(live){try{process.kill(-pid,'SIGKILL');}catch{/* gone */}}
  expect(parent).toBe(receipt.supervisor.pid);expect(live).toBe(false);
  await (await import('node:fs/promises')).writeFile(join(root,'release-daemon'),'go');await new Promise(r=>setTimeout(r,150));await expect(readFile(join(root,'daemon-leak'))).rejects.toThrow();
 }finally{if(terminal&&!terminal.killed)terminal.kill('SIGTERM');}
});
test('lost subreaper identity cannot confirm cancellation',async()=>{
 const root=await fixture();await call(root,'start',{id:'lost',kind:'task',command:'sleep 30',cwd:root,fingerprint:'lost',timeoutMs:10000,maxBytes:100});
 const receipt=JSON.parse(await readFile(join(root,'.ch-jobs','lost','process'),'utf8'));
 try{process.kill(receipt.supervisor.pid,'SIGKILL');await new Promise(r=>setTimeout(r,30));await expect(call(root,'cancel',{id:'lost'})).rejects.toThrow('cancellation unconfirmed');await expect(readFile(join(root,'.ch-jobs','lost','exit'))).rejects.toThrow();}
 finally{try{process.kill(-receipt.pid,'SIGKILL');}catch{/* gone */}}
});

import { afterEach, expect, test, vi } from 'vitest';
const sdk = vi.hoisted(() => ({ getInfo: vi.fn(async()=>({state:'running',machine:{runtime:{ready:true}}})),resume:vi.fn(),stop:vi.fn() }));
vi.mock('@insforge/instabox-sdk',()=>({Sandbox:{connect:vi.fn(async()=>sdk)}}));
import { InstaBoxBackend } from '../src/executors/instabox-backend.js';
const ref = { provider: 'instabox' as const, ownerId: 'owner', workspaceId: 'workspace', machineId: 'machine', generation: 1, root: '/data/home/.cloud-harness/runner/workspace' };
const options = { apiKey: 'private-secret', allowedMachineIds: ['machine'], principalId: 'owner', validateRef: vi.fn() };
afterEach(()=>vi.unstubAllGlobals());
test('rejects untrusted owner and stale refs before transport',async()=>{
 const fetch=vi.fn();vi.stubGlobal('fetch',fetch);
 const b=new InstaBoxBackend(options);
 await expect(b.run({...ref,ownerId:'other'},'true',{timeoutMs:1000,maxBytes:100})).rejects.toThrow();
 const stale = new InstaBoxBackend({...options,validateRef:()=>{throw Error('stale');}});
 await expect(stale.readFile(ref,ref.root+'/file',100)).rejects.toThrow('stale');expect(fetch).not.toHaveBeenCalled();
});
test('drains streaming output with a fixed output budget and retains final exit',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>new Response('event: stdout\ndata: {"data":"abcdefgh"}\n\nevent: stderr\ndata: {"data":"error"}\n\nevent: exit\ndata: {"exitCode":7}\n\n',{headers:{'Content-Type':'text/event-stream'}})));
 const r=await new InstaBoxBackend(options).run(ref,'anything',{maxBytes:5,timeoutMs:1000});
 expect(r).toEqual({stdout:'abcde',stderr:'',exitCode:7,truncated:true});
});
test('redacts provider errors and never retries an ambiguous exec',async()=>{
 const fetch=vi.fn(async()=>new Response(JSON.stringify({error:{code:'host_unavailable',message:options.apiKey}}),{status:503}));vi.stubGlobal('fetch',fetch);
 await expect(new InstaBoxBackend(options).run(ref,'mutate',{maxBytes:100,timeoutMs:1000})).rejects.toThrow('host_unavailable');expect(fetch).toHaveBeenCalledTimes(1);
});
test('refuses oversized file content without accepting partial bytes',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>new Response('too long')));
 await expect(new InstaBoxBackend(options).readFile(ref,ref.root+'/file',3)).rejects.toThrow();
});
test('rejects incomplete streaming execution rather than inventing an exit code',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>new Response('event: stdout\ndata: {"data":"partial"}\n\n',{headers:{'content-type':'text/event-stream'}})));
 await expect(new InstaBoxBackend(options).run(ref,'mutate',{maxBytes:100,timeoutMs:1000})).rejects.toThrow('execution_unknown');
});
test('reports rate limit retry window without retrying execution',async()=>{
 const fetch=vi.fn(async()=>new Response('{"error":{"code":"rate_limited"}}',{status:429,headers:{'retry-after':'19'}}));vi.stubGlobal('fetch',fetch);
 await expect(new InstaBoxBackend(options).run(ref,'true',{maxBytes:100,timeoutMs:1000})).rejects.toMatchObject({providerCode:'rate_limited',retryAfterMs:19000});expect(fetch).toHaveBeenCalledOnce();
});
test('never wakes a suspended machine through file or active lease routes',async()=>{
 sdk.getInfo.mockResolvedValueOnce({state:'suspended',machine:{runtime:{ready:false}}});const fetch=vi.fn();vi.stubGlobal('fetch',fetch);
 await expect(new InstaBoxBackend(options).readFile(ref,ref.root+'/file',100)).rejects.toThrow('machine_not_ready');expect(fetch).not.toHaveBeenCalled();expect(sdk.resume).not.toHaveBeenCalled();
});
test('start applies one shared three-per-minute budget and verifies readiness',async()=>{
 let running=false;
 sdk.getInfo.mockImplementation(async()=>({state:running?'running':'stopped',machine:{runtime:{ready:running}}}));sdk.resume.mockImplementation(async()=>{running=true;});
 const b=new InstaBoxBackend(options);
 try{for(let i=0;i<3;i++){running=false;await b.start(ref);}running=false;await expect(b.start(ref)).rejects.toMatchObject({providerCode:'rate_limited'});expect(sdk.resume).toHaveBeenCalledTimes(3);}
 finally{sdk.getInfo.mockImplementation(async()=>({state:'running',machine:{runtime:{ready:true}}}));sdk.resume.mockReset();}
});
test('bootstrap marker conflict prevents every file overwrite',async()=>{
 const b=new InstaBoxBackend(options);vi.spyOn(b,'run').mockResolvedValueOnce({exitCode:0,stdout:'',stderr:''}).mockResolvedValueOnce({exitCode:0,stdout:'',stderr:''}).mockResolvedValue({exitCode:1,stdout:'',stderr:''});const write=vi.spyOn(b,'writeFile');
 await expect(b.bootstrap(ref,[{path:'runtime/worker',content:'anything'}])).rejects.toThrow('allocation_marker_conflict');expect(write).not.toHaveBeenCalled();
});
test('streamed upload accepts a 10 GiB caller budget and verifies provider digest',async()=>{
 const {mkdtemp,writeFile,rm}=await import('node:fs/promises');const {tmpdir}=await import('node:os');const {join}=await import('node:path');const {createHash}=await import('node:crypto');
 const root=await mkdtemp(join(tmpdir(),'ch-upload-'));const path=join(root,'bytes');const bytes=Buffer.from([0,255,3,4]);await writeFile(path,bytes);
 const fetch=vi.fn(async(_url:string,init:RequestInit)=>{const chunks:Buffer[]=[];for await(const part of init.body as any)chunks.push(Buffer.from(part));const data=Buffer.concat(chunks);expect(data).toEqual(bytes);return new Response(JSON.stringify({size:data.length,sha256:createHash('sha256').update(data).digest('hex')}));});vi.stubGlobal('fetch',fetch);
 try{await new InstaBoxBackend(options).uploadFile(ref,path,ref.root+'/bytes',10*1024**3);expect(fetch).toHaveBeenCalledOnce();}finally{await rm(root,{recursive:true,force:true});}
});
test('failed bounded download preserves existing local destination',async()=>{
 const {mkdtemp,writeFile,readFile,rm,readdir}=await import('node:fs/promises');const {tmpdir}=await import('node:os');const {join}=await import('node:path');const root=await mkdtemp(join(tmpdir(),'ch-download-'));const path=join(root,'file');await writeFile(path,'original');vi.stubGlobal('fetch',vi.fn(async()=>new Response('oversized')));
 try{await expect(new InstaBoxBackend(options).downloadFile(ref,ref.root+'/file',path,3)).rejects.toThrow();expect(await readFile(path,'utf8')).toBe('original');expect(await readdir(root)).toEqual(['file']);}finally{await rm(root,{recursive:true,force:true});}
});
test('a multibyte UTF-8 truncation boundary never expands the byte budget',async()=>{
 const events='event: stdout\ndata: {"data":"aé"}\n\nevent: stderr\ndata: {"data":"€"}\n\nevent: exit\ndata: {"exitCode":0}\n\n';
 vi.stubGlobal('fetch',vi.fn(async()=>new Response(events,{headers:{'content-type':'text/event-stream'}})));
 const result=await new InstaBoxBackend(options).run(ref,'true',{maxBytes:2,timeoutMs:1000});
 expect(result.stdout).toBe('a');expect(result.stderr).toBe('');expect(result.truncated).toBe(true);expect(Buffer.byteLength(result.stdout)+Buffer.byteLength(result.stderr)).toBeLessThanOrEqual(2);
});
test('bootstrap refuses a guest without kernel subreaper support before allocating files',async()=>{
 const b=new InstaBoxBackend(options);vi.spyOn(b,'run').mockResolvedValue({exitCode:1,stdout:'',stderr:''});const write=vi.spyOn(b,'writeFile');
 await expect(b.bootstrap(ref,[])).rejects.toThrow('kernel_subreaper_unavailable');expect(write).not.toHaveBeenCalled();
});
test('bootstrap refuses a guest without noninteractive scoped cleanup privilege before allocating files',async()=>{
 const b=new InstaBoxBackend(options);vi.spyOn(b,'run').mockResolvedValueOnce({exitCode:0,stdout:'',stderr:''}).mockResolvedValueOnce({exitCode:1,stdout:'',stderr:'private sudo error'});const write=vi.spyOn(b,'writeFile');
 await expect(b.bootstrap(ref,[])).rejects.toThrow('privileged_cleanup_unavailable');expect(write).not.toHaveBeenCalled();
});

import { EventEmitter } from 'node:events';
import { beforeEach, expect, test, vi } from 'vitest';
const sockets: any[] = [];
vi.mock('ws', () => ({ default: class extends EventEmitter {
 static OPEN=1; readyState=1; bufferedAmount=0; send=vi.fn((data:unknown)=>{if(Buffer.isBuffer(data)&&data.toString().startsWith('exec node'))queueMicrotask(()=>this.emit('message',Buffer.from(`\x1eCH_READY_${new URL(this.url).searchParams.get('session')}\x1f`),true));}); close=vi.fn(); terminate=vi.fn();
 constructor(readonly url:string,readonly options:object){super();sockets.push(this);queueMicrotask(()=>this.emit('open'));}
} }));
import { InstaBoxPty } from '../src/executors/instabox-pty.js';
import type { InstaBoxBackend } from '../src/executors/instabox-backend.js';
const ref={provider:'instabox' as const,workspaceId:'workspace',ownerId:'owner',machineId:'machine',generation:1,root:'/data/home/.cloud-harness/runner/workspace'};
const request={container:'',terminalId:'terminal',workingDir:'/workspace/src',cols:80,rows:24};
const validate=vi.fn();const readJob=vi.fn();const cancelJob=vi.fn();
beforeEach(()=>{sockets.length=0;vi.clearAllMocks();readJob.mockReset();readJob.mockResolvedValueOnce({status:'unknown',errorCode:'JOB_NOT_FOUND'}).mockResolvedValue({status:'running'});});
const transport=()=>new InstaBoxPty(ref,'key',{validate,readJob,cancelJob} as unknown as InstaBoxBackend);
test('preserves raw bytes, resize controls and close-as-detach',async()=>{
 const p=transport();const c=await p.open(request);expect(sockets[0].url).toContain('wake=0');
 const receive=vi.fn();c.onData(receive);sockets[0].emit('message',Buffer.from([0,255,42]),true);expect(receive).toHaveBeenCalledWith(Buffer.from([0,255,42]));
 await p.resize(c.execId,90,30);expect(sockets[0].send).toHaveBeenCalledWith(JSON.stringify({type:'resize',cols:90,rows:30}));
 c.close();expect(cancelJob).not.toHaveBeenCalled();await p.killSession('',request.terminalId);expect(cancelJob).toHaveBeenCalledOnce();
});
test('refuses reopening a session and stops on taken without reconnect fighting',async()=>{
 const p=transport();const c=await p.open(request);await expect(p.open(request)).rejects.toThrow('terminal_already_opened');
 const ended=vi.fn();c.onEnd(ended);sockets[0].emit('message',Buffer.from('{"type":"taken"}'),false);sockets[0].emit('close');expect(ended).toHaveBeenCalledOnce();expect(ended.mock.calls[0]![0].error.message).toContain('terminal_taken');expect(sockets).toHaveLength(1);
});
test('refuses unknown prior process identity and bounded input overflow',async()=>{
 readJob.mockReset().mockResolvedValue({status:'unknown',errorCode:'PROCESS_IDENTITY_LOST'});await expect(transport().open(request)).rejects.toThrow('terminal_replay_unavailable');expect(sockets).toHaveLength(0);
 readJob.mockReset().mockResolvedValueOnce({status:'unknown',errorCode:'JOB_NOT_FOUND'}).mockResolvedValue({status:'running'});const c=await transport().open(request);sockets[0].bufferedAmount=1048576;expect(()=>c.write(Buffer.from('x'))).toThrow('terminal_backpressure');
});
test('reports provider geometry limits as invalid input without opening a socket',async()=>{
 await expect(transport().open({...request,cols:2,rows:2})).rejects.toMatchObject({code:'INVALID_INPUT'});expect(sockets).toHaveLength(0);
});

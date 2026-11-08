import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type Server, type IncomingMessage } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { IncusClient } from '../src/incus.js';

/**
 * HTTP-level regression tests for the Incus REST client. A real node:http
 * server listens on a unix socket and returns RECORDED Incus envelope
 * bodies — this exercises api()/http() envelope unwrapping, HTTP 202 async
 * acceptance, binary file writes and operation polling exactly as a real
 * daemon responds. Parsed-method fakes cannot catch envelope bugs.
 */

interface RecordedCall {
  method: string;
  url: string;
  contentType: string | undefined;
  body: Buffer;
}

type Responder = (call: RecordedCall) => { status: number; body: unknown };

let dir: string;
let socketPath: string;
let server: Server;
let calls: RecordedCall[];
let responder: Responder;

function envelope(metadata: unknown, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    type: 'sync',
    status: 'Success',
    status_code: 200,
    metadata,
    error_code: 0,
    error: '',
    ...extra
  });
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks);
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'incus-http-'));
  socketPath = join(dir, 'incus.sock');
  calls = [];
  responder = () => ({ status: 500, body: { error: 'unhandled' } });
  server = createServer((req, res) => {
    void (async () => {
      const body = await readBody(req);
      const call: RecordedCall = {
        method: req.method ?? '',
        url: req.url ?? '',
        contentType: req.headers['content-type'],
        body
      };
      calls.push(call);
      const out = responder(call);
      res.writeHead(out.status, { 'Content-Type': 'application/json' });
      res.end(typeof out.body === 'string' ? out.body : JSON.stringify(out.body));
    })();
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  rmSync(dir, { recursive: true, force: true });
});

function client(overrides: { operationPollMs?: number } = {}): IncusClient {
  return new IncusClient({
    socketPath,
    project: 'default',
    requestTimeoutMs: 5_000,
    operationPollMs: overrides.operationPollMs ?? 5
  });
}

describe('IncusClient envelope unwrapping', () => {
  it('listInstances reads the metadata array, not the envelope', async () => {
    responder = () => ({
      status: 200,
      body: envelope([
        { name: 'vm1', status: 'Running', status_code: 103, expanded_config: {}, expanded_devices: {}, profiles: [] },
        { name: 'vm2', status: 'Stopped', status_code: 102, expanded_config: {}, expanded_devices: {}, profiles: [] }
      ])
    });
    const list = await client().listInstances();
    expect(list.map((i) => i.name)).toEqual(['vm1', 'vm2']);
    expect(list[0]!.status).toBe('Running');
  });

  it('getInstance parses metadata fields, not envelope status', async () => {
    responder = () => ({
      status: 200,
      body: envelope({
        name: 'vm1', status: 'Running', status_code: 103,
        expanded_config: { 'user.cloud-harness.workspace-id': 'w1' },
        expanded_devices: {}, profiles: []
      })
    });
    const inst = await client().getInstance('vm1');
    expect(inst?.name).toBe('vm1');
    expect(inst?.status).toBe('Running');
    expect(inst?.expandedConfig['user.cloud-harness.workspace-id']).toBe('w1');
  });

  it('getInstanceState reads metadata.status (VM state), not envelope Success', async () => {
    responder = () => ({
      status: 200,
      body: envelope({ status: 'Running', status_code: 103, pid: 42 })
    });
    const state = await client().getInstanceState('vm1');
    expect(state).toEqual({ status: 'Running', statusCode: 103 });
  });

  it('getApiExtensions reads metadata.api_extensions', async () => {
    responder = () => ({ status: 200, body: envelope({ api_extensions: ['instances_all_projects'] }) });
    await expect(client().getApiExtensions()).resolves.toEqual(['instances_all_projects']);
  });

  it('findPoolNameBySourcePath reads the metadata array', async () => {
    responder = () => ({
      status: 200,
      body: envelope([
        { name: 'default', source: '/var/lib/incus-pool' },
        { name: 'other', source: '/elsewhere' }
      ])
    });
    await expect(client().findPoolNameBySourcePath('/var/lib/incus-pool')).resolves.toBe('default');
  });
});

describe('IncusClient async 202 acceptance', () => {
  it('createInstance returns the operation path on HTTP 202', async () => {
    responder = () => ({
      status: 202,
      body: {
        type: 'async',
        operation: '/1.0/operations/abc123',
        status: 'Success',
        status_code: 202,
        metadata: { id: 'abc123', status: 'Running', status_code: 103 },
        error_code: 0,
        error: ''
      }
    });
    const result = await client().createInstance({
      name: 'vm1',
      imageAlias: 'images:debian/12',
      config: {},
      devices: {}
    });
    expect(result).toEqual({ operation: '/1.0/operations/abc123', synchronous: false });
  });

  it('deleteInstance returns the operation path on HTTP 202', async () => {
    responder = () => ({
      status: 202,
      body: {
        type: 'async',
        operation: '/1.0/operations/del9',
        status: 'Success',
        status_code: 202,
        metadata: { id: 'del9', status: 'Running' },
        error_code: 0,
        error: ''
      }
    });
    const result = await client().deleteInstance('vm1');
    expect(result.operation).toBe('/1.0/operations/del9');
  });

  it('openExecFds maps the native 202 fd secret map to keyed websocket channels', async () => {
    // Native Incus (cmd/incusd/instance_exec.go @1f0ce8e) ALWAYS answers exec
    // POSTs with 202 + an async operation whose metadata.metadata.fds is a
    // SECRET MAP — never an array of ready paths.
    responder = () => ({
      status: 202,
      body: {
        type: 'async',
        operation: '/1.0/operations/ex1',
        status: 'Success',
        status_code: 202,
        metadata: {
          id: 'ex1', class: 'task', status: 'Running', status_code: 103,
          metadata: {
            fds: {
              '0': 'stdin-secret',
              '1': 'stdout-secret',
              '2': 'stderr-secret',
              control: 'ctl-secret'
            }
          }
        },
        error_code: 0,
        error: ''
      }
    });
    const fds = await client().openExecFds('vm1', { command: ['/bin/sh', '-c', 'true'] });
    expect(fds.operation).toBe('/1.0/operations/ex1');
    expect(Object.keys(fds.channels).sort()).toEqual(['0', '1', '2', 'control']);
    expect(fds.channels['0']).toContain('/1.0/operations/ex1/websocket?secret=stdin-secret');
    expect(fds.channels.control).toContain('secret=ctl-secret');
    // The POST must request wait-for-websocket and never record-output.
    const post = calls.find((c) => c.method === 'POST' && c.url.includes('/exec'));
    expect(post).toBeDefined();
    const sent = JSON.parse(post!.body.toString('utf8')) as Record<string, unknown>;
    expect(sent['wait-for-websocket']).toBe(true);
    expect(sent['record-output']).toBeUndefined();
    expect(sent['pty']).toBeUndefined();
  });

  it('openExecFds maps pty requests to native interactive:true with width/height', async () => {
    responder = () => ({
      status: 202,
      body: {
        type: 'async', operation: '/1.0/operations/pty1', status: 'Success', status_code: 202,
        metadata: { id: 'pty1', status: 'Running', status_code: 103, metadata: { fds: { '0': 's', control: 'c' } } },
        error_code: 0, error: ''
      }
    });
    const fds = await client().openExecFds('vm1', { command: ['/bin/bash'], pty: { cols: 120, rows: 40 } });
    const post = calls.find((c) => c.method === 'POST' && c.url.includes('/exec'))!;
    const sent = JSON.parse(post.body.toString('utf8')) as Record<string, unknown>;
    expect(sent['interactive']).toBe(true);
    expect(sent['width']).toBe(120);
    expect(sent['height']).toBe(40);
    expect(sent['pty']).toBeUndefined();
    expect(fds.channels['0']).toBeDefined();
  });

  it('openExecFds fails closed on 202 without an operation handle', async () => {
    responder = () => ({
      status: 202,
      body: {
        type: 'async', status: 'Success', status_code: 202,
        metadata: { id: 'ex1', status: 'Running', status_code: 103, metadata: { fds: { '0': 's' } } },
        error_code: 0, error: ''
      }
    });
    await expect(client().openExecFds('vm1', { command: ['/bin/true'] }))
      .rejects.toThrow(/operation handle/i);
  });

  it('openExecFds rejects an fd ARRAY and an empty secret map', async () => {
    responder = () => ({
      status: 202,
      body: {
        type: 'async', operation: '/1.0/operations/ex1', status: 'Success', status_code: 202,
        metadata: { id: 'ex1', status: 'Running', status_code: 103, metadata: { fds: ['/a', '/b'] } },
        error_code: 0, error: ''
      }
    });
    await expect(client().openExecFds('vm1', { command: ['/bin/true'] }))
      .rejects.toThrow(/fd secret map/i);
    responder = () => ({
      status: 202,
      body: {
        type: 'async', operation: '/1.0/operations/ex1', status: 'Success', status_code: 202,
        metadata: { id: 'ex1', status: 'Running', status_code: 103, metadata: { fds: {} } },
        error_code: 0, error: ''
      }
    });
    await expect(client().openExecFds('vm1', { command: ['/bin/true'] }))
      .rejects.toThrow(/no usable fd secrets/i);
  });
});

describe('IncusClient operation polling', () => {
  it('waitOperation polls metadata.status until Success, not the first envelope', async () => {
    let polls = 0;
    responder = (call) => {
      if (call.url.includes('/operations/')) {
        polls += 1;
        const opStatus = polls < 3 ? 'Running' : 'Success';
        return {
          status: 200,
          body: envelope({
            id: 'op1', class: 'task', status: opStatus,
            status_code: opStatus === 'Success' ? 200 : 103
          })
        };
      }
      return { status: 404, body: envelope(null, { status: 'Failure', error: 'nf' }) };
    };
    const result = await client({ operationPollMs: 2 }).waitOperation('/1.0/operations/op1', Date.now() + 5_000);
    expect(result.status).toBe('Success');
    expect(polls).toBe(3);
  });

  it('waitOperation throws on metadata Failure status', async () => {
    responder = () => ({
      status: 200,
      body: envelope({ id: 'op1', status: 'Failure', status_code: 400, err: 'boom' })
    });
    await expect(
      client().waitOperation('/1.0/operations/op1', Date.now() + 5_000)
    ).rejects.toThrow(/boom|failed/i);
  });
});

describe('IncusClient malformed success rejection', () => {
  it('rejects a 200 with a non-envelope JSON body on a resource GET', async () => {
    responder = () => ({ status: 200, body: { name: 'vm1', status: 'Running' } });
    await expect(client().getInstance('vm1')).rejects.toThrow(/malformed success/);
  });

  it('rejects a 200 with a plain-text body', async () => {
    responder = () => ({ status: 200, body: 'OK' });
    await expect(client().listInstances()).rejects.toThrow(/malformed success/);
  });

  it('rejects a 200 envelope that omits metadata — absence is 404 only', async () => {
    responder = () => ({
      status: 200,
      body: { type: 'sync', status: 'Success', status_code: 200, error_code: 0, error: '' }
    });
    // Must NOT silently read as "instance absent".
    await expect(client().getInstance('vm1')).rejects.toThrow(/malformed success/);
  });

  it('rejects a malformed 202 the same way', async () => {
    responder = () => ({ status: 202, body: { accepted: true } });
    await expect(
      client().setInstanceState('vm1', 'start')
    ).rejects.toThrow(/malformed success/);
  });

  it('still maps a real 404 envelope to absence, not an error', async () => {
    responder = () => ({
      status: 404,
      body: envelope(null, { status: 'Failure', status_code: 404, error: 'not found', error_code: 404 })
    });
    await expect(client().getInstance('missing')).resolves.toBeNull();
  });
});

describe('IncusClient binary file writes', () => {
  it('writeInstanceFile sends raw octet-stream bytes, not JSON', async () => {
    responder = () => ({ status: 200, body: envelope({}) });
    const payload = Buffer.from([0x00, 0xff, 0x10, 0x61, 0x62, 0x63]);
    await client().writeInstanceFile('vm1', '/tmp/blob', payload, { mode: 0o600, uid: 0, gid: 0 });
    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call.method).toBe('POST');
    expect(call.contentType).toBe('application/octet-stream');
    expect(call.body.equals(payload)).toBe(true);
    expect(call.url).toContain('path=%2Ftmp%2Fblob');
    expect(call.url).toContain('mode=600');
  });

  it('writeInstanceFile surfaces the envelope error text on failure', async () => {
    responder = () => ({
      status: 500,
      body: { type: 'error', status: 'Failure', status_code: 500, error: 'permission denied', error_code: 13, metadata: {} }
    });
    await expect(
      client().writeInstanceFile('vm1', '/root/x', Buffer.from('x'))
    ).rejects.toThrow(/permission denied/);
  });
});

describe('IncusClient waitExecExit (native operation poll)', () => {
  it('polls the operation and returns metadata.return as exitCode', async () => {
    let polls = 0;
    responder = (call) => {
      if (call.url.includes('/operations/exec9')) {
        polls += 1;
        const done = polls >= 2;
        return {
          status: 200,
          body: envelope({
            id: 'exec9', class: 'task',
            status: done ? 'Success' : 'Running',
            status_code: done ? 200 : 103,
            metadata: done ? { return: 3 } : { fds: { '0': 's' } }
          })
        };
      }
      return { status: 404, body: envelope(null, { status: 'Failure', error: 'nf' }) };
    };
    const res = await client({ operationPollMs: 2 }).waitExecExit('/1.0/operations/exec9', { deadlineMs: Date.now() + 5_000 });
    expect(res).toEqual({ exitCode: 3, signal: null });
    expect(polls).toBe(2);
  });

  it('reports operation Failure with its err text, not a websocket frame', async () => {
    responder = () => ({
      status: 200,
      body: envelope({ id: 'exec9', class: 'task', status: 'Failure', status_code: 400, err: 'command not found', metadata: {} })
    });
    const res = await client().waitExecExit('/1.0/operations/exec9', { deadlineMs: Date.now() + 5_000 });
    expect(res.exitCode).toBeNull();
    expect(res.error).toMatch(/command not found/);
  });

  it('honors the abort signal instead of polling forever', async () => {
    responder = () => ({
      status: 200,
      body: envelope({ id: 'exec9', class: 'task', status: 'Running', status_code: 103, metadata: {} })
    });
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 10);
    await expect(
      client().waitExecExit('/1.0/operations/exec9', { signal: ac.signal, pollMs: 5 })
    ).rejects.toThrow(/aborted/i);
  });
});

describe('IncusClient listInstancePath (native filename arrays)', () => {
  it('parses a bare JSON string array — the native directory shape', async () => {
    responder = () => ({ status: 200, body: JSON.stringify(['a.txt', 'sub', 'b.log']) });
    const names = await client().listInstancePath('vm1', '/workspace');
    expect(names).toEqual(['a.txt', 'sub', 'b.log']);
  });

  it('tolerates an enveloped metadata array defensively', async () => {
    responder = () => ({ status: 200, body: envelope(['x', 'y']) });
    const names = await client().listInstancePath('vm1', '/workspace');
    expect(names).toEqual(['x', 'y']);
  });

  it('rejects stat-object arrays and malformed entries — never a silent empty dir', async () => {
    responder = () => ({
      status: 200,
      body: JSON.stringify([{ name: 'a', type: 'file', size: 1 }])
    });
    await expect(client().listInstancePath('vm1', '/workspace')).rejects.toThrow(/filename array|malformed/i);
    responder = () => ({ status: 200, body: JSON.stringify(['ok', 'bad/name', '..']) });
    await expect(client().listInstancePath('vm1', '/workspace')).rejects.toThrow(/malformed entry/i);
    responder = () => ({ status: 200, body: JSON.stringify(['']) });
    await expect(client().listInstancePath('vm1', '/workspace')).rejects.toThrow(/malformed entry/i);
  });

  it('enforces the 10k entry bound', async () => {
    responder = () => ({ status: 200, body: JSON.stringify(Array.from({ length: 10_001 }, (_, i) => `f${i}`)) });
    await expect(client().listInstancePath('vm1', '/workspace')).rejects.toThrow(/entry bound/i);
  });
});

describe('IncusClient waitExecExit transient retry', () => {
  it('retries transient 5xx poll failures and still returns the exit', async () => {
    let polls = 0;
    responder = () => {
      polls += 1;
      if (polls <= 2) return { status: 503, body: { error: 'unavailable' } };
      return {
        status: 200,
        body: envelope({ id: 'e', class: 'task', status: 'Success', status_code: 200, metadata: { return: 0 } })
      };
    };
    const res = await client({ operationPollMs: 2 }).waitExecExit('/1.0/operations/e', { deadlineMs: Date.now() + 5_000 });
    expect(res.exitCode).toBe(0);
    expect(polls).toBe(3);
  });

  it('gives up after a bounded number of transient failures — never unbounded', async () => {
    let polls = 0;
    responder = () => { polls += 1; return { status: 503, body: { error: 'unavailable' } }; };
    await expect(
      client({ operationPollMs: 2 }).waitExecExit('/1.0/operations/e', { deadlineMs: Date.now() + 30_000 })
    ).rejects.toThrow(/HTTP 503/);
    expect(polls).toBeLessThanOrEqual(8);
  });

  it('does not retry permanent 4xx poll failures', async () => {
    let polls = 0;
    responder = () => { polls += 1; return { status: 400, body: { error: 'bad request' } }; };
    await expect(
      client({ operationPollMs: 2 }).waitExecExit('/1.0/operations/e', { deadlineMs: Date.now() + 5_000 })
    ).rejects.toThrow(/HTTP 400/);
    expect(polls).toBe(1);
  });
});

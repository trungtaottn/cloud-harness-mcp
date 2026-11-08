import { EventEmitter } from 'node:events';
import { createServer, type Server } from 'node:http';
import type { ChildProcess } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createIncusProbe, createNftMonitorWakeups } from '../../src/network/live.js';

/**
 * Live-probe tests against a REAL unix-socket HTTP server returning
 * realistic Incus /1.0 envelopes — no live Incus, no kernel commands.
 * These pin the envelope `.metadata` unwrap and the strict device-state
 * validation that the guard's fail-closed decisions depend on.
 */

let workDir: string;
let socketPath: string;
let server: Server;
let handler: (path: string) => { status: number; body: unknown };

const envelope = (metadata: unknown) => ({
  type: 'sync',
  status: 'Success',
  status_code: 200,
  metadata,
  metadata_filterable: false,
  error_code: 0,
  error: '',
  operation: '',
  error_code_token: ''
});

const instanceEntry = (over: Record<string, unknown> = {}) => ({
  name: 'chm-vm-ws1',
  status: 'Running',
  status_code: 103,
  expanded_config: {
    'user.cloud-harness.workspace-id': 'ws_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'user.cloud-harness.instance-id': '11111111-1111-4111-8111-111111111111',
    boot: { autostart: 'false' }
  },
  expanded_devices: {
    eth0: { type: 'nic', nictype: 'bridged', parent: 'chmbr0', name: 'eth0', hwaddr: '00:16:3e:aa:bb:cc' }
  },
  profiles: [],
  ...over
});

beforeEach(async () => {
  workDir = await mkdtemp(join(tmpdir(), 'ch-live-test-'));
  socketPath = join(workDir, 'incus.sock');
  handler = () => ({ status: 404, body: envelope(null) });
  server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const out = handler(url.pathname);
    res.writeHead(out.status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(out.body));
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await rm(workDir, { recursive: true, force: true });
});

function probe() {
  return createIncusProbe({ socketPath, project: 'default' });
}

describe('Incus /1.0 envelope handling', () => {
  it('unwraps metadata for getInstanceExpanded — the raw envelope is never parsed as an instance', async () => {
    handler = (path) =>
      path === '/1.0/instances/chm-vm-ws1'
        ? { status: 200, body: envelope(instanceEntry()) }
        : { status: 404, body: envelope(null) };
    const snap = await probe().getInstanceExpanded('chm-vm-ws1');
    expect(snap).not.toBeNull();
    expect(snap!.name).toBe('chm-vm-ws1');
    expect(snap!.status).toBe('Running');
    expect(snap!.expandedConfig['user.cloud-harness.workspace-id']).toBe('ws_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(snap!.expandedDevices.eth0?.parent).toBe('chmbr0');
  });

  it('unwraps metadata arrays for listManagedInstances', async () => {
    handler = (path) =>
      path === '/1.0/instances'
        ? { status: 200, body: envelope([instanceEntry(), { name: 'unrelated', expanded_devices: {} }]) }
        : { status: 404, body: envelope(null) };
    const snaps = await probe().listManagedInstances();
    expect(snaps.map((s) => s.name)).toEqual(['chm-vm-ws1']);
  });

  it('a 2xx response WITHOUT metadata is malformed — throws, never reads as empty', async () => {
    handler = () => ({ status: 200, body: { type: 'sync', status: 'Success' } });
    await expect(probe().getInstanceExpanded('chm-vm-ws1')).rejects.toThrow(/malformed envelope/);
    await expect(probe().listManagedInstances()).rejects.toThrow(/malformed envelope/);
  });

  it('404 on get still reports absent', async () => {
    handler = () => ({ status: 404, body: envelope({ error: 'not found', error_code: 404 }) });
    await expect(probe().getInstanceExpanded('missing')).resolves.toBeNull();
  });
});

describe('strict expanded-device-state validation', () => {
  it('missing expanded_devices → typed failure, even with empty local devices', async () => {
    // THE critical case: `devices: {}` local-only while a profile may still
    // attach NICs — must NOT read as verified-zero. UNKNOWN throws.
    const entry = instanceEntry({ devices: {} });
    delete (entry as Record<string, unknown>).expanded_devices;
    handler = () => ({ status: 200, body: envelope(entry) });
    await expect(probe().getInstanceExpanded('chm-vm-ws1')).rejects.toMatchObject({
      reason: 'incus-instance-malformed'
    });
  });

  it('expanded_devices absent entirely → typed failure (no devices fallback at all)', async () => {
    const entry = instanceEntry({ devices: { eth0: { type: 'nic', parent: 'chmbr0' } } });
    delete (entry as Record<string, unknown>).expanded_devices;
    handler = () => ({ status: 200, body: envelope(entry) });
    await expect(probe().getInstanceExpanded('chm-vm-ws1')).rejects.toMatchObject({
      reason: 'incus-instance-malformed'
    });
  });

  it('expanded_devices: null is malformed → typed failure', async () => {
    const entry = instanceEntry({ expanded_devices: null, devices: { eth0: { type: 'nic' } } });
    handler = () => ({ status: 200, body: envelope(entry) });
    await expect(probe().getInstanceExpanded('chm-vm-ws1')).rejects.toMatchObject({
      reason: 'incus-instance-malformed'
    });
  });

  it('a non-record device entry makes the whole map unverifiable → typed failure', async () => {
    const entry = instanceEntry({ expanded_devices: { eth0: 'oops' } });
    handler = () => ({ status: 200, body: envelope(entry) });
    await expect(probe().getInstanceExpanded('chm-vm-ws1')).rejects.toMatchObject({
      reason: 'incus-instance-malformed'
    });
  });

  it('rejects expanded_devices beyond the 64-device snapshot bound', async () => {
    const devices: Record<string, unknown> = {};
    for (let i = 0; i < 65; i += 1) devices[`dev${i}`] = { type: 'nic' };
    const entry = instanceEntry({ expanded_devices: devices });
    handler = () => ({ status: 200, body: envelope(entry) });
    await expect(probe().getInstanceExpanded('chm-vm-ws1')).rejects.toMatchObject({
      reason: 'incus-instance-malformed'
    });
  });

  it('accepts exactly 64 devices — the bound is inclusive', async () => {
    const devices: Record<string, unknown> = {};
    for (let i = 0; i < 64; i += 1) devices[`dev${i}`] = { type: 'disk' };
    const entry = instanceEntry({ expanded_devices: devices });
    handler = () => ({ status: 200, body: envelope(entry) });
    const snap = await probe().getInstanceExpanded('chm-vm-ws1');
    expect(Object.keys(snap!.expandedDevices)).toHaveLength(64);
  });

  it('rejects expanded_config beyond 256 keys', async () => {
    const big: Record<string, string> = {};
    for (let i = 0; i < 257; i += 1) big[`key${i}`] = 'v';
    const entry = instanceEntry({ expanded_config: big });
    handler = () => ({ status: 200, body: envelope(entry) });
    await expect(probe().getInstanceExpanded('chm-vm-ws1')).rejects.toMatchObject({
      reason: 'incus-instance-malformed'
    });
  });

  it('rejects a config value over 64 KiB', async () => {
    const entry = instanceEntry({ expanded_config: { 'user.cloud-harness.big': 'a'.repeat(64 * 1024 + 1) } });
    handler = () => ({ status: 200, body: envelope(entry) });
    await expect(probe().getInstanceExpanded('chm-vm-ws1')).rejects.toMatchObject({
      reason: 'incus-instance-malformed'
    });
  });

  it('rejects a device property map over 256 keys', async () => {
    const props: Record<string, string> = {};
    for (let i = 0; i < 257; i += 1) props[`p${i}`] = 'v';
    const entry = instanceEntry({ expanded_devices: { eth0: props } });
    handler = () => ({ status: 200, body: envelope(entry) });
    await expect(probe().getInstanceExpanded('chm-vm-ws1')).rejects.toMatchObject({
      reason: 'incus-instance-malformed'
    });
  });

  it('malformed state throws even for an UNMANAGED name — get-by-name can never verify → never null', async () => {
    handler = () => ({ status: 200, body: envelope({ name: 'random-vm', expanded_devices: null }) });
    await expect(probe().getInstanceExpanded('random-vm')).rejects.toMatchObject({
      reason: 'incus-instance-malformed'
    });
  });

  it('verified zero-NIC state parses fine — the network-none exemption input', async () => {
    handler = () => ({ status: 200, body: envelope(instanceEntry({ expanded_devices: {} })) });
    const snap = await probe().getInstanceExpanded('chm-vm-ws1');
    expect(snap).not.toBeNull();
    expect(Object.keys(snap!.expandedDevices)).toHaveLength(0);
  });

  it('list throws typed failure on a MANAGED candidate with unverifiable device state', async () => {
    handler = () => ({
      status: 200,
      body: envelope([
        instanceEntry({ expanded_devices: null }),
        { name: 'random-vm', expanded_devices: null } // unmanaged malformed → skipped
      ])
    });
    await expect(probe().listManagedInstances()).rejects.toMatchObject({
      reason: 'incus-instance-malformed'
    });
  });

  it('list skips an unmanaged malformed entry and returns the managed one', async () => {
    handler = () => ({
      status: 200,
      body: envelope([instanceEntry(), { name: 'random-vm' }]) // no devices at all → malformed, unmanaged
    });
    const snaps = await probe().listManagedInstances();
    expect(snaps.map((s) => s.name)).toEqual(['chm-vm-ws1']);
  });
});

describe('nft monitor wakeups', () => {
  class FakeChild extends EventEmitter {
    stdout = new EventEmitter();
    killed = false;
    kill() {
      this.killed = true;
      return true;
    }
  }

  it('notifies subscribers on monitor data and respawns after child exit', async () => {
    const children: FakeChild[] = [];
    const spawnFn = (() => {
      const c = new FakeChild();
      children.push(c);
      return c as unknown as ChildProcess;
    }) as never;
    const wakeups = createNftMonitorWakeups({ spawnFn, minReconnectMs: 10, maxReconnectMs: 50 });
    let notifications = 0;
    wakeups.subscribe(() => {
      notifications += 1;
    });
    expect(children).toHaveLength(1);
    // Monitor event → immediate wakeup.
    children[0]!.stdout.emit('data', Buffer.from('add rule'));
    expect(notifications).toBe(1);
    // Child death → bounded reconnect → new child + reverify wakeup.
    children[0]!.emit('exit', 0, null);
    await new Promise((r) => setTimeout(r, 80));
    expect(children.length).toBeGreaterThanOrEqual(2);
    expect(notifications).toBeGreaterThanOrEqual(2); // exit reconnect notifies
    wakeups.close();
  });

  it('close() stops reconnecting', async () => {
    const children: FakeChild[] = [];
    const spawnFn = (() => {
      const c = new FakeChild();
      children.push(c);
      return c as unknown as ChildProcess;
    }) as never;
    const wakeups = createNftMonitorWakeups({ spawnFn, minReconnectMs: 10, maxReconnectMs: 50 });
    wakeups.subscribe(() => undefined);
    wakeups.close();
    const count = children.length;
    children[0]?.emit('exit', 0, null);
    await new Promise((r) => setTimeout(r, 80));
    expect(children).toHaveLength(count);
  });
});

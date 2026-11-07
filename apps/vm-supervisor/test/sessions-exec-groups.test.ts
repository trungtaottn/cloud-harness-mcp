import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { IncusClient } from '../src/incus.js';
import type { IncusExecSessionRequest } from '../src/incus.js';
import { IncusExecSession } from '../src/incus-exec.js';
import { VmJournal } from '../src/journal.js';
import { VmLifecycle } from '../src/lifecycle.js';
import { VmSessionManager } from '../src/sessions.js';
import { vmNameForWorkspace } from '../src/identity.js';
import type { WireSessionChannel } from '../src/transport.js';
import type { VmSupervisorConfig } from '../src/config.js';

/**
 * Supplementary-group coverage for workspace execs: Incus exec uid/gid
 * mapping does not run initgroups, so workspace commands must go through the
 * supervisor's `runuser -p -u <guestUser> --` root drop. These tests capture
 * the exact IncusExecSessionRequest spec — command argv, exec user/group,
 * environment — for exec.open (always workspace) and exec.run (workspace vs
 * root), plus the pgid kill-ladder path that must stay unwrapped.
 */

const WORKSPACE_ID = 'ws_groups_test_workspace_01';
const INSTANCE_ID = '11111111-2222-4333-8444-555555555555';
const VM_NAME = vmNameForWorkspace(WORKSPACE_ID);

function makeConfig(dir: string): VmSupervisorConfig {
  return {
    socketPath: join(dir, 'supervisor.sock'),
    token: 't'.repeat(48),
    stateDir: dir,
    incusSocketPath: '/nonexistent/incus.sock',
    incusProject: 'cloud-harness',
    guardStatePath: join(dir, 'guard-state.json'),
    bridgePattern: 'chmbr%d',
    subnetPlan: '10.240.0.0/16',
    uplink: '',
    dnsResolvers: ['10.0.0.2'],
    nonpublicCidrs: [],
    poolPath: dir,
    maxTtlSeconds: 3600,
    maxActive: 4,
    cpus: 4,
    memoryBytes: 8 * 1024 ** 3,
    diskBytes: 4 * 1024 ** 3,
    poolReserveBytes: 1024 ** 3,
    templateId: 'cloudharness-vm-debian13',
    templateDigest: 'a'.repeat(64)
  };
}

const fakeIncus = {
  openExecFds: async () => ({ fds: [] })
} as unknown as IncusClient;

const fakeChannel: WireSessionChannel = {
  emitData: async () => undefined,
  emitMeta: () => undefined,
  emitEnd: () => undefined,
  open: true
} as unknown as WireSessionChannel;

interface CapturedOpen {
  spec: IncusExecSessionRequest;
  events: {
    onStdout(chunk: Buffer): void;
    onStderr(chunk: Buffer): void;
    onMeta?(message: unknown): void;
    onExit(result: { exitCode: number | null; signal: string | null; metadata?: unknown }): void;
    onTransportError(error: Error): void;
  };
}

const stubSession = {
  writeStdin: vi.fn(() => true),
  stdinEof: vi.fn(),
  signal: vi.fn(() => true),
  resize: vi.fn(() => true),
  closeAll: vi.fn()
};

let dir: string;
let journal: VmJournal;
let sessions: VmSessionManager;
let captured: CapturedOpen[];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vmsup-groups-'));
  const config = makeConfig(dir);
  journal = new VmJournal(join(dir, 'journal.sqlite'));
  journal.recordWorkspaceAdmit({
    workspaceId: WORKSPACE_ID, vmName: VM_NAME, instanceId: INSTANCE_ID,
    templateId: config.templateId, templateDigest: config.templateDigest,
    generation: 1, networkProfile: 'network-none'
  });
  journal.setWorkspaceState(WORKSPACE_ID, 'running');
  journal.acceptGeneration(WORKSPACE_ID, 1);
  const lifecycle = new VmLifecycle({
    config, journal, incus: fakeIncus, guard: async () => { throw new Error('unused'); }
  });
  sessions = new VmSessionManager({
    journal, incus: fakeIncus, incusSocketPath: config.incusSocketPath, lifecycle
  });
  captured = [];
  vi.spyOn(IncusExecSession, 'open').mockImplementation(async (_c, _s, _n, spec, events) => {
    captured.push({ spec, events: events as CapturedOpen['events'] });
    return stubSession as unknown as IncusExecSession;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  journal.close();
  rmSync(dir, { recursive: true, force: true });
});

const ENV = { PATH: '/opt/user-tools/bin:/usr/bin', HOME: '/tmp/cloud-harness-home', CUSTOM_SECRETISH: 'not-in-argv' };

describe('exec.open workspace sessions (runuser drop)', () => {
  it('wraps argv in runuser -p -u harness and execs as root, env via environment field', async () => {
    const result = await sessions.openSession({
      sessionId: 'sess-1', workspaceId: WORKSPACE_ID, vmName: VM_NAME,
      instanceId: INSTANCE_ID, generation: 1,
      argv: ['/bin/bash', '-lc', 'docker ps'],
      cwd: '/workspace',
      environment: { ...ENV },
      channel: fakeChannel,
      onClosed: () => undefined
    });
    expect(result).toEqual({ sessionId: 'sess-1', fdsReady: true });
    expect(captured).toHaveLength(1);
    const { spec } = captured[0]!;
    expect(spec.command).toEqual(['/usr/sbin/runuser', '-p', '-u', 'harness', '--', '/bin/bash', '-lc', 'docker ps']);
    expect(spec.user).toBe('root');
    expect(spec.group).toBe('root');
    expect(spec.cwd).toBe('/workspace');
    // The exact supplied env map goes through the exec environment field —
    // never argv — so runuser -p preserves it verbatim for the child.
    expect(spec.environment).toEqual(ENV);
    expect(spec.command.join(' ')).not.toContain('CUSTOM_SECRETISH');
    expect(spec.command.join(' ')).not.toContain('/tmp/cloud-harness-home');
  });

  it('PTY sessions get the same wrapper and keep the pty spec', async () => {
    await sessions.openSession({
      sessionId: 'sess-pty', workspaceId: WORKSPACE_ID, vmName: VM_NAME,
      instanceId: INSTANCE_ID, generation: 1,
      argv: ['/bin/bash', '-i'],
      environment: { ...ENV },
      pty: { cols: 120, rows: 40 },
      channel: fakeChannel,
      onClosed: () => undefined
    });
    const { spec } = captured[0]!;
    expect(spec.command.slice(0, 4)).toEqual(['/usr/sbin/runuser', '-p', '-u', 'harness']);
    expect(spec.command.at(-1)).toBe('-i');
    expect(spec.pty).toEqual({ cols: 120, rows: 40 });
    expect(spec.user).toBe('root');
  });
});

describe('exec.run user mapping', () => {
  it("user 'workspace' (or absent) wraps in runuser and execs as root", async () => {
    const pending = sessions.openAndCapture({
      opId: 'op-ws', workspaceId: WORKSPACE_ID, vmName: VM_NAME,
      argv: ['/usr/bin/id'], environment: { ...ENV },
      timeoutMs: 5_000, maxBytes: 1024, envKeys: [], envDigest: ''
    });
    expect(captured).toHaveLength(1);
    const { spec, events } = captured[0]!;
    expect(spec.command).toEqual(['/usr/sbin/runuser', '-p', '-u', 'harness', '--', '/usr/bin/id']);
    expect(spec.user).toBe('root');
    expect(spec.group).toBe('root');
    events.onExit({ exitCode: 0, signal: null });
    const outcome = await pending;
    expect(outcome.exitCode).toBe(0);
  });

  it("user 'root' bypasses the wrapper and execs argv directly as root", async () => {
    const pending = sessions.openAndCapture({
      opId: 'op-root', workspaceId: WORKSPACE_ID, vmName: VM_NAME,
      argv: ['/usr/bin/id', '-u'], environment: {},
      timeoutMs: 5_000, maxBytes: 1024, user: 'root', envKeys: [], envDigest: ''
    });
    const { spec, events } = captured[0]!;
    expect(spec.command).toEqual(['/usr/bin/id', '-u']);
    expect(spec.user).toBe('root');
    events.onExit({ exitCode: 0, signal: null });
    await pending;
  });
});

describe('cancellation pgid semantics', () => {
  it('killSession control-close still verifies exit on a runuser-wrapped session', async () => {
    await sessions.openSession({
      sessionId: 'sess-kill', workspaceId: WORKSPACE_ID, vmName: VM_NAME,
      instanceId: INSTANCE_ID, generation: 1,
      argv: ['/bin/bash', '-i'], environment: { ...ENV },
      channel: fakeChannel, onClosed: () => undefined
    });
    expect(captured[0]!.spec.command[0]).toBe('/usr/sbin/runuser');
    const killPromise = sessions.killSession('sess-kill', '/tmp/cloud-harness-shells/t1.pid');
    // Session leader gets SIGKILL; the guest exit event then verifies the ladder.
    await new Promise((r) => setTimeout(r, 30));
    expect(stubSession.signal).toHaveBeenCalledWith('SIGKILL');
    captured[0]!.events.onExit({ exitCode: null, signal: 'SIGKILL' });
    await expect(killPromise).resolves.toEqual({ killed: true });
    expect(stubSession.closeAll).toHaveBeenCalled();
    expect(journal.getSession('sess-kill')?.state).toBe('closed');
  });

  it('the pgid-kill exec argv reaches the guest verbatim as root (no runuser wrap)', async () => {
    // Exact argv killSession uses for its step-2 process-group kill.
    const pidFile = '/tmp/cloud-harness-shells/t1.pid';
    const pending = sessions.openAndCapture({
      opId: 'kill:sess-x:1', workspaceId: WORKSPACE_ID, vmName: VM_NAME,
      argv: ['sh', '-c', `kill -- -$(cat ${JSON.stringify(pidFile)} 2>/dev/null) 2>/dev/null || true`],
      user: 'root', environment: {},
      timeoutMs: 15_000, maxBytes: 4096, envKeys: [], envDigest: ''
    });
    const { spec, events } = captured[0]!;
    expect(spec.command).toEqual(['sh', '-c', `kill -- -$(cat ${JSON.stringify(pidFile)} 2>/dev/null) 2>/dev/null || true`]);
    expect(spec.command).not.toContain('/usr/sbin/runuser');
    expect(spec.user).toBe('root');
    events.onExit({ exitCode: 0, signal: null });
    await pending;
  });
});

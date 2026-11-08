import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { IncusExecSessionEvents, ExecExitInfo } from '../src/incus-exec.js';
import type { WsMessage } from '../src/ws-client.js';

/**
 * Native-shaped exec-session regressions: a fake WsClient per channel driven
 * by the test, a controllable waitExecExit, and the REAL IncusExecSession.
 * Proves the operation-poll exit authority plus fd-channel close semantics:
 * Incus ends fd streams when the command exits, so channel close — not a
 * guessed quiet period — is the output-complete signal.
 */

interface FakeWs {
  path: string;
  closed: boolean;
  closeCode: number;
  paused: boolean;
  pauseCalls: number;
  resumeCalls: number;
  sentTexts: string[];
  sentBinary: Buffer[];
  msgListeners: Array<(m: WsMessage) => void>;
  closeListeners: Array<(code: number, reason: string) => void>;
  errorListeners: Array<(e: Error) => void>;
}

const wsByPath = new Map<string, FakeWs>();
/** Paths whose WsClient.connect rejects — partial-connect cleanup tests. */
const failConnectPaths = new Set<string>();
let exitResolver: ((v: { exitCode: number | null; signal: string | null; error?: string }) => void) | undefined;

function makeWs(path: string): FakeWs {
  const ws: FakeWs = {
    path, closed: false, closeCode: 0, paused: false, pauseCalls: 0, resumeCalls: 0,
    sentTexts: [], sentBinary: [],
    msgListeners: [], closeListeners: [], errorListeners: []
  };
  wsByPath.set(path, ws);
  return ws;
}

vi.mock('../src/ws-client.js', () => ({
  WsClient: {
    connect: async (opts: { path: string }) => {
      if (failConnectPaths.has(opts.path)) {
        throw new Error(`connect failed: ${opts.path}`);
      }
      const ws = makeWs(opts.path);
      return {
        onMessage: (l: (m: WsMessage) => void) => { ws.msgListeners.push(l); return () => undefined; },
        onClose: (l: (code: number, reason: string) => void) => { ws.closeListeners.push(l); return () => undefined; },
        onError: (l: (e: Error) => void) => { ws.errorListeners.push(l); return () => undefined; },
        sendBinary: (data: Buffer | string) => {
          if (ws.closed) return false;
          ws.sentBinary.push(typeof data === 'string' ? Buffer.from(data) : data);
          return true;
        },
        sendText: (text: string) => {
          if (ws.closed) return false;
          ws.sentTexts.push(text);
          return true;
        },
        close: (code = 1000) => { ws.closed = true; ws.closeCode = code; },
        waitForDrain: async () => undefined,
        pause: () => { ws.paused = true; ws.pauseCalls += 1; },
        resume: () => { ws.paused = false; ws.resumeCalls += 1; },
        get isClosed() { return ws.closed; }
      };
    }
  }
}));

import { IncusExecSession } from '../src/incus-exec.js';

function emit(ws: FakeWs, opcode: number, payload: Buffer | string): void {
  const p = typeof payload === 'string' ? Buffer.from(payload) : payload;
  for (const l of ws.msgListeners) l({ opcode, payload: p });
}
/** Native Incus stream-end marker: empty TEXT "barrier" frame (shared/ws rwc.go). */
function emitBarrier(ws: FakeWs): void {
  emit(ws, 0x1, '');
}
function closeWs(ws: FakeWs, code: number): void {
  ws.closed = true; ws.closeCode = code;
  for (const l of ws.closeListeners) l(code, '');
}
/** Full native EOF sequence for a data channel: barrier then clean close. */
function nativeEof(ws: FakeWs, code = 1000): void {
  emitBarrier(ws);
  closeWs(ws, code);
}

function makeClient() {
  return {
    openExecFds: async () => ({
      channels: { '0': '/ws/stdin', '1': '/ws/stdout', '2': '/ws/stderr', control: '/ws/control' },
      operation: '/1.0/operations/op-exec'
    }),
    waitExecExit: () => new Promise<{ exitCode: number | null; signal: string | null; error?: string }>((resolve) => {
      exitResolver = resolve;
    })
  };
}

function makeEvents() {
  const order: string[] = [];
  const events: IncusExecSessionEvents = {
    // Empty chunks (the native TEXT barrier) carry no output — skip them.
    onStdout: (c) => { if (c.length > 0) order.push(`stdout:${c.toString()}`); },
    onStderr: (c) => { if (c.length > 0) order.push(`stderr:${c.toString()}`); },
    onExit: (info: ExecExitInfo) => { order.push(`exit:${info.exitCode}`); },
    onTransportError: (e) => { order.push(`transport-error:${e.message}`); }
  };
  return { events, order };
}

const SPEC = { command: ['/bin/echo', 'hi'], environment: {} };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

beforeEach(() => {
  wsByPath.clear();
  failConnectPaths.clear();
  exitResolver = undefined;
});

describe('IncusExecSession native EOF tail handling', () => {
  it('delivers trailing stdout that lands after the exit poll resolves, before onExit', async () => {
    const { events, order } = makeEvents();
    const session = await IncusExecSession.open(
      makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000
    );
    // Command exits; Incus still has buffered fd data in flight.
    exitResolver?.({ exitCode: 0, signal: null });
    await new Promise((r) => setTimeout(r, 5));
    // Trailing frame arrives post-exit-poll, then Incus closes fd streams
    // with the native barrier+FIN sequence.
    emit(wsByPath.get('/ws/stdout')!, 0x2, 'tail-output');
    nativeEof(wsByPath.get('/ws/stdout')!);
    nativeEof(wsByPath.get('/ws/stderr')!);
    await new Promise((r) => setTimeout(r, 5));
    expect(order).toEqual(['stdout:tail-output', 'exit:0']);
    expect(session.hasExited).toBe(true);
  });

  it('fails honestly when a data channel closes without the native EOF barrier', async () => {
    const { events, order } = makeEvents();
    await IncusExecSession.open(makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000);
    exitResolver?.({ exitCode: 0, signal: null });
    await new Promise((r) => setTimeout(r, 5));
    // Clean TCP FIN (1000) but NO empty-text barrier: the frame boundary may
    // have cut the stream — cannot prove output completeness. stderr gets a
    // proper native EOF so only the missing barrier is under test.
    emit(wsByPath.get('/ws/stdout')!, 0x2, 'tail-output');
    closeWs(wsByPath.get('/ws/stdout')!, 1000);
    nativeEof(wsByPath.get('/ws/stderr')!);
    await new Promise((r) => setTimeout(r, 5));
    expect(order.some((s) => s.startsWith('transport-error:'))).toBe(true);
    expect(order.some((s) => s.startsWith('exit:'))).toBe(false);
  });

  it('fails honestly on a non-normal close code even with the barrier', async () => {
    const { events, order } = makeEvents();
    await IncusExecSession.open(makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000);
    exitResolver?.({ exitCode: 0, signal: null });
    await new Promise((r) => setTimeout(r, 5));
    emitBarrier(wsByPath.get('/ws/stdout')!);
    closeWs(wsByPath.get('/ws/stdout')!, 1001); // going-away is NOT normal EOF
    nativeEof(wsByPath.get('/ws/stderr')!);
    await new Promise((r) => setTimeout(r, 5));
    expect(order.some((s) => s.startsWith('transport-error:'))).toBe(true);
    expect(order.some((s) => s.startsWith('exit:'))).toBe(false);
  });

  it('fails honestly when an output channel dies mid-run without a barrier', async () => {
    const { events, order } = makeEvents();
    await IncusExecSession.open(makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000);
    // Command still running (exit poll unresolved); stdout stream truncates.
    emit(wsByPath.get('/ws/stdout')!, 0x2, 'partial');
    closeWs(wsByPath.get('/ws/stdout')!, 1000);
    await new Promise((r) => setTimeout(r, 5));
    expect(order.some((s) => s.startsWith('transport-error:'))).toBe(true);
    expect(order.some((s) => s.startsWith('exit:'))).toBe(false);
  });

  it('treats an early fd close WITH barrier as clean (process closed its fd)', async () => {
    const { events, order } = makeEvents();
    const session = await IncusExecSession.open(makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000);
    // stderr fd closed by the guest process mid-run — legal, barrier proves EOF.
    nativeEof(wsByPath.get('/ws/stderr')!);
    await new Promise((r) => setTimeout(r, 5));
    expect(order.some((s) => s.startsWith('transport-error:'))).toBe(false);
    exitResolver?.({ exitCode: 0, signal: null });
    await new Promise((r) => setTimeout(r, 5));
    nativeEof(wsByPath.get('/ws/stdout')!);
    await new Promise((r) => setTimeout(r, 5));
    expect(order).toContain('exit:0');
    expect(session.hasExited).toBe(true);
  });

  it('fails honestly when a data channel closes abnormally after exit', async () => {
    const { events, order } = makeEvents();
    await IncusExecSession.open(makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000);
    exitResolver?.({ exitCode: 0, signal: null });
    await new Promise((r) => setTimeout(r, 5));
    // 1006 = TCP close without a WS close frame — tail may be lost.
    closeWs(wsByPath.get('/ws/stdout')!, 1006);
    closeWs(wsByPath.get('/ws/stderr')!, 1006);
    await new Promise((r) => setTimeout(r, 5));
    expect(order.some((s) => s.startsWith('transport-error:'))).toBe(true);
    expect(order.some((s) => s.startsWith('exit:'))).toBe(false);
  });

  it('fails honestly when fd streams never close after exit (bounded drain)', async () => {
    const { events, order } = makeEvents();
    await IncusExecSession.open(makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000, 30);
    exitResolver?.({ exitCode: 0, signal: null });
    await new Promise((r) => setTimeout(r, 80));
    expect(order.some((s) => s.startsWith('transport-error:'))).toBe(true);
    expect(order.some((s) => s.startsWith('exit:'))).toBe(false);
  });
});

describe('IncusExecSession holdOutputPaused (bounded pre-bind queue)', () => {
  it('pauses data channels during the handshake and resumes them on open', async () => {
    const { events } = makeEvents();
    // holdOutputPaused = true → stdout/stderr paused from connect until open()
    // finishes its channel loop; stdin/control stay live.
    const session = await IncusExecSession.open(
      makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000, undefined, true
    );
    // open() resumes before returning — the pre-bind window is now bounded
    // by TCP backpressure rather than an unbounded pendingSessionFrames queue.
    expect(wsByPath.get('/ws/stdout')!.resumeCalls).toBeGreaterThan(0);
    expect(wsByPath.get('/ws/stderr')!.resumeCalls).toBeGreaterThan(0);
    expect(wsByPath.get('/ws/stdout')!.pauseCalls).toBeGreaterThan(0);
    expect(wsByPath.get('/ws/stdin')!.pauseCalls).toBe(0);
    expect(wsByPath.get('/ws/control')!.pauseCalls).toBe(0);
    expect(wsByPath.get('/ws/stdout')!.paused).toBe(false);
    session.closeAll();
  });

  it('does not pause channels by default (exec.run capture path unchanged)', async () => {
    const { events } = makeEvents();
    const session = await IncusExecSession.open(
      makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000
    );
    expect(wsByPath.get('/ws/stdout')!.pauseCalls).toBe(0);
    session.closeAll();
  });
});

describe('IncusExecSession post-exit drain vs backpressure', () => {
  it('suspends the drain deadline while output channels are paused for backpressure', async () => {
    const { events, order } = makeEvents();
    const session = await IncusExecSession.open(makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000, 50);
    session.pauseOutputChannels();
    exitResolver?.({ exitCode: 0, signal: null });
    // Well past the 50ms drain deadline — but every output channel is paused,
    // so no EOF/barrier can arrive; the deadline must not fire meanwhile.
    await sleep(160);
    expect(order.some((s) => s.startsWith('transport-error:'))).toBe(false);
    expect(order.some((s) => s.startsWith('exit:'))).toBe(false);
    // Consumer catches up: resume, then the native EOF sequence completes.
    session.resumeOutputChannels();
    nativeEof(wsByPath.get('/ws/stdout')!, 1000);
    nativeEof(wsByPath.get('/ws/stderr')!, 1000);
    await sleep(20);
    expect(order).toContain('exit:0');
    session.closeAll();
  });

  it('re-arms a fresh deadline on resume — a wedged peer still fails honestly', async () => {
    const { events, order } = makeEvents();
    const session = await IncusExecSession.open(makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000, 50);
    session.pauseOutputChannels();
    exitResolver?.({ exitCode: 0, signal: null });
    await sleep(120);
    session.resumeOutputChannels();
    // No EOF ever arrives after resume: the drain must still fail bounded.
    await sleep(140);
    expect(order.some((s) => s.startsWith('transport-error:'))).toBe(true);
    expect(order.some((s) => s.startsWith('exit:'))).toBe(false);
    session.closeAll();
  });

  it('restarts the drain deadline on received output — steady progress is not a timeout', async () => {
    const { events, order } = makeEvents();
    const session = await IncusExecSession.open(makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000, 50);
    exitResolver?.({ exitCode: 0, signal: null });
    const stdout = wsByPath.get('/ws/stdout')!;
    // Frames every ~25ms keep the drain alive past several 50ms windows.
    const ticker = setInterval(() => emit(stdout, 0x2, 'x'), 25);
    await sleep(180);
    clearInterval(ticker);
    expect(order.some((s) => s.startsWith('transport-error:'))).toBe(false);
    expect(order.some((s) => s.startsWith('exit:'))).toBe(false);
    // Progress stops: the deadline now fires honestly.
    await sleep(120);
    expect(order.some((s) => s.startsWith('transport-error:'))).toBe(true);
    session.closeAll();
  });
});

describe('IncusExecSession partial-connect cleanup', () => {
  it('closes every already-connected channel when a later fd connect fails', async () => {
    const { events } = makeEvents();
    failConnectPaths.add('/ws/stderr');
    await expect(
      IncusExecSession.open(makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000)
    ).rejects.toThrow(/connect failed/);
    // stdin + stdout were connected before stderr failed — none may leak.
    expect(wsByPath.get('/ws/stdin')!.closed).toBe(true);
    expect(wsByPath.get('/ws/stdout')!.closed).toBe(true);
    expect(wsByPath.has('/ws/stderr')).toBe(false);
    expect(wsByPath.has('/ws/control')).toBe(false);
  });

  it('closes the pty channel when the optional control connect fails', async () => {
    const { events } = makeEvents();
    const ptyClient = {
      openExecFds: async () => ({
        channels: { '0': '/ws/pty0', control: '/ws/ctl' },
        operation: '/1.0/operations/op-pty'
      }),
      waitExecExit: () => new Promise<never>(() => undefined)
    };
    failConnectPaths.add('/ws/ctl');
    const ptySpec = { command: ['/bin/sh'], environment: {}, pty: { cols: 80, rows: 24 } };
    await expect(
      IncusExecSession.open(ptyClient as never, '/sock', 'vm1', ptySpec, events, 1_000)
    ).rejects.toThrow(/connect failed/);
    expect(wsByPath.get('/ws/pty0')!.closed).toBe(true);
  });
});

describe('IncusExecSession PTY control channel', () => {
  const PTY_SPEC = { command: ['/bin/sh'], environment: {}, pty: { cols: 80, rows: 24 } };

  function makePtyClient() {
    return {
      openExecFds: async () => ({
        channels: { '0': '/ws/pty0', control: '/ws/ctl' },
        operation: '/1.0/operations/op-pty'
      }),
      waitExecExit: () => new Promise<{ exitCode: number | null; signal: string | null; error?: string }>((resolve) => {
        exitResolver = resolve;
      })
    };
  }

  it('resize and signal ride the control channel with the native command shape', async () => {
    const { events } = makeEvents();
    const session = await IncusExecSession.open(makePtyClient() as never, '/sock', 'vm1', PTY_SPEC, events, 1_000);
    const control = wsByPath.get('/ws/ctl')!;
    expect(session.resize(120, 40)).toBe(true);
    expect(JSON.parse(control.sentTexts.at(-1)!)).toEqual({
      command: 'window-resize', args: { width: '120', height: '40' }
    });
    expect(session.signal('TERM')).toBe(true);
    expect(JSON.parse(control.sentTexts.at(-1)!)).toEqual({ command: 'signal', signal: 15 });
    expect(session.signal('NOPE')).toBe(false);
    // pty output still flows to onStdout; data write goes to the pty socket.
    emit(wsByPath.get('/ws/pty0')!, 0x2, 'prompt$ ');
    expect(session.writeStdin(Buffer.from('ls\n'))).toBe(true);
    expect(wsByPath.get('/ws/pty0')!.sentBinary.map((b) => b.toString())).toContain('ls\n');
    session.closeAll();
  });

  it('resize/signal return false when Incus omitted the control channel', async () => {
    const { events } = makeEvents();
    const noCtl = {
      openExecFds: async () => ({
        channels: { '0': '/ws/pty0' },
        operation: '/1.0/operations/op-pty2'
      }),
      waitExecExit: () => new Promise<never>(() => undefined)
    };
    const session = await IncusExecSession.open(noCtl as never, '/sock', 'vm1', PTY_SPEC, events, 1_000);
    expect(session.resize(80, 24)).toBe(false);
    expect(session.signal('TERM')).toBe(false);
    session.closeAll();
  });
});

describe('IncusExecSession paused-drain boundedness', () => {
  it('closeAll during a paused drain leaves no live timer or orphan events', async () => {
    const { events, order } = makeEvents();
    const session = await IncusExecSession.open(makeClient() as never, '/sock', 'vm1', SPEC, events, 1_000, 40);
    session.pauseOutputChannels();
    exitResolver?.({ exitCode: 0, signal: null });
    await sleep(30);
    // Outer session/lease/disconnect deadline analogue: the owner tears down.
    session.closeAll();
    await sleep(120);
    // No drain timer may fire post-close: no transport error, no exit event.
    expect(order.some((s) => s.startsWith('transport-error:'))).toBe(false);
    expect(order.some((s) => s.startsWith('exit:'))).toBe(false);
    expect(session.hasExited).toBe(false);
    for (const ws of wsByPath.values()) expect(ws.closed).toBe(true);
  });
});

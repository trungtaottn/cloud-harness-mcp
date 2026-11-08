import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { Socket } from 'node:net';
import { fileURLToPath } from 'node:url';
import type { VmApplianceProcess } from './export.js';
import type { IncusClient, IncusInstanceInfo } from './incus.js';
import type {
  VmGuardCommandResult,
  VmGuardCommandRunner,
  VmGuardIncusProbe,
  VmGuardInstanceSnapshot
} from './network-ops.js';

/**
 * Adapters wiring the phase-05 guard port to real substrates: an Incus probe
 * backed by IncusClient and a bounded execFile runner for nft/iptables/ip.
 * Command execution is argv-only (never shell strings), time-bounded and
 * output-bounded; timeouts/truncation are reported, not hidden.
 */

const COMMAND_TIMEOUT_MS = 15_000;
const COMMAND_MAX_OUTPUT = 1024 * 1024;

/**
 * Bounded argv runner. `maxTimeoutMs` caps every call's effective timeout —
 * the default 15s suits nft/iptables/ip guard calls; the export appliance
 * needs its own runner with a ceiling >= APPLIANCE_TIMEOUT_MS or every
 * vm.export is silently killed at 15s.
 */
export function makeGuardCommandRunner(opts: { maxTimeoutMs?: number } = {}): VmGuardCommandRunner {
  const ceiling = opts.maxTimeoutMs ?? COMMAND_TIMEOUT_MS;
  return (argv, bounds): Promise<VmGuardCommandResult> =>
    new Promise((resolve) => {
      const timeoutMs = Math.min(bounds.timeoutMs, ceiling);
      const maxOutput = Math.min(bounds.maxOutputBytes, COMMAND_MAX_OUTPUT);
      execFile(
        argv[0]!,
        argv.slice(1),
        { timeout: timeoutMs, maxBuffer: maxOutput, encoding: 'utf8' },
        (error, stdout, stderr) => {
          const timedOut = error !== null && (error as NodeJS.ErrnoException & { killed?: boolean }).killed === true;
          const truncated = Buffer.byteLength(String(stdout)) >= maxOutput || Buffer.byteLength(String(stderr)) >= maxOutput;
          resolve({
            exitCode: typeof (error as { code?: unknown })?.code === 'number' ? (error as { code: number }).code : error === null ? 0 : 1,
            stdout: String(stdout).slice(0, maxOutput),
            stderr: String(stderr).slice(0, maxOutput),
            timedOut,
            truncated
          });
        }
      );
    });
}

/**
 * Environment allowlist for the export appliance. The supervisor process
 * env carries VM_SUPERVISOR_TOKEN and control-plane secrets — none of that
 * may leak into libguestfs/guestfish/qemu descendants, so the child gets an
 * explicit minimal set instead of an inherited environment:
 *
 * - PATH: inherited — required to resolve virt-tar-out and its subprocesses.
 * - HOME=/tmp, TMPDIR=/tmp: appliance scratch lands in tmp space. This does
 *   NOT prevent user config by itself — it relocates config lookup into the
 *   service-private tmpfs: the unit sets PrivateTmp=true, so /tmp is a
 *   private mount namespace writable only by supervisor-spawned processes.
 *   What actually strips config injection is this allowlist (no LIBGUESTFS_*
 *   or XDG_* overrides survive) plus the facts that guestfish's
 *   libguestfs-tools.conf can only express read_only=true — which --ro
 *   already enforces — and the guest has no host filesystem share.
 * - LANG/LC_ALL: deterministic diagnostics only.
 * - LIBGUESTFS_BACKEND=direct: pins the direct appliance backend so an
 *   inherited LIBGUESTFS_BACKEND=libvirt/unix override cannot reroute the
 *   export through libvirtd. No other LIBGUESTFS_* is forwarded — network
 *   stays off because virt-tar-out never passes --network (the appliance
 *   default), and nothing here can re-enable it.
 */
function applianceEnv(): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
    HOME: '/tmp',
    TMPDIR: '/tmp',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    LIBGUESTFS_BACKEND: 'direct'
  };
}

/**
 * ChildProcess wrapper whose kill() requests termination of the WHOLE
 * spawned process group WITHOUT the supervisor ever signaling a pgid.
 *
 * The direct child is appliance-shim.mjs, spawned `detached` as the
 * session/group leader; the shim spawns the appliance into the same group
 * and stays alive until /proc shows the group fully drained. kill() writes
 * a cancel byte to the spawn-private control pipe (stdio[3]) — the LIVE
 * shim then self-administers kill(-pid), so the group signal is sent by a
 * provably-live member and the pgid cannot have been recycled. Once the
 * shim is gone the group identity is unprovable, so a dead/broken channel
 * simply fails and export.ts's bounded reap reports honestly — there is
 * deliberately NO kill(-pid) fallback here.
 */
class SpawnedAppliance implements VmApplianceProcess {
  private readonly child: ChildProcess;
  private readonly control: Socket | null;

  constructor(child: ChildProcess) {
    this.child = child;
    this.control = (child.stdio[3] ?? null) as Socket | null;
    // The control socket is our write end; once the child is gone it can
    // only EPIPE — release it with the process.
    child.once('close', () => {
      try {
        this.control?.destroy();
      } catch {
        // already closed
      }
    });
    this.control?.on('error', () => undefined);
  }

  get stdout() {
    return this.child.stdout;
  }

  get stderr() {
    return this.child.stderr;
  }

  kill(signal?: NodeJS.Signals | number): boolean {
    if (this.child.exitCode !== null || this.child.signalCode !== null) return false;
    const ctl = this.control;
    if (ctl === null || ctl.destroyed) {
      // No channel (defensive — the spawn always provides fd 3): do NOT
      // signal anything. A live shim still has its deadline/watchdog
      // backstops; a dead one means the group already drained.
      return false;
    }
    try {
      ctl.write(`K:${typeof signal === 'string' ? signal : 'SIGKILL'}`);
      return true;
    } catch {
      return false;
    }
  }

  once(event: 'error', listener: (error: Error) => void): unknown;
  once(event: 'close', listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
  once(
    event: 'error' | 'close',
    listener: ((error: Error) => void) | ((code: number | null, signal: NodeJS.Signals | null) => void)
  ): unknown {
    return this.child.once(event as 'error', listener as (error: Error) => void);
  }
}

const APPLIANCE_SHIM_PATH = fileURLToPath(new URL('../appliance-shim.mjs', import.meta.url));

/**
 * Real appliance spawner for vm.export: runs appliance-shim.mjs as the
 * detached process-group leader, which spawns `virt-tar-out ... -` (tar on
 * stdout) into the same group. The shim owns group-drain detection, the
 * control-pipe cancel channel (stdio[3]), the parent-death EOF watchdog and
 * an optional deadline backstop; export.ts owns the bounded file sink, the
 * maxBytes cap, the wall-clock timeout, abort cancel and bounded close/reap.
 */
export function spawnApplianceProcess(
  argv: readonly string[],
  opts: { deadlineMs?: number } = {}
): VmApplianceProcess {
  const shimArgv: string[] = [APPLIANCE_SHIM_PATH];
  if (opts.deadlineMs !== undefined && opts.deadlineMs > 0) {
    shimArgv.push(`--deadline-ms=${Math.floor(opts.deadlineMs)}`);
  }
  shimArgv.push('--', ...argv);
  const child = spawn(process.execPath, shimArgv, {
    stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
    detached: true,
    env: applianceEnv()
  });
  return new SpawnedAppliance(child);
}

function toSnapshot(instance: IncusInstanceInfo): VmGuardInstanceSnapshot {
  return {
    name: instance.name,
    status: instance.status,
    expandedConfig: instance.expandedConfig,
    expandedDevices: instance.expandedDevices,
    profiles: instance.profiles
  };
}

export function makeGuardIncusProbe(incus: IncusClient, isManaged: (config: Record<string, string>) => boolean): VmGuardIncusProbe {
  return {
    async getInstanceExpanded(name: string): Promise<VmGuardInstanceSnapshot | null> {
      const instance = await incus.getInstance(name);
      return instance === null ? null : toSnapshot(instance);
    },
    async stopInstance(name: string): Promise<'stopped' | 'unknown'> {
      try {
        const result = await incus.setInstanceState(name, 'stop', { force: true, timeoutSeconds: 30 });
        if (result.operation !== undefined) {
          await incus.waitOperation(result.operation, Date.now() + 60_000);
        }
        const deadline = Date.now() + 30_000;
        for (;;) {
          const state = await incus.getInstanceState(name);
          if (state === null) return 'stopped';
          if (state.status === 'Stopped') return 'stopped';
          if (Date.now() >= deadline) return 'unknown';
          await new Promise((r) => setTimeout(r, 500));
        }
      } catch {
        return 'unknown';
      }
    },
    async listManagedInstances(): Promise<readonly VmGuardInstanceSnapshot[]> {
      const instances = await incus.listInstances();
      return instances.filter((i) => isManaged(i.expandedConfig)).map(toSnapshot);
    }
  };
}

// ---- pool.info helpers -------------------------------------------------------

export interface PoolVolumeInfo {
  vmName: string;
  configuredBytes: number;
  allocatedBytesStBlocks: number;
}

/** Per-volume allocated bytes (st_blocks*512) under <pool>/virtual-machines. */
export async function poolVolumeInfos(poolPath: string, configuredBytesFor: (vmName: string) => number): Promise<PoolVolumeInfo[]> {
  const out: PoolVolumeInfo[] = [];
  const vmRoot = join(poolPath, 'virtual-machines');
  let entries;
  try {
    entries = await readdir(vmRoot, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries.slice(0, 1_024)) {
    if (!entry.isDirectory()) continue;
    try {
      const s = await stat(join(vmRoot, entry.name, 'root.img'));
      out.push({
        vmName: entry.name,
        configuredBytes: configuredBytesFor(entry.name),
        allocatedBytesStBlocks: Number(s.blocks) * 512
      });
    } catch {
      // skip volumes without root.img
    }
  }
  return out;
}

/** Approximate image-cache bytes under <pool>/images (bounded walk). */
export async function imageCacheBytes(poolPath: string): Promise<number> {
  const root = join(poolPath, 'images');
  let total = 0;
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > 4) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries.slice(0, 4_096)) {
      const p = join(dir, entry.name);
      try {
        if (entry.isDirectory()) await walk(p, depth + 1);
        else if (entry.isFile()) total += (await stat(p)).size;
      } catch {
        // skip
      }
    }
  };
  await walk(root, 0);
  return total;
}

import { execFile } from 'node:child_process';
import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
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

export function makeGuardCommandRunner(): VmGuardCommandRunner {
  return (argv, bounds): Promise<VmGuardCommandResult> =>
    new Promise((resolve) => {
      const timeoutMs = Math.min(bounds.timeoutMs, COMMAND_TIMEOUT_MS);
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

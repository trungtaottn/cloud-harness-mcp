import { spawn, type ChildProcess } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import type {
  VmGuardCommandResult,
  VmGuardCommandRunner,
  VmGuardIncusProbe,
  VmGuardInstanceSnapshot,
  VmNetworkGuardConfig
} from '../network-ops.js';
import { createGuardService } from './guard-service.js';
import type { GuardServiceDeps, GuardWakeups } from './guard-service.js';
import { nftDestroySupport } from './kernel.js';

/**
 * Live adapters for the independent guard service. Everything here runs ONLY
 * inside the guard systemd unit — tests inject fakes and never touch these.
 * No live nft/iptables/ip/incus command is executed by the test suite; the
 * phase-11 live gate owns first real execution.
 */

// ---------------------------------------------------------------------------
// Bounded execFile runner — argv only, never a shell string
// ---------------------------------------------------------------------------

export function createExecFileRunner(): VmGuardCommandRunner {
  return (argv, bounds) =>
    new Promise<VmGuardCommandResult>((resolve) => {
      const child = spawn(argv[0]!, [...argv.slice(1)], { stdio: ['ignore', 'pipe', 'pipe'] });
      const outChunks: Buffer[] = [];
      const errChunks: Buffer[] = [];
      let outBytes = 0;
      let errBytes = 0;
      let truncated = false;
      let timedOut = false;
      let settled = false;

      const finish = (result: VmGuardCommandResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(result);
      };
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, bounds.timeoutMs);

      child.stdout.on('data', (chunk: Buffer) => {
        outBytes += chunk.length;
        if (outBytes <= bounds.maxOutputBytes) outChunks.push(chunk);
        else truncated = true;
      });
      child.stderr.on('data', (chunk: Buffer) => {
        errBytes += chunk.length;
        if (errBytes <= bounds.maxOutputBytes) errChunks.push(chunk);
        else truncated = true;
      });
      child.on('error', (error) => {
        finish({ exitCode: -1, stdout: '', stderr: String(error), timedOut, truncated });
      });
      child.on('close', (code) => {
        finish({
          exitCode: code ?? -1,
          stdout: Buffer.concat(outChunks).toString('utf8'),
          stderr: Buffer.concat(errChunks).toString('utf8'),
          timedOut,
          truncated
        });
      });
    });
}

// ---------------------------------------------------------------------------
// Incus probe over the unix socket (read + bounded stop only)
// ---------------------------------------------------------------------------

export interface IncusProbeConfig {
  socketPath: string;
  project: string;
  requestTimeoutMs?: number;
  maxResponseBytes?: number;
  /** Stop confirmation deadline. Default 45s. */
  stopDeadlineMs?: number;
}

interface IncusApiError extends Error {
  statusCode?: number;
}

function incusRequest(
  cfg: Required<Pick<IncusProbeConfig, 'socketPath' | 'project' | 'requestTimeoutMs' | 'maxResponseBytes'>>,
  method: string,
  path: string,
  body?: unknown
): Promise<{ status: number; data: unknown }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), 'utf8');
    const req = httpRequest(
      {
        socketPath: cfg.socketPath,
        path: `/1.0${path}${path.includes('?') ? '&' : '?'}project=${encodeURIComponent(cfg.project)}`,
        method,
        headers: {
          Host: 'localhost',
          ...(payload !== undefined
            ? { 'Content-Type': 'application/json', 'Content-Length': payload.length }
            : {})
        },
        timeout: cfg.requestTimeoutMs
      },
      (res) => {
        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total > cfg.maxResponseBytes) {
            req.destroy(new Error('incus response exceeded byte bound'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let data: unknown;
          try {
            data = raw.length === 0 ? undefined : JSON.parse(raw);
          } catch {
            data = undefined;
          }
          resolve({ status: res.statusCode ?? 0, data });
        });
        res.on('error', reject);
      }
    );
    req.on('timeout', () => req.destroy(new Error('incus request timed out')));
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asStringMap(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  const rec = asRecord(value);
  if (rec === null) return out;
  for (const [k, v] of Object.entries(rec)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function asDeviceMap(value: unknown): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  const rec = asRecord(value);
  if (rec === null) return out;
  for (const [k, v] of Object.entries(rec)) {
    const inner = asRecord(v);
    if (inner !== null) out[k] = asStringMap(inner);
  }
  return out;
}

function snapshotFromApi(raw: unknown): VmGuardInstanceSnapshot | null {
  const rec = asRecord(raw);
  if (rec === null || typeof rec.name !== 'string') return null;
  const config = asRecord(rec.expanded_config) ?? asRecord(rec.config) ?? {};
  const devices = asDeviceMap(rec.expanded_devices ?? rec.devices);
  const profilesRaw = rec.profiles;
  const profiles = Array.isArray(profilesRaw)
    ? profilesRaw.map((p) => (typeof p === 'string' ? p : asRecord(p)?.name)).filter((p): p is string => typeof p === 'string')
    : [];
  const status = typeof rec.status === 'string' ? rec.status : String(rec.status_code ?? 'unknown');
  return {
    name: rec.name,
    status,
    expandedConfig: asStringMap(config),
    expandedDevices: devices,
    profiles
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function createIncusProbe(cfg: IncusProbeConfig): VmGuardIncusProbe {
  const full = {
    socketPath: cfg.socketPath,
    project: cfg.project,
    requestTimeoutMs: cfg.requestTimeoutMs ?? 15_000,
    maxResponseBytes: cfg.maxResponseBytes ?? 8_388_608
  };
  const stopDeadlineMs = cfg.stopDeadlineMs ?? 45_000;

  return {
    async getInstanceExpanded(name) {
      const { status, data } = await incusRequest(full, 'GET', `/instances/${encodeURIComponent(name)}?recursion=2`);
      if (status === 404) return null;
      if (status < 200 || status >= 300) {
        const err: IncusApiError = new Error(`incus get instance failed: HTTP ${status}`);
        err.statusCode = status;
        throw err;
      }
      return snapshotFromApi(data);
    },

    async listManagedInstances() {
      const { status, data } = await incusRequest(full, 'GET', '/instances?recursion=2');
      if (status < 200 || status >= 300) {
        const err: IncusApiError = new Error(`incus list instances failed: HTTP ${status}`);
        err.statusCode = status;
        throw err;
      }
      const list = Array.isArray(data) ? data : [];
      return list
        .map(snapshotFromApi)
        .filter((s): s is VmGuardInstanceSnapshot => s !== null)
        .filter((s) => typeof s.expandedConfig['user.cloud-harness.workspace-id'] === 'string');
    },

    async stopInstance(name) {
      try {
        const { status } = await incusRequest(full, 'PUT', `/instances/${encodeURIComponent(name)}/state`, {
          action: 'stop',
          timeout: 30,
          force: false
        });
        if (status < 200 || status >= 300) return 'unknown';
      } catch {
        return 'unknown';
      }
      // Confirm via fresh state reads; never trust the PUT alone.
      const deadline = Date.now() + stopDeadlineMs;
      while (Date.now() < deadline) {
        try {
          const snap = await this.getInstanceExpanded(name);
          if (snap !== null && snap.status.trim().toLowerCase() === 'stopped') return 'stopped';
        } catch {
          // transient read failure — keep polling until deadline
        }
        await sleep(500);
      }
      return 'unknown';
    }
  };
}

// ---------------------------------------------------------------------------
// nft monitor wakeups — reconnect with bounded backoff; every (re)connect is
// a full-reverify wake because the cycle never trusts incremental state.
// ---------------------------------------------------------------------------

export interface NftMonitorOptions {
  /** Test seam; production uses node:child_process.spawn. */
  spawnFn?: typeof spawn;
  minReconnectMs?: number;
  maxReconnectMs?: number;
}

export function createNftMonitorWakeups(opts: NftMonitorOptions = {}): GuardWakeups & { close(): void } {
  const spawnFn = opts.spawnFn ?? spawn;
  const minMs = opts.minReconnectMs ?? 1_000;
  const maxMs = opts.maxReconnectMs ?? 30_000;
  const subscribers = new Set<() => void>();
  let child: ChildProcess | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  let backoff = minMs;
  let closed = false;

  const notify = () => {
    for (const cb of subscribers) {
      try {
        cb();
      } catch {
        // subscriber errors must not kill the monitor
      }
    }
  };

  const start = () => {
    if (closed) return;
    child = spawnFn('nft', ['monitor'], { stdio: ['ignore', 'pipe', 'ignore'] });
    child.stdout?.on('data', () => notify());
    child.on('error', () => scheduleReconnect());
    child.on('exit', () => scheduleReconnect());
  };

  const scheduleReconnect = () => {
    if (closed || reconnectTimer !== undefined) return;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = undefined;
      backoff = Math.min(maxMs, backoff * 2);
      start();
      // A (re)connected monitor means we may have missed events — wake a
      // full reverify immediately.
      notify();
    }, backoff);
    if (typeof reconnectTimer === 'object' && 'unref' in reconnectTimer) reconnectTimer.unref();
  };

  return {
    subscribe(callback) {
      subscribers.add(callback);
      if (subscribers.size === 1 && child === null && !closed) {
        backoff = minMs;
        start();
      }
      return () => {
        subscribers.delete(callback);
      };
    },
    close() {
      closed = true;
      if (reconnectTimer !== undefined) clearTimeout(reconnectTimer);
      reconnectTimer = undefined;
      child?.kill('SIGTERM');
      child = null;
      subscribers.clear();
    }
  };
}

// ---------------------------------------------------------------------------
// Env config + service main
// ---------------------------------------------------------------------------

function envRequired(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key];
  if (value === undefined || value.trim() === '') {
    throw new Error(`missing required environment variable ${key}`);
  }
  return value.trim();
}

function envOptional(env: NodeJS.ProcessEnv, key: string, fallback: string): string {
  const value = env[key];
  return value === undefined || value.trim() === '' ? fallback : value.trim();
}

function csvEnv(env: NodeJS.ProcessEnv, key: string, fallback: string): string[] {
  const raw = envOptional(env, key, fallback);
  return raw.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
}

/** Guard-scoped VM_* env → VmNetworkGuardConfig (same keys as the supervisor). */
export function guardConfigFromEnv(env: NodeJS.ProcessEnv = process.env): VmNetworkGuardConfig {
  return {
    bridgePattern: envOptional(env, 'VM_BRIDGE_PATTERN', 'chmbr%d'),
    subnetPlan: envOptional(env, 'VM_SUBNET_PLAN', '10.240.0.0/16'),
    uplink: envOptional(env, 'VM_UPLINK', ''),
    dnsResolvers: csvEnv(env, 'VM_DNS_RESOLVERS', '1.1.1.1,8.8.8.8'),
    nonpublicCidrs: csvEnv(env, 'VM_NONPUBLIC_CIDRS', ''),
    guardStatePath: envOptional(env, 'VM_GUARD_STATE_PATH', '/run/cloud-harness-vm/guard-state.json')
  };
}

export function incusProbeConfigFromEnv(env: NodeJS.ProcessEnv = process.env): IncusProbeConfig {
  return {
    socketPath: envOptional(env, 'VM_INCUS_SOCKET', '/var/lib/incus/unix.socket'),
    project: envRequired(env, 'VM_INCUS_PROJECT')
  };
}

export function buildGuardServiceDeps(env: NodeJS.ProcessEnv = process.env): GuardServiceDeps {
  const config = guardConfigFromEnv(env);
  const incusCfg = incusProbeConfigFromEnv(env);
  const pollEnv = env.VM_GUARD_POLL_MS;
  const pollIntervalMs = pollEnv === undefined ? undefined : Number.parseInt(pollEnv, 10);
  return {
    config,
    incus: createIncusProbe(incusCfg),
    execFile: createExecFileRunner(),
    wakeups: createNftMonitorWakeups(),
    ...(pollIntervalMs !== undefined && Number.isFinite(pollIntervalMs) ? { pollIntervalMs } : {})
  };
}

export async function main(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const deps = buildGuardServiceDeps(env);
  // Prerequisite gate BEFORE enabling: the atomic table apply requires
  // `nft destroy` (nftables >= 1.0.7, kernel >= 6.3). An unsupported host
  // refuses to start the guard at all — fail closed with a clear reason
  // instead of discovering it at the first mutation.
  const support = await nftDestroySupport(deps.execFile);
  if (!support.ok) {
    throw new Error(`vm-guard-service prerequisites unmet: ${support.detail}`);
  }
  const service = createGuardService(deps);
  const shutdown = async () => {
    await service.stop();
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown());
  process.on('SIGINT', () => void shutdown());
  service.start();
}

const invokedAsScript =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
if (invokedAsScript) {
  main().catch((error) => {
    // Fail closed and loud: the guard never runs degraded silently.
    console.error(`vm-guard-service fatal: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
}

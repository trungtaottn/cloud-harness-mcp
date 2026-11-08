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
import { VmNetworkGuardError } from '../network-ops.js';
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

/**
 * VmGuardIncusProbe contract bounds (network-ops.ts): <=256 record keys,
 * <=64 KiB values, <=64 devices per snapshot. Exceeding any bound makes the
 * snapshot UNVERIFIABLE — callers get the same typed malformed failure as a
 * structurally bad entry, never a silently truncated map.
 */
const MAX_SNAPSHOT_RECORD_KEYS = 256;
const MAX_SNAPSHOT_VALUE_BYTES = 64 * 1024;
const MAX_SNAPSHOT_DEVICES = 64;

/** String-map read enforcing the contract key/value bounds; null = over bound. */
function boundedStringMap(rec: Record<string, unknown>): Record<string, string> | null {
  const keys = Object.keys(rec);
  if (keys.length > MAX_SNAPSHOT_RECORD_KEYS) return null;
  const out: Record<string, string> = {};
  for (const k of keys) {
    const v = rec[k];
    if (typeof v !== 'string') continue;
    if (Buffer.byteLength(v, 'utf8') > MAX_SNAPSHOT_VALUE_BYTES) return null;
    out[k] = v;
  }
  return out;
}

/**
 * Strict expanded-device-state read: returns the validated device map, or
 * null when the state is UNVERIFIABLE. `expanded_devices` is REQUIRED — it
 * is Incus's merged view (instance-local PLUS profile-inherited devices).
 * The local `devices` map is NEVER a substitute: it can be empty while a
 * profile still attaches NICs, so falling back to it would read inherited
 * network exposure as verified-zero. Missing key, null, non-record, or any
 * non-record member → null (UNKNOWN). Only a fully validated record —
 * including the positively-empty `{}` of a true network-none instance —
 * returns a map.
 */
function validatedDeviceMap(entry: Record<string, unknown>): Record<string, Record<string, string>> | null {
  if (!('expanded_devices' in entry)) return null;
  const rec = asRecord(entry.expanded_devices);
  if (rec === null) return null;
  const deviceKeys = Object.keys(rec);
  if (deviceKeys.length > MAX_SNAPSHOT_DEVICES) return null;
  const out: Record<string, Record<string, string>> = {};
  for (const k of deviceKeys) {
    const inner = asRecord(rec[k]);
    if (inner === null) return null;
    const props = boundedStringMap(inner);
    if (props === null) return null;
    out[k] = props;
  }
  return out;
}

/** Strict config read: expanded_config ?? config must be a plain record when present. */
function validatedConfigMap(entry: Record<string, unknown>): Record<string, string> | null {
  const hasExpanded = 'expanded_config' in entry;
  const hasConfig = 'config' in entry;
  if (!hasExpanded && !hasConfig) return {};
  const raw = hasExpanded ? entry.expanded_config : entry.config;
  const rec = asRecord(raw);
  if (rec === null) return null;
  return boundedStringMap(rec);
}

type ParsedInstance =
  | { kind: 'ok'; snapshot: VmGuardInstanceSnapshot }
  | { kind: 'malformed' }
  | { kind: 'skip' };

/**
 * Parse one expanded-instance entry. 'skip' = cannot identify it as an
 * instance at all (no usable name) — never ours to act on. 'malformed' =
 * it IS an instance but its device/config state is unverifiable — callers
 * decide fail-closed per path (list throws, get returns null).
 */
function parseInstanceEntry(raw: unknown): ParsedInstance {
  const rec = asRecord(raw);
  if (rec === null || typeof rec.name !== 'string' || rec.name.length === 0) return { kind: 'skip' };
  const config = validatedConfigMap(rec);
  const devices = validatedDeviceMap(rec);
  if (config === null || devices === null) return { kind: 'malformed' };
  const profilesRaw = rec.profiles;
  const profiles = Array.isArray(profilesRaw)
    ? profilesRaw.map((p) => (typeof p === 'string' ? p : asRecord(p)?.name)).filter((p): p is string => typeof p === 'string')
    : [];
  const status = typeof rec.status === 'string' ? rec.status : String(rec.status_code ?? 'unknown');
  return {
    kind: 'ok',
    snapshot: { name: rec.name, status, expandedConfig: config, expandedDevices: devices, profiles }
  };
}

/**
 * Incus answers every /1.0 call with an envelope `{type, metadata, ...}`.
 * The payload lives under `metadata` — reading the envelope itself makes
 * every instance look absent (Array.isArray(envelope) === false, and
 * envelope.name is undefined). A 2xx without a `metadata` member is a
 * malformed response, not an empty result.
 */
function envelopeMetadata(data: unknown, what: string): unknown {
  const env = asRecord(data);
  if (env === null || !('metadata' in env)) {
    const err: IncusApiError = new Error(`incus ${what} returned a malformed envelope`);
    throw err;
  }
  return env.metadata;
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
      const meta = envelopeMetadata(data, 'get instance');
      const parsed = parseInstanceEntry(meta);
      // UNKNOWN is NOT absent: a 2xx response whose device/config state
      // cannot be verified is a typed failure — only a trusted HTTP 404
      // (handled above) may report the instance as absent. Returning null
      // here would let stop-confirmation, attest and containment read
      // "unverifiable" as "confirmed gone/stopped".
      if (parsed.kind !== 'ok') {
        throw new VmNetworkGuardError(
          'incus-instance-malformed',
          `incus instance '${name}' returned unverifiable device/config state`
        );
      }
      return parsed.snapshot;
    },

    async listManagedInstances() {
      const { status, data } = await incusRequest(full, 'GET', '/instances?recursion=2');
      if (status < 200 || status >= 300) {
        const err: IncusApiError = new Error(`incus list instances failed: HTTP ${status}`);
        err.statusCode = status;
        throw err;
      }
      const meta = envelopeMetadata(data, 'list instances');
      if (!Array.isArray(meta)) {
        const err: IncusApiError = new Error('incus list instances returned non-array metadata');
        throw err;
      }
      const out: VmGuardInstanceSnapshot[] = [];
      for (const entry of meta) {
        const parsed = parseInstanceEntry(entry);
        if (parsed.kind === 'skip') continue;
        if (parsed.kind === 'malformed') {
          // A managed candidate we cannot fully read must fail the whole
          // assessment — silently dropping it would let a running managed
          // VM escape unclaimed-stop coverage.
          const rec = asRecord(entry);
          const markers = asRecord(rec?.expanded_config) ?? asRecord(rec?.config) ?? {};
          if (typeof markers['user.cloud-harness.workspace-id'] === 'string') {
            throw new VmNetworkGuardError(
              'incus-instance-malformed',
              `incus instance '${String(rec?.name)}' has unverifiable device/config state`
            );
          }
          continue; // unmanaged and unreadable — not ours to fail over
        }
        const snap = parsed.snapshot;
        if (typeof snap.expandedConfig['user.cloud-harness.workspace-id'] === 'string') {
          out.push(snap);
        }
      }
      return out;
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

import { randomUUID } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { dirname } from 'node:path';
import { HarnessError, type ExecutorBackendKind, type ExecutorNetworkProfile, type RunnerConfig } from '@cloud-harness/contracts';
import { DockerExecutorBackend } from './docker-executor-backend.js';
import type { PtyTransport } from './docker-pty.js';
import { DockerGitDataPlane, type GitDataPlane } from './git-data-plane.js';
import { VmGitTransport } from './git-vm-transport.js';
import { createGuardedFileWriter, IncusExecutorBackend, stagingReservations, type VmSupervisorGateway } from './incus-executor-backend.js';
import type { ExecutorBackend, ProvisionContext } from './executor-backend.js';
import type { WorkspaceLeaseSync, WorkspaceBackendFactory, WorkspaceBackendStack } from './workspace-service.js';
import type { WorkspaceRecord } from './state-store.js';
import type { VmWorkspaceIdentity } from './vm-supervisor-client.js';

/**
 * Phase-07 backend factory: Docker stays the default; `incus-vm` is created
 * only when `vmBackendEnabled` AND the kind is explicitly requested — there is
 * no silent fallback in either direction. The returned factory matches the
 * `WorkspaceBackendFactory` seam phase-03 injected into `WorkspaceService`.
 *
 * Git plane: docker gets `DockerGitDataPlane` directly. incus-vm gets the
 * real `VmGitTransport` — host-staged credentialed helpers plus
 * digest/trailer-verified bundle trees, with `exportWorkspace` auto-wired
 * from the same supervisor client (`vm.export`, offline only). The optional
 * `incusGitPlaneFactory` remains an override seam for tests/custom wiring.
 */

export type IncusGitPlaneFactory = (deps: {
  backend: ExecutorBackend;
  client: VmSupervisorGateway;
  config: RunnerConfig;
  instanceId: string;
}) => GitDataPlane;

export type WorkspaceBackendFactoryDeps = {
  config: RunnerConfig;
  instanceId: string;
  /** Shared supervisor wire client (one per runner; the client multiplexes per call). */
  supervisorClient: VmSupervisorGateway;
  /** Docker network/package seams — same shape the service's default factory uses. */
  network?: {
    ensureProfileReady(profile: ExecutorNetworkProfile): Promise<void>;
    dockerLaunchArgs(profile: ExecutorNetworkProfile): string[];
  };
  packages?: {
    profileFor(ownerId: string, workspaceId: string): { mounts: { source: string; target: string }[]; binDirs: string[] };
  };
  ptyTransport?: PtyTransport;
  incusProvisionAssets?: (record: WorkspaceRecord) => Promise<Array<{ hostDir: string; guestPath: string }>>;
  incusGitPlaneFactory?: IncusGitPlaneFactory;
};

/** Wire identity for lease sync — needs only fields persisted at admit. */
function leaseIdentity(record: WorkspaceRecord): VmWorkspaceIdentity | undefined {
  if (record.backendKind !== 'incus-vm' || !record.backendInstanceId) return undefined;
  return { workspaceId: record.id, generation: record.generation, instanceId: record.backendInstanceId };
}

/**
 * `WorkspaceLeaseSync` over `lease.set`/`lease.clear`. `set` pushes the
 * record's CURRENT expiry pair on every call (open, renew, recover) so the
 * supervisor watchdog always sees fresh deadlines; `clear` is fire-and-forget
 * safe — the watchdog is the hard backstop. Non-VM records are a no-op.
 */
export function createVmLeaseSync(client: VmSupervisorGateway): WorkspaceLeaseSync {
  return {
    set(record: WorkspaceRecord) {
      const identity = leaseIdentity(record);
      if (!identity) return Promise.resolve();
      return client.leaseSet(identity, {
        expiresAt: record.expiresAt,
        hardExpiresAt: record.hardExpiresAt
      }, {
        // Unique per call: the supervisor replays a completed (op,key,digest)
        // record instead of re-applying, so a times-derived key can never
        // restore previously-used deadlines (e.g. rollback compensation).
        // lease.set applies absolute times idempotently, so a fresh key is
        // always safe; times stay in the key for debuggability.
        idempotencyKey: `lease-${identity.instanceId}-${record.expiresAt}-${record.hardExpiresAt}-${randomUUID()}`,
        timeoutMs: 60_000
      });
    },
    clear(record: WorkspaceRecord) {
      const identity = leaseIdentity(record);
      if (!identity) return Promise.resolve();
      return client.leaseClear(identity, {
        idempotencyKey: `lease-clear-${identity.instanceId}-${randomUUID()}`,
        timeoutMs: 60_000
      });
    }
  };
}

/** Offline export seam phase-08's VmGitTransport injects as `exportWorkspace`. */
export type VmExportWorkspaceFn = (ctx: ProvisionContext, opts: {
  guestPath: string;
  destPath: string;
  maxBytes: number;
  /** Optional cancellation — aborts the wire download and cleans staging. */
  signal?: AbortSignal;
}) => Promise<{ sha256: string; bytes: number }>;

/**
 * `vm.export` → host file adapter. Streams the supervisor tar into `destPath`
 * while hashing it, then returns the digest — the offline-export primitive
 * post-hardTTL recovery and `VmGitTransport.exportCheckoutOffline` share.
 * NEVER performs guest exec; the supervisor reads the stopped VM's disk via
 * the libguestfs appliance.
 */
export function createVmExportWorkspace(client: VmSupervisorGateway): VmExportWorkspaceFn {
  return async (ctx, opts) => {
    const record = ctx.record;
    if (record.backendKind !== 'incus-vm' || !record.backendInstanceId) {
      throw new HarnessError('VM_BACKEND_DISABLED', 'offline export requires an incus-vm workspace identity', 503, false);
    }
    const identity: VmWorkspaceIdentity = {
      workspaceId: record.id,
      generation: record.generation,
      instanceId: record.backendInstanceId
    };
    const { createHash } = await import('node:crypto');
    const hash = createHash('sha256');
    let bytes = 0;
    const writer = createGuardedFileWriter(opts.destPath);
    // Shared staging reservation BEFORE the first byte: the export tar is a
    // disk sink, so concurrent exports/pulls cannot over-commit free space.
    const releaseReservation = await stagingReservations.acquire(opts.destPath, dirname(opts.destPath), opts.maxBytes);
    try {
      const trailer = await client.vmExport(identity, {
        guestPath: opts.guestPath,
        maxBytes: opts.maxBytes
      }, {
        sink: (chunk: Buffer) => {
          hash.update(chunk);
          bytes += chunk.length;
          return writer.sink(chunk);
        },
        timeoutMs: 10 * 60_000,
        ...((ctx.signal ?? opts.signal) ? { signal: ctx.signal ?? opts.signal } : {})
      });
      await writer.finish();
      const computed = { sha256: hash.digest('hex'), bytes };
      // M7: the supervisor trailer is evidence, not truth — it must match the
      // bytes that actually landed on disk or the export is corrupt.
      if (trailer.sha256 !== computed.sha256 || trailer.bytes !== computed.bytes) {
        throw new HarnessError('UNAVAILABLE', 'vm.export trailer does not match the written archive', 503, true);
      }
      return computed;
    } catch (error) {
      writer.stream.destroy();
      // Exact cleanup: a cancelled/failed export must not leave a partial
      // archive that a later caller could mistake for a complete export.
      await rm(opts.destPath, { force: true }).catch(() => undefined);
      throw error;
    } finally {
      releaseReservation();
    }
  };
}

/**
 * Builds the `WorkspaceBackendFactory` the service injects. Stacks are
 * created lazily per kind and cached by the caller (`backendStacks` map);
 * this factory itself is stateless apart from the docker stack it memoizes.
 */
export function createWorkspaceBackendFactory(deps: WorkspaceBackendFactoryDeps): WorkspaceBackendFactory {
  let dockerStack: WorkspaceBackendStack | undefined;
  return (kind: ExecutorBackendKind): WorkspaceBackendStack => {
    if (kind === 'docker') {
      dockerStack ??= (() => {
        const backend = new DockerExecutorBackend({
          config: deps.config,
          instanceId: deps.instanceId,
          network: deps.network ?? {
            ensureProfileReady: async () => { throw new HarnessError('UNAVAILABLE', 'docker network manager is not configured', 503, true); },
            dockerLaunchArgs: () => { throw new HarnessError('UNAVAILABLE', 'docker network manager is not configured', 503, true); }
          },
          packages: deps.packages ?? { profileFor: () => ({ mounts: [], binDirs: [] }) }
        });
        return { backend, git: new DockerGitDataPlane({ backend, config: deps.config, instanceId: deps.instanceId }) };
      })();
      return dockerStack;
    }
    if (kind === 'incus-vm') {
      if (!deps.config.vmBackendEnabled) {
        throw new HarnessError('VM_BACKEND_DISABLED', `executor backend 'incus-vm' is not enabled on this runner`, 503, false);
      }
      const backend = new IncusExecutorBackend({
        client: deps.supervisorClient,
        config: deps.config,
        ...(deps.incusProvisionAssets ? { provisionAssets: deps.incusProvisionAssets } : {}),
        ...(deps.packages ? { packages: deps.packages } : {}),
        ...(deps.ptyTransport ? { ptyTransport: deps.ptyTransport } : {})
      });
      const git = deps.incusGitPlaneFactory
        ? deps.incusGitPlaneFactory({ backend, client: deps.supervisorClient, config: deps.config, instanceId: deps.instanceId })
        : new VmGitTransport({
            backend,
            config: deps.config,
            instanceId: deps.instanceId,
            // Real offline export — never optional in production wiring.
            supervisorClient: deps.supervisorClient
          });
      return { backend, git };
    }
    throw new HarnessError('VM_BACKEND_DISABLED', `executor backend '${kind}' is not registered on this runner`, 503, false);
  };
}

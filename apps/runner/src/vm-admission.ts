import { HarnessError } from '@cloud-harness/contracts';
import type { RunnerConfig } from '@cloud-harness/contracts';
import type { VmSupervisorGateway } from './incus-executor-backend.js';

/**
 * Runner-side EARLY admission pre-check for incus-vm workspaces. This runs
 * inside the service's existing admit transaction BEFORE any VM exists and
 * only rejects obvious quota violations — the supervisor's `vm.start` gate
 * remains the authoritative admission on EVERY start path (open, lease_renew
 * reactivation, workspace_recover resume, ensureActive, reconcile-adopt).
 * A pass here is never proof of admission; a fail here is only UX.
 *
 * Checks, in order:
 *  1. backend enabled (`VM_BACKEND_DISABLED`)
 *  2. global counted-VM cap (`countActiveByBackend('incus-vm')` < `vmMaxActive`)
 *  3. per-owner counted limit (same rule the service applies to every backend)
 *  4. pool reserve math via `pool.info`: free must cover
 *     `vmPoolReserveBytes + vmDiskBytes + retained allocated + image cache`
 */

export type VmAdmissionStore = {
  countActiveByBackend(backendKind: 'incus-vm'): number;
  countOwnerCountedWorkspaces(ownerId: string): number;
  effectiveActiveWorkspaceLimit(configured: number): number;
};

export type VmAdmissionDeps = {
  store: VmAdmissionStore;
  client: Pick<VmSupervisorGateway, 'poolInfo'>;
  config: Pick<RunnerConfig,
    | 'vmBackendEnabled' | 'vmMaxActive' | 'vmDiskBytes' | 'vmPoolReserveBytes'
    | 'maxActiveWorkspacesPerOwner'
  >;
};

export type VmAdmissionInput = {
  ownerId: string;
  /**
   * Reactivation of an EXPIRED_RECOVERABLE record needs no exclusion: that
   * status is not counted, so the record consumes no slot until it is ACTIVE
   * again. The parameter exists so callers can document the path explicitly.
   */
  reactivation?: boolean;
};

const ST_BLOCK_BYTES = 512;
/** Bound for the early pool.info probe; the authoritative vm.start gate is unaffected. */
const ADMISSION_POOL_TIMEOUT_MS = 15_000;

/**
 * Throws before any VM exists when the runner-side early checks fail.
 * `VM_QUOTA_EXCEEDED` for VM-pool/global caps, `LIMIT_EXCEEDED` for the
 * per-owner cap (same code the service uses for owner-limit rejection).
 */
export async function assertVmAdmissionAllowed(
  deps: VmAdmissionDeps,
  input: VmAdmissionInput
): Promise<void> {
  const { config, store, client } = deps;
  if (!config.vmBackendEnabled) {
    throw new HarnessError('VM_BACKEND_DISABLED', `executor backend 'incus-vm' is not enabled on this runner`, 503, false);
  }

  const activeVms = store.countActiveByBackend('incus-vm');
  if (activeVms >= config.vmMaxActive) {
    throw new HarnessError(
      'VM_QUOTA_EXCEEDED',
      `incus-vm workspace limit reached: ${activeVms} active of a maximum ${config.vmMaxActive}; close a VM workspace before opening another`,
      429,
      true
    );
  }

  const ownerCounted = store.countOwnerCountedWorkspaces(input.ownerId);
  const ownerLimit = store.effectiveActiveWorkspaceLimit(config.maxActiveWorkspacesPerOwner ?? 0);
  if (ownerCounted >= ownerLimit) {
    throw new HarnessError(
      'LIMIT_EXCEEDED',
      `active workspace limit reached: ${ownerCounted} active of a maximum ${ownerLimit}; close a workspace with workspace_close before opening another`,
      429,
      true
    );
  }

  // Explicit bound: this is an early-UX check on the admit path, so a hung
  // supervisor must not stall admission up to the client default.
  const pool = await client.poolInfo({ timeoutMs: ADMISSION_POOL_TIMEOUT_MS });
  // Retained = bytes already committed to existing VM volumes + image cache.
  // statfs 'free' already excludes allocated disk, so the reserve formula is
  // the plan's conservative bound: reserve + new disk + retained + cache must
  // all still fit inside reported free space.
  let retainedBytes = pool.imageCacheBytes;
  for (const volume of pool.volumes) {
    retainedBytes += volume.configuredBytes + volume.allocatedBytesStBlocks * ST_BLOCK_BYTES;
  }
  const required = config.vmPoolReserveBytes + config.vmDiskBytes + retainedBytes;
  if (pool.statfsFree < required) {
    throw new HarnessError(
      'VM_QUOTA_EXCEEDED',
      `incus pool free space ${pool.statfsFree} bytes is below the required reserve ${required} bytes (reserve ${config.vmPoolReserveBytes} + disk ${config.vmDiskBytes} + retained ${retainedBytes})`,
      429,
      true
    );
  }
}

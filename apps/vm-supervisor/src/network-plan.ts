import {
  VmNetworkGuardNotImplementedError,
  type VmNetworkGuardConfig
} from './network-ops.js';

/**
 * Supervisor-side network identity facade. The CANONICAL derivation is owned
 * by the phase-05 guard: `validateGuardConfig`, `planWorkspaceSubject`,
 * `nicDeviceStamp` and `findWorkspaceSubjectCollisions` in
 * `src/network/policy.ts`. This module consumes that single source through a
 * lazy dynamic import — identical to the `network-ops.ts` seam — so the
 * supervisor still builds and boots when `src/network/**` is absent, and no
 * hash is ever duplicated here. A missing or malformed policy module fails
 * closed with `VmNetworkGuardNotImplementedError`; there is no fallback.
 *
 * `vm.create` stamps the NIC device from `nicDeviceStamp(subject)` — the
 * verbatim record `expectedNicDevice` attests — and can run
 * `findWorkspaceSubjectCollisions` for early slot-conflict detection. The
 * guard derives the same subjects internally for `program`/`attest`/
 * `tearDown`/`quarantine`, so stamped values and enforced values cannot
 * diverge.
 */

/** The full canonical subject (phase-05 `VmNetworkSubject` shape). */
export interface VmWorkspaceNetworkSubject {
  workspaceId: string;
  vmName: string;
  slotIndex: number;
  bridgeName: string;
  hostIp: string;
  guestIp: string;
  prefixLength: number;
  mac: string;
  tapName: string;
}

/** Early collision report mirroring the guard's `VmSubjectCollision`. */
export interface VmWorkspaceSubjectCollision {
  bridgeName: string;
  bridgeIndex: number;
  guestIp: string;
  workspaceIds: string[];
}

export interface VmWorkspaceSubjectPlanner {
  plan(identity: { workspaceId: string; vmName: string }): VmWorkspaceNetworkSubject;
  /** Exact `expanded_devices.eth0` record — identical to guard attestation. */
  stamp(subject: VmWorkspaceNetworkSubject): Record<string, string>;
  /** Pure slot-collision scan over candidate workspace ids (claim registry stays authoritative). */
  findCollisions(workspaceIds: readonly string[]): VmWorkspaceSubjectCollision[];
}

/** Shape of the phase-05 policy module surface this facade consumes. */
interface VmNetworkPolicyModule {
  validateGuardConfig(config: VmNetworkGuardConfig): unknown;
  planWorkspaceSubject(
    config: unknown,
    identity: { workspaceId: string; vmName: string }
  ): Record<string, unknown>;
  nicDeviceStamp(subject: VmWorkspaceNetworkSubject): Record<string, string>;
  findWorkspaceSubjectCollisions(
    config: unknown,
    workspaceIds: readonly string[]
  ): VmWorkspaceSubjectCollision[];
}

function isPolicyModule(value: unknown): value is VmNetworkPolicyModule {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.validateGuardConfig === 'function' &&
    typeof candidate.planWorkspaceSubject === 'function' &&
    typeof candidate.nicDeviceStamp === 'function' &&
    typeof candidate.findWorkspaceSubjectCollisions === 'function'
  );
}

const SUBJECT_STRING_FIELDS = [
  'workspaceId',
  'vmName',
  'bridgeName',
  'hostIp',
  'guestIp',
  'mac',
  'tapName'
] as const;

function toSubject(raw: Record<string, unknown>): VmWorkspaceNetworkSubject {
  const subject = { ...raw } as Record<string, unknown>;
  for (const key of SUBJECT_STRING_FIELDS) {
    const value = subject[key];
    if (typeof value !== 'string' || value === '') {
      throw new VmNetworkGuardNotImplementedError(
        `vm network policy returned an invalid subject field '${key}'`
      );
    }
  }
  if (
    typeof subject.slotIndex !== 'number' ||
    !Number.isInteger(subject.slotIndex) ||
    subject.slotIndex < 0 ||
    typeof subject.prefixLength !== 'number' ||
    !Number.isInteger(subject.prefixLength) ||
    subject.prefixLength <= 0
  ) {
    throw new VmNetworkGuardNotImplementedError(
      'vm network policy returned an invalid subject slotIndex/prefixLength'
    );
  }
  return subject as unknown as VmWorkspaceNetworkSubject;
}

let plannerPromise: Promise<VmWorkspaceSubjectPlanner> | undefined;

/**
 * Resolve the canonical subject planner exactly once per process. The guard
 * config is validated ONCE here (`validateGuardConfig` throws
 * `VmNetworkGuardError` on unusable values — propagated, fail closed) and the
 * validated form is captured in the returned closure.
 */
export function loadVmWorkspaceSubjectPlanner(
  config: VmNetworkGuardConfig
): Promise<VmWorkspaceSubjectPlanner> {
  plannerPromise ??= (async () => {
    let mod: unknown;
    try {
      mod = await import('./network/policy.js');
    } catch (error) {
      throw new VmNetworkGuardNotImplementedError(
        `vm network policy module unavailable: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    const policy = (() => {
      try {
        return isPolicyModule(mod) ? mod : undefined;
      } catch {
        return undefined;
      }
    })();
    if (policy === undefined) {
      throw new VmNetworkGuardNotImplementedError(
        'vm network policy module does not export the required subject functions'
      );
    }
    const validated = policy.validateGuardConfig(config);
    return {
      plan(identity) {
        return toSubject(policy.planWorkspaceSubject(validated, identity));
      },
      stamp(subject) {
        const stamp = policy.nicDeviceStamp(subject);
        if (typeof stamp !== 'object' || stamp === null || Object.keys(stamp).length === 0) {
          throw new VmNetworkGuardNotImplementedError('vm network policy returned an empty NIC stamp');
        }
        return stamp;
      },
      findCollisions(workspaceIds) {
        return policy.findWorkspaceSubjectCollisions(validated, workspaceIds);
      }
    };
  })();
  return plannerPromise;
}

/** Test hook: drop the cached planner so a suite can re-resolve the module. */
export function resetVmWorkspaceSubjectPlannerForTests(): void {
  plannerPromise = undefined;
}

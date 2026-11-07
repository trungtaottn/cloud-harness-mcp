import type {
  ExecutorNetworkProfile,
  VmNetworkAttestResult,
  VmNetworkProgramResult,
  VmNetworkTearDownResult,
  WorkspaceId
} from '@cloud-harness/contracts';

/**
 * Stable supervisor↔network-guard port (phase-04 owned). `server.ts` and the
 * workspace ops import ONLY this module; the real implementation lives in
 * `src/network/ops.ts` (phase-05 owned) and is resolved lazily so the
 * supervisor builds and boots before the guard lands. Until it does,
 * `loadVmNetworkGuard` rejects with `VmNetworkGuardNotImplementedError` and
 * every `network.*` op plus the `vm.start` gate fails closed — there is no
 * permissive stub.
 *
 * Phase-05 implements `createVmNetworkGuard(deps)` in `src/network/ops.ts`
 * and imports the types below with `import type` (no runtime cycle: this file
 * never statically imports `src/network/**`).
 *
 * Ownership split (frozen): the supervisor's own `vm.start` gate attests
 * instance identity (`user.cloud-harness.*` full match), generation fencing,
 * resource actuals vs supervisor config, `profiles=[]`, `boot.autostart=false`
 * and `raw.*` rejection. The guard attests KERNEL state (nft canonical minus
 * counters, DOCKER-USER permits, CH first-jumps, bridge /30 + IPv6-disabled,
 * uplink) plus the network-device slice of the expanded instance (nic shape
 * per profile, `security.*_filtering`, pinned hwaddr/host_name/ipv4.address,
 * zero nics for `network-none`, no `raw.*`). `attest` MUST verify live kernel
 * state at call time — a fresh `guard-state.json` verdict never substitutes
 * for it. Both gates run serialized inside `vm.start`; either failing refuses
 * the start.
 */

/** Verified workspace↔VM identity context, resolved from the supervisor journal. */
export interface VmNetworkIdentity {
  workspaceId: WorkspaceId;
  /** `chm-vm-<sha256(workspaceId)[:32]>` — validated upstream. */
  vmName: string;
  /** `backend_instance_id` UUID assigned at admit. */
  instanceId: string;
  /** workspaceGeneration carried by the request envelope. */
  generation: number;
}

export interface VmNetworkProgramArgs {
  identity: VmNetworkIdentity;
  networkProfile: ExecutorNetworkProfile;
}

export interface VmNetworkAttestArgs {
  identity: VmNetworkIdentity;
  /**
   * Explicit profile: `network-none` must verify NIC-absence in expanded
   * devices, `dependency-access` the full pinned-device shape — never guessed
   * from instance state.
   */
  networkProfile: ExecutorNetworkProfile;
}

export interface VmNetworkTearDownArgs {
  identity: VmNetworkIdentity;
}

export interface VmNetworkQuarantineArgs {
  /** Bounded, sanitized reason (<=500 chars) recorded in the guard journal. */
  reason: string;
  /**
   * Explicit identities to quarantine — always the supervisor journal's
   * managed set (or a verified subset). There is NO global-stop escape: the
   * guard may only stop instances named here, and only after per-instance
   * identity re-verification.
   */
  identities: readonly VmNetworkIdentity[];
}

export type VmNetworkQuarantineOutcome = 'stopped' | 'unknown' | 'skipped';

export interface VmNetworkQuarantineResult {
  quarantined: boolean;
  outcomes: readonly { vmName: string; outcome: VmNetworkQuarantineOutcome }[];
}

export interface VmNetworkGuard {
  /**
   * Program (or idempotently re-assert) the guard resources for one workspace:
   * unmanaged bridge + /30, nft `inet` table rules, iptables-nft permits +
   * MASQUERADE. Ordering invariant is internal: nft table applied and verified
   * BEFORE any permit appears; `network-none` programs nothing and returns the
   * canonical empty-ruleset digest. Result conforms to the `network.program`
   * contract schema exactly.
   */
  program(args: VmNetworkProgramArgs): Promise<VmNetworkProgramResult>;
  /**
   * Fresh attestation for the VM about to start (or already running under
   * re-check): kernel ruleset canonical compare, permits exact, CH first-jump
   * gate, bridge state, uplink unambiguous, and the expanded-instance
   * network-device slice for `args.networkProfile`. Never returns a cached or
   * file-only verdict. Result conforms to the `network.attest` schema.
   */
  attest(args: VmNetworkAttestArgs): Promise<VmNetworkAttestResult>;
  /**
   * Ordered teardown for a VERIFIED-STOPPED identity only: strip permits
   * first, then this workspace's nft rules, then the bridge — the guard table
   * itself is removed LAST, after all reachability is gone. Refuses (throws
   * VmNetworkGuardError) when the instance is not confirmed stopped.
   */
  tearDown(args: VmNetworkTearDownArgs): Promise<VmNetworkTearDownResult>;
  /**
   * Ordered quarantine for explicit managed identities: per instance, disable
   * the host link/NIC or enforce a verified drop FIRST, then strip permits,
   * then confirm stopped via the probe; the nft guard is NEVER removed before
   * a positive stop, and a failed/unknown stop KEEPS the guard in place.
   * Deletes nothing.
   */
  quarantine(args: VmNetworkQuarantineArgs): Promise<VmNetworkQuarantineResult>;
  /**
   * REQUIRED: hold serialize() + the cross-process `guard.lock` for the
   * WHOLE `fn` — `program`, `attest` and whatever the caller does next
   * (Incus start) — so the independent guard-service watcher cannot mutate
   * kernel/claims between attest and start. Lock timeout rejects BEFORE
   * `fn` runs (a contended lock can never start a VM); there is no fallback
   * to the racy per-call path.
   *
   * `args` are the `program` args; `tx.program()`/`tx.attest()` run the
   * inner ops with NO lock re-acquisition (the mkdir lock is not
   * reentrant). Inside `fn`, ONLY `tx.*` may be used: outer guard methods
   * reject with 'nested-guard-call' rather than queue-deadlock.
   */
  withStartTransaction<T>(args: VmNetworkProgramArgs, fn: (tx: VmNetworkStartTx) => Promise<T>): Promise<T>;
}

/** Unlocked guard ops — valid ONLY inside `withStartTransaction`. */
export interface VmNetworkStartTx {
  program(): Promise<VmNetworkProgramResult>;
  attest(): Promise<VmNetworkAttestResult>;
}

/** Bounded snapshot of one Incus instance as the guard needs it. */
export interface VmGuardInstanceSnapshot {
  name: string;
  /** Raw Incus status string ('Running', 'Stopped', ...); guard normalizes. */
  status: string;
  expandedConfig: Readonly<Record<string, string>>;
  expandedDevices: Readonly<Record<string, Readonly<Record<string, string>>>>;
  profiles: readonly string[];
}

/**
 * Narrow read/control Incus surface injected into the guard. Implementations
 * MUST bound record sizes (<=256 config keys, <=64 KiB values, <=64 devices)
 * and return `null`/empty rather than throwing for absent resources where
 * noted; transport failures throw so the guard fails closed.
 */
export interface VmGuardIncusProbe {
  /** Expanded view of one instance; null when absent. Read-only. */
  getInstanceExpanded(name: string): Promise<VmGuardInstanceSnapshot | null>;
  /**
   * Stop a verified managed instance. Returns 'unknown' on any ambiguous
   * outcome (lost reply, partial stop) — callers MUST treat 'unknown' as
   * NOT stopped and retain the guard.
   */
  stopInstance(name: string): Promise<'stopped' | 'unknown'>;
  /** Every instance carrying managed `user.cloud-harness.*`/label markers. */
  listManagedInstances(): Promise<readonly VmGuardInstanceSnapshot[]>;
}

export interface VmGuardCommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** Output exceeded the caller's byte bound and was cut. */
  truncated: boolean;
}

/**
 * Bounded command executor for nft/iptables/ip/bridge invocations. `bounds`
 * is mandatory: implementations MUST enforce `timeoutMs` and `maxOutputBytes`
 * and report `timedOut`/`truncated` rather than hanging or buffering
 * unboundedly. argv is constructed by the guard from its own spec — callers
 * never pass raw shell strings.
 */
export type VmGuardCommandRunner = (
  argv: readonly string[],
  bounds: { timeoutMs: number; maxOutputBytes: number }
) => Promise<VmGuardCommandResult>;

/** Network-scope supervisor configuration consumed by the guard. */
export interface VmNetworkGuardConfig {
  /** Bridge naming pattern, e.g. `chmbr%d` (phase-05 owns expansion). */
  bridgePattern: string;
  /** IPv4 plan the per-workspace /30 is carved from, e.g. `10.240.0.0/16`. */
  subnetPlan: string;
  /** Uplink interface name; empty string = auto-detect single IPv4 default route. */
  uplink: string;
  /** Approved DNS resolvers permitted for guest egress (pinned set). */
  dnsResolvers: readonly string[];
  /** Non-public CIDR set dropped at L3 (link-local/metadata/RFC1918/CGNAT/...). */
  nonpublicCidrs: readonly string[];
  /** Where the separate guard service publishes its verdict JSON. */
  guardStatePath: string;
}

export interface VmNetworkGuardDeps {
  config: VmNetworkGuardConfig;
  incus: VmGuardIncusProbe;
  execFile: VmGuardCommandRunner;
  now?: () => number;
}

/** Typed failure inside the guard; `reason` is a bounded machine string. */
export class VmNetworkGuardError extends Error {
  readonly reason: string;
  constructor(reason: string, message?: string) {
    super(message ?? reason);
    this.name = 'VmNetworkGuardError';
    this.reason = reason;
  }
}

/**
 * Thrown by the shim when `src/network/ops.ts` is absent or malformed. Ops
 * handlers map it to a fail-closed contract error; it is never swallowed.
 */
export class VmNetworkGuardNotImplementedError extends VmNetworkGuardError {
  constructor(message = 'vm network guard module is not installed') {
    super('network-guard-not-implemented', message);
    this.name = 'VmNetworkGuardNotImplementedError';
  }
}

export interface VmNetworkGuardModule {
  createVmNetworkGuard(deps: VmNetworkGuardDeps): VmNetworkGuard;
}

const GUARD_METHODS = ['program', 'attest', 'tearDown', 'quarantine', 'withStartTransaction'] as const;

function isVmNetworkGuard(value: unknown): value is VmNetworkGuard {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return GUARD_METHODS.every((method) => typeof candidate[method] === 'function');
}

let guardPromise: Promise<VmNetworkGuard> | undefined;

/**
 * Resolve the phase-05 guard implementation exactly once per process. The
 * dynamic specifier keeps `src/network/**` out of the static module graph:
 * missing module, missing export, or a malformed return all reject with
 * `VmNetworkGuardNotImplementedError` (fail closed, retryable by restart).
 */
export function loadVmNetworkGuard(deps: VmNetworkGuardDeps): Promise<VmNetworkGuard> {
  guardPromise ??= (async () => {
    let mod: unknown;
    try {
      mod = await import('./network/ops.js');
    } catch (error) {
      throw new VmNetworkGuardNotImplementedError(
        `vm network guard module unavailable: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    const factory = (mod as Partial<VmNetworkGuardModule>).createVmNetworkGuard;
    if (typeof factory !== 'function') {
      throw new VmNetworkGuardNotImplementedError('vm network guard module does not export createVmNetworkGuard');
    }
    const guard = factory(deps);
    if (!isVmNetworkGuard(guard)) {
      throw new VmNetworkGuardNotImplementedError('vm network guard module returned an invalid guard object');
    }
    return guard;
  })();
  return guardPromise;
}

/** Test hook: drop the cached guard so a suite can re-resolve the module. */
export function resetVmNetworkGuardForTests(): void {
  guardPromise = undefined;
}

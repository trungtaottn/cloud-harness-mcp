import { dirname } from 'node:path';
import {
  VmNetworkGuardError,
  type VmGuardCommandRunner,
  type VmGuardIncusProbe,
  type VmGuardInstanceSnapshot,
  type VmNetworkGuardDeps
} from '../network-ops.js';
import {
  applyIpTablesRestore,
  applyNftTable,
  isGuardTaggedRule,
  planPermitRestore,
  readIpChain,
  resolveUplink,
  setBridgeIpv6,
  ensureBridge,
  ensureHostAddress,
  setBridgeUp,
  stripAllTaggedPermits,
  verifyKernelState,
  verifyPermits
} from './kernel.js';
import type { KernelVerifyResult } from './kernel.js';
import { parseIpTablesChain } from './parsers.js';
import { withGuardLock } from './lock.js';
import type { GuardLockOptions } from './lock.js';
import {
  CH_DOCKER_USER_FIRST_RULE,
  CH_FORWARD_FIRST_RULE,
  CH_INPUT_FIRST_RULE,
  canonicalNftTable,
  expandBridgePattern,
  planWorkspaceSubject,
  rulesetDigest,
  validateGuardConfig
} from './policy.js';
import type { ValidatedGuardConfig, VmNetworkSubject } from './policy.js';
import { allClaims, claimsPathFor, writeGuardVerdict } from './state.js';
import type { GuardClaim, GuardVerdictFile } from './state.js';

/**
 * The independent guard watcher (phase-05). It runs OUTSIDE the supervisor
 * process — its own systemd unit — so supervisor crashes, wedges or restarts
 * cannot suspend enforcement. Each cycle re-reads claims and kernel state
 * atomically, repairs drift in the fail-closed direction, and publishes a
 * verdict JSON the supervisor/operator can inspect.
 *
 * Guarantee boundary (documented, not hidden): this is a bounded poll plus
 * `nft monitor` wakeups — there is NO zero-window protection claim. An
 * administrator deleting ALL layers (nft table AND tagged permits AND bridge)
 * outside this service's view is outside the trusted-owner threat model; the
 * service detects and reports, it cannot prevent deliberate host admin action.
 */

export interface GuardWakeups {
  /** Register a callback fired on kernel firewall events / monitor reconnect. */
  subscribe(callback: () => void): () => void;
}

export interface GuardServiceDeps extends VmNetworkGuardDeps {
  /** Verdict JSON path; defaults to config.guardStatePath. */
  verdictPath?: string;
  /** Poll interval; clamped to [250ms, 60s], default 5000ms. */
  pollIntervalMs?: number;
  /** Optional nft-monitor wakeup source (live.ts wires `nft monitor`). */
  wakeups?: GuardWakeups;
  /** Cross-process lock tuning (tests use short timeouts). */
  lockOptions?: GuardLockOptions;
}

export interface GuardCycleResult {
  verdict: GuardVerdictFile['verdict'];
  rulesetHash: string;
  actions: string[];
  drift: string[];
}

const MIN_POLL_MS = 250;
const MAX_POLL_MS = 60_000;
const DEFAULT_POLL_MS = 5_000;
const MAX_ACTIONS = 64;
const MAX_DRIFT = 64;

function pushBounded(list: string[], item: string, max: number): void {
  if (list.length < max) list.push(item);
}

async function claimedSubjectsFor(
  config: ValidatedGuardConfig,
  claimsPath: string
): Promise<{ subjects: VmNetworkSubject[]; claims: GuardClaim[]; corrupt: string | null }> {
  const claims = await allClaims(claimsPath);
  const byBridge = new Map<string, VmNetworkSubject>();
  for (const claim of claims) {
    try {
      const subject = planWorkspaceSubject(config, { workspaceId: claim.workspaceId, vmName: claim.vmName });
      const prior = byBridge.get(subject.bridgeName);
      if (prior && prior.workspaceId !== subject.workspaceId) {
        return { subjects: [...byBridge.values()], claims, corrupt: `bridge '${subject.bridgeName}' claimed by multiple workspaces` };
      }
      byBridge.set(subject.bridgeName, subject);
    } catch (error) {
      return {
        subjects: [...byBridge.values()],
        claims,
        corrupt: `unusable claim for '${claim.vmName}': ${error instanceof Error ? error.message : String(error)}`
      };
    }
  }
  return { subjects: [...byBridge.values()], claims, corrupt: null };
}

/** Instances carrying valid managed identity markers, keyed by vmName. */
function managedInstances(snapshots: readonly VmGuardInstanceSnapshot[]): Map<string, VmGuardInstanceSnapshot> {
  const out = new Map<string, VmGuardInstanceSnapshot>();
  for (const snap of snapshots) {
    const ws = snap.expandedConfig['user.cloud-harness.workspace-id'];
    const iid = snap.expandedConfig['user.cloud-harness.instance-id'];
    if (typeof ws === 'string' && ws.length > 0 && typeof iid === 'string' && iid.length > 0) {
      out.set(snap.name, snap);
    }
  }
  return out;
}

const isStopped = (snap: VmGuardInstanceSnapshot): boolean => snap.status.trim().toLowerCase() === 'stopped';

/**
 * Positively verified NIC presence. The live probe guarantees
 * `expandedDevices` is a VALIDATED record (missing/malformed device state
 * fails the assessment instead of producing a snapshot), so "no
 * nic-typed entry" means verified zero NICs — the network-none case —
 * and never UNKNOWN device state. Only NIC-bearing instances need guard
 * coverage; a zero-NIC VM has no network path to contain.
 */
const hasNicDevice = (snap: VmGuardInstanceSnapshot): boolean =>
  Object.values(snap.expandedDevices).some((dev) => dev['type'] === 'nic');

/**
 * The bridge a NIC-bearing instance is actually attached to, read from
 * its `parent` device property (the pinned template sets
 * `parent: subject.bridgeName`). Returns null when the attachment cannot
 * be positively established — zero/multiple NICs or a missing/non-string
 * parent — which callers must treat as UNKNOWN, never as "no bridge".
 */
function nicParentBridge(snap: VmGuardInstanceSnapshot): string | null {
  const nics = Object.values(snap.expandedDevices).filter((dev) => dev['type'] === 'nic');
  if (nics.length !== 1) return null;
  const parent = nics[0]!['parent'];
  return typeof parent === 'string' && parent.length > 0 ? parent : null;
}

/** Every bridge name the guard plan can legitimately own (chmbr0..N-1). */
function canonicalBridgeNames(config: ValidatedGuardConfig): Set<string> {
  const names = new Set<string>();
  for (let i = 0; i < config.slotCount; i += 1) names.add(expandBridgePattern(config.bridgePattern, i));
  return names;
}

/** DOCKER-USER head-of-chain reorder is ours only when the CH jump survives and only tagged rules precede it. */
async function dockerUserReorderIsOurs(exec: VmGuardCommandRunner): Promise<boolean> {
  const text = await readIpChain(exec, 'filter', 'DOCKER-USER');
  const rules = parseIpTablesChain(text);
  const marker = rules.indexOf(CH_DOCKER_USER_FIRST_RULE);
  if (marker === -1) return false;
  return rules.slice(0, marker).every(isGuardTaggedRule);
}

async function firstRuleIs(exec: VmGuardCommandRunner, chain: string, expected: string): Promise<boolean> {
  const text = await readIpChain(exec, 'filter', chain);
  return parseIpTablesChain(text)[0] === expected;
}

function vmStatusFor(instances: Map<string, VmGuardInstanceSnapshot>): GuardVerdictFile['vms'] {
  return [...instances.values()].map((s) => {
    const vm: GuardVerdictFile['vms'][number] = { vmName: s.name, status: s.status };
    const ws = s.expandedConfig['user.cloud-harness.workspace-id'];
    if (typeof ws === 'string') vm.workspaceId = ws;
    return vm;
  });
}

/**
 * One full reconciliation cycle under the cross-process guard lock: the
 * supervisor's program/tearDown/quarantine take the same lock, so a cycle
 * can never repair on an assessment a concurrent lifecycle mutation has
 * already invalidated. A lock timeout is reported as a failed verdict —
 * fail-closed, never a silent skip.
 */
export async function runGuardCycle(deps: GuardServiceDeps): Promise<GuardCycleResult> {
  const config = validateGuardConfig(deps.config);
  const workDir = dirname(config.guardStatePath);
  try {
    return await withGuardLock(workDir, () => runGuardCycleLocked(deps), deps.lockOptions);
  } catch (error) {
    if (error instanceof VmNetworkGuardError && error.reason === 'guard-lock-timeout') {
      const now = deps.now ?? (() => Date.now());
      const verdictPath = deps.verdictPath ?? config.guardStatePath;
      const file: GuardVerdictFile = {
        verdict: 'failed',
        rulesetHash: '',
        attestedAt: now(),
        updatedAt: now(),
        vms: [],
        reason: `guard lock busy: ${error.message}`
      };
      await writeGuardVerdict(verdictPath, file).catch(() => undefined);
      return { verdict: 'failed', rulesetHash: '', actions: [], drift: [`guard-lock-timeout: ${error.message}`] };
    }
    // Catch-all: ANY unexpected cycle error becomes a failed verdict — the
    // guard process must never die mid-enforcement on a transient fault.
    // Drift/actions context is lost for this path; the verdict still tells
    // the truth and the next poll retries.
    const now = deps.now ?? (() => Date.now());
    const verdictPath = deps.verdictPath ?? config.guardStatePath;
    const file: GuardVerdictFile = {
      verdict: 'failed',
      rulesetHash: '',
      attestedAt: now(),
      updatedAt: now(),
      vms: [],
      reason: `cycle error: ${error instanceof Error ? error.message : String(error)}`
    };
    await writeGuardVerdict(verdictPath, file).catch(() => undefined);
    return {
      verdict: 'failed',
      rulesetHash: '',
      actions: [],
      drift: [`cycle-error: ${error instanceof Error ? error.message : String(error)}`]
    };
  }
}

async function runGuardCycleLocked(deps: GuardServiceDeps): Promise<GuardCycleResult> {
  const config = validateGuardConfig(deps.config);
  const exec: VmGuardCommandRunner = deps.execFile;
  const incus: VmGuardIncusProbe = deps.incus;
  const now = deps.now ?? (() => Date.now());
  const workDir = dirname(config.guardStatePath);
  const claimsPath = claimsPathFor(config.guardStatePath);
  const verdictPath = deps.verdictPath ?? config.guardStatePath;

  const actions: string[] = [];
  const drift: string[] = [];
  const act = (msg: string) => pushBounded(actions, msg, MAX_ACTIONS);
  const note = (msg: string) => pushBounded(drift, msg, MAX_DRIFT);

  const finish = async (
    verdict: GuardVerdictFile['verdict'],
    rulesetHash: string,
    vms: GuardVerdictFile['vms'],
    reason?: string
  ): Promise<GuardCycleResult> => {
    const file: GuardVerdictFile = { verdict, rulesetHash, attestedAt: now(), updatedAt: now(), vms };
    if (reason !== undefined) file.reason = reason;
    try {
      await writeGuardVerdict(verdictPath, file);
    } catch {
      // Verdict write failure must not mask the cycle outcome; the next
      // cycle rewrites it. Drift is still reported in the result.
      note('verdict-write-failed');
    }
    return { verdict, rulesetHash, actions, drift };
  };

  // -- Assessment -----------------------------------------------------------
  let claimsResult: Awaited<ReturnType<typeof claimedSubjectsFor>>;
  let instances: Map<string, VmGuardInstanceSnapshot>;
  try {
    [claimsResult, instances] = await Promise.all([
      claimedSubjectsFor(config, claimsPath),
      incus.listManagedInstances().then(managedInstances)
    ]);
  } catch (error) {
    note(`assessment-transport-failure: ${error instanceof Error ? error.message : String(error)}`);
    return finish('failed', rulesetDigest(''), [], 'assessment transport failure');
  }
  const subjects = claimsResult.subjects;

  let uplink: string;
  try {
    uplink = await resolveUplink(exec, config.uplink);
  } catch (error) {
    note(`uplink-unresolvable: ${error instanceof Error ? error.message : String(error)}`);
    return finish('failed', rulesetDigest(''), [], 'uplink unresolvable');
  }

  const canonical = canonicalNftTable(subjects, config, uplink);
  const rulesetHash = rulesetDigest(canonical);
  const vmStatus = () => vmStatusFor(instances);

  if (claimsResult.corrupt !== null) {
    note(`claims-corrupt: ${claimsResult.corrupt}`);
    await stopAllManaged(incus, instances, act, note);
    return finish('quarantined', rulesetHash, vmStatus(), claimsResult.corrupt);
  }

  // -- Kernel assessment ----------------------------------------------------
  let kernel: KernelVerifyResult;
  try {
    kernel = await verifyKernelState({ exec, workDir, subjects, config, uplink });
  } catch (error) {
    note(`kernel-read-failure: ${error instanceof Error ? error.message : String(error)}`);
    return finish('failed', rulesetHash, vmStatus(), 'kernel read failure');
  }

  const chGateOk = kernel.chGate.ok;
  if (!chGateOk) {
    // Distinguish a repairable reorder — OUR tagged permit sitting ahead of an
    // intact CH first-jump — from foreign tampering. INPUT/FORWARD first rules
    // are never ours to move; DOCKER-USER may legitimately carry our permits,
    // but only AFTER the CH jump. Anything else ahead of the jump is foreign.
    // A transient read failure here must fail the cycle closed, never crash
    // it — and stays fail-closed into quarantine+stopAllManaged: a probe we
    // cannot evaluate is indistinguishable from foreign tampering, so the
    // safe action is unchanged. What changes is the DIAGNOSTIC: the probe
    // error is captured and reported so operators can tell a transient
    // read failure apart from a genuine foreign reorder.
    let repairable = false;
    let inputOk = false;
    let forwardOk = false;
    let dockerUserProbeError: string | null = null;
    try {
      [repairable, inputOk, forwardOk] = await Promise.all([
        dockerUserReorderIsOurs(exec).catch((error: unknown) => {
          dockerUserProbeError = error instanceof Error ? error.message : String(error);
          return false;
        }),
        firstRuleIs(exec, 'INPUT', CH_INPUT_FIRST_RULE),
        firstRuleIs(exec, 'FORWARD', CH_FORWARD_FIRST_RULE)
      ]);
    } catch (error) {
      note(`ch-gate-read-failure: ${error instanceof Error ? error.message : String(error)}`);
      return finish('failed', rulesetHash, vmStatus(), 'ch-gate read failure');
    }
    if (!repairable || !inputOk || !forwardOk) {
      const probeNote =
        dockerUserProbeError !== null
          ? `docker-user probe read failed: ${dockerUserProbeError}`
          : repairable
            ? 'docker-user reorder is ours-repairable; INPUT/FORWARD first rule drifted'
            : 'docker-user reorder is foreign or marker missing';
      note(`ch-first-jump drift: ${kernel.chGate.reason ?? 'unknown'} (${probeNote})`);
      await stopAllManaged(incus, instances, act, note);
      return finish(
        'quarantined',
        rulesetHash,
        vmStatus(),
        `CH first-jump invariant violated (${probeNote})`
      );
    }
    note('docker-user head carries only our tagged permits ahead of an intact CH jump — reorder repair');
  }

  // Managed instances with no claim = running outside guard coverage.
  // Only positively-verified NIC-bearing instances need containment: the
  // probe guarantees expandedDevices is a validated record, so a missing
  // nic-typed entry is verified-zero (network-none), never unknown state.
  const claimedVmNames = new Set(subjects.map((s) => s.vmName));
  const unclaimedRunning = [...instances.values()].filter(
    (s) => !claimedVmNames.has(s.name) && !isStopped(s) && hasNicDevice(s)
  );
  for (const snap of unclaimedRunning) {
    note(`unclaimed-managed-instance: ${snap.name}`);
  }

  // -- Repair decision ------------------------------------------------------
  let repaired = false;

  // -- Containment pass (BEFORE any shared-rule repair) ---------------------
  // A failed stop must freeze the whole repair pass: shared nft/permit
  // cleanup could otherwise strip the last effective enforcement of a VM
  // that is still running. Containment itself is claim-gated — we only
  // ever bridge-down a positively-owned or orphan guard bridge; unknown
  // or foreign attachment state means NO host mutation at all.
  if (unclaimedRunning.length > 0) {
    const claimByBridge = new Map(claimsResult.claims.map((c) => [c.bridgeName, c]));
    let guardBridges: Set<string> | null = null;
    let containmentFailed = false;
    for (const snap of unclaimedRunning) {
      const stopped = await stopVerified(incus, snap, act, note);
      if (stopped) {
        act(`stopped unclaimed managed instance ${snap.name}`);
        continue;
      }
      containmentFailed = true;
      guardBridges ??= canonicalBridgeNames(config);
      const bridgeName = nicParentBridge(snap);
      const ws = snap.expandedConfig['user.cloud-harness.workspace-id'] ?? '';
      const claim = bridgeName === null ? undefined : claimByBridge.get(bridgeName);
      const foreign = claim !== undefined && (claim.workspaceId !== ws || claim.vmName !== snap.name);
      if (bridgeName === null || !guardBridges.has(bridgeName) || foreign) {
        const why =
          bridgeName === null
            ? 'nic attachment unknown'
            : foreign
              ? `bridge '${bridgeName}' claimed by '${claim?.workspaceId}'`
              : `bridge '${bridgeName}' outside guard namespace`;
        note(`containment-unverified ${snap.name}: ${why}`);
        continue;
      }
      try {
        await setBridgeUp(exec, bridgeName, false);
        act(`contained unclaimed instance ${snap.name}: bridge '${bridgeName}' down`);
      } catch (error) {
        note(`containment-bridge-down-failed ${bridgeName}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    if (containmentFailed) {
      // Freeze: no shared-table/permit/bridge repair this cycle — the last
      // effective enforcement of any still-running VM is preserved and the
      // next poll retries once Incus recovers.
      return finish('failed', rulesetHash, vmStatus(), 'unclaimed-instance-stop-failed');
    }
    repaired = true;
  }

  if (!kernel.nft.ok) {
    // Is the allow-path (our tagged permits) still live? Permits without the
    // verified drop-layer is the dangerous state: strip FIRST, stop affected
    // VMs, THEN rebuild. Count live tagged rules directly — drift counters
    // cannot distinguish "never programmed" from "stripped". A transient
    // chain read failure fails the cycle closed — never crashes the guard.
    let taggedLive = -1;
    try {
      const [duText, prText] = await Promise.all([
        readIpChain(exec, 'filter', 'DOCKER-USER'),
        readIpChain(exec, 'nat', 'POSTROUTING')
      ]);
      taggedLive =
        parseIpTablesChain(duText).filter(isGuardTaggedRule).length +
        parseIpTablesChain(prText).filter(isGuardTaggedRule).length;
    } catch (error) {
      note(`permit-count-read-failure: ${error instanceof Error ? error.message : String(error)}`);
      return finish('failed', rulesetHash, vmStatus(), 'permit count read failure');
    }
    if (taggedLive > 0) {
      const stripped = await stripAllTaggedPermits(exec, workDir).catch(() => -1);
      if (stripped < 0) {
        note('permit-strip-failed');
        await stopAllManaged(incus, instances, act, note);
        return finish('failed', rulesetHash, vmStatus(), 'permit strip failed');
      }
      act(`stripped ${stripped} tagged permit rule(s) before guard rebuild`);
      // Every running managed instance was exposed while the drop-layer was
      // unverified — stop them all before rebuilding.
      await stopAllManaged(incus, instances, act, note);
    }
    // Rebuild the canonical table for the claimed set (idempotent).
    try {
      await applyNftTable(exec, workDir, canonical);
      const recheck = await verifyKernelState({ exec, workDir, subjects, config, uplink });
      if (!recheck.nft.ok) {
        for (const d of recheck.nft.diffs.slice(0, 8)) note(`nft-repair-failed: ${d}`);
        await stopAllManaged(incus, instances, act, note);
        return finish('quarantined', rulesetHash, vmStatus(), 'nft guard unreconcilable');
      }
      act('rebuilt canonical nft guard table');
      repaired = true;
      kernel = recheck;
    } catch (error) {
      note(`nft-rebuild-failed: ${error instanceof Error ? error.message : String(error)}`);
      await stopAllManaged(incus, instances, act, note);
      return finish('quarantined', rulesetHash, vmStatus(), 'nft guard unreconcilable');
    }
  }

  // Permit drift with an intact guard → managed-only repair.
  if (kernel.permits.ok === false) {
    let probe: Awaited<ReturnType<typeof verifyPermits>>;
    try {
      probe = await verifyPermits(exec, subjects, config, uplink);
    } catch (error) {
      note(`permit-probe-read-failure: ${error instanceof Error ? error.message : String(error)}`);
      return finish('failed', rulesetHash, vmStatus(), 'permit probe read failure');
    }
    if (!probe.ok) {
      const plan = planPermitRestore(probe.drift);
      try {
        await applyIpTablesRestore(exec, workDir, 'filter', plan.filterLines);
        await applyIpTablesRestore(exec, workDir, 'nat', plan.natLines);
        const recheck = await verifyPermits(exec, subjects, config, uplink);
        if (!recheck.ok) {
          note('permit-repair-unverified');
          await stopAllManaged(incus, instances, act, note);
          return finish('quarantined', rulesetHash, vmStatus(), 'permit repair unreconcilable');
        }
        act(`repaired ${plan.filterLines.length + plan.natLines.length} permit rule op(s)`);
        repaired = true;
      } catch (error) {
        note(`permit-repair-failed: ${error instanceof Error ? error.message : String(error)}`);
        await stopAllManaged(incus, instances, act, note);
        return finish('quarantined', rulesetHash, vmStatus(), 'permit repair unreconcilable');
      }
    }
  }

  // Bridge drift → best-effort repair of claimed bridges (link stays down
  // until the next full verify; never brought up by the service).
  for (const bridge of kernel.bridges) {
    if (bridge.ok) continue;
    const subject = subjects.find((s) => s.bridgeName === bridge.name);
    if (!subject) continue;
    try {
      await ensureBridge(exec, subject);
      await setBridgeIpv6(exec, subject.bridgeName, true);
      await ensureHostAddress(exec, subject);
      act(`repaired bridge resources for ${subject.bridgeName}`);
      repaired = true;
    } catch (error) {
      note(`bridge-repair-failed ${subject.bridgeName}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // -- Final verification ----------------------------------------------------
  let final;
  try {
    final = await verifyKernelState({ exec, workDir, subjects, config, uplink });
  } catch (error) {
    note(`final-kernel-read-failure: ${error instanceof Error ? error.message : String(error)}`);
    return finish('failed', rulesetHash, vmStatus(), 'final kernel read failure');
  }
  const healthy =
    final.nft.ok && final.permits.ok && final.chGate.ok && final.bridges.every((b) => b.ok) && final.uplinkOk && final.forwarding;

  if (!healthy) {
    for (const d of [...final.nft.diffs, ...final.bridges.filter((b) => !b.ok).map((b) => `bridge ${b.name}: ${b.reason ?? '?'}`)].slice(0, 8)) {
      note(`unreconciled: ${d}`);
    }
    await stopAllManaged(incus, instances, act, note);
    return finish('quarantined', rulesetHash, vmStatus(), 'unreconciled kernel drift');
  }

  // Instances may have changed status during the cycle; refresh for verdict.
  let freshInstances = instances;
  try {
    freshInstances = managedInstances(await incus.listManagedInstances());
  } catch {
    // Keep the earlier snapshot; verdict vms are informational.
  }
  return finish(repaired ? 'degraded' : 'ok', rulesetHash, vmStatusFor(freshInstances));
}

// ---------------------------------------------------------------------------
// Managed-instance stop helpers (identity re-verified before every stop)
// ---------------------------------------------------------------------------

async function stopVerified(
  incus: VmGuardIncusProbe,
  snap: VmGuardInstanceSnapshot,
  act: (m: string) => void,
  note: (m: string) => void
): Promise<boolean> {
  if (isStopped(snap)) return true;
  try {
    const result = await incus.stopInstance(snap.name);
    if (result !== 'stopped') {
      note(`stop-unknown: ${snap.name}`);
      return false;
    }
    const confirm = await incus.getInstanceExpanded(snap.name);
    if (confirm === null || !isStopped(confirm)) {
      note(`stop-unconfirmed: ${snap.name}`);
      return false;
    }
    act(`stopped managed instance ${snap.name}`);
    return true;
  } catch (error) {
    note(`stop-failed ${snap.name}: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

async function stopAllManaged(
  incus: VmGuardIncusProbe,
  instances: Map<string, VmGuardInstanceSnapshot>,
  act: (m: string) => void,
  note: (m: string) => void
): Promise<void> {
  for (const snap of instances.values()) {
    // Zero-NIC (verified network-none) instances carry no network exposure —
    // the quarantine hammer must not stop them either.
    if (!isStopped(snap) && hasNicDevice(snap)) {
      // Identity was already verified by managedInstances(); stop is the
      // fail-closed direction and never removes guard resources.
      await stopVerified(incus, snap, act, note);
    }
  }
}

// ---------------------------------------------------------------------------
// Service loop: bounded poll + optional monitor wakeups, serialized cycles
// ---------------------------------------------------------------------------

export interface GuardServiceHandle {
  start(): void;
  stop(): Promise<void>;
  /** Run one cycle now (tests + manual trigger). */
  runOnce(): Promise<GuardCycleResult>;
}

export function createGuardService(deps: GuardServiceDeps): GuardServiceHandle {
  const pollMs = Math.min(MAX_POLL_MS, Math.max(MIN_POLL_MS, deps.pollIntervalMs ?? DEFAULT_POLL_MS));
  let timer: ReturnType<typeof setInterval> | undefined;
  let unsubscribe: (() => void) | undefined;
  let inFlight: Promise<GuardCycleResult> | null = null;
  let wakePending = false;
  let stopped = false;

  // Fire-and-forget invocations must never produce an unhandled rejection:
  // runGuardCycle already converts cycle faults into failed verdicts, so a
  // rejection here means a pre-cycle config/programming error — log it
  // loudly (journald) instead of dying silently or crashing.
  function fireCycle(): void {
    void cycle().catch((error: unknown) => {
      console.error(`vm-guard-service cycle rejected: ${error instanceof Error ? error.message : String(error)}`);
    });
  }

  function cycle(): Promise<GuardCycleResult> {
    if (inFlight !== null) {
      wakePending = true;
      return inFlight;
    }
    const run = (async () => {
      try {
        return await runGuardCycle(deps);
      } finally {
        inFlight = null;
        if (wakePending && !stopped) {
          wakePending = false;
          fireCycle();
        }
      }
    })();
    inFlight = run;
    return run;
  }

  return {
    start() {
      if (timer !== undefined) return;
      stopped = false;
      unsubscribe = deps.wakeups?.subscribe(() => {
        // Monitor event or reconnect → immediate full reverify (the cycle
        // always re-reads everything; there is no incremental trust).
        fireCycle();
      });
      timer = setInterval(fireCycle, pollMs);
      // NO unref(): the poll interval is the process liveness anchor. With
      // it ref'd, an nft-monitor child death (or its unref'd reconnect
      // timer) can never drain the event loop and exit(0) the guard — the
      // monitor is a wakeup accelerator, never the only thing keeping the
      // service alive.
      fireCycle();
    },
    async stop() {
      stopped = true;
      if (timer !== undefined) clearInterval(timer);
      timer = undefined;
      unsubscribe?.();
      unsubscribe = undefined;
      if (inFlight !== null) await inFlight.catch(() => undefined);
    },
    runOnce: cycle
  };
}

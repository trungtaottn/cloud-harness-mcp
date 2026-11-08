import { AsyncLocalStorage } from 'node:async_hooks';
import { dirname } from 'node:path';
import type {
  VmNetworkAttestResult,
  VmNetworkProgramResult,
  VmNetworkTearDownResult
} from '@cloud-harness/contracts';
import {
  VmNetworkGuardError,
  type VmNetworkAttestArgs,
  type VmNetworkGuard,
  type VmNetworkGuardDeps,
  type VmNetworkIdentity,
  type VmNetworkProgramArgs,
  type VmNetworkQuarantineArgs,
  type VmNetworkQuarantineResult,
  type VmNetworkTearDownArgs,
  type VmGuardInstanceSnapshot,
  type VmNetworkStartTx
} from '../network-ops.js';
import {
  EMPTY_RULESET_DIGEST,
  canonicalNftTable,
  expectedNicDevice,
  permitSpecsFor,
  planWorkspaceSubject,
  rulesetDigest,
  validateGuardConfig
} from './policy.js';
import type { ValidatedGuardConfig, VmNetworkSubject } from './policy.js';
import {
  applyIpTablesRestore,
  applyNftTable,
  bridgeIpv6Disabled,
  chGateCheck,
  deleteBridge,
  ensureBridge,
  ensureHostAddress,
  isBridgeUp,
  linkAddresses,
  planPermitRestore,
  readIpChain,
  resolveUplink,
  setBridgeIpv6,
  setBridgeUp,
  verifyKernelState,
  verifyNftTable,
  verifyPermits
} from './kernel.js';
import { ipRuleLineKey, parseIpTablesChain } from './parsers.js';
import { withGuardLock } from './lock.js';
import { allClaims, claimSubject, claimsPathFor, releaseSubject } from './state.js';
import type { GuardClaim } from './state.js';

/**
 * The phase-05 network guard behind the frozen `network-ops.ts` seam.
 *
 * Ordering invariants (verified pilot + phase-05 plan):
 *  - program: bridge created/held DOWN → canonical nft table applied and
 *    read-back verified → iptables permits repaired → CH first-jumps
 *    re-verified → bridge brought UP last. A workspace can never hold
 *    permits without the verified nft guard in front of them.
 *  - attest: ALWAYS reads live kernel + expanded-instance state; a verdict
 *    file or cached digest never substitutes.
 *  - tearDown: verified-stopped identity only → strip permits → rebuild nft
 *    without the subject → bridge down/delete → release claim; the guard
 *    table is deleted LAST and only when no claims remain.
 *  - quarantine: per explicit identity — link-down first, strip permits,
 *    then stop via probe; the guard is NEVER removed and an unknown stop
 *    retains everything.
 *
 * All mutations serialize through one queue so program/attest/tearDown/
 * quarantine can never interleave on the shared nft table or iptables chains.
 */

const MAX_QUARANTINE_IDENTITIES = 256;
const NIC_DEVICE_TYPE = 'nic';
const IDENTITY_WORKSPACE_KEY = 'user.cloud-harness.workspace-id';
const IDENTITY_INSTANCE_KEY = 'user.cloud-harness.instance-id';

/** Guard plus the managed-start transaction extension. `VmNetworkStartTx`
 * is owned by the supervisor seam (`network-ops.ts`) — imported above. */
export interface VmNetworkGuardWithTransactions extends VmNetworkGuard {
  /**
   * Hold serialize()+guard.flock for the ENTIRE `fn` — program, attest and
   * whatever the caller does next (Incus start) — so the independent guard
   * service cannot mutate kernel/claims in the attest→start window. Lock
   * timeout rejects BEFORE `fn` runs (a contended lock can never start a
   * VM). Inside `fn`, ONLY `tx.*` may be used: outer guard methods reject
   * with 'nested-guard-call' rather than queue-deadlock.
   */
  withStartTransaction<T>(args: VmNetworkProgramArgs, fn: (tx: VmNetworkStartTx) => Promise<T>): Promise<T>;
}

function guardError(reason: string, message: string): VmNetworkGuardError {
  return new VmNetworkGuardError(reason, message);
}

export function createVmNetworkGuard(deps: VmNetworkGuardDeps): VmNetworkGuardWithTransactions {
  const config: ValidatedGuardConfig = validateGuardConfig(deps.config);
  const exec = deps.execFile;
  const incus = deps.incus;
  const now = deps.now ?? (() => Date.now());
  const workDir = dirname(config.guardStatePath);
  const claimsPath = claimsPathFor(config.guardStatePath);

  let tail: Promise<void> = Promise.resolve();
  const serialize = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = tail.then(fn);
    tail = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  };

  // Async-context marker for the open transaction. AsyncLocalStorage (not
  // a plain flag) is required: only calls made FROM WITHIN the callback
  // inherit the store — an unrelated caller (e.g. tearDown for another
  // workspace) sees no store, queues behind the transaction normally, and
  // must NOT be rejected. Calls escaping the callback's async context
  // (detached timers/processes) are outside the contract anyway.
  const txContext = new AsyncLocalStorage<true>();
  const rejectNested = <T>(): Promise<T> =>
    Promise.reject(guardError('nested-guard-call', 'guard methods cannot be called inside withStartTransaction; use the provided tx surface'));

  const subjectFor = (identity: { workspaceId: string; vmName: string }): VmNetworkSubject =>
    planWorkspaceSubject(config, { workspaceId: identity.workspaceId, vmName: identity.vmName });

  /** All claimed subjects, re-derived canonically; deduped by bridge name. */
  const claimedSubjects = async (): Promise<VmNetworkSubject[]> => {
    const claims = await allClaims(claimsPath);
    const byBridge = new Map<string, VmNetworkSubject>();
    for (const claim of claims) {
      const subject = subjectFor(claim);
      const prior = byBridge.get(subject.bridgeName);
      if (prior && prior.workspaceId !== subject.workspaceId) {
        throw guardError('bridge-slot-collision', `claims map bridge '${subject.bridgeName}' to multiple workspaces`);
      }
      byBridge.set(subject.bridgeName, subject);
    }
    return [...byBridge.values()];
  };

  /** The live claim on this subject's bridge slot, or null when unclaimed. */
  const claimForBridge = async (subject: VmNetworkSubject): Promise<GuardClaim | null> => {
    const claims = await allClaims(claimsPath);
    return claims.find((c) => c.bridgeName === subject.bridgeName) ?? null;
  };

  /** Subjects the canonical table must contain: every claim plus `extra`. */
  const expectedSubjects = async (extra: VmNetworkSubject): Promise<VmNetworkSubject[]> => {
    const subjects = await claimedSubjects();
    if (!subjects.some((s) => s.bridgeName === extra.bridgeName)) subjects.push(extra);
    return subjects;
  };

  /** Strip this subject's tagged permits; safe to call when none exist. */
  const stripPermitsFor = async (subject: VmNetworkSubject, uplink: string): Promise<void> => {
    const specs = permitSpecsFor(subject, config, uplink);
    // Semantic keys of THIS subject's desired specs — the tag is inside the
    // key, so only our own permits can match (duplicates included).
    const wantDocker = new Set(
      [`-A DOCKER-USER ${specs.egress}`, `-A DOCKER-USER ${specs.ret}`]
        .map((l) => ipRuleLineKey(l))
        .filter((k): k is string => k !== null)
    );
    const wantNat = new Set(
      [`-A POSTROUTING ${specs.nat}`].map((l) => ipRuleLineKey(l)).filter((k): k is string => k !== null)
    );
    const [dockerUserText, postroutingText] = await Promise.all([
      readIpChain(exec, 'filter', 'DOCKER-USER'),
      readIpChain(exec, 'nat', 'POSTROUTING')
    ]);
    // Delete by the LIVE rule's own spec: iptables -D matches structurally,
    // so print-order differences can never make a present permit invisible.
    const filterLines = parseIpTablesChain(dockerUserText)
      .filter((l) => {
        const key = ipRuleLineKey(l);
        return key !== null && wantDocker.has(key);
      })
      .map((l) => `-D DOCKER-USER ${l.slice('-A DOCKER-USER '.length)}`);
    const natLines = parseIpTablesChain(postroutingText)
      .filter((l) => {
        const key = ipRuleLineKey(l);
        return key !== null && wantNat.has(key);
      })
      .map((l) => `-D POSTROUTING ${l.slice('-A POSTROUTING '.length)}`);
    await applyIpTablesRestore(exec, workDir, 'filter', filterLines);
    await applyIpTablesRestore(exec, workDir, 'nat', natLines);
  };

  const instanceStopped = (snapshot: VmGuardInstanceSnapshot | null): boolean =>
    snapshot === null || snapshot.status.trim().toLowerCase() === 'stopped';

  /** Identity re-verification: the named instance must carry OUR markers. */
  const identityMarkersMatch = (snapshot: VmGuardInstanceSnapshot, identity: VmNetworkIdentity): boolean => {
    const ws = snapshot.expandedConfig[IDENTITY_WORKSPACE_KEY];
    const iid = snapshot.expandedConfig[IDENTITY_INSTANCE_KEY];
    return ws === identity.workspaceId && iid === identity.instanceId;
  };

  // -------------------------------------------------------------------------
  // program
  // -------------------------------------------------------------------------

  const program = async (args: VmNetworkProgramArgs): Promise<VmNetworkProgramResult> => {
    const subject = subjectFor(args.identity);
    if (args.networkProfile === 'network-none') {
      // Nothing to program: no NIC exists, so no bridge/rules/permits. The
      // canonical empty digest is the contract's "no ruleset" answer.
      return { rulesetDigest: EMPTY_RULESET_DIGEST };
    }

    // Claim the bridge slot BEFORE touching the kernel — a truncated-hash
    // collision fails closed here, never after resources exist. Snapshot
    // prior ownership first: ONLY a claim this attempt creates (slot was
    // unclaimed) may be rolled back on failure. A pre-existing claim —
    // same-workspace re-program — may protect live resources and is
    // always retained. A FOREIGN claim makes claimSubject throw before any
    // mutation, so it can never reach the rollback path.
    const priorClaim = await claimForBridge(subject);
    await claimSubject(claimsPath, subject, now());
    try {
      return await programClaimed(subject);
    } catch (error) {
      if (priorClaim === null) {
        await releaseClaimIfQuiescent(subject);
      }
      throw error;
    }
  };

  /**
   * Failed-program rollback for a claim THIS attempt created. The claim is
   * released only after the instance is verified quiescent — absent or
   * 'stopped'. A running (or status-unknown, or transport-unverifiable)
   * instance keeps its claim: the guard must retain last protection for a
   * VM that may still be live. Kernel residue is deliberately left for
   * guard convergence — the bridge stays down, stale tagged permits are
   * stripped next cycle, and the nft table rebuilds from claims; every
   * leftover direction is fail-closed, never an open allow-path.
   */
  const releaseClaimIfQuiescent = async (subject: VmNetworkSubject): Promise<void> => {
    let snapshot: VmGuardInstanceSnapshot | null;
    try {
      snapshot = await incus.getInstanceExpanded(subject.vmName);
    } catch {
      return; // unverifiable → retain claim + protection
    }
    if (snapshot !== null && !instanceStopped(snapshot)) return; // running → retain
    await releaseSubject(claimsPath, subject).catch(() => undefined);
  };

  const programClaimed = async (subject: VmNetworkSubject): Promise<VmNetworkProgramResult> => {
    const subjects = await expectedSubjects(subject);
    const uplink = await resolveUplink(exec, config.uplink);

    const gateBefore = await chGateCheck(exec);
    if (!gateBefore.ok) {
      throw guardError('ch-gate-precondition', `refusing to program: ${gateBefore.reason}`);
    }

    // Bridge first, held DOWN: L2 cannot carry traffic until the guard is
    // verified and permits exist.
    await ensureBridge(exec, subject);
    await setBridgeIpv6(exec, subject.bridgeName, true);
    await ensureHostAddress(exec, subject);

    // 1) nft guard for the full claimed set — apply then read-back verify.
    const canonical = canonicalNftTable(subjects, config, uplink);
    await applyNftTable(exec, workDir, canonical);
    const nftVerify = await verifyNftTable(exec, subjects, config, uplink);
    if (!nftVerify.ok) {
      throw guardError('nft-verify-failed', `nft read-back mismatch: ${nftVerify.diffs.join('; ')}`);
    }

    // 2) Permits — repair missing/misplaced/stale tagged specs only.
    const permitsBefore = await verifyPermits(exec, subjects, config, uplink);
    if (!permitsBefore.ok) {
      const plan = planPermitRestore(permitsBefore.drift);
      await applyIpTablesRestore(exec, workDir, 'filter', plan.filterLines);
      await applyIpTablesRestore(exec, workDir, 'nat', plan.natLines);
      const permitsAfter = await verifyPermits(exec, subjects, config, uplink);
      if (!permitsAfter.ok) {
        throw guardError('permit-verify-failed', `permit read-back mismatch: ${JSON.stringify(permitsAfter.drift)}`);
      }
    }

    // 3) CH first-jumps must be untouched by our mutations.
    const gateAfter = await chGateCheck(exec);
    if (!gateAfter.ok) {
      throw guardError('ch-gate-postcondition', `CH first-jump drift after mutation: ${gateAfter.reason}`);
    }

    // 4) This subject's bridge must be canonical before it may come up.
    const bridgeState = await isBridgeUp(exec, subject.bridgeName);
    const bridgeAddrs = await linkAddresses(exec, subject.bridgeName, 4);
    const bridgeOk =
      bridgeState.exists &&
      bridgeState.isBridge &&
      (await bridgeIpv6Disabled(exec, subject.bridgeName)) &&
      bridgeAddrs.some((a) => a.family === 'inet' && a.local === subject.hostIp && a.prefixlen === subject.prefixLength);
    if (!bridgeOk) {
      await setBridgeUp(exec, subject.bridgeName, false).catch(() => undefined);
      throw guardError('bridge-verify-failed', `bridge '${subject.bridgeName}' failed post-program verification`);
    }

    // 5) Link up LAST — only with the verified guard + permits in place.
    await setBridgeUp(exec, subject.bridgeName, true);
    return { rulesetDigest: nftVerify.digest, bridgeName: subject.bridgeName, guestIp: subject.guestIp };
  };

  // -------------------------------------------------------------------------
  // attest — always live kernel + expanded-instance reads
  // -------------------------------------------------------------------------

  const verifyInstanceSlice = (
    snapshot: VmGuardInstanceSnapshot | null,
    subject: VmNetworkSubject,
    networkProfile: VmNetworkProgramArgs['networkProfile'],
    drift: string[]
  ): void => {
    if (snapshot === null) {
      drift.push('instance-missing: expanded view returned null');
      return;
    }
    const configKeys = Object.keys(snapshot.expandedConfig);
    const rawKeys = configKeys.filter((k) => k.startsWith('raw.')).sort();
    for (const key of rawKeys.slice(0, 8)) drift.push(`raw-config-present: ${key}`);
    if (snapshot.expandedConfig['boot.autostart'] === 'true') drift.push('boot.autostart is true');
    if (snapshot.profiles.length > 0) drift.push(`profiles non-empty: ${snapshot.profiles.join(',')}`);

    const nicDevices = Object.entries(snapshot.expandedDevices).filter(([, dev]) => dev['type'] === NIC_DEVICE_TYPE);
    if (networkProfile === 'network-none') {
      if (nicDevices.length > 0) {
        drift.push(`network-none but ${nicDevices.length} nic device(s) present: ${nicDevices.map(([k]) => k).join(',')}`);
      }
      return;
    }
    if (nicDevices.length !== 1) {
      drift.push(`expected exactly 1 nic device, found ${nicDevices.length}`);
      return;
    }
    const [deviceName, device] = nicDevices[0]!;
    const expected = expectedNicDevice(subject);
    for (const [key, want] of Object.entries(expected.expected)) {
      const got = device[key];
      if (got !== want) drift.push(`nic.${key}: expected '${want}', found '${got ?? '<absent>'}' (device '${deviceName}')`);
    }
    const allowed = new Set(expected.allowedKeys);
    for (const key of Object.keys(device).sort()) {
      if (!allowed.has(key)) drift.push(`nic.${key}: unexpected device key on '${deviceName}'`);
    }
  };

  const attest = async (args: VmNetworkAttestArgs): Promise<VmNetworkAttestResult> => {
    const subject = subjectFor(args.identity);
    const drift: string[] = [];

    // Instance slice first — cheap and independent of kernel reads.
    const snapshot = await incus.getInstanceExpanded(args.identity.vmName);
    verifyInstanceSlice(snapshot, subject, args.networkProfile, drift);
    if (snapshot !== null && !identityMarkersMatch(snapshot, args.identity)) {
      drift.push('instance identity markers do not match the requested workspace/instance');
    }

    // Kernel state for the expected subject set. dependency-access expects
    // claims ∪ this subject (an unclaimed subject means program never ran →
    // the table cannot contain its rules → attest must fail). network-none
    // expects claims only: this workspace must hold NO guard resources.
    let subjects: VmNetworkSubject[];
    let staleClaim = false;
    try {
      if (args.networkProfile === 'network-none') {
        // A workspace flipped to network-none must leave no guard footprint:
        // any surviving claim for it is stale and fails attestation.
        const claims = await allClaims(claimsPath);
        staleClaim = claims.some((c) => c.workspaceId === args.identity.workspaceId);
        subjects = await claimedSubjects();
      } else {
        subjects = await expectedSubjects(subject);
        // dependency-access requires REGISTERED guard coverage: the subject
        // must hold a live claim owned by this workspace. expectedSubjects
        // adds the subject unconditionally so kernel drift is still measured
        // — but an unclaimed subject means program's coverage was never
        // registered (or was released), and leftover kernel rules must not
        // let attest approve a start without guard authority.
        const slotClaim = await claimForBridge(subject);
        if (
          slotClaim === null ||
          slotClaim.workspaceId !== subject.workspaceId ||
          slotClaim.vmName !== subject.vmName
        ) {
          drift.push('unclaimed-subject: no live guard claim covers this workspace');
        }
      }
    } catch (error) {
      return {
        ok: false,
        rulesetDigest: EMPTY_RULESET_DIGEST,
        drift: { reasons: [`claims-unreadable: ${error instanceof Error ? error.message : String(error)}`] }
      };
    }
    if (staleClaim) drift.push('stale-claim: claims registry still holds an entry for this workspace under network-none');
    const uplink = await resolveUplink(exec, config.uplink);
    const kernel = await verifyKernelState({ exec, workDir, subjects, config, uplink });
    if (!kernel.nft.ok) drift.push(...kernel.nft.diffs.map((d) => `nft: ${d}`));
    if (!kernel.permits.ok) {
      const d = kernel.permits.drift;
      drift.push(`permits: missing=${d.missing.length} misplaced=${d.misplaced.length} stale=${d.stale.length}`);
      for (const line of [...kernel.permits.drift.missing, ...kernel.permits.drift.misplaced, ...kernel.permits.drift.stale].slice(0, 12)) {
        drift.push(`permit-drift: ${line}`);
      }
    }
    if (!kernel.chGate.ok) drift.push(`ch-gate: ${kernel.chGate.reason ?? 'failed'}`);
    for (const bridge of kernel.bridges) {
      if (!bridge.ok) drift.push(`bridge ${bridge.name}: ${bridge.reason ?? 'not canonical'}`);
    }
    if (!kernel.uplinkOk) drift.push('uplink unresolved');
    if (!kernel.forwarding) drift.push('net.ipv4.ip_forward is not 1');

    const canonical = canonicalNftTable(subjects, config, uplink);
    return {
      ok: drift.length === 0 && kernel.nft.ok && kernel.permits.ok && kernel.chGate.ok && kernel.bridges.every((b) => b.ok) && kernel.uplinkOk && kernel.forwarding,
      rulesetDigest: rulesetDigest(canonical),
      drift: drift.length === 0 ? undefined : { reasons: drift.slice(0, 64) }
    };
  };

  // -------------------------------------------------------------------------
  // tearDown — verified-stopped identity only; guard removed LAST
  // -------------------------------------------------------------------------

  const tearDown = async (args: VmNetworkTearDownArgs): Promise<VmNetworkTearDownResult> => {
    const subject = subjectFor(args.identity);
    const snapshot = await incus.getInstanceExpanded(args.identity.vmName);
    if (snapshot !== null) {
      if (!identityMarkersMatch(snapshot, args.identity)) {
        throw guardError('identity-unverified', `instance '${args.identity.vmName}' does not carry the requested identity markers`);
      }
      if (!instanceStopped(snapshot)) {
        throw guardError('instance-not-stopped', `instance '${args.identity.vmName}' status is '${snapshot.status}'`);
      }
    }
    // Absent instance = nothing can reach the bridge; host cleanup proceeds.

    // Claim-ownership gate BEFORE any host mutation: bridge names, guest
    // IPs and permit specs are all slot-derived, so when the slot was
    // reclaimed by a DIFFERENT workspace (truncated-hash collision after
    // our claim was released) every resource below now belongs to them —
    // stripping "our" permits would strip theirs and deleting the bridge
    // would disconnect their live VM. Our footprint is already gone in
    // that case (their claim could only exist after ours was released),
    // so teardown is honestly complete.
    const slotClaim = await claimForBridge(subject);
    if (slotClaim !== null && (slotClaim.workspaceId !== subject.workspaceId || slotClaim.vmName !== subject.vmName)) {
      return { removed: true };
    }

    const uplink = await resolveUplink(exec, config.uplink);

    // 1) Permits first — reachability dies here even if later steps fail.
    await stripPermitsFor(subject, uplink);

    // 2) Release the claim and rebuild the nft table without this subject.
    //    The guard TABLE is deleted only when the last claim goes away.
    await releaseSubject(claimsPath, subject);
    const remaining = await claimedSubjects();
    await applyNftTable(exec, workDir, canonicalNftTable(remaining, config, uplink));

    // 3) Bridge down then delete — after all L3 enforcement is gone. Link-down
    //    is best-effort hygiene (`ip link del` removes up bridges too); the
    //    delete is authoritative and its failure propagates honestly so a
    //    later tearDown retry can finish the cleanup.
    const bridge = await isBridgeUp(exec, subject.bridgeName);
    if (bridge.exists) {
      await setBridgeUp(exec, subject.bridgeName, false).catch(() => undefined);
      await deleteBridge(exec, subject.bridgeName);
    }
    return { removed: true };
  };

  // -------------------------------------------------------------------------
  // quarantine — drop/link-down first, permits stripped, then verified stop
  // -------------------------------------------------------------------------

  const quarantine = async (args: VmNetworkQuarantineArgs): Promise<VmNetworkQuarantineResult> => {
    const identities = args.identities.slice(0, MAX_QUARANTINE_IDENTITIES);
    const outcomes: { vmName: string; outcome: 'stopped' | 'unknown' | 'skipped' }[] = [];

    for (const identity of identities) {
      let subject: VmNetworkSubject;
      try {
        subject = subjectFor(identity);
      } catch {
        outcomes.push({ vmName: identity.vmName, outcome: 'skipped' });
        continue;
      }
      try {
        // Identity re-verification BEFORE any mutation: never touch a
        // bridge/instance that is not provably this workspace's.
        const snapshot = await incus.getInstanceExpanded(identity.vmName);
        if (snapshot === null) {
          outcomes.push({ vmName: identity.vmName, outcome: 'skipped' });
          continue;
        }
        if (!identityMarkersMatch(snapshot, identity)) {
          outcomes.push({ vmName: identity.vmName, outcome: 'skipped' });
          continue;
        }

        // Claim-ownership gate BEFORE any host mutation: bridge names,
        // guest IPs and permit specs are slot-derived, so a FOREIGN claim
        // on this bridge means the resources now belong to another
        // workspace — bridge-down would disconnect their live VM and
        // stripPermitsFor would remove their identical-spec permits. An
        // absent claim is an orphan slot (safe to contain); a matching
        // claim is ours. The instance itself is identity-verified ours,
        // so the stop below always proceeds — it is instance-scoped and
        // can never touch shared host resources.
        const slotClaim = await claimForBridge(subject);
        const slotOurs =
          slotClaim === null || (slotClaim.workspaceId === identity.workspaceId && slotClaim.vmName === identity.vmName);

        if (slotOurs) {
          // 1) Enforce drop at L2 first: bridge down kills forwarding even
          //    if every later step fails. The nft guard stays in place.
          const bridge = await isBridgeUp(exec, subject.bridgeName);
          if (bridge.exists && bridge.up) {
            await setBridgeUp(exec, subject.bridgeName, false);
          }

          // 2) Strip this subject's permits (best effort — stop is stronger).
          try {
            const uplink = await resolveUplink(exec, config.uplink);
            await stripPermitsFor(subject, uplink);
          } catch {
            // Permit strip failure does not block the stop; the bridge is
            // already down and the nft guard still drops.
          }
        }

        // 3) Stop via probe, then confirm with a fresh expanded read.
        if (instanceStopped(snapshot)) {
          outcomes.push({ vmName: identity.vmName, outcome: 'stopped' });
          continue;
        }
        const stopResult = await incus.stopInstance(identity.vmName);
        if (stopResult !== 'stopped') {
          outcomes.push({ vmName: identity.vmName, outcome: 'unknown' });
          continue;
        }
        const confirm = await incus.getInstanceExpanded(identity.vmName);
        outcomes.push({
          vmName: identity.vmName,
          outcome: confirm !== null && instanceStopped(confirm) ? 'stopped' : 'unknown'
        });
        // 'unknown' retains the guard: nothing was removed above.
      } catch {
        outcomes.push({ vmName: identity.vmName, outcome: 'unknown' });
      }
    }

    return {
      quarantined: outcomes.some((o) => o.outcome === 'stopped'),
      outcomes
    };
  };

  // Mutations take BOTH locks: the in-process queue serializes this guard
  // instance, and the cross-process guard.flock serializes against the
  // independent guard service so a cycle can never mutate on a stale
  // assessment mid-transition. attest stays read-only (in-process queue
  // only): reading mid-mutation correctly reports drift and fails closed.
  // Inside a withStartTransaction window every outer entry point rejects —
  // calling one would queue behind the open transaction and deadlock.
  const outer = {
    program: (args: VmNetworkProgramArgs): Promise<VmNetworkProgramResult> => {
      if (txContext.getStore() === true) return rejectNested();
      return serialize(() => withGuardLock(workDir, () => program(args)));
    },
    attest: (args: VmNetworkAttestArgs): Promise<VmNetworkAttestResult> => {
      if (txContext.getStore() === true) return rejectNested();
      return serialize(() => attest(args));
    },
    tearDown: (args: VmNetworkTearDownArgs): Promise<VmNetworkTearDownResult> => {
      if (txContext.getStore() === true) return rejectNested();
      return serialize(() => withGuardLock(workDir, () => tearDown(args)));
    },
    quarantine: (args: VmNetworkQuarantineArgs): Promise<VmNetworkQuarantineResult> => {
      if (txContext.getStore() === true) return rejectNested();
      return serialize(() => withGuardLock(workDir, () => quarantine(args)));
    },
    withStartTransaction: <T>(args: VmNetworkProgramArgs, fn: (tx: VmNetworkStartTx) => Promise<T>): Promise<T> => {
      if (txContext.getStore() === true) return rejectNested();
      // The lock spans program → attest → the caller's own Incus start:
      // the guard service cannot mutate kernel/claims anywhere in that
      // window. tx methods call the inner ops directly — the lock and the
      // queue are already held, so re-acquiring would self-deadlock. The
      // callback must be bounded by the caller (Incus.start carries its own
      // timeout). The lock is NEVER auto-broken for a live pid — a wedged
      // holder is retained until process death or operator recovery, so
      // this transaction's atomicity cannot be stolen by clock jumps or
      // long holds; contenders simply time out fail-closed.
      return serialize(() =>
        withGuardLock(workDir, () =>
          txContext.run(true, async () => {
            const tx: VmNetworkStartTx = {
              program: () => program(args),
              attest: () => attest(args)
            };
            return await fn(tx);
          })
        )
      );
    }
  };
  return outer;
}

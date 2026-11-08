import type { IncusClient } from './incus.js';
import type { VmLifecycle } from './lifecycle.js';
import type { VmSessionManager } from './sessions.js';
import type { VmWorkspaceSubjectPlanner, VmWorkspaceNetworkSubject } from './network-plan.js';
import { VmOpError } from './lifecycle.js';

/**
 * Guest network provisioning (native agent path, no custom daemon).
 *
 * The template image deliberately ships NO .network files and excludes
 * cloud-init: the per-VM static systemd-networkd unit is rendered here from
 * the canonical workspace subject and pushed through the Incus agent file
 * API after first boot, then applied with `networkctl` and VERIFIED against
 * the exact planned address/route before the workspace is admitted.
 *
 * Ordering contract (opStart): host guard program → attest → Incus start →
 * agent probe → THIS provisioning → workload-ready. Any failure stops the
 * verified instance and fails the start — workloads are never admitted on
 * unverified guest networking. `network-none` workspaces skip this entirely
 * (no eth0 is stamped for them).
 *
 * Deadline contract: the caller passes ONE absolute deadline (lease/hard
 * cutoff ∩ provisioning budget). Every step checks the remaining budget
 * before acting and bounds its exec by it — provisioning can never run
 * fresh per-step timeouts past the workspace cutoff.
 */

export const GUEST_NETWORK_UNIT_PATH = '/etc/systemd/network/10-cloudharness.network';

const GUEST_EXEC_MAX_BYTES = 16_384;
/** Absolute provisioning budget when no lease cutoff applies (~90s). */
export const GUEST_NETWORK_BUDGET_MS = 90_000;
/** Per-exec ceiling; the shared deadline usually binds tighter. */
const GUEST_EXEC_TIMEOUT_MS = 20_000;
/** Address/route settle bound inside the verify exec (~5s of polling). */
const VERIFY_POLL_SECONDS = 20;

/**
 * Render the systemd-networkd unit for one workspace. Field values come from
 * the canonical planner subject (already shape-validated) and the supervisor
 * DNS resolver list — both trusted, bounded inputs; nothing here executes.
 * [Match] binds the permanent MAC, so the guest interface NAME is irrelevant
 * to matching (template NIC naming is not assumed anywhere).
 */
export function renderGuestNetworkUnit(
  subject: VmWorkspaceNetworkSubject,
  dnsResolvers: readonly string[]
): string {
  if (dnsResolvers.length === 0) {
    throw new VmOpError('VM_SUPERVISOR_UNAVAILABLE', 'no approved DNS resolvers configured for guest network', { retryable: true });
  }
  return [
    '# Cloud Harness workspace link — rendered per-instance by the',
    '# cloud-harness-vm supervisor at provision time from supervisor-owned',
    '# settings. Placeholders are substituted verbatim before install to',
    '# /etc/systemd/network/; never edit this file inside a running guest.',
    '#',
    `# workspace=${subject.workspaceId} vm=${subject.vmName} slot=${subject.slotIndex}`,
    '[Match]',
    `MACAddress=${subject.mac}`,
    '',
    '[Network]',
    'DHCP=no',
    'LinkLocalAddressing=no',
    'IPv6AcceptRA=no',
    `DNS=${dnsResolvers.join(' ')}`,
    '',
    '[Address]',
    `Address=${subject.guestIp}/${subject.prefixLength}`,
    '',
    '[Route]',
    `Gateway=${subject.hostIp}`,
    ''
  ].join('\n');
}

export interface GuestNetworkDeps {
  incus: IncusClient;
  sessions: VmSessionManager;
  networkPlan: () => Promise<VmWorkspaceSubjectPlanner>;
  dnsResolvers: readonly string[];
  lifecycle: VmLifecycle;
}

function deadlineError(): VmOpError {
  return new VmOpError('EXPIRED', 'guest network provisioning exceeded the workspace deadline', { retryable: true });
}

/** Remaining budget in ms; throws when the shared deadline has passed. */
function remainingMs(deps: GuestNetworkDeps, deadlineMs: number): number {
  const remaining = deadlineMs - deps.lifecycle.nowMs();
  if (remaining <= 0) throw deadlineError();
  return remaining;
}

async function guestExec(
  deps: GuestNetworkDeps,
  input: { workspaceId: string; vmName: string; argv: string[]; opTag: string; deadlineMs: number }
): Promise<{ exitCode: number | null; stdout: string }> {
  const remaining = remainingMs(deps, input.deadlineMs);
  const outcome = await deps.sessions.openAndCapture({
    opId: `net:${input.opTag}:${input.workspaceId}:${deps.lifecycle.nowMs()}`,
    workspaceId: input.workspaceId,
    vmName: input.vmName,
    argv: input.argv,
    user: 'root',
    environment: {},
    timeoutMs: Math.min(GUEST_EXEC_TIMEOUT_MS, remaining),
    maxBytes: GUEST_EXEC_MAX_BYTES,
    envKeys: [],
    envDigest: ''
  });
  return { exitCode: outcome.exitCode, stdout: outcome.stdout };
}

/**
 * Guest-side snippet resolving the interface that owns the planned
 * permanent MAC. The template's NIC name is NOT assumed (could be eth0,
 * enp1s0, ...); MAC is the canonical identity the guard also pins.
 */
function ifaceForMacScript(mac: string): string {
  return (
    `IFACE=$(for d in /sys/class/net/*; do ` +
    `[ "$(cat "$d/address" 2>/dev/null)" = '${mac}' ] && basename "$d" && break; done); ` +
    `[ -n "$IFACE" ] || { echo 'NO-IFACE-FOR-MAC'; exit 1; }; `
  );
}

/**
 * Push, apply and verify the per-instance guest network unit. Throws
 * VmOpError on any failure; the caller performs the fail-closed stop.
 * `deadlineMs` is the single absolute budget shared by every step.
 */
export async function provisionGuestNetwork(
  deps: GuestNetworkDeps,
  input: { workspaceId: string; vmName: string; deadlineMs: number }
): Promise<void> {
  const planner = await deps.networkPlan();
  const subject = planner.plan({ workspaceId: input.workspaceId, vmName: input.vmName });
  const unit = renderGuestNetworkUnit(subject, deps.dnsResolvers);
  const { deadlineMs } = input;

  // 1. Install the rendered unit (root-owned, world-readable, parent dirs).
  //    The remaining shared budget is passed INTO the HTTP call so a stalled
  //    write aborts at the deadline instead of riding the default request
  //    timeout past the workspace cutoff.
  const writeBudget = remainingMs(deps, deadlineMs);
  await deps.incus.writeInstanceFile(
    input.vmName,
    GUEST_NETWORK_UNIT_PATH,
    Buffer.from(unit, 'utf8'),
    {
      mode: 0o644, uid: 0, gid: 0, createDirs: true,
      timeoutMs: Math.min(GUEST_EXEC_TIMEOUT_MS, writeBudget)
    }
  );
  // Post-step check: never proceed on state written past the cutoff.
  remainingMs(deps, deadlineMs);

  // 2. Apply: reload unit files, then reconfigure the MAC-resolved link so
  //    networkd picks up the new match/address/route without a reboot.
  const reload = await guestExec(deps, {
    workspaceId: input.workspaceId, vmName: input.vmName, opTag: 'reload', deadlineMs,
    argv: ['networkctl', 'reload']
  });
  if (reload.exitCode !== 0) {
    throw new VmOpError('VM_SUPERVISOR_UNAVAILABLE', `guest networkctl reload failed: ${reload.stdout.slice(0, 200)}`, { retryable: true });
  }
  const reconfigure = await guestExec(deps, {
    workspaceId: input.workspaceId, vmName: input.vmName, opTag: 'reconfigure', deadlineMs,
    argv: ['sh', '-c',
      ifaceForMacScript(subject.mac) +
      `networkctl reconfigure "$IFACE"`
    ]
  });
  if (reconfigure.exitCode !== 0) {
    throw new VmOpError('VM_SUPERVISOR_UNAVAILABLE', `guest networkctl reconfigure failed: ${reconfigure.stdout.slice(0, 200)}`, { retryable: true });
  }

  // 3. Verify the EXACT planned state on the MAC-resolved link. Matching is
  //    awk FIELD equality — 'default via 10.240.0.7' must not prefix-match
  //    'default via 10.240.0.70'. Exactness is bidirectional: exactly ONE
  //    inet address (the planned /30) and exactly ONE default route (the
  //    planned gateway) may exist on the link — extra addresses or extra
  //    default routes fail verification. The exec polls briefly for
  //    networkd to settle; the poll count derives from the remaining shared
  //    deadline so verification can never outlive it.
  const addrExact = `${subject.guestIp}/${subject.prefixLength}`;
  const polls = Math.max(
    1,
    Math.min(VERIFY_POLL_SECONDS, Math.floor(remainingMs(deps, deadlineMs) / 250) - 1)
  );
  const verify = await guestExec(deps, {
    workspaceId: input.workspaceId, vmName: input.vmName, opTag: 'verify', deadlineMs,
    argv: ['sh', '-c',
      ifaceForMacScript(subject.mac) +
      `for i in $(seq 1 ${polls}); do ` +
      // exactly one inet addr == planned, and no other inet addrs
      `A=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk -v a='${addrExact}' '$3=="inet" && $4==a {c++} END{print c+0}'); ` +
      `T=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '$3=="inet"{c++} END{print c+0}'); ` +
      // exactly one default route via planned gateway, and no other defaults
      `D=$(ip route show dev "$IFACE" 2>/dev/null | awk -v g='${subject.hostIp}' '$1=="default" && $3==g {c++} END{print c+0}'); ` +
      `TD=$(ip route show dev "$IFACE" 2>/dev/null | awk '$1=="default"{c++} END{print c+0}'); ` +
      `[ "$A" = 1 ] && [ "$T" = 1 ] && [ "$D" = 1 ] && [ "$TD" = 1 ] && exit 0; ` +
      `sleep 0.25; done; ` +
      `echo 'ADDR:'; ip -4 -o addr show dev "$IFACE" 2>&1; echo 'ROUTE:'; ip route show dev "$IFACE" 2>&1; exit 1`
    ]
  });
  if (verify.exitCode !== 0) {
    throw new VmOpError(
      'VM_SUPERVISOR_UNAVAILABLE',
      `guest network verification failed (expected exactly ${addrExact} + default via ${subject.hostIp} on MAC ${subject.mac}): ${verify.stdout.slice(0, 300)}`,
      { retryable: true }
    );
  }
}

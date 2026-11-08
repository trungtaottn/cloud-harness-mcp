import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { GUEST_NETWORK_UNIT_PATH, provisionGuestNetwork, renderGuestNetworkUnit } from '../src/guest-network.js';
import { VmOpError } from '../src/lifecycle.js';
import type { IncusClient } from '../src/incus.js';
import type { VmSessionManager } from '../src/sessions.js';
import type { VmWorkspaceSubjectPlanner } from '../src/network-plan.js';
import type { VmLifecycle } from '../src/lifecycle.js';

const SUBJECT = {
  workspaceId: 'ws_net_abcdefghijklmnopqrstuvwxyz',
  vmName: 'chm-vm-' + 'a'.repeat(32),
  slotIndex: 3,
  hostIp: '10.240.0.7',
  guestIp: '10.240.0.6',
  prefixLength: 30,
  mac: '00:16:3e:aa:bb:cc'
};

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

function makeDeps(overrides: {
  writeImpl?: IncusClient['writeInstanceFile'];
  execImpl?: (argv: string[]) => { exitCode: number | null; stdout: string };
  dns?: string[];
  nowMs?: () => number;
} = {}) {
  const writes: { path: string; data: Buffer; options: Record<string, unknown> }[] = [];
  const execs: { argv: string[]; timeoutMs?: number }[] = [];
  const incus = {
    writeInstanceFile: overrides.writeImpl ?? (async (_n: string, path: string, data: Buffer, options: Record<string, unknown>) => {
      writes.push({ path, data, options });
    })
  } as unknown as IncusClient;
  const sessions = {
    openAndCapture: async (input: { argv: string[]; timeoutMs: number }) => {
      execs.push({ argv: input.argv, timeoutMs: input.timeoutMs });
      return overrides.execImpl ? overrides.execImpl(input.argv) : { exitCode: 0, stdout: '' };
    }
  } as unknown as VmSessionManager;
  const planner: VmWorkspaceSubjectPlanner = {
    plan: () => SUBJECT as never,
    stamp: () => ({}),
    nicDeviceStamp: () => ({})
  } as unknown as VmWorkspaceSubjectPlanner;
  const deps = {
    incus,
    sessions,
    networkPlan: async () => planner,
    dnsResolvers: overrides.dns ?? ['10.0.0.2', '10.0.0.3'],
    lifecycle: { nowMs: overrides.nowMs ?? (() => Date.now()) } as unknown as VmLifecycle
  };
  return { deps, writes, execs };
}

function deadline(ms = 60_000): number {
  return Date.now() + ms;
}

describe('renderGuestNetworkUnit', () => {
  it('renders exact planned MAC/CIDR/gateway/DNS with no placeholders', () => {
    const unit = renderGuestNetworkUnit(SUBJECT as never, ['10.0.0.2']);
    expect(unit).toContain(`MACAddress=${SUBJECT.mac}`);
    expect(unit).toContain(`Address=${SUBJECT.guestIp}/${SUBJECT.prefixLength}`);
    expect(unit).toContain(`Gateway=${SUBJECT.hostIp}`);
    expect(unit).toContain('DNS=10.0.0.2');
    expect(unit).toContain('DHCP=no');
    expect(unit).not.toContain('{{');
    expect(unit).not.toContain('__');
  });

  it('rejects empty DNS resolver list', () => {
    expect(() => renderGuestNetworkUnit(SUBJECT as never, [])).toThrow(VmOpError);
  });
});

describe('provisionGuestNetwork', () => {
  it('writes the unit via the Incus file API then applies and verifies by MAC', async () => {
    const { deps, writes, execs } = makeDeps();
    await provisionGuestNetwork(deps, { workspaceId: SUBJECT.workspaceId, vmName: SUBJECT.vmName, deadlineMs: deadline() });
    expect(writes).toHaveLength(1);
    expect(writes[0]!.path).toBe(GUEST_NETWORK_UNIT_PATH);
    const text = writes[0]!.data.toString('utf8');
    expect(text).toContain(`Address=${SUBJECT.guestIp}/30`);
    expect(text).toContain('00:16:3e:aa:bb:cc');
    // The file write carries the shared deadline into the HTTP timeout.
    expect(writes[0]!.options.timeoutMs).toBeGreaterThan(0);
    expect(writes[0]!.options.timeoutMs).toBeLessThanOrEqual(20_000);
    // reload → MAC-resolved reconfigure → MAC-resolved verify ordering
    expect(execs.map((e) => e.argv[0])).toEqual(['networkctl', 'sh', 'sh']);
    const reconfigureScript = execs[1]!.argv.join(' ');
    expect(reconfigureScript).toContain(SUBJECT.mac);
    expect(reconfigureScript).toContain('networkctl reconfigure "$IFACE"');
    expect(reconfigureScript).not.toContain('eth0');
    const verifyScript = execs[2]!.argv.join(' ');
    expect(verifyScript).toContain(SUBJECT.mac);
    expect(verifyScript).toContain(SUBJECT.guestIp);
    expect(verifyScript).toContain(SUBJECT.hostIp);
    expect(verifyScript).toContain('/sys/class/net/');
    expect(verifyScript).not.toContain('dev eth0');
    // Exact field matching — never substring grep that .70 could satisfy.
    expect(verifyScript).not.toContain('grep -qF');
    expect(verifyScript).toContain('$3=="inet"');
    expect(verifyScript).toContain('$1=="default"');
  });

  it('fails closed when the shared deadline has already passed', async () => {
    const { deps, writes, execs } = makeDeps({ nowMs: () => 2_000_000_000_000 });
    await expect(
      provisionGuestNetwork(deps, { workspaceId: SUBJECT.workspaceId, vmName: SUBJECT.vmName, deadlineMs: 1_000 })
    ).rejects.toMatchObject({ code: 'EXPIRED' });
    expect(writes).toHaveLength(0);
    expect(execs).toHaveLength(0);
  });

  it('propagates the remaining budget into the file-write HTTP timeout', async () => {
    // Deadline ~3s out: the write must abort inside the shared budget, not
    // ride the default request timeout past the workspace cutoff.
    const { deps, writes } = makeDeps();
    const dl = deadline(3_000);
    await provisionGuestNetwork(deps, { workspaceId: SUBJECT.workspaceId, vmName: SUBJECT.vmName, deadlineMs: dl });
    const t = writes[0]!.options.timeoutMs as number;
    expect(t).toBeGreaterThan(1_000);
    expect(t).toBeLessThanOrEqual(3_000);
    expect(t).toBeLessThanOrEqual(20_000);
  });

  it('fails closed when the write crosses the deadline mid-flight', async () => {
    let now = 1_000_000;
    const dl = now + 5_000;
    const { deps, execs } = makeDeps({
      nowMs: () => now,
      writeImpl: async () => { now = dl + 1; } // stalled write lands past cutoff
    });
    await expect(
      provisionGuestNetwork(deps, { workspaceId: SUBJECT.workspaceId, vmName: SUBJECT.vmName, deadlineMs: dl })
    ).rejects.toMatchObject({ code: 'EXPIRED' });
    expect(execs).toHaveLength(0); // never applies state written past cutoff
  });

  it('bounds every exec by the remaining shared deadline', async () => {
    const now = 1_000_000;
    const { deps, execs } = makeDeps({ nowMs: () => now });
    const dl = now + 30_000;
    await provisionGuestNetwork(deps, { workspaceId: SUBJECT.workspaceId, vmName: SUBJECT.vmName, deadlineMs: dl });
    for (const e of execs) {
      expect(e.timeoutMs).toBeLessThanOrEqual(20_000);
      expect(e.timeoutMs).toBeLessThanOrEqual(dl - now);
    }
  });

  it('fails closed when the unit write fails', async () => {
    const { deps, execs } = makeDeps({
      writeImpl: async () => { throw new Error('agent unreachable'); }
    });
    await expect(
      provisionGuestNetwork(deps, { workspaceId: SUBJECT.workspaceId, vmName: SUBJECT.vmName, deadlineMs: deadline() })
    ).rejects.toThrow();
    expect(execs).toHaveLength(0); // never applies unverified state
  });

  it('fails closed when networkctl reload fails', async () => {
    const { deps } = makeDeps({
      execImpl: (argv) => argv[0] === 'networkctl' && argv[1] === 'reload'
        ? { exitCode: 1, stdout: 'no such link' } : { exitCode: 0, stdout: '' }
    });
    await expect(
      provisionGuestNetwork(deps, { workspaceId: SUBJECT.workspaceId, vmName: SUBJECT.vmName, deadlineMs: deadline() })
    ).rejects.toThrow(/reload failed/);
  });

  it('fails closed when guest verification finds no planned address/route', async () => {
    const { deps } = makeDeps({
      execImpl: (argv) => argv[0] === 'sh' && argv.join(' ').includes('for i in')
        ? { exitCode: 1, stdout: 'ADDR:\n    inet 169.254.1.1/16\nROUTE:\n' } : { exitCode: 0, stdout: '' }
    });
    await expect(
      provisionGuestNetwork(deps, { workspaceId: SUBJECT.workspaceId, vmName: SUBJECT.vmName, deadlineMs: deadline() })
    ).rejects.toThrow(/verification failed/);
  });
});

describe('verify loop — real sh execution against ip fixtures', () => {
  /**
   * Capture the generated verify argv and extract its `for i in ... done`
   * loop, then execute it in a real sh with a stubbed `ip` emitting fixture
   * output. This proves the EXACT script text performs exact field
   * matching — a `default via 10.240.0.70` route must NOT satisfy
   * `10.240.0.7`, extra addresses or extra default routes must fail, and
   * the planned state must pass.
   */
  async function captureVerifyLoop(): Promise<string> {
    const { deps, execs } = makeDeps();
    // Small deadline keeps the embedded poll count low for negative cases.
    await provisionGuestNetwork(deps, { workspaceId: SUBJECT.workspaceId, vmName: SUBJECT.vmName, deadlineMs: deadline(1_200) });
    const script = execs[2]!.argv[2]!;
    return script.slice(script.indexOf('for i in'));
  }

  function runLoop(loop: string, addrFixture: string, routeFixture: string): void {
    const dir = mkdtempSync(join(tmpdir(), 'gn-verify-'));
    dirs.push(dir);
    const addrPath = join(dir, 'a');
    const routePath = join(dir, 'r');
    writeFileSync(addrPath, addrFixture);
    writeFileSync(routePath, routeFixture);
    const wrapped =
      `IFACE=eth9; ` +
      `ip() { if [ "$1" = "-4" ]; then cat '${addrPath}'; else cat '${routePath}'; fi; }; ` +
      loop;
    execFileSync('sh', ['-c', wrapped], { stdio: 'pipe' });
  }

  const GOOD_ADDR = `2: eth9    inet ${SUBJECT.guestIp}/${SUBJECT.prefixLength} brd 10.240.0.7 scope global eth9\\       valid_lft forever preferred_lft forever\n`;
  const GOOD_ROUTE = `default via ${SUBJECT.hostIp} dev eth9 proto static\n10.240.0.4/30 dev eth9 proto kernel scope link src ${SUBJECT.guestIp}\n`;

  it('accepts exactly the planned address and gateway', async () => {
    const loop = await captureVerifyLoop();
    expect(() => runLoop(loop, GOOD_ADDR, GOOD_ROUTE)).not.toThrow();
  });

  it('rejects a near-match gateway (10.240.0.70 must not satisfy 10.240.0.7)', async () => {
    const loop = await captureVerifyLoop();
    expect(() => runLoop(loop, GOOD_ADDR, `default via 10.240.0.70 dev eth9 proto static\n`)).toThrow();
  });

  it('rejects extra inet addresses and extra default routes', async () => {
    const loop = await captureVerifyLoop();
    const extraAddr = GOOD_ADDR + `2: eth9    inet 169.254.1.1/16 brd 169.254.1.255 scope link eth9\\       valid_lft forever preferred_lft forever\n`;
    const extraRoute = GOOD_ROUTE + `default via 192.0.2.1 dev eth9 proto static metric 100\n`;
    expect(() => runLoop(loop, extraAddr, extraRoute)).toThrow();
  });
});

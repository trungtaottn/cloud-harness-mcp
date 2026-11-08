import { EventEmitter } from 'node:events';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { ChildProcess } from 'node:child_process';
import { createFakeKernel } from '../fake-kernel.js';
import { createGuardService } from '../../../src/network/guard-service.js';
import { createNftMonitorWakeups } from '../../../src/network/live.js';
import type { VmGuardIncusProbe } from '../../../src/network-ops.js';

/**
 * Fresh-process liveness probe (bundled by service-liveness.test.ts and run
 * under plain `node`): starts the REAL guard service with the REAL nft
 * monitor wakeup source, then kills the monitor child. The service must
 * stay alive on its referenced poll interval alone — if the interval were
 * unref'd, the dead monitor + unref'd reconnect timer would drain the event
 * loop and the process would exit(0) silently before the marker fires.
 *
 * Discrimination requirement: after the monitor-death timer completes, this
 * process must hold NO ref'd handles except the service's poll interval.
 * The marker timer is therefore unref'd — it fires only while the loop is
 * still being driven by something else (the poll interval under test). A
 * ref'd marker timer would keep the loop alive by itself and make the test
 * vacuous.
 */

const stateDir = process.argv[2]!;
const markerPath = process.argv[3]!;

class FakeMonitorChild extends EventEmitter {
  stdout = new EventEmitter();
  kill() {
    return true;
  }
}

const kernel = await createFakeKernel({
  links: [{ ifname: 'enp7s0', operstate: 'UP', addrs: [] }],
  routes: [{ dst: 'default', table: 'main', dev: 'enp7s0' }],
  sysctls: { 'net.ipv4.ip_forward': '1' }
});

const incus: VmGuardIncusProbe = {
  getInstanceExpanded: () => Promise.resolve(null),
  stopInstance: () => Promise.resolve('stopped'),
  listManagedInstances: () => Promise.resolve([])
};

const monitorChild = new FakeMonitorChild() as unknown as ChildProcess;
const wakeups = createNftMonitorWakeups({
  spawnFn: (() => monitorChild) as never,
  minReconnectMs: 20,
  maxReconnectMs: 40
});

const service = createGuardService({
  config: {
    bridgePattern: 'chmbr%d',
    subnetPlan: '10.240.0.0/16',
    uplink: 'enp7s0',
    dnsResolvers: ['1.1.1.1', '8.8.8.8'],
    nonpublicCidrs: [],
    guardStatePath: join(stateDir, 'guard-state.json')
  },
  incus,
  execFile: kernel.exec,
  wakeups,
  pollIntervalMs: 60
});

service.start();

// Kill the monitor child early. This timer is ref'd but completes and is
// gone afterwards; the wakeups reconnect timer it schedules is unref'd.
setTimeout(() => {
  monitorChild.emit('exit', 0, null);
}, 150);

// Proof-of-life marker ~600ms in — 4x past monitor death. UNREF'd: it can
// only fire if the poll interval (the handle under test) is keeping the
// event loop alive. If the interval were unref'd the loop would drain at
// ~150ms and this timer would never fire → no marker → test fails.
const markerTimer = setTimeout(() => {
  void (async () => {
    await writeFile(markerPath, 'alive', 'utf8');
    await service.stop();
    await kernel.dispose();
    process.exit(0);
  })();
}, 600);
if (typeof markerTimer === 'object' && 'unref' in markerTimer) markerTimer.unref();

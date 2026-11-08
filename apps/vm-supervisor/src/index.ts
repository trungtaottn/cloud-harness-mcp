import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { loadVmSupervisorConfig } from './config.js';
import { VmJournal } from './journal.js';
import { RequestDigester } from './request-digest.js';
import { IncusClient } from './incus.js';
import { isManagedInstanceConfig } from './identity.js';
import { VmLifecycle } from './lifecycle.js';
import { VmSessionManager } from './sessions.js';
import { loadVmNetworkGuard, type VmNetworkGuard, type VmNetworkGuardConfig } from './network-ops.js';
import { loadVmWorkspaceSubjectPlanner, type VmWorkspaceSubjectPlanner } from './network-plan.js';
import { makeGuardCommandRunner, makeGuardIncusProbe, spawnApplianceProcess } from './runtime.js';
import { createSupervisorHandler } from './server.js';
import { VmSupervisorWireServer } from './transport.js';
import { DiskReservations } from './disk-reservations.js';

/**
 * vm-supervisor entrypoint: the ONLY component that talks to Incus. Binds a
 * root-owned Unix socket, serves the frozen workspace/host op contract, and
 * enforces fencing, idempotency, admission, watchdog, and fail-closed network
 * integration. Docker remains the default executor backend; this service is
 * opt-in and never Compose-published.
 */

function log(message: string, fields?: Record<string, unknown>): void {
  const suffix = fields === undefined ? '' : ` ${JSON.stringify(fields)}`;
  process.stderr.write(`[vm-supervisor] ${message}${suffix}\n`);
}

async function main(): Promise<void> {
  const config = loadVmSupervisorConfig(process.env);
  mkdirSync(config.stateDir, { recursive: true, mode: 0o700 });
  mkdirSync(join(config.stateDir, 'streams'), { recursive: true, mode: 0o700 });

  const journal = new VmJournal(join(config.stateDir, 'journal.sqlite'));
  const digester = new RequestDigester(join(config.stateDir, 'hmac-key'));
  const incus = new IncusClient({ socketPath: config.incusSocketPath, project: config.incusProject });
  const execFile = makeGuardCommandRunner();
  const guardProbe = makeGuardIncusProbe(incus, (cfg) => isManagedInstanceConfig(cfg));

  // Guard + planner resolution is lazy + cached: phase-05's src/network/**
  // may be absent in early deployments — ops fail closed per-call, startup
  // continues. Both consume the SAME VmNetworkGuardConfig so the stamped NIC
  // identity and the enforced identity can never diverge.
  const guardConfig: VmNetworkGuardConfig = {
    bridgePattern: config.bridgePattern,
    subnetPlan: config.subnetPlan,
    uplink: config.uplink,
    dnsResolvers: config.dnsResolvers,
    nonpublicCidrs: config.nonpublicCidrs,
    guardStatePath: config.guardStatePath
  };
  let guardPromise: Promise<VmNetworkGuard> | undefined;
  const guard = (): Promise<VmNetworkGuard> => {
    guardPromise ??= loadVmNetworkGuard({
      config: guardConfig,
      incus: guardProbe,
      execFile
    });
    return guardPromise;
  };
  let plannerPromise: Promise<VmWorkspaceSubjectPlanner> | undefined;
  const networkPlan = (): Promise<VmWorkspaceSubjectPlanner> => {
    plannerPromise ??= loadVmWorkspaceSubjectPlanner(guardConfig);
    return plannerPromise;
  };

  const lifecycle = new VmLifecycle({ config, journal, incus, guard });
  const sessions = new VmSessionManager({
    journal,
    incus,
    incusSocketPath: config.incusSocketPath,
    lifecycle
  });

  // One ledger backs BOTH upload staging (wire server) and offline-export
  // staging (request handler) so concurrent transfers cannot overcommit the
  // state/pool filesystem.
  const diskReservations = new DiskReservations();

  const handler = createSupervisorHandler({
    config,
    journal,
    digester,
    incus,
    incusSocketPath: config.incusSocketPath,
    lifecycle,
    sessions,
    guard,
    networkPlan,
    execFile,
    spawnAppliance: spawnApplianceProcess,
    diskReservations,
    logger: log
  });

  const server = new VmSupervisorWireServer({
    socketPath: config.socketPath,
    token: config.token,
    handler,
    streamDir: join(config.stateDir, 'streams'),
    diskReservations,
    logger: log
  });

  // Boot sequence: watchdog + reconcile BEFORE accepting traffic so journal
  // state is consistent with Incus reality when the first request lands.
  lifecycle.startWatchdog();
  sessions.startReaper();
  try {
    const report = await lifecycle.reconcile();
    log('reconcile complete', {
      adopted: report.adopted.length,
      quarantined: report.quarantined.length,
      stoppedUnleased: report.stoppedUnleased.length,
      foreignIgnored: report.foreignIgnored.length,
      deferred: report.deferred.length
    });
  } catch (error) {
    log('reconcile failed; continuing with journal state', {
      error: error instanceof Error ? error.message : String(error)
    });
  }

  await server.listen();
  log('listening', { socketPath: config.socketPath, project: config.incusProject });

  const shutdown = (signal: string): void => {
    log('shutting down', { signal });
    lifecycle.stopWatchdog();
    sessions.stopReaper();
    void server.close().finally(() => {
      journal.close();
      process.exit(0);
    });
    // Hard bound: never hang shutdown on a wedged Incus call.
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((error) => {
  log('fatal startup error', { error: error instanceof Error ? error.message : String(error) });
  process.exit(1);
});

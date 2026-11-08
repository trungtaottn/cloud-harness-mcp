import type { VmReconcileReport } from './vm-reconcile.js';

/**
 * Bounded startup wrapper for the incus-vm fleet reconcile sweep.
 *
 * The sweep performs a serial vm.stop + full vm.export + host inspection per
 * retained hard-expired record, and retained records make the work repeat on
 * every boot. This wrapper owns an AbortController: the startup deadline AND
 * runner shutdown both abort it, and the signal is handed to the sweep so it
 * stops scheduling further records — the deadline bounds the WORK, not just
 * how long startup waits. The sweep promise still settles on its own (a
 * signal-aware reconcile returns a partial report or throws an abort error);
 * `done` additionally races a deadline backstop so a sweep that ignores the
 * signal can never hold the startup path.
 *
 * Reconcile stays advisory and log-only: it never authorizes a VM from a
 * cached result and never replaces the authoritative supervisor admission
 * gate on real start paths.
 */
export const VM_FLEET_RECONCILE_DEADLINE_MS = 120_000;

export type VmFleetStartupLogger = {
  info(obj: Record<string, unknown>, msg: string): void;
  warn(obj: Record<string, unknown>, msg: string): void;
};

export type VmFleetStartupHandle = {
  /** Resolves once the sweep settles or the deadline fires. */
  done: Promise<void>;
  /** Abort the sweep (shutdown path). Idempotent; the sweep sees the signal. */
  abort: () => void;
};

function logVmFleetActions(report: VmReconcileReport, logger: VmFleetStartupLogger): void {
  for (const action of report.actions) {
    const detail = { action, workspaceId: 'workspaceId' in action ? action.workspaceId : undefined };
    if (action.type === 'quarantined' || action.type === 'deferred' || action.type === 'orphaned') {
      logger.warn(detail, 'vm fleet reconcile requires attention');
    } else {
      logger.info(detail, 'vm fleet reconcile');
    }
  }
}

/**
 * Starts the sweep with an AbortSignal, logs its actions whenever it
 * completes (including a partial report after cancellation), and returns a
 * handle whose `done` resolves at sweep settlement or deadline — whichever
 * comes first. `abort()` (wired to runner shutdown) and the deadline both
 * cancel the signal; cancellation is logged as info, real failures as warn,
 * each exactly once.
 */
export function startVmFleetReconcileStartup(
  startSweep: (signal: AbortSignal) => Promise<VmReconcileReport>,
  options: { deadlineMs?: number; recordCount?: number; logger: VmFleetStartupLogger }
): VmFleetStartupHandle {
  const logger = options.logger;
  const deadlineMs = options.deadlineMs ?? VM_FLEET_RECONCILE_DEADLINE_MS;
  const controller = new AbortController();
  let stopReason: 'deadline' | 'shutdown' | undefined;

  const sweep = startSweep(controller.signal);
  // Actions are logged whenever the sweep actually completes — including a
  // partial report after cancellation — and sweep failures are logged exactly
  // once here so the raced promise never surfaces as an unhandled rejection.
  void sweep.then(
    (report) => logVmFleetActions(report, logger),
    (error) => {
      if (stopReason !== undefined) {
        logger.info({ reason: stopReason }, 'vm fleet reconcile sweep stopped');
      } else {
        logger.warn({ error }, 'vm fleet reconcile sweep failed');
      }
    }
  );

  const deadline = new Promise<never>((_, reject) => {
    const timer = setTimeout(() => {
      stopReason = 'deadline';
      controller.abort();
      reject(new Error('vm fleet reconcile deadline exceeded'));
    }, deadlineMs);
    timer.unref?.();
  });

  const done = (async () => {
    try {
      await Promise.race([sweep, deadline]);
    } catch {
      if (stopReason === 'deadline') {
        logger.warn(
          { deadlineMs, records: options.recordCount ?? 0 },
          'vm fleet reconcile exceeded startup deadline; abort signalled and unfinished records deferred to next boot'
        );
      }
      // Sweep rejection after shutdown-abort and non-deadline failures were
      // already logged by the sweep handler above.
    }
  })();

  return {
    done,
    abort: () => {
      if (!controller.signal.aborted) {
        stopReason = 'shutdown';
        controller.abort();
      }
    }
  };
}

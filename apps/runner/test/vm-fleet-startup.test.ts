import { describe, expect, it, vi } from 'vitest';
import { startVmFleetReconcileStartup } from '../src/vm-fleet-startup.js';
import type { VmReconcileReport } from '../src/vm-reconcile.js';

function fakeLogger() {
  return { info: vi.fn(), warn: vi.fn() };
}

const CLEAN_REPORT: VmReconcileReport = {
  actions: [{ type: 'export-clean', workspaceId: 'ws_1', vmName: 'chm-vm-abc', reason: 'offline export clean' }]
};

describe('startVmFleetReconcileStartup', () => {
  it('passes an AbortSignal to the sweep and aborts it at the deadline', async () => {
    const logger = fakeLogger();
    let seenSignal: AbortSignal | undefined;
    let resolveSweep: (report: VmReconcileReport) => void = () => undefined;
    const sweepPromise = new Promise<VmReconcileReport>((resolve) => { resolveSweep = resolve; });

    const handle = startVmFleetReconcileStartup(
      (signal) => { seenSignal = signal; return sweepPromise; },
      { deadlineMs: 25, recordCount: 3, logger }
    );
    await handle.done;

    // The deadline aborts the WORK, not just the wait: the sweep's signal is
    // cancelled so a signal-aware reconcile stops scheduling further records.
    expect(seenSignal?.aborted).toBe(true);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ deadlineMs: 25, records: 3 }),
      expect.stringContaining('deadline')
    );

    // A late partial report still logs its real actions; canonical VM data
    // is untouched because reconcile holds no delete authority.
    resolveSweep({ actions: [{ type: 'deferred', vmName: 'chm-vm-x', reason: 'not reached' }] });
    await vi.waitFor(() => {
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ action: expect.objectContaining({ type: 'deferred' }) }),
        'vm fleet reconcile requires attention'
      );
    });
  });

  it('abort() cancels the sweep signal for shutdown and resolves done', async () => {
    const logger = fakeLogger();
    let seenSignal: AbortSignal | undefined;

    const handle = startVmFleetReconcileStartup(
      (signal) => {
        seenSignal = signal;
        // Model a signal-aware reconcile: it rejects once the signal fires.
        return new Promise<VmReconcileReport>((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('reconcile aborted')), { once: true });
        });
      },
      { deadlineMs: 60_000, logger }
    );
    handle.abort();
    handle.abort(); // idempotent
    await handle.done;

    expect(seenSignal?.aborted).toBe(true);
    // Cancellation is informational, not a failure warning.
    await vi.waitFor(() => {
      expect(logger.info).toHaveBeenCalledWith(
        expect.objectContaining({ reason: 'shutdown' }),
        'vm fleet reconcile sweep stopped'
      );
    });
    expect(logger.warn).not.toHaveBeenCalledWith(expect.anything(), 'vm fleet reconcile sweep failed');
  });

  it('does not schedule further sweep work after abort — signal-aware sweeps stop early', async () => {
    const logger = fakeLogger();
    const processed: string[] = [];
    const handle = startVmFleetReconcileStartup(
      async (signal) => {
        const actions: VmReconcileReport['actions'] = [];
        for (const id of ['ws_1', 'ws_2', 'ws_3']) {
          if (signal.aborted) break; // signal-aware reconcile stops scheduling
          processed.push(id);
          await new Promise((resolve) => setTimeout(resolve, 5));
          actions.push({ type: 'stopped', vmName: `chm-vm-${id}`, reason: 'test' });
        }
        return { actions };
      },
      { deadlineMs: 60_000, logger }
    );
    // Abort while early records are in flight: the last record never runs.
    await vi.waitFor(() => expect(processed).toContain('ws_1'));
    handle.abort();
    await handle.done;
    expect(processed).not.toContain('ws_3');
    expect(processed.length).toBeLessThanOrEqual(2);
  });

  it('logs actions and resolves promptly when the sweep completes inside the deadline', async () => {
    const logger = fakeLogger();
    const handle = startVmFleetReconcileStartup(async () => CLEAN_REPORT, { deadlineMs: 5_000, logger });
    await handle.done;
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ action: expect.objectContaining({ type: 'export-clean' }) }),
      'vm fleet reconcile'
    );
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it('logs a sweep failure exactly once and still resolves', async () => {
    const logger = fakeLogger();
    const handle = startVmFleetReconcileStartup(() => Promise.reject(new Error('supervisor gone')), { deadlineMs: 5_000, logger });
    await handle.done;
    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(logger.warn.mock.calls[0]![1]).toBe('vm fleet reconcile sweep failed');
  });
});

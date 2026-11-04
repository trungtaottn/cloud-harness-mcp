import { release } from 'node:os';
import { HarnessError, type RunnerConfig } from '@cloud-harness/contracts';
import { inspectContainer, runDocker } from './docker-engine.js';

export const VM_RUNTIME = 'io.containerd.kata.v2';

/** No arbitrary runtime aliases: an absent Kata shim must fail, never fall back to runc. */
export function vmLaunchArgs(config: Pick<RunnerConfig, 'vmMemoryMiB' | 'vmCpus'>): string[] {
  const memory = `${config.vmMemoryMiB ?? 4096}m`;
  return [
    '--runtime', VM_RUNTIME, '--label', 'cloud-harness.executor=kata',
    '--user', '10001:10001', '--memory', memory, '--memory-swap', memory,
    '--cpus', String(config.vmCpus ?? 2), '--pids-limit', '2048',
    '--ulimit', 'nofile=65536:65536'
  ];
}

export async function assertVmExecutor(name: string): Promise<void> {
  const inspection = await inspectContainer(name);
  const hostConfig = inspection?.HostConfig as { Runtime?: string; Privileged?: boolean; Binds?: string[] } | undefined;
  if (hostConfig?.Runtime !== VM_RUNTIME || hostConfig.Privileged) {
    throw new HarnessError('UNAVAILABLE', 'VM executor requires the Kata runtime without host privileged mode', 503, false);
  }
  const probe = await runDocker(['exec', name, '/bin/uname', '-r'], { timeoutMs: 30_000, maxBytes: 1024 });
  const guestKernel = probe.stdout.trim();
  if (probe.exitCode !== 0 || !guestKernel || guestKernel === release()) {
    throw new HarnessError('UNAVAILABLE', 'VM executor did not attest a separate guest kernel', 503, false);
  }
}

/** Stopping preserves the writable root filesystem; removal is reserved for explicit deletion. */
export async function stopVmExecutor(name: string): Promise<void> {
  const result = await runDocker(['stop', '--time', '20', name], { timeoutMs: 30_000, maxBytes: 8192 });
  if (result.exitCode !== 0) throw new HarnessError('UNAVAILABLE', 'VM could not be stopped; retained state must not be removed', 503, true);
}

export async function vmWritableBytes(name: string): Promise<number> {
  const result = await runDocker(['inspect', '--size', '--format', '{{.SizeRw}}', name], { timeoutMs: 30_000, maxBytes: 1024 });
  const value = result.stdout.trim();
  const bytes = Number(value);
  if (result.exitCode !== 0 || !/^\d+$/.test(value) || !Number.isSafeInteger(bytes)) {
    throw new HarnessError('UNAVAILABLE', 'VM writable disk usage could not be measured', 503, true);
  }
  return bytes;
}

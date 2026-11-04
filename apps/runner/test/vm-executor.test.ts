import { release } from 'node:os';
import { afterEach, describe, expect, it, vi } from 'vitest';
const docker = vi.hoisted(() => ({ inspectContainer: vi.fn(), runDocker: vi.fn() }));
vi.mock('../src/docker-engine.js', () => docker);
import { assertVmExecutor, stopVmExecutor, vmWritableBytes } from '../src/vm-executor.js';
afterEach(() => vi.resetAllMocks());
describe('VM executor enforcement', () => {
  it('refuses a host-kernel runtime before executing commands', async () => {
    docker.inspectContainer.mockResolvedValue({ HostConfig: { Runtime: 'runc' } });
    await expect(assertVmExecutor('workspace')).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(docker.runDocker).not.toHaveBeenCalled();
  });
  it('does not trust the runtime name when the guest reports the host kernel', async () => {
    docker.inspectContainer.mockResolvedValue({ HostConfig: { Runtime: 'io.containerd.kata.v2' } });
    docker.runDocker.mockResolvedValue({ exitCode: 0, stdout: release() });
    await expect(assertVmExecutor('workspace')).rejects.toMatchObject({ code: 'UNAVAILABLE' });
  });
  it('fails a stop rather than report retained shutdown when Docker refuses it', async () => {
    docker.runDocker.mockResolvedValue({ exitCode: 1, stderr: 'unavailable' });
    await expect(stopVmExecutor('workspace')).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(docker.runDocker.mock.calls).toHaveLength(1);
    expect(docker.runDocker.mock.calls[0]?.[0]?.[0]).toBe('stop');
  });
  it('refuses missing or nonnumeric disk measurements', async () => {
    for (const stdout of ['', '<nil>', '-1', 'NaN']) {
      docker.runDocker.mockResolvedValue({ exitCode: 0, stdout });
      await expect(vmWritableBytes('workspace')).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    }
  });
});

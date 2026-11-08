import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ProvisionContext } from '../src/executor-backend.js';
import { createVmExportWorkspace } from '../src/backend-factory.js';
import type { VmSupervisorGateway } from '../src/incus-executor-backend.js';
import { makeCtx, makeRecord, testDirectories, trackDir } from './backend-test-utils.js';

/**
 * Regression coverage for the vm.export → host-file seam: the staging
 * reservation must be acquired BEFORE the guarded writer truncates anything,
 * output lands in a sibling temp, and only a trailer-verified stream is
 * renamed over destPath — so a rejected or failed export preserves an
 * existing destination byte-for-byte.
 */

// Aliases the shared fixture registry so trackDir dirs (makeCtx/makeRecord
// inside vmCtx) drain in afterEach too — same pattern as sibling files.
const directories = testDirectories;
afterEach(() => {
  vi.clearAllMocks();
  for (const dir of directories.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function workDir(): string {
  const dir = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-vm-export-')));
  directories.push(dir);
  return dir;
}

function vmCtx(): ProvisionContext {
  return makeCtx({
    record: makeRecord({ backendKind: 'incus-vm', backendInstanceId: randomUUID() })
  });
}

const PAYLOAD = Buffer.from('guest-workspace-tar-payload');
const PAYLOAD_SHA = createHash('sha256').update(PAYLOAD).digest('hex');

type FakeMode = 'ok' | 'mid-fail' | 'bad-trailer';

function fakeClient(mode: FakeMode): VmSupervisorGateway {
  const vmExport = vi.fn(async (_identity: unknown, _params: unknown, options: { sink: (chunk: Buffer) => void | Promise<void> }) => {
    if (mode === 'mid-fail') {
      await options.sink(PAYLOAD.subarray(0, 8));
      throw new Error('wire dropped mid-export');
    }
    await options.sink(PAYLOAD);
    return mode === 'bad-trailer'
      ? { sha256: '0'.repeat(64), bytes: PAYLOAD.length }
      : { sha256: PAYLOAD_SHA, bytes: PAYLOAD.length };
  });
  return { vmExport } as unknown as VmSupervisorGateway;
}

function tmpResidue(dir: string): string[] {
  return readdirSync(dir).filter((name) => name.includes('.tmp-'));
}

describe('createVmExportWorkspace', () => {
  it('rejects on reservation failure and preserves an existing destination byte-for-byte', async () => {
    const dir = workDir();
    const destPath = join(dir, 'export.tar');
    writeFileSync(destPath, 'pre-existing-sentinel');
    const exportWorkspace = createVmExportWorkspace(fakeClient('ok'));
    await expect(exportWorkspace(vmCtx(), { guestPath: '/workspace', destPath, maxBytes: Number.MAX_SAFE_INTEGER }))
      .rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    expect(readFileSync(destPath, 'utf8')).toBe('pre-existing-sentinel');
    expect(tmpResidue(dir)).toEqual([]);
  });

  it('preserves an existing destination when the stream fails mid-export', async () => {
    const dir = workDir();
    const destPath = join(dir, 'export.tar');
    writeFileSync(destPath, 'pre-existing-sentinel');
    const exportWorkspace = createVmExportWorkspace(fakeClient('mid-fail'));
    await expect(exportWorkspace(vmCtx(), { guestPath: '/workspace', destPath, maxBytes: 1_000_000 }))
      .rejects.toThrow('wire dropped mid-export');
    expect(readFileSync(destPath, 'utf8')).toBe('pre-existing-sentinel');
    expect(tmpResidue(dir)).toEqual([]);
  });

  it('preserves an existing destination when the trailer does not match the bytes written', async () => {
    const dir = workDir();
    const destPath = join(dir, 'export.tar');
    writeFileSync(destPath, 'pre-existing-sentinel');
    const exportWorkspace = createVmExportWorkspace(fakeClient('bad-trailer'));
    await expect(exportWorkspace(vmCtx(), { guestPath: '/workspace', destPath, maxBytes: 1_000_000 }))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(readFileSync(destPath, 'utf8')).toBe('pre-existing-sentinel');
    expect(tmpResidue(dir)).toEqual([]);
  });

  it('leaves no destination behind when a first export fails', async () => {
    const dir = workDir();
    const destPath = join(dir, 'export.tar');
    const exportWorkspace = createVmExportWorkspace(fakeClient('mid-fail'));
    await expect(exportWorkspace(vmCtx(), { guestPath: '/workspace', destPath, maxBytes: 1_000_000 }))
      .rejects.toThrow('wire dropped mid-export');
    expect(existsSync(destPath)).toBe(false);
    expect(tmpResidue(dir)).toEqual([]);
  });

  it('renames the verified temp over destPath on success', async () => {
    const dir = workDir();
    const destPath = join(dir, 'export.tar');
    writeFileSync(destPath, 'old-archive');
    const exportWorkspace = createVmExportWorkspace(fakeClient('ok'));
    const result = await exportWorkspace(vmCtx(), { guestPath: '/workspace', destPath, maxBytes: 1_000_000 });
    expect(result).toEqual({ sha256: PAYLOAD_SHA, bytes: PAYLOAD.length });
    expect(readFileSync(destPath)).toEqual(PAYLOAD);
    expect(tmpResidue(dir)).toEqual([]);
  });
});

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Deploy-artifact contract for the SUPERVISOR systemd unit. /run is a tmpfs
 * wiped on reboot: the supervisor binds /run/cloud-harness-vm/supervisor.sock
 * and its in-process guard hooks share claims/verdict/guard.flock in the same
 * directory, but nothing in the JS path mkdirs it — only systemd
 * RuntimeDirectory does, at unit start, BEFORE ExecStart. Without it the
 * supervisor crash-loops on a fresh boot whenever the guard unit is absent,
 * masked, failed, or below its nft floor (ordering vs the guard is soft by
 * design and must stay that way).
 *
 * These tests pin the artifact so a future edit cannot silently drop the
 * provisioning, reintroduce a dead unit-name reference, or break the
 * shared-directory preserve contract with the guard unit.
 */

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const SUPERVISOR_UNIT = join(REPO_ROOT, 'deploy/vm-supervisor/cloudharness-vm-supervisor.service');
const GUARD_UNIT = join(REPO_ROOT, 'deploy/vm-supervisor/guard/cloud-harness-vm-guard.service');
const SUPERVISOR_INSTALL = join(REPO_ROOT, 'deploy/vm-supervisor/install.sh');

async function unitText(path: string): Promise<string> {
  return readFile(path, 'utf8');
}

function section(unit: string, name: string): string {
  const match = unit.match(new RegExp(`\\[${name}\\]([\\s\\S]*?)(?=\\n\\[|$)`));
  return match?.[1] ?? '';
}

describe('supervisor systemd unit — runtime dir provisioning', () => {
  it('declares RuntimeDirectory=cloud-harness-vm so the socket dir exists at unit start', async () => {
    const unit = await unitText(SUPERVISOR_UNIT);
    expect(unit).toMatch(/^RuntimeDirectory=cloud-harness-vm$/m);
  });

  it('preserves the SHARED dir across supervisor stop — never deletes the guard lock/socket', async () => {
    const unit = await unitText(SUPERVISOR_UNIT);
    // The directory is shared with the guard unit (claims, verdict,
    // guard.flock, guard-state.json). systemd's default removes
    // RuntimeDirectory on unit stop; only 'yes' keeps it for the guard's
    // lifetime — a supervisor restart/stop must never pull the shared
    // lock/socket out from under a live guard.
    expect(unit).toMatch(/^RuntimeDirectoryPreserve=yes$/m);
    expect(unit).not.toMatch(/^RuntimeDirectoryPreserve=restart$/m);
    expect(unit).not.toMatch(/^RuntimeDirectoryPreserve=no$/m);
  });

  it('keeps /run/cloud-harness-vm writable under ProtectSystem=full', async () => {
    const unit = await unitText(SUPERVISOR_UNIT);
    const rw = unit.match(/^ReadWritePaths=(.+)$/m);
    expect(rw).not.toBeNull();
    expect(rw![1]!.split(/\s+/)).toContain('/run/cloud-harness-vm');
  });

  it('the documented default socket path lives under the RuntimeDirectory', async () => {
    const install = await unitText(SUPERVISOR_INSTALL);
    // install.sh documents VM_SUPERVISOR_SOCKET default; it must sit inside
    // the directory systemd creates, not somewhere else on tmpfs.
    expect(install).toContain('/run/cloud-harness-vm/supervisor.sock');
  });
});

describe('supervisor ↔ guard unit contract', () => {
  it('After= references the REAL guard unit filename (cloud-harness-vm-guard.service)', async () => {
    const unit = await unitText(SUPERVISOR_UNIT);
    const after = section(unit, 'Unit').match(/^After=(.+)$/m)?.[1] ?? '';
    // The installed guard unit is cloud-harness-vm-guard.service (hyphen).
    // A dead After= reference silently no-ops the intended soft ordering.
    expect(after.split(/\s+/)).toContain('cloud-harness-vm-guard.service');
    expect(after.split(/\s+/)).not.toContain('cloudharness-vm-guard.service');
  });

  it('never hard-depends on the guard — absence must not block supervisor start', async () => {
    const unit = await unitText(SUPERVISOR_UNIT);
    for (const directive of ['Requires', 'BindsTo', 'PartOf']) {
      const values = section(unit, 'Unit').match(new RegExp(`^${directive}=(.+)$`, 'm'))?.[1] ?? '';
      expect(values.split(/\s+/)).not.toContain('cloud-harness-vm-guard.service');
    }
    const service = section(unit, 'Service');
    for (const directive of ['Requires', 'BindsTo', 'PartOf', 'Upholds']) {
      const values = service.match(new RegExp(`^${directive}=(.+)$`, 'm'))?.[1] ?? '';
      expect(values.split(/\s+/)).not.toContain('cloud-harness-vm-guard.service');
    }
  });

  it('both units declare the SAME RuntimeDirectory so the shared dir is intentional', async () => {
    const supervisor = await unitText(SUPERVISOR_UNIT);
    const guard = await unitText(GUARD_UNIT);
    expect(supervisor).toMatch(/^RuntimeDirectory=cloud-harness-vm$/m);
    expect(guard).toMatch(/^RuntimeDirectory=cloud-harness-vm$/m);
    // Guard keeps its own preserve contract (covered by test/network/);
    // assert it here too so a guard-side regression is caught by either suite.
    expect(guard).toMatch(/^RuntimeDirectoryPreserve=yes$/m);
  });
});

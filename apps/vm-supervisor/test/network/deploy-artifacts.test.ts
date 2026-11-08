import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Deploy-artifact contract for the guard state directory (PR#6 finding #3):
 * /run is a tmpfs wiped on reboot, so the claims/verdict/guard.flock dir must
 * be created by systemd BEFORE the first cycle — RuntimeDirectory= does
 * exactly that at unit start. These tests pin the artifact so a future edit
 * cannot silently drop the provisioning.
 */

const REPO_ROOT = fileURLToPath(new URL('../../../../', import.meta.url));
const UNIT_PATH = join(REPO_ROOT, 'deploy/vm-supervisor/guard/cloud-harness-vm-guard.service');
const INSTALL_PATH = join(REPO_ROOT, 'deploy/vm-supervisor/guard/install.sh');

async function unitText(): Promise<string> {
  return readFile(UNIT_PATH, 'utf8');
}

describe('guard systemd unit — state dir provisioning', () => {
  it('declares RuntimeDirectory=cloud-harness-vm so /run state exists at unit start', async () => {
    const unit = await unitText();
    expect(unit).toMatch(/^RuntimeDirectory=cloud-harness-vm$/m);
  });

  it('preserves the shared state dir across guard stop/restart — never auto-deletes the live lock', async () => {
    const unit = await unitText();
    // The dir is shared with the supervisor (claims, verdict, guard.lock).
    // systemd's default removes RuntimeDirectory on unit stop; 'restart'
    // still removes on explicit stop. Only 'yes' keeps it for the
    // supervisor's lifetime — a guard restart must never pull the shared
    // lock/socket out from under a live holder.
    expect(unit).toMatch(/^RuntimeDirectoryPreserve=yes$/m);
    expect(unit).not.toMatch(/^RuntimeDirectoryPreserve=restart$/m);
    expect(unit).not.toMatch(/^RuntimeDirectoryPreserve=no$/m);
  });

  it('keeps /run/cloud-harness-vm writable under ProtectSystem=full', async () => {
    const unit = await unitText();
    const rw = unit.match(/^ReadWritePaths=(.+)$/m);
    expect(rw).not.toBeNull();
    expect(rw![1]!.split(/\s+/)).toContain('/run/cloud-harness-vm');
  });

  it('the documented default state path lives under the RuntimeDirectory', async () => {
    const install = await readFile(INSTALL_PATH, 'utf8');
    // install.sh documents the required env; the default state path must be
    // inside the directory systemd creates, not somewhere else on tmpfs.
    expect(install).toContain('/run/cloud-harness-vm/guard-state.json');
  });
});

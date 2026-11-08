import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

const repo = process.cwd();
const guest = join(repo, 'deploy/vm-template/guest');
const templateDir = join(repo, 'deploy/vm-template');
const workerDir = join(repo, 'worker');

function sh(scriptPath: string, args: string[] = [], opts: { env?: NodeJS.ProcessEnv } = {}) {
  return spawnSync('bash', [scriptPath, ...args], { encoding: 'utf8', env: { ...process.env, ...opts.env } });
}

describe('baked worker files', () => {
  const bakeEntries: Array<[string, string]> = [
    ['/opt/harness/harness-worker.mjs', 'worker/harness-worker.mjs'],
    ['/opt/harness/worker-runner.sh', 'worker/worker-runner.sh'],
    ['/opt/harness/shell-runner.sh', 'worker/shell-runner.sh'],
    ['/opt/harness/task-runner.sh', 'worker/task-runner.sh'],
    ['/opt/harness/clone-helper.sh', 'worker/clone-helper.sh'],
    ['/opt/harness/git-transfer-helper.sh', 'worker/git-transfer-helper.sh'],
    ['/opt/harness/gh-helper.sh', 'worker/gh-helper.sh'],
    ['/opt/harness/bin/npx', 'worker/bin/npx-dispatcher'],
    ['/opt/harness/bin/skills', 'worker/bin/skills'],
    ['/opt/harness/bin/skillx', 'worker/bin/skillx'],
  ];

  it.each(bakeEntries)('%s is byte-identical to %s', (dest, src) => {
    const baked = readFileSync(join(guest, dest));
    const source = readFileSync(join(repo, src));
    expect(baked.equals(source), `${dest} drifted from ${src}`).toBe(true);
  });

  it('bake set covers every worker file (drift guard completeness)', () => {
    const workerFiles = execFileSync('find', [workerDir, '-type', 'f'], { encoding: 'utf8' })
      .trim().split('\n').map((f) => f.slice(repo.length + 1)).sort();
    const baked = bakeEntries.map(([, src]) => src).sort();
    expect(baked).toEqual(workerFiles);
  });

  it('/opt/harness/package.json marks the tree as ES modules', () => {
    const pkg = JSON.parse(readFileSync(join(guest, 'opt/harness/package.json'), 'utf8'));
    expect(pkg.type).toBe('module');
  });
});

describe('guest static contract', () => {
  it('sudoers drop-in grants harness passwordless sudo', () => {
    expect(readFileSync(join(guest, 'etc/sudoers.d/harness'), 'utf8').trim())
      .toBe('harness ALL=(ALL) NOPASSWD: ALL');
  });

  it('profile.d PATH matches the docker executor contract', () => {
    const profile = readFileSync(join(guest, 'etc/profile.d/harness.sh'), 'utf8');
    const dockerfile = readFileSync(join(repo, 'docker/executor.Dockerfile'), 'utf8');
    const dockerPath = dockerfile.match(/export PATH="([^"]+)"/)?.[1];
    expect(dockerPath, 'docker executor PATH export not found').toBeTruthy();
    const exportLine = profile.match(/export PATH="([^"]+)"/)?.[1];
    expect(exportLine).toBe(dockerPath);
  });

  it('provision.sh creates uid 10001 harness user with docker group + NOPASSWD check', () => {
    const p = readFileSync(join(templateDir, 'provision.sh'), 'utf8');
    expect(p).toContain('useradd --uid 10001');
    expect(p).toContain('usermod -aG docker harness');
    expect(p).toContain('runuser -u harness -- sudo -n true');
    expect(p).toContain('visudo -cf');
  });

  it('provision.sh enables incus-agent and asserts it usable', () => {
    const p = readFileSync(join(templateDir, 'provision.sh'), 'utf8');
    expect(p).toContain('incus-agent.service');
    expect(p).toContain('command -v incus-agent');
    expect(p).toContain('incus-agent binary missing');
  });

  it('provision.sh never writes resolver content by hand', () => {
    const p = readFileSync(join(templateDir, 'provision.sh'), 'utf8');
    expect(p).not.toMatch(/^\s*nameserver/m);
    expect(p).toContain('stub-resolv.conf');
    expect(p).toContain('systemd-networkd-wait-online');
  });

  it('provision.sh normalizes payload ownership to root before install (uid-independent)', () => {
    const p = readFileSync(join(templateDir, 'provision.sh'), 'utf8');
    // chown must run on $PAYLOAD BEFORE cp -a installs the guest tree, so a
    // non-root builder uid can never leak into sudoers.d (sudo ignores
    // non-root-owned drop-ins).
    const chownIdx = p.indexOf('chown -R 0:0 "$PAYLOAD"');
    const cpaIdx = p.indexOf('cp -a "$PAYLOAD/guest/." /');
    expect(chownIdx).toBeGreaterThan(-1);
    expect(cpaIdx).toBeGreaterThan(chownIdx);
    // and the sudoers contract is asserted, not assumed
    expect(p).toContain("stat -c '%u:%g' /etc/sudoers.d");
    expect(p).toContain("stat -c '%u:%g' /etc/sudoers.d/harness");
    expect(p).toContain('sudoers drop-in ownership wrong');
  });

  it('provision.sh purges base-image network configs and asserts zero remain', () => {
    const p = readFileSync(join(templateDir, 'provision.sh'), 'utf8');
    for (const frag of [
      '/etc/systemd/network/*.network',
      '/etc/systemd/network/*.netdev',
      '/usr/lib/systemd/network/*.network',
      '/usr/lib/systemd/network/*.netdev',
      '/usr/local/lib/systemd/network/*.network',
      '/usr/local/lib/systemd/network/*.netdev',
      '*.nmconnection',
      '/etc/netplan',
      '/etc/network/interfaces',
    ]) {
      expect(p, `provision.sh missing purge for ${frag}`).toContain(frag);
    }
    // the zero-config invariant runs before inventory; its implementation
    // lives in network-invariant.sh (enumerated dirs, checked find status)
    // and provision.sh must invoke it ahead of inventory.sh
    const ninv = readFileSync(join(templateDir, 'network-invariant.sh'), 'utf8');
    expect(ninv).toContain('base image left network configs behind');
    expect(ninv).toContain('/usr/local/lib/systemd/network');
    const assertIdx = p.indexOf('network-invariant.sh');
    const invIdx = p.indexOf('inventory.sh');
    expect(assertIdx).toBeGreaterThan(-1);
    expect(invIdx).toBeGreaterThan(assertIdx);
    // inventory records the same three persistent dirs
    const inv = readFileSync(join(templateDir, 'inventory.sh'), 'utf8');
    for (const d of ['/etc/systemd/network', '/usr/lib/systemd/network',
                     '/usr/local/lib/systemd/network']) {
      expect(inv, `inventory.sh missing ${d}`).toContain(d);
    }
  });

  it('provision.sh resets hostname/hosts so the base image identity does not leak', () => {
    const p = readFileSync(join(templateDir, 'provision.sh'), 'utf8');
    expect(p).toContain('/etc/hostname');
    expect(p).toContain('cloudharness-vm');
    expect(p).toContain('/etc/hosts');
  });

  it('git-vm.sh helper ships executable and is recorded in guest-files inventory', () => {
    const helper = join(templateDir, 'guest/usr/local/bin/git-vm.sh');
    expect(existsSync(helper)).toBe(true);
    // executable in the repo AND covered by the apply-modes bin rule (0755)
    expect(statSync(helper).mode & 0o111).not.toBe(0);
    const inv = readFileSync(join(templateDir, 'inventory.sh'), 'utf8');
    expect(inv).toContain('/usr/local/bin/git-vm.sh');
    // it is a guest-tree file, not a baked worker file — no worker-manifest entry
    const manifest = readFileSync(join(templateDir, 'worker-manifest.txt'), 'utf8');
    expect(manifest).not.toContain('git-vm');
  });

  it('inventory.sh probes docker buildx via the plugin command', () => {
    const inv = readFileSync(join(templateDir, 'inventory.sh'), 'utf8');
    expect(inv).toContain('probe docker-buildx docker buildx version');
    expect(inv).not.toContain('docker-buildx --version');
  });

  it('inventory.sh records every section and key in the committed spec', () => {
    const inv = readFileSync(join(templateDir, 'inventory.sh'), 'utf8');
    const spec = readFileSync(join(templateDir, 'inventory.txt'), 'utf8');
    let section = '';
    const missing: string[] = [];
    for (const raw of spec.split('\n')) {
      const line = raw.trim();
      if (line.startsWith('## ')) {
        section = line.slice(3).trim();
        if (!inv.includes(`section ${section}`)) missing.push(`section ${section}`);
      } else if (line.startsWith('- ') && section) {
        const key = line.slice(2).trim();
        if (key === 'rows') continue; // tabular sections verified structurally
        if (!inv.includes(key)) missing.push(`${section}/${key}`);
      }
    }
    expect(missing, `inventory.sh missing spec entries: ${missing.join(', ')}`).toEqual([]);
    expect(inv).toContain('incus-agent.service');
    expect(inv).toContain('harness_sudo_nopasswd');
    expect(inv).toContain('template_id=');
  });

  it('no custom PTY daemon or durable env helper anywhere in the template', () => {
    const out = execFileSync('find', [templateDir, '-type', 'f'], { encoding: 'utf8' });
    for (const f of out.trim().split('\n')) {
      expect(f.toLowerCase()).not.toMatch(/pty|quiesce|durable.*env/);
    }
    const files = out.trim().split('\n').filter(Boolean);
    const all = files.map((f) => readFileSync(f, 'utf8')).join('\n');
    expect(all).not.toContain('pty-broker');
  });
});

describe('apply-modes.sh', () => {
  it('normalizes a staged tree to the payload mode contract', () => {
    const root = mkdtempSync(join(tmpdir(), 'vmtpl-modes-'));
    try {
      mkdirSync(join(root, 'opt/harness/bin'), { recursive: true });
      mkdirSync(join(root, 'etc/sudoers.d'), { recursive: true });
      mkdirSync(join(root, 'etc/cloud-harness'), { recursive: true });
      mkdirSync(join(root, 'usr/local/bin'), { recursive: true });
      writeFileSync(join(root, 'opt/harness/worker.mjs'), 'x');
      writeFileSync(join(root, 'opt/harness/package.json'), '{}');
      writeFileSync(join(root, 'opt/harness/bin/npx'), 'x');
      writeFileSync(join(root, 'etc/sudoers.d/harness'), 'x');
      writeFileSync(join(root, 'etc/cloud-harness/network.tmpl'), 'x');
      writeFileSync(join(root, 'usr/local/bin/guest-df.sh'), 'x');
      writeFileSync(join(root, 'usr/local/bin/git-vm.sh'), 'x');
      // deliberately wrong modes
      execFileSync('chmod', ['-R', '0777', root]);

      const r = sh(join(templateDir, 'apply-modes.sh'), [root]);
      expect(r.status, r.stderr).toBe(0);
      expect(statSync(join(root, 'opt/harness/worker.mjs')).mode & 0o777).toBe(0o555);
      expect(statSync(join(root, 'opt/harness/package.json')).mode & 0o777).toBe(0o644);
      expect(statSync(join(root, 'opt/harness/bin/npx')).mode & 0o777).toBe(0o555);
      expect(statSync(join(root, 'etc/sudoers.d/harness')).mode & 0o777).toBe(0o440);
      expect(statSync(join(root, 'etc/cloud-harness/network.tmpl')).mode & 0o777).toBe(0o644);
      expect(statSync(join(root, 'usr/local/bin/guest-df.sh')).mode & 0o777).toBe(0o755);
      expect(statSync(join(root, 'usr/local/bin/git-vm.sh')).mode & 0o777).toBe(0o755);
      expect(statSync(join(root, 'opt/harness')).mode & 0o777).toBe(0o755);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});

describe('guest-df helper', () => {
  it('prints du -sb --apparent-size lines for given paths', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-df-'));
    try {
      const a = join(dir, 'a'); const b = join(dir, 'b');
      mkdirSync(a); mkdirSync(b);
      writeFileSync(join(a, 'f1'), 'x'.repeat(100));
      writeFileSync(join(b, 'f2'), 'y'.repeat(50));
      const r = spawnSync(join(guest, 'usr/local/bin/guest-df.sh'), [a, b], { encoding: 'utf8' });
      expect(r.status, r.stderr).toBe(0);
      const lines = r.stdout.trim().split('\n');
      expect(lines.length).toBe(2);
      for (const line of lines) {
        const [bytes, path] = line.split('\t');
        expect(Number(bytes)).toBeGreaterThan(0);
        expect([a, b]).toContain(path);
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('kill-session helper', () => {
  // Spawn an orphaned session/group leader and return its pid (== pgid).
  // Orphaning matters: the test's spawnSync blocks the event loop, so a
  // direct child would linger as an unreaped zombie and keep its group
  // "alive". Init reaps orphans promptly.
  function spawnGroupLeader(cmd: string) {
    const out = execFileSync('bash', ['-c',
      `setsid bash -c ${JSON.stringify(cmd)} >/dev/null 2>&1 & echo $!`],
      { encoding: 'utf8' }).trim();
    return Number(out);
  }
  function groupAlive(pgid: number) {
    try { process.kill(-pgid, 0); return true; } catch { return false; }
  }

  it('TERM-kills recorded process groups and removes the pid file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-ks-'));
    try {
      const pidfile = join(dir, 'task.pids');
      const g1 = spawnGroupLeader('sleep 300');
      const g2 = spawnGroupLeader('sleep 300');
      await new Promise((r) => setTimeout(r, 150));
      expect(groupAlive(g1)).toBe(true);
      expect(groupAlive(g2)).toBe(true);
      writeFileSync(pidfile, `${g1}\n${g2}\n`);
      const r = spawnSync(join(guest, 'usr/local/bin/kill-session.sh'), [pidfile], { encoding: 'utf8' });
      expect(r.status, r.stderr).toBe(0);
      await new Promise((res) => setTimeout(res, 100));
      expect(groupAlive(g1)).toBe(false);
      expect(groupAlive(g2)).toBe(false);
      expect(existsSync(pidfile)).toBe(false);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 15000);

  it('escalates to KILL for TERM-immune process groups', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-ks-'));
    try {
      const pidfile = join(dir, 'task.pids');
      // bash ignores TERM and loops forever; only KILL can stop the group.
      const g = spawnGroupLeader('trap "" TERM; while true; do sleep 300; done');
      await new Promise((r) => setTimeout(r, 150));
      expect(groupAlive(g)).toBe(true);
      writeFileSync(pidfile, `${g}\n`);
      const r = spawnSync(join(guest, 'usr/local/bin/kill-session.sh'), [pidfile], { encoding: 'utf8' });
      expect(r.status, r.stderr).toBe(0);
      await new Promise((res) => setTimeout(res, 100));
      expect(groupAlive(g)).toBe(false);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 20000);

  it('fails when the pid file never appears', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-ks-'));
    try {
      const r = spawnSync(join(guest, 'usr/local/bin/kill-session.sh'), [join(dir, 'absent.pids')],
        { encoding: 'utf8' });
      expect(r.status).toBe(1);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

// ------------------------------------------- network-invariant.sh -------
describe('network-invariant.sh (behavioral)', () => {
  const inv = join(templateDir, 'network-invariant.sh');

  function fixtureRoot(files: string[], dirs: string[] = []) {
    const root = mkdtempSync(join(tmpdir(), 'vmtpl-ninv-'));
    for (const d of dirs) mkdirSync(join(root, d), { recursive: true });
    for (const f of files) {
      const p = join(root, f);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, 'x');
    }
    return root;
  }

  it('refuses a forbidden config even when optional search dirs are absent', () => {
    // Only etc/systemd/network exists; etc/netplan, usr/lib/..., NM and
    // interfaces.d are all missing — the old find|grep check could never
    // fire here because find exited 1 on the missing operands.
    const root = fixtureRoot(['etc/systemd/network/10-rogue.network']);
    try {
      const r = sh(inv, [root]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('refusing to ship');
      expect(r.stderr).toContain('10-rogue.network');
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it('catches nested leftovers the top-level rm -f glob cannot reach', () => {
    const root = fixtureRoot(['etc/systemd/network/sub/99-stray.netdev']);
    try {
      const r = sh(inv, [root]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('99-stray.netdev');
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it('passes a clean tree with a mix of existing and missing search dirs', () => {
    const root = fixtureRoot(
      ['etc/systemd/network/.keep', 'usr/lib/systemd/network/.keep'],
      ['etc/NetworkManager/system-connections']
    );
    try {
      const r = sh(inv, [root]);
      expect(r.status, r.stderr).toBe(0);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it('passes when every search dir is absent', () => {
    const root = mkdtempSync(join(tmpdir(), 'vmtpl-ninv-'));
    try {
      expect(sh(inv, [root]).status).toBe(0);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it('fails closed when the scan itself errors (stubbed find)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-ninv-bin-'));
    const root = fixtureRoot(['etc/systemd/network/.keep']);
    try {
      const bin = join(dir, 'bin');
      mkdirSync(bin);
      const stub = join(bin, 'find');
      writeFileSync(stub, '#!/usr/bin/env bash\necho "find: simulated I/O error" >&2\nexit 1\n');
      chmodSync(stub, 0o755);
      const r = sh(inv, [root], { env: { PATH: `${bin}:${process.env.PATH}` } });
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('scan failed');
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.runIf(typeof process.getuid !== 'function' || process.getuid() !== 0)(
    'fails closed on an unreadable search dir (real EACCES)', () => {
    const root = fixtureRoot([], ['etc/systemd/network/locked']);
    const locked = join(root, 'etc/systemd/network/locked');
    try {
      chmodSync(locked, 0o000);
      const r = sh(inv, [root]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('scan failed');
    } finally {
      chmodSync(locked, 0o755);
      rmSync(root, { recursive: true, force: true });
    }
  });
});

// ------------------------------------------- inventory.sh behavioral ----
describe('inventory.sh emitted contract (behavioral)', () => {
  const invSh = join(templateDir, 'inventory.sh');
  const spec = readFileSync(join(templateDir, 'inventory.txt'), 'utf8');

  // PATH stubs make the script runnable on a non-Debian dev host AND keep it
  // deterministic: dpkg/apt emit canned rows, systemctl reports a fixed
  // state, find never fails on absent guest paths, and EVERY probed tool
  // gets a distinct fixture version. The controlled PATH (stub bin +
  // /usr/bin + /bin only) excludes host shims — a real `uv`/`node` resolved
  // through mise or /usr/local/bin could auto-install or drift between the
  // two runs and break the byte-identical determinism contract.
  function writeStubs(dir: string) {
    const bin = join(dir, 'bin');
    mkdirSync(bin, { recursive: true });
    const realFind = execFileSync('bash', ['-c', 'command -v find'], { encoding: 'utf8' }).trim();
    const stubs: Record<string, string> = {
      find: `#!/usr/bin/env bash\n"${realFind}" "$@" 2>/dev/null || true\n`,
      dpkg: '#!/bin/sh\n[ "$1" = "--print-architecture" ] && echo amd64\nexit 0\n',
      'dpkg-query': '#!/bin/sh\nprintf "stubpkg\\t1.0\\tamd64\\notherpkg\\t2.0\\tall\\n"\n',
      'apt-mark': '#!/bin/sh\necho stubpkg\necho otherpkg\n',
      systemctl: '#!/bin/sh\n[ "$1" = "is-enabled" ] && { echo enabled; exit 0; }\nexit 0\n',
      // timeout is BOTH the probe() wrapper and a probed tool: delegate the
      // numeric-timeout wrapper role to the real coreutils binary, report a
      // fixture version for --version probes.
      timeout: '#!/usr/bin/env bash\nif [[ "$1" =~ ^[0-9]+$ ]]; then exec /usr/bin/timeout "$@"; fi\necho "fixture-timeout-1.0.0"\n',
    };
    // Every tool inventory.sh probes gets a distinct, fixed version line.
    for (const tool of [
      'node', 'npm', 'npx', 'bun', 'bunx', 'uv', 'uvx', 'pnpm', 'wrangler',
      'gh', 'ak', 'git', 'docker', 'go', 'python3', 'pip3', 'bwrap', 'jq',
      'rg', 'ctags', 'make', 'gcc', 'psql', 'setsid', 'tar', 'unzip',
    ]) {
      stubs[tool] = `#!/bin/sh\necho "fixture-${tool}-1.0.0"\n`;
    }
    for (const [name, body] of Object.entries(stubs)) {
      const p = join(bin, name);
      writeFileSync(p, body);
      chmodSync(p, 0o755);
    }
    return bin;
  }

  function runInventory(bin: string) {
    return spawnSync('bash', [invSh], {
      encoding: 'utf8',
      env: {
        ...process.env,
        // Controlled PATH: fixture stubs first, then ONLY the base system
        // dirs — no host shim dirs (mise, /usr/local, snap, home bins) that
        // could auto-install tools or drift between runs.
        PATH: `${bin}:/usr/bin:/bin`,
        CH_VM_TEMPLATE_ID: 'cloudharness-vm-debian13',
        CH_VM_TEMPLATE_VERSION: '1',
      },
    });
  }

  it('emits every spec section in order with its required keys, deterministically', { timeout: 30000 }, () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-invstub-'));
    try {
      const bin = writeStubs(dir);
      const r1 = runInventory(bin);
      expect(r1.status, r1.stderr).toBe(0);
      const r2 = runInventory(bin);
      expect(r2.status, r2.stderr).toBe(0);
      // the reproducibility contract: identical inputs -> byte-identical output
      expect(r2.stdout).toBe(r1.stdout);

      // Parse the emitted output into ordered sections.
      const outSections: string[] = [];
      const outBlocks = new Map<string, string[]>();
      let cur = '';
      for (const line of r1.stdout.split('\n')) {
        const m = line.match(/^## (.+)$/);
        if (m) { cur = m[1].trim(); outSections.push(cur); outBlocks.set(cur, []); }
        else if (cur) outBlocks.get(cur)!.push(line);
      }

      // Spec order must match emitted order exactly.
      const specSections = spec.split('\n')
        .map((l) => l.trim())
        .filter((l) => l.startsWith('## '))
        .map((l) => l.slice(3));
      expect(outSections).toEqual(specSections);

      // Every scalar spec key must appear in its section's emitted block.
      let section = '';
      const missing: string[] = [];
      for (const raw of spec.split('\n')) {
        const line = raw.trim();
        if (line.startsWith('## ')) { section = line.slice(3).trim(); continue; }
        if (!line.startsWith('- ') || line.slice(2).trim() === 'rows') continue;
        const key = line.slice(2).trim();
        const block = outBlocks.get(section) ?? [];
        const found = block.some((l) => new RegExp(`^${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([=:\\t]|$)`).test(l));
        if (!found) missing.push(`${section}/${key}`);
      }
      expect(missing, `inventory.sh output missing spec keys: ${missing.join(', ')}`).toEqual([]);

      // Rows sections that stubs guarantee non-empty on any host.
      for (const s of ['dpkg', 'apt-mark-manual', 'systemd-units']) {
        const rows = (outBlocks.get(s) ?? []).filter((l) => l.trim() !== '');
        expect(rows.length, `section ${s} emitted no rows`).toBeGreaterThan(0);
      }
      // guest-files legitimately lists zero files on a dev host (no /opt/harness).
      expect(outBlocks.has('guest-files')).toBe(true);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

// --------------------------- network-invariant path classification -----
describe('network-invariant.sh search-path classification (behavioral)', () => {
  const inv = join(templateDir, 'network-invariant.sh');

  function fixtureRoot(files: string[], dirs: string[] = [], links: [string, string][] = []) {
    const root = mkdtempSync(join(tmpdir(), 'vmtpl-ninv-cls-'));
    for (const d of dirs) mkdirSync(join(root, d), { recursive: true });
    for (const f of files) {
      const p = join(root, f);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, 'x');
    }
    for (const [link, target] of links) {
      const p = join(root, link);
      mkdirSync(dirname(p), { recursive: true });
      // targets are fixture-root-relative (made absolute so they resolve
      // regardless of the link's own directory depth)
      symlinkSync(join(root, target), p);
    }
    return root;
  }

  it('rejects a broken symlink at a persistent search path', () => {
    const root = fixtureRoot([], [], [
      ['etc/systemd/network', join('missing-target')],
    ]);
    try {
      const r = sh(inv, [root]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('broken symlink');
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it('rejects a non-directory at a persistent search path', () => {
    const root = fixtureRoot(['etc/netplan'], ['etc/systemd/network']);
    try {
      const r = sh(inv, [root]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('not a directory');
      expect(r.stderr).toContain('etc/netplan');
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it('follows a symlinked search dir and still catches configs inside', () => {
    // usr/lib/systemd/network -> real dir elsewhere in the fixture holding
    // a forbidden file: find -H must follow the STARTING-POINT symlink.
    const root = fixtureRoot(
      ['realdir/10-stray.network'],
      [],
      [['usr/lib/systemd/network', 'realdir']]
    );
    try {
      const r = sh(inv, [root]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('10-stray.network');
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it('rejects an unverifiable path component (ENOTDIR) instead of skipping it', () => {
    // etc/systemd is a regular FILE, so etc/systemd/network cannot exist —
    // but this is NOT a genuine absence: stat reports ENOTDIR and the scan
    // must refuse rather than silently omit the search path.
    const root = fixtureRoot(['etc/systemd'], ['etc']);
    try {
      const r = sh(inv, [root]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('cannot be verified');
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it.runIf(typeof process.getuid !== 'function' || process.getuid() !== 0)(
    'rejects an unverifiable path under an inaccessible parent (EACCES)', () => {
    const root = fixtureRoot([], ['etc/systemd/network']);
    try {
      chmodSync(join(root, 'etc'), 0o000);
      const r = sh(inv, [root]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('cannot be verified');
    } finally {
      chmodSync(join(root, 'etc'), 0o755);
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('still treats genuinely absent optional dirs as skippable', () => {
    // Only usr/lib/systemd/network exists and is clean; every other
    // candidate — including ones whose parents are absent — must be
    // classified ENOENT and skipped, not rejected.
    const root = fixtureRoot([], ['usr/lib/systemd/network']);
    try {
      const r = sh(inv, [root]);
      expect(r.status, r.stderr).toBe(0);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it('pins the stat classification to the C locale — ENOENT matching cannot drift with LANG', () => {
    // The ENOENT-vs-unverifiable split matches stat's English error text;
    // without LC_ALL=C a translated locale would misclassify genuine
    // absences as unverifiable (or vice versa) and fail/open wrongly.
    const src = readFileSync(inv, 'utf8');
    expect(src).toContain('LC_ALL=C stat -c %F');
    // And the classification must still key on stat's message, not -e tests.
    expect(src).toContain('No such file or directory');
  });

  // Controlled-locale regression: a stat stub emits a NON-ENGLISH ENOENT
  // diagnostic unless LC_ALL is C/POSIX (delegating to real stat then).
  // Proves the absent-optional-dir acceptance does not depend on the host
  // locale — no installed locale required. The stub is python3 (not sh):
  // shells emit their own setlocale warning under a bogus LC_ALL, and that
  // warning text itself contains the English "No such file or directory"
  // phrase the script matches on — it would mask the discrimination.
  const python3 = (() => {
    try {
      return execFileSync('bash', ['-c', 'command -v python3'], { encoding: 'utf8' }).trim();
    } catch { return ''; }
  })();
  function writeLocaleStatStub(dir: string) {
    const bin = join(dir, 'bin');
    mkdirSync(bin, { recursive: true });
    const realStat = execFileSync('bash', ['-c', 'command -v stat'], { encoding: 'utf8' }).trim();
    const stub = join(bin, 'stat');
    writeFileSync(stub, `#!${python3}
import os, sys
if os.environ.get('LC_ALL') in ('C', 'POSIX'):
    os.execv('${realStat}', ['stat'] + sys.argv[1:])
sys.stderr.write('stat: Zugriff auf "%s" nicht möglich: Datei oder Verzeichnis nicht gefunden\\n' % (sys.argv[4] if len(sys.argv) > 4 else ''))
sys.exit(1)
`);
    chmodSync(stub, 0o755);
    return bin;
  }

  it.runIf(python3 !== '')('accepts genuinely absent optional dirs under a non-English locale', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-ninv-locale-'));
    // Only usr/lib/systemd/network exists; every other candidate is absent
    // and reaches the stat classification path under LC_ALL=de_DE.UTF-8.
    const root = fixtureRoot([], ['usr/lib/systemd/network']);
    try {
      const bin = writeLocaleStatStub(dir);
      const r = sh(inv, [root], {
        env: { PATH: `${bin}:${process.env.PATH}`, LC_ALL: 'de_DE.UTF-8' },
      });
      expect(r.status, r.stderr).toBe(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.runIf(python3 !== '')('baseline without the LC_ALL=C pin rejects the same fixture (red proof)', () => {
    // Isolated copy of the script with the locale pin stripped — proves the
    // behavioral test discriminates, without reverting shared source.
    const src = readFileSync(inv, 'utf8');
    const baseline = src.replace('LC_ALL=C stat -c %F', 'stat -c %F');
    expect(baseline).not.toBe(src);
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-ninv-locale-base-'));
    const scriptPath = join(dir, 'network-invariant-baseline.sh');
    writeFileSync(scriptPath, baseline);
    const root = fixtureRoot([], ['usr/lib/systemd/network']);
    try {
      const bin = writeLocaleStatStub(dir);
      const r = sh(scriptPath, [root], {
        env: { PATH: `${bin}:${process.env.PATH}`, LC_ALL: 'de_DE.UTF-8' },
      });
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('cannot be verified');
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

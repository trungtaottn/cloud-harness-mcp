import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
    // the zero-config invariant is asserted before inventory runs, across
    // every PERSISTENT networkd search path (/etc, /usr/lib, /usr/local/lib)
    expect(p).toContain('base image left network configs behind');
    expect(p).toContain('/usr/local/lib/systemd/network');
    const assertIdx = p.indexOf('base image left network configs behind');
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

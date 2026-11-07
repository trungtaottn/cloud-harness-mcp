import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

const repo = process.cwd();
const script = join(repo, 'scripts/vm-template-build.sh');
const templateDir = join(repo, 'deploy/vm-template');

function run(args: string[], opts: { env?: NodeJS.ProcessEnv; cwd?: string } = {}) {
  return spawnSync('bash', [script, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...opts.env },
    cwd: opts.cwd ?? repo,
  });
}

function sha256File(path: string) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

describe('vm-template-build.sh check', () => {
  it('passes the full offline static gate', () => {
    const r = run(['check']);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stderr).toContain('check passed');
  });
});

describe('vm-template-build.sh stage', () => {
  it('assembles a deterministic payload and manifest', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-stage-'));
    try {
      const r1 = run(['stage', '--out', dir]);
      expect(r1.status, r1.stderr).toBe(0);
      const payload = join(dir, 'vm-template-payload');
      expect(existsSync(join(payload, 'guest/opt/harness/harness-worker.mjs'))).toBe(true);
      expect(existsSync(join(payload, 'guest/usr/local/bin/git-vm.sh'))).toBe(true);
      expect(existsSync(join(payload, 'provision.sh'))).toBe(true);
      expect(existsSync(join(payload, 'inventory.sh'))).toBe(true);
      expect(existsSync(join(payload, 'tool-pins.sh'))).toBe(true);
      expect(existsSync(join(dir, 'manifest.txt'))).toBe(true);

      // second stage into a sibling dir must produce an identical manifest
      const dir2 = mkdtempSync(join(tmpdir(), 'vmtpl-stage2-'));
      try {
        expect(run(['stage', '--out', dir2]).status).toBe(0);
        expect(readFileSync(join(dir2, 'manifest.txt'), 'utf8'))
          .toBe(readFileSync(join(dir, 'manifest.txt'), 'utf8'));
      } finally { rmSync(dir2, { recursive: true, force: true }); }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('manifest covers every payload file exactly once with sha256+mode', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-stage-'));
    try {
      expect(run(['stage', '--out', dir]).status).toBe(0);
      const payload = join(dir, 'vm-template-payload');
      const manifest = readFileSync(join(dir, 'manifest.txt'), 'utf8').trim().split('\n');
      const entries = manifest.filter((l) => !l.startsWith('#'));
      const files: string[] = [];
      const walk = (d: string) => {
        for (const e of execFileSync('find', [d, '-type', 'f'], { encoding: 'utf8' }).trim().split('\n')) {
          files.push(e.slice(payload.length + 1));
        }
      };
      walk(payload);
      expect(entries.length).toBe(files.length);
      const listed = new Set(entries.map((l) => l.split('\t')[2]));
      for (const f of files) expect(listed.has(f), `manifest missing ${f}`).toBe(true);
      // spot-check a digest matches the staged file
      const line = entries.find((l) => l.endsWith('\tguest/opt/harness/package.json'))!;
      const [sha, mode] = line.split('\t');
      expect(sha).toBe(sha256File(join(payload, 'guest/opt/harness/package.json')));
      expect(mode).toBe('644');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('vm-template-build.sh render-network', () => {
  const base = ['render-network', '--match-mac', '00:16:3e:71:00:02',
    '--address', '10.203.71.2/30', '--gateway', '10.203.71.1'];

  it('renders a complete static .network fragment', () => {
    const r = run([...base, '--dns', '1.1.1.1 8.8.8.8']);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('MACAddress=00:16:3e:71:00:02');
    expect(r.stdout).toContain('Address=10.203.71.2/30');
    expect(r.stdout).toContain('Gateway=10.203.71.1');
    expect(r.stdout).toContain('DNS=1.1.1.1 8.8.8.8');
    expect(r.stdout).toContain('DHCP=no');
    expect(r.stdout).not.toContain('{{');
  });

  it('normalizes comma-separated DNS to space-separated', () => {
    const r = run([...base, '--dns', '1.1.1.1,8.8.8.8']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('DNS=1.1.1.1 8.8.8.8');
  });

  it.each([
    ['bad mac', [...base.slice(0, 2), 'zz:16:3e:71:00:02', ...base.slice(4), '--dns', '1.1.1.1']],
    ['bad cidr prefix', ['render-network', '--match-mac', '00:16:3e:71:00:02', '--address', '10.0.0.2/33', '--gateway', '10.0.0.1', '--dns', '1.1.1.1']],
    ['octet overflow', ['render-network', '--match-mac', '00:16:3e:71:00:02', '--address', '10.0.0.999/30', '--gateway', '10.0.0.1', '--dns', '1.1.1.1']],
    ['section injection', ['render-network', '--match-mac', '00:16:3e:71:00:02\n[DHCP]', '--address', '10.0.0.2/30', '--gateway', '10.0.0.1', '--dns', '1.1.1.1']],
    ['bad dns', [...base, '--dns', 'not-an-ip']],
    ['empty dns', [...base, '--dns', '']],
  ])('rejects %s', (_name, args) => {
    expect(run(args as string[]).status).not.toBe(0);
  });
});

describe('vm-template-build.sh diff-inventory', () => {
  it('reports identical and differing inventories', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-inv-'));
    try {
      const a = join(dir, 'a.txt'); const b = join(dir, 'b.txt');
      writeFileSync(a, 'line1\nline2\n');
      writeFileSync(b, 'line1\nline2\n');
      expect(run(['diff-inventory', a, b]).status).toBe(0);
      writeFileSync(b, 'line1\nlineX\n');
      expect(run(['diff-inventory', a, b]).status).not.toBe(0);
      expect(run(['diff-inventory', a, join(dir, 'missing')]).status).not.toBe(0);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('vm-template-build.sh scan-secrets', () => {
  it('is clean on the real template tree', () => {
    expect(run(['scan-secrets', templateDir]).status).toBe(0);
  });

  it('flags private keys, tokens, and secret filenames', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-sec-'));
    try {
      writeFileSync(join(dir, 'ok.txt'), 'nothing here\n');
      expect(run(['scan-secrets', dir]).status).toBe(0);

      writeFileSync(join(dir, 'key.pem'), '-----BEGIN RSA PRIVATE KEY-----\nAAAA\n');
      expect(run(['scan-secrets', dir]).status).not.toBe(0);
      rmSync(join(dir, 'key.pem'));

      writeFileSync(join(dir, 'leak.txt'), 'token ghp_abcdefghijklmnopqrstuvwxyz123456\n');
      expect(run(['scan-secrets', dir]).status).not.toBe(0);
      rmSync(join(dir, 'leak.txt'));

      writeFileSync(join(dir, 'id_rsa'), 'not really a key');
      expect(run(['scan-secrets', dir]).status).not.toBe(0);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

// ------------------------------------------------------------ fake incus ----
// The fake mirrors the DOCUMENTED incus grammar: `file push|pull` take
// [<remote>:]<instance>/<path> (instance and path separated by '/', never
// ':'), instance config is readable via `config show`, and launch records
// the -c user.cloud-harness.build-token=... value the build uses as its
// ownership proof. Env knobs:
//   FAKE_INCUS_FAIL=launch|provision|publish   fail that step
//   FAKE_INCUS_PARTIAL=1                       launch creates instance+token then fails
//   FAKE_INCUS_FOREIGN_TOKEN=1                 instance config shows a foreign token
//   FAKE_INCUS_DECOY=1                         token string appears only under an
//                                              unrelated config key (substring trap)
//   FAKE_INCUS_ALIAS_EXISTS=1                  publish alias already taken
//   FAKE_INCUS_CONFIG_FAIL=1                   config show always errors
//   FAKE_INCUS_ALIAS_NAME=<name>               publish alias (default cloudharness-vm-debian13)
function writeFakeIncus(dir: string) {
  const bin = join(dir, 'bin');
  const state = join(dir, 'state');
  mkdirSync(bin, { recursive: true });
  mkdirSync(state, { recursive: true });
  const incus = join(bin, 'incus');
  writeFileSync(incus, `#!/usr/bin/env bash
set -uo pipefail
echo "incus $*" >> "$FAKE_INCUS_LOG"
if [[ "\${1:-}" == "--project" ]]; then shift 2; fi
cmd="\${1:-}"; shift || true
state="$FAKE_INCUS_STATE"
fp="$(printf 'a%.0s' {1..64})"
basefp="$(printf 'b%.0s' {1..64})"
fail="\${FAKE_INCUS_FAIL:-}"
# Documented grammar: <instance>/<path> — split on the FIRST '/'.
split_target() { # split_target <instance/path> -> sets _inst _remote
  _inst="\${1%%/*}"; _remote="/\${1#*/}"
}
case "$cmd" in
  launch)
    vm="\${!#}"
    token=""
    prev=""
    for a in "$@"; do
      [[ "$prev" == "-c" && "$a" == user.cloud-harness.build-token=* ]] && token="\${a#*=}"
      prev="$a"
    done
    [[ "$fail" == "launch" && "\${FAKE_INCUS_PARTIAL:-}" != "1" ]] && { echo "launch failed" >&2; exit 1; }
    mkdir -p "$state/$vm/root"
    if [[ "\${FAKE_INCUS_FOREIGN_TOKEN:-}" == "1" ]]; then token="foreign-token-not-ours"; fi
    printf '%s' "$token" > "$state/$vm/token"
    [[ "$fail" == "launch" ]] && { echo "launch failed after create" >&2; exit 1; }
    echo "launched"
    ;;
  config)
    sub="\${1:-}"
    if [[ "$sub" == "show" ]]; then
      vm="\${2:-}"
      [[ "\${FAKE_INCUS_CONFIG_FAIL:-}" == "1" ]] && { echo "no such instance" >&2; exit 1; }
      [[ -f "$state/$vm/token" ]] || { echo "no such instance" >&2; exit 1; }
      tok="$(cat "$state/$vm/token")"
      if [[ "\${FAKE_INCUS_DECOY:-}" == "1" ]]; then
        # Deceptive output: our token string appears, but only inside an
        # UNRELATED key's free text — the real key is absent/foreign.
        printf 'config:\\n  user.cloud-harness.note: "token was %s"\\n  limits.cpu: "4"\\n' "$tok"
      else
        printf 'config:\\n  user.cloud-harness.build-token: "%s"\\n  limits.cpu: "4"\\n' "$tok"
      fi
      exit 0
    fi
    exit 1
    ;;
  exec)
    vm="$1"; shift
    [[ "\${1:-}" == "--" ]] && shift
    if [[ "$*" == *provision.sh* ]]; then
      [[ "$fail" == "provision" ]] && { echo "provision boom" >&2; exit 1; }
      cat > "$state/$vm/root/vm-template-inventory.txt" <<'INV'
## template
template_id=cloudharness-vm-debian13
template_version=1
## tools
node	v24.11.0
INV
      exit 0
    fi
    if [[ "\${1:-}" == "tar" && "\${2:-}" == "-xf" ]]; then
      tarfile="\${3#/root/}"
      tar -xf "$state/$vm/root/$tarfile" -C "$state/$vm/root/"
      exit $?
    fi
    exit 0
    ;;
  file)
    sub="\${1:-}"; shift || true
    if [[ "$sub" == "push" ]]; then
      src="\${@: -2:1}"; dst="\${@: -1}"
      split_target "$dst"; vm="$_inst"; remote="$_remote"
      mkdir -p "$state/$vm$(dirname "$remote")"
      cp "$src" "$state/$vm$remote"
      exit 0
    elif [[ "$sub" == "pull" ]]; then
      src="\${1}"; dst="\${2:-}"
      split_target "$src"; vm="$_inst"; remote="$_remote"
      cp "$state/$vm$remote" "$dst"
      exit 0
    fi
    exit 1
    ;;
  stop) exit 0 ;;
  publish)
    [[ "$fail" == "publish" ]] && { echo "publish boom" >&2; exit 1; }
    echo "Instance published as image: $fp"
    echo "$fp" > "$state/published.fp"
    ;;
  image)
    sub="\${1:-}"
    if [[ "$sub" == "info" ]]; then
      target="\${2:-}"
      alias_name="\${FAKE_INCUS_ALIAS_NAME:-cloudharness-vm-debian13}"
      if [[ "$target" == "$alias_name" ]]; then
        # the publish alias — exists only after publish or when forced
        if [[ -f "$state/published.fp" || "\${FAKE_INCUS_ALIAS_EXISTS:-}" == "1" ]]; then
          echo "Fingerprint: $(cat "$state/published.fp" 2>/dev/null || echo "$basefp")"
        else
          echo "image not found" >&2; exit 1
        fi
      else
        # any other ref (remote alias, fingerprint, colonless alias) resolves
        echo "Fingerprint: $basefp"
      fi
    fi
    ;;
  delete) vm="\${1:-}"; rm -rf "$state/$vm"; exit 0 ;;
  *) exit 0 ;;
esac
`);
  chmodSync(incus, 0o755);
  return { bin, state };
}

// Fake incus plus a python3 stub that always fails — used to prove the
// static check gate runs (and aborts the build) before any incus call.
function writeFakeIncusWithBrokenPython(dir: string) {
  const { bin, state } = writeFakeIncus(dir);
  const py = join(bin, 'python3');
  writeFileSync(py, '#!/usr/bin/env bash\nexit 1\n');
  chmodSync(py, 0o755);
  return { bin, state };
}

describe('vm-template-build.sh build (fake incus)', () => {
  function setup() {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-build-'));
    const { bin, state } = writeFakeIncus(dir);
    const out = join(dir, 'out');
    const logFile = join(dir, 'incus.log');
    writeFileSync(logFile, '');
    const env = {
      PATH: `${bin}:${process.env.PATH}`,
      FAKE_INCUS_LOG: logFile,
      FAKE_INCUS_STATE: state,
      VM_TEMPLATE_AGENT_WAIT_SECONDS: '10',
    };
    return { dir, out, logFile, env, state };
  }

  it('runs the full orchestration and writes a manifest', () => {
    const { dir, out, logFile, env, state } = setup();
    try {
      const r = run(['build', '--output', out], { env });
      expect(r.status, r.stderr).toBe(0);
      const log = readFileSync(logFile, 'utf8');
      const order = ['launch', 'exec', 'file push', 'exec', 'file pull', 'stop', 'publish', 'delete'];
      let pos = -1;
      for (const step of order) {
        const idx = log.indexOf(step, pos + 1);
        expect(idx, `missing or out-of-order step: ${step}\n${log}`).toBeGreaterThan(pos);
        pos = idx;
      }
      const manifest = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
      expect(manifest.templateId).toBe('cloudharness-vm-debian13');
      expect(manifest.templateVersion).toBe('1');
      expect(manifest.alias).toBe('cloudharness-vm-debian13');
      expect(manifest.imageFingerprint).toMatch(/^[0-9a-f]{64}$/);
      const invSha = sha256File(join(out, 'inventory.txt'));
      expect(manifest.templateDigest).toBe(invSha);
      expect(manifest.inventorySha256).toBe(invSha);
      expect(existsSync(join(out, 'provision.log'))).toBe(true);
      expect(existsSync(join(out, 'payload-manifest.txt'))).toBe(true);
      expect(existsSync(join(state, 'published.fp'))).toBe(true);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('uses the documented <instance>/<path> file grammar and root disk device', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out], { env });
      expect(r.status, r.stderr).toBe(0);
      const log = readFileSync(logFile, 'utf8');
      // push target: <vm>/root/vm-template-payload.tar — '/' separator, no ':'
      expect(log).toMatch(/file push -p \S+ chm-vm-template-\S+\/root\/vm-template-payload\.tar/);
      // pull source: <vm>/root/vm-template-inventory.txt
      expect(log).toMatch(/file pull chm-vm-template-\S+\/root\/vm-template-inventory\.txt \S+/);
      // no colon-separated instance:path anywhere in file commands
      for (const line of log.split('\n').filter((l) => l.includes('file '))) {
        expect(line).not.toMatch(/:\/root\//);
        expect(line).not.toMatch(/file (push|pull).*:[/]/);
      }
      // disk sized via --device root,size=..., not limits.disk
      expect(log).toMatch(/launch .*--device root,size=20GiB/);
      expect(log).not.toContain('limits.disk=');
      // ownership token planted at launch for verify-then-delete cleanup
      expect(log).toMatch(/launch .*user\.cloud-harness\.build-token=chm-build-/);
      // cleanup verified ownership via config show before deleting
      const cfgIdx = log.indexOf('config show');
      const delIdx = log.indexOf('delete');
      expect(cfgIdx).toBeGreaterThan(-1);
      expect(delIdx).toBeGreaterThan(cfgIdx);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('warns that the rolling base alias is unpinned, and accepts a matching pin', () => {
    const { dir, out, env } = setup();
    try {
      const r = run(['build', '--output', out], { env });
      expect(r.status, r.stderr).toBe(0);
      expect(r.stderr).toContain('mutable');
      const manifest = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
      expect(manifest.baseImageFingerprint).toBe('b'.repeat(64));
      expect(manifest.baseImage).toBe('images:debian/13');

      // matching pin passes the pre-launch gate
      const dir2 = mkdtempSync(join(tmpdir(), 'vmtpl-pin-'));
      try {
        const s2 = writeFakeIncus(dir2);
        const log2 = join(dir2, 'incus.log');
        writeFileSync(log2, '');
        const r2 = run(['build', '--output', join(dir2, 'out'),
          '--expect-base-fingerprint', 'b'.repeat(64)],
          { env: { PATH: `${s2.bin}:${process.env.PATH}`, FAKE_INCUS_LOG: log2,
                   FAKE_INCUS_STATE: s2.state, VM_TEMPLATE_AGENT_WAIT_SECONDS: '10' } });
        expect(r2.status, r2.stderr).toBe(0);
      } finally { rmSync(dir2, { recursive: true, force: true }); }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('refuses to launch when the base fingerprint pin does not match', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out,
        '--expect-base-fingerprint', 'c'.repeat(64)], { env });
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain('fingerprint drift');
      // died BEFORE any live incus mutation — only image info probes allowed
      const log = readFileSync(logFile, 'utf8');
      expect(log).not.toContain('launch');
      expect(log).not.toContain('file push');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('refuses to overwrite an existing publish alias without --replace-alias', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out],
        { env: { ...env, FAKE_INCUS_ALIAS_EXISTS: '1' } });
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain('already exists');
      expect(readFileSync(logFile, 'utf8')).not.toContain('launch');

      // explicit opt-in proceeds and publishes with --reuse
      const r2 = run(['build', '--output', join(dir, 'out2'), '--replace-alias'],
        { env: { ...env, FAKE_INCUS_ALIAS_EXISTS: '1' } });
      expect(r2.status, r2.stderr).toBe(0);
      expect(readFileSync(logFile, 'utf8')).toMatch(/publish \S+ --alias \S+ --reuse/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('launch failure with no instance cleans up nothing and deletes nothing', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out],
        { env: { ...env, FAKE_INCUS_FAIL: 'launch' } });
      expect(r.status).not.toBe(0);
      const log = readFileSync(logFile, 'utf8');
      expect(log).toContain('config show');   // ownership probe ran
      expect(log).not.toContain('delete');    // nothing verified -> nothing deleted
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('partial launch (instance created, launch reported failure) is deleted only via token', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out],
        { env: { ...env, FAKE_INCUS_FAIL: 'launch', FAKE_INCUS_PARTIAL: '1' } });
      expect(r.status).not.toBe(0);
      const log = readFileSync(logFile, 'utf8');
      // instance carried OUR token -> verify-then-delete removes it
      expect(log).toContain('config show');
      expect(log.split('\n').some((l) => l.startsWith('incus delete'))).toBe(true);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('retains and reports an instance whose config lacks our build token', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out],
        { env: { ...env, FAKE_INCUS_FAIL: 'provision', FAKE_INCUS_FOREIGN_TOKEN: '1' } });
      expect(r.status).not.toBe(0);
      const log = readFileSync(logFile, 'utf8');
      expect(log).toContain('config show');
      expect(log).not.toContain('incus delete');
      expect(r.stderr).toContain('retaining');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('retains when config show is unreadable (never deletes on doubt)', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out],
        { env: { ...env, FAKE_INCUS_FAIL: 'provision', FAKE_INCUS_CONFIG_FAIL: '1' } });
      expect(r.status).not.toBe(0);
      const log = readFileSync(logFile, 'utf8');
      expect(log).toContain('config show');
      expect(log).not.toContain('incus delete');
      expect(r.stderr).toContain('could not read config');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('does not delete when the token appears only in unrelated config text', () => {
    const { dir, out, logFile, env } = setup();
    try {
      // DECOY: our token string is present in config output but under
      // user.cloud-harness.note — substring matching would wrongly delete.
      const r = run(['build', '--output', out],
        { env: { ...env, FAKE_INCUS_FAIL: 'provision', FAKE_INCUS_DECOY: '1' } });
      expect(r.status).not.toBe(0);
      const log = readFileSync(logFile, 'utf8');
      expect(log).toContain('config show');
      expect(log).not.toContain('incus delete');
      expect(r.stderr).toContain('retaining');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('scopes every incus call through --project when VM_TEMPLATE_PROJECT is set', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out],
        { env: { ...env, VM_TEMPLATE_PROJECT: 'foo' } });
      expect(r.status, r.stderr).toBe(0);
      // every logged line is an incus invocation — all must be project-scoped
      const lines = readFileSync(logFile, 'utf8').split('\n').filter(Boolean);
      expect(lines.length).toBeGreaterThan(0);
      for (const l of lines) {
        expect(l, `unscoped incus call: ${l}`).toMatch(/^incus --project foo /);
      }
      // and the mutating verbs specifically went through the project
      expect(lines.some((l) => l.includes(' launch '))).toBe(true);
      expect(lines.some((l) => l.includes(' config show '))).toBe(true);
      expect(lines.some((l) => l.includes(' delete '))).toBe(true);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('warns about mutable base refs even without a colon (colonless alias)', () => {
    const { dir, out, env } = setup();
    try {
      const r = run(['build', '--output', out, '--base-image', 'myalias'], { env });
      expect(r.status, r.stderr).toBe(0);
      expect(r.stderr).toContain('mutable');
      const manifest = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
      expect(manifest.baseImage).toBe('myalias');
      expect(manifest.baseImageFingerprint).toBe('b'.repeat(64));
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('removes build residue with exact paths after inventory pull, before publish', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out], { env });
      expect(r.status, r.stderr).toBe(0);
      const log = readFileSync(logFile, 'utf8');
      const pullIdx = log.indexOf('file pull');
      const rmIdx = log.indexOf('rm -rf /root/vm-template-payload /root/vm-template-payload.tar');
      const stopIdx = log.indexOf('stop', pullIdx);
      const pubIdx = log.indexOf('publish');
      expect(rmIdx).toBeGreaterThan(pullIdx);
      expect(rmIdx).toBeLessThan(stopIdx);
      expect(rmIdx).toBeLessThan(pubIdx);
      // the rm line must not touch the retained provenance inventory
      const rmLine = log.split('\n').find((l) => l.includes('rm -rf /root/'))!;
      expect(rmLine).not.toContain('vm-template-inventory');
      // exact literal paths only — no globs or variables
      expect(rmLine).toContain('/root/vm-template-payload /root/vm-template-payload.tar');
      expect(rmLine).not.toMatch(/\*|\$/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('fails closed if unique build identity suffixes cannot be generated', () => {
    // static contract: suffixes are regex-validated and die on mismatch —
    // no silent empty/degenerate name or token can reach launch.
    const src = readFileSync(script, 'utf8');
    expect(src).toContain('^[0-9a-f]{8}$');
    expect(src).toContain('^[0-9a-f]{16}$');
    expect(src).toContain('failed to generate unique build identity');
  });

  it('static check failure prevents any incus launch', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-preflight-'));
    const { bin, state } = writeFakeIncusWithBrokenPython(dir);
    try {
      const logFile = join(dir, 'incus.log');
      writeFileSync(logFile, '');
      const r = run(['build', '--output', join(dir, 'out')], {
        env: { PATH: `${bin}:${process.env.PATH}`, FAKE_INCUS_LOG: logFile,
               FAKE_INCUS_STATE: state, VM_TEMPLATE_AGENT_WAIT_SECONDS: '10' },
      });
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/check failed|refusing to launch/);
      expect(readFileSync(logFile, 'utf8')).toBe(''); // zero incus invocations
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('deletes the build VM and skips publish when provision fails', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out], { env: { ...env, FAKE_INCUS_FAIL: 'provision' } });
      expect(r.status).not.toBe(0);
      const log = readFileSync(logFile, 'utf8');
      expect(log).toContain('delete');
      expect(log).not.toContain('publish');
      expect(existsSync(join(out, 'manifest.json'))).toBe(false);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('deletes the build VM when publish fails', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out], { env: { ...env, FAKE_INCUS_FAIL: 'publish' } });
      expect(r.status).not.toBe(0);
      const log = readFileSync(logFile, 'utf8');
      expect(log).toContain('delete');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('keeps the build VM with --keep-vm on failure', () => {
    const { dir, out, logFile, env } = setup();
    try {
      const r = run(['build', '--output', out, '--keep-vm'],
        { env: { ...env, FAKE_INCUS_FAIL: 'provision' } });
      expect(r.status).not.toBe(0);
      expect(readFileSync(logFile, 'utf8')).not.toContain('delete');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('fails cleanly when incus is absent from PATH', () => {
    // incus IS installed on some dev hosts, so build a minimal PATH that
    // contains the tools the script needs but no incus client.
    const dir = mkdtempSync(join(tmpdir(), 'vmtpl-noincus-'));
    try {
      const bin = join(dir, 'bin');
      mkdirSync(bin);
      for (const tool of ['bash', 'dirname', 'sed', 'grep', 'cat', 'cp', 'mkdir',
        'rm', 'find', 'sort', 'sha256sum', 'stat', 'cut', 'tr', 'awk', 'date',
        'tar', 'python3', 'diff', 'sleep', 'head', 'tail', 'xargs', 'uniq', 'wc',
        'chmod', 'ln', 'mv', 'basename', 'mktemp', 'env', 'tee', 'timeout', 'uname',
        'cmp', 'od', 'printf', 'echo']) {
        const src = execFileSync('which', [tool], { encoding: 'utf8' }).trim();
        if (src) spawnSync('ln', ['-sf', src, join(bin, tool)]);
      }
      const r = run(['build', '--output', join(dir, 'out')], { env: { PATH: bin } });
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain('incus client not found');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

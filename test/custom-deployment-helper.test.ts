import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

function python(body: string): void {
  const result = spawnSync('python3', ['-c', `import runpy\nscope = runpy.run_path('custom/recreate-hotfix/deploy.py')\n${body}`], { encoding: 'utf8' });
  expect(result.status, result.stderr).toBe(0);
}

describe('custom deployment dependency configuration', () => {
  it('adds defaults and required hosts while preserving the executor and existing opt-ins', () => {
    python(String.raw`
runtime, proxy = scope['dependency_configuration']('AUTH_MODE="cloudflare-access"\nEXECUTOR_IMAGE=custom-executor\nUNRELATED_SETTING=keep\n', 'PACKAGES_PROXY_HOSTS=pypi.org,files.pythonhosted.org\n')
assert 'EXECUTOR_IMAGE=custom-executor\n' in runtime
assert 'UNRELATED_SETTING=keep\n' in runtime
assert 'DEPENDENCIES_ENABLED=true\n' in runtime
assert 'DEPENDENCIES_TIMEOUT_MS=900000\n' in runtime
assert 'DEPENDENCIES_MAX_BYTES=2147483648\n' in runtime
assert 'MAX_WORKSPACE_BYTES=10737418240\n' in runtime
hosts = set(scope['setting_value'](proxy, 'PACKAGES_PROXY_HOSTS').split(','))
assert hosts == scope['DEPENDENCY_HOSTS'] | {'pypi.org', 'files.pythonhosted.org'}
`);
  });
  it('opts only new workspaces into VM execution without replacing the selected executor image', () => {
    python(String.raw`
runtime, _ = scope['dependency_configuration']('AUTH_MODE=cloudflare-access\nEXECUTOR_IMAGE=custom-executor\n', '', vm=True)
assert 'EXECUTOR_IMAGE=custom-executor\n' in runtime
assert 'EXECUTOR_KIND=kata\n' in runtime
assert 'VM_MEMORY_MIB=4096\n' in runtime
assert 'VM_CPUS=2\n' in runtime
assert 'WORKSPACE_NETWORK_PROFILE=dependency-access\n' in runtime
`);
  });
  it('preserves configured limits and rejects conflicting or unsafe inputs', () => {
    python(String.raw`
configure = scope['dependency_configuration']
runtime, _ = configure('AUTH_MODE=cloudflare-access\nDEPENDENCIES_TIMEOUT_MS=10000\nDEPENDENCIES_MAX_BYTES=1048576\n', '')
assert 'DEPENDENCIES_TIMEOUT_MS=10000\n' in runtime
assert 'DEPENDENCIES_MAX_BYTES=1048576\n' in runtime
for runtime, proxy in [
    ('AUTH_MODE=owner-bearer\n', ''),
    ('AUTH_MODE=cloudflare-access\nAUTH_MODE=owner-bearer\n', ''),
    ('AUTH_MODE=cloudflare-access\nDEPENDENCIES_MAX_BYTES=1\n', ''),
    ('AUTH_MODE=cloudflare-access\nDEPENDENCIES_TIMEOUT_MS=1800001\n', ''),
    ('AUTH_MODE=cloudflare-access\n', 'PACKAGES_PROXY_HOSTS=*.example.com\n'),
    ('AUTH_MODE=cloudflare-access\n', 'PACKAGES_PROXY_HOSTS=127.0.0.1\n'),
]:
    try:
        configure(runtime, proxy)
    except RuntimeError:
        pass
    else:
        raise AssertionError('invalid configuration accepted')
`);
  });
  it.each(['present', 'absent', 'legacy'])('restores proxy configuration and metadata for a %s prior configuration', mode => {
    python(String.raw`
import json
import tempfile
from pathlib import Path
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    backup = root / 'backup'
    backup.mkdir()
    runtime, proxy, marker = root / 'runtime', root / 'proxy', root / 'marker'
    runtime.write_text('new runtime')
    proxy.write_text('new proxy')
    (backup / 'runtime.env').write_text('old runtime')
    (backup / 'provisioning-proxy.env').write_text('old proxy')
    proxy_metadata = root / 'proxy-metadata'
    proxy_metadata.write_text('new metadata')
    (backup / 'release-config-provisioning-proxy.env').write_text('old metadata')
    saved = {'backup': str(backup), 'images': {'api': 'old-api', 'runner': 'old-runner'}, 'metadata': []}
    mode = '${mode}'
    if mode != 'legacy':
        saved['proxy_existed'] = mode == 'present'
        saved['managed_metadata'] = ['release-config-provisioning-proxy.env']
        if mode == 'present':
            saved['metadata'] = ['release-config-provisioning-proxy.env']
    marker.write_text(json.dumps(saved))
    calls = []
    globals = scope['rollback'].__globals__
    globals.update(STATE=root, CONFIG=runtime, PROXY_CONFIG=proxy, MARKER=marker,
                   RELEASE_METADATA={'release-config-provisioning-proxy.env': proxy_metadata},
                   run=lambda *args, **kwargs: calls.append(args), ready=lambda: None)
    scope['rollback'](acquire_lock=False)
    assert runtime.read_text() == 'old runtime'
    assert not marker.exists()
    if mode == 'present':
        assert proxy.read_text() == 'old proxy'
        assert proxy_metadata.read_text() == 'old metadata'
    elif mode == 'absent':
        assert not proxy.exists()
        assert not proxy_metadata.exists()
    else:
        assert proxy.read_text() == 'new proxy'
        assert proxy_metadata.read_text() == 'new metadata'
    assert not any('executor' in str(call) for call in calls)
`);
  });
});


describe('persistent VM service compatibility guard', () => {
  it('parses quoted configuration and forwards the configured network without unrelated credentials', () => {
    python(String.raw`
import runpy
import tempfile
from pathlib import Path
from types import SimpleNamespace
vm = runpy.run_path('custom/guard-vm-runner.py')
with tempfile.TemporaryDirectory() as directory:
    config = Path(directory) / 'fixture.conf'
    config.write_text('export EXECUTOR_KIND = "kata"\nDEPENDENCY_NETWORK_NAME=private-dev\nDEPENDENCY_BRIDGE_INTERFACE=dev-egress0\nDEPENDENCY_BRIDGE_SUBNET=172.29.230.0/24\nDEPENDENCY_DNS_RESOLVERS="9.9.9.9,1.1.1.1"\nUNRELATED_SECRET=must-not-forward\n')
    settings = vm['read_settings'](config)
    assert settings['EXECUTOR_KIND'] == 'kata'
    assert 'UNRELATED_SECRET' not in settings
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(stdout='1' if args[:3] == ['docker', 'image', 'inspect'] else '')
    vm['guard'].__globals__['subprocess'] = SimpleNamespace(run=run)
    vm['guard'].__globals__['os'] = SimpleNamespace(access=lambda *_: True, X_OK=1, environ={})
    vm['guard'](settings)
    env = calls[-1][1]['env']
    assert env == {key: value for key, value in settings.items() if key.startswith('DEPENDENCY_')}
    assert env['DEPENDENCY_BRIDGE_INTERFACE'] == 'dev-egress0'
`);
  });
  it.each(['running-vm', 'stopped-vm'])('blocks an unaware runner while retaining %s', name => {
    const directory = mkdtempSync(join(tmpdir(), 'ch-vm-guard-'));
    try {
      writeFileSync(join(directory, 'docker'), '#!/bin/sh\nif [ "$1" = ps ]; then echo "$VM_TEST_NAME"; else echo "$VM_TEST_AWARE"; fi\n', { mode: 0o755 });
      for (const aware of ['', '<no value>', '0', '1']) {
        const result = spawnSync('python3', ['-c', "import runpy; runpy.run_path('custom/guard-vm-runner.py')['guard']({}, check_only=True)"], {
          env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, VM_TEST_NAME: name, VM_TEST_AWARE: aware }, encoding: 'utf8'
        });
        expect(result.status, result.stderr).toBe(aware === '1' ? 0 : 1);
      }
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
});

it('blocks InstaBox downgrades from config and read-only retained state, tolerating legacy schemas', () => {
  python(String.raw`
import runpy, sqlite3, tempfile
from pathlib import Path
from types import SimpleNamespace
vm = runpy.run_path('custom/guard-vm-runner.py')
with tempfile.TemporaryDirectory() as directory:
    database = Path(directory) / 'state.db'
    assert not vm['retained_instabox'](database)
    assert not database.exists()
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE workspaces (id TEXT)')
    assert not vm['retained_instabox'](database)
    with sqlite3.connect(database) as db:
        db.execute('ALTER TABLE workspaces ADD COLUMN executor_kind TEXT')
        db.execute("INSERT INTO workspaces VALUES ('fixture', 'instabox')")
    assert vm['retained_instabox'](database)
    with sqlite3.connect(database) as db:
        db.execute('DELETE FROM workspaces')
        db.execute('CREATE TABLE executor_allocations (released INTEGER)')
        db.execute('INSERT INTO executor_allocations VALUES (1)')
    assert not vm['retained_instabox'](database)
    with sqlite3.connect(database) as db:
        db.execute('INSERT INTO executor_allocations VALUES (0)')
    assert vm['retained_instabox'](database)
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout='')
    vm['guard'].__globals__['subprocess'] = SimpleNamespace(run=run)
    for settings, path in [({}, database), ({'INSTABOX_ENABLED':'true'}, Path(directory)/'absent')]:
        try:
            vm['guard'](settings, check_only=True, database=path)
        except RuntimeError as error:
            assert 'InstaBox' in str(error)
        else:
            raise AssertionError('unaware runner accepted')
    assert any('io.cloud-harness.instabox-workspaces' in str(call) for call in calls)
    vm['guard'].__globals__['subprocess'] = SimpleNamespace(run=lambda *a, **k: SimpleNamespace(stdout='1' if a[0][1] == 'image' else ''))
    vm['guard']({'INSTABOX_ENABLED':'true'}, database=Path(directory)/'absent')
    assert vm['parse_settings']('INSTABOX_ENABLED=true\nINSTABOX_API_KEY=sentinel\n') == {'INSTABOX_ENABLED': 'true'}
`);
});

it('checks exact target images and preserves explicitly configured remote settings', () => {
  python(String.raw`
import tempfile
from pathlib import Path
from types import SimpleNamespace
with tempfile.TemporaryDirectory() as directory:
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout='0')
    scope['require_instabox_runner'].__globals__.update(STATE=Path(directory), run=run)
    configured = 'AUTH_MODE=cloudflare-access\nINSTABOX_ENABLED=true\nINSTABOX_MACHINE_IDS=fixture-a\nINSTABOX_PRINCIPAL_ID=fixture-owner\nINSTABOX_API_KEY_FILE=/operator/selected/file\n'
    try:
        scope['require_instabox_runner']('old-image', configured)
    except RuntimeError as error:
        assert 'InstaBox' in str(error)
    else:
        raise AssertionError('unsafe image accepted')
    assert calls[0][:4] == ('docker', 'image', 'inspect', 'old-image')
    updated, _ = scope['dependency_configuration'](configured, '')
    for line in configured.splitlines():
        assert line in updated.splitlines()
    scope['require_instabox_runner'].__globals__['run'] = lambda *a, **k: SimpleNamespace(stdout='1')
    assert scope['require_instabox_runner']('aware-image', configured)
`);
});

it('fails closed on corrupt allocation schema without modifying the database', () => {
  python(String.raw`
import runpy, sqlite3, tempfile
from pathlib import Path
vm = runpy.run_path('custom/guard-vm-runner.py')
with tempfile.TemporaryDirectory() as directory:
    database = Path(directory) / 'state.db'
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE executor_allocations (unknown_column TEXT)')
    before = database.read_bytes()
    try:
        vm['retained_instabox'](database)
    except RuntimeError as error:
        assert 'Cannot verify' in str(error)
    else:
        raise AssertionError('unknown allocation schema accepted')
    assert database.read_bytes() == before
`);
});

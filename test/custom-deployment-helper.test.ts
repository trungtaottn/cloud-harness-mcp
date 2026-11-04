import { spawnSync } from 'node:child_process';
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

#!/usr/bin/env python3
"""Activate the tested API/runner overlay and approved dependency cache workflow."""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

STATE = Path('/var/lib/cloud-harness')
CONFIG = Path('/etc/cloud-harness-mcp/runtime.env')
PROXY_CONFIG = CONFIG.with_name('provisioning-proxy.env')
DEPENDENCY_HOSTS = {'registry.npmjs.org', 'proxy.golang.org', 'sum.golang.org', 'storage.googleapis.com'}
MARKER = STATE / 'workspace-recreate-in-progress'
UNIT = 'cloud-harness-mcp.service'
DEPLOY_UNIT = 'cloud-harness-workspace-recreate.service'
RELEASE = '157ed2e61ad6240b79f44ba64b8fffbf4a0f9c2f'
RELEASE_METADATA = {
    'release-api-image': STATE / 'release-api-image',
    'release-runner-image': STATE / 'release-runner-image',
    'release-config-runtime.env': STATE / 'release-config-current/runtime.env',
    'release-config-provisioning-proxy.env': STATE / 'release-config-current/provisioning-proxy.env',
}


def setting_value(text, key):
    values = []
    for line in text.splitlines():
        match = re.match(r'^\s*(?:export\s+)?' + re.escape(key) + r'\s*=(.*)$', line)
        if match:
            try:
                parts = shlex.split(match.group(1), comments=True)
            except ValueError as error:
                raise RuntimeError(f'Invalid configuration syntax for {key}') from error
            if len(parts) > 1:
                raise RuntimeError(f'Ambiguous configuration for {key}')
            values.append(parts[0] if parts else '')
    if len(set(values)) > 1:
        raise RuntimeError(f'Conflicting duplicate settings for {key}')
    return values[-1] if values else ''


def update_settings(text, settings):
    pattern = re.compile(r'^\s*(?:export\s+)?(' + '|'.join(map(re.escape, settings)) + r')\s*=')
    kept = ''.join(line for line in text.splitlines(keepends=True) if not pattern.match(line))
    return kept.rstrip('\n') + '\n' + ''.join(f'{key}={value}\n' for key, value in settings.items())


def dependency_configuration(runtime_text, proxy_text):
    if setting_value(runtime_text, 'AUTH_MODE') != 'cloudflare-access':
        raise RuntimeError('Dependency activation requires Dashboard approval-capable cloudflare-access authentication')
    settings = {'MAX_WORKSPACE_BYTES': '10737418240', 'DEPENDENCIES_ENABLED': 'true'}
    for key, default, minimum, maximum in (
        ('DEPENDENCIES_TIMEOUT_MS', 900000, 10000, 1800000),
        ('DEPENDENCIES_MAX_BYTES', 2147483648, 1048576, 10737418240),
    ):
        raw = setting_value(runtime_text, key) or str(default)
        if not re.fullmatch(r'[0-9]+', raw) or not minimum <= int(raw) <= maximum:
            raise RuntimeError(f'Invalid configuration range for {key}')
        settings[key] = str(int(raw))
    hosts = {host.strip().lower() for host in setting_value(proxy_text, 'PACKAGES_PROXY_HOSTS').split(',') if host.strip()}
    label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    if any(len(host) > 253 or not re.fullmatch(label + r'(?:\.' + label + r')+', host)
           or host.split('.')[-1].isdigit() for host in hosts):
        raise RuntimeError('Existing package proxy hosts contain an invalid hostname')
    return (update_settings(runtime_text, settings),
            update_settings(proxy_text, {'PACKAGES_PROXY_HOSTS': ','.join(sorted(hosts | DEPENDENCY_HOSTS))}))


def run(*args, capture=False, **kwargs):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None, **kwargs)


def ready():
    for _ in range(60):
        result = subprocess.run(['curl', '-fsS', '--max-time', '2', 'http://127.0.0.1:3100/readyz'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError('Readiness did not recover within the wait window')


def replace_file(path, text):
    fd, name = tempfile.mkstemp(prefix='.recreate-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists():
            shutil.copystat(path, name)
            os.chown(name, path.stat().st_uid, path.stat().st_gid)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def rollback(*, acquire_lock=True):
    if not MARKER.exists():
        return
    if acquire_lock:
        with (STATE / 'deploy.lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RuntimeError('Another deployment holds the deploy lock') from error
            rollback(acquire_lock=False)
        return
    if not MARKER.exists():
        return
    saved = json.loads(MARKER.read_text())
    backup = Path(saved['backup'])
    run('systemctl', 'stop', UNIT)
    replace_file(CONFIG, (backup / 'runtime.env').read_text())
    # Old recovery markers predate proxy changes and must leave that configuration alone.
    if 'proxy_existed' in saved:
        if saved['proxy_existed']:
            replace_file(PROXY_CONFIG, (backup / 'provisioning-proxy.env').read_text())
        else:
            PROXY_CONFIG.unlink(missing_ok=True)
    for service, image in saved['images'].items():
        run('docker', 'tag', image, f'cloud-harness-{service}:local')
    run('systemctl', 'start', UNIT)
    ready()
    if 'metadata' in saved:
        backed_up_metadata = set(saved['metadata'])
        managed_metadata = saved.get('managed_metadata', [name for name in RELEASE_METADATA if name != 'release-config-provisioning-proxy.env'])
        for name in managed_metadata:
            path = RELEASE_METADATA[name]
            if name in backed_up_metadata:
                replace_file(path, (backup / name).read_text())
            else:
                path.unlink(missing_ok=True)
    (STATE / 'workspace-recreate-hotfix.json').unlink(missing_ok=True)
    MARKER.unlink()
    print('Previous API/runner and configuration restored.', flush=True)


def apply():
    images = json.loads(Path(__file__).with_name('verified-images.json').read_text())
    if set(images) != {'api', 'runner'} or not all(re.fullmatch(r'sha256:[0-9a-f]{64}', image) for image in images.values()):
        raise RuntimeError('Invalid verified image manifest')
    with (STATE / 'deploy.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if MARKER.exists() or (STATE / 'deploy-in-progress').exists():
            raise RuntimeError('Resolve the existing deployment marker before starting')
        if (STATE / 'release-current').read_text().strip() != RELEASE:
            raise RuntimeError('Production release changed; rebase and verify the patch first')
        for path in (CONFIG, PROXY_CONFIG, *RELEASE_METADATA.values()):
            if path.is_symlink():
                raise RuntimeError('Refusing symlinked deployment configuration or metadata')
        proxy_existed = PROXY_CONFIG.exists()
        runtime_text, proxy_text = dependency_configuration(CONFIG.read_text(), PROXY_CONFIG.read_text() if proxy_existed else '')
        for image in images.values():
            run('docker', 'image', 'inspect', image, capture=True)
        # Do not interrupt an executor with active commands or interactive sessions.
        containers = run('docker', 'ps', '--filter', 'name=cloud-harness-ws-', '--format', '{{.Names}}', capture=True).stdout.splitlines()
        for container in containers:
            # Docker needs PID to associate host processes with this container.
            rows = run('docker', 'top', container, '-eo', 'pid,args', capture=True).stdout.splitlines()[1:]
            commands = [row.strip().split(None, 1)[1] for row in rows]
            if any(command.strip() not in ('sleep infinity', '/usr/bin/tini -- sleep infinity', 'tini -- sleep infinity') for command in commands):
                raise RuntimeError('A workspace has live processes; pause work and close its terminals before deployment')
        for label in ('cloud-harness.agent-container=true', 'cloud-harness.ephemeral=true'):
            active_sidecars = run(
                'docker', 'ps', '--filter', f'label={label}', '--format', '{{.Names}}', capture=True
            ).stdout.splitlines()
            if active_sidecars:
                raise RuntimeError('An agent or helper operation is running; wait for it to finish before deployment')
        dependency_helpers = run(
            'docker', 'ps', '-a', '--filter', 'label=cloud-harness.role=dependency-download',
            '--format', '{{.Names}}', capture=True
        ).stdout.splitlines()
        if dependency_helpers:
            raise RuntimeError('A dependency helper exists; finish or reconcile its download before deployment')
        ready()
        backup = Path(tempfile.mkdtemp(prefix='workspace-recreate-', dir=STATE / 'backups'))
        shutil.copy2(CONFIG, backup / 'runtime.env')
        if proxy_existed:
            shutil.copy2(PROXY_CONFIG, backup / 'provisioning-proxy.env')
        database = STATE / 'state/cloud-harness.db'
        if database.exists():
            with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as source, sqlite3.connect(backup / 'cloud-harness.db') as target:
                source.backup(target)
        metadata = []
        for name, path in RELEASE_METADATA.items():
            if path.exists():
                shutil.copy2(path, backup / name)
                metadata.append(name)
        previous = {service: run('docker', 'inspect', f'cloud-harness-mcp-{service}-1', '--format', '{{.Image}}', capture=True).stdout.strip() for service in images}
        MARKER.write_text(json.dumps({'backup': str(backup), 'images': previous, 'metadata': metadata,
                                      'managed_metadata': list(RELEASE_METADATA), 'proxy_existed': proxy_existed}))
        print(f'Backup: {backup}', flush=True)
        try:
            replace_file(CONFIG, runtime_text)
            replace_file(PROXY_CONFIG, proxy_text)
            for service, image in images.items():
                run('docker', 'tag', image, f'cloud-harness-{service}:local')
            run('systemctl', 'restart', UNIT)
            ready()
            for service, image in images.items():
                actual = run('docker', 'inspect', f'cloud-harness-mcp-{service}-1', '--format', '{{.Image}}', capture=True).stdout.strip()
                if actual != image:
                    raise RuntimeError(f'{service} did not start the verified image')
            run('docker', 'exec', 'cloud-harness-mcp-api-1', 'node', '--input-type=module', '-e',
                "import {TOOL_SCHEMA_BY_NAME as t} from '@cloud-harness/contracts';"
                "const workspaceId='ws_'+ 'a'.repeat(32),planId='dep_'+ 'a'.repeat(32),planDigest='a'.repeat(64);"
                "t.workspace_recover.parse({mode:'recreate'});"
                "for(const ecosystem of ['go','pnpm'])t.dependencies_plan.parse({workspaceId,ecosystem});"
                "t.dependencies_apply.parse({workspaceId,planId,planDigest});"
                "t.dependencies_status.parse({workspaceId});console.log('recreate and dependency schemas: ready')")
            run('docker', 'exec', 'cloud-harness-mcp-runner-1', 'node', '--input-type=module', '-e',
                "import {RunnerConfigSchema as s} from '@cloud-harness/contracts';"
                "const e=process.env;"
                "if(e.MAX_WORKSPACE_BYTES!=='10737418240'||e.DEPENDENCIES_ENABLED!=='true'||e.AUTH_MODE!=='cloudflare-access')process.exit(1);"
                "s.shape.dependenciesEnabled.parse(e.DEPENDENCIES_ENABLED);"
                "s.shape.dependenciesMaxBytes.parse(e.DEPENDENCIES_MAX_BYTES);"
                "s.shape.dependenciesTimeoutMs.parse(e.DEPENDENCIES_TIMEOUT_MS);"
                "console.log('dependency configuration and 10 GiB workspace quota: ready')")
            run('docker', 'exec', 'cloud-harness-mcp-provisioning-proxy-1', 'node', '-e',
                "const hosts=new Set((process.env.PACKAGES_PROXY_HOSTS||'').split(','));"
                "if(!['registry.npmjs.org','proxy.golang.org','sum.golang.org','storage.googleapis.com'].every(h=>hosts.has(h)))process.exit(1);"
                "console.log('dependency registry proxy hosts: ready')")
            # Pass canary credentials by environment, without displaying their values.
            run('bash', '-c', 'set -eu; set -a; source /etc/cloud-harness-mcp/canary-credentials; set +a; exec /usr/local/sbin/cloud-harness-service-compose run --rm --no-deps -e MCP_CANARY_URL -e MCP_CANARY_ACCESS_CLIENT_ID -e MCP_CANARY_ACCESS_CLIENT_SECRET ingress node /app/scripts/deploy-canary.mjs',
                cwd='/opt/cloud-harness-mcp/repo')
            replace_file(RELEASE_METADATA['release-api-image'], images['api'] + '\n')
            replace_file(RELEASE_METADATA['release-runner-image'], images['runner'] + '\n')
            replace_file(RELEASE_METADATA['release-config-runtime.env'], CONFIG.read_text())
            replace_file(RELEASE_METADATA['release-config-provisioning-proxy.env'], PROXY_CONFIG.read_text())
            # The upstream source revision stays unchanged; record this local overlay separately.
            (STATE / 'workspace-recreate-hotfix.json').write_text(json.dumps({'upstream': RELEASE, 'images': images, 'backup': str(backup)}))
            MARKER.unlink()
            print('Local recreate and approved dependency workflow active; workspace storage ceiling is 10 GiB.', flush=True)
        except BaseException:
            rollback(acquire_lock=False)
            raise


def launch():
    with (STATE / 'workspace-recreate-launch.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Another workspace recreation launcher is running') from error
        unit_state = subprocess.run(
            ['systemctl', 'show', '--property=ActiveState', '--value', DEPLOY_UNIT],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        ).stdout.strip()
        if unit_state not in ('', 'inactive', 'failed'):
            raise RuntimeError(f'{DEPLOY_UNIT} is {unit_state}; wait for it to finish before replacing its tooling')
        installed = STATE / 'workspace-recreate-tooling'
        installed.mkdir(mode=0o700, exist_ok=True)
        for name in ('deploy.py', 'verified-images.json'):
            shutil.copy2(Path(__file__).with_name(name), installed / name)
        run('systemd-run', '--wait', '--collect', '--unit=cloud-harness-workspace-recreate',
            '--property=KillMode=mixed', '--property=TimeoutStopSec=300',
            f'--property=ExecStopPost=/usr/bin/python3 {installed}/deploy.py --recover',
            '/usr/bin/python3', str(installed / 'deploy.py'), '--apply')


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo; this changes production images and configuration.')
    os.umask(0o077)
    if '--recover' in sys.argv:
        rollback()
    elif '--apply' in sys.argv:
        def interrupted(_signal, _frame):
            raise RuntimeError('Deployment interrupted')
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGHUP, interrupted)
        apply()
    else:
        launch()


if __name__ == '__main__':
    main()

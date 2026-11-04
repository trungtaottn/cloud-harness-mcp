#!/usr/bin/env python3
"""Activate the tested local API/runner patch and a 10 GiB workspace ceiling."""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

STATE = Path('/var/lib/cloud-harness')
CONFIG = Path('/etc/cloud-harness-mcp/runtime.env')
MARKER = STATE / 'workspace-recreate-in-progress'
UNIT = 'cloud-harness-mcp.service'
DEPLOY_UNIT = 'cloud-harness-workspace-recreate.service'
RELEASE = '157ed2e61ad6240b79f44ba64b8fffbf4a0f9c2f'
RELEASE_METADATA = {
    'release-api-image': STATE / 'release-api-image',
    'release-runner-image': STATE / 'release-runner-image',
    'release-config-runtime.env': STATE / 'release-config-current/runtime.env',
}


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
    for service, image in saved['images'].items():
        run('docker', 'tag', image, f'cloud-harness-{service}:local')
    run('systemctl', 'start', UNIT)
    ready()
    if 'metadata' in saved:
        backed_up_metadata = set(saved['metadata'])
        for name, path in RELEASE_METADATA.items():
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
        ready()
        backup = Path(tempfile.mkdtemp(prefix='workspace-recreate-', dir=STATE / 'backups'))
        shutil.copy2(CONFIG, backup / 'runtime.env')
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
        MARKER.write_text(json.dumps({'backup': str(backup), 'images': previous, 'metadata': metadata}))
        print(f'Backup: {backup}', flush=True)
        try:
            text = ''.join(line for line in CONFIG.read_text().splitlines(keepends=True)
                           if not re.match(r'^\s*(?:export\s+)?MAX_WORKSPACE_BYTES\s*=', line))
            replace_file(CONFIG, text.rstrip('\n') + '\nMAX_WORKSPACE_BYTES=10737418240\n')
            for service, image in images.items():
                run('docker', 'tag', image, f'cloud-harness-{service}:local')
            run('systemctl', 'restart', UNIT)
            ready()
            for service, image in images.items():
                actual = run('docker', 'inspect', f'cloud-harness-mcp-{service}-1', '--format', '{{.Image}}', capture=True).stdout.strip()
                if actual != image:
                    raise RuntimeError(f'{service} did not start the verified image')
            run('docker', 'exec', 'cloud-harness-mcp-api-1', 'node', '--input-type=module', '-e',
                "import {TOOL_SCHEMA_BY_NAME as t} from '@cloud-harness/contracts'; t.workspace_recover.parse({mode:'recreate'}); console.log('recreate schema: ready')")
            run('docker', 'exec', 'cloud-harness-mcp-runner-1', 'node', '-e',
                "if(process.env.MAX_WORKSPACE_BYTES!=='10737418240')process.exit(1); console.log('workspace quota: 10 GiB')")
            # Pass canary credentials by environment, without displaying their values.
            run('bash', '-c', 'set -eu; set -a; source /etc/cloud-harness-mcp/canary-credentials; set +a; exec /usr/local/sbin/cloud-harness-service-compose run --rm --no-deps -e MCP_CANARY_URL -e MCP_CANARY_ACCESS_CLIENT_ID -e MCP_CANARY_ACCESS_CLIENT_SECRET ingress node /app/scripts/deploy-canary.mjs',
                cwd='/opt/cloud-harness-mcp/repo')
            replace_file(RELEASE_METADATA['release-api-image'], images['api'] + '\n')
            replace_file(RELEASE_METADATA['release-runner-image'], images['runner'] + '\n')
            replace_file(RELEASE_METADATA['release-config-runtime.env'], CONFIG.read_text())
            # The upstream source revision stays unchanged; record this local overlay separately.
            (STATE / 'workspace-recreate-hotfix.json').write_text(json.dumps({'upstream': RELEASE, 'images': images, 'backup': str(backup)}))
            MARKER.unlink()
            print('Local recreate patch active; workspace storage ceiling is 10 GiB.', flush=True)
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

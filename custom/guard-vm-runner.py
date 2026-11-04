#!/usr/bin/env python3
"""Protect retained VM roots and restore the configured host egress boundary."""
import ipaddress
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

KEYS = {'EXECUTOR_KIND', 'DEPENDENCY_NETWORK_NAME', 'DEPENDENCY_BRIDGE_INTERFACE',
        'DEPENDENCY_BRIDGE_SUBNET', 'DEPENDENCY_DNS_RESOLVERS'}


def read_settings(path):
    settings = {}
    for line in Path(path).read_text().splitlines():
        match = re.match(r'^\s*(?:export\s+)?([A-Z_]+)\s*=(.*)$', line)
        if not match or match[1] not in KEYS:
            continue
        parts = shlex.split(match[2], comments=True)
        if len(parts) > 1:
            raise RuntimeError('Ambiguous VM network setting')
        value = parts[0] if parts else ''
        if match[1] in settings and settings[match[1]] != value:
            raise RuntimeError('Conflicting VM network settings')
        settings[match[1]] = value
    if settings.get('EXECUTOR_KIND', 'docker') not in ('docker', 'kata'):
        raise RuntimeError('Unknown executor kind')
    for key, pattern in [('DEPENDENCY_NETWORK_NAME', r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'),
                         ('DEPENDENCY_BRIDGE_INTERFACE', r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}')]:
        if key in settings and not re.fullmatch(pattern, settings[key]):
            raise RuntimeError('Invalid VM network identifier')
    if 'DEPENDENCY_BRIDGE_SUBNET' in settings:
        ipaddress.IPv4Network(settings['DEPENDENCY_BRIDGE_SUBNET'])
    if 'DEPENDENCY_DNS_RESOLVERS' in settings:
        resolvers = settings['DEPENDENCY_DNS_RESOLVERS'].replace(',', ' ').split()
        if not resolvers:
            raise RuntimeError('VM DNS resolvers are empty')
        for resolver in resolvers:
            ipaddress.IPv4Address(resolver)
        settings['DEPENDENCY_DNS_RESOLVERS'] = ','.join(resolvers)
    return settings


def guard(settings, check_only=False):
    retained = subprocess.run(['docker', 'ps', '-a', '--filter', 'label=cloud-harness.executor=kata',
                               '--filter', 'label=cloud-harness.managed=true', '--format', '{{.Names}}'],
                              check=True, text=True, capture_output=True).stdout.strip()
    if not retained and settings.get('EXECUTOR_KIND') != 'kata':
        return
    aware = subprocess.run(['docker', 'image', 'inspect', 'cloud-harness-runner:local', '--format',
                            '{{index .Config.Labels "io.cloud-harness.vm-workspaces"}}'],
                           check=True, text=True, capture_output=True).stdout.strip()
    if aware != '1':
        raise RuntimeError('Refusing a runner without persistent-VM support; retained disks require a VM-aware runner')
    if check_only:
        return
    if not os.access('/usr/local/bin/containerd-shim-kata-v2', os.X_OK):
        raise RuntimeError('Kata runtime is not installed')
    # Parse only network settings; never source or export the configuration's credentials.
    network = {key: value for key, value in settings.items() if key.startswith('DEPENDENCY_')}
    subprocess.run(['bash', '/usr/local/lib/cloud-harness/setup-vm-firewall.sh'],
                   check=True, env={**os.environ, **network})


if __name__ == '__main__':
    guard(read_settings('/etc/cloud-harness-mcp/runtime.env'), '--check-only' in sys.argv)

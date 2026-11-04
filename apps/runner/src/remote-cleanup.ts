import { HarnessError } from '@cloud-harness/contracts';
import type { RemoteExecutorRef } from './executors/execution-backend.js';

const shellQuote = (value: string): string => `'${value.replaceAll("'", "'\\''")}'`;

/** Runner-owned privileged cleanup. Traversal stays descriptor-relative and refuses links or mounts. */
export const REMOTE_CLEANUP_SCRIPT = String.raw`
import os, stat, sys

base, instance, workspace = sys.argv[1:]
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

def mount_id(fd):
    with open('/proc/self/fdinfo/%d' % fd, encoding='ascii') as info:
        for line in info:
            if line.startswith('mnt_id:'):
                return int(line.split(':', 1)[1])
    raise RuntimeError('mount identity unavailable')

def open_directory(parent, name, missing_ok=False):
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise
    if not stat.S_ISDIR(before.st_mode):
        raise RuntimeError('cleanup boundary is not a directory')
    opened = os.open(name, flags, dir_fd=parent)
    current = os.fstat(opened)
    if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
        os.close(opened)
        raise RuntimeError('cleanup boundary changed')
    return opened

def remove_contents(directory, device, mount):
    os.fchmod(directory, 0o700)
    for name in os.listdir(directory):
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            child = open_directory(directory, name)
            try:
                opened = os.fstat(child)
                if opened.st_dev != device or mount_id(child) != mount:
                    raise RuntimeError('cleanup refuses a nested mount')
                remove_contents(child, device, mount)
                current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise RuntimeError('cleanup directory changed')
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory)
        else:
            os.unlink(name, dir_fd=directory)

root = os.open('/', flags)
current = root
try:
    for component in [part for part in base.split('/') if part]:
        child = open_directory(current, component)
        if current != root:
            os.close(current)
        current = child
    base_device = os.fstat(current).st_dev
    base_mount = mount_id(current)
    for component in ('.cloud-harness', instance):
        child = open_directory(current, component, True)
        if child is None:
            sys.exit(0)
        if os.fstat(child).st_dev != base_device or mount_id(child) != base_mount:
            os.close(child)
            raise RuntimeError('cleanup refuses an ancestor mount')
        os.close(current)
        current = child
    target = open_directory(current, workspace, True)
    if target is None:
        sys.exit(0)
    target_stat = os.fstat(target)
    if target_stat.st_dev != base_device or mount_id(target) != base_mount:
        raise RuntimeError('cleanup refuses an allocation mount')
    try:
        remove_contents(target, target_stat.st_dev, mount_id(target))
        entry = os.stat(workspace, dir_fd=current, follow_symlinks=False)
        if (entry.st_dev, entry.st_ino) != (target_stat.st_dev, target_stat.st_ino):
            raise RuntimeError('cleanup allocation changed')
    finally:
        os.close(target)
    os.rmdir(workspace, dir_fd=current)
    os.fsync(current)
finally:
    if current != root:
        os.close(current)
    os.close(root)
`;

export const REMOTE_CLEANUP_PREREQUISITE = String.raw`
import os, sys
required = ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC')
if any(not hasattr(os, name) for name in required):
    sys.exit(1)
fd = os.open('/data/home', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    text = open('/proc/self/fdinfo/%d' % fd, encoding='ascii').read()
    sys.exit(0 if 'mnt_id:' in text else 1)
finally:
    os.close(fd)
`;

export function remoteCleanupCommand(ref: RemoteExecutorRef): string {
  const match = ref.root.match(/^\/data\/home\/\.cloud-harness\/([a-f0-9]{36})\/([A-Za-z0-9_-]{1,128})$/);
  if (!match || match[2] !== ref.workspaceId) {
    throw new HarnessError('FORBIDDEN', 'Remote cleanup allocation path is invalid', 403, false);
  }
  return ['sudo', '-n', '--', 'python3', '-c', REMOTE_CLEANUP_SCRIPT, '/data/home', match[1]!, match[2]!]
    .map(shellQuote).join(' ');
}

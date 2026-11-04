#!/usr/bin/env python3
"""Enable npm/uv packages using the existing production deploy and rollback."""
import fcntl
import os
from pathlib import Path
import re
import shlex
import shutil
import tempfile

RELEASE = "157ed2e61ad6240b79f44ba64b8fffbf4a0f9c2f"
STATE = Path("/var/lib/cloud-harness")
CONFIG = Path("/etc/cloud-harness-mcp")
REGISTRIES = {
    "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
    "release-assets.githubusercontent.com",
}


def setting_value(text, key):
    values = []
    for line in text.splitlines():
        match = re.match(r"^\s*(?:export\s+)?" + re.escape(key) + r"\s*=(.*)$", line)
        if match:
            parts = shlex.split(match[1], comments=True)
            if len(parts) > 1:
                raise ValueError(f"Ambiguous configuration for {key}")
            values.append(parts[0] if parts else "")
    if len(set(values)) > 1:
        raise ValueError(f"Conflicting duplicate settings for {key}")
    return values[-1] if values else ""


def update_settings(text, settings):
    pattern = re.compile(r"^\s*(?:export\s+)?(" + "|".join(map(re.escape, settings)) + r")\s*=")
    kept = "".join(line for line in text.splitlines(keepends=True) if not pattern.match(line))
    return kept.rstrip("\n") + "\n" + "".join(f"{key}={value}\n" for key, value in settings.items())


def atomic_write(path, text):
    fd, temporary = tempfile.mkstemp(prefix=".managed-packages-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists():
            shutil.copystat(path, temporary)
            os.chown(temporary, path.stat().st_uid, path.stat().st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo; configuration values and credentials are never printed.")
    with (STATE / "deploy.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (STATE / "release-current").read_text().strip() != RELEASE:
            raise SystemExit("Release changed; review configuration against the new release first.")
        if (STATE / "deploy-in-progress").exists():
            raise SystemExit("Resolve the existing deployment/recovery first.")
        runtime = CONFIG / "runtime.env"
        proxy = CONFIG / "provisioning-proxy.env"
        if runtime.is_symlink() or proxy.is_symlink():
            raise SystemExit("Refusing to replace symlinked configuration.")
        original = runtime.read_text()
        if setting_value(original, "AUTH_MODE") != "cloudflare-access":
            raise SystemExit("This activation requires the current Dashboard approval-capable auth mode.")
        proxy_existed = proxy.exists()
        old_proxy = proxy.read_text() if proxy_existed else ""
        hosts = {host.strip() for host in setting_value(old_proxy, "PACKAGES_PROXY_HOSTS").split(",") if host.strip()}
        updated_proxy = update_settings(old_proxy, {"PACKAGES_PROXY_HOSTS": ",".join(sorted(hosts | REGISTRIES))})
        updated = update_settings(original, {
            "PACKAGES_ENABLED": "true", "PACKAGES_ECOSYSTEMS": "npm,uv",
            "PACKAGES_APPROVAL_MODE": "required", "PACKAGES_NPM_LIFECYCLE_SCRIPTS": "deny",
        })
        backup = Path(tempfile.mkdtemp(prefix="managed-packages-", dir=STATE / "backups"))
        shutil.copy2(runtime, backup / runtime.name)
        if proxy_existed:
            shutil.copy2(proxy, backup / proxy.name)
        else:
            (backup / "proxy-was-absent").touch(mode=0o600)
        try:
            atomic_write(proxy, updated_proxy)
            atomic_write(runtime, updated)
        except BaseException:
            atomic_write(runtime, original)
            if proxy_existed:
                atomic_write(proxy, old_proxy)
            else:
                proxy.unlink(missing_ok=True)
            raise
        print(f"Configuration backup: {backup}", flush=True)
    os.execv("/usr/local/sbin/cloud-harness-deploy", ["cloud-harness-deploy", RELEASE])


if __name__ == "__main__":
    main()

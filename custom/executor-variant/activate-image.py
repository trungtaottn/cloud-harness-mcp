#!/usr/bin/env python3
"""Select the tested executor, then use the installed transactional deploy route."""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

RELEASE = "157ed2e61ad6240b79f44ba64b8fffbf4a0f9c2f"
IMAGE = "cloud-harness-executor:0.80.0-go1.27.3-rust1.99.1"
CONFIG = Path("/etc/cloud-harness-mcp/runtime.env")
STATE = Path("/var/lib/cloud-harness")


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo; no credentials are printed by this script.")
    expected = Path(__file__).with_name("verified-image-id").read_text().strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
        raise SystemExit("Missing or invalid smoke-tested image ID.")
    info = json.loads(subprocess.check_output(["docker", "image", "inspect", IMAGE]))[0]
    if info["Id"] != expected or info["Config"]["User"] != "10001:10001":
        raise SystemExit("Image changed since verification; rebuild and smoke-test first.")
    # Cooperate with the installed deploy lock while preparing configuration.
    with (STATE / "deploy.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (STATE / "release-current").read_text().strip() != RELEASE:
            raise SystemExit("Running release changed; rebuild the variant for that release first.")
        if (STATE / "deploy-in-progress").exists():
            raise SystemExit("Resolve the existing deployment/recovery before activation.")
        if CONFIG.is_symlink():
            raise SystemExit("Refusing to replace a symlinked runtime configuration.")
        original = CONFIG.read_text()
        lines = original.splitlines(keepends=True)
        setting = re.compile(r"^\s*(?:export\s+)?EXECUTOR_IMAGE\s*=")
        updated = "".join(line for line in lines if not setting.match(line))
        # Pin the exact tested image, not a tag that can silently move.
        updated = updated.rstrip("\n") + "\nEXECUTOR_IMAGE=" + expected + "\n"
        backup = Path(tempfile.mkdtemp(prefix="executor-toolchains-", dir=STATE / "backups"))
        shutil.copy2(CONFIG, backup / "runtime.env")
        fd, temporary = tempfile.mkstemp(prefix=".runtime-toolchains-", dir=CONFIG.parent)
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(updated)
                handle.flush()
                os.fsync(handle.fileno())
            shutil.copystat(CONFIG, temporary)
            os.chown(temporary, CONFIG.stat().st_uid, CONFIG.stat().st_gid)
            os.replace(temporary, CONFIG)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        print(f"Configuration backup: {backup}", flush=True)
    # The deploy script snapshots state, runs the canary, and records the new
    # known-good configuration. It owns rollback if the release fails.
    os.execv("/usr/local/sbin/cloud-harness-deploy", ["cloud-harness-deploy", RELEASE])


if __name__ == "__main__":
    main()

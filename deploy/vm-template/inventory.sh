#!/usr/bin/env bash
# inventory.sh — canonical, deterministic description of a provisioned
# cloudharness-vm guest. Runs as root inside the build VM at the end of
# provision.sh; stdout is captured to /root/vm-template-inventory.txt and
# pulled host-side. Two builds from the same inputs must produce byte-
# identical output — that is the phase-11 reproducibility gate.
#
# Sections are emitted in fixed order with LC_ALL=C sorting. The digest of
# this file is the templateDigest recorded in the build manifest.
set -euo pipefail
export LC_ALL=C

section() { printf '\n## %s\n' "$1"; }

probe() { # probe <name> <cmd...> — first line of output, empty on failure
  local name="$1"; shift
  local out
  out="$(timeout 15 "$@" 2>&1 | head -n1)" || true
  printf '%s\t%s\n' "$name" "$out"
}

section template
printf 'template_id=%s\n' "${CH_VM_TEMPLATE_ID:-unknown}"
printf 'template_version=%s\n' "${CH_VM_TEMPLATE_VERSION:-unknown}"

section os
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  printf 'id=%s\nversion=%s\ncodename=%s\n' "${ID:-unknown}" "${VERSION_ID:-unknown}" "${VERSION_CODENAME:-unknown}"
fi
printf 'arch=%s\nkernel_release_host_visible=%s\n' \
  "$(dpkg --print-architecture)" "$(uname -r)"

section dpkg
# Full installed-package inventory: name, version, arch — sorted.
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' | sort

section apt-mark-manual
apt-mark showmanual | sort

section guest-files
# Every file the template owns: sha256 + mode + uid:gid + path.
find /opt/harness /opt/cloud-harness /etc/cloud-harness \
     /etc/profile.d/harness.sh /etc/sudoers.d/harness \
     /usr/local/bin/guest-df.sh /usr/local/bin/kill-session.sh \
     /usr/local/bin/git-vm.sh \
     -type f -print0 2>/dev/null | sort -z | while IFS= read -r -d '' f; do
  sha="$(sha256sum "$f" | cut -d' ' -f1)"
  mode="$(stat -c '%a' "$f")"
  owner="$(stat -c '%u:%g' "$f")"
  printf '%s\t%s\t%s\t%s\n' "$sha" "$mode" "$owner" "$f"
done

section systemd-units
# Enabled-state of every unit the contract cares about. 'absent' covers
# units with no unit file; masked/disabled are recorded verbatim.
for unit in \
  incus-agent.service systemd-networkd.service systemd-networkd-wait-online.service \
  systemd-resolved.service systemd-timesyncd.service docker.service containerd.service \
  ssh.service ssh.socket sshd.service sshd.socket \
  NetworkManager.service networking.service dhcpcd.service dhclient.service \
  netplan-networkd.service wpa_supplicant.service \
  cloud-init.service cloud-init-local.service cloud-config.service cloud-final.service \
  cloud-init.target qemu-guest-agent.service qemu-guest-agent.socket qemu-guest-agent.target \
  unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer e2scrub_reap.service; do
  state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  printf '%s\t%s\n' "$unit" "${state:-absent}"
done | sort

section network
printf 'resolv_conf_symlink=%s\n' "$(readlink /etc/resolv.conf 2>/dev/null || echo 'not-a-symlink')"
printf 'networkd_dir_listing:\n'
# Every PERSISTENT networkd search path — /etc, /usr/lib, /usr/local/lib
# systemd/network (/run is tmpfs). The image must list zero link configs;
# the supervisor pushes the per-VM static .network at workspace provision.
netdir_empty=1
for d in /etc/systemd/network /usr/lib/systemd/network /usr/local/lib/systemd/network; do
  if [[ -d "$d" ]]; then
    entries="$(find "$d" -mindepth 1 | sort)"
    if [[ -n "$entries" ]]; then
      netdir_empty=0
      printf '%s\n' "$entries" | sed 's/^/  /'
    fi
  fi
done
[[ $netdir_empty -eq 1 ]] && printf '  <empty>\n'
command -v incus-agent >/dev/null && printf 'incus_agent_path=%s\n' "$(command -v incus-agent)" || printf 'incus_agent_path=MISSING\n'

section tools
probe node node --version
probe npm npm --version
probe npx npx --version
probe bun bun --version
probe bunx bunx --version
probe uv uv --version
probe uvx uvx --version
probe pnpm pnpm --version
probe wrangler wrangler --version
probe gh gh --version
probe ak ak --version
probe git git --version
probe docker docker --version
probe docker-buildx docker buildx version
probe docker-compose docker compose version
probe go go version
probe python3 python3 --version
probe pip3 pip3 --version
probe bwrap bwrap --version
probe jq jq --version
probe rg rg --version
probe ctags ctags --version
probe make make --version
probe gcc gcc --version
probe psql psql --version
probe setsid setsid --version
probe timeout timeout --version
probe tar tar --version
probe unzip unzip -v

section identity
printf 'harness_passwd=%s\n' "$(getent passwd harness || echo MISSING)"
printf 'harness_group=%s\n' "$(getent group harness || echo MISSING)"
if getent group docker >/dev/null 2>&1 && id -nG harness 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
  printf 'harness_in_docker_group=yes\n'
else
  printf 'harness_in_docker_group=no\n'
fi
if runuser -u harness -- sudo -n true 2>/dev/null; then
  printf 'harness_sudo_nopasswd=yes\n'
else
  printf 'harness_sudo_nopasswd=no\n'
fi
printf 'workspace_mode=%s\nworkspace_owner=%s\n' \
  "$(stat -c '%a' /workspace)" "$(stat -c '%u:%g' /workspace)"
printf 'opt_user_tools_mode=%s\nopt_user_tools_owner=%s\n' \
  "$(stat -c '%a' /opt/user-tools)" "$(stat -c '%u:%g' /opt/user-tools)"
printf 'var_cache_harness_mode=%s\nvar_cache_harness_owner=%s\n' \
  "$(stat -c '%a' /var/cache/harness)" "$(stat -c '%u:%g' /var/cache/harness)"
printf 'tmp_cloud_harness_home_mode=%s\ntmp_cloud_harness_home_owner=%s\n' \
  "$(stat -c '%a' /tmp/cloud-harness-home)" "$(stat -c '%u:%g' /tmp/cloud-harness-home)"
printf 'profile_path_export=%s\n' "$(grep '^export PATH=' /etc/profile.d/harness.sh 2>/dev/null || echo MISSING)"
printf 'template_identity_file:\n'
if [[ -f /etc/cloud-harness/template-identity.env ]]; then
  sed 's/^/  /' /etc/cloud-harness/template-identity.env
else
  printf '  <absent>\n'
fi

#!/usr/bin/env bash
# provision.sh <payload-dir> <template-id> <template-version>
#
# Runs as root inside a disposable Incus VM launched from images:debian/13.
# Installs the cloudharness-vm guest contract: packages, pinned tools,
# harness user (uid 10001, passwordless sudo), baked worker assets,
# systemd-networkd ownership of guest networking, incus-agent enablement,
# and cleanup. Finishes by writing the canonical inventory to
# /root/vm-template-inventory.txt for the host-side build script to pull.
#
# Ordering contract: every network-dependent step (apt, downloads) runs
# BEFORE the network-manager transition, so a networkd/DHCP hiccup can
# never strand an unfinished install. After the transition nothing needs
# connectivity — the per-VM static .network is pushed later by the
# supervisor, so the image itself ships with no .network files.
set -euo pipefail

PAYLOAD="${1:?usage: provision.sh <payload-dir> <template-id> <template-version>}"
TEMPLATE_ID="${2:?missing template-id}"
TEMPLATE_VERSION="${3:?missing template-version}"

[[ $EUID -eq 0 ]] || { echo "provision.sh must run as root" >&2; exit 1; }
ARCH="$(dpkg --print-architecture)"
[[ "$ARCH" == "amd64" ]] || { echo "v1 template supports amd64 only (got $ARCH)" >&2; exit 1; }
[[ -f "$PAYLOAD/packages.txt" && -f "$PAYLOAD/tool-pins.sh" && -d "$PAYLOAD/guest" ]] \
  || { echo "payload incomplete at $PAYLOAD" >&2; exit 1; }

# The staged payload preserves the BUILDER's uid (cp -a from the repo
# worktree). sudo(8) silently ignores sudoers.d entries not owned by root,
# so normalize the whole payload to root:root before anything installs it —
# cp -a below then preserves root ownership into the image regardless of
# which uid ran the build.
chown -R 0:0 "$PAYLOAD"

export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-y --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

mapfile -t PKGS < <(grep -vE '^[[:space:]]*(#|$)' "$PAYLOAD/packages.txt")
[[ ${#PKGS[@]} -gt 0 ]] || { echo "packages.txt is empty" >&2; exit 1; }

# shellcheck disable=SC1090
source "$PAYLOAD/tool-pins.sh"

fetch() { # fetch <url> <dest>
  curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 -o "$2" "$1"
}
verify_sha256() { # verify_sha256 <file> <expected-hex>
  local actual
  actual="$(sha256sum "$1" | cut -d' ' -f1)"
  [[ "$actual" == "$2" ]] || { echo "sha256 mismatch for $1: got $actual want $2" >&2; exit 1; }
}

echo "==> apt: base packages (${#PKGS[@]})"
apt-get update
apt-get install "${APT_OPTS[@]}" "${PKGS[@]}"

echo "==> apt: GitHub CLI repository"
# Same signed-repo trust path as docker/executor.Dockerfile.
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg status=none
chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
  > /etc/apt/sources.list.d/github-cli.list
apt-get update
apt-get install "${APT_OPTS[@]}" gh

echo "==> tools: node ${NODE_VERSION}"
fetch "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz" /tmp/node.tar.xz
verify_sha256 /tmp/node.tar.xz "$NODE_TARBALL_SHA256_AMD64"
tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1
rm -f /tmp/node.tar.xz

echo "==> tools: bun ${BUN_VERSION}"
fetch "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-x64.zip" /tmp/bun.zip
verify_sha256 /tmp/bun.zip "$BUN_ZIP_SHA256_AMD64"
unzip -oq /tmp/bun.zip -d /tmp/bun-dist
install -m 0755 /tmp/bun-dist/bun-linux-x64/bun /usr/local/bin/bun
ln -sf bun /usr/local/bin/bunx
rm -rf /tmp/bun.zip /tmp/bun-dist

echo "==> tools: uv ${UV_VERSION}"
fetch "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz" /tmp/uv.tar.gz
verify_sha256 /tmp/uv.tar.gz "$UV_TARBALL_SHA256_AMD64"
tar -xzf /tmp/uv.tar.gz -C /tmp
install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uv /usr/local/bin/uv
install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uvx /usr/local/bin/uvx
rm -rf /tmp/uv.tar.gz /tmp/uv-x86_64-unknown-linux-gnu

echo "==> tools: npm globals pnpm@${PNPM_VERSION} wrangler@${WRANGLER_VERSION}"
npm install -g "pnpm@${PNPM_VERSION}" "wrangler@${WRANGLER_VERSION}"

echo "==> tools: agentkit ${AK_VERSION}"
fetch "https://releases.agentkit.best/binaries/${AK_VERSION}/ak_${AK_VERSION}_linux_amd64.tar.gz" /tmp/ak.tar.gz
verify_sha256 /tmp/ak.tar.gz "$AK_TARBALL_SHA256_AMD64"
tar -xzf /tmp/ak.tar.gz -C /tmp
AK_BIN="$(find /tmp -maxdepth 3 -type f -name ak | head -n1)"
[[ -n "$AK_BIN" ]] || { echo "ak binary not found in tarball" >&2; exit 1; }
install -m 0755 "$AK_BIN" /usr/local/bin/ak
AK_LICENSE="$(find /tmp -maxdepth 3 -type f \( -name 'LICENSE*' -o -name 'license*' \) | head -n1)"
[[ -n "$AK_LICENSE" ]] && install -D -m 0444 "$AK_LICENSE" /usr/local/share/licenses/agentkit/LICENSE || true
rm -rf /tmp/ak.tar.gz /tmp/ak-* /tmp/LICENSE* /tmp/license* 2>/dev/null || true

echo "==> payload: guest tree + modes"
mkdir -p /opt/harness /opt/cloud-harness/skills /opt/cloud-harness/owner-skills \
  /workspace /opt/user-tools /var/cache/harness /tmp/cloud-harness-home
# Normalize modes on the PAYLOAD copy (a staged-tree root), never on / —
# apply-modes.sh recursively chmods its argument and must not see the live
# filesystem. cp -a then preserves the normalized modes into place.
bash "$PAYLOAD/apply-modes.sh" "$PAYLOAD/guest"
cp -a "$PAYLOAD/guest/." /
# sudo ignores sudoers.d entries (and dirs) not owned by root — assert the
# contract instead of assuming cp -a preserved it.
[[ "$(stat -c '%u:%g' /etc/sudoers.d)" == "0:0" \
   && "$(stat -c '%u:%g' /etc/sudoers.d/harness)" == "0:0" ]] \
  || { echo "sudoers drop-in ownership wrong (want 0:0)" >&2; exit 1; }
chown -R 10001:10001 /workspace /opt/user-tools /var/cache/harness /tmp/cloud-harness-home

echo "==> user: harness uid 10001 + passwordless sudo"
if ! id harness >/dev/null 2>&1; then
  useradd --uid 10001 --user-group --create-home --shell /bin/bash harness
fi
[[ "$(id -u harness)" == "10001" ]] || { echo "harness uid is not 10001" >&2; exit 1; }
usermod -aG docker harness
visudo -cf /etc/sudoers >/dev/null
# Verify the drop-in parses and grants NOPASSWD sudo to uid 10001.
runuser -u harness -- sudo -n true

echo "==> systemd: enable required units, disable competitors"
for unit in incus-agent.service systemd-networkd.service systemd-resolved.service \
            systemd-timesyncd.service docker.service containerd.service; do
  if systemctl list-unit-files --no-legend "$unit" 2>/dev/null | grep -q .; then
    systemctl enable "$unit"
  else
    echo "WARN: unit file missing: $unit" >&2
  fi
done

# Network-ownership units are load-bearing, not optional: resolved generates
# the /run/systemd/resolve/stub-resolv.conf our /etc/resolv.conf symlink
# points at, networkd renders the per-VM .network the supervisor pushes, and
# timesyncd keeps guest clocks sane. packages.txt names all three explicitly
# (they are separate Debian binary packages, not --no-install-recommends
# deps), and a base that still lacks a unit file must fail the build here —
# warn-only would ship guests with dead DNS or no link renderer.
for unit in systemd-networkd.service systemd-resolved.service systemd-timesyncd.service; do
  systemctl cat "$unit" >/dev/null 2>&1 \
    || { echo "required unit missing: $unit" >&2; exit 1; }
  unit_state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  case "$unit_state" in
    enabled|enabled-runtime|static|indirect|generated|transient) ;;
    *) echo "required unit not usable: $unit (${unit_state:-unknown})" >&2; exit 1 ;;
  esac
done

# incus-agent is the exec/files/PTY channel — it MUST be present, enabled and
# active in the final image. The build itself runs over this agent, so a
# missing agent would already have failed earlier; assert anyway.
command -v incus-agent >/dev/null || { echo "incus-agent binary missing" >&2; exit 1; }
systemctl cat incus-agent.service >/dev/null 2>&1 || { echo "incus-agent.service missing" >&2; exit 1; }
systemctl enable incus-agent.service || true
incus_agent_state="$(systemctl is-enabled incus-agent.service 2>/dev/null || true)"
case "$incus_agent_state" in
  enabled|enabled-runtime|static|indirect|generated|transient) ;;
  *) echo "incus-agent.service not usable: ${incus_agent_state:-unknown}" >&2; exit 1 ;;
esac

# Networking ownership: systemd-networkd + systemd-resolved. wait-online is
# disabled because the per-VM .network is pushed AFTER first boot — waiting
# for a carrier/config that does not exist yet would stall every start.
disable_unit() {
  if systemctl list-unit-files --no-legend "$1" 2>/dev/null | grep -q .; then
    systemctl disable "$1" 2>/dev/null || true
  fi
}
for unit in systemd-networkd-wait-online.service ssh.service ssh.socket \
            sshd.service sshd.socket NetworkManager.service networking.service \
            dhcpcd.service dhclient.service netplan-networkd.service \
            systemd-networkd-wait-online.socket wpa_supplicant.service \
            cloud-init.service cloud-init-local.service cloud-config.service \
            cloud-final.service cloud-init.target qemu-guest-agent.service \
            qemu-guest-agent.socket qemu-guest-agent.target \
            unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer \
            e2scrub_reap.service; do
  disable_unit "$unit"
done

# Purge cloud-init / qemu-guest-agent if the base image ships them — the VM
# contract is incus-agent only.
for pkg in cloud-init cloud-initramfs qemu-guest-agent; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    apt-get purge -y "${APT_OPTS[@]}" "$pkg" || apt-get purge -y "$pkg"
  fi
done
apt-get autoremove -y --purge || true

# resolved stub: /etc/resolv.conf must be the resolved stub symlink. We only
# ever create the SYMLINK — resolver content is generated by systemd-resolved
# at runtime from the per-VM .network DNS= lines pushed by the supervisor.
if [[ ! -L /etc/resolv.conf ]] || [[ "$(readlink /etc/resolv.conf)" != "/run/systemd/resolve/stub-resolv.conf" ]]; then
  ln -sfn /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
fi

# Network-manager transition LAST among network-touching steps: give
# networkd a temporary DHCP config for the build VM's own uplink so the
# image ends with networkd enabled but NO committed .network files (the
# supervisor pushes the static per-VM config at provision time). Whatever
# happens to connectivity after this point cannot affect the image.
DEFAULT_IFACE="$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')"
if [[ -n "$DEFAULT_IFACE" ]]; then
  cat > "/etc/systemd/network/10-buildvm-dhcp.network" <<EOF
[Match]
Name=${DEFAULT_IFACE}

[Network]
DHCP=yes
EOF
fi
systemctl enable systemd-networkd.service
systemctl start systemd-networkd.service || true
if [[ -f /etc/systemd/network/10-buildvm-dhcp.network ]]; then
  networkctl reload || true
  # Give networkd a moment, then retire competing managers and the temp
  # config — the image must ship with zero .network files.
  sleep 2
  rm -f /etc/systemd/network/10-buildvm-dhcp.network
fi

# Purge EVERY link config the base image (or a competing manager we just
# disabled) may have shipped: /etc/systemd/network, /usr/lib/systemd/network,
# netplan, NetworkManager keyfiles, ifupdown. The supervisor pushes the
# per-VM static .network at workspace provision time — any leftover DHCP
# config would compete with it via match order.
rm -f /etc/systemd/network/*.network /etc/systemd/network/*.netdev \
      /usr/lib/systemd/network/*.network /usr/lib/systemd/network/*.netdev \
      /usr/local/lib/systemd/network/*.network /usr/local/lib/systemd/network/*.netdev \
      /etc/NetworkManager/system-connections/*.nmconnection \
      /etc/network/interfaces 2>/dev/null || true
rm -rf /etc/netplan /etc/network/interfaces.d 2>/dev/null || true
# Assert the zero-config invariant before inventory records it. All
# PERSISTENT networkd search paths are covered: /etc, /usr/lib, and
# /usr/local/lib systemd/network (/run is tmpfs and correctly out of scope).
# The check lives in network-invariant.sh: it enumerates only existing
# dirs, bounds output, checks find's own status, and fails closed — the old
# inline `find | grep -q` could never fire because find exits 1 on the
# just-deleted paths and pipefail masked grep's match.
bash "$PAYLOAD/network-invariant.sh" /
[[ ! -e /etc/network/interfaces ]] \
  || { echo "/etc/network/interfaces still present — refusing to ship" >&2; exit 1; }

echo "==> identity: /etc/cloud-harness/template-identity.env"
install -d -m 0755 /etc/cloud-harness
{
  printf 'CH_VM_TEMPLATE_ID=%s\n' "$TEMPLATE_ID"
  printf 'CH_VM_TEMPLATE_VERSION=%s\n' "$TEMPLATE_VERSION"
} > /etc/cloud-harness/template-identity.env
chmod 0644 /etc/cloud-harness/template-identity.env

echo "==> cleanup: apt cache, logs, machine-id, ssh host keys"
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
find /tmp /var/tmp -mindepth 1 -maxdepth 1 ! -name 'cloud-harness-home' \
  -exec rm -rf -- {} + 2>/dev/null || true
rm -f /root/.bash_history /root/.viminfo /root/.wget-hsts /root/.curlrc /root/.node_repl_history
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
rm -rf /var/log/journal
find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null || true
rm -f /etc/machine-id /var/lib/dbus/machine-id
rm -f /etc/ssh/ssh_host_* 2>/dev/null || true
# Neutral hostname/hosts: the base image's hostname is build-specific and
# every workspace VM shares this image — do not leak it into guests.
printf 'cloudharness-vm\n' > /etc/hostname
cat > /etc/hosts <<'EOF'
127.0.0.1 localhost
127.0.1.1 cloudharness-vm
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

echo "==> inventory"
export CH_VM_TEMPLATE_ID="$TEMPLATE_ID" CH_VM_TEMPLATE_VERSION="$TEMPLATE_VERSION"
bash "$PAYLOAD/inventory.sh" > /root/vm-template-inventory.txt
chmod 0644 /root/vm-template-inventory.txt
# /root/vm-template-inventory.txt is deliberately RETAINED in the image as
# root-readable provenance of the build (which template version produced
# it). The staged payload tree and pushed tar are removed host-side by
# vm-template-build.sh after the inventory pull, before publish.
echo "provision complete: template ${TEMPLATE_ID} v${TEMPLATE_VERSION}"

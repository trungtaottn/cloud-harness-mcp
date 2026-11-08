#!/usr/bin/env bash
# vm-template-build.sh — build/validate tooling for the cloudharness-vm
# Debian 13 guest template (phase-06).
#
# Subcommands:
#   stage --out DIR                     assemble payload + file manifest (offline)
#   check                               static validation gate (offline)
#   render-network --match-mac M --address CIDR --gateway IP --dns "a b"
#                                       render the systemd-networkd fragment
#   diff-inventory A B                  byte-compare two inventory captures
#   scan-secrets PATH...                secret-pattern scan (files or dirs -r)
#   build --output DIR [--alias A] [--keep-vm] [--base-image REF]
#          [--replace-alias] [--expect-base-fingerprint FP]
#                                       LIVE: launch build VM, provision,
#                                       publish image, write manifest
#
# Everything except `build` is offline and safe to run anywhere. `build`
# requires a working `incus` client and is the phase-11 live gate — it is
# intentionally not exercised by unit tests against a real Incus.
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE_DIR="$REPO_ROOT/deploy/vm-template"
WORKER_DIR="$REPO_ROOT/worker"
GUEST_DIR="$TEMPLATE_DIR/guest"
PAYLOAD_NAME="vm-template-payload"
INVENTORY_NAME="vm-template-inventory.txt"
NET_TMPL="$GUEST_DIR/etc/cloud-harness/network/10-cloudharness.network.tmpl"

log() { printf 'vm-template-build: %s\n' "$*" >&2; }
die() { log "ERROR: $*" >&2; exit 1; }
usage() { sed -n '2,21p' "$0" >&2; exit "${1:-2}"; }

json_field() { # json_field <file> <key>
  sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -n1
}

valid_ipv4() { # valid_ipv4 <a.b.c.d>
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local o1 o2 o3 o4
  IFS=. read -r o1 o2 o3 o4 <<< "$1"
  local o
  for o in "$o1" "$o2" "$o3" "$o4"; do ((10#$o <= 255)) || return 1; done
}

# ---------------------------------------------------------------- stage ----
cmd_stage() {
  local out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out) out="${2:?--out needs a directory}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -n "$out" ]] || usage
  [[ -d "$GUEST_DIR" ]] || die "missing $GUEST_DIR"

  local stage="$out/$PAYLOAD_NAME"
  rm -rf "$stage" "$out/manifest.txt"
  mkdir -p "$stage"

  cp -a "$GUEST_DIR" "$stage/guest"
  # Explicit canonical modes via install -m: plain cp applies the builder's
  # umask to new-file modes, which would make manifest.txt (and therefore
  # payloadManifestSha256) differ across builders with different umasks.
  install -m 0755 "$TEMPLATE_DIR/provision.sh" "$TEMPLATE_DIR/inventory.sh" \
     "$TEMPLATE_DIR/tool-pins.sh" "$TEMPLATE_DIR/apply-modes.sh" \
     "$TEMPLATE_DIR/network-invariant.sh" "$stage/"
  install -m 0644 "$TEMPLATE_DIR/packages.txt" "$TEMPLATE_DIR/template.json" "$stage/"
  bash "$TEMPLATE_DIR/apply-modes.sh" "$stage/guest"

  {
    printf '# vm-template payload manifest\n'
    printf '# template_id=%s version=%s\n' \
      "$(json_field "$TEMPLATE_DIR/template.json" templateId)" \
      "$(json_field "$TEMPLATE_DIR/template.json" version)"
    (cd "$stage" && find . -type f -print0 | sort -z | while IFS= read -r -d '' f; do
      sha="$(sha256sum "$f" | cut -d' ' -f1)"
      mode="$(stat -c '%a' "$f")"
      printf '%s\t%s\t%s\n' "$sha" "$mode" "${f#./}"
    done)
  } > "$out/manifest.txt"

  log "staged payload at $stage"
  log "manifest at $out/manifest.txt"
}

# ------------------------------------------------------------- manifest ----
# Parse worker-manifest.txt and verify: every worker/** file is classified
# exactly once (bake or host-only), every bake entry is byte-identical to
# its guest copy, and no host-only basename leaked into the guest tree.
manifest_ok() {
  local manifest="$TEMPLATE_DIR/worker-manifest.txt"
  [[ -f "$manifest" ]] || { log "missing $manifest"; return 1; }
  declare -A bake=() host=()
  local line src dst rel f base
  while IFS= read -r line; do
    line="${line%%#*}"
    [[ -z "${line//[[:space:]]/}" ]] && continue
    if [[ "$line" == !* ]]; then
      src="$(printf '%s' "$line" | cut -f1 | tr -d '!' | xargs)"
      [[ -n "${host[$src]:-}" ]] && { log "duplicate host-only: $src"; return 1; }
      host["$src"]=1
    else
      dst="$(printf '%s' "$line" | cut -f1 | xargs)"
      src="$(printf '%s' "$line" | cut -f2 | xargs)"
      [[ -z "$dst" || -z "$src" ]] && { log "malformed manifest line: $line"; return 1; }
      [[ -n "${bake[$src]:-}" ]] && { log "duplicate bake source: $src"; return 1; }
      bake["$src"]="$dst"
    fi
  done < "$manifest"

  while IFS= read -r f; do
    rel="${f#$REPO_ROOT/}"
    if [[ -z "${bake[$rel]:-}" && -z "${host[$rel]:-}" ]]; then
      log "unclassified worker file: $rel"; return 1
    fi
    if [[ -n "${bake[$rel]:-}" ]]; then
      local target="$GUEST_DIR${bake[$rel]}"
      [[ -f "$target" ]] || { log "missing baked file: $target"; return 1; }
      cmp -s "$f" "$target" || { log "baked drift: $rel -> $target"; return 1; }
    fi
  done < <(find "$WORKER_DIR" -type f | sort)

  for src in "${!bake[@]}"; do
    [[ -f "$REPO_ROOT/$src" ]] || { log "bake source missing: $src"; return 1; }
  done
  for src in "${!host[@]}"; do
    base="$(basename "$src")"
    if find "$GUEST_DIR" -type f -name "$base" | grep -q .; then
      log "host-only file baked into guest: $src"; return 1
    fi
  done
  return 0
}

network_tmpl_ok() {
  [[ -f "$NET_TMPL" ]] || { log "missing $NET_TMPL"; return 1; }
  local ph count rendered
  for ph in "{{GUEST_MATCH_MAC}}" "{{GUEST_CIDR}}" "{{GATEWAY}}" "{{DNS_SERVERS}}"; do
    grep -qF "$ph" "$NET_TMPL" || { log "missing placeholder $ph"; return 1; }
  done
  count="$(grep -oE '\{\{[A-Z_]+\}\}' "$NET_TMPL" | sort -u | wc -l)"
  [[ "$count" == "4" ]] || { log "unexpected placeholder set in network template"; return 1; }
  grep -q '^\[Match\]' "$NET_TMPL" && grep -q '^\[Network\]' "$NET_TMPL" \
    && grep -q '^\[Address\]' "$NET_TMPL" && grep -q '^\[Route\]' "$NET_TMPL" \
    || { log "network template missing required sections"; return 1; }
  grep -q 'DHCP=no' "$NET_TMPL" || { log "network template must disable DHCP"; return 1; }
  rendered="$(sed -e 's/{{GUEST_MATCH_MAC}}/x/g' -e 's/{{GUEST_CIDR}}/x/g' \
                   -e 's/{{GATEWAY}}/x/g' -e 's/{{DNS_SERVERS}}/x/g' "$NET_TMPL")"
  [[ "$rendered" != *'{{'* ]] || { log "unsubstituted placeholder remains"; return 1; }
  return 0
}

template_json_ok() {
  python3 - "$TEMPLATE_DIR/template.json" <<'PY'
import json, sys, re
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    sys.exit(f"template.json parse error: {e}")
for k in ("templateId", "version", "baseImage", "publishAlias"):
    if k not in d:
        sys.exit(f"missing key {k}")
if not re.fullmatch(r"cloudharness-vm-[a-z0-9-]+", d["templateId"]):
    sys.exit("bad templateId")
if not re.fullmatch(r"[0-9]+(\.[0-9]+)*", str(d["version"])):
    sys.exit("bad version")
if not d["baseImage"].startswith(("images:", "http")):
    sys.exit("bad baseImage")
if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", d["publishAlias"]):
    sys.exit("bad publishAlias")
if "amd64" not in d.get("architectures", []):
    sys.exit("architectures must include amd64")
PY
}

packages_ok() {
  local pkgs
  mapfile -t pkgs < <(grep -vE '^[[:space:]]*(#|$)' "$TEMPLATE_DIR/packages.txt")
  ((${#pkgs[@]} > 10)) || { log "packages.txt suspiciously small"; return 1; }
  local dup bad
  dup="$(printf '%s\n' "${pkgs[@]}" | sort | uniq -d)"
  [[ -z "$dup" ]] || { log "duplicate packages: $dup"; return 1; }
  bad="$(printf '%s\n' "${pkgs[@]}" | grep -vE '^[a-z0-9][a-z0-9+.-]*$' || true)"
  [[ -z "$bad" ]] || { log "invalid package names: $bad"; return 1; }
  for required in docker.io docker-cli docker-compose-v2 bubblewrap ripgrep \
                  universal-ctags postgresql-client libpq-dev golang-go \
                  build-essential python3 xz-utils git curl sudo jq bash \
                  ca-certificates; do
    printf '%s\n' "${pkgs[@]}" | grep -qx "$required" \
      || { log "packages.txt missing required: $required"; return 1; }
  done
  if printf '%s\n' "${pkgs[@]}" | grep -qE 'cloud-init|qemu-guest-agent'; then
    log "packages.txt must not install cloud-init/qemu-guest-agent"; return 1
  fi
  return 0
}

tool_pins_ok() {
  local f="$TEMPLATE_DIR/tool-pins.sh"
  [[ -f "$f" ]] || { log "missing $f"; return 1; }
  # every *_SHA256* assignment must be exactly 64 lowercase hex
  local bad
  bad="$(grep -E 'SHA256' "$f" | grep -vE '=[[:space:]]*"[0-9a-f]{64}"' || true)"
  [[ -z "$bad" ]] || { log "malformed sha256 pin: $bad"; return 1; }
  # versions must be pinned literals, never 'latest'
  if grep -nE 'VERSION="?latest"?' "$f"; then
    log "tool-pins.sh must not use latest"; return 1
  fi
  # bash syntax of the fragment
  bash -n "$f" || return 1
  return 0
}

# ----------------------------------------------------------------- check ---
cmd_check() {
  command -v python3 >/dev/null || { log "python3 required for template.json check"; return 1; }
  local fail=0
  check() {
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then log "ok: $name"; else log "CHECK FAIL: $name"; fail=1; fi
  }
  check "worker-manifest complete + drift-free" manifest_ok
  check "networkd template contract" network_tmpl_ok
  check "template.json valid" template_json_ok
  check "packages.txt valid + complete" packages_ok
  check "tool-pins.sh valid" tool_pins_ok
  check "provision.sh syntax" bash -n "$TEMPLATE_DIR/provision.sh"
  check "inventory.sh syntax" bash -n "$TEMPLATE_DIR/inventory.sh"
  check "apply-modes.sh syntax" bash -n "$TEMPLATE_DIR/apply-modes.sh"
  check "guest-df syntax" bash -n "$GUEST_DIR/usr/local/bin/guest-df.sh"
  check "kill-session syntax" bash -n "$GUEST_DIR/usr/local/bin/kill-session.sh"
  check "git-vm syntax" bash -n "$GUEST_DIR/usr/local/bin/git-vm.sh"
  check "build script syntax" bash -n "$SCRIPT_DIR/vm-template-build.sh"
  check "no pty broker / custom daemon files" \
    bash -c "! find '$GUEST_DIR' \( -iname '*pty*' -o -iname '*broker*' \) | grep -q ."
  check "no symlinks in guest payload" \
    bash -c "! find '$GUEST_DIR' -type l | grep -q ."
  check "no key/cert/env material in guest payload" \
    bash -c "! find '$GUEST_DIR' -type f \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name '*.p12' -o -name '*.pfx' -o -name '*.env' \) | grep -q ."
  check "sudoers drop-in exact" \
    grep -qx 'harness ALL=(ALL) NOPASSWD: ALL' "$GUEST_DIR/etc/sudoers.d/harness"
  check "profile.d PATH parity with docker executor" \
    bash -c "grep -q '/opt/harness/bin:/workspace/node_modules/.bin:/opt/user-tools/bin' '$GUEST_DIR/etc/profile.d/harness.sh' && grep -q 'CLOUD_HARNESS_MANAGED_PATH' '$GUEST_DIR/etc/profile.d/harness.sh'"
  check "provision enables + asserts incus-agent" \
    bash -c "grep -q 'incus-agent.service' '$TEMPLATE_DIR/provision.sh' && grep -q 'incus-agent binary missing' '$TEMPLATE_DIR/provision.sh'"
  check "provision never writes resolver content" \
    bash -c "! grep -nE 'nameserver' '$TEMPLATE_DIR/provision.sh' | grep -q ."
  check "secret scan of template tree" scan_secrets "$TEMPLATE_DIR"
  [[ $fail -eq 0 ]] || die "check failed"
  log "check passed"
}

# ---------------------------------------------------------- render-network --
render_network() {
  local match_mac="" address="" gateway="" dns="" tmpl="$NET_TMPL"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --match-mac) match_mac="${2:?}"; shift 2 ;;
      --address)   address="${2:?}";   shift 2 ;;
      --gateway)   gateway="${2:?}";   shift 2 ;;
      --dns)       dns="${2:?}";       shift 2 ;;
      --template)  tmpl="${2:?}";      shift 2 ;;
      *) usage ;;
    esac
  done

  # Strict validators — anything outside these alphabets is rejected so a
  # bad value can never inject extra .network sections.
  [[ "$match_mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] \
    || die "invalid --match-mac: $match_mac"
  [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/(3[0-2]|[12]?[0-9])$ ]] \
    || die "invalid --address CIDR: $address"
  valid_ipv4 "${address%/*}" || die "invalid --address IP: $address"
  valid_ipv4 "$gateway" || die "invalid --gateway: $gateway"
  [[ -n "$dns" ]] || die "--dns is required"
  local -a dns_list=()
  read -ra dns_list <<< "${dns//,/ }"
  ((${#dns_list[@]} >= 1 && ${#dns_list[@]} <= 4)) || die "--dns takes 1-4 resolvers"
  local ip
  for ip in "${dns_list[@]}"; do valid_ipv4 "$ip" || die "invalid DNS resolver: $ip"; done
  local dns_joined="${dns_list[*]}"

  [[ -f "$tmpl" ]] || die "network template not found: $tmpl"
  sed -e "s|{{GUEST_MATCH_MAC}}|${match_mac}|g" \
      -e "s|{{GUEST_CIDR}}|${address}|g" \
      -e "s|{{GATEWAY}}|${gateway}|g" \
      -e "s|{{DNS_SERVERS}}|${dns_joined}|g" "$tmpl"
}

# --------------------------------------------------------- diff-inventory --
diff_inventory() {
  local a="${1:-}" b="${2:-}"
  [[ -n "$a" && -n "$b" && -f "$a" && -f "$b" ]] \
    || die "usage: diff-inventory <file-a> <file-b> (both must exist)"
  if diff -u --label "a:$a" --label "b:$b" "$a" "$b"; then
    log "inventories identical"
  else
    die "inventories differ"
  fi
}

# ------------------------------------------------------------ scan-secrets --
SECRET_NAME_RE='(\.pem|\.key|\.p12|\.pfx|\.keystore|\.jks|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.env(\.|$)|credentials|secret)'
SECRET_CONTENT_RES=(
  '-----BEGIN [A-Z ]*PRIVATE KEY'
  'ghp_[A-Za-z0-9]{20,}'
  'github_pat_[A-Za-z0-9_]{20,}'
  'gho_[A-Za-z0-9]{20,}'
  'ghu_[A-Za-z0-9]{20,}'
  'ghs_[A-Za-z0-9]{20,}'
  'ghr_[A-Za-z0-9]{20,}'
  '(AKIA|ASIA)[0-9A-Z]{16}'
  'xox[baprs]-[A-Za-z0-9-]{10,}'
  'npm_[A-Za-z0-9]{30,}'
  'sk_live_[A-Za-z0-9]{10,}'
  'AIza[0-9A-Za-z_-]{35}'
  'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}'
)

scan_secrets() {
  local hits=0 path re f line
  for path in "$@"; do
    [[ -e "$path" ]] || { log "scan-secrets: missing path $path" >&2; hits=1; continue; }
    while IFS= read -r f; do
      log "secret-like filename: $f" >&2; hits=1
    done < <(find "$path" \( -type f -o -type l \) -printf '%p\n' 2>/dev/null | grep -iE "$SECRET_NAME_RE" || true)
    for re in "${SECRET_CONTENT_RES[@]}"; do
      while IFS= read -r line; do
        log "secret-like content ($re): $line" >&2; hits=1
      done < <(grep -rInIE --exclude-dir=.git "$re" "$path" 2>/dev/null | head -n 20 || true)
    done
  done
  [[ $hits -eq 0 ]] || die "secret scan found material"
  log "secret scan clean"
}

# ------------------------------------------------------------------ build --
# Ownership/identity contract for the disposable build VM:
#   - vm_name is unique per run AND carries BUILD_TOKEN in instance config
#     (user.cloud-harness.build-token). Cleanup deletes ONLY when the live
#     instance's config still shows our token — a name match alone is never
#     treated as ownership proof, so a partial/colliding launch is retained
#     and reported rather than deleted.
#   - file push/pull use the documented <instance>/<path> grammar.
#   - the publish alias is fail-closed: an existing alias aborts the build
#     unless --replace-alias explicitly opts into replacement.
cmd_build() {
  # keep_vm/vm_name/build_token/use_project/base_fp/base_launch_ref/image_fp/
  # inventory_sha/work must be global: the EXIT-trap cleanup_vm runs after
  # cmd_build returns, when locals are out of scope.
  local out="" alias="" base_image="" replace_alias=0 expect_base_fp=""
  keep_vm=0 vm_name="" build_token="" use_project="" base_fp="" base_launch_ref="" image_fp="" inventory_sha="" work=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output)               out="${2:?}"; shift 2 ;;
      --alias)                alias="${2:?}"; shift 2 ;;
      --keep-vm)              keep_vm=1; shift ;;
      --base-image)           base_image="${2:?}"; shift 2 ;;
      --replace-alias)        replace_alias=1; shift ;;
      --expect-base-fingerprint) expect_base_fp="${2:?}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -n "$out" ]] || usage

  # Offline static gate BEFORE any live Incus call — a payload regression
  # must never reach a real build.
  cmd_check || die "static check failed — refusing to launch build VM"

  command -v incus >/dev/null || die "incus client not found"
  command -v tar >/dev/null || die "tar not found"
  command -v python3 >/dev/null || die "python3 not found (manifest writer)"

  local template_json="$TEMPLATE_DIR/template.json"
  local template_id template_version default_alias default_base pinned_base_fp
  template_id="$(json_field "$template_json" templateId)"
  template_version="$(json_field "$template_json" version)"
  default_alias="$(json_field "$template_json" publishAlias)"
  default_base="$(json_field "$template_json" baseImage)"
  pinned_base_fp="$(json_field "$template_json" baseImageFingerprint)"
  [[ -n "$template_id" && -n "$template_version" && -n "$default_base" ]] \
    || die "template.json missing required fields"
  alias="${alias:-$default_alias}"
  base_image="${base_image:-${VM_TEMPLATE_BASE_IMAGE:-$default_base}}"
  [[ "$alias" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "invalid alias: $alias"
  expect_base_fp="${expect_base_fp:-${VM_TEMPLATE_BASE_FP:-$pinned_base_fp}}"
  if [[ -n "$expect_base_fp" && ! "$expect_base_fp" =~ ^[0-9a-f]{64}$ ]]; then
    die "invalid expected base fingerprint: $expect_base_fp"
  fi

  # Refuse a non-empty --output up front: manifest.json/inventory.txt from
  # an earlier run must never be mistaken for this build's result, and we
  # never delete artifacts we did not create this run. An existing EMPTY
  # directory is fine. Enumeration is checked, not suppressed: an unreadable
  # or non-directory --output fails closed instead of looking empty.
  if [[ -e "$out" || -L "$out" ]]; then
    [[ -d "$out" ]] || die "--output '$out' exists and is not a directory"
    local out_listing
    if ! out_listing="$(ls -A -- "$out" 2>&1)"; then
      die "cannot enumerate --output '$out' — refusing to proceed on an unreadable directory: $out_listing"
    fi
    [[ -z "$out_listing" ]] \
      || die "--output '$out' is not empty — refusing to overwrite or remove existing artifacts; choose a fresh directory"
  fi
  mkdir -p "$out"
  out="$(cd "$out" && pwd)"

  use_project="${VM_TEMPLATE_PROJECT:-}"
  incusx() {
    if [[ -n "$use_project" ]]; then
      incus --project "$use_project" "$@"
    else
      incus "$@"
    fi
  }

  # Resolve + validate the base image fingerprint BEFORE launch so a bad or
  # unpinned base fails fast. images:debian/13 is a rolling alias; record
  # the resolved fingerprint and enforce the pin when configured.
  base_fp="$(incusx image info "$base_image" 2>/dev/null \
    | grep -iE '^[[:space:]]*fingerprint:' | head -n1 | awk '{print $2}' | tr -d '[:space:]' || true)"
  [[ "$base_fp" =~ ^[0-9a-f]{64}$ ]] \
    || die "could not resolve base image fingerprint for $base_image"
  if [[ -n "$expect_base_fp" && "$base_fp" != "$expect_base_fp" ]]; then
    die "base image fingerprint drift: got $base_fp want $expect_base_fp (pin via template.json baseImageFingerprint, --expect-base-fingerprint, or VM_TEMPLATE_BASE_FP)"
  fi
  # Launch the RESOLVED fingerprint, never the mutable alias a second time:
  # an alias that moves between `image info` and `launch` would build on
  # different base content than manifest.baseImageFingerprint records.
  # remote:alias becomes remote:fingerprint; a colonless alias resolved on
  # the default remote, so the bare fingerprint pins the same remote.
  if [[ "$base_image" == *:* ]]; then
    base_launch_ref="${base_image%%:*}:${base_fp}"
  else
    base_launch_ref="$base_fp"
  fi

  # Warn whenever the base ref is mutable — a rolling alias OR any
  # colonless ref — unless it is already an immutable 64-hex fingerprint or
  # a pin is configured. Only a fingerprint is reproducible by itself.
  if [[ -z "$expect_base_fp" && ! "$base_image" =~ ^[0-9a-f]{64}$ ]]; then
    log "WARN: base image '$base_image' is mutable and no fingerprint pin is"
    log "WARN: configured — two builds may resolve different base content. Record"
    log "WARN: baseImageFingerprint=$base_fp into template.json for reproducible builds."
  fi

  # Fail-closed alias check: never overwrite an image alias we did not just
  # create unless the operator explicitly opted in with --replace-alias.
  if incusx image info "$alias" >/dev/null 2>&1; then
    if [[ $replace_alias -eq 0 ]]; then
      die "image alias '$alias' already exists — refusing to overwrite. Re-run with --replace-alias to explicitly replace it, or choose a different --alias."
    fi
    log "alias '$alias' exists — --replace-alias given, will republish over it"
  fi

  # Per-run staging OUTSIDE --output: $out receives artifacts only on
  # success, and the EXIT trap removes this mktemp dir (created by this run
  # alone — never operator files). A failed build leaves $out empty.
  work="$(mktemp -d "${TMPDIR:-/tmp}/ch-vm-template-build.XXXXXXXX")" \
    || die "failed to create staging dir"

  # cleanup_vm is defined and the EXIT trap installed IMMEDIATELY after
  # mktemp — before the first call that can fail (stage, secret scan,
  # launch) — so a staging/scanner failure can never leak this run's temp
  # dir. Its globals (work/vm_name/build_token/keep_vm/use_project) are
  # initialized above and incusx is already defined, so pre-launch exits
  # still clean safely; the verify-then-delete VM logic is unchanged.
  # Verify-then-delete: only remove the instance when its live config still
  # carries OUR build token. Anything else (missing instance, foreign or
  # absent token) is retained and reported — never deleted.
  cleanup_vm() {
    # This run's mktemp staging dir is always safe to remove — it was
    # created by this invocation alone. Runs even when no VM was launched.
    if [[ -n "$work" ]]; then rm -rf "$work"; work=""; fi
    if [[ -z "$vm_name" ]]; then return 0; fi
    if [[ $keep_vm -eq 1 ]]; then
      log "keeping build VM $vm_name (--keep-vm)"
      return 0
    fi
    local shown shown_token cfg_rc=0
    shown="$(incusx config show "$vm_name" 2>/dev/null)" || cfg_rc=$?
    # Exact-match the VALUE of the user.cloud-harness.build-token key only —
    # the token appearing in any unrelated key, comment, or free text must
    # never authorize deletion. Handles YAML and JSON-ish renderings; an
    # unparseable/absent key yields empty -> retain (fail-safe direction).
    shown_token="$(printf '%s\n' "$shown" \
      | sed -n -e 's/^[[:space:]]*user\.cloud-harness\.build-token:[[:space:]]*//p' \
             -e 's/^[[:space:]]*"user\.cloud-harness\.build-token"[[:space:]]*:[[:space:]]*//p' \
      | head -n1)"
    shown_token="${shown_token//\"/}"
    shown_token="${shown_token//[[:space:]]/}"
    if [[ "$shown_token" != "$build_token" ]]; then
      if [[ $cfg_rc -ne 0 ]]; then
        log "WARN: could not read config of $vm_name (rc=$cfg_rc) — retaining it."
      elif [[ -n "$shown" ]]; then
        log "WARN: instance $vm_name exists but its config does NOT carry our"
        log "WARN: build token — retaining it (possible name collision or foreign instance)."
      else
        log "no manageable instance $vm_name found — nothing to clean up"
      fi
      return 0
    fi
    incusx stop "$vm_name" --force >/dev/null 2>&1 || true
    incusx delete "$vm_name" >/dev/null 2>&1 \
      || log "WARN: failed to delete verified build VM $vm_name (clean up manually)"
  }
  trap cleanup_vm EXIT

  cmd_stage --out "$work"
  scan_secrets "$work/$PAYLOAD_NAME" >/dev/null

  # Unique-per-run identity, fail-closed: an empty or malformed suffix dies
  # here rather than producing a trailing-dash name/token later.
  local vm_suffix token_suffix
  vm_suffix="$(cat /proc/sys/kernel/random/uuid 2>/dev/null | cut -c1-8 || true)"
  token_suffix="$(head -c8 /dev/urandom 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n' || true)"
  [[ "$vm_suffix" =~ ^[0-9a-f]{8}$ && "$token_suffix" =~ ^[0-9a-f]{16}$ ]] \
    || die "failed to generate unique build identity (uuid/urandom unavailable)"
  vm_name="chm-vm-template-$(date +%s)-$$-$vm_suffix"
  build_token="chm-build-$(date +%s)-$$-$token_suffix"
  local profile="${VM_TEMPLATE_PROFILE:-default}"
  local cpu="${VM_TEMPLATE_BUILD_CPU:-4}"
  local memory="${VM_TEMPLATE_BUILD_MEMORY:-8GiB}"
  local disk="${VM_TEMPLATE_BUILD_DISK:-20GiB}"
  local agent_wait="${VM_TEMPLATE_AGENT_WAIT_SECONDS:-180}"

  local provision_log="$work/provision.log"
  local inventory_local="$work/$INVENTORY_NAME"
  local manifest_json="$out/manifest.json"

  # Verify-then-delete: only remove the instance when its live config still
  # carries OUR build token. Anything else (missing instance, foreign or
  # absent token) is retained and reported — never deleted.
  cleanup_vm() {
    # This run's mktemp staging dir is always safe to remove — it was
    # created by this invocation alone. Runs even when no VM was launched.
    if [[ -n "$work" ]]; then rm -rf "$work"; work=""; fi
    if [[ -z "$vm_name" ]]; then return 0; fi
    if [[ $keep_vm -eq 1 ]]; then
      log "keeping build VM $vm_name (--keep-vm)"
      return 0
    fi
    local shown shown_token cfg_rc=0
    shown="$(incusx config show "$vm_name" 2>/dev/null)" || cfg_rc=$?
    # Exact-match the VALUE of the user.cloud-harness.build-token key only —
    # the token appearing in any unrelated key, comment, or free text must
    # never authorize deletion. Handles YAML and JSON-ish renderings; an
    # unparseable/absent key yields empty -> retain (fail-safe direction).
    shown_token="$(printf '%s\n' "$shown" \
      | sed -n -e 's/^[[:space:]]*user\.cloud-harness\.build-token:[[:space:]]*//p' \
             -e 's/^[[:space:]]*"user\.cloud-harness\.build-token"[[:space:]]*:[[:space:]]*//p' \
      | head -n1)"
    shown_token="${shown_token//\"/}"
    shown_token="${shown_token//[[:space:]]/}"
    if [[ "$shown_token" != "$build_token" ]]; then
      if [[ $cfg_rc -ne 0 ]]; then
        log "WARN: could not read config of $vm_name (rc=$cfg_rc) — retaining it."
      elif [[ -n "$shown" ]]; then
        log "WARN: instance $vm_name exists but its config does NOT carry our"
        log "WARN: build token — retaining it (possible name collision or foreign instance)."
      else
        log "no manageable instance $vm_name found — nothing to clean up"
      fi
      return 0
    fi
    incusx stop "$vm_name" --force >/dev/null 2>&1 || true
    incusx delete "$vm_name" >/dev/null 2>&1 \
      || log "WARN: failed to delete verified build VM $vm_name (clean up manually)"
  }
  trap cleanup_vm EXIT

  log "launching build VM $vm_name from $base_launch_ref (base fp $base_fp)"
  if ! incusx launch --vm --profile "$profile" \
      -c "limits.cpu=${cpu}" -c "limits.memory=${memory}" \
      -c "user.cloud-harness.build-token=${build_token}" \
      --device "root,size=${disk}" \
      "$base_launch_ref" "$vm_name"; then
    log "incus launch failed — cleanup will only delete the instance if it"
    log "carries our build token (partial-launch safety)"
    die "incus launch failed"
  fi

  local waited=0 ok=0
  while ((waited < agent_wait)); do
    if incusx exec "$vm_name" -- /bin/true >/dev/null 2>&1; then ok=1; break; fi
    sleep 2; waited=$((waited + 2))
  done
  [[ $ok -eq 1 ]] || die "incus agent did not become ready within ${agent_wait}s"

  tar -cf "$work/payload.tar" -C "$work" "$PAYLOAD_NAME"
  # Documented grammar: [<remote>:]<instance>/<path> — instance and path are
  # separated by '/', never ':'.
  incusx file push -p "$work/payload.tar" "$vm_name/root/$PAYLOAD_NAME.tar" \
    || die "payload push failed"
  incusx exec "$vm_name" -- tar -xf "/root/$PAYLOAD_NAME.tar" -C /root/ \
    || die "payload extract failed"

  log "provisioning guest (this is the long step)"
  if ! incusx exec "$vm_name" -- \
      /bin/bash "/root/$PAYLOAD_NAME/provision.sh" "/root/$PAYLOAD_NAME" \
      "$template_id" "$template_version" >"$provision_log" 2>&1; then
    tail -n 40 "$provision_log" >&2 || true
    die "provision.sh failed inside build VM (last 40 log lines above; staging dir is cleaned on exit)"
  fi
  scan_secrets "$provision_log" >/dev/null || die "secret-like material in provision log"

  incusx file pull "$vm_name/root/$INVENTORY_NAME" "$inventory_local" \
    || die "inventory pull failed"
  [[ -s "$inventory_local" ]] || die "inventory is empty"

  # Remove build scaffolding before publish so the image ships clean: the
  # staged payload tree (a second full copy of guest/) and the pushed tar
  # are pure residue. Exact literal paths this build created — no globs,
  # no variables. /root/vm-template-inventory.txt is deliberately RETAINED
  # as root-only provenance of the build (see provision.sh).
  incusx exec "$vm_name" -- rm -rf \
    "/root/$PAYLOAD_NAME" "/root/$PAYLOAD_NAME.tar" \
    || die "build residue cleanup failed"

  incusx stop "$vm_name" --force || die "incus stop failed"
  local publish_out="$work/publish.out"
  local publish_args=(publish "$vm_name" --alias "$alias")
  [[ $replace_alias -eq 1 ]] && publish_args+=(--reuse)
  if ! incusx "${publish_args[@]}" >"$publish_out" 2>&1; then
    cat "$publish_out" >&2 || true
    die "incus publish failed"
  fi
  cat "$publish_out" >&2

  image_fp="$(grep -oE '[0-9a-f]{64}' "$publish_out" | head -n1 || true)"
  if [[ -z "$image_fp" ]]; then
    image_fp="$(incusx image info "$alias" 2>/dev/null \
      | grep -iE '^[[:space:]]*fingerprint:' | head -n1 | awk '{print $2}' | tr -d '[:space:]' || true)"
  fi
  [[ "$image_fp" =~ ^[0-9a-f]{64}$ ]] || die "could not resolve published image fingerprint"

  inventory_sha="$(sha256sum "$inventory_local" | cut -d' ' -f1)"
  local payload_manifest_sha
  payload_manifest_sha="$(sha256sum "$work/manifest.txt" | cut -d' ' -f1)"

  # Values arrive via argv — never interpolated into Python source.
  python3 - "$manifest_json" "$template_id" "$template_version" "$alias" \
    "$base_image" "$base_fp" "$image_fp" "$inventory_sha" \
    "$payload_manifest_sha" "$vm_name" <<'PY'
import json, sys, datetime
(out, template_id, template_version, alias, base_image, base_fp,
 image_fp, inventory_sha, payload_manifest_sha, vm_name) = sys.argv[1:11]
manifest = {
  "templateId": template_id,
  "templateVersion": template_version,
  "alias": alias,
  "baseImage": base_image,
  "baseImageFingerprint": base_fp,
  "imageFingerprint": image_fp,
  "templateDigest": inventory_sha,
  "inventorySha256": inventory_sha,
  "payloadManifestSha256": payload_manifest_sha,
  "builtAtUtc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "buildVm": vm_name,
}
with open(out, "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
PY

  cp "$inventory_local" "$out/inventory.txt"
  cp "$work/manifest.txt" "$out/payload-manifest.txt"
  cp "$provision_log" "$out/provision.log"
  rm -rf "$work"; work=""

  log "published image $alias ($image_fp)"
  log "manifest: $manifest_json"
  log "templateDigest: $inventory_sha"
  log "NOTE: the live two-build reproducibility gate (build twice, diff"
  log "inventories) is a phase-11 gate and is NOT claimed by this script."
}

# ------------------------------------------------------------------ main ---
cmd="${1:-}"; shift || true
case "$cmd" in
  stage)           cmd_stage "$@" ;;
  check)           cmd_check ;;
  render-network)  render_network "$@" ;;
  diff-inventory)  diff_inventory "$@" ;;
  scan-secrets)    scan_secrets "$@" ;;
  build)           cmd_build "$@" ;;
  -h|--help|help)  usage 0 ;;
  *) usage ;;
esac

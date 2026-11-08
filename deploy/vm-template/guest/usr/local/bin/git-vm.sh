#!/usr/bin/env bash
# git-vm.sh — credential-free git data-plane helper for VM guests.
#
# The runner's VM git transport stages bundles under /var/cache/harness and
# drives this script for the two guest-side object operations:
#
#   git-vm.sh bundle-create <repoDir> <bundlePath> <rev> [<rev>...]
#   git-vm.sh bundle-fetch   <repoDir> <bundlePath> <historySpec> <refspec> [<refspec>...]
#
# Hard rules (mirroring worker/git-transfer-helper.sh's git_clean):
#   - every git invocation runs with system/global config disabled, no
#     credential helper, no prompts, no redirects, no hooks, no fsmonitor;
#   - bundle paths must be absolute local paths — never URLs, scp-like
#     'host:path' syntax, or option-looking arguments, so no remote (and
#     therefore no credential) can ever be exercised from inside the guest;
#   - revisions/refspecs are shape-checked before reaching git argv.
#
# Shallow semantics (bundle format cannot carry .git/shallow):
#   - bundle-create also copies the checkout's shallow boundary to
#     <bundleDir>/shallow.txt so the host can stage a shallow-aware bare.
#   - bundle-fetch applies the docker import_history contract by hand:
#     '' keeps old marks but still marks transferred boundary commits whose
#     parents are missing (a shallow bundle must never land unmarked),
#     'full' drops marks whose parents have arrived (unshallow), and
#     depth:/since: recompute the boundary as candidates with a missing
#     parent. A mark survives iff a TRUE parent is absent — a complete
#     checkout is never cut back.
set -euo pipefail
umask 077

die() { printf 'git-vm: %s\n' "$*" >&2; exit 2; }

git_vm() {
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  GIT_TERMINAL_PROMPT=0 GIT_PAGER=cat PAGER=cat \
  git -c core.hooksPath=/dev/null -c core.fsmonitor=false -c core.pager=cat \
      -c credential.helper= -c http.followRedirects=false "$@"
}

# Absolute local path only: leading '/', no '..', no ':' (kills scp-like and
# URL forms), no control characters, bounded length.
valid_local_path() {
  [[ ${#1} -ge 2 && ${#1} -le 4096 && $1 == /* && $1 != *..* && $1 != *:* ]] || return 1
  [[ $1 != *$'\n'* && $1 != *$'\r'* && $1 != *$'\t'* ]]
}

# Absolute path of the repository's COMMON git dir (shallow lives there, so
# linked worktrees resolve correctly). Prints nothing on failure.
common_git_dir() {
  local repo=$1 common
  common=$(git_vm -C "$repo" rev-parse --git-common-dir 2>/dev/null) || return 1
  case $common in
    /*) printf '%s\n' "$common" ;;
    *) printf '%s/%s\n' "$repo" "$common" ;;
  esac
}

# 8 MiB covers the 100k-line mark ceiling for sha256 object ids (~6.6 MB);
# host staging enforces the same bound on the sidecar.
MAX_SHALLOW_BYTES=8388608
MAX_SHALLOW_LINES=100000

# Emit <bundleDir>/shallow.txt next to the bundle when the checkout is shallow.
emit_shallow_boundary() {
  local repo=$1 bundle=$2 common shallow size
  common=$(common_git_dir "$repo") || return 0
  shallow=$common/shallow
  [[ -f $shallow && -s $shallow ]] || return 0
  size=$(stat -c %s "$shallow" 2>/dev/null || printf '0')
  [[ $size =~ ^[0-9]+$ && $size -le $MAX_SHALLOW_BYTES ]] || die 'shallow boundary too large to transfer'
  cp "$shallow" "$(dirname "$bundle")/shallow.txt"
}

# Recompute .git/shallow after a bundle fetch. git ignores --depth /
# --update-shallow / --unshallow for bundle sources, so the boundary has to
# be maintained explicitly. Verified against real `git fetch --depth N`:
#   - a transferred boundary mark survives iff at least one of the commit's
#     TRUE parents is absent — object-presence fact, never a cut-back: a
#     complete checkout keeps every parent it already has;
#   - 'full'/depth:/since: also drop old marks whose parents have arrived
#     (deepening through a mark unmarks it; a full bundle unshallows);
#   - '' keeps every old mark verbatim (no depth change requested) but still
#     applies transferred marks whose parents are missing — required for
#     consistency when a shallow bundle lands in any checkout;
#   - only real commit objects are ever marked.
reconcile_shallow() {
  local repo=$1 spec=$2 boundary_file=$3
  local common shallow
  common=$(common_git_dir "$repo") || return 0
  shallow=$common/shallow

  local work transferred bsize tcount
  work=$(mktemp -d "${TMPDIR:-/tmp}/git-vm-shallow.XXXXXX") || return 1
  trap 'rm -rf "$work"' RETURN
  transferred=$work/transferred
  : > "$transferred"
  if [[ -n $boundary_file && -f $boundary_file ]]; then
    bsize=$(stat -c %s "$boundary_file" 2>/dev/null || printf '0')
    [[ $bsize =~ ^[0-9]+$ && $bsize -le $MAX_SHALLOW_BYTES ]] || die 'shallow boundary too large'
    # awk, not grep: an all-invalid sidecar legitimately yields zero marks
    # and grep's exit-1 would trip pipefail+set -e into a silent death.
    cat "$boundary_file" | tr -d '\r' | awk '/^[0-9a-f]{40}$|^[0-9a-f]{64}$/' | sort -u > "$transferred"
  fi
  tcount=$(wc -l < "$transferred" | tr -d ' ')
  [[ $tcount =~ ^[0-9]+$ ]] || die 'shallow boundary is not a regular file'

  case $spec in
    '') [[ $tcount -gt 0 ]] || return 0 ;;  # nothing transferred → untouched
    full|depth:*|since:*) ;;
    *) return 0 ;;
  esac
  local shallow_exists=0
  [[ -f $shallow ]] && shallow_exists=1
  # A complete checkout with no transferred boundary has nothing to do —
  # a complete checkout is never cut back (docker import_history parity).
  [[ $shallow_exists == 1 || $tcount -gt 0 ]] || return 0

  local oldmarks=$work/oldmarks
  { cat "$shallow" 2>/dev/null || true; } \
    | tr -d '\r' | awk '/^[0-9a-f]{40}$|^[0-9a-f]{64}$/' | sort -u > "$oldmarks"
  local ocount total
  ocount=$(wc -l < "$oldmarks" | tr -d ' ')
  total=$((tcount + ocount))
  [[ $total -le $MAX_SHALLOW_LINES ]] || die 'shallow boundary too large'

  local cands=$work/candidates
  cat "$oldmarks" "$transferred" | sort -u > "$cands"

  # Keep only candidates that are commit objects.
  local existing=$work/existing
  git_vm -C "$repo" cat-file --batch-check='%(objectname) %(objecttype)' < "$cands" \
    | awk '$2 == "commit" { print $1 }' | sort -u > "$existing"

  # Parent oids per candidate commit. cat-file --batch is used instead of
  # rev-list because rev-list applies shallow grafting — a marked commit
  # would report no parents and be wrongly dropped. Only the commit HEADER
  # (up to the first blank line) is parsed: a crafted commit message line
  # starting with "parent " must never inject a false boundary parent.
  local oidparent=$work/oidparent
  if [[ -s $existing ]]; then
    git_vm -C "$repo" cat-file --batch < "$existing" | awk '
      /^[0-9a-f]{40,64} commit [0-9]+$/ { oid = $1; inf = 1; next }
      inf && /^$/ { inf = 0; next }
      inf && /^parent / { print oid, $2 }
    ' > "$oidparent"
  else
    : > "$oidparent"
  fi

  # Parent oids that are absent (or not commits) from the object store.
  local allparents=$work/allparents
  cut -d' ' -f2 "$oidparent" | sed '/^$/d' | sort -u > "$allparents"
  local missing=$work/missing
  if [[ -s $allparents ]]; then
    git_vm -C "$repo" cat-file --batch-check='%(objectname) %(objecttype)' < "$allparents" \
      | awk '$2 != "commit" { print $1 }' > "$missing"
  else
    : > "$missing"
  fi

  # Candidates with at least one missing parent. hasmissing ⊆ existing —
  # oidparent was built only from verified commit objects, so membership
  # here already implies a real commit.
  local hasmissing=$work/hasmissing
  awk 'NR==FNR { miss[$1]=1; next } ($2 in miss) { print $1 }' "$missing" "$oidparent" | sort -u > "$hasmissing"

  local keep=$work/keep
  if [[ $shallow_exists == 0 ]]; then
    # Complete checkout: depth specs do not apply (docker parity — a complete
    # checkout is never cut back). Only transferred marks whose parents are
    # actually missing may be added — required for object consistency when
    # a shallow bundle lands, never a depth instruction.
    awk 'NR==FNR { t[$1]=1; next } ($1 in t) { print $1 }' "$transferred" "$hasmissing" | sort -u > "$keep"
  elif [[ $spec == '' ]]; then
    # No depth change: every old mark survives verbatim; transferred marks
    # join only where a true parent is actually missing.
    {
      cat "$oldmarks"
      awk 'NR==FNR { t[$1]=1; next } ($1 in t) { print $1 }' "$transferred" "$hasmissing"
    } | sort -u > "$keep"
  elif [[ $spec == full ]]; then
    # Unshallow request: any candidate survives iff a true parent is missing.
    awk 'NR==FNR { h[$1]=1; next } ($1 in h) { print $1 }' "$hasmissing" "$cands" | sort -u > "$keep"
  else
    # depth:/since: on an already-shallow checkout — the transferred
    # boundary is authoritative (a depth instruction, not an object-presence
    # fact) and is kept whenever it names a real commit; old marks survive
    # only while at least one parent is still missing.
    {
      awk 'NR==FNR { h[$1]=1; next } ($1 in h) { print $1 }' "$hasmissing" "$oldmarks"
      awk 'NR==FNR { e[$1]=1; next } ($1 in e) { print $1 }' "$existing" "$transferred"
    } | sort -u > "$keep"
  fi

  if [[ -s $keep ]]; then
    local keep_tmp="$shallow.tmp.$$"
    cat "$keep" > "$keep_tmp" && mv "$keep_tmp" "$shallow" || { rm -f "$keep_tmp"; return 1; }
  else
    rm -f "$shallow"
  fi
}

cmd=${1:-}
[[ -n $cmd ]] || die 'missing command'
shift

case $cmd in
  bundle-create)
    repo=${1:-}; bundle=${2:-}
    [[ -n $repo && -n $bundle ]] || die 'usage: bundle-create <repoDir> <bundlePath> <rev>...'
    shift 2
    valid_local_path "$repo" || die 'repo dir must be an absolute local path'
    valid_local_path "$bundle" || die 'bundle path must be an absolute local path'
    [[ -d $repo ]] || die "repo dir not found: $repo"
    revs=()
    for rev in "$@"; do
      [[ -n $rev && ${#rev} -le 512 ]] || die 'invalid revision'
      [[ $rev != *$'\n'* && $rev != *$'\r'* && $rev != *$'\t'* ]] || die 'invalid revision'
      case $rev in
        --branches|--tags|--all|--remotes) ;;
        -*) die "option-like revision rejected: $rev" ;;
      esac
      revs+=("$rev")
    done
    [[ ${#revs[@]} -gt 0 ]] || die 'bundle-create requires at least one revision'
    mkdir -p "$(dirname "$bundle")"
    git_vm -C "$repo" bundle create "$bundle" "${revs[@]}"
    emit_shallow_boundary "$repo" "$bundle"
    ;;

  bundle-fetch)
    repo=${1:-}; bundle=${2:-}; history=${3:-}
    [[ -n $repo && -n $bundle && $# -ge 3 ]] || die 'usage: bundle-fetch <repoDir> <bundlePath> <historySpec> <refspec>...'
    shift 3
    valid_local_path "$repo" || die 'repo dir must be an absolute local path'
    valid_local_path "$bundle" || die 'bundle path must be an absolute local path'
    [[ -d $repo ]] || die "repo dir not found: $repo"
    [[ -f $bundle ]] || die "bundle not found: $bundle"

    # historySpec grammar is identical to worker/git-transfer-helper.sh.
    # Bundles ignore --depth/--update-shallow/--unshallow, so the spec only
    # selects which boundary reconciliation runs after the fetch.
    case $history in
      '') ;;
      full) ;;
      depth:*)
        depth=${history#depth:}
        [[ $depth =~ ^[1-9][0-9]{0,5}$ ]] || die 'invalid fetch depth'
        ;;
      since:*)
        since=${history#since:}
        [[ $since =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}([T][0-9:.]+(Z|[+-][0-9]{2}:[0-9]{2}))?$ ]] || die 'invalid fetch shallow-since date'
        ;;
      *) die 'invalid fetch history spec' ;;
    esac

    refspecs=()
    for refspec in "$@"; do
      [[ -n $refspec && ${#refspec} -le 1024 ]] || die 'invalid refspec'
      [[ $refspec != -* && $refspec != *$'\n'* && $refspec != *$'\r'* && $refspec != *$'\t'* ]] || die "invalid refspec: $refspec"
      refspecs+=("$refspec")
    done
    [[ ${#refspecs[@]} -gt 0 ]] || die 'bundle-fetch requires at least one refspec'

    # `git fetch <bundle>` cannot be used: its in-process unbundle negotiates
    # haves WITHOUT shallow cutoffs, so objects below the client's stale
    # boundary marks are silently dropped (verified: a deepened boundary
    # commit never lands). `git bundle unbundle` stores every pack object
    # unconditionally; refs and FETCH_HEAD are then applied explicitly,
    # matching `git fetch` refspec semantics.
    heads_tmp=$(mktemp "${TMPDIR:-/tmp}/git-vm-heads.XXXXXX") || die 'mktemp failed'
    trap 'rm -f "$heads_tmp"' EXIT
    if ! git_vm -C "$repo" bundle unbundle "$bundle" > "$heads_tmp"; then
      die 'bundle unbundle failed'
    fi
    declare -A bundle_oid=()
    line_count=$(wc -l < "$heads_tmp" | tr -d ' ')
    [[ $line_count =~ ^[0-9]+$ && $line_count -le 10000 ]] || die 'bundle advertises too many refs'
    while IFS= read -r line || [[ -n $line ]]; do
      [[ $line =~ ^([0-9a-f]{40}|[0-9a-f]{64})\ ([^ ]+)$ ]] || die 'malformed bundle ref list'
      oid=${BASH_REMATCH[1]}; ref=${BASH_REMATCH[2]}
      { [[ $ref == HEAD ]] || git_vm check-ref-format "$ref" >/dev/null 2>&1; } \
        || die "bundle advertises invalid ref: $ref"
      bundle_oid[$ref]=$oid
    done < "$heads_tmp"
    rm -f "$heads_tmp"
    trap - EXIT
    ((${#bundle_oid[@]} > 0)) || die 'bundle advertises no refs'

    gitdir=$(git_vm -C "$repo" rev-parse --absolute-git-dir) || die 'not a git worktree'
    # git fetch refuses to update the branch checked out in this worktree;
    # update-ref would not, so reject those destinations explicitly.
    current_ref=$(git_vm -C "$repo" symbolic-ref -q HEAD 2>/dev/null || true)

    # Pass 1: resolve and validate every refspec and compute fast-forward
    # verdicts while .git/shallow still reflects the PRE-import boundary —
    # the same ancestry view the original publish loop used, since
    # reconcile_shallow ran only after all updates. No ref is written here,
    # so a rejected refspec can no longer leave earlier destinations
    # partially published.
    pub_specs=()
    fetch_head=()
    for rs in "${refspecs[@]}"; do
      force=0
      src=$rs; dst=''
      [[ $rs == +* ]] && { force=1; rs=${rs#+}; }
      if [[ $rs == *:* ]]; then
        src=${rs%%:*}; dst=${rs#*:}
        [[ -n $src && -n $dst ]] || die "invalid refspec: $rs"
      fi
      oid=${bundle_oid[$src]:-}
      [[ -n $oid ]] || die "couldn't find remote ref $src"
      case $src in
        refs/heads/*) desc="branch '${src#refs/heads/}' of $bundle" ;;
        refs/tags/*)  desc="tag '${src#refs/tags/}' of $bundle" ;;
        *)            desc="ref '$src' of $bundle" ;;
      esac
      fetch_head+=("$oid"$'\t\t'"$desc")
      [[ -z $dst ]] && continue
      git_vm check-ref-format "$dst" >/dev/null 2>&1 || die "invalid refspec dst: $dst"
      [[ $dst != HEAD && $dst != "$current_ref" ]] || die "refusing to update checked-out ref $dst"
      old=
      if [[ $force == 0 ]]; then
        old=$(git_vm -C "$repo" rev-parse --verify --quiet "$dst" 2>/dev/null || true)
        if [[ -n $old && $old != "$oid" ]]; then
          git_vm -C "$repo" merge-base --is-ancestor "$old" "$oid" || die "non-fast-forward update to $dst"
        fi
      fi
      pub_specs+=("$force"$'\x1f'"$dst"$'\x1f'"$oid"$'\x1f'"$old")
    done

    # Connectivity gate BEFORE any ref is published. `bundle unbundle`
    # stores objects without creating refs; fsck --connectivity-only
    # accepts explicit head objects, so the advertised tips are checked
    # directly — no temporary refs for concurrent git callers to see and
    # nothing to leak on failure. Reconcile the shallow boundary first
    # (it only rewrites .git/shallow, atomically) so legitimate shallow
    # marks are honored by fsck; an EXIT trap then restores the pre-import
    # boundary on ANY exit before publication completes — die, error, or
    # caught signal — so a failed import leaves repo state untouched. On
    # success the imported objects stay reachable through the published
    # refs; unreachable leftovers are reclaimed by gc.
    common=$(common_git_dir "$repo") || die 'not a git worktree'
    shallow_file=$common/shallow
    had_shallow=0
    shallow_bak=
    if [[ -f $shallow_file ]]; then
      had_shallow=1
      shallow_bak=$(mktemp "${TMPDIR:-/tmp}/git-vm-shallow-bak.XXXXXX") || die 'mktemp failed'
      cp -- "$shallow_file" "$shallow_bak" || { rm -f "$shallow_bak"; die 'shallow boundary backup failed'; }
    fi
    gate_armed=0
    restore_on_exit() {
      [[ ${gate_armed:-0} == 1 ]] || return 0
      if [[ $had_shallow == 1 ]]; then
        cp -- "$shallow_bak" "$shallow_file" || true
      else
        rm -f "$shallow_file"
      fi
      if [[ -n $shallow_bak ]]; then
        rm -f "$shallow_bak"
      fi
      return 0
    }
    gate_armed=1
    trap restore_on_exit EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if ! reconcile_shallow "$repo" "$history" "$(dirname "$bundle")/shallow.txt"; then
      die 'bundle shallow reconcile failed'
    fi

    # Unique advertised head oids, chunked so argv stays bounded; every
    # chunk runs inside this exec's existing deadline.
    declare -A gate_seen=()
    gate_oids=()
    for bref in "${!bundle_oid[@]}"; do
      goid=${bundle_oid[$bref]}
      if [[ -z ${gate_seen[$goid]:-} ]]; then
        gate_seen[$goid]=1
        gate_oids+=("$goid")
      fi
    done
    fsck_out=$(mktemp "${TMPDIR:-/tmp}/git-vm-fsck-out.XXXXXX") || die 'mktemp failed'
    fsck_err=$(mktemp "${TMPDIR:-/tmp}/git-vm-fsck-err.XXXXXX") || { rm -f "$fsck_out"; die 'mktemp failed'; }
    fsck_failed=0
    for ((c = 0; c < ${#gate_oids[@]}; c += 500)); do
      : > "$fsck_out"; : > "$fsck_err"
      if ! git_vm -C "$repo" fsck --connectivity-only --no-dangling "${gate_oids[@]:c:500}" >"$fsck_out" 2>"$fsck_err"; then
        fsck_failed=1
        break
      fi
    done
    if [[ $fsck_failed == 1 ]]; then
      detail=$(cat "$fsck_out" "$fsck_err" | head -c 400 | tr '\n' ' ')
      rm -f "$fsck_out" "$fsck_err"
      die "bundle fails connectivity validation: $detail"
    fi
    rm -f "$fsck_out" "$fsck_err"

    # Pass 2: publish the validated destinations in ONE update-ref
    # transaction — either every ref lands or none does, so a failed write
    # cannot leave partial refs either. The old value recorded in pass 1 is
    # re-verified atomically at commit; an all-zero old value asserts the
    # destination did not exist (create-only), matching the pass-1 check.
    {
      printf 'start\n'
      for entry in "${pub_specs[@]}"; do
        IFS=$'\x1f' read -r pforce pdst poid pold <<< "$entry"
        if [[ $pforce == 1 ]]; then
          printf 'update %s %s\n' "$pdst" "$poid"
        elif [[ -z $pold ]]; then
          printf 'update %s %s %s\n' "$pdst" "$poid" "${poid//?/0}"
        elif [[ $pold != "$poid" ]]; then
          printf 'update %s %s %s\n' "$pdst" "$poid" "$pold"
        fi
      done
      printf 'commit\n'
    } | git_vm -C "$repo" update-ref --stdin >/dev/null || die 'ref publication failed'
    # Refs are committed: the reconciled shallow boundary is now the
    # desired state, so the rollback trap disarms before FETCH_HEAD. The
    # backup file itself is dead weight now — remove it here because the
    # disarmed EXIT trap will never run restore_on_exit again.
    gate_armed=0
    if [[ -n $shallow_bak ]]; then
      rm -f -- "$shallow_bak"
      shallow_bak=
    fi
    if ((${#fetch_head[@]} > 0)); then
      printf '%s\n' "${fetch_head[@]}" > "$gitdir/FETCH_HEAD"
    fi
    ;;

  *)
    die "unknown command: $cmd"
    ;;
esac

#!/usr/bin/env node
/**
 * appliance-shim.mjs — sentinel process-group leader for `vm.export`.
 *
 * Spawned by spawnApplianceProcess (src/runtime.ts) as the DETACHED child, so
 * this process is the session + process-group leader (pgid == process.pid)
 * for the whole appliance run. It spawns the real appliance argv
 * (virt-tar-out -> guestfish -> qemu) with stdio:'inherit' — appliance
 * stdout/stderr flow straight into the supervisor's pipes — and then:
 *
 * 1. Arms ONE net.Socket on fd 3, the spawn-private control channel. ANY
 *    outcome is a cancel request and self-administers `kill(-pid, sig)`:
 *      - data  -> explicit cancel from the supervisor (overflow/abort/
 *                 timeout/reap-timeout), optional ":SIGNAL" suffix;
 *      - end   -> supervisor's socket closed = parent death/disconnect;
 *      - error -> broken channel.
 *    The group signal is sent BY the shim while it is provably alive, so the
 *    pgid cannot have been recycled — no supervisor-side kill(-pid), no
 *    check-then-signal gap. fd 3 is never inherited by the appliance
 *    (stdio:'inherit' maps only fds 0-2), so no descendant can cancel or
 *    even see the channel.
 *    NOTE: fd 3 must be a net.Socket, NOT a raw fs.read — a permanently
 *    pending fs.read threadpool request blocks process.exit() on Node 26,
 *    which would wedge the drain-finish path. Socket reads are event-loop
 *    handles and never block exit.
 * 2. Arms a deadline backstop (--deadline-ms=N, export timeout + grace) for
 *    the case where the supervisor event loop is wedged and never cancels.
 * 3. Traps SIGTERM/SIGINT and escalates to a group SIGKILL — a targeted
 *    signal to the shim alone must not orphan the appliance. (SIGKILL is
 *    uncatchable regardless.)
 * 4. After the appliance exits, keeps living until /proc PROVES no other
 *    member of its process group remains — only then exits, propagating the
 *    appliance's real exit code, or re-raising its fatal signal (with the
 *    SIGTERM/SIGINT traps removed first) so the supervisor's 'close' reports
 *    the identical signal. This makes the shim's exit equivalent to "group
 *    fully drained": while it lives the pgid is pinned by a member we own;
 *    once it exits there is nothing left to kill. The drain proof is
 *    fail-closed: if /proc cannot be scanned or a member's stat is unreadable
 *    for any reason other than ENOENT/ESRCH disappearance, the shim kills its
 *    own group rather than fabricate an empty count.
 *
 * Diagnostics go to fd 2 only — fd 1 carries the tar stream and must stay
 * byte-clean.
 */
import { spawn } from 'node:child_process';
import { Socket } from 'node:net';
import { readdirSync, readFileSync } from 'node:fs';

const ME = process.pid;
const CONTROL_FD = 3;
const DRP_POLL_MS = 50;
const RERAISE_FALLBACK_MS = 500;
const TRAPPED_SIGNALS = ['SIGTERM', 'SIGINT'];

/**
 * Test-only fault injection for the /proc drain scan, passed as
 * `--scan-fail=<mode>` BEFORE the `--` separator. spawnApplianceProcess never
 * emits this flag and the production env allowlist cannot smuggle it in, so
 * it is unreachable outside direct test spawns:
 *   readdir              -> readdirSync('/proc') throws EIO
 *   stat:<pid>:<code>    -> that pid's stat read throws <code> (e.g. EACCES)
 *   stat:<pid>:ENOENT    -> that pid's stat read throws ENOENT (disappearance)
 */
function parseArgv(argv) {
  const sep = argv.indexOf('--');
  const head = sep === -1 ? argv : argv.slice(0, sep);
  const appliance = sep === -1 ? [] : argv.slice(sep + 1);
  let deadlineMs = 0;
  let scanFail = '';
  for (const a of head) {
    if (a.startsWith('--deadline-ms=')) {
      const n = Number(a.slice('--deadline-ms='.length));
      deadlineMs = Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
    } else if (a.startsWith('--scan-fail=')) {
      scanFail = a.slice('--scan-fail='.length);
    }
  }
  return { appliance, deadlineMs, scanFail };
}

/** Parses `stat:<pid>:<ERRNO>`; null for any other mode. */
function parseStatFail(scanFail) {
  const m = /^stat:(\d+):([A-Z]+)$/.exec(scanFail);
  return m === null ? null : { pid: Number(m[1]), code: m[2] };
}

function fakeProcError(code) {
  const error = new Error(`injected /proc scan failure (${code})`);
  error.code = code;
  return error;
}

/** Signals the whole group from inside — the shim is alive, so pgid==ME is ours. */
function selfKillGroup(sig) {
  try {
    process.kill(-ME, sig);
  } catch {
    try {
      process.kill(ME, sig);
    } catch {
      /* already gone */
    }
  }
  // Unreachable for fatal signals; belt for exotic cases.
  process.exit(137);
}

function cancelSignal(msg) {
  // Protocol: 'K' optionally followed by ':SIGNAL'. Anything else -> SIGKILL.
  const m = /^K:?([A-Z0-9]+)?$/.exec(typeof msg === 'string' ? msg.trim() : '');
  const sig = m?.[1];
  return sig !== undefined && /^SIG[A-Z0-9]+$/.test(sig) ? sig : 'SIGKILL';
}

const { appliance, deadlineMs, scanFail } = parseArgv(process.argv.slice(2));
const statFail = parseStatFail(scanFail);

if (appliance.length === 0 || appliance[0] === undefined || appliance[0] === '') {
  process.stderr.write('appliance-shim: missing appliance argv after --\n');
  process.exit(127);
}

let childCode = 1;
let childSignal = null;
let terminating = false;
let finished = false;
let controlSocket = null;
let deadlineTimer = null;
let drainTimer = null;

function terminateGroup(sig) {
  if (terminating || finished) return;
  terminating = true;
  selfKillGroup(sig);
}

// --- control channel: any outcome cancels ------------------------------------
{
  // fd 3 is the child-side end of the spawn-private socketpair. Adopting it
  // as a read-only net.Socket gives 'data' (explicit cancel), 'end' (peer
  // closed = supervisor death/disconnect) and 'error' (broken channel).
  controlSocket = new Socket({ fd: CONTROL_FD, readable: true, writable: false });
  controlSocket.on('data', (chunk) => {
    if (finished) return;
    terminateGroup(cancelSignal(chunk.toString('utf8')));
  });
  controlSocket.on('end', () => {
    if (!finished) terminateGroup('SIGKILL');
  });
  controlSocket.on('error', () => {
    if (!finished) terminateGroup('SIGKILL');
  });
}

// --- deadline backstop ---------------------------------------------------------
if (deadlineMs > 0) {
  deadlineTimer = setTimeout(() => terminateGroup('SIGKILL'), deadlineMs);
  deadlineTimer.unref?.();
}

// --- targeted-term escalation --------------------------------------------------
// Handlers are named so finish() can REMOVE them before re-raising the
// appliance's fatal signal: a still-installed trap would swallow the
// re-raised SIGTERM/SIGINT and degrade it to the exit(1) fallback.
const trapHandlers = {};
for (const sig of TRAPPED_SIGNALS) {
  trapHandlers[sig] = () => terminateGroup('SIGKILL');
  process.on(sig, trapHandlers[sig]);
}

// --- spawn the appliance into our process group -------------------------------
function spawnAppliance() {
  try {
    return spawn(appliance[0], appliance.slice(1), { stdio: 'inherit' });
  } catch (error) {
    process.stderr.write(`appliance-shim: spawn failed: ${error?.message ?? error}\n`);
    process.exit(127);
  }
}
const child = spawnAppliance();

child.on('error', (error) => {
  process.stderr.write(`appliance-shim: appliance spawn error: ${error?.message ?? error}\n`);
  process.exit(127);
});

child.on('exit', (code, signal) => {
  childCode = code ?? 1;
  childSignal = signal;
  startDrainWatch();
});

// --- drain watch: exit only when no other group member remains -----------------
/** ENOENT/ESRCH means the process genuinely disappeared mid-scan. */
function isProcDisappearance(error) {
  return (
    error !== null &&
    typeof error === 'object' &&
    (error.code === 'ENOENT' || error.code === 'ESRCH')
  );
}

/**
 * Counts OTHER live members of our process group. Throws on ANY unverifiable
 * read — the caller must treat a throw as "drain cannot be proven" and fail
 * closed, never as an empty group. Only ENOENT/ESRCH per-pid stat failures
 * are tolerated, and only because they prove that pid exited.
 */
function groupMemberCount() {
  let entries;
  try {
    if (scanFail === 'readdir') throw fakeProcError('EIO');
    entries = readdirSync('/proc');
  } catch (error) {
    throw new Error(`/proc readdir failed: ${error?.code ?? error?.message ?? error}`);
  }
  let count = 0;
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    if (pid === ME) continue;
    let stat;
    try {
      if (statFail !== null && pid === statFail.pid) throw fakeProcError(statFail.code);
      stat = readFileSync(`/proc/${entry}/stat`, 'utf8');
    } catch (error) {
      if (isProcDisappearance(error)) continue; // exited between readdir and read
      throw new Error(`/proc/${entry}/stat unreadable: ${error?.code ?? error?.message ?? error}`);
    }
    // comm may contain spaces and ')': fields after the LAST ')' are
    // state ppid pgrp session ... A stat without ')' is malformed — the
    // member's group is unverifiable, so fail closed rather than skip it.
    const closeParen = stat.lastIndexOf(')');
    const rest = closeParen === -1 ? [] : stat.slice(closeParen + 2).split(' ');
    // rest[2] is pgrp — a stat too short to contain it leaves membership
    // unverifiable, so fail closed rather than skip the entry.
    if (rest.length < 3 || !/^\d+$/.test(rest[2] ?? '')) {
      throw new Error(`/proc/${entry}/stat malformed`);
    }
    if (rest[2] === String(ME)) count += 1;
  }
  return count;
}

function finish() {
  if (finished) return;
  finished = true;
  if (drainTimer !== null) clearInterval(drainTimer);
  if (deadlineTimer !== null) clearTimeout(deadlineTimer);
  // Detach the control channel first: a supervisor close racing natural drain
  // must not turn a clean exit into a group kill.
  try {
    controlSocket?.destroy();
  } catch {
    /* already closed */
  }
  if (childSignal !== null) {
    // Re-raise the appliance's fatal signal so 'close' reports it faithfully.
    // The SIGTERM/SIGINT traps MUST be removed first: with them installed the
    // re-raised signal would hit terminateGroup() (already 'finished') and be
    // swallowed, degrading the report to the exit(1) fallback. With the traps
    // gone the signal takes its default disposition and the shim dies BY that
    // signal — genuine fidelity. (SIGKILL was never trappable anyway.)
    for (const sig of TRAPPED_SIGNALS) {
      try {
        process.removeListener(sig, trapHandlers[sig]);
      } catch {
        /* already removed */
      }
    }
    process.exitCode = 1;
    try {
      process.kill(ME, childSignal);
    } catch {
      /* invalid signal name — fall through to exit code */
    }
    setTimeout(() => process.exit(1), RERAISE_FALLBACK_MS);
    return;
  }
  process.exit(childCode);
}

function drainTick() {
  let others;
  try {
    others = groupMemberCount();
  } catch {
    // Unverifiable scan: /proc unreadable or a member's stat failed for a
    // reason other than disappearance. We cannot prove the group drained —
    // fail CLOSED by killing our own group. Fabricating an empty count here
    // could report success while descendants still hold pipes/the image.
    terminateGroup('SIGKILL');
    return;
  }
  if (others === 0) finish();
}

function startDrainWatch() {
  // Arm the interval BEFORE the first tick: an already-empty group finishes
  // synchronously and finish() must be able to clear a live timer.
  drainTimer = setInterval(drainTick, DRP_POLL_MS);
  drainTick();
}

import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, link, lstat, mkdir, open, rename, rm, stat } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { HarnessError, type ExecutorBackendKind, type RunnerConfig } from '@cloud-harness/contracts';
import { validateRepositoryUrl } from './repository-policy.js';
import { createVmExportWorkspace, type VmExportWorkspaceFn } from './backend-factory.js';
import type { VmSupervisorGateway } from './incus-executor-backend.js';
import type { ExecResult, ExecutorBackend, ProvisionContext } from './executor-backend.js';
import type { GitDataPlane } from './git-data-plane.js';
import {
  assertVmTransferOk,
  BARE_DIR_NAME,
  extractTarSafe,
  findCheckoutRoots,
  inspectVmCheckout,
  validateVmShallowBoundary,
  vmRevisionArgs,
  vmShallowSidecarPath,
  VmGitStaging,
  VM_HELPER_GID,
  VM_HELPER_UID,
  VM_MAX_BUNDLE_BYTES,
  VM_MAX_SHALLOW_BOUNDARY_BYTES,
  VM_SHALLOW_BOUNDARY_NAME,
  type VmCheckoutInspection,
  type VmHelperResult,
  type VmHelperRunner
} from './git-vm-staging.js';

/**
 * incus-vm `GitDataPlane`: the workspace checkout lives ONLY inside the guest
 * disk at `/workspace`; host staging bare/bundles live under the job path via
 * {@link VmGitStaging}. Objects cross through digest/trailer-verified
 * `pushTree`/`pullTree`/`pullFile` — never through guest-visible credentials.
 *
 * Remote operations (`remoteFetch`/`remotePush`/`probeRemoteRefOid`) keep the
 * docker broker boundary: credentialed work happens ONLY in host-side
 * `git-transfer-helper.sh` containers (token on stdin, never argv/env/files),
 * the guest sees local bundle files exclusively. There is deliberately no
 * pause/freeze — Incus freeze would kill the agent channel and guest root can
 * evade the cgroup freezer; atomicity comes from git-native bundle objects,
 * atomic ref updates, index.lock, and the unchanged force-with-lease CAS.
 */

const GUEST_CHECKOUT = '/workspace';
const GUEST_XFER_ROOT = '/var/cache/harness';
const GUEST_VM_SCRIPT = '/usr/local/bin/git-vm.sh';
const GUEST_GIT_TIMEOUT_MS = 30_000;
const GUEST_GIT_MAX_BYTES = 65_536;
const GUEST_BUNDLE_TIMEOUT_MS = 300_000;
const OFFLINE_MAX_ENTRIES = 500_000;

async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

export interface VmGitTransportDeps {
  backend: ExecutorBackend;
  config: RunnerConfig;
  instanceId: string;
  /** Host helper runner; defaults to the docker ephemeral-helper runner. */
  runner?: VmHelperRunner;
  /**
   * Offline export seam — the landed `backend-factory.ts` type, i.e.
   * `createVmExportWorkspace(supervisorClient)`. Writes the stopped VM's
   * `/workspace` tar to `opts.destPath` and resolves `{sha256, bytes}`.
   * Absent → `VM_CAPABILITY_UNSUPPORTED`.
   */
  exportWorkspace?: VmExportWorkspaceFn;
  /**
   * Supervisor gateway — convenience for the `incusGitPlaneFactory` wiring:
   * when set and `exportWorkspace` is not, the transport builds
   * `createVmExportWorkspace(supervisorClient)` itself so offline export is
   * never silently unwired.
   */
  supervisorClient?: VmSupervisorGateway;
  /**
   * Repository-URL validation seam. Defaults to `validateRepositoryUrl`
   * against `config.allowedGitHosts` (https/443/allowlist/public-DNS). Tests
   * inject a passthrough so local-path remotes work offline.
   */
  validateUrl?: (raw: string) => Promise<string | URL>;
}

export interface VmRemoteFetchParams {
  repositoryUrl: string;
  /** '' or undefined = all heads; 'refs/heads/X' = one branch; anything else = FETCH_HEAD only. */
  remoteRef?: string;
  /** Same grammar as git-transfer-helper: '', 'full', 'depth:N', 'since:DATE'. */
  historySpec?: string;
  /** Read credential — stdin to the host helper only, never guest-visible. */
  token?: string;
}

export interface VmRemotePushParams {
  repositoryUrl: string;
  /** Normalized `src:dst` refspec (delete form `:dst` allowed). */
  refspec: string;
  /** Lease value: 'absent', a hex object id, or undefined for a plain push. */
  expectedRemoteOid?: string;
  /** Write credential — stdin to the host helper only. */
  token?: string;
}

export interface VmOfflineExportParams {
  maxBytes: number;
  /** Clone ref used for the unpushed-commit exclusion, mirroring close_check. */
  cloneRef?: string;
}

export interface VmOfflineExportResult extends VmCheckoutInspection {
  /** Staging op dir holding export.tar + the extracted tree; remove via staging.removeOpDir or leave for caller cleanup. */
  workDir: string;
  /** Extracted checkout root inside workDir (undefined when no .git found). */
  checkoutDir?: string;
}

/**
 * Remote-operation surface beyond the `GitDataPlane` contract — the brokered
 * credential boundary the service's docker `runGitTransferHelper` /
 * `probeRemoteRefOid` paths map onto for incus-vm. Callers narrow
 * `GitDataPlane` to this interface (or `instanceof VmGitTransport`).
 */
export interface VmGitRemoteOps {
  remoteFetch(ctx: ProvisionContext, params: VmRemoteFetchParams): Promise<{ fetched: VmHelperResult; imported: ExecResult }>;
  remotePush(ctx: ProvisionContext, params: VmRemotePushParams): Promise<VmHelperResult>;
  probeRemoteRefOid(ctx: ProvisionContext, params: { repositoryUrl: string; branch: string; token?: string }): Promise<string | null | undefined>;
  exportCheckoutOffline(ctx: ProvisionContext, params: VmOfflineExportParams): Promise<VmOfflineExportResult>;
}

export class VmGitTransport implements GitDataPlane, VmGitRemoteOps {
  readonly backend: ExecutorBackendKind = 'incus-vm';
  private readonly deps: VmGitTransportDeps;
  private readonly staging: VmGitStaging;
  private readonly exportWorkspace: VmExportWorkspaceFn | undefined;

  constructor(deps: VmGitTransportDeps) {
    this.deps = deps;
    this.exportWorkspace = deps.exportWorkspace
      ?? (deps.supervisorClient ? createVmExportWorkspace(deps.supervisorClient) : undefined);
    this.staging = new VmGitStaging({
      config: deps.config,
      instanceId: deps.instanceId,
      ...(deps.runner !== undefined ? { runner: deps.runner } : {})
    });
  }

  /** Exposed for callers that need the same staging helpers (e.g. offline inspection). */
  get gitStaging(): VmGitStaging {
    return this.staging;
  }

  stagingDir(ctx: ProvisionContext): string {
    return ctx.stagingDir;
  }

  // ------------------------------------------------------------------
  // Host-path confinement — every host path must live under the job path.
  // ------------------------------------------------------------------

  private hostPathUnderJob(ctx: ProvisionContext, hostPath: string): string {
    const job = resolve(ctx.record.workspacePath);
    const abs = resolve(hostPath);
    const rel = relative(job, abs);
    if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
      throw new HarnessError('INVALID_INPUT', 'git data-plane host path must live under the workspace job path', 400, false);
    }
    return abs;
  }

  private newGuestXferDir(): string {
    return `${GUEST_XFER_ROOT}/git-xfer-${randomBytes(8).toString('hex')}`;
  }

  private async linkOrCopy(src: string, dst: string): Promise<void> {
    try {
      await link(src, dst);
    } catch {
      await copyFile(src, dst);
    }
  }

  // ------------------------------------------------------------------
  // Guest exec primitives
  // ------------------------------------------------------------------

  /**
   * Workspace env for `git-vm.sh` helper execs — deliberately NOT
   * `ctx.environment`: bundle transport never needs workspace secrets, and a
   * secret-bearing env would widen the blast radius of an untrusted checkout
   * (same rule as the docker read-only git helper fallback).
   */
  private guestHelperEnv(): Record<string, string> {
    return {
      PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      HOME: '/tmp/cloud-harness-home',
      LANG: 'C.UTF-8',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_SYSTEM: '/dev/null',
      GIT_TERMINAL_PROMPT: '0',
      GIT_PAGER: 'cat',
      PAGER: 'cat'
    };
  }

  private execSignal(ctx: ProvisionContext, signal?: AbortSignal): AbortSignal | undefined {
    return signal ?? ctx.signal;
  }

  /** Credential-free `git -C /workspace …` — the GitDataPlane guestGit contract. */
  async guestGit(ctx: ProvisionContext, args: string[], opts: { timeoutMs?: number; maxBytes?: number; signal?: AbortSignal } = {}): Promise<ExecResult> {
    if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
      throw new HarnessError('INVALID_INPUT', 'guestGit args must be a string array', 400, false);
    }
    const signal = this.execSignal(ctx, opts.signal);
    return this.deps.backend.exec(ctx, {
      argv: ['git', '-C', GUEST_CHECKOUT, ...args],
      environment: ctx.environment,
      timeoutMs: opts.timeoutMs ?? GUEST_GIT_TIMEOUT_MS,
      maxBytes: opts.maxBytes ?? GUEST_GIT_MAX_BYTES,
      ...(signal ? { signal } : {})
    });
  }

  /** Hardened `git-vm.sh` exec — controlled env, no workspace secrets. */
  private async guestVm(ctx: ProvisionContext, args: string[], opts: { timeoutMs?: number; maxBytes?: number; signal?: AbortSignal } = {}): Promise<ExecResult> {
    const signal = this.execSignal(ctx, opts.signal);
    return this.deps.backend.exec(ctx, {
      argv: [GUEST_VM_SCRIPT, ...args],
      environment: this.guestHelperEnv(),
      timeoutMs: opts.timeoutMs ?? GUEST_BUNDLE_TIMEOUT_MS,
      maxBytes: opts.maxBytes ?? 4 * 1024 * 1024,
      ...(signal ? { signal } : {})
    });
  }

  /**
   * Defensive guest-side `mkdir -p` before every `pushTree`/`pullTree` into a
   * fresh xfer dir — the generic tree transport is owned by the supervisor
   * backend, so the git plane guarantees its own precondition instead of
   * depending on backend mkdir semantics.
   */
  private async guestMkdir(ctx: ProvisionContext, guestPath: string): Promise<void> {
    const result = await this.deps.backend.exec(ctx, {
      argv: ['mkdir', '-p', '--', guestPath],
      environment: this.guestHelperEnv(),
      timeoutMs: 30_000,
      maxBytes: 8_192,
      ...(ctx.signal ? { signal: ctx.signal } : {})
    });
    if (result.exitCode !== 0) {
      throw new HarnessError('UNAVAILABLE', `guest transfer dir creation failed: ${result.stderr || result.stdout}`.slice(0, 2_000), 502, true);
    }
  }

  /** Copies the host staging bare's shallow boundary next to a bundle for the guest to reconcile. */
  private async copyShallowBoundary(opDir: string, hostXfer: string): Promise<void> {
    const shallow = join(opDir, BARE_DIR_NAME, 'shallow');
    const info = await lstat(shallow).catch(() => undefined);
    if (info === undefined) return;
    if (!info.isFile() || info.size === 0 || info.size > VM_MAX_SHALLOW_BOUNDARY_BYTES) {
      throw new HarnessError('LIMIT_EXCEEDED', 'staged shallow boundary is not a bounded regular file', 413, false);
    }
    await copyFile(shallow, join(hostXfer, VM_SHALLOW_BOUNDARY_NAME));
  }

  /**
   * True when the bundle header lists '-' prerequisite refs — the incremental
   * shape whose parents are expected in the receiving repository. Shallow
   * bundles carry NO prerequisite lines (rev-list stops at the boundary), so
   * this cleanly separates the two without a clone probe. Only the header is
   * scanned: prerequisites are oid lines before the PACK payload.
   */
  private async bundleHasPrerequisites(bundleFile: string): Promise<boolean> {
    const handle = await open(bundleFile, 'r');
    try {
      const buffer = Buffer.alloc(1024 * 1024);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      const head = buffer.subarray(0, bytesRead).toString('latin1');
      for (const line of head.split('\n')) {
        if (line.startsWith('PACK')) break;
        if (/^-[0-9a-fA-F]{40,64}\s/.test(line)) return true;
      }
      return false;
    } finally {
      await handle.close();
    }
  }

  private async guestRm(ctx: ProvisionContext, guestPath: string): Promise<void> {
    // Cleanup must outlive caller cancellation — an aborted ctx.signal would
    // leave the xfer dir (bundle payload included) on the guest disk forever.
    // It still never runs guest work past the lease: the deadline is the
    // EARLIER of the soft lease expiry and the hard TTL, and the exec is
    // bounded by the time remaining until it — a cleanup starting 1 ms before
    // expiry cannot run a fresh 30 s. Identity is unchanged: backend.exec
    // resolves workspaceId/generation/instanceId from ctx.record.
    const deadline = Math.min(ctx.record.expiresAt, ctx.record.hardExpiresAt);
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) return;
    const cleanupCtx = { ...ctx };
    delete cleanupCtx.signal;
    await this.deps.backend.exec(cleanupCtx, {
      argv: ['rm', '-rf', '--', guestPath],
      environment: this.guestHelperEnv(),
      timeoutMs: Math.min(30_000, remainingMs),
      maxBytes: 8_192
    }).catch(() => undefined);
  }

  // ------------------------------------------------------------------
  // GitDataPlane verbs
  // ------------------------------------------------------------------

  /**
   * Seeds guest `/workspace` from the host staging clone. `pushTree` copies
   * the ENTIRE tree — `.git`, committed files, and uncommitted toolkit
   * patches under `.cloud-harness/` — so phase-09 workspace patches survive
   * seeding. The staging clone is credential-free by construction
   * (clone-helper resets the origin URL; tokens travel stdin-only and are
   * never written into the tree).
   */
  async seedCheckout(ctx: ProvisionContext, stagingRepoDir: string): Promise<void> {
    const src = this.hostPathUnderJob(ctx, stagingRepoDir);
    const info = await stat(src).catch(() => undefined);
    if (!info?.isDirectory()) {
      throw new HarnessError('INVALID_INPUT', 'seedCheckout source must be a host directory', 400, false);
    }
    await this.deps.backend.pushTree(ctx, src, GUEST_CHECKOUT);
    const head = await this.guestGit(ctx, ['rev-parse', '--verify', 'HEAD^{commit}'], { timeoutMs: 30_000 });
    if (head.exitCode !== 0) {
      throw new HarnessError('UNAVAILABLE', `seeded checkout failed git sanity: ${head.stderr || head.stdout}`.slice(0, 2_000), 502, true);
    }
    const status = await this.guestGit(ctx, ['status', '--porcelain'], { timeoutMs: 60_000, maxBytes: 262_144 });
    if (status.exitCode !== 0) {
      throw new HarnessError('UNAVAILABLE', `seeded checkout failed git status sanity: ${status.stderr || status.stdout}`.slice(0, 2_000), 502, true);
    }
  }

  /**
   * Guest-side `git bundle create` under `/var/cache/harness`, then
   * `pullTree` back to the requested host path (which must live under the
   * job path). Returns the bundle's SHA-256 + size.
   *
   * Shallow checkouts: the guest helper emits `shallow.txt` next to the
   * bundle inside the transfer dir; it is validated and persisted as
   * `<outBundleHostPath>.shallow` — the deterministic sibling
   * {@link importObjects} consumes. Callers migrating a bundle MUST carry
   * that sibling file with it or a shallow bundle lands unmarked.
   */
  async exportObjects(ctx: ProvisionContext, refspec: string, outBundleHostPath: string): Promise<{ sha256: string; bytes: number }> {
    const revisions = vmRevisionArgs(refspec);
    if (revisions.length === 0) {
      throw new HarnessError('INVALID_INPUT', 'exportObjects requires at least one revision', 400, false);
    }
    const outPath = this.hostPathUnderJob(ctx, outBundleHostPath);
    await mkdir(dirname(outPath), { recursive: true });
    const xfer = this.newGuestXferDir();
    const guestBundle = `${xfer}/objects.bundle`;
    try {
      const created = await this.guestVm(ctx, ['bundle-create', GUEST_CHECKOUT, guestBundle, ...revisions], { timeoutMs: GUEST_BUNDLE_TIMEOUT_MS });
      if (created.exitCode !== 0) {
        throw new HarnessError('UNAVAILABLE', `git bundle export failed: ${created.stderr || created.stdout}`.slice(0, 2_000), 502, true);
      }
      const hostTmp = join(dirname(outPath), `.git-xfer-${randomBytes(8).toString('hex')}`);
      try {
        await this.deps.backend.pullTree(ctx, xfer, hostTmp);
        const pulled = join(hostTmp, 'objects.bundle');
        const info = await lstat(pulled).catch(() => undefined);
        if (!info?.isFile() || info.size === 0) {
          throw new HarnessError('UNAVAILABLE', 'git bundle export produced no bundle file', 502, true);
        }
        if (info.size > VM_MAX_BUNDLE_BYTES) {
          throw new HarnessError('LIMIT_EXCEEDED', 'git bundle exceeds the maximum transfer size', 413, false);
        }
        // Shallow boundary sidecar — validated before it is persisted; a
        // malformed one fails the export rather than exporting a bundle
        // whose truncated parents cannot be reconstructed.
        const pulledShallow = join(hostTmp, VM_SHALLOW_BOUNDARY_NAME);
        if (await validateVmShallowBoundary(pulledShallow)) {
          await rename(pulledShallow, vmShallowSidecarPath(outPath));
        }
        await rename(pulled, outPath);
        return { sha256: await sha256File(outPath), bytes: info.size };
      } finally {
        await rm(hostTmp, { recursive: true, force: true }).catch(() => undefined);
      }
    } finally {
      await this.guestRm(ctx, xfer);
    }
  }

  /**
   * Digest-verifies `bundleHostPath`, derives fetch refspecs from its heads
   * (same `bundleHeadsToRefspecs` mapping as the docker import), pushes the
   * bundle into the guest, and runs a credential-free `git -C /workspace
   * fetch`. No pause — git's own atomicity covers the transfer.
   *
   * Shallow bundles: when `<bundleHostPath>.shallow` exists (written by
   * {@link exportObjects} or carried by the caller) it is validated and
   * pushed into the guest transfer dir; `bundle-fetch` then marks exactly
   * the transferred boundary commits whose parents are missing — a shallow
   * bundle can never land with unmarked truncated parents. A present-but-
   * malformed sidecar fails the import rather than silently dropping it.
   */
  async importObjects(ctx: ProvisionContext, bundleHostPath: string, expectedSha256: string): Promise<void> {
    if (!/^[0-9a-f]{64}$/i.test(expectedSha256)) {
      throw new HarnessError('INVALID_INPUT', 'expectedSha256 must be a SHA-256 hex digest', 400, false);
    }
    const bundlePath = this.hostPathUnderJob(ctx, bundleHostPath);
    const info = await lstat(bundlePath).catch(() => undefined);
    if (!info?.isFile() || info.size === 0) {
      throw new HarnessError('NOT_FOUND', 'git bundle file not found', 404, false);
    }
    const actual = (await sha256File(bundlePath)).toLowerCase();
    if (actual !== expectedSha256.toLowerCase()) {
      throw new HarnessError('INVALID_INPUT', 'git bundle digest does not match the expected SHA-256', 400, false);
    }
    const sidecarPath = vmShallowSidecarPath(bundlePath);
    const hasSidecar = await validateVmShallowBoundary(sidecarPath);
    const opDir = await this.staging.createOpDir(ctx);
    try {
      await this.linkOrCopy(bundlePath, join(opDir, 'incoming.bundle'));
      const refspecs = await this.staging.bundleRefspecs(opDir, 'incoming.bundle', {
        ...(ctx.signal ? { signal: ctx.signal } : {}),
        workspaceId: ctx.record.id
      });
      if (!hasSidecar) {
        // Two bundle shapes reach here without a sidecar, and they need
        // opposite handling:
        //  - INCREMENTAL: '-' prerequisite lines in the bundle header. The
        //    parents are expected to exist in the checkout, so the import is
        //    valid — bundle-fetch's unbundle enforces them loudly if absent.
        //    A clone-into-empty probe cannot tell this apart from shallow and
        //    must NOT reject it.
        //  - SHALLOW: no '-' lines, but commits whose parents dangle inside
        //    the pack. clone --bare SUCCEEDS on these (verified: the broken
        //    links only surface on traversal), so connectivity — not clone
        //    success — is the detector. Without the sidecar the boundary
        //    would land unmarked: fail loudly instead.
        if (!(await this.bundleHasPrerequisites(join(opDir, 'incoming.bundle')))) {
          const probe = await this.staging.git(opDir, ['clone', '--bare', 'incoming.bundle', 'probe.git'], {
            ...(ctx.signal ? { signal: ctx.signal } : {}),
            workspaceId: ctx.record.id
          });
          if (probe.exitCode !== 0) {
            throw new HarnessError(
              'INVALID_INPUT',
              `git bundle ${vmShallowSidecarPath(bundlePath)} is missing and the bundle is not importable`,
              400,
              false
            );
          }
          // fsck --connectivity-only is the bounded detector: it prints only
          // problems (a few lines) and exits nonzero on broken links, where
          // `rev-list --all --objects` printed one line per object and could
          // exceed the helper's maxOutputBytes on real repos — truncating a
          // COMPLETE bundle into a false "shallow" rejection. Verified:
          // dangling objects alone still exit 0.
          const connectivity = await this.staging.git(opDir, ['-C', 'probe.git', 'fsck', '--connectivity-only'], {
            ...(ctx.signal ? { signal: ctx.signal } : {}),
            workspaceId: ctx.record.id
          });
          if (connectivity.exitCode !== 0) {
            throw new HarnessError(
              'INVALID_INPUT',
              `git bundle is shallow but ${vmShallowSidecarPath(bundlePath)} is missing — the sidecar must travel with the bundle`,
              400,
              false
            );
          }
        }
      }
      const xfer = this.newGuestXferDir();
      const hostXfer = join(opDir, 'xfer');
      await mkdir(hostXfer, { recursive: true });
      await this.linkOrCopy(bundlePath, join(hostXfer, 'incoming.bundle'));
      if (hasSidecar) {
        await this.linkOrCopy(sidecarPath, join(hostXfer, VM_SHALLOW_BOUNDARY_NAME));
      }
      try {
        await this.guestMkdir(ctx, xfer);
        await this.deps.backend.pushTree(ctx, hostXfer, xfer);
        const fetched = await this.guestVm(ctx, ['bundle-fetch', GUEST_CHECKOUT, `${xfer}/incoming.bundle`, '', ...refspecs], {
          timeoutMs: GUEST_BUNDLE_TIMEOUT_MS,
          ...(ctx.signal ? { signal: ctx.signal } : {})
        });
        if (fetched.exitCode !== 0) {
          throw new HarnessError('UNAVAILABLE', `git bundle import failed: ${fetched.stderr || fetched.stdout}`.slice(0, 2_000), 502, true);
        }
      } finally {
        await this.guestRm(ctx, xfer);
      }
    } finally {
      await this.staging.removeOpDir(opDir);
    }
  }

  // ------------------------------------------------------------------
  // Remote operations — the brokered credential boundary
  // ------------------------------------------------------------------

  private async resolveUrl(ctx: ProvisionContext, raw: string): Promise<string> {
    const validate = this.deps.validateUrl
      ?? ((value: string) => validateRepositoryUrl(value, this.deps.config.allowedGitHosts));
    const url = await validate(raw);
    return typeof url === 'string' ? url : url.toString();
  }

  /**
   * fetch/pull remote half: credentialed host fetch into a staging bare →
   * incremental bundle → digest-verified pushTree → credential-free guest
   * fetch. Returns both leg results so callers keep the docker
   * `{fetched, imported}` consumption shape (`imported.stdout/.stderr/.truncated`).
   */
  async remoteFetch(ctx: ProvisionContext, params: VmRemoteFetchParams): Promise<{ fetched: VmHelperResult; imported: ExecResult }> {
    const repositoryUrl = await this.resolveUrl(ctx, params.repositoryUrl);
    const remoteRef = params.remoteRef ?? '';
    const historySpec = params.historySpec ?? '';
    const opDir = await this.staging.createOpDir(ctx);
    try {
      const fetched = await this.staging.fetchRemoteBare(opDir, {
        repositoryUrl,
        remoteRef,
        ...(historySpec ? { historySpec } : {}),
        ...(params.token !== undefined ? { token: params.token } : {}),
        ...(ctx.signal ? { signal: ctx.signal } : {}),
        workspaceId: ctx.record.id
      });
      assertVmTransferOk('fetch', fetched);
      // Bundle revs mirror the renormalized staging refs: '' → all heads;
      // refs/heads/X → that branch; anything else → the FETCH_HEAD-only ref.
      const revs = remoteRef === ''
        ? ['--branches']
        : [remoteRef.startsWith('refs/heads/') ? `refs/heads/${remoteRef.slice('refs/heads/'.length)}` : 'refs/vm-import/fetch'];
      const bundle = await this.staging.createBundle(opDir, { revs, outName: 'fetch.bundle', ...(ctx.signal ? { signal: ctx.signal } : {}), workspaceId: ctx.record.id });
      const refspecs = await this.staging.bundleRefspecs(opDir, 'fetch.bundle', {
        ...(ctx.signal ? { signal: ctx.signal } : {}),
        workspaceId: ctx.record.id
      });
      const xfer = this.newGuestXferDir();
      const hostXfer = join(opDir, 'xfer');
      await mkdir(hostXfer, { recursive: true });
      await this.linkOrCopy(bundle.hostPath, join(hostXfer, 'fetch.bundle'));
      await this.copyShallowBoundary(opDir, hostXfer);
      try {
        await this.guestMkdir(ctx, xfer);
        await this.deps.backend.pushTree(ctx, hostXfer, xfer);
        const imported = await this.guestVm(ctx, ['bundle-fetch', GUEST_CHECKOUT, `${xfer}/fetch.bundle`, historySpec, ...refspecs], {
          timeoutMs: GUEST_BUNDLE_TIMEOUT_MS,
          ...(ctx.signal ? { signal: ctx.signal } : {})
        });
        if (imported.exitCode !== 0) {
          throw new HarnessError('UNAVAILABLE', `git bundle import failed: ${imported.stderr || imported.stdout}`.slice(0, 2_000), 502, true);
        }
        return { fetched, imported };
      } finally {
        await this.guestRm(ctx, xfer);
      }
    } finally {
      await this.staging.removeOpDir(opDir);
    }
  }

  /**
   * push remote half: guest `git bundle create` of the checkout's refs plus
   * the refspec source → pullTree → `git clone --bare` staging → the
   * unchanged `git-transfer-helper.sh push` lease CAS. Lost replies surface
   * as UNKNOWN_REMOTE_STATE via {@link assertVmTransferOk} — reconciliation
   * stays caller-side, byte-identical contract.
   */
  async remotePush(ctx: ProvisionContext, params: VmRemotePushParams): Promise<VmHelperResult> {
    const repositoryUrl = await this.resolveUrl(ctx, params.repositoryUrl);
    const refspec = params.refspec ?? '';
    // Same shape rules as VmGitStaging.pushBare — reject before guest work.
    if (
      refspec.length === 0 || refspec.length > 512 || refspec.startsWith('-')
      || /[\0\n\r]/.test(refspec) || refspec.split(':').length > 2
    ) {
      throw new HarnessError('INVALID_INPUT', 'git push refspec is invalid', 400, false);
    }
    // The bundle must cover every object the push could send. `--all` mirrors
    // `git clone --bare`'s `+refs/*:refs/*` (branches, tags, remote-tracking,
    // stash — the same ref set stage-push's bare clone would see), `HEAD`
    // covers detached checkouts, and the explicit source rev covers sha or
    // exotic revs a ref pattern cannot name. A leading '+' is the refspec
    // force marker, not part of the revision — strip it before git sees it.
    let sourceRev = refspec.split(':')[0] ?? '';
    if (sourceRev.startsWith('+')) sourceRev = sourceRev.slice(1);
    const revs = ['--all', 'HEAD'];
    if (sourceRev !== '' && sourceRev !== 'HEAD' && !sourceRev.includes('*')) revs.push(sourceRev);
    const opDir = await this.staging.createOpDir(ctx);
    try {
      const xfer = this.newGuestXferDir();
      const guestBundle = `${xfer}/push.bundle`;
      try {
        const created = await this.guestVm(ctx, ['bundle-create', GUEST_CHECKOUT, guestBundle, ...revs], {
          timeoutMs: GUEST_BUNDLE_TIMEOUT_MS,
          ...(ctx.signal ? { signal: ctx.signal } : {})
        });
        if (created.exitCode !== 0) {
          const text = `${created.stderr}\n${created.stdout}`;
          if (/bad revision|ambiguous argument|unknown revision|invalid object name|does not match/i.test(text)) {
            throw new HarnessError('INVALID_INPUT', `git bundle export failed: ${text}`.slice(0, 2_000), 400, false);
          }
          throw new HarnessError('UNAVAILABLE', `git bundle export failed: ${text}`.slice(0, 2_000), 502, true);
        }
        const hostPull = join(opDir, 'pull');
        await mkdir(hostPull, { recursive: true });
        await this.guestMkdir(ctx, xfer);
        await this.deps.backend.pullTree(ctx, xfer, hostPull);
        const pulled = join(hostPull, 'push.bundle');
        const info = await lstat(pulled).catch(() => undefined);
        if (!info?.isFile() || info.size === 0) {
          throw new HarnessError('UNAVAILABLE', 'git bundle export produced no bundle file', 502, true);
        }
        if (info.size > VM_MAX_BUNDLE_BYTES) {
          throw new HarnessError('LIMIT_EXCEEDED', 'git bundle exceeds the maximum transfer size', 413, false);
        }
        await rename(pulled, join(opDir, 'push.bundle'));
        // Shallow boundary sidecar travels with the bundle — staging validates
        // and applies it via GIT_SHALLOW_FILE (bounded, hex-oid lines only).
        const shallow = join(hostPull, VM_SHALLOW_BOUNDARY_NAME);
        const shallowInfo = await lstat(shallow).catch(() => undefined);
        if (shallowInfo !== undefined) {
          if (!shallowInfo.isFile()) {
            throw new HarnessError('INVALID_INPUT', 'git shallow boundary sidecar is not a regular file', 400, false);
          }
          await rename(shallow, join(opDir, VM_SHALLOW_BOUNDARY_NAME));
        }
      } finally {
        await this.guestRm(ctx, xfer);
      }
      await this.staging.stagePushBare(opDir, 'push.bundle', {
        ...(ctx.signal ? { signal: ctx.signal } : {}),
        workspaceId: ctx.record.id
      });
      const pushed = await this.staging.pushBare(opDir, {
        repositoryUrl,
        refspec,
        ...(params.expectedRemoteOid !== undefined ? { expectedRemoteOid: params.expectedRemoteOid } : {}),
        ...(params.token !== undefined ? { token: params.token } : {}),
        ...(ctx.signal ? { signal: ctx.signal } : {}),
        workspaceId: ctx.record.id
      });
      assertVmTransferOk('push', pushed, { ...(params.expectedRemoteOid !== undefined ? { expectedRemoteOid: params.expectedRemoteOid } : {}) });
      return pushed;
    } finally {
      await this.staging.removeOpDir(opDir);
    }
  }

  /**
   * Remote branch probe for push reconciliation. Implemented through the
   * existing `git-transfer-helper.sh fetch` mode at `depth:1` (no new helper
   * script needed): exit 0 → rev-parse the staged ref; "couldn't find remote
   * ref" → null (absent); anything else → undefined (unknown). Same
   * tri-state contract as the docker `probeRemoteRefOid`.
   */
  async probeRemoteRefOid(ctx: ProvisionContext, params: { repositoryUrl: string; branch: string; token?: string }): Promise<string | null | undefined> {
    const repositoryUrl = await this.resolveUrl(ctx, params.repositoryUrl);
    const branch = params.branch ?? '';
    if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/.test(branch) || branch.includes('..') || branch.endsWith('/')) {
      return undefined;
    }
    const opDir = await this.staging.createOpDir(ctx);
    try {
      const fetched = await this.staging.fetchRemoteBare(opDir, {
        repositoryUrl,
        remoteRef: `refs/heads/${branch}`,
        historySpec: 'depth:1',
        ...(params.token !== undefined ? { token: params.token } : {}),
        ...(ctx.signal ? { signal: ctx.signal } : {}),
        workspaceId: ctx.record.id
      });
      if (fetched.exitCode === 0) {
        const rev = await this.staging.git(opDir, ['--git-dir=bare.git', 'rev-parse', '--verify', '--quiet', `refs/heads/${branch}^{commit}`], {
          readOnly: true,
          ...(ctx.signal ? { signal: ctx.signal } : {}),
          workspaceId: ctx.record.id
        });
        const oid = rev.stdout.trim();
        return rev.exitCode === 0 && /^[0-9a-f]{40,64}$/.test(oid) ? oid : undefined;
      }
      const text = `${fetched.stderr}\n${fetched.stdout}`;
      if (/couldn't find remote ref|not our ref|no such ref|does not exist/i.test(text)) return null;
      return undefined;
    } finally {
      await this.staging.removeOpDir(opDir).catch(() => undefined);
    }
  }

  // ------------------------------------------------------------------
  // Offline export — stopped VM only; guest code never runs on the host
  // ------------------------------------------------------------------

  /**
   * Exports `/workspace` from a STOPPED VM through the injected
   * `backend-factory` `VmExportWorkspaceFn` seam (libguestfs appliance inside
   * the supervisor — the guest filesystem is never host-mounted and no guest
   * code executes). The tar lands at `workDir/export.tar`; its SHA-256 and
   * byte count are cross-checked against the returned trailer before
   * {@link extractTarSafe} applies hostile-entry rejection (absolute paths,
   * traversal, links, devices, oversized archives). Inspection then runs the
   * credential-free close-check on the untrusted copy. `unknown` verdicts
   * must defer auto-close — never delete.
   */
  async exportCheckoutOffline(ctx: ProvisionContext, params: VmOfflineExportParams): Promise<VmOfflineExportResult> {
    if (!this.exportWorkspace) {
      throw new HarnessError('VM_CAPABILITY_UNSUPPORTED', 'offline VM export is not wired for this transport', 400, false);
    }
    const maxBytes = params.maxBytes;
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
      throw new HarnessError('INVALID_INPUT', 'export maxBytes must be a positive integer', 400, false);
    }
    const opDir = await this.staging.createOpDir(ctx);
    try {
      const tarPath = join(opDir, 'export.tar');
      const trailer = await this.exportWorkspace(ctx, { guestPath: GUEST_CHECKOUT, destPath: tarPath, maxBytes });
      const info = await stat(tarPath).catch(() => undefined);
      if (!info?.isFile() || info.size === 0 || info.size > maxBytes) {
        throw new HarnessError('INVALID_INPUT', 'VM export produced no usable tar within the byte bound', 400, false);
      }
      const digest = await sha256File(tarPath);
      if (digest !== trailer.sha256.toLowerCase() || info.size !== trailer.bytes) {
        throw new HarnessError('INVALID_INPUT', 'VM export digest does not match the supervisor trailer', 400, false);
      }
      const extractDir = join(opDir, 'extract');
      // Extracted files are guest-controlled bytes: chown them to the helper
      // uid where the runner is privileged so host helpers can read them, and
      // let lchown EPERM pass silently on unprivileged dev runners.
      await extractTarSafe(tarPath, extractDir, { maxEntries: OFFLINE_MAX_ENTRIES, maxBytes }, { owner: { uid: VM_HELPER_UID, gid: VM_HELPER_GID } });
      // Every shallowest-depth `.git` candidate is inspected — same-depth
      // decoys cannot hide behind an arbitrary first pick, and deeper nested
      // repos are never mistaken for the checkout.
      const roots = await findCheckoutRoots(extractDir);
      if (roots.length === 0) {
        return { verdict: 'unknown', reason: 'export contains no git checkout root', workDir: opDir };
      }
      if (roots.length > 8) {
        return { verdict: 'unknown', reason: 'export contains too many checkout roots', workDir: opDir };
      }
      const inspections: VmCheckoutInspection[] = [];
      for (const rel of roots) {
        const checkoutDir = rel === '' ? extractDir : join(extractDir, rel);
        inspections.push(await inspectVmCheckout(this.staging, checkoutDir, {
          containerPath: GUEST_CHECKOUT,
          ...(params.cloneRef !== undefined ? { cloneRef: params.cloneRef } : {}),
          ...(ctx.signal ? { signal: ctx.signal } : {}),
          workspaceId: ctx.record.id
        }));
      }
      // Conservative merge: any unknown → unknown, else any retain → retain,
      // counts summed across candidates (over-approximation never hides dirt).
      const verdict = inspections.some((i) => i.verdict === 'unknown') ? 'unknown'
        : inspections.some((i) => i.verdict === 'retain') ? 'retain' : 'clean';
      const firstReason = inspections.map((i) => i.reason).find((reason) => reason !== undefined);
      const merged: VmCheckoutInspection = {
        verdict,
        uncommittedPaths: inspections.reduce((sum, i) => sum + (i.uncommittedPaths ?? 0), 0),
        stashes: inspections.reduce((sum, i) => sum + (i.stashes ?? 0), 0),
        unpushedCommits: inspections.reduce((sum, i) => sum + (i.unpushedCommits ?? 0), 0),
        ...(firstReason !== undefined ? { reason: firstReason } : {})
      };
      const result: VmOfflineExportResult = { ...merged, workDir: opDir };
      if (roots.length === 1) {
        const root = roots[0]!;
        result.checkoutDir = root === '' ? extractDir : join(extractDir, root);
        // Preserve the shallow boundary for callers that stage a push from
        // this checkout (exportVmCheckoutOffline → stagePushBare/pushBare).
        const shallow = join(result.checkoutDir, '.git', 'shallow');
        const shallowInfo = await lstat(shallow).catch(() => undefined);
        if (shallowInfo?.isFile() && shallowInfo.size > 0 && shallowInfo.size <= VM_MAX_SHALLOW_BOUNDARY_BYTES) {
          await copyFile(shallow, join(opDir, VM_SHALLOW_BOUNDARY_NAME));
        }
      }
      return result;
    } catch (error) {
      await this.staging.removeOpDir(opDir).catch(() => undefined);
      throw error;
    }
  }
}

// Re-exported so callers/tests share one import site.
export { VM_MAX_BUNDLE_BYTES };
export type { VmCheckoutInspection, VmHelperResult, VmHelperRunner };

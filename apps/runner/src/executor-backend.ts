import type { PtyTransport } from './docker-pty.js';
import type { WorkspaceRecord } from './state-store.js';
import type {
  BackendCapabilityId,
  BackendCapabilityMap,
  BackendCapabilityValue,
  ExecutorBackendKind,
  ExecutorNetworkProfile
} from '@cloud-harness/contracts';

export type {
  BackendCapabilityId,
  BackendCapabilityMap,
  BackendCapabilityValue,
  ExecutorBackendKind,
  ExecutorNetworkProfile
};

/**
 * A live executor handle. `executorId` is the backend's own executor identity
 * (docker: container name; incus-vm: `chm-vm-<hash>` VM name). `instanceId` is
 * only set for the incus-vm backend (the admitted `backend_instance_id` UUID).
 */
export interface ExecutorRef {
  backend: ExecutorBackendKind;
  workspaceId: string;
  executorId: string;
  /** Workspace `generation` observed when the executor was acquired; fencing input, never authority. */
  generation: number;
  instanceId?: string;
}

/**
 * Where an exec runs. `executor` (default) runs inside the already-provisioned
 * executor — for docker a `docker exec`, for incus-vm a guest `exec.run`.
 * `ephemeral-helper` runs a fresh disposable helper container/VM-side helper
 * with the requested uid — callers MUST opt in explicitly; a missing mode never
 * silently grants helper or root semantics.
 */
export type ExecutorExecutionMode = 'executor' | 'ephemeral-helper';

export interface ExecRequest {
  argv: string[];
  /** Executor-absolute working directory. Omitted means the executor default (`/workspace`). */
  cwd?: string;
  /**
   * REQUIRED environment map. For incus-vm this is the COMPLETE per-exec
   * environment (base ∪ workspace env incl. secrets) — no inheritance
   * assumptions. For docker it is an operation-scoped override layer over the
   * provision-baked environment; the adapter delivers it through a mode-0600
   * env file so values never appear in argv.
   */
  environment: Record<string, string>;
  stdin?: string | Buffer;
  timeoutMs: number;
  maxBytes: number;
  signal?: AbortSignal;
  /** `workspace` = uid 10001, `root` = uid 0, within the selected `executionMode`. */
  user?: 'workspace' | 'root';
  /** Defaults to `'executor'`. See {@link ExecutorExecutionMode}. */
  executionMode?: ExecutorExecutionMode;
  /**
   * Grace period between SIGTERM and SIGKILL when `signal` aborts the docker
   * CLI. Only meaningful for the docker adapter; other backends may ignore it.
   */
  abortKillGraceMs?: number;
}

export interface ExecResult {
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
}

export interface StreamRequest {
  argv: string[];
  cwd?: string;
  /** REQUIRED, same rule as {@link ExecRequest.environment}. */
  environment: Record<string, string>;
  /** Set → interactive exec with PTY + resize + signal support. */
  pty?: { cols: number; rows: number };
}

/**
 * `ChildProcessWithoutNullStreams`-compatible handle: piped stdio, `kill`,
 * and `close`/`error` events, so `OperationManager.track` needs no changes.
 */
export interface StreamHandle {
  stdin: NodeJS.WritableStream | null;
  stdout: NodeJS.ReadableStream;
  stderr: NodeJS.ReadableStream;
  kill(signal?: string): boolean;
  on(event: 'close', cb: (code: number | null, signal: string | null) => void): this;
  on(event: 'error', cb: (err: Error) => void): this;
}

export interface ExecutorInspection {
  state: 'running' | 'stopped' | 'missing' | 'unknown';
  identity?: { instanceId: string; templateId: string; templateDigest: string };
}

export interface ProvisionContext {
  record: WorkspaceRecord;
  /** COMPLETE env for this provision (base ∪ workspace env incl. secrets). */
  environment: Record<string, string>;
  /**
   * Canonical contracts spelling (`'network-none' | 'dependency-access'`). The
   * phase-02 sketch wrote `'none'`; the shipped enum value is `network-none`.
   */
  networkProfile: ExecutorNetworkProfile;
  /** Host git-staging dir under the job path (`record.workspacePath`). */
  stagingDir: string;
  signal?: AbortSignal;
  /**
   * Caller-acknowledged lease deadline for this activation (ms epoch). Set by
   * the service on recoverable resume/renew so the backend's recovery lease
   * covers the INTENDED renewal — not merely the persisted recoverable
   * window. Backends without a durable supervisor lease ignore it; the
   * incus-vm backend prefers it over `min(hardExpiresAt, recoverableUntil)`.
   */
  leaseExpiresAt?: number;
}

/**
 * Backend verbs. There is deliberately no `quiesce`/`resume`: an Incus freeze
 * blocks the agent channel, so Git safety uses native bundle/object/ref/CAS
 * behavior inside `GitDataPlane` instead of claiming a Docker-style
 * all-writer pause. The docker adapter keeps its pause strictly inside
 * `DockerGitDataPlane` where today's behavior already had it.
 */
export interface ExecutorBackend {
  readonly kind: ExecutorBackendKind;
  /** Create + materialize + start the executor. */
  provision(ctx: ProvisionContext): Promise<ExecutorRef>;
  /** Adopt a live executor, gated-start a stopped one, or provision a missing one. */
  ensureActive(ctx: ProvisionContext): Promise<ExecutorRef>;
  exec(ctx: ProvisionContext, req: ExecRequest): Promise<ExecResult>;
  spawnStream(ctx: ProvisionContext, req: StreamRequest): Promise<StreamHandle>;
  /** Interactive PTY transport (existing `PtyTransport` interface). */
  pty(ctx: ProvisionContext): PtyTransport;
  /** Bounded read of an executor-absolute file into a host `Buffer`. */
  pullFile(ctx: ProvisionContext, guestPath: string, maxBytes: number): Promise<Buffer>;
  /** Copy a host directory tree into the executor; returns a content manifest digest. */
  pushTree(ctx: ProvisionContext, hostDir: string, guestPath: string): Promise<{ sha256: string; bytes: number; entryCount: number }>;
  /** Copy an executor directory tree to the host; same digest contract as {@link pushTree}. */
  pullTree(ctx: ProvisionContext, guestPath: string, hostDir: string): Promise<{ sha256: string; bytes: number; entryCount: number }>;
  /** Workspace byte measurement with today's 3-path `du` parity (plus helper fallback). */
  measureWorkspaceBytes(ctx: ProvisionContext): Promise<number>;
  /** Terminate the process group recorded in `pidFile` (executor-absolute path). */
  killProcessGroup(ctx: ProvisionContext, pidFile: string): Promise<void>;
  /** Stop the executor while preserving its disk/state for a later start. */
  stop(ctx: ProvisionContext): Promise<void>;
  /** Destroy the executor. Called only on explicit close/teardown paths. */
  destroy(ctx: ProvisionContext): Promise<void>;
  inspect(ctx: ProvisionContext): Promise<ExecutorInspection>;
  capabilities(): BackendCapabilityMap;
}

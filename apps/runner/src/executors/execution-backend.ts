import type { PtyTransport } from '../docker-pty.js';

/** Remote identity comes from trusted allocation state, never from guest metadata. */
export type RemoteExecutorRef = {
  provider: 'instabox';
  workspaceId: string;
  ownerId: string;
  machineId: string;
  generation: number;
  root: string;
};
export type ExecutionResult = { stdout: string; stderr: string; exitCode: number; truncated?: boolean };
export type ExecutionOptions = {
  cwd?: string; env?: Record<string, string>; stdin?: string;
  timeoutMs: number; maxBytes: number; signal?: AbortSignal;
};
export type RemoteJobSpec = {
  id: string; kind: 'task' | 'shell'; command?: string; cwd: string;
  timeoutMs: number; maxBytes: number; fingerprint: string;
};
export type RemoteJobObservation = {
  status: 'starting' | 'running' | 'exited' | 'unknown';
  exitCode?: number; errorCode?: string; output: Buffer;
  nextOffset: number; outputBytes: number; truncated: boolean;
};
export type RemoteMachineState = {
  state: string; ready: boolean; cooldownUntil?: string; retryAfterMs?: number;
};
/** Small execution boundary shared by the core's remote paths. Local Docker stays in its adapter. */
export interface RemoteExecutionBackend {
  run(ref: RemoteExecutorRef, command: string, options: ExecutionOptions): Promise<ExecutionResult>;
  inspect(ref: RemoteExecutorRef): Promise<RemoteMachineState>;
  start(ref: RemoteExecutorRef): Promise<void>;
  stop(ref: RemoteExecutorRef): Promise<void>;
  bootstrap(ref: RemoteExecutorRef, files: ReadonlyArray<{ path: string; content: string; mode?: number }>): Promise<void>;
  uploadFile(ref: RemoteExecutorRef, localPath: string, guestPath: string, maxBytes: number): Promise<void>;
  downloadFile(ref: RemoteExecutorRef, guestPath: string, localPath: string, maxBytes: number): Promise<void>;
  readFile(ref: RemoteExecutorRef, guestPath: string, maxBytes: number): Promise<Buffer>;
  writeFile(ref: RemoteExecutorRef, guestPath: string, content: Buffer): Promise<void>;
  startJob(ref: RemoteExecutorRef, spec: RemoteJobSpec): Promise<void>;
  readJob(ref: RemoteExecutorRef, jobId: string, offset: number, maxBytes: number): Promise<RemoteJobObservation>;
  writeJob(ref: RemoteExecutorRef, jobId: string, input: string): Promise<void>;
  cancelJob(ref: RemoteExecutorRef, jobId: string): Promise<void>;
  pty(ref: RemoteExecutorRef): PtyTransport;
  activity(ref: RemoteExecutorRef, taskId: string, active: boolean): Promise<void>;
}
export type RemoteExecutionAccess = {
  resolve(workspaceId: string): RemoteExecutorRef | undefined;
  backend: RemoteExecutionBackend;
};

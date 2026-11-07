import { z } from 'zod';
import { ExecutorNetworkProfileSchema, IdempotencyKeySchema, WorkspaceIdSchema } from './identifiers.js';
import { ErrorCodeSchema } from './mcp-results.js';
import {
  VmInstanceIdSchema,
  VmNameSchema,
  VmTemplateDigestSchema,
  VmTemplateIdSchema
} from './executor-backend.js';

/**
 * Frozen runner↔VM-supervisor RPC contract. Two envelopes are deliberately
 * split: workspace-scoped ops carry the full workspace identity fence
 * (workspaceId + generation + vmInstanceId + idempotencyKey) while host-scoped
 * pool/guard ops carry none of it, so a host op can never be mistaken for a
 * workspace mutation. There is intentionally no `purpose`/recovery-probe field:
 * post-hard-expiry recovery is offline-only through `vm.export`.
 *
 * No op accepts resource overrides (cpu/memory/disk/device/raw incus options):
 * `vm.create`/`vm.start` take identity + template + profile only, and resource
 * actuals come from supervisor configuration, asserted by read-back attestation.
 * Runner `VM_CPUS`/`VM_MEMORY_BYTES`/`VM_DISK_BYTES` are expected values for that
 * attestation, never applied through this contract.
 */

const requestId = z.string().min(1).max(128);
/** Milliseconds since epoch, matching the runner's internal timestamps. */
const issuedAt = z.number().int().nonnegative();
const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/, 'expected lowercase SHA-256 hex digest');
const nonNegativeBytes = z.number().int().nonnegative();
/** Upper bound for byte-count parameters; the supervisor enforces tighter per-op limits. */
const maxTransferBytes = z.number().int().min(1).max(68_719_476_736);
const guestPath = z.string().min(1).max(4_096)
  .refine((value) => value.startsWith('/') && !value.includes('\0'), 'guestPath must be an absolute guest path without NUL bytes');
const guestCwd = z.string().min(1).max(4_096)
  .refine((value) => value.startsWith('/') && !value.includes('\0'), 'cwd must be an absolute guest path without NUL bytes')
  .optional();
const argv = z.array(
  z.string().min(1).max(4_096).refine((value) => !value.includes('\0'), 'argv entries cannot contain NUL bytes')
).min(1).max(256);
/** COMPLETE environment map required on every exec entrypoint; no inheritance assumptions. */
const execEnvironment = z.record(z.string().min(1).max(256), z.string().max(65_536));
const ptySize = z.object({
  cols: z.number().int().min(1).max(1_000),
  rows: z.number().int().min(1).max(1_000)
}).strict();
const fileMode = z.number().int().min(0).max(0o7777).optional();
const fileOwnerId = z.number().int().min(0).max(4_294_967_295).optional();
const emptyParams = z.object({}).strict();

// ---------------------------------------------------------------------------
// Operation vocabularies
// ---------------------------------------------------------------------------

export const VmWorkspaceOperationSchema = z.enum([
  'vm.admit',
  'vm.create',
  'vm.start',
  'vm.stop',
  'vm.delete',
  'vm.status',
  'vm.export',
  'exec.run',
  'exec.inspect',
  'exec.open',
  'exec.write',
  'exec.close',
  'exec.resize',
  'exec.killSession',
  'file.push',
  'file.pull',
  'file.stat',
  'file.list',
  'pushTree',
  'pullTree',
  'network.program',
  'network.attest',
  'network.tearDown',
  'lease.set',
  'lease.clear'
]);
export type VmWorkspaceOperation = z.infer<typeof VmWorkspaceOperationSchema>;

export const VmHostOperationSchema = z.enum([
  'vm.list',
  'lease.list',
  'pool.info',
  'reconcile',
  'guard.state'
]);
export type VmHostOperation = z.infer<typeof VmHostOperationSchema>;

export const VmSupervisorOperationSchema = z.enum([
  ...VmWorkspaceOperationSchema.options,
  ...VmHostOperationSchema.options
]);
export type VmSupervisorOperation = z.infer<typeof VmSupervisorOperationSchema>;

// ---------------------------------------------------------------------------
// Shared value schemas
// ---------------------------------------------------------------------------

/** Incubator-visible instance state as reported by the supervisor (Incus statuses normalized). */
export const VmInstanceStateSchema = z.enum(['stopped', 'starting', 'running', 'stopping', 'frozen', 'error', 'unknown']);
export type VmInstanceState = z.infer<typeof VmInstanceStateSchema>;

/** The `user.cloud-harness.*` identity block read back from an instance; authoritative for adoption. */
export const VmUserCloudHarnessSchema = z.object({
  workspaceId: WorkspaceIdSchema,
  instanceId: VmInstanceIdSchema,
  templateId: VmTemplateIdSchema,
  templateDigest: VmTemplateDigestSchema,
  generationPolicy: z.literal('external')
}).strict();
export type VmUserCloudHarness = z.infer<typeof VmUserCloudHarnessSchema>;

/** Trailer closing a streamed tar exchange (vm.export, pushTree request/response, pullTree response). */
export const VmTarTrailerSchema = z.object({
  sha256: sha256Hex,
  bytes: nonNegativeBytes,
  entryCount: z.number().int().nonnegative()
}).strict();
export type VmTarTrailer = z.infer<typeof VmTarTrailerSchema>;

export const VmReconcileEntrySchema = z.object({
  vmName: VmNameSchema,
  workspaceId: WorkspaceIdSchema.optional(),
  instanceId: VmInstanceIdSchema.optional(),
  reason: z.string().max(500).optional()
}).strict();
export type VmReconcileEntry = z.infer<typeof VmReconcileEntrySchema>;

export const VmGuardVerdictSchema = z.enum(['attested', 'failed', 'unknown']);
export type VmGuardVerdict = z.infer<typeof VmGuardVerdictSchema>;

export const VmLeaseStateSchema = z.enum(['active', 'expired', 'cleared']);
export type VmLeaseState = z.infer<typeof VmLeaseStateSchema>;

const leaseTimes = z.object({
  expiresAt: z.number().int().positive(),
  hardExpiresAt: z.number().int().positive()
}).strict();

// ---------------------------------------------------------------------------
// Workspace-envelope op params + results
// ---------------------------------------------------------------------------

const vmAdmitParams = z.object({ networkProfile: ExecutorNetworkProfileSchema }).strict();
const vmAdmitResult = z.object({
  decision: z.enum(['admitted', 'denied']),
  reason: z.string().max(500).optional()
}).strict();

const vmCreateParams = z.object({
  instanceId: VmInstanceIdSchema,
  networkProfile: ExecutorNetworkProfileSchema,
  templateId: VmTemplateIdSchema,
  templateDigest: VmTemplateDigestSchema
}).strict();
const vmCreateResult = z.object({
  vmName: VmNameSchema,
  state: z.literal('stopped')
}).strict();

const vmStartParams = z.object({ networkProfile: ExecutorNetworkProfileSchema }).strict();
const vmStartResult = z.object({ state: z.literal('running') }).strict();

const vmStopResult = z.object({ state: z.literal('stopped') }).strict();

const vmDeleteParams = z.object({ confirmInstanceId: VmInstanceIdSchema }).strict();
const vmDeleteResult = z.object({ state: z.literal('deleted') }).strict();

const vmStatusResult = z.object({
  state: VmInstanceStateSchema,
  instanceId: VmInstanceIdSchema.optional(),
  userCloudHarness: VmUserCloudHarnessSchema.optional(),
  expandedDevices: z.record(z.string(), z.unknown()).optional(),
  expandedConfig: z.record(z.string(), z.unknown()).optional(),
  profiles: z.array(z.string().min(1).max(256)).max(64).optional()
}).strict();

const vmExportParams = z.object({
  guestPath,
  maxBytes: maxTransferBytes,
  sha256: sha256Hex.optional()
}).strict();

const execRunParams = z.object({
  opId: z.string().min(1).max(128),
  argv,
  cwd: guestCwd,
  environment: execEnvironment,
  /** Base64-encoded stdin bytes; absent means no stdin is written before close. */
  stdinBase64: z.base64().optional(),
  timeoutMs: z.number().int().min(1).max(3_600_000),
  maxBytes: z.number().int().min(1).max(10_485_760),
  /** Guest uid mapping: 'workspace' runs as the workspace user, 'root' as uid 0 (privileged exec). */
  user: z.enum(['workspace', 'root']).optional(),
  /** Dispatch semantics: 'executor' is the workspace executor context, 'ephemeral-helper' a disposable helper. */
  executionMode: z.enum(['executor', 'ephemeral-helper']).optional()
}).strict();
const execRunResult = z.object({
  opId: z.string().min(1).max(128),
  exitCode: z.number().int().min(0).max(255).nullable(),
  signal: z.string().max(64).nullable(),
  stdout: z.string().max(16_777_216),
  stderr: z.string().max(16_777_216),
  truncated: z.boolean(),
  timedOut: z.boolean()
}).strict();

const execInspectParams = z.object({ opId: z.string().min(1).max(128) }).strict();
const execInspectResult = z.object({
  state: z.enum(['running', 'exited', 'unknown']),
  exitCode: z.number().int().min(0).max(255).nullable().optional(),
  returnMetadata: z.record(z.string(), z.unknown()).optional()
}).strict();

const execOpenParams = z.object({
  sessionId: z.string().min(1).max(128),
  argv,
  cwd: guestCwd,
  environment: execEnvironment,
  pty: ptySize.optional()
}).strict();
const execOpenResult = z.object({
  sessionId: z.string().min(1).max(128),
  fdsReady: z.literal(true)
}).strict();

const execWriteParams = z.object({
  sessionId: z.string().min(1).max(128),
  fd: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  dataBase64: z.base64(),
  eof: z.boolean().optional()
}).strict();
const execWriteResult = z.object({ acceptedBytes: nonNegativeBytes }).strict();

const execCloseParams = z.object({
  sessionId: z.string().min(1).max(128),
  /** fd -1 is the control close: it kills the session process-group leader. */
  fd: z.union([z.literal(-1), z.literal(0), z.literal(1), z.literal(2)]).optional()
}).strict();
const execCloseResult = z.object({ closed: z.literal(true) }).strict();

const execResizeParams = z.object({
  sessionId: z.string().min(1).max(128),
  cols: z.number().int().min(1).max(1_000),
  rows: z.number().int().min(1).max(1_000)
}).strict();
const execResizeResult = z.object({}).strict();

const execKillSessionParams = z.object({
  sessionId: z.string().min(1).max(128),
  pidFile: guestPath
}).strict();
const execKillSessionResult = z.object({ killed: z.literal(true) }).strict();

const filePushParams = z.object({
  guestPath,
  /** Exactly one of inline base64 data or a reference to a session-framed stream. */
  dataBase64: z.base64().optional(),
  streamRef: z.string().min(1).max(128).optional(),
  sha256: sha256Hex,
  maxBytes: maxTransferBytes,
  mode: fileMode,
  uid: fileOwnerId,
  gid: fileOwnerId
}).strict().refine(
  (value) => (value.dataBase64 === undefined) !== (value.streamRef === undefined),
  'exactly one of dataBase64 or streamRef is required'
);
const filePushResult = z.object({ sha256: sha256Hex, bytes: nonNegativeBytes }).strict();

const filePullParams = z.object({
  guestPath,
  maxBytes: maxTransferBytes,
  sha256: sha256Hex.optional()
}).strict();
const filePullResult = z.object({
  dataBase64: z.base64(),
  sha256: sha256Hex,
  bytes: nonNegativeBytes
}).strict();

const fileStatParams = z.object({ guestPath }).strict();
const fileStatResult = z.object({
  size: nonNegativeBytes,
  mode: z.number().int().min(0).max(0o7777),
  /** Modification time in milliseconds since epoch. */
  mtime: z.number().int(),
  isDir: z.boolean()
}).strict();

const fileListParams = z.object({
  guestPath,
  cursor: z.string().min(1).max(256).optional()
}).strict();
const fileListEntry = z.object({
  name: z.string().min(1).max(255),
  type: z.enum(['file', 'directory', 'symlink', 'other']),
  size: nonNegativeBytes.optional(),
  /** Modification time in milliseconds since epoch. */
  mtime: z.number().int().optional()
}).strict();
const fileListResult = z.object({
  entries: z.array(fileListEntry).max(10_000),
  cursor: z.string().max(256).optional()
}).strict();

const pushTreeParams = z.object({
  guestPath,
  maxBytes: maxTransferBytes,
  sha256: sha256Hex,
  mode: fileMode,
  uid: fileOwnerId,
  gid: fileOwnerId
}).strict();

const pullTreeParams = z.object({
  guestPath,
  maxBytes: maxTransferBytes,
  sha256: sha256Hex.optional()
}).strict();

const networkProgramParams = z.object({ networkProfile: ExecutorNetworkProfileSchema }).strict();
const networkProgramResult = z.object({
  rulesetDigest: sha256Hex,
  bridgeName: z.string().min(1).max(64).regex(/^[A-Za-z0-9][A-Za-z0-9_.-]*$/, 'invalid bridge name').optional(),
  guestIp: z.ipv4().optional()
}).strict();

const networkAttestResult = z.object({
  ok: z.boolean(),
  rulesetDigest: sha256Hex,
  drift: z.unknown().optional()
}).strict();

const networkTearDownResult = z.object({ removed: z.literal(true) }).strict();

const leaseSetParams = z.object({
  expiresAt: z.number().int().positive(),
  hardExpiresAt: z.number().int().positive()
}).strict().refine(
  (value) => value.hardExpiresAt >= value.expiresAt,
  'hardExpiresAt must not precede expiresAt'
);
const leaseSetResult = z.object({ effective: leaseTimes }).strict();

const leaseClearResult = z.object({ cleared: z.literal(true) }).strict();

// ---------------------------------------------------------------------------
// Host-envelope op params + results
// ---------------------------------------------------------------------------

const vmListParams = z.object({ workspaceId: WorkspaceIdSchema.optional() }).strict();
const vmListEntry = z.object({
  vmName: VmNameSchema,
  workspaceId: WorkspaceIdSchema.optional(),
  instanceId: VmInstanceIdSchema.optional(),
  state: VmInstanceStateSchema,
  userCloudHarness: VmUserCloudHarnessSchema.optional()
}).strict();
const vmListResult = z.array(vmListEntry).max(1_024);

const leaseListEntry = z.object({
  workspaceId: WorkspaceIdSchema,
  instanceId: VmInstanceIdSchema,
  generation: z.number().int().positive(),
  expiresAt: z.number().int().positive(),
  hardExpiresAt: z.number().int().positive(),
  state: VmLeaseStateSchema
}).strict();
const leaseListResult = z.array(leaseListEntry).max(1_024);

const poolInfoResult = z.object({
  poolPath: z.string().min(1).max(4_096),
  statfsFree: nonNegativeBytes,
  statfsTotal: nonNegativeBytes,
  volumes: z.array(z.object({
    vmName: VmNameSchema,
    configuredBytes: nonNegativeBytes,
    allocatedBytesStBlocks: nonNegativeBytes
  }).strict()).max(1_024),
  imageCacheBytes: nonNegativeBytes,
  managedRunningCount: z.number().int().nonnegative()
}).strict();

const reconcileResult = z.object({
  adopted: z.array(VmReconcileEntrySchema).max(1_024),
  quarantined: z.array(VmReconcileEntrySchema).max(1_024),
  stoppedUnleased: z.array(VmReconcileEntrySchema).max(1_024),
  foreignIgnored: z.array(VmReconcileEntrySchema).max(1_024),
  deferred: z.array(VmReconcileEntrySchema).max(1_024)
}).strict();

const guardStateResult = z.object({
  verdict: VmGuardVerdictSchema,
  rulesetHash: sha256Hex,
  /** Verdict timestamp in milliseconds since epoch. */
  attestedAt: z.number().int().nonnegative(),
  vms: z.array(z.object({
    vmName: VmNameSchema,
    verdict: VmGuardVerdictSchema
  }).strict()).max(1_024)
}).strict();

// ---------------------------------------------------------------------------
// Named result schemas (one per op; keyed into VmSupervisorOpResultSchemas)
// ---------------------------------------------------------------------------

export const VmAdmitResultSchema = vmAdmitResult;
export const VmCreateResultSchema = vmCreateResult;
export const VmStartResultSchema = vmStartResult;
export const VmStopResultSchema = vmStopResult;
export const VmDeleteResultSchema = vmDeleteResult;
export const VmStatusResultSchema = vmStatusResult;
export const VmExportResultSchema = VmTarTrailerSchema;
export const VmExecRunResultSchema = execRunResult;
export const VmExecInspectResultSchema = execInspectResult;
export const VmExecOpenResultSchema = execOpenResult;
export const VmExecWriteResultSchema = execWriteResult;
export const VmExecCloseResultSchema = execCloseResult;
export const VmExecResizeResultSchema = execResizeResult;
export const VmExecKillSessionResultSchema = execKillSessionResult;
export const VmFilePushResultSchema = filePushResult;
export const VmFilePullResultSchema = filePullResult;
export const VmFileStatResultSchema = fileStatResult;
export const VmFileListResultSchema = fileListResult;
export const VmPushTreeResultSchema = VmTarTrailerSchema;
export const VmPullTreeResultSchema = VmTarTrailerSchema;
export const VmNetworkProgramResultSchema = networkProgramResult;
export const VmNetworkAttestResultSchema = networkAttestResult;
export const VmNetworkTearDownResultSchema = networkTearDownResult;
export const VmLeaseSetResultSchema = leaseSetResult;
export const VmLeaseClearResultSchema = leaseClearResult;
export const VmInstanceListResultSchema = vmListResult;
export const VmLeaseListResultSchema = leaseListResult;
export const VmPoolInfoResultSchema = poolInfoResult;
export const VmReconcileResultSchema = reconcileResult;
export const VmGuardStateResultSchema = guardStateResult;

/**
 * Result schema per operation. The response envelope carries no `op`, so a
 * client validates `result` against the schema for the op it sent:
 * `VmSupervisorOpResultSchemas[request.op].parse(response.result)`.
 */
export const VmSupervisorOpResultSchemas = {
  'vm.admit': vmAdmitResult,
  'vm.create': vmCreateResult,
  'vm.start': vmStartResult,
  'vm.stop': vmStopResult,
  'vm.delete': vmDeleteResult,
  'vm.status': vmStatusResult,
  'vm.export': VmTarTrailerSchema,
  'exec.run': execRunResult,
  'exec.inspect': execInspectResult,
  'exec.open': execOpenResult,
  'exec.write': execWriteResult,
  'exec.close': execCloseResult,
  'exec.resize': execResizeResult,
  'exec.killSession': execKillSessionResult,
  'file.push': filePushResult,
  'file.pull': filePullResult,
  'file.stat': fileStatResult,
  'file.list': fileListResult,
  'pushTree': VmTarTrailerSchema,
  'pullTree': VmTarTrailerSchema,
  'network.program': networkProgramResult,
  'network.attest': networkAttestResult,
  'network.tearDown': networkTearDownResult,
  'lease.set': leaseSetResult,
  'lease.clear': leaseClearResult,
  'vm.list': vmListResult,
  'lease.list': leaseListResult,
  'pool.info': poolInfoResult,
  'reconcile': reconcileResult,
  'guard.state': guardStateResult
} as const;

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

const workspaceEnvelope = <Op extends string, Params extends z.ZodTypeAny>(op: Op, params: Params) =>
  z.object({
    version: z.literal(1),
    requestId,
    workspaceId: WorkspaceIdSchema,
    workspaceGeneration: z.number().int().positive(),
    vmInstanceId: VmInstanceIdSchema,
    idempotencyKey: IdempotencyKeySchema,
    issuedAt,
    op: z.literal(op),
    params
  }).strict();

const hostEnvelope = <Op extends string, Params extends z.ZodTypeAny>(op: Op, params: Params) =>
  z.object({
    version: z.literal(1),
    requestId,
    issuedAt,
    op: z.literal(op),
    params
  }).strict();

export const VmSupervisorWorkspaceRequestSchema = z.discriminatedUnion('op', [
  workspaceEnvelope('vm.admit', vmAdmitParams),
  workspaceEnvelope('vm.create', vmCreateParams),
  workspaceEnvelope('vm.start', vmStartParams),
  workspaceEnvelope('vm.stop', emptyParams),
  workspaceEnvelope('vm.delete', vmDeleteParams),
  workspaceEnvelope('vm.status', emptyParams),
  workspaceEnvelope('vm.export', vmExportParams),
  workspaceEnvelope('exec.run', execRunParams),
  workspaceEnvelope('exec.inspect', execInspectParams),
  workspaceEnvelope('exec.open', execOpenParams),
  workspaceEnvelope('exec.write', execWriteParams),
  workspaceEnvelope('exec.close', execCloseParams),
  workspaceEnvelope('exec.resize', execResizeParams),
  workspaceEnvelope('exec.killSession', execKillSessionParams),
  workspaceEnvelope('file.push', filePushParams),
  workspaceEnvelope('file.pull', filePullParams),
  workspaceEnvelope('file.stat', fileStatParams),
  workspaceEnvelope('file.list', fileListParams),
  workspaceEnvelope('pushTree', pushTreeParams),
  workspaceEnvelope('pullTree', pullTreeParams),
  workspaceEnvelope('network.program', networkProgramParams),
  workspaceEnvelope('network.attest', emptyParams),
  workspaceEnvelope('network.tearDown', emptyParams),
  workspaceEnvelope('lease.set', leaseSetParams),
  workspaceEnvelope('lease.clear', emptyParams)
]);
export type VmSupervisorWorkspaceRequest = z.infer<typeof VmSupervisorWorkspaceRequestSchema>;

export const VmSupervisorHostRequestSchema = z.discriminatedUnion('op', [
  hostEnvelope('vm.list', vmListParams),
  hostEnvelope('lease.list', emptyParams),
  hostEnvelope('pool.info', emptyParams),
  hostEnvelope('reconcile', emptyParams),
  hostEnvelope('guard.state', emptyParams)
]);
export type VmSupervisorHostRequest = z.infer<typeof VmSupervisorHostRequestSchema>;

export const VmSupervisorRequestSchema = z.union([
  VmSupervisorWorkspaceRequestSchema,
  VmSupervisorHostRequestSchema
]);
export type VmSupervisorRequest = z.infer<typeof VmSupervisorRequestSchema>;

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

export const VmSupervisorErrorSchema = z.object({
  code: ErrorCodeSchema,
  message: z.string().min(1).max(2_000),
  retryable: z.boolean()
}).strict();
export type VmSupervisorError = z.infer<typeof VmSupervisorErrorSchema>;

export const VmSupervisorOkResponseSchema = z.object({
  version: z.literal(1),
  requestId,
  ok: z.literal(true),
  /** Validated per-op via VmSupervisorOpResultSchemas; the envelope itself stays result-agnostic. */
  result: z.unknown()
}).strict();
export type VmSupervisorOkResponse = z.infer<typeof VmSupervisorOkResponseSchema>;

export const VmSupervisorErrorResponseSchema = z.object({
  version: z.literal(1),
  requestId,
  ok: z.literal(false),
  error: VmSupervisorErrorSchema,
  /** `unknown: true` means a mutation may have applied: reconcile via reads, NEVER blind-retry. */
  unknown: z.literal(true).optional()
}).strict();
export type VmSupervisorErrorResponse = z.infer<typeof VmSupervisorErrorResponseSchema>;

export const VmSupervisorResponseSchema = z.union([
  VmSupervisorOkResponseSchema,
  VmSupervisorErrorResponseSchema
]);
export type VmSupervisorResponse = z.infer<typeof VmSupervisorResponseSchema>;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export type VmAdmitResult = z.infer<typeof vmAdmitResult>;
export type VmCreateResult = z.infer<typeof vmCreateResult>;
export type VmStartResult = z.infer<typeof vmStartResult>;
export type VmStopResult = z.infer<typeof vmStopResult>;
export type VmDeleteResult = z.infer<typeof vmDeleteResult>;
export type VmStatusResult = z.infer<typeof vmStatusResult>;
export type VmExecRunResult = z.infer<typeof execRunResult>;
export type VmExecInspectResult = z.infer<typeof execInspectResult>;
export type VmExecOpenResult = z.infer<typeof execOpenResult>;
export type VmExecWriteResult = z.infer<typeof execWriteResult>;
export type VmExecCloseResult = z.infer<typeof execCloseResult>;
export type VmExecResizeResult = z.infer<typeof execResizeResult>;
export type VmExecKillSessionResult = z.infer<typeof execKillSessionResult>;
export type VmFilePushResult = z.infer<typeof filePushResult>;
export type VmFilePullResult = z.infer<typeof filePullResult>;
export type VmFileStatResult = z.infer<typeof fileStatResult>;
export type VmFileListResult = z.infer<typeof fileListResult>;
export type VmNetworkProgramResult = z.infer<typeof networkProgramResult>;
export type VmNetworkAttestResult = z.infer<typeof networkAttestResult>;
export type VmNetworkTearDownResult = z.infer<typeof networkTearDownResult>;
export type VmLeaseSetResult = z.infer<typeof leaseSetResult>;
export type VmLeaseClearResult = z.infer<typeof leaseClearResult>;
export type VmInstanceListResult = z.infer<typeof vmListResult>;
export type VmLeaseListResult = z.infer<typeof leaseListResult>;
export type VmPoolInfoResult = z.infer<typeof poolInfoResult>;
export type VmReconcileResult = z.infer<typeof reconcileResult>;
export type VmGuardStateResult = z.infer<typeof guardStateResult>;
export type VmSupervisorOpResult<Op extends VmSupervisorOperation> = z.infer<(typeof VmSupervisorOpResultSchemas)[Op]>;

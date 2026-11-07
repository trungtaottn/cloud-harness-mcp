import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { VmNetworkGuardError } from '../network-ops.js';
import type { VmNetworkSubject } from './policy.js';

/**
 * Durable guard state: the per-slot claim registry (ops-side, prevents two
 * workspaces silently sharing a truncated-hash bridge slot) and the verdict
 * JSON the independent guard service publishes. All writes are atomic
 * (temp file + rename in the same directory); all reads treat missing or
 * corrupt state as ABSENT — never as success.
 */

export interface GuardClaim {
  workspaceId: string;
  vmName: string;
  /** Derived fields kept for observability; subjects are always re-derived. */
  bridgeName: string;
  guestIp: string;
  claimedAt: number;
}

export interface GuardClaimsFile {
  version: 1;
  claims: Record<string, GuardClaim>;
}

export interface GuardVerdictVm {
  vmName: string;
  workspaceId?: string;
  status: string;
}

export interface GuardVerdictFile {
  verdict: 'ok' | 'degraded' | 'failed' | 'quarantined';
  rulesetHash: string;
  attestedAt: number;
  updatedAt: number;
  vms: GuardVerdictVm[];
  reason?: string;
}

async function atomicWriteJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  try {
    await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    await rename(tmp, path);
  } catch (error) {
    await rm(tmp, { force: true }).catch(() => undefined);
    throw new VmNetworkGuardError('guard-state-write', `cannot write ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function readJsonFile(path: string): Promise<unknown | null> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch {
    return null; // absent or unreadable → treated as no state, never success
  }
  try {
    return JSON.parse(raw);
  } catch {
    return null; // corrupt → treated as no state
  }
}

// ---------------------------------------------------------------------------
// Claims registry — keyed by bridge name (the scarce resource)
// ---------------------------------------------------------------------------

export function claimsPathFor(guardStatePath: string): string {
  return `${guardStatePath}.claims.json`;
}

export async function readGuardClaims(path: string): Promise<GuardClaimsFile> {
  const parsed = await readJsonFile(path);
  if (parsed === null || typeof parsed !== 'object') return { version: 1, claims: {} };
  const claims = (parsed as { claims?: unknown }).claims;
  if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) {
    return { version: 1, claims: {} };
  }
  const clean: Record<string, GuardClaim> = {};
  for (const [key, value] of Object.entries(claims as Record<string, unknown>)) {
    if (value === null || typeof value !== 'object') continue;
    const c = value as Record<string, unknown>;
    if (typeof c.workspaceId === 'string' && typeof c.vmName === 'string' && typeof c.bridgeName === 'string') {
      clean[key] = {
        workspaceId: c.workspaceId,
        vmName: c.vmName,
        bridgeName: c.bridgeName,
        guestIp: typeof c.guestIp === 'string' ? c.guestIp : '',
        claimedAt: typeof c.claimedAt === 'number' ? c.claimedAt : 0
      };
    }
  }
  return { version: 1, claims: clean };
}

async function writeGuardClaims(path: string, file: GuardClaimsFile): Promise<void> {
  await atomicWriteJson(path, file);
}

/**
 * Register the subject's bridge slot. Idempotent for the same workspace; a
 * bridge name already claimed by a DIFFERENT workspace is a hard collision —
 * the truncated-hash plan can collide and two guests must never share a /30.
 */
export async function claimSubject(path: string, subject: VmNetworkSubject, now: number): Promise<void> {
  const file = await readGuardClaims(path);
  const existing = file.claims[subject.bridgeName];
  if (existing && existing.workspaceId !== subject.workspaceId) {
    throw new VmNetworkGuardError(
      'bridge-slot-collision',
      `bridge '${subject.bridgeName}' is already claimed by workspace '${existing.workspaceId}'`
    );
  }
  file.claims[subject.bridgeName] = {
    workspaceId: subject.workspaceId,
    vmName: subject.vmName,
    bridgeName: subject.bridgeName,
    guestIp: subject.guestIp,
    claimedAt: now
  };
  await writeGuardClaims(path, file);
}

/** Release a claim — only when it still belongs to this workspace. */
export async function releaseSubject(path: string, subject: VmNetworkSubject): Promise<void> {
  const file = await readGuardClaims(path);
  const existing = file.claims[subject.bridgeName];
  if (!existing || existing.workspaceId !== subject.workspaceId) return;
  delete file.claims[subject.bridgeName];
  await writeGuardClaims(path, file);
}

/** Claims belonging to one workspace (for guard-service reconciliation). */
export async function claimsForWorkspace(path: string, workspaceId: string): Promise<GuardClaim[]> {
  const file = await readGuardClaims(path);
  return Object.values(file.claims).filter((c) => c.workspaceId === workspaceId);
}

export async function allClaims(path: string): Promise<GuardClaim[]> {
  const file = await readGuardClaims(path);
  return Object.values(file.claims);
}

// ---------------------------------------------------------------------------
// Verdict file — published by the independent guard service
// ---------------------------------------------------------------------------

export async function readGuardVerdict(path: string): Promise<GuardVerdictFile | null> {
  const parsed = await readJsonFile(path);
  if (parsed === null || typeof parsed !== 'object') return null;
  const v = parsed as Record<string, unknown>;
  if (
    (v.verdict !== 'ok' && v.verdict !== 'degraded' && v.verdict !== 'failed' && v.verdict !== 'quarantined') ||
    typeof v.rulesetHash !== 'string' ||
    typeof v.attestedAt !== 'number' ||
    !Array.isArray(v.vms)
  ) {
    return null;
  }
  const verdict: GuardVerdictFile = {
    verdict: v.verdict,
    rulesetHash: v.rulesetHash,
    attestedAt: v.attestedAt,
    updatedAt: typeof v.updatedAt === 'number' ? v.updatedAt : v.attestedAt,
    vms: (v.vms as unknown[]).flatMap((entry) => {
      if (entry === null || typeof entry !== 'object') return [];
      const e = entry as Record<string, unknown>;
      if (typeof e.vmName !== 'string' || typeof e.status !== 'string') return [];
      const vm: GuardVerdictVm = { vmName: e.vmName, status: e.status };
      if (typeof e.workspaceId === 'string') vm.workspaceId = e.workspaceId;
      return [vm];
    })
  };
  if (typeof v.reason === 'string') verdict.reason = v.reason;
  return verdict;
}

export async function writeGuardVerdict(path: string, verdict: GuardVerdictFile): Promise<void> {
  await atomicWriteJson(path, verdict);
}

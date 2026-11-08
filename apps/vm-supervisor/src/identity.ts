import { createHash } from 'node:crypto';
import { VmUserCloudHarnessSchema, type VmUserCloudHarness } from '@cloud-harness/contracts';

/**
 * VM identity model (frozen by phase-04 plan):
 * `vm_name = 'chm-vm-' + sha256(workspaceId).hex.slice(0,32)` — DNS-safe and
 * deterministic. The truncated hash is NOT injective, so the authoritative
 * identity lives in the instance's `user.cloud-harness.*` expanded config and
 * is verified in full on every adopt/start. A name match alone never adopts.
 */
export function vmNameForWorkspace(workspaceId: string): string {
  return `chm-vm-${createHash('sha256').update(workspaceId, 'utf8').digest('hex').slice(0, 32)}`;
}

export const VM_IDENTITY_CONFIG_KEYS = {
  workspaceId: 'user.cloud-harness.workspace-id',
  instanceId: 'user.cloud-harness.instance-id',
  templateId: 'user.cloud-harness.template-id',
  templateDigest: 'user.cloud-harness.template-digest',
  generationPolicy: 'user.cloud-harness.generation-policy',
  backend: 'user.cloud-harness.backend'
} as const;

export const VM_GENERATION_POLICY = 'external';
export const VM_BACKEND_KIND = 'incus-vm';

/** Full `user.cloud-harness.*` config block stamped at create. */
export function identityConfigBlock(identity: {
  workspaceId: string;
  instanceId: string;
  templateId: string;
  templateDigest: string;
}): Record<string, string> {
  return {
    [VM_IDENTITY_CONFIG_KEYS.workspaceId]: identity.workspaceId,
    [VM_IDENTITY_CONFIG_KEYS.instanceId]: identity.instanceId,
    [VM_IDENTITY_CONFIG_KEYS.templateId]: identity.templateId,
    [VM_IDENTITY_CONFIG_KEYS.templateDigest]: identity.templateDigest,
    [VM_IDENTITY_CONFIG_KEYS.generationPolicy]: VM_GENERATION_POLICY,
    [VM_IDENTITY_CONFIG_KEYS.backend]: VM_BACKEND_KIND
  };
}

/** Parse the `user.cloud-harness.*` block out of an expanded Incus config. */
export function readIdentityFromConfig(config: Readonly<Record<string, unknown>>): VmUserCloudHarness | undefined {
  const get = (key: string): string | undefined => {
    const value = config[key];
    return typeof value === 'string' ? value : undefined;
  };
  const workspaceId = get(VM_IDENTITY_CONFIG_KEYS.workspaceId);
  const instanceId = get(VM_IDENTITY_CONFIG_KEYS.instanceId);
  const templateId = get(VM_IDENTITY_CONFIG_KEYS.templateId);
  const templateDigest = get(VM_IDENTITY_CONFIG_KEYS.templateDigest);
  const generationPolicy = get(VM_IDENTITY_CONFIG_KEYS.generationPolicy);
  const backend = get(VM_IDENTITY_CONFIG_KEYS.backend);
  if (
    workspaceId === undefined || instanceId === undefined || templateId === undefined ||
    templateDigest === undefined || generationPolicy !== VM_GENERATION_POLICY ||
    backend !== VM_BACKEND_KIND
  ) {
    return undefined;
  }
  const parsed = VmUserCloudHarnessSchema.safeParse({
    workspaceId, instanceId, templateId, templateDigest, generationPolicy
  });
  return parsed.success ? parsed.data : undefined;
}

export type VmIdentityVerdict =
  | { ok: true; identity: VmUserCloudHarness }
  | { ok: false; reason: string };

/**
 * Verify an expanded instance config against the expected identity. Every
 * field must match exactly; missing/foreign markers fail closed.
 */
export function verifyIdentityFromConfig(
  config: Readonly<Record<string, unknown>>,
  expected: { workspaceId: string; instanceId: string; templateId: string; templateDigest: string }
): VmIdentityVerdict {
  const found = readIdentityFromConfig(config);
  if (found === undefined) {
    return { ok: false, reason: 'missing or malformed user.cloud-harness.* identity metadata' };
  }
  if (found.workspaceId !== expected.workspaceId) return { ok: false, reason: 'workspace-id mismatch' };
  if (found.instanceId !== expected.instanceId) return { ok: false, reason: 'instance-id mismatch' };
  if (found.templateId !== expected.templateId) return { ok: false, reason: 'template-id mismatch' };
  if (found.templateDigest !== expected.templateDigest) return { ok: false, reason: 'template-digest mismatch' };
  return { ok: true, identity: found };
}

/** Managed-instance marker: any instance carrying our workspace-id key. */
export function isManagedInstanceConfig(config: Readonly<Record<string, unknown>>): boolean {
  return typeof config[VM_IDENTITY_CONFIG_KEYS.workspaceId] === 'string';
}

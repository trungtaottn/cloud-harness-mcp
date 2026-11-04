import { describe, expect, it } from 'vitest';
import { MetadataRunnerRequestSchema, RunnerOperationSchema, TOOL_SCHEMA_BY_NAME, TOOL_SPECS } from '../src/index.js';
const workspaceId = `ws_${'a'.repeat(24)}`;
const planId = `dep_${'b'.repeat(24)}`;
const planDigest = 'c'.repeat(64);

describe('project dependency tool contract', () => {
  it('exposes planning, apply and status with effect annotations, keeping approval Dashboard-only', () => {
    const expected = {
      dependencies_plan: { readOnly: false, destructive: false, idempotent: false, openWorld: false },
      dependencies_apply: { readOnly: false, destructive: true, idempotent: true, openWorld: true },
      dependencies_status: { readOnly: true, destructive: false, idempotent: true, openWorld: false }
    };
    for (const [name, annotations] of Object.entries(expected)) {
      expect(RunnerOperationSchema.options).toContain(name);
      expect(TOOL_SPECS.find((tool) => tool.name === name)).toMatchObject(annotations);
    }
    for (const operation of ['dependency_plan_approve', 'dependency_plan_reject']) {
      expect(RunnerOperationSchema.options).not.toContain(operation);
      expect(TOOL_SPECS.some((tool) => tool.name === operation)).toBe(false);
    }
  });
  it('requires an owned workspace and confines plan directories', () => {
    const schema = TOOL_SCHEMA_BY_NAME.dependencies_plan;
    expect(schema.parse({ workspaceId, ecosystem: 'go' }).directory).toBe('.');
    expect(schema.parse({ workspaceId, ecosystem: 'pnpm', directory: 'apps/web' }).directory).toBe('apps/web');
    for (const directory of ['..', '../private', '/workspace', 'app/../private', 'app//web', './app', 'app\\web']) {
      expect(schema.safeParse({ workspaceId, ecosystem: 'go', directory }).success).toBe(false);
    }
    expect(schema.safeParse({ ecosystem: 'go' }).success).toBe(false);
    expect(schema.safeParse({ workspaceId, ecosystem: 'npm' }).success).toBe(false);
    expect(schema.safeParse({ workspaceId, ecosystem: 'go', hosts: ['evil.example'] }).success).toBe(false);
  });
  it('binds apply to workspace, plan and full digest without permission overrides', () => {
    const schema = TOOL_SCHEMA_BY_NAME.dependencies_apply;
    const valid = { workspaceId, planId, planDigest };
    expect(schema.safeParse(valid).success).toBe(true);
    for (const field of Object.keys(valid)) {
      const missing = { ...valid } as Record<string, unknown>;
      delete missing[field];
      expect(schema.safeParse(missing).success).toBe(false);
    }
    expect(schema.safeParse({ ...valid, planDigest: 'wrong' }).success).toBe(false);
    expect(schema.safeParse({ ...valid, approved: true }).success).toBe(false);
    expect(schema.safeParse({ ...valid, scripts: 'allow' }).success).toBe(false);
  });
  it('scopes status and validates Dashboard approval digest without publishing approval as MCP', () => {
    expect(TOOL_SCHEMA_BY_NAME.dependencies_status.safeParse({ workspaceId }).success).toBe(true);
    expect(TOOL_SCHEMA_BY_NAME.dependencies_status.safeParse({ workspaceId, planId }).success).toBe(true);
    expect(TOOL_SCHEMA_BY_NAME.dependencies_status.safeParse({ planId }).success).toBe(false);
    expect(TOOL_SCHEMA_BY_NAME.dependencies_status.safeParse({ workspaceId, ownerId: 'someone' }).success).toBe(false);
    const request = { version: 2, principal: { kind: 'external', issuer: 'https://access.example', subject: 'owner' }, operation: 'dependency_plan_approve', input: { planId, planDigest } };
    expect(MetadataRunnerRequestSchema.safeParse(request).success).toBe(true);
    expect(MetadataRunnerRequestSchema.safeParse({ ...request, input: { planId } }).success).toBe(false);
  });
});

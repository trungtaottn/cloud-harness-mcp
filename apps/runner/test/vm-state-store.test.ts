import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it } from 'vitest';
import { downgradeStateSchemaToV5, StateStore, type WorkspaceRecord } from '../src/state-store.js';

const TEMPLATE_DIGEST = 'b'.repeat(64);

function vmNameFor(workspaceId: string): string {
  return `chm-vm-${createHash('sha256').update(workspaceId).digest('hex').slice(0, 32)}`;
}

function workspaceRecord(overrides: Partial<WorkspaceRecord> = {}): WorkspaceRecord {
  const now = Date.now();
  return {
    id: `ws_${'a'.repeat(24)}`,
    ownerId: 'owner',
    idempotencyKey: `key-${Math.random().toString(36).slice(2, 12)}`,
    repositoryUrl: 'https://github.com/example/repository.git',
    repositoryRef: null,
    containerName: null,
    workspacePath: '/var/lib/cloud-harness/jobs/ws-test',
    environmentId: null,
    status: 'ACTIVE',
    networkProfile: 'network-none',
    createdAt: now,
    lastActivityAt: now,
    expiresAt: now + 600_000,
    hardExpiresAt: now + 3_600_000,
    gitAuthorName: null,
    gitAuthorEmail: null,
    mutationLockedUntil: null,
    generation: 1,
    error: null,
    ...overrides
  };
}

function vmRecord(workspaceId: string, overrides: Partial<WorkspaceRecord> = {}): WorkspaceRecord {
  return workspaceRecord({
    id: workspaceId,
    backendKind: 'incus-vm',
    vmName: vmNameFor(workspaceId),
    backendInstanceId: randomUUID(),
    templateId: 'cloud-harness/ubuntu-vm:24.04',
    templateDigest: TEMPLATE_DIGEST,
    ...overrides
  });
}

const identityColumns = ['backend_kind', 'vm_name', 'backend_instance_id', 'template_id', 'template_digest'];

describe('VM workspace backend identity persistence', () => {
  const directories: string[] = [];
  afterEach(() => {
    for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
  });

  function open(): { store: StateStore; path: string } {
    const directory = mkdtempSync(join(tmpdir(), 'vm-state-'));
    directories.push(directory);
    const path = join(directory, 'state.sqlite');
    return { store: new StateStore(path), path };
  }

  it('adds all five backend identity columns to a fresh database', () => {
    const { store } = open();
    try {
      const columns = (store.database.prepare('PRAGMA table_info(workspaces)').all() as { name: string }[]).map((c) => c.name);
      for (const name of identityColumns) expect(columns).toContain(name);
    } finally {
      store.close();
    }
  });

  it('reads a legacy docker row with backendKind docker and null identity fields', () => {
    const { store } = open();
    try {
      // Simulate a pre-VM row by writing only the docker-visible columns directly.
      const now = Date.now();
      store.database.prepare(`INSERT INTO workspaces
        (id, owner_id, idempotency_key, repository_url, repository_ref, container_name, workspace_path,
         environment_id, status, network_profile, created_at, last_activity_at, expires_at, hard_expires_at,
         git_author_name, git_author_email, mutation_locked_until, mutation_lock_count, generation, error,
         request_fingerprint, idle_ttl_seconds, recoverable_grace_seconds, expired_at, recoverable_until)
        VALUES (?, 'owner', ?, 'https://github.com/example/repository.git', NULL, NULL, '/tmp/ws', NULL,
          'ACTIVE', 'network-none', ?, ?, ?, ?, NULL, NULL, NULL, 0, 1, NULL, NULL, NULL, NULL, NULL, NULL)`)
        .run('ws_legacy0000000000000000001', 'legacy-key-1', now, now, now + 600_000, now + 3_600_000);
      const record = store.byId('ws_legacy0000000000000000001');
      expect(record?.backendKind).toBe('docker');
      expect(record?.vmName).toBeNull();
      expect(record?.backendInstanceId).toBeNull();
      expect(record?.templateId).toBeNull();
      expect(record?.templateDigest).toBeNull();
    } finally {
      store.close();
    }
  });

  it('persists a full incus-vm identity at admit and reads it back', () => {
    const { store } = open();
    try {
      const record = vmRecord(`ws_${'b'.repeat(24)}`);
      store.create(record);
      const read = store.byId(record.id);
      expect(read?.backendKind).toBe('incus-vm');
      expect(read?.vmName).toBe(record.vmName);
      expect(read?.backendInstanceId).toBe(record.backendInstanceId);
      expect(read?.templateId).toBe(record.templateId);
      expect(read?.templateDigest).toBe(record.templateDigest);
    } finally {
      store.close();
    }
  });

  it('rejects an incus-vm record missing any identity field', () => {
    const { store } = open();
    try {
      const id = `ws_${'c'.repeat(24)}`;
      for (const field of ['vmName', 'backendInstanceId', 'templateId', 'templateDigest'] as const) {
        expect(() => store.create(vmRecord(id, { [field]: null }))).toThrow();
      }
      expect(store.byId(id)).toBeUndefined();
    } finally {
      store.close();
    }
  });

  it('rejects a docker record carrying VM identity fields', () => {
    const { store } = open();
    try {
      expect(() => store.create(workspaceRecord({ vmName: vmNameFor(`ws_${'d'.repeat(24)}`) }))).toThrow(/docker/);
      expect(() => store.create(workspaceRecord({ backendInstanceId: randomUUID() }))).toThrow(/docker/);
    } finally {
      store.close();
    }
  });

  it('rejects malformed persisted identity formats at admit', () => {
    const { store } = open();
    try {
      const id = `ws_${'e'.repeat(24)}`;
      expect(() => store.create(vmRecord(id, { vmName: 'chm-vm-NOTHEX' }))).toThrow();
      expect(() => store.create(vmRecord(id, { backendInstanceId: 'not-a-uuid' }))).toThrow();
      expect(() => store.create(vmRecord(id, { templateDigest: 'A'.repeat(64) }))).toThrow();
    } finally {
      store.close();
    }
  });

  it('rejects persisting an unknown backend_kind at the storage layer', () => {
    const { store } = open();
    try {
      const record = vmRecord(`ws_${'f'.repeat(24)}`);
      store.create(record);
      // The column CHECK makes an unrecognized backend kind unrepresentable, so a
      // corrupt read can never be silently treated as docker.
      expect(() => store.database.prepare("UPDATE workspaces SET backend_kind = 'containerd' WHERE id = ?").run(record.id)).toThrow(/CHECK/);
      expect(store.byId(record.id)?.backendKind).toBe('incus-vm');
    } finally {
      store.close();
    }
  });

  it('cannot rewrite identity through fenced or generic lifecycle updates', () => {
    const { store } = open();
    try {
      const record = vmRecord(`ws_${'1'.repeat(24)}`, { status: 'CREATING' });
      store.create(record);
      const updated = store.updateFenced(record.id, record.generation, ['CREATING'], {
        status: 'ACTIVE', containerName: 'chm-vm-x', lastActivityAt: Date.now(), expiresAt: record.expiresAt
      });
      expect(updated?.status).toBe('ACTIVE');
      store.update(record.id, { status: 'REAPING', generation: 2 });
      const read = store.byId(record.id);
      expect(read?.backendKind).toBe('incus-vm');
      expect(read?.vmName).toBe(record.vmName);
      expect(read?.backendInstanceId).toBe(record.backendInstanceId);
      expect(read?.templateId).toBe(record.templateId);
      expect(read?.templateDigest).toBe(record.templateDigest);
    } finally {
      store.close();
    }
  });

  it('survives claim transitions without touching identity columns', () => {
    const { store } = open();
    try {
      const record = vmRecord(`ws_${'2'.repeat(24)}`, { status: 'ACTIVE' });
      store.create(record);
      expect(store.claimForReaping(record.id, record.generation)).toBe(true);
      const reaping = store.byId(record.id);
      expect(reaping?.status).toBe('REAPING');
      expect(reaping?.vmName).toBe(record.vmName);
      expect(reaping?.backendInstanceId).toBe(record.backendInstanceId);
    } finally {
      store.close();
    }
  });
});

describe('countActiveByBackend', () => {
  const directories: string[] = [];
  afterEach(() => {
    for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
  });

  function open(): StateStore {
    const directory = mkdtempSync(join(tmpdir(), 'vm-state-count-'));
    directories.push(directory);
    return new StateStore(join(directory, 'state.sqlite'));
  }

  it('counts only the active-slot statuses of the requested backend', () => {
    const store = open();
    try {
      const now = Date.now();
      const statuses = ['CREATING', 'ACTIVE', 'NETWORK_QUARANTINED', 'REAPING', 'CLOSED', 'FAILED', 'EXPIRED_RECOVERABLE'] as const;
      statuses.forEach((status, index) => {
        store.create(vmRecord(`ws_vm${String(index).padStart(21, '0')}`, { status, expiresAt: now + 600_000 }));
        store.create(workspaceRecord({
          id: `ws_dk${String(index).padStart(22, '0')}`,
          status,
          expiresAt: now + 600_000
        }));
      });
      // CREATING+ACTIVE+NETWORK_QUARANTINED+REAPING on incus-vm = 4; CLOSED/FAILED/EXPIRED_RECOVERABLE excluded.
      expect(store.countActiveByBackend('incus-vm')).toBe(4);
      expect(store.countActiveByBackend('docker')).toBe(4);
    } finally {
      store.close();
    }
  });
});

describe('backend identity migration', () => {
  const directories: string[] = [];
  afterEach(() => {
    for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
  });

  it('preserves VM identity through a downgrade-to-v5 and re-upgrade round trip', () => {
    const directory = mkdtempSync(join(tmpdir(), 'vm-state-migrate-'));
    directories.push(directory);
    const path = join(directory, 'state.sqlite');
    const record = vmRecord(`ws_${'3'.repeat(24)}`);
    {
      const store = new StateStore(path);
      try {
        store.create(record);
        downgradeStateSchemaToV5(store.database);
      } finally {
        store.close();
      }
    }
    {
      const store = new StateStore(path);
      try {
        const read = store.byId(record.id);
        expect(read?.backendKind).toBe('incus-vm');
        expect(read?.vmName).toBe(record.vmName);
        expect(read?.backendInstanceId).toBe(record.backendInstanceId);
        expect(read?.templateId).toBe(record.templateId);
        expect(read?.templateDigest).toBe(record.templateDigest);
      } finally {
        store.close();
      }
    }
  });

  it('re-adds the columns on boot when an older database shape lacks them', () => {
    const directory = mkdtempSync(join(tmpdir(), 'vm-state-migrate2-'));
    directories.push(directory);
    const path = join(directory, 'state.sqlite');
    const legacyId = `ws_${'4'.repeat(24)}`;
    {
      const store = new StateStore(path);
      try {
        store.create(workspaceRecord({ id: legacyId }));
      } finally {
        store.close();
      }
    }
    // Emulate a pre-VM database: drop the five identity columns, then reopen so the
    // constructor migration path must restore them and read the legacy row as docker.
    {
      const database = new DatabaseSync(path);
      try {
        for (const name of identityColumns) {
          database.exec(`ALTER TABLE workspaces DROP COLUMN ${name}`);
        }
      } finally {
        database.close();
      }
    }
    {
      const store = new StateStore(path);
      try {
        const columns = (store.database.prepare('PRAGMA table_info(workspaces)').all() as { name: string }[]).map((c) => c.name);
        for (const name of identityColumns) expect(columns).toContain(name);
        const read = store.byId(legacyId);
        expect(read?.backendKind).toBe('docker');
        expect(read?.vmName).toBeNull();
        expect(read?.backendInstanceId).toBeNull();
        expect(read?.templateId).toBeNull();
        expect(read?.templateDigest).toBeNull();
      } finally {
        store.close();
      }
    }
  });
});

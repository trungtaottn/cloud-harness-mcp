import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  allClaims,
  claimSubject,
  claimsForWorkspace,
  claimsPathFor,
  readGuardClaims,
  readGuardVerdict,
  releaseSubject,
  writeGuardVerdict
} from '../../src/network/state.js';
import { planWorkspaceSubject, deriveVmName, validateGuardConfig } from '../../src/network/policy.js';
import type { VmNetworkSubject } from '../../src/network/policy.js';

let dir: string;
let claimsPath: string;
let verdictPath: string;
let subjectA: VmNetworkSubject;
let subjectB: VmNetworkSubject;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'chm-guard-state-'));
  verdictPath = join(dir, 'guard-state.json');
  claimsPath = claimsPathFor(verdictPath);
  const config = validateGuardConfig({
    bridgePattern: 'chmbr%d',
    subnetPlan: '10.240.0.0/16',
    uplink: 'enp7s0',
    dnsResolvers: ['1.1.1.1'],
    nonpublicCidrs: [],
    guardStatePath: verdictPath
  });
  subjectA = planWorkspaceSubject(config, { workspaceId: 'ws_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', vmName: deriveVmName('ws_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') });
  subjectB = planWorkspaceSubject(config, { workspaceId: 'ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', vmName: deriveVmName('ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb') });
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('claims registry', () => {
  it('absent claims read as empty; corrupt or malformed claims fail closed and are preserved', async () => {
    // Genuinely absent (ENOENT) → empty registry — first boot is normal.
    expect((await readGuardClaims(claimsPath)).claims).toEqual({});

    // Unparseable JSON → typed error, file left byte-identical for operator.
    await writeFile(claimsPath, 'not json{{{', 'utf8');
    await expect(readGuardClaims(claimsPath)).rejects.toMatchObject({ reason: 'guard-claims-corrupt' });
    expect(await readFile(claimsPath, 'utf8')).toBe('not json{{{');

    // Wrong top-level shape → corrupt.
    await writeFile(claimsPath, '{"version":1,"claims":"bogus"}', 'utf8');
    await expect(readGuardClaims(claimsPath)).rejects.toMatchObject({ reason: 'guard-claims-corrupt' });

    // Missing version → corrupt.
    await writeFile(claimsPath, '{"claims":{}}', 'utf8');
    await expect(readGuardClaims(claimsPath)).rejects.toMatchObject({ reason: 'guard-claims-corrupt' });

    // A claim entry missing required identity fields → corrupt (never
    // silently dropped — dropping would lose coverage).
    await writeFile(
      claimsPath,
      JSON.stringify({ version: 1, claims: { chmbr0: { workspaceId: 'ws_x' } } }),
      'utf8'
    );
    await expect(readGuardClaims(claimsPath)).rejects.toMatchObject({ reason: 'guard-claims-corrupt' });

    // Map key disagreeing with the claim's bridgeName → corrupt.
    await writeFile(
      claimsPath,
      JSON.stringify({
        version: 1,
        claims: {
          chmbr0: { workspaceId: 'ws_x', vmName: 'chm-vm-x', bridgeName: 'chmbr9', guestIp: '', claimedAt: 1 }
        }
      }),
      'utf8'
    );
    await expect(readGuardClaims(claimsPath)).rejects.toMatchObject({ reason: 'guard-claims-corrupt' });
  });

  it('corrupt claims block writers — evidence is never overwritten', async () => {
    await claimSubject(claimsPath, subjectA, 1);
    await writeFile(claimsPath, '{"version":1,"claims":{corrupt', 'utf8');
    const before = await readFile(claimsPath, 'utf8');
    // claimSubject must fail closed BEFORE writing — the corrupt file and
    // every claim it might have contained survive for the operator.
    await expect(claimSubject(claimsPath, subjectB, 2)).rejects.toMatchObject({ reason: 'guard-claims-corrupt' });
    await expect(releaseSubject(claimsPath, subjectA)).rejects.toMatchObject({ reason: 'guard-claims-corrupt' });
    expect(await readFile(claimsPath, 'utf8')).toBe(before);
  });

  it('claims are idempotent per workspace and collide across workspaces', async () => {
    await claimSubject(claimsPath, subjectA, 1000);
    await claimSubject(claimsPath, subjectA, 2000); // same workspace re-claim OK
    const file = await readGuardClaims(claimsPath);
    expect(Object.keys(file.claims)).toHaveLength(1);
    expect(file.claims[subjectA.bridgeName]?.claimedAt).toBe(2000);

    // Forge a competing claim on the same bridge slot.
    const foreign = { ...subjectB, bridgeName: subjectA.bridgeName };
    await expect(claimSubject(claimsPath, foreign, 3000)).rejects.toMatchObject({ reason: 'bridge-slot-collision' });
  });

  it('release only removes the matching workspace claim', async () => {
    await claimSubject(claimsPath, subjectA, 1);
    await claimSubject(claimsPath, subjectB, 2);
    const foreign = { ...subjectB, bridgeName: subjectA.bridgeName, workspaceId: 'ws_other' };
    await releaseSubject(claimsPath, foreign); // wrong workspace → no-op
    expect(Object.keys((await readGuardClaims(claimsPath)).claims)).toHaveLength(2);
    await releaseSubject(claimsPath, subjectA);
    const claims = await allClaims(claimsPath);
    expect(claims).toHaveLength(1);
    expect(claims[0]!.workspaceId).toBe(subjectB.workspaceId);
    expect(await claimsForWorkspace(claimsPath, subjectB.workspaceId)).toHaveLength(1);
  });

  it('writes atomically — no temp files left behind', async () => {
    await claimSubject(claimsPath, subjectA, 1);
    const entries = await import('node:fs/promises').then((fs) => fs.readdir(dir));
    expect(entries.filter((e) => e.includes('.tmp-'))).toHaveLength(0);
    const raw = await readFile(claimsPath, 'utf8');
    expect(JSON.parse(raw).claims[subjectA.bridgeName].vmName).toBe(subjectA.vmName);
  });
});

describe('verdict file', () => {
  it('round-trips a well-formed verdict', async () => {
    await writeGuardVerdict(verdictPath, {
      verdict: 'ok',
      rulesetHash: 'a'.repeat(64),
      attestedAt: 1234,
      updatedAt: 1235,
      vms: [{ vmName: 'chm-vm-x', workspaceId: 'ws_1', status: 'Running' }]
    });
    const read = await readGuardVerdict(verdictPath);
    expect(read?.verdict).toBe('ok');
    expect(read?.rulesetHash).toBe('a'.repeat(64));
    expect(read?.vms).toHaveLength(1);
    expect(read?.vms[0]?.workspaceId).toBe('ws_1');
  });

  it('missing, corrupt or malformed verdicts read as null — never success', async () => {
    expect(await readGuardVerdict(verdictPath)).toBeNull();
    await writeFile(verdictPath, '{oops', 'utf8');
    expect(await readGuardVerdict(verdictPath)).toBeNull();
    await writeFile(verdictPath, JSON.stringify({ verdict: 'ok' }), 'utf8'); // missing fields
    expect(await readGuardVerdict(verdictPath)).toBeNull();
    await writeFile(verdictPath, JSON.stringify({ verdict: 'bogus', rulesetHash: 'x', attestedAt: 1, vms: [] }), 'utf8');
    expect(await readGuardVerdict(verdictPath)).toBeNull();
  });
});

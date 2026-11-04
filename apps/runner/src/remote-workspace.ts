import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, readFile, readdir, rename, rm, stat, utimes } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { HarnessError, type RunnerConfig } from '@cloud-harness/contracts';
import type { ExecutorStore, ExecutorAllocationState } from './executor-store.js';
import { InstaBoxBackend } from './executors/instabox-backend.js';
import type { RemoteExecutorRef, ExecutionResult } from './executors/execution-backend.js';
import type { WorkspaceRecord } from './state-store.js';
import { REPOSITORY_SUB_RANK } from './skill-resolver.js';
import { runDocker, removeContainer } from './docker-engine.js';
import { remoteCleanupCommand } from './remote-cleanup.js';

const executeFile = promisify(execFile);
export const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
async function digest(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

/** Remote transport only; authorization, admission and Git credentials remain with WorkspaceService. */
export class RemoteWorkspace {
  readonly backend: InstaBoxBackend;
  constructor(readonly allocations: ExecutorStore, private readonly config: RunnerConfig) {
    if (!config.instabox) throw new Error('InstaBox configuration is required');
    this.backend = new InstaBoxBackend({
      apiKey: config.instabox.apiKey, allowedMachineIds: config.instabox.machineIds,
      principalId: config.instabox.principalId, validateRef: ref => allocations.assertRef(ref)
    });
  }
  ref(record: Pick<WorkspaceRecord, 'id' | 'ownerId'>): RemoteExecutorRef {
    const allocation = this.allocations.byWorkspace(record.id);
    if (!allocation || allocation.ownerId !== record.ownerId) throw new HarnessError('UNAVAILABLE', 'Retained remote allocation is unavailable; refusing replacement', 503, false);
    this.allocations.assertRef(allocation);
    const { provider, workspaceId, ownerId, machineId, generation, root } = allocation;
    return { provider, workspaceId, ownerId, machineId, generation, root };
  }
  private claim(ref: RemoteExecutorRef, allowed: readonly ExecutorAllocationState[], state: ExecutorAllocationState): number {
    this.allocations.assertRef(ref);
    const current = this.allocations.byWorkspace(ref.workspaceId)!;
    if (!allowed.includes(current.state) || !this.allocations.setState(ref, state, current.stateGeneration)) {
      throw new HarnessError('CONFLICT', 'Remote lifecycle is owned by another operation or requires recovery', 409, true);
    }
    return current.stateGeneration + 1;
  }
  private checkClaim(ref: RemoteExecutorRef, generation: number, state: ExecutorAllocationState): void {
    this.allocations.assertRef(ref);
    const current = this.allocations.byWorkspace(ref.workspaceId)!;
    if (current.stateGeneration !== generation || current.state !== state) {
      throw new HarnessError('CONFLICT', 'Remote lifecycle allocation fence was lost', 409, false);
    }
  }
  private publish(ref: RemoteExecutorRef, generation: number, state: ExecutorAllocationState): void {
    if (!this.allocations.setState(ref, state, generation)) {
      throw new HarnessError('CONFLICT', 'Remote lifecycle publication lost its allocation fence', 409, false);
    }
  }
  private quarantine(ref: RemoteExecutorRef, generation: number): void {
    // Never overwrite a different operation's newer fence.
    this.allocations.setState(ref, 'QUARANTINED', generation);
  }
  async reserve(record: WorkspaceRecord): Promise<boolean> {
    const settings = this.config.instabox!;
    if (record.ownerId !== settings.principalId) return false;
    const candidates = [...settings.machineIds];
    while (candidates.length) {
      const ref = this.allocations.reserve(record.id, record.ownerId, candidates);
      if (!ref) return false;
      const claim = this.claim(ref, ['RESERVED'], 'STARTING');
      const abandon = () => {
        // Inventory issued no mutating provider calls; an owned fresh reservation is safe to release.
        this.publish(ref, claim, 'RESERVED');
        this.publish(ref, claim + 1, 'RELEASING');
        if (!this.allocations.release(ref, claim + 2)) throw new HarnessError('CONFLICT', 'Reservation release lost its fence', 409, false);
      };
      let state;
      try { state = await this.backend.inspect(ref); }
      catch (error) { abandon(); throw error; }
      if (state.cooldownUntil && Date.parse(state.cooldownUntil) > Date.now()) {
        abandon(); candidates.splice(candidates.indexOf(ref.machineId), 1); continue;
      }
      if (!['running', 'stopped', 'suspended'].includes(state.state)) {
        abandon();
        throw new HarnessError('UNAVAILABLE', 'Remote machine is transitioning; retry admission after provider reconciliation', 503, true);
      }
      this.publish(ref, claim, 'RESERVED');
      return true;
    }
    return false;
  }
  async provision(record: WorkspaceRecord, environment: Record<string, string>): Promise<void> {
    const ref = this.ref(record);
    const claim = this.claim(ref, ['RESERVED'], 'STARTING');
    try {
    await this.backend.start(ref);
    this.checkClaim(ref, claim, 'STARTING');
    const files = await Promise.all(['harness-worker.mjs', 'git-transfer-helper.sh', 'workspace-transfer.mjs'].map(async name => ({
      path: `runtime/${name}`, content: await readFile(resolve('worker', name), 'utf8'), mode: name.endsWith('.sh') ? 0o700 : 0o600
    })));
    await this.backend.bootstrap(ref, files);
    await this.backend.writeFile(ref, `${ref.root}/runtime/environment.json`, Buffer.from(JSON.stringify(environment)));
    await this.importTree(record, join(record.workspacePath, 'repo'), `${ref.root}/repo`);
    // Owner/toolkit projections are approved content, not shared host mounts.
    const projections = [[join(record.workspacePath, 'toolkit-projection', 'owner-skills'), `${ref.root}/owner-skills`]];
    if (this.config.builtinSkillsRoot) projections.push([this.config.builtinSkillsRoot, `${ref.root}/builtin-skills`]);
    for (const [local, remote] of projections) {
      if (!local || !remote) continue;
      if (await stat(local).then(s => s.isDirectory()).catch(() => false)) await this.importTree(record, local, remote);
    }
    this.publish(ref, claim, 'ACTIVE');
    } catch (error) { this.quarantine(ref, claim); throw error; }
  }
  async invoke(record: WorkspaceRecord, command: string, input: { stdin?: string; env?: Record<string, string>; timeoutMs?: number; maxBytes?: number; signal?: AbortSignal } = {}): Promise<ExecutionResult> {
    const ref = this.ref(record);
    // Environment values stay in the guest's private runtime file; never interpolate
    // runtime secrets into provider command/history or overwrite scoped worker roots.
    const environment = { ...input.env, HARNESS_WORKSPACE_ROOT: `${ref.root}/repo`, CH_OWNER_SKILLS_ROOT: `${ref.root}/owner-skills`, BUILTIN_SKILLS_ROOT: `${ref.root}/builtin-skills` };
    const wrapper = `const f=require('fs'),c=require('child_process');const env=JSON.parse(f.readFileSync(${JSON.stringify(ref.root + '/runtime/environment.json')},'utf8'));const r=c.spawnSync('/bin/sh',['-c',${JSON.stringify(command)}],{stdio:'inherit',env:{...process.env,...env,...${JSON.stringify(environment)}}});process.exit(r.status??1);`;
    return this.backend.run(ref, `node -e ${shellQuote(wrapper)}`, {
      cwd: `${ref.root}/repo`, timeoutMs: input.timeoutMs ?? 60000, maxBytes: input.maxBytes ?? this.config.maxOutputBytes,
      ...(input.stdin !== undefined ? { stdin: input.stdin } : {}), ...(input.signal ? { signal: input.signal } : {}),
      env: environment
    });
  }
  async resume(record: WorkspaceRecord): Promise<void> {
    const ref = this.ref(record);
    const claim = this.claim(ref, ['STOPPED', 'ACTIVE', 'QUARANTINED'], 'STARTING');
    try {
      await this.backend.start(ref);
      this.checkClaim(ref, claim, 'STARTING');
      // Never recreate a lost checkout or silently attach another machine.
      const script = `const f=require('fs');const expected=${JSON.stringify(ref)};const actual=JSON.parse(f.readFileSync(${JSON.stringify(ref.root + '/.ch-allocation.json')},'utf8'));if(!Object.entries(expected).every(([k,v])=>actual[k]===v)||!f.statSync(${JSON.stringify(ref.root + '/repo')}).isDirectory())process.exit(1);`;
      const checked = await this.backend.run(ref, `node -e ${shellQuote(script)}`, { cwd: '/data/home', timeoutMs: 30000, maxBytes: 4096 });
      if (checked.exitCode !== 0) throw new HarnessError('UNAVAILABLE', 'Retained remote checkout is missing; operator recovery required', 503, false);
      this.publish(ref, claim, 'ACTIVE');
    } catch (error) { this.quarantine(ref, claim); throw error; }
  }
  async stop(record: WorkspaceRecord): Promise<void> {
    const ref = this.ref(record);
    const claim = this.claim(ref, ['RESERVED', 'ACTIVE', 'STOPPED', 'QUARANTINED'], 'STOPPING');
    try {
      await this.backend.stop(ref);
      this.publish(ref, claim, 'STOPPED');
    } catch (error) { this.quarantine(ref, claim); throw error; }
  }
  async release(record: WorkspaceRecord): Promise<void> {
    const ref = this.ref(record);
    const claim = this.claim(ref, ['RESERVED', 'ACTIVE', 'STOPPED', 'QUARANTINED'], 'RELEASING');
    try {
      // A runner restart can lose foreground handles while guest descendants
      // remain alive. End that boot before cleanup so no old writer can recreate
      // paths between removal and the final stop. This may require a provider
      // start slot; uncertainty keeps the cleanup intent and allocation pinned.
      await this.backend.stop(ref);
      this.checkClaim(ref, claim, 'RELEASING');
      await this.backend.start(ref);
      this.checkClaim(ref, claim, 'RELEASING');
      // The caller stopped operations; this exclusive claim prevents overlapping start/stop/close.
      const result = await this.backend.run(ref, remoteCleanupCommand(ref), { cwd: '/data/home', timeoutMs: 120000, maxBytes: 4096 });
      if (result.exitCode !== 0) throw new Error('remote workspace cleanup failed');
      this.checkClaim(ref, claim, 'RELEASING');
      await this.backend.stop(ref);
      if (!this.allocations.release(ref, claim)) throw new HarnessError('CONFLICT', 'Allocation release lost its fence', 409, false);
    } catch (error) { this.quarantine(ref, claim); throw error; }
  }
  async importTree(record: WorkspaceRecord, hostPath: string, guestPath: string): Promise<void> {
    const ref = this.ref(record), id = randomBytes(12).toString('hex');
    const hostArchive = join(record.workspacePath, `transfer-${id}.chwork`), guestArchive = `${ref.root}/incoming-${id}.chwork`;
    const limit = this.config.maxWorkspaceBytes;
    try {
      await this.packHostTree(record, hostPath, hostArchive, limit, id);
      const hash = await digest(hostArchive);
      await this.backend.uploadFile(ref, hostArchive, guestArchive, limit);
      const result = await this.backend.run(ref,
        `printf '%s  %s\\n' ${shellQuote(hash)} ${shellQuote(guestArchive)} | sha256sum -c - >/dev/null && node ${shellQuote(ref.root + '/runtime/workspace-transfer.mjs')} unpack ${shellQuote(guestArchive)} ${shellQuote(guestPath)} ${limit}`,
        { cwd: ref.root, timeoutMs: 120000, maxBytes: 8192 });
      if (result.exitCode !== 0) throw new HarnessError('UNAVAILABLE', 'Remote checkout transfer failed integrity or extraction checks', 503, false);
    } finally {
      await rm(hostArchive, { force: true });
      await this.backend.run(ref, `rm -f -- ${shellQuote(guestArchive)}`, { cwd: '/data/home', timeoutMs: 10000, maxBytes: 4096 }).catch(() => undefined);
    }
  }
  private async packHostTree(record: WorkspaceRecord, source: string, archive: string, limit: number, id: string): Promise<void> {
    if (process.getuid?.() === 0) {
      await executeFile(process.execPath, [resolve('worker/workspace-transfer.mjs'), 'pack', source, archive, String(limit)], { timeout: 120000, maxBuffer: 8192 });
      return;
    }
    // Clone helpers own some Git objects as uid 10001 with private permissions.
    // A non-root development runner must not relax those checkout permissions.
    // Use a credential-free offline helper with only the exact source/output
    // mounts, then give the resulting private archive to the calling runner.
    const name = `chm-transfer-${id}`;
    const uid = process.getuid?.() ?? 1000, gid = process.getgid?.() ?? 1000;
    const script = await readFile(resolve('worker/workspace-transfer.mjs'), 'utf8')
      + `\n(await import('node:fs')).chownSync(destination, ${uid}, ${gid});\n`;
    try {
      const result = await runDocker(['run', '--rm', '-i', '--name', name, '--network', 'none', '--read-only',
        '--label', 'cloud-harness.role=transfer-helper', '--label', 'cloud-harness.ephemeral=true',
        '--label', `cloud-harness.workspace=${record.id}`,
        '--label', `cloud-harness.instance=${this.ref(record).root.split('/')[4]}`,
        '--user', '0:0', '--cap-drop', 'ALL', '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'CHOWN',
        '--security-opt', 'no-new-privileges', '--pids-limit', '32', '--memory', '256m', '--cpus', '1',
        '--volume', `${source}:/source:ro`, '--volume', `${record.workspacePath}:/transfer:rw`,
        '--entrypoint', 'node', this.config.executorImage, '--input-type=module', '-',
        'pack', '/source', `/transfer/transfer-${id}.chwork`, String(limit)],
      { stdin: script, timeoutMs: 120000, maxBytes: 8192 });
      if (result.exitCode !== 0) throw new HarnessError('UNAVAILABLE', 'Host checkout could not be packaged for remote transfer', 503, false);
    } finally { await removeContainer(name); }
  }
  async exportTree(record: WorkspaceRecord, guestPath: string, hostPath: string, options: { paths?: readonly string[]; maxBytes?: number } = {}): Promise<string> {
    const ref = this.ref(record), id = randomBytes(12).toString('hex');
    const hostArchive = join(record.workspacePath, `transfer-${id}.chwork`), guestArchive = `${ref.root}/outgoing-${id}.chwork`;
    const limit = Math.min(this.config.maxWorkspaceBytes, options.maxBytes ?? this.config.maxWorkspaceBytes);
    try {
      await mkdir(record.workspacePath, { recursive: true });
      const packed = await this.backend.run(ref,
        `node ${shellQuote(ref.root + '/runtime/workspace-transfer.mjs')} pack ${shellQuote(guestPath)} ${shellQuote(guestArchive)} ${limit}${options.paths ? ' ' + shellQuote(JSON.stringify(options.paths)) : ''} && sha256sum ${shellQuote(guestArchive)}`,
        { cwd: ref.root, timeoutMs: 120000, maxBytes: 4096 });
      const hash = packed.stdout.trim().split(/\s+/)[0];
      if (packed.exitCode !== 0 || !hash || !/^[a-f0-9]{64}$/.test(hash)) throw new HarnessError('UNAVAILABLE', 'Remote snapshot could not be prepared', 503, false);
      await this.backend.downloadFile(ref, guestArchive, hostArchive, limit);
      if (await digest(hostArchive) !== hash) throw new HarnessError('UNAVAILABLE', 'Remote snapshot checksum mismatch', 503, false);
      await executeFile(process.execPath, [resolve('worker/workspace-transfer.mjs'), 'unpack', hostArchive, hostPath, String(limit)], { timeout: 120000, maxBuffer: 8192 });
      return hash;
    } finally {
      await rm(hostArchive, { force: true });
      await this.backend.run(ref, `rm -f -- ${shellQuote(guestArchive)}`, { cwd: '/data/home', timeoutMs: 10000, maxBytes: 4096 }).catch(() => undefined);
    }
  }

  /** Fresh immutable skill projection for the host's Skills-over-MCP reader.
   * Never returns the stale initial clone or copies unrelated checkout content.
   * A one-hour retention comfortably exceeds bounded reader calls; snapshots
   * are content-addressed and capped so reads cannot grow host storage forever.
   */
  async snapshotCheckout(record: WorkspaceRecord): Promise<string> {
    const ref = this.ref(record);
    const base = join(record.workspacePath, 'remote-skill-snapshots');
    await mkdir(base, { recursive: true, mode: 0o700 });
    let retained = 0;
    for (const entry of await readdir(base, { withFileTypes: true })) {
      if (!entry.isDirectory() || !/^(?:[a-f0-9]{64}|incoming-[a-f0-9]{24})$/.test(entry.name)) continue;
      const path = join(base, entry.name);
      if ((await stat(path)).mtimeMs < Date.now() - 3600000) await rm(path, { recursive: true });
      else retained++;
    }
    if (retained >= 32) throw new HarnessError('LIMIT_EXCEEDED', 'Remote skill snapshot limit reached; retry after old snapshots expire', 429, true);
    const temporary = join(base, 'incoming-' + randomBytes(12).toString('hex'));
    try {
      const hash = await this.exportTree(record, ref.root + '/repo', temporary, {
        paths: ['.cloud-harness/skills', ...REPOSITORY_SUB_RANK.map(entry => entry.marker)], maxBytes: 64 * 1024 * 1024
      });
      const target = join(base, hash);
      if (!await stat(target).then(s => s.isDirectory()).catch(() => false)) {
        try { await rename(temporary, target); }
        catch (error) {
          if (!['EEXIST', 'ENOTEMPTY'].includes((error as NodeJS.ErrnoException).code ?? '') || !await stat(target).then(s => s.isDirectory()).catch(() => false)) throw error;
        }
      }
      const now = new Date();
      await utimes(target, now, now);
      return target;
    } finally { await rm(temporary, { recursive: true, force: true }); }
  }
}

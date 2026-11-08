import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';

const releaseRuntime = join(process.cwd(), 'deploy/scripts/release-runtime.sh');
const serviceCompose = join(process.cwd(), 'deploy/scripts/service-compose.sh');
const canaryToken = 'vm-overlay-test-canary-token';
const fixtureRoots: string[] = [];

afterEach(() => {
  while (fixtureRoots.length > 0) {
    rmSync(fixtureRoots.pop() as string, { recursive: true, force: true });
  }
});

function makeRoot(withOverlay: boolean, withMarker: boolean) {
  const root = mkdtempSync(join(tmpdir(), 'cloud-harness-vm-overlay-'));
  fixtureRoots.push(root);
  const repo = join(root, 'repo');
  const etc = join(root, 'etc');
  const stubBin = join(root, 'bin');
  for (const dir of [repo, etc, stubBin]) mkdirSync(dir, { recursive: true });
  writeFileSync(join(repo, 'compose.yaml'), 'services: {}\n');
  writeFileSync(join(repo, 'compose.production.yaml'), 'services: {}\n');
  if (withOverlay) writeFileSync(join(repo, 'compose.vm.yaml'), 'services: {}\n');
  if (withMarker) writeFileSync(join(etc, 'vm.enabled'), '');
  writeFileSync(join(etc, 'runtime.env'), `VM_SUPERVISOR_TOKEN=${canaryToken}\n`);
  const dockerStub = join(stubBin, 'docker');
  writeFileSync(dockerStub, [
    '#!/usr/bin/env bash',
    'echo "args:$*"',
    'echo "envfile:${CLOUD_HARNESS_ENV_FILE:-<unset>}"',
    'echo "token:${VM_SUPERVISOR_TOKEN:-<unset>}"',
    ''
  ].join('\n'));
  chmodSync(dockerStub, 0o755);
  return { root, repo, etc, stubBin };
}

function runReleaseCompose(options: { withOverlay: boolean; withMarker: boolean; command?: string[] }) {
  const { etc, repo, stubBin } = makeRoot(options.withOverlay, options.withMarker);
  const command = (options.command ?? ['config']).join(' ');
  const script = `
set -u
source "$1"
config_root="$2"
state="$2/state"
env_file="$2/runtime.env"
export PATH="$4:$PATH"
cd "$3"
compose ${command}
`;
  const result = spawnSync('bash', ['-c', script, 'bash', releaseRuntime, etc, repo, stubBin], {
    encoding: 'utf8',
    env: { ...process.env, VM_SUPERVISOR_TOKEN: '' },
    timeout: 15_000
  });
  return { ...result, output: `${result.stdout}\n${result.stderr}` };
}

function runServiceCompose(options: { withOverlay: boolean; withMarker: boolean; command?: string[] }) {
  const { root, repo, etc, stubBin } = makeRoot(options.withOverlay, options.withMarker);
  // The shipped wrapper execs the absolute /usr/bin/docker; fixture a scoped
  // copy that swaps ONLY that known executable for the stub, and assert the
  // source carries exactly one occurrence so a future second call site cannot
  // silently bypass the fixture.
  const source = readFileSync(serviceCompose, 'utf8');
  expect(source.split('/usr/bin/docker').length - 1).toBe(1);
  const patched = join(root, 'service-compose.sh');
  writeFileSync(patched, source.replace('/usr/bin/docker', join(stubBin, 'docker')));
  chmodSync(patched, 0o755);
  const result = spawnSync('bash', [patched, ...(options.command ?? ['config'])], {
    encoding: 'utf8',
    cwd: repo,
    env: {
      ...process.env,
      CLOUD_HARNESS_CONFIG_DIR: etc,
      CLOUD_HARNESS_ENV_FILE: join(etc, 'runtime.env'),
      VM_SUPERVISOR_TOKEN: ''
    },
    timeout: 15_000
  });
  return { ...result, output: `${result.stdout}\n${result.stderr}`, root };
}

function composeArgs(output: string) {
  return output.split('\n').find((line) => line.startsWith('args:'))?.slice(5) ?? '';
}

describe.skipIf(process.platform === 'win32')('VM overlay compose opt-in', () => {
  it('release-runtime compose() omits the overlay without the marker even when the file exists', () => {
    const result = runReleaseCompose({ withOverlay: true, withMarker: false });
    expect(result.status).toBe(0);
    const args = composeArgs(result.output);
    expect(args).toContain('-f compose.yaml');
    expect(args).toContain('-f compose.production.yaml');
    expect(args).not.toContain('compose.vm.yaml');
    expect(result.stderr).not.toContain('vm.enabled');
  });

  it('release-runtime compose() appends the overlay after production files when marker and overlay exist', () => {
    const result = runReleaseCompose({ withOverlay: true, withMarker: true });
    expect(result.status).toBe(0);
    const args = composeArgs(result.output);
    const production = args.indexOf('compose.production.yaml');
    const vm = args.indexOf('compose.vm.yaml');
    expect(production).toBeGreaterThanOrEqual(0);
    expect(vm).toBeGreaterThan(production);
    expect(result.stderr).not.toContain('vm.enabled');
  });

  it('release-runtime compose() skips the overlay with a warning when the marker survives a rollback to a checkout without it', () => {
    const result = runReleaseCompose({ withOverlay: false, withMarker: true });
    expect(result.status).toBe(0);
    const args = composeArgs(result.output);
    expect(args).not.toContain('compose.vm.yaml');
    expect(args).toContain('-f compose.yaml');
    expect(result.stderr).toContain('vm.enabled');
    expect(result.stderr).toContain('no compose.vm.yaml');
  });

  it('release-runtime compose() omits the overlay silently when neither marker nor file exist', () => {
    const result = runReleaseCompose({ withOverlay: false, withMarker: false });
    expect(result.status).toBe(0);
    expect(composeArgs(result.output)).not.toContain('compose.vm.yaml');
    expect(result.stderr).not.toContain('vm.enabled');
  });

  it('release-runtime compose() forwards lifecycle arguments verbatim through the same overlay decision', () => {
    const enabled = runReleaseCompose({ withOverlay: true, withMarker: true, command: ['down', '--remove-orphans'] });
    expect(enabled.status).toBe(0);
    expect(composeArgs(enabled.output)).toBe('compose -f compose.yaml -f compose.production.yaml -f compose.vm.yaml down --remove-orphans');

    const rolledBack = runReleaseCompose({ withOverlay: false, withMarker: true, command: ['down', '--remove-orphans'] });
    expect(rolledBack.status).toBe(0);
    expect(composeArgs(rolledBack.output)).toBe('compose -f compose.yaml -f compose.production.yaml down --remove-orphans');
    expect(rolledBack.stderr).toContain('vm.enabled');

    const listed = runReleaseCompose({ withOverlay: true, withMarker: true, command: ['ps', '-q', 'runner'] });
    expect(listed.status).toBe(0);
    expect(composeArgs(listed.output)).toBe('compose -f compose.yaml -f compose.production.yaml -f compose.vm.yaml ps -q runner');
  });

  it('service-compose.sh applies the same marker/overlay rule and forwards up/down/ps verbatim', () => {
    const up = runServiceCompose({ withOverlay: true, withMarker: true, command: ['up', '--remove-orphans'] });
    expect(up.status).toBe(0);
    expect(composeArgs(up.output)).toBe('compose -f compose.yaml -f compose.production.yaml -f compose.vm.yaml up --remove-orphans');

    const down = runServiceCompose({ withOverlay: false, withMarker: true, command: ['down'] });
    expect(down.status).toBe(0);
    expect(composeArgs(down.output)).toBe('compose -f compose.yaml -f compose.production.yaml down');
    expect(down.stderr).toContain('vm.enabled');
    expect(down.stderr).toContain('no compose.vm.yaml');

    const ps = runServiceCompose({ withOverlay: true, withMarker: false, command: ['ps', '-q'] });
    expect(ps.status).toBe(0);
    expect(composeArgs(ps.output)).toBe('compose -f compose.yaml -f compose.production.yaml ps -q');
    expect(ps.stderr).not.toContain('vm.enabled');
  });

  it('neither wrapper sources runtime.env — the supervisor token never enters the compose environment', () => {
    for (const result of [
      runReleaseCompose({ withOverlay: true, withMarker: true }),
      runServiceCompose({ withOverlay: true, withMarker: true })
    ]) {
      expect(result.status).toBe(0);
      expect(result.output).toContain('token:<unset>');
      expect(result.output).not.toContain(canaryToken);
    }
    const service = runServiceCompose({ withOverlay: true, withMarker: true });
    expect(service.output).toContain(`envfile:${join(service.root, 'etc', 'runtime.env')}`);
  });

  it('both compose builders carry the marker check', () => {
    for (const path of [serviceCompose, releaseRuntime]) {
      const content = readFileSync(path, 'utf8');
      expect(content).toContain('vm.enabled');
      expect(content).toContain('compose.vm.yaml');
    }
  });
});

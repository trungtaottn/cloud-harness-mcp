import { createServer } from 'node:http';
import { join } from 'node:path';
import pino from 'pino';
import { createRunnerApp } from './app.js';
import { ArtifactStore } from './artifact-store.js';
import { ApiKeyService } from './api-key-service.js';
import { ApiKeyStore } from './api-key-store.js';
import { createVmExportWorkspace, createVmLeaseSync, createWorkspaceBackendFactory } from './backend-factory.js';
import { loadRunnerConfigWithReadiness } from './config.js';
import { DashboardControlService } from './dashboard-control-service.js';
import { extractTarSafe, findCheckoutRoot, inspectVmCheckout, VmGitStaging } from './git-vm-staging.js';
import { GitHubApiInstallationVerifier } from './github-api-installation-verifier.js';
import { GitHubAuthorizationStateStore, GitHubBindingService, GitHubSetupStateStore } from './github-binding-service.js';
import { GitHubApiUserAuthorizer } from './github-user-authorizer.js';
import { SqliteGitHubInstallationStore } from './github-installation-sqlite-store.js';
import { MetadataStore } from './metadata-store.js';
import { McpEventService } from './mcp-event-service.js';
import { SecretKeyring } from './secret-keyring.js';
import { createRunnerDecisionPlane } from './decision-plane/runner-decision-plane.js';
import { StateStore, type WorkspaceRecord } from './state-store.js';
import { WorkspaceService } from './workspace-service.js';
import { reconcileVmFleet, reconcileVmShutdown, type VmExportCleanVerdict, type VmReconcileRecord } from './vm-reconcile.js';
import { startVmFleetReconcileStartup, type VmFleetStartupHandle } from './vm-fleet-startup.js';
import { assertVmAdmissionAllowed } from './vm-admission.js';
import { VmSupervisorClient } from './vm-supervisor-client.js';
import { DockerAgentGatewayControl } from './agent-gateway-control.js';
import { ModelProfileStateRepository } from './model-profile-state-repository.js';
import { CloudflareAccessOAuthProvider } from './cloudflare-access-oauth-provider.js';
import { OAuthGrantSettingsService } from './oauth-grant-settings-service.js';

const logger = pino({ level: process.env.LOG_LEVEL ?? 'info' });
const loaded = loadRunnerConfigWithReadiness();
const config = loaded.config;
const store = new StateStore(config.stateDb, { maxActiveWorkspacesPerOwner: config.maxActiveWorkspacesPerOwner });
let keyring: SecretKeyring | undefined;
let secretReadinessError = loaded.secretReadinessError;
try {
  keyring = config.secretKeyring ? new SecretKeyring(config.secretKeyring.activeVersion, config.secretKeyring.keys) : undefined;
} catch {
  secretReadinessError = 'secret keyring configuration is invalid';
  logger.error('secret operations disabled because the keyring configuration is invalid');
}
const metadata = new MetadataStore(config.stateDb, keyring, secretReadinessError);
const apiKeyStore = new ApiKeyStore(store.database, (database, principalId, action, key) => {
  metadata.recordAuditInTransaction(database, principalId, action, 'api_key', key.id, key.generation, {
    expiresAt: key.expiresAt
  });
});
const apiKeys = new ApiKeyService(store, apiKeyStore);
const events = new McpEventService({
  database: store.database,
  resolvePrincipal: (principal) => store.resolvePrincipal(principal),
  keyring,
  audit: (database, principalId, action, subscriptionId, generation, details) => {
    metadata.recordAuditInTransaction(database, principalId, action, 'mcp_event_subscription', subscriptionId, generation, details);
  }
});
const githubInstallations = new SqliteGitHubInstallationStore(store.database);
const githubApp = config.githubApp;
const githubBinding = githubApp
  ? new GitHubBindingService(
    new GitHubSetupStateStore(store.database),
    githubInstallations,
    new GitHubApiInstallationVerifier(githubApp),
    Date.now,
    githubApp.clientId && githubApp.clientSecret
      ? {
        states: new GitHubAuthorizationStateStore(store.database),
        authorizer: new GitHubApiUserAuthorizer({ appId: githubApp.appId, clientId: githubApp.clientId, clientSecret: githubApp.clientSecret })
      }
      : undefined
  )
  : undefined;
const artifacts = new ArtifactStore(store.database, {
  root: config.artifactRoot, maxArtifactBytes: config.maxArtifactBytes,
  maxPrincipalBytes: config.maxPrincipalArtifactBytes,
  defaultRetentionMs: config.artifactRetentionSeconds * 1_000,
  maxRetentionMs: 2_592_000_000
});
const gatewayControl = config.agents ? new DockerAgentGatewayControl(config.agentGatewayContainer) : undefined;
const modelProfiles = keyring ? new ModelProfileStateRepository(store.database, keyring) : undefined;
// One supervisor wire client per runner; construction is connection-free, so it
// is safe to build unconditionally — every VM path is gated on
// vmBackendEnabled long before a call reaches the socket. The token is schema-
// required whenever the backend is enabled.
const vmSupervisorClient = new VmSupervisorClient({
  socketPath: config.vmSupervisorSocket,
  token: config.vmSupervisorToken ?? ''
});
// Phase-07 factory: docker stack is identical to the service default; incus-vm
// gets the real IncusExecutorBackend + VmGitTransport (offline export auto-
// wired from the same client). network/packages delegate to the service so
// there is exactly one NetworkProfileManager/PackageService instance.
const backendFactory = createWorkspaceBackendFactory({
  config,
  instanceId: store.instanceId(),
  supervisorClient: vmSupervisorClient,
  network: {
    ensureProfileReady: (profile) => service.networkProfileManager.ensureProfileReady(profile),
    dockerLaunchArgs: (profile) => service.networkProfileManager.dockerLaunchArgs(profile)
  },
  packages: {
    profileFor: (ownerId, workspaceId) => service.packages.profileFor(ownerId, workspaceId)
  },
  // Owner/workspace package bindings have no VM mount channel: the workspace
  // still opens, and the unmountable releases are reported honestly here.
  onUnsupportedPackages: (info) => logger.warn(info, 'package bindings are not mounted on the incus-vm executor')
});
const service = new WorkspaceService(config, store, metadata, githubInstallations, githubBinding, artifacts, { modelProfiles, ...(gatewayControl !== undefined ? { gateway: gatewayControl } : {}) }, backendFactory);
service.leaseSync = createVmLeaseSync(vmSupervisorClient);
// UX-only admission pre-check for incus-vm opens (quota/pool math); the
// supervisor's vm.start gate remains the authoritative admission on every
// start path — a pass here never authorizes a VM.
service.vmAdmission = ({ ownerId }) => assertVmAdmissionAllowed({ store, client: vmSupervisorClient, config }, { ownerId });
/** Every persisted incus-vm record (any lifecycle status) for fleet reconcile. */
function listVmWorkspaceRecords(): WorkspaceRecord[] {
  const ids = (store.database.prepare(`SELECT id FROM workspaces WHERE backend_kind = 'incus-vm'`).all() as Array<{ id: string }>).map((row) => row.id);
  return ids.map((id) => store.byId(id)).filter((record): record is WorkspaceRecord => record !== undefined);
}
// Offline-export clean check for hard-expired VMs: extract the supervisor tar
// with hostile-entry rejection, then run the credential-free checkout
// inspection on the untrusted copy. Any failure is 'unknown' → deferred.
const vmExportStaging = new VmGitStaging({ config, instanceId: store.instanceId() });
const inspectVmExport = async ({ record, exportPath, stagingDir }: { record: VmReconcileRecord; exportPath: string; stagingDir: string }): Promise<VmExportCleanVerdict> => {
  try {
    const extractDir = join(stagingDir, 'extract');
    await extractTarSafe(exportPath, extractDir, { maxEntries: 500_000, maxBytes: config.vmMaxWorkspaceBytes });
    const rel = await findCheckoutRoot(extractDir);
    if (rel === undefined) return 'unknown';
    const checkoutDir = rel === '' ? extractDir : join(extractDir, rel);
    const inspection = await inspectVmCheckout(vmExportStaging, checkoutDir, { containerPath: '/workspace', workspaceId: record.id });
    return inspection.verdict === 'clean' ? 'clean' : inspection.verdict === 'retain' ? 'dirty' : 'unknown';
  } catch {
    return 'unknown';
  }
};
const decisionPlane = createRunnerDecisionPlane({
  purposes: config.decisionPlanePurposes,
  typesafeEgress: config.typesafeEgress,
  database: metadata.database,
  keyring,
  modelProfiles,
  recordAudit: (principalId, action, subjectType, subjectId, generation, details) =>
    metadata.recordAudit(principalId, action, subjectType, subjectId, generation, details)
});
service.useDecisionPlane(decisionPlane);
const controls = new DashboardControlService(config, store, metadata, artifacts, service, githubInstallations, githubBinding, modelProfiles, gatewayControl, keyring, decisionPlane);
// A job row outlives the process that wrote it, so startup is where an import interrupted by a restart is
// turned into a terminal state rather than left as a spinner that never ends.
controls.reconcileInterruptedImports();
const oauthGrantSettings = new OAuthGrantSettingsService(
  store,
  config.cloudflareAccessOAuth ? new CloudflareAccessOAuthProvider(config.cloudflareAccessOAuth) : undefined,
  (ownerId, action, details) => metadata.recordAudit(ownerId, action, 'instance', 'oauth_grant_settings', 1, details)
);
await service.start();
// New installs default to the provider-maximum grant. This never blocks startup and
// never overwrites a value an operator set explicitly; failures surface in Settings.
void oauthGrantSettings.reconcileDefault().then(
  (outcome) => logger.info({ outcome }, 'inbound OAuth grant default reconciled'),
  () => logger.warn({ outcome: 'failed' }, 'inbound OAuth grant default reconcile failed')
);
const server = createServer(createRunnerApp(config, service, controls, apiKeys, {
  settings: oauthGrantSettings,
  resolvePrincipal: (principal) => store.resolvePrincipal(principal)
}, events));
server.listen(config.port, config.host, () => logger.info({ host: config.host, port: config.port }, 'runner listening'));

// Fleet reconcile for incus-vm workspaces: adopts verified running VMs,
// reports orphans/quarantine, and runs the offline clean-check on
// hard-expired records. The module holds no delete authority — 'export-clean'
// only proves deletability; close/finalize stays an explicit user action.
//
// This runs AFTER listen under an overall deadline (see vm-fleet-startup.ts):
// awaiting the serial export sweep before listen would hold the whole runner —
// including the default Docker backend — hostage to supervisor latency. The
// wrapper owns an AbortController: the deadline AND runner shutdown abort the
// signal handed to reconcileVmFleet, which stops scheduling further records —
// the deadline bounds the work itself, not just the wait. Unfinished records
// are re-examined on the next boot; reconcile stays log-only advisory.
let vmFleetStartup: VmFleetStartupHandle | undefined;
if (config.vmBackendEnabled) {
  const records = listVmWorkspaceRecords();
  if (records.length > 0) {
    vmFleetStartup = startVmFleetReconcileStartup(
      (signal) => reconcileVmFleet(
        {
          client: vmSupervisorClient,
          exportWorkspace: createVmExportWorkspace(vmSupervisorClient),
          inspectExport: inspectVmExport
        },
        records,
        { signal }
      ),
      { recordCount: records.length, logger }
    );
    void vmFleetStartup.done;
  }
}

async function shutdown(signal: string) {
  logger.info({ signal }, 'runner shutting down');
  server.close();
  // Stop the startup fleet sweep before teardown reconcile: the abort signal
  // reaches in-flight vm.export/inspection calls so no new records are
  // scheduled while shutdown proceeds.
  vmFleetStartup?.abort();
  await service.stop();
  // Best-effort VM teardown: lease.clear + vm.stop per persisted incus-vm
  // record; the supervisor watchdog is the hard backstop for anything missed.
  try {
    const report = await reconcileVmShutdown({ client: vmSupervisorClient }, listVmWorkspaceRecords());
    for (const action of report.actions) {
      if (action.type === 'deferred') logger.warn({ action }, 'vm shutdown reconcile deferred');
    }
  } catch (error) {
    logger.warn({ error }, 'vm shutdown reconcile failed');
  }
  vmSupervisorClient.close();
  metadata.close();
  keyring?.close();
  store.close();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

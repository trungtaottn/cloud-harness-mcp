/**
 * The workspace projection the BFF returns (`cleanWorkspace` in
 * `apps/api/src/dashboard-response.ts`) and its display helpers, shared by the list, the
 * cockpit and the Overview.
 */
export type Workspace = {
  workspaceId: string;
  repositoryUrl?: string;
  ref?: string;
  status?: string;
  networkProfile?: string;
  createdAt?: string;
  lastActivityAt?: string;
  expiresAt?: string;
  version?: number;
  canRenewLease?: boolean;
  leaseCapped?: boolean;
  leaseState?: string;
  availableActions?: string[];
  error?: string;
  /** Executor backend kind, projected by the BFF from the runner's capability result. */
  executionBackend?: string;
  /** Structured backend block: kind, optional VM template id, and the capability matrix. */
  backend?: {
    kind?: string;
    templateId?: string;
    capabilities?: Record<string, string>;
  };
};

export type WorkspaceBackendKind = 'docker' | 'incus-vm';

/** The fields the backend helpers read; a full Workspace satisfies it, and so does a partial projection. */
type BackendCarrier = Pick<Workspace, 'backend' | 'executionBackend'>;

/**
 * The executor backend a workspace runs on. `backend.kind` is the structured
 * block's own claim; `executionBackend` is the flat kind. Either may be absent
 * on an older runner — the helpers return `undefined` rather than guessing, so
 * the UI says "Not reported" instead of implying Docker.
 */
export function backendKindOf(workspace: BackendCarrier | undefined): WorkspaceBackendKind | undefined {
  const kind = workspace?.backend?.kind ?? workspace?.executionBackend;
  return kind === 'docker' || kind === 'incus-vm' ? kind : undefined;
}

export function backendLabel(kind: WorkspaceBackendKind | undefined): string {
  if (kind === 'incus-vm') return 'Incus VM';
  if (kind === 'docker') return 'Docker';
  return 'Not reported';
}

/** The template id a VM workspace was admitted with; undefined for Docker or unreported. */
export function backendTemplateId(workspace: BackendCarrier | undefined): string | undefined {
  const templateId = workspace?.backend?.templateId;
  return typeof templateId === 'string' && templateId.length > 0 ? templateId : undefined;
}

/**
 * One capability's support on this workspace's backend. Only the structured
 * `backend.capabilities` matrix counts — a rendered tab or button never implies
 * support, and the runner re-checks every operation server-side.
 */
export function backendCapability(workspace: BackendCarrier | undefined, id: string): 'supported' | 'unsupported' | undefined {
  const value = workspace?.backend?.capabilities?.[id];
  return value === 'supported' || value === 'unsupported' ? value : undefined;
}

const CAPABILITY_LABELS: Record<string, string> = {
  'packages-bind': 'Package binding',
  'dashboard-repo-skills': 'Repository skill browsing'
};

/** Operator-facing name for a capability id; unknown ids humanize rather than leak the raw key. */
export function capabilityLabel(id: string): string {
  const known = CAPABILITY_LABELS[id];
  if (known) return known;
  const words = id.replace(/[-_]+/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : id;
}

/** Capability ids the backend declares unsupported, sorted for stable display. */
export function unsupportedBackendCapabilities(workspace: BackendCarrier | undefined): string[] {
  const capabilities = workspace?.backend?.capabilities;
  if (!capabilities) return [];
  return Object.keys(capabilities).filter((id) => capabilities[id] === 'unsupported').sort();
}

export const WORKSPACE_STATUSES = ['CREATING', 'ACTIVE', 'EXPIRED_RECOVERABLE', 'NETWORK_QUARANTINED', 'REAPING', 'CLOSED', 'FAILED'] as const;

const STATUS_LABELS: Record<string, string> = {
  CREATING: 'Creating', ACTIVE: 'Active', REAPING: 'Closing', CLOSED: 'Closed', FAILED: 'Failed',
  NETWORK_QUARANTINED: 'Quarantined', EXPIRED_RECOVERABLE: 'Expired (recoverable)'
};

export function workspaceStatusLabel(status: unknown): string {
  return STATUS_LABELS[String(status)] ?? 'Unknown';
}

export function networkLabel(profile: unknown): string {
  return profile === 'dependency-access' ? 'Dependency access' : profile === 'local-host' ? 'Local host' : 'No network';
}

/** `owner/repo` from a credential-free HTTPS repository URL. */
export function repositoryName(url: unknown): string {
  try {
    return new URL(String(url)).pathname.replace(/^\//, '').replace(/\.git$/, '') || 'Repository';
  } catch {
    return 'Repository';
  }
}

/**
 * Whether the runner offers `action` for this workspace. The runner's `availableActions` is
 * authoritative; the status fallback covers an API/runner rolling upgrade, as the legacy
 * `workspaceHasAction` does. A visible control never grants the action: the BFF re-checks.
 */
export function workspaceHasAction(workspace: Workspace | undefined, action: string): boolean {
  if (!workspace) return false;
  if (Array.isArray(workspace.availableActions)) return workspace.availableActions.includes(action);
  const status = workspace.status;
  if (action === 'workspace_context') return status === 'ACTIVE' || status === 'NETWORK_QUARANTINED';
  if (action === 'workspace_lease_renew') return status === 'ACTIVE' || status === 'EXPIRED_RECOVERABLE';
  return false;
}

/** Workspaces matching the list filters: free text over repository and id, status, and an expiry budget in minutes. */
export function filterWorkspaces(workspaces: readonly Workspace[], filters: { q?: string | undefined; status?: string | undefined; expiring?: number | undefined }, now = Date.now()): Workspace[] {
  const term = filters.q?.toLowerCase() ?? '';
  return workspaces.filter((workspace) => {
    if (filters.status && workspace.status !== filters.status) return false;
    if (term && !`${workspace.repositoryUrl ?? ''} ${workspace.workspaceId}`.toLowerCase().includes(term)) return false;
    if (filters.expiring && filters.expiring > 0) {
      const expiresAt = Date.parse(workspace.expiresAt ?? '');
      if (!Number.isFinite(expiresAt) || expiresAt - now > filters.expiring * 60_000) return false;
    }
    return true;
  });
}

import { StatusBadge } from '@/components/data/status-badge';
import { backendKindOf, backendLabel, type Workspace } from './workspace-model';

/**
 * The executor backend a workspace runs on, as the runner reported it. Docker is
 * the default backend and Incus VM is opt-in; the badge only restates the
 * projection — it never implies a capability the backend did not declare.
 */
export function BackendBadge({ workspace }: { workspace: Workspace | undefined }) {
  const kind = backendKindOf(workspace);
  return <StatusBadge status={kind === 'incus-vm' ? 'incus-vm' : 'docker'} tone={kind === 'incus-vm' ? 'info' : 'neutral'} label={backendLabel(kind)} />;
}

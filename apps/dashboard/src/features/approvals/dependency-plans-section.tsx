import { useQuery } from '@tanstack/react-query';
import { PackageIcon } from 'lucide-react';
import { AsyncStatus } from '@/components/feedback/async-status';
import { EmptyState } from '@/components/feedback/empty-state';
import { Button } from '@/components/ui/button';
import { bffQuery } from '@/lib/bff-query';
import { Callout } from '../shared/callout';
import { formatTime } from '../shared/format';
import { Section } from '../shared/section';
import { StatusBadge } from '../shared/status-badge';
import { dependencyPlanCanWithdraw, dependencyPlanIsActionable, dependencyPlanStatusLabel, formatPackageBytes, type DependencyPlanView } from './approvals-model';

export function DependencyPlansSection({ onDecide }: { onDecide: (plan: DependencyPlanView, decision: 'approve' | 'reject') => void }) {
  const query = useQuery({ ...bffQuery<{ plans: DependencyPlanView[] }>('/dependency-plans'), retry: false });
  return (
    <Section title="Dependency downloads" testId="dependency-plans">
      <Callout title="Workspace dependency plans.">Approve the exact manifest hashes, download hosts and limits shown. Downloads keep lifecycle scripts disabled and do not change the workspace network profile.</Callout>
      <AsyncStatus query={query} label="dependency plans">
        {({ data: { plans } }) => plans.length === 0
          ? <EmptyState icon={PackageIcon} title="No dependency plans." description="An agent creates a workspace dependency plan with dependencies_plan." />
          : <ul className="grid gap-3">{plans.map((plan) => (
            <li key={plan.planId} data-testid="dependency-plan-card" className="grid gap-3 rounded-lg border bg-card p-4">
              <div className="flex flex-wrap justify-between gap-2">
                <h3 className="font-semibold">{plan.ecosystem} dependencies · <code>{plan.directory}</code></h3>
                <StatusBadge tone={plan.state === 'SUCCEEDED' ? 'success' : plan.state === 'FAILED' || plan.state === 'REJECTED' ? 'danger' : plan.state === 'PENDING_APPROVAL' ? 'warning' : 'neutral'}>{dependencyPlanStatusLabel(plan)}</StatusBadge>
              </div>
              <dl className="grid gap-3 text-sm sm:grid-cols-2">
                <div><dt className="text-muted-foreground">Workspace</dt><dd className="font-mono break-all">{plan.workspaceId}</dd></div>
                <div><dt className="text-muted-foreground">Plan digest</dt><dd className="font-mono break-all">{plan.planDigest}</dd></div>
                <div><dt className="text-muted-foreground">Allowed hosts</dt><dd className="break-all">{plan.hosts.join(', ') || 'None'}</dd></div>
                <div><dt className="text-muted-foreground">Dependencies</dt><dd>{plan.dependencyCount} · {plan.changes.added} added · {plan.changes.removed} removed</dd></div>
                <div><dt className="text-muted-foreground">Limits</dt><dd>{formatPackageBytes(plan.maxBytes)} · {plan.timeoutMs / 1000} seconds</dd></div>
                <div><dt className="text-muted-foreground">Lifecycle scripts</dt><dd>Disabled</dd></div>
                <div><dt className="text-muted-foreground">Created</dt><dd>{formatTime(plan.createdAt)}</dd></div>
                <div><dt className="text-muted-foreground">Expires</dt><dd>{formatTime(plan.expiresAt)}</dd></div>
              </dl>
              <ul aria-label="Manifest hashes" className="grid gap-2 text-xs">{plan.manifests.map((manifest) => <li key={manifest.path}><code className="break-all">{manifest.path}: {manifest.sha256}</code></li>)}</ul>
              {plan.error ? <p role="status" className="text-sm text-destructive">{plan.error}</p> : null}
              {dependencyPlanIsActionable(plan) ? <div className="flex gap-2">
                <Button size="sm" aria-haspopup="dialog" onClick={() => onDecide(plan, 'approve')}>Approve</Button>
                <Button size="sm" variant="outline" aria-haspopup="dialog" onClick={() => onDecide(plan, 'reject')}>Reject</Button>
              </div> : dependencyPlanCanWithdraw(plan) ? <div><Button size="sm" variant="outline" aria-haspopup="dialog" onClick={() => onDecide(plan, 'reject')}>Withdraw approval</Button></div> : null}
            </li>
          ))}</ul>}
      </AsyncStatus>
    </Section>
  );
}

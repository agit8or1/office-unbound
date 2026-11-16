/** Routes the console ships today. `key` pages get screenshots. */
export interface R { id: string; title: string; min: 'viewer' | 'operator' | 'approver' | 'admin'; key?: boolean }
export const ROUTES: R[] = [
  { id: 'overview', title: 'Overview', min: 'viewer', key: true },
  { id: 'infrastructure/clusters', title: 'Clusters', min: 'viewer' },
  { id: 'infrastructure/nodes', title: 'Nodes', min: 'viewer', key: true },
  { id: 'infrastructure/vms', title: 'Virtual machines', min: 'viewer' },
  { id: 'infrastructure/containers', title: 'Containers', min: 'viewer' },
  { id: 'infrastructure/storage', title: 'Storage', min: 'viewer' },
  { id: 'infrastructure/networks', title: 'Networks', min: 'viewer' },
  { id: 'deployments', title: 'Deployments', min: 'viewer' },
  { id: 'deployments/history', title: 'Deployment history', min: 'viewer' },
  { id: 'jobs', title: 'Jobs', min: 'viewer' },
  { id: 'plans', title: 'Approvals', min: 'viewer', key: true },
  { id: 'releases', title: 'Releases', min: 'viewer', key: true },
  { id: 'maintenance', title: 'Maintenance', min: 'viewer' },
  { id: 'checks', title: 'Health checks', min: 'viewer', key: true },
  { id: 'utilization', title: 'Utilization', min: 'viewer' },
  { id: 'incidents', title: 'Incidents', min: 'viewer', key: true },
  { id: 'users', title: 'Users & roles', min: 'viewer', key: true },
  { id: 'users/invitations', title: 'Invitations', min: 'viewer' },
  { id: 'users/privileged', title: 'Privileged access', min: 'viewer' },
  { id: 'users/roles', title: 'Roles', min: 'viewer' },
  { id: 'users/policies', title: 'Policies', min: 'viewer' },
  { id: 'endpoints', title: 'Integrations', min: 'viewer', key: true },
  { id: 'inventory', title: 'Inventory snapshots', min: 'viewer' },
  { id: 'preview', title: 'Plan preview', min: 'operator' },
  { id: 'audit', title: 'Audit log', min: 'approver' },
  { id: 'system', title: 'System', min: 'admin' },
]
/** Routes that exist only once their feature branch is merged (wizards, /infra/*): probed, tested when present, skipped when "not found". */
export const OPTIONAL_ROUTES: string[] = ['setup', 'deployments/new']

/** ADR-0009 section 6: navigation groups and their children that must exist (planned items must at least be labelled Planned). */
export const IA_GROUPS: Record<string, string[]> = {
  Overview: [],
  Infrastructure: ['Clusters', 'Nodes', 'Virtual machines', 'Containers', 'Storage', 'Networks'],
  Deployments: ['Catalog', 'New deployment', 'Environments', 'History'],
  Operations: ['Jobs', 'Approvals', 'Changes', 'Maintenance', 'Releases'],
  Monitoring: ['Health checks', 'Utilization', 'Alerts'],
  Administration: ['Users', 'Access policies', 'Integrations', 'Configuration', 'Audit', 'System'],
}

/** Routes the console ships today. `key` pages get screenshots. */
export interface R { id: string; title: string; min: 'viewer' | 'operator' | 'approver' | 'admin'; key?: boolean }
export const ROUTES: R[] = [
  { id: 'overview', title: 'Overview', min: 'viewer', key: true },
  { id: 'endpoints', title: 'Endpoints', min: 'viewer' },
  { id: 'checks', title: 'Checks', min: 'viewer', key: true },
  { id: 'incidents', title: 'Incidents', min: 'viewer', key: true },
  { id: 'plans', title: 'Plans', min: 'viewer', key: true },
  { id: 'jobs', title: 'Jobs', min: 'viewer' },
  { id: 'inventory', title: 'Inventory', min: 'viewer' },
  { id: 'preview', title: 'Plan preview', min: 'operator' },
  { id: 'users', title: 'Users', min: 'admin' },
  { id: 'audit', title: 'Audit', min: 'approver' },
]

/** ADR-0009 section 6: navigation groups and their children that must exist (planned items must at least be labelled Planned). */
export const IA_GROUPS: Record<string, string[]> = {
  Overview: [],
  Infrastructure: ['Clusters', 'Nodes', 'Virtual machines', 'Containers', 'Storage', 'Networks'],
  Deployments: ['Catalog', 'New deployment', 'Environments', 'History'],
  Operations: ['Jobs', 'Approvals', 'Changes', 'Maintenance', 'Updates'],
  Monitoring: ['Health checks', 'Utilization', 'Alerts'],
  Administration: ['Users', 'Access policies', 'Integrations', 'Configuration', 'Audit', 'System'],
}

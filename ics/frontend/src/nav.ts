import type { Role } from './api'
import type { IconName } from './ui/icons'

export interface NavItem { label: string; to?: string; icon: IconName; min?: Role; planned?: boolean; badge?: 'incidents' | 'approvals'; match?: string[]; ifPath?: string }
export interface NavGroup { title?: string; items: NavItem[] }

// Information architecture from ADR-0009 section 6. Items without an implemented page are labelled "Planned", never hidden behind errors.
export const NAV: NavGroup[] = [
  { items: [{ label: 'Overview', to: '/overview', icon: 'dashboard' }] },
  { title: 'Infrastructure', items: [
    { label: 'Proxmox clusters', to: '/infrastructure/providers', icon: 'plug', match: ['/infrastructure/providers'] },
    { label: 'Clusters', to: '/infrastructure/clusters', icon: 'cluster' },
    { label: 'Nodes', to: '/infrastructure/nodes', icon: 'server' },
    { label: 'Virtual machines', to: '/infrastructure/vms', icon: 'vm' },
    { label: 'Containers', to: '/infrastructure/containers', icon: 'box' },
    { label: 'Storage', to: '/infrastructure/storage', icon: 'database' },
    { label: 'Networks', to: '/infrastructure/networks', icon: 'network' },
  ] },
  { title: 'Deployments', items: [
    { label: 'Catalog', icon: 'book', planned: true },
    { label: 'New deployment', to: '/deployments/new', icon: 'plus', min: 'operator', ifPath: '/deployments/new' },
    { label: 'All deployments', to: '/deployments', icon: 'rocket', match: ['/deployments'] },
    { label: 'History', to: '/deployments/history', icon: 'clock' },
  ] },
  { title: 'Operations', items: [
    { label: 'Jobs', to: '/jobs', icon: 'list' },
    { label: 'Approvals', to: '/plans', icon: 'shield', badge: 'approvals' },
    { label: 'Maintenance', to: '/maintenance', icon: 'calendar' },
    { label: 'Changes', icon: 'activity', planned: true },
    { label: 'Releases', to: '/releases', icon: 'refresh', min: 'viewer' },
  ] },
  { title: 'Monitoring', items: [
    { label: 'Infrastructure health', to: '/monitoring/infrastructure', icon: 'server' },
    { label: 'Health checks', to: '/checks', icon: 'check' },
    { label: 'Utilization', to: '/utilization', icon: 'activity' },
    { label: 'Incidents', to: '/incidents', icon: 'bell', badge: 'incidents' },
  ] },
  { title: 'Administration', items: [
    { label: 'Users & roles', to: '/users', icon: 'users', min: 'admin' },
    { label: 'Customers', to: '/administration/customers', icon: 'users', min: 'admin' },
    { label: 'Integrations', to: '/endpoints', icon: 'plug' },
    { label: 'Images', to: '/images', icon: 'book', min: 'admin' },
    { label: 'Audit log', to: '/audit', icon: 'file', min: 'approver' },
    { label: 'Network & domains', to: '/settings/network', icon: 'network', min: 'admin' },
    { label: 'System', to: '/system', icon: 'server', min: 'admin' },
    { label: 'Access policies', icon: 'shield', planned: true, min: 'admin' },
    { label: 'Configuration', icon: 'gear', planned: true, min: 'admin' },
  ] },
]

export function isActive(item: NavItem, path: string): boolean {
  if (!item.to) return false
  const bases = item.match ?? [item.to]
  if (item.to === '/deployments' && (path === '/deployments/new' || path === '/deployments/history')) return false
  return bases.some((b) => path === b || path.startsWith(b + '/'))
}

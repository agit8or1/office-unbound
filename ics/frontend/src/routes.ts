import type { RouteRecordRaw } from 'vue-router'
import type { Role } from './api'
import { wizardRoutes } from './wizards'

declare module 'vue-router' {
  interface RouteMeta {
    title?: string
    section?: string                        // breadcrumb group, e.g. "Infrastructure"
    parent?: { label: string; to: string }  // list page this detail page hangs under
    min?: Role                              // minimum role (default viewer)
    bare?: boolean                          // render without the console shell (login, enroll, full-screen wizards)
  }
}

const infraList = (path: string, kind: string, title: string): RouteRecordRaw[] => [
  { path: `/infrastructure/${path}`, name: `infra-${path}`, component: () => import('./views/infra/InfraList.vue'), props: { kind }, meta: { title, section: 'Infrastructure' } },
  { path: `/infrastructure/${path}/:id`, name: `infra-${path}-detail`, component: () => import('./views/infra/InfraDetail.vue'), props: (r) => ({ kind, id: String(r.params.id) }),
    meta: { title, section: 'Infrastructure', parent: { label: title, to: `/infrastructure/${path}` } } },
]

export const routes: RouteRecordRaw[] = [
  { path: '/', redirect: '/overview' },
  { path: '/login', name: 'login', component: () => import('./views/Login.vue'), meta: { title: 'Sign in', bare: true } },
  { path: '/enroll', name: 'enroll', component: () => import('./views/Enroll.vue'), meta: { title: 'Enroll', bare: true } },
  { path: '/overview', name: 'overview', component: () => import('./views/Overview.vue'), meta: { title: 'Overview' } },
  ...infraList('clusters', 'cluster', 'Clusters'),
  ...infraList('nodes', 'node', 'Nodes'),
  ...infraList('vms', 'vm', 'Virtual machines'),
  ...infraList('containers', 'lxc', 'Containers'),
  ...infraList('storage', 'storage', 'Storage'),
  ...infraList('networks', 'network', 'Networks'),
  { path: '/deployments', name: 'deployments', component: () => import('./views/Deployments.vue'), meta: { title: 'Deployments', section: 'Deployments' } },
  { path: '/deployments/:id', name: 'deployment-detail', component: () => import('./views/DeploymentDetail.vue'), props: true, meta: { title: 'Deployment', section: 'Deployments', parent: { label: 'Deployments', to: '/deployments' } } },
  { path: '/jobs/:id?', name: 'jobs', component: () => import('./views/Jobs.vue'), meta: { title: 'Jobs', section: 'Operations' } },
  { path: '/plans/:id?', name: 'plans', component: () => import('./views/Plans.vue'), meta: { title: 'Approvals', section: 'Operations' } },
  { path: '/approvals', redirect: '/plans' },
  { path: '/maintenance', name: 'maintenance', component: () => import('./views/Maintenance.vue'), meta: { title: 'Maintenance', section: 'Operations' } },
  { path: '/checks/:id?', name: 'checks', component: () => import('./views/Checks.vue'), meta: { title: 'Health checks', section: 'Monitoring' } },
  { path: '/utilization', name: 'utilization', component: () => import('./views/Utilization.vue'), meta: { title: 'Utilization', section: 'Monitoring' } },
  { path: '/incidents/:id?', name: 'incidents', component: () => import('./views/Incidents.vue'), meta: { title: 'Incidents', section: 'Monitoring' } },
  { path: '/users/:rest(.*)*', name: 'users', component: () => import('./views/admin/users/UsersPage.vue'), meta: { title: 'Users & roles', section: 'Administration', min: 'viewer' } },
  { path: '/endpoints', name: 'endpoints', component: () => import('./views/Endpoints.vue'), meta: { title: 'Integrations', section: 'Administration' } },
  { path: '/inventory/:id?', name: 'inventory', component: () => import('./views/Inventory.vue'), meta: { title: 'Inventory snapshots', section: 'Administration' } },
  { path: '/preview', name: 'preview', component: () => import('./views/Preview.vue'), meta: { title: 'Plan preview', section: 'Administration', min: 'operator' } },
  { path: '/audit', name: 'audit', component: () => import('./views/Audit.vue'), meta: { title: 'Audit log', section: 'Administration', min: 'approver' } },
  ...wizardRoutes,
  { path: '/:pathMatch(.*)*', name: 'not-found', component: () => import('./views/NotFound.vue'), meta: { title: 'Not found' } },
]

import type { RouteRecordRaw } from 'vue-router'

// Infrastructure > Providers > Proxmox, plus Administration > Customers. Registered in ../../routes.ts.
const P = '/infrastructure/providers'
const parent = { label: 'Proxmox clusters', to: P }
export const providerRoutes: RouteRecordRaw[] = [
  { path: P, name: 'providers', component: () => import('./ProvidersList.vue'), meta: { title: 'Proxmox clusters', section: 'Infrastructure' } },
  { path: `${P}/proxmox/connect`, name: 'provider-connect', component: () => import('./ConnectWizard.vue'), meta: { title: 'Connect a cluster', section: 'Infrastructure', parent, min: 'admin' } },
  { path: `${P}/proxmox/connect-ssh`, name: 'provider-connect-ssh', component: () => import('./SshOnboard.vue'), meta: { title: 'Connect with SSH', section: 'Infrastructure', parent, min: 'operator' } },
  { path: `${P}/:id`, name: 'provider-cluster', component: () => import('./ClusterDashboard.vue'), props: true, meta: { title: 'Cluster', section: 'Infrastructure', parent } },
  { path: `${P}/:id/permissions`, name: 'provider-permissions', component: () => import('./PermissionsPage.vue'), props: true, meta: { title: 'Permissions', section: 'Infrastructure', parent } },
  { path: `${P}/:id/credentials`, name: 'provider-credentials', component: () => import('./CredentialsPage.vue'), props: true, meta: { title: 'Credentials', section: 'Infrastructure', parent } },
  { path: '/administration/customers', name: 'customers', component: () => import('./CustomersPage.vue'), meta: { title: 'Customers and policies', section: 'Administration', min: 'admin' } },
]

// Route table for the wizards. The app shell (src/routes.ts) spreads this into its own table.
// /setup/connection[?endpoint=<id>] is the connection step on its own: "Add endpoint" (no id) / "Edit connection" (id => endpoint.update plan).
import type { Component } from 'vue'
import SetupWizard from './setup/SetupWizard.vue'
import ConnectionWizard from './setup/ConnectionWizard.vue'
import DeployWizard from './deploy/DeployWizard.vue'
import ChangeWizard from './change/ChangeWizard.vue'

export interface WizardRoute { path: string; name: string; title: string; component: Component; minRole: 'operator' | 'admin' }

export const wizardRoutes: WizardRoute[] = [
  { path: '/setup', name: 'setup', title: 'First-run setup', component: SetupWizard, minRole: 'admin' },
  { path: '/setup/connection', name: 'setup-connection', title: 'Endpoint connection', component: ConnectionWizard, minRole: 'admin' },
  { path: '/deployments/new', name: 'deployment-new', title: 'New deployment', component: DeployWizard, minRole: 'operator' },
  { path: '/changes/new', name: 'change-new', title: 'Change an environment', component: ChangeWizard, minRole: 'operator' },
]

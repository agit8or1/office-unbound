import type { RouteRecordRaw } from 'vue-router'

// Agent F fills this: wizard routes (setup wizard, new-deployment wizard, change wizard ...).
// Conventions the console already links to: '/setup' (first-run setup wizard) and '/deployments/new'.
// A route may set meta: { title, section, min, bare } like the routes in ../routes.ts.
export const wizardRoutes: RouteRecordRaw[] = []

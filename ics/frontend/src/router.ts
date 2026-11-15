import { createRouter, createWebHashHistory } from 'vue-router'
import { routes } from './routes'

// Hash history keeps the existing '#/page/arg' URLs; the server only ever serves /ui/ (no history-API fallback needed).
export const router = createRouter({ history: createWebHashHistory('/ui/'), routes, scrollBehavior: () => ({ top: 0 }) })

/** True when a path is registered (used to show or hide links into wizards that may not be merged yet). */
export function hasPath(path: string): boolean {
  const r = router.resolve(path)
  return r.matched.length > 0 && r.name !== 'not-found'
}

// Build-time check entry: bundles the real wizard routes the way the app shell will, so `dist` can be grepped for dev-only mock code.
// Usage: npx vite build --config src/wizards/prodcheck.vite.config.ts
import { wizardRoutes } from './index'
export default wizardRoutes

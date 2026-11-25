// Route table for the Users & roles area. The shell registers this (same shape as the `pages` list in App.vue).
// Sub-pages are tabs inside the page, addressed as #/users/<tab>[/<id-or-mode>[/<username>]]:
//   directory (+ /<user id> opens the detail drawer), invitations, privileged (+ /grant | /create | /change/<username>), roles, policies.
import type { Role } from '../../../api'
import UsersPage from './UsersPage.vue'

export interface AdminRoute { id: string; label: string; min: Role; comp: unknown; group: 'Administration' }

export const usersRoutes: AdminRoute[] = [
  { id: 'users', label: 'Platform admins', min: 'viewer', comp: UsersPage, group: 'Administration' },
]
export const usersTabs = ['directory', 'invitations', 'privileged', 'roles', 'policies'] as const
export { UsersPage }
export default usersRoutes

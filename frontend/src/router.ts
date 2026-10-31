import { nextTick } from 'vue'
import { createRouter, createWebHistory, type LocationQuery, type RouteLocationNormalized } from 'vue-router'
import { can, refreshSession, session, type Role } from '@/composables/useSession'

/** Where a link to the Findings screen from before the split lands: a CVE's (the tool filter on
 * vulnerabilities) on Vulnerabilities, any other on Misconfigurations. */
export function findingsRedirect(query: LocationQuery): 'vulnerabilities' | 'misconfigurations' {
  const tool = query.tool
  return (Array.isArray(tool) ? tool : [tool]).includes('vulnerabilities') ? 'vulnerabilities' : 'misconfigurations'
}

declare module 'vue-router' {
  interface RouteMeta {
    /** The least role that may open the page (ADR-0041); anyone signed in when unset. */
    role?: Role
  }
}

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/sign-in', name: 'sign-in', component: () => import('@/views/SignInView.vue'), meta: { title: 'Sign in', public: true } },
    // After signing in with a password an admin set: every other page waits for a new one.
    { path: '/sign-in/new-password', name: 'new-password', component: () => import('@/views/NewPasswordView.vue'), meta: { title: 'Choose a new password' } },
    { path: '/', name: 'overview', component: () => import('@/views/overview/OverviewView.vue'), meta: { title: 'Overview' } },
    // Navigation follows CatherIs Platform's pattern (design-system.md, Shell): Posture,
    // Investigate and Operate sections, and an Administration module, each page its own route.
    // Schedules and Runs keep their /scans URLs (they moved from a Scans module to Operate on
    // 2026-10-06).
    {
      path: '/posture',
      component: () => import('@/views/ShellLayout.vue'),
      redirect: { name: 'compliance' },
      children: [
        { path: 'compliance', name: 'compliance', component: () => import('@/views/posture/ComplianceView.vue'), meta: { title: 'Compliance · Posture' } },
        // The title gains the framework's name once it loads (FrameworkView).
        { path: 'compliance/:framework', name: 'framework', component: () => import('@/views/posture/FrameworkView.vue'), meta: { title: 'Compliance · Posture', navItem: 'compliance' } },
      ],
    },
    {
      path: '/investigate',
      component: () => import('@/views/ShellLayout.vue'),
      redirect: { name: 'misconfigurations' },
      children: [
        // Prowler's and CloudFox's findings (ADR-0042, amended 2026-10-31: the screen was named
        // Findings, and also listed CVEs).
        { path: 'misconfigurations', name: 'misconfigurations', component: () => import('@/views/investigate/FindingsView.vue'), meta: { title: 'Misconfigurations · Investigate' } },
        { path: 'vulnerabilities', name: 'vulnerabilities', component: () => import('@/views/investigate/VulnerabilitiesView.vue'), meta: { title: 'Vulnerabilities · Investigate' } },
        // A link or bookmark from before the split: a CVE's goes to Vulnerabilities.
        { path: 'findings', redirect: (to) => ({ name: findingsRedirect(to.query), query: to.query }) },
        { path: 'resources', name: 'resources', component: () => import('@/views/investigate/ResourcesView.vue'), meta: { title: 'Resources · Investigate' } },
        { path: 'map', name: 'resource-map', component: () => import('@/views/investigate/map/MapView.vue'), meta: { title: 'Resource map · Investigate' } },
        // An open path adds its rule name in front of the title (AttackPathsView).
        { path: 'attack-paths', name: 'attack-paths', component: () => import('@/views/investigate/paths/AttackPathsView.vue'), meta: { title: 'Attack paths · Investigate' } },
      ],
    },
    {
      path: '/scans',
      component: () => import('@/views/ShellLayout.vue'),
      redirect: { name: 'schedules' },
      children: [
        { path: 'schedules', name: 'schedules', component: () => import('@/views/scans/SchedulesView.vue'), meta: { title: 'Schedules · Operate' } },
        { path: 'runs', name: 'runs', component: () => import('@/views/scans/RunsView.vue'), meta: { title: 'Runs · Operate' } },
      ],
    },
    {
      path: '/admin',
      component: () => import('@/views/ShellLayout.vue'),
      redirect: { name: 'connections' },
      children: [
        { path: 'connections', name: 'connections', component: () => import('@/views/admin/ConnectionsView.vue'), meta: { title: 'Connections · Administration' } },
        { path: 'settings', name: 'settings', component: () => import('@/views/admin/SettingsView.vue'), meta: { title: 'Settings · Administration', role: 'admin' } },
        { path: 'users', name: 'users', component: () => import('@/views/admin/UsersView.vue'), meta: { title: 'Users · Administration', role: 'admin' } },
        // Where Schedules and Runs were before 2026-10-06.
        { path: 'schedules', redirect: { name: 'schedules' } },
        { path: 'runs', redirect: { name: 'runs' } },
      ],
    },
    { path: '/:pathMatch(.*)*', redirect: { name: 'overview' } },
  ],
})

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  if (session.value === null && !(await refreshSession())) {
    return { name: 'sign-in', query: { next: to.fullPath } }
  }
  if (session.value?.must_change_password) {
    return to.name === 'new-password' ? true : { name: 'new-password', query: { next: to.fullPath } }
  }
  if (to.name === 'new-password') return { name: 'overview' }
  if (to.meta.role && !can(to.meta.role)) return { name: 'overview' }
  return true
})

router.afterEach((to: RouteLocationNormalized, from) => {
  document.title = `${String(to.meta.title ?? 'Argus')} · Argus`
  if (from.matched.length === 0) return // first load: leave focus where the browser put it
  if (to.path === from.path) return // a query change (range, account): same page, keep scroll and focus
  // Move focus to the new page's heading so screen readers announce the change.
  void nextTick(() => document.querySelector<HTMLElement>('[data-page-title]')?.focus())
})

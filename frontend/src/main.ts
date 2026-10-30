import '@fontsource/inter/400.css'
import '@fontsource/inter/500.css'
import '@fontsource/inter/600.css'
import '@fontsource/inter/700.css'
import '@fontsource/jetbrains-mono/400.css'
import '@fontsource/jetbrains-mono/500.css'
import '@fontsource/jetbrains-mono/600.css'
import './theme/tokens.css'
// First: stamps the theme on <html> before the app mounts (no flash of the other theme).
import '@/composables/useTheme'
import './theme/base.css'

import { createApp } from 'vue'
import { setForbiddenHandler, setUnauthorizedHandler } from '@/api/client'
import { installLeaveGuard } from '@/composables/useDirtyGuard'
import { can, refreshSession, session } from '@/composables/useSession'
import { toast } from '@/composables/useToasts'
import App from './App.vue'
import { router } from './router'

setUnauthorizedHandler(() => {
  if (router.currentRoute.value.name === 'sign-in') return
  session.value = null
  void router.push({ name: 'sign-in', query: { next: router.currentRoute.value.fullPath, reason: 'expired' } })
})
// A role changed, or a password change became due, while the page was open (ADR-0041): read
// the session again, and let the router send the user where they may be.
setForbiddenHandler(async () => {
  await refreshSession()
  const current = router.currentRoute.value
  if (session.value?.must_change_password && current.name !== 'new-password') {
    await router.replace({ name: 'new-password', query: { next: current.fullPath } })
  } else if (current.meta.role && !can(current.meta.role)) {
    await router.replace({ name: 'overview' })
  }
})

installLeaveGuard(router)
const app = createApp(App)
// A view that throws is never a silent blank: say so (CatherIs Platform's error boundary).
app.config.errorHandler = (err) => {
  console.error(err)
  toast('Something went wrong on this page. Reload it if it keeps happening.', 'error')
}
app.use(router).mount('#app')

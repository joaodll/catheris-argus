/* eslint-disable vue/one-component-per-file -- throwaway harness components for the guard */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h, ref } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { LEAVE_QUESTION, installLeaveGuard, useDirtyGuard } from './useDirtyGuard'

const page = defineComponent({ render: () => h('div') })
const mounted: VueWrapper[] = []

afterEach(() => {
  mounted.splice(0).forEach((w) => w.unmount())
  vi.restoreAllMocks()
})

function setup() {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/settings', component: page },
      { path: '/runs', component: page },
      { path: '/sign-in', name: 'sign-in', component: page },
    ],
  })
  installLeaveGuard(router)
  const first = ref(false)
  const second = ref(false)
  const Form = (dirty: typeof first) => defineComponent({ setup: () => { useDirtyGuard(dirty); return () => h('form') } })
  const wrappers = [mount(Form(first)), mount(Form(second))]
  mounted.push(...wrappers)
  return { router, first, second, wrappers }
}

describe('leave guard', () => {
  it('lets a clean page go without asking', async () => {
    const ask = vi.spyOn(window, 'confirm')
    const { router } = setup()
    await router.push('/settings')
    await router.push('/runs')
    expect(router.currentRoute.value.path).toBe('/runs')
    expect(ask).not.toHaveBeenCalled()
  })

  it('asks once for two dirty forms, and staying keeps the page', async () => {
    const ask = vi.spyOn(window, 'confirm').mockReturnValue(false)
    const { router, first, second } = setup()
    await router.push('/settings')
    first.value = second.value = true
    await router.push('/runs')
    await flushPromises()
    expect(ask).toHaveBeenCalledTimes(1)
    expect(ask).toHaveBeenCalledWith(LEAVE_QUESTION)
    expect(router.currentRoute.value.path).toBe('/settings')
  })

  it('leaves when the person confirms', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { router, first } = setup()
    await router.push('/settings')
    first.value = true
    await router.push('/runs')
    expect(router.currentRoute.value.path).toBe('/runs')
  })

  it('never blocks the redirect to sign-in after the session expires', async () => {
    const { router, first } = setup()
    await router.push('/settings')
    first.value = true
    await router.push({ name: 'sign-in' })
    expect(router.currentRoute.value.path).toBe('/sign-in')
  })

  it('forgets a form once it unmounts', async () => {
    const { router, first } = setup()
    await router.push('/settings')
    first.value = true
    mounted.splice(0).forEach((w) => w.unmount())
    await router.push('/runs')
    expect(router.currentRoute.value.path).toBe('/runs')
  })
})

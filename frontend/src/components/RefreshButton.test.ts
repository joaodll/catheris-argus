import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import RefreshButton from './RefreshButton.vue'

describe('RefreshButton', () => {
  it('reloads once per press and shows that it is busy until the reload ends', async () => {
    let calls = 0
    let finish: () => void = () => {}
    const reload = () => {
      calls += 1
      return new Promise<void>((resolve) => (finish = resolve))
    }
    const wrapper = mount(RefreshButton, { props: { reload } })
    const button = wrapper.get('button')
    expect(button.text()).toBe('Refresh')
    expect(button.attributes('aria-disabled')).toBe('false')

    await button.trigger('click')
    expect(calls).toBe(1)
    expect(button.attributes('aria-disabled')).toBe('true')
    expect(button.find('svg').exists()).toBe(true) // the spinner, beside the label
    expect(button.text()).toBe('Refresh')
    // Still focusable while busy, and a second press does nothing.
    expect(button.attributes('disabled')).toBeUndefined()
    await button.trigger('click')
    expect(calls).toBe(1)

    finish()
    await flushPromises()
    expect(button.attributes('aria-disabled')).toBe('false')
    expect(button.find('svg').exists()).toBe(false)
  })

  it('recovers when the reload fails', async () => {
    const wrapper = mount(RefreshButton, { props: { reload: () => Promise.reject(new Error('down')) } })
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(wrapper.get('button').attributes('aria-disabled')).toBe('false')
  })
})

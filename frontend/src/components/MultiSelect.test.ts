import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import MultiSelect from './MultiSelect.vue'

const OPTIONS = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
]

function make(props: Record<string, unknown> = {}) {
  return mount(MultiSelect, {
    props: { id: 'f-sev', label: 'Severity', options: OPTIONS, modelValue: [], ...props },
    attachTo: document.body,
  })
}

describe('MultiSelect', () => {
  it('says All with nothing chosen, and the first choice plus a count with several', async () => {
    const wrapper = make()
    expect(wrapper.get('button').text()).toContain('All')
    await wrapper.setProps({ modelValue: ['high', 'critical'] })
    expect(wrapper.get('button').text()).toContain('Critical')
    expect(wrapper.get('button').text()).toContain('+1')
    wrapper.unmount()
  })

  it('opens a multi-select listbox and toggles with the keyboard', async () => {
    const wrapper = make({ modelValue: ['high'] })
    const trigger = wrapper.get('#f-sev')
    await trigger.trigger('keydown', { key: 'ArrowDown' })
    expect(trigger.attributes('aria-expanded')).toBe('true')
    const listbox = wrapper.get('[role="listbox"]')
    expect(listbox.attributes('aria-multiselectable')).toBe('true')
    expect(wrapper.findAll('[role="option"]')[1]?.attributes('aria-selected')).toBe('true')
    await listbox.trigger('keydown', { key: 'ArrowDown' })
    await listbox.trigger('keydown', { key: ' ' })
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual([[]]) // High toggled off
    await listbox.trigger('keydown', { key: 'Escape' })
    expect(trigger.attributes('aria-expanded')).toBe('false')
    expect(document.activeElement).toBe(trigger.element)
    wrapper.unmount()
  })

  it('lets Tab reach Clear, and closes once focus leaves the panel', async () => {
    const wrapper = make({ modelValue: ['high'] })
    await wrapper.get('#f-sev').trigger('click')
    const clear = wrapper.get('.ms-foot button')
    await wrapper.get('[role="listbox"]').trigger('focusout', { relatedTarget: clear.element })
    await clear.trigger('keydown', { key: 'Enter' })
    expect(wrapper.emitted('update:modelValue')).toBeUndefined() // Enter on Clear toggles nothing
    expect(wrapper.get('#f-sev').attributes('aria-expanded')).toBe('true')
    await clear.trigger('focusout', { relatedTarget: document.body })
    expect(wrapper.get('#f-sev').attributes('aria-expanded')).toBe('false')
    wrapper.unmount()
  })

  it('adds a choice on click and clears from the footer', async () => {
    const wrapper = make({ modelValue: ['high'] })
    await wrapper.get('#f-sev').trigger('click')
    await wrapper.findAll('[role="option"]')[2]?.trigger('click')
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual([['high', 'medium']])
    await wrapper.get('.ms-foot button').trigger('click')
    expect(wrapper.emitted('update:modelValue')?.[1]).toEqual([[]])
    wrapper.unmount()
  })

  it('searches a long list', async () => {
    const options = Array.from({ length: 12 }, (_, i) => ({ value: `check_${i}`, label: `check_${i}`, mono: true }))
    const wrapper = make({ options })
    await wrapper.get('#f-sev').trigger('click')
    await wrapper.get('input[type="search"]').setValue('_11')
    expect(wrapper.findAll('[role="option"]').map((o) => o.text())).toEqual(['check_11'])
    await wrapper.get('input[type="search"]').setValue('nothing')
    expect(wrapper.text()).toContain('No match')
    wrapper.unmount()
  })

  it('is disabled while loading, on error and with no option in the data', async () => {
    for (const [props, text] of [
      [{ status: 'loading' }, 'Loading…'],
      [{ status: 'error' }, 'Unavailable'],
      [{ options: [] }, 'None in the data'],
    ] as const) {
      const wrapper = make(props)
      const trigger = wrapper.get('#f-sev')
      expect(trigger.text()).toContain(text)
      expect(trigger.attributes('aria-disabled')).toBe('true')
      await trigger.trigger('click')
      expect(trigger.attributes('aria-expanded')).toBe('false')
      wrapper.unmount()
    }
  })
})

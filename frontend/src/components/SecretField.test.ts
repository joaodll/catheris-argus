import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import SecretField from './SecretField.vue'

describe('SecretField', () => {
  it('shows only that a stored secret is set, never an input with a value', () => {
    const wrapper = mount(SecretField, {
      props: { label: 'Secret access key', modelValue: '', setOn: '2026-10-02T10:00:00Z' },
    })
    expect(wrapper.text()).toContain('Set')
    expect(wrapper.text()).toContain('2026-10-02')
    expect(wrapper.find('input').exists()).toBe(false)
  })

  it('replacing opens an empty password input', async () => {
    const wrapper = mount(SecretField, {
      props: { label: 'Secret access key', modelValue: '', setOn: '2026-10-02T10:00:00Z' },
    })
    await wrapper.get('button').trigger('click')
    const input = wrapper.get('input')
    expect(input.attributes('type')).toBe('password')
    expect((input.element as HTMLInputElement).value).toBe('')
    expect(wrapper.text()).toContain('stays in use until you save')
  })
})

import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import AccessKeyFields from './AccessKeyFields.vue'

const empty = { secret: '', sessionToken: '' }

describe('AccessKeyFields', () => {
  it('asks for a session token only for a temporary key', () => {
    const longLived = mount(AccessKeyFields, { props: { modelValue: { accessKeyId: 'AKIA' + 'X'.repeat(16), ...empty } } })
    expect(longLived.text()).not.toContain('Session token')
    const temporary = mount(AccessKeyFields, { props: { modelValue: { accessKeyId: 'ASIA' + 'X'.repeat(16), ...empty } } })
    expect(temporary.text()).toContain('Session token')
    expect(temporary.findAll('input[type="password"]')).toHaveLength(2)
  })

  it('emits the whole key when one part changes', async () => {
    const wrapper = mount(AccessKeyFields, { props: { modelValue: { accessKeyId: '', ...empty } } })
    await wrapper.get('input').setValue('ASIA' + 'X'.repeat(16))
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual([{ accessKeyId: 'ASIA' + 'X'.repeat(16), ...empty }])
  })
})

import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import AddConnectionModal from './AddConnectionModal.vue'

// jsdom has no <dialog>.showModal(): the modal shell is not under test here.
const global = { stubs: { AppModal: { template: '<div><slot /><slot name="footer" /></div>' } } }

function types(demo: boolean): { values: string[]; checked: string } {
  const wrapper = mount(AddConnectionModal, { props: { demo }, global })
  const radios = wrapper.findAll<HTMLInputElement>('input[name="kind"]')
  return {
    values: radios.map((r) => r.element.value),
    checked: radios.find((r) => r.element.checked)?.element.value ?? '',
  }
}

describe('AddConnectionModal', () => {
  it('offers Demo first where the deployment allows it (Docker Compose)', () => {
    expect(types(true)).toEqual({ values: ['demo', 'assume_role', 'access_key'], checked: 'demo' })
  })

  it('offers AWS only on Kubernetes, starting on assume role', () => {
    expect(types(false)).toEqual({ values: ['assume_role', 'access_key'], checked: 'assume_role' })
  })
})

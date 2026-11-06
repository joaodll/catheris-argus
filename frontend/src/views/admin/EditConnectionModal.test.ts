import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Schemas } from '@/api/client'
import EditConnectionModal from './EditConnectionModal.vue'

const patch = vi.fn()
vi.mock('@/api/client', async (actual) => ({
  ...(await actual<typeof import('@/api/client')>()),
  api: { PATCH: (...args: unknown[]) => patch(...args) },
  unwrap: async (p: Promise<unknown>) => p,
}))

// jsdom has no <dialog>.showModal(): the modal shell is not under test here.
const global = {
  stubs: { AppModal: { template: '<div><slot /><slot name="footer" /></div>' }, TestConnection: true },
}

const connection: Schemas['ConnectionOut'] = {
  id: 7,
  name: 'prod',
  kind: 'aws',
  account_id: '210987654321',
  auth_method: 'assume_role',
  role_arn: 'arn:aws:iam::210987654321:role/HandBuilt',
  external_id_set: true,
  access_key_id_hint: null,
  secret_set_at: null,
  enabled: true,
  updated_at: '2026-11-06T00:00:00Z',
  updated_by: 'admin',
}

function sent(): Schemas['ConnectionPatch'] {
  return (patch.mock.calls.at(-1)?.[1] as { body: Schemas['ConnectionPatch'] }).body
}

describe('EditConnectionModal, assume role', () => {
  beforeEach(() => patch.mockReset().mockResolvedValue({}))

  it('sends a new role only, and nothing about the ExternalId it keeps', async () => {
    const wrapper = mount(EditConnectionModal, { props: { connection }, global })
    await wrapper.find('#e-arn').setValue('arn:aws:iam::210987654321:role/ArgusScanner')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(sent()).toEqual({
      assume_role: { role_arn: 'arn:aws:iam::210987654321:role/ArgusScanner', clear_external_id: false },
    })
  })

  it('removes the ExternalId without touching the role', async () => {
    const wrapper = mount(EditConnectionModal, { props: { connection }, global })
    await wrapper.findAll('button').find((b) => b.text() === 'Remove')!.trigger('click')
    expect(wrapper.text()).toContain('Removed when you save')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(sent()).toEqual({ assume_role: { clear_external_id: true } })
  })

  it('never shows the stored ExternalId, and a Viewer gets no controls for it', () => {
    const wrapper = mount(EditConnectionModal, { props: { connection, readonly: true }, global })
    const labels = wrapper.findAll('button').map((b) => b.text())
    expect(labels).not.toContain('Replace')
    expect(labels).not.toContain('Remove')
    // The role field sits in the fieldset a Viewer's copy disables.
    expect(wrapper.find<HTMLFieldSetElement>('fieldset').element.disabled).toBe(true)
    expect(wrapper.find('fieldset #e-arn').exists()).toBe(true)
  })
})

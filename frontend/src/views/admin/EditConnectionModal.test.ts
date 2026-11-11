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

describe('EditConnectionModal, switching the sign-in method', () => {
  beforeEach(() => patch.mockReset().mockResolvedValue({}))

  const accessKeyConnection: Schemas['ConnectionOut'] = {
    ...connection,
    auth_method: 'access_key',
    role_arn: null,
    external_id_set: false,
    access_key_id_hint: '…ZZZZ',
    secret_set_at: '2026-11-01T00:00:00Z',
  }

  function choose(wrapper: ReturnType<typeof mount>, value: string): Promise<void> {
    return wrapper.find(`input[name="e-method"][value="${value}"]`).setValue(true)
  }

  it('selects the stored method, and shows no switch until another is chosen', () => {
    const wrapper = mount(EditConnectionModal, { props: { connection }, global })
    expect(wrapper.find<HTMLInputElement>('input[name="e-method"][value="assume_role"]').element.checked).toBe(true)
    expect(wrapper.text()).not.toContain('Saving switches')
    expect(wrapper.find('button[type="submit"]').text()).toBe('Save changes')
  })

  it('switches a role to an access key with the whole key, and says the role is deleted', async () => {
    const wrapper = mount(EditConnectionModal, { props: { connection }, global })
    await choose(wrapper, 'access_key')
    expect(wrapper.find('#e-arn').exists()).toBe(false) // the stored role's controls are hidden
    expect(wrapper.text()).toContain('The stored role and its external ID are deleted')
    expect(wrapper.text()).not.toContain('deactivate the old key')
    expect(wrapper.find('button[type="submit"]').text()).toBe('Switch and save')
    const inputs = wrapper.findAll('input:not([type="radio"]):not([type="checkbox"])')
    await inputs[1]!.setValue('AKIA' + 'Q'.repeat(16))
    await inputs[2]!.setValue('argus-test-only-not-a-real-secret')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(sent()).toEqual({
      auth_method: 'access_key',
      access_key: { access_key_id: 'AKIA' + 'Q'.repeat(16), secret_access_key: 'argus-test-only-not-a-real-secret', session_token: null },
    })
  })

  it('switches an access key to a role, with no external ID unless one is given', async () => {
    const wrapper = mount(EditConnectionModal, { props: { connection: accessKeyConnection }, global })
    await choose(wrapper, 'assume_role')
    expect(wrapper.text()).toContain('The stored access key and its secret are deleted')
    expect(wrapper.text()).toContain('Then deactivate the old key in IAM.')
    expect(wrapper.findAll('button').map((b) => b.text())).not.toContain('Replace')
    await wrapper.find('#e-new-arn').setValue('arn:aws:iam::210987654321:role/ArgusScanner')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(sent()).toEqual({
      auth_method: 'assume_role',
      assume_role: { role_arn: 'arn:aws:iam::210987654321:role/ArgusScanner', clear_external_id: false },
    })
  })

  it('discards what was typed for the other method when the stored one is chosen again', async () => {
    const wrapper = mount(EditConnectionModal, { props: { connection: accessKeyConnection }, global })
    await choose(wrapper, 'assume_role')
    await wrapper.find('#e-new-arn').setValue('arn:aws:iam::210987654321:role/ArgusScanner')
    await choose(wrapper, 'access_key')
    expect(wrapper.text()).not.toContain('Saving switches')
    await choose(wrapper, 'assume_role')
    expect(wrapper.find<HTMLInputElement>('#e-new-arn').element.value).toBe('')
  })

  it('offers no switch for a Demo connection, and a Viewer cannot switch', () => {
    const demo = mount(EditConnectionModal, {
      props: { connection: { ...connection, kind: 'demo', auth_method: 'none', role_arn: null, external_id_set: false } },
      global,
    })
    expect(demo.find('input[name="e-method"]').exists()).toBe(false)
    const viewer = mount(EditConnectionModal, { props: { connection, readonly: true }, global })
    expect(viewer.find<HTMLFieldSetElement>('fieldset').element.disabled).toBe(true)
    expect(viewer.find('fieldset input[name="e-method"]').exists()).toBe(true)
  })
})

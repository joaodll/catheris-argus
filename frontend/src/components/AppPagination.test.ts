import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import AppPagination from './AppPagination.vue'
import SortHeader from './SortHeader.vue'

describe('AppPagination', () => {
  it('shows the position and the total, and pages within bounds', async () => {
    const wrapper = mount(AppPagination, { props: { total: 683, page: 1, limit: 20 } })
    expect(wrapper.text()).toContain('1 / 35')
    expect(wrapper.text()).toContain('683 records')
    expect(wrapper.get('[aria-label="Previous page"]').attributes('disabled')).toBeDefined()
    await wrapper.get('[aria-label="Next page"]').trigger('click')
    expect(wrapper.emitted('change')?.[0]).toEqual([2])
  })

  it('shows only the total for a single page', () => {
    const wrapper = mount(AppPagination, { props: { total: 1, page: 1 } })
    expect(wrapper.findAll('button')).toHaveLength(0)
    expect(wrapper.text()).toBe('1 record')
  })

  it('says when a search counted only up to the cap', () => {
    const wrapper = mount(AppPagination, { props: { total: 10000, page: 1, capped: true } })
    expect(wrapper.text()).toContain('1 / 500')
    expect(wrapper.text()).toContain('10,000+ records')
  })
})

describe('SortHeader', () => {
  it('states the order and what a click does', async () => {
    const wrapper = mount(SortHeader, {
      props: { label: 'Started (UTC)', direction: 'desc', descText: 'newest first', ascText: 'oldest first' },
      attachTo: document.createElement('tr'),
    })
    expect(wrapper.attributes('aria-sort')).toBe('descending')
    expect(wrapper.get('button').attributes('aria-label')).toBe('Started (UTC), sorted newest first. Sort oldest first')
    await wrapper.get('button').trigger('click')
    expect(wrapper.emitted('toggle')).toHaveLength(1)
  })
})

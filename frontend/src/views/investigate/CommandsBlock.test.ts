import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import CommandsBlock from './CommandsBlock.vue'

type Commands = InstanceType<typeof CommandsBlock>['$props']['commands']

const COMMANDS: Commands = [
  { label: 'acts_on_target', command: 'tool act one', note: null, source: 'a.txt' },
  { label: 'check', command: 'tool look one', note: 'A note from the tool.', source: 'b.txt' },
  { label: 'check', command: 'tool look two', note: null, source: 'b.txt' },
]

describe('CommandsBlock', () => {
  it('groups commands by label, checks first and acting commands last as a warning', () => {
    const wrapper = mount(CommandsBlock, { props: { commands: COMMANDS } })
    const heads = wrapper.findAll('h4').map((h) => h.text())
    expect(heads).toEqual(['Check', 'Acts on the target — run only with authorization'])
    expect(wrapper.text()).toContain('Argus never runs these. Run them only with written authorization.')
    const codes = wrapper.findAll('pre').map((p) => p.text())
    expect(codes).toEqual(['tool look one', 'tool look two', 'tool act one'])
    expect(wrapper.findAll('.cmd.acts')).toHaveLength(1)
    expect(wrapper.find('.cmd.acts pre').text()).toBe('tool act one')
    expect(wrapper.find('.note').text()).toBe('A note from the tool.')
  })

  it('offers copy only: every button copies, none runs anything', () => {
    const wrapper = mount(CommandsBlock, { props: { commands: COMMANDS } })
    const buttons = wrapper.findAll('button')
    expect(buttons).toHaveLength(COMMANDS.length)
    for (const b of buttons) expect(b.attributes('aria-label') ?? b.text()).toMatch(/^Copy/)
    expect(wrapper.find('form').exists()).toBe(false)
    expect(wrapper.find('a').exists()).toBe(false)
  })

  it('labels the section by its own heading', () => {
    const wrapper = mount(CommandsBlock, { props: { commands: COMMANDS } })
    const id = wrapper.get('h3').attributes('id')
    expect(id).toBeTruthy()
    expect(wrapper.get('section').attributes('aria-labelledby')).toBe(id)
  })

  it('renders nothing without commands', () => {
    const wrapper = mount(CommandsBlock, { props: { commands: [] } })
    expect(wrapper.find('section').exists()).toBe(false)
  })
})

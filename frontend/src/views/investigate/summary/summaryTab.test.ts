import { describe, expect, it } from 'vitest'
import { parseTab, summaryConnection } from './summaryTab'

describe('Summary | List in the URL', () => {
  it('opens the summary on the bare screen and the list for any list parameter', () => {
    expect(parseTab({})).toBe('summary')
    expect(parseTab({ severity: 'critical' })).toBe('list')
    expect(parseTab({ finding: '12' })).toBe('list')
    expect(parseTab({ page: '2' })).toBe('list')
    expect(parseTab({ q: '' })).toBe('summary') // an empty value is no filter
  })

  it('lets an explicit tab win', () => {
    expect(parseTab({ tab: 'summary', connection: '7' })).toBe('summary')
    expect(parseTab({ tab: 'list' })).toBe('list')
    expect(parseTab({ tab: 'other' })).toBe('summary')
  })

  it('gives the summary one account or all', () => {
    expect(summaryConnection([])).toBe(0)
    expect(summaryConnection([7])).toBe(7)
    expect(summaryConnection([7, 8])).toBe(0)
  })
})

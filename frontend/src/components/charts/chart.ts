/** Shared by the history charts (the Overview's severity trend, a framework's score). */

/** One line of a LineChart. */
export interface LineSeries {
  key: string
  label: string
  color: string
  values: (number | null | undefined)[] // one per date; a missing one breaks the line
  dotColors?: (string | undefined)[] // per point; the line's colour when unset
}

/** 6M / 3M / 1M: month-ends, weekly, daily. */
export type Range = '6M' | '3M' | '1M'

export const RANGES: { id: Range; label: string }[] = [
  { id: '6M', label: 'Six months, month-end' },
  { id: '3M', label: 'Three months, weekly' },
  { id: '1M', label: 'One month, daily' },
]

/** A range from the URL: 6M when unset or unknown. */
export function parseRange(value: unknown): Range {
  return RANGES.find((r) => r.id === value)?.id ?? '6M'
}

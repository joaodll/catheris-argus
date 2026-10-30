/** Formatting shared by every screen. Missing values are never shown as 0. */

const intFormat = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 })
const oneDecimal = new Intl.NumberFormat('en-US', { minimumFractionDigits: 1, maximumFractionDigits: 1 })

export const NO_DATA = 'No data'

export function int(value: number | null | undefined): string {
  return value == null ? NO_DATA : intFormat.format(value)
}

export function decimal(value: number | null | undefined): string {
  return value == null ? NO_DATA : oneDecimal.format(value)
}

export function percent(value: number | null | undefined): string {
  return value == null ? NO_DATA : `${oneDecimal.format(value)}%`
}

/** +12, −3, ±0 (a true minus sign). */
export function signed(value: number, digits = 0): string {
  const text = new Intl.NumberFormat('en-US', { maximumFractionDigits: digits }).format(Math.abs(value))
  if (value > 0) return `+${text}`
  if (value < 0) return `−${text}`
  return '±0'
}

/** The colour token for a change, given which direction is good. */
export function deltaColor(value: number | null | undefined, upIsGood: boolean): string {
  if (value == null || value === 0) return 'var(--delta-flat)'
  return value > 0 === upIsGood ? 'var(--delta-better)' : 'var(--delta-worse)'
}

export function scoreColor(score: number | null | undefined): string {
  if (score == null) return 'var(--text-3)'
  if (score >= 80) return 'var(--score-good)'
  if (score >= 70) return 'var(--score-fair)'
  if (score >= 60) return 'var(--score-weak)'
  return 'var(--score-poor)'
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** "2026-10" -> "Oct". */
export function monthName(yyyyMm: string): string {
  return MONTHS[Number(yyyyMm.slice(5, 7)) - 1] ?? yyyyMm
}

/** "2026-10-03" -> "Oct 3, 2026". */
export function longDate(iso: string | null | undefined): string {
  if (!iso) return NO_DATA
  const [y, m, d] = iso.slice(0, 10).split('-').map(Number)
  return `${MONTHS[(m ?? 1) - 1]} ${d}, ${y}`
}

/** "2026-10-03" -> "Oct 3". */
export function shortDate(iso: string): string {
  const [, m, d] = iso.slice(0, 10).split('-').map(Number)
  return `${MONTHS[(m ?? 1) - 1]} ${d}`
}

/** A timestamp as "2026-10-03 02:07 UTC". */
export function utc(iso: string | null | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

/** A timestamp as "02:07:41" UTC (tables; the full value goes in the title). */
export function utcTime(iso: string): string {
  return new Date(iso).toISOString().slice(11, 19)
}

export function relative(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return '—'
  const seconds = Math.round((now - new Date(iso).getTime()) / 1000)
  if (seconds < 0) return 'in the future'
  if (seconds < 60) return `${seconds} s ago`
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours} h ago`
  const days = Math.round(hours / 24)
  return days === 1 ? 'yesterday' : `${days} days ago`
}

/** Time since `iso` as a clock: 75 s -> "01:15", 3725 s -> "1:02:05". */
export function elapsed(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return '—'
  const total = Math.max(0, Math.floor((now - new Date(iso).getTime()) / 1000))
  const h = Math.floor(total / 3600)
  const mm = String(Math.floor((total % 3600) / 60)).padStart(2, '0')
  const ss = String(total % 60).padStart(2, '0')
  return h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`
}

/** 47 -> "47 s", 192 -> "3 min 12 s". */
export function duration(seconds: number | null | undefined): string {
  if (seconds == null) return '—'
  if (seconds < 60) return `${seconds} s`
  const minutes = Math.floor(seconds / 60)
  const rest = seconds % 60
  return rest ? `${minutes} min ${rest} s` : `${minutes} min`
}

/**
 * A report's filters in words (Operate -> Reports; palace frontend/08ff3c8d). The list sends its
 * filters in the API's query shape (connection_id, severity…); a stored report holds them in the
 * backend's shape (connection_ids, severities…). Both are described the same way.
 */

export type ReportFilters = Record<string, unknown>

// The backend's stored names, as the list's query names.
const STORED_AS_QUERY: Record<string, string> = {
  connection_ids: 'connection_id',
  severities: 'severity',
  tools: 'tool',
  providers: 'provider',
  regions: 'region',
  services: 'service',
  resource_types: 'resource_type',
  check_ids: 'check_id',
  categories: 'category',
  statuses: 'status',
  reaches: 'reach',
}

/** A stored report's filters in the list's query shape. */
export function fromStored(stored: ReportFilters): ReportFilters {
  return Object.fromEntries(Object.entries(stored).map(([k, v]) => [STORED_AS_QUERY[k] ?? k, v]))
}

const STATES: Record<string, string> = { reopened: 'Reopened', resolved: 'Resolved', accepted_risk: 'Accepted risk' }
const TOOLS: Record<string, string> = { prowler: 'Prowler', cloudfox: 'CloudFox' }

function list(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : []
}

function capital(word: string): string {
  return word.slice(0, 1).toUpperCase() + word.slice(1)
}

/** "one value" or "N <plural>". */
function counted(values: string[], plural: string): string | null {
  const [first] = values
  if (first === undefined) return null
  return values.length === 1 ? first : `${values.length} ${plural}`
}

/** The filters as a short phrase, e.g. "Critical, High · demo-0 · first seen from 2026-10-01". */
export function describe(filters: ReportFilters, accountName: (id: number) => string): string {
  const f = filters
  const words: (string | null)[] = []
  const severity = list(f.severity)
  if (severity.length) words.push(severity.map(capital).join(', '))
  const accounts = list(f.connection_id).map(Number)
  const [account] = accounts
  if (accounts.length === 1 && account !== undefined) words.push(accountName(account))
  else if (accounts.length > 1) words.push(`${accounts.length} accounts`)
  const tools = list(f.tool).flatMap((t) => TOOLS[t] ?? [])
  if (tools.length === 1) words.push(tools[0] ?? null)
  const state = typeof f.state === 'string' ? STATES[f.state] : undefined
  if (state) words.push(state)
  words.push(counted(list(f.region), 'regions'))
  words.push(counted(list(f.service), 'services'))
  words.push(counted(list(f.resource_type), 'resource types'))
  words.push(counted(list(f.check_id), 'checks'))
  words.push(counted(list(f.category), 'categories'))
  const status = list(f.status)
  if (status.length === 1) words.push(status[0] === 'MANUAL' ? 'Manual' : 'Fail')
  const reach = list(f.reach)
  if (reach.length) words.push(`reach: ${reach.join(', ').replaceAll('_', ' ')}`)
  if (f.muted === 'hide') words.push('not muted')
  if (f.muted === 'only') words.push('muted only')
  if (f.new === true) words.push('new')
  if (typeof f.first_seen_from === 'string' && f.first_seen_from) words.push(`first seen from ${f.first_seen_from}`)
  if (typeof f.first_seen_to === 'string' && f.first_seen_to) words.push(`first seen to ${f.first_seen_to}`)
  if (typeof f.resource_id === 'number') words.push('one resource')
  if (typeof f.q === 'string' && f.q) words.push(`“${f.q}”`)
  if (f.exploitable === true) words.push('public exploit')
  if (f.fix === 'available') words.push('fix available')
  if (f.fix === 'none') words.push('no fix yet')
  const shown = words.filter((w): w is string => w !== null)
  return shown.length ? shown.join(' · ') : 'All open'
}

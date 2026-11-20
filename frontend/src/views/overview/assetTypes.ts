/**
 * Assets by category (round 5, 2026-11-10; spec in the palace, frontend/1d636dd5): the one
 * taxonomy the Overview's Inventory card and the Resources Summary share.
 */

import { PROVIDERS } from '@/providers'

export interface TypeGroup {
  name: string
  color: string
  count: number
  types: string[]
}

export const OTHER = 'Other'
// One colour for every category (owner, 2026-11-10, decisions/1bdf306b): a category's bar is one
// measure, its asset count, so length carries it and the name tells categories apart. The
// inventory is Steampipe's, so its fixed tool colour, as the Summary's other inventory bars.
// Other is the rest, in the muted grey.
const CATEGORY_COLOR = 'var(--tool-steampipe)'
const OTHER_COLOR = 'var(--muted)'

// The categories' display order, Other last. Which category a type is in is the backend's
// (metrics.categories, the one taxonomy the screens and the PDF reports share): every row the
// API sends carries it. A category this list does not name yet goes just before Other.
export const CATEGORIES = ['Compute', 'Containers', 'Storage', 'Database', 'Network', 'Identity', 'Security', 'Analytics', 'Integration', 'Management', OTHER]

/** A count of one type, with the category the API gives it. */
export interface TypeCount {
  type: string
  count: number
  category: string | null
}

const order = (name: string) => {
  const i = CATEGORIES.indexOf(name)
  return i === -1 ? CATEGORIES.length - 1.5 : i
}

/** The types grouped by category, in the fixed order, empty categories left out. */
export function groupTypes(byType: TypeCount[]): TypeGroup[] {
  const groups = new Map<string, TypeGroup>()
  for (const { type, count, category } of byType) {
    const name = category ?? OTHER
    const entry = groups.get(name) ?? { name, color: name === OTHER ? OTHER_COLOR : CATEGORY_COLOR, count: 0, types: [] }
    entry.count += count
    entry.types.push(type)
    groups.set(name, entry)
  }
  return [...groups.values()].filter((g) => g.count > 0).sort((a, b) => order(a.name) - order(b.name))
}

/** Largest first, Other always last. */
export function bySize(groups: TypeGroup[]): TypeGroup[] {
  return [...groups].sort((a, b) => Number(a.name === OTHER) - Number(b.name === OTHER) || b.count - a.count)
}

export interface ProviderInventory {
  id: string
  name: string
  covered: boolean
  /** null when the provider is covered but has no inventory scan yet. */
  total: number | null
  /** Largest first, Other always last. */
  groups: TypeGroup[]
}

/** Splits the Steampipe types by their provider prefix (aws_, gcp_, oci_), then groups each. */
export function byProvider(byType: TypeCount[], coverage: Record<string, string>): ProviderInventory[] {
  return PROVIDERS.map(({ id, name }) => {
    const groups = bySize(groupTypes(byType.filter((t) => t.type.startsWith(`${id}_`))))
    const total = groups.reduce((n, g) => n + g.count, 0)
    return { id, name, covered: coverage[id] === 'covered', total: groups.length ? total : null, groups }
  })
}

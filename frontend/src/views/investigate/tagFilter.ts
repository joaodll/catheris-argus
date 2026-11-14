/**
 * The Tag filter (migration 0051; spec in the palace, frontend/27ceefe0): pairs of a tag's name and
 * one of its values. In the URL and the API each pair is a JSON array ["name", "value"], one per
 * value: AWS allows "=", ":" and "/" in both, so no separator would do. Values of one name are OR,
 * names are AND.
 */
import type { LocationQuery } from 'vue-router'

export type TagPair = [string, string]

const KEY_MAX = 128 // as AWS, and the API
const VALUE_MAX = 256
const PAIRS_MAX = 50 // as the API: at most 50 values per filter

function pair(raw: unknown): TagPair | null {
  if (typeof raw !== 'string') return null
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return null
  }
  if (!Array.isArray(parsed) || parsed.length !== 2) return null
  const [key, value] = parsed as unknown[]
  if (typeof key !== 'string' || typeof value !== 'string') return null
  if (key.length < 1 || key.length > KEY_MAX || value.length > VALUE_MAX) return null
  return [key, value]
}

/** ?tag=: the valid pairs, each once, at most 50. Anything else is ignored, never sent. */
export function parseTags(value: LocationQuery[string] | undefined): TagPair[] {
  const all = Array.isArray(value) ? value : value == null ? [] : [value]
  const out: TagPair[] = []
  const seen = new Set<string>()
  for (const raw of all) {
    const p = pair(raw)
    if (!p) continue
    const id = JSON.stringify(p)
    if (seen.has(id)) continue
    seen.add(id)
    out.push(p)
  }
  return out.slice(0, PAIRS_MAX)
}

/** The pairs as the URL and the API carry them. */
export function tagParams(tags: TagPair[]): string[] {
  return tags.map((p) => JSON.stringify(p))
}

/** Each name once, in the order first chosen, with its values. */
export function byName(tags: TagPair[]): { key: string; values: string[] }[] {
  const grouped = new Map<string, string[]>()
  for (const [key, value] of tags) grouped.set(key, [...(grouped.get(key) ?? []), value])
  return [...grouped].map(([key, values]) => ({ key, values }))
}

/** The pairs with one name's values replaced (none: the name is removed), its place kept. */
export function withValues(tags: TagPair[], key: string, values: string[]): TagPair[] {
  const groups = byName(tags)
  const mine = { key, values: [...new Set(values)] }
  const at = groups.findIndex((g) => g.key === key)
  if (at < 0) groups.push(mine)
  else groups[at] = mine
  return groups.flatMap((g) => g.values.map((v): TagPair => [g.key, v])).slice(0, PAIRS_MAX)
}

/** One name's filter in words: "Team = payments or billing"; over three values, "Team = a or 3 more". */
export function tagWords(key: string, values: string[]): string {
  const shown = values.length > 3 ? `${values[0]} or ${values.length - 1} more` : values.join(' or ')
  return `${key} = ${shown}`
}

export const TAG_KEY_MAX = KEY_MAX
export const TAG_VALUE_MAX = VALUE_MAX

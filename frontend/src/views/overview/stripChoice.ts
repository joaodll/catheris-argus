/**
 * Which framework the Overview's strip shows (docs/ui/screens.md, "ThreatScore strip: choosing
 * the framework"; 2026-10-15). '' is the ThreatScore, the default. The URL holds the choice
 * (`?strip=`), and this browser keeps the last one in localStorage, which can be missing or
 * throw (private windows, blocked storage): the strip then opens on the ThreatScore.
 */
import type { LocationQuery } from 'vue-router'

const KEY = 'argus.overview.strip'
const FRAMEWORK_KEY = /^[A-Za-z0-9_.-]{1,200}$/ // as the API's {framework} path parameter

function valid(value: unknown): string {
  return typeof value === 'string' && FRAMEWORK_KEY.test(value) ? value : ''
}

export function parseStrip(value: LocationQuery[string] | undefined): string {
  return valid(Array.isArray(value) ? value[0] : value)
}

export function loadStrip(): string {
  try {
    return valid(localStorage.getItem(KEY))
  } catch {
    return ''
  }
}

export function saveStrip(key: string): void {
  try {
    if (key) localStorage.setItem(KEY, key)
    else localStorage.removeItem(KEY)
  } catch {
    // Storage unavailable: the choice lasts as long as the URL.
  }
}

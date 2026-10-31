// @vitest-environment node
/**
 * The contrast rules of design-system.md ("Light theme"), checked on the real tokens in both
 * themes: text at least 4.5:1 and graphics at least 3:1 on every surface, a severity word over
 * its colour's 12% tint at least 4.5:1, a heatmap cell's text over its score band's 16% tint at
 * least 4.5:1, and digits on filled marks at least 4.5:1.
 */
/// <reference types="node" />
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

// Read from disk: the test runner handles CSS imports itself, and they arrive empty.
const tokensCss = readFileSync(new URL('./tokens.css', import.meta.url), 'utf8')

type Tokens = Record<string, string>

/** The declarations of the first block that starts with this selector. */
function block(selector: string): Tokens {
  const start = tokensCss.indexOf(`${selector} {`)
  if (start === -1) throw new Error(`no ${selector} block in tokens.css`)
  const body = tokensCss.slice(tokensCss.indexOf('{', start) + 1, tokensCss.indexOf('\n}', start))
  const out: Tokens = {}
  for (const m of body.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/--([a-z0-9-]+):\s*([^;]+);/g)) out[m[1]!] = m[2]!.trim()
  return out
}

const dark = block(':root')
const light = { ...dark, ...block(":root[data-theme='light']") }

/** A token's colour as #rrggbb, following var() aliases. */
function hex(theme: Tokens, name: string): string {
  let value = theme[name]
  for (let i = 0; value?.startsWith('var(') && i < 5; i++) value = theme[value.slice(6, -1)]
  if (!value || !/^#[0-9a-f]{6}$/i.test(value)) throw new Error(`--${name} is not a #rrggbb colour: ${value}`)
  return value.toLowerCase()
}

function luminance(h: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(h.slice(i, i + 2), 16) / 255
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  })
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!
}

function ratio(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi! + 0.05) / (lo! + 0.05)
}

/** fg laid over bg at this opacity. */
function mix(fg: string, bg: string, alpha: number): string {
  const ch = (h: string, i: number) => parseInt(h.slice(i, i + 2), 16)
  return `#${[1, 3, 5].map((i) => Math.round(ch(fg, i) * alpha + ch(bg, i) * (1 - alpha)).toString(16).padStart(2, '0')).join('')}`
}

const SURFACES = ['bg', 'surface', 'surface-raised', 'surface-sunken', 'tile']
const TEXT = ['text', 'text-2', 'text-3', 'text-chip', 'link', 'pass', 'delta-worse', 'delta-better', 'delta-flat', 'score-good', 'score-fair', 'score-weak', 'score-poor', 'tool-prowler', 'tool-steampipe', 'tool-cloudfox', 'tool-vulnerabilities']
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const GRAPHICS = ['border-control', 'muted', 'accent', 'pass', 'provider-aws', 'provider-gcp', 'provider-oci', 'type-compute', 'type-identity', 'type-storage', 'type-network', 'type-other', ...SEVERITIES.map((s) => `sev-${s}`)]

describe.each([
  ['dark', dark],
  ['light', light],
])('%s theme contrast', (_, theme) => {
  it('text tokens reach 4.5:1 on every surface', () => {
    const failing = [...TEXT, ...SEVERITIES.map((s) => `sev-${s}-text`)].flatMap((t) =>
      SURFACES.filter((s) => ratio(hex(theme, t), hex(theme, s)) < 4.5).map((s) => `${t} on ${s}: ${ratio(hex(theme, t), hex(theme, s)).toFixed(2)}`),
    )
    expect(failing).toEqual([])
  })

  it('graphics reach 3:1 on every surface', () => {
    const failing = GRAPHICS.flatMap((g) => SURFACES.filter((s) => ratio(hex(theme, g), hex(theme, s)) < 3).map((s) => `${g} on ${s}: ${ratio(hex(theme, g), hex(theme, s)).toFixed(2)}`))
    expect(failing).toEqual([])
  })

  it('a severity word reads over its own tint', () => {
    const failing = SEVERITIES.flatMap((sev) =>
      ['surface', 'surface-raised'].filter((s) => ratio(hex(theme, `sev-${sev}-text`), mix(hex(theme, `sev-${sev}`), hex(theme, s), 0.12)) < 4.5).map((s) => `sev-${sev}-text over its tint on ${s}`),
    )
    expect(failing).toEqual([])
  })

  it('a status word reads over its own tint (status badges)', () => {
    const failing = ['status-ok', 'status-fail', 'status-warn', 'status-run'].flatMap((st) =>
      ['surface', 'surface-raised'].filter((s) => ratio(hex(theme, st), mix(hex(theme, st), hex(theme, s), 0.12)) < 4.5).map((s) => `${st} over its tint on ${s}`),
    )
    expect(failing).toEqual([])
  })

  it('a heatmap cell reads over its score band (Accounts, month over month)', () => {
    const failing = ['score-poor', 'score-weak', 'score-fair', 'score-good'].flatMap((band) =>
      ['text', 'delta-better', 'delta-worse', 'delta-flat']
        .filter((t) => ratio(hex(theme, t), mix(hex(theme, band), hex(theme, 'surface'), 0.16)) < 4.5)
        .map((t) => `${t} over ${band} at 16 %`),
    )
    expect(failing).toEqual([])
  })

  it('digits on filled marks reach 4.5:1', () => {
    const failing = SEVERITIES.filter((sev) => ratio(hex(theme, 'on-sev'), hex(theme, `sev-${sev}`)) < 4.5).map((sev) => `on-sev on sev-${sev}`)
    if (ratio(hex(theme, 'on-accent'), hex(theme, 'accent')) < 4.5) failing.push('on-accent on accent')
    expect(failing).toEqual([])
  })
})

/**
 * Prowler writes its check text in a little Markdown: **bold**, *italic*, `code`, and line
 * breaks. It is shown as text with those three marks and nothing else: the segments become
 * Vue elements, never HTML, so tool output cannot inject markup.
 */

export type Segment = { kind: 'text' | 'strong' | 'em' | 'code'; value: string }

const MARKS = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\*[^*\n]+\*)/g

export function toolText(text: string): Segment[] {
  const segments: Segment[] = []
  let last = 0
  for (const match of text.matchAll(MARKS)) {
    const token = match[0]
    const at = match.index ?? 0
    if (at > last) segments.push({ kind: 'text', value: text.slice(last, at) })
    if (token.startsWith('`')) segments.push({ kind: 'code', value: token.slice(1, -1) })
    else if (token.startsWith('**')) segments.push({ kind: 'strong', value: token.slice(2, -2) })
    else segments.push({ kind: 'em', value: token.slice(1, -1) })
    last = at + token.length
  }
  if (last < text.length) segments.push({ kind: 'text', value: text.slice(last) })
  return segments
}

/** A code snippet without its Markdown fence (```yaml … ```), and the fence's language. */
export function codeBody(value: string): { lang: string | null; body: string } {
  const fenced = value.trim().match(/^```([\w+-]*)\n([\s\S]*?)\n?```$/)
  return fenced ? { lang: fenced[1] || null, body: fenced[2] ?? '' } : { lang: null, body: value.trim() }
}

/** The kinds of remediation code, in the order a reader most often wants them. */
export const CODE_KINDS = [
  { key: 'cli', label: 'AWS CLI' },
  { key: 'terraform', label: 'Terraform' },
  { key: 'native_iac', label: 'CloudFormation' },
] as const

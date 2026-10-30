export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const
export type Severity = (typeof SEVERITIES)[number]

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
}

/** For words in a severity colour (a tag's label): readable on every surface and tint. */
export const SEVERITY_TEXT: Record<Severity, string> = {
  critical: 'var(--sev-critical-text)',
  high: 'var(--sev-high-text)',
  medium: 'var(--sev-medium-text)',
  low: 'var(--sev-low-text)',
  informational: 'var(--sev-info-text)',
}

/** For marks: squares, fills, chart series, badges. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  informational: 'var(--sev-info)',
}

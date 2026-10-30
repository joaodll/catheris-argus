/** How sure Argus is of an attack path (ADR-0037; docs/ui/screens.md, E12). Weakest first. */
export const CONFIDENCES = ['blocked', 'unknown', 'candidate', 'supported', 'confirmed'] as const
export type Confidence = (typeof CONFIDENCES)[number]

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  confirmed: 'Confirmed',
  supported: 'Supported',
  candidate: 'Candidate',
  unknown: 'Unknown',
  blocked: 'Blocked',
}

/** What a level means, for a path or a filter option. */
export const CONFIDENCE_MEANING: Record<Confidence, string> = {
  confirmed: 'Analysed: Argus checked the internet entry, or CloudFox analysed the policies.',
  supported: 'The configuration is there; IAM conditions, SCPs and boundaries are not evaluated.',
  candidate: "One tool's claim, or an assumption Argus cannot check (a key, a trust condition).",
  unknown: 'Data Argus needs to judge a step is missing.',
  blocked: 'Latent: Argus found the entry closed. One change (a route, an ACL, a public address) would open this path.',
}

/** "Confidence: Supported, the weakest step." for a path; null for one found before 2026-10-10. */
export function confidenceLine(level: Confidence | null | undefined): string | null {
  return level ? `${CONFIDENCE_LABEL[level]}, its weakest step. ${CONFIDENCE_MEANING[level]}` : null
}

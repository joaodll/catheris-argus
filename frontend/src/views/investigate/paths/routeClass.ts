/**
 * How sure Argus is of an attack route, and of each of its steps (ADR-0052 §5; spec W6 §1.1).
 * Two vocabularies that never share a word: a route's class (derived, the badge) and a step's
 * level (stored, a small word). Weakest first, as the API ranks them.
 */
import type { IconName } from '@/components/icons'

export const ROUTE_CLASSES = ['blocked', 'unknown', 'potential', 'conditional', 'confirmed'] as const
export type RouteClass = (typeof ROUTE_CLASSES)[number]

export const CLASS_LABEL: Record<RouteClass, string> = {
  confirmed: 'Confirmed',
  conditional: 'Conditional',
  potential: 'Potential',
  unknown: 'Not enough data',
  blocked: 'Latent',
}

export const CLASS_MEANING: Record<RouteClass, string> = {
  confirmed: 'Every step is checked or configured. SCPs and permission boundaries are not evaluated.',
  conditional: "One step is an assumption Argus can't check, such as a foothold or a trust condition.",
  potential: 'Two or more assumptions, or a foothold with no evidence.',
  unknown: 'Data Argus needs to judge a step is missing.',
  blocked: 'Argus found a step closed. One change would open this route.',
}

export const CLASS_ICON: Record<RouteClass, IconName> = {
  confirmed: 'check',
  conditional: 'half',
  potential: 'dot',
  unknown: 'info',
  blocked: 'blocked',
}

export const STEP_LEVELS = ['blocked', 'unknown', 'candidate', 'supported', 'confirmed'] as const
export type StepLevel = (typeof STEP_LEVELS)[number]

export const LEVEL_LABEL: Record<StepLevel, string> = {
  confirmed: 'Checked',
  supported: 'Configured',
  candidate: 'Assumed',
  unknown: 'Missing data',
  blocked: 'Closed',
}

export const LEVEL_MEANING: Record<StepLevel, string> = {
  confirmed: 'Argus checked it: the internet entry, or CloudFox analysed the policies.',
  supported: 'The configuration allows it. IAM conditions, SCPs and boundaries are not evaluated.',
  candidate: "One tool's claim, or an assumption Argus can't check.",
  unknown: 'Argus lacks the data to judge this step.',
  blocked: 'Argus found it closed.',
}

/** A route's class is its surest target's (targets are listed most sure first); each target is
 * as sure as its weakest step. "Confidence: Potential, its surest target. Two or more …" */
export function confidenceLine(cls: RouteClass): string {
  return `Confidence: ${CLASS_LABEL[cls]}, its surest target. ${CLASS_MEANING[cls]}`
}

export type Likelihood = 'higher' | 'lower' | 'unknown'

/** How likely, apart from how sure (ADR-0052 §6 A2): the entry's reach, then the footholds. */
export const LIKELIHOOD_LINE: Record<Likelihood, string> = {
  higher: 'How likely: higher. Argus checked that the internet reaches the entry, and every foothold has evidence.',
  lower: "How likely: lower. The entry's reach is not checked, or a foothold has no evidence.",
  unknown: "How likely: unknown. Argus can't tell whether the internet reaches the entry.",
}

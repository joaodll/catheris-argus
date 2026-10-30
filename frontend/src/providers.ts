/** The clouds Argus knows, in display order. Only AWS is covered yet: GCP and OCI come after
 * Kubernetes (CLAUDE.md, Status), as the backend's Overview coverage says (metrics/overview.py). */
export const PROVIDERS = [
  { id: 'aws', name: 'AWS', covered: true },
  { id: 'gcp', name: 'GCP', covered: false },
  { id: 'oci', name: 'OCI', covered: false },
] as const

export type Provider = (typeof PROVIDERS)[number]['id']

export function providerName(id: string): string {
  return PROVIDERS.find((p) => p.id === id)?.name ?? id.toUpperCase()
}

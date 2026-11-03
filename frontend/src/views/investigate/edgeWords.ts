/**
 * One plain word for each kind of connection (round M3a; the spec is in the palace, frontend):
 * what a Resource map line says, and the base of an attack-path step's short words
 * (paths/pathWords.ts adds what it knows from the step's evidence). Neutral words: a line on the
 * map is a dependency, not a judgement. An unknown type reads as itself, lower case.
 */

const WORDS: Record<string, string> = {
  ROUTES_TO: 'routes to',
  TRIGGERS: 'triggers',
  INTERNET_REACHABLE: 'reaches',
  // Drawn only as a step of a highlighted attack path: the map's layers leave them out.
  PUBLIC_RESTRICTED: 'kept out',
  PUBLIC_UNVERIFIED: 'may reach',
  RUNS_AS: 'runs as',
  CAN_ASSUME: 'can assume',
  IS_ADMIN: 'is administrator',
  CAN_PRIVESC_TO: 'can escalate',
  CAN_ESCALATE_TO: 'can escalate',
  CAN_CONNECT_TO: 'can connect to',
  CAN_RUN_ON: 'runs commands on',
  BELONGS_TO: 'belongs to',
  OUTSIDER: 'trusted by',
  HAS_CREDENTIAL: 'signs in as',
  MEMBER_OF: 'is in',
  IN_NETWORK: 'in network',
  ALLOWS_INGRESS: 'admits',
  PROTECTED_BY: 'protected by',
  HAS_POLICY: 'has policy',
  ACCESSES: 'accesses',
}

/** The line's word: "routes to". Systems Manager's wildcard (`any:ssm`) is reached through. */
export function edgeWord(type: string, targetUid?: string | null): string {
  if (type === 'CAN_RUN_ON' && targetUid?.startsWith('any:ssm')) return 'can run commands through'
  return WORDS[type] ?? type.toLowerCase().replace(/_/g, ' ')
}

/** The word as a title: "Routes to". */
export function edgeTitle(type: string, targetUid?: string | null): string {
  const word = edgeWord(type, targetUid)
  return word.charAt(0).toUpperCase() + word.slice(1)
}

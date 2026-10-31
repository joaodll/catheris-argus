/** What a run left out or how it was kept, in the words the Runs tab uses. */

type Run = { source: string; region_scope: string[]; api_regions?: number | null; raw_encryption?: string | null }

/** KMS keeps a key policy and a decrypt audit trail (ADR-0031); anything else is flagged. */
export function storedWithoutKms(run: Pick<Run, 'raw_encryption'>): boolean {
  return run.raw_encryption != null && run.raw_encryption !== 'aws:kms' && run.raw_encryption !== 'aws:kms:dsse'
}

export function encryptionLabel(encryption: string): string {
  if (encryption === 'AES256') return 'SSE-S3 (AES256)'
  if (encryption === 'none') return 'not encrypted'
  return encryption
}

/** An AWS run with no listed scope covered every enabled region (CloudFox always does). */
export function regionsLabel(run: Run): string {
  if (run.api_regions != null) return `${run.api_regions} region${run.api_regions === 1 ? '' : 's'}`
  return run.source === 'aws' && run.region_scope.length === 0 ? 'All regions' : '—'
}

/** A run id short enough for a table cell: its first block, as in the bucket's folder name. */
export function shortRunId(runUid: string): string {
  return runUid.slice(0, 8)
}

/** Why Run now skipped a tool on an account. With no cooldown, only a duplicate is refused. */
export function refusedBecause(cooldown: number): string {
  return cooldown > 0 ? `queued, running or ran within the last ${cooldown} minutes` : 'already queued or running'
}

/** The rule under the Run now button, in the cooldown in force. */
export function cooldownNote(cooldown: number): string {
  return cooldown > 0
    ? `A tool that ran on an account in the last ${cooldown} minutes is skipped, to protect the account's API limits.`
    : 'A tool already queued or running on an account is skipped.'
}

type Trigger = { reason: string; origin: string; schedule: string | null; requested_by: string; attempt: number }

/** What started a run, in one line: the schedule (by name), Run now (by whom), or history being
 *  built, and for a retry, which attempt it was. A deleted schedule is said so: its runs are kept. */
export function triggerLabel(trigger: Trigger | null | undefined): string {
  if (!trigger) return 'Not recorded'
  let first: string
  if (trigger.origin === 'schedule') first = trigger.schedule ? `Schedule “${trigger.schedule}”` : 'A schedule since deleted'
  else if (trigger.origin === 'manual') first = `Run now by ${trigger.requested_by}`
  else if (trigger.origin === 'backfill') first = 'Building history'
  else first = 'A retry' // the first attempt is gone
  return trigger.attempt > 1 ? `Retry ${trigger.attempt} of 3 · ${first}` : first
}

/** The tool's command line, or why there is none. */
export function commandLabel(run: { source: string; command: string }): string {
  if (run.command) return run.command
  return run.source === 'synthetic' ? 'None: a Demo connection is generated, no tool runs.' : 'Not recorded: the run ended before the tool started, or ran before Argus recorded it.'
}

/** Why a run without incomplete tables is Partial. Throttling is said first: a denied action
 *  alone leaves a Prowler run complete, so its list below is not the cause there. */
export function partialReason(run: { throttle_events: number; denied_actions: string[] }): string {
  const n = run.throttle_events
  const throttled = n > 0 ? `the tool was throttled ${n} time${n === 1 ? '' : 's'}, so some results may be missing` : ''
  if (throttled && run.denied_actions.length) return `${throttled}, and some data was not readable (below)`
  if (throttled) return throttled
  return run.denied_actions.length ? 'some data was not readable (below)' : 'the tool stopped early'
}

/** The tables that made a run partial: those carried forward, less the ones not used in the
 *  account or refused by a resource, which never make a run partial (ADR-0012, 2026-10-21). */
export function partialTables(run: { incomplete_tables: string[]; not_applicable_tables?: string[]; refused_tables?: string[] }): string[] {
  const apart = new Set([...(run.not_applicable_tables ?? []), ...(run.refused_tables ?? [])])
  return run.incomplete_tables.filter((t) => !apart.has(t))
}

/** What a partial run's failed tables mean, per tool (2026-10-31 review): Steampipe carries
 *  the resources forward; Inspector's one table is its findings export, so nothing resolves. */
export function partialTablesNote(tool: string, count: number): string {
  if (tool === 'inspector') {
    return "Partial: Inspector's findings export failed, was denied or was throttled. No vulnerability was resolved by this run, and those already open stay open."
  }
  return `Partial: ${count} of the tables failed, were denied or were throttled. Their resources were carried forward from the previous scan; every other table is up to date. A partial run is not retried.`
}

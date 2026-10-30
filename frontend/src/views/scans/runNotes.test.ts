import { describe, expect, it } from 'vitest'
import { commandLabel, cooldownNote, encryptionLabel, partialReason, partialTables, refusedBecause, regionsLabel, shortRunId, storedWithoutKms, triggerLabel } from './runNotes'

describe('run notes', () => {
  it('flags raw output stored without KMS only', () => {
    expect(storedWithoutKms({ raw_encryption: 'aws:kms' })).toBe(false)
    expect(storedWithoutKms({ raw_encryption: 'aws:kms:dsse' })).toBe(false)
    expect(storedWithoutKms({ raw_encryption: null })).toBe(false) // the local volume
    expect(storedWithoutKms({ raw_encryption: 'AES256' })).toBe(true)
    expect(encryptionLabel('AES256')).toBe('SSE-S3 (AES256)')
  })

  it('says All regions for an AWS run without a listed scope', () => {
    expect(regionsLabel({ source: 'aws', region_scope: [], api_regions: null })).toBe('All regions')
    expect(regionsLabel({ source: 'aws', region_scope: ['eu-west-1'], api_regions: 1 })).toBe('1 region')
    expect(regionsLabel({ source: 'synthetic', region_scope: [], api_regions: null })).toBe('—')
  })

  it('shortens a run id to its first block, as the bucket folder starts', () => {
    expect(shortRunId('ef9900b2-b7f1-49fe-8545-13c5aff7210a')).toBe('ef9900b2')
  })

  it('explains Run now refusals by the cooldown in force', () => {
    expect(refusedBecause(0)).toBe('already queued or running')
    expect(refusedBecause(15)).toBe('queued, running or ran within the last 15 minutes')
    expect(cooldownNote(0)).toBe('A tool already queued or running on an account is skipped.')
    expect(cooldownNote(60)).toContain('in the last 60 minutes')
  })

  it('says what started a run, retries included', () => {
    const base = { reason: 'schedule', origin: 'schedule', schedule: 'nightly', requested_by: 'scheduler', attempt: 1 }
    expect(triggerLabel(base)).toBe('Schedule “nightly”')
    expect(triggerLabel({ ...base, reason: 'retry', attempt: 3 })).toBe('Retry 3 of 3 · Schedule “nightly”')
    expect(triggerLabel({ ...base, schedule: null })).toBe('A schedule since deleted')
    expect(triggerLabel({ ...base, reason: 'manual', origin: 'manual', schedule: null, requested_by: 'admin' })).toBe('Run now by admin')
    expect(triggerLabel({ ...base, reason: 'backfill', origin: 'backfill', schedule: null })).toBe('Building history')
    expect(triggerLabel(null)).toBe('Not recorded')
  })

  it('shows the command, or why there is none', () => {
    expect(commandLabel({ source: 'aws', command: 'prowler aws --profile argus' })).toBe('prowler aws --profile argus')
    expect(commandLabel({ source: 'synthetic', command: '' })).toMatch(/no tool runs/)
    expect(commandLabel({ source: 'aws', command: '' })).toMatch(/^Not recorded/)
  })

  it('names throttling as the reason a run is partial, apart from what was denied', () => {
    expect(partialReason({ throttle_events: 3, denied_actions: ['glue:GetDevEndpoints'] })).toBe(
      'the tool was throttled 3 times, so some results may be missing, and some data was not readable (below)',
    )
    expect(partialReason({ throttle_events: 1, denied_actions: [] })).toBe('the tool was throttled 1 time, so some results may be missing')
    expect(partialReason({ throttle_events: 0, denied_actions: ['s3:GetBucketPolicy'] })).toBe('some data was not readable (below)')
    expect(partialReason({ throttle_events: 0, denied_actions: [] })).toBe('the tool stopped early')
  })

  it('leaves tables not used in the account, or refused by a resource, out of the partial ones', () => {
    expect(
      partialTables({
        incomplete_tables: ['aws_ec2_instance', 'aws_kms_key_rotation', 'aws_timestreamwrite_table'],
        not_applicable_tables: ['aws_timestreamwrite_table'],
        refused_tables: ['aws_kms_key_rotation'],
      }),
    ).toEqual(['aws_ec2_instance'])
    expect(partialTables({ incomplete_tables: ['aws_ec2_instance'] })).toEqual(['aws_ec2_instance'])
  })
})

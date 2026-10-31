/** The raw output storage form's checks: the API's own rules (settings/topics.py), said per field
 *  before anything is sent, so a typo never comes back as a bare 422. */

import { COLLECTOR_IDS, type Collector } from '@/tools'

export type Tool = Collector
export interface RawStorageForm {
  bucket: string
  region: string
  prefixes: Record<Tool, string>
}
export type FieldErrors = Partial<Record<'bucket' | 'region' | Tool, string>>

const BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/
const REGION = /^[a-z]{2}(-[a-z]+)+-[0-9]$/
const FOLDER = /^[A-Za-z0-9_-]+(\/[A-Za-z0-9_-]+)*$/
const MAX_FOLDER = 200

/** What people paste for a bucket, reduced to its name: "s3://my-bucket/", an S3 ARN. */
export function bucketName(value: string): string {
  return value.trim().replace(/^s3:\/\//i, '').replace(/^arn:aws[a-z-]*:s3:::/i, '').replace(/\/+$/, '')
}

/** A folder without the slashes at either end, which S3 keys do not need. */
export function folderName(value: string): string {
  return value.trim().replace(/^\/+|\/+$/g, '')
}

export function normalized(form: RawStorageForm): RawStorageForm {
  return {
    bucket: bucketName(form.bucket),
    region: form.region.trim(),
    prefixes: Object.fromEntries(COLLECTOR_IDS.map((t) => [t, folderName(form.prefixes[t])])) as Record<Tool, string>,
  }
}

/** Each field's problem, in words; empty when the form can be saved. */
export function checkRawStorage(form: RawStorageForm): FieldErrors {
  const errors: FieldErrors = {}
  const { bucket, region, prefixes } = form
  if (bucket.includes('/')) errors.bucket = 'Enter the bucket name only: the folders are set below.'
  else if (bucket && !BUCKET.test(bucket)) {
    errors.bucket = 'A bucket name is 3 to 63 lowercase letters, digits, dots and hyphens, starting and ending with a letter or digit.'
  }
  if (region && !REGION.test(region)) errors.region = 'A region looks like eu-west-1 (no availability zone letter).'
  if (bucket && !region && !errors.bucket) errors.region = 'Enter the bucket’s region too.'
  if (region && !bucket && !errors.region) errors.bucket = 'Enter the bucket too, or clear the region.'
  for (const tool of Object.keys(prefixes) as Tool[]) {
    const folder = prefixes[tool]
    if (!folder) errors[tool] = 'Enter a folder, for example raw/' + tool + '.'
    else if (folder.length > MAX_FOLDER) errors[tool] = `At most ${MAX_FOLDER} characters.`
    else if (!FOLDER.test(folder)) errors[tool] = 'Letters, digits, - and _, in parts separated by /. No dots or spaces.'
  }
  return errors
}

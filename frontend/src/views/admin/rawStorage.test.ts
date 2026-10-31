import { describe, expect, it } from 'vitest'
import { bucketName, checkRawStorage, folderName, normalized, type RawStorageForm } from './rawStorage'

const ok: RawStorageForm = {
  bucket: 'argus-raw',
  region: 'eu-west-1',
  prefixes: { steampipe: 'raw/steampipe', prowler: 'raw/prowler', cloudfox: 'raw/cloudfox', inspector: 'raw/inspector' },
}

describe('raw output storage checks', () => {
  it('accepts the defaults and a bucket turned off', () => {
    expect(checkRawStorage(ok)).toEqual({})
    expect(checkRawStorage({ ...ok, bucket: '', region: '' })).toEqual({})
  })

  it('reduces what people paste to a bucket name and folders without end slashes', () => {
    expect(bucketName(' s3://argus-raw/ ')).toBe('argus-raw')
    expect(bucketName('arn:aws:s3:::argus-raw')).toBe('argus-raw')
    expect(folderName('/raw/prowler/')).toBe('raw/prowler')
    expect(checkRawStorage(normalized({ ...ok, bucket: 's3://argus-raw/', prefixes: { ...ok.prefixes, prowler: 'raw/prowler/' } }))).toEqual({})
  })

  it('says per field what the API would refuse', () => {
    const errors = checkRawStorage({
      bucket: 'Argus_Raw',
      region: 'us-east-1a',
      prefixes: { steampipe: 'raw/steam pipe', prowler: '', cloudfox: 'raw/../x', inspector: 'raw/inspector' },
    })
    expect(Object.keys(errors).sort()).toEqual(['bucket', 'cloudfox', 'prowler', 'region', 'steampipe'])
    expect(checkRawStorage({ ...ok, bucket: 'argus-raw/raw' }).bucket).toMatch(/bucket name only/)
    expect(checkRawStorage({ ...ok, region: '' }).region).toMatch(/region too/)
    expect(checkRawStorage({ ...ok, bucket: '' }).bucket).toMatch(/clear the region/)
  })
})

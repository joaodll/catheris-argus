# Suggested AWS policies

**Owner:** `cloud-native-platform-engineer` (policies) · `documentation-writer` (document)
**Applies to:** Argus 0.1.4 (2026-11-04)

These are the permissions for the three resources Argus needs in your platform account: the IAM role
for its service account, the KMS key and the S3 bucket. Copy them and adapt them to your own rules.
They have not been applied to a real AWS account yet: [check them with Test connection](#check-them).

This page does not cover the read-only role in each scanned account. That is
[`deploy/aws/scanner-role.yaml`](../deploy/aws/scanner-role.yaml), described in
[Connecting AWS accounts](connect-aws.md).

| Resource | Policy | Required? |
| --- | --- | --- |
| [IAM role for the service account](#the-iam-role-for-the-service-account) | Permissions and a trust policy | Yes. Without it, AWS scans can't start |
| [KMS key](#the-kms-key) | Key policy | Recommended. Without a key, runs are stored with the bucket's own encryption and flagged **No KMS** |
| [S3 bucket](#the-s3-bucket) | Bucket policy and settings | The bucket is required. The policy is recommended |
| [Role for reading raw output](#a-role-for-reading-raw-output) | Permissions | Optional. Only for people who need to read raw output |

Replace these in every policy:

| Placeholder | What it is |
| --- | --- |
| `ACCOUNT` | The account holding the role, key and bucket. These policies assume all three are in one account |
| `REGION` | The region of the key and the bucket, which must be the same |
| `BUCKET` | The bucket's name |
| `KEY_ID` | The KMS key's id |
| `argus-platform` | The name you give the role for the service account |
| `argus-key-admin` | The role of whoever manages the key |
| `argus-raw-reader` | The role of whoever may read raw output |

## What Argus does in AWS

These facts decide the policies:

- **It only uploads.** It calls `s3:PutObject`, one object at a time, and never reads from the bucket.
  So it needs `kms:GenerateDataKey` and not `kms:Decrypt`.
- **It sends no encryption headers.** It relies on the bucket's default encryption.
- **It writes to four folders**, one per tool. You can rename them in
  **Settings → Raw output storage**; if you do, change them in the role's policy too.
- **It assumes a role in each scanned account**, and calls nothing else in AWS itself. The tools run
  in the same pod and can read its token, which is why this role is kept so small.

## The IAM role for the service account

Only the service account `<release>-run` has a cloud identity, `argus-run` for a release named
`argus`. Only scan Jobs and connection tests use it, and no other pod holds an AWS identity.

### Permissions

This policy is the only control on where raw output goes, because the bucket is a setting in the UI,
so don't make it broader.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ArgusRawOutput",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": [
        "arn:aws:s3:::BUCKET/raw/steampipe/*",
        "arn:aws:s3:::BUCKET/raw/prowler/*",
        "arn:aws:s3:::BUCKET/raw/cloudfox/*",
        "arn:aws:s3:::BUCKET/raw/vulnerabilities/*"
      ]
    },
    {
      "Sid": "ArgusRawOutputKey",
      "Effect": "Allow",
      "Action": "kms:GenerateDataKey",
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID",
      "Condition": {"StringEquals": {"kms:ViaService": "s3.REGION.amazonaws.com"}}
    },
    {
      "Sid": "ArgusAssumeScannerRoles",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/ArgusScanner"
    }
  ]
}
```

To narrow it, replace `*` in the last statement with your account ids, one ARN per account. A role in
another account can only be assumed if its own trust policy names this role, so this statement grants
nothing in an account you haven't prepared.

### Trust policy

Use one of these on Kubernetes. They assume the namespace `argus` and the release `argus`. On Docker
Compose there is no service account: the identity is credentials you enter in
**Settings → Platform identity**, and they need the permissions above.

**IRSA**, the chart's default. Put the role's ARN in `identity.roleArn`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/oidc.eks.REGION.amazonaws.com/id/PROVIDER_ID"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.REGION.amazonaws.com/id/PROVIDER_ID:sub": "system:serviceaccount:argus:argus-run",
          "oidc.eks.REGION.amazonaws.com/id/PROVIDER_ID:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
```

**EKS Pod Identity.** Set `identity.mode: podIdentity`, and create the association for the namespace
and the service account outside the chart:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "pods.eks.amazonaws.com"},
      "Action": ["sts:AssumeRole", "sts:TagSession"],
      "Condition": {
        "StringEquals": {"aws:SourceAccount": "ACCOUNT"},
        "ArnEquals": {"aws:SourceArn": "arn:aws:eks:REGION:ACCOUNT:cluster/CLUSTER"}
      }
    }
  ]
}
```

## The KMS key

Use a symmetric customer-managed key for this bucket alone, in the bucket's region, with rotation on.
Raw output can hold secret values found in your accounts, and a key of your own adds a key policy and
a decrypt audit trail.

With this policy, Argus can only encrypt, and only through S3 for this bucket. Whoever manages the key
can't decrypt. The first statement keeps the key recoverable if `argus-key-admin` is lost: an IAM
administrator could use it to change the key policy, and that change appears in CloudTrail.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AccountCanRecoverTheKeyButNotUseIt",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:root"},
      "Action": ["kms:Describe*", "kms:Get*", "kms:List*", "kms:PutKeyPolicy"],
      "Resource": "*"
    },
    {
      "Sid": "KeyAdministration",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/argus-key-admin"},
      "Action": [
        "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
        "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource",
        "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
        "kms:RotateKeyOnDemand"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ArgusEncryptsThroughS3Only",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/argus-platform"},
      "Action": "kms:GenerateDataKey",
      "Resource": "*",
      "Condition": {
        "StringEquals": {"kms:ViaService": "s3.REGION.amazonaws.com"},
        "StringLike": {"kms:EncryptionContext:aws:s3:arn": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"]}
      }
    },
    {
      "Sid": "NamedPeopleDecryptThroughS3Only",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/argus-raw-reader"},
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEquals": {"kms:ViaService": "s3.REGION.amazonaws.com"},
        "StringLike": {"kms:EncryptionContext:aws:s3:arn": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"]}
      }
    }
  ]
}
```

## The S3 bucket

### Settings

- **Use it for Argus alone**, because raw output maps your whole account.
- **Block Public Access:** on.
- **Object Ownership:** bucket owner enforced.
- **Default encryption:** SSE-KMS with the key above.
- **S3 Bucket Keys:** off. They reduce KMS calls and, with them, the per-object audit trail. Argus writes
  little, so per-object audit costs little.
- **Versioning:** on, because `PutObject` can overwrite older raw output.
- **Lifecycle:** expire objects after 365 days and older versions after 30 days, and stop incomplete
  uploads after 7 days. Argus never deletes from the bucket.

### Bucket policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyWithoutTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    },
    {
      "Sid": "OnlyArgusWrites",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::BUCKET/*",
      "Condition": {"StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::ACCOUNT:role/argus-platform"}}
    },
    {
      "Sid": "OnlyNamedPeopleReadOrDelete",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:DeleteObject", "s3:DeleteObjectVersion"],
      "Resource": "arn:aws:s3:::BUCKET/*",
      "Condition": {"StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::ACCOUNT:role/argus-raw-reader"}}
    },
    {
      "Sid": "DenyAskingForOtherEncryption",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::BUCKET/*",
      "Condition": {
        "Null": {"s3:x-amz-server-side-encryption": "false"},
        "StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}
      }
    },
    {
      "Sid": "DenyAskingForAnotherKey",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::BUCKET/*",
      "Condition": {
        "Null": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "false"},
        "StringNotEquals": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"}
      }
    }
  ]
}
```

- **Keep the `Null` lines.** A bucket policy sees the request, not the stored object, and Argus sends no
  encryption header. Without those lines, or with `StringNotEqualsIfExists`, every Argus upload is
  denied.
- **With an access key as the identity** instead of a role, add that IAM user's ARN to `OnlyArgusWrites`,
  or Test connection fails.
- **You can't lock yourself out.** No statement denies `s3:PutBucketPolicy`, so an administrator can always
  edit this policy, and that edit appears in CloudTrail.

## A role for reading raw output

Argus never uses this role. It is for the people who may read raw output, which can hold secret values.
The bucket policy only denies, and the key policy only covers KMS, so the role needs its own
permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListRawOutput",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::BUCKET"
    },
    {
      "Sid": "ReadRawOutput",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:GetObjectVersion"],
      "Resource": "arn:aws:s3:::BUCKET/*"
    },
    {
      "Sid": "DecryptRawOutput",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID",
      "Condition": {"StringEquals": {"kms:ViaService": "s3.REGION.amazonaws.com"}}
    }
  ]
}
```

## Check them

In **Administration → Settings**, enter the bucket and its region under **Raw output storage**, then run
**Test connection** on the platform identity. It writes a test object to all four folders and reports the
encryption S3 used, which should be `aws:kms`. A run stored without KMS carries a **No KMS** badge in
**Scans → Runs**.

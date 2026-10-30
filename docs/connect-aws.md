# Connecting AWS accounts

**Owner:** `cloud-native-platform-engineer` (procedure) · `documentation-writer` (document)
**Applies to:** Argus 0.1.0 (2026-10-25), on Docker Compose or Kubernetes

Argus scans an AWS account by assuming a **read-only scanner role** in it. This page sets that
up: the identity Argus signs in with, the bucket its raw output goes to, the role in each
account, and the first scan. Argus never changes anything in a scanned account
([security model](security-model.md#read-only-toward-every-cloud)).

## How Argus signs in

Two identities are involved, and they are kept apart:

- **The platform identity** is Argus itself. It does two things only: it assumes the scanner role
  in each account, and it writes raw output to your bucket.
- **The scanner role** lives in each scanned account. It can read configuration and nothing
  else, and it trusts only the platform identity, with an **ExternalId** you choose.

What the platform identity can be depends on where Argus runs:

| Argus runs on | The platform identity | Set in **Settings → Platform identity** |
| --- | --- | --- |
| Kubernetes on EKS | An IAM role, given to the run service account through IRSA ([runbook](runbook-kubernetes.md#the-platform-identity-irsa)) | **Ambient** |
| Docker Compose | Credentials you enter: an IAM role's temporary credentials (an SSO session, for example), or an IAM user's access key | **Access key** |

On Compose the worker blocks the EC2 instance metadata service for every process it runs, so an
instance role is not used even on EC2: enter credentials instead.

The scanner role template trusts a **role** only. If your platform identity is an IAM user's
access key, use access-key connections instead ([below](#without-a-role-access-key-connections)).

## 1. The raw output bucket

Every AWS run writes its raw output, which can hold secret values found in the account, to an S3
bucket you own, and cannot start until one is set. Create it as
[runbook.md, Operating](runbook.md#operating) describes under **Raw output storage for AWS runs**:
a bucket for Argus alone, SSE-KMS, a one-year lifecycle rule, and the policy that lets the
platform identity put objects there and nothing more. Then enter the bucket and its region in
**Administration → Settings → Raw output storage**.

## 2. Let the platform identity assume the scanner role

Besides the bucket policy, the platform identity needs `sts:AssumeRole` on the scanner roles. With
the template's default role name:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ArgusAssumeScannerRoles",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/ArgusScanner"
    }
  ]
}
```

Narrow `*` to a list of account ids if you prefer. A role in another account is only assumed if
that role's own trust policy names the platform identity, so this statement alone grants nothing
in an account you have not prepared.

## 3. Choose an ExternalId

The ExternalId is a value the platform identity must present to assume the role. Use a random
string of at least 16 characters, for example:

```bash
docker compose run --rm --entrypoint python admin-tools -c "import secrets; print(secrets.token_urlsafe(24))"
```

You can use one ExternalId for every account or one per account. Argus stores it write-only: after
you save a connection, the UI shows it as `********`.

## 4. Deploy the scanner role in each account

The role is defined in [`deploy/aws/scanner-role.yaml`](../deploy/aws/scanner-role.yaml), a
CloudFormation template.

| Parameter | Value |
| --- | --- |
| `HubRoleArn` | The platform identity's role ARN: the IRSA role on Kubernetes, or the role behind your temporary credentials on Compose. For an SSO session that is the `AWSReservedSSO_…` role, with its full path (`role/aws-reserved/sso.amazonaws.com/…`). It must be a role |
| `ExternalId` | The value from step 3 (at least 16 characters; not echoed by CloudFormation) |
| `RoleName` | `ArgusScanner` by default |

**What the role grants:** the AWS managed policies `SecurityAudit` and `ViewOnlyAccess`, plus the
read permissions Prowler and CloudFox document beyond them. **What it denies, explicitly:** reading
secret values, parameter values, decryption, object and table contents, and bulk reads of code,
container images and log content ([ADR-0018](adr/0018-scanner-role-denies-code-images-logs.md)).
The Deny stays in force even if AWS widens a managed policy. Argus's build fails if the template
gains any action that is not a read: you can run the same check yourself, and print the policies
it contains:

```bash
docker compose run --rm policy-check
docker compose run --rm policy-check python print_policies.py /work/scanner-role.yaml
```

**One account**, with the AWS CLI and credentials for that account (IAM is global, so the region
does not matter):

```bash
aws cloudformation deploy \
  --template-file deploy/aws/scanner-role.yaml \
  --stack-name argus-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    HubRoleArn=arn:aws:iam::111122223333:role/argus-platform \
    ExternalId='<your ExternalId>'
```

**Many accounts**, with a StackSet from your AWS Organizations management account or a delegated
administrator, deployed to one region of each account in the organizational units you choose:

```bash
aws cloudformation create-stack-set \
  --stack-set-name argus-scanner \
  --template-body file://deploy/aws/scanner-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --parameters \
    ParameterKey=HubRoleArn,ParameterValue=arn:aws:iam::111122223333:role/argus-platform \
    ParameterKey=ExternalId,ParameterValue='<your ExternalId>'

aws cloudformation create-stack-instances \
  --stack-set-name argus-scanner \
  --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
  --regions us-east-1
```

From a delegated administrator account, add `--call-as DELEGATED_ADMIN` to both commands. A
StackSet with service-managed permissions does not deploy to the management account itself: if
you scan it, deploy the stack there with the single-account command.

Argus itself never calls CloudFormation or IAM: you deploy the role, with your own credentials.

## 5. Add the connection

In **Administration → Connections → Add connection**, choose **Assume role** and enter:

- **Name**: how the account appears in Argus
- **Account ID**: the 12-digit account id
- **Role ARN**: `arn:aws:iam::<account id>:role/ArgusScanner`
- **External ID**: the value from step 3

Save, then open the connection and choose **Test connection**. Argus assumes the role the way a
scan does and must land in the connection's own account; the result appears within seconds. If it
says "Could not assume the role: AccessDenied", the role's trust policy does not name the platform
identity, or the ExternalId differs ([runbook.md, Troubleshooting](runbook.md#troubleshooting)).

**Test connection** under **Settings → Platform identity** checks the identity on its own: it signs
in and writes a small marker object to each tool's folder of the bucket, and reports the encryption
S3 applied.

## 6. The first scan

1. In **Administration → Settings → Collection and throttling**, set **AWS regions to scan** to the regions you
   use. Fewer regions make a run faster. (CloudFox scans every region regardless.)
2. In **Operate → Schedules**, use **Run now** on the new connection. Steampipe runs first, then
   Prowler, then CloudFox; Prowler takes the longest.
3. Follow the runs in **Operate → Runs**. Each ends **Complete**, **Partial** (throttled, a denied
   call, or some tables failed) or **Failed**, with its log and the exact command it ran. A partial
   or failed run never marks a finding as fixed.
4. Add a schedule so the account is scanned daily. Runs on one account never overlap, and starts
   are spread out so a scan does not compete with the account's own workloads.

What to expect from a first real run, and what to do when a permission is missing, is in
[runbook.md, Operating](runbook.md#operating).

## Without a role: access-key connections

A connection can also use an access key directly: an IAM user's key, or temporary SSO credentials,
with read-only permissions. This is the administrator's choice on every install
([ADR-0024](adr/0024-connection-auth-methods.md)). The key is encrypted and write-only, but it is a
long-lived credential stored by Argus, so prefer the role where you can. The exact policies to
attach and the steps are in [runbook.md, Operating](runbook.md#operating), under **The first AWS
scan, with an access key**.

## What it costs

The read-only API calls the tools make are not billed by AWS. What costs money is the S3 storage of
raw output (kept as long as your lifecycle rule says) and the compute Argus runs on. Prowler on a
large account takes hours; size the runs from the first real scans
([design.md, Deployment](design.md#deployment)).

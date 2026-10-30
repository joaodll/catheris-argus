# Security model

**Owner:** `security-architecture-reviewer` (attests) · `documentation-writer` (document)
**Applies to:** Argus 0.1.0 (2026-10-25)

This page is for anyone deciding whether to run Argus, and for the people operating it. It
summarizes how Argus protects what it holds; each section links to the decision record that
explains the choice in full. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Why Argus must be hard to compromise

Argus holds a map of how to attack the organization it scans: what is exposed, which checks fail,
which roles escalate, and the paths between them. It also holds the means to read every scanned
account. Compromising Argus is therefore as bad as compromising the clouds it scans, and it is
designed as a tier-0 system. When security conflicts with convenience, security wins.

## Read-only toward every cloud

Argus never changes anything in a cloud it scans: no create, update, delete, tag, start, stop or
policy change. It observes and recommends; a human applies every fix.

- **The scanner role** grants read actions only: `SecurityAudit`, `ViewOnlyAccess`, and the read
  permissions Prowler and CloudFox document. It carries an explicit **Deny** on reading secret
  values, parameters, decryption, object and table contents, and on bulk reads of code, container
  images and log content: configuration, yes; contents, never
  ([ADR-0018](adr/0018-scanner-role-denies-code-images-logs.md)).
- **A build check enforces it.** Every action in the role template must be a read verb; the
  build fails on any other verb, a wildcard, or a weakened Deny (`deploy/aws/policycheck`).
- **The tools run in their read-only modes.** Prowler's remediation and integration flags are never
  passed (a test asserts it). CloudFox's suggested exploitation commands are shown to the operator
  as text and never run ([ADR-0038](adr/0038-cloudfox-loot-commands.md)).
- **Argus's own code calls AWS only** to sign in (STS: assuming the scanner role, and asking who
  it signed in as for Test connection) and to write raw output to the operator's bucket. Its only writes go to things it owns: its database, that bucket, and, on
  Kubernetes, Jobs in its own namespace.

## Credentials Argus holds

- **How Argus reaches an account** is the administrator's choice per connection: assuming the
  scanner role with an ExternalId (recommended), or an access key
  ([ADR-0024](adr/0024-connection-auth-methods.md)). See [Connecting AWS accounts](connect-aws.md).
- **Stored credentials are sealed** with AES-256-GCM under a keyring that lives in the environment,
  not in the database, and each sealed value is bound to its row.
- **They are write-only.** The API never returns, logs or echoes a stored secret or ExternalId,
  not even in part; the UI shows `********`. The API's database role cannot read the sealed
  columns at all: only the process that runs scans can open them.
- **Keys can be rotated:** a new key is added to the keyring and becomes current, and the old one
  stays so existing secrets still open ([runbook](runbook.md#operating)). It takes a restart of
  the API and the worker.

## Secret values found while scanning

The tools can read secret-bearing configuration (a Lambda function's environment, EC2 user data)
when their checks need it. Argus never stores such a value:

- every value under a secret-bearing key is replaced with `********` before it reaches the
  database, keeping only the shape; credentials embedded in URLs are masked the same way
- CloudFox results keep only the fact that a secret is present, and where
- run logs and error messages are redacted before they are stored or printed
- the only place a secret value can exist is the raw tool output, which goes to the operator's
  own S3 bucket (SSE-KMS recommended; the encryption S3 reports is recorded per run and flagged
  when it is not KMS, [ADR-0031](adr/0031-raw-output-encryption-operator-choice.md)). It is staged
  on a disk only the scanning process mounts, and deleted once uploaded
  ([ADR-0032](adr/0032-raw-staging-on-disk.md)).

## Who can reach Argus

**Docker Compose:**

- the UI is published on `127.0.0.1` only, by the web server, which reaches the API over an
  internal network
- Postgres is never published, and sits on an internal network shared only with the API, the
  worker and the one-shot migration
- the API has no route out; only the worker, which runs the scans, and the web server sit on
  networks that have one
- no service of the running stack mounts the Docker socket (two development tools do: `scan`,
  to read local images, and `kind`, to create a test cluster)

**Kubernetes** ([ADR-0040](adr/0040-helm-chart-trust-boundaries.md)):

- **Network:** default-deny NetworkPolicies. Postgres accepts its clients only, the API accepts the
  web pods only, and only scan Jobs reach port 443 outside the cluster, never instance metadata.
  `helm test` proves the cluster enforces them.
- **What a scan Job can be:** the scheduler is the only pod with a Kubernetes token, and may only
  create Jobs. An admission policy rejects any Job from it whose image, command, service account,
  environment, volumes and mounts, security context, placement, probes or hooks differ from the
  chart's one fixed template; resource sizes are not pinned. A quota bounds how many pods and
  Jobs can exist.
- **Who holds the cloud identity:** only the scan Jobs. Every pod the chart creates meets Pod
  Security `restricted` (non-root, read-only root filesystem, no capabilities), and labelling the
  namespace `restricted`, an install prerequisite, enforces it.
- **No public entry until single sign-on exists:** access is `kubectl port-forward` or an internal
  ingress.

## Sign-in, sessions and the audit trail

- **Users and roles** ([ADR-0041](adr/0041-users-and-roles.md)): each person signs in as
  themselves, with Viewer (reads), Operator (also connections, schedules and scans) or Admin
  (also Settings and Users). Every route checks the role on the server, a refusal is audited, and
  a role change or deactivation ends that user's sessions at once. Passwords are argon2id hashes
  in Postgres, never returned; the API's role can read them to check a sign-in. The first admin
  comes from the environment once, at the first start, and the operator then removes it. No
  second factor until single sign-on.
- **Sessions:** HttpOnly, Secure, SameSite=Strict cookies, double-submit CSRF protection on every
  write, and limits of 30 minutes idle and 12 hours in total.
- **Sign-in limits** per 15 minutes: 5 failures for a username from one address, 20 from one
  address, 100 for a username from anywhere. One attacker cannot lock an administrator out, and
  guessing the current password in a password change counts against the same limits.
- **The audit log** records every sign-in and every change.
- **The API's role in the database** reads scan data read-only, with a 5-second statement timeout.
  It writes only administration rows, and the API never serves its own API description
  ([ADR-0025](adr/0025-openapi-build-time-contract.md)).
- **Only the web server may set the client address** the API records.

## Supply chain

- Every base image and tool is pinned by version and digest. Tool binaries are checked against the
  sha256 their projects publish.
- The tools run unmodified; Argus never forks them.
- Trivy scans the repository and the images, gitleaks scans the working tree and the whole
  history, and both fail the checks every change must pass. Accepted findings are listed with their reason and an expiry
  in `.trivyignore`.

## Known limits

Argus is pre-1.0. These are known and accepted for now:

- **One shared administrator** and no single sign-on or roles. Keep the UI on loopback or inside
  the cluster network until SSO exists.
- **Access keys:** an administrator may store a long-lived key, for a connection or the platform
  identity. It is sealed, write-only and audited, but it is still a long-lived credential in a
  tier-0 database; prefer roles.
- **The scanning process can reach the internet.** On Compose the worker has an unrestricted route
  out; on Kubernetes, scan Jobs reach port 443 anywhere outside the cluster, because AWS service
  endpoints cannot be listed by name in a network policy. A compromised tool could send data out
  that way.
- **The tools can read their own credentials** while they run: the role session or the IRSA
  token. That identity can only assume scanner roles and write to the bucket.
- **No Postgres backup is built in.** Back up the database yourself, or use a managed Postgres.
- **Scan data is not encrypted by Argus at rest.** Only stored credentials are. The database holds
  the attack map: put it on an encrypted volume, or use a managed database with encryption on.
- **No TLS of its own.** The UI is plain HTTP on loopback (Compose) or reached through
  `kubectl port-forward`. Anything wider needs TLS in front: an internal ingress or a proxy.
- **The in-chart Postgres is reached without TLS** inside the cluster (password authentication
  uses SCRAM, so the password does not cross the wire). An external database is reached with
  `verify-full`.
- **`compose.yaml` is for development:** it uses fixed database passwords unless you set your own.
  On a shared host, use `compose.single-instance.yaml`, which refuses them
  ([runbook](runbook.md#single-instance)).
- **On Kubernetes,** the controls depend on the cluster: NetworkPolicy must be enforced (EKS's VPC
  CNI leaves it off by default), and the namespace must be Argus's alone. Run `helm test` after
  every install and upgrade ([runbook](runbook-kubernetes.md#prerequisites)).

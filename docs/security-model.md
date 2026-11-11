# Security model

**Owner:** `security-architecture-reviewer` (attests) · `documentation-writer` (document)
**Applies to:** Argus 0.2.0 (2026-11-06)

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
  it signed in as, for Test connection and before every scan) and to write raw output to the
  operator's bucket. A scan signed in to any account but its connection's fails before a tool
  starts, so another account's key can't change this account's history. Its only writes go to things it owns: its database, that bucket, and, on
  Kubernetes, Jobs in its own namespace.

## Credentials Argus holds

- **How Argus reaches an account** is the administrator's choice per connection: assuming the
  scanner role (recommended), with an ExternalId or, since 2026-11-05, without one, or an access
  key ([ADR-0024](adr/0024-connection-auth-methods.md)). Without an ExternalId, anyone who can add
  connections can add any account whose role trusts the platform identity (the confused deputy):
  keep that identity for Argus alone. See [Connecting AWS accounts](connect-aws.md).
- **Stored credentials are sealed** with AES-256-GCM under a keyring that lives in the environment,
  not in the database, and each sealed value is bound to its row.
- **They are write-only.** The API never returns, logs or echoes a stored secret or ExternalId,
  not even in part; the UI shows `********`. The API's database role cannot read the sealed
  columns at all: only the process that runs scans can open them.
- **A replaced or switched credential leaves the row.** Replacing an access key, or switching a
  connection between assume role and an access key (since 2026-11-10), overwrites or deletes the
  old sealed value in the same statement. Postgres still keeps old row versions until vacuum, and
  write-ahead logs and backups keep them until they expire, still sealed. So deactivate a replaced
  access key in IAM: deleting it from Argus does not make it useless.
- **Keys can be rotated:** a new key is added to the keyring and becomes current, and the old one
  stays so existing secrets still open ([runbook](runbook.md#operating)). It takes a restart of
  the API and the worker.

## Secret values found while scanning

The tools can read secret-bearing configuration (a Lambda function's environment, EC2 user data)
when their checks need it. Argus never stores such a value:

- every value under a secret-bearing key, in a configuration or a tag, is replaced with `********`
  before it reaches the database, keeping only the shape; credentials embedded in URLs are masked
  the same way, and so are secrets written inside text, such as request headers, command lines,
  connection strings, AWS keys and private keys. A CloudFront origin's custom header value is
  always masked, whatever the header is called: it is the usual shared secret between CloudFront
  and its origin (`X-Origin-Verify`), and only the header's name is kept
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
  web pods only, and only scan Jobs reach
  port 443 outside the cluster, never instance metadata. `helm test` proves the cluster enforces
  them once a pod is running; see Known limits for a new pod's first moments.
- **What a scan Job can be:** the scheduler is the only pod with a Kubernetes token, and may only
  create Jobs. An admission policy rejects any Job from it whose image, command, service account,
  environment, resources, volumes and mounts, security context, placement, probes or hooks differ
  from one of the chart's four fixed templates, one per work. A Job is checked whole against the
  template its name prefix names, so one tool's work on another tool's image matches none
  ([ADR-0046](adr/0046-one-image-per-tool.md)). A quota bounds how many pods and Jobs can exist.
- **What a scan Job carries:** only its own tool. Connection tests run on the runtime image with
  no tool. This narrows the code beside the credentials; it does not separate them: every scan Job
  runs as the same `-run` account, with the same database login and keyring.
- **Who holds the cloud identity:** only the scan Jobs. Every pod the chart creates meets Pod
  Security `restricted` (non-root, read-only root filesystem, no capabilities), and labelling the
  namespace `restricted`, an install prerequisite, enforces it.
- **No public entry by default:** access is `kubectl port-forward`. An ingress is off until the
  operator turns it on, and should stay internal or restricted to known addresses until single
  sign-on exists (Known limits).

## Sign-in, sessions and the audit trail

- **Users and roles** ([ADR-0041](adr/0041-users-and-roles.md)): each person signs in as
  themselves, with Viewer (reads), Operator (also connections, schedules, scans and the Collection
  and throttling settings) or Admin (also every other setting and Users). Only an Admin can read
  the raw output bucket or the platform identity. An Operator can make scans push harder on an
  account's API limits, within each setting's range; that can cause throttling, never a write to a
  cloud. Every route checks the role on the server, a refusal is audited, and
  a role change or deactivation ends that user's sessions at once. Passwords are argon2id hashes
  in Postgres, never returned; the API's role can read them to check a sign-in. The first admin
  comes from the environment once, at the first start, and the operator then removes it. No
  second factor until single sign-on.
- **Email addresses:** optional, and the one personal field besides a display name. Only an Admin
  sets or reads one. Argus sends no mail, and the API has no route out to send any. The audit log
  says that an address changed and never holds its value, so deleting a user removes it.
- **Sessions:** HttpOnly, Secure, SameSite=Strict cookies, double-submit CSRF protection on every
  write, and limits of 30 minutes idle and 12 hours in total.
- **What stays in the browser:** no scan data is stored in the browser.
- **Sign-in limits** per 15 minutes: 5 failures for a username from one address, 20 from one
  address, 100 for a username from anywhere. One attacker cannot lock an administrator out, and
  guessing the current password in a password change counts against the same limits.
- **Limits on unauthenticated load:** web allows one sign-in request a second per address, with a
  burst of 5, and each web pod counts on its own. The API runs at most 2 password checks at once,
  each using 64 MiB, and answers 503 when one can't start within a second. Retention deletes
  failures and ended sessions after 30 days.
- **The audit log** records every sign-in and every change. Refused sign-ins, which never reach a
  password check, write one row per address per lockout window. It is never purged.
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
- The runtime and web images fail on a HIGH or CRITICAL finding that has a fix. The worker image and the three tool
  images fail on a CRITICAL that has a fix, because most of its findings are inside the upstream tools and wait on their next release.
- Findings with no fix are accepted and don't fail the scan. The backend images are built on Debian, which lists many
  vulnerabilities in base packages that it hasn't patched, so a registry scanner such as Amazon ECR or Inspector reports
  them until Debian fixes them. Judge them again whenever the base image digest changes.

## Known limits

Argus is pre-1.0. These are known and accepted for now:

- **No single sign-on.** Users have their own passwords and a role (viewer, operator or admin),
  stored in Postgres ([ADR-0041](adr/0041-users-and-roles.md)). Keep the UI on loopback or inside the
  cluster network until SSO exists.
- **Access keys:** an administrator may store a long-lived key, for a connection or the platform
  identity. It is sealed, write-only and audited, but it is still a long-lived credential in a
  tier-0 database; prefer roles.
- **The scanning process can reach the internet.** On Compose the worker has an unrestricted route
  out; on Kubernetes, scan Jobs reach port 443 anywhere outside the cluster, because AWS service
  endpoints cannot be listed by name in a network policy. A compromised tool could send data out
  that way.
- **Redaction goes by names and shapes.** It can't recognize a secret stored under a harmless name
  with no recognizable form, such as a stage variable called `config` holding a password. Such a
  value reaches the database, and every Viewer can read a resource's configuration. Keep secrets
  in a secrets manager, which Argus's scanner role can't read.
- **The tools can read their own credentials** while they run: the role session or the IRSA
  token. That identity can only assume scanner roles and write to the bucket.
- **The tools run as the same user as the scanning process.** That process hides its environment,
  which holds the database password and the keyring, so a tool can't read it. A compromised tool can
  still read anything else that user can, such as the run's staged raw output. On Kubernetes each
  scan has its own pod. On Compose, runs at the same time share a container, so one tool could read
  another run's AWS profile and staged output; set **Max parallel runs** to 1 if that matters to you.
- **Behind an ingress, the address Argus records comes from `X-Forwarded-For`.** Sign-in limits and
  the audit log use its last entry, the one the ingress adds, from whoever connects to web. The
  NetworkPolicy lets only `networkPolicy.webIngressFrom` connect. With the policies off, any pod
  that reaches web can choose the address, dodge the per-address limit and plant an address in the
  audit log. A second proxy in front of the ingress would be recorded as every user's address.
- **An ingress can be internet-facing.** The chart warns about an internet-facing ALB and doesn't
  check that its source addresses are restricted, because that is the operator's to choose. Until
  single sign-on exists there is no second factor behind that sign-in, so an unrestricted ingress
  exposes a system that holds the attack map to password guessing, slowed only by the sign-in limits.
- **A new pod's egress rules don't hold for its first moments on some network plugins.** The plugin
  lets its outgoing traffic through until it has applied the pod's policies. Measured on kind on
  2026-11-03: a pod connecting at its start reached the internet 30 times out of 30, and a pod
  waiting 10 seconds 0 out of 30. The VPC CNI's default `standard` mode documents the same
  behaviour, and its `strict` mode closes it for the whole cluster. Postgres and the API
  still refuse such a pod by their own ingress rules; running pods are enforced; taking advantage
  of the gap needs code running in a pod's first moments. `helm test --logs` reports it on your
  cluster, and the [runbook](runbook-kubernetes.md) has the choice.
- **No Postgres backup is built in.** Back up the database yourself, or use a managed Postgres.
- **Scan data is not encrypted by Argus at rest.** Only stored credentials are. The database holds
  the attack map: put it on an encrypted volume, or use a managed database with encryption on.
- **No TLS of its own.** The UI is plain HTTP on loopback (Compose) or reached through
  `kubectl port-forward`. Anything wider needs TLS in front: an ingress or a proxy.
- **The in-chart Postgres is reached without TLS** inside the cluster (password authentication
  uses SCRAM, so the password does not cross the wire). An external database is reached with
  `verify-full` when you give the chart its CA bundle. Without one it uses `require`: encrypted,
  but the server is not verified, and the install notes warn about it.
- **An external database's address ranges are optional.** Without them, the pods that use the
  database can reach any private address on its port, not only the database, and the install notes
  warn about it. Set `postgres.external.cidrs` to close that.
- **`compose.yaml` is for development:** it uses fixed database passwords unless you set your own.
  On a shared host, use `compose.single-instance.yaml`, which refuses them
  ([runbook](runbook.md#single-instance)).
- **On Kubernetes,** the controls depend on the cluster: NetworkPolicy must be enforced (EKS's VPC
  CNI leaves it off by default), and the namespace must be Argus's alone. Run `helm test` after
  every install and upgrade ([runbook](runbook-kubernetes.md#prerequisites)).

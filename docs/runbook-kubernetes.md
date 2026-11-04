# Runbook: running Argus on Kubernetes

**Owner:** `cloud-native-platform-engineer` (procedures) · `documentation-writer` (document)
**Applies to:** the chart in `charts/argus/` as of 2026-10-26, on EKS with Kubernetes 1.30 or
newer. Verified end to end on kind (Kubernetes 1.34) with Helm 4.3.1, not yet on EKS
([gates/kubernetes-exit.md](gates/kubernetes-exit.md)). Compose is in the [runbook](runbook.md).

On Kubernetes, Argus runs as an `api` Deployment, a `web` Deployment, one `scheduler` replica that
starts scan Jobs from one fixed template, a migrate Job and a rederive Job per release, a daily
retention CronJob, and Postgres in the chart or outside it. A scan Job answers one connection test
or runs one AWS scan, then exits. Kubernetes offers AWS connections only: Demo connections, the
synthetic estate, are for Docker Compose ([runbook.md](runbook.md)). Why it is shaped this way:
[ADR-0039](adr/0039-kubernetes-scheduler-and-run-jobs.md). The trust boundaries the chart holds:
[ADR-0040](adr/0040-helm-chart-trust-boundaries.md).

Not covered yet: Postgres backups (the design's nightly `pg_dump`), an image registry and CI that
publish the images, SSO and a public entry, and stopping a run that is already running.

## Prerequisites

Each of these is a control the chart relies on but cannot set itself.

- **Kubernetes 1.30 or newer** (the ValidatingAdmissionPolicy is GA from 1.30), and rights to
  install cluster-scoped objects: the chart creates a ValidatingAdmissionPolicy and its binding.
- **NetworkPolicy enforced.** EKS's VPC CNI leaves it off: set `enableNetworkPolicy` to `"true"`
  in the `vpc-cni` add-on's configuration. Without it every pod can reach Postgres, and any pod
  can reach the API and choose the client address it records. `helm test` fails when policies
  are not enforced; run it after every install and upgrade.
  - **A new pod's first moments.** In the VPC CNI's default `standard` mode, a new pod starts with
    a default allow until its policies are configured, so its egress rules don't hold for its first
    moments. Postgres and the API still refuse it by their own ingress rules. Anything
    without such a rule stays reachable in that moment, including an external database and the
    Kubernetes API. `helm test --logs` reports it: `note at its start, a new pod's outgoing traffic
    passes before its policies apply`.
    [`strict` mode](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy-configure.html)
    starts pods on a default deny instead (`NETWORK_POLICY_ENFORCING_MODE`, VPC CNI 1.19.3 or newer).
    It closes this gap, but it applies to the whole cluster: every pod in every namespace then
    needs a policy for whatever it reaches, so decide it with whoever owns the cluster.
- **A namespace for Argus alone**, labelled for Pod Security `restricted`. The NetworkPolicies
  deny everything to every pod in it.
- **Instance metadata out of reach of pods:** IMDSv2 required with a hop limit of 1 on every node.
  Scan Jobs are also denied link-local addresses by NetworkPolicy.
- **Encrypted node volumes** (EBS encryption by default). An AWS scan keeps its raw output,
  secret values included, in an `emptyDir` on the node until it is uploaded, never in a volume
  claim ([ADR-0032](adr/0032-raw-staging-on-disk.md), amended by ADR-0040).
- **The three images in a registry the nodes can pull from**, each known by its digest:
  `argus-backend:runtime`, `argus-backend:worker` and `argus-web:runtime`
  (`docker compose build migrate worker web`). The chart refuses tags.
- **`kubectl` and `helm`** (3.18 or newer, or 4) on the machine you install from.

## The platform identity (IRSA)

Only AWS scans and connection tests have a cloud identity, through the service account
`<release>-run` (`argus-run` for a release named `argus`). The chart creates one other account,
`<release>-scheduler`, which may create Jobs and holds nothing else; every other pod runs as the
namespace's `default` account with no token ([chart README](../charts/argus/README.md#service-accounts)).
Create an IAM role for `-run`, with the policies in
[Suggested AWS policies](aws-policies.md#the-iam-role-for-the-service-account):

1. **Trust:** the IRSA policy, for exactly that service account. With EKS Pod Identity instead, use
   its policy, set `identity.mode: podIdentity`, and make the association outside the chart.
2. **Permissions:** the suggested policy, and nothing else.
3. Put the role's ARN in `identity.roleArn`. With no identity at all (`identity.mode: none`), enter
   an access key in **Settings → Platform identity**.

The tools in an `aws` pod can read its IRSA token, as they can read the instance role on a
Compose host. That is why the role may only assume scanner roles and put objects.

## The Secret

One Secret holds every secret value; the chart never generates one. Each pod is given only the
keys it needs.

| Key | What it is |
| --- | --- |
| `ARGUS_DB_PASSWORD` | The schema owner (`database.ownerUser`), used by the migrate Job and the in-chart Postgres |
| `ARGUS_API_DB_PASSWORD` | Role `argus_api` |
| `ARGUS_WORKER_DB_PASSWORD` | Role `argus_worker`: scan Jobs, rederive and retention |
| `ARGUS_SCHEDULER_DB_PASSWORD` | Role `argus_scheduler` |
| `ARGUS_SECRET_KEYS` | The credential keyring, `k1:<base64 of 32 bytes>` |
| `ARGUS_SECRET_KEY_ID` | The current key's id, `k1` |
| `ARGUS_BOOTSTRAP_ADMIN_PASSWORD` or `ARGUS_BOOTSTRAP_ADMIN_PASSWORD_HASH` | First start only: the first admin's password, or its argon2id hash. The migrate Job creates `admin.username` with it while no active admin exists ([ADR-0041](adr/0041-users-and-roles.md)). Remove the key after the first sign-in |

Generate the values from the repository root. Every command runs in a container:

```bash
# A database password; run once per password.
docker compose run --rm --entrypoint python admin-tools -c "import secrets; print(secrets.token_urlsafe(32))"
# The keyring and its id.
docker compose run --rm admin-tools new-secret-key
# The first admin's password hash, if you'd rather not keep the password itself (it prompts
# twice; the password is never printed).
docker compose run --rm admin-tools hash-password
```

Write them to a file as `KEY=value` lines, **without** the single quotes `admin-tools` prints for
`.env` (kubectl keeps quotes as part of the value), create the Secret, then delete the file:

```bash
kubectl -n argus create secret generic argus-secrets --from-env-file=argus-secrets.env
rm argus-secrets.env
```

**From AWS Secrets Manager instead:** with the External Secrets Operator installed, store the
seven keys as one JSON secret and set `externalSecret.enabled: true`,
`externalSecret.secretStoreRef.name` and `externalSecret.remoteKey`. For the first start, add the
bootstrap key to that JSON and name it in `externalSecret.bootstrapKeys`. The chart's
ExternalSecret copies those keys and nothing else into `secrets.existingSecret`.

## Values

`values.schema.json` refuses an install without these, and refuses unknown keys:

| Value | Set it to |
| --- | --- |
| `images.registry`, `images.{runtime,worker,web}.digest` | Your registry, and each image's `sha256:` digest |
| `secrets.existingSecret` | The Secret's name |
| `api.trustedProxies` | The address ranges web's pods get, comma-separated. On the VPC CNI, pods take VPC subnet addresses: list the subnets pods run in. The API believes `X-Forwarded-For` only from these, and the NetworkPolicy lets only web reach the API |
| `networkPolicy.kubeApi.cidrs`, `.port` | The Kubernetes API's endpoint addresses and port (443 on EKS), for the scheduler: `kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o jsonpath='{.items[*].endpoints[*].addresses[*]}'`. EKS can move these addresses when it replaces its control-plane network interfaces (a version upgrade): check them after each cluster upgrade |
| `identity.roleArn` | The IRSA role above (with `identity.mode: irsa`, the default) |

Also review:

- `networkPolicy.scanEgressExcept`: AWS scans and connection tests reach port 443 anywhere except
  these. Keep `169.254.0.0/16` (the schema requires it) and add the cluster's Service range. Add
  the pod subnets only if no VPC interface endpoint for STS or S3 lives in them.
- `networkPolicy.dns`: who the pods may ask for names, kube-dns by default. With NodeLocal
  DNSCache, lookups go to a link-local address on the node instead: allow it here.
- `scanJobs`: the one scan Job, which answers a connection test or runs an AWS scan.
  `scanJobs.activeDeadlineSeconds` (6 hours): a scan past it is lost and counted.
  `scanJobs.scratch.size` (20 Gi): the node disk a scan's raw output may use.
  `scanJobs.resources`: sized for a scan; a connection test uses the same pod size.
- `scheduler.maxRunJobs`: how many AWS scans run at once, a bound below the UI's **Max parallel
  runs**. `scheduler.maxTestJobs`: how many more Jobs may start while connection tests wait, so
  a test never waits behind a long scan.
- `retention.schedule`: the daily CronJob that drops history older than the UI's **History**
  setting, unused configurations and old rule loads. Without it the database grows for ever.
- `api.autoscaling`, `web.autoscaling`: an HPA each, off by default; needs metrics-server.
- `postgres.storage` (20 Gi) and `postgres.maxConnections` (200), and `database.pools`: the
  most connections each pod opens. The install fails, naming the numbers, when every pod's pool
  at once does not fit in `maxConnections` less 3 reserved; raise `maxConnections`, or lower the
  pools, the api replicas or `scheduler.maxRunJobs`. For an external database, set
  `maxConnections` to what it allows Argus. An api pod whose pool stays full answers 503.
- `nodeSelector`, `tolerations`, `affinity` under `api`, `web`, `scheduler`, `postgres` and
  `scanJobs`, to place them on your node groups.

Start from `charts/argus/ci/minimal-values.yaml`; `ci/external-db-values.yaml` sets every
optional piece.

## Install

```bash
kubectl create namespace argus
kubectl label namespace argus \
  pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest
# the Secret (above), then:
helm install argus ./charts/argus -n argus -f values-argus.yaml --wait --timeout 15m
helm test argus -n argus
```

`helm test` runs a pod that no policy allows anywhere. It must resolve the Postgres and API names
and fail to connect to either; it fails if either connection succeeds. The install notes print
a warning for every control turned off.

Open the UI by forwarding the web Service to your machine's loopback (the browser keeps the
Secure session cookie on `localhost`):

```bash
kubectl -n argus port-forward svc/argus-web 8080:8080
```

Then <http://localhost:8080>, as `admin` (`admin.username`) with the bootstrap password. Then
remove the bootstrap key from the Secret (with External Secrets: empty
`externalSecret.bootstrapKeys`, `helm upgrade`, then delete the property in Secrets Manager); the
admin now lives in the database. Add everyone else in **Administration → Users**. `web.ingress` exists for an internal ingress; until SSO
there is no public entry. If you turn it on, add its controller to
`networkPolicy.webIngressFrom`, or it cannot reach web.

### An external Postgres

Postgres 18 (Amazon RDS, for example). You create one role and one database; the migrate Job
creates `argus_api`, `argus_worker` and `argus_scheduler`, sets their passwords from the Secret, and
creates the schema.

**Don't create those three roles yourself.** Since Postgres 16 only a role's creator can change it,
and migrate changes them on every run, so it would fail.

On RDS, connect once as the master user to the database `postgres` and run this, with your master
user's name in place of `MASTER`:

```sql
CREATE ROLE argus_owner LOGIN CREATEROLE;
\password argus_owner

-- CREATE DATABASE ... OWNER needs this first, or it fails with "must be able to SET ROLE".
GRANT argus_owner TO MASTER;
CREATE DATABASE argus OWNER argus_owner;
REVOKE argus_owner FROM MASTER;
```

`\password` hashes the password in psql, so it never reaches the server's logs. The owner needs
nothing more: no `rds_superuser`, no `CREATEDB`. Its password is `ARGUS_DB_PASSWORD` in the Secret.
Argus never uses the master user. Don't run `REVOKE CONNECT ON DATABASE argus FROM PUBLIC` unless you
also grant `CONNECT` to the three roles: the migrations don't.

Set these RDS parameters: `rds.force_ssl` to `1`, `password_encryption` to `scram-sha-256`, and
`rds.restrict_password_commands` to `0`, because migrate sets the three passwords. If you set
`rds.allowed_extensions`, include `pg_trgm`. Set the chart's `postgres.maxConnections` to what RDS
allows Argus.

Then:

```yaml
database:
  ownerUser: argus_owner
postgres:
  enabled: false
  external:
    host: argus.cluster-xxxx.eu-west-1.rds.amazonaws.com
```

Only `host` is required. Two more values are optional and recommended, and the install notes warn
while either is missing:

```yaml
    caConfigMap: rds-ca           # a ConfigMap holding the CA bundle
    caKey: global-bundle.pem
    cidrs: [10.0.32.0/20]         # where the database is, for the NetworkPolicies
```

| Value | With it | Without it |
| --- | --- | --- |
| `caConfigMap`, `caKey` | `sslmode: verify-full`: the connection is encrypted and the server's name is verified | `sslmode: require`: encrypted, but Argus cannot tell the real database from one impersonating it |
| `cidrs` | The database's clients reach only these ranges, on the database's port | They reach any private address on that port (RFC 1918, and `fc00::/7` with `networkPolicy.ipv6`). A database outside those ranges cannot be reached until you set this |

`verify-full` and `verify-ca` are refused without `caConfigMap`, because every connection would
fail.

## Upgrade

1. Build and push the new images; note their digests.
2. `helm upgrade argus ./charts/argus -n argus -f values-argus.yaml --wait --timeout 15m` with
   the new digests.
3. `helm test argus -n argus`.

The migrate Job is named by a hash of its pod, so it runs once per new image. `api` and the
scheduler wait until the schema reaches their image's revision, and only a scheduler that has
waited starts scan Jobs; the old scheduler stops before the new one starts. Migrations only add,
so pods of the old image keep working during the rollout. A rederive Job, named the
same way, derives again after a rule change; it waits behind any ingest running at the time. A
failed migrate or rederive Job stays: read its logs, delete it, and upgrade again.

## Operating

Settings, Test connection, raw output storage and the Cancel button work as on Compose:
[runbook.md, Operating](runbook.md#operating).

**Logs.** Every pod logs JSON lines, redacted, never raw tool output.

```bash
kubectl -n argus logs deploy/argus-scheduler -c scheduler
kubectl -n argus get jobs -l app.kubernetes.io/component=run
kubectl -n argus logs job/<name>
```

A scan Job is deleted 10 minutes after it ends (`scanJobs.ttlSecondsAfterFinished`); after that, its
logs are in your log pipeline or gone. The run itself stays on **Scans → Runs**.

**What the scheduler logs:**

| Line | Meaning |
| --- | --- |
| `job created` | A scan Job started: its name, the AWS connections with claimable scans and the queued connection tests |
| `job not running` | A Job has had no running pod for 5 minutes: an image it cannot pull, no node that fits. It waits until its deadline |
| `kubernetes refused` | The API refused a Job: the admission policy (a template edited outside Helm), the quota, or RBAC. It retries every 30 seconds and runs wait in **Schedules → Queue** |

**A run that was killed.** An evicted, out-of-memory or timed-out pod stops its heartbeat; the
claim is requeued after 10 minutes and another Job takes it. A run lost twice ends as **Failed**
("lost twice while running …") and is not run again. Scan Jobs carry `do-not-disrupt` annotations
so the cluster autoscaler and Karpenter leave them alone.

**Rotating the keyring.** Change the key in the Secret (or in Secrets Manager), then
`kubectl -n argus rollout restart deploy/argus-api`. Scan Jobs read the Secret when they start.
Keyring rotation keeps the old key, as in
[runbook.md, Rotating the credential key](runbook.md#operating).

**Rotating a database password.** Do it while no scan is running: a scan that opens a new connection
with its old password fails, and is retried. The database only keeps a hash, so keep each password
in your vault or Secrets Manager.

For `argus_api`, `argus_worker` or `argus_scheduler`, the Secret comes first, because migrate reads
the new value from it:

1. Change the key in the Secret. With External Secrets, change it in Secrets Manager, then check that
   the Secret has the new value. It refreshes every `externalSecret.refreshInterval`, or at once with
   `kubectl -n argus annotate externalsecret argus-secrets force-sync=$(date +%s) --overwrite`.
2. Run migrate again. It is kept after it finishes, and its name depends on its pod, not on the
   Secret's values, so an upgrade alone does not run it:

   ```bash
   kubectl -n argus delete job -l app.kubernetes.io/component=migrate
   helm upgrade argus ./charts/argus -n argus -f values-argus.yaml --wait --timeout 15m
   kubectl -n argus wait --for=condition=complete job -l app.kubernetes.io/component=migrate --timeout 10m
   ```

3. Restart what holds the old value. Until then, new connections from those pods are refused, so the
   API can answer errors for that moment. Scan Jobs and retention read the Secret when they start.

   ```bash
   kubectl -n argus rollout restart deploy/argus-api deploy/argus-scheduler
   ```

For the owner (`ARGUS_DB_PASSWORD`), the database comes first, because migrate signs in with it. Only
migrate uses this password, so nothing needs a restart:

1. Change it in the database with `\password argus_owner`: on RDS as the master user, and on the
   in-chart Postgres with
   `kubectl -n argus exec -it statefulset/argus-postgres -c postgres -- psql -U argus_owner -d argus`.
2. Change `ARGUS_DB_PASSWORD` in the Secret.

**A forgotten password.** Another admin sets a new one in **Administration → Users**. With no
other admin, from the api pod (it asks twice; the user must change it at the next sign-in, and
their sessions end):

```bash
kubectl -n argus exec -it deploy/argus-api -- python -m argus.entrypoints.admin_tools reset-password admin
```

**Locked out of sign-in.** Wait 15 minutes, or ask an admin to choose **Unlock** on the user in
**Administration → Users**.

## Keeping the controls true

- **`helm test` after every install, upgrade and cluster upgrade.** It is the only proof that
  NetworkPolicy is enforced.
- **The admission policy refuses fields by name.** CEL cannot list a typed object's fields, so the
  policy names every PodSpec and Container field that could run code, reach the host or change
  placement. When the chart's `kubeVersion` floor or the cluster's version moves, read the
  release notes for fields added to PodSpec, Container and JobSpec. Refuse any new one in
  `templates/collectors/admission-policy.yaml`, and add a case to `BAD_JOBS` in
  `deploy/kind/run.sh`.
- **Before changing the chart**, run the checks:

  ```bash
  docker compose run --rm chart-check                    # offline: lint, render, schemas, refusals
  docker compose build migrate worker web
  docker compose run --rm kind up                        # a throwaway kind cluster with the chart
  docker compose run --rm kind test                      # rights, policy, NetworkPolicies, runs, upgrade, helm test
  docker compose run --rm kind down
  ```

  The `kind` service drives the host's Docker socket (root-equivalent) and uses the host network:
  run it only on a development machine. `kind up` prints the admin password once; the cluster
  keeps it in the namespace `argus-kind-harness` for `kind test`.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `helm install` refused with a schema error | A required value is missing, an image has a tag, or a key is misspelled | The message names the path; set it |
| `api` and the scheduler stay in `Init` | The migrate Job has not finished, or the role cannot log in yet | `kubectl -n argus logs job/argus-migrate-<hash>`; check the Secret's keys |
| `helm test` fails: "accepted a connection" | NetworkPolicy is not enforced | Turn on the VPC CNI's network policy, then test again |
| Runs stay queued; the scheduler logs `kubernetes refused` | A denial by the policy or the quota | The `detail` names the rule; reinstall with Helm rather than editing templates by hand |
| Runs stay queued; the scheduler logs a reconcile error with a connection timeout | `networkPolicy.kubeApi.cidrs` no longer holds the API's addresses | Read them again (Values) and upgrade |
| Test connection fails: "Unable to locate credentials" | No identity reached the `test` pod | Check `identity.roleArn`, the role's trust (`sub` names the namespace and `<release>-run`) |

# Runbook: running Argus on Kubernetes

**Owner:** `cloud-native-platform-engineer` (procedures) · `documentation-writer` (document)
**Applies to:** the chart in `charts/argus/` as of 2026-10-26, on EKS with Kubernetes 1.30 or
newer. Verified end to end on kind (Kubernetes 1.34 and 1.36) with Helm 4.3.1, not yet on EKS
([gates/kubernetes-exit.md](gates/kubernetes-exit.md)). Compose is in the [runbook](runbook.md).

On Kubernetes, Argus runs as an `api` Deployment, a `web` Deployment, one `scheduler` replica that
starts Jobs from five fixed templates (four for scans and connection tests, one that works out attack routes; a sixth builds reports on IRSA installs), a migrate Job and a rederive Job per release, a daily
retention CronJob, and Postgres in the chart or outside it. A scan Job answers one connection test
or runs one AWS scan of one tool, then exits. Each tool's Jobs run on that tool's own image, and
connection tests on the runtime image ([ADR-0046](adr/0046-one-image-per-tool.md)), so a Job pulls
only what it runs. Kubernetes offers AWS connections only: Demo connections, the
synthetic estate, are for Docker Compose ([runbook.md](runbook.md)). Why it is shaped this way:
[ADR-0039](adr/0039-kubernetes-scheduler-and-run-jobs.md). The trust boundaries the chart holds:
[ADR-0040](adr/0040-helm-chart-trust-boundaries.md).

Not covered yet: Postgres backups (the design's nightly `pg_dump`), an image registry and CI that
publish the images, a public entry, and stopping a run that is already running.

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
- **The five images in a registry the nodes can pull from**, each known by its digest:
  `argus-backend:runtime`, `argus-backend:worker-steampipe`, `argus-backend:worker-prowler`,
  `argus-backend:worker-cloudfox` and `argus-web:runtime`
  (`docker compose build --pull --no-cache migrate web worker-steampipe worker-prowler worker-cloudfox`).
  Build without the cache: the images take Debian's security fixes at build time, and a cached
  build keeps the packages of the last one. The chart refuses tags. `argus-backend:worker`, with
  every tool, is Compose's only.
- **amd64 nodes.** The images are built for amd64 only. On a cluster that also has arm64 nodes,
  add `kubernetes.io/arch: amd64` to `nodeSelector` in every block under Values, including `tasks`.
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

### The two roles for reports

On an IRSA install, reports go to the `reports/` folder of the raw-output bucket
([ADR-0047](adr/0047-reports.md)). The chart then creates two more accounts, `<release>-api` (the
API reads reports) and `<release>-report` (the report Job writes them), and requires a role for
each. Create them with the policies in
[Suggested AWS policies](aws-policies.md#two-roles-for-reports):

1. **Trust:** the IRSA policy for each account, `system:serviceaccount:argus:argus-api` and
   `system:serviceaccount:argus:argus-report`.
2. **Permissions:** `argus-api` reads `reports/` only; `argus-report` writes `reports/` only.
3. **The key and the bucket:** add the two key-policy statements and the bucket policy's folder
   statements, keep **S3 Bucket Keys off**, and add the lifecycle rule for `reports/`.
4. Put the ARNs in `identity.apiRoleArn` and `identity.reportRoleArn`, and the S3 and STS ranges in
   `networkPolicy.awsEgressCidrs`.

Without IRSA (`identity.mode: podIdentity` or `none`) there are no reports on Kubernetes, and
**Operate → Reports** says so.

## The Secret

One Secret holds every secret value; the chart never generates one. Each pod is given only the
keys it needs.

| Key | What it is |
| --- | --- |
| `ARGUS_DB_PASSWORD` | The schema owner (`database.ownerUser`), used by the migrate Job and the in-chart Postgres |
| `ARGUS_API_DB_PASSWORD` | Role `argus_api` |
| `ARGUS_WORKER_DB_PASSWORD` | Role `argus_worker`: scan Jobs, rederive and retention |
| `ARGUS_SCHEDULER_DB_PASSWORD` | Role `argus_scheduler` |
| `ARGUS_REPORTS_DB_PASSWORD` | IRSA installs: role `argus_reports`, the report Job's. It reads what a report reads and writes its own report rows |
| `ARGUS_PATHS_DB_PASSWORD` | Role `argus_paths`, the paths Job's ([ADR-0052](adr/0052-attack-paths-stored-routes.md)). It reads the edges, the inventory's ids, names and types, the runs and the findings a route step needs, never a configuration or a credential, and writes the route tables only |
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
eight keys (nine on an IRSA install) as one JSON secret and set `externalSecret.enabled: true`,
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
| `identity.apiRoleArn`, `identity.reportRoleArn`, `images.reports.digest` | With IRSA: the two roles for reports, and the reports image (`argus-backend:reports`, the runtime plus the PDF renderer) |
| `networkPolicy.awsEgressCidrs` | With IRSA: S3's ranges (the region's prefix list, `aws ec2 describe-managed-prefix-lists`, or your endpoint subnets) and the STS endpoint's. The API and the report Job reach nothing else outside the cluster |

Also review:

- `networkPolicy.scanEgressExcept`: AWS scans and connection tests reach port 443 anywhere except
  these. Keep `169.254.0.0/16` (the schema requires it) and add the cluster's Service range. Add
  the pod subnets only if no VPC interface endpoint for STS or S3 lives in them.
- `networkPolicy.dns`: who the pods may ask for names, kube-dns by default. With NodeLocal
  DNSCache, lookups go to a link-local address on the node instead: allow it here.
- `scanJobs`: the scan Jobs, one template per work: `test` answers a connection test, and
  `steampipe` (also Vulnerabilities), `prowler` and `cloudfox` each run one AWS scan of their tool.
  `report` (IRSA installs) builds one report. `scheduler.maxReportJobs` (1, at most 3): reports
  built at once; a PDF at every cap peaked at 1.37 GiB. `paths` works out the attack routes
  after scans are ingested ([ADR-0052](adr/0052-attack-paths-stored-routes.md)): one Job at a
  time, on the runtime image, as `argus_paths`, with no cloud identity and no keyring, and no
  route out of the cluster. The scheduler asks every 30 seconds whether routes are due, and starts one at least 5 minutes
  after the last one started, so ingests close together are worked out together and finished
  paths Jobs never hold more than three places in the Job quota. At
  300,000 resources, run as the Job runs, the first evaluation (every route written) took 5.4
  minutes and peaked at 2.33 GiB, and one with nothing new 3.6 minutes and 1.2 GiB (2026-11-16),
  so `scanJobs.work.paths.resources` requests 3 Gi and limits it to 3 Gi. It shares the scan Jobs'
  placement.
  `scanJobs.activeDeadlineSeconds` (6 hours): every Job's deadline, unless its work sets its own
  (`scanJobs.work.<work>.activeDeadlineSeconds`; Prowler's is 12 hours). A Steampipe scan past it
  is lost and counted. Prowler and CloudFox stop their tool 30 minutes before their Job's
  deadline, for the upload and the ingest: the run then fails with a sentence naming the value to
  raise, and is not retried, because the same limit would stop it again. A deadline below 5,400
  seconds (an hour for the tool) is refused for these two. A scan that waits for a node waits
  inside its deadline.
  `scanJobs.work.<work>.resources.requests.cpu`: Prowler requests 2 CPUs and Steampipe 1, since
  both spend hours CPU-bound on a large account; CloudFox, test, paths and report 500m or less.
  `scanJobs.scratch.size` (20 Gi): the node disk a scan's raw output may use.
  `scanJobs.work.<work>.resources`: each template's pod size. A connection test needs far less
  than a scan. The admission policy pins these sizes, so change them here, never on a Job.
  - **Size a scan's memory from its peak.** Every scan run ends its log with
    `argus: peak memory <used> of <limit> (tmp <part>)`. Memory counts the tool's own memory plus
    `/tmp`, which is in memory and holds each tool's home and CloudFox's cache; it never counts
    the page cache.
  - **Near the limit, the scan stops itself.** About a second before the kernel would kill the
    pod, the scan Job stops its tool, and the run fails with a sentence naming the use, the limit
    and the value to raise. The run is not retried, because the same limit would stop it again.
    The threshold is the limit less the larger of 256 MiB and 8 %.
- `scheduler.maxRunJobs`: how many AWS scans run at once, a bound below the UI's **Max parallel
  runs**. There is no bound to set for the paths Job: it is one, fixed. `scheduler.maxTestJobs`: how many more Jobs may start while connection tests wait, so
  a test never waits behind a long scan.
- `retention.schedule`: the daily CronJob that drops history older than the UI's **History**
  setting, unused configurations, old rule loads, and sign-in failures and ended sessions past 30
  days. Without it the database grows for ever.
- `api.autoscaling`, `web.autoscaling`: an HPA each, off by default; needs metrics-server.
- `postgres.storage` (20 Gi) and `postgres.maxConnections` (200), and `database.pools`: the
  most connections each pod opens. The install fails, naming the numbers, when every pod's pool
  at once does not fit in `maxConnections` less 3 reserved; raise `maxConnections`, or lower the
  pools, the api replicas or `scheduler.maxRunJobs`. For an external database, set
  `maxConnections` to what it allows Argus. An api pod whose pool stays full answers 503.
- `nodeSelector`, `tolerations`, `affinity` under `api`, `web`, `scheduler`, `postgres` and
  `tasks`, to place them on your node groups (`tasks` is the pods that run once and exit:
  migrate, rederive, retention and `helm test`'s probe). `scanJobs` takes `nodeSelector` and
  `tolerations`. Set every block: a component left out can land on any node.
- Give scan Jobs their own nodes, and one scan per node: see [Scan nodes](#scan-nodes).
  `scanJobs.onePerNode` (off by default) keeps two scans off one node. `scanJobs.priority`
  (1000) is every Argus Job's priority, through a PriorityClass the chart creates. A scan Job
  has no CPU limit by default, requests its memory whole (6 Gi), and up to
  `scheduler.maxRunJobs` run at once, so on shared nodes they take CPU and memory from the API,
  the scheduler and Postgres. Where scans must share nodes, add a CPU limit under
  `scanJobs.work.<work>.resources`.

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
admin now lives in the database. Add everyone else in **Administration → Users**.

### An ingress

Off by default, with `kubectl port-forward` as the way in. Without single sign-on
([SSO set-up](sso.md)) there is no second factor, so keep an ingress internal, or restrict it to
source addresses you know; with SSO working, turn `auth.localSignIn` off. The chart
warns about an internet-facing ALB but doesn't check for a restriction. With the AWS Load Balancer
Controller:

```yaml
web:
  ingress:
    enabled: true
    className: alb
    host: argus.example.com
    annotations:
      alb.ingress.kubernetes.io/scheme: internet-facing   # or internal
      alb.ingress.kubernetes.io/target-type: ip
      alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS": 443}]'
      alb.ingress.kubernetes.io/certificate-arn: <your ACM certificate>
      # Who may reach the ALB. Needed on an internet-facing one: the default is everyone.
      alb.ingress.kubernetes.io/inbound-cidrs: 203.0.113.0/24,198.51.100.10/32
      # Pin the ALB's subnets, so the list below can't go stale.
      alb.ingress.kubernetes.io/subnets: subnet-0aaa,subnet-0bbb
networkPolicy:
  # What may connect to web: the ALB's subnets, as their address ranges. An ALB connects to its
  # targets from its private addresses in those subnets, also when it is internet-facing, so
  # these are never your users' addresses. `inbound-cidrs` above is what limits those.
  webIngressFrom:
    - ipBlock: {cidr: 10.0.0.0/24}   # subnet-0aaa
    - ipBlock: {cidr: 10.0.1.0/24}   # subnet-0bbb
```

To read the ranges of those subnets:

```bash
aws ec2 describe-subnets --subnet-ids subnet-0aaa subnet-0bbb --query 'Subnets[].CidrBlock'
```

With an in-cluster controller, name its pods instead:

```yaml
networkPolicy:
  webIngressFrom:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: ingress-nginx}}
      podSelector: {matchLabels: {app.kubernetes.io/name: ingress-nginx}}
```

- **HTTPS is required.** The session cookie is `Secure`, so over plain HTTP nobody can sign in.
- **`webIngressFrom` is required while the NetworkPolicies are on,** and the chart refuses an empty
  one. It is also what keeps the client address honest: web believes the last `X-Forwarded-For`
  entry from whoever connects, so whoever is allowed in can set it.
- **One proxy in front of web.** The last entry is the client only when the ingress is the one
  proxy. DNS and a certificate add no hop. A CDN or a second proxy in front of the ingress would be
  recorded as the client, and every user would then share its address for the sign-in limits.
- **`target-type: ip`:** web sees the ALB's own address. In `instance` mode it can see a node's
  address, so `webIngressFrom` would have to cover the nodes.
- **Leave the ALB's `routing.http.xff_header_processing.mode` at `append`, its default.** The ALB
  then adds the client's address as the last entry. `preserve` would let a client choose its address.

**Check it:** sign in with a wrong password, then read `kubectl -n argus logs deploy/argus-web`.
The line for that request must start with your address, and sending a made-up `X-Forwarded-For`
must not change it.

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

## Scan nodes

A scan runs for hours, and a pod that is moved or evicted loses its run. Give scans nodes of
their own, one scan per node, so they never compete with each other or with your applications.

**What the chart does:**
- **One scan per node.** With `scanJobs.onePerNode: true`, the Steampipe, Prowler and CloudFox
  Jobs carry a required pod anti-affinity: no two of them on one node. Test, paths and report
  Jobs share the scans' placement and may run beside a scan, so size the node for them too
  (Sizing, below).
- **No voluntary eviction.** A PodDisruptionBudget (`<release>-jobs`, `maxUnavailable: 0`)
  covers every Argus Job pod, so `kubectl drain` and a managed node group's upgrade wait for
  the Job instead of evicting it. The pods also carry `karpenter.sh/do-not-disrupt` and the
  Cluster Autoscaler's `safe-to-evict: "false"`.
- **Priority.** Every Job names the chart's PriorityClass (`<namespace>-<release>-jobs`, value
  `scanJobs.priority`, `preemptionPolicy: Never`). A pod without a class can't preempt a
  scan, and a scan never preempts anything.
- **Memory requested whole.** Every Argus Job (scans, test, paths, report) requests the memory
  it may use: the chart refuses `requests.memory` different from `limits.memory`, written the
  same way. A pod that can't use more than it requested is the last one the kubelet evicts when
  its node runs short, and no Argus Job beside a scan can push the node short. Near its limit
  the scan stops its own tool and says so on the run, rather than being killed.

The admission policy pins all of this: a Job with another affinity or priority class is
refused.

**What you set up.** Label and taint the scan nodes, then point `scanJobs` at them:

```yaml
scanJobs:
  nodeSelector: {argus.catheris.io/pool: scanners}
  tolerations:
    - {key: argus.catheris.io/scanners, operator: Exists, effect: NoSchedule}
  onePerNode: true
  work:
    prowler: {resources: {requests: {cpu: "1", memory: 12Gi}, limits: {memory: 12Gi}}}
```

With **Karpenter**, a NodePool for scans adds a node for each scan that waits and removes it
once empty:

```yaml
apiVersion: karpenter.sh/v1
kind: NodePool
metadata:
  name: argus-scanners
spec:
  template:
    metadata:
      labels: {argus.catheris.io/pool: scanners}
    spec:
      taints:
        - {key: argus.catheris.io/scanners, effect: NoSchedule}
      requirements:
        - {key: karpenter.sh/capacity-type, operator: In, values: [on-demand]}
        - {key: kubernetes.io/arch, operator: In, values: [amd64]}
      # Longer than the longest scan deadline (Prowler's 12 h): a node is not expired under a scan.
      expireAfter: 720h
      terminationGracePeriod: 13h
      nodeClassRef: {group: karpenter.k8s.aws, kind: EC2NodeClass, name: default}
  disruption:
    consolidationPolicy: WhenEmpty
    consolidateAfter: 10m
  limits:
    memory: 128Gi
```

- **On-demand only:** AWS reclaims a spot node with two minutes' notice, and nothing in
  Kubernetes can refuse it.
- **`limits.memory`** caps what the pool may start: with the 12 Gi of the example, about
  `scheduler.maxRunJobs` nodes.

With a **managed node group**:
- Give the group the same label and taint, and as many nodes as `scheduler.maxRunJobs`. Fewer
  nodes is allowed: the extra scans wait for a free node. Their wait counts against
  `scanJobs.activeDeadlineSeconds` (6 h), so a long queue can run a scan out of time; lower
  `scheduler.maxRunJobs` to the node count instead.
- A node group upgrade waits on the PDB. After 15 minutes it fails rather than killing the scan,
  unless you force it.
- With the Cluster Autoscaler, the pods' `safe-to-evict: "false"` keeps a node with a running
  scan from being scaled down.

**Sizing.** A scan node needs room for:
- the scan's memory, sized from the runs' `peak memory` lines
- the DaemonSets
- a test, paths (3 Gi) or report Job that may land beside it
- the kubelet's reservations and its eviction threshold (below)

**When the node runs out of memory.** A scan pod that ends with an event like

```text
The node was low on resource: memory. Threshold quantity: 100Mi, available: 102192Ki.
Container run was using 7340032Ki, request is 6Gi, has larger consumption of memory.
```

was evicted by the kubelet because the **whole node** fell below its eviction threshold
(`memory.available`, 100 Mi by default). This is not the scan's own limit: the scan can be well
under it, so the scan's memory watch never sees it, and the PDB and the `do-not-disrupt`
annotations don't stop it either. The kubelet evicts first the pods using more than they
requested, then the lower priorities.

Read the event before changing anything:

```bash
kubectl -n argus get events --field-selector reason=Evicted
kubectl -n argus describe pod <the evicted pod>     # within the hour, before the Job's TTL
kubectl describe node <its node>                    # Allocated resources, and what else ran there
```

- **"Container run was using X, request is Y" with X above Y:** the scan could use more than it
  requested. The chart now refuses that for Argus Jobs; check the install's values
  (`helm get values argus`) were upgraded.
- **The scan under its request:** something else on the node used more than it requested: your
  own pods or DaemonSets without limits, or the system itself. Give scans their own nodes
  (`onePerNode`, a taint, above), and reserve memory for the system so that what the scheduler
  counts as allocatable is real:

With **Karpenter** (v1), on the scan nodes' `EC2NodeClass`:

```yaml
spec:
  kubelet:
    systemReserved: {memory: 512Mi}
    kubeReserved: {memory: 512Mi}
    evictionHard: {memory.available: 200Mi}
```

With a **managed node group** on AL2023, the same three settings go in the launch template's
`NodeConfig` (`spec.kubelet.config`). What a node already reserves is in
`kubectl get --raw /api/v1/nodes/<node>/proxy/configz`. Reserved memory comes out of the node's
allocatable, so the scan node's instance type must still hold the scan's request after it.

**What can still end a scan:**
- a spot reclaim, or a node or hardware failure
- a forced drain
- `scanJobs.activeDeadlineSeconds`
- the kernel's OOM killer, when memory grows faster than the scan's one-second look
- the kubelet's node-pressure eviction, when the node itself runs short (above)

The run then ends as "lost" and is run again, once.

## Upgrade

1. Build and push the new images; note their digests.
2. `helm upgrade argus ./charts/argus -n argus -f values-argus.yaml --wait --timeout 15m` with
   the new digests.
3. `helm test argus -n argus`.

**To a chart with reports on Kubernetes** (2026-11-12, ADR-0047): the schema now requires
`images.reports.digest` on every install, and on an IRSA install also `identity.apiRoleArn`,
`identity.reportRoleArn` and `networkPolicy.awsEgressCidrs`. Create the two roles first, add
`ARGUS_REPORTS_DB_PASSWORD` to the Secret (and to the Secrets Manager JSON with External Secrets),
then upgrade: migrate gives `argus_reports` its password, and the API restarts on its new
`-api` account.

**To a chart with the paths Job** (2026-11-16, ADR-0052 round 3): every install gains a `paths`
Job template, its `-paths` account, and the key `ARGUS_PATHS_DB_PASSWORD`. Add the key to the
Secret first (and to the Secrets Manager JSON with External Secrets), or migrate and the paths
Job can't start. Then upgrade: migrate gives `argus_paths` its password, and the scheduler starts
the first paths Job on its next pass. With no new migration in the release, the scheduler may
start that Job before migrate has given `argus_paths` its login: the Job then fails once, and no
other paths Job starts until Kubernetes deletes it (10 minutes), after which routes are worked
out as usual. On Compose nothing changes: the worker's paths thread
works the routes out as `argus_worker`.

**To 0.3.2: the scanner role in every scanned account** (2026-11-16): Prowler 5.50.0 and
Steampipe's AWS plugin 1.36.0 need seven more reads. `ProwlerAdditionsPolicy` gains
`inspector2:SearchVulnerabilities`, `oam:GetSinkPolicy`, `oam:ListTagsForResource` and
`logs:GetDataProtectionPolicy`. A new `SteampipeAdditionsPolicy` grants three
`application-signals` reads. Update the role in every account as
[Connecting AWS accounts](connect-aws.md) describes (StackSet, single stack, or printed policies).
Before or after the chart upgrade both work: until the role is updated, those checks and the
new table have no result. Nothing in the chart, the Secret or the database changes. The same
applies on Compose.

**To a chart with scan nodes** (2026-11-18): Steampipe, Prowler and CloudFox Jobs now request
their memory whole, 6 Gi instead of 2 Gi, so fewer fit on a node: check that your scan nodes hold
`scheduler.maxRunJobs` of them, or set `scanJobs.work.<work>.resources` as you need. Every Job
now names the chart's PriorityClass, and a PDB covers Job pods, so a drain waits for running
Jobs. `scanJobs.onePerNode` is off until you turn it on ([Scan nodes](#scan-nodes)). The
installer needs the right to create a PriorityClass (cluster-wide), as it already creates the
admission policy.

**To a chart with a deadline per tool** (2026-11-19): the Prowler Job's deadline is now 12 hours
(`scanJobs.work.prowler.activeDeadlineSeconds`, was the shared 6 hours), Prowler requests 2 CPUs
and Steampipe 1 (were 500m), and Prowler and CloudFox stop their tool 30 minutes before their
deadline (they stopped at 4 hours). A run stopped there fails saying so and is no longer retried.
Check that the scan nodes hold the new CPU requests, and that a Karpenter NodePool's
`terminationGracePeriod` is longer than the longest deadline.

**To a chart that requires memory requested whole** (2026-11-19): the chart refuses a Job
template whose `requests.memory` differs from its `limits.memory`, so values such as
`requests: {memory: 2Gi}, limits: {memory: 6Gi}` now fail the upgrade with the work's name. Set
both to the same value, written the same way. The defaults changed for the two Jobs that had
less: the test Job requests 512 Mi (was 256 Mi) and the report Job 4 Gi (was 2 Gi), so check
that the nodes they share with scans still hold them.

**From a chart before ADR-0046** (one `images.worker`): the schema refuses `images.worker` and
`scanJobs.resources`. Replace them with `images.workerSteampipe`, `images.workerProwler` and
`images.workerCloudfox` (one digest each), and `scanJobs.work.<work>.resources`. Scan Jobs still
running from the old template finish as they are; the new scheduler starts only the new ones.

The migrate Job is named by a hash of its pod, so it runs once per new image. `api` and the
scheduler wait until the schema reaches their image's revision, and only a scheduler that has
waited starts scan Jobs; the old scheduler stops before the new one starts. Migrations only add,
so pods of the old image keep working during the rollout. A rederive Job, named the
same way, derives again after a rule change; it waits behind any ingest running at the time. A
failed migrate or rederive Job stays: read its logs, delete it, and upgrade again.

## Operating

Settings, Test connection, raw output storage and the Cancel button work as on Compose:
[runbook.md, Operating](runbook.md#operating). Cancelling a running scan deletes no Job: the
scan Job stops its own tool, records the run as cancelled and exits, and Kubernetes removes it
after `scanJobs.ttlSecondsAfterFinished` like any finished Job.

**Logs.** Every pod logs JSON lines, redacted.

```bash
kubectl -n argus logs deploy/argus-scheduler -c scheduler
kubectl -n argus get jobs -l app.kubernetes.io/component=run
kubectl -n argus logs job/<name>
```

**Watching a scan.** While a scan Job's tool runs, its console output is in the pod's log, line by
line, on the logger `argus.tool`:
- A progress bar is shown at most every 10 seconds. Prowler runs on a pseudo-terminal, so its
  bar (`-> Scanning ec2 service`, checks done of total) is shown, with its INFO lines naming the
  service and call it is on (`EC2 - Starting threads for 'describe_instances' ...`).
- Steampipe has one line per table: started, then finished with its row count and how long it
  took, or failed with its reason (a table stopped at its time limit, or killed by the system,
  says so). Its warnings and errors appear as they come, tagged `[<table>]`.
- CloudFox's error log (what a module could not read) appears as it is written, tagged
  `[error log]`.
- A heartbeat every minute says the tool is still running, with its memory, the Steampipe tables
  running and how much each has written, and what was counted since the last heartbeat:
  `AWS calls retried` (a throttle or a transient error that a retry may still answer) and
  `calls given up throttled` (a call whose retries ran out: its data is missing, and the run
  ends Partial). The busiest tables are named.
- A tool printing more than 20 lines a second has the rest left out, and the heartbeat says how
  many.

To follow a Prowler scan as if it ran in a terminal:

```bash
kubectl -n argus logs -f job/<name> | jq -r 'select(.logger == "argus.tool") | .msg'
```

Every line is redacted before it is logged, and tools keep their quiet modes (CloudFox stays at
`--verbosity 1`; a louder level prints secret values). Prowler runs at INFO, never DEBUG
(botocore then prints requests and answers whole); only botocore's one-line retry notice is let
out, and it is counted, not printed. The lines still name resources, ARNs and
account ids, like **Scans → Runs**. If your cluster ships pod logs elsewhere (Fluent Bit,
CloudWatch), that store holds them too: protect it as you protect Argus, or keep the Job's logs
out of it.

A scan Job is deleted 10 minutes after it ends (`scanJobs.ttlSecondsAfterFinished`); after that, its
logs are in your log pipeline or gone. The run itself stays on **Scans → Runs**.

**The audit trail in the logs.** Every audit row is also a line with `"audit": true`: sign-ins and
every change from the API, plus the bootstrap admin from migrate. Keep these lines in a log
store the database's owner can't change; that copy is how a direct edit of the table is noticed.

```bash
kubectl -n argus logs deploy/argus-api --all-containers | grep '"audit": true'
```

**What the scheduler logs:**

| Line | Meaning |
| --- | --- |
| `job created` | A Job started: its name and work, the AWS connections with claimable scans, the queued connection tests and reports, and whether attack routes were due |
| `job not running` | A Job has had no running pod for 5 minutes: an image it cannot pull, no node that fits. The log names its `work`. It waits until its deadline, and while it does no other Job of that work starts, so one missing image holds one slot and the other tools keep running. Mirror that work's image and fix its digest |
| `job failed` | A scan Job failed. `job refused its work` in its own log means its image does not carry its tool: a digest under the wrong `images.worker*` key. No other Job of that work starts until Kubernetes deletes the failed one (`scanJobs.ttlSecondsAfterFinished`, 10 minutes); its requests stay queued. Fix the digest and upgrade |
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

For `argus_api`, `argus_worker`, `argus_scheduler`, `argus_paths` or `argus_reports` (IRSA
installs), the Secret comes first, because migrate reads the new value from it:

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

### Sign-in

Single sign-on is set in the `auth` values, with the IdP's metadata in a ConfigMap you create; see
[SSO set-up](sso.md). That page also covers turning password sign-in off and back on, and what each
refused sign-in means.

## Keeping the controls true

- **`helm test` after every install, upgrade and cluster upgrade.** It is the only proof that
  NetworkPolicy is enforced.
- **The admission policy refuses fields by name.** CEL cannot list a typed object's fields, so the
  policy names every PodSpec and Container field that could run code, reach the host or change
  placement. When the chart's `kubeVersion` floor or the cluster's version moves, read the
  release notes for fields added to PodSpec, Container and JobSpec. Refuse any new one in
  `templates/collectors/admission-policy.yaml`, and add a case to `BAD_JOBS` in
  `deploy/kind/run.sh`.
- **Limit what DNS looks up outside the cluster.** `networkPolicy.dns` lets every pod query the
  cluster's DNS, and it forwards outside names to the VPC's resolver. So even a pod with no route
  out, such as the API, could leak data in the names it asks for
  ([security model](security-model.md#known-limits)). The chart can't stop this: the pods need
  that DNS for cluster names, AWS endpoints and an external database. Close it in one of two
  places:
  - **Route 53 Resolver DNS Firewall** on the cluster's VPC: a rule group that allows the domains
    you trust and blocks the rest. Argus needs `amazonaws.com`, which covers STS, S3, VPC endpoint
    names and an RDS hostname. Names inside the cluster are answered by its own DNS and never
    reach the firewall. The firewall applies to everything in the VPC, nodes and other workloads
    included, so list what they need too: image registries, for example. Start with the Alert
    action, read the resolver's query log across a full scan cycle, then switch to Block.
  - **The cluster's CoreDNS:** forward only the zones you trust, each in its own server block, and
    answer every other name locally instead of forwarding it. This also applies to the whole
    cluster.

  Either way, the list needs upkeep: a new AWS service, registry or tool that needs another domain
  fails until it is added. This advice is reasoned from the AWS and CoreDNS documentation, not
  tested with Argus.
- **Before changing the chart**, run the checks:

  ```bash
  docker compose run --rm chart-check                    # offline: lint, render, schemas, refusals
  docker compose build migrate web worker-steampipe worker-prowler worker-cloudfox
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
| The UI loads, but every page says "Argus can't reach its API" | The API's pods are down or not Ready: web stays Ready on nginx alone (`/healthz`, since 2026-11-06), and nginx answers `/api` with a 502 | `kubectl -n argus get pods -l app.kubernetes.io/component=api`; the API is Ready only while Postgres answers (`/api/v1/ready`), so check the database and the pool next |
| `helm install` refused with a schema error | A required value is missing, an image has a tag, or a key is misspelled | The message names the path; set it |
| `api` and the scheduler stay in `Init` | The migrate Job has not finished, or the role cannot log in yet | `kubectl -n argus logs job/argus-migrate-<hash>`; check the Secret's keys |
| A pod logs `exec /opt/venv/bin/python: exec format error` | The pod is on a node with another CPU type than its image | Set `nodeSelector` and `tolerations` on every block, including `tasks`, so it lands on nodes matching the image: `kubectl get nodes -L kubernetes.io/arch` |
| One person's bad sign-ins lock out everyone, or web's log shows one address for all users | Something adds a second proxy in front of the ingress, or the ingress doesn't set `X-Forwarded-For` | Read the last field of web's log lines: the chain it received. The ingress must add the client last |
| `helm test` fails: "accepted a connection" | NetworkPolicy is not enforced | Turn on the VPC CNI's network policy, then test again |
| The scheduler restarts while scans run; its events say `Liveness probe failed: command timed out` | Up to 0.2.0 its probe started Python with a one-second timeout, too little on a node busy with scans | Upgrade the chart. If pods still slow down during scans, give scan Jobs their own nodes or a CPU limit (Values) |
| A run fails with "<Tool> was stopped at … of the pod's … memory limit" | The tool needed more memory than its scan Job allows | Raise `scanJobs.work.<work>.resources` with `requests.memory` equal to `limits.memory`, sized from the runs' `peak memory` lines, on nodes with room for it, then run the scan again |
| A run fails with "lost 2 times while running (killed, out of memory, evicted or past its deadline)" | The pod died without the scan saying why: evicted, its node removed, past `scanJobs.activeDeadlineSeconds`, or killed by the kernel faster than the scan could stop its tool | `kubectl -n argus get events --field-selector involvedObject.kind=Pod` within the hour; see "Scan nodes" for keeping scans on their node |
| Runs stay queued; the scheduler logs `kubernetes refused` | A denial by the policy or the quota | The `detail` names the rule; reinstall with Helm rather than editing templates by hand |
| Runs stay queued; the scheduler logs a reconcile error with a connection timeout | `networkPolicy.kubeApi.cidrs` no longer holds the API's addresses | Read them again (Values) and upgrade |
| Test connection fails: "Unable to locate credentials" | No identity reached the `test` pod | Check `identity.roleArn`, the role's trust (`sub` names the namespace and `<release>-run`) |

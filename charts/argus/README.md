# argus Helm chart

**Owner:** `cloud-native-platform-engineer`

Deploys [CatherIs Argus](../../README.md) on Kubernetes 1.30 or newer. The install, upgrade and
operating procedure is in [docs/runbook-kubernetes.md](../../docs/runbook-kubernetes.md); this page
says what the chart creates and which values matter.

## What it deploys

| Workload | Kind | What it does |
| --- | --- | --- |
| `api` | Deployment (2 replicas, or an HPA) | The HTTP API, behind `web` |
| `web` | Deployment (2 replicas, or an HPA) | The UI on nginx; proxies `/api` to `api`. ClusterIP only |
| `scheduler` | Deployment (1 replica) | Queues the scans schedules call for and starts a **scan Job** for each. It never scans itself |
| scan Jobs | Jobs the scheduler creates, from one template | Each answers one connection test (the Test connection button) or runs one AWS scan, then exits. Values under `scanJobs` |
| `postgres` | StatefulSet (optional) | PostgreSQL 17, the same image as Compose; or an external database |
| `migrate`, `rederive` | Jobs, one per image | Schema migrations; deriving again after a rule change |
| `retention` | CronJob | Daily: drops history older than the UI's **History** setting, unused configurations and old rule loads |

Kubernetes offers AWS connections only: Demo connections, the synthetic estate, are for Docker
Compose. There is no long-running worker on Kubernetes: each scan is its own short-lived pod, so its
credentials and temporary files go with it ([ADR-0039](../../docs/adr/0039-kubernetes-scheduler-and-run-jobs.md)).
An AWS scan's raw output waits on the node's disk (an `emptyDir`, never a volume claim) until it
is uploaded to your S3 bucket.

## Service accounts

The chart creates two, the only two that hold anything:

| Account | Used by | Holds |
| --- | --- | --- |
| `<release>-run` | Scan Jobs (AWS scans and connection tests) | The AWS identity: the IRSA annotation from `identity.roleArn` |
| `<release>-scheduler` | The scheduler | A Role to create, get and list Jobs in the namespace |

Every other pod runs as the namespace's `default` account with no token mounted. Extra annotations
go in `serviceAccounts.run.annotations` and `serviceAccounts.scheduler.annotations`.

## Values you must set

`values.schema.json` refuses an install without them, and refuses unknown keys and image tags:

| Value | What |
| --- | --- |
| `images.registry`, `images.{runtime,worker,web}.digest` | Where the images are, by `sha256:` digest |
| `secrets.existingSecret` | The Secret holding every secret value ([its keys](../../docs/runbook-kubernetes.md#the-secret)) |
| `api.trustedProxies` | The address ranges web's pods use |
| `networkPolicy.kubeApi.cidrs` | The Kubernetes API's endpoint addresses, for the scheduler |
| `identity.roleArn` | The IRSA role for scans (with `identity.mode: irsa`, the default) |

Every value is described in place in [`values.yaml`](values.yaml). `ci/minimal-values.yaml` is the
smallest valid set; `ci/external-db-values.yaml` turns on every optional piece.

## Scaling

- **Scans** scale through the scheduler: up to `scheduler.maxRunJobs` scan Jobs at once (and the
  UI's **Max parallel runs**, which can only lower it), plus up to `scheduler.maxTestJobs` more
  while connection tests wait. Cluster autoscaling (Karpenter or the cluster autoscaler) adds
  nodes for them; scan pods ask not to be moved.
- **api and web** can scale with an HPA: `api.autoscaling.enabled` and `web.autoscaling.enabled`
  (off by default). It needs metrics-server, which EKS does not install by default. While it is
  on, the Deployment has no fixed replica count and the ResourceQuota counts `maxReplicas`.
- **Database connections:** each pod opens at most its pool from `database.pools` (api 10,
  scheduler 2, scan Job 3, migrate, rederive and retention 2). The render fails when all of them
  at once exceed `postgres.maxConnections` (200) less 3 reserved, and the error names each part:
  api pods (`maxReplicas` while autoscaling is on, plus a rolling-update surge), scan Jobs
  (`maxRunJobs` + `maxTestJobs`), the three one-shots and the scheduler. The defaults need 54.
  For an external database, set `postgres.maxConnections` to what it allows Argus.

## Security controls

On by default, each refused or warned about when turned off:

- an admission policy that pins the scan Jobs to their template (`admissionPolicy`)
- default-deny NetworkPolicies (`networkPolicy`), proven by `helm test`
- a ResourceQuota (`resourceQuota`)

The reasoning is in [ADR-0040](../../docs/adr/0040-helm-chart-trust-boundaries.md); the summary is in
the [security model](../../docs/security-model.md#who-can-reach-argus).

## Checking the chart

```bash
docker compose run --rm chart-check   # offline: lint, render, schemas, refused values
docker compose run --rm kind up       # a throwaway kind cluster with the chart; then kind test, kind down
```

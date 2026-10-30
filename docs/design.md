# CatherIs Argus — Design Doc

Oct 2, 2026 · @Dallas · Updated 2026-10-03: the MVP is built Compose-first on a synthetic estate, with the AWS connection last (see [How the MVP runs](#how-the-mvp-runs)).

## Context and goals

We build our own platform that runs three open-source tools as collectors and owns the join, the history and the UI. Prowler alone gives rule-based findings and limited dashboards, with no history of compliance scores, no dependency map and no attacker view.

| Viewpoint | Tool | What it answers |
| --- | --- | --- |
| Compliance and misconfigurations | Prowler | Which checks fail, per framework, account and cloud, and how to fix them |
| Pentester view | CloudFox | What an attacker can reach, assume or escalate to from a foothold |
| Resource dependencies | Steampipe, plus our relationship rules | Which resource connects to which (network, IAM, compute, data) |
| Context only people know | Our UI | Manual connections, owners, accepted risks |

Goals:

- Compliance scores and misconfigurations per framework, account and cloud, with remediation guidance
- A clickable dependency map with a resource detail panel, where users can add manual connections
- Attack paths drawn over the map, built from all three tools together
- History dashboards: compliance trend, findings opened and fixed, attack paths over time
- Team use: SSO, roles and an audit log

Non-goals for v1:

- Real-time detection: scans run on a schedule or on demand
- Auto-remediation: the platform recommends fixes, it never changes cloud resources
- Our own compliance rules: Prowler owns checks and framework mappings
- Active exploitation: CloudFox enumerates with read-only access only
- Agent-based workload scanning

## MVP scope

The MVP ships two screens, the executive Overview and Administration (ADR-0028), on AWS only, fed by three collectors: Prowler, CloudFox and Steampipe (inventory). It is built and proven on a synthetic estate first; connecting a real AWS account is its last step (ADR-0020). Postgres is the only database: relationship rules write edges to it and the API builds the graph from it. The dependency map and manual edges move to phase 2.

| Area | In the MVP | After the MVP |
| --- | --- | --- |
| Collectors | Prowler, CloudFox, Steampipe (inventory with full configuration) | GCP and OCI connections for the same collectors; more relationship rules; later outside-in probing |
| Compliance and findings | Scores, history, lifecycle, remediation | — |
| Attack paths | Chains of CloudFox steps, joined with failing Prowler checks; counted by category on the Overview | A step-by-step path screen, then paths drawn on the dependency map (Investigate → Attack paths, ADR-0033) |
| Resources | Inventory from Steampipe with each resource's full configuration and its daily versions, joined to Prowler and CloudFox findings by resource\_uid | The dependency map, drawn from rule-derived, CloudFox and manual edges |
| Graph storage | `Edge, snapshot` and `attack_path` tables in Postgres, queried with SQL | The same tables, with recursive SQL for multi-hop paths; no graph database |
| Map and manual edges | Not included | Inventory map (Investigate → Resource map, ADR-0033) and resource panel; the edge editor after it |
| Screens | Two, plus Sign in: the executive Overview and Administration (Connections, Schedules with Run now and the queue, Runs, Settings), in the Titanium Signal theme | Read-only Findings and Resources with the resource panel (built 2026-10-06, ADR-0028 second amendment); Posture → Compliance, read-only (built 2026-10-07, ADR-0028 third amendment); Attack paths, the inventory map; finding states, users, roles and audit log in Admin |
| History | Daily snapshots (snapshot\_date) kept six months in Postgres | The same retention unless a need for longer appears |
| Clouds | AWS | GCP, then OCI |

**Why no graph database.** The map asks for one account, VPC or resource on one day plus its neighbours: a few indexed joins or a recursive query over the edge table. CloudFox already supplies multi-step escalation paths. At 36 accounts a second database would add operations, backups and attack surface without a query that needs it. If a rule ever needs deep path search, the first step is networkx inside ingest, then Apache AGE (Cypher inside Postgres), before any separate graph database.

## How the MVP runs

The architecture below is Argus on Kubernetes (the chart, built 2026-10-25: ADR-0039, ADR-0040). The MVP ran the same code in Docker Compose first, on a synthetic estate, and connected a real AWS account last. Decided 2026-10-02 with the project owner: ADR-0019 to ADR-0024.

| Service | What it does | Database role | Networks |
| --- | --- | --- | --- |
| postgres | PostgreSQL 17, not published to the host | owner | `data` |
| migrate | One-shot: Alembic migrations, then logins and passwords for the api and worker roles | owner | `data` |
| api | FastAPI under `/api/v1`; only writes administration rows (connections, schedules, run requests, settings, sessions, audit log) | `argus_api`: data read-only, column grants, 5 s statement timeout | `edge`, `data` |
| worker | Every 60 s: due schedules become run requests; claims one per account up to *max parallel runs*; collects into the raw volume, ingests; retention once a day (ADR-0019) | `argus_worker` | `data` |
| web | nginx serving the built Vue app and proxying `/api`; the only published port, on `127.0.0.1:8080` | none | `default`, `edge` |

- **Networks.** `edge` and `data` are internal: the API has no route out, and the web container never reaches Postgres. nginx overwrites `X-Forwarded-For` with the real peer, and the API trusts that header only from web's fixed address on `edge`, so a browser cannot choose the IP that the sign-in limits and the audit log record. The worker alone also joins `egress`, its route to S3 for the raw output of AWS runs ([ADR-0029](adr/0029-raw-output-storage-setting.md)).
- **Hardening.** Every service drops all Linux capabilities (Postgres adds back the five its entrypoint needs), sets `no-new-privileges`, runs with a read-only root filesystem where it can, and has memory and process limits set from measured use.
- **Sources.** A connection's kind decides its source. A **Demo** connection uses the synthetic source, which writes each tool's real output format and the manifest into the same raw layout the real tools use (ADR-0020). An **AWS** connection runs the real tools, which the worker image carries, with per-run credentials the tools receive through a private profile ([ADR-0030](adr/0030-aws-source-in-the-worker.md)), and keeps their output in the operator's S3 bucket ([ADR-0029](adr/0029-raw-output-storage-setting.md)). Everything after the raw store is identical.
- **Connections.** An account is a connection row created in the UI, never discovered (ADR-0021). AWS connections assume a role with an ExternalId, or use an access key, the administrator's choice on every install (ADR-0024, amended 2026-10-24). Secrets are write-only: sealed with AES-256-GCM, unreadable to the API's database role, never returned or logged.
- **Configuration.** Every administration setting is made in the UI, stored in `platform_setting`, audited and read on every use; the environment holds only deployment facts, secrets and bounds on what an administrator may set (ADR-0023).
- **Throttling.** One run per account at a time, staggered starts, tool order Steampipe → Prowler → CloudFox, a Run now cooldown, and throttled runs marked partial so they resolve nothing (ADR-0022, layer 1).
- **Retries.** Only a **failed** run is retried, after 30 and then 120 minutes (Settings → Collection). A partial run is not: on a real account it is usually partial because the scanner role denies actions by design, so a retry ends partial again (decided 2026-10-08, argus_v8).
- **Single instance.** `compose.single-instance.yaml` overrides the development defaults: every password, the admin hash and the keyring must be set. Operating it: [`runbook.md`](runbook.md).

## Requirements and assumptions

The platform must add close to $0 of cloud cost and run on an existing Kubernetes cluster. Everything else follows from the goals above.

| Requirement | Target |
| --- | --- |
| Incremental cloud cost | Near $0: free read-only API calls plus S3 storage for raw scan output |
| Scan cadence | Daily scheduled run per account, plus on-demand runs from the UI |
| Freshness | As of the last completed scan; every view shows its scan time |
| History retention | Six months in the database at daily granularity; raw files kept in S3 for a year so fixes can be replayed |
| Availability | Business hours, single instance per component; no high availability in v1 |
| Deployment | Kubernetes (Helm) first; Docker Compose on one cloud instance as fallback |
| Clouds | AWS in v1; GCP and OCI added later through the same adapters |
| Users | A team, with SSO, three roles and an audit log; the MVP had one admin user configured through the environment. Since 2026-10-28 users and three roles (Viewer, Operator, Admin) live in the database; SSO later ([ADR-0041](adr/0041-users-and-roles.md)) |
| Licensing | Apache-2.0 for our code, so a public release stays possible |

Assumptions, each with what changes if it is wrong:

| Assumption | Impact if false |
| --- | --- |
| A read-only scanner role can be deployed to every AWS account (for example with CloudFormation StackSets) | Nothing can be scanned until a role-rollout step exists |
| The cluster runs on EKS (confirmed), so collectors use Pod Identity or IRSA instead of static keys | Long-lived keys in Kubernetes secrets, with rotation to manage |
| The org has up to about 50 accounts and 100,000 resources | Larger orgs need per-account job sharding and a bigger Postgres volume |
| AWS is enough for the first two phases | Phase 1 grows, and keyless access for GCP and OCI must be proven earlier |
| One organization, up to about 20 users | Multi-tenant access rules would be needed |
| Tool output formats stay stable within a pinned version | Adapters break on upgrade; mitigated by pinning and contract tests |

## Architecture overview

&#91;embedded content: platform architecture · 3 collectors, 2 stores, 1 API\]

This section describes Argus on Kubernetes, as the chart in `charts/argus/` deploys it (ADR-0039, ADR-0040; built 2026-10-25). Compose runs the same code as one worker ([How the MVP runs](#how-the-mvp-runs)). Data moves one way: clouds → collectors → S3 (and the run's staged copy) → ingest → Postgres → API → UI. Schedules saved in the UI go through the API to Postgres; the scheduler queues the runs they call for and starts a Job for claimable work, and each Job claims its run from the queue. Manual edges go in through the API to Postgres, and the API adds them to every graph it returns.

**Shape: a modular monolith.** Our code is one Python package and one image, plus a worker variant of the image that adds the three tools (ADR-0030). It runs as processes that differ only in command and service account, so each gets only the permissions its job needs without splitting the code into services.

| Process | Runs as | Can reach |
| --- | --- | --- |
| api | Deployment, 2 replicas | Postgres: read on data, write on schedules, manual edges, sessions and audit log; no Kubernetes or cloud access |
| scheduler | Deployment, 1 replica | Postgres as `argus_scheduler` (no secrets); the Kubernetes API: create, get and list Jobs in its namespace |
| scan Jobs | A Job per unit of work, from one fixed template: a queued Test connection first, otherwise one AWS run (collect and ingest), then exit. No Demo connections on Kubernetes | Postgres as `argus_worker`; the cloud identity and port 443 outside the cluster |
| migrate, rederive | One Job per image | Postgres (the schema owner; `argus_worker`) |
| retention | Daily CronJob | Postgres partition maintenance |

Modules inside the package own their tables and expose a small public interface; other modules call that interface instead of querying another module's tables. Import rules checked in CI (import-linter) keep the boundaries from eroding, and a test holds the same line in SQL: a module may embed SQL its owner exports, never another module's table name (ADR-0026):

- core: configuration, database session, logging, audit log, secrets, redaction, resource\_uid resolver
- connections: the accounts collected from, and their credentials
- settings: administration settings and their bounds
- collection: the raw store, the manifest and the sources (synthetic now, AWS later)
- ingest: one run through its adapter, rules, lifecycle, snapshots, paths and metrics
- retention: partition maintenance and raw-file pruning
- inventory: Steampipe adapter, resources, snapshots, configurations
- relationships: the edge-rule engine and edge snapshots
- findings: Prowler adapter, lifecycle, compliance snapshots
- attackpaths: CloudFox adapter and the attack-path engine
- metrics: metric\_daily rollups
- scheduling: schedules, run requests, claims, the worker loop (the reconciler on Kubernetes)
- auth: admin login, sessions, sign-in limits
- api: thin FastAPI routers that only call module interfaces

A module becomes its own service only when it needs a different scaling profile, release cadence or owner; the module boundary is the seam to cut along.

| Component | Owns | Built with |
| --- | --- | --- |
| Collectors | Run each tool unmodified; write raw output and a manifest to S3 | Prowler, CloudFox and Steampipe export CLIs in the worker image (ADR-0030); a scan Job on Kubernetes |
| S3 raw archive | Unchanged record of every run, replayable | S3; SSE-KMS recommended, encryption recorded per run (ADR-0031) |
| Ingest | Adapters, relationship rules, lifecycle rules, daily snapshots, attack-path engine, daily metrics | Python, in the process that collected the run (the run Job on Kubernetes) |
| Postgres | Canonical models, daily snapshots, schedules, manual edges, users, audit log | PostgreSQL |
| Scheduler | Queues the runs schedules call for and starts run Jobs for claimable work, from fixed templates | Python, a standard-library Kubernetes client (`core/kube.py`) |
| API | Authentication, roles, named graph queries, every read and write | FastAPI |
| UI | Map, findings, compliance, attack paths, trends, admin | Vue with SVG chart components (ADR-0027); Cytoscape.js for the map in phase 2 |

## Canonical data models

Six tables in Postgres are the platform's real contract: every tool maps into them, and the graph is built from them. Swapping a tool means rewriting one adapter, never these models.

| Model | Key | Main fields | Why it exists |
| --- | --- | --- | --- |
| `scan_run` | `run_id` | tool, tool version, provider, account, region scope, started, finished, status, S3 path of raw output | Every row elsewhere points to the run that produced it; failed runs are visible |
| `resource` | `resource_uid` | provider, account, region, type, native id, name, tags, config hash (the configuration itself is in resource\_config), first seen, last seen, deleted at | The join key across all tools; inventory history |
| `edge` | `edge_id` | source uid, target uid, type, origin (rule with its id and version, cloudfox, probe, manual), attributes (ports, policy), first seen, last seen; for manual edges also author and reason | The dependency map and the attacker's moves |
| `finding` | `finding_uid` | tool, check id, resource uid, severity, status, title, remediation text and link, compliance references, service, resource type and categories (Prowler's names for every tool, 2026-10-07), state (open, resolved, reopened, accepted risk), first seen, last seen, resolved at | Misconfigurations with a lifecycle instead of a snapshot |
| `compliance_snapshot` | run, framework, requirement | framework and version, account, requirement id, status (pass, fail, manual), passed checks, failed checks | One row per requirement per scan; the compliance trend |
| `compliance_framework` | framework key (`cis_6.0_aws`) | family and name as Prowler writes them in its compliance CSV (`FRAMEWORK`, `NAME`), version, provider | The Compliance screen names about 40 frameworks per provider (2026-10-07) |
| `attack_path` | `path_id` | rule id, severity, entry uid, target uid, ordered node uids, edge ids, first seen, last seen, resolved at | Paths tracked over time like findings |

History is kept as daily snapshots, so any past day is read with WHERE snapshot\_date = that day:

- resource\_snapshot: one row per resource per day (snapshot date, resource id, config id; integers only)
- resource\_config: the full configuration from Steampipe, stored once per config hash however many days it stays unchanged
- edge\_snapshot: one row per edge per day (snapshot date, source id, target id, type, origin, attributes id)
- finding\_snapshot: one row per failing, manual or muted finding per day (snapshot date, finding id, status, severity, muted); pass counts live in metric\_daily
- finding\_event: one row per state change (opened, resolved, reopened, accepted), with the run that caused it
- compliance\_rollup: one row per requirement per day for all connections together: how many connections fail it, need a manual check or pass it, and the checks summed (integers only). Ingest rebuilds the day after every Prowler load, so the Compliance screen's "All connections" never aggregates snapshot rows at request time (2026-10-07)
- metric\_daily: one row per day, scope and metric, computed after each run so dashboards read small pre-aggregated rows

**All connections** (connection\_id 0 in metric\_daily, and compliance\_rollup) is each **enabled** connection's **latest** result on or before the day, at most 31 days old, combined: counts are summed, and scores are derived from the summed parts (passed ÷ assessed; ThreatScore's numerator ÷ denominator), never averaged. An account scanned yesterday still counts today, until its next scan; one not scanned for 31 days, or disabled, drops out, and its own history stays. `findings.events` (what happened on a day) is summed for that day only. Decided 2026-10-08; before, a day summed only the accounts scanned that day. Migration 0015 recomputed past days.
- finding\_facet: the Findings filter options per connection (regions, services, resource types, categories, checks), rebuilt after each findings load, so the list's options never need a DISTINCT over every finding (2026-10-07: that took about one second on 400,000 findings)

**Retention: six months.** Snapshot, event and metric tables are partitioned by month. A nightly job drops partitions older than six months, then deletes configurations that no remaining snapshot points to. Sizing is under Database load and query rules below; hashing also makes "what changed" a comparison of two hashes.

**Resource identity.** `resource_uid` = provider + the cloud's own global id: the ARN on AWS, the full resource name on GCP, the OCID on OCI. When a tool reports a short id (an instance id, a security group id), the resolver builds the global id from account, region and type. Anything it cannot resolve lands in an `unresolved_refs` table that the UI shows, so a broken join is visible instead of silently dropped.

**Stable ids for history.** `finding_uid` uses Prowler's own finding uid; CloudFox findings use a hash of tool, check and resource. `path_id` is a hash of the rule id and the ordered node uids, so the same path keeps its id across scans.

## Database load and query rules

The snapshot tables are the only part that grows with time, so their row width decides the size. Snapshot rows hold integer ids only; uids, names, tags and configurations live once in dimension tables (resource, resource\_config, finding) and are joined after filtering. Estimates for six months, assuming 2.5 to 3 edges per resource and 2% of configurations changing per day:

| Scenario | Resources | Rows written per day | Six months on disk | Today's partitions |
| --- | --- | --- | --- | --- |
| Small | 20,000 | about 110,000 | about 2 GB | about 8 MB |
| Medium (36 AWS accounts, likely) | 100,000 | about 450,000 | about 8 GB | about 36 MB |
| Large (all providers, growth) | 300,000 | about 1.45 million | about 25 GB | about 120 MB |

With uids and JSON repeated in every snapshot row instead, the medium case grows to about 40 GB, so narrow rows are a schema rule, not an optimisation for later. A Postgres with 2 vCPU, 4 GB of memory and a 50 GB volume covers the medium case; the day's partitions and their indexes fit in memory, and the daily load is a few COPY statements that take seconds.

Query rules, enforced in code review and by the query-budget test:

- Every snapshot query filters snapshot\_date by equality or a short range, so Postgres reads one monthly partition and one index range. Nothing at request time aggregates months of snapshots.
- Trends and every Overview block read metric\_daily, computed by ingest; the API never counts snapshot rows for a chart.
- Filter on integer ids and the snapshot date first, then join dimension tables for names, tags and configuration.
- JSONB is read by relationship rules inside ingest, never by the API. Columns the UI filters on (account, region, type, VPC) are plain indexed columns on resource.
- Multi-hop queries are recursive SQL with a depth limit and cycle detection, run by ingest; their results are stored in attack\_path and, for the Resource map's Flow mode, in flow, flow\_shape, flow\_step, flow\_chip and flow\_snapshot ([ADR-0036](adr/0036-flow-mode.md)). The map's neighbourhood query stops at 3 hops and 500 nodes, and reads one connection's edges ([ADR-0033](adr/0033-resource-map.md), amended 2026-10-09).
- The API connects with a read-only role that has a 5-second statement timeout; every list is paginated.
- No server-side prepared statements (`core/db.py`, `prepare_threshold` off). A prepared statement turns into a generic plan after a few runs, and a generic plan cannot prune partitions at plan time or choose the index for the connection asked for: the query budget measured the Overview at 8 ms planned per call and 120 ms generic, with a 1.7 s run at the switch (2026-10-07).
- metric\_daily's key starts with the date, so it has two more indexes (migration 0013): by connection, metric and dimension (the Overview and the Compliance pages, one connection over six months) and by metric and dimension (one framework across every connection). Real Prowler writes six compliance rows per framework a day for about 40 frameworks; without them, six months of one connection was a scan of whole partitions.
- Each table declares the volatile columns (timestamps, counters, states that flip) left out of its configuration hash, or a single changing field would store a new configuration every day.
- After each load, ingest runs ANALYZE on the day's partitions. Tables are append-only apart from re-running a day, so dropping old partitions keeps them free of bloat.
- The query-budget test loads a synthetic 300,000-resource dataset and checks every API query's plan and time in CI.

## Collectors and adapters

Each tool runs unmodified in its own container at a pinned version, writes raw output to S3, and a small adapter of ours maps that output into the canonical models. We never fork a tool.

| Collector | Clouds | Raw output kept in S3 | Adapter writes |
| --- | --- | --- | --- |
| Prowler CLI | AWS now; GCP and OCI later | JSON-OCSF findings and the per-framework compliance CSVs | `finding`, `compliance_snapshot`, resource stubs |
| CloudFox | AWS first | Its structured outputs for role trusts, permissions, cross-account escalation (`cape`) and endpoints | Edges `CAN_ASSUME`, `IS_ADMIN`, `CAN_PRIVESC_TO` (both to the pseudo-node `admin:<account>`) and `INTERNET_REACHABLE` (from the pseudo-node `internet`), plus attacker-view findings |
| Steampipe export CLIs | AWS in the MVP; GCP and OCI plugins later | JSONL per table and account, with every column of each selected table | resource, resource\_snapshot and resource\_config (the full configuration, stored once per hash), daily asset counts in metric\_daily; edges come from our relationship rules |

**Steampipe** collects the inventory through its [export CLIs](https://steampipe.io/docs/steampipe_export/overview) (steampipe\_export\_aws, steampipe\_export\_gcp, steampipe\_export\_oci): standalone binaries built from the Apache-2.0 plugins, with no database, no service and no login. The runner calls one binary per table and account, with every column, and writes JSONL. The tables to collect are a versioned list per provider in the repository, so adding a resource type is a reviewed change. Export CLIs don't use aggregator connections, so the runner loops over accounts itself: one failing account never stops the others, and each account gets its own scan\_run.

**Why export CLIs instead of Steampipe inside Postgres.** Steampipe also ships a Postgres extension that queries cloud APIs from inside the database. We don't use it: it would put cloud credentials and API calls inside the tier-0 database, and it would skip the raw archive that makes adapters and relationship rules replayable (ADR-003). We also don't run the Steampipe CLI service, which is AGPL-3.0; the export CLIs are enough.

**Every run writes the same S3 layout:** `raw/<tool>/<provider>/<account>/<YYYY>/<MM>/<DD>/<run_id>/` (a single `<date>` folder before 2026-10-06; `scan_run.raw_path` keeps each run's own location), with a `manifest.json` written last (tool, version, scope, start, end, exit status). A run without a manifest is incomplete and never ingested. In S3 each file is stored gzip-compressed as `<file>.gz` and the manifest stays plain; the manifest's file list describes the uncompressed files (2026-10-08, [ADR-0032](adr/0032-raw-staging-on-disk.md) amended). Inside a run directory the files are the tool's own, unchanged. CloudFox's wrapper folders (`cloudfox-output/aws/<profile>-<account>/`) are removed, because the path already names the tool, account and run, so a CloudFox run holds `json/`, `csv/`, `table/` and `loot/` directly (2026-10-06).

The adapter contract:

1. Input: one run's raw files plus its manifest. No network calls, so an adapter can be replayed on old raw data after a bug fix.
2. Output: upserts to the canonical models, keyed on stable ids, in one transaction per run. Running it twice changes nothing.
3. Version: each adapter declares the tool versions it supports and refuses others.
4. Tests: fixtures cut from real outputs of the pinned version; a tool upgrade starts by refreshing the fixtures.

**CloudFox can print secret values** (for example environment variables of functions and containers). Its adapter keeps only the fact that a secret is present and where, never the value.

**CloudFox attacker-view findings** (2026-10-07). The adapter turns the files it already parses for edges into four checks. Each finding carries Prowler's service, resource type and category names, so the Findings filters match both tools:

| Check | From | When | Severity |
| --- | --- | --- | --- |
| `cloudfox_env_var_secret` | env-vars | A variable whose name looks like a secret (the value is never read) | High |
| `cloudfox_role_privesc_to_admin` | role-trusts-principals, role-trusts-services | A role that can escalate to administrator and is not one already, once per role | High |
| `cloudfox_cross_account_root_trust_no_external_id` | role-trusts-principals | A role trusting another account's root with no ExternalId | Medium; High when the role is or can become administrator |
| `cloudfox_public_endpoint` | endpoints | A public endpoint, once per resource and port | Medium, as Prowler's `elbv2_internet_facing` |

A check counts as run, so a complete run can resolve it, only when its file exists; the role checks are global. The other CloudFox modules (resource trusts, access keys, secrets, network ports and more) wait for fixtures cut from a real run, so their findings are written against real columns.

**Steampipe exports secret values too.** Every column of a table includes `aws_lambda_function.environment_variables` and `aws_ec2_instance.user_data`, and Prowler's OCSF resource metadata can carry the same fields. Before anything reaches `resource_config`, the Steampipe and Prowler adapters redact every value under a secret-bearing key (environment, variables, user data, password, secret, token, private key, credential), keeping the shape, as `********` (eight asterisks whatever the value; the word REDACTED before 2026-10-23, ADR-0024 amended), and mask a credential written inside any URL value (its userinfo, and the value of a credential-bearing query parameter such as `sig`, `key`, `code` or `X-Amz-Signature`; added 2026-10-09 after the Resource map's security review found API Gateway integration URLs carrying them under an ordinary key). So "Argus never stores a secret value in Postgres" holds for the inventory as well. Found 2026-10-02 in the secure code review of the fixture scrubber, which already applies the same rule. Open for work item 7b: whether to exclude these columns at collection with `--select` instead, so raw S3 never holds them either.

**Every configuration table** (2026-10-08, [ADR-0012](adr/0012-steampipe-export-clis.md) amended). The Steampipe list holds every configuration table of the pinned plugin (412 of 588 since 2026-10-21) except four classes: contents and data plane, activity/metrics/cost and other tools' findings, reference data, and tables that need a fixed filter. A few tables are narrowed (`collection/tables.py`): only customer-managed IAM policies, and no column the role denies or Argus must not hold (Lambda code, API key values, CloudFormation template bodies). Tables export `steampipe_parallel_tables` at a time (Settings → Collection). **Completeness is per table**: a table that failed, or whose export logged a denied call or throttling, is listed in the run's `incomplete_tables`, its resources carry forward and none of its type is deleted; every other table of the run is complete. Redaction also covers name/value pairs (CloudFormation parameters and outputs, Beanstalk option settings) and secret assignments inside text values (inline buildspecs, state machine definitions, event inputs). Parts, settings and links (rules, versions, attachments, associations) are stored but not counted as assets. **What a table's errors mean** (2026-10-21, ADR-0012 second amendment): a table whose every error says the service does not apply to the account (Organizations not in use, Timestream for LiveAnalytics to a non-customer) is *not applicable*, and one whose every error is a resource's own refusal ("no resource-based policy allows") is *refused*. Both carry their resources forward and neither makes the run Partial; the Runs page lists them apart from the actions missing from the role. Columns that fail on resources the account does not own are left out with `--select` (VPC endpoint service permissions, AppStream image and KMS key tags, WAF logging configuration), and `aws_api_gateway_api_key` is excluded: the scanner role denies the API key paths, whose GET returns key values.

**IAM users and access keys** (2026-10-07). `aws_iam_user` and `aws_iam_access_key` are in the inventory, and the rule `access-key-user` links each key to its user (`BELONGS_TO`). A key is part of its user, not an asset of its own. The secret-key rule would hide `access_key_id`, the last-use columns and `password_last_used`. These are identifiers and dates an operator needs to judge a key, and the secret half of a key pair is not in these tables. So `core.redaction.NOT_SECRET_COLUMNS` names them exactly, for that table and the top level of its rows only. Every other key, table and tool still goes through the rule, so a Lambda variable named `access_key_id` stays secret. Last use is kept in the configuration on purpose (a key used on a day gets a new configuration that day). The fixture scrubber gives each key id a stable pseudonym without a credential shape.

**What a finding says** (2026-10-07). Besides the title and remediation text, the Prowler adapter keeps each result's `status_extended` (what is wrong with this resource, redacted) and the name Prowler reported for the resource. Each check gets one row in `finding_check_text`: description, risk, http(s) links, and remediation code. Prowler 5.44.0's OCSF file carries only the recommendation URL; the CLI, CloudFormation, Terraform and console steps are only in its findings CSV, of which the adapter reads the check id and those four columns and nothing else. The API returns all of it for one finding at a time (`GET /findings/{id}`), so the list stays light.

**Only the top-level OCSF file holds findings** (2026-10-21). Prowler 5.44.0 also writes `compliance/<stem>_<framework>.ocsf.json` for its universal frameworks (CIS Controls, CMMC, CSA CCM, Cyber Essentials, DORA, FedRAMP 20x), whatever `--output-formats` says. It holds one item per finding and requirement, titled with the requirement id, with uid `<finding uid>-<requirement id>`, plus a `manual-<id>` item per requirement without checks. The adapter read them as findings until a real scan showed one row per requirement in the Findings list. It now reads only the top-level file. Migration 0023 removed the stored rows and recomputed the findings metrics of the days they counted in. The check-result metrics (`checks.*`) of those days counted them too and cannot be rebuilt without the raw run, so they stay as they were until the connection's next Prowler run. Requirement titles and sections come from whichever column a framework's CSV uses: `ATTRIBUTES_TITLE`, `NAME` (MITRE ATT&CK, ISO 27001, KISA) or `ATTRIBUTES_NAME`; `ATTRIBUTES_SECTION`, else MITRE's first tactic, else `ATTRIBUTES_CATEGORY` (ISO) or `ATTRIBUTES_CATEGORIA` (ENS).

## Relationship rules

Steampipe only collects; our relationship rules turn its configuration into edges, so the platform, not a tool, decides how resources connect. A rule is a versioned file in the repository, like an attack-path rule: id, version, source and target resource types, edge type, and one read-only SQL query over resource.properties that returns source uid, target uid and attributes.

| Example rule | Reads | Edge |
| --- | --- | --- |
| Instance in security group | aws\_ec2\_instance.security\_groups | instance → security group, MEMBER\_OF |
| Security group open to the internet | aws\_vpc\_security\_group\_rule with 0.0.0.0/0 or ::/0 | internet → security group, ALLOWS\_INGRESS, with ports |
| Instance role | aws\_ec2\_instance.iam\_instance\_profile\_arn and aws\_iam\_instance\_profile | instance → IAM role, RUNS\_AS |
| Function role | aws\_lambda\_function.role | function → IAM role, RUNS\_AS |
| User in group (`user-group`, 2026-10-08) | aws\_iam\_user.groups | user → IAM group, MEMBER\_OF |
| Attached policy (`principal-policy`, 2026-10-08) | attached\_policy\_arns of users, groups and roles | principal → managed policy, HAS\_POLICY (an AWS-managed policy is not inventoried: the edge points to its ARN) |
| Role trust (`role-trust` v2: federated principals too, 2026-10-22) | aws\_iam\_role.assume\_role\_policy | principal → role, CAN\_ASSUME |
| Outsider (`outsider-trust`, 2026-10-22, [ADR-0037](adr/0037-attack-path-search.md) second amendment) | role trusts naming another account, anyone (`*`), or an OpenID Connect provider with no condition on the token's subject | internet → that principal, OUTSIDER (an attack-path entry; the role trust is the move) |
| Leaked credential (`exposed-user-credential`, 2026-10-22) | users with an active access key, or a console password without MFA | internet → user, HAS\_CREDENTIAL (an entry; which credential, how many keys, the oldest key's date, never a key id) |
| Escalation (`privilege-escalation`, 2026-10-22, wave 3) | roles and users, with their groups: a documented IAM escalation method by permission name (CreatePolicyVersion, Put\*Policy, PassRole with a compute create, …; IAMFullAccess) | principal → admin:<account>, CAN\_ESCALATE\_TO (Candidate; resources, conditions, boundaries and SCPs not evaluated) |
| Lateral movement (`lateral-network`, 2026-10-22, replaces `ssh-lateral`) | an instance door (open, unknown, or Restricted with something open) and the groups of instances and databases in its VPC | door → neighbour admitting SSH, RDP, WinRM or a database or cache port from a private range, CAN\_CONNECT\_TO (ports, services) |
| Systems Manager (`ssm-command`, 2026-10-22) | principals allowed ssm:SendCommand or StartSession; aws\_ssm\_managed\_instance Online | principal → any:ssm → each managed instance, CAN\_RUN\_ON |
| Administrator (`principal-admin`, 2026-10-22) | roles and users, with their groups: AdministratorAccess, or an unconditional Allow of `*` on `*` | principal → admin:<account>, IS\_ADMIN (Supported; CloudFox's own stays Confirmed) |
| Load balancer target | aws\_ec2\_target\_group.load\_balancer\_arns and target\_health\_descriptions | load balancer → target, ROUTES\_TO (version 2, ADR-0033: load balancer → target group → instance, function or IP) |
| Resource in subnet | subnet ids on instances, functions and databases | resource → subnet → VPC, IN\_NETWORK |
| Internet entry (`internet-entry` v7, [ADR-0035](adr/0035-internet-reachability.md)) | resources where traffic can really arrive (and, since v7, 2026-10-22, a bucket, queue, topic, function, KMS key, secret or ECR repository public by its own policy: `via` resource\_policy, restricted by S3 Block Public Access, unknown under a condition): enabled CloudFront, API Gateway APIs not private or address-limited, internet-facing load balancers with a security group open to anywhere on a listener port, public running instances and publicly accessible databases with an open security group, function URLs without IAM auth, EKS endpoints open to 0.0.0.0/0 (Route53 records name an entry, they are not one; a public record whose chain ends where Argus does not look is an unknown door, `internet-dns`, ADR-0035 third amendment) | internet → resource, ROUTES\_TO (the map's front doors), with the open ports |
| Internet restricted (`internet-restricted`, ADR-0035) | the same candidates, public by their settings but closed by security groups, IAM auth or address lists | internet → resource, PUBLIC\_RESTRICTED, with the reason and the sources admitted. CloudFox's "public" endpoints and Prowler's exposure checks (`ec2_instance_port_*`, `ec2_instance_public_ip`, `ec2_instance_internet_facing_with_instance_profile`, `rds_instance_no_public_access`, `elb_internet_facing`, `elbv2_internet_facing`; 2026-10-22, ADR-0035 sixth amendment) are checked against these rules: `finding.reach` and `finding.reach_reason` (the door's reason; `no_door` when a Prowler check names a resource the rules judged and found no way into, `not_in_inventory` when they had nothing of it) |
| Exposure evidence (2026-10-21, ADR-0035 fifth amendment) | instances judged per network interface; a stopped instance with an open group is restricted (`not_running`); ICMP opens nothing | every VPC door's edge carries `network` (per interface: public families, what its groups open per family, each subnet's route and ACL) and an instance's `state` |
| Role access (`role-accesses`, [ADR-0036](adr/0036-flow-mode.md); users with their groups since v3, 2026-10-22) | Allow statements of a role's or user's inline and customer-managed policies (the views `ps` and `pa`); since v2 (2026-10-22, [ADR-0037](adr/0037-attack-path-search.md) second amendment) the AWS-managed policies of a curated list, their data access per service derived from AWS's policy documents (`ReadOnlyAccess` reads S3, DynamoDB, SQS and Kinesis, not Secrets Manager) | role → DynamoDB, S3, SQS, SNS, Kinesis, Secrets Manager, KMS, Lambda, Step Functions resource, ACCESSES (`Resource: "*"` and a managed policy → `any:<service>`; Deny, conditions, boundaries, SCPs and unlisted AWS-managed policies not evaluated) |
| WAF (`waf-protects`, ADR-0036) | WAFv2 associated resources, CloudFront web\_acl\_id, API stage web\_acl\_arn | resource → web ACL, PROTECTED\_BY |
| More flows (ADR-0036) | EventBridge pipes and schedules, Step Functions definitions (ARNs only), Firehose sources and destinations, log subscription filters | TRIGGERS |
| Front door chain (ADR-0033) | Route53 alias targets, CNAMEs and A/AAAA addresses (to the instance, network interface or Elastic IP that holds them, 2026-10-13), CloudFront origins, API Gateway integrations, target groups | record → distribution, load balancer or API; distribution → origin; API route or method → integration; target group → ECS service; ROUTES\_TO |
| Compute and network (ADR-0033) | VPC configuration of functions, ECS services, EKS clusters; security groups of load balancers and databases; ECS task and EKS cluster roles | MEMBER\_OF, IN\_NETWORK, RUNS\_AS |
| Event triggers (ADR-0033) | Lambda event source mappings, bucket notifications, topic subscriptions, EventBridge targets | source → function, TRIGGERS |

- Every edge carries origin rule:\<id>@\<version> with first seen and last seen, so a rule change shows up in history.
- Rules run after the Steampipe adapter, in the same step as the lifecycle rules; an edge a complete run no longer produces is absent from that day's snapshot, and past days keep it.
- Raw output stays in S3 and resource\_config keeps every configuration of the last six months, so a new or fixed rule can be replayed over past days.
- A rule upgrade re-derives at once (2026-10-21): each rule load records its rule set (`edge_load.ruleset`: the rules' and path kinds' ids and versions, and since 2026-10-22 the checks whose findings carry a reach), and the worker, when it starts, re-runs the latest standing day of each enabled connection derived with other rules (edges, flows, reach checks, attack paths; nothing resolved).
- Each rule has a fixture: configuration rows in, expected edges out. A coverage report lists resource types that no rule reads, so gaps are visible.
- CloudFox edges such as CAN\_ASSUME and CAN\_PRIVESC\_TO stay; when a rule and CloudFox find the same connection, each origin keeps its own edge and the map merges them.
- A host name no inventoried resource owns (a custom origin, another account's load balancer) becomes the pseudo-node `external:<hostname>`; an AWS-owned host also records an unresolved reference (ADR-0033). The rows above marked ADR-0033 are planned on 2026-10-08 and stay unconfirmed until a fixture cut from a real Steampipe run proves their shapes.

## Keyless multi-account access

Collectors never hold long-lived keys. Every provider is reached from the collector pod's own identity on EKS: at the start of each job the runner writes the connection files from the account list, and the plugins pick them up.

| Provider | Identity in the cluster | In each account, project or tenancy | Steampipe connection | Status |
| --- | --- | --- | --- | --- |
| AWS (MVP) | EKS Pod Identity gives the collector service account a hub role in the security account | A read-only role rolled out by StackSet (SecurityAudit, ViewOnlyAccess, CloudFox's policy) that trusts only the hub role, with an ExternalId | One profile per account in a generated AWS config (role\_arn, credential\_source, external\_id) and one connection per account in aws.spc; accounts listed from AWS Organizations | The plugin uses the AWS SDK for Go v2, which supports Pod Identity, IRSA and role profiles; to be confirmed in phase 0 |
| GCP | The cluster's OIDC issuer is a provider in a Workload Identity Federation pool; the pod reads a projected service-account token | One Viewer service account at organization or folder level, impersonated | An external\_account credential file plus impersonate\_service\_account, one connection per project | After the MVP; confirm the plugin accepts external\_account credentials |
| OCI | The same OIDC token, exchanged through OCI Workload Identity Federation for a 60-minute session token (UPST) | A service user in a group with read-only (inspect and read) policies | A profile holding the session token, with auth = "SecurityToken", renewed before each run | After the MVP and unproven: spike before OCI is enabled; fallback is an API key in Secrets Manager |

Prowler and CloudFox use the same per-account profiles, so each account has one trust to audit. If credential\_source doesn't resolve Pod Identity inside the plugin, the runner calls sts:AssumeRole itself and passes the temporary credentials to each export as environment variables.

Sources: [AWS plugin](https://hub.steampipe.io/plugins/turbot/aws), [GCP plugin](https://hub.steampipe.io/plugins/turbot/gcp), [OCI plugin](https://hub.steampipe.io/plugins/turbot/oci), [OCI Workload Identity Federation](https://www.ateam-oracle.com/post/workload-identity-federation).

## Ingestion, snapshots and attack paths

A run becomes visible only after four steps succeed in order; a failed step leaves the previous state untouched.

1. **Collect.** The run writes raw files, then the manifest, and uploads them; the same process then ingests the run from its staged copy (Argus never reads raw output back from S3). On Kubernetes that process is the run Job; there is no separate ingest Job and no S3 sweep (ADR-0039).
2. **Ingest.** Ingest runs the tool's adapter and upserts the canonical models. Relationship rules then derive edges from the new inventory, and lifecycle rules update states:
   - A finding seen again stays open and gets a new last-seen time.
   - A finding missing from a **complete** run that covered the same tool, account, region and check becomes resolved.
   - A resolved finding that comes back is marked reopened, which the dashboards count as a regression.
   - A failed or partial run never resolves anything. This rule prevents a scan timeout from looking like a fix.
   - A partial run still records what it evaluated: a partial Prowler run's check results and compliance (ThreatScore) are that day's values. Prowler on a real account is often throttled somewhere, and carrying the previous day forward would hide its results for good; the cost is that a throttled day can undercount, and the run shows as Partial (2026-10-06). A failed run has no results: the day keeps what it has, or the previous day's values are carried forward. For Prowler that includes the connection's requirement results (`compliance_snapshot`, within 31 days), and the framework scores are recomputed for the connection and for all connections, so a score history has no gap on a failed day (2026-10-07; before, the scores were left out that day).
3. **Snapshot.** The job writes the day's rows under snapshot\_date: resources with their config hash, new configurations, edges, failing findings and metric\_daily. Running the same day again replaces that day's rows, so a re-run never duplicates history.
4. **Find paths.** The attack-path engine runs every rule (SQL, with recursive queries for multi-hop paths) and upserts results into `attack_path`, resolving paths that no longer match.

**Manual edges** live only in Postgres, with author, reason and creation time, ingestion never deletes them, and the API adds them to every graph it returns. An endpoint can also be an external node (an on-prem network, a partner SaaS) that no collector will ever see. When a real endpoint disappears from the inventory, the edge is flagged stale in the UI instead of being dropped.

**Attack-path rules** are versioned files in the repository: id, name, severity, MITRE ATT&CK technique, description, remediation, and one read-only query that returns ordered paths: SQL over the edge tables, with recursive queries for multi-hop paths. We seed the library from Prowler's Apache-2.0 Attack Paths queries (ported to our graph) and the privilege-escalation catalog at pathfinding.cloud.

The rules worth most are the ones no single tool can produce. For example: a resource CloudFox marks as reachable from the internet, with a failing high-severity Prowler check, whose role CloudFox says can escalate to an admin role or read a sensitive data store.

Path severity starts from the rule. It goes up one level when the entry point is confirmed reachable and down one level when no resource on the path has a failing finding.

## History and dashboards

History comes from the daily snapshots, the compliance snapshots and the finding state changes, not from re-reading old reports. After each run, ingest recomputes `metric_daily`, so dashboards read small pre-aggregated rows.

| Metric | Computed from | Shown as |
| --- | --- | --- |
| Compliance score per framework | Requirements passed ÷ requirements assessed (manual ones excluded), per account and overall | Posture → Compliance (2026-10-07): every framework with its score, change and a 26-week sparkline; per framework, one line over time (6M, 3M, 1M), the month-end table, and each account's month-end score |
| Failing requirements | Latest `compliance_snapshot` (one connection) or `compliance_rollup` (all) | Per framework, the requirements by section with their status and checks; for all connections, how many accounts fail each. The drill-down to checks and resources comes later |
| Open findings by severity | `finding` states, daily | Line per severity over time |
| Opened vs resolved per week | `finding_event` | Bars about zero: opened above, resolved below |
| Mean time to resolve | Resolved at minus first seen, by severity | Bars per severity, last 90 days |
| Regressions | `finding_event` reopened rows | Count over time plus a list |
| Open attack paths | `attack_path` by severity | Line per severity over time |
| Inventory change | `resource`\_snapshot, day over day | Resources added and removed per week |

Every chart filters by cloud, account, framework and date range, and every point drills down to the findings or resources behind it. Charts are drawn in the Vue UI as SVG components built from the theme tokens (ADR-0027).

Retention: the database keeps six months of everything (see Canonical data models). Raw S3 files move to cheaper storage after 90 days and are deleted after 1 year, so a fixed adapter or rule can still be replayed over the whole six months.

## UI and API

The UI is a Vue app over a FastAPI backend, the same stack as Catheris. Users never touch Postgres directly.

| Screen | What people do there |
| --- | --- |
| Overview | MVP: KPIs, ThreatScore history, check results, findings by severity over time, attack paths by category and inventory (see Overview screen below) |
| Compliance | Read-only since 2026-10-07 (Posture → Compliance; [ui/screens.md](ui/screens.md) E9, E10): every Prowler framework with its score and trend; per framework the score history (6M, 3M, 1M), each account month by month, and the requirements by section. Later: requirement → failing checks → resources, export CSV and PDF, the Regressions view, and an overall average across accounts per provider (proposed by the user, set aside on 2026-10-07) |
| Findings | Read-only since 2026-10-06 (Investigate → Findings: filter, search, sort, remediation; [ui/screens.md](ui/screens.md) E7). Prowler-style filters since 2026-10-07: several values per filter (severity, connection, tool, category, service, resource type, check, region, result), muted, new in latest scan, all kept in the URL. A Reach filter (2026-10-22): Argus's verdict on a CloudFox public endpoint or a Prowler exposure check, with its reason in the expanded row; Prowler's exposure findings at Restricted are every disagreement between the tools. After roles: assign, accept a risk with an expiry date and a reason |
| Inventory map | Investigate → Resource map ([ADR-0033](adr/0033-resource-map.md), [ADR-0036](adr/0036-flow-mode.md); [ui/screens.md](ui/screens.md) E11). It starts from one list of front doors (reachable, unknown, restricted or CloudFox only, with the reason; judged by security groups, the subnet's route to an internet gateway and its network ACL, IPv4 and IPv6 apart, ADR-0035; a search by name, ARN or type and filters by reach and region, 2026-10-15) and draws one of two pictures, with no mode switch (2026-10-10). **Flow**: a door opens the whole chain its traffic and events reach, left to right, with security groups, roles and WAF as chips and finding badges. **Explore**: from Explore around on a node, a search, a resource or a door without a flow; expand neighbours step by step within one connection (another connection's resource is a boundary node); group nodes for many neighbours of one kind; columns by hop from the chosen resource, so a chain reads in order (2026-10-13); toggle layers by origin and kind; finding counts per tool as badges. A List view of the same data in both |
| Resource panel | Read-only since 2026-10-06 (Investigate → Resources and its sheet: properties, open findings, edges, tags, configuration; [ui/screens.md](ui/screens.md) E8). With the Resource map: one panel on both screens, a section per tool (Steampipe, Prowler, CloudFox), and the attack paths through it |
| Edge editor | After the Resource map, with the analyst role. Draw a manual connection between two resources or an external node, with a type and a reason |
| Attack paths | Investigate → Attack paths (planned 2026-10-08, ADR-0028 fourth amendment; [ui/screens.md](ui/screens.md) E12). One search from every internet entry to administrator, data stores, a neighbour on the network or a secret in a workload's environment, over every tool's edges, with moves by escalation permission name, lateral network ports and Systems Manager (2026-10-22, wave 3); every door is itself a path since 2026-10-22, high on an administrative or data port (Prowler 5.44.0's port lists) or when public by its own policy, low otherwise; outsiders' principals and users' leaked credentials are entries too; and paths are recomputed after every ingest (Steampipe, Prowler, CloudFox), so a Steampipe run alone shows them; with a confidence per step and per path (Confirmed, Supported, Candidate, Unknown, and Blocked for latent paths from a door Argus found closed, listed only when asked for and never counted on the Overview, 2026-10-21; [ADR-0037](adr/0037-attack-path-search.md)). Ranked list; each path shown as a chain of steps with its evidence and remediation per link (which edge to break); Open in map highlights it. Since 2026-10-23 (wave 4) every row says how the path gets in ("Exposed: tcp/22 (SSH)", "Leaked credential: access key"), every link names its move in words ("can escalate via iam:CreatePolicyVersion"), and a Kind filter sits beside Category |
| Administration | MVP: connections, schedules with Run now and the queue, runs with their logs, and settings (see Administration screen below). Users since 2026-10-28 (ADR-0041). Later: the audit log |

The map renders with Cytoscape.js and never loads the whole estate ([ADR-0033](adr/0033-resource-map.md)): the API builds nodes and edges from Postgres for the chosen resource and day, the neighbourhood endpoint caps depth at 3 hops and the response at 500 nodes, and more than 25 neighbours of one direction, edge type and resource type come back as one group node.

API rules:

- Versioned under `/api/v1`, described by an OpenAPI document committed with the code; the frontend's client is generated from it, and the running API never serves it (ADR-0025).
- Graph reads go through named server-side queries with parameters only; clients never send SQL.
- Every list is paginated; every response carries the scan time it reflects (data lists carry `data_through`, null when nothing has been ingested).
- Roles ([ADR-0041](adr/0041-users-and-roles.md), 2026-10-28; replaces viewer, analyst, admin): **Viewer** reads every screen except Users and Settings; **Operator** also manages connections, schedules and the queue; **Admin** also manages Settings and Users. Finding states and manual edges get their role when they are built. Every write is recorded in the audit log.

## Overview screen (MVP)

The Overview is the main MVP screen: one page that reads Prowler, CloudFox and Steampipe together, for any provider, as of the latest scan. The approved design is board D1 on the v3 page of the [CloudSec MVP Wireframes canvas](https://claude.ai/artifact/NEgBG5HKmBM6aD2KvP2JJs), in the R2 Titanium Signal theme on the v6 page. The UI is in English. Each block reads its own tool's latest scan on or before the day shown, so the page fills in whichever tool runs first and a tool that has not run leaves only its own blocks empty; zero open attack paths reads 0, not "no data" (2026-10-06). Changes from board D1 decided on 2026-10-03: the Overview shows the current state only (no point-in-time selector, no deltas against an earlier day; history stays in the strip, the pass-rate months and the severity series), and Inventory shows assets by type per provider instead of a 30-day chart.

| Block | What it shows | Source | History |
| --- | --- | --- | --- |
| Context bar | Provider, accounts, the date of the latest scan shown; last run time per tool | Run metadata | — |
| KPI cards | Monitored assets; ThreatScore with a bar to the 80 target; open critical findings; exploitable attack paths. Each shows the current value | Steampipe, Prowler, Prowler, CloudFox | — |
| ThreatScore strip | Month-end ThreatScore for the last 6 months, change per month, change since the first month; a select shows any framework with results instead (its requirement pass rate), remembered per browser (2026-10-15) | Prowler ThreatScore framework, or the chosen framework | 6 months, month-end; the current month is to date |
| Check results | Donut of all checks by Pass, Fail, Muted with the pass rate in the centre; not a link, because passed checks are not findings and no list holds that number (2026-10-10) | Prowler | Pass-rate columns by month, 6 months |
| Failed findings by severity | Bars for Critical, High, Medium, Low, Informational | Prowler | — |
| Findings severity over time | One line per severity with month bands; ranges 6M (month-end), 3M (weekly), 1M (daily); a legend that hides or shows each severity | Prowler | Month-over-month table under the chart: value and change per severity, plus a Total row |
| Attack paths by category | Paths per category (internet exposure, IAM privilege escalation, public data exposure, lateral movement, credential access), split by provider, with the CloudFox modules behind each | CloudFox, chained by our rules | — |
| Inventory | Assets by type, per provider: one section per provider with a bar per type group, on one scale; a provider not yet collected shows "not covered" | Steampipe | — |

**Drill-downs (2026-10-10).** Each number opens the list that holds it, filtered so the list reproduces it: KPIs, failed findings per severity, attack paths per category and the ThreatScore strip open Findings, Attack paths or the framework page, and an inventory type group opens in place to its largest types, each linked to Resources. The field-level map is in [`ui/screens.md`](ui/screens.md), "Overview drill-downs".

When data is missing the screen says why, never a zero: Prowler has no ThreatScore for OCI and CloudFox does not support OCI, so those blocks show "not covered". The MVP scans AWS only, so the provider selector lists GCP and OCI only once their collectors exist.

The history behind these blocks needs one daily rollup per provider, account and day in `metric_daily`: assets by type, ThreatScore and its pillars, checks by Pass, Fail and Muted, failed findings by severity, and attack paths by category. Month-end values and the 3M and 1M views are read from it.

## Administration screen (MVP)

The second MVP screen is where the platform is operated, so nothing needs a deploy (ADR-0028). Since 2026-10-06 its four parts are pages in the sidebar, following CatherIs Platform's navigation: **Operate** (Schedules, Runs) and **Administration** (Connections, Settings); an **Investigate** section above them holds the read-only Findings and Resources pages. The field-level specification is [`ui/screens.md`](ui/screens.md).

| Page | What it does |
| --- | --- |
| Connections | Accounts registered by hand (ADR-0021): Demo, AWS assume role, or AWS access key; enable or disable; secrets are write-only |
| Schedules | One or more tools each (queued in tool order), searchable by name: a cron expression with a plain-language preview and the next runs, the connections in scope, enabled or not; a minimum interval is enforced. Run now for chosen connections and tools, and the queue |
| Runs | Status, duration, exit code, throttle events and log tail per run, newest or oldest first, 20 per page; the actions a run was denied and raw output stored without KMS; runs in progress on top; a failed run also shows on the Overview context bar |
| Settings | Collection and throttling, retention, and the platform identity (ADR-0023) |

How a schedule becomes a run in Compose: the worker reads due schedules every minute and runs them through fixed code paths (ADR-0019). On Kubernetes (ADR-0039):

- The API only writes schedule and run\_request rows to Postgres; it holds no Kubernetes permissions.
- The scheduler, a single-replica Deployment with no Service, queues due schedules every minute and, every 2 seconds, starts the Jobs that claimable work needs, up to the UI's **Max parallel runs** and an environment bound. It never claims or runs work itself. A schedule is not a CronJob: one run per account, the global cap and staggered starts are the queue's (ADR-0022).
- Every Job comes from the chart's one fixed scan Job template (image digest, command, service account, environment, volumes). A ValidatingAdmissionPolicy denies any Job from the scheduler that differs from it, so a schedule chooses only the tools, the accounts and the time (ADR-0040).
- Only the scheduler's service account can create Jobs, and only in the platform's namespace; it cannot delete or change them, or touch pods, CronJobs or Secrets.
- Users sign in with local passwords (ADR-0041): no second factor until SSO, so the UI stays reachable only inside the cluster network (port-forward, or an internal load balancer behind the VPN) until SSO arrives.

## Visual design

The theme is Titanium Signal (option R2): neutral graphite surfaces, and one ice-cyan accent reserved for interaction. Everything else that has colour is data, so colour on screen always means something. Since 2026-10-13 the layout, type, density and decoration follow CatherIs Platform, the family's "mother" product, in these colours ([ADR-0028](adr/0028-mvp-second-screen-administration.md), fifth amendment).

Rules:

- The accent marks only what responds to the user: the active nav item, links, buttons, focus rings and the brand mark. Never a chart series or a status.
- Severity, pass/fail and provider colours are fixed across every screen. The light theme (2026-10-14) uses darker shades of the same hues, each checked for contrast ([design-system.md](ui/design-system.md), Light theme).
- Cards have a 1 px border and radius 14, no shadow; a card holding only a table is a flush panel. Ambient decoration (the aurora backdrop, glass tiles with a lit edge) sits behind or around data, never on a data mark.
- Data marks are lit (Signal Glow, 2026-10-03): saturated colours with a gradient and a glow of their own colour on the mark itself. Recipes in `docs/ui/design-system.md` → "Chart marks".
- Text: Inter for words, JetBrains Mono for numbers, ids and check names.
- Every status carries a label or icon as well as its colour.

| Token | Value | Used for |
| --- | --- | --- |
| bg | #08090A | Page background |
| bg-nav | #0B0C0E | Sidebar |
| surface | #141518 | Cards and the context bar |
| surface-raised | #1F2125 | Selected and hover rows |
| border | #24272B | Card and table borders |
| border-strong | #2E3237 | Inputs and dividers |
| text | #F6F7F8 | Primary text and figures |
| text-2 | #B4B9C1 | Secondary text |
| text-3 | #9297A0 | Labels and captions |
| accent | #5CE1E6 | Active nav, focus ring, brand mark |
| link | #8BEAEE | Links (hover #C2F4F6) |
| sev-critical | #FF4D78 | Critical, Fail |
| sev-high | #FF9640 | High |
| sev-medium | #FFD43B | Medium |
| sev-low | #F3EAC2 | Low |
| sev-info | #5E9BFF | Informational |
| pass | #2BF0A0 | Pass, improvement |
| muted | #6A6F77 | Muted findings |
| provider-aws / gcp / oci | #45B6FF / #A98BFF / #B2E35A | Provider series and dots |
| tool-prowler / steampipe / cloudfox | #AFB7FE / #BDC581 / #F8B6FE | Tool tags only: which tool a finding, run or schedule comes from (2026-10-07). Pastel on purpose, never a series |

These tokens go to the frontend as the single source for colour; no screen uses a value outside this table.

## Security of the platform

The platform holds a complete map of how to attack the organization, so it is treated as a tier-0 system: compromising it is as bad as compromising the clouds it scans.

| Area | Control |
| --- | --- |
| Cloud access | One read-only scanner role per account (SecurityAudit, ViewOnlyAccess, Prowler's additions policy without its one write, `securityhub:BatchImportFindings`, and CloudFox's documented custom policy, plus an explicit Deny on secret and data-plane reads and on bulk reads of code, images and log content (ADR-0018); see `deploy/aws/scanner-role.yaml`), assumed with an ExternalId by the platform identity: IRSA on the run service account on Kubernetes, the instance role or an access key on Compose; or an access key per connection, the administrator's choice (ADR-0024, amended 2026-10-24); GCP and OCI through identity federation (see Keyless multi-account access) |
| Scheduling | The API writes schedules but holds no Kubernetes permissions; only the scheduler creates Jobs, from one fixed template that a ValidatingAdmissionPolicy enforces field by field, and a ResourceQuota bounds how many; so neither the UI nor a compromised scheduler can choose an image, a command, a Secret or a service account (ADR-0040) |
| Cluster | A namespace for Argus alone under Pod Security `restricted`; default-deny NetworkPolicies (Postgres from its clients only, the API from web only, no route out except scan Jobs to port 443 outside the cluster and never link-local), proven by `helm test`; only the scheduler mounts a Kubernetes token; only scan Jobs have a cloud identity (ADR-0040) |
| Secrets in scan output | Adapters drop secret values; only "secret present at X" is stored. Run logs and error messages are redacted before they reach Postgres: tool table rows are dropped whole, credential shapes and secret-bearing assignments masked |
| Raw data in S3 | KMS encryption, Block Public Access, versioning, bucket policy limited to the collector and ingest roles |
| Databases | Postgres reachable only inside the namespace (ClusterIP plus NetworkPolicies), authentication on, never exposed to users |
| Users | Since 2026-10-28 ([ADR-0041](adr/0041-users-and-roles.md)): users in Postgres with argon2id hashes and one of three roles; the first admin is created once from the environment (a password or hash the operator removes after the first sign-in), and `admin-tools reset-password` recovers a forgotten one. HttpOnly, Secure, SameSite=Strict session cookie with CSRF double-submit; sign-in limits per 15 minutes: 5 failures for a username from one address, 20 from one address, 100 for a username from anywhere, so one attacker cannot keep the admin locked out; attempts for one username are serialized. Later: OIDC single sign-on with roles enforced in the API. Every login and write goes to the audit log from the start |
| App secrets | One existing Kubernetes Secret, which the chart never generates, optionally filled from AWS Secrets Manager by External Secrets; each pod gets only its own keys; never in images or Git. In Compose, a git-ignored `.env` (see `.env.example`) |
| Stored credentials | Connection secrets sealed with AES-256-GCM under an environment keyring, bound to their row; the API's database role cannot read them or the ExternalId (ADR-0024) |
| API surface | No OpenAPI document or docs UI served (ADR-0025); every route but health needs a session |
| Compose network | Two internal networks; Postgres reachable only from the API and the worker; the UI published on the loopback interface only; nginx the only trusted proxy |
| Supply chain | Tool versions and image digests pinned; images scanned with Trivy in CI; SBOM per release |
| Later outside-in probing | Only IPs the graph says we own, rate-limited, within AWS's penetration-testing policy; dangling DNS reported, never scanned |

## Deployment

One set of container images ships two ways: a Helm chart for Kubernetes (primary) and a Compose file for a single cloud instance (fallback).

| Component | Kubernetes | Docker Compose |
| --- | --- | --- |
| API (FastAPI) | Deployment, 2 replicas, disruption budget | One service |
| UI (Vue, served by nginx) | Deployment, 2 replicas; ClusterIP, no Ingress by default (`kubectl port-forward` until SSO) | One service, on the loopback interface |
| Scheduler | Deployment, 1 replica, `Recreate`, no Service; RBAC: create, get and list Jobs in the namespace | The worker service; no Docker socket |
| Collection and ingest | Scan Jobs from one fixed template (worker image): one Test connection or one AWS run per pod; AWS connections only (ADR-0039, amended 2026-10-26) | The worker service (ADR-0019), Demo connections included |
| Migrations, rederive, retention | A Job per image for migrate and rederive; a daily CronJob for retention | The `migrate` one-shot; the worker |
| Postgres | StatefulSet with a volume (the same image as Compose), or an external Postgres 17 over `verify-full`; monthly partitions; no backup yet (a nightly `pg_dump` to S3 is planned) | One service with a volume |
| Cloud credentials | IRSA on the run service account (Pod Identity by value), or an access key set in the UI; identity federation for GCP and OCI | The platform identity set in the UI: the instance's IAM role, or an access key (ADR-0024) |

Cost stays near zero beyond the cluster itself: read-only API calls are free, and the new bills are S3 storage for raw output and the Postgres volume, where six months of history at about 100,000 resources is estimated at under 10 GB. The phase 0 spike measures both.

## Architecture decisions

These decisions shape the platform; each is an ADR in [`adr/`](adr/README.md), which also records what supersedes what.

| ADR | Decision | Why | Revisit if |
| --- | --- | --- | --- |
| 001 | Build our own platform and use Prowler, CloudFox and Steampipe as collectors, instead of extending Prowler's self-hosted server | Multi-cloud attack paths, manual edges, history dashboards and team workflow don't exist upstream, and a fork becomes maintenance debt | Prowler's server ships history and manual edges |
| 002 | Postgres is the only database; the API builds the graph from its edge tables | At our size the map and path queries are indexed joins or recursive SQL; one database to run, back up and secure; a graph database would add a second store without a query that needs it | A rule needs deep path search SQL can't run in time: first networkx in ingest, then Apache AGE |
| 003 | Raw output of every run is kept, unchanged, in S3 | Adapters can be replayed after a bug fix; raw evidence for audits | Storage cost becomes material |
| 004 | `resource_uid` = provider + the cloud's global id (ARN, full resource name, OCID) | It is the one join key across tools; most integration bugs are id mismatches | A cloud has resources with no global id |
| 005 | The graph the API returns uses our canonical model and our own edge types for every origin (relationship rules, CloudFox, manual) | Stays tool-agnostic; Prowler's Attack Paths queries give the logic we port to SQL | A provider needs a relationship our edge model can't express |
| 006 | Relationships come from our own versioned rules over the raw inventory configuration, not from a graph-building tool | Collectors stay collectors; rules are reviewable, testable and replayable over past raw data; one edge model for AWS, GCP and OCI | Writing rules for the resource types we need costs more than adopting a graph tool |
| 007 | Manual edges are stored in Postgres and added to every graph the API returns | They survive re-ingestion and carry author and reason | — |
| 008 | Collectors and ingestion run as Kubernetes Jobs; no broker or long-running workers (superseded by 019 on Compose; restored on Kubernetes by 039) | Jobs isolate tool dependencies and credentials, and nothing runs between scans | On-demand runs need queueing or retries that Jobs can't give |
| 009 | Attack-path rules are versioned files (metadata plus SQL), and their results are stored | Paths get history like findings, and rules are reviewable and testable | — |
| 010 | The MVP ships Prowler, CloudFox and Steampipe inventory with the first relationship rules (ADR-006, ADR-012); the map and manual edges move to phase 2 | Delivers compliance history and attacker paths soonest, with the fewest moving parts | The team needs network-level dependencies before phase 2 |
| 011 | Attack-path rules run as SQL over the Postgres edge tables, with recursive queries for multi-hop paths | CloudFox already supplies multi-step paths, so a few joins don't justify a second database | Rules need deep or variable-length graph searches |
| 012 | Steampipe export CLIs collect the inventory: every column of a versioned table list, per account, as JSONL in S3 | Apache-2.0 plugins for AWS, GCP and OCI; standalone binaries with no database, service or login; batch output fits the raw archive. CloudQuery's official plugins became paid per row, and Cartography would decide relationships we want to own | Plugin coverage, schema churn or API throttling falls short for our accounts |
| 013 | The MVP UI is two screens, the executive Overview and Schedules, in the Titanium Signal theme (the second screen became Administration: 028) | Smallest UI that proves the pipeline end to end and lets the team run it without deploys; later screens reuse its components and tokens | Users can't act on what the Overview shows without the Findings list |
| 014 | Collectors authenticate without long-lived keys: Pod Identity and per-account roles on AWS; identity federation from the cluster's OIDC issuer on GCP and OCI | The platform is tier-0; one trust per account to audit and no key to rotate or leak | OCI federation can't be made to work from EKS |
| 015 | History is daily snapshots under snapshot\_date, kept six months in monthly partitions; configurations are stored once per hash | A past day is one WHERE clause; dropping a partition enforces retention; narrow integer rows and configurations stored once per hash keep six months near 8 GB at 100,000 resources | Retention must grow well beyond six months or the estate grows several times |
| 016 | Scan schedules are set in the UI and applied by a scheduler that creates CronJobs and Jobs from fixed templates (superseded by 019 on Compose; restored on Kubernetes by 039, with Jobs only) | Schedules change without a deploy; CronJobs keep native retries and history; the API never gets permission to create pods | Runs need dependencies between them that call for a workflow engine |
| 017 | Modular monolith: one Python package and image, run as api, ingest, scheduler and retention processes with separate service accounts; modules own their tables, boundaries checked in CI | One maintainer, one database, no part with its own scaling need; microservices would add network calls, contracts and deploys without a benefit, while separate processes still keep least privilege | A module needs its own scaling, release cadence or team |
| 018 | The scanner role denies bulk reads of code, images and log content | Configuration, yes; contents, never: a stolen session cannot exfiltrate images, code or logs | A requirement to detect secrets in code or logs (then a separate role) |
| 019 | Compose first: one worker process schedules, collects, ingests and runs retention | Runs anywhere without the Docker socket; the API still cannot choose what runs | The Kubernetes phase starts |
| 020 | The MVP is built on a synthetic estate in the tools' real formats; AWS comes last | Every stage exercised, six months of history on day one | The first real run disagrees with a synthetic format |
| 021 | Accounts are connection rows created in the UI; a run is one tool against one account | No Organizations discovery or hub role needed for an AWS-only MVP | Registering accounts by hand becomes error-prone |
| 022 | Throttling-aware collection: scheduling limits, call volume, adaptive SDK retries | Scans must never starve production, and a throttled run must never look like a fix | Measured throttle events stay high |
| 023 | Administration settings live in the UI; the environment holds deployment facts and bounds | A control an administrator can widen is not a control | A setting needs a different owner |
| 024 | AWS connections assume a role or use an access key, the administrator's choice (amended 2026-10-24: the environment bound is gone); secrets are write-only | Local testing, then the owner's choice of one behaviour everywhere | More than one administrator, or a deployment that must forbid long-lived keys |
| 025 | The OpenAPI document is committed and generates the client; the API never serves it | Renames fail the build; no unauthenticated map of a tier-0 API | A third party consumes the API |
| 026 | Module table ownership is enforced in SQL through exported queries and a test | import-linter cannot see SQL | A module becomes a service |
| 027 | Charts are SVG components; no global state store | Pixel-exact to the board, small bundle, strict CSP holds | Charts or shared state the components cannot handle |
| 028 | The second MVP screen is Administration; since 2026-10-06 its pages sit in two sidebar modules, Scans and Administration | Connections and settings moved into the UI | Users and roles arrived before SSO (ADR-0041) |

## Roadmap and MVP plan

&#91;embedded content: roadmap · 5 phases, each with an exit gate\]

Phase 1 is the MVP: the executive Overview and Administration screens on AWS, over Prowler compliance history, CloudFox attack paths and Steampipe inventory with the first relationship rules, built on the data models every later phase uses. Re-planned on 2026-10-02 (ADR-0019 to ADR-0024): the MVP is built in Compose on a synthetic estate, and the Phase 0 spike on a real account opens the AWS phase that follows it. The spike produces the fixtures the adapters are re-verified against, and proves the per-account role.

Phase 0 (spike):

1. Run Prowler and CloudFox on one AWS account and keep their outputs as adapter fixtures. Owner: backend-engineer.
2. Draft the id-mapping rules per resource type, so Prowler findings and CloudFox steps land on the same `resource_uid`. Owner: backend-engineer.
3. Measure run time and raw output size per account, to size the CronJobs and the S3 bill. Owner: cloud-native-platform-engineer.
4. Run the Steampipe AWS export on the same account through Pod Identity and a per-account role, with the first table list; confirm credential\_source works or switch to runner-assumed credentials, and keep the JSONL as fixtures. Owner: cloud-native-platform-engineer.

Phase 1 (MVP) milestones, in order. Each ends verified on the running stack and reviewed:

| # | Milestone | Owner | Status |
| --- | --- | --- | --- |
| M1 | Schema and migrations, monthly partitions, database roles and grants | backend-engineer (schema) | Done 2026-10-02 |
| M2 | Raw store, manifest, synthetic estate, credential sealing | backend-engineer | Done 2026-10-02 |
| M3 | Ingest: resolver, Steampipe adapter and relationship rules; Prowler adapter and lifecycle; CloudFox adapter, attack paths, `metric_daily`, retention | backend-engineer | Done 2026-10-02 |
| M4 | Worker: schedules, claims, heartbeat, retries, throttling layer 1 | backend-engineer | Done 2026-10-03 |
| M5 | API v1, admin sign-in and audit, query-budget test | backend-engineer | Done 2026-10-03 |
| M6 | Design of Administration and Sign in | product-ui-designer | Approved 2026-10-03 |
| M7 | Frontend: Overview, Administration, Sign in | frontend-engineer | Done 2026-10-03 |
| M8 | Security architecture, secure code and code reviews; fixes; documentation; the exit gate | the reviewers, each owner, documentation-writer | Done 2026-10-03; the exit gate passed ([gates/mvp-exit.md](gates/mvp-exit.md)). Two findings stay open as gates before the first real AWS run: raw tool output sits on an unencrypted local volume and moves to S3 with KMS, and a run whose ingest fails still shows `complete` |

MVP exit gate, on the synthetic estate. The procedure and the result are in [gates/mvp-exit.md](gates/mvp-exit.md):

- 180 days of per-framework compliance history from the API, with ThreatScore charted on the Overview (the per-framework chart belongs to the Compliance screen, after the MVP; built 2026-10-07)
- one attack path joined to a failing Prowler check, verified by hand
- a reopened finding recorded as a regression in `finding_event` and `metric_daily` (the Regressions view belongs to the Compliance screen, after the MVP)
- a failed run that resolved nothing
- the Overview renders every block, including 15 and 30 days back
- a resource's configuration and edges readable as of a past day
- a schedule changed in the UI runs at its new time without a restart
- a Demo connection created in the UI backfills and appears on the Overview
- a collection setting changed in the UI takes effect on the next claim, with no restart and no environment change
- an access-key connection is refused when `ARGUS_ALLOW_ACCESS_KEYS=false` (passed 2026-10-03; the switch was removed on 2026-10-24, ADR-0024)
- no secret is ever returned by the API or present in the logs

After the MVP, in order:

1. **AWS connection.** Raw output to S3 with KMS and a failed ingest shown as failed (both gate the first real run; done 2026-10-03, [ADR-0029](adr/0029-raw-output-storage-setting.md)). The `aws` source in the worker, with the three tools in its image and a regions setting; `collectors/` and `collectors/spike-run.sh` are deleted (done 2026-10-03, [ADR-0030](adr/0030-aws-source-in-the-worker.md)). First real scans done (2026-10-05). Done 2026-10-06, ahead of the rest of this item because ADR-0013's revisit condition was met: read-only **Findings** and **Resources** pages under a new Investigate section, with Schedules and Runs under Operate (ADR-0028, second amendment). Done 2026-10-07 (argus_v7): **Test connection** ([ADR-0024](adr/0024-connection-auth-methods.md), amended); the queue's **Cancel**, and schedules that cancel the runs they queued when disabled or deleted; each run's trigger and command; Prowler's per-result detail and each check's risk, description, links and remediation code on the Findings page; IAM users and access keys in the inventory. Done 2026-10-08 (argus_v8): only failed runs are retried; running runs shown live (CatherIs Platform's pattern); raw objects gzip-compressed in S3; the Steampipe inventory widened to every configuration table with per-table completeness, and IAM groups and customer policies linked to users, groups and roles. Deferred by the owner: Prowler's threat-detection checks and CloudFox's outbound-assumed-roles (CloudTrail lookups). Next: a real Steampipe run to confirm the table list; CloudFox's per-principal permission statements (needs a real fixture); then **every adapter re-verified against real output**, with the fixtures refreshed through the scrubber, starting with CloudFox's `loot/` commands (formats learnt from the emulator first, every module offline, 2026-10-14; built 2026-10-15: shown per resource and finding, labelled, never run, [ADR-0038](adr/0038-cloudfox-loot-commands.md)); throttling layers 2 and 3.
2. **Kubernetes and Helm.** Done 2026-10-25: the chart `charts/argus/`, a scheduler that starts scan Jobs from one fixed template ([ADR-0039](adr/0039-kubernetes-scheduler-and-run-jobs.md)), the trust boundaries enforced in the cluster ([ADR-0040](adr/0040-helm-chart-trust-boundaries.md)), and a kind harness that proves them ([gates/kubernetes-exit.md](gates/kubernetes-exit.md)). Next: the first install on EKS ([runbook-kubernetes.md](runbook-kubernetes.md)), and Postgres backups.
3. Phase 2 onward, as in the roadmap above.

Repository layout for the MVP:

```
catheris-argus/
│
├── backend/                         Python modular monolith: one image, four processes
│   ├── src/
│   │   └── argus/
│   │       ├── core/                config, database session, logging, audit, secrets, redaction, resource_uid resolver
│   │       ├── connections/         accounts and their credentials
│   │       ├── settings/            administration settings and their bounds
│   │       ├── collection/          raw stores (volume, S3), manifest, sources (synthetic, aws)
│   │       ├── ingest/              one run: adapter, rules, lifecycle, snapshots, paths, metrics
│   │       ├── retention/           partitions and raw-file pruning
│   │       ├── inventory/           Steampipe adapter, resources, snapshots, configurations
│   │       ├── relationships/       edge-rule engine, edge snapshots
│   │       ├── findings/            Prowler adapter, lifecycle, compliance
│   │       ├── attackpaths/         CloudFox adapter, attack-path engine
│   │       ├── metrics/             metric_daily rollups
│   │       ├── scheduling/          schedules, run requests, claims, the worker loop
│   │       ├── auth/                admin sign-in, sessions, sign-in limits
│   │       ├── api/                 FastAPI routers (module interfaces only)
│   │       └── entrypoints/         api, worker, scheduler, job, migrate, rederive, retention, seed, openapi, admin_tools
│   │
│   ├── rules/                       loaded by the engines at run time
│   │   ├── relationships/           edge rules (metadata + SQL)
│   │   └── attack_paths/            attack-path rules (metadata + SQL)
│   │
│   ├── migrations/                  Alembic
│   ├── tools/prowler/               Prowler's own uv project and lock, for the worker image
│   ├── tests/                       unit, adapter fixtures, rules/fixtures (one per rule), query-budget generator (fixed seed)
│   ├── openapi.json                 the API contract, rendered from the code (ADR-0025)
│   ├── pyproject.toml
│   └── Dockerfile                   argus-backend images: runtime (api), worker (+ the three tools)
│
├── frontend/                        Vue app
│   ├── src/
│   │   ├── views/                   overview, scans (schedules, runs), admin (connections, settings), sign-in
│   │   ├── components/              cards, tables, dialogs, sheets, fields
│   │   ├── composables/             resource loading, session, unsaved-changes guard, toasts
│   │   ├── api/                     client generated from backend/openapi.json only
│   │   └── theme/                   Titanium Signal tokens
│   ├── e2e/                         Playwright walk with axe (unit tests sit next to their source)
│   ├── nginx/                       the web image's server config and security headers
│   ├── package.json
│   └── Dockerfile                   argus-web image (static build on unprivileged nginx)
│
├── charts/
│   └── argus/
│       ├── Chart.yaml
│       ├── values.yaml
│       ├── values.schema.json       refuses tags, missing required values and unknown keys
│       ├── ci/                      values the checks render with
│       └── templates/
│           ├── backend/             api
│           ├── frontend/            web, internal ingress (off)
│           ├── scheduler/           the scheduler and its Role
│           ├── collectors/          the scan Job template's ConfigMap and its admission policy
│           ├── jobs/                migrate, rederive, retention
│           ├── postgres/            StatefulSet (off with an external database)
│           ├── security/            NetworkPolicies, ResourceQuota, ExternalSecret (off)
│           └── tests/               the helm test probe
│
├── deploy/
│   ├── aws/                         scanner-role CloudFormation (the StackSet body) + read-only policy check
│   └── kind/                        the chart's checks and a throwaway kind cluster (chart-check, kind)
│
├── docs/
│   ├── design.md                    this design
│   ├── runbook.md                   running and operating the stack on Compose
│   ├── runbook-kubernetes.md        installing and operating the chart
│   ├── ui/                          design system and screen specifications
│   ├── spikes/                      phase 0 runbook and results
│   ├── gates/                       each phase's exit-gate procedure and result
│   └── adr/
│
├── .github/
│   └── workflows/                   one workflow per top-level folder, path-filtered (once a remote exists)
│
├── compose.yaml                     local development and every command: docker compose run --rm <task>
├── compose.single-instance.yaml     the override for a shared host: no development defaults
├── .env.example                     every environment variable, with how to generate it
├── .editorconfig
├── README.md
└── LICENSE                          Apache-2.0
```

Changes to this layout made when implementation started (2026-10-02), recorded so the tree and the repository agree:

- **No Makefile.** `make` is not on the host, and nothing is installed there. Every task (`test`, `lint`, `scan`, `lock`, `scrub-fixtures`) is a one-shot compose service, run with `docker compose run --rm <task>` from the root `compose.yaml` (until 2026-10-24 a stub that included `deploy/compose/compose.yaml`).
- **No pre-commit.** It needs Python on the host. Its checks run in containers from the `lint` service: gitleaks, the read-only policy check, ruff, mypy and import-linter.
- **`deploy/aws/` added** for the scanner role (work item 2): a CloudFormation template, because StackSets take a CloudFormation body, plus `policycheck/`, which fails the build on any non-read action.
- **`.github/workflows/` waits for a remote.** The workflows will call the same compose services.

Changes made while building the MVP (2026-10-02 to 2026-10-03):

- **Modules added:** `connections`, `settings`, `collection`, `ingest` and `retention`, each owning its tables or its job.
- **The chart came with the Kubernetes phase** (2026-10-25); its home is `charts/argus/` (2026-10-24, was `deploy/helm/`). `deploy/aws/` holds the scanner role for assume-role connections; `deploy/kind/` the chart's checks and a throwaway cluster.
- **`collectors/` is gone (2026-10-03).** The worker image carries the tools, and the manifest's one definition is `backend/src/argus/core/manifest.py` ([ADR-0030](adr/0030-aws-source-in-the-worker.md)).
- **Rule fixtures live in `backend/tests/rules/fixtures/`**, not next to the rules, so the image ships rules only.
- **The frontend image is `argus-web`**, and frontend tests sit next to their source plus `e2e/`.

One repository, with a single owner and pipeline for each top-level folder:

| Folder | Owner | Builds | CI on change |
| --- | --- | --- | --- |
| backend/ | backend-engineer | argus-backend image | Lint, type check, import-linter boundaries, tests, migrations up and down, query-budget test |
| frontend/ | frontend-engineer | argus-web image | Lint, type check, tests, build; fails if the generated API client is out of date |
| charts/ | cloud-native-platform-engineer | The argus chart | helm lint, template and schema validation, install on a throwaway cluster |
| compose.yaml, compose.single-instance.yaml | cloud-native-platform-engineer | — | Start-up smoke test |
| deploy/aws/ | cloud-native-platform-engineer | — | cfn-lint, read-only policy check and its tests |
| deploy/kind/ | cloud-native-platform-engineer | argus-kind tooling image | `chart-check`; `kind up` and `kind test` on a throwaway cluster |
| docs/ | documentation-writer | — | Link check |

Rules:

- Backend and frontend share only the API contract: the backend publishes its OpenAPI file, and the frontend generates its client from it. Neither folder imports from the other.
- `backend/src/argus/core/manifest.py` is the only definition of the run manifest; collection validates what it writes and ingest validates what it reads.
- The chart deploys only images built from this repository, pinned by digest; it never builds code. The scheduler's RBAC and the collector job templates sit in their own template folders so they are easy to review.
- The query-budget dataset is generated in CI from a fixed seed, never committed.
- One copy of the design: this file. The Claude Doc it started as is retired.
- Everything is released together under one version: images are tagged with it and the chart's appVersion matches.

## Risks and open questions

The biggest risk is ids that fail to match across tools, which would silently disconnect findings from the map; it is addressed first, in phase 1.

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Ids don't match across tools, so findings detach from resources | High | High | Resolver with per-type rules, `unresolved_refs` shown in the UI, fixture tests from real output |
| A partial or failed scan marks open findings as resolved | Medium | High | Resolve only within the scope of a complete run; failed runs never resolve |
| CloudFox output exposes secret values | Medium | High | Adapter drops values; KMS-encrypted bucket with narrow access |
| The platform itself is compromised and the attack map leaks | Low | High | Tier-0 controls (Security section) |
| A tool upgrade changes its output format | Medium | Medium | Pinned versions, adapter version checks, fixture refresh, replay from S3 |
| The graph is too large to draw | Medium | Medium | Neighbourhood views only, with depth and node caps, group nodes for high-degree neighbours, noisy layers off by default (ADR-0033) |
| Scope creep into more clouds before AWS is solid | Medium | Medium | Phase gates; GCP and OCI only in phase 4 |
| One maintainer for many moving parts | High | Medium | Reuse tools unmodified; keep adapters small; no feature without an owner |
| Coverage gaps: CloudFox has no OCI support and Prowler has no OCI ThreatScore | High | Medium | The Overview shows "not covered", never zero; OCI attack paths need another source, decided before phase 4 |
| Relationship rules miss connections, so the map and paths look safer than they are | Medium | High | Coverage report of resource types no rule reads; a fixture per rule; CloudFox edges as a second source |
| Accounts × tables × regions hit API rate limits | Medium | Medium | Concurrency caps per account, the plugins' built-in retries, runs spread across the night, a parallel-tables setting, and per-table completeness so one throttled table does not freeze the others (the list covers every configuration table since 2026-10-08) |
| Keyless access for GCP or OCI doesn't work from EKS as designed | Medium | Medium | A spike before each provider is enabled; fallback to a rotated key in Secrets Manager for that provider only |
| The Administration screen can start scans while the MVP has one shared admin login | Medium | High | UI published only on the loopback interface (Compose) or inside the cluster network (Kubernetes) until SSO; a run is only a tool, an account and a time, executed by fixed code paths; the API holds no Kubernetes permissions or Docker socket |
| History grows faster than estimated | Low | Medium | Size measured in phase 0; monthly partitions dropped after six months; configurations stored once per hash |
| A dashboard or API query scans months of snapshots | Medium | Medium | Trends read metric\_daily only; snapshot queries filter one day; read-only API role with a statement timeout; query-budget test in CI |
| The synthetic formats drift from what the real tools emit, so adapters pass on fake data | Medium | High | Formats derived from the pinned tools' source; adapters are pure functions over raw files; the AWS phase starts by re-verifying every adapter on real output (ADR-0020) |
| One worker serialises a long Prowler run ahead of everything else | Medium (closed on Kubernetes 2026-10-25) | Low | On Kubernetes each AWS run is its own Job, up to **Max parallel runs** (ADR-0039); on Compose, acceptable at a single instance's scale |
| NetworkPolicy is not enforced (EKS's VPC CNI leaves it off), so any pod reaches Postgres or sets the client address the API records | Medium | High | A runbook prerequisite; `helm test` fails when policies are not enforced and is run after every install and upgrade; the install notes warn when the policies are off |
| The admission policy refuses fields by name, and a new Kubernetes field lets a compromised scheduler run code in a scan Job | Low | High | 38 refusal cases on kind; the runbook asks for a review of new PodSpec, Container and JobSpec fields on every version change (review SA-4, 2026-10-25) |
| The in-chart Postgres has no backup | Medium | High | Accepted in ADR-0040; a nightly `pg_dump` to S3, or an external managed database, before relying on the history |
| Scans throttle the account's own production APIs | Medium | High | One run per account, staggered starts, region scoping, adaptive SDK retries, low CloudFox concurrency; `throttle_events` measured on every run (ADR-0022) |
| A stored access key leaks | Low | High | Sealed at rest, write-only through the API, never logged, every change audited; offered on every install by the owner's decision of 2026-10-24 (ADR-0024, amended) |
| A setting is added as an environment variable out of habit | Medium | Low | The configuration split in CLAUDE.md and ADR-0023; a configuration-drift test is planned |
| Raw tool output, which can hold secret values, sits on an unencrypted local volume | Low (closed 2026-10-03) | High | AWS runs write to the operator's S3 bucket only, staged on a worker-only disk volume and deleted after upload ([ADR-0032](adr/0032-raw-staging-on-disk.md)); they cannot start while no bucket is set. Only Demo output uses the local volume ([ADR-0029](adr/0029-raw-output-storage-setting.md)) |
| Raw output with secret values sits under SSE-S3, without a key policy or a decrypt audit (accepted 2026-10-05) | Medium | High | The operator chooses the bucket's encryption; every run records it and the UI and worker log flag runs stored without KMS; the runbook asks for SSE-KMS and a bucket for Argus alone ([ADR-0031](adr/0031-raw-output-encryption-operator-choice.md)) |
| A permission the scanning identity lacks leaves data silently missing, so resources or findings look gone | Medium (mitigated 2026-10-05) | High | Denied actions are read from each tool's output and recorded per run; a CloudFox run with denials is partial and resolves nothing, and a Steampipe table with denials is out of its run's scope (per table since 2026-10-08); Runs lists both. CloudFox error lines that do not name the run's account are ignored (its error log is shared by concurrent runs) |
| Raw output is sent to a bucket the operator does not intend, because the bucket is an administration setting with no environment bound | Low | High | The platform identity's IAM policy allows `s3:PutObject` on one bucket only (runbook); every settings change is audited ([ADR-0029](adr/0029-raw-output-storage-setting.md)) |
| A run whose ingest fails shows as `complete`, so a gap in history goes unnoticed | Low (closed 2026-10-03) | Medium | Any ingest error marks the run `failed` with the reason in its log tail, carries the day's metrics forward and retries the run. A failure in the rules after a Steampipe or CloudFox load can leave that day's rows until the retry replaces them |

Open questions:

- [ ] How many AWS accounts and roughly how many resources are in scope today?
- [x] Which compliance frameworks matter most? Answered 2026-10-02: Prowler runs all checks in the regions in use, so every framework is scored from one run (ADR-0022).
- [x] Is EKS Pod Identity or IRSA already set up on the cluster? Answered 2026-10-24: IRSA (ADR-0040); Pod Identity is supported by a value.
- [ ] Is AWS Organizations available, with a delegated administrator account the hub role can list accounts from? (Not needed for the MVP: accounts are registered by hand, ADR-0021.)
- [ ] Should Catheris's EBS vulnerability findings come in later as one more adapter?
- [ ] License for a public release: Apache-2.0 assumed.
- [ ] CloudFox `cape` (cross-account escalation) needs pmapper (NCC Group PrincipalMapper) data, a tool this design does not include. Add pmapper as a fourth collector, or leave `cape` out of the MVP? Found 2026-10-02 while pinning CloudFox v2.0.5; decide during the phase 0 spike.

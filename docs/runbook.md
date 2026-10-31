# Runbook: running Argus with Docker Compose

**Owner:** `cloud-native-platform-engineer` (procedures) · `documentation-writer` (document)
**Applies to:** Compose as of 2026-10-03: Demo connections and AWS connections scanned by the
worker. Kubernetes has its own runbook: [runbook-kubernetes.md](runbook-kubernetes.md).

Argus runs as five Compose services: `postgres`, `migrate` (one-shot), `api`, `worker` and `web`.
How they fit together, and why: [design.md, How the MVP runs](design.md#how-the-mvp-runs).

## Prerequisites

- Docker with Compose v2. Nothing else is installed on the host; every command below runs in a
  container, from the repository root.
- Task services run as `${UID:-1000}`. Bash does not export `UID`, so on a host user other than
  1000, prefix commands with `UID=$(id -u) GID=$(id -g)`.
- The subnet `172.31.250.0/28` free on the host (the API's internal network, see
  [Troubleshooting](#troubleshooting)).

## First start

1. Create `.env` from the template. It is git-ignored; never commit it.

   ```bash
   cp .env.example .env
   ```

2. Choose the first admin's password (at least 12 characters; a long phrase works). Either put
   it in `.env` as `ARGUS_BOOTSTRAP_ADMIN_PASSWORD=...`, or keep only its hash there: the command
   prompts twice and prints the `ARGUS_BOOTSTRAP_ADMIN_PASSWORD_HASH` line to paste.

   ```bash
   docker compose run --rm admin-tools hash-password
   ```

   `migrate` creates this admin (`ARGUS_BOOTSTRAP_ADMIN_USERNAME`, default `admin`) on the first
   start, and only while no active admin exists ([ADR-0041](adr/0041-users-and-roles.md)).

3. Generate the credential keyring and paste both printed lines into `.env`.

   ```bash
   docker compose run --rm admin-tools new-secret-key
   ```

4. Build the images and start the stack. `migrate` runs the migrations and exits; the other
   services wait for it.

   ```bash
   docker compose up -d --build
   docker compose ps
   ```

   Expected: `postgres` and `api` show `healthy`, `web` turns `healthy` within a minute, and
   `worker` is `Up`.

5. Open <http://localhost:8080> and sign in as `admin` with the password from step 2. The UI is
   published on the loopback interface only. Then delete the bootstrap password (or hash) line
   from `.env`: the admin now lives in the database. Add everyone else in **Administration →
   Users**, each with their own role: Viewer reads, Operator also runs connections and
   schedules, Admin also changes Settings and Users.

6. Add history. Either create a Demo connection under **Administration → Connections** (choose
   how many days to backfill), or create three at once:

   ```bash
   docker compose run --rm seed --days 180
   ```

   The worker builds the history oldest day first. **Scans → Schedules** shows the queue
   and "Building history for …" with the runs left. 180 days is 540 runs per connection. At the
   MVP gate (2026-10-03), three connections (1,620 runs) took 192 s, with the worker peaking at
   180 MiB.

## Everyday commands

```bash
docker compose run --rm test                       # backend tests against Postgres
docker compose run --rm test pytest -k name        # one test
docker compose run --rm lint                       # gitleaks, policy check, ruff, mypy, import-linter
docker compose run --rm frontend pnpm check        # client current, lint, types, build, unit tests
ARGUS_E2E_PASSWORD='…' docker compose run --rm e2e # browser walk of every screen (needs the stack up)
docker compose run --rm scan                       # Trivy over files and images (build first)
docker compose --profile dev up frontend-dev       # Vite with hot reload on http://localhost:5173
```

After changing the API contract, regenerate both sides and commit the results
([ADR-0025](adr/0025-openapi-build-time-contract.md)):

```bash
docker compose run --rm openapi                    # writes backend/openapi.json
docker compose run --rm frontend pnpm api:generate # writes frontend/src/api/schema.d.ts
```

### Fixtures from another machine

Adapter fixtures come from real output ([ADR-0037](adr/0037-attack-path-search.md) relies on
CloudFox's). When the real scans run on another machine, scrub there and bring only the result:

1. On the scanning machine, after one complete run per tool, note the three run ids (Operate →
   Runs).
2. There, run `docker compose run --rm scrub-fixtures --run-id <prowler> <cloudfox> <steampipe>`.
   It replaces account ids, ARNs, names, emails and IPs with stable pseudonyms, drops secret
   values, and fails if any original value is left. The mapping (the real values) stays in that
   machine's spike directory, outside the repository.
3. Copy `backend/tests/fixtures/` (only that folder) to this repository, and run the tests.

### The emulator harness (dev only)

`mkdir -p -m 0777 emulated && docker compose --profile emulate run --rm emulate` runs the pinned
CloudFox and Steampipe export against moto (a fake AWS) on a network with no route out, and
writes their output and `report.json` to `emulated/`. The folder is git-ignored and holds the
fake estate's fake secrets.

- **What it is for.**
  - Learning the tools' file names and formats when no real fixture is at hand.
  - Checking that every Steampipe table exports the way production runs it (2026-10-13): the
    harness uses production's own table list, options and failure test, as a user holding the
    scanner role's policies with moto enforcing them.
  - `report.json` lists each table as ok, empty, partial or failed. A failure says why:
    - `denied`: the role lacks an action;
    - `emulator`: moto does not implement the API, or cannot check the signature of a JSON
      service;
    - `error`: anything else, and worth a look.
  - Moto enforces permissions reliably only on query-protocol services (EC2, IAM, ELB, RDS, …),
    which hold the network data the internet rules read.
  - `--table <name>` runs one table. `--no-options` drops production's column choices, which
    shows what they prevent: `aws_ec2_instance` fails on `ec2:GetLaunchTemplateData`.
- **What it is not.** It never replaces a real fixture or a real run: the values are moto's.
- **CloudFox's two outside files** (2026-10-14). CloudFox fetches AWS's region table and
  fwdcloudsec's known-accounts list on every run. The harness answers both itself: small
  stand-ins over HTTPS on `127.0.0.1:443`, with a CA made for the run that only the tools trust
  (`SSL_CERT_FILE`). `report.json` lists them under `outside_files_served`. CloudFox runs with
  moto's permission checks off, because they break moto's JSON services (Lambda, ECS, …);
  Steampipe runs with them on ([spike](spikes/cloudfox-loot.md)).
- `--skip-steampipe` runs CloudFox only, in about a minute.
- **The exposure scenario** (2026-10-21). `... run --rm emulate --scenario exposure --prowler`
  seeds only `backend/tests/tooling/exposure_estate.py`: one instance per way Prowler's exposure
  checks and Argus's internet rules can disagree, plus the entries and moves the attack-path
  rounds need. It exports the fixture's tables with moto's permission checks off, runs
  the pinned Prowler's `ec2_instance_*` checks against the same estate, and writes
  `emulated/scenario/` (`scenario.json` holds Prowler's verdict per case). The committed copy is
  `backend/tests/fixtures/emulated/exposure/`. It is the emulator's own fake estate, so it keeps
  its names and ids. Every secret value is redacted, and the scrubber's leak check runs on each
  file. To refresh it, copy `emulated/scenario/fixture/` over that folder and run
  `tests/ingest/test_exposure_scenarios.py`. Moto does not serve the account's S3 Block Public
  Access (`aws_s3_account_settings`), so the scenario's public bucket is Unknown; a real account
  exports it.
- **moto made AWS-shaped** (2026-10-21). The moto service loads
  `backend/tests/tooling/moto_fidelity/sitecustomize.py`, which fixes three answers where moto
  5.1.4 is unlike AWS and a pinned tool would fail:
  - a stopped instance's reason in GMT, which the Steampipe plugin parses;
  - an instance's own security groups;
  - Lambda's event source mapping path.

  Still not served: SSM managed instances, instance profile tags and instance metadata
  options.
- **Clean up.** Stop it with `docker compose --profile emulate rm -sf moto`.

After editing `backend/pyproject.toml`: `docker compose run --rm lock`, then rebuild with
`--build`. Never edit a lockfile by hand.

After changing backend code that the running stack uses: `docker compose up -d --build` rebuilds
`argus-backend:runtime` and recreates `api` and `worker`. A new migration runs on that start.

**After an upgrade, the worker derives again** (2026-10-21, ADR-0035 fifth amendment). Each rule
load records the rule set it came from. When the worker starts, before it claims any run, it
checks each enabled connection's latest rule load within 31 days. If that load came from other
rules (or from before migration 0026), the worker re-runs the load's day with the new rules:
edges, flows, the reach checks and attack paths. Nothing is resolved. So a new rule version shows
on the map and in Attack paths at once, not after the next Steampipe and CloudFox runs. The same
happens once when a release checks the reach of more findings (2026-10-22: Prowler's exposure
checks), so their Reach and reason show at once. The log
shows `re-derived after a rule upgrade` per connection, then `rule set checked` with the counts.
A failure is logged per connection (`re-derive failed`) and leaves that connection as it was
until its next Steampipe run. A disabled connection waits for its next run.

## Operating

**Settings.** Every administration setting is changed in **Administration → Settings** and is
audited; a change applies on the next claim, without a restart. The environment holds only
deployment facts and bounds ([ADR-0023](adr/0023-configuration-split.md)). To raise a bound (for
example `ARGUS_MAX_HISTORY_DAYS`), edit `.env` and run `docker compose up -d`.

**Logs.** Every service logs JSON lines to stdout:

```bash
docker compose logs -f worker
docker compose logs --since 1h api
```

**A run that seems stuck.** A claimed run sends a heartbeat every 30 seconds. If the worker dies,
its claims are requeued once they have been silent for 10 minutes, with a note in the request's
error. Restarting the worker (`docker compose restart worker`) lets runs in progress finish first
(grace period 2 minutes).

**A run waiting that you want gone.** In **Schedules → Queue**, **Cancel** removes a queued
run: a retry waiting for its turn ("Retry 3 of 3"), a scheduled run waiting for its stagger, a
Run now. A cancelled retry is not retried again, and **Run now** can then start the tool. A run
already running is not stopped from the UI. Disabling or deleting a schedule, or taking a tool
or a connection out of it, cancels the runs it had queued (since 2026-10-07). Every run says
in its details what started it and the command the worker ran.

**Testing a connection or the platform identity.** **Test connection**, in an AWS connection's
edit sheet and under **Settings → Platform identity**, asks the worker to sign in the way a scan
does ([ADR-0024](adr/0024-connection-auth-methods.md)): a connection assumes its role (or uses its
key) and must land in its own account; the identity signs in, then writes
`_argus/connection-test.txt` to each tool's folder of the raw output bucket, overwritten by every
test, and reports the encryption S3 applied. Neither reads or changes anything in a scanned
account. The result appears within seconds; if the worker is down, the test fails after two
minutes saying so.

**Locked out of sign-in.** Failures count for 15 minutes: 5 for a username from one address, 20
from one address, 100 for a username from anywhere. Wait, or ask an admin to open the user in
**Administration → Users** and choose **Unlock**.

**A forgotten password.** Another admin opens the user in **Administration → Users** and sets a
new one; the user chooses their own at the next sign-in. With no other admin, set it from the
api container (it asks for the new password twice; the user must change it at the next sign-in,
and their sessions end):

```bash
docker compose exec api python -m argus.entrypoints.admin_tools reset-password admin
```

**Changing your own password.** The key button in the sidebar's user block. Your other sessions
end; this one stays.

**Upgrading from the environment admin** (before 2026-10-28). An `.env` that still holds
`ARGUS_ADMIN_PASSWORD_HASH` makes `migrate` create that admin on the next start, with the same
password. Sign in once, then delete the `ARGUS_ADMIN_*` lines.

**Rotating the credential key.** Generate a key, prepend it to the keyring and make it current,
keeping the old one so stored secrets still open:

```bash
# .env, before:  ARGUS_SECRET_KEYS='k1:<old>'           ARGUS_SECRET_KEY_ID='k1'
# .env, after:   ARGUS_SECRET_KEYS='k2:<new>,k1:<old>'  ARGUS_SECRET_KEY_ID='k2'
docker compose up -d api worker
```

New secrets are sealed with `k2`. An existing secret moves to `k2` only when it is entered again
in the UI; there is no bulk re-seal yet, so keep `k1` until every access key has been re-entered.

**Raw output storage for AWS runs.** Demo connections write raw output to the local volume. AWS
connections write to your own S3 bucket and cannot run until one is set
([ADR-0029](adr/0029-raw-output-storage-setting.md)). Before the first AWS run:

1. Use a bucket for Argus alone: raw output maps the whole account. Set its default encryption
   to **SSE-KMS** with a customer-managed key. Raw output can hold secret values, and KMS adds a
   key policy and a decrypt audit trail that SSE-S3 does not. Argus stores whatever the default
   is and flags every run stored without KMS ([ADR-0031](adr/0031-raw-output-encryption-operator-choice.md)).
   Add a lifecycle rule that expires objects after one year: Argus never deletes from the bucket.
2. Give the platform identity this policy and nothing broader. It is the only control on where raw
   output can go, because the bucket is set in the UI. Replace the bucket, the folders if you
   changed them, and the key ARN:

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
           "arn:aws:s3:::BUCKET/raw/cloudfox/*"
         ]
       },
       {
         "Sid": "ArgusRawOutputKey",
         "Effect": "Allow",
         "Action": "kms:GenerateDataKey",
         "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
       }
     ]
   }
   ```

   The identity also needs `sts:AssumeRole` on each connection's scanner role
   ([ADR-0024](adr/0024-connection-auth-methods.md)).
3. On a machine with no instance or pod role, the identity is an access key: enter it in
   **Settings → Platform identity**.
   It can be an IAM user's key (`AKIA…`) or your SSO session's temporary credentials (`ASIA…`
   plus the session token, see below).
4. In **Settings → Raw output storage**, enter the bucket and its region, and change the folder per
   tool if you need to. The card shows "Bucket set".

A run whose upload fails shows as **Failed** in **Scans → Runs** with the reason in its log. A run
stored without KMS carries a **No KMS** badge, and the worker logs a warning. Only the worker has a route to the internet (`egress` network).

**Staging ([ADR-0032](adr/0032-raw-staging-on-disk.md)).** The worker writes each AWS run to the
`staging` volume (`/var/lib/argus-staging`, owner-only, mounted in the worker only). When the
tool finishes, it uploads every file to the bucket, `manifest.json` last, then deletes the run's
folder, whether the run succeeded or not. When the worker starts, it empties the volume and logs
"staging swept" with the number of runs it removed (runs a stopped worker left behind; their
requests are requeued). The volume is on the host's disk and holds raw output, secret values
included, until the upload ends: use an encrypted disk (full-disk encryption) on a machine that
scans a real account. Size the disk from the "collection finished" log line, whose `bytes` is
the run's size: the largest run times **Max parallel runs**, with room to spare. Run one worker
per staging volume, because each worker empties the volume when it starts. If staging fills up,
the run fails with "raw staging is full" and no manifest is uploaded, so it is never ingested.

Each run's folder in the bucket is
`<folder>/aws/<account>/<YYYY>/<MM>/<DD>/<run id>/`. **Scans → Runs** shows the run id (first
8 characters in the table, the full id and the raw location in the run's details).

**The first AWS scan, with an access key.** The worker runs Prowler, CloudFox
and Steampipe itself ([ADR-0030](adr/0030-aws-source-in-the-worker.md)). Set up raw output
storage first (above). Then:

1. In the account to scan, create an IAM user for scanning. Attach the AWS managed policies
   `SecurityAudit` and `ViewOnlyAccess`, and the scanner role's own three policies as customer
   managed policies. Print them from the template, so they are exactly what `lint` checks:

   ```bash
   docker compose run --rm policy-check python print_policies.py /work/scanner-role.yaml
   ```

   It prints `ArgusProwlerAdditions`, `ArgusCloudFoxAdditions` and `ArgusDenySecretReads`. Create
   one managed policy from each; together they are too large for one inline user policy. The
   Deny policy is not optional: it keeps secret values, data-plane items, code, images, log
   content and API key values out of reach even if the managed policies widen
   ([ADR-0018](adr/0018-scanner-role-denies-code-images-logs.md)). A hand-written inline policy that
   allows `logs:FilterLogEvents` or `lambda:GetFunction*`, or leaves out the Deny statements,
   breaks the read-only rule: replace it with these three. Create an access key for the user. Keep
   it separate from the platform identity, which can write to the bucket: the scanning identity
   must only read.
2. In **Administration → Connections → Add**, choose **Access key** and enter the account id and
   the scanning user's key.

   Instead of an IAM user you can use temporary credentials from an SSO session whose permission
   set is read-only (`SecurityAudit` and `ViewOnlyAccess`). Print them with the AWS CLI:

   ```bash
   aws sso login --profile <read-only profile>
   aws configure export-credentials --profile <read-only profile> --format env
   ```

   Enter `AWS_ACCESS_KEY_ID` (it starts with `ASIA`), `AWS_SECRET_ACCESS_KEY` and
   `AWS_SESSION_TOKEN`; the **Session token** field appears once the key id starts with `ASIA`.
   The credentials expire with the SSO session. When runs start failing with `ExpiredToken`,
   export a fresh set and enter it in the connection's edit sheet under **Access key → Replace**
   (or in **Settings → Platform identity**). A replacement is always the whole set: key id, secret
   and token.
3. In **Settings → Collection**, set **AWS regions to scan** to the regions in use, for example
   `eu-west-1, us-east-1`. Fewer regions make the first run faster. CloudFox ignores this and scans
   every region.
4. In **Scans → Schedules → Run now**, run the tools on the new connection. Steampipe goes first;
   Vulnerabilities last, after the inventory its CVEs attach to. On AWS it reads AWS Inspector:
   leave Vulnerabilities out if the account does not use Inspector, or its run ends Partial or
   Failed.
   While testing, set **Settings → Collection → Run now cooldown** to `0`: Run now then skips a
   tool only while it is already queued or running on that account. Set it back (the default is
   60 minutes) before scanning accounts other people depend on. **Minimum schedule interval**
   cannot go below 15 minutes.
5. Follow **Scans → Runs**. Each run ends **Complete**, **Partial** (throttled, or some Steampipe tables
   failed) or **Failed**, with the tool's log tail in the expanded row. A run whose output an
   adapter cannot read shows as **Failed** too, with the reason. So does a run that ended before
   it could be recorded (no bucket set, a manifest the database refused): its log tail starts
   "argus: the run ended before it was recorded:", followed by the error. Like any failed run, it is
   retried up to twice.

**Missing permissions.** The tools carry on when a call is denied (HTTP 403) and leave that
data out. Argus reads the denied actions from each tool's output and shows them on the run
("2 permissions missing"; the list is in the run's details, and the Runs filter **Missing
permissions only** finds them). A Steampipe or CloudFox run with denials is **Partial**, so it
resolves nothing; a Prowler run stays **Complete**, because a check that could not run has no
result (a Prowler run is Partial only when it was throttled, and the run says so). Add the
actions listed under **Missing from the role** to the scanning role or permission set (read
actions only) and run again.

Two other lists are not the role's to fix, and neither makes a run Partial
([ADR-0012](adr/0012-steampipe-export-clis.md), second amendment). **Refused by a policy**:
the resource's own policy refused the scanner (IAM says "because no resource-based policy
allows"), for example a KMS key whose key policy does not hand access to IAM, or a VPC endpoint
service the account does not own; or an explicit Deny did ("with an explicit deny in an
identity-based policy"), which is the scanner role's own Deny of secret values, code, log
content and API keys doing its job. Never add those to the role. Fix a key policy if you want
that key read; otherwise leave it. **Not used in this account**: the service is not set up here (Timestream for LiveAnalytics
answers 403 to anyone who is not already a customer, Organizations is not in use). Their tables
carry their resources forward. A table that stays in the Partial list on every run although its
service is not used means its error wording is not in the reviewed list yet
(`NOT_APPLICABLE` in `collection/aws/tools.py`): send the table's lines from the run's log tail.

One denied column can stop a whole Steampipe table. The pinned plugin logs `[ERROR]` and the
table is dropped from that run (the log says `table failed: <table>`). The fix is a narrower
export in `backend/src/argus/collection/tables.py`, not a wider role, when the column holds
contents Argus must not read. For example, `aws_ec2_instance` leaves out `launch_template_data`
and `user_data` (`ec2:GetLaunchTemplateData`, user data) since 2026-10-13. Before that, a real
scan inventoried no instances. Check a new table in the emulator harness first.

CloudFox ignores **AWS regions to scan** and scans every enabled region; its runs show "All
regions". In the bucket, a CloudFox run holds CloudFox's `json/`, `csv/`, `table/` and `loot/`
folders directly under the run id. Argus removes CloudFox's own `cloudfox-output/aws/<profile>-<account>/`
wrapper and changes no file.

**A run that is missing from Runs.** Since 2026-10-06 every request that ends leaves a run
in Runs. A request that ended without one, on an older build or when the database was unreachable,
keeps its error on the request. Read it with:

```bash
docker compose exec -T postgres psql -U argus -d argus -c \
  "SELECT id, tool, attempt, finished_at, error FROM run_request
   WHERE status = 'finished' AND scan_run_id IS NULL ORDER BY id DESC LIMIT 20"
docker compose logs worker | grep -E '"(run request failed|failed run not recorded)"'
``` Watch a run with `docker compose logs -f worker`: it logs "run started", "collection
finished", "raw output stored" and "run request finished", never the tools' output (CloudFox
prints secret values).

Rough durations depend on the account; Prowler is the longest. A run under an assumed role stops
after one hour (role session limit); an access-key run does not.

To refresh the test fixtures from a real run (the Phase 0 spike), see
[spikes/phase-0.md](spikes/phase-0.md). The scrubber reads `ARGUS_SPIKE_DIR`, not S3:

1. Note the three run ids (one per tool) on the Runs page.
2. Copy each run's folder from your raw bucket into
   `$ARGUS_SPIKE_DIR/raw/<tool>/aws/<account>/<YYYY>/<MM>/<DD>/<run_id>/`. The files are
   `<file>.gz` beside a plain `manifest.json` (since 2026-10-08); the scrubber reads them as
   they are.
3. Run `docker compose run --rm scrub-fixtures --run-id STEAMPIPE_ID PROWLER_ID CLOUDFOX_ID`.
   The fixtures land in `backend/tests/fixtures/` as plain files, every account id, name,
   address and secret value replaced; the mapping of original values stays in the spike
   directory, outside the repository. Files that hold secret values in free text are left out
   whole, and the command lists them as dropped: CloudFox's `env-vars` tables and loot (its CSV
   is kept with the Value column blanked), `instance-userdata.txt` and `cloudformation-data.txt`
   (2026-10-14).

**Starting over.** `docker compose down` stops the stack and keeps the data. `docker compose down -v`
also **deletes every volume: the database with all history, and the raw files**. There is no
undo.

## Single instance

For a shared host instead of a laptop, start with the override, which refuses the development
passwords and turns access keys off:

```bash
docker compose -f compose.yaml -f compose.single-instance.yaml up -d --build
```

Set these in `.env` first (see `.env.example`): `ARGUS_DB_PASSWORD`, `ARGUS_API_DB_PASSWORD`,
`ARGUS_WORKER_DB_PASSWORD`, `ARGUS_SECRET_KEYS`, `ARGUS_SECRET_KEY_ID`, and for the first start the
bootstrap admin's password or hash.
A missing one stops Compose before anything starts, naming the variable. The UI is still published
on `127.0.0.1` only; reach it through an SSH tunnel until SSO exists.

Not covered yet: backups. Until the backup procedure exists, a `pg_dump` taken with
`docker compose exec postgres pg_dump -U argus argus` is the only copy of the history.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Pool overlaps with other one on this address space` on `up` | Another network on the host uses `172.31.250.0/28` | Change the subnet, web's `ipv4_address` and `ARGUS_TRUSTED_PROXIES` together in `compose.yaml` |
| `network … not found` when running a task service | A stopped one-shot container still points at a network that was recreated | `docker compose --profile tools rm -f`, then run the task again |
| Root-owned files in the working tree | A task ran as uid 1000 on a host with another uid | Prefix with `UID=$(id -u) GID=$(id -g)` |
| `scan` reports an AWS key in `backend/.pytest_cache` | A parametrized test put a fake key in its test id | Give the cases explicit `ids=`, then delete `backend/.pytest_cache` |
| S3 or a tool says "The AWS Access Key Id you provided does not exist in our records" | An `ASIA…` key sent without its session token (before 2026-10-05 Argus had no token field), or a deleted IAM key | Replace the access key with the whole set, session token included |
| Old runs left objects in the bucket with no `manifest.json` | Before 2026-10-05 a run stored without KMS failed after its first upload | Delete those objects: without a manifest Argus never ingests them. A CloudFox `cached-data/*.gob` object holds raw API answers, env-var values included |
| Runs fail with `ExpiredToken` or "The security token included in the request is expired" | The temporary (SSO) credentials expired | Export a fresh set and replace the access key in the connection or in Platform identity |
| Test connection fails with "Could not assume the role: AccessDenied" | The role's trust policy does not name the platform identity, or the ExternalId differs | Fix the trust policy or add a new connection with the right ExternalId, then test again |
| Test connection fails with "Signed in, but to account …, not the connection's …" | The role ARN or key belongs to another account | Add a connection with the right account and disable this one |
| "Nothing queued: every tool you chose is already queued or running" while nothing runs | A retry or a scheduled run is waiting in the queue | Cancel it in **Schedules → Queue**, then use Run now |
| The API answers 401 and the UI returns to Sign in | The session expired (30 minutes idle) | Sign in again |

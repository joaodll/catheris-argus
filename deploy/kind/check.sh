#!/usr/bin/env bash
# chart-check: the chart's static checks, with no network (ADR-0040). Stops at the first failure.
#   docker compose run --rm chart-check
#
# For the ci/ values and the kind values: helm lint --strict, helm template, kubeconform (strict,
# offline schemas) on every resource and on each scan Job template inside the ConfigMap (one per
# work, ADR-0046), every image by digest. Then the renders that must be refused, and the Postgres image the same as
# compose.yaml's.
set -euo pipefail

CHART=/work/charts/argus
HERE=/work/kind
COMPOSE=/work/compose.yaml
# shellcheck source=versions.env
source "$HERE/versions.env"
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

# Placeholders for what run.sh learns at install time.
KIND_SET=(
  --set "images.runtime.digest=sha256:$(printf '1%.0s' {1..64})"
  --set "images.workerSteampipe.digest=sha256:$(printf '2%.0s' {1..64})"
  --set "images.workerProwler.digest=sha256:$(printf '4%.0s' {1..64})"
  --set "images.workerCloudfox.digest=sha256:$(printf '5%.0s' {1..64})"
  --set "images.web.digest=sha256:$(printf '3%.0s' {1..64})"
  --set "images.registry=localhost:${REGISTRY_PORT}"
  --set "networkPolicy.kubeApi.cidrs={172.18.0.2/32}"
  --set "networkPolicy.kubeApi.port=6443"
)

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

conform() {
  kubeconform -strict -summary -kubernetes-version "$KUBERNETES_VERSION" \
    -schema-location "$KUBECONFORM_SCHEMAS/{{.NormalizedKubernetesVersion}}-standalone{{.StrictSuffix}}/{{.ResourceKind}}{{.KindSuffix}}.json" \
    -skip ExternalSecret "$@"
}

check_render() {
  local name=$1; shift
  step "$name: lint and render"
  helm lint --strict "$CHART" -n argus "$@"
  helm template argus "$CHART" -n argus "$@" > "$OUT/$name.yaml"
  conform "$OUT/$name.yaml"

  step "$name: every image by digest"
  local tagged
  tagged=$(yq -N '.. | select(has("image")) | .image' "$OUT/$name.yaml" | grep -v '@sha256:[0-9a-f]\{64\}$' || true)
  [ -z "$tagged" ] || fail "images without a digest: $tagged"

  step "$name: the scan Job templates, one per work"
  local works=cloudfox,prowler,steampipe,test work
  [ "$(yq -N 'select(.kind == "ConfigMap" and .metadata.name == "argus-job-templates") | .data | keys | sort | join(",")' \
    "$OUT/$name.yaml")" = cloudfox.json,prowler.json,steampipe.json,test.json ] \
    || fail "the ConfigMap does not hold exactly one template per work ($works)"
  for work in ${works//,/ }; do
    yq -N "select(.kind == \"ConfigMap\" and .metadata.name == \"argus-job-templates\") | .data[\"$work.json\"]" \
      "$OUT/$name.yaml" > "$OUT/$name-$work.json"
    jq -e --arg w "$work" '.metadata.generateName and (.metadata.name | not)
        and .metadata.labels["argus/work"] == $w
        and .spec.template.metadata.labels["argus/work"] == $w
        and ([.spec.template.spec.containers[0].env[] | select(.name == "ARGUS_JOB_WORK") | .value] == [$w])
        and ([.spec.template.spec.containers[0].env[] | select(.name == "AWS_EC2_METADATA_DISABLED") | .value] == ["true"])' \
      "$OUT/$name-$work.json" > /dev/null \
      || fail "$work template: no generateName, a fixed name, or not its own work label, ARGUS_JOB_WORK or AWS_EC2_METADATA_DISABLED"
    conform "$OUT/$name-$work.json"
  done
  # Each work on its own image: the test Job on runtime, no two tools on one.
  [ "$(jq -r '.spec.template.spec.containers[0].image' "$OUT/$name-test.json")" \
    = "$(yq -N 'select(.kind == "Deployment" and .metadata.name == "argus-api") | .spec.template.spec.containers[0].image' "$OUT/$name.yaml")" ] \
    || fail "the test template does not run the runtime image"
  [ "$(for work in ${works//,/ }; do jq -r '.spec.template.spec.containers[0].image' "$OUT/$name-$work.json"; done | sort -u | wc -l)" = 4 ] \
    || fail "two works share one image"
}

check_render minimal -f "$CHART/ci/minimal-values.yaml"
check_render external-db -f "$CHART/ci/external-db-values.yaml"
# An external database needs only its host: the CA and its address ranges are optional.
HOST_ONLY=(-f "$CHART/ci/minimal-values.yaml" --set postgres.enabled=false --set postgres.external.host=db)
check_render external-db-host-only "${HOST_ONLY[@]}"
check_render kind -f "$HERE/values-kind.yaml" "${KIND_SET[@]}"

step "renders that must be refused"
refused() {
  local why=$1; shift
  if helm template argus "$CHART" -n argus -f "$CHART/ci/minimal-values.yaml" "$@" > /dev/null 2>&1; then
    fail "rendered, but must be refused: $why"
  fi
  echo "refused: $why"
}
refused "no trusted proxy range" --set api.trustedProxies=
refused "an image by tag" --set images.runtime.digest=latest
refused "the one worker image of before ADR-0046" --set images.worker.digest=sha256:$(printf '2%.0s' {1..64})
refused "a tool image without a digest" --set images.workerProwler.digest=
refused "one pod size for every scan Job, as before ADR-0046" --set scanJobs.resources.limits.memory=6Gi
refused "no Secret name" --set secrets.existingSecret=
refused "the admission policy off, unacknowledged" --set admissionPolicy.enabled=false
refused "an external database without a host" --set postgres.enabled=false --set "postgres.external.cidrs={10.0.0.0/24}"
refused "verify-full without a CA" --set postgres.enabled=false --set postgres.external.host=db --set postgres.external.sslmode=verify-full
refused "verify-ca without a CA" --set postgres.enabled=false --set postgres.external.host=db --set postgres.external.sslmode=verify-ca
refused "no Kubernetes API addresses" --set networkPolicy.kubeApi.cidrs=null
refused "instance metadata reachable from scan Jobs" --set "networkPolicy.scanEgressExcept={10.0.0.0/8}"
refused "autoscaling with min above max" --set api.autoscaling.enabled=true --set api.autoscaling.minReplicas=5 --set api.autoscaling.maxReplicas=3
refused "a volume claim for the scan scratch disk" --set scanJobs.scratch.storageClassName=gp3
refused "IRSA without a role" --set identity.roleArn=
refused "an unknown key" --set networkPolicy.enabeld=false
refused "more database connections than Postgres allows" --set api.autoscaling.enabled=true --set api.autoscaling.maxReplicas=10 --set scheduler.maxRunJobs=20 --set postgres.maxConnections=100
refused "a scan Job pool below a run's peak" --set database.pools.scanJob=2
refused "a session of no minutes" --set api.session.idleMinutes=0
refused "no sign-in failures allowed" --set api.signIn.maxFailures=0
refused "a lockout longer than retention keeps failures" --set api.signIn.lockoutMinutes=43201
refused "a history bound below the UI's minimum" --set retention.maxHistoryDays=10
# With the rest of a valid ingress, so it's refused for this reason and no other.
INGRESS=(--set web.ingress.enabled=true --set web.ingress.host=argus.example)
PEERS=(--set-json 'networkPolicy.webIngressFrom=[{"ipBlock":{"cidr":"10.0.64.0/24"}}]')
refused "an ingress the NetworkPolicy would block" "${INGRESS[@]}"
refused "an ingress with no host" --set web.ingress.enabled=true "${PEERS[@]}"
internet_facing=(--set-json 'web.ingress.annotations={"alb.ingress.kubernetes.io/scheme":"internet-facing"}')
notes=$(helm install argus "$CHART" -n argus --dry-run=client -f "$CHART/ci/minimal-values.yaml" \
  "${INGRESS[@]}" "${PEERS[@]}" "${internet_facing[@]}") || fail "an internet-facing ALB must render"
printf '%s\n' "$notes" | grep -q 'WARNING: this ALB is internet-facing' || fail "no warning for an internet-facing ALB"
echo "rendered with a warning: an internet-facing ALB"
notes=$(helm install argus "$CHART" -n argus --dry-run=client -f "$CHART/ci/minimal-values.yaml" \
  --set networkPolicy.enabled=false "${INGRESS[@]}") || fail "an ingress with the policies off must render"
printf '%s\n' "$notes" | grep -q 'any pod that reaches web can choose' || fail "no warning with the policies off"
echo "rendered with a warning: an ingress with the policies off"
helm template argus "$CHART" -n argus -f "$CHART/ci/minimal-values.yaml" \
  --set admissionPolicy.enabled=false --set admissionPolicy.acknowledgeUnenforced=true > /dev/null \
  || fail "the policy off, acknowledged, must render"
echo "rendered: the admission policy off, acknowledged"

step "the admission policy holds each toleration's seconds as written"
policy=$(helm template argus "$CHART" -n argus -f "$CHART/ci/minimal-values.yaml" \
  --show-only templates/collectors/admission-policy.yaml \
  --set-json 'scanJobs.tolerations=[{"key":"a","operator":"Exists","effect":"NoExecute","tolerationSeconds":0},{"key":"b","operator":"Exists","effect":"NoExecute","tolerationSeconds":3600000},{"key":"c","operator":"Exists","effect":"NoSchedule"}]')
# Values pass through YAML as floats on the way here, and a float prints 3600000 as 3.6e+06.
for seconds in '"key":"a","operator":"Exists","seconds":"0"' \
               '"key":"b","operator":"Exists","seconds":"3600000"' \
               '"key":"c","operator":"Exists","seconds":""'; do
  printf '%s\n' "$policy" | grep -qF "$seconds" || fail "the policy does not hold $seconds"
  echo "holds $seconds"
done

step "every pod takes the node placement it's given"
# Any new component without placement fails here: on a cluster with taints or two CPU types it
# lands on the wrong nodes (`exec format error` on the first EKS install).
placed() { printf '{"nodeSelector":{"check/placed":"yes"},"tolerations":[{"key":"check/placed","operator":"Exists"}]}'; }
placement=(--set-json "tasks=$(placed)" --set-json "api.nodeSelector=$(placed | jq -c .nodeSelector)"
  --set-json "api.tolerations=$(placed | jq -c .tolerations)")
for block in web scheduler postgres scanJobs; do
  placement+=(--set-json "$block.nodeSelector=$(placed | jq -c .nodeSelector)"
    --set-json "$block.tolerations=$(placed | jq -c .tolerations)")
done
helm template argus "$CHART" -n argus -f "$CHART/ci/minimal-values.yaml" "${placement[@]}" \
  | yq -o=json -I=0 'select(.kind)' > "$OUT/placement.json"
# jq: name, then whether the pod carries both; the scan templates are checked from inside their ConfigMap.
jq -r 'def pod: if .kind == "CronJob" then .spec.jobTemplate.spec.template.spec
         elif .kind == "Pod" then .spec else .spec.template.spec? // empty end;
       def report: "\(.metadata.name // .metadata.generateName) " +
         (if (pod.nodeSelector["check/placed"] == "yes") and (pod.tolerations[0].key? == "check/placed")
          then "placed" else "MISSING" end);
       (select(pod) | report),
       (select(.kind == "ConfigMap" and .metadata.name == "argus-job-templates")
          | .data[] | fromjson | report)' "$OUT/placement.json" | sort > "$OUT/placement.txt"
cat "$OUT/placement.txt"
if grep -q MISSING "$OUT/placement.txt"; then fail "a pod ignores its placement values"; fi
for needed in argus-api argus-web argus-scheduler argus-postgres argus-retention argus-netpol-probe argus-scan-test- argus-scan-steampipe- argus-scan-prowler- argus-scan-cloudfox- argus-migrate- argus-rederive-; do
  grep -q "^$needed" "$OUT/placement.txt" || fail "$needed is not in the render, so its placement wasn't checked"
done

step "only an ingress changes how web reads the client's address"
real_ip() { # <rendered file>
  yq -N 'select(.kind == "Deployment" and .metadata.name == "argus-web")
    | .. | select(has("env")) | .env[] | select(.name == "ARGUS_NGINX_REAL_IP") | .value' "$1"
}
expected='set_real_ip_from 0.0.0.0/0; set_real_ip_from ::/0; real_ip_header X-Forwarded-For; real_ip_recursive off;'
[ "$(real_ip "$OUT/external-db.yaml")" = "$expected" ] || fail "ingress on: web has '$(real_ip "$OUT/external-db.yaml")'"
[ -z "$(real_ip "$OUT/minimal.yaml")" ] || fail "ingress off: web still reads the client from a header"
echo "ingress on: $expected"
echo "ingress off: nothing set"

step "the limits reach the pods that read them"
limits=$(helm template argus "$CHART" -n argus -f "$CHART/ci/minimal-values.yaml" \
  --set retention.maxHistoryDays=500 --set api.session.idleMinutes=45 \
  --set api.signIn.maxFailuresPerAddress=33)
expect_env() { # <kind> <object> <variable> <value>
  local got
  got=$(printf '%s\n' "$limits" | yq -N "select(.kind == \"$1\" and .metadata.name == \"argus-$2\")
    | .. | select(has(\"env\")) | .env[] | select(.name == \"$3\") | .value" | head -1)
  [ "$got" = "$4" ] || fail "$2: $3 is '$got', expected $4"
  echo "$2: $3=$4"
}
# Retention deletes what is above its bound, so it must always hold the API's.
expect_env Deployment api ARGUS_MAX_HISTORY_DAYS 500
expect_env CronJob retention ARGUS_MAX_HISTORY_DAYS 500
expect_env Deployment api ARGUS_SESSION_IDLE_MINUTES 45
expect_env Deployment api ARGUS_LOGIN_MAX_FAILURES_PER_IP 33

step "an external database with only a host"
host_only="$OUT/external-db-host-only.yaml"
db_env() { # <rendered file> <variable>
  yq -N "select(.kind == \"Deployment\" and .metadata.name == \"argus-api\")
    | .. | select(has(\"env\")) | .env[] | select(.name == \"$2\") | .value" "$1" | head -1
}
db_ranges() { # <rendered file>
  yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "argus-database-clients")
    | .spec.egress[0].to[].ipBlock.cidr' "$1" | paste -sd,
}
[ "$(db_env "$host_only" ARGUS_DB_SSLMODE)" = require ] || fail "no CA: sslmode is not require"
[ -z "$(db_env "$host_only" ARGUS_DB_SSLROOTCERT)" ] || fail "no CA: a CA path is set"
[ "$(db_ranges "$host_only")" = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" ] \
  || fail "no ranges: database egress is $(db_ranges "$host_only"), expected private addresses only"
echo "no CA: sslmode=require; no ranges: private addresses only"
[ "$(db_env "$OUT/external-db.yaml" ARGUS_DB_SSLMODE)" = verify-full ] || fail "a CA: sslmode is not verify-full"
[ "$(db_ranges "$OUT/external-db.yaml")" = 10.0.32.0/20 ] || fail "ranges set: database egress is not exactly them"
echo "a CA: sslmode=verify-full; ranges set: exactly them"
notes=$(helm install argus "$CHART" -n argus --dry-run=client "${HOST_ONLY[@]}")
for gap in "sslmode=require" "postgres.external.cidrs is empty"; do
  printf '%s\n' "$notes" | grep -q "WARNING.*$gap" || fail "the install notes do not warn about: $gap"
done
echo "the install notes warn about both"

step "the Postgres image is compose.yaml's"
compose_digest=$(grep -o 'image: postgres:[^@]*@sha256:[0-9a-f]\{64\}' "$COMPOSE" | head -1 | sed 's/.*@//')
chart_digest=$(yq '.images.postgres.digest' "$CHART/values.yaml")
[ -n "$compose_digest" ] || fail "no pinned postgres image in compose.yaml"
[ "$compose_digest" = "$chart_digest" ] || fail "postgres: compose.yaml $compose_digest, chart $chart_digest"
echo "postgres $chart_digest"

printf '\nchart-check passed\n'

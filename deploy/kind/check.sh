#!/usr/bin/env bash
# chart-check: the chart's static checks, with no network (ADR-0040). Stops at the first failure.
#   docker compose run --rm chart-check
#
# For the ci/ values and the kind values: helm lint --strict, helm template, kubeconform (strict,
# offline schemas) on every resource and on the scan Job template inside the ConfigMap, every
# image by digest. Then the renders that must be refused, and the Postgres image the same as
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
  --set "images.worker.digest=sha256:$(printf '2%.0s' {1..64})"
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

  step "$name: the scan Job template"
  [ "$(yq -N 'select(.kind == "ConfigMap" and .metadata.name == "argus-job-templates") | .data | keys | join(",")' \
    "$OUT/$name.yaml")" = scan.json ] || fail "the ConfigMap holds another template than scan.json"
  yq -N 'select(.kind == "ConfigMap" and .metadata.name == "argus-job-templates") | .data["scan.json"]' \
    "$OUT/$name.yaml" > "$OUT/$name-scan.json"
  jq -e '.metadata.generateName and (.metadata.labels | length > 0) and (.metadata.name | not)' \
    "$OUT/$name-scan.json" > /dev/null || fail "scan template: no generateName, no labels, or a fixed name"
  conform "$OUT/$name-scan.json"
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
refused "a history bound below the UI's minimum" --set retention.maxHistoryDays=10
helm template argus "$CHART" -n argus -f "$CHART/ci/minimal-values.yaml" \
  --set admissionPolicy.enabled=false --set admissionPolicy.acknowledgeUnenforced=true > /dev/null \
  || fail "the policy off, acknowledged, must render"
echo "rendered: the admission policy off, acknowledged"

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

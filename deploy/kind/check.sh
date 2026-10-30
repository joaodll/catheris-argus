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
refused "an external database without addresses" --set postgres.enabled=false --set postgres.external.host=db
refused "no Kubernetes API addresses" --set networkPolicy.kubeApi.cidrs=null
refused "instance metadata reachable from scan Jobs" --set "networkPolicy.scanEgressExcept={10.0.0.0/8}"
refused "autoscaling with min above max" --set api.autoscaling.enabled=true --set api.autoscaling.minReplicas=5 --set api.autoscaling.maxReplicas=3
refused "a volume claim for the scan scratch disk" --set scanJobs.scratch.storageClassName=gp3
refused "IRSA without a role" --set identity.roleArn=
refused "an unknown key" --set networkPolicy.enabeld=false
refused "more database connections than Postgres allows" --set api.autoscaling.enabled=true --set api.autoscaling.maxReplicas=10 --set scheduler.maxRunJobs=20 --set postgres.maxConnections=100
refused "a scan Job pool below a run's peak" --set database.pools.scanJob=2
helm template argus "$CHART" -n argus -f "$CHART/ci/minimal-values.yaml" \
  --set admissionPolicy.enabled=false --set admissionPolicy.acknowledgeUnenforced=true > /dev/null \
  || fail "the policy off, acknowledged, must render"
echo "rendered: the admission policy off, acknowledged"

step "the Postgres image is compose.yaml's"
compose_digest=$(grep -o 'image: postgres:[^@]*@sha256:[0-9a-f]\{64\}' "$COMPOSE" | head -1 | sed 's/.*@//')
chart_digest=$(yq '.images.postgres.digest' "$CHART/values.yaml")
[ -n "$compose_digest" ] || fail "no pinned postgres image in compose.yaml"
[ "$compose_digest" = "$chart_digest" ] || fail "postgres: compose.yaml $compose_digest, chart $chart_digest"
echo "postgres $chart_digest"

printf '\nchart-check passed\n'

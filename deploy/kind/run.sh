#!/usr/bin/env bash
# kind: the chart on a throwaway kind cluster, and the checks that prove ADR-0039, ADR-0040 and
# ADR-0046 on it. Local only: it drives the host's Docker. Every value it makes is random and stays in the
# cluster.
#   docker compose build migrate web worker-steampipe worker-prowler worker-cloudfox
#                                               the five images, first
#   docker compose run --rm kind up             registry, cluster, images, the Secret, helm install
#   docker compose run --rm kind test           the checks; stops at the first failure
#   docker compose run --rm kind down           deletes the cluster and the registry
set -euo pipefail

HERE=/work/kind
CHART=/work/charts/argus
# shellcheck source=versions.env
source "$HERE/versions.env"
export KUBECONFIG=/tmp/kubeconfig
# The chart's fullname for this release name.
FULL=$RELEASE
HARNESS_NS=argus-kind-harness
SCHEDULER="system:serviceaccount:$NAMESPACE:$FULL-scheduler"

step() { printf '\n== %s\n' "$*"; }
ok() { printf 'ok    %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
k() { kubectl -n "$NAMESPACE" "$@"; }
psql_q() { k exec "statefulset/$FULL-postgres" -c postgres -- psql -U argus -d argus -tAXq -c "$1"; }
rand() { head -c 48 /dev/urandom | base64 -w0 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
kubeconfig() { kind get kubeconfig --name "$CLUSTER" > "$KUBECONFIG"; }

# ---- up -------------------------------------------------------------------------------------

push_image() {
  # Prints the digest the registry gave the image.
  local target="localhost:$REGISTRY_PORT/$1"
  docker tag "$1" "$target"
  docker push "$target" | sed -n 's/.*digest: \(sha256:[0-9a-f]\{64\}\).*/\1/p' | tail -1
}

make_secret() {
  if k get secret argus-secrets > /dev/null 2>&1; then
    # A cluster made before reports were kept in S3 has no password for their role yet.
    if [ -z "$(k get secret argus-secrets -o jsonpath='{.data.ARGUS_REPORTS_DB_PASSWORD}')" ]; then
      k patch secret argus-secrets --type merge \
        -p "{\"stringData\":{\"ARGUS_REPORTS_DB_PASSWORD\":\"$(rand 32)\"}}" > /dev/null
      ok "the Secret gained ARGUS_REPORTS_DB_PASSWORD"
    fi
    ok "the Secret exists; its values are kept"
    return
  fi
  local password hash env
  password=$(rand 24)
  hash=$(printf '%s' "$password" | docker run --rm -i --network none argus-backend:runtime \
    python -c 'import sys; from argon2 import PasswordHasher; print(PasswordHasher().hash(sys.stdin.read()))')
  env=$(mktemp)
  chmod 0600 "$env"
  {
    echo "ARGUS_DB_PASSWORD=$(rand 32)"
    echo "ARGUS_API_DB_PASSWORD=$(rand 32)"
    echo "ARGUS_WORKER_DB_PASSWORD=$(rand 32)"
    echo "ARGUS_SCHEDULER_DB_PASSWORD=$(rand 32)"
    echo "ARGUS_REPORTS_DB_PASSWORD=$(rand 32)"
    echo "ARGUS_SECRET_KEYS=k1:$(head -c 32 /dev/urandom | base64 -w0)"
    echo "ARGUS_SECRET_KEY_ID=k1"
    echo "ARGUS_BOOTSTRAP_ADMIN_PASSWORD_HASH=$hash"
  } > "$env"
  k create secret generic argus-secrets --from-env-file="$env" > /dev/null
  rm -f "$env"
  # For `test` to sign in: kept outside Argus's namespace, in this throwaway cluster only.
  kubectl create namespace "$HARNESS_NS" --dry-run=client -o yaml | kubectl apply -f - > /dev/null
  kubectl -n "$HARNESS_NS" create secret generic admin-password --from-literal=password="$password" > /dev/null
  printf '\nadmin password (shown once): %s\n' "$password"
}

install() {
  local runtime=$1 steampipe=$2 prowler=$3 cloudfox=$4 web=$5 reports=$6 api_ip api_port
  api_ip=$(kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
    -o jsonpath='{.items[0].endpoints[0].addresses[0]}')
  api_port=$(kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
    -o jsonpath='{.items[0].ports[0].port}')
  helm upgrade --install "$RELEASE" "$CHART" -n "$NAMESPACE" -f "$HERE/values-kind.yaml" \
    --set "images.registry=localhost:$REGISTRY_PORT" \
    --set "images.runtime.digest=$runtime" \
    --set "images.workerSteampipe.digest=$steampipe" \
    --set "images.workerProwler.digest=$prowler" \
    --set "images.workerCloudfox.digest=$cloudfox" \
    --set "images.reports.digest=$reports" \
    --set "images.web.digest=$web" \
    --set "networkPolicy.kubeApi.cidrs={$api_ip/32}" \
    --set "networkPolicy.kubeApi.port=$api_port" \
    --wait --timeout 15m
}

up() {
  local image
  for image in argus-backend:runtime argus-backend:worker-steampipe argus-backend:worker-prowler \
               argus-backend:worker-cloudfox argus-backend:reports argus-web:runtime; do
    docker image inspect "$image" > /dev/null 2>&1 \
      || fail "no $image: docker compose build migrate web worker-steampipe worker-prowler worker-cloudfox reports"
  done

  step "local registry on 127.0.0.1:$REGISTRY_PORT"
  # Created once; started again when it stopped (a Docker or host restart: it never restarts).
  if docker inspect "$REGISTRY_NAME" > /dev/null 2>&1; then
    [ "$(docker inspect -f '{{.State.Running}}' "$REGISTRY_NAME")" = true ] \
      || docker start "$REGISTRY_NAME" > /dev/null
  else
    docker run -d --restart=no --name "$REGISTRY_NAME" -p "127.0.0.1:$REGISTRY_PORT:5000" "$REGISTRY_IMAGE" > /dev/null
  fi
  ok "$REGISTRY_NAME"

  step "cluster $CLUSTER"
  kind get clusters 2>/dev/null | grep -qx "$CLUSTER" \
    || kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --config "$HERE/cluster.yaml" --wait 180s
  kubeconfig
  local node dir="/etc/containerd/certs.d/localhost:$REGISTRY_PORT"
  for node in $(kind get nodes --name "$CLUSTER"); do
    docker exec "$node" mkdir -p "$dir"
    printf '[host."http://%s:5000"]\n' "$REGISTRY_NAME" | docker exec -i "$node" cp /dev/stdin "$dir/hosts.toml"
  done
  docker network inspect kind -f '{{range .Containers}}{{.Name}} {{end}}' | grep -qw "$REGISTRY_NAME" \
    || docker network connect kind "$REGISTRY_NAME"
  ok "nodes pull localhost:$REGISTRY_PORT from $REGISTRY_NAME"

  step "images, by digest"
  local runtime steampipe prowler cloudfox web reports
  runtime=$(push_image argus-backend:runtime)
  reports=$(push_image argus-backend:reports)
  steampipe=$(push_image argus-backend:worker-steampipe)
  prowler=$(push_image argus-backend:worker-prowler)
  cloudfox=$(push_image argus-backend:worker-cloudfox)
  web=$(push_image argus-web:runtime)
  [ -n "$runtime" ] && [ -n "$steampipe" ] && [ -n "$prowler" ] && [ -n "$cloudfox" ] && [ -n "$web" ] \
    && [ -n "$reports" ] || fail "a push gave no digest"
  ok "runtime   $runtime"
  ok "steampipe $steampipe"
  ok "prowler   $prowler"
  ok "cloudfox  $cloudfox"
  ok "reports   $reports"
  ok "web       $web"

  step "namespace $NAMESPACE (Pod Security restricted) and the Secret"
  kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - > /dev/null
  kubectl label namespace "$NAMESPACE" --overwrite \
    pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/warn=restricted > /dev/null
  make_secret

  step "helm install"
  install "$runtime" "$steampipe" "$prowler" "$cloudfox" "$web" "$reports"
  ok "installed; next: docker compose run --rm kind test"
}

# ---- test -----------------------------------------------------------------------------------

can() {
  local expect=$1; shift
  local answer
  answer=$(kubectl auth can-i --as="$SCHEDULER" -n "$NAMESPACE" "$@" 2>/dev/null || true)
  [ "$answer" = "$expect" ] || fail "scheduler can-i $*: $answer, expected $expect"
  ok "scheduler can-i $*: $answer"
}

# A Job as the scheduler would create it, through the admission chain without being stored.
create_as_scheduler() {
  kubectl create -n "$NAMESPACE" --as="$SCHEDULER" --dry-run=server -o name -f - 2>&1
}

# name | jq change
BAD_JOBS=(
  'another image|.spec.template.spec.containers[0].image = "registry.k8s.io/pause:3.10"'
  'another command|.spec.template.spec.containers[0].command = ["sh", "-c", "env"]'
  'arguments|.spec.template.spec.containers[0].args = ["--help"]'
  'the whole Secret as env|.spec.template.spec.containers[0].envFrom = [{"secretRef": {"name": "argus-secrets"}}]'
  'the owner password|(.spec.template.spec.containers[0].env[] | select(.name == "ARGUS_DB_PASSWORD") | .valueFrom.secretKeyRef.key) = "ARGUS_DB_PASSWORD"'
  'another database host|(.spec.template.spec.containers[0].env[] | select(.name == "ARGUS_DB_HOST") | .value) = "db.attacker.example"'
  'an extra variable|.spec.template.spec.containers[0].env += [{"name": "AWS_ROLE_ARN", "value": "x"}]'
  'the default account on a scan Job|.spec.template.spec.serviceAccountName = "default"'
  'a mounted token|.spec.template.spec.automountServiceAccountToken = true'
  'the host network|.spec.template.spec.hostNetwork = true'
  'an init container|.spec.template.spec.initContainers = [.spec.template.spec.containers[0] | .name = "init"]'
  'a second container|.spec.template.spec.containers += [.spec.template.spec.containers[0] | .name = "side"]'
  'a hostPath volume|.spec.template.spec.volumes += [{"name": "host", "hostPath": {"path": "/"}}]'
  'a volume claim for the scratch disk|(.spec.template.spec.volumes[] | select(.name == "scratch")) = {"name": "scratch", "ephemeral": {"volumeClaimTemplate": {"spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}}}}'
  'a Secret volume|(.spec.template.spec.volumes[] | select(.name == "scratch")) = {"name": "scratch", "secret": {"secretName": "argus-secrets"}}'
  'privileged|.spec.template.spec.containers[0].securityContext += {"privileged": true, "allowPrivilegeEscalation": true}'
  'root|.spec.template.spec.securityContext.runAsUser = 0'
  'a named node|.spec.template.spec.nodeName = "'"$CLUSTER"'-control-plane"'
  'one more toleration|.spec.template.spec.tolerations += [{"operator": "Exists"}]'
  'a toleration of every taint in place of one|.spec.template.spec.tolerations[0] = {"operator": "Exists"}'
  'a toleration kept for longer|(.spec.template.spec.tolerations[] | select(has("tolerationSeconds")) | .tolerationSeconds) = 3600'
  'a toleration kept for good|.spec.template.spec.tolerations |= map(del(.tolerationSeconds))'
  'the API component label|.spec.template.metadata.labels["app.kubernetes.io/component"] = "api"'
  'another label|.spec.template.metadata.labels["example.com/extra"] = "x"'
  'more pods|.spec.parallelism = 10'
  'a longer deadline|.spec.activeDeadlineSeconds = 864000'
  'an annotation|.spec.template.metadata.annotations["cluster-autoscaler.kubernetes.io/safe-to-evict"] = "true"'
  # A probe or hook runs a command of its own in the pod, with its identity and keyring.
  'an exec startup probe|.spec.template.spec.containers[0].startupProbe = {"exec": {"command": ["python", "-c", "print(1)"]}}'
  'an exec liveness probe|.spec.template.spec.containers[0].livenessProbe = {"exec": {"command": ["sh", "-c", "id"]}}'
  'an exec readiness probe|.spec.template.spec.containers[0].readinessProbe = {"exec": {"command": ["sh", "-c", "id"]}}'
  'a postStart hook|.spec.template.spec.containers[0].lifecycle = {"postStart": {"exec": {"command": ["sh", "-c", "id"]}}}'
  'its own DNS|.spec.template.spec.dnsPolicy = "None" | .spec.template.spec.dnsConfig = {"nameservers": ["10.244.0.99"]}'
  'another scheduler|.spec.template.spec.schedulerName = "other"'
  'a manual selector|.spec.manualSelector = true | .spec.selector = {"matchLabels": .spec.template.metadata.labels}'
  'kept forever|.spec.ttlSecondsAfterFinished = 99999999'
  'a pod deadline|.spec.template.spec.activeDeadlineSeconds = 99999'
  'a mount over the code|.spec.template.spec.containers[0].volumeMounts += [{"name": "tmp", "mountPath": "/opt/venv/lib"}]'
  'a subPath mount|(.spec.template.spec.containers[0].volumeMounts[] | select(.name == "tmp")) += {"subPath": "x"}'
  'the root group|.spec.template.spec.securityContext.runAsGroup = 0'
  'extra groups|.spec.template.spec.securityContext.supplementalGroups = [0]'
  'a terminal|.spec.template.spec.containers[0].tty = true | .spec.template.spec.containers[0].stdin = true'
)

# A pod with the given component label, so the matching NetworkPolicies apply; it tries each
# host:port and prints "host:port open" or "host:port closed".
# A pod's traffic can pass until kindnet has applied the policies to it, so the probe waits and tests
# the running state (without the wait it passed on timing, and failed under load, 2026-11-03). What
# a new pod reaches at its start is measured by helm test's probe.
probe_from() {
  local name=$1 component=$2; shift 2
  local image pod="$FULL-probe-$name"
  image=$(k get deploy "$FULL-api" -o jsonpath='{.spec.template.spec.containers[0].image}')
  k delete pod "$pod" --ignore-not-found --wait > /dev/null
  jq -n --arg name "$pod" --arg image "$image" --arg component "$component" \
        --arg release "$RELEASE" --args '$ARGS.positional as $targets | {
    apiVersion: "v1", kind: "Pod",
    metadata: {name: $name, labels: {
      "app.kubernetes.io/name": "argus", "app.kubernetes.io/instance": $release,
      "app.kubernetes.io/component": $component}},
    spec: {
      restartPolicy: "Never", automountServiceAccountToken: false, enableServiceLinks: false,
      securityContext: {runAsNonRoot: true, runAsUser: 10001, seccompProfile: {type: "RuntimeDefault"}},
      containers: [{name: "probe", image: $image,
        command: (["python", "-c", "import socket, sys, time\ntime.sleep(10)\nfor t in sys.argv[1:]:\n    h, p = t.rsplit(\":\", 1)\n    try:\n        socket.create_connection((h, int(p)), timeout=4).close(); print(t, \"open\")\n    except OSError:\n        print(t, \"closed\")"] + $targets),
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}},
        resources: {requests: {cpu: "10m", memory: "32Mi"}, limits: {memory: "64Mi"}}}]}}' "$@" \
    | k create -f - > /dev/null
  local phase
  for _ in $(seq 60); do
    phase=$(k get pod "$pod" -o jsonpath='{.status.phase}')
    [ "$phase" = Succeeded ] || [ "$phase" = Failed ] && break
    sleep 2
  done
  k logs "$pod"
  k delete pod "$pod" --wait=false > /dev/null
}

expect_reach() {
  # expect_reach <probe output> <who> <host:port> open|closed
  local got
  got=$(printf '%s\n' "$1" | awk -v t="$3" '$1 == t {print $2}')
  [ "$got" = "$4" ] || fail "$2 -> $3: ${got:-no answer}, expected $4"
  ok "$2 -> $3 $4"
}

test_limits() {
  step "the limits reach the processes"
  local got
  got=$(k exec "deploy/$FULL-api" -c api -- python -c \
    'from argus.core.config import get_settings as g; s = g(); print(s.max_history_days, s.session_idle_minutes)')
  [ "$got" = "500 45" ] || fail "the API reads '$got', expected 500 45"
  ok "the API reads the history bound and the session limit from the chart"
  got=$(k get cronjob "$FULL-retention" -o json \
    | jq -r '.spec.jobTemplate.spec.template.spec.containers[0].env[] | select(.name == "ARGUS_MAX_HISTORY_DAYS") | .value')
  [ "$got" = 500 ] || fail "retention's history bound is '$got', expected 500"
  ok "retention holds the API's history bound"
  # Reports in S3 (ADR-0047 round 5): the API knows where, and kind gives it no identity, so the
  # Reports screen says so rather than asking a node's role.
  got=$(k exec "deploy/$FULL-api" -c api -- python -c \
    'from argus.core.config import get_settings as g; from argus.core.aws import web_identity_available as w; print(g().reports_store, w())')
  [ "$got" = "s3 False" ] || fail "the API reads '$got', expected s3 False"
  ok "the API keeps reports in S3, and has no identity on kind"
}

test_install() {
  step "the install"
  local d
  for d in api web scheduler; do
    k rollout status "deploy/$FULL-$d" --timeout 300s > /dev/null
    ok "deploy/$FULL-$d available"
  done
  k rollout status "statefulset/$FULL-postgres" --timeout 300s > /dev/null
  ok "statefulset/$FULL-postgres ready"
  for d in migrate rederive; do
    k wait --for=condition=complete job -l "app.kubernetes.io/component=$d" --timeout 600s > /dev/null
    ok "the $d Job completed"
  done
  [ "$(kubectl get namespace "$NAMESPACE" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')" = restricted ] \
    || fail "the namespace does not enforce Pod Security restricted"
  ok "every pod admitted under Pod Security restricted"
}

test_rights() {
  step "the scheduler's Kubernetes rights"
  can yes create jobs.batch
  can yes list jobs.batch
  can no delete jobs.batch
  can no patch jobs.batch
  can no create pods
  can no create cronjobs.batch
  can no get secrets
  can no list secrets
  can no create deployments.apps
  can no create jobs.batch -n default
  local sa accounts tokens
  for sa in default "$FULL-run" "$FULL-api" "$FULL-report"; do
    [ "$(kubectl auth can-i --as="system:serviceaccount:$NAMESPACE:$sa" -n "$NAMESPACE" create jobs.batch 2>/dev/null || true)" = no ] \
      || fail "$sa can create Jobs"
  done
  ok "no other service account can create Jobs"
  # The chart's own accounts (api and report: reports in S3 on IRSA); every other pod runs as
  # default.
  accounts=$(k get serviceaccounts -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | sort | tr '\n' ' ')
  [ "$accounts" = "$(printf '%s\n' default "$FULL-run" "$FULL-scheduler" "$FULL-api" "$FULL-report" | sort | tr '\n' ' ')" ] \
    || fail "service accounts: $accounts"
  [ "$(k get deploy "$FULL-api" -o jsonpath='{.spec.template.spec.serviceAccountName}')" = "$FULL-api" ] \
    || fail "the API does not run as $FULL-api"
  ok "the API runs as $FULL-api"
  ok "service accounts: $accounts"
  # The scheduler is the only pod with a Kubernetes token.
  tokens=$(k get pods -l "app.kubernetes.io/instance=$RELEASE" -o json \
    | jq -r '.items[] | select([.spec.volumes[]?.projected.sources[]?.serviceAccountToken] | length > 0)
             | .metadata.labels["app.kubernetes.io/component"]' | sort -u | tr '\n' ' ')
  [ "$tokens" = "scheduler " ] || fail "pods with a Kubernetes token: ${tokens:-none}"
  ok "only the scheduler mounts a Kubernetes token"
}

# One template's Job made into another's, field by field (ADR-0046): each must match none of the
# templates. name | template | jq change, where $other is another template's Job.
CROSS_JOBS=(
  "Steampipe's work on Prowler's image|steampipe|.spec.template.spec.containers[0].image = \$other.spec.template.spec.containers[0].image"
  "Prowler's image and work on Steampipe's name|steampipe|.spec.template.spec.containers[0] = \$other.spec.template.spec.containers[0]"
  "another work in the environment|prowler|(.spec.template.spec.containers[0].env[] | select(.name == \"ARGUS_JOB_WORK\") | .value) = \"steampipe\""
  "another work's label|cloudfox|.spec.template.metadata.labels[\"argus/work\"] = \"prowler\""
  "a tool Job's size on the test Job|test|.spec.template.spec.containers[0].resources = \$other.spec.template.spec.containers[0].resources"
  "no memory limit|prowler|del(.spec.template.spec.containers[0].resources.limits)"
  "the test Job on a tool's image|test|.spec.template.spec.containers[0].image = \$other.spec.template.spec.containers[0].image"
  "metadata reachable|test|.spec.template.spec.containers[0].env |= map(select(.name != \"AWS_EC2_METADATA_DISABLED\"))"
  "a name prefix of no template|prowler|.metadata.generateName = \"$FULL-scan-other-\""
  # The report Job (ADR-0047 round 5): never the platform identity, the keyring, the worker's
  # role or a scan Job's routes; and no scan Job on the report account.
  "the report Job as the platform identity|report|.spec.template.spec.serviceAccountName = \$other.spec.template.spec.serviceAccountName"
  "a scan Job as the report account|prowler|.spec.template.spec.serviceAccountName = \"$FULL-report\""
  "the keyring on the report Job|report|.spec.template.spec.containers[0].env += [\$other.spec.template.spec.containers[0].env[] | select(.name | startswith(\"ARGUS_SECRET_KEY\"))]"
  "the worker's role on the report Job|report|(.spec.template.spec.containers[0].env[] | select(.name == \"ARGUS_DB_USER\") | .value) = \"argus_worker\" | (.spec.template.spec.containers[0].env[] | select(.name == \"ARGUS_DB_PASSWORD\") | .valueFrom.secretKeyRef.key) = \"ARGUS_WORKER_DB_PASSWORD\""
  "a scan Job's routes for the report Job|report|.spec.template.metadata.labels[\"app.kubernetes.io/component\"] = \"run\""
  "the report Job on a tool's image|report|.spec.template.spec.containers[0].image = \$other.spec.template.spec.containers[0].image"
)

test_admission() {
  step "the admission policy: each template passes, every change is denied"
  local tmp out entry name change work other
  tmp=$(mktemp -d)
  for work in test steampipe prowler cloudfox report; do
    k get configmap "$FULL-job-templates" -o json | jq -r --arg f "$work.json" '.data[$f]' > "$tmp/$work.json"
    out=$(create_as_scheduler < "$tmp/$work.json") || fail "the $work template is denied: $out"
    ok "the $work template is allowed"
  done
  # The same size written another way is the same size: the API server may hand the policy 2Gi
  # for 2048Mi, so it compares quantities by value.
  out=$(jq '.spec.template.spec.containers[0].resources.limits.memory = "2048Mi"
            | .spec.template.spec.containers[0].resources.requests.cpu = "0.1"' "$tmp/prowler.json" \
        | create_as_scheduler) || fail "an equal size written another way is denied: $out"
  ok "an equal size written another way is allowed (2048Mi for 2Gi, 0.1 for 100m)"
  for entry in "${BAD_JOBS[@]}"; do
    IFS='|' read -r name change <<< "$entry"
    if out=$(jq "$change" "$tmp/prowler.json" | create_as_scheduler); then
      fail "allowed, but must be denied: $name"
    fi
    grep -q 'ValidatingAdmissionPolicy' <<< "$out" || fail "$name: denied, but not by the policy: $out"
    ok "denied: $name ($(sed -n 's/.*denied request: //p' <<< "$out"))"
  done
  for entry in "${CROSS_JOBS[@]}"; do
    IFS='|' read -r name work change <<< "$entry"
    other=prowler; [ "$work" = prowler ] && other=steampipe
    if out=$(jq --slurpfile o "$tmp/$other.json" "\$o[0] as \$other | $change" "$tmp/$work.json" | create_as_scheduler); then
      fail "allowed, but must be denied: $name"
    fi
    grep -q 'ValidatingAdmissionPolicy' <<< "$out" || fail "$name: denied, but not by the policy: $out"
    ok "denied: $name ($(sed -n 's/.*denied request: //p' <<< "$out"))"
  done
  rm -rf "$tmp"
}

# helm install compiles only the kind values' policy, and chart-check compiles none (kubeconform
# doesn't read CEL). Another release's name, so each is created, not an update of the installed one.
test_policy_compiles() {
  step "the admission policy compiles from every ci/ values file"
  local values out
  for values in "$CHART"/ci/*.yaml; do
    out=$(helm template argus "$CHART" -n argus-ci-check -f "$values" \
            --show-only templates/collectors/admission-policy.yaml \
          | kubectl create --dry-run=server -o name -f - 2>&1) \
      || fail "$(basename "$values"): $out"
    ok "$(basename "$values")"
  done
}

test_demo_refused() {
  step "no Demo on Kubernetes: the seed command refuses"
  local out
  if out=$(k exec "deploy/$FULL-api" -c api -- python -m argus.entrypoints.seed --days 1 2>&1); then
    fail "the seed ran: $out"
  fi
  grep -q 'demo connections are off' <<< "$out" || fail "the seed failed for another reason: $out"
  ok "the seed refused"
  [ "$(psql_q "SELECT count(*) FROM connection WHERE kind = 'demo'")" -eq 0 ] || fail "a Demo connection exists"
  ok "no Demo connection"
}

test_web() {
  step "the UI through web: AWS connections only, and a connection test in a test Job"
  local base=http://127.0.0.1:18080 pf tmp
  k port-forward "svc/$FULL-web" 18080:8080 > /dev/null 2>&1 &
  pf=$!
  tmp=$(mktemp -d)
  trap 'kill $pf 2>/dev/null || true; rm -rf "$tmp"; trap - RETURN' RETURN
  for _ in $(seq 30); do curl -fs -o /dev/null "$base/" && break; sleep 1; done
  curl -fsS "$base/" | grep -qi '<!doctype html' || fail "/ is not the app"
  ok "/ serves the app"
  curl -fsS "$base/api/v1/ready" | grep -q ready || fail "/api/v1/ready"
  ok "/api/v1/ready through web"

  kubectl -n "$HARNESS_NS" get secret admin-password -o jsonpath='{.data.password}' | base64 -d \
    | jq -Rs '{username: "admin", password: .}' > "$tmp/sign-in.json"
  [ "$(curl -sS -o /dev/null -D "$tmp/h" -w '%{http_code}' -H 'Content-Type: application/json' \
        --data @"$tmp/sign-in.json" "$base/api/v1/auth/sign-in")" = 204 ] || fail "sign-in refused"
  rm -f "$tmp/sign-in.json"
  local session csrf cookie id status message
  session=$(sed -n 's/^[Ss]et-[Cc]ookie: argus_session=\([^;]*\).*/\1/p' "$tmp/h")
  csrf=$(sed -n 's/^[Ss]et-[Cc]ookie: argus_csrf=\([^;]*\).*/\1/p' "$tmp/h")
  cookie="argus_session=$session; argus_csrf=$csrf"
  ok "signed in as admin"

  # Kubernetes offers real connections only (ADR-0039).
  [ "$(curl -fsS -H "Cookie: $cookie" "$base/api/v1/connections/kinds" | jq -c .)" = '["aws"]' ] \
    || fail "connection kinds: not AWS only"
  ok "connection kinds: AWS only"
  [ "$(curl -sS -o "$tmp/demo" -w '%{http_code}' -X POST -H "Cookie: $cookie" -H "X-Argus-CSRF: $csrf" \
        -H 'Content-Type: application/json' \
        --data '{"kind": "demo", "name": "demo-k8s", "seed": 0, "backfill_days": 1}' \
        "$base/api/v1/connections")" = 422 ] || fail "a Demo connection was not refused: $(cat "$tmp/demo")"
  ok "a Demo connection is refused: $(jq -r .detail "$tmp/demo")"

  id=$(curl -fsS -X POST -H "Cookie: $cookie" -H "X-Argus-CSRF: $csrf" "$base/api/v1/settings/identity/test" | jq -r .id)
  [ -n "$id" ] && [ "$id" != null ] || fail "the identity test was not queued"
  for _ in $(seq 90); do
    curl -fsS -H "Cookie: $cookie" "$base/api/v1/connection-tests/$id" > "$tmp/t"
    status=$(jq -r .status "$tmp/t")
    [ "$status" = passed ] || [ "$status" = failed ] && break
    sleep 2
  done
  message=$(jq -r .message "$tmp/t")
  # No identity on kind: the test Job answers the test, finds no credentials and says so.
  if [ "$status" != failed ] || ! grep -qi 'credentials' <<< "$message"; then
    fail "identity test: $status, $message"
  fi
  ok "identity test answered: $message"
  # On the runtime image, with instance metadata off (ADR-0046, gate review S1), and no tool Job
  # started for it.
  local runtime_image
  runtime_image=$(k get "deploy/$FULL-api" -o jsonpath='{.spec.template.spec.containers[0].image}')
  k get jobs -l argus/work=test -o json > "$tmp/jobs"
  jq -e --arg img "$runtime_image" '.items | length >= 1 and all(.[];
      .spec.template.spec.containers[0].image == $img
      and ([.spec.template.spec.containers[0].env[] | select(.name == "AWS_EC2_METADATA_DISABLED") | .value] == ["true"]))' \
    "$tmp/jobs" > /dev/null || fail "no test Job, or one not on the runtime image with metadata off"
  [ "$(k get jobs -l 'app.kubernetes.io/component=run,argus/work!=test' -o name | wc -l)" -eq 0 ] \
    || fail "a tool Job started for a connection test"
  ok "a test Job on the runtime image answered it; no tool Job started"
}

# web's readiness is nginx's own (/healthz): with no API at all, web stays in its Service and
# serves the app, which says it can't reach the API; nginx answers /api itself with a 502.
test_web_without_api() {
  step "web stays Ready while the API is down"
  local base=http://127.0.0.1:18081 pf="" replicas pods ready code
  replicas=$(k get "deploy/$FULL-api" -o jsonpath='{.spec.replicas}')
  k scale "deploy/$FULL-api" --replicas 0 > /dev/null
  trap 'kill $pf 2>/dev/null || true; k scale "deploy/$FULL-api" --replicas "$replicas" > /dev/null; trap - RETURN' RETURN
  k wait --for=delete pod -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=api" \
    --timeout 120s > /dev/null || fail "the api pods did not stop"
  # Longer than three failed readiness probes (10 s apart): long enough to drop web if it
  # still depended on the API.
  sleep 35
  pods=$(k get pods -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=web" -o json)
  ready=$(jq '[.items[] | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length' <<< "$pods")
  [ "$ready" -ge 1 ] && [ "$ready" -eq "$(jq '.items | length' <<< "$pods")" ] \
    || fail "web pods dropped out without the API: $ready ready"
  ok "every web pod stayed Ready without the API ($ready)"
  k port-forward "svc/$FULL-web" 18081:8080 > /dev/null 2>&1 &
  pf=$!
  for _ in $(seq 30); do curl -fs -o /dev/null "$base/healthz" && break; sleep 1; done
  curl -fsS "$base/" | grep -qi '<!doctype html' || fail "/ is not the app without the API"
  ok "/ serves the app without the API"
  # In seconds, not after nginx's default minute (proxy_connect_timeout 5s).
  code=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' "$base/api/v1/health" || true)
  [ "$code" = 502 ] || [ "$code" = 504 ] || fail "/api without the API answered $code, expected 502 or 504"
  ok "/api without the API: $code from nginx"
  kill $pf 2>/dev/null || true
  k scale "deploy/$FULL-api" --replicas "$replicas" > /dev/null
  k rollout status "deploy/$FULL-api" --timeout 300s > /dev/null || fail "api did not come back"
  ok "api back at $replicas replicas"
}

# The address the API records for a failed sign-in sent with this X-Forwarded-For. A port-forward
# reaches web from 127.0.0.1, standing in for the peer: the ingress, or any other client.
recorded_address() { # <X-Forwarded-For> <username>
  local base=http://127.0.0.1:18081 pf code reached=no
  # Right after a rollout it can attach to a pod that is shutting down, and then exits: start again.
  for _ in $(seq 6); do
    k port-forward "svc/$FULL-web" 18081:8080 > /dev/null 2>&1 &
    pf=$!
    for _ in $(seq 10); do
      curl -fs -o /dev/null "$base/" && { reached=yes; break; }
      sleep 1
    done
    [ "$reached" = yes ] && break
    kill "$pf" 2>/dev/null || true
    wait "$pf" 2>/dev/null || true
  done
  [ "$reached" = yes ] || fail "web did not answer through a port-forward"
  code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H "X-Forwarded-For: $1" \
    --data "{\"username\": \"$2\", \"password\": \"wrong\"}" "$base/api/v1/auth/sign-in")
  kill "$pf" 2>/dev/null || true
  wait "$pf" 2>/dev/null || true
  [ "$code" = 401 ] || fail "a wrong password through web answered $code"
  psql_q "SELECT host(client_ip) FROM audit_log WHERE actor = '$2' AND action = 'auth.sign_in.failed'"
}

# No ingress controller on kind: web's handling of the header is what's tested, not a controller's.
set_ingress() { # <helm flags>
  helm upgrade "$RELEASE" "$CHART" -n "$NAMESPACE" --reuse-values "$@" --wait --timeout 15m > /dev/null
  k rollout status "deploy/$FULL-web" --timeout 300s > /dev/null
}

test_client_address() {
  step "the address behind X-Forwarded-For (F5)"
  # Usernames new to this run, so its audit rows are the only ones read.
  local got run
  run=$(rand 8 | tr '[:upper:]' '[:lower:]')
  got=$(recorded_address "203.0.113.9" "xff-no-ingress-$run")
  [ "$got" = 127.0.0.1 ] || fail "no ingress: recorded '$got', expected the peer, never the header"
  ok "no ingress: a client's X-Forwarded-For is ignored"

  set_ingress --set web.ingress.enabled=true --set web.ingress.host=argus.kind.example \
    --set-json 'networkPolicy.webIngressFrom=[{"ipBlock":{"cidr":"10.244.0.0/16"}}]'
  got=$(recorded_address "198.51.100.7" "xff-ingress-$run")
  [ "$got" = 198.51.100.7 ] || fail "behind an ingress: recorded '$got', expected the address it reported"
  ok "behind an ingress: the address it reports is recorded"
  got=$(recorded_address "203.0.113.9, 198.51.100.7" "xff-forged-$run")
  [ "$got" = 198.51.100.7 ] || fail "a forged left entry: recorded '$got', expected 198.51.100.7"
  ok "behind an ingress: what a client wrote before the ingress's entry is not believed"

  set_ingress --set web.ingress.enabled=false \
    --set-json 'networkPolicy.webIngressFrom=[]'
  got=$(recorded_address "203.0.113.9" "xff-ingress-off-$run")
  [ "$got" = 127.0.0.1 ] || fail "ingress off again: recorded '$got'"
  ok "ingress off again: the header is ignored"
}

test_sign_in_rate() {
  step "web limits sign-in requests per address (F6)"
  local base=http://127.0.0.1:18082 pf tmp codes
  k port-forward "svc/$FULL-web" 18082:8080 > /dev/null 2>&1 &
  pf=$!
  tmp=$(mktemp -d)
  trap 'kill $pf 2>/dev/null || true; rm -rf "$tmp"; trap - RETURN' RETURN
  for _ in $(seq 30); do curl -fs -o /dev/null "$base/" && break; sleep 1; done
  # Past the burst, all at once. The limit is on web, so most never reach the API.
  codes=$(seq 20 | xargs -P 20 -I{} curl -sS -o /dev/null -w '%{http_code}\n' -H 'Content-Type: application/json' \
    --data '{"username": "rate-check", "password": "wrong"}' "$base/api/v1/auth/sign-in" | sort | uniq -c | tr -s ' ' | paste -sd,)
  grep -q ' 429' <<< "$codes" || fail "20 at once were never limited: $codes"
  ok "20 sign-ins at once: $codes"
  curl -sS -o "$tmp/body" -D "$tmp/head" -H 'Content-Type: application/json' \
    --data '{"username": "rate-check", "password": "wrong"}' "$base/api/v1/auth/sign-in" > /dev/null
  grep -q '^HTTP/.* 429' "$tmp/head" || fail "the next one was not limited: $(head -1 "$tmp/head")"
  grep -qi '^retry-after: 5' "$tmp/head" || fail "a limited sign-in has no Retry-After"
  [ "$(jq -r .detail "$tmp/body")" = "too many attempts" ] || fail "a limited sign-in's body: $(cat "$tmp/body")"
  ok "a limited sign-in answers 429 with Retry-After"
  # So this run's failures don't count against the next run's admin sign-in.
  psql_q "DELETE FROM login_failure WHERE username LIKE 'xff-%' OR username = 'rate-check'" > /dev/null
}

test_network() {
  step "NetworkPolicies, enforced"
  local api_ip api_port db="$FULL-postgres:5432" api="$FULL-api:8000" web="$FULL-web:8080" out internet=no
  api_ip=$(kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o jsonpath='{.items[0].endpoints[0].addresses[0]}')
  api_port=$(kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o jsonpath='{.items[0].ports[0].port}')
  curl -s -m 5 -o /dev/null https://1.1.1.1 && internet=yes

  k exec "deploy/$FULL-web" -- nc -z -w 3 "$FULL-api" 8000 || fail "web -> api closed"
  ok "web -> $api open"
  # The full name: busybox nslookup fails when any search domain answers NXDOMAIN.
  k exec "deploy/$FULL-web" -- nslookup "$FULL-postgres.$NAMESPACE.svc.cluster.local." > /dev/null \
    || fail "web cannot resolve $FULL-postgres"
  if k exec "deploy/$FULL-web" -- nc -z -w 3 "$FULL-postgres" 5432 2>/dev/null; then fail "web -> Postgres open"; fi
  ok "web -> $db closed"

  out=$(probe_from api api "$db" 1.1.1.1:443 169.254.169.254:80)
  expect_reach "$out" api "$db" open
  expect_reach "$out" api 1.1.1.1:443 closed
  expect_reach "$out" api 169.254.169.254:80 closed

  out=$(probe_from scan run "$db" "$api" "$web" 169.254.169.254:80 10.96.0.1:443 "$api_ip:$api_port" 1.1.1.1:443)
  expect_reach "$out" scan "$db" open
  expect_reach "$out" scan "$api" closed
  expect_reach "$out" scan "$web" closed
  expect_reach "$out" scan 169.254.169.254:80 closed
  expect_reach "$out" scan 10.96.0.1:443 closed
  expect_reach "$out" scan "$api_ip:$api_port" closed
  if [ "$internet" = yes ]; then
    expect_reach "$out" scan 1.1.1.1:443 open
  else
    echo "      (no internet from this host: scan -> 443 outside not checked)"
  fi

  # The report Job renders names from scanned clouds: the database and S3/STS (192.0.2.0/24 on
  # kind, where nothing answers), never the rest of the internet, metadata or the cluster.
  out=$(probe_from report report "$db" "$api" "$web" 169.254.169.254:80 "$api_ip:$api_port" 1.1.1.1:443)
  expect_reach "$out" report "$db" open
  expect_reach "$out" report "$api" closed
  expect_reach "$out" report "$web" closed
  expect_reach "$out" report 169.254.169.254:80 closed
  expect_reach "$out" report "$api_ip:$api_port" closed
  expect_reach "$out" report 1.1.1.1:443 closed

  out=$(probe_from scheduler scheduler "$db" "$api_ip:$api_port" "$api" 1.1.1.1:443)
  expect_reach "$out" scheduler "$db" open
  expect_reach "$out" scheduler "$api_ip:$api_port" open
  expect_reach "$out" scheduler "$api" closed
  expect_reach "$out" scheduler 1.1.1.1:443 closed

  out=$(probe_from unlisted unlisted "$db" "$api" "$web" 1.1.1.1:443)
  expect_reach "$out" unlisted "$db" closed
  expect_reach "$out" unlisted "$api" closed
  expect_reach "$out" unlisted "$web" closed
  expect_reach "$out" unlisted 1.1.1.1:443 closed
}

# A report Job really runs (ADR-0047 round 5): the scheduler starts it for a queued report, it
# logs in as argus_reports, and with no IRSA on kind it fails the report as not stored, never
# reaching for another identity.
test_report_job() {
  step "a report Job: started for a queued report, as argus_reports, no identity on kind"
  local id state
  k logs -l app.kubernetes.io/component=migrate --tail=-1 | grep -q '"roles_with_login": \[[^]]*"argus_reports"' \
    || fail "migrate did not give argus_reports its login"
  ok "migrate gave argus_reports its login"
  id=$(psql_q "INSERT INTO report_request (kind, format, filters, connection_ids, requested_by,
      storage_bucket, storage_region) VALUES ('misconfigurations', 'csv', '{}', ARRAY[1], 'kind-test',
      'argus-reports-kind', 'eu-west-1') RETURNING id")
  for _ in $(seq 90); do
    state=$(psql_q "SELECT status || '|' || coalesce(error, '') FROM report_request WHERE id = $id")
    [ "${state%%|*}" = failed ] && break
    sleep 2
  done
  [ "$state" = "failed|The report could not be stored. See the report builder's log." ] \
    || fail "report $id: '$state', expected failed as not stored"
  k get jobs -l argus/work=report -o name | grep -q . || fail "no report Job ran"
  ok "a report Job claimed report $id and failed it: no identity on kind"
}

test_retention() {
  step "the retention CronJob's Job"
  local job="$FULL-retention-check"
  k delete job "$job" --ignore-not-found > /dev/null
  k create job "$job" --from="cronjob/$FULL-retention" > /dev/null
  k wait --for=condition=complete "job/$job" --timeout 600s > /dev/null || fail "retention did not complete"
  ok "retention completed: $(k logs "job/$job" -c retention | tail -1)"
  k delete job "$job" > /dev/null
}

test_upgrade() {
  step "helm upgrade: migrate kept, rederive run again"
  local migrate rederive after
  migrate=$(k get job -l app.kubernetes.io/component=migrate -o jsonpath='{.items[*].metadata.uid}')
  rederive=$(k get job -l app.kubernetes.io/component=rederive -o jsonpath='{.items[*].metadata.name}')
  # A change to the rederive pod only (it shares retention's resources), as a new image would
  # make; it alternates, so every `test` changes it.
  local cpu
  cpu=$(helm get values "$RELEASE" -n "$NAMESPACE" -o json | jq -r '.retention.resources.requests.cpu // ""')
  [ "$cpu" = 60m ] && cpu=50m || cpu=60m
  helm upgrade "$RELEASE" "$CHART" -n "$NAMESPACE" --reuse-values \
    --set "retention.resources.requests.cpu=$cpu" --wait --timeout 15m > /dev/null
  [ "$(k get job -l app.kubernetes.io/component=migrate -o jsonpath='{.items[*].metadata.uid}')" = "$migrate" ] \
    || fail "the migrate Job was replaced"
  ok "the migrate Job is the same one"
  after=$(k get job -l app.kubernetes.io/component=rederive -o jsonpath='{.items[*].metadata.name}')
  [ -n "$after" ] && [ "$after" != "$rederive" ] || fail "no new rederive Job ($after)"
  k wait --for=condition=complete "job/$after" --timeout 600s > /dev/null || fail "rederive did not complete"
  ok "a new rederive Job completed ($rederive -> $after)"
}

set_secret() { # <key> <value>
  k patch secret argus-secrets --type merge -p "{\"stringData\":{\"$1\":\"$2\"}}" > /dev/null
}

secret_value() { # <key>
  k get secret argus-secrets -o json | jq -r ".data.$1" | base64 -d
}

signs_in() { # <role> <password>: over TCP from the pod's own address, where the image asks for one
  k exec "statefulset/$FULL-postgres" -c postgres -- sh -c \
    'PGPASSWORD="$2" psql -h "$(hostname -i)" -U "$1" -d argus -tAXqc "SELECT 1"' _ "$1" "$2" \
    > /dev/null 2>&1
}

test_password_rotation() {
  step "rotating every database password, as the runbook says"
  local role key old new owner_new job
  declare -A old_passwords new_passwords
  # The owner first in the database, because migrate signs in with it.
  owner_new=$(rand 32)
  psql_q "ALTER ROLE argus PASSWORD '$owner_new'" > /dev/null
  set_secret ARGUS_DB_PASSWORD "$owner_new"

  for role in api worker scheduler reports; do
    key="ARGUS_${role^^}_DB_PASSWORD"
    old=$(secret_value "$key")
    new=$(rand 32)
    old_passwords[$role]=$old
    new_passwords[$role]=$new
    signs_in "argus_$role" "$old" || fail "argus_$role does not sign in before the rotation"
    set_secret "$key" "$new"
  done

  helm upgrade "$RELEASE" "$CHART" -n "$NAMESPACE" --reuse-values --wait --timeout 15m > /dev/null
  signs_in argus_api "${old_passwords[api]}" \
    || fail "an upgrade alone changed a password, so the runbook's step is not needed"
  ok "the Secret and an upgrade alone leave the database's passwords as they were"

  k delete job -l app.kubernetes.io/component=migrate > /dev/null
  helm upgrade "$RELEASE" "$CHART" -n "$NAMESPACE" --reuse-values --wait --timeout 15m > /dev/null
  job=$(k get job -l app.kubernetes.io/component=migrate -o name)
  [ -n "$job" ] || fail "the upgrade did not create the migrate Job again"
  k wait --for=condition=complete "$job" --timeout 600s > /dev/null \
    || fail "migrate did not complete with the new owner password"
  ok "migrate ran again, signing in with the owner's new password"

  for role in api worker scheduler reports; do
    signs_in "argus_$role" "${new_passwords[$role]}" || fail "argus_$role: the new password is refused"
    if signs_in "argus_$role" "${old_passwords[$role]}"; then
      fail "argus_$role: the old password still signs in"
    fi
  done
  ok "each role signs in with its new password, not the old one"

  # Each init container signs in as its own role before the pod starts, so a wrong password
  # fails these.
  k rollout restart "deploy/$FULL-api" "deploy/$FULL-scheduler" > /dev/null
  k rollout status "deploy/$FULL-api" --timeout 300s > /dev/null || fail "api did not restart"
  k rollout status "deploy/$FULL-scheduler" --timeout 300s > /dev/null || fail "the scheduler did not restart"
  ok "api and the scheduler restarted on their new passwords"
}

test_helm_test() {
  step "helm test"
  local out
  out=$(helm test "$RELEASE" -n "$NAMESPACE" --logs) || { printf '%s\n' "$out"; fail "helm test failed"; }
  printf '%s\n' "$out"
  printf '%s\n' "$out" | grep -q 'at its start, a new pod' || fail "helm test did not measure a new pod's start"
  ok "helm test measured a new pod's start"
}

test_health() {
  step "afterwards"
  local restarts denied
  restarts=$(k get pods -l "app.kubernetes.io/instance=$RELEASE" -o json \
    | jq -r '.items[] | select([.status.containerStatuses[]?.restartCount] | add > 0) | .metadata.name')
  [ -z "$restarts" ] || fail "containers restarted: $restarts"
  ok "no container restarted"
  denied=$(k logs "deploy/$FULL-scheduler" -c scheduler | grep -ci 'denied\|forbidden' || true)
  [ "$denied" -eq 0 ] || fail "the scheduler logged $denied refusals"
  ok "the scheduler logged no refusal"
}

run_tests() {
  kubeconfig
  test_install
  test_limits
  test_rights
  test_admission
  test_policy_compiles
  test_network
  test_report_job
  test_demo_refused
  test_web
  test_web_without_api
  test_client_address
  test_sign_in_rate
  test_upgrade
  test_password_rotation
  # After the rotation: the worker's new password reaches a Job that starts from then on.
  test_retention
  test_helm_test
  test_health
  printf '\nkind test passed\n'
}

# ---- down -----------------------------------------------------------------------------------

down() {
  kind delete cluster --name "$CLUSTER"
  docker rm -f "$REGISTRY_NAME" > /dev/null 2>&1 || true
  ok "cluster and registry removed"
}

case "${1:-}" in
  up) up ;;
  test) run_tests ;;
  down) down ;;
  *) echo "usage: run.sh up|test|down" >&2; exit 2 ;;
esac

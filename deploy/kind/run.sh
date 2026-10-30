#!/usr/bin/env bash
# kind: the chart on a throwaway kind cluster, and the checks that prove ADR-0039 and ADR-0040 on
# it. Local only: it drives the host's Docker. Every value it makes is random and stays in the
# cluster.
#   docker compose build migrate worker web     the three images, first
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
  local runtime=$1 worker=$2 web=$3 api_ip api_port
  api_ip=$(kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
    -o jsonpath='{.items[0].endpoints[0].addresses[0]}')
  api_port=$(kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
    -o jsonpath='{.items[0].ports[0].port}')
  helm upgrade --install "$RELEASE" "$CHART" -n "$NAMESPACE" -f "$HERE/values-kind.yaml" \
    --set "images.registry=localhost:$REGISTRY_PORT" \
    --set "images.runtime.digest=$runtime" \
    --set "images.worker.digest=$worker" \
    --set "images.web.digest=$web" \
    --set "networkPolicy.kubeApi.cidrs={$api_ip/32}" \
    --set "networkPolicy.kubeApi.port=$api_port" \
    --wait --timeout 15m
}

up() {
  local image
  for image in argus-backend:runtime argus-backend:worker argus-web:runtime; do
    docker image inspect "$image" > /dev/null 2>&1 \
      || fail "no $image: docker compose build migrate worker web"
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
  local runtime worker web
  runtime=$(push_image argus-backend:runtime)
  worker=$(push_image argus-backend:worker)
  web=$(push_image argus-web:runtime)
  [ -n "$runtime" ] && [ -n "$worker" ] && [ -n "$web" ] || fail "a push gave no digest"
  ok "runtime $runtime"
  ok "worker  $worker"
  ok "web     $web"

  step "namespace $NAMESPACE (Pod Security restricted) and the Secret"
  kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - > /dev/null
  kubectl label namespace "$NAMESPACE" --overwrite \
    pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/warn=restricted > /dev/null
  make_secret

  step "helm install"
  install "$runtime" "$worker" "$web"
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
  'a toleration|.spec.template.spec.tolerations = [{"operator": "Exists"}]'
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
        command: (["python", "-c", "import socket, sys\nfor t in sys.argv[1:]:\n    h, p = t.rsplit(\":\", 1)\n    try:\n        socket.create_connection((h, int(p)), timeout=4).close(); print(t, \"open\")\n    except OSError:\n        print(t, \"closed\")"] + $targets),
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
  for sa in default "$FULL-run"; do
    [ "$(kubectl auth can-i --as="system:serviceaccount:$NAMESPACE:$sa" -n "$NAMESPACE" create jobs.batch 2>/dev/null || true)" = no ] \
      || fail "$sa can create Jobs"
  done
  ok "no other service account can create Jobs"
  # Only two accounts of the chart's own; every other pod runs as default.
  accounts=$(k get serviceaccounts -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | sort | tr '\n' ' ')
  [ "$accounts" = "$(printf '%s\n' default "$FULL-run" "$FULL-scheduler" | sort | tr '\n' ' ')" ] \
    || fail "service accounts: $accounts"
  ok "service accounts: $accounts"
  # The scheduler is the only pod with a Kubernetes token.
  tokens=$(k get pods -l "app.kubernetes.io/instance=$RELEASE" -o json \
    | jq -r '.items[] | select([.spec.volumes[]?.projected.sources[]?.serviceAccountToken] | length > 0)
             | .metadata.labels["app.kubernetes.io/component"]' | sort -u | tr '\n' ' ')
  [ "$tokens" = "scheduler " ] || fail "pods with a Kubernetes token: ${tokens:-none}"
  ok "only the scheduler mounts a Kubernetes token"
}

test_admission() {
  step "the admission policy: the template passes, every change is denied"
  local tmp out entry name change
  tmp=$(mktemp -d)
  k get configmap "$FULL-job-templates" -o json | jq -r '.data["scan.json"]' > "$tmp/scan.json"
  out=$(create_as_scheduler < "$tmp/scan.json") || fail "the scan template is denied: $out"
  ok "the scan template is allowed"
  for entry in "${BAD_JOBS[@]}"; do
    IFS='|' read -r name change <<< "$entry"
    if out=$(jq "$change" "$tmp/scan.json" | create_as_scheduler); then
      fail "allowed, but must be denied: $name"
    fi
    grep -q 'ValidatingAdmissionPolicy' <<< "$out" || fail "$name: denied, but not by the policy: $out"
    ok "denied: $name ($(sed -n 's/.*denied request: //p' <<< "$out"))"
  done
  rm -rf "$tmp"
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
  step "the UI through web: AWS connections only, and a connection test in a scan Job"
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
  # No identity on kind: the scan Job answers the test, finds no credentials and says so.
  if [ "$status" != failed ] || ! grep -qi 'credentials' <<< "$message"; then
    fail "identity test: $status, $message"
  fi
  ok "identity test answered: $message"
  [ "$(k get jobs -l app.kubernetes.io/component=run -o name | wc -l)" -ge 1 ] || fail "no scan Job"
  ok "a scan Job answered it"
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

test_helm_test() {
  step "helm test"
  helm test "$RELEASE" -n "$NAMESPACE" --logs
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
  test_rights
  test_admission
  test_network
  test_demo_refused
  test_web
  test_retention
  test_upgrade
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

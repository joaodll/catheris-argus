{{/* Names and labels. */}}
{{- define "argus.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "argus.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 40 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 40 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 40 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Selector labels: name, instance, component. Call with (dict "root" $ "component" "api"). */}}
{{- define "argus.selectorLabels" -}}
app.kubernetes.io/name: {{ include "argus.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "argus.labels" -}}
{{ include "argus.selectorLabels" . }}
app.kubernetes.io/part-of: argus
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version | replace "+" "_" }}
{{- end }}

{{/* An image by digest. (dict "root" $ "image" .Values.images.runtime "registry" true) */}}
{{- define "argus.image" -}}
{{- $repo := .image.repository }}
{{- if and .registry .root.Values.images.registry }}
{{- $repo = printf "%s/%s" (trimSuffix "/" .root.Values.images.registry) .image.repository }}
{{- end }}
{{- printf "%s@%s" $repo .image.digest }}
{{- end }}

{{- define "argus.runtimeImage" -}}
{{- include "argus.image" (dict "root" . "image" .Values.images.runtime "registry" true) }}
{{- end }}

{{/* One of the chart's two service accounts: "run" (the AWS identity) or "scheduler". */}}
{{- define "argus.serviceAccount" -}}
{{- printf "%s-%s" (include "argus.fullname" .root) .name }}
{{- end }}

{{/* Placement for a long-running pod: (dict "v" .Values.api). Scan Jobs use scanJobs'. */}}
{{- define "argus.placement" -}}
{{- with .v.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .v.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .v.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/* Database coordinates as one role, and the pod's pool (a key of database.pools).
(dict "root" $ "user" "argus_api" "key" "ARGUS_API_DB_PASSWORD" "pool" "api") */}}
{{- define "argus.dbEnv" -}}
{{- $v := .root.Values -}}
- name: ARGUS_DB_HOST
  value: {{ ternary (printf "%s-postgres" (include "argus.fullname" .root)) $v.postgres.external.host $v.postgres.enabled | quote }}
- name: ARGUS_DB_PORT
  value: {{ ternary 5432 $v.postgres.external.port $v.postgres.enabled | quote }}
- name: ARGUS_DB_NAME
  value: {{ $v.database.name | quote }}
- name: ARGUS_DB_USER
  value: {{ .user | quote }}
- name: ARGUS_DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ $v.secrets.existingSecret }}
      key: {{ .key }}
{{- if not $v.postgres.enabled }}
- name: ARGUS_DB_SSLMODE
  value: {{ $v.postgres.external.sslmode | quote }}
{{- if $v.postgres.external.caConfigMap }}
- name: ARGUS_DB_SSLROOTCERT
  value: {{ printf "/etc/argus/db-ca/%s" $v.postgres.external.caKey | quote }}
{{- end }}
{{- end }}
- name: ARGUS_DB_POOL_MAX
  value: {{ index $v.database.pools .pool | quote }}
- name: ARGUS_LOG_LEVEL
  value: {{ $v.logLevel | quote }}
{{- end }}

{{/*
The connection budget (2026-10-28): the most connections every pod can open at once, which
Postgres must hold beside its 3 reserved. The render fails above postgres.maxConnections. See
database.pools in values.yaml.
*/}}
{{- define "argus.connectionBudget" -}}
{{- $v := .Values }}
{{- $p := $v.database.pools }}
{{- $apiPods := add (ternary $v.api.autoscaling.maxReplicas $v.api.replicas $v.api.autoscaling.enabled) 1 }}
{{- $scanPods := add $v.scheduler.maxRunJobs $v.scheduler.maxTestJobs }}
{{- $api := mul $apiPods $p.api }}
{{- $scans := mul $scanPods $p.scanJob }}
{{- $tasks := add (mul 3 $p.task) 1 }}
{{- $total := add $api $scans $tasks $p.scheduler }}
{{- $room := sub $v.postgres.maxConnections 3 }}
{{- if gt $total $room }}
{{- fail (printf "database connections: the pods can open %d at once (api %d = %d pods x %d, scan Jobs %d = %d x %d, migrate/rederive/retention %d, scheduler %d), above postgres.maxConnections %d less 3 reserved. Raise postgres.maxConnections, or lower database.pools, the api replicas or scheduler.maxRunJobs." $total $api $apiPods (int $p.api) $scans $scanPods (int $p.scanJob) $tasks (int $p.scheduler) (int $v.postgres.maxConnections)) }}
{{- end }}
{{- end }}

{{/* One key of the Secret as an environment variable of the same name; "optional" when the
Secret may lack it. */}}
{{- define "argus.secretEnv" -}}
- name: {{ .key }}
  valueFrom:
    secretKeyRef:
      name: {{ .root.Values.secrets.existingSecret }}
      key: {{ .key }}
      {{- if .optional }}
      optional: true
      {{- end }}
{{- end }}

{{- define "argus.keyringEnv" -}}
{{ include "argus.secretEnv" (dict "root" . "key" "ARGUS_SECRET_KEYS") }}
{{ include "argus.secretEnv" (dict "root" . "key" "ARGUS_SECRET_KEY_ID") }}
{{- end }}

{{/* The external database's CA bundle, when one is set. */}}
{{- define "argus.dbCAVolume" -}}
{{- if and (not .Values.postgres.enabled) .Values.postgres.external.caConfigMap -}}
- name: db-ca
  configMap:
    name: {{ .Values.postgres.external.caConfigMap }}
{{- end }}
{{- end }}

{{- define "argus.dbCAMount" -}}
{{- if and (not .Values.postgres.enabled) .Values.postgres.external.caConfigMap -}}
- name: db-ca
  mountPath: /etc/argus/db-ca
  readOnly: true
{{- end }}
{{- end }}


{{/* Pod and container security contexts (Pod Security "restricted"). */}}
{{- define "argus.podSecurity" -}}
runAsNonRoot: true
runAsUser: {{ .uid }}
runAsGroup: {{ .uid }}
fsGroup: {{ .uid }}
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{- define "argus.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end }}

{{/*
Every pod's spec in the chart (ADR-0040). The same basics everywhere: the namespace's `default`
account with no token unless one is named, no service links, Pod Security "restricted", the pull
secrets, a size-limited /tmp, and the external database's CA when the pod is a database client.
  (dict "root" $ "component" "api" "containers" (include "argus.container" ...))
Optional: "uid" (10001), "serviceAccount", "token", "restartPolicy", "grace",
"fsGroupChangePolicy", "placement" (a values block with nodeSelector, tolerations, affinity),
"spread" (across nodes), "initContainers", "tmp" (dict "sizeLimit" "medium"; 64Mi by default,
false for none), "db" (mounts the CA volume), "volumes" (more volumes, as YAML).
*/}}
{{- define "argus.podSpec" -}}
{{- $tmp := ternary .tmp (dict "sizeLimit" "64Mi") (hasKey . "tmp") -}}
serviceAccountName: {{ .serviceAccount | default "default" }}
automountServiceAccountToken: {{ .token | default false }}
{{- with .restartPolicy }}
restartPolicy: {{ . }}
{{- end }}
enableServiceLinks: false
{{- with .grace }}
terminationGracePeriodSeconds: {{ . }}
{{- end }}
securityContext:
  {{- include "argus.podSecurity" (dict "uid" (.uid | default 10001)) | nindent 2 }}
  {{- with .fsGroupChangePolicy }}
  fsGroupChangePolicy: {{ . }}
  {{- end }}
{{- with .root.Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .placement }}
{{- include "argus.placement" (dict "v" .) }}
{{- end }}
{{- if .spread }}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        {{- include "argus.selectorLabels" (dict "root" .root "component" .component) | nindent 8 }}
{{- end }}
{{- with .initContainers }}
initContainers:
  {{- . | nindent 2 }}
{{- end }}
containers:
  {{- .containers | nindent 2 }}
{{- if or $tmp .volumes .db }}
volumes:
  {{- if $tmp }}
  - name: tmp
    emptyDir:
      {{- with $tmp.medium }}
      medium: {{ . }}
      {{- end }}
      sizeLimit: {{ $tmp.sizeLimit }}
  {{- end }}
  {{- with .volumes }}
  {{- . | nindent 2 }}
  {{- end }}
  {{- if .db }}
  {{- include "argus.dbCAVolume" .root | nindent 2 }}
  {{- end }}
{{- end }}
{{- end }}

{{/*
Every container in the chart: the image by digest (the runtime image unless one is given) and
the restricted security context. A database client ("db": the argus.dbEnv dict) gets its role's
environment first and the CA mount last.
  (dict "root" $ "name" "api" "command" (list ...) "db" $db "resources" .Values.api.resources)
Optional: "image", "command", "args", "env" (more variables, as YAML), "extra" (ports and
probes, as YAML), "tmp" (mounts /tmp; true by default), "mounts" (more mounts, as YAML).
*/}}
{{- define "argus.container" -}}
{{- $tmp := ternary .tmp true (hasKey . "tmp") -}}
- name: {{ .name }}
  image: {{ .image | default (include "argus.runtimeImage" .root) }}
  imagePullPolicy: {{ .root.Values.images.pullPolicy }}
  {{- with .command }}
  command: {{ toJson . }}
  {{- end }}
  {{- with .args }}
  args: {{ toJson . }}
  {{- end }}
  {{- if or .db .env }}
  env:
    {{- with .db }}
    {{- include "argus.dbEnv" . | nindent 4 }}
    {{- end }}
    {{- with .env }}
    {{- . | nindent 4 }}
    {{- end }}
  {{- end }}
  {{- with .extra }}
  {{- . | nindent 2 }}
  {{- end }}
  resources:
    {{- toYaml .resources | nindent 4 }}
  securityContext:
    {{- include "argus.containerSecurity" . | nindent 4 }}
  {{- if or $tmp .mounts .db }}
  volumeMounts:
    {{- if $tmp }}
    - {name: tmp, mountPath: /tmp}
    {{- end }}
    {{- with .mounts }}
    {{- . | nindent 4 }}
    {{- end }}
    {{- if .db }}
    {{- include "argus.dbCAMount" .root | nindent 4 }}
    {{- end }}
  {{- end }}
{{- end }}

{{/* Waits until the schema is at this image's head, as the pod's own role (ADR-0039). Takes the
argus.dbEnv dict. */}}
{{- define "argus.waitForSchema" -}}
{{- include "argus.container" (dict "root" .root "name" "wait-for-schema" "db" .
  "command" (list "python" "-m" "argus.entrypoints.migrate" "--config" "/opt/argus/alembic.ini" "--wait" "--timeout" "900")
  "resources" (dict "requests" (dict "cpu" "20m" "memory" "64Mi") "limits" (dict "memory" "128Mi"))) }}
{{- end }}

{{/*
A Deployment: api, web (rolling, spread across nodes, the replica count unless autoscaling) or
the scheduler ("single": one replica, never two at once, not even during an upgrade).
  (dict "root" $ "component" "api" "v" .Values.api "pod" (dict ...argus.podSpec's options))
Optional: "single", "annotations" (on the pod).
*/}}
{{- define "argus.deployment" -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "argus.fullname" .root }}-{{ .component }}
  labels:
    {{- include "argus.labels" . | nindent 4 }}
spec:
  {{- if .single }}
  replicas: 1
  strategy:
    type: Recreate
  {{- else }}
  {{- if not .v.autoscaling.enabled }}
  replicas: {{ .v.replicas }}
  {{- end }}
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  {{- end }}
  selector:
    matchLabels:
      {{- include "argus.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "argus.labels" . | nindent 8 }}
      {{- with .annotations }}
      annotations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
    spec:
      {{- include "argus.podSpec" (merge .pod (dict "root" .root "component" .component "placement" .v "spread" (not .single))) | nindent 6 }}
{{- end }}

{{/*
The pod of a backend task that runs once and exits (migrate, rederive, retention), as one
database role, waiting for the schema first unless it is the migration itself.
  (dict "root" $ "component" "rederive" "command" (list ...) "db" $db "resources" ... "wait" true)
Optional: "env" (more variables, as YAML).
*/}}
{{- define "argus.taskPod" -}}
metadata:
  labels:
    {{- include "argus.labels" . | nindent 4 }}
spec:
  {{- include "argus.podSpec" (dict "root" .root "component" .component "restartPolicy" "Never" "db" true
    "initContainers" (ternary (include "argus.waitForSchema" .db) "" (default false .wait))
    "containers" (include "argus.container" (dict "root" .root "name" .component "command" .command
      "db" .db "env" .env "resources" .resources))) | nindent 2 }}
{{- end }}

{{/*
The scan Job template (ADR-0039): the only source of a scan Job. The scheduler's ConfigMap and
the admission policy both render it, so they cannot drift. A scan Job answers a connection test
or runs one AWS scan, as the run account (the AWS identity), with the worker image. 10001 is
the user the image's /etc/passwd lists: CloudFox exits under any other.
*/}}
{{- define "argus.scanJob" -}}
{{- $v := .Values }}
{{- $s := $v.scanJobs }}
{{- $labels := include "argus.selectorLabels" (dict "root" . "component" "run") }}
apiVersion: batch/v1
kind: Job
metadata:
  generateName: {{ include "argus.fullname" . }}-scan-
  labels:
    {{- $labels | nindent 4 }}
spec:
  backoffLimit: 0
  completions: 1
  parallelism: 1
  activeDeadlineSeconds: {{ $s.activeDeadlineSeconds }}
  ttlSecondsAfterFinished: {{ $s.ttlSecondsAfterFinished }}
  template:
    metadata:
      labels:
        {{- $labels | nindent 8 }}
      annotations:
        # A run is never moved: an evicted run is lost and counted (ADR-0039).
        karpenter.sh/do-not-disrupt: "true"
        cluster-autoscaler.kubernetes.io/safe-to-evict: "false"
    spec:
      {{- include "argus.podSpec" (dict "root" . "component" "run" "restartPolicy" "Never" "grace" 120 "db" true
        "serviceAccount" (include "argus.serviceAccount" (dict "root" . "name" "run"))
        "placement" (dict "nodeSelector" $s.nodeSelector "tolerations" $s.tolerations)
        "tmp" (dict "medium" "Memory" "sizeLimit" $s.tmpSize)
        "volumes" (include "argus.scanJob.volumes" .)
        "containers" (include "argus.container" (dict "root" . "name" "run"
          "image" (include "argus.image" (dict "root" . "image" $v.images.worker "registry" true))
          "command" (list "python" "-m" "argus.entrypoints.job")
          "db" (dict "root" . "user" "argus_worker" "key" "ARGUS_WORKER_DB_PASSWORD" "pool" "scanJob")
          "env" (include "argus.scanJob.env" .) "resources" $s.resources
          "mounts" "- {name: scratch, mountPath: /var/lib/argus-staging}"))) | nindent 6 }}
{{- end }}

{{- define "argus.scanJob.env" -}}
{{ include "argus.keyringEnv" . }}
# The deployment's bound on scans at once: a Job started for a test never exceeds it.
- name: ARGUS_MAX_RUN_JOBS
  value: {{ .Values.scheduler.maxRunJobs | quote }}
# Only the worker image sets it: no process in a scan Job may use instance metadata.
- name: AWS_EC2_METADATA_DISABLED
  value: "true"
{{- end }}

{{- define "argus.scanJob.volumes" -}}
# Raw output until it is uploaded, deleted with the pod: never a volume claim.
- name: scratch
  emptyDir:
    sizeLimit: {{ .Values.scanJobs.scratch.size }}
{{- end }}

{{/* A one-shot Job's name: its name plus a hash of its pod, parsed so that only a change to
what runs (not to the template's layout) runs it again. */}}
{{- define "argus.oneShotName" -}}
{{- printf "%s-%s-%s" (include "argus.fullname" .root) .name (.pod | fromYaml | toJson | sha256sum | trunc 10) }}
{{- end }}

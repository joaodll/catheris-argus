# syntax=docker/dockerfile:1.7
# argus-kind: the chart's static checks (`chart-check`) and a throwaway kind cluster that installs
# it (`kind`). Local tooling, never deployed. Every tool is pinned and checked against the
# sha256 its project publishes; the docker CLI comes from a pinned image.

ARG DEBIAN_IMAGE=debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
ARG DOCKER_CLI_IMAGE=docker:29.9.1-cli@sha256:6fae2214c3121a28d5aa639d09032f61310b7c9c75ffbad1025f261a1b621800

FROM ${DOCKER_CLI_IMAGE} AS docker-cli

FROM ${DEBIAN_IMAGE} AS fetch
ARG KIND_VERSION=0.33.0
ARG KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
# Within one minor version of the node image in versions.env.
ARG KUBECTL_VERSION=1.34.12
ARG KUBECTL_SHA256=90b7b9058ffeb5c10710bb1c73f541eaf426fb1b4e87df435db669de9a2564a2
ARG HELM_VERSION=4.3.1
ARG HELM_SHA256=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b
ARG KUBECONFORM_VERSION=0.8.0
ARG KUBECONFORM_SHA256=9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
ARG JQ_VERSION=1.8.2
ARG JQ_SHA256=b1c22172dd303f3be49e935aa56aa48a8b7a46e0bc838b4997d3bb451495870f
ARG YQ_VERSION=4.54.1
ARG YQ_SHA256=8e34fc298390875de416e6a4afcb8cabeceb25d9aa8506c1a2f9353cf702ea5f
# kubeconform's schemas, from a fixed commit of yannh/kubernetes-json-schema, for the kinds the
# chart renders: `chart-check` runs with no network.
ARG SCHEMAS_COMMIT=f7d855e49c34b039c9ef2196444910275e31e09e
ARG SCHEMAS_KUBERNETES=v1.34.11
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /fetch
RUN set -eu; \
    get() { curl -fsSLo "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    get kind "https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-amd64" "$KIND_SHA256"; \
    get kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" "$KUBECTL_SHA256"; \
    get helm.tgz "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz" "$HELM_SHA256"; \
    get kubeconform.tgz "https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/kubeconform-linux-amd64.tar.gz" "$KUBECONFORM_SHA256"; \
    get jq "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-amd64" "$JQ_SHA256"; \
    get yq "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64" "$YQ_SHA256"; \
    tar -xzf helm.tgz --strip-components 1 linux-amd64/helm; \
    tar -xzf kubeconform.tgz kubeconform; \
    mkdir -p /out/bin; install -m 0755 kind kubectl helm kubeconform jq yq /out/bin/
RUN set -eu; \
    dir="/out/schemas/${SCHEMAS_KUBERNETES}-standalone-strict"; mkdir -p "$dir"; \
    for kind in configmap-v1 cronjob-batch-v1 deployment-apps-v1 ingress-networking-v1 job-batch-v1 \
        networkpolicy-networking-v1 pod-v1 poddisruptionbudget-policy-v1 resourcequota-v1 \
        role-rbac-v1 rolebinding-rbac-v1 service-v1 serviceaccount-v1 statefulset-apps-v1 \
        horizontalpodautoscaler-autoscaling-v2 \
        validatingadmissionpolicy-admissionregistration-v1 \
        validatingadmissionpolicybinding-admissionregistration-v1; do \
      curl -fsSLo "$dir/$kind.json" \
        "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/${SCHEMAS_COMMIT}/${SCHEMAS_KUBERNETES}-standalone-strict/$kind.json"; \
    done
RUN /out/bin/kind version | grep -q "v${KIND_VERSION}" \
 && /out/bin/helm version --short | grep -q "v${HELM_VERSION}" \
 && /out/bin/kubectl version --client | grep -q "v${KUBECTL_VERSION}"

FROM ${DEBIAN_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /out/bin/ /usr/local/bin/
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=fetch /out/schemas /opt/kubeconform-schemas
ENV KUBECONFORM_SCHEMAS=/opt/kubeconform-schemas \
    HELM_CACHE_HOME=/tmp/helm/cache HELM_CONFIG_HOME=/tmp/helm/config HELM_DATA_HOME=/tmp/helm/data
WORKDIR /work
# chart-check runs as the host user; only the `kind` service, which drives the Docker socket,
# runs as root, and says so in compose.yaml.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin argus
USER 10001

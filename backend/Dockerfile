# syntax=docker/dockerfile:1.7
# argus-backend: one image, run as the api, ingest, scheduler and retention processes (ADR-0017).
#
# Targets, in order. Compose names the target of every image it builds.
#   uv-base      Python + uv, nothing installed. Used by the `lock` service to write uv.lock.
#   development  uv-base + every dependency group in /opt/venv. Source is bind-mounted at /app.
#   builder      resolves runtime dependencies and the project into /opt/venv.
#   runtime      /opt/venv only: no uv, no compilers, no dev tools, non-root. api, migrate.
#   worker       runtime + the three collectors, unmodified and pinned (ADR-0001, ADR-0030).
#                Only the worker runs tools, so only its image carries them.

ARG PYTHON_IMAGE=python:3.13-slim-trixie@sha256:bb2988715db2cf7ace7b53f38f3cffbef7c7046a656bee66245eb0ed386e2e81
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.22@sha256:f513a91fc62fe7c17567eee97230dd198e43edb8a9fbecca843714a4358fe1bc

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH
# No pip: dependencies install with uv from the lock, and the venvs have none. The base image's
# pip carries its own vendored packages (certifi), one more thing to patch for nothing.
RUN groupadd --gid 10001 argus \
 && useradd --uid 10001 --gid argus --no-create-home --shell /usr/sbin/nologin argus \
 && rm -rf /usr/local/bin/pip /usr/local/bin/pip3* /usr/local/lib/python3.13/site-packages/pip \
      /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
      /usr/local/lib/python3.13/ensurepip

FROM base AS uv-base
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    UV_CACHE_DIR=/tmp/uv-cache
WORKDIR /app

FROM uv-base AS development
COPY pyproject.toml uv.lock ./
# The project itself is not installed: /app/src is on PYTHONPATH so the bind mount is live.
RUN uv sync --frozen --no-install-project --all-groups \
 && rm -rf /tmp/uv-cache
ENV PYTHONPATH=/app/src

FROM uv-base AS builder
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM base AS runtime
COPY --from=builder /opt/venv /opt/venv
# Migrations ship in the image so the one-shot `migrate` service runs exactly what was built.
COPY alembic.ini /opt/argus/alembic.ini
COPY migrations /opt/argus/migrations
# Relationship and attack-path rules: versioned files the engines load at run time.
COPY rules /opt/argus/rules
# The raw archive in Compose (S3 later), and the worker's staging for AWS runs (ADR-0032).
# Created here so a fresh named volume inherits the runtime user's ownership instead of root's;
# staging is owner-only, since it holds raw output until the upload ends.
RUN mkdir -p /var/lib/argus /var/lib/argus-staging \
 && chown 10001:10001 /var/lib/argus /var/lib/argus-staging \
 && chmod 0700 /var/lib/argus-staging
USER 10001:10001
WORKDIR /home/argus
# No CMD: each process (api, ingest, scheduler, retention) sets its own command.

# ---- collectors, for the worker image only ---------------------------------------------

FROM base AS tools-fetch
ARG CLOUDFOX_VERSION=2.0.5
# GitHub's published digest for cloudfox-linux-amd64.zip at v2.0.5.
ARG CLOUDFOX_SHA256=3cdc5a1a94ff14eb8df04d3dc8f9eca7db232a1315ceb8a7de26e4cb13e32fd5
ARG STEAMPIPE_AWS_VERSION=1.34.0
# GitHub's published digest for steampipe_export_aws.linux_amd64.tar.gz at v1.34.0.
ARG STEAMPIPE_AWS_SHA256=58e50f487ab15deecf157284735f93b66512480fbdc585ab2eb3a0291d302340
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSLo /tmp/cloudfox.zip \
      "https://github.com/BishopFox/cloudfox/releases/download/v${CLOUDFOX_VERSION}/cloudfox-linux-amd64.zip" \
 && echo "${CLOUDFOX_SHA256}  /tmp/cloudfox.zip" | sha256sum -c - \
 && unzip -q /tmp/cloudfox.zip -d /tmp/cloudfox \
 && install -m 0755 /tmp/cloudfox/cloudfox/cloudfox /usr/local/bin/cloudfox \
 && /usr/local/bin/cloudfox --version | grep -qx ".*version ${CLOUDFOX_VERSION}"
RUN curl -fsSLo /tmp/export.tgz \
      "https://github.com/turbot/steampipe-plugin-aws/releases/download/v${STEAMPIPE_AWS_VERSION}/steampipe_export_aws.linux_amd64.tar.gz" \
 && echo "${STEAMPIPE_AWS_SHA256}  /tmp/export.tgz" | sha256sum -c - \
 && tar -xzf /tmp/export.tgz -C /usr/local/bin steampipe_export_aws \
 && chmod 0755 /usr/local/bin/steampipe_export_aws
# Every table in the versioned list must exist in the pinned plugin. With no credentials and
# instance metadata disabled, a real table fails at the credential step; an unknown one fails
# with "does not provide table". No AWS call succeeds here. ~400 tables (argus_v8): 16 checks
# at a time, each with its own install dir; the first unknown table stops the build (xargs
# stops on exit 255 and returns non-zero).
COPY src/argus/collection/steampipe_tables_aws.txt /tmp/aws.txt
RUN set -eu; export AWS_EC2_METADATA_DISABLED=true AWS_REGION=us-east-1; \
    grep -v '^#' /tmp/aws.txt | grep . | xargs -P 16 -n 1 sh -c ' \
      if STEAMPIPE_INSTALL_DIR="/tmp/sp/$1" timeout 60 steampipe_export_aws "$1" --limit 1 --output jsonl 2>&1 \
           | grep -q "does not provide table"; then \
        echo "unknown table in steampipe_tables_aws.txt: $1" >&2; exit 255; fi' _; \
    rm -rf /tmp/sp

# Prowler from its own lock (tools/prowler/uv.lock), in a venv apart from Argus's.
FROM uv-base AS prowler
COPY tools/prowler/pyproject.toml tools/prowler/uv.lock /opt/prowler-project/
RUN cd /opt/prowler-project \
 && UV_PROJECT_ENVIRONMENT=/opt/prowler uv sync --frozen --no-dev --no-install-project \
 && rm -rf /tmp/uv-cache \
 && /opt/prowler/bin/prowler --version | grep -q "5.45.0"

FROM runtime AS worker
# CloudFox and Steampipe look up the user's home in the passwd entry, not $HOME, and write
# there; on a read-only root it must be the /tmp tmpfs.
USER root
RUN usermod --home /tmp argus
USER 10001:10001
COPY --from=tools-fetch /usr/local/bin/cloudfox /usr/local/bin/steampipe_export_aws /usr/local/bin/
COPY --from=prowler /opt/prowler /opt/prowler
# Tools get credentials only from the per-run profile the worker writes. Instance metadata is
# disabled, so a host's or node's own role is never picked up in its place.
ENV AWS_EC2_METADATA_DISABLED=true

# Tooling image for deploy/aws: cfn-lint, the read-only policy check and its tests.
# Local and CI only; never deployed.
ARG PYTHON_IMAGE=python:3.13-slim-trixie@sha256:bb2988715db2cf7ace7b53f38f3cffbef7c7046a656bee66245eb0ed386e2e81
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.22@sha256:f513a91fc62fe7c17567eee97230dd198e43edb8a9fbecca843714a4358fe1bc

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE}
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy \
    UV_CACHE_DIR=/tmp/uv-cache PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1
WORKDIR /work/policycheck
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project && rm -rf /tmp/uv-cache
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin argus
USER 10001

# syntax=docker/dockerfile:1.7
# argus-web: the Vue app, built to static files and served by unprivileged nginx, which also
# proxies /api to the api service. The browser talks to one origin only.
#
# Targets:
#   base     Node + pnpm (pinned through package.json "packageManager"), nothing installed.
#            The `frontend` and `frontend-dev` services run it with the source bind-mounted.
#   build    pnpm install --frozen-lockfile, then type-check and build.
#   runtime  nginx + dist/ only. No Node, no source. Listens on 8080 as uid 101.

ARG NODE_IMAGE=node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6

FROM ${NODE_IMAGE} AS base
ENV COREPACK_HOME=/opt/corepack \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    npm_config_store_dir=/pnpm-store \
    CI=true
WORKDIR /app
COPY package.json ./
RUN corepack enable \
 && corepack install \
 && chmod -R a+rX /opt/corepack \
 # Mount points for the tool services' named volumes: a fresh volume copies this mode, so the
 # host user (any UID) can write node_modules and the pnpm store without running as root.
 && mkdir -p /pnpm-store /repo/frontend/node_modules \
 && chmod 0777 /pnpm-store /repo/frontend/node_modules \
 && rm package.json

FROM base AS build
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM ${NGINX_IMAGE} AS runtime
# A template the entrypoint fills in at start (ARGUS_API_UPSTREAM), into /etc/nginx/conf.d,
# which must be writable: a tmpfs in Compose, an emptyDir on Kubernetes. Only ARGUS_ variables
# are substituted, never nginx's own ($remote_addr, $host).
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
ENV NGINX_ENVSUBST_FILTER=^ARGUS_
COPY nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --from=build /app/dist /usr/share/nginx/html
# The image's own unprivileged user, stated so the runtime user is explicit in this file.
USER 101
EXPOSE 8080

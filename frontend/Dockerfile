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
# The publisher moved the image from nginxinc/ to nginx/ on Docker Hub from nginx 1.30.6 on; the old
# name gets no new release (github.com/nginx/docker-nginx-unprivileged, README).
ARG NGINX_IMAGE=nginx/nginx-unprivileged:1.30-alpine@sha256:0c53a1f2890c3526bfd201440f0fd3970e5b78f80630f58284aad0d34b5ec7bd

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
# The published base lags Alpine's repository, so its packages carry CVEs already fixed there.
# Upgrade all of them: not to exact versions, because Alpine removes old ones and the build would
# break. curl and libcurl (most of the base's findings) go: nothing here uses them, and the
# healthcheck uses BusyBox wget. So do the base's four dynamic modules, which no config here loads,
# and the libraries only they need (libxslt, libxml2, libgd, libjpeg, GeoIP): fewer packages to
# patch, and nothing for a registry scanner to report.
USER root
RUN apk upgrade --no-cache \
 && apk del --no-cache curl nginx-module-geoip nginx-module-image-filter nginx-module-njs \
      nginx-module-xslt
# A template the entrypoint fills in at start (ARGUS_API_UPSTREAM), into /etc/nginx/conf.d,
# which must be writable: a tmpfs in Compose, an emptyDir on Kubernetes. Only ARGUS_ variables
# are substituted, never nginx's own ($remote_addr, $host).
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
ENV NGINX_ENVSUBST_FILTER=^ARGUS_
# The template leaves an unset variable as it is, which nginx refuses: empty means no ingress.
ENV ARGUS_NGINX_REAL_IP=""
COPY nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY nginx/api-proxy.conf /etc/nginx/snippets/api-proxy.conf
# The configuration must load without the removed modules: fill in the template as the entrypoint
# does (any address will do), test it, and remove the result, so a directive that needs a module
# fails the build rather than the start. The entrypoint writes the real one at start. The test,
# run as root, leaves a root-owned pid file and temp folders in /tmp: remove them too, or nginx,
# as uid 101, can't start where /tmp is not mounted over.
RUN ARGUS_API_UPSTREAM=127.0.0.1:8000 envsubst '${ARGUS_API_UPSTREAM} ${ARGUS_NGINX_REAL_IP}' \
      < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf \
 && nginx -t \
 && rm -rf /etc/nginx/conf.d/default.conf /tmp/nginx.pid /tmp/*_temp
COPY --from=build /app/dist /usr/share/nginx/html
# The image's own unprivileged user, stated so the runtime user is explicit in this file.
USER 101
EXPOSE 8080

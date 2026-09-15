# syntax=docker/dockerfile:1.18

FROM node:24.20.0-alpine3.24@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS toolchain

ENV COREPACK_HOME=/opt/corepack \
    PNPM_HOME=/opt/pnpm \
    PATH=/opt/pnpm:$PATH
WORKDIR /app
RUN corepack enable --install-directory /usr/local/bin \
    && corepack prepare pnpm@11.24.0 --activate

FROM postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2 AS postgres-runtime

ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) alpine_arch=x86_64; libuuid_sha256=8306e5bb577696c9069fe1dfd9e1dcc39d2d481c6a1b0e707fd03c3e21aa6aa2 ;; \
      arm64) alpine_arch=aarch64; libuuid_sha256=9ce20c7ffe2ccaa7c321893c10564abbca13c3f2edb82f60a35f1f68e004f86c ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    libuuid_apk=/tmp/libuuid-2.42.3-r1.apk; \
    wget -q -O "${libuuid_apk}" \
      "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/${alpine_arch}/libuuid-2.42.3-r1.apk"; \
    echo "${libuuid_sha256}  ${libuuid_apk}" | sha256sum -c -; \
    apk verify --keys-dir /etc/apk/keys "${libuuid_apk}"; \
    apk add --no-cache 'libcrypto3=3.5.8-r0' 'libssl3=3.5.8-r0' "${libuuid_apk}"; \
    apk info -e 'libuuid=2.42.3-r1'; \
    rm -f "${libuuid_apk}" /usr/local/bin/gosu; \
    test ! -e /usr/local/bin/gosu

USER 70:70

FROM postgres-runtime AS postgres-client

USER 0:0

RUN set -eux; \
    mkdir -p /client-root/usr/local/bin /client-root/usr/local/share; \
    for tool in pg_dump pg_restore pg_basebackup pg_verifybackup pg_controldata; do \
      cp "/usr/local/bin/${tool}" "/client-root/usr/local/bin/${tool}"; \
    done; \
    cp -R /usr/local/share/postgresql /client-root/usr/local/share/postgresql; \
    for library in $( \
      for tool in pg_dump pg_restore pg_basebackup pg_verifybackup pg_controldata; do \
        ldd "/usr/local/bin/${tool}"; \
      done \
      | awk '/=> \/.* \(/ { print $3 } /^\// { print $1 }' \
      | sort -u \
    ); do \
      mkdir -p "/client-root$(dirname "${library}")"; \
      cp -L "${library}" "/client-root${library}"; \
    done

FROM golang:1.26.6-alpine3.24@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS caddy-build

ENV CGO_ENABLED=0
RUN --mount=type=cache,id=boardagent-go-mod,target=/go/pkg/mod \
    go mod download github.com/caddyserver/caddy/v2@v2.11.4 \
    && mkdir -p /src \
    && cp -R /go/pkg/mod/github.com/caddyserver/caddy/v2@v2.11.4 /src/caddy \
    && chmod -R u+w /src/caddy
WORKDIR /src/caddy
RUN --mount=type=cache,id=boardagent-go-mod,target=/go/pkg/mod \
    --mount=type=cache,id=boardagent-go-build,target=/root/.cache/go-build \
    go mod edit \
      -require=golang.org/x/crypto@v0.55.0 \
      -require=golang.org/x/net@v0.58.0 \
      -require=golang.org/x/text@v0.41.0 \
      -require=google.golang.org/grpc@v1.83.2 \
    && go mod tidy \
    && mkdir -p /out \
    && go build -buildvcs=false -trimpath -tags nobadger,nomysql,nopgx \
      -ldflags '-s -w -X github.com/caddyserver/caddy/v2.CustomVersion=v2.11.4+boardagent.2' \
      -o /out/caddy ./cmd/caddy \
    && go version -m /out/caddy > /out/caddy-build-info.txt \
    && grep -F $'\tdep\tgolang.org/x/crypto\tv0.55.0\t' /out/caddy-build-info.txt \
    && grep -F $'\tdep\tgolang.org/x/net\tv0.58.0\t' /out/caddy-build-info.txt \
    && grep -F $'\tdep\tgolang.org/x/text\tv0.41.0\t' /out/caddy-build-info.txt \
    && grep -F $'\tdep\tgoogle.golang.org/grpc\tv1.83.2\t' /out/caddy-build-info.txt

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS caddy-runtime

ENV XDG_CONFIG_HOME=/config \
    XDG_DATA_HOME=/data
RUN apk add --no-cache 'ca-certificates=20260611-r0' 'libcrypto3=3.5.8-r0' 'libssl3=3.5.8-r0' \
    && addgroup -g 10002 -S boardagent-caddy \
    && adduser -u 10002 -S -D -H -h /nonexistent -s /sbin/nologin -G boardagent-caddy boardagent-caddy \
    && mkdir -p /config /data /etc/caddy /usr/share/boardagent \
    && chown -R 10002:10002 /config /data
COPY --from=caddy-build /out/caddy /usr/bin/caddy
COPY --from=caddy-build /out/caddy-build-info.txt /usr/share/boardagent/caddy-build-info.txt
USER 10002:10002
EXPOSE 80 443 443/udp
STOPSIGNAL SIGTERM
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]

FROM toolchain AS build
COPY . .
RUN --mount=type=cache,id=boardagent-pnpm,target=/opt/pnpm/store \
    pnpm install --frozen-lockfile \
    && pnpm typecheck \
    && pnpm build

FROM toolchain AS production-dependencies
COPY . .
RUN --mount=type=cache,id=boardagent-pnpm,target=/opt/pnpm/store \
    pnpm install --prod --frozen-lockfile

FROM node:24.20.0-alpine3.24@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS runtime

ENV NODE_ENV=production
WORKDIR /app
COPY --from=postgres-client /client-root/ /
RUN apk add --no-cache 'acl-libs=2.3.2-r1' 'libcrypto3=3.5.8-r0' 'libssl3=3.5.8-r0' 'tar=1.35-r5' \
    && addgroup -g 10001 -S boardagent \
    && adduser -u 10001 -S -D -H -h /nonexistent -s /sbin/nologin -G boardagent boardagent \
    && mkdir -p /var/lib/boardagent/blobs /var/lib/boardagent/exports \
    && chown -R 10001:10001 /var/lib/boardagent \
    && ldd /usr/local/bin/pg_dump /usr/local/bin/pg_restore \
      /usr/local/bin/pg_basebackup /usr/local/bin/pg_verifybackup /usr/local/bin/pg_controldata \
      > /tmp/postgres-client.ldd \
    && ! grep -q 'not found' /tmp/postgres-client.ldd \
    && rm /tmp/postgres-client.ldd \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
COPY --from=production-dependencies --chown=10001:10001 /app /app
COPY --from=build --chown=10001:10001 /app/artifacts/server/dist /app/artifacts/server/dist
COPY --from=build --chown=10001:10001 /app/lib /app/lib
COPY --from=build --chown=10001:10001 /app/scripts/dist /app/scripts/dist

USER 10001:10001
EXPOSE 8787
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD ["node", "artifacts/server/dist/main.js", "healthcheck"]
CMD ["node", "artifacts/server/dist/main.js", "server"]

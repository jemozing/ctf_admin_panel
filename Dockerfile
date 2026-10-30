# syntax=docker/dockerfile:1
ARG GO_IMAGE=golang:1.26-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:48e4b67d85f87bd551df43704e24d252f56cc5f8e9718841aace50f19948f0f9
ARG DASHBOARD_IMAGE=alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c
ARG DOCKER_CLI_IMAGE=docker:29.8.2-cli@sha256:35cfcf893c20f2931f4909151b5407aaaeab711277de7ce8b8f521f095d54c32

FROM ${NODE_IMAGE} AS frontend
WORKDIR /src/web
COPY web/package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY web/ ./
RUN npm run build

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=frontend /src/web/dist ./web/dist
COPY web/embed.go ./web/embed.go
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/ctf-manager ./cmd/ctf-manager

FROM ${DASHBOARD_IMAGE} AS dashboard
RUN addgroup -g 10001 -S ctf-manager && adduser -u 10001 -S -D -H -G ctf-manager ctf-manager
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ctf-manager /usr/local/bin/ctf-manager
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/ctf-manager"]
CMD ["dashboard", "--listen", "0.0.0.0:8765", "--state", "/var/lib/ctf-manager", "--socket", "/run/ctf-manager/executor.sock"]

# The official CLI image provides Docker, Compose and Buildx. No daemon is run.
FROM ${DOCKER_CLI_IMAGE} AS executor
COPY --from=build /out/ctf-manager /usr/local/bin/ctf-manager
USER 0:10001
ENV DOCKER_HOST=unix:///var/run/docker.sock DOCKER_CONFIG=/tmp/docker
ENTRYPOINT ["/usr/local/bin/ctf-manager"]
CMD ["--config", "/etc/ctf-manager/executor.json", "executor"]

# ---- build stage ----
# --platform=$BUILDPLATFORM keeps this stage on the BUILDER's native arch (e.g.
# the amd64 CI runner) so the Go toolchain never runs under QEMU; we cross-
# compile to the target arch via GOOS/GOARCH below. Pure-Go (CGO_ENABLED=0)
# makes that free. buildx sets BUILDPLATFORM/TARGETOS/TARGETARCH automatically.
FROM --platform=$BUILDPLATFORM golang:1.26.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Version is injected here, NOT derived from git: .dockerignore excludes .git, so
# `git describe` is unavailable in the build context. CI passes the release tag
# (e.g. v0.1.0) via --build-arg VERSION=...; a plain `docker build` gets "dev".
ARG VERSION=dev
# Cross-compile to the requested platform; buildx sets TARGETOS/TARGETARCH per
# --platform value (both default to the build platform for a plain `docker build`).
ARG TARGETOS TARGETARCH
# Pure-Go, static (modernc sqlite needs no CGO). Reproducible (-trimpath).
RUN CGO_ENABLED=0 GOFLAGS=-trimpath GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w -X github.com/mivanov93/git-tainted/internal/buildinfo.Version=${VERSION}" \
    -o /out/git-taintedd ./cmd/git-taintedd

# ---- runtime stage ----
FROM alpine:3.22
# git is the only runtime dependency (subprocess); ca-certs for https remotes;
# openssh-client for ssh remotes. The Go binary itself is fully static.
# DL3018: alpine floating versions are intentional — we always want the latest
# patched git/openssh from the pinned alpine:3.22 base, not a frozen pin that
# silently rots past CVEs. Reproducibility comes from the pinned base image tag.
# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates openssh-client && adduser -D -u 10001 gt
USER gt
COPY --from=build /out/git-taintedd /usr/local/bin/git-taintedd
# Migrations are embedded in the binary (see db/embed.go) — no db/ folder needed.
COPY spec/openapi.yaml /app/spec/openapi.yaml
EXPOSE 8080
# OCI image metadata (also stamped by docker/metadata-action in release CI).
ARG VERSION
LABEL org.opencontainers.image.title="git-taintedd" \
      org.opencontainers.image.description="git-tainted server — hash-chained git tag-tamper ledger + verify/admin API" \
      org.opencontainers.image.source="https://github.com/mivanov93/git-tainted" \
      org.opencontainers.image.url="https://github.com/mivanov93/git-tainted" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="BUSL-1.1"
ENTRYPOINT ["/usr/local/bin/git-taintedd"]

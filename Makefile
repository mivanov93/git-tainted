GO         ?= go
PKG        := ./...
DOCKER     := docker

.PHONY: tidy generate sqlc oapi-server lint vet test race cover test-mysql \
        build build-server build-cli docker up-local down e2e smoke verify-spec clean

tidy:            ; $(GO) mod tidy
generate: sqlc oapi-server   ## all codegen

sqlc:            ; $(GO) run github.com/sqlc-dev/sqlc/cmd/sqlc generate
oapi-server:     ; $(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen \
                     -config oapi-codegen.yaml spec/openapi.yaml

verify-spec:     ; $(DOCKER) run --rm -v $$PWD:/work openapitools/openapi-generator-cli:v7.x \
                     validate -i /work/spec/openapi.yaml

lint:            ; $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint run
vet:             ; $(GO) vet $(PKG)
test:            ; $(GO) test $(PKG)
race:            ; $(GO) test -race -count=1 $(PKG)
cover:           ; $(GO) test -coverprofile=cover.out $(PKG) && $(GO) tool cover -func=cover.out

# Version is stamped from git: a tag (v0.1.0), commits-past-tag (v0.1.0-3-gabc1234),
# -dirty for a modified tree, or the bare commit when no tag exists (nightly).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/mivanov93/git-tainted/internal/buildinfo.Version=$(VERSION)

build: build-server build-cli   ## build both binaries (version stamped from git describe)
build-server:    ; CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/git-taintedd ./cmd/git-taintedd
build-cli:       ; CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/git-tainted ./cmd/git-tainted

docker:          ; $(DOCKER) build -t git-tainted:dev .
up-local:        ; $(DOCKER) compose -f docker-compose.local.yml up --build -d
down:            ; $(DOCKER) compose -f docker-compose.local.yml down -v

e2e:             ; $(GO) test -tags=e2e -count=1 ./internal/sync/... ./internal/api/...
# test-mysql runs the MySQL Store integration suite (build tag mysql_it) against a
# throwaway mysql:8.4 container started by testcontainers-go. Requires a running
# Docker daemon. On-demand only — NOT part of the default Docker-free gate.
test-mysql:      ; $(GO) test -tags=mysql_it -count=1 ./internal/store/...
smoke: up-local  ; ./scripts/smoke.sh
clean:           ; rm -rf bin cover.out

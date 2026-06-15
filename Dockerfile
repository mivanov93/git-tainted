# ---- build stage ----
FROM golang:1.26.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure-Go, static (modernc sqlite needs no CGO). Reproducible.
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags "-s -w" -o /out/git-taintedd ./cmd/git-taintedd

# ---- runtime stage ----
FROM alpine:3.22
# git is the only runtime dependency (subprocess); ca-certs for https remotes;
# openssh-client for ssh remotes. The Go binary itself is fully static.
RUN apk add --no-cache git ca-certificates openssh-client && adduser -D -u 10001 gt
USER gt
COPY --from=build /out/git-taintedd /usr/local/bin/git-taintedd
COPY db/migrations /app/db/migrations
COPY spec/openapi.yaml /app/spec/openapi.yaml
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/git-taintedd"]

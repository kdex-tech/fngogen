# Build the manager binary
FROM golang:1.26-alpine
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache tree

# Default HOME is / (root-owned). Codegen Jobs run this image as a
# non-root user (UID 65532 under host-manager's PSSRestricted pod
# spec); Go's GOCACHE default derives from HOME, so without this
# every `go run` / `go generate` from entry-point.sh fails with
# "failed to initialize build cache at /.cache/go-build: mkdir
# /.cache: permission denied". /tmp is always writable. See
# kdex-tech/fngogen#1.
#
# The golang:*-alpine base image hardcodes GOPATH=/go and pre-creates
# /go (root-owned). The module download cache lives at
# $GOPATH/pkg/mod/cache, and the sum-db lookaside at $GOPATH/pkg/sumdb,
# so redirect GOPATH to /tmp/go too — otherwise `go mod download`
# fails with "mkdir /go/pkg/mod/cache/...: permission denied" and
# sum-db verification with "open /go/pkg/sumdb/sum.golang.org/latest:
# permission denied". GOPATH inherits from / -derived defaults if
# unset, so the override has to be explicit.
ENV HOME=/tmp
ENV GOPATH=/tmp/go

WORKDIR /
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download; \
    go install github.com/ogen-go/ogen/cmd/ogen@latest

# Copy the go source
COPY cmd/ cmd/

# Build
# the GOARCH has no default value to allow the binary to be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -a -o fngogen cmd/main.go; \
    mv fngogen /usr/local/bin/fngogen; \
    chmod 777 /usr/local/bin/fngogen

COPY entry-point.sh /usr/local/bin/entry-point.sh
RUN chmod 777 /usr/local/bin/entry-point.sh

# The `go mod download` + `go install ogen` build steps above run as
# root and populate /tmp/go/pkg/mod (the module download cache) and
# /tmp/.cache/go-build (the build cache) with root-owned subtrees.
# At runtime the codegen Job runs this image as UID 65532, which can
# READ the cached entries but cannot ADD new ones — every additional
# dependency that ogen / `go generate` needs (goleak, yaml.v3, etc.)
# fails with "permission denied" on the parent directory.
# Make the entire cache tree world-writable so any UID can extend it.
# Safe: the image is read-only-by-convention and the cache content
# isn't security-sensitive. See kdex-tech/fngogen#1.
RUN chmod -R 0777 /tmp/.cache /tmp/go

ENTRYPOINT ["/usr/local/bin/entry-point.sh"]

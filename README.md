# fngogen

Codegen for K-CNAS Go `KDexFunction`s. `fngogen` turns a function's OpenAPI
surface into a compilable Go scaffold: the ogen-generated `api/` package plus
`cmd/{main,default,custom}.go` handler stubs.

It runs in two modes:

- **In-cluster** — as the `generate-code` step of host-manager's codegen Job
  (the `ghcr.io/kdex-tech/fngogen` image, driven by `entry-point.sh`).
- **Locally** — as a single command line executable, no Docker and no cluster
  round-trip (`fngogen local`, added for
  [#2](https://github.com/kdex-tech/fngogen/issues/2)).

## Local codegen (`fngogen local`)

Regenerate a function's `openapi-spec.json`, `api/`, and `cmd/` straight from
its `KDexFunction` CR, in seconds:

```sh
fngogen local \
  --kdexfunction k8s/dev/function_tenancy_service.yaml \
  --server-url  https://dev.knowdrive.ai \
  --dir         functions/tenancy-service
```

What it does, all in-process:

1. **Builds the one-off OpenAPI document** from the CR's `spec.api` — the same
   transform host-manager runs (`internal/openapi` `BuildOneOff`, wrapping
   paths/schemas into the full doc with `info`, `servers`, `x-kdex-*`
   extensions, the standard `components.responses`, and only the security
   schemes an operation actually references). It reuses the **same kin-openapi
   library and marshaling** host-manager uses, so `openapi-spec.json` is
   **byte-identical** to what the cluster commits (proven in
   `cmd/oneoff_test.go` against real `knowdrive-site` functions). No churn when
   the cluster regenerates.
2. **Generates `api/`** by running **ogen as a library** (no `go run`, no
   network) — equivalent to `ogen --target api --clean openapi-spec.json`.
3. **Renders `cmd/{main,default,custom}.go`** from the generated `Handler`
   interface. `cmd/custom.go` is **never overwritten** — hand-authored business
   logic survives regeneration.

It is **gen-only**: it does not run `go mod tidy` / `go vet` / `go fmt` (those
need the Go toolchain and are left to you). After generating:

```sh
cd functions/tenancy-service && go mod tidy && go build ./...
```

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `--kdexfunction` | — | KDexFunction CR YAML; its `spec.api` is resolved into the doc |
| `--spec` | — | an already-resolved `openapi-spec.json` (alternative to `--kdexfunction`) |
| `--server-url` | `http://localhost:8080` | `servers[0].url`; **set it to your host** for byte-identical output |
| `--dir` | `.` | function directory to generate into |

### Just the document (`fngogen build-spec`)

Resolve a CR's `spec.api` into the one-off OpenAPI doc without generating code
(prints to stdout, or `-o <file>`):

```sh
fngogen build-spec --kdexfunction k8s/dev/function_tenancy_service.yaml \
  --server-url https://dev.knowdrive.ai -o openapi-spec.json
```

## Legacy in-image usage (`fngogen --spec`)

The bare `fngogen --spec openapi-spec.json [--target cmd]` form — the template
step used by `entry-point.sh` after ogen runs — is unchanged.

## Build / test

```sh
make            # docker-buildx (multi-arch image)
go build ./cmd  # local binary
go test ./...   # includes the byte-identity golden tests
```

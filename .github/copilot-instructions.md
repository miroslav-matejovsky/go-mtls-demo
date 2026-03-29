# Copilot Instructions

## Commands

```bash
# Run all tests
go test ./...

# Run tests for one package
go test ./internal/scenarios/tlsmem/...
go test ./internal/scenarios/mtlsmem/...
go test ./internal/scenarios/tlsfiles/...
go test ./internal/scenarios/mtlsfiles/...
go test ./internal/scenarios/mtlsenterprise/...

# Run a single test by name
go test ./internal/scenarios/mtlsfiles/... -run TestDemo

# Run a demo
go run ./cmd/ tlsmem
go run ./cmd/ mtlsmem
go run ./cmd/ tlsfiles
go run ./cmd/ mtlsfiles
go run ./cmd/ mtlsenterprise
go run ./cmd/ mtlsenterprisetpm   # Windows only — requires Windows cert store + TPM (or software KSP fallback)
go run ./cmd/ mtlstpm   # Windows only — requires Windows cert store + TPM (or software KSP fallback)

# Via PowerShell script
pwsh scripts/run.ps1 tlsmem
pwsh scripts/run.ps1 mtlsmem
pwsh scripts/run.ps1 tlsfiles
pwsh scripts/run.ps1 mtlsfiles
pwsh scripts/run.ps1 mtlsenterprise
pwsh scripts/run.ps1 mtlsenterprisetpm
pwsh scripts/run.ps1 mtlstpm
```

No linter is configured. No CI/CD pipeline exists.

## Architecture

`internal/cert` is the shared certificate package. The seven demo packages live under `internal/scenarios/`. The first four (`tlsmem`, `mtlsmem`, `tlsfiles`, `mtlsfiles`) share the same four-file layout (`server.go`, `client.go`, `demo.go`, `config.go`). The enterprise packages (`mtlsenterprise`, `mtlsenterprisetpm`) and `mtlstpm` extend this with additional files (`operator.go`, `step*.go`):

```
internal/
  cert/        – shared: CA + leaf cert generation, PrintCertificateInfo, TLSVersionName, WriteCert, WriteKey
  pwsh/        – PowerShell process helpers used for cleanup scripts
  tpm/         – shared Windows TPM + CurrentUser cert-store helpers
  scenarios/
    tlsmem/      – one-way TLS,   certs in memory
    mtlsmem/     – mutual TLS,    certs in memory
    tlsfiles/    – one-way TLS,   certs written to certs/tlsfiles/ and loaded from disk
    mtlsfiles/   – mutual TLS,    certs written to certs/mtlsfiles/ and loaded from disk
    mtlsenterprise/ – mutual TLS, intermediate CA, role-specific EKU, DNS SANs, chain bundles
    mtlsenterprisetpm/ – mutual TLS, enterprise PKI + client key in Windows cert store + TPM (Windows only)
    mtlstpm/     – mutual TLS,    server: files in certs/mtlstpm/; client: Windows cert store + TPM (Windows only)
```

Each demo package has the same four-file structure:

| File        | Role |
|-------------|------|

| `server.go` | `CreateServer(...)` — builds a TLS server: `*httptest.Server` (mem packages) or `*http.Server` (files/tpm packages) |
| `client.go` | `CreateClient(...)` — builds an `http.Client` with the right TLS config |
| `demo.go`   | `RunDemo()` — orchestrates the full flow with narrative step output |

`cmd/main.go` is a thin dispatcher: it reads `os.Args[1]` (`tlsmem`, `mtlsmem`, `tlsfiles`, `mtlsfiles`, `mtlsenterprise`, `mtlsenterprisetpm`, or `mtlstpm`) and calls the appropriate `RunDemo()`. No arg → usage error; unknown arg → error. No default. `mtlsenterprisetpm` is dispatched via `cmd/mtlsenterprisetpm_windows.go` (calls `mtlsenterprisetpm.RunDemo()`) / `cmd/mtlsenterprisetpm_other.go` (returns a "Windows only" error). `mtlstpm` is dispatched via `cmd/mtlstpm_windows.go` (calls `mtlstpm.RunDemo()`) / `cmd/mtlstpm_other.go` (returns a "Windows only" error) to keep build constraints out of `main.go`.

## Key Conventions

**`internal/cert` is the shared package.** `cert.CreateCA(cn, validity)`, `cert.CreateLeafCert(signLeaf, cn)`, `cert.PrintCertificateInfo`, and `cert.TLSVersionName` are the shared exports. All demo packages import it as `"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"` and call `cert.CreateCA(...)` etc. Certificates include SKID/AKID extensions and random serial numbers.

**`signerFunc` / `cert.SignerFunc` closure pattern.** `cert.CreateCA()` returns a `SignerFunc` — a closure that signs leaf certificates with the CA's private key without exposing the key itself. Always pass this function through; never expose the raw CA key outside `internal/cert`.

**`httptest` for mem-package servers.** In `tlsmem` and `mtlsmem`, use `httptest.NewUnstartedServer(handler)`, assign `server.TLS`, then call `server.StartTLS()`. Never call `server.Start()` — this project only exercises TLS paths.

**`tls.Listen` + `server.Serve` for file-based servers.** In `tlsfiles`, `mtlsfiles`, and `mtlstpm`, `CreateServer` returns an `*http.Server` with `TLSConfig` set. The demo starts it with `tls.Listen("tcp", addr, server.TLSConfig)` then `go server.Serve(ln)`. No `httptest` is involved.

**File-based demos use `runDemo(baseDir string)` for testability.** `RunDemo()` calls `runDemo(certBaseDir)` where `certBaseDir = "certs/tlsfiles"` (or `mtlsfiles`). Tests call `runDemo(t.TempDir())` directly — this keeps tests self-contained without touching the repo's `certs/` directory.

**File-based servers use `tls.LoadX509KeyPair`; clients use `os.ReadFile` + `certpool.AppendCertsFromPEM`.** Never reintroduce in-memory PEM bytes in the files packages.

**`certs/` is git-ignored.** File-based demos create it on each run; the directory structure mirrors ownership boundaries (`ca/`, `server/`, `client/`, `untrusted/`).

**mTLS server requires `ClientAuth: tls.RequireAndVerifyClientCert` + `ClientCAs`.** The `CreateServer` in `mtlsmem/` and `mtlsfiles/` takes a CA argument for this reason; the `tls*` versions do not.

**Narrative output style.** `RunDemo()` prints step headers (`=== Step N/M: Description ===`), one-line explanations, then tagged log lines with `[SERVER]`, `[CLIENT]`, or `[UNTRUSTED CLIENT]` prefixes. Use `fmt.Print*` throughout — never `println` (it writes to stderr and interleaves badly).

**All `tls.Config` structs set `MinVersion: tls.VersionTLS12`.** This makes the security floor explicit in every server and client across all packages.

**File-based servers set timeouts.** `ReadTimeout: 10s`, `WriteTimeout: 10s`, `IdleTimeout: 120s` on all `http.Server` structs in `tlsfiles`, `mtlsfiles`, and `mtlstpm`.

**File-based demos use graceful shutdown.** `server.Shutdown(ctx)` with a 5-second timeout context instead of `server.Close()`.

**Private key files use restrictive permissions.** `WriteKey` uses `os.OpenFile(..., 0600)` so key files are owner-only readable.

**Errors are wrapped with context.** Always use `fmt.Errorf("what failed: %w", err)`. `RunDemo()` returns errors; `main.go` panics on non-nil.

**The untrusted-client step in mTLS.** Step 6/6 of the mTLS demo intentionally creates a second CA and a client cert signed by it, then shows the server rejecting it. Suppress the Go HTTP server's internal TLS error log with `server.Config.ErrorLog = log.New(io.Discard, "", 0)` before `StartTLS()` to keep output clean.

**Tests are integration tests.** Each package (except `mtlstpm`) has one `TestDemo` that calls `RunDemo()` and expects no error. There are no unit tests or mocks. A passing test means the full TLS/mTLS handshake succeeded. `mtlstpm` has no test — TPM/Windows cert store operations cannot be mocked.

**`mtlstpm` uses `certtostore` for the client key.** `certtostore.OpenWinCertStoreCurrentUser(provider, container, issuers, ...)` opens the store; `store.Generate(GenerateOpts{EC, 256})` creates the TPM-backed key; `store.StoreWithDisposition(cert, caCert, 3)` imports the signed cert (disposition 3 = CERT_STORE_ADD_REPLACE_EXISTING) — the second argument is the CA certificate (never `nil`; the library unconditionally dereferences it). At runtime, re-derive the key with `store.CertByCommonName(cn)` → `store.CertKey(ctx)` → pass the `*Key` (which implements `crypto.Signer`) as `tls.Certificate.PrivateKey`. The `mtlstpm/client.go::CreateClient` accepts `crypto.Signer`, so it works for both the TPM-backed key and the in-memory `*ecdsa.PrivateKey` used by the untrusted client step. No automatic cleanup — demo prints manual PowerShell commands at the end. `//go:build windows` on all `mtlstpm/*.go` files. Dispatch via `cmd/mtlstpm_windows.go` / `cmd/mtlstpm_other.go`.

**`internal/tpm` package.** Windows-only shared helpers for TPM detection, `CurrentUser\My` inspection, provider selection, key generation, certificate import, and runtime signer recovery.

**`internal/pwsh` package.** Wraps `exec.Command("powershell", ...)` for script execution such as cleanup helpers. No build constraint needed — it just invokes the `powershell` binary.

**Production agent guides and standalone examples.** `example/` contains standalone AGENTS.md files and runnable implementations. `example/mtls/` has enterprise mTLS (certs, operator, server, client packages). `example/winservice/` has Windows service + TPM. `example/container/` has containerized mTLS server + Dockerfile + K8s manifests. Each AGENTS.md is self-contained and can be copied into production repositories.

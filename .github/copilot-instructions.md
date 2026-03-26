# Copilot Instructions

## Commands

```bash
# Run all tests
go test ./...

# Run tests for one package
go test ./internal/tlsmem/...
go test ./internal/mtlsmem/...
go test ./internal/tlsfiles/...
go test ./internal/mtlsfiles/...

# Run a single test by name
go test ./internal/mtlsfiles/... -run TestDemo

# Run a demo
go run cmd/main.go tlsmem
go run cmd/main.go mtlsmem
go run cmd/main.go tlsfiles
go run cmd/main.go mtlsfiles

# Via PowerShell script
pwsh scripts/run.ps1 tlsmem
pwsh scripts/run.ps1 mtlsmem
pwsh scripts/run.ps1 tlsfiles
pwsh scripts/run.ps1 mtlsfiles
```

No linter is configured. No CI/CD pipeline exists.

## Architecture

`internal/cert` is the shared certificate package. There are four demo packages, all self-contained with the same four-file layout:

```
internal/
  cert/        – shared: CA + leaf cert generation, PrintCertificateInfo, TLSVersionName, WriteCert, WriteKey
  tlsmem/      – one-way TLS,   certs in memory
  mtlsmem/     – mutual TLS,    certs in memory
  tlsfiles/    – one-way TLS,   certs written to certs/tlsfiles/ and loaded from disk
  mtlsfiles/   – mutual TLS,    certs written to certs/mtlsfiles/ and loaded from disk
```

Each demo package has the same four-file structure:

| File        | Role |
|-------------|------|

| `server.go` | `CreateServer(...)` — builds an `httptest.Server` with TLS config |
| `client.go` | `CreateClient(...)` — builds an `http.Client` with the right TLS config |
| `demo.go`   | `RunDemo()` — orchestrates the full flow with narrative step output |

`cmd/main.go` is a thin dispatcher: it reads `os.Args[1]` (`tlsmem`, `mtlsmem`, `tlsfiles`, or `mtlsfiles`) and calls the appropriate `RunDemo()`. No arg → usage error; unknown arg → error. No default.

## Key Conventions

**`internal/cert` is the shared package.** `cert.CreateCA(cn string)`, `cert.CreateLeafCert(signLeaf, cn)`, `cert.PrintCertificateInfo`, and `cert.TLSVersionName` are the shared exports. Both demo packages import it as `"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"` and call `cert.CreateCA(...)` etc.

**`signerFunc` / `cert.SignerFunc` closure pattern.** `cert.CreateCA()` returns a `SignerFunc` — a closure that signs leaf certificates with the CA's private key without exposing the key itself. Always pass this function through; never expose the raw CA key outside `internal/cert`.

**`httptest` for the server.** Use `httptest.NewUnstartedServer(handler)`, assign `server.TLS`, then call `server.StartTLS()`. Never call `server.Start()` — this project only exercises TLS paths.

**File-based demos use `runDemo(baseDir string)` for testability.** `RunDemo()` calls `runDemo(certBaseDir)` where `certBaseDir = "certs/tlsfiles"` (or `mtlsfiles`). Tests call `runDemo(t.TempDir())` directly — this keeps tests self-contained without touching the repo's `certs/` directory.

**File-based servers use `tls.LoadX509KeyPair`; clients use `os.ReadFile` + `certpool.AppendCertsFromPEM`.** Never reintroduce in-memory PEM bytes in the files packages.

**`certs/` is git-ignored.** File-based demos create it on each run; the directory structure mirrors ownership boundaries (`ca/`, `server/`, `client/`, `untrusted/`).

**mTLS server requires `ClientAuth: tls.RequireAndVerifyClientCert` + `ClientCAs`.** The `CreateServer` in `mtlsmem/` and `mtlsfiles/` takes a CA argument for this reason; the `tls*` versions do not.

**Narrative output style.** `RunDemo()` prints step headers (`=== Step N/M: Description ===`), one-line explanations, then tagged log lines with `[SERVER]`, `[CLIENT]`, or `[UNTRUSTED CLIENT]` prefixes. Use `fmt.Print*` throughout — never `println` (it writes to stderr and interleaves badly).

**Errors are wrapped with context.** Always use `fmt.Errorf("what failed: %w", err)`. `RunDemo()` returns errors; `main.go` panics on non-nil.

**The untrusted-client step in mTLS.** Step 6/6 of the mTLS demo intentionally creates a second CA and a client cert signed by it, then shows the server rejecting it. Suppress the Go HTTP server's internal TLS error log with `server.Config.ErrorLog = log.New(io.Discard, "", 0)` before `StartTLS()` to keep output clean.

**Tests are integration tests.** Each package has one `TestDemo` that calls `RunDemo()` and expects no error. There are no unit tests or mocks. A passing test means the full TLS/mTLS handshake succeeded.

# Copilot Instructions

## Commands

```bash
# Run all tests
go test ./...

# Run tests for one package
go test ./internal/tlsmem/...
go test ./internal/mtlsmem/...

# Run a single test by name
go test ./internal/mtlsmem/... -run TestDemo

# Run a demo
go run cmd/main.go tlsmem
go run cmd/main.go mtlsmem

# Via PowerShell script
pwsh scripts/run.ps1 tlsmem
pwsh scripts/run.ps1 mtlsmem
```

No linter is configured. No CI/CD pipeline exists.

## Architecture

`internal/ca` is the shared certificate package. `internal/tlsmem` and `internal/mtlsmem` are the two demo packages, each self-contained with the same four-file layout:

```
internal/
  ca/       – shared: CA + leaf cert generation, PrintCertificateInfo, TLSVersionName
  tlsmem/   – one-way TLS:   server authenticated, client is anonymous  (all certs in-memory)
  mtlsmem/  – mutual TLS:    both server and client authenticate each other (all certs in-memory)
```

Each demo package (`tlsmem`, `mtlsmem`) has the same four-file structure:

| File        | Role |
|-------------|------|
| `server.go` | `CreateServer(...)` — builds an `httptest.Server` with TLS config |
| `client.go` | `CreateClient(...)` — builds an `http.Client` with the right TLS config |
| `demo.go`   | `RunDemo()` — orchestrates the full flow with narrative step output |

`cmd/main.go` is a thin dispatcher: it reads `os.Args[1]` (`tlsmem` or `mtlsmem`) and calls the appropriate `RunDemo()`. No arg → usage error; unknown arg → error. No default.

## Key Conventions

**`internal/ca` is the shared package.** `ca.CreateCA(cn string)`, `ca.CreateLeafCert(signLeaf, cn)`, `ca.PrintCertificateInfo`, and `ca.TLSVersionName` are the shared exports. Both demo packages import it as `"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"` and call `ca.CreateCA(...)` etc.

**`signerFunc` / `ca.SignerFunc` closure pattern.** `ca.CreateCA()` returns a `SignerFunc` — a closure that signs leaf certificates with the CA's private key without exposing the key itself. Always pass this function through; never expose the raw CA key outside `internal/ca`.

**`httptest` for the server.** Use `httptest.NewUnstartedServer(handler)`, assign `server.TLS`, then call `server.StartTLS()`. Never call `server.Start()` — this project only exercises TLS paths.

**mTLS server requires `ClientAuth: tls.RequireAndVerifyClientCert` + `ClientCAs`.** The `CreateServer` in `mtlsmem/` takes a `*x509.Certificate` CA argument for this reason; the `tlsmem/` version does not.

**mTLS client takes PEM bytes, not file paths.** `CreateClient(ca, certPem, keyPem []byte)` uses `tls.X509KeyPair` in-memory. Do not reintroduce file-based loading.

**Narrative output style.** `RunDemo()` prints step headers (`=== Step N/M: Description ===`), one-line explanations, then tagged log lines with `[SERVER]`, `[CLIENT]`, or `[UNTRUSTED CLIENT]` prefixes. Use `fmt.Print*` throughout — never `println` (it writes to stderr and interleaves badly).

**Errors are wrapped with context.** Always use `fmt.Errorf("what failed: %w", err)`. `RunDemo()` returns errors; `main.go` panics on non-nil.

**The untrusted-client step in mTLS.** Step 6/6 of the mTLS demo intentionally creates a second CA and a client cert signed by it, then shows the server rejecting it. Suppress the Go HTTP server's internal TLS error log with `server.Config.ErrorLog = log.New(io.Discard, "", 0)` before `StartTLS()` to keep output clean.

**Tests are integration tests.** Each package has one `TestDemo` that calls `RunDemo()` and expects no error. There are no unit tests or mocks. A passing test means the full TLS/mTLS handshake succeeded.

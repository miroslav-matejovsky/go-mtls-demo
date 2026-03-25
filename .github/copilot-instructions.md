# Copilot Instructions

## Commands

```bash
# Run all tests
go test ./...

# Run tests for one package
go test ./internal/tls/...
go test ./internal/mtls/...

# Run a single test by name
go test ./internal/mtls/... -run TestDemo

# Run a demo
go run cmd/main.go tls
go run cmd/main.go mtls

# Via PowerShell script
pwsh scripts/run.ps1 tls
pwsh scripts/run.ps1 mtls
```

No linter is configured. No CI/CD pipeline exists.

## Architecture

Two parallel, self-contained demo packages under `internal/`:

```
internal/
  tls/   – one-way TLS:   server authenticated, client is anonymous
  mtls/  – mutual TLS:    both server and client authenticate each other
```

Each package has the same four-file structure:

| File        | Role |
|-------------|------|
| `cert.go`   | CA + leaf cert generation, `PrintCertificateInfo`, `keyUsageNames` |
| `server.go` | `CreateServer(...)` — builds an `httptest.Server` with TLS config |
| `client.go` | `CreateClient(...)` — builds an `http.Client` with the right TLS config |
| `demo.go`   | `RunDemo()` — orchestrates the full flow with narrative step output |

`cert.go` is intentionally duplicated between the two packages so each package is a standalone, readable unit.

`cmd/main.go` is a thin dispatcher: it reads `os.Args[1]` (`tls` or `mtls`) and calls the appropriate `RunDemo()`. No arg → usage error; unknown arg → error. No default.

## Key Conventions

**In-memory certificates only.** All keys and certificates are generated at runtime with `crypto/ecdsa` + `elliptic.P256()`. No PEM files, no `openssl`. Use `x509.MarshalECPrivateKey` + `pem.EncodeToMemory` to convert to bytes when needed.

**`signerFunc` closure pattern.** `CreateCa()` returns a `signerFunc` — a closure that signs leaf certificates with the CA's private key without exposing the key itself. Always pass this function through; never expose the raw CA key outside `cert.go`.

**`httptest` for the server.** Use `httptest.NewUnstartedServer(handler)`, assign `server.TLS`, then call `server.StartTLS()`. Never call `server.Start()` — this project only exercises TLS paths.

**mTLS server requires `ClientAuth: tls.RequireAndVerifyClientCert` + `ClientCAs`.** The `CreateServer` in `mtls/` takes a `*x509.Certificate` CA argument for this reason; the `tls/` version does not.

**mTLS client takes PEM bytes, not file paths.** `CreateClient(ca, certPem, keyPem []byte)` uses `tls.X509KeyPair` in-memory. Do not reintroduce file-based loading.

**Narrative output style.** `RunDemo()` prints step headers (`=== Step N/M: Description ===`), one-line explanations, then tagged log lines with `[SERVER]`, `[CLIENT]`, or `[UNTRUSTED CLIENT]` prefixes. Use `fmt.Print*` throughout — never `println` (it writes to stderr and interleaves badly).

**Errors are wrapped with context.** Always use `fmt.Errorf("what failed: %w", err)`. `RunDemo()` returns errors; `main.go` panics on non-nil.

**The untrusted-client step in mTLS.** Step 6/6 of the mTLS demo intentionally creates a second CA and a client cert signed by it, then shows the server rejecting it. Suppress the Go HTTP server's internal TLS error log with `server.Config.ErrorLog = log.New(io.Discard, "", 0)` before `StartTLS()` to keep output clean.

**Tests are integration tests.** Each package has one `TestDemo` that calls `RunDemo()` and expects no error. There are no unit tests or mocks. A passing test means the full TLS/mTLS handshake succeeded.

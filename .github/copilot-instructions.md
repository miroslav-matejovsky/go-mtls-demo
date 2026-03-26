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
go run cmd/main.go mtlstpm   # Windows only — requires Windows cert store + TPM (or software KSP fallback)

# Via PowerShell script
pwsh scripts/run.ps1 tlsmem
pwsh scripts/run.ps1 mtlsmem
pwsh scripts/run.ps1 tlsfiles
pwsh scripts/run.ps1 mtlsfiles
pwsh scripts/run.ps1 mtlstpm
```

No linter is configured. No CI/CD pipeline exists.

## Architecture

`internal/cert` is the shared certificate package. There are four demo packages, all self-contained with the same four-file layout:

```
internal/
  cert/        – shared: CA + leaf cert generation, PrintCertificateInfo, TLSVersionName, WriteCert, WriteKey
  pwsh/        – PowerShell helpers used by mtlstpm: CheckTPM(), ShowCertsInStore()
  tlsmem/      – one-way TLS,   certs in memory
  mtlsmem/     – mutual TLS,    certs in memory
  tlsfiles/    – one-way TLS,   certs written to certs/tlsfiles/ and loaded from disk
  mtlsfiles/   – mutual TLS,    certs written to certs/mtlsfiles/ and loaded from disk
  mtlstpm/     – mutual TLS,    server: files in certs/mtlstpm/; client: Windows cert store + TPM (Windows only)
```

Each demo package has the same four-file structure:

| File        | Role |
|-------------|------|

| `server.go` | `CreateServer(...)` — builds an `httptest.Server` with TLS config |
| `client.go` | `CreateClient(...)` — builds an `http.Client` with the right TLS config |
| `demo.go`   | `RunDemo()` — orchestrates the full flow with narrative step output |

`cmd/main.go` is a thin dispatcher: it reads `os.Args[1]` (`tlsmem`, `mtlsmem`, `tlsfiles`, `mtlsfiles`, or `mtlstpm`) and calls the appropriate `RunDemo()`. No arg → usage error; unknown arg → error. No default. `mtlstpm` is dispatched via `cmd/mtlstpm_windows.go` (calls `mtlstpm.RunDemo()`) / `cmd/mtlstpm_other.go` (returns a "Windows only" error) to keep build constraints out of `main.go`.

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

**Tests are integration tests.** Each package (except `mtlstpm`) has one `TestDemo` that calls `RunDemo()` and expects no error. There are no unit tests or mocks. A passing test means the full TLS/mTLS handshake succeeded. `mtlstpm` has no test — TPM/Windows cert store operations cannot be mocked.

**`mtlstpm` uses `certtostore` for the client key.** `certtostore.OpenWinCertStoreCurrentUser(provider, container, issuers, ...)` opens the store; `store.Generate(GenerateOpts{EC, 256})` creates the TPM-backed key; `store.StoreWithDisposition(cert, nil, 3)` imports the signed cert (disposition 3 = CERT_STORE_ADD_REPLACE_EXISTING). At runtime, re-derive the key with `store.CertByCommonName(cn)` → `store.CertKey(ctx)` → pass the `*Key` (which implements `crypto.Signer`) as `tls.Certificate.PrivateKey`. The `mtlstpm/client.go::CreateClient` accepts `crypto.Signer`, so it works for both the TPM-backed key and the in-memory `*ecdsa.PrivateKey` used by the untrusted client step. No automatic cleanup — demo prints manual PowerShell commands at the end. `//go:build windows` on all `mtlstpm/*.go` files. Dispatch via `cmd/mtlstpm_windows.go` / `cmd/mtlstpm_other.go`.

**`internal/pwsh` package.** Wraps `exec.Command("powershell", ...)`. Exports `CheckTPM()` and `ShowCertsInStore(cn)`. No build constraint needed — it just invokes the `powershell` binary.

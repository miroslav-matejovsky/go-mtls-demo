# AGENTS.md

## Project overview

Go TLS / mTLS learning repository with progressive runnable examples — from minimal in-memory TLS through enterprise-grade mTLS with intermediate CAs and TPM-backed keys. Used as both documentation and implementation reference for building production mTLS services in Go, targeting Windows Server and Azure container deployments.

## Setup and commands

```bash
# Build
go build ./...

# Run all tests
go test ./...

# Run tests for one package
go test ./internal/mtlsfiles/...

# Run a single test by name
go test ./internal/mtlsfiles/... -run TestDemo

# Run a demo
go run ./cmd/ <scenario>
# Scenarios: tlsmem | mtlsmem | tlsfiles | mtlsfiles | mtlstpm | mtlsenterprise

# Validate everything (vet + tidy + build + test)
pwsh scripts/check.ps1
```

No linter configured. No CI pipeline.

## Architecture

```
internal/
  cert/              — shared: CA + leaf + intermediate CA generation, PrintCertificateInfo,
                       WriteCert, WriteKey, WriteChainBundle, TLSVersionName
  pwsh/              — PowerShell helpers (TPM check, cert store inspection)
  tlsmem/            — one-way TLS, certs in memory
  mtlsmem/           — mutual TLS, certs in memory
  tlsfiles/          — one-way TLS, certs from disk files
  mtlsfiles/         — mutual TLS, certs from disk files (best general-purpose template)
  mtlstpm/           — mutual TLS, client key in Windows cert store + TPM (Windows only)
  mtlsenterprise/    — mutual TLS, intermediate CA, role-specific EKU, DNS SANs, chain bundles
cmd/                 — thin dispatcher: reads os.Args[1] and calls the matching RunDemo()
configs/             — TOML config files per scenario
docs/                — 8-chapter narrative guide
```

### Package structure (every scenario follows this)

| File | Role |
|------|------|
| `config.go` | TOML config types + loaders |
| `operator.go` | PKI operator: creates CA, signs certs, distributes trust |
| `server.go` | `CreateServer(...)` — builds `*http.Server` or `*httptest.Server` with TLS config |
| `client.go` | `CreateClient(...)` — builds `*http.Client` with TLS config |
| `demo.go` | `RunDemo()` entry point + `runDemo(configs...)` for testability |
| `stepN.go` | One file per demo step |
| `demo_test.go` | Integration test calling `runDemo(...)` with `t.TempDir()` |

### Dispatcher (`cmd/main.go`)

Thin switch on `os.Args[1]`. Each case calls `<package>.RunDemo()`. The `mtlstpm` case is dispatched via build-constrained files (`cmd/mtlstpm_windows.go` / `cmd/mtlstpm_other.go`) to keep `//go:build` out of `main.go`. New scenarios need a new `case` added here.

### Shared certificate package (`internal/cert`)

All certificate generation lives here. Key exports:

| Export | Purpose |
|--------|---------|
| `SignerFunc` | Closure type: signs a leaf cert with the captured CA key |
| `CreateCA(cn, validity)` | Creates a flat CA + returns `SignerFunc` for leaf certs |
| `CreateLeafCert(signFn, cn)` | Generates ECDSA P-256 key + leaf cert via `SignerFunc` |
| `CreateRootCA(cn, validity)` | Creates root CA + returns `SignIntermediateFunc` for 3-tier PKI |
| `SignIntermediateFunc` | Closure type: creates an intermediate CA signed by the root |
| `ProfiledSignerFunc` | Closure type: signs a leaf cert with caller-supplied `LeafProfile` (EKU, SANs) |
| `LeafProfile` | Struct: `ExtKeyUsage`, `DNSNames`, `IPAddresses` |
| `CreateLeafCertWithProfile(signFn, cn, profile)` | Generates key + leaf cert via `ProfiledSignerFunc` |
| `WriteCert(path, cert)` | Writes PEM cert file, creates parent dirs |
| `WriteKey(path, keyDER)` | Writes PEM key file with 0600 permissions |
| `WriteChainBundle(path, leaf, intermediate)` | Writes leaf+intermediate PEM chain bundle |
| `PrintCertificateInfo(cert)` | Prints cert details to stdout |
| `TLSVersionName(version)` | Maps `uint16` TLS version to human-readable string |

## Code conventions

### Error handling

Always wrap errors with context: `fmt.Errorf("what failed: %w", err)`.
`RunDemo()` returns errors; `cmd/main.go` panics on non-nil.

### TLS configuration

- Always set `MinVersion: tls.VersionTLS12` on every `tls.Config`
- mTLS servers: `ClientAuth: tls.RequireAndVerifyClientCert` + `ClientCAs: pool`
- File-based servers: set `ReadTimeout: 10s`, `WriteTimeout: 10s`, `IdleTimeout: 120s`
- Use `server.Shutdown(ctx)` with a 5-second timeout for graceful shutdown

### Certificate generation (`internal/cert`)

- Algorithm: ECDSA P-256 exclusively
- Serial numbers: 128-bit random via `crypto/rand`
- Subject Key ID (SKID): SHA-256 of SubjectPublicKeyInfo on all certs
- Authority Key ID (AKID): Set on all non-self-signed certs, linking to issuer's SKID
- Private key files: written with 0600 permissions (`WriteKey`)

### SignerFunc closure pattern

`cert.CreateCA()` returns a `SignerFunc` — a closure that signs leaf certificates with the CA's private key without exposing the key itself. Similarly, `cert.CreateRootCA()` returns a `SignIntermediateFunc` which itself returns a `ProfiledSignerFunc`. Always pass these closures through; never expose the raw CA key outside `internal/cert`.

### Narrative output

`RunDemo()` prints step headers (`=== Step N/M: Description ===`), one-line explanations, then tagged log lines (`[SERVER]`, `[CLIENT]`, `[OPERATOR]`, `[UNTRUSTED CLIENT]`). Use `fmt.Print*` only — never `println` (it writes to stderr and interleaves badly).

### Build constraints

`mtlstpm` uses `//go:build windows` on all files. Platform dispatch via `cmd/mtlstpm_windows.go` / `cmd/mtlstpm_other.go`.

### Tests

Integration tests only. Each package (except `mtlstpm`) has `TestDemo` calling `runDemo(...)` with `t.TempDir()` configs. No unit tests or mocks. Passing test = full TLS handshake succeeded. Uses `github.com/stretchr/testify/require`.

### Server types by package

- **`tlsmem`, `mtlsmem`**: Use `httptest.NewUnstartedServer(handler)` → assign `server.TLS` → call `server.StartTLS()`. Never `server.Start()`.
- **`tlsfiles`, `mtlsfiles`, `mtlstpm`, `mtlsenterprise`**: Return `*http.Server` with `TLSConfig`. Start with `tls.Listen("tcp", addr, server.TLSConfig)` then `go server.Serve(ln)`.

### File-based demos

- `certs/` is git-ignored and recreated on each run
- Directory structure mirrors ownership boundaries: `ca/`, `server/`, `client/`, `untrusted/`
- Servers use `tls.LoadX509KeyPair`; clients use `os.ReadFile` + `certpool.AppendCertsFromPEM`
- `runDemo(configs...)` accepts config structs with paths, enabling `t.TempDir()` isolation in tests

### Untrusted-client negative test

The second-to-last step in every mTLS demo creates a separate CA and client cert that the server does not trust, then verifies the TLS handshake is rejected. Suppress Go's internal TLS error log with `server.Config.ErrorLog = log.New(io.Discard, "", 0)` before `StartTLS()` (mem packages) or before `server.Serve(ln)` (file packages).

## How to create a new mTLS scenario

1. **Create package** under `internal/<name>/` with the standard file structure
2. **Create configs** under `configs/<name>/` (TOML files for operator, server, client, untrusted_client)
3. **Follow `mtlsfiles` as the base template** — copy and modify
4. **For enterprise features**, follow `mtlsenterprise` which adds:
   - Root CA → Intermediate CA → Leaf (3-tier PKI)
   - Role-specific EKU (`ServerAuth`-only server certs, `ClientAuth`-only client certs)
   - DNS SANs on server certificates
   - Certificate chain bundles (leaf + intermediate PEM concatenated)
5. **Add dispatch** in `cmd/main.go` — new `case` in the switch
6. **Add integration test** with `t.TempDir()` isolation
7. **Include negative-path test** (untrusted client rejection) — always the second-to-last step
8. **Update `cmd/main.go` usage string** with the new scenario name

## Enterprise mTLS implementation guide

Use this section when implementing production mTLS services. The patterns below come from the repo's `mtlsenterprise` scenario, `internal/cert` package, and documentation.

### PKI topology

```
Root CA (offline, long-lived, 1+ year validity)
    │
    ├── Intermediate CA (operational, medium-lived, 30-day validity)
    │       │
    │       ├── Server leaf cert (ServerAuth EKU only, DNS SANs)
    │       └── Client leaf cert (ClientAuth EKU only)
    │
    └── [Future: additional intermediates for rotation]
```

Key rules:
- Root CA NEVER signs leaf certs directly
- Intermediate has `MaxPathLen: 0` and `MaxPathLenZero: true` (cannot create sub-intermediates)
- Root CA key is offline / HSM-backed in production
- Separate EKU per role: `ExtKeyUsageServerAuth` for servers, `ExtKeyUsageClientAuth` for clients
- Trust pools contain the ROOT CA cert only (not the intermediate)

### Operator (PKI) implementation pattern

The operator creates the PKI hierarchy and distributes certificates. In this repo, operator logic lives in `operator.go`.

```go
// Create root CA (offline in production)
rootCert, signIntermediate, err := cert.CreateRootCA(cn, validity)
// signIntermediate is a cert.SignIntermediateFunc closure — the root key is captured
// inside and never exposed.

// Create intermediate CA (operational issuer)
intCert, signLeaf, err := signIntermediate(cn, validity)
// signLeaf is a cert.ProfiledSignerFunc closure — the intermediate key is captured
// inside and never exposed.

// Issue server cert with role-specific profile
serverProfile := cert.LeafProfile{
    ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    DNSNames:    []string{"localhost", "myservice.internal"},
    IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
}
serverCert, serverKey, err := cert.CreateLeafCertWithProfile(signLeaf, cn, serverProfile)

// Issue client cert with client-only EKU
clientProfile := cert.LeafProfile{
    ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
}
clientCert, clientKey, err := cert.CreateLeafCertWithProfile(signLeaf, cn, clientProfile)

// Write chain bundle (leaf + intermediate in one PEM file)
cert.WriteChainBundle(chainPath, serverCert, intCert)

// Write private key (DER-encoded)
keyDER, _ := x509.MarshalECPrivateKey(serverKey)
cert.WriteKey(keyPath, keyDER)

// Distribute ROOT CA cert (not intermediate) to trust pools
cert.WriteCert(trustPath, rootCert)
```

### Server implementation pattern

```go
// Load certificate chain (leaf + intermediate) and private key
serverCert, err := tls.LoadX509KeyPair(chainFile, keyFile)

// Trust pool: ROOT CA cert (not intermediate)
rootPEM, _ := os.ReadFile(rootCertFile)
clientCAs := x509.NewCertPool()
clientCAs.AppendCertsFromPEM(rootPEM)

tlsCfg := &tls.Config{
    MinVersion:   tls.VersionTLS12,
    Certificates: []tls.Certificate{serverCert},
    ClientCAs:    clientCAs,
    ClientAuth:   tls.RequireAndVerifyClientCert,
}

srv := &http.Server{
    TLSConfig:    tlsCfg,
    ReadTimeout:  10 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  120 * time.Second,
    Handler:      handler,
}

// Start with tls.Listen (file-based pattern)
ln, err := tls.Listen("tcp", address, srv.TLSConfig)
go srv.Serve(ln)

// Graceful shutdown
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
srv.Shutdown(ctx)
```

### Client implementation pattern

```go
// Load client certificate chain (leaf + intermediate) and private key
clientCert, err := tls.LoadX509KeyPair(chainFile, keyFile)

// Trust pool: ROOT CA cert
rootPEM, _ := os.ReadFile(rootCertFile)
rootCAs := x509.NewCertPool()
rootCAs.AppendCertsFromPEM(rootPEM)

client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            MinVersion:   tls.VersionTLS12,
            RootCAs:      rootCAs,
            Certificates: []tls.Certificate{clientCert},
        },
    },
}
```

### Certificate chain bundles

Chain bundle = PEM file with leaf cert first, then intermediate cert. This is the standard TLS presentation order.

```
-----BEGIN CERTIFICATE-----
<leaf certificate bytes>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<intermediate CA certificate bytes>
-----END CERTIFICATE-----
```

The server presents this chain during the TLS handshake. The client validates: leaf → intermediate → root (root comes from the trust pool, not the chain file).

Use `cert.WriteChainBundle(path, leafCert, intermediateCert)` to create these files.

### Configuration pattern (TOML)

Enterprise configs use `root_ca` and `intermediate_ca` sections (not the flat `ca` section from simpler scenarios). Server and client configs use `chain_file` (not `cert_file`) and `root_cert_file` (not `ca_cert_file`).

```toml
# configs/mtlsenterprise/operator.toml
[root_ca]
cn        = "My Root CA"
cert_file = "certs/mtlsenterprise/root-ca/cert.crt"
validity  = "8760h"          # 1 year

[intermediate_ca]
cn        = "My Intermediate CA"
cert_file = "certs/mtlsenterprise/intermediate-ca/cert.crt"
validity  = "720h"           # 30 days

# configs/mtlsenterprise/server.toml
[server]
address        = "127.0.0.1:8446"
cn             = "My Server"
chain_file     = "certs/mtlsenterprise/server/chain.crt"      # leaf + intermediate bundle
key_file       = "certs/mtlsenterprise/server/server.key"
root_cert_file = "certs/mtlsenterprise/server/root-ca.crt"    # ROOT CA for client trust pool
dns_names      = ["localhost", "myservice.internal"]

# configs/mtlsenterprise/client.toml
[client]
cn             = "My Client"
chain_file     = "certs/mtlsenterprise/client/chain.crt"      # leaf + intermediate bundle
key_file       = "certs/mtlsenterprise/client/client.key"
root_cert_file = "certs/mtlsenterprise/client/root-ca.crt"    # ROOT CA for server trust pool

# configs/mtlsenterprise/untrusted_client.toml
[untrusted_client]
root_ca_cn         = "Untrusted Root CA"
intermediate_ca_cn = "Untrusted Intermediate CA"
cn                 = "Untrusted Client"
chain_file         = "certs/mtlsenterprise/untrusted/chain.crt"
key_file           = "certs/mtlsenterprise/untrusted/client.key"
root_cert_file     = "certs/mtlsenterprise/untrusted/root-ca.crt"
```

### Security checklist

- ✅ ECDSA P-256 for all key pairs
- ✅ Random 128-bit serial numbers
- ✅ SKID/AKID on all certificates
- ✅ Private key files restricted to 0600
- ✅ `MinVersion: tls.VersionTLS12`
- ✅ Server timeouts (`ReadTimeout`, `WriteTimeout`, `IdleTimeout`)
- ✅ Graceful shutdown via `server.Shutdown(ctx)`
- ✅ Role-specific EKU (`ServerAuth` vs `ClientAuth`)
- ✅ DNS SANs on server certificates
- ✅ Intermediate CA with `MaxPathLen: 0`
- ✅ Root CA trust pool (not intermediate directly)
- ✅ Negative-path testing (untrusted cert rejection)
- ✅ Certificate chain bundles for TLS presentation
- ✅ SignerFunc closure pattern — CA keys never exposed

### Testing pattern

```go
func TestDemo(t *testing.T) {
    base := t.TempDir()
    opCfg := OperatorConfig{
        RootCA: RootCAConfig{
            CN:       "Test Root CA",
            CertFile: filepath.Join(base, "root-ca", "cert.crt"),
            Validity: "24h",
        },
        IntermediateCA: IntermediateCAConfig{
            CN:       "Test Intermediate CA",
            CertFile: filepath.Join(base, "intermediate-ca", "cert.crt"),
            Validity: "24h",
        },
    }
    serverCfg := ServerConfig{
        Address:      "127.0.0.1:0",   // :0 for random port in tests
        CN:           "Test Server",
        ChainFile:    filepath.Join(base, "server", "chain.crt"),
        KeyFile:      filepath.Join(base, "server", "server.key"),
        RootCertFile: filepath.Join(base, "server", "root-ca.crt"),
        DNSNames:     []string{"localhost"},
    }
    clientCfg := ClientConfig{
        CN:           "Test Client",
        ChainFile:    filepath.Join(base, "client", "chain.crt"),
        KeyFile:      filepath.Join(base, "client", "client.key"),
        RootCertFile: filepath.Join(base, "client", "root-ca.crt"),
    }
    untrustedCfg := UntrustedClientConfig{
        RootCACN:           "Untrusted Root CA",
        IntermediateCACN:   "Untrusted Intermediate CA",
        CN:                 "Untrusted Client",
        ChainFile:          filepath.Join(base, "untrusted", "chain.crt"),
        KeyFile:            filepath.Join(base, "untrusted", "client.key"),
        RootCertFile:       filepath.Join(base, "untrusted", "root-ca.crt"),
    }
    require.NoError(t, runDemo(opCfg, serverCfg, clientCfg, untrustedCfg))
}
```

Rules:
- Use `t.TempDir()` for file isolation — never touch the repo's `certs/` directory
- Test the full flow end-to-end (not individual functions)
- Always include the untrusted-client rejection step in the demo flow
- Use `require.NoError` from `github.com/stretchr/testify/require`
- Use address `127.0.0.1:0` in tests for OS-assigned port

## Deployment guidance

For deploying mTLS services in production, see:
- `docs/07-windows-deployment.md` — Windows Server, cert store, TPM, Group Policy
- `docs/08-azure-container-deployment.md` — AKS, ACI, Key Vault, Managed Identity

## Documentation

8 chapters in `docs/`:

| File | Topic |
|------|-------|
| `01-learning-path.md` | Learning path |
| `02-core-tls-and-mtls-model.md` | Core TLS/mTLS model |
| `03-scenario-patterns.md` | Scenario patterns |
| `04-production-guidance.md` | Production guidance (Windows + Azure) |
| `05-security-testability-and-rotation.md` | Security, testability, rotation |
| `06-what-to-copy-next.md` | What to build next |
| `07-windows-deployment.md` | Windows deployment |
| `08-azure-container-deployment.md` | Azure container deployment |

# Enterprise mTLS with TPM-Backed Client Keys

Windows-only demo combining **enterprise PKI topology** (Root CA → Intermediate CA → leaf certificates) with **TPM-backed client keys** via the Windows Certificate Store.

## What it demonstrates

| Feature | Source |
|---------|--------|
| 3-tier certificate hierarchy | `internal/pki.CreateRootCA` → `SignIntermediateFunc` → `ProfiledSignerFunc` |
| Role-specific EKU | ServerAuth for server, ClientAuth for client |
| SKID/AKID chain linkage | Verified in step 2 and summarised in step 9 |
| TPM-backed client key | `certtostore.OpenWinCertStoreCurrentUser` + `Generate` |
| Enterprise cert chain in TLS | Client presents leaf + intermediate during handshake |
| File-based server chain | `tls.LoadX509KeyPair` with chain bundle |
| Untrusted client rejection | Separate PKI hierarchy, server refuses the cert |

## 9-step flow

| Step | Description |
|------|-------------|
| 1 | Create Root CA (offline in production) |
| 2 | Create Intermediate CA (signed by Root) — print SKID/AKID |
| 3 | Generate server cert (ServerAuth EKU, DNS SANs) — write chain bundle + key |
| 4 | Check TPM, generate client key in Windows cert store |
| 5 | Sign client cert with enterprise intermediate (ClientAuth EKU) |
| 6 | Import cert into Windows store, re-derive signer |
| 7 | Start mTLS server, make trusted request |
| 8 | Demonstrate untrusted client (separate enterprise PKI) |
| 9 | Chain summary + cleanup prompt |

## How to run

```bash
go run ./cmd/ mtlsenterprisetpm
```

## File layout

```
internal/scenarios/mtlsenterprisetpm/
├── config.go    — TOML config types and loaders
├── demo.go      — Orchestrator, demoState, scenario-local adapter helpers, resource cleanup
├── step1.go     — Create Root CA
├── step2.go     — Create Intermediate CA
├── step3.go     — Generate server cert
├── step4.go     — Check TPM + generate client key
├── step5.go     — Sign client cert
├── step6.go     — Import cert + re-derive signer
├── step7.go     — Start server + trusted request
├── step8.go     — Untrusted client rejection
└── step9.go     — Chain summary + cleanup
```

## Differences from related demos

| | `mtlstpm` | `mtlsenterprise` | **`mtlsenterprisetpm`** |
|---|-----------|-------------------|-------------------------|
| CA hierarchy | Flat (single CA) | Root → Intermediate | Root → Intermediate |
| Client key storage | Windows cert store (TPM/NCrypt) | File on disk | Windows cert store (TPM/NCrypt) |
| Client TLS chain | Leaf only | Leaf + intermediate (file) | Leaf + intermediate (in-memory from store) |
| Server chain | Single cert file | Chain bundle file | Chain bundle file |

## Windows-only

All `.go` files carry `//go:build windows`. The dispatcher in `cmd/` uses build-constrained files (`mtlsenterprisetpm_windows.go` / `mtlsenterprisetpm_other.go`) so the binary compiles on all platforms but returns an error on non-Windows.

# Go TLS / mTLS Guide and Examples

Hands-on guidance and runnable examples for implementing one-way TLS and mutual TLS (mTLS) in Go using ECDSA P-256 certificates.

## Concepts

```text
TLS (one-way)   Client ──── verify server cert ────► Server
mTLS (mutual)   Client ──── verify server cert ────► Server
                Client ◄─── verify client cert ───── Server
```

## Scenarios

| Package                                   | Mode        | Certs                                                           |
| ----------------------------------------- | ----------- | --------------------------------------------------------------- |
| [tlsmem](internal/tlsmem/README.md)       | One-way TLS | In memory                                                       |
| [mtlsmem](internal/mtlsmem/README.md)     | Mutual TLS  | In memory                                                       |
| [tlsfiles](internal/tlsfiles/README.md)   | One-way TLS | Written to `certs/tlsfiles/`                                    |
| [mtlsfiles](internal/mtlsfiles/README.md) | Mutual TLS  | Written to `certs/mtlsfiles/`                                   |
| [mtlsenterprise](internal/mtlsenterprise/README.md) | Mutual TLS  | Intermediate CA, role-specific EKU, DNS SANs, chain bundles     |
| [mtlstpm](internal/mtlstpm/README.md)     | Mutual TLS  | Server: files · Client: Windows cert store + TPM (Windows only) |

## Guidance

Use [docs/index.md](docs/index.md) as the main guide for how to read this repository as an implementation reference, from basic TLS through production-oriented mTLS patterns.

## Running

```pwsh
go run ./cmd/ <tlsmem|mtlsmem|tlsfiles|mtlsfiles|mtlsenterprise|mtlstpm>
.\scripts\run.ps1  <tlsmem|mtlsmem|tlsfiles|mtlsfiles|mtlsenterprise|mtlstpm>
```

## References

- [Create & Sign x509 Certificates in Golang](https://medium.com/@shaneutt/create-sign-x509-certificates-in-golang-8ac4ae49f903)
- [mTLS series](https://victoronsoftware.com/posts/mtls/)
- [mTLS examples in Go](https://github.com/getvictor/mtls)
- [CertToStore Go package](https://pkg.go.dev/github.com/google/certtostore)

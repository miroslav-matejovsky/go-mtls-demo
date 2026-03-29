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
| [mtlsenterprisetpm](internal/mtlsenterprisetpm/README.md) | Mutual TLS  | Enterprise PKI + client key in Windows cert store + TPM (Windows only) |
| [mtlstpm](internal/mtlstpm/README.md)     | Mutual TLS  | Server: files · Client: Windows cert store + TPM (Windows only) |

## Guidance

Use [docs/index.md](docs/index.md) as the main guide for how to read this repository as an implementation reference, from basic TLS through production-oriented mTLS patterns.

## Standalone Examples

The [example/](example/) folder contains standalone, runnable implementations of enterprise mTLS patterns — each with an AGENTS.md guide for AI coding agents:

| Example | Focus |
| ------- | ----- |
| [example/mtls/](example/mtls/) | Enterprise mTLS with intermediate CA, role-specific EKU, chain bundles |
| [example/winservice/](example/winservice/) | Windows Service + TPM-backed client keys |
| [example/container/](example/container/) | Container deployment with health checks (Dockerfile + K8s) |

### AGENTS.md Guides

| Guide | Focus |
| ----- | ----- |
| [AGENTS.md](example/mtls/AGENTS.md) | Core mTLS concepts, PKI topology, security checklist |
| [certs/AGENTS.md](example/mtls/certs/AGENTS.md) | Certificate domain (creation, signing, store, lifecycle) |
| [operator/AGENTS.md](example/mtls/operator/AGENTS.md) | PKI operator workflows and CLI tool design |
| [server/AGENTS.md](example/mtls/server/AGENTS.md) | Server-side mTLS implementation |
| [client/AGENTS.md](example/mtls/client/AGENTS.md) | Client-side mTLS implementation |
| [container/AGENTS.md](example/container/AGENTS.md) | Container deployment (Azure/Kubernetes) |
| [winservice/AGENTS.windows.md](example/winservice/AGENTS.windows.md) | Windows Server deployment |

## Running

```pwsh
go run ./cmd/ <tlsmem|mtlsmem|tlsfiles|mtlsfiles|mtlsenterprise|mtlsenterprisetpm|mtlstpm>
.\scripts\run.ps1  <tlsmem|mtlsmem|tlsfiles|mtlsfiles|mtlsenterprise|mtlsenterprisetpm|mtlstpm>
```

## References

- [Create & Sign x509 Certificates in Golang](https://medium.com/@shaneutt/create-sign-x509-certificates-in-golang-8ac4ae49f903)
- [mTLS series](https://victoronsoftware.com/posts/mtls/)
- [mTLS examples in Go](https://github.com/getvictor/mtls)
- [CertToStore Go package](https://pkg.go.dev/github.com/google/certtostore)

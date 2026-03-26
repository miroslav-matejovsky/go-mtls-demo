# Go TLS / mTLS Demo

Hands-on walkthroughs of one-way TLS and mutual TLS (mTLS) in Go using ECDSA P-256 certificates.

## Concepts

```
TLS (one-way)   Client ──── verify server cert ────► Server
mTLS (mutual)   Client ──── verify server cert ────► Server
                Client ◄─── verify client cert ───── Server
```

## Scenarios

| Package | Mode | Certs |
|---------|------|-------|
| [tlsmem](internal/tlsmem/README.md) | One-way TLS | In memory |
| [mtlsmem](internal/mtlsmem/README.md) | Mutual TLS | In memory |
| [tlsfiles](internal/tlsfiles/README.md) | One-way TLS | Written to `certs/tlsfiles/` |
| [mtlsfiles](internal/mtlsfiles/README.md) | Mutual TLS | Written to `certs/mtlsfiles/` |

## Running

```pwsh
go run cmd/main.go <tlsmem|mtlsmem|tlsfiles|mtlsfiles>
.\scripts\run.ps1  <tlsmem|mtlsmem|tlsfiles|mtlsfiles>
```

## References

- [Create & Sign x509 Certificates in Golang](https://medium.com/@shaneutt/create-sign-x509-certificates-in-golang-8ac4ae49f903)
- [mTLS series](https://victoronsoftware.com/posts/mtls/)
- [mTLS examples in Go](https://github.com/getvictor/mtls)
- [CertToStore Go package](https://pkg.go.dev/github.com/google/certtostore)

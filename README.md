# Go TLS / mTLS Guide and Examples

Hands-on guidance and runnable examples for implementing one-way TLS and mutual TLS (mTLS) in Go using ECDSA P-256 certificates.

## Concepts

```text
TLS (one-way)   Client ──── verify server cert ────► Server
mTLS (mutual)   Client ──── verify server cert ────► Server
                Client ◄─── verify client cert ───── Server
```

## Scenarios

| Package                                                   | Mode        | Certs                                                                  |
| --------------------------------------------------------- | ----------- | ---------------------------------------------------------------------- |
| [tlsmem](internal/tlsmem/README.md)                       | One-way TLS | In memory                                                              |
| [mtlsmem](internal/mtlsmem/README.md)                     | Mutual TLS  | In memory                                                              |
| [tlsfiles](internal/tlsfiles/README.md)                   | One-way TLS | Written to `certs/tlsfiles/`                                           |
| [mtlsfiles](internal/mtlsfiles/README.md)                 | Mutual TLS  | Written to `certs/mtlsfiles/`                                          |
| [mtlsenterprise](internal/mtlsenterprise/README.md)       | Mutual TLS  | Intermediate CA, role-specific EKU, DNS SANs, chain bundles            |
| [mtlstpm](internal/mtlstpm/README.md)                     | Mutual TLS  | Server: files · Client: Windows cert store + TPM (Windows only)        |
| [mtlsenterprisetpm](internal/mtlsenterprisetpm/README.md) | Mutual TLS  | Enterprise PKI + client key in Windows cert store + TPM (Windows only) |

## Guidance

Use [docs/index.md](docs/index.md) as the main guide for how to read this repository as an implementation reference, from basic TLS through production-oriented mTLS patterns.

## Running

```pwsh
go run ./cmd/ <tlsmem|mtlsmem|tlsfiles|mtlsfiles|mtlsenterprise|mtlsenterprisetpm|mtlstpm>
.\scripts\run.ps1  <tlsmem|mtlsmem|tlsfiles|mtlsfiles|mtlsenterprise|mtlsenterprisetpm|mtlstpm>
```

## Glossary

| Abbreviation     | Meaning                                   | How it is used here                                                                                 |
| ---------------- | ----------------------------------------- | --------------------------------------------------------------------------------------------------- |
| TLS              | Transport Layer Security                  | One-way TLS demos where the client verifies the server certificate                                  |
| mTLS             | Mutual TLS                                | Demos where both client and server present and verify certificates                                  |
| PKI              | Public Key Infrastructure                 | The certificate chain setup used across the demos, from simple local CAs to enterprise-style chains |
| CA               | Certificate Authority                     | Issues the server and client certificates used in the demos                                         |
| Root CA          | Top-level certificate authority           | Acts as the trust anchor for demo certificate chains                                                |
| Intermediate CA  | Certificate authority signed by a root CA | Used in the enterprise-focused demos to model a more realistic chain                                |
| leaf certificate | End-entity certificate                    | The actual server or client certificate presented during the TLS handshake                          |
| EKU              | Extended Key Usage                        | Enterprise demos use it to separate server and client certificate purposes                          |
| SAN              | Subject Alternative Name                  | Holds DNS names and identities checked during certificate validation                                |
| SKID             | Subject Key Identifier                    | Included on generated certificates to help identify the subject key                                 |
| AKID             | Authority Key Identifier                  | Included to link an issued certificate back to its issuer                                           |
| TPM              | Trusted Platform Module                   | Used for Windows client key storage in the TPM-backed demos                                         |
| HSM              | Hardware Security Module                  | Mentioned as the broader hardware-backed key storage category related to TPM-backed keys            |
| KSP              | Key Storage Provider                      | Windows provider used when creating or loading TPM/software-backed keys                             |
| CNG              | Cryptography Next Generation              | The Windows cryptography platform behind the TPM and cert-store integrations                        |
| NCrypt           | Windows CNG key API family                | The Windows key API layer used under provider-backed certificate operations                         |
| PEM              | Privacy-Enhanced Mail                     | Text format used for certificate and key files in the in-memory and file-based demos                |
| DER              | Distinguished Encoding Rules              | Binary X.509 encoding wrapped by PEM when certificates are written to files                         |

## References

- [Create & Sign x509 Certificates in Golang](https://medium.com/@shaneutt/create-sign-x509-certificates-in-golang-8ac4ae49f903)
- [mTLS series](https://victoronsoftware.com/posts/mtls/)
- [mTLS examples in Go](https://github.com/getvictor/mtls)
- [CertToStore Go package](https://pkg.go.dev/github.com/google/certtostore)

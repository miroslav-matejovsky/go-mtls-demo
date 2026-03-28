# Chapter 6: What to build next

Back to [docs index](index.md)

## What to copy first

If you are implementing TLS or mTLS in Go today, use the repo like this:

- copy the trust-wiring ideas from `mtlsmem` if you want the cleanest conceptual example
- copy the loading patterns from `mtlsfiles` if your certificates come from files
- copy the enterprise PKI patterns from `mtlsenterprise` if you need an intermediate CA, role-specific EKU, or chain bundles
- copy the enterprise PKI + TPM patterns from `mtlsenterprisetpm` if you need hardware-backed client keys with a production CA hierarchy (Windows only)
- copy the `crypto.Signer` pattern from `mtlstpm` if your client or server key should stay outside normal file-based key storage
- copy the negative-path validation approach from every mTLS scenario

In practice, `mtlsenterprisetpm` is the most production-complete reference (enterprise PKI + hardware-backed keys, Windows only). On non-Windows platforms, `mtlsenterprise` is the best production PKI starting point. `mtlsfiles` remains the simplest operational baseline for services that use flat CA hierarchies.

## Additional scenarios worth implementing

To make the repo a stronger implementation guide, these scenarios would add value:

| Proposed scenario | Why it helps |
| --- | --- |
| `mtlstpmserverstore` | shows a Windows-hosted server whose key is not file-backed |
| `mtlsazurekv` | shows a server certificate and key sourced from Azure Key Vault |
| `mtlsrotation` | demonstrates leaf renewal and issuer rollover as part of normal operations |
| `mtlsrevocation` | demonstrates how revocation or short-lived cert strategies affect validation design |

Recommended order:

1. `mtlsrotation`
2. `mtlstpmserverstore`
3. `mtlsazurekv`
4. `mtlsrevocation`

## Deployment-specific guidance

After choosing what to copy from the scenarios above, read the deployment chapter that matches your target environment:

- **Deploying to Windows Server**: read [Chapter 7](07-windows-deployment.md) for server identity options (file vs cert store vs TPM), trust distribution via Group Policy, service account configuration, and troubleshooting.
- **Deploying to Azure containers (ACI or AKS)**: read [Chapter 8](08-azure-container-deployment.md) for certificate injection patterns (CSI driver, Key Vault, Managed Identity), renewal strategies, network security, and health probe considerations.

In both cases, `mtlsfiles` is the natural starting point — the Go code's certificate loading pattern stays the same regardless of how the cert files get to the process.

## Final takeaway

The main value of this repository is not that it contains one working demo. The value is that it shows a progression of correct implementation ideas:

- how TLS works in Go
- how mTLS works in Go
- how to structure server and client code
- how to load trust material properly
- how to test positive and negative paths
- how to think about stronger key protection and operational PKI concerns

Read the repo that way, and it becomes both documentation and a set of examples for implementing TLS and mTLS properly in Go.

Previous: [Chapter 5 - Security, testability, and rotation](05-security-testability-and-rotation.md)

Next: [Chapter 7 - Deploying mTLS services on Windows](07-windows-deployment.md)

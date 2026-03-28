# Chapter 6: What to build next

Back to [docs index](index.md)

## What to copy first

If you are implementing TLS or mTLS in Go today, use the repo like this:

- copy the trust-wiring ideas from `mtlsmem` if you want the cleanest conceptual example
- copy the loading patterns from `mtlsfiles` if your certificates come from files
- copy the `crypto.Signer` pattern from `mtlstpm` if your client or server key should stay outside normal file-based key storage
- copy the negative-path validation approach from every mTLS scenario

In practice, `mtlsfiles` plus selected ideas from `mtlstpm` is likely the best starting point for most serious implementations.

## Additional scenarios worth implementing

To make the repo a stronger implementation guide, these scenarios would add a lot of value:

| Proposed scenario | Why it helps |
| --- | --- |
| `mtlsintermediatefiles` | teaches the correct root -> intermediate -> leaf PKI model without adding OS-specific complexity |
| `mtlstpmserverstore` | shows a Windows-hosted server whose key is not file-backed |
| `mtlsazurekv` | shows a server certificate and key sourced from Azure Key Vault |
| `mtlsrotation` | demonstrates leaf renewal and issuer rollover as part of normal operations |
| `mtlsrevocation` | demonstrates how revocation or short-lived cert strategies affect validation design |

Recommended order:

1. `mtlsintermediatefiles`
2. `mtlsrotation`
3. `mtlstpmserverstore`
4. `mtlsazurekv`
5. `mtlsrevocation`

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

# Chapter 1: Learning path through the repository

Back to [docs index](index.md)

This repository is easiest to understand when you treat the scenarios as a progression instead of reading them at random.

## Recommended order

1. `tlsmem`
2. `mtlsmem`
3. `tlsfiles`
4. `mtlsfiles`
5. `mtlstpm`

That order mirrors how you usually build mTLS in a real Go system:

1. get TLS working
2. add client authentication
3. make certificate handling operationally realistic
4. harden private-key storage

## Why each step exists

| Scenario | What it teaches first | Why it matters |
| --- | --- | --- |
| `tlsmem` | CA trust and server authentication | helps you understand the smallest working TLS path |
| `mtlsmem` | client certificates and server-side client verification | isolates the mTLS handshake without file or platform complexity |
| `tlsfiles` | loading trust and identity from disk | matches how many real services are configured |
| `mtlsfiles` | full mTLS with realistic loading and tests | best baseline template for many Go services |
| `mtlstpm` | `crypto.Signer` with Windows cert store and TPM or NCrypt | shows how stronger key protection fits into the same Go TLS model |

## Which scenario to copy from

If you are implementing mTLS in Go today:

- start conceptually from `mtlsmem`
- start operationally from `mtlsfiles`
- borrow selectively from `mtlstpm` if you want stronger client key protection

That combination gives you the clearest path:

- `mtlsmem` explains the handshake
- `mtlsfiles` explains a maintainable real-world layout
- `mtlstpm` explains advanced key storage

## What the repository is trying to teach

The main lesson is not just "how to make one demo pass." The lesson is how to structure TLS and mTLS implementations so they stay understandable and evolve cleanly:

- certificate issuance is separate from transport setup
- trust loading is explicit
- server and client setup are separate concerns
- negative-path behavior is tested, not assumed
- stronger key-management options can be added without changing the TLS model itself

Previous: [docs index](index.md)

Next: [Chapter 2 - Core TLS and mTLS model in Go](02-core-tls-and-mtls-model.md)

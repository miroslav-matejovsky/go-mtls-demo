# Implementing TLS and mTLS in Go

This repository is meant to be both:

- a practical guide to implementing TLS and mTLS in Go
- a set of runnable examples that show the ideas in code

The examples are intentionally progressive. They start with the minimum needed to understand TLS, then add mutual authentication, then make certificate handling more realistic, and finally show stronger key-management patterns.

Use this docs set as the main narrative guide, and use the packages under `internal\` as the concrete examples.

## How to read these docs

If you are new to mTLS in Go, read the chapters in order.

If you already understand the protocol and want implementation patterns, start with:

- Chapter 3 for the best scenario-by-scenario code references
- Chapter 4 for production-oriented PKI and configuration guidance
- Chapter 5 for security, testability, and certificate rotation guidance
- Chapter 7 and 8 for Windows and Azure container deployment guidance

## Chapters

1. [Learning path through the repository](01-learning-path.md)
2. [Core TLS and mTLS model in Go](02-core-tls-and-mtls-model.md)
3. [Scenario patterns and what to copy](03-scenario-patterns.md)
4. [Production guidance and configuration direction](04-production-guidance.md)
5. [Security, testability, and rotation](05-security-testability-and-rotation.md)
6. [What to build next](06-what-to-copy-next.md)
7. [Deploying mTLS services on Windows](07-windows-deployment.md)
8. [Deploying mTLS services as Azure containers](08-azure-container-deployment.md)

## Agent guides for production implementations

The [agents/](agents/) folder contains standalone AGENTS.md files designed to be copied into any production Go repository. They guide AI coding agents on implementing enterprise-grade mTLS — each file is self-contained and covers one concern:

| Guide | Focus |
| ----- | ----- |
| [AGENTS.mtls.md](agents/AGENTS.mtls.md) | Core mTLS concepts, PKI topology, security checklist |
| [AGENTS.server.md](agents/AGENTS.server.md) | Server-side mTLS implementation |
| [AGENTS.client.md](agents/AGENTS.client.md) | Client-side mTLS implementation |
| [AGENTS.cli.md](agents/AGENTS.cli.md) | CLI operator tool for PKI management |
| [AGENTS.windows.md](agents/AGENTS.windows.md) | Windows Server deployment |
| [AGENTS.container.md](agents/AGENTS.container.md) | Container deployment (Azure) |

## Quick map of the scenarios

| Scenario | Role in the guide |
| --- | --- |
| `tlsmem` | smallest possible TLS example |
| `mtlsmem` | smallest possible mTLS example |
| `tlsfiles` | realistic TLS loading from files |
| `mtlsfiles` | best general-purpose mTLS template in the repo |
| `mtlsenterprise` | enterprise mTLS with intermediate CA, role-specific EKU, DNS SANs, chain bundles |
| `mtlstpm` | advanced client key protection with Windows cert store plus TPM or NCrypt |

## Important scope note

These docs use the repository as it exists today, but they also include production-oriented guidance derived from `prompt.txt`, especially for:

- using an intermediate CA instead of issuing leaves directly from a root-like CA
- treating file-backed server keys as test or development defaults
- supporting Windows certificate store or Azure Key Vault for server identity in future scenarios
- keeping the client autonomous after enrollment
- planning for certificate renewal and CA rollover

Where the repo does **not** implement something yet, the docs call that out explicitly.

Next: [Chapter 1 - Learning path through the repository](01-learning-path.md)

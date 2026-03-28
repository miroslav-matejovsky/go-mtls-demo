# Chapter 4: Production guidance and configuration direction

Back to [docs index](index.md)

The repo demonstrates the mechanics correctly, but production systems usually need stronger PKI and stronger storage choices than a teaching demo.

This chapter documents the direction the repo should teach, including the requirements captured in `prompt.txt`.

## Use an intermediate CA for leaf issuance

For production-oriented mTLS, the better model is:

```text
Offline or externally managed root CA
            |
            v
    Issuing intermediate CA
       |               |
       v               v
  Server leaf      Client leaf
```

Why this matters:

- the root CA is not used directly for routine leaf issuance
- intermediate rotation is easier
- compromise blast radius is smaller
- policy and trust management become cleaner

Important current-state note: the repo does **not** implement this yet. Today the scenarios use a single in-memory CA for simplicity. That is a useful teaching simplification, not the final PKI topology to copy unchanged into production.

## Treat file-based server keys as development and test defaults

The current file-based scenarios are good examples for:

- learning
- local development
- test automation
- showing ownership boundaries

But long-term guidance should teach more than flat PEM files for server identity.

### Recommended server identity options

| Option | Best fit | Pros | Cons |
| --- | --- | --- | --- |
| Files | local dev, tests, disposable demos | simplest setup, easiest automation, easiest debugging | weakest secret hygiene, exportable key material |
| Windows certificate store | Windows-hosted services | native OS-managed identity, better key handling than flat files | Windows-only, service identity and store permissions matter |
| Azure Key Vault | cloud-hosted services | centralized control, auditing, managed rotation patterns, HSM-backed options | operational complexity, Azure dependency, identity and RBAC setup |

The repo should keep file-based server identity for testing and teaching, while documenting and eventually implementing stronger storage options.

## Make the client autonomous after enrollment

The `mtlstpm` scenario already points in the right direction: at runtime, the client does not depend on the original in-memory signer. It rediscovers the certificate in the store and derives a signing key handle from it.

That is the model the repo should keep teaching:

- enrollment creates or rotates identity
- runtime discovers the current certificate
- runtime signs through a stable interface such as `crypto.Signer`

For stronger production guidance, the repo should prefer stable runtime lookup identifiers such as:

- thumbprint
- subject key identifier
- explicit certificate labels

Using Common Name lookup is understandable in a demo, but it is too weak as the only long-term identity selection strategy.

## Make CA changes an operational trust problem

The prompt requirement that intermediate-CA changes should not break authentication is best read like this:

- application code should not need to change
- runtime certificate selection should stay stable
- trust bundles and issued leaf certificates may change
- rollout should be handled operationally

That means the repo should eventually teach this rollout pattern:

1. trust the new intermediate before switching issuance
2. allow old and new intermediates during a migration window
3. renew leaves under the new intermediate
4. retire the old intermediate only after convergence

## Current configuration shape in the repo

Today, `configs/mtlstpm` is intentionally simple:

```toml
[ca]
cn        = "go mTLS TPM Demo CA"
cert_file = "certs/mtlstpm/ca/cert.crt"
validity  = "24h"

[server]
address      = "127.0.0.1:8445"
cn           = "go mTLS TPM Demo Server"
cert_file    = "certs/mtlstpm/server/server.crt"
key_file     = "certs/mtlstpm/server/server.key"
ca_cert_file = "certs/mtlstpm/server/ca.crt"

[client]
cn        = "go mTLS TPM Demo Client"
container = "go-mtls-demo-client"

[client.store]
location          = "CurrentUser"
provider_override = ""
```

That works for the current demo, but it does not yet express the production-oriented choices the docs should teach.

## Configuration direction to aim for

A future-friendly configuration shape should make identity sources and trust sources explicit:

```toml
[ca.intermediate]
cn        = "go mTLS Demo Intermediate CA"
cert_file = "certs/mtls/ca/intermediate.crt"
validity  = "720h"

[server]
address = "127.0.0.1:8445"
cn      = "go mTLS Demo Server"

[server.identity]
kind = "file" # file | windows_store | azure_key_vault

[server.identity.file]
cert_file = "certs/mtls/server/server.crt"
key_file  = "certs/mtls/server/server.key"

[server.identity.windows_store]
location   = "LocalMachine"
store_name = "My"
thumbprint = ""

[server.identity.azure_key_vault]
vault_url        = "https://example.vault.azure.net/"
certificate_name = "mtls-server"
certificate_ver  = ""

[server.trust]
client_issuer_bundle = "certs/mtls/server/client-issuers.pem"

[client]
cn        = "go mTLS Demo Client"
container = "go-mtls-demo-client"

[client.store]
location          = "CurrentUser"
provider_override = ""

[client.identity]
lookup_kind  = "thumbprint" # thumbprint | subject_cn | subject_key_id
lookup_value = ""

[client.trust]
server_issuer_source = "windows_store" # windows_store | file
store_location       = "CurrentUser"
store_name           = "CA"
subject_cn           = "go mTLS Demo Intermediate CA"
```

This is not current code. It is a useful target shape for the docs because it makes three things explicit:

- where the server gets its identity
- where the server gets its trust for validating clients
- how the client finds its identity and trust at runtime

Previous: [Chapter 3 - Scenario patterns and what to copy](03-scenario-patterns.md)

Next: [Chapter 5 - Security, testability, and rotation](05-security-testability-and-rotation.md)

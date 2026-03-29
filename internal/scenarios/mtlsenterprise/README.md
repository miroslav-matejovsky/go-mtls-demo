# mtlsenterprise — Enterprise mTLS with Intermediate CA

Demonstrates mutual TLS with a **3-tier PKI hierarchy**: Root CA → Intermediate CA → Leaf certificates.
Each leaf certificate is issued with role-specific Extended Key Usage (EKU), DNS Subject Alternative
Names, and is bundled with the intermediate CA into a chain file for presentation during the TLS handshake.

```text
Root CA (offline)
  └─ Intermediate CA (operational issuer, MaxPathLen: 0)
       ├─ Server cert  (EKU: ServerAuth, DNS SANs)
       └─ Client cert  (EKU: ClientAuth)
```

## What this teaches

- **3-tier PKI hierarchy** — root signs intermediate; intermediate signs leaves; root key is never written to disk
- **Role-specific EKU** — server certs only get `ServerAuth`, client certs only get `ClientAuth`
- **DNS SANs** — server certificates include DNS Subject Alternative Names
- **Chain bundles** — leaf + intermediate packed into a single PEM file for `tls.LoadX509KeyPair`
- **SKID/AKID linkage** — how Subject Key ID and Authority Key ID chain the hierarchy together
- **Root CA trust anchors** — only the root CA cert is distributed; the intermediate is delivered in the chain bundle

## Run

```pwsh
go run ./cmd/ mtlsenterprise
```

Certificate files are written to `certs/mtlsenterprise/` (git-ignored) and recreated on every run.

## What happens

| Step | What                                                                              |
| ---- | --------------------------------------------------------------------------------- |
| 1/8  | Create root CA (offline) — key stays in memory                                    |
| 2/8  | Create intermediate CA signed by root — MaxPathLen: 0 prevents sub-intermediates  |
| 3/8  | Generate server certificate with ServerAuth EKU and DNS SANs                      |
| 4/8  | Generate client certificate with ClientAuth EKU                                   |
| 5/8  | Start mTLS server presenting server cert + intermediate CA chain                  |
| 6/8  | Trusted client request — full chain verification: leaf → intermediate → root      |
| 7/8  | Untrusted client from a different PKI — rejected by the server                    |
| 8/8  | Inspect certificate chain (SKID/AKID) and file layout                             |

## File layout

```text
certs/mtlsenterprise/
  root-ca/
    cert.crt              ← public, root CA certificate (offline)
  intermediate-ca/
    cert.crt              ← public, intermediate CA certificate
  server/
    chain.crt             ← public, server leaf + intermediate CA bundle
    server.key            ← private, never leaves the server machine
    root-ca.crt           ← public, root CA copy for verifying client chains
  client/
    chain.crt             ← public, client leaf + intermediate CA bundle
    client.key            ← private, never leaves the client machine
    root-ca.crt           ← public, root CA copy for verifying server chain
  untrusted/
    chain.crt             ← public, rejected by server (different PKI)
    client.key            ← private
    root-ca.crt           ← public, trusted server's root CA copy
```

## Key differences from mtlsfiles

| Aspect              | mtlsfiles                     | mtlsenterprise                              |
| ------------------- | ----------------------------- | ------------------------------------------- |
| PKI depth           | Single CA → leaf              | Root CA → Intermediate CA → leaf            |
| EKU                 | Both ServerAuth + ClientAuth  | Role-specific (ServerAuth or ClientAuth)    |
| DNS SANs            | Not configured                | Server certs include DNS SANs               |
| Certificate files   | Individual leaf cert PEM      | Chain bundle (leaf + intermediate) PEM      |
| Trust anchor        | CA cert directly              | Root CA cert (intermediate in chain bundle) |
| Untrusted scenario  | Different single CA           | Entirely separate 3-tier PKI hierarchy      |

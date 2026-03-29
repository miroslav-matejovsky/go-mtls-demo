# PKI Operator Workflows

> **Parent:** [AGENTS.mtls.md](AGENTS.mtls.md) — mTLS concepts and architecture
> **Layer:** Application
> **Go package:** `operator.go` in each demo package

> **Audience:** AI coding agents building a production CLI tool in Go that manages
> PKI (Public Key Infrastructure) for mutual TLS. This tool is used by operators
> to create certificate authorities, issue certificates, and distribute trust
> material to servers and clients. For certificate creation APIs and domain logic
> see [AGENTS.certs.md](AGENTS.certs.md).

---

## PKI operator responsibilities

The CLI tool you are building automates the role of a PKI operator. The operator's job is to:

1. **Create and secure the root CA** — an offline ceremony that produces the root of trust. The root CA private key must be protected above all else; in production it lives in an HSM or is deleted from disk after signing the intermediate.
2. **Create intermediate CA(s)** — signed by the root CA. All leaf certificates are issued from an intermediate, never directly from the root. This limits blast radius: if an intermediate is compromised, the root can revoke it and issue a new one.
3. **Issue leaf certificates with role-specific profiles** — server certs get `ExtKeyUsageServerAuth` and DNS SANs; client certs get `ExtKeyUsageClientAuth`. Never mix these.
4. **Distribute trust material** — the root CA certificate (public) goes to every party that needs to verify certificates. This is the only cert that goes into trust pools.
5. **Distribute identity material** — chain bundles (leaf + intermediate PEM) and private keys go to the party that owns them. A server gets its own chain bundle and key. A client gets its own chain bundle and key. Keys never cross boundaries.
6. **Manage certificate lifecycle** — renew leaves before expiry, rotate intermediates periodically, handle revocation when keys are compromised.

> **Certificate creation code:** `CreateRootCA`, `CreateIntermediateCA`, `CreateLeafCert`,
> `SignerFunc`, `ProfiledSignerFunc`, and helper functions (`randomSerial`, `computeSKID`,
> `WriteCert`, `WriteKey`, `WriteChainBundle`) are documented in
> [AGENTS.certs.md](AGENTS.certs.md).

---

## File layout and ownership boundaries

```
certs/
  root-ca/
    cert.crt              # Root CA certificate (public — distribute to all parties)
  intermediate-ca/
    cert.crt              # Intermediate CA certificate (included in chain bundles)
  server/
    chain.crt             # Server leaf cert + intermediate cert (give to server)
    server.key            # Server private key (give to server ONLY)
    root-ca.crt           # Root CA cert copy (server uses for client trust pool)
  client/
    chain.crt             # Client leaf cert + intermediate cert (give to client)
    client.key            # Client private key (give to client ONLY)
    root-ca.crt           # Root CA cert copy (client uses for server trust pool)
```

Design principles:
- **Each directory = one party's files.** The server directory contains everything the server needs to run. The client directory contains everything the client needs to run.
- **Private keys never leave their party's directory.** `server.key` exists only in `server/`. `client.key` exists only in `client/`.
- **Root CA cert is duplicated.** Each party gets a copy of `root-ca.crt` in their own directory. This makes each directory self-contained — no cross-directory references at runtime.
- **Intermediate cert is NOT in trust pools.** Trust pools contain only the root CA cert. The intermediate cert is delivered inside chain bundles. The TLS handshake builds the full path: leaf → intermediate (from chain bundle) → root (from trust pool).

Enterprise PKI notes:
- **Intermediate CA cert appears in two places:** its own file (`intermediate-ca/cert.crt`) AND inside every chain bundle (`server/chain.crt`, `client/chain.crt`). The standalone copy is used during cert issuance; the copies inside chain bundles are used during TLS handshakes.
- **Root CA cert is NOT in chain bundles.** The root cert only appears in trust pool configuration files (`server/root-ca.crt`, `client/root-ca.crt`). TLS peers use the trust pool to verify the chain, not the chain bundle.
- **Cert store imports require the direct issuer.** When storing a leaf cert in an OS certificate store (e.g., Windows cert store via `StoreWithDisposition` or equivalent), you must provide the immediate issuer certificate — the intermediate CA cert, not the root. The store uses this to build the local chain association. Passing the root instead of the intermediate will cause chain-building failures at TLS time. See [AGENTS.certs.md — Certificate store operations](AGENTS.certs.md#certificate-store-operations-certtostore) for the Go API.

---

## Key protection

### File permissions

```go
// Private keys: owner-only read/write
os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)

// Certificates: world-readable (they are public)
os.Create(certPath) // default 0644
```

### Root CA key lifecycle

In production:
1. Generate the root CA key in an air-gapped environment or HSM.
2. Sign the intermediate CA certificate.
3. **Delete the root CA key from disk.** It is no longer needed until the intermediate must be rotated (months or years later).
4. Store the root CA key backup in a secure offline location (hardware security module, safe deposit box).

In a CLI tool, support this workflow:
```
mycli pki init --root-key-output=usb:/secure/root.key
mycli pki rotate-int --root-key-input=usb:/secure/root.key
```

### Intermediate CA key lifecycle

The intermediate CA key should exist only in memory during CLI execution when possible. If it must be written to disk (for multi-step workflows), encrypt it or use OS key storage. Never leave it as a plaintext file after the CLI exits.

### Production key storage

| Environment | Root CA Key | Intermediate CA Key | Leaf Keys |
|---|---|---|---|
| Development | File on disk (0600) | In-memory during CLI run | File on disk (0600) |
| Staging | Encrypted file, offline | Encrypted file or key vault | File on disk (0600) |
| Production | HSM (PKCS#11) or offline | HSM or cloud KMS | File, cert store, or TPM |

---

## TOML configuration pattern

Use TOML for operator-facing configuration. Each CLI command reads a config file that defines the PKI parameters.

```toml
# pki-config.toml

[root_ca]
cn       = "Acme Corp Root CA"
validity = "8760h"              # 1 year

[intermediate_ca]
cn       = "Acme Corp Operational CA"
validity = "720h"               # 30 days

[server]
cn        = "api.acme.corp"
validity  = "168h"              # 7 days
dns_names = ["api.acme.corp", "api.internal"]
ip_addrs  = ["10.0.1.50"]

[client]
cn       = "backend-service"
validity = "168h"               # 7 days
```

Go config types:

```go
type PKIConfig struct {
    RootCA         CAConfig     `toml:"root_ca"`
    IntermediateCA CAConfig     `toml:"intermediate_ca"`
    Server         LeafConfig   `toml:"server"`
    Client         LeafConfig   `toml:"client"`
}

type CAConfig struct {
    CN       string `toml:"cn"`
    Validity string `toml:"validity"` // parsed with time.ParseDuration
}

type LeafConfig struct {
    CN       string   `toml:"cn"`
    Validity string   `toml:"validity"`
    DNSNames []string `toml:"dns_names"`
    IPAddrs  []string `toml:"ip_addrs"` // parsed with net.ParseIP
}
```

Parse the config with `github.com/BurntSushi/toml` or `github.com/pelletier/go-toml/v2`.

---

## CLI command structure

```
mycli pki init             # Create root CA + intermediate CA
mycli pki issue-server     # Issue server cert signed by intermediate
mycli pki issue-client     # Issue client cert signed by intermediate
mycli pki rotate-int       # Rotate intermediate CA (new intermediate from same root)
mycli pki bundle           # Assemble chain bundles for distribution
mycli pki verify           # Verify cert chain validity
```

### `pki init`

1. Read config from `pki-config.toml` (or `--config` flag).
2. Generate root CA key and self-signed certificate.
3. Write root CA cert to `certs/root-ca/cert.crt`.
4. Generate intermediate CA key.
5. Sign intermediate CA cert with root CA key.
6. Write intermediate CA cert to `certs/intermediate-ca/cert.crt`.
7. Securely handle root CA key (delete from memory, optionally write to specified secure location).

### `pki issue-server`

1. Load intermediate CA cert and key (or prompt operator for key location).
2. Read server profile from config (CN, DNS SANs, IP addresses).
3. Generate server key and leaf cert with `ExtKeyUsageServerAuth`.
4. Write chain bundle (server leaf + intermediate) to `certs/server/chain.crt`.
5. Write server key to `certs/server/server.key` with 0600 permissions.
6. Copy root CA cert to `certs/server/root-ca.crt`.

### `pki issue-client`

Same as `issue-server` but with `ExtKeyUsageClientAuth` and no DNS SANs.

### `pki rotate-int`

1. Load root CA key from secure storage.
2. Generate new intermediate CA key.
3. Sign new intermediate CA cert with root CA key.
4. Write new intermediate CA cert.
5. Reissue all leaf certificates from the new intermediate.
6. Rebuild all chain bundles.
7. Output list of files that changed (for deployment automation).

### `pki bundle`

Assemble chain bundles from existing cert files. Useful when certs are generated externally or when rebuilding bundles after intermediate rotation.

### `pki verify`

```go
func VerifyChain(chainFile, rootCertFile string) error {
    chainPEM, err := os.ReadFile(chainFile)
    if err != nil {
        return fmt.Errorf("reading chain file: %w", err)
    }
    rootPEM, err := os.ReadFile(rootCertFile)
    if err != nil {
        return fmt.Errorf("reading root cert: %w", err)
    }

    roots := x509.NewCertPool()
    if !roots.AppendCertsFromPEM(rootPEM) {
        return fmt.Errorf("failed to parse root CA certificate")
    }

    // Parse leaf cert (first cert in chain)
    block, rest := pem.Decode(chainPEM)
    if block == nil {
        return fmt.Errorf("no PEM data in chain file")
    }
    leaf, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return fmt.Errorf("parsing leaf certificate: %w", err)
    }

    // Parse intermediates (remaining certs in chain)
    intermediates := x509.NewCertPool()
    intermediates.AppendCertsFromPEM(rest)

    _, err = leaf.Verify(x509.VerifyOptions{
        Roots:         roots,
        Intermediates: intermediates,
    })
    if err != nil {
        return fmt.Errorf("chain verification failed: %w", err)
    }

    return nil
}
```

---

## Distribution workflow

The operator is responsible for getting the right files to the right parties. The CLI tool generates files; the operator (or automation) distributes them.

### Step-by-step

1. **Operator runs `pki init`** → creates `certs/root-ca/cert.crt` and `certs/intermediate-ca/cert.crt`.
2. **Operator runs `pki issue-server`** → creates `certs/server/chain.crt`, `certs/server/server.key`, and copies `certs/server/root-ca.crt`.
3. **Operator runs `pki issue-client`** → creates `certs/client/chain.crt`, `certs/client/client.key`, and copies `certs/client/root-ca.crt`.
4. **Operator copies `certs/server/` contents** to the server host's certificate directory.
5. **Operator copies `certs/client/` contents** to the client host's certificate directory.
6. **Services reload TLS configuration** (graceful restart or `SIGHUP` handler).

### Automation integration

The CLI should support `--output-dir` to control where files are written, and `--json` for machine-readable output listing all generated files and their intended recipients.

```json
{
  "server": {
    "chain": "certs/server/chain.crt",
    "key": "certs/server/server.key",
    "trust": "certs/server/root-ca.crt"
  },
  "client": {
    "chain": "certs/client/chain.crt",
    "key": "certs/client/client.key",
    "trust": "certs/client/root-ca.crt"
  }
}
```

---

## Rotation workflows

### Leaf rotation (routine, low-risk)

1. Issue a new leaf cert from the same intermediate CA.
2. Deploy the new chain bundle and key to the service.
3. Restart or signal the service to reload TLS config.
4. Retire the old cert (it will expire naturally; no revocation needed if short-lived).

Automate this on a schedule shorter than the leaf validity period. For 7-day leaf certs, rotate every 3-4 days.

### Intermediate rotation (periodic, medium-risk)

1. Load root CA key from secure storage.
2. Generate a new intermediate CA key and cert.
3. Reissue ALL leaf certs from the new intermediate.
4. Rebuild ALL chain bundles.
5. Deploy everything — new chain bundles and keys to all services.
6. Verify all services are using the new chain.
7. The old intermediate expires naturally.

Trust pools do NOT change during intermediate rotation because they contain only the root CA cert.

Enterprise intermediate rotation workflow:

1. **Generate new intermediate from root.** Load the root CA key from offline/HSM storage. Create a new intermediate CA key pair and certificate signed by the root. The new intermediate gets a fresh serial number and validity period.
2. **Re-issue all leaf certs from the new intermediate.** Every server and client cert must be re-signed by the new intermediate's key. The leaf key pairs may be reused (the private keys do not change), but the certificates themselves are new — signed by the new intermediate.
3. **Rebuild all chain bundles.** Every `chain.crt` file (server-chain, client-chain) must be regenerated: new leaf cert + new intermediate cert concatenated in PEM order. Old chain bundles are now invalid because they contain the old intermediate.
4. **Trust pools do NOT change.** Trust pool files contain only the root CA cert, which has not changed. No trust pool updates are needed on any service or client.
5. **Deploy new bundles to all services.** Push the rebuilt chain bundles and the new leaf certs to every server and client. Restart or signal services to reload TLS configuration. Verify each service completes a full TLS handshake with the new chain before decommissioning the old intermediate.

The key insight: intermediate rotation is invisible to trust pools. Every party still trusts the same root. Only the chain bundles — the identity material — change.

### Root rotation (rare, high-risk — avoid if possible)

1. Generate a new root CA.
2. Cross-sign: have the old root sign the new root (or vice versa) to create a transition period.
3. Update ALL trust pools to include both old and new root certs.
4. Issue a new intermediate from the new root.
5. Reissue all leaves from the new intermediate.
6. Deploy everything.
7. After the transition period, remove the old root from trust pools.

Root rotation affects every service and every client. Plan for a long transition period where both roots are trusted.

---

## Negative-path testing

Every mTLS system must verify that untrusted certificates are rejected. Include this in the CLI as a `pki test-untrusted` command or in integration tests.

### Pattern

```go
func TestUntrustedClientRejected(t *testing.T) {
    // Set up the real PKI (root → intermediate → server + client)
    rootCert, signInt, _ := CreateRootCA("Real Root CA", 24*time.Hour)
    intCert, signLeaf, _ := signInt("Real Intermediate CA", 24*time.Hour)

    serverProfile := LeafProfile{
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        DNSNames:    []string{"localhost"},
    }
    serverCert, serverKey, _ := signLeaf("Real Server", serverProfile)

    // Set up a SEPARATE PKI (different root → different intermediate → untrusted client)
    _, untrustedSignInt, _ := CreateRootCA("Untrusted Root CA", 24*time.Hour)
    _, untrustedSignLeaf, _ := untrustedSignInt("Untrusted Intermediate CA", 24*time.Hour)

    clientProfile := LeafProfile{
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }
    untrustedClientCert, untrustedClientKey, _ := untrustedSignLeaf("Untrusted Client", clientProfile)

    // Start server that trusts only the real root CA
    server := startMTLSServer(serverCert, serverKey, intCert, rootCert)
    defer server.Close()

    // Attempt connection with untrusted client cert
    client := createClient(untrustedClientCert, untrustedClientKey, rootCert)
    _, err := client.Get(server.URL)

    // The handshake MUST fail
    require.Error(t, err, "server should reject client cert signed by untrusted CA")
}
```

This test proves:
- The server's `ClientCAs` trust pool is working correctly.
- Only certificates chaining to the real root CA are accepted.
- A valid certificate from a different CA hierarchy is rejected.

### Suppressing expected TLS errors

When the server rejects an untrusted client, Go's HTTP server logs a TLS error to stderr. Suppress this in tests to keep output clean:

```go
server.ErrorLog = log.New(io.Discard, "", 0)
```

---

## Common mistakes

| Mistake | Why it's wrong | Correct approach |
|---|---|---|
| Returning CA private keys from functions | Callers can leak or misuse the key | Use the SignerFunc closure pattern |
| Hardcoding serial numbers (e.g., `big.NewInt(1)`) | Collisions across runs; some TLS stacks reject duplicate serials | Use 128-bit random serials from `crypto/rand` |
| Using SHA-1 for signatures or SKID | SHA-1 is deprecated and rejected by modern TLS stacks | Use SHA-256 everywhere |
| Writing key files with 0644 permissions | Any user on the system can read the private key | Use `0600` via `os.OpenFile` |
| Root CA signs leaf certs directly | No intermediate means root must be online; compromised root = game over | Always use at least one intermediate CA |
| Missing `MaxPathLenZero: true` on intermediate | Go treats `MaxPathLen: 0` without `MaxPathLenZero` as "unset", allowing sub-intermediates | Always set both `MaxPathLen: 0` and `MaxPathLenZero: true` |
| Same EKU on server and client certs | A compromised server cert could be used as a client cert (or vice versa) | Use `ServerAuth` for servers, `ClientAuth` for clients, never both |
| Putting intermediate cert in trust pool | Rotation requires updating all trust pools | Put only root CA cert in trust pools; deliver intermediate via chain bundles |
| Not testing the negative path | No proof that the trust pool actually filters untrusted certs | Always test that an untrusted client cert is rejected |
| Skipping `AuthorityKeyId` on child certs | Debugging chain issues becomes difficult; some validators warn | Set `AuthorityKeyId` to the issuer's `SubjectKeyId` |
| Using RSA instead of ECDSA | RSA keys are larger and slower for equivalent security | Use ECDSA P-256 for all keys |
| Not setting `MinVersion: tls.VersionTLS12` | Allows negotiation of TLS 1.0/1.1 which have known vulnerabilities | Always set `MinVersion: tls.VersionTLS12` on `tls.Config` |

---

## Security checklist

Before shipping the CLI tool, verify:

- [ ] ECDSA P-256 for all key pairs
- [ ] 128-bit random serial numbers on every certificate
- [ ] SKID set on every certificate; AKID set on every non-self-signed certificate
- [ ] Private key files written with 0600 permissions
- [ ] Root CA key is not persisted after signing intermediate (or is encrypted/HSM-backed)
- [ ] Intermediate CA key is not written to disk in plaintext
- [ ] `MinVersion: tls.VersionTLS12` on every `tls.Config`
- [ ] Server certs have `ExtKeyUsageServerAuth` only
- [ ] Client certs have `ExtKeyUsageClientAuth` only
- [ ] Server certs include DNS SANs for all expected hostnames
- [ ] Trust pools contain root CA cert only (not intermediate)
- [ ] Chain bundles contain leaf + intermediate in correct order
- [ ] Negative-path test exists and passes (untrusted cert rejected)
- [ ] All errors wrapped with `fmt.Errorf("context: %w", err)`
- [ ] No hardcoded passwords, keys, or secrets in source code

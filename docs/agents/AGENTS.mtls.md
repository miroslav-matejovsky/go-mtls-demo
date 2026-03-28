# AGENTS.mtls.md — Enterprise mTLS in Go

> **Audience:** AI coding agents working in a production Go codebase.
> This document is self-contained. It covers mutual TLS concepts, PKI topology,
> certificate lifecycle, Go configuration patterns, testing strategy, and
> common mistakes. Drop it into any Go repository that needs mTLS guidance.

---

## 1. What mTLS Is

### One-way TLS vs mutual TLS

In **one-way TLS** (the default for HTTPS), only the server presents a
certificate. The client verifies the server's identity but the server has no
cryptographic proof of who the client is.

In **mutual TLS (mTLS)**, both sides present certificates and verify the other:

| Step | One-way TLS | Mutual TLS |
|------|-------------|------------|
| Server presents cert | ✅ | ✅ |
| Client validates server | ✅ | ✅ |
| Server requests client cert | ❌ | ✅ |
| Client presents cert | ❌ | ✅ |
| Server validates client | ❌ | ✅ |

The server's `tls.Config` controls whether client certificates are required:

```go
// One-way TLS — server does not ask for a client certificate
tlsConfig := &tls.Config{}

// Mutual TLS — server REQUIRES a valid client certificate
tlsConfig := &tls.Config{
    ClientAuth: tls.RequireAndVerifyClientCert,
    ClientCAs:  trustedRootPool,
}
```

### Use cases

- **Service-to-service authentication:** Microservices prove identity to each
  other without tokens or API keys. The certificate IS the credential.
- **Zero-trust networks:** Every connection is authenticated regardless of
  network location. No implicit trust from being "inside the firewall."
- **API security:** Client certificates replace or supplement API keys,
  providing non-repudiation and resistance to credential theft.
- **Regulatory compliance:** PCI-DSS, HIPAA, and SOC 2 environments often
  require mutual authentication for internal service communication.

---

## 2. PKI Topology for Enterprise

### Certificate hierarchy

Production mTLS uses a three-tier PKI:

```
Root CA (offline, long-lived, 1–10 years)
    └── Intermediate CA (operational, medium-lived, 30–90 days)
            ├── Server leaf cert (ServerAuth EKU only)
            └── Client leaf cert (ClientAuth EKU only)
```

### Design rules

1. **Root CA NEVER signs leaf certificates directly.** The root key is the
   highest-value secret in the PKI. Minimizing its use minimizes exposure.

2. **Intermediate CA has `MaxPathLen: 0`.** This constraint prevents the
   intermediate from creating sub-intermediates, bounding the trust chain to
   exactly three levels.

   ```go
   intermediateTemplate := &x509.Certificate{
       IsCA:                  true,
       MaxPathLen:            0,
       MaxPathLenZero:        true,
       BasicConstraintsValid: true,
       KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
   }
   ```

3. **Root CA key is offline / HSM-backed.** In production the root private key
   lives in a Hardware Security Module or an air-gapped machine. It is used
   only to sign (or re-sign) intermediates.

4. **Separate Extended Key Usage per role.** Server certs carry
   `ExtKeyUsageServerAuth`; client certs carry `ExtKeyUsageClientAuth`. Never
   combine both EKUs in a single certificate — it violates the principle of
   least privilege.

---

## 3. Certificate Types and Fields

### Extended Key Usage (EKU)

| Role | EKU | Purpose |
|------|-----|---------|
| Server | `x509.ExtKeyUsageServerAuth` | Server proves identity to clients |
| Client | `x509.ExtKeyUsageClientAuth` | Client proves identity to servers |
| Intermediate CA | (none — uses `KeyUsageCertSign`) | Signs leaf certs only |

Why separate? A compromised server cert with `ClientAuth` EKU could
impersonate a client to other services. Role-specific EKUs contain blast
radius.

### Subject Alternative Names (SANs)

SANs are the **only** field modern TLS libraries use for identity verification.
The legacy `CommonName` field is ignored by Go's `x509` verifier.

- **DNS SANs** on server certs: `DNSNames: []string{"api.example.com"}`
- **IP SANs** for internal/test servers: `IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}`
- Client certs may use DNS SANs, URI SANs, or email SANs depending on the
  identity model.

```go
serverTemplate := &x509.Certificate{
    DNSNames:    []string{"api.prod.internal", "api.prod.internal.svc"},
    IPAddresses: []net.IP{net.ParseIP("10.0.1.42")},
    ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
}
```

### Subject Key ID (SKID) and Authority Key ID (AKID)

- **SKID** is a hash of the certificate's own public key. It uniquely
  identifies the key pair.
- **AKID** references the SKID of the issuer. It tells the verifier which CA
  key signed this certificate.
- Together they form an unambiguous chain: leaf.AKID → intermediate.SKID,
  intermediate.AKID → root.SKID.

Compute SKID from the public key:

```go
pubBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
hash := sha256.Sum256(pubBytes)
template.SubjectKeyId = hash[:]
```

### Serial numbers

Serial numbers MUST be unique within a CA. Use cryptographically random
128-bit values:

```go
serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
if err != nil {
    return fmt.Errorf("generating serial number: %w", err)
}
template.SerialNumber = serialNumber
```

Never hardcode or increment serial numbers — collisions undermine revocation
and can cause TLS stack confusion.

### Validity periods

| Certificate | Typical validity | Rationale |
|------------|------------------|-----------|
| Root CA | 1–10 years | Long-lived, offline, hard to rotate |
| Intermediate CA | 30–90 days | Operational, rotated regularly |
| Server leaf | 1–30 days | Short-lived, automated renewal |
| Client leaf | 1–30 days | Short-lived, automated renewal |

Shorter leaf lifetimes reduce the window of exposure if a key is compromised.
Automate renewal — never rely on humans remembering to rotate.

---

## 4. Chain Bundles

### PEM file format

A chain bundle is a PEM file containing the leaf certificate followed by the
intermediate certificate. The root is NOT included — the verifier already has
it in its trust pool.

```
-----BEGIN CERTIFICATE-----
<leaf certificate bytes — base64 encoded DER>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<intermediate CA certificate bytes — base64 encoded DER>
-----END CERTIFICATE-----
```

### Presentation order

During the TLS handshake the server (or client, in mTLS) sends its certificate
chain. The standard order is:

1. **Leaf certificate** (the entity's own cert)
2. **Intermediate CA certificate** (the issuer of the leaf)

The root CA certificate is omitted — the peer already trusts it.

### Verification chain

The verifier reconstructs the chain in reverse:

```
leaf cert → signed by intermediate? ✅
    intermediate cert → signed by root? ✅ (root is in trust pool)
        chain valid ✅
```

### Loading chain bundles in Go

```go
// Server loads its chain bundle (leaf + intermediate)
serverCert, err := tls.LoadX509KeyPair("server-chain.pem", "server-key.pem")

// The tls package automatically presents the full chain during handshake
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
}
```

When constructing bundles programmatically, concatenate PEM blocks in order:

```go
var chainPEM []byte
chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...)
chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER})...)
```

---

## 5. Trust Model

### Trust pools contain the ROOT CA cert ONLY

This is the most commonly misunderstood aspect of mTLS configuration.

```go
// ✅ CORRECT — trust pool contains ONLY the root CA
rootCAs := x509.NewCertPool()
rootCAs.AppendCertsFromPEM(rootCACertPEM)

// ❌ WRONG — do not add the intermediate to the trust pool
rootCAs.AppendCertsFromPEM(intermediateCertPEM) // NEVER DO THIS
```

### Server-side trust (for validating clients)

```go
// Server's tls.Config for mTLS
serverTLS := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    rootCAs, // root CA only — validates client chains
    MinVersion:   tls.VersionTLS12,
}
```

### Client-side trust (for validating servers)

```go
// Client's tls.Config
clientTLS := &tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      rootCAs, // root CA only — validates server chains
    MinVersion:   tls.VersionTLS12,
}
```

### Why root-only trust?

When the intermediate CA is rotated (new key pair, new cert signed by the same
root), services that trust only the root require **zero configuration changes**.
The new intermediate's chain still validates up to the same trusted root.

If you put the intermediate in the trust pool, every intermediate rotation
requires updating every service's trust configuration — a coordination
nightmare in large deployments.

---

## 6. Certificate Lifecycle

### Issuance workflow

1. **Generate key pair** on the target machine (or in an HSM/KMS).
2. **Create CSR** (Certificate Signing Request) containing the public key and
   requested SANs.
3. **Submit CSR** to the intermediate CA.
4. **CA signs** the CSR, producing the leaf certificate.
5. **Distribute** the signed certificate and chain bundle to the service.
6. **Verify** the chain: `openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem`

### Leaf certificate rotation

1. Issue a new leaf certificate from the current intermediate CA.
2. Deploy the new cert + key to the service.
3. Reload the service's TLS config (graceful restart or hot-reload).
4. Retire the old certificate (it expires naturally or is revoked).

**Critical:** Issue the new cert BEFORE the old one expires. Overlap the
validity periods to allow zero-downtime rotation.

### Intermediate CA rotation

1. Generate a new intermediate key pair.
2. Sign the new intermediate certificate with the root CA.
3. Re-issue all leaf certificates from the new intermediate.
4. Deploy new chain bundles (new leaf + new intermediate) to all services.
5. Services that trust only the root CA require NO trust pool changes.

### Revocation

Go's `crypto/tls` and `crypto/x509` have limited revocation support:

- **CRL (Certificate Revocation List):** Go can parse CRLs
  (`x509.ParseRevocationList`) but does not check them automatically during
  TLS handshakes.
- **OCSP (Online Certificate Status Protocol):** Go can staple OCSP responses
  but does not fetch them automatically.

For production systems, prefer short-lived certificates over revocation. A
certificate that expires in 24 hours limits the exposure window without needing
revocation infrastructure.

If revocation is required, implement custom verification in a
`tls.Config.VerifyPeerCertificate` callback.

---

## 7. Go `tls.Config` Patterns

### Minimal server config (one-way TLS)

```go
serverTLS := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    MinVersion:   tls.VersionTLS12,
}
```

### Server config for mTLS

```go
serverTLS := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    rootCAs,
    MinVersion:   tls.VersionTLS12,
}
```

### Client config for mTLS

```go
clientTLS := &tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      rootCAs,
    MinVersion:   tls.VersionTLS12,
}

client := &http.Client{
    Transport: &http.Transport{TLSClientConfig: clientTLS},
}
```

### Server with timeouts

```go
server := &http.Server{
    Addr:         ":8443",
    Handler:      mux,
    TLSConfig:    serverTLS,
    ReadTimeout:  10 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  60 * time.Second,
}
```

### Graceful shutdown

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

if err := server.Shutdown(ctx); err != nil {
    log.Printf("server shutdown error: %v", err)
}
```

### Key type signatures

```go
// CA signing function — encapsulates the CA private key
type SignerFunc func(template *x509.Certificate, pub crypto.PublicKey) (certDER []byte, err error)

// Creating a TLS certificate from PEM bytes
func loadCert(certPEM, keyPEM []byte) (tls.Certificate, error)

// Creating a trust pool from PEM bytes
func loadTrustPool(rootCAPEM []byte) (*x509.CertPool, error)
```

---

## 8. Security Requirements Checklist

Before deploying mTLS, verify every item:

- [ ] **ECDSA P-256** for all key pairs (`elliptic.P256()`)
- [ ] **Random 128-bit serial numbers** via `crypto/rand`
- [ ] **SKID/AKID** on all certificates for unambiguous chain building
- [ ] **Private key files restricted to `0600`** (`os.WriteFile(path, data, 0600)`)
- [ ] **`MinVersion: tls.VersionTLS12`** on every `tls.Config` — blocks TLS 1.0/1.1
- [ ] **Server timeouts** (`ReadTimeout`, `WriteTimeout`, `IdleTimeout`) to prevent slowloris
- [ ] **Graceful shutdown** via `server.Shutdown(ctx)` for clean connection draining
- [ ] **Role-specific EKU** — `ServerAuth` on server certs, `ClientAuth` on client certs
- [ ] **DNS SANs** on server certificates (Go ignores `CommonName` for verification)
- [ ] **Intermediate CA with `MaxPathLen: 0`** — cannot mint sub-intermediates
- [ ] **Root CA in trust pools** — never add intermediates to trust pools
- [ ] **Negative-path testing** — verify untrusted certs are rejected
- [ ] **Certificate chain bundles** — leaf + intermediate for TLS presentation
- [ ] **CA private keys never exposed** outside generation/signing code

---

## 9. Testing Approach

### Integration tests, not mocks

mTLS correctness depends on the interplay between `crypto/tls`, `crypto/x509`,
and the network stack. Mocking any of these layers defeats the purpose. Run
full TLS handshakes in tests.

### Positive test: trusted client accepted

```go
func TestMTLS_TrustedClient(t *testing.T) {
    // 1. Generate CA, intermediate, server cert, client cert
    // 2. Start TLS server with ClientAuth: RequireAndVerifyClientCert
    // 3. Create client with trusted client cert
    // 4. Make HTTPS request → expect 200 OK
}
```

### Negative test: untrusted client rejected

```go
func TestMTLS_UntrustedClient(t *testing.T) {
    // 1. Generate CA-A (trusted) and CA-B (untrusted)
    // 2. Start server trusting CA-A
    // 3. Create client with cert signed by CA-B
    // 4. Make HTTPS request → expect TLS handshake error
}
```

The negative test is equally important — it proves the server actually
enforces client authentication.

### Test infrastructure patterns

**Use `t.TempDir()` for cert files:**

```go
func TestMTLS(t *testing.T) {
    certDir := t.TempDir() // auto-cleaned after test
    // write certs to certDir...
}
```

**Use OS-assigned ports:**

```go
ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
// ln.Addr() returns the actual assigned address
```

**Suppress expected TLS errors in server logs:**

```go
server.ErrorLog = log.New(io.Discard, "", 0)
```

This keeps test output clean when the negative-path test intentionally
triggers a TLS handshake failure.

### What to assert

- HTTP status code (200 for positive, connection error for negative)
- Response body content (proves the handler executed)
- `tls.ConnectionState()` fields: `PeerCertificates`, `VerifiedChains`,
  `Version` (confirm TLS 1.2+)

---

## 10. Common Mistakes

### ❌ Trusting the intermediate CA instead of the root

**Symptom:** Intermediate CA rotation breaks all connections.

**Fix:** Trust pools contain ONLY the root CA. The presented chain (leaf +
intermediate) is verified against the root in the trust pool.

### ❌ Using the same EKU for server and client certs

**Symptom:** A compromised server cert can impersonate a client.

**Fix:** Server certs get `ExtKeyUsageServerAuth` only. Client certs get
`ExtKeyUsageClientAuth` only.

### ❌ Hardcoding or incrementing serial numbers

**Symptom:** Serial number collisions confuse certificate caches and break CRL
matching.

**Fix:** `rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))`

### ❌ Missing `MinVersion` on `tls.Config`

**Symptom:** Server accepts TLS 1.0 and 1.1 connections, which have known
vulnerabilities (BEAST, POODLE).

**Fix:** Always set `MinVersion: tls.VersionTLS12`.

### ❌ No server timeouts

**Symptom:** Slowloris attacks hold connections open indefinitely, exhausting
server resources.

**Fix:** Set `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` on
`http.Server`.

### ❌ Baking private keys into container images

**Symptom:** Anyone with access to the image registry can extract private keys.

**Fix:** Mount keys at runtime via secrets management (Kubernetes secrets,
Vault, cloud KMS). Never `COPY` key files in a Dockerfile.

### ❌ Not testing the negative path

**Symptom:** mTLS appears to work but the server accepts ANY client certificate
(misconfigured `ClientAuth` or wrong trust pool).

**Fix:** Every test suite must include at least one test where a client with an
untrusted certificate is REJECTED by the server.

### ❌ Omitting DNS SANs on server certificates

**Symptom:** `x509: certificate is not valid for any names` — Go does not fall
back to the `CommonName` field for server identity verification.

**Fix:** Always populate `DNSNames` (and `IPAddresses` if needed) on server
certificate templates.

### ❌ Root CA signing leaf certificates directly

**Symptom:** Root CA key must be online and accessible, massively increasing
the blast radius of a key compromise.

**Fix:** Root signs intermediates only. Intermediates sign leaves.

---

## 11. Quick Reference

### `tls.ClientAuthType` values

| Value | Behavior |
|-------|----------|
| `tls.NoClientCert` | One-way TLS (default) |
| `tls.RequestClientCert` | Ask but don't verify — rarely useful |
| `tls.RequireAnyClientCert` | Require cert but skip CA verification — dangerous |
| `tls.VerifyClientCertIfGiven` | Verify if provided, allow anonymous otherwise |
| `tls.RequireAndVerifyClientCert` | **Use this for mTLS** — require + verify against `ClientCAs` |

### File naming conventions

| File | Contents |
|------|----------|
| `ca-cert.pem` | Root CA certificate (public) |
| `intermediate-cert.pem` | Intermediate CA certificate (public) |
| `server-chain.pem` | Server leaf + intermediate (public, for TLS presentation) |
| `server-key.pem` | Server private key (**secret**, mode `0600`) |
| `client-chain.pem` | Client leaf + intermediate (public, for TLS presentation) |
| `client-key.pem` | Client private key (**secret**, mode `0600`) |

### Imports

```go
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "net"
    "net/http"
    "time"
)
```

---

## 12. Summary

mTLS ensures both sides of every connection are cryptographically
authenticated. The key principles:

1. **Three-tier PKI:** root → intermediate → leaf. Root never signs leaves.
2. **Root-only trust pools:** enables intermediate rotation without config changes.
3. **Role-specific EKU:** server certs authenticate servers, client certs
   authenticate clients. Never combine.
4. **Short-lived leaves:** prefer automated renewal over revocation infrastructure.
5. **Test both paths:** a trusted client must succeed; an untrusted client must
   be rejected.
6. **Defense in depth:** `MinVersion`, timeouts, graceful shutdown, file
   permissions, secret management.

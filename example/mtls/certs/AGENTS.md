# Certificate Domain

> **Parent:** [AGENTS.md](../AGENTS.md) — mTLS concepts and architecture
> **Layer:** Domain
> **Go package:** `internal/cert` · `github.com/google/certtostore`

> **Audience:** AI coding agents working in a production Go codebase.
> This document covers the certificate domain: types, fields, chain bundles,
> generation, signing, certificate store operations, hardware-backed keys, and
> lifecycle. It is the single source of truth for certificate business logic.
> For mTLS concepts see [AGENTS.md](../AGENTS.md); for PKI workflows see
> [operator/AGENTS.md](../operator/AGENTS.md).

---

## Certificate Types and Fields

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

## Chain Bundles

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

## Certificate generation with Go stdlib

### Key packages

```
crypto/x509        — certificate templates, creation, parsing
crypto/ecdsa       — ECDSA key generation
crypto/elliptic    — curve definitions (use P-256)
crypto/rand        — cryptographic random source
crypto/sha256      — computing Subject Key Identifiers
encoding/pem       — PEM encoding/decoding
math/big           — serial number generation
net                — net.IP for SAN IP addresses
```

### Root CA creation

```go
func CreateRootCA(cn string, validity time.Duration) (*x509.Certificate, *ecdsa.PrivateKey, error) {
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, nil, fmt.Errorf("generating root CA key: %w", err)
    }

    template := &x509.Certificate{
        SerialNumber:          randomSerial(),
        Subject:               pkix.Name{CommonName: cn},
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(validity),
        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA:                  true,
        SubjectKeyId:          computeSKID(key),
    }

    certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
    if err != nil {
        return nil, nil, fmt.Errorf("creating root CA certificate: %w", err)
    }

    cert, err := x509.ParseCertificate(certDER)
    if err != nil {
        return nil, nil, fmt.Errorf("parsing root CA certificate: %w", err)
    }

    return cert, key, nil
}
```

Key points:
- `template` is both the template and the parent (self-signed).
- `KeyUsage` includes `CertSign` (to sign child certs) and `CRLSign` (to sign revocation lists).
- `IsCA: true` and `BasicConstraintsValid: true` are both required.
- No `ExtKeyUsage` — CAs should not have extended key usage constraints.

### Intermediate CA creation

```go
func CreateIntermediateCA(
    cn string,
    validity time.Duration,
    rootCert *x509.Certificate,
    rootKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, error) {
    intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, nil, fmt.Errorf("generating intermediate CA key: %w", err)
    }

    template := &x509.Certificate{
        SerialNumber:          randomSerial(),
        Subject:               pkix.Name{CommonName: cn},
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(validity),
        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA:                  true,
        MaxPathLen:            0,
        MaxPathLenZero:        true,
        SubjectKeyId:          computeSKID(intKey),
        AuthorityKeyId:        rootCert.SubjectKeyId,
    }

    certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &intKey.PublicKey, rootKey)
    if err != nil {
        return nil, nil, fmt.Errorf("creating intermediate CA certificate: %w", err)
    }

    cert, err := x509.ParseCertificate(certDER)
    if err != nil {
        return nil, nil, fmt.Errorf("parsing intermediate CA certificate: %w", err)
    }

    return cert, intKey, nil
}
```

Key points:
- The parent is `rootCert`, not `template` — this is what makes it non-self-signed.
- The signing key is `rootKey` — the root CA signs the intermediate.
- `MaxPathLen: 0` with `MaxPathLenZero: true` prevents the intermediate from creating sub-intermediates. Both fields are required; `MaxPathLen: 0` alone is ambiguous in Go's x509 package.
- `AuthorityKeyId` links this cert back to its issuer.

### Leaf certificate with profile

```go
type LeafProfile struct {
    ExtKeyUsage []x509.ExtKeyUsage // ServerAuth, ClientAuth, or both
    DNSNames    []string           // for server certs (e.g., ["api.acme.corp"])
    IPAddresses []net.IP           // for internal services (e.g., [127.0.0.1])
}

func CreateLeafCert(
    cn string,
    validity time.Duration,
    profile LeafProfile,
    issuerCert *x509.Certificate,
    issuerKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, error) {
    leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, nil, fmt.Errorf("generating leaf key: %w", err)
    }

    template := &x509.Certificate{
        SerialNumber:          randomSerial(),
        Subject:               pkix.Name{CommonName: cn},
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(validity),
        KeyUsage:              x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           profile.ExtKeyUsage,
        DNSNames:              profile.DNSNames,
        IPAddresses:           profile.IPAddresses,
        SubjectKeyId:          computeSKID(leafKey),
        AuthorityKeyId:        issuerCert.SubjectKeyId,
    }

    certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &leafKey.PublicKey, issuerKey)
    if err != nil {
        return nil, nil, fmt.Errorf("creating leaf certificate: %w", err)
    }

    cert, err := x509.ParseCertificate(certDER)
    if err != nil {
        return nil, nil, fmt.Errorf("parsing leaf certificate: %w", err)
    }

    return cert, leafKey, nil
}
```

Key points:
- `KeyUsage` is `DigitalSignature` only — leaf certs must not have `CertSign`.
- `ExtKeyUsage` comes from the profile. Use `x509.ExtKeyUsageServerAuth` for servers, `x509.ExtKeyUsageClientAuth` for clients. Never combine both on one cert.
- `DNSNames` should be set on server certs. Clients typically do not need SANs.
- `IsCA` is false (the zero value) — leaf certs are not CAs.

---

## SignerFunc closure pattern

CA private keys must **never** be returned to callers or stored in accessible variables. Use closures to capture the key:

```go
type SignerFunc func(cn string, profile LeafProfile) (*x509.Certificate, *ecdsa.PrivateKey, error)

type SignIntermediateFunc func(cn string, validity time.Duration) (*x509.Certificate, SignerFunc, error)

func CreateRootCA(cn string, validity time.Duration) (*x509.Certificate, SignIntermediateFunc, error) {
    rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, nil, fmt.Errorf("generating root key: %w", err)
    }

    // ... create root cert (self-signed) ...

    signIntermediate := func(intCN string, intValidity time.Duration) (*x509.Certificate, SignerFunc, error) {
        // rootKey is captured here — never exposed outside this closure
        intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        if err != nil {
            return nil, nil, fmt.Errorf("generating intermediate key: %w", err)
        }

        // ... create intermediate cert signed by rootKey ...

        signLeaf := func(leafCN string, profile LeafProfile) (*x509.Certificate, *ecdsa.PrivateKey, error) {
            // intKey is captured here — never exposed outside this closure
            leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
            if err != nil {
                return nil, nil, fmt.Errorf("generating leaf key: %w", err)
            }

            // ... create leaf cert signed by intKey ...

            return leafCert, leafKey, nil
            // leafKey IS returned — the leaf owner needs their private key.
            // intKey is NOT returned — only the closure has it.
        }

        return intCert, signLeaf, nil
    }

    return rootCert, signIntermediate, nil
    // rootKey is NOT returned — only the signIntermediate closure has it.
}
```

Why this matters:
- The root key exists only inside `signIntermediate`. After `CreateRootCA` returns, no caller can access it.
- The intermediate key exists only inside `signLeaf`. After `signIntermediate` returns, no caller can access it.
- Leaf private keys ARE returned — the server or client that owns the cert needs the key for TLS.
- This pattern makes key leaks structurally impossible at the API level.

### ProfiledSignerFunc for External Keys

When leaf private keys live inside hardware (TPM, HSM, smart card), the CA cannot generate the key pair — the hardware does. The CA only sees the public key. A `ProfiledSignerFunc` accepts an externally-provided `crypto.PublicKey` instead of generating its own key pair:

```go
// ProfiledSignerFunc signs a certificate for an externally-provided public key.
// The CA's private key is captured in the closure — never exposed.
type ProfiledSignerFunc func(publicKey crypto.PublicKey, cn string, profile LeafProfile) (*x509.Certificate, error)
```

Note the differences from the standard `SignerFunc`:
- **Input:** receives a `crypto.PublicKey` from the caller (the hardware-generated public key).
- **Output:** returns only the signed `*x509.Certificate` — no private key. The private key never left the hardware.

Typical workflow with a TPM-backed client key:

1. **TPM generates the key pair.** The private key is non-exportable — it exists only inside the TPM.
2. **Export the public key.** The TPM provides the `crypto.PublicKey` (e.g., `*ecdsa.PublicKey`).
3. **Submit to ProfiledSignerFunc.** Pass the public key, common name, and a client leaf profile. The closure signs a certificate using the intermediate CA's captured private key.
4. **Receive the signed certificate.** The result is a standard `*x509.Certificate` with `ExtKeyUsageClientAuth`.
5. **Store the certificate.** Import the signed cert into the OS certificate store (e.g., Windows cert store), associated with the TPM key handle. The store import function requires the direct issuer certificate (the intermediate CA cert, not the root) to build the chain.

At TLS time, the client presents the certificate from the store, and the TPM performs signing operations via `crypto.Signer` — the private key is used but never exposed to user-space code.

This pattern is essential for any environment where keys must not exist in software: TPM-backed workstation identity, HSM-backed service identity, or smart-card-based operator authentication.

---

## Helper functions

### randomSerial — 128-bit random serial number

```go
func randomSerial() *big.Int {
    max := new(big.Int).Lsh(big.NewInt(1), 128)
    serial, err := rand.Int(rand.Reader, max)
    if err != nil {
        panic(fmt.Sprintf("generating serial number: %v", err))
    }
    return serial
}
```

Serial numbers must be unique across all certificates issued by a CA. Using 128-bit random values makes collisions astronomically unlikely without needing a database.

### computeSKID — Subject Key Identifier

```go
func computeSKID(key *ecdsa.PrivateKey) []byte {
    pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
    if err != nil {
        panic(fmt.Sprintf("marshaling public key: %v", err))
    }
    hash := sha256.Sum256(pubBytes)
    return hash[:]
}
```

SKID is set on every certificate and used as `AuthorityKeyId` on child certificates. This creates a chain of identifiers that aids debugging and certificate chain validation.

### WriteCert — write PEM certificate to disk

```go
func WriteCert(path string, cert *x509.Certificate) error {
    if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
        return fmt.Errorf("creating directory for %s: %w", path, err)
    }
    f, err := os.Create(path)
    if err != nil {
        return fmt.Errorf("creating cert file %s: %w", path, err)
    }
    defer f.Close()

    return pem.Encode(f, &pem.Block{
        Type:  "CERTIFICATE",
        Bytes: cert.Raw,
    })
}
```

### WriteKey — write PEM private key with restricted permissions

```go
func WriteKey(path string, keyDER []byte) error {
    if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
        return fmt.Errorf("creating directory for %s: %w", path, err)
    }
    f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
    if err != nil {
        return fmt.Errorf("creating key file %s: %w", path, err)
    }
    defer f.Close()

    return pem.Encode(f, &pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: keyDER,
    })
}
```

The `0600` permission ensures only the file owner can read the private key. This is critical — world-readable key files are a common and severe misconfiguration.

### WriteChainBundle — concatenate leaf + intermediate PEM

```go
func WriteChainBundle(path string, leaf, intermediate *x509.Certificate) error {
    if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
        return fmt.Errorf("creating directory for %s: %w", path, err)
    }
    f, err := os.Create(path)
    if err != nil {
        return fmt.Errorf("creating chain bundle %s: %w", path, err)
    }
    defer f.Close()

    // Leaf first, then intermediate — standard TLS presentation order
    if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}); err != nil {
        return err
    }
    return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Raw})
}
```

Chain bundles are what servers and clients present during the TLS handshake. The peer uses the chain to build a path from the leaf to a trusted root.

---

## Certificate store operations (`certtostore`)

The `github.com/google/certtostore` library provides Go access to the Windows
certificate store and NCrypt key storage providers. It bridges the certificate
domain with platform key storage — the private key stays inside the TPM or
software KSP while Go code operates through the `crypto.Signer` interface.

### Opening the store

```go
import (
    "context"
    "crypto/tls"
    "fmt"

    "github.com/google/certtostore"
)

store, err := certtostore.OpenWinCertStoreCurrentUser(
    certtostore.ProviderMSPlatform, // Microsoft Platform Crypto Provider (TPM)
    containerName,                  // NCrypt container name
    nil,                            // issuer filter — nil means any issuer
    nil,                            // intermediate certs (optional)
    false,                          // requireHardware — true to reject software-only KSP
)
if err != nil {
    return fmt.Errorf("opening cert store: %w", err)
}
defer store.Close()
```

**Providers:**

| Provider constant | KSP | Key storage |
|---|---|---|
| `certtostore.ProviderMSPlatform` | Microsoft Platform Crypto Provider | TPM hardware |
| `certtostore.ProviderMSSoftware` | Microsoft Software Key Storage Provider | Software (file-backed) |

Use `ProviderMSPlatform` for production. Fall back to `ProviderMSSoftware` for
development/testing when no TPM is available.

### Key generation

Generate a new ECDSA P-256 key inside the TPM (or software KSP):

```go
signer, err := store.Generate(certtostore.GenerateOpts{
    Algorithm: certtostore.EC,
    Size:      256,
})
if err != nil {
    return fmt.Errorf("generating key in store: %w", err)
}
// signer implements crypto.Signer — the private key never leaves the provider
```

The returned `crypto.Signer` can be used immediately to build a CSR or passed
to a `ProfiledSignerFunc` for certificate issuance.

### Certificate import — `StoreWithDisposition`

After receiving a signed certificate from the CA, import it into the store:

```go
// StoreWithDisposition: second arg is the CA cert (intermediate, the direct issuer)
err := store.StoreWithDisposition(
    signedCert,        // the signed leaf certificate
    intermediateCert,  // the direct issuer (intermediate CA, NOT the root)
    windows.CERT_STORE_ADD_REPLACE_EXISTING, // disposition = 3
)
```

**Critical:** The second argument must be the **intermediate CA certificate**
(the direct issuer of the leaf), not the root CA. The library uses it to build
the chain association in the store. Passing the root instead of the intermediate
causes chain-building failures at TLS time.

### Certificate retrieval → crypto.Signer

Retrieve a certificate and its associated `crypto.Signer` for use in TLS:

```go
storedCert, ctx, _, err := store.CertByCommonName(cn)
if err != nil {
    return fmt.Errorf("finding certificate %q: %w", cn, err)
}
defer certtostore.FreeCertContext(ctx)

key, err := store.CertKey(context.Background())
if err != nil {
    return fmt.Errorf("obtaining signer for %q: %w", cn, err)
}
// key implements crypto.Signer — backed by TPM or software KSP
```

### Building tls.Certificate from the store

Combine the retrieved cert and signer into a `tls.Certificate`:

```go
func certFromStore(cn string, intermediateDER []byte) (tls.Certificate, func(), error) {
    store, err := certtostore.OpenWinCertStoreCurrentUser(
        certtostore.ProviderMSPlatform,
        cn, nil, nil, false,
    )
    if err != nil {
        return tls.Certificate{}, nil, fmt.Errorf("opening cert store: %w", err)
    }

    cert, ctx, _, err := store.CertByCommonName(cn)
    if err != nil {
        store.Close()
        return tls.Certificate{}, nil, fmt.Errorf("finding certificate %q in store: %w", cn, err)
    }
    defer certtostore.FreeCertContext(ctx)

    key, err := store.CertKey(context.Background())
    if err != nil {
        store.Close()
        return tls.Certificate{}, nil, fmt.Errorf("obtaining signer for %q: %w", cn, err)
    }

    tlsCert := tls.Certificate{
        Certificate: [][]byte{cert.Raw},
        PrivateKey:  key, // crypto.Signer backed by TPM
    }

    // In enterprise PKI, append the intermediate for chain presentation
    if len(intermediateDER) > 0 {
        tlsCert.Certificate = append(tlsCert.Certificate, intermediateDER)
    }

    cleanup := func() { store.Close() }
    return tlsCert, cleanup, nil
}
```

**How it works:** `certtostore` opens the Windows certificate store via
CryptoAPI, locates the certificate, and returns a `*certtostore.Key` that
implements `crypto.Signer`. All `Sign` calls are dispatched to the TPM through
the NCrypt API — the private key material is never exported to user-space memory.

### Enterprise PKI enrollment workflow

Full workflow for TPM-backed keys with enterprise PKI (root → intermediate → leaf):

1. **Generate key inside TPM** — `store.Generate(GenerateOpts{EC, 256})`
2. **Export the public key** — only the public half leaves the TPM
3. **Submit to intermediate CA** — via `ProfiledSignerFunc`, CLI tool, or AD CS
4. **Receive signed cert + intermediate CA cert** — the CA returns both
5. **Import into store** — `store.StoreWithDisposition(cert, intermediateCert, 3)`
6. **Build `tls.Certificate`** — retrieve cert + signer for TLS handshakes

```go
// 1. Generate key in store
signer, err := store.Generate(certtostore.GenerateOpts{
    Algorithm: certtostore.EC,
    Size:      256,
})

// 2-4. Sign with intermediate CA (ProfiledSignerFunc captures intermediate key)
clientCert, err := profiledSign(signer.Public(), cn, clientProfile)

// 5. Import signed cert + intermediate into store
err = store.StoreWithDisposition(clientCert, intermediateCert,
    windows.CERT_STORE_ADD_REPLACE_EXISTING)

// 6. Retrieve for TLS
storedCert, ctx, _, _ := store.CertByCommonName(cn)
defer certtostore.FreeCertContext(ctx)
key, _ := store.CertKey(context.Background())

tlsCert := tls.Certificate{
    Certificate: [][]byte{storedCert.Raw, intermediateCert.Raw},
    PrivateKey:  key,
    Leaf:        storedCert,
}
```

### Cleanup

NCrypt containers persist until explicitly removed. Clean up when
decommissioning:

```go
store, _ := certtostore.OpenWinCertStoreCurrentUser(
    certtostore.ProviderMSPlatform, containerName, nil, nil, false,
)
store.DeleteKeyContainer(containerName)
store.RemoveCertByCommonName("myservice.internal")
```

> For PowerShell-based cleanup commands (`certutil -delkey`, `Remove-Item Cert:\...`),
> see [AGENTS.windows.md](../../winservice/AGENTS.windows.md).

---

## Hardware-backed keys

### `crypto.Signer` — the abstraction for hardware keys

Go's `crypto.Signer` interface is the standard abstraction for private keys
that may live in hardware:

```go
type Signer interface {
    Public() crypto.PublicKey
    Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}
```

Software keys (`*ecdsa.PrivateKey`, `*rsa.PrivateKey`) implement `crypto.Signer`
natively. TPM and HSM libraries provide their own implementations where the
`Sign` method issues a command to the hardware — the private key material never
leaves the secure boundary.

### Why hardware-backed keys matter

A TPM (Trusted Platform Module) or HSM (Hardware Security Module) generates the
key pair internally. Only the public key is exportable. The private key is used
exclusively via the `Sign` method, which delegates to the hardware. Even a
root-level compromise of the host cannot extract the raw key bytes.

### Issuance workflow with hardware keys

The standard CSR workflow adapts naturally to hardware-backed keys:

1. **Generate key in hardware.** The TPM/HSM creates an ECDSA P-256 key pair.
   The private key is non-exportable.
2. **Export the public key.** The `crypto.Signer.Public()` method returns the
   `crypto.PublicKey` without exposing private material.
3. **Submit to the CA.** The CA's signing function accepts the external public
   key and produces a signed leaf certificate containing it.
4. **Receive signed certificate.** The CA returns the signed leaf cert (DER or
   PEM encoded).
5. **Associate certificate with the hardware key.** The signed cert is paired
   with the `crypto.Signer` in a `tls.Certificate` for use in TLS handshakes.

### Building a `tls.Certificate` with a hardware key

When the private key lives in hardware, construct the `tls.Certificate`
manually. The `PrivateKey` field accepts any `crypto.Signer`:

```go
// hwSigner is a crypto.Signer backed by a TPM or HSM.
// leafDER and intermediateDER are the DER-encoded certificates from the CA.
tlsCert := tls.Certificate{
    Certificate: [][]byte{leafDER, intermediateDER},
    PrivateKey:  hwSigner, // crypto.Signer — hardware handle, not raw key bytes
}

clientTLS := &tls.Config{
    Certificates: []tls.Certificate{tlsCert},
    RootCAs:      rootCAs,
    MinVersion:   tls.VersionTLS12,
}
```

The `Certificate` field is an ordered slice of DER-encoded certificates: the
leaf first, followed by the intermediate. This is the same chain the peer
receives during the TLS handshake. The root is omitted — the peer already has
it in its trust pool.

### CA signing functions that accept external public keys

The `SignerFunc` pattern — where the CA's signing function accepts a
`crypto.PublicKey` parameter — is what enables hardware-backed key workflows:

```go
// SignerFunc accepts an external public key, keeping key generation
// completely separate from certificate signing.
type SignerFunc func(pub crypto.PublicKey, cn string) (*x509.Certificate, error)
```

A `ProfiledSignerFunc` variant adds role-specific profiles (EKU, SANs) to the
signature:

```go
// ProfiledSignerFunc extends SignerFunc with a leaf profile controlling EKU
// and SANs. The caller provides the public key; the CA never sees the
// private key.
type ProfiledSignerFunc func(pub crypto.PublicKey, cn string, profile LeafProfile) (*x509.Certificate, error)
```

Because these functions accept `crypto.PublicKey` rather than generating keys
internally, the same CA logic works for software keys, TPM keys, and HSM keys
without modification. The caller generates (or retrieves) the key pair through
whatever mechanism is appropriate, then passes only the public half to the CA.

---

## Certificate lifecycle

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

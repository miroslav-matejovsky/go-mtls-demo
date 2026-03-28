# AGENTS.client.md — Production mTLS Client in Go

You are implementing an HTTP client that authenticates to servers using mutual TLS (mTLS). The client presents its own certificate during the TLS handshake, and the server verifies it against a trusted CA. This guide covers every pattern you need.

## Client TLS configuration

The core of an mTLS client is its `tls.Config`:

```go
tlsCfg := &tls.Config{
    MinVersion:   tls.VersionTLS12,
    RootCAs:      rootCAs,                             // trust pool for server verification
    Certificates: []tls.Certificate{clientCert},       // client's own cert + key
}
```

| Field | Purpose |
|-------|---------|
| `MinVersion` | Floor for the TLS protocol version. Always set `tls.VersionTLS12` — older versions have known vulnerabilities. Go negotiates TLS 1.3 when both sides support it. |
| `RootCAs` | An `*x509.CertPool` containing the root CA certificate(s) used to verify the server's certificate chain. If `nil`, Go falls back to the system trust store. For mTLS you should always set this explicitly. |
| `Certificates` | A slice of `tls.Certificate` values the client presents when the server requests client authentication. Each entry pairs a certificate chain with its private key. Typically you provide exactly one. |

Do not set fields you do not need. Go's defaults are secure — `InsecureSkipVerify` is `false`, cipher suites are well-ordered, and TLS 1.3 is preferred automatically.

## Loading client certificate and key

Use `tls.LoadX509KeyPair` to load the client's certificate chain and private key from PEM files:

```go
clientCert, err := tls.LoadX509KeyPair(chainFile, keyFile)
if err != nil {
    return fmt.Errorf("loading client certificate: %w", err)
}
```

**Chain file contents** — The PEM file should contain the client's leaf certificate first, followed by any intermediate CA certificates, in order up to (but not including) the root:

```
-----BEGIN CERTIFICATE-----
<client leaf certificate>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<intermediate CA certificate>
-----END CERTIFICATE-----
```

`LoadX509KeyPair` parses all certificates in the file and sets them as the chain. The server uses this chain to build a path back to its trusted root.

**Enterprise PKI note:** In organizations with a multi-level CA hierarchy, the chain file should contain the leaf certificate first, then the intermediate CA certificate (the direct issuer of the leaf). Do **not** include the root CA in the chain file — the root belongs only in the server's `ClientCAs` trust pool. Including the root is unnecessary (the server already has it) and violates the separation between "what the client presents" and "what the server trusts."

**Key file contents** — A PEM-encoded private key (ECDSA or RSA). ECDSA P-256 is preferred for new deployments — smaller keys, faster handshakes, equivalent security to RSA-3072.

## Building the server trust pool

Load the **root CA** certificate into an `x509.CertPool`. This is the trust anchor the client uses to verify the server's certificate chain:

```go
rootPEM, err := os.ReadFile(rootCertFile)
if err != nil {
    return fmt.Errorf("reading root CA cert: %w", err)
}

rootCAs := x509.NewCertPool()
if !rootCAs.AppendCertsFromPEM(rootPEM) {
    return fmt.Errorf("no valid certificates found in %s", rootCertFile)
}
```

**Why root-only, not intermediate:** The server presents its leaf certificate plus any intermediates during the handshake. The client only needs the root to anchor the chain. If you put the intermediate in `RootCAs` and the server rotates to a new intermediate (signed by the same root), your client breaks. Using root-only means intermediate rotation is transparent.

**Multiple roots:** Call `AppendCertsFromPEM` multiple times or concatenate root certs into one PEM file. This is useful during root CA rotation — trust both old and new roots simultaneously.

## HTTP client transport

Attach the TLS config to an `http.Client` via `http.Transport`:

```go
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig:     tlsCfg,
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
        TLSHandshakeTimeout: 10 * time.Second,
    },
}
```

| Field | Default | Guidance |
|-------|---------|----------|
| `MaxIdleConns` | 100 | Total idle connections across all hosts. Increase for high-fan-out services. |
| `MaxIdleConnsPerHost` | 2 | Idle connections per host. The default of 2 is low — set to 10-20 for services that talk to few backends heavily. |
| `IdleConnTimeout` | 90s | How long idle connections stay in the pool before closing. |
| `TLSHandshakeTimeout` | 10s | Maximum time for the TLS handshake. Set this to catch unresponsive servers early. |

**Connection pooling:** `http.Transport` maintains a pool of persistent TCP+TLS connections. Reusing connections avoids repeated TLS handshakes — each handshake involves a full cryptographic exchange. This is why you should create **one `http.Client`** (or a small number) and reuse it across your application.

**When to create multiple clients:** Only when you need different TLS configurations — for example, one client for service A (different root CA) and another for service B. Never create a new client per request.

## Request timeout patterns

### Client-level timeout

`http.Client.Timeout` sets the maximum duration for the entire request lifecycle — DNS lookup, TLS handshake, sending the request, reading the response body:

```go
client := &http.Client{
    Timeout:   30 * time.Second,
    Transport: transport,
}
```

If the timeout fires, the request is cancelled and `client.Do(req)` returns an error. This is a safety net — set it to a generous upper bound.

### Per-request timeout with context

Use `context.WithTimeout` for fine-grained, per-request deadlines:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
if err != nil {
    return fmt.Errorf("creating request: %w", err)
}

resp, err := client.Do(req)
```

**Key differences:**
- `Client.Timeout` applies uniformly to all requests made by that client.
- `context.WithTimeout` applies to a single request and can be set per-call.
- If both are set, the shorter one wins.
- Context cancellation is cooperative — the transport checks the context at each stage (dial, TLS, headers, body read).

**Recommendation:** Set `Client.Timeout` as a global safety net (e.g., 60s). Use `context.WithTimeout` for per-endpoint deadlines (e.g., 5s for a health check, 30s for a data fetch).

## Certificate rotation without restart

### The `GetClientCertificate` callback

For long-running services, certificates expire and must be rotated. Instead of restarting the process, use the `GetClientCertificate` callback:

```go
tlsCfg := &tls.Config{
    MinVersion: tls.VersionTLS12,
    RootCAs:    rootCAs,
    GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
        cert, err := tls.LoadX509KeyPair(chainFile, keyFile)
        if err != nil {
            return nil, fmt.Errorf("reloading client cert: %w", err)
        }
        return &cert, nil
    },
}
```

Go calls this function on **every new TLS handshake**. When the cert files are replaced on disk, the next handshake picks up the new certificate automatically.

### When to use `Certificates` vs `GetClientCertificate`

| Scenario | Use |
|----------|-----|
| Short-lived process, cert outlives the process | `Certificates` — simpler, loaded once at startup |
| Long-running service, cert rotates during lifetime | `GetClientCertificate` — reloads from disk per handshake |
| Hardware-backed key (TPM/HSM) | `Certificates` with `crypto.Signer` — the key never changes, only the cert might |

Do **not** set both `Certificates` and `GetClientCertificate`. If `GetClientCertificate` is set, Go uses it exclusively and ignores `Certificates`.

### Caching with file-watch reload

Calling `LoadX509KeyPair` on every handshake works but involves disk I/O. For high-throughput services, cache the certificate and reload only when the file changes:

```go
type certReloader struct {
    mu       sync.RWMutex
    cert     *tls.Certificate
    certPath string
    keyPath  string
}

func (cr *certReloader) GetCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
    cr.mu.RLock()
    defer cr.mu.RUnlock()
    return cr.cert, nil
}

func (cr *certReloader) Reload() error {
    cert, err := tls.LoadX509KeyPair(cr.certPath, cr.keyPath)
    if err != nil {
        return fmt.Errorf("reloading cert: %w", err)
    }
    cr.mu.Lock()
    cr.cert = &cert
    cr.mu.Unlock()
    return nil
}
```

Trigger `Reload()` from a file watcher (e.g., `fsnotify`), a signal handler (e.g., `SIGHUP` on Linux), or a periodic timer. The `sync.RWMutex` ensures concurrent handshakes see a consistent certificate.

## Using crypto.Signer for hardware-backed keys

When the client's private key lives in a TPM, HSM, or platform certificate store, the key material never leaves the hardware. These systems provide a `crypto.Signer` interface — Go's TLS stack calls `Sign()` on the signer during the handshake without ever seeing the raw private key.

Build the `tls.Certificate` manually:

```go
tlsCert := tls.Certificate{
    Certificate: [][]byte{leafDER, intermediateDER}, // DER-encoded cert chain
    PrivateKey:  signer,                              // crypto.Signer from TPM/HSM
    Leaf:        leafCert,                            // parsed *x509.Certificate (optional but recommended)
}
```

| Field | Value |
|-------|-------|
| `Certificate` | Slice of DER-encoded certificates. Leaf first, then intermediates. Use `cert.Raw` to get DER from a parsed `*x509.Certificate`. |
| `PrivateKey` | Any value implementing `crypto.Signer`. The TLS stack calls `signer.Public()` and `signer.Sign()`. |
| `Leaf` | Pre-parsed leaf certificate. Setting this avoids Go re-parsing `Certificate[0]` on every handshake. |

**Enterprise PKI with a TPM-backed key:**

In enterprise environments the client certificate is typically signed by an intermediate CA, not by the root directly. Include the intermediate in the chain so the server can build the full path back to the root:

```go
// Enterprise PKI with TPM-backed client key
tlsCert := tls.Certificate{
    Certificate: [][]byte{leafCert.Raw, intermediateCert.Raw},
    PrivateKey:  tpmSigner, // crypto.Signer from TPM/HSM
    Leaf:        leafCert,
}
```

- `intermediateCert` is the CA that directly issued `leafCert`. Include it in the chain so the server can verify the path: leaf → intermediate → root.
- The root CA is **not** in the chain — it lives in the server's `ClientCAs` pool. The server already trusts it; sending it is redundant and a common misconfiguration.
- `tpmSigner` implements `crypto.Signer`. The private key never leaves the TPM — Go calls `tpmSigner.Sign()` during the handshake, and the TPM performs the cryptographic operation internally.

**Common `crypto.Signer` sources:**
- Windows certificate store via `certtostore` or `ncrypt` libraries
- TPM 2.0 via `go-tpm` or platform-specific KSP
- PKCS#11 HSMs via `crypto11` or `pkcs11` bindings
- Cloud KMS (Azure Key Vault, AWS KMS, GCP Cloud KMS) via their Go SDKs

## Retry patterns for TLS failures

Not all TLS errors are equal. Classify them before deciding whether to retry:

### Do not retry — configuration errors

```go
var unknownAuth x509.UnknownAuthorityError
var certInvalid x509.CertificateInvalidError

if errors.As(err, &unknownAuth) {
    // Server's cert was signed by an unknown CA.
    // Fix: check RootCAs configuration.
    log.Fatal("server certificate not trusted — check root CA config")
}

if errors.As(err, &certInvalid) {
    // Certificate is expired, not yet valid, or has wrong usage.
    // Fix: rotate the certificate, then retry.
    log.Fatal("certificate invalid — check expiry and EKU")
}
```

These indicate misconfiguration or an expired certificate. Retrying will not help — fix the root cause.

### Retry with backoff — transient errors

```go
if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
    // Network timeout — server may be temporarily unreachable.
    // Retry with exponential backoff.
}

if isConnectionRefused(err) {
    // Server is down or not listening.
    // Retry with backoff — it may be restarting.
}
```

Use exponential backoff with jitter for transient failures. A simple pattern:

```go
backoff := 100 * time.Millisecond
for attempt := 0; attempt < maxRetries; attempt++ {
    resp, err := client.Do(req)
    if err == nil {
        return resp, nil
    }
    if !isTransient(err) {
        return nil, err // permanent failure, don't retry
    }
    jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
    time.Sleep(backoff + jitter)
    backoff *= 2
}
```

## Verifying server identity

Go's TLS stack verifies the server's certificate automatically during the handshake:

1. The server presents its certificate chain.
2. Go builds a path from the leaf through intermediates to a root in `RootCAs`.
3. Go checks the leaf's Subject Alternative Names (SANs) against the expected server name.

### The `ServerName` field

By default, Go infers `ServerName` from the URL's hostname. You only need to set it explicitly in these cases:

```go
tlsCfg := &tls.Config{
    MinVersion: tls.VersionTLS12,
    RootCAs:    rootCAs,
    ServerName: "myservice.internal", // override hostname for verification
}
```

**When to set `ServerName` explicitly:**
- Connecting by IP address (e.g., `https://10.0.0.5:8443`) — there's no hostname to infer.
- Connecting through a proxy or load balancer where the dial address differs from the logical service name.
- The server certificate has SANs that don't match the connection address.

### Never disable verification

```go
// ❌ NEVER do this in production
tlsCfg := &tls.Config{
    InsecureSkipVerify: true, // disables ALL server certificate checks
}
```

`InsecureSkipVerify: true` disables certificate chain validation AND hostname verification. It makes the connection vulnerable to man-in-the-middle attacks. There is no legitimate production use case for this setting.

If you need to trust a private CA, add it to `RootCAs`. If the hostname doesn't match, set `ServerName`. These are the correct solutions.

## Testing the client

### Test setup: mTLS server + client

Use `httptest.NewUnstartedServer` to create a test server that requires client certificates:

```go
func TestClientMTLS(t *testing.T) {
    // Generate test CA, server cert, client cert (use your cert generation helpers)
    caCert, serverCert, clientCert := generateTestCerts(t)

    // Build server trust pool (verifies client certs)
    clientCAs := x509.NewCertPool()
    clientCAs.AddCert(caCert)

    // Create test server requiring client auth
    srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))
    srv.TLS = &tls.Config{
        MinVersion:   tls.VersionTLS12,
        Certificates: []tls.Certificate{serverCert},
        ClientCAs:    clientCAs,
        ClientAuth:   tls.RequireAndVerifyClientCert,
    }
    srv.StartTLS()
    defer srv.Close()

    // Build client trust pool (verifies server cert)
    rootCAs := x509.NewCertPool()
    rootCAs.AddCert(caCert)

    // Create mTLS client
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                MinVersion:   tls.VersionTLS12,
                RootCAs:      rootCAs,
                Certificates: []tls.Certificate{clientCert},
            },
        },
    }

    resp, err := client.Get(srv.URL)
    require.NoError(t, err)
    defer resp.Body.Close()
    require.Equal(t, http.StatusOK, resp.StatusCode)
}
```

### Test: server rejects untrusted client

Always test the negative path — a client whose certificate was signed by a different CA must be rejected:

```go
func TestClientUntrustedRejected(t *testing.T) {
    // ... same server setup as above ...

    // Generate a SEPARATE CA and client cert not trusted by the server
    untrustedCACert, untrustedClientCert := generateUntrustedCerts(t)

    // Suppress TLS error log noise from the test server
    srv.Config.ErrorLog = log.New(io.Discard, "", 0)

    rootCAs := x509.NewCertPool()
    rootCAs.AddCert(untrustedCACert) // client trusts the untrusted CA (can verify server if needed)

    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                MinVersion:   tls.VersionTLS12,
                RootCAs:      rootCAs,
                Certificates: []tls.Certificate{untrustedClientCert},
            },
        },
    }

    _, err := client.Get(srv.URL)
    require.Error(t, err) // handshake must fail
}
```

### Test file isolation

When tests write certificate files to disk, always use `t.TempDir()`:

```go
func TestClientWithFiles(t *testing.T) {
    dir := t.TempDir() // cleaned up automatically after test

    chainFile := filepath.Join(dir, "client-chain.crt")
    keyFile := filepath.Join(dir, "client.key")
    // ... write certs, run test ...
}
```

Never read from or write to hardcoded paths in tests. `t.TempDir()` ensures parallel tests don't conflict and cleanup is automatic.

## Common mistakes

### `InsecureSkipVerify: true` left in production code

This is the most dangerous mTLS mistake. It disables all server certificate verification. Code review tools should flag any occurrence. If you see it in a codebase, remove it and replace with proper `RootCAs` configuration.

### Not closing response bodies

```go
// ❌ Leaks connections — the transport can't reuse them
resp, err := client.Get(url)
if err != nil {
    return err
}
// forgot resp.Body.Close()

// ✅ Always close, even if you don't read the body
resp, err := client.Get(url)
if err != nil {
    return err
}
defer resp.Body.Close()
```

An unclosed response body prevents the underlying TCP connection from returning to the pool. Under load, you'll exhaust file descriptors or hit connection limits.

### Creating a new `http.Client` per request

```go
// ❌ No connection reuse — every request does a full TLS handshake
func callService() error {
    client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
    resp, err := client.Get(url)
    // ...
}

// ✅ Create once, reuse everywhere
var client = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}

func callService() error {
    resp, err := client.Get(url)
    // ...
}
```

Each `http.Transport` has its own connection pool. Creating a new one per request means every call performs DNS resolution, TCP connect, and a full TLS handshake — a significant latency penalty.

### Missing chain bundle — only leaf cert in the chain file

If the chain file contains only the leaf certificate (no intermediate), the server may not be able to build a path from the client's leaf cert to the root CA. The handshake fails with a verification error on the server side. Always include the intermediate CA certificate after the leaf in the chain file.

### Using intermediate CA in `RootCAs` instead of root

```go
// ❌ Breaks when the server rotates its intermediate
rootCAs.AppendCertsFromPEM(intermediatePEM)

// ✅ Root CA only — intermediate rotation is transparent
rootCAs.AppendCertsFromPEM(rootPEM)
```

If you put the intermediate in `RootCAs`, any intermediate rotation on the server side breaks your client. The root CA is the stable trust anchor.

### Ignoring `GetClientCertificate` for long-running services

If your service runs for weeks or months and the client certificate has a shorter validity period (e.g., 30 days), using `Certificates` means the process must be restarted to pick up a renewed cert. Use `GetClientCertificate` instead — it reloads from disk on each new TLS handshake.

### Missing the intermediate CA from the client's chain file in enterprise PKI

```go
// ❌ Only the leaf — server cannot build a path to the root
tlsCert := tls.Certificate{
    Certificate: [][]byte{leafCert.Raw},
    PrivateKey:  tpmSigner,
    Leaf:        leafCert,
}

// ✅ Leaf + intermediate — server can verify leaf → intermediate → root
tlsCert := tls.Certificate{
    Certificate: [][]byte{leafCert.Raw, intermediateCert.Raw},
    PrivateKey:  tpmSigner,
    Leaf:        leafCert,
}
```

**Symptom:** The server rejects the client with a `tls: certificate required` or `x509: certificate signed by unknown authority` error, even though the client's leaf cert was legitimately issued by the enterprise PKI. The server has the root CA in its `ClientCAs` pool, but it cannot build the chain because the intermediate is missing. **Fix:** Include the intermediate CA certificate (the direct issuer of the leaf) in the `Certificate` slice, immediately after the leaf.

### Not setting `Leaf` on manually constructed `tls.Certificate`

```go
// ❌ Go re-parses Certificate[0] on every handshake
tlsCert := tls.Certificate{
    Certificate: [][]byte{leafDER},
    PrivateKey:  signer,
}

// ✅ Pre-parse once
tlsCert := tls.Certificate{
    Certificate: [][]byte{leafDER},
    PrivateKey:  signer,
    Leaf:        leafCert, // *x509.Certificate — avoids repeated parsing
}
```

## Quick reference: minimal mTLS client

```go
func NewMTLSClient(chainFile, keyFile, rootCAFile string) (*http.Client, error) {
    clientCert, err := tls.LoadX509KeyPair(chainFile, keyFile)
    if err != nil {
        return nil, fmt.Errorf("loading client cert: %w", err)
    }

    rootPEM, err := os.ReadFile(rootCAFile)
    if err != nil {
        return nil, fmt.Errorf("reading root CA: %w", err)
    }
    rootCAs := x509.NewCertPool()
    if !rootCAs.AppendCertsFromPEM(rootPEM) {
        return nil, fmt.Errorf("no valid certs in %s", rootCAFile)
    }

    return &http.Client{
        Timeout: 30 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                MinVersion:   tls.VersionTLS12,
                RootCAs:      rootCAs,
                Certificates: []tls.Certificate{clientCert},
            },
            MaxIdleConnsPerHost: 10,
            IdleConnTimeout:     90 * time.Second,
            TLSHandshakeTimeout: 10 * time.Second,
        },
    }, nil
}
```

## Required imports

```go
import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "fmt"
    "net/http"
    "net/http/httptest"
    "os"
    "sync"
    "time"
)
```

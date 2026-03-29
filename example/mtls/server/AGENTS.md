# Production mTLS Server in Go

> **Parent:** [AGENTS.md](../AGENTS.md) — mTLS concepts and architecture
> **Layer:** Adapter
> **Go package:** `server.go` in each demo package

You are implementing a production Go HTTP server that requires mutual TLS (mTLS). This guide covers every aspect of server-side mTLS configuration: TLS setup, certificate loading, trust pools, timeouts, graceful shutdown, health checks, logging, certificate rotation, and common mistakes. For certificate creation and chain bundle format see [certs/AGENTS.md](../certs/AGENTS.md).

All code targets Go's standard library (`crypto/tls`, `crypto/x509`, `net/http`). No third-party TLS libraries are needed.

---

## Server TLS configuration

The `tls.Config` struct controls the entire mTLS handshake. Every field below is required for a correct mTLS server.

```go
tlsCfg := &tls.Config{
    MinVersion:   tls.VersionTLS12,
    Certificates: []tls.Certificate{serverCert},
    ClientCAs:    clientCAs,
    ClientAuth:   tls.RequireAndVerifyClientCert,
}
```

| Field | Purpose |
|-------|---------|
| `MinVersion` | Floor for the TLS protocol version. `tls.VersionTLS12` disables TLS 1.0 and 1.1, which have known vulnerabilities. Use `tls.VersionTLS13` if all clients support it. |
| `Certificates` | The server's own certificate chain and private key, loaded as a `tls.Certificate`. The server presents this chain during the handshake. |
| `ClientCAs` | An `*x509.CertPool` containing the root CA(s) the server trusts for validating client certificates. This is the server's trust anchor. |
| `ClientAuth` | Must be `tls.RequireAndVerifyClientCert` for mTLS. This tells the server to demand a client certificate and cryptographically verify it against `ClientCAs`. |

**Why `RequireAndVerifyClientCert`:** The default value is `tls.NoClientCert`, which means the server never asks for a client certificate — mTLS is silently disabled. There is no compile-time or runtime warning. This is the single most common mTLS misconfiguration.

Other `ClientAuth` values (`RequestClientCert`, `RequireAnyClientCert`, `VerifyClientCertIfGiven`) are almost never correct for production mTLS. They either skip verification or make client certs optional, defeating the purpose.

---

## Loading certificate chain bundles

Use `tls.LoadX509KeyPair` to load the server's certificate chain and private key from PEM files:

```go
serverCert, err := tls.LoadX509KeyPair(chainFile, keyFile)
if err != nil {
    return fmt.Errorf("loading server certificate: %w", err)
}
```

**Chain file format.** The chain file is a PEM file containing the leaf certificate followed by any intermediate CA certificates, in order:

```
-----BEGIN CERTIFICATE-----
<leaf certificate>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<intermediate CA certificate>
-----END CERTIFICATE-----
```

- First certificate = leaf (the server's own cert)
- Remaining certificates = intermediates (in chain order, leaf → root)
- Do NOT include the root CA in the chain file — the client already has it in its trust pool

`tls.LoadX509KeyPair` parses all PEM blocks in the chain file automatically. The first block becomes `tls.Certificate.Leaf`; the rest populate `tls.Certificate.Certificate` (the DER-encoded chain).

**Key file.** A separate PEM file containing the server's private key (ECDSA or RSA). Restrict permissions to `0600`.

**Enterprise PKI note:** In organizations that issue certificates through an internal PKI with one or more intermediate CAs, the chain file MUST include the direct issuer intermediate — without it, clients that trust only the root CA cannot build a complete chain and the handshake fails with "certificate signed by unknown authority." `tls.LoadX509KeyPair` automatically parses all PEM blocks in the file, so a multi-certificate chain file (leaf + one or more intermediates) works with no extra code.

---

## Building the client trust pool

The trust pool tells the server which root CAs it trusts for validating client certificates.

```go
rootPEM, err := os.ReadFile(rootCACertFile)
if err != nil {
    return fmt.Errorf("reading root CA cert: %w", err)
}

clientCAs := x509.NewCertPool()
if !clientCAs.AppendCertsFromPEM(rootPEM) {
    return fmt.Errorf("no valid certificates found in %s", rootCACertFile)
}
```

**Load the ROOT CA certificate, not the intermediate.** The trust pool must contain root CA certificates only. This is critical for certificate rotation:

- If you put the intermediate CA in the trust pool, rotating the intermediate requires restarting or reconfiguring every server.
- If you put the root CA in the trust pool, you can rotate intermediates freely — the chain validation (leaf → intermediate → root) still succeeds as long as the root CA is trusted.

`AppendCertsFromPEM` returns `false` if no valid PEM certificate blocks were found. Always check this return value — a common failure mode is passing a key file or empty file by mistake.

---

## Server timeouts

Every production HTTP server MUST set explicit timeouts. Without them, the server is vulnerable to resource exhaustion attacks.

```go
srv := &http.Server{
    TLSConfig:    tlsCfg,
    Handler:      handler,
    ReadTimeout:  10 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  120 * time.Second,
}
```

| Timeout | What it limits | Attack it mitigates |
|---------|---------------|---------------------|
| `ReadTimeout` | Time from connection acceptance to full request body read | **Slowloris**: attacker sends headers byte-by-byte, holding connections open indefinitely |
| `WriteTimeout` | Time from request header read to response write completion | **Slow read**: attacker reads the response byte-by-byte, tying up server goroutines |
| `IdleTimeout` | Time a keep-alive connection can remain idle before being closed | **Connection exhaustion**: attacker opens many connections and holds them idle, consuming file descriptors |

**Tuning guidelines:**

- `ReadTimeout` and `WriteTimeout`: Set to the maximum expected request/response time plus margin. 10–30 seconds covers most API workloads. For file uploads or streaming, increase accordingly.
- `IdleTimeout`: 60–120 seconds is typical. Shorter values free resources faster but increase TLS handshake overhead from reconnections.
- For long-running requests (WebSockets, SSE), use per-handler timeouts with `http.TimeoutHandler` instead of setting large server-level timeouts.

---

## Graceful shutdown

Always use `srv.Shutdown(ctx)`, never `srv.Close()`.

```go
// Set up signal handling
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

// Start server
ln, err := tls.Listen("tcp", address, srv.TLSConfig)
if err != nil {
    return fmt.Errorf("creating TLS listener: %w", err)
}
go srv.Serve(ln)

// Wait for shutdown signal
<-sigCh

// Drain in-flight requests
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
if err := srv.Shutdown(ctx); err != nil {
    return fmt.Errorf("server shutdown: %w", err)
}
```

**`Shutdown` vs `Close`:**

| Method | Behavior |
|--------|----------|
| `srv.Shutdown(ctx)` | Stops accepting new connections, waits for in-flight requests to complete (up to context deadline), then shuts down. This is correct for production. |
| `srv.Close()` | Immediately closes all connections with no drain period. Active requests are killed mid-flight. Use only in tests or emergencies. |

**Signal handling:** Listen for `SIGTERM` (sent by Kubernetes, systemd, container runtimes on graceful stop) and `SIGINT` (Ctrl+C). The 5-second drain timeout should exceed your longest expected request, but be shorter than the orchestrator's kill timeout (Kubernetes default: 30 seconds).

---

## Starting the server

### Production pattern: `tls.Listen` + `srv.Serve`

```go
ln, err := tls.Listen("tcp", address, srv.TLSConfig)
if err != nil {
    return fmt.Errorf("creating TLS listener: %w", err)
}
go srv.Serve(ln)
```

This is the preferred production pattern because:

- You control the listener lifecycle independently of the server
- You can retrieve the actual listen address via `ln.Addr()` (useful when binding to `:0`)
- The `tls.Config` is applied at the listener level, ensuring all connections are TLS from the start
- You can log the listen address before entering `Serve`

**Do NOT use `srv.ListenAndServeTLS(certFile, keyFile)`.** It creates a new `tls.Config` internally and merges it with `srv.TLSConfig` in ways that can override your settings. It also loads certificates from files directly, bypassing any chain bundle setup.

### Test pattern: `httptest.NewUnstartedServer`

```go
ts := httptest.NewUnstartedServer(handler)
ts.TLS = tlsCfg
ts.StartTLS()
defer ts.Close()
// ts.URL contains the server address
```

Use this only in tests. It:

- Allocates a random port automatically
- Handles cleanup via `defer ts.Close()`
- Returns the URL for client connections

Never use `httptest` in production code.

---

## Health check endpoint

mTLS creates a challenge for health checks: Kubernetes probes and load balancers may not have client certificates.

### Option A: Separate plaintext listener (recommended for Kubernetes)

Run the health endpoint on a different port without TLS:

```go
healthMux := http.NewServeMux()
healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("ok"))
})

healthSrv := &http.Server{
    Addr:    ":8081",
    Handler: healthMux,
}
go healthSrv.ListenAndServe()
```

- Kubernetes liveness/readiness probes hit `:8081/healthz` over plaintext
- The main mTLS server runs on a separate port (e.g., `:8443`)
- No client certificate needed for health checks
- The health port should NOT be exposed outside the pod

### Option B: TLS health check (load balancer has client cert)

If the load balancer or ingress controller is configured with a client certificate, the health endpoint can live on the same mTLS listener:

```go
mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("ok"))
})
```

This is simpler but requires the health checker to present a valid client cert.

### Health check content

A production `/healthz` should verify downstream dependencies are reachable (database, cache, dependent services). Return `200 OK` when healthy, `503 Service Unavailable` when not. Keep the check fast — Kubernetes default timeout is 1 second.

---

## Logging TLS handshake info

Use `VerifyPeerCertificate` for audit logging of client connections. This callback runs after the standard certificate verification.

```go
tlsCfg := &tls.Config{
    // ... other fields ...
    VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
        if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
            leaf := verifiedChains[0][0]
            log.Printf("mTLS client connected: CN=%s Serial=%s Issuer=%s",
                leaf.Subject.CommonName,
                leaf.SerialNumber.String(),
                leaf.Issuer.CommonName,
            )
        }
        return nil // return non-nil to reject the connection
    },
}
```

**Guidelines:**

- Log the client's Common Name (CN), serial number, and issuer for audit trails
- Log at connection time, not per-request (the handshake happens once per TLS session)
- NEVER log private key material, raw certificate bytes, or session keys
- Return `nil` to allow the connection. Return an error to reject it (e.g., for allowlist enforcement beyond CA trust)
- `verifiedChains` is populated only when the standard verification succeeded. `rawCerts` contains the raw DER certificates before verification — useful for custom validation but handle with care

---

## Dynamic certificate reloading

Use `GetCertificate` to reload the server certificate without restarting the process. This is essential for certificate rotation in long-running services.

```go
type certReloader struct {
    mu       sync.RWMutex
    cert     *tls.Certificate
    certPath string
    keyPath  string
}

func (cr *certReloader) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
    cr.mu.RLock()
    defer cr.mu.RUnlock()
    return cr.cert, nil
}

func (cr *certReloader) reload() error {
    newCert, err := tls.LoadX509KeyPair(cr.certPath, cr.keyPath)
    if err != nil {
        return fmt.Errorf("reloading certificate: %w", err)
    }
    cr.mu.Lock()
    cr.cert = &newCert
    cr.mu.Unlock()
    return nil
}
```

Wire it into the TLS config:

```go
reloader := &certReloader{certPath: chainFile, keyPath: keyFile}
if err := reloader.reload(); err != nil {
    return fmt.Errorf("initial certificate load: %w", err)
}

tlsCfg := &tls.Config{
    MinVersion:     tls.VersionTLS12,
    GetCertificate: reloader.getCertificate,
    ClientCAs:      clientCAs,
    ClientAuth:     tls.RequireAndVerifyClientCert,
}
```

**When `GetCertificate` is set, do NOT also populate `Certificates`.** Go's TLS stack checks `GetCertificate` first; if it returns a cert, `Certificates` is ignored. Setting both creates confusion about which cert is served.

**Triggering reload:** Watch the certificate files with `fsnotify`, poll on a timer, or handle a `SIGHUP` signal. Always log the reload event (success or failure) and keep serving the old cert if the new one fails to load.

**Thread safety:** The `sync.RWMutex` ensures concurrent TLS handshakes read the certificate safely while a reload writes it. An alternative is `atomic.Pointer[tls.Certificate]` for lock-free reads.

---

### Using Windows Certificate Store and TPM-backed Keys

On Windows servers with a Trusted Platform Module (TPM), the server's private key can be stored in hardware via the platform Key Storage Provider (KSP). The key never leaves the TPM — TLS handshakes are signed inside the module. The certificate and any chain intermediates are retrieved from the Windows certificate store.

> **Full `certtostore` API reference:** See [certs/AGENTS.md — Certificate store operations](../certs/AGENTS.md#certificate-store-operations-certtostore)
> for `OpenWinCertStoreCurrentUser`, `Generate`, `StoreWithDisposition`,
> `CertByCommonName`, `CertKey`, and cleanup patterns.

Wire the `tls.Certificate` returned from `certtostore` into `tls.Config.Certificates` exactly like a file-loaded certificate:

```go
tlsCert, cleanup, err := certFromStore("myserver.example.com", intermediateDER)
if err != nil {
    return fmt.Errorf("loading TPM-backed server cert: %w", err)
}
defer cleanup()

tlsCfg := &tls.Config{
    MinVersion:   tls.VersionTLS12,
    Certificates: []tls.Certificate{tlsCert},
    ClientCAs:    clientCAs,
    ClientAuth:   tls.RequireAndVerifyClientCert,
}
```

**NCrypt container cleanup.** When decommissioning a server, remove the orphaned NCrypt container and certificate from the Windows store to avoid key accumulation. See [AGENTS.windows.md](../../winservice/AGENTS.windows.md) for PowerShell cleanup commands.

---

## Error handling

### Wrapping errors

Always wrap errors with context using `%w`:

```go
if err != nil {
    return fmt.Errorf("creating TLS listener on %s: %w", address, err)
}
```

This preserves the error chain for `errors.Is` / `errors.As` checks upstream.

### Suppressing expected TLS errors

When an untrusted client connects, Go's HTTP server logs a TLS error to `srv.ErrorLog`. In production, untrusted connections are expected (scanners, misconfigured clients) and these logs create noise.

```go
srv.ErrorLog = log.New(io.Discard, "", 0)
```

For more granular control, use a custom `log.Logger` that filters specific TLS error patterns rather than discarding all errors:

```go
srv.ErrorLog = log.New(&tlsErrorFilter{inner: os.Stderr}, "", log.LstdFlags)
```

Where `tlsErrorFilter` implements `io.Writer` and drops lines containing known TLS rejection messages while forwarding everything else.

---

## Common mistakes

### 1. Missing `ClientAuth` field

```go
// WRONG — ClientAuth defaults to tls.NoClientCert
tlsCfg := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientCAs:    clientCAs,
}
```

The server never requests a client certificate. mTLS is silently disabled even though `ClientCAs` is set.

**Fix:** Always set `ClientAuth: tls.RequireAndVerifyClientCert`.

### 2. Using intermediate CA in ClientCAs instead of root

```go
// WRONG — intermediate in trust pool
clientCAs.AppendCertsFromPEM(intermediatePEM)
```

This works initially but breaks when you rotate the intermediate CA. Clients with certs signed by the new intermediate are rejected because the server only trusts the old one.

**Fix:** Load the root CA certificate into `ClientCAs`. The chain validation (leaf → intermediate → root) handles intermediates automatically.

### 3. No timeouts

```go
// WRONG — no timeouts set
srv := &http.Server{
    TLSConfig: tlsCfg,
    Handler:   handler,
}
```

Vulnerable to slowloris, slow-read, and connection exhaustion attacks.

**Fix:** Always set `ReadTimeout`, `WriteTimeout`, and `IdleTimeout`.

### 4. Using `ListenAndServeTLS` instead of `tls.Listen` + `Serve`

```go
// WRONG — less control over listener and TLS config
srv.ListenAndServeTLS("cert.pem", "key.pem")
```

`ListenAndServeTLS` loads certificates from files internally and may override parts of your `TLSConfig`. You also lose access to the listener for address discovery and lifecycle control.

**Fix:** Use `tls.Listen("tcp", addr, srv.TLSConfig)` followed by `srv.Serve(ln)`.

### 5. Not setting MinVersion

```go
// WRONG — allows TLS 1.0 and 1.1
tlsCfg := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    clientCAs,
}
```

Go's default minimum is TLS 1.0. TLS 1.0 and 1.1 have known vulnerabilities and are deprecated by RFC 8996.

**Fix:** Always set `MinVersion: tls.VersionTLS12` (or `tls.VersionTLS13`).

### 6. Forgetting the chain bundle (leaf only, missing intermediate)

```go
// WRONG — only the leaf cert, no intermediate
serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
```

If `server.crt` contains only the leaf certificate, clients that don't have the intermediate CA in their trust store will fail to validate the chain. The TLS handshake fails with a "certificate signed by unknown authority" error.

**Fix:** Concatenate the leaf and intermediate certificates into a single PEM chain file. `tls.LoadX509KeyPair` parses all PEM blocks automatically.

### 7. Using `srv.Close()` instead of `srv.Shutdown(ctx)`

```go
// WRONG — kills in-flight requests immediately
srv.Close()
```

**Fix:** Use `srv.Shutdown(ctx)` with a timeout context to drain in-flight requests gracefully.

### 8. Omitting the intermediate CA from the server's chain bundle in enterprise PKI

```go
// WRONG — chain file contains only the leaf; intermediate is missing
// server-chain.pem has one PEM block (the leaf cert)
serverCert, err := tls.LoadX509KeyPair("server-chain.pem", "server.key")
```

Clients that trust only the root CA cannot build the chain from the leaf to the root. The TLS handshake fails with `x509: certificate signed by unknown authority`. This is especially common in enterprise PKI environments where an intermediate CA issued the server certificate — the intermediate is not in the client's trust store, so the server must provide it.

**Fix:** Include the direct issuer intermediate in the chain file (leaf first, then intermediate). `tls.LoadX509KeyPair` parses all PEM blocks and builds the chain automatically:

```
-----BEGIN CERTIFICATE-----
<leaf certificate>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<intermediate CA certificate>
-----END CERTIFICATE-----
```

### 9. Not checking `AppendCertsFromPEM` return value

```go
// WRONG — silently creates an empty trust pool
clientCAs := x509.NewCertPool()
clientCAs.AppendCertsFromPEM(someBytes)
```

If `someBytes` contains no valid PEM certificates (wrong file, key file instead of cert, empty file), `AppendCertsFromPEM` returns `false` and the pool remains empty. Every client connection will be rejected.

**Fix:** Always check the boolean return value and fail loudly.

---

## Quick reference: complete server setup

```go
func createMTLSServer(addr, chainFile, keyFile, rootCAFile string, handler http.Handler) (*http.Server, net.Listener, error) {
    // Load server cert chain + key
    serverCert, err := tls.LoadX509KeyPair(chainFile, keyFile)
    if err != nil {
        return nil, nil, fmt.Errorf("loading server certificate: %w", err)
    }

    // Build client trust pool from root CA
    rootPEM, err := os.ReadFile(rootCAFile)
    if err != nil {
        return nil, nil, fmt.Errorf("reading root CA: %w", err)
    }
    clientCAs := x509.NewCertPool()
    if !clientCAs.AppendCertsFromPEM(rootPEM) {
        return nil, nil, fmt.Errorf("no valid certs in %s", rootCAFile)
    }

    tlsCfg := &tls.Config{
        MinVersion:   tls.VersionTLS12,
        Certificates: []tls.Certificate{serverCert},
        ClientCAs:    clientCAs,
        ClientAuth:   tls.RequireAndVerifyClientCert,
    }

    srv := &http.Server{
        TLSConfig:    tlsCfg,
        Handler:      handler,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    ln, err := tls.Listen("tcp", addr, srv.TLSConfig)
    if err != nil {
        return nil, nil, fmt.Errorf("TLS listen on %s: %w", addr, err)
    }

    return srv, ln, nil
}
```

**Required imports:**

```go
import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "net/http/httptest"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"
)
```

---

## Security checklist

Before deploying, verify every item:

- ✅ `ClientAuth` is `tls.RequireAndVerifyClientCert`
- ✅ `MinVersion` is `tls.VersionTLS12` or higher
- ✅ `ClientCAs` contains root CA cert (not intermediate)
- ✅ Server cert chain file includes leaf + intermediate (not root)
- ✅ `ReadTimeout`, `WriteTimeout`, `IdleTimeout` are all set
- ✅ Graceful shutdown via `srv.Shutdown(ctx)` with signal handling
- ✅ Private key files have `0600` permissions
- ✅ `AppendCertsFromPEM` return value is checked
- ✅ Health check endpoint is accessible without client cert (if needed)
- ✅ TLS handshake info is logged for audit (client CN, serial, issuer)
- ✅ Certificate reloading is implemented for rotation
- ✅ Expected TLS rejection errors are filtered from logs
- ✅ No use of `ListenAndServeTLS` — use `tls.Listen` + `Serve`

# Chapter 3: Scenario patterns and what to copy

Back to [docs index](index.md)

This chapter maps each scenario to the implementation pattern it teaches best.

## `tlsmem`: smallest working TLS example

Use `tlsmem` to understand the minimum pieces needed for server-authenticated TLS:

- create a CA
- sign a server certificate
- trust the CA on the client
- run an HTTPS server

This is the fastest way to understand what `RootCAs` does and how the client verifies the server.

## `mtlsmem`: smallest working mTLS example

This is the clearest reference for the actual mutual-authentication handshake.

Server-side pattern:

```go
serverTLSConf := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientCAs:    clientCAs,
    ClientAuth:   tls.RequireAndVerifyClientCert,
}
```

Client-side pattern:

```go
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs:      certpool,
            Certificates: []tls.Certificate{certificate},
        },
    },
}
```

This is the best place to understand the contract of mTLS before you introduce file handling, config, or OS-specific key storage.

## `tlsfiles`: TLS with realistic loading boundaries

In real applications, certificates usually come from files, stores, or secret backends rather than from in-memory objects created inside the same process.

`tlsfiles` shows the disk-loading pattern:

```go
caPEM, err := os.ReadFile(caCertFile)
certpool := x509.NewCertPool()
if !certpool.AppendCertsFromPEM(caPEM) {
    return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertFile)
}

client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{RootCAs: certpool},
    },
}
```

Use this when you need a clean example of trust loading from configuration and file paths.

## `mtlsfiles`: best general-purpose mTLS template

If you want one scenario to copy from for a conventional Go mTLS service, this is usually the one.

It demonstrates:

- `tls.LoadX509KeyPair` for identity loading
- `AppendCertsFromPEM` for trust loading
- proper server-side client certificate enforcement
- proper client-side certificate presentation
- an explicit negative-path test
- a clean separation that is easy to integration-test

Server pattern:

```go
serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)

caPEM, err := os.ReadFile(caCertFile)
clientCAs := x509.NewCertPool()
if !clientCAs.AppendCertsFromPEM(caPEM) {
    return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertFile)
}

tlsCfg := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientCAs:    clientCAs,
    ClientAuth:   tls.RequireAndVerifyClientCert,
}
```

Client pattern:

```go
clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)

client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs:      certpool,
            Certificates: []tls.Certificate{clientCert},
        },
    },
}
```

For many real services, this is the best baseline to adapt first.

## `mtlsenterprise`: production PKI topology

`mtlsenterprise` teaches the correct root → intermediate → leaf PKI model used in production environments. It adds three capabilities not present in `mtlsfiles`:

- **3-tier CA hierarchy**: root CA signs an intermediate CA; the intermediate signs all leaf certificates
- **Role-specific EKU**: server certs get only `ServerAuth`, client certs get only `ClientAuth`
- **Chain bundles**: leaf + intermediate packed into a single PEM file for TLS presentation

Operator pattern — building the PKI hierarchy via `ca.NewEnterprise`:

```go
authority, err := ca.NewEnterprise(ca.EnterpriseConfig{
    RootCA:         ca.CAConfig{CN: rootCN, Validity: rootValidity},
    IntermediateCA: ca.CAConfig{CN: intCN, Validity: intValidity},
})
```

Issuing profiled leaf certificates via CSR:

```go
serverCSR, serverKey, err := ca.CreateServerCSR(cn, dnsNames)
serverCert, err := authority.SignServerCSR(serverCSR)
```

Chain bundle loading — both server and client load their chain bundle (leaf + intermediate) the same way:

```go
serverCert, err := tls.LoadX509KeyPair(chainFile, keyFile)
```

Trust is anchored at the root CA — the intermediate is delivered in the chain bundle, not in the trust store:

```go
rootPEM, err := os.ReadFile(rootCertFile)
clientCAs := x509.NewCertPool()
clientCAs.AppendCertsFromPEM(rootPEM)
```

Use this when you need a realistic PKI topology and want to understand how chain bundles, EKU separation, and DNS SANs work together.

## `mtlstpm`: advanced key-management pattern

`mtlstpm` is the advanced example in the repo. Its main teaching value is that Go's TLS stack can work with a `crypto.Signer` instead of raw private-key bytes. All memory-backed scenarios (`tlsmem`, `mtlsmem`) now use the same `crypto.Signer` abstraction — a plain `*ecdsa.PrivateKey` implements the interface, so the pattern is consistent from the simplest demo to TPM-backed production code.

That lets the private key live in the Windows certificate store and be backed by TPM or NCrypt.

The TLS certificate is assembled like this:

```go
tlsCert := tls.Certificate{
    Certificate: [][]byte{clientCert.Raw},
    PrivateKey:  key,
    Leaf:        clientCert,
}
```

And the key is created and enrolled like this:

```go
signer, err := store.Generate(certtostore.GenerateOpts{
    Algorithm: certtostore.EC,
    Size:      256,
})

clientCSR, err := ca.CreateClientCSRForSigner(signer, clientCfg.CN)
if err != nil {
    return err
}

clientCert, err := state.authority.SignClientCSR(clientCSR)
```

This is the right example when you want to keep client private keys outside normal file-based storage.

## `mtlsenterprisetpm`: enterprise PKI with TPM-backed client keys

`mtlsenterprisetpm` combines the enterprise PKI hierarchy from `mtlsenterprise` with TPM-backed client keys from `mtlstpm`. This is the most production-complete scenario in the repo (Windows only).

It teaches:

- everything `mtlsenterprise` teaches (3-tier hierarchy, EKU, chain bundles)
- TPM-backed client key generation via `certtostore`
- in-memory chain assembly: the client cert chain (leaf + intermediate) is built from the Windows cert store rather than loaded from a file

The client-side TLS certificate is assembled in memory with the intermediate cert appended:

```go
tlsCert := tls.Certificate{
    Certificate: [][]byte{clientCert.Raw, intermediateCert.Raw},
    PrivateKey:  key,
    Leaf:        clientCert,
}
```

This is the right example when you need both enterprise PKI topology and hardware-backed client identity on Windows.

## What to copy first

If you are implementing mTLS in Go today:

- copy the trust-wiring ideas from `mtlsmem`
- copy the file-loading patterns from `mtlsfiles`
- copy the enterprise PKI patterns from `mtlsenterprise` if you need an intermediate CA, role-specific EKU, or chain bundles
- copy the enterprise PKI + TPM patterns from `mtlsenterprisetpm` if you need hardware-backed client keys with a production CA hierarchy (Windows only)
- copy the `crypto.Signer` pattern from `mtlstpm` only if you need stronger key isolation with a simpler CA model

The `crypto.Signer` abstraction is now used consistently across all memory-backed scenarios, not just `mtlstpm`. This means you can test the full mTLS client path (including `client.NewMTLSWithSigner`) with a plain `*ecdsa.PrivateKey` — no Windows, TPM, or `internal/tpm` dependency required.

For most applications, `mtlsenterprisetpm` is the most production-complete reference (enterprise PKI + hardware-backed keys, Windows only). On non-Windows platforms, `mtlsenterprise` is the best production PKI reference. `mtlsfiles` remains the simplest operational baseline.

Previous: [Chapter 2 - Core TLS and mTLS model in Go](02-core-tls-and-mtls-model.md)

Next: [Chapter 4 - Production guidance and configuration direction](04-production-guidance.md)

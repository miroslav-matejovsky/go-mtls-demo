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

In real applications, certificates usually come from files, stores, or secret backends rather than from in-memory PEM blobs created inside the same process.

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

## `mtlstpm`: advanced key-management pattern

`mtlstpm` is the advanced example in the repo. Its main teaching value is that Go's TLS stack can work with a `crypto.Signer` instead of raw private-key bytes.

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

clientCert, err := state.operator.SignCertForKey(signer.Public(), clientCfg.CN)
```

This is the right example when you want to keep client private keys outside normal file-based storage.

## What to copy first

If you are implementing mTLS in Go today:

- copy the trust-wiring ideas from `mtlsmem`
- copy the file-loading patterns from `mtlsfiles`
- copy the `crypto.Signer` pattern from `mtlstpm` only if you need stronger key isolation

For most applications, `mtlsfiles` plus selected ideas from `mtlstpm` is the best practical starting point.

Previous: [Chapter 2 - Core TLS and mTLS model in Go](02-core-tls-and-mtls-model.md)

Next: [Chapter 4 - Production guidance and configuration direction](04-production-guidance.md)

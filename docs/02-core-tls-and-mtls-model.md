# Chapter 2: Core TLS and mTLS model in Go

Back to [docs index](index.md)

## The basic trust model

At a high level, every example in this repo follows the same structure:

```text
Issuer (CA or intermediate)
   |
   +--> server certificate --> server TLS config
   |
   +--> client certificate --> client TLS config

Client trusts server issuer
Server trusts client issuer
```

For one-way TLS:

- the server presents its certificate
- the client validates the server against a trust pool

For mutual TLS:

- the client also presents a certificate
- the server also validates the client against a trust pool

## What mTLS means in Go code

On the server side, the important mTLS settings are:

```go
tlsCfg := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientCAs:    clientCAs,
    ClientAuth:   tls.RequireAndVerifyClientCert,
}
```

This means:

- `Certificates` is the server identity
- `ClientCAs` is the trust bundle used to validate client certificates
- `RequireAndVerifyClientCert` means the server will reject clients that do not present a valid trusted certificate

On the client side, the important mTLS settings are:

```go
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs:      certpool,
            Certificates: []tls.Certificate{clientCert},
        },
    },
}
```

This means:

- `RootCAs` is the trust bundle used to validate the server certificate
- `Certificates` is the client identity presented to the server

If your code does not do both of those things, you do not yet have mTLS.

## The implementation split to preserve

One of the best lessons in this repo is that TLS code gets cleaner when you separate these concerns:

- issuing certificates
- loading or discovering certificates
- building `tls.Config`
- orchestrating the actual demo or application flow

That is why the repo keeps:

- shared certificate helpers in `internal/pki`
- per-scenario `CreateServer(...)` and `CreateClient(...)` constructors
- `RunDemo()` as orchestration

That split is worth preserving in real applications too.

## Keep CA private keys behind a narrow interface

The shared certificate package exposes certificate issuance through the `Authority` type:

```go
authority, err := ca.NewSimple(ca.CAConfig{CN: "Demo CA", Validity: 24 * time.Hour})
```

That is a good design rule:

- do not let the whole application manipulate CA private keys directly
- keep issuing authority behind a narrow interface
- make it easier to replace in-memory demo issuance with a more realistic issuer later

The `Authority` type holds the CA private key internally and never exposes it. All leaf
certificate issuance goes through CSR-based methods (`SignServerCSR`, `SignClientCSR`) or
`SignClientCertForKey` for hardware-backed keys that cannot be exported.

## Trust issuers, not random individual leaf certificates

The repo's mTLS examples trust certificate pools, not one-off hardcoded client certificates.

That is the right default design because it scales better operationally:

- certificates can be renewed
- certificates can be reissued
- more than one client can be trusted under the same issuing model

If you choose certificate pinning instead, treat that as a deliberate special case.

## Always prove the negative path

A correct mTLS implementation is not only "trusted client succeeds." It is also "untrusted client fails."

That is why the repo's mTLS scenarios include an intentionally untrusted client signed by a different CA. This is an important engineering rule, not just a demo trick.

Previous: [Chapter 1 - Learning path through the repository](01-learning-path.md)

Next: [Chapter 3 - Scenario patterns and what to copy](03-scenario-patterns.md)

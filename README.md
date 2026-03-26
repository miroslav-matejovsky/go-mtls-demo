# Go TLS / mTLS Demo

A hands-on walkthrough of one-way TLS and mutual TLS (mTLS) in Go.  
All certificates are generated in-memory at runtime using ECDSA P-256 — no files, no `openssl`.

## Concepts

### TLS (one-way)

Only the **server** is authenticated. The client verifies the server's certificate was signed by a
trusted CA. The server accepts any client.

```text
Client ──── verify server cert ────► Server
```

### mTLS (mutual)

**Both** sides are authenticated. The server also requires the client to present a certificate signed
by the same trusted CA. Each party can be sure who it is talking to.

```text
Client ──── verify server cert ────► Server
Client ◄─── verify client cert ───── Server
```

## Running

```pwsh
go run cmd/main.go tlsmem    # one-way TLS demo (in-memory certs)
go run cmd/main.go mtlsmem   # mutual TLS demo  (in-memory certs)
```

Or via the PowerShell script:

```pwsh
.\scripts\run.ps1 tlsmem
.\scripts\run.ps1 mtlsmem
```

## TLS demo output

```text
=== Step 1/4: Generate Certificate Authority (CA) ===
A self-signed CA is the trusted root for this demo.
Its certificate is given to the client so it can verify the server's identity.

  Subject       : go TLS Demo CA
  Issuer        : go TLS Demo CA
  Serial        : 1
  Valid         : 2026-03-25 18:13 UTC → 2026-03-26 19:13 UTC
  Is CA         : true
  Key Usage     : certSign, cRLSign
  Ext Key Usage : [clientAuth serverAuth]

=== Step 2/4: Generate Server Certificate (signed by CA) ===
The server presents this certificate during the TLS handshake.
The client verifies its signature chain leads back to the trusted CA.

  Subject       : go TLS Demo Server
  Issuer        : go TLS Demo CA
  Serial        : 2
  Valid         : 2026-03-25 18:13 UTC → 2026-03-26 19:13 UTC
  Is CA         : false
  Key Usage     : digitalSignature
  Ext Key Usage : [clientAuth serverAuth]

=== Step 3/4: Start TLS server ===
Server config: presents its certificate to clients.
Server does NOT require a certificate from the client (one-way TLS).

[SERVER] Listening on https://127.0.0.1:<port>

=== Step 4/4: Make request over TLS ===
Client config: trusts the CA — does NOT send a certificate (one-way TLS).
Authentication: client verifies server cert → CA   |   server trusts any client.

[CLIENT] GET https://127.0.0.1:<port>
[SERVER] Received request over TLS — version: TLS 1.3, cipher suite: TLS_AES_128_GCM_SHA256
[CLIENT] Handshake complete  — version: TLS 1.3, cipher suite: TLS_AES_128_GCM_SHA256
[CLIENT] Response: 200 OK
```

## mTLS demo output

```text
=== Step 1/5: Generate Certificate Authority (CA) ===
The same CA signs both the server and client certificates.
Both parties trust this CA and will accept any certificate it has signed.

  Subject       : go mTLS Demo CA
  Issuer        : go mTLS Demo CA
  Serial        : 1
  Valid         : 2026-03-25 18:13 UTC → 2026-03-26 19:13 UTC
  Is CA         : true
  Key Usage     : certSign, cRLSign
  Ext Key Usage : [clientAuth serverAuth]

=== Step 2/5: Generate Server Certificate (signed by CA) ===
The server presents this certificate to the client during the mTLS handshake.
The client verifies its signature chain leads back to the trusted CA.

  Subject       : go mTLS Demo Server
  Issuer        : go mTLS Demo CA
  Serial        : 2
  Valid         : 2026-03-25 18:13 UTC → 2026-03-26 19:13 UTC
  Is CA         : false
  Key Usage     : digitalSignature
  Ext Key Usage : [clientAuth serverAuth]

=== Step 3/5: Generate Client Certificate (signed by CA) ===
KEY DIFFERENCE from plain TLS: the client also has a certificate.
The server will require this certificate and verify it against the trusted CA.

  Subject       : go mTLS Demo Client
  Issuer        : go mTLS Demo CA
  Serial        : 2
  Valid         : 2026-03-25 18:13 UTC → 2026-03-26 19:13 UTC
  Is CA         : false
  Key Usage     : digitalSignature
  Ext Key Usage : [clientAuth serverAuth]

=== Step 4/5: Start mTLS server ===
Server config: presents its certificate AND requires a valid client certificate.
Connections without a CA-signed client certificate will be rejected.

[SERVER] Listening on https://127.0.0.1:<port>

=== Step 5/6: Make request over mTLS (trusted client) ===
Client config: trusts the CA AND sends its own certificate (mutual TLS).
Authentication: client verifies server cert → CA   |   server verifies client cert → CA.

[CLIENT] GET https://127.0.0.1:<port>
[SERVER] Received request over mTLS — version: TLS 1.3, cipher suite: TLS_AES_128_GCM_SHA256
[SERVER] Client certificate: CN=go mTLS Demo Client (issued by CN=go mTLS Demo CA)
[CLIENT] Server certificate verified: go mTLS Demo Server (issued by go mTLS Demo CA)
[CLIENT] Handshake complete  — version: TLS 1.3, cipher suite: TLS_AES_128_GCM_SHA256
[CLIENT] Response: 200 OK

=== Step 6/6: Make request with an untrusted client certificate ===
This client has a certificate signed by a different CA that the server does not trust.
The server must reject the connection during the TLS handshake.

[UNTRUSTED CLIENT] GET https://127.0.0.1:<port>
[UNTRUSTED CLIENT] Connection rejected — Get "...": remote error: tls: unknown certificate authority
[UNTRUSTED CLIENT] Expected: server refused the certificate because it was not signed by the trusted CA.
```

## Certificate structure

```text
Trusted CA  (self-signed, IsCA=true, keyUsage: certSign + cRLSign)
├── Server cert            (signed by CA, keyUsage: digitalSignature, extKeyUsage: serverAuth + clientAuth)
└── Client cert            (signed by CA, keyUsage: digitalSignature, extKeyUsage: serverAuth + clientAuth)

Untrusted CA  (separate self-signed CA, not known to the server)
└── Untrusted client cert  (rejected by server — not signed by the trusted CA)
```

All keys use ECDSA P-256. Certificates are valid for 24 hours and are generated fresh on each run.

## References

- [Create & Sign x509 Certificates in Golang](https://medium.com/@shaneutt/create-sign-x509-certificates-in-golang-8ac4ae49f903)
- [mTLS series](https://victoronsoftware.com/posts/mtls/)
- [mTLS examples in Go](https://github.com/getvictor/mtls)
- [CertToStore Go package](https://pkg.go.dev/github.com/google/certtostore)

# tlsmem — One-way TLS (in-memory certificates)

Demonstrates a TLS handshake where only the **server** is authenticated.  
All certificates are generated in memory at runtime — no files, no `openssl`.

```
Client ──── verify server cert ────► Server
```

## Run

```pwsh
go run cmd/main.go tlsmem
```

## What happens

| Step | What |
|------|------|
| 1/4 | Generate a self-signed CA |
| 2/4 | Generate a server certificate signed by the CA |
| 3/4 | Start HTTPS server with the server certificate |
| 4/4 | Client trusts the CA and connects — server accepts any client |

## Sample output

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

## Certificate structure

```
CA (self-signed)
└── Server cert (signed by CA)
```

All keys use ECDSA P-256, valid for 24 hours, generated fresh on each run.

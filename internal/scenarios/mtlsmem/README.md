# mtlsmem — Mutual TLS (in-memory certificates)

Demonstrates a mutual TLS handshake where **both** client and server are authenticated.  
All certificates are generated in memory at runtime — no files, no `openssl`.

```text
Client ──── verify server cert ────► Server
Client ◄─── verify client cert ───── Server
```

## Run

```pwsh
go run ./cmd/ mtlsmem
```

## What happens

| Step | What                                                    |
| ---- | ------------------------------------------------------- |
| 1/5  | Generate a self-signed CA                               |
| 2/5  | Generate a server certificate signed by the CA          |
| 3/5  | Generate a client certificate signed by the CA          |
| 4/5  | Start HTTPS server requiring a valid client certificate |
| 5/6  | Trusted client connects — both sides verify each other  |
| 6/6  | Untrusted client (different CA) is rejected             |

## Sample output

```text
=== Step 1/5: Generate Certificate Authority (CA) ===
The same CA signs both the server and client certificates.
Both parties trust this CA and will accept any certificate it has signed.

  Subject       : go mTLS Demo CA
  ...

=== Step 3/5: Generate Client Certificate (signed by CA) ===
KEY DIFFERENCE from plain TLS: the client also has a certificate.
The server will require this certificate and verify it against the trusted CA.

  Subject       : go mTLS Demo Client
  ...

=== Step 5/6: Make request over mTLS (trusted client) ===
[CLIENT] GET https://127.0.0.1:<port>
[SERVER] Received request over mTLS — version: TLS 1.3, cipher suite: TLS_AES_128_GCM_SHA256
[SERVER] Client certificate: CN=go mTLS Demo Client (issued by CN=go mTLS Demo CA)
[CLIENT] Server certificate verified: go mTLS Demo Server (issued by go mTLS Demo CA)
[CLIENT] Handshake complete  — version: TLS 1.3, cipher suite: TLS_AES_128_GCM_SHA256
[CLIENT] Response: 200 OK

=== Step 6/6: Make request with an untrusted client certificate ===
[UNTRUSTED CLIENT] GET https://127.0.0.1:<port>
[UNTRUSTED CLIENT] Connection rejected — Get "...": remote error: tls: unknown certificate authority
[UNTRUSTED CLIENT] Expected: server refused the certificate because it was not signed by the trusted CA.
```

## Certificate structure

```text
CA (self-signed)
├── Server cert (signed by CA)
└── Client cert (signed by CA)

Untrusted CA (separate, unknown to the server)
└── Untrusted client cert → rejected
```

All keys use ECDSA P-256, valid for 24 hours, generated fresh on each run.

# mtlsfiles — Mutual TLS (file-based certificates)

Demonstrates a mutual TLS handshake where **both** client and server are authenticated.  
Certificates are written to separate directories — each representing a different party's file system.

```text
Client ──── verify server cert ────► Server
Client ◄─── verify client cert ───── Server
```

## Run

```pwsh
go run ./cmd/ mtlsfiles
```

Certificate files are written to `certs/mtlsfiles/` (git-ignored) and recreated on every run.

## What happens

| Step | What                                                                         |
| ---- | ---------------------------------------------------------------------------- |
| 1/6  | Generate CA, server cert, and client cert — write to separate directories    |
| 2/6  | Start HTTPS server loading cert + CA from `server/`                          |
| 3/6  | Trusted client loads cert + CA from `client/` — both sides verify each other |
| 4/6  | Generate untrusted client cert (different CA) — write to `untrusted/`        |
| 5/6  | Untrusted client is rejected by the server                                   |
| 6/6  | Print file layout showing ownership boundaries                               |

## File layout

```text
certs/mtlsfiles/
  ca/
    ca.crt          ← public, distributed to both server and client
  server/
    server.crt      ← public, presented to clients during handshake
    server.key      ← private, never leaves the server machine
  client/
    client.crt      ← public, presented to server during mTLS handshake
    client.key      ← private, never leaves the client machine
  untrusted/
    client.crt      ← public, rejected by server (signed by unknown CA)
    client.key      ← private
```

In production each directory belongs to a different machine or team. The only file shared across
boundaries is `ca.crt` — the CA's public certificate.

## Sample output

```text
=== Step 1/6: Generate CA, Server, and Client certificates ===
Each party owns its own directory — in production they never share private keys:
  certs/mtlsfiles/ca       — Certificate Authority
  certs/mtlsfiles/server   — Server operator
  certs/mtlsfiles/client   — Client operator

  [CA]     Certificate → certs/mtlsfiles/ca/ca.crt
  [CA]     Private key stays on the CA machine — NOT written to disk here.
  [SERVER] Certificate → certs/mtlsfiles/server/server.crt
  [SERVER] Private key  → certs/mtlsfiles/server/server.key
  [CLIENT] Certificate → certs/mtlsfiles/client/client.crt
  [CLIENT] Private key  → certs/mtlsfiles/client/client.key

=== Step 2/6: Start mTLS server (loading certificates from disk) ===
Server reads from its own directory: certs/mtlsfiles/server
Server also holds a copy of the CA cert to verify clients: certs/mtlsfiles/ca/ca.crt

[SERVER] Listening on https://127.0.0.1:<port>

=== Step 3/6: Make request over mTLS (trusted client) ===
Client reads from its own directory: certs/mtlsfiles/client
[SERVER] Client certificate: CN=go mTLS Demo Client (issued by CN=go mTLS Demo CA)
[CLIENT] Server certificate verified: go mTLS Demo Server (issued by go mTLS Demo CA)
[CLIENT] Handshake complete  — version: TLS 1.3, cipher suite: TLS_AES_128_GCM_SHA256
[CLIENT] Response: 200 OK

=== Step 5/6: Make request with untrusted client certificate ===
[UNTRUSTED CLIENT] Connection rejected — remote error: tls: certificate required
[UNTRUSTED CLIENT] Expected: server refused the certificate because it was not signed by the trusted CA.
```

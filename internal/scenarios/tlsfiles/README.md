# tlsfiles — One-way TLS (file-based certificates)

Demonstrates a TLS handshake where only the **server** is authenticated.  
Certificates are written to disk and loaded from files — showing realistic file ownership.

```text
Client ──── verify server cert ────► Server
```

## Run

```pwsh
go run ./cmd/ tlsfiles
```

Certificate files are written to `certs/tlsfiles/` (git-ignored) and recreated on every run.

## What happens

| Step | What                                                                     |
| ---- | ------------------------------------------------------------------------ |
| 1/4  | Generate CA — write `ca/ca.crt` to disk (private key stays in memory)    |
| 2/4  | Generate server cert — write `server/server.crt` and `server/server.key` |
| 3/4  | Start HTTPS server loading cert from `server/` directory                 |
| 4/4  | Client loads `ca/ca.crt` and connects — server accepts any client        |

## File layout

```text
certs/tlsfiles/
  ca/
    ca.crt        ← public, distributed to clients
  server/
    server.crt    ← public, presented to clients during handshake
    server.key    ← private, never leaves the server machine
```

## Sample output

```text
=== Step 1/4: Generate Certificate Authority (CA) ===
In a real deployment the CA lives on a dedicated secure machine.
Its public certificate is distributed to clients and servers.
The private key never leaves the CA machine — it is NOT written to disk here.

  Subject       : go TLS Demo CA
  ...

  [CA] Certificate → certs/tlsfiles/ca/ca.crt

=== Step 2/4: Generate Server Certificate (signed by CA) ===
  [SERVER] Certificate → certs/tlsfiles/server/server.crt
  [SERVER] Private key  → certs/tlsfiles/server/server.key

=== Step 3/4: Start TLS server (loading certificate from disk) ===
Server reads from its own directory: certs/tlsfiles/server

[SERVER] Listening on https://127.0.0.1:<port>

=== Step 4/4: Make request over TLS (loading CA certificate from disk) ===
Client reads CA certificate from: certs/tlsfiles/ca

[CLIENT] GET https://127.0.0.1:<port>
[SERVER] Received request over TLS — version: TLS 1.3, cipher suite: TLS_AES_128_GCM_SHA256
[CLIENT] Handshake complete  — version: TLS 1.3, cipher suite: TLS_AES_128_GCM_SHA256
[CLIENT] Response: 200 OK
```

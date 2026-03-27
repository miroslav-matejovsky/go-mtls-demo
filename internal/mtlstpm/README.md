# mtlstpm — Mutual TLS with TPM-backed Client Key

**Windows only.** This scenario demonstrates mTLS where the client private key is generated
inside the machine's Trusted Platform Module (TPM) via the Windows Certificate Store.
If no TPM is present, it falls back to the Microsoft Software Key Storage Provider (NCrypt).

## What makes this different from mtlsfiles?

| | mtlsfiles | mtlstpm |
|---|---|---|
| Server cert | Files on disk | Files on disk (same) |
| Client cert | File on disk | Windows cert store (`CurrentUser\My`) |
| Client private key | PEM file on disk | TPM or NCrypt — **never a file** |
| Key exportable? | Yes | No (TPM), or software NCrypt |
| Realistic for | Dev/test | Enterprise workstations, device identity |

## Prerequisites

- Windows 10/11 or Windows Server 2016+
- TPM 2.0 chip (optional — falls back to software KSP automatically)
- Run as a regular user (CurrentUser store — no admin required)

## How it works

```
CA (in-memory)
  │
  ├──► signs server cert ──► written to certs/mtlstpm/server/
  │
  └──► signs client cert ──► imported into Windows cert store
                               (key stored in TPM via NCrypt)
```

### Enrollment flow (demo steps 3–4)

1. Open `CurrentUser\My` store via `certtostore.OpenWinCertStoreCurrentUser`
2. `store.Generate(EC/256)` — creates an ECDSA P-256 key inside the TPM/NCrypt;
   returns a `crypto.Signer` whose `Sign()` method calls into the TPM
3. Use the signer's public key to issue a leaf cert signed by the demo CA
4. `store.StoreWithDisposition(cert, nil, REPLACE_EXISTING)` — links the cert to the key

### Runtime flow (demo step 5)

1. `store.CertByCommonName(cn)` — finds the cert by Subject CN
2. `store.CertKey(ctx)` — derives a `*certtostore.Key` (implements `crypto.Signer`) from the cert context
3. Build `tls.Certificate{PrivateKey: key}` — TLS handshake signing happens inside the TPM

## Running

```pwsh
go run cmd/main.go mtlstpm
# or
.\scripts\run.ps1 mtlstpm
```

## File layout after running

```
certs/mtlstpm/
  ca/
    cert.crt          ← CA public cert (reference copy)
  server/
    server.crt        ← server public cert
    server.key        ← server private key (file — server is not using TPM in this demo)
    ca.crt            ← CA cert copy (server uses this to verify client certs)

Windows cert store (CurrentUser\My):
  go mTLS TPM Demo Client   ← client cert, linked to TPM/NCrypt key
```

Inspect the cert in `certmgr.msc` → Personal → Certificates.

## Manual cleanup

The demo intentionally does not remove the cert or key automatically.
You can use the helper script:

```powershell
pwsh scripts/mtlstpm-cleanup.ps1

# or pin the provider printed by the demo
pwsh scripts/mtlstpm-cleanup.ps1 -Provider "Microsoft Platform Crypto Provider"
```

The script writes each cleanup action to the console as it runs.

Or run these PowerShell commands when you are done:

```powershell
# Remove the client certificate from CurrentUser\My
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$store.Certificates |
    Where-Object { $_.Subject -like "*go mTLS TPM Demo Client*" } |
    ForEach-Object { $store.Remove($_) }
$store.Close()

# Delete the NCrypt key container
# Replace <provider> with the provider printed by the demo
$p = New-Object System.Security.Cryptography.CngProvider('<provider>')
$k = [System.Security.Cryptography.CngKey]::Open('go-mtls-demo-client', $p)
$k.Delete()
```

The provider name is printed by the demo in Step 2 — it is either
`Microsoft Platform Crypto Provider` (TPM) or
`Microsoft Software Key Storage Provider` (software fallback).

## Key concepts demonstrated

- **TPM-backed keys** — the private key is generated and stored inside the TPM chip;
  it cannot be exported, copied, or stolen via the file system
- **Windows Certificate Store** — where enterprise client identity certs live;
  managed via `certmgr.msc`, .NET `X509Store`, or `certtostore`
- **`crypto.Signer` interface** — Go's abstraction over any signing key;
  the `tls` package calls `key.Sign()` without knowing whether it's in-memory or in a TPM
- **Server-side verification** — server holds CA cert; rejects any client whose cert
  was not signed by that CA (same as mtlsfiles)

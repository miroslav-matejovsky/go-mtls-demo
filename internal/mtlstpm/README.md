# mtlstpm — Mutual TLS with TPM-backed Client Key

**Windows only.** This scenario demonstrates mTLS where the client private key is generated
inside the machine's Trusted Platform Module (TPM) via the Windows Certificate Store.
If no TPM is present, it falls back to the Microsoft Software Key Storage Provider (NCrypt).

For broader Go TLS and mTLS implementation guidance using the whole repo as examples,
see [`../../docs/index.md`](../../docs/index.md).

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
4. `store.StoreWithDisposition(cert, caCert, REPLACE_EXISTING)` — links the cert to the key
   and imports the CA copy needed by the Windows certificate store chain

### Runtime flow (demo steps 5–6)

1. `store.CertByCommonName(cn)` — finds the cert by Subject CN
2. `store.CertKey(ctx)` — derives a `*certtostore.Key` (implements `crypto.Signer`) from the cert context
3. Build `tls.Certificate{PrivateKey: key}` — TLS handshake signing happens inside the TPM

## Running

```pwsh
go run ./cmd/ mtlstpm
# or
.\scripts\run.ps1 mtlstpm
```

## What happens

| Step | What                                                                                       |
| ---- | ------------------------------------------------------------------------------------------ |
| 1/7  | Generate the in-memory CA and the file-backed server certificate                           |
| 2/7  | Detect TPM availability or choose the configured Windows key storage provider              |
| 3/7  | Generate the client key inside `CurrentUser\My` via TPM/NCrypt                            |
| 4/7  | Import the signed client certificate and CA copy into the Windows certificate store        |
| 5/7  | Start the mTLS server and make a trusted request using the provider-backed client key      |
| 6/7  | Demonstrate rejection of an untrusted client certificate signed by a different CA          |
| 7/7  | Prompt for cleanup and optionally run `scripts/mtlstpm-cleanup.ps1`                        |

## File layout after running

```
certs/mtlstpm/
  ca/
    cert.crt          ← CA public cert (reference copy)
  server/
    server.crt        ← server public cert
    server.key        ← server private key (file — server is not using TPM in this demo)
    ca.crt            ← CA cert copy (server uses this to verify client certs)

Windows cert store:
  CurrentUser\My
    go mTLS TPM Demo Client   ← client cert, linked to TPM/NCrypt key
  CurrentUser\CA
    go mTLS TPM Demo CA       ← CA copy imported during client cert enrollment
```

Inspect the certs in `certmgr.msc`:
- Personal → Certificates
- Intermediate Certification Authorities → Certificates

## Cleanup

In step 7/7, the demo asks whether it should run `scripts/mtlstpm-cleanup.ps1`
for you. If you answer `yes`, the script runs immediately and prints each cleanup step.

If you answer `no`, the demo prints the same script command and manual commands below.

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
    Where-Object { $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq 'go mTLS TPM Demo Client' } |
    ForEach-Object { $store.Remove($_) }
$store.Close()

# Remove the CA certificate from CurrentUser\CA
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new('CA', 'CurrentUser')
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$store.Certificates |
    Where-Object { $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq 'go mTLS TPM Demo CA' } |
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

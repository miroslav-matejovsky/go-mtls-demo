# Chapter 7: Deploying mTLS services on Windows

Back to [docs index](index.md)

Most TLS and mTLS guidance assumes Linux: PEM files on disk, file permissions via `chmod`, and no OS-managed key storage. Windows changes the picture in three important ways. First, Windows has a built-in certificate store that can hold both certificates and private keys, with access controlled by ACLs rather than file permissions. Second, Windows machines with a TPM (or a software KSP fallback) can protect private keys so they never exist as exportable bytes. Third, in Active Directory environments, Group Policy can distribute CA trust and auto-enroll client certificates across every domain-joined machine — eliminating the manual cert-distribution problem entirely.

The repo's `mtlstpm` scenario already demonstrates the client side of this: a client certificate whose private key lives in the Windows certificate store, backed by the platform's NCrypt layer. This chapter extends that foundation to cover full service deployment on Windows — server identity, trust distribution, service account configuration, and troubleshooting.

## Why Windows deserves its own chapter

Go's `crypto/tls` is platform-neutral. A `tls.Config` struct looks the same whether the binary runs on Linux or Windows. But the operational choices around that struct — where keys are stored, how trust is distributed, which identity a service process runs under — are fundamentally different on Windows.

On Linux, key protection usually means file permissions plus optional integration with a secrets manager or HSM. On Windows, the OS provides a richer default: the certificate store (`certlm.msc` for machine, `certmgr.msc` for user) manages certificates and private keys as first-class OS objects. Private keys can be marked non-exportable and backed by a TPM or software KSP, all without leaving the standard Windows APIs. The repo's `mtlstpm` scenario uses this through the `certtostore` library, which wraps the Windows CNG (Cryptography Next Generation) APIs behind Go's `crypto.Signer` interface.

Enterprise Windows environments add another layer: Active Directory Certificate Services (AD CS) can issue certificates automatically via Group Policy, and Group Policy can push CA trust to every machine in the domain. This means that both sides of the mTLS trust equation — identity (certs + keys) and trust (CA bundles) — can be managed centrally without touching individual machines. None of the repo's current scenarios implement AD CS integration, but the runtime patterns from `mtlstpm` (discover cert in store → derive signer → use `crypto.Signer`) would work identically with auto-enrolled certificates.

## Server identity options on Windows

### File-based identity

This is the `mtlsfiles` pattern. It works on Windows identically to Linux: PEM-encoded certificate and key files on disk, loaded at startup with `tls.LoadX509KeyPair`. It is the simplest option and the right choice for development, testing, and CI.

The weakness is that the private key file is a normal file. Anyone who can read it can copy it. On Linux you would restrict it with `chmod 0600`; on Windows the equivalent is NTFS ACLs. If you run your Go service as a dedicated Windows service account, restrict the key file so only that account can read it:

```powershell
icacls "certs\mtlsfiles\server\server.key" /inheritance:r /grant:r "NT SERVICE\MyGoService:(R)"
```

This removes inherited permissions (`/inheritance:r`) and grants read-only access to the service account. It is a reasonable baseline, but the key is still an exportable file — anyone with administrative access to the machine can still copy it.

### Windows certificate store identity

A stronger option is to store the server certificate and private key in the Windows certificate store. The certificate goes into `LocalMachine\My` (the machine's personal store), and the private key is held by the NCrypt key storage provider — either the software KSP or a TPM-backed KSP if the machine has a TPM.

The critical distinction from file-based identity: the private key never exists as a PEM file. It is created inside the KSP and accessed through a handle. Go code uses it via the `crypto.Signer` interface, exactly as the repo's `mtlstpm` scenario does for client identity.

Important current-state note: the repo's `mtlstpm` scenario demonstrates this pattern for the **client** side. Server-side Windows store identity is a proposed future scenario (`mtlstpmserverstore`, described in Chapter 6) but is not yet implemented. The Go code pattern would be the same — the only difference is that the certificate goes into `LocalMachine\My` instead of `CurrentUser\My`, and the `tls.Config` uses the resulting `tls.Certificate` in the server's `Certificates` slice rather than the client's.

The conceptual Go pattern looks like this:

```go
// Conceptual — not in the repo yet
store, _ := certtostore.OpenWinCertStoreLocalMachine(provider, container, issuers, nil, false)
cert, ctx, _, _ := store.CertByCommonName(cn)
signer, _ := store.CertKey(ctx)
tlsCert := tls.Certificate{
    Certificate: [][]byte{cert.Raw},
    PrivateKey:  signer, // crypto.Signer backed by NCrypt/TPM
    Leaf:        cert,
}
```

This is structurally identical to what `mtlstpm/client.go` does today. The interface abstraction means the same `tls.Certificate` struct works whether the key is in a file, in the software KSP, or in a TPM.

### When to use each

| Scenario | Identity source | Key protection |
| --- | --- | --- |
| Development / CI | PEM files | NTFS ACLs only |
| Windows service (standard) | Cert store (`LocalMachine\My`) | NCrypt Software KSP |
| Windows service (high security) | Cert store (`LocalMachine\My`) | NCrypt + TPM |
| Containerized (Docker on Windows) | Mounted files or env vars | Container isolation |

For most Windows-hosted production services, the cert store with software KSP is the practical middle ground. It eliminates exportable key files without requiring TPM hardware. TPM-backed keys are the strongest option but require hardware support and more careful lifecycle management.

## Client identity options

### In-memory (testing only)

The `mtlsmem` scenario generates all certificates at runtime and never writes them to disk. This is the right model for unit tests and integration tests — it is fast, self-contained, and leaves no cleanup. It is not useful for deployed clients.

### File-based

The `mtlsfiles` scenario loads client certificates and keys from PEM files. This works on any platform and is the simplest approach for cross-platform clients. The same NTFS ACL guidance from the server section applies: restrict the key file to the account that runs the client process.

### Windows cert store with TPM

This is the repo's `mtlstpm` scenario — the most advanced pattern currently implemented. The lifecycle has two phases:

**Enrollment time** (runs once or on renewal):
1. Generate a key pair inside the TPM via `store.Generate(GenerateOpts{...})`
2. Create a CSR or use the public key to get a signed certificate from the CA
3. Import the signed certificate into the user's cert store via `store.StoreWithDisposition(...)`

**Runtime** (every time the client starts):
1. Open the cert store and find the certificate by Common Name (or thumbprint)
2. Derive a `crypto.Signer` handle from the stored key via `store.CertKey(ctx)`
3. Build a `tls.Certificate` with that signer as `PrivateKey`
4. Use it in the client's `tls.Config`

The private key never leaves the TPM. Go's `crypto.Signer` interface means the TLS stack calls `signer.Sign(...)` during the handshake, and the TPM performs the cryptographic operation internally.

### Auto-enrollment with AD CS

In enterprise Active Directory environments, client certificate enrollment can be fully automated. Active Directory Certificate Services (AD CS) provides certificate templates and auto-enrollment policies that are pushed to machines via Group Policy. When a user or machine logs in, the AD CS client requests a certificate matching the template, generates the key pair (optionally TPM-backed), and stores the result in the appropriate certificate store — all without user interaction.

From Go's perspective, an auto-enrolled certificate looks identical to one enrolled manually. The runtime discovery pattern from `mtlstpm` — open the store, find the cert, derive the signer — works the same way. The only difference is who created the certificate: a human running a demo script, or the AD CS auto-enrollment agent.

This is not implemented in the repo, but it is the standard approach for managed Windows devices in enterprise environments.

## Trust distribution

### Manual distribution

For development, testing, or small deployments, import CA certificates directly into the Windows certificate store:

```powershell
# Import CA cert to Trusted Root store (machine-wide)
Import-Certificate -FilePath "ca.crt" -CertStoreLocation "Cert:\LocalMachine\Root"

# Import intermediate CA to Intermediate CAs store
Import-Certificate -FilePath "intermediate.crt" -CertStoreLocation "Cert:\LocalMachine\CA"

# Verify chain
certutil -verify -urlfetch server.crt
```

Once a CA certificate is in `LocalMachine\Root`, any service on that machine will trust certificates issued by that CA — both for outgoing TLS connections and for validating client certificates in mTLS. This is the Windows equivalent of adding a CA to `/etc/pki/ca-trust/source/anchors/` on Linux.

### Group Policy distribution

For enterprise environments with Active Directory, Group Policy is the standard way to distribute CA trust at scale.

The process is:

1. Open Group Policy Management Console (`gpmc.msc`)
2. Create or edit a GPO linked to the appropriate OU
3. Navigate to Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies → Trusted Root Certification Authorities
4. Import the CA certificate

All domain-joined machines in the linked OU receive the CA certificate automatically on the next Group Policy refresh (typically within 90 minutes, or immediately via `gpupdate /force`). No per-machine manual steps are needed.

This solves the trust distribution problem that Chapter 5 identifies: when you rotate an intermediate CA, you need every participant to trust the new issuer before you start issuing leaves from it. With Group Policy, that distribution is a single GPO change instead of touching every machine.

### Per-application trust bundles

This is the repo's current pattern in every scenario. Each party loads CA certificates from files at startup and builds an explicit `x509.CertPool`. For example, the mTLS server loads the client-issuing CA into `ClientCAs`, and the client loads the server-issuing CA into `RootCAs`.

This approach is portable, explicit, and self-contained. It does not depend on the OS certificate store, which makes it work identically on Linux, macOS, and Windows. The trade-off is that trust distribution becomes an operational problem: you need a mechanism to get the right CA files onto each machine.

For cross-platform services or machines that are not domain-joined, per-application trust bundles are often the most practical choice. For Windows-only services in an AD environment, Group Policy distribution is simpler and more maintainable.

## Windows service considerations

### Service account selection

The account a Windows service runs under determines what certificate stores it can access, what network identity it presents, and how tightly its permissions can be scoped.

| Account | Cert store access | Network access | Recommendation |
| --- | --- | --- | --- |
| LocalSystem | `LocalMachine\*` | Machine identity | Overly broad; avoid for mTLS services |
| NetworkService | `LocalMachine\*` (read) | Machine identity | Acceptable for simple services |
| Local Service | Limited | No network identity | Rarely appropriate for mTLS |
| Dedicated service account | Configured via ACL | Explicit | Good for isolation |
| gMSA (Group Managed Service Account) | `LocalMachine\*` (configured) | Domain identity | Enterprise recommendation |

For mTLS services, a Group Managed Service Account (gMSA) is the enterprise recommendation. A gMSA provides a domain identity with automatic password rotation, can be granted specific private key access, and does not require a human to manage credentials. If gMSA is not available, a dedicated service account with explicit ACLs is the next best option.

Avoid LocalSystem for mTLS services. It has full access to every key and certificate on the machine, which violates the principle of least privilege. If the service is compromised, the attacker inherits all of that access.

### Private key access for service accounts

When a certificate and key are stored in the Windows certificate store, the private key has its own ACL separate from the certificate. The service account needs explicit read access to the private key to use it for TLS.

```powershell
# Grant private key access to a service account
# Method 1: certutil (requires the certificate serial number)
certutil -repairstore My "serial-number"

# Method 2: MMC (interactive, useful for debugging)
# Open certlm.msc → Personal → Certificates
# Right-click the certificate → All Tasks → Manage Private Keys
# Add the service account with Read permission
```

If the service starts and logs `access denied` or `keyset does not exist` errors during the TLS handshake, the most common cause is that the service account lacks private key access. The MMC method is the fastest way to diagnose this interactively.

### Running a Go mTLS server as a Windows service

To run a Go binary as a Windows service, use the `golang.org/x/sys/windows/svc` package. The service entry point replaces `main()` with a service handler that receives start, stop, and shutdown signals from the Windows Service Control Manager.

The structure maps cleanly to the patterns the repo already teaches:

1. **Startup**: load certificates (from files or cert store), build the `tls.Config`, create the `http.Server`, call `tls.Listen` and `server.Serve` — the same flow as `mtlsfiles/demo.go` or the proposed `mtlstpmserverstore`.
2. **Shutdown**: the service control handler receives a stop signal, which maps to calling `server.Shutdown(ctx)` with a timeout context — the same graceful shutdown pattern the file-based demos already use.
3. **Logging**: Windows services cannot write to stdout. Use the `eventlog` package from `golang.org/x/sys/windows/svc` or a file-based logger instead of `fmt.Printf`.

The TLS and mTLS configuration is identical whether the binary runs as a console application or as a Windows service. The only differences are lifecycle management (service signals instead of OS signals) and logging (event log instead of stdout).

## Troubleshooting

### Certificate verification

These PowerShell commands are useful for diagnosing certificate and trust issues on Windows:

```powershell
# List certificates in the machine's personal store
Get-ChildItem Cert:\LocalMachine\My | Format-List Subject, Thumbprint, NotAfter, HasPrivateKey

# List certificates in the current user's personal store
Get-ChildItem Cert:\CurrentUser\My | Format-List Subject, Thumbprint, NotAfter, HasPrivateKey

# Verify a certificate chain (checks CA trust, expiry, revocation)
certutil -verify -urlfetch path\to\cert.crt

# Check TLS connectivity from Windows
Test-NetConnection -ComputerName 127.0.0.1 -Port 8444

# Export a certificate (public only) for inspection
certutil -dump path\to\cert.crt
```

### Common TLS handshake failures

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `x509: certificate signed by unknown authority` | CA cert not in client's trust pool | Add CA to `RootCAs` pool or import into cert store |
| `x509: certificate has expired or is not yet valid` | Clock skew or expired cert | Check system time; renew cert |
| `remote error: tls: bad certificate` | Server rejected client cert (mTLS) | Check server's `ClientCAs` pool includes the CA that signed the client cert |
| `remote error: tls: certificate required` | Client did not present a cert | Ensure client `tls.Config.Certificates` is populated |
| `tls: private key does not match public key` | Wrong key file paired with cert | Regenerate or match the correct key to the cert |
| Access denied opening cert store | Service account lacks permissions | Grant private key access via `certutil -repairstore` or MMC |
| `keyset does not exist` | Private key ACL missing for service account | Use MMC → Manage Private Keys to grant Read access |
| TPM error during signing | TPM not available or key handle stale | Check TPM status via `Get-Tpm`; re-enroll if key handle is invalid |

### Debugging with repo scenarios

The repo's scenarios form a useful diagnostic ladder for Windows deployment issues:

1. **Run `go run ./cmd/ mtlsfiles` first.** This exercises the full mTLS handshake using plain files, with no OS-store involvement. If this fails, the problem is in your Go or TLS configuration, not in Windows-specific plumbing.

2. **Run `go run ./cmd/ mtlstpm` next.** This adds the Windows cert store and NCrypt layer for the client side. If `mtlsfiles` works but `mtlstpm` fails, the issue is in store access, key permissions, or TPM availability — not in basic TLS configuration.

3. **Check the cert store directly.** The repo's `internal/pwsh` package provides `ShowCertsInStore(cn)`, which lists certificates matching a Common Name. Use this to verify that enrollment actually placed the certificate where you expect it.

4. **Check TPM availability.** Run `pwsh scripts/run.ps1 mtlstpm` — the demo calls `pwsh.CheckTPM()` at startup, which reports whether a TPM is available and what provider will be used. If no TPM is present, the demo falls back to the software KSP, which still provides non-exportable key storage.

## Mapping repo scenarios to Windows deployment

| Deployment pattern | Start from | What to add |
| --- | --- | --- |
| Go service, certs from files | `mtlsfiles` | NTFS ACLs on key files, Windows service wrapper via `x/sys/windows/svc` |
| Go service, client key in TPM | `mtlstpm` | Already demonstrated in the repo |
| Go service, server key in cert store | `mtlsfiles` + `mtlstpm` ideas | Use `certtostore` for server identity (proposed `mtlstpmserverstore` in Chapter 6) |
| Go service, AD CS auto-enrollment | `mtlstpm` runtime discovery pattern | Configure auto-enrollment via GPO; no Go code changes needed |
| Go service in Windows container | `mtlsfiles` | Mount cert files into container; use container isolation for key protection |

The key insight is that the repo's existing patterns cover most of the Go code you need. The Windows-specific work is primarily operational: configuring stores, setting ACLs, choosing service accounts, and distributing trust via Group Policy. The Go code stays the same because `crypto.Signer` and `tls.Config` abstract away the underlying key storage.

Previous: [Chapter 6 - What to build next](06-what-to-copy-next.md)

Next: [Chapter 8 - Deploying mTLS services as Azure containers](08-azure-container-deployment.md)

# Windows Server mTLS Deployment Guide

> **Parent:** [AGENTS.md](../mtls/AGENTS.md) — mTLS concepts and architecture
> **Layer:** Infrastructure
> **Related:** [certs/AGENTS.md](../mtls/certs/AGENTS.md) (certificate domain + certtostore API) · [operator/AGENTS.md](../mtls/operator/AGENTS.md) (PKI workflows)

> **Audience:** AI coding agent deploying a Go mutual-TLS (mTLS) application on Windows Server.
> This guide covers Windows platform infrastructure — certificate store management,
> NCrypt/CNG providers, service configuration, and troubleshooting. For the Go
> `certtostore` API and certificate domain logic see [certs/AGENTS.md](../mtls/certs/AGENTS.md).

---

## Why Windows is different for mTLS

Go's `crypto/tls` package is platform-neutral — a `tls.Config` works identically on Linux
and Windows at the protocol level. The differences are in **key storage**, **trust
distribution**, and **service management**.

| Concern | Linux | Windows |
|---------|-------|---------|
| Key protection | File permissions (`0600`) + optional secrets manager | NTFS ACLs + Certificate Store + TPM / CNG |
| Trust distribution | Copy CA cert files to each host | Group Policy pushes root CAs to all domain machines |
| Key provider | OpenSSL / file on disk | NCrypt / CNG key storage providers (software or TPM) |
| Service lifecycle | systemd unit | Windows Service (`golang.org/x/sys/windows/svc`) |
| Firewall | iptables / nftables | Windows Defender Firewall (`New-NetFirewallRule`) |
| Logging | journald / syslog | Windows Event Log |

Windows provides a managed key-and-certificate infrastructure that is more structured than
Linux's file-based approach. Use it when available — it eliminates key-file sprawl, enables
TPM-backed non-exportable keys, and integrates with Active Directory for automatic trust
and enrollment.

---

## Windows Certificate Store

### Store locations

| Location | Path prefix | Use case |
|----------|-------------|----------|
| `LocalMachine` | `Cert:\LocalMachine\` | Services, daemons, anything running as SYSTEM or a service account |
| `CurrentUser` | `Cert:\CurrentUser\` | User-interactive processes, development, debugging |

**For production services, always use `LocalMachine`.** The service account must have read
access to the private key associated with the certificate.

### Logical stores

| Store name | Purpose |
|------------|---------|
| `My` | Personal certificates — the service's own TLS cert + private key |
| `Root` | Trusted root CAs — certs here are trusted as chain anchors |
| `CA` | Intermediate CAs — certs here are available for chain building |

### Management tools

| Tool | Scope | Notes |
|------|-------|-------|
| `certlm.msc` | LocalMachine | GUI — right-click → All Tasks → Import |
| `certmgr.msc` | CurrentUser | GUI — same workflow, user scope |
| `certutil` | Both | CLI — scripting-friendly, detailed output |
| PowerShell `Cert:\` drive | Both | Native cmdlets, pipeline-friendly |

### Importing certificates via PowerShell

```powershell
# Import root CA to trusted roots (machine store)
Import-Certificate -FilePath "root-ca.crt" `
    -CertStoreLocation "Cert:\LocalMachine\Root"

# Import intermediate CA
Import-Certificate -FilePath "intermediate-ca.crt" `
    -CertStoreLocation "Cert:\LocalMachine\CA"

# Import server cert + private key (PFX format) to personal store
Import-PfxCertificate -FilePath "server.pfx" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -Password (ConvertTo-SecureString -String "changeit" -AsPlainText -Force)

# List certificates in the personal store
Get-ChildItem "Cert:\LocalMachine\My" |
    Format-List Subject, Thumbprint, NotAfter, HasPrivateKey

# Find a specific certificate by subject CN
Get-ChildItem "Cert:\LocalMachine\My" |
    Where-Object { $_.Subject -match "CN=myservice" }

# Remove a certificate by thumbprint
Remove-Item "Cert:\LocalMachine\My\<THUMBPRINT>"
```

### Converting PEM to PFX

Windows cert store requires PFX (PKCS#12) for importing private keys. Convert PEM files:

```powershell
# Leaf cert + key → PFX
openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt

# Chain bundle (leaf + intermediate) + key → PFX
openssl pkcs12 -export -out server.pfx -inkey server.key -in chain.crt

# With a CA cert included in the PFX
openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt -certfile ca.crt
```

When prompted for an export password, choose a strong password. Pass it to
`Import-PfxCertificate` via the `-Password` parameter.

---

## NCrypt / CNG key storage providers

Windows CNG (Cryptography Next Generation) provides pluggable key storage providers (KSPs).
Go code does not call CNG directly — a library wraps CNG behind the `crypto.Signer`
interface.

### Available providers

| Provider | Keys stored in | Exportable? |
|----------|----------------|-------------|
| Microsoft Software Key Storage Provider | Software (DPAPI-protected files) | Yes (if marked exportable) |
| Microsoft Platform Crypto Provider | TPM hardware | No — signing happens inside TPM |
| Third-party HSM providers | Hardware Security Module | Depends on HSM policy |

### How Go interacts with CNG keys

Go's `crypto/tls` accepts any `crypto.Signer` as `tls.Certificate.PrivateKey`. A CNG
wrapper library:

1. Opens the certificate store
2. Finds the certificate by CN, thumbprint, or issuer
3. Obtains a handle to the associated CNG private key
4. Returns a `crypto.Signer` that delegates `Sign()` calls to the CNG key handle

The raw private key bytes **never leave the key provider**. This is the critical security
advantage over file-based keys.

---

## TPM-backed private keys

### What the TPM provides

- The private key is generated **inside the TPM** and never leaves it
- All signing operations (ECDSA Sign, RSA Sign) are performed by TPM hardware
- The key cannot be exported, copied, or extracted — even by local administrators
- If the machine is compromised, the attacker cannot steal the key for use elsewhere

### Go integration pattern

> **Full `certtostore` API reference:** See [certs/AGENTS.md — Certificate store operations](../mtls/certs/AGENTS.md#certificate-store-operations-certtostore)
> for `OpenWinCertStoreCurrentUser`, `Generate`, `StoreWithDisposition`,
> `CertByCommonName`, `CertKey`, and the complete enterprise PKI enrollment workflow in Go.

### Presenting the full chain

If the server or client must present an intermediate CA during the TLS handshake, include
it in the `Certificate` slice. The order is leaf first, then intermediates. The root CA
is **not** included — the peer obtains it from its own trust pool. See
[certs/AGENTS.md — Chain Bundles](../mtls/certs/AGENTS.md#chain-bundles) for the full format specification.

### Key generation via CNG

Generate TPM-backed ECDSA keys using `certtostore.Generate(GenerateOpts{EC, 256})`.
The private key exists only as a TPM key handle. See
[certs/AGENTS.md — Key generation](../mtls/certs/AGENTS.md#key-generation) for the Go API.

### Generating TPM-backed Keys for Enterprise PKI

> **Full enrollment workflow:** See
> [certs/AGENTS.md — Enterprise PKI enrollment workflow](../mtls/certs/AGENTS.md#enterprise-pki-enrollment-workflow)
> for the complete Go code: key generation → public key export → intermediate CA signing →
> `StoreWithDisposition` import → `tls.Certificate` construction.

**Key points:**
- `StoreWithDisposition` requires the **intermediate cert** (direct issuer) as its second
  argument — not the root CA. The library uses it to verify the chain and associate the
  certificate correctly in the store.
- The `tls.Certificate.Certificate` slice must include both the leaf and intermediate so
  that peers can build the full chain during the TLS handshake.
- The root CA is distributed separately (via Group Policy or manual import into
  `Cert:\LocalMachine\Root`) and is never included in the TLS handshake.

### NCrypt Container Cleanup

TPM-backed keys and their associated certificates must be cleaned up when decommissioning
a service. NCrypt containers persist until explicitly removed.

**List NCrypt containers:**

```powershell
# List all CNG key containers on the machine
certutil -key -csp "Microsoft Platform Crypto Provider"

# List software KSP containers (if using software fallback)
certutil -key -csp "Microsoft Software Key Storage Provider"
```

**Remove a specific NCrypt container:**

```powershell
# Delete a CNG key container by name
certutil -delkey -csp "Microsoft Platform Crypto Provider" "<ContainerName>"
```

**Remove certificates from the cert store:**

```powershell
# Find the certificate by CN
$cert = Get-ChildItem "Cert:\LocalMachine\My" |
    Where-Object { $_.Subject -match "CN=myservice" }

# Remove the certificate
Remove-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)"

# Verify removal
Get-ChildItem "Cert:\LocalMachine\My" |
    Where-Object { $_.Subject -match "CN=myservice" }
```

**Programmatic cleanup in Go:**

> See [certs/AGENTS.md — Cleanup](../mtls/certs/AGENTS.md#cleanup) for Go-based
> `certtostore` cleanup patterns (`DeleteKeyContainer`, `RemoveCertByCommonName`).

> **Always clean up NCrypt containers and cert store entries when decommissioning
> services.** Orphaned TPM key handles consume limited TPM storage, and stale certificates
> in the store can cause confusion during troubleshooting or accidental selection during
> TLS handshakes.

---

## File-based fallback on Windows

File-based TLS works identically to Linux. Use this approach when:
- TPM is not available (VMs without vTPM, older hardware)
- Development and testing environments
- Containerized deployments (Windows containers typically lack TPM access)

### Loading certs from files

```go
// Identical to Linux — Go's crypto/tls is platform-neutral
serverCert, err := tls.LoadX509KeyPair("certs/chain.crt", "certs/server.key")

rootPEM, err := os.ReadFile("certs/root-ca.crt")
rootCAs := x509.NewCertPool()
rootCAs.AppendCertsFromPEM(rootPEM)
```

### Protecting key files with NTFS ACLs

On Linux, `chmod 0600 server.key` restricts access. On Windows, use `icacls`:

```powershell
# Remove all inherited permissions
icacls "C:\certs\server.key" /inheritance:r

# Grant read-only to the service account
icacls "C:\certs\server.key" /grant:r "NT SERVICE\MyGoService:(R)"

# Verify permissions
icacls "C:\certs\server.key"
```

**Never leave key files with inherited permissions.** By default, files in most directories
are readable by `BUILTIN\Users` — this exposes the private key to all local users.

### Recommended directory layout

```
C:\ProgramData\MyGoService\certs\
    root-ca\
        cert.crt            ← root CA cert (readable by service account)
    server\
        chain.crt           ← leaf + intermediate bundle
        server.key          ← private key (ACL-restricted to service account)
    client-trust\
        root-ca.crt         ← root CA for client cert validation
```

Lock down the entire `certs\` directory:

```powershell
icacls "C:\ProgramData\MyGoService\certs" /inheritance:r
icacls "C:\ProgramData\MyGoService\certs" /grant:r "NT SERVICE\MyGoService:(OI)(CI)(R)"
icacls "C:\ProgramData\MyGoService\certs" /grant:r "BUILTIN\Administrators:(OI)(CI)(F)"
```

---

## Service account configuration

### Choosing a service account

| Account type | When to use |
|--------------|-------------|
| `NT SERVICE\<ServiceName>` | Default for `sc.exe`-registered services. Automatic, no password management. |
| Group Managed Service Account (gMSA) | Domain environments. AD manages the password automatically. |
| Dedicated domain user | When the service needs network resources (file shares, SQL Server). |
| `LocalSystem` | **Avoid** — overprivileged. Only if absolutely required. |
| `NetworkService` | Legacy. Prefer `NT SERVICE\` or gMSA. |

### Granting private key access (cert store)

When using the Windows cert store, the service account needs read access to the private
key container:

```powershell
# Find the certificate thumbprint
$thumb = (Get-ChildItem "Cert:\LocalMachine\My" |
    Where-Object { $_.Subject -match "CN=myservice" }).Thumbprint

# Get the private key file path
$cert = Get-Item "Cert:\LocalMachine\My\$thumb"
$keyName = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
$keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $keyName

# Grant read access to the service account
icacls $keyPath /grant "NT SERVICE\MyGoService:(R)"
```

For CNG keys (newer key storage), the key container path differs:

```powershell
# CNG keys are stored under:
# %ProgramData%\Microsoft\Crypto\Keys\
# Use certutil to find the key container name:
certutil -store My $thumb
# Look for "Key Container" in the output
```

### Required permissions summary

| Resource | Permission | Purpose |
|----------|------------|---------|
| Private key container (cert store) | Read | TLS handshake signing |
| Certificate files (if file-based) | Read | Loading certs at startup |
| Private key file (if file-based) | Read | TLS handshake signing |
| TCP port (e.g., 8443) | Listen | Accepting TLS connections |
| Event log source | Write | Logging mTLS events |

---

## Group Policy for trust distribution

In Active Directory environments, Group Policy Objects (GPOs) eliminate manual CA cert
distribution.

### Deploying root CA trust via GPO

1. Open **Group Policy Management** (`gpmc.msc`)
2. Create or edit a GPO linked to the target OU
3. Navigate to:
   **Computer Configuration → Policies → Windows Settings → Security Settings →
   Public Key Policies → Trusted Root Certification Authorities**
4. Right-click → **Import** → select the root CA certificate
5. Force update: `gpupdate /force` on target machines (or wait for next policy refresh)

After propagation, every machine in the OU trusts the root CA. Go services on those
machines can validate client certificates signed by that CA without any local cert
installation.

### Deploying intermediate CAs via GPO

Same workflow, but use:
**Public Key Policies → Intermediate Certification Authorities**

This ensures chain building works even if the TLS peer does not present the intermediate
in the handshake.

### Verifying GPO-deployed trust

```powershell
# Check that the root CA is in the machine's trusted roots
Get-ChildItem "Cert:\LocalMachine\Root" |
    Where-Object { $_.Subject -match "CN=My Root CA" }

# Verify a leaf cert chains to the GPO-deployed root
certutil -verify -urlfetch "server.crt"
```

---

## Active Directory Certificate Services (AD CS)

AD CS is Microsoft's enterprise PKI platform. When available, it eliminates manual
certificate lifecycle management.

### Key concepts

| Concept | Description |
|---------|-------------|
| Certificate Authority (CA) | Issues and signs certificates. Can be root or subordinate. |
| Certificate Template | Defines cert properties: EKU, key size, validity, auto-enrollment eligibility. |
| Auto-enrollment | GPO-driven: machines and users automatically request and renew certs. |
| Certificate Revocation List (CRL) | Published list of revoked certificates. |
| Online Responder (OCSP) | Real-time revocation checking. |

### How it integrates with Go mTLS

1. **Infrastructure team** creates server and client certificate templates in AD CS
2. **GPO** enables auto-enrollment for target machines/users
3. Certificates appear automatically in `Cert:\LocalMachine\My`
4. **Go service** finds its certificate in the store at startup (by CN or thumbprint)
5. **Certificate renewal** happens automatically before expiry

The Go application code does not interact with AD CS directly. It reads certificates from
the Windows cert store — AD CS is transparent infrastructure.

### When AD CS is not available

If AD CS is not deployed, manage certificates manually:
- Generate certs with `openssl` or Go tooling
- Distribute root CAs via GPO or manual import
- Track cert expiry with monitoring tools
- Rotate certs manually before expiry

---

## Windows Firewall considerations

### Allowing inbound mTLS connections

```powershell
# Allow inbound TCP on the mTLS server port
New-NetFirewallRule `
    -DisplayName "mTLS Server (port 8443)" `
    -Direction Inbound `
    -LocalPort 8443 `
    -Protocol TCP `
    -Action Allow `
    -Profile Domain,Private

# Verify the rule exists
Get-NetFirewallRule -DisplayName "mTLS Server*" | Format-List
```

### Restricting by remote address (defense in depth)

```powershell
# Allow only from specific subnet
New-NetFirewallRule `
    -DisplayName "mTLS Server - Restricted" `
    -Direction Inbound `
    -LocalPort 8443 `
    -Protocol TCP `
    -Action Allow `
    -RemoteAddress "10.0.0.0/8"
```

### Outbound connections

Outbound connections are **allowed by default** on Windows. If outbound filtering is
enabled, add a rule for the client:

```powershell
New-NetFirewallRule `
    -DisplayName "mTLS Client Outbound" `
    -Direction Outbound `
    -RemotePort 8443 `
    -Protocol TCP `
    -Action Allow
```

---

## Running as a Windows Service

### Using `golang.org/x/sys/windows/svc`

```go
import (
    "golang.org/x/sys/windows/svc"
    "golang.org/x/sys/windows/svc/eventlog"
)

type mtlsService struct {
    server *http.Server
}

func (s *mtlsService) Execute(
    args []string,
    req <-chan svc.ChangeRequest,
    status chan<- svc.Status,
) (bool, uint32) {
    status <- svc.Status{State: svc.StartPending}

    // Start TLS listener
    ln, err := tls.Listen("tcp", s.server.Addr, s.server.TLSConfig)
    if err != nil {
        return true, 1
    }
    go s.server.Serve(ln)

    status <- svc.Status{
        State:   svc.Running,
        Accepts: svc.AcceptStop | svc.AcceptShutdown,
    }

    // Wait for stop signal
    for c := range req {
        switch c.Cmd {
        case svc.Stop, svc.Shutdown:
            status <- svc.Status{State: svc.StopPending}
            ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
            s.server.Shutdown(ctx)
            cancel()
            return false, 0
        case svc.Interrogate:
            status <- c.CurrentStatus
        }
    }
    return false, 0
}
```

### Registering the service

```powershell
# Create the service
sc.exe create MyMTLSService `
    binPath= "C:\Program Files\MyService\myservice.exe" `
    start= auto `
    obj= "NT SERVICE\MyMTLSService" `
    DisplayName= "My mTLS Service"

# Set description
sc.exe description MyMTLSService "Go mTLS server with mutual TLS authentication"

# Set recovery options (restart on failure)
sc.exe failure MyMTLSService reset= 86400 actions= restart/5000/restart/10000/restart/30000

# Start the service
Start-Service MyMTLSService

# Check status
Get-Service MyMTLSService
```

### Service lifecycle

```
Install → sc.exe create
Start   → SCM calls Execute() → StartPending → Running
Stop    → SCM sends Stop → StopPending → server.Shutdown() → Stopped
Crash   → SCM restarts per recovery policy
```

---

## Event logging

### Setting up a Windows Event Log source

```go
import "golang.org/x/sys/windows/svc/eventlog"

// Install the event source (run once, typically during installation)
err := eventlog.InstallAsEventCreate("MyMTLSService", eventlog.Info|eventlog.Warning|eventlog.Error)

// Open the event log for writing
elog, err := eventlog.Open("MyMTLSService")
defer elog.Close()

// Log events
elog.Info(1001, "mTLS server started on :8443")
elog.Info(1002, fmt.Sprintf("Client authenticated: CN=%s, Serial=%s", clientCN, serial))
elog.Warning(2001, fmt.Sprintf("Client cert expiring soon: CN=%s, NotAfter=%s", cn, notAfter))
elog.Error(3001, fmt.Sprintf("TLS handshake failed from %s: %v", remoteAddr, err))
```

### Recommended event IDs

| ID range | Category |
|----------|----------|
| 1000–1999 | Informational — startup, shutdown, successful handshakes |
| 2000–2999 | Warnings — cert expiry approaching, deprecated TLS version |
| 3000–3999 | Errors — handshake failures, cert loading errors, bind failures |

### Extracting mTLS client identity from the connection

```go
handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
        clientCert := r.TLS.PeerCertificates[0]
        clientCN := clientCert.Subject.CommonName
        clientSerial := clientCert.SerialNumber.String()
        // Log or use for authorization decisions
        elog.Info(1002, fmt.Sprintf("Request from CN=%s, Serial=%s", clientCN, clientSerial))
    }
    w.WriteHeader(http.StatusOK)
})
```

### Viewing event logs

```powershell
# View recent events from the service
Get-EventLog -LogName Application -Source "MyMTLSService" -Newest 20

# Filter by event ID
Get-EventLog -LogName Application -Source "MyMTLSService" |
    Where-Object { $_.EventID -eq 3001 }
```

---

## Troubleshooting

### Diagnostic tools

| Tool | Purpose | Example |
|------|---------|---------|
| `certlm.msc` | GUI cert store viewer (machine store) | Inspect cert properties, chain status |
| `certutil -store My` | List certs in personal store | Check thumbprint, expiry, key provider |
| `certutil -verify -urlfetch cert.crt` | Verify certificate chain | Identifies broken chain links |
| `certutil -store My <thumbprint>` | Show cert details + key info | Confirms private key is accessible |
| `netsh http show sslcert` | Show HTTP.sys SSL bindings | Not used by Go directly, but useful for diagnostics |
| `Test-NetConnection -ComputerName localhost -Port 8443` | Test TCP connectivity | Confirms port is reachable |
| `openssl s_client -connect localhost:8443` | Test TLS handshake (one-way) | Shows server cert chain |
| `openssl s_client -connect localhost:8443 -cert client.crt -key client.key` | Test mTLS handshake | Verifies mutual authentication |
| `netstat -ano \| findstr :8443` | Find process using a port | Identifies port conflicts |
| `Get-Process -Id <PID>` | Identify process by PID | Follow up from `netstat` output |

### Common errors and fixes

#### "certificate unknown" or "unknown certificate authority"

**Cause:** The client certificate is not trusted by the server (or vice versa).

**Fix:**
- Verify the root CA cert is in the server's `ClientCAs` pool
- If using cert store trust: check `Cert:\LocalMachine\Root` contains the root CA
- If using file-based trust: verify the root CA PEM file is correct and readable
- Check chain: `certutil -verify -urlfetch client.crt`

#### "access denied" on private key

**Cause:** The service account lacks read permission on the key container.

**Fix:**
```powershell
# Find the key container
$cert = Get-Item "Cert:\LocalMachine\My\<THUMBPRINT>"
$keyName = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
$keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $keyName

# Grant read access
icacls $keyPath /grant "NT SERVICE\MyGoService:(R)"
```

#### "certificate has expired"

**Cause:** The leaf, intermediate, or root CA cert has passed its `NotAfter` date.

**Fix:**
```powershell
# Check all certs in the chain
Get-ChildItem "Cert:\LocalMachine\My" |
    Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) } |
    Format-List Subject, NotAfter
```

Renew or reissue expired certificates. If using AD CS auto-enrollment, trigger a refresh:
`certutil -pulse`

#### Port conflict

**Cause:** Another process is already listening on the mTLS port.

**Fix:**
```powershell
netstat -ano | findstr :8443
# Note the PID, then identify the process:
Get-Process -Id <PID> | Format-List Name, Path
```

#### TLS handshake timeout

**Cause:** Firewall blocking the connection, or the server is not listening.

**Fix:**
```powershell
# Test connectivity
Test-NetConnection -ComputerName localhost -Port 8443

# Check firewall rules
Get-NetFirewallRule -Direction Inbound |
    Where-Object { $_.Enabled -eq 'True' } |
    Get-NetFirewallPortFilter |
    Where-Object { $_.LocalPort -eq 8443 }
```

#### "tls: bad certificate" from the server

**Cause:** The client presented a cert but it failed validation — wrong issuer, expired,
or missing required EKU.

**Fix:**
- Verify the client cert has `ExtKeyUsageClientAuth`
- Verify the client cert is signed by a CA in the server's `ClientCAs` pool
- Check the full chain: leaf → intermediate → root

#### "certificate signed by unknown authority" with enterprise PKI

**Cause:** The intermediate CA certificate is missing from the TLS chain. The peer cannot
build the path from leaf to root because the intermediate is not presented during the
handshake and is not in the peer's local store.

**Fix:**
- Ensure `tls.Certificate.Certificate` includes **both** the leaf cert and the
  intermediate cert (direct issuer):
  ```go
  tlsCert.Certificate = [][]byte{leafCert.Raw, intermediateCert.Raw}
  ```
- Verify the intermediate is correct: `certutil -verify -urlfetch leaf.crt`
- If using `StoreWithDisposition`, confirm the intermediate cert was passed as the second
  argument during import
- Check that the root CA is in the peer's trust pool (`Cert:\LocalMachine\Root` or
  `ClientCAs` / `RootCAs` in `tls.Config`)

#### Service fails to start

**Cause:** Multiple possible — cert not found, port in use, permission denied.

**Fix:**
```powershell
# Check Windows Event Log for the service
Get-EventLog -LogName Application -Source "MyMTLSService" -Newest 10

# Check System log for service control manager errors
Get-EventLog -LogName System -Source "Service Control Manager" -Newest 10 |
    Where-Object { $_.Message -match "MyMTLSService" }
```

---

## Certificate rotation checklist

When rotating certificates in a running Windows service:

1. **Generate or obtain** the new certificate and key
2. **Import** the new cert to the cert store (or deploy new files)
3. **Verify** the new cert chains correctly: `certutil -verify -urlfetch new-cert.crt`
4. **Grant** private key access to the service account
5. **Restart** the service: `Restart-Service MyMTLSService`
6. **Verify** the service is using the new cert:
   `openssl s_client -connect localhost:8443 | openssl x509 -noout -dates -subject`
7. **Remove** the old certificate from the store (after confirming the new one works)

For zero-downtime rotation, implement hot-reload in the Go service using
`tls.Config.GetCertificate` or `tls.Config.GetConfigForClient` callbacks that read the
latest cert from the store on each handshake.

---

## Security checklist

- ✅ Use TPM-backed keys when hardware supports it (non-exportable)
- ✅ Use `LocalMachine` cert store for services (not `CurrentUser`)
- ✅ Run service as `NT SERVICE\<Name>` or gMSA (not `LocalSystem`)
- ✅ Grant minimal private key permissions (read-only to service account)
- ✅ Remove inherited NTFS permissions on key files (if file-based)
- ✅ Set `MinVersion: tls.VersionTLS12` on every `tls.Config`
- ✅ Require client certs: `ClientAuth: tls.RequireAndVerifyClientCert`
- ✅ Use separate EKU: `ServerAuth` for servers, `ClientAuth` for clients
- ✅ Distribute root CA trust via Group Policy (not manual copy)
- ✅ Set server timeouts: `ReadTimeout`, `WriteTimeout`, `IdleTimeout`
- ✅ Use `server.Shutdown(ctx)` for graceful shutdown
- ✅ Log mTLS events to Windows Event Log
- ✅ Monitor certificate expiry and alert before `NotAfter`
- ✅ Restrict firewall rules to required ports and source addresses
- ✅ Use ECDSA P-256 for new key pairs (prefer over RSA)
- ✅ Use enterprise TPM-backed keys with intermediate CA chain bundles
- ✅ Clean up NCrypt containers and cert store entries when decommissioning
- ✅ Include intermediate cert (direct issuer) when importing to cert store

# Chapter 4: Production guidance and configuration direction

Back to [docs index](index.md)

The repo demonstrates the mechanics correctly, but production systems usually need stronger PKI and stronger storage choices than a teaching demo.

This chapter documents the direction the repo teaches for production readiness.

## Use an intermediate CA for leaf issuance

For production-oriented mTLS, the better model is:

```text
Offline or externally managed root CA
            |
            v
    Issuing intermediate CA
       |               |
       v               v
  Server leaf      Client leaf
```

Why this matters:

- the root CA is not used directly for routine leaf issuance
- intermediate rotation is easier
- compromise blast radius is smaller
- policy and trust management become cleaner

The `mtlsenterprise` and `mtlsenterprisetpm` scenarios implement this model. They use `cert.CreateRootCA` → `SignIntermediateFunc` → `ProfiledSignerFunc` to build the full hierarchy, with role-specific EKU (ServerAuth / ClientAuth) and DNS SANs on server certificates. Chain bundles (leaf + intermediate) are written to disk for TLS presentation.

The earlier scenarios (`tlsmem`, `mtlsmem`, `tlsfiles`, `mtlsfiles`, `mtlstpm`) use a single CA for simplicity. That is a useful teaching simplification, not the PKI topology to copy unchanged into production — use `mtlsenterprise` or `mtlsenterprisetpm` as the production PKI reference.

## Treat file-based server keys as development and test defaults

The current file-based scenarios are good examples for:

- learning
- local development
- test automation
- showing ownership boundaries

But long-term guidance should teach more than flat PEM files for server identity.

### Recommended server identity options

| Option | Best fit | Pros | Cons |
| --- | --- | --- | --- |
| Files | local dev, tests, disposable demos | simplest setup, easiest automation, easiest debugging | weakest secret hygiene, exportable key material |
| Windows certificate store | Windows-hosted services | native OS-managed identity, better key handling than flat files | Windows-only, service identity and store permissions matter |
| Azure Key Vault | cloud-hosted services | centralized control, auditing, managed rotation patterns, HSM-backed options | operational complexity, Azure dependency, identity and RBAC setup |

The repo should keep file-based server identity for testing and teaching, while documenting and eventually implementing stronger storage options.

## Make the client autonomous after enrollment

The `mtlstpm` scenario already points in the right direction: at runtime, the client does not depend on the original in-memory signer. It rediscovers the certificate in the store and derives a signing key handle from it.

That is the model the repo should keep teaching:

- enrollment creates or rotates identity
- runtime discovers the current certificate
- runtime signs through a stable interface such as `crypto.Signer`

For stronger production guidance, the repo should prefer stable runtime lookup identifiers such as:

- thumbprint
- subject key identifier
- explicit certificate labels

Using Common Name lookup is understandable in a demo, but it is too weak as the only long-term identity selection strategy.

## Make CA changes an operational trust problem

The prompt requirement that intermediate-CA changes should not break authentication is best read like this:

- application code should not need to change
- runtime certificate selection should stay stable
- trust bundles and issued leaf certificates may change
- rollout should be handled operationally

That means the repo should eventually teach this rollout pattern:

1. trust the new intermediate before switching issuance
2. allow old and new intermediates during a migration window
3. renew leaves under the new intermediate
4. retire the old intermediate only after convergence

## Current configuration shape in the repo

Today, `configs/mtlstpm` is intentionally simple:

```toml
[ca]
cn        = "go mTLS TPM Demo CA"
cert_file = "certs/mtlstpm/ca/cert.crt"
validity  = "24h"

[server]
address      = "127.0.0.1:8445"
cn           = "go mTLS TPM Demo Server"
cert_file    = "certs/mtlstpm/server/server.crt"
key_file     = "certs/mtlstpm/server/server.key"
ca_cert_file = "certs/mtlstpm/server/ca.crt"

[client]
cn        = "go mTLS TPM Demo Client"
container = "go-mtls-demo-client"

[client.store]
location          = "CurrentUser"
provider_override = ""
```

That works for the current demo, but it does not yet express the production-oriented choices the docs should teach.

## Configuration direction to aim for

A future-friendly configuration shape should make identity sources and trust sources explicit:

```toml
[ca.intermediate]
cn        = "go mTLS Demo Intermediate CA"
cert_file = "certs/mtls/ca/intermediate.crt"
validity  = "720h"

[server]
address = "127.0.0.1:8445"
cn      = "go mTLS Demo Server"

[server.identity]
kind = "file" # file | windows_store | azure_key_vault

[server.identity.file]
cert_file = "certs/mtls/server/server.crt"
key_file  = "certs/mtls/server/server.key"

[server.identity.windows_store]
location   = "LocalMachine"
store_name = "My"
thumbprint = ""

[server.identity.azure_key_vault]
vault_url        = "https://example.vault.azure.net/"
certificate_name = "mtls-server"
certificate_ver  = ""

[server.trust]
client_issuer_bundle = "certs/mtls/server/client-issuers.pem"

[client]
cn        = "go mTLS Demo Client"
container = "go-mtls-demo-client"

[client.store]
location          = "CurrentUser"
provider_override = ""

[client.identity]
lookup_kind  = "thumbprint" # thumbprint | subject_cn | subject_key_id
lookup_value = ""

[client.trust]
server_issuer_source = "windows_store" # windows_store | file
store_location       = "CurrentUser"
store_name           = "CA"
subject_cn           = "go mTLS Demo Intermediate CA"
```

This is not current code. It is a useful target shape for the docs because it makes three things explicit:

- where the server gets its identity
- where the server gets its trust for validating clients
- how the client finds its identity and trust at runtime

## Windows Server deployment considerations

Moving from a learning demo to a Windows-hosted service means choosing the right service identity, certificate store, key protection, and trust distribution strategy. This section maps each decision to the repo's scenarios and shows how the patterns generalize.

### Service account identity

Windows services run under a security principal. The choice matters because it controls access to the certificate store and private keys.

| Identity | Cert store access | Private key access | Recommendation |
| --- | --- | --- | --- |
| `LocalSystem` | Full `LocalMachine` access | All keys | Too broad for most services — avoid unless required |
| `NetworkService` | Read `LocalMachine` with ACLs | Only keys explicitly ACL'd | Reasonable for simple services |
| `Local Service` | Limited | Only keys explicitly ACL'd | Least privilege, limited network access |
| **gMSA** (Group Managed Service Account) | Read `LocalMachine` with ACLs | Only keys explicitly ACL'd | **Enterprise recommendation** — no password management, AD-managed rotation |

A gMSA (Group Managed Service Account) is the strongest choice for services that need cert store access. Active Directory manages the password automatically, so there is no service account password to store, rotate, or leak. The service still needs explicit private key ACLs — gMSA does not bypass that requirement.

### Certificate store locations

Windows organizes certificates into stores by purpose and scope.

| Store path | Typical use | Who can access |
| --- | --- | --- |
| `LocalMachine\My` | Server certificates for services | Services running as `LocalSystem`, or other identities with explicit ACLs |
| `CurrentUser\My` | Per-user certificates, interactive testing | The logged-in user only |
| `LocalMachine\Root` | Trusted root CAs (machine-wide) | All processes on the machine |
| `LocalMachine\CA` | Intermediate CAs (machine-wide) | All processes on the machine |

**When to use each:**

- Use `LocalMachine\My` for a Windows service that needs to present a server certificate or a client certificate for outbound mTLS. The service identity (gMSA, NetworkService, etc.) must have read access to the private key — this is not granted by default.
- Use `CurrentUser\My` for interactive testing and development. The repo's `mtlstpm` demo uses this store because the demo runs interactively, not as a service.
- Use `LocalMachine\Root` to trust a CA machine-wide. Adding a cert here means every process trusts it — only add your own organizational CAs, not arbitrary third-party roots.
- Use `LocalMachine\CA` to distribute intermediate CAs. This helps chain-building when a leaf certificate does not include the full chain.

**ACL implications:** Placing a certificate in `LocalMachine\My` does not automatically grant any service access to its private key. You must explicitly grant read permission to the service identity. See the "File ACLs vs cert store ACLs" section below.

### Key storage providers

Windows CNG (Cryptography Next Generation) uses key storage providers (KSPs) to manage private key material.

| Provider | Key location | Exportable? | Hardware needed? |
| --- | --- | --- | --- |
| **Microsoft Platform Crypto Provider** | TPM 2.0 chip | No — hardware-bound | Yes, TPM 2.0 |
| **Microsoft Software Key Storage Provider** | Software (NCrypt) | Configurable — default non-exportable | No |
| Legacy CSPs (e.g. Microsoft Strong Cryptographic Provider) | Software (CryptoAPI) | Configurable | No |

**The repo's `mtlstpm` demo auto-detects between the first two.** It prefers the TPM provider when available and falls back to the software KSP. This is controlled by `internal/pwsh.CheckTPM()` and the `provider_override` config field. See `internal/scenarios/mtlstpm/demo.go` for the detection logic.

Legacy CSPs are not recommended for new implementations. They use older CryptoAPI interfaces and do not support modern elliptic-curve key types.

For production, prefer the Platform Crypto Provider (TPM) when the hardware is available. It gives you non-exportable keys bound to the physical machine — even an administrator cannot extract the private key material.

### File ACLs vs cert store ACLs

Both file-based and cert-store-based deployments need access control on private key material. The mechanisms differ.

**File-based (repo patterns `mtlsfiles`, `tlsfiles`):**

Restrict `.key` files to the service account only:

```powershell
# Remove inherited permissions and grant read-only to the service account
icacls "C:\app\certs\server\server.key" /inheritance:r
icacls "C:\app\certs\server\server.key" /grant "DOMAIN\svc-myapp:(R)"
icacls "C:\app\certs\server\server.key" /grant "BUILTIN\Administrators:(R)"
```

File-based ACLs are straightforward but the key material is a regular file on disk — any process or user with read access can copy it.

**Cert store (repo pattern `mtlstpm`):**

Grant private key access to the service identity using `certutil` or the Certificates MMC snap-in:

```powershell
# Find the certificate thumbprint
certutil -store My "go mTLS TPM Demo Client"

# Grant private key read access to the service account
# (certutil -repairstore updates ACLs on the key container)
certutil -repairstore My "<thumbprint>"
```

For the MMC approach: open `certlm.msc` (Local Machine) or `certmgr.msc` (Current User), right-click the certificate → All Tasks → Manage Private Keys, and add the service identity with Read permission.

**Cert store ACLs are generally stronger** because the private key material stays inside NCrypt (or the TPM). Even with read access, the caller can only use the key for signing operations through the CNG API — it cannot extract the raw key bytes (assuming non-exportable keys).

### Trust distribution in enterprise environments

The repo's current pattern — loading a CA PEM file from disk — works well for development and for systems where you control all endpoints. Enterprise environments need broader distribution.

| Method | Scale | Automation | Repo relevance |
| --- | --- | --- | --- |
| Manual (`certutil`, PowerShell) | Small | None | Development and testing |
| Group Policy (GPO) | Domain-joined machines | Full | Enterprise Windows environments |
| SCCM / Intune | Managed endpoints (including non-domain) | Full | Mixed or cloud-managed fleets |
| Per-application file loading | Any | Application-managed | **Current repo pattern** |

**Manual distribution:**

```powershell
# Import a CA certificate into the machine trusted root store
Import-Certificate -FilePath ".\certs\mtlsfiles\ca\cert.crt" `
    -CertStoreLocation "Cert:\LocalMachine\Root"

# Equivalent using certutil
certutil -addstore Root ".\certs\mtlsfiles\ca\cert.crt"
```

**Group Policy distribution:** In Active Directory environments, use the Group Policy Management Console to push root and intermediate CAs to all domain-joined machines via Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies → Trusted Root Certification Authorities. This is the standard enterprise approach and ensures every machine trusts the CA without per-machine manual steps.

**SCCM/Intune:** For managed endpoints that may not be domain-joined (remote workers, cloud-only machines), use SCCM compliance baselines or Intune configuration profiles to push CA certificates. Intune supports PKCS and SCEP certificate profiles.

**Per-application (current repo pattern):** The repo loads trust bundles from PEM files at runtime. This is portable and works on any OS, but requires you to distribute the CA file alongside the application. It is the right default for a cross-platform Go service and works well inside containers (see the Azure section below).

### Windows Firewall and port binding

**`netsh http add sslcert` is NOT needed** when the Go server manages TLS itself. All repo scenarios (including `mtlstpm`) use Go's `crypto/tls` package to handle the TLS handshake directly. The `netsh` SSL certificate binding is only needed for HTTP.sys-backed servers (IIS, some .NET HttpListener configurations).

If you deploy the repo's Go server as a Windows service, you only need a firewall rule:

```powershell
# Allow inbound traffic on the mTLS port
New-NetFirewallRule -DisplayName "go-mtls-demo" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 8445 `
    -Action Allow `
    -Profile Domain,Private

# For stricter security, restrict to known client IP ranges
New-NetFirewallRule -DisplayName "go-mtls-demo (restricted)" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 8445 `
    -Action Allow `
    -RemoteAddress "10.0.1.0/24","10.0.2.0/24" `
    -Profile Domain
```

### Mapping repo scenarios to Windows deployment

| Repo scenario | Windows deployment model | Key storage | Trust source |
| --- | --- | --- | --- |
| `mtlsfiles` | Windows service loading PEM files from disk | Software file on disk (weakest) | CA PEM file on disk |
| `mtlstpm` | Interactive demo with TPM-backed client key | TPM or Software KSP (strongest) | CA PEM file on disk + Windows cert store |
| Future `mtlstpmserverstore` | Windows service with server cert in cert store, client cert in TPM | Cert store + TPM | Windows cert store for trust |

The `mtlsfiles` → Windows service path is the simplest migration: deploy the PEM files alongside the binary, restrict file ACLs, and run the service under a gMSA. The `mtlstpm` pattern currently covers client-side identity only. A future `mtlstpmserverstore` scenario could demonstrate server identity from the Windows cert store, eliminating PEM files for the server side as well — this is not yet implemented.

## Azure container deployment considerations

Containers in Azure follow different patterns for certificate management than Windows services. The fundamental challenge is the same — get certificates and keys into the process securely — but the mechanisms are container-native: volume mounts, secrets, managed identity, and Key Vault.

### Two deployment models

| Model | Best for | Cert management options |
| --- | --- | --- |
| **Azure Container Instances (ACI)** | Single containers, simple deployments, sidecar patterns | Key Vault volume mounts, Azure File Shares, environment variables |
| **Azure Kubernetes Service (AKS)** | Orchestrated workloads, fleet management, cert-manager integration | CSI SecretStore driver, Kubernetes Secrets, cert-manager, init containers |

AKS gives you more options for automated certificate lifecycle. ACI is simpler but requires more manual orchestration for renewal.

### Certificate injection patterns

From most to least recommended for production:

#### 1. AKS + CSI SecretStore driver + Azure Key Vault provider (recommended)

The Secrets Store CSI driver mounts Key Vault secrets as files in the pod filesystem. Your Go code loads certs exactly like the `mtlsfiles` scenario — `tls.LoadX509KeyPair` and `os.ReadFile` work unchanged.

```yaml
# SecretProviderClass — tells the CSI driver what to fetch
apiVersion: secrets-store.csi.x]8s.io/v1
kind: SecretProviderClass
metadata:
  name: mtls-certs
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "true"
    userAssignedIdentityID: "<managed-identity-client-id>"
    keyvaultName: "my-keyvault"
    objects: |
      array:
        - |
          objectName: mtls-server-cert
          objectType: secret    # "secret" returns the full PFX/PEM bundle
        - |
          objectName: mtls-ca-bundle
          objectType: secret
    tenantId: "<tenant-id>"
```

```yaml
# Pod spec — mount the secrets as files
spec:
  containers:
    - name: mtls-server
      volumeMounts:
        - name: certs
          mountPath: "/certs"
          readOnly: true
  volumes:
    - name: certs
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: "mtls-certs"
```

The Go server then loads `/certs/mtls-server-cert` and `/certs/mtls-ca-bundle` — the same file-loading code as `mtlsfiles`. The CSI driver handles renewal by updating the mounted files when Key Vault content changes.

#### 2. AKS Kubernetes Secrets

Store certificates in Kubernetes Secrets and mount them as volumes:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mtls-server-certs
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
  ca.crt: <base64-encoded-ca>
```

Simpler to set up than the CSI driver, but secrets are stored in etcd (encrypted at rest if configured, but still broader access than Key Vault). Acceptable for non-production or when Key Vault is not available.

#### 3. ACI volume mounts

ACI can mount Azure Key Vault secrets as volumes in a container group:

```bash
# Create container group with Key Vault secret volume
az container create \
    --resource-group myRG \
    --name mtls-server \
    --image myregistry.azurecr.io/mtls-server:latest \
    --ports 8445 \
    --secrets-mount-path /certs \
    --secrets mtls-server-cert="$(az keyvault secret show \
        --vault-name my-keyvault \
        --name mtls-server-cert \
        --query value -o tsv)"
```

ACI also supports Azure File Share mounts if you prefer to manage cert files directly.

#### 4. Runtime fetch from Key Vault

The Go application uses the Azure SDK to fetch certificates at startup:

```go
// Conceptual pattern — not implemented in the repo
// Uses azidentity + azcertificates packages
cred, err := azidentity.NewDefaultAzureCredential(nil)
client, err := azcertificates.NewClient("https://my-keyvault.vault.azure.net/", cred, nil)
certBundle, err := client.GetCertificate(ctx, "mtls-server-cert", "", nil)
// Parse certBundle into tls.Certificate...
```

This is the most flexible approach but adds an Azure SDK dependency. It is useful when you need runtime logic (e.g., selecting different certs per tenant). A future `mtlsazurekv` scenario could demonstrate this pattern — it is not yet implemented in the repo.

#### 5. Build-time baking — never for private keys

You can bake public CA certificates into the container image for trust distribution. **Never bake private keys into images.** Container image layers are not secret — anyone with pull access to the registry can extract every file from every layer. This includes intermediate layers from multi-stage builds unless the key was in a stage that was discarded.

```dockerfile
# Acceptable: bake the CA trust bundle
COPY certs/ca-bundle.crt /app/certs/ca-bundle.crt

# NEVER do this:
# COPY certs/server.key /app/certs/server.key
```

### Azure Key Vault integration

Key Vault stores certificates as composite objects containing both the certificate chain and the private key. This simplifies management but requires understanding the download format.

**Key concepts:**

- A Key Vault "certificate" is really three objects: the certificate (public), the key (private), and a secret (the combined PFX or PEM bundle).
- To get both cert and key in a single download, fetch the **secret** (not the certificate object). The secret contains the full PFX or PEM bundle.
- The CSI driver uses the secret path by default, which is why it works seamlessly with Go's `tls.LoadX509KeyPair`.

**Key Vault references in ACI** are defined in the container group ARM template or Bicep:

```bash
# Create a Key Vault certificate
az keyvault certificate create \
    --vault-name my-keyvault \
    --name mtls-server-cert \
    --policy @cert-policy.json

# Grant the container's managed identity access
az keyvault set-policy \
    --name my-keyvault \
    --object-id <managed-identity-principal-id> \
    --secret-permissions get
```

A future `mtlsazurekv` scenario in the repo could demonstrate end-to-end Key Vault integration. The current file-based patterns (`mtlsfiles`) transfer directly — Key Vault just replaces the file source.

### Managed Identity

Managed Identity eliminates the need to store credentials for accessing Key Vault or other Azure resources. This is critical for zero-credential deployments.

| Type | Lifecycle | Sharing | Best for |
| --- | --- | --- | --- |
| System-assigned | Tied to the resource (deleted when resource is deleted) | Not shareable | Simple, single-resource deployments |
| User-assigned | Independent lifecycle | Shareable across resources | Multi-resource deployments, portability |

**RBAC roles for Key Vault access:**

| Role | Grants | Use when |
| --- | --- | --- |
| `Key Vault Secrets User` | Read secrets (cert + key bundles) | Service needs to load certificates at runtime |
| `Key Vault Certificate User` | Read certificate public portion only | Service only needs the public cert (trust verification) |
| `Key Vault Certificates Officer` | Full certificate management | Enrollment or rotation automation |

```bash
# Assign Key Vault Secrets User to a managed identity
az role assignment create \
    --role "Key Vault Secrets User" \
    --assignee <managed-identity-principal-id> \
    --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>
```

**No secrets in environment variables or config files.** Managed Identity works through the Azure Instance Metadata Service (IMDS) — the token is acquired at runtime without any stored credential. The Go `azidentity.NewDefaultAzureCredential()` or `azidentity.NewManagedIdentityCredential()` handles this transparently.

### Certificate renewal in containers

Containers add a complication: the filesystem is ephemeral and the process may not be long-lived. Renewal patterns differ from traditional servers.

**Short-lived certificates + cert-manager (AKS):**

cert-manager on AKS can issue short-lived certificates (hours or days) and automatically renew them. Combined with the CSI driver, the renewed cert appears as an updated file in the pod. The Go server picks it up on the next TLS handshake if it uses the `GetCertificate` callback:

```go
// Pattern for automatic certificate reload — not yet in the repo
tlsConfig := &tls.Config{
    GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
        // Reload from disk on each handshake (or cache with file-watcher)
        cert, err := tls.LoadX509KeyPair("/certs/tls.crt", "/certs/tls.key")
        if err != nil {
            return nil, fmt.Errorf("loading refreshed cert: %w", err)
        }
        return &cert, nil
    },
}
```

In production, you would add caching and a file watcher rather than reading from disk on every handshake.

**Key Vault auto-renewal + rolling update:**

Key Vault can auto-renew certificates issued by integrated CAs (DigiCert, GlobalSign). When the certificate renews, trigger a rolling restart of the pods (or rely on the CSI driver to update the mounted files).

**File-watcher pattern:**

For long-running Go servers, watch the cert files and reload when they change. The `crypto/tls.Config.GetCertificate` callback makes this possible without restarting the process. This is especially useful with the CSI driver, which updates files in-place when Key Vault content changes.

### Network security for mTLS containers

mTLS provides authentication at the transport layer, but network-level controls are still essential for defense in depth.

**Private endpoints for Key Vault:**

Never expose Key Vault to the public internet. Use a private endpoint so that Key Vault traffic stays within the Azure virtual network:

```bash
az network private-endpoint create \
    --name kv-pe \
    --resource-group myRG \
    --vnet-name myVNet \
    --subnet endpoints \
    --private-connection-resource-id <keyvault-resource-id> \
    --group-id vault \
    --connection-name kv-connection
```

**VNet integration:**

- AKS clusters should use Azure CNI for full VNet integration.
- ACI supports VNet deployment for container groups that need private networking.

**NSG rules:**

Restrict the mTLS port to known client address ranges:

```bash
az network nsg rule create \
    --resource-group myRG \
    --nsg-name myNSG \
    --name allow-mtls \
    --priority 100 \
    --destination-port-ranges 8445 \
    --source-address-prefixes "10.0.1.0/24" "10.0.2.0/24" \
    --access Allow \
    --protocol Tcp
```

**TLS termination vs end-to-end mTLS:**

Azure Front Door and Application Gateway can terminate TLS at the edge. This simplifies certificate management (one cert on the gateway) but means the connection between the gateway and your container is a separate TLS session.

- **Edge termination + backend TLS:** Gateway terminates client TLS, re-encrypts to the backend. Client identity (mTLS) is lost unless the gateway forwards the client certificate in a header (Application Gateway supports this via `X-ARR-ClientCert`).
- **End-to-end mTLS (passthrough):** Gateway passes the TCP connection through without terminating TLS. The Go server handles the full mTLS handshake. This preserves true mutual authentication but means each backend must have its own certificate and trust configuration.

For services where the client certificate identity matters for authorization (not just authentication), prefer end-to-end mTLS passthrough.

### Health and readiness probes

Kubernetes and ACI use probes to decide when a container is ready to receive traffic. With mTLS servers, probe configuration needs thought.

**The problem:** If your server only listens on an mTLS port, the kubelet (which sends probe requests) would need a client certificate to connect. Kubelets do not carry application client certs.

**Recommended approach — separate health port:**

```go
// Conceptual pattern — not yet in the repo
// Start a plaintext HTTP health endpoint on a separate port
go func() {
    mux := http.NewServeMux()
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
        // Check that TLS certs are loaded and listener is ready
        if certsLoaded && tlsListenerReady {
            w.WriteHeader(http.StatusOK)
            return
        }
        w.WriteHeader(http.StatusServiceUnavailable)
    })
    http.ListenAndServe(":8080", mux)
}()
```

```yaml
# Kubernetes probe configuration
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 3
  periodSeconds: 5
```

**Key points:**

- **Liveness probe:** Is the process alive? A simple HTTP 200 on the health port.
- **Readiness probe:** Is the server ready to accept mTLS traffic? Check that certificates are loaded and the TLS listener is bound. Do not mark the pod ready before certs are loaded — this avoids client errors during startup.
- The health port should only be accessible within the cluster (not exposed via the load balancer or ingress).

### Mapping repo scenarios to Azure deployment

| Repo scenario | Azure deployment model | Certificate source | Trust source |
| --- | --- | --- | --- |
| `mtlsfiles` | AKS pod with CSI SecretStore driver | Key Vault → mounted PEM files | Key Vault → mounted CA bundle |
| `mtlsfiles` | ACI with Key Vault volume | Key Vault → mounted PEM files | Key Vault → mounted CA bundle |
| Future `mtlsazurekv` | AKS or ACI with runtime Key Vault fetch | Azure SDK → Key Vault at startup | Azure SDK → Key Vault at startup |

The `mtlsfiles` scenario is the most natural fit for containerized deployment. Its file-loading pattern maps directly to volume-mounted secrets from Key Vault. The Go code does not change — only the source of the files changes from local disk to a CSI-mounted volume.

A future `mtlsazurekv` scenario could demonstrate the runtime-fetch pattern where the Go application uses the Azure SDK to pull certificates from Key Vault at startup, parse them into `tls.Certificate`, and configure the TLS listener programmatically. This is not yet implemented in the repo.

Previous: [Chapter 3 - Scenario patterns and what to copy](03-scenario-patterns.md)

Next: [Chapter 5 - Security, testability, and rotation](05-security-testability-and-rotation.md)

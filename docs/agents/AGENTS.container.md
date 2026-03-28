# AGENTS.container.md — Deploying mTLS Go Services in Containers (Azure)

> **Parent:** [AGENTS.mtls.md](AGENTS.mtls.md) — mTLS concepts and architecture
> **Layer:** Infrastructure
> **Related:** [AGENTS.certs.md](AGENTS.certs.md) (certificate format) · [AGENTS.operator.md](AGENTS.operator.md) (PKI workflows) · [AGENTS.server.md](AGENTS.server.md) · [AGENTS.client.md](AGENTS.client.md)

> **Audience:** AI coding agent deploying a Go mTLS application in containers on Azure (AKS, ACI).
> This guide covers infrastructure-specific deployment patterns. For certificate
> domain logic see [AGENTS.certs.md](AGENTS.certs.md).

---

## Rule #1: Never Bake Private Keys into Container Images

Container image layers are content-addressable and immutable. Anyone with pull access
to the registry can extract every layer — including layers you thought you "deleted."

- **Multi-stage builds do not help.** If you `COPY server.key` in a build stage, that
  layer exists in the build image. If the build image is ever pushed (or cached in a
  shared registry), the key is exposed.
- **`docker history --no-trunc`** reveals every instruction and layer hash. Deleting a
  file in a later `RUN` layer only hides it from the final filesystem — the prior layer
  still contains the original bytes.
- **OCI and Docker registries** serve layers independently. An attacker does not need
  `docker pull`; a single HTTP GET to the blob endpoint extracts a layer.

**What is safe to include in images:**

- Public CA bundles (e.g., `/etc/ssl/certs/ca-certificates.crt`), though even these are
  better mounted at runtime so you can rotate trust anchors without rebuilding.
- Application binaries, static assets, configuration templates.

**What must never be in an image:**

- Private keys (server, client, or CA).
- PFX / PKCS#12 files containing private keys.
- Tokens, passwords, connection strings.

---

## Certificate Injection Patterns

Approaches ordered from simplest to most robust. Choose based on your operational
maturity and security requirements.

### 1. Kubernetes Secrets (base64 PEM, mounted as files)

The simplest option. Store PEM-encoded certificates and keys in a Kubernetes Secret,
mount them as files in the pod.

```bash
kubectl create secret tls mtls-server-cert \
    --cert=chain.crt --key=server.key

kubectl create secret generic mtls-ca-bundle \
    --from-file=root-ca.crt=root-ca.crt
```

**Limitations:** Secrets are base64-encoded (not encrypted at rest by default). Anyone
with RBAC access to the namespace can read them. Enable etcd encryption at rest and
restrict RBAC tightly.

### 2. Azure Key Vault + Secrets Store CSI Driver (preferred for AKS)

Key Vault stores certificates centrally with audit logging, RBAC, and optional
HSM-backed keys. The CSI driver projects them as files into pods — no code changes.

### 3. ACI Volume Mounts from Key Vault

Azure Container Instances support secret volumes directly in the container group
definition. Simpler than AKS — no CSI driver needed.

### 4. Init Containers That Fetch Certs at Startup

An init container runs before the main container, fetches certs from Key Vault (or
another source), writes them to a shared `emptyDir` volume. The main container reads
from that volume.

### 5. cert-manager for Automated Issuance and Rotation

cert-manager is a Kubernetes-native certificate lifecycle manager. It issues
certificates from your internal CA (or ACME, HashiCorp Vault, etc.), stores them in
Kubernetes Secrets, and renews them automatically before expiry.

> **Enterprise PKI note:** When using the Secrets Store CSI driver with an enterprise
> PKI that issues certificates from an intermediate CA, store the leaf certificate and
> intermediate CA certificate as **separate** Key Vault secrets. This gives you
> independent rotation control — you can re-issue leaf certs without touching the
> intermediate, or rotate the intermediate without modifying leaf-cert entries.
>
> ```yaml
> apiVersion: secrets-store.csi.x-k8s.io/v1
> kind: SecretProviderClass
> metadata:
>   name: mtls-enterprise-certs
> spec:
>   provider: azure
>   parameters:
>     usePodIdentity: "false"
>     useVMManagedIdentity: "true"
>     userAssignedIdentityID: "<managed-identity-client-id>"
>     keyvaultName: "myVault"
>     objects: |
>       array:
>         - |
>           objectName: server-leaf-cert
>           objectType: secret
>           objectAlias: leaf.crt
>         - |
>           objectName: intermediate-ca-cert
>           objectType: secret
>           objectAlias: intermediate.crt
>         - |
>           objectName: server-key
>           objectType: secret
>           objectAlias: server.key
>         - |
>           objectName: root-ca-cert
>           objectType: secret
>           objectAlias: root-ca.crt
>     tenantId: "<tenant-id>"
> ```
>
> The Go service assembles the chain at load time (see
> [Enterprise PKI Chain Assembly](#enterprise-pki-chain-assembly) below).

---

## Azure Key Vault as Certificate Source

Azure Key Vault provides centralized, audited certificate and secret storage.

- Access controlled by **Azure RBAC** and **Key Vault access policies**.
- Key Vault can generate keys internally (HSM-backed, non-exportable) — the private
  key never leaves the HSM boundary.
- Or import existing PEM/PFX certificates for use with container workloads.

### Storing Certificates in Key Vault

```bash
# Import a PFX certificate (includes private key)
az keyvault certificate import --vault-name myVault \
    --name server-cert --file server.pfx

# Import a PEM certificate + key (combined file)
az keyvault certificate import --vault-name myVault \
    --name server-cert --file chain.pem

# Store root CA as a secret (public cert only)
az keyvault secret set --vault-name myVault \
    --name root-ca-cert --file root-ca.crt
```

**Enterprise PKI:** When your organization's PKI issues leaf certificates from an
intermediate CA (rather than directly from the root), store the leaf and intermediate
as separate secrets so they can be rotated independently:

```bash
# Leaf certificate (issued by intermediate CA)
az keyvault secret set --vault-name myVault \
    --name server-leaf-cert --file leaf.crt

# Intermediate CA certificate (issued by root CA)
az keyvault secret set --vault-name myVault \
    --name intermediate-ca-cert --file intermediate.crt

# Private key for the leaf certificate
az keyvault secret set --vault-name myVault \
    --name server-key --file server.key

# Root CA (trust anchor — used in client CA pools)
az keyvault secret set --vault-name myVault \
    --name root-ca-cert --file root-ca.crt
```

During pod startup (via CSI driver mount or init container), download both the leaf
and intermediate certificates. The Go service assembles the full chain bundle before
loading into `tls.Config` — see
[Enterprise PKI Chain Assembly](#enterprise-pki-chain-assembly).

> **Tip:** Use `az keyvault certificate import` for certs with private keys. Use
> `az keyvault secret set` for public-only CA bundles or trust anchors.

---

## Secrets Store CSI Driver for AKS

The Secrets Store CSI driver mounts Key Vault secrets and certificates as files in the
pod filesystem. This is the **recommended approach** for AKS.

- **No application code changes** — Go reads files from a mount path, identical to
  reading from disk.
- **Supports auto-rotation** — the driver polls Key Vault for changes and updates
  mounted files.
- **Supports workload identity** — no credentials stored in the cluster.

### SecretProviderClass Manifest

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: mtls-certs
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "true"
    userAssignedIdentityID: "<managed-identity-client-id>"
    keyvaultName: "myVault"
    objects: |
      array:
        - |
          objectName: server-chain
          objectType: secret
          objectAlias: chain.crt
        - |
          objectName: server-key
          objectType: secret
          objectAlias: server.key
        - |
          objectName: root-ca-cert
          objectType: secret
          objectAlias: root-ca.crt
    tenantId: "<tenant-id>"
```

### Pod Volume Mount

```yaml
spec:
  containers:
    - name: mtls-server
      volumeMounts:
        - name: certs
          mountPath: /certs
          readOnly: true
  volumes:
    - name: certs
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: mtls-certs
```

Go code reads from the mount path exactly as it would from local disk:

```go
cert, err := tls.LoadX509KeyPair("/certs/chain.crt", "/certs/server.key")

caCert, err := os.ReadFile("/certs/root-ca.crt")
caPool := x509.NewCertPool()
caPool.AppendCertsFromPEM(caCert)
```

This is identical to the file-based mTLS pattern — no Key Vault SDK, no special
libraries. The CSI driver handles all Key Vault interaction.

### Enterprise PKI Chain Assembly

When an enterprise PKI issues leaf certificates from an intermediate CA, the leaf and
intermediate are typically stored (and rotated) as separate secrets. The Go service
must assemble the full chain before creating a `tls.Certificate`.

```go
// Load separate certs injected via CSI driver or init container
leafPEM, _ := os.ReadFile("/certs/leaf.crt")
intermediatePEM, _ := os.ReadFile("/certs/intermediate.crt")
keyPEM, _ := os.ReadFile("/certs/server.key")

// Assemble chain: leaf first, then intermediate
chainPEM := append(leafPEM, '\n')
chainPEM = append(chainPEM, intermediatePEM...)

// Parse as TLS certificate with full chain
cert, err := tls.X509KeyPair(chainPEM, keyPEM)
```

The resulting `tls.Certificate` contains the leaf certificate followed by the
intermediate. During the TLS handshake, the server sends the full chain so clients
can verify the path back to the root CA — even if they do not have the intermediate
in their trust store.

> **Important:** Order matters. The leaf certificate **must** come first in the
> concatenated PEM bundle, followed by the intermediate(s). Placing the intermediate
> before the leaf will cause `tls.X509KeyPair` to return an error because the private
> key will not match the first certificate in the bundle.

---

## ACI Volume Mounts

Azure Container Instances support secret volumes directly — simpler than AKS, no CSI
driver or Kubernetes infrastructure required.

### Container Group Definition (ARM/Bicep)

```json
{
  "type": "Microsoft.ContainerInstance/containerGroups",
  "properties": {
    "containers": [
      {
        "name": "mtls-server",
        "properties": {
          "image": "myregistry.azurecr.io/mtls-server:latest",
          "volumeMounts": [
            {
              "name": "certs",
              "mountPath": "/certs",
              "readOnly": true
            }
          ]
        }
      }
    ],
    "volumes": [
      {
        "name": "certs",
        "secret": {
          "chain.crt": "<base64-encoded-chain>",
          "server.key": "<base64-encoded-key>",
          "root-ca.crt": "<base64-encoded-root-ca>"
        }
      }
    ]
  }
}
```

Alternatively, mount an **Azure Files** share as a volume if you need to update
certificates without redeploying the container group.

> **Note:** ACI secret volumes accept base64-encoded values. The container sees
> plain-text files at the mount path. Go reads them with `os.ReadFile` as usual.

---

## Workload Identity (AKS)

Workload Identity is the current recommended approach for Azure identity in AKS. It
replaces the deprecated AAD Pod Identity.

- Maps a **Kubernetes ServiceAccount** to an **Azure AD (Entra ID) managed identity**.
- The pod receives a **federated token** automatically via projected volume — no
  credentials in environment variables or files.
- Use it for accessing Key Vault, Azure Storage, Azure SQL, or any Azure service.

### Setup

#### 1. Create and Annotate the ServiceAccount

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mtls-server
  annotations:
    azure.workload.identity/client-id: "<managed-identity-client-id>"
```

#### 2. Federate the Identity

```bash
az identity federated-credential create \
    --identity-name mtls-server-identity \
    --resource-group myRG \
    --issuer "https://oidc.prod-aks.azure.com/<oidc-issuer>" \
    --subject "system:serviceaccount:default:mtls-server"
```

#### 3. Grant Key Vault Access

```bash
az keyvault set-policy --name myVault \
    --object-id "<managed-identity-principal-id>" \
    --secret-permissions get list \
    --certificate-permissions get list
```

#### 4. Reference in Pod Spec

```yaml
spec:
  serviceAccountName: mtls-server
  containers:
    - name: mtls-server
      # Workload identity webhook injects AZURE_* env vars automatically
```

---

## Init Containers for Cert Provisioning

Use this pattern when the CSI driver is not available (e.g., non-AKS Kubernetes, older
clusters, or hybrid environments).

```yaml
initContainers:
  - name: cert-fetcher
    image: mcr.microsoft.com/azure-cli
    command: ["/bin/sh", "-c"]
    args:
      - |
        az login --federated-token "$(cat $AZURE_FEDERATED_TOKEN_FILE)" \
            --service-principal -u "$AZURE_CLIENT_ID" -t "$AZURE_TENANT_ID"
        az keyvault secret download --vault-name myVault \
            --name server-chain -f /certs/chain.crt
        az keyvault secret download --vault-name myVault \
            --name server-key -f /certs/server.key
        az keyvault secret download --vault-name myVault \
            --name root-ca-cert -f /certs/root-ca.crt
        chmod 400 /certs/server.key
    volumeMounts:
      - name: certs
        mountPath: /certs
containers:
  - name: mtls-server
    volumeMounts:
      - name: certs
        mountPath: /certs
        readOnly: true
volumes:
  - name: certs
    emptyDir:
      medium: Memory   # tmpfs — certs never hit disk
```

> **Security:** Use `medium: Memory` for the `emptyDir` volume. This stores certs in
> a tmpfs mount (RAM only), so private keys are never written to the node's disk.

---

## Certificate Rotation in Kubernetes

### With cert-manager

cert-manager automates certificate issuance and renewal:

1. Define an `Issuer` or `ClusterIssuer` pointing to your CA.
2. Create a `Certificate` resource specifying the desired DNS names and duration.
3. cert-manager issues the cert, stores it in a Kubernetes Secret, and renews it
   before expiry.
4. Mount the Secret as a volume — Go reads updated files.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: mtls-server-cert
spec:
  secretName: mtls-server-tls
  issuerRef:
    name: internal-ca
    kind: ClusterIssuer
  commonName: mtls-server.default.svc.cluster.local
  dnsNames:
    - mtls-server.default.svc.cluster.local
  duration: 720h      # 30 days
  renewBefore: 168h   # renew 7 days before expiry
  privateKey:
    algorithm: ECDSA
    size: 256
```

### With CSI Driver Auto-Rotation

The Secrets Store CSI driver polls Key Vault periodically and updates mounted files
when certificates change. The Go server must reload certs to pick up changes.

#### Dynamic Certificate Reload Pattern

```go
// Reload cert from disk on every TLS handshake.
// Simple but reads disk on each connection.
tlsCfg := &tls.Config{
    GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
        cert, err := tls.LoadX509KeyPair("/certs/chain.crt", "/certs/server.key")
        if err != nil {
            return nil, fmt.Errorf("loading server cert: %w", err)
        }
        return &cert, nil
    },
    ClientAuth: tls.RequireAndVerifyClientCert,
    GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
        // Reload client CA pool on each connection
        caCert, err := os.ReadFile("/certs/root-ca.crt")
        if err != nil {
            return nil, fmt.Errorf("loading client CA: %w", err)
        }
        caPool := x509.NewCertPool()
        caPool.AppendCertsFromPEM(caCert)
        return &tls.Config{
            ClientAuth: tls.RequireAndVerifyClientCert,
            ClientCAs:  caPool,
        }, nil
    },
}
```

**For production:** Cache the loaded certificate and CA pool. Use a file watcher
(e.g., `fsnotify`) to detect changes and reload only when files are updated. This
avoids unnecessary disk reads on every handshake.

### Intermediate CA Rotation with CSI Driver

Enterprise PKI environments periodically rotate the intermediate CA — typically
years before the root CA expires. This is the sequence:

1. **PKI operator issues a new intermediate** from the existing root CA.
2. **Re-issue all leaf certificates** signed by the new intermediate. The old
   intermediate may continue to validate existing leaf certs until they expire,
   but new certs should use the new intermediate immediately.
3. **Update Key Vault** with the new intermediate CA certificate secret and
   the newly-issued leaf certificate secrets.
4. **CSI driver detects the change** during its polling interval and updates the
   mounted files inside each pod (`/certs/leaf.crt`, `/certs/intermediate.crt`).
5. **Go service's `GetCertificate` callback** picks up the new chain on the next
   TLS handshake (or the file watcher triggers a reload).
6. **Root CA trust pool does NOT change.** Clients and servers still trust the
   same root CA — only the intermediate layer is replaced.

> **Key insight:** Because the root CA remains the same, no client-side trust store
> updates are required. Clients verify the chain `leaf → new intermediate → root`
> using the same root CA pool they already have. This is the primary operational
> advantage of a two-tier (root + intermediate) PKI hierarchy.

---

## Health Probes over mTLS

Kubernetes liveness and readiness probes need to reach the server. Standard HTTP probes
from the kubelet cannot present a client certificate for mTLS. Options:

### Option 1: Separate Plaintext Health Port (Recommended)

Run a second HTTP listener on a non-TLS port, cluster-internal only.

```go
// Main mTLS server on :8443
go startMTLSServer()

// Health server on :8080 (plaintext, cluster-internal only)
healthMux := http.NewServeMux()
healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
    // Optionally check internal state, DB connections, etc.
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("ok"))
})
go http.ListenAndServe(":8080", healthMux)
```

```yaml
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

> **Security note:** The health port should not expose sensitive data. Only bind it to
> the pod IP (default behavior). Use NetworkPolicy to restrict access if needed.

### Option 2: Exec Probe

Run a health check command inside the container. Useful when you cannot open a second
port.

```yaml
livenessProbe:
  exec:
    command:
      - /health-check          # a small binary that connects via mTLS or checks a file
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Option 3: gRPC Health (if using gRPC)

If your service uses gRPC with mTLS, use Kubernetes native gRPC health probes
(available since Kubernetes 1.24).

```yaml
livenessProbe:
  grpc:
    port: 8443
```

> This requires the kubelet to support the gRPC probe protocol. The probe does not
> perform mTLS — it connects at the TCP/TLS level. Consider whether this meets your
> security requirements or use a separate health port.

---

## Container Image Best Practices

### Minimal Base Image

Use the smallest possible base image. For Go with `CGO_ENABLED=0`, `distroless` or
`scratch` are ideal.

```dockerfile
FROM golang:1.22 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=build /server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]
```

### Why Minimal Images Matter for mTLS

- **No shell, no OpenSSL, no cert tools** — an attacker who compromises the container
  cannot easily extract or manipulate certificates.
- **Smaller attack surface** — fewer packages means fewer CVEs to patch.
- **Faster pulls and startups** — important for autoscaling and pod restarts.

### Security Hardening

```yaml
spec:
  containers:
    - name: mtls-server
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      volumeMounts:
        - name: certs
          mountPath: /certs
          readOnly: true
```

- **`readOnlyRootFilesystem: true`** — the cert volume is mounted separately, so the
  root filesystem does not need to be writable.
- **`runAsNonRoot: true`** — never run as root. The Go binary does not need root
  privileges to bind to high-numbered ports (8443, 8080).
- **`drop: ["ALL"]`** — remove all Linux capabilities. A Go mTLS server needs none.

---

## Network Policies (AKS)

mTLS authenticates clients cryptographically, but network policies add defense-in-depth
by restricting which pods can even reach the server at the network layer.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mtls-server-policy
spec:
  podSelector:
    matchLabels:
      app: mtls-server
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: trusted-client
      ports:
        - protocol: TCP
          port: 8443
    - from: []         # allow health probes from any pod in namespace
      ports:
        - protocol: TCP
          port: 8080
```

- **Port 8443** — only pods labeled `role: trusted-client` can connect.
- **Port 8080** — health port open to the namespace (kubelet probes).
- Combine with mTLS: even if a pod reaches port 8443, it must present a valid client
  certificate signed by the trusted CA.

---

## Common Mistakes

| Mistake | Why It Matters | Fix |
|---------|---------------|-----|
| Baking private keys into container images | Anyone with registry pull access can extract them | Mount keys at runtime via CSI driver, Secrets, or init containers |
| Using environment variables for private keys | Visible in `/proc/<pid>/environ`, `docker inspect`, Kubernetes API | Use file mounts; never pass keys as env vars |
| Hardcoding Key Vault names | Breaks portability across environments (dev/staging/prod) | Use environment variables or config files for vault names |
| No certificate rotation | Certs expire; containers restart with expired certs | Use cert-manager or CSI driver auto-rotation |
| Health probes failing on mTLS | Kubelet cannot present client certs | Use a separate plaintext health port |
| Running as root | Unnecessary privilege; larger blast radius if compromised | Use `USER nonroot:nonroot` in Dockerfile, `runAsNonRoot` in pod spec |
| Writable root filesystem | Attacker can write binaries, scripts, or modified certs | Set `readOnlyRootFilesystem: true`; mount writable volumes only where needed |
| No network policies alongside mTLS | Any pod in the cluster can attempt connections | Apply `NetworkPolicy` to restrict ingress to trusted pods |
| Loading certs once at startup | Rotated certs are not picked up until pod restart | Use `GetCertificate` / `GetConfigForClient` callbacks with file watching |
| Storing certs in `emptyDir` on disk | Keys persisted to node storage can survive pod deletion | Use `emptyDir` with `medium: Memory` (tmpfs) |
| Storing only leaf cert in Key Vault, omitting intermediate from enterprise PKI chain | Clients receive an incomplete chain and cannot verify the path to the root CA — TLS handshakes fail with `x509: certificate signed by unknown authority` | Store the leaf cert and intermediate CA cert as separate Key Vault secrets; assemble the full chain (leaf + intermediate) at load time before passing to `tls.X509KeyPair` |

---

## Quick Reference: File Paths Convention

When mounting certificates into containers, use a consistent path structure:

| File | Path | Contents |
|------|------|----------|
| Server certificate chain | `/certs/chain.crt` | Leaf cert + intermediates, PEM |
| Server private key | `/certs/server.key` | ECDSA or RSA private key, PEM |
| Client CA bundle | `/certs/root-ca.crt` | Trusted CA(s) for verifying client certs, PEM |
| Client certificate (if applicable) | `/certs/client.crt` | Client leaf cert, PEM |
| Client private key (if applicable) | `/certs/client.key` | Client private key, PEM |

Go code:

```go
// Server TLS config
serverCert, err := tls.LoadX509KeyPair("/certs/chain.crt", "/certs/server.key")

// Client CA pool (for mTLS — verifying client certificates)
clientCAPEM, err := os.ReadFile("/certs/root-ca.crt")
clientCAPool := x509.NewCertPool()
clientCAPool.AppendCertsFromPEM(clientCAPEM)

tlsCfg := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    clientCAPool,
    MinVersion:   tls.VersionTLS12,
}
```

---

## Summary: Decision Tree

```
Need certificates in a container?
├── AKS?
│   ├── CSI driver available? → Secrets Store CSI + Key Vault (preferred)
│   ├── cert-manager installed? → cert-manager for issuance + rotation
│   └── Neither? → Init container + Key Vault + Workload Identity
├── ACI?
│   ├── Simple deployment? → Secret volume in container group
│   └── Need rotation? → Azure Files share or redeploy
└── Other Kubernetes?
    ├── cert-manager → Kubernetes Secrets mounted as volumes
    └── No cert-manager → Init container fetching from secret store
```

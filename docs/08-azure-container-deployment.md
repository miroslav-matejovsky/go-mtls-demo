# Chapter 8: Deploying mTLS services as Azure containers

Back to [docs index](index.md)

The repo's file-based scenarios — `mtlsfiles` and `mtlstpm` — load certificates from disk and build `tls.Config` from those files. That pattern maps directly to containerized deployments, where the certificate files are injected into the container's filesystem at runtime rather than generated locally.

This chapter covers how to source, inject, and renew certificates when running Go mTLS services in Azure containers — whether on Azure Container Instances (ACI) or Azure Kubernetes Service (AKS). The Go code itself barely changes. What changes is the infrastructure that puts the right files in the right place before the process starts.

## Two deployment models on Azure

### Azure Container Instances

ACI runs a single container or a container group (multiple containers sharing a network namespace and lifecycle). There is no orchestrator — you define the container group via an ARM template, Bicep, or the Azure CLI, and Azure manages the lifecycle directly.

Certificate injection on ACI uses volume mounts: you can mount an Azure Files share or reference secrets from Azure Key Vault as volumes in the container group definition. The container sees files at the mount path, and the Go code reads them with `tls.LoadX509KeyPair` exactly as it does in `mtlsfiles`.

ACI is a good fit for:

- small-scale mTLS services where Kubernetes is overkill
- dev and staging environments
- sidecar patterns (e.g., an mTLS proxy alongside a plaintext backend)
- scheduled or event-driven workloads that do not need to run continuously

### Azure Kubernetes Service

AKS is a managed Kubernetes platform. It provides richer certificate management than ACI: you can use Kubernetes Secrets, the Secrets Store CSI driver to mount Key Vault secrets directly into pods, or cert-manager to issue and rotate certificates automatically.

Pod identity is handled via AKS Workload Identity (the replacement for the deprecated AAD Pod Identity). Workload Identity maps a Kubernetes ServiceAccount to an Azure AD identity, giving the pod a federated token that Azure SDKs pick up automatically — no credentials in environment variables or files.

AKS is the right choice for:

- production mTLS services at scale
- multi-service architectures where services authenticate to each other via mTLS
- environments that need automated certificate rotation
- workloads that need orchestration features like rolling updates, autoscaling, and self-healing

## Certificate sourcing patterns

There are several ways to get certificates into a container. They range from simple and weak to complex and strong. Choose the weakest approach that meets your security requirements — anything stronger adds operational cost.

### Never bake private keys into container images

This is the most important rule in container certificate management.

Container image layers are not secret. Anyone with pull access to your container registry — or anyone who compromises the registry — can extract every layer of the image. A private key baked into an image layer is effectively public, even if you delete the file in a later layer (the earlier layer still contains it).

This applies to both Docker and OCI images, and it applies whether you use `COPY`, `ADD`, or multi-stage builds that forget to exclude key material from the final stage.

The only thing safe to include in an image is a public CA bundle for trust anchoring — and even that is better mounted at runtime so you can update the trust bundle without rebuilding the image.

### Mount certificates from Kubernetes Secrets

The simplest approach on AKS. You create a Kubernetes Secret containing the certificate and key, then mount it as a volume in the pod spec:

```yaml
# Conceptual — Kubernetes Secret containing cert and key
apiVersion: v1
kind: Secret
metadata:
  name: mtls-server-cert
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
---
# Conceptual — Pod spec mounting the secret
apiVersion: v1
kind: Pod
metadata:
  name: go-mtls-server
spec:
  containers:
  - name: go-mtls-server
    image: myregistry.azurecr.io/go-mtls-server:latest
    volumeMounts:
    - name: tls-certs
      mountPath: /certs
      readOnly: true
  volumes:
  - name: tls-certs
    secret:
      secretName: mtls-server-cert
```

The Go code loads certs from `/certs/tls.crt` and `/certs/tls.key` — identical to the `mtlsfiles` pattern in this repo. The only difference is that the files come from a Kubernetes Secret instead of a local `certs/mtlsfiles/` directory.

This approach is simple and works well for non-sensitive environments. The main limitation is that Kubernetes Secrets are stored in etcd. If etcd encryption at rest is not enabled on your AKS cluster, the secrets are stored in plaintext. AKS enables etcd encryption at rest by default on newer clusters, but verify this for your environment.

### Mount certificates from Azure Key Vault via CSI driver

This is the recommended pattern for AKS production deployments. The Secrets Store CSI driver fetches certificates from Azure Key Vault and mounts them as files in the pod — no Kubernetes Secret required.

```yaml
# Conceptual — SecretProviderClass for Azure Key Vault
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: mtls-keyvault
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMUserAssignedIdentity: "false"
    clientID: "<managed-identity-client-id>"
    keyvaultName: "my-keyvault"
    objects: |
      array:
        - |
          objectName: mtls-server-cert
          objectType: secret
    tenantId: "<tenant-id>"
---
# Conceptual — Pod spec using the CSI driver volume
apiVersion: v1
kind: Pod
metadata:
  name: go-mtls-server
spec:
  containers:
  - name: go-mtls-server
    image: myregistry.azurecr.io/go-mtls-server:latest
    volumeMounts:
    - name: secrets-store
      mountPath: /certs
      readOnly: true
  volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: mtls-keyvault
```

The CSI driver fetches the certificate from Key Vault and mounts it as a file at `/certs/mtls-server-cert`. The Go code reads it exactly as it does in `mtlsfiles`.

Important details:

- `objectType: secret` (not `certificate`) gives you the full PFX/PEM bundle including the private key. Using `objectType: certificate` returns only the public certificate without the key.
- The CSI driver can auto-rotate the mounted files when the Key Vault certificate is renewed (enable `rotationPollInterval` in the driver configuration).
- Authentication to Key Vault uses Managed Identity — no credentials in the pod, no secrets in environment variables. Workload Identity is the recommended identity mechanism (see the Managed Identity section below).

### Fetch certificates at runtime via Azure SDK

Instead of mounting files, the Go service can fetch certificates directly from Key Vault at startup using the Azure SDK. This pattern is not implemented in the repo, but it is worth understanding as an alternative.

Conceptually, the service would:

1. Create a credential with `azidentity.NewDefaultAzureCredential()` (which picks up Managed Identity or Workload Identity automatically)
2. Create a Key Vault client with `azcertificates.NewClient()` or `azsecrets.NewClient()`
3. Download the certificate and key material
4. Parse the PEM/PFX data and build `tls.Config` in memory

Advantages: no file system dependency, no CSI driver to install and manage, no volume mounts to configure. Disadvantages: adds an Azure SDK dependency to the Go service, introduces startup latency while the certificate is fetched, and requires handling Key Vault unavailability (retries, circuit breakers).

This is the pattern a future `mtlsazurekv` scenario would implement if added to the repo.

### ACI volume mounts

For ACI, certificate injection is more limited than AKS. The main options are:

- **Azure Key Vault secret volumes**: the container group definition references a Key Vault secret, and ACI mounts it as a file. This is the preferred approach for key material.
- **Azure Files**: a shared file storage volume. Less secure for private keys because Azure Files permissions are coarser than Key Vault RBAC, but workable for CA trust bundles.
- **Inline secrets**: the container group definition includes base64-encoded secret values directly. These are mounted as files in the container. Simple, but the secrets are visible in the ARM template.

```json
// Conceptual — ACI container group with secret volume (ARM template fragment)
{
  "properties": {
    "containers": [{
      "name": "go-mtls-server",
      "properties": {
        "image": "myregistry.azurecr.io/go-mtls-server:latest",
        "volumeMounts": [{
          "name": "tls-certs",
          "mountPath": "/certs",
          "readOnly": true
        }]
      }
    }],
    "volumes": [{
      "name": "tls-certs",
      "secret": {
        "tls.crt": "<base64-encoded-cert>",
        "tls.key": "<base64-encoded-key>"
      }
    }]
  }
}
```

ACI's Key Vault integration is more limited than the AKS CSI driver — there is no automatic rotation, and the authentication model is simpler (system-assigned Managed Identity on the container group). For production mTLS on ACI, consider fetching certificates via the Azure SDK at runtime rather than relying on volume mounts alone.

## Managed Identity

Managed Identity eliminates credentials from the deployment. Instead of storing a service principal secret or certificate in the container, the container gets an identity from the Azure platform itself. Azure SDKs and the CSI driver pick up this identity automatically.

### System-assigned vs user-assigned

| Type | Lifecycle | Sharing | Best for |
| --- | --- | --- | --- |
| System-assigned | Tied to the resource — created and deleted with it | Cannot share across resources | Single-purpose resources (one ACI group, one AKS cluster) |
| User-assigned | Independent — you create and delete it separately | Share across multiple resources | Multi-resource deployments, consistent identity across environments |

For ACI, system-assigned identity is simpler — the container group gets its own identity with no extra setup. For AKS with multiple services that need Key Vault access, a user-assigned identity shared via Workload Identity is usually cleaner.

### Required RBAC roles for Key Vault access

| Role | Scope | Grants |
| --- | --- | --- |
| Key Vault Secrets User | Key Vault or specific secret | Read secrets (includes cert+key bundles stored as secrets) |
| Key Vault Certificates Officer | Key Vault | Full certificate lifecycle — create, import, update, delete |
| Key Vault Crypto User | Key Vault | Cryptographic operations — sign, verify, wrap, unwrap |

For mTLS certificate retrieval, **Key Vault Secrets User** is usually sufficient. When you store a certificate in Key Vault, the private key is accessible via the secret API (not the certificate API). This is why the CSI driver uses `objectType: secret` — it needs the private key, which is only available through the secrets endpoint.

If your service also needs to create or renew certificates in Key Vault (rather than just reading them), add **Key Vault Certificates Officer**.

### AKS Workload Identity

Workload Identity is the current recommended way to give AKS pods an Azure identity. It replaces the deprecated AAD Pod Identity.

The setup creates a trust relationship between a Kubernetes ServiceAccount and an Azure AD managed identity:

```bash
# Conceptual — enable Workload Identity on an AKS cluster
az aks update \
  --resource-group myRG \
  --name myAKS \
  --enable-oidc-issuer \
  --enable-workload-identity

# Conceptual — create a federated credential linking the K8s ServiceAccount
# to the Azure managed identity
az identity federated-credential create \
  --name fed-cred \
  --identity-name my-identity \
  --resource-group myRG \
  --issuer "${AKS_OIDC_ISSUER}" \
  --subject system:serviceaccount:default:my-service-account
```

Once configured, any pod running with the `my-service-account` ServiceAccount gets a federated token that `azidentity.NewDefaultAzureCredential()` picks up automatically. The CSI driver also supports Workload Identity for authenticating to Key Vault. No client secrets, no certificates for authentication — the platform handles it.

## Certificate renewal in containers

Certificates expire. Containers make renewal both easier (you can redeploy) and harder (you need to coordinate across replicas). Here are the main patterns.

### Short-lived certificates with cert-manager

cert-manager is a Kubernetes operator that issues and renews certificates automatically. It can use an internal CA, Let's Encrypt, Vault (HashiCorp), or a custom issuer.

For mTLS, cert-manager can:

- Issue short-lived certificates (hours to days) to both servers and clients
- Automatically renew certificates before they expire
- Write renewed certificates to Kubernetes Secrets
- Trigger pod restarts when secrets change (via annotations or external controllers)

Short-lived certificates reduce the blast radius of key compromise — a stolen certificate is only useful until it expires, which might be hours instead of months.

### Key Vault auto-renewal with CSI driver

When you configure auto-renewal on a Key Vault certificate, Key Vault generates a new certificate before the current one expires. The CSI driver can detect this change and update the mounted files in the pod.

The pod then picks up the new certificate either by:

1. **File watching and hot-reload**: the Go code detects the file change and reloads `tls.Config` without restarting (zero-downtime renewal)
2. **Rolling update**: a controller or pipeline triggers a rolling update of the deployment, restarting pods one at a time (brief per-pod downtime, but the deployment stays available)

### Hot-reloading certificates in Go

The `tls.Config` struct supports a `GetCertificate` callback that is called on every TLS handshake. This is the hook for hot-reloading:

```go
// Conceptual — not implemented in the repo
// Hot-reload server certificate on each handshake
tlsConfig := &tls.Config{
    GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
        cert, err := tls.LoadX509KeyPair(certFile, keyFile)
        if err != nil {
            return nil, err
        }
        return &cert, nil
    },
    MinVersion: tls.VersionTLS12,
}
```

For mTLS servers that also need to reload the client CA trust pool, use `VerifyPeerCertificate` or periodically rebuild and swap the `tls.Config`.

**Performance note**: reloading the certificate from disk on every handshake is expensive. In practice, you would use a file watcher (e.g., `fsnotify`) or a timer to cache the certificate and reload only when the file changes or a time interval elapses. The pattern above is shown for clarity, not as production-ready code. This is not implemented in the repo — it is documented here as a production direction.

## Network security for mTLS containers

mTLS authenticates both endpoints, but it does not replace network-level controls. Defense in depth means layering mTLS with network restrictions.

### Private endpoints for Azure Key Vault

If your containers fetch certificates from Key Vault (via CSI driver or SDK), the traffic should not traverse the public internet. Create a private endpoint for Key Vault inside the AKS VNet or the ACI subnet. This ensures certificate fetching stays on the Azure backbone.

This is not optional for compliance-sensitive environments (PCI, HIPAA, FedRAMP). Even in less regulated environments, private endpoints reduce the attack surface for credential and certificate retrieval.

### VNet integration

- **AKS**: pods run inside the VNet by default when using Azure CNI networking. Pod-to-pod mTLS traffic never leaves the VNet.
- **ACI**: use VNet integration to place container groups in a subnet. Without VNet integration, ACI containers get a public IP and mTLS traffic traverses the public internet.

Both approaches ensure that mTLS handshakes and encrypted traffic stay within the Azure backbone between services.

### Network Security Groups

Even with mTLS, restrict access at the network level. NSG rules should limit which source CIDRs can reach the mTLS port:

- Allow TCP 8443 (or whatever port your mTLS server uses) only from known client subnets
- Deny all other inbound traffic to the mTLS port
- Keep management ports (SSH, etc.) restricted to bastion hosts or Azure Bastion

mTLS prevents unauthorized clients from completing a handshake, but NSG rules prevent unauthorized clients from even reaching the listener.

### TLS termination vs end-to-end mTLS

This is a critical architectural decision for container deployments:

- **TLS termination at the edge** (Azure Front Door, Application Gateway in termination mode): the load balancer terminates TLS, decrypts the traffic, and forwards plaintext (or re-encrypts) to the backend. This simplifies certificate management — only the load balancer needs a certificate — but it breaks the mTLS model. The backend server never sees the client certificate, so mutual authentication is lost.

- **End-to-end mTLS** (the pattern this repo teaches): the client authenticates directly to the Go server. No intermediary terminates TLS. The server validates the client certificate itself. This is harder to operate behind a load balancer, but it provides true mutual authentication. This is the right choice when client identity matters (service-to-service auth, zero-trust architectures).

- **TLS passthrough** (Application Gateway in passthrough mode, or a TCP load balancer): the load balancer forwards the raw TCP/TLS stream without terminating it. The Go server handles the full TLS handshake including client certificate validation. This preserves mTLS while still providing load balancing. This is usually the right choice for mTLS services behind a load balancer in Azure.

## Health and readiness probes

### The mTLS probe challenge

Kubernetes health probes (`httpGet`, `tcpSocket`, `grpc`) run from the kubelet on the node. The kubelet does not have a client certificate. If your mTLS server requires client certificates on all connections (`tls.RequireAndVerifyClientCert`), the probe will fail the TLS handshake and Kubernetes will think the container is unhealthy.

This is a real operational problem. Here are the solutions, in order of preference:

1. **Separate health port**: run a plaintext HTTP health endpoint on a different port (e.g., `:8080/healthz` for liveness, `:8080/readyz` for readiness). The mTLS port (`:8443`) only accepts authenticated traffic. This is the most common pattern.

```yaml
# Conceptual — separate health port in a pod spec
containers:
- name: go-mtls-server
  ports:
  - containerPort: 8443
    name: mtls
  - containerPort: 8080
    name: health
  livenessProbe:
    httpGet:
      path: /healthz
      port: 8080
  readinessProbe:
    httpGet:
      path: /readyz
      port: 8080
```

2. **TCP probe**: use `tcpSocket` on the mTLS port. This verifies the listener is accepting connections but does not complete a TLS handshake. It catches "process crashed" and "port not listening" but not "certificate expired" or "TLS misconfigured".

3. **Exec probe**: run a command inside the container that performs a full mTLS handshake using a local client certificate. This is the most thorough check, but it requires a client certificate to be available inside the container and adds a process spawn per probe interval.

```yaml
# Conceptual — exec probe that performs an mTLS health check
livenessProbe:
  exec:
    command:
    - /bin/health-check
    - --cert=/certs/client.crt
    - --key=/certs/client.key
    - --ca=/certs/ca.crt
    - --url=https://localhost:8443/healthz
```

For most deployments, option 1 (separate health port) is the right choice. It is simple, reliable, and does not require distributing client certificates to the health check system.

### Certificate readiness

Do not accept mTLS traffic before certificates are loaded. If your service fetches certificates from Key Vault at runtime (via SDK), the readiness probe should return unhealthy until the certificate is successfully loaded and the TLS listener is started.

A simple pattern:

- Start the health port immediately on startup
- Return `503 Service Unavailable` from `/readyz` until certificates are loaded
- Start the mTLS listener and flip `/readyz` to `200 OK`

This prevents Kubernetes from routing traffic to a pod that cannot yet complete a TLS handshake.

## Mapping repo scenarios to Azure deployment

| Deployment pattern | Start from | Certificate source | Identity |
| --- | --- | --- | --- |
| AKS + K8s Secrets | `mtlsfiles` | Kubernetes Secret mounted as files | Manual secret management |
| AKS + CSI driver + Key Vault | `mtlsfiles` | Key Vault via CSI driver (mounted as files) | Workload Identity → Key Vault |
| AKS + runtime fetch | `mtlsfiles` + Azure SDK | Key Vault via `azcertificates` SDK | Workload Identity → Key Vault |
| ACI + volume mount | `mtlsfiles` | Azure Files or Key Vault secret volume | System-assigned Managed Identity |
| ACI + runtime fetch | `mtlsfiles` + Azure SDK | Key Vault via SDK at startup | System-assigned Managed Identity |

The key insight is that **`mtlsfiles` is the right base for all container deployments**. The Go code's certificate loading pattern — `tls.LoadX509KeyPair` for the identity, `x509.CertPool` with `AppendCertsFromPEM` for trust — stays the same across all of these. What changes is the infrastructure that puts the certificate files into the container's filesystem before the Go process reads them.

If you are planning a container deployment, start by running `mtlsfiles` locally, then replace the local `certs/mtlsfiles/` directory with one of the sourcing patterns above.

Previous: [Chapter 7 - Deploying mTLS services on Windows](07-windows-deployment.md)

Next: Back to [docs index](index.md)

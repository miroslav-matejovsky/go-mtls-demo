//go:build windows

package mtlstpm

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	"github.com/google/certtostore"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pwsh"
)

const (
	certBaseDir   = "certs/mtlstpm"
	containerName = "go-mtls-demo-client"
	clientCN      = "go mTLS TPM Demo Client"
	caCN          = "go mTLS TPM Demo CA"

	// certStoreAddReplaceExisting is the Windows CryptoAPI CERT_STORE_ADD_REPLACE_EXISTING
	// disposition constant. It replaces any existing cert with the same subject/issuer
	// rather than silently reusing the old one — ensures re-runs pick up the new cert.
	certStoreAddReplaceExisting = 3
)

func RunDemo() error {
	return runDemo(certBaseDir)
}

func runDemo(baseDir string) error {
	caCertPath      := filepath.Join(baseDir, "ca", "cert.crt")
	serverCertPath  := filepath.Join(baseDir, "server", "server.crt")
	serverKeyPath   := filepath.Join(baseDir, "server", "server.key")
	serverCACertPath := filepath.Join(baseDir, "server", "ca.crt")

	// ── Step 1 ──────────────────────────────────────────────────────────────
	fmt.Println("=== Step 1/6: Generate CA and Server certificate ===")
	fmt.Println("CA is in-memory only — its private key is never written to disk.")
	fmt.Printf("Server cert and CA distribution copy written to: %s\n", filepath.Join(baseDir, "server"))
	fmt.Println()

	caCert, signLeaf, err := cert.CreateCA(caCN)
	if err != nil {
		return fmt.Errorf("error creating CA: %w", err)
	}
	cert.PrintCertificateInfo(caCert)

	if err := cert.WriteCert(caCertPath, caCert); err != nil {
		return fmt.Errorf("error writing CA cert: %w", err)
	}

	serverCert, serverKey, err := cert.CreateLeafCert(signLeaf, "go mTLS TPM Demo Server")
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}
	cert.PrintCertificateInfo(serverCert)

	serverKeyBytes, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("error marshaling server key: %w", err)
	}
	if err := cert.WriteCert(serverCertPath, serverCert); err != nil {
		return fmt.Errorf("error writing server certificate: %w", err)
	}
	if err := cert.WriteKey(serverKeyPath, serverKeyBytes); err != nil {
		return fmt.Errorf("error writing server key: %w", err)
	}
	if err := cert.WriteCert(serverCACertPath, caCert); err != nil {
		return fmt.Errorf("error writing CA cert to server directory: %w", err)
	}
	fmt.Printf("  [SERVER] Certificate → %s\n", serverCertPath)
	fmt.Printf("  [SERVER] Private key  → %s\n", serverKeyPath)
	fmt.Printf("  [SERVER] CA cert      → %s\n", serverCACertPath)
	fmt.Printf("  [CA]     Reference    → %s\n", caCertPath)
	fmt.Println()

	// ── Step 2 ──────────────────────────────────────────────────────────────
	fmt.Println("=== Step 2/6: Check TPM availability ===")
	fmt.Println("Querying the system's Trusted Platform Module (TPM) via Get-Tpm.")
	fmt.Println("If available, the client private key will be generated inside the TPM and never exported.")
	fmt.Println()

	tpmAvailable, tpmDetails, tpmErr := pwsh.CheckTPM()
	var provider string
	if tpmErr != nil {
		fmt.Printf("  [TPM] Warning: could not query TPM — %v\n", tpmErr)
		fmt.Println("  [TPM] Falling back to Microsoft Software Key Storage Provider.")
		tpmAvailable = false
	} else {
		for _, line := range strings.Split(tpmDetails, "\n") {
			fmt.Printf("  %s\n", line)
		}
	}

	if tpmAvailable {
		provider = certtostore.ProviderMSPlatform
		fmt.Println("  [TPM] TPM 2.0 present and enabled.")
		fmt.Printf("  [TPM] Provider selected: %s\n", provider)
		fmt.Println("  [TPM] The private key will be bound to this machine's TPM — it cannot be exported.")
	} else {
		provider = certtostore.ProviderMSSoftware
		fmt.Println("  [TPM] TPM not available or not ready.")
		fmt.Printf("  [TPM] Provider selected: %s\n", provider)
		fmt.Println("  [TPM] The private key will be stored in NCrypt software key storage.")
	}
	fmt.Println()

	// ── Step 3 ──────────────────────────────────────────────────────────────
	fmt.Println("=== Step 3/6: Generate client key in Windows Certificate Store ===")
	fmt.Printf("Opening CurrentUser\\My via provider=%q  container=%q\n", provider, containerName)
	fmt.Println("Generating an ECDSA P-256 key pair. The private key is created by the provider.")
	fmt.Println("certtostore returns a crypto.Signer — operations use the provider, raw bytes stay inside.")
	fmt.Println()

	store, err := certtostore.OpenWinCertStoreCurrentUser(
		provider,
		containerName,
		[]string{"CN=" + caCN},
		nil,
		false,
	)
	if err != nil {
		return fmt.Errorf("error opening Windows cert store: %w", err)
	}
	defer store.Close()

	signer, err := store.Generate(certtostore.GenerateOpts{
		Algorithm: certtostore.EC,
		Size:      256,
	})
	if err != nil {
		return fmt.Errorf("error generating key in Windows cert store: %w", err)
	}
	fmt.Printf("  [CLIENT] Key generated — algorithm: ECDSA P-256, provider: %s\n", provider)

	// Use the TPM key's public key to sign a leaf cert with our CA.
	clientCert, err := signLeaf(signer.Public(), clientCN)
	if err != nil {
		return fmt.Errorf("error signing client certificate: %w", err)
	}
	cert.PrintCertificateInfo(clientCert)
	fmt.Println("  [CLIENT] Private key lives inside the provider — no .key file is written.")
	fmt.Println()

	// ── Step 4 ──────────────────────────────────────────────────────────────
	fmt.Println("=== Step 4/6: Import client certificate into Windows Certificate Store ===")
	fmt.Printf("Linking signed certificate to key container %q in CurrentUser\\My.\n", containerName)
	fmt.Println()

	if err := store.StoreWithDisposition(clientCert, nil, certStoreAddReplaceExisting); err != nil {
		return fmt.Errorf("error storing client certificate: %w", err)
	}
	fmt.Printf("  [CLIENT] Certificate stored in CurrentUser\\My\n")

	if storeInfo, err := pwsh.ShowCertsInStore(clientCN); err != nil {
		fmt.Printf("  [CLIENT] Warning: could not query cert store — %v\n", err)
	} else if storeInfo != "" {
		fmt.Println("  [CLIENT] Cert store entry:")
		for _, line := range strings.Split(storeInfo, "\n") {
			fmt.Printf("    %s\n", line)
		}
	}
	fmt.Println()

	// Simulate runtime lookup: open the cert by issuer, then derive its key
	// from the CertContext. This is what a real application does on startup —
	// it has no signer in memory, it must re-derive it from the store.
	fmt.Println("  [CLIENT] Simulating runtime key lookup (re-deriving key from CertContext) ...")
	storedCert, ctx, _, err := store.CertByCommonName(clientCN)
	if err != nil {
		return fmt.Errorf("error looking up cert from store by CN: %w", err)
	}
	defer certtostore.FreeCertContext(ctx)

	storeKey, err := store.CertKey(ctx)
	if err != nil {
		return fmt.Errorf("error deriving key from cert context: %w", err)
	}
	fmt.Println("  [CLIENT] Key successfully retrieved via CertKey — ready for TLS.")
	fmt.Println()

	// ── Step 5 ──────────────────────────────────────────────────────────────
	fmt.Println("=== Step 5/6: Start mTLS server and make trusted request ===")
	fmt.Printf("Server loads certificates from disk: %s\n", filepath.Join(baseDir, "server"))
	fmt.Printf("Client uses key from Windows cert store (provider: %s) — no key file on disk.\n", provider)
	fmt.Println()

	server, err := CreateServer(serverCertPath, serverKeyPath, serverCACertPath)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	fmt.Printf("[SERVER] Listening on %s\n", server.URL)
	fmt.Println()

	client, err := CreateClient(caCert, storeKey, storedCert)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Printf("[CLIENT] GET %s\n", server.URL)
	resp, err := client.Get(server.URL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] Server certificate verified: %s (issued by %s)\n",
		resp.TLS.PeerCertificates[0].Subject.CommonName, resp.TLS.PeerCertificates[0].Issuer.CommonName)
	fmt.Printf("[CLIENT] Handshake complete  — version: %s, cipher suite: %s\n",
		cert.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Printf("[CLIENT] Signing performed by: %s (private key never left the provider)\n", provider)
	fmt.Println("[CLIENT] Response:", resp.Status)
	fmt.Println()

	// ── Step 6 ──────────────────────────────────────────────────────────────
	fmt.Println("=== Step 6/6: Demonstrate untrusted client ===")
	fmt.Println("Creating a client cert signed by a different CA — not trusted by the server.")
	fmt.Println("The private key is in-memory (no cert store). The server must reject the connection.")
	fmt.Println()

	_, untrustedSign, err := cert.CreateCA("go mTLS TPM Untrusted CA")
	if err != nil {
		return fmt.Errorf("error creating untrusted CA: %w", err)
	}
	untrustedCert, untrustedKey, err := cert.CreateLeafCert(untrustedSign, "go mTLS TPM Untrusted Client")
	if err != nil {
		return fmt.Errorf("error creating untrusted client certificate: %w", err)
	}

	// The untrusted client still uses the trusted CA cert to verify the server —
	// it's rejected because its OWN cert is from a different CA, not because it
	// can't reach the server.
	untrustedClient, err := CreateClient(caCert, untrustedKey, untrustedCert)
	if err != nil {
		return fmt.Errorf("error creating untrusted client: %w", err)
	}

	fmt.Printf("[UNTRUSTED CLIENT] GET %s\n", server.URL)
	_, err = untrustedClient.Get(server.URL)
	if err != nil {
		fmt.Printf("[UNTRUSTED CLIENT] Connection rejected — %s\n", err)
		fmt.Println("[UNTRUSTED CLIENT] Expected: server refused client cert — not signed by the trusted CA.")
	} else {
		return fmt.Errorf("expected untrusted client to be rejected, but request succeeded")
	}
	fmt.Println()

	printCleanupInstructions(provider, containerName, clientCN)
	return nil
}

func printCleanupInstructions(provider, container, cn string) {
	fmt.Println("=== Manual Cleanup ===")
	fmt.Println("The client certificate and key were NOT removed automatically.")
	fmt.Println("You can inspect them in certmgr.msc (CurrentUser → Personal → Certificates).")
	fmt.Println()
	fmt.Println("To remove them, run the following PowerShell commands:")
	fmt.Println()
	fmt.Println("  # 1. Remove the client certificate from CurrentUser\\My:")
	fmt.Printf("  Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.Subject -like \"*%s*\" } | Remove-Item\n", cn)
	fmt.Println()
	fmt.Println("  # 2. Delete the NCrypt key container from the provider:")
	fmt.Printf("  $p = New-Object System.Security.Cryptography.CngProvider('%s')\n", provider)
	fmt.Printf("  $k = [System.Security.Cryptography.CngKey]::Open('%s', $p)\n", container)
	fmt.Println("  $k.Delete()")
}

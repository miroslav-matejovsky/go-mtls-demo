package mtlsfiles

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"path/filepath"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

const certBaseDir = "certs/mtlsfiles"

func RunDemo() error {
	return runDemo(certBaseDir)
}

func runDemo(baseDir string) error {
	caCertPath      := filepath.Join(baseDir, "ca", "cert.crt")
	serverCertPath  := filepath.Join(baseDir, "server", "server.crt")
	serverKeyPath   := filepath.Join(baseDir, "server", "server.key")
	// Each party stores its own copy of the CA cert — distributed by the CA operator.
	// On separate machines none of these directories are shared.
	serverCACertPath   := filepath.Join(baseDir, "server", "ca.crt")
	clientCertPath     := filepath.Join(baseDir, "client", "client.crt")
	clientKeyPath      := filepath.Join(baseDir, "client", "client.key")
	clientCACertPath   := filepath.Join(baseDir, "client", "ca.crt")
	untrustedCertPath  := filepath.Join(baseDir, "untrusted", "client.crt")
	untrustedKeyPath   := filepath.Join(baseDir, "untrusted", "client.key")
	untrustedCACertPath := filepath.Join(baseDir, "untrusted", "ca.crt")

	fmt.Println("=== Step 1/6: Generate CA, Server, and Client certificates ===")
	fmt.Println("Each party owns its own directory — in production they never share private keys:")
	fmt.Printf("  %s  — Certificate Authority\n", filepath.Join(baseDir, "ca"))
	fmt.Printf("  %s  — Server operator\n", filepath.Join(baseDir, "server"))
	fmt.Printf("  %s  — Client operator\n", filepath.Join(baseDir, "client"))
	fmt.Println()

	caCert, signLeaf, err := cert.CreateCA("go mTLS Demo CA")
	if err != nil {
		return fmt.Errorf("error creating CA: %w", err)
	}
	cert.PrintCertificateInfo(caCert)
	if err := cert.WriteCert(caCertPath, caCert); err != nil {
		return fmt.Errorf("error writing CA certificate: %w", err)
	}
	// Distribute CA cert to server and client directories — simulates the CA operator
	// handing the public cert to each team independently.
	if err := cert.WriteCert(serverCACertPath, caCert); err != nil {
		return fmt.Errorf("error writing CA certificate to server directory: %w", err)
	}
	if err := cert.WriteCert(clientCACertPath, caCert); err != nil {
		return fmt.Errorf("error writing CA certificate to client directory: %w", err)
	}
	fmt.Printf("  [CA]     Certificate → %s\n", caCertPath)
	fmt.Printf("  [CA]     Distributed to server → %s\n", serverCACertPath)
	fmt.Printf("  [CA]     Distributed to client → %s\n", clientCACertPath)
	fmt.Println("  [CA]     Private key stays on the CA machine — NOT written to disk here.")
	fmt.Println()

	serverCert, serverPrivateKey, err := cert.CreateLeafCert(signLeaf, "go mTLS Demo Server")
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}
	cert.PrintCertificateInfo(serverCert)

	serverKeyBytes, err := x509.MarshalECPrivateKey(serverPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling server key: %w", err)
	}
	if err := cert.WriteCert(serverCertPath, serverCert); err != nil {
		return fmt.Errorf("error writing server certificate: %w", err)
	}
	if err := cert.WriteKey(serverKeyPath, serverKeyBytes); err != nil {
		return fmt.Errorf("error writing server key: %w", err)
	}
	fmt.Printf("  [SERVER] Certificate → %s\n", serverCertPath)
	fmt.Printf("  [SERVER] Private key  → %s\n", serverKeyPath)
	fmt.Println()

	clientCert, clientPrivateKey, err := cert.CreateLeafCert(signLeaf, "go mTLS Demo Client")
	if err != nil {
		return fmt.Errorf("error creating client certificate: %w", err)
	}
	cert.PrintCertificateInfo(clientCert)

	clientKeyBytes, err := x509.MarshalECPrivateKey(clientPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling client key: %w", err)
	}
	if err := cert.WriteCert(clientCertPath, clientCert); err != nil {
		return fmt.Errorf("error writing client certificate: %w", err)
	}
	if err := cert.WriteKey(clientKeyPath, clientKeyBytes); err != nil {
		return fmt.Errorf("error writing client key: %w", err)
	}
	fmt.Printf("  [CLIENT] Certificate → %s\n", clientCertPath)
	fmt.Printf("  [CLIENT] Private key  → %s\n", clientKeyPath)
	fmt.Println()

	fmt.Println("=== Step 2/6: Start mTLS server (loading certificates from disk) ===")
	fmt.Printf("Server reads from its own directory only: %s\n", filepath.Join(baseDir, "server"))
	fmt.Println("Server config: presents its certificate AND requires a valid client certificate.")
	fmt.Println("Connections without a CA-signed client certificate will be rejected.")
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

	fmt.Println("=== Step 3/6: Make request over mTLS (trusted client) ===")
	fmt.Printf("Client reads from its own directory only: %s\n", filepath.Join(baseDir, "client"))
	fmt.Println("Authentication: client verifies server cert → CA   |   server verifies client cert → CA.")
	fmt.Println()

	client, err := CreateClient(clientCACertPath, clientCertPath, clientKeyPath)
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
	fmt.Println("[CLIENT] Response:", resp.Status)
	fmt.Println()

	fmt.Println("=== Step 4/6: Generate untrusted client certificate (different CA) ===")
	fmt.Println("This simulates a client from an external organisation — its CA is not trusted by the server.")
	fmt.Printf("Untrusted client files written to: %s\n", filepath.Join(baseDir, "untrusted"))
	fmt.Println()

	_, untrustedSignLeaf, err := cert.CreateCA("go mTLS Untrusted CA")
	if err != nil {
		return fmt.Errorf("error creating untrusted CA: %w", err)
	}
	untrustedClientCert, untrustedClientKey, err := cert.CreateLeafCert(untrustedSignLeaf, "go mTLS Untrusted Client")
	if err != nil {
		return fmt.Errorf("error creating untrusted client certificate: %w", err)
	}
	untrustedKeyBytes, err := x509.MarshalECPrivateKey(untrustedClientKey)
	if err != nil {
		return fmt.Errorf("error marshaling untrusted client key: %w", err)
	}
	if err := cert.WriteCert(untrustedCertPath, untrustedClientCert); err != nil {
		return fmt.Errorf("error writing untrusted client certificate: %w", err)
	}
	if err := cert.WriteKey(untrustedKeyPath, untrustedKeyBytes); err != nil {
		return fmt.Errorf("error writing untrusted client key: %w", err)
	}
	// The untrusted client still needs the server's CA cert to verify the server during
	// the handshake — it's untrusted because its OWN cert is signed by a different CA.
	if err := cert.WriteCert(untrustedCACertPath, caCert); err != nil {
		return fmt.Errorf("error writing trusted CA cert to untrusted directory: %w", err)
	}
	fmt.Printf("  [UNTRUSTED CLIENT] Certificate → %s\n", untrustedCertPath)
	fmt.Printf("  [UNTRUSTED CLIENT] Private key  → %s\n", untrustedKeyPath)
	fmt.Printf("  [UNTRUSTED CLIENT] Server CA    → %s  (to verify server, but client cert is from a different CA)\n", untrustedCACertPath)
	fmt.Println()

	fmt.Println("=== Step 5/6: Make request with untrusted client certificate ===")
	fmt.Println("The server must reject this connection during the TLS handshake.")
	fmt.Println()

	// The untrusted client trusts the server's CA so the dial proceeds far enough for
	// the server to evaluate and reject the client certificate.
	untrustedClient, err := CreateClient(untrustedCACertPath, untrustedCertPath, untrustedKeyPath)
	if err != nil {
		return fmt.Errorf("error creating untrusted client: %w", err)
	}

	fmt.Printf("[UNTRUSTED CLIENT] GET %s\n", server.URL)
	_, err = untrustedClient.Get(server.URL)
	if err != nil {
		fmt.Printf("[UNTRUSTED CLIENT] Connection rejected — %s\n", err)
		fmt.Println("[UNTRUSTED CLIENT] Expected: server refused the certificate because it was not signed by the trusted cert.")
	} else {
		return fmt.Errorf("expected untrusted client to be rejected, but request succeeded")
	}
	fmt.Println()

	fmt.Println("=== Step 6/6: Inspect files on disk ===")
	fmt.Println("Each directory represents a security boundary — parties only share public certificates:")
	printDirTree(baseDir)
	return nil
}

func printDirTree(baseDir string) {
	entries := []struct{ owner, file string }{
		{"ca",        "cert.crt           (public — the CA's own copy)"},
		{"server",    "server.crt         (public — presented to clients during handshake)"},
		{"server",    "server.key         (private — never leaves the server machine)"},
		{"server",    "ca.crt             (public — copy received from CA, used to verify client certs)"},
		{"client",    "client.crt         (public — presented to server during mTLS handshake)"},
		{"client",    "client.key         (private — never leaves the client machine)"},
		{"client",    "ca.crt             (public — copy received from CA, used to verify server cert)"},
		{"untrusted", "client.crt         (public — rejected by server, unknown CA)"},
		{"untrusted", "client.key         (private — never leaves the untrusted client)"},
		{"untrusted", "ca.crt             (public — copy of server CA, to verify server cert)"},
	}
	for _, e := range entries {
		fmt.Printf("  %s/%s/%s\n", baseDir, e.owner, e.file)
	}
}

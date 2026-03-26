package tlsfiles

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

const certBaseDir = "certs/tlsfiles"

func RunDemo() error {
	return runDemo(certBaseDir)
}

func runDemo(baseDir string) error {
	caCertPath     := filepath.Join(baseDir, "ca", "cert.crt")
	serverCertPath := filepath.Join(baseDir, "server", "server.crt")
	serverKeyPath  := filepath.Join(baseDir, "server", "server.key")

	fmt.Println("=== Step 1/4: Generate Certificate Authority (CA) ===")
	fmt.Println("In a real deployment the CA lives on a dedicated secure machine.")
	fmt.Println("Its public certificate is distributed to clients and servers.")
	fmt.Println("The private key never leaves the CA machine — it is NOT written to disk here.")
	fmt.Println()

	caCert, signLeaf, err := cert.CreateCA("go TLS Demo CA")
	if err != nil {
		return fmt.Errorf("error creating CA: %w", err)
	}
	cert.PrintCertificateInfo(caCert)
	if err := cert.WriteCert(caCertPath, caCert); err != nil {
		return fmt.Errorf("error writing CA certificate: %w", err)
	}
	fmt.Printf("  [CA] Certificate → %s\n", caCertPath)
	fmt.Println()

	fmt.Println("=== Step 2/4: Generate Server Certificate (signed by CA) ===")
	fmt.Println("The CA signs the server certificate and hands it to the server operator.")
	fmt.Println("The private key is generated locally and stays in the server's own directory.")
	fmt.Println()

	serverCert, serverPrivateKey, err := cert.CreateLeafCert(signLeaf, "go TLS Demo Server")
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

	fmt.Println("=== Step 3/4: Start TLS server (loading certificate from disk) ===")
	fmt.Printf("Server reads from its own directory: %s\n", filepath.Join(baseDir, "server"))
	fmt.Println("Server does NOT require a certificate from the client (one-way TLS).")
	fmt.Println()

	server, err := CreateServer(serverCertPath, serverKeyPath)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	server.StartTLS()
	defer server.Close()
	fmt.Printf("[SERVER] Listening on %s\n", server.URL)
	fmt.Println()

	fmt.Println("=== Step 4/4: Make request over TLS (loading CA certificate from disk) ===")
	fmt.Printf("Client reads CA certificate from: %s\n", filepath.Join(baseDir, "ca"))
	fmt.Println("Client config: trusts the CA — does NOT send a certificate (one-way TLS).")
	fmt.Println("Authentication: client verifies server cert → CA   |   server trusts any client.")
	fmt.Println()

	client, err := CreateClient(caCertPath)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Printf("[CLIENT] GET %s\n", server.URL)
	resp, err := client.Get(server.URL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] Handshake complete  — version: %s, cipher suite: %s\n",
		cert.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Println("[CLIENT] Response:", resp.Status)
	return nil
}

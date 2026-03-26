package tlsfiles

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

func RunDemo(configPath string) error {
	if configPath == "" {
		configPath = defaultConfigPath
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	return runDemo(cfg)
}

func runDemo(cfg Config) error {
	validity, err := cfg.CA.ParseValidity()
	if err != nil {
		return err
	}

	fmt.Println("=== Step 1/4: Generate Certificate Authority (CA) ===")
	fmt.Println("In a real deployment the CA lives on a dedicated secure machine.")
	fmt.Println("Its public certificate is distributed to clients and servers.")
	fmt.Println("The private key never leaves the CA machine — it is NOT written to disk here.")
	fmt.Println()

	caCert, signLeaf, err := cert.CreateCA(cfg.CA.CN, validity)
	if err != nil {
		return fmt.Errorf("error creating CA: %w", err)
	}
	cert.PrintCertificateInfo(caCert)
	if err := cert.WriteCert(cfg.CA.CertFile, caCert); err != nil {
		return fmt.Errorf("error writing CA certificate: %w", err)
	}
	// Distribute the CA cert to the client's own directory (simulates the CA operator
	// handing the public cert to the client team — no shared filesystem needed).
	if err := cert.WriteCert(cfg.Client.CACertFile, caCert); err != nil {
		return fmt.Errorf("error writing CA certificate to client directory: %w", err)
	}
	fmt.Printf("  [CA]     Certificate → %s\n", cfg.CA.CertFile)
	fmt.Printf("  [CA]     Distributed to client → %s\n", cfg.Client.CACertFile)
	fmt.Println()

	fmt.Println("=== Step 2/4: Generate Server Certificate (signed by CA) ===")
	fmt.Println("The CA signs the server certificate and hands it to the server operator.")
	fmt.Println("The private key is generated locally and stays in the server's own directory.")
	fmt.Println()

	serverCert, serverPrivateKey, err := cert.CreateLeafCert(signLeaf, cfg.Server.CN)
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}
	cert.PrintCertificateInfo(serverCert)

	serverKeyBytes, err := x509.MarshalECPrivateKey(serverPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling server key: %w", err)
	}
	if err := cert.WriteCert(cfg.Server.CertFile, serverCert); err != nil {
		return fmt.Errorf("error writing server certificate: %w", err)
	}
	if err := cert.WriteKey(cfg.Server.KeyFile, serverKeyBytes); err != nil {
		return fmt.Errorf("error writing server key: %w", err)
	}
	fmt.Printf("  [SERVER] Certificate → %s\n", cfg.Server.CertFile)
	fmt.Printf("  [SERVER] Private key  → %s\n", cfg.Server.KeyFile)
	fmt.Println()

	fmt.Println("=== Step 3/4: Start TLS server (loading certificate from disk) ===")
	fmt.Printf("Server reads from its own directory: %s\n", filepath.Dir(cfg.Server.CertFile))
	fmt.Println("Server does NOT require a certificate from the client (one-way TLS).")
	fmt.Println()

	server, err := CreateServer(cfg.Server.CertFile, cfg.Server.KeyFile)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	ln, err := tls.Listen("tcp", cfg.Server.Address, server.TLSConfig)
	if err != nil {
		return fmt.Errorf("error starting TLS listener on %s: %w", cfg.Server.Address, err)
	}
	go server.Serve(ln) //nolint:errcheck
	defer server.Close()
	serverURL := "https://" + ln.Addr().String()
	fmt.Printf("[SERVER] Listening on %s\n", serverURL)
	fmt.Println()

	fmt.Println("=== Step 4/4: Make request over TLS (loading CA certificate from disk) ===")
	fmt.Printf("Client reads from its own directory: %s\n", filepath.Dir(cfg.Client.CACertFile))
	fmt.Println("Client trusts the CA cert it received from the CA operator (no access to ca/ needed).")
	fmt.Println("Client config: trusts the CA — does NOT send a certificate (one-way TLS).")
	fmt.Println("Authentication: client verifies server cert → CA   |   server trusts any client.")
	fmt.Println()

	client, err := CreateClient(cfg.Client.CACertFile)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Printf("[CLIENT] GET %s\n", serverURL)
	resp, err := client.Get(serverURL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] Handshake complete  — version: %s, cipher suite: %s\n",
		cert.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Println("[CLIENT] Response:", resp.Status)
	return nil
}

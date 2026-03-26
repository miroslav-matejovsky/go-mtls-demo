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

	fmt.Println("=== Step 1/6: Generate CA, Server, and Client certificates ===")
	fmt.Println("Each party owns its own directory — in production they never share private keys:")
	fmt.Printf("  %s  — Certificate Authority\n", filepath.Dir(cfg.CA.CertFile))
	fmt.Printf("  %s  — Server operator\n", filepath.Dir(cfg.Server.CertFile))
	fmt.Printf("  %s  — Client operator\n", filepath.Dir(cfg.Client.CertFile))
	fmt.Println()

	caCert, signLeaf, err := cert.CreateCA(cfg.CA.CN, validity)
	if err != nil {
		return fmt.Errorf("error creating CA: %w", err)
	}
	cert.PrintCertificateInfo(caCert)
	if err := cert.WriteCert(cfg.CA.CertFile, caCert); err != nil {
		return fmt.Errorf("error writing CA certificate: %w", err)
	}
	// Distribute CA cert to server and client directories — simulates the CA operator
	// handing the public cert to each team independently.
	if err := cert.WriteCert(cfg.Server.CACertFile, caCert); err != nil {
		return fmt.Errorf("error writing CA certificate to server directory: %w", err)
	}
	if err := cert.WriteCert(cfg.Client.CACertFile, caCert); err != nil {
		return fmt.Errorf("error writing CA certificate to client directory: %w", err)
	}
	fmt.Printf("  [CA]     Certificate → %s\n", cfg.CA.CertFile)
	fmt.Printf("  [CA]     Distributed to server → %s\n", cfg.Server.CACertFile)
	fmt.Printf("  [CA]     Distributed to client → %s\n", cfg.Client.CACertFile)
	fmt.Println("  [CA]     Private key stays on the CA machine — NOT written to disk here.")
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

	clientCert, clientPrivateKey, err := cert.CreateLeafCert(signLeaf, cfg.Client.CN)
	if err != nil {
		return fmt.Errorf("error creating client certificate: %w", err)
	}
	cert.PrintCertificateInfo(clientCert)

	clientKeyBytes, err := x509.MarshalECPrivateKey(clientPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling client key: %w", err)
	}
	if err := cert.WriteCert(cfg.Client.CertFile, clientCert); err != nil {
		return fmt.Errorf("error writing client certificate: %w", err)
	}
	if err := cert.WriteKey(cfg.Client.KeyFile, clientKeyBytes); err != nil {
		return fmt.Errorf("error writing client key: %w", err)
	}
	fmt.Printf("  [CLIENT] Certificate → %s\n", cfg.Client.CertFile)
	fmt.Printf("  [CLIENT] Private key  → %s\n", cfg.Client.KeyFile)
	fmt.Println()

	fmt.Println("=== Step 2/6: Start mTLS server (loading certificates from disk) ===")
	fmt.Printf("Server reads from its own directory only: %s\n", filepath.Dir(cfg.Server.CertFile))
	fmt.Println("Server config: presents its certificate AND requires a valid client certificate.")
	fmt.Println("Connections without a CA-signed client certificate will be rejected.")
	fmt.Println()

	server, err := CreateServer(cfg.Server.CertFile, cfg.Server.KeyFile, cfg.Server.CACertFile)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	server.ErrorLog = log.New(io.Discard, "", 0)
	ln, err := tls.Listen("tcp", cfg.Server.Address, server.TLSConfig)
	if err != nil {
		return fmt.Errorf("error starting TLS listener on %s: %w", cfg.Server.Address, err)
	}
	go server.Serve(ln) //nolint:errcheck
	defer server.Close()
	serverURL := "https://" + ln.Addr().String()
	fmt.Printf("[SERVER] Listening on %s\n", serverURL)
	fmt.Println()

	fmt.Println("=== Step 3/6: Make request over mTLS (trusted client) ===")
	fmt.Printf("Client reads from its own directory only: %s\n", filepath.Dir(cfg.Client.CertFile))
	fmt.Println("Authentication: client verifies server cert → CA   |   server verifies client cert → CA.")
	fmt.Println()

	client, err := CreateClient(cfg.Client.CACertFile, cfg.Client.CertFile, cfg.Client.KeyFile)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Printf("[CLIENT] GET %s\n", serverURL)
	resp, err := client.Get(serverURL)
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
	fmt.Printf("Untrusted client files written to: %s\n", filepath.Dir(cfg.Untrusted.CertFile))
	fmt.Println()

	_, untrustedSignLeaf, err := cert.CreateCA(cfg.Untrusted.CACN, validity)
	if err != nil {
		return fmt.Errorf("error creating untrusted CA: %w", err)
	}
	untrustedClientCert, untrustedClientKey, err := cert.CreateLeafCert(untrustedSignLeaf, cfg.Untrusted.CN)
	if err != nil {
		return fmt.Errorf("error creating untrusted client certificate: %w", err)
	}
	untrustedKeyBytes, err := x509.MarshalECPrivateKey(untrustedClientKey)
	if err != nil {
		return fmt.Errorf("error marshaling untrusted client key: %w", err)
	}
	if err := cert.WriteCert(cfg.Untrusted.CertFile, untrustedClientCert); err != nil {
		return fmt.Errorf("error writing untrusted client certificate: %w", err)
	}
	if err := cert.WriteKey(cfg.Untrusted.KeyFile, untrustedKeyBytes); err != nil {
		return fmt.Errorf("error writing untrusted client key: %w", err)
	}
	// The untrusted client still needs the server's CA cert to verify the server during
	// the handshake — it's untrusted because its OWN cert is signed by a different CA.
	if err := cert.WriteCert(cfg.Untrusted.CACertFile, caCert); err != nil {
		return fmt.Errorf("error writing trusted CA cert to untrusted directory: %w", err)
	}
	fmt.Printf("  [UNTRUSTED CLIENT] Certificate → %s\n", cfg.Untrusted.CertFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Private key  → %s\n", cfg.Untrusted.KeyFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Server CA    → %s  (to verify server, but client cert is from a different CA)\n", cfg.Untrusted.CACertFile)
	fmt.Println()

	fmt.Println("=== Step 5/6: Make request with untrusted client certificate ===")
	fmt.Println("The server must reject this connection during the TLS handshake.")
	fmt.Println()

	// The untrusted client trusts the server's CA so the dial proceeds far enough for
	// the server to evaluate and reject the client certificate.
	untrustedClient, err := CreateClient(cfg.Untrusted.CACertFile, cfg.Untrusted.CertFile, cfg.Untrusted.KeyFile)
	if err != nil {
		return fmt.Errorf("error creating untrusted client: %w", err)
	}

	fmt.Printf("[UNTRUSTED CLIENT] GET %s\n", serverURL)
	_, err = untrustedClient.Get(serverURL)
	if err != nil {
		fmt.Printf("[UNTRUSTED CLIENT] Connection rejected — %s\n", err)
		fmt.Println("[UNTRUSTED CLIENT] Expected: server refused the certificate because it was not signed by the trusted cert.")
	} else {
		return fmt.Errorf("expected untrusted client to be rejected, but request succeeded")
	}
	fmt.Println()

	fmt.Println("=== Step 6/6: Inspect files on disk ===")
	fmt.Println("Each directory represents a security boundary — parties only share public certificates:")
	printDirTree(cfg)
	return nil
}

func printDirTree(cfg Config) {
	entries := []struct{ file, note string }{
		{cfg.CA.CertFile, "public — the CA's own copy"},
		{cfg.Server.CertFile, "public — presented to clients during handshake"},
		{cfg.Server.KeyFile, "private — never leaves the server machine"},
		{cfg.Server.CACertFile, "public — copy received from CA, used to verify client certs"},
		{cfg.Client.CertFile, "public — presented to server during mTLS handshake"},
		{cfg.Client.KeyFile, "private — never leaves the client machine"},
		{cfg.Client.CACertFile, "public — copy received from CA, used to verify server cert"},
		{cfg.Untrusted.CertFile, "public — rejected by server, unknown CA"},
		{cfg.Untrusted.KeyFile, "private — never leaves the untrusted client"},
		{cfg.Untrusted.CACertFile, "public — copy of server CA, to verify server cert"},
	}
	for _, e := range entries {
		fmt.Printf("  %-55s  %s\n", e.file, e.note)
	}
}


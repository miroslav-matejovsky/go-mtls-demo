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

func RunDemo() error {
	opCfg, err := LoadOperatorConfig(defaultOperatorConfigPath)
	if err != nil {
		return fmt.Errorf("loading operator config: %w", err)
	}
	serverCfg, err := LoadServerConfig(defaultServerConfigPath)
	if err != nil {
		return fmt.Errorf("loading server config: %w", err)
	}
	clientCfg, err := LoadClientConfig(defaultClientConfigPath)
	if err != nil {
		return fmt.Errorf("loading client config: %w", err)
	}
	untrustedCfg, err := LoadUntrustedClientConfig(defaultUntrustedClientConfigPath)
	if err != nil {
		return fmt.Errorf("loading untrusted client config: %w", err)
	}
	return runDemo(opCfg, serverCfg, clientCfg, untrustedCfg)
}

func runDemo(opCfg OperatorConfig, serverCfg ServerConfig, clientCfg ClientConfig, untrustedCfg UntrustedClientConfig) error {
	fmt.Println("=== Step 1/6: Generate CA, Server, and Client certificates ===")
	fmt.Println("Each party owns its own directory — in production they never share private keys:")
	fmt.Printf("  %s  — Certificate Authority (operator)\n", filepath.Dir(opCfg.CertFile))
	fmt.Printf("  %s  — Server operator\n", filepath.Dir(serverCfg.CertFile))
	fmt.Printf("  %s  — Client operator\n", filepath.Dir(clientCfg.CertFile))
	fmt.Println()

	operator, err := NewOperator(opCfg)
	if err != nil {
		return fmt.Errorf("error creating operator: %w", err)
	}
	validity, err := opCfg.ParseValidity()
	if err != nil {
		return err
	}
	cert.PrintCertificateInfo(operator.CACert())
	if err := operator.DistributeCA(serverCfg.CACertFile); err != nil {
		return fmt.Errorf("error distributing CA certificate to server: %w", err)
	}
	if err := operator.DistributeCA(clientCfg.CACertFile); err != nil {
		return fmt.Errorf("error distributing CA certificate to client: %w", err)
	}
	fmt.Printf("  [OPERATOR] CA Certificate → %s\n", opCfg.CertFile)
	fmt.Printf("  [OPERATOR] Distributed to server → %s\n", serverCfg.CACertFile)
	fmt.Printf("  [OPERATOR] Distributed to client → %s\n", clientCfg.CACertFile)
	fmt.Println("  [OPERATOR] Private key stays on the CA machine — NOT written to disk here.")
	fmt.Println()

	serverCert, serverPrivateKey, err := operator.SignCert(serverCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}
	cert.PrintCertificateInfo(serverCert)

	serverKeyBytes, err := x509.MarshalECPrivateKey(serverPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling server key: %w", err)
	}
	if err := cert.WriteCert(serverCfg.CertFile, serverCert); err != nil {
		return fmt.Errorf("error writing server certificate: %w", err)
	}
	if err := cert.WriteKey(serverCfg.KeyFile, serverKeyBytes); err != nil {
		return fmt.Errorf("error writing server key: %w", err)
	}
	fmt.Printf("  [SERVER] Certificate → %s\n", serverCfg.CertFile)
	fmt.Printf("  [SERVER] Private key  → %s\n", serverCfg.KeyFile)
	fmt.Println()

	clientCert, clientPrivateKey, err := operator.SignCert(clientCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating client certificate: %w", err)
	}
	cert.PrintCertificateInfo(clientCert)

	clientKeyBytes, err := x509.MarshalECPrivateKey(clientPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling client key: %w", err)
	}
	if err := cert.WriteCert(clientCfg.CertFile, clientCert); err != nil {
		return fmt.Errorf("error writing client certificate: %w", err)
	}
	if err := cert.WriteKey(clientCfg.KeyFile, clientKeyBytes); err != nil {
		return fmt.Errorf("error writing client key: %w", err)
	}
	fmt.Printf("  [CLIENT] Certificate → %s\n", clientCfg.CertFile)
	fmt.Printf("  [CLIENT] Private key  → %s\n", clientCfg.KeyFile)
	fmt.Println()

	fmt.Println("=== Step 2/6: Start mTLS server (loading certificates from disk) ===")
	fmt.Printf("Server reads from its own directory only: %s\n", filepath.Dir(serverCfg.CertFile))
	fmt.Println("Server config: presents its certificate AND requires a valid client certificate.")
	fmt.Println("Connections without a CA-signed client certificate will be rejected.")
	fmt.Println()

	server, err := CreateServer(serverCfg.CertFile, serverCfg.KeyFile, serverCfg.CACertFile)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	server.ErrorLog = log.New(io.Discard, "", 0)
	ln, err := tls.Listen("tcp", serverCfg.Address, server.TLSConfig)
	if err != nil {
		return fmt.Errorf("error starting TLS listener on %s: %w", serverCfg.Address, err)
	}
	go server.Serve(ln) //nolint:errcheck
	defer server.Close()
	serverURL := "https://" + ln.Addr().String()
	fmt.Printf("[SERVER] Listening on %s\n", serverURL)
	fmt.Println()

	fmt.Println("=== Step 3/6: Make request over mTLS (trusted client) ===")
	fmt.Printf("Client reads from its own directory only: %s\n", filepath.Dir(clientCfg.CertFile))
	fmt.Println("Authentication: client verifies server cert → CA   |   server verifies client cert → CA.")
	fmt.Println()

	client, err := CreateClient(clientCfg.CACertFile, clientCfg.CertFile, clientCfg.KeyFile)
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
	fmt.Printf("Untrusted client files written to: %s\n", filepath.Dir(untrustedCfg.CertFile))
	fmt.Println()

	_, untrustedSignLeaf, err := cert.CreateCA(untrustedCfg.CACN, validity)
	if err != nil {
		return fmt.Errorf("error creating untrusted CA: %w", err)
	}
	untrustedClientCert, untrustedClientKey, err := cert.CreateLeafCert(untrustedSignLeaf, untrustedCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating untrusted client certificate: %w", err)
	}
	untrustedKeyBytes, err := x509.MarshalECPrivateKey(untrustedClientKey)
	if err != nil {
		return fmt.Errorf("error marshaling untrusted client key: %w", err)
	}
	if err := cert.WriteCert(untrustedCfg.CertFile, untrustedClientCert); err != nil {
		return fmt.Errorf("error writing untrusted client certificate: %w", err)
	}
	if err := cert.WriteKey(untrustedCfg.KeyFile, untrustedKeyBytes); err != nil {
		return fmt.Errorf("error writing untrusted client key: %w", err)
	}
	// The untrusted client still needs the server's CA cert to verify the server during
	// the handshake — it's untrusted because its OWN cert is signed by a different CA.
	if err := operator.DistributeCA(untrustedCfg.CACertFile); err != nil {
		return fmt.Errorf("error writing trusted CA cert to untrusted directory: %w", err)
	}
	fmt.Printf("  [UNTRUSTED CLIENT] Certificate → %s\n", untrustedCfg.CertFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Private key  → %s\n", untrustedCfg.KeyFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Server CA    → %s  (to verify server, but client cert is from a different CA)\n", untrustedCfg.CACertFile)
	fmt.Println()

	fmt.Println("=== Step 5/6: Make request with untrusted client certificate ===")
	fmt.Println("The server must reject this connection during the TLS handshake.")
	fmt.Println()

	// The untrusted client trusts the server's CA so the dial proceeds far enough for
	// the server to evaluate and reject the client certificate.
	untrustedClient, err := CreateClient(untrustedCfg.CACertFile, untrustedCfg.CertFile, untrustedCfg.KeyFile)
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
	printDirTree(opCfg, serverCfg, clientCfg, untrustedCfg)
	return nil
}

func printDirTree(opCfg OperatorConfig, serverCfg ServerConfig, clientCfg ClientConfig, untrustedCfg UntrustedClientConfig) {
	entries := []struct{ file, note string }{
		{opCfg.CertFile, "public — the CA's own copy"},
		{serverCfg.CertFile, "public — presented to clients during handshake"},
		{serverCfg.KeyFile, "private — never leaves the server machine"},
		{serverCfg.CACertFile, "public — copy received from operator, used to verify client certs"},
		{clientCfg.CertFile, "public — presented to server during mTLS handshake"},
		{clientCfg.KeyFile, "private — never leaves the client machine"},
		{clientCfg.CACertFile, "public — copy received from operator, used to verify server cert"},
		{untrustedCfg.CertFile, "public — rejected by server, unknown CA"},
		{untrustedCfg.KeyFile, "private — never leaves the untrusted client"},
		{untrustedCfg.CACertFile, "public — copy of server CA, to verify server cert"},
	}
	for _, e := range entries {
		fmt.Printf("  %-55s  %s\n", e.file, e.note)
	}
}


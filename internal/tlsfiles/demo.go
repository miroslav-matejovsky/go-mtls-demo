package tlsfiles

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
	return runDemo(opCfg, serverCfg, clientCfg)
}

func runDemo(opCfg OperatorConfig, serverCfg ServerConfig, clientCfg ClientConfig) error {
	fmt.Println("=== Step 1/4: Generate Certificate Authority (CA) ===")
	fmt.Println("In a real deployment the CA lives on a dedicated secure machine.")
	fmt.Println("Its public certificate is distributed to clients and servers.")
	fmt.Println("The private key never leaves the CA machine — it is NOT written to disk here.")
	fmt.Println()

	operator, err := NewOperator(opCfg)
	if err != nil {
		return fmt.Errorf("error creating operator: %w", err)
	}
	cert.PrintCertificateInfo(operator.CACert())
	if err := operator.DistributeCA(clientCfg.CACertFile); err != nil {
		return fmt.Errorf("error distributing CA certificate to client: %w", err)
	}
	fmt.Printf("  [OPERATOR] CA Certificate → %s\n", opCfg.CertFile)
	fmt.Printf("  [OPERATOR] Distributed to client → %s\n", clientCfg.CACertFile)
	fmt.Println()

	fmt.Println("=== Step 2/4: Generate Server Certificate (signed by CA) ===")
	fmt.Println("The CA signs the server certificate and hands it to the server operator.")
	fmt.Println("The private key is generated locally and stays in the server's own directory.")
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

	fmt.Println("=== Step 3/4: Start TLS server (loading certificate from disk) ===")
	fmt.Printf("Server reads from its own directory: %s\n", filepath.Dir(serverCfg.CertFile))
	fmt.Println("Server does NOT require a certificate from the client (one-way TLS).")
	fmt.Println()

	server, err := CreateServer(serverCfg.CertFile, serverCfg.KeyFile)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	ln, err := tls.Listen("tcp", serverCfg.Address, server.TLSConfig)
	if err != nil {
		return fmt.Errorf("error starting TLS listener on %s: %w", serverCfg.Address, err)
	}
	go server.Serve(ln) //nolint:errcheck
	defer server.Close()
	serverURL := "https://" + ln.Addr().String()
	fmt.Printf("[SERVER] Listening on %s\n", serverURL)
	fmt.Println()

	fmt.Println("=== Step 4/4: Make request over TLS (loading CA certificate from disk) ===")
	fmt.Printf("Client reads from its own directory: %s\n", filepath.Dir(clientCfg.CACertFile))
	fmt.Println("Client trusts the CA cert it received from the operator (no access to ca/ needed).")
	fmt.Println("Client config: trusts the CA — does NOT send a certificate (one-way TLS).")
	fmt.Println("Authentication: client verifies server cert → CA   |   server trusts any client.")
	fmt.Println()

	client, err := CreateClient(clientCfg.CACertFile)
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

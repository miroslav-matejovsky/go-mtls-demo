package mtlsfiles

import (
	"crypto/tls"
	"fmt"
	"path/filepath"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

// step3MakeTrustedRequest performs the successful mutual-TLS exchange using the trusted client files.
func step3MakeTrustedRequest(state *demoState, clientCfg ClientConfig) error {
	if err := state.unexpectedServerError(); err != nil {
		return err
	}

	fmt.Println("=== Step 3/6: Make request over mTLS (trusted client) ===")
	fmt.Printf("Client reads from its own directory only: %s\n", filepath.Dir(clientCfg.CertFile))
	fmt.Println("Authentication: client verifies server cert → CA   |   server verifies client cert → CA.")
	fmt.Println()

	client, err := CreateClient(clientCfg.CACertFile, clientCfg.CertFile, clientCfg.KeyFile)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Printf("[CLIENT] GET %s\n", state.serverURL)
	resp, err := client.Get(state.serverURL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] Server certificate verified: %s (issued by %s)\n",
		resp.TLS.PeerCertificates[0].Subject.CommonName, resp.TLS.PeerCertificates[0].Issuer.CommonName)
	fmt.Printf("[CLIENT] Handshake complete  — version: %s, cipher suite: %s\n",
		pki.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Println("[CLIENT] Response:", resp.Status)
	fmt.Println()
	if err := state.unexpectedServerError(); err != nil {
		return err
	}
	return nil
}

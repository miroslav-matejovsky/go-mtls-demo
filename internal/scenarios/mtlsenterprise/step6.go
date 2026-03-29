package mtlsenterprise

import (
	"crypto/tls"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
)

// step6TrustedRequest performs the successful mTLS exchange using the trusted client chain bundle.
func step6TrustedRequest(state *demoState, clientCfg ClientConfig) error {
	if err := state.unexpectedServerError(); err != nil {
		return err
	}

	fmt.Println("=== Step 6/8: Make request over mTLS (trusted client) ===")
	fmt.Println("Client presents: client cert + intermediate CA. Client trusts: root CA for server validation.")
	fmt.Println("Full chain verification: leaf → intermediate → root.")
	fmt.Println()

	client, err := CreateClient(clientCfg.RootCertFile, clientCfg.ChainFile, clientCfg.KeyFile)
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
		kpi.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Println("[CLIENT] Response:", resp.Status)
	fmt.Println()
	if err := state.unexpectedServerError(); err != nil {
		return err
	}
	return nil
}

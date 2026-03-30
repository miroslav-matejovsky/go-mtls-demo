package tlsfiles

import (
	"crypto/tls"
	"fmt"
	"path/filepath"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// step4MakeRequest loads the distributed CA certificate from disk and performs the TLS client request.
func step4MakeRequest(state *demoState, clientCfg ClientConfig) error {
	if err := state.unexpectedServerError(); err != nil {
		return err
	}

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

	fmt.Printf("[CLIENT] GET %s\n", state.serverURL)
	resp, err := client.Get(state.serverURL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] Handshake complete  — version: %s, cipher suite: %s\n",
		ca.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Println("[CLIENT] Response:", resp.Status)
	if err := state.unexpectedServerError(); err != nil {
		return err
	}
	return nil
}

package mtlsfiles

import "fmt"

// step5MakeUntrustedRequest shows the server rejecting the client whose certificate chains to the wrong CA.
func step5MakeUntrustedRequest(state *demoState, untrustedCfg UntrustedClientConfig) error {
	fmt.Println("=== Step 5/6: Make request with untrusted client certificate ===")
	fmt.Println("The server must reject this connection during the TLS handshake.")
	fmt.Println()

	// The untrusted client trusts the server's CA so the dial proceeds far enough for
	// the server to evaluate and reject the client certificate.
	untrustedClient, err := CreateClient(untrustedCfg.CACertFile, untrustedCfg.CertFile, untrustedCfg.KeyFile)
	if err != nil {
		return fmt.Errorf("error creating untrusted client: %w", err)
	}

	fmt.Printf("[UNTRUSTED CLIENT] GET %s\n", state.serverURL)
	_, err = untrustedClient.Get(state.serverURL)
	if err != nil {
		fmt.Printf("[UNTRUSTED CLIENT] Connection rejected — %s\n", err)
		fmt.Println("[UNTRUSTED CLIENT] Expected: server refused the certificate because it was not signed by the trusted cert.")
		fmt.Println()
		return nil
	}

	return fmt.Errorf("expected untrusted client to be rejected, but request succeeded")
}

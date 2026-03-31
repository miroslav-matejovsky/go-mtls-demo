package mtlsmem

import (
	"fmt"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// step6MakeUntrustedRequest demonstrates that the server rejects a client certificate signed by another CA.
func step6MakeUntrustedRequest(state *demoState) error {
	fmt.Println("=== Step 6/6: Make request with an untrusted client certificate ===")
	fmt.Println("This client has a certificate signed by a different CA that the server does not trust.")
	fmt.Println("The server must reject the connection during the TLS handshake.")
	fmt.Println()

	untrustedAuthority, err := ca.NewSimple(ca.CAConfig{
		CN:       "go mTLS Untrusted CA",
		Validity: 24 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("error creating untrusted CA: %w", err)
	}
	untrustedCSR, untrustedClientKey, err := ca.CreateClientCSR("go mTLS Untrusted Client")
	if err != nil {
		return fmt.Errorf("error creating untrusted client CSR: %w", err)
	}
	untrustedClientCert, err := untrustedAuthority.SignClientCSR(untrustedCSR)
	if err != nil {
		return fmt.Errorf("error signing untrusted client certificate: %w", err)
	}

	// The untrusted client trusts the server's CA so the TLS dial proceeds far enough for
	// the server to reject the client certificate.
	untrustedClient, err := CreateClient(state.authority.TrustAnchor(), untrustedClientKey, untrustedClientCert)
	if err != nil {
		return fmt.Errorf("error creating untrusted client: %w", err)
	}

	fmt.Printf("[UNTRUSTED CLIENT] GET %s\n", state.serverURL)
	_, err = untrustedClient.Get(state.serverURL)
	if err != nil {
		fmt.Printf("[UNTRUSTED CLIENT] Connection rejected — %s\n", err)
		fmt.Println("[UNTRUSTED CLIENT] Expected: server refused the certificate because it was not signed by the trusted CA.")
		return nil
	}

	return fmt.Errorf("expected untrusted client to be rejected, but request succeeded")
}

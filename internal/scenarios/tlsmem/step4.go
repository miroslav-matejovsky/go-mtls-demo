package tlsmem

import (
	"crypto/tls"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// step4MakeRequest creates the client, performs the TLS request, and prints the negotiated session details.
func step4MakeRequest(state *demoState) error {
	fmt.Println("=== Step 4/4: Make request over TLS ===")
	fmt.Println("Client config: trusts the CA — does NOT send a certificate (one-way TLS).")
	fmt.Println("Authentication: client verifies server cert → CA   |   server trusts any client.")
	fmt.Println()

	client, err := CreateClient(state.caCert)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	state.client = client

	fmt.Printf("[CLIENT] GET %s\n", state.serverURL)
	resp, err := client.Get(state.serverURL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] Handshake complete  — version: %s, cipher suite: %s\n",
		ca.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Println("[CLIENT] Response:", resp.Status)
	return nil
}

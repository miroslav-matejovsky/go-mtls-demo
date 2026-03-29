package mtlsmem

import (
	"crypto/tls"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
)

// step5MakeTrustedRequest performs the successful mutual-TLS request with the CA-signed client certificate.
func step5MakeTrustedRequest(state *demoState) error {
	fmt.Println("=== Step 5/6: Make request over mTLS (trusted client) ===")
	fmt.Println("Client config: trusts the CA AND sends its own certificate (mutual TLS).")
	fmt.Println("Authentication: client verifies server cert → CA   |   server verifies client cert → CA.")
	fmt.Println()

	client, err := CreateClient(state.caCert, state.clientCertPEM, state.clientKeyPEM)
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
	return nil
}

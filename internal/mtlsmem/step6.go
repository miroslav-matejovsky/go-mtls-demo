package mtlsmem

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
)

// step6MakeUntrustedRequest demonstrates that the server rejects a client certificate signed by another CA.
func step6MakeUntrustedRequest(state *demoState) error {
	fmt.Println("=== Step 6/6: Make request with an untrusted client certificate ===")
	fmt.Println("This client has a certificate signed by a different CA that the server does not trust.")
	fmt.Println("The server must reject the connection during the TLS handshake.")
	fmt.Println()

	_, untrustedSignLeaf, err := kpi.CreateCA("go mTLS Untrusted CA", 24*time.Hour)
	if err != nil {
		return fmt.Errorf("error creating untrusted CA: %w", err)
	}
	untrustedClientCert, untrustedClientKey, err := kpi.CreateLeafCertAndKey(untrustedSignLeaf, "go mTLS Untrusted Client")
	if err != nil {
		return fmt.Errorf("error creating untrusted client certificate: %w", err)
	}

	untrustedKeyPEMBytes, err := x509.MarshalECPrivateKey(untrustedClientKey)
	if err != nil {
		return fmt.Errorf("error marshaling untrusted client key: %w", err)
	}
	untrustedCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: untrustedClientCert.Raw})
	untrustedKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: untrustedKeyPEMBytes})

	// The untrusted client trusts the server's CA so the TLS dial proceeds far enough for
	// the server to reject the client certificate.
	untrustedClient, err := CreateClient(state.caCert, untrustedCertPEM, untrustedKeyPEM)
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

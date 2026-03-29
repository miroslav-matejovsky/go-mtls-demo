package mtlsmem

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
)

// step3GenerateClientCertificate creates the trusted client certificate and PEM material for the mutual-TLS client.
func step3GenerateClientCertificate(state *demoState) error {
	fmt.Println("=== Step 3/6: Generate Client Certificate (signed by CA) ===")
	fmt.Println("KEY DIFFERENCE from plain TLS: the client also has a certificate.")
	fmt.Println("The server will require this certificate and verify it against the trusted CA.")
	fmt.Println()

	clientCert, clientPrivateKey, err := kpi.CreateLeafCertAndKey(state.signLeaf, "go mTLS Demo Client")
	if err != nil {
		return fmt.Errorf("error creating client certificate: %w", err)
	}

	clientPrivPEMBytes, err := x509.MarshalECPrivateKey(clientPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling client EC private key: %w", err)
	}

	state.clientCert = clientCert
	state.clientPrivateKey = clientPrivateKey
	state.clientCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw})
	state.clientKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientPrivPEMBytes})

	kpi.PrintCertificateInfo(clientCert)
	return nil
}
